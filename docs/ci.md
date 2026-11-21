# whyreach in CI

When integration tests against a Compose stack fail in CI, the log usually says `Connection refused` or that a connection timed out, and nothing more. whyreach says why. Add three steps after your tests. They run only when a step before them failed. They install a pinned whyreach release, diagnose the connections your tests depend on, and put the diagnosis in the job log, in the job summary and in an artifact. An AI agent asked to fix the failing job can read it there too.

The steps never change the job's result: the tests' failure stays the job's failure, whatever whyreach finds.

> **Version:** the example pins whyreach **v0.2.0**, the release CI mode ships in. Until v0.2.0 is out, the install step can't find it.

## The example (GitHub Actions)

A whole workflow, so you can see where the steps go. Copy the three steps marked `whyreach`, then list your own connections in `WHYREACH_PAIRS`.

```yaml
name: integration tests

on:
  push:
  pull_request:

permissions:
  contents: read

jobs:
  integration:
    runs-on: ubuntu-24.04
    env:
      COMPOSE_PROJECT_NAME: shop # the project name that whyreach's SOURCE uses
    steps:
      - uses: actions/checkout@v7
      - name: Start the stack
        run: docker compose up -d --wait
      - name: Integration tests
        run: make integration-test

      # whyreach: when a step above failed, diagnose the connections the
      # tests depend on. These steps never change the job's result.
      - name: Install whyreach
        id: whyreach-install
        if: failure()
        shell: bash
        env:
          WHYREACH_VERSION: 0.2.0
        run: |
          case "$(uname -m)" in
            x86_64) arch=amd64 ;;
            aarch64 | arm64) arch=arm64 ;;
            *) echo "whyreach has no release for $(uname -m)" >&2; exit 1 ;;
          esac
          archive="whyreach_${WHYREACH_VERSION}_linux_${arch}.tar.gz"
          bin="$RUNNER_TEMP/whyreach/bin"
          mkdir -p "$bin" && cd "$bin"
          for f in "$archive" checksums.txt; do
            curl -fsSL --retry 3 -o "$f" "https://github.com/SandstromPL/whyreach/releases/download/v${WHYREACH_VERSION}/$f"
          done
          # Check the archive against its line in checksums.txt (no line fails too).
          awk -v f="$archive" '$2 == f' checksums.txt | sha256sum --check --strict
          tar -xzf "$archive" whyreach
          echo "$bin" >> "$GITHUB_PATH"

      - name: Diagnose the connections with whyreach
        id: whyreach-diagnose
        if: failure()
        shell: bash
        env:
          # One connection per line, SOURCE TARGET, as the failing code makes
          # it. SOURCE is host (this runner) or service:NAME@PROJECT.
          WHYREACH_PAIRS: |
            host localhost:8080
            service:api@shop db:5432
          # Redacted unless only the repository's readers can see this run:
          # a public repository's logs and artifacts are public.
          WHYREACH_REDACT: ${{ github.event.repository.visibility != 'private' }}
        run: |
          set +e # each failure is handled below: this step reports, it doesn't fail
          base="$RUNNER_TEMP/whyreach"
          out="$base/diagnosis" # the next step uploads this
          mkdir -p "$out" "$base/run" "$base/config/whyreach"
          if ! command -v whyreach > /dev/null; then
            echo "::warning title=whyreach::whyreach isn't installed: see the step before this one"
            exit 0
          fi
          # Checks from inside a container run in short-lived probe containers.
          printf '[permissions]\nprobe_containers = true\n' > "$base/config/whyreach/config.toml"
          export XDG_CONFIG_HOME="$base/config"
          verdict=("no problem reproduced" "cause or likely cause found" "inconclusive")
          n=0
          while read -r from to extra; do
            case "$from" in "" | "#"*) continue ;; esac
            n=$((n + 1))
            if [ -z "$to" ] || [ -n "$extra" ]; then
              echo "::warning title=whyreach::connection $n: write it as SOURCE TARGET"
              continue
            fi
            # whyreach's audit log and report bundle for this connection go in $base/run/N.
            export XDG_STATE_HOME="$base/run/$n/state" XDG_DATA_HOME="$base/run/$n/data"
            whyreach diagnose --report --from "$from" "$to" > "$base/run/$n.out" 2> "$base/run/$n.err"
            code=$?
            reports="$XDG_DATA_HOME/whyreach/reports"
            bundle=$(ls "$reports" 2> /dev/null | head -n 1)
            if [ "$code" -le 2 ] && [ -n "$bundle" ]; then
              mkdir -p "$out/$n"
              if [ "$WHYREACH_REDACT" = false ]; then
                cp "$reports/$bundle"/* "$out/$n/"
              else
                # Addresses, host names, MAC addresses and container IDs become pseudonyms.
                tgz=$(whyreach report export "$bundle" --redact-private | head -n 1) &&
                  tar -xzmf "$tgz" -C "$out/$n" --strip-components=1
              fi
            fi
            if [ -f "$out/$n/report.md" ]; then
              echo "::notice title=whyreach::connection $n: ${verdict[$code]} (exit $code); the diagnosis is in the log, the job summary and the whyreach artifact"
              echo "::group::whyreach, connection $n: ${verdict[$code]}"
              cat "$out/$n/report.md"
              echo "::endgroup::"
              cat "$out/$n/report.md" >> "$GITHUB_STEP_SUMMARY"
            else
              echo "::warning title=whyreach::connection $n: no diagnosis (exit $code); whyreach's error is in the log"
              echo "::group::whyreach, connection $n: exit $code"
              cat "$base/run/$n.err"
              echo "::endgroup::"
            fi
          done <<< "$WHYREACH_PAIRS"
          [ "$n" -gt 0 ] || echo "::warning title=whyreach::WHYREACH_PAIRS lists no connection"
          exit 0

      - name: Upload whyreach's diagnosis
        id: whyreach-upload
        if: failure()
        uses: actions/upload-artifact@v7
        with:
          name: whyreach
          path: ${{ runner.temp }}/whyreach/diagnosis
          if-no-files-found: ignore
          retention-days: 7

      - name: Stop the stack
        if: always()
        run: docker compose down -v
```

## What the steps do

1. **Install whyreach** downloads the archive for the runner's architecture (amd64 or arm64) and `checksums.txt` from this project's [GitHub Releases](https://github.com/SandstromPL/whyreach/releases), checks the archive's SHA-256 against its line in `checksums.txt`, and puts whyreach on the `PATH` of the steps after it. Nothing else is downloaded, and whyreach itself sends nothing but the checks a diagnosis needs: no telemetry, no update checks. Each release's archives also carry a signed build-provenance attestation, which `gh attestation verify <archive> --repo SandstromPL/whyreach` checks with a `GH_TOKEN`; the example doesn't do that.
2. **Diagnose** runs `whyreach diagnose --report --from SOURCE TARGET` for each line of `WHYREACH_PAIRS`. `--report` saves the diagnosis, with all its evidence, as a report bundle: `report.md` (the text whyreach prints, and the evidence), `diagnosis.json` and `evidence.jsonl` (together, what `--json` prints) and `manifest.json`. For each connection, the step:
   - puts the bundle in `$RUNNER_TEMP/whyreach/diagnosis/<N>/`, where `<N>` is the connection's number: its place in `WHYREACH_PAIRS`, not counting blank lines and `#` comments. The bundle is redacted unless the repository is private ([below](#privacy-who-can-read-the-diagnosis));
   - prints `report.md` to the job log, in a group named after the verdict, and adds it to the job summary;
   - adds a notice with the verdict and whyreach's exit code. A connection whyreach couldn't diagnose (exit 3 or 4: a typo in a service's name, say) gets a warning instead, and whyreach's error in the log.
3. **Upload** keeps `$RUNNER_TEMP/whyreach/diagnosis` as the artifact `whyreach` for 7 days.

`RUNNER_TEMP` is emptied at the end of the job, so nothing whyreach wrote stays on the runner (on a self-hosted one, the probe image aside): its config, its audit log, and the bundles that weren't redacted.

## Choosing the connections

Each line of `WHYREACH_PAIRS` is one connection, written as the code that failed makes it:

- **SOURCE** is where the connection starts. Use `host` for tests that run on the runner itself, against ports the stack publishes, and `service:NAME@PROJECT` for a service of the stack. `PROJECT` is the Compose project's name: set `COMPOSE_PROJECT_NAME` (or `name:` in your Compose file), since Compose otherwise takes the directory's name.
- **TARGET** is `HOST:PORT` as the source uses it: a Compose service (`db:5432`), `localhost:8080`, an alias, an address or `host.docker.internal:PORT`.
- The source container must still be running. A one-off container from `docker compose run --rm` is gone by the time whyreach looks, so list the services that the tests talk to and that talk to each other, or `host`.
- Keep the whyreach steps before any step that stops the stack, as in the example.

## Exit codes and the job's result

whyreach's exit code says what it found:

| Code | Meaning |
|---|---|
| 0 | no problem reproduced |
| 1 | cause or likely cause found |
| 2 | inconclusive |
| 3 | usage or policy error |
| 4 | internal error |

The diagnose step records each connection's code in its notice or warning and always exits 0. It runs only after a failure (`if: failure()`), and a step that succeeds later doesn't make a failed job pass, so the tests' failure stays the job's result. The step adds no failure of its own, so the step marked failed is still the one that failed.

Don't put whyreach in the tests' own step, as in `make integration-test || whyreach …`: the `||` hides the tests' failure, and the job passes.

## Permissions: probe containers

A diagnosis needs to look from inside the containers: DNS as the source sees it, and a TCP connect from the source. The example lets whyreach use probe containers for that, and needs nothing more than the access to Docker that a job running Compose already has: no sudo, no root.

- **How:** the step writes a config file with `probe_containers = true` under `RUNNER_TEMP` and points `XDG_CONFIG_HOME` at it. whyreach imports its own binary as a local image (no registry pull) and runs the checks in short-lived containers that join the checked container's network namespace. They carry the label `io.whyreach.probe=1` and are removed afterwards, and each diagnosis lists them as side effects. They leave the stack's own containers alone.
- **Cost:** on the test's stack ([below](#how-the-example-is-tested)), a diagnosis took 0.3 s on Docker Engine, the probe image's import included.
- **Self-hosted runners:** the runner's user needs access to Docker, as for Compose. The probe image stays after the job, about 15 MB per whyreach version: `docker image ls --filter label=io.whyreach.probe=1` lists them.
- **Without probe containers,** whyreach reads Docker's metadata and the containers' listening sockets, and reports the checks from inside a container as gaps.

For a job that must not start containers: whyreach run as root does the same checks without probe containers, by entering the containers' network namespaces itself. The example has no script for that.

## Privacy: who can read the diagnosis

The diagnosis names your containers, services and networks, and holds Docker's addresses. Its evidence includes each container's `resolv.conf` and `hosts` file (its nameservers, search domains and host entries) and, from the runner, its network interfaces and addresses and the ports it listens on, which on a self-hosted runner name the services that run there. whyreach never collects environment variable values or other files' contents.

A public repository's job logs, job summaries and artifacts can be read by anyone. A private repository's can be read by whoever can read the repository.

So the example redacts what it writes unless the repository is private. `WHYREACH_REDACT` is `true` for public and internal repositories, and when GitHub doesn't say. It is `false` only when `github.event.repository.visibility` is `private`. Redacted means:

- The step runs `whyreach report export --redact-private` on each bundle and keeps only that copy. Public and private addresses, host names, MAC addresses and container IDs become pseudonyms (`ip-…`, `host-…`, `ctr-…`), stable within one report, and the runner's home directory becomes `~`. Container, service and network names, loopback addresses and ports stay, and so do the rules' explanations and fixes.
- The bundles that aren't redacted stay in `RUNNER_TEMP`, which is emptied at the end of the job.
- Not redacted: whyreach's error for a connection it couldn't diagnose (exit 3 or 4), which repeats that line of `WHYREACH_PAIRS`.

Check what a redacted report keeps before you rely on it, as you would before attaching one to an issue. To keep everything in a public repository, set `WHYREACH_REDACT: false` deliberately.

## Other CI systems

The same commands work on any Linux CI runner with Docker Engine: install the release with its checksum, then run `whyreach diagnose --report --from SOURCE TARGET` for each connection, with probe containers allowed in whyreach's config, and run `whyreach report export ID --redact-private` before a diagnosis leaves the runner. whyreach's exit code is the diagnosis's; don't let it decide the job's result.

## How the example is tested

`TestCIExample` (`test/e2e/ciexample_test.go`, part of `make lab`) runs this page's example, as written here: it reads the three steps from the YAML block above and runs their scripts the way GitHub Actions runs them (`bash --noprofile --norc -eo pipefail`). It runs them against a deliberately broken stack, the lab's `wr002-loopback-bind`, whose `api` listens only on `127.0.0.1`, so the stack's test, a connect from `worker` to `api:8080`, fails first.

- **Install:** nothing is downloaded. A stand-in for `curl` answers from a release that the test builds from the same source, in the release's layout, and records each URL. The URLs must be the pinned release's archive and `checksums.txt` on this project's GitHub Releases. A tampered archive, or a `checksums.txt` without the archive's line, must stop the step before anything is installed.
- **Diagnose,** redacted and not, with probe containers: worker's connection to `api:8080` must be WR002 (exit 1), a working connection no problem (exit 0), and a service that doesn't exist and a malformed line warnings. The step must exit 0. Redacted, no address or container ID of the stack may appear in the log, the job summary or the artifact.
- **On GitHub:** the `ci-example` workflow (`.github/workflows/ci-example.yml`) runs the same test on GitHub's `ubuntu-24.04` runner, on pushes to `main` and by hand. Started by hand with a version, it downloads that release from GitHub Releases instead of building one.
