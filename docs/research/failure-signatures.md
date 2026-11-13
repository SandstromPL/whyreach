# NetDoctor: real-world failure signatures and name check

Research date: 2026-11-13. Scope: "a container can't reach another container, the host, or the internet". Image builds, volumes and registry login are out of scope.

## Method

I used the Stack Exchange API (lifetime view counts, votes and the number of questions that link to a question), the Docker Community Forums JSON API (topic views and post counts), and GitHub issue search sorted by reactions (`gh api search/issues`) in docker/compose, moby/moby, docker/for-mac, docker/for-win and docker/for-linux. For each signature I picked the canonical or highest-viewed Stack Overflow questions and summed their lifetime views to rank it. Treat the ranking as coarse. View counts are lifetime and include search-engine traffic. The sums are not deduplicated across questions, and I chose the questions by hand, so a signature with many small questions can be undercounted. "Linked from N" is the Stack Exchange `/questions/{id}/linked` total. It counts every question that links to the canonical one, so it includes duplicates but is not a duplicate count; I could not get a pure duplicate count from the API. GitHub search is keyword-fuzzy and I hit its rate limit (30 searches per minute), so the GitHub numbers are spot checks, not a survey. I could not retrieve any Reddit r/docker thread (web search returned none), so Reddit frequency is **not measured**. Where a section says "not measured" it means I looked and found no number I trust. Error strings marked "(title)" come from a question title. Strings marked "typical" are well-known messages that I did not quote from a specific source. Root causes come from the top answers I read plus the Docker docs pages I fetched. Anything from general knowledge only is marked as such.

## Ranked summary

Rank is by summed lifetime views of the cited Stack Overflow questions. Ranks 18 to 20 and the unranked rows have little or no Stack Overflow evidence.

| Rank | Signature | Typical error | Platforms | Rule |
|---|---|---|---|---|
| 1 | `localhost` / 127.0.0.1 used inside a container | `ECONNREFUSED 127.0.0.1:5432`; `Error 111 connecting to 127.0.0.1:6379` | all | ND007 |
| 2 | Containers share no network (separate Compose projects, `docker run` without `--network`) | `Name or service not known`, `getaddrinfo ENOTFOUND`, timeout on IP | all | ND004 |
| 3 | DNS server inside the container fails (upstream unreachable, VPN DNS not picked up, 127.0.0.53, embedded DNS not answering) | `Temporary failure in name resolution`; `getaddrinfo EAI_AGAIN`; `Could not resolve host` | mostly Linux Engine; also Desktop with VPN | NEW |
| 4 | Startup race: destination not ready yet | `Connection refused` on the first attempt only | all | ND010 |
| 5 | Host service bound to 127.0.0.1 (or firewall-limited) | `Connection refused` to host IP or `host.docker.internal` | Linux Engine, WSL2 without Desktop | ND012 |
| 6 | Port not published, or published on a different host port or address (host to container) | `Connection refused` to `localhost:PORT` from the host | all | NEW |
| 7 | `host.docker.internal` does not resolve on Linux Engine | `Could not resolve host: host.docker.internal`; `ENOTFOUND` | Linux Engine, WSL2 without Desktop | ND011 |
| 8 | Name does not resolve on the source's network (typo, other network, nginx upstream) | `nginx: [emerg] host not found in upstream`; `could not translate host name "db"` | all | ND005 |
| 9 | Host firewall (ufw, firewalld, iptables INPUT) rejects bridge-to-host traffic | `No route to host`; sometimes plain timeout | Linux Engine | NEW (ND016 only partly) |
| 10 | No outbound NAT or forwarding (`ip_forward=0`, daemon `iptables:false`, missing MASQUERADE) | `IPv4 forwarding is disabled. Networking will not work`; timeouts to the internet | Linux Engine | NEW |
| 11 | Service inside the container binds loopback only | `Connection reset by peer`; `Empty reply`; refused | all | ND002 |
| 12 | Default `bridge` network has no name resolution | `ping: bad address`; `Name or service not known` | all (Engine, Desktop) | ND009 |
| 13 | Client resolver bypasses Docker DNS or keeps a stale IP (nginx `resolver 8.8.8.8`, cached upstream IP) | `502 Bad Gateway`; `connect() failed (111: Connection refused) while connecting to upstream` | all | NEW |
| 14 | Docker Desktop: `network_mode: host` / `--net=host` is the VM's network, not the machine's | `Published ports are discarded when using host network mode`; refused | Docker Desktop macOS/Windows (older versions especially) | NEW |
| 15 | Docker subnet overlaps a VPN or LAN route | hosts behind the VPN unreachable; `could not find an available, non-overlapping IPv4 address pool` | Linux Engine, Desktop | ND013 |
| 16 | MTU mismatch (VPN, overlay, cloud) | TLS handshake or large transfers hang; small requests work | all | ND017 |
| 17 | Host-published port used container-to-container, or reached via the host IP | `Connection refused`; timeout (hairpin via host IP) | all | ND006 (partial) |
| 18 | IPv6/IPv4 mismatch (`localhost` resolves to `::1`) | `connect ECONNREFUSED ::1:PORT` | all (Node >= 17, others) | ND014 |
| 19 | Client is redirected to an advertised address it can't reach (Kafka and similar) | `1/1 brokers are down`; connect works, then fails on the second address | all | NEW (low priority) |
| 20 | Host-to-container-IP access on Docker Desktop (container IPs not routable from host) | timeout to `172.x.x.x` | Docker Desktop macOS/Windows | NEW (host to container, low priority) |
| not measured | Destination container down, restarting or unhealthy | `Connection refused` | all | ND008 |
| not measured | `internal: true` network but external target | timeout; `Network is unreachable` | all | ND015 |
| not measured | Timeout caused by silent drop | `Connection timed out` | all | ND016 |
| not measured | Proxy env vars intercept traffic | `502`/`403` from a proxy for internal hosts | all | ND018 |

## Signatures

### 1. `localhost` inside a container (ND007)

- **Cause:** `localhost` inside a container is that container's own loopback. The target service runs in another container or on the host.
- **Frequency:** Stack Overflow 24319662, "From inside of a Docker container, how do I connect to the localhost of the machine?": 3568 votes, 2,928,419 views, 45 answers, linked from 763 questions. Container-to-container variants: 33357567 (100 votes, 141,578 views, linked from 38), 34729752 (55 votes, 70,852 views), 43800164 (44, 51,105), 42376867 (41, 58,767), 34711642 (40, 68,892), 51011552 (33, 58,649), 57116745 (11, 15,987). Docker forum "Localhost and docker-compose networking issue" 224,891 views; "Accessing localhost inside the container itself" 98,259 views; "How to reach localhost on host from docker container?" 710,809 views. Sum of the SO questions: about 3.39 million views.
- **Evidence needed:** the target host literal; the source container's netns (to show nothing listens on that port there); a match for the port among other containers' listeners or published ports, to suggest the right name.
- **Sources:** https://stackoverflow.com/questions/24319662 · https://stackoverflow.com/questions/33357567 · https://forums.docker.com/t/23100

### 2. Containers share no network (ND004)

- **Cause:** Compose creates one network per project. Containers from different projects, or started with plain `docker run`, are on different networks, so names don't resolve and IPs are not routable.
- **Frequency:** SO 38088279, "Communication between multiple docker-compose projects": 707 votes, 669,811 views, linked from 107. SO 42385977, "Accessing a Docker container from another container": 232 votes, 378,770 views, linked from 18. Docker forum 99334 (22,241 views) and 128819 (1,186 views). Sum of cited SO questions: about 1.07 million views.
- **Evidence needed:** both containers' network membership (`docker.container` and `docker.network` records), Compose project labels, whether an external network is declared.
- **Sources:** https://stackoverflow.com/questions/38088279 · https://stackoverflow.com/questions/42385977 · https://forums.docker.com/t/99334

### 3. DNS inside the container fails (NEW)

- **Cause (several, all give the same symptom):** the container's upstream DNS (copied from the host's `/etc/resolv.conf`) is unreachable or wrong. Examples from the answers: the host uses a `127.0.0.53` systemd-resolved stub; a corporate firewall blocks the fallback 8.8.8.8; VPN DNS is not picked up until systemd-resolved and Docker are restarted; the Docker daemon needs a restart after network changes; a local DNS server (pihole) broke the embedded 127.0.0.11 resolution. ND005 only covers NXDOMAIN for names on the source's networks. A SERVFAIL or timeout, or a failure on an external name, is not covered.
- **Frequency:** SO 44761246, "Temporary failure in name resolution [Errno -3] with Docker": 109 votes, 209,083 views, linked from 11 (top answer: restart the Docker service). SO 41717180, "Docker-compose container using host DNS server": 68 votes, 287,884 views. SO 49998099 (dnsmasq/127.0.0.53): 49 votes, 150,332 views. SO 62968807, "DNS resolution in docker containers": 25 votes, 123,698 views. SO 64007727, "internal DNS server 127.0.0.11 connection refused": 36 votes, 111,958 views. SO 54134098: 23 votes, 93,387 views. SO 62050860 (VPN DNS not updated): 18 votes, 5,782 views. Docker forum 35107 (pip fails in container): 90,792 views; 134889: 28,484 views. Sum of the cited SO questions: about 0.98 million views.
- **Evidence needed:** the container's resolver config (`ResolvConfPath` on the host, not the host's own `/etc/resolv.conf`); UDP and TCP 53 probes from the source netns to each upstream and to 127.0.0.11; the host's resolver mode (stub address); daemon `dns` setting; VPN state. Keep NXDOMAIN, SERVFAIL and timeout as separate results.
- **Sources:** https://stackoverflow.com/questions/44761246 · https://stackoverflow.com/questions/41717180 · https://stackoverflow.com/questions/49998099 · https://stackoverflow.com/questions/64007727

### 4. Startup race (ND010)

- **Cause:** the app connects before the database or broker is listening. `depends_on` without `condition: service_healthy` only waits for the container to start.
- **Frequency:** SO 31746182, "Docker Compose wait for container X before starting Y": 681 votes, 734,830 views, linked from 202 (the highest linked count after #1). SO 52322800: 47 votes, 89,254 views. SO 60539114: 38, 34,813. SO 52000903: 20, 21,941. docker/compose issue 374, "Is there a way to delay container startup...": 265 reactions, 316 comments (closed). Sum of cited SO questions: about 0.89 million views.
- **Evidence needed:** destination `StartedAt`, `RestartCount`, health status, a listener check (ND001) at diagnosis time, Compose `depends_on` conditions if available.
- **Sources:** https://stackoverflow.com/questions/31746182 · https://github.com/docker/compose/issues/374

### 5. Host service bound to 127.0.0.1 (ND012)

- **Cause:** the service on the host listens on loopback only (PostgreSQL `listen_addresses`, Prometheus targets, RabbitMQ). Traffic from a bridge network arrives on the bridge interface and is refused. The top answer for SO 31249112 says to set `listen_addresses` to all addresses and use the host's IP.
- **Frequency:** SO 31249112, "Allow docker container to connect to a local/host postgres database": 325 votes, 467,913 views, linked from 35. SO 28056522, "Access host database from a docker container": 246 votes, 242,938 views, linked from 23. SO 41089268 (RabbitMQ): 27 votes, 66,125 views. SO 56909896 (Prometheus scraping the host): 38 votes, 39,860 views. docker/for-linux issue 1365, "host.docker.internal failure when host machine bind address 127.0.0.1": 1 reaction, 1 comment (open). Sum of cited SO questions: about 0.82 million views.
- **Evidence needed:** host listeners (address and port), the bridge gateway IP, which interface the connection arrives on. Platform check: I did not verify whether Docker Desktop's `host.docker.internal` reaches loopback-only host services. That needs a lab test before the rule is allowed to fire on Desktop.
- **Sources:** https://stackoverflow.com/questions/31249112 · https://stackoverflow.com/questions/28056522

### 6. Port not published, or published differently (NEW)

- **Cause:** the user connects from the host to `localhost:PORT` but the container has no `-p`/`ports:` entry, maps a different host port, or publishes on a specific host IP. `EXPOSE` alone doesn't publish. The target grammar already allows `from=host` and host-to-container checks (INITIAL.md §2.2), but no catalog rule covers this. ND006 is the reverse case (container-to-container using the host port).
- **Frequency:** SO 36813690, "Connection refused on docker container": 98 votes, 320,281 views (top answer: publish the port with `-p`). SO 35928670, "Docker container for Postgres 9.1 not exposing port 5432 to host": 77 votes, 196,639 views. SO 54940990, "Docker can't connect to Container exposed port": 41 votes, 131,363 views. SO 33336773, "Connecting to mongo docker container from host": 43 votes, 80,341 views. Sum: about 0.73 million views.
- **Evidence needed:** the container's `PortBindings` (HostIp, HostPort), `ExposedPorts`, the container's listeners, host listeners for the published port (docker-proxy or nftables DNAT).
- **Sources:** https://stackoverflow.com/questions/36813690 · https://stackoverflow.com/questions/35928670 · https://stackoverflow.com/questions/54940990

### 7. `host.docker.internal` on Linux (ND011)

- **Cause:** Docker Desktop provides the name. On Docker Engine it exists only if the container has `--add-host=host.docker.internal:host-gateway` (or `extra_hosts`). The Desktop networking docs describe the name for Desktop only.
- **Frequency:** SO 48546124, "What is the Linux equivalent of host.docker.internal?": 432 votes, 674,338 views, linked from 54. docker/for-linux issue 264, "Support host.docker.internal DNS name to host": 1,719 reactions, 271 comments (closed). moby/moby issue 23177, "Add dockerhost as an entry in /etc/hosts in all containers": 267 reactions, 41 comments (closed). SO 65426891 (WSL2 and Docker Desktop for Windows networking): 16 votes, 33,426 views. Docker forum 14248, "Accessing host machine from within docker container": 670,882 views, 47 likes.
- **Evidence needed:** DNS answer in the source netns, `ExtraHosts` of the source container, platform and Engine version.
- **Sources:** https://stackoverflow.com/questions/48546124 · https://github.com/docker/for-linux/issues/264 · https://docs.docker.com/desktop/features/networking/networking-how-tos/

### 8. Name does not resolve on the source's network (ND005)

- **Cause:** wrong name, the destination is on another network, or the source is not yet attached. The name in `nginx` `proxy_pass` is resolved at nginx startup, so a missing network or a not-yet-running container produces `host not found in upstream`. One high-view question (51750715) turned out to be a build-time `RUN` that tried to connect, which is a build issue and out of scope.
- **Frequency:** SO 33639138, "Docker Networking - nginx: [emerg] host not found in upstream": 156 votes, 302,720 views, linked from 9. SO 51750715, `Could not translate host name "db"`: 73 votes, 249,098 views. SO 45717835: 28 votes, 44,181 views. SO 53399905 (`getaddrinfo EAI_AGAIN`): 6 votes, 17,066 views. Sum: about 0.61 million views.
- **Evidence needed:** DNS answer from the source netns (127.0.0.11), network members with names, Aliases and DNSNames, closest-name suggestion.
- **Sources:** https://stackoverflow.com/questions/33639138 · https://stackoverflow.com/questions/51750715

### 9. Host firewall rejects bridge-to-host (NEW)

- **Cause:** ufw or firewalld on the host blocks traffic from the Docker bridge to host ports (INPUT chain). firewalld's reject sends ICMP host-prohibited, which clients report as `No route to host`. The top answer for SO 40214617 says to allow the bridge subnet in firewalld. ND016 covers timeouts only, and `No route to host` is a different errno.
- **Frequency:** SO 30383845, "What is the best practice of docker + ufw under Ubuntu": 196 votes, 223,647 views, linked from 21. SO 40214617, "Docker - No route to host": 44 votes, 122,548 views. SO 43879637 ("cannot connect to host machine: No route to host"): 6 votes, 16,055 views. docker/for-linux issue 690, "Docker bypasses ufw firewall rules": 258 reactions, 124 comments (open). That issue is the reverse problem (published ports exposed past ufw), included here because it is the same firewall interaction. moby/moby issue 22054, "Docker Network bypasses Firewall, no option to disable": 94 reactions, 239 comments (open). Sum of the three SO questions: about 0.37 million views.
- **Evidence needed:** the errno (EHOSTUNREACH vs ETIMEDOUT vs ECONNREFUSED), a host listener that exists and is reachable from the host itself, ufw/firewalld status and zones, INPUT rules or nftables rules for the bridge interface and subnet.
- **Sources:** https://stackoverflow.com/questions/40214617 · https://stackoverflow.com/questions/30383845 · https://docs.docker.com/engine/network/packet-filtering-firewalls/

### 10. No outbound NAT or forwarding (NEW)

- **Cause:** `net.ipv4.ip_forward=0`, the daemon running with `iptables: false`, or a missing MASQUERADE rule, so containers cannot reach the internet or other subnets. The Docker docs say Engine turns forwarding on at startup if it is off, so persistent cases mostly come from `iptables=false`, a later sysctl reset, or the experimental nftables backend (which the docs say does not enable forwarding). The frequency evidence is older (CentOS 7 era), so treat it as a lower-priority check on current Engine versions.
- **Frequency:** SO 41453263, "Docker Networking Disabled: WARNING: IPv4 forwarding is disabled": 186 votes, 192,580 views. SO 39867602, "no internet inside docker-compose service": 46 votes, 46,906 views (answer: `iptables=false` left in daemon config). SO 40792765: 11 votes, 26,769 views. SO 49484847: 2 votes, 8,653 views. Sum: about 0.27 million views.
- **Evidence needed:** host sysctl `ip_forward`, daemon `iptables`/`firewall-backend` settings, nat POSTROUTING rules for the network's subnet, FORWARD policy. A probe from the source netns to an external IP (not a name) separates this from DNS (#3).
- **Sources:** https://stackoverflow.com/questions/41453263 · https://stackoverflow.com/questions/39867602 · https://docs.docker.com/engine/network/packet-filtering-firewalls/

### 11. Service inside the container binds loopback only (ND002)

- **Cause:** the app listens on 127.0.0.1 (for example a dev server default) so other containers, and published ports, are refused or reset. The top answer for SO 57773604 suggests testing with `--network host` to confirm.
- **Frequency:** SO 57773604, "Connection reset by peer when hitting Docker container": 97 votes, 174,158 views, linked from 4. SO 53802676 (Spark Web UI in a container): 6 votes, 9,971 views. Sum: about 0.18 million views. Other loopback-bind questions are filed under generic "connection refused" titles and I could not separate them.
- **Evidence needed:** listeners in the destination's netns with their bind address, refused or reset from another netns.
- **Sources:** https://stackoverflow.com/questions/57773604

### 12. Default bridge has no name resolution (ND009)

- **Cause:** the default `bridge` network has no automatic DNS. The Docker bridge-driver docs say containers there reach each other by IP only (or legacy `--link`). User-defined bridges resolve names.
- **Frequency:** SO 31149501, "How to reach docker containers by name instead of IP address?": 118 votes, 197,454 views, linked from 14. Docker forum 15430, "I can't access a container from another container": 18,312 views. No other canonical question found.
- **Evidence needed:** network name and driver of both containers, an NXDOMAIN from the source.
- **Sources:** https://stackoverflow.com/questions/31149501 · https://docs.docker.com/engine/network/drivers/bridge/

### 13. Client resolver bypasses Docker DNS or keeps a stale IP (NEW)

- **Cause:** from the top answers of SO 35744650: nginx needs `resolver 127.0.0.11` (Docker's embedded DNS) to resolve container names; a `resolver 8.8.8.8` line copied from an SSL config template overrides it; nginx may also ask for AAAA records. Separately, nginx resolves static upstream hostnames at startup and keeps the address until reload, so a recreated container with a new IP gives 502 (general knowledge, not in the sources I fetched).
- **Frequency:** SO 35744650, "Docker Network Nginx Resolver": 115 votes, 138,760 views, linked from 16. SO 51009692 (nginx 502, connection refused to upstream): 18 votes, 30,392 views.
- **Evidence needed:** the source's open sockets (remote IPs in SYN-SENT or ESTABLISHED) compared with the destination's current IP, DNS answers from 127.0.0.11, container recreate time. Reading nginx config would need exec into the container, which the design avoids.
- **Sources:** https://stackoverflow.com/questions/35744650 · https://stackoverflow.com/questions/51009692

### 14. Docker Desktop host networking (NEW)

- **Cause:** with `network_mode: host` or `--net=host` on Docker Desktop, "host" is the Linux VM, not the user's macOS or Windows machine, and published ports are ignored. Recent Desktop docs describe host networking as available, so I can't say which versions are affected without a check; the evidence below is older.
- **Frequency:** SO 63068636, "Docker WARNING: Published ports are discarded when using host network mode": 40 votes, 102,698 views. SO 52321269, "How to reach docker container localhost from Mac?": 6 votes, 10,686 views. docker/for-mac issue 2716, "Block/disallow --net=host (host networking) on Mac OS": 252 reactions, 98 comments (closed). docker/for-mac issue 1031, "network_mode: host probably not working as expected": 98 reactions, 52 comments (closed). docker/compose issue 3800, "network_mode: host does not use the network of host machine": 40 reactions, 22 comments (closed).
- **Evidence needed:** platform (Desktop vs Engine), Desktop version and host-networking setting, the container's `NetworkMode`, `PortBindings`.
- **Sources:** https://stackoverflow.com/questions/63068636 · https://github.com/docker/for-mac/issues/1031 · https://github.com/docker/for-mac/issues/2716

### 15. Docker subnet overlaps a VPN or LAN route (ND013)

- **Cause:** Docker's default pools (172.17.0.0/16 and others) overlap an address range used by the VPN or LAN, so traffic to the real hosts goes into the bridge. The top answer for SO 62849480 says to change the Docker network when the host network uses the same range. The Docker docs I fetched don't discuss this case.
- **Frequency:** SO 62849480, "What is the 'Docker Subnet' used for?": 27 votes, 42,810 views. SO 63612100 (no internet behind a Cisco VPN): 11 votes, 6,424 views. SO 62050860: 18 votes, 5,782 views. docker/for-linux issue 418, "[openvpn] ERROR: could not find an available, non-overlapping IPv4 address pool": 30 reactions, 11 comments (closed); issue 599 (same message): 8 reactions, 23 comments. Several vendor docs (Nebius, IBM, Broadcom) describe the same fix, which suggests it is common in corporate setups, but I have no count. Overall frequency is lower than the rank implies on Stack Overflow because affected users search for VPN symptoms.
- **Evidence needed:** host route lookup for the destination IP, the subnets of all Docker networks, VPN interface routes.
- **Sources:** https://stackoverflow.com/questions/62849480 · https://github.com/docker/for-linux/issues/418 · https://docs.nebius.com/compute/virtual-machines/docker-subnet-conflict

### 16. MTU mismatch (ND017)

- **Cause:** the container's MTU (1500) is larger than what a VPN, tunnel or overlay path carries and ICMP "fragmentation needed" is dropped, so small packets work and large ones stall. In Docker forum 131403 a file upload through a VPN to a container failed, while the same upload to a non-container service worked. The fix is a lower MTU on the Docker network (`com.docker.network.driver.mtu`) or `--mtu`.
- **Frequency:** Docker forum 131403: 14,423 views, 8 posts. SO 73101754, "Docker change mtu on the fly?": 11 votes, 21,264 views. Several blog posts, no counts. Low volume.
- **Evidence needed:** link MTUs (bridge, uplink, VPN interface), a DF-bit probe with sizes if feasible.
- **Sources:** https://forums.docker.com/t/131403 · https://stackoverflow.com/questions/73101754

### 17. Host-published port used from another container (ND006, partial)

- **Cause:** the container uses `host:8081` instead of `service:8080`, or goes via the host's external IP, which can be blocked by host firewall rules (see #9). The answer to SO 42385977 explains that only internal ports are reachable between containers on a shared network. The existing ND006 covers the wrong-port form. The "via the host IP" form needs the firewall evidence from #9.
- **Frequency:** SO 41171115, "Why can't I curl one docker container from another via the host": 35 votes, 30,376 views. Docker forum 44045: 20,387 views. Low volume compared with #1 and #2.
- **Evidence needed:** port mappings, target port, whether the host IP is one of the host's addresses.
- **Sources:** https://stackoverflow.com/questions/41171115 · https://forums.docker.com/t/44045

### 18. IPv6/IPv4 mismatch (ND014)

- **Cause:** Node 17 changed `dns.lookup()` to return addresses in resolver order (`verbatim`), so `localhost` can resolve to `::1` first, while the service listens on IPv4 only.
- **Frequency:** nodejs/node issue 40537, "'localhost' favours IPv6 in node v17, used to favour IPv4": 8 reactions, 12 comments. Issue 39987, "dns: default to verbatim=true in dns.lookup()": 5 reactions, 43 comments. Issue 40702: 8 reactions, 38 comments. MongoDB driver ticket NODE-4077. These are not Docker-specific. Docker-specific frequency: not measured.
- **Evidence needed:** DNS answers for `localhost` in the source netns, listener address families in the destination.
- **Sources:** https://github.com/nodejs/node/issues/40537 · https://github.com/nodejs/node/issues/39987 · https://jira.mongodb.org/browse/NODE-4077

### 19. Advertised-address redirect (NEW, low priority)

- **Cause:** the client connects to a bootstrap address, the server returns another address in its metadata (Kafka `advertised.listeners`), and that address is unreachable from the client's network. The first connection succeeds, which makes it look like a different bug. The Confluent post "Kafka listeners explained" describes this for Docker.
- **Frequency:** SO 59338321: 4 votes, 5,761 views. SO 47983937: 1 vote, 2,372 views. SO 42421448: 3 votes, 1,411 views. Small on Stack Overflow, but the Confluent post is widely cited (no count available).
- **Evidence needed:** the source's second connection target, from its socket table; the destination's configured advertised address (only visible through env var values or config, which conflicts with the "env keys only" policy). Probably out of scope for the MVP.
- **Sources:** https://www.confluent.io/blog/kafka-listeners-explained/ · https://stackoverflow.com/questions/59338321

### 20. Host to container IP on Docker Desktop (NEW, low priority)

- **Cause:** on Desktop for Mac and Windows, containers run in a VM, so container IPs (172.x) are not routable from the host. Only published ports work.
- **Frequency:** docker/for-mac issue 155, "Access the Containers from Host like on Linux": 235 reactions, 117 comments (open). SO 69143270, "Cannot access docker host from macos": 26 votes, 91,215 views (the question is the other direction, answer: `host.docker.internal`).
- **Evidence needed:** platform and the target IP's subnet. This is a host-to-container check, so NetDoctor should say "use a published port" rather than probe.
- **Sources:** https://github.com/docker/for-mac/issues/155

### Not measured: ND008, ND015, ND016, ND018

- **ND008 (destination not running):** it probably underlies many refused-connection posts, but those posts are titled after the crash or the app error, so I found no usable count.
- **ND015 (`internal: true`):** I found only questions about using it deliberately (SO 69544970, 5 votes, 7,223 views; SO 65784039, 11 votes, 16,896 views). No question about it breaking a connection.
- **ND016 (silent drop):** generic timeouts show up inside #9, #10, #15 and #16. I have no separate count.
- **ND018 (proxy):** Docker's CLI proxy docs confirm the client injects proxy env vars into containers. The high-view proxy questions I found are about builds (SO 27749193: 48 votes, 113,746 views), which are out of scope.

### Adjacent, out of scope (publish-time failures)

Two very high-view groups are about failing to bind a host port when starting a container, not about reaching a service. SO 46176584, "Bind for 0.0.0.0:4000 failed: port is already allocated": 340 votes, 610,348 views. SO 65272764, "Ports are not available... An attempt was made to access a socket in a way forbidden by its access permissions" (Windows excluded port ranges): 166 votes, 184,805 views; SO 57316744 (68 votes, 46,465 views) and SO 60830914 (17 votes, 75,311 views) are close variants. If NetDoctor ever diagnoses the host side, these would rank near the top, so it is worth a scope decision.

## Gaps in the current catalog

Proposed new rules, in priority order. IDs continue after ND018.

| Proposed | Rule | Evidence needed |
|---|---|---|
| ND019 | Port not published, or published on a different host port or address (host to container). Covers signature #6. | container `PortBindings` (HostIp, HostPort) and `ExposedPorts`; container listeners; host listener for the published port |
| ND020 | DNS server failure inside the container (SERVFAIL or timeout, unreachable upstream, VPN or stub-resolver mismatch, embedded DNS not answering). Covers #3. Keep separate from ND005 (NXDOMAIN). | container `ResolvConfPath` contents; UDP and TCP 53 probes from the source netns to each resolver; host resolver mode; daemon `dns` setting |
| ND021 | Host firewall rejects bridge-to-host traffic (`No route to host`, EHOSTUNREACH). Covers #9. | errno from the probe; a host listener that works from the host; ufw/firewalld state and zones; INPUT or nftables rules for the bridge |
| ND022 | No outbound NAT or forwarding for the container's subnet. Covers #10. | host sysctl `ip_forward`; daemon `iptables` and `firewall-backend`; POSTROUTING MASQUERADE for the subnet; external-IP probe vs gateway probe |
| ND023 | Docker Desktop `network_mode: host`: "host" means the VM. Covers #14. | platform, Desktop version and setting, `NetworkMode`, `PortBindings` |
| ND024 | Client resolver bypasses Docker DNS or keeps a stale IP. Covers #13. | source netns socket table (remote IPs) vs the destination's current IP; DNS answer from 127.0.0.11 |
| ND025 | Advertised-address redirect (research only, probably after v0.3). Covers #19. | second connection target from the socket table; advertised address config |

Changes to existing rules:

- **ND006:** add the "via the host's external IP" case (#17) and link it to ND021.
- **ND012:** keep it Linux and WSL2-without-Desktop only until a lab test shows what Desktop does with loopback-only host services.
- **ND016:** split by errno so ETIMEDOUT stays ND016 and EHOSTUNREACH goes to ND021.
- **ND005:** state that it fires only on NXDOMAIN, and add an explicit pointer to ND020 for other DNS failures.
- **ND007:** the message should name the host-vs-container case separately, because the fix differs (service name vs `host.docker.internal`).

## Name availability

Checked on 2026-11-13. Search queries contained only the project name.

| Where | Result | Severity for an open-source dev tool |
|---|---|---|
| GitHub | `gh search repos netdoctor --limit 20` returns 20 repos with "netdoctor" in the name or description, none large. Closest: `kosmos-io/netdoctor` (Go, Apache-2.0, 26 stars, last push 2024-12-29), a Kubernetes cluster network diagnosis tool whose own README calls it "NetDoctor"; the Go module proxy lists v0.0.1. `Guiiat/netdoctor` (TypeScript, MIT, 1 star, pushed 2026-10-14): a CLI for DNS, proxy, TCP, TLS and HTTP diagnosis. `sudharsanomprakash/kubevirt-netdoctor` (Go, builds `kubectl-netdoctor`). `Atul-k-m/netdoctor` (Python), `pponikiewski/netdoctor` (Rust, Windows), `x549d/ai-netdoctor`, `mrzroot/netdoctor-ir`, `George01230123/NetDoctor` (Windows tool). Also `heymaikol/network-doctor` and `databricks-solutions/network-doctor`. | Medium. Many same-purpose projects, none for Docker, none popular. A search for "netdoctor docker" will mix in unrelated results. |
| PyPI | `netdoctor` is taken: v0.1.1, MIT, uploaded 2026-06-28, repository `Sahilll15/netdoctor`, a network health-check CLI. `net-doctor` is free. | Low for a Go tool. It would matter only if NetDoctor ever ships a Python wrapper. |
| npm | `netdoctor` and `net-doctor` return 404 (free). | Low. |
| MCP Registry | `?search=netdoctor` and `?search=net-doctor` return 0 servers. | None. |
| Homebrew | No `netdoctor` formula in homebrew-core (API returns 404). A personal tap `bybyKD/homebrew-tap` ships a GoReleaser-built `netdoctor` formula (v1.0.0, "modern, cross-platform network diagnostics toolkit") and `bybyKD/scoop-bucket` a Scoop bucket. The source repo `bybyKD/netdoctor` returns 404 (private or removed). | Low to medium. The core name is free, but `brew install bybyKD/tap/netdoctor` exists, and a second Go binary called `netdoctor` can collide if both are installed. |
| pkg.go.dev | A `netdoctor` package search returns one result, `kubectl-netdoctor` from `sudharsanomprakash/kubevirt-netdoctor`. Module paths are namespaced by repo owner, so there is no hard conflict. | Low. |
| Commercial / trademark | Third-party aggregators list a US trademark "NETDOCTOR" (serial 90554897), Class 9 (software), with a registration (number 6898030, November 2022) owned by Riverbed Technology, Inc. A Justia snapshot still shows an older status (suspension letter, January 2022). I could not verify this at the USPTO: Justia returned 403 and the second aggregator was unreachable. Older NETDOCTOR / NET.DOCTOR / NET-DOCTOR records also exist (serials 78043036, 77271837, 85363183, 75244689, 77891190, 77753581); I did not check their status. SourceForge also lists old `netdoctor` and `netdoctor2` projects (2013, tiny). No active commercial product named NetDoctor turned up. | Unresolved, potentially serious. A registered Class 9 mark for software is the one conflict that could matter, and the owner is a network-performance vendor. Check USPTO TSDR before committing to the name. This is not legal advice. |

**Verdict:** the name is not blocked on any registry (npm, MCP Registry and Homebrew core are free), but it is crowded. At least eight GitHub projects use it for network diagnosis, one of them a Go tool with the exact name, and there is a probable registered trademark held by a network vendor. I would not treat it as free. If the trademark check cannot be cleared quickly, pick another name before the first release.

**Alternatives** (checked on npm, PyPI, Homebrew core and the MCP Registry; GitHub repo-name search returned nothing for all three; none of this is a trademark search):

| Name | npm | PyPI | brew core | MCP Registry | GitHub repo search | Note |
|---|---|---|---|---|---|---|
| `ctrdiag` | free | free | free | 0 | no repos | short, describes "container diagnose" |
| `ctrdoctor` | free | free | free | 0 | no repos | keeps the "doctor" idea |
| `containerdoctor` | free | free | free | 0 | no repos | clearest, longest to type |

`dockerdx` looked free on npm and PyPI but a few small GitHub repos use `DockerDX`, and I could not confirm Homebrew (503), so I dropped it. `netwhy` is used by three GitHub projects that do similar things.
