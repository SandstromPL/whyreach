| Case | Label | Probe containers on | Default config | Status |
|---|---|---|---|---|
| so-73415151 | WR006 | right: WR006 (high) | right: WR006 (high) | scored |
| so-69437475 | WR007 | right: WR007 (high) | right: WR007 (high) | scored |
| so-71877179 | WR009 | right: WR009 (medium) | right: WR009 (medium) | scored |
| so-75237114 | WR007 | right: WR007 (high) | right: WR007 (high) | scored |
| so-78901825 | WR007 | right: WR007 (high) | right: WR007 (high) | scored |
| so-65766633 | WR019 | right: WR019 (high) | right: WR019 (high) | scored |
| so-65596446 | WR008 | right: WR008 (high) (also WR006) | right: WR008 (high) (also WR006) | scored |
| so-78873209 | WR007 | right: WR007 (high) | right: WR007 (high) | scored |
| so-69061621 | WR006 | right: WR006 (high) | right: WR006 (high) | scored |
| so-70088535 | WR007 | right: WR007 (high) | right: WR007 (high) | scored |
| so-78151189 | WR019 | right: WR019 (high) | right: WR019 (high) | scored |
| so-69356818 | WR019 | right: WR019 (medium) | right: WR019 (medium) | scored |
| forum-127146 | outside |  |  | not reproduced: the question's only failure is HAProxy's alert that a backend named app (not in the config shown) has no server; the servers the question names were reachable, and after its one more try the reproducer found no connection in the question it could rebuild as failing |
| forum-139130 | ambiguous |  |  | not reproduced: the question's only failure is an HTTP 503 from the proxy, which accepted the connection; after its one more try the reproducer found no connection the question says failed (the label is ambiguous too) |
| forum-121911 | WR007 | right: WR007 (high) | right: WR007 (high) | scored |
| gh-takwerx-infra-TAK-372 | WR007 | right: WR007 (medium) | right: WR007 (medium) | scored |
| gh-Anagamedina-ft_transcendence-309 | outside |  |  | not reproduced: the failure lives in the address nginx cached at its start; Compose can't recreate the backend after nginx starts, and the rebuild's workaround (that address written into nginx's config, and to as an address) changes what the app named, against the rebuild rules |
| gh-hs3180-disclaude-4608 | WR001 | right: WR001 (high) | right: WR001 (high) | scored |
| gh-coryfinnegan-CollectionMaxxing-819 | WR010 |  |  | not reproduced: the issue as opened reports a stale backup, not a failing connection; the rebuild's backup reached Postgres, and after its one more try the reproducer found no connection the issue says failed (the label's startup race comes from a maintainer's later comment) |
