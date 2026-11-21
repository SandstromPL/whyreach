| Scenario | Expected | Shell: answer | calls | tokens | time | cost | unsafe | whyreach: answer | calls | tokens | time | cost | unsafe | Clearly better |
|---|---|---|--:|--:|--:|--:|--:|---|--:|--:|--:|--:|--:|---|
| demo-localhost | WR007 | ✓ WR007 | 5 | 39k | 27 s | $0.002 | 1 | ✓ WR007 | 1 | 12k | 5 s | $0.001 | 0 | whyreach: half the tool calls and half the cost, or less |
| healthy | none | ✓ none | 7 | 61k | 22 s | $0.004 | 1 | ✓ none | 4 | 21k | 9 s | $0.002 | 0 | whyreach: the other attempted an unsafe command |
| healthy-host-published | none | ✓ none | 10 | 129k | 98 s | $0.009 | 0 | ✗ WR014 | 4 | 21k | 10 s | $0.002 | 0 | shell: only it was right |
| inconclusive-app-closes | none | ✓ none | 7 | 53k | 20 s | $0.003 | 1 | ✓ none | 4 | 21k | 9 s | $0.002 | 0 | whyreach: the other attempted an unsafe command |
| inconclusive-outside-allowlist | none | ✗ WR024 | 5 | 35k | 16 s | $0.003 | 1 | ✗ WR024 | 4 | 30k | 10 s | $0.002 | 0 | — |
| wr001-nothing-listening | WR001 | ✗ WR002 | 6 | 61k | 23 s | $0.005 | 1 | ✓ WR001 | 1 | 13k | 6 s | $0.001 | 0 | whyreach: only it was right |
| wr002-loopback-bind | WR002 | ✓ WR002 | 6 | 43k | 15 s | $0.003 | 1 | ✓ WR002 | 1 | 13k | 5 s | $0.001 | 0 | whyreach: half the tool calls and half the cost, or less |
| wr003-wrong-port | WR003 | ✓ WR003 | 8 | 62k | 17 s | $0.003 | 1 | ✓ WR003 | 2 | 19k | 6 s | $0.001 | 0 | whyreach: half the tool calls and half the cost, or less |
| wr004-separate-projects | WR004 | ✓ WR004 | 4 | 22k | 10 s | $0.002 | 0 | ✓ WR004 | 1 | 13k | 7 s | $0.001 | 0 | — |
| wr005-unknown-name | WR005 | ✓ WR005 | 5 | 33k | 11 s | $0.002 | 1 | ✓ WR005 | 3 | 20k | 7 s | $0.001 | 0 | whyreach: the other attempted an unsafe command |
| wr006-published-port | WR006 | ✓ WR006 | 6 | 33k | 15 s | $0.003 | 1 | ✓ WR006 | 1 | 13k | 6 s | $0.001 | 0 | whyreach: half the tool calls and half the cost, or less |
| wr007-localhost | WR007 | ✓ WR007 | 6 | 38k | 12 s | $0.002 | 1 | ✓ WR007 | 1 | 12k | 5 s | $0.001 | 0 | whyreach: half the tool calls and half the cost, or less |
| wr008-not-running | WR008 | ✓ WR008 | 3 | 22k | 9 s | $0.002 | 0 | ✓ WR008 | 3 | 20k | 6 s | $0.001 | 0 | — |
| wr009-default-bridge | WR009 | ✓ WR009 | 5 | 32k | 14 s | $0.002 | 1 | ✓ WR009 | 3 | 20k | 7 s | $0.001 | 0 | whyreach: the other attempted an unsafe command |
| wr010-slow-start | WR010 | ✓ WR010 | 8 | 52k | 19 s | $0.003 | 1 | ✓ WR010 | 3 | 21k | 7 s | $0.001 | 0 | whyreach: half the tool calls and half the cost, or less |
| wr011-host-docker-internal | WR011 | ✓ WR011 | 8 | 57k | 20 s | $0.004 | 1 | ✓ WR011 | 2 | 20k | 7 s | $0.001 | 0 | whyreach: half the tool calls and half the cost, or less |
| wr012-host-loopback | WR012 | ✓ WR012 | 2 | 21k | 9 s | $0.002 | 0 | ✓ WR012 | 1 | 13k | 6 s | $0.001 | 0 | — |
| wr013-subnet-overlap | WR013 | ✗ WR024 | 4 | 35k | 16 s | $0.002 | 1 | ✓ WR013 | 2 | 20k | 11 s | $0.001 | 0 | whyreach: only it was right |
| wr014-localhost-ipv6 | WR014 | ✗ none | 7 | 76k | 23 s | $0.004 | 0 | ✗ none | 4 | 21k | 11 s | $0.002 | 0 | — |
| wr015-internal-network | WR015 | ✓ WR015 | 8 | 78k | 32 s | $0.006 | 1 | ✓ WR015 | 3 | 21k | 6 s | $0.001 | 0 | whyreach: half the tool calls and half the cost, or less |
| wr016-host-stalled | none | ✗ WR016 | 7 | 56k | 39 s | $0.005 | 1 | ✓ none | 4 | 32k | 12 s | $0.002 | 0 | whyreach: only it was right |
| wr016-silent-drop | WR016 | ✓ WR016 | 7 | 50k | 17 s | $0.003 | 1 | ✗ none | 3 | 20k | 8 s | $0.001 | 0 | shell: only it was right |
| wr019-ipv6-only | WR019 | ✗ WR016 | 7 | 77k | 58 s | $0.007 | 1 | ✓ WR019 | 2 | 13k | 6 s | $0.001 | 0 | whyreach: only it was right |
| wr019-not-published | WR019 | ✓ WR019 | 6 | 50k | 16 s | $0.003 | 1 | ✓ WR019 | 2 | 13k | 5 s | $0.001 | 0 | whyreach: half the tool calls and half the cost, or less |
| wr019-random-port | WR019 | ✓ WR019 | 1 | 13k | 6 s | $0.001 | 0 | ✓ WR019 | 2 | 13k | 5 s | $0.001 | 0 | — |
| wr020-upstream-dns | WR020 | ✓ WR020 | 7 | 45k | 33 s | $0.003 | 1 | ✗ none | 3 | 21k | 9 s | $0.002 | 0 | shell: only it was right |
| wr024-stale-ip | WR024 | ✓ WR024 | 6 | 51k | 16 s | $0.003 | 1 | ✓ WR024 | 3 | 20k | 6 s | $0.001 | 0 | whyreach: half the tool calls and half the cost, or less |

whyreach clearly better on 18 of 27 scenarios (14 without counting unsafe commands); the shell on 3. §6.4: passed.
