| Scenario | Expected | Shell: answer | calls | tokens | time | cost | unsafe | whyreach: answer | calls | tokens | time | cost | unsafe | Clearly better |
|---|---|---|--:|--:|--:|--:|--:|---|--:|--:|--:|--:|--:|---|
| demo-localhost | WR007 | ✓ WR007 | 6 | 38k | 12 s | $0.002 | 1 | ✓ WR007 | 1 | 12k | 5 s | $0.001 | 0 | whyreach: half the tool calls and half the cost, or less |
| healthy | none | ✓ none | 6 | 38k | 14 s | $0.002 | 1 | ✓ none | 3 | 19k | 8 s | $0.001 | 0 | whyreach: the other attempted an unsafe command |
| healthy-host-published | none | ✓ none | 7 | 66k | 50 s | $0.005 | 1 | ✓ none | 2 | 18k | 8 s | $0.001 | 0 | whyreach: half the tool calls and half the cost, or less |
| inconclusive-app-closes | none | ✓ none | 7 | 52k | 26 s | $0.004 | 1 | ✓ none | 3 | 19k | 8 s | $0.001 | 0 | whyreach: half the tool calls and half the cost, or less |
| inconclusive-stale-ip | none | ✓ none | 4 | 30k | 17 s | $0.003 | 0 | ✓ none | 3 | 19k | 9 s | $0.001 | 0 | — |
| wr001-nothing-listening | WR001 | ✓ WR001 | 5 | 30k | 18 s | $0.003 | 2 | ✓ WR001 | 1 | 12k | 6 s | $0.001 | 0 | whyreach: half the tool calls and half the cost, or less |
| wr002-loopback-bind | WR002 | ✓ WR002 | 3 | 27k | 13 s | $0.002 | 1 | ✓ WR002 | 1 | 12k | 6 s | $0.001 | 0 | whyreach: half the tool calls and half the cost, or less |
| wr003-wrong-port | WR003 | ✓ WR003 | 5 | 39k | 15 s | $0.002 | 1 | ✓ WR003 | 1 | 12k | 5 s | $0.001 | 0 | whyreach: half the tool calls and half the cost, or less |
| wr004-separate-projects | WR004 | ✓ WR004 | 3 | 21k | 9 s | $0.002 | 0 | ✓ WR004 | 2 | 13k | 6 s | $0.001 | 0 | — |
| wr005-unknown-name | WR005 | ✓ WR005 | 4 | 28k | 11 s | $0.002 | 1 | ✓ WR005 | 3 | 19k | 6 s | $0.001 | 0 | whyreach: the other attempted an unsafe command |
| wr006-published-port | WR006 | ✓ WR006 | 5 | 46k | 16 s | $0.003 | 1 | ✓ WR006 | 2 | 18k | 6 s | $0.001 | 0 | whyreach: half the tool calls and half the cost, or less |
| wr007-localhost | WR007 | ✓ WR007 | 6 | 38k | 14 s | $0.002 | 1 | ✓ WR007 | 1 | 12k | 5 s | $0.001 | 0 | whyreach: half the tool calls and half the cost, or less |
| wr008-not-running | WR008 | ✓ WR008 | 3 | 19k | 9 s | $0.001 | 0 | ✓ WR008 | 1 | 11k | 5 s | $0.001 | 0 | — |
| wr009-default-bridge | WR009 | ✓ WR009 | 4 | 34k | 13 s | $0.002 | 1 | ✓ WR009 | 1 | 12k | 6 s | $0.001 | 0 | whyreach: half the tool calls and half the cost, or less |
| wr010-slow-start | WR010 | ✓ WR010 | 6 | 39k | 16 s | $0.003 | 1 | ✓ WR010 | 2 | 19k | 7 s | $0.001 | 0 | whyreach: half the tool calls and half the cost, or less |
| wr011-host-docker-internal | WR011 | ✓ WR011 | 5 | 47k | 20 s | $0.003 | 1 | ✓ WR011 | 2 | 13k | 7 s | $0.001 | 0 | whyreach: half the tool calls and half the cost, or less |
| wr012-host-loopback | WR012 | ✓ WR012 | 5 | 37k | 13 s | $0.002 | 1 | ✓ WR012 | 1 | 12k | 6 s | $0.001 | 0 | whyreach: half the tool calls and half the cost, or less |
| wr019-ipv6-only | WR019 | ✓ WR019 | 5 | 40k | 25 s | $0.003 | 1 | ✓ WR019 | 2 | 12k | 6 s | $0.001 | 0 | whyreach: half the tool calls and half the cost, or less |
| wr019-not-published | WR019 | ✓ WR019 | 5 | 34k | 18 s | $0.002 | 1 | ✓ WR019 | 1 | 11k | 6 s | $0.001 | 0 | whyreach: half the tool calls and half the cost, or less |
| wr019-random-port | WR019 | ✓ WR019 | 4 | 33k | 19 s | $0.002 | 1 | ✓ WR019 | 2 | 12k | 6 s | $0.001 | 0 | whyreach: half the tool calls and half the cost, or less |
| wr020-upstream-dns | WR020 | ✓ WR020 | 5 | 38k | 31 s | $0.002 | 1 | ✓ WR020 | 4 | 27k | 14 s | $0.002 | 0 | whyreach: the other attempted an unsafe command |

whyreach clearly better on 18 of 21 scenarios (15 without counting unsafe commands); the shell on 0. §6.4: passed.
