# Adapted Core functional tests

Bitcoin Core functional tests that cannot pass AS WRITTEN with the pinned
framework (refs/bitcoin at the project's pin) -- not on our node and not on
Core's own bitcoind -- because a framework step contradicts what the test
asserts. Each file here imports Core's test class unchanged and replaces only
the framework step named below; every assertion is Core's.

Run them with `scripts/conformance.sh --adapted` (all of them) or by path,
`scripts/conformance.sh tests/functional-adapted/<name>.py`. Their RESULT
lines and tmpdirs carry the path, so they never collide with the original of
the same name in one run. Before a file is added here, the original must be
shown to fail on Core's own binary (`BL_CONFORMANCE_REFERENCE=v28.2`) and the
copy to PASS there.

| test | original fails at (ours AND Core v28.2) | framework steps replaced |
|---|---|---|
| feature_bind_port_discover.py | feature_bind_port_discover.py:66 `assert found_addr1` | test_node.py:274-277 appends `-bind=0.0.0.0:P` and `-bind=127.0.0.1:T=onion` to a node given no `-bind`, so Core's `bind_on_any` (init.cpp:2163) is false and `Discover()` (init.cpp:2193-2197) never runs; test_framework.py:360-378 `setup_network` dials 127.0.0.1 ports that nodes bound to 1.1.1.1 do not listen on |
| feature_bind_port_externalip.py | test_framework.py:583 (`connect_nodes` from `setup_network`, predicate not true) | the same two steps |

Both need 1.1.1.1 (and 2.2.2.2) on an interface: conformance.sh grants
`--cap-add NET_ADMIN` to the conformance container for these two names only
and adds the addresses there (scripts/conformance-local-addresses.py).

The two originals are classified SKIP-by-framework in the functional sweep
(decided 2026-09-30); these copies are their oracle.
