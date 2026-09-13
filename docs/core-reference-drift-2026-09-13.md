# Core reference drift survey — 2026-09-13

`refs/bitcoin` is pinned at `d3056bc` (2026-03-09). This survey fetched Core's
`master` (`17817818da`, 2026-09-12, 50,543 commits ahead of the merge base)
WITHOUT moving the pin, and read the diff of the consensus, policy and
chain-parameter files. Nothing here changes what the node does; it is the
input for the decision to bump the pin.

## Verdict

No new consensus rule has been merged on Core `master` since the pin. BIP54
(the consensus cleanup) is still not merged; `MAX_TX_LEGACY_SIGOPS` (2,500)
remains the policy-only limit the pin already carries, now surfaced as the
reject reason `non-witness sigops exceed bip54 limit`. The pin stays a valid
consensus oracle. Bumping it is a decision about chain parameters and policy,
not about validity rules.

## What changed that touches us

| area | Core merge | effect on this node |
|---|---|---|
| Taproot deployment removed | #26201 (2026-03-20) | `GetBlockScriptFlags` now starts from `P2SH \| WITNESS \| TAPROOT` from genesis, with the mainnet exception block (`0000...e395ad`, height 692,261) validated with `P2SH \| WITNESS`. `DEPLOYMENT_TAPROOT` is gone from `vDeployments` and `deploymentinfo.cpp`; `MinBIP9WarningHeight` moved to 711,648 (mainnet) and 2,013,984 (testnet3). We gate `SCRIPT_VERIFY_TAPROOT` on the buried height (`src/validation/block.lisp`), which agrees with Core on every block of every live chain and differs only on a hypothetical fork below the height that carries a v1 witness spend. `getdeploymentinfo` still reports taproot as `bip9` on our side (`src/validation/versionbits.lisp`); Core master no longer lists it at all. |
| Chain parameters | #36196 (2026-09-11, "pre-32.0") | `nMinimumChainWork`, `defaultAssumeValid` (mainnet 966,143; testnet3 5,128,859; testnet4 151,604), new assumeutxo snapshots (mainnet 965,000; testnet3 5,125,000; testnet4 150,000), chain-tx data, headers-sync commitment periods, fixed seeds. Ours in `src/util/chainparams.lisp` are the pin's values (mainnet assumevalid 938,343). Stale but safe: an older assumevalid only means more script checks. |
| Deployment options | #35335 | `ApplyDeploymentOptions` lets unit tests move buried heights on any chain. Test-only surface. |
| Non-standard input reasons | #29060 (2026-03-19) | `AreInputsStandard` became `ValidateInputsStandardness` returning a `TxValidationState` with per-input debug messages (`input N script unknown`, `p2sh scriptsig malformed`, `p2sh redeemscript sigops exceed limit`). Same verdicts, richer reject strings; `testmempoolaccept` and the functional tests at a bumped pin will assert on them. |
| Mempool-based fee estimation | #34075 (2026-08-21) | New `policy/fees/mempool_estimator.*`, `estimator_man.*`, `estimator_args.*`; `block_policy_estimator` renamed and rewired; `MempoolTransactionsRemovedForBlock` replaces the direct `removeForBlock` call in `ConnectTip`. `estimatesmartfee` output shape may change. Policy, not consensus. |
| PSBTv2 | #21283 (2026-05-05) | BIP 370. Wallet/RPC surface. |
| Package RBF | #35017 | "remove all subsequent tx in pkg on failure". Policy. |
| Mining | #34860 | scriptSig always padded at low heights; `include_dummy_extranonce` dropped from `getblocktemplate`/mining interface. |
| Coins / index | #35465, #35572, #34897 | regular chainstate compaction; DB-only cursor; indexes no longer commit ahead of the flushed chainstate (we ported the last one's shape in GA11). |
| ConnectBlock | #35295 | prevouts fetched in parallel. Performance only. |
| Merkle | #35161 | documents the `mutated` invariant; no behaviour change. |

Everything else in the consensus/policy diff is IWYU, `inline constexpr`
spelling, logging API renames and refactors with no behavioural content.

## Recommendation

Keep the pin for the current functional-test sweep (the suite under
`refs/bitcoin/test/functional` must match the binary's expectations, and
Core's tests at `master` already assert the new reject strings and the
estimator shape). Bump the pin as its own round after the sweep, in this
order: chain parameters (#36196), taproot burial (#26201), standardness
reasons (#29060), fee estimator (#34075). Each is a port with Core lines in
the commit and a pre-fix-red test, as in GA11.
