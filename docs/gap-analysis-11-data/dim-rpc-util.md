# GA11 dimension 8 — rpc/util + core_io + fee estimation + versionbits reporting

Survey only: nothing under `src/` or `tests/` was changed. Findings: `dim-rpc-util.json`
(17 findings — 0 S1, 7 S2, 10 S3; 16 executed, 1 read-both-trees).

Oracle: Bitcoin Core `refs/bitcoin/` at the pinned revision. Every probe ran in this checkout's
own warm container (`bitcoin-lisp-dev-50eb89c4558b`) through `scripts/dev.sh eval`, driving RPCs
with `bl.rpc:dispatch-rpc-method` over `%normalize-rpc-params` so the top-level `[]` and explicit
`false` sentinels behave as they do on the wire.

## What was compared, and how

| Core surface | ours | method |
|---|---|---|
| `rpc/util.cpp` AmountFromValue / ParseFixedPoint | `src/rpc/amounts.lisp` | 19 string spellings executed |
| `rpc/util.cpp` ParseHashV / ParseHexV | `valid-hex-hash-p` + per-handler messages | 7 RPCs driven with Core's own test inputs |
| `rpc/util.cpp` ParseConfirmTarget, ParseVerbosity | `%parse-verbosity`, per-handler bounds | executed (bounds match, 1..1008) |
| `rpc/util.cpp` RPCHelpMan::Check / RPCArg::MatchesType | none | 8 type mismatches + arity, executed |
| `core_io.cpp` ScriptToAsmStr | `bl.val:disassemble-script` | 8 byte vectors executed |
| `core_io.cpp` ScriptToUniv | 4 open-coded copies | decodescript on 4 script classes executed; prevout path read |
| `core_io.cpp` TxToUniv | `tx-to-json` / `input-to-json` / `output-to-json` | read side by side, field for field |
| `core_io.cpp` DecodeHexTx / DecodeTx | `bl.ser:read-transaction` | trailing-byte + ambiguous-input probes executed |
| `core_io.cpp` ValueFromAmount / FormatMoney | `satoshi->btc` / `format-money` | 11 amounts executed (FormatMoney is faithful) |
| `rpc/rawtransaction_util.cpp` ConstructTransaction / AddInputs / AddOutputs / ParseOutputs | `createrawtransaction` + `parse-outputs` | 8 argument shapes executed |
| `rpc/fees.cpp` estimatesmartfee / estimaterawfee | `src/rpc/rawtransaction.lisp:206,916` | executed end to end, empty and populated |
| `policy/fees/block_policy_estimator.cpp` | `src/mempool/block-policy-estimator.lisp` | constants table checked line by line; every TxConfirmStats method and the three estimate* entry points read side by side; a 400-block synthetic replay run twice |
| `versionbits.cpp` Info / statistics, `deploymentinfo.cpp` | `src/validation/versionbits.lisp`, `%bip9-deployment` | 300-block synthetic signalling chain, states DEFINED / STARTED / LOCKED_IN |

## What held up

The estimator's arithmetic is faithful. Every constant in `block_policy_estimator.h:152-199`
matches, and `Record`, `ClearCurrent`, `UpdateMovingAverages`, `removeTx`, `EstimateMedianVal`,
`estimateCombinedFee`, `estimateConservativeFee` and `estimateSmartFee` were read against Core
line by line with no divergence found — including the two easy traps, the `partialNum <
sufficientTxVal / (1 - decay)` bucket-merging rule and the `passing` latch that records only the
first failing range. `MaxUsableEstimate`, the 1→2 target substitution and the `returnedTarget`
reporting are all correct. `FormatMoney` is byte-exact. `ParseConfirmTarget`'s bound is Core's
`HighestTargetTracked(LONG_HALFLIFE)` = 1008, not a hardcoded constant. The `MAX_FILE_AGE`
(60 h) and regtest-only `-acceptstalefeeestimates` rules are present and correct. The buried
and BIP9 deployment objects in `getdeploymentinfo` are otherwise field-for-field Core, including
the two off-by-ones the file's own comments record.

The three S2s that matter most are not in the estimator's maths but in what feeds it and in what
the RPC layer accepts and prints.

## Not covered — and who inherits it

- **`fee_estimates.dat` wire format.** Ours is a deliberate own-format v2 file with a CRC32
  (documented at `block-policy-estimator.lisp:637`); no interop with Core's
  `CURRENT_FEES_FILE_VERSION` 309900 stream was attempted. → dimension 6 (never-opened files),
  or a storage reader.
- **`FlushUnconfirmed` and the estimator across a reorg.** The `processBlock` height guard is
  present; the reorg `removeTx` path was not driven. → dimension 9 (validation / chain seam).
- **`%feerate-from-value` (the sat/vB `decimals=3` parser) and the whole `SetFeeEstimateMode` /
  `InterpretFeeEstimationInstructions` option block.** Read, not probed, and they live in the
  wallet. → dimension 5 (wallet persistence + wallet RPCs).
- **`HexToPubKey`'s three distinct messages and `AddAndGetMultisigDestination` beyond
  `createmultisig`.** Core exercises them through `fundrawtransaction` `solving_data`.
  → dimension 5.
- **`InferDescriptor` itself** — the *content* of the `desc` strings we do emit was never
  compared. → dimension 1 (descriptors + signing).
- **`GBTStatus` / `ComputeBlockVersion` / `-vbparams`** — the getblocktemplate half of
  versionbits. → a mining reader.
- **`rpc_help.py`'s help-text contract** and the named-argument transform beyond GA10's fix.

## Probe caveat — an SBCL trap, not just a probe bug

`(coerce X '(vector (unsigned-byte 8)))` inside a local function that is called with vectors of
several statically-known lengths returns an array of the FIRST call site's length, zero-padded,
with no error: SBCL derives the argument length from the call sites and the `coerce` transform
allocates that fixed size. Reproduced on this image (SBCL 2.6.5):

    (flet ((f (x) (length (coerce x '(vector (unsigned-byte 8))))))
      (list (f <22-byte>) (f <1-byte>) (f <3-byte>)))   ; => (22 22 22)

With the short vector first it correctly gives `(1 3 22)`. A `(declare (type vector x))` and a
`(vector (unsigned-byte 8) *)` result type do not help. It made one ASM probe read as though
every script were 22 bytes long; every ASM result reported was re-run with
`(make-array n :element-type '(unsigned-byte 8) :initial-contents ...)`.

The four production uses of this form — `src/zmq.lisp:182`, `src/crypto/address.lisp:340`,
`src/rpc/output-script.lisp:30`, `src/validation/script.lisp:207` — were checked and are correct
(`%multisig-redeem-script` returns 37 / 71 / 105 bytes for 1-of-1 / 2-of-2 / 2-of-3), but the
form is a landmine for any future helper. Recorded as lesson
`sbcl-coerce-derives-wrong-vector-length`.
