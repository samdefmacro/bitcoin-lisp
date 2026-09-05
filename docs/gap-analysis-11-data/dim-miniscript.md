# GA11 dimension: miniscript — coverage note

Ours: `src/validation/miniscript.lisp` (1,994 lines), its descriptor callers in
`src/rpc/descriptors.lisp`, and its two signing/sizing callers in
`src/rpc/rawtransaction.lisp:469` and `src/wallet/wallet-spend.lisp:489`.
Core: `refs/bitcoin/src/script/miniscript.{h,cpp}`, the miniscript half of
`refs/bitcoin/src/script/descriptor.cpp` and `sign.cpp`, and the vectors in
`refs/bitcoin/src/test/miniscript_tests.cpp`.

Findings: `dim-miniscript.json` — 5 S2, 5 S3, 0 S1. All ten were reached by
running code in the project container (warm image, `scripts/dev.sh eval`).

## The oracle that was run

The 91 `Test("...")` vectors in `miniscript_tests.cpp:501-700` were extracted
verbatim, parsed in Lisp, and replayed in **both** contexts (182 runs). Each run
reproduced Core's own `Test()` assertions: parseability, `IsValid`,
`IsValidTopLevel`, the exact expected script hex, cached-vs-recomputed script
size, `IsNonMalleable`, `NeedsSignature`, the `k` (timelock-mix) property,
`GetOps`, `GetStackSize`, `GetWitnessSize`, `GetExecStackSize`, and the
`FromScript` round trip. The file's separate unit vectors were run too: the
non-minimal-push script, the non-minimal `VERIFY` script, the MINIMALIF `thresh`,
the four duplicate-key cases, the `FindInsaneSub` case, and the four
sign-prefixed number cases.

**Result: 167 of 182 runs matched Core exactly.** All 15 failures were the same
thing — tapscript `FromScript` returning NIL (finding `8c3b8174`).

## What is faithful (verified by execution, not by reading)

`SanitizeType`; the entire `ComputeType` calculus for all 26 fragments,
including the `thresh` timelock accumulator and the P2WSH-vs-tapscript `d:`/`u`
split; `ComputeScriptLen`; script generation in both contexts, including Core's
"in Tapscript keys always serialize as x-only" rule and the `v:` VERIFY-form
folding; `CalcOps`; `CalcStackSize` (the whole `SatInfo` netdiff/exec semiring);
`CalcWitnessSize`; `CheckOpsLimit`; `CheckStackSize` in both its P2WSH
(stack-items) and tapscript (exec-depth) forms; `IsValidTopLevel`,
`IsNonMalleable`, `NeedsSignature`, `CheckTimeLocksMix`, `CheckDuplicateKey`,
`IsSane`, `IsNotSatisfiable`; `FindInsaneSub`'s post-order choice of the
*deepest* insane sub; and the descriptor-level `IsSane` error-branch order.

`ToString` was checked by re-parsing all 107 valid vectors: zero produced a
different script, and the 25 textual differences are all Core's own sugar
normalizations (`c:pk_k`→`pk`, `c:pk_h`→`pkh`, `or_i(0,X)`→`l:`,
`and_v(X,1)`→`t:`), confirmed line by line against `miniscript.h:900-940`.

`ProduceInput` was diffed clause by clause against `miniscript.h:1245-1440` and
matches Core for every fragment except the missing `MULTI_A`.

## Shape of the findings

The type system, the sizing arithmetic and the script compiler — the parts that
are pure functions of the expression — are essentially exact. Everything found
sits at the **edges**: the parser's input validation, the inference decoder's
tapscript and minimality arms, the satisfier's `multi_a` hole, and the two
places where a descriptor's key *expressions* (rather than key bytes) quietly
disable a check. Three of the five S2s are the project's recurring
"correct code, no caller" shape:

- `1141db2b` — tapscript miniscript exists and works, but `tr-leaf-satisfaction`
  never calls it, and its docstring still claims the feature is absent.
- `c7fe77bf` — `ms-from-script` records a `pk_h` hash and the docstring says a
  satisfier looks the key up by it; no satisfier does.
- `05af23cd` — the `MaxScriptSize` half of `IsValid` was added, but it reads a
  script size that is always 0 for exactly the inputs that reach the RPC.

## Not covered — and who inherits it

| gap | inherits |
|---|---|
| Differential fuzzing against Core's binary (`src/test/fuzz/miniscript.cpp`); no random-expression comparison was run | GA11 differential-harness lane |
| End-to-end execution of a produced witness through our script interpreter (stacks were compared against Core's *algorithm*, never run) | script-interpreter dimension |
| How a miniscript descriptor registers key hashes and taproot spend data in the signing provider (`MiniscriptDescriptor::MakeScripts`, descriptor.cpp:1626-1641) — in particular whether a tapscript `pkh()` leaf registers `Hash160(XOnlyPubKey)` rather than the 33-byte key id | descriptors + signing dimension |
| BIP389 multipath key-vector length matching inside a miniscript (descriptor.cpp:2640-2650) | descriptors + signing dimension |
| The satisfier's `estimating` / `Availability::MAYBE` mode — it has no caller anywhere in `src/`, so there is no behaviour to compare | (dead code; note only) |
| Core's four `SanitizeType` `CHECK_NONFATAL`s we do not assert (`d`/`f` conflict, `V`⇒`f`, `K`⇒`s`, `z`⇒`m`) — internal consistency assertions; all 91 vectors agree, so nothing to report | (no finding) |
| `node_deep_destruct`-style stack safety (miniscript_tests.cpp:730): our tree walks are plain recursion where Core's are explicit stacks, but the cubic cost of `d722b087` makes a deep tree unreachable long before the control stack matters | re-test together with the `d722b087` fix |
