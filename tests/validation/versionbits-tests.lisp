(in-package #:bitcoin-lisp.tests)

;;;; BIP9 / versionbits — the reporting half.
;;;;
;;;; ⚠️ Scope, asserted here as well as in the source: this machinery computes
;;;; and REPORTS state and decides nothing. The buried activation heights in
;;;; validation/block.lisp remain the only thing that says when a rule applies
;;;; to a block, because two live nodes are synced to chains whose activation
;;;; decisions must not move.

(def-suite :versionbits-tests
  :description "BIP9 threshold state and its getdeploymentinfo reporting"
  :in :bitcoin-lisp-tests)

(in-suite :versionbits-tests)

(defun %dep (name network)
  "NETWORK's deployment called NAME. One reach for the whole file: the lookup
is internal to BL.VAL (getdeploymentinfo walks the whole list instead), and
eleven copies of the same :: is what the structural ratchet exists to collapse."
  (bl.val::versionbits-deployment name network))

(test versionbits-special-start-times-short-circuit
  "ALWAYS_ACTIVE and NEVER_ACTIVE are answered before any chain walk
(versionbits.cpp:33-40), which is what lets them be evaluated with no block
index at all."
  (let ((always (%dep "taproot" :regtest))
        (never (%dep "testdummy" :mainnet)))
    (is (= bl.val:+vb-always-active+
           (bl.val:vb-deployment-start-time always)))
    (is (eq :active (bl.val:versionbits-state nil nil always)))
    (is (= bl.val:+vb-never-active+
           (bl.val:vb-deployment-start-time never)))
    (is (eq :failed (bl.val:versionbits-state nil nil never)))))

(test versionbits-table-is-per-chain
  "⚠️ The window and threshold DIFFER PER CHAIN, and a chain-blind table gets
exactly this wrong: regtest counts over 144 blocks needing 108, where mainnet
counts over 2016 needing 1815 (kernel/chainparams.cpp:106-107 vs :590-591).
Transcription errors here are invisible until a functional test on regtest
disagrees about when a fork locks in."
  (flet ((dep (net name) (%dep name net)))
    ;; Core's five chains, the values that differ between them.
    (is (= 2016 (bl.val:vb-deployment-period (dep :mainnet "taproot"))))
    (is (= 1815 (bl.val:vb-deployment-threshold (dep :mainnet "taproot"))))
    (is (= 1512 (bl.val:vb-deployment-threshold (dep :testnet3 "taproot"))))
    (is (= 1512 (bl.val:vb-deployment-threshold (dep :testnet4 "taproot"))))
    (is (= 1815 (bl.val:vb-deployment-threshold (dep :signet "taproot"))))
    (is (= 144 (bl.val:vb-deployment-period (dep :regtest "taproot"))))
    (is (= 108 (bl.val:vb-deployment-threshold (dep :regtest "taproot"))))
    ;; Every chain uses bit 2 for taproot and bit 28 for testdummy.
    (dolist (net '(:mainnet :testnet3 :testnet4 :signet :regtest))
      (is (= 2 (bl.val:vb-deployment-bit (dep net "taproot"))))
      (is (= 28 (bl.val:vb-deployment-bit (dep net "testdummy")))))
    ;; Only mainnet delays taproot's activation past lock-in
    ;; (chainparams.cpp:113 vs :244/:352/:503/:589).
    (is (= 709632 (bl.val:vb-deployment-min-activation-height
                   (dep :mainnet "taproot"))))
    (dolist (net '(:testnet3 :testnet4 :signet :regtest))
      (is (= 0 (bl.val:vb-deployment-min-activation-height
                (dep net "taproot")))))
    ;; And only regtest's testdummy is drivable — everywhere else it is
    ;; NEVER_ACTIVE, which is what keeps it out of getdeploymentinfo.
    (is (= 0 (bl.val:vb-deployment-start-time (dep :regtest "testdummy"))))
    (dolist (net '(:mainnet :testnet3 :testnet4 :signet))
      (is (= bl.val:+vb-never-active+
             (bl.val:vb-deployment-start-time (dep net "testdummy")))))))

(test getdeploymentinfo-reports-taproot-as-bip9-not-buried
  "Core carries taproot as a BIP9 deployment in all five chain parameter sets,
so getdeploymentinfo gives it a bip9 object (rpc/blockchain.cpp:1307-1359). We
reported \"buried\" on all five, so a caller reading this to learn the bit, the
window or the signalling count got nothing at all.

⚠️ The deployments come from the NODE's network, not from whatever *network*
happens to be bound to — MAKE-TEST-NODE builds a testnet3 node. Reading the
table by the ambient global instead would be the chain-blind bug this project
has already shipped twice."
  (let* ((node (make-test-node))
         (r (bl.rpc::rpc-getdeploymentinfo node nil))
         (deps (cdr (assoc "deployments" r :test #'string=)))
         (taproot (cdr (assoc "taproot" deps :test #'string=))))
    (is-true taproot "taproot is missing from getdeploymentinfo")
    (is (string= "bip9" (cdr (assoc "type" taproot :test #'string=))))
    (let ((bip9 (cdr (assoc "bip9" taproot :test #'string=))))
      (is-true bip9 "no bip9 object")
      ;; testnet3's taproot: a real window, no activation delay
      ;; (chainparams.cpp:241-246).
      (is (= 1619222400 (cdr (assoc "start_time" bip9 :test #'string=))))
      (is (= 1628640000 (cdr (assoc "timeout" bip9 :test #'string=))))
      (is (= 0 (cdr (assoc "min_activation_height" bip9 :test #'string=))))
      ;; An empty chain is before the start time, so DEFINED — and both states
      ;; are present and named with Core's strings.
      (is (string= "defined" (cdr (assoc "status" bip9 :test #'string=))))
      (is (string= "defined" (cdr (assoc "status_next" bip9 :test #'string=))))
      (is (integerp (cdr (assoc "since" bip9 :test #'string=))))
      ;; No signalling window while DEFINED (versionbits.cpp:210-212), so no
      ;; statistics and no bit.
      (is-false (assoc "statistics" bip9 :test #'string=))
      (is-false (assoc "bit" bip9 :test #'string=)))
    ;; Not active, and with no active_since there is no height key at all.
    (is (eq bl.rpc:+json-false+ (cdr (assoc "active" taproot :test #'string=))))
    (is-false (assoc "height" taproot :test #'string=))
    ;; The buried ones keep their shape.
    (let ((segwit (cdr (assoc "segwit" deps :test #'string=))))
      (is (string= "buried" (cdr (assoc "type" segwit :test #'string=)))))
    ;; testdummy is NEVER_ACTIVE on testnet3, and Core omits a disabled
    ;; deployment entirely (blockchain.cpp:1310).
    (is-false (assoc "testdummy" deps :test #'string=)
              "a NEVER_ACTIVE deployment must not be reported")))

(test versionbits-state-names-are-cores
  "The status strings getdeploymentinfo emits are Core's, exactly."
  (is (string= "defined" (bl.val:versionbits-state-name :defined)))
  (is (string= "started" (bl.val:versionbits-state-name :started)))
  (is (string= "locked_in" (bl.val:versionbits-state-name :locked-in)))
  (is (string= "active" (bl.val:versionbits-state-name :active)))
  (is (string= "failed" (bl.val:versionbits-state-name :failed))))

(test versionbits-elapsed-counts-the-way-core-counts
  "⚠️ Core computes blocks_in_period as `1 + (nHeight %% period)' and counts it
down, so ELAPSED ends at that value (versionbits.cpp:129-150). Writing it as
`(mod (1+ height) period)' agrees everywhere EXCEPT the last block of a period,
where Core reports a full period elapsed and that reports ZERO — and zero
elapsed means zero count and a `possible' computed from nothing.

regtest's period is 144, so height 143 is the case that separates them."
  (let ((dep (%dep "testdummy" :regtest)))
    (multiple-value-bind (cs last) (make-versionbits-chain 144 :signal-bit 28)
      ;; Height 143 is the last block of the first period.
      (is (= 143 (bl.store:block-index-entry-height last)))
      (multiple-value-bind (period threshold elapsed count possible)
          (bl.val:versionbits-statistics cs last dep)
        (declare (ignore possible))
        (is (= 144 period))
        (is (= 108 threshold))
        (is (= 144 elapsed) "the last block of a period must report a full period")
        ;; Every header signals bit 28, so the count is the whole window.
        (is (= 144 count))))
    ;; And one block earlier, elapsed is 143 — the formulas agree here.
    (multiple-value-bind (cs last) (make-versionbits-chain 143 :signal-bit 28)
      (multiple-value-bind (period threshold elapsed)
          (bl.val:versionbits-statistics cs last dep)
        (declare (ignore period threshold))
        (is (= 143 elapsed))))))

(test versionbits-statistics-with-no-block-returns-cores-empty-shape
  "Core returns before counting when there is no block index, with elapsed and
count zero and `possible' FALSE — default-initialised, never computed
(versionbits.cpp:126).

Without that early return the corrected elapsed formula is a trap: `(mod -1 144)'
is 143 in Common Lisp, so it would walk a NIL entry a whole period of times."
  (let ((dep (%dep "testdummy" :regtest)))
    (multiple-value-bind (period threshold elapsed count possible)
        (bl.val:versionbits-statistics nil nil dep)
      (is (= 144 period))
      (is (= 108 threshold))
      (is (= 0 elapsed))
      (is (= 0 count))
      (is (null possible)))))

(test versionbits-non-signalling-blocks-are-not-counted
  "CONDITION requires both the versionbits top bits and the deployment's own
bit; a chain that sets neither counts zero, which is what makes `possible' go
false once the window cannot be reached."
  (let ((dep (%dep "testdummy" :regtest)))
    (multiple-value-bind (cs last) (make-versionbits-chain 144)   ; top bits only, no bit 28
      (multiple-value-bind (period threshold elapsed count possible)
          (bl.val:versionbits-statistics cs last dep)
        (declare (ignore period threshold))
        (is (= 144 elapsed))
        (is (= 0 count))
        (is (null possible) "a full period with no signal cannot still be possible")))))

;;;; What the miner and getblocktemplate read out of the state machine
;;;; (Core ComputeBlockVersion versionbits.cpp:265-279, GBTStatus :228-257).

(test versionbits-mtp-is-computed-from-the-entry-alone
  "⚠️ COMPUTE-MEDIAN-TIME-PAST-FROM-ENTRY takes ONE argument. %VB-MTP passed it
the chain-state as well, so every state that needs a real MTP signalled
SB-INT:SIMPLE-PROGRAM-ERROR — and nothing noticed, because both callers reach
MTP only past a short circuit (ALWAYS_ACTIVE / NEVER_ACTIVE return first, and an
empty chain has no period boundary to walk to). A chain long enough to have one,
carrying a deployment with a real start time, is the case that executes it."
  (multiple-value-bind (cs last) (make-versionbits-chain 144 :signal-bit 28)
    (let ((testdummy (%dep "testdummy" :regtest)))
      (is (eq :started (bl.val:versionbits-state cs last testdummy))))))

(test compute-block-version-signals-started-and-locked-in-deployments
  "Core ComputeBlockVersion ORs in the bit of every STARTED or LOCKED_IN
deployment and of no other (versionbits.cpp:271-275). regtest's testdummy walks
all three states in three 144-block periods, so one chain length per state
covers the whole rule — and the ACTIVE case is the one that must NOT signal.

Every template this node produced carried the bare constant #x20000000, so a
regtest template of ours differed from Core's in the first field a miner reads."
  (flet ((version (n) (multiple-value-bind (cs last)
                          (make-versionbits-chain n :signal-bit 28)
                        (bl.val:compute-block-version cs last :regtest))))
    (is (= #x30000000 (version 144)) "STARTED must signal bit 28")
    (is (= #x30000000 (version 288)) "LOCKED_IN must signal bit 28")
    (is (= #x20000000 (version 432)) "ACTIVE must not signal"))
  ;; taproot is ALWAYS_ACTIVE on regtest and testdummy is NEVER_ACTIVE on the
  ;; four other chains, so those chains signal nothing at all — which is why
  ;; the hardcoded constant was right everywhere except regtest.
  (multiple-value-bind (cs last) (make-versionbits-chain 144 :signal-bit 28)
    (dolist (net '(:mainnet :testnet3 :testnet4 :signet))
      (is (= #x20000000 (bl.val:compute-block-version cs last net))
          "~A must not signal any deployment" net))))

(test versionbits-gbt-status-groups-by-state-and-sorts-by-name
  "GBTStatus splits the deployments into signalling / locked_in / active and
exposes DEFINED and FAILED to nobody (versionbits.cpp:240-255). Its groups are
std::maps keyed by the deployment name, so getblocktemplate's `rules' array is
in NAME order — taproot before testdummy, the reverse of the order the
deployments are declared in, which is what makes the sort observable."
  (flet ((names (list) (mapcar #'bl.val:vb-deployment-name list)))
    (multiple-value-bind (cs last) (make-versionbits-chain 144 :signal-bit 28)
      (multiple-value-bind (signalling locked-in active)
          (bl.val:versionbits-gbt-status cs last :regtest)
        (is (equal '("testdummy") (names signalling)))
        (is (null locked-in))
        (is (equal '("taproot") (names active)))))
    (multiple-value-bind (cs last) (make-versionbits-chain 288 :signal-bit 28)
      (multiple-value-bind (signalling locked-in active)
          (bl.val:versionbits-gbt-status cs last :regtest)
        (is (null signalling))
        (is (equal '("testdummy") (names locked-in)))
        (is (equal '("taproot") (names active)))))
    (multiple-value-bind (cs last) (make-versionbits-chain 432 :signal-bit 28)
      (multiple-value-bind (signalling locked-in active)
          (bl.val:versionbits-gbt-status cs last :regtest)
        (is (null signalling))
        (is (null locked-in))
        (is (equal '("taproot" "testdummy") (names active))
            "the groups are name-ordered, not declaration-ordered")))
    ;; A chain whose deployments are all DEFINED or FAILED reports nothing.
    (multiple-value-bind (cs last) (make-versionbits-chain 144)
      (multiple-value-bind (signalling locked-in active)
          (bl.val:versionbits-gbt-status cs last :mainnet)
        (is (null signalling))
        (is (null locked-in))
        (is (null active))))))

(test vb-gbt-rule-name-prefixes-only-mandatory-rules
  "gbt_rule_value prefixes `!' unless the deployment's VBDeploymentInfo says
gbt_optional_rule (deploymentinfo.cpp:11-20, rpc/mining.cpp:605-612). Both of
Core's deployments are optional, so the mandatory branch has no live vector —
binding the table empty is its positive control, and it also proves the default
for a name nobody classified is MANDATORY rather than a silent pass."
  (let ((taproot (%dep "taproot" :regtest))
        (testdummy (%dep "testdummy" :regtest)))
    (is-true (bl.val:vb-deployment-optional-rule-p taproot))
    (is-true (bl.val:vb-deployment-optional-rule-p testdummy))
    (is (string= "taproot" (bl.val:vb-gbt-rule-name taproot)))
    (is (string= "testdummy" (bl.val:vb-gbt-rule-name testdummy)))
    (let ((bl.val::*vb-gbt-optional-rules* '()))
      (is-false (bl.val:vb-deployment-optional-rule-p taproot))
      (is (string= "!taproot" (bl.val:vb-gbt-rule-name taproot)))
      (is (string= "!testdummy" (bl.val:vb-gbt-rule-name testdummy))))))

(test vb-deployment-mask-is-the-single-signalling-bit
  "Core ThresholdConditionChecker::Mask is 1 << bit, and it is what
ComputeBlockVersion ORs and what getblocktemplate clears for an unsupported
mandatory rule."
  (is (= (ash 1 28) (bl.val:vb-deployment-mask
                     (%dep "testdummy" :regtest))))
  (is (= (ash 1 2) (bl.val:vb-deployment-mask
                    (%dep "taproot" :mainnet)))))

;;;; --- -vbparams (Core ReadRegTestArgs, chainparams.cpp:68-106) -----------

(defun %testdummy-window (&optional (network :regtest))
  "NETWORK's testdummy (start timeout min-activation-height) as the deployment
table currently has it. Reading it must not go through
APPLY-VERSIONBITS-PARAMETERS: calling that with no specs is how the overrides
are CLEARED."
  (let ((d (%dep "testdummy" network)))
    (list (bl.val:vb-deployment-start-time d)
          (bl.val:vb-deployment-timeout d)
          (bl.val:vb-deployment-min-activation-height d))))

(defun %vbparams-testdummy (specs)
  "Apply SPECS and read regtest testdummy's window back."
  (bl.val:apply-versionbits-parameters specs)
  (%testdummy-window))

(defun %vbparams-refusal (specs)
  "The message APPLY-VERSIONBITS-PARAMETERS refuses SPECS with, or NIL."
  (handler-case (progn (bl.val:apply-versionbits-parameters specs) nil)
    (error (e) (princ-to-string e))))

(test vbparams-refuses-exactly-what-core-refuses
  "Core's ReadRegTestArgs splits on ':', demands three or four fields, parses
each number with ToIntegral (the WHOLE string, `-' allowed, `+' and junk not)
and looks the name up in VersionBitsDeploymentInfo, raising one of four
messages (chainparams.cpp:69-105). Every message below is Core's, verbatim: a
functional test that greets a malformed -vbparams by matching Core's stderr
cannot match a paraphrase.

Skipping a bad entry instead of raising is the failure mode this shape exists
to prevent -- the run then proceeds against the default window it was trying
to move and passes for the wrong reason."
  (unwind-protect
       (progn
         (is (equal '(1199145601 1230767999 0)
                    (%vbparams-testdummy '("testdummy:1199145601:1230767999"))))
         (is (equal '(1199145601 1230767999 403200)
                    (%vbparams-testdummy '("testdummy:1199145601:1230767999:403200"))))
         ;; Negative values reach the fields Core declares signed.
         (is (equal '(-1 -2 0) (%vbparams-testdummy '("testdummy:-1:-2"))))
         (dolist (spec '("testdummy:1" "testdummy" "testdummy:1:2:3:4" "" nil))
           (is (equal "Version bits parameters malformed, expecting deployment:start:end[:min_activation_height]"
                      (%vbparams-refusal (list spec)))
               "wrong refusal for ~S" spec))
         (is (equal "Invalid nStartTime (x)" (%vbparams-refusal '("testdummy:x:2"))))
         (is (equal "Invalid nStartTime (+1)" (%vbparams-refusal '("testdummy:+1:2"))))
         (is (equal "Invalid nStartTime ()" (%vbparams-refusal '("testdummy::2"))))
         (is (equal "Invalid nTimeout (2x)" (%vbparams-refusal '("testdummy:1:2x"))))
         (is (equal "Invalid min_activation_height (z)"
                    (%vbparams-refusal '("testdummy:1:2:z"))))
         (is (equal "Invalid deployment (frobnicate)"
                    (%vbparams-refusal '("frobnicate:1:2"))))
         ;; Core matches the name case-sensitively.
         (is (equal "Invalid deployment (TestDummy)"
                    (%vbparams-refusal '("TestDummy:1:2"))))
         ;; Last occurrence of a deployment wins; the other one is untouched.
         (bl.val:apply-versionbits-parameters
          '("testdummy:1:2" "taproot:3:4" "testdummy:5:6"))
         (is (equal '(5 6 0) (%testdummy-window))))
    (bl.val:apply-versionbits-parameters nil)))

(test vbparams-reaches-regtest-only-and-does-not-outlive-its-run
  "Core parses -vbparams in ReadRegTestArgs and writes it into RegTestOptions,
which only CChainParams::RegTest reads (chainparams.cpp:129-133,
kernel/chainparams.cpp:628-632), so no other chain can see it. Clearing on the
next call matters as much: an override that outlived its run would silently
move the window for every later chain in the same image."
  (unwind-protect
       (progn
         (bl.val:apply-versionbits-parameters '("testdummy:77:88:99"))
         (is (equal '(77 88 99) (%testdummy-window)))
         (dolist (network '(:mainnet :testnet3 :testnet4 :signet))
           (let ((d (%dep "testdummy" network)))
             (is (= bl.val:+vb-never-active+ (bl.val:vb-deployment-start-time d))
                 "-vbparams reached ~A" network)))
         ;; Bit, threshold and period are not the option's to move.
         (let ((d (%dep "testdummy" :regtest)))
           (is (= 28 (bl.val:vb-deployment-bit d)))
           (is (= 108 (bl.val:vb-deployment-threshold d)))
           (is (= 144 (bl.val:vb-deployment-period d)))))
    (bl.val:apply-versionbits-parameters nil))
  (is (equal (list 0 (1- (expt 2 63)) 0) (%testdummy-window))))

(defun %versionbits-chain-with-tip (n &rest args)
  "MAKE-VERSIONBITS-CHAIN, plus the chain-state tip pointers that
GET-BLOCK-AT-HEIGHT walks back from -- without them every height lookup on the
synthetic chain answers NIL, and VERSIONBITS-STATE reads NIL as `the block
before genesis' and reports DEFINED for the whole ladder."
  (multiple-value-bind (chain-state last) (apply #'make-versionbits-chain n args)
    (setf (bl.store:chain-state-best-block-hash chain-state)
          (bl.store:block-index-entry-hash last)
          (bl.store:chain-state-best-height chain-state)
          (bl.store:block-index-entry-height last))
    (values chain-state last)))

(defun %vbparams-ladder (chain-state entries specs)
  "The BIP9 state of regtest testdummy after each of ENTRIES, under SPECS."
  (bl.val:apply-versionbits-parameters specs)
  (let ((d (%dep "testdummy" :regtest)))
    (append (mapcar (lambda (e) (bl.val:versionbits-state chain-state e d)) entries)
            (list (bl.val:versionbits-since-height
                   chain-state (car (last entries)) d)))))

(test vbparams-drives-testdummy-through-the-bip9-ladder
  "The point of the option: a regtest chain walks DEFINED -> STARTED ->
LOCKED_IN -> ACTIVE on the window -vbparams gave it, one transition per
144-block period (versionbits.cpp:69-110).

Both custom runs are read against the DEFAULT run on the SAME chain, which is
the control that the chain -- not the option -- is not what moved the states: a
start time one period into the chain delays every transition by one period, and
a min_activation_height beyond the tip holds LOCKED_IN where the default is
already ACTIVE. Block i is timestamped 1000000 + 600i, so the median time past
at the boundaries 143/287/431 is 1082800/1169200/1255600."
  (with-network (:regtest)
    (multiple-value-bind (cs last) (%versionbits-chain-with-tip 576 :signal-bit 28)
      (let ((boundaries (list (bl.store:get-block-at-height cs 143)
                              (bl.store:get-block-at-height cs 287)
                              (bl.store:get-block-at-height cs 431)
                              last)))
        (unwind-protect
             (progn
               (is (equal '(:started :locked-in :active :active 432)
                          (%vbparams-ladder cs boundaries nil)))
               (is (equal '(:defined :started :locked-in :active 576)
                          (%vbparams-ladder
                           cs boundaries '("testdummy:1100000:9223372036854775807"))))
               (is (equal '(:started :locked-in :locked-in :locked-in 288)
                          (%vbparams-ladder
                           cs boundaries '("testdummy:0:9223372036854775807:600"))))
               ;; A timeout the chain passes without signalling is FAILED, which
               ;; the regtest default (NO_TIMEOUT) can never reach.
               (multiple-value-bind (quiet-cs quiet-last)
                   (%versionbits-chain-with-tip 432)
                 (let ((quiet (list (bl.store:get-block-at-height quiet-cs 143)
                                    quiet-last)))
                   (is (equal '(:started :started 144)
                              (%vbparams-ladder quiet-cs quiet nil)))
                   (is (equal '(:started :failed 288)
                              (%vbparams-ladder quiet-cs quiet
                                                '("testdummy:0:1100000")))))))
          (bl.val:apply-versionbits-parameters nil))))))

(test vbparams-shows-up-in-getdeploymentinfo-and-the-block-version
  "getdeploymentinfo echoes start_time, timeout and min_activation_height from
the deployment table (rpc/blockchain.cpp:1345-1360) and reports the status the
window produces, and getblocktemplate reads the same table through
VERSIONBITS-GBT-STATUS and COMPUTE-BLOCK-VERSION (rpc/mining.cpp:598-640): an
override nothing reads is not an override."
  (with-network (:regtest)
    (multiple-value-bind (cs last) (%versionbits-chain-with-tip 576 :signal-bit 28)
      (let ((node (make-test-node :network :regtest)))
        (setf (bl:node-chain-state node) cs)
        (unwind-protect
             (flet ((bip9 (specs)
                      (bl.val:apply-versionbits-parameters specs)
                      (let* ((reply (bl.rpc:dispatch-rpc-method
                                     node "getdeploymentinfo" nil))
                             (deployments (cdr (assoc "deployments" reply
                                                      :test #'string=)))
                             (testdummy (cdr (assoc "testdummy" deployments
                                                    :test #'string=))))
                        (list (cdr (assoc "active" testdummy :test #'string=))
                              (cdr (assoc "height" testdummy :test #'string=))
                              (let ((b (cdr (assoc "bip9" testdummy :test #'string=))))
                                (list (cdr (assoc "status" b :test #'string=))
                                      (cdr (assoc "start_time" b :test #'string=))
                                      (cdr (assoc "timeout" b :test #'string=))
                                      (cdr (assoc "min_activation_height" b
                                                  :test #'string=)))))))
                    (gbt-names ()
                      (mapcar (lambda (group)
                                (mapcar #'bl.val:vb-deployment-name group))
                              (multiple-value-list
                               (bl.val:versionbits-gbt-status cs last :regtest)))))
               (is (equal (list t 432 (list "active" 0 (1- (expt 2 63)) 0))
                          (bip9 nil)))
               ;; JSON-BOOL renders false as YASON:FALSE, and Core omits the
               ;; `height' key entirely while the deployment is not active.
               (is (equal (list 'yason:false nil
                                (list "locked_in" 0 (1- (expt 2 63)) 600))
                          (bip9 '("testdummy:0:9223372036854775807:600")))
                   "getdeploymentinfo did not report the -vbparams window")
               ;; LOCKED_IN, so the template still signals bit 28 and lists
               ;; testdummy as locked_in rather than active.
               (is (= (logior #x20000000 (ash 1 28))
                      (bl.val:compute-block-version cs last :regtest)))
               (is (equal '(nil ("testdummy") ("taproot")) (gbt-names)))
               ;; Under the defaults the same chain has testdummy ACTIVE, so
               ;; the template stops signalling it.
               (bl.val:apply-versionbits-parameters nil)
               (is (= #x20000000 (bl.val:compute-block-version cs last :regtest)))
               (is (equal '(nil nil ("taproot" "testdummy")) (gbt-names))))
          (bl.val:apply-versionbits-parameters nil))))))

(defun %testdummy-bip9 (chain-state)
  "The testdummy `bip9' object getdeploymentinfo reports at CHAIN-STATE's tip."
  (let ((node (make-test-node :network :regtest)))
    (setf (bl:node-chain-state node) chain-state)
    (let* ((reply (bl.rpc:dispatch-rpc-method node "getdeploymentinfo" nil))
           (deployments (cdr (assoc "deployments" reply :test #'string=))))
      (cdr (assoc "bip9" (cdr (assoc "testdummy" deployments :test #'string=))
                  :test #'string=)))))

(defun %bip9-value (bip9 key)
  (cdr (assoc key bip9 :test #'string=)))

(test getdeploymentinfo-emits-the-per-block-bip9-signalling-string
  "GA11 bc10de29. Core threads a per-block record through the statistics walk:
GetStateStatisticsFor sizes signalling_blocks to blocks_in_period = 1 +
(nHeight %% period) and writes at the DECREASING index as it walks backwards
from the reported block (versionbits.cpp:118-155); Info fills it whenever the
current state is STARTED or LOCKED_IN (:207-217); and SoftForkDescPushBack
renders it as `#' per signalling block and `-' per non-signalling one,
immediately after the statistics object and inside the same guard
(rpc/blockchain.cpp:1341-1349). We walked the same blocks and threw the record
away, so `count' said how many of the period signalled but nothing said WHICH.

Every third block signals here, so the ORDER is observable: the period's first
block (144) signals and the block being reported on (208) does not. On an
all-signalling chain a reversed record reads identically, which is why Core's
own rpc_blockchain.py assertion (`#' * (height - 143) at height 207, the second
case below) cannot catch that mistake."
  (with-network (:regtest)
    (let* ((cs (%versionbits-chain-with-tip
                209 :signal-bit 28 :signal-when (lambda (h) (zerop (mod h 3)))))
           (bip9 (%testdummy-bip9 cs))
           (stats (%bip9-value bip9 "statistics"))
           (signalling (%bip9-value bip9 "signalling"))
           ;; heights 144..208: 21 whole "#--" groups (144..206), then 207
           ;; signals and 208 does not.
           (expected (concatenate
                      'string
                      (apply #'concatenate 'string (make-list 21 :initial-element "#--"))
                      "#-")))
      (is (string= "started" (%bip9-value bip9 "status")))
      (is (= 65 (%bip9-value stats "elapsed")))
      (is (= 22 (%bip9-value stats "count")))
      (is-true (stringp signalling) "getdeploymentinfo emitted no signalling string")
      (is-true (and (stringp signalling) (= 65 (length signalling)))
               "the string is one character per elapsed block")
      (is-true (and (stringp signalling) (string= expected signalling))
               "the signalling string is not Core's")
      ;; The two ends, named, because a reversed record is the mistake this
      ;; chain exists to catch and STRING= alone does not say which end moved.
      (is-true (and (stringp signalling) (char= #\# (char signalling 0)))
               "the record starts at the period's FIRST block, which signals here")
      (is-true (and (stringp signalling) (char= #\- (char signalling 64)))
               "and ends at the block being reported on, which does not"))
    ;; Core's own vector: an all-signalling regtest chain at height 207 reports
    ;; '#' * (height - 143) (rpc_blockchain.py:240).
    (let* ((bip9 (%testdummy-bip9 (%versionbits-chain-with-tip 208 :signal-bit 28)))
           (signalling (%bip9-value bip9 "signalling")))
      (is (string= (make-string 64 :initial-element #\#) signalling)))))

(test getdeploymentinfo-drops-threshold-and-possible-once-locked-in
  "GA11 ef28c178. Core computes the statistics and then overrides two of them:
VersionBitsCache::Info sets threshold to 0 and possible to false when the
current state is LOCKED_IN (versionbits.cpp:210-217) -- lock-in is decided, so
there is no threshold left to meet and nothing left that could fail -- and
SoftForkDescPushBack emits the pair only under `threshold > 0 || possible'
(rpc/blockchain.cpp:1337-1340), so in LOCKED_IN the statistics object holds
period, elapsed and count only.

We had the guard but not the override, and every deployment in the table has a
positive threshold, so the guard could never fire: a settled window reported
threshold 108 against count 12 with possible true, which reads as a period
still in progress that could still fail. The override belongs in
VERSIONBITS-INFO and not in the RPC, because GetStateStatisticsFor is
state-blind in Core and other callers read its raw counting result -- the last
assertion is what pins that split.

Three states on the same deployment: STARTED (both keys, and the values Core's
rpc_blockchain.py expects at height 207), LOCKED_IN (neither key, signalling
string still there), ACTIVE (no statistics object at all)."
  (with-network (:regtest)
    (flet ((shape (blocks)
             (let* ((bip9 (%testdummy-bip9
                           (%versionbits-chain-with-tip blocks :signal-bit 28)))
                    (stats (%bip9-value bip9 "statistics")))
               (list (%bip9-value bip9 "status")
                     (mapcar #'car stats)
                     (and (assoc "signalling" bip9 :test #'string=) t)))))
      (is (equal '("started" ("period" "elapsed" "count" "threshold" "possible") t)
                 (shape 208)))
      (is (equal '("locked_in" ("period" "elapsed" "count") t)
                 (shape 300)))
      (is (equal '("active" nil nil) (shape 433))))
    ;; The STARTED values themselves are unchanged.
    (let ((stats (%bip9-value (%testdummy-bip9
                               (%versionbits-chain-with-tip 208 :signal-bit 28))
                              "statistics")))
      (is (= 108 (%bip9-value stats "threshold")))
      (is (eq t (%bip9-value stats "possible"))))
    ;; The override is Info's, not the counting walk's: at the same LOCKED_IN
    ;; block VERSIONBITS-STATISTICS still reports the deployment's threshold
    ;; and the raw arithmetic, as Core's GetStateStatisticsFor does.
    (multiple-value-bind (cs last) (%versionbits-chain-with-tip 300 :signal-bit 28)
      (let ((dep (%dep "testdummy" :regtest)))
        (multiple-value-bind (period threshold elapsed count possible)
            (bl.val:versionbits-statistics cs last dep)
          (is (equal '(144 108 12 12 t)
                     (list period threshold elapsed count (and possible t)))))
        (multiple-value-bind (current next since stats)
            (bl.val:versionbits-info cs last dep)
          (declare (ignore next since))
          (is (eq :locked-in current))
          (is (= 0 (bl.val:vb-stats-threshold stats)))
          (is (null (bl.val:vb-stats-possible stats))))))))
