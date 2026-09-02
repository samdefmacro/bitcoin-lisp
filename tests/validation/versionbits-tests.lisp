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

(test versionbits-special-start-times-short-circuit
  "ALWAYS_ACTIVE and NEVER_ACTIVE are answered before any chain walk
(versionbits.cpp:33-40), which is what lets them be evaluated with no block
index at all."
  (let ((always (bl.val::versionbits-deployment
                 "taproot" :regtest))
        (never (bl.val::versionbits-deployment
                "testdummy" :mainnet)))
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
  (flet ((dep (net name) (bl.val::versionbits-deployment name net)))
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

(defun %vb-chain (n &key (network :regtest) (signal-bit nil) (base-time 1000000))
  "(values chain-state last-entry) for a synthetic chain of N blocks.

Every header carries the versionbits top bits, and SIGNAL-BIT additionally sets
that deployment bit — which is what CONDITION counts."
  (declare (ignore network))
  (let ((cs (bl.store:make-chain-state))
        (prev nil))
    (dotimes (i n)
      (let* ((version (logior #x20000000 (if signal-bit (ash 1 signal-bit) 0)))
             (header (bl.ser:make-block-header
                      :version version
                      :prev-block (make-array 32 :element-type '(unsigned-byte 8)
                                                 :initial-element 0)
                      :merkle-root (make-array 32 :element-type '(unsigned-byte 8)
                                                  :initial-element 0)
                      :timestamp (+ base-time (* i 600))
                      :bits #x207fffff :nonce 0))
             (hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
        (setf (aref hash 0) (logand i #xFF)
              (aref hash 1) (logand (ash i -8) #xFF))
        (let ((e (bl.store:make-block-index-entry
                  :hash hash :height i :prev-entry prev :header header
                  :status :valid)))
          (bl.store:add-block-index-entry cs e)
          (setf prev e))))
    (values cs prev)))

(test versionbits-elapsed-counts-the-way-core-counts
  "⚠️ Core computes blocks_in_period as `1 + (nHeight %% period)' and counts it
down, so ELAPSED ends at that value (versionbits.cpp:129-150). Writing it as
`(mod (1+ height) period)' agrees everywhere EXCEPT the last block of a period,
where Core reports a full period elapsed and that reports ZERO — and zero
elapsed means zero count and a `possible' computed from nothing.

regtest's period is 144, so height 143 is the case that separates them."
  (let ((dep (bl.val::versionbits-deployment "testdummy" :regtest)))
    (multiple-value-bind (cs last) (%vb-chain 144 :signal-bit 28)
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
    (multiple-value-bind (cs last) (%vb-chain 143 :signal-bit 28)
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
  (let ((dep (bl.val::versionbits-deployment "testdummy" :regtest)))
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
  (let ((dep (bl.val::versionbits-deployment "testdummy" :regtest)))
    (multiple-value-bind (cs last) (%vb-chain 144)   ; top bits only, no bit 28
      (multiple-value-bind (period threshold elapsed count possible)
          (bl.val:versionbits-statistics cs last dep)
        (declare (ignore period threshold))
        (is (= 144 elapsed))
        (is (= 0 count))
        (is (null possible) "a full period with no signal cannot still be possible")))))
