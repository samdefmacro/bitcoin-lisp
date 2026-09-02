(in-package #:bitcoin-lisp.validation)

;;;; BIP9 / versionbits (Bitcoin Core versionbits.{h,cpp}, versionbits_impl.h)
;;;;
;;;; This node has never had a versionbits state machine: every deployment is a
;;;; hardcoded activation height. That is fine for DECIDING activation — all of
;;;; ours are long buried, and nothing here changes that decision — but it is
;;;; wrong for REPORTING. Core still carries taproot as a bip9 deployment in
;;;; every chain's parameters (kernel/chainparams.cpp:110-115 and the four
;;;; other chains), so getdeploymentinfo reports it with a `bip9' object on all
;;;; five networks while we reported `buried' on all five. A caller reading
;;;; getdeploymentinfo to learn a deployment's bit, window or signalling count
;;;; got nothing from us at all.
;;;;
;;;; ⚠️ SCOPE. This file computes and REPORTS state. It is deliberately not
;;;; wired into any activation decision: get-taproot-activation-height and the
;;;; buried heights in block.lisp remain the only thing that decides when a
;;;; rule applies to a block. Replacing those with a computed state machine
;;;; could change when a rule activates on a chain two live nodes are synced
;;;; to, and there is no reason to take that risk for a deployment that
;;;; activated years ago.

(defconstant +vb-always-active+ -1
  "Core BIP9Deployment::ALWAYS_ACTIVE (consensus/params.h:73).")

(defconstant +vb-never-active+ -2
  "Core BIP9Deployment::NEVER_ACTIVE (consensus/params.h:78).")

(defconstant +vb-no-timeout+ 9223372036854775807
  "Core BIP9Deployment::NO_TIMEOUT — int64 max (consensus/params.h:67).")

(defconstant +vb-top-mask+ #xE0000000
  "Core VERSIONBITS_TOP_MASK.")

(defconstant +vb-top-bits+ #x20000000
  "Core VERSIONBITS_TOP_BITS: the three high bits a signalling block sets.")

(defstruct (vb-deployment (:constructor %make-vb-deployment))
  "One BIP9 deployment's parameters (Core Consensus::BIP9Deployment,
consensus/params.h:45-79)."
  (name "" :type string)
  (bit 28 :type (integer 0 31))
  (start-time 0 :type integer)
  (timeout 0 :type integer)
  (min-activation-height 0 :type (integer 0))
  (threshold 1916 :type (integer 0))
  (period 2016 :type (integer 1)))

(defun %vb (name bit start timeout min-act threshold period)
  (%make-vb-deployment :name name :bit bit :start-time start :timeout timeout
                       :min-activation-height min-act
                       :threshold threshold :period period))

(defparameter *versionbits-deployments*
  ;; Transcribed from kernel/chainparams.cpp: mainnet :102-115, testnet3
  ;; :233-246, testnet4 :341-354, signet :492-505, regtest :580-591. The
  ;; threshold and period differ per chain — regtest's window is 144 blocks,
  ;; not 2016 — which is exactly the kind of value a chain-blind table gets
  ;; wrong.
  `((:mainnet
     ,(%vb "testdummy" 28 +vb-never-active+ +vb-no-timeout+ 0 1815 2016)
     ,(%vb "taproot"   2  1619222400 1628640000 709632 1815 2016))
    (:testnet3
     ,(%vb "testdummy" 28 +vb-never-active+ +vb-no-timeout+ 0 1512 2016)
     ,(%vb "taproot"   2  1619222400 1628640000 0 1512 2016))
    (:testnet4
     ,(%vb "testdummy" 28 +vb-never-active+ +vb-no-timeout+ 0 1512 2016)
     ,(%vb "taproot"   2  +vb-always-active+ +vb-no-timeout+ 0 1512 2016))
    (:signet
     ,(%vb "testdummy" 28 +vb-never-active+ +vb-no-timeout+ 0 1815 2016)
     ,(%vb "taproot"   2  +vb-always-active+ +vb-no-timeout+ 0 1815 2016))
    (:regtest
     ;; regtest's testdummy starts at time 0 rather than never, which is what
     ;; makes it drivable by a functional test.
     ,(%vb "testdummy" 28 0 +vb-no-timeout+ 0 108 144)
     ,(%vb "taproot"   2  +vb-always-active+ +vb-no-timeout+ 0 108 144)))
  "Per-chain BIP9 deployments, in Core's order.")

(defun versionbits-deployments (&optional (network bl:*network*))
  "The BIP9 deployments defined for NETWORK."
  (rest (assoc network *versionbits-deployments*)))

(defun versionbits-deployment (name &optional (network bl:*network*))
  (find name (versionbits-deployments network) :key #'vb-deployment-name
                                               :test #'string=))

;;;; --- The threshold state machine (versionbits.cpp:27-114) ---------------

(defun %vb-condition-p (entry deployment)
  "Core's ThresholdConditionChecker::Condition (versionbits_impl.h): the block
sets the versionbits top bits and has this deployment's bit set."
  (let ((v (bl.ser:block-header-version
            (bl.store:block-index-entry-header entry))))
    (and (= (logand v +vb-top-mask+) +vb-top-bits+)
         (logbitp (vb-deployment-bit deployment) v)
         t)))

(defun %vb-period-start (chain-state entry period)
  "ENTRY snapped DOWN to the last block of its retarget period, or NIL for the
block before genesis.

Core: `a block's state is always the same as that of the first of its period',
so pindexPrev is moved to the boundary before any walking
(versionbits.cpp:43-46). After this, (height + 1) mod period is 0."
  (when entry
    (let* ((h (bl.store:block-index-entry-height entry))
           (target (- h (mod (1+ h) period))))
      (if (= target h)
          entry
          (and (>= target 0)
               (bl.store:entry-ancestor-at-height entry target))))))

(defvar *versionbits-state-cache* nil
  "Per-call memo for VERSIONBITS-STATE: an EQ table from deployment to an EQ
table from boundary entry to state. NIL disables memoising.

Core keeps a persistent cache keyed by CBlockIndex* (versionbits.cpp:204, and
every GetStateFor writes into it at :113). Ours is bound for the duration of
one getdeploymentinfo call instead, which is where the cost actually is and
which cannot go stale across a reorg because it does not outlive the call.

Without it VERSIONBITS-SINCE-HEIGHT calls VERSIONBITS-STATE once per period and
each of those walks back to the deployment's start — on mainnet taproot at the
current tip that is order 10^7 prev-entry hops per call, and the handler is
also reachable through /rest/deploymentinfo.")

(defmacro with-versionbits-cache (&body body)
  `(let ((*versionbits-state-cache* (make-hash-table :test 'eq)))
     ,@body))

(defun %vb-cached-state (deployment entry thunk)
  (if (null *versionbits-state-cache*)
      (funcall thunk)
      (let ((per-dep (or (gethash deployment *versionbits-state-cache*)
                         (setf (gethash deployment *versionbits-state-cache*)
                               (make-hash-table :test 'eq)))))
        (multiple-value-bind (v present) (gethash entry per-dep)
          (if present v (setf (gethash entry per-dep) (funcall thunk)))))))

(defun %vb-mtp (chain-state entry)
  (and entry (compute-median-time-past-from-entry chain-state entry)))

(defun versionbits-state (chain-state entry deployment)
  "The BIP9 state of the block that would follow ENTRY — Core's
GetStateFor(pindexPrev) (versionbits.cpp:27-114). ENTRY may be NIL, meaning the
block before genesis.

Returns one of :defined :started :locked-in :active :failed."
  (%vb-cached-state deployment entry
   (lambda () (%versionbits-state-1 chain-state entry deployment))))

(defun %versionbits-state-1 (chain-state entry deployment)
  (let ((start (vb-deployment-start-time deployment))
        (period (vb-deployment-period deployment)))
    ;; Both special start times short-circuit before any chain walk
    ;; (versionbits.cpp:33-40).
    (cond
      ((= start +vb-always-active+) (return-from %versionbits-state-1 :active))
      ((= start +vb-never-active+) (return-from %versionbits-state-1 :failed)))
    (let ((cursor (%vb-period-start chain-state entry period))
          (to-compute '()))
      ;; Walk BACK in whole periods until a period whose MTP is before the start
      ;; time — everything at or below that is DEFINED and needs no further walk
      ;; (versionbits.cpp:48-63).
      (loop
        (when (null cursor) (return))
        (when (< (%vb-mtp chain-state cursor) start) (return))
        (push cursor to-compute)
        (let ((h (- (bl.store:block-index-entry-height cursor) period)))
          (setf cursor (and (>= h 0)
                            (bl.store:entry-ancestor-at-height cursor h)))))
      ;; Walk FORWARD, one transition per period (versionbits.cpp:69-110).
      (let ((state :defined))
        (dolist (boundary to-compute state)
          (ecase state
            (:defined
             (when (>= (%vb-mtp chain-state boundary) start)
               (setf state :started)))
            (:started
             (let ((count 0)
                   (walker boundary))
               (dotimes (i period)
                 (unless walker (return))
                 (when (%vb-condition-p walker deployment) (incf count))
                 ;; prev-entry, not a fresh ancestor lookup per step: this
                 ;; runs PERIOD times (2016 on the real chains) and an
                 ;; ancestor walk inside it would be quadratic.
                 (setf walker (bl.store:block-index-entry-prev-entry walker)))
               (cond
                 ;; Threshold wins over timeout when both hold in one period
                 ;; (versionbits.cpp:92-96).
                 ((>= count (vb-deployment-threshold deployment)) (setf state :locked-in))
                 ((>= (%vb-mtp chain-state boundary) (vb-deployment-timeout deployment))
                  (setf state :failed)))))
            (:locked-in
             ;; LOCKED_IN can never go to FAILED; it waits whole periods until
             ;; the activation height (versionbits.cpp:97-103).
             (when (>= (1+ (bl.store:block-index-entry-height boundary))
                       (vb-deployment-min-activation-height deployment))
               (setf state :active)))
            ((:active :failed))))))))

(defun versionbits-since-height (chain-state entry deployment)
  "The height of the first block of the period in which this deployment
entered its current state (Core GetStateSinceHeightFor, versionbits.cpp:116)."
  (let ((state (versionbits-state chain-state entry deployment))
        (period (vb-deployment-period deployment)))
    ;; ALWAYS_ACTIVE is active from genesis (versionbits.cpp:120-122).
    (when (= (vb-deployment-start-time deployment) +vb-always-active+)
      (return-from versionbits-since-height 0))
    (let ((cursor (%vb-period-start chain-state entry period))
          (since 0))
      (loop
        (when (null cursor) (return))
        (let ((h (- (bl.store:block-index-entry-height cursor) period)))
          (let ((prev (and (>= h 0)
                           (bl.store:entry-ancestor-at-height cursor h))))
            (unless (eq state (versionbits-state chain-state prev deployment))
              (setf since (1+ (bl.store:block-index-entry-height cursor)))
              (return))
            (setf cursor prev))))
      since)))

(defun versionbits-statistics (chain-state entry deployment)
  "(values period threshold elapsed count possible) for the CURRENT period —
Core BIP9Stats (versionbits.cpp:135-166). Meaningful only in the STARTED state,
which is what getdeploymentinfo gates it on."
  (let* ((period (vb-deployment-period deployment))
         (threshold (vb-deployment-threshold deployment))
         (height (if entry (bl.store:block-index-entry-height entry) -1))
         ;; Core: blocks_in_period = 1 + (nHeight % period), counted down to
         ;; zero, so elapsed ends at that value (versionbits.cpp:129-150).
         ;; `(mod (1+ height) period)' agrees everywhere EXCEPT the last block
         ;; of a period, where Core reports a full period elapsed and that
         ;; reports zero — and zero elapsed means zero count and a `possible'
         ;; computed from nothing.
         (elapsed (1+ (mod height period)))
         (count 0)
         (walker entry))
    ;; Core returns before counting when there is no block, with elapsed and
    ;; count zero and possible FALSE — default-initialised, never computed
    ;; (versionbits.cpp:126). Reachable here only through a caller that does
    ;; not guard, but `(mod -1 period)' is period-1 in CL, so without this the
    ;; formula above would walk a NIL entry a whole period of times.
    (when (null entry)
      (return-from versionbits-statistics (values period threshold 0 0 nil)))
    (dotimes (i elapsed)
      (unless walker (return))
      (when (%vb-condition-p walker deployment) (incf count))
      (setf walker (bl.store:block-index-entry-prev-entry walker)))
    (values period threshold elapsed count
            ;; `possible' is false once the blocks remaining in the period can
            ;; no longer reach the threshold (versionbits.cpp:161-163).
            (>= (+ count (- period elapsed)) threshold))))

(defun versionbits-state-name (state)
  "Core's BIP9 status strings (rpc/blockchain.cpp's get_state_name)."
  (ecase state
    (:defined "defined")
    (:started "started")
    (:locked-in "locked_in")
    (:active "active")
    (:failed "failed")))
