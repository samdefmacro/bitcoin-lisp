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
;;;; ⚠️ SCOPE. This file computes and REPORTS state, and tells the MINER what
;;;; to signal. It is deliberately not wired into any activation decision: the
;;;; buried heights in block.lisp remain the only thing that decides when a
;;;; rule applies to a block. Replacing those with a computed state machine
;;;; could change when a rule activates on a chain two live nodes are synced
;;;; to, and there is no reason to take that risk for a deployment that
;;;; activated years ago. COMPUTE-BLOCK-VERSION and VERSIONBITS-GBT-STATUS are
;;;; inside the scope line, not across it: what a template of ours signals is
;;;; a statement about the block we are proposing, never about one we accept.

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
  ;; int64 out of -vbparams, narrowed to Core's `int min_activation_height';
  ;; nothing constrains it to be positive there, and the only test on it is
  ;; `pindexPrev->nHeight + 1 >= min_activation_height'.
  (min-activation-height 0 :type integer)
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

(defvar *vbparams-deployments* nil
  "The regtest deployment list with -vbparams applied, or NIL when the option
was not given. Built ONCE by APPLY-VERSIONBITS-PARAMETERS, the way Core builds
the regtest chainparams once, so every caller shares the same structs:
VERSIONBITS-STATE's per-call memo is an EQ table keyed on the deployment
object, and a list rebuilt per call would defeat it.")

(defun versionbits-deployments (&optional (network bl:*network*))
  "The BIP9 deployments defined for NETWORK.

On regtest these are the deployments -vbparams edited, when it was given.
Core reads that option in ReadRegTestArgs (chainparams.cpp:68-106) into
RegTestOptions::version_bits_parameters, and kernel/chainparams.cpp:628-632
writes each entry's start_time, timeout and min_activation_height into
consensus.vDeployments while building the regtest params. It reaches no other
chain because ReadRegTestArgs is called for no other chain."
  (if (and *vbparams-deployments* (eq network :regtest))
      *vbparams-deployments*
      (rest (assoc network *versionbits-deployments*))))

(defun %vbparams-integer (string)
  "STRING as an integer, or NIL. Core parses each field with
ToIntegral<int64_t> (util/strencodings.h), which consumes the WHOLE string:
digits, optionally preceded by `-'; no `+', no whitespace, no trailing junk."
  (let ((n (length string)))
    (when (plusp n)
      (let ((start (if (char= (char string 0) #\-) 1 0)))
        (when (and (> n start)
                   (every #'digit-char-p (subseq string start)))
          (parse-integer string))))))

(defun apply-versionbits-parameters (specs)
  "Install the -vbparams overrides in SPECS, each `deployment:start:end' or
`deployment:start:end:min_activation_height' (Core ReadRegTestArgs,
chainparams.cpp:68-106). Every message below is Core's.

Applied to the REGTEST deployments only, which is the whole of the option:
Core's parse lives in ReadRegTestArgs and the values land in RegTestOptions,
so on any other chain the option is inert. An unparsable field or an unknown
deployment name raises rather than being skipped -- a silently ignored typo
leaves the test running against the window it was trying to move."
  (setf *vbparams-deployments* nil)
  (when specs
    (let ((deployments (mapcar #'copy-vb-deployment
                               (rest (assoc :regtest *versionbits-deployments*)))))
      (dolist (spec specs)
        (let ((parts (and (stringp spec) (uiop:split-string spec :separator ":"))))
          (unless (<= 3 (length parts) 4)
            (config-error "Version bits parameters malformed, expecting deployment:start:end[:min_activation_height]"))
          (destructuring-bind (name start-string timeout-string &optional min-string) parts
            (let ((start (%vbparams-integer start-string))
                  (timeout (%vbparams-integer timeout-string))
                  (min-activation-height (if min-string
                                             (%vbparams-integer min-string)
                                             0)))
              (unless start (config-error "Invalid nStartTime (~A)" start-string))
              (unless timeout (config-error "Invalid nTimeout (~A)" timeout-string))
              (unless min-activation-height
                (config-error "Invalid min_activation_height (~A)" min-string))
              (let ((deployment (find name deployments :key #'vb-deployment-name
                                                       :test #'string=)))
                (unless deployment
                  (config-error "Invalid deployment (~A)" name))
                (setf (vb-deployment-start-time deployment) start
                      (vb-deployment-timeout deployment) timeout
                      (vb-deployment-min-activation-height deployment)
                      min-activation-height)
                (bl:log-info "Setting version bits activation parameters for ~A to start=~D, timeout=~D, min_activation_height=~D"
                             name start timeout min-activation-height))))))
      (setf *vbparams-deployments* deployments))))

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
  (if *versionbits-state-cache*
      (let ((per-dep (or (gethash deployment *versionbits-state-cache*)
                         (setf (gethash deployment *versionbits-state-cache*)
                               (make-hash-table :test 'eq)))))
        (multiple-value-bind (v present) (gethash entry per-dep)
          (if present v (setf (gethash entry per-dep) (funcall thunk)))))
      (funcall thunk)))

(defun %vb-mtp (chain-state entry)
  "ENTRY's median time past, or NIL for the block before genesis.

⚠️ COMPUTE-MEDIAN-TIME-PAST-FROM-ENTRY takes the entry ALONE — it walks
PREV-ENTRY and never consults the index. Passing CHAIN-STATE as well made this
a two-argument call to a one-argument function, so every state that needs a
real MTP signalled SB-INT:SIMPLE-PROGRAM-ERROR at run time. Nothing caught it
because both callers reach MTP only past a short circuit: a deployment with
ALWAYS_ACTIVE or NEVER_ACTIVE returns before any walk, and an empty chain has
no period boundary to walk to — which is every case the tests and the four
non-mainnet chains' tables produce. CHAIN-STATE stays in the signature because
it is part of VERSIONBITS-STATE's, which getdeploymentinfo calls."
  (declare (ignore chain-state))
  (and entry (compute-median-time-past-from-entry entry)))

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

;;;; --- What the miner and getblocktemplate read (versionbits.cpp:228-286) ---

(defparameter *vb-gbt-optional-rules* '("testdummy" "taproot")
  "The deployments whose getblocktemplate rule name carries NO `!' prefix --
Core's VersionBitsDeploymentInfo entries with gbt_optional_rule = true
(deploymentinfo.cpp:11-20). Both of Core's deployments are optional today.

A name absent from this list is MANDATORY, which is the safe default for one
nobody has classified: getblocktemplate then prefixes its rule with `!' and
refuses a client that has not declared it, rather than handing out work the
client cannot mine.")

(defun vb-deployment-optional-rule-p (deployment)
  "Core VBDeploymentInfo::gbt_optional_rule for DEPLOYMENT."
  (and (member (vb-deployment-name deployment) *vb-gbt-optional-rules*
               :test #'string=)
       t))

(defun vb-deployment-mask (deployment)
  "Core ThresholdConditionChecker::Mask: the single nVersion bit DEPLOYMENT
signals on."
  (ash 1 (vb-deployment-bit deployment)))

(defun compute-block-version (chain-state entry &optional (network bl:*network*))
  "The nVersion a block extending ENTRY should carry -- Core
VersionBitsCache::ComputeBlockVersion (versionbits.cpp:265-279): the
versionbits top bits, plus the bit of every deployment that is STARTED or
LOCKED_IN for that block.

⚠️ This is the ONE place where the state machine feeds a decision rather than a
report, and it is a decision about what WE mine, never about what we accept:
nothing in validation reads it. Core computes the same value the same way, so a
template of ours signals exactly what Core's does on the same chain."
  (let ((version +vb-top-bits+))
    (dolist (deployment (versionbits-deployments network) version)
      (when (member (versionbits-state chain-state entry deployment)
                    '(:started :locked-in))
        (setf version (logior version (vb-deployment-mask deployment)))))))

(defun versionbits-gbt-status (chain-state entry &optional (network bl:*network*))
  "(values SIGNALLING LOCKED-IN ACTIVE), the deployments getblocktemplate must
report for a block extending ENTRY -- Core VersionBitsCache::GBTStatus
(versionbits.cpp:228-257). DEFINED and FAILED are not exposed to GBT at all.

Each list is sorted by deployment name, because Core's three groups are
std::map keyed by that name and the `rules' array it emits is therefore in
name order, not in the order the deployments are declared."
  (let ((signalling '()) (locked-in '()) (active '()))
    (dolist (deployment (versionbits-deployments network))
      (case (versionbits-state chain-state entry deployment)
        (:started (push deployment signalling))
        (:locked-in (push deployment locked-in))
        (:active (push deployment active))))
    (flet ((by-name (list)
             (sort list #'string< :key #'vb-deployment-name)))
      (values (by-name signalling) (by-name locked-in) (by-name active)))))

(defun vb-gbt-rule-name (deployment)
  "DEPLOYMENT's name as getblocktemplate spells it in `rules' and
`vbavailable' -- Core gbt_rule_value (rpc/mining.cpp:605-612), which prefixes
`!' when the rule is mandatory."
  (let ((name (vb-deployment-name deployment)))
    (if (vb-deployment-optional-rule-p deployment)
        name
        (concatenate 'string "!" name))))
