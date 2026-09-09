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
  ;; The states cached for the old table describe a chain whose known
  ;; deployments have just changed; see CLEAR-VERSIONBITS-WARNING-CACHE.
  (clear-versionbits-warning-cache)
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

(defun %vb-condition-p (chain-state entry checker)
  "Core's ThresholdConditionChecker::Condition: the block sets the versionbits
top bits and has this deployment's bit set (versionbits_impl.h:66-77).

CHECKER is a VB-DEPLOYMENT, or the VB-WARNING-CHECKER for one bit, whose
Condition is the other one Core defines (versionbits.cpp:323-329). That
predicate is the ONLY thing the two differ in, here as in Core, where they are
two subclasses of one abstract checker."
  (if (vb-warning-checker-p checker)
      (%vb-warning-condition-p chain-state entry checker)
      (let ((v (bl.ser:block-header-version
                (bl.store:block-index-entry-header entry))))
        (and (= (logand v +vb-top-mask+) +vb-top-bits+)
             (logbitp (vb-deployment-bit checker) v)
             t))))

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
  "The threshold-state cache in force: an EQ table from checker to an EQ table
from PERIOD BOUNDARY entry to state. NIL means each VERSIONBITS-STATE gets a
fresh one, which still shares the work within that one call.

The second table is Core's ThresholdConditionCache, and GetStateFor both reads
it to STOP the walk back and writes every boundary it computes on the way
forward (versionbits.cpp:49-113). Keying on the boundary rather than on the
block asked about is what makes it worth anything: all PERIOD blocks of a period
share one entry, so a tip that moved by one block costs a lookup instead of a
walk back to the deployment's start.

A boundary's state is a function of that boundary's ancestors, which never
change, so an entry can never go stale -- not across a reorg either, since the
competing branch is made of different entries. WITH-VERSIONBITS-CACHE binds a
per-call table for getdeploymentinfo; *VERSIONBITS-WARNING-CACHE* is the
persistent one Core keeps on its VersionBitsCache object.

Without any of this VERSIONBITS-SINCE-HEIGHT calls VERSIONBITS-STATE once per
period and each of those walks back to the deployment's start — on mainnet
taproot at the current tip that is order 10^7 prev-entry hops per call, and the
handler is also reachable through /rest/deploymentinfo.")

(defvar *versionbits-warning-cache*
  (make-hash-table :test 'eq :weakness :key :synchronized t)
  "Core VersionBitsCache's m_warning_caches and m_caches (versionbits.h:78-80),
which live as long as the node does.

CHECK-UNKNOWN-ACTIVATIONS runs on every tip change, and its checkers never
FAIL and never leave STARTED on their own -- nothing times them out -- so with
a per-call cache every block would recount every period of the chain since
genesis, for all 29 bits. Weak on the checker so the deployment states a
-vbparams table leaves behind go with it, and the inner tables are weak on the
boundary entry so a test's synthetic chain does too.")

(defmacro with-versionbits-cache (&body body)
  `(let ((*versionbits-state-cache* (make-hash-table :test 'eq)))
     ,@body))

(defun %vb-cache-for (checker)
  "CHECKER's boundary -> state table in the cache now in force — Core's
`ThresholdConditionCache& cache' argument, which GetStateFor always has. A
fresh table when no cache is bound, so the walk below is written one way."
  (let ((outer *versionbits-state-cache*))
    (if outer
        (or (gethash checker outer)
            (setf (gethash checker outer)
                  (make-hash-table :test 'eq :weakness :key :synchronized t)))
        (make-hash-table :test 'eq))))

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

(defun versionbits-state (chain-state entry checker)
  "The BIP9 state of the block that would follow ENTRY — Core's
GetStateFor(pindexPrev) (versionbits.cpp:27-114). ENTRY may be NIL, meaning the
block before genesis. CHECKER is a VB-DEPLOYMENT, or the VB-WARNING-CHECKER for
one bit (see CHECK-UNKNOWN-ACTIVATIONS).

Returns one of :defined :started :locked-in :active :failed."
  (let ((start (vb-deployment-start-time checker)))
    ;; Both special start times short-circuit before any chain walk
    ;; (versionbits.cpp:33-40), which is what lets them be answered with no
    ;; block index at all.
    (cond
      ((= start +vb-always-active+) :active)
      ((= start +vb-never-active+) :failed)
      (t (%versionbits-state-1 chain-state entry checker)))))

(defun %versionbits-state-1 (chain-state entry checker)
  (let* ((start (vb-deployment-start-time checker))
         (period (vb-deployment-period checker))
         (cache (%vb-cache-for checker))
         ;; A block's state is always the state of the first block of its
         ;; period, so both the walk and the cache key are the boundary
         ;; (versionbits.cpp:43-46).
         (cursor (%vb-period-start chain-state entry period))
         (to-compute '())
         (state nil))
    ;; Walk BACK in whole periods to the first boundary whose state is already
    ;; known, or the first one whose MTP is before the start time — everything
    ;; at or below that is DEFINED (versionbits.cpp:48-63).
    (loop
      (multiple-value-bind (known present) (gethash cursor cache)
        (when present
          (setf state known)
          (return)))
      (when (or (null cursor) (< (%vb-mtp chain-state cursor) start))
        (setf (gethash cursor cache) :defined
              state :defined)
        (return))
      (push cursor to-compute)
      (let ((h (- (bl.store:block-index-entry-height cursor) period)))
        (setf cursor (and (>= h 0)
                          (bl.store:entry-ancestor-at-height cursor h)))))
    ;; Walk FORWARD, one transition per period, recording each boundary as Core
    ;; does — that record is what ends the walk above next time
    ;; (versionbits.cpp:69-113).
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
             (when (%vb-condition-p chain-state walker checker) (incf count))
             ;; prev-entry, not a fresh ancestor lookup per step: this
             ;; runs PERIOD times (2016 on the real chains) and an
             ;; ancestor walk inside it would be quadratic.
             (setf walker (bl.store:block-index-entry-prev-entry walker)))
           (cond
             ;; Threshold wins over timeout when both hold in one period
             ;; (versionbits.cpp:92-96).
             ((>= count (vb-deployment-threshold checker)) (setf state :locked-in))
             ((>= (%vb-mtp chain-state boundary) (vb-deployment-timeout checker))
              (setf state :failed)))))
        (:locked-in
         ;; LOCKED_IN can never go to FAILED; it waits whole periods until
         ;; the activation height (versionbits.cpp:97-103).
         (when (>= (1+ (bl.store:block-index-entry-height boundary))
                   (vb-deployment-min-activation-height checker))
           (setf state :active)))
        ((:active :failed)))
      (setf (gethash boundary cache) state))))

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
  "(values period threshold elapsed count possible signalling) for the CURRENT
period — Core BIP9Stats and the signalling_blocks vector it fills alongside
(GetStateStatisticsFor, versionbits.cpp:118-155). Meaningful only in the
STARTED and LOCKED_IN states, which is what getdeploymentinfo gates it on.

SIGNALLING is a bit vector of length ELAPSED whose element I is 1 when the
block I blocks after the START of the period satisfied the condition. Core
sizes it to blocks_in_period and writes at the DECREASING index as it walks
backwards from ENTRY (versionbits.cpp:130-147), so index 0 is the period's
first block and the last element is ENTRY itself. Getting that order backwards
is the easy mistake, and an all-signalling chain cannot catch it."
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
      (return-from versionbits-statistics
        (values period threshold 0 0 nil (make-array 0 :element-type 'bit))))
    (let ((signalling (make-array elapsed :element-type 'bit :initial-element 0)))
      (dotimes (i elapsed)
        (unless walker (return))
        (when (%vb-condition-p chain-state walker deployment)
          (incf count)
          (setf (sbit signalling (- elapsed 1 i)) 1))
        (setf walker (bl.store:block-index-entry-prev-entry walker)))
      (values period threshold elapsed count
              ;; `possible' is false once the blocks remaining in the period can
              ;; no longer reach the threshold (versionbits.cpp:161-163).
              (>= (+ count (- period elapsed)) threshold)
              signalling))))

(defstruct (vb-stats (:constructor %make-vb-stats))
  "What one deployment's CURRENT period looks like so far — Core BIP9Stats
(versionbits.h:31-47) plus the per-block record BIP9Info carries beside it
(signalling_blocks, versionbits.h:58-59). The two are filled by the same walk,
Core gates both on the same `stats.has_value()' and renders them one after the
other (rpc/blockchain.cpp:1332-1349), so they travel together here."
  (period 1 :type (integer 1))
  (threshold 0 :type (integer 0))
  (elapsed 0 :type (integer 0))
  (count 0 :type (integer 0))
  (possible nil :type boolean)
  ;; Indexed from the START of the period; see VERSIONBITS-STATISTICS.
  (signalling #* :type simple-bit-vector))

(defun versionbits-info (chain-state entry deployment)
  "(values CURRENT NEXT SINCE STATS ACTIVE-SINCE) for DEPLOYMENT at ENTRY —
Core VersionBitsCache::Info (versionbits.cpp:188-227), the shape
getdeploymentinfo renders. STATS is a VB-STATS while signalling applies and
NIL otherwise (Core's std::optional<BIP9Stats>), and ACTIVE-SINCE is a height
or NIL (Core's std::optional<int> active_since).

⚠️ CURRENT and NEXT are the states of DIFFERENT blocks. Core's `status' is
GetStateFor(pindex->pprev), the state OF this block, and `status_next' is
GetStateFor(pindex), the state of the NEXT one (versionbits.cpp:197-203).
Reporting one value twice is the easy mistake here.

⚠️ Core has TWO ways a deployment is active-since (versionbits.cpp:219-223):
the state IS active, or the NEXT block's state is. Dropping the second is an
off-by-one reachable on the live mainnet node, which holds the header at
taproot's activation height minus one.

⚠️ The LOCKED_IN override below is Info's, not the counting walk's:
VERSIONBITS-STATISTICS stays state-blind, exactly as GetStateStatisticsFor is,
so a caller that wants the raw counting result still gets it."
  (let* ((prev (and entry (bl.store:block-index-entry-prev-entry entry)))
         (height (if entry (bl.store:block-index-entry-height entry) 0))
         (current (versionbits-state chain-state prev deployment))
         (next (versionbits-state chain-state entry deployment))
         (since (versionbits-since-height chain-state prev deployment))
         (stats
           ;; Core fills the statistics only in the two states where signalling
           ;; is still being counted (versionbits.cpp:210-212).
           (when (member current '(:started :locked-in))
             (multiple-value-bind (period threshold elapsed count possible signalling)
                 (versionbits-statistics chain-state entry deployment)
               ;; Lock-in is already decided, so there is no threshold left to
               ;; meet and nothing left that could fail: Core zeroes the
               ;; threshold and clears `possible' (versionbits.cpp:214-217),
               ;; which is what makes SoftForkDescPushBack's
               ;; `threshold > 0 || possible' guard drop both keys.
               (when (eq current :locked-in)
                 (setf threshold 0 possible nil))
               (%make-vb-stats :period period :threshold threshold
                               :elapsed elapsed :count count
                               :signalling signalling :possible possible)))))
    (values current next since stats
            (cond ((eq current :active) since)
                  ((eq next :active) (1+ height))))))

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

;;;; --- The bits nobody claimed (versionbits.cpp:295-345) --------------------
;;;;
;;;; A soft fork this node has never heard of announces itself the same way one
;;;; it knows does: blocks start setting a version bit. Core runs the BIP9 state
;;;; machine over every bit no deployment of ours would set, and once such a bit
;;;; has locked in and activated it says so, because from that moment the
;;;; majority hashrate is enforcing rules this binary does not know.

(defconstant +versionbits-num-bits+ 29
  "Core VERSIONBITS_NUM_BITS (versionbits.h:25): the bits below the three
top bits, any of which a deployment we have never heard of could be using.")

(defparameter *min-bip9-warning-heights*
  '((:mainnet . 483840)                 ; segwit activation + one window
    (:testnet3 . 836640)                ; likewise
    (:testnet4 . 0)
    (:signet . 0)
    (:regtest . 0))
  "Core consensus.MinBIP9WarningHeight (kernel/chainparams.cpp:95, 226, 333,
490, 574): the height below which an unexpected version bit says nothing,
because the chain's own history is full of blocks that set bits for reasons
older than BIP9. Transcribed here rather than added to CHAIN-PARAMS for the
reason *VERSIONBITS-DEPLOYMENTS* is: this file is the only reader, and a value
that sits beside the table it belongs to is one a reader can check against
Core.")

(defstruct (vb-warning-checker (:include vb-deployment)
                               (:constructor %make-vb-warning-checker))
  "Core WarningBitsConditionChecker (versionbits.cpp:295-330): the BIP9 state
machine run over ONE bit, as though a deployment we have never heard of were
using it.

It is NOT a deployment — it appears in no chain's deployment list and
getdeploymentinfo never sees one — but it IS a threshold-condition checker, so
it carries the same window fields and runs through the same VERSIONBITS-STATE.
That is Core's relationship between its two checker classes exactly, and the
only member they do not share is Condition.

Its window is the whole of time (BeginTime 0, EndTime int64 max), so it can
never FAIL: nothing but signalling ever moves it out of STARTED."
  ;; Core's two extra members: the chain's MinBIP9WarningHeight, and the
  ;; consensus params Condition reads to ask what a bit would mean to us.
  (min-warning-height 0 :type integer)
  (network :mainnet :type keyword))

(defun %vb-warning-window (network)
  "(values PERIOD THRESHOLD) for NETWORK's warning checkers — Core
WarningBitsConditionChecker's constructor (versionbits.cpp:309-315): 2016 and
BIP341's 90% on mainnet, and on every test chain the difficulty adjustment
interval with BIP9's suggested 75%."
  (if (eq network :mainnet)
      (values 2016 1815)
      (let ((period (bl.store:difficulty-adjustment-interval network)))
        (values period (truncate (* period 3) 4)))))

(defvar *vb-warning-checkers* (make-hash-table :test 'equal :synchronized t)
  "(NETWORK . BIT) -> VB-WARNING-CHECKER, interned. Core builds a checker per
scan but hands it the PERSISTENT m_warning_caches.at(bit) (versionbits.cpp:
333-345); ours reaches its cache through its own identity, so the identity is
what has to be stable.")

(defun vb-warning-checker (network bit)
  "NETWORK's warning checker for BIT."
  (let ((key (cons network bit)))
    (or (gethash key *vb-warning-checkers*)
        (setf (gethash key *vb-warning-checkers*)
              (multiple-value-bind (period threshold) (%vb-warning-window network)
                (%make-vb-warning-checker
                 :name (format nil "unknown-bit-~D" bit)
                 :bit bit
                 :start-time 0
                 :timeout +vb-no-timeout+
                 :min-activation-height 0
                 :threshold threshold
                 :period period
                 :network network
                 :min-warning-height
                 (or (cdr (assoc network *min-bip9-warning-heights*)) 0)))))))

(defun clear-versionbits-warning-cache ()
  "Forget every cached threshold state. Called when the deployment table
changes under us (-vbparams), because the warning condition below reads that
table through COMPUTE-BLOCK-VERSION: Core builds its chainparams once and so
never has to."
  (clrhash *versionbits-warning-cache*))

(defun %vb-bit-claimed-p (chain-state entry bit network)
  "T when a deployment we know about would set BIT in the version of a block
built on ENTRY — Core's `((::ComputeBlockVersion(pindex->pprev, m_params,
m_caches) >> m_bit) & 1) == 0', asked one bit at a time (versionbits.cpp:328).

The same answer as reading COMPUTE-BLOCK-VERSION's value: that value is
VERSIONBITS_TOP_BITS ORed with the Mask() of every STARTED or LOCKED_IN
deployment, each mask a single bit, and the top bits all sit above
VERSIONBITS_NUM_BITS. Asked this way it costs a threshold-state lookup only for
a deployment that uses the bit — no work at all for the twenty-seven bits no
deployment has ever claimed, which are exactly the bits this whole scan is
about. Computing the whole version instead would run the state machine for
every deployment on every block of every period, and each of those lookups
walks back to a period boundary through PREV-ENTRY (Core's GetAncestor is a
skip list; BL.STORE:ENTRY-ANCESTOR-AT-HEIGHT is a walk), which on a synced
mainnet node is minutes of validation thread on the first block past IBD."
  (dolist (deployment (versionbits-deployments network) nil)
    (when (and (= (vb-deployment-bit deployment) bit)
               (member (versionbits-state chain-state entry deployment)
                       '(:started :locked-in)))
      (return t))))

(defun %vb-warning-condition-p (chain-state entry checker)
  "Core WarningBitsConditionChecker::Condition (versionbits.cpp:323-329): the
block is at or above the chain's MinBIP9WarningHeight, carries the versionbits
top bits, sets this bit — and the bit is NOT one a block WE would build on the
same parent sets, i.e. no deployment we know of explains it.

Core's clause order, which is also cheapest-first: the last clause is the only
one that touches the chain, and it is reached only for a block that actually
signals the bit."
  (let ((bit (vb-deployment-bit checker))
        (v (bl.ser:block-header-version
            (bl.store:block-index-entry-header entry))))
    (and (>= (bl.store:block-index-entry-height entry)
             (vb-warning-checker-min-warning-height checker))
         (= (logand v +vb-top-mask+) +vb-top-bits+)
         (logbitp bit v)
         (not (%vb-bit-claimed-p chain-state
                                 (bl.store:block-index-entry-prev-entry entry)
                                 bit
                                 (vb-warning-checker-network checker))))))

(defun check-unknown-activations (chain-state entry &optional (network bl:*network*))
  "The version bits an unknown soft fork appears to be deploying on the chain
ending at ENTRY: a list of (BIT . ACTIVE-P) in bit order — Core
VersionBitsCache::CheckUnknownActivations (versionbits.cpp:333-345). A bit
appears once its own BIP9 window has LOCKED_IN, and ACTIVE-P says which of the
two states it has reached.

Only bits no deployment of ours would set are counted, so our own signalling
can never raise this; that is the whole of %VB-WARNING-CONDITION-P's last
clause."
  (let ((*versionbits-state-cache* *versionbits-warning-cache*))
    (loop for bit from 0 below +versionbits-num-bits+
          for state = (versionbits-state chain-state entry
                                         (vb-warning-checker network bit))
          when (member state '(:locked-in :active))
            collect (cons bit (eq state :active)))))
