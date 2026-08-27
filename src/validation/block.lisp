(in-package #:bitcoin-lisp.validation)

;;; Block Validation
;;;
;;; This module validates Bitcoin blocks according to consensus rules.
;;; Uses Coalton types for amounts (Satoshi) and heights (BlockHeight).

;;;; Constants

(defconstant +max-block-sigops-cost+ 80000)  ; BIP 141: max weighted sigops cost
;; +max-block-weight+ and +witness-scale-factor+ are defined in
;; transaction.lisp, which compiles first and needs both for
;; CheckTransaction's per-transaction size limit.
(defconstant +max-disconnected-tx-pool-bytes+ 20000000
  "Cap on the transactions held for mempool re-add while a reorg is in flight
(Core MAX_DISCONNECTED_TX_POOL_BYTES, kernel/disconnected_transactions.h:18).")

(defun trim-disconnect-pool (entries bytes)
  "Bound the reorg disconnect pool (Core LimitMemoryUsage,
kernel/disconnected_transactions.cpp:31). ENTRIES is one (TXS . BYTES) cons
per disconnected block, OLDEST block first, with the block nearest the old tip
at the tail; BYTES is their running total. Returns
(values kept-entries kept-bytes dropped-tx-count).

Drops from the TAIL — the most-recently-confirmed blocks. Core does the same
(its queue holds newest at the front and it pops the front), and the direction
is the whole point: the re-add walks oldest-first, so keeping the oldest keeps
PARENTS. Trimming the oldest instead would strand children with missing inputs
— they would fail re-validation anyway, and we would have discarded the
entries most likely to still be valid. Never trims to empty."
  (let ((dropped 0))
    (loop while (and (> bytes +max-disconnected-tx-pool-bytes+)
                     (cdr entries))
          do (let ((newest (car (last entries))))
               (decf bytes (cdr newest))
               (incf dropped (length (car newest)))
               (setf entries (butlast entries))))
    (values entries bytes dropped)))

(defconstant +max-future-block-time+ 7200)  ; 2 hours in seconds
(defconstant +max-timewarp+ 600
  "BIP 94 timewarp-attack mitigation: on networks that enforce BIP 94
(testnet4), the first block of each difficulty-adjustment period may not
be timestamped more than this many seconds before the previous block.
Bitcoin Core MAX_TIMEWARP (consensus/consensus.h:35).")

;;; Locktime activation heights (BIPs 65/68/112/113)

(defconstant +bip66-activation-height-mainnet+ 363725
  "BIP 66 (DERSIG/strict DER) activation height on mainnet.")
(defconstant +bip66-activation-height-testnet3+ 330776
  "BIP 66 (DERSIG/strict DER) activation height on testnet.")

(defconstant +bip65-activation-height-mainnet+ 388381
  "BIP 65 (CLTV) activation height on mainnet.")
(defconstant +bip65-activation-height-testnet3+ 581885
  "BIP 65 (CLTV) activation height on testnet.")

(defconstant +csv-activation-height-mainnet+ 419328
  "BIP 68/112/113 (CSV soft fork) activation height on mainnet.")
(defconstant +csv-activation-height-testnet3+ 770112
  "BIP 68/112/113 (CSV soft fork) activation height on testnet.")

(defconstant +segwit-activation-height-mainnet+ 481824
  "BIP 141 (SegWit) activation height on mainnet.")
(defconstant +segwit-activation-height-testnet3+ 834624
  "BIP 141 (SegWit) activation height on testnet3.")

(defconstant +taproot-activation-height-mainnet+ 709632
  "BIP 341 (Taproot) activation height on mainnet.")
(defconstant +taproot-activation-height-testnet3+ 2346882
  "BIP 341 (Taproot) activation height on testnet3.")

;;; P2SH is active from block 173805 (mainnet) but enforced from genesis on testnet.
;;; BIP 66 (DERSIG) and BIP 147 (NULLDUMMY) activate with SegWit on most networks.

(defconstant +locktime-threshold+ 500000000
  "Threshold for height vs time-based locktime. Values below are block heights,
values at or above are Unix timestamps.")

(defconstant +sequence-disable-flag+ #x80000000
  "BIP 68: If set, nSequence is not interpreted as relative locktime.")
(defconstant +sequence-type-flag+ #x00400000
  "BIP 68: If set, relative locktime is time-based (512-second units).")
(defconstant +sequence-locktime-mask+ #x0000FFFF
  "BIP 68: Mask for the relative locktime value.")
(defconstant +sequence-locktime-granularity+ 512
  "BIP 68: Time-based relative locktime granularity in seconds.")
(defconstant +sequence-final+ #xFFFFFFFF
  "Fully final sequence number (disables nLockTime for input).")

;;;; Median-Time-Past (BIP 113)

(defconstant +median-time-span+ 11
  "Number of previous blocks used to compute median-time-past.")

(defun compute-median-time-past-from-entry (entry)
  "Median-time-past of ENTRY: the median of its own timestamp and up to its 10
ancestors', walking the PREV-ENTRY chain — Bitcoin Core
CBlockIndex::GetMedianTimePast (chain.h:233-246). Returns NIL when ENTRY is NIL.
The entry chain is the only walk that can see a parent which is not (yet) in the
block index, such as a header staged earlier in the same batch."
  (when entry
    (let ((timestamps '())
          (e entry))
      (dotimes (i +median-time-span+)
        (unless e (return))
        (push (bitcoin-lisp.serialization:block-header-timestamp
               (bitcoin-lisp.storage:block-index-entry-header e))
              timestamps)
        (setf e (bitcoin-lisp.storage:block-index-entry-prev-entry e)))
      (nth (floor (length timestamps) 2) (sort timestamps #'<)))))

(defun compute-median-time-past (chain-state prev-hash)
  "Compute the median-time-past for the block following PREV-HASH.
Returns NIL when PREV-HASH is not in the block index: absence is not a time, and
a numeric fallback silently satisfies a consensus comparison such as
(<= timestamp mtp). Callers on a consensus path must reject on NIL; informational
callers substitute their own default."
  (compute-median-time-past-from-entry
   (bitcoin-lisp.storage:get-block-index-entry chain-state prev-hash)))

;;;; Transaction finality check (IsFinalTx)

(defun check-transaction-final (tx block-height block-time)
  "Check if TX is final per consensus rules.
A transaction is final if:
- nLockTime is 0
- All input sequences are SEQUENCE_FINAL (0xFFFFFFFF)
- nLockTime < block-height (height-based) or nLockTime < block-time (time-based)
Returns T if final, NIL if not."
  (let ((locktime (bitcoin-lisp.serialization:transaction-lock-time tx)))
    ;; nLockTime == 0 means always final
    (when (zerop locktime)
      (return-from check-transaction-final t))
    ;; Check if locktime is satisfied
    (let ((threshold (if (< locktime +locktime-threshold+)
                         block-height    ; height-based
                         block-time)))   ; time-based
      (when (< locktime threshold)
        (return-from check-transaction-final t)))
    ;; If locktime not satisfied, tx is final only if ALL sequences are final
    (every (lambda (input)
             (= (bitcoin-lisp.serialization:tx-in-sequence input) +sequence-final+))
           (bitcoin-lisp.serialization:transaction-inputs tx))))

;;;; BIP 68 Sequence Lock Enforcement

(defun check-sequence-locks (tx utxo-set current-height mtp chain-state
                             &key pending-utxos)
  "Check BIP 68 relative locktime for TX.
For each input with version >= 2 and sequence not disabled (bit 31 clear):
- Height-based: input UTXO must be at least N blocks deep
- Time-based: MTP must be >= N*512 seconds after UTXO's MTP
Returns T if all locks satisfied, NIL if any lock not yet matured."
  ;; BIP 68 applies to version >= 2, compared UNSIGNED. Core stores the version
  ;; as `const uint32_t\' (primitives/transaction.h:293) and gates on
  ;; `tx.version >= 2\' (consensus/tx_verify.cpp:51), so every version with bit
  ;; 31 set is >= 2 and IS enforced. We store the slot as (signed-byte 32) —
  ;; correct, since that is what the wire format reads — so the same bytes come
  ;; back negative and a signed compare skipped BIP68 entirely for them. Version
  ;; 0x80000002 spending an unmatured relative locktime was accepted here and
  ;; rejected by Core as bad-txns-nonfinal.
  ;;
  ;; Reinterpret at the GATE, not in the struct: the slot must stay signed so
  ;; serialization keeps round-tripping, and every other reader of the version
  ;; keeps the value the wire actually carries.
  (when (< (ldb (byte 32 0) (bitcoin-lisp.serialization:transaction-version tx)) 2)
    (return-from check-sequence-locks t))
  (bitcoin-lisp.serialization:dovector (input (bitcoin-lisp.serialization:transaction-inputs tx) t)
    (let ((seq (bitcoin-lisp.serialization:tx-in-sequence input)))
      ;; Skip if disable flag is set
      (unless (logtest seq +sequence-disable-flag+)
        (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
               (prev-txid (bitcoin-lisp.serialization:outpoint-hash prevout))
               (prev-index (bitcoin-lisp.serialization:outpoint-index prevout))
               (utxo (or (and pending-utxos
                              (gethash (cons prev-txid prev-index) pending-utxos))
                         (bitcoin-lisp.storage:get-utxo utxo-set prev-txid prev-index))))
          (unless utxo
            (return-from check-sequence-locks nil))
          (let ((utxo-height (bitcoin-lisp.storage:utxo-entry-height utxo)))
            (if (logtest seq +sequence-type-flag+)
                ;; Time-based relative locktime.
                ;; Bitcoin Core uses block.GetAncestor(max(nCoinHeight-1, 0))->GetMedianTimePast()
                ;; — the MTP of the block PRIOR to the input's confirmation block, not the
                ;; confirmation block itself (consensus/tx_verify.cpp:74).
                (let* ((required-time (* (logand seq +sequence-locktime-mask+)
                                         +sequence-locktime-granularity+))
                       (utxo-prev-height (max 0 (1- utxo-height)))
                       (utxo-prev-entry (bitcoin-lisp.storage:get-block-at-height
                                         chain-state utxo-prev-height))
                       (utxo-mtp (or (compute-median-time-past-from-entry
                                      utxo-prev-entry)
                                     0)))
                  (when (< (- mtp utxo-mtp) required-time)
                    (return-from check-sequence-locks nil)))
                ;; Height-based relative locktime
                (let ((required-height (logand seq +sequence-locktime-mask+)))
                  (when (< (- current-height utxo-height) required-height)
                    (return-from check-sequence-locks nil))))))))))

;;;; Script verification flags

;;;; -testactivationheight (Core chainparams.cpp:49-67)
;;;;
;;;; Moves a BURIED deployment's activation height so a regtest chain can be
;;;; driven across it in a handful of blocks instead of thousands. Core's
;;;; functional suite leans on it heavily — a test that wants pre-BIP66
;;;; behaviour cannot otherwise reach it on a chain that activates at height 1.

(defvar *test-activation-heights* (make-hash-table :test 'equal)
  "Deployment name -> overridden activation height, from -testactivationheight.
Empty unless the option was given. Core stores the same overrides in
options.activation_heights and applies them when building chainparams.")

(defparameter +buried-deployment-names+
  '("segwit" "bip34" "dersig" "cltv" "csv")
  "The deployments -testactivationheight can move, spelled as Core spells them
(GetBuriedDeployment, deploymentinfo.cpp:41-54). `dersig` is BIP66 and `cltv`
is BIP65 — the option takes the deployment's name, not the BIP number.")

(defun parse-test-activation-height (spec)
  "Parse one -testactivationheight value, `name@height`, into (VALUES name
height), or NIL when malformed. Core raises on a missing '@', a height that is
not a non-negative integer, and a name that is not a buried deployment
(chainparams.cpp:49-67)."
  (when (stringp spec)
    (let ((at (position #\@ spec)))
      (when at
        (let ((name (subseq spec 0 at))
              (value (subseq spec (1+ at))))
          (when (and (member name +buried-deployment-names+ :test #'string=)
                     (plusp (length value))
                     (every #'digit-char-p value))
            (let ((height (parse-integer value :junk-allowed t)))
              (when (and height (>= height 0))
                (values name height)))))))))

(defun apply-test-activation-heights (specs)
  "Install the -testactivationheight overrides in SPECS. Signals on a malformed
entry, as Core does — a typo'd deployment name that was silently ignored would
leave the test running against the height it was trying to move."
  (clrhash *test-activation-heights*)
  (dolist (spec specs)
    (multiple-value-bind (name height) (parse-test-activation-height spec)
      (unless name
        (error "Invalid -testactivationheight=~A. Expected name@height, where ~
name is one of ~{~A~^, ~} and height is a non-negative integer."
               spec +buried-deployment-names+))
      (setf (gethash name *test-activation-heights*) height))))

(defun %activation-height (name default)
  "DEFAULT unless -testactivationheight moved NAME."
  (or (gethash name *test-activation-heights*) default))

(defun get-bip66-activation-height (network)
  "Return the BIP 66 (DERSIG) activation height for NETWORK."
  (%activation-height "dersig"
   (ecase network
    (:testnet3 +bip66-activation-height-testnet3+)
    ((:testnet4 :signet :regtest) 1)
    (:mainnet +bip66-activation-height-mainnet+))))

(defun get-bip65-activation-height (network)
  "Return the BIP 65 (CLTV) activation height for NETWORK."
  (%activation-height "cltv"
   (ecase network
    (:testnet3 +bip65-activation-height-testnet3+)
    ((:testnet4 :signet :regtest) 1)
    (:mainnet +bip65-activation-height-mainnet+))))

(defun get-csv-activation-height (network)
  "Return the BIP 68/112/113 (CSV) activation height for NETWORK."
  (%activation-height "csv"
   (ecase network
    (:testnet3 +csv-activation-height-testnet3+)
    ((:testnet4 :signet :regtest) 1)
    (:mainnet +csv-activation-height-mainnet+))))

(defun get-taproot-activation-height (network)
  "Return the BIP 341 (Taproot) activation height for NETWORK."
  (ecase network
    (:testnet3 +taproot-activation-height-testnet3+)
    ((:testnet4 :signet) 1)
    ;; Regtest activates Taproot from genesis (Core ALWAYS_ACTIVE).
    (:regtest 0)
    (:mainnet +taproot-activation-height-mainnet+)))

(defun get-segwit-activation-height (network)
  "Return the BIP 141 (SegWit) activation height for NETWORK."
  (%activation-height "segwit"
   (ecase network
    (:testnet3 +segwit-activation-height-testnet3+)
    ((:testnet4 :signet) 1)
    ;; Regtest activates SegWit from genesis (Core SegwitHeight = 0).
    (:regtest 0)
    (:mainnet +segwit-activation-height-mainnet+))))

;;; Policy vs Consensus Flag Separation
;;;
;;; Bitcoin Core distinguishes MANDATORY (consensus) flags from STANDARD (policy) flags.
;;; Mandatory flags are required for block validation. Standard flags add policy
;;; restrictions for mempool acceptance and transaction relay.

(defparameter +standard-policy-flags+
  '("STRICTENC" "MINIMALDATA" "DISCOURAGE_UPGRADABLE_NOPS"
    "CLEANSTACK" "MINIMALIF" "NULLFAIL" "LOW_S"
    "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" "WITNESS_PUBKEYTYPE"
    "CONST_SCRIPTCODE" "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION"
    "DISCOURAGE_OP_SUCCESS" "DISCOURAGE_UPGRADABLE_PUBKEYTYPE")
  "Policy flags layered on top of mandatory consensus flags for mempool acceptance
(Core STANDARD_SCRIPT_VERIFY_FLAGS minus MANDATORY_SCRIPT_VERIFY_FLAGS =
STANDARD_NOT_MANDATORY_VERIFY_FLAGS, policy/policy.h:118-134).")

(defparameter +mandatory-script-verify-flags+
  '("P2SH" "DERSIG" "NULLDUMMY" "CHECKLOCKTIMEVERIFY"
    "CHECKSEQUENCEVERIFY" "WITNESS" "TAPROOT")
  "Core MANDATORY_SCRIPT_VERIFY_FLAGS (policy/policy.h:104-110): the flags all
NEW transactions must comply with. A height-independent CONSTANT in Core —
distinct from GetBlockScriptFlags/compute-script-flags-for-height, which gate
each flag on its activation height for block (consensus) validation.")

(defparameter +standard-script-verify-flags+
  (format nil "~{~A~^,~}" (append +mandatory-script-verify-flags+
                                  +standard-policy-flags+))
  "Core STANDARD_SCRIPT_VERIFY_FLAGS (policy/policy.h:118-133) as the
comma-separated flag string the script engine consumes: the mandatory set
plus every policy flag. This is what MemPoolAccept::PolicyScriptChecks runs
(validation.cpp:1140) — a constant, not a per-height computation, because
the mempool only ever validates against the current tip where every
deployment is active.")

(defparameter +always-on-block-script-flags+
  '("P2SH" "WITNESS" "TAPROOT")
  "The flags Core turns on for EVERY block, whatever its height
(GetBlockScriptFlags, validation.cpp:2259).

Gating these on activation height — which this did until now — is a consensus
divergence, and not a theoretical one: a block below segwit activation that
spends a v0 witness program with an empty scriptSig and no witness is
WITNESS_PROGRAM_WITNESS_EMPTY to Core and ANYONE-CAN-SPEND to a node that
leaves WITNESS off. The same argument applies to TAPROOT below 709,632.

Core can afford to leave them on because it carries a table of the handful of
historic blocks that break a rule (SCRIPT-FLAG-EXCEPTION below), and it says so
outright: `For simplicity, always leave P2SH+WITNESS+TAPROOT on except for the
two violating blocks' (validation.cpp:2256-2257).

That comment is the citation. A second argument is that the mainnet taproot
exception block sits below taproot activation, so the entry would be
unreachable under height-gating — but note that the height is a property of the
chain, not of Core's source: chainparams.cpp records only the block HASH for
all three entries, never a height.")

(defun %or-height-gated-script-flags (flags height)
  "OR onto FLAGS the deployments that have activated at HEIGHT
(GetBlockScriptFlags, validation.cpp:2266-2285).

Core applies these AFTER any script_flag_exceptions override, which is the
whole reason this is a separate step: an exception replaces the base set and
still gets every rule its height has activated.

Returns the list sorted, because Core's GetScriptFlagNames walks a std::map
keyed by name and so reports flags alphabetically (interpreter.cpp:2168-2211);
`getdeploymentinfo' hands that array straight to the caller."
  (let ((network bitcoin-lisp:*network*))
    (when (>= height (get-bip66-activation-height network))
      (push "DERSIG" flags))
    (when (>= height (get-bip65-activation-height network))
      (push "CHECKLOCKTIMEVERIFY" flags))
    (when (>= height (get-csv-activation-height network))
      (push "CHECKSEQUENCEVERIFY" flags))
    ;; BIP147 activated simultaneously with segwit, and Core keys it on the
    ;; SEGWIT deployment rather than on a NULLDUMMY one (validation.cpp:2283).
    (when (>= height (get-segwit-activation-height network))
      (push "NULLDUMMY" flags))
    (sort flags #'string<)))

(defun mandatory-script-flags-list (height)
  "Block script flags at HEIGHT for a block with no script-flag exception:
the always-on set plus whatever HEIGHT has activated.

Callers that HAVE the block hash must use BLOCK-SCRIPT-FLAGS-LIST instead —
this one cannot see the exception table."
  (%or-height-gated-script-flags
   (copy-list +always-on-block-script-flags+) height))

(defun compute-script-flags-for-height (height)
  "Comma-separated block script verification flags at HEIGHT, for a block with
no script-flag exception (Bitcoin Core GetBlockScriptFlags)."
  (format nil "~{~A~^,~}" (mandatory-script-flags-list height)))


;;; BIP 16 (P2SH) exception block hash for testnet3
;;; This block predates proper BIP 16 enforcement and must skip script validation
;;; See Bitcoin Core's chainparams.cpp: consensus.script_flag_exceptions
;;; Note: Block hashes are displayed in big-endian but stored in little-endian (reversed)
(defvar *bip16-exception-testnet*
  (bitcoin-lisp.crypto:reverse-bytes
   (bitcoin-lisp.crypto:hex-to-bytes "00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105"))
  "Block hash that is exempted from BIP 16 script verification on testnet3 (little-endian).")

;;; BIP 16 (P2SH) exception block hash for mainnet
(defvar *bip16-exception-mainnet*
  (bitcoin-lisp.crypto:reverse-bytes
   (bitcoin-lisp.crypto:hex-to-bytes "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"))
  "Block hash that is exempted from BIP 16 script verification on mainnet (little-endian).")

;;; Taproot script-flag exception block for mainnet (Core chainparams.cpp
;;; script_flag_exceptions): block 0000...e395ad (height 692261) contains a
;;; witness-v1 spend that fails full BIP341 verification, so Core validates it
;;; with P2SH|WITNESS only (taproot disabled for that one block).
(defvar *taproot-exception-mainnet*
  (bitcoin-lisp.crypto:reverse-bytes
   (bitcoin-lisp.crypto:hex-to-bytes "0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad"))
  "Block hash validated with P2SH|WITNESS only on mainnet (little-endian).")

(defun script-flag-exception (block-hash)
  "Core's consensus.script_flag_exceptions for BLOCK-HASH
(kernel/chainparams.cpp:85-88 mainnet, :218-219 testnet3; testnet4, signet and
regtest have no entries).

Returns (VALUES FLAGS FOUND-P). FLAGS is the BASE flag set that REPLACES the
always-on set — NIL means SCRIPT_VERIFY_NONE, which is exactly why the second
value has to exist: an empty list and `no entry' are the same object in CL.

Two things about how Core uses this table are easy to get backwards, and both
were wrong here before:

  - the entry REPLACES the base set and is then still ORed with the height-gated
    flags (validation.cpp:2260-2285). The mainnet taproot exception is
    P2SH|WITNESS, but the block sits at height 692,261, where DERSIG, CLTV, CSV
    and NULLDUMMY are all long active — so it is verified with SIX flags, not
    two. An exception disables the rule the block broke, not every rule.
  - SCRIPT_VERIFY_NONE means run every script with no flags. It does NOT mean
    skip validation: the scripts must still evaluate true, and a block whose
    scripts are outright invalid is still rejected."
  (ecase bitcoin-lisp:*network*
    (:mainnet
     (cond ((equalp block-hash *bip16-exception-mainnet*) (values '() t))
           ((equalp block-hash *taproot-exception-mainnet*)
            (values (list "P2SH" "WITNESS") t))
           (t (values nil nil))))
    (:testnet3
     (if (equalp block-hash *bip16-exception-testnet*)
         (values '() t)
         (values nil nil)))
    ;; testnet4, signet and regtest emplace nothing (chainparams.cpp:320, :433,
    ;; :559 have no script_flag_exceptions at all). The table is per-chain
    ;; consensus data, so matching a mainnet hash on regtest would hand a
    ;; block an exemption its own chain never granted.
    ((:testnet4 :signet :regtest) (values nil nil))))

(defun block-script-flags-list (block-hash height)
  "Script verification flags for the block BLOCK-HASH names at HEIGHT, as a
sorted list of strings. This is Core's GetBlockScriptFlags
(validation.cpp:2255-2287) in full:

    base = P2SH | WITNESS | TAPROOT              ; every block
    if hash in script_flag_exceptions: base = that entry   ; REPLACES
    then OR DERSIG / CLTV / CSV / NULLDUMMY that are active at HEIGHT

Every consensus caller that has the block hash must use this rather than
MANDATORY-SCRIPT-FLAGS-LIST, and that means the sigop counter as well as the
script checker: Core feeds the same GetBlockScriptFlags result into
GetTransactionSigOpCost (validation.cpp ConnectBlock), so the exception has to
reach sigop accounting too or the BIP16 exception block is counted with P2SH
sigops Core does not count."
  (multiple-value-bind (exception found) (script-flag-exception block-hash)
    (%or-height-gated-script-flags
     (copy-list (if found exception +always-on-block-script-flags+))
     height)))

(defun block-script-flags (block-hash height)
  "BLOCK-SCRIPT-FLAGS-LIST as the comma-separated string the script engine
consumes. An empty string is SCRIPT_VERIFY_NONE: PARSE-FLAGS-TO-SET splits it
into one empty token, which matches no flag name."
  (format nil "~{~A~^,~}" (block-script-flags-list block-hash height)))

;;;; Difficulty adjustment validation

(defconstant +testnet-min-difficulty-spacing+ 1200
  "Seconds (20 minutes) after which testnet allows min-difficulty blocks.")

(defun testnet-min-difficulty-allowed-p (block-timestamp prev-timestamp)
  "Check if a testnet block is allowed to use minimum difficulty.
Returns T if more than 20 minutes have elapsed since the previous block."
  (> block-timestamp (+ prev-timestamp +testnet-min-difficulty-spacing+)))

(defun testnet-walk-back-bits (entry)
  "Walk back through the chain from ENTRY to find the last non-min-difficulty bits.
Stops at a block that either sits at a retarget boundary (height % 2016 == 0)
or does not have min-difficulty bits. Returns that block's bits value."
  (let ((current entry))
    (loop while (and current
                     (bitcoin-lisp.storage:block-index-entry-prev-entry current)
                     (/= 0 (mod (bitcoin-lisp.storage:block-index-entry-height current)
                                 bitcoin-lisp.storage:+difficulty-adjustment-interval+))
                     (= (bitcoin-lisp.serialization:block-header-bits
                         (bitcoin-lisp.storage:block-index-entry-header current))
                        bitcoin-lisp.storage:+pow-limit-bits+))
          do (setf current (bitcoin-lisp.storage:block-index-entry-prev-entry current)))
    (if (and current (bitcoin-lisp.storage:block-index-entry-header current))
        (bitcoin-lisp.serialization:block-header-bits
         (bitcoin-lisp.storage:block-index-entry-header current))
        bitcoin-lisp.storage:+pow-limit-bits+)))

(defun get-retarget-ancestor (entry)
  "Walk back from ENTRY to the block at the start of its retarget period.
For a block at height H, this returns the entry at height H - (H mod 2016).
Bitcoin Core's off-by-one: the timespan is measured from this block to ENTRY."
  (let* ((height (bitcoin-lisp.storage:block-index-entry-height entry))
         (interval bitcoin-lisp.storage:+difficulty-adjustment-interval+)
         (blocks-back (mod height interval))
         (current entry))
    (dotimes (i blocks-back)
      (let ((prev (bitcoin-lisp.storage:block-index-entry-prev-entry current)))
        (unless prev (return))
        (setf current prev)))
    current))

(defun get-expected-bits (height prev-entry)
  "Compute the expected bits for a block at HEIGHT with previous block PREV-ENTRY.
Handles: first retarget period, retarget boundaries, non-boundaries,
and testnet min-difficulty exception."
  (let ((interval bitcoin-lisp.storage:+difficulty-adjustment-interval+))
    (cond
      ;; Genesis block or no previous entry
      ((or (zerop height) (null prev-entry))
       bitcoin-lisp.storage:+pow-limit-bits+)

      ;; Regtest never retargets (Bitcoin Core fPowNoRetargeting): every block
      ;; inherits the previous block's bits, so difficulty stays at the trivial
      ;; regtest pow-limit. Checked before the boundary case to skip retargeting.
      ((eq bitcoin-lisp:*network* :regtest)
       (bitcoin-lisp.serialization:block-header-bits
        (bitcoin-lisp.storage:block-index-entry-header prev-entry)))

      ;; Retarget boundary (height is a multiple of 2016)
      ((zerop (mod height interval))
       (let* ((last-retarget-entry (get-retarget-ancestor prev-entry))
              (last-retarget-time
                (bitcoin-lisp.serialization:block-header-timestamp
                 (bitcoin-lisp.storage:block-index-entry-header last-retarget-entry)))
              (last-block-time
                (bitcoin-lisp.serialization:block-header-timestamp
                 (bitcoin-lisp.storage:block-index-entry-header prev-entry)))
              ;; BIP 94 (testnet4): the new target is computed from the FIRST block
              ;; of the just-ended retarget period rather than the last block. This
              ;; preserves the real difficulty across periods even when the 20-min
              ;; min-difficulty exception was used near a retarget boundary.
              (basis-entry (if (eq bitcoin-lisp:*network* :testnet4)
                               last-retarget-entry
                               prev-entry))
              (basis-bits
                (bitcoin-lisp.serialization:block-header-bits
                 (bitcoin-lisp.storage:block-index-entry-header basis-entry))))
         (bitcoin-lisp.storage:calculate-next-work-required
          last-retarget-time last-block-time basis-bits)))

      ;; Non-boundary on a chain WITHOUT min-difficulty blocks: inherit the
      ;; previous block's bits, which is all Core does (pow.cpp:38,
      ;; `return pindexLast->nBits'). Signet sets
      ;; fPowAllowMinDifficultyBlocks = false exactly as mainnet does
      ;; (kernel/chainparams.cpp:491) and so belongs here; it used to fall
      ;; through to the NIL arm, where validate-difficulty routes NIL into the
      ;; testnet min-difficulty branch, which tests only :testnet3/:testnet4 --
      ;; so signet reached the terminal reject and 2015 of every 2016 blocks
      ;; were :bad-difficulty.
      ((member bitcoin-lisp:*network* '(:mainnet :signet))
       (bitcoin-lisp.serialization:block-header-bits
        (bitcoin-lisp.storage:block-index-entry-header prev-entry)))

      ;; Non-boundary on testnet: return nil to indicate caller must check
      ;; timestamp-based min-difficulty or walk-back
      (t nil))))

(defun validate-difficulty (header height prev-entry)
  "Validate that HEADER's bits field matches expected difficulty at HEIGHT.
PREV-ENTRY is the block-index-entry for the previous block.
Returns (VALUES T NIL) on success, (VALUES NIL :bad-difficulty) on failure."
  (let ((block-bits (bitcoin-lisp.serialization:block-header-bits header))
        (expected (get-expected-bits height prev-entry)))
    (cond
      ;; Got a definitive expected value (mainnet, retarget boundary, or first period)
      (expected
       (if (= block-bits expected)
           (values t nil)
           (values nil :bad-difficulty)))

      ;; Testnet non-boundary: check min-difficulty or walk-back
      ;; Applies to testnet3 and testnet4 (fPowAllowMinDifficultyBlocks=true)
      ((member bitcoin-lisp:*network* '(:testnet3 :testnet4))
       (let* ((prev-header (bitcoin-lisp.storage:block-index-entry-header prev-entry))
              (prev-timestamp (bitcoin-lisp.serialization:block-header-timestamp prev-header))
              (block-timestamp (bitcoin-lisp.serialization:block-header-timestamp header))
              (min-diff-allowed (testnet-min-difficulty-allowed-p
                                 block-timestamp prev-timestamp)))
         ;; Core GetNextWorkRequired (pow.cpp): on a min-difficulty chain, a
         ;; >20-min-gap block's expected nBits is powLimit UNCONDITIONALLY, and
         ;; validation.cpp requires block.nBits == expected exactly. So a
         ;; >20-min block MUST carry powLimit bits -- one at the real walk-back
         ;; difficulty is rejected (bad-diffbits). (Previously we also accepted
         ;; the walk-back value here, which over-accepts vs Core and could split
         ;; us from the testnet network on a crafted/unusual block.)
         (if min-diff-allowed
             (if (= block-bits bitcoin-lisp.storage:+pow-limit-bits+)
                 (values t nil)
                 (values nil :bad-difficulty))
             ;; <=20 min gap: must match the walk-back difficulty.
             (let ((walk-back-bits (testnet-walk-back-bits prev-entry)))
               (if (= block-bits walk-back-bits)
                   (values t nil)
                   (values nil :bad-difficulty))))))

      ;; Shouldn't reach here, but reject if we do
      (t (values nil :bad-difficulty)))))

;;;; Proof of Work validation

(defun check-proof-of-work (header)
  "Verify the block hash meets the claimed target. Mirrors Bitcoin Core
CheckProofOfWork (pow.cpp:161-171): reject nBits whose target is
negative, zero, overflowing, or above the PoW limit (derive-target
returns NIL), then require hash <= target. Returns T if valid."
  (let ((target (bitcoin-lisp.storage:derive-target
                 (bitcoin-lisp.serialization:block-header-bits header))))
    (when target
      (let* ((hash (bitcoin-lisp.serialization:block-header-hash header))
             ;; little-endian: byte 0 is least significant
             (hash-value (loop for i from 0 below 32
                               for byte = (aref hash i)
                               sum (ash byte (* 8 i)))))
        (<= hash-value target)))))

;;;; Merkle root calculation

(defun hash-pair (a b)
  "Hash two 32-byte values together for Merkle tree."
  (let ((combined (make-array 64 :element-type '(unsigned-byte 8))))
    (replace combined a :start1 0)
    (replace combined b :start1 32)
    (bitcoin-lisp.crypto:hash256 combined)))

(defun compute-merkle-root (tx-hashes)
  "Compute the Merkle root from a list of transaction hashes.
Returns (VALUES root mutated). MUTATED is T when any level combines two
identical adjacent siblings — the CVE-2012-2459 malleation: an attacker can
pad a valid block's tx list (duplicating the last row) into a distinct block
that hashes to the SAME merkle root. Mirrors Bitcoin Core ComputeMerkleRoot
(consensus/merkle.cpp): the odd-count self-duplication of the last element is
NOT a mutation, only genuine equal adjacent pairs are. Single-value callers
(merkle-root match) are unaffected."
  (when (null tx-hashes)
    (return-from compute-merkle-root
      (values (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0) nil)))

  (let ((level (mapcar #'copy-seq tx-hashes))
        (mutated nil))
    (loop while (> (length level) 1)
          do (let ((next-level '()))
               (loop while level
                     do (let* ((a (pop level))
                               (real-b (pop level))       ; NIL when count is odd
                               (b (or real-b a)))         ; duplicate last if odd
                          (when (and real-b (equalp a real-b))
                            (setf mutated t))
                          (push (hash-pair a b) next-level)))
               (setf level (nreverse next-level))))
    (values (first level) mutated)))

;;;; Block header validation

(defun bip94-timewarp-violation-p (header height prev-entry)
  "T if HEADER violates the BIP 94 timewarp-attack rule: on testnet4, the
first block of each difficulty-adjustment period (HEIGHT a nonzero
multiple of the adjustment interval) must be timestamped no more than
+max-timewarp+ seconds before its predecessor's ACTUAL time (not MTP).
enforce_BIP94 is true only on testnet4 among our networks. Genesis is
excluded — it satisfies the modulo but has no predecessor. Mirrors
Bitcoin Core ContextualCheckBlockHeader (validation.cpp:4129-4136)."
  (and (eq bitcoin-lisp:*network* :testnet4)
       height prev-entry (plusp height)
       (zerop (mod height bitcoin-lisp.storage:+difficulty-adjustment-interval+))
       (< (bitcoin-lisp.serialization:block-header-timestamp header)
          (- (bitcoin-lisp.serialization:block-header-timestamp
              (bitcoin-lisp.storage:block-index-entry-header prev-entry))
             +max-timewarp+))))

(defun header-time-too-old-p (header prev-entry)
  "T if HEADER's timestamp is at or before PREV-ENTRY's median-time-past —
Bitcoin Core ContextualCheckBlockHeader's time-too-old rule (validation.cpp:4124).
An ancestry that yields no median (a NIL PREV-ENTRY) counts as a violation: the
rule cannot be evaluated, and answering with a neutral time would satisfy the
comparison for every header."
  (let ((mtp (compute-median-time-past-from-entry prev-entry)))
    (or (null mtp)
        (<= (bitcoin-lisp.serialization:block-header-timestamp header) mtp))))

(defun validate-block-header (header chain-state current-time
                               &key prev-hash height prev-entry skip-pow)
  "Validate a block header.
PREV-HASH is the hash of the previous block (for MTP calculation).
HEIGHT and PREV-ENTRY are optional; when provided, difficulty adjustment is validated.
SKIP-POW skips only the hash<=target check (Core's fCheckPOW=false), for
dry-running an unmined block template (TEST-BLOCK-VALIDITY); the contextual
checks — timestamp, timewarp, version, difficulty BITS — still run.
Returns (VALUES T NIL) on success, (VALUES NIL ERROR-KEYWORD) on failure."

  ;; Check proof of work
  (unless (or skip-pow (check-proof-of-work header))
    (return-from validate-block-header
      (values nil :bad-proof-of-work)))

  ;; Check timestamp not too far in future
  (let ((timestamp (bitcoin-lisp.serialization:block-header-timestamp header)))
    (when (> timestamp (+ current-time +max-future-block-time+))
      (return-from validate-block-header
        (values nil :time-too-new)))

    ;; Check timestamp > median-time-past of previous 11 blocks. PREV-ENTRY is
    ;; preferred over the hash: a hash lookup cannot see a parent that is not in
    ;; the index.
    (when (or prev-entry (and chain-state prev-hash))
      (when (header-time-too-old-p
             header (or prev-entry
                        (bitcoin-lisp.storage:get-block-index-entry
                         chain-state prev-hash)))
        (return-from validate-block-header
          (values nil :time-too-old))))

    ;; BIP 94 timewarp-attack mitigation (see bip94-timewarp-violation-p).
    (when (bip94-timewarp-violation-p header height prev-entry)
      (return-from validate-block-header
        (values nil :time-timewarp-attack))))

  ;; Version check: ONLY the softfork minimums, exactly Bitcoin Core
  ;; ContextualCheckBlockHeader (validation.cpp:4144-4147). There is NO
  ;; upper bound and no unconditional lower bound: post-BIP9 miners roll
  ;; version bits freely (overt AsicBoost), producing mainnet blocks with
  ;; versions above #x3FFFFFFF — the previous (> version #x3FFFFFFF)
  ;; clause rejected real mainnet block 544,085 and halted the first
  ;; mainnet IBD run. Negative versions (signed i32) fail the < 2 clause
  ;; post-BIP34, matching Core's implicit behavior.
  (let ((version (bitcoin-lisp.serialization:block-header-version header)))
    (when (and height
               (or (and (< version 2)
                        (>= height (get-bip34-activation-height bitcoin-lisp:*network*)))
                   (and (< version 3)
                        (>= height (get-bip66-activation-height bitcoin-lisp:*network*)))
                   (and (< version 4)
                        (>= height (get-bip65-activation-height bitcoin-lisp:*network*)))))
      (return-from validate-block-header
        (values nil :bad-version))))

  ;; Validate difficulty adjustment
  (when (and height prev-entry)
    (multiple-value-bind (valid error)
        (validate-difficulty header height prev-entry)
      (unless valid
        (return-from validate-block-header
          (values nil error)))))

  (values t nil))

;;;; Block script validation

(defparameter +parallel-validation-min-txs+ 16
  "Below this tx count we validate sequentially — thread-spawn overhead
   exceeds the parallel speedup for tiny blocks. Bitcoin Core's
   CCheckQueue uses a similar batching threshold.")

(defparameter +parallel-validation-workers+ 4
  "Number of worker threads for parallel block-script validation, settable
with -par (Core's DEFAULT_SCRIPTCHECK_THREADS / MAX_SCRIPTCHECK_THREADS).
A DEFPARAMETER because -par changes it; see PARSE-PAR-THREADS.")

(defconstant +max-scriptcheck-threads+ 15
  "Core MAX_SCRIPTCHECK_THREADS (validation.h).")

(defun available-processor-count ()
  "How many CPUs this node may use, for -par=0 and -par=<negative>.

Read from /proc/cpuinfo, which is what the node actually runs on (a Linux
container), falling back to 4 where that file does not exist. SBCL exports no
portable CPU count and neither does bordeaux-threads, so the choice is this or
a guess; a wrong guess here oversubscribes the box Core was told to leave
headroom on."
  (or (ignore-errors
       (with-open-file (in #p"/proc/cpuinfo" :if-does-not-exist nil)
         (when in
           (let ((n 0))
             (loop for line = (read-line in nil) while line
                   do (when (and (>= (length line) 9)
                                 (string= "processor" (subseq line 0 9)))
                        (incf n)))
             (and (plusp n) n)))))
      4))

(defun parse-par-threads (value)
  "Core's -par semantics (init.cpp): 0 means \"as many as there are cores\",
a NEGATIVE value means leave that many cores free, and the result is clamped to
MAX_SCRIPTCHECK_THREADS. 1 disables the extra threads.

The negative form is the one worth getting right: -par=-1 on a 4-core box means
THREE workers, not one, and reading it as an absolute value would quietly
oversubscribe the machine Core was told to leave headroom on."
  (let* ((cores (available-processor-count))
         (n (cond ((null value) +parallel-validation-workers+)
                  ((zerop value) cores)
                  ((minusp value) (+ cores value))
                  (t value))))
    (max 0 (min n +max-scriptcheck-threads+))))

(defun prefetch-block-spent-coins (txs utxo-set extra-coins)
  "Resolve every non-coinbase transaction's spent coins UP FRONT, on the
calling thread. Returns a vector of per-transaction spent-utxo vectors, indexed
the same way (rest TXS) is.

This is Core's shape and the reason parallel validation can be safe at all:
ConnectBlock copies each spent Coin into its CScriptCheck BEFORE queuing it
(validation.cpp ~:2540-2560), so the workers never touch the coins view.

Ours previously had each worker call COLLECT-SPENT-UTXOS itself, and that read
path INSERTS ON MISS into the coins-view cache — a plain, non-:synchronized
SBCL hash table. Concurrent read-through inserts corrupt it, and no amount of
care in the script interpreter can make that safe."
  (let* ((non-coinbase (rest txs))
         (out (make-array (length non-coinbase))))
    (loop for tx in non-coinbase
          for i from 0
          do (setf (aref out i)
                   (collect-spent-utxos
                    (bitcoin-lisp.serialization:transaction-inputs tx)
                    utxo-set extra-coins)))
    out))

(defun validate-tx-scripts (tx tx-idx utxo-set script-flags height
                            &key extra-coins spent-utxos)
  "Validate all input scripts of a single transaction. Returns
T on success or NIL on failure. EXTRA-COINS is an optional (txid . index) ->
utxo-entry table of coins created by earlier transactions in the same block,
which are not in UTXO-SET yet.

SPENT-UTXOS, when supplied, is this transaction's already-resolved coins from
PREFETCH-BLOCK-SPENT-COINS. Passing it is what makes a worker thread safe: the
coins view is never touched here, so its non-synchronized cache is never
written concurrently."
  (let* ((tx-inputs (bitcoin-lisp.serialization:transaction-inputs tx))
         (spent-utxos (or spent-utxos
                          (collect-spent-utxos tx-inputs utxo-set extra-coins)))
         (bitcoin-lisp.coalton.interop:*script-flags* script-flags)
         (bitcoin-lisp.coalton.interop:*precomputed-sighash*
           (bitcoin-lisp.coalton.interop:init-precomputed-sighash tx spent-utxos))
         (bitcoin-lisp.coalton.interop:*current-spent-utxos* spent-utxos))
    (loop for input across tx-inputs
          for input-idx from 0
          for utxo = (and spent-utxos (aref spent-utxos input-idx))
          do (unless utxo
               ;; Core asserts the coin is present before verifying
               ;; (CheckInputScripts, validation.cpp:2090). An unresolvable
               ;; coin must fail the transaction, never skip its script:
               ;; a skipped input is an unsigned spend.
               (let ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input)))
                 (bitcoin-lisp:log-warn
                  "SCRIPT-MISSING-COIN: height=~D tx-idx=~D input-idx=~D prev-txid=~A:~D"
                  height tx-idx input-idx
                  (bitcoin-lisp.crypto:bytes-to-hex
                   (bitcoin-lisp.serialization:outpoint-hash prevout))
                  (bitcoin-lisp.serialization:outpoint-index prevout)))
               (return-from validate-tx-scripts nil))
             (unless (validate-input-script tx input-idx utxo)
               ;; Re-run with debug to capture the preimage for the log line
               (let ((bitcoin-lisp.coalton.interop:*debug-bip341-sighash* t))
                 (validate-input-script tx input-idx utxo))
               (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
                      (wvec (bitcoin-lisp.serialization:transaction-witness tx))
                      (witness (and wvec (aref wvec input-idx))))
                 (bitcoin-lisp:log-warn
                  "SCRIPT-FAILED: height=~D tx-idx=~D input-idx=~D prev-txid=~A:~D scriptpubkey=~A scriptsig=~A witness-items=~D witness=~A flags=~A"
                  height tx-idx input-idx
                  (bitcoin-lisp.crypto:bytes-to-hex
                   (bitcoin-lisp.serialization:outpoint-hash prevout))
                  (bitcoin-lisp.serialization:outpoint-index prevout)
                  (bitcoin-lisp.crypto:bytes-to-hex
                   (bitcoin-lisp.storage:utxo-entry-script-pubkey utxo))
                  (bitcoin-lisp.crypto:bytes-to-hex
                   (bitcoin-lisp.serialization:tx-in-script-sig input))
                  (length witness)
                  (format nil "[~{~A~^,~}]"
                          (mapcar #'bitcoin-lisp.crypto:bytes-to-hex witness))
                  bitcoin-lisp.coalton.interop:*script-flags*))
               (return-from validate-tx-scripts nil))
          finally (return t))))


;;;; Persistent script-check worker pool (Core CCheckQueue, checkqueue.h)
;;;;
;;;; Core keeps ONE pool for the life of the process and hands it batches;
;;;; ours used to spawn +parallel-validation-workers+ fresh threads PER BLOCK.
;;;; At one block per ten minutes that is invisible, but during IBD it is a
;;;; thread creation per block, and thread creation in SBCL is not cheap.
;;;;
;;;; The unit of work here is a whole TRANSACTION rather than Core's individual
;;;; CScriptCheck. That is a deliberate simplification: our validator is
;;;; per-transaction, and a finer unit would mean restructuring the interpreter
;;;; entry point for a granularity gain that only matters for blocks with a few
;;;; enormous transactions.

(defstruct (script-check-pool (:constructor %make-script-check-pool))
  "A persistent set of worker threads processing transaction-validation items."
  (lock (bt:make-lock "script-check-pool"))
  (work-cv (bt:make-condition-variable))
  (done-cv (bt:make-condition-variable))
  (queue '() :type list)
  ;; Items neither finished nor abandoned — queued OR in a worker's hands. The
  ;; master waits for this to reach zero, so counting only the QUEUE would let
  ;; it return while a worker was still verifying.
  (todo 0 :type fixnum)
  (failed nil)
  (threads '() :type list)
  (stop nil))

(defvar *script-check-pool* nil
  "The process-wide pool, created on first use. NIL when parallel validation
has never run, which is the default.")

(defvar *script-check-pool-lock* (bt:make-lock "script-check-pool-init")
  "Guards creation of *SCRIPT-CHECK-POOL* so two threads cannot each build one.")

(defun %wake-all-workers (pool)
  "Wake every worker. This bordeaux-threads exports CONDITION-NOTIFY but NOT
CONDITION-BROADCAST, so \"all\" is one notify per thread; a single notify would
wake one worker and leave the rest asleep on a full queue."
  (dotimes (i (max 1 (length (script-check-pool-threads pool))))
    (bt:condition-notify (script-check-pool-work-cv pool))))

(defun %script-check-worker (pool)
  "One worker's loop: take an item, run it, account for it. Never signals out —
a worker that died would leave TODO permanently above zero and hang the master
on the next block."
  (loop
    (let ((item nil))
      (bt:with-lock-held ((script-check-pool-lock pool))
        (loop until (or (script-check-pool-stop pool)
                        (script-check-pool-queue pool))
              do (bt:condition-wait (script-check-pool-work-cv pool)
                                    (script-check-pool-lock pool)))
        (when (script-check-pool-stop pool)
          (return))
        (setf item (pop (script-check-pool-queue pool))))
      (let ((ok (handler-case
                    ;; Once the batch has failed there is nothing to learn from
                    ;; the rest of it; drain without working so the master is
                    ;; not kept waiting on doomed verifications.
                    (if (script-check-pool-failed pool)
                        t
                        (funcall item))
                  (error (e)
                    (bitcoin-lisp:log-error "script-check worker: ~A" e)
                    nil))))
        (bt:with-lock-held ((script-check-pool-lock pool))
          (unless ok (setf (script-check-pool-failed pool) t))
          (when (zerop (decf (script-check-pool-todo pool)))
            (bt:condition-notify (script-check-pool-done-cv pool))))))))

(defun ensure-script-check-pool (n-workers)
  "The process-wide pool, creating it with N-WORKERS threads on first use.

Created lazily rather than at startup: parallel validation is default-off, and
a node that never enables it should not carry idle threads."
  (bt:with-lock-held (*script-check-pool-lock*)
    (or *script-check-pool*
        (let ((pool (%make-script-check-pool)))
          (setf (script-check-pool-threads pool)
                (loop for i below n-workers
                      collect (bt:make-thread
                               (lambda () (%script-check-worker pool))
                               :name (format nil "script-check-~D" i))))
          (setf *script-check-pool* pool)))))

(defun stop-script-check-pool ()
  "Stop the workers and drop the pool (node shutdown)."
  (bt:with-lock-held (*script-check-pool-lock*)
    (let ((pool *script-check-pool*))
      (when pool
        (bt:with-lock-held ((script-check-pool-lock pool))
          (setf (script-check-pool-stop pool) t)
          (%wake-all-workers pool))
        (dolist (th (script-check-pool-threads pool))
          (ignore-errors (bt:join-thread th)))
        (setf *script-check-pool* nil)
        t))))

(defun run-script-checks (pool items)
  "Run ITEMS (a list of thunks) on POOL and return T when every one succeeded.

The CALLER participates, as Core's master thread does (checkqueue.h's fMaster):
it takes work from the same queue rather than blocking immediately, so a
single-worker pool still uses two cores and the master is never idle while work
remains.

One batch at a time — the caller holds the validation thread, and there is only
ever one block being connected."
  (let ((n (length items)))
    (when (zerop n) (return-from run-script-checks t))
    (bt:with-lock-held ((script-check-pool-lock pool))
      (setf (script-check-pool-queue pool) items
            (script-check-pool-todo pool) n
            (script-check-pool-failed pool) nil)
      (%wake-all-workers pool))
    ;; Master participation.
    (loop
      (let ((item nil))
        (bt:with-lock-held ((script-check-pool-lock pool))
          (setf item (pop (script-check-pool-queue pool))))
        (unless item (return))
        (let ((ok (handler-case (if (script-check-pool-failed pool) t (funcall item))
                    (error (e)
                      (bitcoin-lisp:log-error "script-check master: ~A" e)
                      nil))))
          (bt:with-lock-held ((script-check-pool-lock pool))
            (unless ok (setf (script-check-pool-failed pool) t))
            (when (zerop (decf (script-check-pool-todo pool)))
              (bt:condition-notify (script-check-pool-done-cv pool)))))))
    ;; Wait for whatever the workers still hold.
    (bt:with-lock-held ((script-check-pool-lock pool))
      (loop until (zerop (script-check-pool-todo pool))
            do (bt:condition-wait (script-check-pool-done-cv pool)
                                  (script-check-pool-lock pool)))
      (not (script-check-pool-failed pool)))))

(defun validate-block-scripts-parallel (txs script-flags utxo-set height &key extra-coins)
  "Validate all non-coinbase tx scripts in TXS across N worker threads.
Returns T on success or NIL on the first script failure.

Bitcoin Core uses CCheckQueue with a thread pool to do the same — every
sig check is independent across inputs and txs, so this parallelizes
cleanly. The shared sig-cache uses SBCL :synchronized hash-tables for
safe concurrent access. EXTRA-COINS (the block's intra-block coin overlay)
is read-only for the whole of this call and must already be complete when
it is reached — the workers only ever GETHASH it.

The spent coins are resolved HERE, on this thread, before any worker starts
(Core's ConnectBlock does the same before queuing a CScriptCheck). The workers
then receive pure data and never touch the coins view, whose cache inserts on
read and is not synchronized."
  (let* ((non-coinbase (rest txs))
         (prefetched (prefetch-block-spent-coins txs utxo-set extra-coins))
         (pool (ensure-script-check-pool +parallel-validation-workers+))
         ;; One item per transaction. Each closes over data that is already
         ;; resolved, so nothing here reaches the coins view.
         (items (loop for tx in non-coinbase
                      for i from 0
                      collect (let ((tx tx) (i i))
                                (lambda ()
                                  (validate-tx-scripts
                                   tx (1+ i) utxo-set script-flags height
                                   :extra-coins extra-coins
                                   :spent-utxos (aref prefetched i)))))))
    (run-script-checks pool items)))

(defun validate-block-scripts (block utxo-set &key (height 0) extra-coins)
  "Validate all non-coinbase transaction scripts in BLOCK via Coalton interop.
Returns (VALUES T NIL) on success, (VALUES NIL ERROR-KEYWORD) on failure.
Uses validate-input-script for each input (shared with transaction validation).
The block's HASH and HEIGHT together choose the flags, via BLOCK-SCRIPT-FLAGS.
EXTRA-COINS is the block's intra-block coin overlay — the outputs created by
its own earlier transactions, which the confirmed UTXO set does not hold.
Core has already applied them to its coins view by the time it script-checks
a chained spend (UpdateCoins, validation.cpp:2597).

An exception block is NOT skipped. Core runs its scripts under the exception's
flag set — SCRIPT_VERIFY_NONE for the two BIP16 blocks — so the scripts must
still evaluate true. Returning success without executing them, as this did
until now, accepts blocks Core rejects."
  (let ((script-flags
          (block-script-flags (bitcoin-lisp.serialization:block-header-hash
                               (bitcoin-lisp.serialization:bitcoin-block-header block))
                              height))
        (transactions (bitcoin-lisp.serialization:bitcoin-block-transactions block)))
    ;; For non-tiny blocks, parallelize tx-script validation across workers
    ;; — but ONLY when explicitly enabled. The per-block worker threads are
    ;; off by default (bitcoin-lisp:*parallel-block-validation* nil) because at
    ;; mainnet scale their concurrent libsecp CFFI corrupts SBCL's alien-type
    ;; cache and crashes the node; see that var's docstring. Sequential path is
    ;; the default and is also used for tiny blocks where thread-spawn overhead
    ;; dominates any speedup.
    (if (and bitcoin-lisp:*parallel-block-validation*
             (>= (length (rest transactions)) +parallel-validation-min-txs+)
             (> +parallel-validation-workers+ 1))
        (if (validate-block-scripts-parallel transactions script-flags utxo-set height
                                             :extra-coins extra-coins)
            (values t nil)
            (values nil :script-failed))
        ;; Sequential fallback (kept verbatim from the pre-Phase-3 path).
        (let ((bitcoin-lisp.coalton.interop:*script-flags* script-flags))
          (loop for tx in (rest transactions)
                for tx-idx from 1
                do (unless (validate-tx-scripts tx tx-idx utxo-set
                                                script-flags height
                                                :extra-coins extra-coins)
                     (return-from validate-block-scripts
                       (values nil :script-failed))))
          (values t nil)))))


;;;; Witness commitment validation (BIP 141)

(defvar *witness-commitment-header*
  (make-array 4 :element-type '(unsigned-byte 8)
                :initial-contents '(#xaa #x21 #xa9 #xed))
  "4-byte commitment header for witness data in coinbase OP_RETURN.")

(defun find-witness-commitment (coinbase-tx)
  "Find the witness commitment in a coinbase transaction's outputs.
BIP 141: The commitment is in the last OP_RETURN output matching the
header 0xaa21a9ed. Returns the 32-byte commitment hash or NIL."
  (let ((outputs (bitcoin-lisp.serialization:transaction-outputs coinbase-tx))
        (commitment nil))
    ;; Scan all outputs; use the last matching one (per BIP 141)
    (bitcoin-lisp.serialization:dovector (output outputs)
      (let ((script (bitcoin-lisp.serialization:tx-out-script-pubkey output)))
        (when (and (>= (length script) 38)   ; OP_RETURN + push36 + 4-byte header + 32-byte hash
                   (= (aref script 0) #x6a)  ; OP_RETURN
                   (= (aref script 1) #x24)  ; push 36 bytes
                   (equalp (subseq script 2 6) *witness-commitment-header*))
          (setf commitment (subseq script 6 38)))))
    commitment))

(defun block-has-witness-data-p (block)
  "Check if any transaction in the block has witness data."
  (some #'bitcoin-lisp.serialization:transaction-has-witness-p
        (bitcoin-lisp.serialization:bitcoin-block-transactions block)))

(defun compute-witness-merkle-root (transactions)
  "Compute the witness merkle root from a list of transactions.
Uses wtxids for all transactions. The coinbase wtxid is 32 zero bytes (per BIP 141)."
  (let ((wtxids (mapcar #'bitcoin-lisp.serialization:transaction-wtxid transactions)))
    (compute-merkle-root wtxids)))

(defun validate-witness-commitment (block segwit-active)
  "BIP 141 witness-malleation check. Mirrors Bitcoin Core's
CheckWitnessMalleation (validation.cpp:3902-3948).

SEGWIT-ACTIVE is whether the segwit deployment is active for this block
(Core's expect_witness_commitment). When active and the coinbase carries
a witness commitment output, the coinbase witness stack must be exactly
one 32-byte reserved value (:bad-witness-nonce-size) and the commitment
must equal hash256(witness-merkle-root || reserved-value)
(:bad-witness-merkle-match). Otherwise — segwit inactive, or active with
no commitment present — no transaction may carry witness data at all
(:unexpected-witness). Returns (VALUES T NIL) on success.

Note: the gate is segwit activation, NOT whether the block happens to
carry witness data — a pre-segwit block with witness data must be
rejected, and the no-commitment+witness case is :unexpected-witness
(Core has no separate \"missing commitment\" error here)."
  (let ((transactions (bitcoin-lisp.serialization:bitcoin-block-transactions block)))
    (when segwit-active
      (let* ((coinbase-tx (first transactions))
             (commitment (find-witness-commitment coinbase-tx)))
        (when commitment
          ;; Coinbase input-0 witness stack must be exactly one 32-byte item.
          (let* ((cb-witness (bitcoin-lisp.serialization:transaction-witness
                              coinbase-tx))
                 (cb-stack (and cb-witness (plusp (length cb-witness))
                                (aref cb-witness 0))))
            (unless (and (= (length cb-stack) 1)
                         (= (length (first cb-stack)) 32))
              (return-from validate-witness-commitment
                (values nil :bad-witness-nonce-size)))
            (let* ((reserved (first cb-stack))
                   (witness-root (compute-witness-merkle-root transactions))
                   (combined (make-array 64 :element-type '(unsigned-byte 8))))
              (replace combined witness-root :start1 0)
              (replace combined reserved :start1 32)
              (unless (equalp (bitcoin-lisp.crypto:hash256 combined) commitment)
                (return-from validate-witness-commitment
                  (values nil :bad-witness-merkle-match)))))
          ;; Valid commitment — accept without the unexpected-witness scan.
          (return-from validate-witness-commitment (values t nil)))))
    ;; Segwit inactive, or active with no commitment output: no transaction
    ;; may carry witness data.
    (dolist (tx transactions)
      (when (bitcoin-lisp.serialization:transaction-has-witness-p tx)
        (return-from validate-witness-commitment
          (values nil :unexpected-witness))))
    (values t nil)))

(defun witness-reserved-value ()
  "A fresh copy of the BIP141 reserved witness value — the 32 zero bytes a
coinbase's sole witness item must be when the block carries a witness
commitment (Core's `nonce` in UpdateUncommittedBlockStructures)."
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))

(defun update-uncommitted-block-structures (block chain-state)
  "Core ChainstateManager::UpdateUncommittedBlockStructures
(validation.cpp:4017-4027): when BLOCK's coinbase carries a witness commitment
but no witness, install the reserved value as its witness — provided the parent
is in CHAIN-STATE's index and segwit is active at BLOCK's height, the two gates
Core applies. submitblock runs this before validation (rpc/mining.cpp:1076-1080)
so a miner that serializes the template's coinbase without its witness is not
refused with bad-witness-nonce-size. Mutates the coinbase in place and drops its
cached weight, which the witness changes (mine-block does the same for the
header's cached hash)."
  (let* ((header (bitcoin-lisp.serialization:bitcoin-block-header block))
         (prev (bitcoin-lisp.storage:get-block-index-entry
                chain-state (bitcoin-lisp.serialization:block-header-prev-block header)))
         (coinbase (first (bitcoin-lisp.serialization:bitcoin-block-transactions block))))
    (when (and prev coinbase
               (>= (1+ (bitcoin-lisp.storage:block-index-entry-height prev))
                   (get-segwit-activation-height bitcoin-lisp:*network*))
               (find-witness-commitment coinbase)
               (not (bitcoin-lisp.serialization:transaction-has-witness-p coinbase)))
      (setf (bitcoin-lisp.serialization:transaction-witness coinbase)
            (vector (list (witness-reserved-value)))
            (bitcoin-lisp.serialization::transaction-cached-weight coinbase) nil))))

(defun block-witness-stripped-p (block)
  "T if BLOCK carries a witness commitment in its coinbase outputs but its coinbase
witness is NOT exactly one 32-byte item — i.e. the block arrived witness-stripped
(or is malformed). Such a block can never pass BIP141 validation
(bad-witness-nonce-size), so it must not be persisted: a witness-stripped block
stored on a competing fork failed every reorg attempt and wedged testnet4 (see
project_cmpctblock_witness_wedge). Height/network-independent — a block that
commits to witness data ALWAYS carries the 32-byte reserved value, so this never
fires on a legitimate block.

Note the block hash is identical for the stripped and witness-complete copies (the
witness is not covered by the header/merkle root), so callers must treat this as
\"don't persist THIS copy\", never as a permanent reject of the hash."
  (let* ((txs (bitcoin-lisp.serialization:bitcoin-block-transactions block))
         (coinbase (first txs)))
    (and coinbase
         (find-witness-commitment coinbase)
         (let* ((cb-witness (bitcoin-lisp.serialization:transaction-witness coinbase))
                (cb-stack (and cb-witness (plusp (length cb-witness)) (aref cb-witness 0))))
           (not (and (= (length cb-stack) 1)
                     (= (length (first cb-stack)) 32)))))))

;;;; BIP 34 Coinbase Height Validation

(defconstant +bip34-activation-height-testnet3+ 21111
  "BIP 34 activation height on testnet.")

(defconstant +bip34-activation-height-mainnet+ 227931
  "BIP 34 activation height on mainnet.")

(defun get-bip34-activation-height (network)
  "Return the BIP 34 activation height for NETWORK."
  (%activation-height "bip34"
   (ecase network
     (:testnet3 +bip34-activation-height-testnet3+)
     ((:testnet4 :signet :regtest) 1)
     (:mainnet +bip34-activation-height-mainnet+))))

(defconstant +bip34-implies-bip30-limit+ 1983702
  "BIP 30 is re-enforced unconditionally at this height and above: past
this point the BIP 34 height-in-coinbase guarantee can no longer rule
out duplicate coinbases (pre-BIP34 blocks exist with indicated heights
above it), so the optimization of skipping BIP 30 after BIP 34 is
dropped. Bitcoin Core BIP34_IMPLIES_BIP30_LIMIT (validation.cpp:2427).")

(defun bip30-repeat-block-p (height)
  "T for the two grandfathered mainnet blocks (91842, 91880) that contain
duplicate coinbases predating BIP 30 enforcement; BIP 30 must NOT be
enforced on them or they would be wrongly rejected. Bitcoin Core
IsBIP30Repeat (validation.cpp:6208). Only mainnet has these. (We match on
height only, not the block hash Core also checks — forging a pre-BIP34
mainnet fork to these heights is infeasible, and no other network has
repeat blocks.)"
  (and (eq bitcoin-lisp:*network* :mainnet)
       (or (= height 91842) (= height 91880))))

(defun bip30-enforced-p (height)
  "Whether the BIP 30 duplicate-coinbase check must run for a block at
HEIGHT: enforced below BIP 34 activation (except the grandfathered repeat
blocks), and again unconditionally at or above +bip34-implies-bip30-limit+.
Mirrors Bitcoin Core ConnectBlock (validation.cpp:2399-2464). Note: we
approximate Core's BIP34Hash-ancestor test with a height comparison,
omitting only the extra enforcement Core applies on a non-canonical fork
past the BIP 34 height — infeasible to exploit given the PoW required."
  (or (and (not (bip30-repeat-block-p height))
           (< height (get-bip34-activation-height bitcoin-lisp:*network*)))
      (>= height +bip34-implies-bip30-limit+)))

(defun encode-bip34-height (height)
  "The exact coinbase scriptSig prefix Bitcoin Core requires for a BIP 34
block at HEIGHT: the bytes of `CScript() << height`. Heights 0 and 1..16
use the minimal OP_0 / OP_1..OP_16 single opcodes; larger heights use a
minimally-encoded (positive) CScriptNum pushed as data. Returns a byte
vector. Mirrors validation.cpp:4186."
  (cond
    ((zerop height)
     (make-array 1 :element-type '(unsigned-byte 8) :initial-element #x00))  ; OP_0
    ((<= 1 height 16)
     (make-array 1 :element-type '(unsigned-byte 8)
                 :initial-element (+ #x50 height)))                          ; OP_1..OP_16
    (t
     ;; Minimal little-endian CScriptNum bytes, with a trailing 0x00 sign
     ;; byte if the top byte would otherwise look negative; pushed as data
     ;; (opcode == byte length, always <= 75 for any real height).
     (let ((le '())
           (n height))
       (loop while (plusp n)
             do (push (logand n #xff) le)
                (setf n (ash n -8)))
       (setf le (nreverse le))
       (when (logbitp 7 (car (last le)))
         (setf le (append le (list 0))))
       (let* ((data-len (length le))
              (result (make-array (1+ data-len) :element-type '(unsigned-byte 8))))
         (setf (aref result 0) data-len)
         (loop for b in le for i from 1 do (setf (aref result i) b))
         result)))))

(defun decode-coinbase-height (script-sig)
  "Decode the claimed block height from a coinbase scriptSig, for
inspection/display only (RPC, logging). NOT the consensus check — BIP 34
validation is an exact serialized-prefix match against
`encode-bip34-height` (see validate-coinbase-height), because Core
compares bytes rather than numeric value, rejecting non-minimal encodings.
Returns the decoded height, or NIL if the leading push is malformed."
  (when (zerop (length script-sig))
    (return-from decode-coinbase-height nil))
  (let ((push-len (aref script-sig 0)))
    (cond
      ;; OP_0: height = 0
      ((zerop push-len) 0)
      ;; OP_1 through OP_16: height = 1-16
      ((<= #x51 push-len #x60)
       (1+ (- push-len #x51)))
      ;; Direct push (1-75 bytes): read little-endian integer
      ((<= 1 push-len 75)
       (when (< (length script-sig) (1+ push-len))
         (return-from decode-coinbase-height nil))
       (let ((height 0))
         (loop for i from 1 to push-len
               do (setf height (logior height (ash (aref script-sig i) (* 8 (1- i))))))
         height))
      ;; Other encodings not valid for BIP 34
      (t nil))))

(defun validate-coinbase-height (block current-height)
  "Validate BIP 34: at/above the network activation height, the coinbase
scriptSig must START WITH the exact serialized block height (the byte
prefix of `CScript() << height`). This is a byte-prefix match, not a
numeric decode, so non-minimal or wrong-form encodings are rejected even
when they would decode to the right number. Mirrors validation.cpp:4183-4191.
Returns (VALUES T NIL) on success, (VALUES NIL ERROR-KEYWORD) on failure."
  (let ((activation-height (get-bip34-activation-height bitcoin-lisp:*network*)))
    (when (< current-height activation-height)
      (return-from validate-coinbase-height (values t nil))))
  (let* ((coinbase-tx (first (bitcoin-lisp.serialization:bitcoin-block-transactions block)))
         (first-input (aref (bitcoin-lisp.serialization:transaction-inputs coinbase-tx) 0))
         (script-sig (bitcoin-lisp.serialization:tx-in-script-sig first-input))
         (expect (encode-bip34-height current-height)))
    (if (and (>= (length script-sig) (length expect))
             (loop for i below (length expect)
                   always (= (aref script-sig i) (aref expect i))))
        (values t nil)
        (values nil :bad-coinbase-height))))

(defun script-checks-skippable-p (chain-state hash height)
  "T when signature verification may be skipped for the block ENTRY names.

Core's fScriptChecks is a pure function of ASSUMEVALID (validation.cpp:2342-2380)
and CHECKPOINTS PLAY NO PART IN IT. We reduced the whole thing to
`height <= (max last-checkpoint-height assumevalid-height)', which is wrong in
two directions at once:

 - Only a HEIGHT was compared, so any block at or below that height had its
   signatures skipped even when it was NOT an ancestor of the assumevalid
   block. A competing fork block qualifies. A fork must out-work the active
   chain to connect, which is expensive at the mainnet tip but not during IBD
   and cheap by design on the min-difficulty test networks -- and in that
   window we accepted a fork block carrying forged scriptSigs that Core
   verifies and rejects.
 - When the assumevalid header is not yet in our index -- the whole first phase
   of a fresh IBD -- the expression fell back to the CHECKPOINT height and
   skipped every signature up to 840,000 on mainnet and 2,000,000 on testnet3,
   where Core verifies all of them.

Both holes are closed by requiring what Core requires: assumevalid must be
configured, its header must be in the index, and this block must be an ANCESTOR
of it. The ancestry test is by hash, per GA9 S2-2.

DELIBERATELY NOT IMPLEMENTED, and the reason is a real constraint rather than
an oversight: Core additionally requires the block to be on the best-header
chain, the best header's work to be at or above nMinimumChainWork, and more
than two weeks of equivalent work to sit below the best header (its
anti-extortion margin). All three need m_best_header, which Core maintains
incrementally and we recompute by scanning the whole index --
BEST-HEADER-ENTRY's own docstring says it is `O(index size) ... not for
per-block paths'. Consulting it here would put an O(index) scan in the connect
loop. Those three conditions only ever make skipping STRICTER, so omitting them
is a smaller skip window than Core's, never a larger one; closing them properly
means maintaining the best header incrementally first."
  (let* ((av (bitcoin-lisp:network-assumevalid bitcoin-lisp:*network*))
         (av-entry (and av (bitcoin-lisp.storage:get-block-index-entry chain-state av))))
    (and hash av-entry
         ;; The block must BE the assumevalid chain's block at this height.
         ;; Taking a hash and height rather than an index entry is deliberate:
         ;; on the tip-extension path the block is validated BEFORE
         ;; connect-block creates its entry, so an entry-based predicate would
         ;; silently answer NIL there and quietly verify every signature -- safe,
         ;; but it would make the assumevalid optimisation dead on the main IBD
         ;; path rather than merely correct.
         (let ((ancestor (bitcoin-lisp.storage:entry-ancestor-at-height av-entry height)))
           (and ancestor
                (equalp (bitcoin-lisp.storage:block-index-entry-hash ancestor) hash)
                t)))))

(defun calculate-block-weight (transactions)
  "Weight of the block whose transaction list is TRANSACTIONS (Core
GetBlockWeight, consensus/validation.h:136-139).

Core weighs the WHOLE BLOCK, not the transactions: it serializes the block with
and without witnesses, and the block serializer emits
`header(80) || CompactSize(vtx.size()) || txs\'. Expanding
`3*size_nowit + size_wit\' over that shape, the prefix survives with a factor
of four:

    weight = 4 * (80 + compact-size-length(n)) + SUM(transaction-weight)

This summed transaction weights ALONE, i.e. it dropped `4 * (80 + cs(n))\' —
324 weight units for a block of fewer than 253 transactions, 332 up to 65535.
It under-counted, so the error ran in the dangerous direction: a block whose
true weight lands in (4000000, 4000332] passed here, connected, and advanced
our tip while every Core node rejected it as `bad-blk-weight\'. That is a
permanent chain split that ends only by hand.

The prefix depends only on the transaction COUNT, so this needs no block object
and every caller — the consensus check below and getblock\'s `weight\' field —
is corrected at once. That matters for the RPC too: the number we report must
be the number bitcoind reports for the same block.

The base-size check a few lines below already added `80 + compact-size-length\'
correctly, which is what marks this as an oversight rather than a decision."
  (+ (* 4 (+ 80 (bitcoin-lisp.serialization:compact-size-length
                 (length transactions))))
     (loop for tx in transactions
           sum (bitcoin-lisp.serialization:transaction-weight tx))))

;;;; Sigops cost calculation

(defun script-is-p2sh-p (script)
  "Check if SCRIPT is a P2SH scriptPubKey: OP_HASH160 <20 bytes> OP_EQUAL."
  (and (= (length script) 23)
       (= (aref script 0) +op-hash160+)
       (= (aref script 1) 20)       ; Push 20 bytes
       (= (aref script 22) +op-equal+)))

(defun extract-last-push (script)
  "Extract the data from the last push operation in SCRIPT.
Used to get the redeemScript from a P2SH scriptSig.
Tracks indices and allocates only once at the end."
  (let ((len (length script))
        (i 0)
        (last-start nil)
        (last-end nil))
    (loop while (< i len)
          do (let ((opcode (aref script i)))
               (cond
                 ((<= 1 opcode 75)
                  (let ((end (min (+ i 1 opcode) len)))
                    (setf last-start (1+ i) last-end end i end)))
                 ((= opcode +op-pushdata1+)
                  (if (< (1+ i) len)
                      (let* ((size (aref script (1+ i)))
                             (end (min (+ i 2 size) len)))
                        (setf last-start (+ i 2) last-end end i end))
                      (return)))
                 ((= opcode +op-pushdata2+)
                  (if (< (+ i 2) len)
                      (let* ((size (logior (aref script (1+ i))
                                           (ash (aref script (+ i 2)) 8)))
                             (end (min (+ i 3 size) len)))
                        (setf last-start (+ i 3) last-end end i end))
                      (return)))
                 ((= opcode +op-pushdata4+)
                  (if (< (+ i 4) len)
                      (let* ((size (logior (aref script (1+ i))
                                           (ash (aref script (+ i 2)) 8)
                                           (ash (aref script (+ i 3)) 16)
                                           (ash (aref script (+ i 4)) 24)))
                             (end (min (+ i 5 size) len)))
                        (setf last-start (+ i 5) last-end end i end))
                      (return)))
                 (t (incf i)))))
    (when (and last-start last-end)
      (subseq script last-start last-end))))

(defun p2sh-sigop-subscript (script-sig)
  "The subscript Bitcoin Core counts the sigops of when SCRIPT-SIG spends a P2SH
output, or NIL when Core counts none.

CScript::GetSigOpCount(const CScript&) (script.cpp:183-205) walks SCRIPT-SIG with
GetScriptOp and returns zero on a truncated push or on any opcode above OP_16.
That bail-out condition is exactly CScript::IsPushOnly (script.cpp:266-281), so a
non-NIL result doubles as the push-only gate the P2SH-wrapped-witness branch
needs (interpreter.cpp:2152-2163).

GetScriptOp clears its data buffer for every opcode and refills it only for
opcode <= OP_PUSHDATA4 (script.cpp:313-359), so OP_1NEGATE, OP_RESERVED and
OP_1..OP_16 leave an EMPTY subscript behind instead of the preceding push.

Deliberately separate from EXTRACT-LAST-PUSH, which is the policy/standardness
redeem-script extractor and has different semantics."
  (let ((len (length script-sig))
        (i 0)
        (start 0)
        (end 0))
    (loop while (< i len)
          do (let ((opcode (aref script-sig i)))
               (cond
                 ((<= opcode +op-pushdata4+)
                  (let* ((width (cond ((< opcode +op-pushdata1+) 0)
                                      ((= opcode +op-pushdata1+) 1)
                                      ((= opcode +op-pushdata2+) 2)
                                      (t 4)))
                         (data (+ i 1 width)))
                    (when (> data len)
                      (return-from p2sh-sigop-subscript nil))
                    (let ((size (if (zerop width)
                                    opcode
                                    (loop for k from 0 below width
                                          sum (ash (aref script-sig (+ i 1 k)) (* 8 k))))))
                      (when (> (+ data size) len)
                        (return-from p2sh-sigop-subscript nil))
                      (setf start data
                            end (+ data size)
                            i end))))
                 ((> opcode +op-16+)
                  (return-from p2sh-sigop-subscript nil))
                 (t
                  (setf start 0 end 0)
                  (incf i)))))
    (subseq script-sig start end)))

(defun spent-script-sigop-count (script-pubkey script-sig)
  "Core CScript::GetSigOpCount(const CScript& scriptSig) (script.cpp:183-205):
the accurate sigop count of SCRIPT-PUBKEY itself, or, when it is P2SH, of the
redeem script SCRIPT-SIG pushes last (p2sh-sigop-subscript; zero when that
walk bails)."
  (if (script-is-p2sh-p script-pubkey)
      (let ((sub (p2sh-sigop-subscript script-sig)))
        (if sub (count-script-sigops sub :accurate t) 0))
      (count-script-sigops script-pubkey :accurate t)))

(defun count-legacy-sigops (tx)
  "Count legacy (inaccurate) sigops across all scriptSigs and scriptPubKeys of TX."
  (let ((count 0))
    (bitcoin-lisp.serialization:dovector (input (bitcoin-lisp.serialization:transaction-inputs tx))
      (incf count (count-script-sigops
                   (bitcoin-lisp.serialization:tx-in-script-sig input))))
    (bitcoin-lisp.serialization:dovector (output (bitcoin-lisp.serialization:transaction-outputs tx))
      (incf count (count-script-sigops
                   (bitcoin-lisp.serialization:tx-out-script-pubkey output))))
    count))

(defun count-witness-sigops-for-input (script-pubkey witness)
  "Count witness sigops for a single input given its spent SCRIPT-PUBKEY and WITNESS.
Returns 1 for P2WPKH, counts from witness script for P2WSH."
  (let ((len (length script-pubkey)))
    (cond
      ;; P2WPKH: OP_0 <20 bytes>
      ((and (= len 22) (= (aref script-pubkey 0) +op-0+) (= (aref script-pubkey 1) 20))
       1)
      ;; P2WSH: OP_0 <32 bytes>
      ((and (= len 34) (= (aref script-pubkey 0) +op-0+) (= (aref script-pubkey 1) 32))
       (if witness
           (let ((witness-script (car (last witness))))
             (if witness-script
                 (count-script-sigops witness-script :accurate t)
                 0))
           0))
      (t 0))))

(defun count-p2sh-and-witness-sigops (tx get-spent-script)
  "Count P2SH and witness sigops in a single pass over TX inputs.
Returns (VALUES p2sh-count witness-count).
GET-SPENT-SCRIPT takes (txid index) and returns the spent scriptPubKey."
  (let ((p2sh-count 0)
        (witness-count 0))
    (loop for input across (bitcoin-lisp.serialization:transaction-inputs tx)
          for input-idx from 0
          do (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
                    (prev-txid (bitcoin-lisp.serialization:outpoint-hash prevout))
                    (prev-index (bitcoin-lisp.serialization:outpoint-index prevout))
                    (script-pubkey (funcall get-spent-script prev-txid prev-index)))
               (when script-pubkey
                 (cond
                   ;; Native witness program
                   ((script-is-witness-program-p script-pubkey)
                    (let ((witness (get-input-witness tx input-idx)))
                      (incf witness-count (count-witness-sigops-for-input
                                           script-pubkey witness))))
                   ;; P2SH input. A NIL subscript is Core's "not push-only",
                   ;; which zeroes the P2SH sigops AND gates the wrapped-witness
                   ;; branch (CountWitnessSigOps requires IsPushOnly).
                   ((script-is-p2sh-p script-pubkey)
                    (let ((redeem-script (p2sh-sigop-subscript
                                          (bitcoin-lisp.serialization:tx-in-script-sig input))))
                      (when redeem-script
                        ;; P2SH sigops from redeemScript
                        (incf p2sh-count (count-script-sigops redeem-script :accurate t))
                        ;; P2SH-wrapped witness program
                        (when (script-is-witness-program-p redeem-script)
                          (let ((witness (get-input-witness tx input-idx)))
                            (incf witness-count (count-witness-sigops-for-input
                                                 redeem-script witness)))))))))))
    (values p2sh-count witness-count)))

(defun count-transaction-sigops-cost (tx get-spent-script &key (count-p2sh t) (count-witness t))
  "Calculate the weighted sigops cost for TX (BIP 141).
Cost = (legacy + p2sh) * WITNESS_SCALE_FACTOR + witness.
GET-SPENT-SCRIPT takes (txid index) and returns the spent scriptPubKey.

COUNT-P2SH / COUNT-WITNESS gate the P2SH and witness sigops on their activation,
mirroring Bitcoin Core's GetTransactionSigOpCost, which only adds P2SH sigops
when SCRIPT_VERIFY_P2SH is set and witness sigops when SCRIPT_VERIFY_WITNESS is
set (tx_verify.cpp). Legacy sigops are always counted."
  (let ((legacy (count-legacy-sigops tx)))
    (if (or count-p2sh count-witness)
        (multiple-value-bind (p2sh witness)
            (count-p2sh-and-witness-sigops tx get-spent-script)
          (+ (* (+ legacy (if count-p2sh p2sh 0)) +witness-scale-factor+)
             (if count-witness witness 0)))
        (* legacy +witness-scale-factor+))))

;;;; Full block validation

(defun validate-block (block chain-state utxo-set current-height current-time
                        &key skip-scripts skip-header skip-pow context-free-only)
  "Fully validate a block including all transactions.
When CONTEXT-FREE-ONLY is true, run only the checks that are a pure function of
the block itself (Bitcoin Core CheckBlock: header, coinbase structure, signet
solution, merkle root / CVE-2012-2459, weight, size) and RETURN SUCCESS before
the UTXO-dependent contextual checks (BIP30, per-input validation, sequence
locks, scripts, BIP34 coinbase height, coinbase value — Core ContextualCheck
Block + ConnectBlock). Used when accepting a downloaded block that does NOT
extend the active tip: its inputs live on its own branch, not in the active
UTXO set, so the contextual checks would spuriously fail (MISSING-INPUT) — they
are performed instead by PERFORM-REORG, which connects the fork fork-to-tip
against the rewound UTXO set. CURRENT-HEIGHT should still be the block's own
branch height so the header (difficulty/MTP/timewarp) checks are correct.
When SKIP-SCRIPTS is true, script validation is skipped (used during IBD for
blocks below the last checkpoint, matching Bitcoin Core behavior).
When SKIP-HEADER is true, the block-header re-validation (PoW / difficulty /
MTP / timewarp) is skipped — these are header-level checks already performed at
header admission (process-headers), exactly as Bitcoin Core's ConnectBlock does
not re-check the header. Used by perform-reorg, whose fork blocks are already in
the index with validated headers (and whose deserialized copies carry no cached
hash, so a redundant PoW recompute would spuriously fail).
When SKIP-POW is true, only the PoW hash<=target check (and, on signet, the
block-solution check — Core gates both on fCheckPOW) is skipped, while every
contextual header check still runs: the TEST-BLOCK-VALIDITY dry-run of an
unmined template (Core TestBlockValidity's check_pow=false).
Returns (VALUES T NIL FEES) on success, (VALUES NIL ERROR-KEYWORD NIL) on failure."
  (let* ((header (bitcoin-lisp.serialization:bitcoin-block-header block))
         (transactions (bitcoin-lisp.serialization:bitcoin-block-transactions block)))

    ;; Validate header (with difficulty check when prev-entry is available)
    (unless skip-header
      (let ((prev-hash (bitcoin-lisp.serialization:block-header-prev-block header)))
        (multiple-value-bind (valid error)
            (validate-block-header header chain-state current-time
                                   :prev-hash prev-hash
                                   :height current-height
                                   :prev-entry (bitcoin-lisp.storage:get-block-index-entry
                                                chain-state prev-hash)
                                   :skip-pow skip-pow)
          (unless valid
            (return-from validate-block (values nil error nil))))))

    ;; Must have at least one transaction (coinbase)
    (when (null transactions)
      (return-from validate-block
        (values nil :no-transactions nil)))

    ;; First transaction must be coinbase
    (let ((first-tx (first transactions)))
      (unless (is-coinbase-tx first-tx)
        (return-from validate-block
          (values nil :first-tx-not-coinbase nil))))

    ;; Other transactions must not be coinbase
    (loop for tx in (rest transactions)
          when (is-coinbase-tx tx)
            do (return-from validate-block
                 (values nil :multiple-coinbase nil)))

    ;; BIP325: on signet every block must carry a valid signet solution -- a
    ;; signature over the block by the network's challenge key. Without it,
    ;; :signet would follow any low-difficulty chain. Runs regardless of
    ;; SKIP-HEADER (it is a block-level check, never done at header admission,
    ;; so reorg-connected fork blocks must still be checked) but not under
    ;; SKIP-POW — an unmined template has no solution yet. Core CheckBlock:
    ;;   if (signet_blocks && fCheckPOW && !CheckSignetBlockSolution(...)) reject.
    (when (and (eq bitcoin-lisp:*network* :signet) (not skip-pow))
      (unless (check-signet-block-solution block)
        (return-from validate-block (values nil :bad-signet-solution nil))))

    ;; Validate merkle root, then reject CVE-2012-2459 malleation. Order
    ;; mirrors Bitcoin Core CheckBlock: a mutated block hashes to the SAME
    ;; root as the original, so the root check passes and the mutated flag is
    ;; what catches it (bad-txns-duplicate).
    (let* ((tx-hashes (mapcar #'bitcoin-lisp.serialization:transaction-hash
                              transactions))
           (header-root (bitcoin-lisp.serialization:block-header-merkle-root header)))
      (multiple-value-bind (computed-root mutated)
          (compute-merkle-root tx-hashes)
        (unless (equalp computed-root header-root)
          (return-from validate-block
            (values nil :bad-merkle-root nil)))
        (when mutated
          (return-from validate-block
            (values nil :bad-txns-duplicate nil)))))

    ;; Validate block weight (BIP 141)
    (let ((weight (calculate-block-weight transactions)))
      (when (> weight +max-block-weight+)
        (return-from validate-block
          (values nil :block-too-heavy nil))))

    ;; Legacy block size limit (non-witness serialization must fit in 1 MB)
    (let ((base-size (+ 80  ; header
                        (bitcoin-lisp.serialization:compact-size-length
                         (length transactions))
                        (loop for tx in transactions
                              sum (length
                                   (bitcoin-lisp.serialization:serialize-transaction tx))))))
      (when (> base-size +max-block-size+)
        (return-from validate-block
          (values nil :block-too-large nil))))

    ;; Per-transaction context-free checks (Core CheckBlock: CheckTransaction
    ;; per tx — CVE-2018-17144 duplicate inputs, empty vin/vout, value
    ;; overflow, coinbase scriptSig length) plus the legacy-sigop block budget.
    ;; These need no UTXO set, so they run in the context-free portion — a fork
    ;; block is rejected before storage if it is structurally malformed, rather
    ;; than being stored and only caught later in PERFORM-REORG. Core sums
    ;; GetLegacySigOpCount over every tx (coinbase included) and rejects when
    ;; nSigOps * WITNESS_SCALE_FACTOR > MAX_BLOCK_SIGOPS_COST (validation.cpp
    ;; CheckBlock; deliberately an underestimate — P2SH/witness sigops are the
    ;; contextual ConnectBlock count below).
    (let ((legacy-sigops 0))
      (dolist (tx transactions)
        (multiple-value-bind (valid error) (validate-transaction-structure tx)
          (unless valid
            (return-from validate-block (values nil error nil))))
        (incf legacy-sigops (count-legacy-sigops tx)))
      (when (> (* legacy-sigops +witness-scale-factor+) +max-block-sigops-cost+)
        (return-from validate-block (values nil :bad-blk-sigops nil))))

    ;; CONTEXT-FREE-ONLY stops here: everything above is a pure function of the
    ;; block (Core CheckBlock); everything below depends on the active UTXO set
    ;; / chain height (Core ContextualCheckBlock + ConnectBlock) and is only
    ;; correct for a tip-extending block. A fork block is stored now and its
    ;; contextual checks run later in PERFORM-REORG, fork-to-tip.
    (when context-free-only
      (return-from validate-block (values t nil nil)))

    ;; BIP 30: reject a block that re-creates a still-unspent txid.
    ;; Per-output point lookups, exactly Core's HaveCoin loop
    ;; (validation.cpp:2444): a duplicate txid implies an identical tx
    ;; (the txid commits to the outputs), so probing the new tx's own
    ;; output indexes is complete. The previous any-utxo-for-txid-p did a
    ;; LevelDB prefix SCAN per tx — 85% of mainnet-IBD CPU at h~216k once
    ;; the chainstate outgrew LevelDB's table cache (sb-sprof, 2026-06-06).
    (when (bip30-enforced-p current-height)
      (dolist (tx transactions)
        (let ((txid (bitcoin-lisp.serialization:transaction-hash tx)))
          (dotimes (o (length (bitcoin-lisp.serialization:transaction-outputs tx)))
            (when (bitcoin-lisp.storage:get-utxo utxo-set txid o)
              (return-from validate-block
                (values nil :duplicate-txid nil)))))))

    ;; Validate each transaction and collect fees (using Satoshi type)
    ;; Track outputs from earlier transactions for intra-block spending
    (let* ((total-fees (bitcoin-lisp.coalton.interop:wrap-satoshi 0))
           (total-sigops-cost 0)
           (pending-utxos (make-hash-table :test 'equalp))
           ;; Outpoints an earlier transaction of this block already consumed.
           ;; Core spends them out of its per-block coins view (UpdateCoins,
           ;; validation.cpp:1996-2008), so HaveInputs then fails for a second
           ;; spender; our view is read-only for the whole block, so the
           ;; consumed set is tracked alongside the created one. Coin data
           ;; stays in PENDING-UTXOS after the spend — sigop counting and
           ;; script validation still need the spender's own prevouts.
           (spent-outpoints (make-hash-table :test 'equalp))
           ;; Gate P2SH/witness sigop counting on the block's active flags,
           ;; exactly as Bitcoin Core passes GetBlockScriptFlags into
           ;; GetTransactionSigOpCost. Same source of truth as script validation,
           ;; and that means BY BLOCK HASH: the exception table has to reach here
           ;; too. The BIP16 exception block is SCRIPT_VERIFY_NONE, so Core does
           ;; not count its P2SH sigops, and a height-only lookup would.
           (active-flags (block-script-flags-list
                          (bitcoin-lisp.serialization:block-header-hash
                           (bitcoin-lisp.serialization:bitcoin-block-header block))
                          current-height))
           (count-p2sh (and (member "P2SH" active-flags :test #'string=) t))
           (count-witness (and (member "WITNESS" active-flags :test #'string=) t)))

      ;; UTXO lookup function for sigops counting
      (flet ((get-spent-script (txid index)
               (let ((utxo (or (gethash (cons txid index) pending-utxos)
                               (bitcoin-lisp.storage:get-utxo utxo-set txid index))))
                 (when utxo
                   (bitcoin-lisp.storage:utxo-entry-script-pubkey utxo)))))

        ;; Coinbase: per-tx structure (CheckTransaction) already ran in the
        ;; context-free section above; here just accumulate its contextual
        ;; sigop cost and stage its outputs for intra-block spending.
        (let ((coinbase-tx (first transactions)))
          ;; Coinbase sigops: legacy only (no inputs to look up), scaled by witness factor
          (incf total-sigops-cost (* (count-legacy-sigops coinbase-tx) +witness-scale-factor+))
          ;; Add coinbase outputs to pending (for intra-block spending)
          (let ((txid (bitcoin-lisp.serialization:transaction-hash coinbase-tx)))
            (loop for output across (bitcoin-lisp.serialization:transaction-outputs coinbase-tx)
                  for idx from 0
                  do (setf (gethash (cons txid idx) pending-utxos)
                           (bitcoin-lisp.storage::make-utxo-entry
                            :value (bitcoin-lisp.serialization:tx-out-value output)
                            :script-pubkey (bitcoin-lisp.serialization:tx-out-script-pubkey output)
                            :height current-height
                            :coinbase t)))))

        ;; Validate other transactions. Per-tx structure (CheckTransaction)
        ;; already ran context-free above; here we do the contextual checks
        ;; (inputs / fees / sigops with P2SH+witness).
        (loop for tx in (rest transactions)
              do (multiple-value-bind (valid error fee)
                     (validate-transaction-contextual tx utxo-set current-height
                                                      :pending-utxos pending-utxos
                                                      :spent-outpoints spent-outpoints)
                   (unless valid
                     (return-from validate-block (values nil error nil)))
                   ;; fee is now a Satoshi type, use typed addition
                   (setf total-fees (bitcoin-lisp.coalton.interop:satoshi+ total-fees fee)))
                 ;; Accumulate sigops cost and check limit (early exit for DoS protection)
                 (incf total-sigops-cost
                       (count-transaction-sigops-cost tx #'get-spent-script
                                                      :count-p2sh count-p2sh
                                                      :count-witness count-witness))
                 (when (> total-sigops-cost +max-block-sigops-cost+)
                   (return-from validate-block
                     (values nil :too-many-sigops nil)))
                 ;; Core's UpdateCoins order (validation.cpp:1996-2008): mark
                 ;; this transaction's inputs spent, THEN add its outputs. Only
                 ;; non-coinbase transactions reach here, so the coinbase's null
                 ;; prevout is never marked (Core's `if (!tx.IsCoinBase())`).
                 (bitcoin-lisp.serialization:dovector
                     (input (bitcoin-lisp.serialization:transaction-inputs tx))
                   (let ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input)))
                     (setf (gethash (cons (bitcoin-lisp.serialization:outpoint-hash prevout)
                                          (bitcoin-lisp.serialization:outpoint-index prevout))
                                    spent-outpoints)
                           t)))
                 (let ((txid (bitcoin-lisp.serialization:transaction-hash tx)))
                   (loop for output across (bitcoin-lisp.serialization:transaction-outputs tx)
                         for idx from 0
                         do (setf (gethash (cons txid idx) pending-utxos)
                                  (bitcoin-lisp.storage::make-utxo-entry
                                   :value (bitcoin-lisp.serialization:tx-out-value output)
                                   :script-pubkey (bitcoin-lisp.serialization:tx-out-script-pubkey output)
                                   :height current-height
                                   :coinbase nil))))))

      ;; Transaction finality check (IsFinalTx) and BIP 68 sequence locks
      (let* ((prev-hash (bitcoin-lisp.serialization:block-header-prev-block header))
             (mtp (or (compute-median-time-past chain-state prev-hash) 0))
             (csv-height (get-csv-activation-height bitcoin-lisp:*network*))
             (csv-active (>= current-height csv-height))
             ;; For IsFinalTx: use MTP after BIP 113 activation, block timestamp before
             (locktime-check-time (if csv-active
                                      mtp
                                      (bitcoin-lisp.serialization:block-header-timestamp header))))
        ;; Finality covers EVERY transaction including the coinbase: Core's
        ;; ContextualCheckBlock iterates block.vtx with no IsCoinBase guard
        ;; (validation.cpp:4176-4181). This skipped vtx[0], so a coinbase with
        ;; an nLockTime past the cutoff and a non-final nSequence connected
        ;; here while Core rejected the block bad-txns-nonfinal.
        ;;
        ;; The coinbase exclusion belongs to the BIP68 loop directly below,
        ;; which Core really does guard with `if (!tx.IsCoinBase())'
        ;; (validation.cpp:2528) — it was applied to the wrong one of two
        ;; adjacent loops. Keep them different; making them agree reintroduces
        ;; one bug or the other.
        (loop for tx in transactions
              unless (check-transaction-final tx current-height locktime-check-time)
                do (return-from validate-block (values nil :non-final-tx nil)))
        ;; BIP 68 sequence lock enforcement (only at or above CSV activation)
        (when csv-active
          (loop for tx in (rest transactions)
                unless (check-sequence-locks tx utxo-set current-height mtp chain-state
                                             :pending-utxos pending-utxos)
                  do (return-from validate-block (values nil :bad-sequence-lock nil)))))

      ;; Validate transaction scripts via Coalton interop
      ;; Skip during IBD for blocks below the last checkpoint (performance optimization)
      (unless skip-scripts
        (multiple-value-bind (valid error)
            (validate-block-scripts block utxo-set :height current-height
                                                   :extra-coins pending-utxos)
          (unless valid
            (return-from validate-block (values nil error nil)))))

      ;; Validate witness commitment / malleation (BIP 141). Gated on
      ;; segwit activation for this height, matching Core's
      ;; expect_witness_commitment = DeploymentActiveAfter(prev, SEGWIT).
      (multiple-value-bind (valid error)
          (validate-witness-commitment
           block
           (>= current-height
               (get-segwit-activation-height bitcoin-lisp:*network*)))
        (unless valid
          (return-from validate-block (values nil error nil))))

      ;; Validate BIP 34 coinbase height
      (multiple-value-bind (valid error)
          (validate-coinbase-height block current-height)
        (unless valid
          (return-from validate-block (values nil error nil))))

      ;; Validate coinbase value
      (let* ((coinbase-tx (first transactions))
             (coinbase-output-total
               (reduce #'+ (bitcoin-lisp.serialization:transaction-outputs coinbase-tx)
                       :key #'bitcoin-lisp.serialization:tx-out-value))
             (block-subsidy (calculate-block-subsidy current-height))
             ;; Convert total-fees to integer for comparison
             (max-coinbase-value (+ block-subsidy (bitcoin-lisp.coalton.interop:unwrap-satoshi total-fees))))
        (when (> coinbase-output-total max-coinbase-value)
          (return-from validate-block
            (values nil :coinbase-too-large nil))))

      ;; Return total-fees as Satoshi type
      (values t nil total-fees))))

(defun test-block-validity (block chain-state utxo-set
                            &key (current-time
                                  (bitcoin-lisp.serialization:get-unix-time)))
  "Dry-run BLOCK's full validation against CHAIN-STATE's current tip without
mutating any state — Bitcoin Core's TestBlockValidity (validation.cpp:4495),
which every created block template runs through (node/miner.cpp:227-231) so
a template the network would reject is never handed to a miner. BLOCK must
extend the tip. Runs the complete VALIDATE-BLOCK battery — contextual header
checks (difficulty bits, timestamps, BIP94 timewarp), merkle root, block
weight, the sigops budget, scripts, finality, BIP68 sequence locks, witness
commitment, BIP34 height, coinbase value — with only the PoW hash<=target
(and signet solution) skipped, since the template is unmined (Core's
check_pow=false). VALIDATE-BLOCK only reads the UTXO set (intra-block spends
ride in its pending table), so no scratch coins view is needed; nothing is
connected, stored, or indexed. Divergence from Core: Core also skips the
merkle-root check because its template coinbase is a dummy; our callers
validate the fully assembled block, so the root is checked too.
Returns (VALUES T NIL) on success, (VALUES NIL ERROR-KEYWORD) on failure."
  (let* ((header (bitcoin-lisp.serialization:bitcoin-block-header block))
         (prev-hash (bitcoin-lisp.serialization:block-header-prev-block header)))
    (unless (equalp prev-hash (bitcoin-lisp.storage:best-block-hash chain-state))
      (return-from test-block-validity
        (values nil :inconclusive-not-best-prevblk)))
    (multiple-value-bind (valid error)
        (validate-block block chain-state utxo-set
                        (1+ (bitcoin-lisp.storage:current-height chain-state))
                        current-time :skip-pow t)
      (values (and valid t) error))))

;;;; Helper functions

(defun is-coinbase-tx (tx)
  "Check if TX is a coinbase transaction."
  (let ((inputs (bitcoin-lisp.serialization:transaction-inputs tx)))
    (and (= (length inputs) 1)
         (bitcoin-lisp.serialization:coinbase-input-p (aref inputs 0)))))

(defun calculate-block-subsidy (height)
  "Calculate the block subsidy for a given height. Subsidy halves every
halving interval — 210,000 blocks on mainnet/testnet/signet, 150 on regtest
(Bitcoin Core CRegTestParams nSubsidyHalvingInterval). The previous hardcoded
210,000 over-paid regtest coinbases past height 150 vs Core."
  (let* ((interval (if (eq bitcoin-lisp:*network* :regtest) 150 210000))
         (halvings (floor height interval))
         (subsidy (* 50 +coin+)))
    (if (>= halvings 64)
        0
        (ash subsidy (- halvings)))))

;;;; Undo data for chain reorganizations

(defvar *block-undo-data* (make-hash-table :test 'equalp)
  "In-memory cache: maps block-hash -> list of (txid index utxo-entry).")

(defvar *undo-base-path* nil
  "Base directory for undo data files. Set during node startup.")

(defvar *undo-block-store* nil
  "The block store whose rev files hold undo data, or NIL for legacy-only
storage. Set during node startup beside *UNDO-BASE-PATH*.

Held as a special rather than passed down because an undo record is addressed
by nothing but the block index entry that points at it, so every read path —
reorg disconnect, getdescriptoractivity, the block-filter backfill — needs the
store and the index even though all any of them has is a block hash.")

(defvar *undo-chain-state* nil
  "The chain state whose block index carries nUndoPos. See *UNDO-BLOCK-STORE*.")

(defconstant +max-undo-cache+ 100
  "Maximum number of blocks to keep in the in-memory undo cache.")

(defvar *undo-cache-heights* (make-hash-table :test 'equalp)
  "Maps block-hash -> height for cache eviction ordering.")

(defvar *undo-magic* (map '(vector (unsigned-byte 8)) #'char-code "UNDO")
  "Magic bytes identifying an undo data file.")

(defconstant +undo-format-version+ 1
  "Current undo data file format version.")

(defun initialize-undo-storage (base-path &key block-store chain-state)
  "Initialize undo data persistence with BASE-PATH as the legacy per-block
directory. BLOCK-STORE and CHAIN-STATE enable Core's rev-file format: without
them every read and write uses the legacy files, which is also what a store
with *FLAT-BLOCK-FILES* off does."
  ;; The directory is NOT created here. It is the LEGACY per-block undo
  ;; location, and a node writing Core's rev files never puts anything in it —
  ;; so creating it eagerly leaves an empty `undo/` in every fresh datadir, a
  ;; directory Core does not have. That is not cosmetic: Core's functional-test
  ;; framework builds its shared cache datadir and then deletes every entry it
  ;; does not recognise with os.remove, which raises on a DIRECTORY. An empty
  ;; undo/ therefore broke the cache build for the whole suite.
  ;;
  ;; %ENSURE-UNDO-DIRECTORY creates it on the first legacy write instead, which
  ;; is the only time it can be needed; an existing one keeps working untouched.
  (setf *undo-base-path* base-path
        *undo-block-store* block-store
        *undo-chain-state* chain-state))

(defun %ensure-undo-directory ()
  "Create the legacy undo directory, just before something is written into it."
  (when *undo-base-path*
    (ensure-directories-exist *undo-base-path*)))

(defun undo-file-path (block-hash)
  "Return the path for an undo data file given BLOCK-HASH."
  (when *undo-base-path*
    (merge-pathnames
     (make-pathname :name (bitcoin-lisp.crypto:bytes-to-hex block-hash)
                    :type "dat")
     *undo-base-path*)))

(defun delete-undo-file (block-hash)
  "Forget BLOCK-HASH's undo data: delete its legacy per-block file if present,
and clear the flat-file positions its index entry still carries. Pruned blocks
can never be disconnected (no block data to reorg through), so their undo data
is dead weight — Core deletes rev files together with blk files.

Clearing the positions is what PruneOneBlockFile does too
(blockstorage.cpp:264-270: nStatus loses HAVE_DATA and HAVE_UNDO, and nFile /
nDataPos / nUndoPos all go to zero). Leaving a stale nUndoPos behind persists a
lie into the header index and makes every later query for this block read a
rev file that is gone."
  (let ((entry (and *undo-chain-state*
                    (bitcoin-lisp.storage:get-block-index-entry
                     *undo-chain-state* block-hash))))
    (when entry
      (setf (bitcoin-lisp.storage:block-index-entry-file entry) nil
            (bitcoin-lisp.storage:block-index-entry-data-pos entry) nil
            (bitcoin-lisp.storage:block-index-entry-undo-pos entry) nil)))
  (remhash block-hash *block-undo-data*)
  (let ((path (undo-file-path block-hash)))
    (when (and path (probe-file path))
      (ignore-errors (delete-file path))
      (remhash block-hash *undo-cache-heights*)
      t)))

(defun prune-stale-undo-files (chain-state
                               &key (horizon (bitcoin-lisp.storage:chain-state-pruned-height
                                              chain-state)))
  "One-time catch-up: delete undo files for blocks at or below HORIZON
(default: the chain's pruned-height; they accumulated before undo pruning
existed — 53GB/500k files observed on the first mainnet run). Lists the undo
directory and resolves each filename (a block-hash hex) against the
in-memory index, so after the first sweep the directory only holds the
unpruned window and subsequent startup sweeps are cheap. The undo directory
is shared across chainstates, so with an assumeutxo background sync the
caller must pass the MINIMUM pruned-height over all chainstates — sweeping
by the snapshot chainstate's cursor (above the base) would delete the
historical chainstate's whole undo window. Returns the number of files
deleted."
  (let ((deleted 0))
    (when (and *undo-base-path* (plusp horizon))
      (dolist (file (directory (merge-pathnames "*.dat" *undo-base-path*)))
        (let* ((hash (ignore-errors
                      (bitcoin-lisp.crypto:hex-to-bytes (pathname-name file))))
               (entry (and hash
                           (= (length hash) 32)
                           (bitcoin-lisp.storage:get-block-index-entry
                            chain-state hash))))
          ;; Delete when the block is at/below the pruned horizon, or when
          ;; the hash is unknown to the index entirely (stale fork remnant).
          (when (or (null entry)
                    (<= (bitcoin-lisp.storage:block-index-entry-height entry)
                        horizon))
            (ignore-errors (delete-file file))
            (when hash (remhash hash *undo-cache-heights*))
            (incf deleted)))))
    deleted))

(defun %undo-flat-file-number (block-hash)
  "The rev file number BLOCK-HASH's undo record belongs in, or NIL when there
is none: the flat files are off, the store and index are not wired, or the
block is not in a flat file (so there is no rev file to pair with).

The number comes from the STORE, not from the index entry's nFile — see
BLOCK-FLAT-FILE-NUMBER. The entry is still where nUndoPos is recorded, because
a rev record carries no block hash and nothing else can find it again."
  (when (and bitcoin-lisp.storage:*flat-block-files*
             *undo-block-store* *undo-chain-state*)
    (bitcoin-lisp.storage:block-flat-file-number *undo-block-store* block-hash)))

(defun %save-undo-legacy (block-hash spent-utxos)
  "Write SPENT-UTXOS as the legacy one-file-per-block format: a flat list of
(txid, index, entry) triples. Self-describing, so it needs no block. Always
returns NIL, which is what marks it as the non-flat branch.

Byte-buf writer: this runs once per connected block, and the previous
flexi-streams path's Gray-stream dispatch was ~8% of mainnet-IBD CPU at h~280k
(sb-sprof) once blocks carried 500+ spent inputs each."
  (let ((path (undo-file-path block-hash)))
    (when path
      ;; The directory is created here rather than at start-up, so a node that
      ;; only ever writes Core's rev files leaves no empty undo/ behind.
      (%ensure-undo-directory)
      (bitcoin-lisp.storage:save-file-with-crc32-bb
       path
       (lambda (bb)
         (bitcoin-lisp.serialization:bb-write-bytes bb *undo-magic*)
         (bitcoin-lisp.serialization:bb-write-u32-le bb +undo-format-version+)
         (bitcoin-lisp.serialization:bb-write-u32-le bb (length spent-utxos))
         (dolist (entry spent-utxos)
           (destructuring-bind (txid index utxo) entry
             (bitcoin-lisp.serialization:bb-write-bytes bb txid)
             (bitcoin-lisp.serialization:bb-write-u32-le bb index)
             (bitcoin-lisp.storage:bb-write-utxo-entry-fields bb utxo)))))))
  nil)

(defun save-undo-data-to-disk (block-hash spent-utxos &key block)
  "Persist SPENT-UTXOS for BLOCK-HASH and return the FLAT-FILE-POS it was
written to, or NIL when it went to a legacy per-block file.

With *FLAT-BLOCK-FILES* on and BLOCK available, this writes Core's CBlockUndo
into the rev file paired with the block's blk file (blockstorage.cpp:996-1026).
Otherwise it writes the legacy format, which needs no block."
  (or (and block (%save-undo-flat block block-hash spent-utxos))
      (%save-undo-legacy block-hash spent-utxos)))

(defun %save-undo-flat (block block-hash spent-utxos)
  "Write SPENT-UTXOS as Core's CBlockUndo into the rev file paired with BLOCK's
blk file, returning the FLAT-FILE-POS, or NIL when that is not possible.

NIL means \"use the legacy format\". A conversion failure is NIL too, and
deliberately: BLOCK-UNDO-FROM-SPENT-UTXOS signals when the triples do not
account for exactly the block's inputs, and Core's format cannot represent that
(position is the only thing naming a coin). Falling back to the self-describing
legacy format keeps the block disconnectable instead of losing its undo data to
a format mismatch."
  (let ((file (%undo-flat-file-number block-hash)))
    (when file
      (let ((entry (bitcoin-lisp.storage:get-block-index-entry
                    *undo-chain-state* block-hash)))
        (when entry
          ;; Undo data is written ONCE per block. Core skips the write outright
          ;; when the block already has a record (`if (block.GetUndoPos()
          ;; .IsNull())`, blockstorage.cpp:970) — without this a block
          ;; disconnected and reconnected by a reorg appends a second full
          ;; record every time, and nUndoPos changes VALUE while its presence
          ;; bit does not, which the header index's delta log does not notice
          ;; (chain.lisp %entry-persist-key) — so the persisted offset would
          ;; silently stay a generation behind.
          (if (bitcoin-lisp.storage:block-index-entry-undo-pos entry)
              (bitcoin-lisp.storage:make-flat-file-pos
               file (bitcoin-lisp.storage:block-index-entry-undo-pos entry))
              (handler-case
                  (let* ((tx-undos (bitcoin-lisp.storage:block-undo-from-spent-utxos
                                    block spent-utxos))
                         (bytes (bitcoin-lisp.storage:serialize-block-undo tx-undos))
                         (prev-hash (bitcoin-lisp.serialization:block-header-prev-block
                                     (bitcoin-lisp.serialization:bitcoin-block-header block)))
                         (pos (bitcoin-lisp.storage:store-undo-flat
                               *undo-block-store* file prev-hash bytes)))
                    (setf (bitcoin-lisp.storage:block-index-entry-undo-pos entry)
                          (bitcoin-lisp.storage:flat-file-pos-pos pos))
                    pos)
                (error (e)
                  (bitcoin-lisp:log-warn
                   "Undo data for ~A could not be written in Core's format (~A) — ~
falling back to the legacy per-block file"
                   (bitcoin-lisp.crypto:bytes-to-hex block-hash) e)
                  nil))))))))

(defun %load-undo-flat (block-hash &key block)
  "Read BLOCK-HASH's undo record out of its rev file and rebuild the
(txid index entry) triples, or NIL when there is no flat record for it.

BLOCK is fetched when not supplied: Core's CBlockUndo stores NO outpoints, so
the only thing naming each coin is its position — transaction i+1 of the block,
input j (undo.h; validation.cpp:2187, 2224). Callers that already hold the
block should pass it; a full-chain index backfill otherwise reads every block
twice."
  (let ((file (%undo-flat-file-number block-hash)))
    (when file
      (let* ((entry (bitcoin-lisp.storage:get-block-index-entry
                     *undo-chain-state* block-hash))
             (undo-pos (and entry
                            (bitcoin-lisp.storage:block-index-entry-undo-pos entry))))
        (when undo-pos
          (handler-case
              (let ((block (or block
                               (bitcoin-lisp.storage:get-block
                                *undo-block-store* block-hash))))
                (when block
                  (let* ((pos (bitcoin-lisp.storage:make-flat-file-pos file undo-pos))
                         (prev-hash (bitcoin-lisp.serialization:block-header-prev-block
                                     (bitcoin-lisp.serialization:bitcoin-block-header block)))
                         (bytes (bitcoin-lisp.storage:read-undo-flat
                                 *undo-block-store* pos prev-hash)))
                    (when bytes
                      (bitcoin-lisp.storage:spent-utxos-from-block-undo
                       block
                       (bitcoin-lisp.storage:deserialize-block-undo bytes))))))
            (error (e)
              (bitcoin-lisp:log-warn "Failed to load flat undo record for ~A: ~A"
                                     (bitcoin-lisp.crypto:bytes-to-hex block-hash) e)
              nil)))))))

(defun %load-undo-legacy (block-hash)
  "Read BLOCK-HASH's legacy one-file-per-block undo file, or NIL.

Separate from LOAD-UNDO-DATA-FROM-DISK because the migration needs to read the
legacy copy SPECIFICALLY — reading through the dual-read path would hand it the
rev record it just wrote and let it verify that record against itself."
  (let ((path (undo-file-path block-hash)))
    (when path
      (let ((data (bitcoin-lisp.storage:load-file-with-crc32 path 16)))
        (when data
          (handler-case
              (flexi-streams:with-input-from-sequence (stream data)
                (let ((magic (make-array 4 :element-type '(unsigned-byte 8))))
                  (read-sequence magic stream)
                  (unless (equalp magic *undo-magic*)
                    (return-from %load-undo-legacy nil)))
                (let ((version (bitcoin-lisp.serialization:read-uint32-le stream)))
                  (unless (= version +undo-format-version+)
                    (return-from %load-undo-legacy nil)))
                (let* ((count (bitcoin-lisp.serialization:read-uint32-le stream))
                       (entries '()))
                  (dotimes (i count)
                    (let* ((txid (make-array 32 :element-type '(unsigned-byte 8)))
                           (_ (read-sequence txid stream))
                           (index (bitcoin-lisp.serialization:read-uint32-le stream))
                           (utxo (bitcoin-lisp.storage:read-utxo-entry-fields stream)))
                      (declare (ignore _))
                      (push (list txid index utxo) entries)))
                  (nreverse entries)))
            (error (c)
              (bitcoin-lisp:log-warn "Failed to load undo data: ~A" c)
              nil)))))))

(defun load-undo-data-from-disk (block-hash &key block)
  "Load and verify undo data from disk. Returns a list of (txid index utxo-entry)
or NIL.

Dual read, and the flat record is tried FIRST: a store that has ever had the
flat files on holds both forms at once, and the migration writes the flat
record before deleting the legacy file, so preferring the flat one keeps a
half-migrated store reading the copy that is certainly complete."
  (or (%load-undo-flat block-hash :block block)
      (%load-undo-legacy block-hash)))

(defun migrate-undo-to-flat (block-hash)
  "Move BLOCK-HASH's legacy per-block undo file into the rev file paired with
its block, returning :MIGRATED, :SKIPPED, or NIL on failure.

Called from the migrateblocks RPC once a block has reached a flat file, which
is the earliest moment this is possible: a rev record must go into its block's
file number, so the block has to be there first.

The legacy file is deleted only after the flat record has been read back and
compared, the same safety rule the block migration follows — the legacy file is
the only copy until then. A failure keeps it, and dual read keeps serving it."
  (let ((path (undo-file-path block-hash)))
    (cond
      ((not (and path (probe-file path))) :skipped)
      ((null *undo-block-store*) :skipped)
      (t
       ;; The migration converts a store whose -flatblockfiles flag may well be
       ;; OFF: %migrate-one-block forces the same binding for the block itself,
       ;; and without it here every undo record would silently stay legacy
       ;; while migrateblocks reported success.
       (let* ((bitcoin-lisp.storage:*flat-block-files* t)
              (block (bitcoin-lisp.storage:get-block *undo-block-store* block-hash))
              ;; The LEGACY reader specifically. Going through
              ;; load-undo-data-from-disk would return the rev record once one
              ;; exists, and the read-back check below would then be comparing
              ;; that record against itself — deleting a legacy file nothing
              ;; had verified.
              (legacy (%load-undo-legacy block-hash)))
         (cond
           ((null block) :skipped)
           ;; An undo file that is present but holds nothing is either a block
           ;; with no spends or a corrupt file; either way there is nothing to
           ;; convert and Core's format would represent them identically.
           ((null legacy) :skipped)
           ;; A block already carrying nUndoPos has nothing to migrate: the
           ;; write is skipped (Core's IsNull guard) and the legacy file is
           ;; redundant, so drop it once the rev record verifies below.
           ((null (%save-undo-flat block block-hash legacy)) nil)
           (t
            (let ((check (%load-undo-flat block-hash)))
              (cond
                ((%undo-lists-equal-p legacy check)
                 (ignore-errors (delete-file path))
                 :migrated)
                (t
                 ;; Leave nUndoPos pointing at the flat record anyway: it was
                 ;; written and read back wrong, so the legacy file is the
                 ;; trustworthy copy and must keep being preferred. Clearing
                 ;; the pointer is what makes that happen, since the read path
                 ;; tries the flat record first.
                 (let ((entry (bitcoin-lisp.storage:get-block-index-entry
                               *undo-chain-state* block-hash)))
                   (when entry
                     (setf (bitcoin-lisp.storage:block-index-entry-undo-pos entry) nil)))
                 (bitcoin-lisp:log-error
                  "Migration: undo data for ~A did not read back from its rev ~
file; the legacy undo file is kept"
                  (bitcoin-lisp.crypto:bytes-to-hex block-hash))
                 nil))))))))))

(defun %undo-lists-equal-p (a b)
  "T when two (txid index utxo-entry) lists describe the same spent coins.
The read-back check for MIGRATE-UNDO-TO-FLAT.

EQUALP is the comparison: it descends structures slot-wise and vectors
element-wise, which over a UTXO-ENTRY of integers, a boolean and an octet
vector is exactly field equality. The length test is not redundant — EVERY
stops at the shorter list, so without it a truncated read would compare equal."
  (and (listp a) (listp b)
       (= (length a) (length b))
       (every #'equalp a b)))

(defun evict-undo-cache ()
  "Evict the oldest half of cache entries by height (they remain on disk)."
  (let ((entries '()))
    (maphash (lambda (hash height)
               (push (cons hash height) entries))
             *undo-cache-heights*)
    (setf entries (sort entries #'< :key #'cdr))
    (let ((to-evict (subseq entries 0 (floor (length entries) 2))))
      (dolist (pair to-evict)
        (remhash (car pair) *block-undo-data*)
        (remhash (car pair) *undo-cache-heights*)))))

(defun %warn-if-undo-empty (block block-hash height spent-utxos)
  "Tripwire: a block with non-coinbase transactions must spend something, so an
empty SPENT-UTXOS means every prevout was already absent from the UTXO view --
the signature of a double-apply. The old unvalidated reorg-reconnect path
(pre-CC-1, fixed 2026-06-17) did exactly that on testnet4 and overwrote 7
blocks' undo files with empty lists, which later stalled the block filter
backfill. apply-block-to-utxo-set skips missing prevouts silently, so this is
the one place the condition is visible before a bad undo file hits disk."
  (when (and (null spent-utxos)
             (> (length (bitcoin-lisp.serialization:bitcoin-block-transactions
                         block))
                1))
    (bitcoin-lisp:log-warn
     "Undo data EMPTY for spending block ~A at height ~D — prevouts already ~
absent from the UTXO view (double-apply?)"
     (bitcoin-lisp.crypto:bytes-to-hex block-hash) height)))

(defun store-undo-data (block-hash spent-utxos height &key block)
  "Store undo data for a block to disk and in-memory cache.

BLOCK is what allows Core's rev-file format to be used at all: CBlockUndo has
no outpoints, so writing it needs the block to group the spent coins by
transaction and reading it needs the block to name them again. Without BLOCK
the legacy self-describing format is written."
  (save-undo-data-to-disk block-hash spent-utxos :block block)
  (setf (gethash block-hash *block-undo-data*) spent-utxos)
  (setf (gethash block-hash *undo-cache-heights*) height)
  (when (> (hash-table-count *block-undo-data*) +max-undo-cache+)
    (evict-undo-cache)))

(defun get-undo-data (block-hash)
  "Get undo data for a block. Checks the in-memory cache first, then disk.
Disk loads are deliberately NOT cached: this read path (reorg disconnects,
getdescriptoractivity, the block filter backfill) has no eviction hook --
entries it used to stash in *block-undo-data* carried no *undo-cache-heights*
record, so evict-undo-cache could never see them and they were live heap
forever. A filter backfill over the whole testnet4 chain accumulated ~4.5 GiB
of undo lists that way and exhausted the 6 GiB heap at ~72k blocks. Only
store-undo-data (the connect path, which does the height bookkeeping) caches."
  (or (gethash block-hash *block-undo-data*)
      (load-undo-data-from-disk block-hash)))

;;;; Recently-confirmed transactions + most-recent-block tx set
;;;;
;;;; Two small tip-following structures Core keeps for tx relay, maintained
;;;; here because every block-connect path (IBD, relay, compact blocks,
;;;; reorg reconnect) funnels through this file:
;;;;
;;;;  - The recent-confirmed filter (Core m_lazy_recent_confirmed_transactions,
;;;;    txdownloadman_impl.h:120-128, a CRollingBloomFilter{48000, 0.000001}):
;;;;    txids AND wtxids of txs confirmed in recent blocks, so freshly-mined
;;;;    txs aren't re-requested or re-processed when a slower peer announces
;;;;    them (AlreadyHaveTx, txdownloadman_impl.cpp:144). Reset on block
;;;;    DISCONNECT (reorg) so previously-confirmed txs can relay again
;;;;    (BlockDisconnected, txdownloadman_impl.cpp:112-123).
;;;;
;;;;  - The most-recent-block tx map (Core m_most_recent_block_txs,
;;;;    net_processing.cpp:869, rebuilt in NewPoWValidBlock:2121-2132): the
;;;;    newest block's txs keyed by txid and wtxid, so a getdata for a
;;;;    just-confirmed tx is still served even though it left the mempool
;;;;    (FindTxForGetData's second source, net_processing.cpp:2507-2514).
;;;;
;;;;  - The RECONSIDERABLE rejects filter (Core
;;;;    m_lazy_recent_rejects_reconsiderable, txdownloadman_impl.h:83-95):
;;;;    the second of Core's two reject filters, kept here for the same
;;;;    reason — it is reset on every active tip change, and that reset
;;;;    happens in this file.

(defvar *recent-confirmed-txs* (bitcoin-lisp:make-rejects-filter 48000)
  "Bounded rolling set of recently-confirmed txids/wtxids (Core
m_lazy_recent_confirmed_transactions). Reuses the recent-rejects ring
structure, sized like Core: 48,000 entries covers ~a couple hours of blocks.")

(defvar *most-recent-block-txs* nil
  "Hash-table (equalp) mapping the most recent connected block's tx ids —
txid AND wtxid — to their transactions, or NIL before any block connects
(Core m_most_recent_block_txs). Replaced wholesale on every tip advance.")

(defvar *most-recent-block* nil
  "The most recent connected block and its hash, as (hash . block), or NIL
(Core m_most_recent_block / m_most_recent_block_hash). Held so a getdata for
the new tip is answered without re-reading and re-parsing it from disk once
per requesting peer.")

(defvar *most-recent-cmpctblock* nil
  "The most recent block as a ready-to-send BIP152 cmpctblock message, built on
first request and reused (Core m_most_recent_compact_block; Core builds it
eagerly but defers the serialization with a deferred future, and building it
lazily gets the same result without spending the work during IBD, when nobody
is asking). Serving N peers the same new tip therefore costs one construction,
not N — a compact block is the cheapest BIP152 message to send and the most
expensive to build, a SipHash per transaction.")

(defun most-recent-cmpctblock (hash)
  "A cmpctblock message for HASH when HASH is the most recent connected block,
building and caching it on first call; NIL for any other block, which the
caller answers from disk instead."
  (let ((recent *most-recent-block*))
    (when (and recent (equalp hash (car recent)))
      (or *most-recent-cmpctblock*
          (setf *most-recent-cmpctblock*
                (bitcoin-lisp.serialization:make-cmpctblock-message (cdr recent)))))))

(defun recently-confirmed-p (hash)
  "T if HASH (txid or wtxid) was confirmed in a recent block."
  (and (bitcoin-lisp:recent-reject-p *recent-confirmed-txs* hash) t))

(defun most-recent-block-tx (hash)
  "The most recent block's transaction with txid or wtxid HASH, or NIL."
  (and *most-recent-block-txs*
       (gethash hash *most-recent-block-txs*)))

(defun reset-recent-confirmed ()
  "Empty the recent-confirmed filter — on block disconnect (Core
BlockDisconnected: a reorg may return confirmed txs to circulation, and the
filter would otherwise block their relay) and at node start."
  (bitcoin-lisp:clear-recent-rejects *recent-confirmed-txs*))

;;;; The reconsiderable rejects filter (Core's SECOND rejects filter)

(defvar *recent-rejects-reconsiderable* (bitcoin-lisp:make-rejects-filter 50000)
  "Bounded rolling set of wtxids — and 1p1c package hashes — whose last
failure was TX_RECONSIDERABLE: a policy failure a DIFFERENT package could
still overcome. Core keeps this as a filter SEPARATE from the main rejects
filter (m_lazy_recent_rejects_reconsiderable, txdownloadman_impl.cpp:
454-466) precisely so those transactions are not black-holed: an entry here
means \"do not download or submit this by ITSELF again\", not \"never accept
this\" — it may still ride in as part of a package.

Core routes both fee-floor failures here (CheckFeeRate, validation.cpp:
703-711), the RBF fee/diagram failures (:1010, :1028) and \"mempool full\"
(:1401). Everything else keeps going to the main filter.

Node-global, like *RECENT-CONFIRMED-TXS* above: the validation layer loads
before networking, and the active-tip-change reset lives in this file.")

(defun reconsiderable-reject-p (hash)
  "T if HASH (a wtxid, or a 1p1c package hash) failed reconsiderably and so
must not be submitted on its own again (Core
RecentRejectsReconsiderableFilter().contains)."
  (and (bitcoin-lisp:recent-reject-p *recent-rejects-reconsiderable* hash) t))

(defun add-reconsiderable-reject (hash)
  "Record HASH as a reconsiderable failure (Core
RecentRejectsReconsiderableFilter().insert)."
  (bitcoin-lisp:add-recent-reject *recent-rejects-reconsiderable* hash))

(defun clear-reconsiderable-rejects ()
  "Empty the reconsiderable rejects filter. Core resets it beside the main
rejects filter on every active tip change (ActiveTipChange,
txdownloadman_impl.cpp:91-95): a new block changes both the fee floor and
which parents exist, so every cached fee failure is stale."
  (bitcoin-lisp:clear-recent-rejects *recent-rejects-reconsiderable*))

(defun note-block-connected (block)
  "Record BLOCK as the new most-recent block: rebuild the getdata-servable
tx map and add every transaction's txid (and distinct wtxid) to the
recent-confirmed filter (Core BlockConnected, txdownloadman_impl.cpp:98-110,
+ NewPoWValidBlock's most_recent_block_txs rebuild)."
  (let ((map (make-hash-table :test 'equalp)))
    (dolist (tx (coerce (bitcoin-lisp.serialization:bitcoin-block-transactions
                         block)
                        'list))
      (let ((txid (bitcoin-lisp.serialization:transaction-hash tx))
            (wtxid (bitcoin-lisp.serialization:transaction-wtxid tx)))
        (setf (gethash txid map) tx)
        (bitcoin-lisp:add-recent-reject *recent-confirmed-txs* txid)
        (unless (equalp wtxid txid)
          (setf (gethash wtxid map) tx)
          (bitcoin-lisp:add-recent-reject *recent-confirmed-txs* wtxid))))
    (setf *most-recent-block-txs* map
          ;; Keep the block itself too, and drop any compact form built for
          ;; the block this one replaces (most-recent-cmpctblock rebuilds on
          ;; demand). The transactions are retained by MAP either way, so the
          ;; extra cost is one cons.
          *most-recent-block* (cons (bitcoin-lisp.serialization:block-header-hash
                                     (bitcoin-lisp.serialization:bitcoin-block-header block))
                                    block)
          *most-recent-cmpctblock* nil)))

;;;; Block connection

(defun connect-block (block chain-state block-store utxo-set
                      &key tx-index fee-estimator recent-rejects mempool)
  "Connect a validated block to the chain.
Updates chain state and UTXO set.
Optionally updates TX-INDEX if provided and enabled.
Optionally updates FEE-ESTIMATOR with block fee statistics.
Optionally clears RECENT-REJECTS on chain reorganization.
When MEMPOOL is provided, removes the block's confirmed/conflicting txs from it
(the single removal chokepoint — every connect path, IBD or relay, goes here).
Handles chain reorganizations when a competing chain has more work."
  (let* ((header (bitcoin-lisp.serialization:bitcoin-block-header block))
         (hash (bitcoin-lisp.serialization:block-header-hash header))
         (prev-hash (bitcoin-lisp.serialization:block-header-prev-block header))
         (prev-entry (bitcoin-lisp.storage:get-block-index-entry chain-state prev-hash))
         (new-height (if prev-entry
                         (1+ (bitcoin-lisp.storage:block-index-entry-height prev-entry))
                         0))
         (prev-work (if prev-entry
                        (bitcoin-lisp.storage:block-index-entry-chain-work prev-entry)
                        0))
         (chain-work (bitcoin-lisp.storage:calculate-chain-work
                      (bitcoin-lisp.serialization:block-header-bits header)
                      prev-work))
         ;; Store the block here, in the binding list: the height travels with
         ;; it so the file it lands in can be pruned later (a flat block file
         ;; prunes whole, which needs its range). Where it landed is recorded
         ;; on the index entry below, once that entry exists.
         (stored-at (progn
                      ;; Core checks free space before every block and undo
                      ;; write (FindBlockPos, blockstorage.cpp:337) and treats
                      ;; a failure as fatal. Writing blocks onto a full disk is
                      ;; how a truncated-but-indexed .blk gets created, which
                      ;; this node has seen.
                      (bitcoin-lisp::%gate-block-write-on-disk-space)
                      (nth-value 1 (bitcoin-lisp.storage:store-block
                                    block-store block :height new-height)))))

    ;; Index entry. Core NEVER rebuilds a CBlockIndex: AddToBlockIndex is a
    ;; try_emplace that returns the existing object when the hash is already
    ;; known (node/blockstorage.cpp:228-231), and receiving the body mutates
    ;; that object in place. We constructed a fresh entry with :status :valid
    ;; and ADD-BLOCK-INDEX-ENTRY is a plain (setf gethash) — a REPLACE, which
    ;; erased an existing :invalid mark.
    ;;
    ;; That made invalidateblock defeatable by a single unsolicited block
    ;; message: the RPC reorgs down and marks the block :invalid, leaving the
    ;; tip at its parent, so a peer replaying the block hits the tip-extension
    ;; arm, passes validate-block (it IS consensus-valid — invalidateblock is a
    ;; manual override), and landed here to be re-created as :valid. The
    ;; operator's node silently returned to the chain they explicitly refused.
    ;; The same erasure cleared the automatic poison on a doomed fork subtree.
    (let* ((existing (bitcoin-lisp.storage:get-block-index-entry chain-state hash))
           (entry (or existing
                      (bitcoin-lisp.storage:make-block-index-entry
                       :hash hash
                       :height new-height
                       :header header
                       :prev-entry prev-entry
                       :chain-work chain-work
                       :status :valid
                       :tx-count (length (bitcoin-lisp.serialization:bitcoin-block-transactions
                                          block))))))
      (when existing
        ;; Refresh what arriving BODY data supplies, in place. Status is RAISED
        ;; only: an :invalid mark is a decision (operator or validator) and
        ;; nothing here is entitled to overrule it.
        (setf (bitcoin-lisp.storage:block-index-entry-height entry) new-height
              (bitcoin-lisp.storage:block-index-entry-header entry) header
              (bitcoin-lisp.storage:block-index-entry-prev-entry entry) prev-entry
              (bitcoin-lisp.storage:block-index-entry-chain-work entry) chain-work
              (bitcoin-lisp.storage:block-index-entry-tx-count entry)
              (length (bitcoin-lisp.serialization:bitcoin-block-transactions block)))
        (unless (eq (bitcoin-lisp.storage:block-index-entry-status entry) :invalid)
          (setf (bitcoin-lisp.storage:block-index-entry-status entry) :valid)))
      (bitcoin-lisp.storage:add-block-index-entry chain-state entry)
      ;; nFile/nDataPos, now that the entry is in the index (Core
      ;; ReceivedBlockTransactions).
      (bitcoin-lisp.storage::%record-block-position entry stored-at)

      ;; Check if we need a reorganization. REORG-OUTCOME captures perform-reorg's
      ;; result so callers can act on a refused reorg: NIL for a tip extension or
      ;; a stored side block, or (REORG-OK DETAIL) for the reorg branch — where
      ;; a NIL REORG-OK with a LIST detail is "refused, these (hash . height)
      ;; fork blocks are missing from the store" (re-download them) and a NIL
      ;; REORG-OK with a KEYWORD detail is "a fork block was invalid, rolled
      ;; back". Returned as connect-block's second value; existing callers that
      ;; read only the first value (the index entry) are unaffected.
      (let ((reorg-outcome
      (let* ((current-best-hash (bitcoin-lisp.storage:best-block-hash chain-state))
             (current-best-entry (bitcoin-lisp.storage:get-block-index-entry
                                  chain-state current-best-hash))
             (current-best-work (if current-best-entry
                                    (bitcoin-lisp.storage:block-index-entry-chain-work
                                     current-best-entry)
                                    0)))

        (cond
          ;; New block extends the current best chain (normal case).
          ;; Apply UTXO updates and advance chain tip atomically — without-
          ;; interrupts defers any pending bt:destroy-thread / SIGTERM until
          ;; this critical section completes, so saved state on disk is never
          ;; "chain advanced but UTXOs not applied" or vice versa.
          ((equalp prev-hash current-best-hash)
           #+sbcl (sb-sys:without-interrupts
           (let ((spent-utxos (bitcoin-lisp.storage:apply-block-to-utxo-set
                               utxo-set block new-height)))
             (%warn-if-undo-empty block hash new-height spent-utxos)
             (store-undo-data hash spent-utxos new-height :block block)
             ;; BIP158: add this block's basic filter to the block filter index
             ;; (no-op unless the index is enabled; never signals).
             (bitcoin-lisp:index-block-filter chain-state block hash new-height spent-utxos)
             ;; coinstatsindex: fold this block into the running UTXO stats
             ;; (no-op unless enabled; never signals).
             (bitcoin-lisp:index-block-coinstats chain-state block hash new-height spent-utxos)
             ;; txospenderindex: record which tx here spent each output it
             ;; consumes (no-op unless enabled; never signals).
             (bitcoin-lisp:index-block-txospenders chain-state block hash new-height)
             ;; Record fee statistics for fee estimation
             (when fee-estimator
               (let ((stats (bitcoin-lisp.mempool:compute-block-fee-stats
                             block spent-utxos new-height)))
                 (when stats
                   (bitcoin-lisp.mempool:fee-estimator-add-stats fee-estimator stats)
                   (bitcoin-lisp.mempool:maybe-flush-fee-stats fee-estimator)))))
           ;; Core's fee estimator learns from this block: for every
           ;; transaction it was tracking, how many blocks that feerate waited
           ;; (processBlock). Untracked txids are ignored, so the whole block
           ;; goes in. Runs BEFORE the mempool drops the block's transactions,
           ;; while they are still tracked.
           (bitcoin-lisp.mempool:bpe-note-block
            new-height
            (map 'list #'bitcoin-lisp.serialization:transaction-hash
                 (bitcoin-lisp.serialization:bitcoin-block-transactions block)))
           ;; ZMQ BlockConnected: each transaction, then the block and a
           ;; sequence 'C' (zmqnotificationinterface.cpp:180).
           (bitcoin-lisp:zmq-notify-block-connected block hash)
           ;; -blocknotify, detached so an operator hook can never stall block
           ;; connection (Core "thread runs free", init.cpp:2017).
           (bitcoin-lisp:notify-block-tip hash)
           ;; Update transaction index if enabled, and move its best-block
           ;; marker with the tip so the next startup resumes here instead of
           ;; re-reading every block from genesis.
           (when (and tx-index (bitcoin-lisp.storage:tx-index-enabled tx-index))
             (bitcoin-lisp.storage:txindex-add-block tx-index block hash)
             (bitcoin-lisp.storage:txindex-set-best-block tx-index hash))
           (bitcoin-lisp.storage:update-chain-tip chain-state hash new-height)
           ;; Remove now-confirmed (and conflicting) txs from the mempool,
           ;; inside the same critical section as the tip update.
           (when mempool
             (bitcoin-lisp.mempool:mempool-remove-for-block mempool block)))
           ;; Tx-relay tip bookkeeping (outside the critical section):
           ;; expire stale mempool entries once per block (Core expire-on-
           ;; block); erase orphans included in/conflicted by this block
           ;; (Core BlockConnected -> TxOrphanage::EraseForBlock); record the
           ;; block's txids/wtxids as recently confirmed and getdata-servable
           ;; (Core m_lazy_recent_confirmed_transactions +
           ;; m_most_recent_block_txs). A TARGETED chainstate — the assumeutxo
           ;; historical chainstate re-deriving old history — must not touch
           ;; these: its "tip" blocks are ancient, and Core only wires the
           ;; validation-interface tx-relay callbacks to the ACTIVE chainstate
           ;; (BlockConnected checks role, net_processing.cpp:2149-2157).
           (unless (bitcoin-lisp.storage:chain-state-target-blockhash chain-state)
             (when mempool
               (bitcoin-lisp.mempool:mempool-expire mempool)
               (bitcoin-lisp.mempool:orphan-erase-for-block
                (bitcoin-lisp.mempool:mempool-orphan-pool mempool) block))
             (note-block-connected block)
             ;; Wallet chain-tracking hook (wallet P2): scan the block for
             ;; wallet-relevant txs (Core CWallet::blockConnected). Runs
             ;; after mempool-remove-for-block, so the wallet sees the
             ;; conflict removals first — Core's signal order. Cheap no-op
             ;; when no wallets are loaded; never signals.
             (bitcoin-lisp:wallet-notify-block-connected
              chain-state block hash new-height)
             ;; -stopatheight: request shutdown once the ACTIVE tip reaches
             ;; the configured height (Core KernelNotifications::blockTip,
             ;; node/kernel_notifications.cpp:61-66); a background (targeted)
             ;; chainstate's ancient tips never trigger it. After the wallet
             ;; hook — Core's blockTip notification fires after the wallet's
             ;; BlockConnected signals.
             (bitcoin-lisp:maybe-stop-at-height new-height))
           ;; Core resets the recent-rejects filter on EVERY active tip change,
           ;; not just reorgs: cached failures (non-final, too-low-fee, missing
           ;; inputs) can become valid at the next block (ActiveTipChange,
           ;; net_processing.cpp:2045-2059 -> txdownloadman_impl.cpp:92-96
           ;; RecentRejectsFilter().reset()). Previously only the reorg path
           ;; cleared it. ActiveTipChange resets BOTH filters.
           (bitcoin-lisp:clear-recent-rejects recent-rejects)
           (clear-reconsiderable-rejects)
           (bitcoin-lisp:maybe-periodic-flush chain-state)
           ;; Automatic block pruning after connecting a new block; each
           ;; pruned block's undo file goes with it.
           (when (bitcoin-lisp:automatic-pruning-p)
             (let ((pruned (bitcoin-lisp.storage:prune-old-blocks
                            block-store chain-state
                            :on-prune #'delete-undo-file)))
               (when (> pruned 0)
                 (bitcoin-lisp:log-info "Pruned ~D old block~:P" pruned)))))

          ;; New chain has more work - reorganize. Capture perform-reorg's
          ;; (values ok detail) so the caller can re-queue missing fork blocks
          ;; on a refusal.
          ((> chain-work current-best-work)
           (multiple-value-list
            (perform-reorg chain-state block-store utxo-set
                           current-best-entry entry
                           :tx-index tx-index
                           :fee-estimator fee-estimator
                           :recent-rejects recent-rejects
                           :mempool mempool)))

          ;; New block is on a weaker chain - just store it
          (t nil)))))

      (values entry reorg-outcome)))))

(defun find-fork-point (entry-a entry-b)
  "Find the common ancestor (fork point) of two chain entries.
Returns the common ancestor block-index-entry."
  ;; Walk both chains back until we find a common block
  (let ((a entry-a)
        (b entry-b))
    ;; First, align heights
    (loop while (and a b (> (bitcoin-lisp.storage:block-index-entry-height a)
                            (bitcoin-lisp.storage:block-index-entry-height b)))
          do (setf a (bitcoin-lisp.storage:block-index-entry-prev-entry a)))
    (loop while (and a b (> (bitcoin-lisp.storage:block-index-entry-height b)
                            (bitcoin-lisp.storage:block-index-entry-height a)))
          do (setf b (bitcoin-lisp.storage:block-index-entry-prev-entry b)))
    ;; Walk both back until they meet
    (loop while (and a b (not (equalp (bitcoin-lisp.storage:block-index-entry-hash a)
                                      (bitcoin-lisp.storage:block-index-entry-hash b))))
          do (setf a (bitcoin-lisp.storage:block-index-entry-prev-entry a))
             (setf b (bitcoin-lisp.storage:block-index-entry-prev-entry b)))
    a))

(defun collect-chain-entries (tip-entry fork-entry)
  "Collect block-index-entries from TIP-ENTRY back to (not including) FORK-ENTRY."
  (let ((entries '())
        (entry tip-entry)
        (fork-hash (bitcoin-lisp.storage:block-index-entry-hash fork-entry)))
    (loop while (and entry
                     (not (equalp (bitcoin-lisp.storage:block-index-entry-hash entry)
                                  fork-hash)))
          do (push entry entries)
             (setf entry (bitcoin-lisp.storage:block-index-entry-prev-entry entry)))
    (nreverse entries)))

(defun %mempool-entry-invalid-after-reorg-p (mempool entry utxo-set eval-height
                                             chain-state mtp locktime-time
                                             csv-active)
  "Core's filter_final_and_mature predicate (validation.cpp:341-382), run
over a mempool entry after a reorg: T when the entry would be invalid in
the next block on the NEW chain and must be removed with its descendants —
no longer final, BIP68 sequence locks no longer satisfied, or spending a
now-immature coinbase. EVAL-HEIGHT is the next block's height (new tip +
1); MTP the new tip's median-time-past; LOCKTIME-TIME the BIP113 clock for
absolute locktimes (MTP once CSV is active, mirroring the acceptance path)."
  (let ((tx (bitcoin-lisp.mempool:mempool-entry-transaction entry)))
    (or
     ;; The transaction must still be final (Core CheckFinalTxAtTip:
     ;; next-block height + tip MTP, validation.cpp:347-348).
     (not (check-transaction-final tx eval-height locktime-time))
     ;; BIP68 re-tested against the new chain. Core re-tests cached
     ;; LockPoints and recalculates stale ones (TestLockPointValidity /
     ;; CalculateLockPointsAtTip, validation.cpp:350-366); we cache no
     ;; lockpoints, so always recalculate. In-mempool prevouts count as
     ;; confirming in the next block, like acceptance (mempool-extra-coins).
     (and csv-active
          (multiple-value-bind (extra ok)
              (mempool-extra-coins tx utxo-set mempool eval-height)
            (or (not ok)   ; an input no longer exists anywhere — invalid
                (not (check-sequence-locks tx utxo-set eval-height mtp
                                           chain-state :pending-utxos extra)))))
     ;; Coinbase spends must still be mature (validation.cpp:368-379):
     ;; skip inputs funded by other mempool txs (unconfirmed, never
     ;; coinbase); a confirmed coin must be COINBASE_MATURITY deep at the
     ;; next block. Core has a per-entry spends-coinbase flag and asserts
     ;; the coin exists; we scan the inputs and treat a missing coin as
     ;; invalid (defensive — the re-add path should have removed it).
     (block immature
       (bitcoin-lisp.serialization:dovector
           (input (bitcoin-lisp.serialization:transaction-inputs tx))
         (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
                (ptxid (bitcoin-lisp.serialization:outpoint-hash prevout))
                (pidx (bitcoin-lisp.serialization:outpoint-index prevout)))
           (unless (bitcoin-lisp.mempool:mempool-has mempool ptxid)
             (let ((utxo (bitcoin-lisp.storage:get-utxo utxo-set ptxid pidx)))
               (cond ((null utxo)
                      (return-from immature t))
                     ((and (bitcoin-lisp.storage:utxo-entry-coinbase utxo)
                           (< (- eval-height
                                 (bitcoin-lisp.storage:utxo-entry-height utxo))
                              +coinbase-maturity+))
                      (return-from immature t)))))))
       nil))))

(defun remove-reorged-nonfinal-mempool-entries (mempool utxo-set height chain-state)
  "Re-filter PRE-EXISTING mempool entries after a reorg — Core
CTxMemPool::removeForReorg (txmempool.cpp:360-386) driven by
filter_final_and_mature: entries that are non-final under the new tip, have
BIP68 locks the shorter/different chain no longer satisfies, or spend
now-immature coinbases are removed together with all their descendants.
The re-add loop only vets the txs coming BACK from disconnected blocks;
this pass covers what was already in the pool, whose validity the reorg may
have silently revoked. HEIGHT is the NEW tip height. Returns the number of
transactions removed."
  (let* ((eval-height (1+ height))
         (tip-hash (bitcoin-lisp.storage:best-block-hash chain-state))
         (mtp (or (compute-median-time-past chain-state tip-hash) 0))
         (csv-active (>= eval-height
                         (get-csv-activation-height bitcoin-lisp:*network*)))
         ;; BIP113: same clock the acceptance path uses (transaction.lisp).
         (locktime-time (if csv-active
                            mtp
                            (bitcoin-lisp.serialization:get-unix-time)))
         (flagged '()))
    ;; Flag first (Core collects to_remove over all of mapTx), remove after —
    ;; the entries table must not be mutated mid-iteration.
    (bitcoin-lisp.mempool:mempool-for-each
     mempool
     (lambda (txid entry)
       (when (%mempool-entry-invalid-after-reorg-p
              mempool entry utxo-set eval-height chain-state
              mtp locktime-time csv-active)
         (push txid flagged))))
    (let ((removed 0)
          (bitcoin-lisp.mempool:*mempool-removal-reason* :reorg))
      (dolist (txid flagged removed)
        ;; May be gone already as an earlier removal's descendant.
        (when (bitcoin-lisp.mempool:mempool-has mempool txid)
          (incf removed (bitcoin-lisp.mempool:mempool-remove-recursive
                         mempool txid)))))))

(defun readd-disconnected-txs-to-mempool (mempool txs utxo-set height chain-state)
  "Re-add TXS from reorg-disconnected blocks into the mempool, best-effort —
a port of Bitcoin Core's MaybeUpdateMempoolForReorg (validation.cpp:294-389).

TXS is earliest-confirmed first (Core iterates the disconnectpool in
reverse), so parents re-enter before their children. Each tx is re-validated
against the post-reorg chain state with BYPASS-LIMITS (fee floor and TRUC
topology skipped — it was already confirmed — while the RBF economics and
the per-cluster limits stay on, exactly Core's bypass_limits scope).
CHAIN-STATE — already at the NEW tip — keeps the finality/BIP68 checks on:
Core's bypass_limits does NOT skip CheckFinalTxAtTip /
CheckSequenceLocksAtTip (validation.cpp:819,886-889), so a disconnected tx
whose timelock the shorter chain no longer satisfies is dropped, not
re-pooled and re-mined. A tx that fails re-acceptance drags down any pool
transactions spending its outputs, which are now orphans (Core
removeRecursive on the not-re-accepted origin, validation.cpp:317-321).

Acceptance assumes a new entry has no in-mempool children — false for a
previously-confirmed tx whose outputs pre-existing pool entries spend — so
after the per-tx loop, MEMPOOL-UPDATE-FOR-REORG wires those parent->child
dependencies in bulk and restores the cluster limits with ONE trim (Core
UpdateTransactionsFromBlock, txmempool.cpp:91-120). Then the PRE-EXISTING
entries are re-filtered against the new tip (Core removeForReorg,
validation.cpp:384-385 — finality, BIP68, coinbase maturity; the ordering
is Core's MaybeUpdateMempoolForReorg exactly), and a final cap trim
re-limits the pool (Core LimitMempoolSize, validation.cpp:387). Runs even
with no TXS to re-add: the filter and trim concern the pool, not the
disconnected blocks."
  (when mempool
    (let ((readded '()))                ; txids, most-recently-confirmed first
      (dolist (tx txs)
        (let ((txid (bitcoin-lisp.serialization:transaction-hash tx)))
          (handler-case
              (multiple-value-bind (valid error fee replaced sigops)
                  (validate-transaction-for-mempool tx utxo-set mempool height
                                                    :bypass-limits t
                                                    :chain-state chain-state)
                (declare (ignore error))
                (when valid
                  (bitcoin-lisp.mempool:accept-validated-tx
                   mempool txid tx fee height
                   :sigops sigops :replaced replaced :defer-trim t)))
            (error () nil))
          ;; Presence decides the outcome (Core: else if m_mempool->exists,
          ;; validation.cpp:322): a tx that is in the pool now — re-accepted,
          ;; or already there — gets its child links wired below; one that
          ;; isn't drags down its in-pool spenders.
          (if (bitcoin-lisp.mempool:mempool-has mempool txid)
              (push txid readded)
              (bitcoin-lisp.mempool:mempool-remove-spenders
               mempool txid
               (length (bitcoin-lisp.serialization:transaction-outputs tx))))))
      (bitcoin-lisp.mempool:mempool-update-for-reorg mempool readded)
      (remove-reorged-nonfinal-mempool-entries mempool utxo-set height chain-state)
      (bitcoin-lisp.mempool:mempool-trim-to-size mempool))))

(defun %rollback-partial-reorg (chain-state block-store utxo-set
                                connected to-disconnect old-tip-entry)
  "Undo a partially-applied reorg after a fork block failed validation.

CONNECTED is the list of fork blocks already applied, each a
(entry block height spent-utxos), newest-first (the push order in
perform-reorg's connect loop). TO-DISCONNECT is the original chain's
entries tip-first (the blocks perform-reorg already removed from the
UTXO set). Restores the UTXO set, chain tip, and index-entry statuses
to exactly the OLD-TIP-ENTRY state, so a rejected fork leaves the node
on its original chain — never half-reorged.

Side effects (txindex / fee-estimator / mempool) are deferred to
perform-reorg's success phase, so there is nothing to undo here."
  ;; 1. Disconnect the fork blocks we applied, newest-first (reverse of the
  ;;    application order). spent-utxos is the undo data apply returned.
  (dolist (item connected)
    (destructuring-bind (entry block height spent-utxos) item
      ;; HEIGHT enables Core's per-output height comparison in the disconnect
      ;; (validation.cpp:2213-2219); it used to be discarded here.
      (bitcoin-lisp.storage:disconnect-block-from-utxo-set utxo-set block spent-utxos
                                                           :height height)
      (setf (bitcoin-lisp.storage:block-index-entry-status entry) :header-valid)))
  ;; 2. Re-apply the original chain, fork-first (to-disconnect is tip-first).
  ;;    These blocks were valid when first connected; their undo data is
  ;;    still on disk, so a forward apply restores the exact prior UTXO set.
  (dolist (entry (reverse to-disconnect))
    (let ((block (bitcoin-lisp.storage:get-block
                  block-store (bitcoin-lisp.storage:block-index-entry-hash entry))))
      (when block
        (bitcoin-lisp.storage:apply-block-to-utxo-set
         utxo-set block (bitcoin-lisp.storage:block-index-entry-height entry))
        (setf (bitcoin-lisp.storage:block-index-entry-status entry) :valid))))
  ;; 3. Restore the tip.
  (bitcoin-lisp.storage:update-chain-tip
   chain-state
   (bitcoin-lisp.storage:block-index-entry-hash old-tip-entry)
   (bitcoin-lisp.storage:block-index-entry-height old-tip-entry)))

;;;; ---------------------------------------------------------------------------
;;;; Deterministic-invalid classification (Core BLOCK_FAILED_VALID / _CHILD)
;;;;
;;;; When a FORK block fails validation during a reorg we mark it :invalid — and
;;;; BLOCK_FAILED_CHILD its whole descendant subtree — ONLY when the failure is a
;;;; DETERMINISTIC CONSENSUS verdict that a clean re-download can never change.
;;;; Poisoning a RECOVERABLE block would permanently wedge the node (a witness-
;;;; stripped or corrupt-on-disk body, re-fetched clean, would validate) — the
;;;; exact failure class this project has spent months fighting. So the rule is a
;;;; tight ALLOWLIST: anything not explicitly listed stays TRANSIENT and is never
;;;; poisoned (a too-narrow list merely degrades to the pre-item behavior of
;;;; retrying; a too-broad list re-wedges the node — so we err narrow).
;;;;
;;;; The allowlist is exactly the CONTEXTUAL consensus checks (Core
;;;; ContextualCheckBlock + ConnectBlock) that depend SOLELY on data the block
;;;; hash authenticates — txid-committed transaction bytes — plus the chain's own
;;;; structure (heights, the fork's UTXO set, MTP). Two properties make each safe:
;;;;   1. For a fork block these run for the FIRST time at reorg — it was stored
;;;;      after only CONTEXT-FREE / CheckBlock validation (see validate-block's
;;;;      :context-free-only path and protocol.lisp accept-downloaded-block), so a
;;;;      failure here is a genuine NEW verdict, not a re-run of a store-time check.
;;;;   2. Every input to the check is committed by the header / merkle root, so a
;;;;      clean re-download yields the byte-identical block and the identical
;;;;      failure — the block is permanently, deterministically invalid.
;;;;
;;;; DELIBERATELY EXCLUDED (kept TRANSIENT), each because it could fire on a
;;;; RECOVERABLE block:
;;;;   * Every CheckBlock / structural / header / merkle / weight / size / legacy-
;;;;     sigops failure (:bad-merkle-root, :bad-txns-duplicate, :no-transactions,
;;;;     :first-tx-not-coinbase, :multiple-coinbase, :block-too-heavy,
;;;;     :block-too-large, :bad-blk-sigops, the validate-transaction-structure
;;;;     keywords, every validate-block-header keyword, ...). A fork block ALREADY
;;;;     PASSED these when it was stored; failing one now means the on-disk bytes
;;;;     changed = corruption = a re-download fixes it. (:bad-merkle-root is also
;;;;     THE canonical corrupt-body signal.) get-block already prunes a body that
;;;;     fails to deserialize, so such a block surfaces as MISSING, not here.
;;;;   * Script failures (:script-failed), witness-commitment failures
;;;;     (:bad-witness-nonce-size, :bad-witness-merkle-match, :unexpected-witness)
;;;;     and the CONTEXTUAL sigop budget (:too-many-sigops). These consume WITNESS
;;;;     bytes, which the block hash does NOT commit; a corrupt-but-present witness
;;;;     (deserializes cleanly, passes merkle) would fail them yet re-download
;;;;     clean. Witness-STRIPPED bodies are self-healed before PHASE B, but
;;;;     corrupt-PRESENT witnesses are not — so every witness-dependent verdict
;;;;     stays transient. Cost: a fork invalid ONLY by a bad signature is
;;;;     soft-rejected (retry-best-reorg-candidate's bounded rejected-set) instead
;;;;     of poisoned — redundant work, never a wedge (== pre-item behavior).
;;;;   * The control keywords the reorg machinery itself returns
;;;;     (:corrupt-undo, :reorg-refused, :weaker-chain, :unknown-parent,
;;;;     :reorg-failed, :block-missing, :block-not-found, :interrupted) — all
;;;;     transient. :interrupted in particular is a statement about THIS NODE
;;;;     (it is stopping, phase 3b) and never about the block.

(defparameter *deterministic-invalid-block-errors*
  '(:duplicate-txid       ; BIP30: block re-creates a still-unspent txid
    :missing-input        ; spends an output absent from the fork's UTXO set
    :coinbase-not-mature  ; spends a coinbase before +coinbase-maturity+
    :insufficient-funds   ; a tx's outputs exceed its inputs
    :non-final-tx         ; IsFinalTx against the fork height / MTP
    :bad-sequence-lock    ; BIP68 relative locktime not satisfied
    :bad-coinbase-height  ; BIP34 coinbase-height prefix mismatch
    :coinbase-too-large)  ; coinbase pays more than subsidy + fees
  "Allowlist of VALIDATE-BLOCK error keywords that are DETERMINISTIC consensus
verdicts — decided purely from txid-committed data + chain structure, never from
witness bytes, and never a re-run of a CheckBlock test the block already passed
at store time. A fork block failing one of these is permanently invalid
regardless of any re-download, so it (and its descendants) may be marked
:invalid. Every other keyword is deliberately excluded — see the section comment
above for why each exclusion could otherwise poison a recoverable block.")

(defun %deterministic-consensus-failure-p (error)
  "T iff ERROR is a deterministic consensus verdict (member of
*deterministic-invalid-block-errors*) — i.e. safe to permanently mark the failing
block :invalid. Any other value — a transient control keyword, a corrupt-body /
witness-dependent failure, or an unrecognized keyword — returns NIL, defaulting
to the SAFE non-poisoning (recoverable) behavior."
  (and (keywordp error)
       (member error *deterministic-invalid-block-errors*)
       t))

(defun %mark-block-subtree-invalid (chain-state entry)
  "Mark ENTRY and every block-index entry descending from it :invalid — Core
BLOCK_FAILED_VALID on ENTRY plus BLOCK_FAILED_CHILD on the doomed subtree — so
the per-peer download walk aborts above it (ibd find-blocks-to-download-for-peer),
the deep-reorg candidate scan prunes it (%best-completable-reorg-target), and the
best-header / best-valid-tip scans skip it. Idempotent. block-index-descendants
includes ENTRY itself."
  (dolist (e (block-index-descendants chain-state entry))
    (setf (bitcoin-lisp.storage:block-index-entry-status e) :invalid)))

;;;; Cooperative shutdown inside a reorg (plan phase 3b).
;;;;
;;;; Core checks m_chainman.m_interrupt BETWEEN ActivateBestChainStep calls
;;;; (validation.cpp:3514), never inside a block, and never force-terminates its
;;;; validation thread. Ours had no such check, so a stop request arriving during
;;;; a deep reorg was answered only by stop-node's 600s deadline and its
;;;; bt:destroy-thread fallback — an interrupt at an arbitrary instruction.
;;;;
;;;; What makes stopping between blocks SAFE is phase 2: the coins carry their
;;;; own best-block pointer, moved by every apply/disconnect. So on a block
;;;; boundary the coins, their pointer, and (once the tip update below runs) the
;;;; in-memory chain tip all name the same block. We therefore TRUNCATE the reorg
;;;; there rather than rolling it back: rolling back is itself minutes of
;;;; interruptible work, while a truncated reorg is simply a shorter (or
;;;; partially advanced) valid chain that the next sync pass re-activates.
;;;;
;;;; The predicate is bitcoin-lisp:interrupt-requested-p (config.lisp states the
;;;; contract). It is true for BOTH meanings the node has for "stop": a real
;;;; shutdown, and call-with-sync-paused (assumeutxo snapshot activation, after
;;;; which the node keeps RUNNING). Covering the pause too is only safe because the
;;;; truncation moves the IN-MEMORY tip to the coins' block as well: checking a
;;;; flag without moving the tip would merely relocate the inconsistency from disk
;;;; into memory, where no startup check ever looks.

(defun perform-reorg (chain-state block-store utxo-set old-tip-entry new-tip-entry
                      &key tx-index fee-estimator recent-rejects mempool skip-scripts)
  "Perform a chain reorganization from OLD-TIP to NEW-TIP.
Disconnects blocks back to the fork point, then connects blocks on the new chain.

Each fork block is FULLY VALIDATED (scripts, merkle, coinbase value, finality,
BIP68 sequence locks) against the intermediate UTXO state as it is connected —
mirroring Bitcoin Core's ConnectTip. The chain tip is advanced incrementally so
sequence-lock / MTP lookups see the fork's active chain, not the old one. If any
fork block fails validation the reorg is rolled back to OLD-TIP and (VALUES NIL
ERROR) is returned, so a more-work fork carrying an invalid block can never enter
the UTXO set. (Before this, fork blocks were applied unvalidated — a consensus
hole: a more-work fork, cheap to mine on testnet4's min-difficulty rule, could
inject invalid blocks.) SKIP-SCRIPTS mirrors the IBD checkpoint optimization and
is threaded from the caller.

Optionally updates TX-INDEX if provided and enabled.
Optionally updates FEE-ESTIMATOR with block fee statistics.
Clears RECENT-REJECTS if provided (reorg may change transaction validity).
When MEMPOOL is provided, removes connected blocks' txs from it and re-adds the
disconnected blocks' txs (best-effort, re-validated against the new tip).
Side effects (tx-index / fee-estimator / mempool / recent-rejects) are applied
only after the whole fork validates, so a rolled-back reorg leaves them untouched.

A stop request (shutdown / sync pause) TRUNCATES the reorg at the next block
boundary and returns (VALUES NIL :INTERRUPTED): the chain is left on whatever
block the coins reached — never rolled back, never half-applied — and the side
effects below are committed for exactly the blocks that moved. See the section
comment above."
  (let ((fork-entry (find-fork-point old-tip-entry new-tip-entry)))
    (unless fork-entry
      (return-from perform-reorg nil))

    (let ((old-height (bitcoin-lisp.storage:block-index-entry-height old-tip-entry))
          (new-height (bitcoin-lisp.storage:block-index-entry-height new-tip-entry))
          (fork-height (bitcoin-lisp.storage:block-index-entry-height fork-entry)))

      ;; Check if reorg requires blocks that have been pruned
      (when (bitcoin-lisp:pruning-enabled-p)
        (let ((pruned-height (bitcoin-lisp.storage:chain-state-pruned-height chain-state)))
          (when (< fork-height pruned-height)
            (bitcoin-lisp:log-error
             "REORG IMPOSSIBLE: fork point ~D is below pruned height ~D. Node must re-sync."
             fork-height pruned-height)
            (return-from perform-reorg nil))))

      ;; Collect blocks to disconnect (old chain, tip to fork)
      (let ((to-disconnect (collect-chain-entries old-tip-entry fork-entry))
            ;; Collect blocks to connect (new chain, fork to new tip)
            (to-connect (collect-chain-entries new-tip-entry fork-entry))
            ;; Per-disconnected-block non-coinbase tx lists, re-added to the
            ;; mempool after the reorg. Pushed during the tip-first disconnect
            ;; loop, so the list ends up oldest-block-first — flattening then
            ;; re-adds parents before children (a child can only spend a parent
            ;; in an equal-or-lower block).
            ;; Each element is (TXS . BYTES) for one disconnected block.
            (disconnected-block-txs '())
            ;; Running size of the pool above, bounded by
            ;; +max-disconnected-tx-pool-bytes+ (see the trim in the loop).
            (disconnected-bytes 0)
            (disconnected-dropped 0)
            ;; (block . height) per disconnected block, oldest-first (same
            ;; push order), for the PHASE C wallet notifications.
            (disconnected-blocks '())
            ;; Cooperative-stop state (phase 3b). STOP-ENTRY is the PHASE A
            ;; entry the disconnect stopped BEFORE — i.e. the block the coins
            ;; are left at, and therefore where the tip must land. INTERRUPTED
            ;; covers both phases and turns the return value into
            ;; (VALUES NIL :INTERRUPTED).
            (stop-entry nil)
            (interrupted nil))

        ;; Self-heal stored witness-stripped forward blocks. A fork block stored
        ;; via the deferred-validation (:weaker-chain) path before the v2-only
        ;; compact-block fix could land on disk witness-stripped (legacy coinbase
        ;; carrying a witness commitment but no 32-byte reserved value). Such a
        ;; block can NEVER pass BIP141, so it would fail this reorg on every
        ;; attempt and wedge the node permanently (testnet4 stuck ~1800 blocks
        ;; behind). Prune it here so the missing-precondition below re-queues it
        ;; for a witness-complete re-download. Only the to-connect side is checked:
        ;; to-disconnect blocks already validated when they were connected, and we
        ;; still need their bodies for the UTXO disconnect.
        ;; Core's fFailedChain arm (FindMostWorkChain, validation.cpp:3170-3196):
        ;; a candidate tip is refused outright when ANY block on the path to it
        ;; carries BLOCK_FAILED_VALID. We read no status at all here, so a
        ;; branch containing a block the operator invalidated -- or one the
        ;; validator poisoned -- was a legitimate reorg target as long as it
        ;; carried more work.
        ;;
        ;; Checked BEFORE anything is mutated, so refusing costs nothing and
        ;; cannot leave the chainstate half-moved.
        (let ((failed (find-if (lambda (e)
                                 (eq (bitcoin-lisp.storage:block-index-entry-status e)
                                     :invalid))
                               to-connect)))
          (when failed
            (bitcoin-lisp:log-warn
             "REORG refused: block at height ~D on the target branch is marked invalid"
             (bitcoin-lisp.storage:block-index-entry-height failed))
            (return-from perform-reorg (values nil :invalid-branch))))

        (dolist (entry to-connect)
          (let* ((block-hash (bitcoin-lisp.storage:block-index-entry-hash entry))
                 (block (bitcoin-lisp.storage:get-block block-store block-hash)))
            (when (and block (block-witness-stripped-p block))
              (bitcoin-lisp:log-warn
               "REORG: stored block at height ~D is witness-stripped; pruning for witness-complete re-download"
               (bitcoin-lisp.storage:block-index-entry-height entry))
              ;; FORGET, not prune: a flat record cannot be deleted on its
              ;; own, and PRUNE-BLOCK refuses for one — which would leave
              ;; GET-BLOCK serving the same witness-stripped body to every
              ;; later retry of this reorg.
              (bitcoin-lisp.storage:forget-block-body block-store block-hash)
              ;; Header stays in the index; mark it needing a body so the normal
              ;; download path re-fetches it.
              (setf (bitcoin-lisp.storage:block-index-entry-status entry) :header-valid))))

        ;; Precondition: every block on BOTH sides must be in the
        ;; block-store. If anything is missing (including a stripped block just
        ;; pruned above), refuse the reorg without mutating any state — better to
        ;; defer than to leave the chain half-disconnected and corrupt. Return the
        ;; missing list so activate-block's caller can re-queue those blocks for
        ;; download instead of looping forever on the unprocessable incoming tip.
        (let ((missing '()))
          (dolist (entry (append to-disconnect to-connect))
            (let ((block-hash (bitcoin-lisp.storage:block-index-entry-hash entry)))
              (unless (bitcoin-lisp.storage:get-block block-store block-hash)
                (push (cons block-hash
                            (bitcoin-lisp.storage:block-index-entry-height entry))
                      missing))))
          (when missing
            (bitcoin-lisp:log-warn
             "REORG REFUSED: ~D blocks missing from store (first: height ~D)"
             (length missing) (cdr (first missing)))
            (return-from perform-reorg (values nil missing))))

        ;; Corrupt/missing undo on the DISCONNECT side. PHASE A disconnects each
        ;; old-chain block with (or undo '()) — an EMPTY undo for a SPENDING
        ;; block silently corrupts the UTXO set: it removes the outputs the
        ;; block created but never restores the coins it spent, surfacing later
        ;; as spurious MISSING-INPUT wedges or double-spend acceptance (this node
        ;; has a documented history of corrupt undo files). get-undo-data returns
        ;; nil for BOTH a corrupt/missing undo file AND a legitimate coinbase-only
        ;; block (empty undo), so require undo only for tx-count > 1, mirroring
        ;; %warn-if-undo-empty's exemption. Refuse with a DISTINCT keyword — NOT
        ;; the missing-block list, which would (wrongly) tell the caller to
        ;; re-download the to-CONNECT fork; a corrupt LOCAL disconnect-side undo
        ;; is not fixed by fetching fork blocks. Core aborts DisconnectBlock on
        ;; undo-read failure (DISCONNECT_FAILED) for the same reason.
        (dolist (entry to-disconnect)
          (let* ((block-hash (bitcoin-lisp.storage:block-index-entry-hash entry))
                 (block (bitcoin-lisp.storage:get-block block-store block-hash)))
            (when (and block
                       (> (length (bitcoin-lisp.serialization:bitcoin-block-transactions
                                   block))
                          1)
                       (null (get-undo-data block-hash)))
              (bitcoin-lisp:log-error
               "REORG REFUSED: corrupt/missing undo for spending block ~A at height ~D — refusing rather than corrupting the UTXO set"
               (bitcoin-lisp.crypto:bytes-to-hex block-hash)
               (bitcoin-lisp.storage:block-index-entry-height entry))
              (return-from perform-reorg (values nil :corrupt-undo)))))

        (bitcoin-lisp:log-warn "REORG: old tip height ~D -> fork at ~D -> new tip height ~D"
                               old-height fork-height new-height)

        ;; PHASE A — disconnect the old chain (UTXO only), tip-to-fork.
        ;; collect-chain-entries returns tip-first; iterate as-is. Order
        ;; matters across blocks: if A (lower) creates output O and B
        ;; (higher) spends O, disconnecting A first leaves O re-added by
        ;; B's undo data — see coin-view-disconnect-block for the analogous
        ;; within-block case. Side effects (txindex / mempool re-add /
        ;; recent-rejects) are deferred to PHASE C so a rolled-back reorg
        ;; leaves them untouched.
        (dolist (entry to-disconnect)
          ;; Cooperative stop (see the phase-3b section comment above). At the TOP
          ;; of this iteration the coins are exactly ENTRY's state, so the tip
          ;; update below lands on ENTRY instead of the fork point, and nothing
          ;; needs undoing.
          (when (bitcoin-lisp:interrupt-requested-p)
            (setf stop-entry entry
                  interrupted t)
            (return))
          (let* ((block-hash (bitcoin-lisp.storage:block-index-entry-hash entry))
                 (block (bitcoin-lisp.storage:get-block block-store block-hash)))
            (when block
              (let ((undo (get-undo-data block-hash)))
                (bitcoin-lisp.storage:disconnect-block-from-utxo-set
                 utxo-set block (or undo '())
                 :height (bitcoin-lisp.storage:block-index-entry-height entry)))
              ;; Core flushes IF_NEEDED at the end of DisconnectTip
              ;; (validation.cpp:2966). Safe HERE and not a line earlier:
              ;; disconnect-block-from-utxo-set sets the coins-view best-block
              ;; as its last act, so the pointer already names the block whose
              ;; coins are in the cache. Flushing between the two would persist
              ;; a cache and a pointer that disagree.
              (bitcoin-lisp:maybe-critical-flush chain-state)
              ;; Collect this block's non-coinbase txs (original order) for the
              ;; PHASE C mempool re-add. Pushing whole per-block lists during
              ;; the tip-first loop leaves disconnected-block-txs oldest-first.
              ;; Bound the pool at Core's MAX_DISCONNECTED_TX_POOL_BYTES
              ;; (20MB, kernel/disconnected_transactions.h:18). Unbounded, a
              ;; deep reorg over full blocks pins hundreds of MB right in the
              ;; middle of chainstate surgery — and this node has lived
              ;; through multi-hundred-block testnet4 reorgs.
              ;;
              ;; Direction matters: Core trims the MOST-RECENTLY-CONFIRMED
              ;; entries (LimitMemoryUsage pops the front, which holds the
              ;; blocks nearest the old tip) and re-adds from the oldest end,
              ;; so survivors are always PARENTS. Dropping the oldest instead
              ;; would strand children with missing inputs — they would fail
              ;; re-validation anyway, and we would have thrown away the
              ;; entries most likely to still be valid. Our list is
              ;; oldest-block-first with the tip block at the TAIL, so
              ;; "trim newest" means dropping from the tail.
              (when mempool
                (let* ((txs (rest (bitcoin-lisp.serialization:bitcoin-block-transactions block)))
                       ;; Serialized size stands in for Core's
                       ;; RecursiveDynamicUsage: same order of magnitude and
                       ;; monotone in the same thing, without walking every
                       ;; input/output allocation.
                       (bytes (let ((n 0))
                                (dolist (tx txs n)
                                  (incf n (bitcoin-lisp.serialization:transaction-weight tx))))))
                  (push (cons txs bytes) disconnected-block-txs)
                  (incf disconnected-bytes bytes)
                  (multiple-value-bind (kept left dropped)
                      (trim-disconnect-pool disconnected-block-txs disconnected-bytes)
                    (setf disconnected-block-txs kept
                          disconnected-bytes left)
                    (incf disconnected-dropped dropped))))
              (push (cons block (bitcoin-lisp.storage:block-index-entry-height entry))
                    disconnected-blocks)
              (setf (bitcoin-lisp.storage:block-index-entry-status entry) :header-valid))))

        ;; Tip is now logically at the fork point. Set it so each fork block's
        ;; validate-block sees the fork's active chain for sequence-lock / MTP
        ;; lookups (get-block-at-height walks back from the tip).
        ;;
        ;; If a stop request truncated the disconnect, land on STOP-ENTRY
        ;; instead: that is the block the coins stopped at, so this is what
        ;; makes the in-memory tip agree with them (and with the pointer the
        ;; next flush persists) before we return.
        (let ((landing (or stop-entry fork-entry)))
          (bitcoin-lisp.storage:update-chain-tip
           chain-state
           (bitcoin-lisp.storage:block-index-entry-hash landing)
           (bitcoin-lisp.storage:block-index-entry-height landing)))

        ;; PHASE B — validate + connect the fork, fork-to-tip, with rollback.
        ;; collect-chain-entries returns tip-first, so reverse to oldest-first:
        ;; each block must be validated/applied after its parent (so its inputs
        ;; exist), and the incremental tip must end at the new tip, not the
        ;; fork-side block.
        (let ((connected '())          ; (entry block height spent-utxos), newest-first
              (now (bitcoin-lisp.serialization:get-unix-time)))
          ;; A stop request already handled in PHASE A leaves nothing to connect:
          ;; the chain is parked on STOP-ENTRY and must not move further.
          (dolist (entry (if interrupted '() (reverse to-connect)))
            ;; Cooperative stop, as in PHASE A. Here the tip already advanced per
            ;; connected block (below), so this boundary needs no fixing up — and
            ;; no rollback (see the section comment).
            (when (bitcoin-lisp:interrupt-requested-p)
              (setf interrupted t)
              (return))
            (let* ((block-hash (bitcoin-lisp.storage:block-index-entry-hash entry))
                   (block (bitcoin-lisp.storage:get-block block-store block-hash))
                   (height (bitcoin-lisp.storage:block-index-entry-height entry)))
              ;; Full body validation against the intermediate UTXO + active
              ;; chain. The header was checked at receive time, but a
              ;; competing-fork block stored via the :weaker-chain path had its
              ;; body (scripts / merkle / coinbase value / finality / seqlocks)
              ;; UNvalidated — connecting it blindly was the consensus hole.
              ;; Re-run the ONE header rule an already-persisted index entry may
              ;; predate, since :skip-header t below will not. It must stay
              ;; exactly this rule: a fork body re-read from the store carries no
              ;; cached hash, so re-running PoW here would spuriously fail (see
              ;; VALIDATE-BLOCK's SKIP-HEADER docstring).
              (multiple-value-bind (valid error)
                  (if (header-time-too-old-p
                       (bitcoin-lisp.serialization:bitcoin-block-header block)
                       (bitcoin-lisp.storage:block-index-entry-prev-entry entry))
                      (values nil :time-too-old)
                      (validate-block block chain-state utxo-set height now
                                      ;; PER BLOCK, not the caller's single
                                      ;; verdict for the whole fork. PERFORM-REORG
                                      ;; takes SKIP-SCRIPTS as one keyword and
                                      ;; applied it to every block it connected,
                                      ;; which makes Core's ancestor condition
                                      ;; unenforceable for exactly the fork
                                      ;; blocks it exists to protect: a fork
                                      ;; block is by construction NOT an
                                      ;; ancestor of assumevalid. The incoming
                                      ;; SKIP-SCRIPTS can now only ever narrow
                                      ;; the skip, never widen it.
                                      :skip-scripts (and skip-scripts
                                                         (script-checks-skippable-p
                                                          chain-state block-hash height))
                                      ;; Header (PoW/difficulty/MTP/timewarp) was
                                      ;; validated at index admission — Core's
                                      ;; ConnectBlock doesn't re-check it.
                                      :skip-header t))
                (unless valid
                  (bitcoin-lisp:log-error
                   "REORG ABORTED at height ~D: fork block failed validation (~A). Rolling back to original chain."
                   height error)
                  ;; BLOCK_FAILED_VALID / _CHILD: only when this is a DETERMINISTIC
                  ;; consensus verdict (never a corrupt-body / witness-dependent /
                  ;; transient artifact — see %deterministic-consensus-failure-p),
                  ;; poison this fork block and its whole descendant subtree BEFORE
                  ;; the rollback, so the download walk aborts above it and the
                  ;; deep-reorg candidate scan prunes it — the doomed subtree is
                  ;; never re-requested or re-attempted. Marking before the rollback
                  ;; is safe: %rollback-partial-reorg only resets the CONNECTED
                  ;; ancestors (-> :header-valid) and the re-applied original chain
                  ;; (-> :valid); ENTRY (never connected, this is the first failure)
                  ;; and its descendants (all strictly above it, not yet processed)
                  ;; are in neither list, so the :invalid marks survive.
                  (when (%deterministic-consensus-failure-p error)
                    (%mark-block-subtree-invalid chain-state entry))
                  (%rollback-partial-reorg chain-state block-store utxo-set
                                           connected to-disconnect old-tip-entry)
                  (return-from perform-reorg (values nil error))))
              ;; Apply and advance the tip incrementally.
              (let ((spent-utxos (bitcoin-lisp.storage:apply-block-to-utxo-set
                                  utxo-set block height)))
                (%warn-if-undo-empty block block-hash height spent-utxos)
                (store-undo-data block-hash spent-utxos height :block block)
                (setf (bitcoin-lisp.storage:block-index-entry-status entry) :valid)
                (bitcoin-lisp.storage:update-chain-tip chain-state block-hash height)
                (push (list entry block height spent-utxos) connected))))
          ;; NOTE: deliberately NO maybe-critical-flush in this loop, unlike
          ;; PHASE A above, even though Core flushes IF_NEEDED at the end of
          ;; ConnectTip too (validation.cpp:3093).
          ;;
          ;; Core can, because a failed ConnectTip marks the block invalid and
          ;; the chain is disconnected properly; whatever it persisted is a real
          ;; chain state it can move away from. We instead rewind IN MEMORY
          ;; (%rollback-partial-reorg re-applies the original chain), so a flush
          ;; here would leave the coins DB naming a FORK-SIDE block that we then
          ;; reject, and a crash before the rollback is itself flushed would
          ;; roll forward onto the branch we refused.
          ;;
          ;; PHASE A has no such exposure: its flushes only ever land on blocks
          ;; between the old tip and the fork point, which are ancestors of both
          ;; chains, so rolling forward from one is always correct. It is also
          ;; the half that actually grows without bound -- the sharp path is a
          ;; deep rollback (dumptxoutset to an assumeutxo height,
          ;; invalidateblock on an old hash) disconnecting tens of thousands of
          ;; blocks in one loop.
          ;;
          ;; Closing the connect side needs the rollback to become a real
          ;; disconnect, as in Core, rather than an in-memory rewind.

          ;; PHASE C — commit side effects, only now the whole fork is valid
          ;; and applied. Oldest-to-newest for chain-order indexing.
          ;;
          ;; Blocks were disconnected: reset the recent-confirmed filter so
          ;; previously-confirmed txs returning to circulation can relay
          ;; again (Core BlockDisconnected -> RecentConfirmedTransactions
          ;; Filter().reset(), txdownloadman_impl.cpp:112-123). Deferred to
          ;; the commit phase alongside the other side effects: a rolled-back
          ;; reorg never disconnected anything observably.
          (reset-recent-confirmed)
          ;; Wallet chain-tracking (wallet P2): Core fires BlockDisconnected
          ;; per DisconnectTip — tip-first, before the fork's BlockConnected
          ;; signals. Deferred here with the other side effects, so a
          ;; rolled-back reorg never notified anything. disconnected-blocks
          ;; is oldest-first (PHASE A push order); reverse restores tip-first.
          (dolist (pair (reverse disconnected-blocks))
            (bitcoin-lisp:wallet-notify-block-disconnected
             chain-state (car pair) (cdr pair))
            ;; ZMQ BlockDisconnected: the block's transactions, then a
            ;; sequence 'D'. No hashblock/rawblock -- those announce the tip
            ;; moving FORWARD, and a subscriber that saw one for a block now
            ;; being undone learns that from the 'D' instead.
            (bitcoin-lisp:zmq-notify-block-disconnected
             (car pair) (bitcoin-lisp.serialization:block-header-hash
                         (bitcoin-lisp.serialization:bitcoin-block-header (car pair))))
            ;; txospenderindex: erase this block's spender entries. Deferred to
            ;; PHASE C with every other side effect, so an INTERRUPTED reorg —
            ;; which rolls back and leaves these blocks connected — never
            ;; erases entries for blocks that are still on the chain.
            (bitcoin-lisp:unindex-block-txospenders
             chain-state (car pair)
             (bitcoin-lisp.serialization:block-header-hash
              (bitcoin-lisp.serialization:bitcoin-block-header (car pair)))))
          (dolist (item (reverse connected))
            (destructuring-bind (entry block height spent-utxos) item
              (when fee-estimator
                (let ((stats (bitcoin-lisp.mempool:compute-block-fee-stats
                              block spent-utxos height)))
                  (when stats
                    (bitcoin-lisp.mempool:fee-estimator-add-stats fee-estimator stats))))
              ;; Index under the block-index ENTRY's hash — the block index is
              ;; the canonical identity (Core BaseIndex writes are keyed off
              ;; the CBlockIndex), and BLOCK here was re-read from disk so a
              ;; recomputed header hash is a fresh object, not the one the
              ;; connect path / index entries key by.
              (let ((hash (bitcoin-lisp.storage:block-index-entry-hash entry)))
                (when (and tx-index (bitcoin-lisp.storage:tx-index-enabled tx-index))
                  (bitcoin-lisp.storage:txindex-add-block tx-index block hash)
                  (bitcoin-lisp.storage:txindex-set-best-block tx-index hash))
                ;; BIP158: index the reconnected block's basic filter (oldest-to-
                ;; newest here, so its header chains off the already-indexed parent).
                (bitcoin-lisp:index-block-filter chain-state block hash height spent-utxos)
                ;; coinstatsindex: reconnected oldest-to-newest, so each block
                ;; loads its (already-reindexed) parent's running state.
                (bitcoin-lisp:index-block-coinstats chain-state block hash height spent-utxos)
                ;; txospenderindex: the erase for the disconnected side already
                ;; ran earlier in this phase, so these writes cannot be undone
                ;; by it.
                (bitcoin-lisp:index-block-txospenders chain-state block hash height))
              (when mempool
                (bitcoin-lisp.mempool:mempool-remove-for-block mempool block)
                (bitcoin-lisp.mempool:orphan-erase-for-block
                 (bitcoin-lisp.mempool:mempool-orphan-pool mempool) block))
              ;; Each reconnected block counts as connected for the tx-relay
              ;; tip structures; the LAST one leaves the map at the new tip.
              (note-block-connected block)
              ;; Wallet hook: the fork's blocks connect oldest-to-newest,
              ;; after that block's mempool conflict removals (Core order).
              (bitcoin-lisp:wallet-notify-block-connected
               chain-state block (bitcoin-lisp.storage:block-index-entry-hash entry)
               height)))
          ;; The disconnected old chain's txs stay in the tx-index: Core never
          ;; erases txindex entries on disconnect (index/base.h:136 CustomRemove
          ;; defaults to a no-op; index/txindex.cpp has no override). Txs
          ;; re-mined in the new chain were re-pointed by the connect-time
          ;; upserts above; stale-branch-only txs keep resolving through the
          ;; still-stored stale block (removing them here used to leave re-mined
          ;; txs UNINDEXED, since the old txindex-add skipped existing txids).
          ;; Reorg may change tx validity — clear both rejects caches.
          (bitcoin-lisp:clear-recent-rejects recent-rejects)
          (clear-reconsiderable-rejects)
          ;; Re-add disconnected-block txs (best-effort, against the new tip),
          ;; parents before children. Txs re-confirmed or invalidated by the
          ;; new chain are dropped by re-validation.
          (when (plusp disconnected-dropped)
            (bitcoin-lisp:log-warn "REORG: disconnect pool over ~D bytes — dropped ~D transaction~:P nearest the old tip; they will not be re-added to the mempool"
                                   +max-disconnected-tx-pool-bytes+
                                   disconnected-dropped))
          ;; Re-validate against the height the chain ACTUALLY reached: equal to
          ;; NEW-HEIGHT on the normal path, and the truncation point when a stop
          ;; request cut the reorg short.
          (let ((reached (bitcoin-lisp.storage:current-height chain-state)))
            (readd-disconnected-txs-to-mempool
             mempool (loop for entry in disconnected-block-txs append (car entry))
             utxo-set reached chain-state)

            (cond
              (interrupted
               ;; Not a failure: the blocks that moved are committed above, the
               ;; chain sits on a block boundary where coins, pointer and tip
               ;; agree, and the next sync pass re-attempts the rest. Callers must
               ;; treat :INTERRUPTED as transient — never as a verdict on the fork.
               (bitcoin-lisp:log-warn
                "REORG INTERRUPTED by a stop request after disconnecting ~D of ~D and connecting ~D of ~D; chain left at height ~D"
                (length disconnected-blocks) (length to-disconnect)
                (length connected) (length to-connect) reached)
               (values nil :interrupted))
              (t
               (bitcoin-lisp:log-info "REORG complete: disconnected ~D, connected ~D blocks"
                                      (length to-disconnect) (length to-connect))
               t))))))))

;;;; Chain-control helpers (invalidateblock / reconsiderblock)
;;;;
;;;; These power the manual invalidateblock/reconsiderblock RPCs. They mutate
;;;; block-index status and drive perform-reorg, and run ONLY when their RPC is
;;;; called — the normal sync path is untouched. invalidate-block installs no
;;;; chain-selection guard, so it won't fight a future stronger block extending
;;;; the invalidated branch; that's acceptable for the manual/regtest use these
;;;; RPCs target (Bitcoin Core's persistent BLOCK_FAILED_VALID is out of scope).

(defun block-descends-from-p (entry ancestor-entry)
  "True if ANCESTOR-ENTRY lies on ENTRY's ancestry (ENTRY is ANCESTOR-ENTRY or a
descendant of it).

Compares by HASH, not by object identity. It used to use EQ, which made the
answer depend on every entry for a block being the same object forever. That
held only by accident: connect-block used to REPLACE the index slot with a
freshly-built entry, so every header admitted before its body kept pointing at
the orphaned original and this returned NIL for exactly the header-only entries
above the connected tip — the ones invalidateblock and
%mark-block-subtree-invalid exist to cover. It never showed in a restart-based
test, because load-header-index rebuilds a consistent object graph by hash.

connect-block no longer replaces entries (GA9 S1-4), so the cause is gone; this
is the second half, so the invariant stops resting on identity at all. A hash
comparison is what the block index is keyed by anyway."
  (let ((found (bitcoin-lisp.storage:entry-ancestor-at-height
                entry (bitcoin-lisp.storage:block-index-entry-height ancestor-entry))))
    (and found
         (equalp (bitcoin-lisp.storage:block-index-entry-hash found)
                 (bitcoin-lisp.storage:block-index-entry-hash ancestor-entry)))))

(defun block-index-descendants (chain-state entry)
  "All block-index entries that descend from ENTRY, including ENTRY itself."
  (let ((result '()))
    (maphash (lambda (h e) (declare (ignore h))
               (when (block-descends-from-p e entry) (push e result)))
             (bitcoin-lisp.storage::chain-state-block-index chain-state))
    result))

(defun best-valid-tip (chain-state block-store &optional (min-work 0))
  "The highest-chain-work block-index entry that is not :invalid, carries MORE
than MIN-WORK, AND whose block is present in BLOCK-STORE — the target the active
chain can actually reorg to. The block-presence filter excludes header-only
entries (status :header-valid with no downloaded block), which on a live node
routinely outrank everything; without it best-valid-tip would name an
unreachable header and the reorg would no-op.

Test order matters for cost, not just correctness. BLOCK-EXISTS-P is a
filesystem probe, so testing it per entry is ~1M syscalls on a mainnet-sized
index — which is why this was previously only affordable from the
reconsiderblock RPC. Chain-work is an in-memory integer compare, so it goes
first, and MIN-WORK (the caller's current tip work) prunes the probe down to
the handful of entries that could actually beat the tip. On a synced node that
is zero probes."
  (let ((best nil)
        (best-work min-work))
    (maphash (lambda (h e) (declare (ignore h))
               (let ((w (bitcoin-lisp.storage:block-index-entry-chain-work e)))
                 (when (and (> w best-work)
                            (not (eq (bitcoin-lisp.storage:block-index-entry-status e) :invalid))
                            (bitcoin-lisp.storage:block-exists-p
                             block-store (bitcoin-lisp.storage:block-index-entry-hash e)))
                   (setf best e
                         best-work w))))
             (bitcoin-lisp.storage::chain-state-block-index chain-state))
    best))

(defconstant +activation-step-blocks+ 1000
  "How many blocks one ACTIVATE-BEST-CHAIN step will connect at most.

PERFORM-REORG's connect loop deliberately never flushes — a rollback here rewinds
IN MEMORY, so a flush mid-connect could leave the coins DB naming a fork-side
block we then reject (see the note in that loop). That reasoning is sound and
stays; what it means is that ONE call must never be asked to connect an
unbounded number of blocks, because nothing lands until it finishes.

Reindexing a real testnet4 datadir asked for 134,922 blocks in a single call:
97% CPU for sixteen minutes with no coin written and no step completed. Core
does not do this either — ActivateBestChain LOOPS, and each
ActivateBestChainStep connects a bounded batch and returns so the caller can
flush.")

(defun %activation-step-target (chain-state tip target)
  "TARGET, or its ancestor at most +ACTIVATION-STEP-BLOCKS+ above TIP.

Walking back from TARGET rather than forward from TIP because the index links
child -> parent: an entry knows its prev, not its next. The result is always on
TARGET's chain, so a step is a real move toward it and never sideways."
  (let* ((tip-height (if tip (bitcoin-lisp.storage:block-index-entry-height tip) 0))
         (target-height (bitcoin-lisp.storage:block-index-entry-height target))
         (want (+ tip-height +activation-step-blocks+)))
    (if (<= target-height want)
        target
        (let ((e target))
          (loop while (and e (> (bitcoin-lisp.storage:block-index-entry-height e) want))
                do (setf e (bitcoin-lisp.storage:block-index-entry-prev-entry e)))
          ;; A gap in prev-entry links (a pruned or partially-reindexed index)
          ;; leaves E nil; fall back to the full target rather than inventing a
          ;; step, and let PERFORM-REORG report what it cannot reach.
          (or e target)))))

(defun activate-best-chain (chain-state block-store utxo-set
                            &key tx-index fee-estimator recent-rejects mempool)
  "Reorganize onto the most-work fully-downloaded valid chain when it beats the
active tip. Returns (values switched-p missing-blocks), where MISSING-BLOCKS is
perform-reorg's re-queue list if a switch was refused for want of block bodies.

Bitcoin Core's ActivateBestChain (validation.cpp): it loops FindMostWorkChain
until the tip IS the most-work candidate, and it runs from ProcessNewBlock AND
from startup — not only on the arrival of a block.

We previously reorganized ONLY from CONNECT-BLOCK, i.e. only when a block
arrived whose chain-work beat the tip. A heavier chain whose blocks are ALREADY
on disk therefore sat unactivated indefinitely, because nothing re-evaluated
it: the arrival that would have triggered the switch had already happened and
been refused (missing bodies at the time), or happened before a restart.

Observed live 2026-08-19: testnet4 sat on tip 149110 for 40+ minutes while a
fully-downloaded 149120 branch with strictly more work lay on disk, and mainnet
showed five stale-tip episodes in a day that cleared only when some new block
happened to arrive and re-trigger the path.

The loop terminates: each successful switch moves the tip TO the maximum-work
candidate, so the next pass finds nothing above it. The iteration cap is a
backstop against a candidate that reorgs away and reappears."
  (let ((switched nil)
        (missing '()))
    (dotimes (i 4)
      (let* ((tip (bitcoin-lisp.storage:get-block-index-entry
                   chain-state (bitcoin-lisp.storage:best-block-hash chain-state)))
             (tip-work (if tip
                           (bitcoin-lisp.storage:block-index-entry-chain-work tip)
                           0))
             (best (best-valid-tip chain-state block-store tip-work))
             ;; Bounded step, not the absolute best tip: see
             ;; +ACTIVATION-STEP-BLOCKS+. On a synced node the best tip is
             ;; within the step and this is the identity.
             (target (and tip best (%activation-step-target chain-state tip best))))
        (when (or (null tip) (null target))
          (return))
        (multiple-value-bind (ok detail)
            (perform-reorg chain-state block-store utxo-set tip target
                           :tx-index tx-index :fee-estimator fee-estimator
                           :recent-rejects recent-rejects :mempool mempool)
          (cond
            (ok
             (setf switched t)
             ;; Flush BETWEEN steps (Core flushes PERIODIC from
             ;; ActivateBestChain, validation.cpp:3489). Not inside
             ;; PERFORM-REORG's connect loop — that is the flush its own note
             ;; correctly refuses, because a rollback there rewinds in memory.
             ;; Here the step has COMPLETED and is committed, so persisting it
             ;; is persisting a real chain state.
             ;;
             ;; Without this the coins cache grows across every step and never
             ;; drains: *blocks-since-flush* is advanced only by connect-block's
             ;; tip-extension arm, so reorg-connected blocks never trigger a
             ;; periodic flush at all — an unbounded cache on any long
             ;; activation, which is a correctness-of-resource problem whatever
             ;; it costs in time.
             ;;
             ;; It is worth NOT overselling the speed effect. A/B on the same
             ;; offline reindex: ~58,000 blocks in 25 min without it, ~56,000 in
             ;; 20 min with it — about 12% better, not the order of magnitude a
             ;; first reading of the per-step timings suggested. Most of the
             ;; slowdown with height is testnet4's own busy zone around
             ;; 51,000-55,000 (the region scripts/profile-regions.sh already
             ;; singles out), not this cache.
             (bitcoin-lisp:maybe-periodic-flush chain-state)
             ;; -stopatheight, for the same reason and at the same boundary.
             ;; MAYBE-STOP-AT-HEIGHT is called from CONNECT-BLOCK's
             ;; tip-EXTENSION arm only, so a chain activated through
             ;; PERFORM-REORG — which is every block of an offline reindex,
             ;; and every step of any long activation — sailed straight past
             ;; the configured height. Measured on the reindex benchmark:
             ;; -stopatheight=134000 ran on to 134,898, the header tip.
             ;;
             ;; Core checks here too: ActivateBestChain fires the blockTip
             ;; notification after each ActivateBestChainStep
             ;; (validation.cpp), and that notification is what
             ;; kernel_notifications.cpp:61-66 turns into the shutdown
             ;; request. Between steps, never inside the connect loop: the
             ;; step has completed and is committed, and PERFORM-REORG's own
             ;; interrupt check then unwinds the next one on a block boundary.
             (let ((new-tip (bitcoin-lisp.storage:get-block-index-entry
                             chain-state
                             (bitcoin-lisp.storage:best-block-hash chain-state))))
               (when new-tip
                 (bitcoin-lisp:maybe-stop-at-height
                  (bitcoin-lisp.storage:block-index-entry-height new-tip)))))
            (t
             ;; :interrupted means the node is stopping — not a refusal to
             ;; re-queue against.
             (unless (eq detail :interrupted)
               (setf missing detail))
             (return))))))
    (values switched missing)))

(defun invalidate-block (chain-state block-store utxo-set block-hash
                         &key tx-index fee-estimator recent-rejects mempool)
  "Mark BLOCK-HASH and all its descendants :invalid, reorganizing the active
chain back to BLOCK-HASH's parent if the active chain contained it. Returns
(values t nil) on success, (values nil reason-keyword) on failure."
  (let ((entry (bitcoin-lisp.storage:get-block-index-entry chain-state block-hash)))
    (cond
      ((null entry) (values nil :block-not-found))
      ((zerop (bitcoin-lisp.storage:block-index-entry-height entry))
       (values nil :cannot-invalidate-genesis))
      (t
       (let ((tip (bitcoin-lisp.storage:get-block-index-entry
                   chain-state (bitcoin-lisp.storage:best-block-hash chain-state)))
             (parent (bitcoin-lisp.storage:block-index-entry-prev-entry entry)))
         ;; If the active chain contains the invalidated block, reorg down to its
         ;; parent first. perform-reorg downgrades the disconnected blocks to
         ;; :header-valid, so we mark :invalid AFTER it, making invalidation stick.
         ;; Only mark invalid once the block is OFF the active chain — if the
         ;; reorg-away is refused (e.g. blocks pruned), marking the active tip's
         ;; ancestry :invalid would leave status flags disagreeing with the UTXO
         ;; set. (perform-reorg returns NIL on refusal.)
         (when (and tip parent (block-descends-from-p tip entry))
           (multiple-value-bind (ok detail)
               (perform-reorg chain-state block-store utxo-set tip parent
                              :tx-index tx-index :fee-estimator fee-estimator
                              :recent-rejects recent-rejects :mempool mempool)
             ;; Surface :interrupted as itself — the node is stopping, the reorg
             ;; did not fail — so the RPC reports why nothing was invalidated.
             (unless ok
               (return-from invalidate-block
                 (values nil (if (eq detail :interrupted) :interrupted :reorg-failed))))))
         (dolist (e (block-index-descendants chain-state entry))
           (setf (bitcoin-lisp.storage:block-index-entry-status e) :invalid))
         (values t nil))))))

(defun reconsider-block (chain-state block-store utxo-set block-hash
                         &key tx-index fee-estimator recent-rejects mempool)
  "Clear :invalid from BLOCK-HASH plus its ancestors and descendants, then
reorganize to the best valid chain if it now outweighs the active tip. Returns
(values t nil) on success, (values nil reason-keyword) on failure."
  (let ((entry (bitcoin-lisp.storage:get-block-index-entry chain-state block-hash)))
    (if (null entry)
        (values nil :block-not-found)
        (progn
          (maphash (lambda (h e) (declare (ignore h))
                     (when (and (eq (bitcoin-lisp.storage:block-index-entry-status e) :invalid)
                                (or (block-descends-from-p e entry)
                                    (block-descends-from-p entry e)))
                       (setf (bitcoin-lisp.storage:block-index-entry-status e) :header-valid)))
                   (bitcoin-lisp.storage::chain-state-block-index chain-state))
          (let ((tip (bitcoin-lisp.storage:get-block-index-entry
                      chain-state (bitcoin-lisp.storage:best-block-hash chain-state)))
                (target (best-valid-tip chain-state block-store)))
            (when (and target tip
                       (> (bitcoin-lisp.storage:block-index-entry-chain-work target)
                          (bitcoin-lisp.storage:block-index-entry-chain-work tip)))
              ;; perform-reorg now validates the reactivated chain and rolls
              ;; back (returning NIL) if one of its blocks is invalid — in which
              ;; case the chain correctly stays on TIP. Surface that rather than
              ;; reporting success for a switch that didn't happen.
              (multiple-value-bind (ok detail)
                  (perform-reorg chain-state block-store utxo-set tip target
                                 :tx-index tx-index :fee-estimator fee-estimator
                                 :recent-rejects recent-rejects :mempool mempool)
                (unless ok
                  (return-from reconsider-block
                    (values nil (if (eq detail :interrupted) :interrupted :reorg-failed)))))))
          (values t nil)))))

(defun precious-block (chain-state block-store utxo-set block-hash
                       &key tx-index fee-estimator recent-rejects mempool)
  "Treat BLOCK-HASH as preferred (Bitcoin Core preciousblock): if its chain has at
least as much work as the active tip and it isn't already the tip, reorganize to
it. Fork choice here is strict greater-than on chain-work, so an equal-work
competitor that arrives later cannot displace it — which is exactly what
preciousblock guarantees, with no persistent sequence-id needed (unlike Core's
candidate-set model). Returns (values t nil) on success (including the no-ops
where the block is already the tip or weaker), (values nil reason) on failure."
  (let ((entry (bitcoin-lisp.storage:get-block-index-entry chain-state block-hash)))
    (cond
      ((null entry) (values nil :block-not-found))
      (t
       (let ((tip (bitcoin-lisp.storage:get-block-index-entry
                   chain-state (bitcoin-lisp.storage:best-block-hash chain-state))))
         (cond
           ;; Already the tip, or weaker than it — nothing to do.
           ((or (null tip)
                (eq entry tip)
                (< (bitcoin-lisp.storage:block-index-entry-chain-work entry)
                   (bitcoin-lisp.storage:block-index-entry-chain-work tip)))
            (values t nil))
           ;; Can only reorg to a block whose data is present.
           ((not (bitcoin-lisp.storage:block-exists-p block-store block-hash))
            (values nil :block-missing))
           (t
            (multiple-value-bind (ok detail)
                (perform-reorg chain-state block-store utxo-set tip entry
                               :tx-index tx-index :fee-estimator fee-estimator
                               :recent-rejects recent-rejects :mempool mempool)
              (cond (ok (values t nil))
                    ((eq detail :interrupted) (values nil :interrupted))
                    (t (values nil :reorg-failed)))))))))))

;;;; Activate block — validate + connect with reorg awareness.
;;;;
;;;; The validate-then-connect dance in process-received-block does
;;;; validation against the current UTXO set, which is wrong when the
;;;; incoming block sits on a competing fork: its inputs reference
;;;; outputs that exist only on that fork. Validation fails MISSING-INPUT
;;;; before connect-block's chain-work comparison can dispatch to reorg.
;;;;
;;;; activate-block fixes the order: it looks at the incoming block's
;;;; parent and decides whether to extend the current tip, pre-reorg to
;;;; the parent's chain, or just store the block on a weaker side chain.
;;;; Mirrors Bitcoin Core's ActivateBestChainStep in validation.cpp,
;;;; particularly the disconnect/connect interaction before block
;;;; activation.

(defun %maybe-note-target-reached (chain-state)
  "When a targeted (historical) chainstate's tip lands exactly on its target
block, the assumeutxo background block download is complete (Core's
ReachedTarget break in ActivateBestChain, validation.cpp:3437). Hand off to
the node's snapshot-validation completion (Core MaybeValidateSnapshot at
ConnectTip, validation.cpp:3134-3135): it re-hashes the historical coins DB
against the chainparams commitment and, on a match, promotes the snapshot
chainstate. maybe-validate-snapshot re-checks every precondition and is a
no-op (:skipped) when they aren't met, so this stays safe for non-snapshot
chainstates and for tests that drive activate-block directly."
  (let ((target (bitcoin-lisp.storage:chain-state-target-blockhash chain-state)))
    (when (and target
               (equalp (bitcoin-lisp.storage:best-block-hash chain-state) target))
      (bitcoin-lisp:maybe-validate-snapshot chain-state))))

(defun activate-block (block chain-state block-store utxo-set
                       &key current-time skip-scripts tx-index fee-estimator
                            recent-rejects mempool)
  "Validate and activate BLOCK. Three cases:

  1. BLOCK's parent IS the current best tip — validate then connect
     (normal chain extension).
  2. BLOCK's parent is in the index but on a competing fork that, with
     this block added, has strictly more chain-work than our current
     best — pre-reorg to the parent's chain, then validate + connect.
     This is the case the old validate-then-connect order fumbled.
  3. BLOCK's parent is on a weaker chain or unknown — store the block
     for later use without activating it.

Returns (VALUES T NIL) on activation,
        (VALUES NIL ERROR-KEYWORD) on validation failure or
        non-activation. The :weaker-chain return is informational —
        the block was stored safely, just not made active.

A targeted (historical) chainstate — one with a target-blockhash, i.e. an
assumeutxo background-validation chainstate re-deriving history up to the
snapshot base — only ever connects blocks on the exact ancestor path of its
target (Core TryAddBlockIndexCandidate, validation.cpp:3764-3794). Anything
off that path (a sibling fork, or any block past the target) is stored for
the block store's benefit but never activated, so the historical chainstate
can neither wedge on an equal-work sibling nor advance past the base."
  (let* ((header (bitcoin-lisp.serialization:bitcoin-block-header block))
         (prev-hash (bitcoin-lisp.serialization:block-header-prev-block header))
         (current-best-hash (bitcoin-lisp.storage:best-block-hash chain-state))
         (now (or current-time (bitcoin-lisp.serialization:get-unix-time))))
    ;; Historical-chainstate target filter. Runs before any dispatch so no
    ;; branch (extend / pre-reorg) can move the chain off the target path.
    (when (bitcoin-lisp.storage:chain-state-target-blockhash chain-state)
      (let* ((hash (bitcoin-lisp.serialization:block-header-hash header))
             (entry (bitcoin-lisp.storage:get-block-index-entry chain-state hash)))
        (unless (and entry
                     (bitcoin-lisp.storage:entry-target-ancestor-p chain-state entry))
          (unless (block-witness-stripped-p block)
            (bitcoin-lisp.storage::%record-block-position
             entry
             (nth-value 1 (bitcoin-lisp.storage:store-block
                           block-store block
                           ;; NIL when the header is not indexed yet, which
                           ;; leaves the file unprunable rather than guessing.
                           :height (and entry
                                        (bitcoin-lisp.storage:block-index-entry-height
                                         entry))))))
          (return-from activate-block (values nil :weaker-chain)))))
    (cond
      ;; Case 1: extends current tip — normal path.
      ((equalp prev-hash current-best-hash)
       (let ((height (1+ (bitcoin-lisp.storage:current-height chain-state))))
         (multiple-value-bind (valid error)
             (validate-block block chain-state utxo-set height now
                             :skip-scripts skip-scripts)
           (if valid
               (progn
                 (connect-block block chain-state block-store utxo-set
                                :tx-index tx-index
                                :fee-estimator fee-estimator
                                :recent-rejects recent-rejects
                                :mempool mempool)
                 (%maybe-note-target-reached chain-state)
                 (values t nil))
               (values nil error)))))

      (t
       ;; Cases 2 and 3: prev != current best.
       (let* ((prev-entry (bitcoin-lisp.storage:get-block-index-entry
                           chain-state prev-hash))
              (current-best-entry (bitcoin-lisp.storage:get-block-index-entry
                                   chain-state current-best-hash))
              (this-bits (bitcoin-lisp.serialization:block-header-bits header))
              (prev-work (and prev-entry
                              (bitcoin-lisp.storage:block-index-entry-chain-work
                               prev-entry)))
              (new-chain-work (and prev-work
                                   (bitcoin-lisp.storage:calculate-chain-work
                                    this-bits prev-work)))
              (current-best-work (and current-best-entry
                                      (bitcoin-lisp.storage:block-index-entry-chain-work
                                       current-best-entry))))
         (cond
           ;; Parent unknown — caller should queue and request its parent.
           ((null prev-entry)
            (values nil :unknown-parent))

           ;; Case 2: competing fork with strictly more work — pre-reorg.
           ;;
           ;; perform-reorg disconnects our chain back to the common
           ;; ancestor and connects the fork up to (but not including)
           ;; the incoming block. After it returns T, chain-state's tip
           ;; equals prev-entry and the UTXO set reflects that fork's
           ;; state — so validate-block now sees the correct inputs.
           ((and new-chain-work
                 current-best-work
                 (> new-chain-work current-best-work))
            (multiple-value-bind (reorg-ok detail)
                (perform-reorg chain-state block-store utxo-set
                               current-best-entry prev-entry
                               :tx-index tx-index
                               :fee-estimator fee-estimator
                               :recent-rejects recent-rejects
                               :mempool mempool
                               :skip-scripts skip-scripts)
              (cond
                ;; perform-reorg refused with a keyword DETAIL: either a fork
                ;; block failed validation (chain rolled back to the original
                ;; tip), or a pre-mutation refusal (:corrupt-undo — our own
                ;; disconnect-side undo is missing/corrupt, nothing mutated).
                ;; Either way don't re-queue: the fork is invalid or the fault
                ;; is local, not an incomplete download.
                ((and (null reorg-ok) (keywordp detail))
                 (values nil detail))
                ;; Reorg refused for missing fork blocks. chain-state and
                ;; utxo-set are unchanged. DETAIL is the list of missing
                ;; (hash . height) — pass it up so process-received-block
                ;; re-queues them. Without this, perform-reorg refuses on the
                ;; same missing block forever and the tip is retried endlessly.
                ((and (null reorg-ok) detail)
                 (values nil :reorg-refused detail))
                ;; Refused for another reason (no common ancestor, fork below
                ;; pruned height). State unchanged.
                ((null reorg-ok)
                 (values nil :reorg-refused))
                (t
                 (let ((new-height (1+ (bitcoin-lisp.storage:current-height
                                        chain-state))))
                   (multiple-value-bind (valid error)
                       (validate-block block chain-state utxo-set new-height now
                                       :skip-scripts skip-scripts)
                     (if valid
                         (progn
                           (connect-block block chain-state block-store utxo-set
                                          :tx-index tx-index
                                          :fee-estimator fee-estimator
                                          :recent-rejects recent-rejects
                                          :mempool mempool)
                           (%maybe-note-target-reached chain-state)
                           (values t nil))
                         (progn
                           ;; The incoming block that justified this reorg (its
                           ;; extra work made the fork win) is itself invalid.
                           ;; The fork up to prev-entry is valid, but without
                           ;; the incoming block it may be weaker than where we
                           ;; started — so reorg BACK to the original chain
                           ;; rather than sit on a possibly-weaker fork (Core
                           ;; rejects the block and keeps the most-work valid
                           ;; chain).
                           (bitcoin-lisp:log-error
                            "Incoming block failed validation after reorg (~A); reverting to original chain"
                            error)
                           ;; BLOCK_FAILED_VALID / _CHILD: only on a DETERMINISTIC
                           ;; consensus verdict (never a corrupt-body / witness-
                           ;; dependent / transient artifact), poison the incoming
                           ;; block and any indexed descendants so it is never
                           ;; re-activated or extended. The revert below cannot
                           ;; clobber this: the incoming block was never connected,
                           ;; and it sits above the reverted fork on neither reorg
                           ;; side.
                           (when (%deterministic-consensus-failure-p error)
                             (let ((this-entry
                                     (bitcoin-lisp.storage:get-block-index-entry
                                      chain-state
                                      (bitcoin-lisp.serialization:block-header-hash
                                       header))))
                               (when this-entry
                                 (%mark-block-subtree-invalid chain-state this-entry))))
                           (let ((fork-tip (bitcoin-lisp.storage:get-block-index-entry
                                            chain-state
                                            (bitcoin-lisp.storage:best-block-hash
                                             chain-state))))
                             (multiple-value-bind (reverted revert-detail)
                                 (perform-reorg chain-state block-store utxo-set
                                                fork-tip current-best-entry
                                                :tx-index tx-index
                                                :fee-estimator fee-estimator
                                                :recent-rejects recent-rejects
                                                :mempool mempool
                                                :skip-scripts skip-scripts)
                               (cond
                                 (reverted)
                                 ;; A stop request truncated the revert. Not a
                                 ;; failure — the chain is on a consistent
                                 ;; boundary — so don't log it as one.
                                 ((eq revert-detail :interrupted)
                                  (bitcoin-lisp:log-warn
                                   "Revert to original chain truncated by a stop request; chain left at height ~D"
                                   (bitcoin-lisp.storage:current-height chain-state)))
                                 (t
                                  (bitcoin-lisp:log-error
                                   "Failed to revert to original chain after rejecting post-reorg block")))))
                           (values nil error)))))))))

           ;; Case 3: weaker / equal chain — store the block, don't
           ;; activate. Bitcoin Core does the same: blocks on weaker
           ;; tips sit in the block-store until their chain catches up.
           ;; NEVER persist a witness-stripped block: it would sit on disk
           ;; and fail every later reorg that needs it (the original testnet4
           ;; wedge). Drop it; a witness-complete copy is re-fetched. Mirrors
           ;; the target-filter guard above (block.lisp ~2428).
           (t
            (unless (block-witness-stripped-p block)
              (let ((entry (bitcoin-lisp.storage:get-block-index-entry
                            chain-state
                            (bitcoin-lisp.serialization:block-header-hash header))))
                (bitcoin-lisp.storage::%record-block-position
                 entry
                 (nth-value 1 (bitcoin-lisp.storage:store-block
                               block-store block
                               :height (and entry
                                            (bitcoin-lisp.storage:block-index-entry-height
                                             entry)))))))
            (values nil :weaker-chain))))))))
