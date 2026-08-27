(in-package #:bitcoin-lisp)

;;; Configuration
;;;
;;; Global configuration variables and constants that are referenced
;;; across multiple subsystems. Loaded early so that storage, validation,
;;; and networking modules can reference these symbols at compile time.

;;;; Interrupt signalling — THE contract statement for the cooperative-stop
;;;; seam. Other files point here rather than restating it.
;;;;
;;;; The one thing every long-running loop needs to know: has the node been
;;;; asked to stop? Core keeps that BELOW validation — util::SignalInterrupt,
;;;; handed to ChainstateManager by reference (validation.h:1034) — so
;;;; validation never calls up into networking to ask. This variable is the same
;;;; seam, and it lives in the earliest-loaded file for the same reason.

(defvar *interrupt-check* (constantly nil)
  "Predicate of no arguments: T once the node has been asked to stop.

Installed once, by node.lisp (%node-interrupt-requested-p) — the only file that
sees both flags that mean stop: *shutdown-request*, set the moment SIGTERM
arrives, and networking's *ibd-stop-requested*, set later by stop-node and also
by call-with-sync-paused for the assumeutxo pause, after which the node keeps
RUNNING. Consumers that must distinguish those two meanings have to say so
(perform-reorg does, in its phase-3b section comment).

Stays (CONSTANTLY NIL) in an image that never starts a node, so lower layers
never depend upward; tests bind it to interrupt a loop at a chosen point.")

(defun interrupt-requested-p ()
  "T when the node has been asked to stop. Polled at loop boundaries by work
that must give up cooperatively — perform-reorg between blocks,
load-mempool-from-disk between transactions. See *interrupt-check*."
  (funcall *interrupt-check*))

;;;; Block Pruning Configuration

(defconstant +min-blocks-to-keep+ 288
  "Minimum number of recent blocks to keep on disk (matches Bitcoin Core).")

(defconstant +min-disk-space-for-block-files+ (* 550 1024 1024)
  "Floor for the effective automatic-prune target in bytes (Bitcoin Core
MIN_DISK_SPACE_FOR_BLOCK_FILES, validation.h:87). The per-chainstate halving
while an assumeutxo historical chainstate exists never pushes the target
below this.")

(defvar *prune-target-mib* nil
  "Block pruning target in MiB.
NIL = pruning disabled (default).
1 = manual-only mode (pruneblockchain RPC works, no automatic pruning).
>= 550 = automatic pruning to this target size.
Any other value signals an error at startup.")

(defvar *prune-after-height* nil
  "Minimum chain height before pruning can begin.
Set automatically based on network: 100000 for mainnet, 1000 for testnet.")

(defun pruning-enabled-p ()
  "Return T if pruning is enabled (any mode)."
  (and *prune-target-mib* (> *prune-target-mib* 0)))

(defun automatic-pruning-p ()
  "Return T if automatic pruning is enabled (not manual-only)."
  (and *prune-target-mib* (>= *prune-target-mib* 550)))

(defun prune-after-height (network)
  "Return the minimum chain height before pruning begins for NETWORK."
  (bl.chain:chain-params-prune-after-height (bl.chain:find-chain-params network)))

(defvar *minimum-chain-work-override* nil
  "When non-NIL, overrides the per-network nMinimumChainWork. Set by
-minimumchainwork (Core init.cpp:512, chainstatemanager_args.cpp:32-38) and
by tests (the real per-network floors are ~10^25 work, unreachable by
synthetic chains).")

(defvar *assumevalid-override* :unset
  "When not :UNSET, overrides the per-network defaultAssumeValid block hash: a
32-byte WIRE-order hash forces that assumevalid point, or NIL disables the
assumevalid script-skip entirely. :UNSET (the default) uses the built-in
per-network value. For tests, and for operators who want to disable assumevalid.")

;;;; Assumeutxo snapshot commitments
;;;;
;;;; Bitcoin Core's m_assumeutxo_data (kernel/chainparams.cpp:166-191,
;;;; 287-300, 400-413, 521-534, 646-667 @ d3056bc): the trusted UTXO-set
;;;; snapshot heights shipped with the release. loadtxoutset only accepts
;;;; a snapshot whose base block appears here AND whose hash_serialized_3
;;;; content hash matches — same trust model as assumevalid.

(defstruct assumeutxo-data
  "One trusted UTXO-snapshot commitment (Bitcoin Core AssumeutxoData,
kernel/chainparams.h:60-75)."
  (height 0 :type (unsigned-byte 32))
  ;; Base block hash, 32 bytes WIRE order (the block-index key form).
  (blockhash nil :type (or null (simple-array (unsigned-byte 8) (32))))
  ;; hash_serialized_3 over the full UTXO set at HEIGHT, 32 bytes in
  ;; internal digest order (compute-utxo-set-hash's return form).
  (hash-serialized nil :type (or null (simple-array (unsigned-byte 8) (32))))
  ;; Number of transactions in the chain up to and including the base
  ;; block (Core AssumeutxoData::m_chain_tx_count).
  (chain-tx-count 0 :type (unsigned-byte 64)))

(defvar *assumeutxo-data-override* nil
  "When non-NIL, a list of assumeutxo-data entries consulted INSTEAD of the
built-in per-network table. Core's regtest-entries pattern for tests: dump a
synthetic chain's UTXO set, inject its real base hash + hash_serialized_3
here, and load it back through the full verification gate.")

(defun %assumeutxo-entry (height blockhash-hex hash-serialized-hex chain-tx-count)
  "Build an assumeutxo-data from Core's display-order (uint256 GetHex) hex
strings, reversing both to our internal byte orders."
  (make-assumeutxo-data
   :height height
   :blockhash (reverse (bl.crypto:hex-to-bytes blockhash-hex))
   :hash-serialized (reverse (bl.crypto:hex-to-bytes hash-serialized-hex))
   :chain-tx-count chain-tx-count))

(defun network-assumeutxo-data (network)
  "NETWORK's assumeutxo-data entries, newest last (chain-params-assumeutxo,
values mirroring Bitcoin Core kernel/chainparams.cpp). *assumeutxo-data-override*
(when non-NIL) takes precedence over the built-in table."
  (or *assumeutxo-data-override*
      (mapcar (lambda (entry) (apply #'%assumeutxo-entry entry))
              (bl.chain:chain-params-assumeutxo (bl.chain:find-chain-params network)))))

(defun assumeutxo-data-for-blockhash (network blockhash)
  "The assumeutxo-data entry whose base block is BLOCKHASH (32-byte wire
order), or NIL (Core AssumeutxoForBlockhash, kernel/chainparams.cpp:727)."
  (find blockhash (network-assumeutxo-data network)
        :key #'assumeutxo-data-blockhash :test #'equalp))

(defvar *p2p-port-override* nil
  "When non-NIL, the P2P LISTEN port (Core -port, init.cpp:575): the inbound
listener binds here, the onion target listener at port+1 (Core init.cpp:2118),
and -externalip advertisements carry it (Core GetListenPort, net.cpp:138-162).
The DEFAULT port used to dial peers is unaffected — Core dials
chainparams GetDefaultPort regardless of -port.")

(defvar *stop-at-height* 0
  "Stop the node once the active tip reaches this height; 0 = disabled (Core
-stopatheight, DEFAULT_STOPATHEIGHT = 0, node/kernel_notifications.cpp:61-66:
the blockTip notification requests shutdown when nHeight >= m_stop_at_height).")

(defvar *force-dns-seed* nil
  "-forcednsseed (Core DEFAULT_FORCEDNSSEED = false, net.h:97): query the DNS
seeds even when the address book already has enough candidates. Here rather
than in node.lisp, which reads it, because APPLY-CONFIG-GLOBALS sets it and
config.lisp compiles first — the same reason *dns-seed-enabled* is here.")

(defvar *dns-seed-enabled* t
  "Query DNS seeds for peer addresses when the address book is low (Core
-dnsseed, DEFAULT_DNSSEED = true, net.h:96).")

(defvar *fixed-seeds-enabled* t
  "Allow the hardcoded fixed-seed fallback when DNS/addrman leave the
candidate pool thin (Core -fixedseeds, DEFAULT_FIXEDSEEDS = true, net.h:97).")

(defvar *parallel-block-validation* nil
  "When NIL (default), block-script validation runs single-threaded. -par=N>1
turns it on; -par=1 turns it off, as Core's does.

STILL DEFAULT-OFF, and the reason is worth stating precisely because ONE of the
two known hazards has since been removed and the other has not.

Removed (2026-08-22): the workers used to call COLLECT-SPENT-UTXOS themselves,
and that read path INSERTS ON MISS into the coins-view cache — a plain,
non-:synchronized SBCL hash table. Concurrent read-through inserts corrupt it.
PREFETCH-BLOCK-SPENT-COINS now resolves every spent coin on the validation
thread before any worker starts, so the workers receive pure data and never
touch the coins view. That is Core's shape: ConnectBlock copies each spent Coin
into its CScriptCheck before queuing it.

NOT removed: the production crash this flag was turned off for was diagnosed as
concurrent libsecp CFFI calls corrupting SBCL's global alien-type cache
(SB-ALIEN::RECORD-TYPE=, an EQ hash-table mutated under a system lock), which
then faulted during an unrelated alien op — the sync thread's socket-connect —
and spiralled into \"maximum interrupt nesting depth exceeded\". testnet4's
small blocks never crossed the threshold (3h+ stable); mainnet crashed at tip
within minutes. Nothing here addresses that, and the two diagnoses are not the
same bug: the coins-view race explains corruption, the alien-cache one explains
where the fault surfaced.

So: the coins-view hazard is gone, the alien-cache one is unproven either way,
and the honest next step is a testnet4 soak followed by a mainnet one — not
flipping this default on the strength of a fix to the other problem.

IBD was network/disk-bound (sig checks were never the top profile frames), so
the speed cost of leaving it off is small.")

(defun network-assumevalid (network)
  "NETWORK's defaultAssumeValid block hash in WIRE byte order, or NIL when
assumevalid is disabled. *ASSUMEVALID-OVERRIDE* takes precedence when set.

Lives here rather than in the networking layer because the VALIDATION layer is
what has to consult it -- Core's fScriptChecks is a pure function of assumevalid
(validation.cpp:2342-2380) and is evaluated per block during connect, and
src/networking/ibd.lisp loads after src/validation/."
  (if (not (eq *assumevalid-override* :unset))
      *assumevalid-override*
      (let ((display (bl.chain:chain-params-assumevalid-hex (bl.chain:find-chain-params network))))
        (when display
          (reverse (bl.crypto:hex-to-bytes display))))))

(defun minimum-chain-work (network)
  "Return NETWORK's nMinimumChainWork — the anti-DoS work floor below which a
header chain is refused admission to the block index (Bitcoin Core
consensus.nMinimumChainWork, kernel/chainparams.cpp). Values mirror Core
exactly. 0 disables the gate (regtest / custom signet). A node already past
this floor rejects any header whose chain would fall below it, blocking a peer
from bloating the index with a long low-work fork; a node still below it (fresh
genesis sync) accepts headers normally until it crosses the floor."
  (or *minimum-chain-work-override*
      (bl.chain:chain-params-minimum-chain-work (bl.chain:find-chain-params network))))

(defvar *blocksonly* nil
  "Core -blocksonly (DEFAULT_BLOCKSONLY = false, init.cpp:501): when T,
reject transactions from network peers on ANY network — version messages
carry fRelay=0, peers announcing or sending txs anyway are disconnected, no
feefilter is sent, and getnetworkinfo reports localrelay=false. Local
submissions still work and are still announced (sendrawtransaction relays,
per Core BroadcastTransaction), and block relay is unaffected. See
networking's IGNORE-INCOMING-TXS-P. Set by start-node's :blocksonly keyword.")

(defvar *wallet-max-tx-fee* 10000000
  "Maximum ABSOLUTE fee, in satoshis, a wallet-built (or wallet-resubmitted)
transaction may pay (Bitcoin Core -maxtxfee, DEFAULT_TRANSACTION_MAXFEE =
COIN/10 = 0.1 BTC, wallet.h:137). A transaction exceeding it is never built
and never broadcast — funds-safety rail, wallet P4.")

(defvar *wallet-fallback-fee* 0
  "Fee rate in sat/kvB the wallet falls back to when fee estimation has no
data (Bitcoin Core -fallbackfee, DEFAULT_FALLBACK_FEE = 0, wallet.h:106).
0 disables the fallback: fee estimation failure is then an error, exactly
Core's m_allow_fallback_fee = (fallback fee != 0) gate (wallet.cpp:3013).")

(defvar *accept-datacarrier* t
  "Mempool policy: accept OP_RETURN data-carrier outputs (Bitcoin Core
-datacarrier, default true). When NIL the shared *MAX-DATACARRIER-BYTES*
budget is treated as ZERO (Core mempool_args.cpp:95-98: max_datacarrier_bytes
= nullopt -> value_or(0)), so any transaction with an OP_RETURN output is
rejected \"datacarrier\"; the output's NULL_DATA classification itself is
unchanged.")

(defvar *max-datacarrier-bytes* 100000
  "Mempool policy: the SHARED byte budget for OP_RETURN (data-carrier)
outputs across a whole transaction (Bitcoin Core -datacarriersize). Every
NULL_DATA output's raw scriptPubKey size — OP_RETURN byte + push opcodes +
data — draws from the one budget, so multiple OP_RETURN outputs are standard
as long as their total fits (Core IsStandardTx tracks datacarrier_bytes_left
over all outputs, policy.cpp:136-150; the old per-output 83-byte cap and the
one-OP_RETURN-per-tx rule are gone since the 2025 relaxation). Default
MAX_OP_RETURN_RELAY = MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR =
100,000 (policy.h:81-83). Consensus is unaffected; this only gates mempool
standardness.")

(defvar *peer-block-filters* nil
  "When true (and the block filter index is enabled), serve BIP157 compact
filter messages (getcfilters/getcfheaders/getcfcheckpt) and advertise
NODE_COMPACT_FILTERS (Bitcoin Core -peerblockfilters, default false).")

(defvar *tx-reconciliation* nil
  "When true, negotiate BIP330 transaction reconciliation (Erlay) support via
the sendtxrcncl handshake (Bitcoin Core -txreconciliation, DEBUG_ONLY, default
false — net_processing.h:41, init.cpp:574). At Core ref d3056bc only the
handshake + per-peer salt storage exist (no sketch exchange); we match that.")

(defvar *permit-bare-multisig* t
  "Mempool policy: treat bare (non-P2SH) multisig outputs as standard
(Bitcoin Core -permitbaremultisig, DEFAULT_PERMIT_BAREMULTISIG = true in Core).
When NIL, bare multisig is non-standard. Consensus is unaffected.")

;;;; Token Bucket Rate Limiter

(defstruct token-bucket
  "Token bucket for rate limiting. Allows RATE tokens per second with
maximum BURST capacity. Tokens accumulate while idle."
  (rate 1.0 :type single-float)
  (burst 1.0 :type single-float)
  (tokens 0.0 :type single-float)
  (last-refill 0 :type integer))

(defun make-rate-limiter (rate burst)
  "Create a token bucket with RATE tokens/sec and BURST max capacity.
Starts full (tokens = burst) to avoid rejecting initial messages."
  (make-token-bucket :rate (float rate)
                     :burst (float burst)
                     :tokens (float burst)
                     :last-refill (get-internal-real-time)))

(defun token-bucket-allow-p (bucket)
  "Consume one token from BUCKET if available.
Returns T if allowed, NIL if rate limited.
Refills tokens based on elapsed time since last check."
  (let* ((now (get-internal-real-time))
         (elapsed (/ (float (- now (token-bucket-last-refill bucket)))
                     (float internal-time-units-per-second)))
         (refilled (min (token-bucket-burst bucket)
                        (+ (token-bucket-tokens bucket)
                           (* elapsed (token-bucket-rate bucket))))))
    (setf (token-bucket-last-refill bucket) now)
    (if (>= refilled 1.0)
        (progn
          (setf (token-bucket-tokens bucket) (- refilled 1.0))
          t)
        (progn
          (setf (token-bucket-tokens bucket) refilled)
          nil))))

;;;; Recent Transaction Rejects Filter

(defstruct recent-rejects
  "Bounded set of recently rejected transaction hashes.
Uses a hash table for O(1) lookup and a ring buffer for FIFO eviction."
  (table (make-hash-table :test 'equalp) :type hash-table)
  (ring nil :type (or null simple-vector))
  (index 0 :type fixnum)
  (max-size 50000 :type fixnum))

(defun make-rejects-filter (&optional (max-size *recent-rejects-max-size*))
  "Create a recent rejects filter with MAX-SIZE capacity."
  (make-recent-rejects :table (make-hash-table :test 'equalp)
                       :ring (make-array max-size :initial-element nil)
                       :max-size max-size))

(defun recent-reject-p (filter hash)
  "Return T if HASH is in the rejects filter."
  (and filter (gethash hash (recent-rejects-table filter))))

(defun add-recent-reject (filter hash)
  "Add HASH to the rejects filter. Evicts oldest entry if at capacity.
Returns T if added, NIL if already present."
  (when filter
    (let ((table (recent-rejects-table filter)))
      ;; Already present
      (when (gethash hash table)
        (return-from add-recent-reject nil))
      ;; Evict oldest if at capacity
      (let* ((ring (recent-rejects-ring filter))
             (idx (recent-rejects-index filter))
             (old (aref ring idx)))
        (when old
          (remhash old table))
        ;; Insert new entry
        (setf (aref ring idx) hash)
        (setf (gethash hash table) t)
        (setf (recent-rejects-index filter)
              (mod (1+ idx) (recent-rejects-max-size filter)))
        t))))

(defun clear-recent-rejects (filter)
  "Clear all entries from the rejects filter. O(1) when already empty — the
filter is now cleared on every block connect (Core ActiveTipChange resets
RecentRejectsFilter on every tip change), which during IBD would otherwise
wipe a 50k-slot ring per block for nothing."
  (when (and filter (plusp (hash-table-count (recent-rejects-table filter))))
    (clrhash (recent-rejects-table filter))
    (let ((ring (recent-rejects-ring filter)))
      (dotimes (i (length ring))
        (setf (aref ring i) nil)))
    (setf (recent-rejects-index filter) 0)))

;;;; DoS Protection Configuration

(defvar *rate-limit-inv* '(50.0 . 200.0)
  "Rate limit for INV messages: (rate-per-sec . burst).")

(defvar *rate-limit-tx* '(10.0 . 50.0)
  "Rate limit for TX messages: (rate-per-sec . burst).")

(defvar *rate-limit-addr* '(1.0 . 10.0)
  "Rate limit for ADDR/ADDRV2 messages: (rate-per-sec . burst).")

(defvar *rate-limit-getdata* '(20.0 . 100.0)
  "Rate limit for GETDATA messages: (rate-per-sec . burst).")

(defvar *rate-limit-headers* '(10.0 . 50.0)
  "Rate limit for HEADERS messages: (rate-per-sec . burst).")

(defvar *rate-limit-serve* '(5.0 . 20.0)
  "Rate limit for peer SERVE requests — getheaders/getblocks/getaddr, shared
bucket: (rate-per-sec . burst). These answer a peer from our chain/address
state; getheaders/getblocks each walk the active chain (O(tip-fork)), so a peer
spamming them could load the sync thread. A normal syncing peer sends a
getheaders per ~2000-block batch (well under this); a flood is throttled, then
disconnected by handle-message's rate-limit gate.")

(defvar *rpc-rate-limit* '(100.0 . 200.0)
  "Rate limit for RPC requests: (rate-per-sec . burst).")

(defconstant +max-message-payload+ (* 4 1000 1000)
  "Maximum P2P message payload size in bytes: 4,000,000, matching Bitcoin Core
MAX_PROTOCOL_MESSAGE_LENGTH (net.h). Not 4 MiB -- Core uses decimal 4e6.")

(defconstant +max-rpc-body-size+ #x02000000
  "Maximum RPC request body size in bytes: 32 MiB, matching Bitcoin Core's
evhttp_set_max_body_size(MAX_SIZE) (httpserver.cpp:410, serialize.h:32).
The previous 1 MiB cap rejected submitblock for a normal mainnet block.
Oversized bodies get HTTP 400, like libevent's enforcement.")

(defparameter +handshake-timeout-seconds+ 60
  "Maximum seconds a peer has to complete the version handshake, settable with
-peertimeout (Core DEFAULT_PEER_CONNECT_TIMEOUT, net.h:87).

Was 30 with no stated source. Core allows 60, so a peer on a slow link that
Core would keep, we dropped — and re-dialling it costs more than waiting. A
DEFPARAMETER because Core exposes the knob; the +NAME+ spelling is kept because
every caller reads it as a constant.")

(defvar *recent-rejects-max-size* 50000
  "Maximum entries in the recent transaction rejects filter.")

;;;; -----------------------------------------------------------------------
;;;; bitcoin.conf and command-line argument parsing
;;;;
;;;; Bitcoin Core-style configuration: -key=value CLI arguments and a
;;;; bitcoin.conf file, both mapped onto start-node's keyword parameters by
;;;; start-node-from-args (node.lisp). The parsers here are pure string
;;;; functions so they can be unit-tested without launching a node.

(defun locale-independent-atoi (value)
  "Core LocaleIndependentAtoi (util/strencodings.h:118-143), the integer
interpretation the config system is built on.

Emulates C-locale atoi: trim, allow one leading `+` (but `+-` is 0), then take
the LONGEST INTEGER PREFIX. No digits at all is 0 — which is the whole reason
this function has to exist here rather than being approximated, because
`atoi(\"true\")` is 0 and therefore `true` is FALSE to Bitcoin Core."
  (let* ((s (string-trim '(#\Space #\Tab #\Return #\Newline #\Page) value))
         (start 0)
         (len (length s)))
    (when (and (< start len) (char= (char s start) #\+))
      (when (and (< (1+ start) len) (char= (char s (1+ start)) #\-))
        (return-from locale-independent-atoi 0))
      (incf start))
    (let ((sign 1))
      (when (and (< start len) (member (char s start) '(#\+ #\-)))
        (when (char= (char s start) #\-) (setf sign -1))
        (incf start))
      (let ((end start))
        (loop while (and (< end len) (digit-char-p (char s end))) do (incf end))
        (if (= end start)
            0
            (* sign (parse-integer s :start start :end end)))))))

(defun conf-parse-bool (value)
  "Interpret a config VALUE as a boolean, exactly as Core's InterpretBool
 (common/args.cpp:57-62): the empty string (a bare -flag) is true, otherwise
`LocaleIndependentAtoi(value) != 0`.

This is deliberately NOT the lenient reading it looks like it should be. We
used to accept \"true\"/\"yes\"/\"on\" as true and treat any unrecognized value as
true; Core parses those to 0 and calls them FALSE. So the same bitcoin.conf
saying `server=true` opened a listener on our node and left it closed on
Core's — a silent, opposite-direction divergence on a security-relevant flag."
  (let ((v (string-trim '(#\Space #\Tab) value)))
    (if (string= v "")
        t
        (/= 0 (locale-independent-atoi v)))))

(defun conf-parse-int (value)
  "Parse a config VALUE as an integer, or signal an error."
  (let ((v (string-trim '(#\Space #\Tab) value)))
    (handler-case (parse-integer v)
      (error () (error "Invalid integer config value: ~S" value)))))

(defun log-categories-string ()
  "Core's LogCategoriesString: every category name, comma-separated, for the
-loglevel error message."
  (format nil "~{~A~^, ~}" (sort (copy-list bl::+log-categories+) #'string<)))

(defun parse-loglevel-spec (value)
  "Parse one -loglevel value. Returns (VALUES category level), with CATEGORY NIL
for the global form.

Core splits on the first ':' at index 3 or later (init/common.cpp:63), which is
how `-loglevel=net:debug` is told from a bare level; a level name is never long
enough to contain one there. Both halves must be known, and an unknown one is a
fatal init error — the option silently doing nothing is how an operator ends up
staring at a log that will never contain what they asked for."
  (let ((colon (position #\: value :start (min 3 (length value)))))
    (if (null colon)
        (values nil (conf-parse-loglevel value))
        (let ((category (string-downcase (subseq value 0 colon)))
              (level (subseq value (1+ colon))))
          (unless (and (bl::log-category-known-p category)
                       (member (string-downcase level)
                               '("info" "debug" "trace" "warn" "warning" "error")
                               :test #'string=))
            (error "Unsupported category-specific logging level -loglevel=~A. ~
Expected -loglevel=<category>:<loglevel>. Valid categories: ~A. ~
Valid loglevels: info, debug, trace." value (log-categories-string)))
          (values category (conf-parse-loglevel level))))))

(defun conf-parse-loglevel-global (value)
  "The GLOBAL threshold a -loglevel value implies, or NIL when it names a
category instead. A category-specific spec leaves the global level alone."
  (multiple-value-bind (category level) (parse-loglevel-spec value)
    (and (null category) level)))

(defun conf-parse-loglevel (value)
  "Map a -loglevel value to one of :debug :info :warn :error."
  (let ((v (string-downcase (string-trim '(#\Space #\Tab) value))))
    (cond ((member v '("debug" "trace") :test #'string=) :debug)
          ((string= v "info") :info)
          ((member v '("warn" "warning") :test #'string=) :warn)
          ((member v '("error" "none") :test #'string=) :error)
          ;; Core's wording verbatim, list included (init/common.cpp:66,
          ;; LogLevelsString). feature_logging.py matches it as a FULL regex.
          ;; Core's settable levels are exactly info, debug and trace — warn and
          ;; error exist as LEVELS but are not offered as a global threshold, so
          ;; they are accepted here (nothing should start refusing a config that
          ;; worked) and simply not named among the valid values.
          (t (error "Unsupported global logging level -loglevel=~A. ~
Valid values: info, debug, trace." value)))))

(defun conf-parse-money (value)
  "Parse a config VALUE as a BTC amount string into satoshis (Bitcoin Core
ParseMoney, util/moneystr.cpp): optional whitespace, digits, optional '.'
plus up to 8 decimal digits. Returns NIL for anything else (negative,
malformed, >8 decimals, out of range) — callers turn that into their own
AmountErrMsg-style error."
  (let* ((v (string-trim '(#\Space #\Tab) value))
         (dot (position #\. v)))
    (flet ((digits-p (s) (and (plusp (length s)) (every #'digit-char-p s))))
      (let ((whole (if dot (subseq v 0 dot) v))
            (frac (if dot (subseq v (1+ dot)) "")))
        (when (and (digits-p whole)
                   (or (null dot) (digits-p frac))
                   (<= (length frac) 8))
          (let ((sats (+ (* (parse-integer whole) 100000000)
                         (if (plusp (length frac))
                             (* (parse-integer frac)
                                (expt 10 (- 8 (length frac))))
                             0))))
            (when (<= sats 2100000000000000) ; MAX_MONEY
              sats)))))))

(defun conf-parse-user-hex (value)
  "Core uint256::FromUserHex (uint256.h:165-176) as raw bytes: strip an
optional 0x prefix, accept UP TO 64 hex digits, left-pad with zeros to 32
bytes. Returns the 32 bytes in DISPLAY order (most significant first), or
NIL for non-hex / over-long input."
  (let* ((v (string-trim '(#\Space #\Tab) value))
         (v (if (and (> (length v) 1)
                     (char= (char v 0) #\0)
                     (char-equal (char v 1) #\x))
                (subseq v 2)
                v)))
    (when (and (<= (length v) 64)
               (every (lambda (c) (digit-char-p c 16)) v))
      (let ((padded (concatenate 'string
                                 (make-string (- 64 (length v)) :initial-element #\0)
                                 v)))
        (bl.crypto:hex-to-bytes padded)))))

;;; -uacomment / BIP14 subversion (Core init.cpp:1676-1686)

(defconstant +max-subversion-length+ 256
  "Cap on the full formatted subversion string (Core MAX_SUBVERSION_LENGTH,
net.h:67). Exceeding it is an init ERROR, not a truncation.")

(defun ua-comment-safe-p (comment)
  "T when COMMENT survives Core's SanitizeString with SAFE_CHARS_UA_COMMENT
unchanged (strencodings.cpp:25: alphanumerics plus \" .,;-_?@\"). An unsafe
character makes -uacomment an init error, matching Core."
  (every (lambda (c)
           (or (alphanumericp c) (find c " .,;-_?@")))
         comment))

(defconstant +default-proxy-port+ 9050
  "Default SOCKS5 proxy port when -proxy/-onion gives no :port (Tor's SOCKS
port; Bitcoin Core init.cpp:1721 Lookup(..., 9050, ...)).")

(defun conf-parse-proxy (value)
  "Parse a -proxy/-onion VALUE \"ip[:port]\" into (values host port), with
PORT defaulting to 9050. Returns NIL for \"0\" or the empty string — Core's
-noproxy / -proxy=0 'remove the proxy' convention (init.cpp:1700-1704).
Accepts \"[ipv6]:port\" / \"[ipv6]\"; a trailing :port is only honored when it
is all digits after a single colon, so a bare IPv6 address is host-only
(same splitting rules as parse-node-endpoint, node.lisp)."
  (let ((v (string-trim '(#\Space #\Tab) value)))
    (cond
      ((or (zerop (length v)) (string= v "0")) nil)
      ;; [ipv6]:port or [ipv6]
      ((char= (char v 0) #\[)
       (let ((close (position #\] v)))
         (if (null close)
             (values v +default-proxy-port+)
             (let ((host (subseq v 1 close))
                   (rest (subseq v (1+ close))))
               (if (and (plusp (length rest)) (char= (char rest 0) #\:)
                        (plusp (length (subseq rest 1)))
                        (every #'digit-char-p (subseq rest 1)))
                   (values host (parse-integer rest :start 1))
                   (values host +default-proxy-port+))))))
      (t
       (let ((colon (position #\: v :from-end t)))
         (if (and colon
                  (< (1+ colon) (length v))
                  (every #'digit-char-p (subseq v (1+ colon)))
                  ;; A single colon => host:port; multiple => bare IPv6.
                  (= colon (position #\: v)))
             (values (subseq v 0 colon) (parse-integer v :start (1+ colon)))
             (values v +default-proxy-port+)))))))

(defun conf-parse-byte-units (value &optional (default-unit #\M))
  "Core ParseByteUnits (common/args.cpp): a byte count with an optional
[k|K|m|M|g|G|t|T] suffix, LOWERCASE being 1000-base and UPPERCASE 1024-base.
DEFAULT-UNIT applies when there is no suffix — M for -maxuploadtarget, which is
why a bare 100 there means 100 MiB and not 100 bytes. Pass #\B for Core's
ByteUnit::NOOP, where a bare number is a byte count."
  (let* ((v (string-trim '(#\Space #\Tab) value))
         (last (and (plusp (length v)) (char v (1- (length v)))))
         (suffixed (and last (find last "kKmMgGtT")))
         (unit (if suffixed last default-unit))
         (digits (if suffixed (subseq v 0 (1- (length v))) v))
         (multiplier (ecase unit
                       ;; Core's ByteUnit::NOOP, the default for every option
                       ;; other than -maxuploadtarget.
                       (#\B 1)
                       (#\k 1000) (#\K 1024)
                       (#\m (expt 1000 2)) (#\M (expt 1024 2))
                       (#\g (expt 1000 3)) (#\G (expt 1024 3))
                       (#\t (expt 1000 4)) (#\T (expt 1024 4)))))
    (unless (and (plusp (length digits)) (every #'digit-char-p digits))
      (error "Unable to parse byte amount: '~A'" value))
    (* (parse-integer digits) multiplier)))

(defun conf-parse-network-name (value)
  "Map an -onlynet VALUE to a network keyword (Core ParseNetwork,
netbase.cpp: ipv4/ipv6/onion/i2p/cjdns; the old \"tor\" alias is gone)."
  (let ((v (string-downcase (string-trim '(#\Space #\Tab) value))))
    (cond ((string= v "ipv4") :ipv4)
          ((string= v "ipv6") :ipv6)
          ((string= v "onion") :torv3)
          ((string= v "i2p") :i2p)
          ((string= v "cjdns") :cjdns)
          (t (error "Unknown network specified in -onlynet: ~S" value)))))

(defun conf-section-name (network)
  "The bitcoin.conf [section] header that scopes options to NETWORK
(chain-params-core-name: main, test, testnet4, signet, regtest)."
  (bl.chain:chain-params-core-name (bl.chain:find-chain-params network)))

(defun split-option-token (arg)
  "Split one -key / -key=value / --key=value token. Returns (VALUES raw-key
value), where VALUE is NIL when the token carried none and RAW-KEY is
lower-cased and still carries any `no` prefix. NIL raw-key for a bare - or --."
  (let* ((s (string-left-trim "-" arg))
         (eq-pos (position #\= s)))
    (if (zerop (length s))
        (values nil nil)
        (values (string-downcase (if eq-pos (subseq s 0 eq-pos) s))
                (and eq-pos (subseq s (1+ eq-pos)))))))

(defun interpret-arg (raw-key value)
  "Core's InterpretKey + InterpretValue for one option (common/args.cpp:86-126).
Returns (VALUES name string-value json-value).

NAME is RAW-KEY with any `no` prefix stripped. STRING-VALUE is what the option
readers here consume; JSON-VALUE is the JSON Core would have stored, which is
what its `Command-line arg:` / `Config file arg:` lines print — the two differ
exactly on a negation, where the readers want \"0\" and the log wants `false`.

One function for the command line AND the config file, because Core applies the
same two steps to both (config.cpp:63 calls InterpretKey). It used to be written
out three times — twice for the command line, once for the file — and the copies
had already drifted apart on whether the `no` prefix was stripped at all.

Stripping is UNCONDITIONAL, as Core's is. Gating it on the remainder being a
known option looks safer and is not: it makes what a line in bitcoin.conf MEANS
depend on the contents of a lookup table, so adding an option would silently
change the meaning of existing config files. No option in any of this tree's
tables begins with `no`, so the two rules agree today anyway — and where they
would not, Core's is the one whose behaviour is documented."
  (let ((negated (and (> (length raw-key) 2)
                      (string= "no" (subseq raw-key 0 2)))))
    (if negated
        (let ((name (subseq raw-key 2)))
          ;; Double negatives like -nofoo=0 are supported but discouraged
          ;; (args.cpp:114-118), and they mean TRUE.
          (if (and value (not (conf-parse-bool value)))
              (progn
                ;; DEFER-LOG, not LOG-WARN: config parsing runs before the log
                ;; file exists. See FLUSH-DEFERRED-LOG-LINES.
                (defer-log :warn "Parsed potentially confusing double-negative -~A=~A"
                  name value)
                (values name "1" "true"))
              (values name "0" "false")))
        ;; A bare -flag is the empty string to Core, and truthy to InterpretBool.
        (values raw-key (or value "1")
                (render-json-value (or value ""))))))

(defun parse-cli-args (args)
  "Parse Bitcoin Core-style CLI ARGS (a list of strings) into an alist of
 (lower-case-key . value-string), in order. Accepts -key=value and
--key=value; a bare -key means key=1 and -nokey means key=0 (Core
InterpretKey/InterpretValue). A repeated non-repeatable key keeps only its
LAST occurrence (see CONFIG-OPTION-REPEATABLE-P), so an assoc lookup
matches Core's command-line GetArg. Non-flag tokens are ignored here;
check-cli-args rejects them up front."
  (let ((out nil))
    (dolist (arg args)
      (when (and (stringp arg) (plusp (length arg)) (char= (char arg 0) #\-))
        (multiple-value-bind (raw-key value) (split-option-token arg)
          (when raw-key                            ; NIL for a bare "-" / "--"
            ;; One interpreter for the command line AND the config file, so
            ;; Core's InterpretKey/InterpretValue rule has a single home.
            (multiple-value-bind (key string-value) (interpret-arg raw-key value)
              (push (cons key string-value) out))))))
    ;; OUT is reversed (last arg first): keep the FIRST cell seen per
    ;; non-repeatable key = the LAST command-line occurrence, then restore
    ;; command-line order.
    (let ((kept nil) (seen (make-hash-table :test 'equal)))
      (dolist (cell out (copy-list kept))
        (let ((key (car cell)))
          (if (config-option-repeatable-p key)
              (push cell kept)
              (unless (gethash key seen)
                (setf (gethash key seen) t)
                (push cell kept))))))))

(define-condition config-parse-error (error)
  ((message :initarg :message :reader config-parse-error-message))
  (:report (lambda (c stream) (write-string (config-parse-error-message c) stream)))
  (:documentation
   "A bitcoin.conf line Core refuses to parse. Core returns false from
GetConfigOptions with an `error` string and the node does not start; a config
this malformed silently half-applying is how an operator ends up running
settings they did not write."))

(defun %conf-strip-comment (line)
  "Cut LINE at its first #, as Core does (config.cpp:41-44). Returns
 (values text used-hash-p).

Core strips a # ANYWHERE in the line, not only at the start. We stripped only
whole-line comments, so `datadir=/srv/btc  # mainnet` produced a datadir whose
literal name contained the comment — and, since a missing datadir was created
rather than refused, a silent resync from genesis into a junk directory."
  (let ((pos (position #\# line)))
    (if pos
        (values (subseq line 0 pos) t)
        (values line nil))))

(defun parse-bitcoin-conf-sections (text &optional network)
  "Parse bitcoin.conf TEXT into (values section-entries global-entries
section-json global-json). The first two are in-order alists of
 (lower-case-key . value-string); the last two are the same keys paired with
the JSON rendering Core would have stored, for LogArgs.

GLOBAL-ENTRIES are the keys before any [section]; SECTION-ENTRIES are the keys
in the [section] matching NETWORK (all sections when NETWORK is NIL). Core keeps
the same split — it prefixes section keys and stores them under
`ro_config[section][name]` (config.cpp:48-65) — because the two are consulted in
a definite order, not merged blindly. See PARSE-BITCOIN-CONF.

Signals CONFIG-PARSE-ERROR on the three lines Core refuses:
a leading `-`, a non-empty line with no `=`, and `#` inside an rpcpassword."
  (let ((sections nil)
        (globals nil)
        ;; The same cells again, but carrying the JSON rendering Core stored
        ;; rather than the string the config layer wants. They differ exactly
        ;; where a negation happened — `nolisten=1` is the string "0" to an
        ;; option reader and `false` in a `Config file arg:` line — and the log
        ;; wording is a contract Core's functional tests read back.
        (sections-json nil)
        (globals-json nil)
        (in-section nil)
        (active t)
        (want (and network (conf-section-name network)))
        (linenr 0))
    (with-input-from-string (in text)
      (loop for raw = (read-line in nil nil)
            while raw
            do (incf linenr)
               (multiple-value-bind (body used-hash) (%conf-strip-comment raw)
                 (let ((line (string-trim '(#\Space #\Tab #\Return) body)))
                   (cond
                     ((zerop (length line)))
                     ((and (char= (char line 0) #\[)
                           (char= (char line (1- (length line))) #\]))
                      (let ((sec (string-downcase
                                  (string-trim '(#\Space)
                                               (subseq line 1 (1- (length line)))))))
                        (setf in-section t
                              active (or (null want) (string= sec want)))))
                     ((char= (char line 0) #\-)
                      (error 'config-parse-error
                             :message (format nil "parse error on line ~D: ~A, options in ~
                                                   configuration file must be specified ~
                                                   without leading -" linenr line)))
                     (t
                      (let ((eq-pos (position #\= line)))
                        (unless eq-pos
                          (error 'config-parse-error
                                 :message
                                 (format nil "parse error on line ~D: ~A~@[~A~]" linenr line
                                         (when (and (>= (length line) 2)
                                                    (string= "no" (subseq line 0 2)))
                                           (format nil ", if you intended to specify a ~
                                                        negated option, use ~A=1 instead"
                                                   line)))))
                        ;; Core runs InterpretKey/InterpretValue over
                        ;; config-file keys exactly as over command-line ones
                        ;; (common/config.cpp:63 calls InterpretKey), so this is
                        ;; the same INTERPRET-ARG the command line uses. Without
                        ;; it, `nolisten=1` in bitcoin.conf set an option called
                        ;; "nolisten" that nothing reads, so the file could not
                        ;; negate anything at all.
                        (multiple-value-bind (key value json)
                            (interpret-arg
                             (string-downcase
                              (string-trim '(#\Space #\Tab) (subseq line 0 eq-pos)))
                             (string-trim '(#\Space #\Tab) (subseq line (1+ eq-pos))))
                          (when (and used-hash (search "rpcpassword" key))
                            (error 'config-parse-error
                                   :message
                                   (format nil "parse error on line ~D, using # in ~
                                                rpcpassword can be ambiguous and should ~
                                                be avoided" linenr)))
                          (when active
                            (if in-section
                                (progn (push (cons key value) sections)
                                       (push (cons key json) sections-json))
                                (progn (push (cons key value) globals)
                                       (push (cons key json) globals-json))))))))))))
    (values (nreverse sections) (nreverse globals)
            (nreverse sections-json) (nreverse globals-json))))

(defun parse-bitcoin-conf (text &optional network)
  "Parse bitcoin.conf TEXT into a single in-order alist, ordered so that ASSOC
gives Core's precedence: the [network] section BEFORE the global area.

That order is the fix for a silent inversion. Core resolves a setting as
`forced > command line > rw settings > config network section > config default
section` (settings.cpp:36), so a `[main] rpcport=8888` beats a global
`rpcport=7777`. We returned keys in file order and let the first ASSOC win,
which made the GLOBAL value beat the section — the reverse of Core, on every
key an operator bothered to scope."
  (multiple-value-bind (sections globals) (parse-bitcoin-conf-sections text network)
    (append sections globals)))

(defun conf-global-entries (text)
  "The global-area entries only. Core reads the chain selectors with
`section=\"\"` (args.cpp:825-829, get_chain_type=true): the network cannot be
chosen from inside a network section, because the section cannot be scoped
until the network is known.

This is what lets a network selected INSIDE bitcoin.conf still scope its own
section. We used to resolve the network from the CLI alone and then parse the
file against it, so `testnet4=1` in the file left us scoping to the DEFAULT
network's section and silently dropping the whole [testnet4] block."
  (nth-value 1 (parse-bitcoin-conf-sections text nil)))

(defun resolve-network-from-config (alist &optional (default :testnet3))
  "Determine the network from a merged config ALIST. Honors -regtest/-signet/
-testnet4/-testnet flags and -chain=main|test|testnet4|signet|regtest.

More than one selector is an ERROR, as it is in Core (args.cpp:839-841,
\"Invalid combination of -regtest, -signet, -testnet, -testnet4 and -chain. Can
use at most one.\"). We used to resolve a conflict by a silent priority order,
so `-chain=regtest` on the command line plus a stale `testnet=1` left in
bitcoin.conf started the node on PUBLIC TESTNET3 without saying anything."
  (flet ((flag (k) (let ((c (assoc k alist :test #'string=)))
                     (and c (conf-parse-bool (cdr c)))))
         (val (k) (let ((c (assoc k alist :test #'string=))) (and c (cdr c)))))
    (let ((selectors (count t (list (flag "regtest") (flag "signet")
                                    (flag "testnet4") (flag "testnet")
                                    (and (val "chain") t)))))
      (when (> selectors 1)
        (error 'config-parse-error
               :message (format nil "Invalid combination of -regtest, -signet, ~
                                     -testnet, -testnet4 and -chain. Can use at ~
                                     most one."))))
    (cond
      ((flag "regtest") :regtest)
      ((flag "signet") :signet)
      ((flag "testnet4") :testnet4)
      ((flag "testnet") :testnet3)
      ((val "chain")
       (let ((c (string-downcase (val "chain"))))
         (cond ((member c '("main" "mainnet") :test #'string=) :mainnet)
               ((member c '("test" "testnet" "testnet3") :test #'string=) :testnet3)
               ((string= c "testnet4") :testnet4)
               ((string= c "signet") :signet)
               ((string= c "regtest") :regtest)
               (t (error "Unknown -chain value: ~S" c)))))
      (t default))))

(defun supplied-core-only-options (alist)
  "The core-only options actually present in ALIST, deduplicated and in order.
The caller warns about each, so accepting them never passes for implementing
them."
  (remove-duplicates
   (loop for (k . nil) in alist
         when (core-only-option-p k) collect (string-downcase k))
   :test #'string= :from-end t))

(defun known-config-option-p (name)
  "T if NAME (lower-case, no dashes) is a recognized config option: any
DEFINE-OPTION row, including the recognised-but-unimplemented Core options
(accepted so an ordinary bitcoind command line starts this node, warned
about at startup so nobody mistakes that for support). check-cli-args uses
this to reject unknown command-line options at startup, like Core
ArgsManager::ParseParameters (common/args.cpp:229-238)."
  (and (or (find-config-option name)
           ;; -nokey negation of a known key parses to key=0 before this
           ;; check, but tolerate the raw \"noKEY\" spelling too.
           (and (> (length name) 2) (string-equal (subseq name 0 2) "no")
                (known-config-option-p (subseq name 2))))
       t))

(define-condition cli-parse-error (error)
  ((detail :initarg :detail :reader cli-parse-error-detail))
  (:report (lambda (c stream)
             ;; Core's bitcoind prints the parse failure with this prefix and
             ;; nothing else (bitcoind.cpp: InitError(strprintf("Error parsing
             ;; command line arguments: %s", error))), and its functional tests
             ;; match on the prefix rather than on the detail —
             ;; feature_help.py asserts exactly b'Error parsing command line
             ;; arguments' on stderr for an unknown option.
             (format stream "Error parsing command line arguments: ~A"
                     (cli-parse-error-detail c))))
  (:documentation "A command line Core would refuse to parse."))

(defun check-cli-args (args)
  "Reject unknown command-line options and bare non-option tokens, like
Bitcoin Core (common/args.cpp:211 \"Invalid command\", :229-238 \"Invalid
parameter\" — unknown CLI options are a HARD error; unknown CONFIG-FILE keys
only warn, common/config.cpp:107-115 with ignore_invalid_keys=true from
common/init.cpp:38). Returns ARGS.

Signals CLI-PARSE-ERROR, whose report carries Core's prefix. The detail texts
are Core's own, verbatim, because they are what an operator searches for."
  (flet ((refuse (fmt &rest args)
           (error 'cli-parse-error :detail (apply #'format nil fmt args))))
    (dolist (arg args args)
      (unless (stringp arg)
        (refuse "Invalid command '~A'" arg))
      (if (and (plusp (length arg)) (char= (char arg 0) #\-))
          (let* ((s (string-left-trim "-" arg))
                 (eq-pos (position #\= s))
                 (name (string-downcase (if eq-pos (subseq s 0 eq-pos) s))))
            ;; -includeconf is a CONFIG-FILE directive only. Core refuses it on
            ;; the command line outright (common/args.cpp; the text is pinned
            ;; by argsman_tests.cpp:205-206), because honouring it there would
            ;; let a command line pull in a file whose own -includeconf pulls
            ;; in another, with no datadir to anchor the recursion.
            ;; -includeconf, through Core's own key/value interpretation.
            ;;
            ;; The refusal fires on a non-empty settings span (args.cpp:247-253)
            ;; and reports the first value as Core's SettingsValue::write()
            ;; renders it — a JSON string is quoted, a JSON bool is not. So the
            ;; three refusable spellings read:
            ;;
            ;;   -includeconf              -> -includeconf=""      (empty string)
            ;;   -includeconf=x.conf       -> -includeconf="x.conf"
            ;;   -noincludeconf=0          -> -includeconf=true    (double negative)
            ;;
            ;; while -noincludeconf and -noincludeconf=1 CLEAR the span and are
            ;; allowed: that is how an operator suppresses includes from the
            ;; command line, and refusing it would break the one CLI spelling
            ;; Core accepts. feature_includeconf.py exercises the double
            ;; negative and the valued form, and the bare form is pinned by
            ;; argsman_tests.cpp:205-206.
            (let* ((negated (and (> (length name) 2) (string= "no" (subseq name 0 2))))
                   (base (if negated (subseq name 2) name))
                   (value (and eq-pos (subseq s (1+ eq-pos)))))
              (when (string= base "includeconf")
                (cond
                  ((not negated)
                   (refuse "-includeconf cannot be used from commandline; -includeconf=\"~A\""
                           (or value "")))
                  ((and value (not (conf-parse-bool value)))
                   (refuse "-includeconf cannot be used from commandline; -includeconf=true")))))
            (unless (or (zerop (length name))          ; bare "-"/"--"
                        (known-config-option-p name))
              (refuse "Invalid parameter ~A" arg)))
          (refuse "Invalid command '~A'" arg)))))

(defun unknown-config-file-keys (conf-alist)
  "The keys in CONF-ALIST that no option table recognizes. The caller logs a
warning per key (Core LogWarning \"Ignoring unknown configuration value\")
— unknown config-FILE keys never abort startup."
  (remove-duplicates
   (loop for (k . nil) in conf-alist
         unless (known-config-option-p k)
           collect k)
   :test #'string= :from-end t))


;;; --- settings.json (Core's read-write settings file) ---
;;;
;;; Core keeps a JSON object of "read-write" settings in the network directory,
;;; between the command line and the config file in precedence
;;; (common/settings.cpp:36). It is read AND rewritten on every start
;;; (common/init.cpp:98-115), which is how a datadir that has ever been started
;;; always has one.

(defparameter +settings-warning-key+ "_warning_"
  "Core SETTINGS_WARN_MSG_KEY. Stripped on read, re-added on write, and never
visible as a setting.")

(defparameter +client-name+ "bitcoin-lisp"
  "Core's CLIENT_NAME. Named here rather than derived from the user agent
because it is the value scripts/conformance-config.sh publishes to Core's test
framework as CLIENT_NAME, and the framework compares strings with it.")

(defun settings-file-warning ()
  "Core's auto-generated comment, verbatim (common/settings.cpp:129-130)."
  (format nil "This file is automatically generated and updated by ~A. Please ~
do not edit this file while the node is running, as any changes might be ~
ignored or overwritten."
          +client-name+))

(defun render-json-value (value)
  "VALUE as compact JSON, matching UniValue::write() — which is what Core
interpolates into its `Setting file arg:` lines, so the rendering is part of
the log contract rather than a detail.

yason's encoder already produces that form byte for byte, including \\uXXXX for
control characters and `null` for NIL; the values here come straight from
yason's parser, so nothing needs re-tagging on the way in either. Reading a
settings file with PARSE-SETTINGS-JSON and writing it back is a pure round trip
through one library."
  (with-output-to-string (out) (yason:encode value out)))

(defun %json-escape (string)
  "STRING as a JSON string literal, quotes included."
  (render-json-value string))

(defun parse-settings-json (text path-string)
  "Parse settings-file TEXT. Returns (VALUES alist errors), where ALIST maps
setting name to its parsed JSON value and ERRORS is a list of Core's own
message strings — the functional tests match on their wording
(feature_settings.py).

TEXT is parsed TWICE, which is worth the two passes on a file this size. The
:alist pass is the only one that can see a DUPLICATE KEY (a hash-table parse
silently keeps the last, and the node would start on a setting the operator
cannot see in the file) and it preserves the key ORDER Core writes back. The
default pass supplies the VALUES, because only there are the JSON types
unambiguous: as an alist a nested object and an array of pairs are the same
list, and an empty array is NIL, which is also how null arrives.

An error yields NO settings rather than partial ones: Core clears the map on a
duplicate key and returns nothing on a parse failure, and a node that started
with half a settings file applied is worse than one that refused to start."
  (flet ((invalid ()
           (return-from parse-settings-json
             (values nil (list (format nil "Settings file ~A does not contain valid ~
JSON. This is probably caused by disk corruption or a crash, and can be fixed ~
by removing the file, which will reset settings to default values." path-string))))))
    (let ((keyed (handler-case
                     (let ((yason:*parse-object-as* :alist)
                           (yason:*parse-json-booleans-as-symbols* t))
                       (yason:parse text))
                   (error () (invalid))))
          (table nil))
    ;; An alist parse of a non-object gives back the scalar itself, and a JSON
    ;; array parses to a LIST — shaped exactly like an alist of nothing, so
    ;; emptiness alone cannot tell them apart. The test is that every element
    ;; is a (string . value) cons.
    (unless (and (listp keyed)
                 (every (lambda (c) (and (consp c) (stringp (car c)))) keyed))
      (return-from parse-settings-json
        (values nil (list (format nil "Found non-object value ~A in settings file ~A"
                                  (render-json-value keyed) path-string)))))
    ;; Duplicate keys BEFORE the second parse: yason's hash-table parser
    ;; signals on one, and the handler would report it as invalid JSON —
    ;; losing the message Core prints and the test matches on.
    (let ((seen (make-hash-table :test 'equal)))
      (dolist (cell keyed)
        (when (gethash (car cell) seen)
          (return-from parse-settings-json
            (values nil (list (format nil "Found duplicate key ~A in settings file ~A"
                                      (car cell) path-string)))))
        (setf (gethash (car cell) seen) t)))
    (setf table (handler-case
                    (let ((yason:*parse-json-arrays-as-vectors* t)
                          (yason:*parse-json-booleans-as-symbols* t))
                      (yason:parse text))
                  (error () (invalid))))
    (let ((out nil))
      (dolist (cell keyed)
        (unless (string= (car cell) +settings-warning-key+)
          (push (cons (car cell) (gethash (car cell) table)) out)))
      (values (nreverse out) nil)))))

(defun render-settings-json (alist)
  "ALIST as the text of a settings file: the warning comment first, then every
setting in the order given (Core WriteSettings, common/settings.cpp:123-142)."
  (with-output-to-string (out)
    (format out "{~%    ~A: ~A"
            (%json-escape +settings-warning-key+)
            (%json-escape (settings-file-warning)))
    (dolist (cell alist)
      (format out ",~%    ~A: ~A"
              (%json-escape (car cell)) (render-json-value (cdr cell))))
    (format out "~%}~%")))

(defun settings-alist->config-alist (settings)
  "SETTINGS (name -> parsed JSON value) as the (name . string) cells the rest
of the config layer speaks. A JSON false is Core's negation, i.e. \"0\"."
  (loop for (name . value) in settings
        collect (cons name
                      (cond ((eq value 'yason:false) "0")
                            ((eq value 'yason:true) "1")
                            ((null value) "0")
                            ((stringp value) value)
                            (t (render-json-value value))))))

(defun validate-settings-values (settings)
  "The Core-worded init error a settings file's VALUES earn, or NIL.

Only -wallet is checked, because it is the only setting whose JSON TYPE Core
validates rather than coercing: every element of the wallet list must be a
string, and anything else is a fatal init error (wallet/load.cpp:81-86,
121-126). A settings file is written by software, so a wrong type there is not
a typo — it is a corrupted or hand-edited file, and loading a wallet named
`true` is worse than refusing to start."
  (let ((cell (assoc "wallet" settings :test #'string=)))
    (when cell
      (let* ((value (cdr cell))
             (elements (cond
                         ;; A JSON false is -nowallet: no names at all, valid.
                         ((eq value 'yason:false) nil)
                         ((stringp value) (list value))
                         ((or (vectorp value) (and (listp value) value))
                          (coerce value 'list))
                         (t (list value)))))
        (unless (every #'stringp elements)
          "Invalid value detected for '-wallet' or '-nowallet'. '-wallet' requires a string value, while '-nowallet' accepts only '1' to disable all wallets")))))

(defun unknown-settings-keys (settings)
  "The settings-file keys no option table recognizes. Core logs one warning
each and carries on (args.cpp:420-423) — unknown settings never abort startup."
  (unknown-config-file-keys settings))

;;; --- Core's LogArgs() ---

(defun %cli-arg-log-cells (args)
  "The (name . json-text) pairs Core's `Command-line arg:` lines carry.

Re-walks the raw ARGS rather than reading PARSE-CLI-ARGS' output, because that
output is normalized to \"1\"/\"0\" strings and Core logs the JSON value it
actually stored: a negation is `false`, a bare -flag is `\"\"`, and -flag=x is
the string \"x\". INTERPRET-ARG returns both forms from one reading of the
token, so the log and the option readers cannot disagree about what it meant."
  (let ((out nil))
    (dolist (arg args (nreverse out))
      (when (and (stringp arg) (plusp (length arg)) (char= (char arg 0) #\-))
        (multiple-value-bind (raw-key value) (split-option-token arg)
          (when raw-key
            (multiple-value-bind (key string-value json) (interpret-arg raw-key value)
              (declare (ignore string-value))
              (push (cons key json) out))))))))

(defun %config-arg-log-cells (text network)
  "The (section name json-text) triples Core's `Config file arg:` lines carry.

The JSON comes from the parser, not from re-rendering the string it produced:
a negated key is stored as `false`, and the string the option readers see for
it is \"0\", which would render as the string \"0\" instead."
  (multiple-value-bind (sections globals sections-json globals-json)
      (parse-bitcoin-conf-sections text network)
    (declare (ignore sections globals))
    (append
     (loop for (name . json) in sections-json
           collect (list (conf-section-name network) name json))
     (loop for (name . json) in globals-json
           collect (list "" name json)))))

(defun parse-bind-option (spec)
  "Parse one -bind value into (VALUES host port onion-p), or NIL when it is
unparseable.

Core's form is `-bind=<addr>[:<port>][=onion]` (init.cpp; test_node.py:272-276
passes both the plain and the =onion form). The `=onion` suffix marks a
listener reserved for incoming Tor connections rather than an address in its
own right, so it is reported separately. PORT is NIL when the value names only
an address, which means \"the network's default port\".

An IPv6 literal must be bracketed for the port to be separable, exactly as in
Core: `[::1]:8333` has a port, `::1` does not."
  (when (stringp spec)
    (let* ((onion-p nil)
           (text spec))
      ;; The =onion suffix first: it is not part of the address.
      (let ((tail (search "=onion" text :from-end t)))
        (when (and tail (= tail (- (length text) 6)))
          (setf onion-p t text (subseq text 0 tail))))
      (when (plusp (length text))
        (let ((close-bracket (position #\] text :from-end t)))
          (cond
            ;; [v6]:port or bare [v6]
            ((and (char= (char text 0) #\[) close-bracket)
             (let ((host (subseq text 1 close-bracket))
                   (rest (subseq text (1+ close-bracket))))
               (cond ((zerop (length rest)) (values host nil onion-p))
                     ((and (char= (char rest 0) #\:)
                           (%parse-port (subseq rest 1)))
                      (values host (%parse-port (subseq rest 1)) onion-p))
                     (t nil))))
            ;; An unbracketed value with exactly one colon is host:port; more
            ;; than one colon is a bare IPv6 literal, never host:port.
            (t
             (let ((colon (position #\: text)))
               (cond ((null colon) (values text nil onion-p))
                     ((find #\: text :start (1+ colon)) (values text nil onion-p))
                     (t (let ((port (%parse-port (subseq text (1+ colon)))))
                          (when port
                            (values (subseq text 0 colon) port onion-p)))))))))))))

(defun %parse-port (string)
  "STRING as a TCP port number, or NIL."
  (when (and (plusp (length string))
             (every #'digit-char-p string))
    (let ((n (parse-integer string :junk-allowed t)))
      (when (and n (<= 1 n 65535)) n))))

(defun conf-effective-listen-flags (alist)
  "Replay Core's -listen/-listenonion soft-set chain over a merged config
ALIST. Returns (VALUES listen-p listen-onion-p). The ONE encoding of this
chain — the start-node plist assembly and apply-config-globals' -onlynet=onion
gate both derive from it, so the two can never drift.

ORDER IS THE WHOLE THING. Core's SoftSetBoolArg is FIRST-WINS: it sets a value
only if nothing has set one yet, and an explicit user value counts as already
set. InitParameterInteraction (init.cpp:764-810) then runs the interactions in
an order chosen so the earlier ones override the later ones:

  1. -bind / -whitebind soft-set -listen=1 (:768-775). Core's comment says why
     in as many words: \"when specifying an explicit binding address, you want
     to listen on it even when -connect or -proxy is specified\".
  2. -connect in any form, or -maxconnections<=0, soft-sets -dnsseed=0 and
     -listen=0 (:777-784) — \"when only connecting to trusted nodes, do not
     seed via DNS, or listen by default\".
  3. -proxy soft-sets -listen=0, to protect privacy (:786-790).

So -bind BEATS -connect, and this is not a corner case: Core's functional test
framework writes both `bind=127.0.0.1` and `connect=0` into every node's config
(test_framework/util.py), and relies on the node listening anyway so that
connect_nodes can wire the network up with `addnode onetry`. Applying step 2
without step 1 leaves every node deaf, every multi-node test times out in
connect_nodes, and the node logs nothing wrong because from its own point of
view it did what it was told.

-listen=0 then soft-disables -listenonion (:808-809), and the explicit
contradiction -listen=0 -listenonion=1 is an init ERROR (:1022-1024)."
  (flet ((lk (k) (let ((c (assoc k alist :test #'string=))) (and c (cdr c)))))
    (let ((listen nil))                 ; NIL = nothing has set it yet
      (flet ((soft-set (value)
               ;; SoftSetBoolArg: first writer wins.
               (unless listen (setf listen (list value)))))
        ;; An explicit -listen is already set before any interaction runs.
        (let ((explicit (lk "listen")))
          (when explicit (soft-set (and (conf-parse-bool explicit) t))))
        (when (or (lk "bind") (lk "whitebind"))
          (soft-set t))
        (when (or (assoc "connect" alist :test #'string=)
                  (let ((m (lk "maxconnections")))
                    (and m (let ((n (parse-integer m :junk-allowed t)))
                             (and n (<= n 0))))))
          (soft-set nil))
        (when (let ((v (lk "proxy"))) (and v (conf-parse-proxy v)))
          (soft-set nil)))
      (let* ((listen-p (if listen (first listen) t)) ; Core DEFAULT_LISTEN
             (lo (lk "listenonion"))
             (lo-p (and lo (conf-parse-bool lo))))
        (when (and (not listen-p) lo-p)
          (error "Cannot set -listen=0 together with -listenonion=1"))
        (values listen-p
                (and listen-p (if lo lo-p t)))))))

(defun config-alist->start-node-plist (alist network)
  "Convert a merged config ALIST (CLI over file) into a plist of start-node
keyword arguments, coercing each value by its option-table type. NETWORK is the already-
resolved network. Honors -server (enable RPC on the default port when no
-rpcport is given) and -debug (=> loglevel debug unless -loglevel is set)."
  (let ((plist (list :network network)))
    (flet ((lookup (k) (assoc k alist :test #'string=)))
      (dolist (option (scalar-key-options))
        (let ((cell (lookup (config-option-name option))))
          (when cell
            (setf (getf plist (config-option-key option))
                  (parse-option-value option (cdr cell))))))
      ;; -port must be a real port number (Core init.cpp InitError
      ;; "Invalid port specified in -port").
      (let ((port (getf plist :port)))
        (when (and port (not (<= 1 port 65535)))
          (error "Invalid port specified in -port: '~A'" port)))
      ;; Repeatable options whose value is just the string: keep every
      ;; occurrence, CLI and config file, the way Core's GetArgs does (the
      ;; :COLLECT rows of the option table). Each is validated where it is
      ;; used, not here.
      (dolist (option (collected-key-options))
        (let ((values (loop for (k . v) in alist
                            when (string= k (config-option-name option))
                              collect v)))
          (when values (setf (getf plist (config-option-collect option)) values))))
      ;; -disablewallet turns the wallet OFF (Core init.cpp). Inverted into
      ;; :wallet, and only when -wallet was not given explicitly: an operator
      ;; who wrote both said something contradictory, and Core lets the
      ;; explicit -wallet win by loading it anyway.
      (let ((disable (getf plist :disable-wallet)))
        (remf plist :disable-wallet)
        (when (and disable (not (lookup "wallet")))
          (setf (getf plist :wallet) nil)))
      ;; A category-specific -loglevel names no global level, so the scalar
      ;; parse yields NIL. Drop the key rather than passing NIL through: an
      ;; explicit NIL overrides START-NODE's :INFO default, and it only happens
      ;; to behave because LOG-LEVEL-VALUE's fallback is also 1.
      (when (and (member :log-level plist) (null (getf plist :log-level)))
        (remf plist :log-level))
      ;; -wallet carries two things at once. The NAMES to load are Core's
      ;; meaning. The second is ours: wallet support is default-OFF on mainnet
      ;; (docs/wallet-plan.md), and naming a wallet — or a bare -wallet, which
      ;; INTERPRET-ARG renders as "1" — is the operator's opt-in.
      ;;
      ;; `-nowallet` arrives as "0" and means "load no wallets" (Core:
      ;; "'-nowallet' accepts only '1' to disable all wallets"). It names
      ;; nothing and it does NOT turn the subsystem off: the wallet RPCs stay
      ;; registered, which is what wallet_multiwallet.py's first node relies on.
      (let* ((raw (getf plist :wallet-names))
             (names (remove-if (lambda (v) (member v '("0" "1") :test #'string=)) raw)))
        (setf (getf plist :wallet-names) names)
        (when (or names (member "1" raw :test #'string=))
          (setf (getf plist :wallet) t)))
      ;; -bind=<addr>[:<port>][=onion] (Core init.cpp; the functional framework
      ;; passes both forms, test_node.py:272-276). The scalar scan above already
      ;; took the last plain value into :listen-bind; re-derive it here so the
      ;; address is separated from its port, and so an =onion entry — which
      ;; names a Tor-only listener, not an address to bind — is not mistaken
      ;; for one.
      (let* ((specs (loop for (k . v) in alist when (string= k "bind") collect v))
             (parsed (loop for spec in specs
                           collect (multiple-value-list (parse-bind-option spec))))
             (plain (remove-if (lambda (p) (or (null (first p)) (third p))) parsed)))
        (when (and specs (null plain))
          ;; Every -bind was =onion or unparseable: do NOT leave the spec
          ;; scan's raw string (which still carries ":port=onion") in the
          ;; plist as a bind address.
          (remf plist :listen-bind))
        (when plain
          (destructuring-bind (host port onion-p) (first plain)
            (declare (ignore onion-p))
            (setf (getf plist :listen-bind) host)
            ;; A port on -bind overrides -port for the listener, as it does in
            ;; Core, where the bind address carries its own port.
            (when port (setf (getf plist :port) port)))))
      ;; -listen is decided in exactly one place: CONF-EFFECTIVE-LISTEN-FLAGS,
      ;; which replays Core's soft-set chain in Core's order (-bind beats
      ;; -connect beats -proxy). Deciding it here as well is how the -bind case
      ;; got lost the first time.
      ;;
      ;; (-connect's -dnsseed=0 half is applied in APPLY-CONFIG-GLOBALS, which
      ;; owns *dns-seed-enabled*.)
      ;; -debug also raises the log level, because a category's lines are
      ;; emitted at debug level: enabling a category without raising the level
      ;; turns on a switch that changes nothing. An explicit -loglevel wins.
      ;;
      ;; -debug=0/none does NOT raise it — that spelling turns everything off.
      ;; The old read was CONF-PARSE-BOOL of the value, and atoi("net") is 0, so
      ;; -debug=net used to do nothing at all.
      (let ((debug (getf plist :debug-categories)))
        (when (and debug
                   (notevery (lambda (d) (member d '("0" "none") :test #'string=))
                             debug)
                   (not (lookup "loglevel")))
          (setf (getf plist :log-level) :debug)))
      ;; -server enables RPC; give it the network default port if none was set.
      (let ((server (lookup "server")))
        (when (and server (conf-parse-bool (cdr server))
                   (not (getf plist :rpc-port)))
          (setf (getf plist :rpc-port) (network-rpc-port network))))
      ;; The listen chain, applied once, for both flags.
      (multiple-value-bind (listen-p listen-onion-p)
          (conf-effective-listen-flags alist)
        (setf (getf plist :listen) listen-p)
        (unless listen-onion-p
          (setf (getf plist :listen-onion) nil))))
    plist))

(defun parse-option-value (option raw)
  "RAW, the string value of OPTION, parsed by the option's :TYPE. The error
texts are Core's: \"Invalid amount for -x=v\" for a fee that ParseMoney
rejects, \"Invalid value for -x=v (must be a positive integer)\" for an
:int below its :MIN."
  (let ((name (config-option-name option)))
    (ecase (config-option-type option)
      ((nil :string) raw)
      (:bool (conf-parse-bool raw))
      (:int (let ((n (conf-parse-int raw))
                  (min (config-option-min option)))
              (when (and min (< n min))
                (error "Invalid value for -~A=~A (must be a ~A integer)"
                       name raw (if (zerop min) "non-negative" "positive")))
              n))
      (:money (or (conf-parse-money raw)
                  (error "Invalid amount for -~A=~A" name raw)))
      (:hex (bl.crypto:hex-to-bytes raw))
      (:byte-units (conf-parse-byte-units raw))
      (:loglevel (conf-parse-loglevel raw))
      (:loglevel-global (conf-parse-loglevel-global raw)))))

(defun apply-option-globals (merged)
  "Apply every :GLOBAL / :APPLY row of the option table to the MERGED config
alist, in table order: a present scalar option sets its special (or is
handed to its function) parsed by PARSE-OPTION-VALUE; a repeatable option's
function always runs, with the list of every raw value."
  (dolist (option (global-options))
    (let ((name (config-option-name option)))
      (if (config-option-repeatable option)
          (funcall (config-option-apply option)
                   (loop for (k . v) in merged when (string= k name) collect v))
          (let ((cell (assoc name merged :test #'string=)))
            (when cell
              (let ((value (parse-option-value option (cdr cell))))
                (if (config-option-global option)
                    (setf (symbol-value (config-option-global option)) value)
                    (funcall (config-option-apply option) value)))))))))

(defun apply-config-globals (merged)
  "Set the process-global policy/consensus config specials from the MERGED
config alist: first every option that stands alone (the :GLOBAL / :APPLY
rows of src/config-options.lisp -- policy, consensus overrides, networking
and mempool limits, in table order), then the options whose effect depends
on another option, in Core's order (APPLY-PARAMETER-INTERACTIONS).
CLI-over-file precedence is already applied in MERGED. Called at startup by
start-node-from-args."
  (apply-option-globals merged)
  (apply-parameter-interactions merged))

(defun apply-parameter-interactions (merged)
  "The options whose value depends on ANOTHER option (Core init.cpp Step 2
\"parameter interactions\" and the proxy / reachability block of Step 6),
applied after APPLY-OPTION-GLOBALS so each present-case row has already
run and only the soft-set and consistency halves remain, in this order:
the ZMQ publisher list, -maxmempool under -blocksonly, -dnsseed under
-connect / -maxconnections, -proxy / -onion / -proxyrandomize,
-cjdnsreachable, and -onlynet with its clearnet privacy check."
  (flet ((lk (k) (let ((c (assoc k merged :test #'string=))) (and c (cdr c)))))
    ;; -zmqpub<topic>=<address> [+ -zmqpub<topic>hwm]: recorded now, bound by
    ;; start-node. Nothing is loaded or opened here, so a node with no ZMQ
    ;; options never touches libzmq at all.
    (setf *zmq-publisher-specs* (zmq-specs-from-config merged))
    ;; -maxmempool under -blocksonly: Core soft-sets it to
    ;; DEFAULT_BLOCKSONLY_MAX_MEMPOOL_SIZE_MB = 5 (init.cpp:826) -- "soft",
    ;; so an explicit -maxmempool (applied by its row above) still wins.
    (unless (lk "maxmempool")
      (let ((b (lk "blocksonly")))
        (when (and b (conf-parse-bool b))
          (setf bl.mp:*max-mempool-bytes* (* 5 1000 1000)))))
    ;; -dnsseed under -connect / -maxconnections<=0: with only trusted nodes
    ;; to dial (or connections disabled outright) there is nothing for a DNS
    ;; seed to feed. Soft -- an explicit -dnsseed=1 was applied by its row
    ;; and still wins.
    (unless (lk "dnsseed")
      (when (or (lk "connect")
                (let ((m (lk "maxconnections")))
                  (and m (<= (conf-parse-int m) 0))))
        (setf *dns-seed-enabled* nil)))
    ;; -proxy: run ALL outbound P2P connections through a SOCKS5 proxy
    ;; (Bitcoin Core init.cpp:1698-1762 sets it for every network).
    ;; -noproxy / -proxy=0 clears it. -proxyrandomize (default on) enables
    ;; Tor stream-isolation credentials (init.cpp:1698, netbase.cpp:748-810).
    ;; -onion overrides the proxy for reaching onion services, defaulting to
    ;; -proxy (init.cpp:1764-1790); stored for P1+, nothing dials .onion yet.
    (let ((randomize (let ((v (lk "proxyrandomize")))
                       (if v (conf-parse-bool v) t))))
      (flet ((parse-proxy (value)
               (multiple-value-bind (host port) (conf-parse-proxy value)
                 (when host
                   (bl.net:make-proxy
                    :host host :port port
                    :randomize-credentials randomize)))))
        (let ((v (lk "proxy")))
          (when v
            (setf bl.net:*proxy* (parse-proxy v))))
        (let ((v (lk "onion")))
          ;; The torcontrol client only auto-configures the onion proxy from
          ;; Tor's GETINFO when -onion was never given at all (Core's raw
          ;; GetArg("-onion","") == "" test) — record the raw fact.
          (setf bl.net:*onion-proxy-explicit* (and v t))
          (cond (v (setf bl.net:*onion-proxy* (parse-proxy v)))
                ;; No -onion: onion reachability follows -proxy when one was
                ;; given (Core init.cpp:1764 "An empty string is used to not
                ;; override the onion proxy").
                ((lk "proxy")
                 (setf bl.net:*onion-proxy*
                       bl.net:*proxy*))))))
    ;; Network reachability. -onlynet (repeatable) replaces the reachable set
    ;; (Core init.cpp:1529-1536 g_reachable_nets.RemoveAll + Add per value);
    ;; it restricts AUTOMATIC outbound selection and gossip storage only —
    ;; manual addnode/connect are unaffected. Gated nets then drop out unless
    ;; their transport is configured, and naming a gated net explicitly in
    ;; -onlynet is an init error (Core init.cpp:1541-1546, 1760-1800,
    ;; 2240-2245): onion needs a Tor proxy, I2P needs -i2psam (which we do
    ;; not support at all yet), CJDNS needs -cjdnsreachable.
    (setf bl.net:*cjdns-reachable*
          (let ((v (lk "cjdnsreachable"))) (and v (conf-parse-bool v))))
    (let* ((onlynets (loop for (k . v) in merged
                           when (string= k "onlynet")
                             collect (conf-parse-network-name v)))
           (nets (or onlynets
                     (copy-list bl.net:+bip155-networks+)))
           ;; Effective -listenonion via the shared soft-set chain.
           (listenonion-p (nth-value 1 (conf-effective-listen-flags merged))))
      ;; Keep the user's raw restriction for later transport arrivals (the
      ;; torcontrol GETINFO-discovered onion proxy re-admits :torv3 iff
      ;; -onlynet allows it — Core get_socks_cb).
      (setf bl.net:*onlynet-networks* onlynets)
      (unless bl.net:*onion-proxy*
        (when (member :torv3 onlynets)
          ;; Core init.cpp:1769-1773 / 1788-1798: -onion=0 explicitly forbids
          ;; the Tor route; otherwise -listenonion may still deliver a proxy
          ;; later via the torcontrol connection.
          (cond ((lk "onion")
                 (error "-onlynet=onion given but the proxy for reaching the Tor network is explicitly forbidden: -onion=0"))
                ((not listenonion-p)
                 (error "-onlynet=onion given but no Tor route is configured: none of -proxy, -onion or -listenonion is given"))))
        (setf nets (remove :torv3 nets)))
      (when (member :i2p onlynets)
        (error "-onlynet=i2p given but I2P (SAM) is not supported"))
      (setf nets (remove :i2p nets))
      (unless bl.net:*cjdns-reachable*
        (when (member :cjdns onlynets)
          (error "-onlynet=cjdns given without -cjdnsreachable"))
        (setf nets (remove :cjdns nets)))
      (setf bl.net:*reachable-networks* nets)
      ;; PRIVACY: requesting DNS seeds entails clearnet. Resolving a seed
      ;; hostname is a plaintext DNS query to the local resolver, and the
      ;; addresses it returns are dialed directly over IPv4/IPv6 — so a
      ;; Tor-only node (-onlynet=onion with -listenonion and no -proxy) would
      ;; deanonymize itself on its very first start, defeating the point of
      ;; -onlynet. Core soft-sets -dnsseed=0 when -onlynet excludes IPv4 and
      ;; IPv6 (init.cpp:835-844) and aborts when -dnsseed=1 was given
      ;; explicitly (init.cpp:1691-1693). Soft-set semantics matter: an
      ;; explicit -dnsseed=0 must stay 0, and an explicit 1 is an error rather
      ;; than a silent override.
      (unless (or (member :ipv4 nets) (member :ipv6 nets))
        (cond ((not (lk "dnsseed"))
               (setf *dns-seed-enabled* nil))
              (*dns-seed-enabled*
               (error "Incompatible options: -dnsseed=1 was explicitly specified, but -onlynet forbids connections to IPv4/IPv6")))))))

(defun args->start-node-plist (args &optional conf-text settings-cells)
  ;; CONF-TEXT is the main bitcoin.conf, or a LIST of texts when -includeconf
  ;; pulled in more (main file first). See the docstring below.
  "Pure assembly of a start-node keyword plist from Bitcoin Core-style CLI ARGS
 (a list of strings) and CONF-TEXT — one bitcoin.conf's contents, or a LIST of
them (main file first) when -includeconf pulled in more.

Precedence is Core's (settings.cpp:36): command line, then SETTINGS-CELLS
 (the read-write settings file, already flattened to (name . string) cells by
SETTINGS-ALIST->CONFIG-ALIST), then the [network] section of any config file,
then the global area of any config file.

SETTINGS-CELLS deliberately does NOT take part in resolving the network: Core
reads its chain selectors from the command line and the config file's global
area only, and the settings file lives INSIDE the network directory — letting it
choose the network would make its own location depend on its contents.
Returns (VALUES plist merged-alist network); start-node-from-args (node.lisp)
wraps this with the file I/O, apply-config-globals, and launch."
  (let* ((cli (parse-cli-args args))
         ;; The network is resolved from the CLI plus the config file's GLOBAL
         ;; area — never from inside a section, which is Core's rule (it reads
         ;; the chain selectors with section="", args.cpp:825-829). Resolving it
         ;; from the CLI alone, as this used to, meant a `testnet4=1` written in
         ;; bitcoin.conf left us scoping the file to the DEFAULT network's
         ;; section and silently dropping the whole [testnet4] block.
         (texts (cond ((null conf-text) nil)
                      ((listp conf-text) conf-text)
                      (t (list conf-text))))
         (globals (loop for text in texts append (conf-global-entries text)))
         (network (resolve-network-from-config (append cli globals)))
         ;; Sections from EVERY file outrank globals from every file, because
         ;; Core accumulates them all into one ro_config[section][name] map and
         ;; then consults section before "" — the file boundary is not part of
         ;; the precedence, only the section is.
         (conf (append (loop for text in texts
                             append (parse-bitcoin-conf-sections text network))
                       globals))
         ;; CLI > settings.json > [network] section > global area (Core
         ;; settings.cpp:36, MergeSettings' Source order), which
         ;; PARSE-BITCOIN-CONF has already ordered; first ASSOC wins.
         (merged (append cli settings-cells conf)))
    (values (config-alist->start-node-plist merged network) merged network)))
