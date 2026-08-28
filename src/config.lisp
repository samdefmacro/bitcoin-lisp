(in-package #:bitcoin-lisp)

;;; Node configuration
;;;
;;; The process-wide specials the option table sets (assumeutxo overrides,
;;; -blocksonly, wallet fee rails, datacarrier, the protocol's rate limits,
;;; the recent-rejects filter). Loaded early so that validation, the mempool
;;; and the protocol half of networking can reference these symbols at
;;; compile time (the layers below -- storage, net, rpc-server -- cannot, and
;;; do not). The parsers -- CLI, bitcoin.conf, settings.json, option values
;;; -- and the option registry are the bitcoin-lisp/config sub-system
;;; (src/config/); the glue that turns a parsed alist into START-NODE's
;;; keywords and applies the parameter interactions is the node's
;;; (src/node/args.lisp), loaded after every layer it names.

;;;; Chain-work and assumevalid overrides

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
than in src/node/, which reads it, because APPLY-CONFIG-GLOBALS sets it and
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

(defconstant +max-message-payload+ (* 4 1000 1000)
  "Maximum P2P message payload size in bytes: 4,000,000, matching Bitcoin Core
MAX_PROTOCOL_MESSAGE_LENGTH (net.h). Not 4 MiB -- Core uses decimal 4e6.")

(defparameter +handshake-timeout-seconds+ 60
  "Maximum seconds a peer has to complete the version handshake, settable with
-peertimeout (Core DEFAULT_PEER_CONNECT_TIMEOUT, net.h:87).

Was 30 with no stated source. Core allows 60, so a peer on a slow link that
Core would keep, we dropped — and re-dialling it costs more than waiting. A
DEFPARAMETER because Core exposes the knob; the +NAME+ spelling is kept because
every caller reads it as a constant.")

(defvar *recent-rejects-max-size* 50000
  "Maximum entries in the recent transaction rejects filter.")
