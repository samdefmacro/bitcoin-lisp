(in-package #:bitcoin-lisp)

;;; Node configuration
;;;
;;; The process-wide specials the option table sets (assumeutxo overrides,
;;; -blocksonly, wallet fee rails, datacarrier, the protocol's rate limits,
;;; the recent-rejects filter) and the glue that turns a parsed option alist
;;; into START-NODE's keywords and the parameter interactions between them.
;;; Loaded early so that validation, the mempool and the protocol half of
;;; networking can reference these symbols at compile time (the layers below
;;; -- storage, net, rpc-server -- cannot, and do not). The parsers
;;; themselves -- CLI, bitcoin.conf, settings.json, option values -- and the
;;; option registry are the bitcoin-lisp/config sub-system (src/config/),
;;; which knows no chain.

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
          (config-error "Invalid port specified in -port: '~A'" port)))
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
                 (config-error "-onlynet=onion given but the proxy for reaching the Tor network is explicitly forbidden: -onion=0"))
                ((not listenonion-p)
                 (config-error "-onlynet=onion given but no Tor route is configured: none of -proxy, -onion or -listenonion is given"))))
        (setf nets (remove :torv3 nets)))
      (when (member :i2p onlynets)
        (config-error "-onlynet=i2p given but I2P (SAM) is not supported"))
      (setf nets (remove :i2p nets))
      (unless bl.net:*cjdns-reachable*
        (when (member :cjdns onlynets)
          (config-error "-onlynet=cjdns given without -cjdnsreachable"))
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
               (config-error "Incompatible options: -dnsseed=1 was explicitly specified, but -onlynet forbids connections to IPv4/IPv6")))))))

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
Returns (VALUES plist merged-alist network); start-node-from-args (node/init.lisp)
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
