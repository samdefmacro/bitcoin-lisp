(in-package #:bitcoin-lisp)

#+sbcl
(eval-when (:compile-toplevel :load-toplevel :execute)
  (require :sb-sprof))

;;; Bitcoin Node
;;;
;;; Main entry point for the Bitcoin full node.
;;; Coordinates all subsystems: networking, storage, validation.

;;;; Network Configuration

(defconstant +testnet3+ :testnet3)
(defconstant +testnet4+ :testnet4)
(defconstant +signet+ :signet)
(defconstant +mainnet+ :mainnet)

(defconstant +regtest+ :regtest)

(defvar *network* +testnet4+
  "Current network mode (:testnet3, :testnet4, :signet, :regtest, or :mainnet).")

(defun network-magic (network)
  "Return the network magic bytes for NETWORK."
  (ecase network
    (:testnet3 bitcoin-lisp.serialization:+testnet3-magic+)
    (:testnet4 bitcoin-lisp.serialization:+testnet4-magic+)
    (:signet bitcoin-lisp.serialization:+signet-magic+)
    (:regtest bitcoin-lisp.serialization:+regtest-magic+)
    (:mainnet bitcoin-lisp.serialization:+mainnet-magic+)))

(defun network-port (network)
  "Return the default port for NETWORK."
  (ecase network
    (:testnet3 18333)
    (:testnet4 48333)
    (:signet 38333)
    (:regtest 18444)
    (:mainnet 8333)))

(defun network-dns-seeds (network)
  "Return the DNS seeds for NETWORK."
  (ecase network
    (:testnet3 bitcoin-lisp.networking:*testnet3-dns-seeds*)
    (:testnet4 bitcoin-lisp.networking:*testnet4-dns-seeds*)
    (:signet bitcoin-lisp.networking:*signet-dns-seeds*)
    (:regtest bitcoin-lisp.networking:*regtest-dns-seeds*)
    (:mainnet bitcoin-lisp.networking:*mainnet-dns-seeds*)))

(defun network-rpc-port (network)
  "Return the default RPC port for NETWORK."
  (ecase network
    (:testnet3 18332)
    (:testnet4 48332)
    (:signet 38332)
    (:regtest 18443)
    (:mainnet 8332)))

(defvar *mainnet-relay-enabled* nil
  "Whether transaction relay is enabled on mainnet. Default NIL for safety.")

(defconstant +max-inbound-peers+ 64
  "Maximum number of inbound peers to keep (Bitcoin Core allows 125 by default;
we cap lower). Excess inbound connections are disconnected at merge time.")

;;;; Node State

(defstruct node
  "Bitcoin node state."
  (network :testnet3 :type keyword)
  (data-directory nil :type (or null pathname))
  ;; Chainstates, ordered like Core ChainstateManager::m_chainstates
  ;; (validation.h:1377): exactly one today (the primary, fully-validated
  ;; chainstate, owning the coins view); an assumeutxo snapshot activation
  ;; appends a second. Read via node-current-chainstate /
  ;; node-historical-chainstate / node-validated-chainstate, or the
  ;; node-chain-state / node-utxo-set compatibility accessors below.
  (chainstates '() :type list)
  (block-store nil)
  (mempool nil)
  (tx-index nil)  ; Transaction index (optional, for getrawtransaction)
  (blockfilterindex nil)  ; BIP158 basic block filter index (optional)
  (coinstatsindex nil)  ; per-height UTXO stats + MuHash index (optional)
  (fee-estimator nil)  ; Fee rate estimator for estimatesmartfee
  (address-book nil)  ; Persistent peer address database
  (recent-rejects nil)  ; Recently rejected transaction filter (DoS protection)
  (peers '() :type list)
  (running nil :type boolean)
  (log-level :info :type keyword)
  (sync-thread nil :type (or null bt:thread))
  (syncing nil :type boolean)
  ;; Inbound listening: server socket + accept thread, and a lock-guarded
  ;; hand-off list. The listener thread pushes handshaked inbound peers onto
  ;; pending-inbound-peers (under LOCK); the sync thread merges them into PEERS,
  ;; keeping PEERS single-writer so the drain loop never races a push.
  (listener-socket nil)
  (listener-thread nil :type (or null bt:thread))
  (pending-inbound-peers '() :type list)
  (lock (bt:make-recursive-lock "node-lock"))
  (known-addresses '() :type list)
  ;; setnetworkactive: when NIL, the node makes no new outbound connections and
  ;; accepts no inbound ones (existing peers are dropped on toggle-off).
  (network-active t :type boolean)
  ;; addnode "add": manually-pinned peer specs ("host" or "host:port") that the
  ;; maintenance loop keeps connected, independent of max-peers.
  (added-nodes '() :type list)
  ;; addnode "onetry": one-shot dial requests handed off to the sync thread so
  ;; node-peers stays single-writer (only the sync thread pushes to it).
  (pending-onetry '() :type list)
  (max-peers 8 :type (unsigned-byte 8)))

;;; Chainstate selection (Core ChainstateManager, validation.h:1119-1145).
;;; With one chainstate all three return it.

(defun node-current-chainstate (node)
  "The chainstate targeting the network tip (Core CurrentChainstate). New
blocks extend it, the mempool validates against its coins view, and RPC
reports it as the active chainstate."
  (bitcoin-lisp.storage:select-current-chainstate (node-chainstates node)))

(defun node-historical-chainstate (node)
  "The chainstate re-deriving history toward a snapshot base block (Core
HistoricalChainstate); NIL when no background validation is in progress."
  (bitcoin-lisp.storage:select-historical-chainstate (node-chainstates node)))

(defun node-validated-chainstate (node)
  "The fully-validated chainstate (Core ValidatedChainstate) — the one
indexes bind to, since they index blocks in order from genesis."
  (bitcoin-lisp.storage:select-validated-chainstate (node-chainstates node)))

;;; Compatibility accessors for the former chain-state / utxo-set node slots.
;;; The chain-state struct now owns its coins view, and the node holds a
;;; chainstates list; these read/write the current chainstate so existing
;;; call sites (and tests) keep their single-chainstate shape.

(defun node-chain-state (node)
  "The current (active) chainstate — the former chain-state slot."
  (node-current-chainstate node))

(defun (setf node-chain-state) (chainstate node)
  "Install CHAINSTATE as the node's current chainstate, replacing an existing
one. A replaced chainstate's coins view carries over when CHAINSTATE has
none, preserving the former independent-slot semantics (setting chain-state
never clobbered utxo-set)."
  (let ((old (node-current-chainstate node)))
    (when (and old (null (bitcoin-lisp.storage:chain-state-coins-view chainstate)))
      (setf (bitcoin-lisp.storage:chain-state-coins-view chainstate)
            (bitcoin-lisp.storage:chain-state-coins-view old)))
    (setf (node-chainstates node)
          (if old
              (substitute chainstate old (node-chainstates node))
              (append (node-chainstates node) (list chainstate)))))
  chainstate)

(defun node-utxo-set (node)
  "The current chainstate's coins view — the former utxo-set slot."
  (let ((cs (node-current-chainstate node)))
    (and cs (bitcoin-lisp.storage:chain-state-coins-view cs))))

(defun (setf node-utxo-set) (view node)
  "Set the current chainstate's coins view — the former utxo-set slot."
  (let ((cs (node-current-chainstate node)))
    (unless cs
      (error "Cannot set the node's utxo-set: no current chainstate exists"))
    (setf (bitcoin-lisp.storage:chain-state-coins-view cs) view)))

(defvar *node* nil
  "Current running node instance.")

(defvar *node-start-time* nil
  "Unix time the node was started (set by start-node); basis for the uptime RPC.")

;;;; Logging (macros and core functions defined in logging.lisp)

(defun show-logs (&key (n 20) (level :debug))
  "Show the last N log entries at or above LEVEL.
LEVEL can be :debug, :info, :warn, or :error."
  (let ((entries '())
        (min-level (log-level-value level)))
    (bt:with-lock-held (*log-buffer-lock*)
      (let ((start (if (< *log-buffer-count* +log-buffer-size+)
                       0
                       *log-buffer-index*)))
        (dotimes (i *log-buffer-count*)
          (let* ((idx (mod (+ start i) +log-buffer-size+))
                 (entry (aref *log-buffer* idx)))
            (when entry
              (push entry entries))))))
    ;; entries is now oldest-first after reverse
    (setf entries (nreverse entries))
    ;; Filter by level and take last n
    (let ((filtered (remove-if-not
                     (lambda (entry)
                       (let ((level-str (and (> (length entry) 22)
                                             (subseq entry 22 (position #\: entry :start 22)))))
                         (when level-str
                           (let ((entry-level (find-symbol (string-upcase (string-trim " " level-str)) :keyword)))
                             (and entry-level
                                  (>= (log-level-value entry-level) min-level))))))
                     entries)))
      (let ((to-show (last filtered n)))
        (format t "~%=== Last ~D Log Entries ===~%" (length to-show))
        (dolist (entry to-show)
          (format t "~A~%" entry))
        (format t "~%")
        (length to-show)))))

(defun clear-logs ()
  "Clear the log buffer."
  (bt:with-lock-held (*log-buffer-lock*)
    (dotimes (i +log-buffer-size+)
      (setf (aref *log-buffer* i) nil))
    (setf *log-buffer-index* 0)
    (setf *log-buffer-count* 0))
  t)

(defun enable-console-logging ()
  "Enable logging to the console (REPL)."
  (setf *log-stream* *standard-output*)
  t)

(defun disable-console-logging ()
  "Disable logging to the console. Logs still go to buffer and file."
  (setf *log-stream* nil)
  t)

(defun start-file-logging (path)
  "Start logging to a file at PATH."
  (when *log-file-stream*
    (close *log-file-stream*))
  (setf *log-file-stream* (open path :direction :output
                                     :if-exists :append
                                     :if-does-not-exist :create))
  (format t "Logging to file: ~A~%" path)
  path)

(defun stop-file-logging ()
  "Stop logging to file."
  (when *log-file-stream*
    (close *log-file-stream*)
    (setf *log-file-stream* nil))
  t)

;;;; Genesis block headers
;;; Genesis parameters from Bitcoin Core chainparams.cpp

(defvar *genesis-merkle-root*
  (bitcoin-lisp.crypto:hex-to-bytes
   "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a")
  "Genesis block merkle root (little-endian). Same for mainnet and testnet.")

(defun make-genesis-header (network)
  "Construct the genesis block header for NETWORK."
  (let ((prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (ecase network
      (:testnet3
       (bitcoin-lisp.serialization:make-block-header
        :version 1 :prev-block prev-block
        :merkle-root (copy-seq *genesis-merkle-root*)
        :timestamp 1296688602 :bits #x1d00ffff :nonce 414098458))
      (:testnet4
       (bitcoin-lisp.serialization:make-block-header
        :version 1 :prev-block prev-block
        :merkle-root (copy-seq *genesis-merkle-root*)
        :timestamp 1714777860 :bits #x1d00ffff :nonce 393743547))
      (:signet
       (bitcoin-lisp.serialization:make-block-header
        :version 1 :prev-block prev-block
        :merkle-root (copy-seq *genesis-merkle-root*)
        :timestamp 1598918400 :bits #x1e0377ae :nonce 52613770))
      (:regtest
       (bitcoin-lisp.serialization:make-block-header
        :version 1 :prev-block prev-block
        :merkle-root (copy-seq *genesis-merkle-root*)
        :timestamp 1296688602 :bits #x207fffff :nonce 2))
      (:mainnet
       (bitcoin-lisp.serialization:make-block-header
        :version 1 :prev-block prev-block
        :merkle-root (copy-seq *genesis-merkle-root*)
        :timestamp 1231006505 :bits #x1d00ffff :nonce 2083236893)))))

;;;; Startup Sequence

(defun init-node (data-directory &key (network :testnet3) (log-level :info))
  "Initialize a new node with the given data directory and network.
For mainnet, data is stored in a 'mainnet' subdirectory.
For testnet, data stays at the base directory (backward compatible)."
  ;; Validate network parameter
  (unless (member network '(:testnet3 :testnet4 :signet :regtest :mainnet))
    (error "Invalid network: ~A. Must be :testnet3, :testnet4, :signet, :regtest, or :mainnet." network))

  ;; Set global network variable
  (setf *network* network)

  ;; Network-aware PoW limit: regtest's trivial limit, the standard limit
  ;; otherwise. derive-target / check-proof-of-work reject targets above it.
  (setf bitcoin-lisp.storage:*pow-limit-target*
        (if (eq network :regtest)
            bitcoin-lisp.storage:+regtest-pow-limit-target+
            bitcoin-lisp.storage:+pow-limit-target+))

  ;; Calculate data path - each network uses its own subdirectory
  (let* ((base-path (pathname data-directory))
         (data-path (ecase network
                      (:testnet3 base-path)
                      (:testnet4 (merge-pathnames "testnet4/" base-path))
                      (:signet (merge-pathnames "signet/" base-path))
                      (:regtest (merge-pathnames "regtest/" base-path))
                      (:mainnet (merge-pathnames "mainnet/" base-path)))))
    ;; Ensure data directory exists
    (ensure-directories-exist (merge-pathnames "dummy" data-path))

    ;; Set network configuration
    (setf bitcoin-lisp.serialization:*network-magic* (network-magic network))
    (setf bitcoin-lisp.networking:*current-port* (network-port network))
    (setf bitcoin-lisp.networking:*dns-seeds* (network-dns-seeds network))

    ;; Create node instance
    (make-node :network network
               :data-directory data-path
               :log-level log-level)))

;;;; Inbound listening

(defun count-inbound-peers (node)
  (count-if #'bitcoin-lisp.networking:peer-inbound (node-peers node)))

(defun merge-inbound-peers (node)
  "Move handshaked inbound peers from the lock-guarded hand-off list into the
node's peer list (capped at +max-inbound-peers+; excess are disconnected). Called
by the sync thread, so PEERS stays single-writer."
  (let ((pending (bt:with-recursive-lock-held ((node-lock node))
                   (prog1 (node-pending-inbound-peers node)
                     (setf (node-pending-inbound-peers node) nil)))))
    ;; node-peers is written only by the sync thread, but RPC threads read it
    ;; under node-lock; hold the lock around the count + push so those reads see
    ;; a consistent set. Recursive: evict-discouraged-inbound re-takes it.
    (dolist (peer pending)
      (bt:with-recursive-lock-held ((node-lock node))
        (cond
          ((< (count-inbound-peers node) +max-inbound-peers+)
           (push peer (node-peers node)))
          ;; At capacity: a discouraged existing inbound peer is preferred for
          ;; eviction (Bitcoin Core), so make room for the newcomer if we can.
          ((evict-discouraged-inbound node)
           (push peer (node-peers node)))
          ;; Otherwise evict the least valuable inbound peer (protecting the
          ;; most valuable) so slots churn toward better peers instead of the
          ;; newcomer always losing — Core's AttemptToEvictConnection.
          ((evict-least-valuable-inbound node)
           (push peer (node-peers node)))
          (t
           (log-info "Inbound peer cap reached; dropping ~A"
                     (bitcoin-lisp.networking:peer-address peer))
           (bitcoin-lisp.networking:disconnect-peer peer)))))))

(defun evict-discouraged-inbound (node)
  "If any existing inbound peer is discouraged, disconnect it and return T so a
new inbound connection can take its slot. NIL if none are discouraged."
  (bt:with-recursive-lock-held ((node-lock node))
    (let ((victim (find-if (lambda (p)
                             (and (bitcoin-lisp.networking:peer-inbound p)
                                  (bitcoin-lisp.networking:peer-discouraged-p
                                   (bitcoin-lisp.networking:peer-address p))))
                           (node-peers node))))
      (when victim
        (log-info "Evicting discouraged inbound peer ~A to admit a new connection"
                  (bitcoin-lisp.networking:peer-address victim))
        (setf (node-peers node) (remove victim (node-peers node)))
        (bitcoin-lisp.networking:disconnect-peer victim)
        t))))

(defparameter +inbound-eviction-protect-count+ 4
  "Per protection dimension (lowest ping, longest connected), how many inbound
peers to shield from eviction — the spirit of Bitcoin Core's
AttemptToEvictConnection protected set.")

(defun evict-least-valuable-inbound (node)
  "At inbound capacity with no discouraged peer to drop, evict the least
valuable inbound peer so a new connection can take the slot — stopping an
attacker from filling inbound slots with cheap, sticky connections (the current
behavior was to always drop the newcomer, which never churns toward better
peers). Protects the most valuable inbound peers along two dimensions (lowest
ping latency, longest connected); among the unprotected rest, evicts from the
most-represented /16 netgroup, youngest first. Mirrors the intent of Core's
AttemptToEvictConnection. Returns T if a peer was evicted."
  (bt:with-recursive-lock-held ((node-lock node))
    (let ((inbound (remove-if-not #'bitcoin-lisp.networking:peer-inbound
                                  (node-peers node))))
      (when (cdr inbound)               ; need >1 so something stays protected
        (let* ((by-ping (stable-sort
                         (copy-list inbound) #'<
                         :key (lambda (p)
                                (let ((l (bitcoin-lisp.networking:peer-ping-latency p)))
                                  (if (plusp l) l most-positive-fixnum)))))
               (by-age (stable-sort   ; oldest (smallest connect-time) first
                        (copy-list inbound) #'<
                        :key #'bitcoin-lisp.networking:peer-connect-time))
               (n (min +inbound-eviction-protect-count+ (length inbound)))
               (protected (union (subseq by-ping 0 n) (subseq by-age 0 n)))
               (candidates (remove-if (lambda (p) (member p protected)) inbound)))
          (when candidates
            (let ((groups (make-hash-table :test 'equal)))
              (flet ((grp (p) (or (bitcoin-lisp.networking:ip-netgroup
                                   (bitcoin-lisp.networking:peer-address p))
                                  "_")))
                (dolist (p candidates) (incf (gethash (grp p) groups 0)))
                (let ((victim (first (stable-sort
                                      candidates
                                      (lambda (a b)
                                        (let ((ga (gethash (grp a) groups 0))
                                              (gb (gethash (grp b) groups 0)))
                                          (if (/= ga gb)
                                              (> ga gb)  ; most-populous netgroup first
                                              ;; then youngest (largest connect-time)
                                              (> (bitcoin-lisp.networking:peer-connect-time a)
                                                 (bitcoin-lisp.networking:peer-connect-time b)))))))))
                  (when victim
                    (log-info "Evicting least-valuable inbound peer ~A to admit a new connection"
                              (bitcoin-lisp.networking:peer-address victim))
                    (setf (node-peers node) (remove victim (node-peers node)))
                    (bitcoin-lisp.networking:disconnect-peer victim)
                    t))))))))))

(defun run-inbound-listener (node)
  "Accept inbound connections, handshake each, and hand the ready peer to the
sync thread via pending-inbound-peers. Runs until the node stops. The handshake
runs inline (serial accept) with a short timeout, so a silent peer stalls the
loop only briefly; a thread pool is a future refinement."
  (loop while (node-running node)
        do (handler-case
               ;; setnetworkactive off: don't accept inbound connections.
               (if (not (node-network-active node))
                   (sleep 1)
               (let ((conn (bitcoin-lisp.networking:accept-connection
                            (node-listener-socket node) :timeout 1)))
                 (when conn
                   (let ((peer (bitcoin-lisp.networking:make-inbound-peer
                                conn (bitcoin-lisp.networking:connection-host conn))))
                     (if (bitcoin-lisp.networking:perform-inbound-handshake peer)
                         (progn
                           (bitcoin-lisp.networking:send-post-handshake-messages peer)
                           (bitcoin-lisp.networking:send-compact-block-negotiation peer)
                           (bt:with-recursive-lock-held ((node-lock node))
                             (push peer (node-pending-inbound-peers node)))
                           (log-info "Inbound peer ~A (~A) handshake complete"
                                     (bitcoin-lisp.networking:peer-address peer)
                                     (bitcoin-lisp.networking:peer-user-agent peer)))
                         (bitcoin-lisp.networking:disconnect-peer peer))))))
             (error (c)
               (log-debug "Inbound accept/handshake error: ~A" c)))))

(defun start-inbound-listener (node bind)
  "Open the listening socket and spawn the accept thread. No-op (logged) if the
port can't be bound."
  (let ((sock (bitcoin-lisp.networking:open-listener bind (network-port (node-network node)))))
    (if (null sock)
        (log-warn "Inbound listening disabled: could not bind ~A:~D"
                  bind (network-port (node-network node)))
        (progn
          (setf (node-listener-socket node) sock)
          (setf (node-listener-thread node)
                (bt:make-thread (lambda () (run-inbound-listener node))
                                :name "bitcoin-inbound-listener"))
          (log-info "Listening for inbound peers on ~A:~D"
                    bind (network-port (node-network node)))))))

(defun load-mempool-from-disk
    (node &optional (path (bitcoin-lisp.mempool:mempool-dat-path (node-data-directory node))))
  "Load a mempool.dat-format file through the normal acceptance path (Core
LoadMempool): prioritisation deltas first (so fee policy sees them), then per-tx
validation against the current UTXO set — stale entries (spent inputs, reorged
context) simply fail and are dropped. Entries are loaded regardless of age (no
expiry filter, unlike Core): mempool-expire prunes old entries on the next block
connection anyway. Residual deltas (txs not in the saved pool) are re-applied
last. PATH defaults to the node's mempool.dat; the importmempool RPC passes an
arbitrary file. Returns (values accepted failed residual-count) on success, or
NIL if the file is missing or corrupt."
  (when (and path (probe-file path))
      (multiple-value-bind (entries residual ok)
          (bitcoin-lisp.mempool:read-mempool-file path)
        (unless ok
          (log-warn "mempool file ~A unreadable or corrupt" path)
          (return-from load-mempool-from-disk nil))
        (let ((mempool (node-mempool node))
              (utxo-set (node-utxo-set node))
              (chain-state (node-chain-state node))
              (accepted 0) (failed 0))
          (dolist (rec entries)
            (destructuring-bind (tx entry-time delta) rec
              (let ((txid (bitcoin-lisp.serialization:transaction-hash tx))
                    (height (bitcoin-lisp.storage:current-height chain-state)))
                (unless (zerop delta)
                  (bitcoin-lisp.mempool:mempool-prioritise mempool txid delta))
                (multiple-value-bind (valid error fee replaced)
                    (bitcoin-lisp.validation:validate-transaction-for-mempool
                     tx utxo-set mempool height)
                  (declare (ignore error))
                  (cond
                    (valid
                     (if (eq :ok (bitcoin-lisp.mempool:accept-validated-tx
                                  mempool txid tx fee height
                                  :entry-time entry-time :replaced replaced))
                         (incf accepted)
                         (incf failed)))
                    (t (incf failed)))))))
          (dolist (pair residual)
            (bitcoin-lisp.mempool:mempool-prioritise mempool (car pair) (cdr pair)))
          (log-info "Imported mempool: ~D accepted, ~D failed, ~D residual deltas"
                    accepted failed (length residual))
          (values accepted failed (length residual))))))

;;; --- Chainstate crash recovery -------------------------------------------
;;;
;;; do-flush is a 3-phase commit (see do-flush): Phase 1 marks chainstate.dat
;;; in-transition, Phase 2 commits the UTXO LevelDB in ONE atomic writebatch,
;;; Phase 3 clears the marker. A crash between Phase 1 and Phase 3 leaves the
;;; marker set. Because Phase 2 is a single atomic batch, the on-disk UTXO set
;;; is at EXACTLY the new tip (Phase 2 finished) or the previous committed tip
;;; (Phase 2 hadn't run) — never a torn mix. We tell the two apart by probing
;;; coinbase outputs and rewrite chainstate.dat to match the UTXO set, instead
;;; of the old "move aside and re-sync from genesis" — mirrors Bitcoin Core
;;; resolving its DB_HEAD_BLOCKS marker on startup rather than reindexing.

(defvar *pending-chainstate-recovery* nil
  "List of chainstates whose load-state reported :inconsistent, so their
recovery runs after the block store, UTXO caches, and header index are all
open. Per-chainstate: the primary and a snapshot chainstate recover
independently against their own state files and coins views.")

(defun %coinbase-committed-p (node chainstate block-hash)
  "T iff BLOCK-HASH's coinbase output 0 is an unspent coin in CHAINSTATE's
coins view. A coinbase is unspendable for +coinbase-maturity+ (100) blocks,
so once its block is committed to the UTXO set the coin is necessarily
present — and every block above the committed tip contributes no coins at
all. That makes coinbase-presence a monotone probe for 'is the UTXO set at
or past this block', with no false positives from later spends. Returns
NIL if the block isn't on disk (the block store is shared across
chainstates)."
  (let ((block (bitcoin-lisp.storage:get-block (node-block-store node) block-hash)))
    (when block
      (let* ((cb (first (bitcoin-lisp.serialization:bitcoin-block-transactions block)))
             (txid (bitcoin-lisp.serialization:transaction-hash cb)))
        (and (bitcoin-lisp.storage:get-utxo
              (bitcoin-lisp.storage:chain-state-coins-view chainstate) txid 0)
             t)))))

(defun recover-inconsistent-chainstate
    (node &optional (chain-state (node-current-chainstate node)))
  "Resolve an in-transition chainstate without a from-genesis resync.
Per-chainstate: probes CHAIN-STATE's own coins view and rewrites its own
state file (storage-suffix-named), so recovering one chainstate can never
touch another's on-disk state. The 3-phase commit semantics are unchanged.
Probes whether the recorded tip's coins were committed; if so just clears
the marker, otherwise walks back to the highest ancestor whose coins ARE
committed (the true UTXO tip) and rewrites the state file there so IBD
re-validates only the gap. Returns T on success, NIL if the blocks needed
to resolve it aren't on disk (caller then aborts for a resync).

For a snapshot chainstate, its base block is always treated as committed:
the populate step verified and durably flushed the whole snapshot UTXO set
before the chainstate ever existed, and its coins only move forward from
there — so both the tip==base case (nothing dirty could have been flushed)
and the walk-back floor (rewind to the base, whose coins ARE the verified
snapshot) resolve without probing blocks below the base, which are not on
disk on the snapshot side."
  (let* ((new-hash (bitcoin-lisp.storage:best-block-hash chain-state))
         (new-height (bitcoin-lisp.storage:current-height chain-state))
         (snapshot-base (bitcoin-lisp.storage:chain-state-from-snapshot-blockhash
                         chain-state)))
    (flet ((committed-p (hash)
             (or (and snapshot-base (equalp hash snapshot-base))
                 (%coinbase-committed-p node chain-state hash))))
      (cond
        ((null new-hash)
         (log-error "Chainstate recovery: no recorded tip to recover from")
         nil)
        ;; Phase 2 committed the new tip — chainstate.dat already holds it,
        ;; just drop the marker.
        ((committed-p new-hash)
         (bitcoin-lisp.storage:save-state chain-state :in-transition nil)
         (log-info "Chainstate recovery: UTXO set already at recorded tip h=~D; marker cleared"
                   new-height)
         t)
        ;; UTXO set is behind: find the real tip by walking back.
        (t
         (let ((entry (bitcoin-lisp.storage:get-block-index-entry chain-state new-hash)))
           (loop while entry
                 do (setf entry (bitcoin-lisp.storage:block-index-entry-prev-entry entry))
                 until (or (null entry)
                           (committed-p
                            (bitcoin-lisp.storage:block-index-entry-hash entry))))
           (cond
             (entry
              (let ((h (bitcoin-lisp.storage:block-index-entry-height entry))
                    (hash (bitcoin-lisp.storage:block-index-entry-hash entry)))
                ;; pruned-height is left as recorded — pruning is monotone and
                ;; lags the tip by the whole block window, so it is far below
                ;; this rewind point and those files are gone regardless.
                (setf (bitcoin-lisp.storage::chain-state-best-block-hash chain-state) hash
                      (bitcoin-lisp.storage::chain-state-best-height chain-state) h)
                (bitcoin-lisp.storage:save-state chain-state :in-transition nil)
                (log-warn "Chainstate recovery: UTXO set at h=~D (recorded tip h=~D); rewound chainstate.dat ~D block~:P, will re-validate the gap"
                          h new-height (- new-height h))
                t))
             (t
              (log-error "Chainstate recovery: no committed ancestor found on disk (blocks pruned below the UTXO tip?); resync required")
              nil))))))))

;;; --- Assumeutxo snapshot chainstate lifecycle ------------------------------
;;;
;;; Core model (validation.cpp ActivateSnapshot/AddChainstate + node/
;;; chainstate.cpp LoadChainstate): a verified snapshot becomes a SECOND
;;; chainstate with storage suffix "_snapshot", status :unvalidated (never
;;; persisted — re-derived every startup), sharing the block index / block
;;; store / undo storage with the primary. The primary is retargeted at the
;;; snapshot base and becomes the HISTORICAL chainstate, re-deriving history
;;; in the background while the snapshot chainstate follows the network tip.
;;; The only persistent marker is chainstate_snapshot/base_blockhash.
;;;
;;; The streaming/verification half of activation (Core
;;; PopulateAndValidateSnapshot) lives with the loadtxoutset RPC
;;; (rpc/methods.lisp), which parses the snapshot format; the chainstate
;;; mechanics live here.

(defun call-with-sync-paused (node thunk)
  "Run THUNK with the sync thread's IBD loops paused — the coarse equivalent
of Core holding cs_main across snapshot activation. Requests an IBD stop,
waits (bounded) for the in-progress sync-blockchain pass to unwind, runs
THUNK, then clears the stop request so the next sync cycle resumes against
the (possibly changed) chainstate arrangement. A no-op without a live sync
thread (tests, :sync nil nodes)."
  (if (and (node-sync-thread node)
           (bt:thread-alive-p (node-sync-thread node)))
      (progn
        (bitcoin-lisp.networking:request-ibd-stop)
        (loop repeat 600                ; <= 120s; the IBD loops poll the flag
              while (node-syncing node)
              do (sleep 0.2))
        (when (node-syncing node)
          (log-warn "Sync pass did not pause within 120s; proceeding with snapshot activation anyway"))
        (unwind-protect (funcall thunk)
          (bitcoin-lisp.networking:reset-ibd-stop)))
      (funcall thunk)))

(defun %make-snapshot-chainstate (node base-hash)
  "The snapshot chain-state struct for BASE-HASH: status :unvalidated (Core
derives it from from_snapshot_blockhash, validation.cpp:1868 — never
persisted), storage suffix \"_snapshot\", and the block index SHARED with
the primary chainstate (Core keeps it in m_blockman, outside any
chainstate). Used by both activation (create-snapshot-chainstate) and
startup re-detection (load-snapshot-chainstate)."
  (let ((primary (node-current-chainstate node)))
    (bitcoin-lisp.storage:make-chain-state
     :base-path (node-data-directory node)
     :genesis-hash (bitcoin-lisp.storage::chain-state-genesis-hash primary)
     :block-index (bitcoin-lisp.storage::chain-state-block-index primary)
     :from-snapshot-blockhash (copy-seq base-hash)
     :assumeutxo-status :unvalidated
     :storage-suffix "_snapshot")))

(defun create-snapshot-chainstate (node base-hash)
  "Construct an :unvalidated snapshot chainstate for BASE-HASH with a fresh
coins LevelDB at <data-dir>/chainstate_snapshot/ (Core ActivateSnapshot's
Chainstate construction + InitCoinsDB). Stale on-disk leftovers from an
aborted or unadoptable earlier activation are removed first — startup
adopts any intact snapshot chainstate, so anything still here is refuse.
The caller owns cleanup on failure (abort-snapshot-chainstate)."
  (let ((snap (%make-snapshot-chainstate node base-hash)))
    (when (bitcoin-lisp.storage:find-assumeutxo-chainstate-dir
           (node-data-directory node))
      (log-warn "[snapshot] removing stale snapshot chainstate leftovers before activation")
      (bitcoin-lisp.storage:delete-snapshot-chainstate-files
       (node-data-directory node)))
    (bitcoin-lisp.storage:open-chainstate-coins-view snap)
    snap))

(defun abort-snapshot-chainstate (node snap)
  "Tear down SNAP mid-activation (Core cleanup_bad_snapshot): close its coins
DB (releasing the LevelDB lock) and delete its on-disk footprint. Never
signals — this runs on the activation failure path."
  (bitcoin-lisp.storage:close-chainstate-coins-view snap)
  (ignore-errors
    (bitcoin-lisp.storage:delete-snapshot-chainstate-files
     (node-data-directory node)))
  nil)

(defun add-snapshot-chainstate (node snap)
  "Adopt a populated, verified snapshot chainstate (Core AddChainstate,
validation.cpp:6189-6206): retarget the previously-current chainstate at the
snapshot base — making it the historical chainstate — and append SNAP, which
select-current-chainstate then returns as the new current chainstate.

The mempool needs no explicit hand-off (Core swaps the pointer): ours lives
on the node and every mempool call site reads the CURRENT chainstate's coins
view, which this swap redirects. Callers must have verified the mempool is
empty first (Core asserts it). Core's PopulateBlockIndexCandidates has no
equivalent here — our fork choice is per-block (activate-block) and the
historical chainstate's candidate filtering is the target guard there."
  (let* ((prev (node-current-chainstate node))
         (base-hash (bitcoin-lisp.storage:chain-state-from-snapshot-blockhash snap))
         (base-entry (bitcoin-lisp.storage:get-block-index-entry prev base-hash)))
    (assert (eq (bitcoin-lisp.storage:chain-state-assumeutxo-status prev) :validated))
    (assert (null (bitcoin-lisp.storage:chain-state-target-blockhash prev)))
    (assert base-entry)
    (bitcoin-lisp.storage:set-chainstate-target prev base-entry)
    (bt:with-recursive-lock-held ((node-lock node))
      (setf (node-chainstates node)
            (append (node-chainstates node) (list snap))))
    (log-info "[snapshot] successfully activated snapshot ~A: current chainstate now at height ~D following the network tip; historical chainstate (h=~D) re-derives history toward the base in the background"
              (bitcoin-lisp.crypto:bytes-to-hex base-hash)
              (bitcoin-lisp.storage:current-height snap)
              (bitcoin-lisp.storage:current-height prev))
    snap))

(defun load-snapshot-chainstate (node)
  "Detect and re-adopt a persisted snapshot chainstate at startup (Core
LoadAssumeutxoChainstate, validation.cpp:6170-6187, in node/chainstate.cpp
LoadChainstate ordering). The chainstate_snapshot/ dir plus its
base_blockhash marker are the only persistent evidence; assumeutxo-status is
re-derived as :unvalidated (never persisted). Must run after the primary
chainstate's header index is loaded — the base entry has to resolve — and
before crash-recovery resolution (a torn snapshot flush joins
*pending-chainstate-recovery*). Returns the snapshot chainstate or NIL."
  (let* ((data-dir (node-data-directory node))
         (dir (bitcoin-lisp.storage:find-assumeutxo-chainstate-dir data-dir)))
    (when dir
      (let* ((base-hash (bitcoin-lisp.storage:read-snapshot-base-blockhash dir))
             (primary (node-current-chainstate node))
             (base-entry (and base-hash
                              (bitcoin-lisp.storage:get-block-index-entry
                               primary base-hash))))
        (cond
          ((null base-hash)
           (log-warn "[snapshot] snapshot chainstate dir is malformed! no base blockhash file exists at path ~A. Try deleting ~A and calling loadtxoutset again"
                     (namestring (bitcoin-lisp.storage:snapshot-base-blockhash-path dir))
                     (namestring dir))
           nil)
          ((null base-entry)
           ;; Header index lost/regressed below the base. Leave the snapshot
           ;; chainstate on disk and run single-chainstate this boot; once
           ;; headers re-cover the base, the next restart adopts it.
           (log-warn "[snapshot] snapshot base block ~A is not in the header index; not loading the snapshot chainstate this run"
                     (bitcoin-lisp.crypto:bytes-to-hex base-hash))
           nil)
          (t
           (log-info "[snapshot] detected active snapshot chainstate (~A) - loading"
                     (namestring dir))
           (let ((snap (%make-snapshot-chainstate node base-hash))
                 (base-height (bitcoin-lisp.storage:block-index-entry-height base-entry)))
             ;; Tip from chainstate_snapshot.dat; a torn flush defers to the
             ;; per-chainstate recovery pass; a missing .dat means activation
             ;; completed (dir + marker prove the populate did) but the first
             ;; save-state never landed — start the chainstate at its base.
             (case (bitcoin-lisp.storage:load-state snap)
               ((:inconsistent)
                (log-warn "[snapshot] snapshot chainstate in-transition (flush interrupted); will attempt automatic recovery after storage init")
                (push snap *pending-chainstate-recovery*))
               ((t) nil)
               ((nil)
                (log-warn "[snapshot] no chainstate_snapshot.dat; starting the snapshot chainstate at its base (h=~D)" base-height)
                (bitcoin-lisp.storage:update-chain-tip
                 snap (copy-seq base-hash) base-height)))
             ;; The recorded tip must resolve in the shared header index;
             ;; otherwise fall back to the base (blocks above it re-sync).
             (let ((tip-hash (bitcoin-lisp.storage:best-block-hash snap)))
               (unless (and tip-hash
                            (bitcoin-lisp.storage:get-block-index-entry primary tip-hash))
                 (log-warn "[snapshot] snapshot chainstate tip not in the header index; resetting to the base (h=~D)" base-height)
                 (bitcoin-lisp.storage:update-chain-tip
                  snap (copy-seq base-hash) base-height)))
             ;; Open its coins DB (chainstate_snapshot/).
             (bitcoin-lisp.storage:open-chainstate-coins-view snap)
             ;; Retarget the primary (it becomes the historical chainstate)
             ;; and adopt the snapshot chainstate as current.
             (bitcoin-lisp.storage:set-chainstate-target primary base-entry)
             (setf (node-chainstates node)
                   (append (node-chainstates node) (list snap)))
             (log-info "[snapshot] switching active chainstate to the snapshot chainstate (tip h=~D); historical chainstate at h=~D targets the base at h=~D"
                       (bitcoin-lisp.storage:current-height snap)
                       (bitcoin-lisp.storage:current-height primary)
                       base-height)
             snap)))))))

(defun start-node (&key (data-directory "~/.bitcoin-lisp/")
                        (network :testnet3)
                        (log-level :info)
                        (log-file nil)
                        (console-log t)
                        (max-peers 8)
                        (sync t)
                        (txindex nil)
                        (blockfilterindex nil)
                        (prune nil)
                        (rpc-port nil)
                        (rpc-bind "127.0.0.1")
                        (rpc-user nil)
                        (rpc-password nil)
                        (listen t)
                        (listen-bind "0.0.0.0")
                        (dbcache-mib nil)
                        (v2transport nil)
                        (coinstatsindex nil)
                        (reindex-chainstate nil)
                        (force-compact-db nil)
                        (peer-block-filters nil)
                        (tx-reconciliation nil))
  "Start the Bitcoin node.

DATA-DIRECTORY: Path to store blockchain data (mainnet uses mainnet/ subdirectory)
NETWORK: :testnet3 or :mainnet
LOG-LEVEL: :debug, :info, :warn, or :error
LOG-FILE: If non-nil, also append node logs to this path (in addition to console)
CONSOLE-LOG: If T (default), mirror logs to *standard-output* / REPL
MAX-PEERS: Maximum number of peer connections
SYNC: If T, start syncing immediately
TXINDEX: If T, enable transaction index for getrawtransaction lookups
BLOCKFILTERINDEX: If T, enable the BIP158 basic block filter index (getblockfilter,
  scanblocks, getdescriptoractivity)
PRUNE: Block pruning target in MiB (nil=off, 1=manual-only, >=550=automatic)
RPC-PORT: Port for RPC server (nil = no RPC, default 18332 testnet / 8332 mainnet)
RPC-BIND: Address to bind RPC server (default 127.0.0.1)
RPC-USER: RPC authentication username (nil = no auth)
RPC-PASSWORD: RPC authentication password

Returns the node instance."
  (when *node*
    (log-warn "Node already running, stopping first")
    (stop-node))

  (setf *node-start-time* (bitcoin-lisp.serialization:get-unix-time))

  ;; Wire up logging BEFORE init-node so its log-info calls go somewhere.
  ;; Without these, the node runs silently — the May 5 restart had this
  ;; failure mode (no node.log entries since May 2 16:32 crash).
  (when console-log
    (enable-console-logging))
  (when log-file
    (start-file-logging log-file))

  ;; UTXO cache budget (Core -dbcache). Larger = fewer LevelDB disk reads.
  (when dbcache-mib
    (unless (and (integerp dbcache-mib) (>= dbcache-mib 4))
      (error "Invalid dbcache-mib: ~A. Must be an integer >= 4." dbcache-mib))
    (setf *coins-cache-budget-bytes* (* dbcache-mib 1024 1024))
    (log-info "UTXO coins-cache budget: ~D MiB" dbcache-mib))

  ;; Validate the pruning configuration BEFORE assigning the global — a
  ;; config-validation error must not leave *prune-target-mib* set (a failed
  ;; start-node previously leaked the half-applied prune setting into the
  ;; process, making e.g. a later loadtxoutset believe the node is pruned).
  (when prune
    (unless (or (= prune 1) (>= prune 550))
      (error "Invalid prune target: ~A MiB. Must be 1 (manual-only) or >= 550." prune))
    (when (and prune txindex)
      (error "Cannot enable both pruning and txindex. Pruned blocks cannot be looked up."))
    ;; Bitcoin Core init.cpp: -prune is incompatible with -reindex-chainstate --
    ;; the wipe leaves the UTXO set to be replayed from stored blocks, but early
    ;; blocks are pruned, so a pruned reindex-chainstate wedges at the first gap.
    (when (and peer-block-filters (not blockfilterindex))
      (error "Cannot set -peerblockfilters without -blockfilterindex."))
    (when (and prune reindex-chainstate)
      (error "Prune mode is incompatible with -reindex-chainstate (pruned blocks cannot be replayed). Use a full resync instead.")))
  (setf *prune-target-mib* prune)

  ;; Initialize node
  (setf *node* (init-node data-directory :network network :log-level log-level))
  (setf (node-max-peers *node*) max-peers)
  (setf *current-log-level* log-level)
  (log-info "Bitcoin-Lisp Node v0.1.0")
  (log-info "Network: ~A" network)
  (log-info "Data directory: ~A" (node-data-directory *node*))

  ;; Set prune-after-height for this network
  (setf *prune-after-height* (prune-after-height network))

  ;; Log pruning status
  (when (pruning-enabled-p)
    (if (automatic-pruning-p)
        (log-info "Block pruning: AUTOMATIC (target ~D MiB)" *prune-target-mib*)
        (log-info "Block pruning: MANUAL-ONLY (via pruneblockchain RPC)")))

  ;; Mainnet warnings
  (when (eq network :mainnet)
    (log-warn "*** MAINNET MODE ***")
    (log-warn "You are connecting to the production Bitcoin network.")
    (if *mainnet-relay-enabled*
        (log-info "Transaction relay: ENABLED")
        (log-info "Transaction relay: DISABLED (safety default)")))

  ;; Initialize chain state: the chainstates list starts with the one primary
  ;; chainstate (empty storage suffix, so it loads exactly the files a
  ;; single-chainstate node wrote). A persisted snapshot chainstate would be
  ;; detected and appended here (Core LoadAssumeutxoChainstate) — future work.
  (log-info "Loading chain state...")
  (setf (node-chainstates *node*)
        (list (bitcoin-lisp.storage:init-chain-state (node-data-directory *node*))))

  ;; Genesis block index entry is ensured after load-header-index below

  (setf *pending-chainstate-recovery* nil)
  (let ((load-result (bitcoin-lisp.storage:load-state (node-chain-state *node*))))
    (case load-result
      ((:inconsistent)
       ;; A flush was interrupted mid-commit. Don't abort — defer recovery
       ;; until the block store, UTXO cache, and header index are open
       ;; (recover-inconsistent-chainstate needs all three).
       (log-warn "Chainstate in-transition (flush interrupted); will attempt automatic recovery after storage init")
       (push (node-chain-state *node*) *pending-chainstate-recovery*))
      ((t)
       (log-info "Loaded existing chain state: height ~D"
                 (bitcoin-lisp.storage:current-height (node-chain-state *node*))))
      ((nil) nil)))

  ;; Initialize block store
  (log-info "Initializing block storage...")
  (setf (node-block-store *node*)
        (bitcoin-lisp.storage:init-block-store (node-data-directory *node*)))

  ;; Initialize UTXO storage: LevelDB-backed coins-view-cache.
  ;;
  ;; The cache wraps a coins-view-db (LevelDB at <data-dir>/chainstate/).
  ;; Reads pull through from the base on miss; writes accumulate in the
  ;; cache and flush to disk via Phase 2 of do-flush.
  ;;
  ;; First-startup migration: a populated utxoset.dat from a previous
  ;; flat-file version is imported into LevelDB before opening the
  ;; cache. The migration writes a durable marker; once present, we
  ;; never re-migrate (the marker is idempotent and crash-safe).
  (log-info "Initializing UTXO storage (LevelDB-backed)...")
  (let* ((data-dir (node-data-directory *node*))
         (primary (node-chain-state *node*))
         ;; chainstate/ for the primary chainstate (empty storage suffix —
         ;; same directory as always); a snapshot chainstate would open
         ;; chainstate_snapshot/ through the same path function.
         (chainstate-path (namestring
                           (bitcoin-lisp.storage:chainstate-leveldb-path primary)))
         (utxoset-dat (bitcoin-lisp.storage:utxo-set-file-path data-dir))
         (migrated-p (bitcoin-lisp.storage:leveldb-utxo-migration-complete-p
                      chainstate-path)))
    (when (and (not migrated-p) (probe-file utxoset-dat))
      (log-info "Found legacy utxoset.dat; migrating into LevelDB at ~A ..."
                chainstate-path)
      (bitcoin-lisp.storage:migrate-utxoset-dat-to-leveldb
       utxoset-dat chainstate-path)
      (log-info "Migration complete; LevelDB is now the canonical UTXO store"))
    (let ((view (bitcoin-lisp.storage:open-coins-view-db chainstate-path)))
      (setf (bitcoin-lisp.storage:chain-state-coins-view primary)
            (bitcoin-lisp.storage:make-coins-view-cache view))
      (log-info "UTXO cache opened (base: ~A)" chainstate-path)))

  ;; Load persisted header index if available
  (when (bitcoin-lisp.storage:load-header-index (node-chain-state *node*))
    (log-info "Loaded persisted header index: ~D entries"
              (hash-table-count
               (bitcoin-lisp.storage::chain-state-block-index
                (node-chain-state *node*)))))

  ;; Ensure genesis block is in the index with a proper header
  ;; (needed for difficulty walk-back on testnet)
  (let* ((genesis-hash (bitcoin-lisp.storage:network-genesis-hash network))
         (genesis-entry (bitcoin-lisp.storage:get-block-index-entry
                         (node-chain-state *node*) genesis-hash))
         (genesis-header (make-genesis-header network)))
    (if genesis-entry
        ;; Fix existing entry if it has a missing or zeroed header
        (when (or (null (bitcoin-lisp.storage:block-index-entry-header genesis-entry))
                  (zerop (bitcoin-lisp.serialization:block-header-bits
                          (bitcoin-lisp.storage:block-index-entry-header genesis-entry))))
          (setf (bitcoin-lisp.storage:block-index-entry-header genesis-entry)
                genesis-header))
        ;; Create new genesis entry
        (bitcoin-lisp.storage:add-block-index-entry
         (node-chain-state *node*)
         (bitcoin-lisp.storage:make-block-index-entry
          :hash genesis-hash
          :height 0
          :header genesis-header
          :prev-entry nil
          :chain-work 0
          :status :valid
          :tx-count 1))))   ; genesis carries exactly its coinbase

  ;; Snapshot chainstate startup handling (Core LoadChainstate ordering,
  ;; node/chainstate.cpp:151-238). -reindex-chainstate deletes a snapshot
  ;; chainstate outright (Core wipe_chainstate_db) — the primary then
  ;; rebuilds from stored blocks with no target. Otherwise, detect a
  ;; persisted snapshot chainstate dir and re-init dual chainstates. Runs
  ;; after the header index is loaded (the base entry must resolve) and
  ;; before crash-recovery resolution below (a torn snapshot flush joins the
  ;; pending-recovery list).
  (if reindex-chainstate
      (when (bitcoin-lisp.storage:find-assumeutxo-chainstate-dir
             (node-data-directory *node*))
        (log-info "[snapshot] deleting snapshot chainstate due to reindexing")
        (bitcoin-lisp.storage:delete-snapshot-chainstate-files
         (node-data-directory *node*)))
      (load-snapshot-chainstate *node*))

  ;; Resolve interrupted-flush chainstates now that the block store, UTXO
  ;; caches, and header index are all available. Only abort (resync) if the
  ;; on-disk state needed to recover is gone.
  (let ((pending *pending-chainstate-recovery*))
    (setf *pending-chainstate-recovery* nil)
    (dolist (cs pending)
      (unless (recover-inconsistent-chainstate *node* cs)
        (error "chainstate inconsistent and unrecoverable: move ~A aside and re-sync"
               (node-data-directory *node*)))))

  ;; Initialize undo data persistence
  (let ((undo-path (merge-pathnames "undo/" (node-data-directory *node*))))
    (bitcoin-lisp.validation:initialize-undo-storage undo-path)
    (log-info "Undo data directory: ~A" undo-path))

  ;; Catch-up sweep: drop undo files at/below the pruned horizon. They
  ;; accumulated before undo pruning existed (53GB/500k files on the first
  ;; mainnet run); after the first sweep the directory only holds the
  ;; unpruned window, so this is cheap on every later start.
  (when (pruning-enabled-p)
    (let ((swept (bitcoin-lisp.validation:prune-stale-undo-files
                  (node-chain-state *node*))))
      (when (plusp swept)
        (log-info "Pruned ~D stale undo file~:P below the prune horizon" swept))))

  ;; Optional chainstate reindex: rebuild the UTXO set from stored blocks
  ;; before the indexes initialize (so they rebuild against the fresh set) and
  ;; before the sync thread starts (single-threaded here, no writer races).
  ;; Runs after the block index + undo storage are ready.
  (when reindex-chainstate
    (do-reindex-chainstate))

  ;; Initialize recent rejects filter (DoS protection)
  (setf (node-recent-rejects *node*) (make-rejects-filter))

  ;; Initialize mempool
  (log-info "Initializing mempool...")
  (setf (node-mempool *node*) (bitcoin-lisp.mempool:make-mempool))

  ;; Initialize fee estimator
  (log-info "Initializing fee estimator...")
  (setf (node-fee-estimator *node*)
        (bitcoin-lisp.mempool:make-fee-estimator
         :data-directory (node-data-directory *node*)))
  ;; Load persisted fee stats
  (bitcoin-lisp.mempool:load-fee-stats (node-fee-estimator *node*))

  ;; Reload the persisted mempool through normal acceptance (Core LoadMempool)
  (load-mempool-from-disk *node*)

  ;; Initialize peer address book
  (log-info "Loading peer address book...")
  (setf (node-address-book *node*) (bitcoin-lisp.networking:make-address-book))
  (let ((peers-path (bitcoin-lisp.networking:peers-dat-path (node-data-directory *node*))))
    (when (bitcoin-lisp.networking:load-address-book (node-address-book *node*) peers-path)
      (log-info "Loaded peer address book: ~D entries"
                (bitcoin-lisp.networking:address-book-count (node-address-book *node*)))))

  ;; Load reconnection anchors (tried first, before DNS seeds — anti-eclipse).
  (load-anchors *node*)

  ;; Initialize transaction index (optional)
  (when txindex
    (log-info "Initializing transaction index...")
    (setf (node-tx-index *node*)
          (bitcoin-lisp.storage:init-tx-index (node-data-directory *node*)
                                               :enabled t))
    (log-info "Transaction index loaded: ~D entries"
              (bitcoin-lisp.storage:txindex-count (node-tx-index *node*))))

  ;; Initialize BIP158 block filter index (optional)
  (when blockfilterindex
    (log-info "Initializing block filter index...")
    (setf *blockfilterindex-stall-logged* nil)
    (setf (node-blockfilterindex *node*)
          (bitcoin-lisp.storage:init-blockfilterindex (node-data-directory *node*)
                                                       :enabled t))
    (log-info "Block filter index loaded: indexed to height ~D"
              (bitcoin-lisp.storage:blockfilterindex-height (node-blockfilterindex *node*)))
    ;; One-time catch-up over already-stored blocks, before the sync thread
    ;; starts (single-threaded here, so no writer races). Fresh-from-genesis
    ;; nodes have nothing to do; the connect-time hook then indexes forward.
    ;; Indexes bind the validated chainstate (Core ValidatedChainstate) —
    ;; they index blocks in order from genesis. Identical to the current
    ;; chainstate while only the primary exists.
    (let* ((bfi (node-blockfilterindex *node*))
           (cs (node-validated-chainstate *node*))
           (tip (bitcoin-lisp.storage:current-height cs)))
      ;; Repair the recorded "best" if a rollback (e.g. invalidateblock) left it
      ;; above the active tip: repoint it at the highest indexed active-chain
      ;; block, else clear it to force a rebuild.
      (when (> (bitcoin-lisp.storage:blockfilterindex-height bfi) tip)
        (log-warn "Block filter index best above tip (~D > ~D); repairing"
                  (bitcoin-lisp.storage:blockfilterindex-height bfi) tip)
        (loop for h from tip downto 0
              for e = (bitcoin-lisp.storage:get-block-at-height cs h)
              when (and e (bitcoin-lisp.storage:blockfilterindex-has-block-p
                           bfi (bitcoin-lisp.storage:block-index-entry-hash e)))
                do (bitcoin-lisp.storage:blockfilterindex-set-best
                    bfi h (bitcoin-lisp.storage:block-index-entry-hash e))
                   (return)
              finally (bitcoin-lisp.storage:blockfilterindex-clear-best bfi)))
      (when (< (bitcoin-lisp.storage:blockfilterindex-height bfi) tip)
        (log-info "Building block filter index to height ~D..." tip)
        (let ((n (bitcoin-lisp.storage:build-blockfilterindex
                  bfi cs (node-block-store *node*)
                  #'bitcoin-lisp.validation:get-undo-data
                  :progress-callback
                  (lambda (h pct)
                    (log-info "Block filter index: height ~D (~,1F%)" h pct)))))
          (log-info "Block filter index build complete: ~D block~:P indexed" n)))))

  ;; Initialize coinstatsindex (optional). Like the filter index, catch up over
  ;; already-stored blocks before the sync thread starts, then the connect-time
  ;; hook advances it. Its running MuHash must be contiguous from genesis, so a
  ;; pruned node (missing early undo data) can only build it if its stored
  ;; history reaches genesis -- otherwise the backfill stops at the first gap.
  (when coinstatsindex
    (log-info "Initializing coinstats index...")
    (setf (node-coinstatsindex *node*)
          (bitcoin-lisp.storage:init-coinstatsindex (node-data-directory *node*)
                                                    :enabled t))
    (log-info "Coinstats index loaded: indexed to height ~D"
              (bitcoin-lisp.storage:coinstatsindex-height (node-coinstatsindex *node*)))
    ;; A chainstate reindex may have changed UTXO-set contents (e.g. dropping
    ;; unspendable outputs), so the coinstats records must be rebuilt to stay
    ;; consistent. Clear the best marker to force a full rebuild below.
    (when reindex-chainstate
      (bitcoin-lisp.storage:coinstatsindex-clear-best (node-coinstatsindex *node*))
      (log-info "Coinstats index: rebuilding after chainstate reindex"))
    ;; Like the filter index: binds the validated chainstate.
    (let* ((csi (node-coinstatsindex *node*))
           (cs (node-validated-chainstate *node*))
           (tip (bitcoin-lisp.storage:current-height cs)))
      ;; Repair a best marker left above the active tip (e.g. after
      ;; invalidateblock): repoint at the highest indexed active-chain block.
      (when (> (bitcoin-lisp.storage:coinstatsindex-height csi) tip)
        (log-warn "Coinstats index best above tip (~D > ~D); repairing"
                  (bitcoin-lisp.storage:coinstatsindex-height csi) tip)
        (loop for h from tip downto 0
              when (bitcoin-lisp.storage:coinstatsindex-get-stats csi h)
                do (bitcoin-lisp.storage:coinstatsindex-set-best
                    csi h (bitcoin-lisp.storage:block-index-entry-hash
                           (bitcoin-lisp.storage:get-block-at-height cs h)))
                   (return)
              finally (bitcoin-lisp.storage:coinstatsindex-clear-best csi)))
      (when (< (bitcoin-lisp.storage:coinstatsindex-height csi) tip)
        (log-info "Building coinstats index to height ~D..." tip)
        (let ((n (bitcoin-lisp.storage:build-coinstatsindex
                  csi cs (node-block-store *node*)
                  #'bitcoin-lisp.validation:get-undo-data
                  #'bitcoin-lisp.validation:calculate-block-subsidy
                  :progress-callback
                  (lambda (h pct)
                    (log-info "Coinstats index: height ~D (~,1F%)" h pct)))))
          (log-info "Coinstats index build complete: ~D block~:P indexed" n)
          (when (< (bitcoin-lisp.storage:coinstatsindex-height csi) tip)
            (log-warn "Coinstats index stopped at height ~D of ~D (missing block/undo ~
data below the pruned horizon; the index needs genesis-contiguous history)"
                      (bitcoin-lisp.storage:coinstatsindex-height csi) tip))))))

  ;; -forcecompactdb: once every LevelDB is open (and any reindex/backfill has
  ;; run), full-compact them to reclaim tombstone space -- e.g. the ~24M delete
  ;; markers a reindex-chainstate wipe leaves behind. Bitcoin Core does the same
  ;; via CDBWrapper force_compact when -forcecompactdb is set.
  (when force-compact-db
    (force-compact-databases))

  ;; BIP157 filter serving (-peerblockfilters): gated above on the block filter
  ;; index being enabled; advertised as NODE_COMPACT_FILTERS in our version.
  (setf bitcoin-lisp:*peer-block-filters* (and peer-block-filters t))
  (when peer-block-filters
    (log-info "BIP157 compact filter serving enabled (NODE_COMPACT_FILTERS)"))

  ;; BIP330 Erlay handshake (-txreconciliation; Core DEBUG_ONLY, default off).
  ;; Negotiates sendtxrcncl + per-peer salt storage only — no sketch exchange
  ;; exists at Core ref d3056bc either.
  (setf bitcoin-lisp:*tx-reconciliation* (and tx-reconciliation t))
  (when tx-reconciliation
    (log-info "BIP330 transaction reconciliation handshake enabled (sendtxrcncl)"))

  ;; BIP324 v2 transport opt-in. Effective only if libsecp256k1 has the
  ;; ellswift module (probed lazily per connection via v2-available-p).
  (setf bitcoin-lisp.networking:*v2-transport-enabled* (and v2transport t))
  (when v2transport
    (log-info "BIP324 v2 transport enabled (~:[ellswift NOT available -- will run v1 only~;active~])"
              (bitcoin-lisp.networking:v2-available-p)))

  ;; Initialize secp256k1
  (log-info "Initializing cryptographic context...")
  (bitcoin-lisp.crypto:ensure-secp256k1-loaded)

  (setf (node-running *node*) t)

  ;; Start RPC server if port specified
  (when rpc-port
    (bitcoin-lisp.rpc:start-rpc-server *node*
                                        :port rpc-port
                                        :bind rpc-bind
                                        :user rpc-user
                                        :password rpc-password))

  ;; Connect to peers and sync if requested (in background thread)
  ;; Reconnects and retries when peers are lost, similar to Bitcoin Core's
  ;; CheckForStaleTipAndEvictPeers (net_processing.cpp:5460)
  (when sync
    (bitcoin-lisp.networking:reset-ibd-stop)
    (bitcoin-lisp.networking:reset-tx-requests)
    (setf (node-sync-thread *node*)
          (bt:make-thread
           (lambda ()
             (handler-case
                 (handler-bind
                     ((error
                        (lambda (c)
                          ;; handler-bind keeps the stack live; backtrace here
                          ;; points at the actual error site. handler-case
                          ;; (outer) then unwinds.
                          (log-error "Sync thread error: ~A" c)
                          #+sbcl
                          (let ((bt (with-output-to-string (s)
                                      (sb-debug:print-backtrace :stream s :count 50))))
                            (log-error "Sync thread backtrace:~%~A" bt)))))
                   ;; Initial connection
                   (connect-to-peers *node* max-peers :timeout 60 :min-peers 2)
                   ;; Sync + follow-tip loop runs until node shutdown. The
                   ;; previous early-return on "sync complete" exited the only
                   ;; thread reading from peer sockets, so live tip
                   ;; announcements after IBD were never processed. Peers push
                   ;; new tips via sendheaders (BIP 130); this 30s poll is the
                   ;; backstop for inv-only peers and missed announcements.
                   (loop while (node-running *node*)
                         do (merge-inbound-peers *node*)
                            ;; Maintain manually-added peers each cycle (addnode).
                            (connect-added-nodes *node*)
                            (cond
                              ((>= (length (node-peers *node*)) 1)
                               (setf (node-syncing *node*) t)
                               (unwind-protect
                                    (sync-blockchain *node*)
                                 (setf (node-syncing *node*) nil))
                               ;; Full peer maintenance, not just replacement:
                               ;; health checks + outgoing pings, addnode
                               ;; retry, slot refill, dedicated block-relay
                               ;; slots, and feeler probes. maintain-peers was
                               ;; previously dead code — nothing called it, so
                               ;; the PR #216 block-relay/feeler conns and
                               ;; ping-timeout eviction never ran live.
                               (maintain-peers *node*)
                               ;; Re-route any tx getdata that timed out to
                               ;; another announcer (TxRequestTracker).
                               (bitcoin-lisp.networking:retry-timed-out-tx-requests)
                               (loop repeat 30 while (node-running *node*)
                                     do (sleep 1)
                                        ;; Trickled tx announcements: drain
                                        ;; due per-peer inv queues each
                                        ;; second (Poisson schedules inside;
                                        ;; Core SendMessages runs its
                                        ;; equivalent on every message pump).
                                        (bitcoin-lisp.networking:flush-tx-announcements
                                         (node-peers *node*)
                                         (node-mempool *node*))))
                              (t
                               (log-warn "No peers available, reconnecting in 5s...")
                               (loop repeat 5 while (node-running *node*)
                                     do (sleep 1))
                               (connect-to-peers *node* max-peers
                                                 :timeout 30 :min-peers 1)))))
               (error () nil)))
           :name "bitcoin-sync-thread")))

  ;; Inbound listening (depends on the sync thread to merge accepted peers).
  (when (and sync listen)
    (start-inbound-listener *node* listen-bind))

  (install-shutdown-handler)
  (log-info "Node started successfully")
  *node*)

(defun start-node-from-args (&optional (args (rest sb-ext:*posix-argv*)))
  "Start the node from Bitcoin Core-style options: a list of CLI ARGS
 (-key=value, -key, -nokey) plus a bitcoin.conf read from the data directory.
CLI arguments override the config file. This is the argv-friendly entry point —
 e.g. from a saved image's toplevel, or (start-node-from-args
'(\"-chain=main\" \"-txindex\" \"-dbcache=2000\" \"-server\")).

The data directory and network are resolved from the CLI first (so the config
file can be located and its [network] section scoped), then the merged config
is turned into start-node keyword arguments. -conf=PATH overrides the config
file location."
  (let* ((cli (parse-cli-args args))
         (datadir (or (cdr (assoc "datadir" cli :test #'string=)) "~/.bitcoin-lisp/"))
         (conf-path (or (cdr (assoc "conf" cli :test #'string=))
                        ;; Ensure a trailing slash so DATADIR is treated as a
                        ;; directory (else merge-pathnames replaces its last
                        ;; component).
                        (merge-pathnames
                         "bitcoin.conf"
                         (pathname (if (and (plusp (length datadir))
                                            (char= (char datadir (1- (length datadir))) #\/))
                                       datadir
                                       (concatenate 'string datadir "/"))))))
         (conf-text (when (probe-file conf-path)
                      (log-info "Reading config file ~A" conf-path)
                      (alexandria:read-file-into-string conf-path))))
    (multiple-value-bind (plist merged) (args->start-node-plist args conf-text)
      ;; Apply the process-global config specials (options with no start-node
      ;; keyword) from the same merged config, before launching.
      (apply-config-globals merged)
      ;; datadir only comes from the CLI/default (locating the conf needs it), so
      ;; make sure it reaches start-node even if it wasn't in the spec scan.
      (unless (getf plist :data-directory)
        (setf (getf plist :data-directory) datadir))
      (apply #'start-node plist))))

(defparameter +flush-every-n-blocks+ 25000
  "Block-count flush backstop. The 600s time trigger and the 450MiB
   coins-cache size trigger are the real guards; this count only caps the
   redo window if both somehow fail to fire. Was 1000, which at mainnet
   IBD speed (~30 b/s) meant a full header-index rewrite + CRC every
   ~35s — ~6% of CPU by sb-sprof at h≈280k. A crash now redoes at most
   ~10 min of validation (the time trigger), like Core's
   DATABASE_WRITE_INTERVAL bounding work by time, not block count.")

(defparameter +flush-every-n-seconds+ 600
  "Time-based flush trigger (10 min): flush if at least N seconds have
   elapsed since the last flush, regardless of block count. Without this,
   a slow sync window (~2 b/s on testnet4 stress regions) takes ~8 min
   to accumulate 1000 blocks, and a connect-tip stall halts flushes
   entirely (May 2 crash: stuck at h=70700 for 1h40m, last save was at
   h=70000 at 14:34, lost 700 blocks of progress + caused full re-sync
   from genesis on restart). Bitcoin Core uses DATABASE_WRITE_INTERVAL
   = 1h (validation.cpp:DATABASE_WRITE_INTERVAL) — we use 10 min because
   our re-validation from a checkpoint is much slower than Core's.")

(defvar *coins-cache-budget-bytes* (* 450 1024 1024)
  "Memory budget for the in-memory UTXO (coins) cache before a size-triggered
flush. Default mirrors Bitcoin Core's DEFAULT_DB_CACHE (kernel/caches.h,
450 MiB); start-node's :dbcache-mib raises it (Core's -dbcache). A larger
budget keeps more of the UTXO set in RAM, cutting LevelDB disk reads during
IBD — the dominant cost once the chainstate outgrows the LevelDB table cache
(profiled I/O-wait-bound at mainnet h~828k). The cache flushes-and-clears at
the LARGE threshold, so memory stays bounded (the unbounded cache was the
original mainnet OOM blocker).")

(defun large-coins-cache-threshold (budget)
  "The coins-cache usage at which a periodic flush is due. Mirrors Bitcoin Core's
LargeCoinsCacheThreshold (validation.h): flush once less than 10 MiB (or 10% of
the budget, whichever is larger free margin) remains."
  (max (floor (* budget 9) 10)
       (- budget (* 10 1024 1024))))

(defvar *blocks-since-flush* 0
  "Counter incremented per connected block; reset to 0 when a flush runs.")

(defvar *last-flush-universal-time* 0
  "Wall-clock time (get-universal-time) of the last successful periodic
   flush. Used by the time-based trigger.")

(defun log-memory-snapshot (label)
  "Log a snapshot of the major in-memory caches plus SBCL heap usage.
Used to diagnose memory growth — call before/after flush so we can
correlate cache sizes with the heap watermark.

The May 5 OOM at h=72814 had heap at 8.55 GB but the explainable
state (UTXO 600MB + headers 30MB + sig-cache 5MB + queues 80MB) only
accounts for ~700 MB. This logger surfaces the gap."
  #+sbcl
  (let* ((utxo-count (and (node-utxo-set *node*)
                          (bitcoin-lisp.storage:utxo-count
                           (node-utxo-set *node*))))
         (coins-cache-mb (and (node-utxo-set *node*)
                              (/ (bitcoin-lisp.storage:view-mem-bytes
                                  (node-utxo-set *node*))
                                 1048576.0)))
         (header-count (and (node-chain-state *node*)
                            (hash-table-count
                             (bitcoin-lisp.storage::chain-state-block-index
                              (node-chain-state *node*)))))
         (sig-cache-count
           (+ (hash-table-count bitcoin-lisp.coalton.interop:*signature-cache*)
              (hash-table-count bitcoin-lisp.coalton.interop:*signature-cache-prev*)))
         (ibd-pending
           (and bitcoin-lisp.networking::*ibd-context*
                (hash-table-count
                 (bitcoin-lisp.networking::ibd-context-pending-blocks
                  bitcoin-lisp.networking::*ibd-context*))))
         (ibd-queue
           (and bitcoin-lisp.networking::*ibd-context*
                (hash-table-count
                 (bitcoin-lisp.networking::ibd-context-block-queue
                  bitcoin-lisp.networking::*ibd-context*))))
         (ibd-in-flight
           (and bitcoin-lisp.networking::*ibd-context*
                (hash-table-count
                 (bitcoin-lisp.networking::ibd-context-in-flight
                  bitcoin-lisp.networking::*ibd-context*))))
         (dyn-bytes (sb-ext:dynamic-space-size))
         (used-bytes (sb-kernel:dynamic-usage)))
    (log-info "MEM[~A]: utxo=~D coins-cache=~,1FMB headers=~D sigcache=~D ibd-pend=~A queue=~A inflight=~A heap-used=~,1FMB heap-cap=~,1FMB"
              label utxo-count coins-cache-mb header-count sig-cache-count
              ibd-pending ibd-queue ibd-in-flight
              (/ used-bytes 1048576.0) (/ dyn-bytes 1048576.0))))

(defun %flush-chainstate (chainstate)
  "Synchronously flush one CHAINSTATE (its state file, its coins view, and
the shared header index) with 3-phase commit (mirrors Bitcoin Core's
DB_HEAD_BLOCKS marker pattern in txdb.cpp::CCoinsViewDB::BatchWrite).
Each chainstate flushes its own storage-suffix-named files, so flushing one
can never mark another's state file in-transition. Per-flush-CYCLE concerns
(trigger counter resets, the post-flush GC, memory snapshots) live in the
callers — this is strictly the per-chainstate mechanism.

  Phase 1: save-state with in-transition=1 — chainstate.dat marked unsafe.
           If we crash anywhere from here through Phase 3, on restart
           load-state returns :inconsistent and the caller refuses to
           start (must re-sync).
  Phase 2: save-utxo-set — the slow 90-MB write. Uses temp + fsync +
           rename internally so the file itself is atomic, but it might
           be old-or-new depending on whether the rename completed.
  Phase 3: save-state with in-transition=0 — commits the new chainstate.

The previous non-atomic flush ordered chainstate-then-utxo. If
interrupted between, on-disk best-height was ahead of the saved UTXO
entries, which then cascaded into MISSING-INPUT validation failures on
restart (observed at testnet4 h=70541 — block 70514 tx-2's outputs
were nowhere in utxoset.dat despite chainstate showing h=70540)."
  (handler-case
      (#+sbcl sb-sys:without-interrupts
       #-sbcl progn
        ;; Phase 1: mark the chainstate as in-transition.
        (when chainstate
          (bitcoin-lisp.storage:save-state chainstate :in-transition t)
          (bitcoin-lisp.storage:save-header-index chainstate))
        ;; Phase 2: flush cache → LevelDB. Per-flush work is proportional
        ;; to dirty entries (typically a few thousand at the tip), not
        ;; the full ~17M-entry set — replaces the ~13s utxoset.dat
        ;; rewrite that previously froze the sync thread.
        (let ((view (and chainstate
                         (bitcoin-lisp.storage:chain-state-coins-view chainstate))))
          (when view
            ;; :sync t fdatasyncs the LevelDB writebatch before we proceed, so a
            ;; power loss after Phase 3 clears the marker cannot leave the coins
            ;; un-durable while chainstate.dat says they are committed. (Was
            ;; :sync nil — atomic but not durable; the shutdown flush already
            ;; syncs, the periodic one now matches it.)
            (bitcoin-lisp.storage:coins-view-cache-flush view :sync t)))
        ;; Phase 3: commit by re-saving chainstate without the marker.
        (when chainstate
          (bitcoin-lisp.storage:save-state chainstate :in-transition nil))
        (log-info "Periodic flush: chainstate~@[~A~] at height ~D"
                  (let ((suffix (and chainstate
                                     (bitcoin-lisp.storage:chain-state-storage-suffix
                                      chainstate))))
                    (and suffix (plusp (length suffix)) suffix))
                  (and chainstate
                       (bitcoin-lisp.storage:current-height chainstate))))
    (error (c)
      ;; Was log-warn before — surfaced silently. Bumped to log-error so
      ;; persistence failures are obvious in the log instead of getting
      ;; lost between progress lines.
      (log-error "Periodic flush FAILED: ~A" c))))

(defun do-flush (&optional (chainstate (and *node* (node-current-chainstate *node*))))
  "Flush CHAINSTATE (default: the node's current chainstate) and run the
per-cycle bookkeeping: reset the periodic-flush triggers, request a major GC
so reachable post-flush memory is the only thing in the old generations next
time we measure (the same pattern as Bitcoin Core's CCoinsViewCache::Flush
returning bytes freed to the system allocator), and log memory snapshots."
  (log-memory-snapshot "pre-flush")
  (%flush-chainstate chainstate)
  (setf *last-flush-universal-time* (get-universal-time)
        *blocks-since-flush* 0)
  #+sbcl (sb-ext:gc :full t)
  (log-memory-snapshot "post-flush"))

(defun maybe-periodic-flush (&optional chainstate)
  "Flush chainstates (state file, coins view, and the header index) to disk
if either:
- N blocks have been connected since the last flush, OR
- N seconds have elapsed since the last flush (catches slow-sync regions
  where 1000 blocks would take many minutes to accumulate).

Called from connect-block, which passes the chainstate the block connected
to; defaults to the node's current chainstate. The size trigger checks the
connecting chainstate's own coins cache; once ANY trigger fires, EVERY
chainstate is flushed — with an assumeutxo background sync two chainstates
connect blocks concurrently but the global time/count triggers reset on any
flush, so flushing only the triggering one would let the other's dirty
coins and redo window grow unboundedly. Flushing a clean chainstate is
cheap (work is proportional to dirty entries). Cheap if no flush needed;
durable if it does flush (atomic temp+fsync+rename inside save-*)."
  (unless *node* (return-from maybe-periodic-flush))
  (let* ((cs (or chainstate (node-current-chainstate *node*)))
         (view (and cs (bitcoin-lisp.storage:chain-state-coins-view cs))))
    (incf *blocks-since-flush*)
    (when (zerop *last-flush-universal-time*)
      (setf *last-flush-universal-time* (get-universal-time)))
    (when (or (>= *blocks-since-flush* +flush-every-n-blocks+)
              (>= (- (get-universal-time) *last-flush-universal-time*)
                  +flush-every-n-seconds+)
              ;; Size trigger (Bitcoin Core dbcache): flush once the coins cache
              ;; reaches its memory budget, so it can't grow unbounded between the
              ;; block-count / time flushes.
              (and view
                   (>= (bitcoin-lisp.storage:view-mem-bytes view)
                       (large-coins-cache-threshold *coins-cache-budget-bytes*))))
      ;; Triggering chainstate first (its cache may be the urgent one),
      ;; then the rest. Per-cycle bookkeeping (trigger resets, ONE major
      ;; GC, memory snapshots) runs once around the whole pass — not per
      ;; chainstate, which would double the stop-the-world GC pauses
      ;; during an assumeutxo background sync.
      (log-memory-snapshot "pre-flush")
      (%flush-chainstate cs)
      (dolist (other (node-chainstates *node*))
        (unless (eq other cs)
          (%flush-chainstate other)))
      (setf *last-flush-universal-time* (get-universal-time)
            *blocks-since-flush* 0)
      #+sbcl (sb-ext:gc :full t)
      (log-memory-snapshot "post-flush"))))

(defvar *blockfilterindex-stall-logged* nil
  "One-shot latch so a stalled block filter index (non-contiguous connect
refused) logs a single warning instead of one per block until restart.")

(defun index-block-filter (chainstate block block-hash height spent-utxos)
  "Connect-time hook: add BLOCK's BIP158 basic filter to the running node's
block filter index, if one is enabled. CHAINSTATE is the chainstate the
block connected to; signals from any chainstate other than the node's
VALIDATED one are dropped — indexes index blocks in order from genesis, so
they bind Core's ValidatedChainstate (init.cpp:1367-1383) and must ignore
an unvalidated snapshot chainstate's tip-range connects. SPENT-UTXOS is the
undo list the UTXO apply produced. Never signals -- a filter-index failure
must not abort a block connect -- so consensus is unaffected whether the
index is on or off."
  (let ((bfi (and *node* (node-blockfilterindex *node*))))
    (when (and bfi (bitcoin-lisp.storage:blockfilterindex-enabled bfi)
               (eq chainstate (node-validated-chainstate *node*)))
      (handler-case
          (multiple-value-bind (filter status)
              (bitcoin-lisp.storage:blockfilterindex-add-block
               bfi block block-hash height spent-utxos)
            (when (and (eq status :noncontiguous)
                       (not *blockfilterindex-stall-logged*))
              (setf *blockfilterindex-stall-logged* t)
              (log-warn "Block filter index stalled at height ~D: gap below ~
best-indexed height ~D; the startup backfill will heal it on next restart"
                        height
                        (bitcoin-lisp.storage:blockfilterindex-height bfi)))
            filter)
        (error (e)
          (log-warn "Block filter index failed at height ~D: ~A" height e)
          nil)))))

(defun do-reindex-chainstate ()
  "Rebuild the UTXO set from already-stored blocks (Bitcoin Core
-reindex-chainstate): wipe the coins view, reset the chainstate to genesis,
and re-apply every stored active-chain block's UTXO effects, trusting the
already-validated stored blocks (no script re-validation, no re-download).
The undo files are left as-is -- they record spent prevouts, which the rebuild
does not change. Clears the coinstatsindex best marker so its startup backfill
rebuilds it against the reindexed set; the blockfilterindex is unaffected
(its filters are over block scripts, not the UTXO set).

This realizes UTXO-set-content changes (e.g. dropping now-skipped unspendable
outputs) on an existing node without a full network resync, and doubles as
chainstate disaster-recovery when blocks+index are intact but the coins DB is
suspect."
  (let* ((cs (node-chain-state *node*))
         (store (node-block-store *node*))
         (utxo (node-utxo-set *node*))
         (tip-hash (bitcoin-lisp.storage:best-block-hash cs))
         (tip-entry (and tip-hash (bitcoin-lisp.storage:get-block-index-entry cs tip-hash)))
         (tip-height (bitcoin-lisp.storage:current-height cs)))
    (when (or (null tip-entry) (zerop tip-height))
      (log-info "Reindex-chainstate: empty chain, nothing to rebuild")
      (return-from do-reindex-chainstate))
    (log-info "Reindex-chainstate: rebuilding UTXO set from ~D stored blocks..." tip-height)
    ;; Active chain genesis+1 .. tip, ascending (push while walking prev-entry
    ;; down from the tip leaves the list in height order).
    (let ((entries '()))
      (loop with e = tip-entry
            while (and e (plusp (bitcoin-lisp.storage:block-index-entry-height e)))
            do (push e entries)
               (setf e (bitcoin-lisp.storage:block-index-entry-prev-entry e)))
      ;; Empty the coins view and rewind the chainstate to genesis.
      (let ((erased (bitcoin-lisp.storage:coins-view-cache-wipe utxo)))
        (log-info "Reindex-chainstate: erased ~D coin~:P; replaying..." erased))
      (bitcoin-lisp.storage:update-chain-tip
       cs (bitcoin-lisp.storage::chain-state-genesis-hash cs) 0)
      ;; NB: the coinstatsindex is opened AFTER this runs; its rebuild is
      ;; forced in its own init block (keyed off the reindex flag), not here.
      ;; The blockfilterindex is left alone -- its filters are over block
      ;; scripts, unaffected by a UTXO-set rebuild.
      ;; Replay every block's UTXO effects.
      (let ((n 0) (last-report (get-internal-real-time)))
        (block replay
          (dolist (entry entries)
            (let* ((hash (bitcoin-lisp.storage:block-index-entry-hash entry))
                   (height (bitcoin-lisp.storage:block-index-entry-height entry))
                   (blk (bitcoin-lisp.storage:get-block store hash)))
              (unless blk
                (log-warn "Reindex-chainstate: block at height ~D missing from store; ~
stopping (UTXO set rebuilt to height ~D)" height (1- height))
                (return-from replay))
              ;; Apply removes spent prevouts + adds spendable outputs (the
              ;; unspendable skip lives in apply-block-to-utxo-set). Discard the
              ;; returned undo list -- the on-disk undo files are unchanged.
              (bitcoin-lisp.storage:apply-block-to-utxo-set utxo blk height)
              (bitcoin-lisp.storage:update-chain-tip cs hash height)
              (incf n)
              (when (>= (bitcoin-lisp.storage:view-mem-bytes utxo)
                        (large-coins-cache-threshold *coins-cache-budget-bytes*))
                (bitcoin-lisp.storage:coins-view-cache-flush utxo :sync nil))
              (let ((now (get-internal-real-time)))
                (when (> (- now last-report) internal-time-units-per-second)
                  (log-info "Reindex-chainstate: height ~D (~,1F%)"
                            height (* 100.0 (/ height tip-height)))
                  (setf last-report now))))))
        (bitcoin-lisp.storage:coins-view-cache-flush utxo :sync t)
        (bitcoin-lisp.storage:save-state cs)
        (log-info "Reindex-chainstate complete: ~D block~:P re-applied, tip at height ~D"
                  n (bitcoin-lisp.storage:current-height cs))))))

(defun force-compact-databases ()
  "Full-compact every LevelDB the node has open -- the coins/chainstate DB plus
the block-filter and coinstats indexes -- reclaiming the disk that tombstones
still pin after a large deletion churn (e.g. a reindex-chainstate wipe). Mirrors
Bitcoin Core's -forcecompactdb, which sets CDBWrapper force_compact on each
database it opens. Synchronous and potentially slow on a large chainstate."
  (flet ((compact (label db)
           (when db
             (log-info "Starting database compaction of ~A" label)
             (bitcoin-lisp.storage:leveldb-compact db)
             (log-info "Finished database compaction of ~A" label))))
    (let ((utxo (node-utxo-set *node*))
          (bfi (node-blockfilterindex *node*))
          (csi (node-coinstatsindex *node*)))
      (when utxo
        (log-info "Starting database compaction of chainstate")
        (bitcoin-lisp.storage:coins-view-cache-compact utxo)
        (log-info "Finished database compaction of chainstate"))
      (when bfi (compact "blockfilterindex" (bitcoin-lisp.storage:blockfilterindex-db bfi)))
      (when csi (compact "coinstatsindex" (bitcoin-lisp.storage:coinstatsindex-db csi))))))

(defun index-block-coinstats (chainstate block block-hash height spent-utxos)
  "Connect-time hook: fold BLOCK into the running node's coinstatsindex, if
one is enabled. CHAINSTATE is the chainstate the block connected to; like
index-block-filter, only the node's VALIDATED chainstate's connects are
indexed — the running MuHash must be contiguous from genesis, which an
unvalidated snapshot chainstate's tip-range blocks are not. SPENT-UTXOS is
the undo list the UTXO apply produced; the block subsidy is derived from
HEIGHT. Never signals -- an index failure must not abort a block connect --
so consensus is unaffected whether the index is on or off. Returns NIL (and
stalls quietly) if the parent height's record is missing (non-contiguous);
the startup backfill heals such gaps on restart."
  (let ((csi (and *node* (node-coinstatsindex *node*))))
    (when (and csi (bitcoin-lisp.storage:coinstatsindex-enabled csi)
               (eq chainstate (node-validated-chainstate *node*)))
      (handler-case
          (bitcoin-lisp.storage:coinstatsindex-add-block
           csi block block-hash height spent-utxos
           (bitcoin-lisp.validation:calculate-block-subsidy height))
        (error (e)
          (log-warn "Coinstats index failed at height ~D: ~A" height e)
          nil)))))

(defun install-shutdown-handler ()
  "Trap SIGTERM and SIGINT so kill <pid> / Ctrl-C calls stop-node and persists
   chain state and UTXO set before exit. Without this, SIGKILL is the only way
   to stop a long-running node and IBD must restart from genesis on next boot.

   Also installs a fail-fast debugger hook: any unhandled error (including
   heap-exhausted) logs a stack and exits non-zero rather than dropping into
   LDB on a tty no one is reading."
  #+sbcl
  (let ((handler
          (lambda (&rest _)
            (declare (ignore _))
            (format *error-output* "~&[shutdown] caught signal — saving state~%")
            (ignore-errors (stop-node))
            ;; Per-block script-check worker threads (bt:make-thread :name
            ;; "script-check-N" in validate-block.lisp) are non-daemon and
            ;; can outlive stop-node if validation was in progress when the
            ;; sync thread was destroyed. Without a timeout, sb-ext:exit
            ;; blocks forever waiting for them (incident 2026-05-11: node
            ;; logged "Node stopped" but SBCL process hung 6+ minutes,
            ;; eventually needed SIGKILL). Give 5 seconds for any in-flight
            ;; worker to finish naturally, then force-exit. Bitcoin Core's
            ;; CCheckQueue (checkqueue.h:206-225) has an explicit stop flag
            ;; + condvar to join workers; we use a coarser timeout because
            ;; our workers are ephemeral per-block, not a persistent pool.
            (sb-ext:exit :code 0 :timeout 5))))
    (sb-sys:enable-interrupt sb-unix:sigterm handler)
    (sb-sys:enable-interrupt sb-unix:sigint handler))
  ;; SIGUSR1 toggles sb-sprof profiling. First USR1: start sampling. Second
  ;; USR1: stop, write graph + flat report to /data/bitcoin-lisp/logs/profile.txt.
  ;; Use to identify the hot path during live validation: kill -USR1 <pid> to
  ;; arm, wait through a heavy block, kill -USR1 <pid> again, then read report.
  #+sbcl
  (let ((profiling nil))
    (sb-sys:enable-interrupt
     sb-unix:sigusr1
     (lambda (&rest _)
       (declare (ignore _))
       (cond
         ((not profiling)
          (sb-sprof:reset)
          (sb-sprof:start-profiling :max-samples 200000
                                    :sample-interval 0.001
                                    :mode :cpu
                                    :threads :all)
          (setf profiling t)
          (log-info "[sprof] profiling started"))
         (t
          (sb-sprof:stop-profiling)
          (with-open-file (s "/data/bitcoin-lisp/logs/profile.txt"
                             :direction :output
                             :if-exists :supersede
                             :if-does-not-exist :create)
            (let ((*standard-output* s))
              (format s "=== sb-sprof flat report ===~%")
              (sb-sprof:report :type :flat :max 60)
              (format s "~%~%=== sb-sprof graph report ===~%")
              (sb-sprof:report :type :graph :max 50)))
          (setf profiling nil)
          (log-info "[sprof] profile written to /data/bitcoin-lisp/logs/profile.txt")))))
    (log-info "SIGUSR1 toggles sb-sprof profiling"))
  #+sbcl
  (setf sb-ext:*invoke-debugger-hook*
        (lambda (condition hook)
          (declare (ignore hook))
          (ignore-errors
            (log-error "Fatal: ~A" condition)
            (let ((bt (with-output-to-string (s)
                        (sb-debug:print-backtrace :stream s :count 30))))
              (log-error "Backtrace:~%~A" bt)))
          (sb-ext:exit :code 1))))

(defun stop-node ()
  "Stop the running Bitcoin node."
  (unless *node*
    (return-from stop-node nil))

  (log-info "Stopping node...")

  ;; Persist reconnection anchors while peers are still connected (before the
  ;; teardown below disconnects them).
  (save-anchors *node*)

  ;; Stop RPC server first
  (bitcoin-lisp.rpc:stop-rpc-server)

  ;; Signal the node to stop. request-ibd-stop reaches the IBD inner
  ;; loops, which can otherwise run for hours after node-running flips
  ;; (the outer sync loop only checks between run-ibd passes).
  (setf (node-running *node*) nil)
  (bitcoin-lisp.networking:request-ibd-stop)

  ;; Stop the inbound listener: close the socket (unblocks accept) and let the
  ;; accept thread observe node-running=nil and exit (its accept timeout is 1s).
  (when (node-listener-socket *node*)
    (bitcoin-lisp.networking:close-listener (node-listener-socket *node*))
    (setf (node-listener-socket *node*) nil))
  (when (and (node-listener-thread *node*)
             (bt:thread-alive-p (node-listener-thread *node*)))
    (let ((deadline (+ (get-internal-real-time) (* 5 internal-time-units-per-second))))
      (loop while (and (bt:thread-alive-p (node-listener-thread *node*))
                       (< (get-internal-real-time) deadline))
            do (sleep 0.1))
      (when (bt:thread-alive-p (node-listener-thread *node*))
        (bt:destroy-thread (node-listener-thread *node*)))))
  (setf (node-listener-thread *node*) nil)
  ;; Disconnect any inbound peers not yet merged into the peer list. The listener
  ;; thread is already joined above, but take the lock for consistency.
  (let ((pending (bt:with-recursive-lock-held ((node-lock *node*))
                   (prog1 (node-pending-inbound-peers *node*)
                     (setf (node-pending-inbound-peers *node*) nil)))))
    (dolist (peer pending)
      (handler-case (bitcoin-lisp.networking:disconnect-peer peer) (error () nil))))

  ;; Wait for sync thread to finish (with timeout)
  (when (and (node-sync-thread *node*)
             (bt:thread-alive-p (node-sync-thread *node*)))
    (log-info "Waiting for sync thread to stop...")
    (let ((deadline (+ (get-internal-real-time)
                       ;; 10 minutes — long enough that a single heavy block's
                       ;; validation finishes and connect-block updates UTXO set
                       ;; + chain tip atomically, so destroy-thread fallback
                       ;; (which can corrupt mid-update state) is virtually
                       ;; never needed.
                       (* 600 internal-time-units-per-second))))
      (loop while (and (bt:thread-alive-p (node-sync-thread *node*))
                       (< (get-internal-real-time) deadline))
            do (sleep 0.1))
      (when (bt:thread-alive-p (node-sync-thread *node*))
        (log-warn "Sync thread did not stop gracefully, destroying...")
        (bt:destroy-thread (node-sync-thread *node*)))))
  (setf (node-sync-thread *node*) nil)

  ;; Disconnect all peers
  (log-info "Disconnecting peers...")
  (dolist (peer (node-peers *node*))
    (handler-case
        (bitcoin-lisp.networking:disconnect-peer peer)
      (error (c)
        (log-warn "Error disconnecting peer: ~A" c))))
  (bt:with-recursive-lock-held ((node-lock *node*))
    (setf (node-peers *node*) nil))

  ;; Save every chainstate's state file and flush+close its coins view.
  ;; Per-chainstate: with an assumeutxo snapshot active there are two, each
  ;; owning its own storage-suffix-named files and LevelDB.
  (dolist (cs (node-chainstates *node*))
    (log-info "Saving chain state~@[ (~A)~]..."
              (let ((suffix (bitcoin-lisp.storage:chain-state-storage-suffix cs)))
                (and (plusp (length suffix)) suffix)))
    (bitcoin-lisp.storage:save-state cs)
    (let ((view (bitcoin-lisp.storage:chain-state-coins-view cs)))
      (when (typep view 'bitcoin-lisp.storage:coins-view-cache)
        (log-info "Flushing UTXO cache...")
        (bitcoin-lisp.storage:coins-view-cache-flush view :sync t)))
    (bitcoin-lisp.storage:close-chainstate-coins-view cs))

  ;; Save fee statistics
  (when (node-fee-estimator *node*)
    (log-info "Saving fee statistics...")
    (bitcoin-lisp.mempool:save-fee-stats (node-fee-estimator *node*)))

  ;; Save mempool (Core DumpMempool)
  (let ((path (bitcoin-lisp.mempool:mempool-dat-path (node-data-directory *node*))))
    (when (and path (node-mempool *node*))
      (log-info "Saving mempool (~D entries)..."
                (bitcoin-lisp.mempool:save-mempool-file (node-mempool *node*) path))))

  ;; Save header index
  (log-info "Saving header index...")
  (when (node-chain-state *node*)
    (bitcoin-lisp.storage:save-header-index (node-chain-state *node*)))

  ;; Save peer address book
  (when (node-address-book *node*)
    (log-info "Saving peer address book...")
    (bitcoin-lisp.networking:save-address-book
     (node-address-book *node*)
     (bitcoin-lisp.networking:peers-dat-path (node-data-directory *node*))))

  ;; Close transaction index
  (when (node-tx-index *node*)
    (log-info "Closing transaction index...")
    (bitcoin-lisp.storage:close-tx-index (node-tx-index *node*)))

  ;; Close block filter index
  (when (node-blockfilterindex *node*)
    (log-info "Closing block filter index...")
    (bitcoin-lisp.storage:close-blockfilterindex (node-blockfilterindex *node*)))

  ;; Close coinstats index
  (when (node-coinstatsindex *node*)
    (log-info "Closing coinstats index...")
    (bitcoin-lisp.storage:close-coinstatsindex (node-coinstatsindex *node*)))

  ;; Cleanup secp256k1
  (bitcoin-lisp.crypto:cleanup-secp256k1)

  (log-info "Node stopped")

  (setf *node* nil)
  t)

;;;; Peer Management

;;;; Anchor connections (Bitcoin Core anchors.dat)
;;;;
;;;; On shutdown we persist a couple of currently-connected outbound peers and
;;;; reconnect to them first on the next start, BEFORE consulting DNS seeds.
;;;; This closes the across-restart eclipse window: a freshly-started node that
;;;; relied only on DNS seeds (or a poisoned addrman) could be fed an attacker's
;;;; peer set, but a known-good anchor it was just connected to cannot be
;;;; substituted by the attacker. (Core anchors are block-relay-only peers;
;;;; dedicated block-relay-only outbound slots are a separate follow-up — these
;;;; anchors are drawn from the regular outbound pool.)

(defparameter +max-anchors+ 2
  "How many outbound peers to persist as reconnection anchors (Core saves 2).")

(defconstant +anchors-magic-v1+ #x414e4331)  ; "ANC1" — bare IP strings, no port
(defconstant +anchors-magic-v2+ #x414e4332)  ; "ANC2" — network-typed + port

(defvar *pending-anchor-addresses* nil
  "Anchor dial candidates — (host-string . port) conses, port NIL meaning the
network default — loaded at startup and consumed (and cleared) by the first
connect-to-peers so they are attempted before DNS-seed candidates.")

(defun anchors-dat-path (data-directory)
  "Path to anchors.dat in DATA-DIRECTORY."
  (merge-pathnames "anchors.dat" data-directory))

(defun save-anchor-entries (path entries)
  "Write anchor ENTRIES — a list of (network bytes port) — to PATH in the v2
format: magic \"ANC2\", count byte, then per entry a BIP155-style net id,
length-prefixed address bytes and a big-endian port (crash-safe: temp +
fsync + atomic rename, CRC32-protected)."
  (bitcoin-lisp.storage:save-file-with-crc32
   path
   (lambda (stream)
     (loop for shift in '(24 16 8 0)
           do (write-byte (ldb (byte 8 shift) +anchors-magic-v2+) stream))
     (write-byte (length entries) stream)
     (dolist (e entries)
       (destructuring-bind (net bytes port) e
         (write-byte (bitcoin-lisp.networking:network-key-id net) stream)
         (write-byte (length bytes) stream)
         (write-sequence bytes stream)
         (write-byte (ldb (byte 8 8) port) stream)
         (write-byte (ldb (byte 8 0) port) stream))))))

(defun parse-anchor-entries (bytes)
  "Parse anchors.dat payload BYTES (CRC already verified) into a list of
(network bytes port). Reads the v2 network-typed format; a v1 file (bare IP
strings without port) is MIGRATED: each string is parsed to a typed address,
with the port NIL (caller substitutes the network default — all v1-era
anchors were dialed at the default port anyway). Unparseable v1 entries
(e.g. a hostname from addnode) are dropped. Returns NIL for unknown magic."
  (let ((end (- (length bytes) 4))              ; stay inside payload (before CRC)
        (magic (logior (ash (aref bytes 0) 24) (ash (aref bytes 1) 16)
                       (ash (aref bytes 2) 8) (aref bytes 3)))
        (entries '()))
    (cond
      ((= magic +anchors-magic-v2+)
       (let ((count (aref bytes 4)) (pos 5))
         (dotimes (i count)
           (when (< (+ pos 2) end)
             (let ((net (bitcoin-lisp.networking:key-id-network (aref bytes pos)))
                   (len (aref bytes (1+ pos))))
               (incf pos 2)
               (when (and net (<= (+ pos len 2) end))
                 (push (list net
                             (coerce (subseq bytes pos (+ pos len))
                                     '(simple-array (unsigned-byte 8) (*)))
                             (logior (ash (aref bytes (+ pos len)) 8)
                                     (aref bytes (+ pos len 1))))
                       entries))
               (incf pos (+ len 2)))))))
      ((= magic +anchors-magic-v1+)
       (let ((count (aref bytes 4)) (pos 5))
         (dotimes (i count)
           (when (< pos end)
             (let ((len (aref bytes pos)))
               (incf pos)
               (when (<= (+ pos len) end)
                 (multiple-value-bind (net addr-bytes)
                     (bitcoin-lisp.networking:parse-network-address
                      (map 'string #'code-char (subseq bytes pos (+ pos len))))
                   (when net
                     (push (list net addr-bytes nil) entries)))
                 (incf pos len)))))))
      (t (return-from parse-anchor-entries nil)))
    (nreverse entries)))

(defun save-anchors (node)
  "Persist up to +max-anchors+ currently-connected outbound peers to
anchors.dat in the network-typed v2 format (net + address + port)."
  (let* ((ready-outbound
           (remove-if-not
            (lambda (p) (and (not (bitcoin-lisp.networking:peer-inbound p))
                             (eq (bitcoin-lisp.networking:peer-state p) :ready)))
            (node-peers node)))
         ;; Prefer block-relay-only peers as anchors (Core anchors are
         ;; block-relay: an attacker who fed us a poisoned addrman can't
         ;; substitute a peer we were just block-relay-connected to). Fall back
         ;; to full-relay outbound if we have no block-relay peers.
         (block-relay (remove-if-not
                       (lambda (p) (eq (bitcoin-lisp.networking:peer-conn-type p)
                                       :block-relay))
                       ready-outbound))
         (ready (or block-relay ready-outbound))
         (default-port (network-port (node-network node)))
         (entries
           (loop for p in (subseq ready 0 (min +max-anchors+ (length ready)))
                 for (net bytes) = (multiple-value-list
                                    (bitcoin-lisp.networking:parse-network-address
                                     (bitcoin-lisp.networking:peer-address p)))
                 when net                        ; hostname peers (addnode) skipped
                   collect (list net bytes
                                 (let ((conn (bitcoin-lisp.networking::peer-connection p)))
                                   (if conn
                                       (bitcoin-lisp.networking::connection-port conn)
                                       default-port))))))
    (when entries
      (handler-case
          (save-anchor-entries (anchors-dat-path (node-data-directory node)) entries)
        (error (e) (log-warn "Failed to save anchors: ~A" e)))
      (log-info "Saved ~D anchor peer~:P" (length entries)))))

(defun load-anchors (node)
  "Read anchors.dat into *pending-anchor-addresses* — (host . port) dial
candidates, dialed at the STORED port (migrated v1 entries carry port NIL and
fall back to the network default) — so the next connect attempts them first.
Missing/corrupt file is ignored; a v1-era file migrates (see
parse-anchor-entries) and the next save rewrites it as v2. Only networks that
are dialable under the current config (dialable-network-p: onion needs a Tor
proxy, cjdns needs -cjdnsreachable) and reachable (-onlynet) become dial
candidates."
  (let ((bytes (bitcoin-lisp.storage:load-file-with-crc32
                (anchors-dat-path (node-data-directory node)) 6)))
    (when bytes
      (setf *pending-anchor-addresses*
            (loop for (net addr-bytes port) in (parse-anchor-entries bytes)
                  when (and (bitcoin-lisp.networking:dialable-network-p net)
                            (bitcoin-lisp.networking:reachable-network-p net))
                    collect (cons (bitcoin-lisp.networking:network-address-to-string
                                   net addr-bytes)
                                  port)))
      (when *pending-anchor-addresses*
        (log-info "Loaded ~D anchor peer~:P for priority reconnection"
                  (length *pending-anchor-addresses*))))))

(defun %record-outbound-result (address-book addr port peer success)
  "Record an outbound dial outcome for ADDR:PORT in ADDRESS-BOOK, adding the
entry if new (network-typed, so IPv6/onion/cjdns peers get addrman credit
too): SUCCESS => Good + Connected, failure => Attempt with count-failure
(Core CConnman's addrman feedback in ConnectNode/OpenNetworkConnection).
Hostname dial targets (unparseable as addresses) are skipped."
  (when address-book
    (multiple-value-bind (net ip-bytes)
        (bitcoin-lisp.networking:parse-network-address addr)
      (when net
        (unless (bitcoin-lisp.networking:address-book-lookup
                 address-book ip-bytes port net)
          (bitcoin-lisp.networking:address-book-add
           address-book
           (bitcoin-lisp.networking:make-peer-address
            :net net :ip ip-bytes :port port
            :services (if (and success peer)
                          (bitcoin-lisp.networking:peer-services peer)
                          0)
            :last-seen (bitcoin-lisp.serialization:get-unix-time))))
        (if success
            (progn
              (bitcoin-lisp.networking:address-book-good
               address-book ip-bytes port
               (bitcoin-lisp.serialization:get-unix-time) net)
              (bitcoin-lisp.networking:address-book-connected
               address-book ip-bytes port
               (bitcoin-lisp.serialization:get-unix-time) net))
            (bitcoin-lisp.networking:address-book-attempt
             address-book ip-bytes port :count-failure t :net net))))))

(defun connect-to-peers (node max-peers &key (timeout 60) (min-peers 1))
  "Connect to Bitcoin network peers.
Uses address book for warm starts, falls back to DNS seeds. Dial candidates
are (host . port) conses (port NIL = network default): addrman picks and
anchors carry their STORED ports, DNS/fixed seeds the default. Onion default
port = chain default port (Core net.cpp:3395-3404 GetDefaultPort), so the
same fallback covers .onion candidates.
MAX-PEERS: Target number of peers to connect
TIMEOUT: Maximum seconds to spend connecting (default 60)
MIN-PEERS: Return early once we have at least this many peers (default 1)
Returns the number of peers connected."
  ;; setnetworkactive off: make no outbound connections.
  (unless (node-network-active node)
    (return-from connect-to-peers 0))
  (let ((address-book (node-address-book node))
        (addresses '()))
    ;; Warm start: select peers from the addrman (new/tried buckets,
    ;; eclipse-resistant) rather than a single global score ranking.
    (when (and address-book
               (>= (bitcoin-lisp.networking:address-book-count address-book) 8))
      (bitcoin-lisp.networking:resolve-tried-collisions address-book)
      (log-info "Using peer address book (~D entries)..."
                (bitcoin-lisp.networking:address-book-count address-book))
      (let ((seen (make-hash-table :test 'equal))
            (picks '()))
        (dotimes (i (* max-peers 8))
          ;; select-dialable-address, never raw select: post-BIP155 the book
          ;; can hold records not dialable under the current config (torv3
          ;; without a Tor proxy, i2p always, cjdns without -cjdnsreachable).
          (let ((pa (bitcoin-lisp.networking:select-dialable-address address-book)))
            (when pa
              (let ((str (bitcoin-lisp.networking:peer-address-string pa))
                    (port (bitcoin-lisp.networking:peer-address-port pa)))
                (unless (gethash str seen)
                  (setf (gethash str seen) t)
                  (push (cons str (and (plusp port) port)) picks))))))
        (setf addresses (nreverse picks))))
    ;; Fall back to DNS seeds if not enough candidates
    (when (< (length addresses) 8)
      (log-info "Discovering peers from DNS seeds...")
      (let ((dns-addrs (bitcoin-lisp.networking:discover-peers)))
        (log-info "Found ~D potential peers from DNS" (length dns-addrs))
        (setf addresses (append addresses
                                (mapcar (lambda (a) (cons a nil)) dns-addrs)))
        (setf addresses (remove-duplicates addresses :key #'car :test #'string=))))

    ;; Fixed-seed fallback for testnet4: even after DNS, the candidate pool
    ;; may have only one /16 group (sprovoost.nl seed has been dark since
    ;; ~2026-05; wiz.biz returns its own /24 cluster only). Mirrors Bitcoin
    ;; Core's vFixedSeeds population in chainparams.cpp — used as a
    ;; last-resort source so we always have netgroup diversity available.
    (when (and (eq (node-network node) :testnet4)
               (let ((groups (remove-duplicates
                              (remove nil (mapcar (lambda (c)
                                                    (bitcoin-lisp.networking:ip-netgroup
                                                     (car c)))
                                                  addresses))
                              :test #'string=)))
                 (< (length groups) 8)))
      (log-info "Merging testnet4 fixed-seed list (~D peers, ~D /16 groups)"
                (length bitcoin-lisp.networking:*testnet4-fixed-seeds*)
                (length (remove-duplicates
                         (mapcar #'bitcoin-lisp.networking:ip-netgroup
                                 bitcoin-lisp.networking:*testnet4-fixed-seeds*)
                         :test #'string=)))
      (setf addresses
            (remove-duplicates
             (append addresses
                     (mapcar (lambda (a) (cons a nil))
                             bitcoin-lisp.networking:*testnet4-fixed-seeds*))
             :key #'car :test #'string=)))

    ;; Diversify by /16 netgroup so the first 8 connection attempts spread
    ;; across distinct operators (incident 2026-05-11: 8-of-8 peers were
    ;; from 103.165.192.x wiz.biz nodes — one stall stalled the whole
    ;; sync). Mirrors Bitcoin Core's addrman netgroup bucket selection
    ;; (netaddress.cpp CNetAddr::GetGroup).
    (setf addresses (bitcoin-lisp.networking:diversify-by-netgroup addresses
                                                                   :key #'car))

    ;; Anchors first (Core anchors.dat): reconnect to the peers we persisted at
    ;; last shutdown before any DNS/addrman candidate, then consume them so
    ;; later reconnect cycles use the normal pool.
    (when *pending-anchor-addresses*
      (setf addresses (remove-duplicates (append *pending-anchor-addresses* addresses)
                                         :key #'car :test #'string= :from-end t))
      (setf *pending-anchor-addresses* nil))

    (log-info "~D candidate peers available" (length addresses))

    ;; Store discovered addresses for reconnection
    (setf (node-known-addresses node) addresses)

    (let ((connected 0)
          (start-time (get-internal-real-time))
          (timeout-ticks (* timeout internal-time-units-per-second)))
      (dolist (candidate (node-known-addresses node))
        ;; Stop if we have enough peers
        (when (>= connected max-peers)
          (return))

        ;; Check timeout - but only exit early if we have minimum peers
        (when (and (>= connected min-peers)
                   (> (- (get-internal-real-time) start-time) timeout-ticks))
          (log-info "Connection timeout reached with ~D peers" connected)
          (return))

        (let* ((addr (car candidate))
               (dial-port (or (cdr candidate) (network-port (node-network node)))))
          (log-debug "Trying to connect to ~A..." addr)
          (handler-case
              (let ((peer (bitcoin-lisp.networking:connect-peer addr dial-port)))
                (when peer
                  (setf (bitcoin-lisp.networking:peer-address peer) addr)
                  (log-info "Connected to ~A" addr)
                  ;; Perform handshake
                  (when (bitcoin-lisp.networking:perform-handshake peer)
                    (log-info "Handshake complete with ~A (~A, height ~D)"
                              addr
                              (bitcoin-lisp.networking:peer-user-agent peer)
                              (bitcoin-lisp.networking:peer-start-height peer))
                    ;; Send feature negotiation messages
                    (bitcoin-lisp.networking:send-post-handshake-messages peer)
                    ;; Record success in address book (add if not present)
                    (%record-outbound-result address-book addr dial-port peer t)
                    ;; Send compact block negotiation (BIP 152)
                    (bitcoin-lisp.networking:send-compact-block-negotiation peer)
                    (bt:with-recursive-lock-held ((node-lock node))
                      (push peer (node-peers node)))
                    (incf connected))
                  (unless (eq (bitcoin-lisp.networking:peer-state peer) :ready)
                    (bitcoin-lisp.networking:disconnect-peer peer))))
            (error (c)
              (log-debug "Failed to connect to ~A: ~A" addr c)
              ;; Record failure in address book (add if not present)
              (%record-outbound-result address-book addr dial-port nil nil)))))

      (log-info "Connected to ~D peer~:P" connected)
      connected)))

;;;; Peer Health and Reconnection

(defun check-peers-health (node)
  "Check health of all peers. Disconnect unresponsive ones.
Also checks compact block reconstruction timeouts (BIP 152)."
  (let ((to-disconnect '()))
    (dolist (peer (node-peers node))
      ;; Both checks below can WRITE (ping, compact-block getdata); a peer
      ;; that FIN'd since the last drain raises stream-error from that
      ;; write. Fold any error into :disconnect instead of letting it
      ;; escape — this runs on the sync thread, whose outer handler-case
      ;; would otherwise end the thread (2026-05-09 incident pattern).
      (handler-case
          (progn
            ;; Check compact block timeout
            (bitcoin-lisp.networking:check-compact-block-timeout peer)
            ;; Check ping/pong health
            (let ((status (bitcoin-lisp.networking:check-peer-health peer)))
              (when (eq status :disconnect)
                (push peer to-disconnect))))
        (error () (push peer to-disconnect))))
    (dolist (peer to-disconnect)
      (log-warn "Disconnecting unresponsive peer ~A"
                (bitcoin-lisp.networking:peer-address peer))
      (handler-case
          (bitcoin-lisp.networking:disconnect-peer peer)
        (error (c) (declare (ignore c))))
      (bt:with-recursive-lock-held ((node-lock node))
        (setf (node-peers node) (remove peer (node-peers node)))))
    (length to-disconnect)))

(defun replace-disconnected-peers (node)
  "Replace disconnected peers to maintain target peer count.
Returns the number of new peers connected."
  ;; Reap disconnected peers first — this also cleans up peers that
  ;; setnetworkactive dropped, even while networking stays disabled.
  (bt:with-recursive-lock-held ((node-lock node))
    (setf (node-peers node)
          (remove-if (lambda (p)
                       (eq (bitcoin-lisp.networking:peer-state p) :disconnected))
                     (node-peers node))))
  ;; setnetworkactive off: don't dial replacements.
  (unless (node-network-active node)
    (return-from replace-disconnected-peers 0))
  ;; Count only the normal peer set (inbound + full-relay) toward max-peers.
  ;; Block-relay-only peers are a separate additive pool maintained by
  ;; maintain-block-relay-peers (Core keeps m_max_outbound_block_relay distinct
  ;; from m_max_outbound_full_relay); folding them in here would let 2 idle
  ;; block-relay slots starve replacement of a dropped full-relay peer.
  (let* ((active-peers (remove-if-not
                        (lambda (p)
                          (and (eq (bitcoin-lisp.networking:peer-state p) :ready)
                               (not (member (bitcoin-lisp.networking:peer-conn-type p)
                                            '(:block-relay :feeler)))))
                        (node-peers node)))
         (needed (- (node-max-peers node) (length active-peers))))
    (when (<= needed 0)
      (return-from replace-disconnected-peers 0))

    ;; Get addresses already in use
    (let ((used-addrs (mapcar #'bitcoin-lisp.networking:peer-address
                              (node-peers node)))
          (connected 0))
      (dolist (candidate (node-known-addresses node))
        ;; Stop attempting new connect+handshake cycles the moment shutdown is
        ;; requested — each one can otherwise block (connect timeout + handshake
        ;; read) and delay the sync thread reaching its node-running checkpoint.
        (when (or (>= connected needed)
                  (bitcoin-lisp.networking:ibd-stop-requested-p))
          (return))
        (let ((addr (car candidate)))
          (unless (member addr used-addrs :test #'string=)
            (handler-case
                (let ((peer (bitcoin-lisp.networking:connect-peer
                             addr (or (cdr candidate)
                                      (network-port (node-network node))))))
                  (when peer
                    (setf (bitcoin-lisp.networking:peer-address peer) addr)
                    (when (bitcoin-lisp.networking:perform-handshake peer)
                      (log-info "Replacement peer connected: ~A" addr)
                      ;; Send feature negotiation messages
                      (bitcoin-lisp.networking:send-post-handshake-messages peer)
                      ;; Send compact block negotiation (BIP 152)
                      (bitcoin-lisp.networking:send-compact-block-negotiation peer)
                      (bt:with-recursive-lock-held ((node-lock node))
                        (push peer (node-peers node)))
                      (incf connected))
                    (unless (eq (bitcoin-lisp.networking:peer-state peer) :ready)
                      (bitcoin-lisp.networking:disconnect-peer peer))))
              (error (c)
                (declare (ignore c)))))))
      connected)))

;;;; Manually-added peers (addnode)

(defun parse-node-endpoint (node spec)
  "Split an addnode SPEC into (values host port). Accepts \"host\",
\"host:port\", and \"[ipv6]:port\"; bare or bracketless addresses default to the
network's P2P port. A trailing :port is only honored when it is all digits, so a
bare IPv6 address (which contains colons) is treated as host-only."
  (let ((default-port (network-port (node-network node))))
    (cond
      ;; [ipv6]:port  or  [ipv6]
      ((and (plusp (length spec)) (char= (char spec 0) #\[))
       (let ((close (position #\] spec)))
         (if (null close)
             (values spec default-port)
             (let ((host (subseq spec 1 close))
                   (rest (subseq spec (1+ close))))
               (if (and (plusp (length rest)) (char= (char rest 0) #\:)
                        (plusp (length (subseq rest 1)))
                        (every #'digit-char-p (subseq rest 1)))
                   (values host (parse-integer rest :start 1))
                   (values host default-port))))))
      (t
       (let ((colon (position #\: spec :from-end t)))
         (if (and colon
                  (< (1+ colon) (length spec))
                  (every #'digit-char-p (subseq spec (1+ colon)))
                  ;; A single colon => host:port; multiple => bare IPv6.
                  (= colon (position #\: spec)))
             (values (subseq spec 0 colon) (parse-integer spec :start (1+ colon)))
             (values spec default-port)))))))

(defun peer-connected-to-host-p (node host)
  "T if a peer with address HOST is currently in the node's peer list."
  (bt:with-recursive-lock-held ((node-lock node))
    (and (find host (node-peers node)
               :key #'bitcoin-lisp.networking:peer-address :test #'string=)
         t)))

(defun establish-outbound-peer (node host port &key (conn-type :outbound-full-relay))
  "Full outbound connect + handshake to HOST:PORT, pushing the ready peer onto
node-peers. CONN-TYPE (:outbound-full-relay or :block-relay) sets the peer's
connection type. Returns the peer or NIL. MUST run on the sync thread so
node-peers stays single-writer. No-op when networking is disabled."
  (when (node-network-active node)
    (handler-case
        (let ((peer (bitcoin-lisp.networking:connect-peer host port)))
          (when peer
            (setf (bitcoin-lisp.networking:peer-address peer) host)
            (if (bitcoin-lisp.networking:perform-handshake peer :conn-type conn-type)
                (progn
                  (bitcoin-lisp.networking:send-post-handshake-messages peer)
                  (bitcoin-lisp.networking:send-compact-block-negotiation peer)
                  (bt:with-recursive-lock-held ((node-lock node))
                    (push peer (node-peers node)))
                  (log-info "Added-node peer connected: ~A" host)
                  peer)
                (progn (bitcoin-lisp.networking:disconnect-peer peer) nil))))
      (error (c)
        (log-debug "Added-node connect to ~A:~D failed: ~A" host port c)
        nil))))

(defun connect-added-nodes (node)
  "Service addnode requests on the sync thread: drain one-shot \"onetry\" dials,
then keep every \"add\" peer connected. Honors network-active."
  (when (node-network-active node)
    ;; One-shot onetry dials (Core addnode onetry).
    (let ((onetry (bt:with-recursive-lock-held ((node-lock node))
                    (prog1 (node-pending-onetry node)
                      (setf (node-pending-onetry node) nil)))))
      (dolist (spec onetry)
        (multiple-value-bind (host port) (parse-node-endpoint node spec)
          (unless (peer-connected-to-host-p node host)
            (establish-outbound-peer node host port)))))
    ;; Maintain persistent added-node connections.
    (dolist (spec (node-added-nodes node))
      (multiple-value-bind (host port) (parse-node-endpoint node spec)
        (unless (peer-connected-to-host-p node host)
          (establish-outbound-peer node host port))))))

(defconstant +target-block-relay-peers+ 2
  "Dedicated block-relay-only outbound slots (Bitcoin Core opens 2). They carry
blocks/headers but no tx relay -- anti-partition insurance and the source of
reconnection anchors.")

(defconstant +feeler-interval-seconds+ 120
  "Minimum spacing between feeler probes (Core FEELER_INTERVAL averages ~2 min).")

(defvar *last-feeler-time* 0
  "get-universal-time of the last feeler attempt, for rate-limiting.")

(defun peers-of-conn-type (node type)
  "Count current peers whose connection type is TYPE."
  (bt:with-recursive-lock-held ((node-lock node))
    (count type (node-peers node)
           :key #'bitcoin-lisp.networking:peer-conn-type)))

(defun %addrman-pick-unconnected (node &key new-only)
  "Pick an addrman address (as (values host port)) we're not already connected
to, or NIL; PORT is NIL when the record has none stored (caller substitutes
the network default). NEW-ONLY restricts to the 'new' table (for feelers).
Goes through select-dialable-address so automatic slots (block-relay,
feelers) only ever draw records dialable under the current config (torv3
needs a Tor proxy, cjdns needs -cjdnsreachable, i2p never)."
  (let ((ab (node-address-book node)))
    (when ab
      (dotimes (_ 20)
        (let ((pa (bitcoin-lisp.networking:select-dialable-address ab :new-only new-only)))
          (when pa
            (let ((host (bitcoin-lisp.networking:peer-address-string pa))
                  (port (bitcoin-lisp.networking:peer-address-port pa)))
              (unless (peer-connected-to-host-p node host)
                (return-from %addrman-pick-unconnected
                  (values host (and (plusp port) port)))))))))))

(defun maintain-block-relay-peers (node)
  "Ensure up to +target-block-relay-peers+ block-relay-only outbound peers.
Each carries blocks/headers only (relay=0), never tx relay."
  (when (and (node-network-active node) (node-address-book node))
    (loop while (< (peers-of-conn-type node :block-relay) +target-block-relay-peers+)
          do (multiple-value-bind (ip port) (%addrman-pick-unconnected node)
               (unless (and ip (establish-outbound-peer
                                node ip (or port (network-port (node-network node)))
                                :conn-type :block-relay))
                 ;; No candidate, or the connect failed: stop trying this cycle.
                 (return))
               (log-info "Opened block-relay-only peer ~A" ip)))))

(defun do-feeler-connection (node host port)
  "Open a short-lived feeler connection: connect, handshake, and on success mark
the address good (promoting it new -> tried). Always disconnects afterward --
feelers exist only to validate addrman's tried table (Core anti-eclipse), never
to join the peer set."
  (handler-case
      (let ((peer (bitcoin-lisp.networking:connect-peer host port)))
        (when peer
          (setf (bitcoin-lisp.networking:peer-address peer) host)
          (when (bitcoin-lisp.networking:perform-handshake peer :conn-type :feeler)
            (multiple-value-bind (net ip-bytes)
                (bitcoin-lisp.networking:parse-network-address host)
              (when net
                (bitcoin-lisp.networking:address-book-good
                 (node-address-book node) ip-bytes port
                 (bitcoin-lisp.serialization:get-unix-time) net)))
            (log-debug "Feeler validated ~A (new -> tried)" host))
          (bitcoin-lisp.networking:disconnect-peer peer)))
    (error (c)
      (log-debug "Feeler to ~A:~D failed: ~A" host port c))))

(defun maybe-do-feeler (node)
  "Rate-limited: probe one addrman 'new' address with a feeler to validate it
into 'tried'."
  (let ((now (get-universal-time)))
    (when (and (node-network-active node) (node-address-book node)
               (>= (- now *last-feeler-time*) +feeler-interval-seconds+))
      (setf *last-feeler-time* now)
      (multiple-value-bind (ip port) (%addrman-pick-unconnected node :new-only t)
        (when ip
          (do-feeler-connection node ip (or port (network-port (node-network node)))))))))

(defun maintain-peers (node)
  "Run periodic peer maintenance: health checks, reconnection, dedicated
block-relay-only slots, and an occasional feeler probe."
  (check-peers-health node)
  (connect-added-nodes node)
  (replace-disconnected-peers node)
  (maintain-block-relay-peers node)
  (maybe-do-feeler node))

;;;; Blockchain Synchronization

(defun sync-blockchain (node)
  "Run one IBD/follow-tip cycle against connected peers.

Doesn't short-circuit on `peer-start-height` since that value is frozen
at handshake and goes stale once the chain advances — start-ibd's
header-sync phase is what discovers new tips, and its block-download
phase exits quickly when there's nothing new to fetch."
  (unless (node-peers node)
    (log-warn "No peers connected, cannot sync")
    (return-from sync-blockchain 0))

  ;; IBD drives the current chainstate (its tip and coins view). When an
  ;; assumeutxo background sync is active, the historical chainstate rides
  ;; along as a second download cursor inside the same IBD pass: run-ibd
  ;; queues its [historical-tip .. snapshot-base] range and routes received
  ;; blocks to whichever chainstate owns their height.
  (let ((chainstate (node-current-chainstate node))
        (peer-height (bitcoin-lisp.networking:peer-start-height (find-best-peer node))))
    (log-debug "Sync cycle: local height ~D, peer-start height ~D"
               (bitcoin-lisp.storage:current-height chainstate)
               peer-height)
    (bitcoin-lisp.networking::start-ibd
     (node-peers node)
     chainstate
     (bitcoin-lisp.storage:chain-state-coins-view chainstate)
     (node-block-store node)
     peer-height
     :historical-chainstate (node-historical-chainstate node)
     :fee-estimator (node-fee-estimator node)
     :recent-rejects (node-recent-rejects node)
     :mempool (node-mempool node)
     :address-book (node-address-book node))))


(defun find-best-peer (node)
  "Find the best peer for syncing (highest block height)."
  (let ((ready-peers (remove-if-not
                      (lambda (p)
                        (eq (bitcoin-lisp.networking:peer-state p) :ready))
                      (node-peers node))))
    (when ready-peers
      (first (sort (copy-list ready-peers) #'>
                   :key #'bitcoin-lisp.networking:peer-start-height)))))

;;;; Status and Info

(defun node-status ()
  "Print the current node status."
  (unless *node*
    (format t "Node is not running.~%")
    (return-from node-status nil))

  (format t "~%=== Bitcoin-Lisp Node Status ===~%")
  (format t "Network: ~A~%" (node-network *node*))
  (format t "Running: ~A~%" (if (node-running *node*) "Yes" "No"))
  (format t "Syncing: ~A~%" (if (node-syncing *node*) "Yes" "No"))
  (when (node-sync-thread *node*)
    (format t "Sync thread: ~A~%"
            (if (bt:thread-alive-p (node-sync-thread *node*)) "Active" "Stopped")))
  (format t "Data directory: ~A~%" (node-data-directory *node*))
  (format t "~%Chain State:~%")
  (when (node-chain-state *node*)
    (format t "  Height: ~D~%"
            (bitcoin-lisp.storage:current-height (node-chain-state *node*)))
    (format t "  Best block: ~A~%"
            (bitcoin-lisp.crypto:bytes-to-hex
             (bitcoin-lisp.storage:best-block-hash (node-chain-state *node*)))))
  (format t "~%UTXO Set:~%")
  (when (node-utxo-set *node*)
    (format t "  UTXOs: ~D~%"
            (bitcoin-lisp.storage:utxo-count (node-utxo-set *node*))))
  (format t "~%Mempool:~%")
  (when (node-mempool *node*)
    (format t "  Transactions: ~D~%"
            (bitcoin-lisp.mempool:mempool-count (node-mempool *node*)))
    (format t "  Size: ~:D bytes~%"
            (bitcoin-lisp.mempool:mempool-total-size (node-mempool *node*))))
  (format t "~%Peers:~%")
  (if (node-peers *node*)
      (dolist (peer (node-peers *node*))
        (format t "  - ~A (height ~D, latency ~Dms)~%"
                (bitcoin-lisp.networking:peer-user-agent peer)
                (bitcoin-lisp.networking:peer-start-height peer)
                (bitcoin-lisp.networking:peer-ping-latency peer)))
      (format t "  (no peers connected)~%"))
  (format t "~%")
  t)


