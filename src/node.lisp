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
  (chain-state nil)
  (block-store nil)
  (utxo-set nil)
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
  "Set by start-node when load-state reports :inconsistent, so the recovery
runs after the block store, UTXO cache, and header index are all open.")

(defun %coinbase-committed-p (node block-hash)
  "T iff BLOCK-HASH's coinbase output 0 is an unspent coin in the UTXO
LevelDB. A coinbase is unspendable for +coinbase-maturity+ (100) blocks,
so once its block is committed to the UTXO set the coin is necessarily
present — and every block above the committed tip contributes no coins at
all. That makes coinbase-presence a monotone probe for 'is the UTXO set at
or past this block', with no false positives from later spends. Returns
NIL if the block isn't on disk."
  (let ((block (bitcoin-lisp.storage:get-block (node-block-store node) block-hash)))
    (when block
      (let* ((cb (first (bitcoin-lisp.serialization:bitcoin-block-transactions block)))
             (txid (bitcoin-lisp.serialization:transaction-hash cb)))
        (and (bitcoin-lisp.storage:get-utxo (node-utxo-set node) txid 0) t)))))

(defun recover-inconsistent-chainstate (node)
  "Resolve an in-transition chainstate without a from-genesis resync.
Probes whether the recorded tip's coins were committed; if so just clears
the marker, otherwise walks back to the highest ancestor whose coins ARE
committed (the true UTXO tip) and rewrites chainstate.dat there so IBD
re-validates only the gap. Returns T on success, NIL if the blocks needed
to resolve it aren't on disk (caller then aborts for a resync)."
  (let* ((chain-state (node-chain-state node))
         (new-hash (bitcoin-lisp.storage:best-block-hash chain-state))
         (new-height (bitcoin-lisp.storage:current-height chain-state)))
    (cond
      ((null new-hash)
       (log-error "Chainstate recovery: no recorded tip to recover from")
       nil)
      ;; Phase 2 committed the new tip — chainstate.dat already holds it,
      ;; just drop the marker.
      ((%coinbase-committed-p node new-hash)
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
                         (%coinbase-committed-p
                          node (bitcoin-lisp.storage:block-index-entry-hash entry))))
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
            nil)))))))

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
                        (reindex-chainstate nil))
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

  ;; Validate and set pruning configuration
  (setf *prune-target-mib* prune)
  (when prune
    (unless (or (= prune 1) (>= prune 550))
      (error "Invalid prune target: ~A MiB. Must be 1 (manual-only) or >= 550." prune))
    (when (and prune txindex)
      (error "Cannot enable both pruning and txindex. Pruned blocks cannot be looked up.")))

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

  ;; Initialize chain state
  (log-info "Loading chain state...")
  (setf (node-chain-state *node*)
        (bitcoin-lisp.storage:init-chain-state (node-data-directory *node*)))

  ;; Genesis block index entry is ensured after load-header-index below

  (setf *pending-chainstate-recovery* nil)
  (let ((load-result (bitcoin-lisp.storage:load-state (node-chain-state *node*))))
    (case load-result
      ((:inconsistent)
       ;; A flush was interrupted mid-commit. Don't abort — defer recovery
       ;; until the block store, UTXO cache, and header index are open
       ;; (recover-inconsistent-chainstate needs all three).
       (log-warn "Chainstate in-transition (flush interrupted); will attempt automatic recovery after storage init")
       (setf *pending-chainstate-recovery* t))
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
         (chainstate-path (namestring (merge-pathnames "chainstate/" data-dir)))
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
      (setf (node-utxo-set *node*)
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

  ;; Resolve an interrupted-flush chainstate now that the block store, UTXO
  ;; cache, and header index are all available. Only abort (resync) if the
  ;; on-disk blocks needed to recover are gone.
  (when *pending-chainstate-recovery*
    (setf *pending-chainstate-recovery* nil)
    (unless (recover-inconsistent-chainstate *node*)
      (error "chainstate inconsistent and unrecoverable: move ~A aside and re-sync"
             (node-data-directory *node*))))

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
    (let* ((bfi (node-blockfilterindex *node*))
           (cs (node-chain-state *node*))
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
                  bfi (node-chain-state *node*) (node-block-store *node*)
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
    (let* ((csi (node-coinstatsindex *node*))
           (cs (node-chain-state *node*))
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
                               (replace-disconnected-peers *node*)
                               ;; Re-route any tx getdata that timed out to
                               ;; another announcer (TxRequestTracker).
                               (bitcoin-lisp.networking:retry-timed-out-tx-requests)
                               (loop repeat 30 while (node-running *node*)
                                     do (sleep 1)))
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

(defun do-flush ()
  "Synchronously flush chainstate + header-index + UTXO set with 3-phase
commit (mirrors Bitcoin Core's DB_HEAD_BLOCKS marker pattern in
txdb.cpp::CCoinsViewDB::BatchWrite):

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
  (log-memory-snapshot "pre-flush")
  (handler-case
      (#+sbcl sb-sys:without-interrupts
       #-sbcl progn
        ;; Phase 1: mark the chainstate as in-transition.
        (when (node-chain-state *node*)
          (bitcoin-lisp.storage:save-state
           (node-chain-state *node*) :in-transition t)
          (bitcoin-lisp.storage:save-header-index (node-chain-state *node*)))
        ;; Phase 2: flush cache → LevelDB. Per-flush work is proportional
        ;; to dirty entries (typically a few thousand at the tip), not
        ;; the full ~17M-entry set — replaces the ~13s utxoset.dat
        ;; rewrite that previously froze the sync thread.
        (when (node-utxo-set *node*)
          ;; :sync t fdatasyncs the LevelDB writebatch before we proceed, so a
          ;; power loss after Phase 3 clears the marker cannot leave the coins
          ;; un-durable while chainstate.dat says they are committed. (Was
          ;; :sync nil — atomic but not durable; the shutdown flush already
          ;; syncs, the periodic one now matches it.)
          (bitcoin-lisp.storage:coins-view-cache-flush
           (node-utxo-set *node*) :sync t))
        ;; Phase 3: commit by re-saving chainstate without the marker.
        (when (node-chain-state *node*)
          (bitcoin-lisp.storage:save-state
           (node-chain-state *node*) :in-transition nil))
        (setf *last-flush-universal-time* (get-universal-time)
              *blocks-since-flush* 0)
        (log-info "Periodic flush: chainstate at height ~D"
                  (and (node-chain-state *node*)
                       (bitcoin-lisp.storage:current-height
                        (node-chain-state *node*)))))
    (error (c)
      ;; Was log-warn before — surfaced silently. Bumped to log-error so
      ;; persistence failures are obvious in the log instead of getting
      ;; lost between progress lines.
      (log-error "Periodic flush FAILED: ~A" c)))
  ;; After flush, request a major GC so reachable post-flush memory is the
  ;; only thing in the old generations next time we measure. This is the
  ;; same pattern as Bitcoin Core's CCoinsViewCache::Flush returning bytes
  ;; freed to the system allocator.
  #+sbcl (sb-ext:gc :full t)
  (log-memory-snapshot "post-flush"))

(defun maybe-periodic-flush ()
  "Flush chainstate, UTXO set, and header index to disk if either:
- N blocks have been connected since the last flush, OR
- N seconds have elapsed since the last flush (catches slow-sync regions
  where 1000 blocks would take many minutes to accumulate).

Called from connect-block. Cheap if no flush needed; durable if it does
flush (atomic temp+fsync+rename inside save-*)."
  (unless *node* (return-from maybe-periodic-flush))
  (incf *blocks-since-flush*)
  (when (zerop *last-flush-universal-time*)
    (setf *last-flush-universal-time* (get-universal-time)))
  (when (or (>= *blocks-since-flush* +flush-every-n-blocks+)
            (>= (- (get-universal-time) *last-flush-universal-time*)
                +flush-every-n-seconds+)
            ;; Size trigger (Bitcoin Core dbcache): flush once the coins cache
            ;; reaches its memory budget, so it can't grow unbounded between the
            ;; block-count / time flushes.
            (and (node-utxo-set *node*)
                 (>= (bitcoin-lisp.storage:view-mem-bytes (node-utxo-set *node*))
                     (large-coins-cache-threshold *coins-cache-budget-bytes*))))
    (do-flush)))

(defvar *blockfilterindex-stall-logged* nil
  "One-shot latch so a stalled block filter index (non-contiguous connect
refused) logs a single warning instead of one per block until restart.")

(defun index-block-filter (block block-hash height spent-utxos)
  "Connect-time hook: add BLOCK's BIP158 basic filter to the running node's
block filter index, if one is enabled. SPENT-UTXOS is the undo list the UTXO
apply produced. Never signals -- a filter-index failure must not abort a block
connect -- so consensus is unaffected whether the index is on or off."
  (let ((bfi (and *node* (node-blockfilterindex *node*))))
    (when (and bfi (bitcoin-lisp.storage:blockfilterindex-enabled bfi))
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

(defun index-block-coinstats (block block-hash height spent-utxos)
  "Connect-time hook: fold BLOCK into the running node's coinstatsindex, if one
is enabled. SPENT-UTXOS is the undo list the UTXO apply produced; the block
subsidy is derived from HEIGHT. Never signals -- an index failure must not
abort a block connect -- so consensus is unaffected whether the index is on or
off. Returns NIL (and stalls quietly) if the parent height's record is missing
(non-contiguous); the startup backfill heals such gaps on restart."
  (let ((csi (and *node* (node-coinstatsindex *node*))))
    (when (and csi (bitcoin-lisp.storage:coinstatsindex-enabled csi))
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

  ;; Save chain state
  (log-info "Saving chain state...")
  (when (node-chain-state *node*)
    (bitcoin-lisp.storage:save-state (node-chain-state *node*)))

  ;; Flush UTXO cache to LevelDB and close the underlying DB.
  (log-info "Flushing UTXO cache...")
  (when (node-utxo-set *node*)
    (bitcoin-lisp.storage:coins-view-cache-flush
     (node-utxo-set *node*) :sync t)
    (let ((base (bitcoin-lisp.storage:coins-view-cache-base
                 (node-utxo-set *node*))))
      (when base
        (bitcoin-lisp.storage:close-coins-view-db base))))

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

(defconstant +anchors-magic+ #x414e4331)  ; "ANC1"

(defvar *pending-anchor-addresses* nil
  "Anchor IP strings loaded at startup, consumed (and cleared) by the first
connect-to-peers so they are attempted before DNS-seed candidates.")

(defun anchors-dat-path (data-directory)
  "Path to anchors.dat in DATA-DIRECTORY."
  (merge-pathnames "anchors.dat" data-directory))

(defun save-anchors (node)
  "Persist up to +max-anchors+ currently-connected outbound peers' addresses to
anchors.dat (crash-safe: temp + fsync + atomic rename, CRC32-protected)."
  (let* ((outbound (remove-if #'bitcoin-lisp.networking:peer-inbound
                              (node-peers node)))
         (ready (remove-if-not (lambda (p)
                                 (eq (bitcoin-lisp.networking:peer-state p) :ready))
                               outbound))
         (addrs (mapcar #'bitcoin-lisp.networking:peer-address
                        (subseq ready 0 (min +max-anchors+ (length ready))))))
    (when addrs
      (handler-case
          (bitcoin-lisp.storage:save-file-with-crc32
           (anchors-dat-path (node-data-directory node))
           (lambda (stream)
             (write-byte (ldb (byte 8 24) +anchors-magic+) stream)
             (write-byte (ldb (byte 8 16) +anchors-magic+) stream)
             (write-byte (ldb (byte 8 8) +anchors-magic+) stream)
             (write-byte (ldb (byte 8 0) +anchors-magic+) stream)
             (write-byte (length addrs) stream)
             (dolist (a addrs)
               (let ((bytes (map '(vector (unsigned-byte 8)) #'char-code a)))
                 (write-byte (min 255 (length bytes)) stream)
                 (write-sequence bytes stream)))))
        (error (e) (log-warn "Failed to save anchors: ~A" e)))
      (log-info "Saved ~D anchor peer~:P" (length addrs)))))

(defun load-anchors (node)
  "Read anchors.dat into *pending-anchor-addresses* so the next connect attempts
them first. Missing/corrupt file is ignored."
  (let ((bytes (bitcoin-lisp.storage:load-file-with-crc32
                (anchors-dat-path (node-data-directory node)) 6)))
    (when (and bytes
               (= +anchors-magic+
                  (logior (ash (aref bytes 0) 24) (ash (aref bytes 1) 16)
                          (ash (aref bytes 2) 8) (aref bytes 3))))
      (let ((count (aref bytes 4)) (pos 5) (addrs '()))
        (dotimes (i count)
          (when (< pos (- (length bytes) 4))         ; stay inside payload (before CRC)
            (let ((len (aref bytes pos)))
              (incf pos)
              (when (<= (+ pos len) (- (length bytes) 4))
                (push (map 'string #'code-char (subseq bytes pos (+ pos len))) addrs)
                (incf pos len)))))
        (setf *pending-anchor-addresses* (nreverse addrs))
        (when *pending-anchor-addresses*
          (log-info "Loaded ~D anchor peer~:P for priority reconnection"
                    (length *pending-anchor-addresses*)))))))

(defun connect-to-peers (node max-peers &key (timeout 60) (min-peers 1))
  "Connect to Bitcoin network peers.
Uses address book for warm starts, falls back to DNS seeds.
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
          (let ((pa (bitcoin-lisp.networking:address-book-select address-book)))
            (when pa
              (let ((str (bitcoin-lisp.networking:ip-bytes-to-string
                          (bitcoin-lisp.networking:peer-address-ip pa))))
                (unless (gethash str seen)
                  (setf (gethash str seen) t)
                  (push str picks))))))
        (setf addresses (nreverse picks))))
    ;; Fall back to DNS seeds if not enough candidates
    (when (< (length addresses) 8)
      (log-info "Discovering peers from DNS seeds...")
      (let ((dns-addrs (bitcoin-lisp.networking:discover-peers)))
        (log-info "Found ~D potential peers from DNS" (length dns-addrs))
        (setf addresses (append addresses dns-addrs))
        (setf addresses (remove-duplicates addresses :test #'string=))))

    ;; Fixed-seed fallback for testnet4: even after DNS, the candidate pool
    ;; may have only one /16 group (sprovoost.nl seed has been dark since
    ;; ~2026-05; wiz.biz returns its own /24 cluster only). Mirrors Bitcoin
    ;; Core's vFixedSeeds population in chainparams.cpp — used as a
    ;; last-resort source so we always have netgroup diversity available.
    (when (and (eq (node-network node) :testnet4)
               (let ((groups (remove-duplicates
                              (remove nil (mapcar #'bitcoin-lisp.networking:ip-netgroup
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
             (append addresses bitcoin-lisp.networking:*testnet4-fixed-seeds*)
             :test #'string=)))

    ;; Diversify by /16 netgroup so the first 8 connection attempts spread
    ;; across distinct operators (incident 2026-05-11: 8-of-8 peers were
    ;; from 103.165.192.x wiz.biz nodes — one stall stalled the whole
    ;; sync). Mirrors Bitcoin Core's addrman netgroup bucket selection
    ;; (netaddress.cpp CNetAddr::GetGroup).
    (setf addresses (bitcoin-lisp.networking:diversify-by-netgroup addresses))

    ;; Anchors first (Core anchors.dat): reconnect to the peers we persisted at
    ;; last shutdown before any DNS/addrman candidate, then consume them so
    ;; later reconnect cycles use the normal pool.
    (when *pending-anchor-addresses*
      (setf addresses (remove-duplicates (append *pending-anchor-addresses* addresses)
                                         :test #'string= :from-end t))
      (setf *pending-anchor-addresses* nil))

    (log-info "~D candidate peers available" (length addresses))

    ;; Store discovered addresses for reconnection
    (setf (node-known-addresses node) addresses)

    (let ((connected 0)
          (start-time (get-internal-real-time))
          (timeout-ticks (* timeout internal-time-units-per-second)))
      (dolist (addr (node-known-addresses node))
        ;; Stop if we have enough peers
        (when (>= connected max-peers)
          (return))

        ;; Check timeout - but only exit early if we have minimum peers
        (when (and (>= connected min-peers)
                   (> (- (get-internal-real-time) start-time) timeout-ticks))
          (log-info "Connection timeout reached with ~D peers" connected)
          (return))

        (log-debug "Trying to connect to ~A..." addr)
        (handler-case
            (let ((peer (bitcoin-lisp.networking:connect-peer
                         addr (network-port (node-network node)))))
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
                  (when address-book
                    (let ((ip-bytes (bitcoin-lisp.networking:string-to-ip-bytes addr))
                          (peer-port (network-port (node-network node))))
                      (when ip-bytes
                        (unless (bitcoin-lisp.networking:address-book-lookup
                                 address-book ip-bytes peer-port)
                          (bitcoin-lisp.networking:address-book-add
                           address-book
                           (bitcoin-lisp.networking:make-peer-address
                            :ip ip-bytes
                            :port peer-port
                            :services (bitcoin-lisp.networking:peer-services peer)
                            :last-seen (bitcoin-lisp.serialization:get-unix-time))))
                        (bitcoin-lisp.networking:address-book-good
                         address-book ip-bytes peer-port)
                        (bitcoin-lisp.networking:address-book-connected
                         address-book ip-bytes peer-port))))
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
            (when address-book
              (let ((ip-bytes (bitcoin-lisp.networking:string-to-ip-bytes addr))
                    (peer-port (network-port (node-network node))))
                (when ip-bytes
                  (unless (bitcoin-lisp.networking:address-book-lookup
                           address-book ip-bytes peer-port)
                    (bitcoin-lisp.networking:address-book-add
                     address-book
                     (bitcoin-lisp.networking:make-peer-address
                      :ip ip-bytes
                      :port peer-port
                      :last-seen (bitcoin-lisp.serialization:get-unix-time))))
                  (bitcoin-lisp.networking:address-book-attempt
                   address-book ip-bytes peer-port :count-failure t)))))))

      (log-info "Connected to ~D peer~:P" connected)
      connected)))

;;;; Peer Health and Reconnection

(defun check-peers-health (node)
  "Check health of all peers. Disconnect unresponsive ones.
Also checks compact block reconstruction timeouts (BIP 152)."
  (let ((to-disconnect '()))
    (dolist (peer (node-peers node))
      ;; Check compact block timeout
      (bitcoin-lisp.networking:check-compact-block-timeout peer)
      ;; Check ping/pong health
      (let ((status (bitcoin-lisp.networking:check-peer-health peer)))
        (when (eq status :disconnect)
          (push peer to-disconnect))))
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
  (let* ((active-peers (remove-if-not
                        (lambda (p)
                          (eq (bitcoin-lisp.networking:peer-state p) :ready))
                        (node-peers node)))
         (needed (- (node-max-peers node) (length active-peers))))
    (when (<= needed 0)
      (return-from replace-disconnected-peers 0))

    ;; Get addresses already in use
    (let ((used-addrs (mapcar #'bitcoin-lisp.networking:peer-address
                              (node-peers node)))
          (connected 0))
      (dolist (addr (node-known-addresses node))
        ;; Stop attempting new connect+handshake cycles the moment shutdown is
        ;; requested — each one can otherwise block (connect timeout + handshake
        ;; read) and delay the sync thread reaching its node-running checkpoint.
        (when (or (>= connected needed)
                  (bitcoin-lisp.networking:ibd-stop-requested-p))
          (return))
        (unless (member addr used-addrs :test #'string=)
          (handler-case
              (let ((peer (bitcoin-lisp.networking:connect-peer
                           addr (network-port (node-network node)))))
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
              (declare (ignore c))))))
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

(defun establish-outbound-peer (node host port)
  "Full outbound connect + handshake to HOST:PORT, pushing the ready peer onto
node-peers. Returns the peer or NIL. MUST run on the sync thread so node-peers
stays single-writer. No-op when networking is disabled."
  (when (node-network-active node)
    (handler-case
        (let ((peer (bitcoin-lisp.networking:connect-peer host port)))
          (when peer
            (setf (bitcoin-lisp.networking:peer-address peer) host)
            (if (bitcoin-lisp.networking:perform-handshake peer)
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

(defun maintain-peers (node)
  "Run periodic peer maintenance: health checks and reconnection."
  (check-peers-health node)
  (connect-added-nodes node)
  (replace-disconnected-peers node))

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

  (let ((peer-height (bitcoin-lisp.networking:peer-start-height (find-best-peer node))))
    (log-debug "Sync cycle: local height ~D, peer-start height ~D"
               (bitcoin-lisp.storage:current-height (node-chain-state node))
               peer-height)
    (bitcoin-lisp.networking::start-ibd
     (node-peers node)
     (node-chain-state node)
     (node-utxo-set node)
     (node-block-store node)
     peer-height
     :fee-estimator (node-fee-estimator node)
     :recent-rejects (node-recent-rejects node)
     :mempool (node-mempool node))))


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


