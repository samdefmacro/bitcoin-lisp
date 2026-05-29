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
  (fee-estimator nil)  ; Fee rate estimator for estimatesmartfee
  (address-book nil)  ; Persistent peer address database
  (recent-rejects nil)  ; Recently rejected transaction filter (DoS protection)
  (peers '() :type list)
  (running nil :type boolean)
  (log-level :info :type keyword)
  (sync-thread nil :type (or null bt:thread))
  (syncing nil :type boolean)
  (lock (bt:make-lock "node-lock"))
  (known-addresses '() :type list)
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

(defun start-node (&key (data-directory "~/.bitcoin-lisp/")
                        (network :testnet3)
                        (log-level :info)
                        (log-file nil)
                        (console-log t)
                        (max-peers 8)
                        (sync t)
                        (txindex nil)
                        (prune nil)
                        (rpc-port nil)
                        (rpc-bind "127.0.0.1")
                        (rpc-user nil)
                        (rpc-password nil))
  "Start the Bitcoin node.

DATA-DIRECTORY: Path to store blockchain data (mainnet uses mainnet/ subdirectory)
NETWORK: :testnet3 or :mainnet
LOG-LEVEL: :debug, :info, :warn, or :error
LOG-FILE: If non-nil, also append node logs to this path (in addition to console)
CONSOLE-LOG: If T (default), mirror logs to *standard-output* / REPL
MAX-PEERS: Maximum number of peer connections
SYNC: If T, start syncing immediately
TXINDEX: If T, enable transaction index for getrawtransaction lookups
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

  (let ((load-result (bitcoin-lisp.storage:load-state (node-chain-state *node*))))
    (case load-result
      ((:inconsistent)
       (log-error "Chainstate is in-transition (a previous flush was interrupted between writing chainstate.dat and utxoset.dat). On-disk pair is inconsistent. Please move ~A aside and re-sync from genesis."
                  (node-data-directory *node*))
       (error "chainstate inconsistent: re-sync required"))
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
          :status :valid))))

  ;; Initialize undo data persistence
  (let ((undo-path (merge-pathnames "undo/" (node-data-directory *node*))))
    (bitcoin-lisp.validation:initialize-undo-storage undo-path)
    (log-info "Undo data directory: ~A" undo-path))

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

  ;; Initialize peer address book
  (log-info "Loading peer address book...")
  (setf (node-address-book *node*) (bitcoin-lisp.networking:make-address-book))
  (let ((peers-path (bitcoin-lisp.networking:peers-dat-path (node-data-directory *node*))))
    (when (bitcoin-lisp.networking:load-address-book (node-address-book *node*) peers-path)
      (log-info "Loaded peer address book: ~D entries"
                (bitcoin-lisp.networking:address-book-count (node-address-book *node*)))))

  ;; Initialize transaction index (optional)
  (when txindex
    (log-info "Initializing transaction index...")
    (setf (node-tx-index *node*)
          (bitcoin-lisp.storage:init-tx-index (node-data-directory *node*)
                                               :enabled t))
    (log-info "Transaction index loaded: ~D entries"
              (bitcoin-lisp.storage:txindex-count (node-tx-index *node*))))

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
                         do (cond
                              ((>= (length (node-peers *node*)) 1)
                               (setf (node-syncing *node*) t)
                               (unwind-protect
                                    (sync-blockchain *node*)
                                 (setf (node-syncing *node*) nil))
                               (replace-disconnected-peers *node*)
                               (sleep 30))
                              (t
                               (log-warn "No peers available, reconnecting in 5s...")
                               (sleep 5)
                               (connect-to-peers *node* max-peers
                                                 :timeout 30 :min-peers 1)))))
               (error () nil)))
           :name "bitcoin-sync-thread")))

  (install-shutdown-handler)
  (log-info "Node started successfully")
  *node*)

(defparameter +flush-every-n-blocks+ 1000
  "Flush chainstate + UTXO set to disk every N connected blocks so a hard
   crash loses at most N blocks of work. Mirrors Bitcoin Core's
   nMinBlocksToKeep / FlushStateToDisk cadence (validation.cpp).")

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
         (header-count (and (node-chain-state *node*)
                            (hash-table-count
                             (bitcoin-lisp.storage::chain-state-block-index
                              (node-chain-state *node*)))))
         (sig-cache-count
           (hash-table-count bitcoin-lisp.coalton.interop:*signature-cache*))
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
    (log-info "MEM[~A]: utxo=~D headers=~D sigcache=~D ibd-pend=~A queue=~A inflight=~A heap-used=~,1FMB heap-cap=~,1FMB"
              label utxo-count header-count sig-cache-count
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
          (bitcoin-lisp.storage:coins-view-cache-flush
           (node-utxo-set *node*)))
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
                +flush-every-n-seconds+))
    (do-flush)))

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

  ;; Stop RPC server first
  (bitcoin-lisp.rpc:stop-rpc-server)

  ;; Signal the node to stop
  (setf (node-running *node*) nil)

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
  (setf (node-peers *node*) nil)

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

  ;; Cleanup secp256k1
  (bitcoin-lisp.crypto:cleanup-secp256k1)

  (log-info "Node stopped")

  (setf *node* nil)
  t)

;;;; Peer Management

(defun connect-to-peers (node max-peers &key (timeout 60) (min-peers 1))
  "Connect to Bitcoin network peers.
Uses address book for warm starts, falls back to DNS seeds.
MAX-PEERS: Target number of peers to connect
TIMEOUT: Maximum seconds to spend connecting (default 60)
MIN-PEERS: Return early once we have at least this many peers (default 1)
Returns the number of peers connected."
  (let ((address-book (node-address-book node))
        (addresses '()))
    ;; Warm start: prefer address book peers sorted by score
    (when (and address-book
               (>= (bitcoin-lisp.networking:address-book-count address-book) 8))
      (log-info "Using peer address book (~D entries)..."
                (bitcoin-lisp.networking:address-book-count address-book))
      (let ((sorted (bitcoin-lisp.networking:address-book-sorted-peers address-book)))
        (setf addresses
              (mapcar (lambda (pa)
                        (bitcoin-lisp.networking:ip-bytes-to-string
                         (bitcoin-lisp.networking:peer-address-ip pa)))
                      sorted))))
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
                        (bitcoin-lisp.networking:address-book-record-success
                         address-book ip-bytes peer-port))))
                  ;; Send compact block negotiation (BIP 152)
                  (bitcoin-lisp.networking:send-compact-block-negotiation peer)
                  (push peer (node-peers node))
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
                  (bitcoin-lisp.networking:address-book-record-failure
                   address-book ip-bytes peer-port)))))))

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
      (setf (node-peers node) (remove peer (node-peers node))))
    (length to-disconnect)))

(defun replace-disconnected-peers (node)
  "Replace disconnected peers to maintain target peer count.
Returns the number of new peers connected."
  (let* ((active-peers (remove-if-not
                        (lambda (p)
                          (eq (bitcoin-lisp.networking:peer-state p) :ready))
                        (node-peers node)))
         (needed (- (node-max-peers node) (length active-peers))))
    (when (<= needed 0)
      (return-from replace-disconnected-peers 0))

    ;; Remove disconnected peers from list
    (setf (node-peers node)
          (remove-if (lambda (p)
                       (eq (bitcoin-lisp.networking:peer-state p) :disconnected))
                     (node-peers node)))

    ;; Get addresses already in use
    (let ((used-addrs (mapcar #'bitcoin-lisp.networking:peer-address
                              (node-peers node)))
          (connected 0))
      (dolist (addr (node-known-addresses node))
        (when (>= connected needed)
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
                    (push peer (node-peers node))
                    (incf connected))
                  (unless (eq (bitcoin-lisp.networking:peer-state peer) :ready)
                    (bitcoin-lisp.networking:disconnect-peer peer))))
            (error (c)
              (declare (ignore c))))))
      connected)))

(defun maintain-peers (node)
  "Run periodic peer maintenance: health checks and reconnection."
  (check-peers-health node)
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


