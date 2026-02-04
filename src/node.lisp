(in-package #:bitcoin-lisp)

;;; Bitcoin Node
;;;
;;; Main entry point for the Bitcoin full node.
;;; Coordinates all subsystems: networking, storage, validation.

;;;; Network Configuration

(defconstant +testnet+ :testnet)
(defconstant +mainnet+ :mainnet)

(defvar *network* +testnet+
  "Current network mode (:testnet or :mainnet).")

(defun network-magic (network)
  "Return the network magic bytes for NETWORK."
  (ecase network
    (:testnet bitcoin-lisp.serialization:+testnet-magic+)
    (:mainnet bitcoin-lisp.serialization:+mainnet-magic+)))

(defun network-port (network)
  "Return the default port for NETWORK."
  (ecase network
    (:testnet 18333)
    (:mainnet 8333)))

(defun network-dns-seeds (network)
  "Return the DNS seeds for NETWORK."
  (ecase network
    (:testnet bitcoin-lisp.networking:*testnet-dns-seeds*)
    (:mainnet bitcoin-lisp.networking:*mainnet-dns-seeds*)))

(defun network-rpc-port (network)
  "Return the default RPC port for NETWORK."
  (ecase network
    (:testnet 18332)
    (:mainnet 8332)))

(defvar *mainnet-relay-enabled* nil
  "Whether transaction relay is enabled on mainnet. Default NIL for safety.")

;;;; Node State

(defstruct node
  "Bitcoin node state."
  (network :testnet :type keyword)
  (data-directory nil :type (or null pathname))
  (chain-state nil)
  (block-store nil)
  (utxo-set nil)
  (mempool nil)
  (tx-index nil)  ; Transaction index (optional, for getrawtransaction)
  (fee-estimator nil)  ; Fee rate estimator for estimatesmartfee
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

;;;; Startup Sequence

(defun init-node (data-directory &key (network :testnet) (log-level :info))
  "Initialize a new node with the given data directory and network.
For mainnet, data is stored in a 'mainnet' subdirectory.
For testnet, data stays at the base directory (backward compatible)."
  ;; Validate network parameter
  (unless (member network '(:testnet :mainnet))
    (error "Invalid network: ~A. Must be :testnet or :mainnet." network))

  ;; Set global network variable
  (setf *network* network)

  ;; Calculate data path - mainnet uses subdirectory, testnet stays at root
  (let* ((base-path (pathname data-directory))
         (data-path (if (eq network :mainnet)
                        (merge-pathnames "mainnet/" base-path)
                        base-path)))
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
                        (network :testnet)
                        (log-level :info)
                        (max-peers 8)
                        (sync t)
                        (txindex nil)
                        (rpc-port nil)
                        (rpc-bind "127.0.0.1")
                        (rpc-user nil)
                        (rpc-password nil))
  "Start the Bitcoin node.

DATA-DIRECTORY: Path to store blockchain data (mainnet uses mainnet/ subdirectory)
NETWORK: :testnet or :mainnet
LOG-LEVEL: :debug, :info, :warn, or :error
MAX-PEERS: Maximum number of peer connections
SYNC: If T, start syncing immediately
TXINDEX: If T, enable transaction index for getrawtransaction lookups
RPC-PORT: Port for RPC server (nil = no RPC, default 18332 testnet / 8332 mainnet)
RPC-BIND: Address to bind RPC server (default 127.0.0.1)
RPC-USER: RPC authentication username (nil = no auth)
RPC-PASSWORD: RPC authentication password

Returns the node instance."
  (when *node*
    (log-warn "Node already running, stopping first")
    (stop-node))

  ;; Initialize node
  (setf *node* (init-node data-directory :network network :log-level log-level))
  (setf (node-max-peers *node*) max-peers)
  (setf *current-log-level* log-level)
  (log-info "Bitcoin-Lisp Node v0.1.0")
  (log-info "Network: ~A" network)
  (log-info "Data directory: ~A" (node-data-directory *node*))

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

  ;; Add genesis block to block index (needed for header validation)
  (let ((genesis-hash (bitcoin-lisp.storage::chain-state-genesis-hash
                       (node-chain-state *node*))))
    (unless (bitcoin-lisp.storage:get-block-index-entry
             (node-chain-state *node*) genesis-hash)
      (bitcoin-lisp.storage:add-block-index-entry
       (node-chain-state *node*)
       (bitcoin-lisp.storage:make-block-index-entry
        :hash genesis-hash
        :height 0
        :prev-entry nil
        :chain-work 0
        :status :valid))))

  (when (bitcoin-lisp.storage:load-state (node-chain-state *node*))
    (log-info "Loaded existing chain state: height ~D"
              (bitcoin-lisp.storage:current-height (node-chain-state *node*))))

  ;; Initialize block store
  (log-info "Initializing block storage...")
  (setf (node-block-store *node*)
        (bitcoin-lisp.storage:init-block-store (node-data-directory *node*)))

  ;; Initialize UTXO set
  (log-info "Initializing UTXO set...")
  (setf (node-utxo-set *node*) (bitcoin-lisp.storage:make-utxo-set))

  ;; Load persisted UTXO set if available
  (let ((utxo-path (bitcoin-lisp.storage:utxo-set-file-path
                    (node-data-directory *node*))))
    (when (bitcoin-lisp.storage:load-utxo-set (node-utxo-set *node*) utxo-path)
      (log-info "Loaded persisted UTXO set: ~D entries"
                (bitcoin-lisp.storage:utxo-count (node-utxo-set *node*)))))

  ;; Load persisted header index if available
  (when (bitcoin-lisp.storage:load-header-index (node-chain-state *node*))
    (log-info "Loaded persisted header index: ~D entries"
              (hash-table-count
               (bitcoin-lisp.storage::chain-state-block-index
                (node-chain-state *node*)))))

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
  (when sync
    (setf (node-sync-thread *node*)
          (bt:make-thread
           (lambda ()
             (handler-case
                 (progn
                   ;; Connect to at least 2 peers within 60 seconds before syncing
                   ;; This helps avoid getting stuck with a single unresponsive peer
                   (connect-to-peers *node* max-peers :timeout 60 :min-peers 2)
                   (when (>= (length (node-peers *node*)) 1)
                     (setf (node-syncing *node*) t)
                     (unwind-protect
                          (sync-blockchain *node*)
                       (setf (node-syncing *node*) nil))))
               (error (c)
                 (log-error "Sync thread error: ~A" c))))
           :name "bitcoin-sync-thread")))

  (log-info "Node started successfully")
  *node*)

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
                       (* 5 internal-time-units-per-second))))
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

  ;; Save UTXO set
  (log-info "Saving UTXO set...")
  (when (node-utxo-set *node*)
    (bitcoin-lisp.storage:save-utxo-set
     (node-utxo-set *node*)
     (bitcoin-lisp.storage:utxo-set-file-path (node-data-directory *node*))))

  ;; Save fee statistics
  (when (node-fee-estimator *node*)
    (log-info "Saving fee statistics...")
    (bitcoin-lisp.mempool:save-fee-stats (node-fee-estimator *node*)))

  ;; Save header index
  (log-info "Saving header index...")
  (when (node-chain-state *node*)
    (bitcoin-lisp.storage:save-header-index (node-chain-state *node*)))

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
MAX-PEERS: Target number of peers to connect
TIMEOUT: Maximum seconds to spend connecting (default 60)
MIN-PEERS: Return early once we have at least this many peers (default 1)
Returns the number of peers connected."
  (log-info "Discovering peers from DNS seeds...")
  (let ((addresses (bitcoin-lisp.networking:discover-peers)))
    (log-info "Found ~D potential peers" (length addresses))

    ;; Store discovered addresses for reconnection
    (setf (node-known-addresses node) (alexandria:shuffle (copy-list addresses)))

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
                  (push peer (node-peers node))
                  (incf connected))
                (unless (eq (bitcoin-lisp.networking:peer-state peer) :ready)
                  (bitcoin-lisp.networking:disconnect-peer peer))))
          (error (c)
            (log-debug "Failed to connect to ~A: ~A" addr c))))

      (log-info "Connected to ~D peer~:P" connected)
      connected)))

;;;; Peer Health and Reconnection

(defun check-peers-health (node)
  "Check health of all peers. Disconnect unresponsive ones."
  (let ((to-disconnect '()))
    (dolist (peer (node-peers node))
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

(defun sync-blockchain (node &key (max-blocks 1000))
  "Synchronize the blockchain with connected peers.
Downloads up to MAX-BLOCKS using the IBD system."
  (unless (node-peers node)
    (log-warn "No peers connected, cannot sync")
    (return-from sync-blockchain 0))

  (let ((start-height (bitcoin-lisp.storage:current-height (node-chain-state node)))
        (peer-height (bitcoin-lisp.networking:peer-start-height (find-best-peer node))))

    (log-info "Starting sync: local height ~D, peer height ~D" start-height peer-height)

    (when (>= start-height peer-height)
      (log-info "Already synced to peer height")
      (return-from sync-blockchain 0))

    ;; Use IBD system for sync
    (let ((target (min (+ start-height max-blocks) peer-height)))
      (bitcoin-lisp.networking::start-ibd
       (node-peers node)
       (node-chain-state node)
       (node-utxo-set node)
       (node-block-store node)
       target
       :fee-estimator (node-fee-estimator node)))))


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


