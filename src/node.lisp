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

;;;; Node State

(defstruct node
  "Bitcoin node state."
  (network :testnet :type keyword)
  (data-directory nil :type (or null pathname))
  (chain-state nil)
  (block-store nil)
  (utxo-set nil)
  (peers '() :type list)
  (running nil :type boolean)
  (log-level :info :type keyword)
  (sync-thread nil :type (or null bt:thread))
  (syncing nil :type boolean)
  (lock (bt:make-lock "node-lock")))

(defvar *node* nil
  "Current running node instance.")

;;;; Logging

(defvar *log-stream* nil
  "Stream for log output. NIL means logs only go to buffer.")

(defvar *log-file-stream* nil
  "File stream for log output, if logging to file.")

(defvar *log-levels*
  '(:debug 0 :info 1 :warn 2 :error 3)
  "Log level priority values.")

(defconstant +log-buffer-size+ 500
  "Maximum number of log entries to keep in memory.")

(defvar *log-buffer* (make-array +log-buffer-size+ :initial-element nil)
  "Ring buffer for recent log messages.")

(defvar *log-buffer-index* 0
  "Current write position in log buffer.")

(defvar *log-buffer-count* 0
  "Number of entries in log buffer.")

(defvar *log-buffer-lock* (bt:make-lock "log-buffer-lock")
  "Lock for thread-safe log buffer access.")

(defun log-level-value (level)
  "Get numeric value for log LEVEL."
  (getf *log-levels* level 1))

(defun format-log-entry (level format-string args)
  "Format a log entry and return the string."
  (let ((timestamp (multiple-value-bind (sec min hour day month year)
                       (get-decoded-time)
                     (format nil "~4,'0D-~2,'0D-~2,'0D ~2,'0D:~2,'0D:~2,'0D"
                             year month day hour min sec))))
    (format nil "[~A] ~A: ~?"
            timestamp
            (string-upcase (symbol-name level))
            format-string args)))

(defun add-to-log-buffer (entry)
  "Add a log entry to the ring buffer."
  (bt:with-lock-held (*log-buffer-lock*)
    (setf (aref *log-buffer* *log-buffer-index*) entry)
    (setf *log-buffer-index* (mod (1+ *log-buffer-index*) +log-buffer-size+))
    (when (< *log-buffer-count* +log-buffer-size+)
      (incf *log-buffer-count*))))

(defun node-log (level format-string &rest args)
  "Log a message at LEVEL."
  (when (and *node*
             (>= (log-level-value level)
                 (log-level-value (node-log-level *node*))))
    (let ((entry (format-log-entry level format-string args)))
      ;; Always add to buffer
      (add-to-log-buffer entry)
      ;; Write to console if *log-stream* is set
      (when *log-stream*
        (format *log-stream* "~A~%" entry)
        (finish-output *log-stream*))
      ;; Write to file if logging to file
      (when *log-file-stream*
        (format *log-file-stream* "~A~%" entry)
        (finish-output *log-file-stream*)))))

(defmacro log-debug (format-string &rest args)
  `(node-log :debug ,format-string ,@args))

(defmacro log-info (format-string &rest args)
  `(node-log :info ,format-string ,@args))

(defmacro log-warn (format-string &rest args)
  `(node-log :warn ,format-string ,@args))

(defmacro log-error (format-string &rest args)
  `(node-log :error ,format-string ,@args))

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
  "Initialize a new node with the given data directory and network."
  (let ((data-path (pathname data-directory)))
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
                        (sync t))
  "Start the Bitcoin node.

DATA-DIRECTORY: Path to store blockchain data
NETWORK: :testnet or :mainnet
LOG-LEVEL: :debug, :info, :warn, or :error
MAX-PEERS: Maximum number of peer connections
SYNC: If T, start syncing immediately

Returns the node instance."
  (when *node*
    (log-warn "Node already running, stopping first")
    (stop-node))

  ;; Initialize node
  (setf *node* (init-node data-directory :network network :log-level log-level))
  (log-info "Bitcoin-Lisp Node v0.1.0")
  (log-info "Network: ~A" network)
  (log-info "Data directory: ~A" data-directory)

  ;; Initialize chain state
  (log-info "Loading chain state...")
  (setf (node-chain-state *node*)
        (bitcoin-lisp.storage:init-chain-state (node-data-directory *node*)))
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

  ;; Initialize secp256k1
  (log-info "Initializing cryptographic context...")
  (bitcoin-lisp.crypto:ensure-secp256k1-loaded)

  (setf (node-running *node*) t)

  ;; Connect to peers and sync if requested (in background thread)
  (when sync
    (setf (node-sync-thread *node*)
          (bt:make-thread
           (lambda ()
             (handler-case
                 (progn
                   (connect-to-peers *node* max-peers)
                   (when (node-peers *node*)
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

  ;; Cleanup secp256k1
  (bitcoin-lisp.crypto:cleanup-secp256k1)

  (log-info "Node stopped")

  (setf *node* nil)
  t)

;;;; Peer Management

(defun connect-to-peers (node max-peers)
  "Connect to Bitcoin network peers."
  (log-info "Discovering peers from DNS seeds...")
  (let ((addresses (bitcoin-lisp.networking:discover-peers)))
    (log-info "Found ~D potential peers" (length addresses))

    (let ((connected 0))
      (dolist (addr (alexandria:shuffle (copy-list addresses)))
        (when (>= connected max-peers)
          (return))

        (log-debug "Trying to connect to ~A..." addr)
        (handler-case
            (let ((peer (bitcoin-lisp.networking:connect-peer
                         addr (network-port (node-network node)))))
              (when peer
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

;;;; Blockchain Synchronization

(defun sync-blockchain (node &key (max-blocks 1000))
  "Synchronize the blockchain with connected peers.
Downloads up to MAX-BLOCKS."
  (unless (node-peers node)
    (log-warn "No peers connected, cannot sync")
    (return-from sync-blockchain 0))

  (let ((best-peer (find-best-peer node)))
    (unless best-peer
      (log-warn "No suitable peer for sync")
      (return-from sync-blockchain 0))

    (let ((start-height (bitcoin-lisp.storage:current-height
                         (node-chain-state node)))
          (peer-height (bitcoin-lisp.networking:peer-start-height best-peer)))

      (log-info "Starting sync: local height ~D, peer height ~D"
                start-height peer-height)

      (when (>= start-height peer-height)
        (log-info "Already synced to peer height")
        (return-from sync-blockchain 0))

      ;; Request headers first
      (log-info "Requesting headers...")
      (bitcoin-lisp.networking:request-headers best-peer (node-chain-state node))

      (let ((blocks-synced 0)
            (last-progress-report 0))
        (loop while (and (node-running node)
                         (< blocks-synced max-blocks)
                         (< (+ start-height blocks-synced) peer-height))
              do (multiple-value-bind (command payload)
                     (bitcoin-lisp.networking:receive-message best-peer :timeout 120)
                   (unless command
                     (log-warn "Timeout waiting for message")
                     (return))
                   (bitcoin-lisp.networking:handle-message
                    best-peer command payload
                    (node-chain-state node)
                    (node-utxo-set node)
                    (node-block-store node))
                   (when (string= command "block")
                     (incf blocks-synced)
                     ;; Progress report every 100 blocks
                     (when (>= (- blocks-synced last-progress-report) 100)
                       (log-info "Synced ~D blocks, current height ~D"
                                 blocks-synced
                                 (bitcoin-lisp.storage:current-height
                                  (node-chain-state node)))
                       (setf last-progress-report blocks-synced)))))

        (log-info "Sync complete: ~D blocks downloaded, height now ~D"
                  blocks-synced
                  (bitcoin-lisp.storage:current-height (node-chain-state node)))

        ;; Save state after sync
        (bitcoin-lisp.storage:save-state (node-chain-state node))

        blocks-synced))))

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


