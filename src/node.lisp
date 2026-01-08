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
  (log-level :info :type keyword))

(defvar *node* nil
  "Current running node instance.")

;;;; Logging

(defvar *log-stream* *standard-output*
  "Stream for log output.")

(defvar *log-levels*
  '(:debug 0 :info 1 :warn 2 :error 3)
  "Log level priority values.")

(defun log-level-value (level)
  "Get numeric value for log LEVEL."
  (getf *log-levels* level 1))

(defun node-log (level format-string &rest args)
  "Log a message at LEVEL."
  (when (and *node*
             (>= (log-level-value level)
                 (log-level-value (node-log-level *node*))))
    (let ((timestamp (multiple-value-bind (sec min hour day month year)
                         (get-decoded-time)
                       (format nil "~4,'0D-~2,'0D-~2,'0D ~2,'0D:~2,'0D:~2,'0D"
                               year month day hour min sec))))
      (format *log-stream* "[~A] ~A: ~?~%"
              timestamp
              (string-upcase (symbol-name level))
              format-string args)
      (finish-output *log-stream*))))

(defmacro log-debug (format-string &rest args)
  `(node-log :debug ,format-string ,@args))

(defmacro log-info (format-string &rest args)
  `(node-log :info ,format-string ,@args))

(defmacro log-warn (format-string &rest args)
  `(node-log :warn ,format-string ,@args))

(defmacro log-error (format-string &rest args)
  `(node-log :error ,format-string ,@args))

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

  ;; Connect to peers and sync if requested
  (when sync
    (connect-to-peers *node* max-peers)
    (when (node-peers *node*)
      (sync-blockchain *node*)))

  (log-info "Node started successfully")
  *node*)

(defun stop-node ()
  "Stop the running Bitcoin node."
  (unless *node*
    (return-from stop-node nil))

  (log-info "Stopping node...")

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

  (setf (node-running *node*) nil)
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


