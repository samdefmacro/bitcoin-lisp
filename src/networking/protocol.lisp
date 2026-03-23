(in-package #:bitcoin-lisp.networking)

;;; Bitcoin P2P Protocol Handling
;;;
;;; Higher-level protocol operations for syncing and message handling.

(defmacro with-node-lock (&body body)
  "Execute BODY while holding the node lock for thread-safe state access.
Guards shared state (chain-state, UTXO set, mempool, peer list) against
concurrent access from RPC and sync threads."
  `(let ((node bitcoin-lisp::*node*))
     (if (and node (bitcoin-lisp::node-lock node))
         (bt:with-lock-held ((bitcoin-lisp::node-lock node))
           ,@body)
         (progn ,@body))))

(defstruct peer-manager
  "Manages connections to multiple peers."
  (peers '() :type list)
  (max-peers 8 :type (unsigned-byte 8))
  (known-addresses '() :type list))

;;; Peer discovery

(defun resolve-dns-seed (hostname)
  "Resolve a DNS seed to a list of IP addresses."
  (handler-case
      #+sbcl
      (let ((addresses (sb-bsd-sockets:host-ent-addresses
                        (sb-bsd-sockets:get-host-by-name hostname))))
        (mapcar (lambda (addr)
                  (format nil "~{~D~^.~}" (coerce addr 'list)))
                addresses))
      #-sbcl
      nil
    (error () nil)))

(defun discover-peers (&optional (seeds *dns-seeds*))
  "Discover peers from DNS seeds.
Returns a list of IP address strings."
  (let ((addresses '()))
    (dolist (seed seeds)
      (let ((resolved (resolve-dns-seed seed)))
        (when resolved
          (setf addresses (nconc addresses resolved)))))
    (remove-duplicates addresses :test #'string=)))

;;; Message handling

(defun handle-message (peer command payload chain-state utxo-set block-store
                       &key mempool peers fee-estimator address-book recent-rejects)
  "Handle an incoming message from a peer.
MEMPOOL and PEERS are optional; when provided, transaction relay is enabled.
FEE-ESTIMATOR is optional; when provided, fee stats are recorded for blocks.
ADDRESS-BOOK is optional; when provided, addr messages update the peer database.
RECENT-REJECTS is optional; when provided, recently rejected txs are cached.
Returns T if message was handled, NIL otherwise."
  ;; Check per-peer rate limit before processing
  (unless (check-peer-rate-limit peer command)
    (bitcoin-lisp:log-warn "Rate limit exceeded for peer ~A on ~A messages"
                           (peer-address peer) command)
    (disconnect-peer peer)
    (return-from handle-message nil))
  (cond
    ((string= command "ping")
     (let ((nonce (flexi-streams:with-input-from-sequence (s payload)
                    (bitcoin-lisp.serialization:read-uint64-le s))))
       (handle-ping peer nonce))
     t)

    ((string= command "pong")
     (let ((nonce (flexi-streams:with-input-from-sequence (s payload)
                    (bitcoin-lisp.serialization:read-uint64-le s))))
       (handle-pong peer nonce))
     t)

    ((string= command "inv")
     (handle-inv peer payload chain-state mempool :recent-rejects recent-rejects)
     t)

    ((string= command "headers")
     (handle-headers peer payload chain-state)
     t)

    ((string= command "block")
     (handle-block peer payload chain-state utxo-set block-store mempool fee-estimator
                   :recent-rejects recent-rejects)
     t)

    ((string= command "tx")
     (when mempool
       (handle-tx peer payload utxo-set mempool chain-state peers
                  :recent-rejects recent-rejects))
     t)

    ((string= command "getdata")
     (handle-getdata peer payload chain-state mempool)
     t)

    ((string= command "addr")
     (handle-addr peer payload address-book)
     t)

    ((string= command "addrv2")
     (handle-addrv2 peer payload address-book)
     t)

    ((string= command "sendaddrv2")
     ;; No-op post-handshake (only meaningful during handshake)
     t)

    ((string= command "wtxidrelay")
     ;; BIP 339: No-op post-handshake (only meaningful during handshake)
     t)

    ((string= command "sendheaders")
     ;; BIP 130: Peer prefers header announcements over inv
     (setf (peer-prefers-headers peer) t)
     t)

    ((string= command "feefilter")
     ;; BIP 133: Peer's minimum fee rate for tx relay
     (let ((rate (bitcoin-lisp.serialization:parse-feefilter-payload payload)))
       (setf (peer-feefilter-rate peer) rate))
     t)

    ;; Compact block messages (BIP 152)
    ((string= command "sendcmpct")
     (handle-sendcmpct peer payload)
     t)

    ((string= command "cmpctblock")
     (when mempool
       (handle-cmpctblock peer payload chain-state utxo-set block-store mempool
                          fee-estimator :recent-rejects recent-rejects))
     t)

    ((string= command "blocktxn")
     (when mempool
       (handle-blocktxn peer payload chain-state utxo-set block-store mempool
                        fee-estimator :recent-rejects recent-rejects))
     t)

    (t nil)))  ; Unknown message

;;; Inventory handling

(defun handle-inv (peer payload chain-state &optional mempool &key recent-rejects)
  "Handle an inv message."
  (let ((inv-vectors (bitcoin-lisp.serialization:parse-inv-payload payload))
        (wanted '())
        (use-compact (should-use-compact-blocks-p peer)))
    ;; Check which items we want
    (dolist (inv inv-vectors)
      (let ((inv-type (bitcoin-lisp.serialization:inv-vector-type inv))
            (hash (bitcoin-lisp.serialization:inv-vector-hash inv)))
        (cond
          ;; Block inventory - use compact blocks when available
          ((or (= inv-type bitcoin-lisp.serialization:+inv-type-block+)
               (= inv-type bitcoin-lisp.serialization:+inv-type-witness-block+))
           (unless (bitcoin-lisp.storage:get-block-index-entry chain-state hash)
             (push (bitcoin-lisp.serialization:make-inv-vector
                    :type (if use-compact
                              bitcoin-lisp.serialization:+inv-type-cmpct-block+
                              bitcoin-lisp.serialization:+inv-type-witness-block+)
                    :hash hash)
                   wanted)))
          ;; Transaction inventory - request with witness flag
          ;; Skip if already in mempool or recently rejected
          ((or (= inv-type bitcoin-lisp.serialization:+inv-type-tx+)
               (= inv-type bitcoin-lisp.serialization:+inv-type-witness-tx+))
           (when (and mempool
                      (not (bitcoin-lisp.mempool:mempool-has mempool hash))
                      (not (bitcoin-lisp:recent-reject-p recent-rejects hash)))
             (push (bitcoin-lisp.serialization:make-inv-vector
                    :type bitcoin-lisp.serialization:+inv-type-witness-tx+
                    :hash hash)
                   wanted))))))
    ;; Request wanted items
    (when wanted
      (send-message peer
                    (bitcoin-lisp.serialization:make-getdata-message
                     (nreverse wanted))))))

;;; Headers handling

(defun handle-headers (peer payload chain-state)
  "Handle a headers message."
  (declare (ignore peer))
  (let ((headers (bitcoin-lisp.serialization:parse-headers-payload payload)))
    (dolist (header headers)
      (let* ((hash (bitcoin-lisp.serialization:block-header-hash header))
             (prev-hash (bitcoin-lisp.serialization:block-header-prev-block header)))
        ;; Check if we already have this header
        (unless (bitcoin-lisp.storage:get-block-index-entry chain-state hash)
          ;; Check if we have the previous block
          (let ((prev-entry (bitcoin-lisp.storage:get-block-index-entry
                             chain-state prev-hash)))
            (when prev-entry
              ;; Add header to index
              (let ((new-height (1+ (bitcoin-lisp.storage:block-index-entry-height
                                     prev-entry)))
                    (prev-work (bitcoin-lisp.storage:block-index-entry-chain-work
                                prev-entry)))
                (bitcoin-lisp.storage:add-block-index-entry
                 chain-state
                 (bitcoin-lisp.storage:make-block-index-entry
                  :hash hash
                  :height new-height
                  :header header
                  :prev-entry prev-entry
                  :chain-work (bitcoin-lisp.storage:calculate-chain-work
                               (bitcoin-lisp.serialization:block-header-bits header)
                               prev-work)
                  :status :header-valid))))))))))

;;; Block handling

(defun handle-block (peer payload chain-state utxo-set block-store
                     &optional mempool fee-estimator &key recent-rejects)
  "Handle a block message."
  (let ((block (bitcoin-lisp.serialization:parse-block-payload payload)))
    (when block
      (with-node-lock
        (let* ((header (bitcoin-lisp.serialization:bitcoin-block-header block))
               (hash (bitcoin-lisp.serialization:block-header-hash header))
               (current-height (bitcoin-lisp.storage:current-height chain-state))
               (current-time (bitcoin-lisp.serialization:get-unix-time)))
          ;; Validate and connect block
          (multiple-value-bind (valid error)
              (bitcoin-lisp.validation:validate-block
               block chain-state utxo-set (1+ current-height) current-time)
            (if valid
                (progn
                  (bitcoin-lisp.validation:connect-block
                   block chain-state block-store utxo-set
                   :fee-estimator fee-estimator
                   :recent-rejects recent-rejects)
                  ;; Remove confirmed transactions from mempool
                  (when mempool
                    (bitcoin-lisp.mempool:mempool-remove-for-block mempool block)))
                (progn
                  (format t "Block ~A rejected: ~A~%"
                          (bitcoin-lisp.crypto:bytes-to-hex hash) error)
                  ;; Record misbehavior for invalid block
                  (record-misbehavior peer 100)))))))))

;;; Address handling

(defun handle-addr (peer payload &optional address-book)
  "Handle an addr message. When ADDRESS-BOOK is provided, add plausible
addresses (timestamp within last 3 hours) to the address book."
  (declare (ignore peer))
  (let ((now (bitcoin-lisp.serialization:get-unix-time))
        (three-hours (* 3 3600))
        (added 0))
    (flexi-streams:with-input-from-sequence (stream payload)
      (let ((count (bitcoin-lisp.serialization:read-compact-size stream)))
        (loop repeat (min count 1000)  ; Limit to prevent abuse
              do (multiple-value-bind (net-addr timestamp)
                     (bitcoin-lisp.serialization:read-net-addr stream :with-timestamp t)
                   (when (and address-book timestamp
                              (<= (abs (- now timestamp)) three-hours))
                     (address-book-add
                      address-book
                      (make-peer-address
                       :ip (bitcoin-lisp.serialization:net-addr-ip net-addr)
                       :port (bitcoin-lisp.serialization:net-addr-port net-addr)
                       :services (bitcoin-lisp.serialization:net-addr-services net-addr)
                       :last-seen timestamp))
                     (incf added))))))
    (when (and address-book (> added 0))
      (bitcoin-lisp:log-debug "Added ~D peer addresses from addr message" added))
    added))

;;; ADDRv2 handling (BIP 155)

(defun handle-addrv2 (peer payload &optional address-book)
  "Handle an addrv2 message (BIP 155). When ADDRESS-BOOK is provided, add
IPv4/IPv6 addresses with plausible timestamps (within 3 hours) to the address book.
Other network types are silently skipped."
  (declare (ignore peer))
  (let ((now (bitcoin-lisp.serialization:get-unix-time))
        (three-hours (* 3 3600))
        (added 0)
        (entries (bitcoin-lisp.serialization:parse-addrv2-payload payload)))
    (dolist (entry entries)
      (destructuring-bind (net-addr timestamp network-id) entry
        (declare (ignore network-id))
        (when (and address-book
                   (<= (abs (- now timestamp)) three-hours))
          (address-book-add
           address-book
           (make-peer-address
            :ip (bitcoin-lisp.serialization:net-addr-ip net-addr)
            :port (bitcoin-lisp.serialization:net-addr-port net-addr)
            :services (bitcoin-lisp.serialization:net-addr-services net-addr)
            :last-seen timestamp))
          (incf added))))
    (when (and address-book (> added 0))
      (bitcoin-lisp:log-debug "Added ~D peer addresses from addrv2 message" added))
    added))

;;; Transaction handling

(defun handle-tx (peer payload utxo-set mempool chain-state peers
                  &key recent-rejects)
  "Handle a tx message. Validate, add to mempool, and relay.
RECENT-REJECTS is optional; when provided, recently rejected txs are cached."
  (handler-case
      (let ((tx (bitcoin-lisp.serialization:parse-tx-payload payload)))
        (when tx
          (with-node-lock
            (let ((txid (bitcoin-lisp.serialization:transaction-hash tx))
                  (current-height (bitcoin-lisp.storage:current-height chain-state)))
              ;; Mark as announced by this peer
              (setf (gethash txid (peer-announced-txs peer)) t)
              ;; Check recent rejects filter before expensive validation
              (when (bitcoin-lisp:recent-reject-p recent-rejects txid)
                (return-from handle-tx nil))
              ;; Validate for mempool
              (multiple-value-bind (valid error fee)
                  (bitcoin-lisp.validation:validate-transaction-for-mempool
                   tx utxo-set mempool current-height)
                (unless valid
                  ;; Add to recent rejects filter
                  (bitcoin-lisp:add-recent-reject recent-rejects txid)
                  ;; Record misbehavior for invalid transactions
                  ;; (policy violations like :insufficient-fee are not penalized)
                  (when (member error '(:script-failed :no-inputs :no-outputs
                                        :duplicate-inputs :negative-output
                                        :output-too-large :total-output-too-large))
                    (record-misbehavior peer 10)))
                (when valid
                  ;; Add to mempool
                  (let ((tx-size (length (bitcoin-lisp.serialization:serialize-transaction tx)))
                        (entry-time (bitcoin-lisp.serialization:get-unix-time)))
                    (let ((result (bitcoin-lisp.mempool:mempool-add
                                   mempool txid
                                   (bitcoin-lisp.mempool:make-mempool-entry
                                    :transaction tx
                                    :fee fee
                                    :size tx-size
                                    :entry-time entry-time))))
                      (when (eq result :ok)
                        ;; Relay to other peers
                        (when peers
                          (relay-transaction txid peer peers
                                            :fee-rate (if (plusp tx-size)
                                                          (floor fee tx-size)
                                                          0)
                                            :wtxid (bitcoin-lisp.serialization:transaction-wtxid tx))))))))))))
    (error (c)
      (declare (ignore c))
      nil)))

(defun handle-getdata (peer payload chain-state &optional mempool)
  "Handle a getdata message. Respond with requested transactions or blocks.
Does not respond to transaction requests when relay is disabled (mainnet default)."
  (let ((inv-vectors (bitcoin-lisp.serialization:parse-inv-payload payload)))
    (dolist (inv inv-vectors)
      (let ((inv-type (bitcoin-lisp.serialization:inv-vector-type inv))
            (hash (bitcoin-lisp.serialization:inv-vector-hash inv)))
        (cond
          ;; Transaction request - only respond if relay is enabled
          ((or (= inv-type bitcoin-lisp.serialization:+inv-type-tx+)
               (= inv-type bitcoin-lisp.serialization:+inv-type-witness-tx+))
           (when (and mempool (relay-enabled-p))
             (let ((entry (bitcoin-lisp.mempool:mempool-get mempool hash)))
               (when entry
                 (send-message peer
                               (bitcoin-lisp.serialization:make-tx-message
                                (bitcoin-lisp.mempool:mempool-entry-transaction entry)))))))
          ;; Block requests are not handled here (handled by IBD/sync)
          )))))

;;; Transaction relay

(defun relay-enabled-p ()
  "Check if transaction relay is enabled for the current network.
Relay is always enabled on test networks, disabled by default on mainnet for safety."
  (or (member bitcoin-lisp:*network* '(:testnet3 :testnet4 :signet))
      bitcoin-lisp:*mainnet-relay-enabled*))

(defun relay-transaction (txid source-peer peers &key fee-rate wtxid)
  "Relay a transaction to all connected peers except SOURCE-PEER.
Sends inv messages and tracks announcements to avoid duplicates.
FEE-RATE is the transaction fee rate in sat/byte (used for BIP 133 feefilter).
WTXID is the witness txid (used for BIP 339 wtxidrelay peers).
Does nothing if relay is disabled for the current network."
  (unless (relay-enabled-p)
    (return-from relay-transaction nil))
  (let ((txid-inv-msg (bitcoin-lisp.serialization:make-inv-message
                       (list (bitcoin-lisp.serialization:make-inv-vector
                              :type bitcoin-lisp.serialization:+inv-type-tx+
                              :hash txid))))
        (wtxid-inv-msg (when wtxid
                         (bitcoin-lisp.serialization:make-inv-message
                          (list (bitcoin-lisp.serialization:make-inv-vector
                                 :type bitcoin-lisp.serialization:+inv-type-witness-tx+
                                 :hash wtxid)))))
        (fee-rate-per-kb (if fee-rate (* fee-rate 1000) 0)))
    (dolist (peer peers)
      ;; Skip the source peer and disconnected peers
      (when (and (not (eq peer source-peer))
                 (eq (peer-state peer) :ready)
                 ;; Skip if already announced to this peer
                 (not (gethash txid (peer-announced-txs peer)))
                 ;; BIP 133: Skip if tx fee rate below peer's feefilter
                 (or (zerop (peer-feefilter-rate peer))
                     (>= fee-rate-per-kb (peer-feefilter-rate peer))))
        (setf (gethash txid (peer-announced-txs peer)) t)
        ;; BIP 339: Use wtxid-based inv for peers that support it
        (if (and (peer-wtxid-relay peer) wtxid-inv-msg)
            (send-message peer wtxid-inv-msg)
            (send-message peer txid-inv-msg))))))

;;; Sync operations

(defun request-headers (peer chain-state)
  "Request headers from a peer starting from our current tip."
  (let ((locator (bitcoin-lisp.storage:build-block-locator chain-state)))
    (send-message peer
                  (bitcoin-lisp.serialization:make-getheaders-message locator))))

(defun request-blocks (peer block-hashes)
  "Request specific blocks from a peer using MSG_WITNESS_BLOCK
so peers include witness data in the response."
  (let ((inv-vectors (mapcar (lambda (hash)
                               (bitcoin-lisp.serialization:make-inv-vector
                                :type bitcoin-lisp.serialization:+inv-type-witness-block+
                                :hash hash))
                             block-hashes)))
    (send-message peer
                  (bitcoin-lisp.serialization:make-getdata-message inv-vectors))))

;;; Main sync loop

(defun sync-with-peer (peer chain-state utxo-set block-store
                       &key (max-blocks 500) fee-estimator recent-rejects)
  "Synchronize blockchain with a peer.
Downloads headers and blocks up to MAX-BLOCKS."
  (unless (eq (peer-state peer) :ready)
    (return-from sync-with-peer nil))

  ;; Request headers
  (request-headers peer chain-state)

  (let ((blocks-received 0))
    (loop while (< blocks-received max-blocks)
          do (multiple-value-bind (command payload)
                 (receive-message peer :timeout 60)
               (unless command
                 (return-from sync-with-peer blocks-received))
               (handle-message peer command payload
                               chain-state utxo-set block-store
                               :fee-estimator fee-estimator
                               :recent-rejects recent-rejects)
               (when (string= command "block")
                 (incf blocks-received))))
    blocks-received))

;;;; ============================================================
;;;; Compact Block Relay (BIP 152)
;;;; ============================================================

;;; Timeout for pending compact block reconstructions
(defconstant +compact-block-timeout-seconds+ 10)

;;; Compact block reconstruction metrics (thread-safe)
(defvar *compact-block-metrics-lock* (bt:make-lock "compact-block-metrics"))
(defvar *compact-block-success-count* 0)
(defvar *compact-block-failure-count* 0)
(defvar *compact-block-collision-count* 0)

(defun increment-compact-block-success ()
  "Thread-safe increment of success counter."
  (bt:with-lock-held (*compact-block-metrics-lock*)
    (incf *compact-block-success-count*)))

(defun increment-compact-block-failure ()
  "Thread-safe increment of failure counter."
  (bt:with-lock-held (*compact-block-metrics-lock*)
    (incf *compact-block-failure-count*)))

(defun increment-compact-block-collision ()
  "Thread-safe increment of collision counter."
  (bt:with-lock-held (*compact-block-metrics-lock*)
    (incf *compact-block-collision-count*)))

;;; Protocol negotiation

(defun send-compact-block-negotiation (peer)
  "Send sendcmpct messages to advertise compact block support.
Sends version 2 first (preferred for SegWit), then version 1.
Requests high-bandwidth mode when not in IBD (peer will send us
unsolicited compact blocks for faster relay)."
  (let ((high-bw (not (or (eq (ibd-state) :syncing-blocks)
                           (eq (ibd-state) :syncing-headers)))))
    ;; Send version 2 (wtxid-based) first
    (send-message peer (bitcoin-lisp.serialization:make-sendcmpct-message high-bw 2))
    ;; Then version 1 (txid-based) as fallback
    (send-message peer (bitcoin-lisp.serialization:make-sendcmpct-message high-bw 1))))

(defun handle-sendcmpct (peer payload)
  "Handle a sendcmpct message from a peer.
   Updates peer's compact block capabilities."
  (multiple-value-bind (high-bandwidth version)
      (bitcoin-lisp.serialization:parse-sendcmpct-payload payload)
    ;; Accept the highest version we mutually support (1 or 2)
    (when (and (> version 0) (<= version 2))
      ;; Take the higher of current and new version
      (when (> version (peer-compact-block-version peer))
        (setf (peer-compact-block-version peer) version))
      ;; Track high-bandwidth mode preference
      (when high-bandwidth
        (setf (peer-compact-block-high-bandwidth peer) t)))
    (bitcoin-lisp:log-debug "Peer ~A supports compact blocks v~D (high-bw: ~A)"
                            (peer-address peer) version high-bandwidth)))

;;; IBD check

(defun should-use-compact-blocks-p (peer)
  "Return T if we should request compact blocks from PEER.
   Returns NIL during IBD or if peer doesn't support compact blocks."
  (and (> (peer-compact-block-version peer) 0)  ; Peer supports CB
       (not (eq (ibd-state) :syncing-blocks))   ; Not downloading blocks in IBD
       (not (eq (ibd-state) :syncing-headers)))) ; Not syncing headers

;;; Short ID map building

(defun build-shortid-map (mempool k0 k1 use-wtxid)
  "Build hash table mapping short IDs to (tx . expected-id) pairs.
   USE-WTXID is true for compact block version 2.
   Returns (VALUES map collision-detected).
   The map stores cons cells of (transaction . full-txid-or-wtxid) for verification."
  (let ((map (make-hash-table :test 'eql))
        (collision nil))
    (bitcoin-lisp.mempool:mempool-for-each
     mempool
     (lambda (txid entry)
       (let* ((tx (bitcoin-lisp.mempool:mempool-entry-transaction entry))
              (id (if use-wtxid
                      (bitcoin-lisp.serialization:transaction-wtxid tx)
                      txid))
              (short-id (bitcoin-lisp.crypto:compute-short-txid k0 k1 id)))
         ;; Detect collisions within mempool
         (when (gethash short-id map)
           (setf collision t))
         ;; Store tx with its full ID for later verification
         (setf (gethash short-id map) (cons tx id)))))
    (values map collision)))

;;; Block reconstruction

(defun reconstruct-compact-block (compact-block mempool use-wtxid)
  "Attempt to reconstruct full block from compact block and mempool.
   Returns (VALUES block missing-indexes partial-transactions) where:
   - On success: block is the full block, missing-indexes is NIL
   - On missing txs: block is NIL, missing-indexes is list of needed indexes,
     partial-transactions is array with found txs filled in
   - On collision: block is NIL, missing-indexes is :collision"
  (let* ((header (bitcoin-lisp.serialization:compact-block-header compact-block))
         (nonce (bitcoin-lisp.serialization:compact-block-nonce compact-block))
         (short-ids-list (bitcoin-lisp.serialization:compact-block-short-ids compact-block))
         (prefilled (bitcoin-lisp.serialization:compact-block-prefilled-txs compact-block))
         (tx-count (+ (length short-ids-list) (length prefilled)))
         (header-bytes (bitcoin-lisp.serialization:serialize-block-header header))
         ;; Convert short-ids list to vector for O(1) access
         (short-ids (coerce short-ids-list 'vector)))

    ;; Validate tx-count is reasonable (prevent DoS)
    (when (or (zerop tx-count) (> tx-count 100000))
      (bitcoin-lisp:log-warn "Invalid compact block tx count: ~D" tx-count)
      (return-from reconstruct-compact-block (values nil :collision)))

    ;; Compute SipHash keys
    (multiple-value-bind (k0 k1)
        (bitcoin-lisp.crypto:compute-siphash-key header-bytes nonce)

      ;; Build short ID map from mempool
      (multiple-value-bind (shortid-map collision)
          (build-shortid-map mempool k0 k1 use-wtxid)

        ;; Check for collision within mempool
        (when collision
          (increment-compact-block-collision)
          (bitcoin-lisp:log-warn "Short ID collision detected in mempool, falling back to full block")
          (return-from reconstruct-compact-block (values nil :collision nil)))

        (let ((transactions (make-array tx-count :initial-element nil))
              (missing-indexes '())
              (short-id-idx 0))

          ;; Place prefilled transactions at their absolute indexes
          ;; with bounds checking
          (dolist (ptx prefilled)
            (let ((idx (bitcoin-lisp.serialization:prefilled-tx-index ptx)))
              (if (and (>= idx 0) (< idx tx-count))
                  (setf (aref transactions idx)
                        (bitcoin-lisp.serialization:prefilled-tx-transaction ptx))
                  (progn
                    (bitcoin-lisp:log-warn "Prefilled tx index out of bounds: ~D (max ~D)"
                                           idx (1- tx-count))
                    (return-from reconstruct-compact-block (values nil :collision nil))))))

          ;; Fill remaining slots with mempool transactions matched by short ID
          (dotimes (i tx-count)
            (when (null (aref transactions i))
              ;; This slot needs a transaction from short IDs
              (when (>= short-id-idx (length short-ids))
                ;; More empty slots than short IDs - malformed message
                (bitcoin-lisp:log-warn "Short ID count mismatch")
                (return-from reconstruct-compact-block (values nil :collision nil)))
              (let* ((short-id (aref short-ids short-id-idx))
                     (tx-pair (gethash short-id shortid-map)))
                (if tx-pair
                    (let ((tx (car tx-pair))
                          (full-id (cdr tx-pair)))
                      ;; Verify the matched tx produces the expected short ID
                      ;; (guards against hash collisions between mempool and block)
                      (let ((computed-short-id (bitcoin-lisp.crypto:compute-short-txid
                                                k0 k1 full-id)))
                        (if (= computed-short-id short-id)
                            (setf (aref transactions i) tx)
                            ;; Collision between different transactions
                            (push i missing-indexes))))
                    (push i missing-indexes))
                (incf short-id-idx))))

          (if missing-indexes
              (values nil (nreverse missing-indexes) transactions)
              (values (bitcoin-lisp.serialization:make-bitcoin-block
                       :header header
                       :transactions (coerce transactions 'list))
                      nil nil)))))))

;;; Compact block message handling

(defun handle-cmpctblock (peer payload chain-state utxo-set block-store mempool
                          &optional fee-estimator &key recent-rejects)
  "Handle a cmpctblock message. Attempt reconstruction from mempool."
  (let* ((compact-block (bitcoin-lisp.serialization:parse-cmpctblock-payload payload))
         (header (bitcoin-lisp.serialization:compact-block-header compact-block))
         (block-hash (bitcoin-lisp.serialization:block-header-hash header))
         (use-wtxid (= (peer-compact-block-version peer) 2)))

    ;; Clear any old pending reconstruction for different block
    (when (peer-pending-compact-block peer)
      (let ((pending-hash (pending-compact-block-block-hash
                           (peer-pending-compact-block peer))))
        (unless (equalp pending-hash block-hash)
          (setf (peer-pending-compact-block peer) nil))))

    ;; Skip if we already have this block connected
    (let ((entry (bitcoin-lisp.storage:get-block-index-entry chain-state block-hash)))
      (when (and entry
                 (eq (bitcoin-lisp.storage:block-index-entry-status entry) :connected))
        (return-from handle-cmpctblock nil)))

    ;; Attempt reconstruction
    (multiple-value-bind (block missing-indexes partial-transactions)
        (reconstruct-compact-block compact-block mempool use-wtxid)

      (cond
        ;; Successful reconstruction
        (block
         (increment-compact-block-success)
         (bitcoin-lisp:log-debug "Compact block reconstructed successfully")
         ;; Process like a normal block
         (with-node-lock
           (let* ((current-height (bitcoin-lisp.storage:current-height chain-state))
                  (current-time (bitcoin-lisp.serialization:get-unix-time)))
             (multiple-value-bind (valid error)
                 (bitcoin-lisp.validation:validate-block
                  block chain-state utxo-set (1+ current-height) current-time)
               (if valid
                   (progn
                     (bitcoin-lisp.validation:connect-block
                      block chain-state block-store utxo-set
                      :fee-estimator fee-estimator
                      :recent-rejects recent-rejects)
                     (when mempool
                       (bitcoin-lisp.mempool:mempool-remove-for-block mempool block)))
                   (progn
                     (bitcoin-lisp:log-warn "Reconstructed block invalid: ~A" error)
                     (record-misbehavior peer 100)))))))

        ;; Collision or malformed - fall back to full block
        ((eq missing-indexes :collision)
         (increment-compact-block-failure)
         (request-full-block peer block-hash))

        ;; Missing transactions - request them
        (missing-indexes
         (bitcoin-lisp:log-debug "Compact block missing ~D transactions, requesting"
                                 (length missing-indexes))
         ;; Store pending state using the partial transactions from reconstruction
         (setf (peer-pending-compact-block peer)
               (make-pending-compact-block
                :block-hash block-hash
                :header header
                :transactions partial-transactions
                :missing-indexes missing-indexes
                :request-time (get-internal-real-time)
                :use-wtxid use-wtxid))
         ;; Send getblocktxn request
         (send-message peer
                       (bitcoin-lisp.serialization:make-getblocktxn-message
                        block-hash missing-indexes)))))))

(defun handle-blocktxn (peer payload chain-state utxo-set block-store mempool
                        &optional fee-estimator &key recent-rejects)
  "Handle a blocktxn message. Complete pending block reconstruction."
  (let ((response (bitcoin-lisp.serialization:parse-blocktxn-payload payload))
        (pending (peer-pending-compact-block peer)))

    (unless pending
      (bitcoin-lisp:log-debug "Received blocktxn but no pending reconstruction")
      (return-from handle-blocktxn nil))

    (let ((block-hash (bitcoin-lisp.serialization:block-txn-response-block-hash response))
          (txs (bitcoin-lisp.serialization:block-txn-response-transactions response)))

      ;; Verify block hash matches
      (unless (equalp block-hash (pending-compact-block-block-hash pending))
        (bitcoin-lisp:log-warn "blocktxn hash mismatch")
        (return-from handle-blocktxn nil))

      ;; Insert missing transactions
      (let ((transactions (pending-compact-block-transactions pending))
            (missing-indexes (pending-compact-block-missing-indexes pending)))
        (when (/= (length txs) (length missing-indexes))
          (bitcoin-lisp:log-warn "blocktxn transaction count mismatch")
          (setf (peer-pending-compact-block peer) nil)
          (request-full-block peer block-hash)
          (return-from handle-blocktxn nil))

        (loop for tx in txs
              for idx in missing-indexes
              do (setf (aref transactions idx) tx))

        ;; Build complete block
        (let ((block (bitcoin-lisp.serialization:make-bitcoin-block
                      :header (pending-compact-block-header pending)
                      :transactions (coerce transactions 'list))))
          ;; Clear pending state
          (setf (peer-pending-compact-block peer) nil)

          ;; Validate and connect
          (increment-compact-block-success)
          (with-node-lock
            (let* ((current-height (bitcoin-lisp.storage:current-height chain-state))
                   (current-time (bitcoin-lisp.serialization:get-unix-time)))
              (multiple-value-bind (valid error)
                  (bitcoin-lisp.validation:validate-block
                   block chain-state utxo-set (1+ current-height) current-time)
                (if valid
                    (progn
                      (bitcoin-lisp.validation:connect-block
                       block chain-state block-store utxo-set
                       :fee-estimator fee-estimator
                       :recent-rejects recent-rejects)
                      (when mempool
                        (bitcoin-lisp.mempool:mempool-remove-for-block mempool block)))
                    (progn
                      (bitcoin-lisp:log-warn "Completed block invalid: ~A" error)
                      (record-misbehavior peer 100)))))))))))

(defun request-full-block (peer block-hash)
  "Request a full block (fallback from compact block)."
  (increment-compact-block-failure)
  (send-message peer
                (bitcoin-lisp.serialization:make-getdata-message
                 (list (bitcoin-lisp.serialization:make-inv-vector
                        :type bitcoin-lisp.serialization:+inv-type-witness-block+
                        :hash block-hash)))))

;;; Timeout handling

(defun check-compact-block-timeout (peer)
  "Check if pending compact block reconstruction has timed out.
   If so, clear state and request full block."
  (let ((pending (peer-pending-compact-block peer)))
    (when pending
      (let* ((now (get-internal-real-time))
             (elapsed-secs (/ (- now (pending-compact-block-request-time pending))
                              internal-time-units-per-second)))
        (when (> elapsed-secs +compact-block-timeout-seconds+)
          (bitcoin-lisp:log-warn "Compact block reconstruction timed out")
          (let ((block-hash (pending-compact-block-block-hash pending)))
            (setf (peer-pending-compact-block peer) nil)
            (request-full-block peer block-hash)))))))

(defun clear-pending-compact-block (peer)
  "Clear any pending compact block reconstruction for PEER."
  (setf (peer-pending-compact-block peer) nil))

;;; Compact block metrics

(defun compact-block-stats ()
  "Return compact block reconstruction statistics (thread-safe read)."
  (bt:with-lock-held (*compact-block-metrics-lock*)
    (list :successes *compact-block-success-count*
          :failures *compact-block-failure-count*
          :collisions *compact-block-collision-count*)))
