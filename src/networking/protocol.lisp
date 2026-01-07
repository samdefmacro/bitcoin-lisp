(in-package #:bitcoin-lisp.networking)

;;; Bitcoin P2P Protocol Handling
;;;
;;; Higher-level protocol operations for syncing and message handling.

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

(defun handle-message (peer command payload chain-state utxo-set block-store)
  "Handle an incoming message from a peer.
Returns T if message was handled, NIL otherwise."
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
     (handle-inv peer payload chain-state)
     t)

    ((string= command "headers")
     (handle-headers peer payload chain-state)
     t)

    ((string= command "block")
     (handle-block peer payload chain-state utxo-set block-store)
     t)

    ((string= command "addr")
     (handle-addr peer payload)
     t)

    (t nil)))  ; Unknown message

;;; Inventory handling

(defun handle-inv (peer payload chain-state)
  "Handle an inv message."
  (let ((inv-vectors (bitcoin-lisp.serialization:parse-inv-payload payload))
        (wanted '()))
    ;; Check which items we want
    (dolist (inv inv-vectors)
      (let ((inv-type (bitcoin-lisp.serialization:inv-vector-type inv))
            (hash (bitcoin-lisp.serialization:inv-vector-hash inv)))
        (cond
          ;; Block inventory
          ((or (= inv-type bitcoin-lisp.serialization:+inv-type-block+)
               (= inv-type bitcoin-lisp.serialization:+inv-type-witness-block+))
           (unless (bitcoin-lisp.storage:get-block-index-entry chain-state hash)
             (push inv wanted)))
          ;; Transaction inventory (skip for now)
          ((or (= inv-type bitcoin-lisp.serialization:+inv-type-tx+)
               (= inv-type bitcoin-lisp.serialization:+inv-type-witness-tx+))
           nil))))
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

(defun handle-block (peer payload chain-state utxo-set block-store)
  "Handle a block message."
  (declare (ignore peer))
  (let ((block (bitcoin-lisp.serialization:parse-block-payload payload)))
    (when block
      (let* ((header (bitcoin-lisp.serialization:bitcoin-block-header block))
             (hash (bitcoin-lisp.serialization:block-header-hash header))
             (current-height (bitcoin-lisp.storage:current-height chain-state))
             (current-time (bitcoin-lisp.serialization:get-unix-time)))
        ;; Validate and connect block
        (multiple-value-bind (valid error)
            (bitcoin-lisp.validation:validate-block
             block chain-state utxo-set (1+ current-height) current-time)
          (if valid
              (bitcoin-lisp.validation:connect-block
               block chain-state block-store utxo-set)
              (format t "Block ~A rejected: ~A~%"
                      (bitcoin-lisp.crypto:bytes-to-hex hash) error)))))))

;;; Address handling

(defun handle-addr (peer payload)
  "Handle an addr message."
  (declare (ignore peer))
  ;; Parse addresses (simplified)
  (flexi-streams:with-input-from-sequence (stream payload)
    (let ((count (bitcoin-lisp.serialization:read-compact-size stream)))
      (loop repeat (min count 1000)  ; Limit to prevent abuse
            collect (bitcoin-lisp.serialization:read-net-addr stream
                                                              :with-timestamp t)))))

;;; Sync operations

(defun request-headers (peer chain-state)
  "Request headers from a peer starting from our current tip."
  (let ((locator (bitcoin-lisp.storage:build-block-locator chain-state)))
    (send-message peer
                  (bitcoin-lisp.serialization:make-getheaders-message locator))))

(defun request-blocks (peer block-hashes)
  "Request specific blocks from a peer."
  (let ((inv-vectors (mapcar (lambda (hash)
                               (bitcoin-lisp.serialization:make-inv-vector
                                :type bitcoin-lisp.serialization:+inv-type-block+
                                :hash hash))
                             block-hashes)))
    (send-message peer
                  (bitcoin-lisp.serialization:make-getdata-message inv-vectors))))

;;; Main sync loop

(defun sync-with-peer (peer chain-state utxo-set block-store &key (max-blocks 500))
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
                               chain-state utxo-set block-store)
               (when (string= command "block")
                 (incf blocks-received))))
    blocks-received))
