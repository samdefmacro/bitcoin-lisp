(in-package #:bitcoin-lisp.serialization)

;;; Bitcoin P2P protocol messages
;;;
;;; All P2P messages have a common header format:
;;; - 4 bytes: Magic (network identifier)
;;; - 12 bytes: Command name (null-padded ASCII)
;;; - 4 bytes: Payload length
;;; - 4 bytes: Checksum (first 4 bytes of double-SHA256 of payload)
;;; - Variable: Payload

;;;; Network magic bytes
;;; Using alexandria:define-constant for arrays to handle SBCL reloading

(alexandria:define-constant +mainnet-magic+
  (make-array 4 :element-type '(unsigned-byte 8)
                :initial-contents '(#xF9 #xBE #xB4 #xD9))
  :test #'equalp
  :documentation "Mainnet network magic bytes.")

(alexandria:define-constant +testnet-magic+
  (make-array 4 :element-type '(unsigned-byte 8)
                :initial-contents '(#x0B #x11 #x09 #x07))
  :test #'equalp
  :documentation "Testnet network magic bytes.")

(alexandria:define-constant +regtest-magic+
  (make-array 4 :element-type '(unsigned-byte 8)
                :initial-contents '(#xFA #xBF #xB5 #xDA))
  :test #'equalp
  :documentation "Regtest network magic bytes.")

(defvar *network-magic* +testnet-magic+
  "Current network magic bytes.")

;;;; Message header

(defconstant +command-size+ 12)
(defconstant +header-size+ 24)  ; 4 + 12 + 4 + 4

(defstruct message-header
  "P2P message header."
  (magic (copy-seq +testnet-magic+) :type (simple-array (unsigned-byte 8) (4)))
  (command "" :type string)
  (payload-length 0 :type (unsigned-byte 32))
  (checksum (make-array 4 :element-type '(unsigned-byte 8) :initial-element 0)
            :type (simple-array (unsigned-byte 8) (4))))

(defun command-to-bytes (command)
  "Convert command string to 12-byte null-padded array."
  (let ((bytes (make-array +command-size+ :element-type '(unsigned-byte 8) :initial-element 0)))
    (loop for i from 0 below (min (length command) +command-size+)
          do (setf (aref bytes i) (char-code (char command i))))
    bytes))

(defun bytes-to-command (bytes)
  "Convert 12-byte array to command string (stripping nulls)."
  (let ((end (or (position 0 bytes) +command-size+)))
    (map 'string #'code-char (subseq bytes 0 end))))

(defun compute-checksum (payload)
  "Compute message checksum (first 4 bytes of Hash256)."
  (let ((hash (bitcoin-lisp.crypto:hash256 payload)))
    (subseq hash 0 4)))

(defun read-message-header (stream)
  "Read a message header from STREAM."
  (let ((magic (read-bytes stream 4))
        (command-bytes (read-bytes stream +command-size+))
        (payload-length (read-uint32-le stream))
        (checksum (read-bytes stream 4)))
    (make-message-header :magic magic
                         :command (bytes-to-command command-bytes)
                         :payload-length payload-length
                         :checksum checksum)))

(defun write-message-header (stream header)
  "Write a message header to STREAM."
  (write-bytes stream (message-header-magic header))
  (write-bytes stream (command-to-bytes (message-header-command header)))
  (write-uint32-le stream (message-header-payload-length header))
  (write-bytes stream (message-header-checksum header)))

;;;; Network address structure

(defstruct net-addr
  "Network address structure."
  (services 0 :type (unsigned-byte 64))
  (ip (make-array 16 :element-type '(unsigned-byte 8)
                     :initial-contents '(0 0 0 0 0 0 0 0 0 0 #xFF #xFF 127 0 0 1))
      :type (simple-array (unsigned-byte 8) (16)))
  (port 0 :type (unsigned-byte 16)))

(defun read-net-addr (stream &key with-timestamp)
  "Read a network address from STREAM.
If WITH-TIMESTAMP is true, read a 4-byte timestamp first (for addr messages).
Returns (VALUES net-addr timestamp) when WITH-TIMESTAMP, otherwise just net-addr."
  (let ((timestamp (when with-timestamp
                     (read-uint32-le stream))))
    (let ((services (read-uint64-le stream))
          (ip (read-bytes stream 16))
          (port-high (read-byte stream))
          (port-low (read-byte stream)))
      (let ((addr (make-net-addr :services services
                                 :ip ip
                                 :port (logior (ash port-high 8) port-low))))
        (if with-timestamp
            (values addr timestamp)
            addr)))))

(defun write-net-addr (stream addr &key with-timestamp timestamp)
  "Write a network address to STREAM."
  (when with-timestamp
    (write-uint32-le stream (or timestamp (get-unix-time))))
  (write-uint64-le stream (net-addr-services addr))
  (write-bytes stream (net-addr-ip addr))
  ;; Port is big-endian
  (write-byte (ash (net-addr-port addr) -8) stream)
  (write-byte (logand (net-addr-port addr) #xFF) stream))

(defun get-unix-time ()
  "Get current Unix timestamp."
  (- (get-universal-time) 2208988800))  ; Difference between 1900 and 1970

;;;; Version message

(defconstant +protocol-version+ 70016)
(defconstant +node-network+ 1)
(defconstant +node-witness+ (ash 1 3))
(defconstant +node-network-limited+ (ash 1 10))  ; BIP 159: pruned node

(defstruct version-message
  "Version message payload."
  (version +protocol-version+ :type (signed-byte 32))
  (services +node-network+ :type (unsigned-byte 64))
  (timestamp 0 :type (signed-byte 64))
  (addr-recv (make-net-addr) :type net-addr)
  (addr-from (make-net-addr) :type net-addr)
  (nonce 0 :type (unsigned-byte 64))
  (user-agent "/bitcoin-lisp:0.1.0/" :type string)
  (start-height 0 :type (signed-byte 32))
  (relay t :type boolean))

(defun read-version-message (stream)
  "Read a version message payload from STREAM."
  (let* ((version (read-int32-le stream))
         (services (read-uint64-le stream))
         (timestamp (read-int64-le stream))
         (addr-recv (read-net-addr stream))
         (addr-from (read-net-addr stream))
         (nonce (read-uint64-le stream))
         (user-agent-bytes (read-var-bytes stream))
         (user-agent (map 'string #'code-char user-agent-bytes))
         (start-height (read-int32-le stream))
         ;; relay flag may not be present in older versions
         (relay (if (> version 70001)
                    (= (read-byte stream nil 1) 1)
                    t)))
    (make-version-message :version version
                          :services services
                          :timestamp timestamp
                          :addr-recv addr-recv
                          :addr-from addr-from
                          :nonce nonce
                          :user-agent user-agent
                          :start-height start-height
                          :relay relay)))

(defun write-version-message (stream msg)
  "Write a version message payload to STREAM."
  (write-int32-le stream (version-message-version msg))
  (write-uint64-le stream (version-message-services msg))
  (write-int64-le stream (version-message-timestamp msg))
  (write-net-addr stream (version-message-addr-recv msg))
  (write-net-addr stream (version-message-addr-from msg))
  (write-uint64-le stream (version-message-nonce msg))
  (let ((ua-bytes (map '(vector (unsigned-byte 8)) #'char-code
                       (version-message-user-agent msg))))
    (write-var-bytes stream ua-bytes))
  (write-int32-le stream (version-message-start-height msg))
  (write-byte (if (version-message-relay msg) 1 0) stream))

;;;; Inventory vector

(defconstant +inv-type-error+ 0)
(defconstant +inv-type-tx+ 1)
(defconstant +inv-type-block+ 2)
(defconstant +inv-type-filtered-block+ 3)
(defconstant +inv-type-witness-tx+ (logior +inv-type-tx+ (ash 1 30)))
(defconstant +inv-type-witness-block+ (logior +inv-type-block+ (ash 1 30)))

(defstruct inv-vector
  "Inventory vector - identifies an object (transaction or block)."
  (type +inv-type-tx+ :type (unsigned-byte 32))
  (hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
        :type (simple-array (unsigned-byte 8) (32))))

(defun read-inv-vector (stream)
  "Read an inventory vector from STREAM."
  (make-inv-vector :type (read-uint32-le stream)
                   :hash (read-hash256 stream)))

(defun write-inv-vector (stream inv)
  "Write an inventory vector to STREAM."
  (write-uint32-le stream (inv-vector-type inv))
  (write-hash256 stream (inv-vector-hash inv)))

;;;; Generic message serialization

(defun serialize-message (command payload-bytes &key (magic *network-magic*))
  "Create a complete P2P message with header and payload."
  (let ((header (make-message-header
                 :magic (copy-seq magic)
                 :command command
                 :payload-length (length payload-bytes)
                 :checksum (compute-checksum payload-bytes))))
    (flexi-streams:with-output-to-sequence (stream)
      (write-message-header stream header)
      (write-bytes stream payload-bytes))))

(defun make-version-message-bytes (&key (version +protocol-version+)
                                        (services +node-network+)
                                        (timestamp (get-unix-time))
                                        (user-agent "/bitcoin-lisp:0.1.0/")
                                        (start-height 0)
                                        (relay t))
  "Create a serialized version message."
  (let ((msg (make-version-message
              :version version
              :services services
              :timestamp timestamp
              :addr-recv (make-net-addr :services services :port 0)
              :addr-from (make-net-addr :services services :port 0)
              :nonce (random (expt 2 64))
              :user-agent user-agent
              :start-height start-height
              :relay relay)))
    (flexi-streams:with-output-to-sequence (stream)
      (write-version-message stream msg))))

(defun make-verack-message ()
  "Create a serialized verack message (empty payload)."
  (serialize-message "verack" #()))

(defun make-ping-message (&optional (nonce (random (expt 2 64))))
  "Create a serialized ping message."
  (let ((payload (flexi-streams:with-output-to-sequence (stream)
                   (write-uint64-le stream nonce))))
    (serialize-message "ping" payload)))

(defun make-pong-message (nonce)
  "Create a serialized pong message."
  (let ((payload (flexi-streams:with-output-to-sequence (stream)
                   (write-uint64-le stream nonce))))
    (serialize-message "pong" payload)))

(defun make-getblocks-message (block-locator-hashes &optional stop-hash)
  "Create a getblocks message.
BLOCK-LOCATOR-HASHES is a list of block hashes (most recent first).
STOP-HASH is the hash to stop at (or zeros to get maximum blocks)."
  (let ((payload (flexi-streams:with-output-to-sequence (stream)
                   (write-uint32-le stream +protocol-version+)
                   (write-compact-size stream (length block-locator-hashes))
                   (dolist (hash block-locator-hashes)
                     (write-hash256 stream hash))
                   (write-hash256 stream (or stop-hash
                                             (make-array 32 :element-type '(unsigned-byte 8)
                                                         :initial-element 0))))))
    (serialize-message "getblocks" payload)))

(defun make-getheaders-message (block-locator-hashes &optional stop-hash)
  "Create a getheaders message."
  (let ((payload (flexi-streams:with-output-to-sequence (stream)
                   (write-uint32-le stream +protocol-version+)
                   (write-compact-size stream (length block-locator-hashes))
                   (dolist (hash block-locator-hashes)
                     (write-hash256 stream hash))
                   (write-hash256 stream (or stop-hash
                                             (make-array 32 :element-type '(unsigned-byte 8)
                                                         :initial-element 0))))))
    (serialize-message "getheaders" payload)))

(defun make-getdata-message (inv-vectors)
  "Create a getdata message from a list of inv-vectors."
  (let ((payload (flexi-streams:with-output-to-sequence (stream)
                   (write-compact-size stream (length inv-vectors))
                   (dolist (inv inv-vectors)
                     (write-inv-vector stream inv)))))
    (serialize-message "getdata" payload)))

(defun make-inv-message (inv-vectors)
  "Create an inv message from a list of inv-vectors."
  (let ((payload (flexi-streams:with-output-to-sequence (stream)
                   (write-compact-size stream (length inv-vectors))
                   (dolist (inv inv-vectors)
                     (write-inv-vector stream inv)))))
    (serialize-message "inv" payload)))

;;;; Transaction message

(defun make-tx-message (tx)
  "Create a serialized tx message from a transaction."
  (let ((payload (serialize-transaction tx)))
    (serialize-message "tx" payload)))

(defun parse-tx-payload (payload)
  "Parse a tx message payload into a transaction."
  (flexi-streams:with-input-from-sequence (stream payload)
    (read-transaction stream)))

;;;; Message parsing

(defun parse-inv-payload (payload)
  "Parse an inv or getdata message payload into a list of inv-vectors."
  (flexi-streams:with-input-from-sequence (stream payload)
    (let ((count (read-compact-size stream)))
      (loop repeat count collect (read-inv-vector stream)))))

(defun parse-headers-payload (payload)
  "Parse a headers message payload into a list of block headers."
  (flexi-streams:with-input-from-sequence (stream payload)
    (let ((count (read-compact-size stream)))
      (loop repeat count
            collect (prog1 (read-block-header stream)
                      ;; Headers message includes tx count (always 0) after each header
                      (read-compact-size stream))))))

(defun parse-block-payload (payload)
  "Parse a block message payload into a bitcoin-block."
  (flexi-streams:with-input-from-sequence (stream payload)
    (read-bitcoin-block stream)))

;;;; ============================================================
;;;; Compact Block Messages (BIP 152)
;;;; ============================================================

;;; MSG_CMPCT_BLOCK inventory type for getdata
(defconstant +inv-type-cmpct-block+ 4)

;;; Prefilled transaction in a compact block
(defstruct prefilled-tx
  "A prefilled transaction in a compact block (index + full tx)."
  (index 0 :type (unsigned-byte 32))  ; Absolute index (decoded from differential)
  (transaction nil))

;;; Compact block (HeaderAndShortIDs)
(defstruct compact-block
  "BIP 152 compact block (HeaderAndShortIDs)."
  (header nil)                        ; Block header
  (nonce 0 :type (unsigned-byte 64))  ; Random nonce for short ID generation
  (short-ids '() :type list)          ; List of 6-byte short txids (as integers)
  (prefilled-txs '() :type list))     ; List of prefilled-tx structs

;;; Block transactions request (getblocktxn)
(defstruct block-txn-request
  "BIP 152 block transactions request."
  (block-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
              :type (simple-array (unsigned-byte 8) (32)))
  (indexes '() :type list))  ; List of absolute indexes

;;; Block transactions response (blocktxn)
(defstruct block-txn-response
  "BIP 152 block transactions response."
  (block-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
              :type (simple-array (unsigned-byte 8) (32)))
  (transactions '() :type list))  ; List of full transactions

;;; Read/write 6-byte short txid (little-endian)
(defun read-short-txid (stream)
  "Read a 6-byte short transaction ID from STREAM as a 48-bit integer."
  (let ((result 0))
    (dotimes (i 6)
      (setf result (logior result (ash (read-byte stream) (* i 8)))))
    result))

(defun write-short-txid (stream short-id)
  "Write a 6-byte short transaction ID to STREAM."
  (dotimes (i 6)
    (write-byte (logand (ash short-id (- (* i 8))) #xff) stream)))

;;; Parse sendcmpct message
(defun parse-sendcmpct-payload (payload)
  "Parse a sendcmpct message payload.
   Returns (VALUES announce-flag version)."
  (flexi-streams:with-input-from-sequence (stream payload)
    (let ((announce (read-byte stream))
          (version (read-uint64-le stream)))
      (values (= announce 1) version))))

;;; Make sendcmpct message
(defun make-sendcmpct-message (high-bandwidth version)
  "Create a sendcmpct message.
   HIGH-BANDWIDTH is T for high-bandwidth mode, NIL for low-bandwidth.
   VERSION is 1 or 2."
  (let ((payload (flexi-streams:with-output-to-sequence (stream)
                   (write-byte (if high-bandwidth 1 0) stream)
                   (write-uint64-le stream version))))
    (serialize-message "sendcmpct" payload)))

;;; Read compact block
(defun read-compact-block (stream)
  "Read a compact block (HeaderAndShortIDs) from STREAM."
  (let* ((header (read-block-header stream))
         (nonce (read-uint64-le stream))
         (shortids-count (read-compact-size stream))
         (short-ids (loop repeat shortids-count
                          collect (read-short-txid stream)))
         (prefilled-count (read-compact-size stream))
         (prefilled-txs '())
         (last-index -1))
    ;; Read prefilled transactions with differential index encoding
    (dotimes (i prefilled-count)
      (let* ((diff-index (read-compact-size stream))
             (abs-index (+ last-index diff-index 1))
             (tx (read-transaction stream)))
        (push (make-prefilled-tx :index abs-index :transaction tx)
              prefilled-txs)
        (setf last-index abs-index)))
    (make-compact-block :header header
                        :nonce nonce
                        :short-ids short-ids
                        :prefilled-txs (nreverse prefilled-txs))))

;;; Write compact block
(defun write-compact-block (stream cb)
  "Write a compact block to STREAM."
  (write-block-header stream (compact-block-header cb))
  (write-uint64-le stream (compact-block-nonce cb))
  (write-compact-size stream (length (compact-block-short-ids cb)))
  (dolist (sid (compact-block-short-ids cb))
    (write-short-txid stream sid))
  (let ((prefilled (compact-block-prefilled-txs cb)))
    (write-compact-size stream (length prefilled))
    (let ((last-index -1))
      (dolist (ptx prefilled)
        (let ((abs-index (prefilled-tx-index ptx)))
          ;; Write differential index
          (write-compact-size stream (- abs-index last-index 1))
          (write-transaction stream (prefilled-tx-transaction ptx))
          (setf last-index abs-index))))))

;;; Parse cmpctblock payload
(defun parse-cmpctblock-payload (payload)
  "Parse a cmpctblock message payload into a compact-block."
  (flexi-streams:with-input-from-sequence (stream payload)
    (read-compact-block stream)))

;;; Read block transactions request
(defun read-block-txn-request (stream)
  "Read a block transactions request (getblocktxn) from STREAM."
  (let* ((block-hash (read-hash256 stream))
         (count (read-compact-size stream))
         (indexes '())
         (last-index -1))
    ;; Read differentially encoded indexes
    (dotimes (i count)
      (let* ((diff (read-compact-size stream))
             (abs-index (+ last-index diff 1)))
        (push abs-index indexes)
        (setf last-index abs-index)))
    (make-block-txn-request :block-hash block-hash
                            :indexes (nreverse indexes))))

;;; Write block transactions request
(defun write-block-txn-request (stream req)
  "Write a block transactions request to STREAM."
  (write-hash256 stream (block-txn-request-block-hash req))
  (let ((indexes (block-txn-request-indexes req)))
    (write-compact-size stream (length indexes))
    (let ((last-index -1))
      (dolist (idx indexes)
        (write-compact-size stream (- idx last-index 1))
        (setf last-index idx)))))

;;; Make getblocktxn message
(defun make-getblocktxn-message (block-hash indexes)
  "Create a getblocktxn message.
   BLOCK-HASH is the 32-byte block hash.
   INDEXES is a list of absolute transaction indexes to request."
  (let ((payload (flexi-streams:with-output-to-sequence (stream)
                   (write-block-txn-request
                    stream
                    (make-block-txn-request :block-hash block-hash
                                            :indexes indexes)))))
    (serialize-message "getblocktxn" payload)))

;;; Parse getblocktxn payload
(defun parse-getblocktxn-payload (payload)
  "Parse a getblocktxn message payload."
  (flexi-streams:with-input-from-sequence (stream payload)
    (read-block-txn-request stream)))

;;; Read block transactions response
(defun read-block-txn-response (stream)
  "Read a block transactions response (blocktxn) from STREAM."
  (let* ((block-hash (read-hash256 stream))
         (count (read-compact-size stream))
         (txs (loop repeat count collect (read-transaction stream))))
    (make-block-txn-response :block-hash block-hash
                             :transactions txs)))

;;; Write block transactions response
(defun write-block-txn-response (stream resp)
  "Write a block transactions response to STREAM."
  (write-hash256 stream (block-txn-response-block-hash resp))
  (let ((txs (block-txn-response-transactions resp)))
    (write-compact-size stream (length txs))
    (dolist (tx txs)
      (write-transaction stream tx))))

;;; Parse blocktxn payload
(defun parse-blocktxn-payload (payload)
  "Parse a blocktxn message payload."
  (flexi-streams:with-input-from-sequence (stream payload)
    (read-block-txn-response stream)))

;;; Addr (v1) message building

(defun make-addr-message (addrs-with-timestamps)
  "Create a serialized addr (v1) message from ADDRS-WITH-TIMESTAMPS.
Each entry is a list (net-addr timestamp)."
  (let ((payload
          (flexi-streams:with-output-to-sequence (stream)
            (write-compact-size stream (length addrs-with-timestamps))
            (dolist (entry addrs-with-timestamps)
              (destructuring-bind (addr timestamp) entry
                (write-net-addr stream addr :with-timestamp t :timestamp timestamp))))))
    (serialize-message "addr" payload)))

;;;; ============================================================
;;;; ADDRv2 (BIP 155)
;;;; ============================================================

;;; Network ID constants
(defconstant +addrv2-net-ipv4+  1)
(defconstant +addrv2-net-ipv6+  2)
(defconstant +addrv2-net-torv2+ 3)  ; deprecated
(defconstant +addrv2-net-torv3+ 4)
(defconstant +addrv2-net-i2p+   5)
(defconstant +addrv2-net-cjdns+ 6)

;;; Expected address sizes for each known network ID
(defparameter *addrv2-addr-sizes*
  (let ((ht (make-hash-table)))
    (setf (gethash +addrv2-net-ipv4+  ht) 4)
    (setf (gethash +addrv2-net-ipv6+  ht) 16)
    (setf (gethash +addrv2-net-torv2+ ht) 10)
    (setf (gethash +addrv2-net-torv3+ ht) 32)
    (setf (gethash +addrv2-net-i2p+   ht) 32)
    (setf (gethash +addrv2-net-cjdns+ ht) 16)
    ht)
  "Map of BIP 155 network ID to expected address byte length.")

;;; Deserialization

(defun read-net-addr-v2 (stream)
  "Read a single addrv2 entry from STREAM.
Returns (VALUES net-addr timestamp network-id) for IPv4/IPv6 entries with
correct address length. Returns NIL for unknown networks, deprecated TorV2,
or entries with mismatched address lengths (bytes are consumed but skipped)."
  (let* ((timestamp (read-uint32-le stream))
         (services (read-compact-size stream))
         (network-id (read-uint8 stream))
         (addr-len (read-compact-size stream)))
    ;; Read address bytes regardless (to advance stream position)
    (let ((addr-bytes (read-bytes stream addr-len))
          (port-high (read-byte stream))
          (port-low (read-byte stream))
          (expected-len (gethash network-id *addrv2-addr-sizes*)))
      ;; Skip if unknown network, wrong length, or deprecated TorV2
      (when (or (null expected-len)
                (/= addr-len expected-len)
                (= network-id +addrv2-net-torv2+))
        (return-from read-net-addr-v2 nil))
      ;; Build net-addr with 16-byte IP for IPv4/IPv6
      (let ((ip (cond
                  ((= network-id +addrv2-net-ipv4+)
                   ;; Convert 4-byte IPv4 to IPv4-mapped IPv6
                   (let ((mapped (make-array 16 :element-type '(unsigned-byte 8)
                                                :initial-element 0)))
                     (setf (aref mapped 10) #xFF)
                     (setf (aref mapped 11) #xFF)
                     (replace mapped addr-bytes :start1 12)
                     mapped))
                  ((= network-id +addrv2-net-ipv6+)
                   addr-bytes)
                  (t
                   ;; TorV3, I2P, CJDNS — valid parse but not storable in net-addr
                   (return-from read-net-addr-v2 nil)))))
        (values (make-net-addr :services services
                               :ip ip
                               :port (logior (ash port-high 8) port-low))
                timestamp
                network-id)))))

;;; Serialization

(defun write-net-addr-v2 (stream addr network-id timestamp)
  "Write a single addrv2 entry to STREAM.
ADDR is a net-addr, NETWORK-ID is the BIP 155 network type,
TIMESTAMP is the uint32 last-seen time."
  ;; Timestamp
  (write-uint32-le stream timestamp)
  ;; Services (compact-size)
  (write-compact-size stream (net-addr-services addr))
  ;; Network ID
  (write-uint8 stream network-id)
  ;; Address bytes (network-dependent)
  (cond
    ((= network-id +addrv2-net-ipv4+)
     ;; Extract 4-byte IPv4 from IPv4-mapped IPv6
     (write-compact-size stream 4)
     (write-bytes stream (subseq (net-addr-ip addr) 12 16)))
    ((= network-id +addrv2-net-ipv6+)
     (write-compact-size stream 16)
     (write-bytes stream (net-addr-ip addr)))
    (t
     (error "write-net-addr-v2: unsupported network ID ~D (only IPv4 and IPv6 are supported)" network-id)))
  ;; Port (big-endian)
  (write-byte (ash (net-addr-port addr) -8) stream)
  (write-byte (logand (net-addr-port addr) #xFF) stream))

(defun make-sendaddrv2-message ()
  "Create a serialized sendaddrv2 message (empty payload)."
  (serialize-message "sendaddrv2" #()))

(defun make-sendheaders-message ()
  "Create a serialized sendheaders message (BIP 130, empty payload)."
  (serialize-message "sendheaders" #()))

(defun make-wtxidrelay-message ()
  "Create a serialized wtxidrelay message (BIP 339, empty payload).
Must be sent between VERSION and VERACK."
  (serialize-message "wtxidrelay" #()))

(defun parse-feefilter-payload (payload)
  "Parse a feefilter message payload (BIP 133). Returns fee rate as uint64 (sat/kB)."
  (flexi-streams:with-input-from-sequence (stream payload)
    (read-uint64-le stream)))

(defun make-feefilter-message (fee-rate)
  "Create a feefilter message with FEE-RATE in satoshis per 1000 bytes (BIP 133)."
  (let ((payload (flexi-streams:with-output-to-sequence (stream)
                   (write-uint64-le stream fee-rate))))
    (serialize-message "feefilter" payload)))

(defun make-addrv2-message (entries)
  "Create a serialized addrv2 message from ENTRIES.
Each entry is a list (net-addr network-id timestamp)."
  (let ((payload
          (flexi-streams:with-output-to-sequence (stream)
            (write-compact-size stream (length entries))
            (dolist (entry entries)
              (destructuring-bind (addr network-id timestamp) entry
                (write-net-addr-v2 stream addr network-id timestamp))))))
    (serialize-message "addrv2" payload)))

(defun parse-addrv2-payload (payload)
  "Parse an addrv2 message payload.
Returns a list of (VALUES net-addr timestamp network-id) for valid IPv4/IPv6 entries.
Skips unknown or unsupported network types."
  (flexi-streams:with-input-from-sequence (stream payload)
    (let ((count (read-compact-size stream))
          (results '()))
      (loop repeat (min count 1000)
            do (multiple-value-bind (addr timestamp network-id)
                   (read-net-addr-v2 stream)
                 (when addr
                   (push (list addr timestamp network-id) results))))
      (nreverse results))))
