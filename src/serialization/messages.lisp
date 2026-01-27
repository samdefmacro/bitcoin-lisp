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
If WITH-TIMESTAMP is true, read a 4-byte timestamp first (for addr messages)."
  (when with-timestamp
    (read-uint32-le stream))  ; timestamp, ignored for now
  (let ((services (read-uint64-le stream))
        (ip (read-bytes stream 16))
        (port-high (read-byte stream))
        (port-low (read-byte stream)))
    (make-net-addr :services services
                   :ip ip
                   :port (logior (ash port-high 8) port-low))))

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
