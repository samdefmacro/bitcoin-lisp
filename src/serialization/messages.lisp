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

(alexandria:define-constant +testnet3-magic+
  (make-array 4 :element-type '(unsigned-byte 8)
                :initial-contents '(#x0B #x11 #x09 #x07))
  :test #'equalp
  :documentation "Testnet network magic bytes.")

(alexandria:define-constant +testnet4-magic+
  (make-array 4 :element-type '(unsigned-byte 8)
                :initial-contents '(#x1C #x16 #x3F #x28))
  :test #'equalp
  :documentation "Testnet4 network magic bytes.")

(alexandria:define-constant +signet-magic+
  (make-array 4 :element-type '(unsigned-byte 8)
                :initial-contents '(#x0A #x03 #xCF #x40))
  :test #'equalp
  :documentation "Default signet network magic bytes.")

(alexandria:define-constant +regtest-magic+
  (make-array 4 :element-type '(unsigned-byte 8)
                :initial-contents '(#xFA #xBF #xB5 #xDA))
  :test #'equalp
  :documentation "Regtest network magic bytes.")

(defvar *network-magic* +testnet3-magic+
  "Current network magic bytes.")

;;;; Message header

(defconstant +command-size+ 12)
(defconstant +header-size+ 24)  ; 4 + 12 + 4 + 4

(defstruct message-header
  "P2P message header."
  (magic (copy-seq +testnet3-magic+) :type (simple-array (unsigned-byte 8) (4)))
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
  "Network address structure (BIP155 network-typed).
IP holds the raw address bytes: 16 (IPv4-mapped or plain IPv6, or CJDNS),
or 32 (TORv3 ed25519 pubkey / I2P SHA256 destination hash). NET is one of
:ipv4 :ipv6 :torv3 :i2p :cjdns, or NIL meaning \"IP, derive IPv4 vs IPv6
from the 16-byte mapped form\" (the pre-BIP155 representation, kept as the
default so plain-IP constructors need no :net)."
  (services 0 :type (unsigned-byte 64))
  (ip (make-array 16 :element-type '(unsigned-byte 8)
                     :initial-contents '(0 0 0 0 0 0 0 0 0 0 #xFF #xFF 127 0 0 1))
      :type (simple-array (unsigned-byte 8) (*)))
  (port 0 :type (unsigned-byte 16))
  (net nil :type (or null keyword)))

(defun make-empty-net-addr (&key (services 0))
  "An \"empty\" wire address — Core's default-constructed CService: all-zero
IPv6 (\"::\") and port 0. This is what modern Core serializes for the version
message's addr_from (always) and addr_recv (when the peer's address is
unusable), net_processing.cpp:1570/1585. Distinct from make-net-addr's
default, which is loopback."
  (make-net-addr :services services
                 :ip (make-array 16 :element-type '(unsigned-byte 8)
                                    :initial-element 0)
                 :port 0))

(defun ip-bytes-v4-mapped-p (ip)
  "T if a 16-byte address is IPv4-mapped IPv6 (::ffff:a.b.c.d)."
  (and (= (length ip) 16)
       (loop for i below 10 always (zerop (aref ip i)))
       (= (aref ip 10) #xFF)
       (= (aref ip 11) #xFF)))

(defun net-addr-network (addr)
  "The network of ADDR as a keyword (:ipv4 :ipv6 :torv3 :i2p :cjdns),
deriving IPv4 vs IPv6 from the mapped byte form when the net slot is NIL."
  (or (net-addr-net addr)
      (if (ip-bytes-v4-mapped-p (net-addr-ip addr)) :ipv4 :ipv6)))

(defun v1-compatible-network-p (network)
  "T if NETWORK can be carried in pre-BIP155 (addr v1) serialization —
IPv4/IPv6 only. Onion/I2P/CJDNS exist only in addrv2 gossip (Core
CNetAddr::IsAddrV1Compatible, netaddress.cpp:477-494)."
  (member network '(:ipv4 :ipv6)))

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
  "Write a network address to STREAM in the legacy (pre-BIP155) format.
A non-v1-compatible address (onion/I2P/CJDNS) is serialized as 16 zero
bytes, exactly like Core's SerializeV1Array (netaddress.h:324-356) —
callers should skip such addresses entirely where possible (Core
IsAddrCompatible, net_processing.cpp:1117-1119); the zero form is only
the unavoidable-case fallback."
  (when with-timestamp
    (write-uint32-le stream (or timestamp (get-unix-time))))
  (write-uint64-le stream (net-addr-services addr))
  (if (v1-compatible-network-p (net-addr-network addr))
      (write-bytes stream (net-addr-ip addr))
      (write-bytes stream (make-array 16 :element-type '(unsigned-byte 8)
                                         :initial-element 0)))
  ;; Port is big-endian
  (write-byte (ash (net-addr-port addr) -8) stream)
  (write-byte (logand (net-addr-port addr) #xFF) stream))

(defconstant +universal-unix-epoch-offset+ 2208988800
  "Seconds between the CL universal-time epoch (1900) and the Unix epoch (1970).")

(defun get-unix-time ()
  "Get current Unix timestamp."
  (- (get-universal-time) +universal-unix-epoch-offset+))

;;;; Version message

(defconstant +protocol-version+ 70016)
(defconstant +node-network+ 1)
(defconstant +node-witness+ (ash 1 3))
(defconstant +node-network-limited+ (ash 1 10))  ; BIP 159: pruned node
(defconstant +node-p2p-v2+ (ash 1 11))            ; BIP 324: v2 transport support
(defconstant +node-compact-filters+ (ash 1 6))   ; BIP 157/158: serves cfilters

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
(defconstant +inv-type-cmpct-block+ 4)
;; MSG_WTX (BIP339): a tx identified by its witness txid (wtxid), used for
;; wtxidrelay-negotiated announcements/getdata. Distinct from MSG_WITNESS_TX
;; (+inv-type-witness-tx+ = MSG_TX|witness-flag), which is txid-based.
(defconstant +inv-type-wtx+ 5)
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

(defvar *user-agent* "/bitcoin-lisp:0.1.0/"
  "The BIP14 subversion string this node advertises (Core strSubVersion,
init.cpp:1683 FormatSubVersion). -uacomment appends sanitized comments:
\"/bitcoin-lisp:0.1.0(comment1; comment2)/\".")

(defparameter *build-git-rev* "unknown"
  "Short git revision of the running build. The launcher (scripts/run-node.sh)
stamps it via STAMP-BUILD-GIT-REV after loading the system and before the node
advertises, so getnetworkinfo and the version handshake identify exactly which
commit is deployed. Kept separate from the version literal — rather than baked
in at compile time — so the launcher (or a future save-image build step) can
set it without a recompile. The default \"unknown\" leaves the subversion at
its plain BIP14 form.")

(defun subversion-git-comment ()
  "The build git rev as a BIP14 subversion comment token \"g<rev>\", or NIL
when unstamped (*build-git-rev* = \"unknown\"). The leading 'g' (git-describe
convention) over a hex rev is alphanumeric, so it is inherently uacomment-safe
and cannot overflow the +max-subversion-length+ cap."
  (unless (string= *build-git-rev* "unknown")
    (concatenate 'string "g" *build-git-rev*)))

(defun stamp-build-git-rev (rev)
  "Record REV as the running build's git revision and fold it into *user-agent*
as a leading BIP14 comment (\"/bitcoin-lisp:0.1.0(g<rev>)/\"). The launcher
calls this once, after load and before start-node. A NIL, empty, or \"unknown\"
REV leaves the plain \"/bitcoin-lisp:0.1.0/\" subversion. Assumes no -uacomment
is in play (the supervisor path); config parsing of -uacomment re-derives
*user-agent* via FORMAT-SUBVERSION, which also folds in the stamped rev."
  (when (and rev (plusp (length rev)) (not (string= rev "unknown")))
    (setf *build-git-rev* rev))
  (let ((comment (subversion-git-comment)))
    (setf *user-agent*
          (if comment
              (format nil "/bitcoin-lisp:0.1.0(~A)/" comment)
              "/bitcoin-lisp:0.1.0/")))
  *user-agent*)

(defun make-version-message-bytes (&key (version +protocol-version+)
                                        (services +node-network+)
                                        (timestamp (get-unix-time))
                                        (user-agent *user-agent*)
                                        (start-height 0)
                                        (relay t)
                                        addr-recv
                                        nonce)
  "Create a serialized version message. ADDR-RECV (\"addr_you\"), when given,
is a net-addr carrying the peer's own address; the default is the all-zero
empty address. addr_from is ALWAYS the all-zero empty address — that is
Core's behavior too (PushNodeVersion serializes CNetAddr::V1(CService{}) for
\"addrMe\", net_processing.cpp:1585); self-advertisement happens via
addr/addrv2. (The former dummy here was loopback ::ffff:127.0.0.1, a real
divergence from Core's empty CService.)"
  (let ((msg (make-version-message
              :version version
              :services services
              :timestamp timestamp
              :addr-recv (or addr-recv (make-empty-net-addr :services services))
              :addr-from (make-empty-net-addr :services services)
              ;; Caller-supplied per-connection nonce (Core CNode's
              ;; nLocalHostNonce). The default keeps standalone/test callers
              ;; working; the live handshake always passes the peer's own
              ;; nonce so self-connections can be detected.
              :nonce (or nonce (random (expt 2 64)))
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

(defun make-headers-message (headers)
  "Create a headers message from a list of block headers.
Each header is written as the 80-byte header followed by a compact-size 0
transaction count — the on-wire format Bitcoin Core uses (a headers message
serializes header-only CBlocks, which append nTx=0)."
  (let ((payload (flexi-streams:with-output-to-sequence (stream)
                   (write-compact-size stream (length headers))
                   (dolist (header headers)
                     (write-block-header stream header)
                     (write-compact-size stream 0)))))
    (serialize-message "headers" payload)))

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

(defun make-notfound-message (inv-vectors)
  "Create a notfound message (same payload shape as inv): tells a peer we cannot
serve the objects it requested via getdata."
  (let ((payload (flexi-streams:with-output-to-sequence (stream)
                   (write-compact-size stream (length inv-vectors))
                   (dolist (inv inv-vectors)
                     (write-inv-vector stream inv)))))
    (serialize-message "notfound" payload)))

;;;; Transaction message

(defun make-tx-message (tx &key witness)
  "Create a serialized \"tx\" message. With :WITNESS (for MSG_WTX / MSG_WITNESS_TX
getdata), a segwit tx is serialized in BIP144 witness form; a non-witness tx, or
:WITNESS nil (legacy MSG_TX), uses the legacy encoding — matching Core's
TX_WITH_WITNESS vs TX_NO_WITNESS in FindTxForGetData."
  (let ((payload (if witness
                     (transaction-wire-bytes tx)
                     (serialize-transaction tx))))
    (serialize-message "tx" payload)))

(defun make-block-message (block &key witness)
  "Create a serialized block message from BLOCK. With :WITNESS, the transactions
are BIP144 witness-serialized (answering a MSG_WITNESS_BLOCK getdata); otherwise
legacy (MSG_BLOCK). Witness serving requires the block to actually carry its
witness data — see store-block, which persists blocks witness-complete."
  (serialize-message "block"
                     (if witness
                         (serialize-witness-block block)
                         (serialize block))))

(defun parse-tx-payload (payload)
  "Parse a tx message payload into a transaction."
  (flexi-streams:with-input-from-sequence (stream payload)
    (read-transaction stream)))

;;;; Message parsing

(defconstant +max-inv-count+ 50000
  "Maximum entries in an inv/getdata message (Bitcoin Core MAX_INV_SZ). A peer
that exceeds this is misbehaving; reject the whole message.")

(defconstant +max-headers-count+ 2000
  "Maximum headers in a headers message (Bitcoin Core MAX_HEADERS_RESULTS).")

(defconstant +max-addr-count+ 1000
  "Maximum entries in an addr/addrv2 message (Bitcoin Core MAX_ADDR_TO_SEND).")

(defconstant +max-locator-count+ 101
  "Maximum block hashes in a getheaders/getblocks block locator (Bitcoin Core
MAX_LOCATOR_SZ). A peer that exceeds this is misbehaving.")

(defconstant +max-block-tx-count+ 50000
  "Upper bound on the number of transactions referenced by a single block in the
compact-block / getblocktxn / blocktxn messages. A 4M-weight block holds at most
~16.7k of the smallest possible transactions, so this never rejects a valid
block while bounding the per-message allocation well below the compact-size cap.")

(defun parse-inv-payload (payload)
  "Parse an inv or getdata message payload into a list of inv-vectors."
  (flexi-streams:with-input-from-sequence (stream payload)
    (let ((count (read-bounded-count stream +max-inv-count+ "inv/getdata")))
      (loop repeat count collect (read-inv-vector stream)))))

(defun parse-headers-payload (payload)
  "Parse a headers message payload into a list of block headers."
  (flexi-streams:with-input-from-sequence (stream payload)
    (let ((count (read-bounded-count stream +max-headers-count+ "headers")))
      (loop repeat count
            collect (prog1 (read-block-header stream)
                      ;; Headers message includes tx count (always 0) after each header
                      (read-compact-size stream))))))

(defun parse-block-locator-payload (payload)
  "Parse a getheaders or getblocks payload: a 4-byte protocol version, a
bounded block-locator hash list (most-recent-first), and a 32-byte stop hash.
Returns (VALUES locator-hashes stop-hash). A locator longer than
+max-locator-count+ signals an error (the caller disconnects the peer)."
  (flexi-streams:with-input-from-sequence (stream payload)
    (read-uint32-le stream)             ; protocol version (unused)
    (let* ((count (read-bounded-count stream +max-locator-count+ "block locator"))
           (hashes (loop repeat count collect (read-hash256 stream)))
           (stop-hash (read-hash256 stream)))
      (values hashes stop-hash))))

(defun parse-block-payload (payload)
  "Parse a block message payload into a bitcoin-block.

Hot path: called once per block message received from peers (potentially
thousands per minute during IBD). Uses byte-reader for direct index-based
reads instead of flexi-streams' Gray-stream input dispatch."
  (br-read-bitcoin-block (make-byte-reader-from payload)))

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
         (shortids-count (read-bounded-count stream +max-block-tx-count+ "compact-block short-ids"))
         (short-ids (loop repeat shortids-count
                          collect (read-short-txid stream)))
         (prefilled-count (read-bounded-count stream +max-block-tx-count+ "compact-block prefilled"))
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
         (count (read-bounded-count stream +max-block-tx-count+ "getblocktxn indexes"))
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
         (count (read-bounded-count stream +max-block-tx-count+ "blocktxn transactions"))
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

;;; Make blocktxn message (BIP152 serve side)
(defun make-blocktxn-message (block-hash txs &key witness)
  "Create a blocktxn message answering a getblocktxn: BLOCK-HASH followed by the
requested TXS (a list) in order. With :WITNESS, each tx that carries witness data
is BIP144 witness-serialized — a witness compact-block reconstruction needs it;
non-witness txs stay legacy either way, matching Core's TX_WITH_WITNESS. (The
older write-block-txn-response is legacy-only and unsuitable for witness serving.)"
  (let ((payload (flexi-streams:with-output-to-sequence (stream)
                   (write-hash256 stream block-hash)
                   (write-compact-size stream (length txs))
                   (dolist (tx txs)
                     (if (and witness (transaction-has-witness-p tx))
                         (write-witness-transaction stream tx)
                         (write-transaction stream tx))))))
    (serialize-message "blocktxn" payload)))

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

;;; Expected address sizes for each known network ID. TORV2 (id 3) is dead:
;;; Core's SetNetFromBIP155Network no longer recognizes it (netaddress.cpp:
;;; 49-98 has no TORV2 case), so it is skipped like an unknown-from-the-future
;;; id — with NO length check (any length is consumed and dropped).
(defparameter *addrv2-addr-sizes*
  (let ((ht (make-hash-table)))
    (setf (gethash +addrv2-net-ipv4+  ht) 4)
    (setf (gethash +addrv2-net-ipv6+  ht) 16)
    (setf (gethash +addrv2-net-torv3+ ht) 32)
    (setf (gethash +addrv2-net-i2p+   ht) 32)
    (setf (gethash +addrv2-net-cjdns+ ht) 16)
    ht)
  "Map of recognized BIP 155 network ID to required address byte length.")

(defconstant +max-addrv2-address-size+ 512
  "Maximum BIP155 address length (Core CNetAddr::MAX_ADDRV2_SIZE).")

(defparameter *addrv2-net-keywords*
  `((,+addrv2-net-ipv4+  . :ipv4)
    (,+addrv2-net-ipv6+  . :ipv6)
    (,+addrv2-net-torv3+ . :torv3)
    (,+addrv2-net-i2p+   . :i2p)
    (,+addrv2-net-cjdns+ . :cjdns))
  "BIP155 network id <-> network keyword.")

(defun bip155-network-keyword (network-id)
  "Network keyword for a BIP155 NETWORK-ID, or NIL if unrecognized."
  (cdr (assoc network-id *addrv2-net-keywords*)))

(defun network-bip155-id (network)
  "BIP155 network id for the keyword NETWORK (Core GetBIP155Network)."
  (or (car (rassoc network *addrv2-net-keywords*))
      (error "network-bip155-id: unknown network ~S" network)))

;;; Deserialization

(defparameter +torv2-in-ipv6-prefix+ #(#xFD #x87 #xD8 #x7E #xEB #x43)
  "Prefix of the dead TORv2-embedded-in-IPv6 form (Core TORV2_IN_IPV6_PREFIX).")

(defparameter +internal-in-ipv6-prefix+ #(#xFD #x6B #x88 #xC0 #x87 #x24)
  "Prefix of Core's NET_INTERNAL-embedded-in-IPv6 form (0xFD + sha256(\"bitcoin\")[0:5]).")

(defun %bytes-have-prefix-p (bytes prefix)
  (and (>= (length bytes) (length prefix))
       (loop for i below (length prefix)
             always (= (aref bytes i) (aref prefix i)))))

(defun read-net-addr-v2 (stream)
  "Read a single addrv2 entry from STREAM (Core CNetAddr::UnserializeV2Stream,
netaddress.h:423-470). Returns (VALUES net-addr timestamp network-id) for a
usable address; NIL after consuming the entry for ones Core drops silently:
unknown network ids (maybe from the future), dead TORv2, and IPv6 addresses
embedding IPv4/TORv2/NET_INTERNAL forms. Signals an error — rejecting the
whole message, as Core throws — for a recognized network id with the wrong
address length, or any address longer than +max-addrv2-address-size+."
  (let* ((timestamp (read-uint32-le stream))
         ;; services is a BIP155 CompactSize-encoded u64 BITMASK, not a
         ;; length — Core deserializes it with CompactSizeFormatter<false>
         ;; (protocol.h:446), i.e. NO range check. The default cap here
         ;; (+max-compact-size+) made us treat any peer advertising a
         ;; service bit >= 26 as malformed and disconnect it; exposed in
         ;; production when #245's getaddr started soliciting 1000-entry
         ;; addrv2 replies on mainnet (2026-07-12).
         (services (read-compact-size stream :range-check nil))
         (network-id (read-uint8 stream))
         (addr-len (read-compact-size stream)))
    (when (> addr-len +max-addrv2-address-size+)
      (error "addrv2 address too long: ~D > ~D" addr-len +max-addrv2-address-size+))
    (let ((expected-len (gethash network-id *addrv2-addr-sizes*)))
      ;; A recognized network with the wrong length is a stream failure in
      ;; Core (SetNetFromBIP155Network throws) — the entire message is bad.
      (when (and expected-len (/= addr-len expected-len))
        (error "BIP155 network ~D address with length ~D (should be ~D)"
               network-id addr-len expected-len))
      ;; Read address bytes + port regardless (to advance stream position)
      (let* ((addr-bytes (read-bytes stream addr-len))
             (port-high (read-byte stream))
             (port-low (read-byte stream))
             (port (logior (ash port-high 8) port-low)))
        (flet ((entry (net ip)
                 (values (make-net-addr :services services :ip ip
                                        :port port :net net)
                         timestamp network-id)))
          (cond
            ;; Unknown network id (or dead TORv2): silently dropped; Core
            ;; keeps reading subsequent entries (netaddress.cpp:94-98).
            ((null expected-len) nil)
            ((= network-id +addrv2-net-ipv4+)
             ;; Store as IPv4-mapped IPv6 (our internal IP form).
             (let ((mapped (make-array 16 :element-type '(unsigned-byte 8)
                                          :initial-element 0)))
               (setf (aref mapped 10) #xFF)
               (setf (aref mapped 11) #xFF)
               (replace mapped addr-bytes :start1 12)
               (entry :ipv4 mapped)))
            ((= network-id +addrv2-net-ipv6+)
             ;; IPv4, TORv2 and NET_INTERNAL embedded in IPv6 are not valid
             ;; in v2 encoding: Core unserializes them as !IsValid()/internal
             ;; and they never reach addrman (netaddress.h:446-462).
             (if (or (ip-bytes-v4-mapped-p addr-bytes)
                     (%bytes-have-prefix-p addr-bytes +torv2-in-ipv6-prefix+)
                     (%bytes-have-prefix-p addr-bytes +internal-in-ipv6-prefix+))
                 nil
                 (entry :ipv6 addr-bytes)))
            ((= network-id +addrv2-net-torv3+) (entry :torv3 addr-bytes))
            ((= network-id +addrv2-net-i2p+)   (entry :i2p addr-bytes))
            ((= network-id +addrv2-net-cjdns+)
             ;; A CJDNS address without the fc prefix parses but is invalid
             ;; (Core IsValid, netaddress.cpp:441-443) — drop it here.
             (if (= (aref addr-bytes 0) #xFC)
                 (entry :cjdns addr-bytes)
                 nil))))))))

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
  (let ((ip (net-addr-ip addr)))
    (flet ((emit (bytes required-len)
             (unless (= (length bytes) required-len)
               (error "write-net-addr-v2: network ~D address must be ~D bytes, got ~D"
                      network-id required-len (length bytes)))
             (write-compact-size stream required-len)
             (write-bytes stream bytes)))
      (cond
        ((= network-id +addrv2-net-ipv4+)
         ;; Extract 4-byte IPv4 from IPv4-mapped IPv6
         (emit (subseq ip 12 16) 4))
        ((or (= network-id +addrv2-net-ipv6+)
             (= network-id +addrv2-net-cjdns+))
         (emit ip 16))
        ((or (= network-id +addrv2-net-torv3+)
             (= network-id +addrv2-net-i2p+))
         (emit ip 32))
        (t
         (error "write-net-addr-v2: unsupported network ID ~D" network-id)))))
  ;; Port (big-endian)
  (write-byte (ash (net-addr-port addr) -8) stream)
  (write-byte (logand (net-addr-port addr) #xFF) stream))

(defun make-sendaddrv2-message ()
  "Create a serialized sendaddrv2 message (empty payload)."
  (serialize-message "sendaddrv2" #()))

(defun make-getaddr-message ()
  "Create a serialized getaddr message (empty payload)."
  (serialize-message "getaddr" #()))

(defun make-sendheaders-message ()
  "Create a serialized sendheaders message (BIP 130, empty payload)."
  (serialize-message "sendheaders" #()))

(defun make-wtxidrelay-message ()
  "Create a serialized wtxidrelay message (BIP 339, empty payload).
Must be sent between VERSION and VERACK."
  (serialize-message "wtxidrelay" #()))

(defconstant +txreconciliation-version+ 1
  "BIP 330 transaction reconciliation protocol version we support (Bitcoin
Core node/txreconciliation.h:15 TXRECONCILIATION_VERSION).")

(defun make-sendtxrcncl-message (salt &optional (version +txreconciliation-version+))
  "Create a sendtxrcncl message (BIP 330): uint32 VERSION + uint64 SALT, both
LE — 12-byte payload (Core protocol.h:262-266). Must be sent between VERSION
and VERACK."
  (let ((payload (flexi-streams:with-output-to-sequence (stream)
                   (write-uint32-le stream version)
                   (write-uint64-le stream salt))))
    (serialize-message "sendtxrcncl" payload)))

(defun parse-sendtxrcncl-payload (payload)
  "Parse a sendtxrcncl message payload (BIP 330).
Returns (VALUES version salt)."
  (flexi-streams:with-input-from-sequence (stream payload)
    (values (read-uint32-le stream)
            (read-uint64-le stream))))

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
Returns (VALUES entries announced-count): ENTRIES a list of
(net-addr timestamp network-id) for all usable addresses
(IPv4/IPv6/TORv3/I2P/CJDNS), ANNOUNCED-COUNT the message's declared address
count — which can exceed (length entries), since unknown network ids are
skipped without failing the message (BIP155) yet still count toward Core's
vAddr.size() gates. A recognized network id with a wrong address length
signals an error (Core rejects the whole message)."
  (flexi-streams:with-input-from-sequence (stream payload)
    (let ((count (read-bounded-count stream +max-addr-count+ "addrv2"))
          (results '()))
      (loop repeat count
            do (multiple-value-bind (addr timestamp network-id)
                   (read-net-addr-v2 stream)
                 (when addr
                   (push (list addr timestamp network-id) results))))
      (values (nreverse results) count))))

;;;; ============================================================
;;;; BIP 157 compact block filter serving (getcfilters / getcfheaders /
;;;; getcfcheckpt and their replies). Filter type 0 = basic (BIP 158).
;;;; ============================================================

(defun parse-getcfilters-payload (payload)
  "Parse a getcfilters/getcfheaders payload: filter_type (u8), start_height
(u32 LE), stop_hash (32 bytes). Returns (VALUES filter-type start-height
stop-hash), or NIL on truncation."
  (when (>= (length payload) 37)
    (let ((br (make-byte-reader-from payload)))
      (values (br-read-u8 br)
              (br-read-u32-le br)
              (br-read-bytes br 32)))))

(defun parse-getcfcheckpt-payload (payload)
  "Parse a getcfcheckpt payload: filter_type (u8), stop_hash (32 bytes).
Returns (VALUES filter-type stop-hash), or NIL on truncation."
  (when (>= (length payload) 33)
    (let ((br (make-byte-reader-from payload)))
      (values (br-read-u8 br)
              (br-read-bytes br 32)))))

(defun make-cfilter-message (filter-type block-hash filter-bytes)
  "Build a cfilter message: filter_type (u8), block_hash (32), then the encoded
filter as a var-length byte string."
  (let ((payload (flexi-streams:with-output-to-sequence (s)
                   (write-uint8 s filter-type)
                   (write-bytes s block-hash)
                   (write-compact-size s (length filter-bytes))
                   (write-bytes s filter-bytes))))
    (serialize-message "cfilter" payload)))

(defun make-cfheaders-message (filter-type stop-hash prev-header filter-hashes)
  "Build a cfheaders message: filter_type (u8), stop_hash (32), previous filter
header (32), then the vector of per-block filter HASHES (32 each)."
  (let ((payload (flexi-streams:with-output-to-sequence (s)
                   (write-uint8 s filter-type)
                   (write-bytes s stop-hash)
                   (write-bytes s prev-header)
                   (write-compact-size s (length filter-hashes))
                   (dolist (h filter-hashes)
                     (write-bytes s h)))))
    (serialize-message "cfheaders" payload)))

(defun make-cfcheckpt-message (filter-type stop-hash headers)
  "Build a cfcheckpt message: filter_type (u8), stop_hash (32), then the filter
HEADERS at each 1000-block checkpoint (32 each)."
  (let ((payload (flexi-streams:with-output-to-sequence (s)
                   (write-uint8 s filter-type)
                   (write-bytes s stop-hash)
                   (write-compact-size s (length headers))
                   (dolist (h headers)
                     (write-bytes s h)))))
    (serialize-message "cfcheckpt" payload)))
