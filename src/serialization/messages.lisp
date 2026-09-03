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
(defvar *network-magic* (bl.chain:chain-params-magic (bl.chain:find-chain-params :testnet3))
  "Current network magic bytes.")

;;;; Message header

(defconstant +command-size+ 12)
(defconstant +header-size+ 24)  ; 4 + 12 + 4 + 4

(define-message message-header
    (:documentation "P2P message header (Core CMessageHeader).")
  (magic (:bytes 4) :default (copy-seq *network-magic*))
  ;; 12 NUL-padded bytes on the wire, a string in the struct
  (command :custom :slot-type string
           :read (bytes-to-command (br-read-bytes br +command-size+))
           :write (bb-write-bytes bb (command-to-bytes value)))
  (payload-length :u32)
  (checksum (:bytes 4)))

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
  (let ((hash (bl.crypto:hash256 payload)))
    (subseq hash 0 4)))

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
                     (br-read-u32-le stream))))
    (let ((services (br-read-u64-le stream))
          (ip (br-read-bytes stream 16))
          (port-high (br-read-u8 stream))
          (port-low (br-read-u8 stream)))
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
    (bb-write-u32-le stream (or timestamp (get-unix-time))))
  (bb-write-u64-le stream (net-addr-services addr))
  (if (v1-compatible-network-p (net-addr-network addr))
      (bb-write-bytes stream (net-addr-ip addr))
      (bb-write-bytes stream (make-array 16 :element-type '(unsigned-byte 8)
                                         :initial-element 0)))
  ;; Port is big-endian
  (bb-write-u8 stream (ash (net-addr-port addr) -8))
  (bb-write-u8 stream (logand (net-addr-port addr) #xFF)))

(defconstant +universal-unix-epoch-offset+ 2208988800
  "Seconds between the CL universal-time epoch (1900) and the Unix epoch (1970).")

(defvar *mock-time* nil
  "When non-NIL, the Unix timestamp GET-UNIX-TIME reports instead of the system
clock. Core's g_mock_time (util/time.cpp), set by the regtest-only setmocktime
RPC: the functional test framework drives time forward explicitly rather than
sleeping, so almost every non-clean test depends on it.

NIL means the system clock, which is also what setmocktime 0 restores.")

(defun get-real-unix-time ()
  "The system clock's Unix timestamp, never mocked.

For the few things that must keep measuring real elapsed time while a test
drives the mock clock — uptime is the one Core is explicit about, since
GetUptime uses SteadyClock rather than the mockable GetTime
(common/system.cpp:134)."
  (- (get-universal-time) +universal-unix-epoch-offset+))

(defun get-unix-time ()
  "Current Unix timestamp, or the mocked one when setmocktime is in effect
(Core GetTime, util/time.cpp)."
  (or *mock-time* (get-real-unix-time)))

(defun get-node-time ()
  "Current CL universal time, or the mocked one when setmocktime is in effect.

The universal-time counterpart of GET-UNIX-TIME, and the node clock of record
for anything that makes a decision about wall-clock time: peer inactivity, ban
expiry, stale-tip detection, feeler cadence, the getheaders throttle, the
periodic chainstate flush.

Core splits the same way and the split is the whole point. `NodeClock`
(util/time.h:19) returns the mock when one is set; `SteadyClock` (:27) never
does. So `FlushStateToDisk` reads `NodeClock::now()` for the PERIODIC decision
(validation.cpp:2759,2765) but `SteadyClock::now()` for the durations it logs
(:2301,2382); `m_last_getheaders_timestamp` is a `NodeClock::time_point`
(net_processing.cpp:401); and `GetUptime` deliberately uses SteadyClock.

Three classes stay on the raw clock here, each for Core's own reason:

- entropy seeding — a mocked clock is a PREDICTABLE seed;
- anti-hang watchdogs (the stuck-tip halt, the no-progress yield, the disk
  sampler) — they measure real elapsed time, and a clock jumped forward by a
  test would fire them spuriously;
- durations that are only logged, plus the GBT longpoll deadline, which Core
  likewise runs off `steady_clock` (rpc/mining.cpp).

The window in which this matters is exactly the functional test suite: the
framework drives time with setmocktime rather than sleeping
(test_framework.py:810), so a site left on the raw clock is a site no test can
reach."
  (if *mock-time*
      (+ *mock-time* +universal-unix-epoch-offset+)
      (get-universal-time)))

;;;; Version message

(defconstant +protocol-version+ 70016)
(defconstant +node-network+ 1)
(defconstant +node-witness+ (ash 1 3))
(defconstant +node-network-limited+ (ash 1 10))  ; BIP 159: pruned node
(defconstant +node-p2p-v2+ (ash 1 11))            ; BIP 324: v2 transport support
(defconstant +node-compact-filters+ (ash 1 6))   ; BIP 157/158: serves cfilters

(define-message version-message
    (:documentation "Version message payload (Core protocol.h / net_processing.cpp
PushNodeVersion).")
  (version :i32 :default +protocol-version+)
  (services :u64 :default +node-network+)
  (timestamp :i64)
  (addr-recv (:struct net-addr) :default (make-net-addr))
  (addr-from (:struct net-addr) :default (make-net-addr))
  (nonce :u64)
  (user-agent :var-string :default (format-user-agent nil))
  (start-height :i32)
  ;; relay flag may not be present in older versions (BIP 37): absent means T
  (relay :bool :default t
         :read (if (> version 70001)
                   (= (if (br-eof-p br) 1 (br-read-u8 br)) 1)
                   t)))

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

(define-message inv-vector
    (:documentation "Inventory vector - identifies an object (transaction or block).")
  (type :u32 :default +inv-type-tx+)
  (hash :hash256))

;;;; Generic message serialization

(defun serialize-message (command payload-bytes &key (magic *network-magic*))
  "Create a complete P2P message with header and payload."
  (let ((header (make-message-header
                 :magic (copy-seq magic)
                 :command command
                 :payload-length (length payload-bytes)
                 :checksum (compute-checksum payload-bytes))))
    (with-byte-buf (stream)
      (write-message-header stream header)
      (bb-write-bytes stream payload-bytes))))

(defconstant +client-version-major+ 0)
(defconstant +client-version-minor+ 1)
(defconstant +client-version-build+ 0)

(defconstant +client-version+ (+ (* 10000 +client-version-major+)
                                 (* 100 +client-version-minor+)
                                 +client-version-build+)
  "This node's version as Core's CLIENT_VERSION integer
(clientversion.h:26-29: 10000*major + 100*minor + build). The single source of
the version number: getnetworkinfo.version, the BIP14 user agent and the
wallet's creation-version record all derive from it.")

(defun client-version-string ()
  "The dotted client version, e.g. \"0.1.0\"."
  (format nil "~D.~D.~D" +client-version-major+ +client-version-minor+
          +client-version-build+))

(defun format-user-agent (comments)
  "BIP14 subversion \"/bl:<version>(c1; c2)/\" (Core FormatSubVersion,
clientversion.cpp:67-72), with no parenthesised block when COMMENTS is empty."
  (if comments
      (format nil "/bl:~A(~{~A~^; ~})/" (client-version-string) comments)
      (format nil "/bl:~A/" (client-version-string))))

(defvar *user-agent* (format-user-agent nil)
  "The BIP14 subversion string this node advertises (Core strSubVersion,
init.cpp:1683 FormatSubVersion). -uacomment appends sanitized comments:
\"/bl:<version>(comment1; comment2)/\".")

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

(defun subversion-with-build-rev (comments)
  "The BIP14 subversion for COMMENTS with the stamped build rev, when there is
one, prepended as its leading \"g<rev>\" comment — the one place that rule lives
(stamp-build-git-rev and -uacomment parsing both use it)."
  (let ((git (subversion-git-comment)))
    (format-user-agent (if git (cons git comments) comments))))

(defun stamp-build-git-rev (rev)
  "Record REV as the running build's git revision and fold it into *user-agent*
as a leading BIP14 comment (\"/bl:0.1.0(g<rev>)/\"). The launcher
calls this once, after load and before start-node. A NIL, empty, or \"unknown\"
REV leaves the plain \"/bl:0.1.0/\" subversion. Assumes no -uacomment
is in play (the supervisor path); config parsing of -uacomment re-derives
*user-agent* via FORMAT-SUBVERSION, which also folds in the stamped rev."
  (when (and rev (plusp (length rev)) (not (string= rev "unknown")))
    (setf *build-git-rev* rev))
  (setf *user-agent* (subversion-with-build-rev nil)))

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
    (with-byte-buf (stream)
      (write-version-message stream msg))))

(defun make-verack-message ()
  "Create a serialized verack message (empty payload)."
  (serialize-message "verack" #()))

(defun %nonce-payload (nonce)
  "The 8-byte payload ping and pong share (BIP 31)."
  (with-byte-buf (stream) (bb-write-u64-le stream nonce)))

(defun make-ping-message (&optional (nonce (random (expt 2 64))))
  "Create a serialized ping message."
  (serialize-message "ping" (%nonce-payload nonce)))

(defun make-pong-message (nonce)
  "Create a serialized pong message."
  (serialize-message "pong" (%nonce-payload nonce)))

(defun %locator-payload (block-locator-hashes stop-hash)
  "The payload getblocks and getheaders share: protocol version, the block
locator (most recent hash first), and the hash to stop at -- all zeros for
\"as many as you have\"."
  (with-byte-buf (stream)
    (bb-write-u32-le stream +protocol-version+)
    (bb-write-varint stream (length block-locator-hashes))
    (dolist (hash block-locator-hashes)
      (bb-write-hash256 stream hash))
    (bb-write-hash256 stream (or stop-hash
                                 (make-array 32 :element-type '(unsigned-byte 8)
                                                :initial-element 0)))))

(defun make-getblocks-message (block-locator-hashes &optional stop-hash)
  "Create a getblocks message.
BLOCK-LOCATOR-HASHES is a list of block hashes (most recent first).
STOP-HASH is the hash to stop at (or zeros to get maximum blocks)."
  (serialize-message "getblocks" (%locator-payload block-locator-hashes stop-hash)))

(defun make-getheaders-message (block-locator-hashes &optional stop-hash)
  "Create a getheaders message (same payload shape as getblocks)."
  (serialize-message "getheaders" (%locator-payload block-locator-hashes stop-hash)))

(defun make-headers-message (headers)
  "Create a headers message from a list of block headers.
Each header is written as the 80-byte header followed by a compact-size 0
transaction count — the on-wire format Bitcoin Core uses (a headers message
serializes header-only CBlocks, which append nTx=0)."
  (let ((payload (with-byte-buf (stream)
                   (bb-write-varint stream (length headers))
                   (dolist (header headers)
                     (bb-write-block-header stream header)
                     (bb-write-varint stream 0)))))
    (serialize-message "headers" payload)))

(defun %inv-list-payload (inv-vectors)
  "The payload inv, getdata and notfound share: a count and the inv vectors."
  (with-byte-buf (stream)
    (bb-write-varint stream (length inv-vectors))
    (dolist (inv inv-vectors)
      (write-inv-vector stream inv))))

(defun make-getdata-message (inv-vectors)
  "Create a getdata message from a list of inv-vectors."
  (serialize-message "getdata" (%inv-list-payload inv-vectors)))

(defun make-inv-message (inv-vectors)
  "Create an inv message from a list of inv-vectors."
  (serialize-message "inv" (%inv-list-payload inv-vectors)))

(defun make-notfound-message (inv-vectors)
  "Create a notfound message (same payload shape as inv): tells a peer we cannot
serve the objects it requested via getdata."
  (serialize-message "notfound" (%inv-list-payload inv-vectors)))

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
  "Parse a tx message PAYLOAD into a transaction.

⚠️ PAYLOAD must be consumed WHOLE. Core's DecodeTx only accepts a decoding that
leaves the reader empty (core_io.cpp:180, `if (ssData.empty()) ok_extended =
true`), so trailing bytes make the transaction undecodable there. Ignoring them
means sendrawtransaction accepts hex Core rejects, and two nodes disagree about
whether a message is well formed — over a transaction whose txid does not
mention the trailing bytes at all.

Found by FUZZ-TRANSACTION-ROUNDTRIPS-WHAT-IT-PARSES: a mutant whose script
length shrank parsed happily and re-serialized shorter than its input."
  (with-byte-reader (stream payload)
    (let ((tx (br-read-transaction stream)))
      (unless (= (br-pos stream) (length payload))
        (serialization-error "tx payload has ~D trailing byte(s)"
               (- (length payload) (br-pos stream))))
      tx)))

;;;; Message parsing

(defun br-read-bounded-count (br max name)
  "Read a CompactSize count from BR and signal an error if it exceeds MAX.
NAME labels the field. Rejecting an over-limit count up front -- rather than
looping/allocating for it -- is Bitcoin Core's misbehaving-peer posture for
protocol vectors (inv, headers, addr, block txns)."
  (let ((count (br-read-compact-size br)))
    (when (> count max)
      (serialization-error "~A count ~D exceeds maximum ~D" name count max))
    count))

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
  (with-byte-reader (stream payload)
    (let ((count (br-read-bounded-count stream +max-inv-count+ "inv/getdata")))
      (loop repeat count collect (read-inv-vector stream)))))

(defun parse-headers-payload (payload)
  "Parse a headers message payload into a list of block headers."
  (with-byte-reader (stream payload)
    (let ((count (br-read-bounded-count stream +max-headers-count+ "headers")))
      (loop repeat count
            collect (prog1 (br-read-block-header stream)
                      ;; Headers message includes tx count (always 0) after each header
                      (br-read-compact-size stream))))))

(defun parse-block-locator-payload (payload)
  "Parse a getheaders or getblocks payload: a 4-byte protocol version, a
bounded block-locator hash list (most-recent-first), and a 32-byte stop hash.
Returns (VALUES locator-hashes stop-hash). A locator longer than
+max-locator-count+ signals an error (the caller disconnects the peer)."
  (with-byte-reader (stream payload)
    (br-read-u32-le stream)             ; protocol version (unused)
    (let* ((count (br-read-bounded-count stream +max-locator-count+ "block locator"))
           (hashes (loop repeat count collect (br-read-bytes stream 32)))
           (stop-hash (br-read-bytes stream 32)))
      (values hashes stop-hash))))

(defun parse-block-payload (payload)
  "Parse a block message payload into a bitcoin-block.

Hot path: called once per block message received from peers (potentially
thousands per minute during IBD). Uses byte-reader for direct index-based
reads instead of Gray-stream input dispatch."
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
(define-message-field-type :short-txid (unsigned-byte 48)
  (read-short-txid br) (write-short-txid bb value))

(define-message compact-block
    (:documentation "BIP 152 compact block (HeaderAndShortIDs).")
  (header :block-header)
  (nonce :u64)                            ; random nonce for short ID generation
  (short-ids (:list :short-txid :max +max-block-tx-count+ :name "compact-block short-ids"))
  ;; Prefilled transactions carry DIFFERENTIAL indexes (each index is the gap
  ;; from the previous absolute index, minus one) and, per BIP152 v2, are
  ;; serialized WITH witness (Core PrefilledTransaction, blockencodings.h:80):
  ;; the one transaction we ever prefill is the coinbase, whose witness
  ;; carries the BIP141 reserved value, and emitting it stripped makes every
  ;; reconstruction fail bad-witness-nonce-size. br-read-transaction
  ;; auto-detects the BIP144 marker, so the reading side is symmetric.
  (prefilled-txs :custom :slot-type list
    :read (let ((last-index -1))
            (loop repeat (br-read-bounded-count br +max-block-tx-count+ "compact-block prefilled")
                  collect (let* ((diff-index (br-read-compact-size br))
                                 (abs-index (+ last-index diff-index 1))
                                 (tx (br-read-transaction br)))
                            (setf last-index abs-index)
                            (make-prefilled-tx :index abs-index :transaction tx))))
    :write (let ((last-index -1))
             (bb-write-varint bb (length value))
             (dolist (ptx value)
               (let ((abs-index (prefilled-tx-index ptx)))
                 (bb-write-varint bb (- abs-index last-index 1))
                 (bb-write-bytes bb (serialize-witness-transaction (prefilled-tx-transaction ptx)))
                 (setf last-index abs-index))))))


;;; Block transactions request (getblocktxn)
(define-message block-txn-request
    (:documentation "BIP 152 block transactions request (getblocktxn).")
  (block-hash :hash256)
  ;; absolute indexes, DIFFERENTIALLY encoded on the wire (gap minus one)
  (indexes :custom :slot-type list
    :read (let ((last-index -1))
            (loop repeat (br-read-bounded-count br +max-block-tx-count+ "getblocktxn indexes")
                  collect (let ((abs-index (+ last-index (br-read-compact-size br) 1)))
                            (setf last-index abs-index)
                            abs-index)))
    :write (let ((last-index -1))
             (bb-write-varint bb (length value))
             (dolist (idx value)
               (bb-write-varint bb (- idx last-index 1))
               (setf last-index idx)))))


;;; Block transactions response (blocktxn)
(define-message block-txn-response
    (:documentation "BIP 152 block transactions response (blocktxn).")
  (block-hash :hash256)
  (transactions (:list :transaction :max +max-block-tx-count+ :name "blocktxn transactions")))


;;; Read/write 6-byte short txid (little-endian)
(defun read-short-txid (stream)
  "Read a 6-byte short transaction ID from STREAM as a 48-bit integer."
  (let ((result 0))
    (dotimes (i 6)
      (setf result (logior result (ash (br-read-u8 stream) (* i 8)))))
    result))

(defun write-short-txid (stream short-id)
  "Write a 6-byte short transaction ID to STREAM."
  (dotimes (i 6)
    (bb-write-u8 stream (logand (ash short-id (- (* i 8))) #xff))))

;;; Parse sendcmpct message
(defun parse-sendcmpct-payload (payload)
  "Parse a sendcmpct message payload.
   Returns (VALUES announce-flag version)."
  (with-byte-reader (stream payload)
    (let ((announce (br-read-u8 stream))
          (version (br-read-u64-le stream)))
      (values (= announce 1) version))))

;;; Make sendcmpct message
(defun make-sendcmpct-message (high-bandwidth version)
  "Create a sendcmpct message.
   HIGH-BANDWIDTH is T for high-bandwidth mode, NIL for low-bandwidth.
   VERSION is 1 or 2."
  (let ((payload (with-byte-buf (stream)
                   (bb-write-u8 stream (if high-bandwidth 1 0))
                   (bb-write-u64-le stream version))))
    (serialize-message "sendcmpct" payload)))

;;; Read compact block
;;; Write compact block
(defun build-compact-block (block &key (nonce (random (expt 2 64))))
  "BLOCK as a BIP152 HeaderAndShortIDs (Core CBlockHeaderAndShortTxIDs,
blockencodings.cpp:17-38): the header, a nonce, the coinbase prefilled at index
0, and a 6-byte short ID for every other transaction, keyed by SipHash-2-4 over
the header bytes and the nonce. Version 2, so the ids are over WTXIDs (BIP152
+ BIP141) — which is the only version we negotiate."
  (let* ((header (bitcoin-block-header block))
         (txs (bitcoin-block-transactions block))
         ;; The same writer the RECEIVE path keys off (protocol.lisp's
         ;; reconstruct-compact-block), so the two sides cannot derive
         ;; different SipHash keys for the same header.
         (header-bytes (serialize-block-header header)))
    (multiple-value-bind (k0 k1)
        (bl.crypto:compute-siphash-key header-bytes nonce)
      (make-compact-block
       :header header
       :nonce nonce
       :short-ids (loop for tx in (rest txs)
                        collect (bl.crypto:compute-short-txid
                                 k0 k1 (transaction-wtxid tx)))
       ;; Core prefills the coinbase only: a peer's mempool never holds it, so
       ;; without it every reconstruction would need a getblocktxn round trip.
       :prefilled-txs (list (make-prefilled-tx :index 0 :transaction (first txs)))))))

(defun make-cmpctblock-message (block &key (nonce (random (expt 2 64))))
  "A cmpctblock message carrying BLOCK as a BIP152 compact block."
  (let ((payload (with-byte-buf (stream)
                   (write-compact-block stream
                                        (build-compact-block block :nonce nonce)))))
    (serialize-message "cmpctblock" payload)))

;;; Parse cmpctblock payload
(defun parse-cmpctblock-payload (payload)
  "Parse a cmpctblock message payload into a compact-block."
  (with-byte-reader (stream payload)
    (read-compact-block stream)))

;;; Read block transactions request
;;; Write block transactions request
;;; Make getblocktxn message
(defun make-getblocktxn-message (block-hash indexes)
  "Create a getblocktxn message.
   BLOCK-HASH is the 32-byte block hash.
   INDEXES is a list of absolute transaction indexes to request."
  (let ((payload (with-byte-buf (stream)
                   (write-block-txn-request
                    stream
                    (make-block-txn-request :block-hash block-hash
                                            :indexes indexes)))))
    (serialize-message "getblocktxn" payload)))

;;; Parse getblocktxn payload
(defun parse-getblocktxn-payload (payload)
  "Parse a getblocktxn message payload."
  (with-byte-reader (stream payload)
    (read-block-txn-request stream)))

;;; Read block transactions response
;;; Write block transactions response
;;; Parse blocktxn payload
(defun parse-blocktxn-payload (payload)
  "Parse a blocktxn message payload."
  (with-byte-reader (stream payload)
    (read-block-txn-response stream)))

;;; Make blocktxn message (BIP152 serve side)
(defun make-blocktxn-message (block-hash txs &key witness)
  "Create a blocktxn message answering a getblocktxn: BLOCK-HASH followed by the
requested TXS (a list) in order. With :WITNESS, each tx that carries witness data
is BIP144 witness-serialized — a witness compact-block reconstruction needs it;
non-witness txs stay legacy either way, matching Core's TX_WITH_WITNESS. (The
older write-block-txn-response is legacy-only and unsuitable for witness serving.)"
  (let ((payload (with-byte-buf (stream)
                   (bb-write-hash256 stream block-hash)
                   (bb-write-varint stream (length txs))
                   (dolist (tx txs)
                     (if (and witness (transaction-has-witness-p tx))
                         (bb-write-bytes stream (serialize-witness-transaction tx))
                         (bb-write-bytes stream (serialize-transaction tx)))))))
    (serialize-message "blocktxn" payload)))

;;; Addr (v1) message building

(defun make-addr-message (addrs-with-timestamps)
  "Create a serialized addr (v1) message from ADDRS-WITH-TIMESTAMPS.
Each entry is a list (net-addr timestamp)."
  (let ((payload
          (with-byte-buf (stream)
            (bb-write-varint stream (length addrs-with-timestamps))
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
      (internal-error "network-bip155-id: unknown network ~S" network)))

;;; Deserialization

(alexandria:define-constant +torv2-in-ipv6-prefix+ #(#xFD #x87 #xD8 #x7E #xEB #x43)
  :test #'equalp :documentation "Prefix of the dead TORv2-embedded-in-IPv6 form (Core TORV2_IN_IPV6_PREFIX).")

(alexandria:define-constant +internal-in-ipv6-prefix+ #(#xFD #x6B #x88 #xC0 #x87 #x24)
  :test #'equalp :documentation "Prefix of Core's NET_INTERNAL-embedded-in-IPv6 form (0xFD + sha256(\"bitcoin\")[0:5]).")

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
  (let* ((timestamp (br-read-u32-le stream))
         ;; services is a BIP155 CompactSize-encoded u64 BITMASK, not a
         ;; length — Core deserializes it with CompactSizeFormatter<false>
         ;; (protocol.h:446), i.e. NO range check. The default cap here
         ;; (+max-compact-size+) made us treat any peer advertising a
         ;; service bit >= 26 as malformed and disconnect it; exposed in
         ;; production when the getaddr fetch started soliciting 1000-entry
         ;; addrv2 replies on mainnet (2026-07-12).
         (services (br-read-compact-size stream :range-check nil))
         (network-id (br-read-u8 stream))
         (addr-len (br-read-compact-size stream)))
    (when (> addr-len +max-addrv2-address-size+)
      (serialization-error "addrv2 address too long: ~D > ~D" addr-len +max-addrv2-address-size+))
    (let ((expected-len (gethash network-id *addrv2-addr-sizes*)))
      ;; A recognized network with the wrong length is a stream failure in
      ;; Core (SetNetFromBIP155Network throws) — the entire message is bad.
      (when (and expected-len (/= addr-len expected-len))
        (serialization-error "BIP155 network ~D address with length ~D (should be ~D)"
               network-id addr-len expected-len))
      ;; Read address bytes + port regardless (to advance stream position)
      (let* ((addr-bytes (br-read-bytes stream addr-len))
             (port-high (br-read-u8 stream))
             (port-low (br-read-u8 stream))
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
  (bb-write-u32-le stream timestamp)
  ;; Services (compact-size)
  (bb-write-varint stream (net-addr-services addr))
  ;; Network ID
  (bb-write-u8 stream network-id)
  ;; Address bytes (network-dependent)
  (let ((ip (net-addr-ip addr)))
    (flet ((emit (bytes required-len)
             (unless (= (length bytes) required-len)
               (internal-error "write-net-addr-v2: network ~D address must be ~D bytes, got ~D"
                      network-id required-len (length bytes)))
             (bb-write-varint stream required-len)
             (bb-write-bytes stream bytes)))
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
         (internal-error "write-net-addr-v2: unsupported network ID ~D" network-id)))))
  ;; Port (big-endian)
  (bb-write-u8 stream (ash (net-addr-port addr) -8))
  (bb-write-u8 stream (logand (net-addr-port addr) #xFF)))

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
  (let ((payload (with-byte-buf (stream)
                   (bb-write-u32-le stream version)
                   (bb-write-u64-le stream salt))))
    (serialize-message "sendtxrcncl" payload)))

(defconstant +recon-q-precision+ 32768
  "Fixed-point denominator for the q parameter of reqrecon.

BIP-330 sends q as a 16-bit integer; this is the scale it is read at. Chosen
rather than ported: Core has no reqrecon at all, so there is no implementation
to match. Anything that ever talks to another node must agree on this number,
which is why it is a named constant and not a literal.")

(defun make-reqrecon-message (set-size q)
  "BIP-330 reqrecon: uint32 SET-SIZE + uint16 Q, both LE.

The initiator tells the responder how many transactions it is holding for this
link, and how much of the smaller set it guesses the two sides do not share.
Those two numbers are all the responder needs to size a sketch."
  (let ((payload (with-byte-buf (stream)
                   (bb-write-u32-le stream set-size)
                   (bb-write-u16-le stream
                                    (min #xFFFF
                                         (round (* q +recon-q-precision+)))))))
    (serialize-message "reqrecon" payload)))

(defun parse-reqrecon-payload (payload)
  "Returns (VALUES set-size q), q as a rational in [0, 2)."
  (with-byte-reader (stream payload)
    (let ((set-size (br-read-u32-le stream))
          (q-raw (br-read-u16-le stream)))
      (values set-size (/ q-raw +recon-q-precision+)))))

(defun make-sketch-message (sketch-bytes)
  "BIP-330 sketch: the serialized sketch, and nothing else. Its length divided
by the field size is the capacity, so no count is sent."
  (serialize-message "sketch" sketch-bytes))

(defun parse-sketch-payload (payload)
  (copy-seq payload))

(defun make-reqsketchext-message ()
  "BIP-330 reqsketchext: empty. The initiator failed to decode and is asking
for the SECOND HALF of a double-capacity sketch — only the half it does not
have, since sketches extend rather than being resent."
  (serialize-message "reqsketchext" (make-array 0 :element-type '(unsigned-byte 8))))

(defun make-reconcildiff-message (success short-ids)
  "BIP-330 reconcildiff: uint8 SUCCESS + a vector of uint32 short IDs.

SUCCESS says whether the initiator decoded the difference. When it did,
SHORT-IDS are the ones it is missing and wants announced. When it did not, the
list is empty and both sides fall back to announcing their whole sets — the
flood fallback, which is why a failed reconciliation costs bandwidth but never
transactions."
  (let ((payload (with-byte-buf (stream)
                   (bb-write-u8 stream (if success 1 0))
                   (bb-write-varint stream (length short-ids))
                   (dolist (id short-ids)
                     (bb-write-u32-le stream id)))))
    (serialize-message "reconcildiff" payload)))

(defun parse-reconcildiff-payload (payload)
  "Returns (VALUES success-p short-ids)."
  (with-byte-reader (stream payload)
    (let* ((success (plusp (br-read-u8 stream)))
           (count (br-read-compact-size stream))
           (ids (loop repeat count collect (br-read-u32-le stream))))
      (values success ids))))

(defun parse-sendtxrcncl-payload (payload)
  "Parse a sendtxrcncl message payload (BIP 330).
Returns (VALUES version salt)."
  (with-byte-reader (stream payload)
    (values (br-read-u32-le stream)
            (br-read-u64-le stream))))

(defun parse-feefilter-payload (payload)
  "Parse a feefilter message payload (BIP 133). Returns fee rate as uint64 (sat/kB)."
  (with-byte-reader (stream payload)
    (br-read-u64-le stream)))

(defun make-feefilter-message (fee-rate)
  "Create a feefilter message with FEE-RATE in satoshis per 1000 bytes (BIP 133)."
  (let ((payload (with-byte-buf (stream)
                   (bb-write-u64-le stream fee-rate))))
    (serialize-message "feefilter" payload)))

(defun make-addrv2-message (entries)
  "Create a serialized addrv2 message from ENTRIES.
Each entry is a list (net-addr network-id timestamp)."
  (let ((payload
          (with-byte-buf (stream)
            (bb-write-varint stream (length entries))
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
  (with-byte-reader (stream payload)
    (let ((count (br-read-bounded-count stream +max-addr-count+ "addrv2"))
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
  (let ((payload (with-byte-buf (s)
                   (bb-write-u8 s filter-type)
                   (bb-write-bytes s block-hash)
                   (bb-write-varint s (length filter-bytes))
                   (bb-write-bytes s filter-bytes))))
    (serialize-message "cfilter" payload)))

(defun make-cfheaders-message (filter-type stop-hash prev-header filter-hashes)
  "Build a cfheaders message: filter_type (u8), stop_hash (32), previous filter
header (32), then the vector of per-block filter HASHES (32 each)."
  (let ((payload (with-byte-buf (s)
                   (bb-write-u8 s filter-type)
                   (bb-write-bytes s stop-hash)
                   (bb-write-bytes s prev-header)
                   (bb-write-varint s (length filter-hashes))
                   (dolist (h filter-hashes)
                     (bb-write-bytes s h)))))
    (serialize-message "cfheaders" payload)))

(defun make-cfcheckpt-message (filter-type stop-hash headers)
  "Build a cfcheckpt message: filter_type (u8), stop_hash (32), then the filter
HEADERS at each 1000-block checkpoint (32 each)."
  (let ((payload (with-byte-buf (s)
                   (bb-write-u8 s filter-type)
                   (bb-write-bytes s stop-hash)
                   (bb-write-varint s (length headers))
                   (dolist (h headers)
                     (bb-write-bytes s h)))))
    (serialize-message "cfcheckpt" payload)))
