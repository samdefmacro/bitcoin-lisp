(in-package #:bitcoin-lisp.networking)

;;; BIP324 v2 encrypted transport
;;;
;;; Mirrors Bitcoin Core's V2Transport (net.{h,cpp}), reshaped for this
;;; codebase's blocking-stream model: where Core drives per-byte state
;;; machines from its poll loop, our handshake runs as a sequence of blocking
;;; reads on the connection, and the packet layer slots in at the
;;; send-message / receive-message seam in peer.lisp. The byte primitives
;;; (send-bytes / receive-bytes) are shared with v1 untouched.
;;;
;;; Handshake (initiator):  send ellswift-key || garbage
;;;                         recv their 64-byte key        (silence -> v1 retry)
;;;                         send garbage-terminator || version packet
;;;                         scan their garbage for their terminator
;;;                         recv packets until their version packet
;;; Handshake (responder):  recv 16 bytes; v1 prefix -> v1 (bytes pushed back)
;;;                         else it's the start of their key: recv 48 more
;;;                         send key || garbage || terminator || version packet
;;;                         scan garbage, recv version packet as initiator does
;;;
;;; The whole handshake shares ONE absolute deadline, so a peer that trickles
;;; bytes (or a stream of decoys) cannot pin the accept/sync thread past the
;;; timeout. The first packet received after the peer's garbage terminator
;;; authenticates that garbage as AAD; decoy packets (IGNORE bit) are skipped.
;;; Everything is gated on *v2-transport-enabled* plus the ellswift module
;;; being present in libsecp256k1.

(defvar *v2-transport-enabled* nil
  "T when this node offers/accepts the BIP324 v2 transport (start-node
:v2transport flag). Requires libsecp256k1 with the ellswift module; probed
per-connection so a build without it degrades to v1 silently.")

(defparameter *v2-empty-bytes*
  (make-array 0 :element-type '(unsigned-byte 8))
  "Shared empty byte vector (the crypto layer's typed paths reject #()).")

(defconstant +v2-max-garbage-len+ 4095
  "Maximum garbage length either side may send before its terminator.")

(defconstant +v1-prefix-len+ 16
  "Bytes of network magic + command a responder compares to decide v1 vs v2.")

(defparameter *v2-message-ids*
  #("" "addr" "block" "blocktxn" "cmpctblock" "feefilter" "filteradd"
    "filterclear" "filterload" "getblocks" "getblocktxn" "getdata"
    "getheaders" "headers" "inv" "mempool" "merkleblock" "notfound"
    "ping" "pong" "sendcmpct" "tx" "getcfilters" "cfilter" "getcfheaders"
    "cfheaders" "getcfcheckpt" "cfcheckpt" "addrv2")
  "BIP324 1-byte message type IDs, index = ID (Core net.cpp V2_MESSAGE_IDS).
ID 0 means a 12-byte v1-style type follows.")

(defstruct v2-transport
  "Per-connection BIP324 session state. Attached to a connection's TRANSPORT
slot once the handshake completes; its presence is what routes message I/O
through the v2 packet layer."
  (cipher nil)
  ;; The peer's garbage: AAD for the first packet we receive, then cleared.
  (recv-aad nil)
  ;; Serializes encrypt+write as one unit: the sync thread and RPC-thread
  ;; senders (ping, getblockfrompeer) share a connection, and the packet
  ;; cipher's nonce advances per encryption -- wire order must equal encrypt
  ;; order or the peer's Poly1305 check fails. (send-bytes' own lock only
  ;; makes each write atomic, not the encrypt+write pair.)
  (send-lock (bt:make-lock "v2-send")))

;;; --- deadlines ---

(defun %v2-deadline (seconds)
  "Absolute internal-real-time deadline SECONDS from now."
  (+ (get-internal-real-time) (* seconds internal-time-units-per-second)))

(defun %v2-remaining (deadline)
  "Seconds left until DEADLINE (never negative)."
  (max 0 (/ (- deadline (get-internal-real-time)) internal-time-units-per-second)))

(defun %v2-read (conn count deadline)
  "receive-bytes bounded by the shared handshake DEADLINE."
  (receive-bytes conn count :timeout (%v2-remaining deadline)))

;;; --- key material ---

(defun %v2-generate-privkey ()
  "A uniformly random valid secp256k1 secret key."
  (loop for candidate = (ironclad:random-data 32)
        when (bitcoin-lisp.crypto:valid-private-key-p candidate)
          return candidate))

(defun %v2-v1-prefix ()
  "The 16 bytes a v1 connection necessarily starts with: network magic
followed by the zero-padded \"version\" command."
  (let ((prefix (make-array +v1-prefix-len+ :element-type '(unsigned-byte 8)
                                            :initial-element 0)))
    (replace prefix bitcoin-lisp.serialization:*network-magic*)
    (replace prefix (bitcoin-lisp.serialization:command-to-bytes "version")
             :start1 4 :end2 (- +v1-prefix-len+ 4))
    prefix))

;;; --- Packet layer ---

(defconstant +v2-max-contents-len+ (+ 1 12 4000000)
  "Largest valid packet contents (Core MAX_CONTENTS_LEN: type marker +
12-byte long type + MAX_PROTOCOL_MESSAGE_LENGTH payload).")

(defun %v2-send-packet (conn transport contents aad ignore)
  "Encrypt CONTENTS into a v2 packet and write it, holding the transport send
lock so encrypt+write is atomic (see the SEND-LOCK slot). Returns T on
success."
  (bt:with-lock-held ((v2-transport-send-lock transport))
    (let ((packet (bitcoin-lisp.crypto:bip324-cipher-encrypt
                   (v2-transport-cipher transport) contents aad ignore)))
      (and (send-bytes conn packet) t))))

(defun %v2-recv-packet (conn transport deadline)
  "Read and decrypt one v2 packet, skipping decoys, bounded by DEADLINE. The
transport's pending RECV-AAD (the peer's garbage) is consumed by the first
successfully-decrypted packet, decoy or not. Returns (values contents ignore)
for the first non-decoy packet, or NIL on timeout, oversize, or
authentication failure. Any protocol violation, or any read failure AFTER the
length descriptor has advanced the receive cipher, marks the connection dead:
the cipher stream is then unrecoverable, so the connection must not linger as
a zombie (Core CloseConnection)."
  (loop
    (let ((len3 (%v2-read conn bitcoin-lisp.crypto:+bip324-length-len+ deadline)))
      (unless len3 (return nil))
      (let ((len (bitcoin-lisp.crypto:bip324-cipher-decrypt-length
                  (v2-transport-cipher transport) len3)))
        (when (> len +v2-max-contents-len+)
          (bitcoin-lisp:log-warn "V2 transport: packet too large (~D bytes) from ~A, disconnecting"
                                 len (connection-host conn))
          (setf (connection-connected conn) nil)
          (return nil))
        (let ((rest (%v2-read conn (+ len bitcoin-lisp.crypto:+bip324-header-len+
                                      bitcoin-lisp.crypto:+poly1305-taglen+)
                              deadline)))
          ;; The length cipher already advanced; a partial/timed-out body read
          ;; leaves the stream and cipher desynced -- fatal.
          (unless rest
            (setf (connection-connected conn) nil)
            (return nil))
          (multiple-value-bind (contents ignore)
              (bitcoin-lisp.crypto:bip324-cipher-decrypt
               (v2-transport-cipher transport) rest
               (or (v2-transport-recv-aad transport) *v2-empty-bytes*))
            (unless contents
              (bitcoin-lisp:log-warn "V2 transport: packet auth failure from ~A, disconnecting"
                                     (connection-host conn))
              (setf (connection-connected conn) nil)
              (return nil))
            ;; AAD (the peer's garbage) is authenticated by the first packet.
            (setf (v2-transport-recv-aad transport) nil)
            (unless ignore
              (return (values contents nil)))))))))

(defun v2-send-message (conn transport message-bytes)
  "Send a v1-FRAMED message over the v2 transport: strip the v1 envelope the
message builders produce (magic, 12-byte command, length, checksum) and remap
to BIP324 contents (short ID byte, or 0x00 + the 12 type bytes verbatim,
followed by the payload). Returns T on success."
  (let* ((command (bitcoin-lisp.serialization:bytes-to-command
                   (subseq message-bytes 4 16)))
         (payload-len (- (length message-bytes) 24))
         (short-id (position command *v2-message-ids* :test #'equal))
         (contents (make-array (+ (if short-id 1 13) payload-len)
                               :element-type '(unsigned-byte 8)
                               :initial-element 0)))
    (if short-id
        (setf (aref contents 0) short-id)
        (replace contents message-bytes :start1 1 :start2 4 :end2 16))
    (replace contents message-bytes :start1 (if short-id 1 13) :start2 24)
    (%v2-send-packet conn transport contents *v2-empty-bytes* nil)))

(defun v2-receive-message (conn transport &key (timeout 30))
  "Receive one application message over the v2 transport. Returns
(values command payload) like the v1 receive path, or NIL on failure
(including an invalid message type encoding, which Core also rejects)."
  (multiple-value-bind (contents ignore)
      (%v2-recv-packet conn transport (%v2-deadline timeout))
    (declare (ignore ignore))
    (when (and contents (plusp (length contents)))
      (let ((first-byte (aref contents 0)))
        (cond ((and (plusp first-byte) (< first-byte (length *v2-message-ids*)))
               (values (aref *v2-message-ids* first-byte) (subseq contents 1)))
              ((and (zerop first-byte) (>= (length contents) 13))
               ;; Long form: 12 bytes, ASCII up to the first NUL, NULs after.
               (let* ((type-end (or (position 0 contents :start 1 :end 13) 13))
                      (command (map 'string #'code-char
                                    (subseq contents 1 type-end))))
                 (when (and (loop for i from 1 below type-end
                                  always (<= 32 (aref contents i) 127))
                            (loop for i from type-end below 13
                                  always (zerop (aref contents i))))
                   (values command (subseq contents 13))))))))))

;;; --- Handshake ---

(defun %v2-make-session ()
  "Fresh key material for one connection attempt: (values cipher garbage)."
  (let* ((privkey (%v2-generate-privkey))
         (cipher (bitcoin-lisp.crypto:make-bip324-cipher
                  privkey :entropy32 (ironclad:random-data 32)))
         ;; Uniform garbage length in [0, 4095].
         (garbage-len (mod (bitcoin-lisp.crypto:bytes-to-uint64-le
                            (ironclad:random-data 8))
                           (1+ +v2-max-garbage-len+)))
         (garbage (ironclad:random-data garbage-len)))
    (values cipher garbage)))

(defun %v2-scan-garbage (conn cipher deadline)
  "Consume the peer's garbage up to and including its garbage terminator.
Returns the garbage bytes (terminator excluded) or NIL if no terminator
appears within the 4095+16 byte bound (or the DEADLINE passes)."
  (let ((terminator (bitcoin-lisp.crypto:bip324-cipher-recv-garbage-terminator
                     cipher))
        (term-len bitcoin-lisp.crypto:+bip324-garbage-terminator-len+)
        (head (%v2-read conn bitcoin-lisp.crypto:+bip324-garbage-terminator-len+
                        deadline)))
    (unless head (return-from %v2-scan-garbage nil))
    (let ((buf (make-array term-len :element-type '(unsigned-byte 8)
                                    :adjustable t :fill-pointer term-len
                                    :initial-contents head)))
      (loop
        (let ((n (fill-pointer buf)))
          (when (not (mismatch terminator buf :start2 (- n term-len)))
            (return (subseq buf 0 (- n term-len))))
          (when (>= n (+ +v2-max-garbage-len+ term-len))
            (bitcoin-lisp:log-warn "V2 transport: missing garbage terminator from ~A"
                                   (connection-host conn))
            (return nil))
          (let ((next (%v2-read conn 1 deadline)))
            (unless next (return nil))
            (vector-push-extend (aref next 0) buf)))))))

(defun %v2-finish-handshake (conn cipher garbage deadline)
  "Common tail of both roles, after the ciphers are initialized and our key +
garbage are on the wire: send our terminator + version packet (authenticating
our GARBAGE as AAD), scan their garbage, and receive their version packet.
Returns the ready v2-transport or NIL."
  (let ((terminator+version
          (concatenate '(simple-array (unsigned-byte 8) (*))
                       (bitcoin-lisp.crypto:bip324-cipher-send-garbage-terminator
                        cipher)
                       (bitcoin-lisp.crypto:bip324-cipher-encrypt
                        cipher *v2-empty-bytes* garbage nil))))
    (unless (send-bytes conn terminator+version)
      (return-from %v2-finish-handshake nil))
    (let ((their-garbage (%v2-scan-garbage conn cipher deadline)))
      (unless their-garbage (return-from %v2-finish-handshake nil))
      (let ((transport (make-v2-transport :cipher cipher
                                          :recv-aad their-garbage)))
        ;; Their first non-decoy packet is version negotiation; contents are
        ;; ignored (empty today; extensions may add to it).
        (when (%v2-recv-packet conn transport deadline)
          transport)))))

(defun v2-handshake-outbound (conn &key (timeout 30))
  "Attempt the v2 handshake as initiator on a fresh outbound CONN. Returns the
ready v2-transport, :FALLBACK-V1 when the peer never responded to our key
(the BIP324 signal that it is probably a v1-only node: caller reconnects and
speaks v1), or NIL on a hard failure or shutdown."
  (let ((deadline (%v2-deadline timeout)))
    (multiple-value-bind (cipher garbage) (%v2-make-session)
      (unless (send-bytes conn
                          (concatenate '(simple-array (unsigned-byte 8) (*))
                                       (bitcoin-lisp.crypto:bip324-cipher-our-pubkey
                                        cipher)
                                       garbage))
        (return-from v2-handshake-outbound nil))
      (let ((their-key (%v2-read conn 64 deadline)))
        (unless their-key
          ;; Don't reconnect-as-v1 mid-shutdown -- receive-bytes also returns
          ;; NIL when *ibd-stop-requested* is set.
          (return-from v2-handshake-outbound
            (if (ibd-stop-requested-p) nil :fallback-v1)))
        (bitcoin-lisp.crypto:bip324-cipher-initialize
         cipher their-key t bitcoin-lisp.serialization:*network-magic*)
        (%v2-finish-handshake conn cipher garbage deadline)))))

(defun v2-detect-inbound (conn &key (timeout 15))
  "Responder-side v1/v2 detection on a fresh inbound CONN: read the first 16
bytes and compare with the v1 prefix (magic + \"version\" command). Returns
:V1 with the bytes pushed back for the v1 path, a ready v2-transport for a v2
peer, or NIL (dead peer, wrong-network v1 peer, or failed v2 handshake)."
  (let* ((deadline (%v2-deadline timeout))
         (v1-prefix (%v2-v1-prefix))
         (first16 (%v2-read conn +v1-prefix-len+ deadline)))
    (cond
      ((null first16) nil)
      ((equalp first16 v1-prefix)
       ;; v1: hand the sniffed bytes back so the v1 header read sees them.
       (setf (connection-pushback conn) first16)
       :v1)
      ;; A v1 VERSION with the wrong network magic: bytes 4..16 match the
      ;; command but the magic doesn't (else the branch above hit). Not a v2
      ;; key; log and drop (Core does the same for the logging value).
      ((not (mismatch first16 v1-prefix :start1 4 :start2 4))
       (bitcoin-lisp:log-warn "V2 transport: v1 peer with wrong network magic from ~A"
                              (connection-host conn))
       nil)
      (t
       ;; v2: FIRST16 is the start of the peer's 64-byte ellswift key.
       (let ((rest (%v2-read conn 48 deadline)))
         (when rest
           (multiple-value-bind (cipher garbage) (%v2-make-session)
             (bitcoin-lisp.crypto:bip324-cipher-initialize
              cipher
              (concatenate '(simple-array (unsigned-byte 8) (*)) first16 rest)
              nil bitcoin-lisp.serialization:*network-magic*)
             (when (send-bytes conn
                               (concatenate '(simple-array (unsigned-byte 8) (*))
                                            (bitcoin-lisp.crypto:bip324-cipher-our-pubkey
                                             cipher)
                                            garbage))
               (%v2-finish-handshake conn cipher garbage deadline)))))))))

(defun v2-available-p ()
  "T when v2 transport is enabled and the crypto backend supports it."
  (and *v2-transport-enabled*
       (bitcoin-lisp.crypto:ellswift-available-p)))
