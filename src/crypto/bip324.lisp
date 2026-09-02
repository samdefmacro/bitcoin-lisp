(in-package #:bitcoin-lisp.crypto)

;;; BIP324 cipher: the v2 transport's session crypto, composed from the
;;; ElligatorSwift ECDH (secp256k1.lisp) and the forward-secure ciphers
;;; (chacha20.lisp). Mirrors Bitcoin Core src/bip324.{h,cpp} exactly.
;;;
;;; One instance covers one connection: after the ellswift key exchange,
;;; initialize derives four forward-secure cipher keys (send/receive x
;;; length/packet), the two garbage terminators, and the session id from
;;; the ECDH secret via HKDF-SHA256 with salt "bitcoin_v2_shared_secret"
;;; || network magic. Each packet is then
;;;
;;;   [3-byte LE contents length, FSChaCha20-encrypted]
;;;   [1-byte header || contents, FSChaCha20Poly1305-encrypted, +16 tag]
;;;
;;; for a fixed EXPANSION of 20 bytes. The header's IGNORE bit marks decoy
;;; packets. The network magic is a parameter here (the transport layer owns
;;; chain params; this layer stays pure crypto).

(defconstant +bip324-session-id-len+ 32)
(defconstant +bip324-garbage-terminator-len+ 16)
(defconstant +bip324-rekey-interval+ 224)
(defconstant +bip324-length-len+ 3)
(defconstant +bip324-header-len+ 1)
(defconstant +bip324-expansion+ (+ +bip324-length-len+ +bip324-header-len+
                                   +poly1305-taglen+)
  "Total ciphertext overhead per packet: encrypted length + header + tag.")
(defconstant +bip324-ignore-bit+ #x80)
(defconstant +bip324-max-contents+ (1- (ash 1 24))
  "Largest contents length encodable in the 3-byte packet length field.")

(defstruct (bip324-cipher (:constructor %make-bip324-cipher))
  "BIP324 session cipher state (Core's BIP324Cipher). PRIVKEY is wiped by
initialize; the FS cipher slots are NIL until then."
  (privkey nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (our-pubkey nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (session-id nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (send-l nil :type (or null fschacha20))
  (send-p nil :type (or null fschacha20poly1305))
  (recv-l nil :type (or null fschacha20))
  (recv-p nil :type (or null fschacha20poly1305))
  (send-garbage-terminator nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (recv-garbage-terminator nil :type (or null (simple-array (unsigned-byte 8) (*)))))

(defun make-bip324-cipher (privkey &key entropy32 our-ell64)
  "Create a session cipher for the 32-byte PRIVKEY. OUR-ELL64 supplies a
precomputed ElligatorSwift encoding of PRIVKEY's public key (test vectors);
otherwise one is computed, mixing in ENTROPY32 if given (Core's
BIP324Cipher(key, ent32) constructor). Returns NIL if PRIVKEY is invalid."
  (let ((pub (or our-ell64 (ellswift-create privkey entropy32))))
    (when pub
      (%make-bip324-cipher :privkey (copy-seq privkey) :our-pubkey pub))))

(defun bip324-cipher-initialized-p (cipher)
  "T once initialize has derived the session keys (Core's operator bool)."
  (and (bip324-cipher-send-l cipher) t))

(defun bip324-cipher-initialize (cipher their-ell64 initiating magic
                                 &key self-decrypt)
  "Derive all session state from the ECDH secret with THEIR-ELL64, consuming
the private key. INITIATING names our role; MAGIC is the network's 4 message
start bytes (part of the HKDF salt, so cross-network sessions cannot key-
match). SELF-DECRYPT assigns the send keys to the receive slots and vice
versa (test harness use, Core's /*self_decrypt=*/true). Garbage terminators
and the session id depend only on the role, not on SELF-DECRYPT."
  (let* ((label (flexi-streams:string-to-octets "bitcoin_v2_shared_secret"
                                                :external-format :ascii))
         (salt (concatenate '(simple-array (unsigned-byte 8) (*)) label magic))
         (secret (bip324-ecdh their-ell64 (bip324-cipher-our-pubkey cipher)
                              (bip324-cipher-privkey cipher) initiating))
         (prk (hkdf-sha256-extract salt secret))
         ;; Core: bool side = (initiator != self_decrypt), i.e. XOR.
         (side (not (eq (not initiating) (not self-decrypt))))
         (i-l (hkdf-sha256-expand32 prk "initiator_L"))
         (i-p (hkdf-sha256-expand32 prk "initiator_P"))
         (r-l (hkdf-sha256-expand32 prk "responder_L"))
         (r-p (hkdf-sha256-expand32 prk "responder_P"))
         (terminators (hkdf-sha256-expand32 prk "garbage_terminators")))
    (setf (bip324-cipher-send-l cipher)
          (make-fschacha20 (if side i-l r-l) +bip324-rekey-interval+)
          (bip324-cipher-send-p cipher)
          (make-fschacha20poly1305 (if side i-p r-p) +bip324-rekey-interval+)
          (bip324-cipher-recv-l cipher)
          (make-fschacha20 (if side r-l i-l) +bip324-rekey-interval+)
          (bip324-cipher-recv-p cipher)
          (make-fschacha20poly1305 (if side r-p i-p) +bip324-rekey-interval+))
    ;; First 16 bytes are the initiator's send terminator, last 16 the
    ;; responder's -- keyed on the ROLE, not on side/self-decrypt.
    (let ((first16 (subseq terminators 0 +bip324-garbage-terminator-len+))
          (last16 (subseq terminators (- 32 +bip324-garbage-terminator-len+))))
      (setf (bip324-cipher-send-garbage-terminator cipher)
            (if initiating first16 last16)
            (bip324-cipher-recv-garbage-terminator cipher)
            (if initiating last16 first16)))
    (setf (bip324-cipher-session-id cipher) (hkdf-sha256-expand32 prk "session_id"))
    ;; Wipe key material that could re-derive the session keys.
    (fill secret 0)
    (fill prk 0)
    (fill i-l 0) (fill i-p 0) (fill r-l 0) (fill r-p 0)
    (fill (bip324-cipher-privkey cipher) 0)
    (setf (bip324-cipher-privkey cipher) nil)
    cipher))

(defun bip324-cipher-encrypt (cipher contents aad ignore)
  "Encrypt a packet: CONTENTS with the IGNORE header bit (decoy marker) and
AAD authenticated but not transmitted. Returns a fresh vector of length
(+ (length contents) 20): encrypted length || AEAD(header || contents)."
  (let* ((len (length contents))
         (output (make-array (+ len +bip324-expansion+)
                             :element-type '(unsigned-byte 8)))
         (len3 (make-array +bip324-length-len+ :element-type '(unsigned-byte 8)))
         (header (make-array +bip324-header-len+ :element-type '(unsigned-byte 8)
                             :initial-element (if ignore +bip324-ignore-bit+ 0))))
    (assert (<= len +bip324-max-contents+))
    (setf (aref len3 0) (ldb (byte 8 0) len)
          (aref len3 1) (ldb (byte 8 8) len)
          (aref len3 2) (ldb (byte 8 16) len))
    (fschacha20-crypt (bip324-cipher-send-l cipher) len3 output)
    (fsaead-encrypt (bip324-cipher-send-p cipher) header aad output
                    contents +bip324-length-len+)
    output))

(defun bip324-cipher-decrypt-length (cipher len3)
  "Decrypt the leading 3 length bytes of an incoming packet to the contents
length. Advances the receive length cipher, so call exactly once per packet."
  (assert (= (length len3) +bip324-length-len+))
  (let ((buf (make-array +bip324-length-len+ :element-type '(unsigned-byte 8))))
    (fschacha20-crypt (bip324-cipher-recv-l cipher) len3 buf)
    (logior (aref buf 0) (ash (aref buf 1) 8) (ash (aref buf 2) 16))))

(defun bip324-cipher-decrypt (cipher input aad)
  "Verify and decrypt a packet's AEAD portion (everything after the 3 length
bytes: header || contents ciphertext || tag). Returns (values contents
ignore-flag) on success, NIL on authentication failure. Advances the receive
packet cipher either way."
  (let* ((len (- (length input) +bip324-header-len+ +poly1305-taglen+))
         (header (make-array +bip324-header-len+ :element-type '(unsigned-byte 8)))
         (contents (make-array len :element-type '(unsigned-byte 8))))
    (if (fsaead-decrypt (bip324-cipher-recv-p cipher) input aad header contents)
        (values contents (logtest (aref header 0) +bip324-ignore-bit+))
        nil)))
