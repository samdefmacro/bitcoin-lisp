(in-package #:bitcoin-lisp.tests)

;;;; Core's cryptography targets at the pin: fuzz/crypto.cpp,
;;;; crypto_chacha20.cpp (chacha20_split_crypt, chacha20_split_keystream,
;;;; crypto_fschacha20), crypto_chacha20poly1305.cpp (both AEADs),
;;;; crypto_hkdf_hmac_sha256_l32.cpp, bip324.cpp and muhash.cpp.
;;;;
;;;; Where Core's target only exercises a primitive, the port adds the
;;;; property the primitive exists for: a one-shot hash equals the incremental
;;;; one over the same bytes, a split computation equals the whole one.

(def-suite :fuzz-crypto-tests :in :bitcoin-lisp-tests
  :description "Core fuzz crypto*.cpp / bip324.cpp / muhash.cpp targets")

(in-suite :fuzz-crypto-tests)

(defun %incremental-digest (algorithm chunks)
  (let ((d (ironclad:make-digest algorithm)))
    (dolist (c chunks (ironclad:produce-digest d))
      (ironclad:update-digest d c))))

(defun %incremental-hmac (algorithm key chunks)
  (let ((h (ironclad:make-hmac key algorithm)))
    (dolist (c chunks (ironclad:hmac-digest h))
      (ironclad:update-hmac h c))))

(defun %le-integer (bytes)
  (loop for b across bytes for i from 0 sum (ash b (* 8 i))))

(defun %concat-octets (chunks)
  (apply #'concatenate '(simple-array (unsigned-byte 8) (*)) chunks))

;;; --- crypto.cpp ------------------------------------------------------------------

(define-fuzz-target crypto
    (buffer :core "crypto.cpp:22-134" :iterations 3000 :max-len 500)
  "Every hash the node computes over data written in pieces: SHA256 through
libcrypto equals the incremental SHA256 over the same bytes; Hash256 and
Hash160 are their compositions; RIPEMD160, SHA3-256, HMAC-SHA256 (keyed by
the first data, as Core's CHMAC is) and HMAC-SHA512 equal their incremental
forms; the libsecp256k1 tagged hash equals BIP340's definition; and
SipHash-2-4 answers."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (chunks '())
         (first (let ((d (consume-random-length-byte-vector fdp)))
                  (if (plusp (length d))
                      d
                      (make-array (consume-integral-in-range fdp 1 4096)
                                  :element-type '(unsigned-byte 8)
                                  :initial-element (consume-integral fdp :u8)))))
         (k0 (consume-integral fdp :u64))
         (k1 (consume-integral fdp :u64)))
    (push first chunks)
    (limited-while ((consume-bool fdp) 30)
      (push (consume-random-length-byte-vector fdp) chunks))
    (let* ((chunks (reverse chunks))
           (data (%concat-octets chunks))
           (sha (bl.crypto:sha256 data)))
      (fuzz-assert (equalp (fuzz-sabotage sha) (%incremental-digest :sha256 chunks))
                   "SHA256 of ~D bytes in ~D pieces" (length data) (length chunks))
      (fuzz-assert (equalp (bl.crypto:hash256 data) (bl.crypto:sha256 sha)) "Hash256")
      (fuzz-assert (equalp (bl.crypto:hash160 data) (bl.crypto:ripemd160 sha)) "Hash160")
      (fuzz-assert (equalp (bl.crypto:ripemd160 data) (%incremental-digest :ripemd-160 chunks))
                   "RIPEMD160")
      (fuzz-assert (equalp (bl.crypto:sha3-256 data) (%incremental-digest :sha3/256 chunks))
                   "SHA3-256")
      (fuzz-assert (equalp (apply #'bl.crypto:hmac-sha256 first (rest chunks))
                           (%incremental-hmac :sha256 first (rest chunks)))
                   "HMAC-SHA256")
      (fuzz-assert (equalp (bl.crypto:hmac-sha512 first data)
                           (%incremental-hmac :sha512 first chunks))
                   "HMAC-SHA512")
      (let* ((tag (map 'string #'code-char (remove-if (lambda (b) (>= b 128)) first)))
             (tag-hash (bl.crypto:sha256 (flexi-streams:string-to-octets tag :external-format :utf-8))))
        (fuzz-assert (equalp (bl.crypto:tagged-hash tag data)
                             (bl.crypto:sha256 (%concat-octets (list tag-hash tag-hash data))))
                     "tagged hash ~S" tag))
      (bl.crypto:siphash-2-4 k0 k1 data))))

;;; --- crypto_chacha20.cpp ------------------------------------------------------------

(defun %chacha20-split (fdp use-crypt)
  "Core ChaCha20SplitFuzz (crypto_chacha20.cpp:48-117): the whole stream at
once, and the same stream in at most 256 input-chosen chunks -- through Crypt,
or through Keystream mixed with Crypt over zeros -- must agree. At most 20,000
bytes (Core allows a million) keeps a draw inside the budget."
  (let* ((key (let ((v (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
                (replace v (consume-bytes fdp 32))))
         (iv (consume-integral fdp :u64))
         (iv-prefix (consume-integral fdp :u32))
         (total (consume-integral-in-range fdp 0 20000))
         (seek (consume-integral-in-range fdp 0 (logandc2 #xffffffff (ash total -6)) 32))
         (crypt1 (raw-chacha20 key))
         (crypt2 (raw-chacha20 key))
         (data1 (make-array total :element-type '(unsigned-byte 8) :initial-element 0)))
    (raw-chacha20-seek crypt1 iv-prefix iv seek)
    (raw-chacha20-seek crypt2 iv-prefix iv seek)
    (when use-crypt
      (replace data1 (insecure-rand-bytes (make-insecure-random-context (consume-integral fdp :u64))
                                          total)))
    (let ((data2 (copy-seq data1)))
      (if use-crypt
          (raw-chacha20-crypt crypt1 data1 data1)
          (raw-chacha20-keystream crypt1 data1))
      (let ((done 0))
        (loop for iter from 0
              do (let* ((last (or (= iter 255) (= done total) (consume-bool fdp)))
                        (now (if last (- total done) (consume-integral-in-range fdp 0 (- total done)))))
                   (if (or use-crypt (consume-bool fdp))
                       (raw-chacha20-crypt crypt2 data2 data2 :start done :end (+ done now))
                       (raw-chacha20-keystream crypt2 data2 :start done :end (+ done now)))
                   (incf done now)
                   (when last (return))))
        (fuzz-assert (= done total) "processed ~D of ~D bytes" done total))
      (fuzz-assert (equalp data1 (fuzz-sabotage data2))
                   "~D bytes at seek ~D: the split stream differs from the whole one" total seek))))

(define-fuzz-target chacha20-split-crypt
    (buffer :core "crypto_chacha20.cpp:119-123" :iterations 2000 :max-len 400)
  "ChaCha20::Crypt over a stream in chunks equals Crypt over it at once."
  (%chacha20-split (make-fuzzed-data-provider buffer) t))

(define-fuzz-target chacha20-split-keystream
    (buffer :core "crypto_chacha20.cpp:125-129" :iterations 2000 :max-len 400)
  "ChaCha20::Keystream in chunks -- some of them Crypt over zero bytes --
equals Keystream at once."
  (%chacha20-split (make-fuzzed-data-provider buffer) nil))

(define-fuzz-target crypto-fschacha20
    (buffer :core "crypto_chacha20.cpp:131-149" :iterations 3000 :max-len 800)
  "FSChaCha20 with any key and rekey interval: a second instance under the
same key, fed the first's output chunk by chunk, gives back every chunk --
the length cipher of BIP324 stays in step across its rekeys."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (key (let ((v (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
                (replace v (consume-bytes fdp 32))))
         (interval (consume-integral-in-range fdp 1 1024 32))
         (enc (bl.crypto:make-fschacha20 (copy-seq key) interval))
         (dec (bl.crypto:make-fschacha20 (copy-seq key) interval)))
    (limited-while ((consume-bool fdp) 10000)
      (let* ((input (consume-bytes fdp (consume-integral-in-range fdp 0 4096 32)))
             (cipher (make-array (length input) :element-type '(unsigned-byte 8)))
             (plain (make-array (length input) :element-type '(unsigned-byte 8))))
        (bl.crypto:fschacha20-crypt enc input cipher)
        (bl.crypto:fschacha20-crypt dec cipher plain)
        (fuzz-assert (equalp input (fuzz-sabotage plain)) "FSChaCha20 chunk of ~D bytes" (length input))))))

;;; --- crypto_chacha20poly1305.cpp ---------------------------------------------------

(defun %aead-draw (fdp rng)
  "One packet of Core's AEAD targets: (values use-splits damage aad plain),
the lengths taken from the input and the bytes from RNG."
  (let* ((mode (consume-integral fdp :u8))
         (aad-bits (* 3 (ldb (byte 2 3) mode)))
         (aad-length (consume-integral-in-range fdp 0 (1- (ash 1 aad-bits)) 32))
         (length-bits (* 2 (ldb (byte 3 5) mode)))
         (length (consume-integral-in-range fdp 0 (1- (ash 1 length-bits)) 32)))
    (values (logbitp 0 mode) (logbitp 2 mode)
            (insecure-rand-bytes rng aad-length) (insecure-rand-bytes rng length))))

(defun %damage-bit (fdp cipher aad)
  "Flip one input-chosen bit of CIPHER or of AAD."
  (let* ((bit (consume-integral-in-range fdp 0 (1- (* 8 (+ (length cipher) (length aad)))) 32))
         (pos (ash bit -3)))
    (if (>= pos (length cipher))
        (setf (aref aad (- pos (length cipher)))
              (logxor (aref aad (- pos (length cipher))) (ash 1 (logand bit 7))))
        (setf (aref cipher pos) (logxor (aref cipher pos) (ash 1 (logand bit 7)))))))

(defun %split-at (fdp v)
  (let ((i (consume-integral-in-range fdp 1 (length v))))
    (values (subseq v 0 i) (subseq v i))))

(define-fuzz-target crypto-aeadchacha20poly1305
    (buffer :core "crypto_chacha20poly1305.cpp:16-94" :iterations 3000 :max-len 400)
  "AEAD_CHACHA20_POLY1305: decryption inverts encryption, split plaintexts
included; the ciphertext is the plaintext XOR the keystream; a key one bit
off never authenticates; and a packet or AAD with one bit flipped never
decrypts, while an undamaged one always does."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (key (let ((v (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
                (replace v (consume-bytes fdp 32))))
         (aead (raw-aead (copy-seq key)))
         (rng (make-insecure-random-context (consume-integral fdp :u64))))
    (limited-while ((consume-bool fdp) 100)
      (multiple-value-bind (use-splits damage aad plain) (%aead-draw fdp rng)
        (let* ((len (length plain))
               (cipher (make-array (+ len 16) :element-type '(unsigned-byte 8)))
               (nonce1 (%le-integer (insecure-rand-bytes rng 4)))
               (nonce2 (%le-integer (insecure-rand-bytes rng 8))))
          (if (and use-splits (plusp len))
              (multiple-value-bind (a b) (%split-at fdp plain)
                (raw-aead-encrypt aead a aad nonce1 nonce2 cipher b))
              (raw-aead-encrypt aead plain aad nonce1 nonce2 cipher))
          (let ((keystream (make-array len :element-type '(unsigned-byte 8))))
            (raw-aead-keystream aead nonce1 nonce2 keystream)
            (fuzz-assert (every (lambda (p k c) (= c (logxor p k))) plain keystream cipher)
                         "ciphertext is not plaintext XOR keystream"))
          (let* ((pos (consume-integral-in-range fdp 0 31))
                 (bad-key (copy-seq key)))
            (setf (aref bad-key pos) (logxor (aref bad-key pos) (ash 1 (logand pos 7))))
            (fuzz-assert (not (raw-aead-decrypt (raw-aead bad-key)
                                                      cipher aad nonce1 nonce2
                                                      (make-array len :element-type '(unsigned-byte 8))))
                         "a key one bit off authenticates"))
          (when damage (%damage-bit fdp cipher aad))
          (let* ((out (make-array len :element-type '(unsigned-byte 8)))
                 (ok (if (and use-splits (plusp len))
                         (let* ((i (consume-integral-in-range fdp 1 len))
                                (out2 (make-array (- len i) :element-type '(unsigned-byte 8)))
                                (out1 (make-array i :element-type '(unsigned-byte 8)))
                                (ok (raw-aead-decrypt aead cipher aad nonce1 nonce2 out1 out2)))
                           (replace out out1) (replace out out2 :start1 i)
                           ok)
                         (raw-aead-decrypt aead cipher aad nonce1 nonce2 out))))
            (fuzz-assert (eq (not ok) (fuzz-sabotage damage))
                         "~:[an undamaged~;a damaged~] packet ~:[failed~;decrypted~]" damage ok)
            (unless ok (return-from fuzz-target/crypto-aeadchacha20poly1305))
            (fuzz-assert (equalp out plain) "decryption is not the plaintext")))))))

(defun %crypt-till-rekey (aead interval encrypt)
  "Core crypt_till_rekey (crypto_chacha20poly1305.cpp:96-108): INTERVAL empty
packets, so the next real packet uses the next key."
  (let ((tag (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
        (empty (make-array 0 :element-type '(unsigned-byte 8))))
    (dotimes (i interval)
      (if encrypt
          (bl.crypto:fsaead-encrypt aead empty empty tag)
          (bl.crypto:fsaead-decrypt aead tag empty empty)))))

(define-fuzz-target crypto-fschacha20poly1305
    (buffer :core "crypto_chacha20poly1305.cpp:110-185" :iterations 1000 :max-len 400)
  "FSChaCha20Poly1305 across rekeys: a receiver one rekey behind the sender at
every packet still decrypts it; a key one bit off never authenticates; a
damaged packet never decrypts and an undamaged one always does."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (interval (consume-integral-in-range fdp 32 512))
         (key (let ((v (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
                (replace v (consume-bytes fdp 32))))
         (enc (bl.crypto:make-fschacha20poly1305 (copy-seq key) interval))
         (dec (bl.crypto:make-fschacha20poly1305 (copy-seq key) interval))
         (rng (make-insecure-random-context (consume-integral fdp :u64))))
    (limited-while ((consume-bool fdp) 100)
      (multiple-value-bind (use-splits damage aad plain) (%aead-draw fdp rng)
        (let* ((len (length plain))
               (cipher (make-array (+ len 16) :element-type '(unsigned-byte 8))))
          (%crypt-till-rekey enc interval t)
          (if (and use-splits (plusp len))
              (multiple-value-bind (a b) (%split-at fdp plain)
                (bl.crypto:fsaead-encrypt enc a aad cipher b))
              (bl.crypto:fsaead-encrypt enc plain aad cipher))
          (let* ((pos (consume-integral-in-range fdp 0 31))
                 (bad-key (copy-seq key))
                 (bad (progn (setf (aref bad-key pos) (logxor (aref bad-key pos) (ash 1 (logand pos 7))))
                             (bl.crypto:make-fschacha20poly1305 bad-key interval))))
            (%crypt-till-rekey bad interval nil)
            (fuzz-assert (not (bl.crypto:fsaead-decrypt bad cipher aad
                                                        (make-array len :element-type '(unsigned-byte 8))))
                         "a key one bit off authenticates"))
          (when damage (%damage-bit fdp cipher aad))
          (%crypt-till-rekey dec interval nil)
          (let* ((out (make-array len :element-type '(unsigned-byte 8)))
                 (ok (bl.crypto:fsaead-decrypt dec cipher aad out)))
            (fuzz-assert (eq (not ok) (fuzz-sabotage damage))
                         "~:[an undamaged~;a damaged~] packet ~:[failed~;decrypted~]" damage ok)
            (unless ok (return-from fuzz-target/crypto-fschacha20poly1305))
            (fuzz-assert (equalp out plain) "decryption is not the plaintext")))))))

;;; --- crypto_hkdf_hmac_sha256_l32.cpp -------------------------------------------

(define-fuzz-target crypto-hkdf-hmac-sha256-l32
    (buffer :core "crypto_hkdf_hmac_sha256_l32.cpp:14-27" :iterations 3000 :max-len 400)
  "HKDF-SHA256 with L=32 over any key material, salt and info is RFC 5869:
PRK = HMAC(salt, IKM), OKM = HMAC(PRK, info || 0x01)."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (ikm (consume-random-length-byte-vector fdp))
         (salt (consume-random-length-byte-vector fdp 1024))
         (prk (bl.crypto:hkdf-sha256-extract salt ikm)))
    (fuzz-assert (equalp prk (%incremental-hmac :sha256 salt (list ikm))) "HKDF extract")
    (limited-while ((consume-bool fdp) 10000)
      (let ((info (consume-random-length-byte-vector fdp 128)))
        (fuzz-assert (equalp (fuzz-sabotage (bl.crypto:hkdf-sha256-expand32 prk info))
                             (%incremental-hmac :sha256 prk (list info (%bytes 1))))
                     "HKDF expand32")))))

;;; --- bip324.cpp ------------------------------------------------------------------

(defun consume-private-key (fdp)
  "Core ConsumePrivateKey: 32 bytes, zero-filled when fewer remain."
  (let ((v (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace v (consume-bytes fdp 32))))

(define-fuzz-target bip324-cipher-roundtrip
    (buffer :core "bip324.cpp:22-126" :iterations 300 :max-len 600)
  "BIP324Cipher's two ends agree: the session id and each direction's garbage
terminator match, and every packet either side sends -- any contents length,
AAD and ignore bit -- decrypts at the other to its length, contents and
ignore bit, while a packet or AAD with one bit flipped never decrypts."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (init-key (consume-private-key fdp))
         (init-ent (consume-private-key fdp))
         (resp-key (consume-private-key fdp))
         (resp-ent (consume-private-key fdp))
         (initiator (bl.crypto:make-bip324-cipher init-key :entropy32 init-ent))
         (responder (and initiator (bl.crypto:make-bip324-cipher resp-key :entropy32 resp-ent))))
    (unless (and initiator responder) (fuzz-reject))
    (let ((magic (%bytes #xfa #xbf #xb5 #xda)))
      (bl.crypto:bip324-cipher-initialize initiator (bl.crypto:bip324-cipher-our-pubkey responder) t magic)
      (bl.crypto:bip324-cipher-initialize responder (bl.crypto:bip324-cipher-our-pubkey initiator) nil magic))
    (let ((rng (make-insecure-random-context (consume-integral fdp :u64))))
      (fuzz-assert (equalp (bl.crypto:bip324-cipher-session-id initiator)
                           (bl.crypto:bip324-cipher-session-id responder))
                   "session ids differ")
      (fuzz-assert (equalp (bl.crypto:bip324-cipher-send-garbage-terminator initiator)
                           (bl.crypto:bip324-cipher-recv-garbage-terminator responder))
                   "initiator's send terminator is not the responder's receive terminator")
      (fuzz-assert (equalp (bl.crypto:bip324-cipher-recv-garbage-terminator initiator)
                           (bl.crypto:bip324-cipher-send-garbage-terminator responder))
                   "initiator's receive terminator is not the responder's send terminator")
      (limited-while ((plusp (remaining-bytes fdp)) 1000)
        (let* ((mode (consume-integral fdp :u8))
               (ignore (logbitp 0 mode))
               (from-init (logbitp 1 mode))
               (damage (logbitp 2 mode))
               (aad (insecure-rand-bytes rng (consume-integral-in-range
                                              fdp 0 (1- (ash 1 (* 4 (ldb (byte 2 3) mode)))) 32)))
               (length (consume-integral-in-range fdp 0 (1- (ash 1 (* 2 (ldb (byte 3 5) mode)))) 32))
               (contents (insecure-rand-bytes rng length))
               (sender (if from-init initiator responder))
               (receiver (if from-init responder initiator))
               (ciphertext (bl.crypto:bip324-cipher-encrypt sender contents aad ignore)))
          (when damage (%damage-bit fdp ciphertext aad))
          (let ((dec-length (bl.crypto:bip324-cipher-decrypt-length receiver (subseq ciphertext 0 3))))
            (if damage
                (progn
                  (when (> dec-length (+ 16384 length)) (return-from fuzz-target/bip324-cipher-roundtrip))
                  (setf ciphertext (let ((v (make-array (+ dec-length 20) :element-type '(unsigned-byte 8)
                                                                          :initial-element 0)))
                                     (replace v ciphertext))))
                (fuzz-assert (= dec-length length) "decrypted length ~D of ~D" dec-length length))
            (multiple-value-bind (decrypted dec-ignore)
                (bl.crypto:bip324-cipher-decrypt receiver (subseq ciphertext 3) aad)
              (fuzz-assert (eq (null decrypted) (fuzz-sabotage damage))
                           "~:[an undamaged~;a damaged~] packet ~:[failed~;decrypted~]" damage decrypted)
              (unless decrypted (return-from fuzz-target/bip324-cipher-roundtrip))
              (fuzz-assert (eq ignore dec-ignore) "the ignore bit did not survive")
              (fuzz-assert (equalp decrypted contents) "the contents did not survive"))))))))

;;; --- muhash.cpp ---------------------------------------------------------------------

(defparameter +muhash-initial-state-hash+
  "dd5ad2a105c2d29495f577245c357409002329b9f4d6182c0af3dc2f462555c8"
  "muhash.cpp:67: the finalized empty MuHash3072, as uint256's hex (bytes reversed).")

(define-fuzz-target muhash
    (buffer :core "muhash.cpp:60-104" :iterations 2000 :max-len 300)
  "MuHash3072 is a set hash: insertion order does not matter, multiplying
into the empty state changes nothing, dividing by itself and removing what
was inserted both give back the empty set's hash."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (data (consume-random-length-byte-vector fdp))
         (data2 (consume-random-length-byte-vector fdp))
         (mu (bl.crypto:make-muhash))
         (initial (reverse (bl.crypto:hex-to-bytes +muhash-initial-state-hash+))))
    (bl.crypto:muhash-insert mu data)
    (bl.crypto:muhash-insert mu data2)
    (multiple-value-bind (out out2)
        (call-one-of fdp
          (let ((other (bl.crypto:make-muhash)))
            (bl.crypto:muhash-insert other data2)
            (bl.crypto:muhash-insert other data)
            (values (bl.crypto:muhash-finalize mu) (bl.crypto:muhash-finalize other)))
          (let ((empty (bl.crypto:make-muhash)))
            (bl.crypto:muhash-combine empty mu)
            (values (bl.crypto:muhash-finalize mu) (bl.crypto:muhash-finalize empty)))
          (progn (bl.crypto:muhash-divide mu mu)
                 (values (bl.crypto:muhash-finalize mu) initial))
          (progn (bl.crypto:muhash-remove mu data)
                 (bl.crypto:muhash-remove mu data2)
                 (values (bl.crypto:muhash-finalize mu) initial)))
      (fuzz-assert (equalp out (fuzz-sabotage out2)) "~A /= ~A"
                   (bl.crypto:bytes-to-hex out) (bl.crypto:bytes-to-hex out2)))))
