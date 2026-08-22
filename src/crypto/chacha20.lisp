(in-package #:bitcoin-lisp.crypto)

;;; BIP324 cipher suite: ChaCha20, FSChaCha20, AEAD-ChaCha20-Poly1305,
;;; FSChaCha20-Poly1305, and HKDF-SHA256 with 32-byte output.
;;;
;;; Mirrors Bitcoin Core src/crypto/chacha20.{h,cpp} and
;;; chacha20poly1305.{h,cpp} exactly, including Core's specific framing
;;; choices that RFC 8439 leaves open:
;;;   - the 128-bit block input is treated as a 96-bit nonce (one u32 word +
;;;     one u64 tail, both LE) plus a 32-bit block counter, and a counter
;;;     overflow carries into the first nonce word (compatible with 64/64
;;;     split implementations beyond 256 GiB);
;;;   - the forward-secure variants draw their next key from their own
;;;     keystream at Core's exact positions (FSChaCha20: the stream right
;;;     after the last output; FSChaCha20-Poly1305: block 1 at nonce
;;;     {#xFFFFFFFF, rekey-counter}).
;;;
;;; Poly1305 and HMAC-SHA256 come from ironclad (validated against the RFC
;;; 8439 / RFC 5869 vectors in tests); the ChaCha20 core is implemented here
;;; because ironclad's :chacha exposes neither Core's nonce/counter seek
;;; interface nor its buffering semantics, both of which the rekey ratchets
;;; depend on byte-for-byte.
;;;
;;; Only the forward-secure wrappers, HKDF, and the tag-length constant are
;;; exported: BIP324's cipher/transport layers consume exactly those (as in
;;; Core, where BIP324Cipher never touches the bare classes), and a public
;;; bare-AEAD surface would invite bypassing the rekey ratchets.

#+sbcl
(eval-when (:compile-toplevel :load-toplevel :execute)
  (require :sb-rotate-byte))

;;; ============================================================
;;; ChaCha20 core
;;; ============================================================

(deftype u32 () '(unsigned-byte 32))

(defconstant +chacha20-blocklen+ 64
  "ChaCha20 block length in bytes.")

(defstruct (chacha20 (:constructor %make-chacha20))
  "ChaCha20 stream cipher state (Core's ChaCha20 class: key + 32-bit block
counter + 96-bit nonce, with a one-block output buffer so callers may consume
the keystream in arbitrary-sized chunks)."
  ;; words 0-7 key, 8 block counter, 9-11 nonce (LE words, RFC 8439 layout
  ;; without the 4 constant words, exactly Core's input[12]).
  (input (make-array 12 :element-type 'u32 :initial-element 0)
         :type (simple-array (unsigned-byte 32) (12)))
  ;; Block-function working state. A struct slot rather than a
  ;; dynamic-extent local: SBCL heap-allocates DX specialized arrays, which
  ;; cost more garbage than the keystream itself (measured 80B per 64B block).
  (scratch (make-array 16 :element-type 'u32 :initial-element 0)
           :type (simple-array (unsigned-byte 32) (16)))
  (buffer (make-array +chacha20-blocklen+ :element-type '(unsigned-byte 8)
                                          :initial-element 0)
          :type (simple-array (unsigned-byte 8) (64)))
  ;; Number of unconsumed keystream bytes remaining at the END of buffer.
  (bufleft 0 :type (integer 0 64)))

(declaim (inline %u32+ %rotl32))
(defun %u32+ (a b)
  (declare (type u32 a b))
  (ldb (byte 32 0) (+ a b)))

(defun %rotl32 (x n)
  (declare (type u32 x) (type (integer 0 31) n))
  ;; sb-rotate-byte compiles to a native rotate (~20% off the block function
  ;; vs the shift/or idiom, measured).
  #+sbcl (sb-rotate-byte:rotate-byte n (byte 32 0) x)
  #-sbcl (ldb (byte 32 0) (logior (ash x n) (ash x (- n 32)))))

(defmacro %quarter-round (st a b c d)
  "In-place ChaCha quarter round on state vector ST indices A B C D."
  `(progn
     (setf (aref ,st ,a) (%u32+ (aref ,st ,a) (aref ,st ,b))
           (aref ,st ,d) (%rotl32 (logxor (aref ,st ,d) (aref ,st ,a)) 16)
           (aref ,st ,c) (%u32+ (aref ,st ,c) (aref ,st ,d))
           (aref ,st ,b) (%rotl32 (logxor (aref ,st ,b) (aref ,st ,c)) 12)
           (aref ,st ,a) (%u32+ (aref ,st ,a) (aref ,st ,b))
           (aref ,st ,d) (%rotl32 (logxor (aref ,st ,d) (aref ,st ,a)) 8)
           (aref ,st ,c) (%u32+ (aref ,st ,c) (aref ,st ,d))
           (aref ,st ,b) (%rotl32 (logxor (aref ,st ,b) (aref ,st ,c)) 7))))

(defun %chacha20-block (c)
  "Refill C's buffer with one 64-byte keystream block, then advance the block
counter, carrying into the first nonce word on overflow."
  (declare (optimize (speed 3) (safety 1)))
  (let ((input (chacha20-input c))
        (st (chacha20-scratch c))
        (out (chacha20-buffer c)))
    (declare (type (simple-array (unsigned-byte 32) (12)) input)
             (type (simple-array (unsigned-byte 32) (16)) st)
             (type (simple-array (unsigned-byte 8) (64)) out))
    ;; "expand 32-byte k"
    (setf (aref st 0) #x61707865 (aref st 1) #x3320646e
          (aref st 2) #x79622d32 (aref st 3) #x6b206574)
    (replace st input :start1 4)
    (loop repeat 10
          do (%quarter-round st 0 4 8 12)
             (%quarter-round st 1 5 9 13)
             (%quarter-round st 2 6 10 14)
             (%quarter-round st 3 7 11 15)
             (%quarter-round st 0 5 10 15)
             (%quarter-round st 1 6 11 12)
             (%quarter-round st 2 7 8 13)
             (%quarter-round st 3 4 9 14))
    ;; Add original state and serialize LE.
    (setf (aref st 0) (%u32+ (aref st 0) #x61707865)
          (aref st 1) (%u32+ (aref st 1) #x3320646e)
          (aref st 2) (%u32+ (aref st 2) #x79622d32)
          (aref st 3) (%u32+ (aref st 3) #x6b206574))
    (loop for i below 12 do (setf (aref st (+ i 4)) (%u32+ (aref st (+ i 4)) (aref input i))))
    (loop for i below 16
          for w of-type u32 = (aref st i)
          do (setf (aref out (* 4 i)) (ldb (byte 8 0) w)
                   (aref out (+ (* 4 i) 1)) (ldb (byte 8 8) w)
                   (aref out (+ (* 4 i) 2)) (ldb (byte 8 16) w)
                   (aref out (+ (* 4 i) 3)) (ldb (byte 8 24) w)))
    ;; Advance block counter; overflow carries into the first nonce word.
    (let ((ctr (%u32+ (aref input 8) 1)))
      (setf (aref input 8) ctr)
      (when (zerop ctr)
        (setf (aref input 9) (%u32+ (aref input 9) 1))))))

(defun %chacha20-run (c in out in-start in-end out-start)
  "Drive the buffered keystream over IN-END minus IN-START bytes: when IN is
non-NIL, XOR IN[i] into OUT[out-start + (i - in-start)] (en/decrypt); when IN
is NIL, write raw keystream into OUT at the same positions. IN and OUT may be
the same array only at identical offsets."
  (declare (type (or null (simple-array (unsigned-byte 8) (*))) in)
           (type (simple-array (unsigned-byte 8) (*)) out)
           (type fixnum in-start in-end out-start)
           (optimize (speed 3) (safety 1)))
  (let ((buffer (chacha20-buffer c))
        (i in-start)
        (o out-start))
    (declare (type fixnum i o))
    (loop while (< i in-end)
          do (when (zerop (chacha20-bufleft c))
               (%chacha20-block c)
               (setf (chacha20-bufleft c) +chacha20-blocklen+))
             (let* ((bufleft (chacha20-bufleft c))
                    (b (- +chacha20-blocklen+ bufleft))
                    (n (min bufleft (- in-end i))))
               (declare (type fixnum b n))
               (cond ((null in)
                      (replace out buffer :start1 o :start2 b :end2 (+ b n)))
                     ((and (zerop b) (= n +chacha20-blocklen+))
                      ;; Aligned whole block: XOR 8 bytes at a time (the byte
                      ;; loop was ~40% of 4MB-packet crypt time, measured).
                      (loop for k of-type fixnum from 0 below 64 by 8
                            do (setf (nibbles:ub64ref/le out (+ o k))
                                     (logxor (nibbles:ub64ref/le in (+ i k))
                                             (nibbles:ub64ref/le buffer k)))))
                     (t
                      (loop for k of-type fixnum below n
                            do (setf (aref out (+ o k))
                                     (logxor (aref in (+ i k))
                                             (aref buffer (+ b k)))))))
               (incf i n)
               (incf o n)
               (setf (chacha20-bufleft c) (- bufleft n)))))
  out)

(defun chacha20-set-key (c key)
  "Set the 32-byte KEY, and seek to nonce 0, block position 0."
  (declare (type (simple-array (unsigned-byte 8) (*)) key))
  (assert (= (length key) 32))
  (let ((input (chacha20-input c)))
    (loop for i below 8
          for off = (* 4 i)
          do (setf (aref input i)
                   (logior (aref key off)
                           (ash (aref key (+ off 1)) 8)
                           (ash (aref key (+ off 2)) 16)
                           (ash (aref key (+ off 3)) 24))))
    (loop for i from 8 below 12 do (setf (aref input i) 0)))
  (setf (chacha20-bufleft c) 0)
  ;; Key hygiene, mirroring Core's memory_cleanse: don't leave old-key
  ;; keystream in the buffer.
  (fill (chacha20-buffer c) 0)
  c)

(defun make-chacha20 (key)
  "Create a ChaCha20 cipher with the given 32-byte KEY (nonce 0, position 0)."
  (chacha20-set-key (%make-chacha20) key))

(defun chacha20-seek (c nonce1 nonce2 block-counter)
  "Set the 96-bit nonce (NONCE1 = u32 first word, NONCE2 = u64 last 8 bytes,
Core's Nonce96 pair) and the 32-bit BLOCK-COUNTER. Discards buffered
keystream."
  (declare (type u32 nonce1 block-counter) (type (unsigned-byte 64) nonce2))
  (let ((input (chacha20-input c)))
    (setf (aref input 8) block-counter
          (aref input 9) nonce1
          (aref input 10) (ldb (byte 32 0) nonce2)
          (aref input 11) (ldb (byte 32 32) nonce2)))
  (setf (chacha20-bufleft c) 0)
  c)

(defun chacha20-keystream (c out &key (start 0) (end (length out)))
  "Write keystream bytes into OUT[START..END)."
  (%chacha20-run c nil out start end start))

(defun chacha20-crypt (c in out &key (start 0) (end (length in)) (out-start start))
  "XOR IN[START..END) with keystream into OUT starting at OUT-START
(en/decrypt). OUT-START defaults to START, i.e. matching positions."
  (%chacha20-run c in out start end out-start))

;;; ============================================================
;;; FSChaCha20 — forward-secure stream cipher (BIP324 length cipher)
;;; ============================================================

(defstruct (fschacha20 (:constructor %make-fschacha20))
  "Forward-secure ChaCha20: rekeys itself from its own keystream every
REKEY-INTERVAL Crypt operations (Core's FSChaCha20)."
  (cipher nil :type (or null chacha20))
  (rekey-interval 0 :type u32)
  (chunk-counter 0 :type u32)
  (rekey-counter 0 :type (unsigned-byte 64)))

(defun make-fschacha20 (key rekey-interval)
  (%make-fschacha20 :cipher (make-chacha20 key) :rekey-interval rekey-interval))

(defun fschacha20-crypt (fsc in out)
  "Encrypt or decrypt a chunk. The keystream continues across calls within a
rekey section; after REKEY-INTERVAL chunks the next key is drawn from the
stream directly following the last output, and the nonce becomes
{0, rekey-counter} at block 0."
  (let ((c (fschacha20-cipher fsc)))
    (chacha20-crypt c in out)
    (when (= (incf (fschacha20-chunk-counter fsc)) (fschacha20-rekey-interval fsc))
      (let ((new-key (make-array 32 :element-type '(unsigned-byte 8))))
        (chacha20-keystream c new-key)
        (chacha20-set-key c new-key)
        (fill new-key 0))
      (chacha20-seek c 0 (incf (fschacha20-rekey-counter fsc)) 0)
      (setf (fschacha20-chunk-counter fsc) 0)))
  out)

;;; ============================================================
;;; AEAD-ChaCha20-Poly1305 (RFC 8439 section 2.8)
;;; ============================================================

(defconstant +poly1305-taglen+ 16
  "Poly1305 tag length: the AEAD's ciphertext expansion over the plaintext.")

(defparameter *aead-zero-pad*
  (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)
  "Shared read-only zero block for Poly1305's 16-byte input padding.")

(defstruct (aead-chacha20-poly1305 (:constructor %make-aead))
  "RFC 8439 AEAD_CHACHA20_POLY1305 (Core's AEADChaCha20Poly1305). The byte
scratch slots avoid per-packet allocation; one tag computation runs per
packet in each direction."
  (cipher nil :type (or null chacha20))
  (block0 (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)
          :type (simple-array (unsigned-byte 8) (64)))
  (poly-key (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
            :type (simple-array (unsigned-byte 8) (32)))
  (lengths (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)
           :type (simple-array (unsigned-byte 8) (16)))
  (expected (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)
            :type (simple-array (unsigned-byte 8) (16))))

(defun make-aead-chacha20-poly1305 (key)
  (%make-aead :cipher (make-chacha20 key)))

(defun aead-set-key (aead key)
  (chacha20-set-key (aead-chacha20-poly1305-cipher aead) key))

(defun %aead-compute-tag (aead aad cipher cipher-start cipher-end tag tag-start)
  "Poly1305 tag over AAD and CIPHER[CIPHER-START..CIPHER-END) per RFC 8439,
written to TAG[TAG-START..+16). The cipher must be seeked to the message nonce
at block 0; consumes exactly one keystream block (leaving the stream at block
1)."
  (let ((chacha (aead-chacha20-poly1305-cipher aead))
        (block0 (aead-chacha20-poly1305-block0 aead))
        (poly-key (aead-chacha20-poly1305-poly-key aead))
        (lengths (aead-chacha20-poly1305-lengths aead))
        (cipher-len (- cipher-end cipher-start)))
    (chacha20-keystream chacha block0)
    (replace poly-key block0 :end2 32)
    (let ((mac (ironclad:make-mac :poly1305 poly-key)))
      (ironclad:update-mac mac aad)
      (let ((pad (mod (- 16 (mod (length aad) 16)) 16)))
        (ironclad:update-mac mac *aead-zero-pad* :end pad))
      (ironclad:update-mac mac cipher :start cipher-start :end cipher-end)
      (let ((pad (mod (- 16 (mod cipher-len 16)) 16)))
        (ironclad:update-mac mac *aead-zero-pad* :end pad))
      (loop for i below 8
            do (setf (aref lengths i) (ldb (byte 8 (* 8 i)) (length aad))
                     (aref lengths (+ 8 i)) (ldb (byte 8 (* 8 i)) cipher-len)))
      (ironclad:update-mac mac lengths)
      (replace tag (ironclad:produce-mac mac) :start1 tag-start))))

(defun aead-encrypt (aead plain aad nonce1 nonce2 cipher &optional (plain2 nil) (out-start 0))
  "Encrypt PLAIN (optionally followed by PLAIN2) with AAD under the 96-bit
nonce (NONCE1 u32, NONCE2 u64) into CIPHER at OUT-START, which must leave
room for the plaintext plus 16 tag bytes. Returns CIPHER."
  (let* ((c (aead-chacha20-poly1305-cipher aead))
         (len1 (length plain))
         (total (+ len1 (if plain2 (length plain2) 0))))
    (assert (>= (length cipher) (+ out-start total +poly1305-taglen+)))
    (chacha20-seek c nonce1 nonce2 1)
    (chacha20-crypt c plain cipher :out-start out-start)
    (when plain2
      ;; Continue the keystream across the segment boundary, writing the
      ;; second segment directly after the first (Core's two-span Encrypt).
      (chacha20-crypt c plain2 cipher :out-start (+ out-start len1)))
    (chacha20-seek c nonce1 nonce2 0)
    (%aead-compute-tag aead aad cipher out-start (+ out-start total)
                       cipher (+ out-start total))
    cipher))

(defun aead-decrypt (aead cipher aad nonce1 nonce2 plain &optional (plain2 nil))
  "Verify and decrypt CIPHER into PLAIN (and PLAIN2 if given, continuing after
PLAIN). Returns T if the tag is valid, NIL otherwise (outputs unspecified)."
  (let* ((c (aead-chacha20-poly1305-cipher aead))
         (total (- (length cipher) +poly1305-taglen+))
         (expected (aead-chacha20-poly1305-expected aead)))
    (assert (= total (+ (length plain) (if plain2 (length plain2) 0))))
    (chacha20-seek c nonce1 nonce2 0)
    (%aead-compute-tag aead aad cipher 0 total expected 0)
    (unless (ironclad:constant-time-equal expected (subseq cipher total))
      (return-from aead-decrypt nil))
    ;; ComputeTag consumed exactly block 0; the stream is at block 1.
    (chacha20-crypt c cipher plain :end (length plain) :out-start 0)
    (when plain2
      (chacha20-crypt c cipher plain2 :start (length plain) :end total :out-start 0))
    t))

(defun aead-keystream (aead nonce1 nonce2 out)
  "Keystream bytes for this AEAD at the given nonce (skipping block 0, which
generates the Poly1305 key)."
  (let ((c (aead-chacha20-poly1305-cipher aead)))
    (chacha20-seek c nonce1 nonce2 1)
    (chacha20-keystream c out)))

;;; ============================================================
;;; FSChaCha20-Poly1305 — forward-secure AEAD (BIP324 packet cipher)
;;; ============================================================

(defstruct (fschacha20poly1305 (:constructor %make-fsaead))
  "Forward-secure AEAD: the nonce is {packet-counter, rekey-counter} and the
key ratchets from the cipher's own keystream every REKEY-INTERVAL packets
(Core's FSChaCha20Poly1305)."
  (aead nil :type (or null aead-chacha20-poly1305))
  (rekey-interval 0 :type u32)
  (packet-counter 0 :type u32)
  (rekey-counter 0 :type (unsigned-byte 64)))

(defun make-fschacha20poly1305 (key rekey-interval)
  (%make-fsaead :aead (make-aead-chacha20-poly1305 key)
                :rekey-interval rekey-interval))

(defun %fsaead-next-packet (fsa)
  (when (= (incf (fschacha20poly1305-packet-counter fsa))
           (fschacha20poly1305-rekey-interval fsa))
    (let ((new-key (make-array 32 :element-type '(unsigned-byte 8))))
      (aead-keystream (fschacha20poly1305-aead fsa)
                      #xFFFFFFFF (fschacha20poly1305-rekey-counter fsa) new-key)
      (aead-set-key (fschacha20poly1305-aead fsa) new-key)
      (fill new-key 0))
    (setf (fschacha20poly1305-packet-counter fsa) 0)
    (incf (fschacha20poly1305-rekey-counter fsa))))

(defun fsaead-encrypt (fsa plain aad cipher &optional (plain2 nil) (out-start 0))
  "Encrypt PLAIN (+ PLAIN2) with AAD into CIPHER at OUT-START (needs plaintext
length + 16 bytes of room), advancing the packet counter (and key, at the
rekey interval)."
  (aead-encrypt (fschacha20poly1305-aead fsa) plain aad
                (fschacha20poly1305-packet-counter fsa)
                (fschacha20poly1305-rekey-counter fsa)
                cipher plain2 out-start)
  (%fsaead-next-packet fsa)
  cipher)

(defun fsaead-decrypt (fsa cipher aad plain &optional (plain2 nil))
  "Verify and decrypt CIPHER into PLAIN (+ PLAIN2). Returns T on success.
Advances the packet counter regardless, mirroring Core."
  (let ((ok (aead-decrypt (fschacha20poly1305-aead fsa) cipher aad
                          (fschacha20poly1305-packet-counter fsa)
                          (fschacha20poly1305-rekey-counter fsa)
                          plain plain2)))
    (%fsaead-next-packet fsa)
    ok))

;;; ============================================================
;;; HKDF-SHA256 with 32-byte output (RFC 5869; Core's CHKDF_HMAC_SHA256_L32)
;;; ============================================================

(defun hkdf-sha256-extract (salt ikm)
  "RFC 5869 extract: PRK = HMAC-SHA256(SALT, IKM)."
  (hmac-sha256 salt ikm))

(defparameter *hkdf-one*
  (make-array 1 :element-type '(unsigned-byte 8) :initial-element 1)
  "The single 0x01 block-counter byte of HKDF-Expand's first (and, at L=32,
only) output block.")

(defun hkdf-sha256-expand32 (prk info)
  "RFC 5869 expand with L=32: OKM = HMAC-SHA256(PRK, INFO || 0x01). INFO is a
byte vector, or a string (BIP324's \"initiator_L\"-style labels)."
  (hmac-sha256 prk
               (if (stringp info)
                   (flexi-streams:string-to-octets info :external-format :ascii)
                   info)
               *hkdf-one*))
