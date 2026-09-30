(in-package #:bitcoin-lisp.tests)

;;;; Bitcoin Core reference corpora that this tree had not adopted (G7-62,
;;;; G7-65-69). Vectors extracted verbatim from Core's own test sources — the
;;;; point of a corpus is that it was not written by the implementation it
;;;; tests.

(def-suite :bitcoin-core-vector-tests
  :description "Core reference vectors: BIP32 (all five) and the SipHash table"
  :in :bitcoin-lisp-tests)

(in-suite :bitcoin-core-vector-tests)

(defun %core-vector-file (name)
  (merge-pathnames (format nil "tests/data/~A" name)
                   (asdf:system-source-directory :bitcoin-lisp)))

(defun %load-core-vectors (name)
  (with-open-file (s (%core-vector-file name))
    (yason:parse s)))

;;; --- BIP32 (G7-62): Core bip32_tests.cpp -----------------------------------
;;;
;;; We had vector 1 only. Vectors 2-5 are the ones that cover what vector 1
;;; cannot: vector 2's 0xFFFFFFFF/0xFFFFFFFE indices exercise the top of the
;;; child-index range, vector 3's leading-zero chain code is the classic
;;; serialization trap, vector 4 was added to BIP32 specifically for
;;; implementations that mishandle a leading zero in a derived private key, and
;;; vector 5 is a REJECT corpus — sixteen extended keys that must not parse.

(defun %run-bip32-vector (vec label)
  (let* ((seed (bl.crypto:hex-to-bytes (gethash "seed" vec)))
         (key (bl.crypto:bip32-master-key seed :network :mainnet)))
    (loop for step across (coerce (gethash "chain" vec) 'vector)
          for i from 0
          do (let ((want-prv (gethash "prv" step))
                   (want-pub (gethash "pub" step))
                   (child (gethash "child" step)))
               (is (string= want-prv (bl.crypto:bip32-serialize key))
                   "~A step ~D: xprv" label i)
               (is (string= want-pub
                            (bl.crypto:bip32-serialize
                             (bl.crypto:bip32-neuter key)))
                   "~A step ~D: xpub" label i)
               ;; A serialized key must also parse back to the same key — the
               ;; half a round-trip-free corpus never checks.
               (is (string= want-prv
                            (bl.crypto:bip32-serialize
                             (bl.crypto:bip32-parse want-prv)))
                   "~A step ~D: xprv does not survive parse+serialize" label i)
               ;; Derive on EVERY step, as Core's RunTest does. Guarding on a
               ;; non-zero index looks harmless and is not: vector 2's first
               ;; derivation IS child 0, so skipping it silently shifts the
               ;; whole chain by one and compares keys against the wrong step.
               (setf key (bl.crypto:bip32-derive-child key child))))))

(test bip32-core-vectors-1-through-4
  "Core bip32_tests.cpp:41-102. Vector 1 was already covered; 2, 3 and 4 are
where implementations diverge — the 0xFFFFFFFF/0xFFFFFFFE child indices, a
chain code with a leading zero, and BIP32's own vector 4, added for
implementations that mishandle a leading zero byte in a derived private key."
  ;; Core's bip32_tests runs under BasicTestingSetup, whose default chain is
  ;; ChainType::MAIN (test/util/setup_common.h:76): DecodeExtKey reads only the
  ;; running chain's prefix (key_io.cpp:272-275), so these xprv strings parse
  ;; on mainnet and nowhere else.
  (with-network (:mainnet)
    (let ((vectors (%load-core-vectors "bip32_vectors.json")))
      (dolist (name '("test1" "test2" "test3" "test4"))
        (%run-bip32-vector (gethash name vectors) name)))))

(test bip32-invalid-extended-keys-are-rejected
  "BIP32 test vector 5 (Core bip32_tests.cpp:104-122): sixteen extended keys
that are well-formed base58check and still invalid — a bad version byte, a
non-zero depth on a master key, a non-zero parent fingerprint on a master key,
a private key of zero or >= n, an invalid public key, and a bad checksum.

A reject corpus is the half that catches a permissive parser, and a permissive
xprv parser accepts keys that derive to something other than what the writer
intended."
  (with-network (:mainnet)
    (let ((invalid (gethash "invalid" (%load-core-vectors "bip32_vectors.json"))))
      (is (= 16 (length invalid)) "expected Core's sixteen invalid keys")
      (dolist (str (coerce invalid 'list))
        (is-false (ignore-errors (bl.crypto:bip32-parse str))
                  "accepted an extended key Core rejects: ~A" str)))))

;;; --- SipHash (G7-69): Core hash_tests.cpp:62-79 ----------------------------

(test siphash-matches-the-reference-table
  "The 64-entry SipHash-2-4 reference table from the SipHash paper's own
siphash24.c, by way of Core hash_tests.cpp:62-79: k = 00 01 02 ... 0f and input
= the first N bytes of 00 01 02 ... 3e, for N = 0..63.

We had only property tests — determinism, key sensitivity — which any
consistent-but-wrong implementation passes. SipHash keys the compact-block
short IDs and the addrman bucketing, so a wrong-but-consistent implementation
is a node that cannot reconstruct anyone else's compact blocks."
  (let* ((vectors (%load-core-vectors "siphash_vectors.json"))
         (k0 (parse-integer (gethash "k0" vectors) :radix 16))
         (k1 (parse-integer (gethash "k1" vectors) :radix 16))
         (outputs (coerce (gethash "outputs" vectors) 'vector)))
    (is (= 64 (length outputs)))
    (loop for n from 0 below (length outputs)
          do (let ((input (make-array n :element-type '(unsigned-byte 8))))
               (dotimes (i n) (setf (aref input i) i))
               (is (= (parse-integer (aref outputs n) :radix 16)
                      (bl.crypto:siphash-2-4 k0 k1 input))
                   "SipHash-2-4 of the first ~D bytes disagrees with the ~
                    reference table" n)))))

(test the-outpoint-siphash-is-the-siphash-of-the-outpoint-bytes
  "SIPHASH-UINT256 is Core's PresaltedSipHasher(val), SaltedTxidHasher's, and
SIPHASH-UINT256-EXTRA its PresaltedSipHasher(val, extra)
(crypto/siphash.cpp:128-165), the coins cache's SaltedOutpointHasher: equal to
the SipHash-2-4 of the 32 bytes of VAL followed by EXTRA as four little-endian
bytes. The reference table's 36-byte entry (bytes 00..23, k = 00..0f) is that
input, and Core's own check (hash_tests.cpp:133-150) compares the two hashers
on random keys, values and extras; so do we."
  (let* ((vectors (%load-core-vectors "siphash_vectors.json"))
         (k0 (parse-integer (gethash "k0" vectors) :radix 16))
         (k1 (parse-integer (gethash "k1" vectors) :radix 16))
         (want (parse-integer (aref (coerce (gethash "outputs" vectors) 'vector) 36) :radix 16))
         (rs (sb-ext:seed-random-state 20260930)))
    (flet ((words (bytes)
             (loop for w below 4
                   collect (loop for i below 8 sum (ash (aref bytes (+ (* 8 w) i)) (* 8 i))))))
      (let ((bytes (make-array 32 :element-type '(unsigned-byte 8))))
        (dotimes (i 32) (setf (aref bytes i) i))
        (is (= want (apply #'bl.bytes:siphash-uint256-extra k0 k1
                           (append (words bytes) (list #x23222120))))
            "the reference table's 36-byte entry")
        ;; PresaltedSipHasher(uint256), SaltedTxidHasher's: Core's own vector
        ;; (hash_tests.cpp:107) and the table's 32-byte entry.
        (is (= #x7127512f72f27cce
               (apply #'bl.bytes:siphash-uint256 #x0706050403020100 #x0F0E0D0C0B0A0908
                      (words bytes)))
            "hash_tests.cpp:107")
        (is (= (parse-integer (aref (coerce (gethash "outputs" vectors) 'vector) 32) :radix 16)
               (apply #'bl.bytes:siphash-uint256 k0 k1 (words bytes)))
            "the reference table's 32-byte entry"))
      (dotimes (trial 16)
        (let ((k0 (random (ash 1 64) rs)) (k1 (random (ash 1 64) rs))
              (n (random (ash 1 32) rs))
              (bytes (make-array 36 :element-type '(unsigned-byte 8))))
          (dotimes (i 32) (setf (aref bytes i) (random 256 rs)))
          (dotimes (i 4) (setf (aref bytes (+ 32 i)) (ldb (byte 8 (* 8 i)) n)))
          (is (= (bl.crypto:siphash-2-4 k0 k1 bytes)
                 (apply #'bl.bytes:siphash-uint256-extra k0 k1
                        (append (words bytes) (list n))))
              "trial ~D: the two hashers disagree" trial)
          (is (= (bl.crypto:siphash-2-4 k0 k1 (subseq bytes 0 32))
                 (apply #'bl.bytes:siphash-uint256 k0 k1 (words bytes)))
              "trial ~D: the uint256 hasher disagrees" trial))))))
