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
  (let ((vectors (%load-core-vectors "bip32_vectors.json")))
    (dolist (name '("test1" "test2" "test3" "test4"))
      (%run-bip32-vector (gethash name vectors) name))))

(test bip32-invalid-extended-keys-are-rejected
  "BIP32 test vector 5 (Core bip32_tests.cpp:104-122): sixteen extended keys
that are well-formed base58check and still invalid — a bad version byte, a
non-zero depth on a master key, a non-zero parent fingerprint on a master key,
a private key of zero or >= n, an invalid public key, and a bad checksum.

A reject corpus is the half that catches a permissive parser, and a permissive
xprv parser accepts keys that derive to something other than what the writer
intended."
  (let ((invalid (gethash "invalid" (%load-core-vectors "bip32_vectors.json"))))
    (is (= 16 (length invalid)) "expected Core's sixteen invalid keys")
    (dolist (str (coerce invalid 'list))
      (is-false (ignore-errors (bl.crypto:bip32-parse str))
                "accepted an extended key Core rejects: ~A" str))))

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
