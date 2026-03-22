(in-package #:bitcoin-lisp.tests)

(def-suite :merkle-tests
  :description "Tests for Merkle tree computation edge cases"
  :in :bitcoin-lisp-tests)

(in-suite :merkle-tests)

(defun make-merkle-test-hash (byte-val)
  "Create a 32-byte hash filled with BYTE-VAL."
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element byte-val))

(defun manual-hash-pair (a b)
  "Compute hash256(a || b) for manual merkle root verification."
  (let ((combined (make-array 64 :element-type '(unsigned-byte 8))))
    (replace combined a :start1 0)
    (replace combined b :start1 32)
    (bitcoin-lisp.crypto:hash256 combined)))

(test merkle-root-empty
  "Empty hash list should return 32 zero bytes."
  (let ((root (bitcoin-lisp.validation:compute-merkle-root '())))
    (is (= 32 (length root)))
    (is (every #'zerop root))))

(test merkle-root-single-tx
  "Single hash: merkle root equals that hash."
  (let* ((h (make-merkle-test-hash #xAA))
         (root (bitcoin-lisp.validation:compute-merkle-root (list h))))
    (is (equalp h root))))

(test merkle-root-two-tx
  "Two hashes: root = hash256(h0 || h1)."
  (let* ((h0 (make-merkle-test-hash #x11))
         (h1 (make-merkle-test-hash #x22))
         (expected (manual-hash-pair h0 h1))
         (root (bitcoin-lisp.validation:compute-merkle-root (list h0 h1))))
    (is (equalp expected root))))

(test merkle-root-three-tx-odd-duplication
  "Three hashes: third is duplicated to make even count.
Root = hash256(hash256(h0||h1) || hash256(h2||h2))."
  (let* ((h0 (make-merkle-test-hash #x11))
         (h1 (make-merkle-test-hash #x22))
         (h2 (make-merkle-test-hash #x33))
         (left (manual-hash-pair h0 h1))
         (right (manual-hash-pair h2 h2))
         (expected (manual-hash-pair left right))
         (root (bitcoin-lisp.validation:compute-merkle-root (list h0 h1 h2))))
    (is (equalp expected root))))

(test merkle-root-four-tx
  "Four hashes: balanced binary tree."
  (let* ((h0 (make-merkle-test-hash #x10))
         (h1 (make-merkle-test-hash #x20))
         (h2 (make-merkle-test-hash #x30))
         (h3 (make-merkle-test-hash #x40))
         (left (manual-hash-pair h0 h1))
         (right (manual-hash-pair h2 h3))
         (expected (manual-hash-pair left right))
         (root (bitcoin-lisp.validation:compute-merkle-root (list h0 h1 h2 h3))))
    (is (equalp expected root))))

(test merkle-root-deterministic
  "Same inputs should always produce the same root."
  (let* ((hashes (loop for i from 1 to 5
                       collect (make-merkle-test-hash i)))
         (root1 (bitcoin-lisp.validation:compute-merkle-root (copy-list hashes)))
         (root2 (bitcoin-lisp.validation:compute-merkle-root (copy-list hashes))))
    (is (equalp root1 root2))))

(test merkle-root-does-not-mutate-input
  "compute-merkle-root should not modify the input list or hashes."
  (let* ((h0 (make-merkle-test-hash #xAA))
         (h1 (make-merkle-test-hash #xBB))
         (h0-copy (copy-seq h0))
         (h1-copy (copy-seq h1))
         (input-list (list h0 h1)))
    (bitcoin-lisp.validation:compute-merkle-root input-list)
    (is (equalp h0 h0-copy))
    (is (equalp h1 h1-copy))))

(test cve-2012-2459-duplicate-merkle
  "CVE-2012-2459: duplicating the last tx in an odd-count block produces
the same merkle root as the original. This is the known vulnerability
where two different transaction lists yield the same root."
  (let* ((h0 (make-merkle-test-hash #x11))
         (h1 (make-merkle-test-hash #x22))
         (h2 (make-merkle-test-hash #x33))
         ;; Original: [h0, h1, h2] — h2 is duplicated internally
         (root-original (bitcoin-lisp.validation:compute-merkle-root (list h0 h1 h2)))
         ;; Mutated: [h0, h1, h2, h2] — explicitly duplicated
         (root-mutated (bitcoin-lisp.validation:compute-merkle-root (list h0 h1 h2 h2))))
    ;; Both produce the same merkle root — this IS the vulnerability
    (is (equalp root-original root-mutated)
        "Duplicate-last-tx attack should produce identical merkle root")))
