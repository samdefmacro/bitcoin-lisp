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
    (bl.crypto:hash256 combined)))

(test merkle-root-empty
  "Empty hash list should return 32 zero bytes."
  (let ((root (bl.val:compute-merkle-root '())))
    (is (= 32 (length root)))
    (is (every #'zerop root))))

(test merkle-root-single-tx
  "Single hash: merkle root equals that hash."
  (let* ((h (make-merkle-test-hash #xAA))
         (root (bl.val:compute-merkle-root (list h))))
    (is (equalp h root))))

(test merkle-root-two-tx
  "Two hashes: root = hash256(h0 || h1)."
  (let* ((h0 (make-merkle-test-hash #x11))
         (h1 (make-merkle-test-hash #x22))
         (expected (manual-hash-pair h0 h1))
         (root (bl.val:compute-merkle-root (list h0 h1))))
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
         (root (bl.val:compute-merkle-root (list h0 h1 h2))))
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
         (root (bl.val:compute-merkle-root (list h0 h1 h2 h3))))
    (is (equalp expected root))))

(test merkle-root-deterministic
  "Same inputs should always produce the same root."
  (let* ((hashes (loop for i from 1 to 5
                       collect (make-merkle-test-hash i)))
         (root1 (bl.val:compute-merkle-root (copy-list hashes)))
         (root2 (bl.val:compute-merkle-root (copy-list hashes))))
    (is (equalp root1 root2))))

(test merkle-root-does-not-mutate-input
  "compute-merkle-root should not modify the input list or hashes."
  (let* ((h0 (make-merkle-test-hash #xAA))
         (h1 (make-merkle-test-hash #xBB))
         (h0-copy (copy-seq h0))
         (h1-copy (copy-seq h1))
         (input-list (list h0 h1)))
    (bl.val:compute-merkle-root input-list)
    (is (equalp h0 h0-copy))
    (is (equalp h1 h1-copy))))

(test cve-2012-2459-duplicate-merkle
  "CVE-2012-2459: duplicating the last tx of an odd-count block yields the
SAME merkle root, so a valid block can be malleated into a distinct one.
compute-merkle-root returns the identical root for both but flags the mutated
(duplicated) variant via its second value so validate-block can reject it
(bad-txns-duplicate). The honest odd-count self-duplication is NOT flagged."
  (let* ((h0 (make-merkle-test-hash #x11))
         (h1 (make-merkle-test-hash #x22))
         (h2 (make-merkle-test-hash #x33)))
    (multiple-value-bind (root-original mutated-original)
        (bl.val:compute-merkle-root (list h0 h1 h2))
      (multiple-value-bind (root-mutated mutated-flag)
          ;; [h0 h1 h2 h2] — the attacker's explicit duplication of the last tx.
          (bl.val:compute-merkle-root (list h0 h1 h2 h2))
        ;; Same root — this IS the vulnerability.
        (is (equalp root-original root-mutated)
            "Duplicate-last-tx attack should produce identical merkle root")
        ;; The mutated variant is flagged; the honest odd-count tree is not.
        (is (null mutated-original))
        (is (eq t mutated-flag))))))

(test merkle-mutation-flag-honest-trees
  "compute-merkle-root must NOT flag honest trees (no equal adjacent pair),
including the odd-count self-duplication of the last element."
  (dolist (n '(1 2 3 4 5 7 8))
    (let ((hashes (loop for i from 1 to n collect (make-merkle-test-hash i))))
      (multiple-value-bind (root mutated)
          (bl.val:compute-merkle-root hashes)
        (declare (ignore root))
        (is (null mutated) "n=~D should not be flagged mutated" n)))))
