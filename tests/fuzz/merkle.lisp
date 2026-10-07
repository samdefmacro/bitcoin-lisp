(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/merkle.cpp at the pin: ComputeMerkleRoot,
;;;; BlockMerkleRoot, BlockWitnessMerkleRoot and TransactionMerklePath over a
;;;; deserialized block. TransactionMerklePath (consensus/merkle.cpp, the
;;;; mining interface's coinbase path) has no counterpart; the path we build
;;;; is the BIP37 partial merkle tree gettxoutproof and merkleblock serve, so
;;;; the target proves a position with it -- BUILD-PARTIAL-MERKLE-TREE
;;;; matching that one transaction -- and extracts it back, where Core folds
;;;; its path. Either way the root must be the block's merkle root.

(def-suite :fuzz-merkle-tests :in :bitcoin-lisp-tests
  :description "Core fuzz merkle.cpp")

(in-suite :fuzz-merkle-tests)

(define-fuzz-target merkle
    (buffer :core "merkle.cpp:31-80" :iterations 6000 :max-len 600
            :corpus (lambda (fdp)
                      (%concat-octets (list (fdp-random-length-bytes
                                             (bl.ser:serialize-witness-block (consume-block fdp)))
                                            (fdp-integral-bytes (list (list 1 0 255)))))))
  "Over any block: the merkle root of one transaction is its txid and the
witness root zero; the root is the block's; and a partial merkle tree proving
any one position extracts to that root, that transaction and that position,
unless the tree is mutated (two equal siblings), which it refuses."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (block (progn (consume-bool fdp)  ; with_witness: our reader reads both forms
                       (or (consume-deserializable
                            fdp (lambda (b) (bl.ser:br-read-bitcoin-block (bl.ser:make-byte-reader-from b))))
                           (fuzz-reject))))
         (txs (bl.ser:bitcoin-block-transactions block))
         (hashes (mapcar #'bl.ser:transaction-hash txs)))
    (multiple-value-bind (root mutated) (bl.val:compute-merkle-root hashes)
      (when (= 1 (length hashes))
        (fuzz-assert (equalp (fuzz-sabotage root) (first hashes)) "a one-transaction root is not its txid")
        (fuzz-assert (every #'zerop (bl.val:compute-witness-merkle-root txs))
                     "a one-transaction witness root is not zero"))
      (when hashes
        (let* ((position (consume-integral-in-range fdp 0 (1- (length hashes)) 32))
               (match (let ((v (make-array (length hashes) :initial-element nil)))
                        (setf (aref v position) t)
                        v)))
          (multiple-value-bind (bits proof) (bl.net:build-partial-merkle-tree (coerce hashes (quote vector)) match)
            (multiple-value-bind (proved-root matched indices)
                (bl.net:extract-partial-merkle-tree (length hashes) bits proof)
              (if mutated
                  (fuzz-assert (or (null proved-root) (equalp proved-root root)))
                  (fuzz-assert (and (equalp (fuzz-sabotage proved-root) root)
                                    (equalp matched (list (nth position hashes)))
                                    (equal indices (list position)))
                               "the proof of position ~D of ~D extracts ~S at ~S"
                               position (length hashes) proved-root indices)))))))))
