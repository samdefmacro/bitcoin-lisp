(in-package #:bitcoin-lisp.tests)

(def-suite :bitcoin-core-bip341-tests
  :description "Bitcoin Core bip341_wallet_vectors.json compatibility tests"
  :in :bitcoin-lisp-tests)

(in-suite :bitcoin-core-bip341-tests)

(defun load-bip341-vectors ()
  "Load BIP 341 wallet test vectors from Bitcoin Core."
  (let ((path (merge-pathnames
               "refs/bitcoin/src/test/data/bip341_wallet_vectors.json"
               (asdf:system-source-directory :bitcoin-lisp))))
    (with-open-file (stream path :direction :input)
      (yason:parse stream))))

(defun compute-script-tree-merkle-root (tree)
  "Recursively compute the merkle root of a script tree.
TREE can be: null, a leaf (hash-table with 'script' and 'leafVersion'),
or a branch (list of two subtrees)."
  (cond
    ((null tree) nil)
    ((hash-table-p tree)
     ;; Leaf node
     (let ((script (bitcoin-lisp.crypto:hex-to-bytes (gethash "script" tree)))
           (leaf-version (gethash "leafVersion" tree)))
       (bitcoin-lisp.crypto:tap-leaf-hash leaf-version script)))
    ((listp tree)
     ;; Branch: [left, right]
     (let ((left (compute-script-tree-merkle-root (first tree)))
           (right (compute-script-tree-merkle-root (second tree))))
       (bitcoin-lisp.crypto:tap-branch-hash left right)))
    (t (error "Unknown script tree format: ~A" (type-of tree)))))

(test bip341-wallet-vectors
  "Run all BIP 341 wallet test vectors."
  (let* ((data (load-bip341-vectors))
         (vectors (gethash "scriptPubKey" data))
         (passed 0)
         (failed 0)
         (failures '()))
    (dolist (vec vectors)
      (let* ((given (gethash "given" vec))
             (intermediary (gethash "intermediary" vec))
             (expected (gethash "expected" vec))
             (internal-pubkey (bitcoin-lisp.crypto:hex-to-bytes
                               (gethash "internalPubkey" given)))
             (script-tree (gethash "scriptTree" given))
             ;; Compute merkle root from script tree
             (merkle-root (compute-script-tree-merkle-root script-tree))
             ;; Expected intermediary values
             (expected-merkle (gethash "merkleRoot" intermediary))
             (expected-tweak (gethash "tweak" intermediary))
             (expected-tweaked (gethash "tweakedPubkey" intermediary))
             ;; Expected final values
             (expected-spk (gethash "scriptPubKey" expected)))
        (handler-case
            (let ((ok t))
              ;; Check merkle root
              (when expected-merkle
                (let ((expected-bytes (bitcoin-lisp.crypto:hex-to-bytes expected-merkle)))
                  (unless (equalp merkle-root expected-bytes)
                    (setf ok nil)
                    (push (format nil "merkleRoot mismatch") failures))))

              ;; Check tweak
              (let* ((tweak (bitcoin-lisp.crypto:tap-tweak-hash internal-pubkey merkle-root))
                     (expected-tweak-bytes (bitcoin-lisp.crypto:hex-to-bytes expected-tweak)))
                (unless (equalp tweak expected-tweak-bytes)
                  (setf ok nil)
                  (push (format nil "tweak mismatch") failures)))

              ;; Check tweaked pubkey
              (multiple-value-bind (tweaked-pubkey parity)
                  (bitcoin-lisp.coalton.interop:compute-tweaked-pubkey
                   internal-pubkey merkle-root)
                (declare (ignore parity))
                (let ((expected-tweaked-bytes (bitcoin-lisp.crypto:hex-to-bytes expected-tweaked)))
                  (unless (equalp tweaked-pubkey expected-tweaked-bytes)
                    (setf ok nil)
                    (push (format nil "tweakedPubkey mismatch") failures)))

                ;; Check scriptPubKey = OP_1 <32-byte tweaked pubkey>
                (when tweaked-pubkey
                  (let* ((spk (concatenate '(vector (unsigned-byte 8))
                                           #(#x51 #x20) tweaked-pubkey))
                         (spk-hex (bitcoin-lisp.crypto:bytes-to-hex spk)))
                    (unless (string= spk-hex expected-spk)
                      (setf ok nil)
                      (push (format nil "scriptPubKey mismatch: ~A vs ~A" spk-hex expected-spk)
                            failures)))))

              (if ok (incf passed) (incf failed)))
          (error (e)
            (incf failed)
            (push (format nil "Error: ~A" e) failures)))))

    (format t "~%BIP 341 Tests: ~D passed, ~D failed~%" passed failed)
    (when failures
      (format t "Failures:~%")
      (dolist (f failures)
        (format t "  ~A~%" f)))

    (is (zerop failed)
        "All BIP 341 wallet vectors must pass. ~D failed." failed)))

(test bip341-keypath-sighash-vectors
  "BIP 341 keyPathSpending: compute-bip341-sighash-real must match the
intermediary.sigHash for every (txinIndex, hashType) in the wallet
vectors. Validates our taproot key-path sighash against Core's known-good
values (the scriptPubKey section above only covers address derivation)."
  (let* ((data (load-bip341-vectors))
         (kps (first (gethash "keyPathSpending" data)))
         (given (gethash "given" kps))
         (raw-tx (bitcoin-lisp.crypto:hex-to-bytes (gethash "rawUnsignedTx" given)))
         (tx (flexi-streams:with-input-from-sequence (s raw-tx)
               (bitcoin-lisp.serialization:read-transaction s)))
         (utxos-spent (gethash "utxosSpent" given))
         (spent-vec (make-array (length utxos-spent))))
    (loop for u in utxos-spent for i from 0
          do (setf (aref spent-vec i)
                   (bitcoin-lisp.storage:make-utxo-entry
                    :value (gethash "amountSats" u)
                    :script-pubkey (bitcoin-lisp.crypto:hex-to-bytes
                                    (gethash "scriptPubKey" u)))))
    (let ((bitcoin-lisp.coalton.interop::*current-tx* tx)
          (bitcoin-lisp.coalton.interop::*current-spent-utxos* spent-vec)
          (bitcoin-lisp.coalton.interop::*precomputed-sighash* nil))
      (dolist (entry (gethash "inputSpending" kps))
        (let* ((g (gethash "given" entry))
               (inter (gethash "intermediary" entry))
               (idx (gethash "txinIndex" g))
               (hash-type (gethash "hashType" g))
               (expected (gethash "sigHash" inter)))
          (let ((bitcoin-lisp.coalton.interop::*current-input-index* idx))
            (let ((got (bitcoin-lisp.crypto:bytes-to-hex
                        (bitcoin-lisp.coalton.interop::compute-bip341-sighash-real
                         hash-type nil nil))))
              (is (string-equal expected got)
                  "input ~D hashType ~D: expected ~A got ~A" idx hash-type expected got))))))))

;;;; Taproot spend vectors (tests/data/taproot_spend_vectors.json,
;;;; generated by tests/gen_taproot_vectors.py via Core's test_framework).
;;;; Each record is a fully-signed taproot spend; the runner parses it,
;;;; builds the spent-utxo set, and runs verify-script on the given input.

(defun load-taproot-spend-vectors ()
  (let ((path (merge-pathnames "tests/data/taproot_spend_vectors.json"
                               (asdf:system-source-directory :bitcoin-lisp))))
    (with-open-file (s path :direction :input) (yason:parse s))))

(defun run-taproot-spend-vector (rec)
  "Run one taproot spend vector through verify-script. Returns (values ok err)."
  (let* ((tx-bytes (bitcoin-lisp.crypto:hex-to-bytes (gethash "tx" rec)))
         (tx (flexi-streams:with-input-from-sequence (s tx-bytes)
               (bitcoin-lisp.serialization:read-transaction s)))
         (prevouts (gethash "prevouts" rec))
         (index (gethash "index" rec))
         (flags (gethash "flags" rec))
         (spent-vec (make-array (length prevouts))))
    (loop for p in prevouts for i from 0
          do (setf (aref spent-vec i)
                   (bitcoin-lisp.storage:make-utxo-entry
                    :value (gethash "amountSats" p)
                    :script-pubkey (bitcoin-lisp.crypto:hex-to-bytes
                                    (gethash "scriptPubKey" p)))))
    (let* ((utxo (aref spent-vec index))
           (amount (bitcoin-lisp.storage:utxo-entry-value utxo))
           (spk (bitcoin-lisp.storage:utxo-entry-script-pubkey utxo))
           (input (elt (bitcoin-lisp.serialization:transaction-inputs tx) index))
           (sig-bytes (bitcoin-lisp.serialization:tx-in-script-sig input))
           (witness-stack (elt (bitcoin-lisp.serialization:transaction-witness tx) index))
           (bitcoin-lisp.coalton.interop:*current-tx* tx)
           (bitcoin-lisp.coalton.interop:*current-input-index* index)
           (bitcoin-lisp.coalton.interop::*current-spent-utxos* spent-vec)
           (bitcoin-lisp.coalton.interop::*precomputed-sighash* nil)
           (bitcoin-lisp.coalton.interop:*witness-input-amount* amount))
      (bitcoin-lisp.coalton.interop:set-script-flags flags)
      (unwind-protect
           (bitcoin-lisp.coalton.interop:verify-script
            sig-bytes spk :witness witness-stack :amount amount)
        (bitcoin-lisp.coalton.interop:set-script-flags nil)))))

(test taproot-spend-vectors-baseline
  "All generated taproot spends verify: key-path (DEFAULT, ALL|ANYONECANPAY),
key-path with annex, script-path CHECKSIG, and script-path with
OP_CODESEPARATOR after a push (exercises the BIP 341 sighash annex +
codeseparator-opcode-position commitments)."
  (dolist (rec (load-taproot-spend-vectors))
    (let ((comment (gethash "comment" rec)))
      (multiple-value-bind (ok err) (run-taproot-spend-vector rec)
        (is (eq t ok) "taproot vector [~A] failed: ~A" comment err)))))
