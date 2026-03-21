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
