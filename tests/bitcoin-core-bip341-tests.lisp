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

;;;; ============================================================
;;;; GA7 taproot script-path consensus regressions
;;;;
;;;; Two divergences from Core found by the 7th gap analysis (2026-07-23),
;;;; both chain-splitting in both directions and both constructible by the
;;;; coin owner. Each assertion below is a cell where the pre-fix code
;;;; disagreed with EvalChecksigTapscript / SignatureHashSchnorr.
;;;; ============================================================

(defun tapsig-status (sig-len pubkey-len &key flags (weight 1000) (last-byte nil))
  "Call VERIFY-TAPSCRIPT-SIGNATURE with synthetic byte strings of the given
lengths. Only the ordering of the length/type dispatch is under test, so the
bytes themselves never need to form a valid signature. LAST-BYTE overrides the
final signature byte (the explicit sighash byte of a 65-byte sig)."
  (let ((sig (make-array sig-len :element-type '(unsigned-byte 8)
                                 :initial-element #x01))
        (pk (make-array pubkey-len :element-type '(unsigned-byte 8)
                                   :initial-element #x02)))
    (when (and last-byte (plusp sig-len))
      (setf (aref sig (1- sig-len)) last-byte))
    (let ((bitcoin-lisp.coalton.interop::*script-flags* flags)
          (bitcoin-lisp.coalton.interop::*tapscript-validation-weight-left* weight))
      (multiple-value-bind (status result)
          (bitcoin-lisp.coalton.interop:verify-tapscript-signature sig pk)
        (values status result)))))

(test ga7-01-tapscript-checksig-dispatch-order
  "G7-01: EvalChecksigTapscript (interpreter.cpp:346-386) fails an empty pubkey
unconditionally and enforces the 64/65 signature size only inside
CheckSchnorrSignature, which runs only for 32-byte pubkeys. Checking the
signature length first — as we did before this fix — split the chain in both
directions."
  ;; --- Case A: empty sig + empty pubkey.
  ;; Core: SCRIPT_ERR_TAPSCRIPT_EMPTY_PUBKEY, hard fail.
  ;; Pre-fix: :empty-sig -> push false -> OP_NOT -> script SUCCEEDS. We accepted
  ;; a spend Core rejects.
  (is (eq :empty-pubkey (tapsig-status 0 0)))

  ;; --- Case B: non-empty wrong-length sig + upgradable (non-32-byte) pubkey.
  ;; Core: the else branch never inspects the signature, success stays true.
  ;; Pre-fix: :invalid-sig -> hard fail. We rejected a spend Core accepts.
  (multiple-value-bind (status result) (tapsig-status 10 33)
    (is (eq :upgradable-pubkey status))
    (is (eq t result)))
  (multiple-value-bind (status result) (tapsig-status 1 65)
    (is (eq :upgradable-pubkey status))
    (is (eq t result)))

  ;; --- Case C: empty sig + upgradable pubkey. Core sets success = !sig.empty()
  ;; and the upgradable branch must not modify it, so this is a failed-but-not
  ;; -erroring check: push false, exactly as for a 32-byte pubkey.
  (multiple-value-bind (status result) (tapsig-status 0 33)
    (is (eq :empty-sig status))
    (is (null result)))

  ;; --- DISCOURAGE_UPGRADABLE_PUBKEYTYPE is checked in the upgradable branch
  ;; regardless of whether the signature was empty.
  (is (eq :discourage-upgradable-pubkeytype
          (tapsig-status 10 33 :flags "DISCOURAGE_UPGRADABLE_PUBKEYTYPE")))
  (is (eq :discourage-upgradable-pubkeytype
          (tapsig-status 0 33 :flags "DISCOURAGE_UPGRADABLE_PUBKEYTYPE")))

  ;; --- An empty pubkey outranks every signature shape.
  (is (eq :empty-pubkey (tapsig-status 10 0)))
  (is (eq :empty-pubkey (tapsig-status 64 0)))
  (is (eq :empty-pubkey (tapsig-status 0 0 :flags "DISCOURAGE_UPGRADABLE_PUBKEYTYPE")))

  ;; --- Unchanged behaviour for 32-byte pubkeys: empty sig is a soft failure,
  ;; a wrong-length sig is SCRIPT_ERR_SCHNORR_SIG_SIZE, and a 65-byte sig
  ;; carrying an explicit SIGHASH_DEFAULT byte is SCHNORR_SIG_HASHTYPE.
  (multiple-value-bind (status result) (tapsig-status 0 32)
    (is (eq :empty-sig status))
    (is (null result)))
  (is (eq :invalid-sig (tapsig-status 10 32)))
  (is (eq :invalid-sig (tapsig-status 63 32)))
  (is (eq :invalid-sig (tapsig-status 66 32)))
  (is (eq :bad-sighash-type (tapsig-status 65 32 :last-byte #x00)))
  (is (eq :bad-sighash-type (tapsig-status 65 32 :last-byte #x04))))

(test ga7-01-validation-weight-charged-for-any-nonempty-sig
  "G7-01 corollary: Core charges VALIDATION_WEIGHT_PER_SIGOP_PASSED for every
non-empty signature — before the pubkey dispatch, so a wrong-length signature
and an upgradable pubkey type are both charged. The pre-fix code returned on
the length check first and never charged for those."
  ;; 10-byte sig against an upgradable key: charged, and here it exhausts.
  (is (eq :validation-weight-exceeded (tapsig-status 10 33 :weight 10)))
  ;; Same shape, enough weight left: passes and leaves the budget decremented.
  (is (eq :upgradable-pubkey (tapsig-status 10 33 :weight 50)))
  ;; Empty signatures are never charged, so an exhausted budget is not hit.
  (is (eq :empty-sig (tapsig-status 0 32 :weight 0)))
  (is (eq :empty-pubkey (tapsig-status 0 0 :weight 0)))
  ;; The decrement really does land on the caller's binding.
  (let ((bitcoin-lisp.coalton.interop::*script-flags* nil)
        (bitcoin-lisp.coalton.interop::*tapscript-validation-weight-left* 120))
    (bitcoin-lisp.coalton.interop:verify-tapscript-signature
     (make-array 10 :element-type '(unsigned-byte 8) :initial-element 1)
     (make-array 33 :element-type '(unsigned-byte 8) :initial-element 2))
    (is (= 70 bitcoin-lisp.coalton.interop::*tapscript-validation-weight-left*))))

(test ga7-02-bip341-sighash-single-out-of-range
  "G7-02: SignatureHashSchnorr returns false when SIGHASH_SINGLE is used at an
input index with no corresponding output (interpreter.cpp:1549-1550), which
callers turn into SCRIPT_ERR_SCHNORR_SIG_HASHTYPE before verifying anything.
The pre-fix code silently omitted the sha_single_output field and returned a
well-formed sighash, so an owner-crafted signature verified against a preimage
Core never computes. Core's own wallet vectors miss this: their tx has 9 inputs
but only 2 outputs, and every SINGLE vector sits at index 0 or 1."
  (let* ((data (load-bip341-vectors))
         (kps (first (gethash "keyPathSpending" data)))
         (given (gethash "given" kps))
         (raw-tx (bitcoin-lisp.crypto:hex-to-bytes (gethash "rawUnsignedTx" given)))
         (tx (flexi-streams:with-input-from-sequence (s raw-tx)
               (bitcoin-lisp.serialization:read-transaction s)))
         (utxos-spent (gethash "utxosSpent" given))
         (spent-vec (make-array (length utxos-spent)))
         (num-inputs (length (bitcoin-lisp.serialization:transaction-inputs tx)))
         (num-outputs (length (bitcoin-lisp.serialization:transaction-outputs tx))))
    (loop for u in utxos-spent for i from 0
          do (setf (aref spent-vec i)
                   (bitcoin-lisp.storage:make-utxo-entry
                    :value (gethash "amountSats" u)
                    :script-pubkey (bitcoin-lisp.crypto:hex-to-bytes
                                    (gethash "scriptPubKey" u)))))
    ;; Precondition: the vector tx really does have more inputs than outputs.
    (is (= 9 num-inputs))
    (is (= 2 num-outputs))
    (let ((bitcoin-lisp.coalton.interop::*current-tx* tx)
          (bitcoin-lisp.coalton.interop::*current-spent-utxos* spent-vec)
          (bitcoin-lisp.coalton.interop::*precomputed-sighash* nil))
      (loop for idx from 0 below num-inputs
            do (let ((bitcoin-lisp.coalton.interop::*current-input-index* idx))
                 (dolist (ht '(#x03 #x83))   ; SINGLE, SINGLE|ANYONECANPAY
                   (let ((got (bitcoin-lisp.coalton.interop::compute-bip341-sighash-real
                               ht nil nil)))
                     (if (< idx num-outputs)
                         (is (not (null got))
                             "in-range SINGLE at input ~D hashType ~2,'0X must still \
produce a sighash" idx ht)
                         (is (null got)
                             "out-of-range SINGLE at input ~D hashType ~2,'0X must \
hard-fail, got a sighash" idx ht))))
                 ;; Non-SINGLE hash types are unaffected at every index.
                 (dolist (ht '(#x00 #x01 #x02 #x81 #x82))
                   (is (not (null (bitcoin-lisp.coalton.interop::compute-bip341-sighash-real
                                   ht nil nil)))
                       "hashType ~2,'0X at input ~D must produce a sighash" ht idx)))))))

(test ga7-02-key-path-and-tapscript-reject-out-of-range-single
  "G7-02 at the call sites: both the key-path checker and the tapscript CHECKSIG
path must turn a NIL sighash into a hard failure rather than verifying against
one. Uses the same 9-input/2-output vector tx at an out-of-range index."
  (let* ((data (load-bip341-vectors))
         (kps (first (gethash "keyPathSpending" data)))
         (given (gethash "given" kps))
         (raw-tx (bitcoin-lisp.crypto:hex-to-bytes (gethash "rawUnsignedTx" given)))
         (tx (flexi-streams:with-input-from-sequence (s raw-tx)
               (bitcoin-lisp.serialization:read-transaction s)))
         (utxos-spent (gethash "utxosSpent" given))
         (spent-vec (make-array (length utxos-spent)))
         ;; 65-byte sig whose explicit sighash byte is SIGHASH_SINGLE.
         (sig (make-array 65 :element-type '(unsigned-byte 8) :initial-element #x01))
         (pk (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x02)))
    (setf (aref sig 64) #x03)
    (loop for u in utxos-spent for i from 0
          do (setf (aref spent-vec i)
                   (bitcoin-lisp.storage:make-utxo-entry
                    :value (gethash "amountSats" u)
                    :script-pubkey (bitcoin-lisp.crypto:hex-to-bytes
                                    (gethash "scriptPubKey" u)))))
    (let ((bitcoin-lisp.coalton.interop::*current-tx* tx)
          (bitcoin-lisp.coalton.interop::*current-spent-utxos* spent-vec)
          (bitcoin-lisp.coalton.interop::*current-input-index* 5)  ; >= 2 outputs
          (bitcoin-lisp.coalton.interop::*precomputed-sighash* nil)
          (bitcoin-lisp.coalton.interop::*script-flags* nil)
          (bitcoin-lisp.coalton.interop::*tapscript-amount* 0)
          (bitcoin-lisp.coalton.interop::*tapscript-leaf-hash* nil)
          (bitcoin-lisp.coalton.interop::*tapscript-validation-weight-left* 1000))
      ;; Tapscript CHECKSIG: :bad-sighash-type maps to SE-TapscriptInvalidSig,
      ;; a hard failure — never a schnorr verification against a short preimage.
      (multiple-value-bind (status result)
          (bitcoin-lisp.coalton.interop:verify-tapscript-signature sig pk)
        (is (eq :bad-sighash-type status))
        (is (null result)))
      ;; Key path: same input, witness of one 65-byte signature.
      (multiple-value-bind (ok err)
          (bitcoin-lisp.coalton.interop::validate-taproot-key-path (list sig) pk 0)
        (is (null ok))
        (is (eq :sig-hashtype err))))))
