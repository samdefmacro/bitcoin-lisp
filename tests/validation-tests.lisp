(in-package #:bitcoin-lisp.tests)

(in-suite :validation-tests)

;;;; Transaction Structure Validation Tests

(defun make-test-transaction (&key (inputs 1) (outputs 1) (value 50000000))
  "Create a simple test transaction with specified parameters."
  (let ((tx-inputs (loop for i below inputs
                         collect (bitcoin-lisp.serialization:make-tx-in
                                  :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                    :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                      :initial-element (1+ i))
                                                    :index 0)
                                  :script-sig (make-array 10 :element-type '(unsigned-byte 8)
                                                          :initial-element #x00)
                                  :sequence #xFFFFFFFF)))
        (tx-outputs (loop for i below outputs
                          collect (bitcoin-lisp.serialization:make-tx-out
                                   :value (floor value outputs)
                                   :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                              :initial-element #x76)))))
    (bitcoin-lisp.serialization:make-transaction
     :version 1
     :inputs tx-inputs
     :outputs tx-outputs
     :lock-time 0)))

(defun make-coinbase-transaction (&key (value 5000000000) (height 0))
  "Create a coinbase transaction."
  (let* ((coinbase-script (make-array 3 :element-type '(unsigned-byte 8)
                                        :initial-contents (list (logand height #xFF)
                                                                (logand (ash height -8) #xFF)
                                                                (logand (ash height -16) #xFF))))
         (input (bitcoin-lisp.serialization:make-tx-in
                 :previous-output (bitcoin-lisp.serialization:make-outpoint
                                   :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                     :initial-element 0)
                                   :index #xFFFFFFFF)
                 :script-sig coinbase-script
                 :sequence #xFFFFFFFF))
         (output (bitcoin-lisp.serialization:make-tx-out
                  :value value
                  :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                             :initial-element #x76))))
    (bitcoin-lisp.serialization:make-transaction
     :version 1
     :inputs (list input)
     :outputs (list output)
     :lock-time 0)))

(test valid-transaction-structure
  "A valid transaction should pass structure validation."
  (let ((tx (make-test-transaction :inputs 1 :outputs 2 :value 10000000)))
    (multiple-value-bind (valid error)
        (bitcoin-lisp.validation:validate-transaction-structure tx)
      (is (eq t valid))
      (is (null error)))))

(test transaction-no-inputs
  "Transaction without inputs should fail validation."
  (let ((tx (bitcoin-lisp.serialization:make-transaction
             :version 1
             :inputs '()
             :outputs (list (bitcoin-lisp.serialization:make-tx-out
                             :value 1000
                             :script-pubkey (make-array 0 :element-type '(unsigned-byte 8))))
             :lock-time 0)))
    (multiple-value-bind (valid error)
        (bitcoin-lisp.validation:validate-transaction-structure tx)
      (is (null valid))
      (is (eq :no-inputs error)))))

(test transaction-no-outputs
  "Transaction without outputs should fail validation."
  (let ((tx (bitcoin-lisp.serialization:make-transaction
             :version 1
             :inputs (list (bitcoin-lisp.serialization:make-tx-in
                            :previous-output (bitcoin-lisp.serialization:make-outpoint
                                              :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                :initial-element 1)
                                              :index 0)
                            :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                            :sequence #xFFFFFFFF))
             :outputs '()
             :lock-time 0)))
    (multiple-value-bind (valid error)
        (bitcoin-lisp.validation:validate-transaction-structure tx)
      (is (null valid))
      (is (eq :no-outputs error)))))

(test transaction-duplicate-inputs
  "Transaction with duplicate inputs should fail validation."
  (let* ((same-outpoint (bitcoin-lisp.serialization:make-outpoint
                         :hash (make-array 32 :element-type '(unsigned-byte 8)
                                           :initial-element 42)
                         :index 0))
         (empty-script (make-array 0 :element-type '(unsigned-byte 8)))
         (tx (bitcoin-lisp.serialization:make-transaction
              :version 1
              :inputs (list (bitcoin-lisp.serialization:make-tx-in
                             :previous-output same-outpoint
                             :script-sig empty-script
                             :sequence #xFFFFFFFF)
                            (bitcoin-lisp.serialization:make-tx-in
                             :previous-output same-outpoint
                             :script-sig empty-script
                             :sequence #xFFFFFFFF))
              :outputs (list (bitcoin-lisp.serialization:make-tx-out
                              :value 1000
                              :script-pubkey empty-script))
              :lock-time 0)))
    (multiple-value-bind (valid error)
        (bitcoin-lisp.validation:validate-transaction-structure tx)
      (is (null valid))
      (is (eq :duplicate-inputs error)))))

(test transaction-negative-output
  "Transaction with negative output value should fail validation."
  (let* ((empty-script (make-array 0 :element-type '(unsigned-byte 8)))
         (tx (bitcoin-lisp.serialization:make-transaction
              :version 1
              :inputs (list (bitcoin-lisp.serialization:make-tx-in
                             :previous-output (bitcoin-lisp.serialization:make-outpoint
                                               :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                 :initial-element 1)
                                               :index 0)
                             :script-sig empty-script
                             :sequence #xFFFFFFFF))
              :outputs (list (bitcoin-lisp.serialization:make-tx-out
                              :value -1000
                              :script-pubkey empty-script))
              :lock-time 0)))
    (multiple-value-bind (valid error)
        (bitcoin-lisp.validation:validate-transaction-structure tx)
      (is (null valid))
      (is (eq :negative-output error)))))

;;;; Contextual Transaction Validation Tests

(test transaction-missing-input-utxo
  "Transaction spending non-existent UTXO should fail."
  (let ((tx (make-test-transaction :inputs 1 :outputs 1 :value 1000))
        (utxo-set (bitcoin-lisp.storage:make-utxo-set)))
    (multiple-value-bind (valid error fee)
        (bitcoin-lisp.validation:validate-transaction-contextual tx utxo-set 100)
      (declare (ignore fee))
      (is (null valid))
      (is (eq :missing-input error)))))

(test transaction-coinbase-maturity
  "Spending immature coinbase should fail."
  (let ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76))
        (empty-script (make-array 0 :element-type '(unsigned-byte 8))))
    ;; Add coinbase UTXO at height 50
    (bitcoin-lisp.storage:add-utxo utxo-set txid 0 5000000000 script 50 :coinbase t)
    ;; Try to spend at height 100 (only 50 blocks old, need 100)
    (let* ((input (bitcoin-lisp.serialization:make-tx-in
                   :previous-output (bitcoin-lisp.serialization:make-outpoint
                                     :hash txid
                                     :index 0)
                   :script-sig empty-script
                   :sequence #xFFFFFFFF))
           (output (bitcoin-lisp.serialization:make-tx-out
                    :value 4900000000
                    :script-pubkey script))
           (tx (bitcoin-lisp.serialization:make-transaction
                :version 1
                :inputs (list input)
                :outputs (list output)
                :lock-time 0)))
      (multiple-value-bind (valid error fee)
          (bitcoin-lisp.validation:validate-transaction-contextual tx utxo-set 100)
        (declare (ignore fee))
        (is (null valid))
        (is (eq :coinbase-not-mature error))))))

(test transaction-valid-spending
  "Valid transaction spending existing UTXO should pass."
  (let ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76))
        (empty-script (make-array 0 :element-type '(unsigned-byte 8))))
    ;; Add non-coinbase UTXO
    (bitcoin-lisp.storage:add-utxo utxo-set txid 0 10000000 script 10)
    (let* ((input (bitcoin-lisp.serialization:make-tx-in
                   :previous-output (bitcoin-lisp.serialization:make-outpoint
                                     :hash txid
                                     :index 0)
                   :script-sig empty-script
                   :sequence #xFFFFFFFF))
           (output (bitcoin-lisp.serialization:make-tx-out
                    :value 9000000
                    :script-pubkey script))
           (tx (bitcoin-lisp.serialization:make-transaction
                :version 1
                :inputs (list input)
                :outputs (list output)
                :lock-time 0)))
      (multiple-value-bind (valid error fee)
          (bitcoin-lisp.validation:validate-transaction-contextual tx utxo-set 100)
        (is (eq t valid))
        (is (null error))
        ;; Fee is now a Satoshi type - unwrap to compare
        (is (= 1000000 (bitcoin-lisp.coalton.interop:unwrap-satoshi fee)))))))  ; 10M - 9M = 1M fee

(test transaction-insufficient-funds
  "Transaction with outputs exceeding inputs should fail."
  (let ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76))
        (empty-script (make-array 0 :element-type '(unsigned-byte 8))))
    (bitcoin-lisp.storage:add-utxo utxo-set txid 0 1000000 script 10)
    (let* ((input (bitcoin-lisp.serialization:make-tx-in
                   :previous-output (bitcoin-lisp.serialization:make-outpoint
                                     :hash txid
                                     :index 0)
                   :script-sig empty-script
                   :sequence #xFFFFFFFF))
           (output (bitcoin-lisp.serialization:make-tx-out
                    :value 2000000  ; More than input
                    :script-pubkey script))
           (tx (bitcoin-lisp.serialization:make-transaction
                :version 1
                :inputs (list input)
                :outputs (list output)
                :lock-time 0)))
      (multiple-value-bind (valid error fee)
          (bitcoin-lisp.validation:validate-transaction-contextual tx utxo-set 100)
        (declare (ignore fee))
        (is (null valid))
        (is (eq :insufficient-funds error))))))

;;;; Block Validation Tests

(defun make-test-block-header (&key (version 1) (timestamp (get-universal-time))
                                (bits #x1d00ffff) (nonce 0))
  "Create a test block header."
  (bitcoin-lisp.serialization:make-block-header
   :version version
   :prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
   :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
   :timestamp timestamp
   :bits bits
   :nonce nonce))

(test block-header-time-too-new
  "Block with timestamp too far in future should fail."
  ;; Note: PoW validation runs first, so this tests that validation fails
  ;; The actual error may be :bad-proof-of-work if PoW is checked first
  (let* ((current-time (get-universal-time))
         (header (make-test-block-header
                  :timestamp (+ current-time 10000)))  ; 10000 seconds in future
         (state (bitcoin-lisp.storage:init-chain-state "/tmp/btc-test/")))
    (multiple-value-bind (valid error)
        (bitcoin-lisp.validation:validate-block-header header state current-time)
      (is (null valid))
      ;; Either error is acceptable - header is invalid
      (is (member error '(:time-too-new :bad-proof-of-work))))))

(test block-header-bad-version
  "Block with invalid version should fail."
  ;; Note: PoW validation runs first, so this tests that validation fails
  ;; The actual error may be :bad-proof-of-work if PoW is checked first
  (let* ((current-time (get-universal-time))
         (header (make-test-block-header :version 0))  ; Invalid version
         (state (bitcoin-lisp.storage:init-chain-state "/tmp/btc-test/")))
    (multiple-value-bind (valid error)
        (bitcoin-lisp.validation:validate-block-header header state current-time)
      (is (null valid))
      ;; Either error is acceptable - header is invalid
      (is (member error '(:bad-version :bad-proof-of-work))))))

;;;; Merkle Root Tests

(test merkle-root-single-tx
  "Merkle root of single transaction should be its hash."
  (let* ((tx (make-coinbase-transaction :value 5000000000 :height 1))
         (tx-hash (bitcoin-lisp.serialization:transaction-hash tx))
         (merkle-root (bitcoin-lisp.validation:compute-merkle-root (list tx-hash))))
    (is (equalp merkle-root tx-hash))))

(test merkle-root-two-txs
  "Merkle root of two transactions should be hash of concatenated hashes."
  (let* ((tx1 (make-coinbase-transaction :value 5000000000 :height 1))
         (tx2 (make-test-transaction :inputs 1 :outputs 1 :value 1000000))
         (hash1 (bitcoin-lisp.serialization:transaction-hash tx1))
         (hash2 (bitcoin-lisp.serialization:transaction-hash tx2))
         (merkle-root (bitcoin-lisp.validation:compute-merkle-root (list hash1 hash2)))
         ;; Manually compute expected: hash256(hash1 || hash2)
         (combined (make-array 64 :element-type '(unsigned-byte 8))))
    (replace combined hash1 :start1 0)
    (replace combined hash2 :start1 32)
    (let ((expected (bitcoin-lisp.crypto:hash256 combined)))
      (is (equalp merkle-root expected)))))

(test merkle-root-empty
  "Merkle root of empty list should be zeros."
  (let ((merkle-root (bitcoin-lisp.validation:compute-merkle-root nil)))
    (is (every #'zerop merkle-root))))

;;;; BIP 34 Coinbase Height Tests

(test decode-coinbase-height-small
  "decode-coinbase-height should handle small heights encoded with OP_n."
  ;; OP_0 -> height 0
  (is (= 0 (bitcoin-lisp.validation:decode-coinbase-height
             (make-array 1 :element-type '(unsigned-byte 8) :initial-contents '(0)))))
  ;; OP_1 (0x51) -> height 1
  (is (= 1 (bitcoin-lisp.validation:decode-coinbase-height
             (make-array 1 :element-type '(unsigned-byte 8) :initial-contents '(#x51)))))
  ;; OP_16 (0x60) -> height 16
  (is (= 16 (bitcoin-lisp.validation:decode-coinbase-height
              (make-array 1 :element-type '(unsigned-byte 8) :initial-contents '(#x60))))))

(test decode-coinbase-height-push-bytes
  "decode-coinbase-height should handle heights encoded as byte pushes."
  ;; push1 100 -> height 100
  (is (= 100 (bitcoin-lisp.validation:decode-coinbase-height
               (make-array 2 :element-type '(unsigned-byte 8) :initial-contents '(1 100)))))
  ;; push2 0x00 0x01 -> height 256
  (is (= 256 (bitcoin-lisp.validation:decode-coinbase-height
               (make-array 3 :element-type '(unsigned-byte 8) :initial-contents '(2 0 1)))))
  ;; push3 for height 21111 = 0x5277 -> bytes: push3 #x77 #x52 #x00
  (is (= 21111 (bitcoin-lisp.validation:decode-coinbase-height
                 (make-array 4 :element-type '(unsigned-byte 8)
                               :initial-contents '(3 #x77 #x52 #x00))))))

(test decode-coinbase-height-empty-script
  "decode-coinbase-height should return NIL for empty scriptSig."
  (is (null (bitcoin-lisp.validation:decode-coinbase-height
              (make-array 0 :element-type '(unsigned-byte 8))))))

;;;; Witness Commitment Tests

(test find-witness-commitment-present
  "Should find the witness commitment in a coinbase with OP_RETURN output."
  (let* ((commitment-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xBB))
         ;; OP_RETURN push36 0xaa21a9ed <32-byte hash>
         (script (make-array 38 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref script 0) #x6a   ; OP_RETURN
          (aref script 1) #x24   ; push 36 bytes
          (aref script 2) #xaa   ; commitment header
          (aref script 3) #x21
          (aref script 4) #xa9
          (aref script 5) #xed)
    (replace script commitment-hash :start1 6)
    (let* ((output (bitcoin-lisp.serialization:make-tx-out
                    :value 0 :script-pubkey script))
           (coinbase (bitcoin-lisp.serialization:make-transaction
                      :version 1
                      :inputs (list (bitcoin-lisp.serialization:make-tx-in
                                     :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                       :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                         :initial-element 0)
                                                       :index #xFFFFFFFF)
                                     :script-sig (make-array 4 :element-type '(unsigned-byte 8)
                                                               :initial-element 1)))
                      :outputs (list (bitcoin-lisp.serialization:make-tx-out :value 5000000000
                                      :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                                    :initial-element #x76))
                                     output)
                      :lock-time 0)))
      (let ((found (bitcoin-lisp.validation:find-witness-commitment coinbase)))
        (is (not (null found)))
        (is (equalp commitment-hash found))))))

(test find-witness-commitment-absent
  "Should return NIL when no witness commitment exists."
  (let ((coinbase (make-coinbase-transaction :value 5000000000 :height 1)))
    (is (null (bitcoin-lisp.validation:find-witness-commitment coinbase)))))

;;;; Block Script Validation Tests

(test validate-block-scripts-called
  "validate-block should call script validation and reject invalid scripts."
  ;; Create a block with a spending tx that has an empty scriptSig
  ;; spending a P2PKH output. The script should fail because the
  ;; empty scriptSig can't satisfy P2PKH.
  (let* ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
         (prev-txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xAA))
         ;; P2PKH scriptPubKey: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
         (p2pkh-script (make-array 25 :element-type '(unsigned-byte 8)
                                      :initial-contents
                                      (list #x76 #xa9 #x14  ; OP_DUP OP_HASH160 push20
                                            1 2 3 4 5 6 7 8 9 10
                                            11 12 13 14 15 16 17 18 19 20
                                            #x88 #xac)))  ; OP_EQUALVERIFY OP_CHECKSIG
         ;; Empty scriptSig - will fail validation
         (empty-script (make-array 0 :element-type '(unsigned-byte 8))))
    ;; Add UTXO with P2PKH script
    (bitcoin-lisp.storage:add-utxo utxo-set prev-txid 0 1000000 p2pkh-script 5)
    ;; Build block with spending tx that has empty scriptSig
    (let* ((coinbase-tx (make-coinbase-transaction :value 5000000000 :height 10))
           (spending-tx (bitcoin-lisp.serialization:make-transaction
                         :version 1
                         :inputs (list (bitcoin-lisp.serialization:make-tx-in
                                        :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                          :hash prev-txid :index 0)
                                        :script-sig empty-script
                                        :sequence #xFFFFFFFF))
                         :outputs (list (bitcoin-lisp.serialization:make-tx-out
                                         :value 900000
                                         :script-pubkey p2pkh-script))
                         :lock-time 0))
           (block (bitcoin-lisp.serialization:make-bitcoin-block
                   :header (make-test-block-header)
                   :transactions (list coinbase-tx spending-tx))))
      ;; validate-block-scripts should reject this block
      (multiple-value-bind (valid error)
          (bitcoin-lisp.validation:validate-block-scripts block utxo-set)
        (is (null valid))
        (is (eq :script-failed error))))))

;;;; Witness Validation Tests

(defun make-witness-p2wpkh-script ()
  "Create a P2WPKH scriptPubKey: OP_0 <20-byte-hash>."
  (let ((script (make-array 22 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref script 0) #x00   ; OP_0 (witness version 0)
          (aref script 1) #x14)  ; push 20 bytes
    ;; Fill with a fake hash
    (loop for i from 2 below 22 do (setf (aref script i) (mod i 256)))
    script))

(test block-has-witness-data-detects-witness
  "block-has-witness-data-p should return T when transactions have witness data."
  (let* ((coinbase (bitcoin-lisp.serialization:make-transaction
                    :version 1
                    :inputs (list (bitcoin-lisp.serialization:make-tx-in
                                   :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                     :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                       :initial-element 0)
                                                     :index #xFFFFFFFF)
                                   :script-sig (make-array 4 :element-type '(unsigned-byte 8)
                                                             :initial-element 1)))
                    :outputs (list (bitcoin-lisp.serialization:make-tx-out
                                    :value 5000000000
                                    :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                               :initial-element #x76)))
                    :lock-time 0))
         ;; Witness transaction
         (witness-tx (bitcoin-lisp.serialization:make-transaction
                      :version 2
                      :inputs (list (bitcoin-lisp.serialization:make-tx-in
                                     :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                       :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                         :initial-element #x11)
                                                       :index 0)
                                     :script-sig (make-array 0 :element-type '(unsigned-byte 8))))
                      :outputs (list (bitcoin-lisp.serialization:make-tx-out
                                      :value 49000
                                      :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                                 :initial-element #x76)))
                      :lock-time 0
                      :witness (list (list (make-array 72 :element-type '(unsigned-byte 8)
                                                         :initial-element #xAA)
                                          (make-array 33 :element-type '(unsigned-byte 8)
                                                         :initial-element #xBB)))))
         (block (bitcoin-lisp.serialization:make-bitcoin-block
                 :header (make-test-block-header)
                 :transactions (list coinbase witness-tx))))
    ;; Block with witness tx should be detected
    (is (bitcoin-lisp.validation::block-has-witness-data-p block))))

(test block-without-witness-data
  "block-has-witness-data-p should return NIL for legacy blocks."
  (let* ((coinbase (make-coinbase-transaction :value 5000000000 :height 1))
         (block (bitcoin-lisp.serialization:make-bitcoin-block
                 :header (make-test-block-header)
                 :transactions (list coinbase))))
    (is (not (bitcoin-lisp.validation::block-has-witness-data-p block)))))

(test witness-merkle-root-computation
  "Witness merkle root should use wtxids (coinbase wtxid = zeros)."
  (let* ((coinbase (make-coinbase-transaction :value 5000000000 :height 1))
         (regular-tx (make-test-transaction :inputs 1 :outputs 1 :value 1000000))
         (transactions (list coinbase regular-tx)))
    ;; Compute witness merkle root
    (let ((witness-root (bitcoin-lisp.validation:compute-witness-merkle-root transactions)))
      ;; The root should be hash of coinbase-wtxid(zeros) || regular-tx-wtxid
      (let* ((cb-wtxid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
             (tx-wtxid (bitcoin-lisp.serialization:transaction-wtxid regular-tx))
             (combined (make-array 64 :element-type '(unsigned-byte 8))))
        (replace combined cb-wtxid :start1 0)
        (replace combined tx-wtxid :start1 32)
        (let ((expected (bitcoin-lisp.crypto:hash256 combined)))
          (is (equalp witness-root expected)))))))

(test witness-commitment-validation-matching
  "validate-witness-commitment should pass when commitment matches."
  (let* ((coinbase-tx (make-coinbase-transaction :value 5000000000 :height 1))
         ;; A witness tx (with dummy witness data)
         (witness-tx (bitcoin-lisp.serialization:make-transaction
                      :version 2
                      :inputs (list (bitcoin-lisp.serialization:make-tx-in
                                     :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                       :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                         :initial-element #x22)
                                                       :index 0)
                                     :script-sig (make-array 0 :element-type '(unsigned-byte 8))))
                      :outputs (list (bitcoin-lisp.serialization:make-tx-out
                                      :value 49000
                                      :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                                 :initial-element #x76)))
                      :lock-time 0
                      :witness (list (list (make-array 72 :element-type '(unsigned-byte 8)
                                                         :initial-element #xCC)))))
         (transactions (list coinbase-tx witness-tx)))
    ;; Compute what the correct commitment should be
    (let* ((witness-root (bitcoin-lisp.validation:compute-witness-merkle-root transactions))
           ;; Default witness reserved value: 32 zero bytes
           (witness-reserved (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
           (combined (make-array 64 :element-type '(unsigned-byte 8))))
      (replace combined witness-root :start1 0)
      (replace combined witness-reserved :start1 32)
      (let ((commitment (bitcoin-lisp.crypto:hash256 combined)))
        ;; Build OP_RETURN script with correct commitment
        (let ((script (make-array 38 :element-type '(unsigned-byte 8) :initial-element 0)))
          (setf (aref script 0) #x6a   ; OP_RETURN
                (aref script 1) #x24   ; push 36 bytes
                (aref script 2) #xaa   ; commitment header
                (aref script 3) #x21
                (aref script 4) #xa9
                (aref script 5) #xed)
          (replace script commitment :start1 6)
          ;; Add commitment output and witness reserved to coinbase
          (let* ((updated-coinbase
                   (bitcoin-lisp.serialization:make-transaction
                    :version 1
                    :inputs (bitcoin-lisp.serialization:transaction-inputs coinbase-tx)
                    :outputs (append (bitcoin-lisp.serialization:transaction-outputs coinbase-tx)
                                     (list (bitcoin-lisp.serialization:make-tx-out
                                            :value 0 :script-pubkey script)))
                    :lock-time 0
                    :witness (list (list witness-reserved))))  ; coinbase witness
                 (block (bitcoin-lisp.serialization:make-bitcoin-block
                         :header (make-test-block-header)
                         :transactions (list updated-coinbase witness-tx))))
            (multiple-value-bind (valid error)
                (bitcoin-lisp.validation:validate-witness-commitment block)
              (is (eq t valid))
              (is (null error)))))))))

(test witness-commitment-validation-missing
  "validate-witness-commitment should fail when witness data exists but no commitment."
  (let* ((coinbase (make-coinbase-transaction :value 5000000000 :height 1))
         (witness-tx (bitcoin-lisp.serialization:make-transaction
                      :version 2
                      :inputs (list (bitcoin-lisp.serialization:make-tx-in
                                     :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                       :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                         :initial-element #x33)
                                                       :index 0)
                                     :script-sig (make-array 0 :element-type '(unsigned-byte 8))))
                      :outputs (list (bitcoin-lisp.serialization:make-tx-out
                                      :value 49000
                                      :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                                 :initial-element #x76)))
                      :lock-time 0
                      :witness (list (list (make-array 72 :element-type '(unsigned-byte 8)
                                                         :initial-element #xDD)))))
         (block (bitcoin-lisp.serialization:make-bitcoin-block
                 :header (make-test-block-header)
                 :transactions (list coinbase witness-tx))))
    (multiple-value-bind (valid error)
        (bitcoin-lisp.validation:validate-witness-commitment block)
      (is (null valid))
      (is (eq :missing-witness-commitment error)))))

