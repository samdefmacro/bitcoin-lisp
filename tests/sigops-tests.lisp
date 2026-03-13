(in-package #:bitcoin-lisp.tests)

(in-suite :sigops-tests)

;;;; Helper: build raw script byte vectors

(defun make-script (&rest bytes)
  "Create a script byte vector from BYTES."
  (make-array (length bytes) :element-type '(unsigned-byte 8)
                             :initial-contents bytes))

(defun make-p2pkh-script (hash-bytes)
  "Create a P2PKH scriptPubKey: OP_DUP OP_HASH160 <20> hash OP_EQUALVERIFY OP_CHECKSIG."
  (let ((script (make-array 25 :element-type '(unsigned-byte 8))))
    (setf (aref script 0) #x76    ; OP_DUP
          (aref script 1) #xa9    ; OP_HASH160
          (aref script 2) #x14)   ; Push 20 bytes
    (replace script hash-bytes :start1 3 :end1 23)
    (setf (aref script 23) #x88   ; OP_EQUALVERIFY
          (aref script 24) #xac)  ; OP_CHECKSIG
    script))

(defun make-p2sh-script (hash-bytes)
  "Create a P2SH scriptPubKey: OP_HASH160 <20> hash OP_EQUAL."
  (let ((script (make-array 23 :element-type '(unsigned-byte 8))))
    (setf (aref script 0) #xa9    ; OP_HASH160
          (aref script 1) #x14)   ; Push 20 bytes
    (replace script hash-bytes :start1 2 :end1 22)
    (setf (aref script 22) #x87)  ; OP_EQUAL
    script))

(defun make-p2wpkh-script (hash-bytes)
  "Create a P2WPKH scriptPubKey: OP_0 <20> hash."
  (let ((script (make-array 22 :element-type '(unsigned-byte 8))))
    (setf (aref script 0) #x00    ; OP_0
          (aref script 1) #x14)   ; Push 20 bytes
    (replace script hash-bytes :start1 2 :end1 22)
    script))

(defun make-p2wsh-script (hash-bytes)
  "Create a P2WSH scriptPubKey: OP_0 <32> hash."
  (let ((script (make-array 34 :element-type '(unsigned-byte 8))))
    (setf (aref script 0) #x00    ; OP_0
          (aref script 1) #x20)   ; Push 32 bytes
    (replace script hash-bytes :start1 2 :end1 34)
    script))

(defun make-dummy-hash (byte-val size)
  (make-array size :element-type '(unsigned-byte 8) :initial-element byte-val))

;;;; Task 5.1: Unit tests for count-script-sigops

(test empty-script-zero-sigops
  "Empty script has zero sigops."
  (is (= 0 (bitcoin-lisp.validation:count-script-sigops
             (make-array 0 :element-type '(unsigned-byte 8))))))

(test checksig-counts-as-one
  "OP_CHECKSIG counts as 1 sigop."
  (is (= 1 (bitcoin-lisp.validation:count-script-sigops
             (make-script #xac)))))

(test checksigverify-counts-as-one
  "OP_CHECKSIGVERIFY counts as 1 sigop."
  (is (= 1 (bitcoin-lisp.validation:count-script-sigops
             (make-script #xad)))))

(test multiple-checksigs
  "Multiple OP_CHECKSIG opcodes are summed."
  (is (= 3 (bitcoin-lisp.validation:count-script-sigops
             (make-script #xac #xac #xac)))))

(test checkmultisig-inaccurate-counts-20
  "OP_CHECKMULTISIG counts as 20 in inaccurate mode."
  ;; OP_3 <keys> OP_3 OP_CHECKMULTISIG - but inaccurate ignores preceding opcode
  (is (= 20 (bitcoin-lisp.validation:count-script-sigops
              (make-script #x53 #xae)))))

(test checkmultisig-accurate-uses-preceding-opcode
  "OP_CHECKMULTISIG uses preceding OP_n in accurate mode."
  ;; OP_3 OP_CHECKMULTISIG = 3 sigops (accurate)
  (is (= 3 (bitcoin-lisp.validation:count-script-sigops
             (make-script #x53 #xae) :accurate t))))

(test checkmultisig-accurate-op1
  "OP_1 OP_CHECKMULTISIG = 1 sigop in accurate mode."
  (is (= 1 (bitcoin-lisp.validation:count-script-sigops
             (make-script #x51 #xae) :accurate t))))

(test checkmultisig-accurate-op16
  "OP_16 OP_CHECKMULTISIG = 16 sigops in accurate mode."
  (is (= 16 (bitcoin-lisp.validation:count-script-sigops
              (make-script #x60 #xae) :accurate t))))

(test checkmultisig-accurate-no-preceding-small-int
  "OP_CHECKMULTISIG without preceding OP_n counts as 20 even in accurate mode."
  (is (= 20 (bitcoin-lisp.validation:count-script-sigops
              (make-script #x00 #xae) :accurate t))))

(test checkmultisigverify-inaccurate
  "OP_CHECKMULTISIGVERIFY counts as 20 in inaccurate mode."
  (is (= 20 (bitcoin-lisp.validation:count-script-sigops
              (make-script #x53 #xaf)))))

(test checkmultisigverify-accurate
  "OP_CHECKMULTISIGVERIFY uses preceding OP_n in accurate mode."
  (is (= 3 (bitcoin-lisp.validation:count-script-sigops
             (make-script #x53 #xaf) :accurate t))))

(test push-data-skips-sigop-bytes
  "Push data correctly skips over bytes that look like sigops."
  ;; Push 2 bytes [OP_CHECKSIG, OP_CHECKSIG] then actual OP_CHECKSIG
  ;; Only the final OP_CHECKSIG should count
  (is (= 1 (bitcoin-lisp.validation:count-script-sigops
             (make-script #x02 #xac #xac #xac)))))

(test p2pkh-script-sigops
  "P2PKH scriptPubKey has 1 sigop (the OP_CHECKSIG)."
  (is (= 1 (bitcoin-lisp.validation:count-script-sigops
             (make-p2pkh-script (make-dummy-hash #xaa 20))))))

;;;; Task 5.2: Unit tests for count-transaction-sigops-cost

(defun make-sigops-test-tx (&key (script-sig (make-array 0 :element-type '(unsigned-byte 8)))
                              (script-pubkey (make-array 0 :element-type '(unsigned-byte 8)))
                              witness)
  "Create a test transaction with one input and one output."
  (let* ((input (bitcoin-lisp.serialization:make-tx-in
                 :previous-output (bitcoin-lisp.serialization:make-outpoint
                                   :hash (make-dummy-hash #x01 32)
                                   :index 0)
                 :script-sig script-sig
                 :sequence #xFFFFFFFF))
         (output (bitcoin-lisp.serialization:make-tx-out
                  :value 50000000
                  :script-pubkey script-pubkey)))
    (bitcoin-lisp.serialization:make-transaction
     :version 1
     :inputs (list input)
     :outputs (list output)
     :lock-time 0
     :witness (when witness (list witness)))))

(test p2pkh-transaction-sigops-cost
  "P2PKH transaction: 1 OP_CHECKSIG in scriptPubKey => cost = 1 * 4 = 4."
  (let* ((spent-script-pubkey (make-p2pkh-script (make-dummy-hash #xaa 20)))
         (tx (make-sigops-test-tx
              :script-sig (make-script #x00)
              :script-pubkey (make-p2pkh-script (make-dummy-hash #xbb 20))))
         (get-spent (lambda (txid index)
                      (declare (ignore txid index))
                      spent-script-pubkey)))
    ;; Legacy: 1 (output scriptPubKey OP_CHECKSIG) + 0 (scriptSig) = 1 from output
    ;; Plus 1 from the spent scriptPubKey counted via input... no, legacy counts
    ;; the tx's own scriptSig and scriptPubKey, not the spent output.
    ;; Legacy counts: scriptSig has no sigops, output scriptPubKey has 1 OP_CHECKSIG = 1
    ;; P2SH: spent scriptPubKey is P2PKH, not P2SH, so 0
    ;; Witness: not a witness program, so 0
    ;; Cost = (1 + 0) * 4 + 0 = 4
    (is (= 4 (bitcoin-lisp.validation:count-transaction-sigops-cost tx get-spent)))))

(test p2wpkh-transaction-sigops-cost
  "Native P2WPKH transaction: witness sigops = 1, cost = 1."
  (let* ((spent-script-pubkey (make-p2wpkh-script (make-dummy-hash #xaa 20)))
         (tx (make-sigops-test-tx
              :script-sig (make-array 0 :element-type '(unsigned-byte 8))
              :script-pubkey (make-p2pkh-script (make-dummy-hash #xbb 20))
              :witness (list (make-dummy-hash #xcc 72))))
         (get-spent (lambda (txid index)
                      (declare (ignore txid index))
                      spent-script-pubkey)))
    ;; Legacy: output scriptPubKey (P2PKH) has 1 OP_CHECKSIG = 1
    ;; P2SH: not P2SH, 0
    ;; Witness: P2WPKH = 1
    ;; Cost = (1 + 0) * 4 + 1 = 5
    (is (= 5 (bitcoin-lisp.validation:count-transaction-sigops-cost tx get-spent)))))

(test p2sh-wrapped-p2wpkh-sigops-cost
  "P2SH-P2WPKH: witness sigops = 1, redeemScript (witness program) has 0 script sigops."
  (let* ((p2wpkh-redeem (make-p2wpkh-script (make-dummy-hash #xaa 20)))
         ;; scriptSig pushes the redeemScript (the P2WPKH program)
         (script-sig (let ((rs-len (length p2wpkh-redeem)))
                       (concatenate '(vector (unsigned-byte 8))
                                    (vector rs-len)
                                    p2wpkh-redeem)))
         (spent-script-pubkey (make-p2sh-script (make-dummy-hash #xbb 20)))
         (tx (make-sigops-test-tx
              :script-sig script-sig
              :script-pubkey (make-p2pkh-script (make-dummy-hash #xcc 20))
              :witness (list (make-dummy-hash #xdd 72))))
         (get-spent (lambda (txid index)
                      (declare (ignore txid index))
                      spent-script-pubkey)))
    ;; Legacy: output has 1 OP_CHECKSIG, scriptSig has 0 = 1
    ;; P2SH: redeemScript is a witness program (no sigops in script bytes) = 0
    ;; Witness: P2SH-wrapped P2WPKH = 1
    ;; Cost = (1 + 0) * 4 + 1 = 5
    (is (= 5 (bitcoin-lisp.validation:count-transaction-sigops-cost tx get-spent)))))

(test bare-multisig-sigops-cost
  "Bare 2-of-3 multisig: legacy counts OP_CHECKMULTISIG as 20."
  (let* ((multisig-script (make-script #x52    ; OP_2
                                       #x21    ; Push 33 bytes (pubkey1)
                                       #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00
                                       #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00
                                       #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00
                                       #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00
                                       #x00
                                       #x21    ; Push 33 bytes (pubkey2)
                                       #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00
                                       #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00
                                       #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00
                                       #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00
                                       #x00
                                       #x21    ; Push 33 bytes (pubkey3)
                                       #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00
                                       #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00
                                       #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00
                                       #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00
                                       #x00
                                       #x53    ; OP_3
                                       #xae))  ; OP_CHECKMULTISIG
         ;; Spent output has the bare multisig
         (spent-script-pubkey multisig-script)
         (tx (make-sigops-test-tx
              :script-sig (make-script #x00)
              :script-pubkey (make-array 0 :element-type '(unsigned-byte 8))))
         (get-spent (lambda (txid index)
                      (declare (ignore txid index))
                      spent-script-pubkey)))
    ;; Legacy: scriptSig=0, output scriptPubKey=0 (empty), BUT the tx output is empty
    ;; The spent output's script isn't part of legacy counting (only the tx's own scripts)
    ;; Legacy counts the tx's scriptSig (0 sigops) and output scriptPubKey (0 sigops)
    ;; P2SH: spent output is not P2SH = 0
    ;; Witness: not a witness program = 0
    ;; Cost = 0 * 4 + 0 = 0
    ;; NOTE: The multisig is in the *spent* output, which isn't in this tx's scripts.
    ;; Legacy counts are from the tx's OWN scriptSigs and scriptPubKeys.
    (is (= 0 (bitcoin-lisp.validation:count-transaction-sigops-cost tx get-spent)))))

(test p2sh-multisig-sigops-cost
  "P2SH 2-of-3 multisig: P2SH counts accurately from redeemScript."
  (let* ((multisig-redeem (make-script #x52    ; OP_2
                                       #x21    ; Push 33 bytes (pubkey1)
                                       #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00
                                       #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00
                                       #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00
                                       #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00
                                       #x00
                                       #x21    ; Push 33 bytes (pubkey2)
                                       #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00
                                       #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00
                                       #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00
                                       #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00
                                       #x00
                                       #x21    ; Push 33 bytes (pubkey3)
                                       #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00
                                       #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00
                                       #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00
                                       #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00
                                       #x00
                                       #x53    ; OP_3
                                       #xae))  ; OP_CHECKMULTISIG
         ;; scriptSig: push the redeemScript
         (rs-len (length multisig-redeem))
         (script-sig (concatenate '(vector (unsigned-byte 8))
                                  (make-script #x4c rs-len)  ; OP_PUSHDATA1
                                  multisig-redeem))
         (spent-script-pubkey (make-p2sh-script (make-dummy-hash #xbb 20)))
         (tx (make-sigops-test-tx
              :script-sig script-sig
              :script-pubkey (make-array 0 :element-type '(unsigned-byte 8))))
         (get-spent (lambda (txid index)
                      (declare (ignore txid index))
                      spent-script-pubkey)))
    ;; Legacy: scriptSig push-data skips redeemScript bytes=0, output=0 => 0
    ;; P2SH: redeemScript is multisig, accurate count: preceding OP_3 => 3
    ;; Witness: not witness, 0
    ;; Cost = (0 + 3) * 4 + 0 = 12
    (is (= 12 (bitcoin-lisp.validation:count-transaction-sigops-cost tx get-spent)))))

(test witness-scale-factor-constant
  "Witness scale factor is 4."
  (is (= 4 bitcoin-lisp.validation:+witness-scale-factor+)))

(test max-block-sigops-cost-constant
  "Max block sigops cost is 80,000."
  (is (= 80000 bitcoin-lisp.validation:+max-block-sigops-cost+)))
