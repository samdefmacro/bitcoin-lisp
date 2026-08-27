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
  (is (= 0 (bl.val:count-script-sigops
             (make-array 0 :element-type '(unsigned-byte 8))))))

(test checksig-counts-as-one
  "OP_CHECKSIG counts as 1 sigop."
  (is (= 1 (bl.val:count-script-sigops
             (make-script #xac)))))

(test checksigverify-counts-as-one
  "OP_CHECKSIGVERIFY counts as 1 sigop."
  (is (= 1 (bl.val:count-script-sigops
             (make-script #xad)))))

(test multiple-checksigs
  "Multiple OP_CHECKSIG opcodes are summed."
  (is (= 3 (bl.val:count-script-sigops
             (make-script #xac #xac #xac)))))

(test checkmultisig-inaccurate-counts-20
  "OP_CHECKMULTISIG counts as 20 in inaccurate mode."
  ;; OP_3 <keys> OP_3 OP_CHECKMULTISIG - but inaccurate ignores preceding opcode
  (is (= 20 (bl.val:count-script-sigops
              (make-script #x53 #xae)))))

(test checkmultisig-accurate-uses-preceding-opcode
  "OP_CHECKMULTISIG uses preceding OP_n in accurate mode."
  ;; OP_3 OP_CHECKMULTISIG = 3 sigops (accurate)
  (is (= 3 (bl.val:count-script-sigops
             (make-script #x53 #xae) :accurate t))))

(test checkmultisig-accurate-op1
  "OP_1 OP_CHECKMULTISIG = 1 sigop in accurate mode."
  (is (= 1 (bl.val:count-script-sigops
             (make-script #x51 #xae) :accurate t))))

(test checkmultisig-accurate-op16
  "OP_16 OP_CHECKMULTISIG = 16 sigops in accurate mode."
  (is (= 16 (bl.val:count-script-sigops
              (make-script #x60 #xae) :accurate t))))

(test checkmultisig-accurate-no-preceding-small-int
  "OP_CHECKMULTISIG without preceding OP_n counts as 20 even in accurate mode."
  (is (= 20 (bl.val:count-script-sigops
              (make-script #x00 #xae) :accurate t))))

(test checkmultisigverify-inaccurate
  "OP_CHECKMULTISIGVERIFY counts as 20 in inaccurate mode."
  (is (= 20 (bl.val:count-script-sigops
              (make-script #x53 #xaf)))))

(test checkmultisigverify-accurate
  "OP_CHECKMULTISIGVERIFY uses preceding OP_n in accurate mode."
  (is (= 3 (bl.val:count-script-sigops
             (make-script #x53 #xaf) :accurate t))))

(test push-data-skips-sigop-bytes
  "Push data correctly skips over bytes that look like sigops."
  ;; Push 2 bytes [OP_CHECKSIG, OP_CHECKSIG] then actual OP_CHECKSIG
  ;; Only the final OP_CHECKSIG should count
  (is (= 1 (bl.val:count-script-sigops
             (make-script #x02 #xac #xac #xac)))))

(test p2pkh-script-sigops
  "P2PKH scriptPubKey has 1 sigop (the OP_CHECKSIG)."
  (is (= 1 (bl.val:count-script-sigops
             (make-p2pkh-script (make-dummy-hash #xaa 20))))))

;;;; Task 5.2: Unit tests for count-transaction-sigops-cost

(defun make-sigops-test-tx (&key (script-sig (make-array 0 :element-type '(unsigned-byte 8)))
                              (script-pubkey (make-array 0 :element-type '(unsigned-byte 8)))
                              witness)
  "Create a test transaction with one input and one output."
  (let* ((input (bl.ser:make-tx-in
                 :previous-output (bl.ser:make-outpoint
                                   :hash (make-dummy-hash #x01 32)
                                   :index 0)
                 :script-sig script-sig
                 :sequence #xFFFFFFFF))
         (output (bl.ser:make-tx-out
                  :value 50000000
                  :script-pubkey script-pubkey)))
    (bl.ser:make-transaction
     :version 1
     :inputs (vector input)
     :outputs (vector output)
     :lock-time 0
     :witness (when witness (vector witness)))))

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
    (is (= 4 (bl.val:count-transaction-sigops-cost tx get-spent)))))

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
    (is (= 5 (bl.val:count-transaction-sigops-cost tx get-spent)))))

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
    (is (= 5 (bl.val:count-transaction-sigops-cost tx get-spent)))))

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
    (is (= 0 (bl.val:count-transaction-sigops-cost tx get-spent)))))

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
    (is (= 12 (bl.val:count-transaction-sigops-cost tx get-spent)))))

(test sigops-cost-gates-on-activation
  "P2SH/witness sigops are only counted when their flags are active, mirroring
Bitcoin Core's GetTransactionSigOpCost honoring SCRIPT_VERIFY_P2SH/_WITNESS."
  ;; Native P2WPKH input: witness sigops = 1, legacy from P2PKH output = 1.
  (let* ((spent (make-p2wpkh-script (make-dummy-hash #xaa 20)))
         (tx (make-sigops-test-tx
              :script-sig (make-array 0 :element-type '(unsigned-byte 8))
              :script-pubkey (make-p2pkh-script (make-dummy-hash #xbb 20))
              :witness (list (make-dummy-hash #xcc 72))))
         (get-spent (lambda (txid index) (declare (ignore txid index)) spent)))
    ;; witness active: (1+0)*4 + 1 = 5 ; witness inactive: (1+0)*4 + 0 = 4
    (is (= 5 (bl.val:count-transaction-sigops-cost
              tx get-spent :count-witness t)))
    (is (= 4 (bl.val:count-transaction-sigops-cost
              tx get-spent :count-witness nil))))
  ;; P2SH input whose redeemScript is a bare OP_CHECKSIG (accurate p2sh sigops = 1).
  (let* ((redeem (make-script #xac))                 ; OP_CHECKSIG
         (script-sig (make-script #x01 #xac))        ; push the 1-byte redeemScript
         (spent (make-p2sh-script (make-dummy-hash #xbb 20)))
         (tx (make-sigops-test-tx
              :script-sig script-sig
              :script-pubkey (make-array 0 :element-type '(unsigned-byte 8))))
         (get-spent (lambda (txid index) (declare (ignore txid index)) spent)))
    ;; p2sh active: (0+1)*4 + 0 = 4 ; p2sh inactive: (0+0)*4 + 0 = 0
    (is (= 4 (bl.val:count-transaction-sigops-cost
              tx get-spent :count-p2sh t)))
    (is (= 0 (bl.val:count-transaction-sigops-cost
              tx get-spent :count-p2sh nil)))))

(test witness-scale-factor-constant
  "Witness scale factor is 4."
  (is (= 4 bl.val:+witness-scale-factor+)))

(test max-block-sigops-cost-constant
  "Max block sigops cost is 80,000."
  (is (= 80000 bl.val:+max-block-sigops-cost+)))

;;;; P2SH sigop subscript — CScript::GetSigOpCount(const CScript& scriptSig)

(defun %sigop-dense-blob (len)
  "LEN bytes of repeated OP_16 OP_CHECKMULTISIG: 16 accurate sigops per 2 bytes."
  (let ((blob (make-array len :element-type '(unsigned-byte 8))))
    (loop for i from 0 below len by 2
          do (setf (aref blob i) #x60             ; OP_16
                   (aref blob (1+ i)) #xae))      ; OP_CHECKMULTISIG
    blob))

(defun %sigop-pushdata2 (data)
  "OP_PUSHDATA2 <length LE16> DATA."
  (concatenate '(vector (unsigned-byte 8))
               (vector #x4d (ldb (byte 8 0) (length data)) (ldb (byte 8 8) (length data)))
               data))

(defun %sigop-empty-redeem-spk ()
  "P2SH scriptPubKey committing to the EMPTY redeem script."
  (make-p2sh-script (bl.crypto:hash160
                     (make-array 0 :element-type '(unsigned-byte 8)))))

(defun %sigop-empty-redeem-script-sig ()
  "Spends %SIGOP-EMPTY-REDEEM-SPK: a 520-byte sigop-dense push (the leftover the
empty redeem script leaves truthy on the stack) followed by OP_0, the empty
redeem script itself."
  (concatenate '(vector (unsigned-byte 8))
               (%sigop-pushdata2 (%sigop-dense-blob 520))
               (vector #x00)))

(test p2sh-sigop-subscript-cleared-by-small-int-opcodes
  "Core's GetScriptOp clears its data buffer for EVERY opcode and refills it only
for opcode <= OP_PUSHDATA4 (script.cpp:313-359), so a trailing OP_0, OP_1NEGATE,
OP_RESERVED or OP_1..OP_16 leaves an EMPTY subscript rather than the preceding
push — while still not tripping the opcode > OP_16 early-out."
  (let ((blob (%sigop-dense-blob 520)))
    (flet ((expect-empty-subscript (script-sig)
             (let ((subscript (bl.val::p2sh-sigop-subscript script-sig)))
               (is (not (null subscript)))
               (is (zerop (length subscript))))))
      ;; The push alone is the subscript when it really is the last opcode.
      (is (equalp blob (bl.val::p2sh-sigop-subscript
                        (%sigop-pushdata2 blob))))
      ;; OP_0 is a zero-length push; OP_1NEGATE/OP_RESERVED/OP_1/OP_16 are above
      ;; OP_PUSHDATA4 and refill nothing. All five clear the subscript.
      (dolist (op '(#x00 #x4f #x50 #x51 #x60))
        (expect-empty-subscript (concatenate '(vector (unsigned-byte 8))
                                             (%sigop-pushdata2 blob) (vector op))))
      ;; An empty scriptSig is push-only with an empty subscript, not a failure.
      (expect-empty-subscript (make-array 0 :element-type '(unsigned-byte 8))))))

(test p2sh-sigop-subscript-nil-when-not-push-only
  "GetSigOpCount(scriptSig) returns 0 on any GetOp failure or any opcode above
OP_16 (script.cpp:183-205) — the same condition as IsPushOnly (script.cpp:266-281),
so NIL is both the zero-sigop answer and the gate CountWitnessSigOps needs."
  (flet ((subscript-of (&rest bytes)
           (bl.val::p2sh-sigop-subscript (apply #'make-script bytes))))
    ;; OP_NOP (#x61) is one above OP_16.
    (is (null (subscript-of #x01 #x51 #x61)))
    (is (null (subscript-of #xac)))
    ;; Truncated direct push: claims 5 bytes, supplies 2.
    (is (null (subscript-of #x05 #xaa #xbb)))
    ;; OP_PUSHDATA1 with no length byte.
    (is (null (subscript-of #x4c)))
    ;; OP_PUSHDATA2 claiming 520 bytes with one supplied.
    (is (null (subscript-of #x4d #x08 #x02 #xaa)))
    ;; OP_PUSHDATA4 with a truncated length field.
    (is (null (subscript-of #x4e #x01 #x00 #x00)))))

(test p2sh-empty-redeem-script-costs-no-sigops
  "S1-5: a P2SH output committing to the empty redeem script, spent with
<520 sigop-dense bytes> OP_0, costs Core zero sigops. Counting the 520-byte
leftover instead charged 4,160 sigops (16,640 weighted) per input."
  (let* ((spent (%sigop-empty-redeem-spk))
         (tx (make-sigops-test-tx
              :script-sig (%sigop-empty-redeem-script-sig)
              :script-pubkey (make-array 0 :element-type '(unsigned-byte 8))))
         (get-spent (lambda (txid index) (declare (ignore txid index)) spent)))
    ;; Not vacuous: the leftover blob really is worth 4,160 accurate sigops.
    (is (= 4160 (bl.val:count-script-sigops
                 (%sigop-dense-blob 520) :accurate t)))
    (is (= 0 (bl.val:count-transaction-sigops-cost tx get-spent)))))

(test p2sh-wrapped-witness-sigops-need-push-only-script-sig
  "CountWitnessSigOps only looks inside a P2SH scriptSig when it IsPushOnly
(interpreter.cpp:2152-2163). A trailing OP_NOP makes Core charge nothing; the
last-push extractor found the witness program regardless and charged 1."
  (let* ((program (make-p2wpkh-script (make-dummy-hash #xaa 20)))
         (canonical-push (concatenate '(vector (unsigned-byte 8))
                                      (vector (length program)) program))
         (spent (make-p2sh-script (make-dummy-hash #xbb 20)))
         (get-spent (lambda (txid index) (declare (ignore txid index)) spent)))
    (flet ((witness-spend (script-sig)
             (make-sigops-test-tx
              :script-sig script-sig
              :script-pubkey (make-array 0 :element-type '(unsigned-byte 8))
              :witness (list (make-dummy-hash #xcc 72)))))
      ;; OP_NOP after the push makes the scriptSig non-push-only.
      (is (= 0 (bl.val:count-transaction-sigops-cost
                (witness-spend (concatenate '(vector (unsigned-byte 8))
                                            canonical-push (vector #x61)))
                get-spent)))
      ;; Control: drop the OP_NOP and the wrapped P2WPKH costs its 1 witness sigop.
      (is (= 1 (bl.val:count-transaction-sigops-cost
                (witness-spend canonical-push) get-spent))))))

(test p2sh-empty-redeem-script-within-standard-sigops-cost
  "The standardness cap MAX_STANDARD_TX_SIGOPS_COST is fed by the same count, so
the over-count also made us refuse to relay a transaction Core relays. The input
stays nonstandard for an unrelated reason — the per-input MAX_P2SH_SIGOPS gate
keeps its own policy last-push extraction."
  (let* ((mempool (bl.mp:make-mempool))
         (utxo (bl.store:make-utxo-set))
         (funding (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x5a))
         (tx (bl.ser:make-transaction
              :version 2
              :inputs (vector (bl.ser:make-tx-in
                               :previous-output (bl.ser:make-outpoint
                                                 :hash funding :index 0)
                               :script-sig (%sigop-empty-redeem-script-sig)
                               :sequence #xffffffff))
              :outputs (vector (bl.ser:make-tx-out
                                :value 95000 :script-pubkey (%p2sh-optrue-spk)))
              :lock-time 0)))
    (bl.store:add-utxo utxo funding 0 100000 (%sigop-empty-redeem-spk) 1
                                   :coinbase nil)
    ;; Not vacuous: one such input was worth 16,640 weighted sigops, above the cap.
    (is (> 16640 bl.val::+max-standard-tx-sigops-cost+))
    (multiple-value-bind (valid err)
        (bl.val:validate-transaction-for-mempool tx utxo mempool 100)
      (is (null valid))
      (is (eq :nonstandard-inputs err)))))

(test block-with-empty-redeem-p2sh-inputs-is-accepted
  "Five such inputs in one block are 83,200 weighted sigops under the last-push
extractor — past MAX_BLOCK_SIGOPS_COST — so we rejected :too-many-sigops a block
Core fully validates. A pure chain split: our own script engine accepts the
spends, which this block proves by validating with scripts on."
  (%with-regtest
   (let* ((node (%regtest-node-fixture "sigop-p2sh"))
          (cs (bl::node-chain-state node))
          (utxo (bl::node-utxo-set node))
          (mempool (bl::node-mempool node))
          (spk (%sigop-empty-redeem-spk))
          (funding (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x5a)))
     (dotimes (idx 5)
       (bl.store:add-utxo utxo funding idx 100000 spk 0 :coinbase nil))
     (let ((tx (bl.ser:make-transaction
                :version 1
                :inputs (coerce (loop for idx from 0 below 5
                                      collect (bl.ser:make-tx-in
                                               :previous-output
                                               (bl.ser:make-outpoint
                                                :hash funding :index idx)
                                               :script-sig (%sigop-empty-redeem-script-sig)
                                               :sequence #xffffffff))
                                'vector)
                :outputs (vector (bl.ser:make-tx-out
                                  :value 499000 :script-pubkey (%p2sh-optrue-spk)))
                :lock-time 0)))
       ;; Not vacuous: the old count for these five inputs exceeds the budget.
       (is (> (* 5 4 (bl.val:count-script-sigops
                      (%sigop-dense-blob 520) :accurate t))
              bl.val:+max-block-sigops-cost+))
       (%mine-add-entry mempool tx 1000)
       (let ((block (bl.mining:assemble-full-block
                     cs mempool :coinbase-script-pubkey (%p2sh-optrue-spk))))
         (bl.mining:mine-block block)
         (is (= 2 (length (bl.ser:bitcoin-block-transactions block))))
         (multiple-value-bind (valid err)
             (bl.val:validate-block
              block cs utxo 1 (bl.ser:get-unix-time))
           (is (null err))
           (is-true valid)))))))
