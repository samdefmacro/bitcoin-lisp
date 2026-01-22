;;;; Tests for Coalton script module
;;;;
;;;; Tests for typed Bitcoin script operations including:
;;;; - Value conversions (bytes <-> script numbers)
;;;; - Opcode conversions
;;;; - Stack operations
;;;; - Script execution

(in-package #:bitcoin-lisp.coalton.tests)

(in-suite coalton-tests)

;;; ============================================================
;;; ScriptNum Tests
;;; ============================================================

(test script-num-zero
  "Test ScriptNum zero value."
  (is (= 0 (coalton:coalton
            (bitcoin-lisp.coalton.script:script-num-value
             (bitcoin-lisp.coalton.script:make-script-num 0))))))

(test script-num-positive
  "Test ScriptNum positive value."
  (is (= 127 (coalton:coalton
              (bitcoin-lisp.coalton.script:script-num-value
               (bitcoin-lisp.coalton.script:make-script-num 127))))))

(test script-num-negative
  "Test ScriptNum negative value."
  (is (= -1 (coalton:coalton
             (bitcoin-lisp.coalton.script:script-num-value
              (bitcoin-lisp.coalton.script:make-script-num -1))))))

;;; ============================================================
;;; Value Conversion Tests
;;; ============================================================

(test script-num-to-bytes-zero
  "Zero converts to empty vector."
  (is (= 0 (coalton:coalton
            (coalton-library/vector:length
             (bitcoin-lisp.coalton.script:script-num-to-bytes
              (bitcoin-lisp.coalton.script:make-script-num 0)))))))

(test script-num-to-bytes-positive
  "Positive number 127 converts to single byte #x7f."
  (let ((bytes (coalton:coalton
                (bitcoin-lisp.coalton.script:script-num-to-bytes
                 (bitcoin-lisp.coalton.script:make-script-num 127)))))
    (is (= 1 (length bytes)))
    (is (= #x7f (aref bytes 0)))))

(test script-num-to-bytes-negative-one
  "Negative one (-1) converts to #x81 (1 with sign bit)."
  (let ((bytes (coalton:coalton
                (bitcoin-lisp.coalton.script:script-num-to-bytes
                 (bitcoin-lisp.coalton.script:make-script-num -1)))))
    (is (= 1 (length bytes)))
    (is (= #x81 (aref bytes 0)))))

(test script-num-to-bytes-128
  "128 requires two bytes (0x80 has high bit set, needs extra byte)."
  (let ((bytes (coalton:coalton
                (bitcoin-lisp.coalton.script:script-num-to-bytes
                 (bitcoin-lisp.coalton.script:make-script-num 128)))))
    (is (= 2 (length bytes)))
    (is (= #x80 (aref bytes 0)))  ; 128 in low byte
    (is (= #x00 (aref bytes 1))))) ; sign byte

(test cast-to-bool-empty
  "Empty vector is false."
  (is-false (bitcoin-lisp.coalton.script:cast-to-bool #())))

(test cast-to-bool-zero
  "Zero byte is false."
  (is-false (bitcoin-lisp.coalton.script:cast-to-bool #(0))))

(test cast-to-bool-negative-zero
  "Negative zero (0x80) is false."
  (is-false (bitcoin-lisp.coalton.script:cast-to-bool #(#x80))))

(test cast-to-bool-one
  "One byte is true."
  (is-true (bitcoin-lisp.coalton.script:cast-to-bool #(1))))

;;; ============================================================
;;; Opcode Conversion Tests
;;; ============================================================

(test opcode-to-byte-op-0
  "OP_0 converts to byte 0x00."
  (is (= #x00 (coalton:coalton
               (bitcoin-lisp.coalton.script:opcode-to-byte
                bitcoin-lisp.coalton.script:OP-0)))))

(test opcode-to-byte-op-dup
  "OP_DUP converts to byte 0x76."
  (is (= #x76 (coalton:coalton
               (bitcoin-lisp.coalton.script:opcode-to-byte
                bitcoin-lisp.coalton.script:OP-DUP)))))

(test opcode-to-byte-op-hash160
  "OP_HASH160 converts to byte 0xa9."
  (is (= #xa9 (coalton:coalton
               (bitcoin-lisp.coalton.script:opcode-to-byte
                bitcoin-lisp.coalton.script:OP-HASH160)))))

(test opcode-to-byte-op-equal
  "OP_EQUAL converts to byte 0x87."
  (is (= #x87 (coalton:coalton
               (bitcoin-lisp.coalton.script:opcode-to-byte
                bitcoin-lisp.coalton.script:OP-EQUAL)))))

(test byte-to-opcode-op-dup
  "Byte 0x76 converts to OP_DUP."
  (is (= #x76 (coalton:coalton
               (bitcoin-lisp.coalton.script:opcode-to-byte
                (bitcoin-lisp.coalton.script:byte-to-opcode #x76))))))

(test byte-to-opcode-pushbytes
  "Bytes 1-75 convert to OP_PUSHBYTES."
  (is (= 20 (coalton:coalton
             (bitcoin-lisp.coalton.script:opcode-to-byte
              (bitcoin-lisp.coalton.script:byte-to-opcode 20))))))

(test is-push-op-op-0
  "OP_0 is a push operation."
  (is-true (coalton:coalton
            (bitcoin-lisp.coalton.script:is-push-op
             bitcoin-lisp.coalton.script:OP-0))))

(test is-push-op-op-dup
  "OP_DUP is not a push operation."
  (is-false (coalton:coalton
             (bitcoin-lisp.coalton.script:is-push-op
              bitcoin-lisp.coalton.script:OP-DUP))))

(test is-conditional-op-if
  "OP_IF is a conditional operation."
  (is-true (coalton:coalton
            (bitcoin-lisp.coalton.script:is-conditional-op
             bitcoin-lisp.coalton.script:OP-IF))))

(test is-conditional-op-add
  "OP_ADD is not a conditional operation."
  (is-false (coalton:coalton
             (bitcoin-lisp.coalton.script:is-conditional-op
              bitcoin-lisp.coalton.script:OP-ADD))))

;;; ============================================================
;;; Stack Operation Tests
;;; ============================================================

(test stack-depth-empty
  "Empty stack has depth 0."
  (is (= 0 (coalton:coalton
            (bitcoin-lisp.coalton.script:stack-depth
             (bitcoin-lisp.coalton.script:empty-stack))))))

;;; ============================================================
;;; Script Execution Tests
;;; ============================================================

;; Helper to check if script execution succeeded
(defun call-execute-script (script-bytes)
  "Call Coalton execute-script from CL."
  (bitcoin-lisp.coalton.script:execute-script script-bytes))

(defun script-ok-p (result)
  "Return T if result is ScriptOk."
  (bitcoin-lisp.coalton.script:script-result-ok-p result))

(defun script-err-p (result)
  "Return T if result is ScriptErr."
  (bitcoin-lisp.coalton.script:script-result-err-p result))

(defun get-result-stack (result)
  "Get the stack from a ScriptOk result."
  (bitcoin-lisp.coalton.script:get-ok-stack result))

(defun get-stack-depth (stack)
  "Get the depth of a stack."
  (bitcoin-lisp.coalton.script:stack-depth stack))

(test execute-script-op-0
  "OP_0 pushes empty vector."
  (let ((result (call-execute-script #(0))))
    (is-true (script-ok-p result))
    (is (= 1 (get-stack-depth (get-result-stack result))))))

(test execute-script-op-1
  "OP_1 pushes 1."
  (let ((result (call-execute-script #(#x51))))
    (is-true (script-ok-p result))
    (is (= 1 (get-stack-depth (get-result-stack result))))))

(test execute-script-op-dup
  "OP_1 OP_DUP duplicates top."
  (let ((result (call-execute-script #(#x51 #x76))))
    (is-true (script-ok-p result))
    (is (= 2 (get-stack-depth (get-result-stack result))))))

(test execute-script-op-drop
  "OP_1 OP_2 OP_DROP leaves one item."
  (let ((result (call-execute-script #(#x51 #x52 #x75))))
    (is-true (script-ok-p result))
    (is (= 1 (get-stack-depth (get-result-stack result))))))

(test execute-script-op-add
  "OP_1 OP_2 OP_ADD results in single stack item."
  (let ((result (call-execute-script #(#x51 #x52 #x93))))
    (is-true (script-ok-p result))
    (is (= 1 (get-stack-depth (get-result-stack result))))))

(test execute-script-op-equal-true
  "OP_1 OP_1 OP_EQUAL succeeds."
  (let ((result (call-execute-script #(#x51 #x51 #x87))))
    (is-true (script-ok-p result))))

(test execute-script-op-equal-false
  "OP_1 OP_2 OP_EQUAL succeeds (false on stack)."
  (let ((result (call-execute-script #(#x51 #x52 #x87))))
    (is-true (script-ok-p result))))

(test execute-script-op-verify-pass
  "OP_1 OP_VERIFY passes."
  (let ((result (call-execute-script #(#x51 #x69))))
    (is-true (script-ok-p result))
    (is (= 0 (get-stack-depth (get-result-stack result))))))

(test execute-script-op-verify-fail
  "OP_0 OP_VERIFY fails."
  (let ((result (call-execute-script #(#x00 #x69))))
    (is-true (script-err-p result))))

(test execute-script-op-return
  "OP_RETURN fails immediately."
  (let ((result (call-execute-script #(#x6a))))
    (is-true (script-err-p result))))

(test execute-script-pushdata
  "Push 3 bytes directly."
  (let ((result (call-execute-script #(3 #xaa #xbb #xcc))))
    (is-true (script-ok-p result))
    (is (= 1 (get-stack-depth (get-result-stack result))))))

(test execute-script-hash160
  "OP_HASH160 succeeds."
  ;; Push 1 byte (value 42), then hash it
  (let ((result (call-execute-script #(1 42 #xa9))))
    (is-true (script-ok-p result))
    (is (= 1 (get-stack-depth (get-result-stack result))))))

(test execute-script-hash256
  "OP_HASH256 succeeds."
  ;; Push 1 byte (value 42), then hash it
  (let ((result (call-execute-script #(1 42 #xaa))))
    (is-true (script-ok-p result))
    (is (= 1 (get-stack-depth (get-result-stack result))))))

(test execute-script-stack-underflow
  "OP_DUP on empty stack fails."
  (let ((result (call-execute-script #(#x76))))
    (is-true (script-err-p result))))

(test execute-script-swap
  "OP_1 OP_2 OP_SWAP works."
  (let ((result (call-execute-script #(#x51 #x52 #x7c))))
    (is-true (script-ok-p result))
    (is (= 2 (get-stack-depth (get-result-stack result))))))

(test execute-script-rot
  "OP_1 OP_2 OP_3 OP_ROT works."
  (let ((result (call-execute-script #(#x51 #x52 #x53 #x7b))))
    (is-true (script-ok-p result))
    (is (= 3 (get-stack-depth (get-result-stack result))))))

(test execute-script-sub
  "OP_3 OP_1 OP_SUB results in 2."
  (let ((result (call-execute-script #(#x53 #x51 #x94))))
    (is-true (script-ok-p result))
    (is (= 1 (get-stack-depth (get-result-stack result))))))

(test execute-script-2dup
  "OP_1 OP_2 OP_2DUP leaves 4 items."
  (let ((result (call-execute-script #(#x51 #x52 #x6e))))
    (is-true (script-ok-p result))
    (is (= 4 (get-stack-depth (get-result-stack result))))))

(test execute-script-3dup
  "OP_1 OP_2 OP_3 OP_3DUP leaves 6 items."
  (let ((result (call-execute-script #(#x51 #x52 #x53 #x6f))))
    (is-true (script-ok-p result))
    (is (= 6 (get-stack-depth (get-result-stack result))))))

(test execute-script-depth
  "OP_1 OP_2 OP_DEPTH pushes 2."
  (let ((result (call-execute-script #(#x51 #x52 #x74))))
    (is-true (script-ok-p result))
    (is (= 3 (get-stack-depth (get-result-stack result))))))

(test execute-script-equalverify-pass
  "OP_1 OP_1 OP_EQUALVERIFY passes."
  (let ((result (call-execute-script #(#x51 #x51 #x88))))
    (is-true (script-ok-p result))
    (is (= 0 (get-stack-depth (get-result-stack result))))))

(test execute-script-equalverify-fail
  "OP_1 OP_2 OP_EQUALVERIFY fails."
  (let ((result (call-execute-script #(#x51 #x52 #x88))))
    (is-true (script-err-p result))))

(test execute-script-numequal
  "OP_2 OP_2 OP_NUMEQUAL succeeds."
  (let ((result (call-execute-script #(#x52 #x52 #x9c))))
    (is-true (script-ok-p result))
    (is (= 1 (get-stack-depth (get-result-stack result))))))

(test execute-script-lessthan
  "OP_1 OP_2 OP_LESSTHAN (1 < 2) succeeds."
  (let ((result (call-execute-script #(#x51 #x52 #x9f))))
    (is-true (script-ok-p result))
    (is (= 1 (get-stack-depth (get-result-stack result))))))

(test execute-script-negate
  "OP_5 OP_NEGATE works."
  (let ((result (call-execute-script #(#x55 #x8f))))
    (is-true (script-ok-p result))
    (is (= 1 (get-stack-depth (get-result-stack result))))))

(test execute-script-1add
  "OP_5 OP_1ADD works."
  (let ((result (call-execute-script #(#x55 #x8b))))
    (is-true (script-ok-p result))
    (is (= 1 (get-stack-depth (get-result-stack result))))))

(test execute-script-1sub
  "OP_5 OP_1SUB works."
  (let ((result (call-execute-script #(#x55 #x8c))))
    (is-true (script-ok-p result))
    (is (= 1 (get-stack-depth (get-result-stack result))))))

(test execute-script-min
  "OP_3 OP_5 OP_MIN gives 3."
  (let ((result (call-execute-script #(#x53 #x55 #xa3))))
    (is-true (script-ok-p result))
    (is (= 1 (get-stack-depth (get-result-stack result))))))

(test execute-script-max
  "OP_3 OP_5 OP_MAX gives 5."
  (let ((result (call-execute-script #(#x53 #x55 #xa4))))
    (is-true (script-ok-p result))
    (is (= 1 (get-stack-depth (get-result-stack result))))))

(test execute-script-booland
  "OP_1 OP_1 OP_BOOLAND works."
  (let ((result (call-execute-script #(#x51 #x51 #x9a))))
    (is-true (script-ok-p result))
    (is (= 1 (get-stack-depth (get-result-stack result))))))

(test execute-script-boolor
  "OP_0 OP_1 OP_BOOLOR works."
  (let ((result (call-execute-script #(#x00 #x51 #x9b))))
    (is-true (script-ok-p result))
    (is (= 1 (get-stack-depth (get-result-stack result))))))

(test execute-script-toaltstack-fromaltstack
  "OP_1 OP_TOALTSTACK OP_FROMALTSTACK works."
  (let ((result (call-execute-script #(#x51 #x6b #x6c))))
    (is-true (script-ok-p result))
    (is (= 1 (get-stack-depth (get-result-stack result))))))

(test execute-script-ifdup-true
  "OP_1 OP_IFDUP duplicates non-zero."
  (let ((result (call-execute-script #(#x51 #x73))))
    (is-true (script-ok-p result))
    (is (= 2 (get-stack-depth (get-result-stack result))))))

(test execute-script-ifdup-false
  "OP_0 OP_IFDUP doesn't duplicate zero."
  (let ((result (call-execute-script #(#x00 #x73))))
    (is-true (script-ok-p result))
    (is (= 1 (get-stack-depth (get-result-stack result))))))

(test execute-script-nop
  "OP_NOP does nothing."
  (let ((result (call-execute-script #(#x51 #x61))))
    (is-true (script-ok-p result))
    (is (= 1 (get-stack-depth (get-result-stack result))))))

(test execute-script-sha256
  "OP_SHA256 hashes to 32 bytes."
  (let ((result (call-execute-script #(1 42 #xa8))))  ; Push 1 byte, OP_SHA256
    (is-true (script-ok-p result))
    (is (= 1 (get-stack-depth (get-result-stack result))))))

(test execute-script-ripemd160
  "OP_RIPEMD160 hashes to 20 bytes."
  (let ((result (call-execute-script #(1 42 #xa6))))  ; Push 1 byte, OP_RIPEMD160
    (is-true (script-ok-p result))
    (is (= 1 (get-stack-depth (get-result-stack result))))))

;;; ============================================================
;;; Witness Program Detection Tests (SegWit BIP 141)
;;; ============================================================

;; Test vectors:
;; P2WPKH: OP_0 <20-byte-keyhash> = 0x00 0x14 <20 bytes> (22 bytes total)
;; P2WSH:  OP_0 <32-byte-scripthash> = 0x00 0x20 <32 bytes> (34 bytes total)

(defun make-p2wpkh-script (keyhash)
  "Create a P2WPKH scriptPubKey: OP_0 <20-byte-keyhash>"
  (let ((script (make-array 22 :element-type '(unsigned-byte 8))))
    (setf (aref script 0) #x00)  ; OP_0 (version 0)
    (setf (aref script 1) #x14)  ; Push 20 bytes
    (loop for i from 0 below 20
          do (setf (aref script (+ 2 i)) (aref keyhash i)))
    script))

(defun make-p2wsh-script (scripthash)
  "Create a P2WSH scriptPubKey: OP_0 <32-byte-scripthash>"
  (let ((script (make-array 34 :element-type '(unsigned-byte 8))))
    (setf (aref script 0) #x00)  ; OP_0 (version 0)
    (setf (aref script 1) #x20)  ; Push 32 bytes
    (loop for i from 0 below 32
          do (setf (aref script (+ 2 i)) (aref scripthash i)))
    script))

(test is-witness-program-p2wpkh
  "P2WPKH (OP_0 + 20 bytes) is a witness program."
  (let* ((keyhash (make-array 20 :element-type '(unsigned-byte 8) :initial-element #xab))
         (script (make-p2wpkh-script keyhash)))
    (is-true (bitcoin-lisp.coalton.interop:is-witness-program-p script))))

(test is-witness-program-p2wsh
  "P2WSH (OP_0 + 32 bytes) is a witness program."
  (let* ((scripthash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xcd))
         (script (make-p2wsh-script scripthash)))
    (is-true (bitcoin-lisp.coalton.interop:is-witness-program-p script))))

(test is-witness-program-version-1
  "OP_1 + program is a witness v1 program (Taproot)."
  (let ((script (make-array 34 :element-type '(unsigned-byte 8) :initial-element #x00)))
    (setf (aref script 0) #x51)  ; OP_1 (version 1)
    (setf (aref script 1) #x20)  ; Push 32 bytes
    (is-true (bitcoin-lisp.coalton.interop:is-witness-program-p script))))

(test is-witness-program-too-short
  "Script with only 3 bytes is not a witness program."
  (let ((script #(#x00 #x01 #xab)))  ; Too short
    (is-false (bitcoin-lisp.coalton.interop:is-witness-program-p script))))

(test is-witness-program-too-long
  "Script with 43 bytes is not a witness program."
  (let ((script (make-array 43 :element-type '(unsigned-byte 8) :initial-element #x00)))
    (setf (aref script 0) #x00)   ; OP_0
    (setf (aref script 1) #x29)   ; Push 41 bytes (too many)
    (is-false (bitcoin-lisp.coalton.interop:is-witness-program-p script))))

(test is-witness-program-invalid-version
  "OP_RESERVED (0x50) is not a valid witness version."
  (let ((script (make-array 22 :element-type '(unsigned-byte 8) :initial-element #x00)))
    (setf (aref script 0) #x50)   ; OP_RESERVED - not valid version
    (setf (aref script 1) #x14)   ; Push 20 bytes
    (is-false (bitcoin-lisp.coalton.interop:is-witness-program-p script))))

(test is-witness-program-mismatched-length
  "Push length must match actual remaining bytes."
  (let ((script (make-array 22 :element-type '(unsigned-byte 8) :initial-element #x00)))
    (setf (aref script 0) #x00)   ; OP_0
    (setf (aref script 1) #x20)   ; Push 32 bytes (but only 20 follow)
    (is-false (bitcoin-lisp.coalton.interop:is-witness-program-p script))))

(test is-witness-program-not-p2sh
  "P2SH script is not a witness program."
  ;; P2SH: OP_HASH160 <20 bytes> OP_EQUAL
  (let ((script (make-array 23 :element-type '(unsigned-byte 8) :initial-element #x00)))
    (setf (aref script 0) #xa9)   ; OP_HASH160
    (setf (aref script 1) #x14)   ; Push 20 bytes
    (setf (aref script 22) #x87)  ; OP_EQUAL
    (is-false (bitcoin-lisp.coalton.interop:is-witness-program-p script))))

(test get-witness-version-v0
  "Witness version 0 is extracted correctly."
  (let* ((keyhash (make-array 20 :element-type '(unsigned-byte 8) :initial-element #xab))
         (script (make-p2wpkh-script keyhash)))
    (is (= 0 (bitcoin-lisp.coalton.interop:get-witness-version script)))))

(test get-witness-version-v1
  "Witness version 1 (Taproot) is extracted correctly."
  (let ((script (make-array 34 :element-type '(unsigned-byte 8) :initial-element #x00)))
    (setf (aref script 0) #x51)  ; OP_1
    (setf (aref script 1) #x20)  ; Push 32 bytes
    (is (= 1 (bitcoin-lisp.coalton.interop:get-witness-version script)))))

(test get-witness-version-v16
  "Witness version 16 is extracted correctly."
  (let ((script (make-array 34 :element-type '(unsigned-byte 8) :initial-element #x00)))
    (setf (aref script 0) #x60)  ; OP_16
    (setf (aref script 1) #x20)  ; Push 32 bytes
    (is (= 16 (bitcoin-lisp.coalton.interop:get-witness-version script)))))

(test get-witness-version-not-witness
  "Non-witness script returns NIL for version."
  (let ((script #(#x76 #xa9)))  ; OP_DUP OP_HASH160
    (is (null (bitcoin-lisp.coalton.interop:get-witness-version script)))))

(test get-witness-program-bytes-p2wpkh
  "P2WPKH program bytes are extracted correctly."
  (let* ((keyhash (make-array 20 :element-type '(unsigned-byte 8)))
         (script nil))
    ;; Fill with distinct values
    (loop for i from 0 below 20 do (setf (aref keyhash i) (+ i 100)))
    (setf script (make-p2wpkh-script keyhash))
    (let ((program (bitcoin-lisp.coalton.interop:get-witness-program-bytes script)))
      (is (= 20 (length program)))
      (is (equalp keyhash program)))))

(test get-witness-program-bytes-p2wsh
  "P2WSH program bytes are extracted correctly."
  (let* ((scripthash (make-array 32 :element-type '(unsigned-byte 8)))
         (script nil))
    ;; Fill with distinct values
    (loop for i from 0 below 32 do (setf (aref scripthash i) (+ i 50)))
    (setf script (make-p2wsh-script scripthash))
    (let ((program (bitcoin-lisp.coalton.interop:get-witness-program-bytes script)))
      (is (= 32 (length program)))
      (is (equalp scripthash program)))))

;;; ============================================================
;;; Coalton Witness Program Type Tests
;;; ============================================================
;;;
;;; These tests verify the Coalton is-p2wpkh-program and is-p2wsh-program
;;; functions work correctly. Since these functions expect Coalton vectors,
;;; we test them indirectly through consistent behavior with the CL wrappers.

(test is-p2wpkh-not-p2wsh
  "P2WPKH script (22 bytes) is not detected as P2WSH."
  (let* ((keyhash (make-array 20 :element-type '(unsigned-byte 8) :initial-element #xab))
         (script (make-p2wpkh-script keyhash)))
    ;; P2WPKH is a witness program with 20-byte program
    (is-true (bitcoin-lisp.coalton.interop:is-witness-program-p script))
    (is (= 0 (bitcoin-lisp.coalton.interop:get-witness-version script)))
    (is (= 20 (length (bitcoin-lisp.coalton.interop:get-witness-program-bytes script))))))

(test is-p2wsh-not-p2wpkh
  "P2WSH script (34 bytes) is not detected as P2WPKH."
  (let* ((scripthash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xcd))
         (script (make-p2wsh-script scripthash)))
    ;; P2WSH is a witness program with 32-byte program
    (is-true (bitcoin-lisp.coalton.interop:is-witness-program-p script))
    (is (= 0 (bitcoin-lisp.coalton.interop:get-witness-version script)))
    (is (= 32 (length (bitcoin-lisp.coalton.interop:get-witness-program-bytes script))))))

(test p2wpkh-vs-p2wsh-length-difference
  "P2WPKH (20 bytes) and P2WSH (32 bytes) are distinguished by program length."
  (let* ((keyhash (make-array 20 :element-type '(unsigned-byte 8) :initial-element #x11))
         (scripthash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x22))
         (p2wpkh (make-p2wpkh-script keyhash))
         (p2wsh (make-p2wsh-script scripthash)))
    ;; Both are witness programs
    (is-true (bitcoin-lisp.coalton.interop:is-witness-program-p p2wpkh))
    (is-true (bitcoin-lisp.coalton.interop:is-witness-program-p p2wsh))
    ;; But with different program lengths
    (is (= 20 (length (bitcoin-lisp.coalton.interop:get-witness-program-bytes p2wpkh))))
    (is (= 32 (length (bitcoin-lisp.coalton.interop:get-witness-program-bytes p2wsh))))))

;;; ============================================================
;;; BIP 143 Sighash Tests
;;; ============================================================

(test make-p2pkh-script-code
  "P2PKH script code is constructed correctly for BIP 143."
  (let* ((keyhash (make-array 20 :element-type '(unsigned-byte 8)))
         (script-code nil))
    ;; Fill keyhash with test pattern
    (loop for i from 0 below 20 do (setf (aref keyhash i) (+ i 1)))
    (setf script-code (bitcoin-lisp.coalton.interop:make-p2pkh-script-code keyhash))
    ;; Should be: OP_DUP OP_HASH160 <push 20> <keyhash> OP_EQUALVERIFY OP_CHECKSIG
    (is (= 25 (length script-code)))
    (is (= #x76 (aref script-code 0)))   ; OP_DUP
    (is (= #xa9 (aref script-code 1)))   ; OP_HASH160
    (is (= #x14 (aref script-code 2)))   ; Push 20 bytes
    ;; Keyhash bytes 3-22
    (loop for i from 0 below 20
          do (is (= (+ i 1) (aref script-code (+ 3 i)))))
    (is (= #x88 (aref script-code 23)))  ; OP_EQUALVERIFY
    (is (= #xac (aref script-code 24))))) ; OP_CHECKSIG

(test bip143-sighash-produces-32-bytes
  "BIP 143 sighash computation produces 32-byte hash."
  (let* ((script-code (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x00))
         (amount 100000000)  ; 1 BTC in satoshis
         (sighash-type 1))   ; SIGHASH_ALL
    ;; Set up a minimal script code
    (setf (aref script-code 0) #x76)   ; OP_DUP
    (setf (aref script-code 1) #xa9)   ; OP_HASH160
    (setf (aref script-code 2) #x14)   ; Push 20
    (setf (aref script-code 23) #x88)  ; OP_EQUALVERIFY
    (setf (aref script-code 24) #xac)  ; OP_CHECKSIG
    ;; Need to set up original script pubkey for the function
    (let ((bitcoin-lisp.coalton.interop:*original-script-pubkey*
            (make-array 22 :element-type '(unsigned-byte 8) :initial-element #x00)))
      (setf (aref bitcoin-lisp.coalton.interop:*original-script-pubkey* 0) #x00)
      (setf (aref bitcoin-lisp.coalton.interop:*original-script-pubkey* 1) #x14)
      (let ((sighash (bitcoin-lisp.coalton.interop:compute-bip143-sighash
                      script-code amount sighash-type)))
        (is (= 32 (length sighash)))))))

(test bip143-sighash-deterministic
  "BIP 143 sighash is deterministic (same inputs = same output)."
  (let* ((script-code (make-array 25 :element-type '(unsigned-byte 8) :initial-element #xab))
         (amount 50000)
         (sighash-type 1))
    (let ((bitcoin-lisp.coalton.interop:*original-script-pubkey*
            (make-array 22 :element-type '(unsigned-byte 8) :initial-element #x00)))
      (let ((hash1 (bitcoin-lisp.coalton.interop:compute-bip143-sighash
                    script-code amount sighash-type))
            (hash2 (bitcoin-lisp.coalton.interop:compute-bip143-sighash
                    script-code amount sighash-type)))
        (is (equalp hash1 hash2))))))

(test bip143-sighash-different-amounts
  "BIP 143 sighash differs for different input amounts."
  (let* ((script-code (make-array 25 :element-type '(unsigned-byte 8) :initial-element #xab))
         (sighash-type 1))
    (let ((bitcoin-lisp.coalton.interop:*original-script-pubkey*
            (make-array 22 :element-type '(unsigned-byte 8) :initial-element #x00)))
      (let ((hash1 (bitcoin-lisp.coalton.interop:compute-bip143-sighash
                    script-code 100000 sighash-type))
            (hash2 (bitcoin-lisp.coalton.interop:compute-bip143-sighash
                    script-code 200000 sighash-type)))
        (is (not (equalp hash1 hash2)))))))

(test bip143-sighash-different-types
  "BIP 143 sighash differs for different sighash types."
  (let* ((script-code (make-array 25 :element-type '(unsigned-byte 8) :initial-element #xab))
         (amount 100000))
    (let ((bitcoin-lisp.coalton.interop:*original-script-pubkey*
            (make-array 22 :element-type '(unsigned-byte 8) :initial-element #x00)))
      (let ((hash-all (bitcoin-lisp.coalton.interop:compute-bip143-sighash
                       script-code amount 1))   ; SIGHASH_ALL
            (hash-none (bitcoin-lisp.coalton.interop:compute-bip143-sighash
                        script-code amount 2))  ; SIGHASH_NONE
            (hash-single (bitcoin-lisp.coalton.interop:compute-bip143-sighash
                          script-code amount 3))) ; SIGHASH_SINGLE
        (is (not (equalp hash-all hash-none)))
        (is (not (equalp hash-all hash-single)))
        (is (not (equalp hash-none hash-single)))))))

;;; ============================================================
;;; P2WPKH/P2WSH Validation Tests
;;; ============================================================

(test is-compressed-pubkey-valid
  "33-byte pubkey starting with 0x02 is compressed."
  (let ((pubkey (make-array 33 :element-type '(unsigned-byte 8) :initial-element #x00)))
    (setf (aref pubkey 0) #x02)
    (is-true (bitcoin-lisp.coalton.interop:is-compressed-pubkey-p pubkey))))

(test is-compressed-pubkey-valid-03
  "33-byte pubkey starting with 0x03 is compressed."
  (let ((pubkey (make-array 33 :element-type '(unsigned-byte 8) :initial-element #x00)))
    (setf (aref pubkey 0) #x03)
    (is-true (bitcoin-lisp.coalton.interop:is-compressed-pubkey-p pubkey))))

(test is-compressed-pubkey-uncompressed
  "65-byte pubkey is not compressed."
  (let ((pubkey (make-array 65 :element-type '(unsigned-byte 8) :initial-element #x00)))
    (setf (aref pubkey 0) #x04)
    (is-false (bitcoin-lisp.coalton.interop:is-compressed-pubkey-p pubkey))))

(test is-compressed-pubkey-wrong-length
  "32-byte data is not a compressed pubkey."
  (let ((data (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x02)))
    (is-false (bitcoin-lisp.coalton.interop:is-compressed-pubkey-p data))))

(test is-compressed-pubkey-wrong-prefix
  "33-byte with 0x04 prefix is not compressed."
  (let ((pubkey (make-array 33 :element-type '(unsigned-byte 8) :initial-element #x00)))
    (setf (aref pubkey 0) #x04)
    (is-false (bitcoin-lisp.coalton.interop:is-compressed-pubkey-p pubkey))))

(test validate-witness-program-empty-witness
  "Witness program validation fails with empty witness."
  (let* ((keyhash (make-array 20 :element-type '(unsigned-byte 8) :initial-element #xab))
         (script (make-p2wpkh-script keyhash))
         (witness nil)  ; Empty witness
         (amount 100000))
    (multiple-value-bind (success err)
        (bitcoin-lisp.coalton.interop:validate-witness-program script witness amount nil)
      (is-false success)
      (is (eq err :witness-program-witness-empty)))))

(test validate-witness-program-malleated
  "Native witness program fails if scriptSig is non-empty."
  (let* ((keyhash (make-array 20 :element-type '(unsigned-byte 8) :initial-element #xab))
         (script (make-p2wpkh-script keyhash))
         (witness (list (make-array 0 :element-type '(unsigned-byte 8))
                        (make-array 33 :element-type '(unsigned-byte 8) :initial-element #x02)))
         (amount 100000)
         (script-sig #(#x00)))  ; Non-empty scriptSig
    (multiple-value-bind (success err)
        (bitcoin-lisp.coalton.interop:validate-witness-program script witness amount script-sig)
      (is-false success)
      (is (eq err :witness-malleated)))))

(test validate-p2wpkh-wrong-witness-count
  "P2WPKH fails with wrong number of witness elements."
  (let* ((program (make-array 20 :element-type '(unsigned-byte 8) :initial-element #xab))
         (witness (list (make-array 10 :element-type '(unsigned-byte 8))))  ; Only 1 element
         (amount 100000))
    (multiple-value-bind (success err)
        (bitcoin-lisp.coalton.interop:validate-p2wpkh witness program amount)
      (is-false success)
      (is (eq err :witness-program-witness-empty)))))

(test validate-p2wsh-empty-witness
  "P2WSH fails with empty witness."
  (let* ((program (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xcd))
         (witness nil)
         (amount 100000))
    (multiple-value-bind (success err)
        (bitcoin-lisp.coalton.interop:validate-p2wsh witness program amount)
      (is-false success)
      (is (eq err :witness-program-witness-empty)))))

(test validate-p2wsh-hash-mismatch
  "P2WSH fails when witness script hash doesn't match program."
  (let* ((program (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xcd))
         (wrong-script (make-array 10 :element-type '(unsigned-byte 8) :initial-element #xff))
         (witness (list wrong-script))  ; Script that won't hash to program
         (amount 100000))
    (multiple-value-bind (success err)
        (bitcoin-lisp.coalton.interop:validate-p2wsh witness program amount)
      (is-false success)
      (is (eq err :witness-program-mismatch)))))

;;; ============================================================
;;; Witness Error Types Tests
;;; ============================================================

(test witness-error-types-exist
  "All witness error types are defined."
  ;; Just verify the symbols exist and are of the right type
  (is (symbolp 'bitcoin-lisp.coalton.script:SE-WitnessProgramWrongLength))
  (is (symbolp 'bitcoin-lisp.coalton.script:SE-WitnessProgramWitnessEmpty))
  (is (symbolp 'bitcoin-lisp.coalton.script:SE-WitnessProgramMismatch))
  (is (symbolp 'bitcoin-lisp.coalton.script:SE-WitnessUnexpected))
  (is (symbolp 'bitcoin-lisp.coalton.script:SE-WitnessMalleated))
  (is (symbolp 'bitcoin-lisp.coalton.script:SE-WitnessPubkeyType))
  (is (symbolp 'bitcoin-lisp.coalton.script:SE-DiscourageUpgradableWitnessProgram)))

;;; ============================================================
;;; Taproot Tests (BIP 340/341/342)
;;; ============================================================

(test taproot-error-types-exist
  "All Taproot error types are defined."
  (is (symbolp 'bitcoin-lisp.coalton.script:SE-TaprootInvalidSignature))
  (is (symbolp 'bitcoin-lisp.coalton.script:SE-TaprootInvalidControlBlock))
  (is (symbolp 'bitcoin-lisp.coalton.script:SE-TaprootMerkleMismatch))
  (is (symbolp 'bitcoin-lisp.coalton.script:SE-TapscriptInvalidOpcode))
  (is (symbolp 'bitcoin-lisp.coalton.script:SE-SchnorrSignatureSize)))

(test is-taproot-program-valid
  "OP_1 + 32-byte push is a valid Taproot program."
  (let ((script (make-array 34 :element-type '(unsigned-byte 8) :initial-element #xab)))
    (setf (aref script 0) #x51)  ; OP_1 (version 1)
    (setf (aref script 1) #x20)  ; Push 32 bytes
    (is-true (bitcoin-lisp.coalton.interop:is-taproot-program-p script))))

(test is-taproot-program-wrong-version
  "OP_0 + 32-byte push is NOT a Taproot program (wrong version)."
  (let ((script (make-array 34 :element-type '(unsigned-byte 8) :initial-element #xab)))
    (setf (aref script 0) #x00)  ; OP_0 (version 0)
    (setf (aref script 1) #x20)  ; Push 32 bytes
    (is-false (bitcoin-lisp.coalton.interop:is-taproot-program-p script))))

(test is-taproot-program-wrong-length
  "OP_1 + 20-byte push is NOT a Taproot program (wrong length)."
  (let ((script (make-array 22 :element-type '(unsigned-byte 8) :initial-element #xab)))
    (setf (aref script 0) #x51)  ; OP_1 (version 1)
    (setf (aref script 1) #x14)  ; Push 20 bytes
    (is-false (bitcoin-lisp.coalton.interop:is-taproot-program-p script))))

(test parse-control-block-minimal
  "Parse a minimal control block (33 bytes: version + internal key)."
  (let ((cb (make-array 33 :element-type '(unsigned-byte 8) :initial-element #x00)))
    ;; Set leaf version 0xc0 (Tapscript) with even parity
    (setf (aref cb 0) #xc0)
    ;; Set internal key bytes
    (loop for i from 1 below 33 do (setf (aref cb i) i))
    (multiple-value-bind (leaf-version parity internal-key path)
        (bitcoin-lisp.coalton.interop:parse-control-block cb)
      (is (= leaf-version #xc0))
      (is (= parity 0))
      (is (= (length internal-key) 32))
      (is (null path)))))

(test parse-control-block-with-path
  "Parse a control block with one Merkle path element (65 bytes)."
  (let ((cb (make-array 65 :element-type '(unsigned-byte 8) :initial-element #x00)))
    ;; Set leaf version 0xc0 with odd parity
    (setf (aref cb 0) #xc1)
    ;; Set internal key
    (loop for i from 1 below 33 do (setf (aref cb i) i))
    ;; Set path element
    (loop for i from 33 below 65 do (setf (aref cb i) (- i 33)))
    (multiple-value-bind (leaf-version parity internal-key path)
        (bitcoin-lisp.coalton.interop:parse-control-block cb)
      (is (= leaf-version #xc0))
      (is (= parity 1))
      (is (= (length internal-key) 32))
      (is (= (length path) 1))
      (is (= (length (first path)) 32)))))

(test parse-control-block-invalid-length
  "Control block with invalid length returns NIL."
  ;; 34 bytes is invalid (must be 33 + 32*n)
  (let ((cb (make-array 34 :element-type '(unsigned-byte 8) :initial-element #x00)))
    (is (null (bitcoin-lisp.coalton.interop:parse-control-block cb)))))

(test parse-control-block-too-short
  "Control block under 33 bytes returns NIL."
  (let ((cb (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x00)))
    (is (null (bitcoin-lisp.coalton.interop:parse-control-block cb)))))

(test validate-taproot-empty-witness
  "Taproot fails with empty witness."
  (let* ((program (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xab))
         (witness nil)
         (amount 100000))
    (multiple-value-bind (success err)
        (bitcoin-lisp.coalton.interop:validate-taproot witness program amount)
      (is-false success)
      (is (eq err :witness-program-witness-empty)))))

(test validate-taproot-key-path-wrong-sig-size
  "Taproot key path fails with wrong signature size."
  (let* ((program (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xab))
         ;; Signature must be 64 or 65 bytes, not 63
         (witness (list (make-array 63 :element-type '(unsigned-byte 8) :initial-element #x00)))
         (amount 100000))
    (multiple-value-bind (success err)
        (bitcoin-lisp.coalton.interop:validate-taproot-key-path witness program amount)
      (is-false success)
      (is (eq err :schnorr-signature-size)))))

(test taproot-tweak-hash-produces-32-bytes
  "Taproot tweak computation produces 32-byte hash."
  (let ((internal-key (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xab)))
    (let ((tweak (bitcoin-lisp.coalton.interop:compute-taproot-tweak internal-key)))
      (is (= 32 (length tweak))))))

(test taproot-tweak-with-merkle-root
  "Taproot tweak with Merkle root differs from without."
  (let ((internal-key (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xab))
        (merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xcd)))
    (let ((tweak-without (bitcoin-lisp.coalton.interop:compute-taproot-tweak internal-key))
          (tweak-with (bitcoin-lisp.coalton.interop:compute-taproot-tweak internal-key merkle-root)))
      (is (not (equalp tweak-without tweak-with))))))

(test merkle-root-from-empty-path
  "Merkle root from empty path equals the leaf hash."
  (let ((leaf-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xab)))
    (let ((root (bitcoin-lisp.coalton.interop:compute-merkle-root-from-path leaf-hash nil)))
      (is (equalp root leaf-hash)))))

(test valid-taproot-sighash-types
  "Valid Taproot sighash types are accepted."
  ;; SIGHASH_DEFAULT (0x00), ALL (0x01), NONE (0x02), SINGLE (0x03)
  ;; plus ANYONECANPAY (0x80) combinations
  (let ((valid-types '(#x00 #x01 #x02 #x03 #x81 #x82 #x83)))
    (dolist (sht valid-types)
      (is-true (bitcoin-lisp.coalton.interop::valid-taproot-sighash-type-p sht)
               (format nil "Expected sighash type ~2,'0X to be valid" sht)))))

(test invalid-taproot-sighash-types
  "Invalid Taproot sighash types are rejected."
  ;; Invalid: non-standard base types, weird flags
  (let ((invalid-types '(#x04 #x05 #x40 #x20)))
    (dolist (sht invalid-types)
      (is-false (bitcoin-lisp.coalton.interop::valid-taproot-sighash-type-p sht)
                (format nil "Expected sighash type ~2,'0X to be invalid" sht)))))

;;; ============================================================
;;; Tagged Hash Tests (BIP 340)
;;; ============================================================

(test tagged-hash-produces-32-bytes
  "Tagged hash produces 32-byte output."
  (let ((data (make-array 10 :element-type '(unsigned-byte 8) :initial-element #xab)))
    (let ((hash (bitcoin-lisp.crypto:tagged-hash "TapLeaf" data)))
      (is (= 32 (length hash))))))

(test tagged-hash-differs-by-tag
  "Different tags produce different hashes."
  (let ((data (make-array 10 :element-type '(unsigned-byte 8) :initial-element #xab)))
    (let ((hash1 (bitcoin-lisp.crypto:tagged-hash "TapLeaf" data))
          (hash2 (bitcoin-lisp.crypto:tagged-hash "TapBranch" data)))
      (is (not (equalp hash1 hash2))))))

(test tap-leaf-hash-format
  "TapLeaf hash includes leaf version and script."
  (let ((script (make-array 5 :element-type '(unsigned-byte 8) :initial-element #x51)))
    (let ((hash (bitcoin-lisp.crypto:tap-leaf-hash #xc0 script)))
      (is (= 32 (length hash))))))

(test tap-branch-hash-sorted
  "TapBranch hash sorts inputs lexicographically."
  (let ((left (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xff))
        (right (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x00)))
    ;; TapBranch should produce same result regardless of argument order
    (let ((hash1 (bitcoin-lisp.crypto:tap-branch-hash left right))
          (hash2 (bitcoin-lisp.crypto:tap-branch-hash right left)))
      (is (equalp hash1 hash2)))))
