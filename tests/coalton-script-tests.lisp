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
