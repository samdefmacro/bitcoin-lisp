;;;; Bitcoin Core script_tests.json compatibility tests
;;;;
;;;; This file runs our Coalton script interpreter against Bitcoin Core's
;;;; official test vectors to verify consensus compatibility.

(in-package #:bitcoin-lisp.tests)

;;; ============================================================
;;; Script Assembly Parser
;;; ============================================================
;;; Parses Bitcoin Script assembly notation like "1 DUP ADD 2 EQUAL"
;;; into raw script bytes.

(defparameter *opcode-names*
  (alexandria:alist-hash-table
   '(;; Push value
     ("0" . #x00)
     ("FALSE" . #x00)
     ("1NEGATE" . #x4f)
     ("RESERVED" . #x50)
     ("1" . #x51) ("TRUE" . #x51)
     ("2" . #x52) ("3" . #x53) ("4" . #x54) ("5" . #x55)
     ("6" . #x56) ("7" . #x57) ("8" . #x58) ("9" . #x59)
     ("10" . #x5a) ("11" . #x5b) ("12" . #x5c) ("13" . #x5d)
     ("14" . #x5e) ("15" . #x5f) ("16" . #x60)
     ;; Flow control
     ("NOP" . #x61)
     ("VER" . #x62)
     ("IF" . #x63)
     ("NOTIF" . #x64)
     ("VERIF" . #x65)
     ("VERNOTIF" . #x66)
     ("ELSE" . #x67)
     ("ENDIF" . #x68)
     ("VERIFY" . #x69)
     ("RETURN" . #x6a)
     ;; Stack
     ("TOALTSTACK" . #x6b)
     ("FROMALTSTACK" . #x6c)
     ("2DROP" . #x6d)
     ("2DUP" . #x6e)
     ("3DUP" . #x6f)
     ("2OVER" . #x70)
     ("2ROT" . #x71)
     ("2SWAP" . #x72)
     ("IFDUP" . #x73)
     ("DEPTH" . #x74)
     ("DROP" . #x75)
     ("DUP" . #x76)
     ("NIP" . #x77)
     ("OVER" . #x78)
     ("PICK" . #x79)
     ("ROLL" . #x7a)
     ("ROT" . #x7b)
     ("SWAP" . #x7c)
     ("TUCK" . #x7d)
     ;; Splice (disabled)
     ("CAT" . #x7e)
     ("SUBSTR" . #x7f)
     ("LEFT" . #x80)
     ("RIGHT" . #x81)
     ("SIZE" . #x82)
     ;; Bitwise (disabled except EQUAL)
     ("INVERT" . #x83)
     ("AND" . #x84)
     ("OR" . #x85)
     ("XOR" . #x86)
     ("EQUAL" . #x87)
     ("EQUALVERIFY" . #x88)
     ("RESERVED1" . #x89)
     ("RESERVED2" . #x8a)
     ;; Arithmetic
     ("1ADD" . #x8b)
     ("1SUB" . #x8c)
     ("2MUL" . #x8d)
     ("2DIV" . #x8e)
     ("NEGATE" . #x8f)
     ("ABS" . #x90)
     ("NOT" . #x91)
     ("0NOTEQUAL" . #x92)
     ("ADD" . #x93)
     ("SUB" . #x94)
     ("MUL" . #x95)
     ("DIV" . #x96)
     ("MOD" . #x97)
     ("LSHIFT" . #x98)
     ("RSHIFT" . #x99)
     ("BOOLAND" . #x9a)
     ("BOOLOR" . #x9b)
     ("NUMEQUAL" . #x9c)
     ("NUMEQUALVERIFY" . #x9d)
     ("NUMNOTEQUAL" . #x9e)
     ("LESSTHAN" . #x9f)
     ("GREATERTHAN" . #xa0)
     ("LESSTHANOREQUAL" . #xa1)
     ("GREATERTHANOREQUAL" . #xa2)
     ("MIN" . #xa3)
     ("MAX" . #xa4)
     ("WITHIN" . #xa5)
     ;; Crypto
     ("RIPEMD160" . #xa6)
     ("SHA1" . #xa7)
     ("SHA256" . #xa8)
     ("HASH160" . #xa9)
     ("HASH256" . #xaa)
     ("CODESEPARATOR" . #xab)
     ("CHECKSIG" . #xac)
     ("CHECKSIGVERIFY" . #xad)
     ("CHECKMULTISIG" . #xae)
     ("CHECKMULTISIGVERIFY" . #xaf)
     ;; Expansion NOPs
     ("NOP1" . #xb0)
     ("CHECKLOCKTIMEVERIFY" . #xb1) ("NOP2" . #xb1)
     ("CHECKSEQUENCEVERIFY" . #xb2) ("NOP3" . #xb2)
     ("NOP4" . #xb3)
     ("NOP5" . #xb4)
     ("NOP6" . #xb5)
     ("NOP7" . #xb6)
     ("NOP8" . #xb7)
     ("NOP9" . #xb8)
     ("NOP10" . #xb9)
     ;; More
     ("CHECKSIGADD" . #xba)
     ("INVALIDOPCODE" . #xff))
   :test 'equal))

(defun parse-hex-byte (str)
  "Parse a hex string like '0x51' or '0xff' to a byte."
  (when (and (>= (length str) 2)
             (string= (subseq str 0 2) "0x"))
    (parse-integer (subseq str 2) :radix 16 :junk-allowed t)))

(defun parse-hex-bytes (str)
  "Parse a hex string to a vector of bytes."
  (when (and (>= (length str) 2)
             (string= (subseq str 0 2) "0x"))
    (let* ((hex (subseq str 2))
           (len (/ (length hex) 2))
           (result (make-array len :element-type '(unsigned-byte 8))))
      (loop for i from 0 below len
            for pos = (* i 2)
            do (setf (aref result i)
                     (parse-integer (subseq hex pos (+ pos 2)) :radix 16)))
      result)))

(defun parse-decimal-number (str)
  "Parse a decimal number string, including negative numbers."
  (handler-case
      (parse-integer str)
    (error () nil)))

(defun number-to-script-bytes (n)
  "Convert an integer to Bitcoin script number encoding (minimal, little-endian, sign bit)."
  (cond
    ((zerop n) #())
    ((and (>= n -1) (<= n 16))
     ;; Use OP_1NEGATE or OP_1..OP_16
     (if (= n -1)
         (vector #x4f)  ; OP_1NEGATE
         (vector (+ #x50 n))))  ; OP_1..OP_16
    (t
     ;; Full encoding
     (let* ((negative (< n 0))
            (abs-n (abs n))
            (bytes '()))
       ;; Extract bytes
       (loop while (> abs-n 0)
             do (push (logand abs-n #xff) bytes)
                (setf abs-n (ash abs-n -8)))
       ;; Handle sign bit
       (setf bytes (nreverse bytes))
       (if (zerop (logand (car (last bytes)) #x80))
           ;; High bit clear - set it if negative
           (when negative
             (setf (car (last bytes)) (logior (car (last bytes)) #x80)))
           ;; High bit set - need extra byte for sign
           (setf bytes (append bytes (list (if negative #x80 #x00)))))
       ;; Push with appropriate opcode
       (let ((len (length bytes)))
         (cond
           ((<= len 75)
            (concatenate 'vector (vector len) bytes))
           ((<= len 255)
            (concatenate 'vector (vector #x4c len) bytes))
           ((<= len 65535)
            (concatenate 'vector
                         (vector #x4d (logand len #xff) (ash len -8))
                         bytes))
           (t
            (concatenate 'vector
                         (vector #x4e
                                 (logand len #xff)
                                 (logand (ash len -8) #xff)
                                 (logand (ash len -16) #xff)
                                 (ash len -24))
                         bytes))))))))

(defun string-to-push-bytes (str)
  "Convert a string literal to push bytes. Input is without quotes."
  (let* ((bytes (map 'vector #'char-code str))
         (len (length bytes)))
    (cond
      ((zerop len) (vector #x00))  ; OP_0
      ((<= len 75)
       (concatenate 'vector (vector len) bytes))
      ((<= len 255)
       (concatenate 'vector (vector #x4c len) bytes))
      ((<= len 65535)
       (concatenate 'vector
                    (vector #x4d (logand len #xff) (ash len -8))
                    bytes))
      (t
       (concatenate 'vector
                    (vector #x4e
                            (logand len #xff)
                            (logand (ash len -8) #xff)
                            (logand (ash len -16) #xff)
                            (ash len -24))
                    bytes)))))

(defun tokenize-script (script-str)
  "Split script string into tokens, handling strings properly."
  (let ((tokens '())
        (current "")
        (in-string nil)
        (string-char nil))
    (loop for char across script-str
          do (cond
               ;; Start of string
               ((and (not in-string) (char= char #\'))
                (setf in-string t
                      string-char char
                      current (string char)))
               ;; End of string
               ((and in-string (char= char string-char))
                (push (concatenate 'string current (string char)) tokens)
                (setf in-string nil
                      current ""))
               ;; Inside string
               (in-string
                (setf current (concatenate 'string current (string char))))
               ;; Whitespace outside string
               ((member char '(#\Space #\Tab #\Newline))
                (when (> (length current) 0)
                  (push current tokens)
                  (setf current "")))
               ;; Regular character
               (t
                (setf current (concatenate 'string current (string char))))))
    ;; Handle remaining token
    (when (> (length current) 0)
      (push current tokens))
    (nreverse tokens)))

(defun assemble-script (script-str)
  "Assemble a Bitcoin Script from assembly notation to bytes."
  (when (or (null script-str) (string= script-str ""))
    (return-from assemble-script (make-array 0 :element-type '(unsigned-byte 8))))

  (let ((tokens (tokenize-script script-str))
        (result (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (loop for token in tokens
          do (let ((bytes
                     (cond
                       ;; String literal 'xxx'
                       ((and (> (length token) 0)
                             (char= (char token 0) #\'))
                        (string-to-push-bytes
                         (subseq token 1 (1- (length token)))))

                       ;; Hex bytes 0xNN or 0xNNNN...
                       ((and (>= (length token) 4)
                             (string= (subseq token 0 2) "0x"))
                        (parse-hex-bytes token))

                       ;; Named opcode
                       ((gethash (string-upcase token) *opcode-names*)
                        (vector (gethash (string-upcase token) *opcode-names*)))

                       ;; Decimal number
                       ((parse-decimal-number token)
                        (number-to-script-bytes (parse-decimal-number token)))

                       ;; Unknown - try as opcode without OP_ prefix
                       (t
                        (let ((with-prefix (concatenate 'string "OP_" (string-upcase token))))
                          (if (gethash with-prefix *opcode-names*)
                              (vector (gethash with-prefix *opcode-names*))
                              (error "Unknown token: ~A" token)))))))
               (when bytes
                 (loop for b across bytes
                       do (vector-push-extend b result)))))
    (coerce result '(simple-array (unsigned-byte 8) (*)))))

;;; ============================================================
;;; Test Runner
;;; ============================================================

(defun load-script-tests ()
  "Load script_tests.json and return parsed test cases."
  (let ((path (merge-pathnames
               "refs/bitcoin/src/test/data/script_tests.json"
               (asdf:system-source-directory :bitcoin-lisp))))
    (with-open-file (stream path :direction :input)
      (yason:parse stream))))

(defun parse-test-case (test)
  "Parse a test case array into structured form.
   Returns (values scriptSig scriptPubKey flags expected-result comment witness amount)
   or NIL if this is a comment line."
  (when (or (not (listp test))
            (< (length test) 4)
            ;; Skip comment-only lines (first element is a long string)
            (and (= (length test) 1) (stringp (first test))))
    (return-from parse-test-case nil))

  ;; Check if first element is witness data (array starting with array)
  (let* ((has-witness (and (listp (first test))
                           (listp (first (first test)))))
         (witness (when has-witness (butlast (first test))))
         (amount (when has-witness (car (last (first test)))))
         (offset (if has-witness 1 0))
         (script-sig (nth offset test))
         (script-pubkey (nth (+ 1 offset) test))
         (flags (nth (+ 2 offset) test))
         (expected (nth (+ 3 offset) test))
         (comment (when (> (length test) (+ 4 offset))
                    (nth (+ 4 offset) test))))
    (values script-sig script-pubkey flags expected comment witness amount)))

(defun flags-include-p (flags-str flag)
  "Check if flags string includes a specific flag."
  (and flags-str
       (or (search flag flags-str)
           (search (concatenate 'string "," flag) flags-str)
           (search (concatenate 'string flag ",") flags-str))))

(defun parse-witness-stack (witness-data)
  "Parse witness data from test format into list of byte arrays.
   WITNESS-DATA is a list of hex strings."
  (when witness-data
    (mapcar (lambda (hex-str)
              (if (and (stringp hex-str) (> (length hex-str) 0))
                  (let* ((len (/ (length hex-str) 2))
                         (result (make-array len :element-type '(unsigned-byte 8))))
                    (loop for i from 0 below len
                          for pos = (* i 2)
                          do (setf (aref result i)
                                   (parse-integer (subseq hex-str pos (+ pos 2)) :radix 16)))
                    result)
                  (make-array 0 :element-type '(unsigned-byte 8))))
            witness-data)))

(defun run-script-test (script-sig-asm script-pubkey-asm flags &optional witness-data amount)
  "Run a script test and return (values success-p error-or-nil).
   Executes scriptSig, then scriptPubKey on the resulting stack.
   For witness inputs, validates witness program with BIP 143 sighash.
   Success requires: no errors AND non-empty stack AND top is truthy."
  (handler-case
      (let* ((sig-bytes (assemble-script script-sig-asm))
             (pubkey-bytes (assemble-script script-pubkey-asm))
             (p2sh-enabled (flags-include-p flags "P2SH"))
             (witness-enabled (flags-include-p flags "WITNESS"))
             (is-p2sh-script (and p2sh-enabled
                                  (bl.interop:is-p2sh-script-p pubkey-bytes)))
             (is-witness-program (bl.interop:is-witness-program-p pubkey-bytes))
             (witness-stack (parse-witness-stack witness-data))
             (input-amount (or amount 0)))
        ;; Set script flags for STRICTENC validation
        (bl.interop:set-script-flags flags)
        ;; Set witness input amount for BIP 143 sighash
        (setf bl.interop:*witness-input-amount* input-amount)
        (unwind-protect
            (progn
              ;; SIGPUSHONLY: validate that scriptSig contains only push operations
              (when (and (flags-include-p flags "SIGPUSHONLY")
                         (not (bl.interop:script-is-push-only-p sig-bytes)))
                (return-from run-script-test (values nil :sig-pushonly)))

              ;; P2SH requires push-only scriptSig (BIP 16) even without SIGPUSHONLY flag
              (when (and is-p2sh-script
                         (not (bl.interop:script-is-push-only-p sig-bytes)))
                (return-from run-script-test (values nil :sig-pushonly)))

              ;; Handle witness programs
              (when (and witness-enabled is-witness-program)
                ;; Native witness: scriptSig must be empty
                (when (plusp (length sig-bytes))
                  (return-from run-script-test (values nil :witness-malleated)))
                ;; Validate the witness program
                (multiple-value-bind (success err)
                    (bl.interop:validate-witness-program
                     pubkey-bytes witness-stack input-amount sig-bytes)
                  (if success
                      ;; CLEANSTACK is implicit for witness (stack is consumed)
                      (return-from run-script-test (values t nil))
                      (return-from run-script-test (values nil err)))))

              ;; Handle P2SH-wrapped witness programs
              (when (and witness-enabled is-p2sh-script witness-stack)
                ;; The redeem script is the stack top the scriptSig leaves —
                ;; the same derivation production uses (p2sh-redeem-script).
                (let ((redeem-script (bl.interop:p2sh-redeem-script sig-bytes)))
                  (when (and redeem-script
                             (bl.interop:is-witness-program-p redeem-script))
                    ;; Validate the wrapped witness program (is-p2sh = T:
                    ;; Core passes is_p2sh=true, disabling Taproot/P2A branches)
                    (multiple-value-bind (success err)
                        (bl.interop:validate-witness-program
                         redeem-script witness-stack input-amount nil t)
                      (if success
                          (return-from run-script-test (values t nil))
                          (return-from run-script-test (values nil err)))))))

              ;; Legacy script execution
              (multiple-value-bind (success stack-or-error)
                  (bl.interop:run-scripts-with-p2sh
                   sig-bytes pubkey-bytes p2sh-enabled)
                (if success
                    ;; Script executed without error - now check the result
                    ;; Bitcoin requires: stack non-empty AND top element is truthy
                    (if (bl.interop:stack-top-truthy-p stack-or-error)
                        ;; CLEANSTACK: stack must have exactly 1 element
                        (if (and (flags-include-p flags "CLEANSTACK")
                                 (> (length stack-or-error) 1))
                            (values nil :cleanstack)
                            (values t nil))
                        (values nil :eval-false))
                    (values nil stack-or-error))))
          ;; Clear flags after test
          (bl.interop:set-script-flags nil)
          (setf bl.interop:*witness-input-amount* 0)))
    (error (e)
      (values nil e))))

;;; ============================================================
;;; Test Suite
;;; ============================================================

(def-suite :bitcoin-core-script-tests
  :description "Bitcoin Core script_tests.json compatibility"
  :in :bitcoin-lisp-tests)

(in-suite :bitcoin-core-script-tests)

;; Run all tests
(defparameter *max-tests-to-run* 10000)

(test basic-script-assembly
  "Test that script assembly works correctly."
  (is (equalp #(#x51) (assemble-script "1")))
  (is (equalp #(#x52) (assemble-script "2")))
  (is (equalp #(#x00) (assemble-script "0")))
  (is (equalp #(#x76) (assemble-script "DUP")))
  (is (equalp #(#x87) (assemble-script "EQUAL")))
  (is (equalp #(#x51 #x76) (assemble-script "1 DUP")))
  (is (equalp #(#x51 #x52 #x93) (assemble-script "1 2 ADD"))))

(test script-tests-json-full
  "Run all Bitcoin Core script_tests.json vectors with strict pass/fail."
  (let* ((all-tests (load-script-tests))
         (passed 0)
         (failed-p2sh 0)
         (failed-cleanstack 0)
         (failed-minimaldata 0)
         (failed-witness 0)
         (failed-other 0)
         (errors '())
         (minimaldata-errors '())
         (witness-errors '()))

    (loop for test in all-tests
          for i from 0
          when (< i *max-tests-to-run*)
          do (multiple-value-bind (sig pubkey flags expected comment witness amount)
                 (parse-test-case test)
               (when sig  ; Skip comment lines
                 (handler-case
                     (multiple-value-bind (success err)
                         (run-script-test sig pubkey flags witness amount)
                       (let ((expected-ok (string= expected "OK")))
                         (if (eq success expected-ok)
                             (incf passed)
                             ;; Categorize failures
                             (cond
                               ((or witness (flags-include-p flags "WITNESS"))
                                (incf failed-witness)
                                (push (list :index i
                                            :sig sig
                                            :pubkey pubkey
                                            :flags flags
                                            :expected expected
                                            :got (if success "OK" err)
                                            :comment comment)
                                      witness-errors))
                               ((flags-include-p flags "P2SH")
                                (incf failed-p2sh))
                               ((flags-include-p flags "CLEANSTACK")
                                (incf failed-cleanstack))
                               ((flags-include-p flags "MINIMALDATA")
                                (incf failed-minimaldata)
                                (push (list :index i
                                            :sig sig
                                            :pubkey pubkey
                                            :flags flags
                                            :expected expected
                                            :got (if success "OK" err)
                                            :comment comment)
                                      minimaldata-errors))
                               (t
                                (incf failed-other)
                                (push (list :index i
                                            :sig sig
                                            :pubkey pubkey
                                            :flags flags
                                            :expected expected
                                            :got (if success "OK" err)
                                            :comment comment)
                                      errors))))))
                   (error (e)
                     (incf failed-other)
                     (push (list :index i
                                 :sig sig
                                 :pubkey pubkey
                                 :error (format nil "~A" e))
                           errors))))))

    ;; Report results
    (let ((total-failed (+ failed-p2sh failed-cleanstack failed-minimaldata failed-witness failed-other)))
      (format t "~%Bitcoin Core Script Tests Results:~%")
      (format t "  Passed:  ~D~%" passed)
      (format t "  Failed (P2SH):       ~D~%" failed-p2sh)
      (format t "  Failed (CLEANSTACK): ~D~%" failed-cleanstack)
      (format t "  Failed (MINIMALDATA): ~D~%" failed-minimaldata)
      (format t "  Failed (WITNESS):    ~D~%" failed-witness)
      (format t "  Failed (Other):      ~D~%" failed-other)
      (format t "  Total run: ~D~%" (+ passed total-failed))
      (format t "  Pass rate: ~,1F%~%"
              (if (zerop (+ passed total-failed))
                  0.0
                  (* 100.0 (/ passed (+ passed total-failed)))))

      (when witness-errors
        (format t "~%WITNESS failures (first 10):~%")
        (loop for err in (subseq witness-errors 0 (min 10 (length witness-errors)))
              do (format t "  ~A~%" err)))

      (when minimaldata-errors
        (format t "~%MINIMALDATA failures (first 10):~%")
        (loop for err in (subseq minimaldata-errors 0 (min 10 (length minimaldata-errors)))
              do (format t "  ~A~%" err)))

      (when errors
        (format t "~%Other failures (all ~D):~%" (length errors))
        (loop for err in errors
              do (format t "  ~A~%" err)))

      ;; Strict: zero failures across all categories
      (is (zerop (+ failed-p2sh failed-cleanstack failed-minimaldata failed-witness failed-other))
          "All script tests must pass. Failures: P2SH=~D CLEANSTACK=~D MINIMALDATA=~D WITNESS=~D Other=~D"
          failed-p2sh failed-cleanstack failed-minimaldata failed-witness failed-other))))

;;;; Consensus-divergence regression guards (P0 fixes, 2026-06-16)

(test op-pick-roll-reject-oversized-operand
  "CONSENSUS: OP_PICK / OP_ROLL read the index as a 4-byte CScriptNum (Bitcoin
Core interpreter.cpp). A >4-byte operand is a script-number overflow, not an
in-range index, so the script must fail. Before the fix these used an unbounded
conversion, so a 5-byte operand decoding to a valid index (here 0x0100000000 = 1)
was accepted where Core rejects it."
  ;; Raw opcode bytes (assemble-script keys small pushes/opcodes oddly): OP_1=0x51
  ;; OP_2=0x52, OP_PICK=0x79, OP_ROLL=0x7a. Stack: <1> <2> <5-byte index> PICK/ROLL.
  ;; 5-byte index operand -> must fail on both opcodes.
  (multiple-value-bind (ok err)
      (run-script-test "" "0x51 0x52 0x05 0x0100000000 0x79" "")
    (declare (ignore err))
    (is (null ok) "OP_PICK with a 5-byte index operand must fail"))
  (multiple-value-bind (ok err)
      (run-script-test "" "0x51 0x52 0x05 0x0100000000 0x7a" "")
    (declare (ignore err))
    (is (null ok) "OP_ROLL with a 5-byte index operand must fail"))
  ;; Control: a valid 4-byte index (0x01000000 = 1) still works, so we only
  ;; rejected the overflow rather than breaking the opcode.
  (multiple-value-bind (ok err)
      (run-script-test "" "0x51 0x52 0x04 0x01000000 0x79" "")
    (declare (ignore err))
    (is (eq ok t) "OP_PICK with a valid 4-byte index must still succeed")))

(test p2sh-witness-rejects-malleated-scriptsig
  "CONSENSUS (BIP141; WITNESS is a MANDATORY flag): a P2SH-wrapped witness spend
requires the scriptSig to be EXACTLY a single canonical push of the witness
program. An extra leading push (third-party malleability) must be rejected even
though P2SH push-only accepts it — Core returns WITNESS_MALLEATED_P2SH. Before
the fix the redeem script was taken from the scriptSig bytes, the leading junk
was ignored, and the spend was accepted. Uses P2SH(P2WSH(OP_TRUE)) so the
canonical case validates with a trivial witness (no signature needed)."
  (let* ((witness-script (make-array 1 :element-type '(unsigned-byte 8)
                                       :initial-element #x51)) ; OP_TRUE
         (wsh (bl.crypto:sha256 witness-script))     ; 32-byte program
         (wp (concatenate '(vector (unsigned-byte 8)) (vector #x00 #x20) wsh)) ; OP_0 push32
         (p2sh-hash (bl.crypto:hash160 wp))          ; 20 bytes
         (spk (concatenate '(vector (unsigned-byte 8))
                           (vector #xa9 #x14) p2sh-hash (vector #x87))) ; HASH160 <20> EQUAL
         (canonical (concatenate '(vector (unsigned-byte 8)) (vector #x22) wp)) ; single push34
         (malleated (concatenate '(vector (unsigned-byte 8)) (vector #x00 #x22) wp)) ; OP_0 + push34
         (witness (list witness-script)))   ; P2WSH witness stack = [witnessScript]
    (bl.interop:set-script-flags "P2SH,WITNESS")
    (unwind-protect
         (progn
           (multiple-value-bind (ok err)
               (bl.interop:verify-script malleated spk
                                                           :witness witness :amount 0)
             (is (null ok))
             (is (eq err :witness-malleated-p2sh)))
           (multiple-value-bind (ok err)
               (bl.interop:verify-script canonical spk
                                                           :witness witness :amount 0)
             (declare (ignore err))
             (is (eq ok t) "canonical single-push P2SH-witness spend must verify")))
      (bl.interop:set-script-flags nil))))

(test p2sh-witness-redeem-script-is-stack-top
  "CONSENSUS (interpreter.cpp:2058-2060): the P2SH redeem script is the element
the scriptSig leaves on TOP OF THE STACK — not the last push in its bytes. OP_0
pushes an empty element, so `<push program> OP_0` spending P2SH(hash160(''))
has an EMPTY redeem script: to Core it is an ordinary P2SH spend, accepted with
no witness. Before the fix a byte-level walk skipped OP_0, took the witness
program as the redeem script, and rejected the spend as WITNESS_MALLEATED_P2SH
— a block containing it split us from Core."
  (flet ((p2sh (redeem)
           (%w8d-script #xa9 #x14 (bl.crypto:hash160 redeem) #x87)))
    (let* ((wp (%w8d-script #x00 #x14 (make-list 20 :initial-element #xab))) ; v0 program
           (empty (%w8d-script))
           (push-wp (%w8d-script #x16 wp))
           (push-wp-then-op0 (%w8d-script push-wp #x00)))
      (bl.interop:set-script-flags "P2SH,WITNESS")
      (unwind-protect
           (progn
             ;; The divergent case. Core: stack top is the empty element,
             ;; pubKey2 is the empty script, not a witness program -> ACCEPT.
             (multiple-value-bind (ok err)
                 (bl.interop:verify-script
                  push-wp-then-op0 (p2sh empty) :witness nil :amount 0)
               (is (eq ok t)
                   "<push program> OP_0 is a plain P2SH spend of hash160(''), got ~A"
                   err))
             (is (equalp empty (bl.interop:p2sh-redeem-script
                                push-wp-then-op0))
                 "trailing OP_0 leaves an empty element on top")
             ;; Positive control: with the program genuinely on top, the
             ;; witness path still fires — an empty witness must FAIL. For a
             ;; 20-byte v0 program Core's VerifyWitnessProgram reports MISMATCH
             ;; (stack.size() != 2), reserving WITNESS_EMPTY for P2WSH.
             (multiple-value-bind (ok err)
                 (bl.interop:verify-script
                  push-wp (p2sh wp) :witness nil :amount 0)
               (is (null ok))
               (is (eq err :witness-program-mismatch) "got ~A" err)))
        (bl.interop:set-script-flags nil)))))

;;;; Consensus-divergence regression guards (GA10 script opcodes, 2026-09-05)

(test cltv-csv-are-plain-nops-without-their-own-flag
  "CONSENSUS (Core interpreter.cpp:521-526 and :560-565): when
SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY / _CHECKSEQUENCEVERIFY is off, the opcode is
`if (!(flags & ...)) { /* not enabled; treat as a NOP2|NOP3 */ break; }' and
consults nothing else. SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS is read only in
the OP_NOP1 / OP_NOP4..OP_NOP10 case (:594-599) -- BIP65 and BIP112 removed it
from these two branches when they gave the opcodes their own flags. We called
the shared discourage helper instead, so a flag set carrying DISCOURAGE without
CLTV/CSV rejected a script Core accepts. script_tests.json cannot see this: its
DISCOURAGE vectors cover NOP, NOP1 and NOP4..NOP10, never NOP2/NOP3."
  ;; The divergent case: DISCOURAGE on, CLTV/CSV off.
  (multiple-value-bind (ok err) (run-script-test "1" "CHECKLOCKTIMEVERIFY"
                                                 "DISCOURAGE_UPGRADABLE_NOPS")
    (is (eq ok t) "NOP2 without the CLTV flag is a plain NOP, got ~A" err))
  (multiple-value-bind (ok err) (run-script-test "1" "CHECKSEQUENCEVERIFY"
                                                 "DISCOURAGE_UPGRADABLE_NOPS")
    (is (eq ok t) "NOP3 without the CSV flag is a plain NOP, got ~A" err))
  ;; Control 1: the discourage machinery is genuinely armed by this flag string
  ;; -- an upgradable NOP under it still fails, so the two above are not passing
  ;; because the flag went missing.
  (is (null (run-script-test "1" "NOP1" "DISCOURAGE_UPGRADABLE_NOPS"))
      "NOP1 must still be discouraged")
  (is (null (run-script-test "1" "NOP10" "DISCOURAGE_UPGRADABLE_NOPS"))
      "NOP10 must still be discouraged")
  ;; Control 2: with its own flag on, the opcode is not a NOP at all -- stack
  ;; top 1 against the test transaction's nLockTime 0 is UNSATISFIED_LOCKTIME.
  (is (null (run-script-test "1" "CHECKLOCKTIMEVERIFY"
                             "CHECKLOCKTIMEVERIFY,DISCOURAGE_UPGRADABLE_NOPS"))
      "with CHECKLOCKTIMEVERIFY set the opcode must run BIP65, not pass")
  (is (null (run-script-test "1" "CHECKSEQUENCEVERIFY"
                             "CHECKSEQUENCEVERIFY,DISCOURAGE_UPGRADABLE_NOPS"))
      "with CHECKSEQUENCEVERIFY set the opcode must run BIP112, not pass"))

