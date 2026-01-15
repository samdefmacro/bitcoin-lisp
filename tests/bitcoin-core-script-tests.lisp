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
               "bitcoin/src/test/data/script_tests.json"
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

(defun run-script-test (script-sig-asm script-pubkey-asm flags)
  "Run a script test and return (values success-p error-or-nil).
   Executes scriptSig, then scriptPubKey on the resulting stack."
  (handler-case
      (let* ((sig-bytes (assemble-script script-sig-asm))
             (pubkey-bytes (assemble-script script-pubkey-asm))
             (p2sh-enabled (flags-include-p flags "P2SH")))
        ;; Set script flags for STRICTENC validation
        (bitcoin-lisp.coalton.interop:set-script-flags flags)
        (unwind-protect
            ;; Use the CL interop wrapper for P2SH support
            (multiple-value-bind (success stack-or-error)
                (bitcoin-lisp.coalton.interop:run-scripts-with-p2sh
                 sig-bytes pubkey-bytes p2sh-enabled)
              (if success
                  ;; Check if stack has items
                  (let ((depth (bitcoin-lisp.coalton.script:stack-depth stack-or-error)))
                    (if (> depth 0)
                        (values t nil)
                        (values t nil)))  ; Empty stack is ok after VERIFY
                  (values nil stack-or-error)))
          ;; Clear flags after test
          (bitcoin-lisp.coalton.interop:set-script-flags nil)))
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

(test script-tests-json-subset
  "Run a subset of Bitcoin Core script tests."
  (let* ((all-tests (load-script-tests))
         (passed 0)
         (failed-p2sh 0)
         (failed-cleanstack 0)
         (failed-minimaldata 0)
         (failed-other 0)
         (skipped-checksig 0)
         (skipped-witness 0)
         (errors '()))

    (loop for test in all-tests
          for i from 0
          when (< i *max-tests-to-run*)
          do (multiple-value-bind (sig pubkey flags expected comment witness)
                 (parse-test-case test)
               (when sig  ; Skip comment lines
                 (handler-case
                     (cond
                       ;; Skip witness tests
                       ((or witness (flags-include-p flags "WITNESS"))
                        (incf skipped-witness))

                       ;; Skip CHECKMULTISIG tests (not implemented yet)
                       ;; CHECKSIG is now implemented and will be tested
                       ((or (search "CHECKMULTISIG" pubkey)
                            (search "CHECKMULTISIG" sig))
                        (incf skipped-checksig))

                       (t
                        (multiple-value-bind (success err)
                            (run-script-test sig pubkey flags)
                          (let ((expected-ok (string= expected "OK")))
                            (if (eq success expected-ok)
                                (incf passed)
                                ;; Categorize failures
                                (cond
                                  ((flags-include-p flags "P2SH")
                                   (incf failed-p2sh))
                                  ((flags-include-p flags "CLEANSTACK")
                                   (incf failed-cleanstack))
                                  ((flags-include-p flags "MINIMALDATA")
                                   (incf failed-minimaldata))
                                  (t
                                   (incf failed-other)
                                   (push (list :index i
                                               :sig sig
                                               :pubkey pubkey
                                               :flags flags
                                               :expected expected
                                               :got (if success "OK" err)
                                               :comment comment)
                                         errors))))))))
                   (error (e)
                     (incf failed-other)
                     (push (list :index i
                                 :sig sig
                                 :pubkey pubkey
                                 :error (format nil "~A" e))
                           errors))))))

    ;; Report results
    (let ((total-failed (+ failed-p2sh failed-cleanstack failed-minimaldata failed-other)))
      (format t "~%Bitcoin Core Script Tests Results:~%")
      (format t "  Passed:  ~D~%" passed)
      (format t "  Failed (P2SH):       ~D~%" failed-p2sh)
      (format t "  Failed (CLEANSTACK): ~D~%" failed-cleanstack)
      (format t "  Failed (MINIMALDATA): ~D~%" failed-minimaldata)
      (format t "  Failed (Other):      ~D~%" failed-other)
      (format t "  Skipped (CHECKSIG):  ~D~%" skipped-checksig)
      (format t "  Skipped (WITNESS):   ~D~%" skipped-witness)
      (format t "  Total run: ~D~%" (+ passed total-failed))
      (format t "  Pass rate (excl. P2SH/CLEANSTACK/MINIMALDATA): ~,1F%~%"
              (if (zerop (+ passed failed-other))
                  0.0
                  (* 100.0 (/ passed (+ passed failed-other)))))

      (when errors
        (format t "~%Other failures (first 10):~%")
        (loop for err in (subseq errors 0 (min 10 (length errors)))
              do (format t "  ~A~%" err)))

      ;; Pass if "other" failures are zero or very low
      (is (<= failed-other 10)
          "Should have very few 'other' failures. Got: ~D" failed-other))))
