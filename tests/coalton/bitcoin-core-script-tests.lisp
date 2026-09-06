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
  "Convert an integer to Bitcoin script number encoding (minimal, little-endian, sign bit).
Zero is the one-byte OP_0, as CScript::push_int64 writes it (script.h) and as
Core's ParseScript therefore assembles the token \"00\" -- not an empty
script. Assembling it as nothing made a non-empty scriptSig disappear, and
with it the WITNESS_MALLEATED rejection two corpus vectors are about."
  (cond
    ((zerop n) (vector #x00))
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

  ;; A witness vector's first element is the ARRAY [wit1 .. witN, amount];
  ;; every other vector starts with the scriptSig STRING. This used to ask
  ;; whether the first element's first element was itself a list, which no
  ;; vector satisfies -- the witness items are hex STRINGS -- so all 113
  ;; witness vectors were read one field to the left: the scriptSig became
  ;; the witness array, ASSEMBLE-SCRIPT signalled on it, and the expected
  ;; result became the FLAGS string, which is never "OK". Every one of them
  ;; therefore "passed" without executing anything.
  (let* ((has-witness (listp (first test)))
         (witness (when has-witness (butlast (first test))))
         ;; The last element of the witness array is the spent output's value
         ;; in BTC; Core runs it through AmountFromValue
         ;; (test/script_tests.cpp:952), so it reaches VerifyScript as
         ;; satoshis. Passed on raw it was 1e-8 satoshi, and every BIP 143
         ;; sighash over it was computed on a value no signature commits to.
         (amount (when has-witness
                   (round (* (car (last (first test))) 100000000))))
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

;;; Autogenerated Taproot vectors.
;;;
;;; Five corpus vectors do not spell their scriptPubKey or control block out:
;;; a witness element "#SCRIPT#<assembly>" is the tapleaf script, the element
;;; "#CONTROLBLOCK#" is the control block for it, and the scriptPubKey
;;; "0x51 0x20 #TAPROOTOUTPUT#" is the output key. Core's runner builds all
;;; three from the leaf script and its own key0 (script_tests.cpp:931-943 and
;;; :967-969); this does the same, so those vectors -- the corpus's ONLY
;;; tapscript ones -- actually execute here too.

(defparameter +script-test-key0+
  (let ((k (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref k 31) 1)
    k)
  "Core's vchKey0 (test/script_tests.cpp:183): the secret key whose x-only
public key is the internal key of every autogenerated Taproot vector.")

(defparameter +taproot-leaf-tapscript+ #xc0
  "TAPROOT_LEAF_TAPSCRIPT: the only leaf version these vectors use.")

(defun script-test-internal-pubkey ()
  "The 32-byte x-only internal key of the autogenerated Taproot vectors."
  (subseq (bl.crypto:derive-public-key +script-test-key0+ :compressed t) 1 33))

(defun script-test-taproot-spend-data (leaf-script)
  "The output key and control block for a one-leaf Taproot tree over
LEAF-SCRIPT, as Core's TaprootBuilder produces them for depth 0.
Returns (values output-key32 control-block)."
  (let* ((internal (script-test-internal-pubkey))
         (merkle-root (bl.crypto:tap-leaf-hash +taproot-leaf-tapscript+ leaf-script)))
    (multiple-value-bind (output parity) (bl.interop:compute-tweaked-pubkey internal merkle-root)
      (let ((control (make-array 33 :element-type '(unsigned-byte 8))))
        (setf (aref control 0) (logior +taproot-leaf-tapscript+ (if (zerop parity) 0 1)))
        (replace control internal :start1 1)
        (values output control)))))

(defun script-test-leaf-script (item)
  "ITEM assembled as a tapleaf script when it carries the #SCRIPT# flag."
  (let ((flag "#SCRIPT#"))
    (when (and (> (length item) (length flag))
               (string= flag item :end2 (length flag)))
      (assemble-script (subseq item (length flag))))))

(defun parse-witness-stack (witness-data)
  "Parse witness data from test format into a list of byte arrays.
WITNESS-DATA is a list of hex strings, plus the two placeholders Core's runner
expands: \"#SCRIPT#<assembly>\" assembles to the tapleaf script, and
\"#CONTROLBLOCK#\" becomes the control block for the element before it."
  (let ((stack '()))
    (dolist (item witness-data (nreverse stack))
      (push (cond
              ((not (stringp item))
               (make-array 0 :element-type '(unsigned-byte 8)))
              ((script-test-leaf-script item))
              ((string= item "#CONTROLBLOCK#")
               (nth-value 1 (script-test-taproot-spend-data (first stack))))
              ((zerop (length item))
               (make-array 0 :element-type '(unsigned-byte 8)))
              (t (bl.crypto:hex-to-bytes item)))
            stack))))

(defun script-test-script-pubkey (script-pubkey-asm witness-stack)
  "SCRIPT-PUBKEY-ASM assembled, expanding Core's autogenerated Taproot output.
WITNESS-STACK is the already-expanded witness, so the tapleaf script is the
element before the control block -- third from last in the JSON array, whose
last element is the amount (script_tests.cpp:932)."
  (if (string= script-pubkey-asm "0x51 0x20 #TAPROOTOUTPUT#")
      (let ((leaf (nth (- (length witness-stack) 2) witness-stack)))
        (concatenate '(vector (unsigned-byte 8))
                     (vector #x51 #x20)
                     (script-test-taproot-spend-data leaf)))
      (assemble-script script-pubkey-asm)))

(defun script-test-flags (flags)
  "FLAGS with Core's own DoTest implication applied: SCRIPT_VERIFY_CLEANSTACK
drags in P2SH and WITNESS (test/script_tests.cpp:127-130), because cleanstack
is only defined once those two have consumed what they consume."
  (if (flags-include-p flags "CLEANSTACK")
      (concatenate 'string (or flags "") ",P2SH,WITNESS")
      flags))

(defun run-script-test (script-sig-asm script-pubkey-asm flags &optional witness-data amount)
  "Run one script_tests.json vector and return (values success-p error).
The vector goes through BL.INTEROP:VERIFY-SCRIPT, the same entry point block
and mempool validation call, so the corpus measures the shipped VerifyScript
flow (interpreter.cpp:2002-2126) rather than a second copy of it. ERROR is one
of our script-error keywords, which BL.INTEROP:SCRIPT-ERROR-NAME turns into
the SCRIPT_ERR_* name the corpus expects."
  (handler-case
      (let* ((sig-bytes (assemble-script script-sig-asm))
             (witness-stack (parse-witness-stack witness-data))
             (pubkey-bytes (script-test-script-pubkey script-pubkey-asm witness-stack))
             (input-amount (or amount 0)))
        (bl.interop:set-script-flags (script-test-flags flags))
        (setf bl.interop:*witness-input-amount* input-amount)
        (unwind-protect
             (bl.interop:verify-script sig-bytes pubkey-bytes
                                       :witness witness-stack
                                       :amount input-amount)
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

;;;; The corpus, compared on Core's verdict AND on Core's error name.
;;;;
;;;; script_tests.json carries the exact SCRIPT_ERR_* name for every failing
;;;; vector, and Core's own runner asserts it (test/script_tests.cpp:135). A
;;;; rule that rejects for the WRONG reason is invisible to an accept/reject
;;;; comparison, and one extra opcode is often all it takes to turn such a
;;;; difference into a verdict difference -- which is how the PUBKEYTYPE
;;;; divergence closed in "Script: an empty signature still checks the pubkey
;;;; encoding" hid behind 1,222 green vectors.

(defparameter *script-error-name-exceptions*
  ;; (VECTOR-INDEX EXPECTED-NAME OUR-NAME . REASON). Each entry must still be
  ;; a mismatch and still be THAT mismatch: an entry whose case now agrees, or
  ;; disagrees differently, fails the test, so this list can only shrink.
  '()
  "Vectors whose error name we knowingly do not reproduce, with the reason.")

(defun %script-error-name (ok error)
  "The SCRIPT_ERR_* name script_tests.json would carry for our outcome."
  (if ok "OK" (bl.interop:script-error-name error)))

(defun %script-corpus-outcomes ()
  "Run every script_tests.json vector once.
Returns a list of (INDEX EXPECTED GOT-NAME OK-P SIG PUBKEY FLAGS COMMENT),
one per vector, in file order."
  (let ((outcomes '()))
    (loop for test in (load-script-tests)
          for i from 0
          when (< i *max-tests-to-run*)
            do (multiple-value-bind (sig pubkey flags expected comment witness amount)
                   (parse-test-case test)
                 (when sig
                   (multiple-value-bind (ok err)
                       (run-script-test sig pubkey flags witness amount)
                     (push (list i expected (%script-error-name ok err) (and ok t)
                                 sig pubkey flags comment)
                           outcomes)))))
    (nreverse outcomes)))

(defun %script-corpus-mismatches (outcomes)
  "Split OUTCOMES into (VALUES VERDICT-MISMATCHES NAME-MISMATCHES).
A verdict mismatch is accepted-vs-rejected; a name mismatch agrees on the
verdict but names a different Core error."
  (let ((verdict '()) (name '()))
    (dolist (row outcomes)
      (destructuring-bind (index expected got ok &rest vector) row
        (declare (ignore index vector))
        (cond ((not (eq (and ok t) (string= expected "OK"))) (push row verdict))
              ((string/= expected got) (push row name)))))
    (values (nreverse verdict) (nreverse name))))

(defun %describe-script-vector (row)
  "One line naming the vector and both error names."
  (destructuring-bind (index expected got ok sig pubkey flags comment) row
    (format nil "[~D] expected ~A got ~A (~:[reject~;accept~]) sig=~S pubkey=~S flags=~S~@[ ; ~A~]"
            index expected got ok sig pubkey flags comment)))

(test script-tests-json-full
  "Every Bitcoin Core script_tests.json vector, on the verdict AND the error.

Core's runner checks both (test/script_tests.cpp:134-135), so this one does
too: VerifyScript's accept/reject answer, and -- for every vector Core expects
to fail -- the SCRIPT_ERR_* name it expects. The names come from
BL.INTEROP:SCRIPT-ERROR-NAME, which is the single table mapping our script
errors onto Core's."
  (let ((outcomes (%script-corpus-outcomes)))
    (is (= 1222 (length outcomes))
        "the corpus is 1,222 vectors, not ~D -- refs/bitcoin moved?"
        (length outcomes))
    (multiple-value-bind (verdict-mismatches name-mismatches)
        (%script-corpus-mismatches outcomes)
      ;; The exception list is spent first: every entry must still describe a
      ;; live mismatch, so a case that starts agreeing fails until its entry
      ;; is deleted.
      (let ((remaining name-mismatches))
        (dolist (entry *script-error-name-exceptions*)
          (destructuring-bind (index expected got . reason) entry
            (let ((row (find index remaining :key #'first)))
              (is-true row
                       "vector ~D no longer mismatches its error name (~A); ~
delete its exception entry (~A)" index expected reason)
              (when row
                (is (and (string= (second row) expected) (string= (third row) got))
                    "vector ~D now mismatches differently: expected ~A got ~A, ~
the exception says expected ~A got ~A"
                    index (second row) (third row) expected got)
                (setf remaining (remove row remaining))))))
        (format t "~%Bitcoin Core script_tests.json:~%")
        (format t "  Vectors:            ~D~%" (length outcomes))
        (format t "  Verdict mismatches: ~D~%" (length verdict-mismatches))
        (format t "  Error-name mismatches: ~D (~D allowed)~%"
                (length remaining) (length *script-error-name-exceptions*))
        (dolist (row verdict-mismatches)
          (format t "  VERDICT ~A~%" (%describe-script-vector row)))
        (dolist (row remaining)
          (format t "  NAME    ~A~%" (%describe-script-vector row)))
        (is (null verdict-mismatches)
            "~D vectors disagree with Core's accept/reject verdict"
            (length verdict-mismatches))
        (is (null remaining)
            "~D vectors reject for a different reason than Core: ~{~%    ~A~}"
            (length remaining)
            (mapcar #'%describe-script-vector remaining))))))

(test script-error-name-comparison-can-fail
  "Positive control for the comparison above.
A corpus runner that compared only accept/reject passed every one of these
divergences, so the new check must be shown to have teeth: feed
%SCRIPT-CORPUS-MISMATCHES a row whose verdict agrees and whose name does not,
and it must report exactly that row."
  (let* ((agreeing '(7 "EVAL_FALSE" "EVAL_FALSE" nil "" "0" "" nil))
         (misnamed '(9 "EVAL_FALSE" "VERIFY" nil "" "0" "" nil))
         (miscounted '(11 "OK" "VERIFY" nil "" "0" "" nil)))
    (multiple-value-bind (verdicts names)
        (%script-corpus-mismatches (list agreeing misnamed miscounted))
      (is (equal '(11) (mapcar #'first verdicts))
          "the verdict comparison must flag exactly the accepted/rejected split")
      (is (equal '(9) (mapcar #'first names))
          "the name comparison must flag exactly the wrongly-named rejection"))
    ;; And the names themselves must come from the table, not from our keyword
    ;; spelling: these are the four Core names our engine used to answer
    ;; SCRIPT_ERR_VERIFY for.
    (is (string= "EQUALVERIFY" (bl.interop:script-error-name :equalverify)))
    (is (string= "CHECKSIGVERIFY" (bl.interop:script-error-name :checksigverify)))
    (is (string= "PUBKEY_COUNT" (bl.interop:script-error-name :pubkey-count)))
    (is (string= "TAPSCRIPT_EMPTY_PUBKEY"
                 (bl.interop:script-error-name :tapscript-empty-pubkey)))))

;;;; The error vocabulary itself: one Core error per variant, and no gaps.
;;;;
;;;; The corpus above can only compare the errors it happens to provoke. These
;;;; two scans close the rest: every ScriptError the engine defines must name a
;;;; Core error, and every keyword the CHECK(MULTI)SIG wrappers can record must
;;;; convert back to the SAME Core error. Without the second one a new keyword
;;;; silently falls back to SE-VerifyFailed, which is exactly the collapse this
;;;; work undid.

(defun %script-source-text (relative-path)
  "RELATIVE-PATH under the system directory, as one string."
  (let ((path (merge-pathnames relative-path
                               (asdf:system-source-directory :bitcoin-lisp))))
    (with-open-file (in path :if-does-not-exist nil)
      (when in
        (let ((text (make-string (file-length in))))
          (subseq text 0 (read-sequence text in)))))))

(defun %script-error-variant-names (text)
  "The ScriptError constructor names TEXT's DEFINE-TYPE declares.
Factored out so the positive control can feed it a synthetic type."
  (let ((names '())
        (start (search "(define-type ScriptError" text)))
    (when start
      (let* ((end (or (search "(declare script-error-name" text :start2 start)
                      (length text)))
             (body (subseq text start end))
             (pos 0))
        (loop
          (let ((at (search "SE-" body :start2 pos)))
            (unless at (return))
            (let ((stop (or (position-if-not
                             (lambda (c) (or (alphanumericp c) (char= c #\-)))
                             body :start at)
                            (length body))))
              (pushnew (subseq body at stop) names :test #'string=)
              (setf pos stop))))))
    (nreverse names)))

(defun %interop-error-keywords (text function-names)
  "Every error keyword the named top-level functions of TEXT can return or record.
A keyword is one written as `(values nil :name' or stored into a
*LAST-...-ERROR* special."
  (let ((keywords '()))
    (dolist (name function-names (nreverse keywords))
      (let* ((head (format nil "(defun ~A " name))
             (start (search head text)))
        (assert start () "no top-level ~A in the interop source" name)
        (let* ((next (search (format nil "~%(defun ") text :start2 (1+ start)))
               (body (subseq text start (or next (length text))))
               (pos 0))
          (loop
            (let* ((a (search "(values nil :" body :start2 pos))
                   (b (search "-error* :" body :start2 pos))
                   (at (cond ((null a) b) ((null b) a) (t (min a b)))))
              (unless at (return))
              (let* ((colon (position #\: body :start at))
                     (stop (or (position-if-not
                                (lambda (c) (or (alphanumericp c) (char= c #\-)))
                                body :start (1+ colon))
                               (length body))))
                (pushnew (intern (string-upcase (subseq body (1+ colon) stop))
                                 :keyword)
                         keywords)
                (setf pos stop)))))))))

(defun %core-script-error-names ()
  "Every name Bitcoin Core has for a script error.
Two sources, re-parsed each run so a name we invent or misspell cannot pass as
Core's: the quoted names of test/script_tests.cpp's script_errors[] table,
which is what script_tests.json writes (and which is not always the enum name
-- SCRIPT_ERR_SIG_NULLFAIL is spelled \"NULLFAIL\" there), plus the enum names
of script/script_error.h without their prefix, for the Taproot-era values that
table stops short of."
  (let ((names '()))
    ;; script_errors[] rows: {SCRIPT_ERR_X, "NAME"}
    (let ((text (%script-source-text "refs/bitcoin/src/test/script_tests.cpp"))
          (pos 0))
      (loop
        (let ((at (search "{SCRIPT_ERR_" text :start2 pos)))
          (unless at (return))
          (let* ((open (position #\" text :start at))
                 (close (and open (position #\" text :start (1+ open)))))
            (unless close (return))
            (pushnew (subseq text (1+ open) close) names :test #'string=)
            (setf pos close)))))
    ;; script_error.h enum names, prefix stripped
    (let ((text (%script-source-text "refs/bitcoin/src/script/script_error.h"))
          (prefix "SCRIPT_ERR_")
          (pos 0))
      (loop
        (let ((at (search prefix text :start2 pos)))
          (unless at (return))
          (let ((stop (or (position-if-not
                           (lambda (c) (or (alphanumericp c) (char= c #\_)))
                           text :start at)
                          (length text))))
            (pushnew (subseq text (+ at (length prefix)) stop) names :test #'string=)
            (setf pos stop)))))
    names))

(test script-errors-cover-the-engine
  "Every ScriptError variant names exactly one Bitcoin Core SCRIPT_ERR_*.
The corpus can only judge the errors its vectors provoke; this walks the type
itself, so a variant added without a name -- which BL.SCRIPT:SCRIPT-ERROR-NAME
would answer for by falling out of its MATCH -- is caught here instead of
turning into an UNKNOWN_ERROR in the next corpus run."
  (let ((names (%script-error-variant-names
                (%script-source-text "src/coalton/script.lisp")))
        (core-names (%core-script-error-names)))
    (is (> (length names) 40)
        "the scan found ~D ScriptError variants, too few to be the real type"
        (length names))
    (is (> (length core-names) 50)
        "the scan found ~D Core error names, too few to be script_error.h and ~
script_tests.cpp together" (length core-names))
    (is-true (member "NULLFAIL" core-names :test #'string=)
             "the scan must pick up script_tests.cpp's own spellings")
    (dolist (name names)
      ;; The reader upcases, so the constructor's symbol is the upcased name
      ;; even though the type spells it in camel case.
      (let ((symbol (find-symbol (string-upcase name) "BITCOIN-LISP.COALTON.SCRIPT")))
        (is-true symbol "~A is not a symbol of the script package" name)
        (when symbol
          (let* ((value (eval symbol))
                 (core-name (bl.script:script-error-name value)))
            (is-true (assoc (bl.interop:script-error-keyword value)
                            bl.interop:+script-errors+)
                     "~A names ~S, which has no row in +SCRIPT-ERRORS+"
                     name core-name)
            (is-true (member core-name core-names :test #'string=)
                     "~A names ~S, which is not a SCRIPT_ERR_* in Core's own ~
script_error.h" name core-name)))))
    ;; Positive control: the scanner must find the variants of a synthetic
    ;; type, and must not report a name for something that is not an error.
    (is (equal '("SE-Alpha" "SE-Beta")
               (%script-error-variant-names
                "(define-type ScriptError \"d\" SE-Alpha ; c
    SE-Beta) (declare script-error-name ..."))
        "the variant scan must read a type it is handed")
    (is (string= "UNKNOWN_ERROR" (bl.interop:script-error-name :no-such-error))
        "an unnamed error must be Core's UNKNOWN_ERROR, not a guess")
    (is-false (member "NOT_A_CORE_ERROR" (%core-script-error-names) :test #'string=)
              "the script_error.h scan must not answer for an invented name")))

(test checksig-error-keywords-are-all-mapped
  "Every CHECK(MULTI)SIG rejection reaches the engine as its own Core error.
The wrappers record a keyword and BL.INTEROP:SCRIPT-ERROR-FOR-KEYWORD turns it
back into a ScriptError for the opcode to report; an unmapped keyword falls
back to SE-VerifyFailed, so the two would disagree about which Core error the
rejection is. Comparing them keeps the fallback from swallowing a new keyword."
  (let* ((text (%script-source-text "src/coalton/interop.lisp"))
         (keywords (%interop-error-keywords
                    text '("verify-checksig" "verify-checksig-witness"
                           "check-checksig-encodings" "check-pubkey-encoding"
                           "verify-checkmultisig" "verify-checkmultisig-for-script"
                           "do-checkmultisig-stack-op"))))
    (is (> (length keywords) 5)
        "the scan found ~D CHECK(MULTI)SIG error keywords: ~S" (length keywords) keywords)
    (dolist (kw keywords)
      (is (string= (bl.interop:script-error-name kw)
                   (bl.script:script-error-name
                    (bl.interop:script-error-for-keyword kw)))
          "~S is ~A to the table and ~A to the engine"
          kw (bl.interop:script-error-name kw)
          (bl.script:script-error-name (bl.interop:script-error-for-keyword kw))))
    ;; Positive control: a keyword that is deliberately NOT in the map must
    ;; fail the same comparison, so a green run above is not vacuous.
    (is (string/= (bl.interop:script-error-name :sig-pushonly)
                  (bl.script:script-error-name
                   (bl.interop:script-error-for-keyword :sig-pushonly)))
        "an unmapped keyword must disagree with the engine, or this test ~
cannot detect one")))

(test script-error-keywords-all-have-core-names
  "Every error keyword the interop layer returns has a Core name and message.
BL.INTEROP:SCRIPT-ERROR-NAME falls back to UNKNOWN_ERROR, which would make a
new keyword invisible to the corpus comparison and would print Core's
`unknown error' in a mempool reject reason."
  (let* ((text (%script-source-text "src/coalton/interop.lisp"))
         (keywords (%interop-error-keywords
                    text '("verify-script" "validate-witness-program"
                           "validate-p2wpkh" "validate-p2wsh" "run-tapscript"
                           "validate-taproot" "validate-taproot-key-path"
                           "validate-taproot-script-path"))))
    (is (> (length keywords) 12)
        "the scan found ~D witness-level error keywords: ~S"
        (length keywords) keywords)
    (dolist (kw keywords)
      (is-true (assoc kw bl.interop:+script-errors+)
               "~S has no row in +SCRIPT-ERRORS+, so it renders as UNKNOWN_ERROR" kw))
    ;; Positive control: the scanner reads a body it is handed, and a keyword
    ;; that is genuinely absent is reported.
    (is (null (assoc :not-a-script-error bl.interop:+script-errors+))
        "the table must not answer for an invented keyword")))

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

(test is-push-only-counts-op-reserved-as-push
  "CONSENSUS (Core script.cpp:266-281): CScript::IsPushOnly walks the script and
rejects on `opcode > OP_16', so OP_RESERVED (0x50 <= OP_16 = 0x60) IS push-type
-- Core's own comment says so, and notes that executing OP_RESERVED fails
anyway, which is why P2SH is unaffected. We rejected it, so a P2SH spend whose
scriptSig starts with OP_RESERVED was refused as SIG_PUSHONLY where Core refuses
it as BAD_OPCODE (interpreter.cpp:1217-1218, the switch default). No
script_tests.json vector covers it: the one at line 1139 puts OP_RESERVED in the
redeem script, not in the scriptSig."
  (is-true (bl.interop:script-is-push-only-p (%w8d-script #x50))
           "OP_RESERVED is push-type for IsPushOnly")
  (is-true (bl.interop:script-is-push-only-p (%w8d-script #x4f))
           "OP_1NEGATE is push-type")
  (is-true (bl.interop:script-is-push-only-p (%w8d-script #x60))
           "OP_16 is push-type")
  ;; Control: the predicate still says NO one opcode past the boundary, and for
  ;; a push that runs off the end (Core's GetOp failure).
  (is-false (bl.interop:script-is-push-only-p (%w8d-script #x61))
            "OP_NOP (0x61 > OP_16) is not push-type")
  (is-false (bl.interop:script-is-push-only-p (%w8d-script #x02 #x51))
            "a truncated push is not push-only")
  ;; End to end: P2SH(OP_1) spent with OP_RESERVED ahead of the redeem push.
  ;; Core runs the scriptSig and dies on the opcode; we must reach the engine
  ;; too, i.e. report the engine's error and not SIG_PUSHONLY.
  (let* ((redeem (%w8d-script #x51))
         (spk (%w8d-script #xa9 #x14 (bl.crypto:hash160 redeem) #x87)))
    (bl.interop:set-script-flags "P2SH")
    (unwind-protect
         (progn
           (multiple-value-bind (ok err)
               (bl.interop:verify-script (%w8d-script #x50 #x01 #x51) spk)
             (is (null ok))
             (is (eq err :bad-opcode)
                 "OP_RESERVED must fail in the engine (Core BAD_OPCODE), got ~A" err))
           ;; Control: a scriptSig opcode Core really does call non-push still
           ;; short-circuits as SIG_PUSHONLY, and a plain push still verifies.
           (multiple-value-bind (ok err)
               (bl.interop:verify-script (%w8d-script #x61 #x01 #x51) spk)
             (is (null ok))
             (is (eq err :sig-pushonly) "OP_NOP in the scriptSig, got ~A" err))
           (multiple-value-bind (ok err)
               (bl.interop:verify-script (%w8d-script #x01 #x51) spk)
             (is (eq ok t) "the ordinary P2SH(OP_1) spend must verify, got ~A" err)))
      (bl.interop:set-script-flags nil))))

(test checkmultisig-charges-the-key-count-before-verifying
  "CONSENSUS (Core interpreter.cpp:1116-1121): OP_CHECKMULTISIG does
`nOpCount += nKeysCount; if (nOpCount > MAX_OPS_PER_SCRIPT) return
set_error(SCRIPT_ERR_OP_COUNT);' the moment the key count has been read and
range-checked -- ahead of the FindAndDelete loop and ahead of the verification
loop, so a script that busts the 201-op budget costs zero ECDSA verifications.
We charged it after running the whole multisig, so the budget overrun was
reported as whatever the stack ran out of first. The script below is
`<n OP_NOP> <push 20> OP_CHECKMULTISIG': the budget is n + 1 (the CHECKMULTISIG
opcode itself) + 20 (the keys), so Core busts at n = 181 and nowhere earlier.
script_tests.json's OP_COUNT vectors all have the keys on the stack, so they
reach the same verdict either way."
  (flet ((engine-error (n-nops)
           (let ((r (bl.script:execute-script
                     (concatenate 'vector
                                  (make-array n-nops :initial-element #x61)
                                  (vector #x01 #x14 #xae)))))
             (and (not (bl.script:script-result-ok-p r))
                  (bl.script:script-result-error r)))))
    (bl.interop:set-script-flags "")
    (unwind-protect
         (progn
           ;; 181 + 1 + 20 = 202 > 201: the charge fires before the keys are read.
           (is (eq (engine-error 181) bl.script:se-toomanyops)
               "n=181 must bust the op budget before touching the stack")
           (is (eq (engine-error 182) bl.script:se-toomanyops)
               "n=182 likewise")
           ;; Control: one opcode below the boundary, 180 + 1 + 20 = 201, is NOT
           ;; over the limit, so execution proceeds and the missing keys are a
           ;; stack underflow -- exactly Core's INVALID_STACK_OPERATION. Without
           ;; this the test would pass against a charge made anywhere at all.
           (is (eq (engine-error 180) bl.script:se-stackunderflow)
               "n=180 is exactly at the limit and must proceed to the stack")
           (is (eq (engine-error 0) bl.script:se-stackunderflow)
               "with no NOPs at all the failure is still the stack"))
      (bl.interop:set-script-flags nil))))

(test empty-signature-still-checks-the-pubkey-encoding
  "CONSENSUS (Core interpreter.cpp:335): EvalChecksigPreTapscript runs
CheckSignatureEncoding -- which answers true for an EMPTY signature (:186-188)
-- and then CheckPubKeyEncoding for every signature, empty ones included, so
under STRICTENC an ill-encoded key fails PUBKEYTYPE whatever the signature is.
We returned a plain `did not verify' for an empty signature and never looked at
the key. script_tests.json 1086/1087 are this shape and pass either way, because
both trees reject and the corpus runner compares only pass/fail; appending
OP_NOT turns it into an accept/reject split, and Core has no such vector.
The keys are those vectors': 33 bytes with the uncompressed 0x04 prefix, and a
valid compressed one as the control."
  (let* ((bad-key (bl.crypto:hex-to-bytes
                   "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"))
         (good-key (bl.crypto:hex-to-bytes
                    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"))
         (empty-sig (%w8d-script #x00)))
    (flet ((p2pk (key &rest tail)
             (apply #'%w8d-script #x21 key #xac tail))
           (verify (sig spk flags)
             (bl.interop:set-script-flags flags)
             (unwind-protect (multiple-value-list
                              (bl.interop:verify-script sig spk))
               (bl.interop:set-script-flags nil))))
      ;; The accept/reject split: with OP_NOT the skipped check decided the
      ;; verdict, not just the error name.
      (is (equal '(nil :pubkeytype)
                 (verify empty-sig (p2pk bad-key #x91) "STRICTENC"))
          "empty sig against a bad key with NOT must fail (Core PUBKEYTYPE)")
      ;; Same script without NOT: the error name is observable here too --
      ;; a script ERROR, not a false result.
      (is (equal '(nil :pubkeytype)
                 (verify empty-sig (p2pk bad-key) "STRICTENC"))
          "empty sig against a bad key is PUBKEYTYPE, not EVAL_FALSE")
      ;; Control 1: without STRICTENC, Core's CheckPubKeyEncoding passes and the
      ;; empty signature simply fails to verify, so NOT succeeds. This is what
      ;; makes the test above about the encoding check and not about empty
      ;; signatures in general.
      (is (equal '(t nil) (verify empty-sig (p2pk bad-key #x91) ""))
          "without STRICTENC the same script must still succeed")
      ;; Control 2: a well-encoded key under STRICTENC behaves the same way.
      (is (equal '(t nil) (verify empty-sig (p2pk good-key #x91) "STRICTENC"))
          "a valid compressed key with an empty signature must still succeed"))))
