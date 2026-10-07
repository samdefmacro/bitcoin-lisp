(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/parse_script.cpp at the pin: ParseScript (core_io.cpp
;;;; :95-130, bitcoin-tx's outscript= assembler) over any text, where
;;;; std::runtime_error is the only refusal. Ours is PARSE-SCRIPT-ASM.
;;;;
;;;; Beyond Core's no-crash, the target writes programs word by word and
;;;; holds the result to what each word means in Core: a decimal in
;;;; +/-0xFFFFFFFF is CScript::push_int64 (the test-side builder in util.lisp),
;;;; `0x' and an even run of ASCII hex digits is raw bytes, a single-quoted
;;;; word is pushed, an opcode named as GetOpName names it is that byte with
;;;; or without OP_. Any other word refuses the whole text: an out-of-range
;;;; number, odd or non-ASCII hex, the small-number and push opcodes
;;;; (below OP_NOP, never in Core's map), a NOP renamed by its soft fork.

(def-suite :fuzz-parse-script-tests :in :bitcoin-lisp-tests
  :description "Core fuzz parse_script.cpp")

(in-suite :fuzz-parse-script-tests)

(defparameter +parse-script-opcodes+
  '(("OP_RESERVED" . #x50) ("OP_NOP" . #x61) ("OP_VER" . #x62) ("OP_IF" . #x63)
    ("OP_VERIF" . #x65) ("OP_VERNOTIF" . #x66) ("OP_ENDIF" . #x68) ("OP_VERIFY" . #x69)
    ("OP_RETURN" . #x6a) ("OP_DROP" . #x75) ("OP_DUP" . #x76) ("OP_CAT" . #x7e)
    ("OP_EQUAL" . #x87) ("OP_EQUALVERIFY" . #x88) ("OP_RESERVED1" . #x89)
    ("OP_RESERVED2" . #x8a) ("OP_HASH160" . #xa9) ("OP_CODESEPARATOR" . #xab)
    ("OP_CHECKSIG" . #xac) ("OP_CHECKMULTISIG" . #xae) ("OP_NOP1" . #xb0)
    ("OP_CHECKLOCKTIMEVERIFY" . #xb1) ("OP_CHECKSEQUENCEVERIFY" . #xb2)
    ("OP_NOP4" . #xb3) ("OP_NOP10" . #xb9) ("OP_CHECKSIGADD" . #xba))
  "Opcodes by Core's GetOpName (script/script.cpp:20-153).")

(defparameter +parse-script-non-opcodes+
  '("OP_0" "OP_FALSE" "OP_1" "OP_TRUE" "OP_16" "1NEGATE" "OP_1NEGATE" "OP_PUSHDATA1"
    "PUSHDATA4" "OP_NOP2" "NOP3" "OP_INVALIDOPCODE" "OP_UNKNOWN" "op_dup" "OP_DUP2")
  "Words that are no opcode in Core's map: the opcodes below OP_NOP (other than
OP_RESERVED), the soft-fork NOPs by their old names, past MAX_OPCODE, the
wrong case.")

(defun %parse-script-word (fdp out)
  "One word and, into the builder OUT, the bytes Core makes of it; NIL as the
second value when Core refuses it."
  (call-one-of fdp
    (let ((n (consume-integral-in-range fdp (- #xffffffff) #xffffffff)))
      (script-<<-int64 out n)
      (values (format nil "~D" n) t))
    (values (format nil "~:[-~;~]~D" (consume-bool fdp)
                    (consume-integral-in-range fdp #x100000000 (ash 1 70)))
            nil)
    (let ((bytes (consume-bytes fdp (consume-integral-in-range fdp 1 20))))
      (if (plusp (length bytes))
          (progn (script-append out bytes)
                 (values (concatenate 'string "0x" (if (consume-bool fdp)
                                                       (bl.crypto:bytes-to-hex bytes)
                                                       (string-upcase (bl.crypto:bytes-to-hex bytes))))
                         t))
          (values "0x" nil)))
    (values (concatenate 'string "0x" (subseq (bl.crypto:bytes-to-hex (consume-bytes fdp 3)) 0 5)) nil)
    (values (coerce (list #\0 #\x (code-char (+ #x0660 (consume-integral-in-range fdp 0 9)))
                          (code-char (+ #xff10 (consume-integral-in-range fdp 0 9))))
                    'string)
            nil)
    (let ((text (map 'string (lambda (b) (code-char (+ 33 (mod b 94))))
                     (consume-bytes fdp (consume-integral-in-range fdp 0 12)))))
      (script-<<-bytes out (map '(simple-array (unsigned-byte 8) (*)) #'char-code text))
      (values (concatenate 'string "'" text "'") t))
    (let ((op (pick-value-in-array fdp +parse-script-opcodes+)))
      (script-<<-opcode out (cdr op))
      (values (if (consume-bool fdp) (car op) (subseq (car op) 3)) t))
    (values (pick-value-in-array fdp +parse-script-non-opcodes+) nil)))

(defun %parse-script-outcome (text)
  "(values BYTES REFUSED-P): the script, or NIL and T when PARSE-SCRIPT-ASM
refused the text with Core's `script parse error'. Any other condition is a
crash."
  (handler-case (values (bl.tools:parse-script-asm text) nil)
    (error (e)
      (if (search "script parse error" (princ-to-string e))
          (values nil t)
          (error e)))))

(define-fuzz-target parse-script
    (buffer :core "parse_script.cpp:10-18" :iterations 4000 :max-len 300)
  "Any text parses or is refused with Core's script parse error; a text of
known words parses to exactly the bytes those words mean in Core, and one
unknown word refuses it all."
  (let ((fdp (make-fuzzed-data-provider buffer)))
    (if (zerop (consume-integral-in-range fdp 0 3))
        (%parse-script-outcome (map 'string #'code-char (consume-remaining-bytes fdp)))
        (let ((out (script-builder))
              (valid t)
              (words '()))
          (loop repeat (consume-integral-in-range fdp 1 8)
                do (multiple-value-bind (word ok) (%parse-script-word fdp out)
                     (push word words)
                     (unless ok (setf valid nil))))
          (let ((text (format nil (pick-value-in-array fdp '("~{~A~^ ~}" "~{~A~^  ~}" "~{ ~A~^	~}"))
                              (reverse words))))
            (multiple-value-bind (bytes refused) (%parse-script-outcome text)
              (if valid
                  (fuzz-assert (equalp (fuzz-sabotage bytes) (script-bytes out))
                               "~S parses to ~A, Core's bytes are ~A" text
                               (and bytes (bl.crypto:bytes-to-hex bytes)) (bl.crypto:bytes-to-hex (script-bytes out)))
                  (fuzz-assert refused "~S parses, Core refuses it" text))))))))
