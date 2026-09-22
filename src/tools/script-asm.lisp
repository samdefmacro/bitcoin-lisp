(in-package #:bitcoin-lisp.tools)

;;;; Core ParseScript (core_io.cpp:63-130): the script assembler bitcoin-tx's
;;;; outscript= command reads. Not the inverse of ScriptToAsmStr -- it takes
;;;; decimal numbers (pushed as CScriptNum), 0x-prefixed RAW bytes (inserted,
;;;; not pushed), 'quoted' strings (pushed) and opcode names with or without
;;;; their OP_ prefix, and nothing else.

(define-condition script-asm-error (error)
  ((message :initarg :message :reader script-asm-error-message))
  (:report (lambda (c s) (write-string (script-asm-error-message c) s)))
  (:documentation "ParseScript's std::runtime_error: the text Core throws."))

(defvar *opcode-name-table* nil
  "Core's OpCodeParser map (core_io.cpp:53-82), built on first use: every
opcode from OP_NOP to MAX_OPCODE plus OP_RESERVED, by its GetOpName and by
that name without OP_. The small-number opcodes are not in it: their
GetOpName is the number, which ParseScript reads as a number instead.")

(defun %opcode-name-table ()
  (or *opcode-name-table*
      (setf *opcode-name-table*
            (let ((table (make-hash-table :test 'equal)))
              ;; OP_RESERVED (0x50), then OP_NOP (0x61) .. OP_CHECKSIGADD
              ;; (0xba, MAX_OPCODE). The name is what the disassembler prints
              ;; for the one-byte script, which IS Core's GetOpName table.
              (dolist (op (cons #x50 (loop for op from #x61 to #xba collect op)))
                (let ((name (bl.val:disassemble-script
                             (make-array 1 :element-type '(unsigned-byte 8)
                                           :initial-element op))))
                  (unless (string= name "OP_UNKNOWN")
                    (setf (gethash name table) op)
                    (when (and (> (length name) 3) (string= "OP_" name :end2 3))
                      (setf (gethash (subseq name 3) table) op)))))
              table))))

(defun %script-num-bytes (n)
  "CScriptNum::serialize (script.h): N minimal little-endian, sign in the top
bit of the last byte."
  (if (zerop n)
      #()
      (let* ((negative (minusp n))
             (magnitude (abs n))
             (bytes (loop while (plusp magnitude)
                          collect (ldb (byte 8 0) magnitude)
                          do (setf magnitude (ash magnitude -8)))))
        (if (logbitp 7 (car (last bytes)))
            (setf bytes (append bytes (list (if negative #x80 0))))
            (when negative
              (setf (car (last bytes)) (logior (car (last bytes)) #x80))))
        (coerce bytes 'vector))))

(defun %push-int64 (n)
  "CScript::push_int64 (script.h): OP_0, OP_1NEGATE / OP_1..OP_16, or the
CScriptNum bytes as a data push."
  (cond ((zerop n) (vector #x00))
        ((or (= n -1) (<= 1 n 16)) (vector (+ #x50 n)))
        (t (bl.ser:script-push-data
            (coerce (%script-num-bytes n) '(simple-array (unsigned-byte 8) (*)))))))

(defun %all-digits-p (text &key (start 0))
  (and (< start (length text))
       (every (lambda (c) (char<= #\0 c #\9)) (subseq text start))))

(defun parse-script-asm (text)
  "Core ParseScript (core_io.cpp:95-130): TEXT as script bytes. Signals
SCRIPT-ASM-ERROR with Core's message for an unknown word or an out-of-range
decimal."
  (let ((out (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (flet ((emit (bytes) (loop for b across bytes do (vector-push-extend b out))))
      (dolist (word (uiop:split-string text :separator '(#\Space #\Tab #\Newline)))
        (cond
          ((zerop (length word)))
          ;; A number, optionally negative.
          ((or (%all-digits-p word)
               (and (char= (char word 0) #\-) (%all-digits-p word :start 1)))
           (let ((n (ignore-errors (parse-integer word))))
             (unless (and n (<= (- #xffffffff) n #xffffffff))
               (error 'script-asm-error
                      :message "script parse error: decimal numeric value only allowed in the range -0xFFFFFFFF...0xFFFFFFFF"))
             (emit (%push-int64 n))))
          ;; Raw hex, inserted as it stands.
          ((and (> (length word) 2) (string= "0x" word :end2 2)
                (%hex-p (subseq word 2)))
           (emit (bl.crypto:hex-to-bytes (subseq word 2))))
          ;; A single-quoted string, pushed.
          ((and (>= (length word) 2) (char= (char word 0) #\')
                (char= (char word (1- (length word))) #\'))
           (emit (bl.ser:script-push-data
                  (coerce (bl.ser:utf8-string-to-bytes (subseq word 1 (1- (length word))))
                          '(simple-array (unsigned-byte 8) (*))))))
          (t
           (let ((op (gethash word (%opcode-name-table))))
             (unless op
               (error 'script-asm-error :message "script parse error: unknown opcode"))
             (vector-push-extend op out))))))
    (coerce out '(simple-array (unsigned-byte 8) (*)))))
