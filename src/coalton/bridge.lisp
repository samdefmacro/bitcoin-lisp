;;;; The byte-vector crossing between CL and the Coalton interpreter.
;;;;
;;;; Coalton's (Vector U8) is a (VECTOR T): the interpreter's scripts, witness
;;;; items and stack elements are SIMPLE-VECTORs of fixnums, while every CL
;;;; layer (the wire, the crypto FFI, the sighash writers) holds octets. These
;;;; two functions are the whole crossing. They load before the Coalton files
;;;; (in the bridge's own package, defined in package.lisp) so the interpreter
;;;; and the hash wrappers can call them directly.

(in-package #:bitcoin-lisp.coalton.interop)

(defun cl-array-to-coalton-vector (cl-array)
  "Convert a CL byte array to a Coalton vector: a SIMPLE-VECTOR holding the
same elements, which is what (map 'vector #'identity cl-array) returns.

An octet vector -- every script, witness item and stack element the script
paths hand over -- is copied by a typed loop. The generic MAP calls IDENTITY
per element, and the round-10 IBD profile (2,100 regtest blocks of ~925 KB,
sb-sprof over the syncing node) put 12.5% of all samples here: each P2WSH
input converts its scriptPubKey five times. Anything else keeps the generic
path."
  (if (typep cl-array '(simple-array (unsigned-byte 8) (*)))
      (let* ((n (length cl-array))
             (v (make-array n)))
        (declare (type (simple-array (unsigned-byte 8) (*)) cl-array)
                 (type simple-vector v))
        (dotimes (i n v)
          (setf (svref v i) (aref cl-array i))))
      (map 'vector #'identity cl-array)))

(defun coalton-vector-to-cl-array (vec &optional (start 0))
  "VEC's elements from START as a (SIMPLE-ARRAY (UNSIGNED-BYTE 8) (*)): what
(coerce (subseq vec start) '(simple-array (unsigned-byte 8) (*))) returns,
VEC itself included when it already is one and START is 0. An element that is
not an octet is a TYPE-ERROR, as it is for COERCE.

A Coalton vector (a SIMPLE-VECTOR) is copied by a typed loop. COERCE ran it
through the generic REPLACE, checking each element's type through a full
call: every CHECKSIG converted its signature, its pubkey and the script from
the last OP_CODESEPARATOR that way (the last one twice, SUBSEQ then COERCE),
10.4% of the samples of the interpreter over a fixed P2WSH set and 2.6% of
the round-10 IBD profile, as REPLACE under EXECUTE-OPCODE."
  (typecase vec
    ((simple-array (unsigned-byte 8) (*))
     (if (zerop start) vec (subseq vec start)))
    (simple-vector
     (let* ((n (- (length vec) start))
            (out (make-array n :element-type '(unsigned-byte 8))))
       (declare (type fixnum start n))
       (dotimes (i n out)
         (setf (aref out i) (the (unsigned-byte 8) (svref vec (+ start i)))))))
    (t
     (coerce (subseq vec start) '(simple-array (unsigned-byte 8) (*))))))

;;; ============================================================
;;; Script verification flags: Core's flags WORD behind our flags STRING
;;; ============================================================
;;;
;;; Core passes script_verify_flags, a bit set (script/interpreter.h:49-71),
;;; and every rule asks `flags & SCRIPT_VERIFY_X'. Ours bind *SCRIPT-FLAGS* to
;;; a comma-separated STRING -- the surface every caller, RPC and test vector
;;; uses, and it stays. What changes is the question: the string is parsed
;;; once into Core's word, and FLAG-ENABLED-P of a constant name is a bit test
;;; on it. A P2WSH input asked 24 flags, each an EQUAL hash of the flag name
;;; into a per-string table: 1.3% of the round-11 IBD profile.

(defvar *script-flags* nil
  "The script verification flags in force: a comma-separated string of Core's
SCRIPT_VERIFY_* names without the prefix (\"P2SH,WITNESS,...\"), or NIL for
none. Bound per block, per transaction or per test vector.")

(defun set-script-flags (flags-string)
  "Set script execution flags from a comma-separated string."
  (setf *script-flags* flags-string))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defparameter +script-flag-bits+
    '(("P2SH" . 0) ("STRICTENC" . 1) ("DERSIG" . 2) ("LOW_S" . 3)
      ("NULLDUMMY" . 4) ("SIGPUSHONLY" . 5) ("MINIMALDATA" . 6)
      ("DISCOURAGE_UPGRADABLE_NOPS" . 7) ("CLEANSTACK" . 8)
      ("CHECKLOCKTIMEVERIFY" . 9) ("CHECKSEQUENCEVERIFY" . 10) ("WITNESS" . 11)
      ("DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" . 12) ("MINIMALIF" . 13)
      ("NULLFAIL" . 14) ("WITNESS_PUBKEYTYPE" . 15) ("CONST_SCRIPTCODE" . 16)
      ("TAPROOT" . 17) ("DISCOURAGE_UPGRADABLE_TAPROOT_VERSION" . 18)
      ("DISCOURAGE_OP_SUCCESS" . 19) ("DISCOURAGE_UPGRADABLE_PUBKEYTYPE" . 20)
      ;; Not Core's: the interpreter's own mark that a tapscript leaf is
      ;; running (VALIDATE-TAPSCRIPT appends it), where Core passes
      ;; SigVersion::TAPSCRIPT. Above Core's 21 bits so it can never alias one.
      ("TAPSCRIPT" . 32))
    "Flag name -> bit, in Core's script_verify_flag_name order
(script/interpreter.h:49-71, SCRIPT_VERIFY_P2SH = bit 0 ...).")

  (defun script-flag-bit (name)
    "The bit NAME occupies in the flags word, or NIL for a name that has none."
    (cdr (assoc name +script-flag-bits+ :test #'string=))))

(defun parse-script-flags (flags-string)
  "(word . names) for FLAGS-STRING: Core's flags word, and the set of every
comma-separated token -- the whole answer the string gives, for a name that
has no bit."
  (let ((word 0)
        (names (make-hash-table :test 'equal)))
    (dolist (token (uiop:split-string flags-string :separator ","))
      (setf (gethash token names) t)
      (let ((bit (script-flag-bit token)))
        (when bit (setf word (logior word (ash 1 bit))))))
    (cons word names)))

(defvar *flag-set-cache*
  (make-hash-table :test 'equal :size 16 #+sbcl :synchronized #+sbcl t)
  "Flags string -> PARSE-SCRIPT-FLAGS of it.

SYNCHRONIZED, because the parse is inserted on a miss and every parallel
script-check worker reads flags. Concurrent read-through inserts into a plain
SBCL hash table corrupt it silently. Racing the VALUE is harmless: the parse
of a string is deterministic, so a lost store only costs a re-parse.")

(defvar *last-flag-set* (cons nil (cons 0 nil))
  "(flags-string . (word . names)) of the most recent lookup, replaced as a
whole cons -- never mutated -- so a reader on any thread sees a matching pair.
The string bound to *SCRIPT-FLAGS* is one object for a whole block or
transaction, so it is recognized by EQ before *FLAG-SET-CACHE* is hashed.")

(defun current-script-flags ()
  "(word . names) for the string bound to *SCRIPT-FLAGS*, or NIL for none."
  (let ((flags *script-flags*))
    (when flags
      (let ((last *last-flag-set*))
        (if (eq (car last) flags)
            (cdr last)
            (let ((parsed (or (gethash flags *flag-set-cache*)
                              (setf (gethash flags *flag-set-cache*)
                                    (parse-script-flags flags)))))
              (setf *last-flag-set* (cons flags parsed))
              parsed))))))

(declaim (inline script-flag-bit-p))
(defun script-flag-bit-p (bit)
  "Whether BIT is set in the word of the flags bound now: Core's
`flags & SCRIPT_VERIFY_X'."
  (let ((parsed (current-script-flags)))
    (and parsed (logbitp bit (car parsed)))))

(defun flag-enabled-p (flag)
  "Whether FLAG (a name, \"MINIMALDATA\") is among the flags bound in
*SCRIPT-FLAGS*: a bit test on the parsed word. A constant FLAG is resolved to
its bit at compile time (the compiler macro below), so a call site pays no
lookup of the name at all; a name with no bit is answered from the parsed
token set, as the string alone would answer it."
  (let ((bit (script-flag-bit flag)))
    (if bit
        (script-flag-bit-p bit)
        (let ((parsed (current-script-flags)))
          (and parsed (gethash flag (cdr parsed)) t)))))

(define-compiler-macro flag-enabled-p (&whole form flag)
  (let ((bit (and (stringp flag) (script-flag-bit flag))))
    (if bit `(script-flag-bit-p ,bit) form)))
