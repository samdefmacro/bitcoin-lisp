(in-package #:bitcoin-lisp.serialization)

;;;; define-message: one field list, three definitions
;;;
;;; A P2P record used to be written three times -- a DEFSTRUCT, a reader that
;;; pulled each field off the wire in order, and a writer that put them back
;;; -- and the three had to agree by hand (Core writes one SERIALIZE_METHODS
;;; per struct for the same reason). DEFINE-MESSAGE takes the field list once
;;; and expands to all three, so the struct, read-NAME (from a byte-reader)
;;; and write-NAME (to a byte-buf) cannot drift apart.
;;;
;;; A field is (SLOT TYPE &key DEFAULT SLOT-TYPE READ WRITE). TYPE names a row
;;; of *MESSAGE-FIELD-TYPES* (:u32, :hash256, :var-string, ...), or is one of
;;; the compound forms
;;;   (:bytes N)                       exactly N raw bytes
;;;   (:var-string :max N :name STRING) a CompactSize-prefixed string, refused
;;;                                    above N bytes (Core LIMITED_STRING);
;;;                                    STRING labels the error
;;;   (:struct NAME)                   any type with read-NAME (byte-reader)
;;;                                    and write-NAME (byte-buf value), whether
;;;                                    a define-message or hand-written
;;;   (:list TYPE :max M :name STRING) CompactSize count (refused above M,
;;;                                    STRING labels the error) then TYPE items
;;; and the bare keyword :custom, which generates nothing: :READ, :WRITE and
;;; :SLOT-TYPE are all required. A :READ or :WRITE form on a row type replaces
;;; that half of the generated code (the version message's relay flag, which
;;; older peers omit); a field that replaces both must say :custom, so a row
;;; type never labels a wire shape it does not produce. A :READ form sees the
;;; byte-reader as BR and every earlier slot by name; a :WRITE form sees the
;;; byte-buf as BB and the slot's value as VALUE. A field with no :DEFAULT
;;; gets one that satisfies its slot type (0, "", an empty array, (make-NAME)
;;; for a struct, NIL for a list or boolean).

(eval-when (:compile-toplevel :load-toplevel :execute)

(defparameter *message-field-types* '()
  "TYPE -> (slot-type read-form write-form). The forms mention BR, BB and
VALUE literally; DEFINE-MESSAGE substitutes its own variables.")

(defun %message-default-for (slot-type)
  "A default value satisfying SLOT-TYPE when a field gives none: 0 for
integers, \"\" for strings, an empty or zero array for byte arrays, NIL
otherwise (lists, booleans)."
  (cond ((and (consp slot-type) (member (first slot-type) '(unsigned-byte signed-byte))) 0)
        ((eq slot-type 'string) "")
        ((and (consp slot-type) (eq (first slot-type) 'simple-array)
              (equal (second slot-type) '(unsigned-byte 8)))
         (let ((n (first (third slot-type))))
           `(make-array ,(if (integerp n) n 0) :element-type '(unsigned-byte 8)
                                                :initial-element 0)))))

(defun field-codec-forms (type br bb value)
  "(values slot-type read-form write-form default) for the field TYPE, with
BR, BB and VALUE substituted for the template variables. The one codec table
behind DEFINE-MESSAGE and the wallet's DEFINE-WDB-KEY / DEFINE-WDB-VALUE."
  (flet ((substitute-vars (form) (sublis `((br . ,br) (bb . ,bb) (value . ,value)) form))
         (bad () (internal-error "define-message: unknown field type ~S" type)))
    (cond
      ((keywordp type)
       (destructuring-bind (slot-type read write)
           (or (cdr (assoc type *message-field-types*)) (bad))
         (values slot-type (substitute-vars read) (substitute-vars write)
                 (%message-default-for slot-type))))
      ((not (consp type)) (bad))
      ((eq (first type) :bytes)
       (let ((n (second type)))
         (values `(simple-array (unsigned-byte 8) (,n))
                 `(br-read-bytes ,br ,n)
                 `(bb-write-bytes ,bb ,value)
                 `(make-array ,n :element-type '(unsigned-byte 8) :initial-element 0))))
      ((eq (first type) :struct)
       ;; the codec and constructor live where NAME does, which is also
       ;; where a hand-written read-NAME / write-NAME pair would be
       (let* ((name (second type))
              (home (symbol-package name)))
         (values name
                 `(,(intern (format nil "READ-~A" name) home) ,br)
                 `(,(intern (format nil "WRITE-~A" name) home) ,bb ,value)
                 `(,(intern (format nil "MAKE-~A" name) home)))))
      ((eq (first type) :var-string)
       ;; Core LIMITED_STRING(str, N): the length prefix is checked BEFORE any
       ;; allocation and an over-long one throws, so the message fails and the
       ;; peer is dropped. Truncating instead would keep a peer that is
       ;; misbehaving by Core's rules, and would silently change a value the
       ;; RPC surface reports.
       (destructuring-bind (&key max name) (rest type)
         (unless (and max name)
           (internal-error "define-message: a bounded :var-string needs :max and :name"))
         (values 'string
                 `(br-read-limited-string ,br ,max ,name)
                 `(bb-write-var-bytes ,bb (utf8-string-to-bytes ,value))
                 "")))
      ((eq (first type) :list)
       (destructuring-bind (element &key max name) (rest type)
         (let ((item (gensym "ITEM")))
           (multiple-value-bind (item-type item-read item-write)
               (field-codec-forms element br bb item)
             (declare (ignore item-type))
             (values 'list
                     `(loop repeat (br-read-bounded-count ,br ,max ,name)
                            collect ,item-read)
                     `(progn (bb-write-varint ,bb (length ,value))
                             (dolist (,item ,value) ,item-write))
                     nil)))))
      (t (bad)))))

) ; eval-when

(defmacro define-message-field-type (type slot-type read-form write-form)
  "Register TYPE for DEFINE-MESSAGE fields: SLOT-TYPE is the struct slot's
declared type; READ-FORM reads one value from the byte-reader BR; WRITE-FORM
writes VALUE to the byte-buf BB."
  `(eval-when (:compile-toplevel :load-toplevel :execute)
     (setf *message-field-types*
           (cons (list ,type ',slot-type ',read-form ',write-form)
                 (remove ,type *message-field-types* :key #'car)))
     ',type))

(define-message-field-type :u8 (unsigned-byte 8) (br-read-u8 br) (bb-write-u8 bb value))
(define-message-field-type :u16 (unsigned-byte 16) (br-read-u16-le br) (bb-write-u16-le bb value))
(define-message-field-type :u32 (unsigned-byte 32) (br-read-u32-le br) (bb-write-u32-le bb value))
(define-message-field-type :u64 (unsigned-byte 64) (br-read-u64-le br) (bb-write-u64-le bb value))
(define-message-field-type :i32 (signed-byte 32) (br-read-i32-le br) (bb-write-i32-le bb value))
(define-message-field-type :i64 (signed-byte 64) (br-read-i64-le br) (bb-write-i64-le bb value))
;; BR-READ-BOOL, not (= byte 1): Core assigns the byte to a bool, so every
;; nonzero byte is true (serialize.h:277). The writer stays 1/0, which is
;; Core's `uint8_t f = a'.
(define-message-field-type :bool boolean (br-read-bool br) (bb-write-u8 bb (if value 1 0)))
(define-message-field-type :hash256 (simple-array (unsigned-byte 8) (32))
  (br-read-bytes br 32) (bb-write-hash256 bb value))
(define-message-field-type :var-bytes (simple-array (unsigned-byte 8) (*))
  (br-read-var-bytes br) (bb-write-var-bytes bb value))
;; Core's std::string is its BYTES (serialize.h:780-793), so the length prefix
;; and the bytes are BR-READ-VAR-BYTES / BB-WRITE-VAR-BYTES and the character
;; conversion is explicitly UTF-8 -- never one byte per code point, which put a
;; different record on disk than Core's for every character above U+007F and
;; made a write above U+00FF a raw TYPE-ERROR.
(define-message-field-type :var-string string
  (bytes-to-utf8-string (br-read-var-bytes br))
  (bb-write-var-bytes bb (utf8-string-to-bytes value)))
(define-message-field-type :block-header t
  (br-read-block-header br) (bb-write-block-header bb value))
(define-message-field-type :transaction t
  (br-read-transaction br) (bb-write-bytes bb (serialize-transaction value)))
(define-message-field-type :witness-transaction t
  ;; TRANSACTION-WIRE-BYTES, not SERIALIZE-WITNESS-TRANSACTION: Core's
  ;; TX_WITH_WITNESS emits the marker only for a transaction that HAS witness
  ;; data, and a witnessless one written in extended form is a Superfluous
  ;; witness record its own deserializer refuses.
  (br-read-transaction br) (bb-write-bytes bb (transaction-wire-bytes value)))

(defmacro define-message (name (&key documentation) &body fields)
  "Define the struct NAME plus READ-NAME (byte-reader -> struct) and
WRITE-NAME (byte-buf, struct) from FIELDS, each (SLOT TYPE &key DEFAULT
SLOT-TYPE READ WRITE) as described at the top of this file. The generated
reader binds the slots in order, so a :READ form may consult an earlier one."
  (let* ((br (intern "BR" *package*))
         (bb (intern "BB" *package*))
         (value (intern "VALUE" *package*))
         (msg (gensym "MSG"))
         (reader (intern (format nil "READ-~A" name)))
         (writer (intern (format nil "WRITE-~A" name)))
         (specs
           (loop for (slot type . opts) in fields
                 collect (destructuring-bind (&key (default nil default-p) (slot-type nil slot-type-p) read write) opts
                           (when (member slot (list br bb value))
                             (internal-error "define-message ~A: slot ~A collides with the codec variable"
                                    name slot))
                           (when (and read write (not (eq type :custom)))
                             (internal-error "define-message ~A: field ~A overrides both :read and :write -- declare it :custom"
                                    name slot))
                           (multiple-value-bind (derived-type read-form write-form derived-default)
                               (if (eq type :custom)
                                   (progn
                                     (unless (and read write slot-type-p)
                                       (internal-error "define-message ~A: a :custom field (~A) needs :read, :write and :slot-type"
                                              name slot))
                                     (values t nil nil (%message-default-for slot-type)))
                                   (field-codec-forms type br bb value))
                             (let ((final-type (if slot-type-p slot-type derived-type)))
                               (list slot
                                     (cond (default-p default)
                                           (slot-type-p (%message-default-for final-type))
                                           (t derived-default))
                                     final-type
                                     (or read read-form)
                                     (or write write-form))))))))
    `(progn
       (defstruct ,name
         ,@(when documentation (list documentation))
         ,@(loop for (slot default slot-type) in specs
                 collect `(,slot ,default :type ,slot-type)))
       (defun ,reader (,br)
         ,(format nil "Read a ~A from the byte-reader ~A." name br)
         (let* ,(loop for (slot nil nil read-form) in specs
                      collect `(,slot ,read-form))
           (,(intern (format nil "MAKE-~A" name))
            ,@(loop for (slot) in specs
                    append (list (intern (symbol-name slot) :keyword) slot)))))
       (defun ,writer (,bb ,msg)
         ,(format nil "Write a ~A to the byte-buf ~A." name bb)
         ,@(loop for (slot nil nil nil write-form) in specs
                 collect `(let ((,value (,(intern (format nil "~A-~A" name slot)) ,msg)))
                            (declare (ignorable ,value))
                            ,write-form)))
       ',name)))
