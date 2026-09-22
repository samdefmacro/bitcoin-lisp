(in-package #:bitcoin-lisp.tools)

;;;; Core UniValue::write (univalue/lib/univalue_write.cpp) over the values the
;;;; RPC layer builds: an alist of (string . value) is an object, any other
;;;; list or a vector an array, NIL null, T true, BL.RPC:+JSON-FALSE+ false.
;;;;
;;;; The tools print what Core prints BYTE FOR BYTE -- tool_utils.py compares
;;;; stdout with the expected file as TEXT as well as parsed (its "Output
;;;; formatting mismatch" arm), so the layout is part of the contract: four
;;;; spaces per level, "key": value with one space, and an empty array or
;;;; object still broken over two lines ("[\n    ]"), which is what
;;;; writeArray / writeObject produce when they have no members.

(defun %alist-object-p (x)
  "X is a non-empty proper list of (string . value) pairs: a JSON object."
  (and (consp x)
       (loop for tail = x then (cdr tail)
             while (consp tail)
             always (and (consp (car tail)) (stringp (caar tail)))
             finally (return (null tail)))))

(defun %write-json-string (string out)
  "Core json_escape (univalue_escapes.h): the quote, the backslash and the
control characters escaped, \\b \\f \\n \\r \\t by name and the rest as
\\u00XX; everything else, non-ASCII included, verbatim."
  (write-char #\" out)
  (loop for ch across string
        for code = (char-code ch)
        do (case ch
             (#\" (write-string "\\\"" out))
             (#\\ (write-string "\\\\" out))
             (t (cond ((= code 8) (write-string "\\b" out))
                      ((= code 12) (write-string "\\f" out))
                      ((= code 10) (write-string "\\n" out))
                      ((= code 13) (write-string "\\r" out))
                      ((= code 9) (write-string "\\t" out))
                      ((or (< code #x20) (= code #x7f))
                       (format out "\\u~(~4,'0x~)" code))
                      (t (write-char ch out))))))
  (write-char #\" out))

(defun %write-indent (pretty level out)
  (when (plusp pretty)
    (loop repeat (* pretty level) do (write-char #\Space out))))

(defun %write-members (open close items pretty level out writer)
  "writeArray / writeObject: OPEN, each item on its own line at LEVEL,
comma-separated, then CLOSE one level out. With PRETTY 0 everything is on
one line and nothing is indented."
  (write-char open out)
  (when (plusp pretty) (terpri out))
  (loop for (item . more) on items
        do (%write-indent pretty level out)
           (funcall writer item)
           (when more (write-char #\, out))
           (when (plusp pretty) (terpri out)))
  (when (plusp pretty) (%write-indent pretty (1- level) out))
  (write-char close out))

(defun %univalue-write (value pretty level out)
  (let ((next (1+ level)))
    (cond
      ((null value) (write-string "null" out))
      ((eq value t) (write-string "true" out))
      ((eq value bl.rpc:+json-false+) (write-string "false" out))
      ((stringp value) (%write-json-string value out))
      ((integerp value) (format out "~D" value))
      ((hash-table-p value)
       (%write-members #\{ #\}
                       (loop for k being the hash-keys of value using (hash-value v)
                             collect (cons k v))
                       pretty next out
                       (lambda (pair) (%write-pair pair pretty next out))))
      ((%alist-object-p value)
       (%write-members #\{ #\} value pretty next out
                       (lambda (pair) (%write-pair pair pretty next out))))
      ((or (listp value) (vectorp value))
       (%write-members #\[ #\] (coerce value 'list) pretty next out
                       (lambda (item) (%univalue-write item pretty next out))))
      ;; A number the RPC layer spelled itself (satoshi->btc, json-float) --
      ;; its YASON:ENCODE method writes the text it carries.
      (t (yason:encode value out)))))

(defun %write-pair (pair pretty level out)
  (%write-json-string (car pair) out)
  (write-char #\: out)
  (when (plusp pretty) (write-char #\Space out))
  (%univalue-write (cdr pair) pretty level out))

(defun univalue-write (value &optional (pretty 0))
  "VALUE as the text Core's UniValue::write(PRETTY) produces. The top level is
written at indentLevel 0, which Core raises to 1 for its members."
  (with-output-to-string (out)
    (%univalue-write value pretty 0 out)))
