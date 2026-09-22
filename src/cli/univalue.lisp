(in-package #:bitcoin-lisp.cli)

;;;; Core's UniValue, as much of it as bitcoin-cli uses
;;;; (src/univalue/lib/univalue_read.cpp, univalue_write.cpp, univalue_get.cpp)
;;;
;;; The client prints what the server sent, and Core's framework compares that
;;; output with the same call made over RPC (interface_bitcoin_cli.py:141-143,
;;; parse_float=Decimal on both sides). UniValue keeps a NUMBER as the text it
;;; was read from and writes that text back, so an amount like 0.00001000 or a
;;; difficulty like 4.656542373906925e-10 crosses the client unchanged. A
;;; reader that converted numbers to Lisp floats would print a different token
;;; for the same value, and one that converted to rationals could not print
;;; an exponent at all -- so the model here is Core's:
;;;
;;;   null / true / false   :NULL / :TRUE / :FALSE
;;;   number                (:NUM . "text")
;;;   string                a Lisp string
;;;   array                 (:ARR value ...)
;;;   object                (:OBJ (key . value) ...), in order, duplicates kept
;;;
;;; Strings are characters: the bytes on the wire are UTF-8, decoded and
;;; encoded at the socket and the standard streams.

(defun uv-num (x)
  "A UniValue number: X is an integer or the number's JSON text."
  (cons :num (if (stringp x) x (princ-to-string x))))

(defun uv-arr (&rest values) (cons :arr values))

(defun uv-obj (&rest keys-and-values)
  "An object from alternating KEY VALUE arguments, in that order."
  (cons :obj (loop for (k v) on keys-and-values by #'cddr collect (cons k v))))

(defun %uv-type (v)
  (cond ((stringp v) :str)
        ((member v '(:null :true :false)) (if (eq v :null) :null :bool))
        ((and (consp v) (member (car v) '(:num :arr :obj))) (car v))
        (t (cli-error "Not a UniValue: ~S" v))))

(defun uv-null-p (v) (eq v :null))

(defun uv-get (v key)
  "Core UniValue::operator[] for an object KEY (a string) or an array index
 (an integer): the FIRST member of that name, and :NULL when V is not an
object/array or has no such member -- never an error, which is what lets the
client read optional reply fields the way Core's handlers do."
  (cond ((and (stringp key) (consp v) (eq (car v) :obj))
         (let ((cell (assoc key (cdr v) :test #'string=)))
           (if cell (cdr cell) :null)))
        ((and (integerp key) (consp v) (eq (car v) :arr))
         (let ((cell (nthcdr key (cdr v))))
           (if cell (car cell) :null)))
        (t :null)))

(defun uv-val-str (v)
  "Core UniValue::getValStr: the text a string or number holds, \"1\" or \"\"
for a boolean, and \"\" for null, an array or an object. -getinfo prints its
fields through this, which is why an ARRAY of warnings reads as none."
  (case (%uv-type v)
    (:str v)
    (:num (cdr v))
    (:bool (if (eq v :true) "1" ""))
    (t "")))

(defun %uv-type-name (v)
  (ecase (%uv-type v)
    (:null "null") (:bool "bool") (:num "number") (:str "string")
    (:arr "array") (:obj "object")))

(defun %uv-expect (v type)
  (unless (eq (%uv-type v) type)
    (cli-error "JSON value of type ~A is not of expected type ~A"
           (%uv-type-name v)
           (ecase type (:num "number") (:str "string") (:obj "object")
                       (:arr "array") (:bool "bool")))))

(defun uv-get-int (v)
  "Core UniValue::getInt: the number V holds, which must be an integer."
  (%uv-expect v :num)
  (or (ignore-errors (parse-integer (cdr v)))
      (cli-error "JSON integer out of range")))

(defun uv-get-real (v)
  "Core UniValue::get_real: V's number as a double."
  (%uv-expect v :num)
  (let ((*read-default-float-format* 'double-float)
        (*read-eval* nil))
    ;; The text passed the JSON number grammar, so READ sees only a number.
    (coerce (read-from-string (cdr v)) 'double-float)))

(defun uv-get-str (v) (%uv-expect v :str) v)

(defun uv-get-bool (v)
  (%uv-expect v :bool)
  (eq v :true))

(defun uv-values (v)
  "Core UniValue::getValues: the members of an array or object."
  (unless (member (%uv-type v) '(:arr :obj))
    (cli-error "JSON value is not an object or array as expected"))
  (if (eq (car v) :arr) (cdr v) (mapcar #'cdr (cdr v))))

(defun uv-keys (v) (%uv-expect v :obj) (mapcar #'car (cdr v)))

;;; --- Reading (univalue_read.cpp) ---

(define-condition json-parse-failure (error) ()
  (:report "JSON value could not be parsed")
  (:documentation "UniValue::read returned false. Callers turn it into their
own words, as Core's do: `Error parsing JSON: <arg>' for a converted
argument, `couldn't parse reply from server' for a reply."))

(defconstant +max-json-depth+ 512 "Core MAX_JSON_DEPTH (univalue_read.cpp).")

(defvar *jr-text* "" "The text UV-READ is reading.")
(defvar *jr-pos* 0 "UV-READ's position in *JR-TEXT*.")

(defun %jr-fail () (error 'json-parse-failure))

(defun %jr-peek ()
  (if (< *jr-pos* (length *jr-text*)) (char *jr-text* *jr-pos*) nil))

(defun %jr-skip-ws ()
  "json_isspace: space, tab, newline and carriage return, nothing else."
  (loop while (member (%jr-peek) '(#\Space #\Tab #\Newline #\Return))
        do (incf *jr-pos*)))

(defun %jr-digit-p (c) (and c (char<= #\0 c #\9)))

(defun %jr-digits ()
  (unless (%jr-digit-p (%jr-peek)) (%jr-fail))
  (loop while (%jr-digit-p (%jr-peek)) do (incf *jr-pos*)))

(defun %jr-number ()
  "A number token, kept as its text: -?(0|[1-9][0-9]*)(.[0-9]+)?([eE][+-]?[0-9]+)?"
  (let ((start *jr-pos*))
    (when (eql (%jr-peek) #\-) (incf *jr-pos*))
    (unless (%jr-digit-p (%jr-peek)) (%jr-fail))
    (if (eql (%jr-peek) #\0)
        (progn (incf *jr-pos*) (when (%jr-digit-p (%jr-peek)) (%jr-fail)))
        (%jr-digits))
    (when (eql (%jr-peek) #\.) (incf *jr-pos*) (%jr-digits))
    (when (member (%jr-peek) '(#\e #\E))
      (incf *jr-pos*)
      (when (member (%jr-peek) '(#\+ #\-)) (incf *jr-pos*))
      (%jr-digits))
    (cons :num (subseq *jr-text* start *jr-pos*))))

(defun %jr-hex4 ()
  (let ((end (+ *jr-pos* 4)))
    (unless (and (<= end (length *jr-text*))
                 (every (lambda (c) (digit-char-p c 16)) (subseq *jr-text* *jr-pos* end)))
      (%jr-fail))
    (prog1 (parse-integer *jr-text* :start *jr-pos* :end end :radix 16)
      (setf *jr-pos* end))))

(defun %jr-codepoint ()
  "The code point of a \\u escape (the `\\u' already read). JSONUTF8StringFilter:
a high surrogate must be followed by a \\u low surrogate; a lone half fails."
  (let ((cp (%jr-hex4)))
    (cond ((<= #xDC00 cp #xDFFF) (%jr-fail))
          ((<= #xD800 cp #xDBFF)
           (unless (and (eql (%jr-peek) #\\)
                        (< (1+ *jr-pos*) (length *jr-text*))
                        (char= (char *jr-text* (1+ *jr-pos*)) #\u))
             (%jr-fail))
           (incf *jr-pos* 2)
           (let ((lo (%jr-hex4)))
             (unless (<= #xDC00 lo #xDFFF) (%jr-fail))
             (+ #x10000 (ash (- cp #xD800) 10) (- lo #xDC00))))
          (t cp))))

(defun %jr-escape (out)
  "One escape sequence after its backslash, written to OUT."
  (let ((e (or (%jr-peek) (%jr-fail))))
    (incf *jr-pos*)
    (case e
      ((#\" #\\ #\/) (write-char e out))
      (#\b (write-char (code-char 8) out))
      (#\f (write-char (code-char 12) out))
      (#\n (write-char (code-char 10) out))
      (#\r (write-char (code-char 13) out))
      (#\t (write-char (code-char 9) out))
      (#\u (write-char (code-char (%jr-codepoint)) out))
      (t (%jr-fail)))))

(defun %jr-string ()
  "A string token (at its opening quote); a raw control character fails."
  (incf *jr-pos*)
  (with-output-to-string (out)
    (loop
      (let ((c (%jr-peek)))
        (cond ((or (null c) (< (char-code c) #x20)) (%jr-fail))
              ((char= c #\") (incf *jr-pos*) (return))
              ((char= c #\\) (incf *jr-pos*) (%jr-escape out))
              (t (write-char c out) (incf *jr-pos*)))))))

(defun %jr-keyword (word value)
  (let ((end (+ *jr-pos* (length word))))
    (unless (and (<= end (length *jr-text*)) (string= word *jr-text* :start2 *jr-pos* :end2 end))
      (%jr-fail))
    (setf *jr-pos* end)
    value))

(defun %jr-sequence (depth close read-item tag)
  "The members of an array or object (at its opening bracket) up to CLOSE:
READ-ITEM reads one; an empty one is allowed, a trailing comma is not."
  (when (> depth +max-json-depth+) (%jr-fail))
  (incf *jr-pos*)
  (%jr-skip-ws)
  (if (eql (%jr-peek) close)
      (progn (incf *jr-pos*) (list tag))
      (let ((items (list (funcall read-item depth))))
        (loop (%jr-skip-ws)
              (let ((c (%jr-peek)))
                (cond ((eql c #\,) (incf *jr-pos*) (push (funcall read-item depth) items))
                      ((eql c close) (incf *jr-pos*) (return (cons tag (nreverse items))))
                      (t (%jr-fail))))))))

(defun %jr-member (depth)
  (%jr-skip-ws)
  (unless (eql (%jr-peek) #\") (%jr-fail))
  (let ((key (%jr-string)))
    (%jr-skip-ws)
    (unless (eql (%jr-peek) #\:) (%jr-fail))
    (incf *jr-pos*)
    (cons key (%jr-value depth))))

(defun %jr-value (depth)
  (%jr-skip-ws)
  (let ((c (%jr-peek)))
    (case c
      ((nil) (%jr-fail))
      (#\{ (%jr-sequence (1+ depth) #\} #'%jr-member :obj))
      (#\[ (%jr-sequence (1+ depth) #\] #'%jr-value :arr))
      (#\" (%jr-string))
      (#\n (%jr-keyword "null" :null))
      (#\t (%jr-keyword "true" :true))
      (#\f (%jr-keyword "false" :false))
      (t (if (or (eql c #\-) (%jr-digit-p c)) (%jr-number) (%jr-fail))))))

(defun uv-read (text)
  "Parse TEXT as one JSON value, Core's UniValue::read: strict JSON (no
trailing commas, no leading zeros, no control characters inside strings),
any value at the top level, whitespace around it, nothing else after it.
Signals JSON-PARSE-FAILURE where read returns false."
  (let ((*jr-text* text) (*jr-pos* 0))
    (let ((value (%jr-value 0)))
      (%jr-skip-ws)
      (when (< *jr-pos* (length *jr-text*)) (%jr-fail))
      value)))

;;; --- Writing (univalue_write.cpp) ---

(defun %uv-escape (string out)
  "Core json_escape over the escapes table (univalue_escapes.h): every control
character below 0x20 and 0x7f as \\uXXXX except the five with short forms,
the quote and the backslash escaped, everything else -- non-ASCII included --
written as it is."
  (loop for c across string
        for code = (char-code c)
        do (case code
             (8 (write-string "\\b" out))
             (9 (write-string "\\t" out))
             (10 (write-string "\\n" out))
             (12 (write-string "\\f" out))
             (13 (write-string "\\r" out))
             (34 (write-string "\\\"" out))
             (92 (write-string "\\\\" out))
             (t (if (or (< code #x20) (= code #x7f))
                    (format out "\\u~(~4,'0X~)" code)
                    (write-char c out))))))

(defun %uv-write (v pretty level out)
  (let ((mod-indent (max level 1)))
    (flet ((indent (n) (dotimes (i (* pretty n)) (write-char #\Space out)))
           (newline () (when (plusp pretty) (write-char #\Newline out))))
      (ecase (%uv-type v)
        (:null (write-string "null" out))
        (:bool (write-string (if (eq v :true) "true" "false") out))
        (:num (write-string (cdr v) out))
        (:str (write-char #\" out) (%uv-escape v out) (write-char #\" out))
        (:arr
         ;; writeArray: an EMPTY array still gets its newline and closing
         ;; indent when pretty, so Core prints `[' newline `]'.
         (write-char #\[ out) (newline)
         (loop for (item . more) on (cdr v)
               do (indent mod-indent)
                  (%uv-write item pretty (1+ mod-indent) out)
                  (when more (write-char #\, out))
                  (newline))
         (indent (1- mod-indent))
         (write-char #\] out))
        (:obj
         (write-char #\{ out) (newline)
         (loop for ((key . value) . more) on (cdr v)
               do (indent mod-indent)
                  (write-char #\" out) (%uv-escape key out) (write-string "\":" out)
                  (when (plusp pretty) (write-char #\Space out))
                  (%uv-write value pretty (1+ mod-indent) out)
                  (when more (write-char #\, out))
                  (newline))
         (indent (1- mod-indent))
         (write-char #\} out))))))

(defun uv-write (v &optional (pretty 0))
  "Core UniValue::write(PRETTY): compact with PRETTY 0, otherwise PRETTY
spaces per level. bitcoin-cli prints a result with write(2)."
  (with-output-to-string (out) (%uv-write v pretty 0 out)))
