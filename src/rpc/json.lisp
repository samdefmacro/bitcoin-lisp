(in-package #:bitcoin-lisp.rpc)

;;;; JSON values as the RPC layer sees them
;;;
;;; The sentinels the request parser leaves for an explicit false and an
;;; explicit empty array, the readers that understand them, and the
;;; producers that render [] / {} where Core would. Nothing here knows a
;;; chain; every handler file compiles against it.

;;; --- JSON booleans ---
;;;
;;; The RPC layer's historical convention folds CL NIL to JSON null, but a
;;; Core boolean field is ALWAYS true/false when present (UniValue pushKV of
;;; bool; conditional booleans are OMITTED, never null). JSON-BOOL is the one
;;; coercion point: NIL still means null for genuinely nullable/absent
;;; values, and 'YASON:FALSE is the explicit false literal. Defined here (not
;;; server.lisp) so every later-compiled RPC file sees the definitions.

(defconstant +json-false+ 'yason:false
  "The JSON false literal: yason encodes this symbol as false (encode.lisp
defmethod on (eql 'false)); rpc-result->json passes it through as an atom.
On the REQUEST side the same symbol is the explicit-false sentinel the
parser leaves at TOP-LEVEL positional parameter positions (see
parse-json-rpc-request): explicit false must be distinguishable from
null/omitted because Core's isNull() checks treat only the latter as
\"use the default\". IMPORTANT: the sentinel is TRUTHY — positional
boolean parameters must be read through positional-bool /
positional-bool-or, never by raw truthiness.")

(defconstant +json-empty-array+ '%json-empty-array
  "The empty JSON array, at TOP-LEVEL positional parameter positions.

Same problem as +json-false+ and the same shape of answer. Our decoder maps
BOTH `[]` and `null` to NIL, so a handler could not tell an argument that was
given as an empty array from one that was not given at all — and Core's
argument checking splits on exactly that: isNull() means \"use the default\",
while an array of the wrong type is an RPC_TYPE_ERROR. Two of Core's
functional tests fail on the difference alone: getrawtransaction(txid, [])
must answer -3 \"not of expected type number\"
(rpc_rawtransaction.py:136) and scantxoutset(\"start\", []) must scan
nothing rather than be told its argument is missing (rpc_scantxoutset.py:62).

Only TOP-LEVEL positional parameters carry the sentinel, exactly as with
explicit false: nested empty arrays keep folding to NIL, because nested
readers answer absence with present-p instead. IMPORTANT: the sentinel is
TRUTHY and is NOT a list — array parameters must be read through
%POSITIONAL-ARRAY / %POSITIONAL-ARRAY-P, never with LISTP or DOLIST
directly.")

(defun %positional-array-p (value)
  "True if VALUE is a positional parameter that ARRIVED as a JSON array,
empty or not. NIL is null/omitted and is not an array; the empty-array
sentinel is."
  (or (eq value +json-empty-array+)
      (and (consp value) t)))

(defun positional-array (value)
  "The elements of a positional array parameter, as a list.
The empty-array sentinel yields NIL, so callers iterate uniformly; use
%POSITIONAL-ARRAY-P first when the difference between `[]` and null matters."
  (if (eq value +json-empty-array+) nil value))

(defun positional-bool (value)
  "Truth of a positional JSON boolean parameter: NIL (null or omitted) and
the explicit-false sentinel are false; anything else is true. Mirrors
Core's pattern `if (!params[i].isNull()) x = params[i].get_bool()` for
default-false parameters."
  (and value (not (eq value +json-false+)) t))

(defun positional-bool-or (value default)
  "Positional JSON boolean with a non-false DEFAULT: NIL (null or omitted)
yields DEFAULT; explicit false yields NIL; anything else T. Core:
`params[i].isNull() ? default : params[i].get_bool()`."
  (if value
      (positional-bool value)
      default))

(defun json-bool (x)
  "Coerce generalized boolean X to a JSON boolean: T or the false literal.
Use for every field Core emits as a bool — NIL must never leak into such a
field, as it would encode as null."
  (if x t +json-false+))

;;; --- Empty JSON collections ---
;;;
;;; rpc-result->json hands NIL straight to yason, which encodes it as null,
;;; but Core builds every collection as a UniValue VARR/VOBJ and so renders
;;; an EMPTY one as [] / {} — never null. Clients index the result
;;; (`len(node.listbanned())`) and break on null.
;;;
;;; This must be applied PER SITE, not as a global normalizer in
;;; rpc-result->json: CL NIL is genuinely ambiguous — it is the empty list,
;;; the empty alist AND the null/absent value — so only the producing site
;;; knows which of [], {} and null it meant. Core methods that return null
;;; on absence (scantxoutset "status" with no scan running) must keep
;;; returning NIL.

(defstruct (json-number (:constructor make-json-number (text))
                        (:copier nil))
  "A JSON number whose TEXT is written out verbatim.

Core builds a number as a UniValue of type VNUM carrying the exact digits it
means and UniValue writes those digits back unchanged, so the SPELLING of a
number is Core's to choose. A double-float here is spelled by SBCL's float
printer instead, which prints the shortest text that round-trips -- 1.0e-8 for
one satoshi, 0.1 for a tenth of a coin -- where Core prints 0.00000001 and
0.10000000. Every amount the RPC and REST surfaces emit goes through this
(see SATOSHI->BTC), so no float printer stands between a satoshi count and
the reply."
  (text "0" :type string :read-only t))

(defmethod yason:encode ((object json-number) &optional (stream *standard-output*))
  (write-string (json-number-text object) stream)
  object)

(defun json-array (list)
  "LIST as a JSON array, rendering [] rather than null when it is empty.
yason encodes a vector as an array unconditionally, and rpc-result->json
passes vectors through as atoms, so a non-empty LIST is returned unchanged
(letting rpc-result->json recurse into nested objects) while the empty case
becomes a literal empty vector."
  (or list #()))

(defun json-object (alist)
  "ALIST as a JSON object, rendering {} rather than null when it is empty —
the object-valued counterpart of JSON-ARRAY (rpc-result->json turns a
non-empty (string . value) alist into a hash-table by itself, but cannot
tell an empty object from null)."
  (or alist (make-hash-table :test 'equal)))

(defun obj-get (obj key)
  "Read KEY from a JSON object that arrived as either an alist (from tests /
JSON-RPC 1.x) or a hash-table (from yason)."
  (cond ((hash-table-p obj) (gethash key obj))
        ((listp obj) (cdr (assoc key obj :test #'string=)))))

;;; --- JSON types (Core univalue) ---
;;;
;;; Moved here from blockchain.lisp: the argument parsers (amounts.lisp) and
;;; every handler above them signal this one type error, so it has to be
;;; defined below all of them.

(defun %json-type-name (value)
  "Core's uvTypeName (univalue.cpp:217-226) for VALUE as our decoder represents
it: null, bool, object, array, string, number.

NIL is \"null\", and it now means that: a top-level positional `[]` arrives as
+json-empty-array+ rather than folding into NIL, so this no longer has to
guess which of the two it is looking at. That guess is what made
getrawtransaction(txid, []) answer nothing at all where Core answers -3."
  (cond ((eq value +json-empty-array+) "array")
        ((null value) "null")
        ((eq value t) "bool")
        ((eq value +json-false+) "bool")
        ((stringp value) "string")
        ((numberp value) "number")
        ((hash-table-p value) "object")
        ((or (listp value) (vectorp value)) "array")
        (t "null")))

(defun %json-type-error (value expected)
  "Signal Core's canonical UniValue type error for VALUE where EXPECTED was
wanted: \"JSON value of type <actual> is not of expected type <expected>\"
(univalue.cpp:210-214).

One shape, because Core has one shape. Its functional tests match on this
string — rpc_rawtransaction.py looks for \"not of expected type number\",
mempool_accept.py for \"JSON value of type string is not of expected type
array\" — and each hand-written message here (\"First parameter must be an
array of tx hex\", \"JSON value is not an integer as expected\") was a
different sentence saying the same thing, so no caller could match any of them."
  (error 'rpc-error :code +rpc-type-error+
                    :message (format nil "JSON value of type ~A is not of expected type ~A"
                                     (%json-type-name value) expected)))
