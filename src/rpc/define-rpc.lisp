(in-package #:bitcoin-lisp.rpc)

;;;; define-rpc: definition is registration
;;;
;;; An RPC method used to exist in two places that had to agree: its
;;; (defun rpc-NAME (node params) ...) and a line in a 197-line
;;; register-all-methods that mapped "name" to #'rpc-NAME. A handler written
;;; and never listed compiled, passed its own unit tests and was unreachable
;;; over the wire -- the "correct code nothing calls" failure this tree has
;;; shipped more than a dozen times. DEFINE-RPC is the defun and the
;;; registration in one form, so the second cannot be forgotten.
;;;
;;; The registry is a hash table from method name to handler, filled at load
;;; time; REGISTER-ALL-METHODS (server.lisp) reinstalls every definition from
;;; *RPC-REGISTRY*, for the tests that clear the table.

(defvar *rpc-methods* (make-hash-table :test 'equal)
  "Method name -> handler function, the table HANDLE-RPC-CALL dispatches on.")

(defvar *rpc-registry* '()
  "((name . handler-symbol) ...), every DEFINE-RPC in load order; what
REGISTER-ALL-METHODS installs.")

;;; The named-parameter tables %NAMED-PARAMS-TO-POSITIONAL (server.lisp)
;;; consults. Empty here: the chain's own rows are data, generated from Core
;;; into rpc/core-tables.lisp, which SETFs both after the handlers load.

(defvar *rpc-named-arg-names* '()
  "((method arg-name ...) ...): every method's positional argument names in
declaration order, so a named-parameter call can be laid out positionally.")

(defvar *rpc-arg-types* '()
  "((method type ...) ...): every method's positional argument types, Core's
RPCArg::Type in declaration order. Generated into rpc/core-tables.lisp; read
by CHECK-RPC-ARG-TYPES, the gate DISPATCH-RPC-METHOD runs before any handler.")

(defvar *rpc-named-only-args* '()
  "((method option-name ...) ...): the members of each method's
OBJ_NAMED_PARAMS options object, which a named-parameter call may pass at
top level (Core rpc/server.cpp:408-415).")

(defun register-rpc-method (name handler)
  "Install HANDLER (a function of NODE and PARAMS) as method NAME."
  (setf (gethash name *rpc-methods*) handler))

(defun %record-rpc (name symbol)
  (setf *rpc-registry*
        (append (remove name *rpc-registry* :key #'car :test #'string=)
                (list (cons name symbol))))
  (register-rpc-method name (symbol-function symbol)))

(defmacro define-rpc (names (node params) &body body)
  "Define the handler for the JSON-RPC method NAMES -- a string, or a list of
strings for a method with aliases (\"echo\" and \"echojson\") -- as the
function RPC-<first name> of NODE and PARAMS, and register it. BODY is a defun
body: docstring, declarations, forms.

PARAMS is either a symbol, bound to the positional parameter list as the
wire sent it, or a list of parameter specs, one per position in the
method's argument order (Core RPCHelpMan), with the list itself still
available as PARAMS. A spec is VAR, bound to the parameter as sent (NIL
when omitted), or (VAR KIND ...) applying one of the positional coercions:
  (VAR :bool)          POSITIONAL-BOOL -- null and explicit false are NIL
  (VAR :bool-or D)     POSITIONAL-BOOL-OR -- null yields D
  (VAR :array)         POSITIONAL-ARRAY -- the empty-array sentinel is NIL
  (VAR :or D)          the parameter, or D when null
  (VAR :integer-or D)  the parameter when it is an integer, else D
  (VAR :string-or D)   the parameter when it is a string, else D
A position the handler reads through PARAMS itself (a verbosity that
%PARSE-VERBOSITY interprets) still gets a name, so the signature stays
complete; the variables are IGNORABLE. So a handler's signature says what
it takes instead of opening with
(let ((a (first params)) (b (positional-bool (second params)))) ...)."
  (let* ((names (if (listp names) names (list names)))
         (fn (intern (format nil "RPC-~A" (string-upcase (first names)))))
         (specs (mapcar #'alexandria:ensure-list (and (listp params) params)))
         (vars (mapcar #'first specs))
         (params-var (if (listp params) 'params params)))
    (flet ((coercion (spec)
             (destructuring-bind (var &optional kind default) spec
               (when kind
                 (list var
                       (ecase kind
                         (:bool `(positional-bool ,var))
                         (:bool-or `(positional-bool-or ,var ,default))
                         (:array `(positional-array ,var))
                         (:or `(or ,var ,default))
                         (:integer-or `(if (integerp ,var) ,var ,default))
                         (:string-or `(if (stringp ,var) ,var ,default))))))))
      (multiple-value-bind (forms decls doc) (alexandria:parse-body body :documentation t)
        `(progn
           (defun ,fn (,node ,params-var)
             ,@(when doc (list doc))
             ,@decls
             ,@(if specs
                   `((destructuring-bind (&optional ,@vars &rest more) ,params-var
                       (declare (ignore more) (ignorable ,@vars))
                       (let* ,(remove nil (mapcar #'coercion specs))
                         ,@forms)))
                   forms))
           ,@(loop for name in names collect `(%record-rpc ,name ',fn))
           ',fn)))))
