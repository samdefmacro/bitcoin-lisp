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
body: docstring, declarations, forms."
  (let* ((names (if (listp names) names (list names)))
         (fn (intern (format nil "RPC-~A" (string-upcase (first names))))))
    `(progn
       (defun ,fn (,node ,params) ,@body)
       ,@(loop for name in names collect `(%record-rpc ,name ',fn))
       ',fn)))
