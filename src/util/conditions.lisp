(in-package #:bitcoin-lisp.conditions)

;;;; The condition hierarchy (refactoring plan P4)
;;;
;;; Every error this tree signals on purpose is a BITCOIN-LISP-ERROR, so a
;;; caller can tell the project's own failures from a stray TYPE-ERROR, and
;;; a module's callers can handle that module's failures as one type. The
;;; per-module classes are SIMPLE-ERRORs signalled through a function of the
;;; same name -- (config-error "Invalid port ~A" port) -- so a site's message
;;; text is exactly what the bare ERROR call produced before; the functional tests
;;; and the operator read those texts. What changed is only the type.
;;;
;;; CONSENSUS-ERROR and POLICY-ERROR carry Core's reject-reason keyword (the
;;; validation package's vocabulary, checked against Core; not reworded here)
;;; for the validation paths that move onto conditions later.

(define-condition bitcoin-lisp-error (error) ()
  (:documentation "Root of every error this project signals on purpose."))

(defmacro define-simple-error (name doc)
  "A BITCOIN-LISP-ERROR subclass that is also a SIMPLE-ERROR, plus a
function NAME (control &rest args) that signals it with that message."
  `(progn
     (define-condition ,name (bitcoin-lisp-error simple-error) ()
       (:documentation ,doc))
     ;; Never returns, like ERROR itself: without this the compiler could not
     ;; carry a guard's constraint past (unless ok (storage-error ...)) --
     ;; the byte-reader guards on the hot decode paths depend on it.
     (declaim (ftype (function (t &rest t) nil) ,name))
     (defun ,name (control &rest args)
       ,(format nil "Signal a ~A whose message is CONTROL formatted with ARGS." name)
       (error ',name :format-control control :format-arguments args))))

(define-simple-error internal-error
  "An invariant this code maintains was found broken: a bug, never an input.")
(define-simple-error config-error
  "A command line or configuration file the node refuses to start with
(Core InitError from option validation and the parameter interactions).")
(define-simple-error init-error
  "Startup refused for a reason other than the configuration: a datadir
that cannot be locked or migrated, a corrupt on-disk state, a log file that
cannot be opened.")
(define-simple-error serialization-error
  "Bytes that are not a valid encoding of what they claim to be: a
non-canonical CompactSize, a truncated message, a PSBT with the wrong shape.
Untrusted input; the peer or caller is at fault.")
(define-simple-error storage-error
  "Persistent state that cannot be read, written or reconciled: LevelDB,
block and undo files, the datadir layout.")
(define-simple-error net-error
  "A networking failure below the protocol: SOCKS5, Tor control, the address
manager's files.")
(define-simple-error crypto-error
  "A cryptographic primitive refused its input or failed: key sizes, invalid
keys, libsecp256k1 returning failure.")
(define-simple-error wallet-error
  "A wallet-internal failure that is not an RPC-level error code.")

(define-condition consensus-error (bitcoin-lisp-error simple-error)
  ((reason :initarg :reason :initform nil :reader error-reason))
  (:documentation "A block or transaction failed a consensus rule. REASON is
Core's reject-reason keyword when the caller has one."))

(define-condition policy-error (bitcoin-lisp-error simple-error)
  ((reason :initarg :reason :initform nil :reader error-reason))
  (:documentation "A transaction is valid but this node's policy refuses it.
REASON is Core's reject-reason keyword when the caller has one."))
