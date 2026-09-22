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
(define-condition chainstate-load-error (init-error) ()
  (:documentation "A chainstate load that failed where Core's LoadChainstate /
VerifyLoadedChainstate return ChainstateLoadStatus::FAILURE
 (node/chainstate.cpp), the class of failure Core OFFERS A REINDEX for rather
than simply reporting.

It is reported differently from every other startup refusal, which is why it
has its own type. An InitError prints the message under an Error: caption
 (noui.cpp:29-31); a FAILURE here goes to uiInterface.ThreadSafeQuestion, whose
non-interactive text is the message, a period, a newline, and the line Please
restart with -reindex or -reindex-chainstate to recover (init.cpp:1860-1871).
Its style MSG_ERROR|BTN_ABORT matches none of noui's captioned cases, so it is
printed with no caption at all (noui.cpp:28-46). Three functional tests compare
the WHOLE of stderr against exactly that text: feature_reindex_init.py:23,
feature_presegwit_node_upgrade.py:39 and rpc_blockchain.py:125."))

(declaim (ftype (function (t &rest t) nil) chainstate-load-error))

(defun chainstate-load-error (control &rest args)
  "Signal a CHAINSTATE-LOAD-ERROR whose message is CONTROL formatted with ARGS."
  (error 'chainstate-load-error :format-control control :format-arguments args))

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
(define-simple-error cli-error
  "A bitcoin-cli failure on the client side -- an argument, a port, a reply it
cannot read -- which the client prints after `error: ' and exits 1 for
(bitcoin-cli.cpp CommandLineRPC's catch).")

(define-condition protocol-limit-error (serialization-error) ()
  (:documentation "A peer message declared more elements than the protocol
allows -- an inv/getdata over MAX_INV_SZ, a headers message over
MAX_HEADERS_RESULTS, an addr over MAX_ADDR_TO_SEND, a block locator over
MAX_LOCATOR_SZ.

It is a SERIALIZATION-ERROR, so every caller that already handles malformed
bytes keeps working; the separate type exists because Core treats this class
of malformed message differently from every other one. A truncated or
undecodable payload is caught by ProcessMessages and forgiven
(net_processing.cpp:5283-5287), but an over-limit vector is a NAMED rule
inside the handler -- Misbehaving for inv (:4128), getdata (:4219), headers
and addr, a straight fDisconnect for a getblocks/getheaders locator -- so the
peer is punished. SAFELY-DISPATCH-PEER-MESSAGE is where the two part."))

(declaim (ftype (function (t &rest t) nil) protocol-limit-error))
(defun protocol-limit-error (control &rest args)
  "Signal a PROTOCOL-LIMIT-ERROR whose message is CONTROL formatted with ARGS."
  (error 'protocol-limit-error :format-control control :format-arguments args))

(define-condition consensus-error (bitcoin-lisp-error simple-error)
  ((reason :initarg :reason :initform nil :reader error-reason))
  (:documentation "A block or transaction failed a consensus rule. REASON is
Core's reject-reason keyword when the caller has one."))

(define-condition policy-error (bitcoin-lisp-error simple-error)
  ((reason :initarg :reason :initform nil :reader error-reason))
  (:documentation "A transaction is valid but this node's policy refuses it.
REASON is Core's reject-reason keyword when the caller has one."))
