(in-package #:bitcoin-lisp.networking)

;;;; define-p2p-handler: definition is registration
;;;
;;; HANDLE-MESSAGE used to be a 190-line COND of (string= command "...")
;;; branches, and the same command names were spelled out again in
;;; CHECK-PEER-RATE-LIMIT (which bucket a command drains) and in two
;;; smaller dispatch chains. A handler written and never listed in the COND
;;; compiled, passed its own tests and was unreachable from the wire -- the
;;; "correct code nothing calls" failure DEFINE-RPC was built against on the
;;; RPC side. DEFINE-P2P-HANDLER is the defun and the table row in one form:
;;; the command string, the function HANDLE-<command> of (peer payload ctx),
;;; and the two per-command facts the dispatcher needs -- whether the message
;;; is meaningless without a mempool (Core: fRelayTxes / m_ignore_incoming_txs
;;; paths) and which of the peer's token buckets it drains.
;;;
;;; What stays outside the table on purpose: the handshake window in
;;; %AWAIT-VERACK (pre-verack messages have their own phase), and the IBD
;;; override in DISPATCH-IBD-MESSAGE, which handles block/headers itself and
;;; falls through to HANDLE-MESSAGE for everything else.

(defstruct (p2p-handler (:constructor %make-p2p-handler))
  "One row of the message table (keyed by command string): the handler and
its dispatch facts."
  (function nil :type (or null symbol))
  ;; NIL ctx mempool -> the message is acknowledged but not processed
  (needs-mempool nil :type boolean)
  ;; peer -> token bucket, or NIL for an unlimited command
  (rate-bucket nil :type (or null symbol)))

(defvar *p2p-handlers* (make-hash-table :test 'equal :synchronized t)
  "Command string -> P2P-HANDLER, the table HANDLE-MESSAGE dispatches on.
Filled at load time; synchronized because the message pump reads it from
the sync thread while a warm reload (or a test's probe row) writes it.")

(defun p2p-handler-for (command)
  "The P2P-HANDLER registered for COMMAND, or NIL for a command this node does
not handle (HANDLE-MESSAGE answers NIL for those; CHECK-PEER-RATE-LIMIT lets
them through)."
  (values (gethash command *p2p-handlers*)))

(defun (setf p2p-handler-for) (row command)
  "Install ROW (a P2P-HANDLER, or NIL to retire the command) for COMMAND."
  (if row
      (setf (gethash command *p2p-handlers*) row)
      (remhash command *p2p-handlers*))
  row)

(defun %register-p2p-handler (command function &key needs-mempool rate-bucket)
  (setf (p2p-handler-for command)
        (%make-p2p-handler :function function
                           :needs-mempool needs-mempool :rate-bucket rate-bucket))
  function)

(defmacro define-p2p-handler (spec (peer payload ctx) &body body)
  "Define the handler for the P2P message named in SPEC -- a command string,
or (command &key needs-mempool rate-bucket) -- as the function
HANDLE-<command> of PEER, PAYLOAD and CTX (the node-context), and register
it. BODY is a defun body: docstring, declarations, forms. With NEEDS-MEMPOOL,
HANDLE-MESSAGE skips the body when the context carries no mempool (the
message is still acknowledged as handled). RATE-BUCKET names the peer
accessor of the token bucket the command drains; NIL means unlimited."
  (destructuring-bind (command &key needs-mempool rate-bucket)
      (if (listp spec) spec (list spec))
    (let ((fn (intern (format nil "HANDLE-~A" (string-upcase command)))))
      `(progn
         (defun ,fn (,peer ,payload ,ctx) ,@body)
         (%register-p2p-handler ,command ',fn
                                :needs-mempool ,needs-mempool
                                :rate-bucket ',rate-bucket)
         ',fn))))
