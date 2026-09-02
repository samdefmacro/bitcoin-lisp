(defpackage #:bitcoin-lisp.validation-interface
  (:use #:cl)
  (:documentation "Core's CValidationInterface as hook lists: the chain
and the mempool announce what happened, and whoever cares -- the wallet,
ZMQ, the indexes, the node's own housekeeping -- registered a function
for it. Validation and the mempool name nothing above themselves.")
  (:export #:define-validation-hook
           #:validation-hooks
           #:notify-block-connected
           #:notify-block-disconnected
           #:notify-updated-block-tip
           #:notify-transaction-added
           #:notify-transaction-removed))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (bitcoin-lisp.nicknames:install-package-nicknames))

(in-package #:bitcoin-lisp.validation-interface)

;;;; Core validationinterface.h, as data
;;;
;;; Before this file validation/block.lisp called the wallet, ZMQ, the
;;; index driver, -blocknotify, -stopatheight and the periodic flush by
;;; name -- fourteen upward references into src/node/ and src/zmq.lisp from
;;; the layer that is supposed to know nothing about a node -- and the
;;; mempool did the same for ZMQ and the wallet. The layering scanner could
;;; not see them because the top package spans both ends of the load.
;;;
;;; Each event is a list of hook NAMES (symbols, function designators) in
;;; registration order. DEFINE-VALIDATION-HOOK re-registers a name in place,
;;; so a warm reload never doubles a subscriber. The announce loop does not
;;; catch: a subscriber that must never abort a block connect guards its own
;;; body (the wallet and index hooks do), exactly as the same functions did
;;; when validation called them by name -- Core's interface does not catch
;;; either, and a throwing subscriber there is a bug to fix, not to hide.

(defvar *validation-hooks* (make-hash-table :test 'eq)
  "Event keyword -> list of hook names, in registration order.")

(defparameter +validation-events+
  '(:block-connected        ; (chainstate block block-hash height spent-utxos)
    :block-disconnected     ; (chainstate block block-hash height)
    :updated-block-tip      ; (chainstate block-hash height)
    :transaction-added      ; (tx txid sequence)
    :transaction-removed)   ; (tx txid sequence reason)
  "The events and the argument list each hook receives.")

(defun validation-hooks (event)
  "The hook names registered for EVENT, in registration order."
  (unless (member event +validation-events+)
    (bl.err:internal-error "~S is not a validation event; one of ~S" event +validation-events+))
  (gethash event *validation-hooks*))

(defmacro define-validation-hook (event name lambda-list &body body)
  "Define NAME, a function of LAMBDA-LIST (the event's arguments, see
+VALIDATION-EVENTS+), and register it for EVENT. Redefining NAME keeps its
place in the list, so subscribers run in the order they were first
registered -- the load order of the files that define them."
  `(progn
     (defun ,name ,lambda-list ,@body)
     (unless (member ',name (validation-hooks ,event))
       (setf (gethash ,event *validation-hooks*)
             (append (validation-hooks ,event) (list ',name))))
     ',name))

(defun %announce (event &rest args)
  (dolist (hook (validation-hooks event))
    (apply hook args)))

(defun notify-block-connected (chainstate block block-hash height spent-utxos)
  "A block joined CHAINSTATE's chain at HEIGHT (Core BlockConnected).
SPENT-UTXOS is the undo list the connect produced -- what the indexes fold in."
  (%announce :block-connected chainstate block block-hash height spent-utxos))

(defun notify-block-disconnected (chainstate block block-hash height)
  "BLOCK, previously at HEIGHT, left CHAINSTATE's chain (Core BlockDisconnected)."
  (%announce :block-disconnected chainstate block block-hash height))

(defun notify-updated-block-tip (chainstate block-hash height)
  "CHAINSTATE's tip is now BLOCK-HASH at HEIGHT, after a completed activation
step (Core UpdatedBlockTip / the kernel's blockTip notification)."
  (%announce :updated-block-tip chainstate block-hash height))

(defun notify-transaction-added (tx txid sequence)
  "TX entered the mempool, stamped with SEQUENCE (Core TransactionAddedToMempool)."
  (%announce :transaction-added tx txid sequence))

(defun notify-transaction-removed (tx txid sequence reason)
  "TX left the mempool for REASON (Core TransactionRemovedFromMempool)."
  (%announce :transaction-removed tx txid sequence reason))
