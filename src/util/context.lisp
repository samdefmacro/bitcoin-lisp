(in-package #:bitcoin-lisp.context)

;;;; node-context (Core node/context.h NodeContext)
;;;
;;; The references a subsystem needs to act on the node -- the active
;;; chainstate and its coins view, the block store, the mempool, the peers,
;;; the fee estimator, the address book, the recent-rejects filter -- as
;;; one value (the indexes are not carried: the connect hook reaches them
;;; through the node's index list). A message handler used to take up to eight of
;;; them as positional and keyword parameters, and every caller had to name
;;; each one: the 2026-07-10 wiring bug (tx relay, addr gossip and compact
;;; blocks silently disabled outside unit tests) was a dispatch that passed
;;; two of the eight. With one argument there is nothing to forget.
;;;
;;; Data only, so it loads first and every layer can name it; the node
;;; (src/node.lisp node->context) builds one from its slots for each sync pass
;;; and each receive tick, and tests build one with the pieces they have (an
;;; absent piece is NIL, which is what a handler used to receive when a keyword
;;; was omitted). PEERS is the live list: the IBD loop rewrites it when it
;;; prunes disconnected peers.

(defstruct node-context
  "What a handler or sync pass acts on. Slots are NIL when the piece does not
exist (no mempool during a test, no historical chainstate outside assumeutxo
background validation)."
  chain-state            ; the active chainstate (validation targets it)
  utxo-set               ; its coins view
  block-store
  mempool
  peers                  ; the connected peers, for relay
  fee-estimator
  address-book
  recent-rejects
  historical-chainstate) ; assumeutxo background-validation chainstate

(defparameter +node-context-slots+
  '("CHAIN-STATE" "UTXO-SET" "BLOCK-STORE" "MEMPOOL" "PEERS" "FEE-ESTIMATOR"
    "ADDRESS-BOOK" "RECENT-REJECTS" "HISTORICAL-CHAINSTATE")
  "The slot names WITH-NODE-CONTEXT accepts; a misspelling is a macroexpansion
error rather than an undefined accessor at run time.")

(defmacro with-node-context ((&rest slots) context &body body)
  "Bind each of SLOTS (chain-state, mempool, ...) to that slot of CONTEXT
around BODY. A handler written for the old eight-parameter signature keeps
its body verbatim under this. No IGNORABLE: a slot the body does not use is
a style-warning, which is how the lists stay honest."
  (dolist (slot slots)
    (unless (member (symbol-name slot) +node-context-slots+ :test #'string=)
      (error "with-node-context: ~S is not a node-context slot (one of ~{~A~^, ~})"
             slot +node-context-slots+)))
  (let ((c (gensym "CTX")))
    `(let* ((,c ,context)
            ,@(loop for slot in slots
                    collect `(,slot (,(intern (format nil "NODE-CONTEXT-~A" (symbol-name slot))
                                              :bitcoin-lisp.context)
                                     ,c))))
       ,@body)))
