(in-package #:bitcoin-lisp.rpc)

;;; Thread-Safe Node State Accessors
;;;
;;; These functions acquire the node lock before accessing state,
;;; ensuring safe concurrent access from RPC handler threads.
;;;
;;; LOCKING DISCIPLINE. The node has ONE state lock — the recursive
;;; node-lock — guarding the chainstates list, each chainstate's tip/index/
;;; coins view, the mempool (entries, txgraph, deltas, unbroadcast set,
;;; orphan pool), and the peer list. It is our single-lock analogue of
;;; Core's cs_main + pool.cs pair. The P2P sync thread holds it around
;;; every message handler that touches shared state (networking's
;;; WITH-NODE-LOCK, protocol.lisp:7); RPC handler threads run concurrently
;;; on hunchentoot worker threads, so every RPC that MUTATES that state —
;;; or wants a torn-free consistent read of it — must hold the same lock
;;; for the whole operation, not just while fetching the object reference
;;; (which is all the accessors below do).
;;;
;;; Lock ORDERING (deadlock freedom): the node-lock is the OUTERMOST lock.
;;; Code holding it may take leaf locks (per-connection send locks,
;;; *tx-request-lock*, *ban-lock*, *log-lock*, SBCL's synchronized
;;; sig-cache tables); no code path acquires the node-lock while holding
;;; any of those, so the ordering is acyclic. The lock is recursive, so a
;;; locked RPC body may freely call helpers that re-acquire it
;;; (broadcast-transaction-to-peers, the mining assembler's chunk walk,
;;; these accessors). Long-polling RPCs (waitfornewblock/waitforblock*)
;;; must NEVER hold it across their sleep loops — the sync thread needs it
;;; to advance the tip they are waiting on.

(defmacro with-node-lock ((node) &body body)
  "Execute BODY holding NODE's recursive state lock. Use around any RPC
handler section that mutates — or must consistently read — the mempool,
chainstate, or peer list (see the locking discipline above)."
  `(bt:with-recursive-lock-held ((bl::node-lock ,node))
     ,@body))

(defun rpc-get-chain-state (node)
  "Get the current (active) chainstate with lock protection. RPC reports the
active chainstate (Core getblockchaininfo reports CurrentChainstate)."
  (bt:with-recursive-lock-held ((bl::node-lock node))
    (bl::node-current-chainstate node)))

(defun rpc-get-utxo-set (node)
  "Get the current chainstate's coins view with lock protection."
  (bt:with-recursive-lock-held ((bl::node-lock node))
    (let ((cs (bl::node-current-chainstate node)))
      (and cs (bl.store:chain-state-coins-view cs)))))

(defun rpc-get-chainstates (node)
  "Get a copy of the full chainstates list with lock protection (for
getchainstates, which reports every chainstate)."
  (bt:with-recursive-lock-held ((bl::node-lock node))
    (copy-list (bl::node-chainstates node))))

(defun rpc-get-peers (node)
  "Get a copy of the peer list with lock protection."
  (bt:with-recursive-lock-held ((bl::node-lock node))
    (copy-list (bl::node-peers node))))

(defun rpc-get-mempool (node)
  "Get mempool with lock protection."
  (bt:with-recursive-lock-held ((bl::node-lock node))
    (bl::node-mempool node)))

(defun rpc-get-block-store (node)
  "Get block-store with lock protection."
  (bt:with-recursive-lock-held ((bl::node-lock node))
    (bl::node-block-store node)))

(defun rpc-get-network (node)
  "Get network type with lock protection."
  (bt:with-recursive-lock-held ((bl::node-lock node))
    (bl::node-network node)))

(defun rpc-is-syncing (node)
  "Check if node is currently syncing."
  (bt:with-recursive-lock-held ((bl::node-lock node))
    (bl::node-syncing node)))

(defun rpc-get-tx-index (node)
  "Get tx-index with lock protection."
  (bt:with-recursive-lock-held ((bl::node-lock node))
    (bl::node-tx-index node)))

(defun rpc-get-blockfilterindex (node)
  "Get the block filter index with lock protection."
  (bt:with-recursive-lock-held ((bl::node-lock node))
    (bl::node-blockfilterindex node)))

(defun rpc-get-coinstatsindex (node)
  "Get the coinstats index with lock protection."
  (bt:with-recursive-lock-held ((bl::node-lock node))
    (bl::node-coinstatsindex node)))

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
boolean parameters must be read through %positional-bool /
%positional-bool-or, never by raw truthiness.")

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

(defun %positional-array (value)
  "The elements of a positional array parameter, as a list.
The empty-array sentinel yields NIL, so callers iterate uniformly; use
%POSITIONAL-ARRAY-P first when the difference between `[]` and null matters."
  (if (eq value +json-empty-array+) nil value))

(defun %positional-bool (value)
  "Truth of a positional JSON boolean parameter: NIL (null or omitted) and
the explicit-false sentinel are false; anything else is true. Mirrors
Core's pattern `if (!params[i].isNull()) x = params[i].get_bool()` for
default-false parameters."
  (and value (not (eq value +json-false+)) t))

(defun %positional-bool-or (value default)
  "Positional JSON boolean with a non-false DEFAULT: NIL (null or omitted)
yields DEFAULT; explicit false yields NIL; anything else T. Core:
`params[i].isNull() ? default : params[i].get_bool()`."
  (if (null value)
      default
      (%positional-bool value)))

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

(defun %obj-get (obj key)
  "Read KEY from a JSON object that arrived as either an alist (from tests /
JSON-RPC 1.x) or a hash-table (from yason)."
  (cond ((hash-table-p obj) (gethash key obj))
        ((listp obj) (cdr (assoc key obj :test #'string=)))))
