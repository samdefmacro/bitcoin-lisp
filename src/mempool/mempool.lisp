(in-package #:bitcoin-lisp.mempool)

;;; Mempool - In-memory Transaction Pool
;;;
;;; Stores validated unconfirmed transactions. Indexed by txid with
;;; secondary index on spent outpoints for conflict detection.
;;; Enforces size limits via lowest-fee-rate eviction.

;;;; Constants

(defconstant +default-max-mempool-bytes+ (* 300 1024 1024)
  "Default maximum mempool size in bytes (300 MB).")

(defconstant +default-min-relay-fee-rate+ 100
  "Default minimum relay fee rate in satoshis per kvB (Bitcoin Core
DEFAULT_MIN_RELAY_TX_FEE = 100 sat/kvB = 0.1 sat/vB). Was 1 sat/vB -- 10x
stricter than Core, rejecting the whole 0.1..1.0 sat/vB band Core relays; the
sat/kvB representation also makes fractional-sat/vB floors expressible.")

(defconstant +default-ancestor-limit+ 25
  "Max number of in-mempool ancestors (incl. self) for a tx (Bitcoin Core
DEFAULT_ANCESTOR_LIMIT).")

(defconstant +default-descendant-limit+ 25
  "Max number of in-mempool descendants (incl. self) for a tx (Bitcoin Core
DEFAULT_DESCENDANT_LIMIT).")

(defconstant +default-ancestor-size-limit+ 101000
  "Max total vsize of a tx + its ancestors, in vbytes (Core 101 kvB).")

(defconstant +default-descendant-size-limit+ 101000
  "Max total vsize of a tx + its descendants, in vbytes (Core 101 kvB).")

(defconstant +default-mempool-expiry-hours+ 336
  "Drop mempool txs older than this (14 days) — Bitcoin Core
DEFAULT_MEMPOOL_EXPIRY_HOURS.")

;;;; Mempool entry

(defstruct mempool-entry
  "An entry in the mempool."
  (transaction nil :type bitcoin-lisp.serialization:transaction)
  (fee 0 :type (unsigned-byte 64))
  ;; Fee plus any prioritisetransaction delta (Core's GetModifiedFee). This is
  ;; the value mining selection, eviction, and RBF scoring see; FEE stays the
  ;; real paid fee (block reward accounting, fees.base). Can go negative.
  (modified-fee 0 :type integer)
  ;; Serialized (witness) byte length — used for the byte-based mempool size cap.
  (size 0 :type (unsigned-byte 32))
  ;; BIP141 virtual size — the basis for fee-rate (Core computes fee-rate on vsize).
  (vsize 0 :type (unsigned-byte 32))
  ;; Witness txid (BIP339); 32 bytes once populated.
  (wtxid nil :type (or null (simple-array (unsigned-byte 8) (32))))
  ;; Weighted sigop cost (populated at acceptance once inputs are known).
  (sigops 0 :type (unsigned-byte 32))
  ;; Chain height at the time of acceptance.
  (height 0 :type (unsigned-byte 32))
  (entry-time 0 :type (unsigned-byte 64))
  ;; In-mempool dependency links (txid -> t). Ancestor/descendant aggregates
  ;; are derived on demand by walking these (bounded by the 25/25 limits), so
  ;; there are no cached totals to drift out of sync.
  (parents (make-hash-table :test 'equalp) :type hash-table)
  (children (make-hash-table :test 'equalp) :type hash-table)
  ;; This entry's transaction in the mempool's shadow txgraph (cluster mempool
  ;; P3). Core's entry IS its handle (CTxMemPoolEntry : public TxGraph::Ref,
  ;; kernel/mempool_entry.h:65) and the Ref destructor removes the tx from the
  ;; graph; with no destructors, MEMPOOL-ADD assigns this and MEMPOOL-REMOVE
  ;; must explicitly remove it. NIL until the entry is added.
  (graph-handle nil :type (or null tx-handle)))

(defun tx-wire-bytes (tx)
  "TX in its wire encoding: witness form only when the tx has witness data,
so legacy txs aren't charged phantom marker/flag bytes."
  (if (bitcoin-lisp.serialization:transaction-has-witness-p tx)
      (bitcoin-lisp.serialization:serialize-witness-transaction tx)
      (bitcoin-lisp.serialization:serialize-transaction tx)))

(defun make-entry-from-tx (tx fee height &key (sigops 0) (entry-time 0))
  "Build a mempool-entry from TX, computing the derived size/vsize/wtxid fields.
Centralizes entry construction so every acceptance path records the same
fields (handle-tx, sendrawtransaction, reorg re-add)."
  (make-mempool-entry
   :transaction tx
   :fee fee
   :modified-fee fee
   :size (length (tx-wire-bytes tx))
   :vsize (bitcoin-lisp.serialization:transaction-vsize tx)
   :wtxid (bitcoin-lisp.serialization:transaction-wtxid tx)
   :sigops sigops
   :height height
   :entry-time entry-time))

(defun mempool-prioritise (mempool txid fee-delta)
  "Add FEE-DELTA satoshis to TXID's prioritisation (Core's
PrioritiseTransaction). Deltas stack; a net-zero delta is dropped. Applies
immediately to the in-mempool entry's modified fee when present. Returns the
accumulated delta."
  (let* ((delta (+ (gethash txid (mempool-deltas mempool) 0) fee-delta))
         (entry (mempool-get mempool txid)))
    (when entry
      (incf (mempool-entry-modified-fee entry) fee-delta)
      ;; Keep the shadow txgraph's (chunk) feerates honest (Core
      ;; PrioritiseTransaction -> SetTransactionFee, txmempool.cpp:641).
      (let ((handle (mempool-entry-graph-handle entry)))
        (when handle
          (txgraph-set-transaction-fee (mempool-graph mempool) handle
                                       (mempool-entry-modified-fee entry))))
      (%mempool-graph-verify mempool))
    (if (zerop delta)
        (remhash txid (mempool-deltas mempool))
        (setf (gethash txid (mempool-deltas mempool)) delta))
    delta))

(defun mempool-entry-fee-rate (entry)
  "Fee rate (satoshis per virtual byte) for a mempool entry, using the
prioritisation-modified fee (Core scores mining/eviction on modified fees)."
  (let ((vsize (mempool-entry-vsize entry)))
    (if (zerop vsize)
        0
        (/ (mempool-entry-modified-fee entry) vsize))))

;;;; Mempool

(defun %graph-txid-order (a b)
  "Strong fallback order for the mempool's txgraph: byte-lexicographic txid
comparison, mirroring Core's fallback lambda (txmempool.cpp:183-187). The
txid rides in each handle's DATA slot (set by MEMPOOL-ADD)."
  (let ((ta (tx-handle-data a))
        (tb (tx-handle-data b)))
    (loop for i from 0 below 32
          for d = (- (aref ta i) (aref tb i))
          unless (zerop d) return (signum d)
          finally (return 0))))

(defstruct mempool
  "In-memory transaction pool."
  ;; txid (byte vector) -> mempool-entry
  (entries (make-hash-table :test 'equalp) :type hash-table)
  ;; wtxid (byte vector) -> txid  (BIP339 witness-txid lookup for getdata)
  (by-wtxid (make-hash-table :test 'equalp) :type hash-table)
  ;; outpoint-key (byte vector) -> txid that spends it
  (spent-outpoints (make-hash-table :test 'equalp) :type hash-table)
  ;; Total serialized size of all transactions
  (total-size 0 :type integer)
  ;; Maximum allowed size in bytes
  (max-size +default-max-mempool-bytes+ :type integer)
  ;; Minimum relay fee rate (sat/kvB, Core CFeeRate::GetFeePerK units)
  (min-fee-rate +default-min-relay-fee-rate+ :type integer)
  ;; Rolling dynamic minimum fee rate (sat/kvB), raised when the mempool is full
  ;; and trims, decaying back toward the relay floor over time. Bitcoin Core's
  ;; rolling minimum fee.
  (rolling-min-fee-rate 0 :type integer)
  (rolling-min-fee-time 0 :type integer)
  ;; txid -> satoshi fee delta from prioritisetransaction (Core's mapDeltas).
  ;; Deltas may exist for txs not (yet) in the mempool; applied on acceptance.
  (deltas (make-hash-table :test 'equalp) :type hash-table)
  ;; Orphan transactions (inputs not yet available); de-orphaned when a parent
  ;; arrives. Lives here so the tx-handling path reaches it via the mempool.
  (orphan-pool (make-orphan-pool) :type orphan-pool)
  ;; Shadow txgraph (cluster mempool P3): the cluster/chunk engine, maintained
  ;; in lockstep with ENTRIES on every mutation but read by no decision yet -
  ;; mining, eviction, limits, and RBF flip to it in P4-P7. Core-exact cluster
  ;; limits (64 tx / 101 kvB); under today's 25/25 BFS limits a connected
  ;; component can exceed them, in which case the graph holds the offending
  ;; dependencies pending and reports oversized until removals resolve it
  ;; (txgraph.lisp OVERSIZED contract).
  (graph (make-txgraph :fallback-order #'%graph-txid-order) :type txgraph))

(defconstant +rolling-fee-halflife-seconds+ 43200
  "Rolling minimum fee decays by half every 12 hours (Bitcoin Core default).")

(defun mempool-effective-min-fee-rate (mempool &optional (now (bitcoin-lisp.serialization:get-unix-time)))
  "Effective minimum fee rate to enter the mempool, in SAT/KVB: the relay floor,
or the decayed rolling minimum if higher (Bitcoin Core CTxMemPool::GetMinFee,
CFeeRate::GetFeePerK units). Compare as (>= (* fee 1000) (* rate vsize))."
  (let ((rolling (mempool-rolling-min-fee-rate mempool)))
    (if (<= rolling 0)
        (mempool-min-fee-rate mempool)
        (let* ((age (max 0 (- now (mempool-rolling-min-fee-time mempool))))
               (decayed (floor (* rolling
                                  (expt 0.5d0 (/ age +rolling-fee-halflife-seconds+))))))
          (max (mempool-min-fee-rate mempool) decayed)))))

;;;; Shadow txgraph checks (cluster mempool P3)
;;;;
;;;; The txgraph is write-only in this phase: every mutation path mirrors
;;;; into it, nothing reads it for decisions. These checks are the safety
;;;; net for the P4-P7 flips - they prove, across the whole suite and in
;;;; production soak, that the graph agrees with the BFS parent/child
;;;; machinery it will replace.

(defvar *txgraph-shadow-checks* nil
  "When true, assert full mempool/txgraph equivalence after every mempool
mutation: graph tx-count vs entry count, per-entry handle liveness,
TXGRAPH-SANITY-CHECK, and (unless the graph is oversized) ancestor- and
descendant-set equality against the BFS walks plus parent/child edges lying
within one cluster. Divergence signals an ERROR. NIL in production, set to T
by the test suite (tests/package.lisp); production always keeps a free
tx-count equality check that logs a warning instead.")

(defvar *graph-verify-batch* nil
  "True inside a multi-removal mempool operation. Interim states of such a
batch can transiently bridge - a removed tx's parents and children both
still present - where the graph's closure semantics (grandparents stay
ancestors) and the BFS links (severed) legitimately differ, so the
expensive equivalence checks only run at batch end.")

(defun %short-txid (txid)
  (bitcoin-lisp.crypto:bytes-to-hex (subseq txid 0 8)))

(defun %graph-closure-equal-p (closure self bfs-set)
  "True when CLOSURE (a txgraph ancestor/descendant handle list, which
includes SELF) covers exactly BFS-SET (a txid hash-set excluding self)."
  (and (= (length closure) (1+ (hash-table-count bfs-set)))
       (every (lambda (h)
                (or (eq h self) (gethash (tx-handle-data h) bfs-set)))
              closure)))

(defun %verify-graph-entry (mempool graph txid entry)
  "Assert graph/BFS equivalence for one entry: ancestor and descendant sets
match the BFS walks, and every parent edge stays within one cluster. The
graph must not be oversized."
  (let ((handle (mempool-entry-graph-handle entry)))
    (unless (%graph-closure-equal-p (txgraph-get-ancestors graph handle)
                                    handle (mempool-ancestors mempool txid))
      (error "txgraph shadow divergence: ancestor sets differ for ~A"
             (%short-txid txid)))
    (unless (%graph-closure-equal-p (txgraph-get-descendants graph handle)
                                    handle (mempool-descendants mempool txid))
      (error "txgraph shadow divergence: descendant sets differ for ~A"
             (%short-txid txid)))
    (maphash (lambda (parent v)
               (declare (ignore v))
               (let ((pe (mempool-get mempool parent)))
                 (unless (and pe (eq (tx-handle-cluster
                                      (mempool-entry-graph-handle pe))
                                     (tx-handle-cluster handle)))
                   (error "txgraph shadow divergence: edge ~A -> ~A ~
                           spans clusters"
                          (%short-txid parent) (%short-txid txid)))))
             (mempool-entry-parents entry))))

(defun %mempool-graph-verify (mempool)
  "Verify the shadow txgraph against the mempool. The tx-count equality
check is always on (O(1); logs a warning in production, errors under
*TXGRAPH-SHADOW-CHECKS*); the full equivalence checks run only under
*TXGRAPH-SHADOW-CHECKS* and outside removal batches."
  (let ((graph (mempool-graph mempool))
        (count (mempool-count mempool)))
    (unless (= (txgraph-tx-count graph) count)
      (if *txgraph-shadow-checks*
          (error "txgraph shadow divergence: graph has ~D transactions, ~
                  mempool has ~D"
                 (txgraph-tx-count graph) count)
          (bitcoin-lisp:log-warn
           "txgraph shadow divergence: graph ~D txs, mempool ~D"
           (txgraph-tx-count graph) count)))
    (when (and *txgraph-shadow-checks* (not *graph-verify-batch*))
      (txgraph-sanity-check graph)
      (maphash (lambda (txid entry)
                 (let ((handle (mempool-entry-graph-handle entry)))
                   (unless (and handle
                                (txgraph-exists-p graph handle)
                                (equalp (tx-handle-data handle) txid))
                     (error "txgraph shadow divergence: entry ~A has ~
                             ~:[no~;a dead or mismatched~] graph handle"
                            (%short-txid txid) handle))))
               (mempool-entries mempool))
      (unless (txgraph-oversized-p graph)
        (maphash (lambda (txid entry)
                   (%verify-graph-entry mempool graph txid entry))
                 (mempool-entries mempool)))))
  (values))

(defmacro %with-graph-verify-batch ((mempool) &body body)
  "Run BODY as one removal batch: per-removal verification stays cheap
(tx-count only) and the full shadow verification runs once at the end.
Nested batches verify only at the outermost exit."
  (let ((mp (gensym "MEMPOOL")) (outer (gensym "OUTER")))
    `(let* ((,mp ,mempool)
            (,outer (not *graph-verify-batch*))
            (*graph-verify-batch* t))
       (multiple-value-prog1 (progn ,@body)
         (when ,outer
           (let ((*graph-verify-batch* nil))
             (%mempool-graph-verify ,mp)))))))

;;;; Outpoint key helper

(defun make-outpoint-key (txid index)
  "Create a key for the spent-outpoints table."
  (let ((key (make-array 36 :element-type '(unsigned-byte 8))))
    (replace key txid)
    (setf (aref key 32) (logand index #xFF))
    (setf (aref key 33) (logand (ash index -8) #xFF))
    (setf (aref key 34) (logand (ash index -16) #xFF))
    (setf (aref key 35) (logand (ash index -24) #xFF))
    key))

;;;; Core operations

(defun mempool-has (mempool txid)
  "Check if a transaction is in the mempool."
  (not (null (gethash txid (mempool-entries mempool)))))

(defun mempool-get (mempool txid)
  "Get a mempool entry by txid. Returns the entry or NIL."
  (gethash txid (mempool-entries mempool)))

(defun mempool-get-by-wtxid (mempool wtxid)
  "Get a mempool entry by its BIP339 witness txid (wtxid). Returns the entry or
NIL. Used to serve MSG_WTX getdata, where the requested hash is a wtxid."
  (let ((txid (gethash wtxid (mempool-by-wtxid mempool))))
    (when txid (gethash txid (mempool-entries mempool)))))

(defun mempool-count (mempool)
  "Return the number of transactions in the mempool."
  (hash-table-count (mempool-entries mempool)))

(defun mempool-spending-tx (mempool txid vout)
  "Return the txid of the mempool transaction that spends outpoint (TXID, VOUT),
or NIL if no mempool tx spends it. Used by the gettxspendingprevout RPC."
  (gethash (make-outpoint-key txid vout) (mempool-spent-outpoints mempool)))

(defun mempool-check-conflict (mempool tx)
  "Check if TX conflicts with any existing mempool entry.
Returns the txid of the conflicting transaction, or NIL if no conflict."
  (bitcoin-lisp.serialization:dovector (input (bitcoin-lisp.serialization:transaction-inputs tx))
    (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
           (key (make-outpoint-key
                 (bitcoin-lisp.serialization:outpoint-hash prevout)
                 (bitcoin-lisp.serialization:outpoint-index prevout)))
           (spending-txid (gethash key (mempool-spent-outpoints mempool))))
      (when spending-txid
        (return-from mempool-check-conflict spending-txid))))
  nil)

;;;; Ancestor / descendant graph (derived on demand from parent/child links)

(defun mempool-find-parents (mempool tx)
  "Return the distinct txids of TX's inputs that are themselves in the mempool."
  (let ((seen (make-hash-table :test 'equalp))
        (result '()))
    (bitcoin-lisp.serialization:dovector (input (bitcoin-lisp.serialization:transaction-inputs tx))
      (let ((ptxid (bitcoin-lisp.serialization:outpoint-hash
                    (bitcoin-lisp.serialization:tx-in-previous-output input))))
        (when (and (mempool-has mempool ptxid) (not (gethash ptxid seen)))
          (setf (gethash ptxid seen) t)
          (push ptxid result))))
    result))

(defun %walk-mempool-graph (mempool seed-txids link-accessor)
  "BFS from SEED-TXIDS following LINK-ACCESSOR (parents or children of an entry).
Returns a hash-set (txid -> t) of all reached txids (excluding the seeds unless
they are reachable from each other). Bounded by the ancestor/descendant limits."
  (let ((found (make-hash-table :test 'equalp))
        (queue (copy-list seed-txids)))
    (loop while queue
          do (let ((txid (pop queue)))
               (unless (gethash txid found)
                 (let ((entry (mempool-get mempool txid)))
                   (when entry
                     (setf (gethash txid found) t)
                     (maphash (lambda (k v) (declare (ignore v)) (push k queue))
                              (funcall link-accessor entry)))))))
    found))

(defun mempool-ancestors (mempool txid)
  "Hash-set of all in-mempool ancestor txids of TXID (excluding TXID itself)."
  (let ((entry (mempool-get mempool txid)))
    (if entry
        (%walk-mempool-graph mempool
                             (loop for k being the hash-keys of (mempool-entry-parents entry)
                                   collect k)
                             #'mempool-entry-parents)
        (make-hash-table :test 'equalp))))

(defun mempool-descendants (mempool txid)
  "Hash-set of all in-mempool descendant txids of TXID (excluding TXID itself)."
  (let ((entry (mempool-get mempool txid)))
    (if entry
        (%walk-mempool-graph mempool
                             (loop for k being the hash-keys of (mempool-entry-children entry)
                                   collect k)
                             #'mempool-entry-children)
        (make-hash-table :test 'equalp))))

(defun %stats-over (mempool txid-set seed-entry)
  "Return (values count vsize fees) over SEED-ENTRY plus every entry in TXID-SET."
  (let ((count 1)
        (vsize (mempool-entry-vsize seed-entry))
        (fees (mempool-entry-modified-fee seed-entry)))
    (maphash (lambda (txid v)
               (declare (ignore v))
               (let ((e (mempool-get mempool txid)))
                 (when e
                   (incf count)
                   (incf vsize (mempool-entry-vsize e))
                   (incf fees (mempool-entry-modified-fee e)))))
             txid-set)
    (values count vsize fees)))

(defun mempool-ancestor-stats (mempool txid)
  "(values count vsize fees) over TXID and all its ancestors (incl. self)."
  (let ((entry (mempool-get mempool txid)))
    (if entry
        (%stats-over mempool (mempool-ancestors mempool txid) entry)
        (values 0 0 0))))

(defun mempool-descendant-stats (mempool txid)
  "(values count vsize fees) over TXID and all its descendants (incl. self)."
  (let ((entry (mempool-get mempool txid)))
    (if entry
        (%stats-over mempool (mempool-descendants mempool txid) entry)
        (values 0 0 0))))

(defun mempool-ancestor-fee-rate (mempool txid)
  "Ancestor-package fee rate (the mining score): ancestor-fees / ancestor-vsize.
A low-fee tx with a high-fee unconfirmed parent chain scores higher here."
  (multiple-value-bind (count vsize fees) (mempool-ancestor-stats mempool txid)
    (declare (ignore count))
    (if (zerop vsize) 0 (/ fees vsize))))

(defun mempool-descendant-fee-rate (mempool txid)
  "Descendant-package fee rate (the eviction score): descendant-fees /
descendant-vsize. A low-fee parent with a high-fee child (CPFP) scores higher
and is evicted later."
  (multiple-value-bind (count vsize fees) (mempool-descendant-stats mempool txid)
    (declare (ignore count))
    (if (zerop vsize) 0 (/ fees vsize))))

(defconstant +truc-version+ 3
  "BIP431 TRUC (v3) transaction version.")
(defconstant +truc-max-vsize+ 10000
  "Max vsize of a TRUC (v3) transaction (Core TRUC_MAX_VSIZE).")
(defconstant +truc-child-max-vsize+ 1000
  "Max vsize of a TRUC child that spends an unconfirmed TRUC parent
(Core TRUC_CHILD_MAX_VSIZE).")
(defconstant +truc-ancestor-limit+ 2
  "A TRUC tx's ancestor set (incl. self) must be <= this (Core TRUC_ANCESTOR_LIMIT).")
(defconstant +truc-descendant-limit+ 2
  "A TRUC tx's descendant set (incl. self) must be <= this (Core TRUC_DESCENDANT_LIMIT).")

(defun single-truc-checks (mempool tx vsize direct-conflicts)
  "BIP431 TRUC (v3) topology checks for a single new TX at mempool acceptance,
a port of Core policy SingleTRUCChecks. VSIZE is TX's virtual size;
DIRECT-CONFLICTS the list of mempool txids it replaces (RBF). Returns (values t
NIL) when acceptable, else (values NIL reason-keyword).

Enforces: v3<->non-v3 spend inheritance (both directions); v3 tx <= 10000 vsize;
at most 1 unconfirmed ancestor and, for a child of an unconfirmed TRUC parent,
<= 1000 vsize and the parent having no other unconfirmed descendant (unless that
sibling is being replaced). We decline TRUC sibling eviction (Core permits the
caller to), so a v3 tx that would need it is rejected with :truc-descendant-limit."
  (let* ((version (bitcoin-lisp.serialization:transaction-version tx))
         (parents (mempool-find-parents mempool tx))
         (v3 (= version +truc-version+)))
    ;; 1. TRUC / non-TRUC inheritance, both directions.
    (dolist (p parents)
      (let* ((pe (mempool-get mempool p))
             (pv (and pe (bitcoin-lisp.serialization:transaction-version
                          (mempool-entry-transaction pe)))))
        (when pe
          (cond
            ((and (not v3) (= pv +truc-version+))
             (return-from single-truc-checks (values nil :truc-nonv3-spends-v3)))
            ((and v3 (/= pv +truc-version+))
             (return-from single-truc-checks (values nil :truc-v3-spends-nonv3)))))))
    ;; 2. The remaining rules apply only to v3 transactions.
    (unless v3 (return-from single-truc-checks (values t nil)))
    ;; 3. Size cap.
    (when (> vsize +truc-max-vsize+)
      (return-from single-truc-checks (values nil :truc-tx-too-big)))
    ;; 4. Ancestor limit: parents + self must be within the limit.
    (when (> (+ (length parents) 1) +truc-ancestor-limit+)
      (return-from single-truc-checks (values nil :truc-too-many-ancestors)))
    ;; 5. Child-of-unconfirmed-parent rules.
    (when parents
      (let ((parent (first parents)))
        ;; The parent must have no ancestors of its own (it + self + new > 2).
        (when (> (+ (mempool-ancestor-stats mempool parent) 1) +truc-ancestor-limit+)
          (return-from single-truc-checks (values nil :truc-too-many-ancestors)))
        ;; A child spending a TRUC parent is size-limited.
        (when (> vsize +truc-child-max-vsize+)
          (return-from single-truc-checks (values nil :truc-child-too-big)))
        ;; The parent may have at most this one child (unless its existing child
        ;; is being replaced). descendant-stats/ancestor-stats counts include self.
        (let* ((descendants (mempool-descendants mempool parent))   ; excludes parent
               (child-will-be-replaced
                 (loop for d being the hash-keys of descendants
                       thereis (member d direct-conflicts :test #'equalp))))
          (when (and (> (+ (mempool-descendant-stats mempool parent) 1) +truc-descendant-limit+)
                     (not child-will-be-replaced))
            (return-from single-truc-checks (values nil :truc-descendant-limit))))))
    (values t nil)))

(defun check-ancestor-descendant-limits (mempool parent-txids new-vsize)
  "Check that adding a new tx of NEW-VSIZE with the given in-mempool PARENT-TXIDS
keeps it within ancestor and descendant limits. Returns (values ok-p reason)."
  ;; Ancestors of the new tx = its parents plus all of their ancestors.
  (let* ((ancestors (%walk-mempool-graph mempool (copy-list parent-txids)
                                         #'mempool-entry-parents))
         (acount 1) (avsize new-vsize))     ; include the new tx itself
    (maphash (lambda (a v) (declare (ignore v))
               (let ((e (mempool-get mempool a)))
                 (when e (incf acount) (incf avsize (mempool-entry-vsize e)))))
             ancestors)
    (cond
      ((> acount +default-ancestor-limit+) (values nil :too-long-mempool-chain))
      ((> avsize +default-ancestor-size-limit+) (values nil :too-long-mempool-chain))
      (t
       ;; Adding the new tx adds one descendant (+new-vsize) to each ancestor.
       (let ((result-ok t) (result-reason nil))
         (block scan
           (maphash (lambda (a v) (declare (ignore v))
                      (multiple-value-bind (dcount dvsize) (mempool-descendant-stats mempool a)
                        (when (or (> (1+ dcount) +default-descendant-limit+)
                                  (> (+ dvsize new-vsize) +default-descendant-size-limit+))
                          (setf result-ok nil result-reason :too-long-mempool-chain)
                          (return-from scan))))
                    ancestors))
         (values result-ok result-reason))))))

(defun %link-entry-parents (mempool txid entry parent-txids)
  "Wire up the parent/child links between ENTRY (TXID) and its in-mempool parents."
  (dolist (p parent-txids)
    (setf (gethash p (mempool-entry-parents entry)) t)
    (let ((pe (mempool-get mempool p)))
      (when pe (setf (gethash txid (mempool-entry-children pe)) t)))))

(defun %unlink-entry (mempool txid entry)
  "Drop ENTRY (TXID) from its parents' children sets and its children's parents."
  (maphash (lambda (p v) (declare (ignore v))
             (let ((pe (mempool-get mempool p)))
               (when pe (remhash txid (mempool-entry-children pe)))))
           (mempool-entry-parents entry))
  (maphash (lambda (c v) (declare (ignore v))
             (let ((ce (mempool-get mempool c)))
               (when ce (remhash txid (mempool-entry-parents ce)))))
           (mempool-entry-children entry)))

(defun accept-validated-tx (mempool txid tx fee height
                            &key (entry-time
                                  (bitcoin-lisp.serialization:get-unix-time))
                                 replaced)
  "The shared tail of every mempool acceptance path (peer tx handler,
orphan cascade, sendrawtransaction, mempool.dat reload, reorg re-add,
submitpackage): evict the BIP125 REPLACED txids, build the entry for TX,
add it. Caller has already run validate-transaction-for-mempool. Returns
(values result entry) where RESULT is mempool-add's keyword."
  (dolist (rt replaced)
    (mempool-remove-recursive mempool rt))
  (let ((entry (make-entry-from-tx tx (or fee 0) height :entry-time entry-time)))
    (values (mempool-add mempool txid entry) entry)))

(defun mempool-add (mempool txid entry)
  "Add a transaction to the mempool.
Returns :ok on success, or a keyword indicating the rejection reason."
  ;; Check for duplicate
  (when (mempool-has mempool txid)
    (return-from mempool-add :duplicate))

  ;; Apply any pre-existing prioritisation delta (Core: ATMP ApplyDelta) so
  ;; eviction scoring below and later mining selection see the modified fee.
  (let ((delta (gethash txid (mempool-deltas mempool))))
    (when delta
      (incf (mempool-entry-modified-fee entry) delta)))

  ;; Check for conflicts
  (let ((conflict (mempool-check-conflict
                   mempool (mempool-entry-transaction entry))))
    (when conflict
      (return-from mempool-add :conflict)))

  ;; Ancestor/descendant package limits.
  (let ((parent-txids (mempool-find-parents
                       mempool (mempool-entry-transaction entry))))
    (multiple-value-bind (ok reason)
        (check-ancestor-descendant-limits mempool parent-txids
                                          (mempool-entry-vsize entry))
      (unless ok
        (return-from mempool-add reason)))

  ;; Evict if needed to make room
  (let ((tx-size (mempool-entry-size entry)))
    (when (> (+ (mempool-total-size mempool) tx-size)
             (mempool-max-size mempool))
      ;; Try to evict enough lowest-fee-rate entries
      (unless (mempool-evict-for-size mempool tx-size
                                       (mempool-entry-fee-rate entry))
        (return-from mempool-add :mempool-full))))

  ;; Add to entries table
  (setf (gethash txid (mempool-entries mempool)) entry)

  ;; Wire up ancestor/descendant links to in-mempool parents.
  (%link-entry-parents mempool txid entry parent-txids)

  ;; Index by wtxid (BIP339)
  (let ((wtxid (mempool-entry-wtxid entry)))
    (when wtxid
      (setf (gethash wtxid (mempool-by-wtxid mempool)) txid)))

  ;; Index spent outpoints
  (bitcoin-lisp.serialization:dovector (input (bitcoin-lisp.serialization:transaction-inputs
                  (mempool-entry-transaction entry)))
    (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
           (key (make-outpoint-key
                 (bitcoin-lisp.serialization:outpoint-hash prevout)
                 (bitcoin-lisp.serialization:outpoint-index prevout))))
      (setf (gethash key (mempool-spent-outpoints mempool)) txid)))

  ;; Update total size
  (incf (mempool-total-size mempool) (mempool-entry-size entry))

  ;; Mirror into the shadow txgraph (Core ChangeSet::StageAddition +
  ;; ProcessDependencies, txmempool.cpp:1005-1071): the modified fee (the
  ;; delta was applied above; Core adds unmodified then SetTransactionFee -
  ;; one step here), the vsize, and a dependency per in-mempool parent.
  (let* ((graph (mempool-graph mempool))
         (handle (txgraph-add-transaction
                  graph (mempool-entry-modified-fee entry)
                  (mempool-entry-vsize entry))))
    (setf (tx-handle-data handle) txid
          (mempool-entry-graph-handle entry) handle)
    (dolist (p parent-txids)
      (txgraph-add-dependency
       graph (mempool-entry-graph-handle (mempool-get mempool p)) handle)))
  (%mempool-graph-verify mempool)

  :ok))

(defun mempool-remove (mempool txid)
  "Remove a transaction from the mempool by txid.
Returns the removed entry, or NIL if not found.

Callers removing a tx that has in-mempool descendants must use
MEMPOOL-REMOVE-RECURSIVE (as every current caller does; Core has no
non-recursive removal of a tx with descendants either): removing only the
middle of a chain leaves the shadow txgraph - whose closure semantics keep
grandparents connected - disagreeing with the severed BFS links, which the
shadow checks report as divergence."
  (let ((entry (gethash txid (mempool-entries mempool))))
    (when entry
      ;; Remove spent outpoint entries
      (bitcoin-lisp.serialization:dovector (input (bitcoin-lisp.serialization:transaction-inputs
                      (mempool-entry-transaction entry)))
        (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
               (key (make-outpoint-key
                     (bitcoin-lisp.serialization:outpoint-hash prevout)
                     (bitcoin-lisp.serialization:outpoint-index prevout))))
          (remhash key (mempool-spent-outpoints mempool))))
      ;; Remove wtxid index
      (let ((wtxid (mempool-entry-wtxid entry)))
        (when wtxid
          (remhash wtxid (mempool-by-wtxid mempool))))
      ;; Drop ancestor/descendant links to/from this entry
      (%unlink-entry mempool txid entry)
      ;; Remove from entries
      (remhash txid (mempool-entries mempool))
      ;; Update total size
      (decf (mempool-total-size mempool) (mempool-entry-size entry))
      ;; Drop from the shadow txgraph (Core ChangeSet::StageRemoval /
      ;; removeUnchecked; the Ref destructor does this in Core - with no
      ;; destructors it must be explicit on EVERY removal path, and all
      ;; paths funnel through here). A NIL handle means the entry bypassed
      ;; MEMPOOL-ADD; the verify below reports the count divergence.
      (let ((handle (mempool-entry-graph-handle entry)))
        (when handle
          (txgraph-remove-transaction (mempool-graph mempool) handle)))
      (%mempool-graph-verify mempool)
      entry)))

(defun mempool-remove-recursive (mempool txid)
  "Remove TXID and all of its in-mempool descendants. Returns the number of
transactions removed. Used by RBF replacement, eviction, expiry, and
block-conflict removal so a removed tx never leaves dangling children
behind."
  (%with-graph-verify-batch (mempool)
    (let ((targets (mempool-descendants mempool txid))
          (removed 0))
      (setf (gethash txid targets) t)      ; include self
      (maphash (lambda (t2 v) (declare (ignore v))
                 (when (mempool-remove mempool t2) (incf removed)))
               targets)
      removed)))

;;;; Replace-by-fee (BIP125)

(defparameter +max-bip125-rbf-sequence+ #xfffffffd
  "An input signals opt-in RBF when its nSequence is <= this value.")

(defparameter +max-rbf-replacement-candidates+ 100
  "BIP125 rule 5: a replacement may evict at most this many transactions.")

(defparameter +incremental-relay-fee-rate+ 100
  "Incremental relay fee in satoshis per kvB for BIP125 rule 4 (Bitcoin Core
DEFAULT_INCREMENTAL_RELAY_FEE = 100 sat/kvB = 0.1 sat/vB).")

(defvar *mempool-full-rbf* nil
  "When true, treat every mempool tx as replaceable regardless of signaling
(Bitcoin Core -mempoolfullrbf). When nil, enforce BIP125 opt-in signaling.")

(defun tx-signals-rbf-p (tx)
  "True if TX opts in to replacement (any input nSequence <= 0xfffffffd)."
  (some (lambda (in)
          (<= (bitcoin-lisp.serialization:tx-in-sequence in)
              +max-bip125-rbf-sequence+))
        (bitcoin-lisp.serialization:transaction-inputs tx)))

(defun mempool-tx-or-ancestor-signals-rbf-p (mempool txid)
  "True if the mempool tx TXID, or any of its in-mempool ancestors, signals RBF."
  (let ((e (mempool-get mempool txid)))
    (when e
      (or (tx-signals-rbf-p (mempool-entry-transaction e))
          (block found
            (maphash (lambda (a v) (declare (ignore v))
                       (let ((ae (mempool-get mempool a)))
                         (when (and ae (tx-signals-rbf-p (mempool-entry-transaction ae)))
                           (return-from found t))))
                     (mempool-ancestors mempool txid))
            nil)))))

(defun find-rbf-conflicts (mempool tx)
  "Distinct txids of mempool txs that directly conflict with TX (spend a common
outpoint). Generalizes mempool-check-conflict, which returns only the first."
  (let ((seen (make-hash-table :test 'equalp)) (result '()))
    (bitcoin-lisp.serialization:dovector (input (bitcoin-lisp.serialization:transaction-inputs tx) result)
      (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
             (key (make-outpoint-key
                   (bitcoin-lisp.serialization:outpoint-hash prevout)
                   (bitcoin-lisp.serialization:outpoint-index prevout)))
             (sp (gethash key (mempool-spent-outpoints mempool))))
        (when (and sp (not (gethash sp seen)))
          (setf (gethash sp seen) t)
          (push sp result))))))

(defun check-rbf-rules (mempool tx new-fee new-vsize direct-conflicts)
  "Apply the BIP125 replacement rules for TX (paying NEW-FEE — the
prioritisation-MODIFIED fee, like the replaced entries' fees below — over
NEW-VSIZE)
against DIRECT-CONFLICTS (a list of directly-conflicting mempool txids).
Returns (values ok-p reason replaced-set), where REPLACED-SET is a hash-set of
all txids that would be evicted (the conflicts plus their descendants)."
  ;; Build the full set to be replaced: each conflict and all its descendants.
  (let ((replaced (make-hash-table :test 'equalp))
        (orig-fees 0))
    (dolist (ctxid direct-conflicts)
      (setf (gethash ctxid replaced) t)
      (maphash (lambda (d v) (declare (ignore v)) (setf (gethash d replaced) t))
               (mempool-descendants mempool ctxid)))
    ;; Rule 5: bounded number of replacements.
    (when (> (hash-table-count replaced) +max-rbf-replacement-candidates+)
      (return-from check-rbf-rules (values nil :too-many-replacements nil)))
    ;; A replacement must not spend an output of any tx it replaces (Core
    ;; EntriesAndTxidsDisjoint) — that would leave a dangling input after the
    ;; replaced set is evicted.
    (bitcoin-lisp.serialization:dovector (in (bitcoin-lisp.serialization:transaction-inputs tx))
      (when (gethash (bitcoin-lisp.serialization:outpoint-hash
                      (bitcoin-lisp.serialization:tx-in-previous-output in))
                     replaced)
        (return-from check-rbf-rules (values nil :replacement-adds-unconfirmed nil))))
    ;; Rule 1: every directly-conflicting tx must be replaceable (signaling,
    ;; directly or via an ancestor) — unless full-RBF is enabled.
    (unless *mempool-full-rbf*
      (dolist (ctxid direct-conflicts)
        (unless (mempool-tx-or-ancestor-signals-rbf-p mempool ctxid)
          (return-from check-rbf-rules (values nil :txn-mempool-conflict nil)))))
    ;; Rule 2: the replacement may only spend an unconfirmed output if that exact
    ;; outpoint was already spent by one of the original transactions.
    (let ((orig-inputs (make-hash-table :test 'equalp)))
      (dolist (ctxid direct-conflicts)
        (let ((ce (mempool-get mempool ctxid)))
          (when ce
            (bitcoin-lisp.serialization:dovector (in (bitcoin-lisp.serialization:transaction-inputs
                         (mempool-entry-transaction ce)))
              (let ((p (bitcoin-lisp.serialization:tx-in-previous-output in)))
                (setf (gethash (make-outpoint-key
                                (bitcoin-lisp.serialization:outpoint-hash p)
                                (bitcoin-lisp.serialization:outpoint-index p))
                               orig-inputs)
                      t))))))
      (bitcoin-lisp.serialization:dovector (in (bitcoin-lisp.serialization:transaction-inputs tx))
        (let* ((p (bitcoin-lisp.serialization:tx-in-previous-output in))
               (ptxid (bitcoin-lisp.serialization:outpoint-hash p)))
          (when (and (mempool-has mempool ptxid)
                     (not (gethash (make-outpoint-key
                                    ptxid (bitcoin-lisp.serialization:outpoint-index p))
                                   orig-inputs)))
            (return-from check-rbf-rules
              (values nil :replacement-adds-unconfirmed nil))))))
    ;; Sum the fees of everything being replaced.
    (maphash (lambda (txid v) (declare (ignore v))
               (let ((e (mempool-get mempool txid)))
                 (when e (incf orig-fees (mempool-entry-modified-fee e)))))
             replaced)
    ;; Rule 3: pay at least the total fee of the replaced transactions.
    (when (< new-fee orig-fees)
      (return-from check-rbf-rules (values nil :insufficient-fee nil)))
    ;; Rule 4: pay for the replacement's own bandwidth on top, at the
    ;; incremental relay fee rate (0.1 sat/vB), not the 1 sat/vB relay floor.
    (when (< (- new-fee orig-fees)
             (ceiling (* new-vsize +incremental-relay-fee-rate+) 1000))
      (return-from check-rbf-rules (values nil :insufficient-fee nil)))
    (values t nil replaced)))

;;;; Persistence (Bitcoin Core mempool.dat — node/mempool_persist.cpp)
;;;;
;;;; Own versioned format (like the UTXO snapshot, NOT Core's binary layout):
;;;;   magic "MPL\x01" (u32) | version (u8) |
;;;;   entry-count (u32) | entries: [tx-len u32 | tx bytes (witness form) |
;;;;     entry-time u64 | fee-delta i64] |
;;;;   residual-delta-count (u32) | [txid 32B | fee-delta i64]* | CRC32
;;;; Entries are written parents-before-children (ascending in-mempool
;;;; ancestor count) so reload through normal acceptance resolves chained
;;;; spends, mirroring Core's sorted infoAll(). Per-entry deltas ride with
;;;; their entry; deltas for txs not in the pool are the residual map.

(defconstant +mempool-dat-magic+ #x4d504c01
  "Magic identifying a mempool.dat file (\"MPL\" + 0x01).")

(defconstant +mempool-dat-version+ 1)

(defun mempool-dat-path (data-directory)
  "Path of the mempool persistence file under DATA-DIRECTORY, or NIL."
  (when data-directory
    (merge-pathnames "mempool.dat" data-directory)))

(defun %mempool-entries-parents-first (mempool)
  "All (txid . entry) pairs ordered so every in-mempool parent precedes its
children (ascending ancestor count; a child always counts more ancestors
than any of its parents)."
  ;; Decorate-sort-undecorate: ancestor counts are computed ONCE per entry
  ;; (a sort :key would re-walk ancestors on every comparison).
  (let ((pairs '()))
    (maphash (lambda (txid entry)
               (push (list txid entry
                           (nth-value 0 (mempool-ancestor-stats mempool txid)))
                     pairs))
             (mempool-entries mempool))
    (mapcar (lambda (triple) (cons (first triple) (second triple)))
            (sort pairs #'< :key #'third))))

(defun save-mempool-file (mempool path)
  "Persist MEMPOOL (entries + prioritisation deltas) to PATH atomically.
Returns the number of entries written."
  (let ((ordered (%mempool-entries-parents-first mempool))
        (residual '()))
    (maphash (lambda (txid delta)
               (unless (mempool-has mempool txid)
                 (push (cons txid delta) residual)))
             (mempool-deltas mempool))
    (bitcoin-lisp.storage:save-file-with-crc32
     path
     (lambda (s)
       (bitcoin-lisp.serialization:write-uint32-le s +mempool-dat-magic+)
       (bitcoin-lisp.serialization:write-uint8 s +mempool-dat-version+)
       (bitcoin-lisp.serialization:write-uint32-le s (length ordered))
       (loop for (txid . entry) in ordered
             for bytes = (tx-wire-bytes (mempool-entry-transaction entry))
             do (bitcoin-lisp.serialization:write-uint32-le s (length bytes))
                (write-sequence bytes s)
                (bitcoin-lisp.serialization:write-uint64-le s (mempool-entry-entry-time entry))
                (bitcoin-lisp.serialization:write-int64-le
                 s (gethash txid (mempool-deltas mempool) 0)))
       (bitcoin-lisp.serialization:write-uint32-le s (length residual))
       (loop for (txid . delta) in residual
             do (write-sequence txid s)
                (bitcoin-lisp.serialization:write-int64-le s delta))))
    (length ordered)))

(defun read-mempool-file (path)
  "Read a mempool.dat written by save-mempool-file. Returns
(values entries residual-deltas ok-p) where ENTRIES is a list of
(tx entry-time fee-delta) in file (parents-first) order and
RESIDUAL-DELTAS is an alist of (txid . delta). OK-P is NIL when the file
is missing, corrupt, or an unknown version — callers continue with an
empty mempool, like Core."
  (let ((data (bitcoin-lisp.storage:load-file-with-crc32 path 13)))
    (unless data
      (return-from read-mempool-file (values nil nil nil)))
    (handler-case
        ;; The byte-reader spans the full verified buffer; parsing reads
        ;; exactly the declared counts, so the trailing CRC bytes (already
        ;; checked by load-file-with-crc32) are simply never consumed.
        (let ((br (bitcoin-lisp.serialization:make-byte-reader-from data)))
          (unless (and (= (bitcoin-lisp.serialization:br-read-u32-le br) +mempool-dat-magic+)
                       (= (bitcoin-lisp.serialization:br-read-u8 br) +mempool-dat-version+))
            (return-from read-mempool-file (values nil nil nil)))
          (let* ((count (bitcoin-lisp.serialization:br-read-u32-le br))
                 (entries
                   (loop repeat count
                         collect
                         (let* ((len (bitcoin-lisp.serialization:br-read-u32-le br))
                                (bytes (bitcoin-lisp.serialization:br-read-bytes br len))
                                (tx (bitcoin-lisp.serialization:br-read-transaction
                                     (bitcoin-lisp.serialization:make-byte-reader-from bytes)))
                                (entry-time (bitcoin-lisp.serialization:br-read-u64-le br))
                                (delta (bitcoin-lisp.serialization:br-read-i64-le br)))
                           (list tx entry-time delta))))
                 (residual
                   (loop repeat (bitcoin-lisp.serialization:br-read-u32-le br)
                         collect (cons (bitcoin-lisp.serialization:br-read-bytes br 32)
                                       (bitcoin-lisp.serialization:br-read-i64-le br)))))
            (values entries residual t)))
      (error () (values nil nil nil)))))

;;;; Eviction

(defun mempool-evict-for-size (mempool needed-bytes new-entry-fee-rate)
  "Evict transactions to free NEEDED-BYTES of space, lowest descendant-package
fee-rate first (so a high-fee child protects its low-fee parent — CPFP), and
remove each evictee together with its descendants. Only evicts packages whose
fee-rate is below NEW-ENTRY-FEE-RATE. Returns T if enough space was freed."
  (let ((to-free (- (+ (mempool-total-size mempool) needed-bytes)
                     (mempool-max-size mempool))))
    (when (<= to-free 0)
      (return-from mempool-evict-for-size t))

    ;; Rank every entry by its descendant-package fee-rate, ascending.
    (let ((ranked '()))
      (maphash (lambda (txid entry)
                 (declare (ignore entry))
                 (push (cons txid (mempool-descendant-fee-rate mempool txid)) ranked))
               (mempool-entries mempool))
      (setf ranked (sort ranked #'< :key #'cdr))

      (let ((freed 0) (max-evicted-rate 0) (done nil))
        (dolist (pair ranked)
          (when (or done (>= freed to-free)) (return))
          (cond
            ;; Never evict a package that pays at least as much as the incoming tx.
            ((>= (cdr pair) new-entry-fee-rate) (setf done t))
            ;; May already be gone if removed as a descendant of an earlier evictee.
            ((mempool-has mempool (car pair))
             (let ((before (mempool-total-size mempool)))
               (mempool-remove-recursive mempool (car pair))
               (incf freed (- before (mempool-total-size mempool)))
               (setf max-evicted-rate (max max-evicted-rate (cdr pair)))))))
        ;; Raise the rolling minimum fee (sat/kvB) to the priciest evicted
        ;; package's feerate plus the incremental relay fee, so newcomers must
        ;; beat what was just trimmed (Core TrimToSize: maxFeeRateRemoved =
        ;; evicted feerate + incrementalRelayFee). MAX-EVICTED-RATE is sat/vB.
        (when (plusp max-evicted-rate)
          (let ((floor-rate (+ (ceiling (* max-evicted-rate 1000))
                               +incremental-relay-fee-rate+)))
            (when (> floor-rate (mempool-rolling-min-fee-rate mempool))
              (setf (mempool-rolling-min-fee-rate mempool) floor-rate
                    (mempool-rolling-min-fee-time mempool)
                    (bitcoin-lisp.serialization:get-unix-time)))))
        (>= freed to-free)))))

;;;; Expiry and periodic trim

(defun mempool-expire (mempool &optional (now (bitcoin-lisp.serialization:get-unix-time)))
  "Remove transactions (and their descendants) older than the expiry window.
Returns the number of transactions removed."
  (let ((cutoff (- now (* +default-mempool-expiry-hours+ 3600)))
        (stale '())
        (removed 0))
    (maphash (lambda (txid entry)
               (when (< (mempool-entry-entry-time entry) cutoff)
                 (push txid stale)))
             (mempool-entries mempool))
    (dolist (txid stale removed)
      ;; A stale tx may already be gone (removed as a descendant of another).
      (when (mempool-has mempool txid)
        (incf removed (mempool-remove-recursive mempool txid))))))

(defun mempool-trim (mempool)
  "Evict lowest-package-feerate transactions until the mempool is within its
size cap. Returns T (no-op when already under the cap)."
  (mempool-evict-for-size mempool 0 most-positive-fixnum))

;;;; Block interaction

(defun mempool-remove-for-block (mempool block)
  "Remove transactions confirmed in BLOCK from the mempool.
Also removes any transactions that conflict with block transactions,
together with their in-mempool descendants (Core removeForBlock ->
removeConflicts -> removeRecursive, txmempool.cpp:388-424: a conflicted
tx's descendants spend outputs that no longer exist)."
  (%with-graph-verify-batch (mempool)
    (let ((block-outpoints (make-hash-table :test 'equalp)))
      ;; Collect all outpoints spent by block transactions
      (dolist (tx (bitcoin-lisp.serialization:bitcoin-block-transactions block))
        (bitcoin-lisp.serialization:dovector (input (bitcoin-lisp.serialization:transaction-inputs tx))
          (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
                 (key (make-outpoint-key
                       (bitcoin-lisp.serialization:outpoint-hash prevout)
                       (bitcoin-lisp.serialization:outpoint-index prevout))))
            (setf (gethash key block-outpoints) t))))

      ;; Remove confirmed transactions; a mined tx's prioritisation delta is
      ;; spent ballast (Core removeForBlock -> ClearPrioritisation).
      (dolist (tx (bitcoin-lisp.serialization:bitcoin-block-transactions block))
        (let ((txid (bitcoin-lisp.serialization:transaction-hash tx)))
          (remhash txid (mempool-deltas mempool))
          (mempool-remove mempool txid)))

      ;; Remove conflicting transactions (mempool txs that spend same outpoints
      ;; as block txs), recursively: their descendants are conflicted too.
      (let ((to-remove '()))
        (maphash (lambda (outpoint-key spending-txid)
                   (when (gethash outpoint-key block-outpoints)
                     (pushnew spending-txid to-remove :test #'equalp)))
                 (mempool-spent-outpoints mempool))
        (dolist (txid to-remove)
          (mempool-remove-recursive mempool txid))))))

(defun mempool-get-transactions (mempool)
  "Return a list of all transactions in the mempool."
  (let ((txs '()))
    (maphash (lambda (txid entry)
               (declare (ignore txid))
               (push (mempool-entry-transaction entry) txs))
             (mempool-entries mempool))
    txs))

(defun mempool-for-each (mempool fn)
  "Call FN with (txid entry) for each transaction in the mempool.
   Used for building short ID maps in compact block reconstruction."
  (maphash fn (mempool-entries mempool)))
