(in-package #:bitcoin-lisp.mempool)

;;; Mempool - In-memory Transaction Pool
;;;
;;; Stores validated unconfirmed transactions. Indexed by txid with
;;; secondary index on spent outpoints for conflict detection.
;;; Enforces the byte cap by evicting the worst txgraph chunk (cluster
;;; mempool) and per-cluster count/size limits at acceptance.

;;;; Constants

(defconstant +default-max-mempool-bytes+ (* 300 1024 1024)
  "Default maximum mempool size in bytes (300 MB).")

(defconstant +default-min-relay-fee-rate+ 100
  "Default minimum relay fee rate in satoshis per kvB (Bitcoin Core
DEFAULT_MIN_RELAY_TX_FEE = 100 sat/kvB = 0.1 sat/vB). Was 1 sat/vB -- 10x
stricter than Core, rejecting the whole 0.1..1.0 sat/vB band Core relays; the
sat/kvB representation also makes fractional-sat/vB floors expressible.")

;; The historical 25/25 ancestor/descendant package limits (Core
;; DEFAULT_ANCESTOR_LIMIT / DEFAULT_DESCENDANT_LIMIT) are gone: since the
;; cluster-limit flip (P6), acceptance is bounded by the cluster limits
;; below, and ancestor/descendant stats are RPC-reporting-only (Core
;; deprecated -limitancestorcount et al., init.cpp:650-659).

(defvar *cluster-count-limit* +max-cluster-count+
  "Max number of transactions in a cluster (a connected component under the
spends-from relation). Core -limitclustercount (mempool_args.cpp:35), default
DEFAULT_CLUSTER_LIMIT = 64, hard-capped at MAX_CLUSTER_COUNT_LIMIT = 64
(mempool_args.cpp:110-112). Read at MAKE-MEMPOOL time (the graph's limits are
fixed at creation); set from config before the node's mempool is built.")

(defvar *cluster-size-limit* +max-cluster-size+
  "Max total vsize of a cluster, in SIGOP-ADJUSTED vbytes (entries carry the
adjusted size). Core -limitclustersize in kvB x 1000 (mempool_args.cpp:37),
default DEFAULT_CLUSTER_SIZE_LIMIT_KVB = 101; its txgraph limit is the same
101k scaled to adjusted WEIGHT (x4, txmempool.cpp:179-181), so ours matches
up to the per-tx ceiling in SIGOP-ADJUSTED-VSIZE. Core-exact 64/101k
defaults are non-negotiable for relay compatibility. Read at MAKE-MEMPOOL
time, like *CLUSTER-COUNT-LIMIT*.")

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
  ;; Sigop-adjusted virtual size (Core CTxMemPoolEntry::GetTxSize,
  ;; kernel/mempool_entry.h:110-113) — the basis for fee-rates, RBF economics,
  ;; TRUC caps, the cluster size limit, and the txgraph chunk feerates that
  ;; drive mining and eviction. Equals the BIP141 vsize except for sigop-dense
  ;; txs (see SIGOP-ADJUSTED-VSIZE).
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

(defconstant +bytes-per-sigop+ 20
  "Equivalent bytes charged per weighted sigop in the sigop-adjusted
transaction size (Bitcoin Core DEFAULT_BYTES_PER_SIGOP, policy.h:49; the
-bytespersigop knob is not exposed).")

(defun sigop-adjusted-vsize (weight sigops)
  "The sigop-adjusted virtual size: ceil(max(WEIGHT, SIGOPS * 20) / 4) —
Core GetVirtualTransactionSize (policy.cpp:376-384). This, not the raw
BIP141 vsize, is Core's mempool-entry size (CTxMemPoolEntry::GetTxSize):
it prices into the fee floor, RBF rules, TRUC caps, cluster limits, and
chunk feerates the transactions whose cost to the network is validation
work rather than bytes."
  (ceiling (max weight (* sigops +bytes-per-sigop+)) 4))

(defun make-entry-from-tx (tx fee height &key (sigops 0) (entry-time 0))
  "Build a mempool-entry from TX, computing the derived size/vsize/wtxid fields
(VSIZE is sigop-adjusted, so SIGOPS matters beyond the mining budget).
Centralizes entry construction so every acceptance path records the same
fields (handle-tx, sendrawtransaction, reorg re-add)."
  (make-mempool-entry
   :transaction tx
   :fee fee
   :modified-fee fee
   :size (length (bitcoin-lisp.serialization:transaction-wire-bytes tx))
   :vsize (sigop-adjusted-vsize (bitcoin-lisp.serialization:transaction-weight tx)
                                sigops)
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
  ;; The cluster/chunk engine (Core TxGraph), maintained in lockstep with
  ;; ENTRIES on every mutation. AUTHORITATIVE since the P4-P6 flips for
  ;; mining (chunk-walk block builder), eviction (worst-chunk trim), and the
  ;; acceptance limits (64 tx / 101 kvB per cluster, enforced in MEMPOOL-ADD,
  ;; so the graph never stays oversized). RBF economics flip in P7. The BFS
  ;; parent/child machinery remains for RPC ancestor/descendant reporting,
  ;; TRUC topology checks, and mempool.dat ordering, with the P3 shadow
  ;; equivalence asserts as the standing safety net.
  (graph (make-txgraph :max-cluster-count *cluster-count-limit*
                       :max-cluster-size *cluster-size-limit*
                       :fallback-order #'%graph-txid-order)
         :type txgraph))

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

;;;; Shadow txgraph checks (cluster mempool P3, kept through the P4-P6 flips)
;;;;
;;;; Every mutation path mirrors into the txgraph, and since P4-P6 the graph
;;;; is authoritative for mining, eviction, and the acceptance limits. The
;;;; BFS parent/child machinery remains for RPC reporting, TRUC checks, and
;;;; persistence ordering; these equivalence checks stay on as the safety
;;;; net proving the two views agree until the remaining flips (P7 RBF, P8
;;;; reorg bulk re-add) retire the BFS side.

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
ancestors) and the BFS links (severed) legitimately differ, and the reorg
trim removes transactions from the graph before their mempool entries
follow (MEMPOOL-UPDATE-FOR-REORG), so ALL the checks - including the cheap
tx-count equality - only run at batch end.")

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
check is always on outside batches (O(1); logs a warning in production,
errors under *TXGRAPH-SHADOW-CHECKS*); the full equivalence checks run only
under *TXGRAPH-SHADOW-CHECKS* and outside removal batches. Inside a batch
everything is deferred to the batch-end verify."
  (let ((graph (mempool-graph mempool))
        (count (mempool-count mempool)))
    (unless (or *graph-verify-batch* (= (txgraph-tx-count graph) count))
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
they are reachable from each other). Bounded by the 64-tx cluster limit."
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
  "Ancestor-package fee rate: ancestor-fees / ancestor-vsize. The pre-cluster
mining score, reporting/diagnostic-only since mining flipped to txgraph
chunk feerates (P4)."
  (multiple-value-bind (count vsize fees) (mempool-ancestor-stats mempool txid)
    (declare (ignore count))
    (if (zerop vsize) 0 (/ fees vsize))))

(defun mempool-descendant-fee-rate (mempool txid)
  "Descendant-package fee rate: descendant-fees / descendant-vsize. The
pre-cluster eviction score, reporting/diagnostic-only since eviction flipped
to the txgraph's worst chunk (P5)."
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
a port of Core policy SingleTRUCChecks (truc_policy.cpp:171-264). VSIZE is TX's
virtual size; DIRECT-CONFLICTS the list of mempool txids it replaces (RBF).
Returns (values t NIL NIL) when acceptable, else (values NIL reason-keyword
sibling-txid-or-NIL).

Enforces: v3<->non-v3 spend inheritance (both directions); v3 tx <= 10000 vsize;
at most 1 unconfirmed ancestor and, for a child of an unconfirmed TRUC parent,
<= 1000 vsize and the parent having no other unconfirmed descendant (unless that
sibling is being replaced).

The third value mirrors Core's sibling-eviction escape hatch: on a
:truc-descendant-limit failure where eviction of the existing child can be
CONSIDERED — the parent has exactly one existing descendant and that sibling's
ancestor set is exactly {parent, itself} (Core truc_policy.cpp:250-252) — it is
that sibling's txid. The caller (validate-transaction-for-mempool, mirroring
Core PreChecks validation.cpp:950-970) may then treat the sibling as a
to-be-replaced conflict and re-run the RBF economics, instead of rejecting."
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
            ;; Sibling eviction is considerable only in the clean 1p1c shape:
            ;; the parent has exactly this one existing child and the child
            ;; has no relatives beyond the parent (Core: GetDescendantCount
            ;; (parent) == 2 && GetAncestorCount(sibling) == 2, ruling out
            ;; reorg-created multi-child / grandchild shapes).
            (let ((sibling (when (= 1 (hash-table-count descendants))
                             (loop for d being the hash-keys of descendants
                                   return d))))
              (return-from single-truc-checks
                (values nil :truc-descendant-limit
                        (when (and sibling
                                   (= 2 (mempool-ancestor-stats mempool sibling)))
                          sibling))))))))
    (values t nil)))

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
                                 (sigops 0) replaced defer-trim)
  "The shared tail of every mempool acceptance path (peer tx handler,
orphan cascade, sendrawtransaction, mempool.dat reload, reorg re-add,
submitpackage): evict the BIP125 REPLACED txids, build the entry for TX,
add it. Caller has already run validate-transaction-for-mempool and passes
the weighted SIGOPS cost it computed (Core threads the same value from
PreChecks into the entry, validation.cpp:924) — without it the block
assembler's sigop budget is vacuous. Returns (values result entry) where
RESULT is mempool-add's keyword. DEFER-TRIM is threaded to MEMPOOL-ADD
(reorg re-add, package submission)."
  (dolist (rt replaced)
    (mempool-remove-recursive mempool rt))
  (let ((entry (make-entry-from-tx tx (or fee 0) height
                                   :sigops sigops :entry-time entry-time)))
    (values (mempool-add mempool txid entry :defer-trim defer-trim)
            entry)))

(defun mempool-add (mempool txid entry &key defer-trim)
  "Add a transaction to the mempool.
Returns :ok on success, or a rejection keyword: :duplicate, :conflict,
:too-large-cluster (joining its in-mempool parents would form a cluster over
the 64-tx / 101-kvB limits, Core's \"too-large-cluster\",
validation.cpp:1020-1022), or :mempool-full (after adding, trimming back to
the byte cap evicted the new tx's own chunk as the worst,
validation.cpp:1394-1401).

DEFER-TRIM skips only the per-add byte-cap trim, for callers that admit
several transactions and re-limit ONCE afterwards — Core's guard is
`!package_submission && !bypass_limits` (validation.cpp:1393), the single
re-limit living at the end of MaybeUpdateMempoolForReorg (:387) for the
reorg re-add and of AcceptPackage (:1728) for package submission. The
cluster-limit rejection is NOT deferred: Core's CheckMemPoolPolicyLimits
runs unconditionally (validation.cpp:1338-1342)."
  ;; Check for duplicate
  (when (mempool-has mempool txid)
    (return-from mempool-add :duplicate))

  ;; Apply any pre-existing prioritisation delta (Core: ATMP ApplyDelta) so
  ;; eviction scoring and mining selection see the modified fee.
  (let ((delta (gethash txid (mempool-deltas mempool))))
    (when delta
      (incf (mempool-entry-modified-fee entry) delta)))

  ;; Check for conflicts
  (let ((conflict (mempool-check-conflict
                   mempool (mempool-entry-transaction entry))))
    (when conflict
      (return-from mempool-add :conflict)))

  (let ((parent-txids (mempool-find-parents
                       mempool (mempool-entry-transaction entry)))
        (graph (mempool-graph mempool)))
    ;; Stage into the txgraph first (Core ChangeSet::StageAddition +
    ;; ProcessDependencies, txmempool.cpp:1005-1071): the modified fee (the
    ;; delta was applied above; Core adds unmodified then SetTransactionFee -
    ;; one step here), the vsize, and a dependency per in-mempool parent.
    ;; Then enforce the cluster limits (Core CheckMemPoolPolicyLimits ->
    ;; IsOversized, validation.cpp:1020): a dependency whose merged cluster
    ;; would exceed the count/size limits is held pending and the graph
    ;; reports oversized - undo the staged addition and reject. A tx whose
    ;; own vsize exceeds the size limit is oversized the same way. The
    ;; historical 25/25 ancestor/descendant limits no longer reject; they
    ;; are RPC-reporting-only (Core init.cpp:650-659).
    (let ((handle (txgraph-add-transaction
                   graph (mempool-entry-modified-fee entry)
                   (mempool-entry-vsize entry))))
      (setf (tx-handle-data handle) txid)
      (dolist (p parent-txids)
        (txgraph-add-dependency
         graph (mempool-entry-graph-handle (mempool-get mempool p)) handle))
      (when (txgraph-oversized-p graph)
        (txgraph-remove-transaction graph handle)
        (return-from mempool-add :too-large-cluster))
      (setf (mempool-entry-graph-handle entry) handle))

    ;; Add to entries table
    (setf (gethash txid (mempool-entries mempool)) entry)

    ;; Wire up ancestor/descendant links to in-mempool parents.
    (%link-entry-parents mempool txid entry parent-txids))

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
  (%mempool-graph-verify mempool)

  ;; Trim back to the byte cap now that the tx is in (Core FinalizeSubpackage
  ;; then LimitMempoolSize, validation.cpp:1394-1401): the new tx competes as
  ;; part of its own cluster's chunks, and if its chunk is the worst it
  ;; evicts itself - that is the "mempool full" outcome, and the rolling
  ;; minimum fee has been raised past its feerate either way. Skipped under
  ;; DEFER-TRIM (see docstring).
  (when (and (not defer-trim)
             (> (mempool-total-size mempool) (mempool-max-size mempool)))
    (mempool-trim-to-size mempool)
    (unless (mempool-has mempool txid)
      (return-from mempool-add :mempool-full)))

  :ok)

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
  "Cluster-mempool rule 5: a replacement may conflict directly with at most
this many distinct CLUSTERS (Core MAX_REPLACEMENT_CANDIDATES, policy/rbf.h:26;
rbf.cpp:58-83 counts clusters, not transactions, since cluster mempool). The
old BIP125 meaning — at most 100 replaced transactions — is gone.")

(defparameter +max-rbf-gather-transactions+ 500
  "Cluster-mempool rule 5, second bound: the clusters a replacement conflicts
with may hold at most this many transactions in total (Core's GatherClusters
gather cap, txmempool.cpp:988-990), bounding the diagram-staging work.")

(defparameter +incremental-relay-fee-rate+ 100
  "Incremental relay fee in satoshis per kvB for BIP125 rule 4 (Bitcoin Core
DEFAULT_INCREMENTAL_RELAY_FEE = 100 sat/kvB = 0.1 sat/vB).")

(defvar *mempool-full-rbf* nil
  "Retained for RPC display only (Core's IsRBFOptIn survives solely to report
whether a tx signals BIP125 opt-in, rbf.cpp:24-56; getmempoolinfo.fullrbf).
The acceptance path is full-RBF UNCONDITIONALLY — signaling is not consulted
(validation.cpp:490), so this flag no longer gates replacement.")

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

(defun %rbf-entry-handles (mempool txids)
  "The live txgraph handles of the mempool entries named by TXIDS (a list or
a hash-set's keys), skipping any that are absent or handle-less."
  (let ((handles '()))
    (flet ((collect (txid)
             (let ((e (mempool-get mempool txid)))
               (when (and e (mempool-entry-graph-handle e))
                 (push (mempool-entry-graph-handle e) handles)))))
      (if (hash-table-p txids)
          (maphash (lambda (k v) (declare (ignore v)) (collect k)) txids)
          (dolist (k txids) (collect k))))
    handles))

(defun %rbf-replaced-set (mempool direct-conflicts)
  "The full set a replacement of DIRECT-CONFLICTS evicts, as a txid hash-set:
each conflict and all its in-mempool descendants (Core GetEntriesForConflicts
-> CalculateDescendants)."
  (let ((replaced (make-hash-table :test 'equalp)))
    (dolist (ctxid direct-conflicts replaced)
      (setf (gethash ctxid replaced) t)
      (maphash (lambda (d v) (declare (ignore v)) (setf (gethash d replaced) t))
               (mempool-descendants mempool ctxid)))))

(defun %rbf-cluster-caps (mempool direct-conflicts)
  "Rule 5 (redefined for cluster mempool, Core rbf.cpp:58-83 +
txmempool.cpp:988-990): NIL when DIRECT-CONFLICTS touch at most 100 distinct
CLUSTERS together holding at most 500 transactions (the GatherClusters gather
cap that bounds the diagram-staging work), else the rejection keyword."
  (let ((graph (mempool-graph mempool))
        (conflict-handles (%rbf-entry-handles mempool direct-conflicts)))
    (cond ((> (txgraph-count-distinct-clusters graph conflict-handles)
              +max-rbf-replacement-candidates+)
           :too-many-clusters)
          ((> (txgraph-cluster-transaction-count graph conflict-handles)
              +max-rbf-gather-transactions+)
           :too-many-replacements))))

(defun %rbf-replaced-fees (mempool replaced)
  "Total prioritisation-modified fees of the REPLACED txid hash-set's entries."
  (let ((orig-fees 0))
    (maphash (lambda (txid v) (declare (ignore v))
               (let ((e (mempool-get mempool txid)))
                 (when e (incf orig-fees (mempool-entry-modified-fee e)))))
             replaced)
    orig-fees))

(defun %rbf-pays-for-rbf-p (orig-fees new-fee new-vsize)
  "Rules 3 and 4 (Core PaysForRBF, rbf.cpp:106-123): the replacement must pay
at least the total fee of what it replaces (rule 3) PLUS its own bandwidth at
the incremental relay fee rate — 0.1 sat/vB, not the 1 sat/vB relay floor
(rule 4)."
  (and (>= new-fee orig-fees)
       (>= (- new-fee orig-fees)
           (ceiling (* new-vsize +incremental-relay-fee-rate+) 1000))))

(defun %rbf-diagram-verdict (old-diagram new-diagram)
  "The economic verdict on a staged replacement's before/after diagrams:
NIL when NEW strictly improves OLD, :too-large-cluster when the staging was
uncalculable (an over-limit cluster, Core CheckMemPoolPolicyLimits failing
before the diagram, validation.cpp:1020-1022), else :replacement-failed
(Core ImprovesFeerateDiagram failure, rbf.cpp:136-138)."
  (cond ((eq old-diagram :uncalculable) :too-large-cluster)
        ((not (eq (compare-chunks new-diagram old-diagram) :greater))
         :replacement-failed)))

(defun check-rbf-rules (mempool tx new-fee new-vsize direct-conflicts)
  "Apply the cluster-mempool replacement rules for TX (paying NEW-FEE — the
prioritisation-MODIFIED fee, like the replaced entries' fees below — over
NEW-VSIZE) against DIRECT-CONFLICTS (a list of directly-conflicting mempool
txids). Returns (values ok-p reason replaced-set), where REPLACED-SET is a
hash-set of all txids that would be evicted (the conflicts plus their
descendants).

Full-RBF is UNCONDITIONAL: BIP125 rules 1 (signaling) and 2 (no new
unconfirmed inputs) are gone from node policy (Core validation.cpp:490;
rules 1/2 are wallet/RPC-only now). Rules 3 and 4 survive; rule 5 is redefined
in terms of clusters; and the old feerate-superiority test
(PaysMoreThanConflicts) is replaced by the feerate-diagram improvement check
(Core ReplacementChecks, validation.cpp:981-1032)."
  (let ((graph (mempool-graph mempool))
        (replaced (%rbf-replaced-set mempool direct-conflicts)))
    ;; Rule 5.
    (let ((cap-failure (%rbf-cluster-caps mempool direct-conflicts)))
      (when cap-failure
        (return-from check-rbf-rules (values nil cap-failure nil))))
    ;; A replacement must not spend an output of any tx it replaces (Core
    ;; EntriesAndTxidsDisjoint, rbf.cpp:85-98) — that would leave a dangling
    ;; input after the replaced set is evicted. (This is NOT old rule 2, which
    ;; is gone; it only forbids depending on the very txs being removed.)
    (bitcoin-lisp.serialization:dovector (in (bitcoin-lisp.serialization:transaction-inputs tx))
      (when (gethash (bitcoin-lisp.serialization:outpoint-hash
                      (bitcoin-lisp.serialization:tx-in-previous-output in))
                     replaced)
        (return-from check-rbf-rules (values nil :spends-conflicting-tx nil))))
    ;; Rules 3 and 4 against the total fees of everything being replaced.
    (unless (%rbf-pays-for-rbf-p (%rbf-replaced-fees mempool replaced)
                                 new-fee new-vsize)
      (return-from check-rbf-rules (values nil :insufficient-fee nil)))
    ;; Economic test (Core ImprovesFeerateDiagram, rbf.cpp:127-140): the
    ;; replacement must STRICTLY improve the mempool's feerate diagram. Stage
    ;; the removal of the replaced set and the addition of the candidate in a
    ;; scratch copy of the affected clusters, compute the before/after diagrams,
    ;; and require is_gt(CompareChunks(new, old)).
    (let ((removed-handles (%rbf-entry-handles mempool replaced))
          (parent-handles (%rbf-entry-handles
                           mempool (mempool-find-parents mempool tx))))
      (multiple-value-bind (old-diagram new-diagram)
          (txgraph-rbf-diagrams graph removed-handles parent-handles
                                new-fee new-vsize)
        (let ((verdict (%rbf-diagram-verdict old-diagram new-diagram)))
          (when verdict
            (return-from check-rbf-rules (values nil verdict nil))))))
    (values t nil replaced)))

(defun check-package-rbf-rules (mempool parent-fee parent-vsize
                                child-fee child-vsize direct-conflicts)
  "Apply the package RBF rules for a 1-parent-1-child package whose members
conflict with mempool transactions (Core PackageRBFChecks,
validation.cpp:1034-1130). PARENT-FEE/CHILD-FEE are the prioritisation-
modified fees; DIRECT-CONFLICTS the aggregated directly-conflicting mempool
txids of BOTH package members. Returns (values ok-p reason replaced-set)
like CHECK-RBF-RULES.

The caller enforces Core's shape preconditions first: exactly 2 transactions
forming child-with-parents (validation.cpp:1047-1050) and NO in-mempool
ancestors for either (validation.cpp:1052-1064, keeping the resulting
cluster <= 2) — the latter also makes the single-RBF spends-conflicting-tx
check vacuous here (a package member cannot spend any mempool output at
all). On top of the single-RBF anti-DoS rules evaluated against the PACKAGE
totals, the package feerate must STRICTLY exceed the parent's own feerate
(validation.cpp:1104-1111: the pair must be a chunk on its own — the child
must not merely pay anti-DoS fees), and the diagram test stages BOTH package
transactions (validation.cpp:1113-1121)."
  (let ((graph (mempool-graph mempool))
        (replaced (%rbf-replaced-set mempool direct-conflicts))
        (total-fee (+ parent-fee child-fee))
        (total-vsize (+ parent-vsize child-vsize)))
    ;; Rule 5, on the aggregate conflict set ("this limit is not increased in
    ;; a package RBF", validation.cpp:1076-1082).
    (let ((cap-failure (%rbf-cluster-caps mempool direct-conflicts)))
      (when cap-failure
        (return-from check-package-rbf-rules (values nil cap-failure nil))))
    ;; Rules 3 and 4 on the package totals (validation.cpp:1092-1099).
    (unless (%rbf-pays-for-rbf-p (%rbf-replaced-fees mempool replaced)
                                 total-fee total-vsize)
      (return-from check-package-rbf-rules (values nil :insufficient-fee nil)))
    ;; Package feerate must strictly exceed the parent feerate. Core compares
    ;; CFeeRate objects, whose sat/kvB value is the C++-truncated division
    ;; fee*1000/size (validation.cpp:1104-1111).
    (when (<= (truncate (* total-fee 1000) total-vsize)
              (truncate (* parent-fee 1000) parent-vsize))
      (return-from check-package-rbf-rules
        (values nil :package-feerate-not-above-parent nil)))
    ;; Economic test: stage the removal of the replaced set and the addition
    ;; of BOTH package transactions, then require a strict diagram improvement
    ;; (Core CheckMemPoolPolicyLimits + ImprovesFeerateDiagram over the
    ;; two-transaction changeset, validation.cpp:1113-1121).
    (multiple-value-bind (old-diagram new-diagram)
        (txgraph-package-rbf-diagrams graph (%rbf-entry-handles mempool replaced)
                                      parent-fee parent-vsize
                                      child-fee child-vsize)
      (let ((verdict (%rbf-diagram-verdict old-diagram new-diagram)))
        (when verdict
          (return-from check-package-rbf-rules (values nil verdict nil)))))
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
             for bytes = (bitcoin-lisp.serialization:transaction-wire-bytes
                          (mempool-entry-transaction entry))
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

(defun mempool-trim-to-size (mempool &optional (limit (mempool-max-size mempool)))
  "Evict the globally worst chunk - the lowest-chunk-feerate tail of the
mining order - repeatedly until the mempool's total size is within LIMIT
(Core TrimToSize, txmempool.cpp:861-911). A high-fee child still protects
its low-fee parent (CPFP): they share a chunk, evicted only as a unit. Each
evicted chunk raises the rolling minimum fee (sat/kvB) to its feerate plus
the incremental relay fee, so newcomers must beat what was just trimmed
(Core trackPackageRemoved). Returns the number of transactions removed."
  (let ((graph (mempool-graph mempool))
        (removed 0))
    (%with-graph-verify-batch (mempool)
      (loop while (and (plusp (mempool-count mempool))
                       (> (mempool-total-size mempool) limit))
            do (multiple-value-bind (handles feerate)
                   (txgraph-get-worst-main-chunk graph)
                 ;; Feerate in sat/kvB, truncating like Core's
                 ;; CFeeRate(fee, size) constructor, plus the incremental
                 ;; relay fee (txmempool.cpp:870-878).
                 (let ((rate (+ (truncate (* (feefrac-fee feerate) 1000)
                                          (feefrac-size feerate))
                                +incremental-relay-fee-rate+)))
                   (when (> rate (mempool-rolling-min-fee-rate mempool))
                     (setf (mempool-rolling-min-fee-rate mempool) rate
                           (mempool-rolling-min-fee-time mempool)
                           (bitcoin-lisp.serialization:get-unix-time))))
                 ;; The worst chunk is the tail of its own cluster's
                 ;; linearization, so it contains every in-mempool descendant
                 ;; of its members: removing its transactions (delivered
                 ;; children-first, reverse-topological) leaves nothing
                 ;; dangling and needs no recursion (Core removeUnchecked
                 ;; per chunk member).
                 (dolist (h handles)
                   (when (mempool-remove mempool (tx-handle-data h))
                     (incf removed))))))
    removed))

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

(defun mempool-remove-spenders (mempool txid n-outputs)
  "Remove, with their descendants, any mempool transactions spending an output
of TXID — a transaction NOT itself in the pool (Core removeRecursive's
not-in-mempool branch, txmempool.cpp:333-359: \"this can happen during chain
re-orgs if origTx isn't re-accepted into the mempool\"). N-OUTPUTS is TXID's
output count. Used by the reorg re-add path when a disconnected transaction
fails re-acceptance: its in-pool spenders' inputs no longer exist anywhere.
Returns the number of transactions removed."
  (let ((removed 0))
    (dotimes (i n-outputs removed)
      (let ((spender (mempool-spending-tx mempool txid i)))
        (when spender
          (incf removed (mempool-remove-recursive mempool spender)))))))

(defun mempool-update-for-reorg (mempool readded-txids)
  "After a reorg's disconnected transactions have been re-accepted one by one,
repair the whole-pool state in ONE batch (Core UpdateTransactionsFromBlock,
txmempool.cpp:91-120, called from MaybeUpdateMempoolForReorg): acceptance
assumes a new entry has no in-mempool children, which is false for a
previously-confirmed transaction whose outputs pre-existing pool entries
spend, so wire those parent->child links (BFS links + a txgraph dependency
per spender), then restore the cluster limits with a single TXGRAPH-TRIM —
the dependency merges are what can push clusters over 64 tx / 101 kvB, and
batching them here (instead of re-clustering per re-add) is the point of the
bulk flow. READDED-TXIDS is most-recently-confirmed first (Core iterates
vHashUpdate in reverse). Returns the number of transactions the trim evicted."
  (%with-graph-verify-batch (mempool)
    (let ((graph (mempool-graph mempool))
          (deps '()))
      (dolist (txid readded-txids)
        (let ((entry (mempool-get mempool txid)))
          (when entry
            (dotimes (i (length (bitcoin-lisp.serialization:transaction-outputs
                                 (mempool-entry-transaction entry))))
              (let* ((child-txid (mempool-spending-tx mempool txid i))
                     (child (and child-txid (mempool-get mempool child-txid))))
                (when child
                  (%link-entry-parents mempool child-txid child (list txid))
                  (push (cons (mempool-entry-graph-handle entry)
                              (mempool-entry-graph-handle child))
                        deps)))))))
      ;; All graph dependencies in one resolve pass (one union-find and one
      ;; merge + relinearization per connected group), not per pair.
      (txgraph-add-dependencies graph deps)
      ;; One trim (Core m_txgraph->Trim(), txmempool.cpp:115): drops whole
      ;; would-be-descendant subtrees from every over-limit would-be cluster,
      ;; keeping the best chunks. The removed set is descendant-closed, so
      ;; plain per-tx removal leaves nothing dangling.
      (let ((evicted 0))
        (dolist (handle (txgraph-trim graph) evicted)
          (when (mempool-remove mempool (tx-handle-data handle))
            (incf evicted)))))))

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
