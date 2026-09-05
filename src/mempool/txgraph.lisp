(in-package #:bitcoin-lisp.mempool)

;;; TxGraph - cluster registry with a mining-ordered chunk index
;;;
;;; Port of the CONTRACT of Bitcoin Core src/txgraph.{h,cpp}: fees, sizes and
;;; dependencies for a set of transactions, maintained as clusters (connected
;;; components under the spends-from relation), each with a linearization
;;; chopped into chunks, plus one global mining-ordered index over all chunks
;;; of all clusters. Bitcoin-agnostic, like Core's: no txids, no scripts -
;;; just fees, sizes and dependencies.
;;;
;;; Deviations from Core's implementation (the semantics are Core's):
;;;
;;; - EAGER, not lazy. Core queues removals/dependencies and drains them
;;;   through ApplyRemovals -> SplitAll -> GroupClusters -> Merge ->
;;;   ApplyDependencies with cost-budgeted relinearization (DoWork). We apply
;;;   every mutation immediately and relinearize the affected cluster(s) on
;;;   the spot (ancestor-set seeding + post-linearize; Core's budgeted SFL is
;;;   the P10 upgrade). The one thing that stays deferred - exactly as in
;;;   Core - is a dependency whose would-be merged cluster exceeds the
;;;   count/size limits: it is held in PENDING-DEPS and the graph reports
;;;   oversized until removals or TXGRAPH-TRIM make it applicable (or drop
;;;   it). The global chunk index is maintained INCREMENTALLY, as Core
;;;   maintains m_main_chunkindex: a mutation extracts only the chunks of
;;;   the clusters it touches and re-inserts their replacements.
;;;
;;; - HANDLES, not Refs. Core's TxGraph::Ref removes its transaction from
;;;   the graph in its destructor. Lisp has no destructors: every mempool
;;;   entry removal must explicitly call TXGRAPH-REMOVE-TRANSACTION. This is
;;;   the central mechanical discipline of the port; P3's shadow-mode asserts
;;;   exist to catch any missed removal path. Handles must only be used with
;;;   the graph that created them (asserted).
;;;
;;; - SINGLE GRAPH. Core keeps "main" and an optional "staging" overlay;
;;;   staging (start/abort/commit + GetMainStagingDiagrams) is P7. All state
;;;   lives behind the TXGRAPH struct (no globals), so the staging overlay
;;;   can scratch-copy affected clusters without changing any caller.
;;;
;;; - OVERSIZED contract (txgraph.h:122-127): while the graph is oversized
;;;   (a would-be cluster exceeds the limits, or a single transaction alone
;;;   exceeds the size limit), the ancestry/cluster/ordering queries and the
;;;   chunk-index consumers are unavailable - Core Assumes, we assert.
;;;   Always available: the mutators, TXGRAPH-EXISTS-P, TXGRAPH-TX-COUNT,
;;;   TXGRAPH-GET-INDIVIDUAL-FEERATE, TXGRAPH-OVERSIZED-P and TXGRAPH-TRIM.
;;;
;;; - MAKE-TXGRAPH takes no acceptable-cost: with no lazy work queue there
;;;   is no linearization cost budget to configure.

(defconstant +max-cluster-size+ 101000
  "Maximum sum of transaction sizes in a cluster, in virtual bytes (Core
-limitclustersize default DEFAULT_CLUSTER_SIZE_LIMIT_KVB = 101 kvB,
policy/policy.h). Non-negotiable for future relay compatibility.")

;;;; Handles

(defstruct (tx-handle (:constructor %make-tx-handle (graph id data)))
  "A transaction within a TXGRAPH (Core TxGraph::Ref, txgraph.h:232-253,
plus its Entry, txgraph.cpp:602-625). Callers hold these and pass them back
to the txgraph API; all slots except ID are graph-managed. There is no
destructor: the holder must call TXGRAPH-REMOVE-TRANSACTION explicitly."
  (graph nil :read-only t)
  ;; Creation sequence number; basis of the default fallback order.
  (id 0 :type fixnum :read-only t)
  ;; Opaque caller slot, ignored by the graph itself but read by the
  ;; FALLBACK-ORDER callback. Core's mempool entry IS its handle
  ;; (CTxMemPoolEntry : public TxGraph::Ref, kernel/mempool_entry.h:65), so
  ;; the fallback order can reach entry data; our mempool stores the entry's
  ;; txid here for its txid fallback order and the P3 shadow checks. It is
  ;; supplied to TXGRAPH-ADD-TRANSACTION, not assigned afterwards: the
  ;; transaction's chunk enters the mining index before that call returns,
  ;; and comparing it against an existing chunk of another cluster calls the
  ;; fallback order (Core Assumes m_ref != nullptr in CreateChunkData,
  ;; txgraph.cpp:894-896).
  (data nil)
  ;; Cluster this transaction is in; NIL = removed (Core Locator).
  (cluster nil)
  ;; Position in the cluster's depgraph.
  (pos 0 :type (integer 0 63))
  ;; Position in the cluster's linearization (Core m_main_lin_index).
  (lin-index 0 :type fixnum)
  ;; Feerate of the chunk this transaction is in (Core m_main_chunk_feerate).
  ;; Shared with the cluster's chunk object; do not mutate.
  (chunk-feerate nil)
  ;; Sum of the sizes of the chunks in this cluster with feerate equal to
  ;; this chunk's, up to and including it (Core
  ;; m_main_equal_feerate_chunk_prefix_size, txgraph.cpp:613-619).
  (chunk-prefix-size 0 :type fixnum)
  ;; The maximal transaction of this chunk per the graph's fallback order
  ;; (Core m_main_max_chunk_fallback).
  (chunk-fallback nil))

(defmethod print-object ((h tx-handle) stream)
  (print-unreadable-object (h stream :type t)
    (format stream "~D~:[ removed~;~]" (tx-handle-id h) (tx-handle-cluster h))))

(defun %tx-handle-id-order (a b)
  "Default fallback order: handle creation sequence. Core's mempool passes
txid ordering here (txmempool.cpp:183-187); the mempool's shadow graph does
the same via %GRAPH-TXID-ORDER (mempool.lisp)."
  (signum (- (tx-handle-id a) (tx-handle-id b))))

;;;; Clusters and chunks

(defstruct (%chunk (:constructor %make-chunk (txs feerate)))
  "One chunk of a cluster's linearization (Core ChunkData, txgraph.cpp:468)."
  (txs #() :type simple-vector)          ; handles in linearization order
  (feerate nil))

(declaim (inline %chunk-end))
(defun %chunk-end (chunk)
  "The chunk's last transaction, which represents it in the chunk index."
  (let ((txs (%chunk-txs chunk)))
    (svref txs (1- (length txs)))))

(defstruct (%cluster (:constructor %make-cluster (sequence)))
  "A connected component of the graph (Core Cluster, txgraph.cpp:101+)."
  ;; Unique creation sequence (Core m_sequence): deterministic ordering.
  (sequence 0 :type unsigned-byte :read-only t)
  (depgraph (make-depgraph) :type depgraph)
  ;; Depgraph position -> handle (Core m_mapping). May be longer than the
  ;; position range; entries at hole positions are stale.
  (mapping #() :type simple-vector)
  ;; Simple-vector of depgraph positions (Core m_linearization).
  (linearization #() :type simple-vector)
  ;; Simple-vector of %CHUNK, in linearization order.
  (chunks #() :type simple-vector)
  ;; Total size of the member transactions.
  (tx-size 0 :type unsigned-byte))

(defmethod print-object ((c %cluster) stream)
  (print-unreadable-object (c stream :type t)
    (format stream "#~D (~D txs)"
            (%cluster-sequence c) (depgraph-tx-count (%cluster-depgraph c)))))

;;;; The mining-ordered chunk index (Core m_main_chunkindex)
;;;;
;;;; One node per chunk of every cluster, ordered by the mining comparator
;;;; %COMPARE-MAIN applied to the chunk's last transaction (Core's ChunkData
;;;; and ChunkOrder, txgraph.cpp:466-547), maintained INCREMENTALLY: a
;;;; mutation extracts only the chunks of the clusters it touches and
;;;; re-inserts their replacements (Core ClearChunkData / CreateChunkData,
;;;; txgraph.cpp:881-900, driven from Cluster::Updated at
;;;; txgraph.cpp:1072-1146). Eviction then costs O(log C) per evicted chunk
;;;; instead of one sort of every chunk in the pool.
;;;;
;;;; Core's container is a std::set (a red-black tree); ours is a skiplist,
;;;; which gives the same O(log C) insert / erase / maximum and an O(C)
;;;; in-order walk with far less code. Node heights come from a per-index
;;;; xorshift64 stream rather than the global random state, so a graph's
;;;; internal shape is reproducible across runs; nothing observable depends
;;;; on it, because iteration order is decided by %COMPARE-MAIN alone. Keys
;;;; are unique - each %CHUNK has its own last transaction, and %COMPARE-MAIN
;;;; is a strong order over distinct handles - so a node is located by its
;;;; key, which is why a chunk must leave the index BEFORE anything changes
;;;; that key (%CLUSTER-CLEAR-CHUNK-DATA). TXGRAPH-SANITY-CHECK checks the
;;;; live index against %CHUNK-INDEX-FULL-REBUILD, the from-scratch
;;;; collect-and-sort this replaced, which stays as the correctness oracle.

(defconstant +chunk-index-max-level+ 24
  "Skiplist height cap. At p = 1/2 this indexes far more chunks than a 300 MB
mempool's ~312,000 without degrading (2^24 = 16.7 million).")

(defstruct (%ci-node (:constructor %make-ci-node (chunk next)))
  "One skiplist node: a %CHUNK plus one forward pointer per level. The head
node carries a NIL chunk and the maximum number of levels."
  (chunk nil)
  (next #() :type simple-vector))

(defstruct (%chunk-index (:constructor %make-chunk-index ()))
  "The mining-ordered index itself (Core's ChunkIndex, txgraph.cpp:545-547)."
  (head (%make-ci-node nil (make-array +chunk-index-max-level+
                                       :initial-element nil))
   :type %ci-node)
  ;; Scratch predecessor vector shared by insert and delete: the index is
  ;; only ever touched under the node lock, and neither operation re-enters.
  (preds (make-array +chunk-index-max-level+ :initial-element nil)
   :type simple-vector)
  (level 1 :type (integer 1 #.+chunk-index-max-level+))
  (count 0 :type unsigned-byte)
  ;; xorshift64 state for node heights; never zero.
  (rng-state #x2545F4914F6CDD1D :type (unsigned-byte 64)))

;;;; The graph

(defstruct (txgraph (:constructor %make-txgraph
                        (max-cluster-count max-cluster-size fallback-order)))
  "A transaction graph (Core TxGraphImpl, txgraph.cpp:390): the cluster
registry, the pending (unapplicable) dependencies, and the mining-ordered
chunk index. Create with MAKE-TXGRAPH."
  (max-cluster-count +max-cluster-count+ :type (integer 1 64) :read-only t)
  (max-cluster-size +max-cluster-size+ :type (integer 1) :read-only t)
  (fallback-order #'%tx-handle-id-order :type function :read-only t)
  ;; Registry of all clusters (keys; values are T).
  (clusters (make-hash-table :test 'eq) :type hash-table)
  ;; (parent-handle . child-handle) dependencies whose would-be merged
  ;; cluster exceeds the limits (Core m_deps_to_add; non-empty <=> some
  ;; group is oversized, because feasible groups are applied eagerly).
  (pending-deps '() :type list)
  (next-sequence 0 :type unsigned-byte)
  (next-id 0 :type fixnum)
  (tx-count 0 :type unsigned-byte)
  ;; Number of transactions whose own size exceeds MAX-CLUSTER-SIZE (Core
  ;; m_txcount_oversized).
  (oversized-tx-count 0 :type unsigned-byte)
  ;; Every cluster's %CHUNKs in mining order, maintained incrementally
  ;; (Core m_main_chunkindex).
  (chunk-index (%make-chunk-index) :type %chunk-index)
  ;; Active block builders (Core m_main_chunkindex_observers): mutations are
  ;; disallowed while any exist.
  (builder-count 0 :type unsigned-byte))

(defmethod print-object ((g txgraph) stream)
  (print-unreadable-object (g stream :type t)
    (format stream "~D txs, ~D clusters~:[~; OVERSIZED~]"
            (txgraph-tx-count g) (hash-table-count (txgraph-clusters g))
            (txgraph-oversized-p g))))

(defun make-txgraph (&key (max-cluster-count +max-cluster-count+)
                          (max-cluster-size +max-cluster-size+)
                          (fallback-order #'%tx-handle-id-order))
  "Create a transaction graph (Core MakeTxGraph, txgraph.cpp:3570-3581).
MAX-CLUSTER-COUNT (<= 64) and MAX-CLUSTER-SIZE bound each cluster;
FALLBACK-ORDER is a stable strong ordering (handle x handle -> -1/0/1) used
to break mining-order ties between equal-feerate chunks of distinct
clusters (Core's mempool uses txid order)."
  (assert (<= 1 max-cluster-count +max-cluster-count+))
  (assert (plusp max-cluster-size))
  (%make-txgraph max-cluster-count max-cluster-size fallback-order))

(defun txgraph-oversized-p (graph)
  "True when some connected component (including would-be components implied
by pending dependencies) exceeds the cluster limits, or a single transaction
alone exceeds the size limit (Core IsOversized, txgraph.cpp:2606-2624)."
  (or (plusp (txgraph-oversized-tx-count graph))
      (consp (txgraph-pending-deps graph))))

(defun txgraph-exists-p (graph handle)
  "True when HANDLE's transaction has not been removed (Core Exists).
Available even when oversized."
  (%check-handle graph handle)
  (and (tx-handle-cluster handle) t))

;;;; Internal helpers

(defun %check-handle (graph handle)
  (assert (eq (tx-handle-graph handle) graph) ()
          "txgraph: handle ~S belongs to a different graph" handle))

(defun %assert-no-builder (graph)
  (assert (zerop (txgraph-builder-count graph)) ()
          "txgraph: mutation while a block builder is active"))

(defun %assert-not-oversized (graph what)
  (assert (not (txgraph-oversized-p graph)) ()
          "txgraph: ~A is unavailable while the graph is oversized" what))

(defun %copy-depgraph (g)
  "Deep copy of depgraph G (entries and closures)."
  (let* ((new (make-depgraph))
         (entries (%depgraph-entries new)))
    (setf (%depgraph-used new) (%depgraph-used g))
    (loop for e across (%depgraph-entries g)
          do (vector-push-extend (%make-dg-entry (copy-feefrac (%dg-entry-feerate e))
                                                 (%dg-entry-ancestors e)
                                                 (%dg-entry-descendants e))
                                 entries))
    new))

(defun %graph-new-cluster (graph)
  (let ((cluster (%make-cluster (txgraph-next-sequence graph))))
    (incf (txgraph-next-sequence graph))
    (setf (gethash cluster (txgraph-clusters graph)) t)
    cluster))

(defun %positions-handles (cluster bits)
  "The handles at the positions of bitset BITS, ascending position order."
  (let ((mapping (%cluster-mapping cluster))
        (out '()))
    (do-bits (i bits) (push (aref mapping i) out))
    (nreverse out)))

(defun %compare-main (graph a b)
  "Mining-order comparison of handles A and B: -1 when A mines first (Core
CompareMainTransactions, txgraph.cpp:492-524). Keys: chunk feerate
descending; equal-feerate chunk prefix size ascending; for distinct
clusters the fallback order of the chunks' maximal elements; within a
chunk, linearization position."
  (if (eq a b)
      0
      (let ((feerate-cmp (feerate-compare (tx-handle-chunk-feerate b)
                                          (tx-handle-chunk-feerate a))))
        (cond ((not (zerop feerate-cmp)) feerate-cmp)
              ((/= (tx-handle-chunk-prefix-size a) (tx-handle-chunk-prefix-size b))
               (signum (- (tx-handle-chunk-prefix-size a)
                          (tx-handle-chunk-prefix-size b))))
              ((not (eq (tx-handle-cluster a) (tx-handle-cluster b)))
               (let ((c (funcall (txgraph-fallback-order graph)
                                 (tx-handle-chunk-fallback a)
                                 (tx-handle-chunk-fallback b))))
                 (if (zerop c)
                     ;; Unreachable with a strong fallback order
                     ;; (txgraph.cpp:518-520).
                     (signum (- (%cluster-sequence (tx-handle-cluster a))
                                (%cluster-sequence (tx-handle-cluster b))))
                     c)))
              (t (signum (- (tx-handle-lin-index a) (tx-handle-lin-index b))))))))

(defun %ci-random-level (index)
  "A node height drawn from INDEX's own xorshift64 stream: height L with
probability 2^-L, capped at +CHUNK-INDEX-MAX-LEVEL+."
  (let ((s (%chunk-index-rng-state index)))
    (setf s (logand #xFFFFFFFFFFFFFFFF (logxor s (ash s 13))))
    (setf s (logxor s (ash s -7)))
    (setf s (logand #xFFFFFFFFFFFFFFFF (logxor s (ash s 17))))
    (setf (%chunk-index-rng-state index) s)
    (let ((level 1))
      (loop while (and (< level +chunk-index-max-level+) (logbitp (1- level) s))
            do (incf level))
      level)))

(defun %ci-locate (graph index chunk)
  "Fill INDEX's scratch predecessor vector with the last node before CHUNK at
each live level, and return the level-0 node at CHUNK's position - the node
holding CHUNK when it is present, otherwise the first node after it, or NIL."
  (let ((preds (%chunk-index-preds index))
        (key (%chunk-end chunk))
        (node (%chunk-index-head index)))
    (loop for level from (1- (%chunk-index-level index)) downto 0
          do (loop for next = (svref (%ci-node-next node) level)
                   while (and next
                              (minusp (%compare-main
                                       graph
                                       (%chunk-end (%ci-node-chunk next))
                                       key)))
                   do (setf node next))
             (setf (svref preds level) node))
    (svref (%ci-node-next node) 0)))

(defun %ci-insert (graph index chunk)
  "Insert CHUNK at its mining-order position (Core CreateChunkData,
txgraph.cpp:891-900)."
  (%ci-locate graph index chunk)
  (let ((preds (%chunk-index-preds index))
        (level (%ci-random-level index)))
    (when (> level (%chunk-index-level index))
      (loop for l from (%chunk-index-level index) below level
            do (setf (svref preds l) (%chunk-index-head index)))
      (setf (%chunk-index-level index) level))
    (let ((node (%make-ci-node chunk (make-array level :initial-element nil))))
      (dotimes (l level)
        (setf (svref (%ci-node-next node) l)
              (svref (%ci-node-next (svref preds l)) l)
              (svref (%ci-node-next (svref preds l)) l)
              node))
      (incf (%chunk-index-count index))))
  (values))

(defun %ci-delete (graph index chunk)
  "Extract CHUNK from the index (Core ClearChunkData, txgraph.cpp:881-889).
CHUNK's mining key must be unchanged since it was inserted; that is what makes
the clear-before-mutating discipline below mandatory."
  (let ((node (%ci-locate graph index chunk))
        (preds (%chunk-index-preds index)))
    (assert (and node (eq (%ci-node-chunk node) chunk)) ()
            "txgraph: chunk index cannot find ~S - its mining key changed ~
before the chunk was cleared" chunk)
    (dotimes (l (length (%ci-node-next node)))
      (setf (svref (%ci-node-next (svref preds l)) l)
            (svref (%ci-node-next node) l)))
    (loop while (and (> (%chunk-index-level index) 1)
                     (null (svref (%ci-node-next (%chunk-index-head index))
                                  (1- (%chunk-index-level index)))))
          do (decf (%chunk-index-level index)))
    (decf (%chunk-index-count index)))
  (values))

(defun %ci-last (index)
  "The last chunk in mining order, or NIL when the index is empty (Core
m_main_chunkindex.rbegin(), txgraph.cpp:3262). The head node's NIL chunk is
the empty-index answer."
  (let ((node (%chunk-index-head index)))
    (loop for level from (1- (%chunk-index-level index)) downto 0
          do (loop for next = (svref (%ci-node-next node) level)
                   while next do (setf node next)))
    (%ci-node-chunk node)))

(defun %chunk-index-vector (graph)
  "Every chunk in mining order as a fresh simple-vector: one forward walk of
the index, no sort. Core's BlockBuilderImpl walks the same nodes through an
iterator; we materialize because BLOCK-BUILDER addresses chunks by position,
and mutation is forbidden while a builder exists either way."
  (let* ((index (txgraph-chunk-index graph))
         (out (make-array (%chunk-index-count index)))
         (i 0))
    (loop for node = (svref (%ci-node-next (%chunk-index-head index)) 0)
            then (svref (%ci-node-next node) 0)
          while node
          do (setf (svref out i) (%ci-node-chunk node))
             (incf i))
    (assert (= i (%chunk-index-count index)))
    out))

(defun %chunk-index-full-rebuild (graph)
  "The chunk index computed from scratch: every cluster's chunks collected and
sorted by %COMPARE-MAIN. This is what the index used to be recomputed by after
every mutation; it survives as the correctness oracle TXGRAPH-SANITY-CHECK
compares the incrementally maintained index against."
  (let ((entries '()))
    (loop for cluster being the hash-keys of (txgraph-clusters graph)
          do (loop for chunk across (%cluster-chunks cluster)
                   do (push chunk entries)))
    (sort (coerce entries 'simple-vector)
          (lambda (x y)
            (minusp (%compare-main graph (%chunk-end x) (%chunk-end y)))))))

(defun %cluster-clear-chunk-data (graph cluster)
  "Extract CLUSTER's chunks from the mining index (Core ClearChunkData over
the cluster's entries, txgraph.cpp:1055-1063). Must run BEFORE anything that
can change the mining key of one of CLUSTER's transactions - a
relinearization, a depgraph edit, or a re-pointing of its handles - because
the index locates a node by that key. Idempotent: CLUSTER is left with no
chunks."
  (let ((index (txgraph-chunk-index graph)))
    (loop for chunk across (%cluster-chunks cluster)
          do (%ci-delete graph index chunk)))
  (setf (%cluster-chunks cluster) #())
  (values))

(defun %cluster-create-chunk-data (graph cluster)
  "Insert CLUSTER's freshly computed chunks into the mining index (Core
CreateChunkData at the end of Cluster::Updated, txgraph.cpp:1139-1143). Every
member handle's cached mining data must already be current."
  (let ((index (txgraph-chunk-index graph)))
    (loop for chunk across (%cluster-chunks cluster)
          do (%ci-insert graph index chunk)))
  (values))

(defun %cluster-updated (graph cluster)
  "Relinearize CLUSTER and recompute its chunks and its handles' cached
mining-order data (Core Cluster::Updated, txgraph.cpp:1072-1146, done
eagerly in place of Relinearize/MakeAcceptable). CLUSTER's chunks leave the
mining index first and its new ones are inserted at the end, exactly as Core
brackets Cluster::Updated with ClearChunkData/CreateChunkData
(txgraph.cpp:1072-1146)."
  (%cluster-clear-chunk-data graph cluster)
  (let* ((dg (%cluster-depgraph cluster))
         (mapping (%cluster-mapping cluster))
         ;; Core hands Linearize a fallback order over DepGraph positions,
         ;; built by mapping each position back to its entry and deferring to
         ;; the graph's own comparator (txgraph.cpp:2165-2169). It decides the
         ;; order of equal-feerate chunks and of equal-feerate transactions
         ;; within a chunk, so it reaches the mining template.
         (lin (linearize dg
                         :fallback (let ((order (txgraph-fallback-order graph)))
                                     (lambda (a b)
                                       (funcall order (aref mapping a) (aref mapping b))))))
         (info (chunk-linearization-info dg lin))
         (chunks (make-array (length info)))
         (fallback (txgraph-fallback-order graph))
         (lin-index 0)
         (chunk-idx 0)
         ;; Running sum of the chunk feerates equal to the current chunk's,
         ;; restarted whenever the feerate strictly drops
         ;; (txgraph.cpp:1093-1109).
         (acc (make-feefrac))
         (total-size 0))
    (setf (%cluster-linearization cluster) lin)
    (dolist (si info)
      (let* ((feerate (setinfo-feerate si))
             (count (logcount (setinfo-transactions si)))
             (txs (make-array count))
             (max-h nil))
        (setf acc (if (feefrac<< feerate acc) (copy-feefrac feerate) (feefrac+ acc feerate)))
        (incf total-size (feefrac-size feerate))
        (loop for k from 0 below count
              for pos = (svref lin (+ lin-index k))
              for h = (aref mapping pos)
              do (setf (aref txs k) h)
                 (when (or (null max-h) (plusp (funcall fallback h max-h)))
                   (setf max-h h)))
        (loop for k from 0 below count
              for h = (svref txs k)
              do (setf (tx-handle-cluster h) cluster
                       (tx-handle-pos h) (svref lin (+ lin-index k))
                       (tx-handle-lin-index h) (+ lin-index k)
                       (tx-handle-chunk-feerate h) feerate
                       (tx-handle-chunk-prefix-size h) (feefrac-size acc)
                       (tx-handle-chunk-fallback h) max-h))
        (setf (svref chunks chunk-idx) (%make-chunk txs feerate))
        (incf lin-index count)
        (incf chunk-idx)))
    (setf (%cluster-chunks cluster) chunks
          (%cluster-tx-size cluster) total-size)
    (%cluster-create-chunk-data graph cluster)
    cluster))

;;;; Mutations

(defun txgraph-add-transaction (graph fee size &optional data)
  "Add a new transaction with the given fee (satoshis, may be negative) and
size (virtual bytes, > 0) and return its handle (Core AddTransaction,
txgraph.cpp:2230-2260). The transaction starts as a singleton cluster.

DATA is the handle's opaque caller payload (Core's Ref, which AddTransaction
binds before the Cluster is Updated). Pass it here rather than assigning it to
the returned handle: the new chunk joins the mining index before this call
returns, and ordering it against another cluster's chunk calls the graph's
FALLBACK-ORDER, which is what reads DATA."
  (%assert-no-builder graph)
  (assert (plusp size))
  (let ((handle (%make-tx-handle graph (txgraph-next-id graph) data))
        (cluster (%graph-new-cluster graph)))
    (incf (txgraph-next-id graph))
    (depgraph-add-transaction (%cluster-depgraph cluster) (make-feefrac fee size))
    (setf (%cluster-mapping cluster) (vector handle))
    (incf (txgraph-tx-count graph))
    (when (> size (txgraph-max-cluster-size graph))
      (incf (txgraph-oversized-tx-count graph)))
    (%cluster-updated graph cluster)
    handle))

(defun %split-cluster (graph cluster)
  "Re-establish CLUSTER's connected components after removals (Core Split,
txgraph.cpp:1439+): drop it if empty, keep it if still connected, otherwise
replace it with one masked copy per component."
  (let* ((dg (%cluster-depgraph cluster))
         (todo (depgraph-positions dg)))
    (cond ((zerop todo)
           (%cluster-clear-chunk-data graph cluster)
           (remhash cluster (txgraph-clusters graph)))
          ((depgraph-connected-p dg)
           (%cluster-updated graph cluster))
          (t
           (%cluster-clear-chunk-data graph cluster)
           (remhash cluster (txgraph-clusters graph))
           (loop until (zerop todo)
                 do (let* ((component (depgraph-find-connected-component dg todo))
                           (new (%graph-new-cluster graph))
                           (new-dg (%copy-depgraph dg)))
                      (depgraph-remove-transactions
                       new-dg (logandc2 (depgraph-positions dg) component))
                      (setf (%cluster-depgraph new) new-dg
                            (%cluster-mapping new) (copy-seq (%cluster-mapping cluster)))
                      (%cluster-updated graph new)
                      (setf todo (logandc2 todo component))))))))

(defun txgraph-remove-transaction (graph handle)
  "Remove HANDLE's transaction; a no-op if already removed (Core
RemoveTransaction, txgraph.cpp:2262-2279). Splits the cluster into connected
components (removal only masks the dependency closure, so a transaction
bridged by the removed one stays connected to its grandparents), drops
pending dependencies involving the transaction, and retries pending ones
that removals may have made applicable."
  (%check-handle graph handle)
  (%assert-no-builder graph)
  (let ((cluster (tx-handle-cluster handle)))
    (when cluster
      ;; The removal changes the mining keys of this cluster's transactions
      ;; (and unlinks HANDLE, which may be a chunk end), so its chunks leave
      ;; the index before anything else moves.
      (%cluster-clear-chunk-data graph cluster)
      (let* ((dg (%cluster-depgraph cluster))
             (pos (tx-handle-pos handle)))
        (when (> (feefrac-size (depgraph-tx-feerate dg pos))
                 (txgraph-max-cluster-size graph))
          (decf (txgraph-oversized-tx-count graph)))
        (depgraph-remove-transactions dg (ash 1 pos))
        (setf (tx-handle-cluster handle) nil)
        (decf (txgraph-tx-count graph))
        (%split-cluster graph cluster)
        (%resolve-pending graph))))
  (values))

(defun %pending-groups (graph &key include-oversized-singletons)
  "Partition the clusters referenced by pending dependencies into connected
groups by union-find (Core GroupClusters, txgraph.cpp:1856-2066), optionally
seeding a group for each individually-oversized singleton cluster (as Core
does for Trim, txgraph.cpp:1877-1886). Returns a list of (clusters deps
count size) with COUNT/SIZE the would-be merged totals."
  (let ((parent (make-hash-table :test 'eq)))
    (labels ((add (c)
               (unless (gethash c parent) (setf (gethash c parent) c)))
             (find-rep (c)
               (let ((p (gethash c parent)))
                 (if (eq p c)
                     c
                     (setf (gethash c parent) (find-rep p)))))
             (union! (a b)
               (let ((ra (find-rep a)) (rb (find-rep b)))
                 (unless (eq ra rb) (setf (gethash ra parent) rb)))))
      (dolist (dep (txgraph-pending-deps graph))
        (let ((pc (tx-handle-cluster (car dep)))
              (cc (tx-handle-cluster (cdr dep))))
          (add pc) (add cc) (union! pc cc)))
      (when include-oversized-singletons
        (loop for c being the hash-keys of (txgraph-clusters graph)
              when (and (= 1 (depgraph-tx-count (%cluster-depgraph c)))
                        (> (%cluster-tx-size c) (txgraph-max-cluster-size graph)))
                do (add c)))
      (let ((groups (make-hash-table :test 'eq))    ; rep -> (clusters . deps)
            (members '()))
        ;; Snapshot the keys first: FIND-REP's path compression writes into
        ;; PARENT, which is not allowed during traversal.
        (loop for c being the hash-keys of parent do (push c members))
        (dolist (c members)
          (let ((cell (or (gethash (find-rep c) groups)
                          (setf (gethash (find-rep c) groups) (cons '() '())))))
            (push c (car cell))))
        (dolist (dep (txgraph-pending-deps graph))
          (push dep (cdr (gethash (find-rep (tx-handle-cluster (car dep))) groups))))
        (loop for (clusters . deps) being the hash-values of groups
              collect (list clusters deps
                            (reduce #'+ clusters
                                    :key (lambda (c) (depgraph-tx-count (%cluster-depgraph c))))
                            (reduce #'+ clusters :key #'%cluster-tx-size)))))))

(defun %merge-group (graph clusters deps)
  "Merge CLUSTERS into one cluster, preserving each one's dependency
closure, then apply the (parent-handle . child-handle) DEPS (the eager
equivalent of Core Merge + Cluster::ApplyDependencies,
txgraph.cpp:2068-2155). The caller has checked the combined limits."
  ;; Every cluster in the group is about to have its transactions re-pointed
  ;; or relinearized, so all of their chunks leave the mining index first.
  (dolist (c clusters) (%cluster-clear-chunk-data graph c))
  (let ((target
          (if (rest clusters)
              (let* ((total (reduce #'+ clusters
                                    :key (lambda (c) (depgraph-tx-count (%cluster-depgraph c)))))
                     (new (%graph-new-cluster graph))
                     (dg (%cluster-depgraph new))
                     (mapping (make-array total)))
                ;; Copy the transactions.
                (dolist (old clusters)
                  (let ((old-dg (%cluster-depgraph old))
                        (old-map (%cluster-mapping old)))
                    (loop for pos across (%cluster-linearization old)
                          for h = (aref old-map pos)
                          for new-pos = (depgraph-add-transaction
                                         dg (depgraph-tx-feerate old-dg pos))
                          do (setf (aref mapping new-pos) h
                                   (tx-handle-cluster h) new
                                   (tx-handle-pos h) new-pos))))
                (setf (%cluster-mapping new) mapping)
                ;; Re-add each old cluster's internal dependencies (iterating
                ;; reduced parents reconstructs the closure exactly).
                (dolist (old clusters)
                  (let ((old-dg (%cluster-depgraph old))
                        (old-map (%cluster-mapping old)))
                    (do-bits (i (depgraph-positions old-dg))
                      (let ((parents 0))
                        (do-bits (p (depgraph-reduced-parents old-dg i))
                          (setf parents (logior parents (ash 1 (tx-handle-pos (aref old-map p))))))
                        (unless (zerop parents)
                          (depgraph-add-dependencies
                           dg parents (tx-handle-pos (aref old-map i))))))))
                (dolist (old clusters)
                  (remhash old (txgraph-clusters graph)))
                new)
              (first clusters))))
    (let ((dg (%cluster-depgraph target)))
      (dolist (dep deps)
        (depgraph-add-dependencies dg (ash 1 (tx-handle-pos (car dep)))
                                   (tx-handle-pos (cdr dep))))
      (assert (depgraph-acyclic-p dg) ()
              "txgraph: dependencies formed a cycle"))
    (%cluster-updated graph target)))

(defun %resolve-pending (graph)
  "Drop pending dependencies whose endpoints were removed, then eagerly
merge and apply every pending group whose combined totals fit within the
limits (Core GroupClusters + ApplyDependencies + Merge, run to completion
instead of lazily). Deps of over-limit groups stay pending, keeping the
graph oversized until removals or TXGRAPH-TRIM resolve them."
  (setf (txgraph-pending-deps graph)
        (delete-if (lambda (dep)
                     (or (null (tx-handle-cluster (car dep)))
                         (null (tx-handle-cluster (cdr dep)))))
                   (txgraph-pending-deps graph)))
  (when (txgraph-pending-deps graph)
    (let ((still-pending '()))
      (dolist (group (%pending-groups graph))
        (destructuring-bind (clusters deps count size) group
          (if (and (<= count (txgraph-max-cluster-count graph))
                   (<= size (txgraph-max-cluster-size graph)))
              (%merge-group graph clusters deps)
              (setf still-pending (nconc still-pending deps)))))
      (setf (txgraph-pending-deps graph) still-pending))))

(defun txgraph-add-dependency (graph parent child)
  "Make PARENT's transaction a parent of CHILD's (Core AddDependency,
txgraph.cpp:2281-2303). No-op when the two are the same, either is removed,
or PARENT is already an ancestor of CHILD. PARENT must not (transitively)
be a descendant of CHILD. If the merged cluster would exceed the limits the
dependency is held pending and the graph becomes oversized."
  (%check-handle graph parent)
  (%check-handle graph child)
  (%assert-no-builder graph)
  (let ((pc (tx-handle-cluster parent))
        (cc (tx-handle-cluster child)))
    (unless (or (null pc) (null cc) (eq parent child))
      (if (eq pc cc)
          (let ((dg (%cluster-depgraph pc))
                (ppos (tx-handle-pos parent))
                (cpos (tx-handle-pos child)))
            (assert (not (logbitp cpos (depgraph-ancestors dg ppos))) ()
                    "txgraph-add-dependency: parent is a descendant of child")
            (unless (logbitp ppos (depgraph-ancestors dg cpos))
              (depgraph-add-dependencies dg (ash 1 ppos) cpos)
              (%cluster-updated graph pc)))
          (progn
            (push (cons parent child) (txgraph-pending-deps graph))
            (%resolve-pending graph)))))
  (values))

(defun txgraph-add-dependencies (graph deps)
  "Bulk TXGRAPH-ADD-DEPENDENCY: queue every (parent-handle . child-handle)
pair in DEPS, then resolve them in ONE pass — one union-find grouping and
one merge + relinearization per connected group (%RESOLVE-PENDING), instead
of a merge per pair. This is the eager graph's analogue of Core's lazy
m_deps_to_add batching (AddDependency only queues; GroupClusters/Merge run
once in ApplyDependencies, txgraph.cpp:1856-2155), used by the reorg bulk
re-add. Pairs whose endpoints are removed or equal are skipped; groups that
would exceed the limits stay pending (graph oversized) until TXGRAPH-TRIM."
  (%assert-no-builder graph)
  (dolist (dep deps)
    (%check-handle graph (car dep))
    (%check-handle graph (cdr dep))
    (unless (or (eq (car dep) (cdr dep))
                (null (tx-handle-cluster (car dep)))
                (null (tx-handle-cluster (cdr dep))))
      (push (cons (car dep) (cdr dep)) (txgraph-pending-deps graph))))
  (%resolve-pending graph)
  (values))

(defun txgraph-set-transaction-fee (graph handle fee)
  "Change the fee of HANDLE's transaction and re-linearize its cluster; a
no-op if removed (Core SetTransactionFee, txgraph.cpp:2746-2760)."
  (%check-handle graph handle)
  (%assert-no-builder graph)
  (let ((cluster (tx-handle-cluster handle)))
    (when cluster
      (setf (feefrac-fee (depgraph-tx-feerate (%cluster-depgraph cluster)
                                              (tx-handle-pos handle)))
            fee)
      (%cluster-updated graph cluster)))
  (values))

;;;; Queries

(defun txgraph-get-individual-feerate (graph handle)
  "The transaction's own feefrac, or the empty feefrac if removed (Core
GetIndividualFeerate). Available even when oversized."
  (%check-handle graph handle)
  (let ((cluster (tx-handle-cluster handle)))
    (if cluster
        (copy-feefrac (depgraph-tx-feerate (%cluster-depgraph cluster)
                                           (tx-handle-pos handle)))
        (make-feefrac))))

(defun txgraph-get-main-chunk-feerate (graph handle)
  "The feefrac of the chunk HANDLE's transaction is in, or the empty feefrac
if removed (Core GetMainChunkFeerate). The graph must not be oversized."
  (%check-handle graph handle)
  (%assert-not-oversized graph 'txgraph-get-main-chunk-feerate)
  (if (tx-handle-cluster handle)
      (copy-feefrac (tx-handle-chunk-feerate handle))
      (make-feefrac)))

(defun txgraph-get-cluster (graph handle)
  "All handles in the cluster HANDLE's transaction is in, in linearization
order, or NIL if removed (Core GetCluster). The graph must not be
oversized."
  (%check-handle graph handle)
  (%assert-not-oversized graph 'txgraph-get-cluster)
  (let ((cluster (tx-handle-cluster handle)))
    (when cluster
      (loop for pos across (%cluster-linearization cluster)
            collect (aref (%cluster-mapping cluster) pos)))))

(defun txgraph-get-cluster-chunks (graph handle)
  "The chunks of the cluster HANDLE's transaction is in, in mining order, as
a list of (handles . feerate) conses — HANDLES in linearization order,
FEERATE the chunk's aggregate feefrac — or NIL if removed. Not part of
Core's TxGraph interface: Core's RPC layer must RECONSTRUCT chunk membership
from per-entry chunk feerates (clusterToJSON's size countdown,
rpc/mempool.cpp:474-506) because its graph hides chunks; our eager cluster
objects store them directly, so expose them. The graph must not be
oversized."
  (%check-handle graph handle)
  (%assert-not-oversized graph 'txgraph-get-cluster-chunks)
  (let ((cluster (tx-handle-cluster handle)))
    (when cluster
      (loop for chunk across (%cluster-chunks cluster)
            collect (cons (coerce (%chunk-txs chunk) 'list)
                          (copy-feefrac (%chunk-feerate chunk)))))))

(defun txgraph-get-ancestors (graph handle)
  "All ancestors of HANDLE's transaction, including itself, in unspecified
order; NIL if removed (Core GetAncestors). The graph must not be oversized."
  (%check-handle graph handle)
  (%assert-not-oversized graph 'txgraph-get-ancestors)
  (let ((cluster (tx-handle-cluster handle)))
    (when cluster
      (%positions-handles cluster (depgraph-ancestors (%cluster-depgraph cluster)
                                                      (tx-handle-pos handle))))))

(defun txgraph-get-descendants (graph handle)
  "All descendants of HANDLE's transaction, including itself, in unspecified
order; NIL if removed (Core GetDescendants). The graph must not be
oversized."
  (%check-handle graph handle)
  (%assert-not-oversized graph 'txgraph-get-descendants)
  (let ((cluster (tx-handle-cluster handle)))
    (when cluster
      (%positions-handles cluster (depgraph-descendants (%cluster-depgraph cluster)
                                                        (tx-handle-pos handle))))))

(defun %closure-union (graph handles what closure-fn)
  "Union of per-transaction closures over HANDLES, each handle reported
once; removed handles are ignored (Core GetAncestorsUnion /
GetDescendantsUnion, txgraph.cpp:2470-2534)."
  (%assert-not-oversized graph what)
  (let ((per-cluster (make-hash-table :test 'eq))
        (out '()))
    (dolist (h handles)
      (%check-handle graph h)
      (let ((cluster (tx-handle-cluster h)))
        (when cluster
          (setf (gethash cluster per-cluster)
                (logior (gethash cluster per-cluster 0)
                        (funcall closure-fn (%cluster-depgraph cluster)
                                 (tx-handle-pos h)))))))
    (loop for cluster being the hash-keys of per-cluster using (hash-value bits)
          do (setf out (nconc out (%positions-handles cluster bits))))
    out))

(defun txgraph-get-ancestors-union (graph handles)
  "Union of the ancestor sets of HANDLES; see %CLOSURE-UNION."
  (%closure-union graph handles 'txgraph-get-ancestors-union #'depgraph-ancestors))

(defun txgraph-get-descendants-union (graph handles)
  "Union of the descendant sets of HANDLES; see %CLOSURE-UNION."
  (%closure-union graph handles 'txgraph-get-descendants-union #'depgraph-descendants))

(defun txgraph-compare-main-order (graph a b)
  "Compare handles A and B by mining order: -1 when A would be mined first
(Core CompareMainOrder, txgraph.cpp:2762-2781). Both must exist; the graph
must not be oversized."
  (%check-handle graph a)
  (%check-handle graph b)
  (%assert-not-oversized graph 'txgraph-compare-main-order)
  (assert (and (tx-handle-cluster a) (tx-handle-cluster b)) ()
          "txgraph-compare-main-order: both transactions must exist")
  (%compare-main graph a b))

(defun %distinct-clusters (graph handles)
  "The distinct live clusters the transactions of HANDLES belong to, as a
%CLUSTER -> T hash-table; removed handles are ignored. The shared core of the
cluster-count / cluster-gather / RBF affected-set enumerations."
  (let ((seen (make-hash-table :test 'eq)))
    (dolist (h handles seen)
      (%check-handle graph h)
      (let ((cluster (tx-handle-cluster h)))
        (when cluster (setf (gethash cluster seen) t))))))

(defun txgraph-count-distinct-clusters (graph handles)
  "The number of distinct clusters the transactions of HANDLES belong to;
removed handles are ignored (Core CountDistinctClusters,
txgraph.cpp:2783-2808). The graph must not be oversized."
  (%assert-not-oversized graph 'txgraph-count-distinct-clusters)
  (hash-table-count (%distinct-clusters graph handles)))

;;;; Diagram RBF staging (Core txgraph.cpp:2626-2834 staging overlay)
;;;;
;;;; Core keeps a copy-on-write "staging" level and derives the before/after
;;;; feerate diagrams from it (StartStaging + ProcessDependencies +
;;;; GetMainStagingDiagrams). We take the plan's scratch-copy simplification
;;;; (docs/cluster-mempool-plan.md §4.9): the only clusters a replacement can
;;;; touch are those of the transactions it evicts and those of the new
;;;; candidate's in-mempool parents, so we copy exactly those clusters into a
;;;; throwaway graph, apply the removal + addition there, and read the two
;;;; diagrams off the live clusters (before) and the scratch clusters (after).
;;;; This is exactly equivalent to Core's GetConflicts()/AppendChunkFeerates:
;;;; GetConflicts returns the main clusters that contain a removed tx or that
;;;; overlap a staging cluster, and a staging cluster only ever pulls in the
;;;; candidate's parents' clusters (the candidate depends solely on its direct
;;;; parents) plus removal-split remnants.

(defun %cluster-reduced-edges (cluster)
  "The transitive-reduction parent edges of CLUSTER as a list of
\(parent-handle . child-handle) conses. Re-adding these to a fresh graph
reconstructs CLUSTER's exact dependency closure."
  (let ((dg (%cluster-depgraph cluster))
        (mapping (%cluster-mapping cluster))
        (edges '()))
    (do-bits (i (depgraph-positions dg))
      (do-bits (p (depgraph-reduced-parents dg i))
        (push (cons (aref mapping p) (aref mapping i)) edges)))
    edges))

(defun %cluster-set-diagram (cluster-set)
  "The feerate diagram of a set of clusters (CLUSTER-SET is a %CLUSTER -> T
hash-table): every member cluster's chunk feerates gathered and sorted by
DECREASING feerate (Core AppendChunkFeerates over a cluster set followed by the
decreasing-feerate sort, txgraph.cpp:2818-2831)."
  (let ((ffs '()))
    (loop for c being the hash-keys of cluster-set
          do (loop for chunk across (%cluster-chunks c)
                   do (push (copy-feefrac (%chunk-feerate chunk)) ffs)))
    (sort ffs #'feefrac>)))

(defun %rbf-staged-diagrams (graph removed-handles parent-handles new-chain)
  "The shared staging core of TXGRAPH-RBF-DIAGRAMS and
TXGRAPH-PACKAGE-RBF-DIAGRAMS. NEW-CHAIN is a list of (fee . size) conses
describing the candidate transactions, added as a dependency CHAIN (each
subsequent tx spends its predecessor — the only two shapes Core stages are a
single candidate and a 1-parent-1-child package); PARENT-HANDLES are in-graph
parents of the FIRST chain member."
  (%assert-not-oversized graph '%rbf-staged-diagrams)
  ;; The affected main clusters: those of the evicted txs (Core's (P,R)
  ;; conflicts) and those of the candidate's parents (the only clusters a
  ;; staging cluster can overlap, Core's (P,P) conflicts).
  (let ((removed (make-hash-table :test 'eq))
        (affected (%distinct-clusters graph (append removed-handles parent-handles)))
        (scratch (make-txgraph :max-cluster-count (txgraph-max-cluster-count graph)
                               :max-cluster-size (txgraph-max-cluster-size graph)))
        (copy (make-hash-table :test 'eq)))   ; live handle -> scratch handle
    (dolist (h removed-handles) (setf (gethash h removed) t))
    ;; New diagram: rebuild the surviving transactions of the affected clusters
    ;; plus the candidate in a scratch graph, preserving every dependency among
    ;; survivors (all edges are intra-cluster) and wiring the candidate to its
    ;; parents. Add all survivor nodes before any edges so both endpoints exist.
    (loop for c being the hash-keys of affected
          do (let ((dg (%cluster-depgraph c))
                   (mapping (%cluster-mapping c)))
               (do-bits (i (depgraph-positions dg))
                 (let ((h (aref mapping i)))
                   (unless (gethash h removed)
                     (let ((ff (depgraph-tx-feerate dg i)))
                       (setf (gethash h copy)
                             (txgraph-add-transaction
                              scratch (feefrac-fee ff) (feefrac-size ff)))))))))
    (loop for c being the hash-keys of affected
          do (dolist (edge (%cluster-reduced-edges c))
               (let ((p (gethash (car edge) copy))
                     (ch (gethash (cdr edge) copy)))
                 (when (and p ch)
                   (txgraph-add-dependency scratch p ch)))))
    (let ((prev nil))
      (dolist (spec new-chain)
        (let ((cand (txgraph-add-transaction scratch (car spec) (cdr spec))))
          (if prev
              (txgraph-add-dependency scratch prev cand)
              (dolist (ph parent-handles)
                (let ((p (gethash ph copy)))
                  (when p (txgraph-add-dependency scratch p cand)))))
          (setf prev cand))))
    (if (txgraph-oversized-p scratch)
        (values :uncalculable nil)
        ;; Old diagram off the live clusters, new diagram off the scratch ones.
        (values (%cluster-set-diagram affected)
                (%cluster-set-diagram (txgraph-clusters scratch))))))

(defun txgraph-rbf-diagrams (graph removed-handles parent-handles new-fee new-size)
  "Compute the mempool feerate diagrams before and after a candidate RBF
replacement, without mutating GRAPH (Core ChangeSet::CalculateChunksForRBF ->
GetMainStagingDiagrams, txmempool.cpp:994-1002, txgraph.cpp:2810-2834).

REMOVED-HANDLES are the transactions the replacement evicts (the direct
conflicts plus their descendants); PARENT-HANDLES are the candidate's
in-mempool parents; NEW-FEE/NEW-SIZE describe the candidate (fee in satoshis,
the prioritisation-modified fee; size in virtual bytes).

Returns (values old-diagram new-diagram): each a list of FeeFracs sorted by
DECREASING feerate — the chunk feerates whose concave cumulative curve is the
diagram. Returns (values :uncalculable nil) when the staged replacement would
form an over-limit cluster (Core CalculateChunksForRBF returning an Error via
a failed CheckMemPoolPolicyLimits, txmempool.cpp:997-999). GRAPH must not be
oversized."
  (%rbf-staged-diagrams graph removed-handles parent-handles
                        (list (cons new-fee new-size))))

(defun txgraph-package-rbf-diagrams (graph removed-handles
                                     parent-fee parent-size child-fee child-size)
  "TXGRAPH-RBF-DIAGRAMS for a 1-parent-1-child package replacement (Core
PackageRBFChecks staging both package transactions into the same changeset
before ImprovesFeerateDiagram, validation.cpp:1080-1121): the staged additions
are the package parent and its child, wired parent -> child. The package has
no in-graph parents by construction — Core rejects package RBF when either
transaction has in-mempool ancestors (validation.cpp:1060-1064) — so no
PARENT-HANDLES parameter. Same return convention as TXGRAPH-RBF-DIAGRAMS."
  (%rbf-staged-diagrams graph removed-handles '()
                        (list (cons parent-fee parent-size)
                              (cons child-fee child-size))))

;;;; Chunk-index consumers: block builder and eviction

(defun txgraph-get-worst-main-chunk (graph)
  "The last chunk in mining order - the one to evict first - as (values
handles feerate), with the handles in REVERSE-topological order (each
element preceded by all its descendants); (values NIL empty-feefrac) when
the graph is empty (Core GetWorstMainChunk, txgraph.cpp:3258-3283). The
graph must not be oversized."
  (%assert-not-oversized graph 'txgraph-get-worst-main-chunk)
  (let ((chunk (%ci-last (txgraph-chunk-index graph))))
    (if (null chunk)
        (values '() (make-feefrac))
        (values (reverse (coerce (%chunk-txs chunk) 'list))
                (copy-feefrac (%chunk-feerate chunk))))))

(defstruct (block-builder (:constructor %make-block-builder (graph index)))
  "Iterator over the chunk index in mining order (Core BlockBuilderImpl,
txgraph.cpp:850-877/3159-3251). While one exists, no mutations of its graph
are allowed; call BLOCK-BUILDER-FINISH when done (the analogue of Core's
destructor)."
  (graph nil :read-only t)
  (index #() :type simple-vector :read-only t)
  (pos 0 :type fixnum)
  ;; Clusters from which a chunk was skipped (Core m_excluded_clusters).
  (excluded (make-hash-table :test 'eq) :type hash-table)
  (finished nil))

(defmethod print-object ((b block-builder) stream)
  (print-unreadable-object (b stream :type t)
    (format stream "~D/~D~:[~; finished~]"
            (block-builder-pos b) (length (block-builder-index b))
            (block-builder-finished b))))

(defun make-block-builder (graph)
  "Create a block builder over GRAPH's chunk index (Core GetBlockBuilder).
The graph must not be oversized, and must not be mutated until
BLOCK-BUILDER-FINISH is called."
  (%assert-not-oversized graph 'make-block-builder)
  (let ((index (%chunk-index-vector graph)))
    (incf (txgraph-builder-count graph))
    (%make-block-builder graph index)))

(defun block-builder-finish (builder)
  "Release BUILDER, allowing graph mutations again (the explicit analogue
of Core's BlockBuilderImpl destructor)."
  (assert (not (block-builder-finished builder)))
  (setf (block-builder-finished builder) t)
  (decf (txgraph-builder-count (block-builder-graph builder)))
  (values))

(defun %builder-advance (builder)
  "Move to the next chunk not belonging to a skipped cluster (Core
BlockBuilderImpl::Next, txgraph.cpp:3159-3176)."
  (let ((index (block-builder-index builder))
        (excluded (block-builder-excluded builder)))
    (loop do (incf (block-builder-pos builder))
          while (and (< (block-builder-pos builder) (length index))
                     (gethash (tx-handle-cluster
                               (%chunk-end (svref index (block-builder-pos builder))))
                              excluded)))))

(defun block-builder-current-chunk (builder)
  "The chunk currently suggested for inclusion as (values handles feerate),
handles in topological order, or NIL when iteration is done (Core
GetCurrentChunk)."
  (let ((index (block-builder-index builder))
        (pos (block-builder-pos builder)))
    (when (< pos (length index))
      (let ((chunk (svref index pos)))
        (values (coerce (%chunk-txs chunk) 'list)
                (copy-feefrac (%chunk-feerate chunk)))))))

(defun block-builder-current-chunk-feerate (builder)
  "The current chunk's aggregate feefrac only — BLOCK-BUILDER-CURRENT-CHUNK
without materializing the handle list — or NIL when iteration is done. For
consumers like the feerate diagram that never look at the members."
  (let ((index (block-builder-index builder))
        (pos (block-builder-pos builder)))
    (when (< pos (length index))
      (copy-feefrac (%chunk-feerate (svref index pos))))))

(defun block-builder-include (builder)
  "Mark the current chunk as included and move to the next (Core Include)."
  (%builder-advance builder)
  (values))

(defun block-builder-skip (builder)
  "Mark the current chunk as skipped and move on; no further chunks from
its cluster will be reported, as including them without it could be
topologically invalid (Core Skip, txgraph.cpp:3241-3251)."
  (let ((index (block-builder-index builder))
        (pos (block-builder-pos builder)))
    (when (< pos (length index))
      (setf (gethash (tx-handle-cluster (%chunk-end (svref index pos)))
                     (block-builder-excluded builder))
            t)))
  (%builder-advance builder)
  (values))

;;;; Trim

(defstruct (%trim-entry (:constructor %make-trim-entry (handle chunk-feerate size)))
  "Per-transaction state for TXGRAPH-TRIM (Core TrimTxData, txgraph.cpp:61-99)."
  (handle nil :read-only t)
  (chunk-feerate nil :read-only t)
  (size 0 :read-only t)
  (deps-left 0)                 ; unmet dependency instances
  (parents '())                 ; parent entries, one per dependency instance
  (children '())                ; child entries, one per dependency instance
  (included nil)
  ;; Union-find over included entries (path-splitting + union by count).
  (uf-parent nil)
  (uf-count 1)
  (uf-size 0))

(defun %trim-find (e)
  (loop until (eq (%trim-entry-uf-parent e) e)
        do (let ((p (%trim-entry-uf-parent e)))
             (setf (%trim-entry-uf-parent e) (%trim-entry-uf-parent p)
                   e p)))
  e)

(defun %trim-union (a b)
  (let ((ra (%trim-find a)) (rb (%trim-find b)))
    (if (eq ra rb)
        ra
        (progn
          (when (< (%trim-entry-uf-count ra) (%trim-entry-uf-count rb))
            (rotatef ra rb))
          (setf (%trim-entry-uf-parent rb) ra)
          (incf (%trim-entry-uf-size ra) (%trim-entry-uf-size rb))
          (incf (%trim-entry-uf-count ra) (%trim-entry-uf-count rb))
          ra))))

(defun %trim-group (graph clusters deps)
  "Choose the transactions to drop from the would-be cluster formed by
CLUSTERS + DEPS so that the result respects the limits (Core Trim's
per-group body, txgraph.cpp:3300-3527). A rudimentary merged linearization
is simulated: every transaction implicitly depends on its predecessor in
its cluster's linearization (so cluster prefixes are consumed in order),
plus the explicit DEPS; transactions are greedily included best-chunk-
feerate-first unless joining them (with everything they depend on, tracked
by union-find) would exceed the limits. Whatever is not included - which
automatically covers all descendants of anything skipped - is returned as a
list of handles to remove."
  (let ((entries (make-hash-table :test 'eq))
        (fallback (txgraph-fallback-order graph))
        (all '()))
    (flet ((add-dep (par chl)
             (push chl (%trim-entry-children par))
             (push par (%trim-entry-parents chl))
             (incf (%trim-entry-deps-left chl))))
      (dolist (cluster clusters)
        (let ((mapping (%cluster-mapping cluster))
              (dg (%cluster-depgraph cluster))
              (prev nil))
          (loop for pos across (%cluster-linearization cluster)
                for h = (aref mapping pos)
                for e = (%make-trim-entry
                         h (tx-handle-chunk-feerate h)
                         (feefrac-size (depgraph-tx-feerate dg pos)))
                do (setf (gethash h entries) e)
                   (push e all)
                   (when prev (add-dep prev e))
                   (setf prev e))))
      (dolist (dep deps)
        (add-dep (gethash (car dep) entries) (gethash (cdr dep) entries))))
    ;; Greedy inclusion, best chunk feerate first (full feefrac order; Core
    ;; leaves exact ties unspecified - we break them with the fallback
    ;; order for determinism).
    (let ((ready (remove-if-not
                  (lambda (e) (and (zerop (%trim-entry-deps-left e))
                                   (<= (%trim-entry-size e)
                                       (txgraph-max-cluster-size graph))))
                  all)))
      (loop while ready
            do (let ((best (first ready)))
                 (dolist (e (rest ready))
                   (let ((cmp (feefrac-compare (%trim-entry-chunk-feerate e)
                                               (%trim-entry-chunk-feerate best))))
                     (when (or (plusp cmp)
                               (and (zerop cmp)
                                    (minusp (funcall fallback
                                                     (%trim-entry-handle e)
                                                     (%trim-entry-handle best)))))
                       (setf best e))))
                 (setf ready (delete best ready :test #'eq :count 1))
                 (setf (%trim-entry-uf-parent best) best
                       (%trim-entry-uf-count best) 1
                       (%trim-entry-uf-size best) (%trim-entry-size best))
                 ;; The distinct partitions BEST depends on (parents are all
                 ;; included already, or BEST would not be ready).
                 (let ((reps '())
                       (new-count 1)
                       (new-size (%trim-entry-size best)))
                   (dolist (p (%trim-entry-parents best))
                     (pushnew (%trim-find p) reps :test #'eq))
                   (dolist (r reps)
                     (incf new-count (%trim-entry-uf-count r))
                     (incf new-size (%trim-entry-uf-size r)))
                   (when (and (<= new-count (txgraph-max-cluster-count graph))
                              (<= new-size (txgraph-max-cluster-size graph)))
                     (dolist (r reps) (%trim-union best r))
                     (setf (%trim-entry-included best) t)
                     (dolist (c (%trim-entry-children best))
                       (when (zerop (decf (%trim-entry-deps-left c)))
                         (push c ready))))))))
    (loop for e in all
          unless (%trim-entry-included e)
            collect (%trim-entry-handle e))))

(defun txgraph-trim (graph)
  "Restore the cluster limits after bulk operations (reorg re-adds) by
removing transactions - together with their would-be descendants - from
every over-limit would-be cluster, keeping the best chunks (Core Trim,
txgraph.cpp:3285-3533). Also removes individually-oversized transactions.
Fast but best-effort. Returns the list of removed handles; a no-op (NIL)
unless the graph is oversized."
  (%assert-no-builder graph)
  (if (not (txgraph-oversized-p graph))
      '()
      (let ((removed '()))
        (dolist (group (%pending-groups graph :include-oversized-singletons t))
          (destructuring-bind (clusters deps count size) group
            (when (or (> count (txgraph-max-cluster-count graph))
                      (> size (txgraph-max-cluster-size graph)))
              (setf removed (nconc removed (%trim-group graph clusters deps))))))
        (dolist (h removed)
          (txgraph-remove-transaction graph h))
        (assert (not (txgraph-oversized-p graph)))
        removed)))

;;;; Consistency check

(defun txgraph-sanity-check (graph)
  "Verify GRAPH's internal invariants (Core TxGraphImpl::SanityCheck,
txgraph.cpp:2932+): cluster/handle/mapping consistency, connectivity,
acyclicity, limits, eagerly-cached chunk data, pending-dependency
bookkeeping, and the chunk index (order, coverage, and equality with a
from-scratch rebuild). Signals an error on violation; returns T."
  (let ((tx-total 0)
        (oversized-txs 0))
    (loop for cluster being the hash-keys of (txgraph-clusters graph) do
      (let* ((dg (%cluster-depgraph cluster))
             (lin (%cluster-linearization cluster))
             (mapping (%cluster-mapping cluster))
             (n (depgraph-tx-count dg)))
        (assert (plusp n))
        (incf tx-total n)
        (assert (depgraph-acyclic-p dg))
        (assert (depgraph-connected-p dg))
        (assert (linearization-topological-p dg lin))
        (assert (<= n (txgraph-max-cluster-count graph)))
        ;; Only individually-oversized singletons may exceed the size limit.
        (unless (= n 1)
          (assert (<= (%cluster-tx-size cluster) (txgraph-max-cluster-size graph))))
        (let ((size 0))
          (do-bits (i (depgraph-positions dg))
            (let ((h (aref mapping i))
                  (tx-size (feefrac-size (depgraph-tx-feerate dg i))))
              (assert (eq (tx-handle-graph h) graph))
              (assert (eq (tx-handle-cluster h) cluster))
              (assert (= (tx-handle-pos h) i))
              (incf size tx-size)
              (when (> tx-size (txgraph-max-cluster-size graph))
                (incf oversized-txs))))
          (assert (= size (%cluster-tx-size cluster))))
        ;; Chunk cache = fresh chunking; per-handle cached order data.
        (let ((info (chunk-linearization-info dg lin))
              (chunks (%cluster-chunks cluster))
              (lin-idx 0)
              (acc (make-feefrac))
              (prev nil))
          (assert (= (length info) (length chunks)))
          (loop for si in info
                for chunk across chunks
                do (assert (feefrac= (setinfo-feerate si) (%chunk-feerate chunk)))
                   ;; Chunk feerates are monotonically non-increasing.
                   (when prev (assert (not (feefrac>> (%chunk-feerate chunk) prev))))
                   (setf prev (%chunk-feerate chunk))
                   (setf acc (if (feefrac<< (setinfo-feerate si) acc)
                                 (copy-feefrac (setinfo-feerate si))
                                 (feefrac+ acc (setinfo-feerate si))))
                   (let ((max-h nil))
                     (loop for h across (%chunk-txs chunk)
                           do (when (or (null max-h)
                                        (plusp (funcall (txgraph-fallback-order graph) h max-h)))
                                (setf max-h h)))
                     (loop for h across (%chunk-txs chunk)
                           do (assert (logbitp (tx-handle-pos h) (setinfo-transactions si)))
                              (assert (eq h (aref mapping (svref lin lin-idx))))
                              (assert (= (tx-handle-lin-index h) lin-idx))
                              (assert (eq (tx-handle-chunk-feerate h) (%chunk-feerate chunk)))
                              (assert (= (tx-handle-chunk-prefix-size h) (feefrac-size acc)))
                              (assert (eq (tx-handle-chunk-fallback h) max-h))
                              (incf lin-idx))))
          (assert (= lin-idx (length lin))))))
    (assert (= tx-total (txgraph-tx-count graph)))
    (assert (= oversized-txs (txgraph-oversized-tx-count graph)))
    ;; Pending deps have live endpoints, and every pending group is
    ;; genuinely over-limit (feasible ones must have been applied eagerly).
    (dolist (dep (txgraph-pending-deps graph))
      (assert (tx-handle-cluster (car dep)))
      (assert (tx-handle-cluster (cdr dep))))
    (dolist (group (%pending-groups graph))
      (destructuring-bind (clusters deps count size) group
        (declare (ignore clusters))
        (when deps
          (assert (or (> count (txgraph-max-cluster-count graph))
                      (> size (txgraph-max-cluster-size graph)))))))
    ;; The chunk index covers every chunk exactly once, in strictly
    ;; ascending mining order, and holds exactly the chunks a from-scratch
    ;; rebuild would - the oracle for the incremental maintenance.
    (let ((index (%chunk-index-vector graph))
          (oracle (%chunk-index-full-rebuild graph))
          (expected 0))
      (loop for cluster being the hash-keys of (txgraph-clusters graph)
            do (incf expected (length (%cluster-chunks cluster))))
      (assert (= expected (length index)))
      (assert (= (length oracle) (length index)))
      (dotimes (k (length index))
        (assert (eq (svref index k) (svref oracle k))))
      (loop for k from 1 below (length index)
            do (assert (minusp (%compare-main graph
                                              (%chunk-end (svref index (1- k)))
                                              (%chunk-end (svref index k)))))))
    t))
