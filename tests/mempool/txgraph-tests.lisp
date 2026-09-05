(in-package #:bitcoin-lisp.tests)

;;;; TxGraph tests
;;;;
;;;; Validates src/mempool/txgraph.lisp against the contract of Bitcoin
;;;; Core src/txgraph.{h,cpp}: cluster registry semantics, the mining-order
;;;; comparator (chunk feerate desc, equal-feerate prefix size, fallback
;;;; order, linearization position; txgraph.cpp:492-524), the block builder,
;;;; worst-chunk eviction, oversized handling, and Trim. Unit tests cover
;;;; every API function on hand-built shapes; randomized property tests
;;;; check the whole engine against a brute-force closure model (the same
;;;; ancestor/descendant-closure semantics as DepGraph, so a removed
;;;; middleman keeps grandparents connected), reusing the seeded xorshift64
;;;; PRNG from cluster-linearize-tests (make-deterministic-rng).

(def-suite :txgraph-tests
  :description "TxGraph engine vs Core txgraph.{h,cpp}"
  :in :bitcoin-lisp-tests)

(in-suite :txgraph-tests)

;;;; Shorthands

(defun %tg-new (&rest args) (apply #'bl.mp:make-txgraph args))
(defun %tg-add (g fee size) (bl.mp:txgraph-add-transaction g fee size))
(defun %tg-dep (g p c) (bl.mp:txgraph-add-dependency g p c))
(defun %tg-rm (g h) (bl.mp:txgraph-remove-transaction g h))
(defun %tg-setfee (g h fee) (bl.mp:txgraph-set-transaction-fee g h fee))
(defun %tg-exists (g h) (bl.mp:txgraph-exists-p g h))
(defun %tg-count (g) (bl.mp:txgraph-tx-count g))
(defun %tg-oversized (g) (bl.mp:txgraph-oversized-p g))
(defun %tg-feerate (g h) (bl.mp:txgraph-get-individual-feerate g h))
(defun %tg-chunk-feerate (g h) (bl.mp:txgraph-get-main-chunk-feerate g h))
(defun %tg-cluster (g h) (bl.mp:txgraph-get-cluster g h))
(defun %tg-anc (g h) (bl.mp:txgraph-get-ancestors g h))
(defun %tg-desc (g h) (bl.mp:txgraph-get-descendants g h))
(defun %tg-anc-union (g hs) (bl.mp:txgraph-get-ancestors-union g hs))
(defun %tg-desc-union (g hs) (bl.mp:txgraph-get-descendants-union g hs))
(defun %tg-cmp (g a b) (bl.mp:txgraph-compare-main-order g a b))
(defun %tg-distinct (g hs) (bl.mp:txgraph-count-distinct-clusters g hs))
(defun %tg-worst (g) (bl.mp:txgraph-get-worst-main-chunk g))
(defun %tg-trim (g) (bl.mp:txgraph-trim g))
(defun %tg-sane (g) (bl.mp:txgraph-sanity-check g))
(defun %tg-id (h) (bl.mp:tx-handle-id h))
(defun %tg-ids (handles) (sort (mapcar #'%tg-id handles) #'<))
(defun %tg-ff= (f fee size)
  (bl.mp:feefrac= f (bl.mp:make-feefrac fee size)))
(defun %tg-empty-ff-p (f) (bl.mp:feefrac-empty-p f))

(defun %tg-index-oracle-agree-p (g)
  "True when the incrementally maintained mining index holds exactly the
chunks a from-scratch collect-and-sort holds, in the same order. The rebuild
is the correctness oracle the incremental index replaced."
  (let ((live (bl.mp::%chunk-index-vector g))
        (oracle (bl.mp::%chunk-index-full-rebuild g)))
    (and (= (length live) (length oracle))
         (every #'eq live oracle))))

(defun %tg-drop-one-index-chunk (g)
  "Extract one chunk from the live mining index behind the graph's back,
leaving its cluster untouched: the planted corruption that proves the
index-vs-oracle check in TXGRAPH-SANITY-CHECK can actually fail."
  (bl.mp::%ci-delete g (bl.mp::txgraph-chunk-index g)
                     (aref (bl.mp::%chunk-index-vector g) 0)))

(defun %tg-fill-singletons (n)
  "A graph of N independent single-transaction clusters with spread-out fees."
  (let ((g (%tg-new)))
    (dotimes (i n g)
      (%tg-add g (+ 1000 (mod (* i 7919) 100003)) 141))))

(defun %tg-chunks (g)
  "The full mining-order chunk walk (include everything) as a list of
(handles . feerate)."
  (let ((builder (bl.mp:make-block-builder g))
        (out '()))
    (unwind-protect
         (loop (multiple-value-bind (txs feerate)
                   (bl.mp:block-builder-current-chunk builder)
                 (unless txs (return))
                 (push (cons txs feerate) out)
                 (bl.mp:block-builder-include builder)))
      (bl.mp:block-builder-finish builder))
    (nreverse out)))

;;;; Brute-force model
;;;;
;;;; Transactions are indexed by creation order; ancestor/descendant sets
;;;; are integer bitsets over those indices, maintained with the same
;;;; closure-update rules as DepGraph (add-dependency merges full closures;
;;;; removal masks the removed bit everywhere, preserving links bridged by
;;;; the removed transaction). Connectivity is closure-based, exactly like
;;;; depgraph-connected-component.

(defstruct (%tgm-tx (:constructor %make-tgm-tx (handle fee size anc desc)))
  handle fee size anc desc (live t))

(defun %tgm-add (model fee size handle)
  (let ((i (length model)))
    (vector-push-extend (%make-tgm-tx handle fee size (ash 1 i) (ash 1 i)) model)
    i))

(defun %tgm-dep (model p c)
  "Closure update for a new dependency P -> C (both live)."
  (let ((tp (aref model p))
        (tc (aref model c)))
    (unless (logbitp p (%tgm-tx-anc tc))     ; already an ancestor: no-op
      (let ((par-anc (%tgm-tx-anc tp))
            (chl-desc (%tgm-tx-desc tc)))
        (dotimes (i (length model))
          (let ((tx (aref model i)))
            (when (%tgm-tx-live tx)
              (when (logbitp i chl-desc)
                (setf (%tgm-tx-anc tx) (logior (%tgm-tx-anc tx) par-anc)))
              (when (logbitp i par-anc)
                (setf (%tgm-tx-desc tx) (logior (%tgm-tx-desc tx) chl-desc))))))))))

(defun %tgm-rm (model i)
  (setf (%tgm-tx-live (aref model i)) nil)
  (dotimes (j (length model))
    (let ((tx (aref model j)))
      (setf (%tgm-tx-anc tx) (logandc2 (%tgm-tx-anc tx) (ash 1 i))
            (%tgm-tx-desc tx) (logandc2 (%tgm-tx-desc tx) (ash 1 i))))))

(defun %tgm-component (model i)
  "Connected component (bitset) of live tx I via ancestor/descendant closures."
  (let ((ret 0)
        (to-add (ash 1 i)))
    (loop
      (let ((old ret))
        (bl.mp:do-bits (j to-add)
          (let ((tx (aref model j)))
            (setf ret (logior ret (%tgm-tx-anc tx) (%tgm-tx-desc tx)))))
        (setf to-add (logandc2 ret old))
        (when (zerop to-add) (return ret))))))

(defun %tgm-components (model)
  "All live components as a list of bitsets."
  (let ((seen 0)
        (out '()))
    (dotimes (i (length model))
      (when (and (%tgm-tx-live (aref model i)) (not (logbitp i seen)))
        (let ((comp (%tgm-component model i)))
          (setf seen (logior seen comp))
          (push comp out))))
    out))

(defun %tgm-set-ids (model bits)
  "Sorted handle ids for the model indices in bitset BITS."
  (let ((ids '()))
    (bl.mp:do-bits (i bits)
      (push (%tg-id (%tgm-tx-handle (aref model i))) ids))
    (sort ids #'<)))

(defun %tgm-comp-stats (model comp)
  "(values tx-count total-size) of component bitset COMP."
  (let ((count 0) (size 0))
    (bl.mp:do-bits (i comp)
      (incf count)
      (incf size (%tgm-tx-size (aref model i))))
    (values count size)))

(defun %tgm-oversized-p (model max-count max-size)
  "Model prediction of TXGRAPH-OVERSIZED-P: some live component (with all
dependencies applied, pending or not) exceeds the limits, or a single live
transaction alone exceeds the size limit."
  (or (loop for i from 0 below (length model)
              thereis (let ((tx (aref model i)))
                        (and (%tgm-tx-live tx) (> (%tgm-tx-size tx) max-size))))
      (loop for comp in (%tgm-components model)
              thereis (multiple-value-bind (count size) (%tgm-comp-stats model comp)
                        (or (> count max-count) (> size max-size))))))

(defun %tg-verify-model (g model idx-of rng)
  "Full equivalence check of graph G against the closure model (only valid
when G is not oversized)."
  (is-false (%tg-oversized g))
  (is-true (%tg-sane g))
  (let ((live-bits 0))
    (dotimes (i (length model))
      (when (%tgm-tx-live (aref model i)) (setf live-bits (logior live-bits (ash 1 i)))))
    (is (= (logcount live-bits) (%tg-count g)))
    ;; Per-transaction queries.
    (dotimes (i (length model))
      (let* ((tx (aref model i))
             (h (%tgm-tx-handle tx)))
        (is (eq (not (null (%tgm-tx-live tx))) (not (null (%tg-exists g h)))))
        (cond ((%tgm-tx-live tx)
               (is (%tg-ff= (%tg-feerate g h) (%tgm-tx-fee tx) (%tgm-tx-size tx)))
               (is (equal (%tgm-set-ids model (%tgm-tx-anc tx)) (%tg-ids (%tg-anc g h))))
               (is (equal (%tgm-set-ids model (%tgm-tx-desc tx)) (%tg-ids (%tg-desc g h))))
               (is (equal (%tgm-set-ids model (%tgm-component model i))
                          (%tg-ids (%tg-cluster g h)))))
              (t
               (is (%tg-empty-ff-p (%tg-feerate g h)))
               (is (null (%tg-cluster g h)))
               (is (null (%tg-anc g h)))))))
    ;; Union queries on a random subset (removed handles must be ignored).
    (let ((subset (loop for i from 0 below (length model)
                        when (< (funcall rng 100) 40)
                          collect (%tgm-tx-handle (aref model i))))
          (anc-bits 0)
          (desc-bits 0))
      (dolist (h subset)
        (let ((i (gethash h idx-of)))
          (when (%tgm-tx-live (aref model i))
            (setf anc-bits (logior anc-bits (%tgm-tx-anc (aref model i)))
                  desc-bits (logior desc-bits (%tgm-tx-desc (aref model i)))))))
      (is (equal (%tgm-set-ids model anc-bits) (%tg-ids (%tg-anc-union g subset))))
      (is (equal (%tgm-set-ids model desc-bits) (%tg-ids (%tg-desc-union g subset))))
      ;; Distinct-cluster count over the same subset.
      (let ((comps '()))
        (dolist (h subset)
          (let ((i (gethash h idx-of)))
            (when (%tgm-tx-live (aref model i))
              (pushnew (%tgm-component model i) comps :test #'=))))
        (is (= (length comps) (%tg-distinct g subset)))))
    ;; Chunk walk: coverage, feerates, global order, per-cluster
    ;; concatenation, worst chunk, comparator, chunk-feerate query.
    (let ((chunks (%tg-chunks g)))
      (let ((all (loop for (txs . nil) in chunks append txs)))
        (is (equal (%tgm-set-ids model live-bits) (%tg-ids all)))
        ;; Chunk feerate = sum of member fees/sizes.
        (loop for (txs . feerate) in chunks
              do (let ((fee 0) (size 0))
                   (dolist (h txs)
                     (let ((tx (aref model (gethash h idx-of))))
                       (incf fee (%tgm-tx-fee tx))
                       (incf size (%tgm-tx-size tx))))
                   (is (%tg-ff= feerate fee size))))
        ;; Chunk feerates are globally non-increasing (Core SanityCheck,
        ;; txgraph.cpp:3100-3109).
        (loop for ((nil . fa) (nil . fb)) on chunks
              while fb
              do (is-false (bl.mp:feefrac>> fb fa)))
        ;; Concatenating a cluster's chunks in emitted order must equal its
        ;; GetCluster (linearization) order.
        (let ((by-comp (make-hash-table :test 'eql)))
          (loop for (txs . nil) in chunks
                do (dolist (h txs)
                     (push h (gethash (%tgm-component model (gethash h idx-of))
                                      by-comp))))
          (loop for rev being the hash-values of by-comp
                do (let ((in-order (reverse rev)))
                     (is (equal in-order (%tg-cluster g (first in-order)))))))
        ;; Worst chunk = last chunk, in reverse order.
        (multiple-value-bind (worst wf) (%tg-worst g)
          (if chunks
              (let ((last-chunk (car (last chunks))))
                (is (equal worst (reverse (car last-chunk))))
                (is (bl.mp:feefrac= wf (cdr last-chunk))))
              (progn (is (null worst))
                     (is (%tg-empty-ff-p wf)))))
        ;; CompareMainOrder agrees with the emitted per-transaction order
        ;; and is antisymmetric; GetMainChunkFeerate agrees with the walk.
        (when all
          (let ((order (make-hash-table :test 'eq))
                (k 0)
                (v (coerce all 'vector)))
            (dolist (h all) (setf (gethash h order) (incf k)))
            (dotimes (s 20)
              (let ((a (aref v (funcall rng (length v))))
                    (b (aref v (funcall rng (length v)))))
                (is (= (%tg-cmp g a b)
                       (signum (- (gethash a order) (gethash b order)))))
                (is (= (%tg-cmp g a b) (- (%tg-cmp g b a)))))))
          (loop for (txs . feerate) in chunks
                do (dolist (h txs)
                     (is (bl.mp:feefrac= (%tg-chunk-feerate g h) feerate)))))))))

;;;; Unit tests: basics

(test txgraph-constants
  "Cluster limits are Core-exact (txgraph.h:18, policy 101 kvB)."
  (is (= 64 bl.mp:+max-cluster-count+))
  (is (= 101000 bl.mp:+max-cluster-size+)))

(test txgraph-empty-graph
  (let ((g (%tg-new)))
    (is (= 0 (%tg-count g)))
    (is-false (%tg-oversized g))
    (is-true (%tg-sane g))
    (multiple-value-bind (worst wf) (%tg-worst g)
      (is (null worst))
      (is (%tg-empty-ff-p wf)))
    (is (null (%tg-anc-union g '())))
    (is (= 0 (%tg-distinct g '())))
    (let ((b (bl.mp:make-block-builder g)))
      (is (null (bl.mp:block-builder-current-chunk b)))
      (bl.mp:block-builder-finish b))))

(test txgraph-add-exists-remove
  "AddTransaction / Exists / RemoveTransaction basics; removal is a no-op
the second time (Core txgraph.cpp:2262-2266)."
  (let* ((g (%tg-new))
         (a (%tg-add g 100 10))
         (b (%tg-add g -50 20)))         ; negative fees are legal
    (is (= 2 (%tg-count g)))
    (is-true (%tg-exists g a))
    (is-true (%tg-exists g b))
    (is (%tg-ff= (%tg-feerate g a) 100 10))
    (is (%tg-ff= (%tg-feerate g b) -50 20))
    ;; Distinct ids, in creation order.
    (is (< (%tg-id a) (%tg-id b)))
    (%tg-rm g a)
    (is-false (%tg-exists g a))
    (is (= 1 (%tg-count g)))
    (is (%tg-empty-ff-p (%tg-feerate g a)))
    (is (%tg-empty-ff-p (%tg-chunk-feerate g a)))
    (is (null (%tg-cluster g a)))
    (is (null (%tg-anc g a)))
    (is (null (%tg-desc g a)))
    (%tg-rm g a)                          ; no-op
    (is (= 1 (%tg-count g)))
    (is-true (%tg-sane g))))

(test txgraph-handle-of-other-graph-rejected
  (let* ((g1 (%tg-new))
         (g2 (%tg-new))
         (h (%tg-add g1 1 1)))
    (signals error (%tg-rm g2 h))
    (signals error (%tg-feerate g2 h))))

(test txgraph-cpfp-chunk
  "A high-feerate child is chunked with its low-feerate parent; both report
the combined chunk feerate (CPFP)."
  (let* ((g (%tg-new))
         (parent (%tg-add g 100 1000))
         (child (%tg-add g 4900 1000)))
    (%tg-dep g parent child)
    (is (= 1 (%tg-distinct g (list parent child))))
    (is (equal (list parent child) (%tg-cluster g parent)))
    (is (%tg-ff= (%tg-chunk-feerate g parent) 5000 2000))
    (is (%tg-ff= (%tg-chunk-feerate g child) 5000 2000))
    ;; Individual feerates are unchanged.
    (is (%tg-ff= (%tg-feerate g parent) 100 1000))
    ;; One chunk, in topological order; worst chunk is it, reversed.
    (let ((chunks (%tg-chunks g)))
      (is (= 1 (length chunks)))
      (is (equal (list parent child) (car (first chunks)))))
    (multiple-value-bind (worst wf) (%tg-worst g)
      (is (equal (list child parent) worst))
      (is (%tg-ff= wf 5000 2000)))
    (is-true (%tg-sane g))))

(test txgraph-diamond-closures
  "Ancestors/descendants across a diamond: d spends b and c; b and c spend a."
  (let* ((g (%tg-new))
         (a (%tg-add g 1 1)) (b (%tg-add g 2 1))
         (c (%tg-add g 3 1)) (d (%tg-add g 4 1)))
    (%tg-dep g a b)
    (%tg-dep g a c)
    (%tg-dep g b d)
    (%tg-dep g c d)
    (is (equal (%tg-ids (list a)) (%tg-ids (%tg-anc g a))))
    (is (equal (%tg-ids (list a b)) (%tg-ids (%tg-anc g b))))
    (is (equal (%tg-ids (list a c)) (%tg-ids (%tg-anc g c))))
    (is (equal (%tg-ids (list a b c d)) (%tg-ids (%tg-anc g d))))
    (is (equal (%tg-ids (list a b c d)) (%tg-ids (%tg-desc g a))))
    (is (equal (%tg-ids (list b d)) (%tg-ids (%tg-desc g b))))
    (is (equal (%tg-ids (list d)) (%tg-ids (%tg-desc g d))))
    ;; Redundant dependency (a -> d) is a no-op.
    (%tg-dep g a d)
    (is (equal (%tg-ids (list a b c d)) (%tg-ids (%tg-anc g d))))
    ;; Unions.
    (is (equal (%tg-ids (list a b c)) (%tg-ids (%tg-anc-union g (list b c)))))
    (is (equal (%tg-ids (list b c d)) (%tg-ids (%tg-desc-union g (list b c)))))
    ;; Duplicates and removed handles in union inputs are handled.
    (is (equal (%tg-ids (list a b)) (%tg-ids (%tg-anc-union g (list b b)))))
    (is-true (%tg-sane g))))

(test txgraph-add-dependency-noops-and-cycle
  (let* ((g (%tg-new))
         (a (%tg-add g 1 1))
         (b (%tg-add g 2 1))
         (r (%tg-add g 3 1)))
    (%tg-dep g a a)                       ; self: no-op
    (is (= 3 (%tg-distinct g (list a b r))))
    (%tg-rm g r)
    (%tg-dep g r a)                       ; removed parent: no-op
    (%tg-dep g a r)                       ; removed child: no-op
    (is (equal (%tg-ids (list a)) (%tg-ids (%tg-anc g a))))
    (%tg-dep g a b)
    ;; Making b a parent of a would create a cycle (a is b's ancestor).
    (signals error (%tg-dep g b a))
    (is-true (%tg-sane g))))

(test txgraph-merge-and-split
  "add-dependency merges clusters; removal splits them into components; a
removed middleman keeps grandparents connected (closure semantics)."
  (let* ((g (%tg-new))
         (a (%tg-add g 1 1)) (b (%tg-add g 2 1))
         (x (%tg-add g 3 1)) (y (%tg-add g 4 1)))
    (%tg-dep g a b)
    (%tg-dep g x y)
    (is (= 2 (%tg-distinct g (list a b x y))))
    ;; Merge the two clusters.
    (%tg-dep g b x)
    (is (= 1 (%tg-distinct g (list a b x y))))
    (is (equal (%tg-ids (list a b x y)) (%tg-ids (%tg-cluster g a))))
    (is (equal (%tg-ids (list a b x)) (%tg-ids (%tg-anc g x))))
    (is-true (%tg-sane g))
    ;; Removing the middleman b does NOT split: x stays connected to a
    ;; through the masked closure (grandparent relation survives).
    (%tg-rm g b)
    (is (equal (%tg-ids (list a x y)) (%tg-ids (%tg-cluster g a))))
    (is (equal (%tg-ids (list a x)) (%tg-ids (%tg-anc g x))))
    (is (equal (%tg-ids (list a x y)) (%tg-ids (%tg-desc g a))))
    (is-true (%tg-sane g))
    ;; Removing x, too, still does not split: transitive ancestry survives
    ;; any number of removed middlemen (a is still y's ancestor).
    (%tg-rm g x)
    (is (= 1 (%tg-distinct g (list a y))))
    (is (equal (%tg-ids (list a y)) (%tg-ids (%tg-cluster g a))))
    (is (equal (%tg-ids (list a y)) (%tg-ids (%tg-anc g y))))
    (is-true (%tg-sane g))))

(test txgraph-true-split-on-removal
  "Removing a parent with two independent children yields two clusters."
  (let* ((g (%tg-new))
         (p (%tg-add g 1 1))
         (c1 (%tg-add g 2 1))
         (c2 (%tg-add g 3 1)))
    (%tg-dep g p c1)
    (%tg-dep g p c2)
    (is (= 1 (%tg-distinct g (list p c1 c2))))
    (%tg-rm g p)
    (is (= 2 (%tg-distinct g (list c1 c2))))
    (is (equal (list c1) (%tg-cluster g c1)))
    (is (equal (list c2) (%tg-cluster g c2)))
    (is-true (%tg-sane g))))

(test txgraph-set-transaction-fee-rechunks
  "SetTransactionFee re-linearizes and re-chunks the cluster."
  (let* ((g (%tg-new))
         (parent (%tg-add g 1000 1000))
         (child (%tg-add g 1000 1000)))
    (%tg-dep g parent child)
    ;; Equal feerates: two chunks (absorption needs strictly higher).
    (is (= 2 (length (%tg-chunks g))))
    ;; Raise the child's fee: CPFP merges into one chunk.
    (%tg-setfee g child 3000)
    (let ((chunks (%tg-chunks g)))
      (is (= 1 (length chunks)))
      (is (%tg-ff= (cdr (first chunks)) 4000 2000)))
    ;; Drop it again: back to two chunks, parent first.
    (%tg-setfee g child 500)
    (let ((chunks (%tg-chunks g)))
      (is (= 2 (length chunks)))
      (is (equal (list parent) (car (first chunks))))
      (is (%tg-ff= (cdr (first chunks)) 1000 1000))
      (is (%tg-ff= (cdr (second chunks)) 500 1000)))
    ;; Removed handle: no-op.
    (%tg-rm g child)
    (%tg-setfee g child 999999)
    (is (= 1 (%tg-count g)))
    (is-true (%tg-sane g))))

;;;; Mining order (the comparator's tie-break chain)

(test txgraph-compare-main-order-feerate
  "Primary key: chunk feerate, descending."
  (let* ((g (%tg-new))
         (lo (%tg-add g 100 100))
         (hi (%tg-add g 900 100)))
    (is (= -1 (%tg-cmp g hi lo)))
    (is (= 1 (%tg-cmp g lo hi)))
    (is (= 0 (%tg-cmp g lo lo)))))

(test txgraph-compare-main-order-prefix-size
  "Equal feerate: the equal-feerate chunk prefix size breaks the tie,
ascending (txgraph.cpp:502-508) - the smaller chunk mines first."
  (let* ((g (%tg-new))
         (big (%tg-add g 2 2))            ; feerate 1, prefix size 2
         (small (%tg-add g 1 1)))         ; feerate 1, prefix size 1
    (is (= -1 (%tg-cmp g small big)))
    (is (= 1 (%tg-cmp g big small))))
  ;; Within one cluster: two equal-feerate chunks; the later one has the
  ;; larger prefix (sizes accumulate) and mines later.
  (let* ((g (%tg-new))
         (p (%tg-add g 5 5))
         (c (%tg-add g 5 5)))
    (%tg-dep g p c)
    (is (= 2 (length (%tg-chunks g))))
    (is (= -1 (%tg-cmp g p c)))
    (is (= 1 (%tg-cmp g c p)))))

(test txgraph-compare-main-order-fallback
  "Equal feerate and prefix in distinct clusters: the fallback order of the
chunks' maximal elements decides (default: handle creation order)."
  (let* ((g (%tg-new))
         (first-added (%tg-add g 7 7))
         (second-added (%tg-add g 7 7)))
    (is (= -1 (%tg-cmp g first-added second-added)))
    (is (= 1 (%tg-cmp g second-added first-added)))
    ;; The block builder emits them in that order.
    (let ((chunks (%tg-chunks g)))
      (is (equal (list (list first-added) (list second-added))
                 (mapcar #'car chunks))))))

(test txgraph-compare-main-order-custom-fallback
  "A custom fallback order (Core's mempool passes txid order) flips ties."
  (let* ((g (%tg-new :fallback-order
                     (lambda (a b) (signum (- (%tg-id b) (%tg-id a))))))
         (first-added (%tg-add g 7 7))
         (second-added (%tg-add g 7 7)))
    (is (= 1 (%tg-cmp g first-added second-added)))
    (let ((chunks (%tg-chunks g)))
      (is (equal (list (list second-added) (list first-added))
                 (mapcar #'car chunks))))
    (is-true (%tg-sane g))))

(test txgraph-compare-main-order-within-chunk
  "Within a single chunk, linearization position orders transactions."
  (let* ((g (%tg-new))
         (p (%tg-add g 100 1000))
         (c (%tg-add g 4900 1000)))
    (%tg-dep g p c)                       ; one CPFP chunk [p, c]
    (is (= 1 (length (%tg-chunks g))))
    (is (= -1 (%tg-cmp g p c)))
    (is (= 1 (%tg-cmp g c p)))))

;;;; Block builder

(test txgraph-block-builder-order-and-skip
  "Chunks are drawn in mining order across clusters; Skip suppresses the
remainder of the skipped chunk's cluster (Core txgraph.cpp:3241-3251)."
  (let* ((g (%tg-new))
         ;; Cluster X: two chunks, feerates 30 then 10.
         (x1 (%tg-add g 30 1))
         (x2 (%tg-add g 10 1))
         ;; Singleton s: feerate 20, slots between them.
         (s (%tg-add g 20 1)))
    (%tg-dep g x1 x2)
    (is (equal (list (list x1) (list s) (list x2))
               (mapcar #'car (%tg-chunks g))))
    ;; Skip x1's chunk: s is offered, x2 is suppressed.
    (let ((b (bl.mp:make-block-builder g))
          (emitted '()))
      (unwind-protect
           (progn
             (multiple-value-bind (txs feerate)
                 (bl.mp:block-builder-current-chunk b)
               (is (equal (list x1) txs))
               (is (%tg-ff= feerate 30 1)))
             (bl.mp:block-builder-skip b)
             (loop (multiple-value-bind (txs nil-feerate)
                       (bl.mp:block-builder-current-chunk b)
                     (declare (ignore nil-feerate))
                     (unless txs (return))
                     (push txs emitted)
                     (bl.mp:block-builder-include b))))
        (bl.mp:block-builder-finish b))
      (is (equal (list (list s)) (nreverse emitted))))
    ;; Skipping the singleton instead leaves cluster X complete.
    (let ((b (bl.mp:make-block-builder g))
          (emitted '()))
      (unwind-protect
           (loop (multiple-value-bind (txs nil-feerate)
                     (bl.mp:block-builder-current-chunk b)
                   (declare (ignore nil-feerate))
                   (unless txs (return))
                   (if (equal txs (list s))
                       (bl.mp:block-builder-skip b)
                       (progn (push txs emitted)
                              (bl.mp:block-builder-include b)))))
        (bl.mp:block-builder-finish b))
      (is (equal (list (list x1) (list x2)) (nreverse emitted))))))

(test txgraph-block-builder-blocks-mutation
  "While a builder exists, mutators are disallowed (Core
m_main_chunkindex_observers); after finish they work again."
  (let* ((g (%tg-new))
         (a (%tg-add g 5 5))
         (b (bl.mp:make-block-builder g)))
    (unwind-protect
         (progn
           (signals error (%tg-add g 1 1))
           (signals error (%tg-rm g a))
           (signals error (%tg-setfee g a 6))
           ;; Queries stay available.
           (is-true (%tg-exists g a)))
      (bl.mp:block-builder-finish b))
    (is (%tg-add g 1 1))
    (is (= 2 (%tg-count g)))))

;;;; The incremental mining index (Core m_main_chunkindex)

(test txgraph-chunk-index-is-maintained-incrementally
  "Every mutation path leaves the mining index equal to a from-scratch
rebuild: Core clears a cluster's ChunkData before touching it and creates the
new chunks afterwards (txgraph.cpp:881-900 driven from Cluster::Updated,
txgraph.cpp:1072-1146), and the index is never recomputed from the whole
pool. Covers add, cross-cluster merge, in-cluster dependency, fee change,
split by removal, cluster drop and the empty graph."
  (let* ((g (%tg-new))
         (a (%tg-add g 1000 100))
         (b (%tg-add g 3000 100))
         (c (%tg-add g 2000 100))
         (d (%tg-add g 500 100)))
    (is-true (%tg-index-oracle-agree-p g))
    (is-true (%tg-sane g))
    ;; Merge two singleton clusters, then grow the merged one.
    (%tg-dep g a b)
    (is-true (%tg-index-oracle-agree-p g))
    (%tg-dep g b c)
    (is-true (%tg-index-oracle-agree-p g))
    ;; Two chunks in the merged a<-b<-c cluster (b lifts a into its chunk),
    ;; plus the untouched singleton D.
    (is (= 3 (length (%tg-chunks g))))
    ;; A fee change rechunks in place.
    (%tg-setfee g a 9000)
    (is-true (%tg-index-oracle-agree-p g))
    (%tg-setfee g a 1000)
    (is-true (%tg-index-oracle-agree-p g))
    ;; Removing the middle transaction splits the cluster.
    (%tg-rm g b)
    (is-true (%tg-index-oracle-agree-p g))
    (is-true (%tg-sane g))
    ;; Dropping singleton clusters, down to an empty graph.
    (%tg-rm g d)
    (is-true (%tg-index-oracle-agree-p g))
    (%tg-rm g a)
    (%tg-rm g c)
    (is-true (%tg-index-oracle-agree-p g))
    (is (zerop (%tg-count g)))
    (is-true (%tg-empty-ff-p (nth-value 1 (%tg-worst g)))))
  ;; Positive control: the oracle comparison is not vacuous. Extract one
  ;; chunk from the live index without touching its cluster and both the
  ;; agreement predicate and TXGRAPH-SANITY-CHECK must notice.
  (let ((g (%tg-new)))
    (%tg-add g 1000 100)
    (%tg-add g 2000 100)
    (is-true (%tg-index-oracle-agree-p g))
    (is-true (%tg-sane g))
    (%tg-drop-one-index-chunk g)
    (is-false (%tg-index-oracle-agree-p g))
    (signals error (%tg-sane g))))

(test txgraph-eviction-cost-does-not-scale-with-the-pool
  "TIMING-SENSITIVE. One eviction is an O(log C) read of the mining index's
last node plus one removal (Core GetWorstMainChunk reading
m_main_chunkindex.rbegin(), txgraph.cpp:3258-3266) - it must not re-sort the
pool. 200 evictions from a 50,000-transaction graph finish in about 0.2 ms
here; the ceiling is a full second, a ~5,000x margin, so a loaded shared
container cannot make this flake. When the index was rebuilt on every
mutation the same loop cost about 6.8 s (0.034 s per eviction) and grew
linearly with the pool."
  (let* ((g (%tg-fill-singletons 50000))
         (start (get-internal-real-time)))
    (dotimes (i 200)
      (multiple-value-bind (handles feerate) (%tg-worst g)
        (declare (ignore feerate))
        (dolist (h handles) (%tg-rm g h))))
    (let ((secs (float (/ (- (get-internal-real-time) start)
                          internal-time-units-per-second))))
      ;; Positive control for the cost assertion: the loop really evicted 200
      ;; transactions, so an empty or short-circuiting eviction path cannot
      ;; pass the ceiling vacuously.
      (is (= 49800 (%tg-count g)))
      (is (< secs 1)
          "200 evictions from a 50,000-transaction graph took ~,3F s -- the ~
mining index is being rebuilt instead of maintained" secs))))

;;;; Oversized behavior

(test txgraph-oversized-by-count
  "A dependency whose merged cluster would exceed the count limit is held
pending; the graph is oversized, restricted queries signal, mutators and
the always-available queries keep working (txgraph.h:122-134)."
  (let* ((g (%tg-new :max-cluster-count 2))
         (a1 (%tg-add g 1 1))
         (a2 (%tg-add g 2 1))
         (b1 (%tg-add g 3 1)))
    (%tg-dep g a1 a2)
    (is-false (%tg-oversized g))
    (%tg-dep g a2 b1)                     ; would-be cluster of 3 > 2
    (is-true (%tg-oversized g))
    (is-true (%tg-sane g))
    ;; The dependency is NOT applied while oversized.
    (is (= 3 (%tg-count g)))
    (is-true (%tg-exists g b1))
    (is (%tg-ff= (%tg-feerate g b1) 3 1))
    (signals error (%tg-anc g b1))
    (signals error (%tg-desc g b1))
    (signals error (%tg-cluster g b1))
    (signals error (%tg-chunk-feerate g b1))
    (signals error (%tg-cmp g a1 b1))
    (signals error (%tg-distinct g (list a1 b1)))
    (signals error (%tg-worst g))
    (signals error (bl.mp:make-block-builder g))
    ;; Mutators still work while oversized.
    (%tg-setfee g b1 30)
    (is (%tg-ff= (%tg-feerate g b1) 30 1))
    ;; Removing a1 shrinks the group to 2: the pending dep applies eagerly.
    (%tg-rm g a1)
    (is-false (%tg-oversized g))
    (is (equal (%tg-ids (list a2 b1)) (%tg-ids (%tg-cluster g b1))))
    (is (equal (%tg-ids (list a2 b1)) (%tg-ids (%tg-anc g b1))))
    (is-true (%tg-sane g))))

(test txgraph-oversized-clears-when-endpoint-removed
  "Removing a pending dependency's endpoint drops the dependency."
  (let* ((g (%tg-new :max-cluster-count 2))
         (a1 (%tg-add g 1 1))
         (a2 (%tg-add g 2 1))
         (b1 (%tg-add g 3 1)))
    (%tg-dep g a1 a2)
    (%tg-dep g a2 b1)
    (is-true (%tg-oversized g))
    (%tg-rm g a2)                         ; parent of the pending dep
    (is-false (%tg-oversized g))
    ;; The dep died with its endpoint: b1 is still a singleton.
    (is (equal (list b1) (%tg-cluster g b1)))
    (is (equal (%tg-ids (list a1)) (%tg-ids (%tg-cluster g a1))))
    (is-true (%tg-sane g))))

(test txgraph-oversized-by-size
  (let* ((g (%tg-new :max-cluster-size 300))
         (a (%tg-add g 10 200))
         (b (%tg-add g 20 200)))
    (is-false (%tg-oversized g))
    (%tg-dep g a b)                       ; 400 > 300
    (is-true (%tg-oversized g))
    (is-true (%tg-sane g))
    (%tg-rm g b)
    (is-false (%tg-oversized g))))

(test txgraph-individually-oversized-transaction
  "A single transaction larger than the size limit makes the graph
oversized on its own (Core OVERSIZED_SINGLETON, txgraph.cpp:2244-2259);
Trim removes it."
  (let* ((g (%tg-new))
         (huge (%tg-add g 1000 150000)))  ; > 101,000 vB
    (is-true (%tg-oversized g))
    (is-true (%tg-exists g huge))
    (is (%tg-ff= (%tg-feerate g huge) 1000 150000))
    (signals error (%tg-anc g huge))
    (is-true (%tg-sane g))
    (let ((removed (%tg-trim g)))
      (is (equal (list huge) removed)))
    (is-false (%tg-oversized g))
    (is-false (%tg-exists g huge))
    (is (= 0 (%tg-count g)))
    (is-true (%tg-sane g))))

;;;; Trim

(test txgraph-trim-noop-when-not-oversized
  (let ((g (%tg-new)))
    (%tg-add g 1 1)
    (is (null (%tg-trim g)))
    (is (= 1 (%tg-count g)))))

(test txgraph-trim-count-limit
  "Trim keeps the greedy best-chunk-feerate prefix of the would-be cluster
and removes the rest (Core Trim, txgraph.cpp:3285-3533)."
  (let* ((g (%tg-new :max-cluster-count 3))
         ;; Cluster X: x1 (10 sat/vB) -> x2 (5 sat/vB).
         (x1 (%tg-add g 1000 100))
         (x2 (%tg-add g 500 100))
         ;; Cluster Y: y1 (20 sat/vB) -> y2 (1 sat/vB).
         (y1 (%tg-add g 2000 100))
         (y2 (%tg-add g 100 100)))
    (%tg-dep g x1 x2)
    (%tg-dep g y1 y2)
    (is-false (%tg-oversized g))
    (%tg-dep g x2 y1)                     ; would-be cluster of 4 > 3
    (is-true (%tg-oversized g))
    ;; Greedy: x1 (10) -> x2 (5, count 2) -> y1 (20, count 3) -> y2 would
    ;; make 4: dropped.
    (let ((removed (%tg-trim g)))
      (is (equal (list y2) removed)))
    (is-false (%tg-oversized g))
    (is-false (%tg-exists g y2))
    ;; The pending dependency was applied after trimming.
    (is (equal (%tg-ids (list x1 x2 y1)) (%tg-ids (%tg-cluster g x1))))
    (is (equal (%tg-ids (list x1 x2 y1)) (%tg-ids (%tg-anc g y1))))
    (is-true (%tg-sane g))))

(test txgraph-trim-size-limit
  (let* ((g (%tg-new :max-cluster-size 300))
         (x1 (%tg-add g 1000 100))
         (x2 (%tg-add g 500 100))
         (y1 (%tg-add g 2000 100))
         (y2 (%tg-add g 100 100)))
    (%tg-dep g x1 x2)
    (%tg-dep g y1 y2)
    (%tg-dep g x2 y1)                     ; would-be size 400 > 300
    (is-true (%tg-oversized g))
    (let ((removed (%tg-trim g)))
      (is (equal (list y2) removed)))
    (is-false (%tg-oversized g))
    (is (= 3 (%tg-count g)))
    (is-true (%tg-sane g))))

(test txgraph-trim-blocked-descendant
  "A transaction whose dependency chain is cut is removed no matter how
high its own feerate is (unmet dependencies are never jumped)."
  (let* ((g (%tg-new :max-cluster-count 2))
         (c1 (%tg-add g 100 100))
         (c2 (%tg-add g 100 100))
         (c3 (%tg-add g 99000 100)))      ; very high feerate
    (%tg-dep g c1 c2)
    (%tg-dep g c2 c3)                     ; would-be cluster of 3 > 2
    (is-true (%tg-oversized g))
    (let ((removed (%tg-trim g)))
      (is (equal (list c3) removed)))
    (is (equal (%tg-ids (list c1 c2)) (%tg-ids (%tg-cluster g c1))))
    (is-true (%tg-sane g))))

(test txgraph-trim-multiple-groups
  "Trim handles several independent over-limit groups in one call."
  (let* ((g (%tg-new :max-cluster-count 2))
         (a1 (%tg-add g 300 100)) (a2 (%tg-add g 200 100)) (a3 (%tg-add g 100 100))
         (b1 (%tg-add g 900 100)) (b2 (%tg-add g 800 100)) (b3 (%tg-add g 50 100)))
    (%tg-dep g a1 a2) (%tg-dep g a2 a3)
    (%tg-dep g b1 b2) (%tg-dep g b2 b3)
    (is-true (%tg-oversized g))
    (let ((removed (%tg-trim g)))
      (is (equal (%tg-ids (list a3 b3)) (%tg-ids removed))))
    (is-false (%tg-oversized g))
    (is (= 4 (%tg-count g)))
    (is (equal (%tg-ids (list a1 a2)) (%tg-ids (%tg-cluster g a1))))
    (is (equal (%tg-ids (list b1 b2)) (%tg-ids (%tg-cluster g b1))))
    (is-true (%tg-sane g))))

;;;; Randomized property tests vs the brute-force model

(test txgraph-randomized-vs-model
  "Deterministic random op sequences (add/remove/add-dep/set-fee) with the
default (never-oversized at these sizes) limits: every query, the chunk
walk, the comparator, worst-chunk and the sanity check must agree with the
brute-force closure model."
  (let ((rng (make-deterministic-rng 6364136223846793005)))
    (dotimes (iter 25)
      (let ((g (%tg-new))
            (model (make-array 0 :adjustable t :fill-pointer 0))
            (idx-of (make-hash-table :test 'eq)))
        (flet ((live ()
                 (loop for i from 0 below (length model)
                       when (%tgm-tx-live (aref model i)) collect i)))
          (dotimes (op 60)
            (let ((r (funcall rng 100))
                  (live (live)))
              (cond ((or (null live) (< r 35))
                     (let* ((fee (- (funcall rng 10001) 2000))
                            (size (1+ (funcall rng 1000)))
                            (h (%tg-add g fee size)))
                       (setf (gethash h idx-of) (%tgm-add model fee size h))))
                    ((< r 70)
                     (when (rest live)
                       (let ((p (nth (funcall rng (length live)) live))
                             (c (nth (funcall rng (length live)) live)))
                         ;; Skip self-deps and deps that would form a cycle.
                         (unless (or (= p c)
                                     (logbitp c (%tgm-tx-anc (aref model p))))
                           (%tg-dep g (%tgm-tx-handle (aref model p))
                                    (%tgm-tx-handle (aref model c)))
                           (%tgm-dep model p c)))))
                    ((< r 85)
                     (let ((i (nth (funcall rng (length live)) live)))
                       (%tg-rm g (%tgm-tx-handle (aref model i)))
                       (%tgm-rm model i)))
                    (t
                     (let ((i (nth (funcall rng (length live)) live))
                           (fee (- (funcall rng 10001) 2000)))
                       (%tg-setfee g (%tgm-tx-handle (aref model i)) fee)
                       (setf (%tgm-tx-fee (aref model i)) fee))))
              ;; Verify a transient mid-run state once per iteration.
              (when (= op 29) (%tg-verify-model g model idx-of rng))))
          (%tg-verify-model g model idx-of rng))))))

(test txgraph-randomized-block-builder-skip
  "Random skip decisions: the emitted chunk sequence must equal a
simulation over the full chunk list where skipping suppresses the rest of
the chunk's cluster."
  (let ((rng (make-deterministic-rng 88172645463325252)))
    (dotimes (iter 20)
      ;; Build a random (never-oversized) graph.
      (let ((g (%tg-new))
            (model (make-array 0 :adjustable t :fill-pointer 0))
            (idx-of (make-hash-table :test 'eq)))
        (dotimes (k (+ 5 (funcall rng 20)))
          (let* ((fee (- (funcall rng 10001) 2000))
                 (size (1+ (funcall rng 1000)))
                 (h (%tg-add g fee size)))
            (setf (gethash h idx-of) (%tgm-add model fee size h))))
        (dotimes (k (funcall rng 25))
          (let ((p (funcall rng (length model)))
                (c (funcall rng (length model))))
            (unless (or (= p c) (logbitp c (%tgm-tx-anc (aref model p))))
              (%tg-dep g (%tgm-tx-handle (aref model p))
                       (%tgm-tx-handle (aref model c)))
              (%tgm-dep model p c))))
        ;; First pass: full chunk list; precompute one skip decision per
        ;; potentially-offered chunk.
        (let* ((chunks (%tg-chunks g))
               (decisions (loop repeat (length chunks)
                                collect (< (funcall rng 100) 40)))
               ;; Simulate: cluster key = model component of the chunk head.
               (expected '()))
          (let ((excluded '())
                (ds decisions))
            (dolist (chunk chunks)
              (let ((comp (%tgm-component
                           model (gethash (first (car chunk)) idx-of))))
                (unless (member comp excluded :test #'=)
                  (let ((skip (pop ds)))
                    (if skip
                        (push comp excluded)
                        (push (car chunk) expected)))))))
          (setf expected (nreverse expected))
          ;; Drive the real builder with the same decisions.
          (let ((b (bl.mp:make-block-builder g))
                (included '())
                (ds decisions))
            (unwind-protect
                 (loop (multiple-value-bind (txs nil-feerate)
                           (bl.mp:block-builder-current-chunk b)
                         (declare (ignore nil-feerate))
                         (unless txs (return))
                         (if (pop ds)
                             (bl.mp:block-builder-skip b)
                             (progn (push txs included)
                                    (bl.mp:block-builder-include b)))))
              (bl.mp:block-builder-finish b))
            (is (equal expected (nreverse included)))))))))

(test txgraph-randomized-oversized-and-trim
  "Random op sequences under tiny limits, including infeasible dependencies
and Trim. Oversized reporting must match the model's component analysis at
every step; removals take whole descendant sets (the defined-behavior
regime, txgraph.h:82-92); Trim must restore the limits, remove
descendant-closed sets drawn only from over-limit components, and leave a
graph equivalent to the model."
  (let ((rng (make-deterministic-rng 2718281828459045235)))
    (dotimes (iter 25)
      (let* ((max-count (+ 2 (funcall rng 5)))
             (max-size (+ 800 (funcall rng 1500)))
             (g (%tg-new :max-cluster-count max-count :max-cluster-size max-size))
             (model (make-array 0 :adjustable t :fill-pointer 0))
             (idx-of (make-hash-table :test 'eq)))
        (flet ((live ()
                 (loop for i from 0 below (length model)
                       when (%tgm-tx-live (aref model i)) collect i))
               (check-oversized ()
                 (is (eq (not (null (%tgm-oversized-p model max-count max-size)))
                         (not (null (%tg-oversized g)))))))
          (dotimes (op 40)
            (let ((r (funcall rng 100))
                  (live (live)))
              (cond ((or (null live) (< r 35))
                     (let* ((fee (- (funcall rng 10001) 2000))
                            (size (1+ (funcall rng 1000)))
                            (h (%tg-add g fee size)))
                       (setf (gethash h idx-of) (%tgm-add model fee size h))))
                    ((< r 65)
                     (when (rest live)
                       (let ((p (nth (funcall rng (length live)) live))
                             (c (nth (funcall rng (length live)) live)))
                         (unless (or (= p c)
                                     (logbitp c (%tgm-tx-anc (aref model p))))
                           (%tg-dep g (%tgm-tx-handle (aref model p))
                                    (%tgm-tx-handle (aref model c)))
                           (%tgm-dep model p c)))))
                    ((< r 75)
                     ;; Remove a transaction together with all its
                     ;; descendants (the regime where removal ordering
                     ;; relative to pending dependencies is well-defined).
                     (let* ((i (nth (funcall rng (length live)) live))
                            (victims '()))
                       (bl.mp:do-bits
                           (j (%tgm-tx-desc (aref model i)))
                         (push j victims))
                       (dolist (j victims)
                         (%tg-rm g (%tgm-tx-handle (aref model j)))
                         (%tgm-rm model j))))
                    ((< r 85)
                     (let ((i (nth (funcall rng (length live)) live))
                           (fee (- (funcall rng 10001) 2000)))
                       (%tg-setfee g (%tgm-tx-handle (aref model i)) fee)
                       (setf (%tgm-tx-fee (aref model i)) fee)))
                    (t
                     ;; Trim.
                     (let ((was-oversized (%tg-oversized g))
                           (over-bits 0))
                       (dolist (comp (%tgm-components model))
                         (multiple-value-bind (count size)
                             (%tgm-comp-stats model comp)
                           (when (or (> count max-count) (> size max-size))
                             (setf over-bits (logior over-bits comp)))))
                       ;; Individually-oversized txs count as over-limit.
                       (dotimes (i (length model))
                         (let ((tx (aref model i)))
                           (when (and (%tgm-tx-live tx)
                                      (> (%tgm-tx-size tx) max-size))
                             (setf over-bits (logior over-bits (ash 1 i))))))
                       (let* ((removed (%tg-trim g))
                              (removed-bits 0))
                         (dolist (h removed)
                           (setf removed-bits
                                 (logior removed-bits (ash 1 (gethash h idx-of)))))
                         (is (eq (not (null was-oversized))
                                 (not (null removed))))
                         ;; Only over-limit components lose transactions,
                         ;; and removals are descendant-closed.
                         (is (zerop (logandc2 removed-bits over-bits)))
                         (dolist (h removed)
                           (is (zerop (logandc2
                                       (%tgm-tx-desc (aref model (gethash h idx-of)))
                                       removed-bits))))
                         (dolist (h removed)
                           (%tgm-rm model (gethash h idx-of)))
                         (is-false (%tg-oversized g))))))
              (check-oversized)
              (is-true (%tg-sane g))
              ;; While oversized the restricted queries must signal; the
              ;; always-available ones must keep working.
              (let ((live-now (live)))
                (when live-now
                  (let ((h (%tgm-tx-handle
                            (aref model (nth (funcall rng (length live-now))
                                             live-now)))))
                    (if (%tg-oversized g)
                        (progn (signals error (%tg-anc g h))
                               (is-true (%tg-exists g h)))
                        (is (equal (%tgm-set-ids
                                    model (%tgm-tx-anc (aref model (gethash h idx-of))))
                                   (%tg-ids (%tg-anc g h))))))))))
          ;; Finish the iteration in a fully-verified state.
          (let ((removed (%tg-trim g)))
            (dolist (h removed)
              (%tgm-rm model (gethash h idx-of))))
          (%tg-verify-model g model idx-of rng))))))

;;;; Diagram RBF staging (txgraph-rbf-diagrams)
;;;;
;;;; Port of Bitcoin Core src/test/rbf_tests.cpp calc_feerate_diagram_rbf: a
;;;; single candidate replacing various sets, asserting the exact before/after
;;;; feerate diagrams the staging returns. Core measures size in adjusted
;;;; weight; we (like the rest of our txgraph) measure it in vbytes — the
;;;; comparison is scale-free, so we use plain sizes here.

(defun %tg-diag (ffs)
  "A diagram (list of feefracs) as a list of (fee . size) conses."
  (mapcar (lambda (f) (cons (bl.mp:feefrac-fee f)
                            (bl.mp:feefrac-size f)))
          ffs))

(defun %tg-rbf (g removed parents fee size)
  (bl.mp:txgraph-rbf-diagrams g removed parents fee size))

(defun %tg-secs (thunk)
  "Wall-clock seconds one call of THUNK takes."
  (let ((start (get-internal-real-time)))
    (funcall thunk)
    (float (/ (- (get-internal-real-time) start)
              internal-time-units-per-second)
           1d0)))

(defun %tg-chain-depgraph (n)
  "A bare depgraph of N transactions in one chain, with the same spread of
feerates the staging fixture below uses."
  (let ((dg (bl.mp:make-depgraph)))
    (dotimes (i n dg)
      (bl.mp:depgraph-add-transaction
       dg (bl.mp:make-feefrac (+ 1000 (mod (* i 7919) 100003)) 141))
      (when (plusp i)
        (bl.mp:depgraph-add-dependencies dg (ash 1 (1- i)) i)))))

(defun %tg-diagram-size (diagram)
  "Total size covered by a diagram's chunks: every staged transaction appears
in exactly one chunk, so this counts what the staging actually looked at."
  (reduce #'+ diagram :key #'bl.mp:feefrac-size :initial-value 0))

(test rbf-diagrams-replace-singleton
  "Replacing a lone tx: old diagram is its chunk, new is the candidate's."
  (let* ((g (%tg-new))
         (low (%tg-add g 100 100)))     ; feerate 1
    ;; Zero-fee replacement.
    (multiple-value-bind (old new) (%tg-rbf g (list low) '() 0 100)
      (is (equal '((100 . 100)) (%tg-diag old)))
      (is (equal '((0 . 100)) (%tg-diag new)))
      ;; Does not improve the diagram.
      (is (not (eq :greater (bl.mp:compare-chunks new old)))))
    ;; High-fee replacement strictly improves.
    (multiple-value-bind (old new) (%tg-rbf g (list low) '() 10000 100)
      (is (equal '((100 . 100)) (%tg-diag old)))
      (is (equal '((10000 . 100)) (%tg-diag new)))
      (is (eq :greater (bl.mp:compare-chunks new old))))
    ;; The staging did not mutate the live graph.
    (is-true (%tg-sane g))
    (is (= 1 (%tg-count g)))))

(test rbf-diagrams-replace-cpfp-cluster
  "A low->high CPFP cluster is a single chunk; the diagrams reflect removing
both members or only the child."
  (let* ((g (%tg-new))
         (low (%tg-add g 100 100))       ; parent, feerate 1
         (high (%tg-add g 10000 100)))   ; child, feerate 100
    (%tg-dep g low high)                 ; low -> high, one chunk (10100,200)
    ;; Replace the whole cluster.
    (multiple-value-bind (old new) (%tg-rbf g (list low high) '() 10000 100)
      (is (equal '((10100 . 200)) (%tg-diag old)))
      (is (equal '((10000 . 100)) (%tg-diag new))))
    ;; Replace only the CPFP child: the parent survives as its own chunk, so
    ;; the new diagram has two entries (Core replace_cpfp_child).
    (multiple-value-bind (old new) (%tg-rbf g (list high) '() 10000 100)
      (is (equal '((10100 . 200)) (%tg-diag old)))
      (is (equal '((10000 . 100) (100 . 100)) (%tg-diag new))))
    (is-true (%tg-sane g))
    (is (= 2 (%tg-count g)))))

(test rbf-diagrams-multiple-clusters
  "Conflicting with several independent clusters gathers all their chunks
into the old diagram; the single candidate is the whole new diagram."
  (let* ((g (%tg-new))
         (c1 (%tg-add g 100 100))
         (c2 (%tg-add g 200 100))
         (c3 (%tg-add g 300 100)))
    (multiple-value-bind (old new) (%tg-rbf g (list c1 c2 c3) '() 10000 100)
      (is (= 3 (length old)))
      (is (= 1 (length new)))
      ;; Old chunks are sorted by decreasing feerate.
      (is (equal '((300 . 100) (200 . 100) (100 . 100)) (%tg-diag old)))
      (is (equal '((10000 . 100)) (%tg-diag new))))
    (is-true (%tg-sane g))))

(test rbf-diagrams-candidate-merges-parents
  "The candidate's in-mempool parents' clusters are pulled into staging and
merged through it (new diagram is one chunk over parents + candidate)."
  (let* ((g (%tg-new))
         (p1 (%tg-add g 500 100))
         (p2 (%tg-add g 500 100))
         (victim (%tg-add g 100 100)))   ; the tx being replaced
    ;; Candidate spends p1 and p2 and conflicts with VICTIM.
    (multiple-value-bind (old new) (%tg-rbf g (list victim) (list p1 p2) 9000 100)
      ;; Old gathers the three touched clusters' chunks.
      (is (= 3 (length old)))
      ;; New: p1, p2 and the candidate merge into a single cluster. Since the
      ;; candidate's feerate dominates, they form one chunk.
      (is (equal '((10000 . 300)) (%tg-diag new))))
    (is-true (%tg-sane g))))

(test rbf-diagrams-uncalculable-when-oversized
  "When the staged replacement would exceed the cluster limits the diagram is
uncalculable (Core CalculateChunksForRBF returning an Error)."
  ;; A candidate merging two parents into a 3-tx cluster with a 2-tx cap.
  (let* ((g (%tg-new :max-cluster-count 2))
         (p1 (%tg-add g 500 100))
         (p2 (%tg-add g 500 100)))
    (multiple-value-bind (old new) (%tg-rbf g '() (list p1 p2) 9000 100)
      (is (eq :uncalculable old))
      (is (null new)))
    (is-false (%tg-oversized g))         ; live graph untouched
    (is-true (%tg-sane g)))
  ;; A candidate whose own size exceeds the size limit.
  (let* ((g (%tg-new :max-cluster-size 1000))
         (low (%tg-add g 100 100)))
    (multiple-value-bind (old new) (%tg-rbf g (list low) '() 5000 5000)
      (is (eq :uncalculable old))
      (is (null new)))
    (is-true (%tg-sane g))))

;;;; Package RBF staging (txgraph-package-rbf-diagrams, cluster mempool P8)
;;;;
;;;; Core PackageRBFChecks stages BOTH transactions of a 1-parent-1-child
;;;; package into the changeset before ImprovesFeerateDiagram
;;;; (validation.cpp:1080-1121); these mirror that two-addition staging.

(defun %tg-pkg-rbf (g removed pfee psize cfee csize)
  (bl.mp:txgraph-package-rbf-diagrams g removed pfee psize cfee csize))

(test package-rbf-diagrams-stages-both-as-cpfp-chunk
  "A low-fee parent + high-fee child stage as one CPFP chunk; replacing a
conflicting tx improves the diagram when the pair out-earns it."
  (let* ((g (%tg-new))
         (orig (%tg-add g 1000 100)))
    (multiple-value-bind (old new) (%tg-pkg-rbf g (list orig) 10 100 5000 100)
      (is (equal '((1000 . 100)) (%tg-diag old)))
      ;; Child feerate 50 > parent 0.1 -> one merged chunk (5010, 200).
      (is (equal '((5010 . 200)) (%tg-diag new)))
      (is (eq :greater (bl.mp:compare-chunks new old))))
    ;; The staging did not mutate the live graph.
    (is-true (%tg-sane g))
    (is (= 1 (%tg-count g)))))

(test package-rbf-diagrams-two-chunks-when-child-cheaper
  "A child at a lower feerate than its parent does NOT absorb it: the staged
pair contributes two chunks, parent first."
  (let* ((g (%tg-new))
         (orig (%tg-add g 1000 100)))
    (multiple-value-bind (old new) (%tg-pkg-rbf g (list orig) 5000 100 100 100)
      (is (equal '((1000 . 100)) (%tg-diag old)))
      (is (equal '((5000 . 100) (100 . 100)) (%tg-diag new))))
    (is-true (%tg-sane g))))

(test package-rbf-diagrams-survivors-kept
  "Conflicted-cluster survivors stay in the new diagram alongside the pair."
  (let* ((g (%tg-new))
         (keep (%tg-add g 700 100))
         (victim (%tg-add g 100 100)))
    (%tg-dep g keep victim)              ; one cluster, chunks (700,100) (100,100)
    (multiple-value-bind (old new) (%tg-pkg-rbf g (list victim) 10 100 5000 100)
      (is (equal '((700 . 100) (100 . 100)) (%tg-diag old)))
      ;; KEEP survives; the pair forms its own (5010, 200) chunk.
      (is (equal '((5010 . 200) (700 . 100)) (%tg-diag new)))
      (is (eq :greater (bl.mp:compare-chunks new old))))
    (is-true (%tg-sane g))
    (is (= 2 (%tg-count g)))))

(test package-rbf-diagrams-uncalculable-when-oversized
  "A package member whose size exceeds the cluster size limit makes the
staged diagram uncalculable (Core CheckMemPoolPolicyLimits failing,
\"too-large-cluster\")."
  (let* ((g (%tg-new :max-cluster-size 1000))
         (orig (%tg-add g 100 100)))
    (multiple-value-bind (old new) (%tg-pkg-rbf g (list orig) 100 100 90000 5000)
      (is (eq :uncalculable old))
      (is (null new)))
    (is-false (%tg-oversized g))
    (is-true (%tg-sane g))))

(test rbf-diagrams-staging-keeps-a-bridged-dependency
  "Staging COPIES the affected cluster's depgraph instead of replaying its
edges (Core Cluster::CopyToStaging, txgraph.cpp:1221-1237), and
DEPGRAPH-REMOVE-TRANSACTIONS only masks the removed positions out of the
closures, so evicting the middle of a chain leaves the grandparent an ancestor
of the grandchild. A and C therefore stay ONE staged cluster and chunk
together at 1100/200; had the copy dropped the bridge they would be two
singleton clusters and the new diagram would carry one chunk more."
  (let* ((g (%tg-new))
         (a (%tg-add g 100 100))        ; feerate 1
         (b (%tg-add g 100 100))        ; feerate 1, the evicted middle
         (c (%tg-add g 1000 100)))      ; feerate 10
    (%tg-dep g a b)
    (%tg-dep g b c)
    (multiple-value-bind (old new) (%tg-rbf g (list b) '() 5000 100)
      (is (equal '((1200 . 300)) (%tg-diag old)))
      (is (equal '((5000 . 100) (1100 . 200)) (%tg-diag new))))
    (is-true (%tg-sane g))
    (is (= 3 (%tg-count g)))))

(test rbf-diagrams-staging-costs-about-one-relinearization-per-cluster
  "TIMING-SENSITIVE, and calibrated rather than absolute. At the rule-5
maximum shape - 100 clusters (Core MAX_REPLACEMENT_CANDIDATES) of 64
transactions (the largest cluster that can exist), the candidate conflicting
with every cluster's tail - staging must cost about what Core pays after
CopyToStaging: one relinearization per affected cluster
(txgraph.cpp:1221-1237,1693-1706). The yardstick is 100 fresh optimal
LINEARIZE calls on the same 64-transaction chain - the work no implementation
can avoid - measured on the same machine in the same run, so a slow or loaded
container moves both sides together. Rebuilding each staged cluster
transaction by transaction, which is what this replaced, cost about 33 times
the yardstick."
  (let ((g (%tg-new))
        (tails '()))
    (dotimes (i 100)
      (let ((prev nil))
        (dotimes (k 64)
          (let ((h (%tg-add g (+ 1000 (mod (* (+ (* i 64) k) 7919) 100003)) 141)))
            (when prev (%tg-dep g prev h))
            (setf prev h)))
        (push prev tails)))
    (is (= 6400 (%tg-count g)))
    ;; One settling call, which also carries the positive control: the
    ;; diagrams account for every transaction on each side, so a staging that
    ;; quietly did nothing could not pass the cost assertion below.
    (multiple-value-bind (old new) (%tg-rbf g tails '() 100000000 200)
      (is (= (* 6400 141) (%tg-diagram-size old)))
      (is (= (+ (* 6300 141) 200) (%tg-diagram-size new))))
    (let* ((chain (%tg-chain-depgraph 64))
           (staged (%tg-secs (lambda () (%tg-rbf g tails '() 100000000 200))))
           (yardstick (%tg-secs (lambda ()
                                  (dotimes (i 100) (bl.mp:linearize chain))))))
      (is (< staged (* 5 yardstick))
          "staging 100 clusters of 64 took ~,4F s against ~,4F s for the 100 ~
relinearizations it cannot avoid -- ~,1Fx, so the staged clusters are being ~
rebuilt rather than copied"
          staged yardstick (/ staged (max yardstick 1d-9))))))
