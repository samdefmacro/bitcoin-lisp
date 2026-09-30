(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/txgraph.cpp at the pin (d3056bc149): the TxGraph
;;;; simulation. A fuzz-chosen sequence of operations runs against the real
;;;; graph (src/mempool/txgraph.lisp) and against SimTxGraph -- a naive model
;;;; that keeps every transaction, connected or not, in one dependency graph of
;;;; transitive closures -- and every answer the real graph gives is checked
;;;; against the model as it is given; at the end the two are compared in full:
;;;; clusters, ancestry, the mining order CompareMainOrder implies (total,
;;;; topological, optimal, deterministic, tie-broken as Core breaks ties), the
;;;; block builder's walk, the worst chunk, and every chunk feerate.
;;;;
;;;; What the port has and Core's graph has not, and the reverse. The port has
;;;; no staging level (StartStaging / CommitStaging / AbortStaging, the Level
;;;; argument, GetMainStagingDiagrams), no work queue (DoWork: every mutation
;;;; relinearizes on the spot, so every cluster is always optimal -- Core's
;;;; `real_is_optimal' is always true here and the optimality checks always
;;;; run), no GetMainMemoryUsage, and no Ref destructor (a removed handle stays
;;;; a valid object, which is what `~Ref' of a removed transaction becomes).
;;;; In place of the staging diagrams it has TXGRAPH-RBF-DIAGRAMS, the scratch
;;;; copy the mempool's RBF check stages a replacement on; this target drives
;;;; it with a random replacement and checks both diagrams against the model's
;;;; own optimal chunkings, which is the full check Core's target makes of
;;;; GetMainStagingDiagrams (:1262-1310).

(def-suite :fuzz-txgraph-tests :in :bitcoin-lisp-tests
  :description "Core fuzz/txgraph.cpp target")

(in-suite :fuzz-txgraph-tests)

;;; --- SimTxGraph (txgraph.cpp:37-301) ------------------------------------------------

(defparameter *simtx-max-transactions* (* 2 bl.mp:+max-cluster-count+)
  "SimTxGraph::MAX_TRANSACTIONS: twice the cluster count limit, so the
simulation holds more transactions than fit in one cluster.")

(defstruct (simtx (:constructor %make-simtx (max-count max-size)))
  "SimTxGraph: every live transaction at a position of one closure graph
(Core DepGraph<BitSet<128>>, as integers), the position of each handle, and
the handles removed but not yet destroyed."
  (fee (make-array *simtx-max-transactions* :initial-element 0))
  (size (make-array *simtx-max-transactions* :initial-element 0))
  (anc (make-array *simtx-max-transactions* :initial-element 0))
  (desc (make-array *simtx-max-transactions* :initial-element 0))
  (used 0)
  (refs (make-array *simtx-max-transactions* :initial-element nil))
  (revmap (make-hash-table :test 'eq))
  (removed '())
  (max-count 64)
  (max-size 0))

(defun simtx-count (sim) (logcount (simtx-used sim)))

(defun simtx-find (sim handle)
  "SimTxGraph::Find: HANDLE's position, or NIL (Core's MISSING)."
  (gethash handle (simtx-revmap sim)))

(defun simtx-feefrac (sim pos)
  (bl.mp:make-feefrac (aref (simtx-fee sim) pos) (aref (simtx-size sim) pos)))

(defun simtx-set-feefrac (sim set)
  "The summed feerate of the positions in SET."
  (let ((fee 0) (size 0))
    (bl.mp:do-bits (i set)
      (incf fee (aref (simtx-fee sim) i))
      (incf size (aref (simtx-size sim) i)))
    (bl.mp:make-feefrac fee size)))

(defun simtx-component (sim todo pos)
  "DepGraph::GetConnectedComponent(TODO, POS) over the closures."
  (let ((ret 0) (to-add (ash 1 pos)))
    (loop
      (let ((old ret))
        (bl.mp:do-bits (i to-add)
          (setf ret (logior ret (aref (simtx-anc sim) i) (aref (simtx-desc sim) i))))
        (setf ret (logand ret todo)
              to-add (logandc2 ret old))
        (when (zerop to-add) (return ret))))))

(defun simtx-components (sim)
  "SimTxGraph::GetComponents: every connected component, lowest position first."
  (let ((todo (simtx-used sim)) (out '()))
    (loop until (zerop todo)
          do (let ((c (simtx-component sim todo (bits-first todo))))
               (push c out)
               (setf todo (logandc2 todo c))))
    (nreverse out)))

(defun simtx-component-oversized-p (sim component)
  (or (> (logcount component) (simtx-max-count sim))
      (> (bl.mp:feefrac-size (simtx-set-feefrac sim component)) (simtx-max-size sim))))

(defun simtx-oversized-p (sim)
  "SimTxGraph::IsOversized: some component over the count or size limit."
  (some (lambda (c) (simtx-component-oversized-p sim c)) (simtx-components sim)))

(defun simtx-add-transaction (sim graph fee size txid)
  "SimTxGraph::AddTransaction, on the model and on GRAPH."
  (let ((pos (position-if-not (lambda (i) (logbitp i (simtx-used sim)))
                              (loop for i below *simtx-max-transactions* collect i))))
    (setf (aref (simtx-fee sim) pos) fee
          (aref (simtx-size sim) pos) size
          (aref (simtx-anc sim) pos) (ash 1 pos)
          (aref (simtx-desc sim) pos) (ash 1 pos)
          (simtx-used sim) (logior (simtx-used sim) (ash 1 pos)))
    (let ((handle (bl.mp:txgraph-add-transaction graph fee size txid)))
      (setf (aref (simtx-refs sim) pos) handle
            (gethash handle (simtx-revmap sim)) pos)
      handle)))

(defun simtx-add-dependency (sim parent child)
  "SimTxGraph::AddDependency: DepGraph::AddDependencies({PARENT}, CHILD) on
the model when both handles are live in it."
  (let ((par (simtx-find sim parent))
        (chl (simtx-find sim child)))
    (when (and par chl)
      (let ((par-anc (logandc2 (aref (simtx-anc sim) par) (aref (simtx-anc sim) chl))))
        (unless (zerop par-anc)
          (let ((chl-des (aref (simtx-desc sim) chl)))
            (bl.mp:do-bits (a par-anc)
              (setf (aref (simtx-desc sim) a) (logior (aref (simtx-desc sim) a) chl-des)))
            (bl.mp:do-bits (d chl-des)
              (setf (aref (simtx-anc sim) d) (logior (aref (simtx-anc sim) d) par-anc)))))))))

(defun simtx-drop-position (sim pos)
  "DepGraph::RemoveTransactions({POS}): the position goes, and the closures
keep what ran through it."
  (setf (simtx-used sim) (logandc2 (simtx-used sim) (ash 1 pos)))
  (dotimes (i *simtx-max-transactions*)
    (setf (aref (simtx-anc sim) i) (logand (aref (simtx-anc sim) i) (simtx-used sim))
          (aref (simtx-desc sim) i) (logand (aref (simtx-desc sim) i) (simtx-used sim))))
  (let ((handle (aref (simtx-refs sim) pos)))
    (remhash handle (simtx-revmap sim))
    (setf (aref (simtx-refs sim) pos) nil)
    handle))

(defun simtx-remove-transaction (sim handle)
  "SimTxGraph::RemoveTransaction: the handle joins the removed list."
  (let ((pos (simtx-find sim handle)))
    (when pos
      (push (simtx-drop-position sim pos) (simtx-removed sim)))))

(defun simtx-destroy-transaction (sim handle)
  "SimTxGraph::DestroyTransaction: gone from the graph or from the removed list."
  (let ((pos (simtx-find sim handle)))
    (if pos
        (simtx-drop-position sim pos)
        (setf (simtx-removed sim) (remove handle (simtx-removed sim))))))

(defun simtx-reduced-parents (sim i)
  "DepGraph::GetReducedParents (cluster_linearize.h:210-221) over the model."
  (let ((parents (logandc2 (aref (simtx-anc sim) i) (ash 1 i))))
    (dolist (p (bits-list parents) parents)
      (when (logbitp p parents)
        (setf parents (logior (logandc2 parents (aref (simtx-anc sim) p)) (ash 1 p)))))))

(defun simtx-make-set (sim handles)
  "SimTxGraph::MakeSet: the positions of HANDLES, all of which must be live."
  (let ((set 0))
    (dolist (h handles set)
      (let ((pos (simtx-find sim h)))
        (fuzz-assert pos "a handle the graph returned is not live in the model")
        (when pos (setf set (logior set (ash 1 pos))))))))

(defun simtx-anc-desc (sim handle desc)
  "SimTxGraph::GetAncDesc."
  (let ((pos (simtx-find sim handle)))
    (cond ((null pos) 0)
          (desc (aref (simtx-desc sim) pos))
          (t (aref (simtx-anc sim) pos)))))

(defun simtx-include-anc-desc (sim handles desc)
  "SimTxGraph::IncludeAncDesc: HANDLES with every live one's ancestors (or
descendants) added, deduplicated in first-seen order."
  (let ((ret '()))
    (dolist (h handles)
      (let ((pos (simtx-find sim h)))
        (if pos
            (dolist (i (bits-list (if desc (aref (simtx-desc sim) pos) (aref (simtx-anc sim) pos))))
              (push (aref (simtx-refs sim) i) ret))
            (push h ret))))
    (let ((out '()))
      (dolist (h (nreverse ret) (nreverse out))
        (pushnew h out :test #'eq)))))

(defun simtx-matches-oversized-clusters-p (sim set)
  "SimTxGraph::MatchesOversizedClusters: SET touches every oversized
component and no other."
  (when (and (plusp set) (not (simtx-oversized-p sim)))
    (return-from simtx-matches-oversized-clusters-p nil))
  (unless (bits-subset-p set (simtx-used sim))
    (return-from simtx-matches-oversized-clusters-p nil))
  (every (lambda (c) (eq (simtx-component-oversized-p sim c) (logtest set c)))
         (simtx-components sim)))

;;; --- The model's own optimal chunkings -------------------------------------------------

(defun simtx-component-depgraph (sim component)
  "COMPONENT (at most 64 positions) as a BL.MP depgraph, with the vector
mapping its depgraph positions back to model positions."
  (let* ((members (coerce (bits-list component) 'simple-vector))
         (g (bl.mp:make-depgraph)))
    (loop for pos across members
          do (bl.mp:depgraph-add-transaction g (simtx-feefrac sim pos)))
    (loop for pos across members
          for k from 0
          do (let ((parents 0))
               (loop for q across members
                     for j from 0
                     when (and (/= q pos) (logbitp q (aref (simtx-anc sim) pos)))
                       do (setf parents (logior parents (ash 1 j))))
               (unless (zerop parents)
                 (bl.mp:depgraph-add-dependencies g parents k))))
    (values g members)))

(defun simtx-optimal-linearization (sim component txid-of)
  "An optimal linearization of COMPONENT in model positions, ties broken by
TXID-OF as the graph breaks them: Core's Linearize + PostLinearize with the
txid fallback order (txgraph.cpp:1298-1304)."
  (multiple-value-bind (g members) (simtx-component-depgraph sim component)
    (let ((lin (bl.mp:linearize
                g :fallback (lambda (a b)
                              (let ((ta (funcall txid-of (svref members a)))
                                    (tb (funcall txid-of (svref members b))))
                                (cond ((< ta tb) -1) ((> ta tb) 1) (t 0)))))))
      (map 'list (lambda (k) (svref members k)) lin))))

(defun simtx-chunking-info (sim lin)
  "ChunkLinearizationInfo over the model: a list of (set . feefrac)."
  (let ((chunks '()))
    (dolist (i lin)
      (let ((set (ash 1 i)) (rate (simtx-feefrac sim i)))
        (loop while (and chunks (bl.mp:feefrac>> rate (cdr (first chunks))))
              do (let ((prev (pop chunks)))
                   (setf set (logior set (car prev))
                         rate (bl.mp:feefrac+ rate (cdr prev)))))
        (push (cons set rate) chunks)))
    (nreverse chunks)))

(defun simtx-diagram (sim components txid-of)
  "The optimal chunk feerates of COMPONENTS, sorted by decreasing feerate."
  (sort (loop for c in components
              nconc (mapcar #'cdr (simtx-chunking-info
                                   sim (simtx-optimal-linearization sim c txid-of))))
        #'bl.mp:feefrac>))

(defun simtx-copy (sim)
  "A deep copy of SIM's graph (handles shared), for a trial change."
  (let ((new (copy-simtx sim)))
    (setf (simtx-fee new) (copy-seq (simtx-fee sim))
          (simtx-size new) (copy-seq (simtx-size sim))
          (simtx-anc new) (copy-seq (simtx-anc sim))
          (simtx-desc new) (copy-seq (simtx-desc sim))
          (simtx-refs new) (copy-seq (simtx-refs sim))
          (simtx-revmap new) (let ((h (make-hash-table :test 'eq)))
                               (maphash (lambda (k v) (setf (gethash k h) v)) (simtx-revmap sim))
                               h)
          (simtx-removed new) '())
    new))

;;; --- Small helpers ---------------------------------------------------------------------

(defun txgraph-fuzz-rand-below (rng n)
  (if (<= n 1) 0 (mod (clusterlin-rand64 rng) n)))

(defun txgraph-fuzz-shuffle (rng list)
  "LIST in a random order (std::shuffle with the target's RNG)."
  (let ((v (coerce list 'simple-vector)))
    (loop for i from (1- (length v)) downto 1
          do (rotatef (svref v i) (svref v (txgraph-fuzz-rand-below rng (1+ i)))))
    (coerce v 'list)))

(defun feefrac-sum (feefracs)
  (reduce #'bl.mp:feefrac+ feefracs :initial-value (bl.mp:make-feefrac)))

;;; --- The target ---------------------------------------------------------------------------

(defstruct (txgraph-fuzz-builder (:constructor make-txgraph-fuzz-builder (builder)))
  "BlockBuilderData (:353-364): a live builder, what it has had included and
included-or-skipped, and the last chunk feerate it reported."
  builder (included 0) (done 0) (last-feerate nil))

(defun txgraph-fuzz-rbf (sim real fdp rng txid-of)
  "Stage a random replacement on the real graph's scratch copy
(TXGRAPH-RBF-DIAGRAMS) and on a copy of the model: evict a random
descendant-closed set, add one transaction spending up to three survivors,
and check the two diagrams against the model's optimal chunkings of the
affected components -- or, when the staged cluster would be oversized, that
the real graph calls it uncalculable."
  (let* ((live (bits-list (simtx-used sim)))
         (removed-pos 0)
         (parents '()))
    (when (null live) (return-from txgraph-fuzz-rbf))
    (dotimes (k (consume-integral-in-range fdp 0 2))
      (let ((p (nth (consume-integral-in-range fdp 0 (1- (length live))) live)))
        (setf removed-pos (logior removed-pos (aref (simtx-desc sim) p)))))
    (dotimes (k (consume-integral-in-range fdp 0 3))
      (let ((p (nth (consume-integral-in-range fdp 0 (1- (length live))) live)))
        (unless (or (logbitp p removed-pos) (member p parents))
          (push p parents))))
    (let* ((fee (consume-integral-in-range fdp 0 2000))
           (size (consume-integral-in-range fdp 1 400))
           (removed-handles (mapcar (lambda (i) (aref (simtx-refs sim) i)) (bits-list removed-pos)))
           (parent-handles (mapcar (lambda (i) (aref (simtx-refs sim) i)) parents))
           (affected (let ((seed (logior removed-pos
                                         (reduce #'logior parents :key (lambda (p) (ash 1 p))))))
                       (remove-if-not (lambda (c) (logtest c seed)) (simtx-components sim))))
           (after (simtx-copy sim)))
      ;; The model after: the evictions gone, the candidate in the first free
      ;; position, depending on its parents.
      (dolist (i (bits-list removed-pos)) (simtx-drop-position after i))
      (let* ((pos (position-if-not (lambda (i) (logbitp i (simtx-used after)))
                                   (loop for i below *simtx-max-transactions* collect i)))
             (survivors (logandc2 (reduce #'logior affected :initial-value 0) removed-pos)))
        (setf (aref (simtx-fee after) pos) fee
              (aref (simtx-size after) pos) size
              (aref (simtx-anc after) pos) (ash 1 pos)
              (aref (simtx-desc after) pos) (ash 1 pos)
              (simtx-used after) (logior (simtx-used after) (ash 1 pos)))
        (dolist (p parents)
          (let ((par-anc (logandc2 (aref (simtx-anc after) p) (aref (simtx-anc after) pos))))
            (bl.mp:do-bits (a par-anc)
              (setf (aref (simtx-desc after) a) (logior (aref (simtx-desc after) a) (ash 1 pos))))
            (setf (aref (simtx-anc after) pos) (logior (aref (simtx-anc after) pos) par-anc))))
        (let* ((new-components (remove-if-not (lambda (c) (logtest c (logior survivors (ash 1 pos))))
                                              (simtx-components after)))
               (oversized (some (lambda (c) (simtx-component-oversized-p after c)) new-components)))
          (multiple-value-bind (old-diagram new-diagram)
              (bl.mp:txgraph-rbf-diagrams real removed-handles parent-handles fee size)
            (if oversized
                (fuzz-assert (eq old-diagram :uncalculable)
                             "a replacement forming an oversized cluster was staged")
                (let ((txid-after (lambda (i) (if (= i pos)
                                                  (1+ (ash 1 64)) ; the candidate: a txid above all
                                                  (funcall txid-of i)))))
                  (fuzz-assert (listp old-diagram) "an in-limit replacement was called uncalculable")
                  (when (listp old-diagram)
                    ;; Monotonically decreasing feerates, both sides.
                    (loop for (a b) on old-diagram while b
                          do (fuzz-assert (<= (bl.mp:feerate-compare b a) 0)))
                    (loop for (a b) on new-diagram while b
                          do (fuzz-assert (<= (bl.mp:feerate-compare b a) 0)))
                    ;; The gain matches the model's (Core's first check).
                    (fuzz-assert (bl.mp:feefrac= (bl.mp:feefrac- (feefrac-sum new-diagram)
                                                                  (feefrac-sum old-diagram))
                                                 (bl.mp:feefrac-
                                                  (bl.mp:make-feefrac fee size)
                                                  (simtx-set-feefrac sim removed-pos))))
                    ;; And the diagrams are the model's optimal chunkings.
                    (let ((expect-old (simtx-diagram sim affected txid-of))
                          (expect-new (simtx-diagram after new-components txid-after)))
                      (fuzz-assert (and (eq (bl.mp:compare-chunks (fuzz-sabotage-chunks old-diagram)
                                                                  expect-old)
                                            :equal)
                                        (= (length old-diagram) (length expect-old)))
                                   "RBF old diagram ~A, model ~A" old-diagram expect-old)
                      (fuzz-assert (and (eq (bl.mp:compare-chunks new-diagram expect-new) :equal)
                                        (= (length new-diagram) (length expect-new)))
                                   "RBF new diagram ~A, model ~A" new-diagram expect-new)))))))))
    (values)))

(defun txgraph-fuzz-trim-merge (sim real rng max-count max-size)
  "The special Trim case (:924-1039): merge random clusters, by one to three
dependencies each from a child cluster to a parent cluster, until an
oversized one appears (and a random number of merges after), then Trim; the
removals stay within the bound of dropping only the smallest transactions."
  (let* ((clusters (simtx-components sim))
         (made-oversized nil)
         (merges-left (1- (length clusters))))
    (loop while (plusp merges-left)
          do (decf merges-left)
             (let* ((par-cl (txgraph-fuzz-rand-below rng (length clusters)))
                    (chl-cl (let ((c (txgraph-fuzz-rand-below rng (1- (length clusters)))))
                              (if (>= c par-cl) (1+ c) c)))
                    (par-cluster (nth par-cl clusters))
                    (chl-cluster (nth chl-cl clusters)))
               (dotimes (k (1+ (txgraph-fuzz-rand-below rng 3)))
                 (let* ((par-pos (bits-nth par-cluster (txgraph-fuzz-rand-below rng (logcount par-cluster))))
                        (chl-pos (bits-nth chl-cluster (txgraph-fuzz-rand-below rng (logcount chl-cluster))))
                        (par-ref (aref (simtx-refs sim) par-pos))
                        (chl-ref (aref (simtx-refs sim) chl-pos)))
                   (simtx-add-dependency sim par-ref chl-ref)
                   (bl.mp:txgraph-add-dependency real par-ref chl-ref)))
               (let ((new (logior par-cluster chl-cluster)))
                 (setf clusters (append (remove-if (lambda (c) (or (= c par-cluster) (= c chl-cluster)))
                                                   clusters)
                                        (list new)))
                 (unless made-oversized
                   (setf made-oversized
                         (or (> (logcount new) max-count)
                             (> (bl.mp:feefrac-size (simtx-set-feefrac sim new)) max-size)))
                   (when made-oversized
                     (setf merges-left (txgraph-fuzz-rand-below rng (length clusters))))))))
    (let ((max-removed 0))
      (dolist (c clusters)
        (let* ((sizes (sort (mapcar (lambda (i) (aref (simtx-size sim) i)) (bits-list c)) #'>))
               (sum (reduce #'+ sizes)))
          (loop while (or (> (length sizes) max-count) (> sum max-size))
                do (decf sum (car (last sizes)))
                   (setf sizes (butlast sizes))
                   (incf max-removed))))
      (let* ((removed (bl.mp:txgraph-trim real))
             (removed-set (simtx-make-set sim removed)))
        (fuzz-assert (>= (length removed) 1))
        (fuzz-assert (<= (fuzz-sabotage (length removed)) max-removed)
                     "Trim removed ~D, more than the ~D of dropping only the smallest"
                     (length removed) max-removed)
        (dolist (i (bits-list removed-set))
          (fuzz-assert (bits-subset-p (aref (simtx-desc sim) i) removed-set)))
        (fuzz-assert (simtx-matches-oversized-clusters-p sim removed-set))
        (dolist (i (bits-list removed-set))
          (simtx-remove-transaction sim (aref (simtx-refs sim) i)))
        (fuzz-assert (not (simtx-oversized-p sim)))))))

(defun txgraph-fuzz-final-order (sim real rng max-count max-size txid-of fallback-order)
  "The end-of-run checks of a graph that is not oversized (:1059-1256): the
total order CompareMainOrder implies, its topology, optimality and
determinism, Core's tie-breaks between equal-feerate chunks, consistency with
GetMainChunkFeerate, the block builder's walk and GetWorstMainChunk."
  (let* ((positions (bits-list (simtx-used sim)))
         (vec1 (txgraph-fuzz-shuffle rng positions))
         (vec2 (txgraph-fuzz-shuffle rng positions))
         (cmp (lambda (a b)
                (minusp (bl.mp:txgraph-compare-main-order
                         real (aref (simtx-refs sim) a) (aref (simtx-refs sim) b))))))
    (setf vec1 (stable-sort vec1 cmp)
          vec2 (stable-sort vec2 cmp))
    (fuzz-assert (equal vec1 vec2) "CompareMainOrder is not a total order")
    (let ((todo (simtx-used sim)))
      (dolist (i vec1)
        (setf todo (logandc2 todo (ash 1 i)))
        (fuzz-assert (not (logtest (aref (simtx-anc sim) i) todo))
                     "the mining order puts a transaction before its ancestor"))
      (fuzz-assert (zerop todo)))
    ;; Optimality: the implied diagram is the model's optimal one, and each
    ;; cluster's internal order is the model's (deterministic) optimal order.
    (let* ((real-chunking (simtx-chunking-info sim vec1))
           (components (simtx-components sim))
           (sim-diagram (simtx-diagram sim components txid-of)))
      (fuzz-assert (eq (bl.mp:compare-chunks (mapcar #'cdr real-chunking) sim-diagram) :equal)
                   "the mining order's diagram is not optimal")
      (let ((prefix (make-hash-table)) (last-feerate (bl.mp:make-feefrac)) (max-tiebreak (cons 0 0)))
        (dolist (chunk real-chunking)
          (when (bl.mp:feefrac<< (cdr chunk) last-feerate)
            (clrhash prefix)
            (setf max-tiebreak (cons 0 0)))
          (setf last-feerate (cdr chunk))
          (let* ((component (simtx-component sim (simtx-used sim) (bits-first (car chunk))))
                 (key (bits-first component))
                 (chunk-max-txid (reduce #'max (mapcar txid-of (bits-list (car chunk))))))
            (fuzz-assert (bits-subset-p (car chunk) component))
            (incf (gethash key prefix 0) (bl.mp:feefrac-size (cdr chunk)))
            (let ((tiebreak (cons (gethash key prefix) chunk-max-txid)))
              (fuzz-assert (or (> (car tiebreak) (car max-tiebreak))
                               (and (= (car tiebreak) (car max-tiebreak))
                                    (> (cdr tiebreak) (cdr max-tiebreak))))
                           "equal-feerate chunks out of (prefix size, max txid) order")
              (setf max-tiebreak tiebreak)))))
      (dolist (c components)
        (let ((sim-lin (simtx-optimal-linearization sim c txid-of))
              (real-lin (remove-if-not (lambda (i) (logbitp i c)) vec1)))
          (fuzz-assert (equal (fuzz-sabotage sim-lin) real-lin)
                       "cluster order ~S, model's optimal order ~S" real-lin sim-lin))))
    ;; A fresh graph, the same transactions and dependencies added in another
    ;; order, orders them identically.
    (let* ((redo (bl.mp:make-txgraph :max-cluster-count max-count :max-cluster-size max-size
                                     :fallback-order fallback-order))
           (handles (make-hash-table)))
      (dolist (i (txgraph-fuzz-shuffle rng positions))
        (setf (gethash i handles)
              (bl.mp:txgraph-add-transaction redo (aref (simtx-fee sim) i) (aref (simtx-size sim) i)
                                             (funcall txid-of i))))
      (let ((deps '()))
        (dolist (i positions)
          (dolist (j (bits-list (simtx-reduced-parents sim i)))
            (push (cons j i) deps)))
        (dolist (d (txgraph-fuzz-shuffle rng deps))
          (bl.mp:txgraph-add-dependency redo (gethash (car d) handles) (gethash (cdr d) handles))))
      (let ((vec-redo (stable-sort (txgraph-fuzz-shuffle rng positions)
                                   (lambda (a b)
                                     (minusp (bl.mp:txgraph-compare-main-order
                                              redo (gethash a handles) (gethash b handles)))))))
        (fuzz-assert (equal vec1 vec-redo) "a rebuilt graph orders its transactions differently")))
    ;; Chunk feerates agree with the order.
    (let ((v (coerce vec1 'simple-vector)))
      (dotimes (pos (length v))
        (let ((here (bl.mp:txgraph-get-main-chunk-feerate real (aref (simtx-refs sim) (svref v pos)))))
          (when (plusp pos)
            (let ((before (bl.mp:txgraph-get-main-chunk-feerate
                           real (aref (simtx-refs sim) (svref v (txgraph-fuzz-rand-below rng pos))))))
              (fuzz-assert (>= (bl.mp:feerate-compare before here) 0))))
          (when (< (1+ pos) (length v))
            (let ((after (bl.mp:txgraph-get-main-chunk-feerate
                          real (aref (simtx-refs sim)
                                     (svref v (+ pos 1 (txgraph-fuzz-rand-below rng (- (length v) 1 pos))))))))
              (fuzz-assert (<= (bl.mp:feerate-compare after here) 0)))))))
    ;; The block builder walks the same order; its last chunk is the worst.
    (let ((builder (bl.mp:make-block-builder real))
          (walked '()) (last-chunk nil) (last-feerate nil))
      (loop
        (multiple-value-bind (chunk feerate) (bl.mp:block-builder-current-chunk builder)
          (unless chunk (return))
          (let ((sum (bl.mp:make-feefrac)))
            (dolist (h chunk)
              (fuzz-assert (bl.mp:feefrac= (bl.mp:txgraph-get-main-chunk-feerate real h) feerate))
              (setf sum (bl.mp:feefrac+ sum (bl.mp:txgraph-get-individual-feerate real h)))
              (let ((pos (simtx-find sim h)))
                (fuzz-assert pos)
                (push pos walked)))
            (fuzz-assert (bl.mp:feefrac= sum feerate)))
          (setf last-chunk chunk last-feerate feerate)
          (bl.mp:block-builder-include builder)))
      (bl.mp:block-builder-finish builder)
      (fuzz-assert (equal (nreverse walked) vec1) "the block builder's walk is not CompareMainOrder's")
      (multiple-value-bind (worst worst-feerate) (bl.mp:txgraph-get-worst-main-chunk real)
        (fuzz-assert (equal (reverse last-chunk) worst))
        (fuzz-assert (or (null last-feerate) (bl.mp:feefrac= last-feerate worst-feerate)))))))

(defun txgraph-fuzz-full-compare (sim real max-count max-size)
  "The full comparison (:1315-1386): every component of the model is a
cluster of the real graph with the same feerates, ancestors and
descendants, reported in a topological order whose chunking gives exactly
the chunk feerates the graph reports, every chunk connected."
  (fuzz-assert (eq (bl.mp:txgraph-oversized-p real) (and (simtx-oversized-p sim) t)))
  (fuzz-assert (= (bl.mp:txgraph-tx-count real) (simtx-count sim)))
  (unless (simtx-oversized-p sim)
    (dolist (component (simtx-components sim))
      (dolist (i (bits-list component))
        (let ((h (aref (simtx-refs sim) i)))
          (fuzz-assert (bl.mp:feefrac= (simtx-feefrac sim i) (bl.mp:txgraph-get-individual-feerate real h)))
          (let ((anc (simtx-make-set sim (bl.mp:txgraph-get-ancestors real h)))
                (desc (simtx-make-set sim (bl.mp:txgraph-get-descendants real h))))
            (fuzz-assert (<= (logcount anc) max-count))
            (fuzz-assert (= anc (aref (simtx-anc sim) i)))
            (fuzz-assert (<= (logcount desc) max-count))
            (fuzz-assert (= (fuzz-sabotage desc) (aref (simtx-desc sim) i))))
          (let* ((cluster (bl.mp:txgraph-get-cluster real h))
                 (done 0) (total 0) (simlin '()))
            (fuzz-assert (<= (length cluster) max-count))
            (fuzz-assert (= (simtx-make-set sim cluster) component))
            (dolist (ref cluster)
              (let ((p (simtx-find sim ref)))
                (fuzz-assert (bits-subset-p (aref (simtx-desc sim) p) (logandc2 component done)))
                (setf done (logior done (ash 1 p)))
                (fuzz-assert (bits-subset-p (aref (simtx-anc sim) p) done))
                (push p simlin)
                (incf total (aref (simtx-size sim) p))))
            (fuzz-assert (<= total max-size))
            (let ((refs (coerce cluster 'simple-vector)) (idx 0))
              (dolist (chunk (simtx-chunking-info sim (nreverse simlin)))
                (fuzz-assert (= (car chunk) (simtx-component sim (car chunk) (bits-first (car chunk))))
                             "a cluster chunk is not connected")
                (loop repeat (logcount (car chunk))
                      do (fuzz-assert (bl.mp:feefrac= (cdr chunk)
                                                      (bl.mp:txgraph-get-main-chunk-feerate
                                                       real (svref refs idx))))
                         (incf idx))))))))))

(define-fuzz-target txgraph
    (buffer :core "txgraph.cpp:305-1397" :iterations 1000 :max-len 3000
            :corpus (lambda (fdp)
                      ;; Every value this target reads is an integral, taken
                      ;; from the END of the buffer, and small bytes select
                      ;; the operations that grow the graph (commands 0 and
                      ;; 1 are AddTransaction and AddDependency). Skewing
                      ;; three bytes in four that small stands in for the
                      ;; coverage guidance that grows Core's corpus into
                      ;; graphs of more than one cluster's worth.
                      (let ((out (make-array (floor (remaining-bytes fdp) 2)
                                             :element-type '(unsigned-byte 8))))
                        (dotimes (k (length out) out)
                          (let ((b (consume-integral fdp :u8)))
                            (setf (aref out k)
                                  (if (plusp (consume-integral-in-range fdp 0 3)) (mod b 8) b)))))))
  "TxGraph under a random sequence of AddTransaction, AddDependency,
RemoveTransaction, SetTransactionFee, the block builder, Trim and a staged
replacement, answering every query -- counts, existence, oversizedness,
feerates, ancestry, clusters, mining order, distinct clusters, worst chunk --
as the SimTxGraph model does, and matching it in full at the end."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (rng (make-insecure-random-context (consume-integral fdp :u64)))
         (max-count (consume-integral-in-range fdp 1 bl.mp:+max-cluster-count+))
         (max-size (consume-integral-in-range fdp 1 (* #x3fffff bl.mp:+max-cluster-count+)))
         (assigned (make-hash-table))
         (fallback-order (lambda (a b)
                           (let ((ta (bl.mp:tx-handle-data a)) (tb (bl.mp:tx-handle-data b)))
                             (assert (and (gethash ta assigned) (gethash tb assigned)))
                             (cond ((< ta tb) -1) ((> ta tb) 1) (t 0)))))
         (real (bl.mp:make-txgraph :max-cluster-count max-count :max-cluster-size max-size
                                   :fallback-order fallback-order))
         (sim (%make-simtx max-count max-size))
         (empty-ref (let ((h (bl.mp:txgraph-add-transaction real 0 1 0)))
                      (bl.mp:txgraph-remove-transaction real h)
                      h))
         (builders '()))
    (labels ((txid-of (pos) (bl.mp:tx-handle-data (aref (simtx-refs sim) pos)))
             (pick ()
               (let* ((tx-count (simtx-count sim))
                      (choice (consume-integral-in-range
                               fdp 0 (+ tx-count (length (simtx-removed sim))))))
                 (cond ((< choice tx-count)
                        (aref (simtx-refs sim) (bits-nth (simtx-used sim) choice)))
                       ((< (- choice tx-count) (length (simtx-removed sim)))
                        (nth (- choice tx-count) (simtx-removed sim)))
                       (t empty-ref))))
             (oversized () (simtx-oversized-p sim)))
      (limited-while ((plusp (remaining-bytes fdp)) 200)
        (let* ((orig (consume-integral fdp :u8))
               (alt (logbitp 0 orig))
               (command (ash orig -2))
               (builder-idx (if builders (mod (logand orig 3) (length builders)) nil)))
          (macrolet ((op (condition &body body)
                       `(when (and ,condition (prog1 (zerop command) (decf command)))
                          ,@body
                          (return))))
            (loop
              ;; AddTransaction.
              (op (and (null builders) (< (simtx-count sim) *simtx-max-transactions*))
                  (multiple-value-bind (fee size)
                      (if alt
                          (values (consume-integral-in-range fdp #x-8000000000000 #x7ffffffffffff)
                                  (consume-integral-in-range fdp 1 #x3fffff))
                          (values (consume-integral fdp :u8) (consume-integral-in-range fdp 1 #xff)))
                    (let ((txid (loop for id = (clusterlin-rand64 rng)
                                      unless (or (zerop id) (gethash id assigned)) return id)))
                      (setf (gethash txid assigned) t)
                      (simtx-add-transaction sim real fee size txid))))
              ;; AddDependency.
              (op (and (null builders) (> (+ (simtx-count sim) (length (simtx-removed sim))) 1))
                  (let* ((par (pick)) (chl (pick))
                         (pp (simtx-find sim par)) (pc (simtx-find sim chl)))
                    (unless (and pp pc (logbitp pc (aref (simtx-anc sim) pp)))
                      (simtx-add-dependency sim par chl)
                      (bl.mp:txgraph-add-dependency real par chl))))
              ;; RemoveTransaction, with all ancestors or all descendants.
              (op (and (null builders) (< (length (simtx-removed sim)) 100))
                  (dolist (h (txgraph-fuzz-shuffle rng (simtx-include-anc-desc sim (list (pick)) alt)))
                    (bl.mp:txgraph-remove-transaction real h)
                    (simtx-remove-transaction sim h)))
              ;; ~Ref of an already-removed transaction.
              (op (simtx-removed sim)
                  (let ((k (consume-integral-in-range fdp 0 (1- (length (simtx-removed sim))))))
                    (setf (simtx-removed sim)
                          (append (subseq (simtx-removed sim) 0 k) (nthcdr (1+ k) (simtx-removed sim))))))
              ;; ~Ref of any transaction: it leaves the graph for good.
              (op (null builders)
                  (dolist (h (txgraph-fuzz-shuffle rng (simtx-include-anc-desc sim (list (pick)) alt)))
                    (bl.mp:txgraph-remove-transaction real h)
                    (simtx-destroy-transaction sim h)))
              ;; SetTransactionFee.
              (op (null builders)
                  (let ((fee (if alt
                                 (consume-integral-in-range fdp #x-8000000000000 #x7ffffffffffff)
                                 (consume-integral fdp :u8)))
                        (h (pick)))
                    (bl.mp:txgraph-set-transaction-fee real h fee)
                    (let ((pos (simtx-find sim h)))
                      (when pos (setf (aref (simtx-fee sim) pos) fee)))))
              ;; GetTransactionCount.
              (op t (fuzz-assert (= (fuzz-sabotage (bl.mp:txgraph-tx-count real)) (simtx-count sim))))
              ;; Exists.
              (op t (let ((h (pick)))
                      (fuzz-assert (eq (bl.mp:txgraph-exists-p real h) (and (simtx-find sim h) t)))))
              ;; IsOversized.
              (op t (fuzz-assert (eq (bl.mp:txgraph-oversized-p real) (and (oversized) t))
                                 "IsOversized ~A, model ~A" (bl.mp:txgraph-oversized-p real) (oversized)))
              ;; GetIndividualFeerate.
              (op t (let* ((h (pick))
                           (feerate (bl.mp:txgraph-get-individual-feerate real h))
                           (pos (simtx-find sim h)))
                      (if pos
                          (fuzz-assert (bl.mp:feefrac= feerate (simtx-feefrac sim pos)))
                          (fuzz-assert (bl.mp:feefrac-empty-p feerate)))))
              ;; GetMainChunkFeerate.
              (op (not (oversized))
                  (let* ((h (pick))
                         (feerate (bl.mp:txgraph-get-main-chunk-feerate real h))
                         (pos (simtx-find sim h)))
                    (if (null pos)
                        (fuzz-assert (bl.mp:feefrac-empty-p feerate))
                        (progn
                          (fuzz-assert (>= (bl.mp:feefrac-size feerate) (aref (simtx-size sim) pos)))
                          (fuzz-assert (<= (bl.mp:feefrac-size feerate)
                                           (bl.mp:feefrac-size (simtx-set-feefrac sim (simtx-used sim)))))))))
              ;; GetAncestors / GetDescendants.
              (op (not (oversized))
                  (let* ((h (pick))
                         (result (if alt
                                     (bl.mp:txgraph-get-descendants real h)
                                     (bl.mp:txgraph-get-ancestors real h)))
                         (set (simtx-make-set sim result)))
                    (fuzz-assert (<= (length result) max-count))
                    (fuzz-assert (= (length result) (logcount set)))
                    (fuzz-assert (= set (simtx-anc-desc sim h alt)))))
              ;; GetAncestorsUnion / GetDescendantsUnion.
              (op (not (oversized))
                  (let* ((refs (txgraph-fuzz-shuffle
                                rng (loop repeat (consume-integral-in-range fdp 0 15) collect (pick))))
                         (result (if alt
                                     (bl.mp:txgraph-get-descendants-union real refs)
                                     (bl.mp:txgraph-get-ancestors-union real refs)))
                         (set (simtx-make-set sim result))
                         (expect 0))
                    (fuzz-assert (= (length result) (logcount set)))
                    (dolist (r refs) (setf expect (logior expect (simtx-anc-desc sim r alt))))
                    (fuzz-assert (= set expect))))
              ;; GetCluster.
              (op (not (oversized))
                  (let* ((h (pick))
                         (result (bl.mp:txgraph-get-cluster real h))
                         (left (simtx-used sim))
                         (total 0))
                    (fuzz-assert (<= (length result) max-count))
                    (dolist (r result)
                      (let ((p (simtx-find sim r)))
                        (fuzz-assert p)
                        (when p
                          (incf total (aref (simtx-size sim) p))
                          (fuzz-assert (logbitp p left))
                          (setf left (logandc2 left (ash 1 p)))
                          (fuzz-assert (not (logtest (aref (simtx-anc sim) p) left))))))
                    (fuzz-assert (<= total max-size))
                    (let ((set (simtx-make-set sim result))
                          (pos (simtx-find sim h)))
                      (fuzz-assert (or (zerop set) (= set (simtx-component sim set (bits-first set)))))
                      (if pos
                          (fuzz-assert (logbitp pos set))
                          (fuzz-assert (zerop set)))
                      (dolist (i (bits-list set))
                        (fuzz-assert (bits-subset-p (aref (simtx-anc sim) i) set))
                        (fuzz-assert (bits-subset-p (aref (simtx-desc sim) i) set))))))
              ;; CompareMainOrder.
              (op (not (oversized))
                  (let* ((a (pick)) (b (pick))
                         (pa (simtx-find sim a)) (pb (simtx-find sim b)))
                    (when (and pa pb)
                      (let ((c (bl.mp:txgraph-compare-main-order real a b)))
                        (when (/= pa pb) (fuzz-assert (/= c 0)))
                        (when (logbitp pb (aref (simtx-anc sim) pa)) (fuzz-assert (>= c 0)))
                        (when (logbitp pb (aref (simtx-desc sim) pa)) (fuzz-assert (<= c 0)))))))
              ;; CountDistinctClusters.
              (op (not (oversized))
                  (let* ((refs (txgraph-fuzz-shuffle
                                rng (loop repeat (consume-integral-in-range fdp 0 (if alt 255 15))
                                          collect (pick))))
                         (result (bl.mp:txgraph-count-distinct-clusters real refs))
                         (reps 0))
                    (dolist (r refs)
                      (let ((p (simtx-find sim r)))
                        (when p
                          (setf reps (logior reps (ash 1 (bits-first
                                                          (simtx-component sim (simtx-used sim) p))))))))
                    (fuzz-assert (= result (logcount reps)))))
              ;; A staged replacement (the port's GetMainStagingDiagrams).
              (op (not (oversized))
                  (txgraph-fuzz-rbf sim (the bl.mp:txgraph real) fdp rng #'txid-of))
              ;; GetBlockBuilder.
              (op (and (< (length builders) 4) (not (oversized)))
                  (setf builders (append builders
                                         (list (make-txgraph-fuzz-builder (bl.mp:make-block-builder real))))))
              ;; ~BlockBuilder.
              (op builders
                  (let ((b (nth builder-idx builders)))
                    (bl.mp:block-builder-finish (txgraph-fuzz-builder-builder b))
                    (setf builders (remove b builders))))
              ;; GetCurrentChunk, then Include or Skip.
              (op builders
                  (let* ((data (nth builder-idx builders))
                         (b (txgraph-fuzz-builder-builder data))
                         (new-included (txgraph-fuzz-builder-included data))
                         (new-done (txgraph-fuzz-builder-done data)))
                    (multiple-value-bind (chunk feerate) (bl.mp:block-builder-current-chunk b)
                      (if chunk
                          (let ((sum (bl.mp:make-feefrac)))
                            (when (txgraph-fuzz-builder-last-feerate data)
                              (fuzz-assert (not (bl.mp:feefrac>> feerate (txgraph-fuzz-builder-last-feerate data)))))
                            (setf (txgraph-fuzz-builder-last-feerate data) feerate)
                            (dolist (h chunk)
                              (let ((p (simtx-find sim h)))
                                (fuzz-assert p)
                                (setf sum (bl.mp:feefrac+ sum (simtx-feefrac sim p)))
                                (fuzz-assert (not (logbitp p new-done)))
                                (setf new-done (logior new-done (ash 1 p))
                                      new-included (logior new-included (ash 1 p)))
                                (fuzz-assert (bits-subset-p (aref (simtx-anc sim) p) new-included))))
                            (fuzz-assert (bl.mp:feefrac= sum feerate)))
                          (when (= (txgraph-fuzz-builder-done data) (txgraph-fuzz-builder-included data))
                            (fuzz-assert (= (logcount (txgraph-fuzz-builder-done data)) (simtx-count sim)))))
                      (when (>= (mod orig 7) 5)
                        (multiple-value-bind (chunk2 feerate2) (bl.mp:block-builder-current-chunk b)
                          (fuzz-assert (and (equal chunk chunk2)
                                            (or (null chunk) (bl.mp:feefrac= feerate feerate2))))))
                      (if (>= (mod orig 5) 3)
                          (bl.mp:block-builder-skip b)
                          (progn (bl.mp:block-builder-include b)
                                 (setf (txgraph-fuzz-builder-included data) new-included)))
                      (setf (txgraph-fuzz-builder-done data) new-done))))
              ;; GetWorstMainChunk.
              (op (not (oversized))
                  (multiple-value-bind (worst worst-feerate) (bl.mp:txgraph-get-worst-main-chunk real)
                    (if (zerop (simtx-count sim))
                        (progn (fuzz-assert (null worst))
                               (fuzz-assert (bl.mp:feefrac-empty-p worst-feerate)))
                        (let ((done 0) (sum (bl.mp:make-feefrac)))
                          (fuzz-assert worst)
                          (dolist (h worst)
                            (let ((p (simtx-find sim h)))
                              (fuzz-assert p)
                              (setf sum (bl.mp:feefrac+ sum (simtx-feefrac sim p)))
                              (fuzz-assert (not (logbitp p done)))
                              (setf done (logior done (ash 1 p)))
                              (fuzz-assert (bits-subset-p (aref (simtx-desc sim) p) done))))
                          (fuzz-assert (bl.mp:feefrac= sum worst-feerate))))))
              ;; Trim.
              (op (null builders)
                  (let* ((was-oversized (oversized))
                         (removed (bl.mp:txgraph-trim real)))
                    (fuzz-assert (eq (and was-oversized t) (and removed t)))
                    (when was-oversized
                      (let ((removed-set (simtx-make-set sim removed)))
                        (dolist (i (bits-list removed-set))
                          (fuzz-assert (bits-subset-p (aref (simtx-desc sim) i) removed-set)))
                        (fuzz-assert (simtx-matches-oversized-clusters-p sim removed-set))
                        (dolist (i (bits-list removed-set))
                          (simtx-remove-transaction sim (aref (simtx-refs sim) i)))
                        (fuzz-assert (not (oversized)))))))
              ;; Trim of clusters merged until oversized.
              (op (and (null builders) (> (simtx-count sim) max-count) (not (oversized)))
                  (txgraph-fuzz-trim-merge sim real rng max-count max-size))))))
      (bl.mp:txgraph-sanity-check real)
      (unless (oversized)
        (txgraph-fuzz-final-order sim real rng max-count max-size #'txid-of fallback-order))
      (txgraph-fuzz-full-compare sim real max-count max-size)
      (bl.mp:txgraph-sanity-check real)
      (dolist (b builders) (bl.mp:block-builder-finish (txgraph-fuzz-builder-builder b))))))
