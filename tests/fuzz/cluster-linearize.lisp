(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/cluster_linearize.cpp at the pin (d3056bc149): the
;;;; twelve clusterlin_* targets over DepGraph, chunking, PostLinearize and the
;;;; spanning-forest linearizer (src/mempool/cluster-linearize.lisp and
;;;; spanning-forest.lisp), with the test-only machinery they are built on
;;;; ported beside them from the same file and from test/util/cluster_linearize.h:
;;;; DepGraphFormatter (the graph a SpanReader decodes out of the fuzz buffer),
;;;; the two SanityCheck overloads, ReadLinearization / ReadTopologicalSet,
;;;; MakeConnected, BuildTreeGraph, and the reference linearizers the real one is
;;;; judged against -- SimpleCandidateFinder / SimpleLinearize, checked in turn
;;;; against ExhaustiveCandidateFinder / ExhaustiveLinearize.
;;;;
;;;; Sets are Core's BitSet<32> (TestBitSet) as non-negative integers, the
;;;; representation the depgraph port itself uses.
;;;;
;;;; Two departures, both about cost rather than about what is asserted:
;;;; MAX_SIMPLE_ITERATIONS is *CLUSTERLIN-SIMPLE-ITERATIONS* (Core 300,000),
;;;; because one SimpleLinearize at Core's budget costs seconds here and every
;;;; assertion that reads it is stated relative to the budget, so it holds at
;;;; any budget; and clusterlin_depgraph_sim's Compact command is a no-op,
;;;; because DepGraph::Compact only returns memory (its one assertion compares
;;;; DynamicMemoryUsage, which this port has no counterpart of). The
;;;; SpanningForestState::SanityCheck calls in clusterlin_sfl have no
;;;; counterpart either: that is Core's internal consistency check of the SFL
;;;; state, and the port has none to call.

(def-suite :fuzz-cluster-linearize-tests :in :bitcoin-lisp-tests
  :description "Core fuzz/cluster_linearize.cpp targets")

(in-suite :fuzz-cluster-linearize-tests)

;;; --- BitSet<N> as integers --------------------------------------------------------

(defparameter *clusterlin-set-size* 32
  "Core TestBitSet = BitSet<32> (test/util/cluster_linearize.h:24): the SetType
every clusterlin target instantiates DepGraph with, so the most transactions a
deserialized graph holds.")

(defparameter *clusterlin-simple-iterations* 3000
  "Core MAX_SIMPLE_ITERATIONS (cluster_linearize.cpp:764) is 300,000. Every
assertion that reads it is relative to it -- SimpleLinearize claims optimality
only when it stopped short of the budget -- so a smaller budget asks the same
questions of fewer graphs, at a cost the battery can afford.")

(defun bits-fill (n)
  "Core BitSet::Fill(N): positions 0..N-1."
  (1- (ash 1 n)))

(defun bits-first (set)
  "Core BitSet::First(): the lowest position of non-empty SET."
  (1- (integer-length (logand set (- set)))))

(defun bits-last (set)
  "Core BitSet::Last(): the highest position of non-empty SET."
  (1- (integer-length set)))

(defun bits-subset-p (a b)
  "Core A.IsSubsetOf(B)."
  (zerop (logandc2 a b)))

(defun bits-list (set)
  "The positions of SET, ascending (Core's `for (auto i : set)')."
  (let ((out '()))
    (bl.mp:do-bits (i set) (push i out))
    (nreverse out)))

(defun bits-nth (set n)
  "The Nth (from 0) position of SET, ascending."
  (nth n (bits-list set)))

;;; --- The reader: Core's SpanReader with its try/catch shapes ---------------------

(defun clusterlin-varint (reader &optional (default 0))
  "Core `try { reader >> VARINT(x); } catch (const std::ios_base::failure&) {}':
the value, or DEFAULT (X's initial value) when the read fails."
  (handler-case (bl.ser:br-read-core-varint reader)
    (bl.err:serialization-error () default)))

(defun clusterlin-unsigned-to-signed (x)
  "DepGraphFormatter::UnsignedToSigned: even X is X/2, odd X is -(X/2)-1."
  (if (oddp x) (- -1 (floor x 2)) (floor x 2)))

(defun clusterlin-signed-to-unsigned (x)
  "DepGraphFormatter::SignedToUnsigned: X>=0 is 2X, X<0 is -2X-1."
  (if (minusp x) (1+ (* 2 (- -1 x))) (* 2 x)))

;;; --- DepGraph construction and the formatter --------------------------------------

(defun clusterlin-depgraph-remap (src mapping pos-range)
  "Core's DepGraph(depgraph, mapping, pos_range) constructor
(cluster_linearize.h:91-112): SRC's transaction I lands at position
MAPPING[I] of a graph whose positions run 0..POS-RANGE-1, the rest holes, and
SRC's reduced parents are re-added through the mapping."
  (let ((g (bl.mp:make-depgraph))
        (rates (make-array pos-range :initial-element nil))
        (used 0))
    (bl.mp:do-bits (i (bl.mp:depgraph-positions src))
      (setf (aref rates (aref mapping i)) (bl.mp:depgraph-tx-feerate src i)
            used (logior used (ash 1 (aref mapping i)))))
    (dotimes (k pos-range)
      (bl.mp:depgraph-add-transaction g (or (aref rates k) (bl.mp:make-feefrac 0 0))))
    (bl.mp:depgraph-remove-transactions g (logandc2 (bits-fill pos-range) used))
    (bl.mp:do-bits (i (bl.mp:depgraph-positions src))
      (let ((parents 0))
        (bl.mp:do-bits (j (bl.mp:depgraph-reduced-parents src i))
          (setf parents (logior parents (ash 1 (aref mapping j)))))
        (bl.mp:depgraph-add-dependencies g parents (aref mapping i))))
    g))

(defun depgraph-formatter-read (reader)
  "Core DepGraphFormatter::Unser (test/util/cluster_linearize.h:186-282): read
transactions in topological order -- a size (0 ends the graph), a sign-folded
fee, skip counts that pick the parents, and a position code -- tolerating a
read error by keeping what was read so far. Never signals: this is the one
decoder every clusterlin target starts from."
  (let ((topo (bl.mp:make-depgraph))
        (reordering (make-array 0 :adjustable t :fill-pointer 0))
        (total-size 0)
        (n *clusterlin-set-size*))
    (loop
      (let ((new-fee 0) (new-size 0) (new-ancestors 0) (diff 0) (read-error nil))
        (handler-case
            (let ((size (logand (bl.ser:br-read-core-varint reader #x7fffffff) #x3fffff)))
              (when (or (zerop size) (= (bl.mp:depgraph-tx-count topo) n))
                (return))
              (let ((coded-fee (logand (bl.ser:br-read-core-varint reader) #xfffffffffffff)))
                (setf new-fee (clusterlin-unsigned-to-signed coded-fee)
                      new-size size))
              (let ((topo-idx (length reordering)))
                (setf diff (bl.ser:br-read-core-varint reader))
                (loop for dep-dist from 0 below topo-idx
                      for dep-topo-idx = (- topo-idx 1 dep-dist)
                      unless (logbitp dep-topo-idx new-ancestors)
                        do (if (zerop diff)
                               (setf new-ancestors
                                     (logior new-ancestors
                                             (bl.mp:depgraph-ancestors topo dep-topo-idx))
                                     diff (bl.ser:br-read-core-varint reader))
                               (decf diff)))))
          (bl.err:serialization-error () (setf read-error t)))
        (when (zerop new-size) (return))
        (assert (< (length reordering) n))
        (let ((topo-idx (bl.mp:depgraph-add-transaction
                         topo (bl.mp:make-feefrac new-fee new-size))))
          (bl.mp:depgraph-add-dependencies topo new-ancestors topo-idx))
        (if (< total-size n)
            (progn
              (setf diff (mod diff n))
              (if (<= diff total-size)
                  (progn
                    (dotimes (k (length reordering))
                      (when (>= (aref reordering k) (- total-size diff))
                        (incf (aref reordering k))))
                    (vector-push-extend (- total-size diff) reordering)
                    (incf total-size))
                  (progn
                    (setf total-size diff)
                    (vector-push-extend total-size reordering)
                    (incf total-size))))
            (let ((holes (bits-fill n)))
              (setf diff (mod diff (- n (length reordering))))
              (loop for pos across reordering
                    do (setf holes (logandc2 holes (ash 1 pos))))
              (dolist (pos (bits-list holes))
                (when (zerop diff)
                  (vector-push-extend pos reordering)
                  (return))
                (decf diff))))
        (when read-error (return))))
    (clusterlin-depgraph-remap topo reordering total-size)))

(defun depgraph-formatter-write (g)
  "Core DepGraphFormatter::Ser (test/util/cluster_linearize.h:121-184): G's
transactions in topological order (ancestor count, then position), each as
size, sign-folded fee, the parent skip counts and a position code, then 0."
  (let* ((topo-order (coerce (bl.mp:depgraph-topo-sorted g) 'simple-vector))
         (positions (bl.mp:depgraph-positions g))
         (done 0)
         (bb (bl.ser:make-byte-buf)))
    (dotimes (topo-idx (length topo-order))
      (let* ((idx (svref topo-order topo-idx))
             (feerate (bl.mp:depgraph-tx-feerate g idx))
             (written-parents 0)
             (diff 0))
        (bl.ser:bb-write-core-varint bb (bl.mp:feefrac-size feerate))
        (bl.ser:bb-write-core-varint bb (clusterlin-signed-to-unsigned (bl.mp:feefrac-fee feerate)))
        (dotimes (dep-dist topo-idx)
          (let ((dep-idx (svref topo-order (- topo-idx 1 dep-dist))))
            (unless (logtest (bl.mp:depgraph-descendants g dep-idx) written-parents)
              (if (logbitp dep-idx (bl.mp:depgraph-ancestors g idx))
                  (progn
                    (bl.ser:bb-write-core-varint bb diff)
                    (setf diff 0
                          written-parents (logior written-parents (ash 1 dep-idx))))
                  (incf diff)))))
        (let ((add-holes (logandc2 (logandc2 (bits-fill idx) done) positions)))
          (if (zerop add-holes)
              (bl.ser:bb-write-core-varint
               bb (+ diff (logcount (logandc2 done (bits-fill idx)))))
              (progn
                (bl.ser:bb-write-core-varint
                 bb (+ diff (logcount done) (logcount add-holes)))
                (setf done (logior done add-holes)))))
        (setf done (logior done (ash 1 idx)))))
    (bl.ser:bb-write-u8 bb 0)
    (bl.ser:bb-finish bb)))

(defun clusterlin-depgraph= (a b)
  "Core DepGraph::operator== (cluster_linearize.h:59-67): the same positions,
and at each the same feerate, ancestors and descendants."
  (and (= (bl.mp:depgraph-positions a) (bl.mp:depgraph-positions b))
       (every (lambda (i)
                (and (bl.mp:feefrac= (bl.mp:depgraph-tx-feerate a i)
                                     (bl.mp:depgraph-tx-feerate b i))
                     (= (bl.mp:depgraph-ancestors a i) (bl.mp:depgraph-ancestors b i))
                     (= (bl.mp:depgraph-descendants a i) (bl.mp:depgraph-descendants b i))))
              (bits-list (bl.mp:depgraph-positions a)))))

;;; --- SanityCheck (test/util/cluster_linearize.h:285-383) --------------------------

(defun clusterlin-closure (seed step-sets)
  "The fixed point of SEED under `for j in set: set |= STEP-SETS[j]'."
  (let ((set seed))
    (loop
      (let ((old set))
        (bl.mp:do-bits (j old) (setf set (logior set (aref step-sets j))))
        (when (= old set) (return set))))))

(defun clusterlin-sanity-check (g)
  "Core SanityCheck(const DepGraph&): positions against the counters, the
ancestor/descendant closures against each other and against the reduced
parents and children, and -- for an acyclic graph -- the formatter's round
trip, with and without the terminating 0 byte."
  (let ((positions (bl.mp:depgraph-positions g)))
    (fuzz-assert (= (logcount positions) (bl.mp:depgraph-tx-count g)))
    (fuzz-assert (= (if (zerop positions) 0 (1+ (bits-last positions)))
                    (bl.mp:depgraph-position-range g)))
    (fuzz-assert (<= (bl.mp:depgraph-position-range g) *clusterlin-set-size*))
    (dolist (i (bits-list positions))
      (let ((anc (bl.mp:depgraph-ancestors g i)))
        (fuzz-assert (logbitp i anc))
        (dolist (a (bits-list anc))
          (fuzz-assert (bits-subset-p (bl.mp:depgraph-ancestors g a) anc)))))
    (dolist (i (bits-list positions))
      (dolist (j (bits-list positions))
        (fuzz-assert (eq (logbitp j (bl.mp:depgraph-ancestors g i))
                         (logbitp i (bl.mp:depgraph-descendants g j)))))
      (let ((parents (bl.mp:depgraph-reduced-parents g i))
            (children (bl.mp:depgraph-reduced-children g i)))
        (fuzz-assert (not (logbitp i parents)))
        (fuzz-assert (not (logbitp i children)))
        (dolist (p (bits-list parents))
          (fuzz-assert (bits-subset-p (logand (bl.mp:depgraph-ancestors g p) parents) (ash 1 p))))
        (dolist (c (bits-list children))
          (fuzz-assert (bits-subset-p (logand (bl.mp:depgraph-descendants g c) children) (ash 1 c))))))
    (when (bl.mp:depgraph-acyclic-p g)
      (let* ((ser (depgraph-formatter-write g))
             (reader (bl.ser:make-byte-reader-from ser))
             (decoded (depgraph-formatter-read reader)))
        (fuzz-assert (clusterlin-depgraph= g decoded) "formatter round trip changed the graph")
        (fuzz-assert (bl.ser:br-eof-p reader))
        (fuzz-assert (and (plusp (length ser)) (zerop (aref ser (1- (length ser))))))
        (let* ((short (subseq ser 0 (1- (length ser))))
               (reader2 (bl.ser:make-byte-reader-from short)))
          (fuzz-assert (clusterlin-depgraph= g (depgraph-formatter-read reader2))
                       "formatter round trip without the final 0 changed the graph")
          (fuzz-assert (bl.ser:br-eof-p reader2))))
      (let* ((range (bl.mp:depgraph-position-range g))
             (parents (make-array range :initial-element 0))
             (children (make-array range :initial-element 0)))
        (dolist (i (bits-list positions))
          (setf (aref parents i) (bl.mp:depgraph-reduced-parents g i)
                (aref children i) (bl.mp:depgraph-reduced-children g i)))
        (dolist (i (bits-list positions))
          (fuzz-assert (= (fuzz-sabotage (clusterlin-closure (ash 1 i) parents))
                          (bl.mp:depgraph-ancestors g i)))
          (fuzz-assert (= (clusterlin-closure (ash 1 i) children)
                          (bl.mp:depgraph-descendants g i))))))))

(defun clusterlin-sanity-check-linearization (g linearization)
  "Core SanityCheck(depgraph, linearization): complete, in range, topological
and duplicate-free."
  (fuzz-assert (= (length linearization) (bl.mp:depgraph-tx-count g)))
  (let ((done 0))
    (map nil (lambda (i)
               (fuzz-assert (logbitp i (bl.mp:depgraph-positions g)))
               (fuzz-assert (= (logandc2 (bl.mp:depgraph-ancestors g i) done) (ash 1 i)))
               (setf done (logior done (ash 1 i))))
         linearization)))

(defun max-optimal-linearization-cost (count)
  "Core MaxOptimalLinearizationCost (test/util/cluster_linearize.h:397-416):
twice the largest SFL cost Core saw for a cluster of COUNT transactions."
  (let ((costs #(0
                 0 545 928 1633 2647 4065 5598 8258
                 9505 11471 14137 19553 20460 26191 28397 32599
                 41631 47419 56329 57767 72196 63652 95366 96537
                 115653 125407 131734 145090 156349 164665 194224 203953
                 207710 225878 239971 252284 256534 222142 251332 357098
                 325788 295867 410053 497483 533892 576572 577845 572400
                 592536 455082 609249 659130 714091 544507 718788 562378
                 601926 1025081 732725 708896 738224 900445 1092519 1139946)))
    (* 2 (aref costs count))))

;;; --- Reading linearizations and sets out of the buffer ------------------------------

(defun read-linearization (g reader &optional (topological t))
  "Core ReadLinearization (cluster_linearize.cpp:317-353): one VARINT per step
picks the next transaction among those whose ancestors are all placed (or,
with TOPOLOGICAL false, among all remaining)."
  (let ((todo (bl.mp:depgraph-positions g))
        (out '()))
    (loop until (zerop todo)
          do (let ((potential 0))
               (if topological
                   (bl.mp:do-bits (j todo)
                     (when (= (logand (bl.mp:depgraph-ancestors g j) todo) (ash 1 j))
                       (setf potential (logior potential (ash 1 j)))))
                   (setf potential todo))
               (assert (plusp potential))
               (let ((j (bits-nth potential (mod (clusterlin-varint reader) (logcount potential)))))
                 (push j out)
                 (setf todo (logandc2 todo (ash 1 j))))))
    (coerce (nreverse out) 'simple-vector)))

(defun read-topological-set (g todo reader non-empty)
  "Core ReadTopologicalSet (cluster_linearize.cpp:285-312): a VARINT bitmask
over TODO's positions, each set bit pulling in that transaction's ancestors;
with NON-EMPTY, never the empty set."
  (let ((mask (clusterlin-varint reader))
        (ret 0))
    (unless (= mask (1- (ash 1 64)))
      (when non-empty (incf mask)))
    (dolist (i (bits-list todo))
      (unless (logbitp i ret)
        (when (logbitp 0 mask)
          (setf ret (logior ret (bl.mp:depgraph-ancestors g i))))
        (setf mask (ash mask -1))))
    (setf ret (logand ret todo))
    (when (and non-empty (zerop ret))
      (setf ret (logand (bl.mp:depgraph-ancestors g (bits-first todo)) todo)))
    ret))

(defun make-connected (g)
  "Core MakeConnected (cluster_linearize.cpp:268-281): chain each connected
component to the next, last position of one to the first of the next."
  (let* ((todo (bl.mp:depgraph-positions g))
         (comp (bl.mp:depgraph-find-connected-component g todo)))
    (setf todo (logandc2 todo comp))
    (loop until (zerop todo)
          do (let ((next (bl.mp:depgraph-find-connected-component g todo)))
               (bl.mp:depgraph-add-dependencies g (ash 1 (bits-last comp)) (bits-first next))
               (setf todo (logandc2 todo next)
                     comp next)))
    g))

(defun build-tree-graph (g direction)
  "Core BuildTreeGraph (cluster_linearize.cpp:365-398): G's transactions at
the same positions, keeping only each one's first reduced parent (even
DIRECTION) or first reduced child (odd)."
  (let ((tree (bl.mp:make-depgraph))
        (positions (bl.mp:depgraph-positions g)))
    (dotimes (i (bl.mp:depgraph-position-range g))
      (bl.mp:depgraph-add-transaction tree (if (logbitp i positions)
                                               (bl.mp:depgraph-tx-feerate g i)
                                               (bl.mp:make-feefrac 0 0))))
    (bl.mp:depgraph-remove-transactions
     tree (logandc2 (bits-fill (bl.mp:depgraph-position-range g)) positions))
    (dolist (i (bits-list positions))
      (if (logbitp 0 direction)
          (let ((children (bl.mp:depgraph-reduced-children g i)))
            (unless (zerop children)
              (bl.mp:depgraph-add-dependencies tree (ash 1 i) (bits-first children))))
          (let ((parents (bl.mp:depgraph-reduced-parents g i)))
            (unless (zerop parents)
              (bl.mp:depgraph-add-dependencies tree (ash 1 (bits-first parents)) i)))))
    tree))

;;; --- The reference linearizers ------------------------------------------------------

(defun simple-find-candidate-set (g todo max-iterations)
  "Core SimpleCandidateFinder::FindCandidateSet (cluster_linearize.cpp:98-135):
a depth-first walk over connected topological subsets of TODO, at most
MAX-ITERATIONS of them. Returns (values set feefrac iterations-done)."
  (let* ((left max-iterations)
         (queue (list (cons 0 todo)))
         (best-set (logand (bl.mp:depgraph-ancestors g (bits-first todo)) todo))
         (best-rate (bl.mp:depgraph-subset-feerate g best-set)))
    (loop while (and queue (plusp left))
          do (destructuring-bind (inc . und) (pop queue)
               (let ((inc-none (zerop inc)))
                 (dolist (split (bits-list und))
                   (when (or inc-none (logtest inc (bl.mp:depgraph-ancestors g split)))
                     (decf left)
                     (let* ((new-inc (logior inc (logand todo (bl.mp:depgraph-ancestors g split))))
                            (new-rate (bl.mp:depgraph-subset-feerate g new-inc)))
                       (push (cons new-inc (logandc2 und new-inc)) queue)
                       (push (cons inc (logandc2 und (bl.mp:depgraph-descendants g split))) queue)
                       ;; Core pushes new_inc first and pops from the back, so
                       ;; the EXCLUDED branch is explored next.
                       (when (bl.mp:feefrac> new-rate best-rate)
                         (setf best-set new-inc best-rate new-rate)))
                     (return))))))
    (values best-set best-rate (- max-iterations left))))

(defun exhaustive-find-candidate-set (g todo)
  "Core ExhaustiveCandidateFinder::FindCandidateSet (cluster_linearize.cpp:
164-185): the best ancestor-closure of every subset of TODO. O(N 2^N)."
  (let* ((best-set todo)
         (best-rate (bl.mp:depgraph-subset-feerate g todo))
         (members (bits-list todo))
         (limit (1- (ash 1 (length members)))))
    (loop for x from 1 below limit
          do (let ((txn 0))
               (loop for i in members
                     for b from 0
                     when (logbitp b x)
                       do (setf txn (logior txn (bl.mp:depgraph-ancestors g i))))
               (let* ((cur (logand txn todo))
                      (rate (bl.mp:depgraph-subset-feerate g cur)))
                 (when (bl.mp:feefrac> rate best-rate)
                   (setf best-set cur best-rate rate)))))
    (values best-set best-rate)))

(defun simple-linearize (g max-iterations)
  "Core SimpleLinearize (cluster_linearize.cpp:196-213): repeatedly the best
remaining candidate set, in topological order. Returns (values linearization
optimal-p)."
  (let ((todo (bl.mp:depgraph-positions g))
        (out '())
        (optimal t))
    (loop until (zerop todo)
          do (multiple-value-bind (cand rate done)
                 (simple-find-candidate-set g todo max-iterations)
               (declare (ignore rate))
               (when (= done max-iterations) (setf optimal nil))
               (dolist (i (bl.mp:depgraph-topo-sorted g cand)) (push i out))
               (setf todo (logandc2 todo cand))
               (decf max-iterations done)))
    (values (coerce (nreverse out) 'simple-vector) optimal)))

(defun %next-permutation (v)
  "std::next_permutation over the simple-vector V, in place; NIL (and V sorted
ascending again) when V was the last permutation."
  (let ((n (length v)))
    (let ((i (- n 2)))
      (loop while (and (>= i 0) (>= (svref v i) (svref v (1+ i)))) do (decf i))
      (if (< i 0)
          (progn (setf (subseq v 0) (reverse v)) nil)
          (let ((j (1- n)))
            (loop while (<= (svref v j) (svref v i)) do (decf j))
            (rotatef (svref v i) (svref v j))
            (setf (subseq v (1+ i)) (reverse (subseq v (1+ i))))
            t)))))

(defun exhaustive-linearize (g)
  "Core ExhaustiveLinearize (cluster_linearize.cpp:221-261): the best of all
topologically valid orderings, preferring more chunks on an equal diagram.
O(N!), for N <= 8."
  (let ((perm (coerce (bits-list (bl.mp:depgraph-positions g)) 'simple-vector))
        (best nil)
        (best-chunking nil))
    (loop
      (let ((topo-length 0) (perm-done 0))
        (loop while (< topo-length (length perm))
              do (let ((i (svref perm topo-length)))
                   (setf perm-done (logior perm-done (ash 1 i)))
                   (unless (bits-subset-p (bl.mp:depgraph-ancestors g i) perm-done)
                     (return))
                   (incf topo-length)))
        (if (= topo-length (length perm))
            (let* ((chunking (bl.mp:chunk-linearization g perm))
                   (cmp (and best (bl.mp:compare-chunks chunking best-chunking))))
              (when (or (null best) (eq cmp :greater)
                        (and (eq cmp :equal) (> (length chunking) (length best-chunking))))
                (setf best (copy-seq perm) best-chunking chunking)))
            ;; Fast-forward to the last permutation sharing the non-topological
            ;; prefix.
            (setf (subseq perm (1+ topo-length))
                  (reverse (subseq perm (1+ topo-length))))))
      (unless (%next-permutation perm) (return)))
    (or best (vector))))

;;; --- Comparisons read as Core writes them -------------------------------------------

(defun chunks>= (a b)
  "Core `CompareChunks(A, B) >= 0'."
  (member (bl.mp:compare-chunks a b) '(:greater :equal)))

(defun chunks= (a b)
  "Core `CompareChunks(A, B) == 0'."
  (eq (bl.mp:compare-chunks a b) :equal))

(defun clusterlin-sfl-diagram (st)
  "SpanningForestState::GetDiagram (cluster_linearize.h:1616-1624), which Core
itself calls test-only: nothing in the node reads it, so it stays internal."
  (bl.mp::sfl-diagram st))

(defun clusterlin-rand64 (ctx)
  "InsecureRandomContext::rand64 over MAKE-INSECURE-RANDOM-CONTEXT."
  (let ((bytes (insecure-rand-bytes ctx 8)) (v 0))
    (loop for b across bytes do (setf v (logior (ash v 8) b)))
    v))

;;; --- A corpus: serialized random DAGs --------------------------------------------

(defun clusterlin-random-depgraph (fdp &key (max-tx 12) (holes t))
  "A random acyclic depgraph from FDP: up to MAX-TX transactions with small
fees (some negative) and sizes, each depending on a random subset of the ones
before it, and -- with HOLES -- a random subset removed again."
  (let* ((g (bl.mp:make-depgraph))
         (n (consume-integral-in-range fdp 0 max-tx)))
    (dotimes (i n)
      (bl.mp:depgraph-add-transaction
       g (bl.mp:make-feefrac (- (consume-integral-in-range fdp 0 400) 100)
                             (consume-integral-in-range fdp 1 60)))
      (let ((parents 0))
        (dotimes (j i)
          (when (zerop (consume-integral-in-range fdp 0 3))
            (setf parents (logior parents (ash 1 j)))))
        (unless (zerop parents)
          (bl.mp:depgraph-add-dependencies g parents i))))
    (when (and holes (plusp n) (consume-bool fdp))
      (bl.mp:depgraph-remove-transactions g (logand (consume-integral fdp :u32) (bits-fill n))))
    g))

(defun clusterlin-corpus (fdp &key prefix (max-tx 12))
  "PREFIX bytes, a serialized random depgraph, then random bytes for the
VARINTs a target reads after it."
  (concatenate '(vector (unsigned-byte 8))
               (or prefix #())
               (depgraph-formatter-write (clusterlin-random-depgraph fdp :max-tx max-tx))
               (consume-bytes fdp (consume-integral-in-range fdp 0 48))))

;;; --- clusterlin_depgraph_sim (:400-560) ----------------------------------------------

(define-fuzz-target clusterlin-depgraph-sim
    (buffer :core "cluster_linearize.cpp:400-560" :iterations 600 :max-len 400)
  "A DepGraph driven by random AddTransaction / AddDependencies /
RemoveTransactions agrees with a simulation that keeps each position's
feerate and ancestor set and propagates ancestry by brute force: the same
positions (a new transaction takes the lowest free one), feerates and
ancestors, and the result passes SanityCheck."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (size *clusterlin-set-size*)
         (real (bl.mp:make-depgraph))
         (sim (make-array size :initial-element nil))
         (num-tx 0))
    (labels ((idx-fn ()
               (let ((offset (consume-integral-in-range fdp 0 (1- num-tx))))
                 (dotimes (i size)
                   (when (aref sim i)
                     (when (zerop offset) (return-from idx-fn i))
                     (decf offset)))
                 (error "idx-fn fell off the simulation")))
             (subset-fn ()
               (let ((mask (consume-integral-in-range fdp 0 (bits-fill num-tx)))
                     (subset 0))
                 (dotimes (i size)
                   (when (aref sim i)
                     (when (logbitp 0 mask) (setf subset (logior subset (ash 1 i))))
                     (setf mask (ash mask -1))))
                 subset))
             (set-fn ()
               (consume-integral-in-range fdp 0 (bits-fill size)))
             (anc-update ()
               (loop
                 (let ((updates nil))
                   (dotimes (chl size)
                     (when (aref sim chl)
                       (dolist (par (bits-list (cdr (aref sim chl))))
                         (let ((pa (cdr (aref sim par))))
                           (unless (bits-subset-p pa (cdr (aref sim chl)))
                             (setf (cdr (aref sim chl)) (logior (cdr (aref sim chl)) pa)
                                   updates t))))))
                   (unless updates (return)))))
             (check-fn (i)
               (fuzz-assert (eq (logbitp i (bl.mp:depgraph-positions real))
                                (and (aref sim i) t)))
               (when (aref sim i)
                 (fuzz-assert (bl.mp:feefrac= (bl.mp:depgraph-tx-feerate real i)
                                              (car (aref sim i))))
                 (fuzz-assert (= (fuzz-sabotage (bl.mp:depgraph-ancestors real i))
                                 (cdr (aref sim i)))
                              "position ~D: ancestors ~B, simulation ~B" i
                              (bl.mp:depgraph-ancestors real i) (cdr (aref sim i))))))
      (limited-while ((plusp (remaining-bytes fdp)) 1000)
        (let ((command (mod (consume-integral fdp :u8) 4)))
          (loop
            (cond ((and (< num-tx size) (zerop command))
                   (let* ((fee (consume-integral-in-range fdp #x-8000000000000 #x7ffffffffffff))
                          (sz (consume-integral-in-range fdp 1 #x3fffff))
                          (idx (bl.mp:depgraph-add-transaction real (bl.mp:make-feefrac fee sz))))
                     (fuzz-assert (null (aref sim idx)))
                     (fuzz-assert (= idx (position nil sim)))
                     (setf (aref sim idx) (cons (bl.mp:make-feefrac fee sz) (ash 1 idx)))
                     (incf num-tx))
                   (return))
                  ((< num-tx size) (decf command))) ; AddTransaction not chosen
            (cond ((and (plusp num-tx) (zerop command))
                   (let ((child (idx-fn))
                         (parents (subset-fn)))
                     (bl.mp:depgraph-add-dependencies real parents child)
                     (setf (cdr (aref sim child)) (logior (cdr (aref sim child)) parents)))
                   (return))
                  ((plusp num-tx) (decf command)))
            (cond ((and (plusp num-tx) (zerop command))
                   (let ((del (set-fn)))
                     (anc-update)
                     (dolist (i (bits-list del)) (check-fn i))
                     (bl.mp:depgraph-remove-transactions real del)
                     (dotimes (i size)
                       (when (aref sim i)
                         (if (logbitp i del)
                             (progn (decf num-tx) (setf (aref sim i) nil))
                             (setf (cdr (aref sim i)) (logandc2 (cdr (aref sim i)) del))))))
                   (return))
                  ((plusp num-tx) (decf command)))
            ;; Compact: no observable effect (see the file header).
            (when (zerop command) (return))
            (decf command))))
      (anc-update)
      (dotimes (i size) (check-fn i))
      (fuzz-assert (= (bl.mp:depgraph-tx-count real) num-tx))
      (clusterlin-sanity-check real))))

;;; --- clusterlin_depgraph_serialization (:562-605) -----------------------------------

(define-fuzz-target clusterlin-depgraph-serialization
    (buffer :core "cluster_linearize.cpp:562-605" :iterations 1000 :max-len 400
            :corpus (lambda (fdp) (clusterlin-corpus fdp)))
  "Any buffer decodes to an acyclic depgraph that passes SanityCheck (which
round-trips it through the formatter), and a dependency from a transaction
to one of its own ancestors makes IsAcyclic report the cycle."
  (let* ((reader (bl.ser:make-byte-reader-from buffer))
         (g (depgraph-formatter-read reader))
         (par-code 0)
         (chl-code 0))
    ;; `reader >> ... >> VARINT(par_code) >> VARINT(chl_code)', both
    ;; DepGraphIndex (uint32), in one try block.
    (handler-case (setf par-code (bl.ser:br-read-core-varint reader #xffffffff)
                        chl-code (bl.ser:br-read-core-varint reader #xffffffff))
      (bl.err:serialization-error () nil))
    (clusterlin-sanity-check g)
    (fuzz-assert (fuzz-sabotage (bl.mp:depgraph-acyclic-p g)))
    (when (< (bl.mp:depgraph-tx-count g) 2) (fuzz-reject))
    (let* ((par (bits-nth (bl.mp:depgraph-positions g)
                          (mod par-code (bl.mp:depgraph-tx-count g))))
           (ancestors (logandc2 (bl.mp:depgraph-ancestors g par) (ash 1 par))))
      (when (zerop ancestors) (fuzz-reject))
      (let ((chl (bits-nth ancestors (mod chl-code (logcount ancestors)))))
        (bl.mp:depgraph-add-dependencies g (ash 1 par) chl)
        (fuzz-assert (not (bl.mp:depgraph-acyclic-p g)))))))

;;; --- clusterlin_components (:607-697) -----------------------------------------------

(define-fuzz-target clusterlin-components
    (buffer :core "cluster_linearize.cpp:607-697" :iterations 1000 :max-len 400
            :corpus (lambda (fdp) (clusterlin-corpus fdp)))
  "FindConnectedComponent and GetConnectedComponent return a non-empty subset
of the todo set, containing the picked transaction, closed under in-todo
ancestry and descendancy, every member reaching every other -- and equal to
todo exactly when IsConnected says todo is connected."
  (let* ((reader (bl.ser:make-byte-reader-from buffer))
         (g (depgraph-formatter-read reader))
         (todo (bl.mp:depgraph-positions g)))
    (loop until (zerop todo)
          do (let* ((picked-num (clusterlin-varint reader))
                    (picked (and (< picked-num *clusterlin-set-size*)
                                 (logbitp picked-num todo)
                                 picked-num))
                    (component (if picked
                                   (bl.mp:depgraph-connected-component g todo picked)
                                   (bl.mp:depgraph-find-connected-component g todo))))
               (fuzz-assert (bits-subset-p component todo))
               (fuzz-assert (plusp component))
               (when picked (fuzz-assert (logbitp picked component)))
               (when (= todo (bl.mp:depgraph-positions g))
                 (fuzz-assert (eq (= component todo) (bl.mp:depgraph-connected-p g))))
               (fuzz-assert (eq (= (fuzz-sabotage component) todo)
                                (bl.mp:depgraph-connected-p g todo)))
               (dolist (i (bits-list component))
                 (fuzz-assert (bits-subset-p (logand (bl.mp:depgraph-ancestors g i) todo) component))
                 (fuzz-assert (bits-subset-p (logand (bl.mp:depgraph-descendants g i) todo) component)))
               (dolist (i (bits-list component))
                 (let ((reachable (ash 1 i)))
                   (loop
                     (let ((new reachable))
                       (dolist (j (bits-list reachable))
                         (setf new (logior new
                                           (logand (bl.mp:depgraph-ancestors g j) todo)
                                           (logand (bl.mp:depgraph-descendants g j) todo))))
                       (when (= new reachable) (return))
                       (setf reachable new)))
                   (fuzz-assert (= component reachable))))
               (let ((subset-bits (clusterlin-varint reader))
                     (subset 0))
                 (dolist (i (bits-list (bl.mp:depgraph-positions g)))
                   (when (logbitp i todo)
                     (when (logbitp 0 subset-bits) (setf subset (logior subset (ash 1 i))))
                     (setf subset-bits (ash subset-bits -1))))
                 (when (zerop subset) (setf subset (ash 1 (bits-first todo))))
                 (setf todo (logandc2 todo subset)))))
    (fuzz-assert (zerop (bl.mp:depgraph-find-connected-component g todo)))))

;;; --- clusterlin_make_connected (:699-711) -------------------------------------------

(define-fuzz-target clusterlin-make-connected
    (buffer :core "cluster_linearize.cpp:699-711" :iterations 1000 :max-len 400
            :corpus (lambda (fdp) (clusterlin-corpus fdp)))
  "MakeConnected leaves a graph that passes SanityCheck and is connected."
  (let ((g (depgraph-formatter-read (bl.ser:make-byte-reader-from buffer))))
    (make-connected g)
    (clusterlin-sanity-check g)
    (fuzz-assert (fuzz-sabotage (bl.mp:depgraph-connected-p g)))))

;;; --- clusterlin_chunking (:713-762) -------------------------------------------------

(define-fuzz-target clusterlin-chunking
    (buffer :core "cluster_linearize.cpp:713-762" :iterations 1000 :max-len 400
            :corpus (lambda (fdp) (clusterlin-corpus fdp)))
  "ChunkLinearization and ChunkLinearizationInfo agree; chunk feerates never
increase; and each chunk is exactly the highest-feerate prefix of what is
left of the linearization, recomputed naively."
  (let* ((reader (bl.ser:make-byte-reader-from buffer))
         (g (depgraph-formatter-read reader))
         (lin (read-linearization g reader))
         (chunking (bl.mp:chunk-linearization g lin))
         (info (bl.mp:chunk-linearization-info g lin)))
    (fuzz-assert (= (length chunking) (length info)))
    (loop for c in chunking
          for si in info
          do (fuzz-assert (bl.mp:feefrac= c (bl.mp:setinfo-feerate si)))
             (fuzz-assert (bl.mp:feefrac= (bl.mp:depgraph-subset-feerate
                                           g (bl.mp:setinfo-transactions si))
                                          (bl.mp:setinfo-feerate si))))
    (loop for (a b) on chunking
          while b
          do (fuzz-assert (not (bl.mp:feefrac>> b a))))
    (let ((todo (bl.mp:depgraph-positions g)))
      (dolist (si info)
        (fuzz-assert (plusp todo))
        (let ((acc 0) (best nil) (best-rate nil))
          (map nil (lambda (idx)
                     (when (logbitp idx todo)
                       (setf acc (logior acc (ash 1 idx)))
                       (let ((rate (bl.mp:depgraph-subset-feerate g acc)))
                         (when (or (null best-rate) (bl.mp:feefrac>> rate best-rate))
                           (setf best acc best-rate rate)))))
               lin)
          (fuzz-assert (bl.mp:feefrac= (bl.mp:setinfo-feerate si) best-rate))
          (fuzz-assert (= (fuzz-sabotage (bl.mp:setinfo-transactions si)) best))
          (fuzz-assert (bits-subset-p best todo))
          (setf todo (logandc2 todo best))))
      (fuzz-assert (zerop todo)))))

;;; --- clusterlin_simple_finder (:766-842) --------------------------------------------

(define-fuzz-target clusterlin-simple-finder
    (buffer :core "cluster_linearize.cpp:766-842" :iterations 400 :max-len 120
            :corpus (lambda (fdp) (clusterlin-corpus fdp :max-tx 10)))
  "SimpleCandidateFinder returns a non-empty, topological, connected subset of
what remains with its true feerate, within 2^(N-1) iterations; when it claims
optimality it matches ExhaustiveCandidateFinder (for N <= 12) and beats any
topological set the buffer names."
  (let* ((reader (bl.ser:make-byte-reader-from buffer))
         (g (depgraph-formatter-read reader))
         (todo (bl.mp:depgraph-positions g))
         (max-iter *clusterlin-simple-iterations*))
    (loop until (zerop todo)
          do (multiple-value-bind (found rate done) (simple-find-candidate-set g todo max-iter)
               (let ((optimal (/= done max-iter)))
                 (fuzz-assert (<= done max-iter))
                 (fuzz-assert (plusp found))
                 (fuzz-assert (bits-subset-p found todo))
                 (fuzz-assert (bl.mp:feefrac= (bl.mp:depgraph-subset-feerate g found) rate))
                 (dolist (i (bits-list found))
                   (fuzz-assert (bits-subset-p (logand (bl.mp:depgraph-ancestors g i) todo) found)))
                 (fuzz-assert (<= done (ash 1 (1- (logcount todo)))))
                 (when (> max-iter (ash 1 (1- (logcount todo))))
                   (fuzz-assert optimal))
                 (fuzz-assert (bl.mp:depgraph-connected-p g found))
                 (when optimal
                   (when (<= (logcount todo) 12)
                     (multiple-value-bind (exh-set exh-rate) (exhaustive-find-candidate-set g todo)
                       (declare (ignore exh-set))
                       (fuzz-assert (bl.mp:feefrac= exh-rate (fuzz-sabotage-feefrac rate))
                                    "exhaustive ~A, simple ~A" exh-rate rate)))
                   (let ((read-topo (read-topological-set g todo reader t)))
                     (fuzz-assert (bl.mp:feefrac>= rate (bl.mp:depgraph-subset-feerate g read-topo)))))
                 (setf todo (logandc2 todo (read-topological-set g todo reader t))))))))

(defun fuzz-sabotage-feefrac (f)
  "F, or -- in the positive-control run -- F with one more satoshi of fee."
  (if (eq *fuzz-sabotage* :assert)
      (bl.mp:make-feefrac (1+ (bl.mp:feefrac-fee f)) (bl.mp:feefrac-size f))
      f))

;;; --- clusterlin_simple_linearize (:844-889) -----------------------------------------

(define-fuzz-target clusterlin-simple-linearize
    (buffer :core "cluster_linearize.cpp:844-889" :iterations 200 :max-len 120
            :corpus (lambda (fdp)
                      (clusterlin-corpus fdp :max-tx 9
                                             :prefix (let ((bb (bl.ser:make-byte-buf)))
                                                       (bl.ser:bb-write-core-varint
                                                        bb (consume-integral-in-range fdp 0 4000))
                                                       (bl.ser:bb-finish bb)))))
  "SimpleLinearize returns a valid linearization; with an iteration budget
above 2^N it is optimal; an optimal result on at most 8 transactions has the
diagram and chunk count ExhaustiveLinearize finds, and is as good as any
linearization the buffer names."
  (let* ((reader (bl.ser:make-byte-reader-from buffer))
         (iter-count 0)
         (g (bl.mp:make-depgraph)))
    ;; `reader >> VARINT(iter_count) >> Using<DepGraphFormatter>(depgraph)':
    ;; a failed count leaves the graph unread.
    (handler-case (setf iter-count (bl.ser:br-read-core-varint reader)
                        g (depgraph-formatter-read reader))
      (bl.err:serialization-error () nil))
    (setf iter-count (mod iter-count *clusterlin-simple-iterations*))
    (multiple-value-bind (lin optimal) (simple-linearize g iter-count)
      (clusterlin-sanity-check-linearization g lin)
      (let ((simple-chunking (bl.mp:chunk-linearization g lin))
            (n (bl.mp:depgraph-tx-count g)))
        (when (and (<= n 63) (plusp (ash iter-count (- n))))
          (fuzz-assert optimal))
        (when (and optimal (<= n 8))
          (let ((exh-chunking (bl.mp:chunk-linearization g (exhaustive-linearize g))))
            (fuzz-assert (chunks= (fuzz-sabotage-chunks simple-chunking) exh-chunking))
            (fuzz-assert (= (length simple-chunking) (length exh-chunking)))))
        (when optimal
          (let ((read-chunking (bl.mp:chunk-linearization g (read-linearization g reader))))
            (fuzz-assert (chunks>= simple-chunking read-chunking))))))))

(defun fuzz-sabotage-chunks (chunks)
  "CHUNKS, or -- in the positive-control run -- CHUNKS with a better first
chunk (one more satoshi), a diagram no correct comparison calls equal."
  (if (and (eq *fuzz-sabotage* :assert) chunks)
      (cons (fuzz-sabotage-feefrac (first chunks)) (rest chunks))
      chunks))

;;; --- clusterlin_sfl (:891-1008) -----------------------------------------------------

(define-fuzz-target clusterlin-sfl
    (buffer :core "cluster_linearize.cpp:891-1008" :iterations 500 :max-len 600
            :corpus (lambda (fdp)
                      (clusterlin-corpus fdp :max-tx 24
                                             :prefix (concatenate '(vector (unsigned-byte 8))
                                                                  (consume-bytes fdp 8)
                                                                  (vector (consume-integral fdp :u8))))))
  "Every step of the spanning-forest algorithm: the diagram never gets worse
(and, once optimal, never better, with no fewer chunks); the linearization is
at least as good as the diagram (equal once optimal, with as many chunks
once minimal); optimality comes within Core's cost bound; and the result is
as good as SimpleLinearize and as any linearization the buffer names."
  (let* ((reader (bl.ser:make-byte-reader-from buffer))
         (rng-seed 0) (flags 1) (g (bl.mp:make-depgraph)))
    ;; `reader >> rng_seed >> flags >> Using<DepGraphFormatter>(depgraph)' in
    ;; one try block: a short prefix leaves the graph unread.
    (handler-case (setf rng-seed (bl.ser:br-read-u64-le reader)
                        flags (bl.ser:br-read-u8 reader)
                        g (depgraph-formatter-read reader))
      (bl.err:serialization-error () nil))
    (when (<= (bl.mp:depgraph-tx-count g) 1) (fuzz-reject))
    (let* ((rng (make-insecure-random-context rng-seed))
           (make-connected-p (logbitp 0 flags))
           (load-linearization (logbitp 1 flags))
           (load-topological (and load-linearization (logbitp 2 flags))))
      (when make-connected-p (make-connected g))
      (let ((st (bl.mp:make-spanning-forest g (clusterlin-rand64 rng)))
            (last-diagram nil)
            (was-optimal nil))
        (flet ((test-fn (&optional is-optimal is-minimal)
                 (let ((diagram (clusterlin-sfl-diagram st)))
                   (when (zerop (ldb (byte 4 0) (clusterlin-rand64 rng)))
                     (let* ((lin (bl.mp:sfl-get-linearization st))
                            (lin-diagram (bl.mp:chunk-linearization g lin))
                            (cmp (bl.mp:compare-chunks lin-diagram diagram)))
                       (fuzz-assert (member cmp '(:greater :equal)))
                       (when is-optimal (fuzz-assert (eq cmp :equal)))
                       (when is-minimal (fuzz-assert (= (length diagram) (length lin-diagram))))))
                   (when last-diagram
                     (let ((cmp (bl.mp:compare-chunks diagram last-diagram)))
                       (fuzz-assert (member cmp '(:greater :equal)))
                       (when was-optimal
                         (fuzz-assert (eq cmp :equal))
                         (fuzz-assert (>= (length diagram) (length last-diagram))))))
                   (setf last-diagram diagram
                         was-optimal is-optimal))))
          (if load-linearization
              (let ((input (read-linearization g reader load-topological)))
                (bl.mp:sfl-load-linearization st input)
                (if load-topological
                    (setf last-diagram (bl.mp:chunk-linearization g input))
                    (bl.mp:sfl-make-topological st)))
              (bl.mp:sfl-make-topological st))
          (test-fn)
          (bl.mp:sfl-start-optimizing st)
          (loop (test-fn) (unless (bl.mp:sfl-optimize-step st) (return)))
          (test-fn t)
          (bl.mp:sfl-start-minimizing st)
          (loop (test-fn t) (unless (bl.mp:sfl-minimize-step st) (return)))
          (test-fn t t)
          (fuzz-assert (<= (bl.mp:sfl-cost st)
                           (max-optimal-linearization-cost (bl.mp:depgraph-tx-count g)))
                       "SFL cost ~D over Core's bound ~D for ~D transactions"
                       (bl.mp:sfl-cost st)
                       (max-optimal-linearization-cost (bl.mp:depgraph-tx-count g))
                       (bl.mp:depgraph-tx-count g))
          (multiple-value-bind (simple-lin simple-optimal)
              (simple-linearize g (floor *clusterlin-simple-iterations* 10))
            (let* ((simple-diagram (bl.mp:chunk-linearization g simple-lin))
                   (cmp (bl.mp:compare-chunks last-diagram simple-diagram)))
              (fuzz-assert (member (fuzz-sabotage cmp) '(:greater :equal)))
              (when simple-optimal (fuzz-assert (eq cmp :equal)))
              (when (eq cmp :equal)
                (fuzz-assert (>= (length last-diagram) (length simple-diagram))))))
          (dotimes (k 10)
            (let* ((read-diagram (bl.mp:chunk-linearization g (read-linearization g reader)))
                   (cmp (bl.mp:compare-chunks last-diagram read-diagram)))
              (fuzz-assert (member cmp '(:greater :equal)))
              (when (eq cmp :equal)
                (fuzz-assert (>= (length last-diagram) (length read-diagram)))))))))))

;;; --- clusterlin_linearize (:1010-1159) ----------------------------------------------

(defun clusterlin-check-chunk-orders (g lin)
  "The two tie-break assertions of clusterlin_linearize (:1086-1150): inside
a chunk, no transaction could take an earlier one's place with a better
(feerate, size, position) key; and no chunk could take an earlier chunk's
place with a better (feerate, size, last position) key."
  (let ((info (bl.mp:chunk-linearization-info g lin))
        (done 0)
        (pos 0))
    (dolist (chunk info)
      (let* ((start pos)
             (end (+ pos (logcount (bl.mp:setinfo-transactions chunk)) -1)))
        (loop for pos1 from start to end
              for tx1 = (svref lin pos1)
              do (loop for pos2 from (1+ pos1) to end
                       for tx2 = (svref lin pos2)
                       do (when (= 1 (logcount (logandc2 (bl.mp:depgraph-ancestors g tx2) done)))
                            (let ((f1 (bl.mp:depgraph-tx-feerate g tx1))
                                  (f2 (bl.mp:depgraph-tx-feerate g tx2)))
                              (fuzz-assert (bl.mp:feefrac>= f1 f2)
                                           "in-chunk order: tx ~D (~A) before ~D (~A)" tx1 f1 tx2 f2)
                              (when (bl.mp:feefrac= f1 f2)
                                (fuzz-assert (< tx1 tx2))))))
                 (setf done (logior done (ash 1 tx1))))
        (setf pos (1+ end))))
    (setf done 0)
    (loop for (chunk1 . rest) on info
          do (dolist (chunk2 rest)
               (let ((anc2 0))
                 (bl.mp:do-bits (tx (bl.mp:setinfo-transactions chunk2))
                   (setf anc2 (logior anc2 (bl.mp:depgraph-ancestors g tx))))
                 (when (bits-subset-p (logandc2 anc2 done) (bl.mp:setinfo-transactions chunk2))
                   (fuzz-assert (bl.mp:feefrac>= (bl.mp:setinfo-feerate chunk1)
                                                 (bl.mp:setinfo-feerate chunk2))
                                "chunk order: ~A before ~A" (bl.mp:setinfo-feerate chunk1)
                                (bl.mp:setinfo-feerate chunk2))
                   (when (bl.mp:feefrac= (bl.mp:setinfo-feerate chunk1) (bl.mp:setinfo-feerate chunk2))
                     (fuzz-assert (< (bits-last (bl.mp:setinfo-transactions chunk1))
                                     (bits-last (bl.mp:setinfo-transactions chunk2))))))))
             (setf done (logior done (bl.mp:setinfo-transactions chunk1))))))

(define-fuzz-target clusterlin-linearize
    (buffer :core "cluster_linearize.cpp:1010-1159" :iterations 500 :max-len 600
            :corpus (lambda (fdp)
                      (concatenate '(vector (unsigned-byte 8))
                                   (let ((bb (bl.ser:make-byte-buf)))
                                     (bl.ser:bb-write-core-varint
                                      bb (if (consume-bool fdp)
                                             (consume-integral-in-range fdp 0 #x3fffff)
                                             (consume-integral-in-range fdp 0 3000)))
                                     (bl.ser:bb-finish bb))
                                   (depgraph-formatter-write (clusterlin-random-depgraph fdp :max-tx 24))
                                   (consume-bytes fdp 8)
                                   (vector (consume-integral fdp :u8))
                                   (consume-bytes fdp (consume-integral-in-range fdp 0 40)))))
  "Linearize returns a valid linearization at least as good as a topological
input; with a budget above Core's bound it is optimal; an optimal result is as
good as SimpleLinearize (equal to it when that is optimal too, with no fewer
chunks) and as any linearization the buffer names, orders transactions inside
chunks and the chunks themselves by Core's tie-breaks, and is reproduced
exactly from a different seed."
  (let* ((reader (bl.ser:make-byte-reader-from buffer))
         (max-cost 0) (g (bl.mp:make-depgraph)) (rng-seed 0) (flags 7))
    (block read
      (handler-case (setf max-cost (bl.ser:br-read-core-varint reader))
        (bl.err:serialization-error () (return-from read)))
      (setf g (depgraph-formatter-read reader))
      (handler-case (setf rng-seed (bl.ser:br-read-u64-le reader)
                          flags (bl.ser:br-read-u8 reader))
        (bl.err:serialization-error () nil)))
    (when (<= (bl.mp:depgraph-tx-count g) 1) (fuzz-reject))
    (let ((provide-input (logtest flags 6))
          (provide-topological (logbitp 2 flags))
          (claim-topological (= (logand flags 6) 6))
          (old nil))
      (when (logbitp 0 flags) (make-connected g))
      (when provide-input
        (setf old (read-linearization g reader provide-topological))
        (when provide-topological (clusterlin-sanity-check-linearization g old)))
      (setf max-cost (logand max-cost #x3fffff))
      (multiple-value-bind (lin optimal)
          (bl.mp:sfl-linearize g :max-cost max-cost :rng-seed rng-seed
                                 :old-linearization old :topological claim-topological)
        (clusterlin-sanity-check-linearization g lin)
        (let ((chunking (bl.mp:chunk-linearization g lin)))
          (when provide-topological
            (fuzz-assert (chunks>= chunking (bl.mp:chunk-linearization g old))))
          (when (> max-cost (max-optimal-linearization-cost (bl.mp:depgraph-tx-count g)))
            (fuzz-assert optimal "budget ~D over Core's bound, yet not optimal" max-cost))
          (when optimal
            (multiple-value-bind (simple-lin simple-optimal)
                (simple-linearize g *clusterlin-simple-iterations*)
              (clusterlin-sanity-check-linearization g simple-lin)
              (let* ((simple-chunking (bl.mp:chunk-linearization g simple-lin))
                     (cmp (bl.mp:compare-chunks chunking simple-chunking)))
                (fuzz-assert (member (fuzz-sabotage cmp) '(:greater :equal)))
                (when simple-optimal (fuzz-assert (eq cmp :equal)))
                (when (eq cmp :equal)
                  (fuzz-assert (>= (length chunking) (length simple-chunking))))))
            (fuzz-assert (chunks>= chunking (bl.mp:chunk-linearization g (read-linearization g reader))))
            (clusterlin-check-chunk-orders g lin)
            (multiple-value-bind (lin2 optimal2)
                (bl.mp:sfl-linearize g :max-cost (1+ (max-optimal-linearization-cost
                                                      (bl.mp:depgraph-tx-count g)))
                                       :rng-seed (logxor rng-seed #x1337))
              (fuzz-assert optimal2)
              (fuzz-assert (equalp lin2 lin) "reseeded optimal linearization ~S differs from ~S"
                           lin2 lin))))))))

;;; --- clusterlin_postlinearize (:1161-1201) ------------------------------------------

(define-fuzz-target clusterlin-postlinearize
    (buffer :core "cluster_linearize.cpp:1161-1201" :iterations 1000 :max-len 400
            :corpus (lambda (fdp) (clusterlin-corpus fdp :max-tx 16)))
  "PostLinearize never worsens a linearization, a second pass never worsens
the first, and every chunk it produces is connected."
  (let* ((reader (bl.ser:make-byte-reader-from buffer))
         (g (depgraph-formatter-read reader))
         (lin (read-linearization g reader)))
    (clusterlin-sanity-check-linearization g lin)
    (let ((post (bl.mp:post-linearize g lin)))
      (clusterlin-sanity-check-linearization g post)
      (let ((chunking (bl.mp:chunk-linearization g lin))
            (post-chunking (bl.mp:chunk-linearization g post)))
        (fuzz-assert (chunks>= post-chunking (fuzz-sabotage-chunks chunking)))
        (let ((post-post (bl.mp:post-linearize g post)))
          (clusterlin-sanity-check-linearization g post-post)
          (fuzz-assert (chunks>= (bl.mp:chunk-linearization g post-post) post-chunking)))
        (dolist (si (bl.mp:chunk-linearization-info g post))
          (fuzz-assert (bl.mp:depgraph-connected-p g (bl.mp:setinfo-transactions si))))))))

;;; --- clusterlin_postlinearize_tree (:1203-1250) -------------------------------------

(define-fuzz-target clusterlin-postlinearize-tree
    (buffer :core "cluster_linearize.cpp:1203-1250" :iterations 800 :max-len 400
            :corpus (lambda (fdp)
                      (clusterlin-corpus fdp :max-tx 16
                                             :prefix (concatenate '(vector (unsigned-byte 8))
                                                                  (vector (consume-integral fdp :u8))
                                                                  (consume-bytes fdp 8)))))
  "On a graph where every transaction has at most one parent (or at most one
child), PostLinearize is optimal: it never worsens the input, a second pass
leaves the diagram unchanged, and Linearize seeded with its output finds
nothing better."
  (let* ((reader (bl.ser:make-byte-reader-from buffer))
         (direction 0) (rng-seed 0) (gen (bl.mp:make-depgraph)))
    (handler-case (setf direction (bl.ser:br-read-u8 reader)
                        rng-seed (bl.ser:br-read-u64-le reader)
                        gen (depgraph-formatter-read reader))
      (bl.err:serialization-error () nil))
    (let* ((tree (build-tree-graph gen direction))
           (lin (read-linearization tree reader)))
      (clusterlin-sanity-check-linearization tree lin)
      (let* ((post (bl.mp:post-linearize tree lin))
             (chunking (bl.mp:chunk-linearization tree lin))
             (post-chunking (bl.mp:chunk-linearization tree post)))
        (clusterlin-sanity-check-linearization tree post)
        (fuzz-assert (chunks>= post-chunking chunking))
        (let ((post-post (bl.mp:post-linearize tree post)))
          (clusterlin-sanity-check-linearization tree post-post)
          (fuzz-assert (chunks= (bl.mp:chunk-linearization tree post-post)
                                (fuzz-sabotage-chunks post-chunking))))
        (let ((opt (bl.mp:sfl-linearize tree :max-cost 1000000 :rng-seed rng-seed
                                             :old-linearization post)))
          (fuzz-assert (chunks= (bl.mp:chunk-linearization tree opt) post-chunking)
                       "Linearize improved a post-linearized tree"))))))

;;; --- clusterlin_postlinearize_moved_leaf (:1252-1293) -------------------------------

(define-fuzz-target clusterlin-postlinearize-moved-leaf
    (buffer :core "cluster_linearize.cpp:1252-1293" :iterations 1000 :max-len 400
            :corpus (lambda (fdp)
                      (concatenate '(vector (unsigned-byte 8))
                                   (depgraph-formatter-write (clusterlin-random-depgraph fdp :max-tx 16))
                                   (let ((bb (bl.ser:make-byte-buf)))
                                     (bl.ser:bb-write-core-varint bb (consume-integral fdp :u32))
                                     (bl.ser:bb-finish bb))
                                   (consume-bytes fdp (consume-integral-in-range fdp 0 40)))))
  "Moving a leaf of one linearization to the back, raising its fee, and
post-linearizing gives a result at least as good as the original: the RBF
guarantee that `remove conflicts, append the replacement, postlinearize'
never worsens a cluster."
  (let* ((reader (bl.ser:make-byte-reader-from buffer))
         (g (depgraph-formatter-read reader))
         (fee-inc (logand (clusterlin-varint reader) #x3ffff)))
    (when (zerop (bl.mp:depgraph-tx-count g)) (fuzz-reject))
    (let* ((lin (read-linearization g reader))
           (lin-leaf (read-linearization g reader))
           (leaf (svref lin-leaf (1- (length lin-leaf))))
           (moved (concatenate 'simple-vector (remove leaf lin) (vector leaf))))
      (setf moved (bl.mp:post-linearize g moved))
      (clusterlin-sanity-check-linearization g moved)
      (let ((old-chunking (bl.mp:chunk-linearization g lin)))
        (incf (bl.mp:feefrac-fee (bl.mp:depgraph-tx-feerate g leaf)) fee-inc)
        (fuzz-assert (chunks>= (fuzz-sabotage-chunks-worse (bl.mp:chunk-linearization g moved))
                               old-chunking))))))

(defun fuzz-sabotage-chunks-worse (chunks)
  "CHUNKS, or -- in the positive-control run -- CHUNKS with a first chunk one
satoshi poorer, a diagram that cannot compare >= to one it merely equalled."
  (if (and (eq *fuzz-sabotage* :assert) chunks)
      (cons (bl.mp:make-feefrac (1- (bl.mp:feefrac-fee (first chunks)))
                                (bl.mp:feefrac-size (first chunks)))
            (rest chunks))
      chunks))
