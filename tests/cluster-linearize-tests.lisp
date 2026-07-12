(in-package #:bitcoin-lisp.tests)

;;;; Cluster linearization tests
;;;;
;;;; Validates src/mempool/cluster-linearize.lisp against Bitcoin Core's
;;;; cluster_linearize.h semantics. Unit shapes are taken from Core's
;;;; cluster_linearize_tests.cpp depgraph_ser_tests clusters and the DepGraph
;;;; doc comments; the invariant checks port the DepGraph/linearization
;;;; SanityCheck from Core test/util/cluster_linearize.h:286-397. Core's
;;;; depgraph_optimal_tests need the SFL optimal linearizer (out of scope
;;;; until P10), so linearizer quality is covered by PostLinearize's own
;;;; guarantees over deterministic randomized DAGs instead.

(def-suite :cluster-linearize-tests
  :description "DepGraph/chunking/linearization vs Core cluster_linearize.h"
  :in :bitcoin-lisp-tests)

(in-suite :cluster-linearize-tests)

;;;; Helpers

(defun %bits (&rest idxs)
  "Bitset with the given indices set."
  (reduce (lambda (acc i) (logior acc (ash 1 i))) idxs :initial-value 0))

(defun %dg-add (g fee size)
  (bitcoin-lisp.mempool:depgraph-add-transaction
   g (bitcoin-lisp.mempool:make-feefrac fee size)))

(defun %dg-anc (g i) (bitcoin-lisp.mempool:depgraph-ancestors g i))
(defun %dg-desc (g i) (bitcoin-lisp.mempool:depgraph-descendants g i))
(defun %dg-chunks (g lin) (bitcoin-lisp.mempool:chunk-linearization g lin))
(defun %dg-topo-p (g lin) (bitcoin-lisp.mempool:linearization-topological-p g lin))

(defun %cl-make-rng (seed)
  "Deterministic xorshift64 PRNG closure: (funcall rng n) => [0, n). No
dependence on the global *random-state*, so runs are reproducible."
  (let ((state seed))
    (lambda (n)
      (setf state (ldb (byte 64 0) (logxor state (ash state 13))))
      (setf state (logxor state (ash state -7)))
      (setf state (ldb (byte 64 0) (logxor state (ash state 17))))
      (mod state n))))

(defun %cl-random-depgraph (rng n)
  "A random DAG of N transactions; edges only from lower to higher position."
  (let ((g (bitcoin-lisp.mempool:make-depgraph)))
    (dotimes (i n)
      (%dg-add g (- (funcall rng 10001) 2000) (1+ (funcall rng 1000))))
    (loop for child from 1 below n
          do (let ((parents 0))
               (dotimes (p child)
                 (when (< (funcall rng 100) 30)
                   (setf parents (logior parents (ash 1 p)))))
               (bitcoin-lisp.mempool:depgraph-add-dependencies g parents child)))
    g))

(defun %cl-shuffled-topo-linearization (rng g)
  "A pseudo-random valid linearization: shuffle positions, then stable-sort
by ancestor count (Core cluster_linearize_tests.cpp:82-83). Assumes no holes."
  (let* ((n (bitcoin-lisp.mempool:depgraph-tx-count g))
         (v (make-array n)))
    (dotimes (i n) (setf (svref v i) i))
    (loop for i from (1- n) above 0
          do (rotatef (svref v i) (svref v (funcall rng (1+ i)))))
    (stable-sort v #'< :key (lambda (i) (logcount (%dg-anc g i))))))

(defun %cl-chunks-monotone-p (chunks)
  "Chunk feerates must be monotonically non-increasing."
  (loop for (a b) on chunks
        always (or (null b) (not (bitcoin-lisp.mempool:feefrac>> b a)))))

(defun %cl-chunks-connected-p (g lin)
  "Every chunk of LIN must be a connected subset of G."
  (every (lambda (si)
           (bitcoin-lisp.mempool:depgraph-connected-p
            g (bitcoin-lisp.mempool:setinfo-transactions si)))
         (bitcoin-lisp.mempool:chunk-linearization-info g lin)))

(defun %cl-chunks-equal-p (chunks expected)
  "CHUNKS (feefrac list) equals EXPECTED, a list of (fee size) pairs."
  (and (= (length chunks) (length expected))
       (every (lambda (c e)
                (bitcoin-lisp.mempool:feefrac= c (bitcoin-lisp.mempool:make-feefrac
                                                  (first e) (second e))))
              chunks expected)))

(defun %cl-depgraph-sane-p (g)
  "Port of the closure invariants of Core's DepGraph SanityCheck
(test/util/cluster_linearize.h:286-380, minus serialization): self-inclusion,
closure-of-closure, ancestor/descendant duality, and (for acyclic graphs)
that iterating reduced parents/children reconstructs the closures."
  (let ((positions (bitcoin-lisp.mempool:depgraph-positions g)))
    (block check
      (loop for i from 0 below 64 when (logbitp i positions) do
        (let ((anc (%dg-anc g i))
              (desc (%dg-desc g i)))
          ;; Transactions include themselves in both closures.
          (unless (and (logbitp i anc) (logbitp i desc))
            (return-from check nil))
          ;; If a is an ancestor of i, i's ancestors include all of a's.
          (loop for a from 0 below 64 when (logbitp a anc) do
            (unless (zerop (logandc2 (%dg-anc g a) anc))
              (return-from check nil)))
          ;; anc(i)[j] == desc(j)[i].
          (loop for j from 0 below 64 when (logbitp j positions) do
            (unless (eq (logbitp j anc) (logbitp i (%dg-desc g j)))
              (return-from check nil)))
          ;; Reduced parents/children exclude self and are mutually minimal.
          (let ((parents (bitcoin-lisp.mempool:depgraph-reduced-parents g i))
                (children (bitcoin-lisp.mempool:depgraph-reduced-children g i)))
            (when (or (logbitp i parents) (logbitp i children))
              (return-from check nil))
            (loop for p from 0 below 64 when (logbitp p parents) do
              (unless (zerop (logandc2 (logand (%dg-anc g p) parents) (ash 1 p)))
                (return-from check nil)))
            (loop for c from 0 below 64 when (logbitp c children) do
              (unless (zerop (logandc2 (logand (%dg-desc g c) children) (ash 1 c)))
                (return-from check nil))))))
      ;; In acyclic graphs, iterating reduced parents rebuilds the ancestor
      ;; closure exactly.
      (when (bitcoin-lisp.mempool:depgraph-acyclic-p g)
        (loop for i from 0 below 64 when (logbitp i positions) do
          (let ((ancestors (ash 1 i)))
            (loop
              (let ((old ancestors))
                (loop for j from 0 below 64 when (logbitp j ancestors)
                      do (setf ancestors
                               (logior ancestors
                                       (bitcoin-lisp.mempool:depgraph-reduced-parents g j))))
                (when (= old ancestors) (return))))
            (unless (= ancestors (%dg-anc g i))
              (return-from check nil)))))
      t)))

;;;; DepGraph

(test depgraph-add-and-accessors
  "AddTransaction fills the first available position; feerates are stored by
copy (cluster_linearize.h:135-148)."
  (let ((g (bitcoin-lisp.mempool:make-depgraph))
        (fr (bitcoin-lisp.mempool:make-feefrac 42 11)))
    (is (= 0 (bitcoin-lisp.mempool:depgraph-add-transaction g fr)))
    (is (= 1 (%dg-add g -13 7)))
    (is (= (%bits 0 1) (bitcoin-lisp.mempool:depgraph-positions g)))
    (is (= 2 (bitcoin-lisp.mempool:depgraph-position-range g)))
    (is (= 2 (bitcoin-lisp.mempool:depgraph-tx-count g)))
    ;; Mutating the caller's feefrac must not leak into the graph.
    (setf (bitcoin-lisp.mempool:feefrac-fee fr) 999)
    (is (= 42 (bitcoin-lisp.mempool:feefrac-fee
               (bitcoin-lisp.mempool:depgraph-tx-feerate g 0))))
    ;; New transactions are unconnected singletons.
    (is (= (%bits 0) (%dg-anc g 0)))
    (is (= (%bits 0) (%dg-desc g 0)))
    (is (bitcoin-lisp.mempool:feefrac=
         (bitcoin-lisp.mempool:make-feefrac 29 18)
         (bitcoin-lisp.mempool:depgraph-subset-feerate g (%bits 0 1))))))

(test depgraph-diamond-closures
  "A(64,128), B(128,256), C(1,1) with C depending on A and B
(cluster_linearize_tests.cpp:152-166)."
  (let ((g (bitcoin-lisp.mempool:make-depgraph)))
    (%dg-add g 64 128) (%dg-add g 128 256) (%dg-add g 1 1)
    (bitcoin-lisp.mempool:depgraph-add-dependencies g (%bits 0 1) 2)
    (is (= (%bits 0) (%dg-anc g 0)))
    (is (= (%bits 1) (%dg-anc g 1)))
    (is (= (%bits 0 1 2) (%dg-anc g 2)))
    (is (= (%bits 0 2) (%dg-desc g 0)))
    (is (= (%bits 1 2) (%dg-desc g 1)))
    (is (= (%bits 2) (%dg-desc g 2)))
    (is (= (%bits 0 1) (bitcoin-lisp.mempool:depgraph-reduced-parents g 2)))
    (is (= (%bits 2) (bitcoin-lisp.mempool:depgraph-reduced-children g 0)))
    (is (= (%bits 2) (bitcoin-lisp.mempool:depgraph-reduced-children g 1)))
    (is-true (bitcoin-lisp.mempool:depgraph-connected-p g))
    (is-true (bitcoin-lisp.mempool:depgraph-acyclic-p g))
    ;; {A,B} is NOT connected without C...
    (is-false (bitcoin-lisp.mempool:depgraph-connected-p g (%bits 0 1)))
    (is (= (%bits 0) (bitcoin-lisp.mempool:depgraph-find-connected-component g (%bits 0 1))))
    ;; ...and the empty set trivially is.
    (is-true (bitcoin-lisp.mempool:depgraph-connected-p g 0))
    (is-true (%cl-depgraph-sane-p g))))

(test depgraph-transitive-dependencies
  "AddDependencies updates full closures when linking existing chains
(cluster_linearize.h:179-200)."
  (let ((g (bitcoin-lisp.mempool:make-depgraph)))
    (%dg-add g 1 1) (%dg-add g 2 1) (%dg-add g 3 1)
    ;; First C spends B, then B spends A: A's descendants must gain {B,C}
    ;; and C's ancestors must gain A transitively.
    (bitcoin-lisp.mempool:depgraph-add-dependencies g (%bits 1) 2)
    (bitcoin-lisp.mempool:depgraph-add-dependencies g (%bits 0) 1)
    (is (= (%bits 0 1 2) (%dg-anc g 2)))
    (is (= (%bits 0 1 2) (%dg-desc g 0)))
    ;; Reduced parents keep only the direct edge.
    (is (= (%bits 1) (bitcoin-lisp.mempool:depgraph-reduced-parents g 2)))
    (is (= (%bits 1) (bitcoin-lisp.mempool:depgraph-reduced-children g 0)))
    ;; Re-adding an implied dependency (C on A) is a no-op.
    (bitcoin-lisp.mempool:depgraph-add-dependencies g (%bits 0) 2)
    (is (= (%bits 1) (bitcoin-lisp.mempool:depgraph-reduced-parents g 2)))
    (is-true (%cl-depgraph-sane-p g))))

(test depgraph-remove-transactions
  "RemoveTransactions masks closures and reclaims trailing positions; a
removed middleman keeps grandparents as ancestors (cluster_linearize.h:150-173)."
  (let ((g (bitcoin-lisp.mempool:make-depgraph)))
    (%dg-add g 1 1) (%dg-add g 2 1) (%dg-add g 3 1)
    (bitcoin-lisp.mempool:depgraph-add-dependencies g (%bits 0) 1)
    (bitcoin-lisp.mempool:depgraph-add-dependencies g (%bits 1) 2)
    ;; Remove the middle of the chain A->B->C.
    (bitcoin-lisp.mempool:depgraph-remove-transactions g (%bits 1))
    (is (= (%bits 0 2) (bitcoin-lisp.mempool:depgraph-positions g)))
    (is (= 3 (bitcoin-lisp.mempool:depgraph-position-range g)))
    (is (= (%bits 0 2) (%dg-anc g 2)))
    (is (= (%bits 0 2) (%dg-desc g 0)))
    (is (= (%bits 0) (bitcoin-lisp.mempool:depgraph-reduced-parents g 2)))
    ;; Still connected through the whole-graph relation, even with the parent
    ;; missing from the subset (cluster_linearize.h:255-262).
    (is-true (bitcoin-lisp.mempool:depgraph-connected-p g (%bits 0 2)))
    (is (= (%bits 0 2) (bitcoin-lisp.mempool:depgraph-connected-component g (%bits 0 2) 0)))
    ;; Removing the tail entry shrinks the position range...
    (bitcoin-lisp.mempool:depgraph-remove-transactions g (%bits 2))
    (is (= (%bits 0) (bitcoin-lisp.mempool:depgraph-positions g)))
    (is (= 1 (bitcoin-lisp.mempool:depgraph-position-range g)))
    ;; ...and the freed position is the next one handed out.
    (is (= 1 (%dg-add g 5 1)))
    (is (= (%bits 1) (%dg-anc g 1)))
    (is-true (%cl-depgraph-sane-p g))))

(test depgraph-five-tx-example
  "The A..E cluster from Core's serialization tests: A(1,2) B(3,1) C(2,1)
D(1,3) E(1,1); deps C->A, D->A, D->B, E->D (cluster_linearize_tests.cpp:189-192)."
  (let ((g (bitcoin-lisp.mempool:make-depgraph)))
    (%dg-add g 1 2) (%dg-add g 3 1) (%dg-add g 2 1) (%dg-add g 1 3) (%dg-add g 1 1)
    (bitcoin-lisp.mempool:depgraph-add-dependencies g (%bits 0) 2)
    (bitcoin-lisp.mempool:depgraph-add-dependencies g (%bits 0 1) 3)
    (bitcoin-lisp.mempool:depgraph-add-dependencies g (%bits 3) 4)
    (is (= (%bits 0) (%dg-anc g 0)))
    (is (= (%bits 1) (%dg-anc g 1)))
    (is (= (%bits 0 2) (%dg-anc g 2)))
    (is (= (%bits 0 1 3) (%dg-anc g 3)))
    (is (= (%bits 0 1 3 4) (%dg-anc g 4)))
    (is (= (%bits 0 2 3 4) (%dg-desc g 0)))
    (is (= (%bits 1 3 4) (%dg-desc g 1)))
    (is (= (%bits 2) (%dg-desc g 2)))
    (is (= (%bits 3 4) (%dg-desc g 3)))
    (is (= (%bits 4) (%dg-desc g 4)))
    (is (= (%bits 0 1) (bitcoin-lisp.mempool:depgraph-reduced-parents g 3)))
    (is (= (%bits 3) (bitcoin-lisp.mempool:depgraph-reduced-parents g 4)))
    (is (= (%bits 2 3) (bitcoin-lisp.mempool:depgraph-reduced-children g 0)))
    (is (= (%bits 3) (bitcoin-lisp.mempool:depgraph-reduced-children g 1)))
    (is-true (bitcoin-lisp.mempool:depgraph-connected-p g))
    (is-true (bitcoin-lisp.mempool:depgraph-acyclic-p g))
    ;; Connected components within {C,D,E}: {C} and {D,E}.
    (is (= (%bits 2) (bitcoin-lisp.mempool:depgraph-connected-component g (%bits 2 3 4) 2)))
    (is (= (%bits 3 4) (bitcoin-lisp.mempool:depgraph-connected-component g (%bits 2 3 4) 3)))
    (is-false (bitcoin-lisp.mempool:depgraph-connected-p g (%bits 2 3 4)))
    ;; Topological subsets: closed under ancestors.
    (is-true (bitcoin-lisp.mempool:topological-subset-p g (%bits 0)))
    (is-true (bitcoin-lisp.mempool:topological-subset-p g (%bits 0 2)))
    (is-false (bitcoin-lisp.mempool:topological-subset-p g (%bits 2)))
    (is-true (bitcoin-lisp.mempool:topological-subset-p g (%bits 0 1 3)))
    (is-false (bitcoin-lisp.mempool:topological-subset-p g (%bits 3 4)))
    (is-true (bitcoin-lisp.mempool:topological-subset-p g (%bits 0 1 2 3 4)))
    ;; Topological order and the linearization validity check.
    (is (equal '(0 1 2 3 4) (bitcoin-lisp.mempool:depgraph-topo-sorted g)))
    (is-true (%dg-topo-p g #(0 1 2 3 4)))
    (is-true (%dg-topo-p g #(1 0 3 4 2)))
    (is-false (%dg-topo-p g #(1 3 0 4 2)))   ; D before its parent A
    (is-false (%dg-topo-p g #(0 1 2 3)))     ; incomplete
    (is-false (%dg-topo-p g #(0 0 1 2 3)))   ; duplicate
    (is-true (%cl-depgraph-sane-p g))))

;;;; Chunking

(test chunk-linearization-basics
  "The greedy absorb pass (cluster_linearize.h:427-463)."
  (let ((g (bitcoin-lisp.mempool:make-depgraph)))
    (%dg-add g 1 2) (%dg-add g 3 1)
    (bitcoin-lisp.mempool:depgraph-add-dependencies g (%bits 0) 1)
    ;; Singleton.
    (is (%cl-chunks-equal-p (%dg-chunks g #(0)) '((1 2))))
    ;; Higher-feerate successor is absorbed (CPFP).
    (is (%cl-chunks-equal-p (%dg-chunks g #(0 1)) '((4 3)))))
  (let ((g (bitcoin-lisp.mempool:make-depgraph)))
    (%dg-add g 3 1) (%dg-add g 1 2)
    ;; Decreasing feerates stay separate.
    (is (%cl-chunks-equal-p (%dg-chunks g #(0 1)) '((3 1) (1 2)))))
  (let ((g (bitcoin-lisp.mempool:make-depgraph)))
    (%dg-add g 1 1) (%dg-add g 1 1)
    ;; Absorption needs a STRICTLY higher feerate; equal stays separate.
    (is (%cl-chunks-equal-p (%dg-chunks g #(0 1)) '((1 1) (1 1)))))
  (let ((g (bitcoin-lisp.mempool:make-depgraph)))
    (%dg-add g 1 1) (%dg-add g 5 1) (%dg-add g 2 1)
    ;; Cascading absorb: (5,1) eats (1,1); (2,1) does not eat (6,2).
    (is (%cl-chunks-equal-p (%dg-chunks g #(0 1 2)) '((6 2) (2 1))))
    ;; The setinfo variant carries the chunk transaction sets (boundaries).
    (let ((info (bitcoin-lisp.mempool:chunk-linearization-info g #(0 1 2))))
      (is (= 2 (length info)))
      (is (= (%bits 0 1) (bitcoin-lisp.mempool:setinfo-transactions (first info))))
      (is (= (%bits 2) (bitcoin-lisp.mempool:setinfo-transactions (second info))))
      (is (bitcoin-lisp.mempool:feefrac=
           (bitcoin-lisp.mempool:make-feefrac 6 2)
           (bitcoin-lisp.mempool:setinfo-feerate (first info)))))))

;;;; Linearization

(test ancestor-sort-linearization-cpfp
  "Ancestor-set feerate seeding picks the best remaining ancestor set."
  ;; Low-fee parent 0, high-fee child 1, medium standalone 2: the {0,1}
  ;; package (rate 0.5) beats standalone {2} (0.3).
  (let ((g (bitcoin-lisp.mempool:make-depgraph)))
    (%dg-add g 1 100) (%dg-add g 99 100) (%dg-add g 30 100)
    (bitcoin-lisp.mempool:depgraph-add-dependencies g (%bits 0) 1)
    (is (equalp #(0 1 2) (bitcoin-lisp.mempool:ancestor-sort-linearization g))))
  ;; With a better standalone (0.9), it goes first.
  (let ((g (bitcoin-lisp.mempool:make-depgraph)))
    (%dg-add g 1 100) (%dg-add g 99 100) (%dg-add g 90 100)
    (bitcoin-lisp.mempool:depgraph-add-dependencies g (%bits 0) 1)
    (is (equalp #(2 0 1) (bitcoin-lisp.mempool:ancestor-sort-linearization g)))))

(test post-linearize-improves-diagram
  "PostLinearize pulls a high-fee child past an unrelated low-fee tx
(cluster_linearize.h:1854-2037): [0,1,2] with 2 spending 0 becomes [0,2,1]."
  (let ((g (bitcoin-lisp.mempool:make-depgraph)))
    (%dg-add g 5 1) (%dg-add g 0 1000) (%dg-add g 10 1)
    (bitcoin-lisp.mempool:depgraph-add-dependencies g (%bits 0) 2)
    (let* ((input #(0 1 2))
           (output (bitcoin-lisp.mempool:post-linearize g input)))
      (is (equalp #(0 2 1) output))
      (is-true (%dg-topo-p g output))
      (is (%cl-chunks-equal-p (%dg-chunks g output) '((15 2) (0 1000))))
      (is (eq :greater (bitcoin-lisp.mempool:compare-chunks
                        (%dg-chunks g output) (%dg-chunks g input))))
      (is-true (%cl-chunks-connected-p g output))
      ;; Already-optimal input: diagram is preserved.
      (let ((again (bitcoin-lisp.mempool:post-linearize g output)))
        (is-true (%dg-topo-p g again))
        (is (eq :equal (bitcoin-lisp.mempool:compare-chunks
                        (%dg-chunks g again) (%dg-chunks g output))))))))

(test linearize-full-pipeline
  "linearize = ancestor seeding + PostLinearize; sane on small fixed shapes."
  (let ((g (bitcoin-lisp.mempool:make-depgraph)))
    ;; Diamond A(64,128) B(128,256) C(1,1), C spends A and B.
    (%dg-add g 64 128) (%dg-add g 128 256) (%dg-add g 1 1)
    (bitcoin-lisp.mempool:depgraph-add-dependencies g (%bits 0 1) 2)
    (let ((lin (bitcoin-lisp.mempool:linearize g)))
      (is-true (%dg-topo-p g lin))
      (is-true (%cl-chunks-monotone-p (%dg-chunks g lin)))
      (is-true (%cl-chunks-connected-p g lin))))
  ;; Empty graph.
  (let ((g (bitcoin-lisp.mempool:make-depgraph)))
    (is (equalp #() (bitcoin-lisp.mempool:linearize g)))
    (is (null (%dg-chunks g #())))))

(test cluster-linearize-randomized-properties
  "200 deterministic random DAGs (up to 12 txs): the linearizer is
topological; chunk feerates are non-increasing; PostLinearize never worsens
the diagram (:greater or :equal, its documented guarantee) and leaves only
connected chunks; DepGraph invariants hold throughout."
  (let ((rng (%cl-make-rng 88172645463325252)))
    (dotimes (iter 200)
      (let* ((n (1+ (funcall rng 12)))
             (g (%cl-random-depgraph rng n))
             (lin0 (bitcoin-lisp.mempool:ancestor-sort-linearization g))
             (lin1 (bitcoin-lisp.mempool:post-linearize g lin0)))
        (is-true (%cl-depgraph-sane-p g))
        (is-true (%dg-topo-p g lin0))
        (is-true (%dg-topo-p g lin1))
        (is-true (%cl-chunks-monotone-p (%dg-chunks g lin0)))
        (is-true (%cl-chunks-monotone-p (%dg-chunks g lin1)))
        (is (member (bitcoin-lisp.mempool:compare-chunks
                     (%dg-chunks g lin1) (%dg-chunks g lin0))
                    '(:greater :equal)))
        (is-true (%cl-chunks-connected-p g lin1))
        ;; Same PostLinearize guarantees from an arbitrary valid input order.
        (let* ((lin2 (%cl-shuffled-topo-linearization rng g))
               (lin3 (bitcoin-lisp.mempool:post-linearize g lin2)))
          (is-true (%dg-topo-p g lin2))
          (is-true (%dg-topo-p g lin3))
          (is (member (bitcoin-lisp.mempool:compare-chunks
                       (%dg-chunks g lin3) (%dg-chunks g lin2))
                      '(:greater :equal)))
          (is-true (%cl-chunks-connected-p g lin3)))))))
