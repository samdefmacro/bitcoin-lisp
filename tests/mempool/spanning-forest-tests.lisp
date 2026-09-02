(in-package #:bitcoin-lisp.tests)

(def-suite :spanning-forest-tests
  :description "Core's spanning-forest linearization (SFL)"
  :in :bitcoin-lisp-tests)

(in-suite :spanning-forest-tests)

(defun %sf-graph (feerates &optional deps)
  "A depgraph with one transaction per (fee . size) in FEERATES, plus DEPS as
a list of (parent-index . child-index)."
  (let ((g (bl.mp:make-depgraph)))
    (dolist (fr feerates)
      (bl.mp:depgraph-add-transaction
       g (bl.mp:make-feefrac (car fr) (cdr fr))))
    (dolist (d deps)
      (bl.mp:depgraph-add-dependencies g (ash 1 (car d)) (cdr d)))
    g))

(defun %sf-chunks (g lin)
  (bl.mp:chunk-linearization g lin))

(defun %sf-incumbent (g)
  "The linearizer SFL replaced: ancestor-set feerate seeding refined by
PostLinearize. Built explicitly because LINEARIZE is now SFL — comparing
against LINEARIZE would compare the port with itself."
  (bl.mp:post-linearize
   g (bl.mp:ancestor-sort-linearization g)))

(defstruct (%sf-rng (:constructor %make-sf-rng (state)))
  (state 1 :type (unsigned-byte 62)))

(defun %sf-rnd (rng n)
  "Deterministic small PRNG for the fuzz cases, so a failure is reproducible."
  (setf (%sf-rng-state rng)
        (mod (+ (* (%sf-rng-state rng) 6364136223846793005) 1442695040888963407)
             (expt 2 62)))
  (mod (ash (%sf-rng-state rng) -20) n))

(defun %sf-random-graph (rng max-n)
  "A random DAG: dependencies only ever run from a lower index to a higher one,
so it is acyclic by construction."
  (let* ((n (1+ (%sf-rnd rng max-n)))
         (g (bl.mp:make-depgraph)))
    (dotimes (i n)
      (bl.mp:depgraph-add-transaction
       g (bl.mp:make-feefrac (1+ (%sf-rnd rng 100)) (1+ (%sf-rnd rng 5)))))
    (dotimes (i n)
      (loop for j from (1+ i) below n
            do (when (zerop (%sf-rnd rng 3))
                 (bl.mp:depgraph-add-dependencies g (ash 1 i) j))))
    (values g n)))

;;; --- Basics -----------------------------------------------------------------

(test sfl-orders-independent-transactions-by-feerate
  "With no dependencies every transaction is its own chunk, so the answer is
simply decreasing feerate."
  (let ((g (%sf-graph '((10 . 1) (30 . 1) (20 . 1)))))
    (multiple-value-bind (lin optimal) (bl.mp::sfl-linearize g :rng-seed 42)
      (is (equalp #(1 2 0) lin))
      (is-true optimal))))

(test sfl-respects-dependencies
  "A high-feerate child cannot come before its low-feerate parent."
  ;; tx0 pays 1/1, tx1 pays 100/1 and depends on tx0.
  (let ((g (%sf-graph '((1 . 1) (100 . 1)) '((0 . 1)))))
    (multiple-value-bind (lin optimal) (bl.mp::sfl-linearize g :rng-seed 1)
      (is (equalp #(0 1) lin))
      (is-true optimal)
      ;; They chunk together: the pair's feerate beats tx0 alone.
      (is (= 1 (length (%sf-chunks g lin)))))))

(test sfl-handles-the-empty-and-singleton-cases
  (let ((g (%sf-graph '())))
    (is (equalp #() (bl.mp::sfl-linearize g :rng-seed 3))))
  (let ((g (%sf-graph '((5 . 2)))))
    (multiple-value-bind (lin optimal) (bl.mp::sfl-linearize g :rng-seed 3)
      (is (equalp #(0) lin))
      (is-true optimal))))

(test sfl-handles-a-diamond-at-least-as-well-as-the-incumbent
  "A diamond D->{B,C}->A, the shape whose non-tree structure PostLinearize has
no optimality guarantee for. Both linearizers in fact solve it; the assertion is
the one that matters either way -- SFL is never worse."
  (let* ((g (%sf-graph '((1 . 1) (9 . 1) (2 . 1) (9 . 1))
                       '((0 . 1) (0 . 2) (1 . 3) (2 . 3)))))
    (multiple-value-bind (lin optimal) (bl.mp::sfl-linearize g :rng-seed 5)
      (is-true optimal)
      (is-true (bl.mp:linearization-topological-p g lin))
      (let ((cmp (bl.mp:compare-chunks
                  (%sf-chunks g lin)
                  (%sf-chunks g (%sf-incumbent g)))))
        (is (member cmp '(:greater :equal))
            "SFL must never be worse than the ancestor-set linearizer")))))

;;; --- Properties over random clusters ----------------------------------------

(test sfl-output-is-always-a-valid-topological-linearization
  "Every position exactly once, parents before children, over 400 random DAGs."
  (let ((rng (%make-sf-rng 20260820))
        (bad-count 0)
        (bad-topo 0))
    (dotimes (trial 400)
      (multiple-value-bind (g n) (%sf-random-graph rng 10)
        (let ((lin (bl.mp::sfl-linearize g :rng-seed (1+ trial))))
          (unless (and (= n (length lin))
                       (= n (length (remove-duplicates (coerce lin 'list)))))
            (incf bad-count))
          (unless (bl.mp:linearization-topological-p g lin)
            (incf bad-topo)))))
    (is (zerop bad-count) "every transaction must appear exactly once")
    (is (zerop bad-topo) "every output must be topologically valid")))

(defun %sf-random-graph-sized (rng min-n max-n density)
  "A random DAG with between MIN-N and MAX-N transactions, where each ordered
pair is joined with probability DENSITY/100."
  (let* ((n (+ min-n (%sf-rnd rng (1+ (- max-n min-n)))))
         (g (bl.mp:make-depgraph)))
    (dotimes (i n)
      (bl.mp:depgraph-add-transaction
       g (bl.mp:make-feefrac (1+ (%sf-rnd rng 50)) (1+ (%sf-rnd rng 10)))))
    (dotimes (i n)
      (loop for j from (1+ i) below n
            do (when (< (%sf-rnd rng 100) density)
                 (bl.mp:depgraph-add-dependencies g (ash 1 i) j))))
    (values g n)))

(test sfl-is-never-worse-than-the-ancestor-set-linearizer
  "The guarantee that lets it replace the incumbent, measured where the
difference actually shows.

On clusters of up to about 7 transactions the incumbent (ancestor-set seeding
plus PostLinearize) is ALREADY optimal -- verified here by exhaustive search
over every topological order, at three densities, with zero suboptimal results
from either linearizer. Small random clusters therefore cannot distinguish the
two, and a comparison run only on them would report a successful port that
changed nothing.

At 40-64 transactions -- Core's cluster limit, and the size where linearization
quality is worth paying for -- SFL is strictly better on a few percent of
random clusters and never worse. That is the shape of the improvement Core
bought with the algorithm, and it is what this asserts."
  (let ((rng (%make-sf-rng 20260821))
        (worse 0) (better 0) (unordered 0))
    (dotimes (trial 200)
      (multiple-value-bind (g n) (%sf-random-graph-sized rng 40 64 15)
        (declare (ignore n))
        (case (bl.mp:compare-chunks
               (%sf-chunks g (bl.mp::sfl-linearize g :rng-seed (1+ trial)))
               (%sf-chunks g (%sf-incumbent g)))
          (:less (incf worse))
          (:greater (incf better))
          (:unordered (incf unordered)))))
    (is (zerop worse) "SFL must never produce a worse diagram")
    (is (zerop unordered) "an incomparable diagram would also be a regression")
    (is (plusp better)
        "SFL must beat the incumbent on at least some 40-64 transaction
         clusters; if it never does, the port is a no-op and the measurement
         above is what would have hidden it")))

(test both-linearizers-are-optimal-on-small-clusters
  "The other half of the measurement above, and the reason it has to run at
40-64 transactions: on clusters small enough to check exhaustively, BOTH
linearizers already find the optimum, at every density tried. Stated as a test
so the claim stays true rather than remaining a note in a commit message."
  (let ((rng (%make-sf-rng 777))
        (old-suboptimal 0) (sfl-suboptimal 0) (checked 0))
    (dolist (density '(20 60 85))
      (dotimes (trial 60)
        (multiple-value-bind (g n) (%sf-random-graph-sized rng 2 7 density)
          (incf checked)
          (let ((cs (%sf-chunks g (bl.mp::sfl-linearize g :rng-seed (1+ trial))))
                (co (%sf-chunks g (%sf-incumbent g)))
                (all (%sf-all-topological-orders g n)))
            (when (some (lambda (c) (eq :greater (bl.mp:compare-chunks
                                                  (%sf-chunks g c) co)))
                        all)
              (incf old-suboptimal))
            (when (some (lambda (c) (eq :greater (bl.mp:compare-chunks
                                                  (%sf-chunks g c) cs)))
                        all)
              (incf sfl-suboptimal))))))
    (is (= 180 checked))
    (is (zerop sfl-suboptimal) "SFL must be optimal wherever we can check it exhaustively")
    (is (zerop old-suboptimal)
        "the incumbent is optimal on small clusters too -- which is exactly why
         the comparison test has to use large ones")))

(test sfl-seeded-from-a-linearization-is-never-worse-than-it
  "LoadLinearization's contract (Core: the result is guaranteed at least as good
as old_linearization). Seed with a deliberately bad order -- reverse topological
by index -- and require the result beat or match it."
  (let ((rng (%make-sf-rng 555))
        (worse 0))
    (dotimes (trial 200)
      (multiple-value-bind (g n) (%sf-random-graph rng 8)
        ;; Index order is topological here by construction, and it is a poor
        ;; linearization because it ignores feerate entirely.
        (let* ((seed-lin (coerce (loop for i below n collect i) 'simple-vector))
               (lin (bl.mp::sfl-linearize
                     g :rng-seed (1+ trial) :old-linearization seed-lin)))
          (is-true (bl.mp:linearization-topological-p g lin))
          (when (eq :less (bl.mp:compare-chunks
                           (%sf-chunks g lin) (%sf-chunks g seed-lin)))
            (incf worse)))))
    (is (zerop worse))))

(test sfl-optimal-flag-agrees-with-exhaustive-search
  "The claim OPTIMAL-P makes is checkable directly on small clusters: enumerate
every topologically valid order and confirm none has a better diagram."
  (let ((rng (%make-sf-rng 4242))
        (checked 0)
        (violations 0))
    (dotimes (trial 60)
      (multiple-value-bind (g n) (%sf-random-graph rng 6)
        (multiple-value-bind (lin optimal) (bl.mp::sfl-linearize
                                            g :rng-seed (1+ trial))
          (when optimal
            (incf checked)
            (let ((best (%sf-chunks g lin)))
              (dolist (cand (%sf-all-topological-orders g n))
                (when (eq :less (bl.mp:compare-chunks
                                 best (%sf-chunks g cand)))
                  (incf violations))))))))
    (is (plusp checked) "the fuzz must actually produce optimal results to check")
    (is (zerop violations)
        "a linearization reported optimal was beaten by an exhaustive search")))

(defun %sf-all-topological-orders (g n)
  "Every topologically valid ordering of G's positions. Exponential, so only for
the tiny clusters the optimality test uses."
  (let ((results '()))
    (labels ((walk (chosen-set chosen-list)
               (if (= (logcount chosen-set) n)
                   (push (coerce (reverse chosen-list) 'simple-vector) results)
                   (dotimes (i n)
                     (unless (logbitp i chosen-set)
                       (let ((parents (logandc2 (bl.mp:depgraph-ancestors g i)
                                                (ash 1 i))))
                         (when (= parents (logand parents chosen-set))
                           (walk (logior chosen-set (ash 1 i))
                                 (cons i chosen-list)))))))))
      (walk 0 '()))
    results))

;;; --- Work budget ------------------------------------------------------------

(test sfl-respects-its-cost-budget
  "MAX-COST bounds the work, and a starved run still returns a valid
linearization -- just not a provably optimal one."
  (let ((g (%sf-graph (loop for i below 20 collect (cons (1+ (* 7 (mod i 13))) (1+ (mod i 3))))
                      (loop for i below 19 collect (cons i (1+ i))))))
    (multiple-value-bind (lin optimal cost) (bl.mp::sfl-linearize
                                             g :rng-seed 9 :max-cost 1)
      (is (= 20 (length lin)))
      (is-true (bl.mp:linearization-topological-p g lin))
      (is-false optimal "no budget means no optimality claim")
      (is (plusp cost)))
    ;; With a real budget the same cluster is solved and reported optimal.
    (multiple-value-bind (lin optimal) (bl.mp::sfl-linearize g :rng-seed 9)
      (is-true optimal)
      (is-true (bl.mp:linearization-topological-p g lin)))))

(test sfl-is-deterministic-for-a-given-seed
  "Same graph, same seed, same answer -- the randomness is a heuristic, not a
source of run-to-run variation."
  (let ((rng (%make-sf-rng 31337)))
    (dotimes (trial 30)
      (multiple-value-bind (g n) (%sf-random-graph rng 8)
        (declare (ignore n))
        (is (equalp (bl.mp::sfl-linearize g :rng-seed 77)
                    (bl.mp::sfl-linearize g :rng-seed 77)))))))

;;; --- The seam ---------------------------------------------------------------

(test the-node-linearizer-is-the-spanning-forest-one
  "A correct algorithm nothing calls is the failure mode this project keeps
finding, so assert the swap-in itself: on a cluster where SFL and the incumbent
disagree, LINEARIZE — the function the mempool's txgraph actually calls — must
produce SFL's answer and not the incumbent's."
  (let ((rng (%make-sf-rng 20260821))
        (found nil))
    ;; Search for a cluster the two linearizers disagree on. The measurement in
    ;; the comparison test above says a few percent of 40-64 transaction
    ;; clusters qualify, so this terminates quickly.
    (dotimes (trial 200)
      (unless found
        (multiple-value-bind (g n) (%sf-random-graph-sized rng 40 64 15)
          (declare (ignore n))
          (let ((sfl (%sf-chunks g (bl.mp::sfl-linearize g :rng-seed (1+ trial))))
                (inc (%sf-chunks g (%sf-incumbent g))))
            (when (eq :greater (bl.mp:compare-chunks sfl inc))
              (setf found (list g (1+ trial))))))))
    (is-true found "no disagreeing cluster found; the comparison below is vacuous")
    (when found
      (destructuring-bind (g seed) found
        (let* ((bl.mp::*linearize-rng-seed* seed)
               (via-linearize (%sf-chunks g (bl.mp:linearize g)))
               (incumbent (%sf-chunks g (%sf-incumbent g))))
          (is (eq :greater (bl.mp:compare-chunks via-linearize incumbent))
              "LINEARIZE must give SFL's better answer, not the incumbent's"))))))

(test linearize-still-runs-post-linearize-over-the-sfl-output
  "Core does not replace PostLinearize with SFL, it runs both
(txgraph.cpp:2170-2179): PostLinearize improves a non-optimal result and, in
either case, guarantees every chunk is connected. Starve SFL of budget so its
output is not optimal, and require LINEARIZE's chunks to be connected anyway."
  (let ((g (%sf-graph (loop for i below 24 collect (cons (1+ (* 11 (mod i 7))) (1+ (mod i 4))))
                      (loop for i below 23 collect (cons i (1+ i))))))
    (let ((bl.mp::*linearize-rng-seed* 4))
      (let ((lin (bl.mp:linearize g :max-cost 1)))
        (is (= 24 (length lin)))
        (is-true (bl.mp:linearization-topological-p g lin))
        (dolist (si (bl.mp:chunk-linearization-info g lin))
          (is-true (bl.mp:depgraph-connected-p
                    g (bl.mp:setinfo-transactions si))
                   "every chunk PostLinearize produces must be connected"))))))
