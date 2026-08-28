(in-package #:bitcoin-lisp.mempool)

;;;; Spanning-forest linearization (SFL)
;;;;
;;;; Port of Bitcoin Core's SpanningForestState and Linearize
;;;; (cluster_linearize.h:546-1836), the linearizer Core replaced its
;;;; ancestor-set + PostLinearize pair with. Everything here follows Core's
;;;; structure and naming so the two can be diffed; the algorithm's own
;;;; explanation lives in Core's comment at :546-717 and is not restated.
;;;;
;;;; The one-paragraph version: every dependency is either active or inactive;
;;;; the active ones always form a spanning forest, and the connected
;;;; components they induce are the chunks. Merging chunks activates a
;;;; dependency, splitting one deactivates it. The state is driven towards
;;;; "optimal" (no active dependency whose top set has strictly higher feerate
;;;; than its bottom) and then "minimal" (chunks split into their equal-feerate
;;;; parts), and the output is the chunks in decreasing feerate order, each
;;;; internally topologically sorted.
;;;;
;;;; Deviation from Core, in one place only: Core's InsecureRandomContext is a
;;;; xoshiro variant seeded per Linearize call. SFL uses randomness ONLY for
;;;; heuristics — which equal-feerate candidate to merge with, what order to
;;;; visit chunks in, how to break ties in the output — so the choice of
;;;; generator changes which of several equally-good linearizations comes out,
;;;; never whether the result is valid or how good it is. This uses SplitMix64,
;;;; which the wallet's coin selection already relies on for the same kind of
;;;; decision; it cannot live in a shared place without src/mempool/ depending
;;;; on src/rpc/.

;;;; --- RNG ---------------------------------------------------------------

(defconstant +sfl-u64-max+ (1- (ash 1 64)))

(defstruct (sfl-rng (:constructor make-sfl-rng (state)))
  "SplitMix64. See the deviation note above: heuristics only."
  (state 0 :type (unsigned-byte 64)))

(defun sfl-rand64 (rng)
  (let ((z (setf (sfl-rng-state rng)
                 (logand (+ (sfl-rng-state rng) #x9E3779B97F4A7C15) +sfl-u64-max+))))
    (setf z (logand (* (logxor z (ash z -30)) #xBF58476D1CE4E5B9) +sfl-u64-max+))
    (setf z (logand (* (logxor z (ash z -27)) #x94D049BB133111EB) +sfl-u64-max+))
    (logxor z (ash z -31))))

(defun sfl-randrange (rng n)
  "Uniform integer in [0, N). N >= 1."
  (declare (type (integer 1) n))
  (if (= n 1)
      0
      (let ((mask (1- (ash 1 (integer-length (1- n))))))
        (loop for v = (logand (sfl-rand64 rng) mask)
              when (< v n) return v))))

(defun sfl-randbool (rng)
  (= 1 (logand (sfl-rand64 rng) 1)))

;;;; --- A FIFO with indexed access ----------------------------------------
;;;;
;;;; Core uses VecDeque, and needs three things of it: push_back, pop_front,
;;;; and indexed access plus swap-with-back (which is how it shuffles the
;;;; initial queue order as it fills it).

(defstruct (sfl-queue (:constructor make-sfl-queue ()))
  (items (make-array 16 :adjustable t :fill-pointer 0) :type vector)
  (head 0 :type fixnum))

(declaim (inline sfl-queue-count sfl-queue-empty-p))
(defun sfl-queue-count (q) (- (fill-pointer (sfl-queue-items q)) (sfl-queue-head q)))
(defun sfl-queue-empty-p (q) (zerop (sfl-queue-count q)))

(defun sfl-queue-push (q x)
  (vector-push-extend x (sfl-queue-items q))
  q)

(defun sfl-queue-pop (q)
  (let ((items (sfl-queue-items q))
        (head (sfl-queue-head q)))
    (prog1 (aref items head)
      (setf (aref items head) nil)
      (incf (sfl-queue-head q))
      ;; Reclaim once the dead prefix dominates, so a long optimization run
      ;; does not grow the backing vector without bound.
      (when (and (> head 32) (> head (ash (sfl-queue-count q) 1)))
        (replace items items :start2 (sfl-queue-head q)
                             :end2 (fill-pointer items))
        (setf (fill-pointer items) (sfl-queue-count q)
              (sfl-queue-head q) 0)))))

(defun sfl-queue-shuffle-in-last (q rng)
  "Core's fill-time shuffle: after pushing, swap the new back element with a
uniformly random position among the live elements."
  (let* ((items (sfl-queue-items q))
         (n (sfl-queue-count q))
         (j (sfl-randrange rng n)))
    (unless (= j (1- n))
      (rotatef (aref items (+ (sfl-queue-head q) j))
               (aref items (1- (fill-pointer items)))))))

(defun sfl-queue-clear (q)
  (setf (fill-pointer (sfl-queue-items q)) 0
        (sfl-queue-head q) 0))

;;;; --- State -------------------------------------------------------------

(defconstant +sfl-invalid-idx+ -1
  "Core INVALID_SET_IDX.")

(defstruct (sfl-tx (:constructor %make-sfl-tx (dep-top-idx)))
  "Core SpanningForestState::TxData (cluster_linearize.h:735-748)."
  ;; Top set index for every ACTIVE child dependency, indexed by child TxIdx.
  ;; Only meaningful for indexes present in ACTIVE-CHILDREN.
  (dep-top-idx nil :type simple-vector)
  (parents 0 :type (unsigned-byte 64))
  (children 0 :type (unsigned-byte 64))
  (active-children 0 :type (unsigned-byte 64))
  (chunk-idx 0 :type fixnum))

(defstruct (sfl-state (:conc-name sfl-))
  "Core SpanningForestState (cluster_linearize.h:718+)."
  (depgraph nil)
  (rng nil :type (or null sfl-rng))
  ;; TxIdx -> sfl-tx, with DepGraph's holes preserved.
  (tx-data #() :type simple-vector)
  ;; SetIdx -> setinfo (a chunk, or an active dependency's top set).
  (set-info #() :type simple-vector)
  ;; SetIdx -> (upward . downward) out-of-chunk reachable transaction sets.
  (reach-up #() :type simple-vector)
  (reach-down #() :type simple-vector)
  (transaction-idxs 0 :type (unsigned-byte 64))
  (chunk-idxs 0 :type (unsigned-byte 64))
  (suboptimal-idxs 0 :type (unsigned-byte 64))
  (suboptimal-chunks nil :type (or null sfl-queue))
  (nonminimal-chunks nil :type (or null sfl-queue))
  (cost 0 :type (integer 0)))

(declaim (inline %sfl-tx %sfl-set %sfl-chunk-feerate))
(defun %sfl-tx (st i) (svref (sfl-tx-data st) i))
(defun %sfl-set (st i) (svref (sfl-set-info st) i))
(defun %sfl-chunk-feerate (st i) (setinfo-feerate (%sfl-set st i)))

(defun sfl-pick-random-tx (st tx-idxs)
  "Core PickRandomTx: a uniformly random member of a non-empty set."
  (let ((pos (sfl-randrange (sfl-rng st) (logcount tx-idxs))))
    (do-bits (tx tx-idxs)
      (when (zerop pos) (return-from sfl-pick-random-tx tx))
      (decf pos))
    (internal-error "PickRandomTx on an empty set")))

;;;; --- Cost model (Core SFLDefaultCostModel, cluster_linearize.h:496-544) --
;;;;
;;;; The coefficients are Core's, measured in February 2026 across machines and
;;;; rescaled so only their ratios matter; one cost unit is roughly 0.5-2.5 ns.
;;;; They are what makes max_cost a portable work budget rather than a
;;;; wall-clock guess, so they are copied exactly rather than re-derived.

(declaim (inline %cost))
(defun %cost (st n) (incf (sfl-cost st) n))

;;;; --- Activate / Deactivate ---------------------------------------------

(defun sfl-activate (st parent-idx child-idx)
  "Make the inactive dependency PARENT-IDX -> CHILD-IDX active, merging their
two chunks. Returns the merged chunk's SetIdx (Core Activate, :813-880)."
  (let* ((parent-data (%sfl-tx st parent-idx))
         (child-data (%sfl-tx st child-idx))
         (parent-chunk-idx (sfl-tx-chunk-idx parent-data))
         (child-chunk-idx (sfl-tx-chunk-idx child-data))
         (top-info (%sfl-set st parent-chunk-idx))
         (bottom-info (%sfl-set st child-chunk-idx)))
    ;; Every dependency whose top set contains the activated dependency's
    ;; PARENT gains the bottom chunk; every one whose top set contains its
    ;; CHILD gains the top chunk. Core's worked example is at :832-845.
    (do-bits (tx-idx (setinfo-transactions top-info))
      (let ((tx-data (%sfl-tx st tx-idx)))
        (setf (sfl-tx-chunk-idx tx-data) child-chunk-idx)
        (do-bits (dep-child (sfl-tx-active-children tx-data))
          (let ((dep-top (%sfl-set st (svref (sfl-tx-dep-top-idx tx-data) dep-child))))
            (when (logbitp parent-idx (setinfo-transactions dep-top))
              (setinfo-union! dep-top bottom-info))))))
    (do-bits (tx-idx (setinfo-transactions bottom-info))
      (let ((tx-data (%sfl-tx st tx-idx)))
        (do-bits (dep-child (sfl-tx-active-children tx-data))
          (let ((dep-top (%sfl-set st (svref (sfl-tx-dep-top-idx tx-data) dep-child))))
            (when (logbitp child-idx (setinfo-transactions dep-top))
              (setinfo-union! dep-top top-info))))))
    ;; The child chunk grows into the merged chunk.
    (setinfo-union! bottom-info top-info)
    (let ((merged (setinfo-transactions bottom-info)))
      (setf (svref (sfl-reach-up st) child-chunk-idx)
            (logandc2 (logior (svref (sfl-reach-up st) child-chunk-idx)
                              (svref (sfl-reach-up st) parent-chunk-idx))
                      merged)
            (svref (sfl-reach-down st) child-chunk-idx)
            (logandc2 (logior (svref (sfl-reach-down st) child-chunk-idx)
                              (svref (sfl-reach-down st) parent-chunk-idx))
                      merged))
      ;; The old parent chunk becomes the new dependency's top set.
      (setf (svref (sfl-tx-dep-top-idx parent-data) child-idx) parent-chunk-idx)
      (setf (sfl-tx-active-children parent-data)
            (logior (sfl-tx-active-children parent-data) (ash 1 child-idx)))
      (setf (sfl-chunk-idxs st)
            (logandc2 (sfl-chunk-idxs st) (ash 1 parent-chunk-idx)))
      (%cost st (+ (* 10 (1- (logcount merged))) 1))
      child-chunk-idx)))

(defun sfl-deactivate (st parent-idx child-idx)
  "Make an active dependency inactive, splitting its chunk. Returns
(values top-chunk-idx bottom-chunk-idx) (Core Deactivate, :884-940)."
  (let* ((parent-data (%sfl-tx st parent-idx))
         (parent-chunk-idx (svref (sfl-tx-dep-top-idx parent-data) child-idx))
         (child-chunk-idx (sfl-tx-chunk-idx parent-data))
         (top-info (%sfl-set st parent-chunk-idx))
         (bottom-info (%sfl-set st child-chunk-idx))
         (ntx (logcount (setinfo-transactions bottom-info))))
    (setf (sfl-tx-active-children parent-data)
          (logandc2 (sfl-tx-active-children parent-data) (ash 1 child-idx)))
    (setf (sfl-chunk-idxs st) (logior (sfl-chunk-idxs st) (ash 1 parent-chunk-idx)))
    (setinfo-subtract! bottom-info top-info)
    (let ((top-parents 0) (top-children 0)
          (bottom-parents 0) (bottom-children 0))
      (do-bits (tx-idx (setinfo-transactions top-info))
        (let ((tx-data (%sfl-tx st tx-idx)))
          (setf (sfl-tx-chunk-idx tx-data) parent-chunk-idx)
          (setf top-parents (logior top-parents (sfl-tx-parents tx-data))
                top-children (logior top-children (sfl-tx-children tx-data)))
          (do-bits (dep-child (sfl-tx-active-children tx-data))
            (let ((dep-top (%sfl-set st (svref (sfl-tx-dep-top-idx tx-data) dep-child))))
              (when (logbitp parent-idx (setinfo-transactions dep-top))
                (setinfo-subtract! dep-top bottom-info))))))
      (do-bits (tx-idx (setinfo-transactions bottom-info))
        (let ((tx-data (%sfl-tx st tx-idx)))
          (setf bottom-parents (logior bottom-parents (sfl-tx-parents tx-data))
                bottom-children (logior bottom-children (sfl-tx-children tx-data)))
          (do-bits (dep-child (sfl-tx-active-children tx-data))
            (let ((dep-top (%sfl-set st (svref (sfl-tx-dep-top-idx tx-data) dep-child))))
              (when (logbitp child-idx (setinfo-transactions dep-top))
                (setinfo-subtract! dep-top top-info))))))
      (setf (svref (sfl-reach-up st) parent-chunk-idx)
            (logandc2 top-parents (setinfo-transactions top-info))
            (svref (sfl-reach-down st) parent-chunk-idx)
            (logandc2 top-children (setinfo-transactions top-info))
            (svref (sfl-reach-up st) child-chunk-idx)
            (logandc2 bottom-parents (setinfo-transactions bottom-info))
            (svref (sfl-reach-down st) child-chunk-idx)
            (logandc2 bottom-children (setinfo-transactions bottom-info))))
    (%cost st (+ (* 11 (1- ntx)) 8))
    (values parent-chunk-idx child-chunk-idx)))

;;;; --- Merging ------------------------------------------------------------

(defun sfl-merge-chunks (st top-idx bottom-idx)
  "Activate a uniformly random dependency from the top chunk to the bottom
chunk, which must exist. Returns the merged chunk (Core MergeChunks, :943-982)."
  (let ((top-txs (setinfo-transactions (%sfl-set st top-idx)))
        (bottom-txs (setinfo-transactions (%sfl-set st bottom-idx)))
        (num-deps 0))
    (do-bits (tx-idx top-txs)
      (incf num-deps (logcount (logand (sfl-tx-children (%sfl-tx st tx-idx)) bottom-txs))))
    (%cost st (* 2 (logcount top-txs)))
    (assert (plusp num-deps) () "MergeChunks with no dependency between the chunks")
    (let ((pick (sfl-randrange (sfl-rng st) num-deps))
          (steps 0))
      (do-bits (tx-idx top-txs)
        (incf steps)
        (let* ((tx-data (%sfl-tx st tx-idx))
               (intersect (logand (sfl-tx-children tx-data) bottom-txs))
               (count (logcount intersect)))
          (cond ((< pick count)
                 (do-bits (child-idx intersect)
                   (when (zerop pick)
                     (%cost st (+ (* 3 steps) 5))
                     (return-from sfl-merge-chunks (sfl-activate st tx-idx child-idx)))
                   (decf pick)))
                (t (decf pick count)))))
      (internal-error "MergeChunks failed to find the picked dependency"))))

(defun sfl-pick-merge-candidate (st chunk-idx downward)
  "The chunk CHUNK-IDX should merge with, or +SFL-INVALID-IDX+ (Core
PickMergeCandidate, :1006-1043). Upward: the LOWEST-feerate chunk it depends on
among those at or below its own feerate. Downward: the HIGHEST-feerate chunk
depending on it among those at or above."
  (let* ((chunk-info (%sfl-set st chunk-idx))
         (best-feerate (setinfo-feerate chunk-info))
         (best-idx +sfl-invalid-idx+)
         (best-tiebreak 0)
         (todo (if downward
                   (svref (sfl-reach-down st) chunk-idx)
                   (svref (sfl-reach-up st) chunk-idx)))
         (steps 0))
    (loop until (zerop todo)
          do (incf steps)
             (let* ((reached-idx (sfl-tx-chunk-idx (%sfl-tx st (%lowest-bit todo))))
                    (reached-info (%sfl-set st reached-idx))
                    (cmp (if downward
                             (feerate-compare best-feerate (setinfo-feerate reached-info))
                             (feerate-compare (setinfo-feerate reached-info) best-feerate))))
               (setf todo (logandc2 todo (setinfo-transactions reached-info)))
               (unless (plusp cmp)
                 (let ((tiebreak (sfl-rand64 (sfl-rng st))))
                   (when (or (minusp cmp) (>= tiebreak best-tiebreak))
                     (setf best-feerate (setinfo-feerate reached-info)
                           best-idx reached-idx
                           best-tiebreak tiebreak))))))
    (%cost st (* 8 steps))
    best-idx))

(defun sfl-merge-step (st chunk-idx downward)
  "One merge attempt. Returns the merged chunk or +SFL-INVALID-IDX+."
  (let ((merge-idx (sfl-pick-merge-candidate st chunk-idx downward)))
    (if (= merge-idx +sfl-invalid-idx+)
        +sfl-invalid-idx+
        (if downward
            (sfl-merge-chunks st chunk-idx merge-idx)
            (sfl-merge-chunks st merge-idx chunk-idx)))))

(defun %sfl-mark-suboptimal (st chunk-idx)
  (unless (logbitp chunk-idx (sfl-suboptimal-idxs st))
    (setf (sfl-suboptimal-idxs st) (logior (sfl-suboptimal-idxs st) (ash 1 chunk-idx)))
    (sfl-queue-push (sfl-suboptimal-chunks st) chunk-idx)))

(defun sfl-merge-sequence (st chunk-idx downward)
  "Merge repeatedly in one direction until no candidate remains, then mark the
result improvable (Core MergeSequence, :1059-1073)."
  (loop for merged = (sfl-merge-step st chunk-idx downward)
        until (= merged +sfl-invalid-idx+)
        do (setf chunk-idx merged))
  (%sfl-mark-suboptimal st chunk-idx))

(defun sfl-improve (st parent-idx child-idx)
  "Split on a dependency, then merge back to topological (Core Improve,
:1076-1110)."
  (multiple-value-bind (parent-chunk-idx child-chunk-idx)
      (sfl-deactivate st parent-idx child-idx)
    (if (logtest (svref (sfl-reach-up st) parent-chunk-idx)
                 (setinfo-transactions (%sfl-set st child-chunk-idx)))
        ;; Self-merge: the new top depends on the new bottom through some other
        ;; dependency, so the two must rejoin and nothing else can change.
        ;; The roles reverse — the child chunk is now the top.
        (%sfl-mark-suboptimal st (sfl-merge-chunks st child-chunk-idx parent-chunk-idx))
        (progn
          (sfl-merge-sequence st parent-chunk-idx nil)
          (sfl-merge-sequence st child-chunk-idx t)))))

;;;; --- Optimization -------------------------------------------------------

(defun sfl-pick-chunk-to-optimize (st)
  "Core PickChunkToOptimize (:1113-1134). Entries that stopped being chunks
(because they merged into another) are skipped."
  (let ((steps 0))
    (loop until (sfl-queue-empty-p (sfl-suboptimal-chunks st))
          do (incf steps)
             (let ((chunk-idx (sfl-queue-pop (sfl-suboptimal-chunks st))))
               (setf (sfl-suboptimal-idxs st)
                     (logandc2 (sfl-suboptimal-idxs st) (ash 1 chunk-idx)))
               (when (logbitp chunk-idx (sfl-chunk-idxs st))
                 (%cost st (+ steps 4))
                 (return-from sfl-pick-chunk-to-optimize chunk-idx))))
    (%cost st (+ steps 4))
    +sfl-invalid-idx+))

(defun sfl-pick-dependency-to-split (st chunk-idx)
  "A uniformly random active dependency in the chunk whose top set has strictly
higher feerate than the chunk, or NIL (Core PickDependencyToSplit, :1137-1166)."
  (let* ((chunk-info (%sfl-set st chunk-idx))
         (chunk-feerate (setinfo-feerate chunk-info))
         (candidate nil)
         (candidate-tiebreak 0))
    (do-bits (tx-idx (setinfo-transactions chunk-info))
      (let ((tx-data (%sfl-tx st tx-idx)))
        (do-bits (child-idx (sfl-tx-active-children tx-data))
          (let ((dep-top (%sfl-set st (svref (sfl-tx-dep-top-idx tx-data) child-idx))))
            (when (plusp (feerate-compare (setinfo-feerate dep-top) chunk-feerate))
              (let ((tiebreak (sfl-rand64 (sfl-rng st))))
                (when (>= tiebreak candidate-tiebreak)
                  (setf candidate (cons tx-idx child-idx)
                        candidate-tiebreak tiebreak))))))))
    (%cost st (+ (* 8 (logcount (setinfo-transactions chunk-info))) 9))
    candidate))

;;;; --- Construction and the public steps ----------------------------------

(defun make-spanning-forest (depgraph rng-seed)
  "Every transaction in its own chunk; not yet topological (Core constructor,
:1171-1204)."
  (let* ((positions (depgraph-positions depgraph))
         (num-tx (logcount positions))
         (range (depgraph-position-range depgraph))
         (st (make-sfl-state
              :depgraph depgraph
              :rng (make-sfl-rng (logand rng-seed +sfl-u64-max+))
              :tx-data (make-array (max range 1) :initial-element nil)
              :set-info (make-array (max num-tx 1) :initial-element nil)
              :reach-up (make-array (max num-tx 1) :initial-element 0)
              :reach-down (make-array (max num-tx 1) :initial-element 0)
              :transaction-idxs positions
              :suboptimal-chunks (make-sfl-queue)
              :nonminimal-chunks (make-sfl-queue))))
    (do-bits (tx-idx positions)
      (setf (svref (sfl-tx-data st) tx-idx)
            (%make-sfl-tx (make-array (max range 1) :initial-element 0))))
    (let ((num-chunks 0) (num-deps 0))
      (do-bits (tx-idx positions)
        (let ((tx-data (%sfl-tx st tx-idx)))
          (setf (sfl-tx-parents tx-data) (depgraph-reduced-parents depgraph tx-idx))
          (do-bits (parent-idx (sfl-tx-parents tx-data))
            (let ((pd (%sfl-tx st parent-idx)))
              (setf (sfl-tx-children pd) (logior (sfl-tx-children pd) (ash 1 tx-idx)))))
          (incf num-deps (logcount (sfl-tx-parents tx-data)))
          (setf (sfl-tx-chunk-idx tx-data) num-chunks)
          (setf (svref (sfl-set-info st) num-chunks)
                (make-setinfo (ash 1 tx-idx)
                              (copy-feefrac (depgraph-tx-feerate depgraph tx-idx))))
          (incf num-chunks)))
      ;; Reachability of a singleton chunk is just its transaction's parents
      ;; and children. Done in a second pass because CHILDREN is only complete
      ;; once every transaction's parents have been walked.
      (dotimes (chunk-idx num-chunks)
        (let ((tx-data (%sfl-tx st (%lowest-bit
                                    (setinfo-transactions (%sfl-set st chunk-idx))))))
          (setf (svref (sfl-reach-up st) chunk-idx) (sfl-tx-parents tx-data)
                (svref (sfl-reach-down st) chunk-idx) (sfl-tx-children tx-data))))
      (setf (sfl-chunk-idxs st) (1- (ash 1 num-chunks)))
      (%cost st (+ (* 39 num-chunks) (* 48 num-chunks) (* 4 num-deps))))
    st))

(defun sfl-load-linearization (st linearization)
  "Seed the state from an existing linearization, so the state's own output is
immediately at least as good as it (Core LoadLinearization, :1208-1219). Only
upward merges are needed."
  (map nil (lambda (tx-idx)
             (let ((chunk-idx (sfl-tx-chunk-idx (%sfl-tx st tx-idx))))
               (loop for merged = (sfl-merge-step st chunk-idx nil)
                     until (= merged +sfl-invalid-idx+)
                     do (setf chunk-idx merged))))
       linearization)
  st)

(defun %sfl-fill-queue-shuffled (st)
  "Push every chunk onto the suboptimal queue in a uniformly random order."
  (setf (sfl-suboptimal-idxs st) (sfl-chunk-idxs st))
  (do-bits (chunk-idx (sfl-chunk-idxs st))
    (sfl-queue-push (sfl-suboptimal-chunks st) chunk-idx)
    (sfl-queue-shuffle-in-last (sfl-suboptimal-chunks st) (sfl-rng st))))

(defun sfl-make-topological (st)
  "Merge until no inactive dependency runs from a chunk to an equal-or-higher
feerate chunk (Core MakeTopological, :1222-1288)."
  (let ((init-dir (if (sfl-randbool (sfl-rng st)) 1 0))
        (merged-chunks 0)
        (chunks (logcount (sfl-chunk-idxs st)))
        (steps 0))
    (%sfl-fill-queue-shuffled st)
    (loop until (sfl-queue-empty-p (sfl-suboptimal-chunks st))
          do (incf steps)
             (let ((chunk-idx (sfl-queue-pop (sfl-suboptimal-chunks st))))
               (setf (sfl-suboptimal-idxs st)
                     (logandc2 (sfl-suboptimal-idxs st) (ash 1 chunk-idx)))
               (when (logbitp chunk-idx (sfl-chunk-idxs st))
                 ;; 1 = up, 2 = down, 3 = both. A chunk that is itself the
                 ;; result of a merge is tried both ways; a fresh one only
                 ;; needs one direction, since any non-topological inactive
                 ;; dependency is found from one of its two ends.
                 (let ((direction (if (logbitp chunk-idx merged-chunks) 3 (1+ init-dir)))
                       (flip (if (sfl-randbool (sfl-rng st)) 1 0)))
                   (dotimes (i 2)
                     (let* ((downward (zerop (logxor i flip)))
                            (bit (if downward 2 1)))
                       (when (logtest direction bit)
                         (let ((result (sfl-merge-step st chunk-idx downward)))
                           (unless (= result +sfl-invalid-idx+)
                             (%sfl-mark-suboptimal st result)
                             (setf merged-chunks (logior merged-chunks (ash 1 result)))
                             (return))))))))))
    (%cost st (+ (* 20 chunks) (* 28 steps))))
  st)

(defun sfl-start-optimizing (st)
  "Core StartOptimizing (:1291-1305)."
  (%sfl-fill-queue-shuffled st)
  (%cost st (* 13 (sfl-queue-count (sfl-suboptimal-chunks st))))
  st)

(defun sfl-optimize-step (st)
  "One improvement step. NIL once the state is optimal (Core OptimizeStep,
:1308-1323)."
  (let ((chunk-idx (sfl-pick-chunk-to-optimize st)))
    (cond ((= chunk-idx +sfl-invalid-idx+) nil)
          (t (let ((dep (sfl-pick-dependency-to-split st chunk-idx)))
               (cond ((null dep)
                      ;; Nothing to improve here; carry on with other chunks.
                      (not (sfl-queue-empty-p (sfl-suboptimal-chunks st))))
                     (t (sfl-improve st (car dep) (cdr dep))
                        t)))))))

(defun sfl-start-minimizing (st)
  "Core StartMinimizing (:1327-1345). Only valid once the state is optimal."
  (sfl-queue-clear (sfl-nonminimal-chunks st))
  (do-bits (chunk-idx (sfl-chunk-idxs st))
    (let ((pivot (sfl-pick-random-tx st (setinfo-transactions (%sfl-set st chunk-idx)))))
      (sfl-queue-push (sfl-nonminimal-chunks st)
                      (list chunk-idx pivot (if (sfl-randbool (sfl-rng st)) 1 0)))
      (sfl-queue-shuffle-in-last (sfl-nonminimal-chunks st) (sfl-rng st))))
  (%cost st (* 18 (sfl-queue-count (sfl-nonminimal-chunks st))))
  st)

(defun sfl-minimize-step (st)
  "Split one chunk into equal-feerate parts if possible. NIL once every chunk is
minimal (Core MinimizeStep, :1348-1442)."
  (if (sfl-queue-empty-p (sfl-nonminimal-chunks st))
      nil
      (destructuring-bind (chunk-idx pivot-idx flags)
          (sfl-queue-pop (sfl-nonminimal-chunks st))
        (let* ((chunk-info (%sfl-set st chunk-idx))
               (chunk-feerate (setinfo-feerate chunk-info))
               (move-pivot-down (logbitp 0 flags))
               (second-stage (logbitp 1 flags))
               (candidate nil)
               (candidate-tiebreak 0)
               (have-any nil))
          ;; Look for an active dependency whose top and bottom feerates are
          ;; EQUAL — the top can never be higher here, OptimizeStep removed
          ;; those — with the pivot on the required side.
          (do-bits (tx-idx (setinfo-transactions chunk-info))
            (let ((tx-data (%sfl-tx st tx-idx)))
              (do-bits (child-idx (sfl-tx-active-children tx-data))
                (let ((dep-top (%sfl-set st (svref (sfl-tx-dep-top-idx tx-data) child-idx))))
                  (unless (feefrac<< (setinfo-feerate dep-top) chunk-feerate)
                    (setf have-any t)
                    (unless (eq move-pivot-down
                                (logbitp pivot-idx (setinfo-transactions dep-top)))
                      (let ((tiebreak (logior (sfl-rand64 (sfl-rng st)) 1)))
                        (when (> tiebreak candidate-tiebreak)
                          (setf candidate-tiebreak tiebreak
                                candidate (cons tx-idx child-idx))))))))))
          (%cost st (+ (* 11 (logcount (setinfo-transactions chunk-info))) 11))
          (cond
            ;; No equal-feerate dependency at all: this chunk is minimal.
            ((not have-any) t)
            ;; Some exist but all have the pivot on the wrong side: flip the
            ;; direction once, then give up on this pivot.
            ((null candidate)
             (let ((new-flags (logxor flags 3)))
               (unless second-stage
                 (sfl-queue-push (sfl-nonminimal-chunks st)
                                 (list chunk-idx pivot-idx new-flags)))
               t))
            (t
             (multiple-value-bind (parent-chunk-idx child-chunk-idx)
                 (sfl-deactivate st (car candidate) (cdr candidate))
               (cond
                 ((logtest (svref (sfl-reach-up st) parent-chunk-idx)
                           (setinfo-transactions (%sfl-set st child-chunk-idx)))
                  ;; A self-merge: no split was possible on this dependency.
                  (let ((merged (sfl-merge-chunks st child-chunk-idx parent-chunk-idx)))
                    (sfl-queue-push (sfl-nonminimal-chunks st)
                                    (list merged pivot-idx flags))
                    (%cost st 7)))
                 (t
                  ;; A real split. The part holding the pivot keeps it and its
                  ;; direction (and its second-stage flag, since we already
                  ;; know no split exists with the pivot on the other side);
                  ;; the other part gets a fresh random pivot.
                  (if move-pivot-down
                      (let ((parent-pivot (sfl-pick-random-tx
                                           st (setinfo-transactions
                                               (%sfl-set st parent-chunk-idx)))))
                        (sfl-queue-push (sfl-nonminimal-chunks st)
                                        (list parent-chunk-idx parent-pivot
                                              (if (sfl-randbool (sfl-rng st)) 1 0)))
                        (sfl-queue-push (sfl-nonminimal-chunks st)
                                        (list child-chunk-idx pivot-idx flags)))
                      (let ((child-pivot (sfl-pick-random-tx
                                          st (setinfo-transactions
                                              (%sfl-set st child-chunk-idx)))))
                        (sfl-queue-push (sfl-nonminimal-chunks st)
                                        (list parent-chunk-idx pivot-idx flags))
                        (sfl-queue-push (sfl-nonminimal-chunks st)
                                        (list child-chunk-idx child-pivot
                                              (if (sfl-randbool (sfl-rng st)) 1 0)))))
                  (when (sfl-randbool (sfl-rng st))
                    (let* ((items (sfl-queue-items (sfl-nonminimal-chunks st)))
                           (n (fill-pointer items)))
                      (rotatef (aref items (1- n)) (aref items (- n 2)))))
                  (%cost st 24))))
             t))))))

;;;; --- Output -------------------------------------------------------------

(defun %sfl-tx-order< (st a b fallback)
  "Core's tx heap comparator, as a strict less-than for sorting: higher feerate
first, then smaller size, then lower FALLBACK order (:1503-1520)."
  (let* ((g (sfl-depgraph st))
         (fa (depgraph-tx-feerate g a))
         (fb (depgraph-tx-feerate g b))
         (cmp (feerate-compare fa fb)))
    (cond ((/= cmp 0) (plusp cmp))
          ((/= (feefrac-size fa) (feefrac-size fb))
           (< (feefrac-size fa) (feefrac-size fb)))
          (t (minusp (funcall fallback a b))))))

(defun %sfl-chunk-order< (st a b fallback)
  "Core's chunk heap comparator (:1525-1542). A and B are (idx . max-fallback)."
  (let* ((fa (%sfl-chunk-feerate st (car a)))
         (fb (%sfl-chunk-feerate st (car b)))
         (cmp (feerate-compare fa fb)))
    (cond ((/= cmp 0) (plusp cmp))
          ((/= (feefrac-size fa) (feefrac-size fb))
           (< (feefrac-size fa) (feefrac-size fb)))
          (t (minusp (funcall fallback (cdr a) (cdr b)))))))

(defun %sfl-pop-best (list less-p)
  "Remove and return the best element of LIST under LESS-P, returning
(values best rest). A linear scan stands in for Core's binary heap: clusters are
capped at 64 transactions, so the heap's advantage never materialises."
  (let ((best (first list)))
    (dolist (x (rest list))
      (when (funcall less-p x best) (setf best x)))
    (values best (remove best list :test #'eq :count 1))))

(defun sfl-get-linearization (st &optional (fallback #'%sfl-default-fallback))
  "The linearization implied by the current state, which must be topological
(Core GetLinearization, :1461-1600): chunks in decreasing feerate order, each
internally topologically sorted, ties broken as Core documents at :1444-1459."
  (let* ((range (length (sfl-tx-data st)))
         (nsets (length (sfl-set-info st)))
         (chunk-deps (make-array nsets :initial-element 0))
         (tx-deps (make-array range :initial-element 0))
         (result '()))
    (do-bits (chl-idx (sfl-transaction-idxs st))
      (let* ((chl-data (%sfl-tx st chl-idx))
             (chunk-idx (sfl-tx-chunk-idx chl-data)))
        (setf (aref tx-deps chl-idx) (logcount (sfl-tx-parents chl-data)))
        (incf (aref chunk-deps chunk-idx)
              (logcount (logandc2 (sfl-tx-parents chl-data)
                                  (setinfo-transactions (%sfl-set st chunk-idx)))))))
    (flet ((max-fallback (chunk-idx)
             (let ((best nil))
               (do-bits (tx (setinfo-transactions (%sfl-set st chunk-idx)))
                 (when (or (null best) (plusp (funcall fallback tx best)))
                   (setf best tx)))
               best)))
      (let ((ready-chunks '()))
        (do-bits (chunk-idx (sfl-chunk-idxs st))
          (when (zerop (aref chunk-deps chunk-idx))
            (push (cons chunk-idx (max-fallback chunk-idx)) ready-chunks)))
        (loop until (null ready-chunks)
              do (multiple-value-bind (best rest)
                     (%sfl-pop-best ready-chunks
                                    (lambda (a b) (%sfl-chunk-order< st a b fallback)))
                   (setf ready-chunks rest)
                   (let* ((chunk-idx (car best))
                          (chunk-txs (setinfo-transactions (%sfl-set st chunk-idx)))
                          (ready-tx '()))
                     (do-bits (tx-idx chunk-txs)
                       (when (zerop (aref tx-deps tx-idx)) (push tx-idx ready-tx)))
                     (loop until (null ready-tx)
                           do (multiple-value-bind (tx-idx tx-rest)
                                  (%sfl-pop-best ready-tx
                                                 (lambda (a b) (%sfl-tx-order< st a b fallback)))
                                (setf ready-tx tx-rest)
                                (push tx-idx result)
                                (do-bits (chl-idx (sfl-tx-children (%sfl-tx st tx-idx)))
                                  (let ((chl-data (%sfl-tx st chl-idx)))
                                    (when (and (zerop (decf (aref tx-deps chl-idx)))
                                               (logbitp chl-idx chunk-txs))
                                      (push chl-idx ready-tx))
                                    (unless (= (sfl-tx-chunk-idx chl-data) chunk-idx)
                                      (when (zerop (decf (aref chunk-deps
                                                               (sfl-tx-chunk-idx chl-data))))
                                        (push (cons (sfl-tx-chunk-idx chl-data)
                                                    (max-fallback (sfl-tx-chunk-idx chl-data)))
                                              ready-chunks)))))))))))
      (coerce (nreverse result) 'simple-vector))))

(defun %sfl-default-fallback (a b)
  "Core IndexTxOrder (:473): compare by position."
  (cond ((< a b) -1) ((> a b) 1) (t 0)))

(defun sfl-diagram (st)
  "The feerate diagram of the current state: every chunk's feerate, high to low
(Core GetDiagram, :1616-1624). Test-only, as in Core."
  (let ((chunks '()))
    (do-bits (chunk-idx (sfl-chunk-idxs st))
      (push (copy-feefrac (%sfl-chunk-feerate st chunk-idx)) chunks))
    (sort chunks (lambda (a b) (plusp (feefrac-compare a b))))))

;;;; --- The entry point ----------------------------------------------------

(defun sfl-linearize (depgraph &key (max-cost most-positive-fixnum) (rng-seed 0)
                                    (fallback #'%sfl-default-fallback)
                                    old-linearization (topological t))
  "Core Linearize (cluster_linearize.h:1799-1836). Returns
(values linearization optimal-p cost).

The result is guaranteed to be at least as good as OLD-LINEARIZATION in the
feerate-diagram sense, and OPTIMAL-P says whether it is known to be optimal
with minimal chunks. MAX-COST bounds the work in the units of Core's cost
model, so the same budget means the same amount of work on any machine."
  (let ((st (make-spanning-forest depgraph rng-seed)))
    (cond ((and old-linearization (plusp (length old-linearization)))
           (sfl-load-linearization st old-linearization)
           (unless topological (sfl-make-topological st)))
          (t (sfl-make-topological st)))
    (when (< (sfl-cost st) max-cost)
      (sfl-start-optimizing st)
      (loop while (sfl-optimize-step st)
            until (>= (sfl-cost st) max-cost)))
    (let ((optimal nil))
      (when (< (sfl-cost st) max-cost)
        (sfl-start-minimizing st)
        (loop (unless (sfl-minimize-step st) (setf optimal t) (return))
              (when (>= (sfl-cost st) max-cost) (return))))
      (values (sfl-get-linearization st fallback) optimal (sfl-cost st)))))

;;;; --- The cluster linearizer used by the rest of the node -----------------

(defvar *linearize-rng-seed* nil
  "When non-NIL, every LINEARIZE call uses this seed instead of drawing one.
For tests that need a reproducible linearization; production must leave it NIL,
see the anti-grinding note in LINEARIZE.")

(defvar %linearize-rng
  (make-sfl-rng (let ((bytes (ironclad:random-data 8)))
                  (loop with acc = 0
                        for b across bytes
                        do (setf acc (logior (ash acc 8) b))
                        finally (return acc))))
  "Process-wide seed source for LINEARIZE, standing in for Core's per-TxGraph
m_rng (txgraph.cpp:2164).")

(defun linearize (g &key old-linearization fallback (max-cost most-positive-fixnum))
  "Linearize cluster G. Returns a simple-vector of positions in a topologically
valid order.

Core's Cluster::Relinearize (txgraph.cpp:2157-2196) in the two steps it takes:
SFL, then PostLinearize over its output. The second is not redundant — Core's
own comment is that it improves the linearization (when SFL stopped short of
optimal) and, whether or not it did, \"guarantees that all chunks are
connected\".

The seed is drawn fresh per call rather than fixed. Core does the same and says
why: a predictable seed lets a peer work out which clusters are expensive for
this node to linearize and feed it exactly those.

OLD-LINEARIZATION is Core's incremental-work path: seeding from the cluster's
previous order makes the result at least as good as it was, which matters when
a work budget can stop the search early. Our caller does not pass one, because
without Core's DoWork budget every call runs to optimality anyway — so seeding
could only save time we are not short of, while a stale order (one that no
longer matches the cluster's positions) would be a correctness hazard. The
parameter exists, and is tested, for when that budget is ported."
  (let ((seed (or *linearize-rng-seed* (sfl-rand64 %linearize-rng))))
    (post-linearize
     g
     (sfl-linearize g :max-cost max-cost
                      :rng-seed seed
                      :fallback (or fallback #'%sfl-default-fallback)
                      :old-linearization old-linearization
                      :topological (and old-linearization
                                        (linearization-topological-p
                                         g old-linearization))))))
