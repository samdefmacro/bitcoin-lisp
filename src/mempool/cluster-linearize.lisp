(in-package #:bitcoin-lisp.mempool)

;;; Cluster linearization foundations
;;;
;;; Port of the pure-algorithm layer of Bitcoin Core cluster_linearize.h for
;;; clusters of up to 64 transactions: DepGraph (per-tx feerate + transitive
;;; ancestor/descendant closures), chunking, a first-cut ancestor-set-feerate
;;; linearizer, and the PostLinearize improvement sweep. Core's SFL optimal
;;; linearizer (SpanningForestState, cluster_linearize.h:718+) is a later
;;; drop-in quality upgrade behind the same interface.
;;;
;;; Transaction sets are plain non-negative integers used as 64-bit masks
;;; (Core's SetType = BitSet<64>); bit i set = position i in the set. SBCL
;;; fixnums are 62 bits so masks touching bits 62/63 become bignums - fine,
;;; all operations are logior/logand/ash.

(defconstant +max-cluster-count+ 64
  "Maximum number of transactions in a cluster/DepGraph (Core
txgraph.h MAX_CLUSTER_COUNT_LIMIT; DepGraph's SetType::Size()).")

(defconstant +all-positions+ (1- (ash 1 +max-cluster-count+))
  "Bitset of every representable position (Core SetType::Fill(Size()),
cluster_linearize.h:137).")

(defmacro do-bits ((var set) &body body)
  "Execute BODY with VAR bound to each set bit index of SET, ascending.
SET is evaluated once; mutations during iteration don't affect it."
  (let ((s (gensym "SET")) (low (gensym "LOW")))
    `(let ((,s ,set))
       (loop until (zerop ,s)
             do (let* ((,low (logand ,s (- ,s)))
                       (,var (1- (integer-length ,low))))
                  ,@body
                  (setf ,s (logxor ,s ,low)))))))

(declaim (inline %lowest-bit))
(defun %lowest-bit (set)
  "Index of the lowest set bit of SET (Core SetType First())."
  (1- (integer-length (logand set (- set)))))

;;;; DepGraph (cluster_linearize.h:29-357)

(defstruct (%dg-entry (:constructor %make-dg-entry (feerate ancestors descendants)))
  "Information about a single transaction (cluster_linearize.h:33-49)."
  (feerate (make-feefrac) :type feefrac)
  ;; All ancestors of the transaction (including itself).
  (ancestors 0 :type (unsigned-byte 64))
  ;; All descendants of the transaction (including itself).
  (descendants 0 :type (unsigned-byte 64)))

(defstruct (depgraph (:conc-name %depgraph-))
  "A transaction graph's preprocessed data: per-position feerate plus
transitive-closure ancestor/descendant sets (cluster_linearize.h:29-357).
Positions may contain holes after removals; USED tracks live positions."
  (entries (make-array 8 :adjustable t :fill-pointer 0) :type vector)
  ;; Which positions are used (Core m_used).
  (used 0 :type (unsigned-byte 64)))

(declaim (inline depgraph-positions depgraph-position-range depgraph-tx-count
                 depgraph-tx-feerate depgraph-ancestors depgraph-descendants))

(defun depgraph-positions (g)
  "Bitset of transaction positions in use (cluster_linearize.h:116)."
  (%depgraph-used g))

(defun depgraph-position-range (g)
  "All positions in use are in [0, position-range) (cluster_linearize.h:118)."
  (fill-pointer (%depgraph-entries g)))

(defun depgraph-tx-count (g)
  "Number of transactions in the graph (cluster_linearize.h:120)."
  (logcount (%depgraph-used g)))

(defun depgraph-tx-feerate (g i)
  "The feefrac of the transaction at position I (cluster_linearize.h:122).
Do not mutate the returned object; it is the graph's own copy."
  (%dg-entry-feerate (aref (%depgraph-entries g) i)))

(defun depgraph-ancestors (g i)
  "Ancestor closure of position I, including I itself (cluster_linearize.h:126)."
  (%dg-entry-ancestors (aref (%depgraph-entries g) i)))

(defun depgraph-descendants (g i)
  "Descendant closure of position I, including I itself (cluster_linearize.h:128)."
  (%dg-entry-descendants (aref (%depgraph-entries g) i)))

(defun depgraph-add-transaction (g feerate)
  "Add a new unconnected transaction in the first available position and
return its index (cluster_linearize.h:135-148)."
  (let ((available (logandc2 +all-positions+ (%depgraph-used g))))
    (assert (plusp available) () "DepGraph is full (64 transactions)")
    (let* ((new-idx (%lowest-bit available))
           (entry (%make-dg-entry (copy-feefrac feerate)
                                  (ash 1 new-idx) (ash 1 new-idx)))
           (entries (%depgraph-entries g)))
      (if (= new-idx (fill-pointer entries))
          (vector-push-extend entry entries)
          (setf (aref entries new-idx) entry))
      (setf (%depgraph-used g) (logior (%depgraph-used g) (ash 1 new-idx)))
      new-idx)))

(defun depgraph-remove-transactions (g del)
  "Remove the positions in bitset DEL from G (cluster_linearize.h:159-173).
DepGraph only tracks closures, not direct edges: removing a parent while a
grandparent remains keeps the grandparent an ancestor."
  (let ((entries (%depgraph-entries g)))
    (setf (%depgraph-used g) (logandc2 (%depgraph-used g) del))
    ;; Remove now-unused trailing entries.
    (loop while (and (plusp (fill-pointer entries))
                     (not (logbitp (1- (fill-pointer entries))
                                   (%depgraph-used g))))
          do (vector-pop entries))
    ;; Remove the deleted transactions from ancestors/descendants of others.
    ;; Deleted (hole) positions keep stale data, overwritten on reuse.
    (loop with used = (%depgraph-used g)
          for entry across entries
          do (setf (%dg-entry-ancestors entry)
                   (logand (%dg-entry-ancestors entry) used)
                   (%dg-entry-descendants entry)
                   (logand (%dg-entry-descendants entry) used)))
    g))

(defun depgraph-add-dependencies (g parents child)
  "Add every position in bitset PARENTS as a parent of CHILD, updating the
transitive ancestor/descendant closures (cluster_linearize.h:179-200)."
  (assert (logbitp child (%depgraph-used g)))
  (assert (zerop (logandc2 parents (%depgraph-used g))))
  ;; Ancestors of PARENTS that are not already ancestors of CHILD.
  (let ((par-anc 0))
    (do-bits (par (logandc2 parents (depgraph-ancestors g child)))
      (setf par-anc (logior par-anc (depgraph-ancestors g par))))
    (setf par-anc (logandc2 par-anc (depgraph-ancestors g child)))
    (when (zerop par-anc) (return-from depgraph-add-dependencies g))
    ;; To each such ancestor, add the child's descendants as descendants.
    (let ((chl-des (depgraph-descendants g child))
          (entries (%depgraph-entries g)))
      (do-bits (anc-of-par par-anc)
        (let ((entry (aref entries anc-of-par)))
          (setf (%dg-entry-descendants entry)
                (logior (%dg-entry-descendants entry) chl-des))))
      ;; To each descendant of the child, add those ancestors.
      (do-bits (dec-of-chl chl-des)
        (let ((entry (aref entries dec-of-chl)))
          (setf (%dg-entry-ancestors entry)
                (logior (%dg-entry-ancestors entry) par-anc))))))
  g)

(defun depgraph-reduced-parents (g i)
  "The minimal subset of I's ancestors whose own ancestors cover all of I's
ancestors: the direct-parent set recovered from the closures (Core
GetReducedParents, cluster_linearize.h:210-221)."
  (let ((parents (logandc2 (depgraph-ancestors g i) (ash 1 i))))
    (do-bits (parent parents)              ; iterates the initial snapshot
      (when (logbitp parent parents)
        (setf parents (logior (logandc2 parents (depgraph-ancestors g parent))
                              (ash 1 parent)))))
    parents))

(defun depgraph-reduced-children (g i)
  "The minimal subset of I's descendants whose own descendants cover all of
I's descendants: the direct-child set (Core GetReducedChildren,
cluster_linearize.h:231-242)."
  (let ((children (logandc2 (depgraph-descendants g i) (ash 1 i))))
    (do-bits (child children)
      (when (logbitp child children)
        (setf children (logior (logandc2 children (depgraph-descendants g child))
                               (ash 1 child)))))
    children))

(defun depgraph-subset-feerate (g elems)
  "Aggregate feefrac of the positions in bitset ELEMS (cluster_linearize.h:248-253)."
  (let ((fee 0) (size 0))
    (do-bits (pos elems)
      (let ((fr (depgraph-tx-feerate g pos)))
        (incf fee (feefrac-fee fr))
        (incf size (feefrac-size fr))))
    (make-feefrac fee size)))

(defun depgraph-connected-component (g todo tx)
  "The connected component within bitset TODO that contains TX (Core
GetConnectedComponent, cluster_linearize.h:265-281). Connectivity is through
ancestor/descendant relations in the ENTIRE graph, so a tx and its
grandparent connect even if TODO misses the parent."
  (assert (logbitp tx todo))
  (assert (zerop (logandc2 todo (%depgraph-used g))))
  (let ((to-add (ash 1 tx))
        (ret 0))
    (loop
      (let ((old ret))
        (do-bits (add to-add)
          (setf ret (logior ret
                            (depgraph-descendants g add)
                            (depgraph-ancestors g add))))
        (setf ret (logand ret todo))
        (setf to-add (logandc2 ret old))
        (when (zerop to-add) (return ret))))))

(defun depgraph-find-connected-component (g todo)
  "The connected component containing the first transaction of bitset TODO,
or 0 if TODO is empty (cluster_linearize.h:290-294)."
  (if (zerop todo)
      0
      (depgraph-connected-component g todo (%lowest-bit todo))))

(defun depgraph-connected-p (g &optional (subset (depgraph-positions g)))
  "True when bitset SUBSET (default: the whole graph) is connected
(cluster_linearize.h:300-309)."
  (= (depgraph-find-connected-component g subset) subset))

(defun depgraph-acyclic-p (g)
  "True when the graph has no dependency cycles (cluster_linearize.h:328-336)."
  (do-bits (i (%depgraph-used g))
    (unless (= (logand (depgraph-ancestors g i) (depgraph-descendants g i))
               (ash 1 i))
      (return-from depgraph-acyclic-p nil)))
  t)

(defun depgraph-topo-sorted (g &optional (select (depgraph-positions g)))
  "The positions of bitset SELECT as a list in a topologically valid order:
ascending ancestor-closure count, ties by position (Core AppendTopo,
cluster_linearize.h:315-325)."
  (let ((idxs '()))
    (do-bits (i select) (push i idxs))
    (sort (nreverse idxs)
          (lambda (a b)
            (let ((a-anc (logcount (depgraph-ancestors g a)))
                  (b-anc (logcount (depgraph-ancestors g b))))
              (if (/= a-anc b-anc)
                  (< a-anc b-anc)
                  (< a b)))))))

(defun topological-subset-p (g subset)
  "True when bitset SUBSET is topologically closed: it contains every
in-graph ancestor of each of its members."
  (and (zerop (logandc2 subset (%depgraph-used g)))
       (progn
         (do-bits (i subset)
           (unless (zerop (logandc2 (depgraph-ancestors g i) subset))
             (return-from topological-subset-p nil)))
         t)))

(defun linearization-topological-p (g linearization)
  "True when LINEARIZATION (sequence of positions) is a complete, duplicate-
free, topologically valid ordering of G (Core's linearization SanityCheck,
test/util/cluster_linearize.h:383-397)."
  (let ((done 0)
        (count 0))
    (map nil (lambda (i)
               (incf count)
               (unless (and (logbitp i (%depgraph-used g))
                            (= (logandc2 (depgraph-ancestors g i) done)
                               (ash 1 i)))
                 (return-from linearization-topological-p nil))
               (setf done (logior done (ash 1 i))))
         linearization)
    (= count (depgraph-tx-count g))))

;;;; Chunking (cluster_linearize.h:427-463)

(defstruct (setinfo (:constructor make-setinfo
                        (&optional (transactions 0) (feerate (make-feefrac)))))
  "A set of transactions together with their aggregate feerate (Core SetInfo,
cluster_linearize.h:361-424)."
  (transactions 0 :type (unsigned-byte 64))
  (feerate (make-feefrac) :type feefrac))

(defun chunk-linearization (g linearization)
  "The chunk feerates of LINEARIZATION as a list of feefracs (Core
ChunkLinearization, cluster_linearize.h:448-463): each tx starts a singleton
chunk; while it has strictly higher feerate than the previous chunk, absorb
that chunk. Chunk feerates are monotonically non-increasing."
  (let ((chunks '()))                     ; reversed; head = last chunk
    (map nil (lambda (i)
               (let ((new-chunk (copy-feefrac (depgraph-tx-feerate g i))))
                 (loop while (and chunks (feefrac>> new-chunk (first chunks)))
                       do (let ((prev (pop chunks)))
                            (incf (feefrac-fee new-chunk) (feefrac-fee prev))
                            (incf (feefrac-size new-chunk) (feefrac-size prev))))
                 (push new-chunk chunks)))
         linearization)
    (nreverse chunks)))

(defun chunk-linearization-info (g linearization)
  "Like CHUNK-LINEARIZATION but returns setinfos carrying each chunk's
transaction set alongside its feerate (Core ChunkLinearizationInfo,
cluster_linearize.h:428-443); the sets delimit the chunk boundaries."
  (let ((chunks '()))
    (map nil (lambda (i)
               (let ((new-chunk (make-setinfo (ash 1 i)
                                              (copy-feefrac (depgraph-tx-feerate g i)))))
                 (loop while (and chunks
                                  (feefrac>> (setinfo-feerate new-chunk)
                                             (setinfo-feerate (first chunks))))
                       do (let ((prev (pop chunks)))
                            (setf (setinfo-transactions new-chunk)
                                  (logior (setinfo-transactions new-chunk)
                                          (setinfo-transactions prev)))
                            (incf (feefrac-fee (setinfo-feerate new-chunk))
                                  (feefrac-fee (setinfo-feerate prev)))
                            (incf (feefrac-size (setinfo-feerate new-chunk))
                                  (feefrac-size (setinfo-feerate prev)))))
                 (push new-chunk chunks)))
         linearization)
    (nreverse chunks)))

;;;; First-cut linearizer: ancestor-set feerate seeding

(defun ancestor-sort-linearization (g)
  "A topologically valid linearization built by repeatedly moving the
remaining ancestor set with the best (full-order) aggregate feerate to the
output - the classic ancestor-set-feerate approach of Core's former
AncestorCandidateFinder. O(n^3) worst case; fine for n <= 64. Returns a
simple-vector of positions."
  (let ((todo (depgraph-positions g))
        (out (make-array (depgraph-tx-count g)))
        (pos 0))
    (loop until (zerop todo)
          do (let ((best-set 0)
                   (best-feerate nil))
               ;; Pick the remaining tx whose within-TODO ancestor set has
               ;; the highest aggregate feerate (ties: lowest position).
               (do-bits (i todo)
                 (let* ((anc (logand (depgraph-ancestors g i) todo))
                        (feerate (depgraph-subset-feerate g anc)))
                   (when (or (null best-feerate) (feefrac> feerate best-feerate))
                     (setf best-set anc
                           best-feerate feerate))))
               ;; Emit that ancestor set in topological order.
               (dolist (i (depgraph-topo-sorted g best-set))
                 (setf (svref out pos) i)
                 (incf pos))
               (setf todo (logandc2 todo best-set))))
    out))

;;;; PostLinearize (cluster_linearize.h:1854-2037)

(defun post-linearize (g linearization)
  "Improve LINEARIZATION with Core's PostLinearize two-pass sweep
(cluster_linearize.h:1854-2037); returns a fresh simple-vector at least as
good (feerate-diagram-wise) as the input. Guarantees: chunks of the result
are connected; optimal for tree-shaped clusters (every tx at most one parent,
or every tx at most one child); starting with the backward pass gives the
moved-tree property (cluster_linearize.h:1844-1852).

Each pass sweeps the previous linearization, maintaining a list of groups:
every tx starts as a fresh group appended at the back, then repeatedly
merges with (if dependent) or swaps past (if independent) the group before
it while that group has strictly lower feerate. Pass 0 runs back-to-front
with parent/child and the fee sign reversed; pass 1 runs front-to-back.
Groups are singly-linked tx lists (PREV-TX, back to front), themselves in a
circular singly-linked group list (PREV-GROUP) rooted at a sentinel, exactly
as Core lays it out (cluster_linearize.h:1884-1943). Entry arrays are indexed
by tx+1; index 0 is the sentinel, and 0 also serves as Core's NO_PREV_TX."
  (let* ((lin (coerce linearization 'simple-vector))
         (n (length lin))
         (count (1+ (depgraph-position-range g)))
         ;; Per-entry fields (Core TxEntry, cluster_linearize.h:1899-1919).
         ;; group/deps/feerate/first-tx/prev-group are only meaningful for
         ;; tail transactions (the last tx of a group).
         (prev-tx (make-array count :initial-element 0))
         (first-tx (make-array count :initial-element 0))
         (prev-group (make-array count :initial-element 0))
         (group (make-array count :initial-element 0))
         (deps (make-array count :initial-element 0))
         ;; The group feerate, as separate fee/size so the sentinel's stays
         ;; the empty feefrac (never >> or << anything, terminating the
         ;; merge/swap loop at the list head).
         (g-fee (make-array count :initial-element 0))
         (g-size (make-array count :initial-element 0)))
    (setf lin (copy-seq lin))
    (dotimes (pass 2)
      (let ((rev (= pass 0)))             ; rev = !(pass & 1)
        ;; Sentinel group: start of the circular list, empty feerate.
        (setf (aref prev-group 0) 0)
        ;; Iterate over all elements in the existing linearization; even
        ;; (rev) passes go back to front.
        (dotimes (i n)
          (let* ((idx (svref lin (if rev (- n 1 i) i)))
                 (cur-group (1+ idx)))
            ;; New group containing just IDX. In rev passes the meanings of
            ;; parent/child and high/low feerate are swapped.
            (setf (aref group cur-group) (ash 1 idx)
                  (aref deps cur-group) (if rev
                                            (depgraph-descendants g idx)
                                            (depgraph-ancestors g idx))
                  (aref g-fee cur-group) (let ((fee (feefrac-fee (depgraph-tx-feerate g idx))))
                                           (if rev (- fee) fee))
                  (aref g-size cur-group) (feefrac-size (depgraph-tx-feerate g idx))
                  (aref prev-tx cur-group) 0       ; no previous tx in group
                  (aref first-tx cur-group) cur-group
                  ;; Insert at the back of the group list.
                  (aref prev-group cur-group) (aref prev-group 0)
                  (aref prev-group 0) cur-group)
            ;; Merge/swap cycle: continue while CUR-GROUP has strictly higher
            ;; feerate than the group before it (cross-multiplied compare;
            ;; the sentinel's 0/0 always stops the loop).
            (let ((next-group 0)
                  (prev-grp (aref prev-group cur-group)))
              (loop while (> (* (aref g-fee cur-group) (aref g-size prev-grp))
                             (* (aref g-fee prev-grp) (aref g-size cur-group)))
                    do (if (logtest (aref deps cur-group) (aref group prev-grp))
                           ;; Dependency between them: merge PREV-GRP into
                           ;; CUR-GROUP (cluster_linearize.h:1985-1998).
                           (progn
                             (setf (aref group cur-group)
                                   (logior (aref group cur-group) (aref group prev-grp))
                                   (aref deps cur-group)
                                   (logior (aref deps cur-group) (aref deps prev-grp)))
                             (incf (aref g-fee cur-group) (aref g-fee prev-grp))
                             (incf (aref g-size cur-group) (aref g-size prev-grp))
                             ;; Link the previous group's txs in front of ours.
                             (setf (aref prev-tx (aref first-tx cur-group)) prev-grp
                                   (aref first-tx cur-group) (aref first-tx prev-grp)
                                   prev-grp (aref prev-group prev-grp)
                                   (aref prev-group cur-group) prev-grp))
                           ;; No dependency: swap them. [PP, P, C, N] becomes
                           ;; [PP, C, P, N] (cluster_linearize.h:2000-2010).
                           (let ((preprev-group (aref prev-group prev-grp)))
                             (setf (aref prev-group next-group) prev-grp
                                   (aref prev-group prev-grp) cur-group
                                   (aref prev-group cur-group) preprev-group
                                   next-group prev-grp
                                   prev-grp preprev-group)))))))
        ;; Convert the groups back to a linearization, walking the group list
        ;; back to front and each group's txs tail to front: written forward
        ;; in rev passes, backward otherwise (cluster_linearize.h:2015-2035).
        (let ((cur-group (aref prev-group 0))
              (done 0))
          (loop until (zerop cur-group)
                do (let ((cur-tx cur-group))
                     (if rev
                         (loop do (setf (svref lin done) (1- cur-tx))
                                  (incf done)
                                  (setf cur-tx (aref prev-tx cur-tx))
                               until (zerop cur-tx))
                         (loop do (incf done)
                                  (setf (svref lin (- n done)) (1- cur-tx))
                                  (setf cur-tx (aref prev-tx cur-tx))
                               until (zerop cur-tx)))
                     (setf cur-group (aref prev-group cur-group))))
          (assert (= done n)))))
    lin))

(defun linearize (g)
  "Linearize cluster G: ancestor-set feerate seeding refined by
POST-LINEARIZE. Returns a simple-vector of positions in a topologically
valid order. Correct but not always optimal on non-tree DAGs; Core's SFL
(cluster_linearize.h:1799) is the future optimal replacement."
  (post-linearize g (ancestor-sort-linearization g)))
