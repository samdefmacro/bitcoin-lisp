(in-package #:bitcoin-lisp.storage)

;;;; The block index consistency check (Core ChainstateManager::CheckBlockIndex,
;;;; validation.cpp:5165-5470)
;;;
;;; A depth-first walk over EVERY block index entry that asserts what the rest
;;; of the node maintains: heights, chain work and validity levels agree along
;;; each path, a failed block's descendants are failed, the body/transaction
;;; bookkeeping (Core's nStatus HAVE_DATA, nTx) agrees with itself, the
;;; unlinked-body table holds exactly the bodies waiting on a missing ancestor,
;;; and every entry is reached from genesis. Core runs it on regtest after
;;; every header, every accepted body and every ActivateBestChain; so do we --
;;; the sampling and the drive sites are BL.VAL:CHECK-BLOCK-INDEX's.
;;;
;;; Core's fields, as this walk reads them from our entry:
;;;   nStatus             ENTRY-DISK-STATUS (the record we write to blocks/index):
;;;                       validity level, HAVE_DATA, HAVE_UNDO, FAILED_VALID
;;;   nTx                 BLOCK-INDEX-ENTRY-TX-COUNT
;;;   nHeight, pprev,     the slots of the same names
;;;   nChainWork
;;;   nSequenceId         BLOCK-INDEX-ENTRY-SEQUENCE-ID
;;;   m_best_header       BEST-HEADER-ENTRY
;;;   m_blocks_unlinked   *BLOCKS-UNLINKED* (keyed by the parent's hash)
;;;   m_have_pruned       a chainstate's PRUNED-HEIGHT above zero
;;;   SnapshotBase()      the snapshot base: a snapshot chainstate's
;;;                       FROM-SNAPSHOT-BLOCKHASH, a historical one's TARGET
;;;
;;; Asserts with no counterpart in our model, and why (each is named again at
;;; the place Core makes it):
;;;   - m_chain_tx_count / HaveNumChainTxs (:5271, :5292-5293, :5308-5317): our
;;;     index stores no chain transaction count -- getchaintxstats sums tx-count
;;;     on demand -- so HaveNumChainTxs is taken from its definition (every
;;;     block back to genesis or the snapshot base has had its transactions,
;;;     i.e. FIRST-NEVER-PROCESSED is NIL or the entry is the base). :5292 then
;;;     holds by construction, :5293 becomes `FIRST-NEVER-PROCESSED and
;;;     FIRST-NOT-TRANSACTIONS-VALID are NIL together', :5271 keeps its meaning
;;;     (an entry with an assigned sequence id has every ancestor's
;;;     transactions), and the three sums have no stored value to compare.
;;;   - pskip (:5296): the index keeps no skip pointers; ENTRY-ANCESTOR-AT-
;;;     HEIGHT walks prev links.
;;;   - setBlockIndexCandidates (:5321-5378, and the candidate half of
;;;     :5396-5415): we keep no candidate SET. FindMostWorkChain's candidates
;;;     are derived from the index on every call (BL.VAL::%TIP-CANDIDATES:
;;;     every non-failed entry better than the tip with its body on disk), so
;;;     membership holds by definition, and the re-parking of a pruned path's
;;;     candidates into m_blocks_unlinked (:3184-3188) has no equivalent.

(define-condition block-index-check-failed (internal-error) ()
  (:documentation "A CHECK-BLOCK-INDEX-NOW assertion did not hold: the block
index contradicts itself. Core asserts, which aborts bitcoind; the drive sites
(BL.VAL:CHECK-BLOCK-INDEX) report it as a fatal error that stops the node."))

(defstruct (cbi-walk (:conc-name cbi-))
  "The state of one CHECK-BLOCK-INDEX-NOW walk: the oldest entry on the path
from genesis to the current one that is the first with each property (Core's
pindexFirst* pointers, validation.cpp:5210-5216), the five a snapshot base
stashes (snap_first_*, :5222-5232), and what every entry is compared with."
  (snap-base nil)
  (snap-ancestors nil)
  (have-pruned nil)
  (best-header nil)
  (first-invalid nil)
  (first-missing nil)
  (first-never-processed nil)
  (first-not-tree-valid nil)
  (first-not-transactions-valid nil)
  (first-not-chain-valid nil)
  (first-not-scripts-valid nil)
  (snap-missing nil)
  (snap-notx nil)
  (snap-notv nil)
  (snap-nocv nil)
  (snap-nosv nil))

(defun %cbi-fail (invariant entry)
  "Log and signal BLOCK-INDEX-CHECK-FAILED naming INVARIANT and ENTRY."
  (let ((message
          (if entry
              (format nil "~A (block ~A at height ~D)" invariant
                      (if (block-index-entry-hash entry)
                          (bl.crypto:bytes-to-hex
                           (bl.crypto:reverse-bytes (block-index-entry-hash entry)))
                          "without a hash")
                      (block-index-entry-height entry))
              invariant)))
    (bl.log:log-error "Block index consistency check failed: ~A" message)
    (error 'block-index-check-failed
           :format-control "Block index consistency check failed: ~A"
           :format-arguments (list message))))

(defmacro cbi-assert (form invariant &optional entry)
  "Core's assert(FORM) inside CheckBlockIndex: fail naming INVARIANT."
  `(unless ,form (%cbi-fail ,invariant ,entry)))

(defun %cbi-level (status) (logand status +block-valid-mask+))

(defun %cbi-chain-vector (tip)
  "Core CChain::SetTip: a vector of TIP's ancestors indexed by height, built
by the prev links. Each must sit one height below the next and end at a
parentless height-0 entry -- the checks Core's SetTip gets for free from
nHeight."
  (let* ((n (1+ (block-index-entry-height tip)))
         (v (make-array n :initial-element nil)))
    (loop for e = tip then (block-index-entry-prev-entry e)
          for h downfrom (1- n)
          while (>= h 0)
          do (cbi-assert (and e (= (block-index-entry-height e) h))
                         "nHeight must be consistent along the best header chain" tip)
             (setf (svref v h) e)
          finally (cbi-assert (null e) "genesis has no parent" e))
    v))

(defun %cbi-at (chain height)
  "Core CChain::operator[]: the entry at HEIGHT, NIL past the tip."
  (and (< -1 height (length chain)) (svref chain height)))

(defun %cbi-contains (chain entry)
  "Core CChain::Contains."
  (eq (%cbi-at chain (block-index-entry-height entry)) entry))

(defun %cbi-forward-map (index chain)
  "Core's `forward' multimap (validation.cpp:5190-5200): parent -> the
children NOT on the best header chain, as an EQ table, and its size."
  (let ((forward (make-hash-table :test 'eq)) (size 0))
    (maphash (lambda (hash entry)
               (declare (ignore hash))
               (unless (%cbi-contains chain entry)
                 (cbi-assert (block-index-entry-prev-entry entry)
                             "only genesis, on the best header chain, has no parent"
                             entry)
                 (push entry (gethash (block-index-entry-prev-entry entry) forward))
                 (incf size)))
             index)
    (values forward size)))

(defun %cbi-note-firsts (w entry status)
  "The top of Core's walk (validation.cpp:5235-5258): ENTRY becomes the first
of each property it has that no ancestor on the path already has."
  (let ((prev (block-index-entry-prev-entry entry))
        (level (%cbi-level status)))
    (when (and (null (cbi-first-invalid w)) (logtest status +block-failed-valid+))
      (setf (cbi-first-invalid w) entry))
    (when (and (null (cbi-first-missing w)) (not (logtest status +block-have-data+)))
      (setf (cbi-first-missing w) entry))
    (when (and (null (cbi-first-never-processed w))
               (zerop (block-index-entry-tx-count entry)))
      (setf (cbi-first-never-processed w) entry))
    (when prev
      (when (and (null (cbi-first-not-tree-valid w)) (< level +block-valid-tree+))
        (setf (cbi-first-not-tree-valid w) entry))
      (when (and (null (cbi-first-not-transactions-valid w))
                 (< level +block-valid-transactions+))
        (setf (cbi-first-not-transactions-valid w) entry))
      (when (and (null (cbi-first-not-chain-valid w)) (< level +block-valid-chain+))
        (setf (cbi-first-not-chain-valid w) entry))
      (when (and (null (cbi-first-not-scripts-valid w)) (< level +block-valid-scripts+))
        (setf (cbi-first-not-scripts-valid w) entry)))))

(defun %cbi-clear-firsts (w entry)
  "Leaving ENTRY upwards (validation.cpp:5439-5446): it is no longer the first
of anything on the path."
  (macrolet ((clear (&rest accessors)
               `(progn ,@(loop for a in accessors
                               collect `(when (eq (,a w) entry) (setf (,a w) nil))))))
    (clear cbi-first-invalid cbi-first-missing cbi-first-never-processed
           cbi-first-not-tree-valid cbi-first-not-transactions-valid
           cbi-first-not-chain-valid cbi-first-not-scripts-valid)))

(defun %cbi-snap-update-firsts (w entry)
  "Core's snap_update_firsts (validation.cpp:5224-5232): at the snapshot base
the missing/unprocessed/not-valid firsts below it are stashed going down and
restored coming back up, so the blocks above the base are checked as if
everything below it had been downloaded and validated."
  (when (and entry (eq entry (cbi-snap-base w)))
    (rotatef (cbi-snap-missing w) (cbi-first-missing w))
    (rotatef (cbi-snap-notx w) (cbi-first-never-processed w))
    (rotatef (cbi-snap-notv w) (cbi-first-not-transactions-valid w))
    (rotatef (cbi-snap-nocv w) (cbi-first-not-chain-valid w))
    (rotatef (cbi-snap-nosv w) (cbi-first-not-scripts-valid w))))

(defun %cbi-check-status (w entry status height)
  "Core's per-entry asserts on nStatus, nTx, the validity levels, heights and
work (validation.cpp:5260-5320)."
  (let* ((prev (block-index-entry-prev-entry entry))
         (level (%cbi-level status))
         (ntx (block-index-entry-tx-count entry))
         (have-data (logtest status +block-have-data+))
         (snap-base (cbi-snap-base w))
         (fnp (cbi-first-never-processed w))
         ;; HaveNumChainTxs by its definition: see the header comment.
         (have-chain-txs (or (null fnp) (eq entry snap-base))))
    (unless prev
      (cbi-assert (equalp (block-index-entry-hash entry)
                          (network-genesis-hash bl.chain:*network*))
                  "the genesis block's hash must match" entry))
    (unless have-chain-txs
      (cbi-assert (<= (block-index-entry-sequence-id entry) +seq-id-init-from-disk+)
                  "an entry with a sequence id must have every ancestor's transactions"
                  entry))
    (if (cbi-have-pruned w)
        (when have-data
          (cbi-assert (plusp ntx) "HAVE_DATA implies nTx > 0" entry))
        (progn
          (cbi-assert (eq (not have-data) (zerop ntx))
                      "HAVE_DATA is equivalent to nTx > 0 when nothing was pruned" entry)
          (cbi-assert (eq (cbi-first-missing w) fnp)
                      "the first block without data is the first never processed when nothing was pruned"
                      entry)))
    (when (logtest status +block-have-undo+)
      (cbi-assert have-data "HAVE_UNDO implies HAVE_DATA" entry))
    (when (and snap-base (eq (%cbi-at (cbi-snap-ancestors w)
                                      (block-index-entry-height entry))
                             entry))
      (cbi-assert (>= level +block-valid-tree+)
                  "the snapshot base's ancestors must be TREE valid" entry))
    (cbi-assert (eq (>= level +block-valid-transactions+) (plusp ntx))
                "VALID_TRANSACTIONS is equivalent to nTx > 0" entry)
    ;; :5292 holds by construction; :5293 is the agreement of the two firsts.
    (cbi-assert (eq have-chain-txs
                    (or (null (cbi-first-not-transactions-valid w)) (eq entry snap-base)))
                "every ancestor processed is equivalent to every ancestor VALID_TRANSACTIONS"
                entry)
    (cbi-assert (= (block-index-entry-height entry) height)
                "nHeight must be consistent" entry)
    (when prev
      (cbi-assert (>= (block-index-entry-chain-work entry)
                      (block-index-entry-chain-work prev))
                  "the chain work must not be below the parent's" entry))
    ;; :5296 (pskip) has no counterpart: no skip pointers.
    (cbi-assert (null (cbi-first-not-tree-valid w))
                "every entry must be at least TREE valid" entry)
    (when (>= level +block-valid-chain+)
      (cbi-assert (null (cbi-first-not-chain-valid w))
                  "CHAIN valid implies all parents are CHAIN valid" entry))
    (when (>= level +block-valid-scripts+)
      (cbi-assert (null (cbi-first-not-scripts-valid w))
                  "SCRIPTS valid implies all parents are SCRIPTS valid" entry))
    (if (null (cbi-first-invalid w))
        (cbi-assert (not (logtest status +block-failed-valid+))
                    "the failed flag cannot be set for blocks without invalid parents" entry)
        (cbi-assert (logtest status +block-failed-valid+)
                    "invalid blocks and their descendants must be marked as invalid" entry))
    ;; :5308-5317 (m_chain_tx_count sums) have no counterpart: not stored.
    (cbi-assert (or (logtest status +block-failed-valid+)
                    (<= (block-index-entry-chain-work entry)
                        (block-index-entry-chain-work (cbi-best-header w))))
                "no block may have more work than the best header unless it is invalid"
                entry)))

(defun %cbi-check-unlinked (w entry status)
  "Core's m_blocks_unlinked asserts (validation.cpp:5379-5398): a body whose
chain lacks some ancestor's transactions waits in *BLOCKS-UNLINKED*, and
nothing else does."
  (let* ((prev (block-index-entry-prev-entry entry))
         (have-data (logtest status +block-have-data+))
         ;; One table lookup per entry, skipped while nothing waits.
         (found (and prev (plusp (hash-table-count *blocks-unlinked*))
                     (member entry (gethash (block-index-entry-hash prev)
                                            *blocks-unlinked*)
                             :test #'eq))))
    (when (and prev have-data (cbi-first-never-processed w)
               (null (cbi-first-invalid w)))
      (cbi-assert found
                  "a body with a never-processed ancestor and no invalid one must be unlinked"
                  entry))
    (unless have-data
      (cbi-assert (not found) "an entry without HAVE_DATA cannot be unlinked" entry))
    (unless (cbi-first-missing w)
      (cbi-assert (not found)
                  "an entry missing no ancestor's data cannot be unlinked" entry))
    (when (and prev have-data (null (cbi-first-never-processed w))
               (cbi-first-missing w))
      ;; The rest of :5399-5415 asks about setBlockIndexCandidates: no
      ;; counterpart (see the header comment).
      (cbi-assert (cbi-have-pruned w)
                  "a body whose ancestor's data is missing although processed implies pruning"
                  entry))))

(defun %cbi-walk (w chain forward)
  "Core's depth-first walk (validation.cpp:5234-5469) from CHAIN's genesis:
forks first, the best header chain last, upwards through the prev links when
a branch ends. Returns the number of entries visited."
  (let ((entry (svref chain 0)) (height 0) (nodes 0))
    (loop while entry
          do (incf nodes)
             (let ((status (entry-disk-status entry)))
               (%cbi-note-firsts w entry status)
               (%cbi-check-status w entry status height)
               (%cbi-check-unlinked w entry status))
             (%cbi-snap-update-firsts w entry)
             (let ((kids (gethash entry forward)))
               (cond
                 (kids (setf entry (first kids)) (incf height))
                 ((%cbi-contains chain entry)
                  (incf height)
                  (setf entry (%cbi-at chain height)))
                 (t
                  ;; A leaf: up until a parent has a child not yet visited.
                  (loop while entry
                        do (%cbi-snap-update-firsts w entry)
                           (%cbi-clear-firsts w entry)
                           (let* ((parent (block-index-entry-prev-entry entry))
                                  (rest (member entry (gethash parent forward) :test #'eq)))
                             (cbi-assert rest
                                         "our parent must have the node we come from as a child"
                                         entry)
                             (cond
                               ((cdr rest) (setf entry (second rest)) (return))
                               ((eq parent (%cbi-at chain (1- height)))
                                (setf entry (%cbi-at chain height))
                                (cbi-assert (eq (null entry)
                                                (eq parent (svref chain (1- (length chain)))))
                                            "only the best header has no best-chain child"
                                            parent)
                                (return))
                               (t (setf entry parent) (decf height)))))))))
    nodes))

(defun check-block-index-now (chain-state)
  "Core ChainstateManager::CheckBlockIndex (validation.cpp:5165-5470) over
CHAIN-STATE's block index, unconditionally: T, or BLOCK-INDEX-CHECK-FAILED
naming the first invariant that does not hold. O(index). The asserts this
port could not map are listed, with the reason, at the top of
src/storage/check-block-index.lisp. The sampling (-checkblockindex) and the
drive sites are BL.VAL:CHECK-BLOCK-INDEX's."
  (let ((index (chain-state-block-index chain-state))
        (tip (get-block-index-entry chain-state (chain-state-best-block-hash chain-state))))
    ;; :5173-5179 -- no active chain yet: genesis at most.
    (unless tip
      (cbi-assert (<= (hash-table-count index) 1)
                  "an index without an active chain holds at most genesis")
      (return-from check-block-index-now t))
    (let ((best (best-header-entry chain-state)))
      (cbi-assert best "there is a best header")
      (cbi-assert (not (eq (block-index-entry-status best) :invalid))
                  "the best header is not invalid" best)
      (let ((chain (%cbi-chain-vector best))
            (snap (or (chain-state-from-snapshot-blockhash chain-state)
                      (chain-state-target-blockhash chain-state))))
        (multiple-value-bind (forward forward-size) (%cbi-forward-map index chain)
          (cbi-assert (= (+ forward-size (length chain)) (hash-table-count index))
                      "every entry is either on the best header chain or a parent's child")
          ;; :5264-5266 -- the chainstate's genesis is the index's.
          (cbi-assert (eq (entry-ancestor-at-height tip 0) (svref chain 0))
                      "the chain's genesis block must be the index's" tip)
          (let* ((base (and snap (get-block-index-entry chain-state snap)))
                 (w (make-cbi-walk
                    :snap-base base
                    :snap-ancestors (and base (entry-ancestor-vector base))
                    :have-pruned (plusp (chain-state-pruned-height chain-state))
                    :best-header best)))
            (cbi-assert (= (%cbi-walk w chain forward)
                           (+ forward-size (length chain)))
                        "the walk must visit every entry of the block index")))))
    t))
