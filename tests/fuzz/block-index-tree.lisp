(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/block_index_tree.cpp at the pin: a block index grown by
;;;; fuzzed headers, bodies (valid or not), activations, prunes and
;;;; re-downloads, and then CheckBlockIndex over the result. Validation is
;;;; mocked as Core mocks it: a header is valid by assumption, a body is
;;;; consensus-invalid on a coin flip, and the activation is Core's simplified
;;;; ActivateBestChain. Each step goes through the bookkeeping the node uses --
;;;; ADD-BLOCK-INDEX-ENTRY, %RECORD-BLOCK-POSITION and NOTE-BLOCK-RECEIVED
;;;; (ReceivedBlockTransactions), POISON-FAILED-BLOCK (InvalidBlockFound),
;;;; DROP-UNLINKED-BLOCK (PruneOneBlockFile) -- so the invariant,
;;;; BL.STORE:CHECK-BLOCK-INDEX-NOW, judges that bookkeeping.

(def-suite :fuzz-block-index-tree-tests :in :bitcoin-lisp-tests
  :description "Core fuzz block_index_tree.cpp: CheckBlockIndex over a fuzzed block tree")

(in-suite :fuzz-block-index-tree-tests)

(defun %bit-genesis (chain-state)
  "Regtest genesis as the node holds it: connected, its body and undo record
on disk, one transaction. Becomes the tip."
  (let ((genesis (%cbi-received (add-regtest-genesis-entry chain-state) 8 :undo t)))
    (bl.store:update-chain-tip chain-state (bl.store:block-index-entry-hash genesis) 0)
    genesis))

(defun %bit-add-header (fdp chain-state prev nonce)
  "Core's ConsumeBlockHeader + AddToBlockIndex: a header on PREV with a fuzzed
version and time, regtest genesis bits and NONCE to keep hashes apart."
  (let* ((header (bl.ser:make-block-header
                  :version (consume-integral fdp :i32)
                  :prev-block (bl.store:block-index-entry-hash prev)
                  :merkle-root (make-array 32 :element-type '(unsigned-byte 8)
                                              :initial-element 0)
                  :timestamp (consume-integral fdp :u32)
                  :bits bl.store:+regtest-pow-limit-bits+
                  :nonce nonce)))
    (bl.store:add-block-index-entry
     chain-state
     (bl.store:make-block-index-entry
      :hash (bl.ser:block-header-hash header)
      :height (1+ (bl.store:block-index-entry-height prev))
      :header header :prev-entry prev :status :header-valid
      :chain-work (bl.store:calculate-chain-work
                   bl.store:+regtest-pow-limit-bits+
                   (bl.store:block-index-entry-chain-work prev))))))

(defun %bit-receive (chain-state entry position tx-count)
  "Core ReceivedBlockTransactions: the body lands at POSITION of blk file 0
with TX-COUNT transactions."
  (bl.store:%record-block-position entry (bl.store:make-flat-file-pos 0 position)
                                   :tx-count tx-count)
  (bl.store:note-block-received chain-state entry))

(defun %bit-invalid-found (chain-state entry)
  "Core InvalidBlockFound for a consensus failure: the block and its
descendants are failed."
  (bl.val:poison-failed-block chain-state (bl.store:block-index-entry-header entry)
                              :missing-input))

(defun %bit-most-work (chain-state tip)
  "Core FindMostWorkChain, simplified as the target simplifies it: the best
entry, by CBlockIndexWorkComparator, that is not failed and whose path back to
the active chain holds every body and no failed block -- TIP when none beats
it."
  (let ((best tip))
    (maphash (lambda (hash e)
               (declare (ignore hash))
               (when (and (bl.store:entry-better-p e best)
                          (loop for a = e then (bl.store:block-index-entry-prev-entry a)
                                until (or (null a) (bl.store:entry-on-active-chain-p chain-state a))
                                always (and (bl.store:block-index-entry-data-pos a)
                                            (not (eq (bl.store:block-index-entry-status a)
                                                     :invalid)))))
                 (setf best e)))
             (bl.store:chain-state-block-index chain-state))
    best))

(defun %bit-activate (fdp chain-state)
  "The target's simplified ActivateBestChain: rewind to the fork, connect
toward the most-work chain, a block failing on a coin flip. :ABORT when a
block to disconnect has no undo record (pruned)."
  (let ((old-tip (bl.store:get-block-index-entry
                  chain-state (bl.store:best-block-hash chain-state))))
    (loop
      (let* ((tip (bl.store:get-block-index-entry
                   chain-state (bl.store:best-block-hash chain-state)))
             (best (%bit-most-work chain-state tip)))
        (when (eq best tip) (return))
        (let ((fork (bl.val:find-fork-point tip best)))
          (loop for e = tip then (bl.store:block-index-entry-prev-entry e)
                until (eq e fork)
                unless (bl.store:block-index-entry-undo-pos e)
                  do (fuzz-assert (plusp (bl.store:chain-state-pruned-height chain-state)))
                     (return-from %bit-activate :abort))
          (bl.store:update-chain-tip chain-state (bl.store:block-index-entry-hash fork)
                                     (bl.store:block-index-entry-height fork))
          (dolist (block (reverse (loop for e = best then (bl.store:block-index-entry-prev-entry e)
                                        until (eq e fork) collect e)))
            (fuzz-assert (bl.store:block-index-entry-data-pos block))
            (unless (eq (bl.store:block-index-entry-status block) :valid)
              (when (consume-bool fdp)
                (%bit-invalid-found chain-state block)
                (return))
              (setf (bl.store:block-index-entry-status block) :valid
                    (bl.store:block-index-entry-undo-pos block)
                    (bl.store:block-index-entry-data-pos block)))
            (bl.store:update-chain-tip chain-state (bl.store:block-index-entry-hash block)
                                       (bl.store:block-index-entry-height block))
            (when (and (> (bl.store:block-index-entry-chain-work block)
                          (bl.store:block-index-entry-chain-work old-tip))
                       (consume-bool fdp))
              (return)))
          ;; Core's do ... while the tip sorts below the old one.
          (unless (bl.store:entry-better-p
                   old-tip
                   (bl.store:get-block-index-entry
                    chain-state (bl.store:best-block-hash chain-state)))
            (return)))))
    (fuzz-assert (>= (bl.store:block-index-entry-chain-work
                      (bl.store:get-block-index-entry
                       chain-state (bl.store:best-block-hash chain-state)))
                     (bl.store:block-index-entry-chain-work old-tip)))
    nil))

(defun %bit-prune (fdp chain-state pruned)
  "The target's prune: a random active-chain block other than the tip loses
its body and undo record (PruneOneBlockFile). Returns PRUNED, extended."
  (let* ((tip-height (bl.store:current-height chain-state))
         (entry (bl.store:get-block-at-height
                 chain-state (consume-integral-in-range fdp 0 tip-height))))
    (if (and (< (bl.store:block-index-entry-height entry) tip-height)
             (bl.store:block-index-entry-data-pos entry))
        (progn
          (setf (bl.store:chain-state-pruned-height chain-state)
                (max 1 (bl.store:chain-state-pruned-height chain-state))
                (bl.store:block-index-entry-file entry) nil
                (bl.store:block-index-entry-data-pos entry) nil
                (bl.store:block-index-entry-undo-pos entry) nil)
          (bl.store:drop-unlinked-block entry)
          (cons entry pruned))
        pruned)))

(defun %bit-have-data-p (entry)
  "ENTRY's nStatus carries BLOCK_HAVE_DATA (8) and BLOCK_VALID_TRANSACTIONS
(level 3 or more), as ReceivedBlockTransactions leaves it."
  (let ((status (bl.store:entry-disk-status entry)))
    (and (logtest status 8) (>= (logand 7 status) 3))))

(defun %bit-step (fdp chain-state blocks pruned nonce)
  "One of the target's five operations. Returns (values BLOCKS PRUNED ABORT)."
  (let ((abort nil))
    (call-one-of fdp
      ;; A header on any block not known to be invalid.
      (let ((prev (pick-value-in-array fdp blocks)))
        (unless (eq (bl.store:block-index-entry-status prev) :invalid)
          (let ((entry (%bit-add-header fdp chain-state prev nonce)))
            (fuzz-assert (eq prev (bl.store:block-index-entry-prev-entry entry)))
            ;; BLOCK_VALID_TREE (2) in BLOCK_VALID_MASK (7).
            (fuzz-assert (>= (logand 7 (bl.store:entry-disk-status entry)) 2))
            (setf blocks (append blocks (list entry))))))
      ;; A body, valid or invalid, for a header never received.
      (let ((entry (pick-value-in-array fdp blocks)))
        (when (and (zerop (bl.store:block-index-entry-tx-count entry))
                   (not (eq (bl.store:block-index-entry-status entry) :invalid)))
          (if (consume-bool fdp)
              (%bit-invalid-found chain-state entry)
              (progn
                (%bit-receive chain-state entry (consume-integral-in-range fdp 1 1000)
                              (consume-integral-in-range fdp 1 1000))
                (fuzz-assert (%bit-have-data-p entry))))))
      ;; Activation.
      (setf abort (eq :abort (%bit-activate fdp chain-state)))
      ;; Prune.
      (setf pruned (%bit-prune fdp chain-state pruned))
      ;; Re-download a pruned body.
      (when pruned
        (let ((entry (pick-value-in-array fdp pruned)))
          (%bit-receive chain-state entry (consume-integral-in-range fdp 1 1000)
                        (bl.store:block-index-entry-tx-count entry))
          (fuzz-assert (%bit-have-data-p entry))
          (setf pruned (remove entry pruned)))))
    (values blocks pruned abort)))

(defun %bit-corpus (fdp)
  "A buffer that keeps the target's loop going for up to 200 operations --
headers weighted first, then bodies, activations, prunes and re-downloads --
laid out the way the target consumes it while the tree has under 256 blocks:
what a qa-assets corpus entry for Core's target does, where random bytes stop
after a couple of operations. Its draws come from FDP."
  (let ((tail (make-fdp-tail))
        (blocks 1))
    (labels ((r (min max) (fdp-tail-integral tail (consume-integral-in-range fdp min max) min max))
             (b () (fdp-tail-bool tail (consume-bool fdp)))
             ;; PICK-VALUE-IN-ARRAY reads nothing from a one-element array.
             (pick () (when (> blocks 1) (r 0 (1- (min blocks 256))))))
      (dotimes (i (consume-integral-in-range fdp 20 200))
        (fdp-tail-bool tail t)
        (let ((op (aref #(0 0 0 0 1 1 1 2 2 3 4) (consume-integral-in-range fdp 0 10))))
          (fdp-tail-integral tail op 0 4)
          (ecase op
            (0 (pick) (r 0 #xffffffff) (r 0 #xffffffff) (incf blocks))
            (1 (pick) (b) (r 1 1000) (r 1 1000))
            (2 (b) (b) (b) (b))
            (3 (r 0 255))
            (4 (r 0 255) (r 1 1000)))))
      (fdp-tail-bool tail nil))
    (fdp-tail-bytes tail)))

(define-fuzz-target block-index-tree
    (buffer :core "block_index_tree.cpp:39-232" :iterations 300 :max-len 400
            :corpus #'%bit-corpus)
  "Whatever headers, bodies, failures, activations, prunes and re-downloads
arrive in whatever order, the block index passes Core's CheckBlockIndex."
  (with-network (:regtest)
    (bl.store:reset-block-sequence-state)
    (bl.val:reset-fork-warning-state)
    (let* ((fdp (make-fuzzed-data-provider buffer))
           (chain-state (bl.store:make-chain-state))
           (blocks (list (%bit-genesis chain-state)))
           (pruned '())
           (nonce 0)
           (abort nil))
      (unwind-protect
           (progn
             (limited-while ((and (not abort) (consume-bool fdp)) 1000)
               (multiple-value-setq (blocks pruned abort)
                 (%bit-step fdp chain-state blocks pruned (incf nonce))))
             (unless abort
               (let ((failure (handler-case (progn (bl.store:check-block-index-now chain-state)
                                                   nil)
                                (bl.store:block-index-check-failed (c) (princ-to-string c)))))
                 (fuzz-assert (null (fuzz-sabotage failure)) "~A" failure))))
        (bl.store:reset-block-sequence-state)
        (bl.val:reset-fork-warning-state)))))
