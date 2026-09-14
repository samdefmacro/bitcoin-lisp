;;;; Bump fees for unconfirmed inputs -- Core's node::MiniMiner
;;;; (node/mini_miner.{h,cpp}).
;;;;
;;;; A minimal BlockAssembler run over one connected component of the mempool.
;;;; The wallet needs it to answer one question: if I spend this unconfirmed
;;;; output, how much extra fee must my transaction pay so that the miner takes
;;;; my ancestors along at my target feerate? Core asks it through the chain
;;;; interface (node/interfaces.cpp:690-708, calculateIndividualBumpFees /
;;;; calculateCombinedBumpFee) and applies the answer to each candidate coin's
;;;; effective value (wallet/spend.cpp:274, :516) and to sendall's fee budget
;;;; (:798, rpc/spend.cpp:1502).
;;;;
;;;; It lives in the wallet module rather than in a node file because the
;;;; wallet layer compiles BEFORE the node's: the wallet already reaches the
;;;; mempool through BL.MP's exported readers (see %MEMPOOL-TX-ANCESTRY in
;;;; wallet-spend.lisp), and this is the same shape of read. Nothing here
;;;; mutates the mempool.
;;;;
;;;; Without it the wallet paid the target feerate on the new transaction only,
;;;; so a spend of a low-feerate unconfirmed parent confirmed at the PARENT's
;;;; feerate: wallet_spend_unconfirmed.py:107 measured 15.5 sat/vB for a
;;;; 30 sat/vB target, and wallet_sendall.py:433 swept a wallet without
;;;; leaving the ancestors any more fee than they already had.

(in-package #:bitcoin-lisp.wallet)

(defstruct (mm-entry (:conc-name mm-) (:copier nil))
  "One MiniMinerMempoolEntry (node/mini_miner.h:25-57): a mempool transaction
with its own vsize/fee and the vsize/fee of its whole ancestor set. The
ancestor pair is MUTATED as ancestors are mined into the mock block, which is
what makes a second pass see only the ancestors that did not make it."
  txid
  tx
  (vsize 0 :type integer)
  (fee 0 :type integer)
  (anc-vsize 0 :type integer)
  (anc-fee 0 :type integer))

(defun %mm-feefrac< (fee-a size-a fee-b size-b)
  "FeeFrac's ordering (util/feefrac.h) over two (fee, size) pairs: an exact
rational comparison, NOT the rounded sat/kvB CFeeRate. Sizes are positive."
  (< (* fee-a size-b) (* fee-b size-a)))

(defun %mm-mining-score (entry)
  "The score MiniMiner's AncestorFeerateComparator sorts on
(node/mini_miner.cpp:180-197): the MINIMUM of the entry's own feerate and its
ancestor-set feerate, as (values fee size). Taking the ancestor feerate alone
would let a cheap child ride in on an expensive parent."
  (if (%mm-feefrac< (mm-anc-fee entry) (mm-anc-vsize entry)
                    (mm-fee entry) (mm-vsize entry))
      (values (mm-anc-fee entry) (mm-anc-vsize entry))
      (values (mm-fee entry) (mm-vsize entry))))

(defun %mm-better-p (a b)
  "Is A ordered before B by AncestorFeerateComparator: higher mining score
first, the txid breaking ties so the walk is deterministic."
  (multiple-value-bind (fee-a size-a) (%mm-mining-score a)
    (multiple-value-bind (fee-b size-b) (%mm-mining-score b)
      (cond ((%mm-feefrac< fee-b size-b fee-a size-a) t)
            ((%mm-feefrac< fee-a size-a fee-b size-b) nil)
            (t (%mm-txid< (mm-txid a) (mm-txid b)))))))

(defun %mm-txid< (a b)
  "Lexicographic order over two 32-byte txids -- std::set<Txid>'s ordering,
used only as the comparator's tiebreak."
  (loop for i from 0 below (min (length a) (length b))
        do (cond ((< (aref a i) (aref b i)) (return t))
                 ((> (aref a i) (aref b i)) (return nil)))
        finally (return nil)))

(defun %mm-component (mempool txids)
  "The mempool transactions connected to TXIDS through parent or child links
-- Core CTxMemPool::GatherClusters, which MiniMiner uses to bound the work to
one cluster (node/mini_miner.cpp:64-66). Returns a hash-set of txids."
  (let ((seen (bl.bytes:make-octets-hash-table))
        (queue (copy-list txids)))
    (loop while queue
          do (let ((txid (pop queue)))
               (unless (gethash txid seen)
                 (setf (gethash txid seen) t)
                 (when (bl.mp:mempool-get mempool txid)
                   (loop for k being the hash-keys
                           of (bl.mp:mempool-ancestors mempool txid)
                         do (push k queue))
                   (loop for k being the hash-keys
                           of (bl.mp:mempool-descendants mempool txid)
                         do (push k queue))))))
    seen))

(defstruct (mm-state (:conc-name mms-) (:copier nil))
  "The MiniMiner's state after its constructor (node/mini_miner.cpp:24-131):
BUMP-FEES already-decided zeros keyed by outpoint key, REQUESTED the requested
outpoints grouped by txid, ENTRIES the mock-mempool entries by txid,
DESCENDANTS each entry's descendant txids (itself included), READY-P Core's
m_ready_to_calculate."
  (bump-fees (bl.bytes:make-octets-hash-table) :type hash-table)
  (requested (bl.bytes:make-octets-hash-table) :type hash-table)
  (entries (bl.bytes:make-octets-hash-table) :type hash-table)
  (descendants (bl.bytes:make-octets-hash-table) :type hash-table)
  (ready-p t))

(defun %mm-make (mempool outpoints)
  "Core's MiniMiner(mempool, outpoints) constructor. OUTPOINTS is a list of
(txid . index)."
  (let ((state (make-mm-state))
        (to-be-replaced (bl.bytes:make-octets-hash-table)))
    (let ((bump-fees (mms-bump-fees state))
          (requested (mms-requested state)))
      (dolist (op outpoints)
        (destructuring-bind (txid . index) op
          (cond
            ;; Confirmed, or not in the mempool at all: no information, so no
            ;; bump (node/mini_miner.cpp:30-37).
            ((null (bl.mp:mempool-get mempool txid))
             (setf (gethash (%wtx-outpoint-key txid index) bump-fees) 0))
            (t
             (push op (gethash txid requested))
             ;; Already spent in the mempool: the caller means to replace that
             ;; spender, so it and its descendants leave the mock mempool
             ;; (:43-58).
             (let ((spender (bl.mp:mempool-spending-tx mempool txid index)))
               (when spender
                 (setf (gethash spender to-be-replaced) t)
                 (loop for d being the hash-keys
                         of (bl.mp:mempool-descendants mempool spender)
                       do (setf (gethash d to-be-replaced) t))))))))
      (when (zerop (hash-table-count requested))
        (return-from %mm-make state))
      (let ((component (%mm-component
                        mempool
                        (loop for k being the hash-keys of requested collect k))))
        (when (zerop (hash-table-count component))
          (setf (mms-ready-p state) nil)
          (return-from %mm-make state))
        (loop for txid being the hash-keys of component
              do (let ((entry (bl.mp:mempool-get mempool txid)))
                   (cond
                     ((gethash txid to-be-replaced)
                      ;; The requested outpoint belongs to a transaction that
                      ;; is about to be replaced; spending it is impossible, so
                      ;; its bump fee is 0 (:88-97).
                      (let ((ops (gethash txid requested)))
                        (when ops
                          (dolist (op ops)
                            (setf (gethash (%wtx-outpoint-key (car op) (cdr op))
                                           bump-fees)
                                  0))
                          (remhash txid requested))))
                     (entry
                      (multiple-value-bind (count anc-vsize anc-fee)
                          (bl.mp:mempool-ancestor-stats mempool txid)
                        (declare (ignore count))
                        (setf (gethash txid (mms-entries state))
                              (make-mm-entry
                               :txid txid
                               :tx (bl.mp:mempool-entry-transaction entry)
                               :vsize (bl.mp:mempool-entry-vsize entry)
                               :fee (bl.mp:mempool-entry-modified-fee entry)
                               :anc-vsize anc-vsize
                               :anc-fee anc-fee)))))))
        ;; Each entry's descendant set, ITSELF INCLUDED (:99-125) and the
        ;; to-be-replaced left out.
        (loop for txid being the hash-keys of component
              unless (gethash txid to-be-replaced)
                do (let ((set (list txid)))
                     (loop for d being the hash-keys
                             of (bl.mp:mempool-descendants mempool txid)
                           do (unless (gethash d to-be-replaced) (push d set)))
                     (setf (gethash txid (mms-descendants state)) set)))))
    state))

(defun %mm-build-template (state target-feerate)
  "Core MiniMiner::BuildMockTemplate (node/mini_miner.cpp:244-303): mine
ancestor packages, best mining score first, until the next package would not
pay TARGET-FEERATE. Returns the hash-set of mined txids; STATE's entries are
consumed, so what is left is exactly what did NOT make it into the block, with
its ancestor state reduced to the ancestors that are still outside."
  (let ((entries (mms-entries state))
        (descendants (mms-descendants state))
        (in-block (bl.bytes:make-octets-hash-table)))
    (loop
      (when (zerop (hash-table-count entries)) (return))
      (let ((best nil))
        (loop for e being the hash-values of entries
              do (when (or (null best) (%mm-better-p e best)) (setf best e)))
        ;; Everything still here needs bumping (:257-262).
        (when (and target-feerate
                   (< (mm-anc-fee best)
                      (bl.rpc:feerate-fee target-feerate (mm-anc-vsize best))))
          (return))
        (let ((ancestors (bl.bytes:make-octets-hash-table))
              (queue (list best)))
          (loop while queue
                do (let ((e (pop queue)))
                     (unless (gethash (mm-txid e) ancestors)
                       (setf (gethash (mm-txid e) ancestors) e)
                       (bl.ser:dovector
                           (in (bl.ser:transaction-inputs (mm-tx e)))
                         (let ((parent
                                 (gethash (bl.ser:outpoint-hash
                                           (bl.ser:tx-in-previous-output in))
                                          entries)))
                           (when (and parent
                                      (not (gethash (mm-txid parent) ancestors)))
                             (push parent queue)))))))
          ;; "Mine" the package: every descendant of a mined ancestor loses
          ;; that ancestor's size and fee from its ancestor state (:199-229).
          (loop for e being the hash-values of ancestors
                do (setf (gethash (mm-txid e) in-block) t)
                   (dolist (d (gethash (mm-txid e) descendants))
                     (let ((de (gethash d entries)))
                       (when de
                         (decf (mm-anc-vsize de) (mm-vsize e))
                         (decf (mm-anc-fee de) (mm-fee e))))))
          (loop for txid being the hash-keys of ancestors
                do (remhash txid entries)
                   (remhash txid descendants)))))
    in-block))

(defun mini-miner-bump-fees (mempool outpoints target-feerate)
  "Core MiniMiner::CalculateBumpFees through chain.calculateIndividualBumpFees
(node/mini_miner.cpp:309-387, node/interfaces.cpp:690-701): the extra fee each
of OUTPOINTS must pay for its unconfirmed ancestors to reach TARGET-FEERATE
(sat/kvB). OUTPOINTS is a list of (txid . index); the answer is a hash table
keyed by %WTX-OUTPOINT-KEY. A NIL MEMPOOL answers 0 for every outpoint, which
is Core's no-mempool branch.

Per outpoint the answer is the LARGER of the two bumps -- the one that lifts
the ancestor set to the target and the one that lifts the transaction itself --
because a transaction is only mined when both its own feerate and its ancestor
set's reach it (the worked example at :330-360)."
  (let ((answers (bl.bytes:make-octets-hash-table)))
    (cond
      ((null mempool)
       (dolist (op outpoints answers)
         (setf (gethash (%wtx-outpoint-key (car op) (cdr op)) answers) 0)))
      (t
       (let ((state (%mm-make mempool outpoints)))
         (unless (mms-ready-p state)
           (return-from mini-miner-bump-fees answers))
         (let ((in-block (%mm-build-template state target-feerate))
               (requested (mms-requested state)))
           (setf answers (mms-bump-fees state))
           ;; Mined: the ancestor package already pays the target (:315-326).
           (loop for txid being the hash-keys of in-block
                 do (let ((ops (gethash txid requested)))
                      (when ops
                        (dolist (op ops)
                          (setf (gethash (%wtx-outpoint-key (car op) (cdr op))
                                         answers)
                                0))
                        (remhash txid requested))))
           (loop for txid being the hash-keys of requested
                 using (hash-value ops)
                 do (let ((entry (gethash txid (mms-entries state))))
                      (when entry
                        (let ((bump
                                (max (- (bl.rpc:feerate-fee target-feerate
                                                            (mm-anc-vsize entry))
                                        (mm-anc-fee entry))
                                     (- (bl.rpc:feerate-fee target-feerate
                                                            (mm-vsize entry))
                                        (mm-fee entry)))))
                          (dolist (op ops)
                            (setf (gethash (%wtx-outpoint-key (car op) (cdr op))
                                           answers)
                                  (max 0 bump)))))))
           answers))))))

(defun mini-miner-total-bump-fee (mempool outpoints target-feerate)
  "Core MiniMiner::CalculateTotalBumpFees through
chain.calculateCombinedBumpFee (node/mini_miner.cpp:389-428): ONE bump fee for
spending all of OUTPOINTS together, counting each shared ancestor once. NIL
when the calculation could not be made (Core's std::nullopt), 0 for a NIL
mempool.

Not the sum of the individual answers: outpoints of one wallet commonly share
ancestors, and adding their bumps would pay for the same parent several times."
  (when (null mempool) (return-from mini-miner-total-bump-fee 0))
  (let ((state (%mm-make mempool outpoints)))
    (unless (mms-ready-p state) (return-from mini-miner-total-bump-fee nil))
    (let* ((in-block (%mm-build-template state target-feerate))
           (entries (mms-entries state))
           (ancestors (bl.bytes:make-octets-hash-table))
           (queue '()))
      (loop for txid being the hash-keys of (mms-requested state)
            do (unless (gethash txid in-block)
                 (let ((entry (gethash txid entries)))
                   (when entry
                     (setf (gethash txid ancestors) entry)
                     (push entry queue)))))
      (loop while queue
            do (let ((e (pop queue)))
                 (bl.ser:dovector (in (bl.ser:transaction-inputs (mm-tx e)))
                   (let ((parent (gethash (bl.ser:outpoint-hash
                                           (bl.ser:tx-in-previous-output in))
                                          entries)))
                     (when (and parent (not (gethash (mm-txid parent) ancestors)))
                       (setf (gethash (mm-txid parent) ancestors) parent)
                       (push parent queue))))))
      (let ((size 0) (fee 0))
        (loop for e being the hash-values of ancestors
              do (incf size (mm-vsize e))
                 (incf fee (mm-fee e)))
        (- (bl.rpc:feerate-fee target-feerate size) fee)))))
