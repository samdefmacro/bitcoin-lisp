(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/txorphan.cpp at the pin (d3056bc149): txorphan (random
;;;; transactions through every orphanage entry point, with the contract of
;;;; each return value), txorphan_protected (a peer that stays inside its own
;;;; reservation never loses an orphan, however the others flood), and
;;;; txorphanage_sim (the orphanage against a naive model -- a list of
;;;; announcements in arrival order, trimmed by recomputing every peer's DoS
;;;; score -- compared in full at the end). The orphanage is
;;;; src/mempool/orphan.lisp; TxOrphanage::SanityCheck (txorphanage.cpp:
;;;; 687-760) is ported here, over the pool's exported records.
;;;;
;;;; The work set (AddChildrenToWorkSet / GetTxToReconsider /
;;;; HaveTxToReconsider) is driven and checked as Core drives it, the model
;;;; carrying each announcement's reconsider flag. A NodeId is a fixnum here
;;;; (the pool keys peers by EQ, and Core's int64 is folded by an
;;;; order-preserving shift).

(def-suite :fuzz-txorphan-tests :in :bitcoin-lisp-tests
  :description "Core fuzz/txorphan.cpp targets")

(in-suite :fuzz-txorphan-tests)

;;; --- Transactions --------------------------------------------------------------------

(defun orphan-fuzz-uint256 (n)
  "Core uint256{N} for a small N: the byte N first, the rest zero."
  (let ((v (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref v 0) n)
    v))

(defun orphan-fuzz-tx (inputs outputs &key (version 2) (lock-time 0))
  "A transaction from INPUTS, each (txid index sequence script-sig witness-item)
-- WITNESS-ITEM NIL for no witness, else the one element of a one-item stack --
and OUTPUTS, each a scriptPubKey."
  (let ((witness (map 'simple-vector (lambda (in) (and (fifth in) (list (fifth in)))) inputs)))
    (bl.ser:make-transaction
     :version version :lock-time lock-time
     :inputs (map 'simple-vector
                  (lambda (in)
                    (bl.ser:make-tx-in
                     :previous-output (bl.ser:make-outpoint :hash (first in) :index (second in))
                     :script-sig (or (fourth in) (make-array 0 :element-type '(unsigned-byte 8)))
                     :sequence (third in)))
                  inputs)
     :outputs (map 'simple-vector
                   (lambda (spk) (bl.ser:make-tx-out :value 0 :script-pubkey spk))
                   outputs)
     :witness (when (some #'identity witness) witness))))

(defun orphan-fuzz-zero-bytes (n)
  (make-array n :element-type '(unsigned-byte 8) :initial-element 0))

(defun orphan-fuzz-peer (fdp)
  "ConsumeIntegral<NodeId>(), folded into a fixnum by an order-preserving
shift (the pool compares peers by EQ, and a bignum is not EQ to itself)."
  (floor (consume-integral fdp :i64) 8))

(defun orphan-fuzz-announce (pool wtxid peer)
  "Core AddAnnouncer (txorphanage.cpp:343-372): a new announcement of an orphan
already present. The pool's ORPHAN-ADD of that orphan's transaction takes the
same path Core's AddTx takes for an existing orphan; what AddAnnouncer returns
-- whether the (wtxid, peer) emplacement happened -- is decided before the
call, as Core decides it before LimitOrphans runs."
  (let ((tx (bl.mp:orphan-tx pool wtxid)))
    (when (and tx (not (bl.mp:orphan-have-from-peer pool wtxid peer)))
      (bl.mp:orphan-add pool tx peer)
      t)))

(defun orphan-fuzz-latency-from-peer (pool peer)
  "Core LatencyScoreFromPeer."
  (let ((info (gethash peer (bl.mp:orphan-pool-peer-info pool))))
    (if info (bl.mp:orphan-peer-info-latency info) 0)))

(defun orphan-fuzz-block (txs)
  (bl.ser:make-bitcoin-block :transactions txs))

;;; --- TxOrphanage::SanityCheck (txorphanage.cpp:687-760) ------------------------------

(defun orphan-fuzz-sanity-check (pool)
  "Core TxOrphanageImpl::SanityCheck over the pool's records: every peer's
usage, latency score and announcement count re-summed from the announcements;
the parent index exactly the parents of the stored orphans; the cached
unique counts, usage and input scores re-derived; and the pool within its
limits."
  (let ((peers (make-hash-table :test 'eq))
        (parents (make-hash-table :test 'equalp))
        (unique 0) (announcements 0) (usage 0) (input-score 0))
    (maphash
     (lambda (wtxid entry)
       (let ((tx (bl.mp:orphan-entry-transaction entry)))
         (fuzz-assert (equalp wtxid (bl.ser:transaction-wtxid tx)))
         (fuzz-assert (equalp wtxid (bl.mp:orphan-entry-wtxid entry)))
         (fuzz-assert (= (bl.mp:orphan-entry-weight entry) (bl.ser:transaction-weight tx)))
         (fuzz-assert (= (bl.mp:orphan-entry-latency-score entry)
                         (1+ (floor (length (bl.ser:transaction-inputs tx)) 10))))
         (fuzz-assert (bl.mp:orphan-entry-announcements entry))
         (incf unique)
         (incf usage (bl.mp:orphan-entry-weight entry))
         (incf input-score (1- (bl.mp:orphan-entry-latency-score entry)))
         (loop for in across (bl.ser:transaction-inputs tx)
               do (pushnew wtxid (gethash (bl.ser:outpoint-hash (bl.ser:tx-in-previous-output in))
                                          parents)
                           :test #'equalp))
         ;; At most one announcement per wtxid in a work set, and exactly the
         ;; wtxids with one are the pool's reconsiderable set (:713-725).
         (let ((reconsider (count-if #'bl.mp:orphan-announcement-reconsider
                                     (bl.mp:orphan-entry-announcements entry))))
           (fuzz-assert (<= reconsider 1) "two work-set announcements of one orphan")
           (fuzz-assert (eq (= reconsider 1)
                            (and (gethash wtxid (bl.mp:orphan-pool-reconsiderable-wtxids pool)) t))
                        "the reconsiderable set disagrees with the announcements"))
         (let ((seen '()))
           (dolist (ann (bl.mp:orphan-entry-announcements entry))
             (let* ((peer (bl.mp:orphan-announcement-peer ann))
                    (acc (or (gethash peer peers) (setf (gethash peer peers) (list 0 0 0)))))
               (fuzz-assert (not (member peer seen)) "two announcements of one orphan by one peer")
               (push peer seen)
               (incf announcements)
               (incf (first acc) (bl.mp:orphan-entry-weight entry))
               (incf (second acc) (bl.mp:orphan-entry-latency-score entry))
               (incf (third acc)))))))
     (bl.mp:orphan-pool-by-wtxid pool))
    (maphash (lambda (wtxid flag)
               (declare (ignore flag))
               (fuzz-assert (gethash wtxid (bl.mp:orphan-pool-by-wtxid pool))
                            "a reconsiderable wtxid that is not stored"))
             (bl.mp:orphan-pool-reconsiderable-wtxids pool))
    ;; Per-peer records.
    (fuzz-assert (= (hash-table-count peers) (hash-table-count (bl.mp:orphan-pool-peer-info pool))))
    (maphash (lambda (peer info)
               (let ((acc (gethash peer peers)))
                 (fuzz-assert acc "a peer record with no announcement")
                 (when acc
                   (fuzz-assert (= (first acc) (bl.mp:orphan-peer-info-usage info)))
                   (fuzz-assert (= (second acc) (bl.mp:orphan-peer-info-latency info)))
                   (fuzz-assert (= (third acc) (bl.mp:orphan-peer-info-count info))))))
             (bl.mp:orphan-pool-peer-info pool))
    ;; The parent index names exactly the stored orphans' parents.
    (fuzz-assert (= (hash-table-count parents) (hash-table-count (bl.mp:orphan-pool-by-prev pool))))
    (maphash (lambda (ptxid wtxids)
               (let ((expect (gethash ptxid parents)))
                 (fuzz-assert (and expect
                                   (= (length expect) (length wtxids))
                                   (every (lambda (w) (member w expect :test #'equalp)) wtxids))
                              "the parent index is stale")))
             (bl.mp:orphan-pool-by-prev pool))
    ;; Cached aggregates.
    (fuzz-assert (= unique (bl.mp:orphan-pool-count pool)))
    (fuzz-assert (= announcements (bl.mp:orphan-pool-announcement-count pool)))
    (fuzz-assert (>= announcements unique))
    (fuzz-assert (<= announcements (* (hash-table-count peers) unique)))
    (fuzz-assert (= usage (bl.mp:orphan-pool-unique-usage pool)))
    (fuzz-assert (= input-score (bl.mp:orphan-pool-unique-input-score pool)))
    (let ((peer-usage 0) (peer-latency 0))
      (maphash (lambda (peer info)
                 (declare (ignore peer))
                 (incf peer-usage (bl.mp:orphan-peer-info-usage info))
                 (incf peer-latency (bl.mp:orphan-peer-info-latency info)))
               (bl.mp:orphan-pool-peer-info pool))
      (fuzz-assert (>= peer-usage usage))
      (fuzz-assert (>= peer-latency (+ input-score announcements))))
    ;; !NeedsTrim().
    (fuzz-assert (<= (fuzz-sabotage (bl.mp:orphan-total-latency-score pool))
                     (bl.mp:orphan-pool-max-global-latency-score pool))
                 "latency score ~D over the limit ~D" (bl.mp:orphan-total-latency-score pool)
                 (bl.mp:orphan-pool-max-global-latency-score pool))
    (fuzz-assert (<= (bl.mp:orphan-total-usage pool) (bl.mp:orphan-max-global-usage pool)))))

;;; --- txorphan (:38-223) ------------------------------------------------------------------

(defun orphan-fuzz-spends-p (child parent)
  "CHILD has an input spending an output of PARENT."
  (let ((ptxid (bl.ser:transaction-hash parent)))
    (some (lambda (in) (equalp (bl.ser:outpoint-hash (bl.ser:tx-in-previous-output in)) ptxid))
          (bl.ser:transaction-inputs child))))

(define-fuzz-target txorphan
    (buffer :core "txorphan.cpp:38-223" :iterations 2000 :max-len 1200)
  "Every orphanage entry point keeps its contract on random transactions and
peers: AddTx is false for a transaction already stored or already announced
by the peer, and true only under the weight limit; AddAnnouncer only adds to
a stored orphan; EraseTx answers whether it had the orphan and leaves
nothing behind; EraseForPeer and EraseForBlock remove what they name; the
children found for a peer spend the parent; usage never grows on a failed
add; GetTx agrees with HaveTx; and the pool passes SanityCheck."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (pool (progn (consume-uint256 fdp) (bl.mp:make-orphan-pool)))
         ;; Core's orphanage_rng, a FastRandomContext seeded from the input.
         (rng (sb-ext:seed-random-state 0))
         (outpoints (make-array 4 :adjustable t :fill-pointer 0))
         (potential-parent nil)
         (history (make-array 0 :adjustable t :fill-pointer 0)))
    (dotimes (i 4) (vector-push-extend (cons (orphan-fuzz-uint256 i) 0) outpoints))
    (limited-while ((and (< (length outpoints) 200000) (consume-bool fdp)) 1000)
      (let* ((tx (let* ((num-in (consume-integral-in-range fdp 1 (length outpoints)))
                        (num-out (consume-integral-in-range fdp 1 256))
                        (inputs (loop repeat num-in
                                      collect (let ((op (pick-value-in-array fdp outpoints)))
                                                (list (car op) (cdr op)
                                                      (consume-integral-in-range fdp 0 #xffffffff)))))
                        (new (orphan-fuzz-tx inputs (loop repeat num-out collect (orphan-fuzz-zero-bytes 0))))
                        (txid (bl.ser:transaction-hash new)))
                   (dotimes (i num-out) (vector-push-extend (cons txid i) outpoints))
                   new))
             (wtxid (bl.ser:transaction-wtxid tx)))
        (vector-push-extend tx history)
        (when potential-parent
          ;; Set up a future GetTxToReconsider (:91-94).
          (bl.mp:orphan-add-children-to-work-set pool potential-parent rng)
          (let ((peer (orphan-fuzz-peer fdp)))
            (dolist (child (bl.mp:orphan-children-from-peer pool potential-parent peer))
              (fuzz-assert (orphan-fuzz-spends-p child potential-parent)))))
        (limited-while ((consume-bool fdp) 1000)
          (let* ((peer (orphan-fuzz-peer fdp))
                 (total-start (bl.mp:orphan-total-usage pool))
                 (peer-start (bl.mp:orphan-usage-by-peer pool peer))
                 (weight (bl.ser:transaction-weight tx)))
            (call-one-of fdp
              ;; GetTxToReconsider (:115-121): what it hands out is stored.
              (let ((ref (bl.mp:orphan-get-tx-to-reconsider pool peer)))
                (when ref
                  (fuzz-assert (fuzz-sabotage (bl.mp:orphan-have pool (bl.ser:transaction-wtxid ref))))))
              ;; AddTx.
              (let* ((have (bl.mp:orphan-have pool wtxid))
                     (have-from-peer (bl.mp:orphan-have-from-peer pool wtxid peer))
                     (added (bl.mp:orphan-add pool tx peer)))
                (fuzz-assert (or (not have) (not added)))
                (fuzz-assert (or (not have-from-peer) (not added)))
                (if added
                    (fuzz-assert (<= weight 400000)) ; MAX_STANDARD_TX_WEIGHT
                    (progn
                      (when (> (bl.mp:orphan-usage-by-peer pool peer) peer-start)
                        (fuzz-assert (bl.mp:orphan-have-from-peer pool wtxid peer)))
                      (fuzz-assert (<= (fuzz-sabotage (bl.mp:orphan-total-usage pool)) total-start)
                                   "a failed AddTx grew the orphanage"))))
              ;; AddAnnouncer.
              (let* ((have (bl.mp:orphan-have pool wtxid))
                     (have-from-peer (bl.mp:orphan-have-from-peer pool wtxid peer))
                     (added (orphan-fuzz-announce pool wtxid peer)))
                (fuzz-assert (or have (not added)))
                (fuzz-assert (or (not have-from-peer) (not added)))
                (fuzz-assert (<= (bl.mp:orphan-total-usage pool) total-start)))
              ;; EraseTx.
              (let* ((have (bl.mp:orphan-have pool wtxid))
                     (have-from-peer (bl.mp:orphan-have-from-peer pool wtxid peer))
                     (peer-before (bl.mp:orphan-usage-by-peer pool peer)))
                (fuzz-assert (eq have (bl.mp:orphan-remove pool wtxid)))
                (when (and have (not have-from-peer))
                  (fuzz-assert (= (bl.mp:orphan-usage-by-peer pool peer) peer-before)))
                (fuzz-assert (and (not (bl.mp:orphan-have pool wtxid))
                                  (not (bl.mp:orphan-have-from-peer pool wtxid peer))
                                  (not (bl.mp:orphan-remove pool wtxid)))))
              ;; EraseForPeer.
              (progn
                (bl.mp:orphan-erase-for-peer pool peer)
                (fuzz-assert (not (bl.mp:orphan-have-from-peer pool wtxid peer)))
                (fuzz-assert (zerop (bl.mp:orphan-usage-by-peer pool peer))))
              ;; EraseForBlock.
              (let ((txs (loop repeat (consume-integral-in-range fdp 0 1000)
                               collect (pick-value-in-array fdp history))))
                (bl.mp:orphan-erase-for-block pool (orphan-fuzz-block txs))
                (dolist (removed txs)
                  (fuzz-assert (not (bl.mp:orphan-have pool (bl.ser:transaction-wtxid removed))))
                  (fuzz-assert (not (bl.mp:orphan-have-from-peer
                                     pool (bl.ser:transaction-wtxid removed) peer))))))))
        (when (or (null potential-parent) (consume-bool fdp))
          (setf potential-parent tx))
        (fuzz-assert (eq (bl.mp:orphan-have pool wtxid)
                         (and (bl.mp:orphan-tx pool wtxid) t)))))
    (orphan-fuzz-sanity-check pool)))

;;; --- txorphan_protected (:225-364) ------------------------------------------------------

(define-fuzz-target txorphan-protected
    (buffer :core "txorphan.cpp:225-364" :iterations 300 :max-len 1200)
  "A peer that never announces past its own share -- the per-peer weight
reservation and its slice of the global latency score -- never loses an
announcement to eviction, however the other peers flood the orphanage."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (num-peers (progn (consume-uint256 fdp) (consume-integral-in-range fdp 1 125)))
         (protected (loop repeat num-peers collect (consume-bool fdp)))
         (latency-limit (consume-integral-in-range fdp num-peers 6000))
         ;; Core draws the reservation from 1..4,040,000 and OP_RETURN payloads
         ;; from 0..100,000 bytes; both are a tenth of that here, which keeps
         ;; every ratio the target exercises and a transaction under 3 MB.
         (reservation (consume-integral-in-range fdp 1 404000))
         (pool (bl.mp:make-orphan-pool :max-global-latency-score latency-limit
                                       :reserved-peer-usage reservation))
         (honest-latency-limit (floor latency-limit num-peers))
         (outpoints (make-array 4 :adjustable t :fill-pointer 0))
         (protected-wtxids (make-hash-table :test 'equalp)))
    (dotimes (i 4) (vector-push-extend (cons (orphan-fuzz-uint256 i) 0) outpoints))
    (limited-while ((and (< (length outpoints) 400) (consume-bool fdp)) 1000)
      (let* ((tx (let* ((num-in (consume-integral-in-range fdp 1 (length outpoints)))
                        (num-out (consume-integral-in-range fdp 1 256))
                        (inputs (loop repeat num-in
                                      collect (let ((op (pick-value-in-array fdp outpoints)))
                                                (list (car op) (cdr op)
                                                      (consume-integral-in-range fdp 0 #xffffffff)))))
                        (outputs (loop repeat num-out
                                       collect (let ((payload (consume-integral-in-range fdp 0 10000)))
                                                 (if (plusp payload)
                                                     (concatenate '(vector (unsigned-byte 8))
                                                                  #(#x6a) ; OP_RETURN
                                                                  (bl.ser:script-push-data
                                                                   (orphan-fuzz-zero-bytes payload)))
                                                     (orphan-fuzz-zero-bytes 0)))))
                        (new (orphan-fuzz-tx inputs outputs))
                        (txid (bl.ser:transaction-hash new)))
                   (dotimes (i num-out) (vector-push-extend (cons txid i) outpoints))
                   new))
             (wtxid (bl.ser:transaction-wtxid tx))
             (weight (bl.ser:transaction-weight tx)))
        (limited-while ((plusp (remaining-bytes fdp)) (* 10 latency-limit))
          (let* ((peer (consume-integral-in-range fdp 0 (1- num-peers)))
                 (peer-protected (nth peer protected)))
            (flet ((over-share-p ()
                     (and peer-protected
                          (not (bl.mp:orphan-have-from-peer pool wtxid peer))
                          (or (> (+ (bl.mp:orphan-usage-by-peer pool peer) weight) reservation)
                              (> (+ (orphan-fuzz-latency-from-peer pool peer)
                                    (floor (length (bl.ser:transaction-inputs tx)) 10) 1)
                                 honest-latency-limit)))))
              (call-one-of fdp
                ;; AddTx.
                (unless (over-share-p)
                  (bl.mp:orphan-add pool tx peer)
                  (when (and peer-protected (bl.mp:orphan-have-from-peer pool wtxid peer))
                    (setf (gethash wtxid protected-wtxids) t)))
                ;; AddAnnouncer.
                (unless (over-share-p)
                  (orphan-fuzz-announce pool wtxid peer)
                  (when (and peer-protected (bl.mp:orphan-have-from-peer pool wtxid peer))
                    (setf (gethash wtxid protected-wtxids) t)))
                ;; EraseTx.
                (progn
                  (remhash wtxid protected-wtxids)
                  (bl.mp:orphan-remove pool wtxid)
                  (fuzz-assert (not (bl.mp:orphan-have pool wtxid))))
                ;; EraseForPeer.
                (unless peer-protected
                  (bl.mp:orphan-erase-for-peer pool peer)
                  (fuzz-assert (zerop (bl.mp:orphan-usage-by-peer pool peer)))
                  (fuzz-assert (zerop (orphan-fuzz-latency-from-peer pool peer)))
                  (fuzz-assert (zerop (bl.mp:orphan-announcements-from-peer pool peer))))))))))
    (orphan-fuzz-sanity-check pool)
    (maphash (lambda (wtxid v)
               (declare (ignore v))
               (fuzz-assert (fuzz-sabotage (bl.mp:orphan-have pool wtxid))
                            "a protected peer's orphan was evicted"))
             protected-wtxids)))

;;; --- txorphanage_sim (:366-826) ------------------------------------------------------------

(defun orphan-sim-rand-below (rng n)
  (txgraph-fuzz-rand-below rng n))

(defun orphan-sim-transactions (fdp rng)
  "Section 2 of txorphanage_sim (:385-460): sixteen transactions in a random
topological order with random dependencies, some duplicating the previous
one's txid under another wtxid, each wtxid distinct. Returns a vector."
  (let* ((n 16)
         (order (coerce (txgraph-fuzz-shuffle rng (loop for i below n collect i)) 'simple-vector))
         (deps (let ((all '()))
                 (loop for p from 0 below (1- n)
                       do (loop for c from (1+ p) below n do (push (cons c p) all)))
                 (subseq (txgraph-fuzz-shuffle rng (nreverse all))
                         0 (consume-integral-in-range fdp 0 (1- (* n 4))))))
         (txn (make-array n :initial-element nil))
         (specs (make-array n :initial-element nil)) ; t -> (inputs outputs) as built
         (wtxids '()))
    (dotimes (tt n)
      (let (inputs outputs)
        (if (and (plusp tt) (zerop (orphan-sim-rand-below rng 4)))
            ;; Duplicate the previous transaction: same txid, witness to vary.
            (destructuring-bind (ins outs) (aref specs (aref order (1- tt)))
              (setf inputs (mapcar #'copy-list ins) outputs outs))
            (progn
              (setf outputs (loop repeat (1+ (orphan-sim-rand-below rng (ash 1 (orphan-sim-rand-below rng 5))))
                                  collect (orphan-fuzz-zero-bytes (consume-integral-in-range fdp 20 34))))
              (dolist (d deps)
                (when (= (car d) tt)
                  (let* ((partx (aref txn (aref order (cdr d)))))
                    (assert (= (bl.ser:transaction-version partx) 1))
                    (push (list (bl.ser:transaction-hash partx)
                                (orphan-sim-rand-below rng (length (bl.ser:transaction-outputs partx)))
                                #xffffffff
                                (orphan-fuzz-zero-bytes (consume-integral-in-range fdp 16 200))
                                nil)
                          inputs))))
              (setf inputs (nreverse inputs))
              (unless inputs
                (setf inputs (list (list (insecure-rand-bytes rng 32) (orphan-sim-rand-below rng 16)
                                         #xffffffff
                                         (orphan-fuzz-zero-bytes (consume-integral-in-range fdp 16 200))
                                         nil))))))
        (flet ((build () (orphan-fuzz-tx inputs outputs :version 1 :lock-time #xffffffff)))
          (loop while (or (member (bl.ser:transaction-wtxid (build)) wtxids :test #'equalp)
                          (zerop (orphan-sim-rand-below rng 4)))
                do (let ((in (nth (orphan-sim-rand-below rng (length inputs)) inputs)))
                     (setf (fifth in)
                           (if (zerop (orphan-sim-rand-below rng 2))
                               (orphan-fuzz-zero-bytes (orphan-sim-rand-below rng 100))
                               nil))))
          (let ((tx (build)))
            (setf (aref txn (aref order tt)) tx
                  (aref specs (aref order tt)) (list inputs outputs))
            (push (bl.ser:transaction-wtxid tx) wtxids)
            (assert (< (bl.ser:transaction-weight tx) 400000))))))
    txn))

(defstruct (orphan-sim-ann (:constructor make-orphan-sim-ann (tx announcer)))
  "SimAnnouncement (:480-487). RECONSIDER is its work-set flag."
  tx announcer (reconsider nil))

(define-fuzz-target txorphanage-sim
    (buffer :core "txorphan.cpp:366-826" :iterations 2000 :max-len 600)
  "The orphanage against a list of announcements in arrival order: AddTx and
AddAnnouncer answer as the list predicts, the erasures remove what the list
removes, and after every command the orphanage has trimmed exactly what the
list trims -- the oldest announcement of the DoSiest peer (the higher NodeId
on a tie), under limits fixed for the whole trim -- until it is within its
latency and usage limits. At the end every inspector agrees with the list."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (rng (make-insecure-random-context (consume-integral fdp :u64)))
         (num-peers 16)
         (max-ann 64)
         (txn (orphan-sim-transactions fdp rng))
         (num-tx (length txn))
         (total-usage (reduce #'+ txn :key #'bl.ser:transaction-weight))
         (max-global-latency (consume-integral-in-range fdp num-peers max-ann))
         (reserved-usage (consume-integral-in-range fdp 1 total-usage))
         (real (bl.mp:make-orphan-pool :max-global-latency-score max-global-latency
                                       :reserved-peer-usage reserved-usage))
         (sim '()))                    ; announcements, oldest first
    (labels ((wtxid (i) (bl.ser:transaction-wtxid (aref txn i)))
             (have-tx (tx) (find tx sim :key #'orphan-sim-ann-tx))
             (find-ann (tx peer) (find-if (lambda (a) (and (= (orphan-sim-ann-tx a) tx)
                                                           (= (orphan-sim-ann-announcer a) peer)))
                                          sim))
             (count-peers () (length (remove-duplicates (mapcar #'orphan-sim-ann-announcer sim))))
             (weight (i) (bl.ser:transaction-weight (aref txn i)))
             (inputs (i) (length (bl.ser:transaction-inputs (aref txn i))))
             (dos-score (peer max-count max-usage)
               (let ((count 0) (usage 0))
                 (dolist (a sim)
                   (when (= (orphan-sim-ann-announcer a) peer)
                     (incf count (1+ (floor (inputs (orphan-sim-ann-tx a)) 10)))
                     (incf usage (weight (orphan-sim-ann-tx a)))))
                 (let ((c (bl.mp:make-feefrac count max-count))
                       (u (bl.mp:make-feefrac usage max-usage)))
                   (if (bl.mp:feefrac< c u) u c))))
             (spends-p (i outpoints)
               (some (lambda (in)
                       (let ((op (bl.ser:tx-in-previous-output in)))
                         (member (cons (bl.ser:outpoint-hash op) (bl.ser:outpoint-index op))
                                 outpoints :test #'equalp)))
                     (bl.ser:transaction-inputs (aref txn i)))))
      (limited-while ((plusp (remaining-bytes fdp)) 200)
        (let ((command (consume-integral-in-range fdp 0 15)))
          (loop
            (when (and (< (length sim) max-ann) (prog1 (zerop command) (decf command)))
              ;; AddTx.
              (let* ((code (consume-integral-in-range fdp 0 (1- (* num-tx num-peers))))
                     (tx (mod code num-tx)) (peer (floor code num-tx))
                     (added (bl.mp:orphan-add real (aref txn tx) peer)))
                (fuzz-assert (eq (and added t) (not (have-tx tx)))
                             "AddTx answered ~A with the orphan ~:[absent~;present~]" added (have-tx tx))
                (unless (find-ann tx peer)
                  (setf sim (append sim (list (make-orphan-sim-ann tx peer))))))
              (return))
            (when (and (< (length sim) max-ann) (prog1 (zerop command) (decf command)))
              ;; AddAnnouncer.
              (let* ((code (consume-integral-in-range fdp 0 (1- (* num-tx num-peers))))
                     (tx (mod code num-tx)) (peer (floor code num-tx))
                     (added (orphan-fuzz-announce real (wtxid tx) peer)))
                (fuzz-assert (eq (and added t) (and (not (find-ann tx peer)) (have-tx tx) t)))
                (when added
                  (setf sim (append sim (list (make-orphan-sim-ann tx peer))))))
              (return))
            (when (prog1 (zerop command) (decf command))
              ;; EraseTx.
              (let* ((tx (consume-integral-in-range fdp 0 (1- num-tx)))
                     (erased (bl.mp:orphan-remove real (wtxid tx))))
                (fuzz-assert (eq (and erased t) (and (have-tx tx) t)))
                (setf sim (remove tx sim :key #'orphan-sim-ann-tx)))
              (return))
            (when (prog1 (zerop command) (decf command))
              ;; EraseForPeer.
              (let ((peer (consume-integral-in-range fdp 0 (1- num-peers))))
                (bl.mp:orphan-erase-for-peer real peer)
                (setf sim (remove peer sim :key #'orphan-sim-ann-announcer)))
              (return))
            (when (prog1 (zerop command) (decf command))
              ;; EraseForBlock.
              (let* ((pattern (consume-integral-in-range fdp 0 (1- (ash 1 num-tx))))
                     (block-txs '()) (spent '()))
                (dotimes (i num-tx)
                  (when (logbitp i pattern)
                    (push (aref txn i) block-txs)
                    (loop for in across (bl.ser:transaction-inputs (aref txn i))
                          do (let ((op (bl.ser:tx-in-previous-output in)))
                               (push (cons (bl.ser:outpoint-hash op) (bl.ser:outpoint-index op)) spent)))))
                (bl.mp:orphan-erase-for-block real (orphan-fuzz-block (txgraph-fuzz-shuffle rng block-txs)))
                (setf sim (remove-if (lambda (a) (spends-p (orphan-sim-ann-tx a) spent)) sim)))
              (return))
            (when (prog1 (zerop command) (decf command))
              ;; AddChildrenToWorkSet (:624-662): every child of TX not yet in
              ;; a work set gets exactly one reconsider announcement.
              (let* ((tx (consume-integral-in-range fdp 0 (1- num-tx)))
                     (added (bl.mp:orphan-add-children-to-work-set
                             real (aref txn tx)
                             (sb-ext:seed-random-state (orphan-sim-rand-below rng (ash 1 32)))))
                     (children (loop for child below num-tx
                                     when (and (have-tx child)
                                               (not (find-if (lambda (a) (and (= (orphan-sim-ann-tx a) child)
                                                                              (orphan-sim-ann-reconsider a)))
                                                             sim))
                                               (orphan-fuzz-spends-p (aref txn child) (aref txn tx)))
                                       collect (wtxid child))))
                (loop for (w . peer) in added
                      do (let ((ann (find-if (lambda (a) (and (equalp (wtxid (orphan-sim-ann-tx a)) w)
                                                              (= (orphan-sim-ann-announcer a) peer)))
                                             sim)))
                           (fuzz-assert (member w children :test #'equalp)
                                        "AddChildrenToWorkSet marked a non-child or a child twice")
                           (fuzz-assert (and ann (not (orphan-sim-ann-reconsider ann))))
                           (when ann (setf (orphan-sim-ann-reconsider ann) t))
                           (setf children (remove w children :test #'equalp))))
                (fuzz-assert (null (fuzz-sabotage children))
                             "AddChildrenToWorkSet left ~D child~:P out" (length children)))
              (return))
            (when (prog1 (zerop command) (decf command))
              ;; GetTxToReconsider (:664-680).
              (let* ((peer (consume-integral-in-range fdp 0 (1- num-peers)))
                     (result (bl.mp:orphan-get-tx-to-reconsider real peer)))
                (if result
                    (let ((ann (find-if (lambda (a)
                                          (and (equalp (wtxid (orphan-sim-ann-tx a))
                                                       (bl.ser:transaction-wtxid result))
                                               (= (orphan-sim-ann-announcer a) peer)))
                                        sim)))
                      (fuzz-assert (and ann (orphan-sim-ann-reconsider ann)))
                      (when ann (setf (orphan-sim-ann-reconsider ann) nil)))
                    (fuzz-assert (not (find-if (lambda (a) (and (= (orphan-sim-ann-announcer a) peer)
                                                                (orphan-sim-ann-reconsider a)))
                                               sim)))))
              (return))))
        ;; Trim the model as LimitOrphans must have trimmed the real one.
        (let ((max-count (floor max-global-latency (max 1 (count-peers))))
              (max-mem reserved-usage))
          (loop
            (let* ((present (remove-duplicates (mapcar #'orphan-sim-ann-tx sim)))
                   (usage (reduce #'+ present :key #'weight))
                   (latency (+ (length sim) (reduce #'+ present :key (lambda (i) (floor (inputs i) 10)))))
                   (peers (count-peers)))
              (unless (or (> usage (* reserved-usage peers)) (> latency max-global-latency))
                (return))
              (let ((worst-score (bl.mp:make-feefrac 0 1)) (worst-peer nil))
                (dotimes (peer num-peers)
                  (let ((score (dos-score peer max-count max-mem)))
                    (when (bl.mp:feefrac>= score worst-score)
                      (setf worst-score score worst-peer peer))))
                (fuzz-assert (and worst-peer (bl.mp:feefrac>> worst-score (bl.mp:make-feefrac 1 1))))
                ;; Its oldest announcement, outside the work set first (:715-726).
                (let ((victim (or (find-if (lambda (a) (and (= (orphan-sim-ann-announcer a) worst-peer)
                                                            (not (orphan-sim-ann-reconsider a))))
                                           sim)
                                  (find worst-peer sim :key #'orphan-sim-ann-announcer))))
                  (fuzz-assert victim)
                  (unless victim (return))
                  (setf sim (remove victim sim)))))))
        (fuzz-assert (<= (bl.mp:orphan-total-latency-score real)
                         (bl.mp:orphan-pool-max-global-latency-score real)))
        (fuzz-assert (<= (bl.mp:orphan-total-usage real) (bl.mp:orphan-max-global-usage real))))
      ;; Section 6: the full comparison.
      (orphan-fuzz-sanity-check real)
      (let ((usage 0) (unique 0) (latency (length sim))
            (usage-by-peer (make-array num-peers :initial-element 0))
            (count-by-peer (make-array num-peers :initial-element 0)))
        (dotimes (tx num-tx)
          (let ((sim-have (have-tx tx)))
            (when sim-have
              (incf usage (weight tx))
              (incf latency (floor (inputs tx) 10))
              (incf unique))
            (fuzz-assert (eq (bl.mp:orphan-have real (wtxid tx)) (and sim-have t))
                         "orphan ~D: HaveTx ~A, model ~A" tx (bl.mp:orphan-have real (wtxid tx)) (and sim-have t))
            (let ((ref (bl.mp:orphan-tx real (wtxid tx))))
              (fuzz-assert (eq (and ref t) (and sim-have t)))
              (when (and ref sim-have)
                (fuzz-assert (equalp (bl.ser:transaction-wtxid ref) (wtxid tx)))))
            (let ((announcers (bl.mp:orphan-announcers real (wtxid tx))))
              (dotimes (peer num-peers)
                (let ((sim-ann (find-ann tx peer)))
                  (when sim-ann
                    (incf (aref usage-by-peer peer) (weight tx))
                    (incf (aref count-by-peer peer))
                    (fuzz-assert sim-have))
                  (when sim-have
                    (fuzz-assert (eq (and (member peer announcers) t) (and sim-ann t))))
                  (fuzz-assert (eq (bl.mp:orphan-have-from-peer real (wtxid tx) peer)
                                   (fuzz-sabotage (and sim-ann t)))
                               "orphan ~D peer ~D: HaveTxFromPeer disagrees with the model" tx peer)
                  ;; GetChildrenFromSamePeer: the peer's children of TX, newest first.
                  (let ((expect (reverse
                                 (loop for a in sim
                                       when (and (= (orphan-sim-ann-announcer a) peer)
                                                 (orphan-fuzz-spends-p (aref txn (orphan-sim-ann-tx a))
                                                                       (aref txn tx)))
                                         collect (wtxid (orphan-sim-ann-tx a)))))
                        (got (mapcar #'bl.ser:transaction-wtxid
                                     (bl.mp:orphan-children-from-peer real (aref txn tx) peer))))
                    (fuzz-assert (equalp expect got) "children of ~D from peer ~D out of order" tx peer)))))))
        (fuzz-assert (= usage (bl.mp:orphan-total-usage real)))
        (dotimes (peer num-peers)
          ;; HaveTxToReconsider (:802-805).
          (fuzz-assert (eq (bl.mp:orphan-have-tx-to-reconsider real peer)
                           (and (find-if (lambda (a) (and (= (orphan-sim-ann-announcer a) peer)
                                                          (orphan-sim-ann-reconsider a)))
                                         sim)
                                t)))
          (fuzz-assert (= (aref usage-by-peer peer) (bl.mp:orphan-usage-by-peer real peer)))
          (fuzz-assert (= (aref count-by-peer peer) (bl.mp:orphan-announcements-from-peer real peer))))
        (fuzz-assert (= (length sim) (bl.mp:orphan-pool-announcement-count real)))
        (fuzz-assert (= unique (bl.mp:orphan-pool-count real)))
        (fuzz-assert (= max-global-latency (bl.mp:orphan-pool-max-global-latency-score real)))
        (fuzz-assert (= reserved-usage (bl.mp:orphan-pool-reserved-peer-usage real)))
        (fuzz-assert (= (floor max-global-latency (max 1 (count-peers)))
                        (bl.mp:orphan-max-peer-latency-score real)))
        (fuzz-assert (= (* reserved-usage (max 1 (count-peers))) (bl.mp:orphan-max-global-usage real)))
        (fuzz-assert (= latency (bl.mp:orphan-total-latency-score real)))))))

(test txorphanage-sim-pinned-buffers
  "The buffers the txorphanage_sim port found failing, replayed. The first
(the target's third draw) made AddTx answer `not new' for a new orphan its
own trim evicted (txorphanage.cpp:305-341 returns brand_new regardless;
fixed in `Mempool: AddTx reports a new orphan as new, whatever its own trim
evicts')."
  (is (null (replay-fuzz-target
             'txorphanage-sim
             "82e5fb4462c6ade67328fcc437a9ce892f5ca8e9f72546848227cf0276cc0ecf167d446cba63917d72d5833dbed2ba81884c0f590d865fecfd31c5e4faf526457557d17de42653f96e0707531d892df7d70ae49cb2fffa7b9395f2de699a35c65ff8a04604cb395cc8a21f53b3a9ce89f55e28ea1a40d6e4daf057fbbe1e9e273d8ed0f437176e89d503e0987af2a46d308baee816cf18213023e73a226ee5e515759b"))))
