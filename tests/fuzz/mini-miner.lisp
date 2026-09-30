(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/mini_miner.cpp at the pin (d3056bc149): a pool built
;;;; from a queue of 100 coins (each transaction spending the queue's head,
;;;; some of its outputs returned to it), outpoints of those transactions and
;;;; of nowhere, and the MiniMiner's answers at a random target feerate --
;;;; CalculateBumpFees (one answer per outpoint, none negative) and
;;;; CalculateTotalBumpFees (never more than their sum). The MiniMiner is the
;;;; wallet's (src/wallet/mini-miner.lisp).
;;;;
;;;; Beyond Core's assertions the port checks both answers against a model of
;;;; node/mini_miner.cpp written from scratch over the pool: the cluster of
;;;; the requested transactions minus what spending an already-spent outpoint
;;;; would replace, mined ancestor package by ancestor package, best
;;;; min(ancestor, own) FeeFrac first (the smaller size, then the txid, on a
;;;; tie), recomputing every ancestor set after each package, until the next
;;;; package pays less than the target; then each requested transaction left
;;;; out bumps by the larger of its ancestor-set and its own shortfall, and the
;;;; total by the shortfall of the union of their remaining ancestors.

(def-suite :fuzz-mini-miner-tests :in :bitcoin-lisp-tests
  :description "Core fuzz/mini_miner.cpp target")

(in-suite :fuzz-mini-miner-tests)

(defun mini-miner-fuzz-fee (target size)
  "CFeeRate(TARGET sat/kvB).GetFee(SIZE): rounded up (policy/feerate.cpp:20-27)."
  (ceiling (* target size) 1000))

(defun mini-miner-fuzz-txid< (a b)
  (loop for x across a for y across b
        do (cond ((< x y) (return t)) ((> x y) (return nil)))
        finally (return nil)))

(defun mini-miner-model (pool outpoints target)
  "(values bump-fees total) for OUTPOINTS (a list of (txid . index)) at TARGET
sat/kvB, from node/mini_miner.cpp's rules recomputed over POOL. BUMP-FEES is
an alist of (outpoint . fee)."
  (let ((answers '())
        (requested (make-hash-table :test 'equalp))   ; txid -> outpoints
        (replaced (make-hash-table :test 'equalp)))
    ;; Constructor (:24-131).
    (dolist (op outpoints)
      (if (not (bl.mp:mempool-has pool (car op)))
          (push (cons op 0) answers)
          (progn
            (push op (gethash (car op) requested))
            (let ((spender (bl.mp:mempool-spending-tx pool (car op) (cdr op))))
              (when spender
                (setf (gethash spender replaced) t)
                (maphash (lambda (d v) (declare (ignore v)) (setf (gethash d replaced) t))
                         (bl.mp:mempool-descendants pool spender)))))))
    (let ((entries (make-hash-table :test 'equalp)))  ; txid -> (vsize fee tx)
      ;; The cluster of the requested transactions.
      (let ((todo (loop for k being the hash-keys of requested collect k))
            (seen (make-hash-table :test 'equalp)))
        (loop while todo
              do (let ((txid (pop todo)))
                   (unless (gethash txid seen)
                     (setf (gethash txid seen) t)
                     (let ((e (bl.mp:mempool-get pool txid)))
                       (loop for k being the hash-keys of (bl.mp:mempool-entry-parents e) do (push k todo))
                       (loop for k being the hash-keys of (bl.mp:mempool-entry-children e) do (push k todo))))))
        (loop for txid being the hash-keys of seen
              do (if (gethash txid replaced)
                     (let ((ops (gethash txid requested)))
                       (dolist (op ops) (push (cons op 0) answers))
                       (remhash txid requested))
                     (let ((e (bl.mp:mempool-get pool txid)))
                       (setf (gethash txid entries)
                             (list (bl.mp:mempool-entry-vsize e) (bl.mp:mempool-entry-modified-fee e)
                                   (bl.mp:mempool-entry-transaction e)))))))
      (labels ((ancestors (txid)
                 ;; TXID's ancestors among the entries still out of the block.
                 (let ((set (make-hash-table :test 'equalp)) (todo (list txid)))
                   (loop while todo
                         do (let ((x (pop todo)))
                              (unless (gethash x set)
                                (setf (gethash x set) t)
                                (loop for in across (bl.ser:transaction-inputs (third (gethash x entries)))
                                      do (let ((p (bl.ser:outpoint-hash (bl.ser:tx-in-previous-output in))))
                                           (when (gethash p entries) (push p todo)))))))
                   set))
               (sums (set)
                 (let ((size 0) (fee 0))
                   (loop for k being the hash-keys of set
                         do (incf size (first (gethash k entries)))
                            (incf fee (second (gethash k entries))))
                   (values size fee)))
               (score (txid)
                 ;; min(ancestor FeeFrac, own FeeFrac), FeeFrac's full order.
                 (multiple-value-bind (asize afee) (sums (ancestors txid))
                   (let ((anc (bl.mp:make-feefrac afee asize))
                         (own (bl.mp:make-feefrac (second (gethash txid entries))
                                                  (first (gethash txid entries)))))
                     (if (bl.mp:feefrac< own anc) own anc)))))
        ;; BuildMockTemplate (:244-303).
        (let ((in-block (make-hash-table :test 'equalp)))
          (loop while (plusp (hash-table-count entries))
                do (let ((best nil) (best-score nil))
                     (loop for txid being the hash-keys of entries
                           do (let ((sc (score txid)))
                                (when (or (null best)
                                          (bl.mp:feefrac> sc best-score)
                                          (and (bl.mp:feefrac= sc best-score)
                                               (mini-miner-fuzz-txid< txid best)))
                                  (setf best txid best-score sc))))
                     (let ((anc (ancestors best)))
                       (multiple-value-bind (size fee) (sums anc)
                         (when (< fee (mini-miner-fuzz-fee target size)) (return))
                         (loop for k being the hash-keys of anc
                               do (setf (gethash k in-block) t)
                                  (remhash k entries))))))
          ;; CalculateBumpFees (:305-387).
          (let ((unmined '()))
            (maphash (lambda (txid ops)
                       (if (gethash txid in-block)
                           (dolist (op ops) (push (cons op 0) answers))
                           (progn
                             (push txid unmined)
                             (multiple-value-bind (asize afee) (sums (ancestors txid))
                               (let ((bump (max (- (mini-miner-fuzz-fee target asize) afee)
                                                (- (mini-miner-fuzz-fee target (first (gethash txid entries)))
                                                   (second (gethash txid entries))))))
                                 (dolist (op ops) (push (cons op bump) answers)))))))
                     requested)
            ;; CalculateTotalBumpFees (:389-428).
            (let ((union (make-hash-table :test 'equalp)))
              (dolist (txid unmined)
                (maphash (lambda (k v) (setf (gethash k union) v)) (ancestors txid)))
              (multiple-value-bind (size fee) (sums union)
                (values answers (- (mini-miner-fuzz-fee target size) fee))))))))))

(defun mini-miner-fuzz-corpus (fdp)
  "The choices at the END of the buffer: how many coins each transaction
spends and how many outputs it makes, a fee, which outputs go back to the
queue and which outpoints are asked about -- small numbers, so a draw builds
a pool of many chained transactions -- then the target feerate."
  (let ((tail (make-fdp-tail))
        (coins 100))
    (fdp-tail-integral tail (consume-integral fdp :i64) (- (ash 1 63)) (1- (ash 1 63)))
    (loop repeat (consume-integral-in-range fdp 1 30)
          while (plusp coins)
          do (let ((num-in (consume-integral-in-range fdp 1 (min 3 coins)))
                   (num-out (consume-integral-in-range fdp 1 4)))
               (fdp-tail-integral tail num-in 1 coins)
               (fdp-tail-integral tail num-out 1 50)
               (decf coins num-in)
               (fdp-tail-integral tail (consume-integral-in-range fdp 0 100000) 0 (floor bl.val:+max-money+ 100000))
               (dotimes (n num-out)
                 (let ((back (consume-bool fdp)))
                   (fdp-tail-bool tail back)
                   (when back (incf coins))))
               (fdp-tail-bool tail t)
               (fdp-tail-integral tail (consume-integral-in-range fdp 0 num-out) 0 num-out)))
    (fdp-tail-integral tail (consume-integral-in-range fdp 0 200000) 0 (floor bl.val:+max-money+ 1000))
    (concatenate '(vector (unsigned-byte 8))
                 (insecure-rand-bytes (make-insecure-random-context (consume-integral fdp :u64)) 64)
                 (fdp-tail-bytes tail))))

(define-fuzz-target mini-miner
    (buffer :core "mini_miner.cpp:41-117" :iterations 150 :max-len 1500
            :corpus (lambda (fdp) (mini-miner-fuzz-corpus fdp)))
  "Every outpoint gets a bump fee and none is negative; the combined bump
never exceeds their sum; and both are what node/mini_miner.cpp's rules give,
recomputed from scratch over the pool."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (pool (progn (consume-integral fdp :i64) (bl.mp:make-mempool)))
         (zero (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
         (coins (loop for i below 100 collect (cons zero i)))
         (outpoints '()))
    (limited-while (coins 100)
      (let* ((num-in (consume-integral-in-range fdp 1 (length coins)))
             (num-out (consume-integral-in-range fdp 1 50))
             (inputs (loop repeat num-in collect (pop coins)))
             (tx (bl.ser:make-transaction
                  :version 2 :lock-time 0
                  :inputs (map 'simple-vector
                               (lambda (op)
                                 (bl.ser:make-tx-in :previous-output (bl.ser:make-outpoint :hash (car op) :index (cdr op))
                                                    :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                                                    :sequence #xffffffff))
                               inputs)
                  :outputs (coerce (loop repeat num-out
                                         collect (bl.ser:make-tx-out :value 100 :script-pubkey +p2wsh-op-true+))
                                   'simple-vector)))
             (txid (bl.ser:transaction-hash tx))
             (fee (consume-money fdp (floor bl.val:+max-money+ 100000))))
        ;; TestMemPoolEntryHelper's entry: height 1, sigop cost 4.
        (try-add-to-mempool pool (bl.mp:make-entry-from-tx tx fee 1 :sigops 4))
        (dotimes (n num-out)
          (when (consume-bool fdp) (setf coins (append coins (list (cons txid n))))))
        (if (consume-bool fdp)
            (push (cons txid (consume-integral-in-range fdp 0 num-out)) outpoints)
            (let ((bytes (consume-random-length-byte-vector fdp)))
              (when (>= (length bytes) 36)
                (let ((op (cons (subseq bytes 0 32)
                                (logior (aref bytes 32) (ash (aref bytes 33) 8)
                                        (ash (aref bytes 34) 16) (ash (aref bytes 35) 24)))))
                  (unless (member op outpoints :test #'equalp)
                    (push op outpoints))))))))
    (setf outpoints (nreverse outpoints))
    (let* ((target (consume-money fdp (floor bl.val:+max-money+ 1000)))
           (bumps (bl.wallet:mini-miner-bump-fees pool outpoints target))
           (total (bl.wallet:mini-miner-total-bump-fee pool outpoints target))
           (sum 0))
      (multiple-value-bind (model-bumps model-total) (mini-miner-model pool outpoints target)
        (dolist (op outpoints)
          (let ((bump (gethash (bl.ser:outpoint-key (car op) (cdr op)) bumps)))
            (fuzz-assert bump "no bump fee for an outpoint")
            (when bump
              (fuzz-assert (>= bump 0))
              (incf sum bump)
              (fuzz-assert (= (fuzz-sabotage bump) (cdr (assoc op model-bumps :test #'equalp)))
                           "bump fee ~D, node/mini_miner.cpp's rules give ~D" bump
                           (cdr (assoc op model-bumps :test #'equalp))))))
        (fuzz-assert total "CalculateTotalBumpFees had no answer")
        (when total
          (fuzz-assert (>= sum total))
          (fuzz-assert (= total model-total) "total bump ~D, the rules give ~D" total model-total))))))

(test mini-miner-orders-equal-feerate-packages-by-feefrac-then-txid
  "Core's AncestorFeerateComparator (node/mini_miner.cpp:180-197) scores an
entry std::min(ancestor FeeFrac, own FeeFrac) and orders two scores by
FeeFrac's FULL order, whose tie between equal ratios goes to the smaller size;
only equal FeeFracs fall back to the txid. E (own 100/10, ancestors 200/20)
scores 200/20 -- at an equal ratio the larger size is the smaller FeeFrac --
and X (150/15 both ways) scores 150/15, so X comes first although E's txid is
lower. The port compared bare ratios, took E's own 100/10, called the two
equal and put E first."
  (flet ((entry (txid-byte fee vsize anc-fee anc-vsize)
           (funcall 'bl.wallet::make-mm-entry
                    :txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element txid-byte)
                    :fee fee :vsize vsize :anc-fee anc-fee :anc-vsize anc-vsize))
         (better-p (a b) (funcall 'bl.wallet::%mm-better-p a b)))
    (let ((e (entry 0 100 10 200 20))
          (x (entry #xff 150 15 150 15)))
      (is-true (better-p x e) "X (150/15) must come before E (score 200/20)")
      (is-false (better-p e x))
      ;; Control: equal FeeFracs fall back to the txid.
      (is-true (better-p e (entry #xff 200 20 200 20)) "equal scores: the lower txid first"))))
