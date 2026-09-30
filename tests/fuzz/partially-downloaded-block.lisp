(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/partially_downloaded_block.cpp at the pin
;;;; (d3056bc149): a block from the buffer, its compact form, some of its
;;;; transactions in the mempool, and the reconstruction -- InitData, then
;;;; FillBlock with the transactions still missing (some withheld).
;;;;
;;;; InitData is RECONSTRUCT-COMPACT-BLOCK (src/networking/protocol.lisp).
;;;; FillBlock has no function of its own here: the blocktxn handler fills the
;;;; missing slots in order, refuses a count that does not match
;;;; (READ_STATUS_INVALID) and runs the mutation check (READ_STATUS_FAILED),
;;;; and the target does the same with Core's mock standing in for the
;;;; mutation check. A reconstruction InitData refuses is not filled (Core
;;;; would still call FillBlock, which answers INVALID for a refused header).
;;;; The node keeps no extra-transaction pool (-blockreconstructionextratxn is
;;;; accepted and not implemented), so Core's add-to-extra-txn choice is read
;;;; and has no effect.

(def-suite :fuzz-partially-downloaded-block-tests :in :bitcoin-lisp-tests
  :description "Core fuzz/partially_downloaded_block.cpp target")

(in-suite :fuzz-partially-downloaded-block-tests)

(defun pdb-fuzz-corpus (fdp)
  "A serialized block of a few small transactions at the front, sometimes one
of them repeated, and random bytes behind it for the choices."
  (let* ((n (consume-integral-in-range fdp 1 8))
         (txs (loop repeat n
                    collect (loop repeat 8
                                  for tx = (consume-transaction fdp :max-num-in 2 :max-num-out 2)
                                  when (plusp (length (bl.ser:transaction-inputs tx))) return tx
                                  finally (return tx))))
         (txs (if (and (> n 2) (consume-bool fdp))
                  (append txs (list (nth (consume-integral-in-range fdp 1 (1- n)) txs)))
                  txs))
         (block (bl.ser:make-bitcoin-block
                 :header (bl.ser:make-block-header
                          :version (consume-integral fdp :i32)
                          :prev-block (consume-uint256 fdp) :merkle-root (consume-uint256 fdp)
                          :timestamp (consume-integral fdp :u32)
                          :bits (consume-integral-in-range fdp 1 #xffffffff 32)
                          :nonce (consume-integral fdp :u32))
                 :transactions txs)))
    ;; A tail of its own for the integral reads, which come off the END: without
    ;; it they would eat into the block.
    (concatenate '(vector (unsigned-byte 8))
                 (fdp-random-length-bytes (bl.ser:serialize-witness-block block))
                 (insecure-rand-bytes (make-insecure-random-context (consume-integral fdp :u64)) 256))))

(define-fuzz-target partially-downloaded-block
    (buffer :core "partially_downloaded_block.cpp:46-134" :iterations 1500 :max-len 1200
            :corpus (lambda (fdp) (pdb-fuzz-corpus fdp)))
  "Whatever InitData marks available was put in the mempool; a reconstruction
that is filled with every missing transaction and passes the mutation check
is the original block, transaction for transaction; one that withheld a
missing transaction is never OK; and FAILED comes only from the mutation
check."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (block (progn (consume-integral fdp :i64)
                       (consume-deserializable
                        fdp (lambda (bytes) (bl.ser:br-read-bitcoin-block
                                             (bl.ser:make-byte-reader-from bytes))))))
         (txs (and block (coerce (bl.ser:bitcoin-block-transactions block) 'simple-vector))))
    (when (or (null block) (zerop (length txs)) (>= (length txs) #xffff))
      (fuzz-reject))
    (let* ((cmpct (bl.ser:build-compact-block block :nonce (consume-integral fdp :u64)))
           (pool (bl.mp:make-mempool))
           (available (list 0)))
      (loop for i from 1 below (length txs)
            do (let ((tx (svref txs i))
                     (to-extra (consume-bool fdp))
                     (to-mempool (consume-bool fdp)))
                 (declare (ignore to-extra))
                 (when (and to-mempool (not (bl.mp:mempool-has pool (bl.ser:transaction-hash tx))))
                   (try-add-to-mempool pool (fuzz-mempool-entry (consume-tx-mempool-entry fdp tx #xffffffff)))
                   (push i available))))
      (multiple-value-bind (rblock missing-indexes partial)
          (%cb-reconstruct cmpct pool t)
        (let* ((init-ok (not (member missing-indexes '(:collision :malformed))))
               (slot-available (lambda (i)
                                 (and init-ok (or rblock (and partial (aref partial i)) nil))))
               (missing '())
               (skipped-missing nil))
          (dotimes (i (length txs))
            (when init-ok
              (fuzz-assert (or (not (funcall slot-available i)) (member i available))
                           "slot ~D came from nowhere we put it" i))
            (let ((skip (consume-bool fdp)))
              (unless (funcall slot-available i)
                (if skip
                    (setf skipped-missing t)
                    (push (svref txs i) missing)))))
          (setf missing (nreverse missing))
          (let ((segwit-active (consume-bool fdp))
                (fail-mutated (consume-bool fdp)))
            (declare (ignore segwit-active))
            (when init-ok
              ;; FillBlock as the blocktxn handler performs it.
              (let* ((filled (copy-seq (or partial (coerce (bl.ser:bitcoin-block-transactions rblock)
                                                            'simple-vector))))
                     (status (cond ((/= (length missing) (count nil filled)) :invalid)
                                   (fail-mutated :failed)
                                   (t :ok))))
                (when (eq status :ok)
                  (let ((queue missing))
                    (dotimes (i (length filled))
                      (unless (aref filled i) (setf (aref filled i) (pop queue))))))
                (case status
                  (:ok
                   (fuzz-assert (not skipped-missing))
                   (fuzz-assert (not fail-mutated))
                   (fuzz-assert (equalp (bl.ser:block-header-hash (bl.ser:bitcoin-block-header block))
                                        (bl.ser:block-header-hash (bl.ser:compact-block-header cmpct))))
                   (fuzz-assert (every (lambda (a b) (equalp (bl.ser:transaction-wtxid a)
                                                             (bl.ser:transaction-wtxid b)))
                                       (fuzz-sabotage-txs filled) txs)
                                "the reconstructed block is not the original"))
                  (:failed (fuzz-assert fail-mutated)))))))))))

(defun fuzz-sabotage-txs (txs)
  "TXS, or -- in the positive-control run -- TXS in reverse."
  (if (and (eq *fuzz-sabotage* :assert) (> (length txs) 1)) (reverse txs) txs))
