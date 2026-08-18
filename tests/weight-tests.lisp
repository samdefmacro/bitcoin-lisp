(in-package #:bitcoin-lisp.tests)

(in-suite :weight-tests)

;;;; Transaction Weight Tests

(defun make-legacy-test-tx (&key (inputs 1) (outputs 1) (script-sig-size 10) (script-pubkey-size 25))
  "Create a legacy test transaction (no witness)."
  (let ((tx-inputs (loop for i below inputs
                         collect (bitcoin-lisp.serialization:make-tx-in
                                  :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                    :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                      :initial-element (1+ i))
                                                    :index 0)
                                  :script-sig (make-array script-sig-size :element-type '(unsigned-byte 8)
                                                          :initial-element #x00)
                                  :sequence #xFFFFFFFF)))
        (tx-outputs (loop for i below outputs
                          collect (bitcoin-lisp.serialization:make-tx-out
                                   :value 50000000
                                   :script-pubkey (make-array script-pubkey-size :element-type '(unsigned-byte 8)
                                                              :initial-element #x76)))))
    (bitcoin-lisp.serialization:make-transaction
     :version 1
     :inputs (coerce tx-inputs 'simple-vector)
     :outputs (coerce tx-outputs 'simple-vector)
     :lock-time 0)))

(defun make-witness-test-tx (&key (inputs 1) (outputs 1) (script-sig-size 0)
                               (script-pubkey-size 25) (witness-item-size 72))
  "Create a witness test transaction."
  (let ((tx-inputs (loop for i below inputs
                         collect (bitcoin-lisp.serialization:make-tx-in
                                  :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                    :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                      :initial-element (1+ i))
                                                    :index 0)
                                  :script-sig (make-array script-sig-size :element-type '(unsigned-byte 8)
                                                          :initial-element #x00)
                                  :sequence #xFFFFFFFF)))
        (tx-outputs (loop for i below outputs
                          collect (bitcoin-lisp.serialization:make-tx-out
                                   :value 50000000
                                   :script-pubkey (make-array script-pubkey-size :element-type '(unsigned-byte 8)
                                                              :initial-element #x76))))
        (witness (loop for i below inputs
                       collect (list (make-array witness-item-size :element-type '(unsigned-byte 8)
                                                                   :initial-element #xAB)))))
    (bitcoin-lisp.serialization:make-transaction
     :version 1
     :inputs (coerce tx-inputs 'simple-vector)
     :outputs (coerce tx-outputs 'simple-vector)
     :lock-time 0
     :witness (coerce witness 'simple-vector))))

;;; Task 4.1: Unit tests for transaction-weight

(test legacy-tx-weight-is-4x-size
  "Legacy transaction weight = serialized_size * 4."
  (let* ((tx (make-legacy-test-tx))
         (size (length (bitcoin-lisp.serialization:serialize-transaction tx)))
         (weight (bitcoin-lisp.serialization:transaction-weight tx)))
    (is (= weight (* 4 size)))))

(test witness-tx-weight-formula
  "Witness transaction weight = 3 * base_size + total_size."
  (let* ((tx (make-witness-test-tx))
         (base-size (length (bitcoin-lisp.serialization:serialize-transaction tx)))
         (total-size (length (bitcoin-lisp.serialization:serialize-witness-transaction tx)))
         (weight (bitcoin-lisp.serialization:transaction-weight tx)))
    (is (= weight (+ (* 3 base-size) total-size)))))

(test weight-vsize-relationship
  "Weight = vsize * 4 for legacy; weight <= vsize * 4 for witness (due to ceiling)."
  (let* ((legacy-tx (make-legacy-test-tx))
         (legacy-weight (bitcoin-lisp.serialization:transaction-weight legacy-tx))
         (legacy-vsize (bitcoin-lisp.serialization:transaction-vsize legacy-tx)))
    (is (= legacy-weight (* 4 legacy-vsize))))
  (let* ((witness-tx (make-witness-test-tx))
         (witness-weight (bitcoin-lisp.serialization:transaction-weight witness-tx))
         (witness-vsize (bitcoin-lisp.serialization:transaction-vsize witness-tx)))
    ;; vsize = ceiling(weight / 4), so weight <= vsize * 4
    (is (<= witness-weight (* 4 witness-vsize)))
    ;; and vsize = ceiling(weight/4)
    (is (= witness-vsize (ceiling witness-weight 4)))))

(test witness-discount
  "Witness data should make weight less than 4x total_size."
  (let* ((tx (make-witness-test-tx))
         (total-size (length (bitcoin-lisp.serialization:serialize-witness-transaction tx)))
         (weight (bitcoin-lisp.serialization:transaction-weight tx)))
    ;; Weight should be less than 4 * total_size because witness gets discount
    (is (< weight (* 4 total-size)))))

;;; Task 4.2: Unit test for calculate-block-weight

(test calculate-block-weight-counts-the-block-prefix
  "Core weighs the whole BLOCK, not the transaction list (GetBlockWeight,
consensus/validation.h:136-139): the serialized block is
`header(80) || CompactSize(n) || txs\', and expanding 3*size_nowit + size_wit
over that shape leaves the prefix counted FOUR times.

    weight = 4 * (80 + compact-size-length(n)) + SUM(transaction-weight)

The predecessor of this test asserted weight == SUM alone, which is precisely
why the missing prefix survived: the bug was not merely untested, it was
pinned in place by a test that agreed with it."
  (let* ((tx1 (make-legacy-test-tx :inputs 1 :outputs 1))
         (tx2 (make-legacy-test-tx :inputs 2 :outputs 2))
         (tx3 (make-witness-test-tx :inputs 1 :outputs 1))
         (transactions (list tx1 tx2 tx3))
         (sum (+ (bitcoin-lisp.serialization:transaction-weight tx1)
                 (bitcoin-lisp.serialization:transaction-weight tx2)
                 (bitcoin-lisp.serialization:transaction-weight tx3)))
         (actual (bitcoin-lisp.validation:calculate-block-weight transactions)))
    (is (= (+ (* 4 (+ 80 1)) sum) actual)
        "3 transactions: prefix is 4*(80+1) = 324 weight units")
    (is (> actual sum)
        "and the block must always outweigh its transactions -- the direction
         matters, because under-counting is what let a block Core rejects as
         bad-blk-weight connect here and split the chain")))

(test block-weight-prefix-follows-the-compact-size-boundary
  "The varint widens from 1 byte to 3 at 253 transactions, so the prefix goes
324 -> 332. Tested because the two magnitudes are the whole content of the bug
and a fix that hard-coded 324 would look right on every small block."
  (let* ((tx (make-legacy-test-tx :inputs 1 :outputs 1))
         (w (bitcoin-lisp.serialization:transaction-weight tx)))
    (flet ((prefix (n)
             (- (bitcoin-lisp.validation:calculate-block-weight
                 (make-list n :initial-element tx))
                (* n w))))
      (is (= 324 (prefix 252)) "252 txs: 1-byte varint")
      (is (= 332 (prefix 253)) "253 txs: varint widens to 3 bytes"))))

(test empty-block-weight-is-the-prefix-alone
  "An empty transaction list still serializes as header + a zero varint, so its
weight is 4*(80+1) = 324, not 0. The old test asserted 0."
  (is (= 324 (bitcoin-lisp.validation:calculate-block-weight '()))))

;;; Task 4.3: Integration tests for block weight limit

(test block-within-weight-limit-accepted
  "Block within +max-block-weight+ should pass weight validation."
  (let* ((tx (make-legacy-test-tx))
         (weight (bitcoin-lisp.validation:calculate-block-weight (list tx))))
    ;; A single small tx is well under 4M weight units
    (is (< weight bitcoin-lisp.validation:+max-block-weight+))))

(test max-block-weight-constant
  "Max block weight constant is 4,000,000."
  (is (= 4000000 bitcoin-lisp.validation:+max-block-weight+)))
