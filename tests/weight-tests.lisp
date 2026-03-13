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
     :inputs tx-inputs
     :outputs tx-outputs
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
     :inputs tx-inputs
     :outputs tx-outputs
     :lock-time 0
     :witness witness)))

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

(test calculate-block-weight-sums-tx-weights
  "Block weight is sum of all transaction weights."
  (let* ((tx1 (make-legacy-test-tx :inputs 1 :outputs 1))
         (tx2 (make-legacy-test-tx :inputs 2 :outputs 2))
         (tx3 (make-witness-test-tx :inputs 1 :outputs 1))
         (transactions (list tx1 tx2 tx3))
         (expected (+ (bitcoin-lisp.serialization:transaction-weight tx1)
                      (bitcoin-lisp.serialization:transaction-weight tx2)
                      (bitcoin-lisp.serialization:transaction-weight tx3)))
         (actual (bitcoin-lisp.validation:calculate-block-weight transactions)))
    (is (= expected actual))))

(test empty-block-weight-is-zero
  "Block with no transactions has zero weight."
  (is (= 0 (bitcoin-lisp.validation:calculate-block-weight '()))))

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
