(in-package #:bitcoin-lisp.tests)

(in-suite :difficulty-tests)

;;;; Helper: build a chain of mock block-index-entries

(defun make-mock-header (&key (version 1) (prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
                              (merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
                              (timestamp 0) (bits #x1d00ffff) (nonce 0))
  "Create a mock block header for testing."
  (bitcoin-lisp.serialization:make-block-header
   :version version
   :prev-block prev-block
   :merkle-root merkle-root
   :timestamp timestamp
   :bits bits
   :nonce nonce))

(defun build-mock-chain (count &key (start-bits #x1d00ffff)
                                    (start-time 1231006505)
                                    (interval 600)
                                    (bits-fn nil))
  "Build a chain of COUNT mock block-index-entries.
BITS-FN if provided is called with (height) and should return bits for that block.
Returns a list of entries from genesis (index 0) to tip."
  (let ((entries (make-array count))
        (chain-state (bitcoin-lisp.storage:make-chain-state)))
    (dotimes (h count)
      (let* ((bits (if bits-fn (funcall bits-fn h) start-bits))
             (timestamp (+ start-time (* h interval)))
             (prev-entry (if (> h 0) (aref entries (1- h)) nil))
             (prev-hash (if prev-entry
                            (bitcoin-lisp.storage:block-index-entry-hash prev-entry)
                            (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
             (header (make-mock-header :timestamp timestamp :bits bits :prev-block prev-hash))
             ;; Generate a unique hash for this entry
             (hash (let ((h-bytes (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
                     (setf (aref h-bytes 0) (logand h #xFF))
                     (setf (aref h-bytes 1) (logand (ash h -8) #xFF))
                     (setf (aref h-bytes 2) (logand (ash h -16) #xFF))
                     h-bytes))
             (entry (bitcoin-lisp.storage:make-block-index-entry
                     :hash hash
                     :height h
                     :header header
                     :prev-entry prev-entry
                     :chain-work (bitcoin-lisp.storage:calculate-chain-work bits
                                  (if prev-entry
                                      (bitcoin-lisp.storage:block-index-entry-chain-work prev-entry)
                                      0))
                     :status :valid)))
        (setf (aref entries h) entry)
        (bitcoin-lisp.storage:add-block-index-entry chain-state entry)))
    ;; Update chain tip
    (let ((tip (aref entries (1- count))))
      (bitcoin-lisp.storage:update-chain-tip
       chain-state
       (bitcoin-lisp.storage:block-index-entry-hash tip)
       (1- count)))
    (values entries chain-state)))

;;;; Task 4.1: target-to-bits roundtrip tests

(test target-to-bits-roundtrip
  "target-to-bits roundtrips with bits-to-target for standard values."
  ;; Genesis / min difficulty
  (let* ((bits #x1d00ffff)
         (target (bitcoin-lisp.storage:bits-to-target bits))
         (result (bitcoin-lisp.storage:target-to-bits target)))
    (is (= bits result)))
  ;; A real mainnet difficulty bits value (block 100000)
  (let* ((bits #x1b04864c)
         (target (bitcoin-lisp.storage:bits-to-target bits))
         (result (bitcoin-lisp.storage:target-to-bits target)))
    (is (= bits result)))
  ;; Another real value
  (let* ((bits #x1a05db8b)
         (target (bitcoin-lisp.storage:bits-to-target bits))
         (result (bitcoin-lisp.storage:target-to-bits target)))
    (is (= bits result))))

(test target-to-bits-zero
  "target-to-bits of zero returns zero."
  (is (= 0 (bitcoin-lisp.storage:target-to-bits 0))))

(test target-to-bits-pow-limit
  "target-to-bits of the PoW limit target gives 0x1d00ffff."
  (let ((pow-limit (bitcoin-lisp.storage:bits-to-target #x1d00ffff)))
    (is (= #x1d00ffff (bitcoin-lisp.storage:target-to-bits pow-limit)))))

;;;; Task 4.2: calculate-next-work-required tests

(test retarget-no-change
  "When actual timespan equals target timespan, bits stay the same."
  (let* ((bits #x1d00ffff)
         (start-time 1231006505)
         (end-time (+ start-time bitcoin-lisp.storage:+pow-target-timespan+))
         (result (bitcoin-lisp.storage:calculate-next-work-required start-time end-time bits)))
    (is (= bits result))))

(test retarget-4x-clamp-increase
  "When blocks are mined very fast, difficulty increase is clamped to 4x."
  (let* ((bits #x1d00ffff)
         (start-time 1231006505)
         ;; Timespan = 1 second (extremely fast), should clamp to timespan/4
         (end-time (+ start-time 1))
         (result (bitcoin-lisp.storage:calculate-next-work-required start-time end-time bits))
         ;; With 1/4 timespan, target should be target/4 (harder)
         (expected-timespan (floor bitcoin-lisp.storage:+pow-target-timespan+ 4))
         (expected (bitcoin-lisp.storage:calculate-next-work-required
                    start-time (+ start-time expected-timespan) bits)))
    (is (= result expected))))

(test retarget-4x-clamp-decrease
  "When blocks are mined very slowly, difficulty decrease is clamped to 4x."
  (let* ((bits #x1d00ffff)
         (start-time 1231006505)
         ;; Timespan = 100 * target (extremely slow), should clamp to timespan*4
         (end-time (+ start-time (* 100 bitcoin-lisp.storage:+pow-target-timespan+)))
         (result (bitcoin-lisp.storage:calculate-next-work-required start-time end-time bits))
         ;; With 4x timespan, target should be target*4 (easier) but capped at pow-limit
         (expected-timespan (* 4 bitcoin-lisp.storage:+pow-target-timespan+))
         (expected (bitcoin-lisp.storage:calculate-next-work-required
                    start-time (+ start-time expected-timespan) bits)))
    (is (= result expected))))

(test retarget-halved-timespan
  "When blocks are mined in half the target time, difficulty roughly doubles."
  (let* ((bits #x1d00ffff)
         (start-time 1231006505)
         (half-timespan (floor bitcoin-lisp.storage:+pow-target-timespan+ 2))
         (end-time (+ start-time half-timespan))
         (result (bitcoin-lisp.storage:calculate-next-work-required start-time end-time bits))
         (old-target (bitcoin-lisp.storage:bits-to-target bits))
         (new-target (bitcoin-lisp.storage:bits-to-target result)))
    ;; New target should be roughly half the old target (harder)
    (is (< new-target old-target))
    ;; Within rounding, new-target ~= old-target / 2
    (is (< (abs (- new-target (floor old-target 2)))
            ;; Allow small rounding difference
            (floor old-target 100)))))

(test retarget-does-not-exceed-pow-limit
  "The retarget result should never exceed the PoW limit."
  (let* ((bits #x1d00ffff)
         (start-time 1231006505)
         ;; 4x slower than target timespan (maximum decrease)
         (end-time (+ start-time (* 4 bitcoin-lisp.storage:+pow-target-timespan+)))
         (result (bitcoin-lisp.storage:calculate-next-work-required start-time end-time bits))
         (result-target (bitcoin-lisp.storage:bits-to-target result))
         (pow-limit (bitcoin-lisp.storage:bits-to-target bitcoin-lisp.storage:+pow-limit-bits+)))
    (is (<= result-target pow-limit))))

;;;; Task 4.3: testnet min-difficulty and walk-back tests

(test testnet-min-difficulty-allowed
  "testnet-min-difficulty-allowed-p returns T when >20 min gap."
  (is (bitcoin-lisp.validation:testnet-min-difficulty-allowed-p
       (+ 1000 1201) 1000))
  (is (not (bitcoin-lisp.validation:testnet-min-difficulty-allowed-p
            (+ 1000 1200) 1000)))
  (is (not (bitcoin-lisp.validation:testnet-min-difficulty-allowed-p
            (+ 1000 600) 1000))))

(test testnet-walk-back-bits-finds-real-difficulty
  "testnet-walk-back-bits walks past min-difficulty blocks."
  (let ((real-bits #x1b04864c))
    (multiple-value-bind (entries chain-state)
        (build-mock-chain 10
                          :bits-fn (lambda (h)
                                     (cond
                                       ;; First 5 blocks use real difficulty
                                       ((< h 5) real-bits)
                                       ;; Next 5 are min-difficulty
                                       (t #x1d00ffff))))
      (declare (ignore chain-state))
      ;; Walk back from the last entry (height 9, min-difficulty)
      (let ((result (bitcoin-lisp.validation:testnet-walk-back-bits (aref entries 9))))
        ;; Should find real-bits at height 4
        (is (= real-bits result))))))

(test testnet-walk-back-stops-at-retarget-boundary
  "testnet-walk-back-bits stops at retarget boundary even if min-difficulty."
  ;; Build a chain where block 0 (retarget boundary) has min-difficulty
  ;; and blocks 1-5 also have min-difficulty
  (multiple-value-bind (entries chain-state)
      (build-mock-chain 6 :start-bits #x1d00ffff)
    (declare (ignore chain-state))
    ;; Walk back from entry 5 should stop at entry 0 (height 0, retarget boundary)
    (let ((result (bitcoin-lisp.validation:testnet-walk-back-bits (aref entries 5))))
      (is (= #x1d00ffff result)))))

;;;; Task 4.4: first retarget period tests

(test first-period-uses-genesis-bits
  "Blocks in the first retarget period (heights 0-2015) expect pow-limit bits on mainnet."
  (let ((bitcoin-lisp:*network* :mainnet))
    (multiple-value-bind (entries chain-state)
        (build-mock-chain 100)
      (declare (ignore chain-state))
      ;; Check various heights within first period
      (dolist (h '(1 50 99))
        (let* ((prev-entry (aref entries (1- h)))
               (expected (bitcoin-lisp.validation:get-expected-bits h prev-entry)))
          (is (= bitcoin-lisp.storage:+pow-limit-bits+ expected)
              "Height ~D should expect pow-limit bits" h))))))

(test genesis-block-expects-pow-limit
  "Height 0 (genesis) expects pow-limit bits."
  (is (= bitcoin-lisp.storage:+pow-limit-bits+
         (bitcoin-lisp.validation:get-expected-bits 0 nil))))

;;;; Task 4.5: validate-difficulty integration tests

(test validate-difficulty-accepts-correct-mainnet-bits
  "validate-difficulty accepts correct bits on mainnet."
  (let ((bitcoin-lisp:*network* :mainnet))
    (multiple-value-bind (entries chain-state)
        (build-mock-chain 100)
      (declare (ignore chain-state))
      ;; All blocks use pow-limit bits, which is correct for the first period
      (dotimes (h 99)
        (let* ((entry (aref entries (1+ h)))
               (header (bitcoin-lisp.storage:block-index-entry-header entry))
               (prev-entry (aref entries h)))
          (multiple-value-bind (valid error)
              (bitcoin-lisp.validation:validate-difficulty header (1+ h) prev-entry)
            (is (eq t valid) "Height ~D should be valid" (1+ h))
            (is (null error))))))))

(test validate-difficulty-rejects-wrong-bits-mainnet
  "validate-difficulty rejects incorrect bits on mainnet."
  (let ((bitcoin-lisp:*network* :mainnet))
    (multiple-value-bind (entries chain-state)
        (build-mock-chain 10)
      (declare (ignore chain-state))
      ;; Create a header with wrong bits
      (let* ((prev-entry (aref entries 4))
             (wrong-header (make-mock-header :bits #x1b04864c :timestamp 1231006505)))
        (multiple-value-bind (valid error)
            (bitcoin-lisp.validation:validate-difficulty wrong-header 5 prev-entry)
          (is (null valid))
          (is (eq :bad-difficulty error)))))))

(test validate-difficulty-at-retarget-boundary
  "validate-difficulty accepts correct retarget at boundary."
  (let ((bitcoin-lisp:*network* :mainnet))
    ;; Build exactly 2017 blocks (0 through 2016)
    (multiple-value-bind (entries chain-state)
        (build-mock-chain 2017 :start-time 1231006505 :interval 600)
      (declare (ignore chain-state))
      ;; Block 2016 is a retarget boundary
      ;; Timespan from block 0 to block 2015 = 2015 * 600 = 1,209,000 seconds
      ;; This is close to target (1,209,600), so bits should be very similar
      (let* ((prev-entry (aref entries 2015))
             (expected-bits (bitcoin-lisp.validation:get-expected-bits 2016 prev-entry))
             (header (make-mock-header :bits expected-bits
                                       :timestamp (+ 1231006505 (* 2016 600)))))
        (multiple-value-bind (valid error)
            (bitcoin-lisp.validation:validate-difficulty header 2016 prev-entry)
          (is (eq t valid))
          (is (null error)))))))

(test validate-difficulty-testnet-min-difficulty
  "validate-difficulty accepts min-difficulty on testnet with >20 min gap."
  (let ((bitcoin-lisp:*network* :testnet))
    (multiple-value-bind (entries chain-state)
        (build-mock-chain 10 :start-time 1000000 :interval 600
                          :bits-fn (lambda (h) (declare (ignore h)) #x1b04864c))
      (declare (ignore chain-state))
      ;; Create a header with min-difficulty and >20 min gap
      (let* ((prev-entry (aref entries 9))
             (prev-time (bitcoin-lisp.serialization:block-header-timestamp
                         (bitcoin-lisp.storage:block-index-entry-header prev-entry)))
             (header (make-mock-header :bits #x1d00ffff
                                       :timestamp (+ prev-time 1201))))
        (multiple-value-bind (valid error)
            (bitcoin-lisp.validation:validate-difficulty header 10 prev-entry)
          (is (eq t valid))
          (is (null error)))))))

(test validate-difficulty-testnet-walk-back
  "validate-difficulty uses walk-back bits on testnet with <=20 min gap."
  (let ((bitcoin-lisp:*network* :testnet)
        (real-bits #x1b04864c))
    (multiple-value-bind (entries chain-state)
        (build-mock-chain 10 :start-time 1000000 :interval 600
                          :bits-fn (lambda (h)
                                     (if (< h 7) real-bits #x1d00ffff)))
      (declare (ignore chain-state))
      ;; Create a header with real bits and <=20 min gap (should pass via walk-back)
      (let* ((prev-entry (aref entries 9))
             (prev-time (bitcoin-lisp.serialization:block-header-timestamp
                         (bitcoin-lisp.storage:block-index-entry-header prev-entry)))
             (header (make-mock-header :bits real-bits
                                       :timestamp (+ prev-time 600))))
        (multiple-value-bind (valid error)
            (bitcoin-lisp.validation:validate-difficulty header 10 prev-entry)
          (is (eq t valid))
          (is (null error)))))))
