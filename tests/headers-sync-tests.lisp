(in-package #:bitcoin-lisp.tests)

(def-suite :headers-sync-tests
  :description "Low-work headers sync (anti-DoS): presync/redownload state machine"
  :in :bitcoin-lisp-tests)

(in-suite :headers-sync-tests)

;;; --- fixtures ---------------------------------------------------------------

(defun hs-hash (k)
  "A distinct 32-byte hash filled with byte K."
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element k))

(defun hs-salt ()
  "A fixed 16-byte salt so commitment bits are deterministic across a test."
  (make-array 16 :element-type '(unsigned-byte 8) :initial-element 42))

(defun hs-test-header (prev-hash bits &key (timestamp 1000) (nonce 0) (merkle 0))
  "A block-header linking to PREV-HASH, with MERKLE folded into the merkle-root
so distinct MERKLE/NONCE give distinct header hashes."
  (let ((mr (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref mr 0) (logand merkle #xff)
          (aref mr 1) (logand (ash merkle -8) #xff))
    (bitcoin-lisp.serialization:make-block-header
     :version 1 :prev-block prev-hash :merkle-root mr
     :timestamp timestamp :bits bits :nonce nonce)))

(defun hs-build-chain (n start-hash bits)
  "N continuous, distinct headers extending START-HASH (no real PoW; fed
directly to the state machine which does not re-check PoW)."
  (let ((prev start-hash) (out nil))
    (dotimes (i n (nreverse out))
      (let ((h (hs-test-header prev bits :merkle (1+ i) :nonce (1+ i))))
        (push h out)
        (setf prev (bitcoin-lisp.serialization:block-header-hash h))))))

(defun hs-start-entry (hash bits &key (work 0) (height 0) (timestamp 1000))
  "A block-index-entry usable as a headers-sync chain-start fork point."
  (bitcoin-lisp.storage:make-block-index-entry
   :hash hash :height height :chain-work work :status :header-valid :prev-entry nil
   :header (hs-test-header (hs-hash 0) bits :timestamp timestamp)))

(defun hs-per-header-work (bits)
  (bitcoin-lisp.storage:calculate-chain-work bits 0))

;;; --- queue ------------------------------------------------------------------

(test hss-queue-is-fifo
  "The functional queue preserves push-back / pop-front order across a refill."
  (let ((q (bitcoin-lisp.networking::%make-hss-queue)))
    (bitcoin-lisp.networking::hss-queue-push q :a)
    (bitcoin-lisp.networking::hss-queue-push q :b)
    (bitcoin-lisp.networking::hss-queue-push q :c)
    (is (= 3 (bitcoin-lisp.networking::hss-queue-size q)))
    (is (eq :a (bitcoin-lisp.networking::hss-queue-pop q)))
    (is (eq :b (bitcoin-lisp.networking::hss-queue-pop q)))
    (bitcoin-lisp.networking::hss-queue-push q :d)     ; refill after partial drain
    (is (eq :c (bitcoin-lisp.networking::hss-queue-pop q)))
    (is (eq :d (bitcoin-lisp.networking::hss-queue-pop q)))
    (is-true (bitcoin-lisp.networking::hss-queue-empty-p q))))

;;; --- difficulty-transition guard --------------------------------------------

(test permitted-difficulty-transition-bounds
  "PermittedDifficultyTransition: off on min-difficulty nets; on mainnet it
pins bits off-boundary and clamps to 4x either way on a retarget boundary."
  (flet ((pdt (net h o n) (bitcoin-lisp.networking::permitted-difficulty-transition net h o n)))
    ;; Min-difficulty networks: always permitted (fPowAllowMinDifficultyBlocks).
    (is-true (pdt :regtest  2016 #x1d00ffff #x1e0fffff))
    (is-true (pdt :testnet4 2016 #x1d00ffff #x1e0fffff))
    ;; Mainnet off-boundary: bits must not change at all.
    (is-true  (pdt :mainnet 5 #x1b0404cb #x1b0404cb))
    (is-false (pdt :mainnet 5 #x1b0404cb #x1b0404cc))
    ;; Mainnet on a boundary: within 4x either direction ok, beyond rejected.
    (let ((ot (bitcoin-lisp.storage:bits-to-target #x1b0404cb)))
      (flet ((for-target (target) (bitcoin-lisp.storage:target-to-bits target)))
        (is-true  (pdt :mainnet 2016 #x1b0404cb (for-target (* ot 3))))     ; 3x easier
        (is-false (pdt :mainnet 2016 #x1b0404cb (for-target (* ot 5))))     ; 5x easier
        (is-true  (pdt :mainnet 2016 #x1b0404cb (for-target (floor ot 3)))) ; 3x harder
        (is-false (pdt :mainnet 2016 #x1b0404cb (for-target (floor ot 5)))))))) ; 5x harder

;;; --- presync ----------------------------------------------------------------

(test presync-accumulates-work-without-storing
  "In PRESYNC we accumulate work and height but store nothing to the index."
  (let* ((bitcoin-lisp:*network* :regtest)
         (bits #x207fffff)
         (gh (hs-hash 9))
         (entry (hs-start-entry gh bits :work 0))
         (headers (hs-build-chain 6 gh bits))
         ;; Threshold unreachable, so we never leave PRESYNC.
         (hss (bitcoin-lisp.networking::make-headers-sync
               entry (expt 2 200) :network :regtest :salt (hs-salt))))
    (multiple-value-bind (ok more ready)
        (bitcoin-lisp.networking::hss-process-next-headers hss headers t)
      (is-true ok)
      (is-true more)                         ; full batch → ask for more
      (is (null ready))                      ; nothing released to the index
      (is (eq :presync (bitcoin-lisp.networking::hss-state hss)))
      (is (= 6 (bitcoin-lisp.networking::hss-current-height hss)))
      (is (= (* 6 (hs-per-header-work bits))
             (bitcoin-lisp.networking::hss-current-work hss))))))

(test presync-aborts-past-max-commitments
  "A chain longer than the memory bound (max-commitments) aborts the sync."
  (let* ((bitcoin-lisp:*network* :regtest)
         (bits #x207fffff)
         (gh (hs-hash 9))
         (entry (hs-start-entry gh bits :work 0))
         (headers (hs-build-chain 10 gh bits))
         (hss (bitcoin-lisp.networking::make-headers-sync
               entry (expt 2 200) :network :regtest :salt (hs-salt))))
    ;; Commit at every height, but allow only 3 commitments.
    (setf (bitcoin-lisp.networking::hss-commitment-period hss) 1
          (bitcoin-lisp.networking::hss-commit-offset hss) 0
          (bitcoin-lisp.networking::hss-max-commitments hss) 3)
    (multiple-value-bind (ok more ready)
        (bitcoin-lisp.networking::hss-process-next-headers hss headers t)
      (declare (ignore more ready))
      (is-false ok)
      (is (eq :final (bitcoin-lisp.networking::hss-state hss))))))

;;; --- full presync -> redownload -> accept -----------------------------------

(test presync-to-redownload-accepts-full-chain
  "Once presync work crosses the threshold we switch to REDOWNLOAD; feeding the
same chain back verifies commitments and releases every header for storage."
  (let* ((bitcoin-lisp:*network* :regtest)
         (bits #x207fffff)
         (proof (hs-per-header-work bits))
         (gh (hs-hash 9))
         (entry (hs-start-entry gh bits :work 0))
         (headers (hs-build-chain 8 gh bits))
         (hss (bitcoin-lisp.networking::make-headers-sync
               entry (* 3 proof) :network :regtest :salt (hs-salt))))
    ;; Small deterministic commitment schedule; release headers immediately.
    (setf (bitcoin-lisp.networking::hss-commitment-period hss) 2
          (bitcoin-lisp.networking::hss-commit-offset hss) 0
          (bitcoin-lisp.networking::hss-redownload-buffer-size hss) 0)
    ;; PRESYNC: crosses the 3-header threshold, switches to REDOWNLOAD.
    (multiple-value-bind (ok more ready)
        (bitcoin-lisp.networking::hss-process-next-headers hss headers nil)
      (is-true ok)
      (is-true more)                          ; switched -> re-request from start
      (is (null ready))
      (is (eq :redownload (bitcoin-lisp.networking::hss-state hss))))
    ;; REDOWNLOAD: same chain back -> all 8 released, in order, sync final.
    (multiple-value-bind (ok more ready)
        (bitcoin-lisp.networking::hss-process-next-headers hss headers nil)
      (declare (ignore more))
      (is-true ok)
      (is (= 8 (length ready)))
      (is (equalp (mapcar #'bitcoin-lisp.serialization:block-header-hash headers)
                  (mapcar #'bitcoin-lisp.serialization:block-header-hash ready)))
      (is (eq :final (bitcoin-lisp.networking::hss-state hss))))))

(test redownload-commitment-mismatch-aborts
  "A peer that proves work in presync but substitutes a different header at a
commitment height in redownload is caught by the stored commitment."
  (let* ((bitcoin-lisp:*network* :regtest)
         (bits #x207fffff)
         (proof (hs-per-header-work bits))
         (gh (hs-hash 9))
         (entry (hs-start-entry gh bits :work 0))
         (headers (hs-build-chain 6 gh bits))
         (hss (bitcoin-lisp.networking::make-headers-sync
               entry (* 4 proof) :network :regtest :salt (hs-salt))))
    (setf (bitcoin-lisp.networking::hss-commitment-period hss) 2
          (bitcoin-lisp.networking::hss-commit-offset hss) 0)
    ;; PRESYNC over all 6 -> crosses 4-header threshold -> REDOWNLOAD.
    (bitcoin-lisp.networking::hss-process-next-headers hss headers nil)
    (is (eq :redownload (bitcoin-lisp.networking::hss-state hss)))
    (let* ((h1 (first headers))                                   ; height 1 (no commit)
           (real-h2 (second headers))                             ; height 2 (commit)
           (ref-bit (bitcoin-lisp.networking::hss-commitment-bit
                     hss (bitcoin-lisp.serialization:block-header-hash real-h2)))
           (h1-hash (bitcoin-lisp.serialization:block-header-hash h1))
           ;; A different header at height 2 whose commitment bit is flipped.
           (alt-h2 (loop for n from 100 below 5000
                         for h = (hs-test-header h1-hash bits :merkle n :nonce n)
                         when (/= (bitcoin-lisp.networking::hss-commitment-bit
                                   hss (bitcoin-lisp.serialization:block-header-hash h))
                                  ref-bit)
                           do (return h))))
      (is (not (null alt-h2)))
      (multiple-value-bind (ok more ready)
          (bitcoin-lisp.networking::hss-process-next-headers hss (list h1 alt-h2) nil)
        (declare (ignore more ready))
        (is-false ok)
        (is (eq :final (bitcoin-lisp.networking::hss-state hss)))))))

;;; --- the storage-diversion gate --------------------------------------------

(test maybe-start-presync-gates-on-work-and-fullness
  "A full batch of low-work headers connecting to our index is diverted into
presync; a non-full batch is not (the peer has nothing more to prove work with)."
  (let* ((bitcoin-lisp:*network* :regtest)
         (bitcoin-lisp.storage:*pow-limit-target* bitcoin-lisp.storage:+regtest-pow-limit-target+)
         (bitcoin-lisp:*minimum-chain-work-override* 1000000)
         (bits #x207fffff)
         (gh (hs-hash 9))
         (state (bitcoin-lisp.storage::make-chain-state))
         (entry (bitcoin-lisp.storage:make-block-index-entry
                 :hash gh :height 0 :chain-work 1 :status :valid :prev-entry nil
                 :header (hs-test-header (hs-hash 0) bits))))
    (setf (bitcoin-lisp.storage::chain-state-best-block-hash state) gh)
    (bitcoin-lisp.storage:add-block-index-entry state entry)
    ;; Mine a short continuous PoW-valid chain off genesis.
    (let ((headers (let ((prev gh) (out nil))
                     (dotimes (i 3 (nreverse out))
                       (let ((h (loop for n from 0 below 100000
                                      for hh = (hs-test-header prev bits :merkle (1+ i) :nonce n)
                                      when (bitcoin-lisp.validation:check-proof-of-work hh)
                                        do (return hh))))
                         (push h out)
                         (setf prev (bitcoin-lisp.serialization:block-header-hash h)))))))
      ;; Full batch, work far below the (overridden) floor -> presync.
      (is (bitcoin-lisp.networking::headers-sync-state-p
           (bitcoin-lisp.networking::maybe-start-presync headers state t)))
      ;; Non-full batch -> store normally (no presync).
      (is (null (bitcoin-lisp.networking::maybe-start-presync headers state nil))))))
