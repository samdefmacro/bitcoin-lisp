(in-package #:bitcoin-lisp.networking)

;;;; Low-work headers synchronization (anti-DoS) — Bitcoin Core headerssync.cpp
;;;;
;;;; The P2P protocol offers no cheap way to learn the work on a peer's header
;;;; chain: a getheaders yields up to 2000 headers at a time. A malicious peer
;;;; (especially against a brand-new node syncing from genesis) can feed us a
;;;; very long, individually-PoW-valid but cheap header chain and, since we
;;;; store one block-index entry per header, exhaust our memory.
;;;;
;;;; The defense (Core HeadersSyncState) is to download a peer's headers TWICE
;;;; whenever their claimed chain-work is below our anti-DoS threshold, and to
;;;; commit NOTHING to the block index until the chain's total work is proven:
;;;;
;;;;   PRESYNC    — walk the whole chain once, storing only accumulated work and
;;;;                a 1-bit salted commitment every N headers (bounded memory,
;;;;                even for a very long chain). Validate each header's PoW and
;;;;                that its difficulty transition is permitted.
;;;;   REDOWNLOAD — once cumulative work crosses the threshold, re-request from
;;;;                the fork point, verifying the stored commitments so the peer
;;;;                cannot substitute a different (cheap) chain in phase 2, and
;;;;                buffer headers, releasing them to the block index only once
;;;;                enough commitments beneath them have been verified.
;;;;
;;;; This module is the state machine; the driver lives in sync-headers (ibd).

;;; Per-network HeadersSyncParams, from Core kernel/chainparams.cpp
;;; m_headers_sync_params (tuned by contrib/devtools/headerssync-params.py for a
;;; fixed memory/security target). CAR = commitment period (store 1 bit per this
;;; many headers in presync); CDR = redownload buffer size (release a header to
;;; the index only once this many sit on top of it, i.e. ~buffer/period verified
;;; commitments).
(defun headers-sync-params (network)
  (ecase network
    (:mainnet  '(641 . 15218))
    (:testnet3 '(673 . 14460))
    (:testnet4 '(606 . 16092))
    (:signet   '(620 . 15724))
    (:regtest  '(275 . 7017))))

;; Fastest block rate a consensus-valid chain can sustain given the median-time-
;; past rule (Core assumes 6 blocks/second); used to bound presync memory.
(defconstant +hss-max-block-rate+ 6)
(defconstant +hss-max-future-block-time+ 7200
  "Core MAX_FUTURE_BLOCK_TIME: 2h of clock slack added to the presync bound.")

;;; A functional FIFO queue: push-back and pop-front are amortized O(1), and
;;; popped elements are freed (no giant backing array over a full-chain sync).
(defstruct (hss-queue (:constructor %make-hss-queue))
  (in nil :type list)
  (out nil :type list)
  (size 0 :type fixnum))

(declaim (inline hss-queue-empty-p))
(defun hss-queue-empty-p (q) (zerop (hss-queue-size q)))

(defun hss-queue-push (q x)
  (push x (hss-queue-in q))
  (incf (hss-queue-size q))
  x)

(defun hss-queue-pop (q)
  "Remove and return the front element. Caller must ensure the queue is non-empty."
  (when (null (hss-queue-out q))
    (setf (hss-queue-out q) (nreverse (hss-queue-in q))
          (hss-queue-in q) nil))
  (decf (hss-queue-size q))
  (pop (hss-queue-out q)))

(defstruct (headers-sync-state (:conc-name hss-))
  (state :presync :type keyword)                 ; :presync | :redownload | :final
  (network :mainnet :type keyword)
  (commitment-period 641 :type fixnum)
  (redownload-buffer-size 15218 :type fixnum)
  (commit-offset 0 :type fixnum)                 ; secret height offset for commitments
  (salt nil)                                     ; 16 random bytes for the salted hasher
  (min-required-work 0)                          ; anti-DoS work threshold (bignum)
  ;; The fork point in our block index that the peer's chain branches from.
  (chain-start-hash nil)
  (chain-start-height 0)
  (chain-start-work 0)
  (chain-start-bits 0 :type (unsigned-byte 32))
  (chain-start-entry nil)                        ; for building getheaders locators
  ;; PRESYNC progress.
  (current-work 0)                               ; cumulative work seen (bignum)
  (current-height 0)
  (last-hash nil)                                ; hash of last presync header
  (last-bits 0 :type (unsigned-byte 32))         ; nBits of last presync header
  (commitments (%make-hss-queue))                ; FIFO of commitment bits (0/1)
  (max-commitments 0)
  ;; REDOWNLOAD progress.
  (redownload-buffer (%make-hss-queue))          ; FIFO of full block-header objects
  (redownload-last-height 0)
  (redownload-last-hash nil)
  (redownload-last-bits 0 :type (unsigned-byte 32))
  (redownload-work 0)                            ; cumulative redownloaded work (bignum)
  (process-all-remaining nil :type boolean))

;;; --- Difficulty-transition guard (Core pow.cpp PermittedDifficultyTransition)

(defun pow-allow-min-difficulty-blocks-p (network)
  "Core Consensus::Params.fPowAllowMinDifficultyBlocks — testnet3/testnet4/regtest."
  (and (member network '(:testnet3 :testnet4 :regtest)) t))

(defun permitted-difficulty-transition (network height old-bits new-bits)
  "Port of Bitcoin Core pow.cpp PermittedDifficultyTransition. Bound how much
the difficulty may change from OLD-BITS to NEW-BITS across the boundary at
HEIGHT, so a low-hashpower attacker cannot forge a high-work chain by spiking
difficulty into few blocks. On min-difficulty networks the check is disabled
(as in Core). Returns T if the transition is allowed."
  (if (pow-allow-min-difficulty-blocks-p network)
      t
      (let ((interval bitcoin-lisp.storage:+difficulty-adjustment-interval+))
        (cond
          ((zerop (mod height interval))
           (let* ((timespan bitcoin-lisp.storage:+pow-target-timespan+)
                  (smallest (floor timespan 4))
                  (largest (* timespan 4))
                  (pow-limit bitcoin-lisp.storage:*pow-limit-target*)
                  (old-target (bitcoin-lisp.storage:bits-to-target old-bits))
                  (observed (bitcoin-lisp.storage:bits-to-target new-bits))
                  ;; Largest permitted new target (easiest difficulty), capped.
                  (largest-target (min pow-limit (floor (* old-target largest) timespan)))
                  (max-new (bitcoin-lisp.storage:bits-to-target
                            (bitcoin-lisp.storage:target-to-bits largest-target)))
                  ;; Smallest permitted new target (hardest difficulty), capped.
                  (smallest-target (min pow-limit (floor (* old-target smallest) timespan)))
                  (min-new (bitcoin-lisp.storage:bits-to-target
                            (bitcoin-lisp.storage:target-to-bits smallest-target))))
             (not (or (< max-new observed) (> min-new observed)))))
          ;; Off a boundary, difficulty must not change at all.
          (t (= old-bits new-bits))))))

;;; --- Salted commitment hasher

(defun hss-commitment-bit (hss header-hash)
  "The 1-bit commitment for HEADER-HASH under this sync's secret salt. Both
phases use the same salt, so bits match iff the header hashes match; an
attacker who doesn't know the salt cannot craft a divergent phase-2 chain that
reproduces the phase-1 commitments (Core SaltedUint256Hasher)."
  (let* ((salt (hss-salt hss))
         (buf (concatenate '(simple-array (unsigned-byte 8) (*)) salt header-hash))
         (digest (bitcoin-lisp.crypto:sha256 buf)))
    (logand (aref digest 0) 1)))

;;; --- Construction

(defun hss-median-time-past (entry)
  "Median timestamp of ENTRY and up to its 10 ancestors (Core GetMedianTimePast)."
  (let ((times nil) (e entry) (n 0))
    (loop while (and e (< n 11))
          do (push (bitcoin-lisp.serialization:block-header-timestamp
                    (bitcoin-lisp.storage:block-index-entry-header e))
                   times)
             (setf e (bitcoin-lisp.storage:block-index-entry-prev-entry e))
             (incf n))
    (let ((sorted (sort times #'<)))
      (if sorted (nth (floor (length sorted) 2) sorted) 0))))

(defun bytes->uint (bytes)
  "Big-endian interpret a byte vector as a non-negative integer."
  (let ((acc 0))
    (loop for b across bytes do (setf acc (+ (* acc 256) b)))
    acc))

(defun make-headers-sync (chain-start-entry min-work
                          &key (network bitcoin-lisp:*network*)
                               (now (bitcoin-lisp.serialization:get-unix-time))
                               salt)
  "Build a HeadersSyncState to presync a peer's chain that branches from
CHAIN-START-ENTRY (a block-index entry) and requires MIN-WORK total chain work
before we will store it. SALT (16 bytes) may be supplied for deterministic
tests; otherwise it is drawn from the OS CSPRNG. Mirrors Core's ctor."
  (destructuring-bind (period . buffer-size) (headers-sync-params network)
    (let* ((header (bitcoin-lisp.storage:block-index-entry-header chain-start-entry))
           (start-hash (bitcoin-lisp.storage:block-index-entry-hash chain-start-entry))
           (start-bits (bitcoin-lisp.serialization:block-header-bits header))
           (start-work (bitcoin-lisp.storage:block-index-entry-chain-work chain-start-entry))
           (start-height (bitcoin-lisp.storage:block-index-entry-height chain-start-entry))
           (salt (or salt (ironclad:random-data 16)))
           ;; Secret offset in [0, period): commit at heights h where
           ;; (h mod period) == commit-offset.
           (offset (mod (bytes->uint salt) period))
           ;; Memory bound on presync: the longest a consensus-valid chain could
           ;; possibly be right now is 6 blocks/sec since chain-start's MTP, plus
           ;; 2h of future-time slack. Any peer exceeding this is aborted.
           (mtp (hss-median-time-past chain-start-entry))
           (max-seconds (+ (max 0 (- now mtp)) +hss-max-future-block-time+))
           (max-commitments (floor (* +hss-max-block-rate+ max-seconds) period)))
      (make-headers-sync-state
       :state :presync :network network
       :commitment-period period :redownload-buffer-size buffer-size
       :commit-offset offset :salt salt
       :min-required-work min-work
       :chain-start-hash start-hash :chain-start-height start-height
       :chain-start-work start-work :chain-start-bits start-bits
       :chain-start-entry chain-start-entry
       :current-work start-work :current-height start-height
       :last-hash start-hash :last-bits start-bits
       :max-commitments max-commitments))))

(defun hss-finalize (hss)
  "Free the sync's buffers and mark it unusable (Core Finalize)."
  (setf (hss-state hss) :final
        (hss-commitments hss) (%make-hss-queue)
        (hss-redownload-buffer hss) (%make-hss-queue))
  hss)

;;; --- PRESYNC

(defun hss-block-proof (bits)
  "Work contributed by a header with the given compact BITS (Core GetBlockProof)."
  (bitcoin-lisp.storage:calculate-chain-work bits 0))

(defun hss-validate-and-process-single (hss header)
  "PRESYNC: validate one HEADER's difficulty transition, store its commitment if
this height is a commitment height, and advance cumulative work/height. Returns
NIL (caller aborts) if the transition is impermissible or the peer's chain has
grown beyond max-commitments."
  (let ((next-height (1+ (hss-current-height hss)))
        (bits (bitcoin-lisp.serialization:block-header-bits header)))
    (cond
      ((not (permitted-difficulty-transition (hss-network hss) next-height
                                             (hss-last-bits hss) bits))
       nil)
      (t
       (when (= (mod next-height (hss-commitment-period hss)) (hss-commit-offset hss))
         (hss-queue-push (hss-commitments hss)
                         (hss-commitment-bit hss (bitcoin-lisp.serialization:block-header-hash header)))
         (when (> (hss-queue-size (hss-commitments hss)) (hss-max-commitments hss))
           (return-from hss-validate-and-process-single nil)))
       (incf (hss-current-work hss) (hss-block-proof bits))
       (setf (hss-last-hash hss) (bitcoin-lisp.serialization:block-header-hash header)
             (hss-last-bits hss) bits
             (hss-current-height hss) next-height)
       t))))

(defun hss-validate-and-store-commitments (hss headers)
  "PRESYNC: process a batch, and if cumulative work crosses the threshold,
transition to REDOWNLOAD. Returns NIL on any failure (caller aborts)."
  (unless (equalp (bitcoin-lisp.serialization:block-header-prev-block (first headers))
                  (hss-last-hash hss))
    ;; Non-continuous with what we've seen — peer likely reorged; give up.
    (return-from hss-validate-and-store-commitments nil))
  (dolist (header headers)
    (unless (hss-validate-and-process-single hss header)
      (return-from hss-validate-and-store-commitments nil)))
  (when (>= (hss-current-work hss) (hss-min-required-work hss))
    ;; Enough work proven: restart the download, this time storing.
    (setf (hss-redownload-buffer hss) (%make-hss-queue)
          (hss-redownload-last-height hss) (hss-chain-start-height hss)
          (hss-redownload-last-hash hss) (hss-chain-start-hash hss)
          (hss-redownload-last-bits hss) (hss-chain-start-bits hss)
          (hss-redownload-work hss) (hss-chain-start-work hss)
          (hss-state hss) :redownload))
  t)

;;; --- REDOWNLOAD

(defun hss-validate-and-store-redownloaded (hss header)
  "REDOWNLOAD: validate one HEADER against the chain we committed to in presync
(continuity, difficulty, and — at commitment heights — the stored commitment
bit), and buffer it. Returns NIL (caller aborts) on any mismatch."
  (let ((next-height (1+ (hss-redownload-last-height hss)))
        (bits (bitcoin-lisp.serialization:block-header-bits header))
        (hash (bitcoin-lisp.serialization:block-header-hash header)))
    (cond
      ((not (equalp (bitcoin-lisp.serialization:block-header-prev-block header)
                    (hss-redownload-last-hash hss)))
       nil)
      ((not (permitted-difficulty-transition (hss-network hss) next-height
                                             (hss-redownload-last-bits hss) bits))
       nil)
      (t
       (incf (hss-redownload-work hss) (hss-block-proof bits))
       (when (>= (hss-redownload-work hss) (hss-min-required-work hss))
         (setf (hss-process-all-remaining hss) t))
       ;; Verify the commitment at commitment heights — but not once we've
       ;; passed the target work (the peer may have legitimately extended its
       ;; chain since presync, so we stop checking and accept the tail).
       (when (and (not (hss-process-all-remaining hss))
                  (= (mod next-height (hss-commitment-period hss)) (hss-commit-offset hss)))
         (when (hss-queue-empty-p (hss-commitments hss))
           (return-from hss-validate-and-store-redownloaded nil))
         (let ((expected (hss-queue-pop (hss-commitments hss)))
               (actual (hss-commitment-bit hss hash)))
           (unless (= expected actual)
             (return-from hss-validate-and-store-redownloaded nil))))
       (hss-queue-push (hss-redownload-buffer hss) header)
       (setf (hss-redownload-last-height hss) next-height
             (hss-redownload-last-hash hss) hash
             (hss-redownload-last-bits hss) bits)
       t))))

(defun hss-pop-ready (hss)
  "Return the buffered headers now safe to accept: those with a full
redownload-buffer-size worth of verified headers on top, or everything once the
target work is reached. Mirrors PopHeadersReadyForAcceptance."
  (let ((buf (hss-redownload-buffer hss))
        (limit (hss-redownload-buffer-size hss))
        (ready nil))
    (loop while (or (> (hss-queue-size buf) limit)
                    (and (plusp (hss-queue-size buf)) (hss-process-all-remaining hss)))
          do (push (hss-queue-pop buf) ready))
    (nreverse ready)))

;;; --- Driver entry points (called from sync-headers)

(defun hss-process-next-headers (hss headers full-message-p)
  "Feed a validated batch of HEADERS to the sync. FULL-MESSAGE-P is true when
the batch was at the protocol maximum (the peer may have more). Returns
 (values success-p request-more-p ready-headers): READY-HEADERS is the list the
caller may now fully validate and store (only non-empty in REDOWNLOAD). On
failure or completion the sync is finalized. Mirrors ProcessNextHeaders."
  (when (or (null headers) (eq (hss-state hss) :final))
    (return-from hss-process-next-headers (values nil nil nil)))
  (multiple-value-bind (success request-more ready)
      (ecase (hss-state hss)
        (:presync
         (if (hss-validate-and-store-commitments hss headers)
             ;; Ask for more while batches are full, or (having just switched to
             ;; REDOWNLOAD) to restart the download from the fork point. A
             ;; non-full batch still in PRESYNC means the chain ended short of
             ;; the threshold — nothing more to get.
             (values t (or full-message-p (eq (hss-state hss) :redownload)) nil)
             (values nil nil nil)))
        (:redownload
         (let ((ok t))
           (dolist (header headers)
             (unless (hss-validate-and-store-redownloaded hss header)
               (setf ok nil) (return)))
           (if ok
               (let ((ready (hss-pop-ready hss)))
                 (values t
                         ;; Done once the buffer is drained after hitting target;
                         ;; else keep going while batches are full.
                         (not (or (and (hss-queue-empty-p (hss-redownload-buffer hss))
                                       (hss-process-all-remaining hss))
                                  (not full-message-p)))
                         ready))
               (values nil nil nil)))))
    (unless (and success request-more)
      (hss-finalize hss))
    (values success request-more ready)))

(defun hss-locator-entries (entry)
  "Block locator hashes walking back from ENTRY with exponential step
(Core LocatorEntries)."
  (let ((hashes nil) (step 1) (n 0) (e entry))
    (loop while e do
      (push (bitcoin-lisp.storage:block-index-entry-hash e) hashes)
      (when (> n 10) (setf step (* step 2)))
      (dotimes (_ step)
        (when (null e) (return))
        (setf e (bitcoin-lisp.storage:block-index-entry-prev-entry e)))
      (incf n))
    (nreverse hashes)))

(defun hss-locator-hashes (hss)
  "Locator for the next getheaders: the last header we processed in the current
phase, followed by the fork-point locator so the peer can re-anchor if it
reorged (Core NextHeadersRequestLocator)."
  (let ((tip (ecase (hss-state hss)
               (:presync (hss-last-hash hss))
               (:redownload (hss-redownload-last-hash hss))
               (:final nil))))
    (if tip
        (cons tip (hss-locator-entries (hss-chain-start-entry hss)))
        nil)))

;;; --- Entry from the headers handler

(defun headers-pow-valid-p (headers)
  "Core CheckHeadersPoW: every header satisfies its own claimed target and the
batch is internally continuous. Required before feeding a batch to a sync."
  (and (every #'bitcoin-lisp.validation:check-proof-of-work headers)
       (loop for (a b) on headers
             while b
             always (equalp (bitcoin-lisp.serialization:block-header-hash a)
                            (bitcoin-lisp.serialization:block-header-prev-block b)))))

(defun anti-dos-work-threshold (chain-state)
  "Core GetAntiDoSWorkThreshold: max(nMinimumChainWork, tip_work - 144·tip_proof).
The 144-block buffer lets us accept headers that fork just below our tip."
  (let* ((min-work (bitcoin-lisp:minimum-chain-work bitcoin-lisp:*network*))
         (tip (bitcoin-lisp.storage:get-block-index-entry
               chain-state (bitcoin-lisp.storage:best-block-hash chain-state))))
    (if tip
        (let* ((tip-work (bitcoin-lisp.storage:block-index-entry-chain-work tip))
               (tip-bits (bitcoin-lisp.serialization:block-header-bits
                          (bitcoin-lisp.storage:block-index-entry-header tip)))
               (tip-proof (hss-block-proof tip-bits))
               (near (- tip-work (min (* 144 tip-proof) tip-work))))
          (max near min-work))
        min-work)))

(defun claimed-headers-work (chain-start-entry headers)
  "Total work a chain would have if HEADERS extend CHAIN-START-ENTRY."
  (let ((w (bitcoin-lisp.storage:block-index-entry-chain-work chain-start-entry)))
    (dolist (h headers w)
      (incf w (hss-block-proof (bitcoin-lisp.serialization:block-header-bits h))))))

(defun maybe-start-presync (headers chain-state full-batch-p)
  "Decide whether a received header batch should be diverted into low-work
presync instead of stored directly. Returns a fresh headers-sync-state when the
batch connects to our index, is a full batch (so the peer may have much more),
and its claimed total work is below the anti-DoS threshold; otherwise NIL and
the caller stores the batch normally. Mirrors the gate in ProcessHeadersMessage/
TryLowWorkHeadersSync."
  (let ((chain-start (bitcoin-lisp.storage:get-block-index-entry
                      chain-state
                      (bitcoin-lisp.serialization:block-header-prev-block (first headers)))))
    (when (and chain-start full-batch-p (headers-pow-valid-p headers))
      (let ((min-work (anti-dos-work-threshold chain-state)))
        (when (< (claimed-headers-work chain-start headers) min-work)
          (make-headers-sync chain-start min-work))))))
