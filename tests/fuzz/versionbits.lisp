(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/versionbits.cpp at the pin: a BIP9 deployment with
;;;; fuzzed parameters over a mined chain of fuzzed signalling, and the state,
;;;; since-height and statistics of the final period checked against what the
;;;; rules allow. Core's TestConditionChecker is a BIP9Deployment run through
;;;; the ordinary checker; ours is a VB-DEPLOYMENT (a copy of a regtest one
;;;; with its fields set) run through VERSIONBITS-STATE, -SINCE-HEIGHT and
;;;; -STATISTICS. Core's Blocks class is a list of block-index entries whose
;;;; headers carry the version and a time INTERVAL apart.

(def-suite :fuzz-versionbits-tests :in :bitcoin-lisp-tests
  :description "Core fuzz versionbits.cpp over our BIP9 state machine")

(in-suite :fuzz-versionbits-tests)

(defconstant +vb-fuzz-max-start-time+ 4102444800 "Core MAX_START_TIME (2100-01-01).")

(defun %vb-fuzz-mine (tip height version time)
  "Core Blocks::mine_block: an entry at HEIGHT on TIP with a header carrying
VERSION and TIME."
  (let ((hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref hash 0) (ldb (byte 8 0) height)
          (aref hash 1) (ldb (byte 8 8) height))
    (bl.store:make-block-index-entry
     :hash hash :height height :prev-entry tip :status :valid
     :header (bl.ser:make-block-header
              :version version
              :prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
              :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
              :timestamp time :bits #x1d00ffff :nonce 0))))

(defun %vb-fuzz-condition-p (dep version)
  "VersionBitsConditionChecker::Condition on a bare version (versionbits_impl.h)."
  (and (= (logand version #xE0000000) #x20000000)
       (logbitp (bl.val:vb-deployment-bit dep) version)))

(defun %vb-fuzz-corpus (fdp)
  "A buffer that gets past versionbits' early exits: versions that do and do
not signal the chosen bit, one deployment of each kind (a timed window seven
times in eight, else ALWAYS_ACTIVE or NEVER_ACTIVE), and up to 30 prior
periods -- what the qa-assets corpus holds for Core's target."
  (let* ((bit (consume-integral-in-range fdp 0 28))
         (kind (consume-integral-in-range fdp 0 7))
         (other (logand (consume-integral fdp :u32) #x1fffffff))
         (ver-signal (logior #x20000000 (ash 1 bit) other))
         (ver-nosignal (if (consume-bool fdp)
                           (logandc2 (logior #x20000000 other) (ash 1 bit))
                           (consume-integral-in-range fdp 0 4)))
         (specs `((,(consume-integral-in-range fdp 1231006505 +vb-fuzz-max-start-time+) 1231006505 ,+vb-fuzz-max-start-time+)
                  (,ver-signal ,(- (ash 1 31)) ,(1- (ash 1 31)))
                  (,ver-nosignal ,(- (ash 1 31)) ,(1- (ash 1 31)))
                  (,(if (= kind 0) 1 0) 0 255)
                  ,@(unless (= kind 0) `((,(if (= kind 1) 1 0) 0 255)))
                  (,(consume-integral-in-range fdp 1 32) 1 32)
                  (,bit 0 28)
                  ,@(if (< kind 2)
                        `((1 0 255))
                        `((,(consume-integral-in-range fdp 0 416) 0 416)
                          (,(consume-integral-in-range fdp 0 416) 0 416)
                          (,(consume-integral fdp :u8) 0 255)
                          (,(consume-integral fdp :u8) 0 255)))
                  (,(consume-integral-in-range fdp 0 512) 0 512)
                  (,(consume-integral fdp :u32) 0 #xffffffff)
                  ,@(loop repeat (consume-integral-in-range fdp 0 30)
                          collect `(,(consume-integral fdp :u8) 0 255)))))
    (fdp-integral-bytes specs)))

(define-fuzz-target versionbits
    (buffer :core "versionbits.cpp:70-340" :iterations 400 :max-len 64
            :corpus #'%vb-fuzz-corpus)
  "Whatever the deployment's threshold, bit, start, timeout and minimum
activation height, and whatever prior periods signalled, the final period's
state and since-height do not move within the period, its statistics count
exactly the signalling blocks with Core's `possible', and the state reached
at the period's end is one of the transitions BIP9 allows from the state it
started in -- DEFINED only before the start time, LOCKED_IN only on a met
threshold, ACTIVE only at the minimum activation height, FAILED only on the
timeout, and everything settled once sixteen periods have passed."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (interval 600)
         (period 32) (max-periods 16) (max-blocks (* 2 period max-periods))
         (block-start-time (consume-integral-in-range fdp 1231006505 +vb-fuzz-max-start-time+ 32))
         (ver-signal (consume-integral fdp :i32))
         (ver-nosignal (consume-integral fdp :i32)))
    (when (minusp ver-nosignal) (return-from fuzz-target/versionbits))
    (let* ((always-active (consume-bool fdp))
           (never-active (and (not always-active) (consume-bool fdp)))
           (dep (copy-structure (first (bl.val:versionbits-deployments :regtest)))))
      (setf (bl.val:vb-deployment-period dep) period
            (bl.val:vb-deployment-threshold dep) (consume-integral-in-range fdp 1 period 32)
            (bl.val:vb-deployment-bit dep) (consume-integral-in-range fdp 0 28 32))
      (cond ((or always-active never-active)
             (setf (bl.val:vb-deployment-start-time dep)
                   (if always-active bl.val:+vb-always-active+ bl.val:+vb-never-active+)
                   (bl.val:vb-deployment-timeout dep)
                   (if (consume-bool fdp) bl.val:+vb-no-timeout+ (consume-integral fdp :i64))))
            (t
             (let ((start-block (consume-integral-in-range fdp 0 (* period (- max-periods 3)) 32))
                   (end-block (consume-integral-in-range fdp 0 (* period (- max-periods 3)) 32)))
               (setf (bl.val:vb-deployment-start-time dep) (+ block-start-time (* start-block interval))
                     (bl.val:vb-deployment-timeout dep) (+ block-start-time (* end-block interval)))
               (when (consume-bool fdp) (incf (bl.val:vb-deployment-start-time dep) (floor interval 2)))
               (when (consume-bool fdp) (incf (bl.val:vb-deployment-timeout dep) (floor interval 2))))))
      (setf (bl.val:vb-deployment-min-activation-height dep)
            (consume-integral-in-range fdp 0 (* period max-periods) 32))
      ;; Early exit if the versions don't signal sensibly for the deployment.
      (unless (and (%vb-fuzz-condition-p dep ver-signal)
                   (not (%vb-fuzz-condition-p dep ver-nosignal)))
        (return-from fuzz-target/versionbits))
      (fuzz-assert (plusp ver-signal) "a signalling version ~D is not positive" ver-signal)
      (let ((signalling-mask (consume-integral fdp :u32))
            (tip nil) (size 0))
        (flet ((mine (signal)
                 (setf tip (%vb-fuzz-mine tip size (if signal ver-signal ver-nosignal)
                                          (+ block-start-time (* size interval))))
                 (incf size)
                 tip)
               (state (entry) (bl.val:versionbits-state nil entry dep))
               (since (entry) (bl.val:versionbits-since-height nil entry dep))
               (mtp (entry) (bl.val:compute-median-time-past-from-entry entry)))
          ;; Prior periods, each wholly signalling or wholly not.
          (loop while (plusp (remaining-bytes fdp))
                do (let ((signal (consume-bool fdp)))
                     (dotimes (b period) (mine signal)))
                   (when (> (+ size (* 2 period)) max-blocks) (return)))
          (let* ((prev tip)
                 (exp-since (since prev))
                 (exp-state (state prev))
                 (blocks-sig 0)
                 (last-count 0)
                 (last-signals '()))
            (fuzz-assert (<= exp-since (if prev (1+ (bl.store:block-index-entry-height prev)) 0))
                         "since ~D is past the next height" exp-since)
            ;; The period's first PERIOD-1 blocks: state and since hold, the
            ;; statistics grow by exactly this block.
            (loop for b from 1 below period
                  do (let* ((signal (logbitp (mod b 32) signalling-mask))
                            (block (mine signal)))
                       (when signal (incf blocks-sig))
                       (fuzz-assert (eq (%vb-fuzz-condition-p
                                         dep (bl.ser:block-header-version
                                              (bl.store:block-index-entry-header block)))
                                        signal))
                       (fuzz-assert (eq (fuzz-sabotage (state block)) exp-state)
                                    "the state moved inside a period: ~S then ~S" exp-state (state block))
                       (fuzz-assert (= (since block) exp-since))
                       (multiple-value-bind (s-period s-threshold elapsed count possible signals)
                           (bl.val:versionbits-statistics nil block dep)
                         (fuzz-assert (and (= s-period period)
                                           (= s-threshold (bl.val:vb-deployment-threshold dep))))
                         (fuzz-assert (= (fuzz-sabotage elapsed) b)
                                      "elapsed ~D after block ~D of the period" elapsed b)
                         (fuzz-assert (= count (+ last-count (if signal 1 0)))
                                      "count ~D after ~D" count last-count)
                         (fuzz-assert (eq possible
                                          (>= (+ count period)
                                              (+ elapsed (bl.val:vb-deployment-threshold dep))))
                                      "possible is ~S at count ~D elapsed ~D" possible count elapsed)
                         (setf last-count count)
                         (setf last-signals (append last-signals (list (if signal 1 0))))
                         (fuzz-assert (equal (coerce signals 'list) last-signals)
                                      "signalling record ~S, want ~S" signals last-signals))))
            (when (eq exp-state :started)
              (when (>= blocks-sig (1- (bl.val:vb-deployment-threshold dep)))
                (fuzz-assert (nth-value 4 (bl.val:versionbits-statistics nil tip dep)))))
            ;; The final block of the period.
            (let* ((signal (logbitp (mod period 32) signalling-mask))
                   (current (mine signal))
                   (threshold (bl.val:vb-deployment-threshold dep))
                   (next-height (1+ (bl.store:block-index-entry-height current))))
              (when signal (incf blocks-sig))
              (multiple-value-bind (s-period s-threshold elapsed count possible)
                  (bl.val:versionbits-statistics nil current dep)
                (fuzz-assert (and (= s-period period) (= s-threshold threshold)
                                  (= elapsed period) (= (fuzz-sabotage count) blocks-sig))
                             "final statistics ~S" (list s-period s-threshold elapsed count))
                (fuzz-assert (eq possible (>= (+ count period) (+ elapsed threshold)))))
              (let ((state (state current))
                    (since (since current)))
                (fuzz-assert (zerop (mod (fuzz-sabotage since) period)) "since ~D is not a period start" since)
                (fuzz-assert (<= 0 since next-height))
                (if (eq state exp-state)
                    (fuzz-assert (= since exp-since) "since moved from ~D to ~D without a transition"
                                 exp-since since)
                    (fuzz-assert (= since next-height)
                                 "a transition ~S -> ~S dated ~D, not ~D" exp-state state since next-height))
                (ecase state
                  (:defined
                   (fuzz-assert (and (zerop since) (eq exp-state :defined)
                                     (< (mtp current) (bl.val:vb-deployment-start-time dep)))
                                "DEFINED at since ~D from ~S" since exp-state))
                  (:started
                   (fuzz-assert (>= (mtp current) (bl.val:vb-deployment-start-time dep)))
                   (if (eq exp-state :started)
                       (fuzz-assert (and (< blocks-sig threshold)
                                         (< (mtp current) (bl.val:vb-deployment-timeout dep)))
                                    "still STARTED with ~D of ~D signalling" blocks-sig threshold)
                       (fuzz-assert (eq exp-state :defined))))
                  (:locked-in
                   (if (eq exp-state :locked-in)
                       (fuzz-assert (< next-height (bl.val:vb-deployment-min-activation-height dep))
                                    "still LOCKED_IN at ~D past the activation height ~D"
                                    next-height (bl.val:vb-deployment-min-activation-height dep))
                       (fuzz-assert (and (eq exp-state :started) (>= blocks-sig threshold))
                                    "LOCKED_IN from ~S with ~D of ~D" exp-state blocks-sig threshold)))
                  (:active
                   (fuzz-assert (or always-active
                                    (<= (bl.val:vb-deployment-min-activation-height dep) next-height)))
                   (fuzz-assert (member exp-state '(:active :locked-in))))
                  (:failed
                   (fuzz-assert (or never-active (>= (mtp current) (bl.val:vb-deployment-timeout dep))))
                   (if (eq exp-state :started)
                       (fuzz-assert (< blocks-sig threshold))
                       (fuzz-assert (eq exp-state :failed)))))
                (when (>= size (* period max-periods))
                  (fuzz-assert (member state '(:active :failed))
                               "~S after ~D blocks" state size))
                (cond (always-active
                       (fuzz-assert (and (eq state :active) (eq exp-state :active) (zerop since))))
                      (never-active
                       (fuzz-assert (and (eq state :failed) (eq exp-state :failed) (zerop since))))
                      (t
                       (fuzz-assert (or (plusp since) (eq state :defined)))
                       (fuzz-assert (or (plusp exp-since) (eq exp-state :defined)))))))))))))
