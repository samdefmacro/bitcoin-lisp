(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/txrequest.cpp at the pin (d3056bc149): the
;;;; TxRequestTracker against a naive reimplementation -- one announcement
;;;; slot per (txhash, peer) for sixteen txhashes and sixteen peers, each
;;;; NOTHING, CANDIDATE, REQUESTED or COMPLETED -- driven by a byte stream of
;;;; commands, with every request the tracker makes checked against the model
;;;; and a full comparison of counts, candidate peers and states at the end.
;;;;
;;;; Our tracker (src/networking/protocol.lisp, `Tx-request tracking') is
;;;; Core's in a different shape, and the target is adapted to it, not to
;;;; Core's API:
;;;;   - an announcement's delay is the peer's (preferred outbound peers
;;;;     none, inbound peers NONPREF_PEER_TX_DELAY), not an argument, so peers
;;;;     0-7 are outbound and 8-15 inbound, and Core's delayed-inv commands
;;;;     (7, 8) announce like the immediate ones;
;;;;   - there is no GetRequestable(peer) + RequestedTx(peer): the scheduler
;;;;     pass (RETRY-TIMED-OUT-TX-REQUESTS, then PROCESS-TX-REQUESTS) grants
;;;;     every hash to its best candidate at once with the sixty-second
;;;;     GETDATA_TX_INTERVAL expiry, which is what GetRequestable for every
;;;;     peer followed by RequestedTx for each result does; commands 2 and 9
;;;;     both run it;
;;;;   - TX-REQUEST-WANTED-P requests a ready announcement AT ONCE, which
;;;;     Core does in the SendMessages that follows the inv: the model checks
;;;;     such a request is one GetRequestable would have made then.
;;;; The clock is the mockable one the tracker reads, in seconds; Core's delay
;;;; table (microseconds) is read in seconds, rounded.

(def-suite :fuzz-txrequest-tests :in :bitcoin-lisp-tests
  :description "Core fuzz/txrequest.cpp target")

(in-suite :fuzz-txrequest-tests)

(defparameter *txrequest-hashes*
  (coerce (loop for i below 16
                collect (bl.crypto:sha256 (make-array 1 :element-type '(unsigned-byte 8)
                                                        :initial-element i)))
          'simple-vector)
  "TXHASHES (txrequest.cpp:22-38): SHA256 of the single byte 0..15.")

(defparameter *txrequest-delays*
  (let ((delays (make-array 256 :initial-element 0))
        (prev 0))
    ;; DELAYS[N] (:30-50): N microseconds for N < 16; an exponentially
    ;; growing sequence to about 198 s for N < 128 (the SipHash of N with a
    ;; zero key, shifted); the negations for N >= 128.
    (dotimes (i 16) (setf (aref delays i) i prev i))
    (loop for i from 16 below 128
          do (let* ((diff-bits (floor (* (- i 10) 2) 9))
                    (key (let ((v (make-array 8 :element-type '(unsigned-byte 8))))
                           (dotimes (k 8 v) (setf (aref v k) (ldb (byte 8 (* 8 k)) i)))))
                    (diff (1+ (ash (bl.crypto:siphash-2-4 0 0 key) (- diff-bits 64)))))
               (setf prev (+ prev diff)
                     (aref delays i) prev)))
    (loop for i from 128 below 256
          do (setf (aref delays i) (- (aref delays (- 255 i)))))
    (map 'simple-vector (lambda (us) (round us 1000000)) delays))
  "Core's DELAYS table read in seconds, the unit of the tracker's clock.")

(defun txrequest-priority (hash peer-id preferred k0 k1)
  "Core PriorityComputer (txrequest.cpp:112-118): SipHash(k0, k1, txhash ||
peer) shifted right one bit, the preferred bit on top."
  (let ((message (concatenate '(vector (unsigned-byte 8))
                              hash
                              (let ((v (make-array 8 :element-type '(unsigned-byte 8))))
                                (dotimes (k 8 v) (setf (aref v k) (ldb (byte 8 (* 8 k)) peer-id)))))))
    (logior (ash (bl.crypto:siphash-2-4 k0 k1 message) -1)
            (if preferred (ash 1 63) 0))))

(defstruct (txrequest-ann (:constructor make-txrequest-ann ()))
  "Tester::Announcement (:74-83)."
  (state :nothing) (time 0) (sequence 0) (wtxid nil) (priority 0))

(define-fuzz-target txrequest
    (buffer :core "txrequest.cpp:325-389" :iterations 1000 :max-len 400)
  "Every request the tracker makes is the one Core's GetRequestable picks --
the ready candidate with the highest salted priority, only while nothing is
in flight -- and goes out under that announcement's own id type; an expired
request completes and fails over; a response, a forgotten hash and a
disconnect release exactly what Core's do; and at the end every
(txhash, peer) state, every count and every candidate-peer set is the
model's."
  (let* ((k0 #x0123456789abcdef) (k1 #xfedcba9876543210)
         (anns (make-array '(16 16)))
         (events '())
         (sequence 0)
         (now 1600000000)
         (peers (coerce (loop for p below 16
                              collect (bl.net:make-peer :state :ready :inbound (>= p 8)))
                        'simple-vector))
         (it 0))
    (dotimes (h 16) (dotimes (p 16) (setf (aref anns h p) (make-txrequest-ann))))
    (labels ((next-byte () (if (< it (length buffer)) (prog1 (aref buffer it) (incf it)) 0))
             (preferred-p (p) (< p 8))
             (cleanup (h)
               ;; Delete a txhash whose only announcements are COMPLETED.
               (let ((all-nothing t))
                 (dotimes (p 16)
                   (let ((st (txrequest-ann-state (aref anns h p))))
                     (unless (eq st :nothing)
                       (unless (eq st :completed) (return-from cleanup))
                       (setf all-nothing nil))))
                 (unless all-nothing
                   (dotimes (p 16) (setf (txrequest-ann-state (aref anns h p)) :nothing)))))
             (selected (h)
               ;; The best ready CANDIDATE for H, or NIL when a request is out.
               (let ((ret nil) (best 0))
                 (dotimes (p 16 ret)
                   (let ((a (aref anns h p)))
                     (when (eq (txrequest-ann-state a) :requested) (return nil))
                     (when (and (eq (txrequest-ann-state a) :candidate)
                                (<= (txrequest-ann-time a) now)
                                (or (null ret) (> (txrequest-ann-priority a) best)))
                       (setf ret p best (txrequest-ann-priority a)))))))
             (request (h p)
               ;; RequestedTx with the tracker's GETDATA_TX_INTERVAL expiry.
               (dotimes (p2 16)
                 (when (eq (txrequest-ann-state (aref anns h p2)) :requested)
                   (setf (txrequest-ann-state (aref anns h p2)) :completed)))
               (setf (txrequest-ann-state (aref anns h p)) :requested
                     (txrequest-ann-time (aref anns h p)) (+ now 60))
               (push (+ now 60) events))
             (set-now (time)
               (setf now time bl.ser:*mock-time* time)
               (setf events (remove-if (lambda (e) (<= e now)) events)))
             (check-in-flight (h)
               ;; The tracker's outstanding request for H is the model's, and
               ;; goes out as that announcement's id type.
               (let ((real (tx-request-in-flight-peer (aref *txrequest-hashes* h)))
                     (model (loop for p below 16
                                  when (eq (txrequest-ann-state (aref anns h p)) :requested)
                                    return p)))
                 (fuzz-assert (eq real (and model (aref peers model)))
                              "hash ~D: in flight to ~A, the model says peer ~A" h
                              (and real (position real peers)) model)
                 (when (and model (eq real (aref peers model)))
                   (fuzz-assert (eq (and (tx-request-wtxid-entry-p
                                          (aref *txrequest-hashes* h))
                                         t)
                                    (txrequest-ann-wtxid (aref anns h model)))
                                "hash ~D requested from peer ~D as a ~:[txid~;wtxid~], announced as a ~:[txid~;wtxid~]"
                                h model (tx-request-wtxid-entry-p (aref *txrequest-hashes* h))
                                (txrequest-ann-wtxid (aref anns h model))))))
             (scheduler-pass ()
               ;; GetRequestable for every peer: expire, then grant each hash
               ;; to its best ready candidate.
               (dotimes (h 16)
                 (dotimes (p 16)
                   (let ((a (aref anns h p)))
                     (when (and (eq (txrequest-ann-state a) :requested) (<= (txrequest-ann-time a) now))
                       (setf (txrequest-ann-state a) :completed)
                       (return))))
                 (cleanup h)
                 (let ((best (selected h)))
                   (when best (request h best))))
               (bl.net:retry-timed-out-tx-requests)
               (bl.net:process-tx-requests)
               (dotimes (h 16) (check-in-flight h))))
      (bl.net:reset-tx-requests)
      (let ((bl.ser:*mock-time* now))
        (with-tx-request-salt (k0 k1)
          (loop while (< it (length buffer))
                do (let ((cmd (mod (next-byte) 11)))
                     (case cmd
                       (0 (let ((next (reduce #'min events :initial-value most-positive-fixnum)))
                            (when (< next most-positive-fixnum) (set-now next))))
                       (1 (set-now (+ now (aref *txrequest-delays* (next-byte)))))
                       ((2 9) (when (= cmd 9) (next-byte) (next-byte) (next-byte))
                        (scheduler-pass))
                       (3 (let ((p (mod (next-byte) 16)))
                            (dotimes (h 16)
                              (unless (eq (txrequest-ann-state (aref anns h p)) :nothing)
                                (setf (txrequest-ann-state (aref anns h p)) :nothing)
                                (cleanup h)))
                            (bl.net:tx-request-disconnected-peer (aref peers p))))
                       (4 (let ((h (mod (next-byte) 16)))
                            (dotimes (p 16) (setf (txrequest-ann-state (aref anns h p)) :nothing))
                            (bl.net:tx-request-received (aref *txrequest-hashes* h))))
                       ((5 6 7 8)
                        (let* ((p (mod (next-byte) 16))
                               (txidnum (next-byte))
                               (h (mod txidnum 16))
                               (wtxid (logbitp 0 (floor txidnum 16)))
                               (a (aref anns h p)))
                          (when (>= cmd 7) (next-byte))
                          (when (eq (txrequest-ann-state a) :nothing)
                            (setf (txrequest-ann-state a) :candidate
                                  (txrequest-ann-time a) (if (preferred-p p) now (+ now 2))
                                  (txrequest-ann-wtxid a) wtxid
                                  (txrequest-ann-sequence a) (incf sequence)
                                  (txrequest-ann-priority a)
                                  (txrequest-priority (aref *txrequest-hashes* h)
                                                      (bl.net:peer-id (aref peers p))
                                                      (preferred-p p) k0 k1))
                            (when (> (txrequest-ann-time a) now)
                              (push (txrequest-ann-time a) events)))
                          (let ((requested (bl.net:tx-request-wanted-p
                                            (aref *txrequest-hashes* h) (aref peers p) wtxid 0)))
                            (when requested
                              ;; Core requests in the SendMessages after the inv,
                              ;; and only the best ready candidate.
                              (fuzz-assert (eql (selected h) p)
                                           "peer ~D was sent a request for hash ~D the model grants to ~A"
                                           p h (selected h))
                              (when (eql (selected h) p) (request h p)))
                            (check-in-flight h))))
                       (10 (let ((p (mod (next-byte) 16))
                                 (h (mod (next-byte) 16)))
                             (unless (eq (txrequest-ann-state (aref anns h p)) :nothing)
                               (setf (txrequest-ann-state (aref anns h p)) :completed)
                               (cleanup h))
                             (bl.net:tx-request-received-response (aref peers p) (aref *txrequest-hashes* h))
                             (check-in-flight h))))))
          ;; Check (:297-322).
          (let ((total 0))
            (dotimes (p 16)
              (let ((tracked 0) (inflight 0) (candidates 0))
                (dotimes (h 16)
                  (let ((st (txrequest-ann-state (aref anns h p)))
                        (hash (aref *txrequest-hashes* h)))
                    (unless (eq st :nothing) (incf tracked))
                    (when (eq st :requested) (incf inflight))
                    (when (eq st :candidate) (incf candidates))
                    ;; This (txhash, peer) slot is the model's.
                    (let ((real-state
                            (cond ((eq (tx-request-in-flight-peer hash) (aref peers p)) :requested)
                                  ((member (aref peers p) (tx-request-announcement-peers hash))
                                   :candidate)
                                  ((tx-request-completed-p hash (aref peers p)) :completed)
                                  (t :nothing))))
                      (fuzz-assert (eq (fuzz-sabotage-state real-state) st)
                                   "hash ~D peer ~D: tracker ~A, model ~A" h p real-state st))))
                (fuzz-assert (= (bl.net:tx-request-count (aref peers p)) tracked)
                             "peer ~D: Count ~D, model ~D" p (bl.net:tx-request-count (aref peers p)) tracked)
                (fuzz-assert (= (tx-request-peer-in-flight-count (aref peers p)) inflight)
                             "peer ~D: CountInFlight ~D, model ~D" p
                             (tx-request-peer-in-flight-count (aref peers p)) inflight)
                (incf total tracked)))
            (fuzz-assert (= total (loop for h below 16
                                        sum (length (tx-request-announcement-peers
                                                     (aref *txrequest-hashes* h) :completed t))))
                         "Size differs from the model")
            (dotimes (h 16)
              (let ((expect (loop for p below 16
                                  when (member (txrequest-ann-state (aref anns h p)) '(:candidate :requested))
                                    collect (aref peers p)))
                    (got (bl.net:tx-request-candidate-peers (aref *txrequest-hashes* h))))
                (fuzz-assert (and (= (length expect) (length got))
                                  (every (lambda (x) (member x expect)) got))
                             "hash ~D: candidate peers differ" h)))))))))

(defun fuzz-sabotage-state (state)
  "STATE, or -- in the positive-control run -- the next state of the four."
  (if (eq *fuzz-sabotage* :assert)
      (case state (:nothing :candidate) (:candidate :requested) (:requested :completed) (t :nothing))
      state))

(test txrequest-pinned-buffers
  "The buffers the txrequest port found failing, replayed. The first draw
asked a wtxid announcer for its hash by txid, the tracker keeping one id type
per hash (fixed in `Net: a tx request goes out under the id type of the
announcement it is granted to'); the 27th then asked a newcomer ahead of a
ready candidate of higher priority (fixed in `Net: an announcement is asked
for at once only when it is the best candidate')."
  (is (null (replay-fuzz-target
             'txrequest
             "fd073175d97ca7f852bf60d1a10b3d7cd7aec20c0cf4f7055fc647ec7d04edf3759fe26fea30e324a447ba79f1648941f9a07e464af0c33d3676448eec95e80ea3de873c564db6c3d9e2d9b2d56763bdb72623afb7cc6a87aa1ca537b7a054805901afbf9c6eb76c164b3a3cf0d7f0fda581e6837378bd6129a3b0966cac2d9b5bc8d4a1734e9250ddf8c641")))
  (is (null (replay-fuzz-target
             'txrequest
             "ded1a1f1963845d9aa5854741a4a2e8fc2fc80a3da9adf718b8abb3e372dada871cbd3b2a33443c4f94c3340e4ccca7d6e3be51da15331f52ce6172ab14418692496c665746aab3d765a8d2f6e616f68eb50dfd726af5fce95c4cb37151368df6954d4234b40be922c40d4b98f60abc7f9e896e235e866bc5fd401198b82dd2c5e88ecc1ce3de2b307017185ea6cb691b3f3218e982671a149af69de9d66d61a06b4fecbffcc88f0c3fbbe281e06806fc8885e2446a8af6bd9329c5800d2441a824f2562da4c61050bb5597d9a13523dd431133c5051e4baa54b26a165bed88f3e3b19c550d1c32313ac01e32c9ec3cb3f590721eccb01b9996ee1ea6ad7ec4fafd3de55da32feb744209727d17937cdb52721f47df4795b9013e050e505cfd04849a1a189ef8b8add50a5355c6a1710ea24b0f0e585de9b11fadde6c72b8872516e5d591ff56c16d780675def7b5b2cf4cf8cf5b45482ab9d344567ffac51122b16a9dceb40c276d0e68572014b6a030002fa010fa1f132a05ef45d4b32fa1b3ecbffd208a9709add0e67"))))
