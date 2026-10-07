(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/txrequest.cpp at the pin (d3056bc149): the
;;;; TxRequestTracker against a naive reimplementation -- one announcement
;;;; slot per (txhash, peer) for sixteen txhashes and sixteen peers, each
;;;; NOTHING, CANDIDATE, REQUESTED or COMPLETED -- driven by a byte stream of
;;;; commands, with every GetRequestable checked against the model (its
;;;; requests in announcement order and its expiries) and a full comparison of
;;;; counts, candidate peers and states at the end, then SanityCheck.
;;;;
;;;; The tracker is src/networking/txrequest.lisp, an object with Core's API,
;;;; so this is Core's Tester line for line: peers are the integers 0-15
;;;; (Core's NodeId), times are integers in Core's microseconds, and the
;;;; priority salt is Core's deterministic one, k0 = k1 = 0.

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
    delays)
  "Core's DELAYS table (txrequest.cpp:30-50), in microseconds.")

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
  "Every GetRequestable answer is the model's -- for each txhash the ready
candidate of highest salted priority while nothing is in flight, in
announcement order, under its own id type -- and so is every expiry it
reports; a response, a forgotten hash, a disconnect and a RequestedTx move
exactly what Core's do; and at the end every count, every candidate-peer set
and SanityCheck agree with the model."
  (let* ((tr (bl.net:make-tx-request-tracker))
         (anns (make-array '(16 16)))
         (events '())
         (sequence 0)
         (now 244466666)
         (it 0))
    (dotimes (h 16) (dotimes (p 16) (setf (aref anns h p) (make-txrequest-ann))))
    (labels ((next-byte () (if (< it (length buffer)) (prog1 (aref buffer it) (incf it)) 0))
             (hash (h) (aref *txrequest-hashes* h))
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
             (drop-past-events ()
               (setf events (remove-if (lambda (e) (<= e now)) events)))
             (advance-time (offset)
               (incf now offset)
               (drop-past-events))
             (advance-to-event ()
               (drop-past-events)
               (when events
                 (let ((next (reduce #'min events)))
                   (setf now next
                         events (remove next events :count 1)))))
             (disconnected-peer (p)
               (dotimes (h 16)
                 (unless (eq (txrequest-ann-state (aref anns h p)) :nothing)
                   (setf (txrequest-ann-state (aref anns h p)) :nothing)
                   (cleanup h)))
               (bl.net:txrequest-disconnected-peer tr p))
             (forget-tx-hash (h)
               (dotimes (p 16) (setf (txrequest-ann-state (aref anns h p)) :nothing))
               (cleanup h)
               (bl.net:txrequest-forget-tx-hash tr (hash h)))
             (received-inv (p h wtxidp preferred reqtime)
               (let ((a (aref anns h p)))
                 (when (eq (txrequest-ann-state a) :nothing)
                   (setf (txrequest-ann-state a) :candidate
                         (txrequest-ann-time a) reqtime
                         (txrequest-ann-wtxid a) wtxidp
                         (txrequest-ann-sequence a) (prog1 sequence (incf sequence))
                         (txrequest-ann-priority a) (txrequest-priority (hash h) p preferred 0 0))
                   (when (> reqtime now) (push reqtime events))))
               (bl.net:txrequest-received-inv tr p (hash h) wtxidp preferred reqtime))
             (requested-tx (p h exptime)
               (when (eq (txrequest-ann-state (aref anns h p)) :candidate)
                 (dotimes (p2 16)
                   (when (eq (txrequest-ann-state (aref anns h p2)) :requested)
                     (setf (txrequest-ann-state (aref anns h p2)) :completed)))
                 (setf (txrequest-ann-state (aref anns h p)) :requested
                       (txrequest-ann-time (aref anns h p)) exptime))
               (when (> exptime now) (push exptime events))
               (bl.net:txrequest-requested-tx tr p (hash h) exptime))
             (received-response (p h)
               (unless (eq (txrequest-ann-state (aref anns h p)) :nothing)
                 (setf (txrequest-ann-state (aref anns h p)) :completed)
                 (cleanup h))
               (bl.net:txrequest-received-response tr p (hash h)))
             (get-requestable (p)
               (let ((result '()) (expected-expired '()))
                 (dotimes (h 16)
                   ;; Mark any expired REQUESTED announcement COMPLETED.
                   (dotimes (p2 16)
                     (let ((a2 (aref anns h p2)))
                       (when (and (eq (txrequest-ann-state a2) :requested)
                                  (<= (txrequest-ann-time a2) now))
                         (push (list p2 h (txrequest-ann-wtxid a2)) expected-expired)
                         (setf (txrequest-ann-state a2) :completed)
                         (return))))
                   (cleanup h)
                   (let ((a (aref anns h p)))
                     (when (and (eq (txrequest-ann-state a) :candidate)
                                (eql (selected h) p))
                       (push (list (txrequest-ann-sequence a) h (txrequest-ann-wtxid a)) result))))
                 (setf result (sort result #'< :key #'first))
                 (multiple-value-bind (actual expired)
                     (bl.net:txrequest-get-requestable tr p now)
                   (let ((got (sort (mapcar (lambda (e)
                                              (list (first e) (position (second e) *txrequest-hashes*
                                                                        :test #'equalp)
                                                    (and (cddr e) t)))
                                            expired)
                                    #'< :key (lambda (e) (+ (* 100 (first e)) (second e)))))
                         (want (sort expected-expired #'< :key (lambda (e) (+ (* 100 (first e)) (second e))))))
                     (fuzz-assert (equal got (fuzz-sabotage want))
                                  "GetRequestable(~D) expired ~S, the model ~S" p got want))
                   (fuzz-assert (= (length result) (length actual))
                                "GetRequestable(~D) returned ~D, the model ~D" p (length actual) (length result))
                   (loop for (nil h wtxidp) in result
                         for (hash . actual-wtxidp) in actual
                         do (fuzz-assert (and (equalp (hash h) hash) (eq wtxidp actual-wtxidp))
                                         "GetRequestable(~D) out of order or of the wrong id type" p))))))
      (with-tx-request-salt (0 0)
        (loop while (< it (length buffer))
              do (let ((cmd (mod (next-byte) 11)))
                   (case cmd
                     (0 (advance-to-event))
                     (1 (advance-time (aref *txrequest-delays* (next-byte))))
                     (2 (get-requestable (mod (next-byte) 16)))
                     (3 (disconnected-peer (mod (next-byte) 16)))
                     (4 (forget-tx-hash (mod (next-byte) 16)))
                     ((5 6)
                      (let ((p (mod (next-byte) 16)) (txidnum (next-byte)))
                        (received-inv p (mod txidnum 16) (logbitp 0 (floor txidnum 16)) (logbitp 0 cmd)
                                      most-negative-fixnum)))
                     ((7 8)
                      (let ((p (mod (next-byte) 16)) (txidnum (next-byte)) (delaynum (next-byte)))
                        (received-inv p (mod txidnum 16) (logbitp 0 (floor txidnum 16)) (logbitp 0 cmd)
                                      (+ now (aref *txrequest-delays* delaynum)))))
                     (9 (let ((p (mod (next-byte) 16)) (txidnum (next-byte)) (delaynum (next-byte)))
                          (requested-tx p (mod txidnum 16) (+ now (aref *txrequest-delays* delaynum)))))
                     (10 (let ((p (mod (next-byte) 16)) (txidnum (next-byte)))
                           (received-response p (mod txidnum 16)))))))
        ;; Check (:291-322).
        (let ((total 0))
          (dotimes (p 16)
            (let ((tracked 0) (inflight 0) (candidates 0))
              (dotimes (h 16)
                (let ((st (txrequest-ann-state (aref anns h p))))
                  (unless (eq st :nothing) (incf tracked))
                  (when (eq st :requested) (incf inflight))
                  (when (eq st :candidate) (incf candidates))))
              (fuzz-assert (= (bl.net:txrequest-count tr p) tracked)
                           "peer ~D: Count ~D, model ~D" p (bl.net:txrequest-count tr p) tracked)
              (fuzz-assert (= (bl.net:txrequest-count-in-flight tr p) inflight)
                           "peer ~D: CountInFlight ~D, model ~D" p
                           (bl.net:txrequest-count-in-flight tr p) inflight)
              (fuzz-assert (= (fuzz-sabotage (bl.net:txrequest-count-candidates tr p)) candidates)
                           "peer ~D: CountCandidates ~D, model ~D" p
                           (bl.net:txrequest-count-candidates tr p) candidates)
              (incf total tracked)))
          (dotimes (h 16)
            (let ((expect (loop for p below 16
                                when (member (txrequest-ann-state (aref anns h p)) '(:candidate :requested))
                                  collect p))
                  (got (bl.net:txrequest-get-candidate-peers tr (hash h))))
              (fuzz-assert (and (= (length expect) (length got))
                                (every (lambda (x) (member x expect)) got))
                           "hash ~D: candidate peers differ" h)))
          (fuzz-assert (= (bl.net:txrequest-size tr) total)
                       "Size ~D, the model ~D" (bl.net:txrequest-size tr) total)
          (let ((problems (bl.net:txrequest-sanity-check tr)))
            (fuzz-assert (null problems) "SanityCheck: ~{~A~^; ~}" problems)))))))

(test txrequest-pinned-buffers
  "The buffers the first txrequest port found failing, replayed through
Core's tester as it stands. The first draw asked a wtxid announcer for its
hash by txid, the tracker keeping one id type per hash (fixed in `Net: a tx
request goes out under the id type of the announcement it is granted to'); the
27th then asked a newcomer ahead of a ready candidate of higher priority (fixed
in `Net: an announcement is asked for at once only when it is the best
candidate')."
  (is (null (replay-fuzz-target
             'txrequest
             "fd073175d97ca7f852bf60d1a10b3d7cd7aec20c0cf4f7055fc647ec7d04edf3759fe26fea30e324a447ba79f1648941f9a07e464af0c33d3676448eec95e80ea3de873c564db6c3d9e2d9b2d56763bdb72623afb7cc6a87aa1ca537b7a054805901afbf9c6eb76c164b3a3cf0d7f0fda581e6837378bd6129a3b0966cac2d9b5bc8d4a1734e9250ddf8c641")))
  (is (null (replay-fuzz-target
             'txrequest
             "ded1a1f1963845d9aa5854741a4a2e8fc2fc80a3da9adf718b8abb3e372dada871cbd3b2a33443c4f94c3340e4ccca7d6e3be51da15331f52ce6172ab14418692496c665746aab3d765a8d2f6e616f68eb50dfd726af5fce95c4cb37151368df6954d4234b40be922c40d4b98f60abc7f9e896e235e866bc5fd401198b82dd2c5e88ecc1ce3de2b307017185ea6cb691b3f3218e982671a149af69de9d66d61a06b4fecbffcc88f0c3fbbe281e06806fc8885e2446a8af6bd9329c5800d2441a824f2562da4c61050bb5597d9a13523dd431133c5051e4baa54b26a165bed88f3e3b19c550d1c32313ac01e32c9ec3cb3f590721eccb01b9996ee1ea6ad7ec4fafd3de55da32feb744209727d17937cdb52721f47df4795b9013e050e505cfd04849a1a189ef8b8add50a5355c6a1710ea24b0f0e585de9b11fadde6c72b8872516e5d591ff56c16d780675def7b5b2cf4cf8cf5b45482ab9d344567ffac51122b16a9dceb40c276d0e68572014b6a030002fa010fa1f132a05ef45d4b32fa1b3ecbffd208a9709add0e67"))))
