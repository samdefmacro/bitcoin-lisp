(in-package #:bitcoin-lisp.tests)

;;;; Core node/timeoffsets.cpp and its drive sites: the median of the last 50
;;;; outbound peers' clock offsets, the CLOCK_OUT_OF_SYNC warning past ten
;;;; minutes, and getnetworkinfo's "timeoffset" (test/timeoffsets_tests.cpp).

(def-suite :timeoffsets-tests
  :description "Core TimeOffsets: outbound clock offsets, their median and warning"
  :in :bitcoin-lisp-tests)

(in-suite :timeoffsets-tests)

(defun %time-offsets-of (samples)
  "A fresh TimeOffsets holding SAMPLES, added in order (Core AddMulti)."
  (let ((offsets (bl.net:make-time-offsets)))
    (dolist (s samples offsets)
      (bl.net:time-offsets-add offsets s))))

(defun %clock-warning-p ()
  (some (lambda (m) (search "out of sync with the network" m))
        (coerce (bl.log:warnings-for-rpc) 'list)))

(test time-offsets-median-is-cores
  "timeoffsets_tests.cpp:21-42: 0 below five samples, the upper median at or
above, and at 50 samples the oldest one goes."
  (let ((offsets (%time-offsets-of '(0 -1 -2 -3))))
    (is (= 0 (bl.net:time-offsets-median offsets)) "four samples: no median yet")
    (bl.net:time-offsets-add offsets -4)
    (is (= -2 (bl.net:time-offsets-median offsets)))
    (dotimes (_ 4) (bl.net:time-offsets-add offsets 5))
    (is (= 0 (bl.net:time-offsets-median offsets)))
    (dotimes (_ 41) (bl.net:time-offsets-add offsets 10))
    (is (= 10 (bl.net:time-offsets-median offsets)))
    (dotimes (_ 25) (bl.net:time-offsets-add offsets 15))
    (is (= 15 (bl.net:time-offsets-median offsets))
        "25 tens then 25 fifteens: the first nine samples are gone")))

(test time-offsets-warn-past-ten-minutes
  "timeoffsets_tests.cpp:52-58, and the warning reaches the RPC `warnings' array
and leaves it once the median is back within ten minutes."
  (bl.log:reset-warnings)
  (unwind-protect
       (flet ((raised-p (samples)
                (bl.net:time-offsets-warn-if-out-of-sync (%time-offsets-of samples))))
         (is-true (raised-p (list -3600 -2400 -1800 0 600)))
         (is-true (raised-p (make-list 5 :initial-element 660)))
         (is-false (raised-p (make-list 4 :initial-element 3600)) "four samples have no median")
         (is-false (raised-p (make-list 100 :initial-element 180)))
         (let ((offsets (%time-offsets-of (make-list 5 :initial-element -660))))
           (bl.net:time-offsets-warn-if-out-of-sync offsets)
           (is-true (%clock-warning-p))
           (dotimes (_ 6) (bl.net:time-offsets-add offsets 0))
           (bl.net:time-offsets-warn-if-out-of-sync offsets)
           (is-false (%clock-warning-p))))
    (bl.log:reset-warnings)))

(defun %handshake-with-clock (peer offset &key inbound)
  "Run PEER's handshake against a scripted VERSION whose timestamp is OFFSET
seconds from now, with our sends discarded. INBOUND uses the inbound path."
  (let ((script (list (lambda ()
                        (values "version"
                                (bl.ser:make-version-message-bytes
                                 :services (logior bl.ser:+node-network+ bl.ser:+node-witness+)
                                 :timestamp (+ (bl.ser:get-unix-time) offset))))))
        (real-send (fdefinition 'bl.net:send-message))
        (real-receive (fdefinition 'bl.net:receive-message-blocking))
        (bl.net:*v2-transport-enabled* nil))
    (unwind-protect
         (progn
           (setf (fdefinition 'bl.net:send-message) (lambda (p m) (declare (ignore p m)) t)
                 (fdefinition 'bl.net:receive-message-blocking)
                 (lambda (p &key timeout)
                   (declare (ignore p timeout))
                   (let ((next (pop script)))
                     (if next (funcall next) (values nil nil)))))
           (if inbound
               (bl.net:perform-inbound-handshake peer :timeout 1)
               (bl.net:perform-handshake peer :conn-type :feeler :try-v2 nil)))
      (setf (fdefinition 'bl.net:send-message) real-send
            (fdefinition 'bl.net:receive-message-blocking) real-receive))))

(test outbound-versions-feed-the-clock-check
  "net_processing.cpp:3793-3799: every VERSION from a connection we opened adds
its peer's offset and re-checks the warning; an inbound one only sets the
peer's own offset. getnetworkinfo's timeoffset is the median (rpc/net.cpp:707)."
  (let ((bl.net:*outbound-time-offsets* (bl.net:make-time-offsets)))
    (bl.log:reset-warnings)
    (unwind-protect
         (progn
           (dotimes (i 5)
             (%handshake-with-clock (bl.net:make-peer :id (+ 700 i) :address "20.0.0.1"
                                                     :inbound t :conn-type :inbound)
                                    -3600 :inbound t))
           (is (= 0 (bl.net:time-offsets-median bl.net:*outbound-time-offsets*))
               "five inbound peers an hour behind add nothing")
           (is-false (%clock-warning-p))
           (dotimes (i 5)
             (%handshake-with-clock (bl.net:make-peer :id (+ 710 i) :address "20.0.0.2") -3600))
           (is (<= -3601 (bl.net:time-offsets-median bl.net:*outbound-time-offsets*) -3599)
               "five outbound peers an hour behind are the median")
           (is-true (%clock-warning-p) "and raise the clock warning")
           (is (= (bl.net:time-offsets-median bl.net:*outbound-time-offsets*)
                  (cdr (assoc "timeoffset"
                              (bl.rpc:dispatch-rpc-method (make-test-node) "getnetworkinfo" nil)
                              :test #'string=)))
               "getnetworkinfo reports it"))
      (bl.log:reset-warnings))))
