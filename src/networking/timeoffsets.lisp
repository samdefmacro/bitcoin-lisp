(in-package #:bitcoin-lisp.networking)

;;;; Core node/timeoffsets.{h,cpp}: the clock offsets the last 50 outbound
;;;; peers reported in their VERSION, the median of those, and the
;;;; CLOCK_OUT_OF_SYNC warning raised when that median is more than ten
;;;; minutes off. PeerManagerImpl owns one (net_processing.cpp:793), feeds it
;;;; from every non-inbound VERSION (:3793-3799), and getnetworkinfo reports
;;;; its median as "timeoffset" (rpc/net.cpp:707, through
;;;; GetInfo's median_outbound_time_offset, net_processing.cpp:1855).

(defconstant +time-offsets-max-size+ 50
  "Core TimeOffsets::MAX_SIZE (timeoffsets.h): samples kept.")

(defconstant +time-offsets-warn-threshold+ (* 10 60)
  "Core TimeOffsets::WARN_THRESHOLD (timeoffsets.h): ten minutes, in seconds.")

(defstruct (time-offsets (:constructor make-time-offsets ()))
  "Core TimeOffsets: the samples, oldest first, under their own lock."
  (samples '() :type list)
  (lock (bt:make-lock "time-offsets")))

(defvar *outbound-time-offsets* (make-time-offsets)
  "Core PeerManagerImpl::m_outbound_time_offsets (net_processing.cpp:793).
Replaced by a fresh one at every node start, as Core builds a new PeerManager.")

(defun time-offsets-add (offsets seconds)
  "Core TimeOffsets::Add (timeoffsets.cpp:20-29): keep SECONDS, dropping the
oldest sample once MAX_SIZE are held."
  (bt:with-lock-held ((time-offsets-lock offsets))
    (let ((samples (time-offsets-samples offsets)))
      (setf (time-offsets-samples offsets)
            (append (if (>= (length samples) +time-offsets-max-size+) (rest samples) samples)
                    (list seconds)))
      (bl:log-cat "net" "Added time offset ~@Ds, total samples ~D"
                  seconds (length (time-offsets-samples offsets))))))

(defun time-offsets-median (offsets)
  "Core TimeOffsets::Median (timeoffsets.cpp:31-40): 0 below five samples,
otherwise the upper median of the sorted samples."
  (let ((samples (bt:with-lock-held ((time-offsets-lock offsets))
                   (copy-list (time-offsets-samples offsets)))))
    (if (< (length samples) 5)
        0
        (nth (floor (length samples) 2) (sort samples #'<)))))

(defun time-offsets-warn-if-out-of-sync (offsets)
  "Core TimeOffsets::WarnIfOutOfSync (timeoffsets.cpp:42-60): clear
CLOCK_OUT_OF_SYNC while the median is within ten minutes; otherwise log the
warning and set it. Returns T when the warning is raised."
  (cond ((<= (abs (time-offsets-median offsets)) +time-offsets-warn-threshold+)
         (bl.log:unset-warning :clock-out-of-sync)
         nil)
        (t
         (let ((message
                 (format nil "Your computer's date and time appear to be more than ~D minutes out of sync with the network, ~
this may lead to consensus failure. After you've confirmed your computer's clock, this message ~
should no longer appear when you restart your node. Without a restart, it should stop showing ~
automatically after you've connected to a sufficient number of new outbound peers, which may ~
take some time. You can inspect the `timeoffset` field of the `getpeerinfo` and `getnetworkinfo` ~
RPC methods to get more info."
                         (floor +time-offsets-warn-threshold+ 60))))
           (bl:log-warn "~A" message)
           (bl.log:set-warning :clock-out-of-sync message)
           t))))
