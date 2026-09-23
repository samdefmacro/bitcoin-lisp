(in-package #:bitcoin-lisp)

;;;; Two of Core's threads that are small enough to be threads here as well
;;;;
;;;; Core runs a lightweight task scheduler on its own "scheduler" thread
;;;; (init.cpp:1457) and keeps the -addnode connections on "addcon"
;;;; (ThreadOpenAddedConnections, net.cpp:3530). Most of what Core's scheduler
;;;; runs lives on our sync thread instead -- the stale-tip check, the
;;;; peers.dat dump, the fee-estimate flush and the wallet resend all touch
;;;; state that thread owns without a lock -- so the scheduler thread here
;;;; carries only the two jobs that touch nothing the sync thread writes: the
;;;; five-minute disk-space check (init.cpp:1464-1473) and closing the log
;;;; rate limiter's window (init.cpp:1475-1479). The addcon thread decides
;;;; when each added node is dialed, on Core's cadence, and hands the dial to
;;;; the sync thread through the queue `addnode onetry' uses, because a peer's
;;;; socket is only ever read by one thread.

(defvar *scheduler-thread* nil
  "The running scheduler thread, or NIL.")

(defvar *scheduler-stop* nil
  "Set to ask the scheduler thread to return.")

(defconstant +scheduler-disk-check-seconds+ 300
  "Core checks the blocks directory's free space every five minutes from the
scheduler (init.cpp:1464-1473).")

(defun %sleep-while (predicate seconds)
  "Sleep up to SECONDS, in tenths, for as long as PREDICATE holds. Returns T
when the full time passed, NIL when PREDICATE ended it (Core's
m_interrupt_net->sleep_for, which returns false once interrupted)."
  (loop repeat (max 1 (round (* seconds 10)))
        do (unless (funcall predicate) (return-from %sleep-while nil))
           (sleep 0.1))
  (funcall predicate))

(defun %scheduler-loop (node)
  "The scheduler thread's service loop (CScheduler::serviceQueue with the two
tasks start-up schedules on it here)."
  (let ((next-disk-check (+ (get-universal-time) +scheduler-disk-check-seconds+)))
    (loop while (%sleep-while (lambda () (not *scheduler-stop*)) 1)
          do (bl.log:log-rate-limiter-tick)
             (when (>= (get-universal-time) next-disk-check)
               (setf next-disk-check (+ (get-universal-time) +scheduler-disk-check-seconds+))
               (let ((dir (node-data-directory node)))
                 (when (and dir (not (check-disk-space dir)))
                   (log-error "Shutting down due to lack of disk space!")
                   (request-node-shutdown "lack of disk space"
                                          :exit-code +node-exit-error+)))))))

(defun start-scheduler-thread (node)
  "Start Core's lightweight task scheduler thread (init.cpp:1452-1457)."
  (setf *scheduler-stop* nil
        *scheduler-thread*
        (bt:make-thread (lambda ()
                          (bl.log:trace-thread "scheduler"
                                               (lambda () (%scheduler-loop node))))
                        :name "bitcoin-scheduler")))

(defun stop-scheduler-thread ()
  "Stop and join the scheduler thread (CScheduler::stop, init.cpp:405-410)."
  (let ((thread *scheduler-thread*))
    (setf *scheduler-stop* t
          *scheduler-thread* nil)
    (when thread
      (bl.net:join-thread-or-destroy
       thread :deadline (+ (get-internal-real-time)
                           (* 5 internal-time-units-per-second))))))

(defun %queue-added-node-dial (node spec)
  "Hand the dial of added node SPEC to the sync thread, unless one is already
queued. Returns T when this call queued it."
  (bt:with-recursive-lock-held ((node-lock node))
    (unless (assoc spec (node-pending-onetry node) :test #'string=)
      (setf (node-pending-onetry node)
            (append (node-pending-onetry node) (list (cons spec t))))
      t)))

(defun %addcon-loop (node)
  "Core ThreadOpenAddedConnections (net.cpp:2969-2997): each added node that
is not connected is dialed, half a second apart; then wait 60 seconds if
anything was tried and two otherwise."
  (flet ((running () (node-running node)))
    (loop
      (let ((tried nil))
        (when (node-network-active node)
          (dolist (spec (bt:with-recursive-lock-held ((node-lock node))
                          (copy-list (node-added-nodes node))))
            (multiple-value-bind (host port) (parse-node-endpoint node spec)
              (unless (peer-connected-to-endpoint-p node host port)
                (%queue-added-node-dial node spec)
                (setf tried t)
                (unless (%sleep-while #'running 0.5)
                  (return-from %addcon-loop))))))
        (unless (%sleep-while #'running (if tried 60 2))
          (return-from %addcon-loop))))))

(defun start-addcon-thread (node)
  "Start the added-connections thread (CConnman::Start, net.cpp:3529-3530)."
  (setf *addcon-thread*
        (bt:make-thread (lambda ()
                          (bl.log:trace-thread "addcon" (lambda () (%addcon-loop node))))
                        :name "bitcoin-addcon")))

(defun stop-addcon-thread ()
  "Join the added-connections thread, which returns once NODE-RUNNING is off."
  (let ((thread *addcon-thread*))
    (setf *addcon-thread* nil)
    (when thread
      (bl.net:join-thread-or-destroy
       thread :deadline (+ (get-internal-real-time)
                           (* 5 internal-time-units-per-second))))))
