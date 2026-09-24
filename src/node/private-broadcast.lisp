(in-package #:bitcoin-lisp)

;;;; The private-broadcast opener (Core CConnman::ThreadPrivateBroadcast)
;;;;
;;;; A thread of its own under -privatebroadcast (net.cpp:3554-3556): it waits
;;;; until connections are wanted, picks Tor, I2P or -- through the Tor proxy,
;;;; once that proxy has been seen to work -- IPv4/IPv6, draws an address of
;;;; that network from addrman, dials it as a private-broadcast connection and
;;;; hands the connection to a conversation thread
;;;; (BL.NET:RUN-PRIVATE-BROADCAST-CONNECTION). The queue, the conversation and
;;;; the connection count are in networking/private-broadcast.lisp.

(defparameter +max-private-broadcast-connections+ 64
  "Core's MAX_PRIVATE_BROADCAST_CONNECTIONS (net.h:77): the connections
reserved for private broadcast (TRIM-MAX-CONNECTIONS), and the most open at
once (m_sem_conn_max).")

(defvar *private-broadcast-thread* nil
  "The running private-broadcast opener thread, or NIL.")

(defvar *private-broadcast-conversations* 0
  "Private-broadcast connections open now; Core bounds them with m_sem_conn_max
(MAX_PRIVATE_BROADCAST_CONNECTIONS).")

(defvar *private-broadcast-conversations-lock* (bt:make-lock "private-broadcast-conversations"))

(defvar *next-private-broadcast-reattempt* 0
  "Scheduler-clock time of the next ReattemptPrivateBroadcast pass; 0 = at once,
as Core schedules the first one 0 min out (net_processing.cpp:2040-2042).")

(defun %private-broadcast-pick-network ()
  "Core PrivateBroadcast::PickNetwork (net.cpp:3054-3085): (values NETWORK
PROXY) -- Tor when reachable, and then IPv4/IPv6 too when the Tor proxy has
carried an outbound connection (ProxyForIPv4or6, :3113-3120), which is also
the PROXY those two are dialed through; I2P when reachable. NIL when neither
Tor nor I2P is."
  (let ((nets '()) (clearnet-proxy nil))
    (when (bl.net:reachable-network-p :torv3)
      (push :torv3 nets)
      (setf clearnet-proxy (and bl.net:*outbound-tor-ok-at-least-once*
                                bl.net:*onion-proxy*))
      (when clearnet-proxy
        (dolist (net '(:ipv4 :ipv6))
          (when (bl.net:reachable-network-p net) (push net nets)))))
    (when (bl.net:reachable-network-p :i2p) (push :i2p nets))
    (when nets
      (let ((net (nth (random (length nets)) nets)))
        (values net (and (member net '(:ipv4 :ipv6)) clearnet-proxy))))))

(defun %local-address-p (pa)
  "Core IsLocal (net.cpp:329-333): PA is one of our own addresses."
  (find-if (lambda (la)
             (and (eq (bl.net:local-address-network la) (bl.net:peer-address-network pa))
                  (equalp (bl.net:local-address-bytes la) (bl.net:peer-address-ip pa))))
           (bl.net:local-addresses)))

(defun %start-private-broadcast-conversation (peer)
  "Run PEER's private-broadcast conversation on its own thread, counted
against MAX_PRIVATE_BROADCAST_CONNECTIONS."
  (bt:with-lock-held (*private-broadcast-conversations-lock*)
    (incf *private-broadcast-conversations*))
  (bt:make-thread
   (lambda ()
     (unwind-protect
          (handler-case (bl.net:run-private-broadcast-connection peer)
            (error (e)
              (log-debug "private broadcast conversation with peer=~D failed: ~A"
                         (bl.net:peer-id peer) e)))
       (bt:with-lock-held (*private-broadcast-conversations-lock*)
         (decf *private-broadcast-conversations*))))
   :name "bitcoin-privbcast-conn"))

(defun %private-broadcast-open-one (node)
  "One pass of ThreadPrivateBroadcast's loop body (net.cpp:3224-3270) once a
connection is wanted. Returns the seconds to pause before the next pass."
  (multiple-value-bind (net proxy) (%private-broadcast-pick-network)
    (unless net
      (log-warn "Unable to open -privatebroadcast connections: neither Tor nor I2P is reachable")
      (return-from %private-broadcast-open-one 5))
    (let ((pa (and (node-address-book node)
                   (bl.net:address-book-select (node-address-book node) :networks (list net)))))
      (when (or (null pa) (%local-address-p pa))
        (return-from %private-broadcast-open-one 0.5))
      (let* ((host (bl.net:peer-address-string pa))
             (port (bl.net:peer-address-port pa))
             (target (format nil "~A~@[ through the proxy at ~A~]"
                             (format nil (if (find #\: host) "[~A]:~D" "~A:~D") host port)
                             (and proxy (format nil "~A:~D" (bl.net:proxy-host proxy)
                                                (bl.net:proxy-port proxy)))))
             (peer (%dial-outbound-peer node host port t
                                        :conn-type :private-broadcast :use-v2 nil
                                        :proxy proxy)))
        (cond
          (peer
           (setf (bl.net:peer-address peer) host)
           (bl:log-cat "privatebroadcast" "Socket connected to ~A; remaining connections to open: ~D"
                       target (bl.net:private-broadcast-num-to-open-sub 1))
           (%start-private-broadcast-conversation peer)
           0)
          ((zerop (bl.net:private-broadcast-num-to-open))
           (bl:log-cat "privatebroadcast"
                       "Failed to connect to ~A, will not retry, no more connections needed" target)
           0)
          (t
           (bl:log-cat "privatebroadcast"
                       "Failed to connect to ~A, will retry to a different address; remaining connections to open: ~D"
                       target (bl.net:private-broadcast-num-to-open))
           0.1))))))

(defun %private-broadcast-loop (node)
  "Core ThreadPrivateBroadcast (net.cpp:3206-3270)."
  (flet ((running () (node-running node)))
    (loop while (running)
          do (cond
               ((not (node-network-active node)) (%sleep-while #'running 5))
               ((>= *private-broadcast-conversations* +max-private-broadcast-connections+)
                (%sleep-while #'running 0.1))
               ((bl.net:private-broadcast-wait-to-open #'running)
                (let ((pause (%private-broadcast-open-one node)))
                  (when (plusp pause) (%sleep-while #'running pause))))))))

(defun start-private-broadcast-thread (node)
  "Start the opener under -privatebroadcast (net.cpp:3554-3556)."
  (bl.net:reset-private-broadcast)
  (setf *next-private-broadcast-reattempt* 0)
  (when *private-broadcast*
    (setf *private-broadcast-thread*
          (bt:make-thread (lambda ()
                            (bl.log:trace-thread "privbcast"
                                                 (lambda () (%private-broadcast-loop node))))
                          :name "bitcoin-privbcast"))))

(defun stop-private-broadcast-thread ()
  "Join the opener, which returns once NODE-RUNNING is off (net.cpp:3609-3617)."
  (let ((thread *private-broadcast-thread*))
    (setf *private-broadcast-thread* nil)
    (when thread
      (bl.net:join-thread-or-destroy
       thread :deadline (+ (get-internal-real-time)
                           (* 5 internal-time-units-per-second))))))

(defun %reattempt-private-broadcast (node)
  "Core ReattemptPrivateBroadcast (net_processing.cpp:1645-1674): each stale
queued transaction that would still enter the mempool gets one more
connection; one that would not is given up."
  (let ((wanted 0))
    (dolist (tx (bl.net:private-broadcast-stale))
      (let ((txid (bl.crypto:bytes-to-hex (bl.crypto:reverse-bytes (bl.ser:transaction-hash tx))))
            (wtxid (bl.crypto:bytes-to-hex (bl.crypto:reverse-bytes (bl.ser:transaction-wtxid tx)))))
        (multiple-value-bind (valid error)
            (bt:with-recursive-lock-held ((node-lock node))
              (bl.val:validate-transaction-for-mempool
               tx (node-utxo-set node) (node-mempool node)
               (bl.store:current-height (node-chain-state node))
               :chain-state (node-chain-state node)))
          (cond
            (valid
             (bl:log-cat "privatebroadcast" "Reattempting broadcast of stale txid=~A wtxid=~A" txid wtxid)
             (incf wanted))
            (t
             (bl:log-cat "privatebroadcast" "Giving up broadcast attempts for txid=~A wtxid=~A: ~A"
                         txid wtxid (bl.val:tx-reject-reason-string error))
             (bl.net:private-broadcast-remove tx))))))
    (when (plusp wanted)
      (bl.net:private-broadcast-num-to-open-add wanted))))

(defun maybe-reattempt-private-broadcast (node)
  "Run %REATTEMPT-PRIVATE-BROADCAST when due on the scheduler's clock: at once,
then every 2 min plus up to 1 more (net_processing.cpp:1672-1673)."
  (when *private-broadcast*
    (let ((now (bl.ser:get-scheduler-time)))
      (when (>= now *next-private-broadcast-reattempt*)
        (setf *next-private-broadcast-reattempt* (+ now 120 (random 60)))
        (%reattempt-private-broadcast node)))))
