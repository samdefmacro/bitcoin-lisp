(in-package #:bitcoin-lisp.networking)

;;;; Private broadcast of our own transactions (-privatebroadcast)
;;;;
;;;; Core sends a locally submitted transaction without putting it in the
;;;; mempool: it opens short-lived connections to Tor or I2P peers (or to
;;;; IPv4/IPv6 peers THROUGH the Tor proxy), and on each one it says as little
;;;; as a connection can -- a VERSION with no services, no time, no addresses,
;;;; a fixed user agent and height 0 -- announces the one transaction, sends it
;;;; when asked, pings, and hangs up on the pong. The transaction is dropped
;;;; from the queue once it comes back to us from the network; until then it
;;;; is re-sent every few minutes.
;;;;
;;;; Three pieces of Core are here: the queue (private_broadcast.cpp,
;;;; PrivateBroadcast), the count of connections still to open
;;;; (CConnman::PrivateBroadcast in net.cpp:3087-3120) and the per-connection
;;;; conversation (net_processing.cpp's IsPrivateBroadcastConn branches). The
;;;; thread that opens the connections is the node's (node/private-broadcast.lisp,
;;;; Core ThreadPrivateBroadcast), because it needs the address book and the dial.
;;;;
;;;; A private-broadcast connection is driven start to finish by its own thread
;;;; and never joins the node's peer list, so the message pump never reads its
;;;; socket and nothing but this conversation is ever sent on it -- which is
;;;; the guarantee Core's IsOutboundMessageAllowedInPrivateBroadcast
;;;; (net.cpp:4049-4064) adds to its shared send path. It is therefore absent
;;;; from getpeerinfo, where Core lists it as "private-broadcast".

(defconstant +num-private-broadcast-per-tx+ 3
  "Core NUM_PRIVATE_BROADCAST_PER_TX (net_processing.cpp:201): connections
opened for each newly queued transaction.")

(defconstant +private-broadcast-max-connection-lifetime+ 180
  "Core PRIVATE_BROADCAST_MAX_CONNECTION_LIFETIME, 3 min (net_processing.cpp:
203): a private-broadcast connection that has not finished by then is dropped.")

(defconstant +private-broadcast-stale-seconds+ 60
  "Core STALE_DURATION, 1 min (private_broadcast.cpp:12): a transaction no peer
has confirmed within this long of its last confirmation is due a rebroadcast.")

(defparameter +private-broadcast-user-agent+ "/pynode:0.0.1/"
  "The user agent every private-broadcast VERSION carries, a constant other
than ours (net_processing.cpp:1561).")

(defstruct (pb-send-status (:constructor make-pb-send-status (peer-id address picked)))
  "Core PrivateBroadcast::SendStatus (private_broadcast.h:118-126): the peer a
transaction was picked for, its address, when, and when the peer confirmed
reception with a pong."
  (peer-id 0 :type integer)
  (address "" :type string)
  (picked 0 :type integer)
  (confirmed nil :type (or null integer)))

(defvar *private-broadcast-lock* (bt:make-lock "private-broadcast")
  "Guards the queue and the connection count (Core's m_mutex and the
atomic m_num_to_open).")

(defvar *private-broadcast-changed* (bt:make-condition-variable)
  "Signalled whenever the connection count rises (Core m_num_to_open.notify_all).")

(defvar *private-broadcast-txs* '()
  "Core PrivateBroadcast::m_transactions: (TX . SEND-STATUSES) per queued
transaction, keyed by wtxid, newest first.")

(defvar *private-broadcast-to-open* 0
  "Core CConnman::PrivateBroadcast::m_num_to_open: connections still wanted.")

(defvar *outbound-tor-ok-at-least-once* nil
  "Core m_outbound_tor_ok_at_least_once (net.h:1204): set the first time we
send VERACK to an outbound Tor peer. Until then the Tor proxy is not trusted
for clearnet private-broadcast connections (ProxyForIPv4or6, net.cpp:3113-3120).")

(defun reset-private-broadcast ()
  "Empty the queue and the connection count (node start, and tests)."
  (bt:with-lock-held (*private-broadcast-lock*)
    (setf *private-broadcast-txs* '()
          *private-broadcast-to-open* 0
          *outbound-tor-ok-at-least-once* nil)))

(defun %pb-find (tx)
  "The queue cell for TX, by wtxid. Caller holds the lock."
  (let ((wtxid (bl.ser:transaction-wtxid tx)))
    (find wtxid *private-broadcast-txs*
          :key (lambda (cell) (bl.ser:transaction-wtxid (car cell)))
          :test #'equalp)))

(defun %pb-priority (statuses)
  "Core DerivePriority (private_broadcast.cpp:125-137): (num-picked
num-confirmed last-picked last-confirmed) of a transaction's send statuses."
  (let ((last-picked 0) (confirmed 0) (last-confirmed 0))
    (dolist (s statuses)
      (setf last-picked (max last-picked (pb-send-status-picked s)))
      (when (pb-send-status-confirmed s)
        (incf confirmed)
        (setf last-confirmed (max last-confirmed (pb-send-status-confirmed s)))))
    (list (length statuses) confirmed last-picked last-confirmed)))

(defun %pb-more-urgent-p (a b)
  "T when priority A beats B (Core Priority::operator<=>, private_broadcast.h:
139-146): fewer picks, then fewer confirmations, then the older pick, then the
older confirmation."
  (loop for x in a for y in b
        when (< x y) return t
        when (> x y) return nil))

(defun private-broadcast-add (tx)
  "Core PrivateBroadcast::Add: queue TX; NIL when it is queued already."
  (bt:with-lock-held (*private-broadcast-lock*)
    (unless (%pb-find tx)
      (push (list tx) *private-broadcast-txs*)
      t)))

(defun %pb-remove (tx)
  "Remove TX's cell; its confirmation count, or NIL. Caller holds the lock."
  (let ((cell (%pb-find tx)))
    (when cell
      (setf *private-broadcast-txs* (remove cell *private-broadcast-txs*))
      (second (%pb-priority (cdr cell))))))

(defun private-broadcast-remove (tx)
  "Core PrivateBroadcast::Remove: forget TX; how many peers confirmed it, or
NIL when it was not queued."
  (bt:with-lock-held (*private-broadcast-lock*)
    (%pb-remove tx)))

(defun private-broadcast-pick-tx (peer-id address)
  "Core PickTxForSend (private_broadcast.cpp:34-51): the most urgent queued
transaction, remembered as sent to PEER-ID at ADDRESS; NIL when none."
  (bt:with-lock-held (*private-broadcast-lock*)
    (let ((best nil) (best-priority nil))
      (dolist (cell *private-broadcast-txs*)
        (let ((p (%pb-priority (cdr cell))))
          (when (or (null best) (%pb-more-urgent-p p best-priority))
            (setf best cell best-priority p))))
      (when best
        (setf (cdr best) (append (cdr best)
                                 (list (make-pb-send-status peer-id address
                                                            (bl.ser:get-unix-time)))))
        (car best)))))

(defun %pb-status-for-peer (peer-id)
  "(values TX STATUS) for the transaction picked for PEER-ID. Caller holds the lock."
  (dolist (cell *private-broadcast-txs*)
    (let ((s (find peer-id (cdr cell) :key #'pb-send-status-peer-id)))
      (when s (return (values (car cell) s))))))

(defun private-broadcast-tx-for-peer (peer-id)
  "Core GetTxForNode: the transaction picked for PEER-ID, or NIL."
  (bt:with-lock-held (*private-broadcast-lock*)
    (values (%pb-status-for-peer peer-id))))

(defun private-broadcast-confirm (peer-id)
  "Core NodeConfirmedReception: PEER-ID answered our ping."
  (bt:with-lock-held (*private-broadcast-lock*)
    (let ((s (nth-value 1 (%pb-status-for-peer peer-id))))
      (when s (setf (pb-send-status-confirmed s) (bl.ser:get-unix-time))))))

(defun private-broadcast-confirmed-p (peer-id)
  "Core DidNodeConfirmReception."
  (bt:with-lock-held (*private-broadcast-lock*)
    (let ((s (nth-value 1 (%pb-status-for-peer peer-id))))
      (and s (pb-send-status-confirmed s) t))))

(defun private-broadcast-pending-p ()
  "Core HavePendingTransactions."
  (bt:with-lock-held (*private-broadcast-lock*)
    (and *private-broadcast-txs* t)))

(defun private-broadcast-stale ()
  "Core GetStale (private_broadcast.cpp:95-107): the queued transactions no
peer has confirmed in the last minute -- one never confirmed included."
  (bt:with-lock-held (*private-broadcast-lock*)
    (let ((stale-time (- (bl.ser:get-unix-time) +private-broadcast-stale-seconds+)))
      (loop for (tx . statuses) in *private-broadcast-txs*
            when (< (fourth (%pb-priority statuses)) stale-time)
              collect tx))))

(defun private-broadcast-info ()
  "Core GetBroadcastInfo: (TX . SEND-STATUSES) per queued transaction, copied."
  (bt:with-lock-held (*private-broadcast-lock*)
    (loop for (tx . statuses) in (reverse *private-broadcast-txs*)
          collect (cons tx (mapcar #'copy-pb-send-status statuses)))))

;;; The count of connections still to open (Core NumToOpen*, net.cpp:3087-3111)

(defun private-broadcast-num-to-open ()
  (bt:with-lock-held (*private-broadcast-lock*) *private-broadcast-to-open*))

(defun private-broadcast-num-to-open-add (n)
  "Core NumToOpenAdd: N more connections wanted; wakes the opener."
  (bt:with-lock-held (*private-broadcast-lock*)
    (incf *private-broadcast-to-open* n)
    (bt:condition-notify *private-broadcast-changed*)))

(defun %pb-num-to-open-sub (n)
  "Caller holds the lock."
  (setf *private-broadcast-to-open* (max 0 (- *private-broadcast-to-open* n))))

(defun private-broadcast-num-to-open-sub (n)
  "Core NumToOpenSub: N fewer wanted, never below zero; the new count."
  (bt:with-lock-held (*private-broadcast-lock*)
    (%pb-num-to-open-sub n)))

(defun private-broadcast-wait-to-open (running-p)
  "Core NumToOpenWait: block until a connection is wanted or RUNNING-P turns
false (checked every second). T when one is wanted."
  (bt:with-lock-held (*private-broadcast-lock*)
    (loop
      (cond ((not (funcall running-p)) (return nil))
            ((plusp *private-broadcast-to-open*) (return t))
            (t (bt:condition-wait *private-broadcast-changed* *private-broadcast-lock*
                                  :timeout 1))))))

(defun %pb-tx-string (tx)
  (format nil "txid=~A, wtxid=~A"
          (bl.crypto:bytes-to-hex (bl.crypto:reverse-bytes (bl.ser:transaction-hash tx)))
          (bl.crypto:bytes-to-hex (bl.crypto:reverse-bytes (bl.ser:transaction-wtxid tx)))))

(defun initiate-tx-broadcast-private (tx)
  "Core InitiateTxBroadcastPrivate (net_processing.cpp:2268-2277): queue TX
and ask for NUM_PRIVATE_BROADCAST_PER_TX connections, or say it is queued."
  (if (private-broadcast-add tx)
      (progn
        (bl:log-cat "privatebroadcast" "Requesting ~D new connections due to ~A"
                    +num-private-broadcast-per-tx+ (%pb-tx-string tx))
        (private-broadcast-num-to-open-add +num-private-broadcast-per-tx+))
      (bl:log-cat "privatebroadcast"
                  "Ignoring unnecessary request to schedule an already scheduled transaction: ~A"
                  (%pb-tx-string tx))))

(defun private-broadcast-abort (id)
  "Core AbortPrivateBroadcast (net_processing.cpp:1865-1882): remove every
queued transaction whose txid or wtxid is ID, and cancel the connections it
still had coming. The removed transactions, oldest first."
  (bt:with-lock-held (*private-broadcast-lock*)
    (let ((removed '()) (cancelled 0))
      (dolist (cell (reverse *private-broadcast-txs*))
        (let ((tx (car cell)))
          (when (or (equalp id (bl.ser:transaction-hash tx))
                    (equalp id (bl.ser:transaction-wtxid tx)))
            (let ((acks (%pb-remove tx)))
              (push tx removed)
              (when (< acks +num-private-broadcast-per-tx+)
                (incf cancelled (- +num-private-broadcast-per-tx+ acks)))))))
      (%pb-num-to-open-sub cancelled)
      (nreverse removed))))

(defun note-own-tx-received-back (peer tx)
  "Core's TX-handler arm for a transaction we are privately broadcasting
(net_processing.cpp:4494-4503): it came back from the network, so stop, and
cancel the connections of the first NUM_PRIVATE_BROADCAST_PER_TX that were
not needed."
  (let ((broadcast (private-broadcast-remove tx)))
    (when broadcast
      (bl:log-cat "privatebroadcast"
                  "Received our privately broadcast transaction (txid=~A) from the network from ~A; stopping private broadcast attempts"
                  (bl.crypto:bytes-to-hex (bl.crypto:reverse-bytes (bl.ser:transaction-hash tx)))
                  (peer-log-name peer))
      (when (< broadcast +num-private-broadcast-per-tx+)
        (private-broadcast-num-to-open-sub (- +num-private-broadcast-per-tx+ broadcast))))))

(defun note-verack-sent (peer)
  "Core PushMessage's side effect for VERACK (net.cpp:4067-4072): the first
VERACK we send to an outbound Tor peer proves the Tor proxy works."
  (when (and (not *outbound-tor-ok-at-least-once*)
             (not (peer-inbound peer))
             (stringp (peer-address peer))
             (parse-onion-address (peer-address peer)))
    (setf *outbound-tor-ok-at-least-once* t)))

;;; The conversation on one private-broadcast connection

(defun %pb-send-version (peer)
  "Core PushNodeVersion's private-broadcast arm (net_processing.cpp:1557-1564):
no services, time 0, empty addresses, a fixed user agent, height 0, no relay."
  (send-message peer (bl.ser:serialize-message
                      "version"
                      (bl.ser:make-version-message-bytes
                       :services 0 :timestamp 0
                       :user-agent +private-broadcast-user-agent+
                       :start-height 0 :relay nil
                       :nonce (peer-local-nonce peer)))))

(defun %pb-push-tx (peer)
  "Core PushPrivateBroadcastTx (net_processing.cpp:3557-3575): after VERACK,
announce the most urgent transaction by txid; NIL when none is left."
  (let ((tx (private-broadcast-pick-tx
             (peer-id peer)
             ;; Core CService::ToStringAddrPort, which getprivatebroadcastinfo
             ;; reports.
             (let ((conn (peer-connection peer))
                   (host (peer-address peer)))
               (format nil (if (find #\: host) "[~A]:~D" "~A:~D")
                       host (if conn (connection-port conn) 0))))))
    (cond
      ((null tx)
       (bl:log-cat "privatebroadcast"
                   "Disconnecting: no more transactions for private broadcast (connected in vain), ~A"
                   (peer-log-name peer))
       nil)
      (t
       (let ((txid (bl.ser:transaction-hash tx))
             (wtxid (bl.ser:transaction-wtxid tx)))
         (bl:log-cat "privatebroadcast" "P2P handshake completed, sending INV for txid=~A~A, ~A"
                     (bl.crypto:bytes-to-hex (bl.crypto:reverse-bytes txid))
                     (if (equalp txid wtxid)
                         ""
                         (format nil ", wtxid=~A"
                                 (bl.crypto:bytes-to-hex (bl.crypto:reverse-bytes wtxid))))
                     (peer-log-name peer))
         (send-message peer (bl.ser:make-inv-message
                             (list (bl.ser:make-inv-vector :type bl.ser:+inv-type-tx+
                                                           :hash txid)))))))))

(defun %pb-answer-getdata (peer payload)
  "Core's GETDATA arm for a private-broadcast connection (net_processing.cpp:
4231-4255): exactly one MSG_TX inv for the transaction we announced gets the
transaction and a ping; anything else ends the connection. T to go on."
  (let ((tx (private-broadcast-tx-for-peer (peer-id peer)))
        (invs (bl.ser:parse-inv-payload payload)))
    (cond
      ((null tx)
       (bl:log-cat "privatebroadcast" "Disconnecting: got GETDATA without sending an INV, ~A"
                   (peer-log-name peer))
       nil)
      ((and (= 1 (length invs))
            (= (bl.ser:inv-vector-type (first invs)) bl.ser:+inv-type-tx+)
            (equalp (bl.ser:inv-vector-hash (first invs)) (bl.ser:transaction-hash tx)))
       (send-message peer (bl.ser:make-tx-message tx :witness t))
       (send-ping peer)
       t)
      (t
       (bl:log-cat "privatebroadcast" "Disconnecting: got an unexpected GETDATA message, ~A"
                   (peer-log-name peer))
       nil))))

(defun %pb-pong-p (peer payload)
  "T when PAYLOAD answers our outstanding ping (Core's PONG handler)."
  (and (>= (length payload) 8)
       (let ((nonce (bl.bytes:with-byte-reader (s payload) (bl.bytes:br-read-u64-le s))))
         (record-pong peer nonce))
       t))

(defun %pb-step (peer command payload)
  "One received message on a private-broadcast connection; NIL ends it."
  (cond
    ((string= command "version")
     (let ((relay (bl.bytes:with-byte-reader (s payload)
                    (bl.ser:version-message-relay (bl.ser:read-version-message s)))))
       (cond (relay (send-message peer (bl.ser:make-verack-message)) t)
             (t (bl:log-cat "privatebroadcast"
                            "Disconnecting: does not support transaction relay (connected in vain), ~A"
                            (peer-log-name peer))
                nil))))
    ((string= command "verack")
     (setf (peer-state peer) :ready)
     (%pb-push-tx peer))
    ((string= command "getdata") (%pb-answer-getdata peer payload))
    ((and (string= command "pong") (%pb-pong-p peer payload))
     (private-broadcast-confirm (peer-id peer))
     (bl:log-cat "privatebroadcast"
                 "Got a PONG (the transaction will probably reach the network), marking for disconnect, ~A"
                 (peer-log-name peer))
     nil)
    (t (bl:log-cat "privatebroadcast" "Ignoring incoming message '~A', ~A"
                   (bl.bytes:sanitize-string command) (peer-log-name peer))
       t)))

(defun run-private-broadcast-connection (peer)
  "Drive the connected private-broadcast PEER to the end (Core's
IsPrivateBroadcastConn branches of ProcessMessage and SendMessages): our
VERSION, VERACK on theirs, INV / TX / PING, and the hang-up on the pong or at
PRIVATE_BROADCAST_MAX_CONNECTION_LIFETIME. On the way out, Core FinalizeNode's
arm (net_processing.cpp:1744-1749): a connection that did not get its
transaction confirmed while transactions are pending asks for another."
  (setf (peer-state peer) :handshaking
        (peer-conn-type peer) :private-broadcast
        (peer-local-nonce peer) (%fresh-local-nonce))
  (let ((deadline (+ (get-internal-real-time)
                     (* +private-broadcast-max-connection-lifetime+
                        internal-time-units-per-second))))
    (unwind-protect
         (when (%pb-send-version peer)
           (loop
             (let ((left (/ (- deadline (get-internal-real-time))
                            internal-time-units-per-second)))
               (when (<= left 0)
                 (bl:log-cat "privatebroadcast"
                             "Disconnecting: did not complete the transaction send within ~D seconds, ~A"
                             +private-broadcast-max-connection-lifetime+ (peer-log-name peer))
                 (return))
               (multiple-value-bind (command payload)
                   (receive-message-blocking peer :timeout (min 5 left))
                 (when command
                   (log-received-message peer command payload)
                   (unless (%pb-step peer command payload) (return)))
                 (unless (or command (peer-connection peer)) (return))))))
      (ignore-errors (disconnect-peer peer))
      (when (and (not (private-broadcast-confirmed-p (peer-id peer)))
                 (private-broadcast-pending-p))
        (private-broadcast-num-to-open-add 1)))))
