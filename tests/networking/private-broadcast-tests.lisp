(in-package #:bitcoin-lisp.tests)

;;;; -privatebroadcast: the queue (Core private_broadcast.cpp) and the
;;;; conversation on one private-broadcast connection (net_processing.cpp's
;;;; IsPrivateBroadcastConn branches).

(def-suite :private-broadcast-tests
  :description "Private broadcast of our own transactions (-privatebroadcast)"
  :in :bitcoin-lisp-tests)

(in-suite :private-broadcast-tests)

(defun %pb-dummy-tx (id &optional witness)
  "Core private_broadcast_tests.cpp MakeDummyTx: one input whose sequence is
ID, with an empty witness stack of one element when WITNESS -- the same txid,
a different wtxid."
  (bl.ser:make-transaction
   :version 2
   :inputs (vector (bl.ser:make-tx-in
                    :previous-output (bl.ser:make-outpoint
                                      :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                           :initial-element 0)
                                      :index #xffffffff)
                    :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                    :sequence id))
   :outputs (vector)
   :lock-time 0
   :witness (and witness
                 (vector (list (make-array 0 :element-type '(unsigned-byte 8)))))))

(defmacro %with-private-broadcast-state (&body body)
  "BODY on an empty queue and connection count, emptied again afterwards."
  `(progn (bl.net:reset-private-broadcast)
          (unwind-protect (progn ,@body)
            (bl.net:reset-private-broadcast))))

(test private-broadcast-queue-is-cores
  "Core private_broadcast_tests.cpp `basic': a transaction is queued once by
wtxid (a same-txid twin is a second entry), picks alternate between the least
picked, a pong-confirmed transaction stops being stale for a minute, and
Remove answers the confirmation count once."
  (%with-private-broadcast-state
    (let ((bl.ser:*mock-time* 1700000000)
          (tx1 (%pb-dummy-tx 1))
          (tx2 (%pb-dummy-tx 1 t)))
      (is (null (bl.net::private-broadcast-pick-tx 1 "160.176.192.1:1111")))
      (is (null (bl.net:private-broadcast-stale)))
      (is-true (bl.net:private-broadcast-add tx1))
      (is-false (bl.net:private-broadcast-add tx1) "the same wtxid again")
      (is (equalp (bl.ser:transaction-hash tx1) (bl.ser:transaction-hash tx2)))
      (is-true (bl.net:private-broadcast-add tx2) "a different wtxid")
      (let ((for-1 (bl.net::private-broadcast-pick-tx 1 "160.176.192.1:1111"))
            (for-2 (bl.net::private-broadcast-pick-tx 2 "160.176.192.1:2222")))
        (is (not (eq for-1 for-2)) "the second pick is the other transaction")
        (is (equal '(1 1) (mapcar (lambda (cell) (length (cdr cell)))
                                  (bl.net:private-broadcast-info))))
        (is (eq for-1 (bl.net::private-broadcast-tx-for-peer 1)))
        (is (null (bl.net::private-broadcast-tx-for-peer 0)))
        (is (= 2 (length (bl.net:private-broadcast-stale))))
        (bl.net::private-broadcast-confirm 0)
        (bl.net::private-broadcast-confirm 1)
        (is (equal (list for-2) (bl.net:private-broadcast-stale))
            "a transaction confirmed just now is not stale")
        (let ((bl.ser:*mock-time* (+ 1700000000 (* 10 3600))))
          (is (= 2 (length (bl.net:private-broadcast-stale)))))
        (is (eql 1 (bl.net:private-broadcast-remove for-1)))
        (is (null (bl.net:private-broadcast-remove for-1)))
        (is (eql 0 (bl.net:private-broadcast-remove for-2)))
        (is (null (bl.net:private-broadcast-info)))))))

(test private-broadcast-connections-follow-the-queue
  "Core InitiateTxBroadcastPrivate asks for NUM_PRIVATE_BROADCAST_PER_TX
connections per new transaction and none for a queued one (net_processing.cpp:
2268-2277); abortprivatebroadcast cancels what an aborted transaction still had
coming (:1865-1882), and a transaction received back cancels the ones not
needed (:4494-4503)."
  (%with-private-broadcast-state
    (let ((tx1 (%pb-dummy-tx 1))
          (tx2 (%pb-dummy-tx 2)))
      (bl.net:initiate-tx-broadcast-private tx1)
      (is (= 3 (bl.net:private-broadcast-num-to-open)))
      (is (search "Ignoring unnecessary request to schedule an already scheduled transaction"
                  (nth-value 1 (log-text-of "privatebroadcast"
                                            (lambda () (bl.net:initiate-tx-broadcast-private tx1))))))
      (is (= 3 (bl.net:private-broadcast-num-to-open)))
      (bl.net:initiate-tx-broadcast-private tx2)
      (is (= 6 (bl.net:private-broadcast-num-to-open)))
      (is (equal (list tx2) (bl.net:private-broadcast-abort (bl.ser:transaction-hash tx2))))
      (is (= 3 (bl.net:private-broadcast-num-to-open)))
      (is (null (bl.net:private-broadcast-abort (bl.ser:transaction-hash tx2))))
      (bl.net:note-own-tx-received-back (bl.net:make-peer :id 7) tx1)
      (is (= 0 (bl.net:private-broadcast-num-to-open)))
      (is (null (bl.net:private-broadcast-info))))))

(test private-broadcast-conversation-is-cores
  "One private-broadcast connection, message by message (net_processing.cpp:
1557-1564, 3704-3711, 3859-3866, 3557-3575, 4231-4255, 5009-5013): a VERSION
with no services, time, addresses or relay, a fixed user agent and height 0;
VERACK on the peer's VERSION; INV of the queued transaction by txid on its
VERACK; the transaction and a PING on its GETDATA; the hang-up on the PONG,
with the reception confirmed. p2p_private_broadcast.py:250-270 asserts
exactly version, verack, inv, tx and ping arrive."
  (%with-private-broadcast-state
    (let* ((tx (%pb-dummy-tx 5 t))
           (txid (bl.ser:transaction-hash tx))
           (peer (bl.net:make-peer :id 41 :address "20.0.0.1"))
           (sent '())
           (script
             (list (lambda () (values "version"
                                      (bl.ser:make-version-message-bytes :relay t)))
                   (lambda () (values "verack" (make-array 0 :element-type '(unsigned-byte 8))))
                   (lambda () (values "getdata"
                                      (subseq (bl.ser:make-getdata-message
                                               (list (bl.ser:make-inv-vector
                                                      :type bl.ser:+inv-type-tx+ :hash txid)))
                                              24)))
                   (lambda () (values "pong"
                                      (subseq (bl.ser:make-pong-message
                                               (bl.net:peer-ping-nonce peer))
                                              24)))))
           (real-send (fdefinition 'bl.net:send-message))
           (real-receive (fdefinition 'bl.net:receive-message-blocking)))
      (bl.net:private-broadcast-add tx)
      (unwind-protect
           (progn
             (setf (fdefinition 'bl.net:send-message)
                   (lambda (p m) (declare (ignore p)) (push m sent) t)
                   (fdefinition 'bl.net:receive-message-blocking)
                   (lambda (p &key timeout)
                     (declare (ignore p timeout))
                     (let ((next (pop script)))
                       (if next (funcall next) (values nil nil)))))
             (bl.net:run-private-broadcast-connection peer))
        (setf (fdefinition 'bl.net:send-message) real-send
              (fdefinition 'bl.net:receive-message-blocking) real-receive))
      (flet ((command (m) (string-right-trim (string (code-char 0))
                                             (map 'string #'code-char (subseq m 4 16)))))
        (is (equal '("version" "verack" "inv" "tx" "ping")
                   (mapcar #'command (reverse sent))))
        (let ((version (bl.bytes:with-byte-reader (s (subseq (car (last sent)) 24))
                         (bl.ser:read-version-message s))))
          (is (= 0 (bl.ser:version-message-services version)))
          (is (= 0 (bl.ser:version-message-timestamp version)))
          (is (= 0 (bl.ser:version-message-start-height version)))
          (is (string= "/pynode:0.0.1/" (bl.ser:version-message-user-agent version)))
          (is-false (bl.ser:version-message-relay version))))
      (let ((statuses (cdr (first (bl.net:private-broadcast-info)))))
        (is (= 1 (length statuses)))
        (is-true (bl.net:pb-send-status-confirmed (first statuses))
                 "the pong confirmed reception")))))

(test private-broadcast-rpcs-are-cores
  "getprivatebroadcastinfo (rpc/mempool.cpp:142-205) lists each queued
transaction's txid, wtxid, hex and the peers it was sent to; abortprivatebroadcast
(:207-259) removes by txid or wtxid and refuses an id not queued with -5.
p2p_private_broadcast.py:349 and :470-485 read both."
  (%with-private-broadcast-state
    (let* ((node (make-test-node))
           (tx (%pb-dummy-tx 9 t))
           (txid (bl.crypto:bytes-to-hex (bl.crypto:reverse-bytes (bl.ser:transaction-hash tx))))
           (wtxid (bl.crypto:bytes-to-hex (bl.crypto:reverse-bytes (bl.ser:transaction-wtxid tx)))))
      (bl.net:private-broadcast-add tx)
      (let ((json (rpc-result-json
                   (bl.rpc:dispatch-rpc-method node "getprivatebroadcastinfo" nil))))
        (is (search (format nil "\"txid\":\"~A\"" txid) json) "got ~A" json)
        (is (search (format nil "\"wtxid\":\"~A\"" wtxid) json))
        (is (search "\"peers\":[]" json)))
      (let ((json (rpc-result-json
                   (bl.rpc:dispatch-rpc-method node "abortprivatebroadcast" (list wtxid)))))
        (is (search (format nil "\"removed_transactions\":[{\"txid\":\"~A\"" txid) json)
            "got ~A" json))
      (is (equal '(-5 . "Transaction not in private broadcast queue. Check getprivatebroadcastinfo.")
                 (rpc-error-of (lambda ()
                                 (bl.rpc:dispatch-rpc-method node "abortprivatebroadcast"
                                                             (list txid)))))))))
