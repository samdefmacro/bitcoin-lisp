(in-package #:bitcoin-lisp.networking)

;;; Peer Management
;;;
;;; Handles the state machine for Bitcoin peer connections.

(deftype peer-state ()
  '(member :disconnected :connecting :connected :handshaking :ready :banned))

(defstruct peer
  "A Bitcoin peer."
  (connection nil :type (or null connection))
  (state :disconnected :type peer-state)
  (version nil)  ; Received version message
  (services 0 :type (unsigned-byte 64))
  (start-height 0 :type (signed-byte 32))
  (user-agent "" :type string)
  (ping-nonce nil)
  (last-ping-time 0 :type integer)
  (ping-latency 0 :type integer)
  (send-queue '() :type list)
  ;; Set of txids announced to this peer (hash-table of txid -> t)
  (announced-txs (make-hash-table :test 'equalp) :type hash-table)
  ;; Health monitoring
  (consecutive-ping-failures 0 :type (unsigned-byte 8))
  (last-health-check 0 :type integer)
  ;; Block request timeout tracking
  (block-timeout-count 0 :type (unsigned-byte 8))
  (address "" :type string))

;;; Network parameters

(defvar *testnet-port* 18333)
(defvar *mainnet-port* 8333)
(defvar *current-port* *testnet-port*)

(defvar *testnet-dns-seeds*
  '("testnet-seed.bitcoin.jonasschnelli.ch"
    "seed.tbtc.petertodd.org"
    "seed.testnet.bitcoin.sprovoost.nl"
    "testnet-seed.bluematt.me"))

(defvar *mainnet-dns-seeds*
  '("seed.bitcoin.sipa.be"
    "dnsseed.bluematt.me"
    "dnsseed.bitcoin.dashjr.org"
    "seed.bitcoinstats.com"
    "seed.bitcoin.jonasschnelli.ch"))

(defvar *dns-seeds* *testnet-dns-seeds*)

;;; Peer connection

(defun connect-peer (host &optional (port *current-port*))
  "Connect to a peer at HOST:PORT.
Returns a peer structure or NIL on failure."
  (let ((conn (make-tcp-connection host port)))
    (when conn
      (make-peer :connection conn
                 :state :connected))))

(defun disconnect-peer (peer)
  "Disconnect from a peer."
  (when (peer-connection peer)
    (close-connection (peer-connection peer)))
  (setf (peer-state peer) :disconnected)
  (setf (peer-connection peer) nil))

;;; Message I/O

(defun send-message (peer message-bytes)
  "Send a raw message to a peer.
Returns T on success, NIL on failure."
  (when (and (peer-connection peer)
             (connection-connected (peer-connection peer)))
    (send-bytes (peer-connection peer) message-bytes)))

(defun receive-message (peer &key (timeout 30))
  "Receive a message from a peer.
Returns (VALUES COMMAND PAYLOAD) on success, NIL on failure/timeout."
  (when (and (peer-connection peer)
             (connection-connected (peer-connection peer)))
    (let ((conn (peer-connection peer)))
      ;; Read header (24 bytes)
      (let ((header-bytes (receive-bytes conn 24 :timeout timeout)))
        (when header-bytes
          (flexi-streams:with-input-from-sequence (stream header-bytes)
            (let ((header (bitcoin-lisp.serialization:read-message-header stream)))
              ;; Verify magic
              (unless (equalp (bitcoin-lisp.serialization:message-header-magic header)
                              bitcoin-lisp.serialization:*network-magic*)
                (return-from receive-message nil))
              ;; Read payload
              (let* ((payload-len (bitcoin-lisp.serialization:message-header-payload-length header))
                     (payload (if (zerop payload-len)
                                  #()
                                  (receive-bytes conn payload-len :timeout timeout))))
                (when (or (zerop payload-len) payload)
                  ;; Verify checksum
                  (let ((computed-checksum
                          (bitcoin-lisp.serialization:compute-checksum
                           (if (zerop payload-len) #() payload))))
                    (when (equalp (subseq computed-checksum 0 4)
                                  (bitcoin-lisp.serialization:message-header-checksum header))
                      (values (bitcoin-lisp.serialization:message-header-command header)
                              payload))))))))))))

;;; Handshake

(defun perform-handshake (peer)
  "Perform the Bitcoin version handshake.
Returns T on success, NIL on failure."
  (setf (peer-state peer) :handshaking)

  ;; Send version message
  (let* ((version-payload (bitcoin-lisp.serialization:make-version-message-bytes
                           :start-height 0
                           :timestamp (bitcoin-lisp.serialization:get-unix-time)))
         (version-msg (bitcoin-lisp.serialization:serialize-message
                       "version" version-payload)))
    (unless (send-message peer version-msg)
      (return-from perform-handshake nil)))

  ;; Receive version message
  (multiple-value-bind (command payload)
      (receive-message peer :timeout 30)
    (unless (string= command "version")
      (return-from perform-handshake nil))
    ;; Parse and store version info
    (flexi-streams:with-input-from-sequence (stream payload)
      (let ((version-msg (bitcoin-lisp.serialization:read-version-message stream)))
        (setf (peer-version peer) version-msg)
        (setf (peer-services peer)
              (bitcoin-lisp.serialization:version-message-services version-msg))
        (setf (peer-start-height peer)
              (bitcoin-lisp.serialization:version-message-start-height version-msg))
        (setf (peer-user-agent peer)
              (bitcoin-lisp.serialization:version-message-user-agent version-msg)))))

  ;; Send verack
  (unless (send-message peer (bitcoin-lisp.serialization:make-verack-message))
    (return-from perform-handshake nil))

  ;; Receive verack (may receive other messages first like wtxidrelay, sendaddrv2)
  (loop repeat 10  ; Max 10 messages before giving up
        do (multiple-value-bind (command payload)
               (receive-message peer :timeout 30)
             (declare (ignore payload))
             (unless command
               (return-from perform-handshake nil))
             (when (string= command "verack")
               (setf (peer-state peer) :ready)
               (return-from perform-handshake t))
             ;; Ignore other handshake-phase messages (wtxidrelay, sendaddrv2, etc.)
             ))

  nil)  ; Didn't receive verack

;;; Ping/Pong

(defun send-ping (peer)
  "Send a ping message to the peer."
  (let ((nonce (random (expt 2 64))))
    (setf (peer-ping-nonce peer) nonce)
    (setf (peer-last-ping-time peer) (get-internal-real-time))
    (send-message peer (bitcoin-lisp.serialization:make-ping-message nonce))))

(defun handle-ping (peer nonce)
  "Handle a ping message by sending a pong."
  (send-message peer (bitcoin-lisp.serialization:make-pong-message nonce)))

(defun handle-pong (peer nonce)
  "Handle a pong message."
  (when (and (peer-ping-nonce peer)
             (= nonce (peer-ping-nonce peer)))
    (setf (peer-ping-latency peer)
          (- (get-internal-real-time) (peer-last-ping-time peer)))
    (setf (peer-ping-nonce peer) nil)
    ;; Reset failure count on successful pong
    (setf (peer-consecutive-ping-failures peer) 0)))

;;; Peer Health Monitoring

(defconstant +ping-interval-seconds+ 60)
(defconstant +ping-timeout-seconds+ 30)
(defconstant +max-ping-failures+ 3)
(defconstant +max-block-timeouts+ 3)

(defun check-peer-health (peer)
  "Check health of a single peer. Returns :ok, :ping-sent, or :disconnect.
Should be called periodically (every ~60s)."
  (unless (eq (peer-state peer) :ready)
    (return-from check-peer-health :ok))

  (let ((now (get-internal-real-time))
        (interval-ticks (* +ping-interval-seconds+ internal-time-units-per-second))
        (timeout-ticks (* +ping-timeout-seconds+ internal-time-units-per-second)))

    ;; Check if a ping is outstanding and has timed out
    (when (peer-ping-nonce peer)
      (when (> (- now (peer-last-ping-time peer)) timeout-ticks)
        ;; Ping timed out
        (incf (peer-consecutive-ping-failures peer))
        (setf (peer-ping-nonce peer) nil)
        (when (>= (peer-consecutive-ping-failures peer) +max-ping-failures+)
          (return-from check-peer-health :disconnect))))

    ;; Send a new ping if enough time has passed
    (when (> (- now (peer-last-health-check peer)) interval-ticks)
      (setf (peer-last-health-check peer) now)
      (send-ping peer)
      (return-from check-peer-health :ping-sent))

    :ok))

(defun record-block-timeout (peer)
  "Record a block request timeout for PEER.
Returns T if the peer should be disconnected."
  (incf (peer-block-timeout-count peer))
  (>= (peer-block-timeout-count peer) +max-block-timeouts+))
