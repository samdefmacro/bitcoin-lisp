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
  ;; Block delivery tracking
  (block-timeout-count 0 :type (unsigned-byte 8))
  (last-block-received-time 0 :type integer)  ; internal-real-time of last block from this peer
  (address "" :type string)
  ;; Misbehavior scoring
  (misbehavior-score 0 :type (unsigned-byte 32))
  ;; Compact block support (BIP 152)
  (compact-block-version 0 :type (unsigned-byte 64))  ; 0=not supported, 1 or 2
  (compact-block-high-bandwidth nil :type boolean)    ; High-bandwidth mode enabled
  (pending-compact-block nil)                         ; Pending reconstruction state
  ;; ADDRv2 support (BIP 155)
  (wants-addrv2 nil :type boolean)                    ; Peer sent sendaddrv2
  ;; BIP 130 sendheaders support
  (prefers-headers nil :type boolean)                  ; Peer sent sendheaders
  ;; BIP 133 feefilter support
  (feefilter-rate 0 :type (unsigned-byte 64))          ; Peer's minimum fee rate (sat/kB)
  ;; DoS protection: per-peer rate limiters
  (rate-limit-inv nil)
  (rate-limit-tx nil)
  (rate-limit-addr nil)
  (rate-limit-getdata nil)
  (rate-limit-headers nil)
  ;; Handshake timeout tracking
  (connect-time 0 :type integer))                     ; internal-real-time at connection

;;; Pending compact block reconstruction state
(defstruct pending-compact-block
  "State for in-progress compact block reconstruction."
  (block-hash nil)           ; Hash of block being reconstructed
  (header nil)               ; Block header
  (transactions nil)         ; Partial transaction array (with nils for missing)
  (missing-indexes nil)      ; List of indexes still needed
  (request-time 0)           ; When getblocktxn was sent (internal-real-time)
  (use-wtxid nil))           ; Version 2 uses wtxid

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

(defun init-peer-rate-limiters (peer)
  "Initialize per-peer rate limiters from global configuration."
  (flet ((rl (config) (bitcoin-lisp:make-rate-limiter (car config) (cdr config))))
    (setf (peer-rate-limit-inv peer) (rl bitcoin-lisp:*rate-limit-inv*))
    (setf (peer-rate-limit-tx peer) (rl bitcoin-lisp:*rate-limit-tx*))
    (setf (peer-rate-limit-addr peer) (rl bitcoin-lisp:*rate-limit-addr*))
    (setf (peer-rate-limit-getdata peer) (rl bitcoin-lisp:*rate-limit-getdata*))
    (setf (peer-rate-limit-headers peer) (rl bitcoin-lisp:*rate-limit-headers*)))
  peer)

(defun connect-peer (host &optional (port *current-port*))
  "Connect to a peer at HOST:PORT.
Returns a peer structure or NIL on failure.
Returns NIL if the host is banned."
  (when (peer-banned-p host)
    (return-from connect-peer nil))
  (let ((conn (make-tcp-connection host port)))
    (when conn
      (let ((peer (make-peer :connection conn
                             :state :connected
                             :address host
                             :connect-time (get-internal-real-time))))
        (init-peer-rate-limiters peer)
        peer))))

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
              ;; Validate payload size before allocating/reading
              (let ((payload-len (bitcoin-lisp.serialization:message-header-payload-length header)))
                (when (> payload-len bitcoin-lisp:+max-message-payload+)
                  (bitcoin-lisp:log-warn "Oversized message from peer ~A: ~D bytes (max ~D), disconnecting"
                                         (peer-address peer) payload-len bitcoin-lisp:+max-message-payload+)
                  (disconnect-peer peer)
                  (return-from receive-message nil))
                ;; Read payload
                (let ((payload (if (zerop payload-len)
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
                                payload)))))))))))))

;;; Handshake

(defun perform-handshake (peer)
  "Perform the Bitcoin version handshake.
Returns T on success, NIL on failure."
  (setf (peer-state peer) :handshaking)

  ;; Send version message
  ;; BIP 159: Advertise NODE_NETWORK_LIMITED instead of NODE_NETWORK when pruning
  (let* ((services (if (bitcoin-lisp:pruning-enabled-p)
                       (logior bitcoin-lisp.serialization:+node-network-limited+
                               bitcoin-lisp.serialization:+node-witness+)
                       (logior bitcoin-lisp.serialization:+node-network+
                               bitcoin-lisp.serialization:+node-witness+)))
         (version-payload (bitcoin-lisp.serialization:make-version-message-bytes
                           :services services
                           :start-height 0
                           :timestamp (bitcoin-lisp.serialization:get-unix-time)))
         (version-msg (bitcoin-lisp.serialization:serialize-message
                       "version" version-payload)))
    (unless (send-message peer version-msg)
      (return-from perform-handshake nil)))

  ;; Send sendaddrv2 (BIP 155) — must be after VERSION, before VERACK
  (send-message peer (bitcoin-lisp.serialization:make-sendaddrv2-message))

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
             ;; BIP 155: Track peer's addrv2 capability
             (when (string= command "sendaddrv2")
               (setf (peer-wants-addrv2 peer) t))
             ;; BIP 130: Track peer's sendheaders preference
             (when (string= command "sendheaders")
               (setf (peer-prefers-headers peer) t))
             ;; Ignore other handshake-phase messages (wtxidrelay, etc.)
             ))

  ;; Didn't receive verack
  nil)

(defun send-post-handshake-messages (peer)
  "Send feature negotiation messages after handshake completes."
  ;; BIP 130: Request header announcements
  (send-message peer (bitcoin-lisp.serialization:make-sendheaders-message))
  ;; BIP 133: Announce our minimum relay fee rate (1000 sat/kB = 1 sat/byte)
  (send-message peer (bitcoin-lisp.serialization:make-feefilter-message 1000)))

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

(defun check-handshake-timeout (peer)
  "Check if a peer has exceeded the handshake timeout.
Returns :disconnect if the peer should be disconnected, :ok otherwise."
  (when (and (member (peer-state peer) '(:connected :connecting :handshaking))
             (not (zerop (peer-connect-time peer))))
    (let* ((now (get-internal-real-time))
           (elapsed-secs (/ (float (- now (peer-connect-time peer)))
                            (float internal-time-units-per-second))))
      (when (> elapsed-secs bitcoin-lisp:+handshake-timeout-seconds+)
        (bitcoin-lisp:log-warn "Handshake timeout for peer ~A (~,1Fs elapsed)"
                               (peer-address peer) elapsed-secs)
        (return-from check-handshake-timeout :disconnect))))
  :ok)

(defun check-peer-health (peer)
  "Check health of a single peer. Returns :ok, :ping-sent, or :disconnect.
Should be called periodically (every ~60s).
Also checks handshake timeout for peers that haven't completed handshake."
  ;; Check handshake timeout for non-ready peers
  (unless (eq (peer-state peer) :ready)
    (return-from check-peer-health (check-handshake-timeout peer)))

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

(defun record-block-received-from-peer (peer)
  "Record that we received a block from PEER. Resets stalling state."
  (setf (peer-last-block-received-time peer) (get-internal-real-time))
  (setf (peer-block-timeout-count peer) 0))

(defun peer-stalling-p (peer &key (timeout-seconds 30))
  "Check if PEER is stalling block download.
A peer is stalling if it has been connected and we haven't received a block
from it in TIMEOUT-SECONDS despite having in-flight requests.
Returns T if the peer appears to be stalling."
  (and (eq (peer-state peer) :ready)
       (not (zerop (peer-last-block-received-time peer)))
       (> (/ (float (- (get-internal-real-time) (peer-last-block-received-time peer)))
             (float internal-time-units-per-second))
          timeout-seconds)))

(defun consider-peer-eviction (peer our-height)
  "Check if PEER should be evicted based on chain quality.
Peers whose advertised height is significantly behind our validated tip
are likely unproductive. Returns T if the peer should be disconnected."
  (and (eq (peer-state peer) :ready)
       ;; Peer claims a height far behind ours (>1000 blocks)
       (> our-height (+ (peer-start-height peer) 1000))))

;;; Misbehavior Scoring and Banning

(defconstant +misbehavior-ban-threshold+ 100
  "Misbehavior score at which a peer gets banned.")

(defconstant +ban-duration-seconds+ (* 24 60 60)
  "Ban duration: 24 hours.")

(defvar *banned-peers* (make-hash-table :test 'equal)
  "Hash table mapping peer address (string) -> ban-expiry-time (universal-time).")

(defun record-misbehavior (peer score-increment)
  "Increment PEER's misbehavior score by SCORE-INCREMENT.
If the score reaches the ban threshold, the peer is banned and disconnected.
Returns T if the peer was banned."
  (incf (peer-misbehavior-score peer) score-increment)
  (when (>= (peer-misbehavior-score peer) +misbehavior-ban-threshold+)
    (ban-peer peer)
    t))

(defun ban-peer (peer)
  "Ban a peer. Sets state to :banned and records ban expiry."
  (setf (peer-state peer) :banned)
  (let ((address (peer-address peer)))
    (when (and address (plusp (length address)))
      (setf (gethash address *banned-peers*)
            (+ (get-universal-time) +ban-duration-seconds+))))
  (when (peer-connection peer)
    (close-connection (peer-connection peer))
    (setf (peer-connection peer) nil)))

(defun peer-banned-p (address)
  "Check if ADDRESS is currently banned.
Returns T if banned, NIL otherwise. Expired bans are cleaned up."
  (let ((expiry (gethash address *banned-peers*)))
    (cond
      ((null expiry) nil)
      ((> (get-universal-time) expiry)
       ;; Ban expired, remove it
       (remhash address *banned-peers*)
       nil)
      (t t))))

(defun clear-ban-list ()
  "Clear all bans."
  (clrhash *banned-peers*))

;;; Per-Peer Rate Limiting

(defun check-peer-rate-limit (peer command)
  "Check if PEER is within rate limits for COMMAND.
Returns T if allowed, NIL if rate limit exceeded."
  (let ((bucket (cond
                  ((string= command "inv") (peer-rate-limit-inv peer))
                  ((string= command "tx") (peer-rate-limit-tx peer))
                  ((string= command "addr") (peer-rate-limit-addr peer))
                  ((string= command "addrv2") (peer-rate-limit-addr peer))
                  ((string= command "getdata") (peer-rate-limit-getdata peer))
                  ((string= command "headers") (peer-rate-limit-headers peer))
                  (t nil))))  ; No rate limit for other message types
    (if bucket
        (bitcoin-lisp:token-bucket-allow-p bucket)
        t)))
