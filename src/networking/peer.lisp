(in-package #:bitcoin-lisp.networking)

;;; Peer Management
;;;
;;; Handles the state machine for Bitcoin peer connections.

(deftype peer-state ()
  '(member :disconnected :connecting :connected :handshaking :ready :banned))

;;; Monotonic per-node peer ids (Bitcoin Core CNode::id), assigned at peer
;;; creation. Exposed via getpeerinfo "id" and used by getblockfrompeer to name a
;;; peer. Lock-guarded because outbound (sync thread) and inbound (listener
;;; thread) peers are created concurrently.
(defvar *peer-id-counter* 0)
(defvar *peer-id-lock* (bt:make-lock "peer-id"))
(defun next-peer-id ()
  (bt:with-lock-held (*peer-id-lock*) (incf *peer-id-counter*)))

(defstruct peer
  "A Bitcoin peer."
  (id (next-peer-id) :type integer)
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
  ;; Bounded set of txids announced to this peer. Was an unbounded hash-table --
  ;; a per-peer memory leak on long-lived relay connections. Core bounds the
  ;; equivalent m_tx_inventory_known_filter at CRollingBloomFilter{50000}; we use
  ;; the same hash+FIFO-ring bounded set as the recent-rejects filter.
  (announced-txs (bitcoin-lisp:make-rejects-filter 50000)
                 :type bitcoin-lisp:recent-rejects)
  ;; Bounded set of addresses (ip||port keys) this peer already knows -- either
  ;; it sent them to us or we relayed them to it. Dedup for addr gossip; Core's
  ;; m_addr_known CRollingBloomFilter{5000}.
  (known-addrs (bitcoin-lisp:make-rejects-filter 5000)
               :type bitcoin-lisp:recent-rejects)
  ;; Pending tx announcements, flushed in batches on a Poisson schedule
  ;; instead of per-tx immediate invs (Core m_tx_inventory_to_send +
  ;; m_next_inv_send_time). Entries are (txid wtxid fee-rate-per-kb),
  ;; oldest first. Single-writer: enqueue (relay-transaction) and flush
  ;; (flush-tx-announcements) both run on the sync thread.
  (tx-inv-queue '() :type list)
  ;; internal-real-time deadline of the next inv flush for this peer
  ;; (outbound peers only — inbound peers share one rotation, see
  ;; *next-inbound-inv-flush*). 0 = not yet scheduled.
  (next-inv-send-time 0 :type integer)
  ;; Health monitoring
  (consecutive-ping-failures 0 :type (unsigned-byte 8))
  (last-health-check 0 :type integer)
  ;; Block delivery tracking
  (block-timeout-count 0 :type (unsigned-byte 8))
  (last-block-received-time 0 :type integer)  ; internal-real-time of last block from this peer
  (address "" :type string)
  ;; T if the peer connected to us (inbound); NIL if we dialed out (outbound).
  (inbound nil :type boolean)
  ;; T if the peer connected through our local Tor onion-service listener
  ;; (Core CNode::m_inbound_onion, set when the accepting socket is an onion
  ;; bind). Such peers' socket address is Tor's local client (127.0.0.1), so
  ;; this flag is what makes ConnectedThroughNetwork() answer :torv3 — the
  ;; network used for the self-advertisement privacy rule.
  (inbound-onion nil :type boolean)
  ;; internal-real-time deadline of the next local-address self-announcement
  ;; to this peer; 0 = none sent yet, due immediately (Core Peer::
  ;; m_next_local_addr_send, net_processing.cpp:376).
  (next-local-addr-send 0 :type integer)
  ;; Connection type (Bitcoin Core ConnectionType). Determines tx-relay
  ;; participation and lifetime:
  ;;   :inbound              peer dialed us
  ;;   :outbound-full-relay  normal outbound; full tx + block + addr relay
  ;;   :block-relay          outbound relay=0 slot; blocks/headers only, NO tx
  ;;                         relay (anti-partition + the anchor source), and we
  ;;                         don't request addrs from it
  ;;   :feeler               short-lived probe of an addrman "new" address to
  ;;                         validate it into "tried" (anti-eclipse), then close
  (conn-type :inbound :type keyword)
  ;; T once we have answered this peer's getaddr (Bitcoin Core m_getaddr_recvd):
  ;; one address response per connection, to limit address-stamping spam.
  (getaddr-sent nil :type boolean)
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
  ;; BIP 339 wtxidrelay support
  (wtxid-relay nil :type boolean)                      ; Peer supports wtxid-based tx relay
  ;; BIP 330 transaction reconciliation (Erlay) handshake state. Core keeps a
  ;; per-peer {m_we_initiate, m_k0, m_k1} once registered, or just the locally
  ;; generated salt while pre-registered (node/txreconciliation.cpp Impl
  ;; m_states); we keep all of it on the peer struct so disconnect cleanup is
  ;; free. At ref d3056bc only the handshake exists — nothing reads k0/k1 yet
  ;; (the sketch exchange is unimplemented upstream too).
  (recon-local-salt nil :type (or null (unsigned-byte 64))) ; ours, sent in sendtxrcncl
  (recon-version 0 :type (unsigned-byte 32))          ; negotiated min(theirs, ours=1)
  (recon-k0 nil :type (or null (unsigned-byte 64)))   ; short-id SipHash key halves
  (recon-k1 nil :type (or null (unsigned-byte 64)))
  (recon-we-initiate nil :type boolean)               ; T = we dialed them (outbound)
  (recon-registered nil :type boolean)                ; sendtxrcncl exchanged both ways
  ;; DoS protection: per-peer rate limiters
  (rate-limit-inv nil)
  (rate-limit-tx nil)
  (rate-limit-addr nil)
  (rate-limit-getdata nil)
  (rate-limit-headers nil)
  ;; Shared bucket for serve requests: getheaders/getblocks/getaddr.
  (rate-limit-serve nil)
  ;; Handshake timeout tracking
  (connect-time 0 :type integer)                     ; internal-real-time at connection
  ;; Per-peer block-availability tracking. Mirrors a subset of Bitcoin
  ;; Core's CNodeState (net_processing.cpp:445-449). update-block-
  ;; availability writes these on inv/headers; readers today use
  ;; best-known-block-hash to gate inv-driven requests.
  ;;
  ;;   best-known-block-hash — peer's best advertised tip.
  ;;   hash-last-unknown-block — staging slot for inv hashes we don't
  ;;     have an index entry for yet; resolved on next call to
  ;;     process-block-availability once headers catch up.
  (best-known-block-hash nil)
  (hash-last-unknown-block nil))

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

(defvar *testnet3-port* 18333)
(defvar *testnet4-port* 48333)
(defvar *signet-port* 38333)
(defvar *mainnet-port* 8333)
(defvar *current-port* *testnet4-port*)

(defvar *testnet3-dns-seeds*
  '("testnet-seed.bitcoin.jonasschnelli.ch"
    "seed.tbtc.petertodd.org"
    "seed.testnet.bitcoin.sprovoost.nl"
    "testnet-seed.bluematt.me"))

(defvar *testnet4-dns-seeds*
  '("seed.testnet4.bitcoin.sprovoost.nl"
    "seed.testnet4.wiz.biz"))

(defvar *testnet4-fixed-seeds*
  '("2.59.134.244" "2.110.106.102" "5.182.4.106" "31.220.30.248"
    "34.232.194.104" "35.201.167.154" "38.102.86.40" "45.41.204.8"
    "45.50.223.112" "45.94.168.5" "51.158.61.33" "52.6.23.153"
    "54.76.27.166" "54.78.49.45" "62.84.190.200" "65.108.143.22"
    "67.81.240.18" "67.213.127.87" "69.26.129.172" "70.95.111.216"
    "71.13.92.62" "71.183.49.199" "74.133.9.162" "80.253.94.252"
    "82.67.102.15" "89.58.9.219" "94.183.188.204" "95.141.35.117"
    "95.182.100.206" "96.79.5.26" "103.69.87.64" "103.99.169.203"
    "103.99.169.204" "103.165.192.201" "103.165.192.210" "103.232.248.31"
    "104.237.131.138" "109.123.236.96" "121.98.22.147" "135.180.99.74"
    "142.160.218.208" "144.172.110.246" "148.51.196.40" "158.69.118.2"
    "158.69.211.155" "158.220.90.103" "162.220.166.82" "168.119.11.220"
    "173.53.122.49" "174.177.47.73" "176.169.208.187" "181.174.165.116"
    "185.254.97.76" "193.30.123.70" "195.154.199.2" "198.58.102.18"
    "203.51.4.72" "203.132.94.196" "208.68.4.50" "208.68.4.71"
    "208.73.202.78" "217.31.57.128" "222.66.94.2")
  "Hardcoded testnet4 IPv4 fallback peers (63 nodes across 59 distinct /16
groups), extracted from Bitcoin Core's contrib/seeds/nodes_testnet4.txt
(makeseeds.py output). Used by connect-to-peers when DNS discovery
returns too few diverse netgroups — testnet4's two DNS seeds are
sprovoost.nl (currently dark/unresponsive 2026-05-11) and wiz.biz
(returns only its own /24 cluster), so without this fallback the node
ends up 8-of-8 connected to one operator and stalls when that operator
slows down. Mirrors Bitcoin Core's vFixedSeeds in chainparams.cpp
which is populated from chainparams_seed_testnet4 (the same
nodes_testnet4.txt source).")

(defvar *signet-dns-seeds*
  '("seed.signet.bitcoin.sprovoost.nl"
    "seed.signet.achownodes.xyz"))

(defvar *mainnet-dns-seeds*
  '("seed.bitcoin.sipa.be"
    "dnsseed.bluematt.me"
    "dnsseed.bitcoin.dashjr.org"
    "seed.bitcoinstats.com"
    "seed.bitcoin.jonasschnelli.ch"))

(defvar *regtest-dns-seeds* '()
  "Regtest has no DNS seeds — it is an isolated local chain with no peers.")

(defvar *dns-seeds* *testnet4-dns-seeds*)

;;; Peer connection

(defun init-peer-rate-limiters (peer)
  "Initialize per-peer rate limiters from global configuration."
  (flet ((rl (config) (bitcoin-lisp:make-rate-limiter (car config) (cdr config))))
    (setf (peer-rate-limit-inv peer) (rl bitcoin-lisp:*rate-limit-inv*))
    (setf (peer-rate-limit-tx peer) (rl bitcoin-lisp:*rate-limit-tx*))
    (setf (peer-rate-limit-addr peer) (rl bitcoin-lisp:*rate-limit-addr*))
    (setf (peer-rate-limit-getdata peer) (rl bitcoin-lisp:*rate-limit-getdata*))
    (setf (peer-rate-limit-headers peer) (rl bitcoin-lisp:*rate-limit-headers*))
    (setf (peer-rate-limit-serve peer) (rl bitcoin-lisp:*rate-limit-serve*)))
  peer)

(defun connect-peer (host &optional (port *current-port*))
  "Connect to a peer at HOST:PORT.
Returns a peer structure or NIL on failure.
Returns NIL if the host is banned or discouraged (never dial either)."
  (when (or (peer-banned-p host) (peer-discouraged-p host))
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
  (setf (peer-connection peer) nil)
  ;; Drop any orphan transactions this peer contributed (DoS hygiene).
  (let ((node bitcoin-lisp::*node*))
    (when (and node (bitcoin-lisp::node-mempool node))
      (bitcoin-lisp.mempool:orphan-erase-for-peer
       (bitcoin-lisp.mempool:mempool-orphan-pool (bitcoin-lisp::node-mempool node))
       peer))))

;;; Message I/O

(defun send-message (peer message-bytes)
  "Send a raw (v1-framed) message to a peer; a connection with a v2 transport
re-frames it as an encrypted BIP324 packet. Returns T on success, NIL on
failure."
  (when (and (peer-connection peer)
             (connection-connected (peer-connection peer)))
    (let ((conn (peer-connection peer)))
      (if (connection-transport conn)
          (v2-send-message conn (connection-transport conn) message-bytes)
          (send-bytes conn message-bytes)))))

(defun receive-message (peer &key (timeout 30))
  "Receive a message from a peer.
Returns (VALUES COMMAND PAYLOAD) on success, NIL on failure/timeout."
  (when (and (peer-connection peer)
             (connection-connected (peer-connection peer)))
    (let ((conn (peer-connection peer)))
      (when (connection-transport conn)
        (return-from receive-message
          (v2-receive-message conn (connection-transport conn)
                              :timeout timeout)))
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

(defun peer-relays-txs-p (peer)
  "T if we relay transactions with PEER. Block-relay-only and feeler
connections do not (Core: fRelay=false, no tx inv/getdata either way)."
  (not (member (peer-conn-type peer) '(:block-relay :feeler))))

;;; BIP330 sendtxrcncl handshake (Erlay). Core parity at ref d3056bc is the
;;; handshake + salt storage only — no reqtxrcncl/sketch messages exist
;;; upstream either (protocol.h:266 defines nothing beyond sendtxrcncl).

(defun compute-recon-salt (salt1 salt2)
  "Combine the two sendtxrcncl salts into the reconciliation short-id keys
(Core txreconciliation.cpp:18-30 ComputeSalt): BIP340-style tagged hash with
tag \"Tx Relay Salting\" over the two u64 salts serialized LE in ascending
order; k0/k1 are the digest's first/second 8 bytes read LE (Core uint256
GetUint64(0)/(1)). Returns (VALUES K0 K1)."
  (let ((msg (make-array 16 :element-type '(unsigned-byte 8)))
        (lo (min salt1 salt2))
        (hi (max salt1 salt2)))
    (dotimes (i 8)
      (setf (aref msg i) (ldb (byte 8 (* 8 i)) lo)
            (aref msg (+ 8 i)) (ldb (byte 8 (* 8 i)) hi)))
    (let ((digest (bitcoin-lisp.crypto:tagged-hash "Tx Relay Salting" msg)))
      (flet ((u64-le-at (offset)
               (loop for i below 8
                     sum (ash (aref digest (+ offset i)) (* 8 i)))))
        (values (u64-le-at 0) (u64-le-at 8))))))

(defun %forget-recon-state (peer)
  "Erase all BIP330 reconciliation state for PEER (Core ForgetPeer,
txreconciliation.cpp:128-136). All state lives on the peer struct, so a
disconnect needs no extra cleanup."
  (setf (peer-recon-local-salt peer) nil
        (peer-recon-version peer) 0
        (peer-recon-k0 peer) nil
        (peer-recon-k1 peer) nil
        (peer-recon-we-initiate peer) nil
        (peer-recon-registered peer) nil))

(defun %maybe-send-sendtxrcncl (peer)
  "Announce BIP330 reconciliation support, after the peer's VERSION and before
our VERACK (Core sends from its VERSION handler, net_processing.cpp:3728-3742),
when: -txreconciliation is enabled, the negotiated protocol supports wtxid
relay (>= 70016), our side of the connection relays txs (not block-relay/
feeler), and the peer's VERSION set fRelay=1. On send, pre-register a random
u64 local salt (txreconciliation.cpp:82-94 PreRegisterPeer). Always returns
T — declining to offer never fails the handshake."
  (let ((version-msg (peer-version peer)))
    (when (and bitcoin-lisp:*tx-reconciliation*
               version-msg
               ;; Negotiated protocol = min(ours, theirs); ours is
               ;; +protocol-version+ = 70016 (WTXID_RELAY_VERSION), so the
               ;; gate reduces to theirs >= 70016.
               (>= (bitcoin-lisp.serialization:version-message-version version-msg)
                   bitcoin-lisp.serialization:+protocol-version+)
               (peer-relays-txs-p peer)
               (bitcoin-lisp.serialization:version-message-relay version-msg))
      (let ((salt (random (expt 2 64))))
        (setf (peer-recon-local-salt peer) salt)
        (send-message peer
                      (bitcoin-lisp.serialization:make-sendtxrcncl-message salt)))))
  t)

(defun %handle-handshake-sendtxrcncl (peer payload)
  "Process a pre-verack sendtxrcncl (Core net_processing.cpp:3963-4014 +
txreconciliation.cpp:97-126 RegisterPeer). Disconnects PEER and returns NIL
on a protocol violation; returns T otherwise (registered, or benignly
ignored)."
  (flet ((violation (reason)
           (bitcoin-lisp:log-cat "net" "sendtxrcncl ~A — disconnecting peer ~A"
                                 reason (peer-address peer))
           (disconnect-peer peer)
           nil))
    (cond
      ;; Feature disabled: ignored entirely (net_processing.cpp:3964-3967).
      ((not bitcoin-lisp:*tx-reconciliation*) t)
      ;; Our VERSION indicated no tx relay on this connection (block-relay/
      ;; feeler) — Core's RejectIncomingTxs check (:3976-3980).
      ((not (peer-relays-txs-p peer))
       (violation "received to which we indicated no tx relay"))
      ;; The peer's own VERSION had fRelay=0 (:3982-3990).
      ((not (and (peer-version peer)
                 (bitcoin-lisp.serialization:version-message-relay
                  (peer-version peer))))
       (violation "received which indicated no tx relay to us"))
      (t
       (multiple-value-bind (their-version their-salt)
           (handler-case
               (bitcoin-lisp.serialization:parse-sendtxrcncl-payload payload)
             (error () (values nil nil)))
         (cond
           ;; Truncated payload: Core's deserialize failure drops the peer.
           ((null their-version) (violation "with malformed payload"))
           ;; We never offered, so no pre-registration exists: ignore
           ;; without disconnecting (RegisterPeer NOT_FOUND).
           ((null (peer-recon-local-salt peer)) t)
           ;; Second sendtxrcncl on one connection (ALREADY_REGISTERED).
           ((peer-recon-registered peer)
            (violation "from already registered peer"))
           ;; Negotiated version = min(theirs, ours); v1 is the lowest, so
           ;; below that is a violation — higher-than-ours downgrades fine
           ;; (txreconciliation.cpp:112-119).
           ((< (min their-version
                    bitcoin-lisp.serialization:+txreconciliation-version+)
               1)
            (violation "with unsupported version"))
           (t
            (multiple-value-bind (k0 k1)
                (compute-recon-salt (peer-recon-local-salt peer) their-salt)
              (setf (peer-recon-version peer)
                    (min their-version
                         bitcoin-lisp.serialization:+txreconciliation-version+)
                    (peer-recon-k0 peer) k0
                    (peer-recon-k1 peer) k1
                    ;; We initiate reconciliation rounds iff we dialed them
                    ;; (Core: we_initiate = !is_peer_inbound).
                    (peer-recon-we-initiate peer) (not (peer-inbound peer))
                    (peer-recon-registered peer) t))
            t)))))))

(defun %verack-finalize-recon (peer)
  "At VERACK time, reconciliation requires negotiated wtxid relay (which
cannot be announced later): if the peer (pre-)registered but wtxidrelay never
arrived, forget the reconciliation state (Core net_processing.cpp:3879-3886)."
  (unless (and (peer-wtxid-relay peer) (peer-recon-registered peer))
    (%forget-recon-state peer)))

(defun local-services ()
  "Our advertised service bits (Core g_local_services / peer.m_our_services),
used in our version message and as the services field of our self-advertised
address (Core MaybeSendAddr's CAddress{*local_service, peer.m_our_services,
...}). Mirrors Core's composition (init.cpp:863,1946-1953): the base is
NODE_NETWORK_LIMITED | NODE_WITNESS; NODE_NETWORK is added only when we can
actually serve ALL historical blocks — i.e. not pruning AND no assumeutxo
historical chainstate exists (while a snapshot's background validation
runs, blocks below the snapshot base are not yet locally available, so the
node runs as NODE_NETWORK_LIMITED until it completes). BIP 324 adds
NODE_P2P_V2 when the v2 transport is available; BIP 157 adds
NODE_COMPACT_FILTERS when filter serving is enabled."
  (let ((node bitcoin-lisp::*node*))
    (logior bitcoin-lisp.serialization:+node-network-limited+
            bitcoin-lisp.serialization:+node-witness+
            (if (or (bitcoin-lisp:pruning-enabled-p)
                    (and node (bitcoin-lisp::node-historical-chainstate node)))
                0
                bitcoin-lisp.serialization:+node-network+)
            (if (v2-available-p)
                bitcoin-lisp.serialization:+node-p2p-v2+ 0)
            ;; BIP157: advertise filter serving when enabled.
            (if bitcoin-lisp:*peer-block-filters*
                bitcoin-lisp.serialization:+node-compact-filters+ 0))))

(defun %version-addr-recv (peer)
  "The addr_recv (\"addr_you\") field for our version message to PEER: the
peer's own address with the services we know for it, when that address is
routable and carriable in the version message's pre-BIP155 form — else the
all-zero dummy, exactly Core's `addr.IsRoutable() && !IsProxy(addr) &&
addr.IsAddrV1Compatible() ? addr : CService{}` (net_processing.cpp:1570).
The IsProxy arm has no analogue here: our peer-address always records the
dial TARGET, never the proxy. addr_from stays the all-zero dummy — that IS
Core's behavior (CNetAddr::V1(CService{}), net_processing.cpp:1585); real
self-advertisement happens via addr/addrv2 push, not the version message."
  (multiple-value-bind (net bytes) (parse-network-address (peer-address peer))
    (if (and net
             (bitcoin-lisp.serialization:v1-compatible-network-p net)
             (address-routable-p bytes net))
        (bitcoin-lisp.serialization:make-net-addr
         :services (peer-services peer)
         :ip bytes
         :port (let ((conn (peer-connection peer)))
                 (if conn (connection-port conn) 0)))
        (bitcoin-lisp.serialization:make-empty-net-addr
         :services (peer-services peer)))))

(defun %send-version-and-capabilities (peer)
  "Send our version message followed by the post-version capability messages
(wtxidrelay BIP339, sendaddrv2 BIP155 — both must come after VERSION and before
VERACK). Returns T if the version was sent. On a block-relay/feeler connection
the version's relay flag is 0 and we skip wtxidrelay (Core does not negotiate
tx relay on those)."
  (let* ((services (local-services))
         (relays (peer-relays-txs-p peer))
         ;; Advertise our real chain height (Core sends my_height) so peers can
         ;; pick us as a block-sync source; 0 only if the node isn't up yet.
         ;; The height is the CURRENT (active) chainstate's tip — never a
         ;; historical chainstate's.
         (node bitcoin-lisp::*node*)
         (start-height (if node
                           (bitcoin-lisp.storage:current-height
                            (bitcoin-lisp::node-current-chainstate node))
                           0))
         (version-payload (bitcoin-lisp.serialization:make-version-message-bytes
                           :services services
                           :addr-recv (%version-addr-recv peer)
                           :start-height start-height
                           :timestamp (bitcoin-lisp.serialization:get-unix-time)
                           :relay relays))
         (version-msg (bitcoin-lisp.serialization:serialize-message
                       "version" version-payload)))
    (when (send-message peer version-msg)
      ;; wtxidrelay only makes sense when we relay txs (BIP339); skip it on
      ;; block-relay/feeler connections, as Core does.
      (when relays
        (send-message peer (bitcoin-lisp.serialization:make-wtxidrelay-message)))
      (send-message peer (bitcoin-lisp.serialization:make-sendaddrv2-message))
      t)))

(defun %receive-and-store-version (peer &key (timeout 30))
  "Receive the peer's version message and record its services/height/user-agent.
Returns T on success, NIL if the first message wasn't a version."
  (multiple-value-bind (command payload) (receive-message peer :timeout timeout)
    (when (and command (string= command "version"))
      (flexi-streams:with-input-from-sequence (stream payload)
        (let ((version-msg (bitcoin-lisp.serialization:read-version-message stream)))
          (setf (peer-version peer) version-msg
                (peer-services peer)
                (bitcoin-lisp.serialization:version-message-services version-msg)
                (peer-start-height peer)
                (bitcoin-lisp.serialization:version-message-start-height version-msg)
                (peer-user-agent peer)
                (bitcoin-lisp.serialization:version-message-user-agent version-msg))))
      t)))

(defun %await-verack (peer &key (timeout 30))
  "Read messages until VERACK arrives (tolerating interleaved wtxidrelay/
sendaddrv2/sendheaders/sendtxrcncl), tracking the peer's advertised
capabilities. Sets the peer :ready and returns T on VERACK; NIL otherwise
(including a sendtxrcncl protocol violation, which disconnects)."
  (loop repeat 10
        do (multiple-value-bind (command payload) (receive-message peer :timeout timeout)
             (unless command (return nil))
             (cond
               ((string= command "verack")
                (%verack-finalize-recon peer)
                (setf (peer-state peer) :ready)
                (return t))
               ((string= command "sendaddrv2") (setf (peer-wants-addrv2 peer) t))
               ((string= command "sendheaders") (setf (peer-prefers-headers peer) t))
               ((string= command "wtxidrelay") (setf (peer-wtxid-relay peer) t))
               ((string= command "sendtxrcncl")
                (unless (%handle-handshake-sendtxrcncl peer payload)
                  (return nil)))))
        finally (return nil)))

(defun %v2-try-outbound (peer)
  "Attempt the BIP324 v2 handshake on PEER's fresh outbound connection.
On :FALLBACK-V1 (the peer never answered our key -- almost certainly a v1
node), reconnect to the same host/port and continue in v1. Returns T when the
version handshake may proceed (over whichever transport), NIL to give up."
  (let* ((conn (peer-connection peer))
         (result (v2-handshake-outbound conn)))
    (cond
      ((v2-transport-p result)
       (setf (connection-transport conn) result)
       (bitcoin-lisp:log-info "Peer ~A: v2 transport established (outbound)"
                              (peer-address peer))
       t)
      ((eq result :fallback-v1)
       (let ((fresh (make-tcp-connection (connection-host conn)
                                         (connection-port conn))))
         (when fresh
           (close-connection conn)
           (setf (peer-connection peer) fresh)
           (bitcoin-lisp:log-info "Peer ~A: no v2 response, reconnected as v1"
                                  (peer-address peer))
           t)))
      (t nil))))

(defun perform-handshake (peer &key (try-v2 (v2-available-p))
                                    (conn-type :outbound-full-relay))
  "Outbound version handshake (we initiate): send version+caps, receive the
peer's version, send verack, await theirs. CONN-TYPE sets the peer's connection
type (:outbound-full-relay, :block-relay, or :feeler) before the version is
sent, so a block-relay/feeler peer advertises relay=0 and skips wtxidrelay.
When TRY-V2 (default: whenever the v2 transport is enabled and supported), the
BIP324 encrypted transport is established first, reconnecting as v1 if the peer
turns out not to speak it. Returns T on success."
  (setf (peer-state peer) :handshaking
        (peer-conn-type peer) conn-type)
  (and (or (not try-v2)
           (%v2-try-outbound peer))
       (%send-version-and-capabilities peer)
       (%receive-and-store-version peer)
       ;; BIP330 offer goes after their VERSION (it is gated on their fRelay)
       ;; and before our VERACK (Core net_processing.cpp:3728-3744).
       (%maybe-send-sendtxrcncl peer)
       (send-message peer (bitcoin-lisp.serialization:make-verack-message))
       (%await-verack peer)))

(defun perform-inbound-handshake (peer &key (timeout 15))
  "Inbound version handshake (the peer dialed us, so it sends VERSION first):
receive their version, send ours+caps, send verack, await theirs. When v2
transport is enabled, the first 16 bytes decide v1 vs v2 (BIP324 detection):
v1 bytes are pushed back for the normal path; a v2 initiator gets the full
key/garbage/version-packet exchange before the version handshake. A shorter
TIMEOUT than the outbound path bounds how long a silent inbound peer can
stall. Returns T on success."
  (setf (peer-state peer) :handshaking)
  (when (v2-available-p)
    (let ((detected (v2-detect-inbound (peer-connection peer) :timeout timeout)))
      (cond ((v2-transport-p detected)
             (setf (connection-transport (peer-connection peer)) detected)
             (bitcoin-lisp:log-info "Peer ~A: v2 transport established (inbound)"
                                    (peer-address peer)))
            ((eq detected :v1))         ; sniffed bytes pushed back; proceed v1
            (t (return-from perform-inbound-handshake nil)))))
  (and (%receive-and-store-version peer :timeout timeout)
       (%send-version-and-capabilities peer)
       ;; BIP330 offer: their VERSION is already in hand on the inbound path;
       ;; ordering matches Core (wtxidrelay → sendaddrv2 → sendtxrcncl →
       ;; verack, net_processing.cpp:3715-3744).
       (%maybe-send-sendtxrcncl peer)
       (send-message peer (bitcoin-lisp.serialization:make-verack-message))
       (%await-verack peer :timeout timeout)))

(defun make-inbound-peer (connection address &key inbound-onion)
  "Build a peer for an accepted inbound CONNECTION from ADDRESS (state :connected,
inbound t, rate limiters initialized). INBOUND-ONION marks a connection accepted
on the local onion-service listener (Tor forwarding), whose true network is
:torv3 even though the socket peer is 127.0.0.1."
  (let ((peer (make-peer :connection connection
                         :state :connected
                         :address address
                         :inbound t
                         :inbound-onion (and inbound-onion t)
                         :connect-time (get-internal-real-time))))
    (init-peer-rate-limiters peer)
    peer))

(defun send-post-handshake-messages (peer)
  "Send feature negotiation messages after handshake completes."
  ;; BIP 130: Request header announcements
  (send-message peer (bitcoin-lisp.serialization:make-sendheaders-message))
  ;; BIP 133: Announce our minimum relay fee rate (1000 sat/kB = 1 sat/byte)
  (send-message peer (bitcoin-lisp.serialization:make-feefilter-message 1000))
  ;; One-time address fetch to populate/update addrman. Core sends GETADDR
  ;; on outbound connections only, and never block-relay-only ones (no addr
  ;; relay there, to avoid leaking the link): net_processing.cpp:3754-3772
  ;; + SetupAddressRelay. Without this, addrman fills only from unsolicited
  ;; gossip, DNS seeds, and fixed seeds.
  (when (and (not (peer-inbound peer))
             (not (eq (peer-conn-type peer) :block-relay)))
    (send-message peer (bitcoin-lisp.serialization:make-getaddr-message))))

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

(defconstant +max-block-timeouts+ 15
  "Per-peer block-request timeout count threshold before disconnect.
The previous value (3) caused a death-spiral in the testnet4 stress
region (h=51k-67k): a single 3MB stress block transits the wire in
30-90s, but the request-timeout fires per in-flight request. With
multiple in-flight requests to the same peer, all of them time out
within seconds of each other before any can be reset by a successful
receive — count rolled past 3 in one tick and the peer was
disconnected mid-transfer. Raised to 15: tolerates a normal stalled
batch without evicting peers who are simply mid-transit on big
blocks. record-block-received-from-peer still resets the count to
zero on any successful block.")

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

;;; Misbehavior, Discouragement, and Banning
;;;
;;; Two distinct mechanisms, mirroring Bitcoin Core's BanMan:
;;;  - Discouragement (automatic): a peer that misbehaves is added to a bounded,
;;;    ephemeral rolling filter. We never dial it, prefer it for inbound
;;;    eviction, and don't gossip it — but it is not hard-banned (which
;;;    previously let a peer grow our banned map without bound). Bitcoin Core's
;;;    misbehavior model is BINARY (PRs #25325 / #26294): a single protocol
;;;    violation marks the peer for discouragement — there is no accumulating
;;;    ban score, and loose (non-block) transaction-validation failures do not
;;;    count as misbehavior at all.
;;;  - Banning (manual): ban-peer / *banned-peers*, an explicit address ban with
;;;    an expiry (e.g. for a future setban RPC). Unaffected by misbehavior.

(defconstant +ban-duration-seconds+ (* 24 60 60)
  "Ban duration: 24 hours.")

(defvar *banned-peers* (make-hash-table :test 'equal)
  "Hash table mapping peer address (string) -> ban-expiry-time (universal-time).")

(defvar *discouraged-peers* (bitcoin-lisp:make-rejects-filter)
  "Bounded, ephemeral rolling set of discouraged peer addresses (strings).
Mirrors Bitcoin Core's BanMan discourage filter: auto-populated on misbehavior,
never persisted, and bounded (FIFO eviction) so a peer cannot grow it without
limit. Reuses the recent-rejects ring+hashtable structure.")

(defvar *ban-lock* (bt:make-lock "ban-lock")
  "Guards *banned-peers* and *discouraged-peers* (their hash-table / ring-buffer
mutations are not thread-safe). These are sync-thread-only today, so this is
future-proofing for a cross-thread writer (e.g. a setban RPC). Lock order is
always node-lock -> ban-lock (the readers run standalone or already under
node-lock), never the reverse, so it cannot deadlock against node-lock.")

(defun discourage-peer (address)
  "Mark ADDRESS as discouraged (bounded rolling filter)."
  (when (and address (plusp (length address)))
    (bt:with-lock-held (*ban-lock*)
      (bitcoin-lisp:add-recent-reject *discouraged-peers* address))))

(defun peer-discouraged-p (address)
  "T if ADDRESS is currently discouraged."
  (and address (plusp (length address))
       (bt:with-lock-held (*ban-lock*)
         (bitcoin-lisp:recent-reject-p *discouraged-peers* address))
       t))

(defun clear-discouraged ()
  "Clear the discourage filter."
  (bt:with-lock-held (*ban-lock*)
    (bitcoin-lisp:clear-recent-rejects *discouraged-peers*)))

(defun record-misbehavior (peer &optional reason)
  "Discourage and disconnect PEER for a protocol violation. Bitcoin Core's
misbehavior model is binary (Misbehaving -> m_should_discourage): any single
call marks the peer for discouragement — there is no accumulating score. The
address is added to the ephemeral discourage filter (never dialed, preferred
for eviction, not gossiped) and the connection is dropped. REASON, if given, is
logged. Returns T."
  (when reason
    (bitcoin-lisp:log-cat "net" "Misbehaving peer ~A: ~A"
                          (peer-address peer) reason))
  (discourage-peer (peer-address peer))
  (when (peer-connection peer)
    (close-connection (peer-connection peer))
    (setf (peer-connection peer) nil))
  (setf (peer-state peer) :disconnected)
  t)

(defun ban-peer (peer)
  "Ban a peer. Sets state to :banned and records ban expiry."
  (setf (peer-state peer) :banned)
  (let ((address (peer-address peer)))
    (when (and address (plusp (length address)))
      (bt:with-lock-held (*ban-lock*)
        (setf (gethash address *banned-peers*)
              (+ (get-universal-time) +ban-duration-seconds+)))))
  (when (peer-connection peer)
    (close-connection (peer-connection peer))
    (setf (peer-connection peer) nil)))

(defun peer-banned-p (address)
  "Check if ADDRESS is currently banned.
Returns T if banned, NIL otherwise. Expired bans are cleaned up."
  (bt:with-lock-held (*ban-lock*)
    (let ((expiry (gethash address *banned-peers*)))
      (cond
        ((null expiry) nil)
        ((> (get-universal-time) expiry)
         ;; Ban expired, remove it
         (remhash address *banned-peers*)
         nil)
        (t t)))))

(defun clear-ban-list ()
  "Clear all bans."
  (bt:with-lock-held (*ban-lock*)
    (clrhash *banned-peers*)))

(defun ban-address (address &optional (seconds +ban-duration-seconds+))
  "Manually ban ADDRESS (string) for SECONDS from now (Bitcoin Core setban add).
Returns T, NIL for an empty address."
  (when (and (stringp address) (plusp (length address)))
    (bt:with-lock-held (*ban-lock*)
      (setf (gethash address *banned-peers*)
            (+ (get-universal-time) seconds)))
    t))

(defun unban-address (address)
  "Remove ADDRESS from the ban list (Bitcoin Core setban remove). Returns T if it
was banned, NIL otherwise."
  (bt:with-lock-held (*ban-lock*)
    (remhash address *banned-peers*)))

(defun list-bans ()
  "Return a list of (address . banned-until-universal-time) for active bans,
pruning any that have expired (Bitcoin Core listbanned)."
  (let ((now (get-universal-time))
        (result '())
        (expired '()))
    (bt:with-lock-held (*ban-lock*)
      (maphash (lambda (addr expiry)
                 (if (> now expiry)
                     (push addr expired)
                     (push (cons addr expiry) result)))
               *banned-peers*)
      (dolist (addr expired) (remhash addr *banned-peers*)))
    result))

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
                  ;; Serve requests share one bucket (getheaders/getblocks each
                  ;; walk the active chain; bound the aggregate load).
                  ((string= command "getheaders") (peer-rate-limit-serve peer))
                  ((string= command "getblocks") (peer-rate-limit-serve peer))
                  ((string= command "getaddr") (peer-rate-limit-serve peer))
                  (t nil))))  ; No rate limit for other message types
    (if bucket
        (bitcoin-lisp:token-bucket-allow-p bucket)
        t)))
