(in-package #:bitcoin-lisp.networking)

;;; Peer Management
;;;
;;; Handles the state machine for Bitcoin peer connections.

(deftype peer-state ()
  '(member :disconnected :connecting :connected :handshaking :ready))

;;; Monotonic per-node peer ids (Bitcoin Core CNode::id), assigned at peer
;;; creation. Exposed via getpeerinfo "id" and used by getblockfrompeer to name a
;;; peer. Lock-guarded because outbound (sync thread) and inbound (listener
;;; thread) peers are created concurrently.
;;;
;;; The FIRST id is 0. Core's CConnman::GetNewNodeId is
;;; `nLastNodeId.fetch_add(1)' over a counter initialised to 0
;;; (net.cpp:3390-3393, net.h:1609), so it hands out the value BEFORE the
;;; increment; ours handed out the value after it and every peer id in this
;;; node was one too high. The framework asserts the absolute id of a node's
;;; first peer -- p2p_addrfetch.py:40 and p2p_mutated_blocks.py:77 both read
;;; `info[0]['id'] == 0'.
(defvar *peer-id-counter* 0)
(defvar *peer-id-lock* (bt:make-lock "peer-id"))
(defun next-peer-id ()
  (bt:with-lock-held (*peer-id-lock*)
    (prog1 *peer-id-counter* (incf *peer-id-counter*))))

;;; Per-address addr/addrv2 intake rate limit (Bitcoin Core
;;; net_processing.cpp:190-197): the units are ADDRESSES, not messages.
(defconstant +max-addr-rate-per-second+ 0.1d0
  "Token-bucket refill rate for gossiped-address processing (Core
MAX_ADDR_RATE_PER_SECOND). At steady state a peer gets one address through
every 10 seconds; everything faster is dropped, not queued.")

(defconstant +max-addr-processing-token-bucket+
  bl.ser:+max-addr-count+
  "Soft cap of the addr token bucket (Core MAX_ADDR_PROCESSING_TOKEN_BUCKET =
MAX_ADDR_TO_SEND = 1000): time-based refill never exceeds it, but the
+MAX_ADDR_TO_SEND bump after our own getaddr may.")

(defstruct peer
  "A Bitcoin peer."
  (id (next-peer-id) :type integer)
  (connection nil :type (or null connection))
  (state :disconnected :type peer-state)
  (version nil)  ; Received version message
  ;; Chain-sync timeout state (Core CNodeState::ChainSyncTimeoutState,
  ;; net_processing.cpp:490-501). All times are UNIX SECONDS — the codebase
  ;; also carries get-node-time (universal) and internal-real-time clocks, and
  ;; mixing them here would be a ~2.2e9-second error.
  (chain-sync-timeout 0 :type integer)        ; 0 = unarmed
  (chain-sync-work-header nil)                ; tip hash we benchmarked against
  (chain-sync-sent-getheaders nil)
  (chain-sync-protect nil)
  ;; Core CNodeState::m_last_block_announcement (net_processing.cpp:504). UNIX
  ;; SECONDS, 0 = never announced. Credited where a block is ANNOUNCED with
  ;; more work than our tip — headers (:2922) and cmpctblock (:4624) — and
  ;; deliberately NOT where a compact block reconstructs: a peer that keeps us
  ;; current by announcing is doing its job whether or not our own mempool
  ;; happened to hold the txs. Read only by the extra-outbound rotation, which
  ;; evicts the OLDEST stamp; 0 therefore means "first in line", which is why
  ;; that rotation needs a tie-break — every fresh peer sits at 0 together.
  (last-block-announcement 0 :type integer)
  ;; BIP133 feefilter state (Core Peer::m_fee_filter_sent /
  ;; m_next_send_feefilter). FEE-FILTER-SENT is the last value we put on the
  ;; wire (NIL = none yet); NEXT-SEND-FEEFILTER is a unix time, 0 = due now.
  (fee-filter-sent nil)
  (next-send-feefilter 0 :type integer)
  ;; OUR nonce for this one connection, sent in the VERSION we push (Core
  ;; CNode::nLocalHostNonce, net.h:994). Per-connection, never node-wide.
  (local-nonce 0 :type (unsigned-byte 64))
  (services 0 :type (unsigned-byte 64))
  ;; Core Peer::m_starting_height{-1} (net_processing.cpp:277): -1 is "the peer
  ;; has not told us", and getpeerinfo reports it verbatim -- rpc_net.py:148
  ;; reads -1 for a peer that never sent a VERSION. A 0 default said "genesis".
  (start-height -1 :type (signed-byte 32))
  (user-agent "" :type string)
  (ping-nonce nil)
  ;; NIL means no ping has ever been sent on this connection, which is DUE, not
  ;; recent. Core encodes the same thing as m_ping_start{0us} against an
  ;; absolute clock, so `now > m_ping_start + PING_INTERVAL` is true on a fresh
  ;; peer (net_processing.cpp:5508). A 0 here would be an INTERNAL-REAL-TIME
  ;; zero, which means "process start" — see CHECK-PEER-HEALTH.
  (last-ping-time nil :type (or null integer))
  (ping-latency 0 :type integer)
  ;; Minimum ping round-trip observed on this connection, internal-time units
  ;; (Core CNode::m_min_ping_time; 0 = no pong yet). Surfaced as getpeerinfo
  ;; "minping".
  (min-ping-latency 0 :type integer)
  ;; Seconds the peer's version-message timestamp was ahead of (positive) or
  ;; behind (negative) our clock at receipt (Core Peer::m_time_offset,
  ;; net_processing.cpp:3646). getpeerinfo "timeoffset".
  (time-offset 0 :type integer)
  ;; Unix time of the last transaction ACCEPTED to the mempool from this peer
  ;; (Core CNode::m_last_tx_time, stamped on MempoolAcceptResult VALID,
  ;; net_processing.cpp:4540). 0 = never.
  (last-tx-time 0 :type integer)
  ;; Unix time of the last block received from this peer (Core
  ;; CNode::m_last_block_time, stamped in ProcessBlock, net_processing.cpp:
  ;; 3432). 0 = never.
  (last-block-time 0 :type integer)
  ;; Unix time this peer object was created (Core CNode::m_connected).
  (connected-at (bl.ser:get-unix-time) :type integer)
  ;; T once address relay is set up with this peer (Core Peer::
  ;; m_addr_relay_enabled via SetupAddressRelay): at handshake time for
  ;; outbound non-block-relay connections, or on the first addr-related
  ;; message (getaddr/addr/addrv2) from an inbound peer. Never for
  ;; block-relay-only connections.
  (addr-relay-enabled nil :type boolean)
  ;; Per-message-type wire byte counters (Core CNode::mapSendBytesPerMsgType /
  ;; mapRecvBytesPerMsgType), keyed by command string. Synchronized: sends
  ;; happen from both the sync thread and RPC threads, and getpeerinfo reads
  ;; from RPC threads (a lost incf under contention only under-counts a stat).
  (sent-per-msg (make-hash-table :test 'equal #+sbcl :synchronized #+sbcl t)
                :type hash-table)
  (recv-per-msg (make-hash-table :test 'equal #+sbcl :synchronized #+sbcl t)
                :type hash-table)
  (send-queue '() :type list)
  ;; Inv vectors from getdata messages this peer has sent that are not
  ;; answered yet, oldest first (Core Peer::m_getdata_requests,
  ;; net_processing.cpp:398). The getdata handler appends the whole message
  ;; and then serves from the front; serving STOPS while the peer is
  ;; send-paused, and whatever is left waits here until the next message pass
  ;; drains it (Core ProcessMessages, net_processing.cpp:5222-5227). Dropping
  ;; the remainder instead would make the peer wait out its own request
  ;; timeout for a block we had already read off disk.
  (getdata-queue '() :type list)
  ;; Bounded set of transactions this peer already knows about: everything we
  ;; have announced to it AND everything it has announced or sent to us (Core
  ;; m_tx_inventory_known_filter, written by AddKnownTx). Keyed by the id this
  ;; peer PREFERS -- wtxid once it negotiated wtxidrelay, txid otherwise, which
  ;; is the id its own invs carry -- so every reader must build the inv first
  ;; and look the filter up by that hash (net_processing.cpp:4491-4492,
  ;; :6060-6069). Was an unbounded hash-table -- a per-peer memory leak on
  ;; long-lived relay connections. Core bounds the equivalent at
  ;; CRollingBloomFilter{50000}; we use the same hash+FIFO-ring bounded set as
  ;; the recent-rejects filter.
  (announced-txs (bl:make-rejects-filter 50000)
                 :type bl:recent-rejects)
  ;; Bounded set of addresses (ip||port keys) this peer already knows -- either
  ;; it sent them to us or we relayed them to it. Dedup for addr gossip; Core's
  ;; m_addr_known CRollingBloomFilter{5000}.
  (known-addrs (bl:make-rejects-filter 5000)
               :type bl:recent-rejects)
  ;; Addresses waiting to be gossiped to this peer, in push order (Core
  ;; Peer::m_addrs_to_send, net_processing.cpp:343). RELAY-ADDRESS appends
  ;; here instead of sending; FLUSH-ADDR-ANNOUNCEMENTS empties the whole
  ;; vector into ONE addr/addrv2 on the peer's Poisson schedule, which is
  ;; what breaks the correlation between when we LEARNED an address and when
  ;; we pass it on. Bounded by +max-addr-to-send+ with random replacement,
  ;; so a flood cannot choose which addresses survive.
  (addrs-to-send (make-array 0 :adjustable t :fill-pointer 0)
                 :type (array t (*)))
  ;; internal-real-time deadline of the next addr flush to this peer (Core
  ;; Peer::m_next_addr_send, net_processing.cpp:374). 0 = due now, which is
  ;; Core's initial value too.
  (next-addr-send 0 :type integer)
  ;; Pending tx announcements, flushed in batches on a Poisson schedule
  ;; instead of per-tx immediate invs (Core m_tx_inventory_to_send +
  ;; m_next_inv_send_time). Entries are (txid wtxid fee-rate-per-kb),
  ;; NEWEST FIRST: an enqueue is a PUSH, which is the O(1) insert Core gets
  ;; from a std::set, and %FLUSH-PEER-TX-INVS restores announcement order
  ;; when it drains. Nothing truncates it -- Core has no cap on
  ;; m_tx_inventory_to_send either, and its pressure valve is the drain that
  ;; accelerates with the backlog. Guarded by the node lock: the P2P enqueue
  ;; paths (handle-tx, orphan cascade) run under with-current-node-lock on the
  ;; sync thread, the RPC broadcast path (sendrawtransaction/submitpackage)
  ;; enqueues under the same lock from RPC threads, and the flush
  ;; (flush-tx-announcements) takes it too.
  (tx-inv-queue '() :type list)
  ;; Unix-time deadline of the next inv flush for this peer, on Core's
  ;; MOCKABLE clock -- Core's m_next_inv_send_time comes from
  ;; GetTime<microseconds>(), which setmocktime moves, and that is how the
  ;; functional tests make a trickle fire without sleeping (an inbound
  ;; peer's is read off the shared rotation, see *next-inbound-inv-flush*).
  ;; 0 = no pass yet: the first one trickles, as Core's does.
  (next-inv-send-time 0 :type integer)
  ;; Health monitoring
  ;; Block delivery tracking.
  ;;
  ;; Core CNodeState::m_downloading_since (net_processing.cpp:458): stamped
  ;; when this peer's in-flight list goes from EMPTY to non-empty, and
  ;; re-stamped every time the FRONT in-flight block is delivered. So it
  ;; measures SILENCE since the last delivery, not the age of a request --
  ;; which is what makes one decision per peer possible. 0 = not downloading.
  (downloading-since 0 :type integer)
  ;; Core CNodeState::m_stalling_since (:455): set only when the block
  ;; download WINDOW cannot move because this peer holds its first missing
  ;; block, cleared by any delivery. 0 = not stalling.
  (stalling-since 0 :type integer)
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
  ;;   :manual               operator-named destination (-addnode, -connect,
  ;;                         addnode RPC): full relay like :outbound-full-relay,
  ;;                         but outside every automatic slot budget, never
  ;;                         auto-evicted and never punished (Core MANUAL)
  ;;   :addr-fetch           one-shot -seednode dial, closed once it answers
  (conn-type :inbound :type keyword)
  ;; T once we have answered this peer's getaddr (Bitcoin Core m_getaddr_recvd):
  ;; one address response per connection, to limit address-stamping spam.
  (getaddr-sent nil :type boolean)
  ;; T while a getaddr WE sent to this peer is unanswered (Bitcoin Core
  ;; m_getaddr_sent — note our getaddr-sent slot above is Core's
  ;; m_getaddr_recvd). Set when send-post-handshake-messages requests
  ;; addresses; cleared by the addr handler on any non-full (<1000) addr/
  ;; addrv2 message. While set, freshly-learned addresses are NOT relayed
  ;; onward (getaddr responses are stale gossip, net_processing.cpp:4100).
  (getaddr-requested nil :type boolean)
  ;; Per-peer addr processing token bucket (Core Peer::m_addr_token_bucket,
  ;; net_processing.cpp:384): starts at 1.0, refills at
  ;; +max-addr-rate-per-second+ (0.1/s) up to +max-addr-processing-token-
  ;; bucket+ (1000), one token consumed per gossiped address; addresses
  ;; beyond the bucket are DROPPED. Sending a getaddr bumps it by 1000 so
  ;; the solicited response is exempt.
  (addr-token-bucket 1.0d0 :type double-float)
  ;; internal-real-time when the bucket was last refilled (m_addr_token_timestamp).
  (addr-token-timestamp (get-internal-real-time) :type integer)
  ;; Lifetime counters surfaced in getpeerinfo (m_addr_processed /
  ;; m_addr_rate_limited).
  (addr-processed 0 :type integer)
  (addr-rate-limited 0 :type integer)
  ;; In-progress low-work headers presync/redownload with this peer, or NIL
  ;; (Bitcoin Core Peer::m_headers_sync). One slot serves both drivers — the
  ;; solicited Phase-1 sync (sync-headers) and the generic announcement path
  ;; (ingest-headers-from-peer) — so they can never run two syncs at once.
  (headers-sync nil)
  ;; Universal-time of our last getheaders to this peer, 0 = never (Core
  ;; Peer::m_last_getheaders_timestamp). Throttles our own requests; cleared
  ;; when a connecting headers message arrives, so the answer re-arms it.
  (last-getheaders-time 0 :type integer)
  ;; T once this node has opened header sync with the peer (Core
  ;; CNodeState::fSyncStarted, net_processing.cpp:453). Core's SendMessages
  ;; sends its initial getheaders only `if (!state.fSyncStarted)'
  ;; (net_processing.cpp:5797), so a peer is asked ONCE and everything after
  ;; that is announcement-driven. Nothing clears it while the connection
  ;; lives: a fresh peer object is how a reconnect starts over.
  (headers-sync-started nil :type boolean)
  ;; Deadline for this peer's INITIAL headers sync (Core
  ;; Peer::m_headers_sync_timeout, net_processing.cpp:5814-5818), on the
  ;; mockable clock in Unix seconds. NIL while no sync has been opened;
  ;; an integer once one has; :NEVER once our header chain has caught up
  ;; to within a day of now, which is Core's microseconds::max() -- "after
  ;; we've caught up once, reset the timeout so we can't trigger disconnect
  ;; later" (:6150-6153).
  (headers-sync-timeout nil)
  ;; Core Peer::m_inv_triggered_getheaders_before_sync
  ;; (net_processing.cpp:4197): set once a block INV from this peer has been
  ;; answered with a getheaders while header sync was NOT open with it, so a
  ;; peer earns at most one such getheaders before it becomes the sync peer.
  (inv-triggered-getheaders-before-sync nil :type boolean)
  ;; Compact block support (BIP 152)
  (compact-block-version 0 :type (unsigned-byte 64))  ; 0=not supported, 1 or 2
  (compact-block-high-bandwidth nil :type boolean)    ; Peer selected US as high-bandwidth (Core m_bip152_highbandwidth_from)
  (compact-block-high-bandwidth-to nil :type boolean) ; WE selected peer as high-bandwidth (Core m_bip152_highbandwidth_to)
  (pending-compact-block nil)                         ; Pending reconstruction state
  ;; ADDRv2 support (BIP 155)
  (wants-addrv2 nil :type boolean)                    ; Peer sent sendaddrv2
  ;; BIP 130 sendheaders support
  (prefers-headers nil :type boolean)                  ; Peer sent sendheaders
  ;; BIP 133 feefilter support
  (feefilter-rate 0 :type (unsigned-byte 64))          ; Peer's minimum fee rate (sat/kB)
  ;; Mempool-sequence snapshot taken at each inv flush to this peer (Core
  ;; Peer::TxRelay::m_last_inv_sequence, net_processing.cpp:322, init 1).
  ;; The getdata anti-probing gate serves a mempool tx only when its entry
  ;; sequence is BELOW this snapshot — i.e. the tx was already in the pool
  ;; when we last announced inventory to the peer (Core FindTxForGetData ->
  ;; info_for_relay). Blocks mempool-content probing of txs the peer
  ;; shouldn't know about yet.
  (last-inv-sequence 1 :type (unsigned-byte 64))
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
  ;; Transactions held back for reconciliation with this peer instead of being
  ;; announced (BIP-330). Created on demand, only for a registered peer.
  (recon-set nil)
  ;; The in-flight reconciliation round, if this node is its initiator.
  (recon-round nil)
  ;; Universal time of the last round with this peer, so the timer can space
  ;; them out.
  (recon-last-round 0 :type integer)
  ;; DoS protection: per-peer rate limiters
  (rate-limit-inv nil)
  (rate-limit-tx nil)
  (rate-limit-addr nil)
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
  (hash-last-unknown-block nil)
  ;;   last-common-block-hash — the walk cursor for per-peer block download
  ;;     (Core CNodeState::pindexLastCommonBlock): the highest block on BOTH
  ;;     this peer's best chain and ours whose ancestors we already have. Block
  ;;     requests to this peer start just above it, so we only ever ask a peer
  ;;     for blocks on the peer's OWN chain — the fix for fixating on a fork
  ;;     whose blocks no connected peer serves.
  (last-common-block-hash nil)
  ;; --- Queued block announcements (Core Peer::m_blocks_for_headers_relay,
  ;; net_processing.h). UpdatedBlockTip only QUEUES a new tip here
  ;; (net_processing.cpp:2180-2188); SendMessages turns the whole queue into
  ;; ONE announcement per pass (:5830-5956) -- up to 8 connected headers as a
  ;; single headers message, or one inv for the tip. Ours announced
  ;; synchronously from whatever thread connected the block, so a 400-block
  ;; `generate' put 400 separate invs on the wire per peer.
  ;;
  ;; Oldest-first, and written only under the node lock (the connect path) or
  ;; on the sync thread (the flush), which are the same two writers the peer
  ;; list already has.
  (blocks-for-headers-relay '() :type list)
  ;; The highest header we have SENT this peer (Core
  ;; CNodeState::pindexBestHeaderSent), the second half of PeerHasHeader: a
  ;; header we just sent is one the peer has, even before it tells us so.
  (best-header-sent-hash nil))

(defun peer-log-name (peer)
  "How a log line names PEER: Core's `peer=%d%s' of GetId() and
CNode::LogIP(fLogIPs) -- the numeric id always, the address only under -logips.

The id is what getpeerinfo, getblockfrompeer and every other line about the
same peer use, so it is the join key an operator already has; the address is
one flag away and out of the default log, which is Core's privacy model
(logging.h:28, net.cpp:704-707). Written once here rather than as an id and a
LOG-IP argument at each of the thirty-odd call sites."
  (format nil "peer=~D~A" (peer-id peer) (bl:log-ip (peer-address peer))))

(defvar *last-block-inv-triggering-headers-sync* nil
  "Core PeerManagerImpl::m_last_block_inv_triggering_headers_sync
(net_processing.cpp:4207): the hash of the last block announced by INV that
made this node open a getheaders with a peer it had not started header sync
with. NODE-WIDE, and that is the whole mechanism: with one initial-sync peer
at a time, Core is willing to add ONE MORE peer per newly announced block, so
the announcement is remembered here and every other peer announcing the SAME
block is skipped.")

(defun disconnect-msg (peer)
  "Core CNode::DisconnectMsg (net.cpp:709-714): \"disconnecting \" plus
PEER-LOG-NAME. A caller with a reason of its own writes it as Core does,
\"<reason>, ~A\"."
  (format nil "disconnecting ~A" (peer-log-name peer)))

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

(defvar *current-port* (bl.chain:chain-params-port (bl.chain:find-chain-params :testnet4))
  "The P2P port the node dials and listens on; init-node sets it per chain.")

(defvar *dns-seeds* (bl.chain:chain-params-dns-seeds (bl.chain:find-chain-params :testnet4))
  "The DNS seeds the node queries; init-node sets them per chain.")

;;; Peer connection

(defun init-peer-rate-limiters (peer)
  "Initialize per-peer rate limiters from global configuration."
  (flet ((rl (config) (bl:make-rate-limiter (car config) (cdr config))))
    (setf (peer-rate-limit-inv peer) (rl bl:*rate-limit-inv*))
    (setf (peer-rate-limit-tx peer) (rl bl:*rate-limit-tx*))
    (setf (peer-rate-limit-addr peer) (rl bl:*rate-limit-addr*))
    (setf (peer-rate-limit-headers peer) (rl bl:*rate-limit-headers*))
    (setf (peer-rate-limit-serve peer) (rl bl:*rate-limit-serve*)))
  peer)

(defun connect-peer (host &optional (port *current-port*))
  "Connect to a peer at HOST:PORT.
Returns (VALUES PEER PROXY-CONNECTION-FAILED-P): the peer, or NIL on failure.
Returns NIL if the host is banned or discouraged (never dial either).

PROXY-CONNECTION-FAILED-P is MAKE-TCP-CONNECTION's second value passed
straight through — Core's `proxy_connection_failed', T only when the dial died
at the SOCKS5 proxy and so says nothing about HOST. The dial's caller uses it
to decide whether the address is charged an addrman attempt at all
(net.cpp:494-497)."
  (when (or (peer-banned-p host) (peer-discouraged-p host))
    (return-from connect-peer nil))
  (multiple-value-bind (conn proxy-failed) (make-tcp-connection host port)
    (if conn
        (let ((peer (make-peer :connection conn
                               :state :connected
                               :address host
                               :connect-time (get-internal-real-time))))
          (init-peer-rate-limiters peer)
          ;; Core logs this on every CNode it constructs, outbound and inbound
          ;; alike (net.cpp:4005-4007), and p2p_add_connections.py greps for it.
          (if bl:*log-ips*
              (bl:log-cat "net" "Added connection to ~A peer=~D" host (peer-id peer))
              (bl:log-cat "net" "Added connection peer=~D" (peer-id peer)))
          peer)
        (values nil proxy-failed))))

(defun peer-live-p (peer)
  "T while PEER is still a connection we could actually use — our stand-in for
Core's `!pfrom.fDisconnect`.

Core marks a node it has decided to retire with fDisconnect and then refuses
to give it anything more; the socket handler reaps it on the next pass and
FinalizeNode runs. We have no fDisconnect flag: our retirement paths set the
state instead — every retirement path ends in DISCONNECT-PEER, which sets
:disconnected — so that state is our \"already retired\".

Anything that hands a retired peer a RESOURCE must consult this first: the
peer will never be retired a second time, so whatever it was granted is never
given back. (REPLACE-DISCONNECTED-PEERS reaps that state straight out of
NODE-PEERS without running a release, because by then the retirement that set
the state already did.)"
  (not (eq (peer-state peer) :disconnected)))

;;; --- Chain-sync protection slots (Core
;;; m_outbound_peers_with_protect_from_disconnect) ---
;;;
;;; Lives here, next to DISCONNECT-PEER, rather than in ibd.lisp beside
;;; CONSIDER-CHAIN-SYNC-EVICTION: the counter is peer-LIFECYCLE state, and
;;; every path that retires a peer has to hand the slot back. ibd.lisp loads
;;; after this file, so a release call there would be a forward reference and
;;; the previous placement left the counter with no production releaser at all
;;; — it only ever incremented, so after one round of outbound churn every
;;; slot was permanently spent and no peer could earn protection again.

(defun credit-block-announcement (peer)
  "Stamp PEER as having just announced a block that beats our tip (Core
net_processing.cpp:2922 for headers, :4624 for cmpctblock).

Both Core sites carry the same two-part condition, and both halves are load
bearing. The announced chain must be STRICTLY better than our tip — equalling
it is what every peer at the same tip does all day and would keep the whole
outbound set looking equally useful — and the announcement must have been NEW
to us, so that relaying a block we already had earns nothing. Otherwise a peer
could hold its slot forever by echoing back what we just told it.

Unix seconds, matching the slot and the sweep that reads it."
  (setf (peer-last-block-announcement peer)
        (bl.ser:get-unix-time)))

(defconstant +max-outbound-peers-to-protect+ 4
  "Core MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT.")

(defvar *protected-outbound-count* 0
  "How many outbound peers currently hold chain-sync protection.")

(defvar *outbound-protection-lock* (bt:make-lock "outbound-protection")
  "Guards *PROTECTED-OUTBOUND-COUNT* and the per-peer flag together. Core keeps
the counter under cs_main; we grant from the sync thread but release from the
sync, listener, and RPC threads, so a check-then-increment without a lock can
lose a release and re-create the leak this lock exists to prevent.")

(defun maybe-protect-outbound-peer (peer)
  "Grant chain-sync protection to an outbound FULL-RELAY peer that delivered a
chain at least as good as our tip (Core net_processing.cpp:2946-2956), up to
MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT.

Block-relay peers are deliberately NOT protected — Core keeps them always
subject to the bad/lagging chain logic.

A peer that has ALREADY been retired is refused (PEER-LIVE-P = Core's
`!pfrom.fDisconnect` on :2951). Without that clause the grant is a permanent
slot leak: the retirement that would hand the slot back has already happened,
so the increment is never undone and after four of them no peer can ever earn
protection again. Core needs the guard because the sub-minchainwork drop
(:2926-2944) sets fDisconnect a few lines ABOVE this grant on the same peer in
the same pass, and both conditions are satisfied at once by the common IBD
case of a peer whose best-known beats our low tip but misses the work floor."
  (bt:with-lock-held (*outbound-protection-lock*)
    (when (and (not (peer-chain-sync-protect peer))
               (peer-live-p peer)
               (not (peer-inbound peer))
               (eq (peer-conn-type peer) :outbound-full-relay)
               (< *protected-outbound-count* +max-outbound-peers-to-protect+))
      (setf (peer-chain-sync-protect peer) t)
      (incf *protected-outbound-count*)
      t)))

(defun release-outbound-protection (peer)
  "Give back PEER's protection slot. Core's FinalizeNode
(net_processing.cpp:1717-1718) does
`m_outbound_peers_with_protect_from_disconnect -= state->m_chain_sync.m_protect`
and then asserts the counter never went negative; FinalizeNode runs for every
node removal whatever the reason, so every one of our retirement paths
(DISCONNECT-PEER, RECORD-MISBEHAVIOR, BAN-PEER) calls this.

The per-peer flag is the single source of truth, which makes a repeated release
a no-op: without that, a peer retired twice (disconnected and then reaped, or
misbehaving and then disconnected) would decrement twice and let us hand out
more than MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT slots. Returns T iff a
slot was actually returned."
  (bt:with-lock-held (*outbound-protection-lock*)
    (when (peer-chain-sync-protect peer)
      (setf (peer-chain-sync-protect peer) nil)
      ;; Core's assert(m_outbound_peers_with_protect_from_disconnect >= 0). The
      ;; flag makes the else branch unreachable; if it ever runs the accounting
      ;; is broken, so say so loudly and refuse to go negative rather than let a
      ;; negative counter silently uncap protection.
      (if (plusp *protected-outbound-count*)
          (decf *protected-outbound-count*)
          (bl:log-warn
           "Outbound protection counter underflow releasing ~A"
           (peer-log-name peer)))
      t)))

(defvar *peer-disconnect-hook* nil
  "When non-NIL, a function of one argument (the peer) called from
DISCONNECT-PEER after the connection is torn down. protocol.lisp registers
the tx-request tracker's DisconnectedPeer cleanup here — the tracker lives in
a later-loaded file, so a direct call would be a forward reference.")

(defun disconnect-peer (peer)
  "Disconnect from a peer."
  (when (peer-connection peer)
    (close-connection (peer-connection peer)))
  (setf (peer-state peer) :disconnected)
  (setf (peer-connection peer) nil)
  ;; Hand back any chain-sync protection slot (Core FinalizeNode). Done before
  ;; the hooks below, which are wrapped in IGNORE-ERRORS and must not be able
  ;; to skip it.
  (release-outbound-protection peer)
  ;; Drop any in-progress low-work headers sync with this peer (Core
  ;; FinalizeNode resets Peer state; the buffers die with the struct).
  (setf (peer-headers-sync peer) nil)
  ;; Drop this peer's orphan ANNOUNCEMENTS (DoS hygiene). Orphans other
  ;; peers also announced survive (Core TxOrphanage::EraseForPeer).
  (let ((node bl:*node*))
    (when (and node (bl:node-mempool node))
      (bl.mp:orphan-erase-for-peer
       (bl.mp:mempool-orphan-pool (bl:node-mempool node))
       peer)))
  ;; Tx-request tracker cleanup (Core TxDownloadManagerImpl::DisconnectedPeer):
  ;; forget the peer's announcements; its in-flight requests become
  ;; re-schedulable so the next scheduler pass fails them over.
  (when *peer-disconnect-hook*
    (ignore-errors (funcall *peer-disconnect-hook* peer))))

(defun peer-handshake-in-flight-p (peer)
  "T while PEER's version handshake is still running, i.e. Core's
`!pnode->fSuccessfullyConnected' (net.cpp:2006, net_processing.cpp:5244).

An accepted inbound peer is published at ACCEPT, as Core's CNode is
(net.cpp:1854-1858), so it is in the node's peer list -- and in getpeerinfo --
while a thread of its own drives its handshake. Every sync-thread duty that
would touch that socket asks this first, because the two threads must not share
the stream."
  (member (peer-state peer) '(:connected :handshaking)))

(defun flush-peer-send-buffers (peers)
  "Retry every connected peer's buffered unsent bytes without blocking — the
periodic half of Core's per-socket SocketSendData, driven from the sync/IBD
housekeeping loops (~1x/second) since we have no dedicated socket thread.
No-op for peers with nothing buffered.

Never a peer whose handshake is still running: that socket belongs to the
handshake thread until it reaches :READY (an accepted inbound peer is published
at ACCEPT, as Core's CNode is), and two threads writing one stream interleave.
Nothing waits -- a mid-handshake peer's buffered bytes go out on the
handshake's own next send."
  (dolist (peer peers)
    (let ((conn (peer-connection peer)))
      (when (and conn (connection-connected conn)
                 (not (peer-handshake-in-flight-p peer)))
        (flush-send-buffer conn)))))

;;; Message I/O

(defun %message-wire-size (v2-p command payload-len)
  "On-the-wire byte size of one message with COMMAND and PAYLOAD-LEN: v1 is
the 24-byte header plus payload; a BIP324 v2 packet is the 3-byte encrypted
length, 1-byte header, contents (1-byte short type id, or 0x00 + the 12-byte
type verbatim, plus the payload), and the 16-byte Poly1305 tag."
  (if v2-p
      (+ 20
         (if (position command *v2-message-ids* :test #'equal) 1 13)
         payload-len)
      (+ 24 payload-len)))

(alexandria:define-constant +known-message-commands+
  '("addr" "addrv2" "block" "blocktxn" "cfcheckpt" "cfheaders" "cfilter"
    "cmpctblock" "feefilter" "filteradd" "filterclear" "filterload" "getaddr"
    "getblocks" "getblocktxn" "getcfcheckpt" "getcfheaders" "getcfilters"
    "getdata" "getheaders" "headers" "inv" "mempool" "merkleblock" "notfound"
    "ping" "pong" "reject" "sendaddrv2" "sendcmpct" "sendheaders"
    "sendtxrcncl" "tx" "verack" "version" "wtxidrelay")
  :test #'equalp :documentation "Message types that get their own byte-accounting bucket — Core's
ALL_NET_MESSAGE_TYPES. Anything else is folded into +other-message-command+.")

(alexandria:define-constant +other-message-command+ "*other*"
  :test #'equalp :documentation "Core NET_MESSAGE_TYPE_OTHER: the single bucket every unrecognised command
shares.")

(defun %account-message (table v2-p command payload-len)
  "Accumulate one message's wire bytes into TABLE (a per-peer command ->
bytes counter map, Core mapSend/RecvBytesPerMsgType).

The command is normalised to a KNOWN type or to the shared other-bucket
BEFORE the gethash. Core initialises its map once per CNode with every known
type plus NET_MESSAGE_TYPE_OTHER and folds anything unrecognised into that
bucket, under the comment `To prevent a memory DOS, only allow known message
types' (net.cpp:684-691) -- the map is a fixed small size for the life of the
connection.

We used the raw wire command as the key, so every distinct command string a
peer sent created a permanent new entry. An unrecognised command is otherwise a
complete no-op here -- no rate-limit bucket, and handle-message falls through
to (t nil) -- so nothing disconnected the peer or even noticed. A 24-byte
message with a fresh random type field cost the attacker 24 bytes and cost us a
hash entry plus a string key, never reclaimed while the peer stayed connected.

Normalising BEFORE the lookup is the whole point: doing it after would have
already created the entry."
  (let ((key (if (member command +known-message-commands+ :test #'string=)
                 command
                 +other-message-command+)))
    (incf (gethash key table 0) (%message-wire-size v2-p command payload-len))))

(defun snapshot-per-msg-table (table)
  "Fresh copy of a per-message byte-counter TABLE for safe cross-thread
reporting (getpeerinfo bytessent_per_msg / bytesrecv_per_msg): the live
table is written by the sync/RPC sender threads while getpeerinfo reads."
  (let ((copy (make-hash-table :test 'equal)))
    (flet ((copy-all ()
             (maphash (lambda (k v) (setf (gethash k copy) v)) table)))
      #+sbcl (sb-ext:with-locked-hash-table (table) (copy-all))
      #-sbcl (copy-all))
    copy))

(defun send-message (peer message-bytes)
  "Send a raw (v1-framed) message to a peer; a connection with a v2 transport
re-frames it as an encrypted BIP324 packet. Returns T on success, NIL on
failure."
  (when (and (peer-connection peer)
             (connection-connected (peer-connection peer)))
    (let ((conn (peer-connection peer))
          (command (bl.ser:bytes-to-command (subseq message-bytes 4 16))))
      ;; Core logs every send under net (PushMessage, net.cpp:4075:
      ;; `sending %s (%d bytes) peer=%d`). The receive side is logged the
      ;; same way, so a reply that never reached the wire is otherwise the
      ;; one thing a debug.log cannot show.
      (bl:log-cat "net" "sending ~A (~D bytes) peer=~A"
                  command (- (length message-bytes) 24) (peer-id peer))
      ;; Per-command send accounting (Core CConnman::PushMessage's
      ;; mapSendBytesPerMsgType, counted when the message is handed to the
      ;; transport). The command sits at bytes 4-15 of the v1 frame.
      (%account-message (peer-sent-per-msg peer)
                        (connection-transport conn)
                        command
                        (- (length message-bytes) 24))
      (if (connection-transport conn)
          (v2-send-message conn (connection-transport conn) message-bytes)
          (send-bytes conn message-bytes)))))

(defun receive-message (peer &key (timeout 30))
  "Take the next complete message from PEER without waiting for one.

Returns (VALUES COMMAND PAYLOAD) when a whole message is in hand, or
(VALUES NIL :INCOMPLETE) when part of one has arrived and the rest has not —
the caller should move on and come back. (VALUES NIL NIL) is a failure, and the
connection has already been dropped where that matters.

Partial reads live on the connection (Core CNode::vRecvMsg), so a peer trickling
a 4 MiB block costs its own turn in the pump and nothing else. Callers that
genuinely cannot proceed without an answer — the handshakes — want
RECEIVE-MESSAGE-BLOCKING instead."
  (when (and (peer-connection peer)
             (connection-connected (peer-connection peer)))
    (let ((conn (peer-connection peer)))
      (when (connection-transport conn)
        (return-from receive-message
          (multiple-value-bind (command payload)
              (v2-receive-message conn (connection-transport conn)
                                  :timeout timeout)
            (when command
              (%account-message (peer-recv-per-msg peer) t command
                                (length payload)))
            (values command payload))))
      ;; Parse the 24-byte header, unless a previous pass already did.
      ;;
      ;; A message is TWO reads, and that makes framing a per-MESSAGE property
      ;; the byte reader cannot see — which is why the parsed header is parked
      ;; on the CONNECTION between passes. Magic and size are validated in the
      ;; branch that parses, so a resumed pass goes straight to its payload.
      (let ((header (connection-recv-framing conn)))
        (unless header
          (let ((bytes (receive-bytes-resumable conn 24)))
            (when (eq bytes :incomplete)
              (return-from receive-message (values nil :incomplete)))
            (unless bytes
              (return-from receive-message nil))
            (setf header (bl.bytes:with-byte-reader (stream bytes)
                           (bl.ser:read-message-header stream)))
            ;; Nothing is parked yet, so these two rejections leave no framing
            ;; state behind — but the 24 bytes ARE consumed, so both must drop
            ;; the connection (see %abandon-receive for why).
            (unless (equalp (bl.ser:message-header-magic header)
                            bl.ser:*network-magic*)
              ;; The bytes we actually saw, as Core prints them (`Header
              ;; error: Wrong MessageStart %s received, peer=%d`,
              ;; net.cpp:753). Without them the line says only that the
              ;; stream is out of frame, never where the stream came from --
              ;; and a desynchronised read and a wrong-network peer produce
              ;; exactly the same line.
              (bl:log-cat "net"
                          "Bad message magic ~A from ~A, disconnecting"
                          (bl.crypto:bytes-to-hex
                           (bl.ser:message-header-magic header))
                          (peer-log-name peer))
              (disconnect-peer peer)
              (return-from receive-message nil))
            (when (> (bl.ser:message-header-payload-length header)
                     bl:+max-message-payload+)
              (bl:log-cat "net" "Oversized message from ~A: ~D bytes (max ~D), disconnecting"
                          (peer-log-name peer)
                          (bl.ser:message-header-payload-length header)
                          bl:+max-message-payload+)
              (disconnect-peer peer)
              (return-from receive-message nil))
            ;; Park it: the payload read below may span several more passes and
            ;; the framing must survive them.
            (setf (connection-recv-framing conn) header)))
        (let ((payload-len (bl.ser:message-header-payload-length header)))
                ;; Read payload
                (let ((payload (if (zerop payload-len)
                                   #()
                                   (let ((r (receive-bytes-resumable conn payload-len)))
                                     (when (eq r :incomplete)
                                       (return-from receive-message
                                         (values nil :incomplete)))
                                     r))))
                  ;; Whole message in hand (or failed): the framing state is
                  ;; consumed either way.
                  (setf (connection-recv-framing conn) nil)
                  (unless (or (zerop payload-len) payload)
                    ;; Header consumed, payload never completed: the peer is now
                    ;; permanently out of frame with us. Nothing here means the
                    ;; peer is malicious — a payload lagging its header past the
                    ;; caller's timeout is enough — but the connection is
                    ;; unusable either way, so drop it and let peer maintenance
                    ;; dial a replacement.
                    (bl:log-cat "net" "Incomplete ~A message from ~A, disconnecting"
                                (bl.ser:message-header-command header)
                                (peer-log-name peer))
                    (disconnect-peer peer)
                    (return-from receive-message nil))
                  ;; Verify checksum
                  (let ((computed-checksum
                          (bl.ser:compute-checksum
                           (if (zerop payload-len) #() payload))))
                    (unless (equalp (subseq computed-checksum 0 4)
                                    (bl.ser:message-header-checksum header))
                      ;; Drop the MESSAGE, keep the peer — Core's explicit choice
                      ;; ("Message deserialization failed. Drop the message but
                      ;; don't disconnect the peer.", net.cpp:678-683, reached
                      ;; for a wrong checksum at net.cpp:819-825). A full message
                      ;; was consumed here, so unlike every other failure in this
                      ;; function the framing is intact and there is nothing to
                      ;; resynchronize. Disconnecting would also turn any bug in
                      ;; our own payload handling into node-wide peer churn.
                      ;; Bad MAGIC is the opposite case and does disconnect
                      ;; above, matching net.cpp:752-755.
                      (bl:log-cat "net" "Bad checksum on ~A from ~A, dropping message"
                                  (bl.ser:message-header-command header)
                                  (peer-log-name peer))
                      (return-from receive-message nil))
                    (let ((command (bl.ser:message-header-command header)))
                      (%account-message (peer-recv-per-msg peer) nil
                                        command payload-len)
                      (values command payload)))))))))

(defun receive-message-blocking (peer &key (timeout 30))
  "WAIT for the next complete message from PEER; (VALUES COMMAND PAYLOAD), or
NIL if none arrives within the budget.

For the conversations that cannot proceed without an answer: the version/verack
handshake, and the header-sync exchange, which is a request/response dialogue
with one chosen peer rather than a pass over all of them. Everything that pumps
MANY peers must use RECEIVE-MESSAGE — waiting here is precisely what let one
slow peer stall the rest.

⚠️ The residual is REAL and node-wide, not peer-local. Header sync runs on the
SAME thread as the pump (sync-blockchain -> sync-headers-with-sync-peer, and the
pump only runs after it returns), so while this waits on its chosen peer NO peer
is drained. Its bound is loose too: sync-headers' attempt counter only advances
on a silent peer, so one that keeps sending anything else runs 30 attempts x 5s
per request, up to max-requests. Making header sync a per-peer state machine over
the shared pump — Core has no header-sync loop at all, it is ordinary message
handling — is what removes this, and it is the next step, not this one."
  (let ((deadline (+ (get-internal-real-time)
                     (* timeout internal-time-units-per-second))))
    (loop
      (multiple-value-bind (command payload) (receive-message peer :timeout timeout)
        (when command
          (return (values command payload)))
        ;; A hard failure (bad magic, oversized, EOF) has already dropped the
        ;; peer; only :incomplete is worth waiting on.
        (unless (eq payload :incomplete)
          (return nil)))
      ;; Re-read the connection each pass: a dispatch elsewhere can NIL it.
      (let ((conn (peer-connection peer)))
        (when (or *ibd-stop-requested*
                  (> (get-internal-real-time) deadline)
                  (null conn)
                  (not (connection-connected conn)))
          ;; End the read we abandoned rather than leaving an allocated
          ;; accumulator behind: %receive-gave-up drops the peer if part of a
          ;; message was consumed (it is out of frame either way) and simply
          ;; clears the state if not. Returning bare NIL used to strand a
          ;; zero-filled buffer that the pump then reported as a stalled peer.
          (return (when conn (%receive-gave-up conn))))
        ;; Nothing readable this instant: wait a short window. The deadline
        ;; above ends the wait; the reader itself applies no clock.
        (data-available-p conn :timeout 0.2)))))

(defun peer-outbound-or-block-relay-p (peer)
  "T for the connection types that are candidates for AUTOMATIC disconnection
on chain-quality grounds — Core CNode::IsOutboundOrBlockRelayConn
(net.h:771-785): OUTBOUND_FULL_RELAY and BLOCK_RELAY only.

Two halves matter equally. It must INCLUDE :block-relay, which the word
\"outbound\" does not obviously cover in our vocabulary. And it must EXCLUDE
:manual (-addnode) peers: connect-added-nodes redials every missing added node
on the ~30s maintenance tick, so admitting one would produce a
connect -> getheaders -> disconnect -> reconnect loop every 30 seconds against
a peer the operator explicitly pinned. Feelers and inbound are excluded too."
  (and (not (peer-inbound peer))
       (member (peer-conn-type peer) '(:outbound-full-relay :block-relay))
       t))

(defun peer-preferred-download-p (peer)
  "Core CNodeState::fPreferredDownload, assigned once at VERACK
(net_processing.cpp:3750): `(!IsInboundConn() || HasPermission(NoBan)) &&
!IsAddrFetchConn() && CanServeBlocks(peer)\'. Derived here rather than stored,
because every input is already a property of the peer.

It is the set the headers-download timeout counts: a stalling sync peer is
dropped only when there is ANOTHER preferred-download peer to ask instead
(net_processing.cpp:6128), so a node whose peers are all inbound keeps its
sync peer -- Core: \"we have bigger problems if we can\'t get any outbound
peers\"."
  (and (or (not (peer-inbound peer))
           (peer-has-permission-p peer +perm-noban+))
       (not (eq (peer-conn-type peer) :addr-fetch))
       (logtest (peer-services peer)
                (logior bl.ser:+node-network+ bl.ser:+node-network-limited+))
       t))

(defun peer-expects-services-p (peer)
  "T when PEER's connection type makes the DESIRABLE-SERVICES gate apply --
Core CNode::ExpectServicesFromConn (net.h:833-847), whose switch says false
for INBOUND, MANUAL and FEELER and true for OUTBOUND_FULL_RELAY, BLOCK_RELAY,
ADDR_FETCH and PRIVATE_BROADCAST.

This is NOT PEER-OUTBOUND-OR-BLOCK-RELAY-P, which is Core's
IsOutboundOrBlockRelayConn and governs chain-quality eviction; the two sets
differ by ADDR_FETCH, and using the eviction predicate here was the bug.
p2p_handshake.py exercises all three of outbound-full-relay, block-relay-only
and addr-fetch with services Core refuses, and asserts a disconnect for each
(p2p_handshake.py:53-64); ours handshaked the addr-fetch peer, so the fifth
of nine cases hung."
  (and (not (peer-inbound peer))
       (not (member (peer-conn-type peer) '(:inbound :manual :feeler)))
       t))

(defun peer-manual-p (peer)
  "Core CNode::IsManualConn (net.h:791): PEER is an operator-named connection
(-addnode, -connect, the addnode RPC). Such a peer is typed :manual by the
dial sites in src/node/peers.lisp; nothing else produces the type."
  (eq (peer-conn-type peer) :manual))

;;; Handshake

(defun peer-relays-txs-p (peer)
  "T if OUR side of the connection participates in tx relay with PEER.
Block-relay-only and feeler connections do not (Core: fRelay=false, no tx
inv/getdata either way). This is our half only; whether the PEER wants tx
announcements from us is PEER-TX-RELAY-P (their version's fRelay)."
  (not (member (peer-conn-type peer) '(:block-relay :feeler))))

(defun relay-enabled-p ()
  "Check if transaction relay is enabled for the current network: always on
test networks, disabled by default on mainnet for safety (a non-participation
posture stricter than Core's -blocksonly — it also gates block relay and
local-submission announcements; see flush-block-announcements /
relay-transaction).
Returns a strict boolean. The Core-parity incoming-tx switch is
IGNORE-INCOMING-TXS-P, which this feeds."
  (and (or (member bl:*network* '(:testnet3 :testnet4 :signet :regtest))
           bl:*mainnet-relay-enabled*)
       t))

(defun ignore-incoming-txs-p ()
  "Core PeerManager::Options::ignore_incoming_txs — T when this node refuses
transactions FROM the network: -blocksonly=1, or the network relay posture is
off (mainnet default). Drives the version message's fRelay=0, disconnection
of peers that announce or send txs anyway (Core RejectIncomingTxs), feefilter
suppression, high-bandwidth compact-block opt-out, and getnetworkinfo's
localrelay. It does NOT gate block relay or announcing locally-submitted
txs — a -blocksonly node still relays its OWN transactions (Core
BroadcastTransaction is unaffected by the flag)."
  (or bl:*blocksonly*
      (not (relay-enabled-p))))

(defun reject-incoming-txs-p (peer)
  "Core PeerManagerImpl::RejectIncomingTxs (net_processing.cpp:5686-5694): does
this node refuse transactions from PEER?

  - a block-relay-only or feeler connection may never send us txs, whatever its
    permissions;
  - otherwise, only the -blocksonly posture refuses, and the RELAY permission
    excuses that clause -- and only that clause.

ONE function because Core has one: the check is asked from two places -- the
fRelay bit of the VERSION we send (net_processing.cpp:1573) and the tx handler
that drops a peer for sending one anyway (:4475) -- and inlining it twice let
them drift. The handler had the permission carve-out; the VERSION did not, so
a node started with `-blocksonly -whitelist=relay@127.0.0.1' told that very
peer fRelay=0 and then accepted its transactions (p2p_blocksonly.py:57)."
  (or (not (peer-relays-txs-p peer))
      (and (ignore-incoming-txs-p)
           (not (peer-has-permission-p peer +perm-relay+)))))

(defun peer-tx-relay-p (peer)
  "T when tx-relay state exists for PEER — the exact condition under which
Core initializes Peer::TxRelay at VERSION time (net_processing.cpp:3681-3696):
the connection is not block-relay-only or feeler, AND the peer's version set
fRelay=1. We never advertise NODE_BLOOM, so Core's other arm (fRelay=0 but
NODE_BLOOM offered, letting a later filterload turn relay on) never applies:
a BIP37/BIP60 fRelay=0 peer gets NO tx invs and its tx getdata is ignored for
the life of the connection. A peer with no stored version yet counts as
relaying — Core's pre-70001 default is fRelay=true (net_processing.cpp:3597)."
  (and (peer-relays-txs-p peer)
       (let ((v (peer-version peer)))
         (or (null v)
             (bl.ser:version-message-relay v)))))

(defun peer-tx-relay-state-p (peer)
  "T when PEER has a Peer::TxRelay at all -- Core's `peer->GetTxRelay() !=
nullptr' (net_processing.cpp:1819). Core CREATES that object in the VERSION
handler (:3681-3696), so a peer that has not sent one has none, and
GetNodeStateStats then reports the no-object defaults rather than the peer's:
m_relay_txs false, m_fee_filter_received 0, m_inv_to_send 0 and the stats
struct's own m_last_inv_seq (:1825-1829).

PEER-TX-RELAY-P answers the other question -- WOULD we relay to this peer --
and deliberately treats a version-less peer as relaying, because Core's
pre-70001 fRelay default is true. Reading that one in getpeerinfo reported
relaytxes true and last_inv_sequence 1 for a peer that had said nothing
(rpc_net.py:148 expects false and 0)."
  (and (peer-version peer) (peer-tx-relay-p peer) t))

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
    (let ((digest (bl.crypto:tagged-hash "Tx Relay Salting" msg)))
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
        (peer-recon-registered peer) nil
        (peer-recon-set peer) nil
        (peer-recon-round peer) nil))

(defun %maybe-send-sendtxrcncl (peer)
  "Announce BIP330 reconciliation support, after the peer's VERSION and before
our VERACK (Core sends from its VERSION handler, net_processing.cpp:3728-3742),
when: -txreconciliation is enabled, the negotiated protocol supports wtxid
relay (>= 70016), our side of the connection relays txs (not block-relay/
feeler), and the peer's VERSION set fRelay=1. On send, pre-register a random
u64 local salt (txreconciliation.cpp:82-94 PreRegisterPeer). Always returns
T — declining to offer never fails the handshake."
  (let ((version-msg (peer-version peer)))
    (when (and bl:*tx-reconciliation*
               version-msg
               ;; Negotiated protocol = min(ours, theirs); ours is
               ;; +protocol-version+ = 70016 (WTXID_RELAY_VERSION), so the
               ;; gate reduces to theirs >= 70016.
               (>= (bl.ser:version-message-version version-msg)
                   bl.ser:+protocol-version+)
               (peer-relays-txs-p peer)
               ;; Core also skips the offer entirely in blocksonly mode
               ;; (!m_opts.ignore_incoming_txs, net_processing.cpp:3737) —
               ;; reconciliation is pointless when we reject incoming txs.
               (not (ignore-incoming-txs-p))
               (bl.ser:version-message-relay version-msg))
      ;; The salt travels in the sendtxrcncl message, so it comes off the OS
      ;; CSPRNG rather than the shared MT stream (Core's is a
      ;; FastRandomContext draw, net_processing.cpp).
      (let ((salt (bl.crypto:rand-u64)))
        (setf (peer-recon-local-salt peer) salt)
        (send-message peer
                      (bl.ser:make-sendtxrcncl-message salt)))))
  t)

(defun %log-sendtxrcncl-ignored (peer)
  "Core's line for a sendtxrcncl arriving with -txreconciliation off
(net_processing.cpp:3964-3967). p2p_sendtxrcncl.py:181 greps the debug log
for its tail, so the wording is behaviour, not decoration. Both ignore paths
-- inside the handshake window and after VERACK -- reach Core's single
`if (!m_txreconciliation)` early return, so both say this."
  (bl:log-cat "net" "sendtxrcncl from peer=~A ignored, as our node does not ~
have txreconciliation enabled"
              (peer-id peer)))

(defun %handle-handshake-sendtxrcncl (peer payload)
  "Process a pre-verack sendtxrcncl (Core net_processing.cpp:3963-4014 +
txreconciliation.cpp:97-126 RegisterPeer). Disconnects PEER and returns NIL
on a protocol violation; returns T otherwise (registered, or benignly
ignored)."
  (flet ((violation (reason)
           (bl:log-cat "net" "sendtxrcncl ~A, ~A" reason (disconnect-msg peer))
           (disconnect-peer peer)
           nil))
    (cond
      ;; Feature disabled: ignored entirely, with Core's log line
      ;; (net_processing.cpp:3964-3967).
      ((not bl:*tx-reconciliation*) (%log-sendtxrcncl-ignored peer) t)
      ;; Our VERSION indicated no tx relay on this connection (block-relay/
      ;; feeler) — Core's RejectIncomingTxs check (:3976-3980).
      ((not (peer-relays-txs-p peer))
       (violation "received to which we indicated no tx relay"))
      ;; The peer's own VERSION had fRelay=0 (:3982-3990).
      ((not (and (peer-version peer)
                 (bl.ser:version-message-relay
                  (peer-version peer))))
       (violation "received which indicated no tx relay to us"))
      (t
       (multiple-value-bind (their-version their-salt)
           (handler-case
               (bl.ser:parse-sendtxrcncl-payload payload)
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
                    bl.ser:+txreconciliation-version+)
               1)
            (violation "with unsupported version"))
           (t
            (multiple-value-bind (k0 k1)
                (compute-recon-salt (peer-recon-local-salt peer) their-salt)
              (setf (peer-recon-version peer)
                    (min their-version
                         bl.ser:+txreconciliation-version+)
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
  (let ((node bl:*node*))
    (logior bl.ser:+node-network-limited+
            bl.ser:+node-witness+
            (if (or (bl:pruning-enabled-p)
                    (and node (bl:node-historical-chainstate node)))
                0
                bl.ser:+node-network+)
            (if (v2-available-p)
                bl.ser:+node-p2p-v2+ 0)
            ;; BIP157: advertise filter serving when enabled.
            (if bl:*peer-block-filters*
                bl.ser:+node-compact-filters+ 0))))

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
             (bl.ser:v1-compatible-network-p net)
             (address-routable-p bytes net))
        (bl.ser:make-net-addr
         :services (peer-services peer)
         :ip bytes
         :port (let ((conn (peer-connection peer)))
                 (if conn (connection-port conn) 0)))
        (bl.ser:make-empty-net-addr
         :services (peer-services peer)))))

;;; --- Self-connection detection (Core CheckIncomingNonce) ---
;;;
;;; A node that dials its own advertised address completes the handshake
;;; against itself: the connection answers ping/pong forever, is never evicted,
;;; permanently burns an outbound slot and pollutes addrman and getpeerinfo.
;;; The only signal is the VERSION nonce — if a nonce we just sent comes back
;;; at us, the far end is us.

(defvar *outbound-nonce-lock* (bt:make-lock "outbound-nonces"))

(defvar *outbound-nonces* (make-hash-table :test 'eql)
  "Nonces of outbound connections whose handshake is still in flight, i.e.
whose VERACK has not been received. Core matches only against nodes with
!fSuccessfullyConnected (net.cpp:353-370); registering for exactly the
handshake window is the same test. Entries MUST be released on handshake
failure too, or the registry leaks and stays armed forever.")

(defun %fresh-local-nonce ()
  "A fresh 64-bit VERSION nonce for ONE connection.

Core gives every CNode its own nonce (net.cpp:515-516 outbound, :1824-1825
inbound) rather than reusing a node-wide value, and that matters beyond
tidiness: the nonce travels in cleartext in the first message of every
connection, so a stable one would be a permanent unique fingerprint linking
our clearnet, Tor and I2P identities and every reconnect. Core keeps the real
per-connection nonce even on privacy-hardened private-broadcast connections
where it blanks every other field (net_processing.cpp:1557-1564).

Uses the OS CSPRNG: SBCL's *random-state* is neither thread-safe nor
unpredictable, and handshakes run on several threads at once."
  (bl.crypto:rand-u64))

(defun %register-outbound-nonce (nonce)
  (bt:with-lock-held (*outbound-nonce-lock*)
    (setf (gethash nonce *outbound-nonces*) t)))

(defun %release-outbound-nonce (nonce)
  (bt:with-lock-held (*outbound-nonce-lock*)
    (remhash nonce *outbound-nonces*)))

(defun self-connection-nonce-p (nonce)
  "T when NONCE belongs to an outbound handshake of ours still in flight —
i.e. the peer that sent it is us (Core CheckIncomingNonce)."
  (bt:with-lock-held (*outbound-nonce-lock*)
    (and (gethash nonce *outbound-nonces*) t)))

(defun %detected-self-connection-p (peer)
  "T when the VERSION already stored on PEER carries one of our own in-flight
outbound nonces. Only meaningful on the INBOUND side: an inbound peer's nonce
is never registered, so this cannot false-positive on a normal peer unless it
guesses a 64-bit CSPRNG value."
  (let ((version (peer-version peer)))
    (and version
         (self-connection-nonce-p
          (bl.ser:version-message-nonce version)))))

(defun %greatest-common-version (peer)
  "Core's greatest_common_version = min(nVersion, PROTOCOL_VERSION)
(net_processing.cpp:3668), the number the post-VERSION capability messages are
gated on. A peer whose VERSION we have not read yet -- our OUTBOUND path sends
first -- counts as speaking our own version, which is what we assumed before
this gate existed."
  (let ((theirs (peer-version peer)))
    (if theirs
        (min (bl.ser:version-message-version theirs) bl.ser:+protocol-version+)
        bl.ser:+protocol-version+)))

(defun %send-post-version-capabilities (peer)
  "The post-VERSION capability messages, in Core's order and under Core's
gates (net_processing.cpp:3715-3726):

  wtxidrelay (BIP339) when greatest_common_version >= WTXID_RELAY_VERSION;
  sendaddrv2 (BIP155) when greatest_common_version >= 70016, which Core calls
  a courtesy -- \"some implementations reject messages they don't know\".

Both must come after VERSION and before VERACK. Ours sent sendaddrv2 to every
peer and gated wtxidrelay on whether OUR side relays transactions, which is
not a condition Core has at all: p2p_leak.py:123 opens a peer announcing
protocol 70015 and asserts at :154-155 that neither message arrives.

The gate bites on the INBOUND path, where the peer's VERSION is already in
hand. On the OUTBOUND path we still send these with our own VERSION, before
theirs arrives -- Core sends them from its VERSION handler in both directions
-- so %GREATEST-COMMON-VERSION reads our own version there and both messages
go out, as they always did. Returns T."
  (let ((common (%greatest-common-version peer)))
    (when (>= common bl.ser:+wtxid-relay-version+)
      (send-message peer (bl.ser:make-wtxidrelay-message)))
    (when (>= common 70016)
      (send-message peer (bl.ser:make-sendaddrv2-message))))
  t)

(defun %send-version-and-capabilities (peer)
  "Send our version message followed by the post-version capability messages
(wtxidrelay BIP339, sendaddrv2 BIP155 — both must come after VERSION and before
VERACK). Returns T if the version was sent."
  (let* ((services (local-services))
         ;; Advertise our real chain height (Core sends my_height) so peers can
         ;; pick us as a block-sync source; 0 only if the node isn't up yet.
         ;; The height is the CURRENT (active) chainstate's tip — never a
         ;; historical chainstate's.
         (node bl:*node*)
         (start-height (if node
                           (bl.store:current-height
                            (bl:node-current-chainstate node))
                           0))
         (version-payload (bl.ser:make-version-message-bytes
                           :services services
                           :addr-recv (%version-addr-recv peer)
                           :start-height start-height
                           :timestamp (bl.ser:get-unix-time)
                           ;; This connection's own nonce, so a peer that is
                           ;; really us can be recognised when it echoes back.
                           :nonce (peer-local-nonce peer)
                           ;; Core my_tx_relay = !RejectIncomingTxs(pnode)
                           ;; (net_processing.cpp:1573): false on
                           ;; block-relay/feeler connections AND in blocksonly
                           ;; mode (-blocksonly, or our mainnet relay-disabled
                           ;; default) unless this peer holds the RELAY
                           ;; permission. With fRelay=0 honest peers stop
                           ;; announcing txs to us.
                           :relay (not (reject-incoming-txs-p peer))))
         (version-msg (bl.ser:serialize-message
                       "version" version-payload)))
    (when (send-message peer version-msg)
      (%send-post-version-capabilities peer))))

(defconstant +min-peer-proto-version+ 31800
  "Core MIN_PEER_PROTO_VERSION (protocol_version.h:18): a peer announcing an
older protocol is disconnected at VERSION (net_processing.cpp:3623-3627).")

(defun desirable-service-flags (services near-tip)
  "Core GetDesirableServiceFlags (net_processing.cpp:1759-1768): the services
an automatic outbound peer must offer — NODE_NETWORK|NODE_WITNESS, or
NODE_NETWORK_LIMITED|NODE_WITNESS from a limited peer once we are NEAR-TIP
(Core: best-block depth under NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS)."
  (if (and near-tip
           (logtest services bl.ser:+node-network-limited+))
      (logior bl.ser:+node-network-limited+
              bl.ser:+node-witness+)
      (logior bl.ser:+node-network+
              bl.ser:+node-witness+)))

(defun has-all-desirable-service-flags-p (services near-tip)
  "Core HasAllDesirableServiceFlags (net_processing.cpp:1753-1756)."
  (zerop (logandc2 (desirable-service-flags services near-tip) services)))

(defun %receive-and-store-version (peer &key (timeout 30) near-tip)
  "Receive the peer's version message and record its services/height/user-agent.
Returns T on success, NIL if the first message wasn't a version — or if Core
would disconnect on it: an automatic outbound peer lacking the desirable
services (net_processing.cpp:3611-3619), or any peer announcing a protocol
older than +min-peer-proto-version+ (:3623-3627). NEAR-TIP widens the
desirable set to limited peers, as in Core."
  (multiple-value-bind (command payload)
      (receive-message-blocking peer :timeout timeout)
    (when (and command (string= command "version"))
      (bl.bytes:with-byte-reader (stream payload)
        (let* ((version-msg (bl.ser:read-version-message stream))
               (services (bl.ser:version-message-services version-msg))
               (proto (bl.ser:version-message-version version-msg)))
          (setf (peer-version peer) version-msg
                (peer-services peer) services
                (peer-start-height peer)
                (bl.ser:version-message-start-height version-msg)
                ;; Core stores SanitizeString(strSubVer) as cleanSubVer and
                ;; keeps the raw string nowhere (net_processing.cpp:3641), so
                ;; the log line, getpeerinfo's "subver" and every other reader
                ;; get the filtered form with no further work. The filter is
                ;; what stops log-line forgery: %log-escape-message passes a
                ;; newline through, exactly as Core's LogEscapeMessage does,
                ;; because Core has already dropped it here.
                (peer-user-agent peer)
                (bl.bytes:sanitize-string
                 (bl.ser:version-message-user-agent version-msg))
                ;; Their clock vs ours, captured at receipt (Core Peer::
                ;; m_time_offset, net_processing.cpp:3646); getpeerinfo
                ;; "timeoffset".
                (peer-time-offset peer)
                (- (bl.ser:version-message-timestamp version-msg)
                   (bl.ser:get-unix-time)))
          ;; Core's two VERSION-time disconnects (net_processing.cpp:3611-3627).
          ;; The services gate is guarded by CNode::ExpectServicesFromConn
          ;; (net_processing.cpp:3613), which exempts inbound, manual and
          ;; feeler connections and covers ADDR-FETCH along with the two
          ;; automatic outbound types.
          (cond ((and (peer-expects-services-p peer)
                      (not (has-all-desirable-service-flags-p services near-tip)))
                 (bl:log-cat "net"
                             "peer does not offer the expected services ~
                              (~8,'0x offered, ~8,'0x expected), ~A"
                             services
                             (desirable-service-flags services near-tip)
                             (disconnect-msg peer))
                 nil)
                ((< proto +min-peer-proto-version+)
                 (bl:log-cat "net" "peer using obsolete version ~D, ~A"
                             proto (disconnect-msg peer))
                 nil)
                (t t)))))))

(defun %await-verack (peer &key (timeout 30))
  "Read messages until VERACK arrives (tolerating interleaved wtxidrelay/
sendaddrv2/sendheaders/sendtxrcncl), tracking the peer's advertised
capabilities. Sets the peer :ready and returns T on VERACK; NIL otherwise
(including a sendtxrcncl protocol violation, which disconnects).

TIMEOUT is an ABSOLUTE budget for the whole wait, not per read. It used to be
per read inside `loop repeat 10', so the real budget was 10x TIMEOUT and the
loop exited early only when the peer went SILENT. A peer sending any complete
non-verack message — a 32-byte ping is enough, since no clause below matches it
— once every timeout-minus-epsilon renewed the deadline indefinitely up to the
repeat count, holding the single accept thread for minutes on a few hundred
bytes. accept-connection does not run in that window, so the listen backlog
fills and the node stops taking inbound peers at all.

Core never has this exposure: CreateNodeFromAcceptedSocket does no blocking
read whatsoever (net.cpp:1761-1869) — VERSION and VERACK are ordinary
asynchronous messages. Moving our handshake off the accept thread is the
structural fix; this bounds the damage in the meantime."
  (let* ((units internal-time-units-per-second)
         (deadline (+ (get-internal-real-time) (round (* timeout units)))))
    (flet ((remaining ()
             (/ (max 0 (- deadline (get-internal-real-time))) units)))
      (loop repeat 10
        do (when (<= (remaining) 0) (return nil))
           (multiple-value-bind (command payload)
               (receive-message-blocking peer :timeout (remaining))
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
        finally (return nil)))))

(defun %v2-try-outbound (peer)
  "Attempt the BIP324 v2 handshake on PEER's fresh outbound connection.
On :FALLBACK-V1 (the peer never answered our key -- almost certainly a v1
node), reconnect to the same host/port and continue in v1. Returns T when the
version handshake may proceed (over whichever transport), NIL to give up."
  (let* ((conn (peer-connection peer))
         (result (v2-handshake-outbound conn :peer-id (peer-id peer))))
    (cond
      ((v2-transport-p result)
       (setf (connection-transport conn) result)
       (bl:log-info "v2 transport established (outbound), ~A"
                    (peer-log-name peer))
       t)
      ((eq result :fallback-v1)
       (let ((fresh (make-tcp-connection (connection-host conn)
                                         (connection-port conn))))
         (when fresh
           (close-connection conn)
           (setf (peer-connection peer) fresh)
           ;; Core's own line for this reconnection (net.cpp:1951). Ours read
           ;; "no v2 response, reconnected as v1", which says the same thing to
           ;; a person and nothing to p2p_v2_transport.py:46, which names this
           ;; exact text as the message that must NOT appear while two v2 nodes
           ;; connect -- so that half of the assertion could never fail.
           (bl:log-cat "net" "retrying with v1 transport protocol for peer=~D"
                       (peer-id peer))
           t))))))

(defun perform-handshake (peer &key (try-v2 (v2-available-p))
                                    (conn-type :outbound-full-relay)
                                    near-tip)
  "Outbound version handshake (we initiate): send version+caps, receive the
peer's version, send verack, await theirs. CONN-TYPE sets the peer's connection
type (:outbound-full-relay, :block-relay, :feeler, :addr-fetch or :manual)
before the version is sent, so a block-relay/feeler peer advertises relay=0 and
skips wtxidrelay.
When TRY-V2 (default: whenever the v2 transport is enabled and supported), the
BIP324 encrypted transport is established first, reconnecting as v1 if the peer
turns out not to speak it. Returns T on success."
  (setf (peer-state peer) :handshaking
        (peer-conn-type peer) conn-type
        (peer-local-nonce peer) (%fresh-local-nonce))
  ;; Arm self-connection detection for exactly the handshake window (Core
  ;; matches only against !fSuccessfullyConnected nodes). unwind-protect so a
  ;; FAILED handshake releases the nonce too — otherwise the registry leaks
  ;; and stays armed against an unrelated future peer forever.
  (%register-outbound-nonce (peer-local-nonce peer))
  (unwind-protect
       (and (or (not try-v2)
                (%v2-try-outbound peer))
            (%send-version-and-capabilities peer)
            (%receive-and-store-version peer :near-tip near-tip)
            ;; BIP330 offer goes after their VERSION (it is gated on their fRelay)
            ;; and before our VERACK (Core net_processing.cpp:3728-3744).
            (%maybe-send-sendtxrcncl peer)
            (send-message peer (bl.ser:make-verack-message))
            (%await-verack peer))
    (%release-outbound-nonce (peer-local-nonce peer))))

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
    (let ((detected (v2-detect-inbound (peer-connection peer)
                                       :timeout timeout
                                       :peer-id (peer-id peer))))
      (cond ((v2-transport-p detected)
             (setf (connection-transport (peer-connection peer)) detected)
             (bl:log-cat "net" "v2 transport established (inbound), ~A"
                         (peer-log-name peer)))
            ((eq detected :v1))         ; sniffed bytes pushed back; proceed v1
            (t (return-from perform-inbound-handshake nil)))))
  (setf (peer-local-nonce peer) (%fresh-local-nonce))
  (and (%receive-and-store-version peer :timeout timeout)
       ;; SELF-CONNECTION: their VERSION carries a nonce we are still using for
       ;; an outbound handshake, so the far end is us. Refuse BEFORE replying
       ;; and before any local-address/addrman bookkeeping — Core's check at
       ;; net_processing.cpp:3649 precedes both SeenLocal (:3658) and
       ;; PushNodeVersion (:3664). The disconnect is SILENT: no ban, no
       ;; discouragement, no misbehaviour score. Scoring it would be actively
       ;; harmful, since the address being punished is our own.
       ;;
       ;; This is one of the two places Core prints an address with no -logips
       ;; gate: LogInfo("connected to self at %s, disconnecting",
       ;; net_processing.cpp:3651), like net.cpp:388 and :1787. Exceptional
       ;; paths, and the address here is OURS. Matched, not special-cased.
       (cond ((%detected-self-connection-p peer)
              (bl:log-info "Peer ~A: connected to self, disconnecting"
                                     (peer-address peer))
              nil)
             (t
              (and (%send-version-and-capabilities peer)
                   ;; BIP330 offer: their VERSION is already in hand on the
                   ;; inbound path; ordering matches Core (wtxidrelay →
                   ;; sendaddrv2 → sendtxrcncl → verack,
                   ;; net_processing.cpp:3715-3744).
                   (%maybe-send-sendtxrcncl peer)
                   (send-message peer (bl.ser:make-verack-message))
                   (%await-verack peer :timeout timeout))))))

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
    ;; Core's inbound branch has no address in the line (net.cpp:4009).
    (bl:log-cat "net" "Added connection peer=~D" (peer-id peer))
    peer))

;;; --- BIP133 feefilter (Core MaybeSendFeefilter + FeeFilterRounder) ---
;;;
;;; We used to send ONE hardcoded 1000 sat/kvB filter at handshake and never
;;; revisit it, while our actual floor defaults to 100 and rises dynamically.
;;; BIP133-honouring peers therefore withheld the whole 0.1-1.0 sat/vB band we
;;; would happily have accepted — degrading mempool completeness, fee
;;; estimation and compact-block reconstruction — while during IBD they kept
;;; flooding us with txs we discard, and when the pool filled they kept
;;; streaming txs already doomed by the rolling minimum.

(defconstant +feefilter-version+ 70013
  "Minimum common protocol version for feefilter (Core FEEFILTER_VERSION).")

(defconstant +avg-feefilter-broadcast-interval+ 600
  "Mean seconds between feefilter refreshes (Core's 10min, drawn from an
exponential so refreshes do not align across peers).")

(defconstant +max-feefilter-change-delay+ 300
  "Cap on how long a SUBSTANTIALLY changed filter waits (Core's 5min).")

(defparameter *fee-filter-buckets*
  (let ((set (list 0))
        ;; max(1, DEFAULT_MIN_RELAY_TX_FEE/2) where Core's compile-time
        ;; DEFAULT_MIN_RELAY_TX_FEE is 100 — NOT the configured
        ;; -minrelaytxfee. Configuring the relay floor must not move the
        ;; buckets, or our quantization would become a fingerprint.
        (boundary 50.0d0))
    (loop while (<= boundary 1d7)
          do (push boundary set)
             (setf boundary (* boundary 1.1d0)))
    (coerce (sort set #'<) 'vector))
  "Ascending bucket boundaries {0} U {50 * 1.1^k <= 1e7} (Core MakeFeeSet).
Built by repeated multiplication, like Core, so the values match bit for bit
rather than being recomputed as 50*1.1^k.")

(defun %exponential-interval (mean-seconds)
  "Seconds until the next event of a Poisson process with MEAN-SECONDS (Core
rand_exp_duration). Returns SECONDS, matching the unix-time clock the
feefilter timers use — protocol.lisp's %next-exp-interval-ticks returns
internal-real-time TICKS and must not be mixed with them."
  (max 1 (round (* mean-seconds (- (log (- 1.0d0 (random 1.0d0))))))))

(defun fee-filter-round (fee)
  "Quantize FEE (sat/kvB) to a bucket, Core FeeFilterRounder::round.

Takes the ceiling bucket 1/3 of the time and the one below it 2/3 of the time.
The draw is PER CALL, not a per-session skew: modelling it as a session
constant would make our successive broadcasts correlated in a way Core's are
not, which is itself a fingerprint. A fee above the top bucket clamps to the
top bucket — which is why Core's IBD sentinel goes on the wire as the top
bucket and never as MAX_MONEY."
  (let* ((buckets *fee-filter-buckets*)
         (n (length buckets))
         (idx (or (position-if (lambda (b) (>= b fee)) buckets) n)))
    ;; Core: --it when past the end, or when not at the beginning and the
    ;; 1-in-3 draw does not land.
    (when (or (= idx n)
              (and (> idx 0) (/= 0 (random 3))))
      (decf idx))
    (values (floor (aref buckets (max 0 idx))))))

(defun %feefilter-max-value ()
  "What Core puts on the wire during IBD: round(MAX_MONEY), which clamps to the
top bucket (net_processing.cpp:5645). Deterministic — the clamp branch never
consults the RNG."
  (values (floor (aref *fee-filter-buckets* (1- (length *fee-filter-buckets*))))))

(defun maybe-send-feefilter (peer mempool chain-state now)
  "Core MaybeSendFeefilter (net_processing.cpp:5628-5669), driven from the
periodic tick rather than once at handshake."
  (when (and mempool
             (not (ignore-incoming-txs-p))
             ;; Core gates on the COMMON version; we never negotiate below our
             ;; own, so the peer's advertised version is the common one.
             (let ((v (peer-version peer)))
               (and v (>= (bl.ser:version-message-version v)
                          +feefilter-version+)))
             (not (eq (peer-conn-type peer) :block-relay)))
    (let ((current (if (initial-block-download-p chain-state)
                       ;; Tx invs are discarded during IBD, so ask for none.
                       most-positive-fixnum
                       (bl.mp:mempool-decayed-rolling-min-fee-rate
                        mempool now))))
      ;; Leaving IBD must force a resend, or peers keep withholding txs for up
      ;; to another 10 minutes.
      (unless (initial-block-download-p chain-state)
        (when (eql (peer-fee-filter-sent peer) (%feefilter-max-value))
          (setf (peer-next-send-feefilter peer) 0)))
      (cond
        ((> now (peer-next-send-feefilter peer))
         (let ((to-send (max (fee-filter-round current)
                             (bl.mp:mempool-min-fee-rate mempool))))
           (unless (eql to-send (peer-fee-filter-sent peer))
             (send-message peer (bl.ser:make-feefilter-message to-send))
             (setf (peer-fee-filter-sent peer) to-send))
           ;; Advanced UNCONDITIONALLY, even when nothing was sent — otherwise
           ;; the tick re-evaluates every second forever.
           (setf (peer-next-send-feefilter peer)
                 (+ now (%exponential-interval +avg-feefilter-broadcast-interval+)))))
        ;; Substantially changed and the scheduled broadcast is far off: pull it
        ;; forward. This branch only RESCHEDULES; it never sends.
        ((and (peer-fee-filter-sent peer)
              (< (+ now +max-feefilter-change-delay+) (peer-next-send-feefilter peer))
              (or (< current (floor (* 3 (peer-fee-filter-sent peer)) 4))
                  (> current (floor (* 4 (peer-fee-filter-sent peer)) 3))))
         (setf (peer-next-send-feefilter peer)
               (+ now (random (1+ +max-feefilter-change-delay+)))))))))

(defun send-post-handshake-messages (peer)
  "Send feature negotiation messages after handshake completes."
  ;; BIP 130: Request header announcements
  (send-message peer (bl.ser:make-sendheaders-message))
  ;; BIP133 feefilter is NOT sent here. It is driven entirely by
  ;; maybe-send-feefilter on the periodic tick, which sends the first filter
  ;; within a second of the handshake. Sending from the handshake site as well
  ;; would run the IBD check and the RNG on the inbound-listener thread, and
  ;; would emit a filter for a connection that may still fail — for the sake of
  ;; under a second of latency.
  ;; Address relay is set up for every outbound connection except
  ;; block-relay-only ones (Core SetupAddressRelay from the VERSION handler,
  ;; net_processing.cpp:3754+5697-5711); inbound peers enable it on their
  ;; first addr-related message instead (see handle-getaddr/handle-addr).
  (when (and (not (peer-inbound peer))
             (not (eq (peer-conn-type peer) :block-relay)))
    (setf (peer-addr-relay-enabled peer) t))
  ;; One-time address fetch to populate/update addrman. Core sends GETADDR
  ;; on outbound connections only, and never block-relay-only ones (no addr
  ;; relay there, to avoid leaking the link): net_processing.cpp:3754-3772
  ;; + SetupAddressRelay. Without this, addrman fills only from unsolicited
  ;; gossip, DNS seeds, and fixed seeds.
  (when (and (not (peer-inbound peer))
             (not (eq (peer-conn-type peer) :block-relay)))
    (send-message peer (bl.ser:make-getaddr-message))
    ;; Track the solicitation and accept a full MAX_ADDR_TO_SEND response
    ;; beyond the token bucket's cap (Core net_processing.cpp:3769-3772:
    ;; "When requesting a getaddr, accept an additional MAX_ADDR_TO_SEND
    ;; addresses in response (bypassing the MAX_ADDR_PROCESSING_TOKEN_BUCKET
    ;; limit)").
    (setf (peer-getaddr-requested peer) t)
    (incf (peer-addr-token-bucket peer)
          (coerce bl.ser:+max-addr-count+ 'double-float))))

;;; Ping/Pong

(defun send-ping (peer)
  "Send a ping message to the peer.

The nonce is published, so BL.SER:MAKE-PING-MESSAGE's OS-CSPRNG default is
what draws it -- named here because the pong has to match it."
  (let ((nonce (bl.crypto:rand-u64)))
    (setf (peer-ping-nonce peer) nonce)
    (setf (peer-last-ping-time peer) (get-internal-real-time))
    (send-message peer (bl.ser:make-ping-message nonce))))

(defun reply-to-ping (peer nonce)
  "Answer a ping carrying NONCE with the pong; HANDLE-PING parses the wire."
  (send-message peer (bl.ser:make-pong-message nonce)))

(defun record-pong (peer nonce)
  "Record the round trip a pong carrying NONCE closes; HANDLE-PONG parses the wire."
  (when (and (peer-ping-nonce peer)
             (= nonce (peer-ping-nonce peer)))
    (let ((rtt (- (get-internal-real-time) (peer-last-ping-time peer))))
      (setf (peer-ping-latency peer) rtt)
      ;; Track the connection's best round trip (Core m_min_ping_time).
      (when (or (zerop (peer-min-ping-latency peer))
                (< rtt (peer-min-ping-latency peer)))
        (setf (peer-min-ping-latency peer) rtt)))
    (setf (peer-ping-nonce peer) nil)))

;;; Peer Health Monitoring

(defconstant +ping-interval-seconds+ 120
  "Core PING_INTERVAL (net_processing.cpp:122): a keepalive/latency ping is
sent once no ping is outstanding and this long has passed.")
(defconstant +ping-timeout-seconds+ +timeout-interval-seconds+
  "Core TIMEOUT_INTERVAL (net.h:59): a ping left unanswered this long
disconnects the peer (MaybeSendPing, net_processing.cpp:5487-5494) -- behind
SHOULD-RUN-INACTIVITY-CHECKS-P, like every other liveness verdict.")

(defun should-run-inactivity-checks-p (peer &optional (now (get-internal-real-time)))
  "T once PEER has been connected for longer than -peertimeout: Core's
CConnman::ShouldRunInactivityChecks, `node.m_connected + m_peer_connect_timeout
< now` (net.cpp:2003-2006).

In Core this is the master gate for EVERY liveness disconnect, not one timeout
among several: it guards all four rules of InactivityCheck (net.cpp:2008-2058)
and, less obviously, MaybeSendPing's ping timeout, whose own comment says \"To
disable the check during testing, increase -peertimeout\"
(net_processing.cpp:5488-5497). That is what makes -peertimeout the knob that
silences liveness disconnects wholesale -- Core's functional framework writes
peertimeout=999999999 into every node's bitcoin.conf so that mocktime jumps do
not disconnect peers (test/functional/test_framework/util.py:570-574). Ours
disconnected on an outstanding ping at 1200 s under exactly that setting,
because the ping timeout was not gated by the knob.

A peer whose CONNECT-TIME was never stamped is exempt, the same reading
CHECK-HANDSHAKE-TIMEOUT has always given a 0."
  (let ((connected-at (peer-connect-time peer)))
    (and (not (zerop connected-at))
         (< (+ connected-at (* bl:*handshake-timeout-seconds*
                               internal-time-units-per-second))
            now))))

(defun inactivity-check-reason (conn &optional (unix-now (bl.ser:get-node-time)))
  "Why CONN fails Core's CConnman::InactivityCheck (net.cpp:2008-2052), worded
as Core words the line, or NIL when it passes. The caller applies
SHOULD-RUN-INACTIVITY-CHECKS-P first, as Core's InactivityCheck does on its own
first line; that gate is the only part of the check that is about the PEER
rather than about its socket, which is why it is not asked here.

Core's three timing rules, in Core's order: nothing ever sent or received,
nothing SENT for TIMEOUT_INTERVAL, nothing RECEIVED for TIMEOUT_INTERVAL. They
read the connection's LAST-SEND-TIME / LAST-RECV-TIME -- the times themselves,
as Core's m_last_send / m_last_recv are, both already maintained on every
accepted write and completed read -- and not the send queue.
CONNECTION-SEND-STALLED-P remains the separate, tighter backpressure signal it
is: it additionally requires data pending, so it is not this rule and cannot
stand in for it. Core's fourth rule, the unfinished handshake, is peer state
and lives in CHECK-HANDSHAKE-TIMEOUT.

The receive rule is suspended for a RECEIVE-PAUSED peer, which is the one
pause that stops our reads (CONNECTION-RECV-PAUSED-P: an over-cap backlog of
messages read but not dispatched, Core fPauseRecv). LAST-RECV-TIME would then
go stale for our own reason and this rule would disconnect a healthy peer for
a pause we imposed on it.

A SEND-paused peer is NOT exempt, and used to be: while the pause also stopped
the socket read the exemption was forced, but the read now continues through a
send pause exactly as Core's socket handler does (DRAIN-AND-REAP-PEER), so
m_last_recv advances there as it does in Core and the rule applies unchanged.
A peer that never drains is still bounded -- CONNECTION-SEND-STALLED-P fires on
the same window."
  (let ((last-send (connection-last-send-time conn))
        (last-recv (connection-last-recv-time conn)))
    (cond
      ((or (zerop last-recv) (zerop last-send))
       (format nil "socket no message in first ~D seconds~@[~A~]~@[~A~]"
               bl:*handshake-timeout-seconds*
               (and (zerop last-recv) ", never received from peer")
               (and (zerop last-send) ", never sent to peer")))
      ((> unix-now (+ last-send +timeout-interval-seconds+))
       (format nil "socket sending timeout: ~Ds" (- unix-now last-send)))
      ((and (> unix-now (+ last-recv +timeout-interval-seconds+))
            (not (connection-recv-paused-p conn)))
       (format nil "socket receive timeout: ~Ds" (- unix-now last-recv))))))

(defun check-handshake-timeout (peer)
  "Check if a peer has exceeded the handshake timeout -- Core InactivityCheck's
last rule, `if (!node.fSuccessfullyConnected)` behind ShouldRunInactivityChecks
(net.cpp:2003-2006, 2053-2058). Returns :disconnect if the peer should be
disconnected, :ok otherwise.

The gate IS the rule here: Core's own condition is that the connection has
outlived -peertimeout without finishing its handshake, so this asks
SHOULD-RUN-INACTIVITY-CHECKS-P rather than recomputing the same arithmetic."
  (if (and (member (peer-state peer) '(:connected :connecting :handshaking))
           (should-run-inactivity-checks-p peer))
      (progn
        (bl:log-cat "net" "version handshake timeout: ~,1Fs elapsed, ~A"
                    (/ (float (- (get-internal-real-time) (peer-connect-time peer)))
                       (float internal-time-units-per-second))
                    (disconnect-msg peer))
        :disconnect)
      :ok))

(defun maybe-send-ping (peer &optional (now (get-internal-real-time)))
  "Core PeerManagerImpl::MaybeSendPing (net_processing.cpp:5487-5510). Returns
:disconnect, :ping-sent or :ok.

While a ping is outstanding nothing new is sent, and the peer is disconnected
once it has gone unanswered for +PING-TIMEOUT-SECONDS+ -- but only once the
-peertimeout gate is open, which is what Core puts on the first line of this
function. SENDING a ping is NOT gated: Core's pingSend arms below the gate, so
a node started with a huge -peertimeout still pings and still measures latency,
it just never disconnects for the answer.

Both clocks are the send time of the last ping, so an outstanding ping is never
overwritten and its age never reset."
  (let* ((last (peer-last-ping-time peer))
         (age (and last (- now last))))
    (cond
      ((peer-ping-nonce peer)
       (cond
         ((and (> age (* +ping-timeout-seconds+ internal-time-units-per-second))
               (should-run-inactivity-checks-p peer now))
          (bl:log-cat "net" "ping timeout: ~,1Fs, disconnecting peer=~A"
                      (/ (float age) (float internal-time-units-per-second))
                      (peer-id peer))
          :disconnect)
         (t :ok)))
      ;; Never pinged: due NOW, as Core's is.
      ;;
      ;; This was `(- (get-internal-real-time) 0)` against a 0 initform, and
      ;; the two clocks do not mean the same thing. Core's m_ping_start is 0 on
      ;; an ABSOLUTE clock, so the interval has always already elapsed. Ours was
      ;; 0 on INTERNAL-REAL-TIME, whose zero is roughly process start — so on a
      ;; freshly started node the first ping to any peer waited out the full
      ;; two-minute interval measured from BOOT, not from the connection.
      ;;
      ;; Nothing about it looks wrong in a long-lived node, which is where it
      ;; was never noticed: after two minutes of uptime every new peer is
      ;; pinged at once. It shows up only in the first two minutes, which is
      ;; exactly the window Core's functional framework runs in — connect_nodes
      ;; waits 60s for a pong before it will hand a test its network
      ;; (test_framework.py:596), so this alone failed every multi-node test.
      ((null last)
       (send-ping peer)
       :ping-sent)
      ((> age (* +ping-interval-seconds+ internal-time-units-per-second))
       (send-ping peer)
       :ping-sent)
      (t :ok))))

(defun check-peer-health (peer)
  "Check health of a single peer. Returns :ok, :ping-sent, or :disconnect.

Every DISCONNECT verdict below is behind SHOULD-RUN-INACTIVITY-CHECKS-P, Core's
one gate in front of every liveness rule; what is not gated is the upkeep that
is not a verdict -- flushing the send buffer, and sending the ping itself.
Inside the gate the rules are Core's: the send-buffer backpressure signal, then
InactivityCheck's timing rules (INACTIVITY-CHECK-REASON), then the unfinished
handshake (CHECK-HANDSHAKE-TIMEOUT, which is InactivityCheck's fourth rule),
then MaybeSendPing (MAYBE-SEND-PING)."
  (let ((conn (peer-connection peer))
        (now (get-internal-real-time)))
    (when (and conn (connection-connected conn))
      ;; Upkeep, not a verdict, so it runs whether or not the gate is open:
      ;; retry buffered unsent bytes, non-blocking (Core's periodic
      ;; SocketSendData).
      (flush-send-buffer conn)
      (when (should-run-inactivity-checks-p peer now)
        ;; Buffered data the socket has accepted nothing of for the stall
        ;; window (Core InactivityCheck "socket sending timeout", narrowed by
        ;; the pending-data test to the backpressure case).
        (when (connection-send-stalled-p conn)
          (bl:log-cat "net" "socket sending timeout: ~D unsent bytes, ~A"
                      (connection-send-queue-bytes conn)
                      (disconnect-msg peer))
          (return-from check-peer-health :disconnect))
        (let ((reason (inactivity-check-reason conn)))
          (when reason
            (bl:log-cat "net" "~A, disconnecting peer=~A" reason (peer-id peer))
            (return-from check-peer-health :disconnect)))))
    ;; A peer that has not finished its handshake is not yet pingable; the
    ;; handshake rule is behind the same gate, inside CHECK-HANDSHAKE-TIMEOUT.
    (unless (eq (peer-state peer) :ready)
      (return-from check-peer-health (check-handshake-timeout peer)))
    (maybe-send-ping peer now)))

(defun record-block-received-from-peer (peer)
  "Record that we received a block from PEER. Resets stalling state and
stamps the unix receipt time getpeerinfo reports as \"last_block\" (Core
CNode::m_last_block_time; Core stamps only NEW blocks in ProcessBlock —
ours stamps every block message, but we request each block once, so
duplicates are rare)."
  (setf (peer-last-block-received-time peer) (get-internal-real-time))
  (setf (peer-last-block-time peer) (bl.ser:get-unix-time)))

;;; Misbehavior, Discouragement, and Banning
;;;
;;; Two distinct mechanisms, mirroring Bitcoin Core's BanMan:
;;;  - Discouragement (automatic): a peer that misbehaves is added to a bounded,
;;;    ephemeral rolling filter. We never dial it, prefer it for inbound
;;;    eviction, and don't gossip it — but it is not hard-banned (which
;;;    previously let a peer grow our banned map without bound). Bitcoin Core's
;;;    misbehavior model is BINARY (PRs bitcoin/bitcoin#25325 / bitcoin/bitcoin#26294): a single protocol
;;;    violation marks the peer for discouragement — there is no accumulating
;;;    ban score, and loose (non-block) transaction-validation failures do not
;;;    count as misbehavior at all.
;;;  - Banning (manual): ban-address / *banned-peers*, an explicit ADDRESS ban
;;;    with an expiry. Core's BanMan::Ban is reached from the setban RPC alone
;;;    (rpc/net.cpp:799-808 via node/interfaces.cpp:233); misbehaviour never
;;;    bans, so there is no per-peer ban entry point here either.

(defconstant +ban-duration-seconds+ (* 24 60 60)
  "Default ban duration: 24 hours (Bitcoin Core DEFAULT_MISBEHAVING_BANTIME,
banman.h:19).")

(defvar *default-ban-time-seconds* +ban-duration-seconds+
  "Effective default ban duration in seconds, applied when setban/ban-address
gets no explicit time (Core -bantime, banman.cpp:130-140: a non-positive
ban_time_offset falls back to m_default_ban_time). Set from config at startup.")

(defstruct (ban-entry (:constructor %make-ban-entry (created until subnet)))
  "One manual ban: Core's CBanEntry (nCreateTime / nBanUntil, banman.h:20-40)
plus the CSubNet it is keyed by.

CREATED and UNTIL are universal times. SUBNET is the parsed range, or NIL for
an address on a network Core compares by equality rather than by mask (onion,
I2P) -- there the key string IS the match."
  (created 0 :type integer)
  (until 0 :type integer)
  (subnet nil))

(defvar *banned-peers* (make-hash-table :test 'equal)
  "Core's BanMan::m_banned (banman.h:60): canonical subnet string -> BAN-ENTRY.

The KEY is Core's CSubNet::ToString of the banned range, so `127.0.0.1' and
`127.0.0.1/32' are one entry and `127.0.0.0/24' is a different one -- which is
what makes Unban an exact erase (banman.cpp:144-152) while IsBanned(CNetAddr)
walks every range (:89-102).")

(defvar *banlist-path* nil
  "Pathname of the banlist.json persistence file (Core BanMan's
<datadir>/banlist.json), or NIL when persistence is off (no node running).
Set at node startup; every manual-ban mutation dumps the file immediately,
exactly like Core (banman.cpp:153,170,79 — Ban/Unban/ClearBanned each call
DumpBanlist).")

(defvar *discouraged-peers* (bl:make-rejects-filter)
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
      (bl:add-recent-reject *discouraged-peers* address))))

(defun peer-discouraged-p (address)
  "T if ADDRESS is currently discouraged."
  (and address (plusp (length address))
       (bt:with-lock-held (*ban-lock*)
         (bl:recent-reject-p *discouraged-peers* address))
       t))

(defun clear-discouraged ()
  "Clear the discourage filter."
  (bt:with-lock-held (*ban-lock*)
    (bl:clear-recent-rejects *discouraged-peers*)))

(defun loopback-address-p (address)
  "T when ADDRESS is a loopback address — Core CNetAddr::IsLocal
(netaddress.cpp:398-410): IPv4 127.0.0.0/8 or 0.0.0.0/8, or IPv6 ::1.

NOT named local-address-p: that symbol is already the struct predicate of the
LOCAL-ADDRESS defstruct in netaddress.lisp, which loads AFTER this file and so
silently clobbered a function of that name. The warm image happened to keep
mine and the cold build took the struct predicate, which answers NIL for every
string -- so the carve-out below quietly did nothing in exactly the build that
matters.

Used to decide whether misbehaviour may be DISCOURAGED, which is an
address-level verdict. Every inbound onion peer reaches us through the local
Tor daemon, so they all present as 127.0.0.1: discouraging that address bans
the loopback itself and takes every onion peer with it."
  (and (stringp address)
       (or (string= address "::1")
           (let ((dot (position #\. address)))
             (and dot
                  (let ((first-octet (ignore-errors
                                      (parse-integer address :end dot))))
                    (and first-octet (or (= first-octet 127) (= first-octet 0)))))))))

(defun peer-permissions (peer)
  "Core CNode::m_permission_flags for PEER, derived rather than stored — see
the divergence note in netaddress.lisp, and PEER-PERMISSION-FLAGS for what an
inbound onion peer's address is worth.

An inbound peer's flags come from -whitebind and the INCOMING ranges
(net.cpp:1755-1772). An outbound connection starts from
NetPermissionFlags::None and consults the OUTGOING ranges only when it is
MANUAL (net.cpp:510-512):

    std::vector<NetWhitelistPermissions> whitelist_permissions =
        conn_type == ConnectionType::MANUAL ? vWhitelistedRangeOutgoing
                                            : std::vector<NetWhitelistPermissions>{};

so an automatic outbound peer inside a `noban,out@' range holds nothing. We
applied the ,out ranges to every outbound peer, which handed an addrman-chosen
peer that happened to fall inside the operator's range the operator's own
trusted-peer exemptions."
  (cond ((peer-inbound peer)
         (peer-permission-flags (peer-address peer) t (peer-inbound-onion peer)))
        ((peer-manual-p peer)
         (peer-permission-flags (peer-address peer) nil))
        (t 0)))

(defun peer-has-permission-p (peer flag)
  "T when PEER holds FLAG (Core CNode::HasPermission over PEER-PERMISSIONS)."
  (permission-flag-set-p (peer-permissions peer) flag))

(defun record-misbehavior (peer &optional reason)
  "Discourage and disconnect PEER for a protocol violation. Bitcoin Core's
misbehavior model is binary (Misbehaving -> m_should_discourage): any single
call marks the peer for discouragement — there is no accumulating score. The
address is added to the ephemeral discourage filter (never dialed, preferred
for eviction, not gossiped) and the connection is dropped. REASON, if given, is
logged. Returns T, or NIL when PEER was left alone -- because it holds the
noban permission, or because it is a MANUAL connection; Core exempts both,
independently."
  (when reason
    (bl:log-cat "net" "Misbehaving: ~A: ~A"
                (peer-log-name peer) reason))
  ;; NoBan: neither discouraged NOR disconnected (Core
  ;; MaybeDiscourageAndDisconnect, net_processing.cpp — a noban peer's
  ;; m_should_discourage is cleared and the connection kept). The whole point
  ;; of -whitelist=noban is that a peer the operator trusts survives our
  ;; opinion of its behaviour, so stopping at "not discouraged" while still
  ;; dropping the connection would not deliver the option.
  (when (peer-has-permission-p peer +perm-noban+)
    (bl:log-cat "net" "Not punishing whitelisted ~A"
                (peer-log-name peer))
    (return-from record-misbehavior nil))
  ;; Core's SECOND exemption, and it is INDEPENDENT of the first
  ;; (net_processing.cpp:5187-5190): "We never disconnect or discourage manual
  ;; peers for bad behavior". A manual connection does not get NoBan by
  ;; default -- CConnman gives an outbound dial NetPermissionFlags::None and
  ;; consults vWhitelistedRangeOutgoing only for MANUAL connections
  ;; (net.cpp:510-512, PEER-PERMISSIONS here) -- so an -addnode peer with no
  ;; matching -whitelist ...,out entry holds no permissions at all and is
  ;; exempt purely by its connection type.
  ;;
  ;; Without it an operator-pinned peer that trips any misbehaviour site was
  ;; disconnected AND discouraged, and CONNECT-PEER refuses a discouraged
  ;; address outright -- which is the very call CONNECT-ADDED-NODES makes from
  ;; maintain-peers on every tick. Our discourage filter is a 50,000-entry FIFO
  ;; with no time expiry, so on any node that does not discourage tens of
  ;; thousands of addresses the entry never rolls out and the pinned peer stays
  ;; down until the process restarts. That removes the whole point of -addnode:
  ;; the operator's ability to keep a peer whose implementation we disagree
  ;; with, which is why Core's exemption exists and why Core logs it as a
  ;; warning rather than acting.
  ;;
  ;; Deliberately a separate test rather than folding MANUAL into
  ;; PEER-PERMISSIONS: those flags are address-derived and shared with
  ;; inbound admission and eviction, and granting a manual peer NoBan would
  ;; exempt it from those too, which Core does not do.
  (when (peer-manual-p peer)
    (bl:log-warn "Not punishing manually connected ~A"
                 (peer-log-name peer))
    (return-from record-misbehavior nil))
  ;; Core MaybeDiscourageAndDisconnect (net_processing.cpp:5194-5201):
  ;; disconnect a local peer for bad behaviour but do NOT discourage it,
  ;; "since that would discourage all peers on the same local address" — and
  ;; Core's own log line names the inbound-onion case as what this protects.
  ;;
  ;; We discouraged unconditionally. Every inbound onion peer arrives via the
  ;; local Tor daemon on the loopback listener, so its address is literally
  ;; "127.0.0.1": one misbehaving onion peer discouraged the loopback address
  ;; and with it every present and future onion peer, silently disabling onion
  ;; reachability. The disconnect below still happens either way.
  (unless (loopback-address-p (peer-address peer))
    (discourage-peer (peer-address peer)))
  ;; Core has exactly ONE node-removal path: however a peer leaves,
  ;; DisconnectNode leads to FinalizeNode, which unconditionally runs the
  ;; tx-download manager's DisconnectedPeer, TxOrphanage::EraseForPeer and the
  ;; Peer-state reset -- MaybeDiscourageAndDisconnect reaches it like every
  ;; other caller (net_processing.cpp:5171-5207). We had three retirement
  ;; paths and only DISCONNECT-PEER was complete: this one closed the socket,
  ;; set the state and released the protection slot, and stopped. No
  ;; disconnect hook, so the tx-request tracker kept every announcement the
  ;; peer had made -- keyed by the peer OBJECT, so the struct stayed pinned --
  ;; no orphanage sweep, and the headers-sync buffer stayed attached.
  ;; Delegating is the whole fix; DISCONNECT-PEER already does all of it,
  ;; including the protection release that used to be duplicated here.
  (disconnect-peer peer)
  t)

(defun ban-key (string)
  "The canonical ban-list key for STRING, as (VALUES key subnet), or NIL when
it names neither an address nor a subnet.

An IP or CIDR range becomes Core's CSubNet::ToString of it (a bare address is
the /32 or /128 containing it, exactly as CSubNet(CNetAddr) makes one,
banman.cpp:118-122). An onion or I2P address keeps its own string and carries
no subnet: Core's CSubNet compares those by equality."
  (when (and (stringp string) (plusp (length string)))
    (let ((subnet (parse-subnet string)))
      (if subnet
          (values (subnet-string subnet) subnet)
          (multiple-value-bind (network address) (parse-network-address string)
            (when address
              (values (network-address-to-string network address) nil)))))))

(defun %ban-entry-live-p (entry now)
  (< now (ban-entry-until entry)))

(defun peer-banned-p (address)
  "Check if ADDRESS is currently banned -- Core BanMan::IsBanned(CNetAddr)
(banman.cpp:89-102), which walks EVERY banned range rather than looking the
address up: a ban on 127.0.0.0/24 covers 127.0.0.1, and that is what
p2p_disconnect_ban.py:52 asserts by re-banning the covered address and
expecting `IP/Subnet already banned'.

Returns T if banned, NIL otherwise. Expired bans are cleaned up."
  (let ((now (bl.ser:get-node-time)))
    (multiple-value-bind (key) (ban-key address)
      (bt:with-lock-held (*ban-lock*)
        ;; The exact key first: it is the common case, and it is the only one
        ;; an onion or I2P ban can hit.
        (let ((entry (and key (gethash key *banned-peers*))))
          (when entry
            (cond ((%ban-entry-live-p entry now) (return-from peer-banned-p t))
                  (t (remhash key *banned-peers*)))))
        ;; Otherwise ask every live range whether it covers this address.
        (let ((expired '())
              (hit nil))
          (maphash (lambda (k entry)
                     (cond ((not (%ban-entry-live-p entry now)) (push k expired))
                           ((and (ban-entry-subnet entry)
                                 (address-in-subnets-p
                                  address (list (ban-entry-subnet entry))))
                            (setf hit t))))
                   *banned-peers*)
          (dolist (k expired) (remhash k *banned-peers*))
          hit)))))

(defun subnet-exactly-banned-p (string)
  "T when STRING names a range that is itself on the ban list -- Core
BanMan::IsBanned(CSubNet) (banman.cpp:104-116), an exact lookup rather than a
walk. This is the question setban asks for an argument carrying a `/', and it
is why banning 127.0.0.0/24 twice is refused while banning 127.0.0.0/25 after
it is not."
  (let ((key (ban-key string)))
    (when key
      (bt:with-lock-held (*ban-lock*)
        (let ((entry (gethash key *banned-peers*)))
          (and entry (%ban-entry-live-p entry (bl.ser:get-node-time))))))))

(defun clear-ban-list ()
  "Clear all bans."
  (bt:with-lock-held (*ban-lock*)
    (clrhash *banned-peers*))
  (save-banlist))

(defun ban-address (address &optional (seconds *default-ban-time-seconds*))
  "Manually ban ADDRESS -- an IP, a CIDR subnet, or an onion/I2P address --
for SECONDS from now (Core BanMan::Ban, banman.cpp:130-142; SECONDS defaults
to -bantime). Records the creation time as Core's CBanEntry does, so
listbanned can report ban_duration. Returns T, NIL when ADDRESS names no
address or range."
  (multiple-value-bind (key subnet) (ban-key address)
    (when key
      (let ((now (bl.ser:get-node-time)))
        (bt:with-lock-held (*ban-lock*)
          (setf (gethash key *banned-peers*)
                (%make-ban-entry now (+ now seconds) subnet))))
      (save-banlist)
      t)))

(defun unban-address (address)
  "Remove ADDRESS from the ban list (Core BanMan::Unban, banman.cpp:144-152).
An EXACT erase of that range, not \"whatever covers it\": with 127.0.0.0/24
banned, unbanning 127.0.0.1 fails, as it does in Core. Returns T if the range
was banned, NIL otherwise."
  (let* ((key (ban-key address))
         (removed (and key
                       (bt:with-lock-held (*ban-lock*)
                         (remhash key *banned-peers*)))))
    (when removed (save-banlist))
    removed))

(defun %ban-network-rank (network)
  "Core's Network enum order (netaddress.h:33-51), which is the first term of
CNetAddr::operator< and so of CSubNet::operator<."
  (case network (:ipv4 1) (:ipv6 2) (:torv3 3) (:i2p 4) (:cjdns 5) (t 9)))

(defun %ban-order (a b)
  "Core's CSubNet::operator< (netaddress.cpp:1090-1093): the network address
first (itself network tag then bytes, :608-611), then the netmask.

The order is not cosmetic. Core's m_banned is a std::map keyed by CSubNet, so
listbanned comes out sorted and p2p_disconnect_ban.py:83 reads a row BY INDEX
-- listBeforeShutdown[2] must be the ban it inserted fourth."
  (flet ((key (ban)
           (let ((subnet (ban-entry-subnet (cdr ban))))
             (if subnet
                 (list (%ban-network-rank (subnet-network subnet))
                       (subnet-address subnet)
                       (subnet-netmask subnet))
                 ;; No subnet: an onion or I2P ban, keyed by its own string.
                 (multiple-value-bind (network address)
                     (parse-network-address (car ban))
                   (list (%ban-network-rank network)
                         (or address #())
                         #()))))))
    (destructuring-bind (rank-a addr-a mask-a) (key a)
      (destructuring-bind (rank-b addr-b mask-b) (key b)
        (cond ((/= rank-a rank-b) (< rank-a rank-b))
              ((mismatch addr-a addr-b)
               (let ((i (mismatch addr-a addr-b)))
                 (cond ((>= i (length addr-a)) t)
                       ((>= i (length addr-b)) nil)
                       (t (< (aref addr-a i) (aref addr-b i))))))
              (t (let ((i (mismatch mask-a mask-b)))
                   (and i
                        (cond ((>= i (length mask-a)) t)
                              ((>= i (length mask-b)) nil)
                              (t (< (aref mask-a i) (aref mask-b i))))))))))))

(defun list-bans ()
  "Return a list of (address . BAN-ENTRY) for active bans, pruning any that
have expired (Bitcoin Core listbanned), in Core's CSubNet order. ADDRESS is
the canonical range string the ban is keyed by."
  (let ((now (bl.ser:get-node-time))
        (result '())
        (expired '()))
    (bt:with-lock-held (*ban-lock*)
      (maphash (lambda (addr entry)
                 (if (%ban-entry-live-p entry now)
                     (push (cons addr entry) result)
                     (push addr expired)))
               *banned-peers*)
      (dolist (addr expired) (remhash addr *banned-peers*)))
    (sort result #'%ban-order)))

;;; Banlist persistence (Core BanMan <datadir>/banlist.json, banman.cpp).
;;; Core dumps immediately on every Ban/Unban/ClearBanned plus a 15-minute
;;; scheduler sweep; the mutators above call save-banlist directly, so the
;;; file never lags the in-memory list.

(defun save-banlist (&optional (path *banlist-path*))
  "Write the manual ban list to PATH as Core-style banlist.json:
{\"banned_nets\": [{\"version\", \"ban_created\", \"banned_until\",
\"address\"}]} with UNIX-epoch times. No-op when PATH is NIL. Never signals —
a failed dump only logs (Core LogError in DumpBanlist)."
  (when path
    (handler-case
        (let* ((bans (list-bans))
               (entries
                 (mapcar (lambda (ban)
                           (let ((ht (make-hash-table :test 'equal))
                                 (entry (cdr ban)))
                             (setf (gethash "version" ht) 1
                                   (gethash "ban_created" ht)
                                   (- (ban-entry-created entry)
                                      bl.ser:+universal-unix-epoch-offset+)
                                   (gethash "banned_until" ht)
                                   (- (ban-entry-until entry)
                                      bl.ser:+universal-unix-epoch-offset+)
                                   (gethash "address" ht) (car ban))
                             ht))
                         bans))
               (top (make-hash-table :test 'equal))
               (tmp (merge-pathnames (concatenate 'string (file-namestring path) ".new")
                                     path)))
          (setf (gethash "banned_nets" top) entries)
          (ensure-directories-exist path)
          (with-open-file (out tmp :direction :output :if-exists :supersede
                                   :if-does-not-exist :create)
            (yason:encode top out))
          (rename-file tmp path)
          t)
      (error (e)
        (bl:log-warn "Could not write banlist ~A: ~A" path e)
        nil))))

(defun load-banlist (&optional (path *banlist-path*))
  "Open the manual ban list at PATH: Core BanMan's constructor, which is
LoadBanlist() and then DumpBanlist() (banman.cpp:17-22), dropping
already-expired entries (Core SweepBanned). Returns the number of active bans
loaded; NIL when the file was absent or unreadable, in which case it has been
RECREATED before this returns."
  ;; Core logs "Recreating the banlist database" whenever CBanDB::Read fails
  ;; (banman.cpp:41), and an ABSENT file is one of those failures — a fresh
  ;; datadir has no banlist.json. Returning NIL silently was the gap:
  ;; p2p_disconnect_ban.py greps for the line on a node that has never banned
  ;; anyone.
  ;;
  ;; The failed read also sets m_is_dirty (banman.cpp:43), so the DumpBanlist
  ;; the constructor runs next WRITES the empty list back out; after a read
  ;; that succeeded nothing is dirty and that dump writes nothing
  ;; (banman.cpp:56), which is why the recreate lives in these two branches
  ;; and not after the parse. p2p_disconnect_ban.py:43-47 deletes
  ;; banlist.json, restarts the node, and asserts the file is there again.
  (unless (and path (probe-file path))
    (bl:log-info "Recreating the banlist database")
    (save-banlist path)
    (return-from load-banlist nil))
  (when (and path (probe-file path))
    (handler-case
        (let* ((json (with-open-file (in path) (yason:parse in)))
               (nets (and (hash-table-p json) (gethash "banned_nets" json)))
               (now (bl.ser:get-node-time))
               (count 0))
          (bt:with-lock-held (*ban-lock*)
            (dolist (entry nets)
              (when (hash-table-p entry)
                (let ((addr (gethash "address" entry))
                      (until (gethash "banned_until" entry))
                      (created (gethash "ban_created" entry)))
                  (when (and (stringp addr) (integerp until))
                    (let ((expiry (+ until bl.ser:+universal-unix-epoch-offset+)))
                      (when (> expiry now)
                        ;; Re-key through BAN-KEY: the stored string is already
                        ;; canonical, but a file written by Core (or by an
                        ;; older build of this node) need not be, and the
                        ;; subnet has to be re-parsed for matching either way.
                        (multiple-value-bind (key subnet) (ban-key addr)
                          (when key
                            (setf (gethash key *banned-peers*)
                                  (%make-ban-entry
                                   (if (integerp created)
                                       (+ created bl.ser:+universal-unix-epoch-offset+)
                                       expiry)
                                   expiry subnet))
                            (incf count))))))))))
          count)
      (error (e)
        ;; Core logs this exact line and starts from an empty list rather than
        ;; failing (banman.cpp:42). p2p_disconnect_ban.py greps for it, which is
        ;; the whole point of matching the wording: Core's own tests are the
        ;; behavioural oracle, and they read the log.
        (bl:log-info "Recreating the banlist database")
        (bl:log-warn "Could not read banlist ~A: ~A" path e)
        ;; Core's failed-read branch is m_banned = {} (banman.cpp:42), so a
        ;; half-parsed file leaves no bans behind and the recreate writes the
        ;; empty list.
        (bt:with-lock-held (*ban-lock*) (clrhash *banned-peers*))
        (save-banlist path)
        nil))))

;;; Per-Peer Rate Limiting

(defun check-peer-rate-limit (peer command &optional (handler (p2p-handler-for command)))
  "Check if PEER is within rate limits for COMMAND: T if allowed, NIL if the
command's token bucket (its DEFINE-P2P-HANDLER :rate-bucket) is empty. A
command with no bucket, or none this node handles, is always allowed.
HANDLER is COMMAND's table row; HANDLE-MESSAGE passes the one it already
looked up."
  (let ((bucket (and handler (p2p-handler-rate-bucket handler))))
    (or (null bucket)
        (bl:token-bucket-allow-p (funcall bucket peer)))))
