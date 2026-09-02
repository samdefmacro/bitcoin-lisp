(in-package #:bitcoin-lisp.rpc)

;;;; Network RPCs (Core rpc/net.cpp): peers, addresses, manual connections, bans,
;;;; getnettotals, addpeeraddress and sendmsgtopeer.

;;; --- Network Query Methods ---

(defun %connection-type-string (conn-type)
  "Core CNode::ConnectionTypeAsString for our peer conn-type keyword."
  (case conn-type
    (:inbound "inbound")
    (:outbound-full-relay "outbound-full-relay")
    (:block-relay "block-relay-only")
    (:feeler "feeler")
    (:manual "manual")
    (:addr-fetch "addr-fetch")
    (t (string-downcase (symbol-name conn-type)))))

(defun %service-names (services)
  "Human-readable service-flag names for SERVICES as a list, in bit order —
Core serviceFlagsToStr (protocol.cpp:92-115): the six named bits, and
UNKNOWN[2^n] for any other set bit. Callers emitting a possibly-EMPTY set
must coerce to a vector (NIL would encode as null, not [])."
  (loop for bit from 0 below 64
        when (logtest services (ash 1 bit))
          collect (case bit
                    (0 "NETWORK")
                    (2 "BLOOM")
                    (3 "WITNESS")
                    (6 "COMPACT_FILTERS")
                    (10 "NETWORK_LIMITED")
                    (11 "P2P_V2")
                    (t (format nil "UNKNOWN[2^~D]" bit)))))

(defun %peer-network-name (peer)
  "Core GetNetworkName(ConnectedThroughNetwork()) for getpeerinfo's
\"network\": a peer accepted through the local onion service is \"onion\"
regardless of its socket address (127.0.0.1); otherwise the address's
network, or \"not_publicly_routable\" when it isn't a routable literal."
  (multiple-value-bind (net bytes)
      (bl.net:parse-network-address
       (bl.net:peer-address peer))
    (cond
      ((bl.net:peer-inbound-onion peer) "onion")
      ((and net (bl.net:address-routable-p bytes net))
       (ecase net
         (:ipv4 "ipv4") (:ipv6 "ipv6") (:torv3 "onion")
         (:i2p "i2p") (:cjdns "cjdns")))
      (t "not_publicly_routable"))))

(defun %peer-addrbind (peer)
  "The local end of this peer's socket, \"ip:port\", or NIL when it cannot be
read (Core addrBind, CNode::addrBind, set from the accepted/connected socket).

Every P2P functional test reads this field: the framework matches a connection
it opened against the node's getpeerinfo row by comparing addrbind to the
address it dialled. Taken from the socket rather than from configuration —
with -bind=0.0.0.0 the configured address names no interface, and the bind
address of an OUTBOUND connection is whichever local address the kernel chose."
  (let* ((connection (bl.net:peer-connection peer))
         (socket (and connection (bl.net:connection-socket connection))))
    (when socket
      (ignore-errors
       (let ((address (usocket:get-local-address socket))
             (port (usocket:get-local-port socket)))
         (when (and address port)
           (let ((text (usocket:host-to-hostname address)))
             ;; A v6 literal is bracketed before the port, as Core's
             ;; CService::ToStringAddrPort does.
             (if (find #\: text)
                 (format nil "[~A]:~D" text port)
                 (format nil "~A:~D" text port)))))))))

(defun %peer-addr (peer)
  "The peer's address as \"ip:port\" (Core CNode::addr.ToStringAddrPort(),
which is what getpeerinfo's `addr` carries — rpc/net.cpp:130).

Ours reported the host alone. The port is not decoration: the framework pairs
the two ends of a connection by comparing one node's `addrbind` against the
other's `addr` (rpc_net.py:116-117), and a bare host can never equal an
\"ip:port\". More plainly, two peers behind one address are indistinguishable
in getpeerinfo output without it, which on regtest is every peer.

Read from the socket, like ADDRBIND: an outbound connection knows the port it
dialled, and an inbound one only learns the remote's ephemeral port from the
accepted socket."
  (let* ((connection (bl.net:peer-connection peer))
         (socket (and connection (bl.net:connection-socket connection)))
         (host (bl.net:peer-address peer))
         (port (or (ignore-errors (and socket (usocket:get-peer-port socket)))
                   (let ((p (and connection
                                 (bl.net:connection-port connection))))
                     (and p (plusp p) p)))))
    (cond ((null port) host)
          ;; A v6 literal is bracketed before the port, as Core's
          ;; CService::ToStringAddrPort does.
          ((find #\: host) (format nil "[~A]:~D" host port))
          (t (format nil "~A:~D" host port)))))

(defun %peer-addrlocal (peer)
  "Our address as the peer reported it in its version message's addr_recv
(Core addrLocal, set from the version addrMe for outbound peers when
routable, net_processing.cpp:3651-3654). Returns \"ip:port\" or NIL — the
field is optional in Core and omitted when unknown."
  (let ((vmsg (bl.net:peer-version peer)))
    (when (and vmsg (not (bl.net:peer-inbound peer)))
      (let* ((addr-me (bl.ser:version-message-addr-recv vmsg))
             (ip (bl.ser:net-addr-ip addr-me))
             (net (and (= (length ip) 16) (bl.net:ip-network ip))))
        (when (and net (bl.net:address-routable-p ip net))
          (format nil "~A:~D"
                  (bl.net:network-address-to-string net ip)
                  (bl.ser:net-addr-port addr-me)))))))

(defun %universal-to-unix (universal)
  "Universal-time -> unix time, preserving 0 as \"never\" (Core reports 0)."
  (if (plusp universal)
      (- universal bl.ser:+universal-unix-epoch-offset+)
      0))

(define-rpc "getpeerinfo" (node params)
  "Return information about connected peers (Bitcoin Core getpeerinfo),
emitting every Core field we can populate honestly. Deliberate omissions:
mapped_as (no -asmap support).
Divergences: startingheight is always present (Core hides it behind
-deprecatedrpc=startingheight); synced_blocks is always -1 (we track no
per-peer last-common-block cursor — -1 is Core's \"unknown\" value);
last_block stamps every block received (Core stamps only NEW blocks)."
  (declare (ignore params))
  ;; Core builds a UniValue VARR, so a node with no peers answers [] — a bare
  ;; NIL list would encode as null.
  (json-array (%peerinfo-rows node)))

(defun %peerinfo-rows (node)
  "One getpeerinfo row (a field alist) per CONNECTED peer — the body of Core's
getpeerinfo loop, rpc/net.cpp:107-227.

Rows come out in ASCENDING PEER ID, which is Core's order and not an
aesthetic choice: m_nodes is a vector appended to on connect, ids are handed
out monotonically, and GetNodeStats walks it in place (net.cpp:3797-3807). Our
node-peers is a list PUSHED to, so it was newest-first — exactly reversed.

Tests index this array positionally. rpc_net.py pairs the two ends of a
connection with `assert_equal(peer_info[0][0]['addrbind'],
peer_info[1][0]['addr'])` (:116), which compares the wrong two peers entirely
if either node's list is reversed, and does so with plausible-looking values.

Peers in state :DISCONNECTED are skipped. Core has no equivalent filter because
it has no equivalent state: DisconnectNodes() removes the node from m_nodes on
every socket-handler pass, roughly every 50ms, so a disconnected node is simply
not in the list getpeerinfo walks. Ours is reaped by REPLACE-DISCONNECTED-PEERS
once per sync cycle, and a sync cycle can be half a minute — so a peer this node
had already dropped kept being reported as connected for that long.

Core's functional framework allows FIVE seconds for a disconnected peer to
leave getpeerinfo (disconnect_nodes, test_framework.py:626), which is generous
against 50ms and hopeless against 30s. Filtering here is not a workaround for
the reap cadence: reporting a peer we have closed the socket on is wrong
whatever the cadence is."
  (let ((peers (sort (remove-if (lambda (p)
                                  (eq (bl.net:peer-state p) :disconnected))
                                (rpc-get-peers node))
                     #'< :key #'bl.net:peer-id))
        (chain-state (rpc-get-chain-state node))
        (now (get-internal-real-time)))
    (mapcar
     (lambda (peer)
       ;; peer-version holds the received version *message* struct, not a
       ;; number — pull the numeric protocol version out of it.
       (let* ((vmsg (bl.net:peer-version peer))
              (conn (bl.net:peer-connection peer))
              (ping (bl.net:peer-ping-latency peer))
              (minping (bl.net:peer-min-ping-latency peer))
              (ping-nonce (bl.net:peer-ping-nonce peer))
              (services (or (bl.net:peer-services peer) 0))
              (sh (or (bl.net:peer-start-height peer) -1))
              (hss (bl.net:peer-headers-sync peer))
              (transport (and conn (bl.net:connection-transport conn)))
              ;; Last header we have in common: the peer's best known block
              ;; per its inv/headers announcements (Core pindexBestKnownBlock
              ;; -> nSyncHeight), -1 while unknown.
              (best-known (bl.net:peer-best-known-block-hash peer))
              (best-entry (and best-known chain-state
                               (bl.store:get-block-index-entry
                                chain-state best-known)))
              ;; Heights of blocks in flight from this peer (Core
              ;; vHeightInFlight), ascending; hashes whose header vanished
              ;; (reorged index) are skipped.
              (inflight
                (sort (loop for hash in (bl.net:peer-inflight-block-hashes peer)
                            for entry = (and chain-state
                                             (bl.store:get-block-index-entry
                                              chain-state hash))
                            when entry
                              collect (bl.store:block-index-entry-height entry))
                      #'<)))
         `(("id" . ,(bl.net:peer-id peer))
           ("addr" . ,(%peer-addr peer))
           ,@(let ((addrlocal (%peer-addrlocal peer)))
               (when addrlocal `(("addrlocal" . ,addrlocal))))
           ,@(let ((addrbind (%peer-addrbind peer)))
               (when addrbind `(("addrbind" . ,addrbind))))
           ("network" . ,(%peer-network-name peer))
           ;; Core reports services as a 16-hex-digit string, not a number.
           ("services" . ,(string-downcase (format nil "~16,'0X" services)))
           ("servicesnames" . ,(coerce (%service-names services) 'vector))
           ;; Whether we relay txs to this peer: tx-relay state exists — the
           ;; connection type allows it AND the peer's version set fRelay
           ;; (Core CNodeStateStats::m_relay_txs).
           ("relaytxes" . ,(json-bool (bl.net:peer-tx-relay-p peer)))
           ;; Mempool sequence snapshot of our last inv flush to this peer +
           ;; queued-but-unsent announcements (Core m_last_inv_sequence /
           ;; m_inv_to_send).
           ("last_inv_sequence" . ,(bl.net:peer-last-inv-sequence peer))
           ("inv_to_send" . ,(length (bl.net:peer-tx-inv-queue peer)))
           ("lastsend" . ,(%universal-to-unix
                           (if conn (bl.net:connection-last-send-time conn) 0)))
           ("lastrecv" . ,(%universal-to-unix
                           (if conn (bl.net:connection-last-recv-time conn) 0)))
           ("last_transaction" . ,(bl.net:peer-last-tx-time peer))
           ("last_block" . ,(bl.net:peer-last-block-time peer))
           ("bytessent" . ,(if conn (bl.net:connection-bytes-sent conn) 0))
           ("bytesrecv" . ,(if conn (bl.net:connection-bytes-received conn) 0))
           ("conntime" . ,(bl.net:peer-connected-at peer))
           ;; Peer's version-message timestamp vs our clock at receipt.
           ("timeoffset" . ,(bl.net:peer-time-offset peer))
           ;; ping stats are in internal-time units; report seconds. All
           ;; three are optional in Core: pingtime/minping only once a pong
           ;; arrived, pingwait only while a ping is outstanding.
           ,@(when (plusp ping)
               `(("pingtime" . ,(/ ping internal-time-units-per-second 1.0d0))))
           ,@(when (plusp minping)
               `(("minping" . ,(/ minping internal-time-units-per-second 1.0d0))))
           ,@(when ping-nonce
               `(("pingwait" . ,(/ (- now (bl.net:peer-last-ping-time peer))
                                   internal-time-units-per-second 1.0d0))))
           ("version" . ,(if vmsg
                             (bl.ser:version-message-version vmsg)
                             0))
           ("subver" . ,(or (bl.net:peer-user-agent peer) ""))
           ("inbound" . ,(json-bool (bl.net:peer-inbound peer)))
           ;; BIP152 high-bandwidth selection, both directions (Core
           ;; m_bip152_highbandwidth_to / _from).
           ("bip152_hb_to" . ,(json-bool
                               (bl.net:peer-compact-block-high-bandwidth-to peer)))
           ("bip152_hb_from" . ,(json-bool
                                 (bl.net:peer-compact-block-high-bandwidth peer)))
           ;; Kept unconditionally (Core gates it behind -deprecatedrpc).
           ("startingheight" . ,sh)
           ;; Low-work headers presync progress (Core presync_height): the
           ;; current height of an in-progress PRESYNC phase, else -1.
           ("presynced_headers"
            . ,(if (and hss (eq (bl.net:hss-state hss) :presync))
                   (bl.net:hss-current-height hss)
                   -1))
           ("synced_headers" . ,(if best-entry
                                    (bl.store:block-index-entry-height best-entry)
                                    -1))
           ;; We keep no pindexLastCommonBlock analogue; -1 = unknown.
           ("synced_blocks" . -1)
           ("inflight" . ,(coerce inflight 'vector))
           ("addr_relay_enabled" . ,(json-bool
                                     (bl.net:peer-addr-relay-enabled peer)))
           ;; Addr intake counters (Core m_addr_processed /
           ;; m_addr_rate_limited; the rate-limited count is addresses
           ;; dropped by the per-address token bucket).
           ("addr_processed" . ,(bl.net:peer-addr-processed peer))
           ("addr_rate_limited" . ,(bl.net:peer-addr-rate-limited peer))
           ;; The -whitelist / -whitebind permissions this peer holds (Core
           ;; getpeerinfo "permissions", rpc/net.cpp). Was hardcoded empty.
           ("permissions"
            . ,(let ((names (bl.net:permission-flag-names
                             (bl.net:peer-permission-flags
                              (bl.net:peer-address peer)
                              (bl.net:peer-inbound peer)))))
                 (if names (coerce names 'vector) #())))
           ;; BIP133: the peer's advertised fee floor, sat/kvB -> BTC/kvB.
           ("minfeefilter" . ,(/ (bl.net:peer-feefilter-rate peer)
                                 100000000.0d0))
           ("bytessent_per_msg" . ,(bl.net:snapshot-per-msg-table
                                    (bl.net:peer-sent-per-msg peer)))
           ("bytesrecv_per_msg" . ,(bl.net:snapshot-per-msg-table
                                    (bl.net:peer-recv-per-msg peer)))
           ;; Core ConnectionType string (block-relay-only/feeler peers get
           ;; no tx relay -- #216).
           ;; A manual peer's TYPE is "manual" in Core — ConnectionType::MANUAL
           ;; is a first-class member of the enum (node/connection_types.cpp:13),
           ;; not an outbound-full-relay peer carrying a flag. We keep it as a
           ;; flag internally because the outbound-slot budgets are written
           ;; against the automatic types, and Core's manual peer likewise
           ;; occupies none of them; what has to agree is the REPORT.
           ("connection_type" . ,(if (and (bl.net:peer-manual peer)
                                          (not (bl.net:peer-inbound peer)))
                                     "manual"
                                     (%connection-type-string
                                      (bl.net:peer-conn-type peer))))
           ;; Core TransportTypeAsString: the BIP324 v2 session lives in
           ;; connection-transport (NIL = plaintext v1). Peers surface
           ;; here only after the handshake, so "detecting" never applies.
           ("transport_protocol_type" . ,(if transport "v2" "v1"))
           ;; BIP324 session id (v2 only; "" otherwise, like Core).
           ("session_id"
            . ,(let ((sid (and transport
                               (bl.net:v2-transport-p transport)
                               (bl.crypto:bip324-cipher-session-id
                                (bl.net:v2-transport-cipher transport)))))
                 (if sid (bl.crypto:bytes-to-hex sid) ""))))))
     peers)))

(define-rpc "getnetworkinfo" (node params)
  "Return network state information (Bitcoin Core getnetworkinfo)."
  (declare (ignore params))
  (let* ((network (rpc-get-network node))
         (peers (rpc-get-peers node))
         ;; THE service bits we advertise on the wire (peer.lisp local-services,
         ;; Core g_local_services) — the one composition; do not duplicate it
         ;; here. Names via the shared %service-names (Core GetServicesNames).
         (services (bl.net:local-services))
         (service-names (%service-names services))
         (in (count-if #'bl.net:peer-inbound peers))
         ;; The EFFECTIVE -minrelaytxfee (sat/kvB -> BTC/kvB); Core reports
         ;; ::minRelayTxFee.GetFeePerK(), not the compile-time default.
         (relayfee (/ bl.mp:*min-relay-fee-rate*
                      100000000.0d0))
         ;; *incremental-relay-fee-rate* is sat/kvB -> BTC/kvB.
         (incfee (/ bl.mp:*incremental-relay-fee-rate* 100000000.0d0)))
    `(("version" . ,bl.ser:+client-version+)
      ("subversion" . ,bl.ser:*user-agent*)
      ("protocolversion" . 70016)
      ("localservices" . ,(string-downcase (format nil "~16,'0X" services)))
      ("localservicesnames" . ,service-names)
      ;; Core: localrelay = !peerman->IgnoresIncomingTxs() — false under
      ;; -blocksonly OR our mainnet relay-disabled default. json-bool so it
      ;; serializes as JSON true/false (never null).
      ("localrelay" . ,(json-bool (not (bl.net:ignore-incoming-txs-p))))
      ("timeoffset" . 0)
      ("networkactive" . ,(json-bool (bl:node-network-active node)))
      ("connections" . ,(length peers))
      ("connections_in" . ,in)
      ("connections_out" . ,(- (length peers) in))
      ("networks" . ((("name" . ,(case network
                                   (:testnet3 "testnet")
                                   (:testnet4 "testnet4")
                                   (:signet "signet")
                                   (:regtest "regtest")
                                   (:mainnet "mainnet")
                                   (t "unknown")))
                      ("reachable" . t))))
      ("relayfee" . ,relayfee)
      ("incrementalfee" . ,incfee)
      ;; We record no local addresses, so this is Core's empty VARR — [], not
      ;; null (a bare NIL encodes as null).
      ("localaddresses" . #())
      ("warnings" . #()))))

(define-rpc "getconnectioncount" (node params)
  "Return the number of connected peers."
  (declare (ignore params))
  (length (rpc-get-peers node)))

(define-rpc "ping" (node params)
  "Queue a ping to every connected peer (Bitcoin Core ping). The round-trip
result later surfaces in getpeerinfo's pingtime. Returns null. send-ping is a
no-op on a peer whose connection has dropped, and ignore-errors guards against a
peer disconnecting mid-send."
  (declare (ignore params))
  (dolist (peer (rpc-get-peers node))
    (ignore-errors (bl.net:send-ping peer)))
  nil)

;;; --- Peer / address RPCs ---

(define-rpc "getnodeaddresses" (node params)
  "Return known peer addresses from the address book (Bitcoin Core
getnodeaddresses). PARAMS: ([count]) — max addresses (default 1; 0 = all)."
  (let* ((count (if (integerp (first params)) (first params) 1))
         (book (bl:node-address-book node))
         ;; count=0 => all known addresses; count>0 => up to that many.
         (limited (and book (bl.net:address-book-get-addr
                             book :max (max count 0) :pct 100))))
    ;; Core pushes a VARR: an empty address book is [], not null.
    (json-array
     (mapcar
      (lambda (pa)
        `(("time" . ,(bl.net:peer-address-last-seen pa))
          ("services" . ,(bl.net:peer-address-services pa))
          ("address" . ,(bl.net:peer-address-string pa))
          ("port" . ,(bl.net:peer-address-port pa))
          ("network" . ,(or (%addrman-network-name pa) "unroutable"))))
      limited))))

(defun %addrman-network-name (pa)
  "Network bucket name (Bitcoin Core GetNetworkName) for a peer-address PA, or
NIL for an unroutable/empty address."
  (let ((network (bl.net:peer-address-network pa)))
    (when (bl.net:address-routable-p
           (bl.net:peer-address-ip pa) network)
      (ecase network
        (:ipv4 "ipv4") (:ipv6 "ipv6") (:torv3 "onion")
        (:i2p "i2p") (:cjdns "cjdns")))))

(define-rpc "getaddrmaninfo" (node params)
  "Address-manager new/tried/total counts per network plus an all_networks
aggregate (Bitcoin Core getaddrmaninfo). Like Core, every standard network key
is always present (0 when empty); all_networks uses the address book's
authoritative running counts."
  (declare (ignore params))
  (let ((book (bl:node-address-book node))
        ;; name -> (new . tried)
        (tally (make-hash-table :test 'equal))
        (networks '("ipv4" "ipv6" "onion" "i2p" "cjdns")))
    (dolist (n networks) (setf (gethash n tally) (cons 0 0)))
    (when book
      (maphash
       (lambda (id pa)
         (declare (ignore id))
         (let ((name (%addrman-network-name pa)))
           (when name
             (let ((cell (gethash name tally)))
               (if (bl.net:peer-address-in-tried pa)
                   (incf (cdr cell))
                   (incf (car cell)))))))
       (bl.net:address-book-info book)))
    (flet ((entry (new tried)
             `(("new" . ,new) ("tried" . ,tried) ("total" . ,(+ new tried)))))
      (let ((result (mapcar (lambda (n)
                              (let ((cell (gethash n tally)))
                                (cons n (entry (car cell) (cdr cell)))))
                            networks))
            (nn (if book (bl.net:address-book-n-new book) 0))
            (nt (if book (bl.net:address-book-n-tried book) 0)))
        (append result (list (cons "all_networks" (entry nn nt))))))))

(defparameter %addconnection-types
  '(("outbound-full-relay" . :outbound-full-relay)
    ("block-relay-only"    . :block-relay)
    ("addr-fetch"          . :addr-fetch)
    ("feeler"              . :feeler))
  "Core addconnection's connection_type strings (rpc/net.cpp) and the peer
conn-types they name here. MANUAL and INBOUND are deliberately absent: Core's
AddConnection returns false for them (net.cpp), because addconnection exists to
open the AUTOMATIC connection kinds a test cannot otherwise ask for.")

(defun %addconnection-capacity-left-p (node conn-type)
  "Whether another CONN-TYPE connection fits (Core CConnman::AddConnection's
max_connections switch, net.cpp).

ADDR-FETCH and FEELER have no cap in Core — the first because -seednode has
none either, the second because feelers are short-lived — so they always fit."
  (case conn-type
    (:outbound-full-relay
     (< (bl:peers-of-conn-type node :outbound-full-relay)
        (bl:node-max-peers node)))
    (:block-relay
     (< (bl:peers-of-conn-type node :block-relay)
        bl:+target-block-relay-peers+))
    (t t)))

(define-rpc "addconnection" (node params)
  "Open one outbound connection of a named type (Core addconnection,
rpc/net.cpp). Regtest only, and for testing only: it is how the functional
framework attaches its own P2P connections to a node.

PARAMS: (address connection_type v2transport). The dial itself is HANDED TO THE
SYNC THREAD rather than run here — node-peers is single-writer by design, and
Core's own AddConnection likewise returns before the connection completes. The
capacity check runs synchronously, because that is the answer the caller needs."
  (unless (eq bl:*network* :regtest)
    ;; Core raises a plain std::runtime_error, which JSONRPCError maps to
    ;; RPC_MISC_ERROR with this exact text (rpc/net.cpp).
    (error 'rpc-error :code +rpc-misc-error+
                      :message "addconnection is for regression testing (-regtest mode) only."))
  (let* ((address (first params))
         (type-string (second params))
         (v2transport (third params)))
    (unless (and (stringp address) (plusp (length address)))
      (error 'rpc-error :code +rpc-type-error+
                        :message "Expected type string for address"))
    (unless (stringp type-string)
      (error 'rpc-error :code +rpc-type-error+
                        :message "Expected type string for connection_type"))
    (let* ((trimmed (string-trim '(#\Space #\Tab #\Newline #\Return) type-string))
           (conn-type (cdr (assoc trimmed %addconnection-types :test #'string=))))
      (unless conn-type
        (error 'rpc-error :code +rpc-invalid-parameter+
                          :message "Type of connection to open (\"outbound-full-relay\", \"block-relay-only\", \"addr-fetch\" or \"feeler\")."))
      ;; Core refuses a v2 request when the node was not started with
      ;; -v2transport, rather than silently dialing v1 (rpc/net.cpp).
      (when (and (positional-bool v2transport)
                 (not (bl.net:v2-available-p)))
        (error 'rpc-error :code +rpc-invalid-parameter+
                          :message "Error: Adding v2transport connections requires -v2transport init flag to be set."))
      (unless (%addconnection-capacity-left-p node conn-type)
        (error 'rpc-error :code +rpc-client-node-capacity-reached+
                          :message "Error: Already at capacity for specified connection type."))
      (bt:with-recursive-lock-held ((bl:node-lock node))
        (push (cons address conn-type) bl:*pending-test-connections*))
      `(("address" . ,address)
        ("connection_type" . ,trimmed)))))

(define-rpc "addnode" (node (spec command))
  "Manage manually-added peers (Bitcoin Core addnode). PARAMS:
(node command [v2transport]). COMMAND is \"add\" (remember the peer and keep it
connected), \"remove\", or \"onetry\" (dial once now). The actual dialing is
handed to the sync thread (via added-nodes / pending-onetry) so node-peers stays
single-writer. Returns null. v2transport is accepted and ignored — BIP324 v2
transport is not implemented."
  (unless (and (stringp spec) (plusp (length spec)))
    (error 'rpc-error :code +rpc-invalid-parameter+ :message "node must be a string"))
  (unless (member command '("add" "remove" "onetry") :test #'equal)
    (error 'rpc-error :code +rpc-invalid-parameter+
                      :message "command must be \"add\", \"remove\", or \"onetry\""))
  (bt:with-recursive-lock-held ((bl:node-lock node))
    (cond
      ((equal command "onetry")
       (push spec (bl:node-pending-onetry node)))
      ((equal command "add")
       (when (member spec (bl:node-added-nodes node) :test #'string=)
         (error 'rpc-error :code +rpc-client-node-already-added+
                           :message "Error: Node already added"))
       (setf (bl:node-added-nodes node)
             (append (bl:node-added-nodes node) (list spec))))
      ((equal command "remove")
       (unless (member spec (bl:node-added-nodes node) :test #'string=)
         (error 'rpc-error :code +rpc-client-node-not-added+
                           :message "Error: Node could not be removed. It has not been added previously."))
       (setf (bl:node-added-nodes node)
             (remove spec (bl:node-added-nodes node) :test #'string=)))))
  nil)

(define-rpc "getaddednodeinfo" (node (filter))
  "Report manually-added peers and their connection state (Bitcoin Core
getaddednodeinfo). PARAMS: ([node]) — restrict to one added node (errors if it
was never added). Returns an array of {addednode, connected, addresses}."
  (when (and filter (not (stringp filter)))
    (error 'rpc-error :code +rpc-invalid-parameter+ :message "node must be a string"))
  (let ((added (bt:with-recursive-lock-held ((bl:node-lock node))
                 (copy-list (bl:node-added-nodes node)))))
    (when filter
      (unless (member filter added :test #'string=)
        (error 'rpc-error :code +rpc-client-node-not-added+
                          :message "Error: Node has not been added."))
      (setf added (list filter)))
    ;; Core pushes a VARR: no added nodes is [], not null.
    (json-array
     (mapcar
      (lambda (spec)
        (let* ((host (bl:parse-node-endpoint node spec))
               (peer (bt:with-recursive-lock-held ((bl:node-lock node))
                       (find host (bl:node-peers node)
                             :key #'bl.net:peer-address :test #'string=))))
          `(("addednode" . ,spec)
            ("connected" . ,(json-bool peer))
            ;; A list (not a vector) when populated, so rpc-result->json
            ;; recurses into it and normalizes the nested address object;
            ;; json-array renders the disconnected case as [], not null.
            ("addresses"
             . ,(json-array
                 (when peer
                   (list `(("address" . ,(bl.net:peer-address peer))
                           ("connected" . ,(if (bl.net:peer-inbound peer)
                                               "inbound" "outbound"))))))))))
      added))))

(defun %set-network-active (node state)
  "Flip the node's network-active flag (Core CConnman::SetNetworkActive).
When disabling, mark current peers disconnected (close socket + set state) —
Core's socket thread does the same as a consequence of the cleared flag
(net.cpp DisconnectNodes); the sync thread reaps them from node-peers,
keeping it single-writer. Shared by setnetworkactive and dumptxoutset's
rollback-time NetworkDisable. Returns STATE."
  (setf (bl:node-network-active node) state)
  (unless state
    (dolist (peer (bt:with-recursive-lock-held ((bl:node-lock node))
                    (copy-list (bl:node-peers node))))
      (ignore-errors (bl.net:disconnect-peer peer))))
  state)

(define-rpc "setnetworkactive" (node ((state :bool)))
  "Enable or disable all P2P network activity (Bitcoin Core setnetworkactive).
PARAMS: (state). Disabling drops all current peers and stops new inbound/outbound
connections until re-enabled. Returns the new state."
  (when (endp params)
    (error 'rpc-error :code +rpc-invalid-parameter+ :message "state is required"))
  ;; Bare JSON boolean result (Core net.cpp:907) — false must not be null.
  (json-bool (%set-network-active node state)))

(define-rpc "disconnectnode" (node (address nodeid))
  "Disconnect a connected peer by ADDRESS or by NODEID (Bitcoin Core
disconnectnode, rpc/net.cpp:462-486). PARAMS: (address nodeid).

Core's selection rule exactly, including which combination is an error:
address without nodeid disconnects by address; nodeid with either no address or
an EMPTY one disconnects by id; anything else is RPC_INVALID_PARAMS with Core's
text. The empty-string case is not a nicety — it is how Core's own help says to
disconnect by id positionally (`disconnectnode \"\" 1`).

By-id was missing, and it is the form Core's functional framework uses:
disconnect_nodes calls `disconnectnode(nodeid=peer_id)` for every peer it wants
gone (test_framework.py:616). With only the address form, that arrived as a
NIL address and answered \"address must be a string\" — an error about a
parameter the caller never sent."
  (let* ((have-address (and (stringp address) (plusp (length address))))
         (have-nodeid (integerp nodeid)))
    ;; Atomic against the sync thread's node-peers mutations: hold node-lock
    ;; across the find + disconnect so we don't act on a peer mid-removal.
    (bt:with-recursive-lock-held ((bl:node-lock node))
      (let ((target
              (cond
                ((and have-address (not have-nodeid))
                 (find address (bl:node-peers node)
                       :key (lambda (p) (bl.net:peer-address p))
                       :test #'string=))
                ((and have-nodeid (or (null address)
                                      (and (stringp address) (zerop (length address)))))
                 (find nodeid (bl:node-peers node)
                       :key (lambda (p) (bl.net:peer-id p))
                       :test #'eql))
                (t
                 (error 'rpc-error :code +rpc-invalid-params+
                                   :message "Only one of address and nodeid should be provided.")))))
        (unless target
          ;; Core: RPC_CLIENT_NODE_NOT_CONNECTED (-29), net.cpp:482.
          (error 'rpc-error :code +rpc-client-node-not-connected+
                            :message "Node not found in connected nodes"))
        (bl.net:disconnect-peer target)
        ;; Reap it here rather than waiting for the next sync cycle's
        ;; REPLACE-DISCONNECTED-PEERS. Core's DisconnectNodes() runs every
        ;; socket-handler pass, so by the time disconnectnode returns the node
        ;; is already out of m_nodes; ours would otherwise linger in
        ;; node-peers for as long as a sync cycle takes. We already hold
        ;; node-lock, which is the only thing that made this awkward before.
        (setf (bl:node-peers node)
              (remove target (bl:node-peers node)))
        nil))))

;;; --- Manual ban management (Bitcoin Core setban/listbanned/clearbanned) ---
;;;
;;; The MANUAL ban list (*banned-peers*) is separate from the automatic,
;;; ephemeral discouragement filter (see record-misbehavior); these RPCs only
;;; touch manual bans. Addresses are matched exactly (no subnet/CIDR support).

(define-rpc "setban" (node (address command bantime (absolute :bool)))
  "Add or remove a manual ban (Bitcoin Core setban). PARAMS:
(address command [bantime] [absolute]). COMMAND is \"add\" or \"remove\". For add,
BANTIME is seconds from now (default -bantime, 24h), or an absolute Unix time
when ABSOLUTE is true, and every connected peer with that address is
disconnected (Core net.cpp:803-810 -> CConnman::DisconnectNode). Error codes
mirror Core (net.cpp:766-812): a non-address (-30
RPC_CLIENT_INVALID_IP_OR_SUBNET), re-banning (-23), a failed unban (-30).
Subnet (CIDR) bans are not supported — bans match exact addresses — so
subnet syntax is rejected as invalid. Returns null."
  (unless (and (stringp address) (plusp (length address)))
    (error 'rpc-error :code +rpc-invalid-parameter+ :message "address required"))
  ;; Core: unparseable IP/subnet -> RPC_CLIENT_INVALID_IP_OR_SUBNET (-30),
  ;; net.cpp:781. parse-network-address accepts IPv4/IPv6/onion/i2p
  ;; literals; hostnames and CIDR subnets are rejected.
  (unless (bl.net:parse-network-address address)
    (error 'rpc-error :code +rpc-client-invalid-ip-or-subnet+
                      :message "Error: Invalid IP/Subnet"))
  (cond
    ((equal command "add")
     ;; Core: already banned -> RPC_CLIENT_NODE_ALREADY_ADDED (-23),
     ;; net.cpp:786.
     (when (bl.net:peer-banned-p address)
       (error 'rpc-error :code +rpc-client-node-already-added+
                         :message "Error: IP/Subnet already banned"))
     (cond
       ((null bantime) (bl.net:ban-address address))
       ((not (integerp bantime))
        (error 'rpc-error :code +rpc-invalid-parameter+ :message "bantime must be an integer"))
       (absolute
        ;; Core: an absolute time in the past is -8, net.cpp:796.
        (let ((offset (- bantime (bl.ser:get-unix-time))))
          (when (minusp offset)
            (error 'rpc-error :code +rpc-invalid-parameter+
                              :message "Error: Absolute timestamp is in the past"))
          (bl.net:ban-address address offset)))
       ;; Core: bantime <= 0 falls back to -bantime (banman.cpp:130-140).
       ((<= bantime 0) (bl.net:ban-address address))
       (t (bl.net:ban-address address bantime)))
     ;; Core: a fresh ban disconnects every matching connected peer itself
     ;; (net.cpp:803-810, CConnman::DisconnectNode marks ALL nodes with
     ;; that address). Same node-lock discipline as rpc-disconnectnode:
     ;; hold it across the scan + disconnects so we never act on a peer
     ;; mid-removal by the sync thread.
     (bt:with-recursive-lock-held ((bl:node-lock node))
       (dolist (peer (bl:node-peers node))
         (when (string= address (bl.net:peer-address peer))
           (bl.net:disconnect-peer peer))))
     nil)
    ((equal command "remove")
     (unless (bl.net:unban-address address)
       ;; Core: RPC_CLIENT_INVALID_IP_OR_SUBNET (-30), net.cpp:812.
       (error 'rpc-error :code +rpc-client-invalid-ip-or-subnet+
                         :message "Error: Unban failed. Requested address/subnet was not previously manually banned."))
     nil)
    (t (error 'rpc-error :code +rpc-invalid-parameter+
                         :message "command must be \"add\" or \"remove\""))))

(define-rpc "listbanned" (node params)
  "List active manual bans (Bitcoin Core listbanned)."
  (declare (ignore node params))
  ;; Core pushes a VARR: no bans is [], not null.
  (json-array
   (mapcar (lambda (ban)
             `(("address" . ,(car ban))
               ("banned_until" . ,(- (cdr ban)
                                     bl.ser:+universal-unix-epoch-offset+))))
           (bl.net:list-bans))))

(define-rpc "clearbanned" (node params)
  "Clear all manual bans (Bitcoin Core clearbanned). Returns null."
  (declare (ignore node params))
  (bl.net:clear-ban-list)
  nil)

;;; --- Network totals (Bitcoin Core getnettotals) ---

(define-rpc "getnettotals" (node params)
  "Cumulative network byte totals since startup (Bitcoin Core getnettotals)."
  (declare (ignore node params))
  `(("totalbytesrecv" . ,bl.net:*total-bytes-received*)
    ("totalbytessent" . ,bl.net:*total-bytes-sent*)
    ("timemillis" . ,(* (bl.ser:get-unix-time) 1000))
    ;; -maxuploadtarget (Core rpc/net.cpp:598-608). With no target set every
    ;; field reads as Core's disabled shape, because Core's own accessors
    ;; short-circuit on nMaxOutboundLimit == 0.
    ("uploadtarget"
     . (("timeframe" . ,bl.net:+max-upload-timeframe-seconds+)
        ("target" . ,bl.net:*max-upload-target*)
        ("target_reached"
         . ,(json-bool (bl.net:outbound-target-reached-p nil)))
        ("serve_historical_blocks"
         . ,(json-bool (not (bl.net:outbound-target-reached-p t))))
        ("bytes_left_in_cycle"
         . ,(bl.net:outbound-target-bytes-left))
        ("time_left_in_cycle"
         . ,(bl.net:max-outbound-time-left-in-cycle))))))

;;; --- addpeeraddress, sendmsgtopeer (Core rpc/net.cpp) ---

(define-rpc "addpeeraddress" (node (address port (tried :bool)))
  "Add an address to the address manager (Core addpeeraddress, rpc/net.cpp).
For testing only: it is how a functional test seeds addrman without a peer.

PARAMS: (address port [tried]). Returns {\"success\": bool} and, when TRIED was
asked for and refused, Core's \"error\" string alongside it — the promotion can
legitimately fail (the tried bucket position may be occupied and queued for a
collision test), and reporting success for that would misinform the test."
  (unless (and (stringp address) (plusp (length address)))
    (error 'rpc-error :code +rpc-type-error+ :message "Expected type string for address"))
  (unless (and (integerp port) (<= 0 port 65535))
    (error 'rpc-error :code +rpc-type-error+ :message "Expected type number for port"))
  (multiple-value-bind (net bytes)
      (bl.net:parse-network-address address)
    (unless (and net bytes)
      (error 'rpc-error :code +rpc-client-invalid-ip-or-subnet+
                        :message "Invalid IP address"))
    (let ((book (bl:node-address-book node)))
      (unless book
        (error 'rpc-error :code +rpc-misc-error+ :message "Address manager unavailable"))
      (let* ((pa (bl.net:make-peer-address
                  :net net :ip bytes :port port
                  ;; Core stores NODE_NETWORK|NODE_WITNESS for the address.
                  :services (logior 1 8)
                  :last-seen (bl.ser:get-unix-time)))
             (added (bl.net:address-book-add book pa)))
        (cond
          ((not added) `(("success" . ,(json-bool nil))))
          ((not tried) `(("success" . ,(json-bool t))))
          ((bl.net:address-book-good
            book bytes port (bl.ser:get-unix-time) net)
           `(("success" . ,(json-bool t))))
          (t `(("success" . ,(json-bool nil))
               ("error" . "failed-adding-to-tried"))))))))

(defconstant +max-message-type-size+ 12
  "Core CMessageHeader::MESSAGE_TYPE_SIZE.")

(define-rpc "sendmsgtopeer" (node (peer-id msg-type msg-hex))
  "Send a raw P2P message to a connected peer (Core sendmsgtopeer,
rpc/net.cpp). For testing only: it lets a functional test put an arbitrary
message on the wire without writing a P2P client.

PARAMS: (peer_id msg_type msg). Returns an empty object."
  (unless (integerp peer-id)
    (error 'rpc-error :code +rpc-type-error+ :message "Expected type number for peer_id"))
  (unless (stringp msg-type)
    (error 'rpc-error :code +rpc-type-error+ :message "Expected type string for msg_type"))
  (when (> (length msg-type) +max-message-type-size+)
    (error 'rpc-error :code +rpc-invalid-parameter+
                      :message (format nil "Error: msg_type too long, max length is ~D"
                                       +max-message-type-size+)))
  (unless (and (stringp msg-hex) (evenp (length msg-hex))
               (every (lambda (c) (digit-char-p c 16)) msg-hex))
    (error 'rpc-error :code +rpc-invalid-parameter+
                      :message "Error parsing input for msg"))
  (let ((peer (bt:with-recursive-lock-held ((bl:node-lock node))
                (find peer-id (bl:node-peers node)
                      :key #'bl.net:peer-id))))
    (unless peer
      (error 'rpc-error :code +rpc-misc-error+
                        :message "Error: Could not send message to peer"))
    (handler-case
        (bl.net:send-message
         peer (bl.ser:serialize-message
               msg-type (bl.crypto:hex-to-bytes msg-hex)))
      (error ()
        (error 'rpc-error :code +rpc-misc-error+
                          :message "Error: Could not send message to peer")))
    ;; Core returns an empty object; an empty hash-table serializes as {}.
    (make-hash-table :test (quote equal))))
