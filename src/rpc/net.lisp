(in-package #:bitcoin-lisp.rpc)

;;;; Network RPCs (Core rpc/net.cpp): peers, addresses, manual connections, bans,
;;;; getnettotals, addpeeraddress and sendmsgtopeer.

;;; --- Network Query Methods ---

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
network, or \"not_publicly_routable\" when it isn't a routable literal.

The routability question is Core's own -- ADDRESS-PUBLICLY-ROUTABLE-P, not the
addrman dial predicate beside it, which keeps loopback and the private and
documentation IPv4 ranges routable for regtest. Reading the dial predicate
here reported \"ipv4\" for a peer connecting from 127.0.0.1, where
rpc_net.py:148 expects \"not_publicly_routable\"."
  (multiple-value-bind (net bytes)
      (bl.net:parse-network-address
       (bl.net:peer-address peer))
    (cond
      ((bl.net:peer-inbound-onion peer) "onion")
      ((and net (bl.net:address-publicly-routable-p bytes net))
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
  "Our address as PEER reported it in its version message's addr_recv, as
\"ip:port\" -- for EVERY peer, inbound or outbound, whenever the report is a
valid address (Core CopyStats, net.cpp:652-654, over the m_addr_local the
VERSION handler sets for every peer, net_processing.cpp:3674). NIL before a
version or for an invalid report, where Core leaves the field out. Ours
reported outbound peers only, and only routable reports."
  (multiple-value-bind (net ip port) (bl.net:peer-addr-local peer)
    (when (and net (bl.net:address-valid-p ip net))
      (let ((host (bl.net:network-address-to-string net ip)))
        ;; CService::ToStringAddrPort brackets an IPv6 literal.
        (if (eq net :ipv6)
            (format nil "[~A]:~D" host port)
            (format nil "~A:~D" host port))))))

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

(defun network-names (&optional append-unroutable)
  "Core GetNetworkNames (netbase.cpp:130-142): the names of every publicly
routable network, in Network-enum order, with \"not_publicly_routable\"
appended when APPEND-UNROUTABLE. NET_INTERNAL is never named.

Core has ONE such function and two callers that have to agree: getaddrmaninfo
enumerates the networks it reports counts for (rpc/net.cpp:1103), and
getpeerinfo's help renders the list into the `network' field's own
description (:137). Keeping one list here is what makes rpc_net.py:131 --
which greps that help for the parenthesised list -- a check on the node
rather than on a comment."
  (append '("ipv4" "ipv6" "onion" "i2p" "cjdns")
          (when append-unroutable '("not_publicly_routable"))))

(defun %getpeerinfo-network-help ()
  "getpeerinfo's `network' result line, built the way Core builds it:

    {RPCResult::Type::STR, \"network\",
     \"Network (\" + Join(GetNetworkNames(/*append_unroutable=*/true), \", \")
     + \")\"}                                          (rpc/net.cpp:137)

rpc_net.py:131 asserts the parenthesised list appears in
help(\"getpeerinfo\") -- Core's own way of catching a node whose documented
networks have drifted from the ones it reports."
  (format nil "Result:~%  \"network\" : \"str\",    (string) Network (~{~A~^, ~})"
          (network-names t)))

(register-rpc-help-detail "getpeerinfo" #'%getpeerinfo-network-help)

(defun %getnetworkinfo-network-help ()
  "getnetworkinfo's per-network `name' result line, built the way Core builds
it:

    {RPCResult::Type::STR, \"name\",
     \"network (\" + Join(GetNetworkNames(), \", \") + \")\"}  (rpc/net.cpp:735)

The SECOND caller of GetNetworkNames that has to agree with the list itself --
without append_unroutable here, because getnetworkinfo reports one object per
routable network and never a `not_publicly_routable' one. rpc_net.py:243
asserts the parenthesised list appears in help(\"getnetworkinfo\")."
  (format nil "Result:~%  \"networks\" : [~%    { \"name\" : \"str\",    (string) network (~{~A~^, ~}) }~%  ]"
          (network-names)))

(register-rpc-help-detail "getnetworkinfo" #'%getnetworkinfo-network-help)

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
  (let ((peers (sort (rpc-get-connected-peers node)
                     #'< :key #'bl.net:peer-id))
        (chain-state (rpc-get-chain-state node)))
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
              (tx-relay (bl.net:peer-tx-relay-state-p peer))
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
           ;;
           ;; These three, and minfeefilter below, are read off the Peer::TxRelay
           ;; object, which Core only creates in the VERSION handler; with none,
           ;; GetNodeStateStats fills in false / 0 / 0 / 0 rather than the peer's
           ;; own values (net_processing.cpp:1819-1829). Asking
           ;; PEER-TX-RELAY-P instead answered relaytxes true and
           ;; last_inv_sequence 1 for a peer that had sent nothing at all.
           ;; m_relay_txs itself: an fRelay=0 peer offered NODE_BLOOM has the
           ;; object but relays nothing until a filterload/filterclear.
           ("relaytxes" . ,(json-bool (and tx-relay (bl.net:peer-tx-relay-p peer))))
           ;; Mempool sequence snapshot of our last inv flush to this peer +
           ;; queued-but-unsent announcements (Core m_last_inv_sequence /
           ;; m_inv_to_send).
           ("last_inv_sequence" . ,(if tx-relay
                                       (bl.net:peer-last-inv-sequence peer)
                                       0))
           ("inv_to_send" . ,(if tx-relay
                                 (length (bl.net:peer-tx-inv-queue peer))
                                 0))
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
           ;; ping stats are in microseconds; report seconds. All
           ;; three are optional in Core: pingtime/minping only once a pong
           ;; arrived, pingwait only while a ping is outstanding.
           ,@(when (plusp ping)
               `(("pingtime" . ,(/ ping 1000000 1.0d0))))
           ,@(when (plusp minping)
               `(("minping" . ,(/ minping 1000000 1.0d0))))
           ;; Core GetNodeStateStats: the MOCKABLE clock less m_ping_start.
           ,@(when ping-nonce
               `(("pingwait" . ,(/ (- (bl.ser:get-time-micros)
                                      (bl.net:peer-last-ping-time peer))
                                   1000000 1.0d0))))
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
           ;; getpeerinfo "permissions", rpc/net.cpp). Core reports the stored
           ;; m_permission_flags, so this asks the same question the
           ;; enforcement sites ask (PEER-PERMISSIONS: direction, connection
           ;; type and onion-ness), or a peer is REPORTED holding a grant
           ;; nothing will honour.
           ("permissions"
            . ,(let ((names (bl.net:permission-flag-names
                             (bl.net:peer-permissions peer))))
                 (if names (coerce names 'vector) #())))
           ;; BIP133: the peer's advertised fee floor, sat/kvB -> BTC/kvB.
           ;; Core m_fee_filter_received, 0 with no Peer::TxRelay (:1827).
           ("minfeefilter" . ,(satoshi->btc
                               (if tx-relay (bl.net:peer-feefilter-rate peer) 0)))
           ("bytessent_per_msg" . ,(bl.net:snapshot-per-msg-table
                                    (bl.net:peer-sent-per-msg peer)))
           ("bytesrecv_per_msg" . ,(bl.net:snapshot-per-msg-table
                                    (bl.net:peer-recv-per-msg peer)))
           ;; Core ConnectionTypeAsString (node/connection_types.cpp:9-25).
           ("connection_type" . ,(bl.net:connection-type-string
                                  (bl.net:peer-conn-type peer)))
           ;; Core TransportTypeAsString: the BIP324 v2 session lives in
           ;; connection-transport (NIL = plaintext v1). A peer is published
           ;; at accept, so one still in the BIP324 exchange reports
           ;; "detecting", as V2Transport::GetInfo does (net.cpp:1586-1592).
           ("transport_protocol_type"
            . ,(cond ((and conn (bl.net:connection-v2-detecting conn)) "detecting")
                     (transport "v2")
                     (t "v1")))
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
  (let* (;; Live peers only, as getpeerinfo already lists: Core counts m_nodes
         ;; (GetNodeCount, net.cpp:3769-3781), and DisconnectNodes erases a
         ;; closed connection from m_nodes on the next socket round
         ;; (net.cpp:1909-1939). Ours keeps a :disconnected peer in node-peers
         ;; until the sync cycle reaps it, so the framework saw its test peers
         ;; gone from getpeerinfo while connections_out still counted them
         ;; (p2p_add_connections.py:73, 10 == 0 after disconnect_p2ps).
         (peers (rpc-get-connected-peers node))
         ;; THE service bits we advertise on the wire (peer.lisp local-services,
         ;; Core g_local_services) — the one composition; do not duplicate it
         ;; here. Names via the shared %service-names (Core GetServicesNames).
         (services (bl.net:local-services))
         (service-names (%service-names services))
         (in (count-if #'bl.net:peer-inbound peers))
         ;; The EFFECTIVE -minrelaytxfee (sat/kvB -> BTC/kvB); Core reports
         ;; ::minRelayTxFee.GetFeePerK(), not the compile-time default.
         (relayfee (satoshi->btc bl.mp:*min-relay-fee-rate*))
         ;; *incremental-relay-fee-rate* is sat/kvB -> BTC/kvB.
         (incfee (satoshi->btc bl.mp:*incremental-relay-fee-rate*)))
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
      ("networks" . ,(%networks-info))
      ("relayfee" . ,relayfee)
      ("incrementalfee" . ,incfee)
      ;; mapLocalHost, in its (address) order (rpc/net.cpp:721-733); an empty
      ;; map is Core's empty VARR -- [], not null (a bare NIL encodes as null).
      ("localaddresses" . ,(json-array (local-addresses-for-rpc)))
      ("warnings" . ,(bl.log:warnings-for-rpc)))))

(defun %proxy-string (proxy)
  "Core Proxy::ToString (netbase.h:223-229): a `unix:' proxy is its path as
given, with no port; an IP one host:port, an IPv6 host bracketed."
  (let ((host (bl.net:proxy-host proxy)))
    (cond ((bl.net:unix-socket-path-p host) host)
          ((find #\: host) (format nil "[~A]:~D" host (bl.net:proxy-port proxy)))
          (t (format nil "~A:~D" host (bl.net:proxy-port proxy))))))

(defun %networks-info ()
  "Core GetNetworksInfo (rpc/net.cpp:614-631): one entry per network a peer
can be on -- ipv4, ipv6, onion, i2p, cjdns, in Core's enum order -- with its
reachability and the proxy that reaches it: each IP network's own
(BL.NET:NETWORK-PROXY -- -proxy, or its `=<network>' form, init.cpp:1706-1757),
the onion proxy (-onion, or -proxy) for onion, and -i2psam for i2p. The list used to hold ONE entry named after the CHAIN, so
nothing reading it -- bitcoin-cli -getinfo's Proxies line, -netinfo's
counts table (bitcoin-cli.cpp:611-627) -- found a network in it."
  (loop for (network name) in '((:ipv4 "ipv4") (:ipv6 "ipv6") (:torv3 "onion")
                                (:i2p "i2p") (:cjdns "cjdns"))
        collect (let ((proxy (case network
                               ((:ipv4 :ipv6 :cjdns) (bl.net:network-proxy network))
                               (:torv3 bl.net:*onion-proxy*)))
                      (reachable (bl.net:reachable-network-p network)))
                  `(("name" . ,name)
                    ("limited" . ,(json-bool (not reachable)))
                    ("reachable" . ,(json-bool reachable))
                    ("proxy" . ,(cond (proxy (%proxy-string proxy))
                                      ((eq network :i2p) (or bl.net:*i2p-sam-proxy* ""))
                                      (t "")))
                    ("proxy_randomize_credentials"
                     . ,(json-bool (and proxy (bl.net:proxy-randomize-credentials proxy))))))))

(defun %local-address< (a b)
  "Core's CNetAddr operator< over two local-address records: network first,
in Core's Network enum order, then the address bytes (netaddress.h)."
  (flet ((rank (la)
           (or (position (bl.net:local-address-network la)
                         '(:ipv4 :ipv6 :torv3 :i2p :cjdns))
               9)))
    (let ((ra (rank a)) (rb (rank b))
          (ba (bl.net:local-address-bytes a)) (bb (bl.net:local-address-bytes b)))
      (if (/= ra rb)
          (< ra rb)
          (let ((m (mismatch ba bb)))
            (and m (< m (length ba)) (< m (length bb))
                 (< (aref ba m) (aref bb m))))))))

(defun local-addresses-for-rpc ()
  "getnetworkinfo's localaddresses: one {address, port, score} object per
mapLocalHost entry (rpc/net.cpp:721-733), in the std::map's key order."
  (mapcar (lambda (la)
            `(("address" . ,(bl.net:network-address-to-string
                             (bl.net:local-address-network la)
                             (bl.net:local-address-bytes la)))
              ("port" . ,(bl.net:local-address-port la))
              ("score" . ,(bl.net:local-address-score la))))
          (sort (bl.net:local-addresses) #'%local-address<)))

(define-rpc "getconnectioncount" (node params)
  "Return the number of connected peers.

Core answers connman.GetNodeCount(ConnectionDirection::Both) (rpc/net.cpp:79),
the size of m_nodes, and DisconnectNodes erases a closed connection from
m_nodes on the next socket round (net.cpp:1909-1939). Counting NODE-PEERS
instead reported a peer this node had already dropped for the rest of the sync
cycle -- p2p_nobloomfilter_messages.py:31 asserts 0 the moment its peer's
socket closes."
  (declare (ignore params))
  (length (rpc-get-connected-peers node)))

(define-rpc "ping" (node params)
  "Queue a ping to every connected peer (Bitcoin Core ping). The round-trip
result later surfaces in getpeerinfo's pingtime. Returns null. send-ping is a
no-op on a peer whose connection has dropped, and ignore-errors guards against a
peer disconnecting mid-send."
  (declare (ignore params))
  (dolist (peer (rpc-get-connected-peers node))
    (ignore-errors (bl.net:send-ping peer)))
  nil)

;;; --- Peer / address RPCs ---

(define-rpc "getnodeaddresses" (node params)
  "Return known peer addresses from the address book (Bitcoin Core
getnodeaddresses). PARAMS: ([count] [network]) — max addresses (default 1;
0 = all), and only addresses of NETWORK (ipv4, ipv6, onion, i2p, cjdns) when
given (rpc/net.cpp:947-955). A negative count and an unknown network are -8,
as in Core."
  (let* ((count (if (integerp (first params)) (first params) 1))
         (network-name (second params))
         (network (and (stringp network-name)
                       (cdr (assoc (string-downcase network-name)
                                   '(("ipv4" . :ipv4) ("ipv6" . :ipv6)
                                     ("onion" . :torv3) ("i2p" . :i2p)
                                     ("cjdns" . :cjdns))
                                   :test #'string=))))
         (book (bl:node-address-book node)))
    (when (minusp count)
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "Address count out of range"))
    (when (and (stringp network-name) (null network))
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message (format nil "Network not recognized: ~A" network-name)))
  (let (;; count=0 => all known addresses; count>0 => up to that many.
        (limited (and book (bl.net:address-book-get-addr
                            book :max count :pct 100 :network network))))
    ;; Core pushes a VARR: an empty address book is [], not null.
    (json-array
     (mapcar
      (lambda (pa)
        `(("time" . ,(bl.net:peer-address-last-seen pa))
          ("services" . ,(bl.net:peer-address-services pa))
          ("address" . ,(bl.net:peer-address-string pa))
          ("port" . ,(bl.net:peer-address-port pa))
          ("network" . ,(or (%addrman-network-name pa) "unroutable"))))
      limited)))))

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
        ;; Core enumerates the Network enum, skipping NET_UNROUTABLE and
        ;; NET_INTERNAL (rpc/net.cpp:1103) -- GetNetworkNames' own set.
        (networks (network-names)))
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

(defun %net-class-network-name (net bytes)
  "Core GetNetworkName(addr.GetNetClass()) (netbase.cpp:106-120 over
netaddress.cpp:674-690) for an address on NET with BYTES."
  (ecase (bl.net:address-net-class net bytes)
    (:unroutable "not_publicly_routable")
    (:ipv4 "ipv4") (:ipv6 "ipv6") (:torv3 "onion") (:i2p "i2p") (:cjdns "cjdns")))

(defun %addrman-entry-json (pa)
  "One getrawaddrman entry: Core AddrmanEntryToJSON (rpc/net.cpp:1120-1139),
fields in Core's order. The source is the address that relayed PA to us, which
is PA itself when it announced itself (a NIL source slot, as addpeeraddress
records it: rpc/net.cpp's Add({address}, address)). mapped_as and
source_mapped_as appear only when -asmap maps the address, as in Core."
  (let* ((net (bl.net:peer-address-network pa))
         (ip (bl.net:peer-address-ip pa))
         (source (bl.net:peer-address-source pa))
         (source-net (if source (car source) net))
         (source-ip (if source (cdr source) ip))
         (mapped-as (bl.net:asmap-asn ip net))
         (source-mapped-as (bl.net:asmap-asn source-ip source-net)))
    `(("address" . ,(bl.net:network-address-to-string net ip))
      ,@(when mapped-as `(("mapped_as" . ,mapped-as)))
      ("port" . ,(bl.net:peer-address-port pa))
      ("services" . ,(bl.net:peer-address-services pa))
      ("time" . ,(bl.net:peer-address-last-seen pa))
      ("network" . ,(%net-class-network-name net ip))
      ("source" . ,(bl.net:network-address-to-string source-net source-ip))
      ("source_network" . ,(%net-class-network-name source-net source-ip))
      ,@(when source-mapped-as `(("source_mapped_as" . ,source-mapped-as))))))

(defun %addrman-table-json (book from-tried)
  "Core AddrmanTableToJSON (rpc/net.cpp:1141-1155): an object keyed
\"<bucket>/<position>\" over GetEntries' walk. An empty table is {}."
  (json-object
   (when book
     (mapcar (lambda (entry)
               (destructuring-bind (bucket position pa) entry
                 (cons (format nil "~D/~D" bucket position)
                       (%addrman-entry-json pa))))
             (bl.net:address-book-entries book from-tried)))))

(define-rpc "getrawaddrman" (node params)
  "Every address-manager entry of the new and tried tables, keyed by its
bucket/position (Core getrawaddrman, rpc/net.cpp:1157-1195). Hidden, like
Core's: it exists for tests (rpc_net.py:470, feature_asmap.py:118)."
  (declare (ignore params))
  (let ((book (bl:node-address-book node)))
    `(("new" . ,(%addrman-table-json book nil))
      ("tried" . ,(%addrman-table-json book t)))))

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
           (conn-type (cdr (assoc trimmed %addconnection-types :test #'string=)))
           (done (list nil)))          ; set by the sync thread once dialed
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
        ;; The transport travels with the request: Core's AddConnection
        ;; dials with exactly the v2transport the caller named
        ;; (rpc/net.cpp:405-417, net.cpp:1905), which is how
        ;; p2p_v2_encrypted.py:67 gets a v1 connection out of a v2 node.
        (push (list address conn-type (positional-bool v2transport) done)
              bl:*pending-test-connections*))
      ;; Core's AddConnection opens the connection before the RPC returns
      ;; (net.cpp:1871-1907): the new peer is in getpeerinfo at once, and
      ;; p2p_handshake.py:100-104 relies on it -- it waits for getpeerinfo
      ;; to EMPTY after asking a node to connect to itself, and only then
      ;; reads the log for "connected to self". So wait, bounded, for the
      ;; sync thread to have made the dial.
      (let ((sync (bl:node-sync-thread node)))
        (when (and sync (bt:thread-alive-p sync))
          (loop repeat 200
                until (car done)
                do (sleep 0.05))))
      `(("address" . ,address)
        ("connection_type" . ,trimmed)))))

(defun %numeric-endpoint (node spec)
  "Core LookupNumeric(SPEC, default port): (ip-bytes . port) when SPEC's host
is a numeric address, else NIL."
  (multiple-value-bind (host port) (bl:parse-node-endpoint node spec)
    (let ((ip (bl.net:numeric-host-ip-bytes host)))
      (and ip (cons ip port)))))

(defun %added-node-duplicate-p (node spec)
  "Whether SPEC names a node already on NODE's added-node list: the same
string, or -- when SPEC is numeric -- the same address and port however it is
spelled (Core CConnman::AddNode, net.cpp:3732-3744: \"127.1:18444\" is
\"127.0.0.1:18444\")."
  (let ((resolved (%numeric-endpoint node spec)))
    (some (lambda (added)
            (or (string= spec added)
                (and resolved
                     (equalp resolved (%numeric-endpoint node added)))))
          (bl:node-added-nodes node))))

(define-rpc "addnode" (node (spec command v2transport))
  "Manage manually-added peers (Bitcoin Core addnode). PARAMS:
(node command [v2transport]). COMMAND is \"add\" (remember the peer and keep it
connected), \"remove\", or \"onetry\" (dial once now). The actual dialing is
handed to the sync thread (via added-nodes / pending-onetry) so node-peers stays
single-writer. Returns null.

V2TRANSPORT defaults to whether this node speaks BIP324 and is refused when it
does not (rpc/net.cpp:349-354). A onetry dial carries it (net.cpp:359: the
functional framework's connect_nodes(peer_advertises_v2=...) asks for v1 or v2
this way); \"add\" entries keep dialing with the node's own setting."
  (unless (and (stringp spec) (plusp (length spec)))
    (error 'rpc-error :code +rpc-invalid-parameter+ :message "node must be a string"))
  ;; An unknown command is answered with the method's help document as a
  ;; plain runtime_error, i.e. -1 (Core rpc/net.cpp:339-342;
  ;; rpc_net.py:273 matches `addnode "node" "command"').
  (unless (member command '("add" "remove" "onetry") :test #'equal)
    (error 'rpc-error :code +rpc-misc-error+
                      :message (rpc-help-document "addnode")))
  (let ((use-v2 (positional-bool-or v2transport (bl.net:v2-available-p))))
    (when (and use-v2 (not (bl.net:v2-available-p)))
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "Error: v2transport requested but not enabled (see -v2transport)"))
  ;; onetry: Core opens the connection on the RPC thread before it returns
  ;; (rpc/net.cpp:356-361, OpenNetworkConnection), so the dial's own log
  ;; lines -- p2p_i2p_sessions.py:26 reads `Creating persistent I2P SAM
  ;; session' the moment the call returns -- are written by then. Wait,
  ;; bounded and OUTSIDE the node lock the dial needs, for the sync thread.
  (when (equal command "onetry")
    (let ((done (bl:queue-onetry-dial node spec use-v2))
          (sync (bl:node-sync-thread node)))
      (when (and sync (bt:thread-alive-p sync))
        (loop repeat 200 until (car done) do (sleep 0.05)))))
  (bt:with-recursive-lock-held ((bl:node-lock node))
    (cond
      ((equal command "add")
       (when (%added-node-duplicate-p node spec)
         (error 'rpc-error :code +rpc-client-node-already-added+
                           :message "Error: Node already added"))
       (setf (bl:node-added-nodes node)
             (append (bl:node-added-nodes node) (list spec))))
      ((equal command "remove")
       (unless (member spec (bl:node-added-nodes node) :test #'string=)
         (error 'rpc-error :code +rpc-client-node-not-added+
                           :message "Error: Node could not be removed. It has not been added previously."))
       (setf (bl:node-added-nodes node)
             (remove spec (bl:node-added-nodes node) :test #'string=))))))
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
rollback-time NetworkDisable. Returns STATE.

Core opens with LogInfo(\"%s: %s\\n\", __func__, active) (net.cpp:3356), before
the no-op early return, so the line appears on every call whether or not the
flag moves. rpc_net.py:218 and :225 wrap setnetworkactive in assert_debug_log
for exactly that line, in both directions."
  (bl:log-info "SetNetworkActive: ~:[false~;true~]" state)
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
                 ;; Core matches CNode::m_addr_name (net.cpp:3809-3820), which
                 ;; is the connection's "ip:port" -- the same string
                 ;; getpeerinfo reports as `addr', which is where a caller gets
                 ;; it from (p2p_disconnect_ban.py:131-133 reads
                 ;; getpeerinfo()[0]['addr'] and hands it straight back). Ours
                 ;; compared the bare HOST, so the address getpeerinfo had just
                 ;; printed was "not found in connected nodes".
                 ;;
                 ;; The bare host still matches: it is what this node's own web
                 ;; UI and RPC callers have always passed, and Core's
                 ;; m_addr_name for a peer dialled by name is whatever the
                 ;; operator wrote.
                 (find-if (lambda (p)
                            (or (string= address (%peer-addr p))
                                (string= address (bl.net:peer-address p))))
                          (bl:node-peers node)))
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
(address command [bantime] [absolute]). ADDRESS is an IP, a CIDR subnet, or an
onion/I2P address. COMMAND is \"add\" or \"remove\". For add,
BANTIME is seconds from now (default -bantime, 24h), or an absolute Unix time
when ABSOLUTE is true, and every connected peer the ban covers is
disconnected (Core net.cpp:799-808 -> CConnman::DisconnectNode). Error codes
mirror Core (net.cpp:766-812): a non-address (-30
RPC_CLIENT_INVALID_IP_OR_SUBNET), re-banning (-23), a failed unban (-30).

Core decides SUBNET-ness by the presence of a `/' and asks a different
question for each (net.cpp:770-786): an ADDRESS is already-banned when ANY
live range covers it, a SUBNET only when that exact range is on the list.
REMOVE is always the exact range. Returns null."
  (unless (and (stringp address) (plusp (length address)))
    (error 'rpc-error :code +rpc-invalid-parameter+ :message "address required"))
  ;; Core: unparseable IP/subnet -> RPC_CLIENT_INVALID_IP_OR_SUBNET (-30),
  ;; net.cpp:781. BAN-KEY accepts IPv4/IPv6 literals, CIDR subnets and
  ;; onion/i2p addresses; a hostname resolves to none of them.
  (unless (bl.net:ban-key address)
    (error 'rpc-error :code +rpc-client-invalid-ip-or-subnet+
                      :message "Error: Invalid IP/Subnet"))
  (cond
    ((equal command "add")
     ;; Core: already banned -> RPC_CLIENT_NODE_ALREADY_ADDED (-23),
     ;; net.cpp:786 -- IsBanned(CSubNet) for a `/' argument (exact), and
     ;; IsBanned(CNetAddr) for a bare one (any covering range).
     (when (if (find #\/ address)
               (bl.net:subnet-exactly-banned-p address)
               (bl.net:peer-banned-p address))
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
     ;; Core's DisconnectNode takes the CSubNet or the CNetAddr it just
     ;; banned and drops every node it covers (net.cpp:799-808), so a /24 ban
     ;; disconnects the whole range rather than one exact string match.
     (bt:with-recursive-lock-held ((bl:node-lock node))
       (dolist (peer (bl:node-peers node))
         (when (bl.net:peer-banned-p (bl.net:peer-address peer))
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
  (let ((now (bl.ser:get-unix-time)))
    (json-array
     (mapcar (lambda (ban)
               ;; Core's five fields, in Core's order (rpc/net.cpp:854-858).
               ;; BAN_DURATION and TIME_REMAINING are derived, not stored --
               ;; rpc_setban.py:75 restarts with -bantime=1234 and reads the
               ;; duration back, which needs the CREATION time Core's CBanEntry
               ;; keeps and ours had been writing as a hardcoded 0.
               (let* ((entry (cdr ban))
                      (created (- (bl.net:ban-entry-created entry)
                                  bl.ser:+universal-unix-epoch-offset+))
                      (until (- (bl.net:ban-entry-until entry)
                                bl.ser:+universal-unix-epoch-offset+)))
                 `(("address" . ,(car ban))
                   ("ban_created" . ,created)
                   ("banned_until" . ,until)
                   ("ban_duration" . ,(- until created))
                   ("time_remaining" . ,(- until now)))))
             (bl.net:list-bans)))))

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
  ;; An EMPTY string is still a string: Core's LookupHost fails on it and the
  ;; answer is -30 "Invalid IP address" (rpc/net.cpp:1002-1005), below.
  (unless (stringp address)
    (error 'rpc-error :code +rpc-type-error+ :message "Expected type string for address"))
  (unless (numberp port)
    (error 'rpc-error :code +rpc-type-error+ :message "Expected type number for port"))
  ;; Core reads the port as getInt<uint16_t> (rpc/net.cpp:998); a number that
  ;; is no uint16 throws "JSON integer out of range" (univalue.h:139-149),
  ;; which the server reports as -1 (rpc_net.py:361-362).
  (unless (typep port '(unsigned-byte 16))
    (error 'rpc-error :code +rpc-misc-error+ :message "JSON integer out of range"))
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
          ;; Core pushes the reason for either refusal (rpc/net.cpp:1014-1025).
          ((not added) `(("success" . ,(json-bool nil))
                         ("error" . "failed-adding-to-new")))
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
