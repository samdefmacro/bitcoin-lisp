(in-package #:bitcoin-lisp.networking)

;;; Bitcoin P2P Protocol Handling
;;;
;;; Higher-level protocol operations for syncing and message handling.

(defmacro with-current-node-lock (&body body)
  "Execute BODY while holding the node lock for thread-safe state access.
Guards shared state (chain-state, UTXO set, mempool, peer list) against
concurrent access from RPC and sync threads. The node is read from
bl:*node* into a private binding: BODY's own NODE variables are untouched
(the first version bound the literal name NODE around BODY). RPC handlers,
which always hold a node, use bl.rpc:with-node-lock (node) instead."
  (let ((node (gensym "NODE")))
    `(let ((,node bl:*node*))
       (if (and ,node (bl:node-lock ,node))
           (bt:with-recursive-lock-held ((bl:node-lock ,node))
             ,@body)
           (progn ,@body)))))

(defun block-interval-seconds ()
  "Core consensusParams.nPowTargetSpacing -- the target seconds between blocks
-- for the chain the node runs, read from the chain parameters in the util
layer (BL.CHAIN:CHAIN-POW-TARGET-SPACING, kernel/chainparams.cpp:98). It used
to name BL:+POW-TARGET-SPACING-SECONDS+, which the node layer defines ABOVE
this one, so a fresh build compiled it as an undefined variable."
  (bl.chain:chain-pow-target-spacing bl:*network*))

(defstruct peer-manager
  "Manages connections to multiple peers."
  (peers '() :type list)
  (max-peers 8 :type (unsigned-byte 8))
  (known-addresses '() :type list))

;;; Peer discovery

(defun resolve-dns-seed (hostname)
  "Resolve a DNS seed to a list of IP addresses."
  (handler-case
      #+sbcl
      (let ((addresses (sb-bsd-sockets:host-ent-addresses
                        (sb-bsd-sockets:get-host-by-name hostname))))
        (mapcar (lambda (addr)
                  (format nil "~{~D~^.~}" (coerce addr 'list)))
                addresses))
      #-sbcl
      nil
    (error () nil)))

(defun ip-netgroup (addr)
  "Return a netgroup string key for an address string, NIL for hostnames.
IPv4 dotted-quad: the /16 prefix (e.g. \"103.165\") — mirrors Bitcoin
Core's CNetAddr::GetGroup() for routable IPv4: groups addresses by the
first two octets so peer selection prefers connections from distinct
operators / netgroups. Without this, DNS seeds that dump many IPs from
one /24 (e.g. wiz.biz's testnet4 nodes at 103.165.192.x) cause an
8-of-8 single-operator peer set, which becomes a single point of stall.
Other networks (IPv6, .onion, .b32.i2p, CJDNS) render the byte-level
net-group-key (Core netgroup.cpp grouping) as an opaque string key —
only equality between keys matters to the callers."
  (let ((dots 0)
        (end nil))
    (dotimes (i (length addr))
      (when (char= (char addr i) #\.)
        (incf dots)
        (when (= dots 2)
          (setf end i)
          (return))))
    (if (and end (every (lambda (c) (or (digit-char-p c) (char= c #\.)))
                        (subseq addr 0 end)))
        (subseq addr 0 end)
        ;; Non-dotted-quad: parse to a typed address and use its byte-level
        ;; group; hostnames (unparseable) return NIL as before.
        (multiple-value-bind (net bytes) (parse-network-address addr)
          (when net
            (format nil "~{~D~^.~}"
                    (coerce (net-group-key bytes net) 'list)))))))

(defun diversify-by-netgroup (addresses &key (key #'identity))
  "Reorder ADDRESSES so consecutive entries come from distinct /16
netgroups when possible. Round-robins across groups: caller (which
connects to the first N entries) gets the broadest spread for free
without needing per-group caps. Stable within each group so the DNS-
returned ordering acts as the within-group tiebreaker. KEY extracts the
address string from an entry (connect-to-peers passes (host . port)
dial candidates with :key #'car)."
  (let ((groups (make-hash-table :test 'equal))
        (group-keys '()))
    ;; Bucket by group, preserve within-group order.
    (dolist (addr addresses)
      (let ((g (or (ip-netgroup (funcall key addr)) "_nogroup")))
        (unless (gethash g groups)
          (push g group-keys))
        (setf (gethash g groups) (nconc (gethash g groups) (list addr)))))
    (setf group-keys (nreverse group-keys))
    ;; Round-robin pull from each group until all are drained.
    (let ((result '()))
      (loop while group-keys do
            (let ((next-keys '()))
              (dolist (g group-keys)
                (let ((bucket (gethash g groups)))
                  (when bucket
                    (push (first bucket) result)
                    (setf (gethash g groups) (rest bucket))
                    (when (rest bucket)
                      (push g next-keys)))))
              (setf group-keys (nreverse next-keys))))
      (nreverse result))))

(defun discover-peers (&optional (seeds *dns-seeds*))
  "Discover peers from DNS seeds.
Returns a list of IP address strings, ordered so the first N entries
span as many distinct /16 netgroups as possible (see diversify-by-
netgroup). The caller iterates this list and connects to the first
peers that succeed; round-robin ordering prevents a single operator's
DNS-clustered nodes from monopolizing our 8-peer outbound budget.

When a SOCKS5 proxy is configured (*proxy*), seeds are NOT resolved locally
— that would leak DNS queries outside the tunnel. Instead each seed HOSTNAME
is returned as a dial target itself: make-tcp-connection passes it through
the proxy in the SOCKS5 CONNECT (ATYP DOMAINNAME), and the proxy resolves it.
Mirrors Bitcoin Core's proxy-mode seed handling, where seeds become one-shot
AddAddrFetch peer dials instead of getaddrinfo lookups (net.cpp:2353-2358)."
  (if *proxy*
      (copy-list seeds)
      (let ((addresses '()))
        (dolist (seed seeds)
          ;; `Loading addresses from DNS seed' is the caller's line: the DNS
          ;; seed thread writes it per seed before this lookup, as Core does
          ;; (net.cpp:2353), under a name proxy too.
          (let ((resolved (resolve-dns-seed seed)))
            (when resolved
              (setf addresses (nconc addresses resolved)))))
        (diversify-by-netgroup
         (remove-duplicates addresses :test #'string=)))))

;;; Message handling

(defun handle-message (peer command payload ctx)
  "Handle an incoming message from a peer: the DEFINE-P2P-HANDLER row for
COMMAND, after the per-peer rate limit. CTX is the node-context; a NIL slot
disables the path that needs it: no mempool or peers, no transaction relay;
no address-book, no peer
database updates from addr messages; no recent-rejects, no reject cache.
Returns T if the message was handled, NIL for a command this node does not
know or a peer that exceeded its rate limit (and was disconnected)."
  (bl.ctx:with-node-context (mempool) ctx
    ;; Core logs EVERY inbound message here, before dispatch
    ;; (net_processing.cpp:3582). It is not a debugging nicety: several functional
    ;; tests assert on the exact line -- p2p_addr_relay.py waits for
    ;; "received: addr (301 bytes) peer=1" to know the message was taken in at all,
    ;; because the observable effect it is really testing (relay to two peers)
    ;; happens later and asynchronously.
    ;;
    ;; The BYTE COUNT is the payload's, not the framed message's, matching
    ;; vRecv.size() at that point.
    ;; SANITIZED FOR THE LOG ONLY: the 12-byte command field is peer-controlled
    ;; bytes, newline included, and Core wraps every log line that prints a
    ;; message type in SanitizeString (net_processing.cpp:3582 and the others).
    ;; DISPATCH below must keep using the RAW command -- sanitizing drops
    ;; characters rather than escaping them, so "bl<LF>ock" would sanitize to
    ;; "block" and a forged command name would reach a real handler.
    (log-received-message peer command payload)
    ;; No per-command message count is checked here: Core disconnects a peer
    ;; for how many messages of a kind it sends for none of them
    ;; (net_processing.cpp ProcessMessage). Its bounds are per message, in the
    ;; handlers -- MAX_INV_SZ, MAX_HEADERS_RESULTS, MAX_ADDR_TO_SEND,
    ;; MAX_LOCATOR_SZ, the addr token bucket that drops excess addresses --
    ;; and the send-buffer pause that bounds what serving a request costs.
    (let ((handler (p2p-handler-for command)))
      (cond ((null handler) nil)          ; Unknown message
            ;; Acknowledged but not processed: the message needs a mempool
            ;; and this context has none (a header-only or IBD pump).
            ((and (p2p-handler-needs-mempool handler) (null mempool)) t)
            (t (funcall (p2p-handler-function handler) peer payload ctx)
               t)))))

;;; The messages whose whole handling fits in a table row. The larger
;;; handlers below are DEFINE-P2P-HANDLER forms of their own.

(define-p2p-handler "ping" (peer payload ctx)
  "BIP31: answer with the same nonce."
  (declare (ignore ctx))
  (let ((nonce (bl.bytes:with-byte-reader (s payload)
                 (bl.bytes:br-read-u64-le s))))
    (bl:log-debug "ping from ~A: ~D payload bytes, nonce ~D"
                  (peer-log-name peer)
                  (length payload) nonce)
    (reply-to-ping peer nonce)))

(define-p2p-handler "pong" (peer payload ctx)
  "Close the round trip our last ping opened: Core's PONG handler
(net_processing.cpp:4990-5049), problem by problem. A pong too short to hold
the nonce is `Short payload' and cancels the outstanding ping; with no ping
outstanding it is `Unsolicited pong without ping'; a different nonce is
`Nonce mismatch' and leaves the ping outstanding (pings overlap), except a
zero one, `Nonce zero', which cancels it. Each problem is one debug line,
`pong peer=<id>: <problem>, <sent> expected, <received> received, <n> bytes'
in hex, which p2p_ping.py:60-83 waits for; the peer is kept. Ours cancelled
the ping on any nonce and named only the short payload."
  (declare (ignore ctx))
  (let ((avail (length payload))
        (sent (or (peer-ping-nonce peer) 0))
        (nonce 0)
        (finished nil)
        (problem nil))
    (cond ((< avail 8)
           (setf finished t problem "Short payload"))
          (t
           (setf nonce (bl.bytes:with-byte-reader (s payload) (bl.bytes:br-read-u64-le s)))
           (cond ((zerop sent) (setf problem "Unsolicited pong without ping"))
                 ((= nonce sent)
                  (setf finished t)
                  (unless (record-pong peer nonce)
                    (setf problem "Timing mishap")))
                 ((zerop nonce) (setf finished t problem "Nonce zero"))
                 (t (setf problem "Nonce mismatch")))))
    (when problem
      (bl:log-cat "net" "pong peer=~A: ~A, ~(~X~) expected, ~(~X~) received, ~D bytes"
                  (peer-id peer) problem sent nonce avail))
    (when finished
      (setf (peer-ping-nonce peer) nil))))

(define-p2p-handler "mempool" (peer payload ctx)
  "BIP35 (Core net_processing.cpp:4939-4966): honoured only when we offer the
peer NODE_BLOOM or it holds the \"mempool\" permission, and -- unless it holds
that permission -- only while -maxuploadtarget is not spent. Either refusal
disconnects, except a noban peer, which is kept. The answer is the pool
filtered by the peer's feefilter and bloom filter (HANDLE-MEMPOOL-REQUEST)."
  (cond
    ((not (or (peer-offers-bloom-p peer) (peer-has-permission-p peer +perm-mempool+)))
     (unless (peer-has-permission-p peer +perm-noban+)
       (bl:log-cat "net" "mempool request with bloom filters disabled, ~A"
                   (disconnect-msg peer))
       (disconnect-peer peer)))
    ((and (outbound-target-reached-p nil)
          (not (peer-has-permission-p peer +perm-mempool+)))
     (unless (peer-has-permission-p peer +perm-noban+)
       (bl:log-cat "net" "mempool request with bandwidth limit reached, ~A"
                   (disconnect-msg peer))
       (disconnect-peer peer)))
    (t (handle-mempool-request peer payload ctx))))

(defun %refuse-bloom-filter-message (peer command)
  "Drop PEER for a BIP37 filter message when we do not offer it NODE_BLOOM
(Core net_processing.cpp:5051-5056, :5076-5081, :5104-5109), with Core's line
and CNode::DisconnectMsg; p2p_nobloomfilter_messages.py sends each of the
three and waits for the connection to close. Returns T when it refused."
  (unless (peer-offers-bloom-p peer)
    (bl:log-cat "net" "~A received despite not offering bloom services, ~A"
                command (disconnect-msg peer))
    (disconnect-peer peer)
    t))

(define-p2p-handler "filterload" (peer payload ctx)
  "BIP37 filterload (Core net_processing.cpp:5051-5074): a filter over the
size limits is Misbehaving (`too-large bloom filter'); otherwise it replaces
the peer's filter and turns tx relay on, for a tx-relay peer."
  (declare (ignore ctx))
  (unless (%refuse-bloom-filter-message peer "filterload")
    (let ((filter (parse-bloom-filter payload)))
      (cond ((not (bloom-within-size-constraints-p filter))
             (record-misbehavior peer "too-large bloom filter"))
            ((peer-tx-relay-state-p peer)
             (setf (peer-bloom-filter peer) filter
                   (peer-bloom-relay-txs peer) t))))))

(define-p2p-handler "filteradd" (peer payload ctx)
  "BIP37 filteradd (Core net_processing.cpp:5076-5102): an element over
MAX_SCRIPT_ELEMENT_SIZE, or one sent with no filter loaded, is Misbehaving
(`bad filteradd message'); otherwise it is inserted into the filter."
  (declare (ignore ctx))
  (unless (%refuse-bloom-filter-message peer "filteradd")
    (let* ((data (bl.bytes:with-byte-reader (s payload)
                   (bl.bytes:br-read-bytes s (bl.bytes:br-read-compact-size s))))
           (bad (cond ((> (length data) +max-script-element-size+) t)
                      ((not (peer-tx-relay-state-p peer)) nil)
                      ((peer-bloom-filter peer)
                       (bloom-insert (peer-bloom-filter peer) data)
                       nil)
                      (t t))))
      (when bad
        (record-misbehavior peer "bad filteradd message")))))

(define-p2p-handler "filterclear" (peer payload ctx)
  "BIP37 filterclear (Core net_processing.cpp:5104-5120): drop the filter and
turn tx relay on."
  (declare (ignore payload ctx))
  (unless (%refuse-bloom-filter-message peer "filterclear")
    (when (peer-tx-relay-state-p peer)
      (setf (peer-bloom-filter peer) nil
            (peer-bloom-relay-txs peer) t))))

(define-p2p-handler "version" (peer payload ctx)
  "A second version, after the handshake already took the first. Core ignores
it with this line (net_processing.cpp:3585-3589) -- `redundant version message
from peer=N' -- and p2p_invalid_messages.py:105-106 greps the log for it. The
handshake's own version never reaches this table (%AWAIT-VERACK reads it)."
  (declare (ignore payload ctx))
  (bl:log-cat "net" "redundant version message from peer=~A" (peer-id peer)))

(define-p2p-handler "verack" (peer payload ctx)
  "A second verack, after the handshake already completed. Core ignores it
with this exact line rather than disconnecting (net_processing.cpp:3822)
-- and p2p_handshake.py greps the log for it, so the wording is part of
the behaviour, not decoration."
  (declare (ignore payload ctx))
  (bl:log-cat "net" "ignoring redundant verack message from peer=~A"
              (peer-id peer)))

(defun %disconnect-after-verack (peer command)
  "Drop PEER for sending the feature-negotiation message COMMAND after VERACK.
BIP155 (sendaddrv2), BIP339 (wtxidrelay) and BIP330 (sendtxrcncl) all place
their negotiation strictly between VERSION and VERACK: switching announcement
protocol on a live connection is the relay problem the window exists to
prevent, and Core enforces it by dropping the connection from each of the
three handlers (net_processing.cpp:3928-3933, :3950-3955, :3969-3973).
HANDLE-MESSAGE is only ever reached post-handshake -- the window itself is
%await-verack, which handles these three inline -- so arriving here IS the
violation and no state check is needed.

The line is Core's own, CNode::DisconnectMsg with fLogIPs off
(net.cpp:709-713); p2p_addrv2_relay.py:81 greps for it verbatim and
p2p_sendtxrcncl.py:217 for its prefix, so the wording is behaviour."
  (bl:log-cat "net" "~A received after verack, disconnecting peer=~A"
              command (peer-id peer))
  (disconnect-peer peer))

(define-p2p-handler "sendaddrv2" (peer payload ctx)
  "BIP 155: post-verack, so the negotiation window is over -- disconnect."
  (declare (ignore payload ctx))
  (%disconnect-after-verack peer "sendaddrv2"))

(define-p2p-handler "wtxidrelay" (peer payload ctx)
  "BIP 339: post-verack, so the negotiation window is over -- disconnect."
  (declare (ignore payload ctx))
  (%disconnect-after-verack peer "wtxidrelay"))

(define-p2p-handler "sendtxrcncl" (peer payload ctx)
  "BIP 330: as sendaddrv2/wtxidrelay above, except that Core reaches the
post-verack check only with txreconciliation enabled -- with the flag off
the message is ignored outright, and says so (net_processing.cpp:3964-3967)."
  (declare (ignore payload ctx))
  (if bl:*tx-reconciliation*
      (%disconnect-after-verack peer "sendtxrcncl")
      (%log-sendtxrcncl-ignored peer)))

;;; BIP-330 reconciliation. None of these messages exists in Core d3056bc
;;; (protocol.h:266 ends at sendtxrcncl), so each is answered only from a
;;; peer that completed the sendtxrcncl handshake -- impossible without
;;; -txreconciliation -- and only in the role BIP-330 gives it: `After both
;;; peers have confirmed support by sending "sendtxrcncl", the initiator of the
;;; P2P connection assumes the role of reconciliation initiator (will send
;;; "reqrecon" messages) and the other peer assumes the role of reconciliation
;;; responder.' A message from the wrong side, or from a peer that never
;;; registered, is ignored: with the flag off they are inert rather than errors.

(defun %recon-message-allowed-p (peer command from-initiator-p)
  "T when PEER may send COMMAND: it registered for reconciliation, and it
holds the role the message belongs to -- FROM-INITIATOR-P for reqrecon,
reqsketchext and reconcildiff, which only the initiator sends, NIL for
sketch, which only the responder does. Logs the refusal of a registered
peer in the wrong role."
  (cond ((not (peer-recon-registered peer)) nil)
        ;; The peer is the initiator exactly when WE are not.
        ((eq from-initiator-p (not (peer-recon-we-initiate peer))) t)
        (t (bl:log-cat "txreconciliation"
                       "~A from peer=~A ignored: that is the ~:[responder~;initiator~]'s message"
                       command (peer-id peer) from-initiator-p)
           nil)))

(define-p2p-handler "reqrecon" (peer payload ctx)
  "The initiator opens a reconciliation round: answer with a sketch."
  (declare (ignore ctx))
  (when (%recon-message-allowed-p peer "reqrecon" t)
    (%handle-reqrecon peer payload)))

(define-p2p-handler "sketch" (peer payload ctx)
  "The responder's sketch: decode, or ask for an extension."
  (when (%recon-message-allowed-p peer "sketch" nil)
    (%handle-sketch peer payload (and ctx (bl.ctx:node-context-mempool ctx)))))

(define-p2p-handler "reqsketchext" (peer payload ctx)
  "The initiator could not decode: send the sketch extension."
  (declare (ignore payload ctx))
  (when (%recon-message-allowed-p peer "reqsketchext" t)
    (%handle-reqsketchext peer)))

(define-p2p-handler "reconcildiff" (peer payload ctx)
  "The initiator's verdict: announce what it asked for, or everything on failure."
  (when (%recon-message-allowed-p peer "reconcildiff" t)
    (%handle-reconcildiff peer payload (and ctx (bl.ctx:node-context-mempool ctx)))))

(define-p2p-handler "sendheaders" (peer payload ctx)
  "BIP 130: Peer prefers header announcements over inv."
  (declare (ignore payload ctx))
  (setf (peer-prefers-headers peer) t))

(define-p2p-handler "feefilter" (peer payload ctx)
  "BIP 133: the peer's minimum fee rate for tx relay. Core applies it
only when MoneyRange (net_processing.cpp:5126); a rate above
MAX_MONEY would otherwise silently suppress all relay to this peer."
  (declare (ignore ctx))
  (let ((rate (bl.ser:parse-feefilter-payload payload)))
    (when (<= rate bl.val:+max-money+)
      (setf (peer-feefilter-rate peer) rate))))

;;; Inventory handling

(defun block-inv-type-p (inv-type)
  "T if INV-TYPE is a block inventory type (plain or witness, BIP 144)."
  (or (= inv-type bl.ser:+inv-type-block+)
      (= inv-type bl.ser:+inv-type-witness-block+)))

(defun tx-inv-type-p (inv-type)
  "T if INV-TYPE is a transaction inventory type — Core CInv::IsGenTxMsg:
MSG_TX and MSG_WITNESS_TX carry a txid, MSG_WTX (BIP339) a wtxid."
  (or (= inv-type bl.ser:+inv-type-tx+)
      (= inv-type bl.ser:+inv-type-witness-tx+)
      (= inv-type bl.ser:+inv-type-wtx+)))

(defun %peer-inv-hash (peer txid wtxid)
  "The id PEER's transaction inventory uses: the wtxid once it negotiated
wtxidrelay, the txid otherwise (Core's `peer.m_wtxid_relay ? wtxid : txid`,
net_processing.cpp:4491-4492). Falls back to the txid when no wtxid is known.

This is also the key of PEER-ANNOUNCED-TXS at EVERY site. Core says so in a
comment at net_processing.cpp:6060-6063 -- the filter \"contains either txids
or wtxids depending on whether our peer supports wtxid-relay\", so a reader
constructs the inv (or this hash) first and looks the filter up by it. A site
that keys it by txid while the peer announces wtxids writes into a filter
nobody reads."
  (if (and (peer-wtxid-relay peer) wtxid) wtxid txid))

(defun %peer-tx-inv (peer txid wtxid)
  "The inv entry announcing this transaction to PEER: MSG_WTX carrying the
wtxid for a wtxidrelay peer, MSG_TX carrying the txid otherwise (BIP339, Core
net_processing.cpp:6064-6066). Its hash is %PEER-INV-HASH."
  (let ((wtxp (and (peer-wtxid-relay peer) wtxid t)))
    (bl.ser:make-inv-vector
     :type (if wtxp bl.ser:+inv-type-wtx+ bl.ser:+inv-type-tx+)
     :hash (%peer-inv-hash peer txid wtxid))))

;;; --- Transaction download: the drive sites of Core's m_txdownloadman ---
;;;
;;; The TxDownloadManager (txdownloadman.lisp) decides; these functions are
;;; net_processing.cpp's side of each decision -- what goes on the wire, what
;;; is validated, what is relayed -- and they call the manager exactly where
;;; Core calls m_txdownloadman.

(defconstant +max-blocks-in-transit-per-peer+ 16
  "Core MAX_BLOCKS_IN_TRANSIT_PER_PEER (net_processing.cpp:130). Read here
only for the notfound size guard: a peer cannot have more than its
MAX_PEER_TX_ANNOUNCEMENTS plus this many requests outstanding, so a notfound
that names more items than that is answering nothing we asked for
(net_processing.cpp:5150-5164).")
(defconstant +max-cmpctblocks-inflight-per-block+ 3
  "Core MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK (net_processing.h:48): how many
peers may hold one block in flight at once, each on its own compact-block
getblocktxn round trip. The last slot is kept for an outbound peer
(:4707-4712).")
(defconstant +max-getdata-size+ 1000
  "Core MAX_GETDATA_SZ (net_processing.cpp:127): a getdata SendMessages builds
is sent and a new one begun at this many entries (:6207-6211).")

(bl.vi:define-validation-hook :block-connected txdownload-note-block-connected
    (chainstate block block-hash height spent-utxos)
  "Core PeerManagerImpl::BlockConnected's tx-download call
(net_processing.cpp:2086-2092): m_txdownloadman.BlockConnected(pblock), only
for the active chainstate and only OUTSIDE initial block download, reading the
latched IsInitialBlockDownload -- *CACHED-IS-IBD* here. The recently-confirmed
filter used to be filled during IBD too, which made a transaction confirmed
then unrequestable once the node was out: p2p_ibd_txrelay.py:93-96 announces
the coinbase of a block mined in IBD and waits for the getdata. An assumeutxo
TARGETED chainstate re-derives ancient history; its blocks would otherwise
release announcements of transactions that are still unconfirmed for us."
  (declare (ignore block-hash height spent-utxos))
  (unless (or *cached-is-ibd*
              (bl.store:chain-state-target-blockhash chainstate))
    (txdownload-block-connected (node-txdownloadman) block)))

(bl.vi:define-validation-hook :block-disconnected txdownload-note-block-disconnected
    (chainstate block block-hash height)
  "Core PeerManagerImpl::BlockDisconnected (net_processing.cpp:2095-2099):
m_txdownloadman.BlockDisconnected(), so transactions a reorg returns to
circulation are not held back by the recently-confirmed filter. Validation
announces disconnects after a reorg commits; a TARGETED chainstate's are
history being re-derived, not transactions leaving the node's chain, and Core
disconnects only on the active one."
  (declare (ignore block block-hash height))
  (unless (bl.store:chain-state-target-blockhash chainstate)
    (txdownload-block-disconnected (node-txdownloadman))))

(bl.vi:define-validation-hook :active-tip-change txdownload-note-active-tip-change
    (chainstate)
  "Core PeerManagerImpl::ActiveTipChange (net_processing.cpp:2045-2059):
outside initial block download, every rejection may be stale at the new tip --
a timelock, a fee floor -- so m_txdownloadman.ActiveTipChange() resets both
rejection filters. Validation announces it for the active chainstate after
every activation step and every reorg, as Core's ActivateBestChain and
InvalidateBlock do (validation.cpp:3472-3475, :3722-3726)."
  (unless (initial-block-download-p chainstate)
    (txdownload-active-tip-change (node-txdownloadman))))

(defun tx-fetch-inv-type (peer)
  "Inv type for a TXID-based tx getdata to PEER: MSG_TX|MSG_WITNESS_FLAG when
the peer can serve witnesses, bare MSG_TX otherwise — Core's GetFetchFlags
(net_processing.cpp:2591-2598, CanServeWitnesses = NODE_WITNESS in the peer's
services). Requesting a segwit tx with bare MSG_TX returns the
witness-stripped serialization, which can never pass script validation.
wtxid-based requests never use this: they are always MSG_WTX."
  (if (logtest (peer-services peer) bl.ser:+node-witness+)
      bl.ser:+inv-type-witness-tx+
      bl.ser:+inv-type-tx+))

(defun tx-request-inv (hash wtxidp peer)
  "The inv-vector for requesting tracked tx HASH from PEER: MSG_WTX for a
wtxid-based entry, MSG_TX|witness-flag for a txid-based one — Core's
\"gtxid.IsWtxid() ? MSG_WTX : (MSG_TX | GetFetchFlags(peer))\"
(net_processing.cpp:6207)."
  (bl.ser:make-inv-vector
   :type (if wtxidp
             bl.ser:+inv-type-wtx+
             (tx-fetch-inv-type peer))
   :hash hash))

(defun send-tx-requests (peer mgr &optional (now (%tx-request-now)))
  "SendMessages' transaction getdata section (net_processing.cpp:6201-6217):
ask PEER for what MGR's GetRequestsToSend hands it at NOW, MAX_GETDATA_SZ
entries per message, each under the id type of the announcement it was granted
to. Returns the number of transactions requested."
  (let* ((invs (mapcar (lambda (gtxid) (tx-request-inv (car gtxid) (cdr gtxid) peer))
                       (txdownload-get-requests-to-send mgr peer now)))
         (sent (length invs)))
    (loop while invs
          do (let ((batch (subseq invs 0 (min +max-getdata-size+ (length invs)))))
               (setf invs (nthcdr (length batch) invs))
               (handler-case (send-message peer (bl.ser:make-getdata-message batch))
                 (error () nil))))
    sent))

;;; Initial-block-download status (Core ChainstateManager::IsInitialBlockDownload)

(defvar *max-tip-age-seconds* (* 24 60 60)
  "Consider the node still in IBD while the active tip is older than
this. Core DEFAULT_MAX_TIP_AGE (kernel/chainstatemanager_opts.h:24), settable
with -maxtipage.

A DEFPARAMETER because Core exposes the knob; the +NAME+ spelling is kept
because every caller reads it as a constant.")

(defun near-tip-p (chain-state)
  "Core's near-tip test for accepting NODE_NETWORK_LIMITED peers as automatic
outbounds: ApproximateBestBlockDepth() < NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS
(net_processing.cpp:1342-1345, 1759-1768), i.e. the tip's timestamp is within
144 block intervals of now. Unlike initial-block-download-p this does not latch
and has no chain-work term, so a tip gone stale for a day reverts to demanding
full NODE_NETWORK peers, as Core does."
  (let* ((tip-hash (bl.store:best-block-hash chain-state))
         (tip (and tip-hash (bl.store:get-block-index-entry chain-state tip-hash))))
    (and tip
         (> (bl.ser:block-header-timestamp
             (bl.store:block-index-entry-header tip))
            (- (bl.ser:get-unix-time) (* 144 600))))))

(defun initial-block-download-p (chain-state)
  "Return T while the node is in initial block download.
Latches to (and then always returns) NIL once the active tip exists,
has at least the network's minimum chain work, and its timestamp is
within *max-tip-age-seconds* of now — Core UpdateIBDStatus
(validation.cpp:3314-3322) + CChain::IsTipRecent (chain.h:431-437)."
  (unless *cached-is-ibd*
    (return-from initial-block-download-p nil))
  (let* ((tip-hash (bl.store:best-block-hash chain-state))
         (tip (and tip-hash
                   (bl.store:get-block-index-entry chain-state tip-hash))))
    (if (and tip
             (>= (bl.store:block-index-entry-chain-work tip)
                 (bl:minimum-chain-work bl:*network*))
             (>= (bl.ser:block-header-timestamp
                  (bl.store:block-index-entry-header tip))
                 (- (bl.ser:get-unix-time)
                    *max-tip-age-seconds*)))
        (progn
          (bl:log-info "Leaving InitialBlockDownload (latching to false)")
          (setf *cached-is-ibd* nil)
          ;; With an assumeutxo background chainstate in use, leaving IBD
          ;; shifts the coins-cache allocation to the historical chainstate
          ;; (Core ActivateBestChain's exited_ibd -> MaybeRebalanceCaches,
          ;; validation.cpp:3479-3486).
          (bl:rebalance-caches-on-ibd-exit)
          nil)
        t)))

(defconstant +max-fee-estimation-tip-age+ (* 3 60 60)
  "Core MAX_FEE_ESTIMATION_TIP_AGE (validation.cpp:99): three hours.")

(defun current-for-fee-estimation-p (chain-state)
  "Core IsCurrentForFeeEstimation (validation.cpp:280-292): may what the
mempool accepts right now teach the fee estimator anything?

Not during initial block download, not while the tip is older than
MAX_FEE_ESTIMATION_TIP_AGE, and not while the tip is more than one block
behind the best header (`m_chain.Height() < m_best_header->nHeight - 1') --
in each state the node is catching up, so the number of blocks a transaction
waits says nothing about the fee market. One block behind is current: that is
the ordinary gap between a header's arrival and its body's.

It lives here, beside INITIAL-BLOCK-DOWNLOAD-P, because that latch does; Core
keeps it in validation.cpp next to the ATMP call sites that read it.
BEST-HEADER-ENTRY is Core's cached m_best_header, O(1), which is what lets a
predicate that runs once per accepted transaction ask it."
  (and (not (initial-block-download-p chain-state))
       (let* ((tip-hash (bl.store:best-block-hash chain-state))
              (tip (and tip-hash
                        (bl.store:get-block-index-entry chain-state tip-hash)))
              (best (bl.store:best-header-entry chain-state)))
         (and tip
              (>= (bl.ser:block-header-timestamp
                   (bl.store:block-index-entry-header tip))
                  (- (bl.ser:get-unix-time) +max-fee-estimation-tip-age+))
              (or (null best)
                  (>= (bl.store:block-index-entry-height tip)
                      (1- (bl.store:block-index-entry-height best))))
              t))))

(define-p2p-handler "inv" (peer payload ctx)
  "Handle an inv message.

For block invs we DO NOT request the block directly via getdata — under
headers-first sync (BIP 130 era), an unknown block hash means we are
missing the header chain that reaches it, so a getdata would race the
header that defines the block's parent and `process-received-block`
would drop it with WARN: Received unknown block. Instead, on the first
unknown block hash we send a getheaders sourced from our header tip;
once headers connect, the IBD/follow-tip path issues the actual getdata.

Mirrors Bitcoin Core net_processing.cpp:4126-4214 (reject_tx_invs,
wtxidrelay-mismatch skip, AddTxAnnouncement, best_block tracking plus a
single MaybeSendGetHeaders after the inv vector is fully scanned)."
  (bl.ctx:with-node-context (chain-state mempool) ctx
  (let ((inv-vectors (bl.ser:parse-inv-payload payload))
        ;; Core's own RejectIncomingTxs, not a third inlined copy of it
        ;; (net_processing.cpp:4134) -- so the RELAY permission excuses the
        ;; -blocksonly clause here exactly as it does for the VERSION we sent
        ;; and for the tx handler.
        (reject-tx-invs (reject-incoming-txs-p peer))
        ;; Core's current_time, read once for the whole message
        ;; (net_processing.cpp:4122).
        (now (%tx-request-now))
        (unknown-block-hash nil))
    (dolist (inv inv-vectors)
      (let ((inv-type (bl.ser:inv-vector-type inv))
            (hash (bl.ser:inv-vector-hash inv)))
        (cond
          ((block-inv-type-p inv-type)
           ;; Per-peer availability: announcing a block hash counts as
           ;; "peer has it" — update best-known-block (or stage
           ;; hash-last-unknown if we don't have the header yet).
           (bl.net:update-block-availability peer chain-state hash)
           (unless (bl.store:get-block-index-entry chain-state hash)
             (setf unknown-block-hash hash)))
          ;; Transaction announcement. MSG_TX / MSG_WITNESS_TX carry a
          ;; txid; MSG_WTX (BIP339) carries a wtxid. Matching MSG_WTX here
          ;; is essential: peers that negotiated wtxidrelay — every modern
          ;; Core peer — announce txs exclusively under MSG_WTX
          ;; (net_processing.cpp:6009,6065), so without this branch no tx
          ;; announcement from them was ever requested.
          ((tx-inv-type-p inv-type)
           ;; Tx invs in violation of our advertised fRelay=0 (blocksonly
           ;; mainnet default, block-relay/feeler conns): disconnect (Core
           ;; net_processing.cpp:4168-4172).
           (when reject-tx-invs
             ;; Core names the offending hash in this line
             ;; (net_processing.cpp:4169, `transaction (%s) inv sent in
             ;; violation of protocol, %s'), and p2p_blocksonly.py:36 asserts
             ;; on the line WITH it. inv.hash.ToString() is uint256's display
             ;; order, i.e. the wire bytes reversed.
             (bl:log-cat "net"
                         "transaction (~A) inv sent in violation of protocol, ~A"
                         (bl.crypto:bytes-to-hex (bl.crypto:reverse-bytes hash))
                         (disconnect-msg peer))
             (disconnect-peer peer)
             (return-from handle-inv))
           ;; Ignore invs that don't match the wtxidrelay negotiation: a
           ;; wtxidrelay peer never announces MSG_TX, a non-wtxidrelay peer
           ;; never MSG_WTX (Core net_processing.cpp:4145-4152).
           (let ((wtxidp (= inv-type bl.ser:+inv-type-wtx+)))
             (unless (if (peer-wtxid-relay peer)
                         (= inv-type bl.ser:+inv-type-tx+)
                         wtxidp)
               ;; The peer knows this transaction: it just told us about it.
               ;; Core AddKnownTx(peer, inv.hash), net_processing.cpp:4174 --
               ;; placed OUTSIDE the IBD branch below on purpose, so a peer
               ;; that announced during IBD is still not told about the
               ;; transaction once we leave it. The mismatch test above has
               ;; already established that INV-TYPE matches the peer's
               ;; negotiation, so HASH is the id this peer's filter is keyed
               ;; by. Without this we announce every transaction we accept
               ;; straight back to the peers that announced it to us.
               (%mark-tx-known-to-peer peer hash)
               ;; Core requests announced txs only outside IBD -- their
               ;; inputs won't resolve against a stale UTXO set anyway
               ;; (net_processing.cpp:4176-4180 gates AddTxAnnouncement on
               ;; !IsInitialBlockDownload). The announcement is only
               ;; RECORDED here: the getdata goes out from the SendMessages
               ;; pass that follows (SEND-TX-REQUESTS), as Core's does.
               (when (and mempool
                          (not (initial-block-download-p chain-state)))
                 (let ((have (txdownload-add-tx-announcement
                              (ctx-txdownloadman ctx) peer hash wtxidp now)))
                   (bl:log-cat "net" "got inv: ~A  ~:[new~;have~] peer=~D"
                               (%inv-vector-description inv) have
                               (peer-id peer))))))))))
    ;; Throttled, as Core's is (MaybeSendGetHeaders at :4198, one per
    ;; HEADERS_RESPONSE_TIME per peer): a peer announcing block after block by
    ;; inv buys one getheaders per window, not one per inv -- p2p_sendheaders.py
    ;; :334 asserts exactly that no second getheaders follows the second inv.
    ;;
    ;; ONE NEW PEER PER ANNOUNCED BLOCK. Core's gate is
    ;; `state.fSyncStarted || (!peer.m_inv_triggered_getheaders_before_sync &&
    ;; *best_block != m_last_block_inv_triggering_headers_sync)'
    ;; (net_processing.cpp:4197), with its own comment: with initial headers
    ;; sync open with ONE peer at a time, Core is "willing to add one new peer
    ;; per block to sync with as well, to sync quicker in the case where our
    ;; initial peer is unresponsive (but less bandwidth than we'd use if we
    ;; turned on sync with all peers)". The sync peer answers every
    ;; announcement; every other peer answers at most one announcement ever,
    ;; and only if no other peer has already been opened on THAT block.
    ;; p2p_initial_headers_sync.py:105 announces one block from three peers
    ;; and asserts that exactly one of the two non-sync peers is asked.
    (when (and unknown-block-hash
               (or (peer-headers-sync-started peer)
                   (and (not (peer-inv-triggered-getheaders-before-sync peer))
                        (not (equalp unknown-block-hash
                                     *last-block-inv-triggering-headers-sync*)))))
      (when (%maybe-send-getheaders peer (build-header-locator chain-state))
        (bl:log-cat "net" "inv: unknown block ~A from ~A — sending getheaders"
                    (bl.crypto:bytes-to-hex unknown-block-hash)
                    (peer-log-name peer)))
      ;; Recorded whether or not the request survived the throttle, as Core
      ;; records it (net_processing.cpp:4202-4210): the budget this spends is
      ;; the peer's one pre-sync announcement, and the block that spent it.
      (unless (peer-headers-sync-started peer)
        (setf (peer-inv-triggered-getheaders-before-sync peer) t
              *last-block-inv-triggering-headers-sync* unknown-block-hash))))))

;;; Notfound handling

(define-p2p-handler "notfound" (peer payload ctx)
  "Handle a notfound message: the peer is telling us it lacks one or
more items we requested via getdata. Its tx items go to
m_txdownloadman.ReceivedNotFound (net_processing.cpp:5150-5164,
txdownloadman_impl.cpp:288-295), which completes this peer's announcement of
each, so the next candidate is asked at the SendMessages pass that follows
instead of the request burning its 60s expiry. Block items are ignored, as
Core's NOTFOUND arm ignores them: no Core peer — and no bitcoin-lisp peer, see
handle-getdata — ever sends a notfound for a block, and a peer that cannot
serve one it announced is handled by the block-download timeout like any
other stalled request.

The tx items are ignored outright when the message carries more than
MAX_PEER_TX_ANNOUNCEMENTS + MAX_BLOCKS_IN_TRANSIT_PER_PEER of them -- more
than the peer could possibly be answering -- rather than the 50,000 the inv
parser allows. Nothing is re-requested from here: Core re-issues from each
peer's own SendMessages, and so does SEND-TX-REQUESTS, which keeps
an unsolicited notfound's cost at its own item count."
  (let ((invs (bl.ser:parse-inv-payload payload))
        (hashes '()))
    (when (<= (length invs)
              (+ +max-peer-tx-announcements+ +max-blocks-in-transit-per-peer+))
      (dolist (inv invs)
        (when (tx-inv-type-p (bl.ser:inv-vector-type inv))
          (push (bl.ser:inv-vector-hash inv) hashes))))
    (txdownload-received-not-found (ctx-txdownloadman ctx) peer (nreverse hashes))))

;;; Headers handling

(define-p2p-handler "headers" (peer payload ctx)
  "Handle a headers message: validate the announced headers (PoW, MTP,
difficulty, checkpoint) and admit only the valid ones to the block index,
queueing them for block download. This is the generic message-loop path (the
IBD pre-sync drain via handle-message, and BIP130 sendheaders announcements);
like the Phase-1 sync-headers path it MUST validate before admission, or a peer
could inject unchecked headers into the index — inflating chain-work with
low-target headers lacking matching PoW and bypassing checkpoints at admission.
Routes through ingest-headers-from-peer (Core ProcessHeadersMessage), which
adds the low-work anti-DoS presync gate this path previously lacked: during a
from-genesis IBD the validated tip sits below the work floor, so
process-headers' own gate is off and unbounded cheap headers could be
committed to the index from announcements."
  (bl.ctx:with-node-context (chain-state) ctx
  (let ((headers (bl.ser:parse-headers-payload payload)))
    ;; Node lock: process-headers (inside ingest-headers-from-peer) mutates
    ;; the block index, which the RPC threads (submitheader, chain queries)
    ;; also touch under this lock — the same discipline handle-block follows.
    (with-current-node-lock
      (ingest-headers-from-peer peer headers chain-state)))))

;;; Block handling

(defun accept-downloaded-block (block chain-state utxo-set block-store
                                &key mempool)
  "Validate and connect a freshly-downloaded block (full, reconstructed, or
completed compact), handling the fork case correctly. Must be called under the
node lock. Returns (values valid error).

A block that extends the active tip gets full contextual validation at tip+1,
then CONNECT-BLOCK applies it. A block whose parent is NOT the current tip is
on a side branch: it is validated CONTEXT-FREE (Core CheckBlock) at its own
branch height and handed to CONNECT-BLOCK, which stores it and — once its
branch outweighs the active chain — reorganizes onto it via PERFORM-REORG,
which runs the contextual checks (inputs / scripts / BIP34 height / value)
fork-to-tip against the rewound UTXO set.

Tip-validating a fork block was the deep-reorg wedge: its inputs live on its
own branch, not the active UTXO set (MISSING-INPUT), and its height is not
tip+1 (BAD-COINBASE-HEIGHT), so it was rejected before storage and PERFORM-REORG
never received the branch's blocks."
  (let* ((header (bl.ser:bitcoin-block-header block))
         (prev-hash (bl.ser:block-header-prev-block header))
         (current-best-hash (bl.store:best-block-hash chain-state))
         (current-time (bl.ser:get-unix-time)))
    (flet ((%refuse (error)
             ;; Core's InvalidBlockFound (validation.cpp:1985-1994), reached
             ;; from AcceptBlock (:4382-4386) and ConnectBlock alike: a
             ;; deterministic verdict is cached on the index entry, so the
             ;; same block is answered `duplicate-invalid' and a child of it
             ;; `bad-prevblk' (p2p_compactblocks.py:773-795).
             (bl.val:poison-failed-block chain-state header error)
             (values nil error))
           (%connect ()
             (multiple-value-bind (entry reorg-outcome)
                 (bl.val:connect-block
                  block chain-state block-store utxo-set
                  :mempool mempool)
               (declare (ignore entry))
               ;; If CONNECT-BLOCK triggered a reorg that was REFUSED because
               ;; fork blocks are missing from the store, re-download them.
               ;; REORG-OUTCOME is (REORG-OK DETAIL): a NIL REORG-OK with a LIST
               ;; detail is the missing (hash . height) list. The IBD path
               ;; (process-received-block -> activate-block) does this itself,
               ;; but a winning block arriving via the compact/relay path lands
               ;; here instead — without re-queuing, the sub-tip fork blocks the
               ;; reorg needs are never requested and the node wedges (the
               ;; testnet4 deep-reorg wedge). A VERDICT detail means an invalid
               ;; fork block (rolled back) — do not re-download.
               (when (and (consp reorg-outcome)
                          (null (first reorg-outcome))
                          (bl.val:reorg-missing-blocks-p (second reorg-outcome)))
                 (queue-missing-fork-blocks (second reorg-outcome))))
             ;; AcceptBlock's and ActivateBestChain's closing CheckBlockIndex
             ;; (validation.cpp:4425, :3517): CONNECT-BLOCK did both.
             (bl.val:check-block-index chain-state)))
      ;; Core's two AcceptBlockHeader gates, which this path had neither of --
      ;; it branched only on whether the parent is the tip.
      ;;
      ;; duplicate-invalid (validation.cpp:4231-4235): a block we already hold
      ;; and already marked invalid is refused outright. Without it,
      ;; invalidateblock is undone by one unsolicited block message.
      (let ((known (bl.store:get-block-index-entry
                    chain-state (bl.ser:block-header-hash header))))
        (when (and known
                   (eq (bl.store:block-index-entry-status known) :invalid))
          (return-from accept-downloaded-block (values nil :duplicate-invalid))))
      ;; bad-prevblk (validation.cpp:4252-4255): a block building on an invalid
      ;; parent is refused before any work is done on it. This is what stops a
      ;; poisoned subtree being re-offered block by block to force the whole
      ;; doomed reorg to be attempted again -- roughly 1 MB of message buying
      ;; an unmetered amount of our validation.
      (let ((parent (bl.store:get-block-index-entry chain-state prev-hash)))
        (when (and parent
                   (eq (bl.store:block-index-entry-status parent) :invalid))
          (return-from accept-downloaded-block (values nil :bad-prevblk))))
      (if (equalp prev-hash current-best-hash)
          ;; Extends the active tip — full validation at tip+1.
          (let ((new-height (1+ (bl.store:current-height chain-state))))
            (multiple-value-bind (valid error)
                (bl.val:validate-block
                 block chain-state utxo-set new-height current-time)
              (if valid (progn (%connect) (values t nil)) (%refuse error))))
          ;; Side branch — context-free validation at the block's own height;
          ;; CONNECT-BLOCK stores it and reorgs (validating fully) when it wins.
          (let ((prev-entry (bl.store:get-block-index-entry
                             chain-state prev-hash)))
            (if (null prev-entry)
                ;; Parent header unknown: can't place the block or check its
                ;; PoW/difficulty. Drop it (a healthy IBD has the headers first).
                (values nil :orphan-block)
                (let ((fork-height (1+ (bl.store:block-index-entry-height
                                        prev-entry))))
                  (multiple-value-bind (valid error)
                      (bl.val:validate-block
                       block chain-state utxo-set fork-height current-time
                       :context-free-only t)
                    (if valid (progn (%connect) (values t nil)) (%refuse error))))))))))

(defun %block-newly-connected-p (chain-state hash tip-before)
  "T when accepting the block HASH actually ADVANCED the active chain onto it.
TIP-BEFORE is BEST-BLOCK-HASH sampled before ACCEPT-DOWNLOADED-BLOCK ran.

This is the BlockChecked gate. Core reaches
MaybeSetPeerAsAnnouncingHeaderAndIDs only from BlockChecked's `state.IsValid()'
arm (net_processing.cpp:2214-2223), and the only emit site that can produce a
VALID state is ConnectTip (validation.cpp:3070): ProcessNewBlock's other emit
(:4455) is the AcceptBlock-failure path, and a block we already have
short-circuits inside AcceptBlock long before ConnectTip. So a block Core never
connects promotes nobody, and a REPLAY of a block we already hold promotes
nobody either.

ACCEPT-DOWNLOADED-BLOCK's `valid' value cannot express that on its own: it is T
for a block merely STORED on a side branch (the :context-free-only arm above)
and T again for a block we already hold — including a replay of our own tip,
for which `(equalp (best-block-hash cs) hash)' alone is TRIVIALLY TRUE, since
the tip already is that block. Hence TIP-BEFORE: the tip must have MOVED, and
it must have moved onto this very block. Without it any inbound peer that sent
sendcmpct could echo our own tip back and buy a high-bandwidth slot for free,
repeatedly, choosing which honest peer the cap-of-3 eviction demotes.

Conservative in exactly one direction, deliberately: if accepting HASH also
reconnects already-stored descendants, the tip lands above it and we do not
promote where Core would. Failing closed costs a little bandwidth; failing open
sells an HB slot."
  (and (not (equalp tip-before hash))
       (equalp (bl.store:best-block-hash chain-state) hash)))

(defun %refuse-mutated-block (peer block chain-state)
  "Core's wire-level mutation gate on an arriving BLOCK
(net_processing.cpp:4871-4879), run before anything else touches it. Returns T
when the block was refused, in which case the caller must return.

    if (prev_block && IsBlockMutated(*pblock, DeploymentActiveAfter(prev_block, SEGWIT))) {
        LogDebug(BCLog::NET, \"Received mutated block from peer=%d\\n\", peer.m_id);
        Misbehaving(peer, \"mutated block\");
        RemoveBlockRequest(pblock->GetHash(), peer.m_id);
        return;
    }

Everything about the placement is the point. A mutated block carries the HASH
of the honest one, so letting it reach the validator means the honest block's
own download bookkeeping is cleared by the copy -- our
HANDLE-VALIDATION-FAILURE frees the in-flight slot and re-queues the hash, so
an attacker could cancel an honest peer's delivery at will and repeat it. And
the verdict must not be remembered against the hash, because the hash is not
the attacker's to spoil: gated here, nothing is written at all.
p2p_mutated_blocks.py:82-91 sends the mutated copy from a second peer while a
getblocktxn to the honest one is outstanding, and asserts that the attacker is
disconnected and the honest peer's `inflight' is untouched.

The gate is asked only for a block whose parent we have, because the witness
half of the question needs the parent's height to know whether segwit is
active -- the same reason Core guards it with `prev_block &&'. Only THIS
peer's request for the hash is withdrawn."
  (let* ((header (bl.ser:bitcoin-block-header block))
         (prev (bl.store:get-block-index-entry
                chain-state (bl.ser:block-header-prev-block header))))
    (when prev
      (multiple-value-bind (mutated reason)
          (bl.val:block-mutated-p
           block
           (bl.val:segwit-active-at-height-p
            (1+ (bl.store:block-index-entry-height prev))))
        (when mutated
          ;; Core's own two lines: the verdict from IsBlockMutated
          ;; (validation.cpp:4063) and the peer it came from (:4874).
          (when reason
            (bl:log-cat "validation" "Block mutated: ~A" reason))
          (bl:log-cat "net" "Received mutated block from peer=~D" (peer-id peer))
          (record-misbehavior peer "mutated block")
          (remove-block-request (bl.ser:block-header-hash header) peer)
          t)))))

(define-p2p-handler "block" (peer payload ctx)
  "Handle a block message. Announcing a new tip onward is the :updated-block-tip
hook's job (announce-block-tip), not this handler's. A peer that delivers a
block that CONNECTS earns consideration for high-bandwidth compact-block
announcements — Core
drives that off mapBlockSource (net_processing.cpp:2202, 2218-2223), which is
filled for plain block messages exactly as it is for reconstructed compact
ones, so promotion must not be a compact-block-only privilege."
  (bl.ctx:with-node-context (chain-state utxo-set block-store mempool) ctx
  (let ((block (bl.ser:parse-block-payload payload)))
    (when (and block (%refuse-mutated-block peer block chain-state))
      (return-from handle-block nil))
    (when block
      (let ((connected
              (with-current-node-lock
                (let* ((header (bl.ser:bitcoin-block-header block))
                       (hash (bl.ser:block-header-hash header))
                       (tip-before (bl.store:best-block-hash chain-state)))
                  (multiple-value-bind (valid error)
                      (accept-downloaded-block block chain-state utxo-set block-store
                                               :mempool mempool)
                    (cond
                      (valid
                       ;; Announcing the new tip is the :updated-block-tip
                       ;; hook's job (announce-block-tip, Core UpdatedBlockTip):
                       ;; it fires for THIS path, the block-download drain and
                       ;; a reorg alike, so no path is a block sink.
                       ;; Promotion needs strictly more than acceptance: the
                       ;; block must have CONNECTED (see %block-newly-connected-p).
                       (%block-newly-connected-p chain-state hash tip-before))
                      (t
                       (bl:log-warn "Block ~A rejected: ~A"
                                    (bl.crypto:bytes-to-hex hash)
                                    (bl.val:block-reject-reason-string error))
                       (record-misbehavior peer "invalid block")
                       nil)))))))
        ;; Outside the node lock: promotion writes sendcmpct to up to two peers.
        (when connected
          (maybe-promote-block-deliverer peer chain-state)))))))

;;; Address handling

(defun %addr-gossip-key (peer-addr)
  "Dedup key for addr gossip: network-typed [net-id, addr-bytes..., port]."
  (make-address-key (peer-address-ip peer-addr) (peer-address-port peer-addr)
                    (peer-address-network peer-addr)))

(defun addr-compatible-p (peer peer-addr)
  "T when PEER can carry PEER-ADDR at all (Core IsAddrCompatible,
net_processing.cpp:1117-1120): a peer that never negotiated addrv2 has no
encoding for onion/i2p/cjdns, so those addresses are never selected for it and
never queued to it."
  (or (peer-wants-addrv2 peer)
      (bl.ser:v1-compatible-network-p (peer-address-network peer-addr))))

(defun push-address (peer peer-addr)
  "Queue PEER-ADDR for PEER's next addr flush (Core PushAddress,
net_processing.cpp:1128-1141). Nothing goes on the wire here — that is
FLUSH-ADDR-ANNOUNCEMENTS's job, and the delay between the two is the point
(see +avg-address-broadcast-interval+).

Skipped for an address the peer already knows (Core: \"only to save space from
duplicates\" — the flush filters again, because the peer can learn an address
between the push and the flush) and for one it cannot encode; T is returned
only when the address was actually queued, which is how RELAY-ADDRESS counts
what it passed on without widening its own fan-out to make the count up.

Once the queue holds bl.ser:+max-addr-count+ entries (Core MAX_ADDR_TO_SEND,
the same 1000 that bounds an addr message) a new address REPLACES a uniformly
random one rather than being appended or dropped, so a peer flooding us with
addresses cannot decide which of the queued ones we pass on."
  (let ((queue (peer-addrs-to-send peer)))
    (when (and (not (rolling-bloom-contains-p (peer-known-addrs peer)
                                        (%addr-gossip-key peer-addr)))
               (addr-compatible-p peer peer-addr))
      (if (>= (fill-pointer queue) bl.ser:+max-addr-count+)
          (setf (aref queue (random (fill-pointer queue))) peer-addr)
          (vector-push-extend peer-addr queue))
      t)))

(defconstant +randomizer-id-address-relay+ #x3cac0035b5866b90
  "Core RANDOMIZER_ID_ADDRESS_RELAY (net_processing.cpp:114). The domain
separator written into the node's deterministic randomizer before anything
else, so address-relay ranking shares no key material with the other users of
the same per-node seed.")

(defconstant +rotate-addr-relay-dest-interval-seconds+ (* 24 60 60)
  "Core ROTATE_ADDR_RELAY_DEST_INTERVAL (net_processing.cpp:162). One address
keeps the same relay destinations for this long, which is what lets those
destinations' own addr-known filters suppress the repeats: a peer sending us
the same address over and over gains it no extra propagation.")

(defvar *address-relay-salt* nil
  "The node-lifetime SipHash key (K0 . K1) for address-relay destination
ranking -- Core's CConnman::nSeed0/nSeed1, drawn once per process and reached
through GetDeterministicRandomizer. The ranking must not be computable by
anyone else: with an unsalted hash over public inputs, which is what this used
to be, an attacker knows in advance which two of our peers any address reaches
and can pick addresses to steer the fan-out. Drawn lazily so nothing in
start-up ordering depends on it; two threads racing the first draw is benign
(both values are equally good, and the loser's ranking is simply the one
that stands). A test binds it to fix the ranking.")

(defun %address-relay-salt ()
  "The node's address-relay SipHash key, drawn from the OS CSPRNG on first use."
  (or *address-relay-salt*
      (setf *address-relay-salt* (random-siphash-key))))

(defun %addr-relay-hash (key)
  "Core's hash_addr = CServiceHash(0, 0)(addr) (netaddress.h:571-589): the
UNSALTED per-address hash, which both offsets the rotation instant and feeds
the ranking below. Core hashes the network, the port and the address bytes; we
hash our own canonical gossip key, which carries exactly those three. Byte
compatibility with Core is not available here anyway -- what the value ends up
keying is a per-node secret."
  (bl.crypto:siphash-2-4 0 0 key))

(defun %addr-relay-message (hash-addr time-addr &optional peer-id)
  "The SipHash message Core assembles for address relay: the randomizer id,
the address hash and the rotation epoch, each a little-endian uint64 word
(CSipHasher::Write(uint64_t)), plus the peer id for the per-peer ranking
(net_processing.cpp:2298-2313). Without PEER-ID this is the base hasher Core
finalizes to decide the fan-out of an unreachable address."
  (let ((words (list (int-to-le-bytes +randomizer-id-address-relay+ 8)
                     (int-to-le-bytes hash-addr 8)
                     (int-to-le-bytes time-addr 8))))
    (apply #'concatenate '(vector (unsigned-byte 8))
           (if peer-id
               (append words (list (int-to-le-bytes peer-id 8)))
               words))))

(defun relay-address (peer-addr source-peer peers
                      &key (now (bl.ser:get-unix-time)) (reachable t))
  "Forward a freshly-learned address to the deterministically-chosen best one
or two peers (Core RelayAddress, net_processing.cpp:2279-2337): eligibility is
ready + address relay set up (block-relay-only/feeler peers get no addr gossip,
and neither does an inbound peer that never sent addr/getaddr -- Core
:2311) + not the announcing peer + able to carry the address at all (a peer
that has not negotiated addrv2 never receives onion/i2p/cjdns addresses, Core
IsAddrCompatible :1117).

REACHABLE is Core's fReachable: a reachable address goes to 2 peers, an
unreachable one to 1 or 2 depending on the low bit of the same hasher
(:2301-2302), so an address on a network we cannot dial still spreads, just
at half the average fan-out.

Selection ranks the eligible peers by SipHash(node secret; randomizer id,
address hash, rotation epoch, peer id) and takes the top N -- Core's `best'
array, filled by strict improvement. Two details of that are the whole point:
the rank is keyed by a PER-NODE secret (see *ADDRESS-RELAY-SALT*), and the
rotation epoch carries the address's own hash, so every address rotates its
destinations at its own instant in the 24h cycle instead of the whole network
turning over at 00:00 UTC. Walking further down the ranking to find N peers
that do not already know the address is NOT what Core does: PushAddress simply
does nothing for a peer that knows it, which is how repeats of an address stay
inside the same two destinations for the day.

The chosen peers are QUEUED to, never sent to (Core RelayAddress calls
PushAddress and nothing else): sending here would weld the moment we pass an
address on to the moment we learned it, which is the timing correlation the
flush's exponential schedule exists to destroy. Marking the ANNOUNCER as
knowing the address is not done here either -- Core does it in the ADDR
handler, for every address the message carried rather than only the few that
are relayed onward (see %INGEST-GOSSIPED-ADDRESS). Returns the number of
peers the address was actually queued on."
  (let* ((key (%addr-gossip-key peer-addr))
         (hash-addr (%addr-relay-hash key))
         ;; Core: "Adding address hash makes exact rotation time different per
         ;; address, while preserving periodicity" (net_processing.cpp:2296).
         ;; Masked to 64 bits because Core's sum is uint64 and wraps.
         (time-addr (floor (logand (+ now hash-addr) #xFFFFFFFFFFFFFFFF)
                           +rotate-addr-relay-dest-interval-seconds+))
         (salt (%address-relay-salt))
         (sent 0))
    (flet ((rank (&optional peer-id)
             (bl.crypto:siphash-2-4 (car salt) (cdr salt)
                                    (%addr-relay-message hash-addr time-addr
                                                         peer-id))))
      (let ((n-relay (if (or reachable (logbitp 0 (rank))) 2 1))
            (ranked
              (sort (loop for p in peers
                          when (and (eq (peer-state p) :ready)
                                    (not (eq p source-peer))
                                    (peer-addr-relay-enabled p)
                                    (addr-compatible-p p peer-addr))
                            collect (cons (rank (peer-id p)) p))
                    #'> :key #'car)))
        ;; The known-addrs mark for a target is made by the FLUSH, on the same
        ;; pass that filters (Core MaybeSendAddr's addr_already_known lambda).
        (loop for (nil . p) in ranked
              repeat n-relay
              when (push-address p peer-addr) do (incf sent))))
    sent))

(defun peer-source-address (peer)
  "PEER's own address as (VALUES net ip-bytes net-group-key) — addrman's
`source` argument (Core AddrMan::Add). The group keys new-bucket placement so
one source cannot dominate our address set; the address itself identifies a
self-announcement, which Core exempts from the gossip time penalty
(addrman.cpp:559-563). Network-typed, so onion/i2p/cjdns peers get their
proper source groups. All NIL for a hostname peer (addnode by name) or no
peer at all."
  (when peer
    (multiple-value-bind (net bytes) (parse-network-address (peer-address peer))
      (when net (values net bytes (net-group-key bytes net))))))

;;; Gossiped-address timestamp handling (Core's ADDR handler,
;;; net_processing.cpp:4087-4114). Age is NOT an admission rule: Core stores
;;; whatever it is told and lets addrman drop stale entries at SELECTION time
;;; (ADDRMAN_HORIZON, 30 days — addr-info-terrible-p here). Core's own DNS-seed
;;; path deliberately mints entries aged 3-7 days (net.cpp:2375), so any
;;; storage-side freshness window would throw away exactly the addresses a
;;; getaddr response exists to deliver.

(defconstant +addr-time-init+ 100000000
  "CAddress::TIME_INIT (protocol.h): a gossiped timestamp at or below this
(1973-03-03) is not a real observation, it is an unset field.")

(defconstant +addr-absurd-time-replacement-seconds+ (* 5 24 60 60)
  "How far in the past an absurd gossiped timestamp is rewritten to — 5 days
(net_processing.cpp:4092). Old enough not to be relayed onward or preferred by
selection, young enough to stay inside the 30-day addrman horizon.")

(defconstant +addr-gossip-time-penalty-seconds+ (* 2 60 60)
  "Time penalty applied when STORING a gossiped address (Core's
/*time_penalty=*/2h at net_processing.cpp:4114): hearsay about a peer is
weaker evidence of liveness than having connected to it ourselves.")

(defun may-have-useful-address-db-p (services)
  "Core's storage service filter for gossiped addresses
(net_processing.cpp:4087, MayHaveUsefulAddressDB): a peer advertising neither
NODE_NETWORK nor NODE_NETWORK_LIMITED is not worth remembering. Core writes it
as `!MayHaveUsefulAddressDB(s) && !HasAllDesirableServiceFlags(s)`, but the
second test cannot rescue an address the first rejects — the desirable set
always contains NODE_NETWORK or NODE_NETWORK_LIMITED
(GetDesirableServiceFlags, net_processing.cpp:1759-1768) — so the pair reduces
to this one bit test."
  (logtest services (logior bl.ser:+node-network+
                            bl.ser:+node-network-limited+)))

(defun address-banned-or-discouraged-p (pa)
  "T when the PEER-ADDRESS PA is one this node has decided is hostile: banned
(setban) or discouraged (the rolling misbehaviour filter). Core's BanMan tests
are CNetAddr-typed, so the port plays no part -- PEER-ADDRESS-STRING renders
network and address only, exactly like the ban list's own keys."
  (let ((address (peer-address-string pa)))
    (or (peer-discouraged-p address)
        (peer-banned-p address))))

(defun %ingest-gossiped-address (peer net-addr timestamp address-book source-group
                                 now &optional source-net source-ip)
  "Shared addr/addrv2 ingestion for one gossiped NET-ADDR (Core's per-address
loop in the ADDR handler, net_processing.cpp:4069-4106) learned from PEER,
whose net-group key is SOURCE-GROUP and own address SOURCE-NET/SOURCE-IP. Stores
it in ADDRESS-BOOK only when its network is REACHABLE (-onlynet; Core \"Do not
store addresses outside our network\"), but fresh (10-min) ROUTABLE addresses
are relay candidates regardless — an unreachable-net address still relays,
just to 1 peer instead of 2 (Core RelayAddress fReachable).

Age gates RELAY only, never storage. An absurd timestamp (unset, or more than
10 minutes ahead of us) is rewritten to now - 5 days and stored anyway
(net_processing.cpp:4090-4092) rather than dropped; the stored copy carries
the 2h gossip penalty, waived for a peer announcing itself. Addresses whose
services bits promise no useful address DB are skipped entirely — neither
stored nor relayed, as in Core — and so are addresses this node has banned or
discouraged (net_processing.cpp:4094-4097).

PEER is marked as knowing the address (Core AddAddressKnown, :4093) after the
timestamp is fixed up and BEFORE the ban test, so a peer is never told back an
address it has just told us, whether or not we go on to store or relay it. It
is also the reason the mark is here and not in RELAY-ADDRESS, which only ever
saw the small fresh-and-routable subset that gets gossiped onward.

Returns (VALUES stored relay-entry processed): STORED is 1/0 for the caller's
log count, RELAY-ENTRY a (peer-address . reachable) cons when the address
should be gossiped onward -- REACHABLE being Core's fReachable argument to
RelayAddress, which decides the fan-out -- and PROCESSED is Core's ++num_proc,
true for an address that reached the relay/store stage. A banned one has not:
Core counts it in neither num_proc nor num_rate_limit."
  (unless (and address-book timestamp
               (may-have-useful-address-db-p
                (bl.ser:net-addr-services net-addr)))
    (return-from %ingest-gossiped-address (values 0 nil nil)))
  (let* ((time (if (or (<= timestamp +addr-time-init+)
                       (> timestamp (+ now 600)))
                   (max 0 (- now +addr-absurd-time-replacement-seconds+))
                   timestamp))
         (pa (make-peer-address
              :net (bl.ser:net-addr-net net-addr)
              :ip (bl.ser:net-addr-ip net-addr)
              :port (bl.ser:net-addr-port net-addr)
              :services (bl.ser:net-addr-services net-addr)
              :last-seen time
              ;; Core AddrInfo::source, which peers.dat keeps.
              :source (and source-net (cons source-net source-ip))))
         (network (peer-address-network pa))
         (reachable (reachable-network-p network))
         ;; Core: "Do not set a penalty for a source's self-announcement"
         ;; (addrman.cpp:559-563; the comparison is CNetAddr, so port-blind).
         (penalty (if (and source-net (eq source-net network)
                           (equalp source-ip (peer-address-ip pa)))
                      0
                      +addr-gossip-time-penalty-seconds+)))
    ;; Core AddAddressKnown (net_processing.cpp:4093), on the announcing peer,
    ;; for EVERY address that got past the service filter and before the ban
    ;; test below -- "remembering we received them" is exactly what the next
    ;; comment means by it.
    (when peer
      (rolling-bloom-insert (peer-known-addrs peer) (%addr-gossip-key pa)))
    ;; Core: "Do not process banned/discouraged addresses beyond remembering we
    ;; received them" (net_processing.cpp:4094-4097). Its `continue` skips the
    ;; ++num_proc, the RelayAddress call and the vAddrOk push that feeds
    ;; addrman, so a hostile address neither takes a bucket from a good one nor
    ;; gets gossiped onward by the node that decided it was hostile -- and it
    ;; is not reported as processed either.
    (when (address-banned-or-discouraged-p pa)
      (return-from %ingest-gossiped-address (values 0 nil nil)))
    (when reachable
      (address-book-add address-book pa source-group penalty))
    (values (if reachable 1 0)
            ;; Core relays only fresh (10-min) routable addrs — on the
            ;; rewritten timestamp, so a "flying DeLorean" address cannot buy
            ;; itself relay by claiming a future time.
            (when (and (> time (- now 600))
                       (address-routable-p (peer-address-ip pa) network))
              (cons pa reachable))
            t)))

(defun addr-token-clock ()
  "Now in MOCKABLE microseconds, the clock of the addr token bucket: Core
refills m_addr_token_bucket from GetTime<std::chrono::microseconds>()
(net_processing.cpp:4057), so setmocktime moves it.
p2p_addr_relay.py:427-439 advances the mock clock a day between one-address
messages and expects every message processed; on the process clock the
bucket saw a few real seconds a day, 0.1 token each, and ran dry."
  (if bl.ser:*mock-time*
      (* (bl.ser:get-unix-time) 1000000)
      #+sbcl (multiple-value-bind (seconds microseconds) (sb-ext:get-time-of-day)
               (+ (* seconds 1000000) microseconds))
      #-sbcl (* (bl.ser:get-unix-time) 1000000)))

(defun %refill-addr-token-bucket (peer &optional (now (addr-token-clock)))
  "Refill PEER's addr token bucket from elapsed time, once per addr/addrv2
message (Core net_processing.cpp:4056-4064): only while below the soft cap,
at +max-addr-rate-per-second+, clamped to the cap — so the getaddr-response
bump above the cap is never refilled further but also not clawed back. The
timestamp always advances. NOW is ADDR-TOKEN-CLOCK microseconds; a peer whose
timestamp is still 0 has never been refilled and gains nothing (Core stamps
m_addr_token_timestamp when the Peer is created, :386)."
  (let ((cap (coerce +max-addr-processing-token-bucket+ 'double-float)))
    (when (< (peer-addr-token-bucket peer) cap)
      (let* ((last (peer-addr-token-timestamp peer))
             (elapsed (if (zerop last) 0 (max 0 (- now last))))
             (increment (* (/ (coerce elapsed 'double-float) 1000000)
                           +max-addr-rate-per-second+)))
        (setf (peer-addr-token-bucket peer)
              (min (+ (peer-addr-token-bucket peer) increment) cap))))
    (setf (peer-addr-token-timestamp peer) now)))

(defun %log-addrman-added (address-book added peer)
  "Core's AddrMan::Add_ closing line, `Added N addresses (of M) from <source>:
T tried, N new' (addrman.cpp:687-689), written when an addr or addrv2 message
stored anything; p2p_invalid_messages.py:236 waits for `Added 1 addresses'.
Ours adds one address at a time, so `of' counts the ones that were stored."
  (when (and address-book (plusp added))
    (bl:log-cat "addrman" "Added ~D addresses (of ~D) from ~A: ~D tried, ~D new"
                added added (if peer (peer-address peer) "")
                (address-book-n-tried address-book)
                (address-book-n-new address-book))))

(defun %process-gossiped-addresses (peer entries announced-count address-book peers)
  "Shared addr/addrv2 processing core (the per-address loop of Core's
ADDR/ADDRV2 handler, net_processing.cpp:4038-4118). ENTRIES is a list of
(net-addr . timestamp); ANNOUNCED-COUNT is the message's declared address
count. Applies the per-ADDRESS token bucket — addresses beyond the bucket
are DROPPED, not queued (Core rate_limited branch; we have no per-peer Addr
permission, so every peer is subject to it and only the getaddr-response
bump exempts solicited replies). Processing order is shuffled first so an
attacker cannot choose which addresses survive the limit (Core std::shuffle).
Fresh routable addresses from small (<=10) UNSOLICITED announcements relay
onward; a non-full message marks our outstanding getaddr answered. Returns
the number stored."
  (multiple-value-bind (source-net source-ip source-group)
      (peer-source-address peer)
    (let* ((now (bl.ser:get-unix-time))
           ;; Read before the end-of-message reset below, like Core (the reset
           ;; runs after the loop): a getaddr response never relays onward.
           (unsolicited (not (and peer (peer-getaddr-requested peer))))
           (added 0)
           (num-proc 0)
           (num-rate-limit 0)
           (relay-candidates '()))
      (when peer
        (%refill-addr-token-bucket peer))
      ;; The "addr" permission lifts the rate limit entirely: such a peer may
      ;; send us unlimited addresses (Core net_processing.cpp:4066
      ;; `rate_limited = !pfrom.HasPermission(NetPermissionFlags::Addr)`).
      (let ((rate-limited (and peer (not (peer-has-permission-p peer +perm-addr+)))))
      (dolist (entry (alexandria:shuffle (copy-list entries)))
        ;; Core's rate-limit branch verbatim (net_processing.cpp:4076-4083):
        ;; below one token a rate-limited peer's address is dropped and
        ;; counted, while a peer holding the Addr permission is let through
        ;; and spends NOTHING -- only the else branch takes a token.
        (let ((below-a-token (and peer (< (peer-addr-token-bucket peer) 1.0d0))))
          (cond
            ((and below-a-token rate-limited)
             (incf num-rate-limit))
            (t
             (when (and peer (not below-a-token))
               (decf (peer-addr-token-bucket peer) 1.0d0))
             ;; num_proc counts what reached the relay/store stage, so it is
             ;; incremented by the ingest's verdict and not here: Core's
             ;; ++num_proc sits AFTER the service filter and the ban test
             ;; (net_processing.cpp:4098), and counting on the way in reported
             ;; addresses we had refused as processed.
             (multiple-value-bind (stored relay processed)
                 (%ingest-gossiped-address peer (car entry) (cdr entry)
                                           address-book source-group now
                                           source-net source-ip)
               (incf added stored)
               (when processed (incf num-proc))
               (when relay (push relay relay-candidates))))))))
      (when peer
        (incf (peer-addr-processed peer) num-proc)
        (incf (peer-addr-rate-limited peer) num-rate-limit)
        (when (plusp num-rate-limit)
          (bl:log-cat "net" "addr: ~D processed, ~D rate-limited, ~A"
                      num-proc num-rate-limit
                      (peer-log-name peer)))
        ;; A non-full message answers our getaddr (Core: "if (vAddr.size() <
        ;; 1000) peer.m_getaddr_sent = false", net_processing.cpp:4116).
        (when (< announced-count bl.ser:+max-addr-count+)
          (setf (peer-getaddr-requested peer) nil))
        ;; An addr-fetch connection (-seednode) exists ONLY to collect
        ;; addresses: once it has delivered some, it is done (Core
        ;; net_processing.cpp:4117-4121). Core requires MORE THAN ONE address
        ;; so a peer that merely self-announces does not end the fetch.
        (when (and (eq (peer-conn-type peer) :addr-fetch)
                   (> announced-count 1))
          (bl:log-cat "net" "addrfetch connection completed, ~A"
                      (disconnect-msg peer))
          (disconnect-peer peer)))
      (when (and peers unsolicited (<= announced-count 10))
        (loop for (pa . reachable) in relay-candidates
              do (relay-address pa peer peers :now now :reachable reachable)))
      added)))

(define-p2p-handler "addr" (peer payload ctx)
  "Handle an addr message. When CTX carries an address-book, add the addresses on
reachable networks to the address book regardless of age (absurd timestamps are
rewritten, not dropped — see %ingest-gossiped-address), keyed to the gossiping
PEER as their source (addrman source-group spreading), subject to the
per-address token bucket (see %process-gossiped-addresses). Ignored entirely
from a block-relay-only peer (Core SetupAddressRelay,
net_processing.cpp:4041); more than 1000 announced addresses is misbehavior
(net_processing.cpp:4046-4050)."
  (bl.ctx:with-node-context (address-book peers) ctx
  (when (and peer (eq (peer-conn-type peer) :block-relay))
    (bl:log-cat "net" "ignoring addr message from block-relay-only ~A"
                (peer-log-name peer))
    (return-from handle-addr 0))
  ;; First addr-related message from an inbound peer enables address relay
  ;; (Core SetupAddressRelay; getpeerinfo addr_relay_enabled).
  (when peer (setf (peer-addr-relay-enabled peer) t))
  (let ((entries '())
        (msg-count 0))
    (bl.bytes:with-byte-reader (stream payload)
      (let ((count (bl.bytes:br-read-compact-size stream)))
        (when (> count bl.ser:+max-addr-count+)
          (when peer
            (record-misbehavior peer (format nil "addr message size = ~D" count)))
          (return-from handle-addr 0))
        (setf msg-count count)
        (loop repeat count
              do (multiple-value-bind (net-addr timestamp)
                     (bl.ser:read-net-addr stream :with-timestamp t)
                   (push (cons net-addr timestamp) entries)))))
    (let ((added (%process-gossiped-addresses peer (nreverse entries) msg-count
                                              address-book peers)))
      (%log-addrman-added address-book added peer)
      added))))

;;; ADDRv2 handling (BIP 155)

(define-p2p-handler "addrv2" (peer payload ctx)
  "Handle an addrv2 message (BIP 155). When CTX carries an address-book, add
addresses of any representable network (IPv4/IPv6/TORv3/I2P/CJDNS) to the
address book regardless of age (absurd timestamps are rewritten, not dropped —
see %ingest-gossiped-address) — non-IP networks only when reachable (-onlynet
+ proxy/flag gates), subject to the per-address token bucket (see
%process-gossiped-addresses). Unknown network ids were
already skipped by the codec; a count above 1000 fails parsing (Core
Misbehaving path — the caller disconnects). Ignored entirely from a
block-relay-only peer (Core SetupAddressRelay)."
  (bl.ctx:with-node-context (address-book peers) ctx
  (when (and peer (eq (peer-conn-type peer) :block-relay))
    (bl:log-cat "net" "ignoring addrv2 message from block-relay-only ~A"
                (peer-log-name peer))
    (return-from handle-addrv2 0))
  ;; First addr-related message from an inbound peer enables address relay
  ;; (Core SetupAddressRelay; getpeerinfo addr_relay_enabled).
  (when peer (setf (peer-addr-relay-enabled peer) t))
  ;; Core's oversize rule, and its words: `Misbehaving(peer, "<type> message
  ;; size = N")' for either message type (net_processing.cpp:4046-4050);
  ;; p2p_addrv2_relay.py:106 waits for `addrv2 message size = 1010'. The
  ;; codec's own limit would reject the payload too, in words of its own.
  (let ((count (bl.bytes:with-byte-reader (stream payload)
                 (bl.bytes:br-read-compact-size stream))))
    (when (> count bl.ser:+max-addr-count+)
      (when peer
        (record-misbehavior peer (format nil "addrv2 message size = ~D" count)))
      (return-from handle-addrv2 0)))
  (multiple-value-bind (entries announced-count)
      (bl.ser:parse-addrv2-payload payload)
    (let ((added (%process-gossiped-addresses
                  peer
                  (mapcar (lambda (entry)
                            (destructuring-bind (net-addr timestamp network-id) entry
                              (declare (ignore network-id))
                              (cons net-addr timestamp)))
                          entries)
                  announced-count address-book peers)))
      (%log-addrman-added address-book added peer)
      added))))

;;; Transaction handling

;;; Core's vExtraTxnForCompact (net_processing.cpp:996-1003, 1885-1893): a ring
;;; of the last -blockreconstructionextratxn transactions a peer relayed that
;;; did not stay in the mempool -- rejected on first sight, or replaced -- which
;;; compact-block reconstruction consults after the mempool.

(defconstant +default-block-reconstruction-extra-txn+ 100
  "Core DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN (net_processing.h:47).")

(defvar *max-extra-txs* +default-block-reconstruction-extra-txn+
  "Core PeerManager::Options::max_extra_txs, -blockreconstructionextratxn
clamped to 0..uint32 max (node/peerman_args.cpp:18-21). 0 keeps no ring.")

(defvar *extra-txn-for-compact* (make-array 0)
  "The ring: (wtxid . tx) conses or NIL, sized to *MAX-EXTRA-TXS* on first use.")

(defvar *extra-txn-for-compact-index* 0
  "Core vExtraTxnForCompactIt: where the next transaction goes.")

(defun reset-compact-extra-transactions ()
  "Empty the ring (a new node, or a test)."
  (setf *extra-txn-for-compact* (make-array 0)
        *extra-txn-for-compact-index* 0))

(defun add-to-compact-extra-transactions (tx)
  "Core AddToCompactExtraTransactions (net_processing.cpp:1885-1893): TX
overwrites the oldest slot of the ring, which is sized on first use."
  (let ((max *max-extra-txs*))
    (when (plusp max)
      (unless (= (length *extra-txn-for-compact*) max)
        (setf *extra-txn-for-compact* (make-array max :initial-element nil)
              *extra-txn-for-compact-index* 0))
      (setf (aref *extra-txn-for-compact* *extra-txn-for-compact-index*)
            (cons (bl.ser:transaction-wtxid tx) tx)
            *extra-txn-for-compact-index* (mod (1+ *extra-txn-for-compact-index*) max)))))

(defun compact-extra-transactions ()
  "The ring's (wtxid . tx) entries in slot order, as InitData walks
vExtraTxnForCompact (blockencodings.cpp:147)."
  (remove nil (coerce *extra-txn-for-compact* 'list)))

(defvar *compact-extra-replaced* nil
  "True while a PEER's transaction is being accepted (Core ProcessValidTx's
callers): every transaction that acceptance replaces joins the ring
(net_processing.cpp:3165-3167). An RPC or wallet replacement does not.")

(bl.vi:define-validation-hook :transaction-removed note-replaced-for-compact-extra
    (tx txid sequence reason)
  (declare (ignore txid sequence))
  (when (and *compact-extra-replaced* (eq reason :replaced))
    (add-to-compact-extra-transactions tx)))

(defun %process-transaction (tx ctx)
  "Core ChainstateManager::ProcessTransaction (validation.cpp:4476-4493) for a
peer's TX: validate it against the active chainstate, admit it, and run the
mempool check after the attempt. Returns (values result reason): result :VALID,
:INVALID with the rejection REASON, or :MEMPOOL-ENTRY for one already in the
pool. A transaction a peer's acceptance REPLACES joins the compact-block extra
pool (*COMPACT-EXTRA-REPLACED*, ProcessValidTx's loop, net_processing.cpp:
3165-3167).

The coins a rejected transaction pulled into the cache are uncached again
(validation.cpp:1787-1790): a peer streaming transactions that fail after
input fetch -- a bad signature suffices -- would otherwise leave one cache
entry per distinct prevout until the next block, ~24,000 for a ~1 MB
transaction."
  (bl.ctx:with-node-context (utxo-set mempool chain-state) ctx
    (let ((height (bl.store:current-height chain-state)))
      (multiple-value-bind (valid error fee replaced sigops)
          (bl.store:with-coins-to-uncache (utxo-set)
            (bl.val:validate-transaction-for-mempool
             tx utxo-set mempool height :chain-state chain-state))
        (if (not valid)
            (progn (bl.val:check-mempool-at-tip mempool utxo-set chain-state)
                   (values :invalid error))
            (let ((result (let ((*compact-extra-replaced* t))
                            (bl.mp:accept-validated-tx
                             mempool (bl.ser:transaction-hash tx) tx fee height
                             :sigops sigops :replaced replaced
                             :chainstate-current (current-for-fee-estimation-p chain-state)))))
              (bl.val:check-mempool-at-tip mempool utxo-set chain-state)
              ;; Admitted by validation and refused by the pool -- mempool
              ;; full, a cluster limit, a conflict -- is a rejection like any
              ;; other: Core's state is invalid then, and MempoolRejectedTx
              ;; caches it (:mempool-full as reconsiderable, validation.cpp:
              ;; 1399-1402).
              (case result
                (:ok (values :valid nil))
                (:duplicate (values :mempool-entry nil))
                (t (values :invalid result)))))))))

(defun process-valid-tx (peer tx ctx)
  "Core ProcessValidTx (net_processing.cpp:3149-3168): TX from PEER entered
the mempool. m_txdownloadman.MempoolAcceptedTx forgets every request for it
and puts the orphans spending it into their announcers' work sets; then it is
relayed, at the fee rate its pool entry carries, to every peer but PEER."
  (bl.ctx:with-node-context (mempool peers) ctx
    (let* ((txid (bl.ser:transaction-hash tx))
           (wtxid (bl.ser:transaction-wtxid tx))
           (entry (bl.mp:mempool-get mempool txid)))
      (txdownload-mempool-accepted-tx (ctx-txdownloadman ctx) tx)
      (bl:log-cat "mempool" "AcceptToMemoryPool: peer=~D: accepted ~A (wtxid=~A) (poolsz ~D txn, ~D kB)"
                  (%tx-peer-node-id peer) (%tx-hex txid) (%tx-hex wtxid)
                  (bl.mp:mempool-count mempool)
                  (floor (bl.mp:mempool-dynamic-usage mempool) 1000))
      (when (and entry peers)
        (let ((vsize (bl.mp:mempool-entry-vsize entry))
              (fee (bl.mp:mempool-entry-fee entry)))
          (relay-transaction txid peer peers
                             :fee-rate-per-kvb (if (plusp vsize) (floor (* 1000 fee) vsize) 0)
                             :wtxid wtxid))))))

(defun process-invalid-tx (peer tx reason first-time-failure ctx)
  "Core ProcessInvalidTx (net_processing.cpp:3122-3147): TX from PEER was
refused for REASON. The line Core logs for every refusal comes first
(p2p_permissions.py:133-138 greps it); m_txdownloadman.MempoolRejectedTx then
records the verdict, and its todo is carried out here: a first-time failure
under 100,000 bytes joins the compact-block extra pool, and the orphan's
missing parents are marked known to PEER -- it just sent a child spending
them, so announcing them back is wasted egress. Returns the 1p1c
PACKAGE-TO-VALIDATE the manager found, or NIL."
  (bl:log-cat "mempoolrej" "~A (wtxid=~A) from peer=~D was not accepted: ~A"
              (%tx-hex (bl.ser:transaction-hash tx))
              (%tx-hex (bl.ser:transaction-wtxid tx))
              (%tx-peer-node-id peer)
              (bl.val:tx-reject-reason-string reason))
  (multiple-value-bind (add-extra parents package)
      (txdownload-mempool-rejected-tx (ctx-txdownloadman ctx)
                                      tx reason peer first-time-failure)
    (when (and add-extra (< (bl.mp:transaction-dynamic-usage tx) 100000))
      (add-to-compact-extra-transactions tx))
    ;; Always by TXID: an orphan's parents are known only by txid, which is
    ;; why Core writes parent_txid into a filter that is otherwise
    ;; wtxid-keyed for a wtxidrelay peer.
    (when (peer-p peer)
      (dolist (parent parents)
        (%mark-tx-known-to-peer peer parent)))
    package))

(defun process-package-result (ptv msg results ctx)
  "Core ProcessPackageResult (net_processing.cpp:3170-3220) for the 1p1c
package PTV, which ProcessNewPackage answered with MSG and the per-transaction
RESULTS (package order). A package that failed is remembered by its hash
(m_txdownloadman.MempoolRejectedPackage), so the same pairing is not
validated again on every re-announcement. The members are walked CHILD
FIRST, so an in-package descendant leaves the orphanage before its parent's
acceptance could put it in a work set; an accepted member takes
ProcessValidTx, a refused or different-witness one ProcessInvalidTx at
first_time_failure=false -- no orphan intake, no further 1p1c, and a child
still missing an input (the nonfinal phase-1 verdict a package-LEVEL failure
leaves it, validation.cpp:1759-1763) is cached nowhere and stays an orphan.
A member with no result -- a context-free package check failed first -- is
skipped, as Core's `it_result != end()' guard skips it."
  (unless (eq msg :success)
    (txdownload-mempool-rejected-package
     (ctx-txdownloadman ctx) (ptv-txns ptv)))
  (loop for tx in (reverse (ptv-txns ptv))
        for sender in (list (ptv-child-sender ptv) (ptv-parent-sender ptv))
        for res in (reverse results)
        do (case (bl.val:package-tx-result-status res)
             (:valid (process-valid-tx sender tx ctx))
             ;; A DIFFERENT_WITNESS result carries a default-constructed
             ;; (TX_RESULT_UNSET) state (validation.h:228-229), which
             ;; MempoolRejectedTx caches in the main filter by wtxid.
             ((:invalid :different-witness)
              (process-invalid-tx sender tx (bl.val:package-tx-result-error res) nil ctx))
             (otherwise nil))))

(defun %process-new-package (ptv ctx)
  "Core's ProcessNewPackage + ProcessPackageResult pair the TX handler runs
for a 1p1c package (net_processing.cpp:4523-4527, :4543-4547)."
  (bl.ctx:with-node-context (utxo-set mempool chain-state) ctx
    (multiple-value-bind (msg results)
        (let ((*compact-extra-replaced* t))
          (bl.val:validate-package-for-mempool (ptv-txns ptv) utxo-set mempool chain-state))
      (bl:log-cat "txpackages" "package evaluation for parent ~A (wtxid=~A, sender=~D) + child ~A (wtxid=~A, sender=~D): ~:[package rejected~;package accepted~]"
                  (%tx-hex (bl.ser:transaction-hash (ptv-parent ptv)))
                  (%tx-hex (bl.ser:transaction-wtxid (ptv-parent ptv)))
                  (%tx-peer-node-id (ptv-parent-sender ptv))
                  (%tx-hex (bl.ser:transaction-hash (ptv-child ptv)))
                  (%tx-hex (bl.ser:transaction-wtxid (ptv-child ptv)))
                  (%tx-peer-node-id (ptv-child-sender ptv))
                  (eq msg :success))
      (process-package-result ptv msg results ctx))))

(defun process-orphan-tx (peer ctx)
  "Core ProcessOrphanTx (net_processing.cpp:3227-3263): take the orphans in
PEER's work set one at a time (m_txdownloadman.GetTxToReconsider) until one of
them is resolved -- accepted, or refused for something other than a missing
input -- and return T, or NIL when the work set ran dry. One resolution per
call is the point: the message loop interleaves it with the peer's messages,
so a parent cannot buy a cascade of re-validations inside one message (\"the
orphan processing used to be uninterruptible and quadratic, which could allow
a peer to stall the node for hours\", :3229-3230). An orphan still missing an
input stays in the orphanage, out of the work set until another parent
arrives."
  (bl.ctx:with-node-context (mempool) ctx
    (when mempool
      (with-current-node-lock
        (loop for orphan = (txdownload-get-tx-to-reconsider (ctx-txdownloadman ctx) peer)
              while orphan
              do (multiple-value-bind (result reason) (%process-transaction orphan ctx)
                   (case result
                     (:valid
                      (bl:log-cat "txpackages" "   accepted orphan tx ~A (wtxid=~A)"
                                  (%tx-hex (bl.ser:transaction-hash orphan))
                                  (%tx-hex (bl.ser:transaction-wtxid orphan)))
                      (process-valid-tx peer orphan ctx)
                      (return t))
                     (:invalid
                      (unless (eq (bl.val:tx-reject-keyword reason) :missing-input)
                        (bl:log-cat "txpackages" "   invalid orphan tx ~A (wtxid=~A) from peer=~D. ~A"
                                    (%tx-hex (bl.ser:transaction-hash orphan))
                                    (%tx-hex (bl.ser:transaction-wtxid orphan))
                                    (%tx-peer-node-id peer)
                                    (bl.val:tx-reject-reason-string reason))
                        (process-invalid-tx peer orphan reason nil ctx)
                        (return t)))))
              finally (return nil))))))

(defun %force-relay-known-tx (peer txid wtxid mempool peers)
  "Core's ForceRelay arm of the TX handler (net_processing.cpp:4509-4521): a
transaction we already have, arriving again from a peer holding ForceRelay, is
relayed onward when it is in the mempool -- \"allowing the node to function as
a gateway for nodes hidden behind it\" -- and reported and dropped when it is
not. Both log lines are Core's own wording; p2p_permissions.py:121 greps for
the first."
  ;; Core's uint256::ToString() order, which is how it spells a transaction in
  ;; both lines.
  (flet ((shown (hash) (bl.crypto:bytes-to-hex (bl.crypto:reverse-bytes hash))))
    (let ((entry (bl.mp:mempool-get mempool txid)))
      (if (null entry)
          (bl:log-info "Not relaying non-mempool transaction ~A (wtxid=~A) from forcerelay peer=~D"
                       (shown txid) (shown wtxid) (peer-id peer))
          (let ((vsize (bl.mp:mempool-entry-vsize entry))
                (fee (bl.mp:mempool-entry-fee entry)))
            (bl:log-info "Force relaying tx ~A (wtxid=~A) from peer=~D"
                         (shown txid) (shown wtxid) (peer-id peer))
            (relay-transaction txid peer peers
                               :fee-rate-per-kvb
                               (if (plusp vsize) (floor (* 1000 fee) vsize) 0)
                               :wtxid wtxid))))))

(define-p2p-handler ("tx" :needs-mempool t) (peer payload ctx)
  "Handle a tx message -- Core's TX branch of ProcessMessage
(net_processing.cpp:4473-4552), in its order: the RejectIncomingTxs and IBD
gates, the parse, AddKnownTx, the private-broadcast check, then
m_txdownloadman.ReceivedTx's verdict. Something it already has is not
validated (a ForceRelay peer's copy is relayed onward if it is in the pool),
and one known to fail reconsiderably may be retried as a 1p1c package with an
orphan child; everything else goes to ProcessTransaction and then
ProcessValidTx or ProcessInvalidTx(first_time_failure=true) -- which, for a
reconsiderable failure, may hand back a package to try at once.

There is no per-peer tx count limit: Core never disconnects a peer for the
NUMBER of transactions it sends, solicited or not. A token bucket we used to
charge here disconnected a peer at its 51st transaction -- first for every tx
message (feature_fee_estimation.py:283-291 lost its relaying peer), then for
unsolicited ones only, which still cut off p2p_opportunistic_1p1c.py:557's
single DoSy peer mid-flood, and the orphans it had announced went with it.
What bounds an unsolicited flood is what bounds it in Core: the orphanage's
per-peer DoS scores (LimitOrphans) and the rejects filters. Nor is a
transaction that fails validation misbehavior: Core removed tx-relay
punishment (PR #26294), since validity is subjective to our mempool and
chain; consensus-invalid transactions are punished only inside a block."
  (bl.ctx:with-node-context (mempool chain-state peers) ctx
  ;; A tx sent where we advertised fRelay=0 (-blocksonly / relay-disabled
  ;; mainnet default, block-relay/feeler conns) violates the protocol:
  ;; disconnect (Core RejectIncomingTxs gate in the TX handler,
  ;; net_processing.cpp:4474-4479). A peer holding the "relay" permission may
  ;; send us transactions even in -blocksonly (Core RejectIncomingTxs,
  ;; net_processing.cpp:5686-5694 — the permission excuses the -blocksonly
  ;; clause and ONLY that clause).
  (when (reject-incoming-txs-p peer)
    (bl:log-cat "net" "transaction sent in violation of protocol, ~A"
                (disconnect-msg peer))
    (disconnect-peer peer)
    (return-from handle-tx nil))
  ;; "Stop processing the transaction early if we are still in IBD since we
  ;; don't have enough information to validate it yet. Sending unsolicited
  ;; transactions is not considered a protocol violation, so don't punish the
  ;; peer" (net_processing.cpp:4479-4483) — before the parse, and with no
  ;; reject reason, no rejects-cache entry and no orphan intake, exactly as
  ;; Core returns there. The same predicate gates the inv half.
  (when (initial-block-download-p chain-state)
    (return-from handle-tx nil))
  ;; No catch here: Core deserializes the transaction inside ProcessMessage
  ;; (`vRecv >> TX_WITH_WITNESS(ptx)', net_processing.cpp:4486), and an
  ;; undecodable one -- an unknown witness flag is `Unknown transaction
  ;; optional data' (primitives/transaction.h:235) -- reaches ProcessMessages'
  ;; catch, which logs it and keeps the peer (SAFELY-DISPATCH-PEER-MESSAGE).
  ;; p2p_segwit.py:1984 waits for that line.
  (let ((tx (bl.ser:parse-tx-payload payload)))
    (when tx
      (with-current-node-lock
        (let ((txid (bl.ser:transaction-hash tx))
              (wtxid (bl.ser:transaction-wtxid tx)))
          ;; The peer knows this transaction: it just sent it to us. Core
          ;; AddKnownTx(peer, peer.m_wtxid_relay ? wtxid : txid),
          ;; net_processing.cpp:4491-4492 -- keyed by the id THIS peer's
          ;; inventory uses, which is what the relay path looks up.
          (%mark-tx-known-to-peer peer (%peer-inv-hash peer txid wtxid))
          ;; One of ours we are broadcasting privately came back from the
          ;; network: stop (net_processing.cpp:4494-4503).
          (note-own-tx-received-back peer tx)
          (multiple-value-bind (should-validate package)
              (txdownload-received-tx (ctx-txdownloadman ctx) peer tx)
            (unless should-validate
              ;; A ForceRelay peer's copy of something we already have is
              ;; relayed onward anyway, so \"the node can function as a
              ;; gateway for nodes hidden behind it\" (:4508-4521).
              (when (peer-has-permission-p peer +perm-force-relay+)
                (%force-relay-known-tx peer txid wtxid mempool peers))
              (when package
                (%process-new-package package ctx))
              (return-from handle-tx nil))
            (multiple-value-bind (result reason) (%process-transaction tx ctx)
              (case result
                (:valid
                 (process-valid-tx peer tx ctx)
                 ;; getpeerinfo "last_transaction" (Core m_last_tx_time,
                 ;; stamped only on ACCEPTANCE, net_processing.cpp:4540).
                 (setf (peer-last-tx-time peer) (bl.ser:get-unix-time)))
                (:invalid
                 (let ((package (process-invalid-tx peer tx reason t ctx)))
                   (when package
                     (%process-new-package package ctx)))))))))))))

(defconstant +stale-relay-age-limit+ (* 30 24 60 60)
  "Core STALE_RELAY_AGE_LIMIT (net_processing.cpp:117): a block NOT on the
active chain is served only while it is younger than a month. Serving an
arbitrarily old side-chain block on request is a fingerprinting oracle — it
tells the asker exactly which forks this node witnessed and kept.")

(defconstant +node-network-limited-min-blocks+ 288
  "Core NODE_NETWORK_LIMITED_MIN_BLOCKS (net_processing.cpp:154): a
NODE_NETWORK_LIMITED peer promises the last 288 blocks and nothing more.")

(defun %block-request-allowed-p (chain-state entry best-header)
  "Core PeerManagerImpl::BlockRequestAllowed (net_processing.cpp:1953-1960).

A block on the ACTIVE chain is always servable. Anything else is servable only
while it is recent by BOTH measures — wall-clock age and work-equivalent age —
because an old side-chain block is a fingerprint, not a service."
  (let* ((height (bl.store:block-index-entry-height entry))
         (active (bl.store:get-block-at-height chain-state height)))
    (when (and active
               (equalp (bl.store:block-index-entry-hash active)
                       (bl.store:block-index-entry-hash entry)))
      (return-from %block-request-allowed-p t))
    (let ((header (bl.store:block-index-entry-header entry))
          (best-hdr (and best-header
                         (bl.store:block-index-entry-header best-header))))
      (and header best-hdr
           ;; Core requires BLOCK_VALID_SCRIPTS, i.e. the block was fully
           ;; validated at some point; :valid is our equivalent. In Core that
           ;; is a MONOTONE property -- DisconnectTip never lowers nStatus --
           ;; so a block reorged off the chain stays servable, which is what
           ;; p2p_fingerprint.py:93 asks for. Ours used to downgrade a
           ;; disconnected block to :header-valid, and the fingerprint test
           ;; got "ignoring request ... for an old block that is not on
           ;; the main chain" for a block it had just watched us validate.
           (eq (bl.store:block-index-entry-status entry) :valid)
           (< (- (bl.ser:block-header-timestamp best-hdr)
                 (bl.ser:block-header-timestamp header))
              +stale-relay-age-limit+)
           (< (bl.store:block-proof-equivalent-time best-header entry best-header)
              +stale-relay-age-limit+)))))

(defun %below-network-limited-threshold-p (chain-state entry &optional peer)
  "T when serving ENTRY to PEER would leak our prune height (Core
net_processing.cpp:2385-2392).

A PEER holding the noban permission is exempt, as Core's
`!pfrom.HasPermission(NetPermissionFlags::NoBan) && (...)' makes it: an
operator who whitelisted a peer is not hiding the prune height from it, and a
refusal would disconnect a peer we promised never to punish.

A node advertising NODE_NETWORK_LIMITED without NODE_NETWORK promises the last
288 blocks. Answering for anything deeper tells the asker how much history this
node actually kept — which is its prune configuration. Core's two-block buffer
is kept: without it a race against a tip advance turns a legitimate request
into a disconnect."
  (let ((services (local-services)))
    (and (not (and peer (peer-has-permission-p peer +perm-noban+)))
         (plusp (logand services bl.ser:+node-network-limited+))
         (zerop (logand services bl.ser:+node-network+))
         (let ((tip-height (bl.store:chain-state-best-height chain-state))
               (height (bl.store:block-index-entry-height entry)))
           (> (- tip-height height) (+ +node-network-limited-min-blocks+ 2))))))

(defconstant +max-blocks-served-per-getdata+ 500
  "Cap on full blocks served from a single getdata message. A well-behaved peer
requests at most ~16 blocks in flight (and up to 500 after a getblocks inv); this
bounds the disk-read/serialize/send work a single message can demand, since a
getdata can carry up to MAX_INV_SZ (50000) entries.")

(defconstant +max-cmpctblock-depth+ 5
  "Core MAX_CMPCTBLOCK_DEPTH (net_processing.cpp:138): a MSG_CMPCT_BLOCK
request for a block deeper than this below the tip is answered with the full
block instead. A peer asking for old blocks is almost certainly unable to
reconstruct one — its mempool holds nothing that old — so building the compact
form would waste the work on both ends.")

(defun %can-direct-fetch-p (chain-state)
  "Core CanDirectFetch (net_processing.cpp:1347): our tip is younger than 20
block intervals. The depth rule below is expressed relative to OUR tip, so it
only means \"a recent block\" while this holds — on a node in IBD or catching
up, five blocks below a stale tip can be years old, which is exactly the case
Core refuses to build a compact block for."
  (let* ((tip-hash (bl.store:best-block-hash chain-state))
         (tip (and tip-hash (bl.store:get-block-index-entry
                             chain-state tip-hash))))
    (and tip
         (> (bl.ser:block-header-timestamp
             (bl.store:block-index-entry-header tip))
            (- (bl.ser:get-unix-time)
               (* 20 (block-interval-seconds)))))))

(defun %serve-compact-p (chain-state entry)
  "T when a MSG_CMPCT_BLOCK request for ENTRY should be answered compactly:
our tip is recent AND ENTRY is within +max-cmpctblock-depth+ of it (Core
net_processing.cpp:2468). A peer asking for anything older is almost certainly
unable to reconstruct it — its mempool holds nothing that old — so the compact
form would waste the construction on both ends."
  (and entry
       (%can-direct-fetch-p chain-state)
       (>= (bl.store:block-index-entry-height entry)
           (- (bl.store:current-height chain-state)
              +max-cmpctblock-depth+))))

(defconstant +historical-block-age-seconds+ (* 7 24 60 60)
  "A block older than this (relative to our best header) is \"historical\" for
the -maxuploadtarget serving limit (Core HISTORICAL_BLOCK_AGE,
net_processing.cpp:120).")

(defun %serve-filtered-block (peer block)
  "Answer a MSG_FILTERED_BLOCK getdata (Core ProcessGetBlockData,
net_processing.cpp:2440-2458): with a bloom filter loaded, the merkleblock
the filter selects and then every matched transaction, witness-stripped, so
the client need not ask for them; with none, nothing at all."
  (let ((filter (peer-bloom-filter peer)))
    (when filter
      (multiple-value-bind (payload matched) (make-merkle-block block filter)
        (send-message peer (bl.ser:serialize-message "merkleblock" payload))
        (let ((txs (coerce (bl.ser:bitcoin-block-transactions block) 'vector)))
          (dolist (m matched)
            (send-message peer (bl.ser:make-tx-message (aref txs (car m)) :witness nil))))))))

(defun %inv-vector-description (inv)
  "One inv as Core's CInv::ToString prints it -- `<type> <hash>'
(protocol.cpp:58-84). The type name is Core's own spelling, the
MSG_WITNESS_FLAG bit shows as a `witness-' prefix, an unknown type falls back
to `0x%08x', and the hash is in uint256 display order."
  (let* ((type (bl.ser:inv-vector-type inv))
         (witness (logtest type (ash 1 30)))
         (masked (logand type (lognot (ash 1 30))))
         (name (cond ((= masked bl.ser:+inv-type-tx+) "tx")
                     ((= masked bl.ser:+inv-type-wtx+) "wtx")
                     ((= masked bl.ser:+inv-type-block+) "block")
                     ((= masked bl.ser:+inv-type-filtered-block+) "merkleblock")
                     ((= masked bl.ser:+inv-type-cmpct-block+) "cmpctblock")
                     (t nil))))
    (format nil "~A ~A"
            (if name
                (concatenate 'string (if witness "witness-" "") name)
                (format nil "0x~8,'0X" type))
            (bl.crypto:bytes-to-hex
             (bl.crypto:reverse-bytes (bl.ser:inv-vector-hash inv))))))

(defun queue-getdata (peer invs)
  "Append INVS to PEER's pending getdata queue, oldest first (Core
peer.m_getdata_requests.insert / push_back, net_processing.cpp:4260 and
:4389). INVS is a fresh list in both callers, so it is spliced rather than
copied."
  (setf (peer-getdata-queue peer)
        (nconc (peer-getdata-queue peer) invs)))

(define-p2p-handler ("getdata") (peer payload ctx)
  "Handle a getdata message: append every requested inv to the peer's pending
getdata queue and serve what we can right now (Core's GETDATA branch,
net_processing.cpp:4258-4262 — the insert and the ProcessGetData call are one
step). PROCESS-PEER-GETDATA is the serving half and the resume point.

No rate bucket. Core places NO limit at all on INCOMING getdata beyond the
message-size cap -- MAX_GETDATA_SZ is 1000 and its own comment says it is `not
used in processing incoming GETDATA for compatibility\' (net_processing.cpp:
127-128). The bound Core relies on is the one PROCESS-PEER-GETDATA already
enforces: a peer whose send buffer is over -maxsendbuffer is send-paused and
served nothing more until it drains. A token bucket on TOP of that disconnects
a peer for asking for exactly what this node announced to it, which is what a
node doing its job looks like from the other side."
  (let ((invs (bl.ser:parse-inv-payload payload)))
    ;; Core's two lines, in Core's order (net_processing.cpp:4224-4229): the
    ;; count, then the FIRST entry spelled out. p2p_blocksonly.py:64 waits on
    ;; the second under assert_debug_log, and it is the only place the log says
    ;; WHAT a peer asked for -- the generic `received: getdata (N bytes)' line
    ;; above it names a byte count and nothing else.
    (bl:log-cat "net" "received getdata (~D invsz) peer=~A"
                (length invs) (peer-id peer))
    (when invs
      (bl:log-cat "net" "received getdata for: ~A peer=~A"
                  (%inv-vector-description (first invs)) (peer-id peer)))
    (queue-getdata peer invs))
  (process-peer-getdata peer ctx))

(defun process-peer-getdata (peer ctx)
  "Serve PEER's pending getdata queue (Core ProcessGetData,
net_processing.cpp:2517-2589). Responds with the requested transactions or
blocks; a tx request is ignored entirely when relay is disabled (mainnet
default) or the peer has no tx-relay state, and blocks are served from
BLOCK-STORE — MSG_BLOCK legacy, MSG_WITNESS_BLOCK with witness — so the node
is a serving peer, not just a leech. A requested block we do not have on disk
(pruned or unknown) is silently skipped, like Bitcoin Core's handling of
unavailable blocks.

Called from HANDLE-GETDATA and, for whatever a send-paused peer left behind,
from DRAIN-AND-REAP-PEER before it decides whether to read that peer at all."
  (bl.ctx:with-node-context (chain-state mempool block-store) ctx
  (let ((blocks-served 0)
        (not-found '())
        ;; Read at most once per getdata, and only if an off-chain block is
        ;; actually asked for, as Core reads m_best_header once per request.
        (best-header :unset))
    (flet ((best-header ()
             (when (eq best-header :unset)
               (setf best-header
                     (and chain-state
                          (bl.store:best-header-entry chain-state))))
             best-header))
    (loop
      ;; Serve from the front of the queue and stop while the peer is
      ;; send-paused (its outgoing buffer is over the cap) — Core breaks out
      ;; of ProcessGetData on fPauseSend (net_processing.cpp:2532-2536,
      ;; :2558) and erases only the prefix it answered
      ;; (net_processing.cpp:2570), so the rest waits in m_getdata_requests
      ;; until the buffer drains. Popping as we go leaves exactly that
      ;; remainder on the peer, whichever branch below ends the pass. The
      ;; notfound for what WAS processed still goes out at the end, as in Core.
      (let ((conn (peer-connection peer)))
        (when (or (null (peer-getdata-queue peer))
                  (and conn (connection-send-paused-p conn)))
          (return)))
      (let* ((inv (pop (peer-getdata-queue peer)))
             (inv-type (bl.ser:inv-vector-type inv))
             (hash (bl.ser:inv-vector-hash inv)))
        (cond
          ;; Transaction request - only respond if relay is enabled. Resolve the
          ;; hash by the id its inv type implies: MSG_TX by txid (legacy
          ;; serialization), MSG_WITNESS_TX by txid (witness serialization),
          ;; MSG_WTX by wtxid (BIP339, witness serialization). We also accept a
          ;; wtxid under MSG_WITNESS_TX: our pre-BIP339-fix versions announced
          ;; wtxids under that type, and txids and wtxids never collide, so
          ;; trying both is safe (kept for peers echoing those old requests).
          ((or (= inv-type bl.ser:+inv-type-tx+)
               (= inv-type bl.ser:+inv-type-witness-tx+)
               (= inv-type bl.ser:+inv-type-wtx+))
           (cond
             ;; No tx-relay state with this peer (its version had fRelay=0, or
             ;; a block-relay/feeler conn): ignore the request entirely — not
             ;; even a notfound (Core ProcessGetData's `tx_relay == nullptr`
             ;; continue, net_processing.cpp:2539-2543).
             ((not (peer-tx-relay-p peer)))
             (t
              (let* ((entry (when (and mempool (relay-enabled-p))
                              (cond
                                ((= inv-type bl.ser:+inv-type-wtx+)
                                 (bl.mp:mempool-get-by-wtxid mempool hash))
                                ((= inv-type bl.ser:+inv-type-tx+)
                                 (bl.mp:mempool-get mempool hash))
                                (t
                                 (or (bl.mp:mempool-get mempool hash)
                                     (bl.mp:mempool-get-by-wtxid mempool hash))))))
                     ;; Anti-probing gate (Core FindTxForGetData ->
                     ;; info_for_relay, net_processing.cpp:2496-2505): serve a
                     ;; mempool tx only if it entered the pool BEFORE our last
                     ;; inv flush to this peer — i.e. we could already have
                     ;; announced it. A getdata for anything newer reveals the
                     ;; peer is probing mempool contents: notfound.
                     (tx (cond
                           ((and entry
                                 (< (bl.mp:mempool-entry-sequence entry)
                                    (peer-last-inv-sequence peer)))
                            (bl.mp:mempool-entry-transaction entry))
                           ;; Or it might be from the most recent block (Core
                           ;; m_most_recent_block_txs, keyed by txid AND
                           ;; wtxid) — freshly-confirmed txs stay servable.
                           (t (bl.val:most-recent-block-tx hash)))))
                (cond
                  (tx
                   (send-message peer
                                 (bl.ser:make-tx-message
                                  tx
                                  :witness (/= inv-type bl.ser:+inv-type-tx+)))
                   ;; A peer requesting the tx is the proof our announcement
                   ;; propagated: drop it from the unbroadcast set (Core
                   ;; ProcessGetData, net_processing.cpp:2550 — on EVERY
                   ;; successful serve, either source).
                   (when mempool
                     (bl.mp:mempool-remove-unbroadcast
                      mempool
                      (bl.ser:transaction-hash tx))))
                  (t
                   ;; Core accumulates vNotFound for txs it can't serve so the
                   ;; requester re-routes immediately instead of timing out.
                   (push inv not-found)))))))
          ;; Block request — served from disk (witness-aware). MSG_CMPCT_BLOCK
          ;; takes the same path and the same guards, as Core's
          ;; ProcessGetBlockData does, and differs only in what is sent.
          ((or (= inv-type bl.ser:+inv-type-block+)
               (= inv-type bl.ser:+inv-type-witness-block+)
               (= inv-type bl.ser:+inv-type-filtered-block+)
               (= inv-type bl.ser:+inv-type-cmpct-block+))
           (when (and block-store (< blocks-served +max-blocks-served-per-getdata+))
             (let ((entry (and chain-state
                               (bl.store:get-block-index-entry
                                chain-state hash))))
               (cond
                 ;; Unknown to the index: nothing to reason about, and Core's
                 ;; ProcessGetBlockData returns before any serving.
                 ((and chain-state (null entry)))
                 ;; Anti-fingerprinting: an old block off the active chain is
                 ;; not served at all (Core BlockRequestAllowed).
                 ((and entry (not (%block-request-allowed-p chain-state entry
                                                            (best-header))))
                  (bl:log-cat
                   "net" "getdata: ignoring request from ~A for an old ~
                          block that is not on the main chain"
                   (peer-log-name peer)))
                 ;; -maxuploadtarget: stop serving HISTORICAL blocks once the
                 ;; 24h budget (less a buffer big enough to still relay every
                 ;; new block) is spent, and disconnect the asker — Core
                 ;; net_processing.cpp:2376-2383. Only blocks older than a week
                 ;; relative to our best header count as historical, so a peer
                 ;; following the tip is unaffected, and a peer holding the
                 ;; "download" permission may exceed the target outright.
                 ((and entry
                       (bl.net:outbound-target-reached-p t)
                       (not (peer-has-permission-p peer +perm-download+))
                       (let ((best (best-header)))
                         (flet ((btime (e)
                                  (let ((h (bl.store:block-index-entry-header e)))
                                    (and h (bl.ser:block-header-timestamp h)))))
                           (let ((bt (and best (btime best)))
                                 (et (btime entry)))
                             (or (= inv-type bl.ser:+inv-type-filtered-block+)
                                 (and bt et
                                      (> (- bt et) +historical-block-age-seconds+)))))))
                  (bl:log-cat "net" "historical block serving limit reached, ~A"
                              (disconnect-msg peer))
                  (disconnect-peer peer)
                  (return))
                 ;; Prune-height leak: refuse AND disconnect, as Core does —
                 ;; a peer left waiting for a block we will never send stalls
                 ;; instead of re-routing the request.
                 ((and entry (%below-network-limited-threshold-p chain-state entry peer))
                  (bl:log-cat
                   "net" "Ignore block request below NODE_NETWORK_LIMITED ~
                          threshold, ~A"
                   (disconnect-msg peer))
                  (disconnect-peer peer)
                  (return))
                 (t
                  (let ((block (bl.store:get-block block-store hash))
                        ;; Only the legacy MSG_BLOCK is witness-stripped;
                        ;; MSG_WITNESS_BLOCK and the full-block fallback for
                        ;; MSG_CMPCT_BLOCK both carry witnesses (Core
                        ;; ProcessGetBlockData, TX_WITH_WITNESS).
                        (witnessed (/= inv-type
                                       bl.ser:+inv-type-block+)))
                    (when (and block (= inv-type bl.ser:+inv-type-filtered-block+))
                      (incf blocks-served)
                      (%serve-filtered-block peer block)
                      (setf block nil))
                    (when block
                      (incf blocks-served)
                      (send-message
                       peer
                       (if (and (= inv-type
                                   bl.ser:+inv-type-cmpct-block+)
                                (%serve-compact-p chain-state entry))
                           ;; Cached when this is the tip we just connected —
                           ;; N peers asking for the same new block cost one
                           ;; construction (Core m_most_recent_compact_block).
                           (or (bl.val:most-recent-cmpctblock hash)
                               (bl.ser:make-cmpctblock-message block))
                           (bl.ser:make-block-message
                            block :witness witnessed)))))))))))))
    ;; One notfound for every unserved tx request (Core sends notfound for txs
    ;; only, never blocks).
    (when not-found
      (send-message peer (bl.ser:make-notfound-message
                          (nreverse not-found))))))))

(defconstant +max-getcfilters-size+ 1000
  "Max filters per getcfilters request (Core MAX_GETCFILTERS_SIZE).")
(defconstant +max-getcfheaders-size+ 2000
  "Max headers per getcfheaders request (Core MAX_GETCFHEADERS_SIZE).")
(defconstant +cfcheckpt-interval+ 1000
  "Block spacing of cfcheckpt filter headers (Core CFCHECKPT_INTERVAL).")

(defun %cf-serving-index ()
  "The block filter index to serve BIP157 requests from, or NIL when serving is
off (-peerblockfilters absent) or the index is unavailable."
  (and bl:*peer-block-filters*
       bl:*node*
       (let ((bfi (bl:node-blockfilterindex bl:*node*)))
         (and bfi (bl.store:blockfilterindex-enabled bfi) bfi))))

(defun %prepare-block-filter-request (peer chain-state filter-type start-height
                                      stop-hash max-height-diff)
  "Core PrepareBlockFilterRequest (net_processing.cpp:3265-3316): the stop
block's index entry and the filter index to answer from, as two values, or NIL
when the request is not served. In Core's order, each refusal but the last
DISCONNECTS the peer with Core's debug line: a filter type other than basic,
or any type when we do not offer this peer NODE_COMPACT_FILTERS; a stop hash
that is unknown or that BlockRequestAllowed would not serve (a recent stale
block IS served -- p2p_blockfilters.py:116 asks for one); a start height above
the stop height; a span of MAX-HEIGHT-DIFF blocks or more. A missing filter
index answers nothing.

We used to serve the active chain only and drop every bad request silently,
so a light client that asked a wrong question waited forever instead of being
told by the disconnect."
  (flet ((refuse (control &rest args)
           (bl:log-cat "net" "~?, ~A" control args (disconnect-msg peer))
           (disconnect-peer peer)
           (return-from %prepare-block-filter-request nil)))
    (unless (and (eql filter-type 0)
                 (logtest (peer-our-services peer) bl.ser:+node-compact-filters+))
      (refuse "peer requested unsupported block filter type: ~D" filter-type))
    (let ((stop (bl.store:get-block-index-entry chain-state stop-hash)))
      (unless (and stop (%block-request-allowed-p
                         chain-state stop (bl.store:best-header-entry chain-state)))
        (refuse "peer requested invalid block hash: ~A"
                (bl.crypto:bytes-to-hex (bl.crypto:reverse-bytes stop-hash))))
      (let ((stop-height (bl.store:block-index-entry-height stop)))
        (when (> start-height stop-height)
          (refuse "peer sent invalid getcfilters/getcfheaders with start height ~D ~
and stop height ~D" start-height stop-height))
        (when (>= (- stop-height start-height) max-height-diff)
          (refuse "peer requested too many cfilters/cfheaders: ~D / ~D"
                  (1+ (- stop-height start-height)) max-height-diff)))
      (let ((bfi (%cf-serving-index)))
        (if bfi
            (values stop bfi)
            (bl:log-cat "net" "Filter index for supported type basic not found"))))))

(defun %cf-chain-accessor (chain-state stop)
  "A function from a height to the hash of STOP's ancestor there, or NIL (Core
GetAncestor, as LookupFilterRange and ProcessGetCFCheckPt use it), so a stale
stop block is
answered from its own branch. The branch below STOP is walked once, down to
where it rejoins the active chain; every height at or below that is an O(1)
active-chain lookup, which keeps a getcfcheckpt at the mainnet tip from
walking the whole chain."
  (let ((branch '())
        (e stop))
    (loop while (and e (not (bl.store:entry-on-active-chain-p chain-state e)))
          do (push e branch)
             (setf e (bl.store:block-index-entry-prev-entry e)))
    (let ((fork-height (if e (bl.store:block-index-entry-height e) -1))
          (branch (coerce branch 'vector)))
      (lambda (height)
        (let ((entry (if (<= height fork-height)
                         (bl.store:get-block-at-height chain-state height)
                         (let ((i (- height fork-height 1)))
                           (and (< -1 i (length branch)) (aref branch i))))))
          (and entry (bl.store:block-index-entry-hash entry)))))))

(defun %cf-range-filters (at bfi start-height stop-height)
  "((hash . filter) ...) for every height START-HEIGHT..STOP-HEIGHT through the
ancestor accessor AT, or NIL when any filter is missing -- Core's
LookupFilterRange / LookupFilterHashRange, which fail the whole request then."
  (loop for h from start-height to stop-height
        for bh = (funcall at h)
        for filter = (and bh (bl.store:blockfilterindex-get-filter bfi bh h))
        unless filter do (return nil)
        collect (cons bh filter)))

(define-p2p-handler "getcfilters" (peer payload ctx)
  "Serve a BIP157 getcfilters (Core ProcessGetCFilters, net_processing.cpp:
3318-3344): one cfilter per block from START-HEIGHT to the stop block, along
the stop block's chain, or nothing when a filter is missing."
  (bl.ctx:with-node-context (chain-state) ctx
    (multiple-value-bind (ftype start-height stop-hash)
        (bl.ser:parse-getcfilters-payload payload)
      (multiple-value-bind (stop bfi)
          (%prepare-block-filter-request peer chain-state ftype start-height
                                         stop-hash +max-getcfilters-size+)
        (when stop
          (loop for (bh . filter)
                  in (%cf-range-filters (%cf-chain-accessor chain-state stop) bfi
                                        start-height (bl.store:block-index-entry-height stop))
                do (send-message peer (bl.ser:make-cfilter-message 0 bh filter))))))))

(define-p2p-handler "getcfheaders" (peer payload ctx)
  "Serve a BIP157 getcfheaders (Core ProcessGetCFHeaders, net_processing.cpp:
3346-3386): the filter header of the stop block's ancestor at START-1 (zeros
at genesis) plus the filter HASHES from START-HEIGHT to the stop block."
  (bl.ctx:with-node-context (chain-state) ctx
    (multiple-value-bind (ftype start-height stop-hash)
        (bl.ser:parse-getcfilters-payload payload)
      (multiple-value-bind (stop bfi)
          (%prepare-block-filter-request peer chain-state ftype start-height
                                         stop-hash +max-getcfheaders-size+)
        (when stop
          (let* ((at (%cf-chain-accessor chain-state stop))
                 (prev-header
                   (if (plusp start-height)
                       (let ((ph (funcall at (1- start-height))))
                         (or (and ph (bl.store:blockfilterindex-get-header
                                      bfi ph (1- start-height)))
                             (return-from handle-getcfheaders)))
                       (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
                 (filters (%cf-range-filters at bfi start-height
                                             (bl.store:block-index-entry-height stop))))
            (when filters
              (send-message
               peer (bl.ser:make-cfheaders-message
                     0 stop-hash prev-header
                     (mapcar (lambda (f) (bl.crypto:hash256 (cdr f))) filters))))))))))

(define-p2p-handler "getcfcheckpt" (peer payload ctx)
  "Serve a BIP157 getcfcheckpt (Core ProcessGetCFCheckPt, net_processing.cpp:
3388-3421): the filter header at every 1000th height of the stop block's
chain, up to the stop block."
  (bl.ctx:with-node-context (chain-state) ctx
    (multiple-value-bind (ftype stop-hash)
        (bl.ser:parse-getcfcheckpt-payload payload)
      (multiple-value-bind (stop bfi)
          (%prepare-block-filter-request peer chain-state ftype 0 stop-hash
                                         (1- (expt 2 32)))
        (when stop
          (let* ((at (%cf-chain-accessor chain-state stop))
                 (headers
                  (loop for h from +cfcheckpt-interval+
                          to (bl.store:block-index-entry-height stop)
                          by +cfcheckpt-interval+
                        for bh = (funcall at h)
                        collect (or (and bh (bl.store:blockfilterindex-get-header bfi bh h))
                                    (return-from handle-getcfcheckpt)))))
            (send-message
             peer (bl.ser:make-cfcheckpt-message 0 stop-hash headers))))))))

(defconstant +max-blocktxn-depth+ 10
  "Core MAX_BLOCKTXN_DEPTH (net_processing.cpp:140). Deeper than this we refuse
to build a blocktxn and send the whole block instead.")

(define-p2p-handler "getblocktxn" (peer payload ctx)
  "Serve a BIP152 getblocktxn: reply with a blocktxn carrying the requested
transactions (by index, witness-serialized) from the named block. This is the
serve side of compact-block relay — without it a peer reconstructing one of our
compact blocks can't fetch the txs it's missing. Skipped if we don't have the
block on disk (the peer falls back to a full getdata). An out-of-range index is
a malformed request: record misbehavior and don't reply.

DEPTH: Core serves a blocktxn only within MAX_BLOCKTXN_DEPTH (10) of the tip
and otherwise sends the full block, for a reason its own comment states
(net_processing.cpp:4380-4387):

  Sending a full block response instead of a small blocktxn response is
  preferable in the case where a peer might maliciously send lots of
  getblocktxn requests to trigger expensive disk reads, because it will
  require the peer to actually receive all the data read from disk over
  the network.

We had no depth test. Every historical block hash is public and GET-BLOCK has
no cache, so ~40 wire bytes bought a random-file open, a full read and a full
parse of up to a 4 MB block for a ~250-byte reply — and the pump grants each
peer 32 messages per pass on the same thread that runs block validation. This
is the one serving path where reply size is decoupled from work done; getdata
for blocks is self-limiting because the sender must push the bytes.

The test must run BEFORE GET-BLOCK, or the read it exists to prevent has
already happened. With no CHAIN-STATE we cannot judge depth, so we fall back to
sending the whole block — never to a free deep read."
  (bl.ctx:with-node-context (block-store chain-state) ctx
  (when block-store
    (let* ((req (bl.ser:parse-getblocktxn-payload payload))
           (block-hash (bl.ser:block-txn-request-block-hash req))
           (indexes (bl.ser:block-txn-request-indexes req))
           (entry (and chain-state
                       (bl.store:get-block-index-entry chain-state block-hash)))
           (tip-height (and chain-state (bl.store:current-height chain-state)))
           (within-depth
             (and entry tip-height
                  (>= (bl.store:block-index-entry-height entry)
                      (- tip-height +max-blocktxn-depth+)))))
      (unless within-depth
        ;; Core pushes a full MSG_WITNESS_BLOCK onto the peer's getdata queue
        ;; and returns (net_processing.cpp:4387-4390, "the message processing
        ;; loop will go around again ... and we will respond then"), so the
        ;; block goes out through the getdata path and inherits its
        ;; backpressure instead of needing its own copy of it. Sending here
        ;; would trade a disk-read DoS for a queue one — a peer that never
        ;; drains could make us read and serialize 4 MB blocks that then pile
        ;; up in memory.
        (bl:log-cat "net" "Peer ~A sent us a getblocktxn for a block > ~D deep"
                    (peer-id peer) +max-blocktxn-depth+)
        (queue-getdata peer (list (bl.ser:make-inv-vector
                                   :type bl.ser:+inv-type-witness-block+
                                   :hash block-hash)))
        (process-peer-getdata peer ctx)
        (return-from handle-getblocktxn nil))
      (let ((block (bl.store:get-block block-store block-hash)))
      (when block
        (let* ((txs (coerce (bl.ser:bitcoin-block-transactions block)
                            'vector))
               (n (length txs)))
          (if (every (lambda (i) (and (>= i 0) (< i n))) indexes)
              (send-message peer
                            (bl.ser:make-blocktxn-message
                             block-hash
                             (mapcar (lambda (i) (aref txs i)) indexes)
                             :witness t))
              (record-misbehavior peer "getblocktxn with out-of-bounds tx indices")))))))))

;;; Serving headers / blocks / addresses to peers
;;;
;;; The responder side of getheaders/getblocks/getaddr, mirroring Bitcoin Core's
;;; net_processing handlers so other nodes can sync headers, blocks, and peer
;;; addresses from us.

(defconstant +getblocks-inv-limit+ 500
  "Maximum block hashes returned in an inv answering a getblocks (Bitcoin Core).")

(defun zero-hash-p (hash)
  "T if HASH is the all-zero stop hash (meaning 'no stop, send the maximum')."
  (every #'zerop hash))

(defun truncate-entries-at-stop (entries stop-hash inclusivep)
  "Truncate the ascending block-index-entry list ENTRIES at the entry whose hash
equals STOP-HASH. When INCLUSIVEP the stop entry is kept (getheaders semantics),
otherwise it is dropped (getblocks). A null/all-zero STOP-HASH means 'no stop',
returning ENTRIES whole; a STOP-HASH not present in ENTRIES also returns all."
  (if (or (null stop-hash) (zero-hash-p stop-hash))
      entries
      (let ((tail (member stop-hash entries
                          :key #'bl.store:block-index-entry-hash
                          :test #'equalp)))
        (cond ((null tail) entries)
              (inclusivep (ldiff entries (cdr tail)))
              (t (ldiff entries tail))))))

(defun getheaders-response-message (payload chain-state)
  "Build the headers message answering a getheaders PAYLOAD: up to
+max-headers-count+ headers from our active chain just after the locator's fork
point — or just the stop block's header when the locator is empty. Returns a
serialized headers message (empty when we have nothing to add), or NIL when
Core sends nothing at all. The second value is what Core then records as the
peer's pindexBestHeaderSent (net_processing.cpp:4455-4468): the last header
sent, or our tip when the answer is empty -- \"we might have announced the
block being connected with a compact block\", so it is RESET, never maxed.
Mirrors Bitcoin Core's GETHEADERS handler (net_processing.cpp:4426-4470)."
  (multiple-value-bind (locator-hashes stop-hash)
      (bl.ser:parse-block-locator-payload payload)
    (when (null locator-hashes)
      ;; Null locator: Core answers with the stop block's header alone, and
      ;; RETURNS -- sending no message whatsoever -- when it does not know the
      ;; block or BlockRequestAllowed refuses it (:4429-4436). The gate is the
      ;; same one the getdata path uses, so a RECENT stale block is served
      ;; here too; asking only "is it on the active chain" refused a block
      ;; this node had just reorged away from, which is what
      ;; p2p_fingerprint.py:97 waits for.
      (let ((entry (bl.store:get-block-index-entry chain-state stop-hash)))
        (return-from getheaders-response-message
          (when (and entry
                     (%block-request-allowed-p
                      chain-state entry (bl.store:best-header-entry chain-state)))
            (values (bl.ser:make-headers-message
                     (list (bl.store:block-index-entry-header entry)))
                    stop-hash)))))
    ;; Walk forward from the fork point, stop hash inclusive.
    (let* ((fork (bl.store:find-fork-in-active-chain
                  chain-state locator-hashes))
           (entries (bl.store:active-chain-entries-from
                     chain-state
                     (1+ (bl.store:block-index-entry-height fork))
                     bl.ser:+max-headers-count+))
           (sent (truncate-entries-at-stop entries stop-hash t)))
      (values (bl.ser:make-headers-message
               (mapcar #'bl.store:block-index-entry-header sent))
              (if sent
                  (bl.store:block-index-entry-hash (car (last sent)))
                  (bl.store:best-block-hash chain-state))))))

(define-p2p-handler "getheaders" (peer payload ctx)
  "Serve a peer's getheaders by sending the headers message built from PAYLOAD
against our active chain (see getheaders-response-message). NIL means Core
sends nothing at all -- a null-locator request for a block we do not know or
may not serve."
  (bl.ctx:with-node-context (chain-state) ctx
  (multiple-value-bind (msg best-sent)
      (getheaders-response-message payload chain-state)
    (when msg
      ;; PeerHasHeader reads this: after a getheaders at our tip, the next
      ;; block's parent is known to the peer, so it is announced as a header
      ;; (p2p_sendheaders.py:300-309).
      (setf (peer-best-header-sent-hash peer) best-sent)
      (send-message peer msg)))))

(defun getblocks-response-message (payload chain-state)
  "Build the inv message answering a getblocks PAYLOAD: up to
+getblocks-inv-limit+ block hashes from our active chain after the locator's
fork point, stopping before the stop hash. Returns NIL when there is nothing to
announce. Mirrors Bitcoin Core's GETBLOCKS handler (legacy blocks-first peers)."
  (multiple-value-bind (locator-hashes stop-hash)
      (bl.ser:parse-block-locator-payload payload)
    (let* ((fork (bl.store:find-fork-in-active-chain
                  chain-state locator-hashes))
           (entries (bl.store:active-chain-entries-from
                     chain-state
                     (1+ (bl.store:block-index-entry-height fork))
                     +getblocks-inv-limit+))
           (chosen (truncate-entries-at-stop entries stop-hash nil)))
      (when chosen
        (bl.ser:make-inv-message
         (mapcar (lambda (entry)
                   (bl.ser:make-inv-vector
                    :type bl.ser:+inv-type-block+
                    :hash (bl.store:block-index-entry-hash entry)))
                 chosen))))))

(define-p2p-handler "getblocks" (peer payload ctx)
  "Serve a peer's getblocks by sending the inv built from PAYLOAD, if any (see
getblocks-response-message)."
  (bl.ctx:with-node-context (chain-state) ctx
  (let ((msg (getblocks-response-message payload chain-state)))
    (when msg
      (send-message peer msg)))))

(defun peer-address->net-addr (peer-addr)
  "Build a net-addr (wire address) from a stored PEER-ADDRESS record."
  (bl.ser:make-net-addr
   :services (peer-address-services peer-addr)
   :net (peer-address-net peer-addr)
   :ip (peer-address-ip peer-addr)
   :port (peer-address-port peer-addr)))

(defun build-addr-response (peer peer-addrs)
  "Build an addr message (or addrv2 when PEER advertised sendaddrv2) announcing
the PEER-ADDRESS records in PEER-ADDRS. A peer without addrv2 can only carry
IPv4/IPv6: non-v1-compatible addresses are SKIPPED for it, never emitted as
16-zero-byte garbage (Core IsAddrCompatible gating on PushAddress/relay,
net_processing.cpp:1117-1136). Returns NIL when nothing remains to announce."
  (if (peer-wants-addrv2 peer)
      (bl.ser:make-addrv2-message
       (mapcar (lambda (pa)
                 (list (peer-address->net-addr pa)
                       (bl.ser:network-bip155-id
                        (peer-address-network pa))
                       (peer-address-last-seen pa)))
               peer-addrs))
      (let ((compatible
              (remove-if-not
               (lambda (pa)
                 (bl.ser:v1-compatible-network-p
                  (peer-address-network pa)))
               peer-addrs)))
        (when compatible
          (bl.ser:make-addr-message
           (mapcar (lambda (pa)
                     (list (peer-address->net-addr pa) (peer-address-last-seen pa)))
                   compatible))))))

;;; --- getaddr response cache (Core CConnman::m_addr_response_caches) ---
;;;
;;; Answering every getaddr with a FRESH ~23% sample of addrman lets an
;;; attacker reconnect repeatedly and harvest many independent samples: enough
;;; to reconstruct much of our address table and to watch timestamps churn.
;;; Core answers every requestor arriving on the same network with the SAME
;;; snapshot for 21-27h, which is exactly what makes reconnecting pointless
;;; (net.h:1621-1640, net.cpp:3694-3730).

(defconstant +addr-response-cache-base-seconds+ (* 21 60 60)
  "Base lifetime of a cached getaddr response (Core's 21 hours).")

(defconstant +addr-response-cache-jitter-seconds+ (* 6 60 60)
  "Random extra lifetime on top of the base (Core's rand(6h)), so the refresh
instant is not predictable.")

(defvar *addr-response-caches* (make-hash-table :test 'equal)
  "(requestor network . local listening port) -> (ADDRS . EXPIRY-UNIX). Core
keys by (network, local listening socket) -- H(RANDOMIZER_ID_NETWORKKEY,
netclass, bind addr, bind port), net.cpp:1832-1836 -- so a requestor arriving
through a different bind gets a different snapshot. p2p_getaddr_caching.py
binds two onion targets and checks each answers from its own cache. The port
stands for the socket: our listeners are all on loopback or one address.")

(defun clear-addr-response-caches ()
  "Drop every cached getaddr response (tests; also a reset point if the
address book is rebuilt)."
  (clrhash *addr-response-caches*))

(defun %sample-addr-response (book)
  "Take a fresh addrman sample for the cache, filtered as Core's
GetAddressesUnsafe filters it (net.cpp:3686-3690): banned AND discouraged
addresses are dropped HERE, at fill time."
  (remove-if #'address-banned-or-discouraged-p
             (address-book-get-addr book :max +addrman-getaddr-max+
                                         :pct +addrman-getaddr-pct+)))

(defun cached-getaddr-response (book network now &optional local-port)
  "The cached response for a requestor on NETWORK, refilling if absent or
expired.

The ban/discourage filter runs only when the cache is FILLED, never on a hit —
Core returns m_addrs_response_cache verbatim (net.cpp:3729). Re-filtering per
hit would make responses differ between requestors inside one window whenever a
ban landed mid-window, which is precisely the fingerprinting signal the cache
exists to erase. The visible consequence is that we keep gossiping an address
for up to 27h after banning it; that is Core-identical and intended."
  (let* ((key (cons network local-port))
         (entry (gethash key *addr-response-caches*)))
    (if (and entry (< now (cdr entry)))
        (car entry)
        (let ((addrs (%sample-addr-response book)))
          (setf (gethash key *addr-response-caches*)
                (cons addrs (+ now +addr-response-cache-base-seconds+
                               (random (1+ +addr-response-cache-jitter-seconds+)))))
          addrs))))

(define-p2p-handler "getaddr" (peer payload ctx)
  "Serve a peer's getaddr: reply once per connection, and only to inbound peers,
with up to +max-addr-count+ known addresses from ADDRESS-BOOK (defaulting to the
node's). The inbound-only + once-per-connection rules mirror Bitcoin Core's
GETADDR handler (anti-fingerprinting and anti-spam) — the once flag latches as
soon as the request arrives, before we build any response, so a peer can never
elicit more than one reply regardless of whether we had addresses to send."
  (declare (ignore payload))
  (bl.ctx:with-node-context (address-book) ctx
  ;; getaddr is an addr-related message: it enables address relay with the
  ;; peer unless the connection never does addr relay (block-relay-only) —
  ;; Core SetupAddressRelay from the GETADDR handler.
  (unless (eq (peer-conn-type peer) :block-relay)
    (setf (peer-addr-relay-enabled peer) t))
  ;; Core's two refusals, each logged under net (net_processing.cpp:4910-4924);
  ;; p2p_addr_relay.py:307 waits for the second.
  (cond ((not (peer-inbound peer))
         (bl:log-cat "net" "Ignoring \"getaddr\" from ~A connection. peer=~A"
                     (if (eq (peer-conn-type peer) :block-relay)
                         "block-relay-only"
                         (string-downcase (symbol-name (peer-conn-type peer))))
                     (peer-id peer)))
        ((peer-getaddr-sent peer)
         (bl:log-cat "net" "Ignoring repeated \"getaddr\". peer=~A" (peer-id peer))))
  (when (and (peer-inbound peer)
             (not (peer-getaddr-sent peer)))
    (setf (peer-getaddr-sent peer) t)
    (let ((book (or address-book
                    (let ((node bl:*node*))
                      (and node (bl:node-address-book node))))))
      (when book
        ;; Served from the per-network cache: every requestor arriving on this
        ;; network sees the SAME snapshot for 21-27h, so reconnecting harvests
        ;; nothing new. Banned/discouraged addresses were filtered when the
        ;; cache was filled.
        ;;
        ;; QUEUED, as Core's `for (const CAddress &addr : vAddr)
        ;; PushAddress(peer, addr)' (net_processing.cpp:4926-4936): the reply
        ;; leaves with the next addr flush, and a first self-announcement due
        ;; on the same pass goes out BEFORE it, alone
        ;; (p2p_addr_selfannouncement.py:48-54 asserts it is the first addr
        ;; message). PUSH-ADDRESS applies the same known/compatible filters,
        ;; and the queue is cleared first, as Core's is.
        (setf (fill-pointer (peer-addrs-to-send peer)) 0)
        (dolist (pa (cached-getaddr-response
                     book
                     (peer-connected-through-network peer)
                     (bl.ser:get-unix-time)
                     (peer-local-port peer)))
          (push-address peer pa)))))))

;;; Local-address self-advertisement (Core MaybeSendAddr's local-address half,
;;; net_processing.cpp:5530-5567 + GetLocalAddrForPeer, net.cpp:240-267)

(defconstant +avg-local-address-broadcast-interval+ (* 24 60 60)
  "Mean seconds between self-announcements of our own address to a peer
(Core AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL = 24h, net_processing.cpp:158).")

(defun peer-connected-through-network (peer)
  "The network of the transport PEER is actually connected over (Core
CNode::ConnectedThroughNetwork, net.cpp:602-605: m_inbound_onion ? NET_ONION
: addr.GetNetClass()): :torv3 for peers accepted on the local onion-service
listener (whose socket address is Tor's 127.0.0.1); otherwise the CLASS of
the peer's address -- :unroutable for one that is not publicly routable
(10.0.0.1, 127.0.0.1), :ipv4 for an IPv6 address carrying an IPv4 one --
or :unroutable when it cannot be typed (hostname addnode). The class keys
the getaddr response cache (net.cpp:1832-1836) and drives GetLocal's privacy
rule; the reachability rank reads the peer's own network instead (see
GET-LOCAL-ADDR-FOR-PEER)."
  (if (peer-inbound-onion peer)
      :torv3
      (multiple-value-bind (net bytes)
          (parse-network-address (peer-address peer))
        (if net (address-net-class net bytes) :unroutable))))

(defun peer-addr-local (peer)
  "The address PEER says it sees us at -- the addr_recv of the version message
it sent (Core CNode::m_addr_local, set for every peer at
net_processing.cpp:3674) -- as (VALUES network bytes port), or NIL before a
version or when the field names no IP address."
  (let ((vmsg (peer-version peer)))
    (when vmsg
      (let* ((addr (bl.ser:version-message-addr-recv vmsg))
             (ip (bl.ser:net-addr-ip addr)))
        (when (= 16 (length ip))
          (values (ip-network ip) ip (bl.ser:net-addr-port addr)))))))

(defun %peer-addr-local-good-p (peer)
  "Core IsPeerAddrLocalGood (net.cpp:233-238): under -discover, a peer at a
routable address whose report of our address is routable and on a reachable
network."
  (and *discover*
       (multiple-value-bind (net bytes) (parse-network-address (peer-address peer))
         (and net (address-publicly-routable-p bytes net)))
       (multiple-value-bind (net bytes) (peer-addr-local peer)
         (and net
              (address-publicly-routable-p bytes net)
              (reachable-network-p net)))))

(defun get-local-addr-for-peer (peer)
  "The local address worth advertising to PEER, as a local-address record, or
NIL (Core GetLocalAddrForPeer, net.cpp:240-267): the best mapLocalHost entry
for the peer's connected-through network (privacy rule + reachability rank,
best-local-address) -- except that under -discover, when the peer's report of
our address is good, that report is used instead whenever we have no routable
address of our own, and otherwise once in 2 (once in 8 for an address scoring
above LOCAL_MANUAL): an inbound peer's report whole, an outbound one's IP
only, keeping our port, since the peer cannot observe our listening port on a
connection we opened. Whichever address results is advertised only if
routable."
  (let ((la (best-local-address (peer-connected-through-network peer)
                                (or (parse-network-address (peer-address peer)) :unroutable))))
    (when (and (%peer-addr-local-good-p peer)
               (or (null la)
                   (not (address-publicly-routable-p (local-address-bytes la)
                                                     (local-address-network la)))
                   (zerop (random (if (> (local-address-score la) +local-manual+) 8 2)))))
      (multiple-value-bind (net bytes port) (peer-addr-local peer)
        (setf la (make-local-address
                  :network net :bytes (copy-seq bytes)
                  :port (if (peer-inbound peer)
                            port
                            ;; GetLocalAddress's fallback port is GetListenPort.
                            (if la (local-address-port la) *advertised-listen-port*))
                  :score 0))))
    (when (and la
               (address-routable-p (local-address-bytes la)
                                   (local-address-network la)))
      la)))

(defun %announce-local-address (peer firstp)
  "Announce our best local address for PEER (Core MaybeSendAddr's local half,
net_processing.cpp:5547-5565); T when an announcement was actually made.

The FIRST announcement on a connection is its own single-address addr/addrv2,
for the reason Core gives: \"this makes sure rate-limiting with limited
start-tokens doesn't ignore it if the first message ends up containing
multiple addresses\". Every LATER one is PUSHED onto the peer's ordinary
gossip queue instead, so it leaves with that batch on the flush's exponential
schedule rather than as a lone message whose arrival announces, by itself,
that our 24h timer has just fired.

BUILD-ADDR-RESPONSE drops a torv3 address for a peer without addrv2 and
PUSH-ADDRESS skips one it cannot encode, so both arms carry Core's
IsAddrCompatible test."
  (let ((la (get-local-addr-for-peer peer)))
    (when la
      (let ((pa (make-peer-address
                 :net (local-address-network la)
                 :ip (local-address-bytes la)
                 :port (local-address-port la)
                 :services (peer-our-services peer)
                 :last-seen (bl.ser:get-unix-time))))
        ;; Core logs this in GetLocalAddrForPeer (net.cpp:262-264), i.e. for
        ;; the repeats that ride the queue as well as for the first;
        ;; p2p_addr_selfannouncement.py:136 waits for it after each 20-day
        ;; bumpmocktime.
        (bl:log-cat "net" "Advertising address ~A:~D to ~A"
                    (peer-address-string pa)
                    (peer-address-port pa)
                    (peer-log-name peer))
        (if firstp
            (let ((msg (build-addr-response peer (list pa))))
              (and msg (send-message peer msg) t))
            (push-address peer pa))))))

(defun maybe-advertise-local-address (peers chain-state)
  "Advertise our own best local address to each due addr-relay peer (Core
MaybeSendAddr's local half, net_processing.cpp:5535-5567): per peer, every
~24h on an exponential schedule, with the first announcement due as soon as
the peer is ready. Only the first is its own message; the repeats ride the
gossip queue (see %ANNOUNCE-LOCAL-ADDRESS), which is why the peer's
addr-known filter is RESET first -- the previous announcement marked our own
address known, and the flush's filter would silently drop the repeat.
Core's own comment: \"if we've sent before, clear the bloom filter for the
peer, so that our self-announcement will actually go out\"; it costs the peer
a few re-sent gossip addresses once a day on average.

Eligibility matches our addr gossip: ready + address relay enabled. Gated on
!IBD like Core; the fListen gate is implicit -- the local-address map only
gains entries while the onion service (which requires listening) is up. Call
~1x/second from the sync loop. Returns the number of peers announced to."
  ;; Fast path first: an empty map is the steady state of every node without
  ;; a Tor daemon, and this runs every second — don't touch the chainstate
  ;; (initial-block-download-p) or the peer list for it. (Consequence, unlike
  ;; Core: peers aren't rescheduled +24h while there is nothing to say, so
  ;; the first announcement goes out promptly once the service appears.)
  (unless *local-addresses*
    (return-from maybe-advertise-local-address 0))
  (when (initial-block-download-p chain-state)
    (return-from maybe-advertise-local-address 0))
  ;; The mockable clock in seconds, as the gossip flush's (Core reads the
  ;; same current_time for both halves of MaybeSendAddr).
  (let ((now (bl.ser:get-unix-time))
        (sent 0))
    (dolist (peer peers sent)
      (when (and (eq (peer-state peer) :ready)
                 ;; Core MaybeSendAddr self-advertises only on addr-relay
                 ;; peers (net_processing.cpp:5533).
                 (peer-addr-relay-enabled peer)
                 (or (<= (peer-next-local-addr-send peer) now)
                     (%inv-deadline-unreachable-p
                      (peer-next-local-addr-send peer) now
                      +avg-local-address-broadcast-interval+)))
        (let ((firstp (zerop (peer-next-local-addr-send peer))))
          ;; The reset happens whether or not we end up with an address to
          ;; announce, as it does in Core (it precedes GetLocalAddrForPeer).
          (unless firstp
            (rolling-bloom-reset (peer-known-addrs peer)))
          (when (%announce-local-address peer firstp)
            (incf sent)))
        ;; Reschedule whether or not anything was sent (Core sets
        ;; m_next_local_addr_send unconditionally once due).
        (setf (peer-next-local-addr-send peer)
              (+ now (%next-exp-interval-seconds
                      +avg-local-address-broadcast-interval+)))))))

;;; Gossiped-address flush (Core MaybeSendAddr's queue half,
;;; net_processing.cpp:5570-5604)

(defconstant +avg-address-broadcast-interval+ 30
  "Mean seconds between addr flushes to one peer (Core
AVG_ADDRESS_BROADCAST_INTERVAL = 30s, net_processing.cpp:160). The deadline
is redrawn from an exponential distribution after every flush, so the gap
between an address arriving and our passing it on carries no information
about when it arrived — the property RELAY-ADDRESS's queue exists for.")

(defun %flush-peer-addrs (peer)
  "Send PEER everything RELAY-ADDRESS queued for it as ONE addr/addrv2 message
and empty the queue. Assumes the peer is due; FLUSH-ADDR-ANNOUNCEMENTS owns
the schedule. Core MaybeSendAddr, net_processing.cpp:5575-5604."
  (let ((queue (peer-addrs-to-send peer)))
    ;; Core's Assume + resize: the push path already bounds this, so a queue
    ;; over the cap is a bug rather than an input, and trimming recovers.
    (when (> (fill-pointer queue) bl.ser:+max-addr-count+)
      (setf (fill-pointer queue) bl.ser:+max-addr-count+))
    ;; Drop what the peer has learned since the push, marking the rest known
    ;; on the same pass -- Core's addr_already_known lambda
    ;; (net_processing.cpp:5582-5587): contains, and insert when not.
    (let* ((known (peer-known-addrs peer))
           (fresh (loop for pa across queue
                        for key = (%addr-gossip-key pa)
                        unless (rolling-bloom-contains-p known key)
                          do (rolling-bloom-insert known key)
                          and collect pa)))
      (setf (fill-pointer queue) 0)
      (let ((msg (and fresh (build-addr-response peer fresh))))
        (when msg
          (send-message peer msg))))))

(defun flush-addr-announcements (peers)
  "Flush due per-peer addr gossip queues (call ~1x/second from the sync loop,
next to FLUSH-TX-ANNOUNCEMENTS). Core MaybeSendAddr, net_processing.cpp:5570-
5573: a peer is skipped while its deadline has not passed, and the deadline is
redrawn as an exponential with mean +avg-address-broadcast-interval+ every
time it does — including on a pass that finds the queue empty, which is what
arms a freshly-ready peer's first interval. Returns the number of peers a
message actually went out to."
  ;; The MOCKABLE clock, in seconds: Core's current_time is
  ;; GetTime<std::chrono::microseconds>() (net_processing.cpp:5737), and
  ;; p2p_addr_relay.py:128-136 moves setmocktime 600 s forward precisely to
  ;; make every peer's m_next_addr_send due. On the process clock the flush
  ;; kept its real-time schedule and 3 of the 20 relayed addresses arrived.
  (let ((now (bl.ser:get-unix-time))
        (sent 0))
    (dolist (peer peers sent)
      (when (and (eq (peer-state peer) :ready)
                 ;; Core MaybeSendAddr's first line: nothing to do for a peer
                 ;; without address relay (net_processing.cpp:5533).
                 (peer-addr-relay-enabled peer)
                 (or (> now (peer-next-addr-send peer))
                     ;; A clock moved backwards under the deadline.
                     (%inv-deadline-unreachable-p (peer-next-addr-send peer) now
                                                  +avg-address-broadcast-interval+)))
        (setf (peer-next-addr-send peer)
              (+ now (%next-exp-interval-seconds +avg-address-broadcast-interval+)))
        (when (%flush-peer-addrs peer)
          (incf sent))))))

;;; Transaction relay
;;;
;;; relay-enabled-p lives in peer.lisp now (the version handshake needs it to
;;; set our fRelay bit, and peer.lisp loads first).

;;; Trickled (Poisson) tx announcement batching — Core SendMessages tx
;;; inventory (net_processing.cpp:5960-6070). Announcing every tx the
;;; instant it is accepted leaks its arrival time (tx-origin inference);
;;; Core instead queues announcements per peer and flushes them in
;;; batches on a randomized schedule: each OUTBOUND peer flushes on its
;;; own exponential timer (mean 2s), while ALL INBOUND peers share one
;;; rotation (mean 5s) so an attacker connecting many times gains no
;;; extra timing resolution.

(defconstant +inbound-inv-broadcast-interval+ 5
  "Mean seconds between inv flushes to inbound peers (shared rotation).
Core INBOUND_INVENTORY_BROADCAST_INTERVAL (net_processing.cpp:165).")

(defconstant +outbound-inv-broadcast-interval+ 2
  "Mean seconds between inv flushes to an outbound peer.
Core OUTBOUND_INVENTORY_BROADCAST_INTERVAL (net_processing.cpp:169).")

(defconstant +inv-broadcast-target+ 70
  "Max announcements per flush: INVENTORY_BROADCAST_PER_SECOND (14) x
the inbound interval (5s) — net_processing.cpp:172-174. Remainder stays
queued for the next flush.")

(defconstant +inv-broadcast-max+ 1000
  "Ceiling on one flush's announcements however deep the backlog is —
Core INVENTORY_BROADCAST_MAX (net_processing.cpp:177), whose static_assert
ties it to MAX_PEER_TX_ANNOUNCEMENTS above and to
+inv-broadcast-target+ below.

There is deliberately no bound on the QUEUE. Core does not truncate
m_tx_inventory_to_send at all; the accelerating drain below is the whole
pressure valve, so a backlog is worked off rather than silently discarded.")

(defun %tx-inv-broadcast-max (queue-length)
  "How many announcements one flush to a peer may send at this backlog:
Core's broadcast_max = INVENTORY_BROADCAST_TARGET + (size/1000)*5, clamped to
INVENTORY_BROADCAST_MAX (net_processing.cpp:6046-6047) — 70 at rest, 95 at a
5,000-entry backlog, 1,000 at the ceiling. \"No reason to drain out at many
times the network's capacity\" is Core's comment for the base rate; the growth
term is what lets a peer that fell behind catch up instead of accumulating
forever."
  (min +inv-broadcast-max+
       (+ +inv-broadcast-target+ (* 5 (floor queue-length 1000)))))

(defvar *next-inbound-inv-flush* 0
  "Unix-time deadline of the shared inbound inv rotation, on Core's MOCKABLE
clock (Core NextInvToInbounds — one timer for all inbound peers).")

(defun %next-exp-interval-seconds (mean-seconds)
  "Whole seconds until the next event of a Poisson process with MEAN-SECONDS
(Core rand_exp_duration): -mean * ln(U), U uniform in (0,1], rounded UP so a
schedule always advances on a one-second clock. Core measures the same draw in
microseconds; the flush pass runs about once a second either way, so the extra
resolution buys nothing here and a deadline equal to now would flush on every
pass."
  (max 1 (ceiling (* mean-seconds (- (log (- 1.0d0 (random 1.0d0))))))))

(defun %inv-deadline-unreachable-p (deadline now mean-seconds)
  "T when DEADLINE can no longer be reached because the clock moved BACKWARDS
under it -- setmocktime hands the node a base far in the past, and a gate
written `now >= deadline' then never opens again. Re-armed rather than trusted;
Core recomputes its schedule from current_time on every SendMessages pass."
  (and (plusp deadline) (> (- deadline now) (* 10 mean-seconds))))

(defun relay-transaction (txid source-peer peers &key fee-rate-per-kvb wtxid)
  "Queue a newly-accepted transaction for announcement to all connected
peers except SOURCE-PEER. Nothing is sent here — flush-tx-announcements
drains each peer's queue on its Poisson schedule (Core queues into
m_tx_inventory_to_send exactly the same way). FEE-RATE-PER-KVB is the
transaction's fee rate in satoshis per KILO-vbyte, used against BIP133
feefilters at flush time.

Per KVB, and NOT sat/vB scaled up afterwards, which is what it used to be:
the caller computed (floor fee vsize) and this multiplied by 1000, so every
transaction paying under 1 sat/vB was queued at rate 0 and withheld from every
peer that had sent a feefilter at all. p2p_feefilter.py:87 sets a filter of 150
sat/kvB and expects transactions paying exactly 0.15 sat/vB; they were all
dropped. Core compares fee against filterrate.GetFee(vsize) with no
intermediate rate at all (net_processing.cpp:6072), and
`floor(fee*1000/vsize) >= filter' is that comparison exactly, both sides being
integers. WTXID enables BIP339 MSG_WTX
announcements. Does nothing if relay is disabled for the network — but is
deliberately NOT gated on -blocksonly: a blocksonly node still announces
its OWN (locally-submitted) transactions, exactly like Core, whose
RelayTransaction has no ignore_incoming_txs check (incoming txs can't
reach here anyway — their senders are disconnected)."
  (unless (relay-enabled-p)
    (return-from relay-transaction nil))
  (let ((fee-rate-per-kb (or fee-rate-per-kvb 0)))
    (dolist (peer peers)
      ;; Skip the source peer and disconnected peers
      (when (and (not (eq peer source-peer))
                 (eq (peer-state peer) :ready)
                 ;; No announcements without tx-relay state: block-relay/
                 ;; feeler conns AND peers whose version had fRelay=0 (BIP37/
                 ;; BIP60 blocksonly peers — Core only builds tx inventory
                 ;; under `if (tx_relay != nullptr)`, and announcing to them
                 ;; gets us disconnected).
                 (peer-tx-relay-p peer)
                 ;; Skip a transaction this peer already knows: one we have
                 ;; announced to it, or one it announced or sent to US (Core
                 ;; InitiateTxBroadcastToAll's known-filter test,
                 ;; net_processing.cpp:2261-2263, over the same
                 ;; `m_wtxid_relay ? wtxid : txid` key).
                 (not (rolling-bloom-contains-p (peer-announced-txs peer)
                                                (%peer-inv-hash peer txid wtxid))))
        ;; BIP-330: a peer we reconcile with gets the transaction held back in
        ;; its reconciliation set rather than announced — unless this
        ;; transaction is one of the few chosen for immediate fanout, which is
        ;; what stops an adversary timing the first announcement to find the
        ;; origin. Reconciliation is off unless -txreconciliation was set AND
        ;; the peer completed the handshake, so this branch is dead by default.
        ;;
        ;; A FULL set refuses (RECON-SET-ADD returns NIL at
        ;; +RECON-MAX-SET-SIZE+) and the transaction takes the ordinary path
        ;; below instead: the fallback is flooding, never dropping.
        (unless (and (%recon-hold-p peer wtxid txid peers)
                     (recon-set-add (%peer-recon-set peer)
                                    (peer-recon-k0 peer) (peer-recon-k1 peer)
                                    wtxid))
          ;; Core PushTxInventory is one insert into m_tx_inventory_to_send
          ;; and nothing else (net_processing.cpp:2261-2263). Two things
          ;; used to happen here that Core does not do: the entry was NCONCd
          ;; onto the tail, walking the whole queue, and then a LENGTH walked
          ;; it again to NTHCDR the excess past 5,000 off the FRONT --
          ;; silently discarding the OLDEST announcements, which nothing
          ;; ever re-queues, so those transactions were never announced to
          ;; this peer at all. A PUSH is Core's O(1) insert; the flush
          ;; restores announcement order and drains faster as the queue
          ;; grows (%TX-INV-BROADCAST-MAX).
          (%queue-tx-announcement peer txid wtxid fee-rate-per-kb))))))

(defun %handle-reqrecon (peer payload)
  "The peer wants to reconcile: size a sketch against what it says it holds and
send it back."
  (handler-case
      (multiple-value-bind (their-size q)
          (bl.ser:parse-reqrecon-payload payload)
        (send-message peer (recon-respond-to-request peer their-size q)))
    (error (e)
      (bl:log-cat "txreconciliation" "reqrecon from ~A failed: ~A"
                  (peer-log-name peer) e))))

(defun %handle-sketch (peer payload &optional mempool)
  "The responder's sketch arrived. Merge it with ours and either announce the
answer or ask for an extension."
  (let ((round (peer-recon-round peer)))
    (unless round
      ;; A sketch we did not ask for. Ignore rather than disconnect: a round
      ;; can time out on our side while the answer is still in flight.
      (return-from %handle-sketch nil))
    (handler-case
        (let ((their-sketch (ms-sketch-deserialize
                             (bl.ser:parse-sketch-payload payload))))
          (multiple-value-bind (ids ok) (recon-round-decode round their-sketch)
            (cond
              (ok
               (multiple-value-bind (ask announce) (recon-finish-round peer ids)
                 (send-message peer
                               (bl.ser:make-reconcildiff-message t ask))
                 (%announce-wtxids peer announce mempool)))
              ((not (recon-round-extended round))
               ;; One extension is allowed, then the fallback.
               (setf (recon-round-extended round) t
                     (recon-round-state round) :extended)
               (send-message peer (bl.ser:make-reqsketchext-message)))
              (t
               (send-message peer
                             (bl.ser:make-reconcildiff-message nil '()))
               (%announce-wtxids peer (recon-abandon-round peer) mempool)))))
      (error (e)
        (bl:log-cat "txreconciliation" "sketch from ~A failed: ~A"
                    (peer-log-name peer) e)
        ;; A sketch that cannot even be read ends the round the way a failed
        ;; decode does, for BOTH sides: the responder keeps its snapshot
        ;; "until a reconcildiff message is received" (BIP-330), so it has
        ;; to be told, or it holds that snapshot until the next reqrecon
        ;; replaces it.
        (send-message peer (bl.ser:make-reconcildiff-message nil '()))
        (%announce-wtxids peer (recon-abandon-round peer) mempool)))))

(defun %handle-reqsketchext (peer)
  "The initiator could not decode and wants BIP-330's sketch extension: the
same frozen snapshot at twice the capacity, minus the part already sent
(RECON-RESPOND-TO-EXTENSION). Reconciling against a set that moved since the
first sketch would describe something the initiator never saw; asking with no
sketch sent this round gets nothing."
  (let ((msg (recon-respond-to-extension peer)))
    (when msg (send-message peer msg))))

(defun %handle-reconcildiff (peer payload &optional mempool)
  "The initiator finished. Announce what it asked for; on a failure, announce
the whole snapshot — the flood fallback that keeps a failed round from losing
transactions.

A SUCCESS retires the responder's WHOLE snapshot, the same way
RECON-FINISH-ROUND retires the initiator's: the ids the initiator asked for
are settled because we are announcing them now, and the rest of the snapshot
is settled because it cancelled in the sketch, which only happens when both
sides already hold it. Retiring only the asked-for ids left the cancelled ones
in the set for the life of the connection.

A FAILURE floods the snapshot through RECON-FLOOD-SNAPSHOT, the responder's
half of BIP-330's fallback. This is the responder: it has no round to abandon
(only the initiator opens one), and reaching for that round here used to find
NIL and announce nothing."
  (handler-case
      (multiple-value-bind (ok ask)
          (bl.ser:parse-reconcildiff-payload payload)
        (let ((set (peer-recon-set peer)))
          (cond (ok
                 (%announce-wtxids peer (recon-settle-ids set ask) mempool)
                 (when set (recon-set-clear-snapshot set)))
                (t
                 (%announce-wtxids peer (recon-flood-snapshot peer) mempool)))))
    (error (e)
      (bl:log-cat "txreconciliation" "reconcildiff from ~A failed: ~A"
                  (peer-log-name peer) e))))

(defun %announce-wtxids (peer wtxids mempool)
  "Queue WTXIDS for ordinary announcement to PEER. Reconciliation decides WHAT
to announce; the announcement itself is the same inv path everything else uses,
through %QUEUE-TX-ANNOUNCEMENT with what RELAY-TRANSACTION gives it: the TXID
and the fee rate per kvB, both read from MEMPOOL by wtxid. A wtxid the mempool
no longer holds has nothing to announce, and without a MEMPOOL nothing does --
there is no txid to queue."
  (when mempool
    (dolist (wtxid wtxids)
      (let* ((txid (gethash wtxid (bl.mp:mempool-by-wtxid mempool)))
             (entry (and txid (bl.mp:mempool-get mempool txid))))
        (when entry
          (let ((vsize (bl.mp:mempool-entry-vsize entry)))
            (%queue-tx-announcement
             peer txid wtxid
             (if (plusp vsize)
                 (floor (* 1000 (bl.mp:mempool-entry-fee entry)) vsize)
                 0))))))))

(defun maybe-start-reconciliation (peer now &optional mempool)
  "The timer entry point, per peer per tick: give up a round that has waited
+RECON-ROUND-TIMEOUT-SECONDS+ for its sketch, and open a new one if it is due.
Returns T when a round was started.

A timed-out round ends as a failed one does (BIP-330's fallback): our snapshot
is flooded -- from MEMPOOL, which the announcement needs for each txid and fee
rate -- and reconcildiff(success=0) tells the responder to flood its own.
Rounds are spread across peers rather than run together, so a node's
announcement pattern does not reveal how many peers it has."
  (when (recon-round-timed-out-p peer now)
    (bl:log-cat "txreconciliation" "reconciliation round with peer=~A timed out"
                (peer-id peer))
    (send-message peer (bl.ser:make-reconcildiff-message nil '()))
    (%announce-wtxids peer (recon-abandon-round peer) mempool))
  (when (recon-should-start-round-p peer now)
    (send-message peer (recon-start-round peer now))
    t))

(defun %mark-tx-known-to-peer (peer hash)
  "Record that PEER holds the transaction its inventory calls HASH: it
announced or sent it to us, or we announced it. This is Core's AddKnownTx /
m_tx_inventory_known_filter insert (net_processing.cpp:4174, :4491-4492,
:6019, :6083), with the one consequence BIP-330 adds: a transaction the peer
already has is out of its reconciliation set. The set holds what `would have
been announced using INV messages absent this protocol', and this one was --
left in, it would cost sketch capacity every round until a round happened to
settle it. A reconciling peer negotiated wtxid relay, so HASH is the wtxid the
set is keyed by. Core d3056bc has no set to remove from; the BIP is the
oracle."
  (rolling-bloom-insert (peer-announced-txs peer) hash)
  (let ((set (peer-recon-set peer)))
    (when (and set (peer-recon-k0 peer))
      (recon-set-remove set (peer-recon-k0 peer) (peer-recon-k1 peer) hash))))

(defun %recon-hold-p (peer wtxid txid peers)
  "T when this transaction should wait for reconciliation with PEER rather than
being announced now.

Three conditions, all required: the peer completed the sendtxrcncl handshake
(which needs -txreconciliation on both sides), we have a wtxid to compute its
short ID from, and this transaction did not draw the immediate-fanout slot for
this peer."
  (and (peer-recon-registered peer)
       (peer-recon-k0 peer)
       wtxid
       (not (recon-fanout-target-p
             (or wtxid txid)
             (peer-recon-k0 peer)
             ;; The fanout budget is a share of the RECONCILING peers, so the
             ;; count has to exclude the ones being announced to anyway.
             (count-if #'peer-recon-registered peers)
             (not (peer-inbound peer))))))

;;; The two std:: heap operations Core's inventory drain is written in
;;; (make_heap + pop_heap over a vector of candidates). They live here rather
;;; than in a utility layer because the flush below is their only caller, and
;;; the reason it wants a heap rather than a sort is Core's: only as many
;;; entries as are actually sent need ordering.

(defun %sift-down (vec root end predicate)
  "Restore the max-heap property at ROOT over VEC[0,END) under PREDICATE
(libstdc++ __sift_down): swap the root down past the larger of its children
until neither is larger."
  (loop for child = (+ (* 2 root) 1)
        while (< child end)
        do (when (and (< (1+ child) end)
                      (funcall predicate (aref vec child) (aref vec (1+ child))))
             (incf child))
           (when (not (funcall predicate (aref vec root) (aref vec child)))
             (return))
           (rotatef (aref vec root) (aref vec child))
           (setf root child)))

(defun %make-heap (vec end predicate)
  "std::make_heap over VEC[0,END) under PREDICATE. Linear in END, and orders
no more than a heap needs to — which is the point of using one when only the
first few elements are wanted."
  (loop for i from (1- (floor end 2)) downto 0
        do (%sift-down vec i end predicate)))

(defun %pop-heap (vec end predicate)
  "std::pop_heap: move the maximum of VEC[0,END) to VEC[END-1] and restore the
heap over the rest. The caller then reads VEC[END-1] and shrinks END."
  (rotatef (aref vec 0) (aref vec (1- end)))
  (%sift-down vec 0 (1- end) predicate))

(defun %tx-inv-announced-later-p (mempool a b)
  "The max-heap predicate over two queued announcements: T when A should be
announced LATER than B.

Core CompareInvMempoolOrder (net_processing.cpp:5670-5684), reversed for the
same stated reason — \"as std::make_heap produces a max-heap, we want the
entries with the higher mining score to sort later\" — so the heap's maximum
is the announcement Core would send first."
  (minusp (bl.mp:mempool-compare-mining-order mempool (first b) (first a))))

(defun %bloom-admits-p (peer mempool txid)
  "T unless PEER has a bloom filter the mempool transaction TXID does not
match (Core IsRelevantAndUpdate in SendMessages, net_processing.cpp:6075). A
transaction that has left the mempool is not judged here."
  (let ((filter (peer-bloom-filter peer)))
    (or (null filter)
        (null mempool)
        (let ((entry (bl.mp:mempool-get mempool txid)))
          (or (null entry)
              (bloom-relevant-and-update-p filter (bl.mp:mempool-entry-transaction entry)))))))

(defun %flush-peer-tx-invs (peer mempool)
  "Drain queued announcements to PEER as one inv message: as many as
%TX-INV-BROADCAST-MAX allows at the current backlog, in the order the mempool
would mine them. At flush time each entry is re-checked: still unknown to the
peer, still in the mempool, and above the peer's BIP133 feefilter (feefiltered
entries are dropped, not deferred — Core skips them the same way). BIP339:
wtxidrelay peers get MSG_WTX + wtxid, others MSG_TX + txid
(net_processing.cpp:6009,6065).

The order is Core's, and Core says why: \"topologically and fee-rate sort the
inventory we send for privacy and priority reasons\" (:6040-6041). Priority,
because when the queue is longer than the budget the cut must keep the
announcements worth the most, not the ones that happened to arrive first.
Privacy, because arrival order is a signal about this node that mempool order
is not. A HEAP rather than a sort, again as Core does: only as many entries as
are actually sent get ordered.

Without a mempool to ask — or with a graph too big to have a main order — the
queue drains in the order it is stored, which is insertion order. That
fallback matters: insertion order is topological (a parent is accepted, and so
relayed, before its child), so it is the one order available here that cannot
announce a child before its parent. (An ordered flush leaves its unsent
remainder as a heap, so a node that loses its mempool mid-run keeps that
guarantee only for what it queues afterwards.)

The queue is held newest-first so an enqueue is O(1); taking from the BACK of
the candidate vector is therefore oldest-first, and is also where %POP-HEAP
puts the element it selects. An entry that is skipped (gone from the mempool,
already known, feefiltered) leaves the queue without spending budget, which is
Core's `continue` before nRelayedTransactions++."
  (let* ((candidates (coerce (shiftf (peer-tx-inv-queue peer) '()) 'vector))
         (end (length candidates))
         (budget (%tx-inv-broadcast-max end))
         (later-p (lambda (a b) (%tx-inv-announced-later-p mempool a b)))
         (orderedp (and mempool
                        (bl.mp:mempool-mining-order-available-p mempool)))
         (invs '())
         (count 0))
    (when orderedp (%make-heap candidates end later-p))
    (loop while (and (plusp end) (< count budget))
          do (when orderedp (%pop-heap candidates end later-p))
             (destructuring-bind (txid wtxid fee-rate-per-kb)
                 (aref candidates (decf end))
               ;; Core builds the inv FIRST and uses ITS hash for both the
               ;; filter check and the filter insert (net_processing.cpp:
               ;; 6060-6083): the filter holds whichever id this peer's
               ;; inventory uses, so a txid lookup on a wtxidrelay peer reads
               ;; a filter nothing ever wrote.
               (let* ((inv (%peer-tx-inv peer txid wtxid))
                      (known (bl.ser:inv-vector-hash inv)))
                 (when (and (not (rolling-bloom-contains-p
                                  (peer-announced-txs peer) known))
                            ;; Evicted/confirmed since queueing => nothing to announce.
                            (or (null mempool)
                                (bl.mp:mempool-has mempool txid))
                            ;; BIP 133 feefilter, evaluated at flush time.
                            (or (zerop (peer-feefilter-rate peer))
                                (>= fee-rate-per-kb (peer-feefilter-rate peer)))
                            ;; BIP37: only what the peer's filter matches
                            ;; (net_processing.cpp:6075).
                            (%bloom-admits-p peer mempool txid))
                   (%mark-tx-known-to-peer peer known)
                   (incf count)
                   (push inv invs)))))
    ;; Whatever the budget did not reach stays queued.
    (setf (peer-tx-inv-queue peer)
          (loop for i from 0 below end collect (aref candidates i)))
    (when invs
      ;; A dead socket raises from the write; the drain/health passes own
      ;; disconnecting — just stop announcing to it this round.
      (handler-case
          (send-message peer (bl.ser:make-inv-message
                              (nreverse invs)))
        (error () nil)))
    ;; Snapshot the mempool sequence: everything in the pool right now was
    ;; announceable in this flush, so getdata for it is legitimate from here
    ;; on (Core SendMessages, net_processing.cpp:6086-6088 — updated on every
    ;; trickle flush, sent invs or not). This is what FindTxForGetData's
    ;; anti-probing gate compares against.
    (when mempool
      (setf (peer-last-inv-sequence peer)
            (bl.mp:mempool-sequence mempool)))))

(defun handle-mempool-request (peer payload ctx)
  "BIP35: announce the whole mempool to a peer holding the \"mempool\"
permission (Core sets m_send_mempool and the next inv flush sends the pool,
net_processing.cpp).

Core's filters apply here as they do to an ordinary announcement: the peer's
BIP133 feefilter, and its wtxid-relay preference for the inv type. Sent as one
batch — Core caps an inv message at MAX_INV_SZ and so do we, which for a pool
larger than that means the rest waits for ordinary relay, exactly as a peer
that connected mid-flush would see it."
  (declare (ignore payload))
  (bl.ctx:with-node-context (mempool) ctx
  (unless (and mempool (peer-tx-relay-p peer))
    (return-from handle-mempool-request nil))
  (let ((invs '())
        (count 0))
    (bl.mp:mempool-for-each
     mempool
     (lambda (txid entry)
       (when (and entry (< count bl.ser:+max-inv-count+))
         (let ((fee-rate-per-kb
                 (let ((vsize (bl.mp:mempool-entry-vsize entry)))
                   (if (plusp vsize)
                       (floor (* 1000 (bl.mp:mempool-entry-fee entry))
                              vsize)
                       0))))
           (when (and (or (zerop (peer-feefilter-rate peer))
                          (>= fee-rate-per-kb (peer-feefilter-rate peer)))
                      ;; BIP37 (net_processing.cpp:6017-6019).
                      (or (null (peer-bloom-filter peer))
                          (bloom-relevant-and-update-p
                           (peer-bloom-filter peer)
                           (bl.mp:mempool-entry-transaction entry))))
             (incf count)
             ;; Mark it known to the peer, under the id its inventory uses, so
             ;; the ordinary relay path does not announce it a second time
             ;; (Core inserts inv.hash on this same dump path,
             ;; net_processing.cpp:6019). The getdata anti-probing gate is
             ;; PEER-LAST-INV-SEQUENCE, snapshotted below, not this filter.
             (let ((inv (%peer-tx-inv peer txid
                                      (bl.mp:mempool-entry-wtxid entry))))
               (%mark-tx-known-to-peer peer (bl.ser:inv-vector-hash inv))
               (push inv invs)))))))
    (when invs
      (handler-case
          (send-message peer (bl.ser:make-inv-message
                              (nreverse invs)))
        (error () nil)))
    ;; As in the ordinary flush: everything in the pool now was announceable.
    (setf (peer-last-inv-sequence peer)
          (bl.mp:mempool-sequence mempool))
    count)))

(defun %next-inv-to-inbounds (now)
  "Core NextInvToInbounds (net_processing.cpp:1172-1181): the shared inbound
rotation's deadline, advanced to NOW plus a fresh draw once NOW has passed it
(or the clock moved back out of its reach), and returned either way."
  (when (or (< *next-inbound-inv-flush* now)
            (%inv-deadline-unreachable-p *next-inbound-inv-flush* now
                                         +inbound-inv-broadcast-interval+))
    (setf *next-inbound-inv-flush*
          (+ now (%next-exp-interval-seconds +inbound-inv-broadcast-interval+))))
  *next-inbound-inv-flush*)

(defun flush-tx-announcements (peers mempool)
  "Flush due per-peer tx announcement queues (call ~1x/second from the
sync loop): Core SendMessages' trickle gate (net_processing.cpp:5980-5990).
Every peer carries its own m_next_inv_send_time -- an outbound peer's drawn
with mean +outbound-inv-broadcast-interval+, an inbound peer's taken from the
shared rotation (%NEXT-INV-TO-INBOUNDS, mean +inbound-inv-broadcast-interval+)
-- and a peer whose time has passed trickles and re-draws. A peer's FIRST
pass trickles too, its time starting at zero as Core's does: armed without a
send, as this used to be, the first pass after a setmocktime jump armed the
deadline past the frozen clock, and the queued inv never left
(p2p_leak_tx.py:51, one run in two). A noban peer trickles on every pass
(:5981). Holds the node lock: the queues are also written by the RPC
broadcast path (sendrawtransaction/submitpackage), which enqueues under the
same lock from RPC handler threads."
  (with-current-node-lock
    (let ((now (bl.ser:get-unix-time)))
      (dolist (peer peers)
        (when (and (eq (peer-state peer) :ready)
                   ;; fRelay=0 peers have no tx-relay state: no inv flushes,
                   ;; and no last-inv-sequence advance either (their getdata
                   ;; is ignored outright anyway).
                   (peer-tx-relay-p peer))
          ;; noban: the framework's `-whitelist=noban@127.0.0.1  # immediate
          ;; tx relay' relies on it under a frozen clock (mempool_reorg.py:38).
          (let* ((trickle (peer-has-permission-p peer +perm-noban+))
                 (next (peer-next-inv-send-time peer))
                 (mean (if (peer-inbound peer)
                           +inbound-inv-broadcast-interval+
                           +outbound-inv-broadcast-interval+))
                 (backwards (%inv-deadline-unreachable-p next now mean)))
            (when (or backwards (zerop next) (>= now next))
              ;; A clock that moved BACKWARDS re-arms without a send.
              (unless backwards (setf trickle t))
              (setf (peer-next-inv-send-time peer)
                    (if (peer-inbound peer)
                        (%next-inv-to-inbounds now)
                        (+ now (%next-exp-interval-seconds mean)))))
            (when trickle
              (%flush-peer-tx-invs peer mempool))))))))

;;; Initial broadcast of locally-submitted transactions (Core
;;; BroadcastTransaction -> InitiateTxBroadcastToAll + the scheduled
;;; ReattemptInitialBroadcast pass over the mempool's unbroadcast set).

(defun announce-mempool-tx (peers mempool txid)
  "Queue an announcement of the in-mempool TXID to every relay-capable peer
(Core PeerManagerImpl::InitiateTxBroadcastToAll, net_processing.cpp:
2245-2266, with no source peer to exclude). Announces the ENTRY's wtxid —
when a caller re-broadcasts a same-txid/different-witness transaction, the
mempool's witness is the one peers must request (Core BroadcastTransaction,
node/transaction.cpp:63-72). The entry's feerate rides along for BIP133
flush-time filtering. Peers that already had the tx announced are skipped
by relay-transaction's per-peer known filter, exactly like Core's
m_tx_inventory_known_filter check. Returns T when the tx was in the pool
and queued, NIL otherwise."
  (let ((entry (and mempool (bl.mp:mempool-get mempool txid))))
    (when entry
      (let ((vsize (bl.mp:mempool-entry-vsize entry))
            (fee (bl.mp:mempool-entry-fee entry)))
        (relay-transaction txid nil peers
                           :fee-rate-per-kvb
                           (if (plusp vsize) (floor (* 1000 fee) vsize) 0)
                           :wtxid (bl.mp:mempool-entry-wtxid entry)))
      t)))

(defconstant +initial-broadcast-interval+ 600
  "Base seconds between unbroadcast re-announcement passes (Core
INITIAL_BROADCAST_INTERVAL semantics: ReattemptInitialBroadcast reschedules
itself 10min out, net_processing.cpp:1639-1642).")

(defconstant +initial-broadcast-jitter+ 300
  "Random extra seconds added to every re-announcement interval — Core adds
randrange(5min) each cycle so the cadence can't fingerprint the node
(net_processing.cpp:1639-1641).")

(defvar *next-initial-broadcast-time* 0
  "Unix-time deadline of the next unbroadcast re-announcement pass;
0 = not yet scheduled (armed on the first maybe- call, matching Core's
initial scheduleFromNow a full interval out, net_processing.cpp:2036-2038).

On the SCHEDULER's clock (BL.SER:GET-SCHEDULER-TIME: the mockable clock plus
every mockscheduler forward), because Core runs this pass on
its CScheduler and `mockscheduler' exists to move that scheduler forward:
mempool_unbroadcast.py:66 and mempool_persist.py:219 both call it and then
wait for the re-announcement. Measured from GET-INTERNAL-REAL-TIME, as this
was, the deadline was ten minutes of WALL time away and no RPC could reach
it -- both tests waited out their timeout with the transaction sitting in the
unbroadcast set.")

(defun %next-initial-broadcast-seconds ()
  (+ +initial-broadcast-interval+ (random +initial-broadcast-jitter+)))

(defun reset-initial-broadcast-schedule ()
  "ARM the re-announcement deadline a full interval out (called at node
start, alongside reset-compact-extra-transactions), as Core's PeerManager schedules the
first pass from StartScheduledTasks (net_processing.cpp:2036-2038) -- before
any RPC can run. Left to the first idle tick, as it was, a mockscheduler that
reached the node before that tick found nothing armed, and the tick then armed
the deadline 10-15 minutes past the ALREADY-forwarded scheduler clock:
mempool_persist.py:219 restarts the node and forwards 16 minutes at once, and
the pass never came."
  (setf *next-initial-broadcast-time*
        (+ (bl.ser:get-scheduler-time) (%next-initial-broadcast-seconds))))

(defun reattempt-initial-broadcast (peers mempool)
  "Re-announce every unbroadcast tx still in the mempool to the current
relay peers; drop the ids of txs that have left the pool (Core
PeerManagerImpl::ReattemptInitialBroadcast, net_processing.cpp:1625-1643).
Because each peer's known filter suppresses re-queueing, this mostly
reaches peers connected since the original announcement."
  (dolist (txid (bl.mp:mempool-unbroadcast-txids mempool))
    (unless (announce-mempool-tx peers mempool txid)
      (bl.mp:mempool-remove-unbroadcast mempool txid t))))

(defun maybe-reattempt-initial-broadcast (peers mempool)
  "Run the unbroadcast re-announcement pass when due (call ~1x/second from
the sync loop, our stand-in for Core's scheduler). Each cycle — including
the first — is scheduled 10min + rand(5min) out, on the mockable clock."
  (when mempool
    (let ((now (bl.ser:get-scheduler-time)))
      (cond ((zerop *next-initial-broadcast-time*)
             (setf *next-initial-broadcast-time*
                   (+ now (%next-initial-broadcast-seconds))))
            ;; A clock that moved BACKWARDS -- setmocktime to a base older
            ;; than the stamp this node armed at start-up -- would otherwise
            ;; park the deadline a whole mocked epoch away and the pass would
            ;; never run again. Re-arm from where the clock now is.
            ((> (- *next-initial-broadcast-time* now)
                (+ +initial-broadcast-interval+ +initial-broadcast-jitter+))
             (setf *next-initial-broadcast-time*
                   (+ now (%next-initial-broadcast-seconds))))
            ((>= now *next-initial-broadcast-time*)
             (setf *next-initial-broadcast-time*
                   (+ now (%next-initial-broadcast-seconds)))
             (with-current-node-lock
               (reattempt-initial-broadcast peers mempool)))))))

(defconstant +max-blocks-to-announce+ 8
  "Core MAX_BLOCKS_TO_ANNOUNCE (net_processing.cpp:134): the most headers one
announcement may carry. A queue longer than this reverts to a single inv for
the tip and lets the peer's own sync mechanism fetch the rest -- which is what
keeps a deep reorg from turning into a headers flood.")

(defun queue-block-announcement (peer hash)
  "Queue HASH on PEER for the next announcement pass (Core UpdatedBlockTip
pushing onto Peer::m_blocks_for_headers_relay, net_processing.cpp:2180-2188).

QUEUEING, not sending, is the whole point: Core announces once per
SendMessages pass, so a run of connected blocks becomes ONE headers message
(or one inv for the tip), while announcing at connect time put one message per
block on the wire -- 400 invs per peer for a 400-block `generate'."
  (setf (peer-blocks-for-headers-relay peer)
        (nconc (peer-blocks-for-headers-relay peer) (list hash))))

(defun %peer-has-header-p (peer chain-state entry)
  "Core PeerHasHeader (net_processing.cpp:1352-1359): the peer has ENTRY when
it is an ANCESTOR of the peer's best-known block, or of the highest header we
have already sent it.

The ancestor half is what makes this true for everything BELOW the peer's tip,
not just for the tip itself -- so a peer that announced block 100 is not sent
blocks 1..99 back."
  (flet ((covers (known-hash)
           (let ((known (and known-hash
                             (bl.store:get-block-index-entry chain-state known-hash))))
             (and known
                  (let ((ancestor (bl.store:entry-ancestor-at-height
                                   known (bl.store:block-index-entry-height entry))))
                    (and ancestor
                         (equalp (bl.store:block-index-entry-hash ancestor)
                                 (bl.store:block-index-entry-hash entry))))))))
    (or (covers (peer-best-known-block-hash peer))
        (covers (peer-best-header-sent-hash peer)))))

(defun %announcement-headers (peer chain-state)
  "The headers PEER's queue should be announced as, or NIL to fall back to an
inv (Core SendMessages' fRevertToInv walk, net_processing.cpp:5830-5892).

Core's rules, in Core's order: a peer that did not ask for headers gets an inv;
so does a queue longer than MAX_BLOCKS_TO_ANNOUNCE. Otherwise walk the queue
oldest-first, skipping what the peer already has until the first NEW block,
then take the rest -- bailing out to an inv on anything that has left the
active chain or does not connect to what came before it."
  (let ((queue (peer-blocks-for-headers-relay peer)))
    ;; fRevertToInv (:5838-5840): a peer that asked for neither headers nor
    ;; high-bandwidth compact blocks, or asked only for compact blocks with
    ;; more than one block queued, or any queue over the limit.
    (when (or (and (not (peer-prefers-headers peer))
                   (or (not (peer-compact-block-high-bandwidth peer))
                       (> (length queue) 1)))
              (> (length queue) +max-blocks-to-announce+))
      (return-from %announcement-headers nil))
    (let ((headers '())
          (started nil)
          (previous nil))
      (dolist (hash queue (nreverse headers))
        (let ((entry (bl.store:get-block-index-entry chain-state hash)))
          (unless (and entry (bl.store:entry-on-active-chain-p chain-state entry))
            (return-from %announcement-headers nil))
          (when (and previous
                     (not (equalp (bl.ser:block-header-prev-block
                                   (bl.store:block-index-entry-header entry))
                                  (bl.store:block-index-entry-hash previous))))
            ;; The queued blocks do not chain: revert, as Core does.
            (return-from %announcement-headers nil))
          (setf previous entry)
          (cond (started
                 (push (bl.store:block-index-entry-header entry) headers))
                ((%peer-has-header-p peer chain-state entry))  ; keep looking
                ((let ((prev (bl.store:block-index-entry-prev-entry entry)))
                   (or (null prev) (%peer-has-header-p peer chain-state prev)))
                 (setf started t)
                 (push (bl.store:block-index-entry-header entry) headers))
                ;; Neither this header nor its parent will connect for the
                ;; peer: an inv is the only useful answer.
                (t (return-from %announcement-headers nil))))))))

(defun %flush-peer-block-announcements (peer chain-state)
  "Turn PEER's queued announcements into ONE message and clear the queue (Core
SendMessages' block-announcement section, net_processing.cpp:5825-5956).
Returns T when something was sent."
  (let ((queue (peer-blocks-for-headers-relay peer)))
    (when queue
      (unwind-protect
           (let ((headers (%announcement-headers peer chain-state)))
             (cond
               ;; One new block for a peer that asked us to announce in
               ;; high-bandwidth mode: send it as header-and-ids (:5893-5916).
               ((and headers (null (cdr headers))
                     (peer-compact-block-high-bandwidth peer)
                     (%send-announcement-cmpctblock
                      peer (bl.ser:block-header-hash (first headers))))
                t)
               ((and headers (not (peer-prefers-headers peer)))
                ;; Core's `else fRevertToInv = true' (:5930-5931).
                (%announce-by-inv peer chain-state queue))
               (headers
                (send-message peer (bl.ser:make-headers-message headers))
                ;; Remember the highest header sent: PeerHasHeader asks it
                ;; next time, so the peer is never sent the same range twice.
                (setf (peer-best-header-sent-hash peer)
                      (bl.ser:block-header-hash (car (last headers))))
                t)
               (t (%announce-by-inv peer chain-state queue))))
        (setf (peer-blocks-for-headers-relay peer) nil)))))

(defun %announce-by-inv (peer chain-state queue)
  "Revert to an inv of the LAST queued hash -- Core's \"just try to inv the
tip\" (net_processing.cpp:5933-5953) -- unless the peer has it. T when sent."
  (let* ((hash (car (last queue)))
         (entry (bl.store:get-block-index-entry chain-state hash)))
    (when (and entry (not (%peer-has-header-p peer chain-state entry)))
      (send-message peer (bl.ser:make-inv-message
                          (list (bl.ser:make-inv-vector
                                 :type bl.ser:+inv-type-block+ :hash hash))))
      t)))

(defun %send-announcement-cmpctblock (peer hash)
  "Announce block HASH to PEER as a cmpctblock and record it as the best
header sent (Core SendMessages :5893-5916 and NewPoWValidBlock :2144-2151):
the cached message when HASH is the most recent block, else one built from
the body on disk. NIL, sending nothing, when the body is not there."
  (let ((msg (or (bl.val:most-recent-cmpctblock hash)
                 (let ((block (and bl:*node* (bl.store:get-block
                                           (bl:node-block-store bl:*node*) hash))))
                   (and block (bl.ser:make-cmpctblock-message block))))))
    (when msg
      (bl:log-debug "sending header-and-ids ~A to ~A"
                    (bl.crypto:bytes-to-hex (bl.crypto:reverse-bytes hash))
                    (peer-log-name peer))
      (send-message peer msg)
      (setf (peer-best-header-sent-hash peer) hash)
      t)))

(defvar *highest-fast-announce* 0
  "Core m_highest_fast_announce: the highest block NEW-POW-VALID-BLOCK has
pushed, so each height is pushed once.")

(defun new-pow-valid-block (chain-state entry peers)
  "Core PeerManagerImpl::NewPoWValidBlock (net_processing.cpp:2105-2153): a
new block on our tip is pushed at once, as a cmpctblock, to every peer that
asked us for high-bandwidth announcements (sendcmpct 1) and already has its
parent -- not left for the next SendMessages pass. Once per height, and only
where segwit is active (:2111-2115), and not while relay is disabled, like
every other block announcement here (FLUSH-BLOCK-ANNOUNCEMENTS). Returns the
peers it was sent to."
  (unless (relay-enabled-p)
    (return-from new-pow-valid-block nil))
  (let ((height (bl.store:block-index-entry-height entry))
        (hash (bl.store:block-index-entry-hash entry))
        (prev (bl.store:block-index-entry-prev-entry entry))
        (sent '()))
    (when (and prev
               (> height *highest-fast-announce*)
               (>= height (bl.val:get-segwit-activation-height bl:*network*)))
      (setf *highest-fast-announce* height)
      (dolist (peer peers)
        (when (and (eq (peer-state peer) :ready)
                   (peer-compact-block-high-bandwidth peer)
                   (not (%peer-has-header-p peer chain-state entry))
                   (%peer-has-header-p peer chain-state prev)
                   (%send-announcement-cmpctblock peer hash))
          (push peer sent))))
    sent))

(defun flush-block-announcements (peers chain-state)
  "Announce every peer's queued blocks, one message per peer (Core's
SendMessages pass). Driven from the idle tick, which is where the rest of
SendMessages' per-pass duties already run. Gated on RELAY-ENABLED-P like
RELAY-BLOCK, so a relay-disabled node stays a non-participant -- and it still
CLEARS the queues, so they cannot grow without bound while relay is off."
  (dolist (peer peers)
    (when (peer-blocks-for-headers-relay peer)
      (if (and (relay-enabled-p) (eq (peer-state peer) :ready))
          (handler-case (%flush-peer-block-announcements peer chain-state)
            (error (e)
              (setf (peer-blocks-for-headers-relay peer) nil)
              (bl:log-warn "Announcing to ~A failed: ~A" (peer-log-name peer) e)))
          (setf (peer-blocks-for-headers-relay peer) nil)))))

;;; Sync operations

(defun request-headers (peer chain-state)
  "Request headers from a peer starting from our current tip."
  (let ((locator (bl.store:build-block-locator chain-state)))
    (send-message peer
                  (bl.ser:make-getheaders-message locator))))

;;;; ============================================================
;;;; Compact Block Relay (BIP 152)
;;;; ============================================================

;;; Timeout for pending compact block reconstructions
(defconstant +compact-block-timeout-seconds+ 10)

;;; Compact block reconstruction metrics (thread-safe)
(defvar *compact-block-metrics-lock* (bt:make-lock "compact-block-metrics"))
(defvar *compact-block-success-count* 0)
(defvar *compact-block-failure-count* 0)
(defvar *compact-block-collision-count* 0)

(defun increment-compact-block-success ()
  "Thread-safe increment of success counter."
  (bt:with-lock-held (*compact-block-metrics-lock*)
    (incf *compact-block-success-count*)))

(defun increment-compact-block-failure ()
  "Thread-safe increment of failure counter."
  (bt:with-lock-held (*compact-block-metrics-lock*)
    (incf *compact-block-failure-count*)))

(defun increment-compact-block-collision ()
  "Thread-safe increment of collision counter."
  (bt:with-lock-held (*compact-block-metrics-lock*)
    (incf *compact-block-collision-count*)))

;;; Protocol negotiation

(defconstant +compact-blocks-version+ 2
  "The only BIP152 compact-block version we support: version 2 (wtxid-based,
witness-carrying). Matches Bitcoin Core's CMPCTBLOCKS_VERSION
(net_processing.cpp). Version 1 is non-witness — its prefilled coinbase is
serialized without the 32-byte witness reserved value, so a block reconstructed
from a v1 compact block fails BIP141 validation (bad-witness-nonce-size). We
therefore never announce or accept v1; non-v2 peers fall back to full
MSG_WITNESS_BLOCK downloads.")

(defvar *hb-announcing-peers* '()
  "Peers we have asked to announce blocks in high-bandwidth compact form,
OLDEST FIRST (Core lNodesAnnouncingHeaderAndIDs). BIP152 caps this at 3;
promotion is earned by delivering a new best block, never granted at
handshake.")

(defconstant +max-hb-announcing-peers+ 3
  "BIP152: only 3 peers are asked to announce with compact encodings.")

(defun send-compact-block-negotiation (peer)
  "Advertise compact block support to PEER. We announce only version 2
(witness), matching Bitcoin Core — a v1 (non-witness) compact block would strip
the coinbase witness nonce.

The initial sendcmpct is LOW-BANDWIDTH, as Core's is. High bandwidth is not a
capability handshake, it is a scarce selection: BIP152 allows only 3 peers, and
Core grants it only to a peer that has just delivered a new best block
(MaybeSetPeerAsAnnouncingHeaderAndIDs). Asking every compact-capable peer for
HB — what we used to do — makes every one of them push an unsolicited
cmpctblock for every block instead of about three, and misreports
getpeerinfo's bip152_hb_to."
  (send-message peer (bl.ser:make-sendcmpct-message
                      nil +compact-blocks-version+)))

(defun %set-peer-hb (peer high-bandwidth)
  (setf (peer-compact-block-high-bandwidth-to peer) high-bandwidth)
  (send-message peer (bl.ser:make-sendcmpct-message
                      high-bandwidth +compact-blocks-version+)))

(defun %hb-peer-live-p (peer)
  "T while PEER is still a peer we could actually ask to announce blocks.

Core reaches its HB list entries by NodeId — GetPeerRef (net_processing.cpp:1296)
and ForNode (:1310) — so an entry whose peer has gone away simply resolves to
nothing: it counts as NEITHER inbound nor outbound in the census (:1297), can
never be the protected front (:1303-1305), and a promotion targeting a gone
node mutates nothing at all (ForNode returns without running the lambda). We
hold the peer STRUCT rather than an id, so nothing resolves to nothing for us
and we have to ask the struct: :disconnected is our \"gone\"."
  (not (eq (peer-state peer) :disconnected)))

(defun maybe-set-peer-announcing-hb (peer)
  "Promote PEER to high-bandwidth compact-block announcements after it
delivered a new best block (Core MaybeSetPeerAsAnnouncingHeaderAndIDs,
net_processing.cpp:1273-1330).

Four subtleties, each of which Core spells out:
  - A peer ALREADY in the list is only moved to the back; no sendcmpct is
    re-sent. Re-announcing on every block would be a visible protocol anomaly.
  - Never in blocksonly mode: our mempool would not hold the transactions
    needed to reconstruct the block anyway.
  - INBOUND-PROTECTION SWAP. When the peer being promoted is inbound, the list
    is already full, and exactly ONE entry is outbound sitting at the front,
    Core swaps the first two so the outbound HB peer is not the one evicted.
    Without it a flood of inbound peers evicts every outbound HB peer in turn —
    an eclipse/partition weakening, and the same class of ordering mistake as
    trimming the wrong end of the reorg disconnect pool.
  - DEAD ENTRIES ARE NOT PEERS. Core's list holds NodeIds, so a disconnected
    entry is inert everywhere it is read. Ours holds live struct references, so
    a corpse would keep counting as outbound and could trigger the protection
    swap in ITS favour — evicting a live inbound HB peer to defend a peer that
    is never going to announce anything again. Sweeping them here (the list's
    only reader) restores Core's semantics AND reclaims the slot, which Core
    itself cannot do because it never revisits the list on disconnect."
  (when (and (not (ignore-incoming-txs-p))
             ;; Core's m_provides_cmpctblocks gate: only a peer that signalled
             ;; compact-block support is eligible.
             (plusp (peer-compact-block-version peer))
             ;; Core's ForNode(nodeid) lookup: a gone peer is never found, so
             ;; nothing is evicted and nothing is added on its behalf.
             (%hb-peer-live-p peer))
    (setf *hb-announcing-peers*
          (remove-if-not #'%hb-peer-live-p *hb-announcing-peers*))
    ;; Already selected: move to the back (most recently useful), send nothing.
    (if (member peer *hb-announcing-peers*)
        (setf *hb-announcing-peers*
              (append (remove peer *hb-announcing-peers*) (list peer)))
        (let ((outbound-count (count-if-not #'peer-inbound *hb-announcing-peers*)))
          ;; Inbound-protection swap.
          (when (and (peer-inbound peer)
                     (>= (length *hb-announcing-peers*) +max-hb-announcing-peers+)
                     (= outbound-count 1)
                     (first *hb-announcing-peers*)
                     (not (peer-inbound (first *hb-announcing-peers*))))
            (rotatef (nth 0 *hb-announcing-peers*) (nth 1 *hb-announcing-peers*)))
          ;; Over the cap: demote the OLDEST (front) back to low bandwidth.
          (when (>= (length *hb-announcing-peers*) +max-hb-announcing-peers+)
            (let ((evicted (first *hb-announcing-peers*)))
              (setf *hb-announcing-peers* (rest *hb-announcing-peers*))
              (ignore-errors (%set-peer-hb evicted nil))))
          (%set-peer-hb peer t)
          (setf *hb-announcing-peers*
                (append *hb-announcing-peers* (list peer)))))))

(defun maybe-promote-block-deliverer (peer chain-state)
  "Consider promoting PEER to HB after it delivered a block (Core BlockChecked,
net_processing.cpp:2207-2223).

CALL THIS ONLY ONCE THE BLOCK HAS CONNECTED — validating is not enough. Core's
BlockChecked splits on the validation result: an INVALID block goes to
MaybePunishNodeForBlock (:2207), and only the `state.IsValid()` arm reaches
MaybeSetPeerAsAnnouncingHeaderAndIDs (:2218-2223). Promoting before validation
lets a peer that delivers a reconstructible-but-invalid compact block buy an HB
slot and, through the cap-of-3 eviction, demote an honest one — an
attacker-chosen swap for the price of one bad block.

And a VALID state can only ever come from ConnectTip (validation.cpp:3070);
ProcessNewBlock's other BlockChecked emit (:4455) is the AcceptBlock-failure
path, and a block we already hold short-circuits inside AcceptBlock and never
reaches ConnectTip. So the transports must gate on the block having ADVANCED
THE TIP (%block-newly-connected-p), not on ACCEPT-DOWNLOADED-BLOCK's `valid',
which is also T for a side-branch store and for a replay of our own tip — the
free-HB-slot echo. The transport itself does not matter: Core drives this off
mapBlockSource, which is filled for full blocks as well as compact ones, so
every delivery path must reach here after (and only after) it connects.

Core's gate is state.IsValid() AND !IsInitialBlockDownload() AND
mapBlocksInFlight.count(hash) == mapBlocksInFlight.size() — that last clause
being its proxy for \"this delivery was not part of a batch download\". We gate
on connection and not-IBD only. DOCUMENTED DIVERGENCE: we may therefore promote
somewhat more eagerly than Core mid-download. The blast radius is bounded — the
cap of 3, the move-to-back on re-selection, and the inbound-protection swap all
still apply — but it is a real difference and is left as a follow-up rather
than silently approximated away."
  (unless (initial-block-download-p chain-state)
    (maybe-set-peer-announcing-hb peer)))

(define-p2p-handler "sendcmpct" (peer payload ctx)
  "Handle a sendcmpct message from a peer. We support only compact block version 2;
any other version is ignored entirely, mirroring Bitcoin Core
(net_processing.cpp:3913 `if (sendcmpct_version != CMPCTBLOCKS_VERSION) return;`). A
v1 compact block would deliver a witness-stripped coinbase.

The high-bandwidth flag FOLLOWS the message in both directions
(net_processing.cpp:3917-3921): sendcmpct(1) selects us as the peer's BIP152
high-bandwidth announcer, sendcmpct(0) deselects us again. Core sends the
deselecting one itself, to the peer it drops from lNodesAnnouncingHeaderAndIDs
(MaybeSetPeerAsAnnouncingHeaderAndIDs, :1317), so a promote-then-demote is
ordinary traffic rather than a corner case. Setting the slot only on 1 left
getpeerinfo's bip152_hb_from stuck at T for the life of such a connection."
  (declare (ignore ctx))
  (multiple-value-bind (high-bandwidth version)
      (bl.ser:parse-sendcmpct-payload payload)
    (when (= version +compact-blocks-version+)
      (setf (peer-compact-block-version peer) version)
      (setf (peer-compact-block-high-bandwidth peer) high-bandwidth))
    (bl:log-debug "sendcmpct v~D (high-bw: ~A) ~A"
                  version high-bandwidth
                  (peer-log-name peer))))

;;; Short ID map building

(defun build-shortid-map (mempool k0 k1 use-wtxid &optional extra-txn)
  "Build hash table mapping short IDs to (tx . expected-id) pairs.
   USE-WTXID is true for compact block version 2.
   Returns (VALUES map collision-detected).
   A short ID two mempool transactions share maps to :COLLISION instead: a
   block slot carrying it is requested, as Core's InitData requests one two
   mempool transactions match (blockencodings.cpp:131-138).
   EXTRA-TXN, Core's extra_txn -- the (wtxid . tx) ring of recently rejected
   and replaced transactions -- is folded in after the mempool as InitData
   folds it (:147-176): an extra transaction supplies a short ID nothing
   matched yet, and one that matches a short ID already supplied by a
   transaction with a DIFFERENT wtxid makes it a collision (the same
   transaction in the pool and the ring is no collision)."
  (let ((map (make-hash-table :test 'eql))
        (collision nil))
    (bl.mp:mempool-for-each
     mempool
     (lambda (txid entry)
       (let* ((tx (bl.mp:mempool-entry-transaction entry))
              (id (if use-wtxid
                      (bl.ser:transaction-wtxid tx)
                      txid))
              (short-id (bl.crypto:compute-short-txid k0 k1 id)))
         (if (gethash short-id map)
             (setf collision t
                   (gethash short-id map) :collision)
             (setf (gethash short-id map) (cons tx id))))))
    (loop for (wtxid . tx) in extra-txn
          for id = (if use-wtxid wtxid (bl.ser:transaction-hash tx))
          for short-id = (bl.crypto:compute-short-txid k0 k1 id)
          for have = (gethash short-id map)
          do (cond ((null have) (setf (gethash short-id map) (cons tx id)))
                   ((and (consp have)
                         (not (equalp (bl.ser:transaction-wtxid (car have)) wtxid)))
                    (setf collision t
                          (gethash short-id map) :collision))))
    (values map collision)))


;;; Block reconstruction

(defun reconstruct-compact-block (compact-block mempool use-wtxid)
  "Attempt to reconstruct full block from compact block and mempool.
   Returns (VALUES block missing-indexes partial-transactions) where:
   - On success: block is the full block, missing-indexes is NIL
   - On missing txs: block is NIL, missing-indexes is list of needed indexes,
     partial-transactions is array with found txs filled in
   - On collision: block is NIL, missing-indexes is :COLLISION
   - On a structurally malformed message: block is NIL, missing-indexes is
     :MALFORMED

:COLLISION and :MALFORMED are Core's two distinct PartiallyDownloadedBlock::
InitData failures and the caller must NOT conflate them (blockencodings.cpp:
59-120). :MALFORMED is READ_STATUS_INVALID — a message no honest peer can
send (a null header, no transactions at all, an absurd transaction count, a
null prefilled transaction, a prefilled index outside the block, fewer short
IDs than empty slots) — and Core answers it with Misbehaving
(net_processing.cpp:4680-4683). :COLLISION is READ_STATUS_FAILED — the block's
OWN short IDs repeat, which a 48-bit hash does by chance — and Core answers it
with a plain full-block getdata (:4683-4694). Two MEMPOOL transactions that
share a short ID are no failure: a block slot carrying it is simply requested
(blockencodings.cpp:131-138), and one the block does not carry costs nothing.
Core's other READ_STATUS_FAILED, a std::unordered_map bucket over twelve
entries (:98-111), measures its container's hashing and has no counterpart."
  (let* ((header (bl.ser:compact-block-header compact-block))
         (nonce (bl.ser:compact-block-nonce compact-block))
         (short-ids-list (bl.ser:compact-block-short-ids compact-block))
         (prefilled (bl.ser:compact-block-prefilled-txs compact-block))
         (tx-count (+ (length short-ids-list) (length prefilled)))
         (header-bytes (bl.ser:serialize-block-header header))
         (short-ids (coerce short-ids-list 'vector)))

    ;; Validate tx-count is reasonable (prevent DoS). Core InitData's first two
    ;; guards, both READ_STATUS_INVALID (blockencodings.cpp:60-63), the first
    ;; also refusing a null header (CBlockHeader::IsNull, nBits 0).
    (when (or (zerop (bl.ser:block-header-bits header))
              (zerop tx-count) (> tx-count 100000))
      (bl:log-warn "Invalid compact block tx count: ~D" tx-count)
      (return-from reconstruct-compact-block (values nil :malformed)))

    ;; Compute SipHash keys
    (multiple-value-bind (k0 k1)
        (bl.crypto:compute-siphash-key header-bytes nonce)

      ;; Build short ID map from mempool
      (let ((shortid-map (build-shortid-map mempool k0 k1 use-wtxid (compact-extra-transactions))))
        (let ((transactions (make-array tx-count :initial-element nil))
              (missing-indexes '())
              (short-id-idx 0))

          ;; Place prefilled transactions at their absolute indexes. A null
          ;; one (CTransaction::IsNull: no inputs, no outputs) and one past
          ;; the block (Core's lastprefilledindex bound) are
          ;; READ_STATUS_INVALID (blockencodings.cpp:72-84).
          (dolist (ptx prefilled)
            (let ((idx (bl.ser:prefilled-tx-index ptx))
                  (ptx-tx (bl.ser:prefilled-tx-transaction ptx)))
              (when (or (and (zerop (length (bl.ser:transaction-inputs ptx-tx)))
                             (zerop (length (bl.ser:transaction-outputs ptx-tx))))
                        (not (< -1 idx tx-count)))
                (bl:log-warn "Invalid prefilled tx at index ~D (max ~D)" idx (1- tx-count))
                (return-from reconstruct-compact-block (values nil :malformed nil)))
              (setf (aref transactions idx) ptx-tx)))

          ;; The block's own short IDs, each to the slot it fills (the
          ;; slots no prefilled transaction took, in order). A short ID the
          ;; block carries twice is READ_STATUS_FAILED
          ;; (blockencodings.cpp:92-117).
          (let ((slots (make-hash-table :test 'eql)))
            (dotimes (i tx-count)
              (when (null (aref transactions i))
                (when (>= short-id-idx (length short-ids))
                  ;; More empty slots than short IDs — a slot with neither a
                  ;; prefilled tx nor a short ID. READ_STATUS_INVALID in Core
                  ;; (blockencodings.cpp:80-84).
                  (bl:log-warn "Short ID count mismatch")
                  (return-from reconstruct-compact-block (values nil :malformed nil)))
                (let ((short-id (aref short-ids short-id-idx)))
                  (when (gethash short-id slots)
                    (increment-compact-block-collision)
                    (bl:log-warn "Short ID collision in the compact block, falling back to full block")
                    (return-from reconstruct-compact-block (values nil :collision nil)))
                  (setf (gethash short-id slots) i))
                (incf short-id-idx)))
            ;; Fill each slot from the mempool: a short ID one mempool
            ;; transaction matches supplies it; one that none or several
            ;; match is requested (blockencodings.cpp:120-146).
            (maphash (lambda (short-id i)
                       (let ((tx-pair (gethash short-id shortid-map)))
                         (if (consp tx-pair)
                             (setf (aref transactions i) (car tx-pair))
                             (push i missing-indexes))))
                     slots)
            (setf missing-indexes (sort missing-indexes #'<)))

          (if missing-indexes
              (values nil missing-indexes transactions)
              (values (bl.ser:make-bitcoin-block
                       :header header
                       :transactions (coerce transactions 'list))
                      nil nil)))))))

;;; Compact block message handling

;;; Core's MaybePunishNodeForBlock (net_processing.cpp:1908-1950) is PER
;;; REASON, never all-or-nothing: via_compact_block exempts three of its seven
;;; arms and no more. Every compact-block outcome is routed through it — the
;;; announced header at :4589-4593, and both ProcessNewBlock results, whose
;;; mapBlockSource entries carry /*punish=*/false (:4778 cmpctblock, :3516
;;; blocktxn) which :2211 inverts into via_compact_block=true. So the exemption
;;; is a filter on the VERDICT, not an amnesty for the message type. The two
;;; lists below are that switch, arm by arm, over the verdicts our
;;; VALIDATE-BLOCK / VALIDATE-BLOCK-HEADER actually return.

(alexandria:define-constant +compact-block-punished-reasons+
  '(:bad-proof-of-work :bad-difficulty :bad-version :time-too-old
    :time-timewarp-attack :bad-prevblk)
  :test #'equalp :documentation "Validation verdicts Core punishes even when via_compact_block is true.

The first five are BLOCK_INVALID_HEADER: high-hash (validation.cpp:3864),
bad-diffbits (:4121), time-too-old (:4125), time-timewarp-attack (:4134),
bad-version (:4148). :BAD-PREVBLK is BLOCK_INVALID_PREV (:4254). Both arms call
Misbehaving unconditionally (net_processing.cpp:1936-1940). No honest peer
relays a header that fails PoW, difficulty, MTP, the BIP94 timewarp rule or the
softfork version floor, so there is no false-positive risk here — and leaving
the class unpunished is not merely a parity gap but a DoS: nothing downstream
scores a compact block, so one connection can replay an invalid-PoW cmpctblock
without limit, each replay costing a full BUILD-SHORTID-MAP SipHash pass over
every mempool entry under an attacker-chosen key.

BLOCK_MISSING_PREV (our :ORPHAN-BLOCK) is deliberately absent. Core punishes
that arm too (:1942-1944) but structurally cannot reach it from a compact
block: the cmpctblock handler returns at the parent lookup with a getheaders
(:4571-4577), and by blocktxn time the header is already in the index.
HANDLE-CMPCTBLOCK's parent guard is that same foreclosure, so an :ORPHAN-BLOCK
that survives it means our own index lost an entry — the honest-peer case the
GA8 finding was about.")

(alexandria:define-constant +compact-block-ignored-reasons+
  '(:time-too-new :duplicate-invalid)
  :test #'equalp :documentation "Verdicts that end a compact block with neither punishment NOR a refetch.

:TIME-TOO-NEW is BLOCK_TIME_FUTURE (validation.cpp:4141), whose arm is a bare
break (net_processing.cpp:1946-1947): the block is not ours to accept yet, and
refetching it in full would route an honest peer straight into HANDLE-BLOCK,
which does punish. :DUPLICATE-INVALID is BLOCK_CACHED_INVALID (:4232 /
net_processing.cpp:1926-1935), exempted for every compact-block sender;
re-downloading a block we already marked invalid would be self-inflicted DoS.")

(defun compact-block-failure-action (reason)
  "Which MaybePunishNodeForBlock arm REASON lands on with via_compact_block
true: :PUNISH, :IGNORE, or :REFETCH.

:REFETCH is the BLOCK_CONSENSUS / BLOCK_MUTATED default (net_processing.cpp:
1920-1926) — the one class BIP152 makes an honest peer's fault to have, since a
relaying peer may have validated only the header and a reconstruction that
substituted one of OUR mempool transactions can yield a block the sender never
sent. Core answers that shape one layer down with a plain getdata (:4683-4694);
if the block really is bad, the full copy arrives on the BLOCK message path,
where via_compact_block is false and HANDLE-BLOCK punishes. An unrecognised
verdict defaults to :REFETCH: a new validation keyword must never start
discouraging peers just by existing."
  (cond ((member reason +compact-block-punished-reasons+) :punish)
        ((member reason +compact-block-ignored-reasons+) :ignore)
        (t :refetch)))

(defun handle-compact-block-failure (peer block-hash reason context)
  "Dispose of a failed compact block from PEER per COMPACT-BLOCK-FAILURE-ACTION.
Exactly one compact-block failure is counted on every branch (:REFETCH counts
its own inside REQUEST-FULL-BLOCK). Returns the action taken."
  (let ((action (compact-block-failure-action reason)))
    (bl:log-warn "~A ~A: ~(~A~) — ~(~A~)"
                           context (bl.crypto:bytes-to-hex block-hash)
                           reason action)
    (ecase action
      (:punish (increment-compact-block-failure)
               (record-misbehavior peer (format nil "~A (~(~A~))" context reason)))
      (:ignore (increment-compact-block-failure))
      (:refetch (request-full-block peer block-hash)))
    action))

(defun compact-block-header-verdict (chain-state header block-hash prev-hash)
  "Core's cmpctblock header admission — the parent lookup, the anti-DoS work
floor and ProcessNewBlockHeaders({{cmpctblock.header}}) — run BEFORE any
reconstruction (net_processing.cpp:4569-4593). Returns
(VALUES VERDICT REASON CREDITS-ANNOUNCEMENT):

  :NO-PARENT — parent absent from the index; the caller answers with getheaders
  :LOW-WORK  — the announced chain does not clear the anti-DoS work floor; the
               caller drops it silently
  :ALREADY-HAVE — in the index and nothing to gain from it; the caller drops it
  :ACCEPT    — the header is admissible, go on and reconstruct
  :REJECT    — REASON says what HANDLE-COMPACT-BLOCK-FAILURE must do with it

CREDITS-ANNOUNCEMENT is Core's
`received_new_header && pindex->nChainWork > tip->nChainWork' (:4623): the
announced block was unknown to us AND beats our tip. It is returned from here
rather than recomputed by the caller because both halves are index reads, and
this function is the one place already holding the node lock across them — and
because the `unknown to us' half must be answered from the SAME lookup the
:ACCEPT/:REJECT decision used. Answering it after the caller has processed the
block would always say `known'.

Order is the handler's, not AcceptBlockHeader's: Core looks the PARENT up first
(:4570-4577), then applies the anti-DoS work floor (:4578-4582), and only then
calls ProcessNewBlockHeaders, whose AcceptBlockHeader short-circuits a header we
already hold (BLOCK_CACHED_INVALID when we marked it invalid, otherwise accepted
without re-checking) and otherwise runs CheckBlockHeader's PoW, the parent's own
validity and ContextualCheckBlockHeader (validation.cpp:4226-4259). The two
handler gates come FIRST on purpose: they are the ones that cost the sender
nothing to trigger, so a header below the work floor must be dropped before it
can be scored, logged per-arm, or reach the mempool. Doing all of this before
the mempool is touched is what makes a junk header cheap for us and expensive
for nobody: BUILD-SHORTID-MAP hashes the whole mempool under a key derived from
the attacker's header, so it must not run for a header we are going to drop.

Pure reads of the block index — the caller holds the node lock across it, does
the index INSERTION for an accepted header (Core's ProcessNewBlockHeaders write
half) and does the IO (getheaders / getdata / disconnect) outside."
  (let* ((known (bl.store:get-block-index-entry chain-state block-hash))
         (prev-entry (bl.store:get-block-index-entry chain-state prev-hash))
         ;; Core's `prev_block->nChainWork + GetBlockProof(cmpctblock.header)'
         ;; (:4578) — the work the announced chain would carry. Used by both
         ;; the anti-DoS floor below and the announcement credit at the end,
         ;; which is the same quantity in Core.
         (announced-work
           (and prev-entry
                (bl.store:calculate-chain-work
                 (bl.ser:block-header-bits header)
                 (bl.store:block-index-entry-chain-work prev-entry)))))
    (cond
      ;; Parent not in the index: the announcement outran our header chain.
      ;; The ORDINARY case, not an attack — high-bandwidth compact relay beats
      ;; headers announcements by design, so falling one block behind while a
      ;; getblocktxn round-trip is in flight is enough. Core asks for deeper
      ;; headers and returns before anything can be DoS-scored (:4571-4577);
      ;; reconstructing instead would hand ACCEPT-DOWNLOADED-BLOCK a block whose
      ;; parent entry is missing, i.e. :ORPHAN-BLOCK, and permanently exile our
      ;; fastest honest block-relay peer.
      ((null prev-entry) (values :no-parent nil))
      ;; "Ignoring low-work compact block" (:4578-4582), the gate that makes
      ;; the whole handler affordable. Everything below this line — the header
      ;; battery, the index write, the shortid map over the mempool — is work
      ;; a peer can ask for with a ~100-byte message, and PoW at the announced
      ;; header's own claimed difficulty is the only thing that bounds how
      ;; often it may. Without it a header at the minimum regtest/testnet
      ;; target, ground in microseconds, buys a full mempool pass every time.
      ;; Silent: Core logs and returns, with no misbehaviour score, because a
      ;; peer far behind us relays low-work blocks honestly.
      ((< announced-work (anti-dos-work-threshold chain-state))
       (values :low-work nil nil))
      ;; Already-known header. Core returns true early for it, except when we
      ;; marked it invalid: BLOCK_CACHED_INVALID (validation.cpp:4229-4237).
      ((and known (eq (bl.store:block-index-entry-status known) :invalid))
       (values :reject :duplicate-invalid))
      ;; Already in the index AND nothing new to gain from it: Core's
      ;; `pindex->nChainWork <= tip->nChainWork || pindex->nTx != 0` early
      ;; return (net_processing.cpp CMPCTBLOCK handler). Either we know
      ;; something better, or we have had this block's body at some point — in
      ;; both cases our mempool is the wrong tool and reconstruction is pure
      ;; cost. Without this gate a peer can replay one cmpctblock forever and
      ;; make us hash the WHOLE MEMPOOL into a shortid map each time.
      ;; Core also re-requests the block by plain getdata here when it had
      ;; asked THIS peer for it; HANDLE-CMPCTBLOCK's :ALREADY-HAVE arm does.
      ((and known
            (let ((tip-hash (bl.store:best-block-hash chain-state)))
              (or (plusp (bl.store:block-index-entry-tx-count known))
                  (let ((tip (and tip-hash
                                  (bl.store:get-block-index-entry
                                   chain-state tip-hash))))
                    (and tip
                         (<= (bl.store:block-index-entry-chain-work known)
                             (bl.store:block-index-entry-chain-work tip)))))))
       (values :already-have nil nil))
      ;; Known, but it beats our tip and we have never had the body: worth
      ;; reconstructing. received_new_header is false, so no announcement
      ;; credit however much work it carries.
      (known (values :accept nil nil))
      ;; Building on a block we rejected: BLOCK_INVALID_PREV (validation.cpp:
      ;; 4251-4255), punished regardless of via_compact_block.
      ((eq (bl.store:block-index-entry-status prev-entry) :invalid)
       (values :reject :bad-prevblk))
      (t
       ;; CheckBlockHeader + ContextualCheckBlockHeader at the header's own
       ;; branch height — PoW, MTP, BIP94 timewarp, softfork version floor and
       ;; the difficulty bits. Identical to the header battery VALIDATE-BLOCK
       ;; runs later, so this rejects nothing we would have accepted; it only
       ;; moves the verdict ahead of the mempool pass and makes it punishable.
       (multiple-value-bind (valid reason)
           (bl.val:validate-block-header
            header chain-state (bl.ser:get-unix-time)
            :prev-hash prev-hash
            :height (1+ (bl.store:block-index-entry-height prev-entry))
            :prev-entry prev-entry)
         (if valid
             (values :accept nil
                     ;; KNOWN is NIL on this branch, so received_new_header
                     ;; holds; all that remains is the work comparison. The
                     ;; header is not in the index yet (this function is pure
                     ;; reads), so its work is ANNOUNCED-WORK above — the way
                     ;; Core computes it a few lines earlier for the anti-DoS
                     ;; floor (:4578).
                     (let* ((tip-hash (bl.store:best-block-hash chain-state))
                            (tip (and tip-hash
                                      (bl.store:get-block-index-entry
                                       chain-state tip-hash))))
                       (and tip
                            (> announced-work
                               (bl.store:block-index-entry-chain-work tip)))))
             (values :reject reason)))))))

(defun admit-compact-block-header (peer chain-state header block-hash prev-hash)
  "COMPACT-BLOCK-HEADER-VERDICT plus, for an accepted header, the WRITE half of
Core's ProcessNewBlockHeaders({{cmpctblock.header}}, min_pow_checked=true)
(net_processing.cpp:4590) and the UpdateBlockAvailability that follows it
(:4617). Returns the verdict's three values unchanged. Must be called under the
node lock: it mutates the block index.

AcceptBlockHeader ends in AddToBlockIndex, so in Core the announced header is in
the index from the FIRST cmpctblock on and a replay is answered by the
already-known gates. We used to run the verdict and never insert anything, which
left KNOWN permanently NIL for an unseen header — the :ALREADY-HAVE arm was
unreachable on this path, and every copy of one message re-ran the header
battery and then BUILD-SHORTID-MAP over the whole mempool.

PROCESS-HEADERS is our AddToBlockIndex: it skips a header we already hold,
computes the chain work, stores it :HEADER-VALID and queues the body for
download. Core's min_pow_checked=true here means `the caller already applied the
work floor', which the verdict's :LOW-WORK arm is; process-headers' own floor
agrees with it (the anti-DoS threshold is never below nMinimumChainWork), so it
cannot drop a header the verdict accepted."
  (multiple-value-bind (verdict reason credits-announcement)
      (compact-block-header-verdict chain-state header block-hash prev-hash)
    (when (eq verdict :accept)
      (process-headers (list header) chain-state)
      (update-block-availability peer chain-state block-hash)
      ;; Core's `pindex->nChainWork <= ActiveChain().Tip()->nChainWork'
      ;; return (net_processing.cpp:4645-4655) runs on the header it has JUST
      ;; indexed too: a new header no better than our tip stays headers-only
      ;; and is not reconstructed. The verdict tested it only for a header
      ;; already known, so an old fork's compact block was rebuilt and stored
      ;; (p2p_compactblocks.py:708 expects `headers-only').
      (let ((entry (bl.store:get-block-index-entry chain-state block-hash))
            (tip (bl.store:get-block-index-entry
                  chain-state (bl.store:best-block-hash chain-state))))
        (when (and entry tip
                   (<= (bl.store:block-index-entry-chain-work entry)
                       (bl.store:block-index-entry-chain-work tip)))
          (setf verdict :already-have))))
    (values verdict reason credits-announcement)))

(define-p2p-handler ("cmpctblock" :needs-mempool t) (peer payload ctx)
  "Handle a cmpctblock message: validate the announced header, then attempt
reconstruction from the mempool.

Punishment follows Core's MaybePunishNodeForBlock arm by arm (see
COMPACT-BLOCK-FAILURE-ACTION). An INVALID HEADER — bad PoW, bad difficulty
bits, a timestamp at or below MTP, a BIP94 timewarp violation, a version below
the softfork floor — still discourages its sender through the compact path,
exactly as Core does at net_processing.cpp:4589-4593, and does so BEFORE the
mempool is hashed. What no longer punishes is the class BIP152 makes honest:
a peer may relay a compact block having validated only the header, and
reconstruction can substitute our own mempool transactions, so a
consensus-invalid result earns a full-block getdata instead. A structurally
malformed MESSAGE (READ_STATUS_INVALID) is punished as before."
  (bl.ctx:with-node-context (chain-state mempool) ctx
  (let* ((compact-block (bl.ser:parse-cmpctblock-payload payload))
         (header (bl.ser:compact-block-header compact-block))
         (block-hash (bl.ser:block-header-hash header))
         (prev-hash (bl.ser:block-header-prev-block header))
         (use-wtxid (= (peer-compact-block-version peer) 2)))

    ;; Header gate, ahead of everything else — including the stale-pending
    ;; clear below, so an announcement we are about to drop cannot destroy an
    ;; in-flight reconstruction of the block we are actually missing (Core
    ;; keeps per-block in-flight state, so it has no such cross-talk).
    (multiple-value-bind (verdict reason credits-announcement)
        (with-current-node-lock
          (admit-compact-block-header peer chain-state header block-hash
                                      prev-hash))
      (ecase verdict
        (:accept
         ;; Core net_processing.cpp:4623. The stamp is credited HERE, on the
         ;; announcement, and not in the successful-reconstruction branch
         ;; below: whether we could rebuild the block from our own mempool
         ;; says something about our mempool, not about how useful this peer
         ;; is at keeping us on the best chain. Crediting the reconstruct
         ;; instead would penalise exactly the peer that reaches us first with
         ;; a block nobody has seen yet.
         (when credits-announcement
           (credit-block-announcement peer)))
        (:already-have
         ;; Not a fault: an honest peer relays what it just accepted, and two
         ;; of them announcing the same block is normal. Debug-level, and no
         ;; punishment.
         (bl:log-cat
          "net" "cmpctblock ~A from ~A: already known and no better than our tip"
          (bl.crypto:bytes-to-hex block-hash)
          (peer-log-name peer))
         ;; `We requested this block for some reason, but our mempool will
         ;; probably be useless so we just grab the block via normal getdata'
         ;; (net_processing.cpp:4645-4654).
         (when (block-requested-from-peer-p block-hash peer)
           (%getdata-witness-block peer block-hash))
         (return-from handle-cmpctblock nil))
        (:low-work
         ;; Core "Ignoring low-work compact block from peer %d" (:4581):
         ;; LogDebug and return, with no misbehaviour score — a peer whose
         ;; chain is far behind ours relays such blocks in good faith. In
         ;; Core's words: p2p_compactblocks.py:656 waits for this line.
         (bl:log-cat "net" "Ignoring low-work compact block from peer ~D"
                     (peer-id peer))
         (return-from handle-cmpctblock nil))
        (:no-parent
         (bl:log-cat "net"
                     "cmpctblock ~A: parent ~A not in index — getheaders to ~A"
                     (bl.crypto:bytes-to-hex block-hash)
                     (bl.crypto:bytes-to-hex prev-hash)
                     (peer-log-name peer))
         ;; Core gates the getheaders on !IsInitialBlockDownload(): during IBD
         ;; the header sync owns the locator and an extra request is noise.
         (unless (initial-block-download-p chain-state)
           (request-headers-for-ibd peer chain-state))
         (return-from handle-cmpctblock nil))
        (:reject
         (handle-compact-block-failure peer block-hash reason
                                       "invalid header via cmpctblock")
         (return-from handle-cmpctblock nil))))

    ;; Core's in-flight rules for an announced block we still want
    ;; (net_processing.cpp:4629-4745). Up to +MAX-CMPCTBLOCKS-INFLIGHT-PER-
    ;; BLOCK+ peers may each run a getblocktxn round trip for the same block;
    ;; the first to complete it wins and settles everyone else's request.
    (let* ((requests (block-in-flight-requests block-hash))
           (already-in-flight (length requests))
           ;; `It's either empty or first in line' (:4633-4634).
           (first-in-flight (or (null requests) (eq (car (first requests)) peer)))
           (from-this-peer (block-requested-from-peer-p block-hash peer))
           (height (1+ (bl.store:block-index-entry-height
                        (bl.store:get-block-index-entry chain-state prev-hash)))))
      (cond
        ;; `If we're not close to tip yet, give up and let parallel block
        ;; fetch work its magic' (:4657-4660).
        ((and (zerop already-in-flight) (not (%can-direct-fetch-p chain-state)))
         nil)
        ;; Far ahead of our tip (:4735-4746): our mempool will be no use. A
        ;; block we asked this peer for is fetched whole; an announcement is
        ;; treated as the headers message it amounts to (:4756-4763).
        ((> height (+ (bl.store:current-height chain-state) 2))
         (if from-this-peer
             (%getdata-witness-block peer block-hash)
             (with-current-node-lock
               (ingest-headers-from-peer peer (list header) chain-state))))
        ;; A slot for this peer (:4665-4666): the block is not yet held by
        ;; three peers and this one is not at its own download cap -- or it
        ;; is one of the peers already holding it.
        ((or (and (< already-in-flight +max-cmpctblocks-inflight-per-block+)
                  (< (count-peer-in-flight peer) +max-blocks-in-transit-per-peer+))
             from-this-peer)
         (%compact-block-take-slot peer compact-block block-hash header
                                   use-wtxid already-in-flight first-in-flight
                                   ctx))
        ;; Already in flight from others, or this peer has too many blocks
        ;; outstanding: `Optimistically try to reconstruct anyway since we
        ;; might be able to without any round trips' (:4724-4741), and give
        ;; up quietly otherwise.
        (t
         (let ((block (reconstruct-compact-block compact-block mempool use-wtxid)))
           (when block
             (%process-compact-block peer block block-hash ctx
                                     "reconstructed compact block invalid")))))))))

(defun %getdata-witness-block (peer block-hash)
  "Ask PEER for BLOCK-HASH as a whole witness block."
  (send-message peer
                (bl.ser:make-getdata-message
                 (list (bl.ser:make-inv-vector
                        :type bl.ser:+inv-type-witness-block+
                        :hash block-hash)))))

(defun %process-compact-block (peer block block-hash ctx context)
  "Validate and connect BLOCK, rebuilt from PEER's compact block (from the
mempool alone, or completed by a blocktxn). Core ProcessBlock with
force_processing (net_processing.cpp:3427-3441, :3520, :4777-4798): a block
that is accepted settles EVERY peer's request for it -- RemoveBlockRequest(hash,
nullopt) -- so the other peers racing to complete the same block are told
nothing more and their late blocktxn is one we were not expecting. CONTEXT
names the path in the failure log. Returns T when the block connected."
  (bl.ctx:with-node-context (chain-state utxo-set block-store mempool) ctx
    (increment-compact-block-success)
    ;; A rebuilt block is a block delivery from this peer: stamps getpeerinfo
    ;; "last_block" and resets stall tracking.
    (record-block-received-from-peer peer)
    (let ((connected
            (with-current-node-lock
              (let ((tip-before (bl.store:best-block-hash chain-state)))
                (multiple-value-bind (valid error)
                    (accept-downloaded-block block chain-state utxo-set block-store
                                             :mempool mempool)
                  (cond
                    (valid
                     (remove-block-request block-hash)
                     (%block-newly-connected-p chain-state block-hash tip-before))
                    (t
                     (handle-compact-block-failure peer block-hash error context)
                     nil)))))))
      ;; Earned HB promotion -- only once the block CONNECTED, never on
      ;; acceptance alone (Core BlockChecked's valid state comes from
      ;; ConnectTip; an invalid block goes to MaybePunishNodeForBlock, and a
      ;; block we already have never reaches ConnectTip at all). Outside the
      ;; node lock: promotion writes sendcmpct to up to two sockets.
      (when connected
        (maybe-promote-block-deliverer peer chain-state))
      connected)))

(defun %compact-block-take-slot (peer compact-block block-hash header use-wtxid
                                 already-in-flight first-in-flight ctx)
  "PEER takes an in-flight slot for BLOCK-HASH and we try to complete its
compact block: Core net_processing.cpp:4667-4722. ALREADY-IN-FLIGHT and
FIRST-IN-FLIGHT are the block's request count and whether PEER heads its
request list, both as they stood BEFORE this announcement.

When transactions are missing, the getblocktxn goes to the peer first in
line; to any other peer only when it is one we chose as high-bandwidth AND
it is outbound, or an outbound peer already holds the block, or this is not
the LAST slot -- `which we may reserve for first outbound' (:4707-4716).
Otherwise the slot is given back at once."
  (bl.ctx:with-node-context (mempool) ctx
    (let ((pending (peer-pending-compact-block peer)))
      (when pending
        (when (equalp (pending-compact-block-block-hash pending) block-hash)
          ;; Core (:4668-4673): BlockRequested finds the block in flight from
          ;; this peer with a partial block already attached.
          (bl:log-cat "net" "Peer sent us compact block we were already syncing!")
          (return-from %compact-block-take-slot nil))
        ;; One reconstruction per peer: an announcement of a DIFFERENT block
        ;; replaces the one this peer had pending.
        (clear-pending-compact-block peer)))
    ;; Core BlockRequested (:4668), before the message is even decoded.
    (mark-block-in-flight block-hash peer)
    (multiple-value-bind (block missing-indexes partial-transactions)
        (reconstruct-compact-block compact-block mempool use-wtxid)
      (cond
        ;; READ_STATUS_INVALID (:4679-4683): the one compact-block shape an
        ;; honest peer cannot produce.
        ((eq missing-indexes :malformed)
         (remove-block-request block-hash peer)
         (increment-compact-block-failure)
         (record-misbehavior peer "invalid compact block"))
        ;; READ_STATUS_FAILED (:4683-4694): a short-ID collision in OUR
        ;; mempool, nobody's fault. The peer first in line is asked for the
        ;; whole block and keeps its slot; any other gives its slot back and
        ;; waits for the first download.
        ((eq missing-indexes :collision)
         (if first-in-flight
             (request-full-block peer block-hash)
             (remove-block-request block-hash peer)))
        ;; Nothing missing (:4697-4703, :4748-4752): Core hands it to
        ;; ProcessCompactBlockTxns, which gives this peer's slot back
        ;; (:3508) before processing the block.
        (block
         (remove-block-request block-hash peer)
         (%process-compact-block peer block block-hash ctx
                                 "reconstructed compact block invalid"))
        ((or first-in-flight
             (and (peer-compact-block-high-bandwidth-to peer)
                  (or (not (peer-inbound peer))
                      (block-requested-from-outbound-p block-hash)
                      (< already-in-flight
                         (1- +max-cmpctblocks-inflight-per-block+)))))
         (bl:log-debug "Compact block missing ~D transactions, requesting"
                       (length missing-indexes))
         (setf (peer-pending-compact-block peer)
               (make-pending-compact-block
                :block-hash block-hash
                :header header
                :transactions partial-transactions
                :missing-indexes missing-indexes
                :request-time (get-internal-real-time)
                :use-wtxid use-wtxid))
         (send-message peer
                       (bl.ser:make-getblocktxn-message
                        block-hash missing-indexes)))
        ;; `Give up for this peer and wait for other peer(s)' (:4717-4722).
        (t
         (remove-block-request block-hash peer))))))

(define-p2p-handler ("blocktxn" :needs-mempool t) (peer payload ctx)
  "Handle a blocktxn message. Complete pending block reconstruction.

Same per-reason punishment rule as HANDLE-CMPCTBLOCK: the completed block is a
compact-block delivery (mapBlockSource ... /*punish=*/false,
net_processing.cpp:3516, inverted at :2211), so its verdict goes through
COMPACT-BLOCK-FAILURE-ACTION — the BLOCK_CONSENSUS / BLOCK_MUTATED class earns
a full-block refetch and no discouragement, while the header-invalid class
would still punish (it cannot normally arrive here: HANDLE-CMPCTBLOCK gated the
same header before sending the getblocktxn). A blocktxn that does not answer
the getblocktxn we sent — Core's READ_STATUS_INVALID from FillBlock — is
punished outright (:3487-3491).

Core looks the block up in PEER's in-flight requests (:3451-3469): an answer
for a block we are not completing with this peer -- none asked, another block,
or one another peer already delivered, which settled this peer's request with
it -- is logged and ignored."
  (let ((response (bl.ser:parse-blocktxn-payload payload))
        (pending (peer-pending-compact-block peer)))
    (unless (and pending
                 (equalp (bl.ser:block-txn-response-block-hash response)
                         (pending-compact-block-block-hash pending)))
      (bl:log-cat "net" "Peer ~D sent us block transactions for block we weren't expecting"
                  (peer-id peer))
      (return-from handle-blocktxn nil))

    (let* ((block-hash (bl.ser:block-txn-response-block-hash response))
           (txs (bl.ser:block-txn-response-transactions response))
           (header (pending-compact-block-header pending))
           (transactions (pending-compact-block-transactions pending))
           (missing-indexes (pending-compact-block-missing-indexes pending))
           (requests (block-in-flight-requests block-hash))
           (first-in-flight (or (null requests) (eq (car (first requests)) peer))))
      ;; FillBlock already ran for this reconstruction and failed; Core wipes
      ;; the header then (`Make sure we can't call FillBlock again',
      ;; blockencodings.cpp:210-212), so a second blocktxn for it is refused
      ;; and punished (net_processing.cpp:3474-3481).
      (unless header
        (remove-block-request block-hash peer)
        (record-misbehavior peer "previous compact block reconstruction attempt failed")
        (bl:log-cat "net" "Peer ~D sent compact block transactions multiple times"
                    (peer-id peer))
        (return-from handle-blocktxn nil))
      ;; A blocktxn that does not deliver exactly the transactions we asked
      ;; for is structurally malformed: Core's FillBlock returns
      ;; READ_STATUS_INVALID for both too few and too many
      ;; (blockencodings.cpp:198-217) and the peer is punished
      ;; (net_processing.cpp:3487-3491).
      (when (/= (length txs) (length missing-indexes))
        (bl:log-warn "blocktxn transaction count mismatch")
        (clear-pending-compact-block peer)
        (increment-compact-block-failure)
        (record-misbehavior peer
                            "invalid compact block/non-matching block transactions")
        (return-from handle-blocktxn nil))

      (loop for tx in txs
            for idx in missing-indexes
            do (setf (aref transactions idx) tx))
      (setf (pending-compact-block-header pending) nil)

      (let ((block (bl.ser:make-bitcoin-block
                    :header header
                    :transactions (coerce transactions 'list))))
        (cond
          ;; READ_STATUS_FAILED (blockencodings.cpp:218-222 -> net_processing.
          ;; cpp:3492-3504): the filled block is mutated, most likely a short-ID
          ;; collision. The peer first in line is asked for the whole block and
          ;; keeps its spent reconstruction, so a repeat blocktxn is caught
          ;; above; any other peer gives its slot back.
          ((%compact-block-mutated-p block (bl.ctx:node-context-chain-state ctx))
           (if first-in-flight
               (request-full-block peer block-hash)
               (progn
                 (remove-block-request block-hash peer)
                 (bl:log-cat "net" "Peer ~D sent us a compact block but it failed to reconstruct, waiting on first download to complete"
                             (peer-id peer)))))
          (t
           ;; `Block is okay for further processing' (:3506-3508): this
           ;; peer's request is settled, and processing the block settles the
           ;; rest.
           (clear-pending-compact-block peer)
           (%process-compact-block peer block block-hash ctx
                                   "completed compact block invalid")))))))

(defun %compact-block-mutated-p (block chain-state)
  "Core FillBlock's early mutation check (blockencodings.cpp:218-222):
IsBlockMutated on the filled BLOCK -- a merkle root, or with segwit active
after its parent a witness commitment, that the transactions do not produce."
  (let ((prev (bl.store:get-block-index-entry
               chain-state
               (bl.ser:block-header-prev-block (bl.ser:bitcoin-block-header block)))))
    (and prev
         (bl.val:block-mutated-p
          block (bl.val:segwit-active-at-height-p
                 (1+ (bl.store:block-index-entry-height prev))))
         t)))

(defun request-full-block (peer block-hash)
  "Request a full block (fallback from compact block)."
  (increment-compact-block-failure)
  (%getdata-witness-block peer block-hash))

;;; Timeout handling

(defun check-compact-block-timeout (peer)
  "Check if pending compact block reconstruction has timed out.
   If so, clear state and request full block."
  (let ((pending (peer-pending-compact-block peer)))
    (when pending
      (let* ((now (get-internal-real-time))
             (elapsed-secs (/ (- now (pending-compact-block-request-time pending))
                              internal-time-units-per-second)))
        (when (> elapsed-secs +compact-block-timeout-seconds+)
          (bl:log-warn "Compact block reconstruction timed out")
          (let ((block-hash (pending-compact-block-block-hash pending)))
            (clear-pending-compact-block peer)
            (request-full-block peer block-hash)))))))

(defun clear-pending-compact-block (peer)
  "Give up on PEER's pending compact-block reconstruction: drop the pending
slot AND the in-flight entry the getblocktxn made for it.

Core pairs BlockRequested with RemoveBlockRequest on every path that
abandons a compact-block round trip -- an invalid message
(net_processing.cpp:4681), a short-id collision it will not chase (:4692),
a slot it declines (:4721) -- and the delivered block clears the entry
through the normal receive path. A port that marks the block in flight and
forgets one of those paths leaves a peer permanently holding a block
nothing will ask anyone else for, so every clear site goes through here."
  (let ((pending (peer-pending-compact-block peer)))
    (when pending
      (remove-block-request (pending-compact-block-block-hash pending) peer)))
  (setf (peer-pending-compact-block peer) nil))

;;; Compact block metrics

(defun compact-block-stats ()
  "Return compact block reconstruction statistics (thread-safe read)."
  (bt:with-lock-held (*compact-block-metrics-lock*)
    (list :successes *compact-block-success-count*
          :failures *compact-block-failure-count*
          :collisions *compact-block-collision-count*)))
