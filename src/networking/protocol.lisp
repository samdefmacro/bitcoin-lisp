(in-package #:bitcoin-lisp.networking)

;;; Bitcoin P2P Protocol Handling
;;;
;;; Higher-level protocol operations for syncing and message handling.

(defmacro with-node-lock (&body body)
  "Execute BODY while holding the node lock for thread-safe state access.
Guards shared state (chain-state, UTXO set, mempool, peer list) against
concurrent access from RPC and sync threads."
  `(let ((node bitcoin-lisp::*node*))
     (if (and node (bitcoin-lisp::node-lock node))
         (bt:with-recursive-lock-held ((bitcoin-lisp::node-lock node))
           ,@body)
         (progn ,@body))))

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
          (let ((resolved (resolve-dns-seed seed)))
            (when resolved
              (setf addresses (nconc addresses resolved)))))
        (diversify-by-netgroup
         (remove-duplicates addresses :test #'string=)))))

;;; Message handling

(defun handle-message (peer command payload chain-state utxo-set block-store
                       &key mempool peers fee-estimator address-book recent-rejects)
  "Handle an incoming message from a peer.
MEMPOOL and PEERS are optional; when provided, transaction relay is enabled.
FEE-ESTIMATOR is optional; when provided, fee stats are recorded for blocks.
ADDRESS-BOOK is optional; when provided, addr messages update the peer database.
RECENT-REJECTS is optional; when provided, recently rejected txs are cached.
Returns T if message was handled, NIL otherwise."
  ;; Check per-peer rate limit before processing
  (unless (check-peer-rate-limit peer command)
    (bitcoin-lisp:log-warn "Rate limit exceeded for peer ~A on ~A messages"
                           (peer-address peer) command)
    (disconnect-peer peer)
    (return-from handle-message nil))
  (cond
    ((string= command "ping")
     (let ((nonce (flexi-streams:with-input-from-sequence (s payload)
                    (bitcoin-lisp.serialization:read-uint64-le s))))
       (handle-ping peer nonce))
     t)

    ((string= command "pong")
     (let ((nonce (flexi-streams:with-input-from-sequence (s payload)
                    (bitcoin-lisp.serialization:read-uint64-le s))))
       (handle-pong peer nonce))
     t)

    ((string= command "inv")
     (handle-inv peer payload chain-state mempool
                 :recent-rejects recent-rejects
                 :peers peers
                 :utxo-set utxo-set)
     t)

    ((string= command "headers")
     (handle-headers peer payload chain-state)
     t)

    ((string= command "block")
     (handle-block peer payload chain-state utxo-set block-store mempool fee-estimator
                   :recent-rejects recent-rejects :peers peers)
     t)

    ((string= command "tx")
     (when mempool
       (handle-tx peer payload utxo-set mempool chain-state peers
                  :recent-rejects recent-rejects))
     t)

    ((string= command "getdata")
     (handle-getdata peer payload chain-state mempool block-store)
     t)

    ((string= command "getheaders")
     (handle-getheaders peer payload chain-state)
     t)

    ((string= command "getblocks")
     (handle-getblocks peer payload chain-state)
     t)

    ((string= command "getaddr")
     (handle-getaddr peer address-book)
     t)

    ((string= command "mempool")
     ;; BIP35. Core only honors this when it advertises NODE_BLOOM or the
     ;; peer has explicit mempool permission — otherwise it disconnects
     ;; ("mempool request with bloom filters disabled",
     ;; net_processing.cpp:4940-4951). We never advertise NODE_BLOOM, so
     ;; the disconnect path is the whole behavior.
     (bitcoin-lisp:log-cat "net" "mempool request with bloom filters disabled — disconnecting peer ~A"
                           (peer-address peer))
     (disconnect-peer peer)
     t)

    ((string= command "notfound")
     (handle-notfound peer payload)
     t)

    ((string= command "addr")
     (handle-addr peer payload address-book peers)
     t)

    ((string= command "addrv2")
     (handle-addrv2 peer payload address-book peers)
     t)

    ((string= command "getcfilters")
     (handle-getcfilters peer payload chain-state)
     t)

    ((string= command "getcfheaders")
     (handle-getcfheaders peer payload chain-state)
     t)

    ((string= command "getcfcheckpt")
     (handle-getcfcheckpt peer payload chain-state)
     t)

    ((string= command "sendaddrv2")
     ;; No-op post-handshake (only meaningful during handshake)
     t)

    ((string= command "wtxidrelay")
     ;; BIP 339: No-op post-handshake (only meaningful during handshake)
     t)

    ((string= command "sendtxrcncl")
     ;; BIP 330: feature negotiation is only valid between VERSION and VERACK
     ;; (handled in %await-verack). Receiving it here — post-verack — is a
     ;; protocol violation: Core disconnects (net_processing.cpp:3969-3973),
     ;; unlike the sendaddrv2/wtxidrelay no-op stubs above. With
     ;; -txreconciliation off, Core ignores the message instead (:3964-3967).
     (when bitcoin-lisp:*tx-reconciliation*
       (bitcoin-lisp:log-cat "net" "sendtxrcncl received after verack — disconnecting peer ~A"
                             (peer-address peer))
       (disconnect-peer peer))
     t)

    ((string= command "sendheaders")
     ;; BIP 130: Peer prefers header announcements over inv
     (setf (peer-prefers-headers peer) t)
     t)

    ((string= command "feefilter")
     ;; BIP 133: Peer's minimum fee rate for tx relay
     (let ((rate (bitcoin-lisp.serialization:parse-feefilter-payload payload)))
       (setf (peer-feefilter-rate peer) rate))
     t)

    ;; Compact block messages (BIP 152)
    ((string= command "sendcmpct")
     (handle-sendcmpct peer payload)
     t)

    ((string= command "cmpctblock")
     (when mempool
       (handle-cmpctblock peer payload chain-state utxo-set block-store mempool
                          fee-estimator :recent-rejects recent-rejects))
     t)

    ((string= command "blocktxn")
     (when mempool
       (handle-blocktxn peer payload chain-state utxo-set block-store mempool
                        fee-estimator :recent-rejects recent-rejects))
     t)

    ((string= command "getblocktxn")
     (handle-getblocktxn peer payload block-store chain-state)
     t)

    (t nil)))  ; Unknown message

;;; Inventory handling

(defun block-inv-type-p (inv-type)
  "T if INV-TYPE is a block inventory type (plain or witness, BIP 144)."
  (or (= inv-type bitcoin-lisp.serialization:+inv-type-block+)
      (= inv-type bitcoin-lisp.serialization:+inv-type-witness-block+)))

;;; --- Tx-request tracking (Core TxRequestTracker, simplified) ---
;;;
;;; handle-inv used to fire a getdata to the announcing peer with no in-flight
;;; bookkeeping: the same tx could be requested from every peer that announced
;;; it at once, and if the one peer we asked never delivered, the tx was lost
;;; until re-announced. We keep at most one outstanding request per txid, record
;;; the other announcers as failover candidates, and re-route to one of them if
;;; the request times out, the peer answers notfound, or it disconnects.
;;;
;;; Wave 9 adds Core's txrequest protections (src/txrequest.cpp constants and
;;; their use in src/node/txdownloadman_impl.cpp:196-282 at d3056bc):
;;;   - MAX_PEER_TX_ANNOUNCEMENTS (5000): announcements beyond a peer's cap
;;;     are dropped outright.
;;;   - Request-time delays: NONPREF_PEER_TX_DELAY (2s) for non-preferred
;;;     (inbound) peers, TXID_RELAY_DELAY (2s) for txid-based announcements
;;;     while wtxid-relay peers are connected, OVERLOADED_PEER_TX_DELAY (2s)
;;;     for peers with >= MAX_PEER_TX_REQUEST_IN_FLIGHT (100) requests
;;;     outstanding. A delayed announcement becomes a candidate; the
;;;     scheduler (process-tx-requests, run ~1x/second from the sync loop)
;;;     requests it once due, preferring preferred (outbound) candidates.
;;;   - GETDATA_TX_INTERVAL (60s) expiry with failover, and DisconnectedPeer
;;;     cleanup: a disconnecting peer's announcements are forgotten and its
;;;     in-flight requests become immediately re-schedulable.
;;;
;;; Simplified vs Core's full 3-state priority machinery (txrequest.cpp):
;;; no per-(peer,txhash) priority hashing — candidate selection is preferred-
;;; first then earliest-ready; expiry failover selects among currently-ready
;;; candidates instead of promoting the exact next-by-priority announcement;
;;; and the scheduler runs on a ~1s cadence rather than per SendMessages pass.

(defvar *tx-in-flight* (make-hash-table :test 'equalp)
  "txid -> (peer . request-internal-real-time); at most one per txid.")
(defvar *tx-announcers* (make-hash-table :test 'equalp)
  "hash -> list of (peer . ready-internal-real-time) announcements — failover
candidates, each requestable once its ready time (announcement time + Core's
NONPREF/TXID/OVERLOADED delays) passes. The peer currently in flight stays in
this list; its cons is the record that it announced the hash.")
(defvar *tx-request-wtxid-p* (make-hash-table :test 'equalp)
  "hash -> T when the tracked announcement is wtxid-based (BIP339 MSG_WTX).
Core's TxRequestTracker stores GenTxids, so every entry remembers whether it
is a txid or a wtxid (txrequest.cpp Announcement::m_gtxid) — the getdata for
a wtxid entry MUST go out as MSG_WTX and for a txid entry as
MSG_TX|witness-flag (net_processing.cpp:6207). A wtxid re-requested under
MSG_WITNESS_TX is interpreted by Core peers as a TXID lookup and answered
notfound, so failover would silently never work for segwit txs.")
(defvar *tx-peer-announcements* (make-hash-table :test 'eq)
  "peer -> number of tracked announcements (candidates + in-flight), for the
MAX_PEER_TX_ANNOUNCEMENTS cap (Core m_txrequest.Count(peer)).")
(defvar *tx-peer-in-flight* (make-hash-table :test 'eq)
  "peer -> number of in-flight getdata requests, for the overloaded-peer
delay (Core m_txrequest.CountInFlight(peer)).")
(defvar *tx-request-lock* (bt:make-lock "tx-request"))

(defparameter +tx-request-timeout-seconds+ 60
  "Expire an outstanding tx getdata after this long with no delivery and fail
over to another announcer (Core GETDATA_TX_INTERVAL, txdownloadman.h:38).")
(defconstant +max-peer-tx-announcements+ 5000
  "Per-peer cap on tracked tx announcements; beyond it new announcements from
the peer are dropped (Core MAX_PEER_TX_ANNOUNCEMENTS, txdownloadman.h:30).")
(defconstant +max-peer-tx-request-in-flight+ 100
  "In-flight request count above which a peer's further announcements get the
overloaded delay (Core MAX_PEER_TX_REQUEST_IN_FLIGHT, txdownloadman.h:25).")
(defconstant +nonpref-peer-tx-delay-seconds+ 2
  "Request delay for announcements from non-preferred (inbound) peers (Core
NONPREF_PEER_TX_DELAY, txdownloadman.h:34).")
(defconstant +txid-relay-delay-seconds+ 2
  "Extra delay for txid-based announcements while wtxid-relay peers are
connected — preferring the malleation-proof id (Core TXID_RELAY_DELAY,
txdownloadman.h:32).")
(defconstant +overloaded-peer-tx-delay-seconds+ 2
  "Extra delay for announcements from overloaded peers (Core
OVERLOADED_PEER_TX_DELAY, txdownloadman.h:36).")

(defun reset-tx-requests ()
  "Clear all tx-request tracking (called at node start)."
  (bt:with-lock-held (*tx-request-lock*)
    (clrhash *tx-in-flight*)
    (clrhash *tx-announcers*)
    (clrhash *tx-request-wtxid-p*)
    (clrhash *tx-peer-announcements*)
    (clrhash *tx-peer-in-flight*)))

(defun tx-request-preferred-p (peer)
  "Preferred announcers are requested first and without the non-preferred
delay: outbound connections (Core's fPreferredDownload — outbound or NoBan
permission; we have no permission flags)."
  (not (peer-inbound peer)))

(defun %tx-announcement-delay-ticks (peer wtxidp num-wtxid-peers)
  "The announcement's request delay in internal-time ticks — the sum Core
computes in AddTxAnnouncement (txdownloadman_impl.cpp:210-219)."
  (* internal-time-units-per-second
     (+ (if (tx-request-preferred-p peer) 0 +nonpref-peer-tx-delay-seconds+)
        (if (and (not wtxidp) (plusp num-wtxid-peers))
            +txid-relay-delay-seconds+ 0)
        (if (>= (gethash peer *tx-peer-in-flight* 0)
                +max-peer-tx-request-in-flight+)
            +overloaded-peer-tx-delay-seconds+ 0))))

(defun %tx-request-mark-in-flight (hash peer now)
  "Lock held: record an outstanding getdata for HASH to PEER."
  (setf (gethash hash *tx-in-flight*) (cons peer now))
  (incf (gethash peer *tx-peer-in-flight* 0)))

(defun %tx-request-clear-in-flight (hash)
  "Lock held: drop HASH's outstanding request, fixing the peer's count."
  (let ((entry (gethash hash *tx-in-flight*)))
    (when entry
      (let ((n (1- (gethash (car entry) *tx-peer-in-flight* 1))))
        (if (plusp n)
            (setf (gethash (car entry) *tx-peer-in-flight*) n)
            (remhash (car entry) *tx-peer-in-flight*)))
      (remhash hash *tx-in-flight*))))

(defun %tx-request-drop-announcer (hash peer)
  "Lock held: remove PEER's announcement of HASH (if any), fixing its count.
Removes the whole entry when no announcers remain."
  (let* ((anns (gethash hash *tx-announcers*))
         (ann (assoc peer anns :test #'eq)))
    (when ann
      (let ((rest (remove ann anns)))
        (if rest
            (setf (gethash hash *tx-announcers*) rest)
            (progn (remhash hash *tx-announcers*)
                   (remhash hash *tx-request-wtxid-p*))))
      (let ((n (1- (gethash peer *tx-peer-announcements* 1))))
        (if (plusp n)
            (setf (gethash peer *tx-peer-announcements*) n)
            (remhash peer *tx-peer-announcements*))))))

(defun tx-request-count (peer)
  "Number of announcements tracked for PEER (Core m_txrequest.Count)."
  (bt:with-lock-held (*tx-request-lock*)
    (gethash peer *tx-peer-announcements* 0)))

(defun tx-request-wanted-p (hash peer &optional wtxidp (num-wtxid-peers 0))
  "Record PEER as an announcer of HASH and return T iff a getdata should go to
PEER immediately — no request outstanding and the announcement carries no
delay. NIL means the announcement was either dropped (per-peer cap), retained
as a failover candidate behind an in-flight request, or deferred until its
Core-mandated delay passes (the scheduler sends it then). WTXIDP marks the
announcement as wtxid-based (MSG_WTX): the id type is a property of the
announced hash itself and is remembered for the lifetime of the entry, so a
timed-out request fails over with the SAME id type. NUM-WTXID-PEERS is the
count of connected wtxid-relay peers, driving Core's TXID_RELAY_DELAY."
  (bt:with-lock-held (*tx-request-lock*)
    (let ((anns (gethash hash *tx-announcers*)))
      ;; Duplicate announcement from the same peer: nothing new to record.
      (when (assoc peer anns :test #'eq)
        (return-from tx-request-wanted-p nil))
      ;; MAX_PEER_TX_ANNOUNCEMENTS: drop, don't record
      ;; (txdownloadman_impl.cpp:204-207).
      (when (>= (gethash peer *tx-peer-announcements* 0)
                +max-peer-tx-announcements+)
        (return-from tx-request-wanted-p nil))
      (let* ((now (get-internal-real-time))
             (ready (+ now (%tx-announcement-delay-ticks peer wtxidp
                                                         num-wtxid-peers))))
        (push (cons peer ready) (gethash hash *tx-announcers*))
        (incf (gethash peer *tx-peer-announcements* 0))
        (setf (gethash hash *tx-request-wtxid-p*) wtxidp)
        (cond ((gethash hash *tx-in-flight*) nil)
              ((> ready now) nil)        ; deferred; scheduler sends when due
              (t (%tx-request-mark-in-flight hash peer now)
                 t))))))

(defun tx-request-received (hash)
  "Clear tracking for HASH once the tx arrives (or is otherwise resolved) —
Core ForgetTxHash: every peer's announcement of it is released."
  (bt:with-lock-held (*tx-request-lock*)
    (%tx-request-clear-in-flight hash)
    (dolist (ann (gethash hash *tx-announcers*))
      (let ((n (1- (gethash (car ann) *tx-peer-announcements* 1))))
        (if (plusp n)
            (setf (gethash (car ann) *tx-peer-announcements*) n)
            (remhash (car ann) *tx-peer-announcements*))))
    (remhash hash *tx-announcers*)
    (remhash hash *tx-request-wtxid-p*)))

(defun tx-request-notfound (peer hash)
  "PEER answered notfound for HASH: mark its announcement completed (Core
ReceivedNotFound -> m_txrequest.ReceivedResponse) so the request fails over
to another announcer on the next scheduler pass instead of burning the full
timeout."
  (bt:with-lock-held (*tx-request-lock*)
    (let ((entry (gethash hash *tx-in-flight*)))
      (when (and entry (eq (car entry) peer))
        (%tx-request-clear-in-flight hash)))
    (%tx-request-drop-announcer hash peer)))

(defun tx-request-disconnected-peer (peer)
  "Forget every announcement PEER made and release its in-flight requests so
other announcers take over (Core TxRequestTracker::DisconnectedPeer via
TxDownloadManagerImpl::DisconnectedPeer). Failover getdatas go out on the
next scheduler pass — deliberately not from here, which may run on a non-sync
thread. Registered as *peer-disconnect-hook*."
  (bt:with-lock-held (*tx-request-lock*)
    ;; Release in-flight requests held by this peer.
    (let ((held '()))
      (maphash (lambda (hash entry)
                 (when (eq (car entry) peer) (push hash held)))
               *tx-in-flight*)
      (dolist (hash held) (%tx-request-clear-in-flight hash)))
    ;; Forget its announcements.
    (let ((announced '()))
      (maphash (lambda (hash anns)
                 (when (assoc peer anns :test #'eq) (push hash announced)))
               *tx-announcers*)
      (dolist (hash announced) (%tx-request-drop-announcer hash peer)))
    (remhash peer *tx-peer-announcements*)
    (remhash peer *tx-peer-in-flight*)))

;;; Registered here rather than called directly from peer.lisp (which loads
;;; first): the tracker must observe every disconnect path.
(setf *peer-disconnect-hook* #'tx-request-disconnected-peer)

(defun %tx-request-best-candidate (anns now &optional exclude)
  "The best requestable announcement in ANNS at NOW: ready (delay passed),
peer :ready, not EXCLUDE — preferred (outbound) peers first, then earliest
ready time (Core GetRequestable's CANDIDATE_BEST selection, simplified)."
  (let ((best nil))
    (dolist (ann anns best)
      (destructuring-bind (peer . ready) ann
        (when (and (not (eq peer exclude))
                   (<= ready now)
                   (eq (peer-state peer) :ready))
          (when (or (null best)
                    (let ((bp (tx-request-preferred-p (car best)))
                          (ap (tx-request-preferred-p peer)))
                      (or (and ap (not bp))
                          (and (eq ap bp) (< ready (cdr best))))))
            (setf best ann)))))))

(defun process-tx-requests ()
  "Send getdatas for announcements whose delay has passed and that have no
request outstanding — the scheduler half of Core's GetRequestsToSend
(txdownloadman_impl.cpp:264-284), run ~1x/second from the sync loop. Each
hash goes to its best ready candidate (preferred first). Returns the number
of requests sent."
  (let ((now (get-internal-real-time))
        (to-send '()))                  ; (peer . list-of-invs)
    (bt:with-lock-held (*tx-request-lock*)
      (maphash
       (lambda (hash anns)
         (unless (gethash hash *tx-in-flight*)
           (let ((best (%tx-request-best-candidate anns now)))
             (when best
               (let ((peer (car best))
                     (wtxidp (gethash hash *tx-request-wtxid-p*)))
                 (%tx-request-mark-in-flight hash peer now)
                 (let ((bucket (assoc peer to-send :test #'eq)))
                   (if bucket
                       (push (tx-request-inv hash wtxidp peer) (cdr bucket))
                       (push (list peer (tx-request-inv hash wtxidp peer))
                             to-send))))))))
       *tx-announcers*))
    ;; Send outside the lock, one getdata per peer.
    (let ((sent 0))
      (loop for (peer . invs) in to-send
            do (incf sent (length invs))
               (handler-case
                   (send-message peer
                                 (bitcoin-lisp.serialization:make-getdata-message
                                  invs))
                 (error () nil)))
      sent)))

(defun tx-fetch-inv-type (peer)
  "Inv type for a TXID-based tx getdata to PEER: MSG_TX|MSG_WITNESS_FLAG when
the peer can serve witnesses, bare MSG_TX otherwise — Core's GetFetchFlags
(net_processing.cpp:2591-2598, CanServeWitnesses = NODE_WITNESS in the peer's
services). Requesting a segwit tx with bare MSG_TX returns the
witness-stripped serialization, which can never pass script validation.
wtxid-based requests never use this: they are always MSG_WTX."
  (if (logtest (peer-services peer) bitcoin-lisp.serialization:+node-witness+)
      bitcoin-lisp.serialization:+inv-type-witness-tx+
      bitcoin-lisp.serialization:+inv-type-tx+))

(defun tx-request-inv (hash wtxidp peer)
  "The inv-vector for requesting tracked tx HASH from PEER: MSG_WTX for a
wtxid-based entry, MSG_TX|witness-flag for a txid-based one — Core's
\"gtxid.IsWtxid() ? MSG_WTX : (MSG_TX | GetFetchFlags(peer))\"
(net_processing.cpp:6207)."
  (bitcoin-lisp.serialization:make-inv-vector
   :type (if wtxidp
             bitcoin-lisp.serialization:+inv-type-wtx+
             (tx-fetch-inv-type peer))
   :hash hash))

(defun retry-timed-out-tx-requests ()
  "Re-route each in-flight tx getdata outstanding longer than
GETDATA_TX_INTERVAL to the next ready announcer (the timed-out peer's
announcement is dropped — Core's expiry marks it COMPLETED); drop tracking
for a tx with no other ready announcer. Returns the number re-requested."
  (let ((now (get-internal-real-time))
        (timeout-ticks (* +tx-request-timeout-seconds+ internal-time-units-per-second))
        (reroutes '()))
    (bt:with-lock-held (*tx-request-lock*)
      (let ((timed-out '()))
        (maphash (lambda (txid entry)
                   (when (> (- now (cdr entry)) timeout-ticks)
                     (push (cons txid entry) timed-out)))
                 *tx-in-flight*)
        (dolist (item timed-out)
          (let* ((txid (car item))
                 (old-peer (cadr item)))
            (%tx-request-clear-in-flight txid)
            ;; The expired announcement is completed (Core txrequest expiry).
            (%tx-request-drop-announcer txid old-peer)
            (let ((next (%tx-request-best-candidate
                         (gethash txid *tx-announcers*) now old-peer)))
              (if next
                  (progn (%tx-request-mark-in-flight txid (car next) now)
                         (push (list txid (car next)
                                     (gethash txid *tx-request-wtxid-p*))
                               reroutes))
                  ;; No READY candidate right now. Entries with only delayed
                  ;; candidates stay for the scheduler; entries with no
                  ;; announcers at all were already dropped above.
                  (let ((anns (gethash txid *tx-announcers*)))
                    (unless (find-if (lambda (ann)
                                       (eq (peer-state (car ann)) :ready))
                                     anns)
                      (dolist (ann anns)
                        (%tx-request-drop-announcer txid (car ann)))))))))))
    ;; Send getdata outside the lock. The re-request must carry the id type the
    ;; entry was announced under: a wtxid entry as MSG_WTX, a txid entry as
    ;; MSG_TX|witness-flag. Previously every failover went out as
    ;; MSG_WITNESS_TX regardless — Core interprets MSG_WITNESS_TX getdata as a
    ;; TXID lookup, so a wtxid hash got a notfound and failover never worked
    ;; for segwit txs (first-announcer-wins censorship primitive).
    (dolist (entry reroutes)
      (destructuring-bind (txid next wtxidp) entry
        (handler-case
            (send-message next
                          (bitcoin-lisp.serialization:make-getdata-message
                           (list (tx-request-inv txid wtxidp next))))
          (error () nil))))
    (length reroutes)))

;;; Initial-block-download status (Core ChainstateManager::IsInitialBlockDownload)

(defconstant +max-tip-age-seconds+ (* 24 60 60)
  "Consider the node still in IBD while the active tip is older than
this. Core DEFAULT_MAX_TIP_AGE (kernel/chainstatemanager_opts.h:24).")

(defvar *cached-is-ibd* t
  "Latched IBD status: starts true; initial-block-download-p latches it
to false once the tip has enough work and is recent, and it never flips
back for the life of the node (Core m_cached_is_ibd, validation.h:1049,
latched by UpdateIBDStatus, validation.cpp:3314-3322). Re-set to T by
reset-ibd-stop at node start.")

(defun initial-block-download-p (chain-state)
  "Return T while the node is in initial block download.
Latches to (and then always returns) NIL once the active tip exists,
has at least the network's minimum chain work, and its timestamp is
within +max-tip-age-seconds+ of now — Core UpdateIBDStatus
(validation.cpp:3314-3322) + CChain::IsTipRecent (chain.h:431-437)."
  (unless *cached-is-ibd*
    (return-from initial-block-download-p nil))
  (let* ((tip-hash (bitcoin-lisp.storage:best-block-hash chain-state))
         (tip (and tip-hash
                   (bitcoin-lisp.storage:get-block-index-entry chain-state tip-hash))))
    (if (and tip
             (>= (bitcoin-lisp.storage:block-index-entry-chain-work tip)
                 (bitcoin-lisp:minimum-chain-work bitcoin-lisp:*network*))
             (>= (bitcoin-lisp.serialization:block-header-timestamp
                  (bitcoin-lisp.storage:block-index-entry-header tip))
                 (- (bitcoin-lisp.serialization:get-unix-time)
                    +max-tip-age-seconds+)))
        (progn
          (bitcoin-lisp:log-info "Leaving InitialBlockDownload (latching to false)")
          (setf *cached-is-ibd* nil)
          ;; With an assumeutxo background chainstate in use, leaving IBD
          ;; shifts the coins-cache allocation to the historical chainstate
          ;; (Core ActivateBestChain's exited_ibd -> MaybeRebalanceCaches,
          ;; validation.cpp:3479-3486).
          (bitcoin-lisp:rebalance-caches-on-ibd-exit)
          nil)
        t)))

(defun count-wtxid-relay-peers (peers)
  "Number of connected peers that negotiated BIP339 wtxid relay (Core
m_num_wtxid_peers, txdownloadman_impl.cpp ConnectedPeer/DisconnectedPeer).
Drives the TXID_RELAY_DELAY on txid-based announcements."
  (count-if (lambda (p) (and (eq (peer-state p) :ready)
                             (peer-wtxid-relay p)))
            peers))

(defun %already-have-tx-p (hash wtxidp mempool recent-rejects
                           &optional include-reconsiderable)
  "Core AlreadyHaveTx (txdownloadman_impl.cpp:126-148): the orphanage (HASH
cast to a wtxid — never a real txid lookup, witness malleation makes txid
matches unreliable; for non-segwit txs txid == wtxid so the cast still finds
them), the recent-confirmed filter, recent rejects, and the mempool by the id
the announcement implies.

INCLUDE-RECONSIDERABLE is Core's parameter of the same name (declared at
:125, consulted at :142). Core passes TRUE at exactly one site,
AddTxAnnouncement (:199); every other caller passes false (:180, :274, :395,
:527). Set it where the question is \"is there any point requesting this?\" —
a tx that failed reconsiderably must not be re-downloaded to be submitted
alone. Leave it NIL where the question is \"can this still be resolved?\" —
notably when filtering an orphan's missing parents, since a low-feerate
parent is exactly what the orphan may be able to fee-bump (:393-395)."
  (or (bitcoin-lisp.mempool:orphan-have
       (bitcoin-lisp.mempool:mempool-orphan-pool mempool) hash)
      (and include-reconsiderable
           (bitcoin-lisp.validation:reconsiderable-reject-p hash))
      (bitcoin-lisp.validation:recently-confirmed-p hash)
      (bitcoin-lisp:recent-reject-p recent-rejects hash)
      (if wtxidp
          (bitcoin-lisp.mempool:mempool-get-by-wtxid mempool hash)
          (bitcoin-lisp.mempool:mempool-has mempool hash))))

(defun %maybe-add-orphan-resolution-candidate (peer orphan-wtxid mempool utxo-set
                                               recent-rejects num-wtxid-peers)
  "A wtxid announcement matched a stored orphan: treat PEER as an orphan-
resolution candidate instead of requesting the announced tx again (Core
AddTxAnnouncement's orphan branch + MaybeAddOrphanResolutionCandidate,
txdownloadman_impl.cpp:172-282): unless PEER already announced this orphan,
register its still-missing parents with the tx-request tracker as txid-based
announcements from PEER (with the usual delays; the per-parent cap check
lives in request-orphan-parents) and record PEER as an additional announcer."
  (let* ((pool (bitcoin-lisp.mempool:mempool-orphan-pool mempool))
         (otx (bitcoin-lisp.mempool:orphan-tx pool orphan-wtxid)))
    (when (and otx (not (bitcoin-lisp.mempool:orphan-have-from-peer
                         pool orphan-wtxid peer)))
      (let ((parents (remove-if
                      (lambda (ptxid)
                        (%already-have-tx-p ptxid nil mempool recent-rejects))
                      (missing-parent-txids otx utxo-set mempool))))
        ;; All parents accepted/rejected since the orphan was stored: nothing
        ;; to resolve from this peer (the orphan awaits reprocessing).
        (when parents
          (when (request-orphan-parents peer parents num-wtxid-peers)
            (bitcoin-lisp.mempool:orphan-add pool otx peer)))))))

(defun handle-inv (peer payload chain-state &optional mempool
                   &key recent-rejects peers utxo-set)
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
  (let ((inv-vectors (bitcoin-lisp.serialization:parse-inv-payload payload))
        (reject-tx-invs (or (ignore-incoming-txs-p)
                            (not (peer-relays-txs-p peer))))
        (num-wtxid-peers (count-wtxid-relay-peers peers))
        (wanted '())
        (unknown-block-hash nil))
    (dolist (inv inv-vectors)
      (let ((inv-type (bitcoin-lisp.serialization:inv-vector-type inv))
            (hash (bitcoin-lisp.serialization:inv-vector-hash inv)))
        (cond
          ((block-inv-type-p inv-type)
           ;; Per-peer availability: announcing a block hash counts as
           ;; "peer has it" — update best-known-block (or stage
           ;; hash-last-unknown if we don't have the header yet).
           (bitcoin-lisp.networking::update-block-availability peer chain-state hash)
           (unless (bitcoin-lisp.storage:get-block-index-entry chain-state hash)
             (setf unknown-block-hash hash)))
          ;; Transaction announcement. MSG_TX / MSG_WITNESS_TX carry a
          ;; txid; MSG_WTX (BIP339) carries a wtxid. Matching MSG_WTX here
          ;; is essential: peers that negotiated wtxidrelay — every modern
          ;; Core peer — announce txs exclusively under MSG_WTX
          ;; (net_processing.cpp:6009,6065), so without this branch no tx
          ;; announcement from them was ever requested.
          ((or (= inv-type bitcoin-lisp.serialization:+inv-type-tx+)
               (= inv-type bitcoin-lisp.serialization:+inv-type-witness-tx+)
               (= inv-type bitcoin-lisp.serialization:+inv-type-wtx+))
           ;; Tx invs in violation of our advertised fRelay=0 (blocksonly
           ;; mainnet default, block-relay/feeler conns): disconnect (Core
           ;; net_processing.cpp:4168-4172).
           (when reject-tx-invs
             (bitcoin-lisp:log-cat "net" "transaction inv sent in violation of protocol — disconnecting peer ~A"
                                   (peer-address peer))
             (disconnect-peer peer)
             (return-from handle-inv))
           ;; Ignore invs that don't match the wtxidrelay negotiation: a
           ;; wtxidrelay peer never announces MSG_TX, a non-wtxidrelay peer
           ;; never MSG_WTX (Core net_processing.cpp:4145-4152).
           (let ((wtxidp (= inv-type bitcoin-lisp.serialization:+inv-type-wtx+)))
             (unless (if (peer-wtxid-relay peer)
                         (= inv-type bitcoin-lisp.serialization:+inv-type-tx+)
                         wtxidp)
               (when (and mempool
                          ;; Core requests announced txs only outside IBD —
                          ;; their inputs won't resolve against a stale UTXO
                          ;; set anyway (net_processing.cpp:4176-4180 gates
                          ;; AddTxAnnouncement on !IsInitialBlockDownload).
                          (not (initial-block-download-p chain-state)))
                 (cond
                   ;; A wtxid announcement matching a stored orphan makes
                   ;; PEER an orphan-resolution candidate: fetch the missing
                   ;; PARENTS from it, not the orphan again.
                   ((and wtxidp utxo-set
                         (bitcoin-lisp.mempool:orphan-have
                          (bitcoin-lisp.mempool:mempool-orphan-pool mempool)
                          hash))
                    (%maybe-add-orphan-resolution-candidate
                     peer hash mempool utxo-set recent-rejects num-wtxid-peers))
                   ;; include-reconsiderable: a tx whose last failure was
                   ;; reconsiderable must not be requested to be submitted
                   ;; alone again (Core AddTxAnnouncement, :199).
                   ((%already-have-tx-p hash wtxidp mempool recent-rejects t)
                    nil)
                   ;; Records PEER as an announcer AND the id type of the
                   ;; announcement (wtxid vs txid), so a timed-out request
                   ;; fails over with the right inv type; T only if no request
                   ;; is outstanding AND the announcement carries no delay
                   ;; (non-preferred / txid-relay / overloaded) — delayed ones
                   ;; go out via process-tx-requests when due.
                   ((tx-request-wanted-p hash peer wtxidp num-wtxid-peers)
                    ;; Request with the id type the announcement used: wtxids
                    ;; as MSG_WTX, txids as MSG_TX|WITNESS_FLAG — Core's
                    ;; "gtxid.IsWtxid() ? MSG_WTX : (MSG_TX | GetFetchFlags)"
                    ;; (net_processing.cpp:6207).
                    (push (tx-request-inv hash wtxidp peer) wanted))))))))))
    (when unknown-block-hash
      (bitcoin-lisp:log-cat "net" "inv: unknown block ~A from peer ~A — sending getheaders"
                              (bitcoin-lisp.crypto:bytes-to-hex unknown-block-hash)
                              (peer-address peer))
      (request-headers-for-ibd peer chain-state))
    (when wanted
      (send-message peer
                    (bitcoin-lisp.serialization:make-getdata-message
                     (nreverse wanted))))))

;;; Notfound handling

(defun handle-notfound (peer payload)
  "Handle a notfound message: the peer is telling us it lacks one or
more items we requested via getdata. For block items, record the
disclaim so the IBD scheduler stops asking this peer for the block and
releases it from in-flight for immediate retry elsewhere (see
note-block-not-available). Without this we burn the full block-request
timeout on every peer that lacks a stale-fork block before giving up.
For tx items, complete the peer's announcement in the tx-request tracker
so the request fails over to another announcer instead of burning the
60s expiry (Core ReceivedNotFound -> m_txrequest.ReceivedResponse,
txdownloadman_impl.cpp:287-293). Mirrors Bitcoin Core's MSG NOTFOUND
handling (net_processing.cpp)."
  (let ((tx-completed nil))
    (dolist (inv (bitcoin-lisp.serialization:parse-inv-payload payload))
      (let ((inv-type (bitcoin-lisp.serialization:inv-vector-type inv))
            (hash (bitcoin-lisp.serialization:inv-vector-hash inv)))
        (cond
          ((block-inv-type-p inv-type)
           (note-block-not-available peer hash))
          ((or (= inv-type bitcoin-lisp.serialization:+inv-type-tx+)
               (= inv-type bitcoin-lisp.serialization:+inv-type-witness-tx+)
               (= inv-type bitcoin-lisp.serialization:+inv-type-wtx+))
           (tx-request-notfound peer hash)
           (setf tx-completed t)))))
    ;; Fail over promptly: re-run the scheduler so another announcer's
    ;; candidate is requested now rather than on the next 1s tick.
    (when tx-completed
      (process-tx-requests))))

;;; Headers handling

(defun handle-headers (peer payload chain-state)
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
  (let ((headers (bitcoin-lisp.serialization:parse-headers-payload payload)))
    ;; Node lock: process-headers (inside ingest-headers-from-peer) mutates
    ;; the block index, which the RPC threads (submitheader, chain queries)
    ;; also touch under this lock — the same discipline handle-block follows.
    (with-node-lock
      (ingest-headers-from-peer peer headers chain-state))))

;;; Block handling

(defun accept-downloaded-block (block chain-state utxo-set block-store
                                &key mempool fee-estimator recent-rejects)
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
  (let* ((header (bitcoin-lisp.serialization:bitcoin-block-header block))
         (prev-hash (bitcoin-lisp.serialization:block-header-prev-block header))
         (current-best-hash (bitcoin-lisp.storage:best-block-hash chain-state))
         (current-time (bitcoin-lisp.serialization:get-unix-time)))
    (flet ((%connect ()
             (multiple-value-bind (entry reorg-outcome)
                 (bitcoin-lisp.validation:connect-block
                  block chain-state block-store utxo-set
                  :fee-estimator fee-estimator
                  :recent-rejects recent-rejects
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
               ;; testnet4 deep-reorg wedge). A KEYWORD detail means an invalid
               ;; fork block (rolled back) — do not re-download.
               (when (and (consp reorg-outcome)
                          (null (first reorg-outcome))
                          (consp (second reorg-outcome)))
                 (queue-missing-fork-blocks (second reorg-outcome))))))
      ;; Core's two AcceptBlockHeader gates, which this path had neither of --
      ;; it branched only on whether the parent is the tip.
      ;;
      ;; duplicate-invalid (validation.cpp:4231-4235): a block we already hold
      ;; and already marked invalid is refused outright. Without it,
      ;; invalidateblock is undone by one unsolicited block message.
      (let ((known (bitcoin-lisp.storage:get-block-index-entry
                    chain-state (bitcoin-lisp.serialization:block-header-hash header))))
        (when (and known
                   (eq (bitcoin-lisp.storage:block-index-entry-status known) :invalid))
          (return-from accept-downloaded-block (values nil :duplicate-invalid))))
      ;; bad-prevblk (validation.cpp:4252-4255): a block building on an invalid
      ;; parent is refused before any work is done on it. This is what stops a
      ;; poisoned subtree being re-offered block by block to force the whole
      ;; doomed reorg to be attempted again -- roughly 1 MB of message buying
      ;; an unmetered amount of our validation.
      (let ((parent (bitcoin-lisp.storage:get-block-index-entry chain-state prev-hash)))
        (when (and parent
                   (eq (bitcoin-lisp.storage:block-index-entry-status parent) :invalid))
          (return-from accept-downloaded-block (values nil :bad-prevblk))))
      (if (equalp prev-hash current-best-hash)
          ;; Extends the active tip — full validation at tip+1.
          (let ((new-height (1+ (bitcoin-lisp.storage:current-height chain-state))))
            (multiple-value-bind (valid error)
                (bitcoin-lisp.validation:validate-block
                 block chain-state utxo-set new-height current-time)
              (if valid (progn (%connect) (values t nil)) (values nil error))))
          ;; Side branch — context-free validation at the block's own height;
          ;; CONNECT-BLOCK stores it and reorgs (validating fully) when it wins.
          (let ((prev-entry (bitcoin-lisp.storage:get-block-index-entry
                             chain-state prev-hash)))
            (if (null prev-entry)
                ;; Parent header unknown: can't place the block or check its
                ;; PoW/difficulty. Drop it (a healthy IBD has the headers first).
                (values nil :orphan-block)
                (let ((fork-height (1+ (bitcoin-lisp.storage:block-index-entry-height
                                        prev-entry))))
                  (multiple-value-bind (valid error)
                      (bitcoin-lisp.validation:validate-block
                       block chain-state utxo-set fork-height current-time
                       :context-free-only t)
                    (if valid (progn (%connect) (values t nil)) (values nil error))))))))))

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
       (equalp (bitcoin-lisp.storage:best-block-hash chain-state) hash)))

(defun handle-block (peer payload chain-state utxo-set block-store
                     &optional mempool fee-estimator &key recent-rejects peers)
  "Handle a block message. When PEERS is supplied and the block becomes the new
active tip, announce it onward (BIP 130 headers / inv), so the node propagates
blocks instead of being a sink. A peer that delivers a block that CONNECTS
earns consideration for high-bandwidth compact-block announcements — Core
drives that off mapBlockSource (net_processing.cpp:2202, 2218-2223), which is
filled for plain block messages exactly as it is for reconstructed compact
ones, so promotion must not be a compact-block-only privilege."
  (let ((block (bitcoin-lisp.serialization:parse-block-payload payload)))
    (when block
      (let ((connected
              (with-node-lock
                (let* ((header (bitcoin-lisp.serialization:bitcoin-block-header block))
                       (hash (bitcoin-lisp.serialization:block-header-hash header))
                       (tip-before (bitcoin-lisp.storage:best-block-hash chain-state)))
                  (multiple-value-bind (valid error)
                      (accept-downloaded-block block chain-state utxo-set block-store
                                               :mempool mempool
                                               :fee-estimator fee-estimator
                                               :recent-rejects recent-rejects)
                    (cond
                      (valid
                       ;; Announce onward only if this block is now the active
                       ;; tip (accept may have stored a side block or reorged).
                       (when (and peers
                                  (equalp (bitcoin-lisp.storage:best-block-hash chain-state)
                                          hash))
                         (relay-block header peer peers))
                       ;; Promotion needs strictly more than acceptance: the
                       ;; block must have CONNECTED (see %block-newly-connected-p).
                       (%block-newly-connected-p chain-state hash tip-before))
                      (t
                       (bitcoin-lisp:log-warn "Block ~A rejected: ~A"
                                              (bitcoin-lisp.crypto:bytes-to-hex hash) error)
                       (record-misbehavior peer "invalid block")
                       nil)))))))
        ;; Outside the node lock: promotion writes sendcmpct to up to two peers.
        (when connected
          (maybe-promote-block-deliverer peer chain-state))))))

;;; Address handling

(defun %addr-gossip-key (peer-addr)
  "Dedup key for addr gossip: network-typed [net-id, addr-bytes..., port]."
  (make-address-key (peer-address-ip peer-addr) (peer-address-port peer-addr)
                    (peer-address-network peer-addr)))

(defun relay-address (peer-addr source-peer peers
                      &key (now (bitcoin-lisp.serialization:get-unix-time))
                           (max-targets 2))
  "Forward a freshly-learned address to up to MAX-TARGETS deterministically-
chosen peers (Core RelayAddress, net_processing.cpp:2298-2337): eligibility is
ready + tx-relaying (block-relay-only/feeler peers get no addr gossip) + not
the announcing peer + able to carry the address at all (a peer that has not
negotiated addrv2 never receives onion/i2p/cjdns addresses — Core
IsAddrCompatible, net_processing.cpp:1117/2311). Selection ranks peers by
sha256(addr || day || peer-id), so the same address takes the same hops
network-wide for a day. Core relays an address OUTSIDE our reachable set to
only 1 peer instead of 2 (net_processing.cpp:2303) — callers pass
:max-targets 1 for those. Per-peer dedup via the bounded known-addrs set (the
source is marked as knowing it too). Returns the number of peers sent to."
  (let* ((key (%addr-gossip-key peer-addr))
         (network (peer-address-network peer-addr))
         (day (floor now 86400))
         (sent 0))
    (when source-peer
      (bitcoin-lisp:add-recent-reject (peer-known-addrs source-peer) key))
    (let ((ranked
            (sort
             (loop for p in peers
                   when (and (eq (peer-state p) :ready)
                             (not (eq p source-peer))
                             (peer-relays-txs-p p)
                             (or (peer-wants-addrv2 p)
                                 (bitcoin-lisp.serialization:v1-compatible-network-p
                                  network)))
                     collect (cons (let* ((material (concatenate '(vector (unsigned-byte 8))
                                                                 key
                                                                 (int-to-le-bytes day 8)
                                                                 (int-to-le-bytes (peer-id p) 8)))
                                          (h (bitcoin-lisp.crypto:sha256 material)))
                                     (loop for i below 8 sum (ash (aref h i) (* 8 i))))
                                   p))
             #'> :key #'car)))
      ;; Take the best <=MAX-TARGETS peers that don't already know the address;
      ;; count the chosen targets (Core queues to exactly its picked nodes)
      ;; rather than successful writes, so a dropped connection can't widen the
      ;; fan-out.
      (loop for (nil . p) in ranked
            while (< sent max-targets)
            unless (bitcoin-lisp:recent-reject-p (peer-known-addrs p) key)
              do (bitcoin-lisp:add-recent-reject (peer-known-addrs p) key)
                 (let ((msg (build-addr-response p (list peer-addr))))
                   (when msg (send-message p msg)))
                 (incf sent)))
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
  (logtest services (logior bitcoin-lisp.serialization:+node-network+
                            bitcoin-lisp.serialization:+node-network-limited+)))

(defun %ingest-gossiped-address (net-addr timestamp address-book source-group now
                                 &optional source-net source-ip)
  "Shared addr/addrv2 ingestion for one gossiped NET-ADDR (Core's per-address
loop in the ADDR handler, net_processing.cpp:4056-4098) learned from a peer
with net-group key SOURCE-GROUP and own address SOURCE-NET/SOURCE-IP. Stores
it in ADDRESS-BOOK only when its network is REACHABLE (-onlynet; Core \"Do not
store addresses outside our network\"), but fresh (10-min) ROUTABLE addresses
are relay candidates regardless — an unreachable-net address still relays,
just to 1 peer instead of 2 (Core RelayAddress fReachable).

Age gates RELAY only, never storage. An absurd timestamp (unset, or more than
10 minutes ahead of us) is rewritten to now - 5 days and stored anyway
(net_processing.cpp:4090-4092) rather than dropped; the stored copy carries
the 2h gossip penalty, waived for a peer announcing itself. Addresses whose
services bits promise no useful address DB are skipped entirely — neither
stored nor relayed, as in Core.

Returns (VALUES stored relay-entry): STORED is 1/0 for the caller's log count,
RELAY-ENTRY a (peer-address . max-targets) cons when the address should be
gossiped onward."
  (unless (and address-book timestamp
               (may-have-useful-address-db-p
                (bitcoin-lisp.serialization:net-addr-services net-addr)))
    (return-from %ingest-gossiped-address (values 0 nil)))
  (let* ((time (if (or (<= timestamp +addr-time-init+)
                       (> timestamp (+ now 600)))
                   (max 0 (- now +addr-absurd-time-replacement-seconds+))
                   timestamp))
         (pa (make-peer-address
              :net (bitcoin-lisp.serialization:net-addr-net net-addr)
              :ip (bitcoin-lisp.serialization:net-addr-ip net-addr)
              :port (bitcoin-lisp.serialization:net-addr-port net-addr)
              :services (bitcoin-lisp.serialization:net-addr-services net-addr)
              :last-seen time))
         (network (peer-address-network pa))
         (reachable (reachable-network-p network))
         ;; Core: "Do not set a penalty for a source's self-announcement"
         ;; (addrman.cpp:559-563; the comparison is CNetAddr, so port-blind).
         (penalty (if (and source-net (eq source-net network)
                           (equalp source-ip (peer-address-ip pa)))
                      0
                      +addr-gossip-time-penalty-seconds+)))
    (when reachable
      (address-book-add address-book pa source-group penalty))
    (values (if reachable 1 0)
            ;; Core relays only fresh (10-min) routable addrs — on the
            ;; rewritten timestamp, so a "flying DeLorean" address cannot buy
            ;; itself relay by claiming a future time.
            (when (and (> time (- now 600))
                       (address-routable-p (peer-address-ip pa) network))
              (cons pa (if reachable 2 1))))))

(defun %refill-addr-token-bucket (peer &optional (now (get-internal-real-time)))
  "Refill PEER's addr token bucket from elapsed time, once per addr/addrv2
message (Core net_processing.cpp:4056-4064): only while below the soft cap,
at +max-addr-rate-per-second+, clamped to the cap — so the getaddr-response
bump above the cap is never refilled further but also not clawed back. The
timestamp always advances."
  (let ((cap (coerce +max-addr-processing-token-bucket+ 'double-float)))
    (when (< (peer-addr-token-bucket peer) cap)
      (let* ((elapsed (max 0 (- now (peer-addr-token-timestamp peer))))
             (increment (* (/ (coerce elapsed 'double-float)
                              internal-time-units-per-second)
                           +max-addr-rate-per-second+)))
        (setf (peer-addr-token-bucket peer)
              (min (+ (peer-addr-token-bucket peer) increment) cap))))
    (setf (peer-addr-token-timestamp peer) now)))

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
    (let* ((now (bitcoin-lisp.serialization:get-unix-time))
           ;; Read before the end-of-message reset below, like Core (the reset
           ;; runs after the loop): a getaddr response never relays onward.
           (unsolicited (not (and peer (peer-getaddr-requested peer))))
           (added 0)
           (num-proc 0)
           (num-rate-limit 0)
           (relay-candidates '()))
      (when peer
        (%refill-addr-token-bucket peer))
      (dolist (entry (alexandria:shuffle (copy-list entries)))
        (cond
          ((and peer (< (peer-addr-token-bucket peer) 1.0d0))
           (incf num-rate-limit))
          (t
           (when peer
             (decf (peer-addr-token-bucket peer) 1.0d0)
             (incf num-proc))
           (multiple-value-bind (stored relay)
               (%ingest-gossiped-address (car entry) (cdr entry)
                                         address-book source-group now
                                         source-net source-ip)
             (incf added stored)
             (when relay (push relay relay-candidates))))))
      (when peer
        (incf (peer-addr-processed peer) num-proc)
        (incf (peer-addr-rate-limited peer) num-rate-limit)
        (when (plusp num-rate-limit)
          (bitcoin-lisp:log-cat "net" "addr from peer ~A: ~D processed, ~D rate-limited"
                                (peer-address peer) num-proc num-rate-limit))
        ;; A non-full message answers our getaddr (Core: "if (vAddr.size() <
        ;; 1000) peer.m_getaddr_sent = false", net_processing.cpp:4116).
        (when (< announced-count bitcoin-lisp.serialization:+max-addr-count+)
          (setf (peer-getaddr-requested peer) nil)))
      (when (and peers unsolicited (<= announced-count 10))
        (loop for (pa . max-targets) in relay-candidates
              do (relay-address pa peer peers :now now :max-targets max-targets)))
      added)))

(defun handle-addr (peer payload &optional address-book peers)
  "Handle an addr message. When ADDRESS-BOOK is provided, add the addresses on
reachable networks to the address book regardless of age (absurd timestamps are
rewritten, not dropped — see %ingest-gossiped-address), keyed to the gossiping
PEER as their source (addrman source-group spreading), subject to the
per-address token bucket (see %process-gossiped-addresses). Ignored entirely
from a block-relay-only peer (Core SetupAddressRelay,
net_processing.cpp:4041); more than 1000 announced addresses is misbehavior
(net_processing.cpp:4046-4050)."
  (when (and peer (eq (peer-conn-type peer) :block-relay))
    (bitcoin-lisp:log-cat "net" "ignoring addr message from block-relay-only peer ~A"
                          (peer-address peer))
    (return-from handle-addr 0))
  ;; First addr-related message from an inbound peer enables address relay
  ;; (Core SetupAddressRelay; getpeerinfo addr_relay_enabled).
  (when peer (setf (peer-addr-relay-enabled peer) t))
  (let ((entries '())
        (msg-count 0))
    (flexi-streams:with-input-from-sequence (stream payload)
      (let ((count (bitcoin-lisp.serialization:read-compact-size stream)))
        (when (> count bitcoin-lisp.serialization:+max-addr-count+)
          (when peer
            (record-misbehavior peer (format nil "addr message size = ~D" count)))
          (return-from handle-addr 0))
        (setf msg-count count)
        (loop repeat count
              do (multiple-value-bind (net-addr timestamp)
                     (bitcoin-lisp.serialization:read-net-addr stream :with-timestamp t)
                   (push (cons net-addr timestamp) entries)))))
    (let ((added (%process-gossiped-addresses peer (nreverse entries) msg-count
                                              address-book peers)))
      (when (and address-book (> added 0))
        (bitcoin-lisp:log-cat "net" "Added ~D peer addresses from addr message" added))
      added)))

;;; ADDRv2 handling (BIP 155)

(defun handle-addrv2 (peer payload &optional address-book peers)
  "Handle an addrv2 message (BIP 155). When ADDRESS-BOOK is provided, add
addresses of any representable network (IPv4/IPv6/TORv3/I2P/CJDNS) to the
address book regardless of age (absurd timestamps are rewritten, not dropped —
see %ingest-gossiped-address) — non-IP networks only when reachable (-onlynet
+ proxy/flag gates), subject to the per-address token bucket (see
%process-gossiped-addresses). Unknown network ids were
already skipped by the codec; a count above 1000 fails parsing (Core
Misbehaving path — the caller disconnects). Ignored entirely from a
block-relay-only peer (Core SetupAddressRelay)."
  (when (and peer (eq (peer-conn-type peer) :block-relay))
    (bitcoin-lisp:log-cat "net" "ignoring addrv2 message from block-relay-only peer ~A"
                          (peer-address peer))
    (return-from handle-addrv2 0))
  ;; First addr-related message from an inbound peer enables address relay
  ;; (Core SetupAddressRelay; getpeerinfo addr_relay_enabled).
  (when peer (setf (peer-addr-relay-enabled peer) t))
  (multiple-value-bind (entries announced-count)
      (bitcoin-lisp.serialization:parse-addrv2-payload payload)
    (let ((added (%process-gossiped-addresses
                  peer
                  (mapcar (lambda (entry)
                            (destructuring-bind (net-addr timestamp network-id) entry
                              (declare (ignore network-id))
                              (cons net-addr timestamp)))
                          entries)
                  announced-count address-book peers)))
      (when (and address-book (> added 0))
        (bitcoin-lisp:log-cat "net" "Added ~D peer addresses from addrv2 message" added))
      added)))

;;; Transaction handling

(defparameter +reconsiderable-tx-failures+
  '(:insufficient-fee :replacement-failed :mempool-full)
  "The rejection reasons Bitcoin Core classifies TX_RECONSIDERABLE — \"fails
some policy, but might be acceptable if submitted in a (different) package\"
(consensus/validation.h:48). Core's four sites: both fee-floor failures in
CheckFeeRate (validation.cpp:703-711), the RBF anti-DoS fee check (:1010)
and the RBF diagram check (:1028) — our :replacement-failed — and \"mempool
full\", i.e. a tx that self-evicted on the post-add trim (:1399-1402).

NOT reconsiderable, and so still cached in the MAIN filter: :too-large-cluster
(Core TX_MEMPOOL_POLICY, validation.cpp:1020-1022) — a cluster-limit failure
is not a fee problem and a package cannot fix it.")

(defun %reconsiderable-failure-p (reason)
  "T if REASON is one Core would mark TX_RECONSIDERABLE."
  (and (member reason +reconsiderable-tx-failures+) t))

(defun %cache-tx-rejection (tx reason recent-rejects)
  "Core MempoolRejectedTx's caching rules, for the first_time_failure=false
callers this node has (txdownloadman_impl.cpp:350-484):

  - :missing-input is cached NOWHERE (:361-364). Core's TX_MISSING_INPUTS
    branch does orphan INTAKE, and only when first_time_failure is true;
    at first_time_failure=false — which is what every caller here is — the
    whole branch is a no-op. A missing input is not a verdict on the
    transaction: the parent may still arrive, or the pair may still be
    submitted as a package. Caching it in the main filter would black-hole
    the CHILD of a CPFP pair, which is the mirror of the bug the
    reconsiderable filter exists to fix. This arm matters because a
    package member can REACH here carrying :missing-input: a package-LEVEL
    failure (TRUC topology, package RBF, cluster limits, ephemeral dust, or
    the quit-early path) leaves the child's nonfinal phase-1 result
    untouched, and Core deliberately carries that nonfinal
    TX_MISSING_INPUTS into results_final (validation.cpp:1759-1763) so that
    ProcessPackageResult can see it and do nothing with it.
  - RECONSIDERABLE failures go to the SEPARATE reconsiderable filter, keyed
    by wtxid (:454-459). They must not enter the main filter: an entry there
    is permanent until the next block, and would black-hole the transaction
    — the parent of a CPFP package would never be accepted, mined or
    relayed, no matter how much fee its child brings.
  - :witness-stripped is cached NOWHERE (:438-439): wtxid == txid for such a
    tx, so caching would poison the TXID of the real, witnessed transaction.
  - Everything else is cached in the main filter under the WTXID only —
    the witness is malleable (Core issue #8279) — plus the TXID for
    :nonstandard-inputs, a failure that depends only on the txid (:471-484)."
  (let ((txid (bitcoin-lisp.serialization:transaction-hash tx))
        (wtxid (bitcoin-lisp.serialization:transaction-wtxid tx)))
    (cond
      ((eq reason :missing-input) nil)
      ((eq reason :witness-stripped) nil)
      ((%reconsiderable-failure-p reason)
       (bitcoin-lisp.validation:add-reconsiderable-reject wtxid))
      (t
       (bitcoin-lisp:add-recent-reject recent-rejects wtxid)
       (when (and (eq reason :nonstandard-inputs) (not (equalp wtxid txid)))
         (bitcoin-lisp:add-recent-reject recent-rejects txid))))))

(defun process-orphans (accepted-txid utxo-set mempool chain-state peers
                        &key recent-rejects)
  "De-orphan cascade: after ACCEPTED-TXID enters the mempool, re-validate the
orphans that depend on it; accept+relay any now valid, drop those now invalid,
and recurse on newly-accepted txs so a parent can unblock a whole chain.
The orphanage is wtxid-keyed (Core TxOrphanage); children reference parents
by TXID, so the cascade work list carries txids."
  (let ((pool (bitcoin-lisp.mempool:mempool-orphan-pool mempool))
        (work (list accepted-txid)))
    (loop while work do
      (let ((ptxid (pop work)))
        (dolist (owtxid (bitcoin-lisp.mempool:orphans-depending-on pool ptxid))
          (let ((otx (bitcoin-lisp.mempool:orphan-tx pool owtxid)))
            (when otx
              (let ((otxid (bitcoin-lisp.serialization:transaction-hash otx))
                    (current-height (bitcoin-lisp.storage:current-height chain-state)))
                (multiple-value-bind (valid error fee replaced sigops)
                    (bitcoin-lisp.validation:validate-transaction-for-mempool
                     otx utxo-set mempool current-height :chain-state chain-state)
                  (cond
                    (valid
                     (multiple-value-bind (result entry)
                         (bitcoin-lisp.mempool:accept-validated-tx
                          mempool otxid otx fee current-height
                          :sigops sigops :replaced replaced)
                       (when (eq :ok result)
                         (bitcoin-lisp.mempool:orphan-remove pool owtxid)
                         (when peers
                           (let ((vsize (bitcoin-lisp.mempool:mempool-entry-vsize entry)))
                             (relay-transaction
                              otxid nil peers
                              :fee-rate (if (plusp vsize) (floor fee vsize) 0)
                              :wtxid owtxid)))
                         (push otxid work))))   ; cascade to this tx's dependents
                    ((eq error :missing-input) nil)   ; still missing another parent
                    (t (bitcoin-lisp.mempool:orphan-remove pool owtxid)  ; now invalid
                       ;; Same insertion rules as handle-tx — Core routes
                       ;; orphan re-validation failures through the same
                       ;; MempoolRejectedTx. This is Core's
                       ;; first_time_failure=false path, so no 1p1c retry is
                       ;; attempted here (net_processing.cpp:3207-3211).
                       (%cache-tx-rejection otx error recent-rejects))))))))))))

(defun missing-parent-txids (tx utxo-set mempool)
  "Deduplicated txids of TX's inputs found in neither the UTXO set nor the
mempool — the parents whose absence makes TX an orphan (Core GetUniqueParents,
txdownloadman_impl.cpp:333-348, minus the already-have filter its callers
apply)."
  (let ((seen (make-hash-table :test 'equalp))
        (parents '()))
    (bitcoin-lisp.serialization:dovector (input (bitcoin-lisp.serialization:transaction-inputs tx))
      (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
             (ptxid (bitcoin-lisp.serialization:outpoint-hash prevout))
             (pidx (bitcoin-lisp.serialization:outpoint-index prevout)))
        (unless (or (gethash ptxid seen)
                    (bitcoin-lisp.storage:get-utxo utxo-set ptxid pidx)
                    (bitcoin-lisp.mempool:mempool-has mempool ptxid))
          (setf (gethash ptxid seen) t)
          (push ptxid parents))))
    (nreverse parents)))

(defun request-orphan-parents (peer parent-txids &optional (num-wtxid-peers 0))
  "Register an orphan's missing PARENT-TXIDS with the tx-request tracker as
txid-based announcements from PEER and getdata the ones requestable now.
Returns the list of inv-vectors sent immediately (delayed/duplicate parents
ride the scheduler), or NIL when the whole batch was dropped by the per-peer
cap — Core MaybeAddOrphanResolutionCandidate returns false then and no
announcer is recorded (txdownloadman_impl.cpp:230-282). NUM-WTXID-PEERS
drives the txid-relay delay: Core delays parent fetches whenever wtxid peers
exist, since parents are requested by txid (:246-251).

Parents are known only by TXID, so the request MUST carry the witness flag
(MSG_TX|MSG_WITNESS_FLAG) for witness-capable peers — Core requests every
txid-based announcement as MSG_TX | GetFetchFlags(peer)
(net_processing.cpp:6207; orphan parents enter the tracker as
GenTxid::Txid announcements via MaybeAddOrphanResolutionCandidate,
txdownloadman_impl.cpp:257-260). A bare MSG_TX getdata is answered with the
WITNESS-STRIPPED serialization: a stripped segwit parent can never pass
script validation, and since a stripped tx's wtxid equals its txid, the
reject path then poisoned recent-rejects with the parent's real TXID — the
witnessed parent could never be fetched again and the orphan never resolved.

Registration with the shared tracker means concurrent orphans wanting the
same parent don't duplicate the getdata and a timed-out parent request fails
over like any other (Core routes them through the same m_txrequest)."
  ;; Bulk per-peer cap (Core: Count(peer) + unique_parents.size() >
  ;; MAX_PEER_TX_ANNOUNCEMENTS drops the whole candidacy, :242).
  (when (> (+ (tx-request-count peer) (length parent-txids))
           +max-peer-tx-announcements+)
    (return-from request-orphan-parents nil))
  (let ((invs '()))
    (dolist (ptxid parent-txids)
      ;; Parents are txid-based announcements: Core adds TXID_RELAY_DELAY
      ;; whenever wtxid peers exist (unconditional on the id type, :251) —
      ;; matched here since wtxidp is NIL.
      (when (tx-request-wanted-p ptxid peer nil num-wtxid-peers)
        (push (tx-request-inv ptxid nil peer) invs)))
    (setf invs (nreverse invs))
    (when invs
      (send-message peer (bitcoin-lisp.serialization:make-getdata-message invs)))
    (or invs t)))

;;; --- Opportunistic 1-parent-1-child package relay ---
;;;
;;; The reason the reconsiderable filter exists. A CPFP package (an LN
;;; commitment transaction paying no fee of its own, plus the child that
;;; fee-bumps it) arrives as two separate `tx` messages, and neither can be
;;; accepted alone: the parent is under the fee floor, the child has a
;;; missing input. Core pairs them up opportunistically — the parent's
;;; reconsiderable failure triggers a search of the orphanage for a child
;;; that spends it, and the two are submitted together through the ordinary
;;; package-validation path (net_processing.cpp:4523-4527, :4543-4547).

(defun %after-mempool-accept (tx peer peers utxo-set mempool chain-state
                              recent-rejects)
  "The shared tail for a transaction that has just entered the mempool from
the P2P path (Core ProcessValidTx -> MempoolAcceptedTx,
txdownloadman_impl.cpp:323-333): forget it as an orphan, relay it, and run
the de-orphan cascade over the children waiting on it. PEER is the source,
excluded from relay."
  (let ((txid (bitcoin-lisp.serialization:transaction-hash tx))
        (wtxid (bitcoin-lisp.serialization:transaction-wtxid tx)))
    ;; It may have been in our orphanage (announced by another peer, or held
    ;; while a parent was fetched); Core's EraseTx is a no-op otherwise.
    (bitcoin-lisp.mempool:orphan-remove
     (bitcoin-lisp.mempool:mempool-orphan-pool mempool) wtxid)
    ;; The entry carries the fee and the sigop-adjusted vsize the feefilter
    ;; gate needs; read it from the pool rather than threading it, so the
    ;; package path (which has no entry in hand) shares this tail.
    (let ((entry (and peers (bitcoin-lisp.mempool:mempool-get mempool txid))))
      (when entry
        (let ((vsize (bitcoin-lisp.mempool:mempool-entry-vsize entry))
              (fee (bitcoin-lisp.mempool:mempool-entry-fee entry)))
          (relay-transaction txid peer peers
                             :fee-rate (if (plusp vsize) (floor fee vsize) 0)
                             :wtxid wtxid))))
    (process-orphans txid utxo-set mempool chain-state peers
                     :recent-rejects recent-rejects)))

(defun %find-1p1c-package (peer parent-tx mempool recent-rejects)
  "Core Find1P1CPackage (txdownloadman_impl.cpp:297-321): the newest orphan
announced BY PEER that spends PARENT-TX and whose pairing with it is not
already known to fail — the package hash in the reconsiderable filter, or
the child's TXID in the main rejects filter. Returns the child transaction,
or NIL when there is no eligible candidate."
  (let ((pool (bitcoin-lisp.mempool:mempool-orphan-pool mempool)))
    (dolist (child (bitcoin-lisp.mempool:orphan-children-from-peer
                    pool parent-tx peer))
      (unless (or (bitcoin-lisp.validation:reconsiderable-reject-p
                   (bitcoin-lisp.validation:package-hash (list parent-tx child)))
                  (bitcoin-lisp:recent-reject-p
                   recent-rejects
                   (bitcoin-lisp.serialization:transaction-hash child)))
        (return child)))))

(defun %try-1p1c-package (peer parent-tx utxo-set mempool chain-state peers
                          recent-rejects)
  "PARENT-TX failed on its own for a reconsiderable reason: look for a child
of it in the orphanage and submit the pair as a package (Core's
ProcessNewPackage + ProcessPackageResult, net_processing.cpp:3170-3220).
Returns T if a package was submitted.

Result handling mirrors ProcessPackageResult exactly: a package-level
failure is remembered by package hash so the same combination is not
re-validated on every re-announcement; members are walked CHILD FIRST, so
an in-package descendant leaves the orphanage before the parent's de-orphan
cascade could pick it up again; an accepted member takes the ordinary
accept tail; and a member that failed is cached under Core's
first_time_failure=false rules — no orphan intake, no further 1p1c.

Note the CHILD of a package that failed a PACKAGE-LEVEL check still carries
its nonfinal phase-1 :missing-input result, which under those rules is
cached NOWHERE and does not even leave the orphanage. Caching it would
black-hole an honest CPFP child after a single lost package attempt."
  (let ((child (%find-1p1c-package peer parent-tx mempool recent-rejects)))
    (when child
      (let ((package (list parent-tx child)))
        (multiple-value-bind (msg results)
            (bitcoin-lisp.validation:validate-package-for-mempool
             package utxo-set mempool chain-state)
          (bitcoin-lisp:log-cat "mempool" "1p1c package evaluation: ~A" msg)
          (unless (eq msg :success)
            (bitcoin-lisp.validation:add-reconsiderable-reject
             (bitcoin-lisp.validation:package-hash package)))
          ;; RESULTS is in package order; walk it backwards.
          (loop for tx in (reverse package)
                for res in (reverse results)
                do (let ((err (bitcoin-lisp.validation:package-tx-result-error res)))
                     (case (bitcoin-lisp.validation:package-tx-result-status res)
                       (:valid
                        (%after-mempool-accept tx peer peers utxo-set mempool
                                               chain-state recent-rejects))
                       ;; Core routes INVALID and DIFFERENT_WITNESS through the
                       ;; same ProcessInvalidTx (net_processing.cpp:3204-3212).
                       ;; A DIFFERENT_WITNESS result carries a
                       ;; default-constructed (TX_RESULT_UNSET) state
                       ;; (validation.h:228-229), so MempoolRejectedTx's final
                       ;; else caches its wtxid in the main filter — which is
                       ;; what %CACHE-TX-REJECTION does for a NIL reason.
                       ((:invalid :different-witness)
                        ;; :missing-input is cached nowhere and does NOT leave
                        ;; the orphanage: a package-LEVEL failure leaves the
                        ;; child's nonfinal phase-1 result untouched, and Core
                        ;; deliberately does nothing with it here
                        ;; (txdownloadman_impl.cpp:361-364, :489-492).
                        (%cache-tx-rejection tx err recent-rejects)
                        (unless (eq err :missing-input)
                          (bitcoin-lisp.mempool:orphan-remove
                           (bitcoin-lisp.mempool:mempool-orphan-pool mempool)
                           (bitcoin-lisp.serialization:transaction-wtxid tx))))
                       ;; :not-validated — a context-free package check
                       ;; (well-formedness, child-with-parents) failed before
                       ;; any member was processed. Core's ProcessNewPackage
                       ;; returns no per-tx results at all in that case and
                       ;; ProcessPackageResult's `it_result != end()` guard
                       ;; skips them, so nothing is cached: deliberate.
                       (otherwise nil))))
          t)))))

(defun %orphan-parents-rejected-p (parent-txids recent-rejects)
  "Core's fRejectedParents scan (txdownloadman_impl.cpp:371-396): T when an
orphan with these MISSING PARENT-TXIDS must not be kept at all.

A parent in the MAIN rejects filter is fatal — no witness and no package can
make this child acceptable. A parent in the RECONSIDERABLE filter is NOT: it
may be precisely the low-feerate parent this child exists to fee-bump. Core
tolerates exactly ONE such parent, because it only submits 1-parent-1-child
packages, so a second one could never be rescued.

PARENT-TXIDS are already the parents missing from both the UTXO set and the
mempool, which subsumes Core's `!m_opts.m_mempool.exists(parent_txid)` guard."
  (let ((reconsiderable 0))
    (dolist (ptxid parent-txids nil)
      (cond ((bitcoin-lisp:recent-reject-p recent-rejects ptxid)
             (return t))
            ((bitcoin-lisp.validation:reconsiderable-reject-p ptxid)
             (when (> (incf reconsiderable) 1)
               (return t)))))))

(defun handle-tx (peer payload utxo-set mempool chain-state peers
                  &key recent-rejects)
  "Handle a tx message. Validate, add to mempool, and relay.
RECENT-REJECTS is optional; when provided, recently rejected txs are cached."
  ;; A tx sent where we advertised fRelay=0 (-blocksonly / relay-disabled
  ;; mainnet default, block-relay/feeler conns) violates the protocol:
  ;; disconnect (Core RejectIncomingTxs gate in the TX handler,
  ;; net_processing.cpp:4474-4479).
  (when (or (ignore-incoming-txs-p)
            (not (peer-relays-txs-p peer)))
    (bitcoin-lisp:log-cat "net" "transaction sent in violation of protocol — disconnecting peer ~A"
                          (peer-address peer))
    (disconnect-peer peer)
    (return-from handle-tx nil))
  (handler-case
      (let ((tx (bitcoin-lisp.serialization:parse-tx-payload payload)))
        (when tx
          (with-node-lock
            (let ((txid (bitcoin-lisp.serialization:transaction-hash tx))
                  (wtxid (bitcoin-lisp.serialization:transaction-wtxid tx))
                  (current-height (bitcoin-lisp.storage:current-height chain-state)))
              ;; The requested tx arrived — clear its in-flight/announcer
              ;; tracking. MSG_WTX announcements are tracked under the wtxid,
              ;; so clear that key too (txids and wtxids never collide; for
              ;; no-witness txs they are equal and one call suffices).
              (tx-request-received txid)
              (unless (equalp wtxid txid)
                (tx-request-received wtxid))
              ;; Mark as announced by this peer (bounded set)
              (bitcoin-lisp:add-recent-reject (peer-announced-txs peer) txid)
              ;; Check recent rejects and recently-confirmed before expensive
              ;; validation (Core's AlreadyHaveTx at tx receipt). The rejects
              ;; filter is wtxid-keyed (Core m_lazy_recent_rejects); txid
              ;; entries exist only where Core adds them too, so check both
              ;; ids. Freshly-confirmed txs (still relaying through the
              ;; network) are dropped without being treated as rejects.
              (when (or (bitcoin-lisp:recent-reject-p recent-rejects wtxid)
                        (bitcoin-lisp:recent-reject-p recent-rejects txid)
                        (bitcoin-lisp.validation:recently-confirmed-p wtxid)
                        (bitcoin-lisp.validation:recently-confirmed-p txid))
                (return-from handle-tx nil))
              ;; Already known to fail RECONSIDERABLY (too-low feerate, RBF
              ;; economics, mempool full): do not submit it alone again — but
              ;; it may succeed paired with a child we are already holding as
              ;; an orphan, which is how a CPFP package whose two halves
              ;; arrive separately gets assembled (Core ReceivedTx's second
              ;; branch, txdownloadman_impl.cpp:544-551).
              (when (bitcoin-lisp.validation:reconsiderable-reject-p wtxid)
                (%try-1p1c-package peer tx utxo-set mempool chain-state peers
                                   recent-rejects)
                (return-from handle-tx nil))
              ;; Validate for mempool
              (multiple-value-bind (valid error fee replaced sigops)
                  (bitcoin-lisp.validation:validate-transaction-for-mempool
                   tx utxo-set mempool current-height :chain-state chain-state)
                (unless valid
                  (cond
                    ;; Missing inputs => hold as an orphan (not a real reject);
                    ;; a later parent will trigger re-evaluation. Request the
                    ;; missing parents from this peer so they arrive sooner.
                    ;; UNLESS the parents make the orphan hopeless
                    ;; (%orphan-parents-rejected-p): then reject it outright —
                    ;; under BOTH ids, exactly like Core's "not keeping orphan
                    ;; with rejected parents" (txdownloadman_impl.cpp:422-436;
                    ;; the txid too, so non-wtxidrelay peers can't make us
                    ;; re-download it).
                    ((eq error :missing-input)
                     (let ((parents (missing-parent-txids tx utxo-set mempool)))
                       (if (%orphan-parents-rejected-p parents recent-rejects)
                           (progn
                             (bitcoin-lisp:add-recent-reject recent-rejects txid)
                             (bitcoin-lisp:add-recent-reject recent-rejects wtxid))
                           (progn
                             (bitcoin-lisp.mempool:orphan-add
                              (bitcoin-lisp.mempool:mempool-orphan-pool mempool) tx peer)
                             (request-orphan-parents
                              peer parents (count-wtxid-relay-peers peers))))))
                    (t
                     ;; Cache the failure so we don't re-request it (see
                     ;; %cache-tx-rejection for which filter and which ids).
                     ;; A loose transaction that fails validation is NOT
                     ;; misbehavior: Bitcoin Core removed tx-relay punishment
                     ;; (PR #26294), since tx validity is subjective (our
                     ;; mempool/chain state) and an honest peer shouldn't be
                     ;; discouraged for relaying a tx we happen to reject.
                     ;; Consensus-invalid txs are only punished inside a block.
                     (%cache-tx-rejection tx error recent-rejects)
                     ;; A FIRST-TIME reconsiderable failure is where Core looks
                     ;; for a child in the orphanage and retries the pair as a
                     ;; package (txdownloadman_impl.cpp:460-465).
                     (when (%reconsiderable-failure-p error)
                       (%try-1p1c-package peer tx utxo-set mempool chain-state
                                          peers recent-rejects)))))
                (when valid
                  (let ((result (bitcoin-lisp.mempool:accept-validated-tx
                                 mempool txid tx fee current-height
                                 :sigops sigops :replaced replaced)))
                    (cond
                      ((eq result :ok)
                       ;; getpeerinfo "last_transaction" (Core m_last_tx_time,
                       ;; stamped only on mempool ACCEPTANCE,
                       ;; net_processing.cpp:4540).
                       (setf (peer-last-tx-time peer)
                             (bitcoin-lisp.serialization:get-unix-time))
                       ;; Relay, de-orphan, cascade.
                       (%after-mempool-accept tx peer peers utxo-set mempool
                                              chain-state recent-rejects))
                      ;; The tx passed validation but the mempool refused it.
                      ;; Core reports these through the same MempoolRejectedTx
                      ;; path as any other failure, so they are cached like
                      ;; one: :mempool-full is reconsiderable — the tx
                      ;; self-evicted on the trim and a package could still
                      ;; carry it (validation.cpp:1399-1402) — while
                      ;; :too-large-cluster and :conflict go to the main
                      ;; filter. Uncached, every re-announcement was
                      ;; re-downloaded and fully re-validated.
                      ((eq result :duplicate) nil)   ; we already have it
                      (t
                       (%cache-tx-rejection tx result recent-rejects)
                       (when (%reconsiderable-failure-p result)
                         (%try-1p1c-package peer tx utxo-set mempool
                                            chain-state peers
                                            recent-rejects)))))))))))
    (error (c)
      (declare (ignore c))
      nil)))

(defconstant +max-blocks-served-per-getdata+ 500
  "Cap on full blocks served from a single getdata message. A well-behaved peer
requests at most ~16 blocks in flight (and up to 500 after a getblocks inv); this
bounds the disk-read/serialize/send work a single message can demand, since a
getdata can carry up to MAX_INV_SZ (50000) entries.")

(defun handle-getdata (peer payload chain-state &optional mempool block-store)
  "Handle a getdata message. Respond with requested transactions or blocks.
Does not respond to transaction requests when relay is disabled (mainnet default).
Blocks are served from BLOCK-STORE — MSG_BLOCK legacy, MSG_WITNESS_BLOCK with
witness — so the node is a serving peer, not just a leech. A requested block we
do not have on disk (pruned or unknown) is silently skipped, like Bitcoin Core's
handling of unavailable blocks."
  (declare (ignore chain-state))
  (let ((inv-vectors (bitcoin-lisp.serialization:parse-inv-payload payload))
        (blocks-served 0)
        (not-found '()))
    (dolist (inv inv-vectors)
      ;; Stop serving a send-paused peer (its outgoing buffer is over the
      ;; cap) — Core breaks out of ProcessGetData on fPauseSend
      ;; (net_processing.cpp:2536). Core parks the rest of the getdata for
      ;; later; we drop it and the peer re-requests, which its own request
      ;; timeout already handles. The notfound for what WAS processed still
      ;; goes out below, as in Core.
      (let ((conn (peer-connection peer)))
        (when (and conn (connection-send-paused-p conn))
          (return)))
      (let ((inv-type (bitcoin-lisp.serialization:inv-vector-type inv))
            (hash (bitcoin-lisp.serialization:inv-vector-hash inv)))
        (cond
          ;; Transaction request - only respond if relay is enabled. Resolve the
          ;; hash by the id its inv type implies: MSG_TX by txid (legacy
          ;; serialization), MSG_WITNESS_TX by txid (witness serialization),
          ;; MSG_WTX by wtxid (BIP339, witness serialization). We also accept a
          ;; wtxid under MSG_WITNESS_TX: our pre-BIP339-fix versions announced
          ;; wtxids under that type, and txids and wtxids never collide, so
          ;; trying both is safe (kept for peers echoing those old requests).
          ((or (= inv-type bitcoin-lisp.serialization:+inv-type-tx+)
               (= inv-type bitcoin-lisp.serialization:+inv-type-witness-tx+)
               (= inv-type bitcoin-lisp.serialization:+inv-type-wtx+))
           (cond
             ;; No tx-relay state with this peer (its version had fRelay=0, or
             ;; a block-relay/feeler conn): ignore the request entirely — not
             ;; even a notfound (Core ProcessGetData's `tx_relay == nullptr`
             ;; continue, net_processing.cpp:2539-2543).
             ((not (peer-tx-relay-p peer)))
             (t
              (let* ((entry (when (and mempool (relay-enabled-p))
                              (cond
                                ((= inv-type bitcoin-lisp.serialization:+inv-type-wtx+)
                                 (bitcoin-lisp.mempool:mempool-get-by-wtxid mempool hash))
                                ((= inv-type bitcoin-lisp.serialization:+inv-type-tx+)
                                 (bitcoin-lisp.mempool:mempool-get mempool hash))
                                (t
                                 (or (bitcoin-lisp.mempool:mempool-get mempool hash)
                                     (bitcoin-lisp.mempool:mempool-get-by-wtxid mempool hash))))))
                     ;; Anti-probing gate (Core FindTxForGetData ->
                     ;; info_for_relay, net_processing.cpp:2496-2505): serve a
                     ;; mempool tx only if it entered the pool BEFORE our last
                     ;; inv flush to this peer — i.e. we could already have
                     ;; announced it. A getdata for anything newer reveals the
                     ;; peer is probing mempool contents: notfound.
                     (tx (cond
                           ((and entry
                                 (< (bitcoin-lisp.mempool:mempool-entry-sequence entry)
                                    (peer-last-inv-sequence peer)))
                            (bitcoin-lisp.mempool:mempool-entry-transaction entry))
                           ;; Or it might be from the most recent block (Core
                           ;; m_most_recent_block_txs, keyed by txid AND
                           ;; wtxid) — freshly-confirmed txs stay servable.
                           (t (bitcoin-lisp.validation:most-recent-block-tx hash)))))
                (cond
                  (tx
                   (send-message peer
                                 (bitcoin-lisp.serialization:make-tx-message
                                  tx
                                  :witness (/= inv-type bitcoin-lisp.serialization:+inv-type-tx+)))
                   ;; A peer requesting the tx is the proof our announcement
                   ;; propagated: drop it from the unbroadcast set (Core
                   ;; ProcessGetData, net_processing.cpp:2550 — on EVERY
                   ;; successful serve, either source).
                   (when mempool
                     (bitcoin-lisp.mempool:mempool-remove-unbroadcast
                      mempool
                      (bitcoin-lisp.serialization:transaction-hash tx))))
                  (t
                   ;; Core accumulates vNotFound for txs it can't serve so the
                   ;; requester re-routes immediately instead of timing out.
                   (push inv not-found)))))))
          ;; Block request - serve the full block from disk (witness-aware).
          ((or (= inv-type bitcoin-lisp.serialization:+inv-type-block+)
               (= inv-type bitcoin-lisp.serialization:+inv-type-witness-block+))
           (when (and block-store (< blocks-served +max-blocks-served-per-getdata+))
             (let ((block (bitcoin-lisp.storage:get-block block-store hash)))
               (when block
                 (incf blocks-served)
                 (send-message
                  peer
                  (bitcoin-lisp.serialization:make-block-message
                   block
                   :witness (= inv-type
                               bitcoin-lisp.serialization:+inv-type-witness-block+))))))))))
    ;; One notfound for every unserved tx request (Core sends notfound for txs
    ;; only, never blocks).
    (when not-found
      (send-message peer (bitcoin-lisp.serialization:make-notfound-message
                          (nreverse not-found))))))

(defconstant +max-getcfilters-size+ 1000
  "Max filters per getcfilters request (Core MAX_GETCFILTERS_SIZE).")
(defconstant +max-getcfheaders-size+ 2000
  "Max headers per getcfheaders request (Core MAX_GETCFHEADERS_SIZE).")
(defconstant +cfcheckpt-interval+ 1000
  "Block spacing of cfcheckpt filter headers (Core CFCHECKPT_INTERVAL).")

(defun %cf-serving-index ()
  "The block filter index to serve BIP157 requests from, or NIL when serving is
off (-peerblockfilters absent) or the index is unavailable."
  (and bitcoin-lisp:*peer-block-filters*
       bitcoin-lisp::*node*
       (let ((bfi (bitcoin-lisp::node-blockfilterindex bitcoin-lisp::*node*)))
         (and bfi (bitcoin-lisp.storage:blockfilterindex-enabled bfi) bfi))))

(defun %cf-active-hash (chain-state height)
  "Hash of the ACTIVE-chain block at HEIGHT, or NIL."
  (let ((e (bitcoin-lisp.storage:get-block-at-height chain-state height)))
    (and e (bitcoin-lisp.storage:block-index-entry-hash e))))

(defun %cf-request-stop-height (chain-state start-height stop-hash max-diff)
  "Validate a BIP157 request (Core PrepareBlockFilterRequest): STOP-HASH must be
a known block on the ACTIVE chain, START-HEIGHT <= stop height, and the span
under MAX-DIFF. Returns the stop height, or NIL. (Core also serves recent fork
blocks via GetAncestor; we serve the active chain only -- the light-client case.)"
  (let ((entry (bitcoin-lisp.storage:get-block-index-entry chain-state stop-hash)))
    (when entry
      (let* ((stop-height (bitcoin-lisp.storage:block-index-entry-height entry))
             (active (%cf-active-hash chain-state stop-height)))
        (when (and active (equalp active stop-hash)
                   (<= start-height stop-height)
                   (< (- stop-height start-height) max-diff))
          stop-height)))))

(defun handle-getcfilters (peer payload chain-state)
  "Serve a BIP157 getcfilters: one cfilter message per block in the requested
range, from the block filter index. Silently ignored when serving is disabled
or the request is invalid (Core disconnects; we drop the request)."
  (let ((bfi (%cf-serving-index)))
    (when bfi
      (multiple-value-bind (ftype start-height stop-hash)
          (bitcoin-lisp.serialization:parse-getcfilters-payload payload)
        (when (and ftype (zerop ftype))   ; type 0 = basic
          (let ((stop-height (%cf-request-stop-height
                              chain-state start-height stop-hash
                              +max-getcfilters-size+)))
            (when stop-height
              (loop for h from start-height to stop-height
                    for bh = (%cf-active-hash chain-state h)
                    for filter = (and bh (bitcoin-lisp.storage:blockfilterindex-get-filter bfi bh))
                    while filter
                    do (send-message
                        peer (bitcoin-lisp.serialization:make-cfilter-message
                              0 bh filter))))))))))

(defun handle-getcfheaders (peer payload chain-state)
  "Serve a BIP157 getcfheaders: the previous filter header at START-1 (zeros at
genesis) plus the per-block filter HASHES for the range, in one cfheaders."
  (let ((bfi (%cf-serving-index)))
    (when bfi
      (multiple-value-bind (ftype start-height stop-hash)
          (bitcoin-lisp.serialization:parse-getcfilters-payload payload)
        (when (and ftype (zerop ftype))
          (let ((stop-height (%cf-request-stop-height
                              chain-state start-height stop-hash
                              +max-getcfheaders-size+)))
            (when stop-height
              (let ((prev-header (make-array 32 :element-type '(unsigned-byte 8)
                                                :initial-element 0)))
                (when (plusp start-height)
                  (let* ((ph (%cf-active-hash chain-state (1- start-height)))
                         (hdr (and ph (bitcoin-lisp.storage:blockfilterindex-get-header bfi ph))))
                    (unless hdr (return-from handle-getcfheaders))
                    (setf prev-header hdr)))
                (let ((hashes '()))
                  (loop for h from start-height to stop-height
                        for bh = (%cf-active-hash chain-state h)
                        for filter = (and bh (bitcoin-lisp.storage:blockfilterindex-get-filter bfi bh))
                        do (unless filter (return-from handle-getcfheaders))
                           (push (bitcoin-lisp.crypto:hash256 filter) hashes))
                  (send-message
                   peer (bitcoin-lisp.serialization:make-cfheaders-message
                         0 stop-hash prev-header (nreverse hashes))))))))))))

(defun handle-getcfcheckpt (peer payload chain-state)
  "Serve a BIP157 getcfcheckpt: the filter header at every 1000th block up to
the stop hash."
  (let ((bfi (%cf-serving-index)))
    (when bfi
      (multiple-value-bind (ftype stop-hash)
          (bitcoin-lisp.serialization:parse-getcfcheckpt-payload payload)
        (when (and ftype (zerop ftype))
          (let ((stop-height (%cf-request-stop-height
                              chain-state 0 stop-hash most-positive-fixnum)))
            (when stop-height
              (let ((headers '()))
                (loop for h from +cfcheckpt-interval+ to stop-height by +cfcheckpt-interval+
                      for bh = (%cf-active-hash chain-state h)
                      for hdr = (and bh (bitcoin-lisp.storage:blockfilterindex-get-header bfi bh))
                      do (unless hdr (return-from handle-getcfcheckpt))
                         (push hdr headers))
                (send-message
                 peer (bitcoin-lisp.serialization:make-cfcheckpt-message
                       0 stop-hash (nreverse headers)))))))))))

(defconstant +max-blocktxn-depth+ 10
  "Core MAX_BLOCKTXN_DEPTH (net_processing.cpp:140). Deeper than this we refuse
to build a blocktxn and send the whole block instead.")

(defun handle-getblocktxn (peer payload block-store &optional chain-state)
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
  (when block-store
    (let* ((req (bitcoin-lisp.serialization:parse-getblocktxn-payload payload))
           (block-hash (bitcoin-lisp.serialization:block-txn-request-block-hash req))
           (indexes (bitcoin-lisp.serialization:block-txn-request-indexes req))
           (entry (and chain-state
                       (bitcoin-lisp.storage:get-block-index-entry chain-state block-hash)))
           (tip-height (and chain-state (bitcoin-lisp.storage:current-height chain-state)))
           (within-depth
             (and entry tip-height
                  (>= (bitcoin-lisp.storage:block-index-entry-height entry)
                      (- tip-height +max-blocktxn-depth+)))))
      (unless within-depth
        ;; Core queues a full MSG_WITNESS_BLOCK on the peer\'s getdata list, so
        ;; the block goes out through the getdata path and inherits its
        ;; backpressure. We send it here instead, which means we must apply
        ;; that backpressure ourselves: HANDLE-GETDATA refuses to serve another
        ;; block once the send side is paused, and without the same guard this
        ;; fallback would just trade a disk-read DoS for a queue one — a peer
        ;; that never drains could still make us read and serialize 4 MB
        ;; blocks, only now they pile up in memory.
        ;;
        ;; Paused means no reply at all; the peer re-requests, exactly as the
        ;; getdata path already relies on.
        (let ((conn (peer-connection peer)))
          (unless (and conn (connection-send-paused-p conn))
            (let ((block (bitcoin-lisp.storage:get-block block-store block-hash)))
              (when block
                (send-message peer (bitcoin-lisp.serialization:make-block-message
                                    block :witness t))))))
        (return-from handle-getblocktxn nil))
      (let ((block (bitcoin-lisp.storage:get-block block-store block-hash)))
      (when block
        (let* ((txs (coerce (bitcoin-lisp.serialization:bitcoin-block-transactions block)
                            'vector))
               (n (length txs)))
          (if (every (lambda (i) (and (>= i 0) (< i n))) indexes)
              (send-message peer
                            (bitcoin-lisp.serialization:make-blocktxn-message
                             block-hash
                             (mapcar (lambda (i) (aref txs i)) indexes)
                             :witness t))
              (record-misbehavior peer "getblocktxn with out-of-bounds tx indices"))))))))

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
                          :key #'bitcoin-lisp.storage:block-index-entry-hash
                          :test #'equalp)))
        (cond ((null tail) entries)
              (inclusivep (ldiff entries (cdr tail)))
              (t (ldiff entries tail))))))

(defun getheaders-response-message (payload chain-state)
  "Build the headers message answering a getheaders PAYLOAD: up to
+max-headers-count+ headers from our active chain just after the locator's fork
point — or just the stop block's header when the locator is empty. Always
returns a serialized headers message (empty when we have nothing to add).
Mirrors Bitcoin Core's GETHEADERS handler."
  (multiple-value-bind (locator-hashes stop-hash)
      (bitcoin-lisp.serialization:parse-block-locator-payload payload)
    (let ((headers
            (if (null locator-hashes)
                ;; Null locator: return only the stop block's header, if it is on
                ;; our active chain.
                (let ((entry (bitcoin-lisp.storage:get-block-index-entry
                              chain-state stop-hash)))
                  (when (and entry
                             (bitcoin-lisp.storage:entry-on-active-chain-p
                              chain-state entry))
                    (list (bitcoin-lisp.storage:block-index-entry-header entry))))
                ;; Walk forward from the fork point, stop hash inclusive.
                (let* ((fork (bitcoin-lisp.storage:find-fork-in-active-chain
                              chain-state locator-hashes))
                       (entries (bitcoin-lisp.storage:active-chain-entries-from
                                 chain-state
                                 (1+ (bitcoin-lisp.storage:block-index-entry-height fork))
                                 bitcoin-lisp.serialization:+max-headers-count+)))
                  (mapcar #'bitcoin-lisp.storage:block-index-entry-header
                          (truncate-entries-at-stop entries stop-hash t))))))
      (bitcoin-lisp.serialization:make-headers-message headers))))

(defun handle-getheaders (peer payload chain-state)
  "Serve a peer's getheaders by sending the headers message built from PAYLOAD
against our active chain (see getheaders-response-message)."
  (send-message peer (getheaders-response-message payload chain-state)))

(defun getblocks-response-message (payload chain-state)
  "Build the inv message answering a getblocks PAYLOAD: up to
+getblocks-inv-limit+ block hashes from our active chain after the locator's
fork point, stopping before the stop hash. Returns NIL when there is nothing to
announce. Mirrors Bitcoin Core's GETBLOCKS handler (legacy blocks-first peers)."
  (multiple-value-bind (locator-hashes stop-hash)
      (bitcoin-lisp.serialization:parse-block-locator-payload payload)
    (let* ((fork (bitcoin-lisp.storage:find-fork-in-active-chain
                  chain-state locator-hashes))
           (entries (bitcoin-lisp.storage:active-chain-entries-from
                     chain-state
                     (1+ (bitcoin-lisp.storage:block-index-entry-height fork))
                     +getblocks-inv-limit+))
           (chosen (truncate-entries-at-stop entries stop-hash nil)))
      (when chosen
        (bitcoin-lisp.serialization:make-inv-message
         (mapcar (lambda (entry)
                   (bitcoin-lisp.serialization:make-inv-vector
                    :type bitcoin-lisp.serialization:+inv-type-block+
                    :hash (bitcoin-lisp.storage:block-index-entry-hash entry)))
                 chosen))))))

(defun handle-getblocks (peer payload chain-state)
  "Serve a peer's getblocks by sending the inv built from PAYLOAD, if any (see
getblocks-response-message)."
  (let ((msg (getblocks-response-message payload chain-state)))
    (when msg
      (send-message peer msg))))

(defun peer-address->net-addr (peer-addr)
  "Build a net-addr (wire address) from a stored PEER-ADDRESS record."
  (bitcoin-lisp.serialization:make-net-addr
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
      (bitcoin-lisp.serialization:make-addrv2-message
       (mapcar (lambda (pa)
                 (list (peer-address->net-addr pa)
                       (bitcoin-lisp.serialization:network-bip155-id
                        (peer-address-network pa))
                       (peer-address-last-seen pa)))
               peer-addrs))
      (let ((compatible
              (remove-if-not
               (lambda (pa)
                 (bitcoin-lisp.serialization:v1-compatible-network-p
                  (peer-address-network pa)))
               peer-addrs)))
        (when compatible
          (bitcoin-lisp.serialization:make-addr-message
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

(defvar *addr-response-caches* (make-hash-table :test 'eq)
  "Requestor network keyword -> (ADDRS . EXPIRY-UNIX). Core keys by
(network, local listening socket) — H(RANDOMIZER_ID_NETWORKKEY, netclass,
bind addr, bind port), net.cpp:1832-1836. We key by network ALONE. That is a
deliberate simplification, not byte parity: our two listeners (clearnet and
onion, node.lisp) already map to distinct network keywords through
peer-connected-through-network, so the multi-bind case Core's key exists to
separate is covered. Two binds on the SAME network would share a cache here.")

(defun clear-addr-response-caches ()
  "Drop every cached getaddr response (tests; also a reset point if the
address book is rebuilt)."
  (clrhash *addr-response-caches*))

(defun %sample-addr-response (book)
  "Take a fresh addrman sample for the cache, filtered as Core's
GetAddressesUnsafe filters it (net.cpp:3686-3690): banned AND discouraged
addresses are dropped HERE, at fill time."
  (remove-if (lambda (pa)
               (let ((s (peer-address-string pa)))
                 (or (peer-discouraged-p s)
                     (peer-banned-p s))))
             (address-book-get-addr book :max +addrman-getaddr-max+
                                         :pct +addrman-getaddr-pct+)))

(defun cached-getaddr-response (book network now)
  "The cached response for a requestor on NETWORK, refilling if absent or
expired.

The ban/discourage filter runs only when the cache is FILLED, never on a hit —
Core returns m_addrs_response_cache verbatim (net.cpp:3729). Re-filtering per
hit would make responses differ between requestors inside one window whenever a
ban landed mid-window, which is precisely the fingerprinting signal the cache
exists to erase. The visible consequence is that we keep gossiping an address
for up to 27h after banning it; that is Core-identical and intended."
  (let ((entry (gethash network *addr-response-caches*)))
    (if (and entry (< now (cdr entry)))
        (car entry)
        (let ((addrs (%sample-addr-response book)))
          (setf (gethash network *addr-response-caches*)
                (cons addrs (+ now +addr-response-cache-base-seconds+
                               (random (1+ +addr-response-cache-jitter-seconds+)))))
          addrs))))

(defun handle-getaddr (peer &optional address-book)
  "Serve a peer's getaddr: reply once per connection, and only to inbound peers,
with up to +max-addr-count+ known addresses from ADDRESS-BOOK (defaulting to the
node's). The inbound-only + once-per-connection rules mirror Bitcoin Core's
GETADDR handler (anti-fingerprinting and anti-spam) — the once flag latches as
soon as the request arrives, before we build any response, so a peer can never
elicit more than one reply regardless of whether we had addresses to send."
  ;; getaddr is an addr-related message: it enables address relay with the
  ;; peer unless the connection never does addr relay (block-relay-only) —
  ;; Core SetupAddressRelay from the GETADDR handler.
  (unless (eq (peer-conn-type peer) :block-relay)
    (setf (peer-addr-relay-enabled peer) t))
  (when (and (peer-inbound peer)
             (not (peer-getaddr-sent peer)))
    (setf (peer-getaddr-sent peer) t)
    (let ((book (or address-book
                    (let ((node bitcoin-lisp::*node*))
                      (and node (bitcoin-lisp::node-address-book node))))))
      (when book
        ;; Served from the per-network cache: every requestor arriving on this
        ;; network sees the SAME snapshot for 21-27h, so reconnecting harvests
        ;; nothing new. Banned/discouraged addresses were filtered when the
        ;; cache was filled.
        (let* ((addrs (cached-getaddr-response
                       book
                       (peer-connected-through-network peer)
                       (bitcoin-lisp.serialization:get-unix-time)))
               ;; NIL when the peer is v1-only and every address was non-IP.
               (msg (and addrs (build-addr-response peer addrs))))
          (when msg
            (send-message peer msg)))))))

;;; Local-address self-advertisement (Core MaybeSendAddr's local-address half,
;;; net_processing.cpp:5530-5567 + GetLocalAddrForPeer, net.cpp:240-267)

(defconstant +avg-local-address-broadcast-interval+ (* 24 60 60)
  "Mean seconds between self-announcements of our own address to a peer
(Core AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL = 24h, net_processing.cpp:158).")

(defun peer-connected-through-network (peer)
  "The network of the transport PEER is actually connected over (Core
CNode::ConnectedThroughNetwork): :torv3 for peers accepted on the local
onion-service listener (whose socket address is Tor's 127.0.0.1) and for
outbound dials to .onion targets; otherwise the network of the peer's
address, or :unroutable when it cannot be typed (hostname addnode)."
  (if (peer-inbound-onion peer)
      :torv3
      (multiple-value-bind (net bytes)
          (parse-network-address (peer-address peer))
        (declare (ignore bytes))
        (or net :unroutable))))

(defun get-local-addr-for-peer (peer)
  "The local address worth advertising to PEER, as a local-address record, or
NIL (Core GetLocalAddrForPeer, net.cpp:240-267): the best mapLocalHost entry
for the peer's connected-through network (privacy rule + reachability rank,
best-local-address), provided it is routable. Core's other branch — sometimes
echoing back the address the peer SEES us as — is fDiscover-gated, and we
have no -discover support (fDiscover permanently false), so it never fires."
  (let ((la (best-local-address (peer-connected-through-network peer))))
    (when (and la
               (address-routable-p (local-address-bytes la)
                                   (local-address-network la)))
      la)))

(defun %announce-local-address (peer)
  "Send our best local address for PEER as a single-address addr/addrv2
message; T when one actually went out. build-addr-response drops a torv3
address for a peer without addrv2 (Core IsAddrCompatible); the sent address
is marked into the peer's known-addrs (Core AddAddressKnown at the queue
flush) so relay-address won't echo it back."
  (let ((la (get-local-addr-for-peer peer)))
    (when la
      (let* ((pa (make-peer-address
                  :net (local-address-network la)
                  :ip (local-address-bytes la)
                  :port (local-address-port la)
                  :services (local-services)
                  :last-seen (bitcoin-lisp.serialization:get-unix-time)))
             (msg (build-addr-response peer (list pa))))
        (when msg
          (bitcoin-lisp:add-recent-reject (peer-known-addrs peer)
                                          (%addr-gossip-key pa))
          (when (send-message peer msg)
            (bitcoin-lisp:log-cat "net" "Advertising address ~A:~D to peer ~A"
                                  (peer-address-string pa)
                                  (peer-address-port pa)
                                  (peer-address peer))
            t))))))

(defun maybe-advertise-local-address (peers chain-state)
  "Advertise our own best local address to each due addr-relay peer (Core
MaybeSendAddr's periodic local-address push): per peer, every ~24h on an
exponential schedule, with the first announcement due as soon as the peer is
ready. All our announcements are their own single-address message (Core only
distinguishes the first because later ones ride its outgoing addr queue,
which we don't have; its addr-known bloom reset before repeats is unneeded
here because this path never consults known-addrs). Eligibility matches our
addr gossip: ready + tx-relaying. Gated on !IBD like Core; the fListen gate
is implicit — the local-address map only gains entries while the onion
service (which requires listening) is up. Call ~1x/second from the sync
loop. Returns the number of peers announced to."
  ;; Fast path first: an empty map is the steady state of every node without
  ;; a Tor daemon, and this runs every second — don't touch the chainstate
  ;; (initial-block-download-p) or the peer list for it. (Consequence, unlike
  ;; Core: peers aren't rescheduled +24h while there is nothing to say, so
  ;; the first announcement goes out promptly once the service appears.)
  (unless *local-addresses*
    (return-from maybe-advertise-local-address 0))
  (when (initial-block-download-p chain-state)
    (return-from maybe-advertise-local-address 0))
  (let ((now (get-internal-real-time))
        (sent 0))
    (dolist (peer peers sent)
      (when (and (eq (peer-state peer) :ready)
                 (peer-relays-txs-p peer)
                 (<= (peer-next-local-addr-send peer) now))
        (when (%announce-local-address peer)
          (incf sent))
        ;; Reschedule whether or not anything was sent (Core sets
        ;; m_next_local_addr_send unconditionally once due).
        (setf (peer-next-local-addr-send peer)
              (+ now (%next-exp-interval-ticks
                      +avg-local-address-broadcast-interval+)))))))

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

(defconstant +max-tx-inv-queue+ 5000
  "Per-peer pending-announcement bound (Core MAX_PEER_TX_ANNOUNCEMENTS);
oldest entries are dropped beyond it.")

(defvar *next-inbound-inv-flush* 0
  "internal-real-time deadline of the shared inbound inv rotation
(Core NextInvToInbounds — one timer for all inbound peers).")

(defun %next-exp-interval-ticks (mean-seconds)
  "Ticks until the next event of a Poisson process with MEAN-SECONDS
(Core rand_exp_duration): -mean * ln(U), U uniform in (0,1]."
  (round (* mean-seconds internal-time-units-per-second
            (- (log (- 1.0d0 (random 1.0d0)))))))

(defun relay-transaction (txid source-peer peers &key fee-rate wtxid)
  "Queue a newly-accepted transaction for announcement to all connected
peers except SOURCE-PEER. Nothing is sent here — flush-tx-announcements
drains each peer's queue on its Poisson schedule (Core queues into
m_tx_inventory_to_send exactly the same way). FEE-RATE is sat/vB, used
against BIP133 feefilters at flush time. WTXID enables BIP339 MSG_WTX
announcements. Does nothing if relay is disabled for the network — but is
deliberately NOT gated on -blocksonly: a blocksonly node still announces
its OWN (locally-submitted) transactions, exactly like Core, whose
RelayTransaction has no ignore_incoming_txs check (incoming txs can't
reach here anyway — their senders are disconnected)."
  (unless (relay-enabled-p)
    (return-from relay-transaction nil))
  (let ((fee-rate-per-kb (if fee-rate (* fee-rate 1000) 0)))
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
                 ;; Skip if already announced to this peer (Core checks the
                 ;; known-filter at queue time too, PushTxInventory).
                 (not (bitcoin-lisp:recent-reject-p (peer-announced-txs peer) txid)))
        (setf (peer-tx-inv-queue peer)
              (nconc (peer-tx-inv-queue peer)
                     (list (list txid wtxid fee-rate-per-kb))))
        ;; Bound the queue: drop oldest beyond the cap.
        (let ((excess (- (length (peer-tx-inv-queue peer)) +max-tx-inv-queue+)))
          (when (plusp excess)
            (setf (peer-tx-inv-queue peer)
                  (nthcdr excess (peer-tx-inv-queue peer)))))))))

(defun %flush-peer-tx-invs (peer mempool)
  "Drain up to +inv-broadcast-target+ queued announcements to PEER as one
inv message. At flush time each entry is re-checked: still unannounced,
still in the mempool, and above the peer's BIP133 feefilter (feefiltered
entries are dropped, not deferred — Core skips them the same way).
BIP339: wtxidrelay peers get MSG_WTX + wtxid, others MSG_TX + txid
(net_processing.cpp:6009,6065)."
  (let ((invs '())
        (count 0))
    (loop while (and (peer-tx-inv-queue peer)
                     (< count +inv-broadcast-target+))
          do (destructuring-bind (txid wtxid fee-rate-per-kb)
                 (pop (peer-tx-inv-queue peer))
               (when (and (not (bitcoin-lisp:recent-reject-p
                                (peer-announced-txs peer) txid))
                          ;; Evicted/confirmed since queueing => nothing to announce.
                          (or (null mempool)
                              (bitcoin-lisp.mempool:mempool-has mempool txid))
                          ;; BIP 133 feefilter, evaluated at flush time.
                          (or (zerop (peer-feefilter-rate peer))
                              (>= fee-rate-per-kb (peer-feefilter-rate peer))))
                 (bitcoin-lisp:add-recent-reject (peer-announced-txs peer) txid)
                 (incf count)
                 (push (if (and (peer-wtxid-relay peer) wtxid)
                           (bitcoin-lisp.serialization:make-inv-vector
                            :type bitcoin-lisp.serialization:+inv-type-wtx+
                            :hash wtxid)
                           (bitcoin-lisp.serialization:make-inv-vector
                            :type bitcoin-lisp.serialization:+inv-type-tx+
                            :hash txid))
                       invs))))
    (when invs
      ;; A dead socket raises from the write; the drain/health passes own
      ;; disconnecting — just stop announcing to it this round.
      (handler-case
          (send-message peer (bitcoin-lisp.serialization:make-inv-message
                              (nreverse invs)))
        (error () nil)))
    ;; Snapshot the mempool sequence: everything in the pool right now was
    ;; announceable in this flush, so getdata for it is legitimate from here
    ;; on (Core SendMessages, net_processing.cpp:6086-6088 — updated on every
    ;; trickle flush, sent invs or not). This is what FindTxForGetData's
    ;; anti-probing gate compares against.
    (when mempool
      (setf (peer-last-inv-sequence peer)
            (bitcoin-lisp.mempool:mempool-sequence mempool)))))

(defun flush-tx-announcements (peers mempool)
  "Flush due per-peer tx announcement queues (call ~1x/second from the
sync loop). Outbound peers each run an exponential timer with mean
+outbound-inv-broadcast-interval+; all inbound peers flush together on
the shared *next-inbound-inv-flush* rotation with mean
+inbound-inv-broadcast-interval+ — Core net_processing.cpp:5980-5990.
Holds the node lock: the queues are also written by the RPC broadcast
path (sendrawtransaction/submitpackage), which enqueues under the same
lock from RPC handler threads."
  (with-node-lock
    (let ((now (get-internal-real-time))
          (inbound-due nil))
      ;; Shared inbound rotation.
      (cond ((zerop *next-inbound-inv-flush*)
             (setf *next-inbound-inv-flush*
                   (+ now (%next-exp-interval-ticks +inbound-inv-broadcast-interval+))))
            ((>= now *next-inbound-inv-flush*)
             (setf inbound-due t
                   *next-inbound-inv-flush*
                   (+ now (%next-exp-interval-ticks +inbound-inv-broadcast-interval+)))))
      (dolist (peer peers)
        (when (and (eq (peer-state peer) :ready)
                   ;; fRelay=0 peers have no tx-relay state: no inv flushes,
                   ;; and no last-inv-sequence advance either (their getdata
                   ;; is ignored outright anyway).
                   (peer-tx-relay-p peer))
          (if (peer-inbound peer)
              (when inbound-due
                (%flush-peer-tx-invs peer mempool))
              (cond ((zerop (peer-next-inv-send-time peer))
                     (setf (peer-next-inv-send-time peer)
                           (+ now (%next-exp-interval-ticks
                                   +outbound-inv-broadcast-interval+))))
                    ((>= now (peer-next-inv-send-time peer))
                     (setf (peer-next-inv-send-time peer)
                           (+ now (%next-exp-interval-ticks
                                   +outbound-inv-broadcast-interval+)))
                     (%flush-peer-tx-invs peer mempool)))))))))

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
  (let ((entry (and mempool (bitcoin-lisp.mempool:mempool-get mempool txid))))
    (when entry
      (let ((vsize (bitcoin-lisp.mempool:mempool-entry-vsize entry))
            (fee (bitcoin-lisp.mempool:mempool-entry-fee entry)))
        (relay-transaction txid nil peers
                           :fee-rate (if (plusp vsize) (floor fee vsize) 0)
                           :wtxid (bitcoin-lisp.mempool:mempool-entry-wtxid entry)))
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
  "internal-real-time deadline of the next unbroadcast re-announcement pass;
0 = not yet scheduled (armed on the first maybe- call, matching Core's
initial scheduleFromNow a full interval out, net_processing.cpp:2036-2038).")

(defun %next-initial-broadcast-ticks ()
  (+ (* +initial-broadcast-interval+ internal-time-units-per-second)
     (random (* +initial-broadcast-jitter+ internal-time-units-per-second))))

(defun reset-initial-broadcast-schedule ()
  "Clear the re-announcement deadline (called at node start, alongside
reset-tx-requests) so the first pass re-arms fresh."
  (setf *next-initial-broadcast-time* 0))

(defun reattempt-initial-broadcast (peers mempool)
  "Re-announce every unbroadcast tx still in the mempool to the current
relay peers; drop the ids of txs that have left the pool (Core
PeerManagerImpl::ReattemptInitialBroadcast, net_processing.cpp:1625-1643).
Because each peer's known filter suppresses re-queueing, this mostly
reaches peers connected since the original announcement."
  (dolist (txid (bitcoin-lisp.mempool:mempool-unbroadcast-txids mempool))
    (unless (announce-mempool-tx peers mempool txid)
      (bitcoin-lisp.mempool:mempool-remove-unbroadcast mempool txid))))

(defun maybe-reattempt-initial-broadcast (peers mempool)
  "Run the unbroadcast re-announcement pass when due (call ~1x/second from
the sync loop, our stand-in for Core's scheduler). Each cycle — including
the first — is scheduled 10min + rand(5min) out."
  (when mempool
    (let ((now (get-internal-real-time)))
      (cond ((zerop *next-initial-broadcast-time*)
             (setf *next-initial-broadcast-time*
                   (+ now (%next-initial-broadcast-ticks))))
            ((>= now *next-initial-broadcast-time*)
             (setf *next-initial-broadcast-time*
                   (+ now (%next-initial-broadcast-ticks)))
             (with-node-lock
               (reattempt-initial-broadcast peers mempool)))))))

(defun block-relay-targets (source-peer peers)
  "The peers a newly-connected block is announced to: every ready peer except
SOURCE-PEER (which already has it)."
  (remove-if (lambda (p)
               (or (eq p source-peer)
                   (not (eq (peer-state p) :ready))))
             peers))

(defun relay-block (header source-peer peers)
  "Announce a newly-connected best-tip block to PEERS except SOURCE-PEER.
BIP 130: peers that sent sendheaders get a headers message (the cheaper
announcement Core prefers); the rest get an inv. Gated on relay-enabled-p so a
relay-disabled node (mainnet default) stays a non-participant. Without this the
node validates blocks but never propagates them — a pure block sink.
Deliberately NOT gated on -blocksonly: blocksonly is a TX-relay switch only;
Core relays blocks normally under it."
  (unless (relay-enabled-p)
    (return-from relay-block nil))
  (let ((headers-msg (bitcoin-lisp.serialization:make-headers-message (list header)))
        (inv-msg (bitcoin-lisp.serialization:make-inv-message
                  (list (bitcoin-lisp.serialization:make-inv-vector
                         :type bitcoin-lisp.serialization:+inv-type-block+
                         :hash (bitcoin-lisp.serialization:block-header-hash header))))))
    (dolist (peer (block-relay-targets source-peer peers))
      (handler-case
          (if (peer-prefers-headers peer)
              (send-message peer headers-msg)
              (send-message peer inv-msg))
        (error () nil)))))

;;; Sync operations

(defun request-headers (peer chain-state)
  "Request headers from a peer starting from our current tip."
  (let ((locator (bitcoin-lisp.storage:build-block-locator chain-state)))
    (send-message peer
                  (bitcoin-lisp.serialization:make-getheaders-message locator))))

(defun request-blocks (peer block-hashes)
  "Request specific blocks from a peer using MSG_WITNESS_BLOCK
so peers include witness data in the response."
  (let ((inv-vectors (mapcar (lambda (hash)
                               (bitcoin-lisp.serialization:make-inv-vector
                                :type bitcoin-lisp.serialization:+inv-type-witness-block+
                                :hash hash))
                             block-hashes)))
    (send-message peer
                  (bitcoin-lisp.serialization:make-getdata-message inv-vectors))))

;;; Main sync loop

(defun sync-with-peer (peer chain-state utxo-set block-store
                       &key (max-blocks 500) fee-estimator recent-rejects)
  "Synchronize blockchain with a peer.
Downloads headers and blocks up to MAX-BLOCKS."
  (unless (eq (peer-state peer) :ready)
    (return-from sync-with-peer nil))

  ;; Request headers
  (request-headers peer chain-state)

  (let ((blocks-received 0))
    (loop while (< blocks-received max-blocks)
          do (multiple-value-bind (command payload)
                 (receive-message-blocking peer :timeout 60)
               (unless command
                 (return-from sync-with-peer blocks-received))
               (handle-message peer command payload
                               chain-state utxo-set block-store
                               :fee-estimator fee-estimator
                               :recent-rejects recent-rejects)
               (when (string= command "block")
                 (incf blocks-received))))
    blocks-received))

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
  (send-message peer (bitcoin-lisp.serialization:make-sendcmpct-message
                      nil +compact-blocks-version+)))

(defun %set-peer-hb (peer high-bandwidth)
  (setf (peer-compact-block-high-bandwidth-to peer) high-bandwidth)
  (send-message peer (bitcoin-lisp.serialization:make-sendcmpct-message
                      high-bandwidth +compact-blocks-version+)))

(defun %hb-peer-live-p (peer)
  "T while PEER is still a peer we could actually ask to announce blocks.

Core reaches its HB list entries by NodeId — GetPeerRef (net_processing.cpp:1296)
and ForNode (:1310) — so an entry whose peer has gone away simply resolves to
nothing: it counts as NEITHER inbound nor outbound in the census (:1297), can
never be the protected front (:1303-1305), and a promotion targeting a gone
node mutates nothing at all (ForNode returns without running the lambda). We
hold the peer STRUCT rather than an id, so nothing resolves to nothing for us
and we have to ask the struct: :disconnected / :banned is our \"gone\"."
  (not (member (peer-state peer) '(:disconnected :banned))))

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

(defun handle-sendcmpct (peer payload)
  "Handle a sendcmpct message from a peer. We support only compact block version 2;
any other version is ignored entirely, mirroring Bitcoin Core
(net_processing.cpp: `if (sendcmpct_version != CMPCTBLOCKS_VERSION) return;`). A
v1 compact block would deliver a witness-stripped coinbase."
  (multiple-value-bind (high-bandwidth version)
      (bitcoin-lisp.serialization:parse-sendcmpct-payload payload)
    (when (= version +compact-blocks-version+)
      (setf (peer-compact-block-version peer) version)
      ;; Track high-bandwidth mode preference
      (when high-bandwidth
        (setf (peer-compact-block-high-bandwidth peer) t)))
    (bitcoin-lisp:log-debug "Peer ~A sendcmpct v~D (high-bw: ~A)"
                            (peer-address peer) version high-bandwidth)))

;;; IBD check

(defun should-use-compact-blocks-p (peer)
  "Return T if we should request compact blocks from PEER.
   Returns NIL during IBD or if peer doesn't support compact blocks."
  (and (> (peer-compact-block-version peer) 0)  ; Peer supports CB
       (not (eq (ibd-state) :syncing-blocks))   ; Not downloading blocks in IBD
       (not (eq (ibd-state) :syncing-headers)))) ; Not syncing headers

;;; Short ID map building

(defun build-shortid-map (mempool k0 k1 use-wtxid)
  "Build hash table mapping short IDs to (tx . expected-id) pairs.
   USE-WTXID is true for compact block version 2.
   Returns (VALUES map collision-detected).
   The map stores cons cells of (transaction . full-txid-or-wtxid) for verification."
  (let ((map (make-hash-table :test 'eql))
        (collision nil))
    (bitcoin-lisp.mempool:mempool-for-each
     mempool
     (lambda (txid entry)
       (let* ((tx (bitcoin-lisp.mempool:mempool-entry-transaction entry))
              (id (if use-wtxid
                      (bitcoin-lisp.serialization:transaction-wtxid tx)
                      txid))
              (short-id (bitcoin-lisp.crypto:compute-short-txid k0 k1 id)))
         ;; Detect collisions within mempool
         (when (gethash short-id map)
           (setf collision t))
         ;; Store tx with its full ID for later verification
         (setf (gethash short-id map) (cons tx id)))))
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
send (no transactions at all, an absurd transaction count, a prefilled index
outside the block, fewer short IDs than empty slots) — and Core answers it with
Misbehaving (net_processing.cpp:4680-4683). :COLLISION is READ_STATUS_FAILED —
two of OUR OWN mempool transactions sharing a short ID, which is nobody's
fault — and Core answers it with a plain full-block getdata (:4683-4694)."
  (let* ((header (bitcoin-lisp.serialization:compact-block-header compact-block))
         (nonce (bitcoin-lisp.serialization:compact-block-nonce compact-block))
         (short-ids-list (bitcoin-lisp.serialization:compact-block-short-ids compact-block))
         (prefilled (bitcoin-lisp.serialization:compact-block-prefilled-txs compact-block))
         (tx-count (+ (length short-ids-list) (length prefilled)))
         (header-bytes (bitcoin-lisp.serialization:serialize-block-header header))
         ;; Convert short-ids list to vector for O(1) access
         (short-ids (coerce short-ids-list 'vector)))

    ;; Validate tx-count is reasonable (prevent DoS). Core InitData's first two
    ;; guards, both READ_STATUS_INVALID (blockencodings.cpp:62-66).
    (when (or (zerop tx-count) (> tx-count 100000))
      (bitcoin-lisp:log-warn "Invalid compact block tx count: ~D" tx-count)
      (return-from reconstruct-compact-block (values nil :malformed)))

    ;; Compute SipHash keys
    (multiple-value-bind (k0 k1)
        (bitcoin-lisp.crypto:compute-siphash-key header-bytes nonce)

      ;; Build short ID map from mempool
      (multiple-value-bind (shortid-map collision)
          (build-shortid-map mempool k0 k1 use-wtxid)

        ;; Check for collision within mempool
        (when collision
          (increment-compact-block-collision)
          (bitcoin-lisp:log-warn "Short ID collision detected in mempool, falling back to full block")
          (return-from reconstruct-compact-block (values nil :collision nil)))

        (let ((transactions (make-array tx-count :initial-element nil))
              (missing-indexes '())
              (short-id-idx 0))

          ;; Place prefilled transactions at their absolute indexes
          ;; with bounds checking
          (dolist (ptx prefilled)
            (let ((idx (bitcoin-lisp.serialization:prefilled-tx-index ptx)))
              (if (and (>= idx 0) (< idx tx-count))
                  (setf (aref transactions idx)
                        (bitcoin-lisp.serialization:prefilled-tx-transaction ptx))
                  (progn
                    ;; Core's lastprefilledindex bounds check, READ_STATUS_INVALID
                    ;; (blockencodings.cpp:78-84).
                    (bitcoin-lisp:log-warn "Prefilled tx index out of bounds: ~D (max ~D)"
                                           idx (1- tx-count))
                    (return-from reconstruct-compact-block (values nil :malformed nil))))))

          ;; Fill remaining slots with mempool transactions matched by short ID
          (dotimes (i tx-count)
            (when (null (aref transactions i))
              ;; This slot needs a transaction from short IDs
              (when (>= short-id-idx (length short-ids))
                ;; More empty slots than short IDs — a slot with neither a
                ;; prefilled tx nor a short ID. READ_STATUS_INVALID in Core
                ;; (blockencodings.cpp:80-84).
                (bitcoin-lisp:log-warn "Short ID count mismatch")
                (return-from reconstruct-compact-block (values nil :malformed nil)))
              (let* ((short-id (aref short-ids short-id-idx))
                     (tx-pair (gethash short-id shortid-map)))
                (if tx-pair
                    (let ((tx (car tx-pair))
                          (full-id (cdr tx-pair)))
                      ;; Verify the matched tx produces the expected short ID
                      ;; (guards against hash collisions between mempool and block)
                      (let ((computed-short-id (bitcoin-lisp.crypto:compute-short-txid
                                                k0 k1 full-id)))
                        (if (= computed-short-id short-id)
                            (setf (aref transactions i) tx)
                            ;; Collision between different transactions
                            (push i missing-indexes))))
                    (push i missing-indexes))
                (incf short-id-idx))))

          (if missing-indexes
              (values nil (nreverse missing-indexes) transactions)
              (values (bitcoin-lisp.serialization:make-bitcoin-block
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

(defparameter +compact-block-punished-reasons+
  '(:bad-proof-of-work :bad-difficulty :bad-version :time-too-old
    :time-timewarp-attack :bad-prevblk)
  "Validation verdicts Core punishes even when via_compact_block is true.

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

(defparameter +compact-block-ignored-reasons+
  '(:time-too-new :duplicate-invalid)
  "Verdicts that end a compact block with neither punishment NOR a refetch.

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
    (bitcoin-lisp:log-warn "~A ~A: ~(~A~) — ~(~A~)"
                           context (bitcoin-lisp.crypto:bytes-to-hex block-hash)
                           reason action)
    (ecase action
      (:punish (increment-compact-block-failure)
               (record-misbehavior peer (format nil "~A (~(~A~))" context reason)))
      (:ignore (increment-compact-block-failure))
      (:refetch (request-full-block peer block-hash)))
    action))

(defun compact-block-header-verdict (chain-state header block-hash prev-hash)
  "Core's ProcessNewBlockHeaders({{cmpctblock.header}}) step, run BEFORE any
reconstruction (net_processing.cpp:4571-4593). Returns
(VALUES VERDICT REASON CREDITS-ANNOUNCEMENT):

  :NO-PARENT — parent absent from the index; the caller answers with getheaders
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

Order mirrors AcceptBlockHeader (validation.cpp:4226-4259): a header we already
hold short-circuits (BLOCK_CACHED_INVALID when we marked it invalid, otherwise
accepted without re-checking), then CheckBlockHeader's PoW, then the parent's
own validity, then ContextualCheckBlockHeader. Doing this before the mempool is
touched is what makes an invalid header cheap for us and expensive for nobody:
BUILD-SHORTID-MAP hashes the whole mempool under a key derived from the
attacker's header, so it must not run for a header we are going to reject.

Pure reads of the block index — the caller holds the node lock across it and
does the IO (getheaders / getdata / disconnect) outside."
  (let ((known (bitcoin-lisp.storage:get-block-index-entry chain-state block-hash))
        (prev-entry (bitcoin-lisp.storage:get-block-index-entry chain-state prev-hash)))
    (cond
      ;; Already-known header. Core returns true early for it, except when we
      ;; marked it invalid: BLOCK_CACHED_INVALID (validation.cpp:4229-4237).
      ((and known (eq (bitcoin-lisp.storage:block-index-entry-status known) :invalid))
       (values :reject :duplicate-invalid))
      ;; Already in the index: accepted, but received_new_header is false, so
      ;; no announcement credit however much work it carries.
      (known (values :accept nil nil))
      ;; Parent not in the index: the announcement outran our header chain.
      ;; The ORDINARY case, not an attack — high-bandwidth compact relay beats
      ;; headers announcements by design, so falling one block behind while a
      ;; getblocktxn round-trip is in flight is enough. Core asks for deeper
      ;; headers and returns before anything can be DoS-scored (:4571-4577);
      ;; reconstructing instead would hand ACCEPT-DOWNLOADED-BLOCK a block whose
      ;; parent entry is missing, i.e. :ORPHAN-BLOCK, and permanently exile our
      ;; fastest honest block-relay peer.
      ((null prev-entry) (values :no-parent nil))
      ;; Building on a block we rejected: BLOCK_INVALID_PREV (validation.cpp:
      ;; 4251-4255), punished regardless of via_compact_block.
      ((eq (bitcoin-lisp.storage:block-index-entry-status prev-entry) :invalid)
       (values :reject :bad-prevblk))
      (t
       ;; CheckBlockHeader + ContextualCheckBlockHeader at the header's own
       ;; branch height — PoW, MTP, BIP94 timewarp, softfork version floor and
       ;; the difficulty bits. Identical to the header battery VALIDATE-BLOCK
       ;; runs later, so this rejects nothing we would have accepted; it only
       ;; moves the verdict ahead of the mempool pass and makes it punishable.
       (multiple-value-bind (valid reason)
           (bitcoin-lisp.validation:validate-block-header
            header chain-state (bitcoin-lisp.serialization:get-unix-time)
            :prev-hash prev-hash
            :height (1+ (bitcoin-lisp.storage:block-index-entry-height prev-entry))
            :prev-entry prev-entry)
         (if valid
             (values :accept nil
                     ;; KNOWN is NIL on this branch, so received_new_header
                     ;; holds; all that remains is the work comparison. The
                     ;; header is not in the index yet (this function is pure
                     ;; reads), so its work is computed the way Core computes
                     ;; it a few lines earlier for the anti-DoS floor (:4578):
                     ;; the parent's work plus this header's own proof.
                     (let* ((tip-hash (bitcoin-lisp.storage:best-block-hash chain-state))
                            (tip (and tip-hash
                                      (bitcoin-lisp.storage:get-block-index-entry
                                       chain-state tip-hash))))
                       (and tip
                            (> (bitcoin-lisp.storage:calculate-chain-work
                                (bitcoin-lisp.serialization:block-header-bits header)
                                (bitcoin-lisp.storage:block-index-entry-chain-work
                                 prev-entry))
                               (bitcoin-lisp.storage:block-index-entry-chain-work tip)))))
             (values :reject reason)))))))

(defun handle-cmpctblock (peer payload chain-state utxo-set block-store mempool
                          &optional fee-estimator &key recent-rejects)
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
  (let* ((compact-block (bitcoin-lisp.serialization:parse-cmpctblock-payload payload))
         (header (bitcoin-lisp.serialization:compact-block-header compact-block))
         (block-hash (bitcoin-lisp.serialization:block-header-hash header))
         (prev-hash (bitcoin-lisp.serialization:block-header-prev-block header))
         (use-wtxid (= (peer-compact-block-version peer) 2)))

    ;; Header gate, ahead of everything else — including the stale-pending
    ;; clear below, so an announcement we are about to drop cannot destroy an
    ;; in-flight reconstruction of the block we are actually missing (Core
    ;; keeps per-block in-flight state, so it has no such cross-talk).
    (multiple-value-bind (verdict reason credits-announcement)
        (with-node-lock
          (compact-block-header-verdict chain-state header block-hash prev-hash))
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
        (:no-parent
         (bitcoin-lisp:log-cat "net"
                               "cmpctblock ~A: parent ~A not in index — getheaders to ~A"
                               (bitcoin-lisp.crypto:bytes-to-hex block-hash)
                               (bitcoin-lisp.crypto:bytes-to-hex prev-hash)
                               (peer-address peer))
         ;; Core gates the getheaders on !IsInitialBlockDownload(): during IBD
         ;; the header sync owns the locator and an extra request is noise.
         (unless (initial-block-download-p chain-state)
           (request-headers-for-ibd peer chain-state))
         (return-from handle-cmpctblock nil))
        (:reject
         (handle-compact-block-failure peer block-hash reason
                                       "invalid header via cmpctblock")
         (return-from handle-cmpctblock nil))))

    ;; Clear any old pending reconstruction for different block
    (when (peer-pending-compact-block peer)
      (let ((pending-hash (pending-compact-block-block-hash
                           (peer-pending-compact-block peer))))
        (unless (equalp pending-hash block-hash)
          (setf (peer-pending-compact-block peer) nil))))

    ;; NOTE: a dedup guard used to sit here testing
    ;; (eq (block-index-entry-status entry) :connected). :CONNECTED is not in
    ;; the status enum (storage/chain.lisp:17 — :unknown / :header-valid /
    ;; :valid / :invalid), so it could never fire and was deleted: a guard that
    ;; cannot fire is worse than none, because it reads as protection that is
    ;; not there. Core's real dedup is
    ;; `pindex->nChainWork <= tip->nChainWork || pindex->nTx != 0'
    ;; (net_processing.cpp, CMPCTBLOCK handler), which also wants the
    ;; unknown-parent getheaders answer next to it; both belong to the wave-4
    ;; compact-block item in docs/gap-analysis-8-plan.md. What the missing
    ;; dedup must NOT be relied on for is HB selection — that is gated below on
    ;; the block actually connecting, not on it being new to us.

    ;; Attempt reconstruction
    (multiple-value-bind (block missing-indexes partial-transactions)
        (reconstruct-compact-block compact-block mempool use-wtxid)

      (cond
        ;; Successful reconstruction
        (block
         (increment-compact-block-success)
         ;; A reconstructed compact block is a block delivery from this peer:
         ;; stamps getpeerinfo "last_block" and resets stall tracking.
         (record-block-received-from-peer peer)
         (bitcoin-lisp:log-debug "Compact block reconstructed successfully")
         ;; Process like a normal block (fork-aware: a reconstructed block on a
         ;; side branch is stored and reorged, not tip-validated).
         (let ((connected
                 (with-node-lock
                   (let ((tip-before (bitcoin-lisp.storage:best-block-hash chain-state)))
                     (multiple-value-bind (valid error)
                         (accept-downloaded-block block chain-state utxo-set block-store
                                                  :mempool mempool
                                                  :fee-estimator fee-estimator
                                                  :recent-rejects recent-rejects)
                       (unless valid
                         (handle-compact-block-failure peer block-hash error
                                                       "reconstructed compact block invalid"))
                       (and valid
                            (%block-newly-connected-p chain-state block-hash
                                                      tip-before)))))))
           ;; Earned HB promotion — only once the block CONNECTED, never on
           ;; acceptance alone (Core BlockChecked's valid state comes from
           ;; ConnectTip; an invalid block goes to MaybePunishNodeForBlock, and
           ;; a block we already have never reaches ConnectTip at all). Outside
           ;; the node lock: promotion writes sendcmpct to up to two sockets.
           (when connected
             (maybe-promote-block-deliverer peer chain-state))))

        ;; Structurally malformed message — Core READ_STATUS_INVALID ->
        ;; Misbehaving (net_processing.cpp:4679-4683). This is the one
        ;; compact-block shape an honest peer cannot produce.
        ((eq missing-indexes :malformed)
         (increment-compact-block-failure)
         (record-misbehavior peer "invalid compact block"))

        ;; Short-ID collision in OUR mempool — nobody's fault, fall back to the
        ;; full block (Core READ_STATUS_FAILED, net_processing.cpp:4683-4694).
        ((eq missing-indexes :collision)
         (request-full-block peer block-hash))

        ;; Missing transactions - request them
        (missing-indexes
         (bitcoin-lisp:log-debug "Compact block missing ~D transactions, requesting"
                                 (length missing-indexes))
         ;; Store pending state using the partial transactions from reconstruction
         (setf (peer-pending-compact-block peer)
               (make-pending-compact-block
                :block-hash block-hash
                :header header
                :transactions partial-transactions
                :missing-indexes missing-indexes
                :request-time (get-internal-real-time)
                :use-wtxid use-wtxid))
         ;; Send getblocktxn request
         (send-message peer
                       (bitcoin-lisp.serialization:make-getblocktxn-message
                        block-hash missing-indexes)))))))

(defun handle-blocktxn (peer payload chain-state utxo-set block-store mempool
                        &optional fee-estimator &key recent-rejects)
  "Handle a blocktxn message. Complete pending block reconstruction.

Same per-reason punishment rule as HANDLE-CMPCTBLOCK: the completed block is a
compact-block delivery (mapBlockSource ... /*punish=*/false,
net_processing.cpp:3516, inverted at :2211), so its verdict goes through
COMPACT-BLOCK-FAILURE-ACTION — the BLOCK_CONSENSUS / BLOCK_MUTATED class earns
a full-block refetch and no discouragement, while the header-invalid class
would still punish (it cannot normally arrive here: HANDLE-CMPCTBLOCK gated the
same header before sending the getblocktxn). A blocktxn that does not answer
the getblocktxn we sent — Core's READ_STATUS_INVALID from FillBlock — is
punished outright (:3487-3491)."
  (let ((response (bitcoin-lisp.serialization:parse-blocktxn-payload payload))
        (pending (peer-pending-compact-block peer)))

    (unless pending
      (bitcoin-lisp:log-debug "Received blocktxn but no pending reconstruction")
      (return-from handle-blocktxn nil))

    (let ((block-hash (bitcoin-lisp.serialization:block-txn-response-block-hash response))
          (txs (bitcoin-lisp.serialization:block-txn-response-transactions response)))

      ;; Verify block hash matches
      (unless (equalp block-hash (pending-compact-block-block-hash pending))
        (bitcoin-lisp:log-warn "blocktxn hash mismatch")
        (return-from handle-blocktxn nil))

      ;; Insert missing transactions
      (let ((transactions (pending-compact-block-transactions pending))
            (missing-indexes (pending-compact-block-missing-indexes pending)))
        ;; A blocktxn that does not deliver exactly the transactions we asked
        ;; for is structurally malformed: Core's FillBlock returns
        ;; READ_STATUS_INVALID for both too few and too many
        ;; (blockencodings.cpp:198-217) and the peer is punished
        ;; (net_processing.cpp:3487-3491).
        (when (/= (length txs) (length missing-indexes))
          (bitcoin-lisp:log-warn "blocktxn transaction count mismatch")
          (setf (peer-pending-compact-block peer) nil)
          (increment-compact-block-failure)
          (record-misbehavior peer
                              "invalid compact block/non-matching block transactions")
          (return-from handle-blocktxn nil))

        (loop for tx in txs
              for idx in missing-indexes
              do (setf (aref transactions idx) tx))

        ;; Build complete block
        (let ((block (bitcoin-lisp.serialization:make-bitcoin-block
                      :header (pending-compact-block-header pending)
                      :transactions (coerce transactions 'list))))
          ;; Clear pending state
          (setf (peer-pending-compact-block peer) nil)

          ;; Validate and connect
          (increment-compact-block-success)
          ;; Block delivery from this peer (getpeerinfo "last_block").
          (record-block-received-from-peer peer)
          (let ((connected
                  (with-node-lock
                    (let ((tip-before (bitcoin-lisp.storage:best-block-hash chain-state)))
                      (multiple-value-bind (valid error)
                          (accept-downloaded-block block chain-state utxo-set block-store
                                                   :mempool mempool
                                                   :fee-estimator fee-estimator
                                                   :recent-rejects recent-rejects)
                        (unless valid
                          (handle-compact-block-failure peer block-hash error
                                                        "completed compact block invalid"))
                        (and valid
                             (%block-newly-connected-p chain-state block-hash
                                                       tip-before)))))))
            ;; HB promotion only once the completed block CONNECTED (Core
            ;; BlockChecked's valid state is emitted from ConnectTip), never on
            ;; delivery or bare acceptance.
            (when connected
              (maybe-promote-block-deliverer peer chain-state))))))))

(defun request-full-block (peer block-hash)
  "Request a full block (fallback from compact block)."
  (increment-compact-block-failure)
  (send-message peer
                (bitcoin-lisp.serialization:make-getdata-message
                 (list (bitcoin-lisp.serialization:make-inv-vector
                        :type bitcoin-lisp.serialization:+inv-type-witness-block+
                        :hash block-hash)))))

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
          (bitcoin-lisp:log-warn "Compact block reconstruction timed out")
          (let ((block-hash (pending-compact-block-block-hash pending)))
            (setf (peer-pending-compact-block peer) nil)
            (request-full-block peer block-hash)))))))

(defun clear-pending-compact-block (peer)
  "Clear any pending compact block reconstruction for PEER."
  (setf (peer-pending-compact-block peer) nil))

;;; Compact block metrics

(defun compact-block-stats ()
  "Return compact block reconstruction statistics (thread-safe read)."
  (bt:with-lock-held (*compact-block-metrics-lock*)
    (list :successes *compact-block-success-count*
          :failures *compact-block-failure-count*
          :collisions *compact-block-collision-count*)))
