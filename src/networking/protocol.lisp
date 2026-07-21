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
     (handle-getblocktxn peer payload block-store)
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

(defun %already-have-tx-p (hash wtxidp mempool recent-rejects)
  "Core AlreadyHaveTx (txdownloadman_impl.cpp:126-148): the orphanage (HASH
cast to a wtxid — never a real txid lookup, witness malleation makes txid
matches unreliable; for non-segwit txs txid == wtxid so the cast still finds
them), the recent-confirmed filter, recent rejects, and the mempool by the id
the announcement implies."
  (or (bitcoin-lisp.mempool:orphan-have
       (bitcoin-lisp.mempool:mempool-orphan-pool mempool) hash)
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
                   ((%already-have-tx-p hash wtxidp mempool recent-rejects)
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
             (bitcoin-lisp.validation:connect-block
              block chain-state block-store utxo-set
              :fee-estimator fee-estimator
              :recent-rejects recent-rejects
              :mempool mempool)))
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

(defun handle-block (peer payload chain-state utxo-set block-store
                     &optional mempool fee-estimator &key recent-rejects peers)
  "Handle a block message. When PEERS is supplied and the block becomes the new
active tip, announce it onward (BIP 130 headers / inv), so the node propagates
blocks instead of being a sink."
  (let ((block (bitcoin-lisp.serialization:parse-block-payload payload)))
    (when block
      (with-node-lock
        (let* ((header (bitcoin-lisp.serialization:bitcoin-block-header block))
               (hash (bitcoin-lisp.serialization:block-header-hash header)))
          (multiple-value-bind (valid error)
              (accept-downloaded-block block chain-state utxo-set block-store
                                       :mempool mempool
                                       :fee-estimator fee-estimator
                                       :recent-rejects recent-rejects)
            (if valid
                ;; Announce onward only if this block is now the active tip
                ;; (accept may have stored a side block or reorged).
                (when (and peers
                           (equalp (bitcoin-lisp.storage:best-block-hash chain-state)
                                   hash))
                  (relay-block header peer peers))
                (progn
                  (bitcoin-lisp:log-warn "Block ~A rejected: ~A"
                                         (bitcoin-lisp.crypto:bytes-to-hex hash) error)
                  (record-misbehavior peer "invalid block")))))))))

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

(defun peer-source-group (peer)
  "Net-group key of PEER's own address, for addrman source bucketing (Core
AddrMan::Add's source argument) — network-typed, so onion/i2p/cjdns peers
get their proper source groups. NIL for hostname peers (addnode by name)."
  (multiple-value-bind (net bytes) (parse-network-address (peer-address peer))
    (when net (net-group-key bytes net))))

(defun %ingest-gossiped-address (net-addr timestamp address-book source-group now)
  "Shared addr/addrv2 ingestion for one gossiped NET-ADDR (Core's per-address
loop in the ADDR handler, net_processing.cpp:4056-4098) learned from a peer
with net-group key SOURCE-GROUP. Stores it in ADDRESS-BOOK only when its
network is REACHABLE (-onlynet; Core \"Do not store addresses outside our
network\"), but fresh (10-min) ROUTABLE addresses are relay candidates
regardless — an unreachable-net address still relays, just to 1 peer instead
of 2 (Core RelayAddress fReachable). Returns (VALUES stored relay-entry):
STORED is 1/0 for the caller's log count, RELAY-ENTRY a
(peer-address . max-targets) cons when the address should be gossiped onward."
  (unless (and address-book timestamp
               (<= (abs (- now timestamp)) (* 3 3600)))
    (return-from %ingest-gossiped-address (values 0 nil)))
  (let* ((pa (make-peer-address
              :net (bitcoin-lisp.serialization:net-addr-net net-addr)
              :ip (bitcoin-lisp.serialization:net-addr-ip net-addr)
              :port (bitcoin-lisp.serialization:net-addr-port net-addr)
              :services (bitcoin-lisp.serialization:net-addr-services net-addr)
              :last-seen timestamp))
         (network (peer-address-network pa))
         (reachable (reachable-network-p network)))
    (when reachable
      (address-book-add address-book pa source-group))
    (values (if reachable 1 0)
            ;; Core relays only fresh (10-min) routable addrs.
            (when (and (> timestamp (- now 600))
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
  (let* ((now (bitcoin-lisp.serialization:get-unix-time))
         (source-group (when peer (peer-source-group peer)))
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
                                       address-book source-group now)
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
    added))

(defun handle-addr (peer payload &optional address-book peers)
  "Handle an addr message. When ADDRESS-BOOK is provided, add plausible
addresses (timestamp within last 3 hours) on reachable networks to the address
book, keyed to the gossiping PEER as their source (addrman source-group
spreading), subject to the per-address token bucket (see
%process-gossiped-addresses). Ignored entirely from a block-relay-only peer
(Core SetupAddressRelay, net_processing.cpp:4041); more than 1000 announced
addresses is misbehavior (net_processing.cpp:4046-4050)."
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
addresses of any representable network (IPv4/IPv6/TORv3/I2P/CJDNS) with
plausible timestamps (within 3 hours) to the address book — non-IP networks
only when reachable (-onlynet + proxy/flag gates), subject to the per-address
token bucket (see %process-gossiped-addresses). Unknown network ids were
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
                       (when recent-rejects
                         ;; Same insertion rules as handle-tx — Core routes
                         ;; orphan re-validation failures through the same
                         ;; MempoolRejectedTx (txdownloadman_impl.cpp:438-484):
                         ;; wtxid-keyed (witness malleability — Core issue
                         ;; #8279), nothing at all for a witness-stripped
                         ;; failure (wtxid == txid there — caching would poison
                         ;; the real tx's txid), plus the txid for
                         ;; :nonstandard-inputs (txid-only failure).
                         (unless (eq error :witness-stripped)
                           (bitcoin-lisp:add-recent-reject recent-rejects owtxid)
                           (when (and (eq error :nonstandard-inputs)
                                      (not (equalp owtxid otxid)))
                             (bitcoin-lisp:add-recent-reject recent-rejects otxid)))))))))))))))

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
              ;; Validate for mempool
              (multiple-value-bind (valid error fee replaced sigops)
                  (bitcoin-lisp.validation:validate-transaction-for-mempool
                   tx utxo-set mempool current-height :chain-state chain-state)
                (unless valid
                  (cond
                    ;; Missing inputs => hold as an orphan (not a real reject);
                    ;; a later parent will trigger re-evaluation. Request the
                    ;; missing parents from this peer so they arrive sooner.
                    ;; UNLESS a missing parent was itself recently rejected:
                    ;; then this tx can never be accepted regardless of what
                    ;; parent data arrives, so reject it outright — under BOTH
                    ;; ids, exactly like Core's "not keeping orphan with
                    ;; rejected parents" (txdownloadman_impl.cpp:422-436;
                    ;; the txid too, so non-wtxidrelay peers can't make us
                    ;; re-download it).
                    ((eq error :missing-input)
                     (let ((parents (missing-parent-txids tx utxo-set mempool)))
                       (if (some (lambda (ptxid)
                                   (bitcoin-lisp:recent-reject-p recent-rejects ptxid))
                                 parents)
                           (progn
                             (bitcoin-lisp:add-recent-reject recent-rejects txid)
                             (bitcoin-lisp:add-recent-reject recent-rejects wtxid))
                           (progn
                             (bitcoin-lisp.mempool:orphan-add
                              (bitcoin-lisp.mempool:mempool-orphan-pool mempool) tx peer)
                             (request-orphan-parents
                              peer parents (count-wtxid-relay-peers peers))))))
                    (t
                     ;; Add to recent rejects so we don't re-request it. A loose
                     ;; transaction that fails validation is NOT misbehavior:
                     ;; Bitcoin Core removed tx-relay punishment (PR #26294),
                     ;; since tx validity is subjective (our mempool/chain state)
                     ;; and an honest peer shouldn't be discouraged for relaying
                     ;; a tx we happen to reject. Consensus-invalid txs are only
                     ;; punished when they arrive inside a block.
                     ;;
                     ;; Keyed by WTXID, never the txid of a witness tx: the
                     ;; witness can be malleated, so the same txid with a
                     ;; different witness could still be valid (Core issue
                     ;; #8279; txdownloadman_impl.cpp MempoolRejectedTx). For
                     ;; no-witness txs wtxid == txid, so those are covered.
                     ;;
                     ;; :witness-stripped is never cached AT ALL (Core
                     ;; TX_WITNESS_STRIPPED, txdownloadman_impl.cpp:438-439):
                     ;; the tx arrived without its witness, so wtxid == txid
                     ;; here — caching it would poison the TXID of the real,
                     ;; witnessed tx and block its relay permanently.
                     ;;
                     ;; :nonstandard-inputs additionally caches the TXID for a
                     ;; witness tx (Core TX_INPUTS_NOT_STANDARD,
                     ;; txdownloadman_impl.cpp:471-484): that failure depends
                     ;; only on the txid (the scriptPubKeys being spent), so no
                     ;; witness can fix it and the txid entry stops re-fetching
                     ;; via the orphan parent-request path.
                     (unless (eq error :witness-stripped)
                       (bitcoin-lisp:add-recent-reject recent-rejects wtxid)
                       (when (and (eq error :nonstandard-inputs)
                                  (not (equalp wtxid txid)))
                         (bitcoin-lisp:add-recent-reject recent-rejects txid))))))
                (when valid
                  (multiple-value-bind (result entry)
                      (bitcoin-lisp.mempool:accept-validated-tx
                       mempool txid tx fee current-height
                       :sigops sigops :replaced replaced)
                    (when (eq result :ok)
                      ;; getpeerinfo "last_transaction" (Core m_last_tx_time,
                      ;; stamped only on mempool ACCEPTANCE,
                      ;; net_processing.cpp:4540).
                      (setf (peer-last-tx-time peer)
                            (bitcoin-lisp.serialization:get-unix-time))
                      ;; Relay to other peers
                      (when peers
                        (let ((vsize (bitcoin-lisp.mempool:mempool-entry-vsize entry)))
                          (relay-transaction txid peer peers
                                             :fee-rate (if (plusp vsize)
                                                           (floor fee vsize)
                                                           0)
                                             :wtxid (bitcoin-lisp.serialization:transaction-wtxid tx))))
                      ;; De-orphan: this tx may unblock waiting children.
                      (process-orphans txid utxo-set mempool chain-state peers
                                       :recent-rejects recent-rejects)))))))))
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

(defun handle-getblocktxn (peer payload block-store)
  "Serve a BIP152 getblocktxn: reply with a blocktxn carrying the requested
transactions (by index, witness-serialized) from the named block. This is the
serve side of compact-block relay — without it a peer reconstructing one of our
compact blocks can't fetch the txs it's missing. Skipped if we don't have the
block on disk (the peer falls back to a full getdata). An out-of-range index is
a malformed request: record misbehavior and don't reply."
  (when block-store
    (let* ((req (bitcoin-lisp.serialization:parse-getblocktxn-payload payload))
           (block-hash (bitcoin-lisp.serialization:block-txn-request-block-hash req))
           (indexes (bitcoin-lisp.serialization:block-txn-request-indexes req))
           (block (bitcoin-lisp.storage:get-block block-store block-hash)))
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
              (record-misbehavior peer "getblocktxn with out-of-bounds tx indices")))))))

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
        ;; Don't gossip discouraged addresses (Bitcoin Core skips them in relay).
        (let* ((addrs (remove-if
                       (lambda (pa)
                         (peer-discouraged-p (peer-address-string pa)))
                       (address-book-get-addr book :max +addrman-getaddr-max+
                                                   :pct +addrman-getaddr-pct+)))
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
                 (receive-message peer :timeout 60)
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

(defun send-compact-block-negotiation (peer)
  "Advertise compact block support to PEER. We announce only version 2 (witness),
matching Bitcoin Core — a v1 (non-witness) compact block would strip the coinbase
witness nonce. Requests high-bandwidth mode when not in IBD (peer may then send us
unsolicited compact blocks for faster relay) — but never in blocksonly mode:
our mempool won't contain the transactions needed to reconstruct a compact
block (Core MaybeSetPeerAsAnnouncingHeaderAndIDs, net_processing.cpp:1275-1280)."
  (let ((high-bw (and (not (ignore-incoming-txs-p))
                      (not (or (eq (ibd-state) :syncing-blocks)
                               (eq (ibd-state) :syncing-headers))))))
    ;; getpeerinfo bip152_hb_to (Core m_bip152_highbandwidth_to): whether WE
    ;; selected the peer as a high-bandwidth compact-block peer.
    (when high-bw
      (setf (peer-compact-block-high-bandwidth-to peer) t))
    (send-message peer (bitcoin-lisp.serialization:make-sendcmpct-message
                        high-bw +compact-blocks-version+))))

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
   - On collision: block is NIL, missing-indexes is :collision"
  (let* ((header (bitcoin-lisp.serialization:compact-block-header compact-block))
         (nonce (bitcoin-lisp.serialization:compact-block-nonce compact-block))
         (short-ids-list (bitcoin-lisp.serialization:compact-block-short-ids compact-block))
         (prefilled (bitcoin-lisp.serialization:compact-block-prefilled-txs compact-block))
         (tx-count (+ (length short-ids-list) (length prefilled)))
         (header-bytes (bitcoin-lisp.serialization:serialize-block-header header))
         ;; Convert short-ids list to vector for O(1) access
         (short-ids (coerce short-ids-list 'vector)))

    ;; Validate tx-count is reasonable (prevent DoS)
    (when (or (zerop tx-count) (> tx-count 100000))
      (bitcoin-lisp:log-warn "Invalid compact block tx count: ~D" tx-count)
      (return-from reconstruct-compact-block (values nil :collision)))

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
                    (bitcoin-lisp:log-warn "Prefilled tx index out of bounds: ~D (max ~D)"
                                           idx (1- tx-count))
                    (return-from reconstruct-compact-block (values nil :collision nil))))))

          ;; Fill remaining slots with mempool transactions matched by short ID
          (dotimes (i tx-count)
            (when (null (aref transactions i))
              ;; This slot needs a transaction from short IDs
              (when (>= short-id-idx (length short-ids))
                ;; More empty slots than short IDs - malformed message
                (bitcoin-lisp:log-warn "Short ID count mismatch")
                (return-from reconstruct-compact-block (values nil :collision nil)))
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

(defun handle-cmpctblock (peer payload chain-state utxo-set block-store mempool
                          &optional fee-estimator &key recent-rejects)
  "Handle a cmpctblock message. Attempt reconstruction from mempool."
  (let* ((compact-block (bitcoin-lisp.serialization:parse-cmpctblock-payload payload))
         (header (bitcoin-lisp.serialization:compact-block-header compact-block))
         (block-hash (bitcoin-lisp.serialization:block-header-hash header))
         (use-wtxid (= (peer-compact-block-version peer) 2)))

    ;; Clear any old pending reconstruction for different block
    (when (peer-pending-compact-block peer)
      (let ((pending-hash (pending-compact-block-block-hash
                           (peer-pending-compact-block peer))))
        (unless (equalp pending-hash block-hash)
          (setf (peer-pending-compact-block peer) nil))))

    ;; Skip if we already have this block connected
    (let ((entry (bitcoin-lisp.storage:get-block-index-entry chain-state block-hash)))
      (when (and entry
                 (eq (bitcoin-lisp.storage:block-index-entry-status entry) :connected))
        (return-from handle-cmpctblock nil)))

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
         (with-node-lock
           (multiple-value-bind (valid error)
               (accept-downloaded-block block chain-state utxo-set block-store
                                        :mempool mempool
                                        :fee-estimator fee-estimator
                                        :recent-rejects recent-rejects)
             (unless valid
               (bitcoin-lisp:log-warn "Reconstructed block invalid: ~A" error)
               (record-misbehavior peer "invalid compact block")))))

        ;; Collision or malformed - fall back to full block
        ((eq missing-indexes :collision)
         (increment-compact-block-failure)
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
  "Handle a blocktxn message. Complete pending block reconstruction."
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
        (when (/= (length txs) (length missing-indexes))
          (bitcoin-lisp:log-warn "blocktxn transaction count mismatch")
          (setf (peer-pending-compact-block peer) nil)
          (request-full-block peer block-hash)
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
          (with-node-lock
            (multiple-value-bind (valid error)
                (accept-downloaded-block block chain-state utxo-set block-store
                                         :mempool mempool
                                         :fee-estimator fee-estimator
                                         :recent-rejects recent-rejects)
              (unless valid
                (bitcoin-lisp:log-warn "Completed block invalid: ~A" error)
                (record-misbehavior peer "invalid reconstructed block")))))))))

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
