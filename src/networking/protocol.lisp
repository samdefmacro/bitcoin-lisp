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
  "Return the /16 group key for an IPv4 dotted-quad string, NIL otherwise.
Mirrors Bitcoin Core's CNetAddr::GetGroup() for routable IPv4: groups
addresses by the first two octets so addrman's bucket selection
prefers connections from distinct operators / netgroups. Without
this, DNS seeds that dump many IPs from one /24 (e.g. wiz.biz's
testnet4 nodes at 103.165.192.x) cause an 8-of-8 single-operator
peer set, which becomes a single point of stall."
  (let ((dots 0)
        (end nil))
    (dotimes (i (length addr))
      (when (char= (char addr i) #\.)
        (incf dots)
        (when (= dots 2)
          (setf end i)
          (return))))
    (when end
      (subseq addr 0 end))))

(defun diversify-by-netgroup (addresses)
  "Reorder ADDRESSES so consecutive entries come from distinct /16
netgroups when possible. Round-robins across groups: caller (which
connects to the first N entries) gets the broadest spread for free
without needing per-group caps. Stable within each group so the DNS-
returned ordering acts as the within-group tiebreaker."
  (let ((groups (make-hash-table :test 'equal))
        (group-keys '()))
    ;; Bucket by group, preserve within-group order.
    (dolist (addr addresses)
      (let ((g (or (ip-netgroup addr) "_nogroup")))
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
DNS-clustered nodes from monopolizing our 8-peer outbound budget."
  (let ((addresses '()))
    (dolist (seed seeds)
      (let ((resolved (resolve-dns-seed seed)))
        (when resolved
          (setf addresses (nconc addresses resolved)))))
    (diversify-by-netgroup
     (remove-duplicates addresses :test #'string=))))

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
     (handle-inv peer payload chain-state mempool :recent-rejects recent-rejects)
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

    ((string= command "notfound")
     (handle-notfound peer payload)
     t)

    ((string= command "addr")
     (handle-addr peer payload address-book)
     t)

    ((string= command "addrv2")
     (handle-addrv2 peer payload address-book)
     t)

    ((string= command "sendaddrv2")
     ;; No-op post-handshake (only meaningful during handshake)
     t)

    ((string= command "wtxidrelay")
     ;; BIP 339: No-op post-handshake (only meaningful during handshake)
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
;;; the request times out.

(defvar *tx-in-flight* (make-hash-table :test 'equalp)
  "txid -> (peer . request-internal-real-time); at most one per txid.")
(defvar *tx-announcers* (make-hash-table :test 'equalp)
  "txid -> list of peers that announced it (failover candidates).")
(defvar *tx-request-lock* (bt:make-lock "tx-request"))
(defparameter +tx-request-timeout-seconds+ 60
  "Re-route a tx getdata to another announcer after this long with no delivery
(Bitcoin Core GETDATA_TX_INTERVAL is 60s for non-preferred peers).")

(defun reset-tx-requests ()
  "Clear all tx-request tracking (called at node start)."
  (bt:with-lock-held (*tx-request-lock*)
    (clrhash *tx-in-flight*)
    (clrhash *tx-announcers*)))

(defun tx-request-wanted-p (txid peer)
  "Record PEER as an announcer of TXID and return T iff we should send a getdata
to PEER now — i.e. no request for TXID is currently outstanding. NIL means a
request is already in flight and PEER is retained only as a failover candidate."
  (bt:with-lock-held (*tx-request-lock*)
    (pushnew peer (gethash txid *tx-announcers*))
    (cond ((gethash txid *tx-in-flight*) nil)
          (t (setf (gethash txid *tx-in-flight*)
                   (cons peer (get-internal-real-time)))
             t))))

(defun tx-request-received (txid)
  "Clear tracking for TXID once the tx arrives (or is otherwise resolved)."
  (bt:with-lock-held (*tx-request-lock*)
    (remhash txid *tx-in-flight*)
    (remhash txid *tx-announcers*)))

(defun retry-timed-out-tx-requests ()
  "Re-route each in-flight tx getdata outstanding longer than the timeout to the
next ready announcer (other than the one that timed out); drop tracking for a
tx with no other announcer. Returns the number re-requested."
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
                 (old-peer (cadr item))
                 (next (find-if (lambda (p) (and (not (eq p old-peer))
                                                 (eq (peer-state p) :ready)))
                                (gethash txid *tx-announcers*))))
            (if next
                (progn (setf (gethash txid *tx-in-flight*) (cons next now))
                       (push (cons txid next) reroutes))
                (progn (remhash txid *tx-in-flight*)
                       (remhash txid *tx-announcers*)))))))
    ;; Send getdata outside the lock.
    (dolist (pair reroutes)
      (handler-case
          (send-message (cdr pair)
                        (bitcoin-lisp.serialization:make-getdata-message
                         (list (bitcoin-lisp.serialization:make-inv-vector
                                :type bitcoin-lisp.serialization:+inv-type-witness-tx+
                                :hash (car pair)))))
        (error () nil)))
    (length reroutes)))

(defun handle-inv (peer payload chain-state &optional mempool &key recent-rejects)
  "Handle an inv message.

For block invs we DO NOT request the block directly via getdata — under
headers-first sync (BIP 130 era), an unknown block hash means we are
missing the header chain that reaches it, so a getdata would race the
header that defines the block's parent and `process-received-block`
would drop it with WARN: Received unknown block. Instead, on the first
unknown block hash we send a getheaders sourced from our header tip;
once headers connect, the IBD/follow-tip path issues the actual getdata.

Mirrors Bitcoin Core net_processing.cpp:4153-4211 (best_block tracking
plus a single MaybeSendGetHeaders after the inv vector is fully scanned)."
  (let ((inv-vectors (bitcoin-lisp.serialization:parse-inv-payload payload))
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
          ((or (= inv-type bitcoin-lisp.serialization:+inv-type-tx+)
               (= inv-type bitcoin-lisp.serialization:+inv-type-witness-tx+))
           (when (and mempool
                      (not (bitcoin-lisp.mempool:mempool-has mempool hash))
                      (not (bitcoin-lisp:recent-reject-p recent-rejects hash))
                      ;; Records PEER as an announcer; T only if no request for
                      ;; this txid is already outstanding (dedup across peers).
                      (tx-request-wanted-p hash peer))
             (push (bitcoin-lisp.serialization:make-inv-vector
                    :type bitcoin-lisp.serialization:+inv-type-witness-tx+
                    :hash hash)
                   wanted))))))
    (when unknown-block-hash
      (bitcoin-lisp:log-debug "inv: unknown block ~A from peer ~A — sending getheaders"
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
Mirrors Bitcoin Core's MSG NOTFOUND handling (net_processing.cpp)."
  (dolist (inv (bitcoin-lisp.serialization:parse-inv-payload payload))
    (when (block-inv-type-p (bitcoin-lisp.serialization:inv-vector-type inv))
      (note-block-not-available peer (bitcoin-lisp.serialization:inv-vector-hash inv)))))

;;; Headers handling

(defun handle-headers (peer payload chain-state)
  "Handle a headers message: validate the announced headers (PoW, MTP,
difficulty, checkpoint) and admit only the valid ones to the block index,
queueing them for block download. This is the generic message-loop path (the
IBD pre-sync drain via handle-message, and BIP130 sendheaders announcements);
like the Phase-1 sync-headers path it MUST validate before admission, or a peer
could inject unchecked headers into the index — inflating chain-work with
low-target headers lacking matching PoW and bypassing checkpoints at admission.
Previously this admitted any header with a known parent, unvalidated."
  (let ((headers (bitcoin-lisp.serialization:parse-headers-payload payload)))
    (multiple-value-bind (valid-headers error)
        (validate-header-chain headers chain-state)
      (when error
        (bitcoin-lisp:log-warn "Header validation error: ~A" error))
      (process-headers valid-headers chain-state)
      ;; Per-peer availability: the peer's advertised tip is the last VALID
      ;; header. Mirrors Core's UpdateBlockAvailability (net_processing.cpp).
      (let ((last (car (last valid-headers))))
        (when last
          (update-block-availability
           peer chain-state
           (bitcoin-lisp.serialization:block-header-hash last)))))))

;;; Block handling

(defun handle-block (peer payload chain-state utxo-set block-store
                     &optional mempool fee-estimator &key recent-rejects peers)
  "Handle a block message. When PEERS is supplied and the block becomes the new
active tip, announce it onward (BIP 130 headers / inv), so the node propagates
blocks instead of being a sink."
  (let ((block (bitcoin-lisp.serialization:parse-block-payload payload)))
    (when block
      (with-node-lock
        (let* ((header (bitcoin-lisp.serialization:bitcoin-block-header block))
               (hash (bitcoin-lisp.serialization:block-header-hash header))
               (current-height (bitcoin-lisp.storage:current-height chain-state))
               (current-time (bitcoin-lisp.serialization:get-unix-time)))
          ;; Validate and connect block
          (multiple-value-bind (valid error)
              (bitcoin-lisp.validation:validate-block
               block chain-state utxo-set (1+ current-height) current-time)
            (if valid
                (progn
                  (bitcoin-lisp.validation:connect-block
                   block chain-state block-store utxo-set
                   :fee-estimator fee-estimator
                   :recent-rejects recent-rejects
                   :mempool mempool)
                  ;; Announce onward only if this block is now the active tip
                  ;; (connect-block may have stored a side block or reorged).
                  (when (and peers
                             (equalp (bitcoin-lisp.storage:best-block-hash chain-state)
                                     hash))
                    (relay-block header peer peers)))
                (progn
                  (format t "Block ~A rejected: ~A~%"
                          (bitcoin-lisp.crypto:bytes-to-hex hash) error)
                  ;; Record misbehavior for invalid block
                  (record-misbehavior peer 100)))))))))

;;; Address handling

(defun handle-addr (peer payload &optional address-book)
  "Handle an addr message. When ADDRESS-BOOK is provided, add plausible
addresses (timestamp within last 3 hours) to the address book, keyed to the
gossiping PEER as their source (addrman source-group spreading)."
  (let ((now (bitcoin-lisp.serialization:get-unix-time))
        (three-hours (* 3 3600))
        (source-ip (when peer (string-to-ip-bytes (peer-address peer))))
        (added 0))
    (flexi-streams:with-input-from-sequence (stream payload)
      (let ((count (bitcoin-lisp.serialization:read-compact-size stream)))
        (loop repeat (min count 1000)  ; Limit to prevent abuse
              do (multiple-value-bind (net-addr timestamp)
                     (bitcoin-lisp.serialization:read-net-addr stream :with-timestamp t)
                   (when (and address-book timestamp
                              (<= (abs (- now timestamp)) three-hours))
                     (address-book-add
                      address-book
                      (make-peer-address
                       :ip (bitcoin-lisp.serialization:net-addr-ip net-addr)
                       :port (bitcoin-lisp.serialization:net-addr-port net-addr)
                       :services (bitcoin-lisp.serialization:net-addr-services net-addr)
                       :last-seen timestamp)
                      source-ip)
                     (incf added))))))
    (when (and address-book (> added 0))
      (bitcoin-lisp:log-debug "Added ~D peer addresses from addr message" added))
    added))

;;; ADDRv2 handling (BIP 155)

(defun handle-addrv2 (peer payload &optional address-book)
  "Handle an addrv2 message (BIP 155). When ADDRESS-BOOK is provided, add
IPv4/IPv6 addresses with plausible timestamps (within 3 hours) to the address book.
Other network types are silently skipped."
  (let ((now (bitcoin-lisp.serialization:get-unix-time))
        (three-hours (* 3 3600))
        (source-ip (when peer (string-to-ip-bytes (peer-address peer))))
        (added 0)
        (entries (bitcoin-lisp.serialization:parse-addrv2-payload payload)))
    (dolist (entry entries)
      (destructuring-bind (net-addr timestamp network-id) entry
        (declare (ignore network-id))
        (when (and address-book
                   (<= (abs (- now timestamp)) three-hours))
          (address-book-add
           address-book
           (make-peer-address
            :ip (bitcoin-lisp.serialization:net-addr-ip net-addr)
            :port (bitcoin-lisp.serialization:net-addr-port net-addr)
            :services (bitcoin-lisp.serialization:net-addr-services net-addr)
            :last-seen timestamp)
           source-ip)
          (incf added))))
    (when (and address-book (> added 0))
      (bitcoin-lisp:log-debug "Added ~D peer addresses from addrv2 message" added))
    added))

;;; Transaction handling

(defun process-orphans (accepted-txid utxo-set mempool chain-state peers
                        &key recent-rejects)
  "De-orphan cascade: after ACCEPTED-TXID enters the mempool, re-validate the
orphans that depend on it; accept+relay any now valid, drop those now invalid,
and recurse on newly-accepted txs so a parent can unblock a whole chain."
  (let ((pool (bitcoin-lisp.mempool:mempool-orphan-pool mempool))
        (work (list accepted-txid)))
    (loop while work do
      (let ((ptxid (pop work)))
        (dolist (otxid (bitcoin-lisp.mempool:orphans-depending-on pool ptxid))
          (let ((otx (bitcoin-lisp.mempool:orphan-tx pool otxid)))
            (when otx
              (let ((current-height (bitcoin-lisp.storage:current-height chain-state)))
                (multiple-value-bind (valid error fee replaced)
                    (bitcoin-lisp.validation:validate-transaction-for-mempool
                     otx utxo-set mempool current-height :chain-state chain-state)
                  (cond
                    (valid
                     (multiple-value-bind (result entry)
                         (bitcoin-lisp.mempool:accept-validated-tx
                          mempool otxid otx fee current-height :replaced replaced)
                       (when (eq :ok result)
                         (bitcoin-lisp.mempool:orphan-remove pool otxid)
                         (when peers
                           (let ((vsize (bitcoin-lisp.mempool:mempool-entry-vsize entry)))
                             (relay-transaction
                              otxid nil peers
                              :fee-rate (if (plusp vsize) (floor fee vsize) 0)
                              :wtxid (bitcoin-lisp.serialization:transaction-wtxid otx))))
                         (push otxid work))))   ; cascade to this tx's dependents
                    ((eq error :missing-input) nil)   ; still missing another parent
                    (t (bitcoin-lisp.mempool:orphan-remove pool otxid)  ; now invalid
                       (when recent-rejects
                         (bitcoin-lisp:add-recent-reject recent-rejects otxid)))))))))))))

(defun request-orphan-parents (peer tx utxo-set mempool)
  "Send a getdata to PEER for TX's missing parents (inputs not in the UTXO set
or the mempool), so an orphan can be resolved promptly."
  (let ((seen (make-hash-table :test 'equalp))
        (invs '()))
    (bitcoin-lisp.serialization:dovector (input (bitcoin-lisp.serialization:transaction-inputs tx))
      (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
             (ptxid (bitcoin-lisp.serialization:outpoint-hash prevout))
             (pidx (bitcoin-lisp.serialization:outpoint-index prevout)))
        (unless (or (gethash ptxid seen)
                    (bitcoin-lisp.storage:get-utxo utxo-set ptxid pidx)
                    (bitcoin-lisp.mempool:mempool-has mempool ptxid))
          (setf (gethash ptxid seen) t)
          (push (bitcoin-lisp.serialization:make-inv-vector
                 :type bitcoin-lisp.serialization:+inv-type-tx+ :hash ptxid)
                invs))))
    (when invs
      (send-message peer (bitcoin-lisp.serialization:make-getdata-message invs)))))

(defun handle-tx (peer payload utxo-set mempool chain-state peers
                  &key recent-rejects)
  "Handle a tx message. Validate, add to mempool, and relay.
RECENT-REJECTS is optional; when provided, recently rejected txs are cached."
  (handler-case
      (let ((tx (bitcoin-lisp.serialization:parse-tx-payload payload)))
        (when tx
          (with-node-lock
            (let ((txid (bitcoin-lisp.serialization:transaction-hash tx))
                  (current-height (bitcoin-lisp.storage:current-height chain-state)))
              ;; The requested tx arrived — clear its in-flight/announcer tracking.
              (tx-request-received txid)
              ;; Mark as announced by this peer
              (setf (gethash txid (peer-announced-txs peer)) t)
              ;; Check recent rejects filter before expensive validation
              (when (bitcoin-lisp:recent-reject-p recent-rejects txid)
                (return-from handle-tx nil))
              ;; Validate for mempool
              (multiple-value-bind (valid error fee replaced)
                  (bitcoin-lisp.validation:validate-transaction-for-mempool
                   tx utxo-set mempool current-height :chain-state chain-state)
                (unless valid
                  (cond
                    ;; Missing inputs => hold as an orphan (not a real reject);
                    ;; a later parent will trigger re-evaluation. Request the
                    ;; missing parents from this peer so they arrive sooner.
                    ((eq error :missing-input)
                     (bitcoin-lisp.mempool:orphan-add
                      (bitcoin-lisp.mempool:mempool-orphan-pool mempool) tx peer)
                     (request-orphan-parents peer tx utxo-set mempool))
                    (t
                     ;; Add to recent rejects filter
                     (bitcoin-lisp:add-recent-reject recent-rejects txid)
                     ;; Record misbehavior for invalid transactions
                     ;; (policy violations like :insufficient-fee are not penalized)
                     (when (member error '(:script-failed :no-inputs :no-outputs
                                           :duplicate-inputs :negative-output
                                           :output-too-large :total-output-too-large))
                       (record-misbehavior peer 10)))))
                (when valid
                  (multiple-value-bind (result entry)
                      (bitcoin-lisp.mempool:accept-validated-tx
                       mempool txid tx fee current-height :replaced replaced)
                    (when (eq result :ok)
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
        (blocks-served 0))
    (dolist (inv inv-vectors)
      (let ((inv-type (bitcoin-lisp.serialization:inv-vector-type inv))
            (hash (bitcoin-lisp.serialization:inv-vector-hash inv)))
        (cond
          ;; Transaction request - only respond if relay is enabled
          ((or (= inv-type bitcoin-lisp.serialization:+inv-type-tx+)
               (= inv-type bitcoin-lisp.serialization:+inv-type-witness-tx+))
           (when (and mempool (relay-enabled-p))
             (let ((entry (bitcoin-lisp.mempool:mempool-get mempool hash)))
               (when entry
                 (send-message peer
                               (bitcoin-lisp.serialization:make-tx-message
                                (bitcoin-lisp.mempool:mempool-entry-transaction entry)))))))
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
                               bitcoin-lisp.serialization:+inv-type-witness-block+))))))))))))

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
   :ip (peer-address-ip peer-addr)
   :port (peer-address-port peer-addr)))

(defun build-addr-response (peer peer-addrs)
  "Build an addr message (or addrv2 when PEER advertised sendaddrv2) announcing
the PEER-ADDRESS records in PEER-ADDRS."
  (if (peer-wants-addrv2 peer)
      (bitcoin-lisp.serialization:make-addrv2-message
       (mapcar (lambda (pa)
                 (list (peer-address->net-addr pa)
                       (if (ipv4-mapped-p (peer-address-ip pa))
                           bitcoin-lisp.serialization:+addrv2-net-ipv4+
                           bitcoin-lisp.serialization:+addrv2-net-ipv6+)
                       (peer-address-last-seen pa)))
               peer-addrs))
      (bitcoin-lisp.serialization:make-addr-message
       (mapcar (lambda (pa)
                 (list (peer-address->net-addr pa) (peer-address-last-seen pa)))
               peer-addrs))))

(defun handle-getaddr (peer &optional address-book)
  "Serve a peer's getaddr: reply once per connection, and only to inbound peers,
with up to +max-addr-count+ known addresses from ADDRESS-BOOK (defaulting to the
node's). The inbound-only + once-per-connection rules mirror Bitcoin Core's
GETADDR handler (anti-fingerprinting and anti-spam) — the once flag latches as
soon as the request arrives, before we build any response, so a peer can never
elicit more than one reply regardless of whether we had addresses to send."
  (when (and (peer-inbound peer)
             (not (peer-getaddr-sent peer)))
    (setf (peer-getaddr-sent peer) t)
    (let ((book (or address-book
                    (let ((node bitcoin-lisp::*node*))
                      (and node (bitcoin-lisp::node-address-book node))))))
      (when book
        ;; Don't gossip discouraged addresses (Bitcoin Core skips them in relay).
        (let ((addrs (remove-if
                      (lambda (pa)
                        (peer-discouraged-p (ip-bytes-to-string (peer-address-ip pa))))
                      (address-book-get-addr book :max +addrman-getaddr-max+
                                                  :pct +addrman-getaddr-pct+))))
          (when addrs
            (send-message peer (build-addr-response peer addrs))))))))

;;; Transaction relay

(defun relay-enabled-p ()
  "Check if transaction relay is enabled for the current network.
Relay is always enabled on test networks, disabled by default on mainnet for safety."
  (or (member bitcoin-lisp:*network* '(:testnet3 :testnet4 :signet :regtest))
      bitcoin-lisp:*mainnet-relay-enabled*))

(defun relay-transaction (txid source-peer peers &key fee-rate wtxid)
  "Relay a transaction to all connected peers except SOURCE-PEER.
Sends inv messages and tracks announcements to avoid duplicates.
FEE-RATE is the transaction fee rate in sat/byte (used for BIP 133 feefilter).
WTXID is the witness txid (used for BIP 339 wtxidrelay peers).
Does nothing if relay is disabled for the current network."
  (unless (relay-enabled-p)
    (return-from relay-transaction nil))
  (let ((txid-inv-msg (bitcoin-lisp.serialization:make-inv-message
                       (list (bitcoin-lisp.serialization:make-inv-vector
                              :type bitcoin-lisp.serialization:+inv-type-tx+
                              :hash txid))))
        (wtxid-inv-msg (when wtxid
                         (bitcoin-lisp.serialization:make-inv-message
                          (list (bitcoin-lisp.serialization:make-inv-vector
                                 :type bitcoin-lisp.serialization:+inv-type-witness-tx+
                                 :hash wtxid)))))
        (fee-rate-per-kb (if fee-rate (* fee-rate 1000) 0)))
    (dolist (peer peers)
      ;; Skip the source peer and disconnected peers
      (when (and (not (eq peer source-peer))
                 (eq (peer-state peer) :ready)
                 ;; Skip if already announced to this peer
                 (not (gethash txid (peer-announced-txs peer)))
                 ;; BIP 133: Skip if tx fee rate below peer's feefilter
                 (or (zerop (peer-feefilter-rate peer))
                     (>= fee-rate-per-kb (peer-feefilter-rate peer))))
        (setf (gethash txid (peer-announced-txs peer)) t)
        ;; BIP 339: Use wtxid-based inv for peers that support it
        (if (and (peer-wtxid-relay peer) wtxid-inv-msg)
            (send-message peer wtxid-inv-msg)
            (send-message peer txid-inv-msg))))))

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
node validates blocks but never propagates them — a pure block sink."
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

(defun send-compact-block-negotiation (peer)
  "Send sendcmpct messages to advertise compact block support.
Sends version 2 first (preferred for SegWit), then version 1.
Requests high-bandwidth mode when not in IBD (peer will send us
unsolicited compact blocks for faster relay)."
  (let ((high-bw (not (or (eq (ibd-state) :syncing-blocks)
                           (eq (ibd-state) :syncing-headers)))))
    ;; Send version 2 (wtxid-based) first
    (send-message peer (bitcoin-lisp.serialization:make-sendcmpct-message high-bw 2))
    ;; Then version 1 (txid-based) as fallback
    (send-message peer (bitcoin-lisp.serialization:make-sendcmpct-message high-bw 1))))

(defun handle-sendcmpct (peer payload)
  "Handle a sendcmpct message from a peer.
   Updates peer's compact block capabilities."
  (multiple-value-bind (high-bandwidth version)
      (bitcoin-lisp.serialization:parse-sendcmpct-payload payload)
    ;; Accept the highest version we mutually support (1 or 2)
    (when (and (> version 0) (<= version 2))
      ;; Take the higher of current and new version
      (when (> version (peer-compact-block-version peer))
        (setf (peer-compact-block-version peer) version))
      ;; Track high-bandwidth mode preference
      (when high-bandwidth
        (setf (peer-compact-block-high-bandwidth peer) t)))
    (bitcoin-lisp:log-debug "Peer ~A supports compact blocks v~D (high-bw: ~A)"
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
         (bitcoin-lisp:log-debug "Compact block reconstructed successfully")
         ;; Process like a normal block
         (with-node-lock
           (let* ((current-height (bitcoin-lisp.storage:current-height chain-state))
                  (current-time (bitcoin-lisp.serialization:get-unix-time)))
             (multiple-value-bind (valid error)
                 (bitcoin-lisp.validation:validate-block
                  block chain-state utxo-set (1+ current-height) current-time)
               (if valid
                   (progn
                     (bitcoin-lisp.validation:connect-block
                      block chain-state block-store utxo-set
                      :fee-estimator fee-estimator
                      :recent-rejects recent-rejects
                      :mempool mempool))
                   (progn
                     (bitcoin-lisp:log-warn "Reconstructed block invalid: ~A" error)
                     (record-misbehavior peer 100)))))))

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
          (with-node-lock
            (let* ((current-height (bitcoin-lisp.storage:current-height chain-state))
                   (current-time (bitcoin-lisp.serialization:get-unix-time)))
              (multiple-value-bind (valid error)
                  (bitcoin-lisp.validation:validate-block
                   block chain-state utxo-set (1+ current-height) current-time)
                (if valid
                    (progn
                      (bitcoin-lisp.validation:connect-block
                       block chain-state block-store utxo-set
                       :fee-estimator fee-estimator
                       :recent-rejects recent-rejects
                       :mempool mempool))
                    (progn
                      (bitcoin-lisp:log-warn "Completed block invalid: ~A" error)
                      (record-misbehavior peer 100)))))))))))

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
