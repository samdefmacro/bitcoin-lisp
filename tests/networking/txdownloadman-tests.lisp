(in-package #:bitcoin-lisp.tests)

;;;; Core's TxDownloadManager (src/networking/txdownloadman.lisp) and the
;;;; net_processing.cpp sites that drive it: the method contracts the
;;;; handlers rely on, and the behaviours the restructure brought into line
;;;; with Core -- the orphan work set taken one orphan per message-loop turn,
;;;; and a tip change that leaves the rejection filters alone during initial
;;;; block download.

(in-suite :txdownloadman-tests)

(defun %tdm-peer (&rest args)
  "A :ready outbound peer advertising NODE_WITNESS."
  (apply #'bl.net:make-peer :state :ready :services bl.ser:+node-witness+ args))

(defun %tdm-payload (tx)
  "The `tx' message payload for TX, header stripped."
  (subseq (bl.ser:make-tx-message tx) 24))

(defun %tdm-hash (n)
  (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref h 0) (ldb (byte 8 0) n) (aref h 1) (ldb (byte 8 8) n) (aref h 31) 7)
    h))

(defmacro %with-fresh-txdownloadman ((mgr &optional mempool) &body body)
  "Run BODY out of initial block download against a fresh node manager bound
to MGR, reading MEMPOOL."
  `(let ((bl.net:*cached-is-ibd* nil))
     (let ((,mgr (bl.net:reset-txdownloadman ,mempool)))
       (declare (ignorable ,mgr))
       (unwind-protect (progn ,@body)
         (bl.net:reset-txdownloadman)))))

;;; --- The orphan work set (Core ProcessOrphanTx) ---

(test an-accepted-parent-puts-its-orphans-in-a-work-set-not-the-mempool
  "Core MempoolAcceptedTx puts the orphans spending an accepted transaction
into their announcers' work sets (txdownloadman_impl.cpp:330,
AddChildrenToWorkSet txorphanage.cpp:527-565), and each announcer's
ProcessMessages takes ONE of them per turn before its next message
(ProcessOrphanTx, net_processing.cpp:3227-3263, :5232-5237) -- \"the orphan
processing used to be uninterruptible and quadratic, which could allow a peer
to stall the node for hours\". Ours re-validated the whole cascade inside the
parent's own tx message (PROCESS-ORPHANS from %AFTER-MEMPOOL-ACCEPT), so a
chain of orphans was one message's work. Here a grandchild and a child wait on
a parent: the parent's arrival resolves NEITHER; the child's announcer's next
turn resolves the child, which puts the grandchild in its work set; the turn
after that resolves the grandchild."
  (multiple-value-bind (utxo mempool state funding) (make-package-fixture)
    (let* ((parent (pkg-tx funding 0 (- 100000000 50000)))
           (pid (bl.ser:transaction-hash parent))
           (child (pkg-tx pid 0 (- 100000000 100000)))
           (cid (bl.ser:transaction-hash child))
           (grandchild (pkg-tx cid 0 (- 100000000 150000)))
           (gid (bl.ser:transaction-hash grandchild))
           (a (%tdm-peer)) (b (%tdm-peer))
           (ctx (bl.ctx:make-node-context :chain-state state :utxo-set utxo :mempool mempool)))
      (%with-fresh-txdownloadman (mgr mempool)
        (deliver-tx a (%tdm-payload grandchild) ctx)
        (deliver-tx a (%tdm-payload child) ctx)
        (is-true (bl.mp:orphan-have (test-orphanage) (bl.ser:transaction-wtxid child)))
        (is-false (bl.net:txdownload-have-more-work mgr a))
        ;; B delivers the parent: it is accepted, and only that.
        (deliver-tx b (%tdm-payload parent) ctx)
        (is-true (bl.mp:mempool-has mempool pid))
        (is-false (bl.mp:mempool-has mempool cid)
                  "the parent's message must not re-validate its orphans")
        (is-false (bl.mp:mempool-has mempool gid))
        ;; The child is in A's work set (A is its only announcer).
        (is-true (bl.net:txdownload-have-more-work mgr a))
        (is-false (bl.net:txdownload-have-more-work mgr b))
        ;; A's next turn: the child, and nothing else.
        (is-true (bl.net:process-orphan-tx a ctx))
        (is-true (bl.mp:mempool-has mempool cid))
        (is-false (bl.mp:mempool-has mempool gid)
                  "one orphan per turn")
        (is-true (bl.net:txdownload-have-more-work mgr a))
        ;; The turn after: the grandchild.
        (is-true (bl.net:process-orphan-tx a ctx))
        (is-true (bl.mp:mempool-has mempool gid))
        (is-false (bl.net:txdownload-have-more-work mgr a))
        (is-false (bl.net:process-orphan-tx a ctx))
        (is (zerop (bl.mp:orphan-pool-count (test-orphanage))))))))

(test an-orphan-still-missing-an-input-leaves-the-work-set-and-stays
  "ProcessOrphanTx keeps taking orphans while each is still missing an input
(net_processing.cpp:3235-3262): such an orphan leaves the work set but stays
in the orphanage, \"not reconsidered again until there is a new reason to do
so\" (txorphanage.cpp:591-592), and the call reports no resolution."
  (multiple-value-bind (utxo mempool state funding) (make-package-fixture)
    (let* ((parent (pkg-tx funding 0 (- 100000000 50000)))
           (pid (bl.ser:transaction-hash parent))
           (other (%tdm-hash 4100))
           (child (pkg-tx-2in pid 0 other 0 (- 100000000 100000)))
           (a (%tdm-peer)) (b (%tdm-peer))
           (ctx (bl.ctx:make-node-context :chain-state state :utxo-set utxo :mempool mempool)))
      (%with-fresh-txdownloadman (mgr mempool)
        (deliver-tx a (%tdm-payload child) ctx)
        (deliver-tx b (%tdm-payload parent) ctx)
        (is-true (bl.net:txdownload-have-more-work mgr a) "control: the child was queued")
        (is-false (bl.net:process-orphan-tx a ctx))
        (is-false (bl.net:txdownload-have-more-work mgr a))
        (is-true (bl.mp:orphan-have (test-orphanage) (bl.ser:transaction-wtxid child)))))))

(test the-message-pump-takes-an-orphan-turn-before-the-next-message
  "The drive site: DRAIN-AND-REAP-PEER runs ProcessOrphanTx before it reads
the peer's next message, as ProcessMessages does (net_processing.cpp:
5232-5237) -- so a peer with no input at all still has its work set
drained."
  (multiple-value-bind (utxo mempool state funding) (make-package-fixture)
    (let* ((parent (pkg-tx funding 0 (- 100000000 50000)))
           (pid (bl.ser:transaction-hash parent))
           (child (pkg-tx pid 0 (- 100000000 100000)))
           (a (%tdm-peer)) (b (%tdm-peer))
           (ctx (bl.ctx:make-node-context :chain-state state :utxo-set utxo :mempool mempool)))
      (%with-fresh-txdownloadman (mgr mempool)
        (deliver-tx a (%tdm-payload child) ctx)
        (deliver-tx b (%tdm-payload parent) ctx)
        (is-false (bl.mp:mempool-has mempool (bl.ser:transaction-hash child)))
        ;; A has no connection to read from: only the orphan turn can run.
        (setf (bl.net:peer-connection a)
              (make-test-connection :host "127.0.0.1" :port 1 :connected t))
        (ignore-errors (drain-peer-once a ctx))
        (is-true (bl.mp:mempool-has mempool (bl.ser:transaction-hash child)))))))

;;; --- ActiveTipChange during IBD (Core net_processing.cpp:2045-2059) ---

(test a-tip-change-in-ibd-leaves-the-rejection-filters-alone
  "Core's PeerManagerImpl::ActiveTipChange resets the rejection filters only
`if (!is_ibd)' (net_processing.cpp:2052-2058). Ours cleared them on every
activation step, IBD included, from the validation layer. Control: the same
signal out of IBD clears both."
  (let ((h (%tdm-hash 4200))
        (state (bl.store:make-chain-state)))
    (%with-fresh-txdownloadman (mgr)
      (bl.net:rolling-bloom-insert (bl.net:txdownload-recent-rejects mgr) h)
      (bl.net:rolling-bloom-insert (bl.net:txdownload-recent-rejects-reconsiderable mgr) h)
      (let ((bl.net:*cached-is-ibd* t))
        (bl.vi:notify-active-tip-change state))
      (is-true (bl.net:rolling-bloom-contains-p (bl.net:txdownload-recent-rejects mgr) h))
      (is-true (bl.net:rolling-bloom-contains-p (bl.net:txdownload-recent-rejects-reconsiderable mgr) h))
      (bl.vi:notify-active-tip-change state)
      (is-false (bl.net:rolling-bloom-contains-p (bl.net:txdownload-recent-rejects mgr) h))
      (is-false (bl.net:rolling-bloom-contains-p (bl.net:txdownload-recent-rejects-reconsiderable mgr) h)))))

;;; --- The method contracts ---

(test an-unregistered-peers-announcement-is-not-tracked
  "AddTxAnnouncement tracks nothing for a peer ConnectedPeer never registered
(txdownloadman_impl.cpp:201-202); registration is VERACK's
(net_processing.cpp:3888-3895) and DisconnectedPeer undoes it, wtxid-relay
count included (:149-168)."
  (%with-fresh-txdownloadman (mgr)
    (let ((h (%tdm-hash 4300)))
      (is-false (bl.net:txdownload-add-tx-announcement mgr 7 h t 1000))
      (is (zerop (bl.net:txrequest-count (bl.net:txdownload-txrequest mgr) 7)))
      (bl.net:txdownload-connected-peer
       mgr 7 (bl.net:make-txdownload-connection-info :preferred t :wtxid-relay t))
      (is (= 1 (bl.net:txdownload-num-wtxid-peers mgr)))
      ;; Registering twice changes nothing (:151-152).
      (bl.net:txdownload-connected-peer
       mgr 7 (bl.net:make-txdownload-connection-info :preferred t :wtxid-relay t))
      (is (= 1 (bl.net:txdownload-num-wtxid-peers mgr)))
      (bl.net:txdownload-add-tx-announcement mgr 7 h t 1000)
      (is (= 1 (bl.net:txrequest-count (bl.net:txdownload-txrequest mgr) 7)))
      (bl.net:txdownload-disconnected-peer mgr 7)
      (is (zerop (bl.net:txdownload-num-wtxid-peers mgr)))
      (is (null (bl.net:txdownload-check-is-empty mgr 7)))
      (is (null (bl.net:txdownload-check-is-empty mgr))))))

(test requests-go-out-with-the-announcements-delays
  "GetRequestsToSend hands a peer its announcements once their delay has
passed, each marked REQUESTED for GETDATA_TX_INTERVAL
(txdownloadman_impl.cpp:264-286): a preferred wtxid announcement at once, a
non-preferred one NONPREF_PEER_TX_DELAY later, a txid one TXID_RELAY_DELAY
later while a wtxid-relay peer is registered (:215-221)."
  (%with-fresh-txdownloadman (mgr)
    (let ((w (%tdm-hash 4401)) (txid (%tdm-hash 4402)) (slow (%tdm-hash 4403)))
      (bl.net:txdownload-connected-peer
       mgr 1 (bl.net:make-txdownload-connection-info :preferred t :wtxid-relay t))
      (bl.net:txdownload-connected-peer
       mgr 2 (bl.net:make-txdownload-connection-info :preferred nil))
      (bl.net:txdownload-add-tx-announcement mgr 1 w t 1000)
      (bl.net:txdownload-add-tx-announcement mgr 1 txid nil 1000)
      (bl.net:txdownload-add-tx-announcement mgr 2 slow t 1000)
      (is (equalp (list (cons w t)) (bl.net:txdownload-get-requests-to-send mgr 1 1000)))
      (is (null (bl.net:txdownload-get-requests-to-send mgr 2 1001)))
      (is (equalp (list (cons txid nil)) (bl.net:txdownload-get-requests-to-send mgr 1 1002)))
      (is (equalp (list (cons slow t)) (bl.net:txdownload-get-requests-to-send mgr 2 1002)))
      (is (= 1 (bl.net:txrequest-count-in-flight (bl.net:txdownload-txrequest mgr) 2))))))

(test a-rejection-is-recorded-where-core-records-it
  "MempoolRejectedTx's verdict classes (txdownloadman_impl.cpp:438-485): a
witness-stripped failure is cached nowhere and stays out of the compact extra
pool; a reconsiderable one goes to the second filter by wtxid; an
inputs-not-standard one to the main filter by wtxid AND txid; any other by
wtxid only. A first-time failure asks for the extra pool, a later one never
does."
  (%with-fresh-txdownloadman (mgr)
    (let* ((witness-tx (bl.ser:make-transaction
                        :version 2
                        :inputs (vector (bl.ser:make-tx-in
                                         :previous-output (bl.ser:make-outpoint :hash (%tdm-hash 4500) :index 0)
                                         :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                                         :sequence #xffffffff))
                        :outputs (vector (bl.ser:make-tx-out :value 1000 :script-pubkey (p2sh-optrue-script-pubkey)))
                        :lock-time 0
                        :witness (vector (list (make-array 1 :element-type '(unsigned-byte 8)
                                                             :initial-element 1)))))
           (txid (bl.ser:transaction-hash witness-tx))
           (wtxid (bl.ser:transaction-wtxid witness-tx))
           (rejects (bl.net:txdownload-recent-rejects mgr))
           (reconsiderable (bl.net:txdownload-recent-rejects-reconsiderable mgr)))
      (is-false (equalp txid wtxid))
      (is-false (bl.net:txdownload-mempool-rejected-tx mgr witness-tx :witness-stripped 1 t))
      (is-false (bl.net:rolling-bloom-contains-p rejects wtxid))
      (is-false (bl.net:rolling-bloom-contains-p rejects txid))
      (is-true (bl.net:txdownload-mempool-rejected-tx mgr witness-tx :insufficient-fee 1 t))
      (is-true (bl.net:rolling-bloom-contains-p reconsiderable wtxid))
      (is-false (bl.net:rolling-bloom-contains-p rejects wtxid))
      (is-false (bl.net:txdownload-mempool-rejected-tx mgr witness-tx :not-standard 1 nil))
      (is-true (bl.net:rolling-bloom-contains-p rejects wtxid))
      (is-false (bl.net:rolling-bloom-contains-p rejects txid))
      (bl.net:txdownload-mempool-rejected-tx mgr witness-tx :nonstandard-inputs 1 nil)
      (is-true (bl.net:rolling-bloom-contains-p rejects txid)))))

(test received-tx-offers-a-package-for-a-reconsiderable-parent
  "ReceivedTx (txdownloadman_impl.cpp:505-555): a transaction already known
to fail reconsiderably is not validated alone, and when the delivering peer
also announced an orphan child of it the pair comes back as a 1p1c
PackageToValidate, parent first, both from that peer (Find1P1CPackage,
:297-321). Control: from another peer there is no package."
  (multiple-value-bind (utxo mempool state funding) (make-package-fixture)
    (declare (ignore utxo state))
    (let* ((parent (pkg-tx funding 0 (- 100000000 5)))
           (pid (bl.ser:transaction-hash parent))
           (child (pkg-tx pid 0 (- 100000000 100000))))
      (%with-fresh-txdownloadman (mgr mempool)
        (dolist (peer '(1 2))
          (bl.net:txdownload-connected-peer
           mgr peer (bl.net:make-txdownload-connection-info :preferred t)))
        (bl.net:txdownload-mempool-rejected-tx mgr parent :insufficient-fee 1 t)
        (bl.net:txdownload-mempool-rejected-tx mgr child :missing-input 1 t)
        (is-true (bl.mp:orphan-have (bl.net:txdownload-orphanage mgr)
                                    (bl.ser:transaction-wtxid child)))
        (multiple-value-bind (validate package) (bl.net:txdownload-received-tx mgr 2 parent)
          (is-false validate)
          (is (null package) "control: peer 2 announced no child"))
        (multiple-value-bind (validate package) (bl.net:txdownload-received-tx mgr 1 parent)
          (is-false validate)
          (is-true package)
          (when package
            (is (eq parent (bl.net:ptv-parent package)))
            (is (eq child (bl.net:ptv-child package)))
            (is (eql 1 (bl.net:ptv-parent-sender package)))
            (is (eql 1 (bl.net:ptv-child-sender package)))))
        ;; A failed package is not offered again (MempoolRejectedPackage).
        (bl.net:txdownload-mempool-rejected-package mgr (list parent child))
        (is (null (nth-value 1 (bl.net:txdownload-received-tx mgr 1 parent))))))))

(test the-inv-handler-records-and-sendmessages-asks
  "The two drive sites of a transaction request: the INV handler calls
AddTxAnnouncement and sends nothing (net_processing.cpp:4176-4180), and
SendMessages asks for what GetRequestsToSend hands out, as MSG_WTX for a wtxid
(:6201-6217)."
  (let* ((state (bl.store:make-chain-state))
         (mempool (bl.mp:make-mempool))
         (peer (%tdm-peer :wtxid-relay t))
         (wtxid (%tdm-hash 4600))
         (ctx (bl.ctx:make-node-context :chain-state state :mempool mempool)))
    (%with-fresh-txdownloadman (mgr mempool)
      (is (null (captured-sends
                 (lambda () (deliver-inv peer (tx-inv-payload bl.ser:+inv-type-wtx+ wtxid) ctx))))
          "the inv handler sends nothing")
      (is (equal (list peer) (tx-request-candidate-peers wtxid)))
      (let ((sent (captured-sends (lambda () (bl.net:send-tx-requests peer mgr)))))
        (is (= 1 (length sent)))
        (when sent
          (let ((bytes (first sent)))
            (is (string= "getdata" (message-command bytes)))
            (is (= bl.ser:+inv-type-wtx+
                   (logior (aref bytes 25) (ash (aref bytes 26) 8)
                           (ash (aref bytes 27) 16) (ash (aref bytes 28) 24))))
            (is (equalp wtxid (subseq bytes 29 61)))))))))

;;; --- Round 12 phase 2: Core's filters and Core's asserts ---

(test the-rejects-filter-remembers-core-s-120-000
  "Core's recent-rejects filter is a CRollingBloomFilter of 120,000 at one in
a million (txdownloadman_impl.h:61-66): a rejection is remembered for at
least 120,000 later ones. Ours was a 50,000-entry ring, so the 50,001st
rejection evicted the first and the transaction was downloaded again. And it
has Core's false-positive rate: none of 10,000 keys never inserted."
  (%with-fresh-txdownloadman (mgr)
    (let ((rejects (bl.net:txdownload-recent-rejects mgr))
          (key (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 5)))
                 (lambda (i)
                   (dotimes (k 4 (copy-seq h)) (setf (aref h k) (ldb (byte 8 (* 8 k)) i)))))))
      (dotimes (i 60001)
        (bl.net:rolling-bloom-insert rejects (funcall key i)))
      (is-true (bl.net:rolling-bloom-contains-p rejects (funcall key 0))
               "the first of 60,001 rejections is still remembered")
      (is (zerop (loop for i from 70000 below 80000
                       count (bl.net:rolling-bloom-contains-p rejects (funcall key i))))))
    (is (= 20 (bl.net:rolling-bloom-filter-hash-funcs
               (bl.net:txdownload-recent-rejects-reconsiderable mgr))))
    (is (= 64700 (length (bl.net:rolling-bloom-filter-data
                          (bl.net:txdownload-recent-confirmed mgr)))))))

(test a-departed-peers-leftovers-fail-core-s-check-is-empty
  "Core asserts CheckIsEmpty once no peer is left (net_processing.cpp:
1720-1730) and for a new peer at InitializeNode (:1612): a manager still
holding an orphan to reconsider, or a request outstanding, for a peer that
is gone is a bookkeeping leak, and Core aborts. Ours logged it. Here state is
planted for a peer that never registered (no DisconnectedPeer will clean it)
and the last registered peer then disconnects through the shipped
DISCONNECT-PEER: TXDOWNLOAD-CHECK-FAILED. Control: the same disconnect with
nothing planted is quiet."
  (multiple-value-bind (utxo mempool state funding) (make-package-fixture)
    (declare (ignore utxo state))
    (let ((parent (pkg-tx funding 0 (- 100000000 50000))))
      (%with-fresh-txdownloadman (mgr mempool)
        (let ((last (%tdm-peer)))
          (bl.net:txdownload-connected-peer mgr last (bl.net:txdownload-connection-info-for last))
          (finishes (bl.net:disconnect-peer last) "control: nothing left, no signal")))
      ;; An orphan in a departed peer's work set.
      (%with-fresh-txdownloadman (mgr mempool)
        (let ((last (%tdm-peer))
              (child (pkg-tx (bl.ser:transaction-hash parent) 0 (- 100000000 100000))))
          (bl.net:txdownload-connected-peer mgr last (bl.net:txdownload-connection-info-for last))
          (bl.mp:orphan-add (bl.net:txdownload-orphanage mgr) child 41)
          (bl.mp:orphan-add-children-to-work-set (bl.net:txdownload-orphanage mgr) parent)
          (is-true (bl.mp:orphan-have-tx-to-reconsider (bl.net:txdownload-orphanage mgr) 41))
          (signals bl.net:txdownload-check-failed (bl.net:disconnect-peer last))))
      ;; A request outstanding to a departed peer.
      (%with-fresh-txdownloadman (mgr mempool)
        (let ((last (%tdm-peer))
              (tr (bl.net:txdownload-txrequest mgr))
              (h (%tdm-hash 4700)))
          (bl.net:txdownload-connected-peer mgr last (bl.net:txdownload-connection-info-for last))
          (bl.net:txrequest-received-inv tr 42 h t t 0)
          (bl.net:txrequest-requested-tx tr 42 h 100)
          (signals bl.net:txdownload-check-failed (bl.net:disconnect-peer last))))
      ;; The per-peer form, Core's CheckIsEmpty(nodeid) at InitializeNode.
      (%with-fresh-txdownloadman (mgr mempool)
        (bl.net:txrequest-received-inv (bl.net:txdownload-txrequest mgr) 43 (%tdm-hash 4701) t t 0)
        (signals bl.net:txdownload-check-failed (bl.net:txdownload-assert-empty mgr 43))
        (finishes (bl.net:txdownload-assert-empty mgr 44))))))

(test a-peer-s-getdata-goes-out-with-its-own-message-turn
  "Core's message handler pairs each node's ProcessMessages with its
SendMessages (net.cpp:3143-3148), so a peer is asked for what
GetRequestsToSend hands it at the end of its own turn, not after every other
peer's messages: DRAIN-AND-REAP-PEER ends with that peer's getdata."
  (let* ((state (bl.store:make-chain-state))
         (mempool (bl.mp:make-mempool))
         (peer (%tdm-peer :wtxid-relay t))
         (other (%tdm-peer :wtxid-relay t))
         (wtxid (%tdm-hash 4800))
         (ctx (bl.ctx:make-node-context :chain-state state :mempool mempool)))
    (%with-fresh-txdownloadman (mgr mempool)
      (bl.net:txdownload-add-tx-announcement mgr peer wtxid t (bl.ser:get-unix-time))
      (bl.net:txdownload-add-tx-announcement mgr other (%tdm-hash 4801) t (bl.ser:get-unix-time))
      (setf (bl.net:peer-connection peer)
            (make-test-connection :host "127.0.0.1" :port 1 :connected t))
      (let ((sent (captured-sends (lambda () (ignore-errors (drain-peer-once peer ctx))))))
        (is (= 1 (count "getdata" sent :key #'message-command :test #'string=)))
        (is (eq peer (tx-request-in-flight-peer wtxid)))
        (is (null (tx-request-in-flight-peer (%tdm-hash 4801)))
            "the other peer is asked at its own turn")))))
