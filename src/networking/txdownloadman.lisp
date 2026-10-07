(in-package #:bitcoin-lisp.networking)

;;;; Core's TxDownloadManager (src/node/txdownloadman.h, txdownloadman_impl.{h,cpp}
;;;; at d3056bc) as one object.
;;;
;;; It decides which transactions to request and, once they arrive, whether
;;; and how to validate them, and it owns everything that decision reads: the
;;; orphanage, the TxRequestTracker, the three rolling filters -- recent
;;; rejects, recent rejects that a package may still rescue, recently
;;; confirmed -- and each transaction-relay peer's connection facts. The P2P
;;; handlers call its methods at the points net_processing.cpp calls
;;; m_txdownloadman (every call site is named at its caller), and nothing else
;;; reaches the pieces: before this object they were a tracker of globals in
;;; protocol.lisp, an orphanage inside the mempool, the main filter in the
;;; node context and the other two in the validation layer, each read and
;;; written from the handlers directly.
;;;
;;; The node has one, *TXDOWNLOADMAN* (Core's PeerManager has one); a fuzz
;;; target or a test builds its own with MAKE-TXDOWNLOAD-MANAGER.
;;;
;;; A peer is any EQL key -- the node passes PEER structs, a fuzz target small
;;; integers (Core's NodeId). Times are %TX-REQUEST-NOW seconds. A GenTxid is a
;;; hash and a WTXIDP flag.

(defconstant +max-peer-tx-request-in-flight+ 100
  "In-flight request count above which a peer's further announcements get the
overloaded delay (Core MAX_PEER_TX_REQUEST_IN_FLIGHT, txdownloadman.h:25).")
(defconstant +max-peer-tx-announcements+ 5000
  "Per-peer cap on tracked tx announcements; beyond it new announcements from
the peer are dropped (Core MAX_PEER_TX_ANNOUNCEMENTS, txdownloadman.h:30).")
(defconstant +txid-relay-delay-seconds+ 2
  "Extra delay for txid-based announcements while wtxid-relay peers are
connected — preferring the malleation-proof id (Core TXID_RELAY_DELAY,
txdownloadman.h:32).")
(defconstant +nonpref-peer-tx-delay-seconds+ 2
  "Request delay for announcements from non-preferred (inbound) peers (Core
NONPREF_PEER_TX_DELAY, txdownloadman.h:34).")
(defconstant +overloaded-peer-tx-delay-seconds+ 2
  "Extra delay for announcements from overloaded peers (Core
OVERLOADED_PEER_TX_DELAY, txdownloadman.h:36).")
(defconstant +getdata-tx-interval-seconds+ 60
  "How long a tx getdata is outstanding before the request expires and another
announcer is asked (Core GETDATA_TX_INTERVAL, txdownloadman.h:38).")

(alexandria:define-constant +reconsiderable-tx-failures+
  '(:insufficient-fee :mempool-min-fee-not-met :rbf-insufficient-fee
    :replacement-failed :mempool-full)
  :test #'equalp :documentation "The rejection reasons Bitcoin Core classifies TX_RECONSIDERABLE — \"fails
some policy, but might be acceptable if submitted in a (different) package\"
(consensus/validation.h:48). Core's four sites: both fee-floor failures in
CheckFeeRate (validation.cpp:703-711), the RBF anti-DoS fee check (:1010) —
our :rbf-insufficient-fee — and the RBF diagram check (:1028) — our
:replacement-failed — and \"mempool full\", i.e. a tx that self-evicted on the
post-add trim (:1399-1402).

NOT reconsiderable, and so still cached in the MAIN filter: :too-large-cluster
(Core TX_MEMPOOL_POLICY, validation.cpp:1020-1022) — a cluster-limit failure
is not a fee problem and a package cannot fix it.")

(defun %reconsiderable-failure-p (reason)
  "T if REASON is one Core would mark TX_RECONSIDERABLE. A verdict that
carries Core's debug message is the list (KEYWORD DETAIL); the class is the
KEYWORD's."
  (and (member (bl.val:tx-reject-keyword reason) +reconsiderable-tx-failures+)
       t))

(defun %tx-hex (hash)
  "HASH as Core's uint256::ToString prints it: the wire bytes reversed."
  (bl.crypto:bytes-to-hex (bl.crypto:reverse-bytes hash)))

(defstruct (txdownload-connection-info (:conc-name txdl-info-))
  "Core TxDownloadConnectionInfo (txdownloadman.h:51-58): what a peer's
announcements are scheduled by, fixed when it connects."
  (preferred nil :type boolean)
  (relay-permissions nil :type boolean)
  (wtxid-relay nil :type boolean))

(defstruct (package-to-validate (:conc-name ptv-))
  "Core PackageToValidate (txdownloadman.h:60-95): a 1-parent-1-child package
and the peer each transaction came from."
  parent child parent-sender child-sender)

(defun ptv-txns (ptv)
  "The package's transactions, parent first (Core m_txns)."
  (list (ptv-parent ptv) (ptv-child ptv)))

(defstruct (txdownload-manager
            (:constructor make-txdownload-manager
                (&key mempool
                      (orphanage (bl.mp:make-orphan-pool))
                      (random-state (make-random-state t))))
            (:conc-name txdownload-))
  "Core TxDownloadManagerImpl (txdownloadman_impl.h:20-200)."
  ;; Core TxDownloadOptions::m_mempool, read only: AlreadyHaveTx asks it.
  mempool
  ;; Core m_orphanage.
  (orphanage (bl.mp:make-orphan-pool) :type bl.mp:orphan-pool)
  ;; Core m_txrequest.
  (txrequest (make-tx-request-tracker) :type tx-request-tracker)
  ;; The three rolling bloom filters, built on first use as Core's m_lazy_*
  ;; are (TXDOWNLOAD-RECENT-REJECTS and its two siblings below).
  (%recent-rejects nil)
  (%recent-rejects-reconsiderable nil)
  (%recent-confirmed nil)
  ;; Core m_peer_info (:140-143): peer -> TXDOWNLOAD-CONNECTION-INFO.
  (peer-info (make-hash-table :test 'eql) :type hash-table)
  ;; Core m_num_wtxid_peers (:146).
  (num-wtxid-peers 0 :type fixnum)
  ;; Core TxDownloadOptions::m_rng: the orphanage's work-set draw.
  (random-state (make-random-state t))
  ;; Core m_tx_download_mutex, taken here rather than by every caller.
  (lock (bt:make-recursive-lock "txdownloadman")))

(defun txdownload-recent-rejects (mgr)
  "Core RecentRejectsFilter() (txdownloadman_impl.h:61-66): wtxids -- and the
txid where no witness can change the verdict -- of transactions the mempool
refused, a CRollingBloomFilter of 120,000 at a false-positive rate of one in
a million, built on first use. Reset on every tip change outside IBD."
  (or (txdownload-%recent-rejects mgr)
      (setf (txdownload-%recent-rejects mgr) (make-rolling-bloom-filter 120000 0.000001d0))))

(defun txdownload-recent-rejects-reconsiderable (mgr)
  "Core RecentRejectsReconsiderableFilter() (:91-96): wtxids that failed for a
reason a package may overcome, and the hashes of 1p1c packages that failed;
120,000 at one in a million, built on first use."
  (or (txdownload-%recent-rejects-reconsiderable mgr)
      (setf (txdownload-%recent-rejects-reconsiderable mgr)
            (make-rolling-bloom-filter 120000 0.000001d0))))

(defun txdownload-recent-confirmed (mgr)
  "Core RecentConfirmedTransactionsFilter() (:120-128): txids and wtxids of
recently confirmed transactions, 48,000 at one in a million, built on first
use. Reset on a block disconnect."
  (or (txdownload-%recent-confirmed mgr)
      (setf (txdownload-%recent-confirmed mgr) (make-rolling-bloom-filter 48000 0.000001d0))))

(defmacro with-txdownload-lock ((mgr) &body body)
  `(bt:with-recursive-lock-held ((txdownload-lock ,mgr))
     ,@body))

(defun node-txdownloadman (&optional mempool)
  "The node's TxDownloadManager, built on first use. MEMPOOL, when given, is
the node context's mempool and becomes the one the manager reads -- the node
has one, and Core's TxDownloadOptions::m_mempool is a reference to it; a test
that builds its own mempool hands it over the same way."
  (let ((mgr (or *txdownloadman*
                 (setf *txdownloadman* (make-txdownload-manager)))))
    (when (and mempool (not (eq mempool (txdownload-mempool mgr))))
      (setf (txdownload-mempool mgr) mempool))
    mgr))

(defun ctx-txdownloadman (ctx)
  "The TxDownloadManager a handler acting on node context CTX drives: the
context's own, or the node's (NODE-TXDOWNLOADMAN, reading CTX's mempool). A
NIL context is the node's."
  (or (and ctx (bl.ctx:node-context-txdownloadman ctx))
      (node-txdownloadman (and ctx (bl.ctx:node-context-mempool ctx)))))

(defun reset-txdownloadman (&optional mempool)
  "Give the node a fresh TxDownloadManager reading MEMPOOL (node start; a test
that must not inherit another's announcements, orphans or filters)."
  (setf *txdownloadman* (make-txdownload-manager :mempool mempool)))

;;; --- Chain events (Core :91-123) ---

(defun txdownload-active-tip-change (mgr)
  "Core ActiveTipChange (txdownloadman_impl.cpp:92-96): a new tip may make a
rejected transaction valid -- a timelock, a fee floor -- so both rejection
filters start over."
  (with-txdownload-lock (mgr)
    (rolling-bloom-reset (txdownload-recent-rejects mgr))
    (rolling-bloom-reset (txdownload-recent-rejects-reconsiderable mgr))))

(defun txdownload-block-connected (mgr block)
  "Core BlockConnected (txdownloadman_impl.cpp:98-110): the block's orphans
and their conflicts leave the orphanage, every transaction it confirmed is
remembered by txid and (when different) wtxid, and every peer's announcement
of it is forgotten under both ids -- it is resolved, so asking anyone for it
would buy a whole redundant body."
  (with-txdownload-lock (mgr)
    (bl.mp:orphan-erase-for-block (txdownload-orphanage mgr) block)
    (let ((confirmed (txdownload-recent-confirmed mgr))
          (tr (txdownload-txrequest mgr)))
      (bl.ser:dovector (tx (bl.ser:bitcoin-block-transactions block))
        (let ((txid (bl.ser:transaction-hash tx))
              (wtxid (bl.ser:transaction-wtxid tx)))
          (rolling-bloom-insert confirmed txid)
          (unless (equalp wtxid txid)
            (rolling-bloom-insert confirmed wtxid))
          (txrequest-forget-tx-hash tr txid)
          (txrequest-forget-tx-hash tr wtxid))))))

(defun txdownload-block-disconnected (mgr)
  "Core BlockDisconnected (txdownloadman_impl.cpp:112-123): a reorg may return
confirmed transactions to circulation, so the recently-confirmed filter is
cleared rather than allowed to block their relay."
  (with-txdownload-lock (mgr)
    (rolling-bloom-reset (txdownload-recent-confirmed mgr))))

;;; --- AlreadyHaveTx (Core :125-147) ---

(defun txdownload-already-have-tx-p (mgr hash wtxidp include-reconsiderable)
  "Core AlreadyHaveTx (txdownloadman_impl.cpp:125-147): the orphanage (HASH
cast to a wtxid — never a real txid lookup, witness malleation makes txid
matches unreliable; for non-segwit txs txid == wtxid so the cast still finds
them), the reconsiderable filter when INCLUDE-RECONSIDERABLE, the
recently-confirmed filter, recent rejects, and the mempool by the id the
GenTxid names.

INCLUDE-RECONSIDERABLE is true at exactly one site, AddTxAnnouncement (:199):
a transaction that failed reconsiderably must not be downloaded to be
submitted alone again. Every other caller asks \"can this still be
resolved?\", notably when filtering an orphan's missing parents, since a
low-feerate parent is exactly what the orphan may be able to fee-bump."
  (with-txdownload-lock (mgr)
    (let ((mempool (txdownload-mempool mgr)))
      (or (bl.mp:orphan-have (txdownload-orphanage mgr) hash)
          (and include-reconsiderable
               (rolling-bloom-contains-p (txdownload-recent-rejects-reconsiderable mgr) hash))
          (rolling-bloom-contains-p (txdownload-recent-confirmed mgr) hash)
          (rolling-bloom-contains-p (txdownload-recent-rejects mgr) hash)
          (and mempool
               (if wtxidp
                   (bl.mp:mempool-get-by-wtxid mempool hash)
                   (bl.mp:mempool-has mempool hash))
               t)))))

;;; --- Peers (Core :149-168) ---

(defun tx-request-preferred-p (peer)
  "Preferred announcers are requested first and without the non-preferred
delay (Core's m_preferred = fPreferredDownload, net_processing.cpp:3750 and
:3892): an outbound connection, or an inbound one holding the noban
permission, and never an addr-fetch connection. p2p_tx_download.py:231-234
whitelists noban@127.0.0.1 and expects an inbound peer's inv to be fetched at
once. Core's third term, CanServeBlocks, is left out here: it is about BLOCK
download, every peer the tx tests make advertises NODE_NETWORK anyway, and
the synthetic peers of our own suites do not (PEER-PREFERRED-DOWNLOAD-P keeps
it for the headers timeout, where it matters)."
  (and (or (not (peer-inbound peer))
           (peer-has-permission-p peer +perm-noban+))
       (not (eq (peer-conn-type peer) :addr-fetch))))

(defun txdownload-connection-info-for (peer)
  "The connection facts Core hands ConnectedPeer at VERACK
(net_processing.cpp:3888-3895), read from PEER: preferred download, the relay
permission, and whether it negotiated wtxidrelay."
  (make-txdownload-connection-info
   :preferred (and (tx-request-preferred-p peer) t)
   :relay-permissions (and (peer-has-permission-p peer +perm-relay+) t)
   :wtxid-relay (and (peer-wtxid-relay peer) t)))

(defun txdownload-connected-peer (mgr peer info)
  "Core ConnectedPeer (txdownloadman_impl.cpp:149-156): register PEER's
connection INFO; a peer already registered is left as it is."
  (with-txdownload-lock (mgr)
    (unless (gethash peer (txdownload-peer-info mgr))
      (setf (gethash peer (txdownload-peer-info mgr)) info)
      (when (txdl-info-wtxid-relay info)
        (incf (txdownload-num-wtxid-peers mgr))))))

(defun txdownload-disconnected-peer (mgr peer)
  "Core DisconnectedPeer (txdownloadman_impl.cpp:158-168): PEER's orphan
announcements and tracked announcements go -- its in-flight requests become
the next candidate's -- and so does its registration."
  (with-txdownload-lock (mgr)
    (bl.mp:orphan-erase-for-peer (txdownload-orphanage mgr) peer)
    (txrequest-disconnected-peer (txdownload-txrequest mgr) peer)
    (let ((info (gethash peer (txdownload-peer-info mgr))))
      (when info
        (when (txdl-info-wtxid-relay info)
          (decf (txdownload-num-wtxid-peers mgr)))
        (remhash peer (txdownload-peer-info mgr))))))

(defun %txdownload-peer-info (mgr peer)
  "PEER's registered connection facts (Core m_peer_info.find), or NIL. A
:READY peer struct that was never registered is registered on first contact:
every peer of the node passes through %AWAIT-VERACK, which registers it, so
this arm is the unit suites', whose peers are built :READY directly."
  (or (gethash peer (txdownload-peer-info mgr))
      (when (and (peer-p peer) (eq (peer-state peer) :ready))
        (txdownload-connected-peer mgr peer (txdownload-connection-info-for peer))
        (gethash peer (txdownload-peer-info mgr)))))

;;; --- Announcements and requests (Core :170-295) ---

(defun %txdownload-request-delay (mgr peer info txid-based-p)
  "The reqtime delay Core adds in AddTxAnnouncement and
MaybeAddOrphanResolutionCandidate (txdownloadman_impl.cpp:215-219, :245-253):
NONPREF for a non-preferred peer, TXID_RELAY for a txid while any wtxid-relay
peer is connected, OVERLOADED for a peer without the relay permission holding
MAX_PEER_TX_REQUEST_IN_FLIGHT requests."
  (+ (if (txdl-info-preferred info) 0 +nonpref-peer-tx-delay-seconds+)
     (if (and txid-based-p (plusp (txdownload-num-wtxid-peers mgr)))
         +txid-relay-delay-seconds+ 0)
     (if (and (not (txdl-info-relay-permissions info))
              (>= (txrequest-count-in-flight (txdownload-txrequest mgr) peer)
                  +max-peer-tx-request-in-flight+))
         +overloaded-peer-tx-delay-seconds+ 0)))

(defun unique-parent-txids (tx)
  "Core GetUniqueParents (txdownloadman_impl.cpp:335-347): the txids TX's
inputs spend, deduplicated and sorted as Core sorts them (uint256 order).
Nothing is filtered here; the callers apply AlreadyHaveTx and the
rejected-parents scan."
  (let ((parents '()))
    (bl.ser:dovector (input (bl.ser:transaction-inputs tx))
      (pushnew (bl.ser:outpoint-hash (bl.ser:tx-in-previous-output input))
               parents :test #'equalp))
    (sort parents #'bl.bytes:octets<)))

(defun %maybe-add-orphan-resolution-candidate (mgr unique-parents wtxid peer now)
  "Core MaybeAddOrphanResolutionCandidate (txdownloadman_impl.cpp:226-262):
treat PEER as having announced every txid in UNIQUE-PARENTS -- the missing
parents of orphan WTXID -- with the delays an announcement would carry, the
txid delay whenever wtxid-relay peers exist (the parent and child may simply
have arrived out of order). Refused for an unregistered peer, one already an
announcer of the orphan, and one without the relay permission whose tracked
announcements plus these would pass MAX_PEER_TX_ANNOUNCEMENTS. Returns T when
PEER was enrolled."
  (let ((info (%txdownload-peer-info mgr peer))
        (tr (txdownload-txrequest mgr)))
    (when (and info
               (not (bl.mp:orphan-have-from-peer (txdownload-orphanage mgr) wtxid peer))
               (or (txdl-info-relay-permissions info)
                   (<= (+ (txrequest-count tr peer) (length unique-parents))
                       +max-peer-tx-announcements+)))
      (let ((reqtime (+ now (%txdownload-request-delay mgr peer info t))))
        (dolist (parent unique-parents)
          (txrequest-received-inv tr peer parent nil (txdl-info-preferred info) reqtime)))
      (bl:log-cat "txpackages" "added peer=~D as a candidate for resolving orphan ~A"
                  (%tx-peer-node-id peer)
                  (%tx-hex wtxid))
      t)))

(defun txdownload-add-tx-announcement (mgr peer hash wtxidp now)
  "Core AddTxAnnouncement (txdownloadman_impl.cpp:170-224): PEER announced
HASH (a wtxid when WTXIDP) at NOW. A wtxid naming an orphan makes PEER a
resolution candidate for the orphan's missing parents instead; otherwise an
announcement of something we already have -- the reconsiderable filter
included -- is dropped, and anything else is tracked with the peer's delays,
unless PEER is unregistered or, without the relay permission, already at
MAX_PEER_TX_ANNOUNCEMENTS. Returns T when the announcement was for something
we already have (Core's `fAlreadyHave')."
  (with-txdownload-lock (mgr)
    (let ((orphanage (txdownload-orphanage mgr))
          (tr (txdownload-txrequest mgr)))
      (when wtxidp
        (let ((orphan (bl.mp:orphan-tx orphanage hash)))
          (when orphan
            (let ((parents (remove-if (lambda (txid)
                                        (txdownload-already-have-tx-p mgr txid nil nil))
                                      (unique-parent-txids orphan))))
              ;; The missing parents may all have been accepted or rejected
              ;; since; the orphan may be queued for processing (:183-187).
              (when (and parents
                         (%maybe-add-orphan-resolution-candidate mgr parents hash peer now))
                (bl.mp:orphan-add orphanage orphan peer)))
            (return-from txdownload-add-tx-announcement t))))
      (when (txdownload-already-have-tx-p mgr hash wtxidp t)
        (return-from txdownload-add-tx-announcement t))
      (let ((info (%txdownload-peer-info mgr peer)))
        (when (and info
                   (or (txdl-info-relay-permissions info)
                       (< (txrequest-count tr peer) +max-peer-tx-announcements+)))
          (txrequest-received-inv tr peer hash wtxidp (txdl-info-preferred info)
                                  (+ now (%txdownload-request-delay mgr peer info
                                                                    (not wtxidp))))))
      nil)))

(defun txdownload-get-requests-to-send (mgr peer now)
  "Core GetRequestsToSend (txdownloadman_impl.cpp:264-286): what PEER should
be asked for at NOW, as (hash . wtxidp) in announcement order, each marked
REQUESTED until NOW + GETDATA_TX_INTERVAL. Requests that expired by NOW are
logged; one for a transaction we have acquired some other way since its
announcement is forgotten instead of sent -- \"just a belt-and-suspenders\",
as everything that makes a transaction AlreadyHaveTx already forgets it."
  (with-txdownload-lock (mgr)
    (let ((tr (txdownload-txrequest mgr))
          (requests '()))
      (multiple-value-bind (requestable expired) (txrequest-get-requestable tr peer now)
        (loop for (expired-peer hash . wtxidp) in expired
              do (bl:log-cat "net" "timeout of inflight ~:[tx~;wtx~] ~A from peer=~D"
                             wtxidp (%tx-hex hash)
                             (%tx-peer-node-id expired-peer)))
        (loop for (hash . wtxidp) in requestable
              do (cond ((txdownload-already-have-tx-p mgr hash wtxidp nil)
                        (txrequest-forget-tx-hash tr hash))
                       (t
                        (bl:log-cat "net" "Requesting ~:[tx~;wtx~] ~A peer=~D"
                                    wtxidp (%tx-hex hash)
                                    (%tx-peer-node-id peer))
                        (push (cons hash wtxidp) requests)
                        (txrequest-requested-tx tr peer hash
                                                (+ now +getdata-tx-interval-seconds+))))))
      (nreverse requests))))

(defun txdownload-received-not-found (mgr peer hashes)
  "Core ReceivedNotFound (txdownloadman_impl.cpp:288-295): PEER cannot serve
HASHES, so each of its announcements completes and the next announcer is
asked at its own turn."
  (with-txdownload-lock (mgr)
    (dolist (hash hashes)
      (txrequest-received-response (txdownload-txrequest mgr) peer hash))))

;;; --- Validation results (Core :297-503) ---

(defun %find-1p1c-package (mgr parent peer)
  "Core Find1P1CPackage (txdownloadman_impl.cpp:297-321): the newest orphan
PEER announced that spends PARENT and whose pairing with it is not already
known to fail -- the package hash in the reconsiderable filter, or the child's
TXID in the main filter -- as a PACKAGE-TO-VALIDATE, or NIL. Only PEER's own
orphans are candidates, so a flood of fake children from someone else cannot
crowd out the honest peer's real one."
  (let ((reconsiderable (txdownload-recent-rejects-reconsiderable mgr)))
    (dolist (child (bl.mp:orphan-children-from-peer (txdownload-orphanage mgr) parent peer))
      (unless (or (rolling-bloom-contains-p reconsiderable
                                      (bl.val:package-hash (list parent child)))
                  (rolling-bloom-contains-p (txdownload-recent-rejects mgr)
                                      (bl.ser:transaction-hash child)))
        (return (make-package-to-validate :parent parent :child child
                                          :parent-sender peer :child-sender peer))))))

(defun txdownload-mempool-accepted-tx (mgr tx)
  "Core MempoolAcceptedTx (txdownloadman_impl.cpp:323-333): TX is in the
mempool, so every request for it goes under both ids, the orphans spending it
join their announcers' work sets, and it leaves the orphanage if it was there."
  (with-txdownload-lock (mgr)
    (let ((tr (txdownload-txrequest mgr))
          (orphanage (txdownload-orphanage mgr)))
      (txrequest-forget-tx-hash tr (bl.ser:transaction-hash tx))
      (txrequest-forget-tx-hash tr (bl.ser:transaction-wtxid tx))
      (bl.mp:orphan-add-children-to-work-set orphanage tx (txdownload-random-state mgr))
      (bl.mp:orphan-remove orphanage (bl.ser:transaction-wtxid tx)))))

(defun %orphan-parents-rejected-p (mgr parents)
  "Core's fRejectedParents scan (txdownloadman_impl.cpp:371-389): T when an
orphan with these unique PARENTS must not be kept at all. A parent in the main
rejects filter is fatal; ONE parent in the reconsiderable filter is tolerated
-- it may be precisely the low-feerate parent this child exists to fee-bump,
and only 1-parent-1-child packages are ever submitted -- unless it has since
entered the mempool, when it does not count at all."
  (let ((reconsiderable 0)
        (mempool (txdownload-mempool mgr)))
    (dolist (txid parents nil)
      (cond ((rolling-bloom-contains-p (txdownload-recent-rejects mgr) txid)
             (return t))
            ((and (rolling-bloom-contains-p (txdownload-recent-rejects-reconsiderable mgr) txid)
                  (not (and mempool (bl.mp:mempool-has mempool txid))))
             (when (> (incf reconsiderable) 1)
               (return t)))))))

(defun %txdownload-take-orphan (mgr tx peer parents now)
  "The keep branch of Core's TX_MISSING_INPUTS arm (txdownloadman_impl.cpp:
390-420): enrol PEER and every other live announcer of the orphan, by txid and
-- when it has a witness -- wtxid, as resolution candidates; each one enrolled
holds an announcement in the orphanage. Then the orphan is forgotten by the
tracker under both ids: once in the orphanage it is AlreadyHave. Enrolling
before forgetting is what lets GetCandidatePeers find the announcers at all."
  (let* ((tr (txdownload-txrequest mgr))
         (txid (bl.ser:transaction-hash tx))
         (wtxid (bl.ser:transaction-wtxid tx))
         (candidates (list peer)))
    (dolist (p (txrequest-get-candidate-peers tr txid))
      (pushnew p candidates))
    (unless (equalp wtxid txid)
      (dolist (p (txrequest-get-candidate-peers tr wtxid))
        (pushnew p candidates)))
    (dolist (candidate (nreverse candidates))
      (when (%maybe-add-orphan-resolution-candidate mgr parents wtxid candidate now)
        (bl.mp:orphan-add (txdownload-orphanage mgr) tx candidate)))
    (txrequest-forget-tx-hash tr txid)
    (txrequest-forget-tx-hash tr wtxid)))

(defun %txdownload-missing-inputs (mgr tx peer first-time-failure)
  "Core's TX_MISSING_INPUTS arm (txdownloadman_impl.cpp:361-437). Returns the
unique parents to mark known to PEER, and whether the transaction is new to the
orphanage (which decides the compact-block extra pool)."
  (let* ((wtxid (bl.ser:transaction-wtxid tx))
         (txid (bl.ser:transaction-hash tx))
         (rejects (txdownload-recent-rejects mgr))
         (tr (txdownload-txrequest mgr)))
    ;; Only a first-time failure is a new orphan; at false it is already in the
    ;; orphanage or came from 1p1c processing (:362-364).
    (unless (and first-time-failure (not (rolling-bloom-contains-p rejects wtxid)))
      (return-from %txdownload-missing-inputs (values '() t)))
    (let ((parents (unique-parent-txids tx)))
      (cond
        ((%orphan-parents-rejected-p mgr parents)
         ;; Core's line (:423-425); p2p_invalid_tx.py:153 waits for it. Both
         ;; ids: whatever witness comes, its parents make it unacceptable.
         (bl:log-cat "mempool" "not keeping orphan with rejected parents ~A (wtxid=~A)"
                     (%tx-hex txid)
                     (%tx-hex wtxid))
         (rolling-bloom-insert rejects txid)
         (rolling-bloom-insert rejects wtxid)
         (txrequest-forget-tx-hash tr txid)
         (txrequest-forget-tx-hash tr wtxid)
         (values '() t))
        (t
         ;; Exclude the reconsiderable filter: the missing parent may be the
         ;; low-feerate one this orphan can CPFP (:391-396).
         (let ((missing (remove-if (lambda (p) (txdownload-already-have-tx-p mgr p nil nil))
                                   parents))
               (already-held (bl.mp:orphan-have (txdownload-orphanage mgr) wtxid)))
           (%txdownload-take-orphan mgr tx peer missing (%tx-request-now))
           (values missing (not already-held))))))))

(defun txdownload-mempool-rejected-tx (mgr tx reason peer first-time-failure)
  "Core MempoolRejectedTx (txdownloadman_impl.cpp:350-498): record why TX from
PEER was refused, where Core records it, and say what the caller should do.

  - :missing-input is orphan INTAKE, and only for a FIRST-TIME failure; a
    parent in the main filter, or more than one reconsiderable parent,
    rejects it under both ids instead.
  - :witness-stripped is cached nowhere: its txid equals its wtxid, and
    caching would poison the real, witnessed transaction.
  - A RECONSIDERABLE failure goes to the second filter by wtxid, and a
    first-time one looks for a child in the orphanage to try as a package.
  - Anything else goes to the main filter by wtxid -- the witness is
    malleable (Core issue #8279) -- plus the txid for :nonstandard-inputs,
    a verdict on the scriptPubKeys spent, which the txid commits to.

Every verdict but :missing-input forgets the tracked wtxid, and takes TX out
of the orphanage. Returns three values, Core's RejectedTxTodo: whether TX
belongs in the compact-block extra pool, the parents to mark known to PEER,
and a PACKAGE-TO-VALIDATE or NIL."
  (with-txdownload-lock (mgr)
    (let ((kind (bl.val:tx-reject-keyword reason))
          (wtxid (bl.ser:transaction-wtxid tx))
          (txid (bl.ser:transaction-hash tx))
          (tr (txdownload-txrequest mgr))
          (add-extra first-time-failure)
          (parents '())
          (package nil))
      (cond
        ((eq kind :missing-input)
         (multiple-value-bind (missing new-orphan-p)
             (%txdownload-missing-inputs mgr tx peer first-time-failure)
           (setf parents missing
                 add-extra (and add-extra new-orphan-p))))
        ((eq kind :witness-stripped)
         (setf add-extra nil))
        (t
         (cond ((%reconsiderable-failure-p reason)
                (rolling-bloom-insert (txdownload-recent-rejects-reconsiderable mgr) wtxid)
                (when first-time-failure
                  (bl:log-cat "txpackages" "tx ~A (wtxid=~A) failed but reconsiderable, looking for child in orphanage"
                              (%tx-hex txid)
                              (%tx-hex wtxid))
                  (setf package (%find-1p1c-package mgr tx peer))))
               (t (rolling-bloom-insert (txdownload-recent-rejects mgr) wtxid)))
         (txrequest-forget-tx-hash tr wtxid)
         (when (and (eq kind :nonstandard-inputs) (not (equalp wtxid txid)))
           (rolling-bloom-insert (txdownload-recent-rejects mgr) txid)
           (txrequest-forget-tx-hash tr txid))))
      ;; A transaction that failed for any reason but a missing input leaves
      ;; the orphanage (:487-491).
      (when (and (not (eq kind :missing-input))
                 (bl.mp:orphan-remove (txdownload-orphanage mgr) wtxid))
        (bl:log-cat "txpackages" "   removed orphan tx ~A (wtxid=~A)"
                    (%tx-hex txid)
                    (%tx-hex wtxid)))
      (values add-extra parents package))))

(defun txdownload-mempool-rejected-package (mgr txns)
  "Core MempoolRejectedPackage (txdownloadman_impl.cpp:500-503): this
combination of transactions failed as a package and is not tried again."
  (with-txdownload-lock (mgr)
    (rolling-bloom-insert (txdownload-recent-rejects-reconsiderable mgr)
                          (bl.val:package-hash txns))))

(defun txdownload-received-tx (mgr peer tx)
  "Core ReceivedTx (txdownloadman_impl.cpp:505-555): TX arrived from PEER.
Only PEER's announcements of it complete -- under the txid, and the wtxid when
it has a witness -- so an unsolicited copy or a witness-malleated twin cannot
release every honest announcer. Returns (values should-validate package): NIL
for something AlreadyHaveTx knows by wtxid (never by txid: a malleated twin
would otherwise hide the real one), NIL and the 1p1c package to try for one
already known to fail reconsiderably, T otherwise."
  (with-txdownload-lock (mgr)
    (let ((txid (bl.ser:transaction-hash tx))
          (wtxid (bl.ser:transaction-wtxid tx))
          (tr (txdownload-txrequest mgr)))
      (txrequest-received-response tr peer txid)
      (unless (equalp wtxid txid)
        (txrequest-received-response tr peer wtxid))
      (cond ((txdownload-already-have-tx-p mgr wtxid t nil)
             (values nil nil))
            ((rolling-bloom-contains-p (txdownload-recent-rejects-reconsiderable mgr) wtxid)
             (bl:log-cat "txpackages" "found tx ~A (wtxid=~A) in reconsiderable rejects, looking for child in orphanage"
                         (%tx-hex txid)
                         (%tx-hex wtxid))
             (values nil (%find-1p1c-package mgr tx peer)))
            (t (values t nil))))))

;;; --- The work set (Core :557-565) ---

(defun txdownload-have-more-work (mgr peer)
  "Core HaveMoreWork (txdownloadman_impl.cpp:557-560): PEER has an orphan in
its work set."
  (with-txdownload-lock (mgr)
    (bl.mp:orphan-have-tx-to-reconsider (txdownload-orphanage mgr) peer)))

(defun txdownload-get-tx-to-reconsider (mgr peer)
  "Core GetTxToReconsider (txdownloadman_impl.cpp:562-565): the next orphan
from PEER's work set, or NIL."
  (with-txdownload-lock (mgr)
    (bl.mp:orphan-get-tx-to-reconsider (txdownload-orphanage mgr) peer)))

;;; --- Consistency (Core :567-583) ---

(defun txdownload-check-is-empty (mgr &optional (peer nil peer-p))
  "Core CheckIsEmpty (txdownloadman_impl.cpp:567-578) as the list of what is
NOT empty: with PEER, nothing tracked or orphaned for it; without, nothing at
all and no wtxid-relay peer counted. TXDOWNLOAD-ASSERT-EMPTY is Core's
assert over it."
  (with-txdownload-lock (mgr)
    (let ((tr (txdownload-txrequest mgr))
          (orphanage (txdownload-orphanage mgr))
          (problems '()))
      (if peer-p
          (progn
            (unless (zerop (txrequest-count tr peer))
              (push "tracked announcements remain for the peer" problems))
            (unless (zerop (bl.mp:orphan-usage-by-peer orphanage peer))
              (push "orphan usage remains for the peer" problems)))
          (progn
            (unless (zerop (bl.mp:orphan-total-usage orphanage))
              (push "orphan usage remains" problems))
            (unless (zerop (bl.mp:orphan-pool-count orphanage))
              (push "orphans remain" problems))
            (unless (zerop (txrequest-size tr))
              (push "tracked announcements remain" problems))
            (unless (zerop (txdownload-num-wtxid-peers mgr))
              (push "wtxid-relay peers are still counted" problems))))
      (nreverse problems))))

(define-condition txdownload-check-failed (internal-error) ()
  (:documentation "A TxDownloadManager CheckIsEmpty did not hold: state is
left for a peer that is gone, or for anyone once every peer is. Core asserts,
which aborts the node; we log the failure and signal this, as the mempool's
consistency check does (MEMPOOL-CHECK-FAILED)."))

(defun txdownload-assert-empty (mgr &optional (peer nil peer-p))
  "Core's CheckIsEmpty asserts (txdownloadman_impl.cpp:567-578): signal
TXDOWNLOAD-CHECK-FAILED when TXDOWNLOAD-CHECK-IS-EMPTY finds anything -- for
PEER when given, else overall."
  (let ((problems (if peer-p
                      (txdownload-check-is-empty mgr peer)
                      (txdownload-check-is-empty mgr))))
    (when problems
      (let ((message (format nil "~:[~*~;peer=~D: ~]~{~A~^; ~}"
                             peer-p (and peer-p (%tx-peer-node-id peer)) problems)))
        (bl:log-warn "TxDownloadManager CheckIsEmpty failed: ~A" message)
        (error 'txdownload-check-failed
               :format-control "TxDownloadManager CheckIsEmpty failed: ~A"
               :format-arguments (list message))))))

(defun txdownload-peer-count (mgr)
  "How many peers are registered (Core m_peer_info.size())."
  (with-txdownload-lock (mgr)
    (hash-table-count (txdownload-peer-info mgr))))

(defun txdownload-get-orphan-transactions (mgr)
  "Core GetOrphanTransactions (txdownloadman_impl.cpp:579-582): every orphan as
(transaction . announcers), for getorphantxs."
  (with-txdownload-lock (mgr)
    (bl.mp:orphan-transactions (txdownload-orphanage mgr))))
