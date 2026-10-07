(in-package #:bitcoin-lisp.mempool)

;;; Orphan transaction pool — a port of Bitcoin Core's TxOrphanage at ref
;;; d3056bc (src/node/txorphanage.{h,cpp}).
;;;
;;; Holds transactions whose inputs reference outputs not yet available
;;; (neither confirmed nor in the mempool). When a parent later arrives, its
;;; children are re-evaluated (the de-orphan cascade lives in the networking
;;; layer).
;;;
;;; Core's current shape (post per-peer-limits overhaul, txorphanage.h:25-36):
;;;  - Orphans are keyed by WTXID; the same txid may appear under multiple
;;;    wtxids (witness malleation), and each (wtxid, peer) ANNOUNCEMENT is
;;;    tracked separately so several peers can announce one orphan.
;;;  - Per-peer accounting: each announcement charges its peer the full tx
;;;    weight (memory score) and 1 + floor(inputs/10) (latency score).
;;;  - Global limits scale with the number of peers that have entries:
;;;    usage <= 404,000 weight x npeers, total latency score <= 3,000.
;;;  - Eviction (LimitOrphans) never lets one peer flush another's orphans:
;;;    when over a global limit, the peer with the highest DoS score — the
;;;    max of its latency-score and usage ratios against its per-peer
;;;    allowance — loses its OLDEST announcement, repeatedly, until the pool
;;;    is back within limits. An orphan only disappears once its last
;;;    announcement does.
;;;  - EraseForPeer removes a disconnecting peer's announcements (not the
;;;    orphans other peers also announced); EraseForBlock removes orphans
;;;    that are included in or conflict with a connected block, by exact
;;;    spent outpoint.
;;;  - There is NO time-based expiry at d3056bc (the old ORPHAN_TX_EXPIRE_TIME
;;;    scheme is gone); LimitOrphans + EraseForBlock/ForPeer are the only
;;;    eviction paths.
;;;
;;;  - The WORK SET (txorphanage.cpp:527-608): when a parent enters the
;;;    mempool, each orphan spending one of its outputs gets ONE announcement
;;;    -- a random announcer's -- marked RECONSIDER, and that peer's message
;;;    loop takes them one at a time (GetTxToReconsider), so a parent never
;;;    buys a whole cascade of re-validations inside one message: Core's fix
;;;    for the orphan-processing stall it disclosed in 2024
;;;    (net_processing.cpp:3229-3230). A wtxid has at most one reconsider
;;;    announcement (the RECONSIDERABLE-WTXIDS set), and eviction takes a
;;;    peer's non-reconsider announcements before its reconsider ones.
;;;
;;; Representation, documented:
;;;  - Peers are opaque objects compared with EQ (the networking layer, which
;;;    owns the peer struct, loads later). Where Core orders peers by NodeId
;;;    -- LimitOrphans' tie-break -- it asks ORPHAN-PEER-ID, which that layer
;;;    implements for its peer struct.

(defconstant +max-orphanage-latency-score+ 3000
  "Global latency-score budget (announcements + 1 per 10 inputs of each unique
orphan) — Core DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE (txorphanage.h:23).")

(defconstant +reserved-orphan-weight-per-peer+ 404000
  "Per-peer reserved orphan weight; the global usage cap is this times the
number of peers with entries — Core DEFAULT_RESERVED_ORPHAN_WEIGHT_PER_PEER
(txorphanage.h:20).")

(defconstant +orphan-max-tx-weight+ 400000
  "Orphans above max standard tx weight are never stored (send-big-orphans
memory-exhaustion attack) — Core AddTx's MAX_STANDARD_TX_WEIGHT check
(txorphanage.cpp:311-316). Duplicates +max-standard-tx-weight+ from the
validation layer, which loads after this file.")

(defstruct orphan-announcement
  "One (orphan, peer) announcement — Core txorphanage.cpp Announcement.
RECONSIDER is Core's m_reconsider: this announcement is in its peer's work
set (txorphanage.cpp:44-46)."
  (peer nil)
  (sequence 0 :type integer)
  (reconsider nil :type boolean))

(defstruct orphan-entry
  "An orphan transaction awaiting a missing parent, with its announcers."
  (transaction nil :type bl.ser:transaction)
  (txid nil :type (or null (simple-array (unsigned-byte 8) (32))))
  (wtxid nil :type (or null (simple-array (unsigned-byte 8) (32))))
  ;; Usage metric: the transaction weight (Core Announcement::GetMemUsage).
  (weight 0 :type integer)
  ;; Latency metric: 1 + floor(inputs/10) (Core Announcement::GetLatencyScore).
  (latency-score 1 :type integer)
  ;; List of orphan-announcement, one per announcing peer.
  (announcements '() :type list))

(defstruct orphan-peer-info
  "Per-peer orphanage accounting (Core PeerDoSInfo): each announcement adds
the orphan's full weight and latency score."
  (usage 0 :type integer)
  (latency 0 :type integer)
  (count 0 :type integer))

(defstruct orphan-pool
  "Pool of orphan transactions (Core TxOrphanageImpl). MAX-GLOBAL-LATENCY-SCORE
and RESERVED-PEER-USAGE are the two limits Core's constructor takes
(TxOrphanageImpl(max_global_latency_score, reserved_peer_usage),
txorphanage.cpp:190-193; MakeTxOrphanage, :776-783); the node uses Core's
defaults, and a test or fuzz target shrinks them to reach eviction with a
handful of transactions."
  (max-global-latency-score +max-orphanage-latency-score+ :type integer :read-only t)
  (reserved-peer-usage +reserved-orphan-weight-per-peer+ :type integer :read-only t)
  ;; wtxid -> orphan-entry
  (by-wtxid (make-hash-table :test 'equalp) :type hash-table)
  ;; parent txid -> list of orphan wtxids referencing it in some input.
  ;; Core keys m_outpoint_to_orphan_wtxids by exact outpoint; we key by the
  ;; parent txid (the granularity every lookup needs) and verify exact
  ;; outpoints where Core's semantics demand it (orphan-erase-for-block).
  (by-prev (make-hash-table :test 'equalp) :type hash-table)
  ;; peer -> orphan-peer-info; entries are dropped when a peer's count hits 0,
  ;; so disconnected peers are not tracked forever (Core m_peer_orphanage_info).
  (peer-info (make-hash-table :test 'eq) :type hash-table)
  ;; Monotonic announcement sequence (Core m_current_sequence).
  (next-sequence 0 :type integer)
  ;; wtxid -> T for every orphan with (exactly) one RECONSIDER announcement
  ;; (Core m_reconsiderable_wtxids, txorphanage.cpp:122-123).
  (reconsiderable-wtxids (make-hash-table :test 'equalp) :type hash-table)
  ;; Cached aggregates (Core m_orphans.size() / m_unique_orphan_usage /
  ;; m_unique_rounded_input_scores).
  (announcement-count 0 :type integer)
  (unique-usage 0 :type integer)
  (unique-input-score 0 :type integer))

;;;; Lookups

(defun orphan-pool-count (pool)
  "Number of unique orphans, by wtxid (Core CountUniqueOrphans)."
  (hash-table-count (orphan-pool-by-wtxid pool)))

(defun orphan-have (pool wtxid)
  "T if an orphan with WTXID is stored (Core HaveTx). Callers holding only a
txid may pass it 'casted' to a wtxid: for non-segwit txs txid == wtxid, and a
false positive is impossible (Core AlreadyHaveTx's guess, txdownloadman_impl
.cpp:126-141)."
  (and (gethash wtxid (orphan-pool-by-wtxid pool)) t))

(defun orphan-tx (pool wtxid)
  "The transaction for orphan WTXID, or NIL (Core GetTx)."
  (let ((e (gethash wtxid (orphan-pool-by-wtxid pool))))
    (when e (orphan-entry-transaction e))))

(defun orphan-have-from-peer (pool wtxid peer)
  "T if orphan WTXID has an announcement from PEER (Core HaveTxFromPeer)."
  (let ((e (gethash wtxid (orphan-pool-by-wtxid pool))))
    (and e
         (member peer (orphan-entry-announcements e)
                 :key #'orphan-announcement-peer)
         t)))

(defun orphan-announcers (pool wtxid)
  "The peers announcing orphan WTXID (Core OrphanInfo::announcers)."
  (let ((e (gethash wtxid (orphan-pool-by-wtxid pool))))
    (when e
      (mapcar #'orphan-announcement-peer (orphan-entry-announcements e)))))

(defun orphan-children-from-peer (pool parent-tx peer)
  "The orphan transactions PEER announced that spend an output of PARENT-TX,
NEWEST announcement first (Core GetChildrenFromSamePeer,
txorphanage.cpp:645-670). Restricting the search to one peer's own orphans is
the anti-censorship property Core documents there: an attacker flooding us
with fake children of PARENT-TX cannot crowd out the real child supplied by
the honest peer, because we only ever pair a parent with children from the
same announcer. Newest-first matters when children replace one another — the
most recent is usually the highest-feerate one."
  (let ((ptxid (bl.ser:transaction-hash parent-tx))
        (found '()))
    (dolist (wtxid (gethash ptxid (orphan-pool-by-prev pool)))
      (let ((entry (gethash wtxid (orphan-pool-by-wtxid pool))))
        (when entry
          (let ((ann (find peer (orphan-entry-announcements entry)
                           :key #'orphan-announcement-peer)))
            (when ann
              (push (cons (orphan-announcement-sequence ann)
                          (orphan-entry-transaction entry))
                    found))))))
    ;; by-prev is parent-txid-granular, which is exactly the granularity of
    ;; Core's `input.prevout.hash == parent_txid` test, so no per-outpoint
    ;; re-check is needed here (unlike orphan-erase-for-block).
    (mapcar #'cdr (sort found #'> :key #'car))))

;;;; Aggregates (Core's Count/Usage accessors)

(defun orphan-total-latency-score (pool)
  "Deduplicated global latency score: one per announcement plus each unique
orphan's input surcharge (Core TotalLatencyScore, txorphanage.cpp:766)."
  (+ (orphan-pool-unique-input-score pool)
     (orphan-pool-announcement-count pool)))

(defun orphan-total-usage (pool)
  "Total weight of unique orphans (Core TotalOrphanUsage)."
  (orphan-pool-unique-usage pool))

(defun orphan-announcements-from-peer (pool peer)
  "Number of announcements from PEER (Core AnnouncementsFromPeer)."
  (let ((info (gethash peer (orphan-pool-peer-info pool))))
    (if info (orphan-peer-info-count info) 0)))

(defun orphan-usage-by-peer (pool peer)
  "Summed weight of the orphans PEER announced (Core UsageByPeer)."
  (let ((info (gethash peer (orphan-pool-peer-info pool))))
    (if info (orphan-peer-info-usage info) 0)))

(defun orphan-max-peer-latency-score (pool)
  "Per-peer latency allowance: the global budget split across peers with
entries (Core MaxPeerLatencyScore, txorphanage.cpp:768)."
  (floor (orphan-pool-max-global-latency-score pool)
         (max 1 (hash-table-count (orphan-pool-peer-info pool)))))

(defun orphan-max-global-usage (pool)
  "Global usage cap: the per-peer reservation times the number of peers with
entries (Core MaxGlobalUsage, txorphanage.cpp:769)."
  (* (orphan-pool-reserved-peer-usage pool)
     (max 1 (hash-table-count (orphan-pool-peer-info pool)))))

(defun %orphan-needs-trim-p (pool)
  "Core NeedsTrim (txorphanage.cpp:771-774)."
  (or (> (orphan-total-latency-score pool) (orphan-pool-max-global-latency-score pool))
      (> (orphan-total-usage pool) (orphan-max-global-usage pool))))

;;;; Internal add/remove plumbing

(defun %orphan-latency-score (tx)
  "1 + floor(inputs/10) (Core Announcement::GetLatencyScore)."
  (1+ (floor (length (bl.ser:transaction-inputs tx)) 10)))

(defun %orphan-peer-info-add (pool peer entry)
  (let ((info (or (gethash peer (orphan-pool-peer-info pool))
                  (setf (gethash peer (orphan-pool-peer-info pool))
                        (make-orphan-peer-info)))))
    (incf (orphan-peer-info-usage info) (orphan-entry-weight entry))
    (incf (orphan-peer-info-latency info) (orphan-entry-latency-score entry))
    (incf (orphan-peer-info-count info))))

(defun %orphan-peer-info-subtract (pool peer entry)
  "Subtract one announcement of ENTRY from PEER's accounting; drop the peer's
record entirely at count 0 (Core Erase, txorphanage.cpp:240-246)."
  (let ((info (gethash peer (orphan-pool-peer-info pool))))
    (when info
      (decf (orphan-peer-info-usage info) (orphan-entry-weight entry))
      (decf (orphan-peer-info-latency info) (orphan-entry-latency-score entry))
      (when (zerop (decf (orphan-peer-info-count info)))
        (remhash peer (orphan-pool-peer-info pool))))))

(defun %orphan-deindex (pool entry)
  "Remove ENTRY's wtxid from every by-prev bucket of its input parents."
  (let ((wtxid (orphan-entry-wtxid entry)))
    (bl.ser:dovector
        (in (bl.ser:transaction-inputs
             (orphan-entry-transaction entry)))
      (let* ((ptxid (bl.ser:outpoint-hash
                     (bl.ser:tx-in-previous-output in)))
             (bucket (gethash ptxid (orphan-pool-by-prev pool))))
        (when bucket
          (let ((rest (remove wtxid bucket :test #'equalp)))
            (if rest
                (setf (gethash ptxid (orphan-pool-by-prev pool)) rest)
                (remhash ptxid (orphan-pool-by-prev pool)))))))))

(defun %orphan-remove-announcement (pool entry ann)
  "Remove one announcement; when it was the orphan's last, remove the orphan
itself and its indexes (Core Erase's IsUnique branch)."
  (%orphan-peer-info-subtract pool (orphan-announcement-peer ann) entry)
  (decf (orphan-pool-announcement-count pool))
  ;; The wtxid's one reconsider announcement is gone (Core Erase, :269).
  (when (orphan-announcement-reconsider ann)
    (remhash (orphan-entry-wtxid entry) (orphan-pool-reconsiderable-wtxids pool)))
  (setf (orphan-entry-announcements entry)
        (remove ann (orphan-entry-announcements entry)))
  (when (null (orphan-entry-announcements entry))
    (decf (orphan-pool-unique-usage pool) (orphan-entry-weight entry))
    (decf (orphan-pool-unique-input-score pool)
          (1- (orphan-entry-latency-score entry)))
    (%orphan-deindex pool entry)
    (remhash (orphan-entry-wtxid entry) (orphan-pool-by-wtxid pool))))

(defun %orphan-erase-entry (pool entry)
  "Erase ENTRY entirely — all announcements (Core EraseTxInternal)."
  (dolist (ann (copy-list (orphan-entry-announcements entry)))
    (%orphan-remove-announcement pool entry ann)))

(defgeneric orphan-peer-id (peer)
  (:documentation "PEER's NodeId, as the orphanage orders peers by it: LimitOrphans
breaks a tie between equal DoS scores toward the HIGHER NodeId, the more
recently connected peer (Core's compare_score, txorphanage.cpp:461-465). The
pool itself compares peers with EQ; the networking layer, which owns the peer
struct, supplies the method for it. An integer is its own NodeId, as Core's
NodeId is an integer.")
  (:method ((peer integer)) peer)
  (:method ((peer t)) 0))

(defun %orphan-dos-score (info max-latency max-usage)
  "A peer's DoS score under the per-peer allowances MAX-LATENCY and MAX-USAGE:
the larger of its latency score and its usage as FeeFracs over them (Core
PeerDoSInfo::GetDosScore, txorphanage.cpp:161-168). A FeeFrac and not a
ratio, as Core's is: two equal ratios then still order -- the one with the
smaller denominator, the latency score, first -- and that order is
std::max's choice here and LimitOrphans' choice between peers."
  (let ((latency (make-feefrac (orphan-peer-info-latency info) max-latency))
        (usage (make-feefrac (orphan-peer-info-usage info) max-usage)))
    (if (feefrac< latency usage) usage latency)))

(defun %orphan-announcement-before-p (a b)
  "Core's ByPeer order within one peer, (m_reconsider, m_entry_sequence)
(txorphanage.cpp:84-92): every announcement outside the work set before every
one in it, oldest first within each."
  (let ((ra (orphan-announcement-reconsider a))
        (rb (orphan-announcement-reconsider b)))
    (if (eq ra rb)
        (< (orphan-announcement-sequence a) (orphan-announcement-sequence b))
        rb)))

(defun %orphan-first-announcement-for-peer (pool peer &key reconsider-only)
  "PEER's first announcement in Core's ByPeer order, as (values entry ann):
the one LimitOrphans evicts first -- its oldest outside the work set, then its
oldest in it (\"sorting non-reconsiderable before reconsiderable\",
txorphanage.cpp:486-489). With RECONSIDER-ONLY, its oldest IN the work set,
which is GetTxToReconsider's lower_bound(peer, true, 0) (:587-590)."
  (let ((best-entry nil) (best-ann nil))
    (flet ((consider (entry)
             (dolist (ann (orphan-entry-announcements entry))
               (when (and (eq (orphan-announcement-peer ann) peer)
                          (or (not reconsider-only)
                              (orphan-announcement-reconsider ann))
                          (or (null best-ann)
                              (%orphan-announcement-before-p ann best-ann)))
                 (setf best-entry entry best-ann ann)))))
      ;; The work set is a handful of orphans at most, and the message pump
      ;; asks for it before every message: walk it, not the whole pool.
      (if reconsider-only
          (loop for wtxid being the hash-keys of (orphan-pool-reconsiderable-wtxids pool)
                do (consider (gethash wtxid (orphan-pool-by-wtxid pool))))
          (loop for entry being the hash-values of (orphan-pool-by-wtxid pool)
                do (consider entry))))
    (values best-entry best-ann)))

(defun %limit-orphans (pool)
  "Evict announcements while a global limit is exceeded (Core LimitOrphans,
txorphanage.cpp:436-525): take the peer with the highest DoS score -- the
higher ORPHAN-PEER-ID on a tie -- and drop its announcements, oldest first and
those outside the work set before those in it, until the
pool is within its limits or that peer's score falls to the next peer's (or
to 1), then put it back and take the worst again. The per-peer allowances are
read ONCE, at the start: a peer that loses its last announcement during the
trim does not raise the others' allowance before the trim ends (Core's
\"use consistent limits throughout\", :448-451). Only peers over their
allowance (score above 1) are candidates, so a peer within its own
reservation never loses an orphan while another exceeds it. Returns the
number of announcements evicted."
  (unless (%orphan-needs-trim-p pool)
    (return-from %limit-orphans 0))
  (let* ((max-latency (orphan-max-peer-latency-score pool))
         (max-usage (orphan-pool-reserved-peer-usage pool))
         (one (make-feefrac 1 1))
         (candidates '())                 ; (peer . score), worst first
         (evicted 0))
    (flet ((worse-p (a b)
             ;; Core's compare_score as a max-heap order (:461-465).
             (let ((c (feefrac-compare (cdr a) (cdr b))))
               (if (zerop c)
                   (> (orphan-peer-id (car a)) (orphan-peer-id (car b)))
                   (plusp c))))
           (score-of (peer)
             (let ((info (gethash peer (orphan-pool-peer-info pool))))
               (and info (%orphan-dos-score info max-latency max-usage)))))
      (maphash (lambda (peer info)
                 (let ((score (%orphan-dos-score info max-latency max-usage)))
                   (when (feefrac>> score one)
                     (push (cons peer score) candidates))))
               (orphan-pool-peer-info pool))
      (setf candidates (stable-sort candidates #'worse-p))
      (loop while candidates
            do (let* ((worst-peer (car (pop candidates)))
                      (threshold (if candidates (cdr (first candidates)) one)))
                 (loop while (%orphan-needs-trim-p pool)
                       do (multiple-value-bind (entry ann)
                              (%orphan-first-announcement-for-peer pool worst-peer)
                            (unless ann (return))
                            (%orphan-remove-announcement pool entry ann)
                            (incf evicted)
                            (let ((score (score-of worst-peer)))
                              (when (or (null score) (feefrac<= score threshold))
                                (return)))))
                 (unless (%orphan-needs-trim-p pool) (return))
                 (let ((score (score-of worst-peer)))
                   (when score
                     (setf candidates (merge 'list (list (cons worst-peer score))
                                             candidates #'worse-p)))))))
    (when (plusp evicted)
      (bl:log-cat "mempool" "orphanage overflow, removed ~D announcement~:P"
                            evicted))
    evicted))

;;;; Public mutators

(defun orphan-add (pool tx peer)
  "Add an announcement of TX by PEER (Core AddTx / AddAnnouncer): a new orphan
is stored and indexed under each input's parent txid; an orphan already
present gains PEER as an additional announcer. Oversized (> max standard
weight) transactions and duplicate (wtxid, peer) announcements are ignored.
Returns T iff TX was not stored before the call (Core AddTx's brand_new,
txorphanage.cpp:305-341) -- decided before LimitOrphans runs and returned
whatever that trim then evicts, the new orphan itself included, as Core
returns it."
  (let ((weight (bl.ser:transaction-weight tx)))
    (when (> weight +orphan-max-tx-weight+)
      (bl:log-cat "mempool" "ignoring large orphan tx (weight ~D)" weight)
      (return-from orphan-add nil))
    (let* ((wtxid (bl.ser:transaction-wtxid tx))
           (entry (gethash wtxid (orphan-pool-by-wtxid pool)))
           (brand-new (null entry)))
      ;; Duplicate (wtxid, peer) announcement: nothing to do.
      (when (and entry
                 (member peer (orphan-entry-announcements entry)
                         :key #'orphan-announcement-peer))
        (return-from orphan-add nil))
      (when brand-new
        (setf entry (make-orphan-entry
                     :transaction tx
                     :txid (bl.ser:transaction-hash tx)
                     :wtxid wtxid
                     :weight weight
                     :latency-score (%orphan-latency-score tx)))
        (setf (gethash wtxid (orphan-pool-by-wtxid pool)) entry)
        (incf (orphan-pool-unique-usage pool) weight)
        (incf (orphan-pool-unique-input-score pool)
              (1- (orphan-entry-latency-score entry)))
        (bl.ser:dovector
            (in (bl.ser:transaction-inputs tx))
          (let ((ptxid (bl.ser:outpoint-hash
                        (bl.ser:tx-in-previous-output in))))
            (pushnew wtxid (gethash ptxid (orphan-pool-by-prev pool))
                     :test #'equalp))))
      (push (make-orphan-announcement
             :peer peer
             :sequence (orphan-pool-next-sequence pool))
            (orphan-entry-announcements entry))
      (incf (orphan-pool-next-sequence pool))
      (incf (orphan-pool-announcement-count pool))
      (%orphan-peer-info-add pool peer entry)
      ;; DoS prevention: never grow unbounded (CVE-2012-3789).
      (%limit-orphans pool)
      brand-new)))

(defun orphan-remove (pool wtxid)
  "Erase orphan WTXID with all its announcements (Core EraseTx). Returns T if
it was present."
  (let ((entry (gethash wtxid (orphan-pool-by-wtxid pool))))
    (when entry
      (%orphan-erase-entry pool entry)
      ;; Fewer peers can shrink the global usage cap (Core EraseTx re-trims).
      (%limit-orphans pool)
      t)))

(defun orphan-erase-for-peer (pool peer)
  "Remove all of PEER's announcements (peer disconnected). Orphans other
peers also announced stay; single-announcer orphans go (Core EraseForPeer).
Returns the number of announcements removed."
  (let ((removed 0)
        (entries '()))
    (maphash (lambda (wtxid entry)
               (declare (ignore wtxid))
               (when (member peer (orphan-entry-announcements entry)
                             :key #'orphan-announcement-peer)
                 (push entry entries)))
             (orphan-pool-by-wtxid pool))
    (dolist (entry entries)
      (dolist (ann (copy-list (orphan-entry-announcements entry)))
        (when (eq (orphan-announcement-peer ann) peer)
          (%orphan-remove-announcement pool entry ann)
          (incf removed))))
    (%limit-orphans pool)
    removed))

(defun orphan-erase-for-block (pool block)
  "Erase every orphan included in or conflicting with BLOCK: any orphan
spending an outpoint that a block transaction also spends (Core
EraseForBlock, txorphanage.cpp:610-643 — exact outpoint match; an orphan
spending a DIFFERENT output of the same parent is untouched). Returns the
number of orphans erased."
  (when (zerop (orphan-pool-count pool))
    (return-from orphan-erase-for-block 0))
  (let ((to-erase '()))
    (dolist (block-tx (coerce (bl.ser:bitcoin-block-transactions
                               block)
                              'list))
      (bl.ser:dovector
          (in (bl.ser:transaction-inputs block-tx))
        (let* ((prevout (bl.ser:tx-in-previous-output in))
               (ptxid (bl.ser:outpoint-hash prevout))
               (pidx (bl.ser:outpoint-index prevout)))
          (dolist (wtxid (gethash ptxid (orphan-pool-by-prev pool)))
            (let ((entry (gethash wtxid (orphan-pool-by-wtxid pool))))
              ;; The by-prev bucket is parent-txid-granular; confirm the
              ;; orphan spends this exact outpoint (Core's outpoint keying).
              (when (and entry
                         (some (lambda (oin)
                                 (let ((op (bl.ser:tx-in-previous-output oin)))
                                   (and (= (bl.ser:outpoint-index op) pidx)
                                        (equalp (bl.ser:outpoint-hash op)
                                                ptxid))))
                               (coerce (bl.ser:transaction-inputs
                                        (orphan-entry-transaction entry))
                                       'list)))
                (pushnew wtxid to-erase :test #'equalp)))))))
    (dolist (wtxid to-erase)
      (let ((entry (gethash wtxid (orphan-pool-by-wtxid pool))))
        (when entry (%orphan-erase-entry pool entry))))
    (when to-erase
      ;; Core's line, category and all (txorphanage.cpp:636-638);
      ;; p2p_invalid_tx.py:180 waits for it.
      (bl:log-cat "txpackages"
                  "Erased ~D orphan transaction(s) included or conflicted by block"
                  (length to-erase))
      (%limit-orphans pool))
    (length to-erase)))

;;;; The work set (Core AddChildrenToWorkSet / GetTxToReconsider /
;;;; HaveTxToReconsider, txorphanage.cpp:527-608)

(defun %orphan-spends-output-p (entry parent-txid output-count)
  "T when ENTRY's orphan spends an output of PARENT-TXID that exists -- an
index below OUTPUT-COUNT. Core walks COutPoint(tx.GetHash(), i) for every i in
the parent's vout (txorphanage.cpp:531-532), so an orphan naming an output the
parent does not have is not its child; BY-PREV is parent-txid-granular, so the
index is checked here."
  (some (lambda (in)
          (let ((op (bl.ser:tx-in-previous-output in)))
            (and (< (bl.ser:outpoint-index op) output-count)
                 (equalp (bl.ser:outpoint-hash op) parent-txid))))
        (bl.ser:transaction-inputs (orphan-entry-transaction entry))))

(defun orphan-add-children-to-work-set (pool tx &optional (random-state *random-state*))
  "Core AddChildrenToWorkSet (txorphanage.cpp:527-565): TX entered the
mempool, so every orphan spending one of its outputs is ready to be looked at
again. Each such orphan not already in a work set gets ONE announcement marked
RECONSIDER -- a random announcer's, so the peer that will do the work cannot
be chosen by an attacker and \"cannot purposefully stop us from processing the
orphan by disconnecting\" either (:545-547). Returns the (wtxid . peer) pairs
marked, in the order they were marked."
  (let* ((txid (bl.ser:transaction-hash tx))
         (outputs (length (bl.ser:transaction-outputs tx)))
         (reconsiderable (orphan-pool-reconsiderable-wtxids pool))
         (marked '()))
    ;; Core visits the children of each output in wtxid order (a std::set).
    (dolist (wtxid (sort (copy-list (gethash txid (orphan-pool-by-prev pool)))
                         #'bl.bytes:octets<))
      (let ((entry (gethash wtxid (orphan-pool-by-wtxid pool))))
        (when (and entry
                   (not (gethash wtxid reconsiderable))
                   (%orphan-spends-output-p entry txid outputs))
          ;; Core's ByWtxid index orders one orphan's announcements by NodeId
          ;; and advances randrange(num_announcers) into them (:549-552).
          (let* ((anns (sort (copy-list (orphan-entry-announcements entry)) #'<
                             :key (lambda (ann)
                                    (orphan-peer-id (orphan-announcement-peer ann)))))
                 (ann (nth (random (length anns) random-state) anns)))
            (setf (orphan-announcement-reconsider ann) t
                  (gethash wtxid reconsiderable) t)
            (bl:log-cat "txpackages" "added ~A (wtxid=~A) to peer ~A workset"
                        (bl.crypto:bytes-to-hex (bl.crypto:reverse-bytes
                                                 (orphan-entry-txid entry)))
                        (bl.crypto:bytes-to-hex (bl.crypto:reverse-bytes wtxid))
                        (orphan-peer-id (orphan-announcement-peer ann)))
            (push (cons wtxid (orphan-announcement-peer ann)) marked)))))
    (nreverse marked)))

(defun orphan-get-tx-to-reconsider (pool peer)
  "Core GetTxToReconsider (txorphanage.cpp:587-601): PEER's OLDEST work-set
announcement leaves the work set and its transaction is returned, or NIL when
PEER has none. The flag goes even if the orphan then stays in the pool: it is
not looked at again \"until there is a new reason to do so\"."
  (multiple-value-bind (entry ann)
      (%orphan-first-announcement-for-peer pool peer :reconsider-only t)
    (when ann
      (setf (orphan-announcement-reconsider ann) nil)
      (remhash (orphan-entry-wtxid entry) (orphan-pool-reconsiderable-wtxids pool))
      (orphan-entry-transaction entry))))

(defun orphan-have-tx-to-reconsider (pool peer)
  "Core HaveTxToReconsider (txorphanage.cpp:604-608): PEER has an announcement
in the work set."
  (and (nth-value 1 (%orphan-first-announcement-for-peer pool peer :reconsider-only t))
       t))

(defun orphan-transactions (pool)
  "Core GetOrphanTransactions (txorphanage.cpp:672-685): every orphan as
(transaction . announcers)."
  (loop for wtxid being the hash-keys of (orphan-pool-by-wtxid pool) using (hash-value entry)
        collect (cons (orphan-entry-transaction entry) (orphan-announcers pool wtxid))))
