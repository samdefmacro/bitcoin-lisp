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
;;; Simplifications vs Core, documented:
;;;  - Core's reconsider/work-set machinery (m_reconsider, GetTxToReconsider)
;;;    is not ported: our de-orphan cascade re-validates children immediately
;;;    when the parent is accepted (process-orphans), so no work set exists.
;;;    Eviction order within a peer is therefore purely oldest-first, without
;;;    Core's "non-reconsiderable before reconsiderable" refinement.
;;;  - LimitOrphans recomputes the DoSiest peer each eviction instead of
;;;    keeping Core's heap + threshold bookkeeping; the evicted multiset is
;;;    the same except for exact-tie ordering.
;;;  - Core tiebreaks equal DoS scores toward the more recent NodeId; peers
;;;    are opaque objects here (the networking layer loads later), so ties
;;;    break by which peer holds the oldest announcement.

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
  "One (orphan, peer) announcement — Core txorphanage.cpp Announcement."
  (peer nil)
  (sequence 0 :type integer))

(defstruct orphan-entry
  "An orphan transaction awaiting a missing parent, with its announcers."
  (transaction nil :type bitcoin-lisp.serialization:transaction)
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
  "Pool of orphan transactions (Core TxOrphanageImpl)."
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
  (not (null (gethash wtxid (orphan-pool-by-wtxid pool)))))

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

(defun orphans-depending-on (pool parent-txid)
  "The wtxids of orphans that reference PARENT-TXID as an input parent
(Core AddChildrenToWorkSet's m_outpoint_to_orphan_wtxids lookup across all of
the parent's outputs)."
  (copy-list (gethash parent-txid (orphan-pool-by-prev pool))))

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

(defun %orphan-max-peer-latency-score (pool)
  "Per-peer latency allowance: the global budget split across peers with
entries (Core MaxPeerLatencyScore, txorphanage.cpp:768)."
  (floor +max-orphanage-latency-score+
         (max 1 (hash-table-count (orphan-pool-peer-info pool)))))

(defun %orphan-max-global-usage (pool)
  "Global usage cap: the per-peer reservation times the number of peers with
entries (Core MaxGlobalUsage, txorphanage.cpp:769)."
  (* +reserved-orphan-weight-per-peer+
     (max 1 (hash-table-count (orphan-pool-peer-info pool)))))

(defun %orphan-needs-trim-p (pool)
  "Core NeedsTrim (txorphanage.cpp:771-774)."
  (or (> (orphan-total-latency-score pool) +max-orphanage-latency-score+)
      (> (orphan-total-usage pool) (%orphan-max-global-usage pool))))

;;;; Internal add/remove plumbing

(defun %orphan-latency-score (tx)
  "1 + floor(inputs/10) (Core Announcement::GetLatencyScore)."
  (1+ (floor (length (bitcoin-lisp.serialization:transaction-inputs tx)) 10)))

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
    (bitcoin-lisp.serialization:dovector
        (in (bitcoin-lisp.serialization:transaction-inputs
             (orphan-entry-transaction entry)))
      (let* ((ptxid (bitcoin-lisp.serialization:outpoint-hash
                     (bitcoin-lisp.serialization:tx-in-previous-output in)))
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

(defun %orphan-dos-score (pool info)
  "PEER's DoS score: max of its latency and usage ratios against the per-peer
allowances, as an exact rational (Core PeerDoSInfo::GetDosScore)."
  (max (/ (orphan-peer-info-latency info)
          (%orphan-max-peer-latency-score pool))
       (/ (orphan-peer-info-usage info)
          +reserved-orphan-weight-per-peer+)))

(defun %orphan-oldest-announcement-for-peer (pool peer)
  "PEER's oldest (lowest-sequence) announcement, as (values entry ann)."
  (let ((best-entry nil) (best-ann nil))
    (maphash (lambda (wtxid entry)
               (declare (ignore wtxid))
               (dolist (ann (orphan-entry-announcements entry))
                 (when (and (eq (orphan-announcement-peer ann) peer)
                            (or (null best-ann)
                                (< (orphan-announcement-sequence ann)
                                   (orphan-announcement-sequence best-ann))))
                   (setf best-entry entry best-ann ann))))
             (orphan-pool-by-wtxid pool))
    (values best-entry best-ann)))

(defun %limit-orphans (pool)
  "Evict announcements while a global limit is exceeded: repeatedly take the
peer with the highest DoS score and drop its oldest announcement (Core
LimitOrphans, txorphanage.cpp:436-525). A peer within its own reservation is
never selected while another exceeds its allowance, so no peer can evict
another's orphans. Returns the number of announcements evicted."
  (let ((evicted 0))
    (loop while (%orphan-needs-trim-p pool)
          do (let ((worst-peer nil) (worst-score nil))
               (maphash
                (lambda (peer info)
                  (let ((score (%orphan-dos-score pool info)))
                    (when (or (null worst-score) (> score worst-score))
                      (setf worst-peer peer worst-score score))))
                (orphan-pool-peer-info pool))
               (unless worst-score (return))
               (multiple-value-bind (entry ann)
                   (%orphan-oldest-announcement-for-peer pool worst-peer)
                 (unless ann (return))
                 (%orphan-remove-announcement pool entry ann)
                 (incf evicted))))
    (when (plusp evicted)
      (bitcoin-lisp:log-cat "mempool" "orphanage overflow, removed ~D announcement~:P"
                            evicted))
    evicted))

;;;; Public mutators

(defun orphan-add (pool tx peer)
  "Add an announcement of TX by PEER (Core AddTx / AddAnnouncer): a new orphan
is stored and indexed under each input's parent txid; an orphan already
present gains PEER as an additional announcer. Oversized (> max standard
weight) transactions and duplicate (wtxid, peer) announcements are ignored.
Returns T iff TX was newly stored (Core AddTx's brand_new)."
  (let ((weight (bitcoin-lisp.serialization:transaction-weight tx)))
    (when (> weight +orphan-max-tx-weight+)
      (bitcoin-lisp:log-cat "mempool" "ignoring large orphan tx (weight ~D)" weight)
      (return-from orphan-add nil))
    (let* ((wtxid (bitcoin-lisp.serialization:transaction-wtxid tx))
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
                     :txid (bitcoin-lisp.serialization:transaction-hash tx)
                     :wtxid wtxid
                     :weight weight
                     :latency-score (%orphan-latency-score tx)))
        (setf (gethash wtxid (orphan-pool-by-wtxid pool)) entry)
        (incf (orphan-pool-unique-usage pool) weight)
        (incf (orphan-pool-unique-input-score pool)
              (1- (orphan-entry-latency-score entry)))
        (bitcoin-lisp.serialization:dovector
            (in (bitcoin-lisp.serialization:transaction-inputs tx))
          (let ((ptxid (bitcoin-lisp.serialization:outpoint-hash
                        (bitcoin-lisp.serialization:tx-in-previous-output in))))
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
      ;; Report brand-new only if the entry survived its own trim.
      (and brand-new (orphan-have pool wtxid)))))

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
    (dolist (block-tx (coerce (bitcoin-lisp.serialization:bitcoin-block-transactions
                               block)
                              'list))
      (bitcoin-lisp.serialization:dovector
          (in (bitcoin-lisp.serialization:transaction-inputs block-tx))
        (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output in))
               (ptxid (bitcoin-lisp.serialization:outpoint-hash prevout))
               (pidx (bitcoin-lisp.serialization:outpoint-index prevout)))
          (dolist (wtxid (gethash ptxid (orphan-pool-by-prev pool)))
            (let ((entry (gethash wtxid (orphan-pool-by-wtxid pool))))
              ;; The by-prev bucket is parent-txid-granular; confirm the
              ;; orphan spends this exact outpoint (Core's outpoint keying).
              (when (and entry
                         (some (lambda (oin)
                                 (let ((op (bitcoin-lisp.serialization:tx-in-previous-output oin)))
                                   (and (= (bitcoin-lisp.serialization:outpoint-index op) pidx)
                                        (equalp (bitcoin-lisp.serialization:outpoint-hash op)
                                                ptxid))))
                               (coerce (bitcoin-lisp.serialization:transaction-inputs
                                        (orphan-entry-transaction entry))
                                       'list)))
                (pushnew wtxid to-erase :test #'equalp)))))))
    (dolist (wtxid to-erase)
      (let ((entry (gethash wtxid (orphan-pool-by-wtxid pool))))
        (when entry (%orphan-erase-entry pool entry))))
    (when to-erase
      (bitcoin-lisp:log-cat "mempool"
                            "Erased ~D orphan transaction~:P included or conflicted by block"
                            (length to-erase))
      (%limit-orphans pool))
    (length to-erase)))
