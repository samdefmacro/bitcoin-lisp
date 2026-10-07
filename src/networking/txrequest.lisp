(in-package #:bitcoin-lisp.networking)

;;;; Core's TxRequestTracker (src/txrequest.{h,cpp} at d3056bc) as an object.
;;;
;;; One TX-REQUEST-TRACKER per TxDownloadManager (txdownloadman_impl.h:29), so
;;; a fuzz target or a test builds its own and the node's lives in the node's
;;; manager. It decides WHICH peer is asked for a transaction and WHEN; the
;;; manager decides whether a transaction is wanted at all and what delay an
;;; announcement carries. The API is Core's: ReceivedInv, GetRequestable (with
;;; the expiries SetTimePoint finds), RequestedTx, ReceivedResponse,
;;; ForgetTxHash, DisconnectedPeer, GetCandidatePeers, Count, CountInFlight,
;;; CountCandidates, Size, SanityCheck.
;;;
;;; Core's announcement STATES (txrequest.cpp:52-100) are kept in two tables
;;; rather than one multi-index container: CANDIDATE_DELAYED and
;;; CANDIDATE_READY are an announcement whose READY time is in the future or
;;; the past, REQUESTED is the IN-FLIGHT entry naming that peer, and COMPLETED
;;; is the announcement's own flag. CANDIDATE_BEST is not stored: it is the
;;; selectable announcement of highest salted priority, computed when asked
;;; (%TX-REQUEST-BEST-CANDIDATE), which is what Core's SetTimePoint and
;;; ChangeAndReselect maintain incrementally. The BY-PEER index is Core's ByPeer
;;; index: it is what makes GetRequestable(peer) and DisconnectedPeer cost the
;;; peer's own announcements rather than the whole table.
;;;
;;; A peer is any EQL key: the node passes PEER structs, a fuzz target small
;;; integers (Core's NodeId). The priority hash reads its NodeId
;;; (%TX-PEER-NODE-ID).
;;;
;;; The clock is the caller's: every time here is a %TX-REQUEST-NOW value,
;;; Core's mockable clock in seconds.

(defun %tx-request-now ()
  "The tx-request clock, and it is Core's MOCKABLE one. SendMessages hands
`GetTime<std::chrono::microseconds>()' to GetRequestsToSend
(net_processing.cpp:6162) and AddTxAnnouncement stamps each announcement's
reqtime from the same call (txdownloadman_impl.cpp:210-219), so setmocktime
moves every request delay and the sixty-second expiry with it.

Ours read GET-INTERNAL-REAL-TIME -- a process-relative clock nothing can move
-- for both. That put the whole tracker out of reach of the functional suite,
which drives it with mocktime and then waits seconds, not minutes:
p2p_tx_download.py:175-176 jumps the clock past GETDATA_TX_INTERVAL and gives
the fallback peer ONE second to be asked, and p2p_ibd_txrelay.py:95-96 bumps
it by NONPREF_PEER_TX_DELAY and waits for the getdata."
  (bl.ser:get-unix-time))

(defstruct (tx-announcement
            (:constructor %make-tx-announcement (peer ready priority wtxid sequence))
            (:conc-name tx-ann-))
  "One peer's announcement of one txhash — Core's txrequest Announcement
(txrequest.cpp:52-100). READY is the %TX-REQUEST-NOW time at which it becomes
requestable (Core m_time as a reqtime: CANDIDATE_DELAYED until then,
CANDIDATE_READY after). COMPLETED is Core's State::COMPLETED: the peer
answered notfound, let its request expire, or delivered something for this
hash, so the announcement is never selected again — but the SLOT STAYS, which
is the point. Deleting it instead would let that peer re-announce its way
straight back into the candidate set and would refund the
MAX_PEER_TX_ANNOUNCEMENTS budget its failure spent, and Core's data structure
exists to prevent exactly that: \"The same transaction is never requested
twice from the same peer, unless the announcement was forgotten in between
... giving a peer multiple chances to announce a transaction would allow them
to bias requests in their favor, worsening transaction censoring attacks\"
(txrequest.h:45-58). WTXID is the announcement's own id type, Core's
Announcement::m_gtxid: a request goes out under the type of the announcement
it is granted to (GetRequestable returns that GenTxid, txrequest.cpp:595-624,
and SendMessages builds the getdata from it, net_processing.cpp:6207) -- MSG_WTX
for a wtxid, MSG_TX|witness-flag for a txid. A wtxid re-requested under
MSG_WITNESS_TX is a TXID lookup to a Core peer, answered notfound. SEQUENCE is
Core's m_sequence, the order GetRequestable returns a peer's requests in."
  (peer nil)
  (ready 0 :type integer)
  (completed nil :type boolean)
  (wtxid nil :type boolean)
  ;; %TX-REQUEST-PRIORITY of (txhash, peer), computed once here because none
  ;; of its three inputs can change for the life of the announcement -- Core
  ;; likewise pays for it once, by keeping the ByTxHash index SORTED by it
  ;; rather than recomputing on every GetRequestable.
  (priority 0 :type unsigned-byte)
  (sequence 0 :type unsigned-byte))

(defstruct (tx-request-tracker
            (:constructor make-tx-request-tracker ())
            (:conc-name txrequest-))
  "Core TxRequestTracker::Impl (txrequest.cpp:300-760)."
  ;; hash -> list of TX-ANNOUNCEMENT, every state including COMPLETED (Core's
  ;; ByTxHash index).
  (announcers (bl.bytes:make-octets-hash-table) :type hash-table)
  ;; hash -> (peer . expiry): the REQUESTED announcement, at most one per hash.
  (in-flight (bl.bytes:make-octets-hash-table) :type hash-table)
  ;; peer -> (hash -> TX-ANNOUNCEMENT): Core's ByPeer index. A peer's entry
  ;; goes when its last announcement does, so its size is Core's
  ;; m_peerinfo[peer].m_total and a disconnected peer is not tracked forever.
  (by-peer (make-hash-table :test 'eql) :type hash-table)
  ;; peer -> number of REQUESTED announcements (Core PeerInfo::m_requested).
  (peer-in-flight (make-hash-table :test 'eql) :type hash-table)
  ;; Core m_current_sequence.
  (sequence 0 :type unsigned-byte)
  ;; No REQUESTED announcement expires before this time: SetTimePoint has
  ;; nothing to do until then. Core's ByTime index answers the same question
  ;; by looking at its first entry; every peer's SendMessages asks it.
  (next-expiry 0 :type integer)
  (lock (bt:make-recursive-lock "tx-request")))

(defvar *tx-request-salt* nil
  "The node-lifetime SipHash key (K0 . K1) that orders tx-request candidates
-- Core PriorityComputer's m_k0/m_k1, two FastRandomContext draws kept for
the life of the process (txrequest.cpp:105-110). Drawn lazily so nothing in
start-up ordering depends on it; two threads racing the first draw is benign
(both values are equally good). A test or a fuzz target binds it to fix the
ranking, which is what Core's `deterministic' constructor argument does.")

(defun %tx-request-salt ()
  "The node's tx-request SipHash key, drawn from the OS CSPRNG on first use."
  (or *tx-request-salt*
      (setf *tx-request-salt* (random-siphash-key))))

(defun %tx-peer-node-id (peer)
  "PEER's NodeId: a PEER struct's id, or PEER itself when it is the integer a
fuzz target uses (Core's NodeId is an integer)."
  (if (peer-p peer) (peer-id peer) peer))

(defun %tx-request-priority (hash peer preferred)
  "Core's PriorityComputer (txrequest.cpp:112-118):

    SipHash(k0, k1, txhash || peer) >> 1  |  preferred << 63

and the HIGHEST priority wins. Two properties follow, and both are the point
(txrequest.h:66-84). Preferred (outbound) announcers outrank every
non-preferred one, because their bit is the most significant. Within a class
the winner is a function of the transaction and of a per-process secret, so
it is uniform over the candidates, DIFFERENT for each transaction, and not
computable by anyone else.

Selecting by announcement order instead -- preferred first, then earliest
ready -- put the choice entirely in the announcer's hands: a peer that races
the network's announcements took the request for EVERY transaction rather
than for a random 1/(number of preferred candidates) of them, and A such
connections held A consecutive GETDATA_TX_INTERVAL windows with no variance.
Core models that delay as k * GETDATA_TX_INTERVAL with k hypergeometric
precisely because the pick is random; announcement order made k its maximum,
deterministically, at the attacker's choosing.

Announcement TIME keeps its other role -- gating readiness through the
NONPREF / TXID_RELAY / OVERLOADED delays -- and stops deciding the winner."
  (let* ((salt (%tx-request-salt))
         (message (concatenate '(vector (unsigned-byte 8))
                               hash (int-to-le-bytes (%tx-peer-node-id peer) 8)))
         (low-bits (ash (bl.crypto:siphash-2-4 (car salt) (cdr salt) message)
                        -1)))
    (if preferred
        (logior low-bits (ash 1 63))
        low-bits)))

;;; --- Lock-held plumbing ---

(defun %tx-announcement-for (tr hash peer)
  "PEER's announcement of HASH, completed or not (Core's ByPeer lookup, which
searches both the CANDIDATE_BEST and the non-best key), or NIL."
  (let ((anns (gethash peer (txrequest-by-peer tr))))
    (and anns (gethash hash anns))))

(defun %tx-request-mark-in-flight (tr hash peer expiry)
  "Record PEER's announcement of HASH as REQUESTED until EXPIRY."
  (setf (gethash hash (txrequest-in-flight tr)) (cons peer expiry)
        (txrequest-next-expiry tr) (min expiry (txrequest-next-expiry tr)))
  (incf (gethash peer (txrequest-peer-in-flight tr) 0)))

(defun %tx-request-clear-in-flight (tr hash)
  "Drop HASH's REQUESTED entry, fixing its peer's in-flight count."
  (let ((entry (gethash hash (txrequest-in-flight tr))))
    (when entry
      (let ((n (1- (gethash (car entry) (txrequest-peer-in-flight tr) 1))))
        (if (plusp n)
            (setf (gethash (car entry) (txrequest-peer-in-flight tr)) n)
            (remhash (car entry) (txrequest-peer-in-flight tr))))
      (remhash hash (txrequest-in-flight tr)))))

(defun %tx-request-unindex (tr hash ann)
  "Remove ANN from its peer's BY-PEER entry (Core Erase's m_peerinfo
bookkeeping, txrequest.cpp:375-383): the peer's entry goes with its last
announcement."
  (let* ((peer (tx-ann-peer ann))
         (anns (gethash peer (txrequest-by-peer tr))))
    (when anns
      (remhash hash anns)
      (when (zerop (hash-table-count anns))
        (remhash peer (txrequest-by-peer tr))))))

(defun %tx-announcers-erase (tr hash)
  "Erase EVERY announcement of HASH, completed or not, and its request — Core
ForgetTxHash (txrequest.cpp:560-566) and the branch of MakeCompleted that
fires when the last non-completed announcement completes."
  (%tx-request-clear-in-flight tr hash)
  (dolist (ann (gethash hash (txrequest-announcers tr)))
    (%tx-request-unindex tr hash ann))
  (remhash hash (txrequest-announcers tr)))

(defun %tx-request-make-completed (tr hash peer)
  "Core MakeCompleted (txrequest.cpp:456-478). PEER's announcement of HASH
becomes COMPLETED — kept, so a re-announcement from PEER is still refused by
the (peer, txhash) uniqueness of Core's ByPeer index and its budget stays
charged — UNLESS it was the last non-COMPLETED announcement for the hash, in
which case every announcement of the hash is erased (IsOnlyNonCompleted,
:463-470; \"If for a given txhash only already-failed announcements remain,
they are all forgotten\", txrequest.h:52). A REQUESTED announcement stops
being in flight either way. Returns T while the announcement still exists."
  (let ((ann (%tx-announcement-for tr hash peer)))
    (cond ((null ann) nil)
          ((tx-ann-completed ann) t)
          ((find-if (lambda (a) (and (not (eq a ann)) (not (tx-ann-completed a))))
                    (gethash hash (txrequest-announcers tr)))
           (let ((entry (gethash hash (txrequest-in-flight tr))))
             (when (and entry (eq (car entry) peer))
               (%tx-request-clear-in-flight tr hash)))
           (setf (tx-ann-completed ann) t)
           t)
          (t (%tx-announcers-erase tr hash)
             nil))))

(defun %tx-request-selectable-p (ann now)
  "Core IsSelectable (txrequest.cpp:88-92) in our two-table form: the
announcement is not COMPLETED and its delay has passed (CANDIDATE_READY rather
than CANDIDATE_DELAYED). A PEER struct must also still be :READY -- the one
guard Core does not need, because nothing of ours is in the tracker between a
peer's state flip and its DisconnectedPeer except on the disconnecting thread
itself."
  (and (not (tx-ann-completed ann))
       (<= (tx-ann-ready ann) now)
       (let ((peer (tx-ann-peer ann)))
         (or (not (peer-p peer)) (eq (peer-state peer) :ready)))))

(defun %tx-request-best-candidate (anns now)
  "The selectable announcement in ANNS with the highest %TX-REQUEST-PRIORITY
at NOW — Core's CANDIDATE_BEST (GetRequestable, txrequest.cpp:595-624, over
an index sorted by that same priority)."
  (let ((best nil))
    (dolist (ann anns best)
      (when (and (%tx-request-selectable-p ann now)
                 (or (null best)
                     (> (tx-ann-priority ann) (tx-ann-priority best))))
        (setf best ann)))))

(defun %tx-request-set-time-point (tr now)
  "Core SetTimePoint's expiry half (txrequest.cpp:485-500): every REQUESTED
announcement whose expiry is at or before NOW is completed -- `m_time <= now',
so a request expires AT its expiry, not a second later -- and returned as
(peer hash . wtxidp). The other half, promoting a CANDIDATE_DELAYED whose time
has come (and demoting one when the clock went BACKWARDS), is what computing
CANDIDATE_BEST from READY and NOW already does."
  (when (< now (txrequest-next-expiry tr))
    (return-from %tx-request-set-time-point '()))
  (let ((expired '())
        (next most-positive-fixnum))
    (maphash (lambda (hash entry)
               (if (<= (cdr entry) now)
                   (let ((ann (%tx-announcement-for tr hash (car entry))))
                     (push (list* (car entry) hash (and ann (tx-ann-wtxid ann)))
                           expired))
                   (setf next (min next (cdr entry)))))
             (txrequest-in-flight tr))
    (setf (txrequest-next-expiry tr) next)
    (dolist (item expired)
      (%tx-request-make-completed tr (second item) (first item)))
    (nreverse expired)))

;;; --- Core's API ---

(defun txrequest-received-inv (tr peer hash wtxidp preferred reqtime)
  "Core ReceivedInv (txrequest.cpp:578-592): record PEER's announcement of
HASH (a wtxid when WTXIDP), requestable from REQTIME, ranked with the
PREFERRED bit. A second announcement from the same peer -- live or COMPLETED --
is refused by the (peer, txhash) uniqueness of Core's ByPeer index, so a peer
whose request failed does not get a second one. Returns T when recorded."
  (bt:with-recursive-lock-held ((txrequest-lock tr))
    (unless (%tx-announcement-for tr hash peer)
      (let ((ann (%make-tx-announcement peer reqtime
                                        (%tx-request-priority hash peer preferred)
                                        (and wtxidp t)
                                        (txrequest-sequence tr))))
        (incf (txrequest-sequence tr))
        (push ann (gethash hash (txrequest-announcers tr)))
        (setf (gethash hash (or (gethash peer (txrequest-by-peer tr))
                                (setf (gethash peer (txrequest-by-peer tr))
                                      (bl.bytes:make-octets-hash-table))))
              ann)
        t))))

(defun txrequest-get-requestable (tr peer now)
  "Core GetRequestable (txrequest.cpp:595-624): move time to NOW -- expiring
every request whose time is up -- and return the txhashes PEER should be asked
for now, as (hash . wtxidp) in announcement order: those for which PEER holds
the CANDIDATE_BEST announcement and nothing is in flight. The second value is
the expired requests, as (peer hash . wtxidp)."
  (bt:with-recursive-lock-held ((txrequest-lock tr))
    (let ((expired (%tx-request-set-time-point tr now))
          (selected '())
          (anns (gethash peer (txrequest-by-peer tr))))
      (when anns
        (maphash (lambda (hash ann)
                   (when (and (not (gethash hash (txrequest-in-flight tr)))
                              (%tx-request-selectable-p ann now)
                              (eq ann (%tx-request-best-candidate
                                       (gethash hash (txrequest-announcers tr)) now)))
                     (push (cons hash ann) selected)))
                 anns))
      (values (mapcar (lambda (item) (cons (car item) (tx-ann-wtxid (cdr item))))
                      (sort selected #'< :key (lambda (item) (tx-ann-sequence (cdr item)))))
              expired))))

(defun txrequest-requested-tx (tr peer hash expiry)
  "Core RequestedTx (txrequest.cpp:626-665): PEER's candidate announcement of
HASH becomes REQUESTED until EXPIRY. When it was not the CANDIDATE_BEST --
a caller that requests something GetRequestable did not hand it -- an
outstanding request for HASH to another peer is completed first, \"as we're no
longer waiting for a response to the previous REQUESTED announcement\". No
candidate announcement from PEER: nothing happens."
  (bt:with-recursive-lock-held ((txrequest-lock tr))
    (let ((ann (%tx-announcement-for tr hash peer))
          (entry (gethash hash (txrequest-in-flight tr))))
      (when (and ann (not (tx-ann-completed ann))
                 (not (and entry (eq (car entry) peer))))
        (when entry
          (let ((old (%tx-announcement-for tr hash (car entry))))
            (%tx-request-clear-in-flight tr hash)
            (when old (setf (tx-ann-completed old) t))))
        (%tx-request-mark-in-flight tr hash peer expiry)
        t))))

(defun txrequest-received-response (tr peer hash)
  "PEER answered our request for HASH — with the transaction, or with a
notfound. Core ReceivedResponse (txrequest.cpp:667-676): ONLY this peer's
announcement is completed, so every other announcer stays a candidate and is
asked at its own next GetRequestable.

It is deliberately not ForgetTxHash. A peer that sends an unsolicited copy of
a transaction — or a witness-malleated twin, same txid and a different wtxid
— would otherwise release every honest announcer of that txid and no further
request would be issued for it."
  (bt:with-recursive-lock-held ((txrequest-lock tr))
    (%tx-request-make-completed tr hash peer)))

(defun txrequest-forget-tx-hash (tr hash)
  "Forget HASH entirely — Core ForgetTxHash (txrequest.cpp:560-566): the
outstanding request and EVERY peer's announcement of it are released.

This is for a hash that is genuinely RESOLVED, and only for those: it entered
the mempool, a block confirmed it, it went into the orphanage, or it failed
in a way that will not be reconsidered. A transaction merely ARRIVING is not
that — see TXREQUEST-RECEIVED-RESPONSE, which is what a delivery calls."
  (bt:with-recursive-lock-held ((txrequest-lock tr))
    (%tx-announcers-erase tr hash)))

(defun txrequest-disconnected-peer (tr peer)
  "Core DisconnectedPeer (txrequest.cpp:527-558): every announcement PEER made
is completed -- which erases a txhash whose other announcements were all
completed already, and releases PEER's requests so the next best candidate is
asked at its own GetRequestable -- and then erased."
  (bt:with-recursive-lock-held ((txrequest-lock tr))
    (let ((anns (gethash peer (txrequest-by-peer tr))))
      (when anns
        (dolist (hash (loop for h being the hash-keys of anns collect h))
          (when (%tx-request-make-completed tr hash peer)
            (let ((ann (%tx-announcement-for tr hash peer)))
              (when ann
                (%tx-request-unindex tr hash ann)
                (let ((rest (remove ann (gethash hash (txrequest-announcers tr)))))
                  (if rest
                      (setf (gethash hash (txrequest-announcers tr)) rest)
                      (remhash hash (txrequest-announcers tr))))))))))
    (remhash peer (txrequest-peer-in-flight tr))))

(defun txrequest-get-candidate-peers (tr hash)
  "Every peer with a LIVE (non-COMPLETED) announcement of HASH — Core
GetCandidatePeers (txrequest.cpp:568-576). Orphan intake uses it to enrol every
peer that announced the orphan as a resolution candidate, not only the one that
delivered it: a peer announces a transaction ONCE, so an announcer we do not
enrol here will not offer itself again."
  (bt:with-recursive-lock-held ((txrequest-lock tr))
    (loop for ann in (gethash hash (txrequest-announcers tr))
          unless (tx-ann-completed ann)
            collect (tx-ann-peer ann))))

(defun txrequest-count (tr peer)
  "Number of announcements tracked for PEER, every state (Core Count)."
  (bt:with-recursive-lock-held ((txrequest-lock tr))
    (let ((anns (gethash peer (txrequest-by-peer tr))))
      (if anns (hash-table-count anns) 0))))

(defun txrequest-count-in-flight (tr peer)
  "Number of PEER's REQUESTED announcements (Core CountInFlight)."
  (bt:with-recursive-lock-held ((txrequest-lock tr))
    (gethash peer (txrequest-peer-in-flight tr) 0)))

(defun txrequest-count-candidates (tr peer)
  "Number of PEER's CANDIDATE announcements, delayed or ready (Core
CountCandidates): neither REQUESTED nor COMPLETED."
  (bt:with-recursive-lock-held ((txrequest-lock tr))
    (let ((anns (gethash peer (txrequest-by-peer tr))))
      (if anns
          (loop for hash being the hash-keys of anns using (hash-value ann)
                count (and (not (tx-ann-completed ann))
                           (let ((entry (gethash hash (txrequest-in-flight tr))))
                             (not (and entry (eq (car entry) peer))))))
          0))))

(defun txrequest-size (tr)
  "Total number of announcements tracked, every peer and state (Core Size)."
  (bt:with-recursive-lock-held ((txrequest-lock tr))
    (loop for anns being the hash-values of (txrequest-by-peer tr)
          sum (hash-table-count anns))))

(defun txrequest-sanity-check (tr)
  "Core TxRequestTracker::SanityCheck (txrequest.cpp:317-356), returning the
list of violated invariants as strings (empty when consistent): the per-peer
caches agree with the announcements, no txhash is left with COMPLETED
announcements only, at most one request is outstanding per txhash and it
belongs to a live announcement, and no peer announced a txhash twice."
  (bt:with-recursive-lock-held ((txrequest-lock tr))
    (let ((problems '())
          (counted (make-hash-table :test 'eql))
          (requested (make-hash-table :test 'eql)))
      (flet ((fail (fmt &rest args) (push (apply #'format nil fmt args) problems)))
        (maphash
         (lambda (hash anns)
           (when (null anns) (fail "an empty announcer list is kept"))
           (when (every #'tx-ann-completed anns)
             (fail "a txhash has only COMPLETED announcements"))
           (let ((peers (mapcar #'tx-ann-peer anns)))
             (unless (= (length peers) (length (remove-duplicates peers)))
               (fail "a peer announced one txhash twice")))
           (dolist (ann anns)
             (incf (gethash (tx-ann-peer ann) counted 0))
             (unless (eq ann (%tx-announcement-for tr hash (tx-ann-peer ann)))
               (fail "the by-peer index does not hold an announcement"))))
         (txrequest-announcers tr))
        (maphash (lambda (hash entry)
                   (let ((ann (%tx-announcement-for tr hash (car entry))))
                     (when (or (null ann) (tx-ann-completed ann))
                       (fail "a request is outstanding on no live announcement")))
                   (incf (gethash (car entry) requested 0)))
                 (txrequest-in-flight tr))
        (maphash (lambda (peer anns)
                   (unless (= (hash-table-count anns) (gethash peer counted 0))
                     (fail "a peer's Count is not its announcements"))
                   ;; Core PeerInfo: m_total = candidates + requested + completed.
                   (unless (= (hash-table-count anns)
                              (+ (txrequest-count-candidates tr peer)
                                 (gethash peer (txrequest-peer-in-flight tr) 0)
                                 (loop for ann being the hash-values of anns
                                       count (tx-ann-completed ann))))
                     (fail "a peer's Count is not its candidates, requests and completions")))
                 (txrequest-by-peer tr))
        (unless (= (hash-table-count counted) (hash-table-count (txrequest-by-peer tr)))
          (fail "a peer with announcements is missing from the by-peer index"))
        (maphash (lambda (peer n)
                   (unless (= n (gethash peer requested 0))
                     (fail "a peer's CountInFlight is not its requests")))
                 (txrequest-peer-in-flight tr))
        (unless (= (hash-table-count requested)
                   (hash-table-count (txrequest-peer-in-flight tr)))
          (fail "a peer with a request is missing from the in-flight counts")))
      (nreverse problems))))
