(in-package #:bitcoin-lisp.networking)

;;;; BIP-330 reconciliation sets (Erlay P2)
;;;;
;;;; ⚠️ BEYOND BITCOIN CORE. Core ships the sendtxrcncl HANDSHAKE and nothing
;;;; else: its TxReconciliationTracker is 170 lines with four methods
;;;; (PreRegisterPeer, RegisterPeer, ForgetPeer, IsPeerRegistered), no AddToSet,
;;;; no fanout, no timer, no sketch — and its own comments still read "TODO:
;;;; ... once used in the following commits". Everything in this file is built
;;;; from BIP-330 rather than ported, so it has no reference implementation to
;;;; be checked against, which is the single most reliable error-catcher this
;;;; project has. It stays behind -txreconciliation, default off.
;;;;
;;;; This file is the MECHANISM only: per-peer sets, short IDs, and the fanout
;;;; decision. Nothing diverts a transaction into a set yet — a set that
;;;; nothing drains would delay announcements forever, so the relay path is
;;;; only rewired once the sketch exchange exists to drain it.

(defconstant +recon-short-id-bits+ 32
  "BIP-330 short IDs are 32 bits, which is also minisketch's field size here.")

(defun recon-short-id (k0 k1 wtxid)
  "The 32-bit short ID of WTXID for a peer with salt (K0, K1).

Salted per peer so the same transaction has a different ID on every link: an
observer watching one link cannot tell which transactions a node holds on
another, and cannot grind IDs that collide for everybody.

Zero is remapped to one because 0 has no sketch — its powers are all zero, so
it would be invisible in the sketch rather than merely unlucky."
  (let ((id (logand (bl.crypto:siphash-2-4 k0 k1 wtxid) #xFFFFFFFF)))
    (if (zerop id) 1 id)))

(defstruct (recon-set (:constructor %make-recon-set))
  "The transactions waiting to be reconciled with one peer.

Keyed by SHORT ID rather than by wtxid because that is what the sketch holds
and what comes back from a decode; the wtxid is kept alongside so the node can
announce the real transaction once the difference is known."
  (by-short-id (make-hash-table :test 'eql) :type hash-table)
  ;; Snapshot taken when a round starts. A round spans several messages, and
  ;; transactions keep arriving meanwhile; reconciling against a moving set
  ;; would make the sketch describe something the peer never saw.
  (snapshot nil))

(defun make-recon-set () (%make-recon-set))

(defun recon-set-size (set) (hash-table-count (recon-set-by-short-id set)))

(defun recon-set-add (set k0 k1 wtxid)
  "Queue WTXID for reconciliation. Returns the short ID, or NIL if it was
already queued."
  (let ((id (recon-short-id k0 k1 wtxid)))
    (unless (gethash id (recon-set-by-short-id set))
      (setf (gethash id (recon-set-by-short-id set)) (copy-seq wtxid))
      id)))

(defun recon-set-remove (set k0 k1 wtxid)
  "Drop WTXID — it was announced another way, or it left the mempool."
  (remhash (recon-short-id k0 k1 wtxid) (recon-set-by-short-id set)))

(defun recon-set-wtxid (set short-id)
  (gethash short-id (recon-set-by-short-id set)))

(defun recon-set-short-ids (set)
  (loop for id being the hash-keys of (recon-set-by-short-id set) collect id))

(defun recon-set-take-snapshot (set)
  "Freeze the current contents for a reconciliation round and return the short
IDs in it. Named apart from the RECON-SET-SNAPSHOT accessor on purpose: one
reads the frozen list, this one creates it."
  (setf (recon-set-snapshot set) (recon-set-short-ids set)))

(defun recon-set-clear-snapshot (set)
  (setf (recon-set-snapshot set) nil))

;;;; --- Sketch construction ------------------------------------------------

(defconstant +recon-capacity-slack+ 1
  "BIP-330's constant term c: one extra slot, so a difference estimated
exactly right still fits.")

(defun recon-estimate-capacity (local-size remote-size q)
  "BIP-330's capacity estimate: |local - remote| + q * min(local, remote) + c.

Q is the responder's guess at how much of the smaller set the two sides fail to
share, sent as a fixed-point fraction. Guessing low costs an extension round;
guessing high costs bandwidth on every round, which is what Erlay exists to
save — so the estimate is deliberately tight and the extension is the
safety net."
  (+ (abs (- local-size remote-size))
     (floor (* q (min local-size remote-size)))
     +recon-capacity-slack+))

(defun recon-build-sketch (short-ids capacity)
  "A sketch of CAPACITY over SHORT-IDS."
  (let ((sk (ms-make-sketch capacity)))
    (dolist (id short-ids sk)
      (ms-sketch-add sk id))))

;;;; --- Fanout -------------------------------------------------------------
;;;;
;;;; Reconciliation alone would let an adversary learn a transaction's origin
;;;; by timing which link announces it first, so BIP-330 keeps announcing to a
;;;; SMALL RANDOM SUBSET of peers immediately and reconciles with the rest.
;;;; That subset is what "low fanout" means, and the choice has to be per
;;;; transaction, not per peer: a fixed subset would be a fixed observation
;;;; point.

(defconstant +recon-outbound-fanout-destinations+ 1
  "How many reconciling OUTBOUND peers still get an immediate announcement.")

(defconstant +recon-inbound-fanout-fraction+ 0.1d0
  "Fraction of reconciling INBOUND peers that get an immediate announcement.")

(defun recon-fanout-target-p (wtxid peer-salt reconciling-peer-count outbound-p)
  "Whether this transaction should be announced to this peer immediately rather
than reconciled.

RECONCILING-PEER-COUNT is how many peers are reconciling at all, which is what
turns \"one outbound destination\" into a per-peer probability of 1/n. It is
passed in because only the caller can see the peer list.

Deterministic in (wtxid, peer salt), so a node does not reveal a new sample on
every retry, and unpredictable to anyone who does not know the salt.

With a single reconciling peer the outbound share is 1, so everything is
announced — correctly: one destination out of one peer IS that peer, and
holding transactions back to reconcile with nobody else would only delay them."
  (let* ((h (bl.crypto:siphash-2-4 peer-salt 0 wtxid))
         (draw (/ (float (logand h #xFFFFFFFF) 1d0) 4294967296d0)))
    (if outbound-p
        (< draw (if (plusp reconciling-peer-count)
                    (min 1d0 (/ (float +recon-outbound-fanout-destinations+ 1d0)
                                (float reconciling-peer-count 1d0)))
                    1d0))
        (< draw +recon-inbound-fanout-fraction+))))

;;;; --- Reconciliation rounds (Erlay P4) -----------------------------------
;;;;
;;;; One round, in messages:
;;;;
;;;;   initiator -> reqrecon(set_size, q)
;;;;   responder -> sketch(their sketch at the estimated capacity)
;;;;   initiator: merge, decode
;;;;     decoded -> reconcildiff(success=1, ids it is missing)
;;;;     failed  -> reqsketchext, responder sends the extension, decode again
;;;;                still failed -> reconcildiff(success=0) and both sides
;;;;                announce their whole sets
;;;;
;;;; ⚠️ Still beyond Core: none of these messages exists there.

(defstruct recon-round
  "The initiator's state for one reconciliation round."
  (peer nil)
  ;; The frozen short IDs this round is about.
  (local-ids '() :type list)
  ;; The capacity the responder used, needed to size the extension.
  (capacity 0 :type (integer 0))
  ;; The responder's sketch, kept so an extension can be appended to it rather
  ;; than the whole thing resent.
  (their-sketch nil)
  (extended nil :type boolean)
  (state :requested :type keyword))

(defun recon-round-decode (round their-sketch)
  "Merge the responder's sketch with our own and try to decode.

Returns (values short-ids ok-p). A NIL id list with OK-P false is the ordinary
`difference was bigger than the sketch' outcome, which the caller answers with
an extension rather than a failure."
  (let* ((capacity (length their-sketch))
         (mine (recon-build-sketch (recon-round-local-ids round) capacity))
         (merged (ms-sketch-merge mine their-sketch))
         (decoded (ms-decode merged)))
    (setf (recon-round-their-sketch round) their-sketch
          (recon-round-capacity round) capacity)
    (if decoded
        (values decoded t)
        (values nil nil))))

(defun recon-round-missing-ids (round decoded-ids)
  "Of the differing short IDs, the ones WE do not have — the set to ask for.

The rest are ours to announce, since a symmetric difference says only that an
element is on exactly one side, not which."
  (let ((ours (make-hash-table :test 'eql)))
    (dolist (id (recon-round-local-ids round))
      (setf (gethash id ours) t))
    (remove-if (lambda (id) (gethash id ours)) decoded-ids)))

(defun recon-round-ours-to-announce (round decoded-ids)
  "The differing short IDs that ARE ours, which the peer is missing."
  (let ((ours (make-hash-table :test 'eql)))
    (dolist (id (recon-round-local-ids round))
      (setf (gethash id ours) t))
    (remove-if-not (lambda (id) (gethash id ours)) decoded-ids)))

;;;; --- Driving rounds from the peer loop ----------------------------------

(defconstant +recon-round-interval-seconds+ 8
  "How often a node opens a round with one of its reconciling outbound peers.

BIP-330 spreads rounds across peers rather than running them all at once, so a
node's announcement pattern does not reveal how many peers it has. Eight
seconds is a starting point, not a ported constant — Core has no timer to copy.")

(defconstant +recon-default-q+ 0.25d0
  "The initiator's guess at the fraction of the smaller set the two sides do
not share. Also unported for the same reason.")

(defun recon-should-start-round-p (peer now)
  "T when it is this peer's turn and it has nothing already in flight."
  (and (peer-recon-registered peer)
       (peer-recon-k0 peer)
       ;; Only the side that DIALLED initiates, so both ends never open a round
       ;; against each other at once (BIP-330 gives the role to the outbound
       ;; peer, which is what recon-we-initiate records at handshake time).
       (peer-recon-we-initiate peer)
       (null (peer-recon-round peer))
       (>= (- now (peer-recon-last-round peer)) +recon-round-interval-seconds+)))

(defun recon-start-round (peer now)
  "Freeze this peer's set and send reqrecon. Returns the message, or NIL when
there is nothing to reconcile."
  (let* ((set (peer-recon-set peer))
         (ids (and set (recon-set-take-snapshot set))))
    (setf (peer-recon-last-round peer) now)
    (when ids
      (setf (peer-recon-round peer)
            (make-recon-round :peer peer :local-ids ids :state :requested))
      (bl.ser:make-reqrecon-message
       (length ids) +recon-default-q+))))

(defun recon-respond-to-request (peer their-size q)
  "The responder's half: size a sketch against what the initiator says it has,
and send it."
  (let* ((set (peer-recon-set peer))
         (ids (if set (recon-set-take-snapshot set) '()))
         (capacity (recon-estimate-capacity (length ids) their-size q)))
    (bl.ser:make-sketch-message
     (ms-sketch-serialize (recon-build-sketch ids capacity)))))

(defun recon-settle-ids (set short-ids)
  "Drop SHORT-IDS from SET and return the wtxids they were holding.

An id passed here is SETTLED with this peer — announced to it, requested from
it, or shown by the sketch to be held by both sides — so it must not still be
in the set the next round reconciles. Returns NIL for a NIL SET, and skips an
id the set no longer holds."
  (when set
    (loop for id in short-ids
          for wtxid = (recon-set-wtxid set id)
          when wtxid
            collect wtxid
            and do (remhash id (recon-set-by-short-id set)))))

(defun recon-finish-round (peer decoded-ids)
  "Split the decoded difference and retire the round's snapshot.

Returns (values ids-to-request wtxids-to-announce). Nothing is sent here — the
caller owns the socket — but the split has to happen while the round's frozen
snapshot is still around.

A SUCCESSFUL round retires the WHOLE snapshot, not only the symmetric
difference. Every id in the snapshot is known to both sides once the round
succeeds: the ones in the difference because they were just requested or
announced, and the ones that CANCELLED in the sketch because both sides
already held them. Removing only the difference — which is what this did —
kept every cancelled id for the life of the connection, so the set grew
monotonically and RECON-ESTIMATE-CAPACITY sized every later sketch against
dead weight, which is exactly the bandwidth Erlay exists to save.
RECON-ABANDON-ROUND already retires the same ids; this is that shape.

BIP-330 is the specification for this: Core at d3056bc ships the sendtxrcncl
handshake and no reconciliation set at all (see this file's header)."
  (let* ((round (peer-recon-round peer))
         (ask (recon-round-missing-ids round decoded-ids))
         (mine (recon-round-ours-to-announce round decoded-ids))
         (set (peer-recon-set peer))
         ;; Ours are announced by wtxid, so they leave the set: the peer is
         ;; about to hear about them the ordinary way.
         (announce (recon-settle-ids set mine)))
    (setf (peer-recon-round peer) nil)
    ;; The rest of the snapshot cancelled in the sketch: both sides hold it.
    (recon-settle-ids set (recon-round-local-ids round))
    (when set (recon-set-clear-snapshot set))
    (values ask announce)))

(defun recon-abandon-round (peer)
  "Give up on the round and fall back to announcing everything in the snapshot
— BIP-330's flood fallback. A failed reconciliation costs bandwidth, never
transactions."
  (let* ((round (peer-recon-round peer))
         (set (peer-recon-set peer))
         (ids (and round (recon-round-local-ids round)))
         (announce (recon-settle-ids set ids)))
    (setf (peer-recon-round peer) nil)
    (when set (recon-set-clear-snapshot set))
    announce))

(defun maybe-start-reconciliation (peer now)
  "The timer entry point: open a round with PEER if it is due. Returns T when
one was started.

Rounds are spread across peers rather than run together, so a node's
announcement pattern does not reveal how many peers it has."
  (when (recon-should-start-round-p peer now)
    (let ((msg (recon-start-round peer now)))
      (when msg
        (send-message peer msg)
        t))))
