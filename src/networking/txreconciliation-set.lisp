(in-package #:bitcoin-lisp.networking)

;;;; BIP-330 reconciliation sets and rounds (Erlay P2 + P4)
;;;;
;;;; ⚠️ BEYOND BITCOIN CORE. Core d3056bc ships the sendtxrcncl HANDSHAKE and
;;;; nothing else: its TxReconciliationTracker (node/txreconciliation.cpp)
;;;; has four methods (PreRegisterPeer, RegisterPeer, ForgetPeer,
;;;; IsPeerRegistered) and no set, short ID, fanout, timer or sketch message --
;;;; protocol.h:266 defines no message past sendtxrcncl -- and the per-peer
;;;; k0/k1 it stores are read by nothing ("Make private once used in the
;;;; following commits", txreconciliation.cpp:40-53). Everything in this file
;;;; is therefore BIP-330's text, not a port: the short ID, the capacity
;;;; estimate, the reqrecon/sketch/reqsketchext/reconcildiff round and its
;;;; extension. The sketches themselves are Core's vendored minisketch
;;;; (minisketch.lisp, checked against Core's own reference implementation).
;;;;
;;;; What is LIVE, and only behind -txreconciliation (default off, Core's
;;;; DEBUG_ONLY flag, init.cpp): a peer that completed the handshake has its
;;;; transactions diverted into a set by RELAY-TRANSACTION (%RECON-HOLD-P,
;;;; minus the fanout draw), the sync loop's per-tick MAYBE-START-RECONCILIATION
;;;; opens rounds as the initiator, and the four round messages are handled
;;;; only from a registered peer in the role BIP-330 gives it
;;;; (protocol.lisp's define-p2p-handler forms). With the flag off no peer can
;;;; register, so none of it is reachable from the wire.
;;;;
;;;; Choices the BIP leaves open and Core has no code for, each a named
;;;; constant below: the set bound, the round interval, the default q, the
;;;; fanout shares, the sketch-capacity ceiling and the round timeout.

(defconstant +recon-short-id-bits+ 32
  "BIP-330 short IDs are 32 bits, which is also minisketch's field size here.")

(defun recon-short-id (k0 k1 wtxid)
  "The 32-bit short ID of WTXID for a peer with salt (K0, K1): BIP-330's `Let s
= SipHash-2-4((k0,k1),wtxid) ... The short ID is equal to 1 + (s mod
0xFFFFFFFF)'. WTXID is in internal byte order, the bytes Core's SipHashUint256
hashes.

Salted per peer so the same transaction has a different ID on every link: an
observer watching one link cannot tell which transactions a node holds on
another, and cannot grind IDs that collide for everybody.

The 1 + (s mod 0xFFFFFFFF) is what keeps 0 out of the range -- 0 has no sketch,
its powers are all zero -- and it is the BIP's exact map, not merely a nonzero
one: a peer that computed `s mod 2^32, 0 remapped to 1' (this function until
2026-09-29) disagrees on nearly every ID, so nothing it reconciles ever
cancels."
  (1+ (mod (bl.crypto:siphash-2-4 k0 k1 wtxid) #xFFFFFFFF)))

(defstruct (recon-set (:constructor %make-recon-set))
  "The transactions waiting to be reconciled with one peer.

Keyed by SHORT ID rather than by wtxid because that is what the sketch holds
and what comes back from a decode; the wtxid is kept alongside so the node can
announce the real transaction once the difference is known.

Two tables, as BIP-330 has them: the SET, where arriving transactions go, and
the SNAPSHOT a round works on. `A reconciliation set is moved to the
corresponding set snapshot after the transmission of the initial sketch', and
`every node should store the snapshot of the current reconciliation set, and
clear the set' -- so a transaction arriving mid-round goes to the next round,
and the round reconciles exactly what its sketch described."
  (by-short-id (make-hash-table :test 'eql) :type hash-table)
  ;; The snapshot, short ID -> wtxid, moved out of BY-SHORT-ID when a round
  ;; starts; NIL between rounds.
  (snapshot nil :type (or null hash-table))
  ;; The RESPONDER's capacity for the snapshot's sketch, NIL when it has not
  ;; answered a reqrecon. A reqsketchext is answered from it: BIP-330's
  ;; extension is the same transactions at a higher capacity `without the
  ;; part sent initially', so the responder must know where that part ended.
  (snapshot-capacity nil :type (or null (integer 0)))
  ;; The INITIATOR's q for this peer, re-estimated after every decoded round
  ;; (RECON-REESTIMATE-Q); NIL until then, which means +RECON-DEFAULT-Q+.
  (q nil :type (or null rational)))

(defun make-recon-set () (%make-recon-set))

(defun recon-set-size (set)
  "Everything SET holds: the set proper and a round's snapshot."
  (+ (hash-table-count (recon-set-by-short-id set))
     (let ((snap (recon-set-snapshot set))) (if snap (hash-table-count snap) 0))))

(defconstant +recon-max-set-size+ 3000
  "The most transactions one peer's reconciliation set holds.

A set has to be bounded: BIP-330 puts set_size on the wire as a uint16 in
reqrecon, and every entry costs sketch capacity on every round until it
settles. The figure is the MAX_SET_SIZE of the Core Erlay work that d3056bc
does not yet carry (its tracker has no set at all), so it is a ported number
without a ported reader to check against. A transaction that finds the set
full is announced by inv instead -- the fallback is flooding, never dropping.
The snapshot counts: it is held too.")

(defun recon-set-add (set k0 k1 wtxid)
  "Queue WTXID for reconciliation. Returns its short ID -- also when it was
already queued, which is a no-op -- or NIL when the set is full, in which case
the caller announces the transaction the ordinary way instead. Core's Erlay
branch shapes AddToSet the same way: a refusal at MAX_SET_SIZE that the relay
path answers with a plain inv."
  (let ((id (recon-short-id k0 k1 wtxid))
        (table (recon-set-by-short-id set)))
    (cond ((gethash id table) id)
          ((>= (recon-set-size set) +recon-max-set-size+) nil)
          (t (setf (gethash id table) (copy-seq wtxid))
             id))))

(defun recon-set-remove (set k0 k1 wtxid)
  "Drop WTXID: the peer is known to hold it (%MARK-TX-KNOWN-TO-PEER is the one
caller), so there is nothing left to reconcile, in the set or in a round's
snapshot. A transaction that left the mempool is not dropped here; the inv
flush skips it when it comes to be announced."
  (let ((id (recon-short-id k0 k1 wtxid)))
    (remhash id (recon-set-by-short-id set))
    (when (recon-set-snapshot set)
      (remhash id (recon-set-snapshot set)))))

(defun recon-set-wtxid (set short-id)
  "The wtxid SHORT-ID stands for, from the snapshot or the set."
  (or (and (recon-set-snapshot set) (gethash short-id (recon-set-snapshot set)))
      (gethash short-id (recon-set-by-short-id set))))

(defun recon-set-short-ids (set)
  "The short IDs in the set proper -- what the NEXT round will reconcile."
  (loop for id being the hash-keys of (recon-set-by-short-id set) collect id))

(defun recon-set-snapshot-ids (set)
  "The short IDs of the round in progress, NIL between rounds."
  (let ((snap (recon-set-snapshot set)))
    (and snap (loop for id being the hash-keys of snap collect id))))

(defun recon-set-take-snapshot (set)
  "BIP-330's move: the set becomes the round's snapshot and the set starts
empty. Returns the snapshot's short IDs.

A snapshot still standing from an earlier round (a reqrecon arriving before
the previous round's reconcildiff, which BIP-330 forbids the initiator to
send) is not dropped: its entries join the new one, so a protocol slip costs
a larger sketch, never a transaction."
  (let ((snap (recon-set-by-short-id set))
        (stale (recon-set-snapshot set)))
    (when stale
      (maphash (lambda (id wtxid) (setf (gethash id snap) wtxid)) stale))
    (setf (recon-set-snapshot set) snap
          (recon-set-by-short-id set) (make-hash-table :test 'eql))
    (recon-set-snapshot-ids set)))

(defun recon-set-clear-snapshot (set)
  "End the round: forget the snapshot. Whatever it still held was settled by
the round (cancelled in the sketch) or is flooded by the caller first."
  (setf (recon-set-snapshot set) nil
        (recon-set-snapshot-capacity set) nil))

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

(defconstant +recon-max-sketch-capacity+ 128
  "The largest capacity this node sketches at, or accepts a first sketch at;
an extension doubles it once.

minisketch's own advice (doc/protocoltips.md:9): `Decode times can be
constrained by limiting sketch capacity'. BIP-330 names no ceiling and Core
has no sketch code to copy one from, so the number is measured, not ported:
this pure-Lisp decoder takes ~0.13 s for a full capacity-128 sketch and ~0.5 s
for the capacity-256 extension (2026-09-29, warm image), which bounds what one
round can cost. Without it a reqrecon claiming a 65535-transaction set with q
near 2 sized a sketch in the hundreds of thousands. A difference larger than
the extension can hold fails to decode, and the round floods -- the BIP's
answer to any failed round.

DECIDED 2026-09-29 (Round 9): this is OUR number, a measured denial-of-service
bound with no Core reference behind it -- Core d3056bc has no sketch exchange,
and BIP-330 gives none. Revisit it against Core's value if Core ever merges
the round.")

(defun recon-build-sketch (short-ids capacity)
  "A sketch of CAPACITY over SHORT-IDS."
  (let ((sk (ms-make-sketch capacity)))
    (dolist (id short-ids sk)
      (ms-sketch-add sk id))))

(defun recon-sketch-extension (short-ids capacity)
  "BIP-330's sketch extension for a round first sketched at CAPACITY: `a
sketch (of the same transactions sketched initially) of higher capacity
without the part sent initially'. The higher capacity is double the first
(so the extension is exactly as large as the first sketch); the syndromes a
capacity-c sketch carries are the first c of any larger one, which is what
lets the initiator append this to what it already holds."
  (subseq (recon-build-sketch short-ids (* 2 capacity)) capacity))

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
  (state :requested :type keyword)
  ;; When the round was opened, on the clock MAYBE-START-RECONCILIATION is
  ;; given: the timeout is measured from here.
  (started 0 :type real))

(defun recon-round-decode (round their-sketch)
  "Merge the responder's sketch with our own and try to decode.

Returns (values short-ids ok-p). A NIL id list with OK-P false is the ordinary
`difference was bigger than the sketch' outcome, which the caller answers with
an extension rather than a failure.

A NIL id list with OK-P TRUE is the other empty answer, and the common one:
the two sides hold the same transactions, so the sketches cancel to zero and
the difference is empty -- MS-DECODE's own verdict, its second value.

On an EXTENDED round THEIR-SKETCH is BIP-330's extension, the syndromes past
the ones the first sketch carried, so it is appended to the first sketch and
the whole decoded at twice the capacity. A first sketch over
+RECON-MAX-SKETCH-CAPACITY+, or an extension that is not exactly as long as
the first sketch, is a failed decode: a sketch this node did not size is not
one it will spend a decode on."
  (let ((stored (recon-round-their-sketch round))
        (extended (recon-round-extended round)))
    (when (if extended
              (or (null stored) (/= (length their-sketch) (length stored)))
              (> (length their-sketch) +recon-max-sketch-capacity+))
      (return-from recon-round-decode (values nil nil)))
    (let* ((full (if extended
                     (concatenate '(vector (unsigned-byte 32)) stored their-sketch)
                     their-sketch))
           (capacity (length full)))
      (unless extended
        (setf (recon-round-their-sketch round) their-sketch))
      (setf (recon-round-capacity round) capacity)
      (ms-decode (ms-sketch-merge
                  (recon-build-sketch (recon-round-local-ids round) capacity)
                  full)))))

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

(defconstant +recon-default-q+ 1/4
  "The initiator's first guess at the fraction of the smaller set the two sides
do not share, before any round has been decoded (RECON-REESTIMATE-Q replaces
it per peer). Unported for the same reason.")

(defconstant +recon-round-timeout-seconds+ 60
  "How long the initiator waits for a round's sketch before it gives the round
up and floods the snapshot, sending reconcildiff(success=0) so the responder
floods its own.

BIP-330 names no timeout and Core at d3056bc has no round to time out, so the
value is Core's nearest analogue: the expiry of an unanswered transaction
request, GETDATA_TX_INTERVAL = 60 s (node/txdownloadman.h:38, armed at
txdownloadman_impl.cpp:278 as current_time + GETDATA_TX_INTERVAL). A reqrecon
is a request whose answer we need in order to announce -- exactly what a
getdata is -- and a responder slower than that has kept the snapshot's
transactions from the peer for as long as Core would wait before asking
someone else. Without a timeout, a responder that never answered pinned the
round for the life of the connection: no later round could open, and the
snapshot was never announced at all.")

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

(defun %peer-recon-set (peer)
  "PEER's reconciliation set, created on first use."
  (or (peer-recon-set peer)
      (setf (peer-recon-set peer) (make-recon-set))))

(defun recon-start-round (peer now)
  "Freeze this peer's set and return the reqrecon that opens the round.

An EMPTY set still opens one. Only the initiator opens rounds, so the
responder's set -- the transactions it held back from us -- drains through
our rounds and no other way: skipping the round whenever OUR side had nothing
left a listening node's transactions unannounced to a quiet dialler (bar the
fanout draw) until its set overflowed into flooding. BIP-330's reqrecon
carries set_size 0 as readily as any other."
  (let* ((set (%peer-recon-set peer))
         (ids (recon-set-take-snapshot set)))
    (setf (peer-recon-last-round peer) now
          (peer-recon-round peer)
          (make-recon-round :peer peer :local-ids ids :state :requested
                            :started now))
    (bl.ser:make-reqrecon-message (length ids)
                                  (or (recon-set-q set) +recon-default-q+))))

(defun recon-respond-to-request (peer their-size q)
  "The responder's half: size a sketch against what the initiator says it has,
and send it. The capacity is BIP-330's estimate, held to
+RECON-MAX-SKETCH-CAPACITY+, and remembered with the snapshot so a
reqsketchext can be answered with the part after it."
  (let* ((set (%peer-recon-set peer))
         (ids (recon-set-take-snapshot set))
         (capacity (min (recon-estimate-capacity (length ids) their-size q)
                        +recon-max-sketch-capacity+)))
    (setf (recon-set-snapshot-capacity set) capacity)
    (bl.ser:make-sketch-message
     (ms-sketch-serialize (recon-build-sketch ids capacity)))))

(defun recon-respond-to-extension (peer)
  "The responder's answer to reqsketchext: the extension of the sketch it sent
for this round (RECON-SKETCH-EXTENSION), over the same frozen snapshot, or NIL
when it has sent no sketch this round to extend. An EMPTY snapshot is still
answered -- its extension is all zeros -- or the initiator's round would wait
forever for it."
  (let* ((set (peer-recon-set peer))
         (capacity (and set (recon-set-snapshot-capacity set))))
    (when capacity
      (bl.ser:make-sketch-message
       (ms-sketch-serialize
        (recon-sketch-extension (recon-set-snapshot-ids set) capacity))))))

(defun recon-settle-ids (set short-ids)
  "Drop SHORT-IDS from SET -- the round's snapshot first, then the set -- and
return the wtxids they were holding.

An id passed here is SETTLED with this peer -- announced to it or requested
from it -- so it must not still be held when the next round reconciles.
Returns NIL for a NIL SET, and skips an id nothing holds any more."
  (when set
    (loop for id in short-ids
          for wtxid = (recon-set-wtxid set id)
          when wtxid
            collect wtxid
            and do (remhash id (recon-set-by-short-id set))
                   (when (recon-set-snapshot set)
                     (remhash id (recon-set-snapshot set))))))

(defun recon-reestimate-q (local-size ours-only theirs-only old-q)
  "BIP-330's q update from a decoded round: `if in previous round
set_size=30 and local_set_size=20, and the *actual* difference was 12, then
a node should compute q as following: q=(12 - |30-20|) / min(30, 20)=0.1'.

The initiator knows its own LOCAL-SIZE and the decoded difference, split into
OURS-ONLY and THEIRS-ONLY; the responder's set size follows, local - ours-only
+ theirs-only, since every element it holds is shared or one of theirs. With
an empty side the formula divides by zero and says nothing, so OLD-Q stands.
The result is held to what reqrecon's uint16 can carry, [0, 65535/32767]."
  (let* ((remote-size (+ (- local-size ours-only) theirs-only))
         (smaller (min local-size remote-size)))
    (if (zerop smaller)
        old-q
        (max 0 (min (/ #xFFFF bl.ser:+recon-q-precision+)
                    (/ (- (+ ours-only theirs-only) (abs (- remote-size local-size)))
                       smaller))))))

(defun recon-finish-round (peer decoded-ids)
  "Split the decoded difference, re-estimate q, and retire the round.

Returns (values ids-to-request wtxids-to-announce). Nothing is sent here — the
caller owns the socket — but the split has to happen while the round's frozen
snapshot is still around.

A SUCCESSFUL round retires the WHOLE snapshot, not only the symmetric
difference: the differing ids were just requested or are announced now, and
the ones that CANCELLED in the sketch cancelled because both sides hold them.
Clearing the snapshot is that retirement -- the set it was moved out of holds
only what arrived after the round began.

BIP-330 is the specification for this: Core at d3056bc ships the sendtxrcncl
handshake and no reconciliation set at all (see this file's header)."
  (let* ((round (peer-recon-round peer))
         (ask (recon-round-missing-ids round decoded-ids))
         (mine (recon-round-ours-to-announce round decoded-ids))
         (set (peer-recon-set peer))
         (announce (recon-settle-ids set mine)))
    (setf (peer-recon-round peer) nil)
    (when set
      (setf (recon-set-q set)
            (recon-reestimate-q (length (recon-round-local-ids round))
                                (length mine) (length ask)
                                (or (recon-set-q set) +recon-default-q+)))
      (recon-set-clear-snapshot set))
    (values ask announce)))

(defun recon-flood-snapshot (peer)
  "The failure path for EITHER role: settle everything in this peer's frozen
snapshot and return the wtxids to announce -- BIP-330's fallback to flooding.
A failed reconciliation costs bandwidth, never transactions.

The initiator's snapshot is the one RECON-START-ROUND moved out of the set
(the round's LOCAL-IDS are its ids); the responder's is the one
RECON-RESPOND-TO-REQUEST moved to answer reqrecon. The responder has no round
object -- only the initiator opens one -- which is why this reads the set's
snapshot and not the round. BIP-330: `If success=0 (reconciliation failure),
receiver should announce all transactions from the reconciliation set via an
inv message', and the snapshot `is cleared by the sender and the receiver of
the message'. A transaction that arrived after the snapshot was taken is in
the set, not the snapshot, and waits for the next round."
  (let* ((set (peer-recon-set peer))
         (announce (and set (recon-settle-ids set (recon-set-snapshot-ids set)))))
    (when set (recon-set-clear-snapshot set))
    announce))

(defun recon-abandon-round (peer)
  "The INITIATOR gives up on its round: close it and flood the snapshot. The
caller sends the reconcildiff(success=0) that tells the responder to do the
same with its own snapshot."
  (setf (peer-recon-round peer) nil)
  (recon-flood-snapshot peer))

(defun recon-round-timed-out-p (peer now)
  "T when PEER has a round open for +RECON-ROUND-TIMEOUT-SECONDS+ or longer."
  (let ((round (peer-recon-round peer)))
    (and round
         (>= (- now (recon-round-started round)) +recon-round-timeout-seconds+))))
