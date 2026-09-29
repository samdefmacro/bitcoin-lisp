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
;;;; fanout shares and the sketch-capacity ceiling.

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
announce the real transaction once the difference is known."
  (by-short-id (make-hash-table :test 'eql) :type hash-table)
  ;; Snapshot taken when a round starts. A round spans several messages, and
  ;; transactions keep arriving meanwhile; reconciling against a moving set
  ;; would make the sketch describe something the peer never saw.
  (snapshot nil)
  ;; The RESPONDER's capacity for the snapshot's sketch, NIL when it has not
  ;; answered a reqrecon. A reqsketchext is answered from it: BIP-330's
  ;; extension is the same transactions at a higher capacity `without the
  ;; part sent initially', so the responder must know where that part ended.
  (snapshot-capacity nil :type (or null (integer 0))))

(defun make-recon-set () (%make-recon-set))

(defun recon-set-size (set) (hash-table-count (recon-set-by-short-id set)))

(defconstant +recon-max-set-size+ 3000
  "The most transactions one peer's reconciliation set holds.

A set has to be bounded: BIP-330 puts set_size on the wire as a uint16 in
reqrecon, and every entry costs sketch capacity on every round until it
settles. The figure is the MAX_SET_SIZE of the Core Erlay work that d3056bc
does not yet carry (its tracker has no set at all), so it is a ported number
without a ported reader to check against. A transaction that finds the set
full is announced by inv instead -- the fallback is flooding, never dropping.")

(defun recon-set-add (set k0 k1 wtxid)
  "Queue WTXID for reconciliation. Returns its short ID -- also when it was
already queued, which is a no-op -- or NIL when the set is full, in which case
the caller announces the transaction the ordinary way instead. Core's Erlay
branch shapes AddToSet the same way: a refusal at MAX_SET_SIZE that the relay
path answers with a plain inv."
  (let ((id (recon-short-id k0 k1 wtxid))
        (table (recon-set-by-short-id set)))
    (cond ((gethash id table) id)
          ((>= (hash-table-count table) +recon-max-set-size+) nil)
          (t (setf (gethash id table) (copy-seq wtxid))
             id))))

(defun recon-set-remove (set k0 k1 wtxid)
  "Drop WTXID: the peer is known to hold it (%MARK-TX-KNOWN-TO-PEER is the one
caller), so there is nothing left to reconcile. A transaction that left the
mempool is not dropped here; the inv flush skips it when it comes to be
announced."
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
answer to any failed round.")

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
  (state :requested :type keyword))

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
  (let ((ids (recon-set-take-snapshot (%peer-recon-set peer))))
    (setf (peer-recon-last-round peer) now
          (peer-recon-round peer)
          (make-recon-round :peer peer :local-ids ids :state :requested))
    (bl.ser:make-reqrecon-message (length ids) +recon-default-q+)))

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
        (recon-sketch-extension (recon-set-snapshot set) capacity))))))

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

(defun recon-flood-snapshot (peer)
  "The failure path for EITHER role: settle everything in this peer's frozen
snapshot and return the wtxids to announce -- BIP-330's fallback to flooding.
A failed reconciliation costs bandwidth, never transactions.

The initiator's snapshot is the one RECON-START-ROUND froze (the round's
LOCAL-IDS are that same list); the responder's is the one
RECON-RESPOND-TO-REQUEST froze to answer reqrecon. The responder has no round
object -- only the initiator opens one -- which is why this reads the set's
snapshot and not the round: the responder's reconcildiff(success=0) path used
to reach for a round it never had, find none, and announce nothing, so
everything the initiator could not decode stayed unannounced until some later
round happened to settle it. BIP-330: `If success=0 (reconciliation failure),
receiver should announce all transactions from the reconciliation set via an
inv message', and the snapshot `is cleared by the sender and the receiver of
the message'. A transaction that arrived after the snapshot was taken is not
part of this round; it stays in the set for the next one."
  (let* ((set (peer-recon-set peer))
         (announce (and set (recon-settle-ids set (recon-set-snapshot set)))))
    (when set (recon-set-clear-snapshot set))
    announce))

(defun recon-abandon-round (peer)
  "The INITIATOR gives up on its round: close it and flood the snapshot. The
caller sends the reconcildiff(success=0) that tells the responder to do the
same with its own snapshot."
  (setf (peer-recon-round peer) nil)
  (recon-flood-snapshot peer))

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
