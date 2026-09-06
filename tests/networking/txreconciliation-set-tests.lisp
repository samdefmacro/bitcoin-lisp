(in-package #:bitcoin-lisp.tests)

(def-suite :txreconciliation-set-tests
  :description "BIP-330 reconciliation sets, short IDs and fanout (Erlay P2)"
  :in :bitcoin-lisp-tests)

(in-suite :txreconciliation-set-tests)

;;;; ⚠️ Everything under test here is BEYOND Bitcoin Core, which ships the
;;;; sendtxrcncl handshake and nothing else. There is no reference
;;;; implementation to check against, so these tests assert the PROPERTIES
;;;; BIP-330 relies on rather than agreement with anyone — which is the weaker
;;;; kind of verification, and worth saying so.

(defun %rc-wtxid (n)
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element n))

(defun %rc-count (set)
  "How many transactions SET is holding for reconciliation. This file's one
reader for that, since almost every test here asserts on it."
  (bl.net::recon-set-size set))

(defun %rc-hold (peer wtxids &key (k0 11) (k1 22))
  "Queue WTXIDS in PEER's reconciliation set — what RELAY-TRANSACTION does for
a registered peer that did not draw the fanout slot — and return the set. The
set is created on first use, exactly as the relay path creates it."
  (let ((set (bl.net::%peer-recon-set peer)))
    (dolist (w wtxids set)
      (bl.net::recon-set-add set k0 k1 w))))

(test short-ids-are-per-peer-and-never-zero
  "Salted per peer so an observer on one link cannot tell which transactions a
node holds on another, and cannot grind IDs that collide for everybody. Zero is
remapped because 0 has no sketch — its powers are all zero, so it would be
INVISIBLE rather than merely unlucky."
  (let ((wtxid (%rc-wtxid 7)))
    (let ((a (bl.net::recon-short-id 1 2 wtxid))
          (b (bl.net::recon-short-id 3 4 wtxid)))
      (is (/= a b) "the same transaction must look different on different links")
      (is (<= 1 a #xFFFFFFFF))
      (is (<= 1 b #xFFFFFFFF))))
  ;; Same salt, same answer.
  (is (= (bl.net::recon-short-id 9 9 (%rc-wtxid 1))
         (bl.net::recon-short-id 9 9 (%rc-wtxid 1))))
  ;; Across many transactions, none is ever zero.
  (is (loop for n from 0 below 200
            always (plusp (bl.net::recon-short-id 5 6 (%rc-wtxid n))))))

(test a-reconciliation-set-is-keyed-by-short-id
  "Keyed by short ID because that is what the sketch holds and what a decode
returns; the wtxid rides along so the node can announce the real transaction
once the difference is known."
  (let ((set (bl.net::make-recon-set))
        (wtxid (%rc-wtxid 11)))
    (is (= 0 (%rc-count set)))
    (let ((id (bl.net::recon-set-add set 1 2 wtxid)))
      (is-true id)
      (is (= 1 (%rc-count set)))
      (is (equalp wtxid (bl.net::recon-set-wtxid set id)))
      ;; Adding the same transaction again is a no-op, not a duplicate.
      (is-false (bl.net::recon-set-add set 1 2 wtxid))
      (is (= 1 (%rc-count set)))
      ;; Removal is by wtxid, resolved through the same salt.
      (bl.net::recon-set-remove set 1 2 wtxid)
      (is (= 0 (%rc-count set))))))

(test a-round-reconciles-a-frozen-snapshot
  "A round spans several messages while transactions keep arriving.
Reconciling against a moving set would make the sketch describe something the
peer never saw, so the round works from a snapshot."
  (let ((set (bl.net::make-recon-set)))
    (dotimes (i 3) (bl.net::recon-set-add set 1 2 (%rc-wtxid i)))
    (let ((snap (bl.net::recon-set-take-snapshot set)))
      (is (= 3 (length snap)))
      ;; More arrive mid-round; the snapshot does not move.
      (dotimes (i 3) (bl.net::recon-set-add set 1 2 (%rc-wtxid (+ 100 i))))
      (is (= 6 (%rc-count set)))
      (is (= 3 (length (bl.net::recon-set-snapshot set))))
      (bl.net::recon-set-clear-snapshot set)
      (is-false (bl.net::recon-set-snapshot set)))))

(test two-sets-reconcile-to-their-difference
  "The whole point, end to end over the sketch layer: each side sketches its
own short IDs, the sketches are merged, and what decodes out is exactly what
one side has and the other does not."
  (let* ((mine (bl.net::make-recon-set))
         (theirs (bl.net::make-recon-set))
         (k0 77) (k1 88)
         (shared (loop for i from 0 below 5 collect (%rc-wtxid i)))
         (only-mine (loop for i from 20 below 23 collect (%rc-wtxid i)))
         (only-theirs (loop for i from 40 below 42 collect (%rc-wtxid i))))
    (dolist (w (append shared only-mine))
      (bl.net::recon-set-add mine k0 k1 w))
    (dolist (w (append shared only-theirs))
      (bl.net::recon-set-add theirs k0 k1 w))
    (let* ((capacity (bl.net::recon-estimate-capacity
                      (%rc-count mine)
                      (%rc-count theirs)
                      0.5d0))
           (a (bl.net::recon-build-sketch
               (bl.net::recon-set-short-ids mine) capacity))
           (b (bl.net::recon-build-sketch
               (bl.net::recon-set-short-ids theirs) capacity))
           (decoded (bl.net::ms-decode
                     (bl.net::ms-sketch-merge a b))))
      (is-true decoded "the difference must decode at the estimated capacity")
      (let ((want (sort (append (mapcar (lambda (w)
                                          (bl.net::recon-short-id k0 k1 w))
                                        only-mine)
                                (mapcar (lambda (w)
                                          (bl.net::recon-short-id k0 k1 w))
                                        only-theirs))
                        #'<)))
        (is (equal want (sort (copy-list decoded) #'<)))
        ;; And every recovered ID resolves back to a transaction one side holds.
        (dolist (id decoded)
          (is-true (or (bl.net::recon-set-wtxid mine id)
                       (bl.net::recon-set-wtxid theirs id))))))))

(test the-capacity-estimate-follows-bip330
  "|local - remote| + q * min(local, remote) + 1. The estimate is deliberately
tight — guessing high costs bandwidth on every round, which is what Erlay
exists to save, so the extension round is the safety net rather than slack."
  (is (= 1 (bl.net::recon-estimate-capacity 0 0 0.5d0)))
  (is (= 6 (bl.net::recon-estimate-capacity 10 5 0.0d0)))
  ;; q pays for the shared-but-unknown part of the smaller set.
  (is (= 11 (bl.net::recon-estimate-capacity 10 5 1.0d0)))
  (is (= 3 (bl.net::recon-estimate-capacity 4 4 0.5d0))))

(test fanout-selection-is-deterministic-and-a-minority
  "Reconciliation alone would let an adversary time which link announces a
transaction first, so a small random subset still gets it immediately. The
choice must be per TRANSACTION — a fixed subset would be a fixed observation
point — and deterministic, so a retry does not reveal a fresh sample."
  (let ((wtxid (%rc-wtxid 3)))
    (is (eq (bl.net::recon-fanout-target-p wtxid 1234 8 nil)
            (bl.net::recon-fanout-target-p wtxid 1234 8 nil))
        "same transaction, same peer, same answer"))
  ;; Over many transactions the inbound fraction is a small minority.
  (let ((hits (loop for n from 0 below 1000
                    count (bl.net::recon-fanout-target-p
                           (%rc-wtxid (mod n 256)) (+ 1000 n) 8 nil))))
    (is (< hits 300) "inbound fanout must stay a minority, got ~D/1000" hits))
  ;; Different peers get different draws for the same transaction.
  (let* ((wtxid (%rc-wtxid 5))
         (answers (loop for salt from 1 to 40
                        collect (bl.net::recon-fanout-target-p
                                 wtxid salt 8 nil))))
    (is (and (member t answers) (member nil answers))
        "the same transaction must not be fanned out to all peers or none")))

;;; --- The sketch exchange (P4) ------------------------------------------------

(test bip330-messages-round-trip
  "The four messages a round is made of. Their formats are BIP-330's, but the
q scale is a choice — Core has no reqrecon at all — so it is pinned here as
well as named in the source."
  ;; reqrecon
  (multiple-value-bind (size q)
      (bl.ser:parse-reqrecon-payload
       (subseq (bl.ser:make-reqrecon-message 1234 0.25d0) 24))
    (is (= 1234 size))
    (is (= 1/4 q) "q must survive the fixed-point round trip exactly"))
  ;; A q of zero and a q at the top of the range.
  (multiple-value-bind (size q)
      (bl.ser:parse-reqrecon-payload
       (subseq (bl.ser:make-reqrecon-message 0 0d0) 24))
    (is (= 0 size))
    (is (= 0 q)))
  ;; sketch: the bytes and nothing else, so the capacity is implied by length.
  (let ((bytes (make-array 12 :element-type '(unsigned-byte 8) :initial-element 7)))
    (is (equalp bytes (bl.ser:parse-sketch-payload
                       (subseq (bl.ser:make-sketch-message bytes) 24)))))
  ;; reqsketchext carries nothing.
  (is (= 24 (length (bl.ser:make-reqsketchext-message))))
  ;; reconcildiff, both ways.
  (multiple-value-bind (ok ids)
      (bl.ser:parse-reconcildiff-payload
       (subseq (bl.ser:make-reconcildiff-message
                t '(#xDEADBEEF 1 #xFFFFFFFF)) 24))
    (is-true ok)
    (is (equal '(#xDEADBEEF 1 #xFFFFFFFF) ids)))
  (multiple-value-bind (ok ids)
      (bl.ser:parse-reconcildiff-payload
       (subseq (bl.ser:make-reconcildiff-message nil '()) 24))
    (is-false ok)
    (is (null ids) "a failed round asks for nothing and both sides flood")))

(test a-round-splits-the-difference-into-mine-and-yours
  "A symmetric difference says an element is on exactly ONE side, not which.
So after decoding, the initiator has to sort the recovered IDs into the ones it
already holds — which it must ANNOUNCE — and the ones it does not, which it
must ASK for. Getting that backwards would have each side request what it
already has and announce nothing."
  (let* ((k0 5) (k1 6)
         (mine (bl.net::make-recon-set))
         (theirs (bl.net::make-recon-set))
         (shared (loop for i from 0 below 4 collect (%rc-wtxid i)))
         (only-mine (loop for i from 30 below 33 collect (%rc-wtxid i)))
         (only-theirs (loop for i from 60 below 62 collect (%rc-wtxid i))))
    (dolist (w (append shared only-mine))
      (bl.net::recon-set-add mine k0 k1 w))
    (dolist (w (append shared only-theirs))
      (bl.net::recon-set-add theirs k0 k1 w))
    (let* ((capacity (bl.net::recon-estimate-capacity
                      (%rc-count mine)
                      (%rc-count theirs)
                      0.5d0))
           (round (bl.net::make-recon-round
                   :local-ids (bl.net::recon-set-short-ids mine)))
           (their-sketch (bl.net::recon-build-sketch
                          (bl.net::recon-set-short-ids theirs)
                          capacity)))
      (multiple-value-bind (ids ok)
          (bl.net::recon-round-decode round their-sketch)
        (is-true ok)
        (let ((ask (bl.net::recon-round-missing-ids round ids))
              (tell (bl.net::recon-round-ours-to-announce round ids)))
          (is (= (length only-theirs) (length ask))
              "ask for exactly what only they have")
          (is (= (length only-mine) (length tell))
              "announce exactly what only we have")
          ;; And the two halves partition the difference, with no overlap.
          (is (null (intersection ask tell)))
          (is (= (length ids) (+ (length ask) (length tell))))
          ;; Every id we ask for resolves in THEIR set, and none in ours.
          (dolist (id ask)
            (is-true (bl.net::recon-set-wtxid theirs id))
            (is-false (bl.net::recon-set-wtxid mine id))))))))

(test a-decoded-round-is-a-claim-that-the-protocol-must-check
  "The uncomfortable property, stated plainly rather than assumed away.

A merged sketch whose difference exceeds the capacity does NOT reliably fail to
decode: it decodes to whatever set of that size reproduces it, which is usually
not the real difference. So a successful decode is a CLAIM, and BIP-330 treats
it as one — the initiator asks for the short IDs it believes it is missing, the
peer announces what it can, and anything still absent is picked up by the next
round or by fanout. Nothing is lost, but nothing here is a guarantee either.

Asserted so the property stays documented in something that runs, and so a
future change that starts trusting the decode has to delete this test first."
  (let* ((truth (loop for i from 1 to 20 collect (* i 7919)))
         (round (bl.net::make-recon-round :local-ids truth))
         ;; A capacity far below the real difference.
         (their-sketch (bl.net::recon-build-sketch
                        '(#xAAAAAAAA #xBBBBBBBB) 2)))
    (multiple-value-bind (ids ok)
        (bl.net::recon-round-decode round their-sketch)
      (when ok
        ;; If it decoded at all, the answer reproduces the merged sketch...
        (is (= 2 (length ids)))
        ;; ...and is nonetheless NOT the real difference, which is the point.
        (is (not (subsetp ids truth))
            "an over-capacity decode is consistent, not correct")))
    ;; Sized correctly, the same machinery gets it right — so the failure above
    ;; is about capacity, not about the decoder.
    (let* ((theirs '(#xAAAAAAAA #xBBBBBBBB))
           (capacity (+ (length truth) (length theirs)))
           (round2 (bl.net::make-recon-round :local-ids truth))
           (sketch (bl.net::recon-build-sketch theirs capacity)))
      (multiple-value-bind (ids ok)
          (bl.net::recon-round-decode round2 sketch)
        (is-true ok)
        (is (= (+ (length truth) (length theirs)) (length ids)))
        (is (equal (sort (copy-list theirs) #'<)
                   (sort (bl.net::recon-round-missing-ids round2 ids) #'<)))))))

;;; --- Wiring into the live relay path ------------------------------------------

(defmacro %with-relay-network (&body body)
  "relay-transaction is a no-op unless relay is enabled for the network, which
on mainnet it is not. These tests are about the reconciliation branch inside
it, so they run on a network where relay is on."
  `(let ((bl:*network* :testnet4)) ,@body))

(defun %rc-peer (&key registered (inbound nil) (k0 11) (k1 22) (we-initiate t))
  (let ((p (bl.net:make-peer :address "10.0.0.1" :inbound nil :state :ready)))
    ;; PEER-TX-RELAY-P is derived, not a slot: it reads the connection type and
    ;; the peer's version fRelay. A default peer is neither block-relay nor
    ;; feeler and has no stored version, which counts as relaying — Core's
    ;; pre-70001 default — so nothing needs setting for it.
    (setf (bl.net:peer-state p) :ready
          (bl.net:peer-inbound p) inbound
          (bl.net::peer-recon-registered p) registered
          (bl.net::peer-recon-we-initiate p) we-initiate)
    (when registered
      (setf (bl.net::peer-recon-k0 p) k0
            (bl.net::peer-recon-k1 p) k1))
    p))

(test relay-is-untouched-when-reconciliation-is-off
  "The property that makes this safe to ship: with -txreconciliation off no
peer is ever registered, so every transaction takes the ordinary announcement
path and nothing is held back. This is the test that would catch a diversion
leaking into the default configuration."
  (%with-relay-network
    (let ((peer (%rc-peer :registered nil))
          (txid (%rc-wtxid 1))
          (wtxid (%rc-wtxid 2)))
      (bl.net:relay-transaction txid nil (list peer)
                                                  :wtxid wtxid :fee-rate 1)
      (is (= 1 (length (bl.net:peer-tx-inv-queue peer)))
          "an unregistered peer must be announced to, not reconciled with")
      (is-false (bl.net::peer-recon-set peer)
                "and no reconciliation set is even created"))))

(test a-registered-peer-holds-transactions-for-reconciliation
  "With the handshake done, most transactions go into the set instead of the
announcement queue — and the ones that do not are the fanout draw, which is
what keeps the first announcement from revealing the origin."
  (%with-relay-network
    ;; Eight reconciling peers, so the one outbound fanout destination is a
    ;; 1-in-8 draw. With a SINGLE peer everything is announced instead — one
    ;; destination out of one peer is that peer — which is correct, and is its
    ;; own test below.
    (let* ((peer (%rc-peer :registered t))
           (peers (cons peer (loop repeat 7 collect (%rc-peer :registered t))))
           (held 0) (announced 0))
      (dotimes (i 60)
        (let ((wtxid (%rc-wtxid i)))
          (setf (bl.net:peer-tx-inv-queue peer) '())
          (bl.net:relay-transaction
           wtxid nil peers :wtxid wtxid :fee-rate 1)
          (if (bl.net:peer-tx-inv-queue peer)
              (incf announced)
              (incf held))))
      (is (plusp held) "reconciliation must actually hold transactions back")
      (is (plusp announced) "and fanout must still let some through immediately")
      (is (> held announced)
          "holding is the common case; fanout is the minority (~D held, ~D fanned out)"
          held announced)
      (is (= held (%rc-count (bl.net::%peer-recon-set peer)))
          "everything held is in the set, once each"))))

(test a-lone-reconciling-peer-is-simply-announced-to
  "One outbound fanout destination out of ONE reconciling peer is that peer, so
everything is announced. Holding transactions back to reconcile with nobody
else would only delay them, which is the opposite of the point."
  (%with-relay-network
   (let ((peer (%rc-peer :registered t)))
     (dotimes (i 10)
       (let ((wtxid (%rc-wtxid i)))
         (bl.net:relay-transaction
          wtxid nil (list peer) :wtxid wtxid :fee-rate 1)))
     (is (= 10 (length (bl.net:peer-tx-inv-queue peer))))
     (is-false (bl.net::peer-recon-set peer)))))

(test a-transaction-without-a-wtxid-is-never-held-back
  "Short IDs are computed from the wtxid. Without one there is nothing to put
in a sketch, so the transaction must take the ordinary path rather than
vanishing into a set that can never describe it."
  (%with-relay-network
    (let ((peer (%rc-peer :registered t))
          (txid (%rc-wtxid 3)))
      (bl.net:relay-transaction txid nil (list peer)
                                                  :wtxid nil :fee-rate 1)
      (is (= 1 (length (bl.net:peer-tx-inv-queue peer)))))))

(test only-the-dialling-side-opens-a-round
  "Both ends opening rounds against each other at once would waste a sketch
every time. BIP-330 gives the initiator role to the outbound peer, which is
what the handshake recorded."
  (let ((out (%rc-peer :registered t :we-initiate t))
        (in (%rc-peer :registered t :we-initiate nil :inbound t))
        (now 100000))
    (dolist (p (list out in))
      (%rc-hold p (list (%rc-wtxid 9))))
    (is-true (bl.net::recon-should-start-round-p out now))
    (is-false (bl.net::recon-should-start-round-p in now))))

(test rounds-are-spaced-and-not-doubled-up
  "One round per peer at a time, and not more often than the interval — a node
that reconciled continuously would announce in a pattern that reveals how many
peers it has."
  (let ((peer (%rc-peer :registered t))
        (now 100000))
    (%rc-hold peer (list (%rc-wtxid 4)))
    (is-true (bl.net::recon-should-start-round-p peer now))
    (is-true (bl.net::recon-start-round peer now))
    ;; A round is in flight: not again.
    (is-false (bl.net::recon-should-start-round-p peer (+ now 100)))
    ;; Even once it clears, the interval still applies.
    (setf (bl.net::peer-recon-round peer) nil)
    (is-false (bl.net::recon-should-start-round-p peer now))
    (is-true (bl.net::recon-should-start-round-p
              peer (+ now bl.net::+recon-round-interval-seconds+)))))

(test an-empty-set-does-not-open-a-round
  "Nothing to reconcile means no reqrecon: a sketch of an empty set is pure
overhead, and Erlay exists to remove overhead."
  (let ((peer (%rc-peer :registered t)))
    (is-false (bl.net::recon-start-round peer 100000))
    (is-false (bl.net::peer-recon-round peer))))

(test abandoning-a-round-announces-everything-rather-than-losing-it
  "The flood fallback. A reconciliation that cannot decode costs bandwidth —
never transactions — so everything in the frozen snapshot goes out the ordinary
way and leaves the set."
  (let* ((peer (%rc-peer :registered t))
         (wtxids (loop for i from 40 below 45 collect (%rc-wtxid i)))
         (set (%rc-hold peer wtxids)))
    (bl.net::recon-start-round peer 100000)
    (let ((flooded (bl.net::recon-abandon-round peer)))
      (is (= (length wtxids) (length flooded))
          "every held transaction must be announced after a failed round")
      (is (= 0 (%rc-count set))
          "and leave the set, so it is not announced twice")
      (is-false (bl.net::peer-recon-round peer)))))

(test a-successful-round-retires-the-whole-snapshot
  "After a round DECODES, the peer holds every transaction the frozen snapshot
described: the ones in the symmetric difference because they have just been
requested from it or announced to it, and the ones that CANCELLED in the
sketch because both sides already had them. Retiring only the difference kept
every cancelled id for the life of the connection, so the set grew
monotonically and RECON-ESTIMATE-CAPACITY sized each later sketch against dead
weight -- the bandwidth Erlay exists to save. BIP-330 is the specification
here; Core ships no reconciliation set to compare against."
  (let* ((peer (%rc-peer :registered t))
         (shared (loop for i from 0 below 20 collect (%rc-wtxid i)))
         (ours-only (loop for i from 60 below 63 collect (%rc-wtxid i)))
         (set (%rc-hold peer (append shared ours-only))))
    (bl.net::recon-start-round peer 100000)
    (is (= 23 (%rc-count set)))
    ;; The peer held SHARED, so those cancel in the sketch and the decoded
    ;; difference is OURS-ONLY alone.
    (multiple-value-bind (ask announce)
        (bl.net::recon-finish-round
         peer (mapcar (lambda (w) (bl.net::recon-short-id 11 22 w)) ours-only))
      (is (null ask) "nothing to request: the peer was missing nothing")
      (is (= 3 (length announce))))
    (is (= 0 (%rc-count set))
        "the 20 that cancelled must leave the set too, or it never shrinks")))

(test a-reconcildiff-retires-the-responders-whole-snapshot
  "The responder half of the same rule. It froze a snapshot to answer
reqrecon; a SUCCESS reconcildiff asks for the ids it was missing, and the rest
of that snapshot is settled because cancelling in the sketch is exactly what
both sides holding it looks like."
  (let* ((peer (%rc-peer :registered t))
         (wtxids (loop for i from 70 below 78 collect (%rc-wtxid i)))
         (set (%rc-hold peer wtxids))
         (asked (bl.net::recon-short-id 11 22 (first wtxids))))
    ;; RECON-RESPOND-TO-REQUEST freezes the set like this before it sketches.
    (bl.net::recon-set-take-snapshot set)
    (bl.net::%handle-reconcildiff
     peer (subseq (bl.ser:make-reconcildiff-message t (list asked)) 24))
    (is (= 1 (length (bl.net:peer-tx-inv-queue peer)))
        "only the asked-for transaction is announced")
    (is (= 0 (%rc-count set))
        "and the seven that cancelled leave the set with it")))
