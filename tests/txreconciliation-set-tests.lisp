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

(test short-ids-are-per-peer-and-never-zero
  "Salted per peer so an observer on one link cannot tell which transactions a
node holds on another, and cannot grind IDs that collide for everybody. Zero is
remapped because 0 has no sketch — its powers are all zero, so it would be
INVISIBLE rather than merely unlucky."
  (let ((wtxid (%rc-wtxid 7)))
    (let ((a (bitcoin-lisp.networking::recon-short-id 1 2 wtxid))
          (b (bitcoin-lisp.networking::recon-short-id 3 4 wtxid)))
      (is (/= a b) "the same transaction must look different on different links")
      (is (<= 1 a #xFFFFFFFF))
      (is (<= 1 b #xFFFFFFFF))))
  ;; Same salt, same answer.
  (is (= (bitcoin-lisp.networking::recon-short-id 9 9 (%rc-wtxid 1))
         (bitcoin-lisp.networking::recon-short-id 9 9 (%rc-wtxid 1))))
  ;; Across many transactions, none is ever zero.
  (is (loop for n from 0 below 200
            always (plusp (bitcoin-lisp.networking::recon-short-id 5 6 (%rc-wtxid n))))))

(test a-reconciliation-set-is-keyed-by-short-id
  "Keyed by short ID because that is what the sketch holds and what a decode
returns; the wtxid rides along so the node can announce the real transaction
once the difference is known."
  (let ((set (bitcoin-lisp.networking::make-recon-set))
        (wtxid (%rc-wtxid 11)))
    (is (= 0 (bitcoin-lisp.networking::recon-set-size set)))
    (let ((id (bitcoin-lisp.networking::recon-set-add set 1 2 wtxid)))
      (is-true id)
      (is (= 1 (bitcoin-lisp.networking::recon-set-size set)))
      (is (equalp wtxid (bitcoin-lisp.networking::recon-set-wtxid set id)))
      ;; Adding the same transaction again is a no-op, not a duplicate.
      (is-false (bitcoin-lisp.networking::recon-set-add set 1 2 wtxid))
      (is (= 1 (bitcoin-lisp.networking::recon-set-size set)))
      ;; Removal is by wtxid, resolved through the same salt.
      (bitcoin-lisp.networking::recon-set-remove set 1 2 wtxid)
      (is (= 0 (bitcoin-lisp.networking::recon-set-size set))))))

(test a-round-reconciles-a-frozen-snapshot
  "A round spans several messages while transactions keep arriving.
Reconciling against a moving set would make the sketch describe something the
peer never saw, so the round works from a snapshot."
  (let ((set (bitcoin-lisp.networking::make-recon-set)))
    (dotimes (i 3) (bitcoin-lisp.networking::recon-set-add set 1 2 (%rc-wtxid i)))
    (let ((snap (bitcoin-lisp.networking::recon-set-take-snapshot set)))
      (is (= 3 (length snap)))
      ;; More arrive mid-round; the snapshot does not move.
      (dotimes (i 3) (bitcoin-lisp.networking::recon-set-add set 1 2 (%rc-wtxid (+ 100 i))))
      (is (= 6 (bitcoin-lisp.networking::recon-set-size set)))
      (is (= 3 (length (bitcoin-lisp.networking::recon-set-snapshot set))))
      (bitcoin-lisp.networking::recon-set-clear-snapshot set)
      (is-false (bitcoin-lisp.networking::recon-set-snapshot set)))))

(test two-sets-reconcile-to-their-difference
  "The whole point, end to end over the sketch layer: each side sketches its
own short IDs, the sketches are merged, and what decodes out is exactly what
one side has and the other does not."
  (let* ((mine (bitcoin-lisp.networking::make-recon-set))
         (theirs (bitcoin-lisp.networking::make-recon-set))
         (k0 77) (k1 88)
         (shared (loop for i from 0 below 5 collect (%rc-wtxid i)))
         (only-mine (loop for i from 20 below 23 collect (%rc-wtxid i)))
         (only-theirs (loop for i from 40 below 42 collect (%rc-wtxid i))))
    (dolist (w (append shared only-mine))
      (bitcoin-lisp.networking::recon-set-add mine k0 k1 w))
    (dolist (w (append shared only-theirs))
      (bitcoin-lisp.networking::recon-set-add theirs k0 k1 w))
    (let* ((capacity (bitcoin-lisp.networking::recon-estimate-capacity
                      (bitcoin-lisp.networking::recon-set-size mine)
                      (bitcoin-lisp.networking::recon-set-size theirs)
                      0.5d0))
           (a (bitcoin-lisp.networking::recon-build-sketch
               (bitcoin-lisp.networking::recon-set-short-ids mine) capacity))
           (b (bitcoin-lisp.networking::recon-build-sketch
               (bitcoin-lisp.networking::recon-set-short-ids theirs) capacity))
           (decoded (bitcoin-lisp.networking::ms-decode
                     (bitcoin-lisp.networking::ms-sketch-merge a b))))
      (is-true decoded "the difference must decode at the estimated capacity")
      (let ((want (sort (append (mapcar (lambda (w)
                                          (bitcoin-lisp.networking::recon-short-id k0 k1 w))
                                        only-mine)
                                (mapcar (lambda (w)
                                          (bitcoin-lisp.networking::recon-short-id k0 k1 w))
                                        only-theirs))
                        #'<)))
        (is (equal want (sort (copy-list decoded) #'<)))
        ;; And every recovered ID resolves back to a transaction one side holds.
        (dolist (id decoded)
          (is-true (or (bitcoin-lisp.networking::recon-set-wtxid mine id)
                       (bitcoin-lisp.networking::recon-set-wtxid theirs id))))))))

(test the-capacity-estimate-follows-bip330
  "|local - remote| + q * min(local, remote) + 1. The estimate is deliberately
tight — guessing high costs bandwidth on every round, which is what Erlay
exists to save, so the extension round is the safety net rather than slack."
  (is (= 1 (bitcoin-lisp.networking::recon-estimate-capacity 0 0 0.5d0)))
  (is (= 6 (bitcoin-lisp.networking::recon-estimate-capacity 10 5 0.0d0)))
  ;; q pays for the shared-but-unknown part of the smaller set.
  (is (= 11 (bitcoin-lisp.networking::recon-estimate-capacity 10 5 1.0d0)))
  (is (= 3 (bitcoin-lisp.networking::recon-estimate-capacity 4 4 0.5d0))))

(test fanout-selection-is-deterministic-and-a-minority
  "Reconciliation alone would let an adversary time which link announces a
transaction first, so a small random subset still gets it immediately. The
choice must be per TRANSACTION — a fixed subset would be a fixed observation
point — and deterministic, so a retry does not reveal a fresh sample."
  (let ((wtxid (%rc-wtxid 3)))
    (is (eq (bitcoin-lisp.networking::recon-fanout-target-p wtxid 1234 8 nil)
            (bitcoin-lisp.networking::recon-fanout-target-p wtxid 1234 8 nil))
        "same transaction, same peer, same answer"))
  ;; Over many transactions the inbound fraction is a small minority.
  (let ((hits (loop for n from 0 below 1000
                    count (bitcoin-lisp.networking::recon-fanout-target-p
                           (%rc-wtxid (mod n 256)) (+ 1000 n) 8 nil))))
    (is (< hits 300) "inbound fanout must stay a minority, got ~D/1000" hits))
  ;; Different peers get different draws for the same transaction.
  (let* ((wtxid (%rc-wtxid 5))
         (answers (loop for salt from 1 to 40
                        collect (bitcoin-lisp.networking::recon-fanout-target-p
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
      (bitcoin-lisp.serialization:parse-reqrecon-payload
       (subseq (bitcoin-lisp.serialization:make-reqrecon-message 1234 0.25d0) 24))
    (is (= 1234 size))
    (is (= 1/4 q) "q must survive the fixed-point round trip exactly"))
  ;; A q of zero and a q at the top of the range.
  (multiple-value-bind (size q)
      (bitcoin-lisp.serialization:parse-reqrecon-payload
       (subseq (bitcoin-lisp.serialization:make-reqrecon-message 0 0d0) 24))
    (is (= 0 size))
    (is (= 0 q)))
  ;; sketch: the bytes and nothing else, so the capacity is implied by length.
  (let ((bytes (make-array 12 :element-type '(unsigned-byte 8) :initial-element 7)))
    (is (equalp bytes (bitcoin-lisp.serialization:parse-sketch-payload
                       (subseq (bitcoin-lisp.serialization:make-sketch-message bytes) 24)))))
  ;; reqsketchext carries nothing.
  (is (= 24 (length (bitcoin-lisp.serialization:make-reqsketchext-message))))
  ;; reconcildiff, both ways.
  (multiple-value-bind (ok ids)
      (bitcoin-lisp.serialization:parse-reconcildiff-payload
       (subseq (bitcoin-lisp.serialization:make-reconcildiff-message
                t '(#xDEADBEEF 1 #xFFFFFFFF)) 24))
    (is-true ok)
    (is (equal '(#xDEADBEEF 1 #xFFFFFFFF) ids)))
  (multiple-value-bind (ok ids)
      (bitcoin-lisp.serialization:parse-reconcildiff-payload
       (subseq (bitcoin-lisp.serialization:make-reconcildiff-message nil '()) 24))
    (is-false ok)
    (is (null ids) "a failed round asks for nothing and both sides flood")))

(test a-round-splits-the-difference-into-mine-and-yours
  "A symmetric difference says an element is on exactly ONE side, not which.
So after decoding, the initiator has to sort the recovered IDs into the ones it
already holds — which it must ANNOUNCE — and the ones it does not, which it
must ASK for. Getting that backwards would have each side request what it
already has and announce nothing."
  (let* ((k0 5) (k1 6)
         (mine (bitcoin-lisp.networking::make-recon-set))
         (theirs (bitcoin-lisp.networking::make-recon-set))
         (shared (loop for i from 0 below 4 collect (%rc-wtxid i)))
         (only-mine (loop for i from 30 below 33 collect (%rc-wtxid i)))
         (only-theirs (loop for i from 60 below 62 collect (%rc-wtxid i))))
    (dolist (w (append shared only-mine))
      (bitcoin-lisp.networking::recon-set-add mine k0 k1 w))
    (dolist (w (append shared only-theirs))
      (bitcoin-lisp.networking::recon-set-add theirs k0 k1 w))
    (let* ((capacity (bitcoin-lisp.networking::recon-estimate-capacity
                      (bitcoin-lisp.networking::recon-set-size mine)
                      (bitcoin-lisp.networking::recon-set-size theirs)
                      0.5d0))
           (round (bitcoin-lisp.networking::make-recon-round
                   :local-ids (bitcoin-lisp.networking::recon-set-short-ids mine)))
           (their-sketch (bitcoin-lisp.networking::recon-build-sketch
                          (bitcoin-lisp.networking::recon-set-short-ids theirs)
                          capacity)))
      (multiple-value-bind (ids ok)
          (bitcoin-lisp.networking::recon-round-decode round their-sketch)
        (is-true ok)
        (let ((ask (bitcoin-lisp.networking::recon-round-missing-ids round ids))
              (tell (bitcoin-lisp.networking::recon-round-ours-to-announce round ids)))
          (is (= (length only-theirs) (length ask))
              "ask for exactly what only they have")
          (is (= (length only-mine) (length tell))
              "announce exactly what only we have")
          ;; And the two halves partition the difference, with no overlap.
          (is (null (intersection ask tell)))
          (is (= (length ids) (+ (length ask) (length tell))))
          ;; Every id we ask for resolves in THEIR set, and none in ours.
          (dolist (id ask)
            (is-true (bitcoin-lisp.networking::recon-set-wtxid theirs id))
            (is-false (bitcoin-lisp.networking::recon-set-wtxid mine id))))))))

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
         (round (bitcoin-lisp.networking::make-recon-round :local-ids truth))
         ;; A capacity far below the real difference.
         (their-sketch (bitcoin-lisp.networking::recon-build-sketch
                        '(#xAAAAAAAA #xBBBBBBBB) 2)))
    (multiple-value-bind (ids ok)
        (bitcoin-lisp.networking::recon-round-decode round their-sketch)
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
           (round2 (bitcoin-lisp.networking::make-recon-round :local-ids truth))
           (sketch (bitcoin-lisp.networking::recon-build-sketch theirs capacity)))
      (multiple-value-bind (ids ok)
          (bitcoin-lisp.networking::recon-round-decode round2 sketch)
        (is-true ok)
        (is (= (+ (length truth) (length theirs)) (length ids)))
        (is (equal (sort (copy-list theirs) #'<)
                   (sort (bitcoin-lisp.networking::recon-round-missing-ids round2 ids) #'<)))))))
