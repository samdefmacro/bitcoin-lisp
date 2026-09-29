(in-package #:bitcoin-lisp.tests)

(def-suite :txreconciliation-set-tests
  :description "BIP-330 reconciliation sets, short IDs and fanout (Erlay P2)"
  :in :bitcoin-lisp-tests)

(in-suite :txreconciliation-set-tests)

;;;; ⚠️ Everything under test here is BEYOND Bitcoin Core, which ships the
;;;; sendtxrcncl handshake and nothing else. What has an executable oracle is
;;;; checked against it: the short IDs and salts against vectors from Core's
;;;; own SipHash and the BIP's formula, the sketches against Core's vendored
;;;; minisketch (minisketch-tests.lisp), the wire formats against BIP-330's
;;;; tables. The round logic has no reference implementation, so those tests
;;;; assert the PROPERTIES BIP-330 relies on, and the loopback test at the end
;;;; runs a round between two real nodes.

(defun %rc-wtxid (n)
  "The Nth distinct test wtxid. Below 256 every byte is N, as it always was;
above, the second byte carries the high bits, so a test that needs thousands
of distinct transactions can have them."
  (let ((w (make-array 32 :element-type '(unsigned-byte 8)
                          :initial-element (ldb (byte 8 0) n))))
    (when (> n 255)
      ;; Byte 2 marks the wide form: without it, 257 (bytes 01 01 01 ...) IS
      ;; wtxid 1, and every multiple of 257 collides the same way.
      (setf (aref w 1) (ldb (byte 8 8) n)
            (aref w 2) 0))
    w))

(defun %rc-reconcildiff (sent)
  "The (success ask) of the one reconcildiff in SENT, or NIL when SENT is not
exactly one reconcildiff message."
  (when (and (= 1 (length sent))
             (string= "reconcildiff" (message-command (first sent))))
    (multiple-value-list
     (bl.ser:parse-reconcildiff-payload (subseq (first sent) 24)))))

(defun %rc-sketch-payload (short-ids capacity)
  "A sketch message payload, header stripped, as the handler sees it: what a
peer holding SHORT-IDS would answer a reqrecon with at CAPACITY."
  (let ((sk (bl.net:ms-make-sketch capacity)))
    (dolist (id short-ids) (bl.net:ms-sketch-add sk id))
    (subseq (bl.ser:make-sketch-message (bl.net:ms-sketch-serialize sk)) 24)))

(defun %rc-extension-payload (short-ids capacity)
  "BIP-330's sketch extension for a round first sketched at CAPACITY, header
stripped: syndromes CAPACITY..2*CAPACITY-1 of the double-capacity sketch."
  (let ((sk (bl.net:ms-make-sketch (* 2 capacity))))
    (dolist (id short-ids) (bl.net:ms-sketch-add sk id))
    (subseq (bl.ser:make-sketch-message
             (bl.net:ms-sketch-serialize (subseq sk capacity)))
            24)))

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
      (bl.net:recon-set-add set k0 k1 w))))

(defun %rc-short-ids (wtxids &key (k0 11) (k1 22))
  "The short IDs of WTXIDS under the salt %RC-PEER gives a registered peer."
  (mapcar (lambda (w) (bl.net:recon-short-id k0 k1 w)) wtxids))

(defun %rc-mempool-wtxids (n &key (seed 1))
  "A mempool holding N real transactions -- P2SH(OP_TRUE) spends of distinct
synthetic fundings numbered from SEED -- and their wtxids, in order. The
announcement path reads each txid and fee rate from the mempool, so a test
that asserts on what a round ANNOUNCES holds these, not bare wtxids."
  (let ((mempool (bl.mp:make-mempool)))
    (values mempool
            (loop for i from seed below (+ seed n)
                  collect (let ((funding (make-array 32 :element-type '(unsigned-byte 8)
                                                        :initial-element 0)))
                            (setf (aref funding 0) (ldb (byte 8 0) i)
                                  (aref funding 1) (ldb (byte 8 8) i)
                                  (aref funding 2) 1)
                            (let ((tx (pkg-tx funding 0 (- 100000000 10000))))
                              (bl.mp:mempool-add mempool (bl.ser:transaction-hash tx)
                                                 (bl.mp:make-entry-from-tx tx 10000 1))
                              (bl.ser:transaction-wtxid tx)))))))

(defun %rc-round-open-p (peer)
  "Whether PEER has a reconciliation round in flight -- the initiator's state,
which a closed round leaves empty."
  (and (bl.net::peer-recon-round peer) t))

(test short-ids-are-per-peer-and-never-zero
  "Salted per peer so an observer on one link cannot tell which transactions a
node holds on another, and cannot grind IDs that collide for everybody. Zero is
remapped because 0 has no sketch — its powers are all zero, so it would be
INVISIBLE rather than merely unlucky."
  (let ((wtxid (%rc-wtxid 7)))
    (let ((a (bl.net:recon-short-id 1 2 wtxid))
          (b (bl.net:recon-short-id 3 4 wtxid)))
      (is (/= a b) "the same transaction must look different on different links")
      (is (<= 1 a #xFFFFFFFF))
      (is (<= 1 b #xFFFFFFFF))))
  ;; Same salt, same answer.
  (is (= (bl.net:recon-short-id 9 9 (%rc-wtxid 1))
         (bl.net:recon-short-id 9 9 (%rc-wtxid 1))))
  ;; Across many transactions, none is ever zero.
  (is (loop for n from 0 below 200
            always (plusp (bl.net:recon-short-id 5 6 (%rc-wtxid n))))))

(test short-ids-match-bip330-and-cores-siphash
  "BIP-330's short ID, `1 + (s mod 0xFFFFFFFF)' with s = SipHash-2-4((k0,k1),
wtxid), and its salt, TaggedHash(\"Tx Relay Salting\", min salt || max salt)
read as k0/k1 -- Core's ComputeSalt (txreconciliation.cpp:18-30) -- against
tests/data/minisketch_core_vectors.json, computed with Core's functional-test
SipHash (test_framework/crypto/siphash.py). Salts include 0 and 2^64-1, the
ends of the ascending sort. The ID this used to compute, s mod 2^32 with 0
remapped to 1, differs on almost every one of them."
  (dolist (v (gethash "short_id" (yason:parse (project-source-text
                                                "tests/data/minisketch_core_vectors.json"))))
    (multiple-value-bind (k0 k1)
        (bl.net:compute-recon-salt (gethash "salt1" v) (gethash "salt2" v))
      (is (= (gethash "k0" v) k0))
      (is (= (gethash "k1" v) k1)))
    (let ((wtxid (bl.crypto:hex-to-bytes (gethash "wtxid_internal_hex" v))))
      (is (= (gethash "siphash" v)
             (bl.crypto:siphash-2-4 (gethash "k0" v) (gethash "k1" v) wtxid)))
      (is (= (gethash "short_id" v)
             (bl.net:recon-short-id (gethash "k0" v) (gethash "k1" v) wtxid))
          "short id of ~A" (gethash "wtxid_internal_hex" v)))))

(test a-reconciliation-set-is-keyed-by-short-id
  "Keyed by short ID because that is what the sketch holds and what a decode
returns; the wtxid rides along so the node can announce the real transaction
once the difference is known."
  (let ((set (bl.net:make-recon-set))
        (wtxid (%rc-wtxid 11)))
    (is (= 0 (%rc-count set)))
    (let ((id (bl.net:recon-set-add set 1 2 wtxid)))
      (is-true id)
      (is (= 1 (%rc-count set)))
      (is (equalp wtxid (bl.net::recon-set-wtxid set id)))
      ;; Adding the same transaction again is a no-op, not a duplicate -- and
      ;; not a refusal either: NIL is reserved for a FULL set, which the relay
      ;; path answers by announcing the transaction instead.
      (is (= id (bl.net:recon-set-add set 1 2 wtxid)))
      (is (= 1 (%rc-count set)))
      ;; Removal is by wtxid, resolved through the same salt.
      (bl.net::recon-set-remove set 1 2 wtxid)
      (is (= 0 (%rc-count set))))))

(test a-round-reconciles-a-frozen-snapshot
  "BIP-330: `A reconciliation set is moved to the corresponding set snapshot
after the transmission of the initial sketch' and the node should `clear the
set'. So a round works on the snapshot, the set starts empty, and a
transaction arriving mid-round goes to the NEXT round -- where this used to
leave it in the one table the round also read from."
  (let ((set (bl.net:make-recon-set)))
    (dotimes (i 3) (bl.net:recon-set-add set 1 2 (%rc-wtxid i)))
    (let ((snap (bl.net:recon-set-take-snapshot set)))
      (is (= 3 (length snap)))
      (is (null (bl.net::recon-set-short-ids set)) "the set was moved, and is empty")
      ;; More arrive mid-round; they go to the set, not the snapshot.
      (dotimes (i 3) (bl.net:recon-set-add set 1 2 (%rc-wtxid (+ 100 i))))
      (is (= 6 (%rc-count set)) "both are held")
      (is (= 3 (length (bl.net:recon-set-snapshot-ids set))))
      (is (= 3 (length (bl.net::recon-set-short-ids set))))
      (bl.net::recon-set-clear-snapshot set)
      (is (null (bl.net:recon-set-snapshot-ids set)))
      (is (= 3 (%rc-count set)) "and the latecomers wait for the next round"))))

(test two-sets-reconcile-to-their-difference
  "The whole point, end to end over the sketch layer: each side sketches its
own short IDs, the sketches are merged, and what decodes out is exactly what
one side has and the other does not."
  (let* ((mine (bl.net:make-recon-set))
         (theirs (bl.net:make-recon-set))
         (k0 77) (k1 88)
         (shared (loop for i from 0 below 5 collect (%rc-wtxid i)))
         (only-mine (loop for i from 20 below 23 collect (%rc-wtxid i)))
         (only-theirs (loop for i from 40 below 42 collect (%rc-wtxid i))))
    (dolist (w (append shared only-mine))
      (bl.net:recon-set-add mine k0 k1 w))
    (dolist (w (append shared only-theirs))
      (bl.net:recon-set-add theirs k0 k1 w))
    (let* ((capacity (bl.net::recon-estimate-capacity
                      (%rc-count mine)
                      (%rc-count theirs)
                      0.5d0))
           (a (bl.net::recon-build-sketch
               (bl.net::recon-set-short-ids mine) capacity))
           (b (bl.net::recon-build-sketch
               (bl.net::recon-set-short-ids theirs) capacity))
           (decoded (bl.net:ms-decode
                     (bl.net:ms-sketch-merge a b))))
      (is-true decoded "the difference must decode at the estimated capacity")
      (let ((want (sort (append (mapcar (lambda (w)
                                          (bl.net:recon-short-id k0 k1 w))
                                        only-mine)
                                (mapcar (lambda (w)
                                          (bl.net:recon-short-id k0 k1 w))
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
  (is (= 1 (bl.net:recon-estimate-capacity 0 0 0.5d0)))
  (is (= 6 (bl.net:recon-estimate-capacity 10 5 0.0d0)))
  ;; q pays for the shared-but-unknown part of the smaller set.
  (is (= 11 (bl.net:recon-estimate-capacity 10 5 1.0d0)))
  (is (= 3 (bl.net:recon-estimate-capacity 4 4 0.5d0))))

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
  "The four messages a round is made of, in BIP-330's formats -- Core d3056bc
has none of them, so the BIP's tables are the oracle. reqrecon is `uint16
set_size' and `uint16 q', q `Multiplied by PRECISION=(2^15) - 1': four bytes,
where this used to send a uint32 set_size and scale q by 2^15."
  ;; reqrecon, byte for byte: 1234 = d2 04, floor(0.25 * 32767) = 8191 = ff 1f.
  (let ((payload (subseq (bl.ser:make-reqrecon-message 1234 0.25d0) 24)))
    (is (string= "d204ff1f" (string-downcase (bl.crypto:bytes-to-hex payload))))
    (multiple-value-bind (size q) (bl.ser:parse-reqrecon-payload payload)
      (is (= 1234 size))
      (is (= 8191/32767 q))))
  ;; A q of zero, and q = 1 at exactly PRECISION.
  (multiple-value-bind (size q)
      (bl.ser:parse-reqrecon-payload
       (subseq (bl.ser:make-reqrecon-message 0 0d0) 24))
    (is (= 0 size))
    (is (= 0 q)))
  (multiple-value-bind (size q)
      (bl.ser:parse-reqrecon-payload
       (subseq (bl.ser:make-reqrecon-message 7 1) 24))
    (is (= 7 size))
    (is (= 1 q)))
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
         (mine (bl.net:make-recon-set))
         (theirs (bl.net:make-recon-set))
         (shared (loop for i from 0 below 4 collect (%rc-wtxid i)))
         (only-mine (loop for i from 30 below 33 collect (%rc-wtxid i)))
         (only-theirs (loop for i from 60 below 62 collect (%rc-wtxid i))))
    (dolist (w (append shared only-mine))
      (bl.net:recon-set-add mine k0 k1 w))
    (dolist (w (append shared only-theirs))
      (bl.net:recon-set-add theirs k0 k1 w))
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
          (bl.net:recon-round-decode round their-sketch)
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
        (bl.net:recon-round-decode round their-sketch)
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
          (bl.net:recon-round-decode round2 sketch)
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
      ;; A reconciling peer negotiated wtxid relay: reconciliation needs it
      ;; (BIP-330, and the verack check that forgets the state without it),
      ;; and the set is keyed by the same wtxid its inventory uses.
      (setf (bl.net:peer-wtxid-relay p) t
            (bl.net::peer-recon-k0 p) k0
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
                                                  :wtxid wtxid :fee-rate-per-kvb 1)
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
           wtxid nil peers :wtxid wtxid :fee-rate-per-kvb 1)
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
          wtxid nil (list peer) :wtxid wtxid :fee-rate-per-kvb 1)))
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
                                                  :wtxid nil :fee-rate-per-kvb 1)
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
    (is-true (bl.net:recon-should-start-round-p out now))
    (is-false (bl.net:recon-should-start-round-p in now))))

(test rounds-are-spaced-and-not-doubled-up
  "One round per peer at a time, and not more often than the interval — a node
that reconciled continuously would announce in a pattern that reveals how many
peers it has."
  (let ((peer (%rc-peer :registered t))
        (now 100000))
    (%rc-hold peer (list (%rc-wtxid 4)))
    (is-true (bl.net:recon-should-start-round-p peer now))
    (is-true (bl.net::recon-start-round peer now))
    ;; A round is in flight: not again.
    (is-false (bl.net:recon-should-start-round-p peer (+ now 100)))
    ;; Even once it clears, the interval still applies.
    (setf (bl.net::peer-recon-round peer) nil)
    (is-false (bl.net:recon-should-start-round-p peer now))
    (is-true (bl.net::recon-should-start-round-p
              peer (+ now bl.net::+recon-round-interval-seconds+)))))

(test an-empty-set-still-opens-a-round
  "Only the initiator opens rounds, so the RESPONDER's set drains through them
and no other way. An initiator with nothing of its own still sends reqrecon
(set_size 0), or a listening node's held transactions would wait for the
dialler to happen to have something -- which is what skipping the empty round
did. Then the responder's side of it: an empty set is answered too."
  (let* ((peer (%rc-peer :registered t))
         (msg (bl.net::recon-start-round peer 100000)))
    (is (string= "reqrecon" (message-command msg)))
    (is (= 0 (bl.ser:parse-reqrecon-payload (subseq msg 24))))
    (is-true (%rc-round-open-p peer)))
  (let ((responder (%rc-peer :registered t)))
    (is (string= "sketch" (message-command
                           (bl.net::recon-respond-to-request responder 3 1/4))))))

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
      (is-false (%rc-round-open-p peer)))))

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
        (bl.net::recon-finish-round peer (%rc-short-ids ours-only))
      (is (null ask) "nothing to request: the peer was missing nothing")
      (is (= 3 (length announce))))
    (is (= 0 (%rc-count set))
        "the 20 that cancelled must leave the set too, or it never shrinks")))

(test a-reconcildiff-retires-the-responders-whole-snapshot
  "The responder half of the same rule. It moved its set into a snapshot to
answer reqrecon; a SUCCESS reconcildiff asks for the ids it was missing, and
the rest of that snapshot is settled because cancelling in the sketch is
exactly what both sides holding it looks like."
  (multiple-value-bind (mempool wtxids) (%rc-mempool-wtxids 8 :seed 70)
    (let* ((peer (%rc-peer :registered t))
           (set (%rc-hold peer wtxids))
           (asked (first (%rc-short-ids wtxids))))
      ;; RECON-RESPOND-TO-REQUEST moves the set like this before it sketches.
      (bl.net:recon-set-take-snapshot set)
      (bl.net::%handle-reconcildiff
       peer (subseq (bl.ser:make-reconcildiff-message t (list asked)) 24) mempool)
      (is (= 1 (length (bl.net:peer-tx-inv-queue peer)))
          "only the asked-for transaction is announced")
      (is (= 0 (%rc-count set))
          "and the seven that cancelled leave with it"))))

;;; --- Bounds, settlement and the failure paths (GA11 left-outs) -----------------
;;;
;;; Still BIP-330 territory: Core d3056bc ships the sendtxrcncl handshake and no
;;; reconciliation set, so the BIP is the oracle for everything below and the
;;; Core lines cited are the known-filter sites the set behaviour hangs off.

(test a-full-reconciliation-set-falls-back-to-flooding
  "A set has to be bounded: BIP-330 sends set_size as a uint16 in reqrecon, and
every entry costs sketch capacity on every round until it settles. The bound is
3000 -- the MAX_SET_SIZE of the Core Erlay work that d3056bc does not yet carry
-- and a transaction that finds the set full is ANNOUNCED, not dropped: the
fallback everywhere in Erlay is flooding. Pinned as a literal here, as the q
scale is, so a change to the constant has to change the test too.

The fanout draw is deterministic in (wtxid, peer salt), so a TWIN peer with the
same salt and an empty set is the oracle for which transactions the draw would
hold: one the twin holds, the full peer must announce instead."
  (%with-relay-network
    (let* ((cap 3000)
           (full (%rc-peer :registered t))
           (twin (%rc-peer :registered t))
           (others (loop repeat 7 collect (%rc-peer :registered t)))
           (set (%rc-hold full (loop for i from 0 below (1- cap)
                                     collect (%rc-wtxid i))))
           ;; The first two candidates past the fill that the draw HOLDS.
           (held-by-draw
             (loop for i from cap
                   for w = (%rc-wtxid i)
                   do (setf (bl.net:peer-tx-inv-queue twin) '())
                      (bl.net:relay-transaction w nil (cons twin others)
                                                :wtxid w :fee-rate-per-kvb 1)
                   when (null (bl.net:peer-tx-inv-queue twin))
                     collect w into held
                   when (= 2 (length held))
                     return held)))
      (is (= (1- cap) (%rc-count set)))
      ;; Positive control: one slot left, so a held candidate is held.
      (bl.net:relay-transaction (first held-by-draw) nil (cons full others)
                                :wtxid (first held-by-draw) :fee-rate-per-kvb 1)
      (is (null (bl.net:peer-tx-inv-queue full))
          "below the cap the transaction is reconciled, not announced")
      (is (= cap (%rc-count set)))
      ;; The set is full: the next one the draw would hold is announced.
      (bl.net:relay-transaction (second held-by-draw) nil (cons full others)
                                :wtxid (second held-by-draw) :fee-rate-per-kvb 1)
      (is (= 1 (length (bl.net:peer-tx-inv-queue full)))
          "a full set falls back to an ordinary announcement")
      (is (equalp (second held-by-draw)
                  (first (first (bl.net:peer-tx-inv-queue full)))))
      (is (= cap (%rc-count set)) "and the set does not grow past the cap"))))

(test a-transaction-we-announce-leaves-the-peers-reconciliation-set
  "Once the peer has been told about a transaction by inv there is nothing left
to reconcile: BIP-330 keeps in the set what 'would have been announced using
INV messages absent this protocol', and this one WAS announced. Left in, it
would cost sketch capacity every round until a round happened to settle it. The
site is the known-filter insert of Core's inv flush (net_processing.cpp:
6060-6083): a transaction the peer knows is one it has nothing to learn about."
  (%with-relay-network
    (let* ((peer (%rc-peer :registered t))
           (kept (%rc-wtxid 90))
           (told (%rc-wtxid 91))
           (set (%rc-hold peer (list kept told))))
      (push (list told told 0) (bl.net:peer-tx-inv-queue peer))
      (flush-peer-invs peer)
      (is-true (bl:recent-reject-p (bl.net:peer-announced-txs peer) told)
               "positive control: the flush did announce it")
      (is (= 1 (%rc-count set)) "the announced transaction left the set")
      ;; The other one is what stayed: announcing it empties the set.
      (push (list kept kept 0) (bl.net:peer-tx-inv-queue peer))
      (flush-peer-invs peer)
      (is (= 0 (%rc-count set))))))

(test a-transaction-the-peer-announces-to-us-leaves-its-set
  "The peer just told us it has this transaction, so a sketch can teach it
nothing about it. Core marks it known to the peer (AddKnownTx,
net_processing.cpp:4174); with a reconciliation set the same fact takes it out
of the set."
  (%with-relay-network
    (let* ((peer (%rc-peer :registered t))
           (w (%rc-wtxid 92))
           (set (%rc-hold peer (list w (%rc-wtxid 93)))))
      (deliver-inv peer (tx-inv-payload bl.ser:+inv-type-wtx+ w)
                   (bl.ctx:make-node-context))
      (is-true (bl:recent-reject-p (bl.net:peer-announced-txs peer) w)
               "positive control: the inv was taken in as known")
      (is (= 1 (%rc-count set)) "and only the announced one left the set"))))

(test a-failed-round-makes-the-responder-flood-its-snapshot
  "The responder's failure path. It answered reqrecon with a sketch over a
frozen snapshot; when the initiator gives up, BIP-330 says 'If success=0
(reconciliation failure), receiver should announce all transactions from the
reconciliation set via an inv message', and the snapshot 'is cleared by the
sender and the receiver of the message'. The responder never has a ROUND --
only the initiator opens one -- and the old path reached for that round, found
none, and announced nothing: every transaction the initiator could not decode
stayed unannounced until some later round happened to settle it."
  (let* ((peer (%rc-peer :registered t :we-initiate nil :inbound t))
         (held (multiple-value-list (%rc-mempool-wtxids 5 :seed 70)))
         (set (%rc-hold peer (second held)))
         (ctx (bl.ctx:make-node-context :mempool (first held))))
    ;; reqrecon freezes the snapshot and is answered with a sketch.
    (let ((sent (captured-sends
                 (lambda ()
                   (bl.net:handle-message
                    peer "reqrecon"
                    (subseq (bl.ser:make-reqrecon-message 5 0.25d0) 24) ctx)))))
      (is (equal '("sketch") (mapcar #'message-command sent))))
    ;; A transaction arriving mid-round is not part of this round.
    (%rc-hold peer (list (%rc-wtxid 75)))
    (bl.net:handle-message peer "reconcildiff"
                           (subseq (bl.ser:make-reconcildiff-message nil '()) 24)
                           ctx)
    (is (= 5 (length (bl.net:peer-tx-inv-queue peer)))
        "everything the sketch described is announced the ordinary way")
    (is (= 1 (%rc-count set))
        "the one that arrived after the snapshot waits for the next round")
    ;; The snapshot is cleared with it: a second failure notice, with no
    ;; reqrecon in between, has nothing left to flood.
    (bl.net:handle-message peer "reconcildiff"
                           (subseq (bl.ser:make-reconcildiff-message nil '()) 24)
                           ctx)
    (is (= 5 (length (bl.net:peer-tx-inv-queue peer)))
        "and the snapshot is cleared: nothing is announced twice")
    (is (= 1 (%rc-count set)))))

(test a-failed-extension-makes-the-initiator-report-and-flood
  "The initiator's failure path, end to end through the handlers. BIP-330: when
the extension does not decode either, the initiator 'terminates the
reconciliation right away by sending a reconcildiff message with the failure
flag set', and that message 'should also be accompanied with announcing all
transactions from the ... set snapshot'. Then the positive control: a round
that DECODES closes the same round, announcing only the difference."
  (let* ((peer (%rc-peer :registered t :we-initiate t))
         (held (multiple-value-list (%rc-mempool-wtxids 5 :seed 40)))
         (wtxids (second held))
         (ids (%rc-short-ids wtxids))
         (set (%rc-hold peer wtxids))
         (ctx (bl.ctx:make-node-context :mempool (first held)))
         ;; Ten ids we do not hold at capacity 5, against our five: fifteen
         ;; differences. An over-full sketch CAN decode (to a wrong set; Core
         ;; decodes about half of the random capacity-2 sketches), so the
         ;; difference is three times the capacity and the extension still
         ;; short of it; the decode is a pure function of these fixed inputs.
         (theirs (%rc-short-ids (loop for i from 300 below 310 collect (%rc-wtxid i))
                                :k0 1 :k1 2))
         (undecodable (%rc-sketch-payload theirs 5)))
    (let ((sent (captured-sends
                 (lambda () (bl.net:maybe-start-reconciliation peer 100000)))))
      (is (equal '("reqrecon") (mapcar #'message-command sent))))
    ;; The first sketch does not decode: one extension is asked for.
    (let ((sent (captured-sends
                 (lambda () (bl.net:handle-message peer "sketch" undecodable ctx)))))
      (is (equal '("reqsketchext") (mapcar #'message-command sent))))
    (is (null (bl.net:peer-tx-inv-queue peer))
        "nothing is flooded while the extension is pending")
    ;; The extension -- the same ten ids, syndromes 6-10 of a capacity-10
    ;; sketch -- does not decode either: report the failure and flood.
    (let* ((sent (captured-sends
                  (lambda ()
                    (bl.net:handle-message
                     peer "sketch" (%rc-extension-payload theirs 5) ctx))))
           (diff (%rc-reconcildiff sent)))
      (is-true diff "exactly one reconcildiff is sent")
      (when diff
        (is-false (first diff) "with success=0")
        (is (null (second diff)) "asking for nothing")))
    (is (= 5 (length (bl.net:peer-tx-inv-queue peer)))
        "the whole snapshot is announced the ordinary way")
    (is (= 0 (%rc-count set)))
    (is-false (%rc-round-open-p peer) "and the round is closed")
    ;; Positive control: the next round decodes -- the peer holds our five and
    ;; one more -- so it asks for that one, announces nothing, and closes.
    (setf (bl.net:peer-tx-inv-queue peer) '())
    (%rc-hold peer wtxids)
    (bl.net:maybe-start-reconciliation peer 200000)
    (let* ((sent (captured-sends
                  (lambda ()
                    (bl.net:handle-message
                     peer "sketch" (%rc-sketch-payload (cons #xAAAAAAAA ids) 3) ctx))))
           (diff (%rc-reconcildiff sent)))
      (is-true diff "exactly one reconcildiff is sent")
      (when diff
        (is-true (first diff) "with success=1")
        (is (equal (list #xAAAAAAAA) (second diff)) "asking for the one we lack")))
    (is (null (bl.net:peer-tx-inv-queue peer))
        "the peer was missing nothing of ours")
    (is (= 0 (%rc-count set)))
    (is-false (%rc-round-open-p peer))))

(test a-malformed-sketch-ends-the-round-for-both-sides
  "A sketch that cannot even be read ends the round the way a failed decode
does: the initiator floods its snapshot AND tells the responder so, because
the responder keeps its snapshot 'until a reconcildiff message is received'
(BIP-330) and would otherwise hold it until the next reqrecon replaced it."
  (let* ((peer (%rc-peer :registered t :we-initiate t))
         (held (multiple-value-list (%rc-mempool-wtxids 3 :seed 50)))
         (set (%rc-hold peer (second held)))
         (ctx (bl.ctx:make-node-context :mempool (first held))))
    (bl.net:maybe-start-reconciliation peer 100000)
    (let ((sent (captured-sends
                 (lambda ()
                   ;; Five bytes: not a whole number of 32-bit field elements.
                   (bl.net:handle-message
                    peer "sketch"
                    (subseq (bl.ser:make-sketch-message
                             (make-array 5 :element-type '(unsigned-byte 8)
                                           :initial-element 1))
                            24)
                    ctx)))))
      (is (equal '(nil nil) (%rc-reconcildiff sent))
          "one reconcildiff, success=0, asking for nothing"))
    (is (= 3 (length (bl.net:peer-tx-inv-queue peer))))
    (is (= 0 (%rc-count set)))
    (is-false (%rc-round-open-p peer))))

(test identical-sets-reconcile-to-nothing-and-succeed
  "Two peers holding the same transactions is the steady state Erlay exists
for: 'directly connected pairs of nodes are aware they have nothing to learn
from each other' (BIP-330). Their sketches cancel to zero, which DECODES -- to
the empty difference. Treating an empty decode as a failed one sent every such
round through an extension and then flooded the whole set, so the peers that
agreed most completely paid the most bandwidth."
  (let* ((peer (%rc-peer :registered t :we-initiate t))
         (wtxids (loop for i from 40 below 45 collect (%rc-wtxid i)))
         (ids (%rc-short-ids wtxids))
         (set (%rc-hold peer wtxids))
         (ctx (bl.ctx:make-node-context)))
    (bl.net:maybe-start-reconciliation peer 100000)
    (let* ((sent (captured-sends
                  (lambda ()
                    (bl.net:handle-message
                     peer "sketch" (%rc-sketch-payload ids 3) ctx))))
           (diff (%rc-reconcildiff sent)))
      (is-true diff "no extension: the round is decided by the first sketch")
      (when diff
        (is-true (first diff) "and decided as a success")
        (is (null (second diff)) "with nothing to ask for")))
    (is (null (bl.net:peer-tx-inv-queue peer)) "nothing to announce")
    (is (= 0 (%rc-count set)) "and the whole snapshot is settled")
    (is-false (%rc-round-open-p peer))))

;;; --- BIP-330's extension, the roles, and the capacity ceiling --------------

(defun %rc-reqrecon (peer set-size q ctx)
  "Deliver a reqrecon to PEER and return the messages it sent back."
  (captured-sends
   (lambda ()
     (bl.net:handle-message peer "reqrecon"
                            (subseq (bl.ser:make-reqrecon-message set-size q) 24)
                            ctx))))

(test the-responder-extends-its-sketch-without-resending-it
  "BIP-330: `Upon receipt of a \"reqsketchext\" message, a node responds to it
with a \"sketch\" message, which contains a sketch extension: a sketch (of the
same transactions sketched initially) of higher capacity without the part sent
initially.' The first sketch's syndromes are the first half of the
double-capacity sketch, so the extension is its second half -- this used to
resend a whole sketch at twice the SNAPSHOT SIZE, which a BIP peer appends to
what it holds and decodes as garbage. An empty snapshot is extended too (all
zeros), or the initiator waits for ever; with no sketch sent, nothing is."
  (let* ((peer (%rc-peer :registered t :we-initiate nil :inbound t))
         (wtxids (loop for i from 80 below 86 collect (%rc-wtxid i)))
         (ids (progn (%rc-hold peer wtxids) (%rc-short-ids wtxids)))
         (ctx (bl.ctx:make-node-context)))
    (is (null (captured-sends
               (lambda () (bl.net:handle-message peer "reqsketchext" #() ctx))))
        "no sketch sent this round, so nothing to extend")
    ;; |6 - 2| + floor(0 * 2) + 1 = 5.
    (let ((first (first (%rc-reqrecon peer 2 0 ctx))))
      (is (equalp (%rc-sketch-payload ids 5) (subseq first 24))))
    (let ((ext (captured-sends
                (lambda () (bl.net:handle-message peer "reqsketchext" #() ctx)))))
      (is (equal '("sketch") (mapcar #'message-command ext)))
      (is (equalp (%rc-extension-payload ids 5) (subseq (first ext) 24))
          "syndromes 6-10 of the capacity-10 sketch, and nothing else")))
  (let ((peer (%rc-peer :registered t :we-initiate nil :inbound t))
        (ctx (bl.ctx:make-node-context)))
    (%rc-reqrecon peer 3 0 ctx)
    (let ((ext (first (captured-sends
                       (lambda () (bl.net:handle-message peer "reqsketchext" #() ctx))))))
      (is-true ext "an empty snapshot's extension is still sent")
      (is (equalp (%rc-extension-payload '() 4) (subseq ext 24))))))

(test the-initiator-appends-the-extension-and-decodes
  "The initiator's half of the extension: the second sketch is appended to the
first and the whole decoded at twice the capacity. A ten-element difference
does not decode at capacity 5 and does at 10; an extension of the wrong length,
or a first sketch past +RECON-MAX-SKETCH-CAPACITY+, is a failed decode."
  (let* ((peer (%rc-peer :registered t :we-initiate t))
         (wtxids (loop for i from 90 below 94 collect (%rc-wtxid i)))
         (ids (progn (%rc-hold peer wtxids) (%rc-short-ids wtxids)))
         (extra (sort (%rc-short-ids (loop for i from 200 below 210 collect (%rc-wtxid i))
                              :k0 1 :k1 2)
                     #'<))
         (theirs (append ids extra))
         (ctx (bl.ctx:make-node-context)))
    (bl.net:maybe-start-reconciliation peer 100000)
    (is (equal '("reqsketchext")
               (mapcar #'message-command
                       (captured-sends
                        (lambda ()
                          (bl.net:handle-message
                           peer "sketch" (%rc-sketch-payload theirs 5) ctx))))))
    (let ((diff (%rc-reconcildiff
                 (captured-sends
                  (lambda ()
                    (bl.net:handle-message
                     peer "sketch" (%rc-extension-payload theirs 5) ctx))))))
      (is-true (first diff) "the extended sketch decodes")
      (is (equal extra (sort (copy-list (second diff)) #'<))
          "and asks for exactly the ten we lack")))
  (let ((round (bl.net::make-recon-round :local-ids '(1 2))))
    (is-false (nth-value 1 (bl.net:recon-round-decode
                            round (bl.net:ms-make-sketch
                                   (1+ bl.net::+recon-max-sketch-capacity+))))
              "a first sketch past the ceiling is not decoded")
    (bl.net:recon-round-decode round (bl.net:ms-make-sketch 3))
    (setf (bl.net::recon-round-extended round) t)
    (is-false (nth-value 1 (bl.net:recon-round-decode round (bl.net:ms-make-sketch 4)))
              "an extension must be exactly as long as the first sketch")))

(test the-responder-caps-the-sketch-it-sizes
  "A reqrecon claiming 65535 transactions with q near 2 asked for a sketch of
over 100,000 syndromes over the whole set. The capacity is BIP-330's estimate
held to +RECON-MAX-SKETCH-CAPACITY+."
  (let ((peer (%rc-peer :registered t :we-initiate nil :inbound t)))
    (%rc-hold peer (list (%rc-wtxid 1)))
    (let ((sketch (first (%rc-reqrecon peer 65535 65535/32767 (bl.ctx:make-node-context)))))
      (is (= (* 4 bl.net::+recon-max-sketch-capacity+) (- (length sketch) 24))))))

(test reconciliation-messages-are-taken-only-from-the-right-role
  "BIP-330: `the initiator of the P2P connection assumes the role of
reconciliation initiator (will send \"reqrecon\" messages) and the other peer
assumes the role of reconciliation responder', and `\"reqrecon\" messages can
only be sent by the reconciliation initiator'. A reqrecon from the peer we
dialled -- we are its initiator -- is ignored, as is a sketch from the peer
that dialled us; the positive controls are the same messages from the right
side."
  (let ((ctx (bl.ctx:make-node-context)))
    (let ((we-initiate (%rc-peer :registered t :we-initiate t)))
      (%rc-hold we-initiate (list (%rc-wtxid 1)))
      (is (null (%rc-reqrecon we-initiate 1 0 ctx))))
    (let ((we-respond (%rc-peer :registered t :we-initiate nil :inbound t)))
      (%rc-hold we-respond (list (%rc-wtxid 1)))
      (is (equal '("sketch") (mapcar #'message-command (%rc-reqrecon we-respond 1 0 ctx))))
      ;; It cannot have a round of ours, and a sketch from it is not answered.
      (setf (bl.net::peer-recon-round we-respond)
            (bl.net::make-recon-round :local-ids '()))
      (is (null (captured-sends
                 (lambda ()
                   (bl.net:handle-message we-respond "sketch"
                                          (%rc-sketch-payload '(5) 2) ctx))))))
    (let ((unregistered (%rc-peer :registered nil :we-initiate nil :inbound t)))
      (is (null (%rc-reqrecon unregistered 1 0 ctx))
          "and nothing at all from a peer that never registered"))))

;;; --- Two of our nodes, one real connection, whole rounds ---------------------

(defun %rc-loopback-pair ()
  "Two of our peers over a real loopback TCP connection, handshaked by the
shipped outbound (PERFORM-HANDSHAKE) and inbound (PERFORM-INBOUND-HANDSHAKE)
paths with -txreconciliation on both, so sendtxrcncl, RegisterPeer and the
salt combination all run for real. Returns (values dialler listener-side
listener-socket): the dialler is the reconciliation initiator."
  (let* ((srv (bl.net:open-listener "127.0.0.1" 0))
         (port (usocket:get-local-port srv))
         (network bl:*network*)
         (inbound nil)
         (th (bt:make-thread
              (lambda ()
                ;; Specials are per thread: this one stands for the other node.
                (let ((bl:*tx-reconciliation* t) (bl:*network* network))
                  (ignore-errors
                   (let ((conn (bl.net:accept-connection srv :timeout 10)))
                     (when conn
                       (setf inbound (bl.net:make-inbound-peer conn "127.0.0.1"))
                       (bl.net:perform-inbound-handshake inbound :timeout 10))))))
              :name "recon-loopback-listener"))
         (outbound (bl.net:connect-peer "127.0.0.1" port)))
    (when outbound
      (with-private-outbound-nonces
        (bl.net:perform-handshake outbound :try-v2 nil)))
    (sb-thread:join-thread th :default nil :timeout 15)
    (values outbound inbound srv)))

(defun %rc-node-context (fundings peer)
  "One node: a chainstate, a coins view holding a 1 BTC P2SH(OP_TRUE) output
for each of FUNDINGS, an empty mempool, and PEER as its only connection."
  (let ((utxo (bl.store:make-utxo-set)))
    (dolist (f fundings)
      (bl.store:add-utxo utxo f 0 100000000 (p2sh-optrue-script-pubkey) 1 :coinbase nil))
    (bl.ctx:make-node-context :chain-state (bl.store:make-chain-state :best-height 200)
                              :utxo-set utxo :mempool (bl.mp:make-mempool)
                              :recent-rejects (bl:make-rejects-filter 1000)
                              :peers (list peer))))

(defun %rc-accept (ctx tx &key (relay t))
  "Deliver TX to the node CTX from a third party, through the shipped tx
handler: validation, the mempool and -- with RELAY -- the relay path that
holds it for a reconciling peer. Returns its wtxid."
  (deliver-tx (bl.net:make-peer :address "third-party" :state :ready
                                :services bl.ser:+node-witness+)
              (subseq (bl.ser:make-tx-message tx) 24)
              (if relay
                  ctx
                  (bl.ctx:make-node-context
                   :chain-state (bl.ctx:node-context-chain-state ctx)
                   :utxo-set (bl.ctx:node-context-utxo-set ctx)
                   :mempool (bl.ctx:node-context-mempool ctx)
                   :recent-rejects (bl.ctx:node-context-recent-rejects ctx))))
  (bl.ser:transaction-wtxid tx))

(defun %rc-loopback-run (&key wrong-salt (rounds t) (seconds 12) (shared-count 10))
  "Run two nodes through reconciliation over a real connection and report.

SHARED-COUNT (ten) shared transactions are in both mempools and both reconciliation sets --
the state after both nodes heard them from third parties -- and six more
reach only the listening node, whose relay path holds them for its dialler
(bar the fanout draw). The dialler holds nothing else of its own. The pump is the
shipped one: the round timer (unless ROUNDS is NIL), the inv flush, the
tx-request scheduler and the per-peer message drain, on both sides, until the
dialler has everything or SECONDS pass.

WRONG-SALT flips a bit of the dialler's k0 before its set is filled, so its
short IDs are not the listener's. Returns a plist: :MISSING, the listener's
transactions the dialler still lacks; :HELD, how many of them the listener's
relay path held back for reconciliation; :SHARED-ANNOUNCED, how many shared
transactions either side announced -- none when the sketches cancelled them,
all when a failed round fell back to flooding; :REGISTERED, whether the
handshake registered both sides."
  (let ((bl:*tx-reconciliation* t)
        (bl:*network* :regtest)
        (bl.val:*recent-rejects-reconsiderable* (bl:make-rejects-filter 100)))
    (with-tx-relay-out-of-ibd
      (bl.net:reset-tx-requests)
      (multiple-value-bind (a b srv) (%rc-loopback-pair)
        (unwind-protect
             (let* ((fundings (loop for i from 1 to (+ shared-count 6)
                                    collect (make-array 32 :element-type '(unsigned-byte 8)
                                                           :initial-element i)))
                    (ctx-a (%rc-node-context fundings a))
                    (ctx-b (%rc-node-context fundings b))
                    (txs (mapcar (lambda (f) (pkg-tx f 0 (- 100000000 10000))) fundings))
                    (shared (subseq txs 0 shared-count))
                    (only-b (subseq txs shared-count)))
               (when wrong-salt
                 (setf (bl.net::peer-recon-k0 a) (logxor 1 (bl.net::peer-recon-k0 a))))
               (dolist (tx shared)
                 (%rc-accept ctx-a tx :relay nil)
                 (%rc-accept ctx-b tx :relay nil)
                 (dolist (peer (list a b))
                   (%rc-hold peer (list (bl.ser:transaction-wtxid tx))
                             :k0 (bl.net::peer-recon-k0 peer)
                             :k1 (bl.net::peer-recon-k1 peer))))
               ;; The dialler has sent its BIP133 feefilter, as every node does:
               ;; 1 sat/vB, which these transactions clear a hundred times over.
               (setf (bl.net:peer-feefilter-rate b) 1000)
               (dolist (tx only-b) (%rc-accept ctx-b tx))
               (let ((held (- (%rc-count (bl.net::peer-recon-set b)) (length shared)))
                     (deadline (+ (get-internal-real-time)
                                  (* seconds internal-time-units-per-second))))
                 (flet ((missing ()
                          (remove-if (lambda (tx)
                                       (bl.mp:mempool-has (bl.ctx:node-context-mempool ctx-a)
                                                          (bl.ser:transaction-hash tx)))
                                     only-b)))
                   (loop while (and (missing) (< (get-internal-real-time) deadline))
                         do (when rounds
                              (bl.net:maybe-start-reconciliation a (bl.ser:get-unix-time)))
                            (flush-peer-invs a (bl.ctx:node-context-mempool ctx-a))
                            (flush-peer-invs b (bl.ctx:node-context-mempool ctx-b))
                            (bl.net:process-tx-requests)
                            (drain-peer-once a ctx-a)
                            (drain-peer-once b ctx-b)
                            (sleep 0.02))
                   (list :registered (and (bl.net::peer-recon-registered a)
                                          (bl.net::peer-recon-registered b)
                                          t)
                         :missing (length (missing))
                         :held held
                         :shared-announced
                         (count-if (lambda (tx)
                                     (let ((w (bl.ser:transaction-wtxid tx)))
                                       (or (bl:recent-reject-p (bl.net:peer-announced-txs a) w)
                                           (bl:recent-reject-p (bl.net:peer-announced-txs b) w))))
                                   shared)))))
          (ignore-errors (bl.net:disconnect-peer a))
          (ignore-errors (bl.net:disconnect-peer b))
          (bl.net:close-listener srv)
          (bl.net:reset-tx-requests))))))

(test two-nodes-reconcile-their-mempools-over-a-real-connection
  "Two of our nodes with -txreconciliation=1 on one loopback connection: the
handshake registers both, the listener holds its new transactions back from
the dialler, and the dialler's round -- reqrecon, sketch, merge and decode,
reconcildiff, the inv, getdata and tx that follow -- brings the dialler's
mempool level with the listener's. The ten shared transactions cancel in the
sketch, so neither side announces them.

Two controls, because a green convergence check alone proves nothing:
- no rounds: the held transactions never reach the dialler, so it is the
  round that delivered them;
- a wrong short-ID salt on one side: the shared transactions no longer cancel,
  the difference outgrows the sketch and its extension, and the round fails
  over to flooding -- every shared transaction is announced. The mempools
  still converge, as BIP-330 intends (a failed reconciliation `costs
  bandwidth, never transactions'), which is why the salt's visible effect is
  the flood and not a lost transaction."
  (let ((ok (%rc-loopback-run)))
    (is-true (getf ok :registered) "the handshake registered both sides: ~S" ok)
    (is (plusp (getf ok :held)) "the listener held transactions for the round: ~S" ok)
    (is (zerop (getf ok :missing)) "the mempools converged: ~S" ok)
    (is (zerop (getf ok :shared-announced))
        "the shared transactions cancelled in the sketch: ~S" ok))
  ;; With nothing in common the dialler's own set is EMPTY, and its round
  ;; must still run: only the dialler opens rounds, so skipping an empty one
  ;; left the listener's held transactions with no way out.
  (let ((empty (%rc-loopback-run :shared-count 0)))
    (is (zerop (getf empty :missing))
        "an empty initiator set still reconciles the listener's: ~S" empty))
  (let ((no-rounds (%rc-loopback-run :rounds nil :seconds 3)))
    (is (= (getf no-rounds :held) (getf no-rounds :missing))
        "without a round, exactly the held transactions stay missing: ~S" no-rounds))
  (let ((wrong (%rc-loopback-run :wrong-salt t)))
    (is (zerop (getf wrong :missing)) "the flood still converges: ~S" wrong)
    (is (= 10 (getf wrong :shared-announced))
        "but nothing cancelled -- the round failed and flooded: ~S" wrong)))

;;; --- Phase 2: the round timeout, the responder's move, q, one queue writer ---

(test an-unanswered-round-times-out-and-floods
  "A responder that never sends its sketch used to pin the round for the life
of the connection: no later round could open and the snapshot was never
announced. After +RECON-ROUND-TIMEOUT-SECONDS+ (Core's GETDATA_TX_INTERVAL,
the expiry of an unanswered transaction request, txdownloadman.h:38) the
initiator gives the round up as a failed one: reconcildiff(success=0) so the
responder floods its snapshot, our snapshot announced from the mempool, and the
next round opens. One second earlier, nothing happens -- the control."
  (multiple-value-bind (mempool wtxids) (%rc-mempool-wtxids 4 :seed 120)
    (let ((peer (%rc-peer :registered t :we-initiate t))
          (timeout bl.net::+recon-round-timeout-seconds+))
      (%rc-hold peer wtxids)
      (bl.net:maybe-start-reconciliation peer 100000 mempool)
      (is-true (%rc-round-open-p peer))
      (is (null (captured-sends
                 (lambda ()
                   (bl.net:maybe-start-reconciliation peer (+ 100000 timeout -1) mempool))))
          "still waiting one second before the timeout")
      (is-true (%rc-round-open-p peer))
      (let ((sent (captured-sends
                   (lambda ()
                     (bl.net:maybe-start-reconciliation peer (+ 100000 timeout) mempool)))))
        (is (equal '("reconcildiff" "reqrecon") (mapcar #'message-command sent))
            "the failure is reported, and the next round opens")
        (is (equal '(nil nil) (%rc-reconcildiff (list (first sent))))))
      (is (= 4 (length (bl.net:peer-tx-inv-queue peer)))
          "the timed-out snapshot is announced the ordinary way"))))

(test the-responder-moves-its-set-into-the-snapshot
  "BIP-330 on reqrecon: the receiver `Makes a snapshot of their current
reconciliation set, and clears the set itself.' A transaction arriving during
the round goes to the next one: the next reqrecon's sketch holds it and
nothing the settled round already carried. A reqrecon arriving before the
previous round's reconcildiff (which BIP-330 forbids) folds the stale
snapshot into the new one rather than dropping it."
  (let* ((peer (%rc-peer :registered t :we-initiate nil :inbound t))
         (first-three (loop for i from 130 below 133 collect (%rc-wtxid i)))
         (late (%rc-wtxid 140))
         (set (%rc-hold peer first-three))
         (ctx (bl.ctx:make-node-context)))
    (%rc-reqrecon peer 0 0 ctx)
    (is (null (bl.net::recon-set-short-ids set)) "the set was moved out and cleared")
    (is (= 3 (length (bl.net:recon-set-snapshot-ids set))))
    (%rc-hold peer (list late))
    (is (equal (%rc-short-ids (list late)) (bl.net::recon-set-short-ids set))
        "the latecomer is in the set, not the round")
    (bl.net:handle-message peer "reconcildiff"
                           (subseq (bl.ser:make-reconcildiff-message t '()) 24) ctx)
    ;; The next round sketches the latecomer alone: |1 - 0| + 0 + 1 = 2.
    (is (equalp (%rc-sketch-payload (%rc-short-ids (list late)) 2)
                (subseq (first (%rc-reqrecon peer 0 0 ctx)) 24)))
    ;; No reconcildiff for that round, and a third reqrecon: nothing is lost.
    (%rc-hold peer (list (%rc-wtxid 141)))
    (%rc-reqrecon peer 0 0 ctx)
    (is (= 2 (length (bl.net:recon-set-snapshot-ids set)))
        "the stale snapshot joined the new one")))

(test q-is-re-estimated-from-the-previous-round
  "BIP-330's worked example: set_size=30, local_set_size=20, an actual
difference of 12 gives q = (12 - |30-20|) / min(30,20) = 0.1. The initiator
holds 20, the responder 30 (19 shared, 11 of its own, 1 of ours); after that
round decodes, the NEXT reqrecon carries floor(0.1 * 32767) = 3276 instead of
the default 1/4's 8191."
  (is (= 1/10 (bl.net::recon-reestimate-q 20 1 11 1/4)))
  (is (= 1/4 (bl.net::recon-reestimate-q 0 0 5 1/4)) "an empty side says nothing")
  (let* ((peer (%rc-peer :registered t :we-initiate t))
         (ours (loop for i from 150 below 170 collect (%rc-wtxid i)))
         (ids (%rc-short-ids ours))
         (theirs (append (rest ids)
                         (%rc-short-ids (loop for i from 300 below 311 collect (%rc-wtxid i))
                                        :k0 5 :k1 6)))
         (ctx (bl.ctx:make-node-context)))
    (%rc-hold peer ours)
    (let ((first-req (first (captured-sends
                             (lambda () (bl.net:maybe-start-reconciliation peer 100000))))))
      (is (= 8191 (nth-value 1 (%rc-reqrecon-raw first-req)))))
    ;; The responder would size |30-20| + floor(1/4 * 20) + 1 = 16.
    (is-true (first (%rc-reconcildiff
                     (captured-sends
                      (lambda ()
                        (bl.net:handle-message peer "sketch" (%rc-sketch-payload theirs 16) ctx)))))
             "the first round decodes")
    (%rc-hold peer (list (%rc-wtxid 200)))
    (let ((second-req (first (captured-sends
                              (lambda () (bl.net:maybe-start-reconciliation peer 100010))))))
      (is (= 3276 (nth-value 1 (%rc-reqrecon-raw second-req)))
          "the second reqrecon carries the re-estimated q"))))

(defun %rc-reqrecon-raw (message)
  "The (set_size q-raw) of a framed reqrecon MESSAGE, both uint16 LE."
  (let ((p (subseq message 24)))
    (values (logior (aref p 0) (ash (aref p 1) 8))
            (logior (aref p 2) (ash (aref p 3) 8)))))

(defun %inv-queue-writers (text)
  "The names of the top-level definitions in TEXT that PUSH onto a peer's
tx-inv queue, read with the Lisp reader (IN-PACKAGE forms honoured) and walked
for (push ITEM (peer-tx-inv-queue ...)). The scanner the queue-writer ratchet
runs over src/, factored out so its positive control can feed it a writer that
must be reported."
  (let ((names '())
        (*package* (find-package :bitcoin-lisp.tests))
        (*read-eval* t))
    (labels ((queue-place-p (place)
               (and (consp place) (symbolp (first place))
                    (string= "PEER-TX-INV-QUEUE" (symbol-name (first place)))))
             (writes-p (form)
               (and (consp form)
                    (or (and (symbolp (first form))
                             (string= "PUSH" (symbol-name (first form)))
                             (consp (cdr form)) (consp (cddr form))
                             (queue-place-p (third form)))
                        (loop for rest on form
                              thereis (and (consp rest) (writes-p (car rest))))))))
      (with-input-from-string (in text)
        (loop for form = (read in nil in)
              until (eq form in)
              do (cond ((and (consp form) (eq (first form) 'in-package))
                        (setf *package* (find-package (second form))))
                       ((and (consp form) (writes-p form))
                        (push (string-downcase (symbol-name (second form))) names))))))
    (nreverse names)))

(test one-writer-queues-tx-announcements
  "Every transaction announcement goes onto a peer's queue through
%QUEUE-TX-ANNOUNCEMENT, which takes a txid and an integer fee rate per kvB:
the flush checks the TXID against the mempool and the rate against the
feefilter, and reconciliation's (wtxid wtxid 0) entries failed both silently.
The ratchet: no other src definition pushes onto the queue. The positive
control is a synthetic writer the scanner must report. And the reconciliation
path queues the mempool's txid for a SEGWIT transaction, whose txid and wtxid
differ, with its real fee rate."
  (is (equal '("rogue") (%inv-queue-writers (format nil "~%(defun rogue (p w)~%  (push (list w w 0) (peer-tx-inv-queue p)))~%(defun fine () 1)"))))
  (let ((writers (loop for path in (directory (merge-pathnames
                                                "src/**/*.lisp"
                                                (asdf:system-source-directory :bitcoin-lisp)))
                       for text = (uiop:read-file-string path)
                       ;; Only a file that names the queue can write it.
                       when (search "peer-tx-inv-queue" text)
                         append (%inv-queue-writers text))))
    (is (equal '("%queue-tx-announcement") writers) "writers: ~S" writers))
  (let* ((mempool (bl.mp:make-mempool))
         (funding (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9))
         (plain (pkg-tx funding 0 (- 100000000 20000)))
         (segwit (bl.ser:make-transaction
                  :version 2 :inputs (bl.ser:transaction-inputs plain)
                  :outputs (bl.ser:transaction-outputs plain) :lock-time 0
                  :witness (vector (list (make-array 1 :element-type '(unsigned-byte 8)
                                                       :initial-element 1)))))
         (txid (bl.ser:transaction-hash segwit))
         (wtxid (bl.ser:transaction-wtxid segwit))
         (peer (%rc-peer :registered t)))
    (bl.mp:mempool-add mempool txid (bl.mp:make-entry-from-tx segwit 20000 1))
    (is (not (equalp txid wtxid)) "the control: a segwit transaction's ids differ")
    (bl.net::%announce-wtxids peer (list wtxid) mempool)
    (let ((entry (first (bl.net:peer-tx-inv-queue peer))))
      (is (equalp txid (first entry)) "the txid slot holds the txid")
      (is (equalp wtxid (second entry)))
      (is (plusp (third entry)) "and the real fee rate"))
    (setf (bl.net:peer-tx-inv-queue peer) '())
    (bl.net::%announce-wtxids peer (list wtxid) nil)
    (is (null (bl.net:peer-tx-inv-queue peer)) "no mempool, no txid, nothing queued")))
