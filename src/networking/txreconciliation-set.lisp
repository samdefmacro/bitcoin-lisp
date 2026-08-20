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
  (let ((id (logand (bitcoin-lisp.crypto:siphash-2-4 k0 k1 wtxid) #xFFFFFFFF)))
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

(defun recon-fanout-target-p (wtxid peer-salt inbound-count outbound-p)
  "Whether this transaction should be announced to this peer immediately rather
than reconciled.

Deterministic in (wtxid, peer salt), so a node does not reveal a new sample on
every retry, and unpredictable to anyone who does not know the salt."
  (let* ((h (bitcoin-lisp.crypto:siphash-2-4 peer-salt 0 wtxid))
         (draw (/ (float (logand h #xFFFFFFFF) 1d0) 4294967296d0)))
    (if outbound-p
        ;; With one outbound destination out of the reconciling outbounds, the
        ;; per-peer probability is 1/n — but the caller knows n, not this
        ;; function, so it passes the count in INBOUND-COUNT for both cases.
        (< draw (if (plusp inbound-count)
                    (/ (float +recon-outbound-fanout-destinations+ 1d0)
                       (float inbound-count 1d0))
                    1d0))
        (< draw +recon-inbound-fanout-fraction+))))
