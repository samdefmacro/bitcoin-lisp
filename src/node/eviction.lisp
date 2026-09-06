(in-package #:bitcoin-lisp)

;;;; Inbound eviction (Core eviction.cpp): which connection to drop when
;;;; the inbound slots are full, and which ones are protected.

(defun count-inbound-peers (node)
  (count-if #'bl.net:peer-inbound (node-peers node)))

(defun merge-inbound-peers (node)
  "Move handshaked inbound peers from the lock-guarded hand-off list into the
node's peer list (capped at *max-inbound-connections*; excess are disconnected). Called
by the sync thread, so PEERS stays single-writer."
  (let ((pending (bt:with-recursive-lock-held ((node-lock node))
                   (prog1 (node-pending-inbound-peers node)
                     (setf (node-pending-inbound-peers node) nil)))))
    ;; node-peers is written only by the sync thread, but RPC threads read it
    ;; under node-lock; hold the lock around the count + push so those reads see
    ;; a consistent set. Recursive: evict-discouraged-inbound re-takes it.
    (dolist (peer pending)
      (bt:with-recursive-lock-held ((node-lock node))
        (cond
          ((< (count-inbound-peers node) *max-inbound-connections*)
           (push peer (node-peers node)))
          ;; At capacity: a discouraged existing inbound peer is preferred for
          ;; eviction (Bitcoin Core), so make room for the newcomer if we can.
          ((evict-discouraged-inbound node)
           (push peer (node-peers node)))
          ;; Otherwise evict the least valuable inbound peer (protecting the
          ;; most valuable) so slots churn toward better peers instead of the
          ;; newcomer always losing — Core's AttemptToEvictConnection.
          ((evict-least-valuable-inbound node)
           (push peer (node-peers node)))
          (t
           (log-info "Inbound peer cap reached; dropping ~A"
                     (bl.net:peer-address peer))
           (bl.net:disconnect-peer peer)))))))

(defun evict-discouraged-inbound (node)
  "If any existing inbound peer is discouraged, disconnect it and return T so a
new inbound connection can take its slot. NIL if none are discouraged."
  (bt:with-recursive-lock-held ((node-lock node))
    (let ((victim (find-if (lambda (p)
                             (and (bl.net:peer-inbound p)
                                  (bl.net:peer-discouraged-p
                                   (bl.net:peer-address p))))
                           (node-peers node))))
      (when victim
        (log-info "Evicting discouraged inbound peer ~A to admit a new connection"
                  (bl.net:peer-address victim))
        (setf (node-peers node) (remove victim (node-peers node)))
        (bl.net:disconnect-peer victim)
        t))))

(defconstant +evict-protect-netgroup+ 4
  "Core SelectNodeToEvict: 4 peers protected by keyed netgroup
(eviction.cpp:186-188). Deterministic but unpredictable — an attacker cannot
tell which netgroups will be protected without the node's key.")
(defconstant +evict-protect-min-ping+ 8
  "8 peers with the lowest MINIMUM ping (:189-191). Was 4 here.")
(defconstant +evict-protect-tx+ 4
  "4 peers that most recently gave us a novel mempool transaction (:192-194).")
(defconstant +evict-protect-block-relay-only+ 8
  "8 NON-tx-relay peers that gave us novel blocks (:195-197). Missing here
entirely, which meant a block-relay-only peer doing exactly the job it exists
for was no safer than an idle one.")
(defconstant +evict-protect-block+ 4
  "4 peers that most recently gave us a novel block (:199-201).")

(defun %evict-erase-last-k (candidates comparator k &optional filter)
  "Core EraseLastKElements: sort CANDIDATES by COMPARATOR and REMOVE the last K
that satisfy FILTER — \"remove\" meaning protect, since this list is the
eviction pool. Returns the remaining candidates.

The comparator orders WORST-first, so the last K are the best K by that
measure. FILTER restricts the pass to a subset (Core's block-relay-only pass is
the only one that uses it) without letting the excluded peers consume slots."
  (let* ((eligible (if filter (remove-if-not filter candidates) candidates))
         (sorted (stable-sort (copy-list eligible) comparator))
         (n (min k (length sorted)))
         (protected (subseq sorted (- (length sorted) n))))
    (remove-if (lambda (p) (member p protected)) candidates)))

(defvar *eviction-netgroup-key* nil
  "The two 64-bit words keying %EVICT-KEYED-NETGROUP, as a cons, or NIL until
SEED-EVICTION-NETGROUP-KEY has drawn them. Core's CConnman nSeed0/nSeed1,
drawn once per PROCESS from a default-constructed FastRandomContext at
AppInitMain (init.cpp:1642-1648: `FastRandomContext rng; ...
CConnman(rng.rand64(), rng.rand64(), ...)').

NIL rather than a load-time draw, and NIL is a hard error at the point of use
rather than a fallback. This was `(defvar *eviction-netgroup-secret* (random
most-positive-fixnum))', whose initform runs at ASDF LOAD time -- before
INIT-NODE re-seeds *random-state*, so the draw came from SBCL's build-time
sequence and was the same integer, 1193941380623146742, in every node of every
operator (and in a bare `sbcl' anybody can run). The whole point of keying the
netgroup is that an attacker cannot compute which groups the eviction pass
protects, so a key computable without even the binary voided
+EVICT-PROTECT-NETGROUP+.")

(defun seed-eviction-netgroup-key ()
  "Draw *EVICTION-NETGROUP-KEY* from the OS CSPRNG; return it.

Core's two rand64() calls at CConnman construction (init.cpp:1642-1648).
Called from INIT-NODE, the one place a node is constructed, so every process
gets its own key. BL.CRYPTO:RAND-U64 has no fallback: a node that cannot reach
the system entropy source fails to start instead of running with a guessable
protection set."
  (setf *eviction-netgroup-key* (cons (bl.crypto:rand-u64) (bl.crypto:rand-u64))))

(defconstant +randomizer-id-netgroup+ #x6c0edd8036ef4036
  "Core RANDOMIZER_ID_NETGROUP (net.cpp:110), SHA256(\"netgroup\")[0:8]. The
domain separator Core writes into the deterministic randomizer before the
netgroup bytes (GetDeterministicRandomizer, net.cpp:4131-4141), so the same
node key produces unrelated values for netgroups and for the other things Core
keys with it.")

(defun %evict-keyed-netgroup (peer)
  "SipHash-2-4 of the peer's netgroup under the node's own key -- Core
CConnman::CalculateKeyedNetGroup (net.cpp:4136-4141), which is
GetDeterministicRandomizer(RANDOMIZER_ID_NETGROUP).Write(group).Finalize().

The KEY is what makes the netgroup protection unpredictable: without it an
attacker knows which groups sort first and can arrange to be outside them. The
PRF matters too, and this used to be (sxhash (cons secret group)): SBCL's
SXHASH over a string does not avalanche, so netgroups sharing a prefix hashed
to adjacent values -- the top twelve of all 57,088 /16 groups were one
contiguous block, 190.210 through 190.238 -- and an attacker who learned the
key at all learned a whole neighbourhood of winners at once.

Signals rather than defaulting when the key was never drawn: a silent fallback
is how the load-time draw survived unnoticed in the first place."
  (let ((key (or *eviction-netgroup-key*
                 (internal-error "eviction netgroup key never drawn (SEED-EVICTION-NETGROUP-KEY runs in INIT-NODE)")))
        ;; IP-NETGROUP renders every network as digits and dots, so CHAR-CODE
        ;; is the group's byte sequence.
        (group (or (bl.net:ip-netgroup (bl.net:peer-address peer)) "_")))
    (bl.crypto:siphash-2-4
     (car key) (cdr key)
     (concatenate '(vector (unsigned-byte 8))
                  (bl.crypto:uint64-to-bytes-le +randomizer-id-netgroup+)
                  (map '(vector (unsigned-byte 8)) #'char-code group)))))

(defun %evict-newest-first (a b)
  "Order two eviction candidates most-recently-connected FIRST — Core's
ReverseCompareNodeTimeConnected, `a.m_connected > b.m_connected'
(eviction.cpp:21-24), which is also the final term of CompareNodeNetworkTime
(:71) and the tie-break of every other comparator in that file.

%EVICT-ERASE-LAST-K protects the LAST K, so this order is what makes the
protected set the LONGEST-connected peers — Core's stated point, \"protect the
half of the remaining nodes which have been connected the longest ... and
precludes attacks that start later\" (:105-107). BOTH ratio passes use it, and
one function rather than two lambdas so they cannot drift apart again: the
disadvantaged-network reserve ran with the comparison reversed, which handed
the reserved quarter of the inbound slots to whoever had connected MOST
recently — the exact attack the pass exists to preclude."
  (> (bl.net:peer-connect-time a) (bl.net:peer-connect-time b)))

(defun %evict-disadvantaged-network (peer)
  "Which of Core's four disadvantaged networks PEER belongs to, or NIL
(eviction.cpp:118-119): CJDNS, I2P, localhost, onion. These \"tend to be
otherwise disadvantaged under our eviction criteria\" — they are higher-latency,
so they lose the ping pass, and inbound onion peers all share the loopback
netgroup, so they lose the netgroup pass too."
  (cond ((bl.net:peer-inbound-onion peer) :onion)
        (t (multiple-value-bind (net bytes)
               (bl.net:parse-network-address
                (bl.net:peer-address peer))
             (declare (ignore bytes))
             (case net
               (:cjdns :cjdns)
               (:i2p :i2p)
               (:torv3 :onion)
               (t (when (bl.net:loopback-address-p
                         (bl.net:peer-address peer))
                    :local)))))))

(defun %evict-protect-by-ratio (candidates)
  "Core ProtectEvictionCandidatesByRatio (eviction.cpp:104-176).

Protects the half of the remaining candidates connected longest, and reserves
up to half of THAT (a quarter of the candidates) for the four disadvantaged
networks — giving the network with the FEWEST candidates first claim on unused
slots, so a single onion peer is not crowded out by a dozen I2P ones.

Within the reserve the peers protected are that network's LONGEST-connected
ones, the same measure as the general half; both passes go through
%EVICT-NEWEST-FIRST, which is where the direction is stated once.

This replaces an ad-hoc onion exemption that predated it here. The exemption
worked for the case it was written for — every inbound onion peer shares the
loopback netgroup, so two of them were automatically the largest group and one
was evicted on every admission — but it protected onion peers absolutely rather
than proportionally, so an all-onion inbound set could not make room at all."
  (let* ((initial (length candidates))
         (total-protect (floor initial 2))
         (max-by-network (floor total-protect 2))
         (num-protected 0)
         (remaining candidates)
         ;; Counts per network, fewest first: Core sorts ascending so the
         ;; scarcest network gets first claim on slots the others leave.
         (networks (list :cjdns :i2p :local :onion))
         (counts (mapcar (lambda (net)
                           (cons net (count net candidates
                                            :key #'%evict-disadvantaged-network)))
                         networks)))
    (setf counts (stable-sort counts #'< :key #'cdr))
    (loop while (< num-protected max-by-network)
          do (let ((live (count-if #'plusp counts :key #'cdr)))
               (when (zerop live) (return))
               (let* ((left (- max-by-network num-protected))
                      (per-network (max 1 (floor left live)))
                      (protected-any nil))
                 (dolist (entry counts)
                   (when (plusp (cdr entry))
                     (let* ((net (car entry))
                            (before (length remaining))
                            (after (%evict-erase-last-k
                                    remaining
                                    #'%evict-newest-first
                                    per-network
                                    (lambda (p) (eq net (%evict-disadvantaged-network p))))))
                       (setf remaining after)
                       (let ((delta (- before (length remaining))))
                         (when (plusp delta)
                           (setf protected-any t)
                           (incf num-protected delta)
                           (decf (cdr entry) delta)
                           (when (>= num-protected max-by-network) (return)))))))
                 (unless protected-any (return)))))
    ;; Whatever is left of the half goes to the longest-connected.
    (%evict-erase-last-k remaining
                         #'%evict-newest-first
                         (max 0 (- total-protect num-protected)))))

(defun select-inbound-peer-to-evict (inbound)
  "Core SelectNodeToEvict (eviction.cpp:178-240), pass for pass. Returns the
peer to evict, or NIL when every candidate is protected.

The order is load-bearing and is Core's: noban, then the five \"has done
something useful\" passes with Core's own k values, then the ratio reserve,
then prefer-evict, then the most-populous netgroup, youngest first.

Ours previously ran four passes at k=4 apiece with no netgroup pass, no
block-relay-only pass, no noban protection, and an onion exemption standing in
for the ratio reserve."
  (let ((candidates inbound))
    ;; ProtectNoBanConnections (eviction.cpp:181). Only possible since net
    ;; permissions landed; a noban peer is never evicted for any reason.
    (setf candidates
          (remove-if (lambda (p)
                       (bl.net:peer-has-permission-p
                        p bl.net:+perm-noban+))
                     candidates))
    ;; ProtectOutboundConnections is implicit: INBOUND is inbound-only.
    (setf candidates (%evict-erase-last-k candidates
                                          (lambda (a b)
                                            (< (%evict-keyed-netgroup a)
                                               (%evict-keyed-netgroup b)))
                                          +evict-protect-netgroup+))
    ;; Lowest MINIMUM ping, not the latest sample: an attacker can inflate a
    ;; recent sample at will but cannot lower a minimum without being closer.
    (setf candidates (%evict-erase-last-k
                      candidates
                      (lambda (a b)
                        (flet ((ping (p)
                                 (let ((l (bl.net:peer-min-ping-latency p)))
                                   (if (plusp l) l most-positive-fixnum))))
                          (> (ping a) (ping b))))
                      +evict-protect-min-ping+))
    (setf candidates (%evict-erase-last-k
                      candidates
                      (lambda (a b)
                        (< (bl.net:peer-last-tx-time a)
                           (bl.net:peer-last-tx-time b)))
                      +evict-protect-tx+))
    ;; Block-relay-only peers that have given us blocks: Core filters this pass
    ;; to non-tx-relay peers so the slots cannot be taken by ordinary peers
    ;; that happen to have relayed a block.
    (setf candidates (%evict-erase-last-k
                      candidates
                      (lambda (a b)
                        (< (bl.net:peer-last-block-time a)
                           (bl.net:peer-last-block-time b)))
                      +evict-protect-block-relay-only+
                      (lambda (p)
                        (not (bl.net:peer-relays-txs-p p)))))
    (setf candidates (%evict-erase-last-k
                      candidates
                      (lambda (a b)
                        (< (bl.net:peer-last-block-time a)
                           (bl.net:peer-last-block-time b)))
                      +evict-protect-block+))
    (setf candidates (%evict-protect-by-ratio candidates))
    (when (null candidates)
      (return-from select-inbound-peer-to-evict nil))
    ;; Peers preferred for eviction, if any, are considered alone — but only
    ;; AFTER the passes above, since a peer that is genuinely the best by other
    ;; criteria should survive regardless (Core's own comment, :215-217).
    ;; Core's prefer_evict is set for a discouraged peer, which is exactly what
    ;; EVICT-DISCOURAGED-INBOUND already drops first; reaching here means none
    ;; was found, so this arm normally finds none either. It stays because the
    ;; two paths can disagree: a peer discouraged BETWEEN the two calls is
    ;; still preferred here.
    (let ((preferred (remove-if-not
                      (lambda (p)
                        (bl.net:peer-discouraged-p
                         (bl.net:peer-address p)))
                      candidates)))
      (when preferred (setf candidates preferred)))
    ;; Finally: the netgroup with the most connections, youngest member first.
    (let ((groups (make-hash-table :test 'equal)))
      (flet ((grp (p) (or (bl.net:ip-netgroup
                           (bl.net:peer-address p))
                          "_")))
        (dolist (p candidates) (incf (gethash (grp p) groups 0)))
        (first (stable-sort
                (copy-list candidates)
                (lambda (a b)
                  (let ((ga (gethash (grp a) groups 0))
                        (gb (gethash (grp b) groups 0)))
                    (if (/= ga gb)
                        (> ga gb)
                        (> (bl.net:peer-connect-time a)
                           (bl.net:peer-connect-time b)))))))))))

(defun evict-least-valuable-inbound (node)
  "At inbound capacity with no discouraged peer to drop, evict the least
valuable inbound peer so a new connection can take the slot — stopping an
attacker from filling inbound slots with cheap, sticky connections. Returns T
if a peer was evicted.

The selection is SELECT-INBOUND-PEER-TO-EVICT, which is Core's
AttemptToEvictConnection pass for pass."
  (bt:with-recursive-lock-held ((node-lock node))
    (let ((inbound (remove-if-not #'bl.net:peer-inbound
                                  (node-peers node))))
      (when (cdr inbound)               ; need >1 so something stays protected
        (let ((victim (select-inbound-peer-to-evict inbound)))
          (when victim
            (log-info "Evicting least-valuable inbound peer ~A to admit a new connection"
                      (bl.net:peer-address victim))
            (setf (node-peers node) (remove victim (node-peers node)))
            (bl.net:disconnect-peer victim)
            t))))))

(defun inbound-connection-allowed-p (node host &optional onion)
  "Admission check for a freshly-accepted inbound connection from HOST,
before any handshake work (Core CConnman::CreateNodeFromAcceptedSocket,
net.cpp:1801-1813): a banned address is always dropped; a discouraged
address is dropped only when the inbound slots are (almost) full; and no
connection is admitted while the hand-off queue is already full. Returns T,
or (VALUES NIL REASON) when the connection must be dropped.

BOTH ban arms are exempted for a peer holding NoBan, which is Core's shape:
each drop is guarded by `!NetPermissions::HasFlag(permission_flags,
NetPermissionFlags::NoBan)' (net.cpp:1798-1812), the flags having been filled
from vWhitelistedRangeIncoming at :1771. Surviving our own ban list is the
whole point of -whitelist=noban@..., and this was the one place in the tree
that consulted neither the flag nor the -whitebind grant, so an operator's
explicitly trusted peer was still refused at accept time by a `setban' (or a
banlist.json entry persisted from before the whitelist was configured). The
backlog arm is NOT exempted: it is ours, not Core's, and it bounds file
descriptors rather than expressing an opinion about the peer.

ONION is the accepting listener's onion-ness (Core's inbound_onion, computed
from m_onion_binds at :1767 and passed to the whitelist lookup at :1770-1772,
which is BEFORE both ban arms read the flags). It must be threaded here and
not only onto the peer: every inbound onion connection presents the local Tor
daemon's loopback address, so without it a range grant covering 127.0.0.1
would exempt every anonymous onion peer from this node's own ban list. See
PEER-PERMISSION-FLAGS.

The backlog arm matters because *MAX-INBOUND-CONNECTIONS* is otherwise enforced only
at MERGE time, by the sync thread. Accepted peers hold a socket while they wait
in PENDING-INBOUND-PEERS, so anything that stalls that thread turns every new
connection into a leaked descriptor — the live wedge of 2026-08-16 accumulated
751 sockets in CLOSE-WAIT this way. Counting the queue bounds the damage at
twice the inbound cap no matter what the rest of the node is doing."
  ;; Ban check first and lock-free: a connect flood is exactly when the listener
  ;; must not contend with the sync thread and RPC readers for the node lock.
  (let ((noban (bl.net:permission-flag-set-p
                (bl.net:peer-permission-flags host t onion)
                bl.net:+perm-noban+)))
    (cond
      ((and (not noban) (bl.net:peer-banned-p host))
       (values nil :banned))
      ((>= (bt:with-recursive-lock-held ((node-lock node))
             (length (node-pending-inbound-peers node)))
           *max-inbound-connections*)
       (values nil :backlog))
      ((and (not noban)
            (bl.net:peer-discouraged-p host)
            (>= (1+ (bt:with-recursive-lock-held ((node-lock node))
                      (count-inbound-peers node)))
                *max-inbound-connections*))
       (values nil :discouraged))
      (t t))))
