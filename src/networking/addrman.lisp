(in-package #:bitcoin-lisp.networking)

;;; Address Manager (addrman) — new/tried bucket scheme (Bitcoin Core AddrMan).
;;;
;;; Eclipse-attack hardening. Unverified gossiped addresses live in the NEW
;;; table (1024 buckets); addresses we have successfully connected to live in the
;;; TRIED table (256 buckets). Bucket placement is keyed by a per-node secret +
;;; the address's network group and — for new entries — the *source* peer's
;;; group, so one operator (or one source) cannot dominate our address set or
;;; selection. Mirrors refs/bitcoin/src/addrman.cpp.

;;;; Constants (addrman.cpp:27-46 / addrman_impl.h:26-33)

(defconstant +addrman-new-bucket-count+ 1024)
(defconstant +addrman-tried-bucket-count+ 256)
(defconstant +addrman-bucket-size+ 64)
(defconstant +addrman-new-buckets-per-source-group+ 64)
(defconstant +addrman-tried-buckets-per-group+ 8)
(defconstant +addrman-new-buckets-per-address+ 8)
(defconstant +addrman-horizon-seconds+ (* 30 24 60 60))      ; 30 days
(defconstant +addrman-retries+ 3)
(defconstant +addrman-max-failures+ 10)
(defconstant +addrman-min-fail-seconds+ (* 7 24 60 60))      ; 7 days
(defconstant +addrman-replacement-seconds+ (* 4 60 60))      ; 4 hours
(defconstant +addrman-set-tried-collision-size+ 10)
(defconstant +addrman-test-window-seconds+ (* 40 60))        ; 40 minutes
(defconstant +addrman-replacement-min-seconds+ 60
  "Core ResolveCollisions gives an incumbent at least this long after a
connection attempt to succeed before the challenger replaces it
(addrman.cpp:944-950).")
(defconstant +addrman-getaddr-max+ 1000)
(defconstant +addrman-getaddr-pct+ 23)
(defconstant +addrman-select-max-iterations+ 50000
  "Runaway backstop for address-book-select's bucket scan. Comfortably exceeds
the bucket count so a sparse table still finds an occupied bucket; if it is ever
exhausted, select falls back to a uniform random pick (never NIL for non-empty).")

;;;; Data structures

(defun make-addrman-key ()
  "A fresh 32-byte secret used to key bucket placement. Read from the OS CSPRNG
so an attacker cannot predict our bucketing (which would let them target
specific buckets); falls back to the Lisp PRNG only if /dev/urandom is absent."
  (let ((k (make-array 32 :element-type '(unsigned-byte 8))))
    (or (ignore-errors
          (with-open-file (u "/dev/urandom" :element-type '(unsigned-byte 8))
            (= 32 (read-sequence k u))))
        (dotimes (i 32) (setf (aref k i) (random 256))))
    k))

(defun make-bucket-table (n-buckets)
  "A flat fixnum table for N-BUCKETS × bucket-size, all slots empty (-1)."
  (make-array (* n-buckets +addrman-bucket-size+)
              :element-type 'fixnum :initial-element -1))

(defstruct address-book
  "Bitcoin Core-style address manager: new/tried buckets keyed by a per-node
secret, source-group spreading, and test-before-evict tried promotion."
  (key (make-addrman-key) :type (simple-array (unsigned-byte 8) (32)))
  (next-id 0 :type fixnum)
  (info (make-hash-table :test 'eql) :type hash-table)         ; id -> peer-address
  (addr-map (make-hash-table :test 'equalp) :type hash-table)  ; 18-byte key -> id
  (random-ids (make-array 0 :adjustable t :fill-pointer 0))    ; vector of ids
  (new-table (make-bucket-table +addrman-new-bucket-count+)
   :type (simple-array fixnum (*)))
  (tried-table (make-bucket-table +addrman-tried-bucket-count+)
   :type (simple-array fixnum (*)))
  (n-new 0 :type fixnum)
  (n-tried 0 :type fixnum)
  (tried-collisions '() :type list)
  (last-good 1 :type (unsigned-byte 32))    ; m_last_good (failure-count epoch)
  (dirty nil :type boolean))

(defun ab-now ()
  (bl.ser:get-unix-time))

(declaim (inline bucket-slot))
(defun bucket-slot (bucket pos)
  (+ (* bucket +addrman-bucket-size+) pos))

;;;; Hashing + grouping

(defun int-to-le-bytes (n n-bytes)
  "Encode integer N as N-BYTES little-endian."
  (let ((v (make-array n-bytes :element-type '(unsigned-byte 8))))
    (dotimes (i n-bytes v)
      (setf (aref v i) (ldb (byte 8 (* 8 i)) n)))))

(defun addrman-cheap-hash (&rest parts)
  "First 8 bytes (little-endian uint64) of hash256 over the concatenation of
PARTS (byte vectors). Bitcoin Core's HashWriter().GetCheapHash(); only internal
consistency matters (the key is a per-node secret), not byte-compat with Core."
  (let* ((total (reduce #'+ parts :key #'length))
         (buf (make-array total :element-type '(unsigned-byte 8)))
         (off 0))
    (dolist (p parts)
      (replace buf p :start1 off)
      (incf off (length p)))
    (let ((h (bl.crypto:hash256 buf)))
      (logior (aref h 0) (ash (aref h 1) 8) (ash (aref h 2) 16) (ash (aref h 3) 24)
              (ash (aref h 4) 32) (ash (aref h 5) 40) (ash (aref h 6) 48)
              (ash (aref h 7) 56)))))

(defun %ipv6-prefix-p (ip bytes)
  "T when IP starts with BYTES (Core's HasPrefix over its fixed prefix arrays)."
  (loop for b in bytes for i from 0 always (= (aref ip i) b)))

(defun ipv6-linked-ipv4-group (ip)
  "The two high bytes of the IPv4 address carried inside a tunneled/translated
IPv6 address (Core HasLinkedIPv4/GetLinkedIPv4, netaddress.cpp:652-673), or
NIL: RFC6052 (64:ff9b::/96) and RFC6145 (::ffff:0:0:0/96) carry it in the
last 4 bytes, RFC3964 (2002::/16, 6to4) in bytes 2-5, and RFC4380 (2001::/32,
Teredo) bit-flipped in the last 4 bytes. IPv4-mapped addresses are :ipv4 in
our representation and never reach this."
  (flet ((prefix-p (bytes) (%ipv6-prefix-p ip bytes)))
    (cond ((or (prefix-p '(#x00 #x64 #xFF #x9B #x00 #x00      ; RFC6052
                           #x00 #x00 #x00 #x00 #x00 #x00))
               (prefix-p '(#x00 #x00 #x00 #x00 #x00 #x00      ; RFC6145
                           #x00 #x00 #xFF #xFF #x00 #x00)))
           (list (aref ip 12) (aref ip 13)))
          ((prefix-p '(#x20 #x02))                            ; RFC3964 6to4
           (list (aref ip 2) (aref ip 3)))
          ((prefix-p '(#x20 #x01 #x00 #x00))                  ; RFC4380 Teredo
           (list (logxor #xFF (aref ip 12)) (logxor #xFF (aref ip 13)))))))

(defun net-group-key (ip &optional net)
  "GetGroup (Core netgroup.cpp:19-107): the bucket group used to
spread addresses across buckets by network operator. IPv4 -> [1, /16];
IPv6 -> [2, /32], except tunneled/translated IPv4 carriers (6to4, Teredo,
RFC6052/6145) which group as the linked IPv4's /16 with Core's NET_IPV4
class byte (GetNetClass, netaddress.cpp) and he.net (2001:470::/32) which
gets /36 groups; TORv3/I2P -> [net, addr[0]|0x0F] (4 group bits of a
pubkey-derived address); CJDNS -> [5, addr[0], addr[1]|0x0F] (12 bits,
skipping the constant 0xFC prefix byte); unroutable -> [0] (for IPv6 that
includes fc00::/7 arriving untagged, per address-routable-p; private IPv4
stays grouped — our deliberate divergence). The leading byte is Core's
Network enum value (IPV4=1 IPV6=2 ONION=3 I2P=4 CJDNS=5). NET NIL derives
IPv4/IPv6 from the 16-byte mapped form.

With an -asmap loaded, a mapped address groups by its ASN instead of its
prefix (Core GetGroup's `if (m_asmap.size())` branch, netgroup.cpp:31-40). That
is the whole point of the option: an AS often spans many /16s, so prefix
bucketing lets one operator look like many groups. An address the map does not
cover falls back to the prefix rules below, as Core's does when Interpret
returns 0."
  (flet ((group (&rest bytes)
           (make-array (length bytes) :element-type '(unsigned-byte 8)
                                      :initial-contents bytes)))
    (let ((asn (and *asmap* (= (length ip) 16) (asmap-asn ip))))
      (when asn
        ;; Core prefixes the network class byte and then the ASN, so two
        ;; addresses in one AS share a group and nothing else does.
        (return-from net-group-key
          (group 1
                 (logand #xff (ash asn -24)) (logand #xff (ash asn -16))
                 (logand #xff (ash asn -8))  (logand #xff asn)))))
    (let ((net (or net (and (= (length ip) 16) (ip-network ip)))))
      (case net
        (:ipv4
         (if (ipv4-mapped-p ip)
             (group 1 (aref ip 12) (aref ip 13))
             (group 0)))
        (:ipv6
         (let ((linked (ipv6-linked-ipv4-group ip)))
           (cond
             ((or (every #'zerop ip) (member (aref ip 0) '(#xFC #xFD)))
              (group 0))
             (linked (apply #'group 1 linked))
             ;; he.net 2001:470::/32 -> /36 groups (netgroup.cpp:62-64).
             ((and (= (aref ip 0) #x20) (= (aref ip 1) #x01)
                   (= (aref ip 2) #x04) (= (aref ip 3) #x70))
              (group 2 (aref ip 0) (aref ip 1) (aref ip 2) (aref ip 3)
                     (logior (aref ip 4) #x0F)))
             (t (group 2 (aref ip 0) (aref ip 1) (aref ip 2) (aref ip 3))))))
        (:torv3 (group 3 (logior (aref ip 0) #x0F)))
        (:i2p (group 4 (logior (aref ip 0) #x0F)))
        (:cjdns (group 5 (aref ip 0) (logior (aref ip 1) #x0F)))
        (t (group 0))))))

(defun %ipv6-unroutable-p (ip)
  "Core's IPv6 exclusions in IsRoutable/IsValid (netaddress.cpp:341-391,
398-412, 462-465): ::1 (IsLocal), RFC4862 link-local (fe80::/64 as Core
matches it), RFC4193 (fc00::/7, CJDNS's carve-out — must arrive tagged
NET_CJDNS), RFC3849 documentation (2001:db8::/32), RFC4843 ORCHID
(2001:10::/28) and RFC7343 ORCHIDv2 (2001:20::/28)."
  (or (and (= (aref ip 15) 1) (loop for i below 15 always (zerop (aref ip i))))
      (%ipv6-prefix-p ip '(#xFE #x80 0 0 0 0 0 0))
      (member (aref ip 0) '(#xFC #xFD))
      (%ipv6-prefix-p ip '(#x20 #x01 #x0D #xB8))
      (and (%ipv6-prefix-p ip '(#x20 #x01 #x00))
           (member (logand (aref ip 3) #xF0) '(#x10 #x20)))))

(defun address-routable-p (ip &optional net)
  "Core IsRoutable (netaddress.cpp:462-465), per network: correct byte length,
non-zero, CJDNS carries the 0xFC prefix, and no IPv6 special-purpose range
(%ipv6-unroutable-p).

Deliberate divergence: IPv4 private (RFC1918) and documentation (RFC5737)
ranges stay routable here — Core rejects both — for private/regtest setups
and the fixtures in tests/ that depend on them."
  (let ((net (or net (and (= (length ip) 16) (ip-network ip)))))
    (and net
         (= (length ip) (network-address-length net))
         (notevery #'zerop ip)
         (case net
           (:cjdns (= (aref ip 0) #xFC))
           (:ipv6 (not (%ipv6-unroutable-p ip)))
           (t t)))))

(defun peer-address-key (pa)
  "The addrman map key for record PA (network-typed)."
  (make-address-key (peer-address-ip pa) (peer-address-port pa)
                    (peer-address-network pa)))

(defun peer-address-group (pa)
  "The netgroup key for record PA (network-typed)."
  (net-group-key (peer-address-ip pa) (peer-address-network pa)))

(defun tried-bucket (book pa)
  "Tried-table bucket for PA (Core GetTriedBucket)."
  (let* ((key (address-book-key book))
         (akey (peer-address-key pa))
         (group (peer-address-group pa))
         (h1 (addrman-cheap-hash key akey))
         (h2 (addrman-cheap-hash
              key group (int-to-le-bytes
                         (mod h1 +addrman-tried-buckets-per-group+) 8))))
    (mod h2 +addrman-tried-bucket-count+)))

(defun new-bucket (book pa source-group)
  "New-table bucket for PA learned from SOURCE-GROUP (Core GetNewBucket)."
  (let* ((key (address-book-key book))
         (group (peer-address-group pa))
         (h1 (addrman-cheap-hash key group source-group))
         (h2 (addrman-cheap-hash
              key source-group (int-to-le-bytes
                                (mod h1 +addrman-new-buckets-per-source-group+) 8))))
    (mod h2 +addrman-new-bucket-count+)))

(defun bucket-position-akey (book akey new-p bucket)
  "Slot within BUCKET for the address whose 18-byte key is AKEY. Split out so a
scan over all buckets (MakeTried) computes AKEY once instead of per bucket."
  (let ((marker (make-array 1 :element-type '(unsigned-byte 8)
                              :initial-element (if new-p 78 75))))  ; 'N' / 'K'
    (mod (addrman-cheap-hash (address-book-key book) marker
                             (int-to-le-bytes bucket 4) akey)
         +addrman-bucket-size+)))

(defun bucket-position (book pa new-p bucket)
  "Slot within BUCKET for PA (Core GetBucketPosition). Depends only on the
address + bucket + table, so MakeTried can scan all buckets at this position."
  (bucket-position-akey book (peer-address-key pa) new-p bucket))

;;;; Quality (Core IsTerrible / GetChance)

(defun addr-info-terrible-p (pa now)
  "T if PA is so stale/unreachable it should be a candidate for eviction."
  (cond
    ((<= (- now (peer-address-last-attempt pa)) 60) nil)   ; tried within the last minute
    ((> (peer-address-last-seen pa) (+ now 600)) t)         ; timestamp from the future
    ((> (- now (peer-address-last-seen pa)) +addrman-horizon-seconds+) t)  ; not seen in 30d
    ((and (zerop (peer-address-last-success pa))
          (>= (peer-address-n-attempts pa) +addrman-retries+)) t)
    ((and (> (- now (peer-address-last-success pa)) +addrman-min-fail-seconds+)
          (>= (peer-address-n-attempts pa) +addrman-max-failures+)) t)
    (t nil)))

(defun addr-info-chance (pa now)
  "Selection-probability weight in [0,1] (Core GetChance)."
  (let ((chance 1.0d0))
    (when (< (- now (peer-address-last-attempt pa)) 600)
      (setf chance (* chance 0.01d0)))
    (* chance (expt 0.66d0 (min (peer-address-n-attempts pa) 8)))))

;;;; Random-id set (vRandom) — O(1) membership removal

(defun ab-random-push (book pa)
  (let ((v (address-book-random-ids book)))
    (setf (peer-address-random-pos pa) (fill-pointer v))
    (vector-push-extend (peer-address-id pa) v)))

(defun ab-random-remove (book pa)
  (let* ((v (address-book-random-ids book))
         (pos (peer-address-random-pos pa)))
    (when (>= pos 0)
      (let* ((last (1- (fill-pointer v)))
             (last-id (aref v last)))
        (setf (aref v pos) last-id)
        (let ((last-pa (gethash last-id (address-book-info book))))
          (when last-pa (setf (peer-address-random-pos last-pa) pos)))
        (decf (fill-pointer v))
        (setf (peer-address-random-pos pa) -1)))))

;;;; Core map operations

(defun ab-find (book ip port &optional net)
  "Return the peer-address record for IP:PORT on network NET (NIL derives
IPv4/IPv6 from the 16-byte form), or NIL."
  (let ((id (gethash (make-address-key ip port net) (address-book-addr-map book))))
    (and id (gethash id (address-book-info book)))))

(defun ab-create (book ip port services time source-group &optional net)
  "Create and register a fresh record (not yet in any bucket). Caller counts it."
  (let* ((id (address-book-next-id book))
         (pa (make-peer-address :net net :ip (copy-seq ip) :port port
                                :services services :last-seen time
                                :source-group source-group :id id)))
    (incf (address-book-next-id book))
    (setf (gethash id (address-book-info book)) pa)
    (setf (gethash (make-address-key ip port net) (address-book-addr-map book)) id)
    (ab-random-push book pa)
    pa))

(defun ab-delete (book id)
  "Remove a refcount-0, non-tried entry entirely (Core Delete)."
  (let ((pa (gethash id (address-book-info book))))
    (when pa
      (decf (address-book-n-new book))
      (ab-random-remove book pa)
      (remhash (peer-address-key pa) (address-book-addr-map book))
      (remhash id (address-book-info book)))))

(defun ab-clear-new (book bucket pos)
  "Empty new[BUCKET][POS]; if the displaced entry loses its last ref, delete it."
  (let* ((nt (address-book-new-table book))
         (slot (bucket-slot bucket pos))
         (id (aref nt slot)))
    (when (>= id 0)
      (let ((pa (gethash id (address-book-info book))))
        (setf (aref nt slot) -1)
        (when pa
          (decf (peer-address-ref-count pa))
          (when (zerop (peer-address-ref-count pa))
            (ab-delete book id)))))))

(defun ab-make-tried (book pa)
  "Move PA from the new table into the tried table (Core MakeTried), evicting any
incumbent back to a new bucket."
  (let ((nt (address-book-new-table book))
        (id (peer-address-id pa))
        (akey (peer-address-key pa)))
    ;; Remove from every new bucket (scan by position — independent of source;
    ;; AKEY is computed once and reused across all 1024 buckets).
    (dotimes (b +addrman-new-bucket-count+)
      (let ((slot (bucket-slot b (bucket-position-akey book akey t b))))
        (when (= (aref nt slot) id)
          (setf (aref nt slot) -1)
          (decf (peer-address-ref-count pa)))))
    (decf (address-book-n-new book))
    (setf (peer-address-ref-count pa) 0)
    (let* ((tb (tried-bucket book pa))
           (tp (bucket-position book pa nil tb))
           (slot (bucket-slot tb tp))
           (tt (address-book-tried-table book))
           (evict-id (aref tt slot)))
      (when (/= evict-id -1)
        ;; Demote the incumbent back into a new bucket.
        (let ((old (gethash evict-id (address-book-info book))))
          (setf (peer-address-in-tried old) nil)
          (setf (aref tt slot) -1)
          (decf (address-book-n-tried book))
          (let* ((sg (or (peer-address-source-group old)
                         (peer-address-group old)))
                 (ub (new-bucket book old sg))
                 (up (bucket-position book old t ub)))
            (ab-clear-new book ub up)
            (setf (peer-address-ref-count old) 1)
            (setf (aref nt (bucket-slot ub up)) evict-id)
            (incf (address-book-n-new book)))))
      (setf (aref tt slot) id)
      (incf (address-book-n-tried book))
      (setf (peer-address-in-tried pa) t)
      (setf (address-book-dirty book) t))))

;;;; Public API

(defun address-book-count (book)
  "Total addresses tracked (new + tried)."
  (+ (address-book-n-new book) (address-book-n-tried book)))

(defun address-book-lookup (book ip port &optional net)
  "Return the record for IP:PORT on network NET (NIL derives IPv4/IPv6 from
the 16-byte form), or NIL (Core Find)."
  (ab-find book ip port net))

(defun address-book-add (book pa &optional source-group (time-penalty 0))
  "Add address PA (a peer-address carrying net/ip/port/services/last-seen)
learned from a peer whose net-group key is SOURCE-GROUP (a net-group-key
result over the gossiping peer's typed address — any network, now that
onion/cjdns peers can be dial sources; defaults to the added address's own
group), placing it in a NEW bucket per Bitcoin Core AddrMan AddSingle.

TIME-PENALTY (seconds, default none) ages the timestamp we record, exactly as
Core's AddrMan::Add time_penalty argument does (addrman.cpp:596): a third
party telling us about an address is weaker evidence of liveness than our own
observation, so gossiped addresses are stored 2h in the past
(net_processing.cpp:4114) while our own dial outcomes are not. A
self-announcement is exempt (addrman.cpp:559-563) — that is the caller's call,
since only it knows the source address. The stored timestamp never moves
backwards and never goes negative.

Returns T if newly inserted into a new bucket."
  (let ((ip (peer-address-ip pa))
        (net (peer-address-network pa)))
    (unless (address-routable-p ip net)
      (return-from address-book-add nil))
    (let* ((port (peer-address-port pa))
           (services (peer-address-services pa))
           (time (max 0 (- (peer-address-last-seen pa) time-penalty)))
           (source-group (or source-group (net-group-key ip net)))
           (existing (ab-find book ip port net))
           (info nil))
      (if existing
          (progn
            (setf (peer-address-services existing)
                  (logior (peer-address-services existing) services))
            (when (> time (peer-address-last-seen existing))
              (setf (peer-address-last-seen existing) time))
            ;; Don't multiply into more buckets once tried or at max multiplicity.
            (when (or (peer-address-in-tried existing)
                      (>= (peer-address-ref-count existing)
                          +addrman-new-buckets-per-address+))
              (return-from address-book-add nil))
            ;; Exponentially harder to add to yet another new bucket.
            (let ((factor (ash 1 (peer-address-ref-count existing))))
              (when (and (> factor 1) (/= 0 (random factor)))
                (return-from address-book-add nil)))
            (setf info existing))
          (progn
            (setf info (ab-create book ip port services time source-group
                                  (peer-address-net pa)))
            (incf (address-book-n-new book))))
      (let* ((bucket (new-bucket book info source-group))
             (pos (bucket-position book info t bucket))
             (slot (bucket-slot bucket pos))
             (nt (address-book-new-table book))
             (cur (aref nt slot))
             (id (peer-address-id info))
             (insert (= cur -1)))
        (when (/= cur id)
          (when (and (not insert) (>= cur 0))
            (let ((other (gethash cur (address-book-info book))))
              (when (and other
                         (or (addr-info-terrible-p other (ab-now))
                             (and (> (peer-address-ref-count other) 1)
                                  (zerop (peer-address-ref-count info)))))
                (setf insert t))))
          (if insert
              (progn
                (ab-clear-new book bucket pos)
                (incf (peer-address-ref-count info))
                (setf (aref nt slot) id))
              (when (zerop (peer-address-ref-count info))
                (ab-delete book id))))
        (setf (address-book-dirty book) t)
        insert))))

(defun address-book-good (book ip port &optional (now (ab-now)) net)
  "Record a successful connection to IP:PORT and promote it new -> tried
(test-before-evict). Returns T if promoted, NIL if queued for collision test."
  (setf (address-book-last-good book) now)
  (let ((pa (ab-find book ip port net)))
    (when pa
      (setf (peer-address-last-success pa) now
            (peer-address-last-attempt pa) now
            (peer-address-n-attempts pa) 0)
      (when (or (peer-address-in-tried pa) (zerop (peer-address-ref-count pa)))
        (return-from address-book-good nil))
      (let* ((tb (tried-bucket book pa))
             (tp (bucket-position book pa nil tb))
             (slot (bucket-slot tb tp)))
        (if (/= (aref (address-book-tried-table book) slot) -1)
            (progn
              (when (< (length (address-book-tried-collisions book))
                       +addrman-set-tried-collision-size+)
                (pushnew (peer-address-id pa) (address-book-tried-collisions book)))
              nil)
            (progn (ab-make-tried book pa) t))))))

(defun address-book-attempt (book ip port &key (count-failure t) (now (ab-now)) net)
  "Record a connection attempt to IP:PORT (Core Attempt)."
  (let ((pa (ab-find book ip port net)))
    (when pa
      (setf (peer-address-last-attempt pa) now)
      (when (and count-failure
                 (< (peer-address-last-count-attempt pa) (address-book-last-good book)))
        (setf (peer-address-last-count-attempt pa) now)
        (incf (peer-address-n-attempts pa))))))

(defun address-book-connected (book ip port &optional (now (ab-now)) net)
  "Refresh nTime after a working connection, throttled to avoid topology leaks
(Core Connected — only bumps if >20 min stale)."
  (let ((pa (ab-find book ip port net)))
    (when (and pa (> (- now (peer-address-last-seen pa)) 1200))
      (setf (peer-address-last-seen pa) now))))

(defun address-book-select (book &key new-only (now (ab-now)))
  "Choose an address for a new outbound connection (Core Select). Returns a
peer-address or NIL. Picks a random bucket+position, biased toward higher-quality
entries via GetChance; alternates new/tried roughly 50/50 when both are present."
  (when (zerop (fill-pointer (address-book-random-ids book)))
    (return-from address-book-select nil))
  (let ((have-new (> (address-book-n-new book) 0))
        (have-tried (> (address-book-n-tried book) 0)))
    (when (and new-only (not have-new)) (return-from address-book-select nil))
    (unless (or have-new have-tried) (return-from address-book-select nil))
    (let ((search-tried (cond ((or new-only (not have-tried)) nil)
                              ((not have-new) t)
                              (t (zerop (random 2)))))
          (chance 1.0d0))
      ;; Core loops unbounded (guaranteed to terminate for a non-empty table as
      ;; chance grows each iteration). We cap the scan and, if it is ever
      ;; exhausted, fall back to a uniform random entry so a non-empty table
      ;; never yields NIL.
      (or
       (dotimes (_ +addrman-select-max-iterations+ nil)
         (let* ((table (if search-tried (address-book-tried-table book)
                           (address-book-new-table book)))
                (n-buckets (if search-tried +addrman-tried-bucket-count+
                               +addrman-new-bucket-count+))
                (bucket (random n-buckets))
                (start (random +addrman-bucket-size+)))
           (dotimes (i +addrman-bucket-size+)
             (let ((id (aref table (bucket-slot bucket (mod (+ start i)
                                                            +addrman-bucket-size+)))))
               (when (>= id 0)
                 (let ((pa (gethash id (address-book-info book))))
                   (when (and pa (< (random 1.0d0) (* chance (addr-info-chance pa now))))
                     (return-from address-book-select pa))))))
           (setf chance (* chance 1.2d0))))
       (let ((v (address-book-random-ids book)))
         (when (plusp (fill-pointer v))
           (gethash (aref v (random (fill-pointer v))) (address-book-info book))))))))

(defun select-dialable-address (book &key new-only (tries 20))
  "address-book-select restricted to AUTOMATIC-outbound-eligible addresses:
the network must be dialable by our transport stack (dialable-network-p —
config-aware: torv3 needs a Tor proxy, cjdns needs -cjdnsreachable, i2p is
never dialable until P4) AND reachable per -onlynet. Every automatic
selection path (outbound slots, feelers, block-relay slots) must go through
this, never raw address-book-select: post-BIP155 the book can hold records
nothing can connect to under the current config. Manual connections
(addnode) bypass addrman entirely and are unaffected. Returns a
peer-address or NIL after TRIES draws."
  (dotimes (_ tries nil)
    (let ((pa (address-book-select book :new-only new-only)))
      (when pa
        (let ((net (peer-address-network pa)))
          (when (and (dialable-network-p net) (reachable-network-p net))
            (return pa)))))))

(defun address-book-get-addr (book &key (max +addrman-getaddr-max+)
                                         (pct +addrman-getaddr-pct+) (now (ab-now)))
  "Return a random sample of non-terrible addresses (Core GetAddr). MAX 0 = no
count cap; PCT >= 100 = no percentage cap (used by getnodeaddresses count=0)."
  (let* ((v (address-book-random-ids book))
         (n (fill-pointer v))
         (limit (cond ((and (zerop max) (>= pct 100)) n)
                      ((zerop max) (floor (* n pct) 100))
                      ((>= pct 100) max)
                      (t (min max (floor (* n pct) 100)))))
         (ids (make-array n))
         (result '()))
    (dotimes (i n) (setf (aref ids i) (aref v i)))
    ;; Partial Fisher-Yates: sample without replacement until LIMIT kept.
    (loop for i from 0 below n
          while (< (length result) limit)
          do (let ((j (+ i (random (- n i)))))
               (rotatef (aref ids i) (aref ids j))
               (let ((pa (gethash (aref ids i) (address-book-info book))))
                 (when (and pa (not (addr-info-terrible-p pa now)))
                   (push pa result)))))
    (nreverse result)))

(defun select-tried-collision (book)
  "The INCUMBENT of a randomly chosen queued tried-table collision — the entry
a feeler should test before it is evicted (Core SelectTriedCollision_,
addrman.cpp:975-1000) — or NIL when nothing is queued.

This is the half that makes resolve-tried-collisions a test-before-evict:
without it no incumbent is ever probed, so the only branch that can fire for
a typical entry is the 40-minute \"unable to test\" fallback, and any
challenger evicts any incumbent we simply have not dialed lately. Feeling out
the incumbent instead lets its own success (address-book-good -> drop the
challenger) or failure (attempted, no success -> replace) decide."
  (let ((ids (address-book-tried-collisions book)))
    (when ids
      (let* ((id (nth (random (length ids)) ids))
             (pa (gethash id (address-book-info book))))
        (cond
          ((null pa)                              ; stale id: forget it
           (setf (address-book-tried-collisions book) (remove id ids))
           nil)
          (t
           (let* ((tb (tried-bucket book pa))
                  (tp (bucket-position book pa nil tb))
                  (old-id (aref (address-book-tried-table book) (bucket-slot tb tp))))
             (when (/= old-id -1)
               (gethash old-id (address-book-info book))))))))))

(defun resolve-tried-collisions (book &optional (now (ab-now)))
  "Resolve queued tried-table collisions (Core ResolveCollisions,
addrman.cpp:930-960): the incumbent's own evidence decides. Healthy (connected
within +addrman-replacement-seconds+) drops the challenger; attempted and
failed within that window promotes the challenger once the incumbent has had
+addrman-replacement-min-seconds+ to answer; and a collision that has gone
unresolved for +addrman-test-window-seconds+ promotes anyway, because we
evidently cannot test the incumbent. select-tried-collision is what produces
the attempt the second branch reads."
  (let ((remaining '()))
    (dolist (id (address-book-tried-collisions book))
      (let ((pa (gethash id (address-book-info book))))
        (cond
          ((null pa))                                              ; gone
          ((or (peer-address-in-tried pa) (zerop (peer-address-ref-count pa)))) ; resolved/invalid
          (t
           (let* ((tb (tried-bucket book pa))
                  (tp (bucket-position book pa nil tb))
                  (old-id (aref (address-book-tried-table book) (bucket-slot tb tp))))
             (if (= old-id -1)
                 (ab-make-tried book pa)                           ; slot freed
                 (let ((old (gethash old-id (address-book-info book))))
                   (cond
                     ((and old (< (- now (peer-address-last-success old))
                                  +addrman-replacement-seconds+)))  ; incumbent healthy -> drop
                     ;; Attempted (by the feeler) and did NOT succeed, or the
                     ;; healthy branch would have caught it: replace once the
                     ;; incumbent has had its 60 s to answer.
                     ((and old (< (- now (peer-address-last-attempt old))
                                  +addrman-replacement-seconds+))
                      (if (> (- now (peer-address-last-attempt old))
                             +addrman-replacement-min-seconds+)
                          (ab-make-tried book pa)
                          (push id remaining)))
                     ((> (- now (peer-address-last-success pa))
                         +addrman-test-window-seconds+)
                      (ab-make-tried book pa))                      ; untestable -> force
                     (t (push id remaining)))))))))) ; keep waiting
    (setf (address-book-tried-collisions book) remaining)))

;;;; Persistence (rename-to-.bak + fresh on mismatch, Core LoadAddrman)

(defparameter +addrman-magic+ #(#x41 #x44 #x52 #x4D)  ; "ADRM"
  "Magic bytes for the bucket-format peers.dat.")
(defconstant +addrman-format-version+ 4
  "v4 makes entries network-typed (BIP155): a net-id byte and a
variable-length address replace the fixed 16-byte IP, so torv3/i2p/cjdns
records persist. v2/v3 files still load — their 16-byte IPs migrate in
place (net derived from the mapped form) and the file is rewritten as v4
on the next save. v3 added each new-table entry's bucket numbers so
multi-source placements (ref-count > 1) survive restart; v2 files load
with each address reconstructed into the single bucket its source-group
implies.")

(defun %new-table-buckets (book)
  "Map id -> list of new-bucket numbers currently referencing it (one scan
over the new table; an address added from several source groups appears in
up to +addrman-new-buckets-per-address+ buckets)."
  (let ((m (make-hash-table))
        (nt (address-book-new-table book)))
    (dotimes (slot (length nt))
      (let ((id (aref nt slot)))
        (when (>= id 0)
          (push (floor slot +addrman-bucket-size+) (gethash id m)))))
    m))

(defun save-address-book (book path)
  "Persist BOOK to PATH (atomic write, CRC32-checked, bucket format)."
  (ensure-directories-exist path)
  (let* ((tmp-path (make-pathname
                    :defaults path
                    :type (concatenate 'string (or (pathname-type path) "dat") ".tmp")))
         (all-bytes
           (coerce
            (flexi-streams:with-output-to-sequence (s)
              (write-sequence +addrman-magic+ s)
              (bl.ser:write-uint32-le s +addrman-format-version+)
              (write-sequence (address-book-key book) s)
              (bl.ser:write-uint32-le s (address-book-n-new book))
              (bl.ser:write-uint32-le s (address-book-n-tried book))
              (bl.ser:write-uint32-le
               s (hash-table-count (address-book-info book)))
              (let ((id-buckets (%new-table-buckets book)))
              (maphash
               (lambda (id pa)
                 (write-byte (if (peer-address-in-tried pa) 1 0) s)
                 ;; v4: BIP155 net id + length-prefixed address bytes.
                 (write-byte (network-key-id (peer-address-network pa)) s)
                 (write-byte (length (peer-address-ip pa)) s)
                 (write-sequence (peer-address-ip pa) s)
                 (write-byte (ldb (byte 8 8) (peer-address-port pa)) s)
                 (write-byte (ldb (byte 8 0) (peer-address-port pa)) s)
                 (bl.ser:write-uint64-le s (peer-address-services pa))
                 (bl.ser:write-uint32-le s (peer-address-last-seen pa))
                 (bl.ser:write-uint32-le s (peer-address-last-attempt pa))
                 (bl.ser:write-uint32-le s (peer-address-last-success pa))
                 (bl.ser:write-uint32-le s (peer-address-n-attempts pa))
                 (let ((sg (or (peer-address-source-group pa) #())))
                   (write-byte (length sg) s)
                   (write-sequence sg s))
                 ;; v3: this entry's new-bucket numbers (empty for tried).
                 (let ((buckets (gethash id id-buckets)))
                   (write-byte (length buckets) s)
                   (dolist (b buckets)
                     (bl.ser:write-uint16-le s b))))
               (address-book-info book))))
            '(simple-array (unsigned-byte 8) (*)))))
    (with-open-file (out tmp-path :direction :output :if-exists :supersede
                                  :element-type '(unsigned-byte 8))
      (write-sequence all-bytes out)
      (write-sequence (bl.store:compute-crc32 all-bytes) out))
    (rename-file tmp-path path))
  (setf (address-book-dirty book) nil)
  t)

(defun ab-load-entry (book tried-p net ip port services last-seen last-attempt
                      last-success n-attempts source-group
                      &optional new-buckets)
  "Reconstruct one saved entry into BOOK, preserving its stats. NET is the
network keyword (v4 files), or NIL to derive IPv4/IPv6 from the 16-byte
mapped IP (v2/v3 migration). NEW-BUCKETS, when supplied (v3+ files), is the
saved list of new-bucket numbers — the entry is placed back into each,
restoring multi-source ref-counts. Without it (v2), the single bucket
implied by the source-group is used. Positions within buckets re-derive
from the address-book key, which load-address-book reads before any entry;
only bucket NUMBERS need persisting."
  (let ((pa (ab-create book ip port services last-seen
                       (if (plusp (length source-group)) source-group nil)
                       net)))
    (incf (address-book-n-new book))
    (setf (peer-address-last-attempt pa) last-attempt
          (peer-address-last-success pa) last-success
          (peer-address-n-attempts pa) n-attempts)
    ;; Place into new bucket(s); positions re-derive from the persisted key.
    (let ((buckets (or (remove-duplicates new-buckets)
                       (list (new-bucket book pa
                                         (or (peer-address-source-group pa)
                                             (peer-address-group pa)))))))
      (setf (peer-address-ref-count pa) 0)
      (dolist (b buckets)
        (let ((p (bucket-position book pa t b)))
          (ab-clear-new book b p)
          (incf (peer-address-ref-count pa))
          (setf (aref (address-book-new-table book) (bucket-slot b p))
                (peer-address-id pa)))))
    (when tried-p (ab-make-tried book pa))))

(defun load-address-book (book path)
  "Load BOOK from PATH. On a missing/corrupt/incompatible file, rename it to
PATH.bak and leave BOOK empty (Bitcoin Core LoadAddrman). Returns T if entries
were loaded, NIL otherwise."
  ;; ⚠️ Core reports a count even when there is nothing to load: DeserializeFileDB
  ;; throwing DbNotFoundError leaves an empty addrman and the line still says
  ;; "Loaded 0 addresses from peers.dat" (addrdb.cpp:207-211). A fresh datadir is
  ;; the ordinary case and feature_addrman.py greps for exactly that. Same shape
  ;; as the banlist gap: absence is a RESULT, not a reason to say nothing.
  (unless (probe-file path)
    (bl:log-info "Loaded 0 addresses from peers.dat")
    (return-from load-address-book nil))
  (flet ((backup ()
           (ignore-errors
            (rename-file path (make-pathname
                               :defaults path
                               :type (concatenate 'string
                                                  (or (pathname-type path) "dat") ".bak"))))))
    (handler-case
        (with-open-file (in path :direction :input :element-type '(unsigned-byte 8))
          (let* ((file-size (file-length in))
                 (data (make-array file-size :element-type '(unsigned-byte 8))))
            (read-sequence data in)
            (when (< file-size 48)              ; magic+ver+key+counts minimum
              (backup) (return-from load-address-book nil))
            (let ((payload (subseq data 0 (- file-size 4)))
                  (stored-crc (subseq data (- file-size 4))))
              (unless (equalp (bl.store:compute-crc32 payload) stored-crc)
                (bl:log-warn "peers.dat CRC32 mismatch; backing up to .bak")
                (backup) (return-from load-address-book nil))
              (flexi-streams:with-input-from-sequence (s payload)
                (let ((magic (make-array 4 :element-type '(unsigned-byte 8))))
                  (read-sequence magic s)
                  (unless (equalp magic +addrman-magic+)
                    (bl:log-warn "peers.dat unknown format; backing up to .bak")
                    (backup) (return-from load-address-book nil)))
                (let ((version (bl.ser:read-uint32-le s)))
                  (unless (member version '(2 3 4))
                    (bl:log-warn "peers.dat version ~D unsupported; backing up to .bak"
                                           version)
                    (backup) (return-from load-address-book nil))
                (read-sequence (address-book-key book) s)
                (bl.ser:read-uint32-le s)  ; n-new (recomputed)
                (bl.ser:read-uint32-le s)  ; n-tried (recomputed)
                (let ((count (bl.ser:read-uint32-le s)))
                  (dotimes (i count)
                    (let* ((tried-p (= 1 (read-byte s)))
                           ;; v4: net-id + length-prefixed address; v2/v3:
                           ;; fixed 16-byte IP, net derived (migrate-on-load;
                           ;; the next save rewrites the file as v4).
                           (net (when (>= version 4)
                                  (or (key-id-network (read-byte s))
                                      (error "peers.dat: unknown network id"))))
                           (ip-len (if (>= version 4) (read-byte s) 16))
                           (ip (make-array ip-len :element-type '(unsigned-byte 8))))
                      (read-sequence ip s)
                      (let* ((port (logior (ash (read-byte s) 8) (read-byte s)))
                             (services (bl.ser:read-uint64-le s))
                             (last-seen (bl.ser:read-uint32-le s))
                             (last-attempt (bl.ser:read-uint32-le s))
                             (last-success (bl.ser:read-uint32-le s))
                             (n-attempts (bl.ser:read-uint32-le s))
                             (sg-len (read-byte s))
                             (sg (make-array sg-len :element-type '(unsigned-byte 8))))
                        (read-sequence sg s)
                        (let ((new-buckets
                                (when (>= version 3)
                                  (loop repeat (read-byte s)
                                        collect (bl.ser:read-uint16-le s)))))
                          (ab-load-entry book tried-p net ip port services last-seen
                                         last-attempt last-success n-attempts sg
                                         new-buckets)))))
                  ;; ⚠️ Core's wording exactly: "Loaded %i addresses from
                  ;; peers.dat" (addrdb.cpp:207). Core's tests match this as a
                  ;; SUBSTRING, and our extra word "peer" broke the match — the
                  ;; count is the same, the sentence was not. The tried count
                  ;; moves to its own line rather than being dropped: it is
                  ;; genuinely useful and Core simply does not report it.
                  (bl:log-info "Loaded ~D addresses from peers.dat"
                                         (address-book-count book))
                  (bl:log-cat "net" "  (~D of them tried)"
                                         (address-book-n-tried book))
                  (> count 0)))))))
      (error (c)
        (bl:log-warn "Failed to load peers.dat (~A); backing up to .bak" c)
        (backup)
        nil))))
