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

(defvar *deterministic-addrman* nil
  "Core's `-test=addrman' (HasTestOption(args, \"addrman\"), addrdb.cpp:199):
an address book made while this is true is keyed by uint256{1} instead of a
random secret (AddrManImpl's nKey, addrman.cpp:108-110), so its bucket
placement is reproducible -- Core's functional tests assert exact
bucket/position pairs and grind addresses that collide under that key
(rpc_net.py:343-397, :471-600). A test-only option: a predictable key lets
anyone target our buckets.")

(defun initial-addrman-key ()
  "The key a new address book is made with: uint256{1} -- a 1 in the first,
least significant byte -- under *DETERMINISTIC-ADDRMAN*, a fresh random
secret otherwise (Core AddrManImpl, addrman.cpp:108-110)."
  (if *deterministic-addrman*
      (let ((k (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
        (setf (aref k 0) 1)
        k)
      (make-addrman-key)))

(defun random-siphash-key ()
  "A fresh per-process SipHash key as (K0 . K1), two 64-bit words drawn from
the OS CSPRNG -- Core's `CSipHasher(m_k0, m_k1)' salts, each drawn once from a
FastRandomContext at start-up (txrequest.cpp:107-110, net.cpp nSeed0/nSeed1).

Drawn by a FUNCTION, never a toplevel initform: an initform is evaluated at
LOAD time, so it would be frozen into a saved image and every process started
from that binary would share one 'per-process secret'."
  (let ((k (make-addrman-key)))
    (flet ((word (offset)
             (loop for i below 8 sum (ash (aref k (+ offset i)) (* 8 i)))))
      (cons (word 0) (word 8)))))

(defun make-bucket-table (n-buckets)
  "A flat fixnum table for N-BUCKETS × bucket-size, all slots empty (-1)."
  (make-array (* n-buckets +addrman-bucket-size+)
              :element-type 'fixnum :initial-element -1))

(defstruct address-book
  "Bitcoin Core-style address manager: new/tried buckets keyed by a per-node
secret, source-group spreading, and test-before-evict tried promotion."
  (key (initial-addrman-key) :type (simple-array (unsigned-byte 8) (32)))
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
PARTS (byte vectors). Bitcoin Core's HashWriter().GetCheapHash() (hash.h),
byte-compatible when PARTS are serialized as Core's are: with a deterministic
key (-test=addrman) Core's functional tests assert exact bucket positions."
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
    (let ((asn (and *asmap* (= (length ip) 16) (asmap-asn ip net))))
      (when asn
        ;; Core prefixes NET_IPV6 -- for IPv4 too, so an IPv4 and an IPv6
        ;; address in one AS share a group -- and then the ASN least
        ;; significant byte first (netgroup.cpp:24-31).
        (return-from net-group-key
          (group 2
                 (ldb (byte 8 0) asn) (ldb (byte 8 8) asn)
                 (ldb (byte 8 16) asn) (ldb (byte 8 24) asn)))))
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

(defun address-valid-p (ip &optional net)
  "Core CNetAddr::IsValid (netaddress.cpp:424-451) for a 16-byte IP address:
not the unspecified IPv6 address, not RFC3849 documentation (2001:db8::/32),
not Core's internal range (fd6b:88c0:8724::/48, what a legacy address of a
non-IP network decodes to), and for IPv4 neither INADDR_ANY nor INADDR_NONE.
Weaker than routability on purpose: getpeerinfo's addrlocal is reported
whenever the peer's report of our address is merely VALID
(CNode::CopyStats, net.cpp:652-654), loopback included."
  (let ((net (or net (and (= (length ip) 16) (ip-network ip)))))
    (and (member net '(:ipv4 :ipv6))
         (= (length ip) 16)
         (not (every #'zerop ip))
         (not (%ipv6-prefix-p ip '(#x20 #x01 #x0D #xB8)))
         (not (%ipv6-prefix-p ip '(#xFD #x6B #x88 #xC0 #x87 #x24)))
         (or (not (eq net :ipv4))
             (let ((v4 (subseq ip 12)))
               (not (or (every #'zerop v4)
                        (every (lambda (b) (= b 255)) v4))))))))

(defun %ipv4-unroutable-p (ip)
  "The IPv4 exclusions Core's IsRoutable applies (netaddress.cpp:462-465), which
ADDRESS-ROUTABLE-P deliberately does not: IsLocal (127.0.0.0/8 and 0.0.0.0/8,
netaddress.cpp:341-347), RFC1918 private (10/8, 172.16/12, 192.168/16),
RFC2544 benchmarking (198.18/15), RFC3927 link-local (169.254/16), RFC5737
documentation (192.0.2/24, 198.51.100/24, 203.0.113/24) and RFC6598 shared
address space (100.64/10).

IP is either the four octets or the 16-byte IPv4-mapped form
PARSE-NETWORK-ADDRESS hands back for :IPV4 (::ffff:a.b.c.d), so the octets are
read from the END. Reading index 0 of the mapped form sees a zero byte, which
is IsLocal, and calls every IPv4 address unroutable."
  (let* ((o (- (length ip) 4))
         (a (aref ip o)) (b (aref ip (+ o 1))) (c (aref ip (+ o 2))))
    (or (member a '(0 127))                              ; IsLocal
        (= a 10)                                         ; RFC1918
        (and (= a 172) (<= 16 b 31))                     ; RFC1918
        (and (= a 192) (= b 168))                        ; RFC1918
        (and (= a 198) (member b '(18 19)))              ; RFC2544
        (and (= a 169) (= b 254))                        ; RFC3927
        (and (= a 192) (= b 0) (= c 2))                  ; RFC5737
        (and (= a 198) (= b 51) (= c 100))               ; RFC5737
        (and (= a 203) (= b 0) (= c 113))                ; RFC5737
        (and (= a 100) (<= 64 b 127)))))                 ; RFC6598

(defun address-publicly-routable-p (ip &optional net)
  "Core IsRoutable in full (netaddress.cpp:462-465) -- WITHOUT the regtest
carve-out ADDRESS-ROUTABLE-P makes for IPv4 private and documentation ranges.

Two predicates because they answer two questions. Whether to STORE and dial an
address is the one addrman asks, and this tree keeps 10/8 and 198.51.100/24
dialable on purpose so private deployments and the addrman fixtures work.
Whether an address has a publicly routable NETWORK is Core's GetNetClass
(netaddress.cpp:920-926), which returns NET_UNROUTABLE for every range above --
so getpeerinfo's `network' field reads `not_publicly_routable' for a loopback
peer, which is what rpc_net.py:148 asserts for a connection from 127.0.0.1.
Asking the dial predicate there answered `ipv4'."
  (let ((net (or net (and (= (length ip) 16) (ip-network ip)))))
    (and (address-routable-p ip net)
         (not (and (eq net :ipv4) (%ipv4-unroutable-p ip))))))

(defun peer-address-key (pa)
  "The addrman map key for record PA (network-typed)."
  (make-address-key (peer-address-ip pa) (peer-address-port pa)
                    (peer-address-network pa)))

(defun peer-address-group (pa)
  "The netgroup key for record PA (network-typed)."
  (net-group-key (peer-address-ip pa) (peer-address-network pa)))

(defun %ser-vector (bytes)
  "BYTES as Core serializes a std::vector<unsigned char> into a HashWriter:
a CompactSize length, then the bytes (serialize.h). Every group and address
key below is such a vector, so the hash commits to its length too."
  (let ((n (length bytes)))
    (concatenate '(simple-array (unsigned-byte 8) (*))
                 (cond ((< n 253) (vector n))
                       (t (vector 253 (ldb (byte 8 0) n) (ldb (byte 8 8) n))))
                 bytes)))

(defun peer-address-hash-key (pa)
  "Core CService::GetKey for PA (netaddress.cpp:895-901) as the vector the
bucket hashes serialize: GetAddrBytes -- the 16-byte V1 form for IPv4/IPv6,
the raw address for every other network -- then the port, most significant
byte first. PEER-ADDRESS-KEY is the same with our network-id byte in front,
which Core's key does not have."
  (%ser-vector (subseq (peer-address-key pa) 1)))

(defun tried-bucket (book pa)
  "Tried-table bucket for PA (Core AddrInfo::GetTriedBucket, addrman.cpp:48-53):
every input serialized as Core's HashWriter does, so a deterministic addrman
(-test=addrman) places an address where Core's does."
  (let* ((key (address-book-key book))
         (akey (peer-address-hash-key pa))
         (group (%ser-vector (peer-address-group pa)))
         (h1 (addrman-cheap-hash key akey))
         (h2 (addrman-cheap-hash
              key group (int-to-le-bytes
                         (mod h1 +addrman-tried-buckets-per-group+) 8))))
    (mod h2 +addrman-tried-bucket-count+)))

(defun new-bucket (book pa source-group)
  "New-table bucket for PA learned from SOURCE-GROUP (Core
AddrInfo::GetNewBucket, addrman.cpp:55-61), serialized as Core's HashWriter."
  (let* ((key (address-book-key book))
         (group (%ser-vector (peer-address-group pa)))
         (source-group (%ser-vector source-group))
         (h1 (addrman-cheap-hash key group source-group))
         (h2 (addrman-cheap-hash
              key source-group (int-to-le-bytes
                                (mod h1 +addrman-new-buckets-per-source-group+) 8))))
    (mod h2 +addrman-new-bucket-count+)))

(defun bucket-position-akey (book akey new-p bucket)
  "Slot within BUCKET for the address whose serialized Core key is AKEY
(PEER-ADDRESS-HASH-KEY; Core AddrInfo::GetBucketPosition, addrman.cpp:63-67).
Split out so a scan over all buckets (MakeTried) computes AKEY once instead of
per bucket."
  (let ((marker (make-array 1 :element-type '(unsigned-byte 8)
                              :initial-element (if new-p 78 75))))  ; 'N' / 'K'
    (mod (addrman-cheap-hash (address-book-key book) marker
                             (int-to-le-bytes bucket 4) akey)
         +addrman-bucket-size+)))

(defun bucket-position (book pa new-p bucket)
  "Slot within BUCKET for PA (Core GetBucketPosition). Depends only on the
address + bucket + table, so MakeTried can scan all buckets at this position."
  (bucket-position-akey book (peer-address-hash-key pa) new-p bucket))

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
          (>= (peer-address-n-attempts pa) +addrman-max-failures+)) t)))

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
        (akey (peer-address-hash-key pa)))
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

(defun address-book-entries (book from-tried)
  "Every entry of BOOK's TRIED table (FROM-TRIED true) or NEW table, as a list
of (bucket position record) in bucket-major, position-minor order -- Core
AddrManImpl::GetEntries_ (addrman.cpp:853-875), the walk getrawaddrman reports.
A new-table entry referenced from several buckets appears once per bucket, as
in Core, which walks the table and not the records."
  (let ((table (if from-tried
                   (address-book-tried-table book)
                   (address-book-new-table book)))
        (info (address-book-info book))
        (entries '()))
    (dotimes (bucket (if from-tried
                         +addrman-tried-bucket-count+
                         +addrman-new-bucket-count+))
      (dotimes (position +addrman-bucket-size+)
        (let ((id (aref table (bucket-slot bucket position))))
          (when (>= id 0)
            (push (list bucket position (gethash id info)) entries)))))
    (nreverse entries)))

(defun address-net-class (net ip)
  "Core CNetAddr::GetNetClass (netaddress.cpp:674-690) for an address on
network NET with bytes IP: :unroutable when it is not publicly routable, :ipv4
for an IPv6 address carrying an IPv4 one (6to4, Teredo, NAT64), else NET.
NET_INTERNAL has no counterpart here."
  (let ((net (or net (and (= (length ip) 16) (ip-network ip)))))
    (cond ((not (address-publicly-routable-p ip net)) :unroutable)
          ((and (eq net :ipv6) (ipv6-linked-ipv4-group ip)) :ipv4)
          (t net))))

(defun address-book-empty-networks (book networks)
  "The members of NETWORKS for which BOOK holds no address (Core
CConnman::GetReachableEmptyNetworks over g_reachable_nets, net.cpp:2490-2501,
whose per-network test is AddrMan::Size(net) == 0). Walks the records only
until every network has been seen once."
  (let ((empty (copy-list networks)))
    (when (plusp (address-book-count book))
      (block walk
        (maphash (lambda (id pa)
                   (declare (ignore id))
                   (setf empty (delete (peer-address-network pa) empty))
                   (when (null empty) (return-from walk)))
                 (address-book-info book))))
    empty))

(defun address-book-lookup (book ip port &optional net)
  "Return the record for IP:PORT on network NET (NIL derives IPv4/IPv6 from
the 16-byte form), or NIL (Core Find)."
  (ab-find book ip port net))

(defun peer-address-addr-port-string (pa)
  "PA as Core's ToStringAddrPort prints it: `ip:port', an IPv6 address in
brackets (netaddress.cpp CService::ToStringAddrPort)."
  (let ((host (peer-address-string pa)))
    (format nil (if (eq (peer-address-network pa) :ipv6) "[~A]:~D" "~A:~D")
            host (peer-address-port pa))))

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
  (maybe-check-address-book book)
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
            (setf (peer-address-source info) (peer-address-source pa))
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
                (setf (aref nt slot) id)
                ;; Core's line (addrman.cpp:615-616); p2p_invalid_messages.py
                ;; :236 waits for the address in it. No -asmap here, so no
                ;; `mapped to AS' part.
                (bl.log:log-cat "addrman" "Added ~A to new[~D][~D]"
                                (peer-address-addr-port-string info) bucket pos))
              (when (zerop (peer-address-ref-count info))
                (ab-delete book id))))
        (setf (address-book-dirty book) t)
        insert))))

(defun address-book-good (book ip port &optional (now (ab-now)) net)
  "Record a successful connection to IP:PORT and promote it new -> tried
(test-before-evict). Returns T if promoted, NIL if queued for collision test."
  (maybe-check-address-book book)
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
  (maybe-check-address-book book)
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
  (maybe-check-address-book book)
  (let ((pa (ab-find book ip port net)))
    (when (and pa (> (- now (peer-address-last-seen pa)) 1200))
      (setf (peer-address-last-seen pa) now))))

(defun address-book-select (book &key new-only (now (ab-now)))
  "Choose an address for a new outbound connection (Core Select). Returns a
peer-address or NIL. Picks a random bucket+position, biased toward higher-quality
entries via GetChance; alternates new/tried roughly 50/50 when both are present."
  (maybe-check-address-book book)
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
never dialable until P4), reachable per -onlynet, and — for IPv4/IPv6 — not on
a port Core refuses to dial (bad-port-p). Every automatic selection path
(outbound slots, feelers, block-relay slots) must go through this, never raw
address-book-select: post-BIP155 the book can hold records nothing can connect
to under the current config, and any peer may gossip a record naming a third
party's SSH or SMTP port. Manual connections (addnode) bypass addrman entirely
and are unaffected, which is Core's split too — IsBadPort is applied inside
ThreadOpenConnections (net.cpp:2854), not in Select and not on the paths that
name a destination. Returns a peer-address or NIL after TRIES draws."
  (dotimes (_ tries nil)
    (let ((pa (address-book-select book :new-only new-only)))
      (when pa
        (let ((net (peer-address-network pa)))
          (when (and (dialable-network-p net)
                     (reachable-network-p net)
                     ;; Core applies IsBadPort to IPv4/IPv6 only: a port
                     ;; number means nothing for an onion or I2P destination.
                     (not (and (member net '(:ipv4 :ipv6))
                               (bad-port-p (peer-address-port pa)))))
            (return pa)))))))

(defun address-book-get-addr (book &key (max +addrman-getaddr-max+)
                                         (pct +addrman-getaddr-pct+) (now (ab-now))
                                         network)
  "Return a random sample of non-terrible addresses (Core GetAddr). MAX 0 = no
count cap; PCT >= 100 = no percentage cap (used by getnodeaddresses count=0).
NETWORK, when given, keeps only addresses on that network; the cap is still
computed over the whole table, as Core's GetAddr_ does
(addrman.cpp:812-848)."
  (maybe-check-address-book book)
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
                 (when (and pa
                            (or (null network)
                                (eq network (peer-address-network pa)))
                            (not (addr-info-terrible-p pa now)))
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
  (maybe-check-address-book book)
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
  (maybe-check-address-book book)
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
