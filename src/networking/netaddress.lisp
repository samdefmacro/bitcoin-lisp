(in-package #:bitcoin-lisp.networking)

;;; Network-typed addresses: human-readable codecs and reachability.
;;;
;;; BIP155 made non-IP networks (TORv3 onion, I2P, CJDNS) first-class in addr
;;; gossip. This file holds everything string- and policy-shaped about them:
;;; the base32 codec, onion/i2p address parsing and formatting (Bitcoin Core
;;; netaddress.cpp:185-261), the network reachability set (-onlynet), and the
;;; dialable-network predicate that keeps the P1 address layer from ever
;;; trying to raw-TCP a 32-byte onion pubkey.

;;;; Network keywords

(defparameter +bip155-networks+ '(:ipv4 :ipv6 :torv3 :i2p :cjdns)
  "All networks representable in our address layer (BIP155 ids 1,2,4,5,6).")

(defun network-address-length (network)
  "Required address byte length for NETWORK, in OUR internal representation
(IPv4 is kept 16-byte IPv4-mapped, unlike Core's 4-byte form)."
  (ecase network
    ((:ipv4 :ipv6 :cjdns) 16)
    ((:torv3 :i2p) 32)))

;;;; Reachability / dialability

(defvar *reachable-networks* '(:ipv4 :ipv6)
  "Networks automatic outbound selection (and address storage) may use.
Set at startup from -onlynet/-proxy/-cjdnsreachable by apply-config-globals
(mirrors Core's g_reachable_nets: init.cpp:1529-1551 rebuilds it from
-onlynet; onion stays only with a Tor proxy, I2P only with -i2psam — which
we do not support yet — and CJDNS only with -cjdnsreachable). Manual
connections (addnode/connect) are never restricted by this set.")

(defvar *cjdns-reachable* nil
  "T when -cjdnsreachable is set: the local cjdroute TUN exists, so :cjdns
addresses are dialable (plain TCP into fc00::/8, dialable-network-p) and
apply-config-globals admits :cjdns to *reachable-networks* — which in turn
enables the fc00::/8 ingress retag (maybe-flip-ipv6-to-cjdns).")

(defvar *onlynet-networks* nil
  "The raw -onlynet restriction as a list of network keywords, NIL when no
-onlynet was given. Set by apply-config-globals. *reachable-networks* is the
DERIVED set (restriction minus transport-gated nets); this keeps the user's
stated restriction so a transport that comes up later — the torcontrol
GETINFO-discovered onion proxy (Core get_socks_cb, torcontrol.cpp:412-426) —
can re-admit its network exactly when -onlynet allows it.")

(defun reachable-network-p (network)
  "T if NETWORK is in the reachable set (Core g_reachable_nets.Contains)."
  (and (member network *reachable-networks*) t))

(defun admit-reachable-network (network)
  "Admit NETWORK to the reachable set iff the user's -onlynet restriction
allows it — the re-admission rule for a transport that arrives after startup
(Core get_socks_cb's g_reachable_nets.Add gate, torcontrol.cpp:412-426).
Lives here, next to the globals it manipulates, so each late transport
(torcontrol today, I2P SAM later) shares one copy of the rule."
  (when (or (null *onlynet-networks*)
            (member network *onlynet-networks*))
    (pushnew network *reachable-networks*)))

(defun split-host-port (spec default-port)
  "Split a \"host[:port]\" SPEC into (VALUES host port), PORT defaulting to
DEFAULT-PORT. Accepts \"[ipv6]:port\" / \"[ipv6]\"; a trailing :port is only
honored when it is all digits after a single colon, so a bare IPv6 literal is
host-only. The one splitter behind the networking layer's host:port surfaces
(-torcontrol, GETINFO socks locations; -proxy/-onion and addnode specs
predate it and keep their own copies for now)."
  (cond
    ((and (plusp (length spec)) (char= (char spec 0) #\[))
     (let ((close (position #\] spec)))
       (if (null close)
           (values spec default-port)
           (let ((host (subseq spec 1 close))
                 (rest (subseq spec (1+ close))))
             (if (and (> (length rest) 1) (char= (char rest 0) #\:)
                      (every #'digit-char-p (subseq rest 1)))
                 (values host (parse-integer rest :start 1))
                 (values host default-port))))))
    (t
     (let ((colon (position #\: spec :from-end t)))
       (if (and colon
                (< (1+ colon) (length spec))
                (every #'digit-char-p (subseq spec (1+ colon)))
                ;; A single colon => host:port; multiple => bare IPv6.
                (= colon (position #\: spec)))
           (values (subseq spec 0 colon) (parse-integer spec :start (1+ colon)))
           (values spec default-port))))))

(defun dialable-network-p (network)
  "T if our transport stack can actually open a connection to NETWORK under
the CURRENT configuration (the Core equivalent: whether ConnectNode has a
route to the target — a proxy for its network, or plain TCP):
  - :ipv4/:ipv6 — always (direct TCP, or through -proxy);
  - :torv3 — only with a Tor-capable SOCKS5 proxy (*onion-proxy*, i.e. -onion
    defaulting to -proxy; -onion=0 clears it even when -proxy is set,
    init.cpp:1766-1780);
  - :cjdns — only with -cjdnsreachable (dialing is ordinary TCP into the
    local cjdroute TUN's fc00::/8);
  - :i2p — never (the SAM transport is P4).
Automatic outbound selection, feelers, block-relay slot filling and anchor
redials MUST filter through this predicate (select-dialable-address adds the
-onlynet reachability check on top): raw-TCP-ing a 32-byte onion key is a
bug. Manual connections (addnode/connect) hit the same transport gate at
dial time via proxy-for-target."
  (case network
    ((:ipv4 :ipv6) t)
    (:torv3 (and *onion-proxy* t))
    (:cjdns *cjdns-reachable*)
    (t nil)))

(defun maybe-flip-ipv6-to-cjdns (network bytes)
  "Retag an :ipv6 address whose first byte is 0xFC as :cjdns when the CJDNS
network is reachable — Core's exact gate is g_reachable_nets.Contains(NET_CJDNS)
(MaybeFlipIPv6toCJDNS, netbase.cpp:942-949), i.e. -cjdnsreachable minus any
-onlynet exclusion. Applied at ingress points where addresses arrive UNTYPED
(string parsing — and through it inbound socket addresses, whose host strings
are parsed wherever they are used in typed form) — addrv2 gossip carries the
CJDNS tag itself, and an fc00::/8 that arrives as plain :ipv6 in v1 addr
gossip stays :ipv6 and is dropped as unroutable, both as in Core. Returns
the (possibly new) network keyword."
  (if (and (eq network :ipv6)
           (reachable-network-p :cjdns)
           (plusp (length bytes))
           (= (aref bytes 0) #xFC))
      :cjdns
      network))

(defun proxy-for-target (host)
  "The SOCKS5 proxy for an outbound dial to HOST (a peer-address string or
hostname) — Core ConnectNode's per-target-network proxy pick (net.cpp:449
GetProxy(target network), table built by init.cpp:1696-1801). Returns
(VALUES PROXY REFUSAL):
  - a .onion target uses the Tor proxy (*onion-proxy*: -onion, defaulting to
    -proxy). With none configured, REFUSAL (a string) says why the dial must
    not happen at all — falling through to a raw dial would leak the onion
    name to local DNS;
  - a .b32.i2p target is always refused (no SAM transport until P4);
  - everything else — IPv4/IPv6/CJDNS literals and hostnames — uses *proxy*
    (NIL = direct dial). Matches Core, where an unsuffixed -proxy covers
    IPv4/IPv6/CJDNS/name lookups (init.cpp:1735) and CJDNS without a proxy
    is ordinary TCP to the fc00::/8 address."
  (cond ((parse-onion-address host)
         (if *onion-proxy*
             (values *onion-proxy* nil)
             (values nil "onion peer but no Tor proxy is configured (-proxy/-onion)")))
        ((parse-i2p-address host)
         (values nil "I2P peers are not dialable (no SAM support)"))
        (t (values *proxy* nil))))

;;;; Base32 (Core util/strencodings.cpp:144-200)
;;;
;;; RFC4648 base32 with Core's lowercase alphabet; decoding is
;;; case-insensitive and enforces that leftover bits are zero
;;; (ConvertBits<5,8,false>), so a truncated/garbage tail is rejected.

(defparameter +base32-alphabet+ "abcdefghijklmnopqrstuvwxyz234567")

(defun base32-encode (bytes &key pad)
  "Encode BYTES as lowercase base32. With PAD, append '=' to a multiple of 8."
  (let ((out (make-string-output-stream))
        (acc 0)
        (bits 0))
    (loop for b across bytes
          do (setf acc (logior (ash acc 8) b))
             (incf bits 8)
             (loop while (>= bits 5)
                   do (decf bits 5)
                      (write-char (char +base32-alphabet+ (ldb (byte 5 bits) acc))
                                  out)))
    (when (plusp bits)
      (write-char (char +base32-alphabet+
                        (logand (ash acc (- 5 bits)) #x1F))
                  out))
    (let ((s (get-output-stream-string out)))
      (if pad
          (concatenate 'string s
                       (make-string (mod (- (length s)) 8) :initial-element #\=))
          s))))

(defun %base32-char-value (ch)
  "Decode table entry for CH: 0-31, or NIL. Case-insensitive, like Core's
decode32_table (strencodings.cpp:166-180)."
  (cond ((char<= #\a ch #\z) (- (char-code ch) (char-code #\a)))
        ((char<= #\A ch #\Z) (- (char-code ch) (char-code #\A)))
        ((char<= #\2 ch #\7) (+ 26 (- (char-code ch) (char-code #\2))))
        (t nil)))

(defun base32-decode (string)
  "Decode base32 STRING (Core DecodeBase32). Requires a length that is a
multiple of 8; permits 1, 3, 4 or 6 trailing '=' padding characters; the
final partial byte's leftover bits must be zero. Returns a byte vector,
or NIL on any invalid input."
  (unless (zerop (mod (length string) 8))
    (return-from base32-decode nil))
  (let ((end (length string)))
    ;; Strip padding exactly like Core: '=', then '==', then '=', then '=='.
    (flet ((strip (suffix)
             (let ((n (length suffix)))
               (when (and (>= end n)
                          (string= suffix string :start2 (- end n) :end2 end))
                 (decf end n)))))
      (strip "=") (strip "==") (strip "=") (strip "=="))
    (let ((out (make-array (floor (* end 5) 8) :element-type '(unsigned-byte 8)
                                               :fill-pointer 0))
          (acc 0)
          (bits 0))
      (dotimes (i end)
        (let ((v (%base32-char-value (char string i))))
          (unless v (return-from base32-decode nil))
          (setf acc (logior (ash acc 5) v))
          (incf bits 5)
          (when (>= bits 8)
            (decf bits 8)
            (vector-push (ldb (byte 8 bits) acc) out))))
      ;; ConvertBits<5,8,false>: leftover bits must all be zero.
      (unless (zerop (ldb (byte bits 0) acc))
        (return-from base32-decode nil))
      (coerce out '(simple-array (unsigned-byte 8) (*))))))

;;;; TORv3 onion codec (netaddress.cpp:185-261)
;;;
;;; onion_address = base32(PUBKEY(32) | CHECKSUM(2) | VERSION(1=0x03)) + ".onion"
;;; CHECKSUM = SHA3-256(".onion checksum" | PUBKEY | VERSION)[0:2]

(defconstant +torv3-version-byte+ 3)

(defun %torv3-checksum (pubkey)
  "First 2 bytes of SHA3-256(\".onion checksum\" || PUBKEY || 0x03)."
  (let ((material (make-array (+ 15 32 1) :element-type '(unsigned-byte 8))))
    (replace material (map 'vector #'char-code ".onion checksum"))
    (replace material pubkey :start1 15)
    (setf (aref material 47) +torv3-version-byte+)
    (subseq (bitcoin-lisp.crypto:sha3-256 material) 0 2)))

(defun onion-address-string (pubkey)
  "Format a 32-byte TORv3 ed25519 PUBKEY as its .onion address string
(Core OnionToString): 56 lowercase base32 chars + \".onion\"."
  (let ((payload (make-array 35 :element-type '(unsigned-byte 8))))
    (replace payload pubkey)
    (replace payload (%torv3-checksum pubkey) :start1 32)
    (setf (aref payload 34) +torv3-version-byte+)
    (concatenate 'string (base32-encode payload) ".onion")))

(defun parse-onion-address (string)
  "Parse a TORv3 .onion address STRING into its 32-byte pubkey, or NIL.
Strict, mirroring Core SetTor (netaddress.cpp:231-261): lowercase \".onion\"
suffix, base32 body decoding to exactly 35 bytes (case-insensitive), version
byte 0x03, and a matching SHA3-256 checksum. TORv2 (16-char) addresses
decode to the wrong length and are rejected."
  (let ((suffix ".onion"))
    (when (and (> (length string) (length suffix))
               ;; Core's ends_with is case-sensitive for the suffix.
               (string= suffix string :start2 (- (length string) (length suffix))))
      (let ((decoded (base32-decode
                      (subseq string 0 (- (length string) (length suffix))))))
        (when (and decoded
                   (= (length decoded) 35)
                   (= (aref decoded 34) +torv3-version-byte+))
          (let ((pubkey (subseq decoded 0 32)))
            (when (equalp (%torv3-checksum pubkey) (subseq decoded 32 34))
              pubkey)))))))

;;;; I2P codec (netaddress.cpp:262-292)
;;;
;;; address = base32(32-byte SHA256 destination hash), unpadded -> exactly
;;; 52 chars, + ".b32.i2p" (suffix matched case-insensitively).

(defun i2p-address-string (hash)
  "Format a 32-byte I2P destination HASH as base32 + \".b32.i2p\" (52+8 chars)."
  (concatenate 'string (base32-encode hash) ".b32.i2p"))

(defun parse-i2p-address (string)
  "Parse an I2P .b32.i2p address STRING into its 32-byte hash, or NIL.
Mirrors Core SetI2P: total length exactly 60 (52 base32 chars + suffix),
case-insensitive suffix, decode with \"====\" padding to exactly 32 bytes.
Explicit '=' inside the body (e.g. a 51-char hash + '=') decodes short and
is rejected; 56-char (encrypted-leaseset) forms are rejected by length."
  (let ((suffix ".b32.i2p"))
    (when (and (= (length string) (+ 52 (length suffix)))
               (string-equal suffix string :start2 52))
      (let ((decoded (base32-decode
                      (concatenate 'string (subseq string 0 52) "===="))))
        (when (and decoded (= (length decoded) 32))
          decoded)))))

;;;; String <-> typed address (all networks)

(defun network-address-to-string (network bytes)
  "Human-readable string for a typed address (Core CNetAddr::ToStringAddr):
IPv4 dotted quad, IPv6/CJDNS hex groups, .onion, or .b32.i2p."
  (ecase network
    ((:ipv4 :ipv6 :cjdns) (ip-bytes-to-string bytes))
    (:torv3 (onion-address-string bytes))
    (:i2p (i2p-address-string bytes))))

(defun parse-network-address (string)
  "Parse an address STRING of any supported network. Returns
(VALUES network bytes) — :ipv4 as 16-byte mapped IPv6, :ipv6/:cjdns as 16
bytes, :torv3/:i2p as their 32-byte forms — or NIL if unparseable (e.g. a
hostname). IP parsing (dotted quad and every IPv6 text form, including
::ffff:1.2.3.4) is string-to-ip-bytes (peerdb.lisp). An fc00::/8 IPv6 is
retagged :cjdns when CJDNS is reachable, this being a string-ingress point
(Core applies MaybeFlipIPv6toCJDNS to Lookup results, netbase.cpp:825)."
  (let ((onion (parse-onion-address string)))
    (when onion (return-from parse-network-address (values :torv3 onion))))
  (let ((i2p (parse-i2p-address string)))
    (when i2p (return-from parse-network-address (values :i2p i2p))))
  (let ((ip (string-to-ip-bytes string)))
    (when ip
      (values (maybe-flip-ipv6-to-cjdns (ip-network ip) ip) ip))))

;;;; Subnets (Core CSubNet, netaddress.h:519)
;;;
;;; A network tag plus a masked network address, matched bytewise under a
;;; netmask. The netmask is kept as bytes rather than a prefix length because
;;; Core stores it that way and its dotted-quad form need not be contiguous.

(defstruct (subnet (:constructor %make-subnet (network address netmask)))
  "A range of addresses: Core's CSubNet (netaddress.h:519-560)."
  (network nil :type symbol)
  (address nil :type (simple-array (unsigned-byte 8) (*)))
  (netmask nil :type (simple-array (unsigned-byte 8) (*))))

(defun %prefix-netmask (bits)
  "A 16-byte netmask whose first BITS bits are ones."
  (let ((mask (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (dotimes (i 16 mask)
      (let ((remaining (- bits (* 8 i))))
        (setf (aref mask i)
              (cond ((>= remaining 8) #xff)
                    ((<= remaining 0) 0)
                    (t (logand #xff (ash #xff (- 8 remaining))))))))))

(defun parse-subnet (string)
  "Parse STRING as a subnet, or NIL when it names none. Core accepts a bare
address, a network/CIDR and (for IPv4) a network/netmask, and masks the network
at construction so 1.2.3.4/24 names 1.2.3.0/24 (LookupSubNet, netbase.cpp:743-772;
CSubNet::CSubNet, netaddress.cpp).

IPv4 is held in its 16-byte mapped form, so an IPv4 /N covers 96+N bits: the
::ffff: prefix is part of the network, which is what keeps 0.0.0.0/0 an
IPv4-only wildcard the way Core's per-network Match does.

Only the three 16-byte networks are subnettable. Core's CSubNet compares
:torv3/:i2p/:cjdns by exact equality instead of by mask, and no caller here
needs that."
  (when (stringp string)
    (let* ((slash (position #\/ string))
           (host (if slash (subseq string 0 slash) string))
           (suffix (and slash (subseq string (1+ slash)))))
      (multiple-value-bind (network address) (parse-network-address host)
        ;; Only the 16-byte networks are subnettable; a .onion or .b32.i2p host
        ;; parses fine and is 32 bytes, so test the length rather than the tag.
        (when (and address (= 16 (length address)))
          (let* ((offset (if (eq network :ipv4) 96 0))
                 (netmask
                   (cond ((null suffix) (%prefix-netmask 128))
                         ((and (plusp (length suffix))
                               (every #'digit-char-p suffix))
                          (let ((bits (parse-integer suffix)))
                            (when (<= 0 bits (- 128 offset))
                              (%prefix-netmask (+ offset bits)))))
                         ;; A dotted-quad netmask masks the IPv4 octets only;
                         ;; the mapped prefix is forced to ones so the network
                         ;; tag still has to match.
                         ((eq network :ipv4)
                          (multiple-value-bind (mask-network mask-bytes)
                              (parse-network-address suffix)
                            (when (eq mask-network :ipv4)
                              (let ((m (copy-seq mask-bytes)))
                                (fill m #xff :end 12)
                                m)))))))
            (when netmask
              (let ((masked (copy-seq address)))
                (dotimes (i 16)
                  (setf (aref masked i) (logand (aref masked i) (aref netmask i))))
                (%make-subnet network masked netmask)))))))))

(defun subnet-match-p (subnet network address)
  "T when the NETWORK/ADDRESS pair falls inside SUBNET. Core compares the
network tag before the netmask, so a v4 subnet never matches a v6 address and
::/0 is not a wildcard over IPv4 (CSubNet::Match, netaddress.cpp)."
  (and (eq (subnet-network subnet) network)
       (let ((mask (subnet-netmask subnet))
             (masked (subnet-address subnet)))
         (loop for i below 16
               always (= (logand (aref address i) (aref mask i)) (aref masked i))))))

(defun address-in-subnets-p (string subnets)
  "T when the address STRING parses and falls inside any of SUBNETS. An address
that does not parse is refused, never defaulted in (Core ClientAllowed rejects
!IsValid, httpserver.cpp:139-140)."
  (when (and (stringp string) (plusp (length string)))
    (multiple-value-bind (network address) (parse-network-address string)
      (and address
           (= 16 (length address))
           (loop for subnet in subnets
                   thereis (subnet-match-p subnet network address))))))

(defun peer-address-string (pa)
  "Human-readable address string for a peer-address record PA."
  (network-address-to-string (peer-address-network pa) (peer-address-ip pa)))

;;;; Local addresses (Core mapLocalHost, net.cpp:119)
;;;
;;; The addresses THIS node is reachable at, for self-advertisement. The
;;; writers are the torcontrol client (ADD_ONION -> add-local, Core
;;; AddLocal(service, LOCAL_MANUAL)) and -externalip at startup; there is no
;;; interface discovery (Core Discover()/-discover), so entries are always
;;; LOCAL_MANUAL. The map is read by the sync thread (self-advertisement) and
;;; written by the torcontrol thread — hence the lock.

;; Core LocalServiceInfo scores (net.h:152-160).
(defconstant +local-none+ 0)
(defconstant +local-if+ 1)
(defconstant +local-bind+ 2)
(defconstant +local-manual+ 3)

(defstruct local-address
  "One entry of the local-address map: an address this node believes it is
reachable at (Core mapLocalHost key + LocalServiceInfo)."
  (network :ipv4 :type keyword)
  (bytes (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)
         :type (simple-array (unsigned-byte 8) (*)))
  (port 0 :type (unsigned-byte 16))
  (score 0 :type fixnum))

(defvar *local-addresses* '()
  "List of local-address records (Core mapLocalHost). Guarded by
*local-addresses-lock*.")

(defvar *external-ips* '()
  "Raw -externalip strings from config (Core init.cpp:1803-1808), consumed
at node startup: each parses through parse-network-address and lands in the
local-address map via add-local with +local-manual+ and the listen port.")

(defvar *local-addresses-lock* (bt:make-lock "local-addresses")
  "Guards *local-addresses* (torcontrol thread writes, sync thread reads —
Core g_maplocalhost_mutex).")

(defun privacy-network-p (network)
  "T for networks whose addresses must not be advertised across networks
(Core CNetAddr::IsPrivacyNet, netaddress.h:186: onion and I2P)."
  (and (member network '(:torv3 :i2p)) t))

(defun clear-local-addresses ()
  "Remove all local addresses (Core ClearLocal; for tests)."
  (bt:with-lock-held (*local-addresses-lock*)
    (setf *local-addresses* '())))

(defun local-addresses ()
  "Snapshot of the local-address records."
  (bt:with-lock-held (*local-addresses-lock*)
    (copy-list *local-addresses*)))

(defun %find-local-address (network bytes)
  "The local-address record for NETWORK/BYTES, or NIL. mapLocalHost is keyed
by the ADDRESS only (Core std::map<CNetAddr, ...>) — the port lives in the
entry and updates on re-add. Caller holds *local-addresses-lock*."
  (find-if (lambda (la)
             (and (eq (local-address-network la) network)
                  (equalp (local-address-bytes la) bytes)))
           *local-addresses*))

(defun add-local (network bytes port &optional (score +local-none+))
  "Register an address this node is reachable at (Core AddLocal,
net.cpp:277-303). Rejects unroutable addresses and unreachable networks
(g_reachable_nets gate: e.g. -onion=0 keeps an onion service from being
advertised); without discovery support, only LOCAL_MANUAL-or-better entries
are accepted (Core's !fDiscover gate, with fDiscover permanently false for
us). Re-adding an existing address with a score at least as high bumps its
score by one and updates the port, exactly like Core. Returns T if the
address is (now) present."
  (unless (address-routable-p bytes network)
    (return-from add-local nil))
  (when (< score +local-manual+)
    (return-from add-local nil))
  (unless (reachable-network-p network)
    (return-from add-local nil))
  (bitcoin-lisp:log-info "AddLocal(~A:~D,~D)"
                         (network-address-to-string network bytes) port score)
  (bt:with-lock-held (*local-addresses-lock*)
    (let ((existing (%find-local-address network bytes)))
      (if existing
          (when (>= score (local-address-score existing))
            (setf (local-address-score existing) (1+ score)
                  (local-address-port existing) port))
          (push (make-local-address :network network
                                    :bytes (copy-seq bytes)
                                    :port port
                                    :score score)
                *local-addresses*))))
  t)

(defun remove-local (network bytes)
  "Forget a local address (Core RemoveLocal, net.cpp:310-315; keyed by
address only, like the map)."
  (bitcoin-lisp:log-info "RemoveLocal(~A)"
                         (network-address-to-string network bytes))
  (bt:with-lock-held (*local-addresses-lock*)
    (let ((la (%find-local-address network bytes)))
      (when la
        (setf *local-addresses* (remove la *local-addresses*))))))

;; Core GetReachabilityFrom's Reachability enum (netaddress.cpp:715-723).
;; We omit the Teredo (RFC4380) and tunneled-IPv6 (RFC3964/6052/6145)
;; refinements — we have no predicates for those encapsulations, and they
;; only shade tie-breaks between multiple IPv6-ish local addresses, which
;; cannot occur while the map's only writer is torcontrol (onion entries).
(defconstant +reach-unreachable+ 0)
(defconstant +reach-default+ 1)
(defconstant +reach-ipv4+ 4)
(defconstant +reach-ipv6-strong+ 5)
(defconstant +reach-private+ 6)

(defun network-reachability-from (our-net their-net)
  "How good is a local address on OUR-NET to advertise to a peer connected
through THEIR-NET (Core CNetAddr::GetReachabilityFrom, netaddress.cpp:713-770,
minus the Teredo/tunnel shadings)? THEIR-NET may be :unroutable for a peer
whose address we cannot type (Core's default arm)."
  (case their-net
    (:ipv4 (if (eq our-net :ipv4) +reach-ipv4+ +reach-default+))
    (:ipv6 (case our-net
             (:ipv4 +reach-ipv4+)
             (:ipv6 +reach-ipv6-strong+)
             (t +reach-default+)))
    (:torv3 (case our-net
              (:ipv4 +reach-ipv4+)      ; Tor users can connect to IPv4 as well
              (:torv3 +reach-private+)
              (t +reach-default+)))
    (:i2p (if (eq our-net :i2p) +reach-private+ +reach-default+))
    (:cjdns (if (eq our-net :cjdns) +reach-private+ +reach-default+))
    ;; Unroutable/unknown partner (Core's trailing default arm).
    (t (case our-net
         (:ipv6 +reach-ipv6-strong+)
         (:ipv4 +reach-ipv4+)
         ;; "either from Tor, or don't care about our address"
         (:torv3 +reach-private+)
         (t +reach-default+)))))

(defun best-local-address (peer-network)
  "The best local address to advertise to a peer connected through
PEER-NETWORK (Core GetLocal, net.cpp:166-196): highest reachability, then
highest score, subject to the privacy rule — never advertise a privacy-net
(onion/I2P) address to a peer on a different network, and never advertise
any other-network address to a privacy-net peer. Returns the local-address
record, or NIL."
  (let ((best nil)
        (best-reach -1)
        (best-score -1))
    (bt:with-lock-held (*local-addresses-lock*)
      (dolist (la *local-addresses*)
        (let ((net (local-address-network la)))
          (unless (and (not (eq net peer-network))
                       (or (privacy-network-p net)
                           (privacy-network-p peer-network)))
            (let ((reach (network-reachability-from net peer-network))
                  (score (local-address-score la)))
              (when (or (> reach best-reach)
                        (and (= reach best-reach) (> score best-score)))
                (setf best la
                      best-reach reach
                      best-score score)))))))
    best))
