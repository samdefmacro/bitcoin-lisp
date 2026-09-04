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

(alexandria:define-constant +bip155-networks+ '(:ipv4 :ipv6 :torv3 :i2p :cjdns)
  :test #'equalp :documentation "All networks representable in our address layer (BIP155 ids 1,2,4,5,6).")

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
       (if close
           (let ((host (subseq spec 1 close))
                 (rest (subseq spec (1+ close))))
             (if (and (> (length rest) 1) (char= (char rest 0) #\:)
                      (every #'digit-char-p (subseq rest 1)))
                 (values host (parse-integer rest :start 1))
                 (values host default-port)))
           (values spec default-port))))
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
    (:cjdns *cjdns-reachable*)))

(alexandria:define-constant +bad-ports+
    #(1 7 9 11 13 15 17 19 20 21 22 23 25 37 42 43 53 69 77 79 87 95 101 102
      103 104 109 110 111 113 115 117 119 123 135 137 139 143 161 179 389 427
      465 512 513 514 515 526 530 531 532 540 548 554 556 563 587 601 636 989
      990 993 995 1719 1720 1723 2049 3306 3389 3659 4045 5060 5061 5432 5900
      6000 6566 6665 6666 6667 6668 6669 6697 10080 27017)
  :test #'equalp
  :documentation
  "Core's IsBadPort deny-list, netbase.cpp:847-935, in Core's own order —
tcpmux, echo, discard, ftp, ssh, telnet, smtp, dns, pop3, nntp, ntp, netbios,
imap, snmp, bgp, ldap, printer, syslog, nfs, MySQL, RDP, sip, PostgreSQL, VNC,
X11, IRC, MongoDB and the rest, documented service by service in
doc/p2p-bad-ports.md. Extracted from that switch mechanically rather than
transcribed: 85 entries, and a hand-copied one would be wrong in a way nothing
here could catch.")

(defun bad-port-p (port)
  "T if PORT is one Core refuses to make an AUTOMATIC outbound connection to
(IsBadPort, netbase.cpp:847-935; the dial-side gate is net.cpp:2854, `nTries <
50 && (addr.IsIPv4() || addr.IsIPv6()) && IsBadPort(addr.GetPort())').

The point is not that such a peer is useless — it is that anyone may gossip
`victim:25' or `victim:22', and a node that dials it speaks the Bitcoin
protocol at some third party's SMTP or SSH daemon on the gossiper's behalf.
That is what doc/p2p-bad-ports.md exists for, and it is why the filter belongs
on the DIAL and not on storage or relay: Core stores and re-gossips these
records exactly as we do.

Divergence: Core drops the check after 50 rejected draws in one
ThreadOpenConnections pass, so a node whose addrman is nothing but bad ports
still dials eventually. SELECT-DIALABLE-ADDRESS returns NIL when its draws are
exhausted instead of looping, so there is no loop for that escape hatch to
break."
  (and (find port +bad-ports+) t))

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

(defun %target-unroutable-p (host)
  "T if HOST is an IP literal Core would classify as unroutable — loopback,
RFC1918 private, link-local, RFC6598 CGNAT, RFC2544 benchmarking, RFC5737
documentation, or IPv6 ::1 / fe80::/10 / fc00::/7.

Core reaches the same answer structurally rather than with a list: GetNetwork()
returns NET_UNROUTABLE for any address IsRoutable() rejects
(netaddress.cpp:496-505), and a proxy is only ever registered for a real
network, so GetProxy(NET_UNROUTABLE, ...) always fails and the dial goes
direct.

That is not a corner case. Core's rpc_net.py starts every node with
-proxy=127.0.0.1:1 — a deliberately dead proxy, \"to make sure no actual
connections to public IPs are attempted\" — and then expects the nodes to
connect to EACH OTHER over loopback anyway. A node that proxies its loopback
dials cannot be tested that way, and on a private network it cannot reach its
own peers at all.

Hostnames are not covered, deliberately: Core routes name lookups through the
proxy (its point is that the name must not leak to local DNS).

Two of Core's unroutable ranges are deliberately NOT here: the documentation
blocks (RFC5737 192.0.2/24, 198.51.100/24, 203.0.113/24) and RFC2544
benchmarking space. This tree already treats those as ROUTABLE on purpose —
see ADDRESS-ROUTABLE-P, whose divergence note says so — because the test
fixtures use them as stand-ins for public addresses. Classifying them as
unroutable HERE and routable THERE would be two definitions of the same word,
and would silently change what every one of those fixtures is testing.

fc00::/7 is not here either, and that one is Core's own doing rather than a
divergence. Core's IsRFC4193() is guarded by IsIPv6(), which is a check on the
address's NETWORK TAG, not its bytes — so a CJDNS address (same prefix, tagged
NET_CJDNS) is routable and an unsuffixed -proxy covers it (init.cpp:1735).
Telling ULA from CJDNS needs that tag, which a bare host string does not carry,
so this stays out rather than guessing."
  (let ((ip (string-to-ip-bytes host)))
    (when ip
      (flet ((v4 () (and (ipv4-mapped-p ip) (subseq ip 12))))
        (let ((a (v4)))
          (cond
            (a (let ((b0 (aref a 0)) (b1 (aref a 1)))
                 (or (= b0 127)                                   ; loopback
                     (= b0 0)                                     ; "this network"
                     (= b0 10)                                    ; RFC1918
                     (and (= b0 172) (<= 16 b1 31))               ; RFC1918
                     (and (= b0 192) (= b1 168))                  ; RFC1918
                     (and (= b0 169) (= b1 254))                  ; RFC3927 link-local
                     (and (= b0 100) (<= 64 b1 127)))))            ; RFC6598 CGNAT
            (t (or (equalp ip #(0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1)) ; ::1
                   (and (= (aref ip 0) #xFE)
                        (= (logand (aref ip 1) #xC0) #x80)))))))))) ; fe80::/10

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
        ;; Unroutable targets are dialed directly, never through the proxy —
        ;; Core's NET_UNROUTABLE has no proxy registered for it. See
        ;; %TARGET-UNROUTABLE-P.
        ((%target-unroutable-p host) (values nil nil))
        (t (values *proxy* nil))))

;;;; Base32 (Core util/strencodings.cpp:144-200)
;;;
;;; RFC4648 base32 with Core's lowercase alphabet; decoding is
;;; case-insensitive and enforces that leftover bits are zero
;;; (ConvertBits<5,8,false>), so a truncated/garbage tail is rejected.

(alexandria:define-constant +base32-alphabet+ "abcdefghijklmnopqrstuvwxyz234567"
  :test #'equalp)

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
        ((char<= #\2 ch #\7) (+ 26 (- (char-code ch) (char-code #\2))))))

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
    (subseq (bl.crypto:sha3-256 material) 0 2)))

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
  (bl.log:log-info "AddLocal(~A:~D,~D)"
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
  (bl.log:log-info "RemoveLocal(~A)"
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

;;;; Net permissions (-whitelist / -whitebind)
;;;;
;;;; Core NetPermissionFlags (net_permissions.h:24-47). A peer whose address
;;;; falls inside a -whitelist range, or which arrived on a -whitebind listener,
;;;; is exempted from specific policy limits.
;;;;
;;;; DIVERGENCE, stated because it is load-bearing: Core attaches flags to the
;;;; CNode at connection time, because whitebind flags belong to the LISTENING
;;;; SOCKET a peer arrived on and Core can hold several. We bind one listener
;;;; (-bind takes the last), so the flags a peer has are a pure function of its
;;;; ADDRESS plus the parsed configuration, and are computed on demand rather
;;;; than stored per peer. Anything that adds a second listener must revisit
;;;; this — the whitebind flags would then have to travel with the connection.

(defconstant +perm-bloom-filter+ (ash 1 1))
(defconstant +perm-force-relay-only+ (ash 1 2))
(defconstant +perm-relay+ (ash 1 3))
(defconstant +perm-noban-only+ (ash 1 4))
(defconstant +perm-mempool+ (ash 1 5))
(defconstant +perm-download+ (ash 1 6))
(defconstant +perm-addr+ (ash 1 7))
(defconstant +perm-implicit+ (ash 1 31)
  "Set when the operator gave a range with NO explicit permissions, so the
implicit defaults apply (Core NetPermissionFlags::Implicit).")

(defconstant +perm-force-relay+ (logior +perm-force-relay-only+ +perm-relay+)
  "Core: \"forcerelay implies relay\" — the enumerator itself is the OR.")
(defconstant +perm-noban+ (logior +perm-noban-only+ +perm-download+)
  "Core: \"noban ... implies download\".")
(defconstant +perm-all+ (logior +perm-bloom-filter+ +perm-force-relay+
                                +perm-relay+ +perm-noban+ +perm-mempool+
                                +perm-download+ +perm-addr+))

(defparameter *permission-names*
  `(("bloomfilter" . ,+perm-bloom-filter+)
    ("bloom"       . ,+perm-bloom-filter+)   ; Core accepts both spellings
    ("noban"       . ,+perm-noban+)
    ("forcerelay"  . ,+perm-force-relay+)
    ("relay"       . ,+perm-relay+)
    ("mempool"     . ,+perm-mempool+)
    ("download"    . ,+perm-download+)
    ("addr"        . ,+perm-addr+)
    ("all"         . ,+perm-all+))
  "Core TryParsePermissionFlags' name table (net_permissions.cpp:50-57).")

(defstruct (whitelist-entry (:constructor %make-whitelist-entry (subnet flags direction)))
  "One -whitelist range and the permissions it grants."
  (subnet nil)
  (flags 0 :type (unsigned-byte 32))
  ;; :in, :out, or :both — Core's ConnectionDirection, from the \"in\"/\"out\"
  ;; pseudo-permissions. Defaults to :both, as Core does when neither is given.
  (direction :both :type keyword))

(defun parse-permission-flags (string)
  "Parse Core's \"perm1,perm2@range\" prefix.

Returns (values flags direction rest) — REST being the address part — or NIL
when a permission name is unknown. With no @ at all there are no explicit
permissions and REST is the whole string, which is Core's implicit case
(net_permissions.cpp:26-36)."
  (let ((at (position #\@ string)))
    (if at
        (let ((flags 0)
              (direction nil)
              (rest (subseq string (1+ at))))
          (dolist (name (%split-on-comma (subseq string 0 at)))
            (cond ((string= name "in")
                   (setf direction (if (eq direction :out) :both :in)))
                  ((string= name "out")
                   (setf direction (if (eq direction :in) :both :out)))
                  (t (let ((bit (cdr (assoc name *permission-names* :test #'string=))))
                       (unless bit (return-from parse-permission-flags nil))
                       (setf flags (logior flags bit))))))
          (values flags (or direction :both) rest))
        (values +perm-implicit+ :both string))))

(defun %split-on-comma (string)
  (loop with start = 0
        for comma = (position #\, string :start start)
        collect (subseq string start comma)
        while comma
        do (setf start (1+ comma))))

(defun parse-whitelist-entry (spec &key (allow-out t))
  "Parse one -whitelist (or -whitebind) SPEC into a WHITELIST-ENTRY, or NIL.

ALLOW-OUT NIL is -whitebind, where Core refuses \"out\" outright: a listening
socket has no outgoing connections to grant permissions to
(net_permissions.cpp:60-64)."
  (multiple-value-bind (flags direction rest) (parse-permission-flags spec)
    (when (and flags
               (or allow-out (not (member direction '(:out :both))))
               ;; :both only reaches the refusal above when it came from an
               ;; explicit \"out\"; the default :both carries no direction at all.
               t)
      (let ((subnet (parse-subnet rest)))
        (when subnet (%make-whitelist-entry subnet flags direction))))))

(defvar *whitelist-entries* '()
  "Parsed -whitelist ranges, in configuration order.")

(defvar *whitebind-flags* 0
  "Permissions granted to every INBOUND peer by -whitebind. A single value
because we bind a single listener; see the divergence note above.")

(defvar *whitelist-relay* t
  "-whitelistrelay (Core DEFAULT_WHITELISTRELAY = true): a whitelisted peer's
transactions are relayed even in -blocksonly.")

(defvar *whitelist-force-relay* nil
  "-whitelistforcerelay (Core DEFAULT_WHITELISTFORCERELAY = false).")

(defun peer-permission-flags (address inbound)
  "The permissions a peer at ADDRESS holds (Core CNode::m_permission_flags).

An entry applies when its direction covers this connection's direction, so
\"noban@1.2.3.4/32,out\" grants nothing to an inbound peer from that range.
-whitebind's flags apply to inbound peers only, since they describe a listening
socket."
  (let ((flags (if inbound *whitebind-flags* 0)))
    (dolist (entry *whitelist-entries* flags)
      (when (and (or (eq (whitelist-entry-direction entry) :both)
                     (eq (whitelist-entry-direction entry)
                         (if inbound :in :out)))
                 (address-in-subnets-p address
                                       (list (whitelist-entry-subnet entry))))
        (setf flags (logior flags (whitelist-entry-flags entry)))))))

(defun permission-flag-set-p (flags flag)
  "T when FLAGS grants FLAG — Core NetPermissions::HasFlag,
`(flags & f) == f' (net_permissions.h). The equality is load-bearing: an
enumerator can be several bits (\"noban ... implies download\", so
+PERM-NOBAN+ is +PERM-NOBAN-ONLY+ | +PERM-DOWNLOAD+), and a LOGTEST would
then report noban for a peer granted only `download'."
  (= flag (logand flags flag)))

(defun permission-flag-names (flags)
  "FLAGS as Core renders them in getpeerinfo.permissions (NetPermissions::
ToStrings). \"implicit\" is not a permission and is never listed."
  (let ((out '()))
    (macrolet ((emit (bit name)
                 `(when (= ,bit (logand flags ,bit)) (push ,name out))))
      (emit +perm-bloom-filter+ "bloomfilter")
      (emit +perm-noban+ "noban")
      (emit +perm-force-relay+ "forcerelay")
      (emit +perm-relay+ "relay")
      (emit +perm-mempool+ "mempool")
      (emit +perm-download+ "download")
      (emit +perm-addr+ "addr"))
    (nreverse out)))

;;;; -asmap: ASN-based netgroup bucketing (Core util/asmap.cpp)
;;;;
;;;; Without a map, Core (and this node) buckets IPv4 peers by /16. That is a
;;;; crude proxy for "different operator": a single AS often spans many /16s,
;;;; so an attacker holding one AS can present addresses that look like many
;;;; groups. An asmap replaces the /16 with the real ASN, which is what the
;;;; eclipse-resistance argument actually wants.
;;;;
;;;; The file is a bit-packed binary trie. The bits within a byte are read
;;;; LITTLE-endian for the map and BIG-endian for the IP being looked up —
;;;; getting that pair backwards decodes to plausible garbage rather than
;;;; failing, so both directions are pinned by test against Core's own vectors.

(defconstant +asmap-invalid+ #xFFFFFFFF
  "Core's INVALID sentinel: a decode that ran off the end of the data.")

(defvar *asmap* nil
  "The loaded -asmap bytecode as a byte vector, or NIL for /16 bucketing.")

(defun %asmap-bit-le (data bitpos)
  "One bit of DATA at BITPOS, LITTLE-endian within the byte (Core
ConsumeBitLE). Used for the MAP."
  (declare (type (simple-array (unsigned-byte 8) (*)) data)
           (type fixnum bitpos))
  (logand 1 (ash (aref data (ash bitpos -3)) (- (logand bitpos 7)))))

(defun %asmap-bit-be (data bitpos)
  "One bit of DATA at BITPOS, BIG-endian within the byte (Core ConsumeBitBE).
Used for the IP, to match network byte order."
  (declare (type (simple-array (unsigned-byte 8) (*)) data)
           (type fixnum bitpos))
  (logand 1 (ash (aref data (ash bitpos -3)) (- (- 7 (logand bitpos 7))))))

(defun %asmap-decode-bits (data bitpos minval bit-sizes)
  "Core DecodeBits: a variable-length integer, MINVAL plus a class-encoded
offset. Returns (values value new-bitpos), or (values +asmap-invalid+ ...) on
EOF. Continuation bits select the class; the mantissa within a class is
BIG-endian even though the bits come off the stream little-endian."
  (declare (type (simple-array (unsigned-byte 8) (*)) data)
           (type fixnum bitpos))
  (let ((val minval)
        (endpos (* 8 (length data)))
        (n (length bit-sizes)))
    (loop for i below n
          for size = (elt bit-sizes i)
          for last-class-p = (= i (1- n))
          do (let ((bit (if last-class-p
                            0
                            (if (>= bitpos endpos)
                                (return-from %asmap-decode-bits
                                  (values +asmap-invalid+ bitpos))
                                (prog1 (%asmap-bit-le data bitpos)
                                  (incf bitpos))))))
               (if (= bit 1)
                   (incf val (ash 1 size))
                   (progn
                     (dotimes (b size)
                       (when (>= bitpos endpos)
                         (return-from %asmap-decode-bits
                           (values +asmap-invalid+ bitpos)))
                       (incf val (ash (%asmap-bit-le data bitpos) (- size 1 b)))
                       (incf bitpos))
                     (return-from %asmap-decode-bits (values val bitpos))))))
    (values +asmap-invalid+ bitpos)))

(alexandria:define-constant +asmap-type-bit-sizes+ #(0 0 1)
  :test #'equalp)
(alexandria:define-constant +asmap-asn-bit-sizes+ #(15 16 17 18 19 20 21 22 23 24)
  :test #'equalp)
(alexandria:define-constant +asmap-match-bit-sizes+ #(1 2 3 4 5 6 7 8)
  :test #'equalp)
(alexandria:define-constant +asmap-jump-bit-sizes+
  #(5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30)
  :test #'equalp)

(defun asmap-interpret (asmap ip-bytes)
  "Core Interpret (asmap.cpp:182-232): walk the trie for IP-BYTES and return
its ASN, or 0 when the map does not cover it.

0 is not a valid ASN, so a 0 here means \"no mapping\" and callers must fall
back. Core asserts on a malformed map because SanityCheckAsmap ran at load
time; we return 0 instead — a node that loaded a bad file should bucket by /16
rather than die mid-connection."
  (declare (type (simple-array (unsigned-byte 8) (*)) asmap ip-bytes))
  (let ((pos 0)
        (endpos (* 8 (length asmap)))
        (ip-bit 0)
        (ip-bits-end (* 8 (length ip-bytes)))
        (default-asn 0))
    (loop while (< pos endpos)
          do (multiple-value-bind (opcode next)
                 (%asmap-decode-bits asmap pos 0 +asmap-type-bit-sizes+)
               (setf pos next)
               (case opcode
                 (0                              ; RETURN
                  (multiple-value-bind (asn next2)
                      (%asmap-decode-bits asmap pos 1 +asmap-asn-bit-sizes+)
                    (declare (ignore next2))
                    (return-from asmap-interpret
                      (if (= asn +asmap-invalid+) 0 asn))))
                 (1                              ; JUMP
                  (multiple-value-bind (jump next2)
                      (%asmap-decode-bits asmap pos 17 +asmap-jump-bit-sizes+)
                    (when (= jump +asmap-invalid+) (return))
                    (setf pos next2)
                    (when (= ip-bit ip-bits-end) (return))
                    (when (>= jump (- endpos pos)) (return))
                    (let ((bit (%asmap-bit-be ip-bytes ip-bit)))
                      (incf ip-bit)
                      (when (= bit 1) (incf pos jump)))))
                 (2                              ; MATCH
                  (multiple-value-bind (match next2)
                      (%asmap-decode-bits asmap pos 2 +asmap-match-bit-sizes+)
                    (when (= match +asmap-invalid+) (return))
                    (setf pos next2)
                    (let ((matchlen (1- (integer-length match))))
                      (when (< (- ip-bits-end ip-bit) matchlen) (return))
                      (dotimes (b matchlen)
                        (let ((bit (%asmap-bit-be ip-bytes ip-bit)))
                          (incf ip-bit)
                          (unless (= bit (logand 1 (ash match (- (- matchlen 1 b)))))
                            (return-from asmap-interpret default-asn)))))))
                 (3                              ; DEFAULT
                  (multiple-value-bind (asn next2)
                      (%asmap-decode-bits asmap pos 1 +asmap-asn-bit-sizes+)
                    (when (= asn +asmap-invalid+) (return))
                    (setf default-asn asn
                          pos next2)))
                 (t (return)))))
    ;; Ran off the end without a RETURN. Core asserts; we report "unmapped".
    0))

(defun asmap-asn (ip-bytes)
  "The ASN for a 16-byte address under the loaded -asmap, or NIL when no map is
loaded or the map does not cover it.

IPv4 is looked up on its 4 native bytes, not the 16-byte mapped form: Core
builds the lookup key from CNetAddr::GetAddrBytes, which for IPv4 is 4 bytes,
and an asmap built for 32-bit IPv4 keys would walk into nonsense given 128 bits
of ::ffff: prefix."
  (when (and *asmap* (= 16 (length ip-bytes)))
    (let* ((v4 (and (loop for i below 10 always (zerop (aref ip-bytes i)))
                    (= #xff (aref ip-bytes 10))
                    (= #xff (aref ip-bytes 11))))
           (key (if v4
                    (subseq ip-bytes 12 16)
                    ip-bytes))
           (asn (asmap-interpret *asmap* key)))
      (and (plusp asn) asn))))

(defun load-asmap-file (path)
  "Read an -asmap file into *ASMAP*. Returns the byte count, or signals.

Core aborts startup on an unreadable or empty asmap file (init.cpp:1587-1600):
a node that silently kept /16 bucketing after being told to use an ASN map
would have exactly the eclipse exposure the operator was trying to close."
  (with-open-file (in path :element-type '(unsigned-byte 8)
                           :if-does-not-exist nil)
    (unless in
      (config-error "Could not find asmap file ~A" path))
    (let* ((size (file-length in))
           (buf (make-array size :element-type '(unsigned-byte 8))))
      (when (zerop size)
        (config-error "Could not parse asmap file ~A" path))
      (read-sequence buf in)
      (setf *asmap* buf)
      ;; Core logs the OPEN here, inside the reader, with the path quoted and
      ;; the size (util/asmap.cpp:331); the "Using asmap version" line comes
      ;; later, from init. feature_asmap.py greps for both, which is why they
      ;; are two lines and not one.
      (bl.log:log-info "Opened asmap file \"~A\" (~D bytes) from disk"
                             (namestring path) size)
      size)))

(defun asmap-version ()
  "Core AsmapVersion (util/asmap.cpp:348): SHA256d over the asmap bytes, or NIL
when no map is loaded. It identifies WHICH map a node is bucketing with, which
is the thing an operator comparing two nodes actually needs."
  ;; ⚠️ REVERSED for display. Core's AsmapVersion returns a uint256, which
  ;; prints big-endian while the hash is computed and stored little-endian —
  ;; the same convention as every block hash and txid. Printing the raw digest
  ;; gives the right bytes in the wrong order, which reads as a completely
  ;; different version and matches nothing an operator can compare against.
  (when (and *asmap* (plusp (length *asmap*)))
    (bl.crypto:bytes-to-hex
     (bl.crypto:reverse-bytes
      (bl.crypto:hash256 *asmap*)))))
