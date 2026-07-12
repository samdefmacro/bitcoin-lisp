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
  "T when -cjdnsreachable is set: fc00::/8 IPv6 addresses arriving at
ingress points (parsed strings, inbound connections) are retagged :cjdns
(Core MaybeFlipIPv6toCJDNS, netbase.cpp:942-949).")

(defun reachable-network-p (network)
  "T if NETWORK is in the reachable set (Core g_reachable_nets.Contains)."
  (and (member network *reachable-networks*) t))

(defun dialable-network-p (network)
  "T if our transport stack can actually open a connection to NETWORK.
P1 note: the address layer can now REPRESENT torv3/i2p/cjdns addresses, but
nothing can dial them until P2 (onion via SOCKS5 DOMAINNAME, CJDNS via the
cjdroute TUN) — so automatic outbound selection, feelers and block-relay
slot filling MUST filter through this predicate regardless of -onlynet or
proxy configuration. Raw-TCP-ing a 32-byte onion key is a bug."
  (and (member network '(:ipv4 :ipv6)) t))

(defun maybe-flip-ipv6-to-cjdns (network bytes)
  "Retag an :ipv6 address whose first byte is 0xFC as :cjdns when
-cjdnsreachable is set (Core MaybeFlipIPv6toCJDNS, netbase.cpp:942-949).
Applied at ingress points where addresses arrive UNTYPED (string parsing,
inbound socket addresses) — addrv2 gossip carries the CJDNS tag itself.
Returns the (possibly new) network keyword."
  (if (and (eq network :ipv6)
           *cjdns-reachable*
           (plusp (length bytes))
           (= (aref bytes 0) #xFC))
      :cjdns
      network))

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

(defun %parse-ipv6-string (string)
  "Parse an IPv6 STRING (full or with one \"::\" compression) to 16 bytes,
or NIL. Accepts what ip-bytes-to-string emits plus standard compressed
forms used in config values; scoped (%zone) and embedded-IPv4 tails are
not supported."
  (let* ((double (search "::" string))
         (split (lambda (s)
                  (when (plusp (length s))
                    (loop for start = 0 then (1+ pos)
                          for pos = (position #\: s :start start)
                          collect (subseq s start (or pos (length s)))
                          while pos))))
         (head (funcall split (if double (subseq string 0 double) string)))
         (tail (when double (funcall split (subseq string (+ double 2))))))
    ;; A second "::" is invalid.
    (when (and double (search "::" string :start2 (+ double 1)))
      (return-from %parse-ipv6-string nil))
    (let ((groups (+ (length head) (length tail))))
      (when (or (and double (<= groups 7))
                (and (not double) (= groups 8)))
        (let ((words (append head
                             (make-list (if double (- 8 groups) 0)
                                        :initial-element "0")
                             tail))
              (bytes (make-array 16 :element-type '(unsigned-byte 8))))
          (loop for w in words
                for i from 0
                do (let ((v (and (<= 1 (length w) 4)
                                 (ignore-errors (parse-integer w :radix 16)))))
                     (unless (and v (<= 0 v #xFFFF))
                       (return-from %parse-ipv6-string nil))
                     (setf (aref bytes (* 2 i)) (ash v -8)
                           (aref bytes (1+ (* 2 i))) (logand v #xFF))))
          bytes)))))

(defun parse-network-address (string)
  "Parse an address STRING of any supported network. Returns
(VALUES network bytes) — :ipv4 as 16-byte mapped IPv6, :ipv6/:cjdns as 16
bytes, :torv3/:i2p as their 32-byte forms — or NIL if unparseable (e.g. a
hostname). An fc00::/8 IPv6 is retagged :cjdns under -cjdnsreachable, this
being a string-ingress point (Core applies MaybeFlipIPv6toCJDNS to Lookup
results, netbase.cpp:825)."
  (let ((onion (parse-onion-address string)))
    (when onion (return-from parse-network-address (values :torv3 onion))))
  (let ((i2p (parse-i2p-address string)))
    (when i2p (return-from parse-network-address (values :i2p i2p))))
  (let ((v4 (ignore-errors (string-to-ip-bytes string))))
    (when v4 (return-from parse-network-address (values :ipv4 v4))))
  (when (find #\: string)
    (let ((v6 (%parse-ipv6-string string)))
      (when v6
        (return-from parse-network-address
          (values (maybe-flip-ipv6-to-cjdns :ipv6 v6) v6)))))
  nil)

(defun peer-address-string (pa)
  "Human-readable address string for a peer-address record PA."
  (network-address-to-string (peer-address-network pa) (peer-address-ip pa)))
