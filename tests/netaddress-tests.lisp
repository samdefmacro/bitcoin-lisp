(in-package #:bitcoin-lisp.tests)

(in-suite :netaddress-tests)

;;; Network-typed addresses (BIP155 P1): onion/i2p human-readable codecs,
;;; base32, netgroups for the new nets, reachability/dialability predicates.
;;;
;;; All codec vectors are taken verbatim from Bitcoin Core's own tests
;;; (refs/bitcoin/src/test/net_tests.cpp cnetaddr_basic /
;;; cnetaddr_serialize_v2 / cnetaddr_unserialize_v2) — the address bytes are
;;; Core's hex, the strings Core's expected ToStringAddr output.

(defun %na-hex (s) (bitcoin-lisp.crypto:hex-to-bytes s))

(defparameter +onion-pubkey-1+
  "79bcc625184b05194975c28b66b66b0469f7f6556fb1ac3189a79b40dda32f1f")
(defparameter +onion-str-1+
  "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion")
(defparameter +onion-pubkey-2+
  "53cd5648488c4707914182655b7664034e09e66f7e8cbf1084e654eb56c5bd88")
(defparameter +onion-str-2+
  "kpgvmscirrdqpekbqjsvw5teanhatztpp2gl6eee4zkowvwfxwenqaid.onion")
(defparameter +i2p-hash-1+
  "a2894dabaec08c0051a481a6dac88b64f98232ae42d4b6fd2fa81952dfe36a87")
(defparameter +i2p-str-1+
  "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p")
(defparameter +i2p-str-2+
  "udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna.b32.i2p")

;;;; Onion v3 codec

(test onion-format-core-vectors
  "32-byte pubkey -> .onion string, both Core vectors."
  (is (string= +onion-str-1+
               (bitcoin-lisp.networking:onion-address-string (%na-hex +onion-pubkey-1+))))
  (is (string= +onion-str-2+
               (bitcoin-lisp.networking:onion-address-string (%na-hex +onion-pubkey-2+))))
  ;; 56 chars before the suffix, always.
  (is (= (+ 56 6) (length +onion-str-1+))))

(test onion-parse-core-vectors
  ".onion string -> pubkey, and encode/parse round-trips."
  (is (equalp (%na-hex +onion-pubkey-1+)
              (bitcoin-lisp.networking:parse-onion-address +onion-str-1+)))
  (is (equalp (%na-hex +onion-pubkey-2+)
              (bitcoin-lisp.networking:parse-onion-address +onion-str-2+)))
  (let* ((pk (%na-hex +onion-pubkey-1+))
         (rt (bitcoin-lisp.networking:parse-onion-address
              (bitcoin-lisp.networking:onion-address-string pk))))
    (is (equalp pk rt))))

(test onion-parse-rejects-corruption
  "Core cnetaddr_basic negative cases: checksum, version, length, base32, TORv2."
  ;; Wrong checksum ('yd' -> 'ad' tail flip, Core's exact vector).
  (is (null (bitcoin-lisp.networking:parse-onion-address
             "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscsad.onion")))
  ;; Wrong version byte (trailing 'd' -> 'e').
  (is (null (bitcoin-lisp.networking:parse-onion-address
             "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscrye.onion")))
  ;; TORv2 (16 chars) is dead: wrong decoded length.
  (is (null (bitcoin-lisp.networking:parse-onion-address "6hzph5hv6337r6p2.onion")))
  ;; Bogus length.
  (is (null (bitcoin-lisp.networking:parse-onion-address "mfrggzak.onion")))
  ;; Invalid base32 characters.
  (is (null (bitcoin-lisp.networking:parse-onion-address "mf*g zak.onion")))
  ;; Missing/foreign suffix.
  (is (null (bitcoin-lisp.networking:parse-onion-address +i2p-str-1+)))
  (is (null (bitcoin-lisp.networking:parse-onion-address "totally bogus"))))

(test onion-parse-case-handling
  "Base32 body decodes case-insensitively (Core decode32_table); the .onion
suffix itself is case-sensitive (Core ends_with)."
  (is (equalp (%na-hex +onion-pubkey-1+)
              (bitcoin-lisp.networking:parse-onion-address
               (concatenate 'string
                            (string-upcase (subseq +onion-str-1+ 0 56))
                            ".onion"))))
  (is (null (bitcoin-lisp.networking:parse-onion-address
             (concatenate 'string (subseq +onion-str-1+ 0 56) ".ONION")))))

;;;; I2P codec

(test i2p-format-core-vector
  (is (string= +i2p-str-1+
               (bitcoin-lisp.networking:i2p-address-string (%na-hex +i2p-hash-1+))))
  (is (= (+ 52 8) (length +i2p-str-1+))))

(test i2p-parse-core-vectors
  (is (equalp (%na-hex +i2p-hash-1+)
              (bitcoin-lisp.networking:parse-i2p-address +i2p-str-1+)))
  ;; Round trip through format.
  (let ((h (bitcoin-lisp.networking:parse-i2p-address +i2p-str-2+)))
    (is (not (null h)))
    (is (string= +i2p-str-2+ (bitcoin-lisp.networking:i2p-address-string h)))))

(test i2p-parse-case-insensitive
  "Core parses 'UDHDrt....b32.I2P' (mixed case body AND suffix) and formats
it back lowercase."
  (let ((h (bitcoin-lisp.networking:parse-i2p-address
            "UDHDrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna.b32.I2P")))
    (is (not (null h)))
    (is (string= +i2p-str-2+ (bitcoin-lisp.networking:i2p-address-string h)))))

(test i2p-parse-rejects-corruption
  "Core cnetaddr_basic negative cases."
  ;; Correct length but '=' in the body decodes short.
  (is (null (bitcoin-lisp.networking:parse-i2p-address
             "udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jn=.b32.i2p")))
  ;; Extra unnecessary padding (61 chars).
  (is (null (bitcoin-lisp.networking:parse-i2p-address
             "udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna=.b32.i2p")))
  ;; 56-char (encrypted-leaseset) form is unsupported.
  (is (null (bitcoin-lisp.networking:parse-i2p-address
             "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscsad.b32.i2p")))
  ;; Invalid base32.
  (is (null (bitcoin-lisp.networking:parse-i2p-address "tp*szydbh4dp.b32.i2p")))
  ;; Onion string is not I2P.
  (is (null (bitcoin-lisp.networking:parse-i2p-address +onion-str-1+))))

;;;; Base32 (Core strencodings_tests vectors: "test" <-> "orsxg5a=")

(test base32-core-vectors
  (let ((plain (map '(vector (unsigned-byte 8)) #'char-code "test")))
    (is (string= "orsxg5a=" (bitcoin-lisp.networking:base32-encode plain :pad t)))
    (is (string= "orsxg5a" (bitcoin-lisp.networking:base32-encode plain)))
    (is (equalp plain (bitcoin-lisp.networking:base32-decode "orsxg5a=")))
    (is (equalp plain (bitcoin-lisp.networking:base32-decode "ORSXG5A=")))
    ;; Length not a multiple of 8.
    (is (null (bitcoin-lisp.networking:base32-decode "orsxg5a")))
    ;; Nonzero leftover bits ('b' instead of 'a' flips a padding bit).
    (is (null (bitcoin-lisp.networking:base32-decode "orsxg5b=")))))

;;;; Generic string <-> typed address

(test parse-network-address-all-nets
  (multiple-value-bind (net bytes)
      (bitcoin-lisp.networking:parse-network-address "203.0.113.7")
    (is (eq :ipv4 net))
    (is (equalp (bitcoin-lisp.networking:ipv4-to-mapped-ipv6 203 0 113 7) bytes)))
  (multiple-value-bind (net bytes)
      (bitcoin-lisp.networking:parse-network-address "2001:db8::1")
    (is (eq :ipv6 net))
    (is (equalp (%na-hex "20010db8000000000000000000000001") bytes)))
  (multiple-value-bind (net bytes)
      (bitcoin-lisp.networking:parse-network-address +onion-str-1+)
    (is (eq :torv3 net))
    (is (equalp (%na-hex +onion-pubkey-1+) bytes)))
  (multiple-value-bind (net bytes)
      (bitcoin-lisp.networking:parse-network-address +i2p-str-1+)
    (is (eq :i2p net))
    (is (equalp (%na-hex +i2p-hash-1+) bytes)))
  ;; Hostnames are not addresses.
  (is (null (bitcoin-lisp.networking:parse-network-address "seed.bitcoin.sipa.be"))))

(test network-address-to-string-round-trips
  (dolist (case (list (list :ipv4 (bitcoin-lisp.networking:ipv4-to-mapped-ipv6 10 1 2 3))
                      (list :ipv6 (%na-hex "20010db8000000000000000000000001"))
                      (list :torv3 (%na-hex +onion-pubkey-2+))
                      (list :i2p (%na-hex +i2p-hash-1+))))
    (destructuring-bind (net bytes) case
      (multiple-value-bind (pnet pbytes)
          (bitcoin-lisp.networking:parse-network-address
           (bitcoin-lisp.networking:network-address-to-string net bytes))
        (is (eq net pnet))
        (is (equalp bytes pbytes))))))

;;;; CJDNS retag at string ingress (-cjdnsreachable)

(test cjdns-flip-on-ingress
  (let ((fc-bytes (%na-hex "fc000001000200030004000500060007")))
    ;; Flag off: fc00::/8 strings stay :ipv6 (and are unroutable, see below).
    (let ((bitcoin-lisp.networking:*cjdns-reachable* nil))
      (is (eq :ipv6 (bitcoin-lisp.networking:maybe-flip-ipv6-to-cjdns :ipv6 fc-bytes)))
      (is (eq :ipv6 (nth-value 0 (bitcoin-lisp.networking:parse-network-address
                                  "fc00:1:2:3:4:5:6:7")))))
    ;; Flag on: retagged :cjdns.
    (let ((bitcoin-lisp.networking:*cjdns-reachable* t))
      (is (eq :cjdns (bitcoin-lisp.networking:maybe-flip-ipv6-to-cjdns :ipv6 fc-bytes)))
      (multiple-value-bind (net bytes)
          (bitcoin-lisp.networking:parse-network-address "fc00:1:2:3:4:5:6:7")
        (is (eq :cjdns net))
        (is (equalp fc-bytes bytes)))
      ;; Non-fc addresses never flip.
      (is (eq :ipv6 (bitcoin-lisp.networking:maybe-flip-ipv6-to-cjdns
                     :ipv6 (%na-hex "20010db8000000000000000000000001")))))))

;;;; Routability per network (addrman gate)

(test address-routable-per-network
  (is-true (bitcoin-lisp.networking:address-routable-p
            (bitcoin-lisp.networking:ipv4-to-mapped-ipv6 1 2 3 4) :ipv4))
  (is-true (bitcoin-lisp.networking:address-routable-p
            (%na-hex "20010db8000000000000000000000001") :ipv6))
  (is-true (bitcoin-lisp.networking:address-routable-p (%na-hex +onion-pubkey-1+) :torv3))
  (is-true (bitcoin-lisp.networking:address-routable-p (%na-hex +i2p-hash-1+) :i2p))
  (is-true (bitcoin-lisp.networking:address-routable-p
            (%na-hex "fc000001000200030004000500060007") :cjdns))
  ;; CJDNS without the fc prefix is invalid (Core IsValid).
  (is-false (bitcoin-lisp.networking:address-routable-p
             (%na-hex "aa000001000200030004000500060007") :cjdns))
  ;; Plain IPv6 inside fc00::/7 (RFC4193) is not routable — must arrive
  ;; tagged CJDNS to count.
  (is-false (bitcoin-lisp.networking:address-routable-p
             (%na-hex "fc000001000200030004000500060007") :ipv6))
  (is-false (bitcoin-lisp.networking:address-routable-p
             (%na-hex "fd6b88c08724ca978112ca1bbdcafac2") :ipv6))
  ;; Wrong length for the net.
  (is-false (bitcoin-lisp.networking:address-routable-p
             (%na-hex "20010db8000000000000000000000001") :torv3))
  ;; All zero.
  (is-false (bitcoin-lisp.networking:address-routable-p
             (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
             :torv3)))

;;;; Netgroups for the new nets (Core netgroup.cpp:52-77)

(test net-group-key-new-nets
  ;; Tor/I2P: [net-class, addr[0] | 0x0F].
  (let ((pk (%na-hex +onion-pubkey-1+)))   ; addr[0] = #x79
    (is (equal (list 3 (logior #x79 #x0F))
               (coerce (bitcoin-lisp.networking:net-group-key pk :torv3) 'list))))
  (let ((h (%na-hex +i2p-hash-1+)))        ; addr[0] = #xA2
    (is (equal (list 4 (logior #xA2 #x0F))
               (coerce (bitcoin-lisp.networking:net-group-key h :i2p) 'list))))
  ;; Same bytes, different net => different group (net class differs).
  (is (not (equalp (bitcoin-lisp.networking:net-group-key (%na-hex +i2p-hash-1+) :torv3)
                   (bitcoin-lisp.networking:net-group-key (%na-hex +i2p-hash-1+) :i2p))))
  ;; CJDNS: [5, addr[0], addr[1] | 0x0F] — skips the constant fc prefix bits.
  (let ((c (%na-hex "fc010203000000000000000000000001")))
    (is (equal (list 5 #xFC (logior #x01 #x0F))
               (coerce (bitcoin-lisp.networking:net-group-key c :cjdns) 'list)))))

(test ip-netgroup-strings
  ;; Dotted-quad behavior unchanged: /16 prefix string.
  (is (string= "103.165" (bitcoin-lisp.networking:ip-netgroup "103.165.192.4")))
  ;; Onion strings group by [3, addr0|0x0F]; two onions with distinct first
  ;; bytes land in distinct groups, hostnames in none.
  (let ((g1 (bitcoin-lisp.networking:ip-netgroup +onion-str-1+))   ; 0x79
        (g2 (bitcoin-lisp.networking:ip-netgroup +onion-str-2+)))  ; 0x53
    (is (stringp g1))
    (is (stringp g2))
    (is (not (string= g1 g2))))
  (is (null (bitcoin-lisp.networking:ip-netgroup "seed.bitcoin.sipa.be"))))

;;;; Reachability / dialability

(test dialable-network-p-ip-only
  "P1 safety valve: only IP networks are dialable until P2, no matter what
-onlynet or the proxy config says."
  (is-true (bitcoin-lisp.networking:dialable-network-p :ipv4))
  (is-true (bitcoin-lisp.networking:dialable-network-p :ipv6))
  (is-false (bitcoin-lisp.networking:dialable-network-p :torv3))
  (is-false (bitcoin-lisp.networking:dialable-network-p :i2p))
  (is-false (bitcoin-lisp.networking:dialable-network-p :cjdns)))

(test reachable-network-p-follows-special
  (let ((bitcoin-lisp.networking:*reachable-networks* '(:ipv4 :torv3)))
    (is-true (bitcoin-lisp.networking:reachable-network-p :ipv4))
    (is-true (bitcoin-lisp.networking:reachable-network-p :torv3))
    (is-false (bitcoin-lisp.networking:reachable-network-p :ipv6))))

(test select-dialable-never-returns-non-ip
  "A book holding ONLY onion/i2p records yields nothing to automatic outbound
selection; mixed books only ever yield the IP records."
  (let ((book (bitcoin-lisp.networking:make-address-book))
        (bitcoin-lisp.networking:*reachable-networks*
          (copy-list bitcoin-lisp.networking:+bip155-networks+)))
    (is-true (bitcoin-lisp.networking:address-book-add
              book (bitcoin-lisp.networking:make-peer-address
                    :net :torv3 :ip (%na-hex +onion-pubkey-1+) :port 8333
                    :services 1 :last-seen (bitcoin-lisp.serialization:get-unix-time))))
    (is-true (bitcoin-lisp.networking:address-book-add
              book (bitcoin-lisp.networking:make-peer-address
                    :net :i2p :ip (%na-hex +i2p-hash-1+) :port 0
                    :services 1 :last-seen (bitcoin-lisp.serialization:get-unix-time))))
    ;; Raw select can see them; the dialable filter never lets them out.
    (is (not (null (bitcoin-lisp.networking:address-book-select book))))
    (is (null (bitcoin-lisp.networking:select-dialable-address book :tries 200)))
    ;; Add an IPv4 record: the filter now yields only that one.
    (is-true (bitcoin-lisp.networking:address-book-add
              book (bitcoin-lisp.networking:make-peer-address
                    :ip (bitcoin-lisp.networking:ipv4-to-mapped-ipv6 8 8 8 8)
                    :port 8333 :services 1
                    :last-seen (bitcoin-lisp.serialization:get-unix-time))))
    (dotimes (_ 20)
      (let ((pa (bitcoin-lisp.networking:select-dialable-address book :tries 200)))
        (is (not (null pa)))
        (is (eq :ipv4 (bitcoin-lisp.networking:peer-address-network pa)))))))

(test select-dialable-honors-onlynet
  "-onlynet=ipv6 (reachable set without :ipv4) excludes IPv4 records from
automatic selection even though IPv4 is dialable."
  (let ((book (bitcoin-lisp.networking:make-address-book)))
    (bitcoin-lisp.networking:address-book-add
     book (bitcoin-lisp.networking:make-peer-address
           :ip (bitcoin-lisp.networking:ipv4-to-mapped-ipv6 8 8 4 4)
           :port 8333 :services 1
           :last-seen (bitcoin-lisp.serialization:get-unix-time)))
    (let ((bitcoin-lisp.networking:*reachable-networks* '(:ipv6)))
      (is (null (bitcoin-lisp.networking:select-dialable-address book :tries 200))))
    (let ((bitcoin-lisp.networking:*reachable-networks* '(:ipv4)))
      (is (not (null (bitcoin-lisp.networking:select-dialable-address book :tries 200)))))))

;;;; peer-address-string

(test peer-address-string-all-nets
  (is (string= "1.2.3.4"
               (bitcoin-lisp.networking:peer-address-string
                (bitcoin-lisp.networking:make-peer-address
                 :ip (bitcoin-lisp.networking:ipv4-to-mapped-ipv6 1 2 3 4)))))
  (is (string= +onion-str-1+
               (bitcoin-lisp.networking:peer-address-string
                (bitcoin-lisp.networking:make-peer-address
                 :net :torv3 :ip (%na-hex +onion-pubkey-1+)))))
  (is (string= +i2p-str-1+
               (bitcoin-lisp.networking:peer-address-string
                (bitcoin-lisp.networking:make-peer-address
                 :net :i2p :ip (%na-hex +i2p-hash-1+))))))
