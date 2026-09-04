(in-package #:bitcoin-lisp.tests)

(in-suite :netaddress-tests)

;;; Network-typed addresses (BIP155 P1): onion/i2p human-readable codecs,
;;; base32, netgroups for the new nets, reachability/dialability predicates.
;;;
;;; All codec vectors are taken verbatim from Bitcoin Core's own tests
;;; (refs/bitcoin/src/test/net_tests.cpp cnetaddr_basic /
;;; cnetaddr_serialize_v2 / cnetaddr_unserialize_v2) — the address bytes are
;;; Core's hex, the strings Core's expected ToStringAddr output.

(defun %na-hex (s) (bl.crypto:hex-to-bytes s))

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
               (bl.net:onion-address-string (%na-hex +onion-pubkey-1+))))
  (is (string= +onion-str-2+
               (bl.net:onion-address-string (%na-hex +onion-pubkey-2+))))
  ;; 56 chars before the suffix, always.
  (is (= (+ 56 6) (length +onion-str-1+))))

(test onion-parse-core-vectors
  ".onion string -> pubkey, and encode/parse round-trips."
  (is (equalp (%na-hex +onion-pubkey-1+)
              (bl.net:parse-onion-address +onion-str-1+)))
  (is (equalp (%na-hex +onion-pubkey-2+)
              (bl.net:parse-onion-address +onion-str-2+)))
  (let* ((pk (%na-hex +onion-pubkey-1+))
         (rt (bl.net:parse-onion-address
              (bl.net:onion-address-string pk))))
    (is (equalp pk rt))))

(test onion-parse-rejects-corruption
  "Core cnetaddr_basic negative cases: checksum, version, length, base32, TORv2."
  ;; Wrong checksum ('yd' -> 'ad' tail flip, Core's exact vector).
  (is (null (bl.net:parse-onion-address
             "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscsad.onion")))
  ;; Wrong version byte (trailing 'd' -> 'e').
  (is (null (bl.net:parse-onion-address
             "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscrye.onion")))
  ;; TORv2 (16 chars) is dead: wrong decoded length.
  (is (null (bl.net:parse-onion-address "6hzph5hv6337r6p2.onion")))
  ;; Bogus length.
  (is (null (bl.net:parse-onion-address "mfrggzak.onion")))
  ;; Invalid base32 characters.
  (is (null (bl.net:parse-onion-address "mf*g zak.onion")))
  ;; Missing/foreign suffix.
  (is (null (bl.net:parse-onion-address +i2p-str-1+)))
  (is (null (bl.net:parse-onion-address "totally bogus"))))

(test onion-parse-case-handling
  "Base32 body decodes case-insensitively (Core decode32_table); the .onion
suffix itself is case-sensitive (Core ends_with)."
  (is (equalp (%na-hex +onion-pubkey-1+)
              (bl.net:parse-onion-address
               (concatenate 'string
                            (string-upcase (subseq +onion-str-1+ 0 56))
                            ".onion"))))
  (is (null (bl.net:parse-onion-address
             (concatenate 'string (subseq +onion-str-1+ 0 56) ".ONION")))))

;;;; I2P codec

(test i2p-format-core-vector
  (is (string= +i2p-str-1+
               (bl.net:i2p-address-string (%na-hex +i2p-hash-1+))))
  (is (= (+ 52 8) (length +i2p-str-1+))))

(test i2p-parse-core-vectors
  (is (equalp (%na-hex +i2p-hash-1+)
              (bl.net:parse-i2p-address +i2p-str-1+)))
  ;; Round trip through format.
  (let ((h (bl.net:parse-i2p-address +i2p-str-2+)))
    (is (not (null h)))
    (is (string= +i2p-str-2+ (bl.net:i2p-address-string h)))))

(test i2p-parse-case-insensitive
  "Core parses 'UDHDrt....b32.I2P' (mixed case body AND suffix) and formats
it back lowercase."
  (let ((h (bl.net:parse-i2p-address
            "UDHDrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna.b32.I2P")))
    (is (not (null h)))
    (is (string= +i2p-str-2+ (bl.net:i2p-address-string h)))))

(test i2p-parse-rejects-corruption
  "Core cnetaddr_basic negative cases."
  ;; Correct length but '=' in the body decodes short.
  (is (null (bl.net:parse-i2p-address
             "udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jn=.b32.i2p")))
  ;; Extra unnecessary padding (61 chars).
  (is (null (bl.net:parse-i2p-address
             "udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna=.b32.i2p")))
  ;; 56-char (encrypted-leaseset) form is unsupported.
  (is (null (bl.net:parse-i2p-address
             "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscsad.b32.i2p")))
  ;; Invalid base32.
  (is (null (bl.net:parse-i2p-address "tp*szydbh4dp.b32.i2p")))
  ;; Onion string is not I2P.
  (is (null (bl.net:parse-i2p-address +onion-str-1+))))

;;;; Base32 (Core strencodings_tests vectors: "test" <-> "orsxg5a=")

(test base32-core-vectors
  (let ((plain (map '(vector (unsigned-byte 8)) #'char-code "test")))
    (is (string= "orsxg5a=" (bl.net:base32-encode plain :pad t)))
    (is (string= "orsxg5a" (bl.net:base32-encode plain)))
    (is (equalp plain (bl.net:base32-decode "orsxg5a=")))
    (is (equalp plain (bl.net:base32-decode "ORSXG5A=")))
    ;; Length not a multiple of 8.
    (is (null (bl.net:base32-decode "orsxg5a")))
    ;; Nonzero leftover bits ('b' instead of 'a' flips a padding bit).
    (is (null (bl.net:base32-decode "orsxg5b=")))))

;;;; Generic string <-> typed address

(test parse-network-address-all-nets
  (multiple-value-bind (net bytes)
      (bl.net:parse-network-address "203.0.113.7")
    (is (eq :ipv4 net))
    (is (equalp (bl.net:ipv4-to-mapped-ipv6 203 0 113 7) bytes)))
  (multiple-value-bind (net bytes)
      (bl.net:parse-network-address "2001:db8::1")
    (is (eq :ipv6 net))
    (is (equalp (%na-hex "20010db8000000000000000000000001") bytes)))
  (multiple-value-bind (net bytes)
      (bl.net:parse-network-address +onion-str-1+)
    (is (eq :torv3 net))
    (is (equalp (%na-hex +onion-pubkey-1+) bytes)))
  (multiple-value-bind (net bytes)
      (bl.net:parse-network-address +i2p-str-1+)
    (is (eq :i2p net))
    (is (equalp (%na-hex +i2p-hash-1+) bytes)))
  ;; Hostnames are not addresses.
  (is (null (bl.net:parse-network-address "seed.bitcoin.sipa.be"))))

(test network-address-to-string-round-trips
  (dolist (case (list (list :ipv4 (bl.net:ipv4-to-mapped-ipv6 10 1 2 3))
                      (list :ipv6 (%na-hex "20010db8000000000000000000000001"))
                      (list :torv3 (%na-hex +onion-pubkey-2+))
                      (list :i2p (%na-hex +i2p-hash-1+))))
    (destructuring-bind (net bytes) case
      (multiple-value-bind (pnet pbytes)
          (bl.net:parse-network-address
           (bl.net:network-address-to-string net bytes))
        (is (eq net pnet))
        (is (equalp bytes pbytes))))))

;;;; CJDNS retag at string ingress
;;;;
;;;; Core's exact gate is g_reachable_nets.Contains(NET_CJDNS)
;;;; (MaybeFlipIPv6toCJDNS, netbase.cpp:942-949): -cjdnsreachable admits
;;;; :cjdns to the reachable set (apply-config-globals), -onlynet can
;;;; exclude it again.

(test cjdns-flip-on-ingress
  (let ((fc-bytes (%na-hex "fc000001000200030004000500060007")))
    ;; CJDNS not reachable (default set): fc00::/8 strings stay :ipv6 (and
    ;; are unroutable as such, see below).
    (let ((bl.net:*reachable-networks* '(:ipv4 :ipv6)))
      (is (eq :ipv6 (bl.net:maybe-flip-ipv6-to-cjdns :ipv6 fc-bytes)))
      (is (eq :ipv6 (nth-value 0 (bl.net:parse-network-address
                                  "fc00:1:2:3:4:5:6:7")))))
    ;; CJDNS reachable (-cjdnsreachable set): retagged :cjdns.
    (let ((bl.net:*reachable-networks* '(:ipv4 :ipv6 :cjdns)))
      (is (eq :cjdns (bl.net:maybe-flip-ipv6-to-cjdns :ipv6 fc-bytes)))
      (multiple-value-bind (net bytes)
          (bl.net:parse-network-address "fc00:1:2:3:4:5:6:7")
        (is (eq :cjdns net))
        (is (equalp fc-bytes bytes)))
      ;; Non-fc addresses never flip.
      (is (eq :ipv6 (bl.net:maybe-flip-ipv6-to-cjdns
                     :ipv6 (%na-hex "20010db8000000000000000000000001")))))
    ;; -cjdnsreachable but -onlynet excludes cjdns: Core does NOT retag
    ;; (the reachable set, not the raw flag, is the gate).
    (let ((bl.net:*cjdns-reachable* t)
          (bl.net:*reachable-networks* '(:ipv4)))
      (is (eq :ipv6 (bl.net:maybe-flip-ipv6-to-cjdns :ipv6 fc-bytes))))))

;;;; Routability per network (addrman gate)

(test address-routable-per-network
  (is-true (bl.net:address-routable-p
            (bl.net:ipv4-to-mapped-ipv6 1 2 3 4) :ipv4))
  (is-true (bl.net:address-routable-p
            (%na-hex "26064700000000000000000000000001") :ipv6))
  ;; Core IsRoutable/IsValid refusals (netaddress.cpp:398-465) we used to
  ;; store, dial and re-gossip: ::1, link-local, documentation, ORCHID v1/v2.
  (dolist (hex '("00000000000000000000000000000001"
                 "fe800000000000000000000000000001"
                 "20010db8000000000000000000000001"
                 "20010010000000000000000000000001"
                 "20010020000000000000000000000001"))
    (is-false (bl.net:address-routable-p (%na-hex hex) :ipv6) hex))
  ;; IPv4 keeps the deliberate divergence: private AND documentation ranges
  ;; stay routable here (Core rejects both), because private/regtest setups
  ;; and the test suite's stand-in addresses depend on it.
  (is-true (bl.net:address-routable-p
            (bl.net:ipv4-to-mapped-ipv6 192 168 1 1) :ipv4))
  (is-true (bl.net:address-routable-p
            (bl.net:ipv4-to-mapped-ipv6 203 0 113 1) :ipv4))
  (is-true (bl.net:address-routable-p (%na-hex +onion-pubkey-1+) :torv3))
  (is-true (bl.net:address-routable-p (%na-hex +i2p-hash-1+) :i2p))
  (is-true (bl.net:address-routable-p
            (%na-hex "fc000001000200030004000500060007") :cjdns))
  ;; CJDNS without the fc prefix is invalid (Core IsValid).
  (is-false (bl.net:address-routable-p
             (%na-hex "aa000001000200030004000500060007") :cjdns))
  ;; Plain IPv6 inside fc00::/7 (RFC4193) is not routable — must arrive
  ;; tagged CJDNS to count.
  (is-false (bl.net:address-routable-p
             (%na-hex "fc000001000200030004000500060007") :ipv6))
  (is-false (bl.net:address-routable-p
             (%na-hex "fd6b88c08724ca978112ca1bbdcafac2") :ipv6))
  ;; Wrong length for the net.
  (is-false (bl.net:address-routable-p
             (%na-hex "20010db8000000000000000000000001") :torv3))
  ;; All zero.
  (is-false (bl.net:address-routable-p
             (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
             :torv3)))

;;;; Netgroups for the new nets (Core netgroup.cpp:52-77)

(test net-group-key-new-nets
  ;; Tor/I2P: [net-class, addr[0] | 0x0F].
  (let ((pk (%na-hex +onion-pubkey-1+)))   ; addr[0] = #x79
    (is (equal (list 3 (logior #x79 #x0F))
               (coerce (bl.net:net-group-key pk :torv3) 'list))))
  (let ((h (%na-hex +i2p-hash-1+)))        ; addr[0] = #xA2
    (is (equal (list 4 (logior #xA2 #x0F))
               (coerce (bl.net:net-group-key h :i2p) 'list))))
  ;; Same bytes, different net => different group (net class differs).
  (is (not (equalp (bl.net:net-group-key (%na-hex +i2p-hash-1+) :torv3)
                   (bl.net:net-group-key (%na-hex +i2p-hash-1+) :i2p))))
  ;; CJDNS: [5, addr[0], addr[1] | 0x0F] — skips the constant fc prefix bits.
  (let ((c (%na-hex "fc010203000000000000000000000001")))
    (is (equal (list 5 #xFC (logior #x01 #x0F))
               (coerce (bl.net:net-group-key c :cjdns) 'list)))))

(test ip-netgroup-strings
  ;; Dotted-quad behavior unchanged: /16 prefix string.
  (is (string= "103.165" (bl.net:ip-netgroup "103.165.192.4")))
  ;; Onion strings group by [3, addr0|0x0F]; two onions with distinct first
  ;; bytes land in distinct groups, hostnames in none.
  (let ((g1 (bl.net:ip-netgroup +onion-str-1+))   ; 0x79
        (g2 (bl.net:ip-netgroup +onion-str-2+)))  ; 0x53
    (is (stringp g1))
    (is (stringp g2))
    (is (not (string= g1 g2))))
  (is (null (bl.net:ip-netgroup "seed.bitcoin.sipa.be"))))

;;;; Reachability / dialability

(test dialable-network-p-config-matrix
  "P2 config-aware dialability: every net x {no proxy, -proxy, -onion,
-onion=0 with -proxy, -cjdnsreachable}. torv3 is dialable iff a Tor-capable
proxy is configured (*onion-proxy* — apply-config-globals defaults it to
-proxy, and -onion=0 clears it, Core init.cpp:1766-1780); cjdns iff
-cjdnsreachable; i2p never; ipv4/ipv6 always. -onlynet never affects
dialability (it is applied separately, via reachable-network-p)."
  (let ((tor (bl.net:make-proxy :host "127.0.0.1" :port 9050)))
    ;; No proxy, no flags: IP-only, exactly as before P2.
    (let ((bl.net:*proxy* nil)
          (bl.net:*onion-proxy* nil)
          (bl.net:*cjdns-reachable* nil))
      (is-true (bl.net:dialable-network-p :ipv4))
      (is-true (bl.net:dialable-network-p :ipv6))
      (is-false (bl.net:dialable-network-p :torv3))
      (is-false (bl.net:dialable-network-p :i2p))
      (is-false (bl.net:dialable-network-p :cjdns)))
    ;; -proxy: apply-config-globals mirrors it into *onion-proxy* => torv3
    ;; dialable. (dialable-network-p itself reads only *onion-proxy*.)
    (let ((bl.net:*proxy* tor)
          (bl.net:*onion-proxy* tor)
          (bl.net:*cjdns-reachable* nil))
      (is-true (bl.net:dialable-network-p :torv3))
      (is-false (bl.net:dialable-network-p :i2p))
      (is-false (bl.net:dialable-network-p :cjdns)))
    ;; -onion alone (no general proxy): torv3 dialable, clearnet direct.
    (let ((bl.net:*proxy* nil)
          (bl.net:*onion-proxy* tor))
      (is-true (bl.net:dialable-network-p :torv3))
      (is-true (bl.net:dialable-network-p :ipv4)))
    ;; -proxy with -onion=0: *onion-proxy* cleared => torv3 NOT dialable
    ;; even though a general proxy exists.
    (let ((bl.net:*proxy* tor)
          (bl.net:*onion-proxy* nil))
      (is-false (bl.net:dialable-network-p :torv3)))
    ;; -cjdnsreachable: cjdns dialable (plain TCP into the cjdroute TUN).
    (let ((bl.net:*cjdns-reachable* t)
          (bl.net:*onion-proxy* nil))
      (is-true (bl.net:dialable-network-p :cjdns))
      (is-false (bl.net:dialable-network-p :torv3))
      (is-false (bl.net:dialable-network-p :i2p)))))

(test proxy-for-target-per-network
  "Per-target-network proxy pick (Core ConnectNode, net.cpp:449): .onion =>
*onion-proxy* (refused when none — never raw-dialed/DNS-leaked); .b32.i2p
=> always refused; everything else => *proxy* (NIL = direct dial)."
  (let ((tor (bl.net:make-proxy :host "10.0.0.2" :port 9051))
        (all (bl.net:make-proxy :host "10.0.0.1" :port 9050)))
    ;; Onion with a Tor proxy configured.
    (let ((bl.net:*proxy* all)
          (bl.net:*onion-proxy* tor))
      (multiple-value-bind (proxy refusal)
          (bl.net:proxy-for-target +onion-str-1+)
        (is (eq tor proxy))          ; -onion's proxy, not -proxy's
        (is (null refusal)))
      ;; Clearnet targets and hostnames use *proxy*.
      (multiple-value-bind (proxy refusal)
          (bl.net:proxy-for-target "203.0.113.7")
        (is (eq all proxy))
        (is (null refusal)))
      (multiple-value-bind (proxy refusal)
          (bl.net:proxy-for-target "seed.example.org")
        (is (eq all proxy))
        (is (null refusal)))
      ;; CJDNS literal: *proxy* covers it (Core: unsuffixed -proxy sets the
      ;; cjdns proxy too, init.cpp:1735).
      (multiple-value-bind (proxy refusal)
          (bl.net:proxy-for-target "fc00:1:2:3:4:5:6:7")
        (is (eq all proxy))
        (is (null refusal)))
      ;; I2P is refused even with proxies configured (SAM is P4).
      (multiple-value-bind (proxy refusal)
          (bl.net:proxy-for-target +i2p-str-1+)
        (is (null proxy))
        (is (stringp refusal))))
    ;; No proxies at all: onion refused, clearnet/cjdns dial direct.
    (let ((bl.net:*proxy* nil)
          (bl.net:*onion-proxy* nil))
      (multiple-value-bind (proxy refusal)
          (bl.net:proxy-for-target +onion-str-1+)
        (is (null proxy))
        (is (stringp refusal)))
      (multiple-value-bind (proxy refusal)
          (bl.net:proxy-for-target "fc00:1:2:3:4:5:6:7")
        (is (null proxy))
        (is (null refusal))))))

(test reachable-network-p-follows-special
  (let ((bl.net:*reachable-networks* '(:ipv4 :torv3)))
    (is-true (bl.net:reachable-network-p :ipv4))
    (is-true (bl.net:reachable-network-p :torv3))
    (is-false (bl.net:reachable-network-p :ipv6))))

(test select-dialable-never-returns-non-ip
  "WITHOUT a Tor proxy, a book holding ONLY onion/i2p records yields nothing
to automatic outbound selection — even with every network in the reachable
set; mixed books only ever yield the IP records."
  (let ((book (bl.net:make-address-book))
        (bl.net:*reachable-networks*
          (copy-list bl.net:+bip155-networks+))
        (bl.net:*onion-proxy* nil)
        (bl.net:*cjdns-reachable* nil))
    (is-true (bl.net:address-book-add
              book (bl.net:make-peer-address
                    :net :torv3 :ip (%na-hex +onion-pubkey-1+) :port 8333
                    :services 1 :last-seen (bl.ser:get-unix-time))))
    (is-true (bl.net:address-book-add
              book (bl.net:make-peer-address
                    :net :i2p :ip (%na-hex +i2p-hash-1+) :port 0
                    :services 1 :last-seen (bl.ser:get-unix-time))))
    ;; Raw select can see them; the dialable filter never lets them out.
    (is (not (null (bl.net:address-book-select book))))
    (is (null (bl.net:select-dialable-address book :tries 200)))
    ;; Add an IPv4 record: the filter now yields only that one.
    (is-true (bl.net:address-book-add
              book (bl.net:make-peer-address
                    :ip (bl.net:ipv4-to-mapped-ipv6 8 8 8 8)
                    :port 8333 :services 1
                    :last-seen (bl.ser:get-unix-time))))
    (dotimes (_ 20)
      (let ((pa (bl.net:select-dialable-address book :tries 200)))
        (is (not (null pa)))
        (is (eq :ipv4 (bl.net:peer-address-network pa)))))))

(test select-dialable-yields-onion-with-proxy-never-i2p
  "WITH a Tor proxy, automatic selection may yield torv3 records — but NEVER
i2p, under any configuration (the P4 gap stays closed)."
  (let ((book (bl.net:make-address-book))
        (bl.net:*reachable-networks*
          (copy-list bl.net:+bip155-networks+))
        (bl.net:*onion-proxy*
          (bl.net:make-proxy :host "127.0.0.1" :port 9050))
        (bl.net:*cjdns-reachable* t))
    (is-true (bl.net:address-book-add
              book (bl.net:make-peer-address
                    :net :torv3 :ip (%na-hex +onion-pubkey-1+) :port 8333
                    :services 1 :last-seen (bl.ser:get-unix-time))))
    (is-true (bl.net:address-book-add
              book (bl.net:make-peer-address
                    :net :i2p :ip (%na-hex +i2p-hash-1+) :port 0
                    :services 1 :last-seen (bl.ser:get-unix-time))))
    ;; The onion record is now selectable...
    (let ((pa (bl.net:select-dialable-address book :tries 500)))
      (is (not (null pa)))
      (is (eq :torv3 (bl.net:peer-address-network pa))))
    ;; ...and i2p never comes out, however many draws.
    (dotimes (_ 50)
      (let ((pa (bl.net:select-dialable-address book :tries 50)))
        (when pa
          (is (not (eq :i2p (bl.net:peer-address-network pa)))))))
    ;; Onion selection dies with the proxy (e.g. -onion=0): nothing dialable
    ;; remains in this book but the i2p record, which stays excluded.
    (let ((bl.net:*onion-proxy* nil))
      (is (null (bl.net:select-dialable-address book :tries 200))))))

(test select-dialable-honors-onlynet
  "-onlynet=ipv6 (reachable set without :ipv4) excludes IPv4 records from
automatic selection even though IPv4 is dialable."
  (let ((book (bl.net:make-address-book)))
    (bl.net:address-book-add
     book (bl.net:make-peer-address
           :ip (bl.net:ipv4-to-mapped-ipv6 8 8 4 4)
           :port 8333 :services 1
           :last-seen (bl.ser:get-unix-time)))
    (let ((bl.net:*reachable-networks* '(:ipv6)))
      (is (null (bl.net:select-dialable-address book :tries 200))))
    (let ((bl.net:*reachable-networks* '(:ipv4)))
      (is (not (null (bl.net:select-dialable-address book :tries 200)))))))

(defun %bad-port-p (port)
  "Core IsBadPort. The one reach into the deny-list predicate in this file."
  (bl.net::bad-port-p port))

(defun %book-with-record (net ip port)
  "An address book holding exactly one record."
  (let ((book (bl.net:make-address-book)))
    (bl.net:address-book-add
     book (bl.net:make-peer-address
           :net net :ip ip :port port :services 1
           :last-seen (bl.ser:get-unix-time)))
    book))

(test bad-ports-are-never-selected-for-an-automatic-dial
  "GA10 d9aadbc5. Core refuses an automatic outbound connection to a port on
IsBadPort's deny-list — `nTries < 50 && (addr.IsIPv4() || addr.IsIPv6()) &&
IsBadPort(addr.GetPort())' (net.cpp:2854), the list itself at
netbase.cpp:847-935 and documented service by service in
doc/p2p-bad-ports.md. Nothing in this tree implemented it, so any peer could
gossip `victim:25' / `:22' / `:3306' / `:6667' and we would store it, select
it, open a TCP connection and speak the Bitcoin protocol at a third party's
SMTP, SSH, MySQL or IRC daemon — the cross-protocol abuse that document exists
for — while wasting an automatic outbound slot on an address that can never
complete a handshake.

SELECT-DIALABLE-ADDRESS is the choke point every automatic path is required to
go through (outbound refill, block-relay slots, feelers), which is where Core
applies it too: not in Select, and not on the paths that name a destination, so
-addnode to a strange port still works."
  (is (= 85 (loop for port from 0 to 65535 count (%bad-port-p port)))
      "Core's IsBadPort switch has 85 cases and the list is extracted from it; ~
a different total means an entry was added, dropped or mistyped")
  (dolist (port '(1 7 22 23 25 53 110 119 123 143 179 389 465 587 636 993 995
                  3306 3389 5432 5900 6000 6667 6697 10080 27017))
    (is-true (%bad-port-p port) "port ~D must be on the deny-list" port))
  (dolist (port '(0 2 8333 18333 18444 38333 9050 4444 65535))
    (is-false (%bad-port-p port) "port ~D must NOT be on the deny-list" port))
  ;; Through the shipped filter: an SMTP record never comes out, however many
  ;; draws, and a good-port record from the same address does.
  (let ((bl.net:*reachable-networks* (copy-list bl.net:+bip155-networks+)))
    (let ((smtp (%book-with-record :ipv4 (bl.net:ipv4-to-mapped-ipv6 198 51 100 7) 25)))
      (is (not (null (bl.net:address-book-select smtp)))
          "control: raw select still sees the record, so the filter is what drops it")
      (is (null (bl.net:select-dialable-address smtp :tries 200))
          "an SMTP-port record reached the automatic dial filter"))
    (let ((good (%book-with-record :ipv4 (bl.net:ipv4-to-mapped-ipv6 198 51 100 7) 8333)))
      (is (not (null (bl.net:select-dialable-address good :tries 200)))
          "control: the same address on the P2P port is still selectable"))
    ;; Core applies the check to IPv4/IPv6 only — a port number says nothing
    ;; about an onion destination, and Core's guard names the two IP families.
    (let ((bl.net:*onion-proxy* (bl.net:make-proxy :host "127.0.0.1" :port 9050))
          (onion (%book-with-record :torv3 (%na-hex +onion-pubkey-1+) 25)))
      (is (not (null (bl.net:select-dialable-address onion :tries 200)))
          "an onion record must not be filtered on its port"))))

;;;; IPv6 text parsing (string-to-ip-bytes / %parse-ipv6-string)
;;;;
;;;; Address strings are Core's own test inputs (netbase_tests.cpp
;;;; netbase_properties/netbase_getgroup ResolveIP calls, which reach
;;;; inet_pton); expected bytes follow from the RFC4291 text rules.

(test ipv6-parse-core-vectors
  (flet ((p (s) (bl.net:string-to-ip-bytes s)))
    ;; Full 8-group colon-hex.
    (is (equalp (%na-hex "00010002000300040005000600070008") (p "1:2:3:4:5:6:7:8")))
    ;; "::" compression, leading/trailing/inner.
    (is (equalp (%na-hex "00000000000000000000000000000001") (p "::1")))
    (is (equalp (%na-hex "20010db8000000000000000000000001") (p "2001:db8::1")))
    (is (equalp (%na-hex "20010000000000000000000000008888") (p "2001::8888")))
    (is (equalp (%na-hex "00010002000300040005000600070000") (p "1:2:3:4:5:6:7::")))
    (is (equalp (%na-hex "00000000000000000000000000000000") (p "::")))
    ;; Case-insensitive hex (Core: "FC00::", "64:FF9B::").
    (is (equalp (%na-hex "fc000000000000000000000000000000") (p "FC00::")))
    ;; Embedded IPv4 tails: mapped (-> :ipv4 net), RFC6145-translated, plain.
    (is (equalp (%na-hex "00000000000000000000ffff7f000001") (p "::ffff:127.0.0.1")))
    (is (equalp (%na-hex "00000000000000000000ffffc0a80101") (p "::FFFF:192.168.1.1")))
    (is (equalp (%na-hex "0000000000000000ffff000001020304") (p "::FFFF:0:102:304")))
    (is (equalp (%na-hex "0064ff9b000000000000000001020304") (p "64:FF9B::102:304")))
    ;; Dotted quad still parses to the mapped form.
    (is (equalp (bl.net:ipv4-to-mapped-ipv6 8 8 8 8) (p "8.8.8.8")))
    ;; Invalid forms all return NIL (total function, never signals).
    (dolist (bad '("1:2:3:4:5:6:7:8:9"   ; 9 groups
                   "1:2:3:4:5:6:7:8::"   ; 8 groups + "::"
                   "1:2:3"               ; too few, no "::"
                   "1::2::3"             ; two "::"
                   ":::"                 ; ditto
                   "1:2:3:4:5:6:7:8%zone" ; scoped
                   "fe80::1%eth0"        ; scoped
                   "12345::1"            ; >4 hex digits
                   "g::1"                ; non-hex
                   "1.2.3.4::"           ; v4 not in the last 32 bits
                   "::ffff:1.2.3.4.5"    ; 5-part quad
                   "256.1.1.1"           ; v4 octet out of range
                   "-1.2.3.4"            ; sign
                   "1.2.3"               ; short quad
                   "seed.example.org"    ; hostname
                   ""))
      (is (null (p bad)) "~S should not parse" bad))))

(test parse-network-address-ipv6-nets
  "parse-network-address types IPv6 text right: mapped quads are :ipv4 (Core
IsIPv4 on ::FFFF:a.b.c.d), everything else :ipv6 (:cjdns handled in
cjdns-flip-on-ingress)."
  (multiple-value-bind (net bytes)
      (bl.net:parse-network-address "::ffff:127.0.0.1")
    (is (eq :ipv4 net))
    (is (equalp (bl.net:ipv4-to-mapped-ipv6 127 0 0 1) bytes)))
  (multiple-value-bind (net bytes)
      (bl.net:parse-network-address "1:2:3:4:5:6:7:8")
    (is (eq :ipv6 net))
    (is (equalp (%na-hex "00010002000300040005000600070008") bytes)))
  ;; Round-trip: our uncompressed rendering re-parses to the same bytes.
  (let ((bytes (%na-hex "20010db8000000000000000000000001")))
    (multiple-value-bind (net rt)
        (bl.net:parse-network-address
         (bl.net:ip-bytes-to-string bytes))
      (is (eq :ipv6 net))
      (is (equalp bytes rt)))))

;;;; Netgroups: Core netbase_getgroup vectors (netbase_tests.cpp:329-343,
;;;; adapted: NoAsmap, so IPv4 /16 and IPv6 /32).
;;;;
;;;; Deliberate divergence retained from the pre-P1 code: private IPv4
;;;; (RFC1918 etc.) still gets a real group here (Core: [0] unroutable) —
;;;; regtest/private setups rely on it.

(test net-group-key-core-vectors
  (flet ((g (s) (multiple-value-bind (net bytes)
                    (bl.net:parse-network-address s)
                  (coerce (bl.net:net-group-key bytes net)
                          'list))))
    (let ((bl.net:*reachable-networks* '(:ipv4 :ipv6)))
      ;; IPv4 -> [1, /16].
      (is (equal '(1 1 2) (g "1.2.3.4")))
      ;; Linked-IPv4 carriers group as the tunneled IPv4's /16 with Core's
      ;; NET_IPV4 class byte (GetNetClass returns NET_IPV4 for them).
      (is (equal '(1 1 2) (g "::FFFF:0:102:304")))                       ; RFC6145
      (is (equal '(1 1 2) (g "64:FF9B::102:304")))                       ; RFC6052
      (is (equal '(1 1 2) (g "2002:102:304:9999:9999:9999:9999:9999")))  ; RFC3964
      (is (equal '(1 1 2) (g "2001:0:9999:9999:9999:9999:FEFD:FCFB")))   ; RFC4380
      ;; he.net -> /36; other IPv6 -> /32.
      (is (equal '(2 32 1 4 112 175) (g "2001:470:abcd:9999:9999:9999:9999:9999")))
      (is (equal '(2 32 1 32 1) (g "2001:2001:9999:9999:9999:9999:9999:9999")))
      ;; fc00::/7 arriving untagged (:ipv6) is unroutable -> [0], like Core.
      (is (equal '(0) (g "fc00:1:2:3:4:5:6:7")))
      (is (equal '(0) (g "fd6b:88c0:8724:ca97:8112:ca1b:bdca:fac2"))))
    ;; The same fc00 bytes tagged :cjdns keep their real 12-bit group.
    (is (equal (list 5 #xFC (logior #x00 #x0F))
               (coerce (bl.net:net-group-key
                        (%na-hex "fc000001000200030004000500060007") :cjdns)
                       'list)))))

(test ip-netgroup-ipv6-strings
  "ip-netgroup (string level, used by eviction/diversification) gives IPv6 a
real /32 group and distinct operators distinct groups — inbound IPv6/CJDNS
peers are grouped through this exact path (their socket address strings)."
  (let ((bl.net:*reachable-networks* '(:ipv4 :ipv6 :cjdns)))
    (let ((a (bl.net:ip-netgroup "2001:db8::1"))
          (b (bl.net:ip-netgroup "2001:db8::2"))
          (c (bl.net:ip-netgroup "2607:f8b0::1")))
      (is (stringp a))
      (is (string= a b))               ; same /32
      (is (not (string= a c))))        ; different /32
    ;; fc00::/8 inbound under -cjdnsreachable groups as CJDNS (flip at the
    ;; string ingress), not as one IPv6 blob.
    (let ((g (bl.net:ip-netgroup "fc00:1:2:3:4:5:6:7")))
      (is (string= "5.252.15" g)))))   ; [5, #xFC, #x01|#x0F] rendered

;;;; peer-address-string

(test peer-address-string-all-nets
  (is (string= "1.2.3.4"
               (bl.net:peer-address-string
                (bl.net:make-peer-address
                 :ip (bl.net:ipv4-to-mapped-ipv6 1 2 3 4)))))
  (is (string= +onion-str-1+
               (bl.net:peer-address-string
                (bl.net:make-peer-address
                 :net :torv3 :ip (%na-hex +onion-pubkey-1+)))))
  (is (string= +i2p-str-1+
               (bl.net:peer-address-string
                (bl.net:make-peer-address
                 :net :i2p :ip (%na-hex +i2p-hash-1+))))))
