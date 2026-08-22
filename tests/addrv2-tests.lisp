(in-package #:bitcoin-lisp.tests)

(def-suite :addrv2-tests
  :description "Tests for ADDRv2 (BIP 155) support"
  :in :bitcoin-lisp-tests)

(in-suite :addrv2-tests)

;;; Helper to build a raw addrv2 entry as bytes
(defun make-addrv2-entry-bytes (timestamp services network-id addr-bytes port)
  "Build raw bytes for a single addrv2 entry."
  (coerce
   (flexi-streams:with-output-to-sequence (s)
     (bitcoin-lisp.serialization:write-uint32-le s timestamp)
     (bitcoin-lisp.serialization:write-compact-size s services)
     (bitcoin-lisp.serialization:write-uint8 s network-id)
     (bitcoin-lisp.serialization:write-compact-size s (length addr-bytes))
     (write-sequence addr-bytes s)
     ;; Port big-endian
     (write-byte (ash port -8) s)
     (write-byte (logand port #xFF) s))
   '(simple-array (unsigned-byte 8) (*))))

;;; Task 3.1: Parse addrv2 entry with IPv4 address
(test parse-addrv2-ipv4
  "Parse an addrv2 entry with IPv4 (network ID 1, 4-byte address)."
  (let* ((addr-bytes #(192 168 1 42))
         (entry (make-addrv2-entry-bytes 1000000 1 1 addr-bytes 8333)))
    (flexi-streams:with-input-from-sequence (s entry)
      (multiple-value-bind (addr timestamp network-id)
          (bitcoin-lisp.serialization:read-net-addr-v2 s)
        (is (not (null addr)))
        (is (= 1000000 timestamp))
        (is (= 1 network-id))
        (is (= 8333 (bitcoin-lisp.serialization:net-addr-port addr)))
        (is (= 1 (bitcoin-lisp.serialization:net-addr-services addr)))
        ;; Should be IPv4-mapped IPv6
        (let ((ip (bitcoin-lisp.serialization:net-addr-ip addr)))
          (is (= #xFF (aref ip 10)))
          (is (= #xFF (aref ip 11)))
          (is (= 192 (aref ip 12)))
          (is (= 168 (aref ip 13)))
          (is (= 1 (aref ip 14)))
          (is (= 42 (aref ip 15))))))))

;;; Task 3.1: Parse addrv2 entry with IPv6 address
(test parse-addrv2-ipv6
  "Parse an addrv2 entry with IPv6 (network ID 2, 16-byte address)."
  (let* ((addr-bytes (make-array 16 :element-type '(unsigned-byte 8)
                                    :initial-contents '(#x20 #x01 #x0d #xb8
                                                        0 0 0 0 0 0 0 0
                                                        0 0 0 1)))
         (entry (make-addrv2-entry-bytes 2000000 9 2 addr-bytes 18333)))
    (flexi-streams:with-input-from-sequence (s entry)
      (multiple-value-bind (addr timestamp network-id)
          (bitcoin-lisp.serialization:read-net-addr-v2 s)
        (is (not (null addr)))
        (is (= 2000000 timestamp))
        (is (= 2 network-id))
        (is (= 18333 (bitcoin-lisp.serialization:net-addr-port addr)))
        (is (= 9 (bitcoin-lisp.serialization:net-addr-services addr)))
        ;; IP should be the raw 16 bytes
        (is (equalp addr-bytes (bitcoin-lisp.serialization:net-addr-ip addr)))))))

;;; TorV3 entries decode to real typed addresses (P1 address layer).
(test parse-addrv2-torv3-typed
  "Parse an addrv2 entry with TorV3 (network ID 4, 32-byte): a typed net-addr."
  (let* ((addr-bytes (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xAB))
         (entry (make-addrv2-entry-bytes 3000000 1 4 addr-bytes 9050)))
    (flexi-streams:with-input-from-sequence (s entry)
      (multiple-value-bind (addr timestamp network-id)
          (bitcoin-lisp.serialization:read-net-addr-v2 s)
        (is (not (null addr)))
        (is (= 3000000 timestamp))
        (is (= bitcoin-lisp.serialization:+addrv2-net-torv3+ network-id))
        (is (eq :torv3 (bitcoin-lisp.serialization:net-addr-network addr)))
        (is (equalp addr-bytes (bitcoin-lisp.serialization:net-addr-ip addr)))
        (is (= 9050 (bitcoin-lisp.serialization:net-addr-port addr)))))))

;;; Task 3.1: Skip unknown network ID
(test parse-addrv2-unknown-network
  "An entry with unknown network ID is skipped without error."
  (let* ((addr-bytes (make-array 8 :element-type '(unsigned-byte 8) :initial-element 0))
         (entry (make-addrv2-entry-bytes 1000000 1 99 addr-bytes 1234)))
    (flexi-streams:with-input-from-sequence (s entry)
      (let ((addr (bitcoin-lisp.serialization:read-net-addr-v2 s)))
        (is (null addr))
        ;; Stream should be fully consumed
        (is (= (length entry) (file-position s)))))))

;;; A recognized network id with the wrong length REJECTS the message.
;;; Core's SetNetFromBIP155Network throws for founding nets with a bad size
;;; ("BIP155 IPv4 address with length 5 (should be 4)", net_tests.cpp
;;; cnetaddr_unserialize_v2) — unlike unknown ids, which are skipped.
(test parse-addrv2-mismatched-length-errors
  (dolist (case '((1 8) (2 4) (4 0) (5 3) (6 1)))
    (destructuring-bind (net-id len) case
      (let* ((addr-bytes (make-array len :element-type '(unsigned-byte 8)
                                         :initial-element 0))
             (entry (make-addrv2-entry-bytes 1000000 1 net-id addr-bytes 8333)))
        (flexi-streams:with-input-from-sequence (s entry)
          (signals error (bitcoin-lisp.serialization:read-net-addr-v2 s)))))))

;;; Extreme length rejects the message even for an unknown id (Core
;;; "Address too long: ... > 512").
(test parse-addrv2-address-too-long-errors
  (let ((entry (coerce
                (flexi-streams:with-output-to-sequence (s)
                  (bitcoin-lisp.serialization:write-uint32-le s 1000000)
                  (bitcoin-lisp.serialization:write-compact-size s 1)
                  (bitcoin-lisp.serialization:write-uint8 s #xAA)
                  (bitcoin-lisp.serialization:write-compact-size s 513)
                  (write-sequence (make-array 513 :element-type '(unsigned-byte 8)
                                                  :initial-element 1) s)
                  (write-byte 32 s) (write-byte 141 s))
                '(simple-array (unsigned-byte 8) (*)))))
    (flexi-streams:with-input-from-sequence (s entry)
      (signals error (bitcoin-lisp.serialization:read-net-addr-v2 s)))))

;;; Task 3.1: Compact-size services round-trip
(test addrv2-compact-size-services
  "Services field uses compact-size encoding and round-trips correctly."
  (let* ((large-services (logior 1 (ash 1 10)))  ; NODE_NETWORK | NODE_NETWORK_LIMITED = 1025
         (addr-bytes #(10 0 0 1))
         (entry (make-addrv2-entry-bytes 1000000 large-services 1 addr-bytes 8333)))
    (flexi-streams:with-input-from-sequence (s entry)
      (multiple-value-bind (addr timestamp network-id)
          (bitcoin-lisp.serialization:read-net-addr-v2 s)
        (declare (ignore timestamp network-id))
        (is (not (null addr)))
        (is (= large-services (bitcoin-lisp.serialization:net-addr-services addr)))))))

;;; Task 3.1: Build and parse sendaddrv2 message
(test sendaddrv2-message-roundtrip
  "sendaddrv2 message has correct header and empty payload."
  (let ((msg (bitcoin-lisp.serialization:make-sendaddrv2-message)))
    (is (not (null msg)))
    ;; Message should be 24 bytes (header only, zero payload)
    (is (= 24 (length msg)))
    ;; Parse the header
    (flexi-streams:with-input-from-sequence (s msg)
      (let ((header (bitcoin-lisp.serialization:read-message-header s)))
        (is (string= "sendaddrv2" (bitcoin-lisp.serialization:message-header-command header)))
        (is (= 0 (bitcoin-lisp.serialization:message-header-payload-length header)))))))

;;; Task 3.1: Build and parse addrv2 message with multiple entries
(test addrv2-message-roundtrip
  "Build an addrv2 message with multiple entries and parse it back."
  (let* ((addr1 (bitcoin-lisp.serialization:make-net-addr
                  :services 1
                  :ip (bitcoin-lisp.networking:ipv4-to-mapped-ipv6 10 0 0 1)
                  :port 8333))
         (addr2 (bitcoin-lisp.serialization:make-net-addr
                  :services 9
                  :ip (make-array 16 :element-type '(unsigned-byte 8)
                                     :initial-contents '(#x20 #x01 0 0 0 0 0 0
                                                         0 0 0 0 0 0 0 1))
                  :port 18333))
         (entries (list (list addr1 bitcoin-lisp.serialization:+addrv2-net-ipv4+ 1000000)
                        (list addr2 bitcoin-lisp.serialization:+addrv2-net-ipv6+ 2000000)))
         (msg (bitcoin-lisp.serialization:make-addrv2-message entries)))
    ;; Parse the message: skip 24-byte header to get payload
    (let* ((payload (subseq msg 24))
           (parsed (bitcoin-lisp.serialization:parse-addrv2-payload payload)))
      (is (= 2 (length parsed)))
      ;; First entry: IPv4
      (destructuring-bind (pa1 ts1 nid1) (first parsed)
        (is (= 1000000 ts1))
        (is (= 1 nid1))
        (is (= 8333 (bitcoin-lisp.serialization:net-addr-port pa1)))
        (is (= 1 (bitcoin-lisp.serialization:net-addr-services pa1))))
      ;; Second entry: IPv6
      (destructuring-bind (pa2 ts2 nid2) (second parsed)
        (is (= 2000000 ts2))
        (is (= 2 nid2))
        (is (= 18333 (bitcoin-lisp.serialization:net-addr-port pa2)))
        (is (= 9 (bitcoin-lisp.serialization:net-addr-services pa2)))))))

;;; handle-addrv2 stores only REACHABLE networks (Core "Do not store
;;; addresses outside our network"): with the default reachable set
;;; {ipv4, ipv6}, a TorV3 entry parses but is not stored.
(test addr-fetch-peer-disconnects-once-it-delivers-addresses
  "An addr-fetch peer (-seednode) exists only to hand over addresses and is
disconnected as soon as it does (Core net_processing.cpp:4117-4121). Core
requires MORE THAN ONE address, so a peer that merely self-announces does not
end the fetch — without that, a seed answering with its own address alone would
be dropped before delivering anything useful."
  (flet ((deliver (conn-type count)
           (let* ((book (bitcoin-lisp.networking:make-address-book))
                  (peer (bitcoin-lisp.networking:make-peer
                         :address "10.9.9.9" :conn-type conn-type
                         :state :ready))
                  (now (bitcoin-lisp.serialization:get-unix-time))
                  (entries (loop for i below count
                                 collect (cons (bitcoin-lisp.serialization:make-net-addr
                                                :services 1
                                                :ip (bitcoin-lisp.networking:ipv4-to-mapped-ipv6
                                                     10 0 0 (1+ i))
                                                :port 8333)
                                               now))))
             ;; A generous token bucket, so the rate limiter is not what
             ;; decides the outcome here.
             (setf (bitcoin-lisp.networking::peer-addr-token-bucket peer) 100d0)
             (bitcoin-lisp.networking::%process-gossiped-addresses
              peer entries count book nil)
             (bitcoin-lisp.networking:peer-state peer))))
    (is (eq :disconnected (deliver :addr-fetch 5))
        "an addr-fetch peer stayed connected after delivering addresses")
    (is-false (eq :disconnected (deliver :addr-fetch 1))
              "an addr-fetch peer was dropped on a single self-announcement")
    ;; An ordinary outbound peer is never dropped for answering our getaddr.
    (is-false (eq :disconnected (deliver :outbound-full-relay 5)))))

(test handle-addrv2-filters-networks
  "handle-addrv2 adds IPv4/IPv6 to address book, skips unreachable TorV3."
  (let* ((bitcoin-lisp.networking:*reachable-networks* '(:ipv4 :ipv6))
         (book (bitcoin-lisp.networking:make-address-book))
         (now (bitcoin-lisp.serialization:get-unix-time))
         ;; Build payload with IPv4, IPv6, and TorV3 entries
         (payload
           (coerce
            (flexi-streams:with-output-to-sequence (s)
              (bitcoin-lisp.serialization:write-compact-size s 3)
              ;; IPv4 entry
              (bitcoin-lisp.serialization:write-net-addr-v2
               s
               (bitcoin-lisp.serialization:make-net-addr :services 1
                 :ip (bitcoin-lisp.networking:ipv4-to-mapped-ipv6 10 0 0 1)
                 :port 8333)
               bitcoin-lisp.serialization:+addrv2-net-ipv4+ now)
              ;; IPv6 entry
              (bitcoin-lisp.serialization:write-net-addr-v2
               s
               (bitcoin-lisp.serialization:make-net-addr :services 1
                 :ip (make-array 16 :element-type '(unsigned-byte 8)
                                    :initial-contents '(#x20 #x01 0 0 0 0 0 0
                                                        0 0 0 0 0 0 0 2))
                 :port 8333)
               bitcoin-lisp.serialization:+addrv2-net-ipv6+ now)
              ;; TorV3 entry (should be skipped)
              (bitcoin-lisp.serialization:write-uint32-le s now)
              (bitcoin-lisp.serialization:write-compact-size s 1)
              (bitcoin-lisp.serialization:write-uint8 s bitcoin-lisp.serialization:+addrv2-net-torv3+)
              (bitcoin-lisp.serialization:write-compact-size s 32)
              (write-sequence (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xAA) s)
              (write-byte 0 s) (write-byte 80 s))  ; port 80
            '(simple-array (unsigned-byte 8) (*)))))
    (let ((added (bitcoin-lisp.networking:handle-addrv2 nil payload book)))
      ;; Only IPv4 and IPv6 should be added (TorV3 skipped)
      (is (= 2 added))
      (is (= 2 (bitcoin-lisp.networking:address-book-count book))))))

;;; Task 3.1: IPv4 from addrv2 converted to mapped-IPv6
(test addrv2-ipv4-to-mapped-ipv6
  "IPv4 address from addrv2 is stored as IPv4-mapped IPv6 in address book."
  (let* ((book (bitcoin-lisp.networking:make-address-book))
         (now (bitcoin-lisp.serialization:get-unix-time))
         (payload
           (coerce
            (flexi-streams:with-output-to-sequence (s)
              (bitcoin-lisp.serialization:write-compact-size s 1)
              (bitcoin-lisp.serialization:write-net-addr-v2
               s
               (bitcoin-lisp.serialization:make-net-addr :services 1
                 :ip (bitcoin-lisp.networking:ipv4-to-mapped-ipv6 172 16 0 5)
                 :port 8333)
               bitcoin-lisp.serialization:+addrv2-net-ipv4+ now))
            '(simple-array (unsigned-byte 8) (*)))))
    (bitcoin-lisp.networking:handle-addrv2 nil payload book)
    (is (= 1 (bitcoin-lisp.networking:address-book-count book)))
    ;; Look up with the mapped IPv6 address
    (let* ((mapped-ip (bitcoin-lisp.networking:ipv4-to-mapped-ipv6 172 16 0 5))
           (entry (bitcoin-lisp.networking:address-book-lookup book mapped-ip 8333)))
      (is (not (null entry)))
      (let ((ip (bitcoin-lisp.networking:peer-address-ip entry)))
        ;; Verify it's IPv4-mapped
        (is (= #xFF (aref ip 10)))
        (is (= #xFF (aref ip 11)))
        (is (= 172 (aref ip 12)))
        (is (= 16 (aref ip 13)))
        (is (= 0 (aref ip 14)))
        (is (= 5 (aref ip 15)))))))

;;; Regression: services is a u64 bitmask, not a length. Core deserializes
;;; it with CompactSizeFormatter<false> (protocol.h:446) — no range check.
;;; Our default read-compact-size cap made any peer advertising a service
;;; bit >= 26 look malformed, and the whole addrv2 message (e.g. a
;;; 1000-entry getaddr reply) was dropped and the peer disconnected.
;;; Observed live on mainnet 2026-07-12 after #245 started sending getaddr.
(test parse-addrv2-large-services-bitmask
  "addrv2 entries with high service bits (>= bit 26) must parse."
  (let* ((services (logior (ash 1 26) (ash 1 30) 1033)) ; > +max-compact-size+
         (entry (make-addrv2-entry-bytes 1720000000 services 1 #(203 0 113 5) 8333)))
    (flexi-streams:with-input-from-sequence (s entry)
      (multiple-value-bind (addr timestamp network-id)
          (bitcoin-lisp.serialization:read-net-addr-v2 s)
        (declare (ignore timestamp network-id))
        (is (not (null addr)))
        (is (= services (bitcoin-lisp.serialization:net-addr-services addr))))))
  ;; A whole message: exotic-services entry followed by a normal one —
  ;; the stream stays aligned and neither entry is lost.
  (let* ((e1 (make-addrv2-entry-bytes 1720000000 (ash 1 33) 1 #(1 2 3 4) 8333))
         (e2 (make-addrv2-entry-bytes 1720000001 9 1 #(5 6 7 8) 8334))
         (payload (coerce
                   (flexi-streams:with-output-to-sequence (s)
                     (bitcoin-lisp.serialization:write-compact-size s 2)
                     (write-sequence e1 s)
                     (write-sequence e2 s))
                   '(simple-array (unsigned-byte 8) (*))))
         (addrs (bitcoin-lisp.serialization:parse-addrv2-payload payload)))
    (is (= 2 (length addrs)))))

;;;; ============================================================
;;;; P1: network-typed addrv2 (Core net_tests.cpp cnetaddr_unserialize_v2
;;;; address payloads, wrapped in full addrv2 entries)
;;;; ============================================================

(defun %av2-hex (s) (bitcoin-lisp.crypto:hex-to-bytes s))

(test parse-addrv2-core-vectors-all-nets
  "Decode Core's five valid CNetAddr v2 payloads inside addrv2 entries."
  ;; (net-id addr-hex expected-net expected-ip-hex-or-nil)
  (dolist (case (list
                 (list 1 "01020304" :ipv4 "00000000000000000000ffff01020304")
                 (list 2 "0102030405060708090a0b0c0d0e0f10" :ipv6 nil)
                 (list 4 "79bcc625184b05194975c28b66b66b0469f7f6556fb1ac3189a79b40dda32f1f"
                       :torv3 nil)
                 (list 5 "a2894dabaec08c0051a481a6dac88b64f98232ae42d4b6fd2fa81952dfe36a87"
                       :i2p nil)
                 (list 6 "fc000001000200030004000500060007" :cjdns nil)))
    (destructuring-bind (net-id addr-hex expected-net expected-ip) case
      (let ((entry (make-addrv2-entry-bytes 1700000000 9 net-id
                                            (%av2-hex addr-hex) 8333)))
        (flexi-streams:with-input-from-sequence (s entry)
          (multiple-value-bind (addr timestamp network-id)
              (bitcoin-lisp.serialization:read-net-addr-v2 s)
            (is (not (null addr)))
            (is (= 1700000000 timestamp))
            (is (= net-id network-id))
            (is (eq expected-net (bitcoin-lisp.serialization:net-addr-network addr)))
            (is (equalp (%av2-hex (or expected-ip addr-hex))
                        (bitcoin-lisp.serialization:net-addr-ip addr)))))))))

(test addrv2-round-trip-all-nets
  "write-net-addr-v2 -> read-net-addr-v2 for every representable network."
  (dolist (case (list
                 (list bitcoin-lisp.serialization:+addrv2-net-ipv4+
                       nil (bitcoin-lisp.networking:ipv4-to-mapped-ipv6 203 0 113 9))
                 (list bitcoin-lisp.serialization:+addrv2-net-ipv6+
                       :ipv6 (%av2-hex "20010db8000000000000000000000042"))
                 (list bitcoin-lisp.serialization:+addrv2-net-torv3+
                       :torv3 (%av2-hex "53cd5648488c4707914182655b7664034e09e66f7e8cbf1084e654eb56c5bd88"))
                 (list bitcoin-lisp.serialization:+addrv2-net-i2p+
                       :i2p (%av2-hex "a2894dabaec08c0051a481a6dac88b64f98232ae42d4b6fd2fa81952dfe36a87"))
                 (list bitcoin-lisp.serialization:+addrv2-net-cjdns+
                       :cjdns (%av2-hex "fc000001000200030004000500060007"))))
    (destructuring-bind (net-id net ip) case
      (let* ((orig (bitcoin-lisp.serialization:make-net-addr
                    :services 1033 :net net :ip ip :port 18444))
             (bytes (coerce
                     (flexi-streams:with-output-to-sequence (s)
                       (bitcoin-lisp.serialization:write-net-addr-v2
                        s orig net-id 1700000123))
                     '(simple-array (unsigned-byte 8) (*)))))
        (flexi-streams:with-input-from-sequence (s bytes)
          (multiple-value-bind (addr timestamp network-id)
              (bitcoin-lisp.serialization:read-net-addr-v2 s)
            (is (not (null addr)))
            (is (= 1700000123 timestamp))
            (is (= net-id network-id))
            (is (equalp ip (bitcoin-lisp.serialization:net-addr-ip addr)))
            (is (= 18444 (bitcoin-lisp.serialization:net-addr-port addr)))
            (is (= 1033 (bitcoin-lisp.serialization:net-addr-services addr)))))))))

(test parse-addrv2-skips-dead-and-embedded-forms
  "Silently-dropped (NIL, stream advanced) forms, per Core: dead TORv2 (any
length, no length check), IPv6 with embedded IPv4 / TORv2 / internal
prefixes, CJDNS without the fc prefix, and unknown ids with zero length."
  (dolist (case (list
                 ;; TORv2 net id 3, its historical 10-byte length.
                 (list 3 (%av2-hex "f1f2f3f4f5f6f7f8f9fa"))
                 ;; TORv2 with a nonsense length is STILL only skipped.
                 (list 3 (%av2-hex "0102030405"))
                 ;; IPv6 embedding IPv4 (Core: !IsValid).
                 (list 2 (%av2-hex "00000000000000000000ffff01020304"))
                 ;; IPv6 embedding TORv2 (Core: !IsValid).
                 (list 2 (%av2-hex "fd87d87eeb430102030405060708090a"))
                 ;; IPv6 embedding NET_INTERNAL (Core: internal, not gossiped).
                 (list 2 (%av2-hex "fd6b88c08724ca978112ca1bbdcafac2"))
                 ;; CJDNS with the wrong prefix (Core: !IsValid).
                 (list 6 (%av2-hex "aa000001000200030004000500060007"))
                 ;; Unknown id, zero-length address.
                 (list #xAA (make-array 0 :element-type '(unsigned-byte 8)))))
    (destructuring-bind (net-id addr-bytes) case
      (let ((entry (make-addrv2-entry-bytes 1700000000 1 net-id addr-bytes 8333)))
        (flexi-streams:with-input-from-sequence (s entry)
          (is (null (bitcoin-lisp.serialization:read-net-addr-v2 s)))
          ;; The whole entry was consumed: subsequent entries stay readable.
          (is (= (length entry) (file-position s))))))))

(test handle-addrv2-stores-typed-when-reachable
  "With onion in the reachable set (-proxy configured), a TorV3 addrv2 entry
lands in addrman as a typed record, keyed and retrievable by (net,bytes,port)."
  (let* ((bitcoin-lisp.networking:*reachable-networks* '(:ipv4 :ipv6 :torv3))
         (book (bitcoin-lisp.networking:make-address-book))
         (now (bitcoin-lisp.serialization:get-unix-time))
         (pubkey (%av2-hex "79bcc625184b05194975c28b66b66b0469f7f6556fb1ac3189a79b40dda32f1f"))
         (payload
           (coerce
            (flexi-streams:with-output-to-sequence (s)
              (bitcoin-lisp.serialization:write-compact-size s 2)
              (write-sequence (make-addrv2-entry-bytes now 1 4 pubkey 8333) s)
              (write-sequence (make-addrv2-entry-bytes now 1 1 #(10 0 0 1) 8333) s))
            '(simple-array (unsigned-byte 8) (*)))))
    (is (= 2 (bitcoin-lisp.networking:handle-addrv2 nil payload book)))
    (is (= 2 (bitcoin-lisp.networking:address-book-count book)))
    (let ((entry (bitcoin-lisp.networking:address-book-lookup book pubkey 8333 :torv3)))
      (is (not (null entry)))
      (is (eq :torv3 (bitcoin-lisp.networking:peer-address-network entry)))
      (is (equalp pubkey (bitcoin-lisp.networking:peer-address-ip entry))))))

(test v1-addr-fc00-gossip-drops-not-retags
  "An fc00::/8 address arriving as plain IPv6 in a v1 addr message is NOT
retagged to CJDNS at gossip ingestion (Core's ADDR handler has no
MaybeFlipIPv6toCJDNS call) — addrman drops it as unroutable IPv6, even with
CJDNS fully reachable. The same 16 bytes properly TAGGED cjdns in addrv2
store fine. Together with the string-ingress flip (netaddress-tests
cjdns-flip-on-ingress), this covers every fc00 ingress point."
  (let* ((bitcoin-lisp.networking:*reachable-networks* '(:ipv4 :ipv6 :cjdns))
         (bitcoin-lisp.networking:*cjdns-reachable* t)
         (book (bitcoin-lisp.networking:make-address-book))
         (now (bitcoin-lisp.serialization:get-unix-time))
         (fc (%av2-hex "fc000001000200030004000500060007"))
         (v1-payload
           (coerce
            (flexi-streams:with-output-to-sequence (s)
              (bitcoin-lisp.serialization:write-compact-size s 1)
              (bitcoin-lisp.serialization:write-net-addr
               s (bitcoin-lisp.serialization:make-net-addr
                  :services 1 :ip fc :port 8333)
               :with-timestamp t :timestamp now))
            '(simple-array (unsigned-byte 8) (*)))))
    ;; (handle-addr's return counts plausible+reachable entries for the log;
    ;; the routability drop happens inside address-book-add — assert the book.)
    (bitcoin-lisp.networking::handle-addr nil v1-payload book)
    (is (= 0 (bitcoin-lisp.networking:address-book-count book)))
    (is (null (bitcoin-lisp.networking:address-book-lookup book fc 8333 :cjdns)))
    (is (null (bitcoin-lisp.networking:address-book-lookup book fc 8333 :ipv6)))
    (let ((v2-payload
            (coerce
             (flexi-streams:with-output-to-sequence (s)
               (bitcoin-lisp.serialization:write-compact-size s 1)
               (write-sequence (make-addrv2-entry-bytes
                                now 1 bitcoin-lisp.serialization:+addrv2-net-cjdns+
                                fc 8333)
                               s))
             '(simple-array (unsigned-byte 8) (*)))))
      (is (= 1 (bitcoin-lisp.networking:handle-addrv2 nil v2-payload book)))
      (let ((entry (bitcoin-lisp.networking:address-book-lookup book fc 8333 :cjdns)))
        (is (not (null entry)))
        (is (eq :cjdns (bitcoin-lisp.networking:peer-address-network entry)))))))

;;;; v1 (legacy addr) discipline: non-IP addresses never emitted

(test v1-write-net-addr-zeroes-non-ip
  "write-net-addr (legacy 26/30-byte form) serializes an onion address as 16
zero bytes (Core SerializeV1Array), never garbage."
  (let* ((onion (bitcoin-lisp.serialization:make-net-addr
                 :services 1 :net :torv3
                 :ip (%av2-hex "79bcc625184b05194975c28b66b66b0469f7f6556fb1ac3189a79b40dda32f1f")
                 :port 8333))
         (bytes (coerce (flexi-streams:with-output-to-sequence (s)
                          (bitcoin-lisp.serialization:write-net-addr s onion))
                        '(simple-array (unsigned-byte 8) (*)))))
    ;; services(8) + ip(16) + port(2)
    (is (= 26 (length bytes)))
    (is (every #'zerop (subseq bytes 8 24)))))

(test v1-addr-response-skips-non-ip
  "build-addr-response for a peer WITHOUT addrv2 drops onion records entirely
(NIL when nothing remains); an addrv2 peer receives them typed."
  (let ((onion-pa (bitcoin-lisp.networking:make-peer-address
                   :net :torv3
                   :ip (%av2-hex "79bcc625184b05194975c28b66b66b0469f7f6556fb1ac3189a79b40dda32f1f")
                   :port 8333 :services 1 :last-seen 1700000000))
        (ip-pa (bitcoin-lisp.networking:make-peer-address
                :ip (bitcoin-lisp.networking:ipv4-to-mapped-ipv6 203 0 113 7)
                :port 8333 :services 1 :last-seen 1700000000))
        (v1-peer (bitcoin-lisp.networking:make-peer :wants-addrv2 nil))
        (v2-peer (bitcoin-lisp.networking:make-peer :wants-addrv2 t)))
    ;; v1 peer, onion only: nothing to send.
    (is (null (bitcoin-lisp.networking::build-addr-response v1-peer (list onion-pa))))
    ;; v1 peer, mixed: only the IP record goes out, as an "addr" with 1 entry.
    (let ((msg (bitcoin-lisp.networking::build-addr-response
                v1-peer (list onion-pa ip-pa))))
      (is (not (null msg)))
      (flexi-streams:with-input-from-sequence (s msg)
        (let ((header (bitcoin-lisp.serialization:read-message-header s)))
          (is (string= "addr" (bitcoin-lisp.serialization:message-header-command header)))))
      ;; payload: count=1 entry only.
      (flexi-streams:with-input-from-sequence (s (subseq msg 24))
        (is (= 1 (bitcoin-lisp.serialization:read-compact-size s)))))
    ;; addrv2 peer, onion only: a full typed addrv2 announcement.
    (let ((msg (bitcoin-lisp.networking::build-addr-response v2-peer (list onion-pa))))
      (is (not (null msg)))
      (let ((parsed (bitcoin-lisp.serialization:parse-addrv2-payload (subseq msg 24))))
        (is (= 1 (length parsed)))
        (destructuring-bind (addr ts nid) (first parsed)
          (declare (ignore ts))
          (is (= bitcoin-lisp.serialization:+addrv2-net-torv3+ nid))
          (is (eq :torv3 (bitcoin-lisp.serialization:net-addr-network addr))))))))
