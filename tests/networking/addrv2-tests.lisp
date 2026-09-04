(in-package #:bitcoin-lisp.tests)

(def-suite :addrv2-tests
  :description "Tests for ADDRv2 (BIP 155) support"
  :in :bitcoin-lisp-tests)

(in-suite :addrv2-tests)

;;; Helper to build a raw addrv2 entry as bytes
(defun make-addrv2-entry-bytes (timestamp services network-id addr-bytes port)
  "Build raw bytes for a single addrv2 entry."
  (coerce
   (bl.bytes:with-byte-buf (s)
     (bl.bytes:bb-write-u32-le s timestamp)
     (bl.bytes:bb-write-varint s services)
     (bl.bytes:bb-write-u8 s network-id)
     (bl.bytes:bb-write-varint s (length addr-bytes))
     (bl.bytes:bb-write-bytes s addr-bytes)
     ;; Port big-endian
     (bl.bytes:bb-write-u8 s (ash port -8))
     (bl.bytes:bb-write-u8 s (logand port #xFF)))
   '(simple-array (unsigned-byte 8) (*))))

;;; Task 3.1: Parse addrv2 entry with IPv4 address
(test parse-addrv2-ipv4
  "Parse an addrv2 entry with IPv4 (network ID 1, 4-byte address)."
  (let* ((addr-bytes #(192 168 1 42))
         (entry (make-addrv2-entry-bytes 1000000 1 1 addr-bytes 8333)))
    (bl.bytes:with-byte-reader (s entry)
      (multiple-value-bind (addr timestamp network-id)
          (bl.ser:read-net-addr-v2 s)
        (is (not (null addr)))
        (is (= 1000000 timestamp))
        (is (= 1 network-id))
        (is (= 8333 (bl.ser:net-addr-port addr)))
        (is (= 1 (bl.ser:net-addr-services addr)))
        ;; Should be IPv4-mapped IPv6
        (let ((ip (bl.ser:net-addr-ip addr)))
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
    (bl.bytes:with-byte-reader (s entry)
      (multiple-value-bind (addr timestamp network-id)
          (bl.ser:read-net-addr-v2 s)
        (is (not (null addr)))
        (is (= 2000000 timestamp))
        (is (= 2 network-id))
        (is (= 18333 (bl.ser:net-addr-port addr)))
        (is (= 9 (bl.ser:net-addr-services addr)))
        ;; IP should be the raw 16 bytes
        (is (equalp addr-bytes (bl.ser:net-addr-ip addr)))))))

;;; TorV3 entries decode to real typed addresses (P1 address layer).
(test parse-addrv2-torv3-typed
  "Parse an addrv2 entry with TorV3 (network ID 4, 32-byte): a typed net-addr."
  (let* ((addr-bytes (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xAB))
         (entry (make-addrv2-entry-bytes 3000000 1 4 addr-bytes 9050)))
    (bl.bytes:with-byte-reader (s entry)
      (multiple-value-bind (addr timestamp network-id)
          (bl.ser:read-net-addr-v2 s)
        (is (not (null addr)))
        (is (= 3000000 timestamp))
        (is (= bl.ser:+addrv2-net-torv3+ network-id))
        (is (eq :torv3 (bl.ser:net-addr-network addr)))
        (is (equalp addr-bytes (bl.ser:net-addr-ip addr)))
        (is (= 9050 (bl.ser:net-addr-port addr)))))))

;;; Task 3.1: Skip unknown network ID
(test parse-addrv2-unknown-network
  "An entry with unknown network ID is skipped without error."
  (let* ((addr-bytes (make-array 8 :element-type '(unsigned-byte 8) :initial-element 0))
         (entry (make-addrv2-entry-bytes 1000000 1 99 addr-bytes 1234)))
    (bl.bytes:with-byte-reader (s entry)
      (let ((addr (bl.ser:read-net-addr-v2 s)))
        (is (null addr))
        ;; Stream should be fully consumed
        (is (= (length entry) (bl.bytes:br-pos s)))))))

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
        (bl.bytes:with-byte-reader (s entry)
          (signals error (bl.ser:read-net-addr-v2 s)))))))

;;; Extreme length rejects the message even for an unknown id (Core
;;; "Address too long: ... > 512").
(test parse-addrv2-address-too-long-errors
  (let ((entry (coerce
                (bl.bytes:with-byte-buf (s)
                  (bl.bytes:bb-write-u32-le s 1000000)
                  (bl.bytes:bb-write-varint s 1)
                  (bl.bytes:bb-write-u8 s #xAA)
                  (bl.bytes:bb-write-varint s 513)
                  (bl.bytes:bb-write-bytes s (make-array 513 :element-type '(unsigned-byte 8)
                                                  :initial-element 1))
                  (bl.bytes:bb-write-u8 s 32) (bl.bytes:bb-write-u8 s 141))
                '(simple-array (unsigned-byte 8) (*)))))
    (bl.bytes:with-byte-reader (s entry)
      (signals error (bl.ser:read-net-addr-v2 s)))))

;;; Task 3.1: Compact-size services round-trip
(test addrv2-compact-size-services
  "Services field uses compact-size encoding and round-trips correctly."
  (let* ((large-services (logior 1 (ash 1 10)))  ; NODE_NETWORK | NODE_NETWORK_LIMITED = 1025
         (addr-bytes #(10 0 0 1))
         (entry (make-addrv2-entry-bytes 1000000 large-services 1 addr-bytes 8333)))
    (bl.bytes:with-byte-reader (s entry)
      (multiple-value-bind (addr timestamp network-id)
          (bl.ser:read-net-addr-v2 s)
        (declare (ignore timestamp network-id))
        (is (not (null addr)))
        (is (= large-services (bl.ser:net-addr-services addr)))))))

;;; Task 3.1: Build and parse sendaddrv2 message
(test sendaddrv2-message-roundtrip
  "sendaddrv2 message has correct header and empty payload."
  (let ((msg (bl.ser:make-sendaddrv2-message)))
    (is (not (null msg)))
    ;; Message should be 24 bytes (header only, zero payload)
    (is (= 24 (length msg)))
    ;; Parse the header
    (bl.bytes:with-byte-reader (s msg)
      (let ((header (bl.ser:read-message-header s)))
        (is (string= "sendaddrv2" (bl.ser:message-header-command header)))
        (is (= 0 (bl.ser:message-header-payload-length header)))))))

;;; Task 3.1: Build and parse addrv2 message with multiple entries
(test addrv2-message-roundtrip
  "Build an addrv2 message with multiple entries and parse it back."
  (let* ((addr1 (bl.ser:make-net-addr
                  :services 1
                  :ip (bl.net:ipv4-to-mapped-ipv6 10 0 0 1)
                  :port 8333))
         (addr2 (bl.ser:make-net-addr
                  :services 9
                  :ip (make-array 16 :element-type '(unsigned-byte 8)
                                     :initial-contents '(#x20 #x01 0 0 0 0 0 0
                                                         0 0 0 0 0 0 0 1))
                  :port 18333))
         (entries (list (list addr1 bl.ser:+addrv2-net-ipv4+ 1000000)
                        (list addr2 bl.ser:+addrv2-net-ipv6+ 2000000)))
         (msg (bl.ser:make-addrv2-message entries)))
    ;; Parse the message: skip 24-byte header to get payload
    (let* ((payload (subseq msg 24))
           (parsed (bl.ser:parse-addrv2-payload payload)))
      (is (= 2 (length parsed)))
      ;; First entry: IPv4
      (destructuring-bind (pa1 ts1 nid1) (first parsed)
        (is (= 1000000 ts1))
        (is (= 1 nid1))
        (is (= 8333 (bl.ser:net-addr-port pa1)))
        (is (= 1 (bl.ser:net-addr-services pa1))))
      ;; Second entry: IPv6
      (destructuring-bind (pa2 ts2 nid2) (second parsed)
        (is (= 2000000 ts2))
        (is (= 2 nid2))
        (is (= 18333 (bl.ser:net-addr-port pa2)))
        (is (= 9 (bl.ser:net-addr-services pa2)))))))

;;; handle-addrv2 stores only REACHABLE networks (Core "Do not store
;;; addresses outside our network"): with the default reachable set
;;; {ipv4, ipv6}, a TorV3 entry parses but is not stored.
(defparameter +core-asmap-test-data+
  (concatenate
   'string
    "fd38d50f7d5d665357f64bba6bfc190d6078a7e68e5d3ac032edf47f8b5755f87881bfd3633d9aa7c1fa279b3"
    "6fe26c63bbc9de44e0f04e5a382d8e1cddbe1c26653bc939d4327f287e8b4d1f8aff33176787cb0ff7cb28e3f"
    "daef0f8f47357f801c9f7ff7a99f7f9c9f99de7f3156ae00f23eb27a303bc486aa3ccc31ec19394c2f8a53ddd"
    "ea3cc56257f3b7e9b1f488be9c1137db823759aa4e071eef2e984aaf97b52d5f88d0f373dd190fe45e06efef1"
    "df7278be680a73a74c76db4dd910f1d30752c57fe2bc9f079f1a1e1b036c2a69219f11c5e11980a3fa51f4f82"
    "d36373de73b1863a8c27e36ae0e4f705be3d76ecff038a75bc0f92ba7e7f6f4080f1c47c34d095367ecf4406c"
    "1e3bbc17ba4d6f79ea3f031b876799ac268b1e0ea9babf0f9a8e5f6c55e363c6363df46afc696d7afceaf49b6"
    "e62df9e9dc27e70664cafe5c53df66dd0b8237678ada90e73f05ec60e6f6e96c3cbb1ea2f9dece115d5bdba10"
    "33e53662a7d72a29477b5beb35710591d3e23e5f0379baea62ffdee535bcdf879cbf69b88d7ea37c8015381cf"
    "63dc33d28f757a4a5e15d6a08")
  "Core's own asmap_test_vectors data (src/test/netbase_tests.cpp:621-633): a
randomly generated map with 128 ranges and up to 20-bit AS numbers.")

(defparameter +core-asmap-expectations+
  '(
    ("0:1559:183:3728:224c:65a5:62e6:e991" . 961340)
    ("d0:d493:faa0:8609:e927:8b75:293c:f5a4" . 961340)
    ("2a0:26f:8b2c:2ee7:c7d1:3b24:4705:3f7f" . 693761)
    ("a77:7cd4:4be5:a449:89f2:3212:78c6:ee38" . 0)
    ("1336:1ad6:2f26:4fe3:d809:7321:6e0d:4615" . 672176)
    ("1d56:abd0:a52f:a8d5:d5a7:a610:581d:d792" . 499880)
    ("378e:7290:54e5:bd36:4760:971c:e9b9:570d" . 0)
    ("406c:820b:272a:c045:b74e:fc0a:9ef2:cecc" . 248495)
    ("46c2:ae07:9d08:2d56:d473:2bc7:57e3:20ac" . 248495)
    ("50d2:3db6:52fa:2e7:12ec:5bc4:1bd1:49f9" . 124471)
    ("53e1:1812:ffa:dccf:f9f2:64be:75fa:795" . 539993)
    ("544d:eeba:3990:35d1:ad66:f9a3:576d:8617" . 374443)
    ("6a53:40dc:8f1d:3ffa:efeb:3aa3:df88:b94b" . 435070)
    ("87aa:d1c9:9edb:91e7:aab1:9eb9:baa0:de18" . 244121)
    ("9f00:48fa:88e3:4b67:a6f3:e6d2:5cc1:5be2" . 862116)
    ("c49f:9cc6:86ad:ba08:4580:315e:dbd1:8a62" . 969411)
    ("dff5:8021:61d:b17d:406d:7888:fdac:4a20" . 969411)
    ("e888:6791:2960:d723:bcfd:47e1:2d8c:599f" . 824019)
    ("ffff:d499:8c4b:4941:bc81:d5b9:b51e:85a8" . 824019))
  "Core's expected GetMappedAS for each address, verbatim from the same test.")

(test asmap-matches-cores-own-test-vectors
  "Every expectation here is copied from Core's asmap_test_vectors
(src/test/netbase_tests.cpp:618-663), against Core's own map data.

This is the test that matters for the whole option: the format is a bit-packed
trie read LITTLE-endian within a byte for the MAP and BIG-endian for the IP,
and getting that pair backwards decodes to plausible garbage rather than
failing. Only vectors from Core can tell the two apart. The 0s are as
load-bearing as the ASNs — they are addresses the map deliberately does not
cover, and a decoder that invented an ASN for them would silently mis-bucket."
  (let ((data (bl.crypto:hex-to-bytes +core-asmap-test-data+)))
    (is (= 413 (length data)) "the map data did not round-trip through hex")
    (dolist (entry +core-asmap-expectations+)
      (multiple-value-bind (net bytes)
          (bl.net:parse-network-address (car entry))
        (declare (ignore net))
        (is (= (cdr entry) (bl.net:asmap-interpret data bytes))
            "~A mapped to ~D, Core says ~D"
            (car entry)
            (bl.net:asmap-interpret data bytes)
            (cdr entry))))))

(test asmap-changes-the-netgroup-and-falls-back-when-unmapped
  "The point of -asmap: two addresses in ONE AS share a bucket group, where
prefix bucketing would have put them in different ones. An address the map does
not cover keeps the prefix rules, as Core's GetGroup does when Interpret
returns 0."
  (let ((data (bl.crypto:hex-to-bytes +core-asmap-test-data+)))
    (flet ((group (host)
             (multiple-value-bind (net bytes)
                 (bl.net:parse-network-address host)
               (bl.net:net-group-key bytes net))))
      ;; Two addresses Core maps to the SAME ASN (969411) but which share no
      ;; prefix at all.
      (let ((a "c49f:9cc6:86ad:ba08:4580:315e:dbd1:8a62")
            (b "dff5:8021:61d:b17d:406d:7888:fdac:4a20"))
        (let ((bl.net:*asmap* nil))
          (is (not (equalp (group a) (group b)))
              "control: without a map these must be different groups"))
        (let ((bl.net:*asmap* data))
          (is (equalp (group a) (group b))
              "two addresses in one AS did not share a group")))
      ;; An address the map does not cover (Core says 0) keeps prefix
      ;; bucketing rather than collapsing into a single "unmapped" group.
      (let ((u1 "a77:7cd4:4be5:a449:89f2:3212:78c6:ee38")
            (u2 "378e:7290:54e5:bd36:4760:971c:e9b9:570d"))
        (let ((bl.net:*asmap* data))
          (is (not (equalp (group u1) (group u2)))
              "unmapped addresses collapsed into one group"))))))

(test asmap-file-loading-is-fatal-on-failure
  "Core aborts startup on a missing or empty asmap file (init.cpp:1587-1600).
Silently keeping /16 bucketing would leave exactly the eclipse exposure the
operator was trying to close."
  (signals error (bl.net:load-asmap-file
                  #p"/nonexistent/asmap.dat"))
  (let ((path (merge-pathnames (format nil "bl-empty-asmap-~D"
                                       (get-internal-real-time))
                               (uiop:temporary-directory))))
    (unwind-protect
         (progn
           (with-open-file (out path :direction :output
                                     :element-type '(unsigned-byte 8)
                                     :if-exists :supersede))
           (signals error (bl.net:load-asmap-file path)))
      (ignore-errors (delete-file path))))
  ;; And it reaches the plist as an ordinary option.
  (is (equal "peers.map"
             (getf (start-node-plist
                    '("-regtest" "-asmap=peers.map") nil)
                   :asmap)))
  (is-true (bl:known-config-option-p "asmap"))
  (is-false (bl.cfg:core-only-option-p "asmap")))

(test addr-fetch-peer-disconnects-once-it-delivers-addresses
  "An addr-fetch peer (-seednode) exists only to hand over addresses and is
disconnected as soon as it does (Core net_processing.cpp:4117-4121). Core
requires MORE THAN ONE address, so a peer that merely self-announces does not
end the fetch — without that, a seed answering with its own address alone would
be dropped before delivering anything useful."
  (flet ((deliver (conn-type count)
           (let* ((book (bl.net:make-address-book))
                  (peer (bl.net:make-peer
                         :address "10.9.9.9" :conn-type conn-type
                         :state :ready))
                  (now (bl.ser:get-unix-time))
                  (entries (loop for i below count
                                 collect (cons (bl.ser:make-net-addr
                                                :services 1
                                                :ip (bl.net:ipv4-to-mapped-ipv6
                                                     10 0 0 (1+ i))
                                                :port 8333)
                                               now))))
             ;; A generous token bucket, so the rate limiter is not what
             ;; decides the outcome here.
             (setf (bl.net::peer-addr-token-bucket peer) 100d0)
             (bl.net::%process-gossiped-addresses
              peer entries count book nil)
             (bl.net:peer-state peer))))
    (is (eq :disconnected (deliver :addr-fetch 5))
        "an addr-fetch peer stayed connected after delivering addresses")
    (is-false (eq :disconnected (deliver :addr-fetch 1))
              "an addr-fetch peer was dropped on a single self-announcement")
    ;; An ordinary outbound peer is never dropped for answering our getaddr.
    (is-false (eq :disconnected (deliver :outbound-full-relay 5)))))

(test handle-addrv2-filters-networks
  "handle-addrv2 adds IPv4/IPv6 to address book, skips unreachable TorV3."
  (let* ((bl.net:*reachable-networks* '(:ipv4 :ipv6))
         (book (bl.net:make-address-book))
         (now (bl.ser:get-unix-time))
         ;; Build payload with IPv4, IPv6, and TorV3 entries
         (payload
           (coerce
            (bl.bytes:with-byte-buf (s)
              (bl.bytes:bb-write-varint s 3)
              ;; IPv4 entry
              (bl.ser:write-net-addr-v2
               s
               (bl.ser:make-net-addr :services 1
                 :ip (bl.net:ipv4-to-mapped-ipv6 10 0 0 1)
                 :port 8333)
               bl.ser:+addrv2-net-ipv4+ now)
              ;; IPv6 entry
              (bl.ser:write-net-addr-v2
               s
               (bl.ser:make-net-addr :services 1
                 :ip (make-array 16 :element-type '(unsigned-byte 8)
                                    :initial-contents '(#x20 #x01 0 0 0 0 0 0
                                                        0 0 0 0 0 0 0 2))
                 :port 8333)
               bl.ser:+addrv2-net-ipv6+ now)
              ;; TorV3 entry (should be skipped)
              (bl.bytes:bb-write-u32-le s now)
              (bl.bytes:bb-write-varint s 1)
              (bl.bytes:bb-write-u8 s bl.ser:+addrv2-net-torv3+)
              (bl.bytes:bb-write-varint s 32)
              (bl.bytes:bb-write-bytes s (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xAA))
              (bl.bytes:bb-write-u8 s 0) (bl.bytes:bb-write-u8 s 80))  ; port 80
            '(simple-array (unsigned-byte 8) (*)))))
    (let ((added (bl.net:handle-addrv2 nil payload (bl.ctx:make-node-context :address-book book))))
      ;; Only IPv4 and IPv6 should be added (TorV3 skipped)
      (is (= 2 added))
      (is (= 2 (bl.net:address-book-count book))))))

;;; Task 3.1: IPv4 from addrv2 converted to mapped-IPv6
(test addrv2-ipv4-to-mapped-ipv6
  "IPv4 address from addrv2 is stored as IPv4-mapped IPv6 in address book."
  (let* ((book (bl.net:make-address-book))
         (now (bl.ser:get-unix-time))
         (payload
           (coerce
            (bl.bytes:with-byte-buf (s)
              (bl.bytes:bb-write-varint s 1)
              (bl.ser:write-net-addr-v2
               s
               (bl.ser:make-net-addr :services 1
                 :ip (bl.net:ipv4-to-mapped-ipv6 172 16 0 5)
                 :port 8333)
               bl.ser:+addrv2-net-ipv4+ now))
            '(simple-array (unsigned-byte 8) (*)))))
    (bl.net:handle-addrv2 nil payload (bl.ctx:make-node-context :address-book book))
    (is (= 1 (bl.net:address-book-count book)))
    ;; Look up with the mapped IPv6 address
    (let* ((mapped-ip (bl.net:ipv4-to-mapped-ipv6 172 16 0 5))
           (entry (bl.net:address-book-lookup book mapped-ip 8333)))
      (is (not (null entry)))
      (let ((ip (bl.net:peer-address-ip entry)))
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
;;; Observed live on mainnet 2026-07-12 after the getaddr fetch started sending getaddr.
(test parse-addrv2-large-services-bitmask
  "addrv2 entries with high service bits (>= bit 26) must parse."
  (let* ((services (logior (ash 1 26) (ash 1 30) 1033)) ; > +max-compact-size+
         (entry (make-addrv2-entry-bytes 1720000000 services 1 #(203 0 113 5) 8333)))
    (bl.bytes:with-byte-reader (s entry)
      (multiple-value-bind (addr timestamp network-id)
          (bl.ser:read-net-addr-v2 s)
        (declare (ignore timestamp network-id))
        (is (not (null addr)))
        (is (= services (bl.ser:net-addr-services addr))))))
  ;; A whole message: exotic-services entry followed by a normal one —
  ;; the stream stays aligned and neither entry is lost.
  (let* ((e1 (make-addrv2-entry-bytes 1720000000 (ash 1 33) 1 #(1 2 3 4) 8333))
         (e2 (make-addrv2-entry-bytes 1720000001 9 1 #(5 6 7 8) 8334))
         (payload (coerce
                   (bl.bytes:with-byte-buf (s)
                     (bl.bytes:bb-write-varint s 2)
                     (bl.bytes:bb-write-bytes s e1)
                     (bl.bytes:bb-write-bytes s e2))
                   '(simple-array (unsigned-byte 8) (*))))
         (addrs (bl.ser:parse-addrv2-payload payload)))
    (is (= 2 (length addrs)))))

;;;; ============================================================
;;;; P1: network-typed addrv2 (Core net_tests.cpp cnetaddr_unserialize_v2
;;;; address payloads, wrapped in full addrv2 entries)
;;;; ============================================================

(defun %av2-hex (s) (bl.crypto:hex-to-bytes s))

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
        (bl.bytes:with-byte-reader (s entry)
          (multiple-value-bind (addr timestamp network-id)
              (bl.ser:read-net-addr-v2 s)
            (is (not (null addr)))
            (is (= 1700000000 timestamp))
            (is (= net-id network-id))
            (is (eq expected-net (bl.ser:net-addr-network addr)))
            (is (equalp (%av2-hex (or expected-ip addr-hex))
                        (bl.ser:net-addr-ip addr)))))))))

(test addrv2-round-trip-all-nets
  "write-net-addr-v2 -> read-net-addr-v2 for every representable network."
  (dolist (case (list
                 (list bl.ser:+addrv2-net-ipv4+
                       nil (bl.net:ipv4-to-mapped-ipv6 203 0 113 9))
                 (list bl.ser:+addrv2-net-ipv6+
                       :ipv6 (%av2-hex "20010db8000000000000000000000042"))
                 (list bl.ser:+addrv2-net-torv3+
                       :torv3 (%av2-hex "53cd5648488c4707914182655b7664034e09e66f7e8cbf1084e654eb56c5bd88"))
                 (list bl.ser:+addrv2-net-i2p+
                       :i2p (%av2-hex "a2894dabaec08c0051a481a6dac88b64f98232ae42d4b6fd2fa81952dfe36a87"))
                 (list bl.ser:+addrv2-net-cjdns+
                       :cjdns (%av2-hex "fc000001000200030004000500060007"))))
    (destructuring-bind (net-id net ip) case
      (let* ((orig (bl.ser:make-net-addr
                    :services 1033 :net net :ip ip :port 18444))
             (bytes (coerce
                     (bl.bytes:with-byte-buf (s)
                       (bl.ser:write-net-addr-v2
                        s orig net-id 1700000123))
                     '(simple-array (unsigned-byte 8) (*)))))
        (bl.bytes:with-byte-reader (s bytes)
          (multiple-value-bind (addr timestamp network-id)
              (bl.ser:read-net-addr-v2 s)
            (is (not (null addr)))
            (is (= 1700000123 timestamp))
            (is (= net-id network-id))
            (is (equalp ip (bl.ser:net-addr-ip addr)))
            (is (= 18444 (bl.ser:net-addr-port addr)))
            (is (= 1033 (bl.ser:net-addr-services addr)))))))))

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
        (bl.bytes:with-byte-reader (s entry)
          (is (null (bl.ser:read-net-addr-v2 s)))
          ;; The whole entry was consumed: subsequent entries stay readable.
          (is (= (length entry) (bl.bytes:br-pos s))))))))

(test handle-addrv2-stores-typed-when-reachable
  "With onion in the reachable set (-proxy configured), a TorV3 addrv2 entry
lands in addrman as a typed record, keyed and retrievable by (net,bytes,port)."
  (let* ((bl.net:*reachable-networks* '(:ipv4 :ipv6 :torv3))
         (book (bl.net:make-address-book))
         (now (bl.ser:get-unix-time))
         (pubkey (%av2-hex "79bcc625184b05194975c28b66b66b0469f7f6556fb1ac3189a79b40dda32f1f"))
         (payload
           (coerce
            (bl.bytes:with-byte-buf (s)
              (bl.bytes:bb-write-varint s 2)
              (bl.bytes:bb-write-bytes s (make-addrv2-entry-bytes now 1 4 pubkey 8333))
              (bl.bytes:bb-write-bytes s (make-addrv2-entry-bytes now 1 1 #(10 0 0 1) 8333)))
            '(simple-array (unsigned-byte 8) (*)))))
    (is (= 2 (bl.net:handle-addrv2 nil payload (bl.ctx:make-node-context :address-book book))))
    (is (= 2 (bl.net:address-book-count book)))
    (let ((entry (bl.net:address-book-lookup book pubkey 8333 :torv3)))
      (is (not (null entry)))
      (is (eq :torv3 (bl.net:peer-address-network entry)))
      (is (equalp pubkey (bl.net:peer-address-ip entry))))))

(test v1-addr-fc00-gossip-drops-not-retags
  "An fc00::/8 address arriving as plain IPv6 in a v1 addr message is NOT
retagged to CJDNS at gossip ingestion (Core's ADDR handler has no
MaybeFlipIPv6toCJDNS call) — addrman drops it as unroutable IPv6, even with
CJDNS fully reachable. The same 16 bytes properly TAGGED cjdns in addrv2
store fine. Together with the string-ingress flip (netaddress-tests
cjdns-flip-on-ingress), this covers every fc00 ingress point."
  (let* ((bl.net:*reachable-networks* '(:ipv4 :ipv6 :cjdns))
         (bl.net:*cjdns-reachable* t)
         (book (bl.net:make-address-book))
         (now (bl.ser:get-unix-time))
         (fc (%av2-hex "fc000001000200030004000500060007"))
         (v1-payload
           (coerce
            (bl.bytes:with-byte-buf (s)
              (bl.bytes:bb-write-varint s 1)
              (bl.ser:write-net-addr
               s (bl.ser:make-net-addr
                  :services 1 :ip fc :port 8333)
               :with-timestamp t :timestamp now))
            '(simple-array (unsigned-byte 8) (*)))))
    ;; (handle-addr's return counts plausible+reachable entries for the log;
    ;; the routability drop happens inside address-book-add — assert the book.)
    (bl.net:handle-addr nil v1-payload (bl.ctx:make-node-context :address-book book))
    (is (= 0 (bl.net:address-book-count book)))
    (is (null (bl.net:address-book-lookup book fc 8333 :cjdns)))
    (is (null (bl.net:address-book-lookup book fc 8333 :ipv6)))
    (let ((v2-payload
            (coerce
             (bl.bytes:with-byte-buf (s)
               (bl.bytes:bb-write-varint s 1)
               (bl.bytes:bb-write-bytes s (make-addrv2-entry-bytes
                                now 1 bl.ser:+addrv2-net-cjdns+
                                fc 8333)))
             '(simple-array (unsigned-byte 8) (*)))))
      (is (= 1 (bl.net:handle-addrv2 nil v2-payload (bl.ctx:make-node-context :address-book book))))
      (let ((entry (bl.net:address-book-lookup book fc 8333 :cjdns)))
        (is (not (null entry)))
        (is (eq :cjdns (bl.net:peer-address-network entry)))))))

;;;; v1 (legacy addr) discipline: non-IP addresses never emitted

(test v1-write-net-addr-zeroes-non-ip
  "write-net-addr (legacy 26/30-byte form) serializes an onion address as 16
zero bytes (Core SerializeV1Array), never garbage."
  (let* ((onion (bl.ser:make-net-addr
                 :services 1 :net :torv3
                 :ip (%av2-hex "79bcc625184b05194975c28b66b66b0469f7f6556fb1ac3189a79b40dda32f1f")
                 :port 8333))
         (bytes (coerce (bl.bytes:with-byte-buf (s)
                          (bl.ser:write-net-addr s onion))
                        '(simple-array (unsigned-byte 8) (*)))))
    ;; services(8) + ip(16) + port(2)
    (is (= 26 (length bytes)))
    (is (every #'zerop (subseq bytes 8 24)))))

(test v1-addr-response-skips-non-ip
  "build-addr-response for a peer WITHOUT addrv2 drops onion records entirely
(NIL when nothing remains); an addrv2 peer receives them typed."
  (let ((onion-pa (bl.net:make-peer-address
                   :net :torv3
                   :ip (%av2-hex "79bcc625184b05194975c28b66b66b0469f7f6556fb1ac3189a79b40dda32f1f")
                   :port 8333 :services 1 :last-seen 1700000000))
        (ip-pa (bl.net:make-peer-address
                :ip (bl.net:ipv4-to-mapped-ipv6 203 0 113 7)
                :port 8333 :services 1 :last-seen 1700000000))
        (v1-peer (bl.net:make-peer :wants-addrv2 nil))
        (v2-peer (bl.net:make-peer :wants-addrv2 t)))
    ;; v1 peer, onion only: nothing to send.
    (is (null (bl.net::build-addr-response v1-peer (list onion-pa))))
    ;; v1 peer, mixed: only the IP record goes out, as an "addr" with 1 entry.
    (let ((msg (bl.net::build-addr-response
                v1-peer (list onion-pa ip-pa))))
      (is (not (null msg)))
      (bl.bytes:with-byte-reader (s msg)
        (let ((header (bl.ser:read-message-header s)))
          (is (string= "addr" (bl.ser:message-header-command header)))))
      ;; payload: count=1 entry only.
      (bl.bytes:with-byte-reader (s (subseq msg 24))
        (is (= 1 (bl.bytes:br-read-compact-size s)))))
    ;; addrv2 peer, onion only: a full typed addrv2 announcement.
    (let ((msg (bl.net::build-addr-response v2-peer (list onion-pa))))
      (is (not (null msg)))
      (let ((parsed (bl.ser:parse-addrv2-payload (subseq msg 24))))
        (is (= 1 (length parsed)))
        (destructuring-bind (addr ts nid) (first parsed)
          (declare (ignore ts))
          (is (= bl.ser:+addrv2-net-torv3+ nid))
          (is (eq :torv3 (bl.ser:net-addr-network addr))))))))
