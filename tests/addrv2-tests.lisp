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

;;; Task 3.1: Parse addrv2 entry with TorV3 (parsed but returns NIL)
(test parse-addrv2-torv3-skipped
  "Parse an addrv2 entry with TorV3 (network ID 4, 32-byte). Returns NIL."
  (let* ((addr-bytes (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xAB))
         (entry (make-addrv2-entry-bytes 3000000 1 4 addr-bytes 9050)))
    (flexi-streams:with-input-from-sequence (s entry)
      (let ((addr (bitcoin-lisp.serialization:read-net-addr-v2 s)))
        ;; TorV3 is valid BIP155 but not connectable — returns NIL
        (is (null addr))))))

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

;;; Task 3.1: Skip entry with mismatched address length
(test parse-addrv2-mismatched-length
  "An IPv4 entry with wrong address length is skipped."
  ;; IPv4 expects 4 bytes, but we provide 8
  (let* ((addr-bytes (make-array 8 :element-type '(unsigned-byte 8) :initial-element 0))
         (entry (make-addrv2-entry-bytes 1000000 1 1 addr-bytes 8333)))
    (flexi-streams:with-input-from-sequence (s entry)
      (let ((addr (bitcoin-lisp.serialization:read-net-addr-v2 s)))
        (is (null addr))))))

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

;;; Task 3.1: handle-addrv2 adds only IPv4/IPv6 to address book
(test handle-addrv2-filters-networks
  "handle-addrv2 adds IPv4/IPv6 to address book, skips others."
  (let* ((book (bitcoin-lisp.networking:make-address-book))
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
