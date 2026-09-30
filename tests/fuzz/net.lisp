(in-package #:bitcoin-lisp.tests)

;;;; Core's network-object targets at the pin: fuzz/bloom_filter.cpp,
;;;; rolling_bloom_filter.cpp, net_permissions.cpp, netaddress.cpp.

(def-suite :fuzz-net-tests :in :bitcoin-lisp-tests
  :description "Core fuzz bloom_filter / rolling_bloom_filter / net_permissions / netaddress targets")

(in-suite :fuzz-net-tests)

;;; --- bloom_filter.cpp ----------------------------------------------------------

(define-fuzz-target bloom-filter
    (buffer :core "bloom_filter.cpp:21-80" :iterations 1500 :max-len 600)
  "A CBloomFilter of any size, false-positive rate, tweak and update mode
never forgets: every byte string, outpoint and hash inserted is contained
right after, whatever else the filter was asked -- IsRelevantAndUpdate over
arbitrary transactions included -- and asking IsWithinSizeConstraints
answers."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (filter (bl.net:make-bloom-filter
                  (consume-integral-in-range fdp 1 10000000 32)
                  (/ 1d0 (consume-integral-in-range fdp 1 #xffffffff 32))
                  (consume-integral fdp :u32)
                  (pick-value-in-array fdp '(0 1 2 3))))
         (good-data t))
    (flet ((insert-and-find (key)
             (bl.net:bloom-contains-p filter key)
             (bl.net:bloom-insert filter key)
             (fuzz-assert (fuzz-sabotage (bl.net:bloom-contains-p filter key))
                          "inserted ~A, not contained" (bl.crypto:bytes-to-hex key))))
      (limited-while ((and good-data (plusp (remaining-bytes fdp))) 10000)
        (call-one-of fdp
          (insert-and-find (consume-random-length-byte-vector fdp))
          (let ((op (consume-deserializable
                     fdp (lambda (b) (bl.ser:br-read-outpoint (bl.ser:make-byte-reader-from b))))))
            (if op
                (insert-and-find (bl.net:outpoint-bytes (bl.ser:outpoint-hash op) (bl.ser:outpoint-index op)))
                (setf good-data nil)))
          (let ((hash (consume-deserializable
                       fdp (lambda (b) (bl.ser:br-read-bytes (bl.ser:make-byte-reader-from b) 32)))))
            (if hash (insert-and-find hash) (setf good-data nil)))
          (let ((tx (consume-deserializable
                     fdp (lambda (b) (bl.ser:br-read-transaction (bl.ser:make-byte-reader-from b))))))
            (if tx (bl.net:bloom-relevant-and-update-p filter tx) (setf good-data nil))))
        (bl.net:bloom-within-size-constraints-p filter)))))

;;; --- rolling_bloom_filter.cpp ----------------------------------------------------

(define-fuzz-target rolling-bloom-filter
    (buffer :core "rolling_bloom_filter.cpp:18-50" :iterations 1500 :max-len 600)
  "Core's CRollingBloomFilter is ours as the recent-rejects ring (a bounded
hash set with FIFO eviction), which every rolling filter of Core's maps onto
-- the known-address and known-inventory filters, the recent rejects, the
recently confirmed. Whatever the capacity and whatever was inserted or reset
before, an element is contained right after it is inserted."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (filter (bl:make-rejects-filter (consume-integral-in-range fdp 1 1000 32))))
    (consume-integral-in-range fdp 1 #xffffffff 32) ; Core's false-positive rate
    (flet ((insert-and-find (key)
             (bl:recent-reject-p filter key)
             (bl:add-recent-reject filter key)
             (fuzz-assert (fuzz-sabotage (and (bl:recent-reject-p filter key) t))
                          "inserted ~A, not contained" (bl.crypto:bytes-to-hex key))))
      (limited-while ((plusp (remaining-bytes fdp)) 3000)
        (call-one-of fdp
          (insert-and-find (consume-random-length-byte-vector fdp))
          (insert-and-find (consume-uint256 fdp))
          (bl:clear-recent-rejects filter))))))

;;; --- net_permissions.cpp -------------------------------------------------------

(defparameter +net-permission-flags+
  (list 0 bl.net:+perm-bloom-filter+ bl.net:+perm-relay+ bl.net:+perm-force-relay+
        bl.net:+perm-download+ bl.net:+perm-noban+ bl.net:+perm-mempool+ bl.net:+perm-addr+
        bl.net:+perm-implicit+ bl.net:+perm-all+)
  "Core ALL_NET_PERMISSION_FLAGS (test/fuzz/util/net.h), our encodings.")

(define-fuzz-target net-permissions
    (buffer :core "net_permissions.cpp:14-44" :iterations 8000 :max-len 200
            :corpus (lambda (fdp)
                      (let ((names (loop repeat (consume-integral-in-range fdp 0 4)
                                         collect (pick-value-in-array
                                                  fdp '("bloomfilter" "bloom" "noban" "forcerelay" "relay"
                                                        "mempool" "download" "addr" "all" "in" "out" "" "x"))))
                            (host (pick-value-in-array
                                   fdp '("1.2.3.4" "1.2.3.0/24" "::1" "[::1]" "2001:db8::/32" "10.0.0.0/255.0.0.0"
                                         "fc00::1" "127.0.0.1/255.255.0.255" "not-an-address"))))
                        (map '(vector (unsigned-byte 8)) #'char-code
                             (format nil "~{~A~^,~}~:[~;@~]~A" names (or names (consume-bool fdp)) host)))))
  "A -whitebind or -whitelist spec that parses (NetWhitebindPermissions /
NetWhitelistPermissions::TryParse) holds any flag added to it, and prints
(ToStrings) -- and every name it prints parses back to a flag it holds."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (spec (consume-random-length-string fdp 1000))
         (flag (pick-value-in-array fdp +net-permission-flags+)))
    (dolist (allow-out '(nil t))
      (let ((entry (bl.net:parse-whitelist-entry spec :allow-out allow-out)))
        (when entry
          (let ((flags (logior (bl.net:whitelist-entry-flags entry) flag)))
            (fuzz-assert (fuzz-sabotage (bl.net:permission-flag-set-p flags flag))
                         "~S plus flag ~D does not hold it" spec flag)
            (dolist (name (bl.net:permission-flag-names flags))
              (let ((named (bl.net:parse-permission-flags (format nil "~A@1.2.3.4" name))))
                (fuzz-assert (and named (bl.net:permission-flag-set-p flags named))
                             "~S prints ~S, which names flags it does not hold" spec name)))))))))

;;; --- netaddress.cpp ------------------------------------------------------------

(defun consume-net-addr (fdp)
  "Core ConsumeNetAddr (test/fuzz/util/net.cpp:29-86), as (values network
bytes) in our representation: IPv4 as the 16-byte ::ffff:a.b.c.d form, the
BIP155 lengths for the others. NET_INTERNAL has no counterpart here."
  (let ((network (pick-value-in-array fdp '(:ipv4 :ipv6 :torv3 :i2p :cjdns))))
    (values network
            (let ((raw (consume-bytes fdp (ecase network (:ipv4 4) ((:ipv6 :cjdns) 16) ((:torv3 :i2p) 32)))))
              (ecase network
                (:ipv4 (let ((v (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
                         (setf (aref v 10) #xff (aref v 11) #xff)
                         (replace v raw :start1 12)))
                ((:ipv6 :cjdns :torv3 :i2p)
                 (let ((v (make-array (bl.net:network-address-length network)
                                      :element-type '(unsigned-byte 8) :initial-element 0)))
                   (replace v raw))))))))

(define-fuzz-target netaddress
    (buffer :core "netaddress.cpp:20-133" :iterations 8000 :max-len 120)
  "A CNetAddr of any network: its class is its network, IPv4, or unroutable
(GetNetClass), and an address that is not routable classes as unroutable;
ToStringAddr is injective -- the string parses back to the same address
(netaddress.cpp:105-107 asserts the injectivity); and a CSubNet built from
it with any CIDR length, or any netmask written as an address, is either
refused or prints as a subnet that parses back to itself and contains the
address it was built from."
  (let ((fdp (make-fuzzed-data-provider buffer)))
    (multiple-value-bind (network bytes) (consume-net-addr fdp)
      (let ((class (bl.net:address-net-class network bytes)))
        (fuzz-assert (member class (list network :ipv4 :unroutable))
                     "~S address classes as ~S" network class)
        (unless (bl.net:address-publicly-routable-p bytes network)
          (fuzz-assert (eq class :unroutable) "not routable, classes as ~S" class)))
      (bl.net:address-routable-p bytes network)
      (bl.net:address-valid-p bytes network)
      (let ((string (bl.net:network-address-to-string network bytes)))
        (multiple-value-bind (parsed-network parsed) (bl.net:parse-network-address string)
          (fuzz-assert (equalp (fuzz-sabotage parsed) bytes)
                       "~S ~A prints as ~S, which parses to ~A" network
                       (bl.crypto:bytes-to-hex bytes) string (and parsed (bl.crypto:bytes-to-hex parsed)))
          ;; An fc00::/8 string is CJDNS exactly when CJDNS is reachable
          ;; (MaybeFlipIPv6toCJDNS), so the text keeps the network up to that.
          (fuzz-assert (or (eq parsed-network network)
                           (and (member network '(:cjdns :ipv6))
                                (member parsed-network '(:cjdns :ipv6))))
                       "~S prints as ~S, which parses as ~S" network string parsed-network)
          ;; The subnet is of the address the string names (LookupSubNet).
          (dolist (suffix (list (format nil "~D" (consume-integral fdp :u8))
                                (multiple-value-bind (mask-network mask) (consume-net-addr fdp)
                                  (bl.net:network-address-to-string mask-network mask))))
            (let ((subnet (bl.net:parse-subnet (format nil "~A/~A" string suffix))))
              (when subnet
                (let ((printed (bl.net:subnet-string subnet)))
                  (fuzz-assert (equalp (bl.net:parse-subnet printed) (fuzz-sabotage subnet))
                               "~A/~A prints as ~A, which parses to another subnet" string suffix printed)
                  (fuzz-assert (bl.net:subnet-match-p subnet parsed-network parsed)
                               "~A/~A does not contain ~A" string suffix string))))))))))

;;; --- net.cpp: local_address -----------------------------------------------------

(defun %fuzz-local-service (fdp)
  "Core ConsumeService: (network bytes port) of any network the node knows,
IPv4 in its mapped form."
  (let ((network (pick-value-in-array fdp '(:ipv4 :ipv6 :torv3 :i2p :cjdns))))
    (list network
          (ecase network
            (:ipv4 (let ((ip (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
                     (setf (aref ip 10) #xff (aref ip 11) #xff)
                     (replace ip (consume-bytes fdp 4) :start1 12)))
            (:ipv6 (consume-uint128 fdp))
            ((:torv3 :i2p) (consume-uint256 fdp))
            (:cjdns (let ((ip (consume-uint128 fdp)))
                      (when (consume-bool fdp) (setf (aref ip 0) #xfc))
                      ip)))
          (consume-integral fdp :u16))))

(define-fuzz-target local-address
    (buffer :core "net.cpp:76-116 (local_address)" :iterations 600 :max-len 400)
  "The local-address table under random AddLocal, RemoveLocal and SeenLocal of
services of every network: an address AddLocal accepts is routable, is then
in the table, and SeenLocal of it succeeds; GetLocal answers for any peer
network."
  (let ((fdp (make-fuzzed-data-provider buffer)))
    (%with-local-address-table
      (let ((bl.net:*reachable-networks* '(:ipv4 :ipv6 :torv3 :i2p :cjdns))
            (bl.net:*discover* (consume-bool fdp))
            (service (%fuzz-local-service fdp)))
        (limited-while ((%fuzz-continue-p fdp) 10000)
          (destructuring-bind (network bytes port) service
            (call-one-of fdp
              (setf service (%fuzz-local-service fdp))
              (when (bl.net:add-local network bytes port (consume-integral-in-range fdp 0 4))
                (fuzz-assert (bl.net:address-routable-p bytes network)
                             "AddLocal took an unroutable ~A address" network)
                (fuzz-assert (fuzz-sabotage
                              (and (find-if (lambda (la) (and (eq (bl.net:local-address-network la) network)
                                                              (equalp (bl.net:local-address-bytes la) bytes)))
                                            (bl.net:local-addresses))
                                   t))
                             "an address AddLocal took is not local")
                (fuzz-assert (bl.net:seen-local network bytes) "SeenLocal of a local address failed"))
              (bl.net:remove-local network bytes)
              (bl.net:seen-local network bytes)
              (bl.net:best-local-address (pick-value-in-array fdp '(:ipv4 :ipv6 :torv3 :i2p :cjdns))))))))))
