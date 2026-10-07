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
  "Core's CRollingBloomFilter (src/networking/bloom.lisp): whatever the
capacity, the false-positive rate and what was inserted or reset before, an
element is contained right after it is inserted."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (filter (bl.net:make-rolling-bloom-filter
                  (consume-integral-in-range fdp 1 1000 32)
                  (/ 0.999d0 (consume-integral-in-range fdp 1 #xffffffff 32)))))
    (flet ((insert-and-find (key)
             (bl.net:rolling-bloom-insert filter key)
             (fuzz-assert (fuzz-sabotage (bl.net:rolling-bloom-contains-p filter key))
                          "inserted ~A, not contained" (bl.crypto:bytes-to-hex key))))
      (limited-while ((plusp (remaining-bytes fdp)) 3000)
        (call-one-of fdp
          (insert-and-find (consume-random-length-byte-vector fdp))
          (insert-and-find (consume-uint256 fdp))
          (bl.net:rolling-bloom-reset filter))))))

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

;;; --- net.cpp: net ---------------------------------------------------------------
;;;
;;; Core's target builds a CNode from the buffer and calls its operations in
;;; any order: CloseSocketDisconnect, CopyStats, AddRef/Release,
;;; ReceiveMsgBytes, then the getters. Ours is a PEER over one end of a
;;; loopback pair. ReceiveMsgBytes is bytes written into the other end and
;;; read off with RECEIVE-MESSAGE; CopyStats is the peer's getpeerinfo row;
;;; CloseSocketDisconnect is DISCONNECT-PEER. AddRef/Release have no
;;; counterpart (a peer is collected, not counted) and stay as choices that do
;;; nothing, so the buffer's other draws keep Core's shape; so does
;;; SetCommonVersion, which ours derives from the VERSION message.
;;;
;;; Core asserts AddRef returns the node and the reference count stays
;;; non-negative. Ours asserts what the operations are FOR: the messages
;;; delivered are Core's V1Transport reading of every byte fed so far
;;; (%V1-REFERENCE-MESSAGES), a connection Core would drop is dropped; the
;;; stats row names the peer, its type and direction, the network it is
;;; connected through, and the local address it reported exactly when that
;;; address is valid; and with no whitelist the peer holds no permission.

(defparameter +fuzz-net-conn-types+
  '(:inbound :outbound-full-relay :manual :feeler :block-relay :addr-fetch)
  "Core ALL_CONNECTION_TYPES (node/connection_types.h), as peer conn-types.")

(defun %fuzz-net-node-peer (fdp connection)
  "Core ConsumeNode (test/fuzz/util/net.h:270-309) as a PEER on CONNECTION.
Returns the peer and, second, the network of the address it was given."
  (multiple-value-bind (network bytes) (consume-net-addr fdp)
    (let* ((id (consume-integral-in-range fdp 0 (1- (ash 1 63))))
           (port (consume-integral fdp :u16))
           (address (bl.net:network-address-to-string network bytes)))
      (consume-integral fdp :u64)            ; keyed net group: derived from the address
      (let ((nonce (consume-integral fdp :u64)))
        (consume-net-addr fdp)                ; addr_bind: the socket's own
        (consume-random-length-string fdp 64) ; addr_name: the address string here
        (let* ((conn-type (pick-value-in-array fdp +fuzz-net-conn-types+))
               (inbound (eq conn-type :inbound))
               (onion (and inbound (consume-bool fdp))))
          (consume-integral fdp :u64)         ; network key
          (consume-integral fdp :u32)         ; permission flags: ours derive from the whitelist
          (values (bl.net:make-peer :id id :connection connection :state :ready
                                    :address address :remote-port port :local-nonce nonce
                                    :conn-type conn-type :inbound inbound :inbound-onion onion)
                  network))))))

(defun %fuzz-net-type-string (field)
  "The 12-byte type FIELD as RECEIVE-MESSAGE names it: trailing NULs dropped."
  (map 'string #'code-char (subseq field 0 (1+ (or (position 0 field :test-not #'eql :from-end t) -1)))))

(defparameter +fuzz-net-network-names+
  '((:ipv4 . "ipv4") (:ipv6 . "ipv6") (:torv3 . "onion") (:i2p . "i2p") (:cjdns . "cjdns")
    (:unroutable . "not_publicly_routable"))
  "Core GetNetworkName (netbase.cpp:111-127).")

(defun %fuzz-net-receive-bytes (peer writer bytes fed delivered)
  "CNode::ReceiveMsgBytes (net.cpp:653-697): BYTES into PEER through the
WRITER end, read until the reader has taken every byte FED (an adjustable
vector BYTES are appended to) or the peer is gone; messages are pushed onto
the cell DELIVERED."
  (let ((conn (bl.net:peer-connection peer)))
    (when (and (plusp (length bytes)) (bl.net:send-bytes writer bytes))
      (%v2t-drain writer :seconds 2)
      (loop for b across bytes do (vector-push-extend b fed))
      (loop with deadline = (+ (get-internal-real-time) (* 5 internal-time-units-per-second))
            do (multiple-value-bind (command payload) (bl.net:receive-message peer :timeout 1)
                 (cond (command (push (cons command (coerce payload '(vector (unsigned-byte 8))))
                                      (car delivered)))
                       ((eq (bl.net:peer-state peer) :disconnected) (return))
                       ((and (eq payload :incomplete)
                             (>= (bl.net:connection-bytes-received conn) (length fed)))
                        (return))
                       ((> (get-internal-real-time) deadline) (return))
                       ((eq payload :incomplete) (sleep 0.0005))))))))

(defun %fuzz-net-check-received (peer fed delivered)
  "What PEER delivered is Core's reading of FED, and a connection Core drops
is dropped."
  (multiple-value-bind (want end) (%v1-reference-messages fed bl.ser:*network-magic*)
    (let ((got (reverse (car delivered))))
      (fuzz-assert (= (length (fuzz-sabotage got)) (length want))
                   "~D messages delivered where Core delivers ~D (~A)" (length got) (length want) end)
      (loop for (command . payload) in got
            for (field . want-payload) in want
            do (fuzz-assert (and (string= command (%fuzz-net-type-string field)) (equalp payload want-payload))
                            "delivered ~S where Core delivers ~S" command (%fuzz-net-type-string field)))
      (when (eq end :disconnect)
        (fuzz-assert (eq (bl.net:peer-state peer) :disconnected)
                     "Core drops this connection; ours is ~S" (bl.net:peer-state peer))))))

(defun %fuzz-net-check-stats (node peer addr-local)
  "CNode::CopyStats (net.cpp:607-661) through getpeerinfo: one row while the
peer is connected and none after (getpeerinfo walks Core's m_nodes, which a
closed node leaves), naming the peer as it is. ADDR-LOCAL is the
(network bytes port) the peer reported, or NIL."
  (let ((rows (yason:parse (rpc-result-json (bl.rpc:dispatch-rpc-method node "getpeerinfo" nil)))))
    (if (eq (bl.net:peer-state peer) :disconnected)
        (fuzz-assert (null rows) "a closed peer is still in getpeerinfo")
        (let* ((row (first rows))
               (field (lambda (name) (gethash name row))))
          (fuzz-assert (and (= (length rows) 1) (eql (funcall field "id") (fuzz-sabotage (bl.net:peer-id peer))))
                       "getpeerinfo answered ~D rows for peer ~D" (length rows) (bl.net:peer-id peer))
          (fuzz-assert (equal (funcall field "connection_type")
                              (bl.net:connection-type-string (bl.net:peer-conn-type peer)))
                       "connection_type ~S for ~S" (funcall field "connection_type") (bl.net:peer-conn-type peer))
          (fuzz-assert (eq (funcall field "inbound") (bl.net:peer-inbound peer)))
          (fuzz-assert (equal (funcall field "network")
                              (cdr (assoc (bl.net:peer-connected-through-network peer) +fuzz-net-network-names+)))
                       "getpeerinfo says ~S for a peer connected through ~S"
                       (funcall field "network") (bl.net:peer-connected-through-network peer))
          (destructuring-bind (&optional network bytes port) addr-local
            (let ((valid (and network (bl.net:address-valid-p bytes network)))
                  (shown (funcall field "addrlocal")))
              (fuzz-assert (eq (and shown t) (and valid t))
                           "addrlocal ~S for a reported ~A address that is ~:[not ~;~]valid"
                           shown network valid)
              (when shown
                (let* ((colon (position #\: shown :from-end t))
                       (host (string-trim "[]" (subseq shown 0 colon))))
                  (multiple-value-bind (parsed-network parsed) (bl.net:parse-network-address host)
                    (declare (ignore parsed-network))
                    (fuzz-assert (and (equalp parsed bytes)
                                      (= (parse-integer shown :start (1+ colon)) port))
                                 "addrlocal ~S does not name ~A port ~D"
                                 shown (bl.net:network-address-to-string network bytes) port))))))))))

(define-fuzz-target net
    (buffer :core "net.cpp:31-74 (net)" :iterations 150 :max-len 800)
  "A peer under any sequence of disconnects, stats reads and received bytes:
it delivers exactly the messages Core's transport reads out of the bytes and
drops the connection where Core does; its stats name it, its connection type,
the network it came through and the local address it reported when that is
valid; it holds no permission no whitelist granted."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (bl.ser:*mock-time* (consume-integral-in-range fdp 1 4102444800))
         (bl.net:*whitelist-entries* '())
         (bl.net:*whitebind-flags* 0)
         (node (make-test-node)))
    (%with-loopback-pair (writer reader)
      (let* ((peer (%fuzz-net-node-peer fdp reader))
             (addr-local nil)
             (fed (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))
             (delivered (list '())))
        (setf (bl:node-peers node) (list peer))
        (consume-integral fdp :i32)           ; SetCommonVersion
        (when (consume-bool fdp)              ; SetAddrLocal: a V1 CService
          (multiple-value-bind (network bytes) (consume-net-addr fdp)
            (declare (ignore network))
            ;; A V1 address is sixteen bytes and its network is what the bytes
            ;; say (CNetAddr::V1 unserialization): a CJDNS address is IPv6 here.
            (when (= (length bytes) 16)
              (setf addr-local (list (bl.net:ip-network bytes) bytes (consume-integral fdp :u16)))
              ;; As the VERSION handler stores it: the message read off the wire.
              (setf (bl.net:peer-version peer)
                    (bl.bytes:with-byte-reader
                        (in (bl.ser:make-version-message-bytes
                             :addr-recv (bl.ser:make-net-addr :ip bytes :port (third addr-local))))
                      (bl.ser:read-version-message in))))))
        (limited-while ((%fuzz-continue-p fdp) 10000)
          (call-one-of fdp
            (bl.net:disconnect-peer peer)
            (%fuzz-net-check-stats node peer addr-local)
            nil                               ; AddRef
            nil                               ; Release
            (unless (eq (bl.net:peer-state peer) :disconnected)
              (%fuzz-net-receive-bytes
               peer writer
               (if (consume-bool fdp)
                   (consume-random-length-byte-vector fdp)
                   (bl.ser:serialize-message (pick-value-in-array fdp +fuzz-net-message-types+)
                                             (consume-random-length-byte-vector fdp)))
               fed delivered)
              (%fuzz-net-check-received peer fed delivered))))
        (%fuzz-net-check-stats node peer addr-local)
        (bl.net:peer-addr-local peer)
        (fuzz-assert (eq (bl.net:peer-connected-through-network peer)
                         (if (bl.net:peer-inbound-onion peer)
                             :torv3
                             (multiple-value-bind (network bytes)
                                 (bl.net:parse-network-address (bl.net:peer-address peer))
                               (bl.net:address-net-class network bytes))))
                     "~A is connected through ~S, Core's GetNetClass says otherwise"
                     (bl.net:peer-address peer) (bl.net:peer-connected-through-network peer))
        (let ((flag (pick-value-in-array fdp (list 0 1 2 4 8 16 32 64 (consume-integral fdp :u32)))))
          (fuzz-assert (eq (bl.net:peer-has-permission-p peer flag) (zerop flag))
                       "with no whitelist the peer holds permission ~D" flag))))))
