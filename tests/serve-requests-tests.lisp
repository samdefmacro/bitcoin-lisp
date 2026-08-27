(in-package #:bitcoin-lisp.tests)

;;; Serving peer requests: getheaders / getblocks / getaddr.
;;;
;;; The responder side mirrors Bitcoin Core's net_processing handlers — find the
;;; fork point of the peer's locator in our active chain, then walk forward
;;; answering with headers (getheaders) or an inv of block hashes (getblocks),
;;; and answer getaddr from the address book (inbound-only, once per connection).
;;; These tests build a synthetic active chain and exercise the pure response
;;; builders plus the getaddr gating, with no sockets involved.

(in-suite :serve-requests-tests)

;;;; Helpers

(defun %zero32 ()
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))

(defun %uniq-hash (id)
  "A distinct 32-byte hash from an integer ID (for synthetic chains/locators)."
  (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref h 0) (logand id #xFF))
    (setf (aref h 1) (logand (ash id -8) #xFF))
    (setf (aref h 2) (logand (ash id -16) #xFF))
    h))

(defun %make-served-chain (n)
  "Build a fresh chain-state with a genesis block plus N further blocks, each
carrying a real header chained by prev-block hash and set as the active tip.
Returns (VALUES chain-state entries) with ENTRIES ascending (genesis first)."
  (let* ((entries '())
         (prev-hash (%zero32))
         (prev-entry nil)
         (cs nil))
    (dotimes (h (1+ n))
      (let* ((merkle (%uniq-hash (+ 5000 h)))
             (header (bl.ser:make-block-header
                      :version 1 :prev-block prev-hash :merkle-root merkle
                      :timestamp (+ 1700000000 h) :bits #x1d00ffff :nonce h))
             (hash (bl.ser:block-header-hash header))
             (entry (bl.store:make-block-index-entry
                     :hash hash :height h :header header
                     :prev-entry prev-entry :chain-work (1+ h) :status :valid)))
        (when (zerop h)
          (setf cs (bl.store:make-chain-state
                    :genesis-hash hash :best-block-hash hash :best-height 0)))
        (bl.store:add-block-index-entry cs entry)
        (bl.store:update-chain-tip cs hash h)
        (push entry entries)
        (setf prev-hash hash prev-entry entry)))
    (values cs (nreverse entries))))

(defun %entry-hash (entries height)
  (bl.store:block-index-entry-hash (nth height entries)))

(defun %getheaders-payload (locator-hashes &optional stop-hash)
  "Build the on-wire payload (header stripped) of a getheaders message."
  (subseq (bl.ser:make-getheaders-message locator-hashes stop-hash)
          24))

(defun %getblocks-payload (locator-hashes &optional stop-hash)
  (subseq (bl.ser:make-getblocks-message locator-hashes stop-hash)
          24))

(defun %message-payload (msg)
  "Return the payload bytes of a serialized P2P message (strip 24-byte header)."
  (bl.bytes:with-byte-reader (s msg)
    (let ((hdr (bl.ser:read-message-header s)))
      (subseq msg 24 (+ 24 (bl.ser:message-header-payload-length hdr))))))

(defun %message-command (msg)
  (bl.bytes:with-byte-reader (s msg)
    (bl.ser:message-header-command
     (bl.ser:read-message-header s))))

;;;; find-fork-in-active-chain

(test fork-returns-tip-when-locator-has-tip
  (multiple-value-bind (cs entries) (%make-served-chain 5)
    (let ((fork (bl.store:find-fork-in-active-chain
                 cs (list (%entry-hash entries 5)))))
      (is (= 5 (bl.store:block-index-entry-height fork))))))

(test fork-returns-highest-on-chain-hash
  (multiple-value-bind (cs entries) (%make-served-chain 5)
    ;; Locator most-recent-first: an unknown hash, then block 3, then block 1.
    (let ((fork (bl.store:find-fork-in-active-chain
                 cs (list (%uniq-hash 999999)
                          (%entry-hash entries 3)
                          (%entry-hash entries 1)))))
      (is (= 3 (bl.store:block-index-entry-height fork))))))

(test fork-falls-back-to-genesis
  (multiple-value-bind (cs entries) (%make-served-chain 5)
    (declare (ignore entries))
    (let ((fork (bl.store:find-fork-in-active-chain
                 cs (list (%uniq-hash 111) (%uniq-hash 222)))))
      (is (= 0 (bl.store:block-index-entry-height fork))))))

;;;; active-chain-entries-from

(test active-chain-entries-ascending-and-bounded
  (multiple-value-bind (cs entries) (%make-served-chain 5)
    (declare (ignore entries))
    (let ((got (bl.store:active-chain-entries-from cs 1 100)))
      (is (= 5 (length got)))
      (is (equal '(1 2 3 4 5)
                 (mapcar #'bl.store:block-index-entry-height got))))
    ;; Limit caps the count, still from FROM-HEIGHT ascending.
    (let ((got (bl.store:active-chain-entries-from cs 2 2)))
      (is (equal '(2 3)
                 (mapcar #'bl.store:block-index-entry-height got))))
    ;; Above the tip => empty.
    (is (null (bl.store:active-chain-entries-from cs 6 100)))))

;;;; getheaders-response-message

(test getheaders-from-genesis-returns-rest-of-chain
  (multiple-value-bind (cs entries) (%make-served-chain 5)
    (let* ((payload (%getheaders-payload (list (%entry-hash entries 0))))
           (msg (bl.net::getheaders-response-message payload cs))
           (headers (bl.ser:parse-headers-payload
                     (%message-payload msg))))
      (is (string= "headers" (%message-command msg)))
      (is (= 5 (length headers)))
      ;; Headers are blocks 1..5 in order, matching our index hashes.
      (loop for header in headers
            for height from 1
            do (is (equalp (%entry-hash entries height)
                           (bl.ser:block-header-hash header)))))))

(test getheaders-at-tip-returns-empty
  (multiple-value-bind (cs entries) (%make-served-chain 5)
    (let* ((payload (%getheaders-payload (list (%entry-hash entries 5))))
           (msg (bl.net::getheaders-response-message payload cs))
           (headers (bl.ser:parse-headers-payload
                     (%message-payload msg))))
      (is (null headers)))))

(test getheaders-stop-hash-is-inclusive
  (multiple-value-bind (cs entries) (%make-served-chain 5)
    (let* ((payload (%getheaders-payload (list (%entry-hash entries 0))
                                         (%entry-hash entries 2)))
           (msg (bl.net::getheaders-response-message payload cs))
           (headers (bl.ser:parse-headers-payload
                     (%message-payload msg))))
      ;; Blocks 1 and 2 — stop hash (block 2) is included.
      (is (= 2 (length headers)))
      (is (equalp (%entry-hash entries 2)
                  (bl.ser:block-header-hash
                   (car (last headers))))))))

(test getheaders-null-locator-returns-stop-header
  (multiple-value-bind (cs entries) (%make-served-chain 5)
    (let* ((payload (%getheaders-payload '() (%entry-hash entries 3)))
           (msg (bl.net::getheaders-response-message payload cs))
           (headers (bl.ser:parse-headers-payload
                     (%message-payload msg))))
      (is (= 1 (length headers)))
      (is (equalp (%entry-hash entries 3)
                  (bl.ser:block-header-hash (first headers)))))))

;;;; getblocks-response-message

(test getblocks-from-genesis-returns-inv
  (multiple-value-bind (cs entries) (%make-served-chain 5)
    (let* ((payload (%getblocks-payload (list (%entry-hash entries 0))))
           (msg (bl.net::getblocks-response-message payload cs))
           (invs (bl.ser:parse-inv-payload (%message-payload msg))))
      (is (string= "inv" (%message-command msg)))
      (is (= 5 (length invs)))
      (loop for inv in invs
            for height from 1
            do (is (= bl.ser:+inv-type-block+
                      (bl.ser:inv-vector-type inv)))
               (is (equalp (%entry-hash entries height)
                           (bl.ser:inv-vector-hash inv)))))))

(test getblocks-stop-hash-is-exclusive
  (multiple-value-bind (cs entries) (%make-served-chain 5)
    (let* ((payload (%getblocks-payload (list (%entry-hash entries 0))
                                        (%entry-hash entries 2)))
           (msg (bl.net::getblocks-response-message payload cs))
           (invs (bl.ser:parse-inv-payload (%message-payload msg))))
      ;; Only block 1 — the inv stops before the stop hash (block 2).
      (is (= 1 (length invs)))
      (is (equalp (%entry-hash entries 1)
                  (bl.ser:inv-vector-hash (first invs)))))))

(test getblocks-at-tip-returns-nil
  (multiple-value-bind (cs entries) (%make-served-chain 5)
    (let ((payload (%getblocks-payload (list (%entry-hash entries 5)))))
      (is (null (bl.net::getblocks-response-message payload cs))))))

;;;; truncate-entries-at-stop

(test truncate-zero-hash-keeps-all
  (multiple-value-bind (cs entries) (%make-served-chain 3)
    (declare (ignore cs))
    (is (= 4 (length (bl.net::truncate-entries-at-stop
                      entries (%zero32) t))))))

(test truncate-missing-stop-keeps-all
  (multiple-value-bind (cs entries) (%make-served-chain 3)
    (declare (ignore cs))
    (is (= 4 (length (bl.net::truncate-entries-at-stop
                      entries (%uniq-hash 424242) t))))))

;;;; getaddr gating + addr response building

(defun %make-test-peer-address (a b c d port)
  (bl.net:make-peer-address
   :ip (bl.net::ipv4-to-mapped-ipv6 a b c d)
   :port port :services 1 :last-seen 1700000000))

(test getaddr-only-once-and-inbound-only
  (let ((bl::*node* nil))    ; book resolves to NIL: gating only, no send
    ;; Outbound peer: never marked as answered.
    (let ((outbound (bl.net:make-peer :inbound nil)))
      (bl.net::handle-getaddr outbound #() (bl.ctx:make-node-context))
      (is (null (bl.net:peer-getaddr-sent outbound))))
    ;; Inbound peer: answered exactly once (flag latches on first call).
    (let ((inbound (bl.net:make-peer :inbound t)))
      (is (null (bl.net:peer-getaddr-sent inbound)))
      (bl.net::handle-getaddr inbound #() (bl.ctx:make-node-context))
      (is-true (bl.net:peer-getaddr-sent inbound))
      ;; Second call is a no-op; flag stays set.
      (bl.net::handle-getaddr inbound #() (bl.ctx:make-node-context))
      (is-true (bl.net:peer-getaddr-sent inbound)))))

(test build-addrv2-response-round-trips
  (let ((peer (bl.net:make-peer :wants-addrv2 t))
        (addrs (list (%make-test-peer-address 203 0 113 7 18333)
                     (%make-test-peer-address 198 51 100 9 48333))))
    (let* ((msg (bl.net::build-addr-response peer addrs))
           (parsed (bl.ser:parse-addrv2-payload (%message-payload msg))))
      (is (string= "addrv2" (%message-command msg)))
      (is (= 2 (length parsed)))
      ;; Ports survive the round trip.
      (is (equal '(18333 48333)
                 (mapcar (lambda (e) (bl.ser:net-addr-port (first e)))
                         parsed))))))

(test build-addr-v1-response-has-addr-command
  (let ((peer (bl.net:make-peer :wants-addrv2 nil))
        (addrs (list (%make-test-peer-address 203 0 113 7 18333))))
    (is (string= "addr" (%message-command
                         (bl.net::build-addr-response peer addrs))))))

(test notfound-message-roundtrip
  "make-notfound-message builds a \"notfound\" message whose payload parses as
inv vectors (same shape as inv) -- the reply for unserved tx getdata."
  (let* ((inv (bl.ser:make-inv-vector
               :type bl.ser:+inv-type-wtx+
               :hash (%uniq-hash 777)))
         (msg (bl.ser:make-notfound-message (list inv))))
    (is (string= "notfound" (%message-command msg)))
    (let ((parsed (bl.ser:parse-inv-payload (%message-payload msg))))
      (is (= 1 (length parsed)))
      (is (= bl.ser:+inv-type-wtx+
             (bl.ser:inv-vector-type (first parsed))))
      (is (equalp (%uniq-hash 777)
                  (bl.ser:inv-vector-hash (first parsed)))))))

(test relay-address-fanout-and-dedup
  "relay-address (Core RelayAddress) forwards a fresh address to exactly 2
eligible peers -- skipping the source, block-relay/feeler peers, and peers that
already know it -- and marks the source + targets in their known-addrs sets."
  (let* ((source (bl.net:make-peer :state :ready :address "9.9.9.9:8333"))
         (full (loop for i below 4
                     collect (bl.net:make-peer
                              :state :ready :addr-relay-enabled t
                              :address (format nil "1.1.1.~D:8333" i))))
         (br (bl.net:make-peer :state :ready :conn-type :block-relay))
         (peers (append (list source br) full))
         (pa (bl.net:make-peer-address
              :ip (let ((ip (make-array 16 :element-type '(unsigned-byte 8)
                                           :initial-element 0)))
                    (setf (aref ip 10) #xff (aref ip 11) #xff (aref ip 12) 8) ip)
              :port 8333 :services 1
              :last-seen (bl.ser:get-unix-time)))
         (key (bl.net::%addr-gossip-key pa))
         (sent (bl.net::relay-address pa source peers)))
    ;; exactly 2 targets chosen (4 eligible; source + block-relay excluded)
    (is (= 2 sent))
    ;; the source is marked as knowing the address
    (is-true (bl:recent-reject-p
              (bl.net:peer-known-addrs source) key))
    ;; exactly 2 of the full-relay peers know it; the block-relay peer doesn't
    (is (= 2 (count-if (lambda (p)
                         (bl:recent-reject-p
                          (bl.net:peer-known-addrs p) key))
                       full)))
    (is-false (bl:recent-reject-p
               (bl.net:peer-known-addrs br) key))
    ;; relaying the same address again the same day: all targets already know
    ;; it or get deduped -- at most the remaining 2 fresh peers are picked
    (let ((sent2 (bl.net::relay-address pa source peers)))
      (is (= 2 sent2))
      (is (= 4 (count-if (lambda (p)
                           (bl:recent-reject-p
                            (bl.net:peer-known-addrs p) key))
                         full)))
      ;; third time: everyone knows it -> nothing sent
      (is (= 0 (bl.net::relay-address pa source peers))))))

;;;; ============================================================
;;;; G7-20: per-network getaddr response cache
;;;; ============================================================

(defun %g720-book (n)
  "An address book seeded with N routable addresses spread across /16s, with
RECENT last-seen stamps — addrman excludes 'terrible' (stale) entries from
GetAddr, so a fixed 2023 timestamp yields an empty sample.

NB the book may hold FEWER than N — addrman buckets collide by design — so
these tests never assert an exact count (a standing rule in this project)."
  (let ((book (bl.net:make-address-book))
        (now (bl.ser:get-unix-time)))
    (dotimes (i n)
      (bl.net:address-book-add
       book (bl.net:make-peer-address
             :ip (bl.net::ipv4-to-mapped-ipv6
                  203 (mod i 250) (floor i 250) 7)
             :port (+ 18333 i) :services 1 :last-seen now)))
    book))

(test g7-20-getaddr-response-is-cached-per-network
  "G7-20: re-sampling addrman on every getaddr let an attacker reconnect
repeatedly and harvest many independent samples — enough to reconstruct the
table and watch timestamps churn. Core answers every requestor on one network
with the SAME snapshot for 21-27h (net.cpp:3694-3730), which is what makes
reconnecting pointless."
  (bl.net::clear-addr-response-caches)
  (let* ((book (%g720-book 200))
         (now 1700000000))
    (let ((r1 (bl.net::cached-getaddr-response book :ipv4 now))
          (r2 (bl.net::cached-getaddr-response book :ipv4 (+ now 60)))
          (r3 (bl.net::cached-getaddr-response
               book :ipv4 (+ now (* 3 60 60)))))
      (is (eq r1 r2) "a second requestor inside the window gets the SAME snapshot")
      (is (eq r1 r3) "still the same snapshot hours later"))
    ;; A different requestor network gets its own snapshot and its own expiry.
    (let ((v4 (bl.net::cached-getaddr-response book :ipv4 now))
          (onion (bl.net::cached-getaddr-response book :torv3 now)))
      (is (not (eq v4 onion))
          "networks must not share a cache entry"))
    (is (= 2 (hash-table-count bl.net::*addr-response-caches*)))))

(test g7-20-cache-expires-between-21h-and-27h
  "Expiry is 21h + rand(6h) (Core's m_cache_entry_expiration), so the refresh
instant is not predictable and cannot itself be used as a clock signal."
  (bl.net::clear-addr-response-caches)
  (let ((book (%g720-book 60))
        (now 1700000000))
    (let ((first (bl.net::cached-getaddr-response book :ipv4 now)))
      ;; Just under the minimum lifetime: still the same object.
      (is (eq first (bl.net::cached-getaddr-response
                     book :ipv4 (+ now (* 21 60 60) -60))))
      ;; Past the maximum lifetime: refilled.
      (let ((refreshed (bl.net::cached-getaddr-response
                        book :ipv4 (+ now (* 27 60 60) 60))))
        (is (not (eq first refreshed)) "must refill after the maximum lifetime")))
    ;; The stored expiry must sit inside [21h, 27h].
    (bl.net::clear-addr-response-caches)
    (bl.net::cached-getaddr-response book :ipv4 now)
    (let ((expiry (cdr (gethash :ipv4 bl.net::*addr-response-caches*))))
      (is (>= expiry (+ now (* 21 60 60))))
      (is (<= expiry (+ now (* 27 60 60)))))))

(test g7-20-ban-filter-runs-at-fill-time-only
  "Core filters banned/discouraged inside GetAddressesUnsafe (net.cpp:3686-3690),
which runs ONLY on a cache miss; a hit returns the cached list verbatim
(net.cpp:3729). Re-filtering per hit would make responses differ between
requestors inside one window whenever a ban landed mid-window — exactly the
fingerprinting signal the cache exists to erase. The visible consequence is
that a banned address keeps being gossiped for up to 27h. That is
Core-identical and intended, so it is asserted here rather than 'fixed'."
  (bl.net::clear-addr-response-caches)
  (bl.net::clear-discouraged)
  (let* ((book (%g720-book 40))
         (now 1700000000)
         (filled (bl.net::cached-getaddr-response book :ipv4 now)))
    (is (plusp (length filled)) "precondition: the cache filled with something")
    ;; Discourage an address that IS in the cached snapshot.
    (let ((victim (bl.net:peer-address-string (first filled))))
      (bl.net:discourage-peer victim)
      (let ((hit (bl.net::cached-getaddr-response book :ipv4 (+ now 60))))
        (is (eq filled hit)
            "a cache HIT must be returned verbatim, not re-filtered"))
      ;; ...but a refill after expiry drops it.
      (let ((refilled (bl.net::cached-getaddr-response
                       book :ipv4 (+ now (* 28 60 60)))))
        (is (notany (lambda (pa)
                      (string= victim (bl.net:peer-address-string pa)))
                    refilled)
            "a refill must apply the ban/discourage filter"))
      (bl.net::clear-discouraged))))

(test g7-20-getnodeaddresses-stays-uncached
  "Core's rpc/net.cpp:956 deliberately calls the UNCACHED GetAddressesUnsafe:
the operator asking their own node must see live addrman state, not a snapshot
frozen for a day. Guard against 'helpfully' routing it through the cache."
  (let ((src (with-open-file (s (merge-pathnames "src/rpc/methods.lisp"
                                                 (asdf:system-source-directory :bitcoin-lisp)))
               (let ((text (make-string (file-length s))))
                 (subseq text 0 (read-sequence text s))))))
    (let ((start (search "defun rpc-getnodeaddresses" src)))
      (is (integerp start) "rpc-getnodeaddresses must exist")
      (when start
        (let ((body (subseq src start (min (length src) (+ start 2000)))))
          (is (null (search "cached-getaddr-response" body))
              "getnodeaddresses must not use the getaddr cache"))))))

(test relay-address-skips-peers-without-addr-relay
  "Core RelayAddress (net_processing.cpp:2311) gossips only to peers with
address relay set up: an inbound peer that never sent addr/getaddr — so
SetupAddressRelay never ran for it — receives nothing, even though it relays
transactions."
  (let* ((source (bl.net:make-peer :state :ready :address "9.9.9.9:8333"))
         (with (bl.net:make-peer :state :ready :addr-relay-enabled t
                                                   :address "1.1.1.1:8333"))
         (without (bl.net:make-peer :state :ready
                                                      :address "1.1.1.2:8333"))
         (pa (%make-test-peer-address 8 0 0 0 8333))
         (key (bl.net::%addr-gossip-key pa)))
    (is (= 1 (bl.net::relay-address pa source (list source with without))))
    (is-true (bl:recent-reject-p
              (bl.net:peer-known-addrs with) key))
    (is-false (bl:recent-reject-p
               (bl.net:peer-known-addrs without) key))))

(test feefilter-above-max-money-is-ignored
  "Core applies a feefilter only when MoneyRange(newFeeFilter)
(net_processing.cpp:5126); a rate above MAX_MONEY is ignored rather than
stored, where it would silently suppress every announcement to the peer."
  (let ((peer (bl.net:make-peer :state :ready :address "1.1.1.3:8333"))
        (ok (%message-payload (bl.ser:make-feefilter-message 1000)))
        (absurd (%message-payload (bl.ser:make-feefilter-message
                                   (1+ bl.val:+max-money+)))))
    (bl.net::handle-message peer "feefilter" ok (bl.ctx:make-node-context))
    (is (= 1000 (bl.net:peer-feefilter-rate peer)))
    (bl.net::handle-message peer "feefilter" absurd (bl.ctx:make-node-context))
    (is (= 1000 (bl.net:peer-feefilter-rate peer)))))

(test automatic-inbound-capacity-follows-core
  "Core CConnman::Init (net.h:1110-1113): -maxconnections is the automatic
total; inbound = total - (full-relay + block-relay-only + feeler), floored at 0."
  (is (= 114 (bl::automatic-inbound-capacity 125 8)))
  (is (= 5 (bl::automatic-inbound-capacity 16 8)))
  (is (= 0 (bl::automatic-inbound-capacity 8 8))))
