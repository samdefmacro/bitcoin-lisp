(in-package #:bitcoin-lisp.tests)

;;; Address manager (new/tried bucket addrman) tests.
;;;
;;; Bucket determinism + grouping, Add/Good/Attempt placement and promotion,
;;; Select/GetAddr behavior, and the eclipse-resistance properties: any single
;;; source-group occupies at most 64 of the 1024 new buckets, and flooding new
;;; addresses can never evict the tried table.

(in-suite :addrman-tests)

;;;; Helpers

(defun %ab ()
  "A fresh address book with a fixed (deterministic) bucket key."
  (let ((k (make-array 32 :element-type '(unsigned-byte 8))))
    (dotimes (i 32) (setf (aref k i) (mod (* i 7) 256)))
    (bitcoin-lisp.networking:make-address-book :key k)))

(defun %ip (a b c d) (bitcoin-lisp.networking:ipv4-to-mapped-ipv6 a b c d))

(defun %now () (bitcoin-lisp.serialization:get-unix-time))

(defun %pa (a b c d &key (port 8333) (services 1) (last-seen (%now)))
  (bitcoin-lisp.networking:make-peer-address
   :ip (%ip a b c d) :port port :services services :last-seen last-seen))

(defun %ipv6 (&rest first-bytes)
  (let ((ip (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (loop for b in first-bytes for i from 0 do (setf (aref ip i) b))
    ip))

;;;; Grouping

(test net-group-key-ipv4-is-slash16
  (is (equal '(1 203 0)
             (coerce (bitcoin-lisp.networking:net-group-key (%ip 203 0 113 5)) 'list))))

(test net-group-key-ipv6-is-slash32
  (is (equal '(2 #x20 #x01 #x0d #xb8)
             (coerce (bitcoin-lisp.networking:net-group-key
                      (%ipv6 #x20 #x01 #x0d #xb8 #xab #xcd))
                     'list))))

;;;; Bucket functions

(test buckets-deterministic-and-in-range
  (let* ((book (%ab)) (pa (%pa 1 2 3 4))
         (sg (bitcoin-lisp.networking:net-group-key (%ip 9 9 9 9))))
    (is (= (bitcoin-lisp.networking::new-bucket book pa sg)
           (bitcoin-lisp.networking::new-bucket book pa sg)))
    (is (<= 0 (bitcoin-lisp.networking::new-bucket book pa sg) 1023))
    (is (= (bitcoin-lisp.networking::tried-bucket book pa)
           (bitcoin-lisp.networking::tried-bucket book pa)))
    (is (<= 0 (bitcoin-lisp.networking::tried-bucket book pa) 255))
    (is (<= 0 (bitcoin-lisp.networking::bucket-position book pa t 0) 63))))

;;;; Add / Good / Attempt

(test add-creates-new-entry
  (let ((book (%ab)))
    (is-true (bitcoin-lisp.networking:address-book-add book (%pa 1 2 3 4)))
    (is (= 1 (bitcoin-lisp.networking:address-book-count book)))
    (is (= 1 (bitcoin-lisp.networking::address-book-n-new book)))
    (is (= 0 (bitcoin-lisp.networking::address-book-n-tried book)))
    (let ((pa (bitcoin-lisp.networking:address-book-lookup book (%ip 1 2 3 4) 8333)))
      (is (not (null pa)))
      (is (= 1 (bitcoin-lisp.networking:peer-address-ref-count pa)))
      (is (null (bitcoin-lisp.networking:peer-address-in-tried pa))))))

(test add-rejects-unroutable
  (let ((book (%ab)))
    (is (null (bitcoin-lisp.networking:address-book-add
               book (bitcoin-lisp.networking:make-peer-address
                     :ip (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)
                     :port 8333))))
    (is (= 0 (bitcoin-lisp.networking:address-book-count book)))))

(test good-promotes-new-to-tried
  (let ((book (%ab)))
    (bitcoin-lisp.networking:address-book-add book (%pa 1 2 3 4))
    (is-true (bitcoin-lisp.networking:address-book-good book (%ip 1 2 3 4) 8333))
    (is (= 0 (bitcoin-lisp.networking::address-book-n-new book)))
    (is (= 1 (bitcoin-lisp.networking::address-book-n-tried book)))
    (is (= 1 (bitcoin-lisp.networking:address-book-count book)))
    (let ((pa (bitcoin-lisp.networking:address-book-lookup book (%ip 1 2 3 4) 8333)))
      (is-true (bitcoin-lisp.networking:peer-address-in-tried pa))
      (is (= 0 (bitcoin-lisp.networking:peer-address-ref-count pa))))))

(test attempt-counts-failures
  (let ((book (%ab)))
    (bitcoin-lisp.networking:address-book-add book (%pa 1 2 3 4))
    (bitcoin-lisp.networking:address-book-attempt book (%ip 1 2 3 4) 8333 :count-failure t)
    (let ((pa (bitcoin-lisp.networking:address-book-lookup book (%ip 1 2 3 4) 8333)))
      (is (= 1 (bitcoin-lisp.networking:peer-address-n-attempts pa))))))

;;;; Quality

(test terrible-when-ancient
  (is-true (bitcoin-lisp.networking:addr-info-terrible-p (%pa 1 2 3 4 :last-seen 1000) (%now))))

(test not-terrible-when-recent
  (let ((now (%now)))
    (is (null (bitcoin-lisp.networking:addr-info-terrible-p (%pa 1 2 3 4 :last-seen now) now)))))

;;;; Select / GetAddr

(test select-returns-known-address
  (let ((book (%ab)))
    (dotimes (i 5) (bitcoin-lisp.networking:address-book-add book (%pa 10 0 0 i)))
    (is (not (null (bitcoin-lisp.networking:address-book-select book))))))

(test select-empty-book-is-nil
  (is (null (bitcoin-lisp.networking:address-book-select (%ab)))))

(test get-addr-skips-terrible
  (let ((book (%ab)))
    (bitcoin-lisp.networking:address-book-add book (%pa 10 0 0 1 :last-seen (%now)))
    (bitcoin-lisp.networking:address-book-add book (%pa 10 0 0 2 :last-seen 1000)) ; ancient
    (let ((addrs (bitcoin-lisp.networking:address-book-get-addr book :max 0 :pct 100)))
      (is (= 1 (length addrs)))
      (is (equalp (%ip 10 0 0 1)
                  (bitcoin-lisp.networking:peer-address-ip (first addrs)))))))

(test get-addr-respects-max
  (let ((book (%ab)))
    (dotimes (i 20) (bitcoin-lisp.networking:address-book-add book (%pa 12 0 0 i)))
    (is (<= (length (bitcoin-lisp.networking:address-book-get-addr book :max 5 :pct 100)) 5))))

;;;; Eclipse resistance

(test one-source-group-bounded-to-64-new-buckets
  "Every address learned from a single source-group lands in at most 64 of the
1024 new buckets — an attacker flooding from one source can poison only 64."
  (let* ((book (%ab))
         (sg (bitcoin-lisp.networking:net-group-key (%ip 6 6 6 6)))
         (buckets (make-hash-table)))
    (dotimes (i 600)
      (let ((pa (%pa (+ 11 (mod i 200)) (mod (floor i 200) 256) (mod i 251) (mod i 241))))
        (setf (gethash (bitcoin-lisp.networking::new-bucket book pa sg) buckets) t)))
    (is (<= (hash-table-count buckets) 64))))

(test tried-table-survives-new-flood
  "Flooding new addresses (even all from one source) never evicts tried entries."
  (let ((book (%ab)))
    (dotimes (i 3)
      (bitcoin-lisp.networking:address-book-add book (%pa 20 0 0 i))
      (bitcoin-lisp.networking:address-book-good book (%ip 20 0 0 i) 8333))
    (let ((tried-before (bitcoin-lisp.networking::address-book-n-tried book))
          (src (bitcoin-lisp.networking:net-group-key (%ip 7 7 7 7))))
      (is (> tried-before 0))
      (dotimes (i 400)
        (bitcoin-lisp.networking:address-book-add
         book (%pa (+ 100 (mod i 150)) (mod (floor i 150) 256) (mod i 251) (mod i 241)) src))
      (is (= tried-before (bitcoin-lisp.networking::address-book-n-tried book))))))

;;;; Network-typed records (BIP155 P1): keying, persistence v4, migration

(defparameter +am-onion-pk+
  "79bcc625184b05194975c28b66b66b0469f7f6556fb1ac3189a79b40dda32f1f"
  "Core net_tests.cpp TORv3 vector (pg6mm....onion).")
(defparameter +am-i2p-hash+
  "a2894dabaec08c0051a481a6dac88b64f98232ae42d4b6fd2fa81952dfe36a87"
  "Core net_tests.cpp I2P vector (ukeu3....b32.i2p).")

(defun %am-hex (s) (bitcoin-lisp.crypto:hex-to-bytes s))

(defun %pa-net (net ip &key (port 8333) (services 1) (last-seen (%now)))
  (bitcoin-lisp.networking:make-peer-address
   :net net :ip ip :port port :services services :last-seen last-seen))

(test add-records-typed-source-group
  "address-book-add's optional source is a net-group KEY (any network), so
gossip learned from an onion peer buckets by the onion source group — Core
AddrMan::Add(…, source) with a Tor source."
  (let* ((book (%ab))
         (sg (bitcoin-lisp.networking:net-group-key (%am-hex +am-onion-pk+) :torv3)))
    (is-true (bitcoin-lisp.networking:address-book-add book (%pa 1 2 3 4) sg))
    (let ((pa (bitcoin-lisp.networking:address-book-lookup book (%ip 1 2 3 4) 8333)))
      (is (not (null pa)))
      (is (equalp sg (bitcoin-lisp.networking::peer-address-source-group pa))))))

(test address-key-disambiguates-networks
  "Identical bytes + port on different networks produce different keys, so a
TORv3 pubkey that happens to equal an I2P hash can never collide in the map."
  (let ((bytes (%am-hex +am-onion-pk+)))
    (is (not (equalp (bitcoin-lisp.networking:make-address-key bytes 8333 :torv3)
                     (bitcoin-lisp.networking:make-address-key bytes 8333 :i2p))))
    ;; And the same record keys identically both times.
    (is (equalp (bitcoin-lisp.networking:make-address-key bytes 8333 :torv3)
                (bitcoin-lisp.networking:make-address-key bytes 8333 :torv3)))
    ;; NIL net derives ipv4/ipv6 from 16-byte mapped form (compat callers).
    (is (equalp (bitcoin-lisp.networking:make-address-key (%ip 1 2 3 4) 8333)
                (bitcoin-lisp.networking:make-address-key (%ip 1 2 3 4) 8333 :ipv4)))))

(test same-bytes-different-net-coexist
  "Add the same 32 bytes as TORv3 and as I2P: two independent records."
  (let ((book (%ab))
        (bytes (%am-hex +am-onion-pk+)))
    (is-true (bitcoin-lisp.networking:address-book-add
              book (%pa-net :torv3 bytes :port 8333)))
    (is-true (bitcoin-lisp.networking:address-book-add
              book (%pa-net :i2p bytes :port 8333)))
    (is (= 2 (bitcoin-lisp.networking:address-book-count book)))
    (let ((tor (bitcoin-lisp.networking:address-book-lookup book bytes 8333 :torv3))
          (i2p (bitcoin-lisp.networking:address-book-lookup book bytes 8333 :i2p)))
      (is (not (null tor)))
      (is (not (null i2p)))
      (is (not (eq tor i2p)))
      (is (eq :torv3 (bitcoin-lisp.networking:peer-address-network tor)))
      (is (eq :i2p (bitcoin-lisp.networking:peer-address-network i2p))))))

(test addrman-good-promotes-onion
  "Good() works for a typed record: the onion entry moves new -> tried."
  (let ((book (%ab))
        (bytes (%am-hex +am-onion-pk+)))
    (bitcoin-lisp.networking:address-book-add book (%pa-net :torv3 bytes))
    (is-true (bitcoin-lisp.networking:address-book-good book bytes 8333 (%now) :torv3))
    (let ((pa (bitcoin-lisp.networking:address-book-lookup book bytes 8333 :torv3)))
      (is (not (null pa)))
      (is-true (bitcoin-lisp.networking:peer-address-in-tried pa)))))

(defun %am-force-collision (book &key (limit 6000))
  "Add + Good addresses until a tried-table collision queues. Returns the
challenger's peer-address, or NIL if none collided within LIMIT."
  (loop for i from 1 to limit
        do (let ((pa (%pa (ldb (byte 8 16) i) (ldb (byte 8 8) i)
                          (ldb (byte 8 0) i) 7)))
             (bitcoin-lisp.networking:address-book-add book pa)
             (bitcoin-lisp.networking:address-book-good
              book (bitcoin-lisp.networking:peer-address-ip pa) 8333 (%now) :ipv4)
             (let ((ids (bitcoin-lisp.networking::address-book-tried-collisions book)))
               (when ids
                 (return (gethash (first ids)
                                  (bitcoin-lisp.networking::address-book-info book))))))))

(test tried-collision-tests-the-incumbent-before-evicting
  "Core's test-before-evict (addrman.cpp:930-960, 975-1000). A queued tried
collision is resolved by the INCUMBENT's own evidence, and select-tried-collision
is what hands that incumbent to the feeler: without it the only branch that can
fire is the 40-minute fallback, so any challenger evicts any entry we merely
have not dialed lately."
  (let* ((book (bitcoin-lisp.networking:make-address-book))
         (challenger (%am-force-collision book)))
    (is-true challenger "a tried collision was queued")
    ;; select-tried-collision hands back the INCUMBENT holding the slot.
    (let ((incumbent (bitcoin-lisp.networking:select-tried-collision book)))
      (is-true incumbent)
      (is-true (bitcoin-lisp.networking::peer-address-in-tried incumbent))
      (is (not (eq incumbent challenger)))
      ;; (a) Incumbent connected recently -> challenger dropped, slot kept.
      (setf (bitcoin-lisp.networking::peer-address-last-success incumbent) (%now))
      (bitcoin-lisp.networking:resolve-tried-collisions book)
      (is (null (bitcoin-lisp.networking::address-book-tried-collisions book)))
      (is-true (bitcoin-lisp.networking::peer-address-in-tried incumbent))
      (is-false (bitcoin-lisp.networking::peer-address-in-tried challenger)))))

(test tried-collision-replaces-an-incumbent-that-failed-its-probe
  "The branch select-tried-collision exists to feed (addrman.cpp:941-950): the
feeler attempted the incumbent, it did not succeed, and it has had its 60 s —
so the challenger takes the slot. Before this branch existed the only exit was
the blind 40-minute timer."
  (let* ((book (bitcoin-lisp.networking:make-address-book))
         (challenger (%am-force-collision book)))
    (is-true challenger)
    (let ((incumbent (bitcoin-lisp.networking:select-tried-collision book))
          (now (%now)))
      (is-true incumbent)
      ;; Probed 2 minutes ago and never answered; last success is stale.
      (setf (bitcoin-lisp.networking::peer-address-last-success incumbent)
            (- now (* 5 60 60))
            (bitcoin-lisp.networking::peer-address-last-attempt incumbent)
            (- now 120))
      (bitcoin-lisp.networking:resolve-tried-collisions book)
      (is (null (bitcoin-lisp.networking::address-book-tried-collisions book)))
      (is-true (bitcoin-lisp.networking::peer-address-in-tried challenger)
               "challenger promoted after the incumbent failed its probe"))))

(test tried-collision-waits-out-a-fresh-probe
  "An incumbent probed seconds ago keeps its slot: Core gives it 60 s to answer
before the challenger may replace it (addrman.cpp:946)."
  (let* ((book (bitcoin-lisp.networking:make-address-book))
         (challenger (%am-force-collision book)))
    (is-true challenger)
    (let ((incumbent (bitcoin-lisp.networking:select-tried-collision book))
          (now (%now)))
      (is-true incumbent)
      (setf (bitcoin-lisp.networking::peer-address-last-success incumbent)
            (- now (* 5 60 60))
            (bitcoin-lisp.networking::peer-address-last-attempt incumbent)
            (- now 5)
            ;; Not yet old enough for the untestable fallback either.
            (bitcoin-lisp.networking::peer-address-last-success challenger) now)
      (bitcoin-lisp.networking:resolve-tried-collisions book)
      (is-true (bitcoin-lisp.networking::address-book-tried-collisions book)
               "collision still queued while the probe is in flight")
      (is-false (bitcoin-lisp.networking::peer-address-in-tried challenger)))))

(test peers-dat-v4-roundtrip-all-nets
  "Save/load the v4 network-typed format: IPv4, IPv6, TORv3 (tried), I2P and
CJDNS records all survive with their networks, bytes, ports and stats."
  (let ((book (bitcoin-lisp.networking:make-address-book))
        (tmp-dir (merge-pathnames "test-addrman-v4/" (uiop:temporary-directory))))
    (ensure-directories-exist (merge-pathnames "dummy" tmp-dir))
    (unwind-protect
         (let ((path (merge-pathnames "peers.dat" tmp-dir))
               (onion (%am-hex +am-onion-pk+))
               (i2p (%am-hex +am-i2p-hash+))
               (cjdns (%am-hex "fc000001000200030004000500060007")))
           (bitcoin-lisp.networking:address-book-add book (%pa 1 2 3 4 :services 9))
           (bitcoin-lisp.networking:address-book-add
            book (bitcoin-lisp.networking:make-peer-address
                  ;; Global unicast: 2001:db8::/32 is documentation space,
                  ;; which address-routable-p now refuses as Core does.
                  :ip (%ipv6 #x26 #x06 #x47 #x00 0 0 0 0 0 0 0 0 0 0 0 1)
                  :port 8333 :services 1 :last-seen (%now)))
           (bitcoin-lisp.networking:address-book-add book (%pa-net :torv3 onion))
           (bitcoin-lisp.networking:address-book-add book (%pa-net :i2p i2p :port 0))
           (bitcoin-lisp.networking:address-book-add book (%pa-net :cjdns cjdns))
           (bitcoin-lisp.networking:address-book-good book onion 8333 (%now) :torv3)
           (is (eq t (bitcoin-lisp.networking:save-address-book book path)))
           ;; Version byte in the file header is 4.
           (with-open-file (in path :element-type '(unsigned-byte 8))
             (let ((head (make-array 8 :element-type '(unsigned-byte 8))))
               (read-sequence head in)
               (is (= 4 (aref head 4)))))
           (let ((book2 (bitcoin-lisp.networking:make-address-book)))
             (is (eq t (bitcoin-lisp.networking:load-address-book book2 path)))
             (is (= 5 (bitcoin-lisp.networking:address-book-count book2)))
             (is (= 1 (bitcoin-lisp.networking::address-book-n-tried book2)))
             (let ((tor (bitcoin-lisp.networking:address-book-lookup book2 onion 8333 :torv3)))
               (is (not (null tor)))
               (is (eq :torv3 (bitcoin-lisp.networking:peer-address-network tor)))
               (is-true (bitcoin-lisp.networking:peer-address-in-tried tor)))
             (let ((v4 (bitcoin-lisp.networking:address-book-lookup book2 (%ip 1 2 3 4) 8333)))
               (is (not (null v4)))
               (is (= 9 (bitcoin-lisp.networking:peer-address-services v4))))
             (is (not (null (bitcoin-lisp.networking:address-book-lookup book2 i2p 0 :i2p))))
             (is (not (null (bitcoin-lisp.networking:address-book-lookup book2 cjdns 8333 :cjdns))))))
      (uiop:delete-directory-tree tmp-dir :validate t :if-does-not-exist :ignore))))

(defparameter +peers-dat-v3-fixture-hex+
  "4144524d0300000007070707070707070707070707070707070707070707070707070707070707070200000001000000030000000100000000000000000000ffff01020304208d090000000000000000f153652cf253652cf253650000000003010102000000000000000000000000ffff05060708479d010000000000000064f1536500000000000000000000000003010506010c010020010db8000000000000000000000001208d0904000000000000c8f15365000000000000000000000000050220010db8017000c2abd34a"
  "A peers.dat written by the PRE-P1 v3 writer (generated with the old
save-address-book before the network-typed change): three entries —
1.2.3.4:8333 services 9 TRIED, 5.6.7.8:18333 services 1, and
[2001:db8::1]:8333 services 1033 — under a fixed all-07 bucket key.")

(test peers-dat-v3-migrates-on-load
  "A v3 (fixed 16-byte IP) file loads with networks derived from the mapped
form, and the next save rewrites it as v4 with everything intact."
  (let ((tmp-dir (merge-pathnames "test-addrman-migrate/" (uiop:temporary-directory))))
    (ensure-directories-exist (merge-pathnames "dummy" tmp-dir))
    (unwind-protect
         (let ((path (merge-pathnames "peers.dat" tmp-dir)))
           (with-open-file (out path :direction :output :if-exists :supersede
                                     :element-type '(unsigned-byte 8))
             (write-sequence (%am-hex +peers-dat-v3-fixture-hex+) out))
           (let ((book (bitcoin-lisp.networking:make-address-book)))
             (is (eq t (bitcoin-lisp.networking:load-address-book book path)))
             (is (= 3 (bitcoin-lisp.networking:address-book-count book)))
             (is (= 1 (bitcoin-lisp.networking::address-book-n-tried book)))
             (let ((a (bitcoin-lisp.networking:address-book-lookup book (%ip 1 2 3 4) 8333)))
               (is (not (null a)))
               (is (eq :ipv4 (bitcoin-lisp.networking:peer-address-network a)))
               (is (= 9 (bitcoin-lisp.networking:peer-address-services a)))
               (is-true (bitcoin-lisp.networking:peer-address-in-tried a)))
             (let ((b (bitcoin-lisp.networking:address-book-lookup book (%ip 5 6 7 8) 18333)))
               (is (not (null b)))
               (is (= 1700000100 (bitcoin-lisp.networking:peer-address-last-seen b))))
             (let ((c (bitcoin-lisp.networking:address-book-lookup
                       book (%ipv6 #x20 #x01 #x0d #xb8 0 0 0 0 0 0 0 0 0 0 0 1) 8333)))
               (is (not (null c)))
               (is (eq :ipv6 (bitcoin-lisp.networking:peer-address-network c)))
               (is (= 1033 (bitcoin-lisp.networking:peer-address-services c))))
             ;; Migration completes on the next save: file becomes v4 and
             ;; still round-trips.
             (is (eq t (bitcoin-lisp.networking:save-address-book book path)))
             (with-open-file (in path :element-type '(unsigned-byte 8))
               (let ((head (make-array 8 :element-type '(unsigned-byte 8))))
                 (read-sequence head in)
                 (is (= 4 (aref head 4)))))
             (let ((book2 (bitcoin-lisp.networking:make-address-book)))
               (is (eq t (bitcoin-lisp.networking:load-address-book book2 path)))
               (is (= 3 (bitcoin-lisp.networking:address-book-count book2)))
               (is (= 1 (bitcoin-lisp.networking::address-book-n-tried book2))))))
      (uiop:delete-directory-tree tmp-dir :validate t :if-does-not-exist :ignore))))

(test get-addr-includes-typed-records
  "GetAddr returns typed records; peer-address-string renders them."
  (let ((book (%ab)))
    (bitcoin-lisp.networking:address-book-add
     book (%pa-net :torv3 (%am-hex +am-onion-pk+)))
    (let ((addrs (bitcoin-lisp.networking:address-book-get-addr book :pct 100)))
      (is (= 1 (length addrs)))
      (is (string= "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"
                   (bitcoin-lisp.networking:peer-address-string (first addrs)))))))
