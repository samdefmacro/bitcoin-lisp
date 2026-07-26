(in-package #:bitcoin-lisp.tests)

(def-suite :peerdb-tests
  :description "Tests for the peer address records, IP helpers, and persistence"
  :in :bitcoin-lisp-tests)

(in-suite :peerdb-tests)

(defun make-test-peer-addr (&key (a 192) (b 168) (c 1) (d 1) (port 8333)
                                 (services 1) (last-seen 1000000))
  "Create a test peer address with IPv4-mapped IPv6."
  (bitcoin-lisp.networking:make-peer-address
   :ip (bitcoin-lisp.networking:ipv4-to-mapped-ipv6 a b c d)
   :port port :services services :last-seen last-seen))

(defun make-test-address-book ()
  "A fresh address book whose bucket key is FIXED, so placement is deterministic.

Production reads the key from /dev/urandom (make-addrman-key) and that must
stay: an unpredictable key is what stops an attacker from steering addresses
into a bucket of their choosing. The price is that placement is random. Two
addresses sharing a netgroup and a source group (e.g. 192.168.1.1 and
192.168.1.2, both /16 group [1 192 168]) always land in the SAME new bucket
and differ only in their slot, so with probability 1/64 they collide — and
because these fixtures carry ancient last-seen values they are `terrible', so
the newcomer evicts the incumbent. That is correct Core-faithful behaviour,
but it silently drops an entry the test expects to be there: measured 22
reddened runs in 500 across this file before the key was pinned.

So tests that assert on exact book contents pin the key instead of rolling
the dice, exactly as tests/addrman-tests.lisp's %ab does. make-address-book
already takes :key, so nothing in the production path changes."
  (let ((k (make-array 32 :element-type '(unsigned-byte 8))))
    (dotimes (i 32) (setf (aref k i) (mod (* i 7) 256)))
    (bitcoin-lisp.networking:make-address-book :key k)))

(defun peerdb-book-rows (book)
  "Every record in BOOK as comparable field rows, sorted so hash-table
iteration order cannot affect a comparison. The fields are exactly what
save/load is contracted to preserve: identity (network + address bytes +
port), the advertised/attempt statistics, the tried flag, and the new-table
placement (ref-count + the bucket numbers themselves). LAST-COUNT-ATTEMPT is
deliberately absent — like Core's m_last_count_attempt it is not persisted."
  (let ((rows '())
        (id-buckets (bitcoin-lisp.networking::%new-table-buckets book)))
    (maphash
     (lambda (id pa)
       (push (list (bitcoin-lisp.networking:peer-address-network pa)
                   (coerce (bitcoin-lisp.networking:peer-address-ip pa) 'list)
                   (bitcoin-lisp.networking:peer-address-port pa)
                   (bitcoin-lisp.networking:peer-address-services pa)
                   (bitcoin-lisp.networking:peer-address-last-seen pa)
                   (bitcoin-lisp.networking:peer-address-last-attempt pa)
                   (bitcoin-lisp.networking:peer-address-last-success pa)
                   (bitcoin-lisp.networking:peer-address-n-attempts pa)
                   (if (bitcoin-lisp.networking:peer-address-in-tried pa) :tried :new)
                   (bitcoin-lisp.networking:peer-address-ref-count pa)
                   (sort (copy-list (gethash id id-buckets)) #'<))
             rows))
     (bitcoin-lisp.networking::address-book-info book))
    (sort rows #'string< :key (lambda (row) (format nil "~S" row)))))

(test create-and-populate-address-book
  "Create an address book and add entries."
  (let ((book (make-test-address-book)))
    (is (= 0 (bitcoin-lisp.networking:address-book-count book)))
    (bitcoin-lisp.networking:address-book-add book (make-test-peer-addr :d 1))
    (is (= 1 (bitcoin-lisp.networking:address-book-count book)))
    (bitcoin-lisp.networking:address-book-add book (make-test-peer-addr :d 2))
    (is (= 2 (bitcoin-lisp.networking:address-book-count book)))))

(test add-duplicate-peer-updates
  "Adding a duplicate peer updates the existing entry, not the count."
  (let ((book (make-test-address-book)))
    (bitcoin-lisp.networking:address-book-add
     book (make-test-peer-addr :d 1 :services 1 :last-seen 1000))
    (bitcoin-lisp.networking:address-book-add
     book (make-test-peer-addr :d 1 :services 9 :last-seen 2000))
    (is (= 1 (bitcoin-lisp.networking:address-book-count book)))
    (let* ((ip (bitcoin-lisp.networking:ipv4-to-mapped-ipv6 192 168 1 1))
           (addr (bitcoin-lisp.networking:address-book-lookup book ip 8333)))
      (is (not (null addr)))
      ;; Services OR-merged, last-seen advanced.
      (is (= 9 (bitcoin-lisp.networking:peer-address-services addr)))
      (is (= 2000 (bitcoin-lisp.networking:peer-address-last-seen addr))))))

(test save-and-load-roundtrip
  "Save the address book, load it back, and verify the reloaded book is an
exact replica of the saved one — identity, statistics, tried status and
new-table placement — not merely that the entry count matches."
  (let ((book (make-test-address-book))
        (tmp-dir (merge-pathnames "test-peerdb/" (uiop:temporary-directory))))
    (ensure-directories-exist (merge-pathnames "dummy" tmp-dir))
    (unwind-protect
         (let ((path (merge-pathnames "peers.dat" tmp-dir)))
           (bitcoin-lisp.networking:address-book-add
            book (make-test-peer-addr :d 1 :port 8333 :services 9 :last-seen 999999))
           (bitcoin-lisp.networking:address-book-add
            book (make-test-peer-addr :d 2 :port 18333 :services 1 :last-seen 888888))
           ;; Promote the first entry into the tried table.
           (bitcoin-lisp.networking:address-book-good
            book (bitcoin-lisp.networking:ipv4-to-mapped-ipv6 192 168 1 1) 8333)
           ;; The pre-save book is the yardstick the reload has to reproduce;
           ;; with a pinned bucket key it is deterministic, so both entries are
           ;; always present and exactly one of them is tried.
           (let ((before (peerdb-book-rows book)))
             (is (= 2 (bitcoin-lisp.networking:address-book-count book)))
             (is (= 1 (bitcoin-lisp.networking::address-book-n-tried book)))
             (is (eq t (bitcoin-lisp.networking:save-address-book book path)))
             ;; book2 keeps its own random key on purpose: everything below
             ;; only works if load reads the key back out of the file.
             (let ((book2 (bitcoin-lisp.networking:make-address-book)))
               (is (eq t (bitcoin-lisp.networking:load-address-book book2 path)))
               (is (= 2 (bitcoin-lisp.networking:address-book-count book2)))
               (is (= 1 (bitcoin-lisp.networking::address-book-n-tried book2)))
               ;; Round-trip fidelity: what was saved is exactly what loads.
               (is (equal before (peerdb-book-rows book2)))
               (let ((addr (bitcoin-lisp.networking:address-book-lookup
                            book2
                            (bitcoin-lisp.networking:ipv4-to-mapped-ipv6 192 168 1 1)
                            8333)))
                 (is (not (null addr)))
                 ;; Guarded so a regression reports the missing entry above
                 ;; instead of aborting the test on a NIL accessor.
                 (when addr
                   (is (= 9 (bitcoin-lisp.networking:peer-address-services addr)))
                   (is (= 999999 (bitcoin-lisp.networking:peer-address-last-seen addr)))
                   ;; The promoted entry is restored to the tried table.
                   (is-true (bitcoin-lisp.networking:peer-address-in-tried addr)))))))
      (uiop:delete-directory-tree tmp-dir :validate t :if-does-not-exist :ignore))))

(test save-and-load-multi-bucket-refs
  "v3: an address referenced from several new buckets (added via multiple
source groups) keeps all its placements and its ref-count across save/load
(pre-v3, reload collapsed everything to a single bucket with ref-count 1)."
  (let ((book (make-test-address-book))
        (tmp-dir (merge-pathnames "test-peerdb-multibucket/" (uiop:temporary-directory))))
    (ensure-directories-exist (merge-pathnames "dummy" tmp-dir))
    (unwind-protect
         (let ((path (merge-pathnames "peers.dat" tmp-dir))
               (ip (bitcoin-lisp.networking:ipv4-to-mapped-ipv6 8 8 4 4)))
           ;; Add the same address from many distinct source /16s. Extra
           ;; placements are probabilistic (Core's 1/2^n gate), so loop until
           ;; multiplicity >= 2 — P(never) over 64 sources is ~2^-64.
           (loop for a from 1 to 64
                 do (bitcoin-lisp.networking:address-book-add
                     book
                     (bitcoin-lisp.networking:make-peer-address
                      :ip ip :port 8333 :services 1
                      :last-seen (bitcoin-lisp.serialization:get-unix-time))
                     (bitcoin-lisp.networking:ipv4-to-mapped-ipv6 a 7 1 1))
                 until (>= (bitcoin-lisp.networking:peer-address-ref-count
                            (bitcoin-lisp.networking:address-book-lookup book ip 8333))
                           2))
           (let* ((before (bitcoin-lisp.networking:address-book-lookup book ip 8333))
                  (refs (bitcoin-lisp.networking:peer-address-ref-count before)))
             (is (>= refs 2))
             (is (eq t (bitcoin-lisp.networking:save-address-book book path)))
             (let ((book2 (bitcoin-lisp.networking:make-address-book)))
               (is (eq t (bitcoin-lisp.networking:load-address-book book2 path)))
               (let ((after (bitcoin-lisp.networking:address-book-lookup book2 ip 8333)))
                 (is (not (null after)))
                 ;; Multiplicity survives, and the live new-table agrees.
                 (is (= refs (bitcoin-lisp.networking:peer-address-ref-count after)))
                 (let ((buckets (gethash (bitcoin-lisp.networking::peer-address-id after)
                                         (bitcoin-lisp.networking::%new-table-buckets book2))))
                   (is (= refs (length buckets))))))))
      (uiop:delete-directory-tree tmp-dir :validate t :if-does-not-exist :ignore))))

(test reject-corrupted-file
  "A peers.dat with a bad CRC32 is rejected (and backed up to .bak)."
  (let ((book (make-test-address-book))
        (tmp-dir (merge-pathnames "test-peerdb-corrupt/" (uiop:temporary-directory))))
    (ensure-directories-exist (merge-pathnames "dummy" tmp-dir))
    (unwind-protect
         (let ((path (merge-pathnames "peers.dat" tmp-dir)))
           (bitcoin-lisp.networking:address-book-add book (make-test-peer-addr :d 1))
           (bitcoin-lisp.networking:save-address-book book path)
           (let ((data (alexandria:read-file-into-byte-vector path)))
             (setf (aref data 15) (logxor (aref data 15) #xFF))   ; corrupt a key byte
             (with-open-file (out path :direction :output :if-exists :supersede
                                       :element-type '(unsigned-byte 8))
               (write-sequence data out)))
           (let ((book2 (bitcoin-lisp.networking:make-address-book)))
             (is (null (bitcoin-lisp.networking:load-address-book book2 path)))
             (is (= 0 (bitcoin-lisp.networking:address-book-count book2)))))
      (uiop:delete-directory-tree tmp-dir :validate t :if-does-not-exist :ignore))))

(test handle-missing-file
  "Loading a non-existent peers.dat returns NIL gracefully."
  (let ((book (make-test-address-book)))
    (is (null (bitcoin-lisp.networking:load-address-book
               book #P"/tmp/nonexistent-peers-12345.dat")))
    (is (= 0 (bitcoin-lisp.networking:address-book-count book)))))

(test ipv4-to-mapped-ipv6-conversion
  "IPv4 addresses are correctly mapped to IPv6."
  (let ((ip (bitcoin-lisp.networking:ipv4-to-mapped-ipv6 192 168 1 100)))
    (is (= 16 (length ip)))
    (is (every #'zerop (subseq ip 0 10)))
    (is (= #xFF (aref ip 10)))
    (is (= #xFF (aref ip 11)))
    (is (= 192 (aref ip 12)))
    (is (= 168 (aref ip 13)))
    (is (= 1 (aref ip 14)))
    (is (= 100 (aref ip 15)))))
