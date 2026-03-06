(in-package #:bitcoin-lisp.tests)

(def-suite :peerdb-tests
  :description "Tests for persistent peer database"
  :in :bitcoin-lisp-tests)

(in-suite :peerdb-tests)

(defun make-test-peer-addr (&key (a 192) (b 168) (c 1) (d 1) (port 8333)
                                  (services 1) (last-seen 1000000) (successes 0) (failures 0))
  "Create a test peer address with IPv4-mapped IPv6."
  (bitcoin-lisp.networking:make-peer-address
   :ip (bitcoin-lisp.networking:ipv4-to-mapped-ipv6 a b c d)
   :port port
   :services services
   :last-seen last-seen
   :successes successes
   :failures failures))

(test create-and-populate-address-book
  "Create an address book and add entries."
  (let ((book (bitcoin-lisp.networking:make-address-book)))
    (is (= 0 (bitcoin-lisp.networking:address-book-count book)))
    (bitcoin-lisp.networking:address-book-add book (make-test-peer-addr :d 1))
    (is (= 1 (bitcoin-lisp.networking:address-book-count book)))
    (bitcoin-lisp.networking:address-book-add book (make-test-peer-addr :d 2))
    (is (= 2 (bitcoin-lisp.networking:address-book-count book)))))

(test add-duplicate-peer-updates
  "Adding a duplicate peer updates the existing entry."
  (let ((book (bitcoin-lisp.networking:make-address-book)))
    (bitcoin-lisp.networking:address-book-add
     book (make-test-peer-addr :d 1 :services 1 :last-seen 1000))
    (bitcoin-lisp.networking:address-book-add
     book (make-test-peer-addr :d 1 :services 9 :last-seen 2000))
    ;; Still one entry
    (is (= 1 (bitcoin-lisp.networking:address-book-count book)))
    ;; Services and last-seen updated
    (let ((ip (bitcoin-lisp.networking:ipv4-to-mapped-ipv6 192 168 1 1)))
      (let ((addr (bitcoin-lisp.networking:address-book-lookup book ip 8333)))
        (is (not (null addr)))
        (is (= 9 (bitcoin-lisp.networking:peer-address-services addr)))
        (is (= 2000 (bitcoin-lisp.networking:peer-address-last-seen addr)))))))

(test score-reliable-vs-unreliable
  "Reliable peers score higher than unreliable ones."
  (let ((reliable (make-test-peer-addr :d 1 :successes 10 :failures 1 :last-seen 1000000))
        (unreliable (make-test-peer-addr :d 2 :successes 1 :failures 10 :last-seen 1000000)))
    (is (> (bitcoin-lisp.networking:compute-peer-score reliable 1000000)
           (bitcoin-lisp.networking:compute-peer-score unreliable 1000000)))))

(test score-untried-peer-defaults
  "Untried peers (0 successes, 0 failures) get reliability 0.5."
  (let ((untried (make-test-peer-addr :d 1 :successes 0 :failures 0 :last-seen 1000000)))
    (let ((score (bitcoin-lisp.networking:compute-peer-score untried 1000000)))
      ;; With age=1 hour (max of 1), score = 0.5 / sqrt(1) = 0.5
      (is (> score 0.0))
      (is (<= score 0.5)))))

(test eviction-when-full
  "When the book is full, the lowest-scored entry is evicted on add."
  (let ((book (bitcoin-lisp.networking:make-address-book)))
    ;; Set small capacity
    (setf (bitcoin-lisp.networking::address-book-max-entries book) 3)
    ;; Add 3 entries with varying quality
    (bitcoin-lisp.networking:address-book-add
     book (make-test-peer-addr :d 1 :successes 10 :failures 0 :last-seen 1000000))
    (bitcoin-lisp.networking:address-book-add
     book (make-test-peer-addr :d 2 :successes 0 :failures 10 :last-seen 1000000))
    (bitcoin-lisp.networking:address-book-add
     book (make-test-peer-addr :d 3 :successes 5 :failures 0 :last-seen 1000000))
    (is (= 3 (bitcoin-lisp.networking:address-book-count book)))
    ;; Add a 4th - should evict the worst (d=2, failures=10)
    (bitcoin-lisp.networking:address-book-add
     book (make-test-peer-addr :d 4 :successes 3 :failures 0 :last-seen 1000000))
    (is (= 3 (bitcoin-lisp.networking:address-book-count book)))
    ;; The unreliable peer (d=2) should be gone
    (let ((ip2 (bitcoin-lisp.networking:ipv4-to-mapped-ipv6 192 168 1 2)))
      (is (null (bitcoin-lisp.networking:address-book-lookup book ip2 8333))))
    ;; Others remain
    (let ((ip1 (bitcoin-lisp.networking:ipv4-to-mapped-ipv6 192 168 1 1)))
      (is (not (null (bitcoin-lisp.networking:address-book-lookup book ip1 8333)))))))

(test save-and-load-roundtrip
  "Save address book to file, load it back, verify contents match."
  (let ((book (bitcoin-lisp.networking:make-address-book))
        (tmp-dir (merge-pathnames "test-peerdb/" (uiop:temporary-directory))))
    (ensure-directories-exist (merge-pathnames "dummy" tmp-dir))
    (unwind-protect
         (let ((path (merge-pathnames "peers.dat" tmp-dir)))
           ;; Populate
           (bitcoin-lisp.networking:address-book-add
            book (make-test-peer-addr :d 1 :port 8333 :services 9
                                       :successes 5 :failures 2 :last-seen 999999))
           (bitcoin-lisp.networking:address-book-add
            book (make-test-peer-addr :d 2 :port 18333 :services 1
                                       :successes 0 :failures 0 :last-seen 888888))
           ;; Save
           (is (eq t (bitcoin-lisp.networking:save-address-book book path)))
           ;; Load into fresh book
           (let ((book2 (bitcoin-lisp.networking:make-address-book)))
             (is (eq t (bitcoin-lisp.networking:load-address-book book2 path)))
             (is (= 2 (bitcoin-lisp.networking:address-book-count book2)))
             ;; Check first entry
             (let ((addr (bitcoin-lisp.networking:address-book-lookup
                          book2
                          (bitcoin-lisp.networking:ipv4-to-mapped-ipv6 192 168 1 1)
                          8333)))
               (is (not (null addr)))
               (is (= 9 (bitcoin-lisp.networking:peer-address-services addr)))
               (is (= 5 (bitcoin-lisp.networking:peer-address-successes addr)))
               (is (= 2 (bitcoin-lisp.networking:peer-address-failures addr)))
               (is (= 999999 (bitcoin-lisp.networking:peer-address-last-seen addr))))))
      ;; Cleanup
      (uiop:delete-directory-tree tmp-dir :validate t :if-does-not-exist :ignore))))

(test reject-corrupted-file
  "A peers.dat with bad CRC32 is rejected."
  (let ((book (bitcoin-lisp.networking:make-address-book))
        (tmp-dir (merge-pathnames "test-peerdb-corrupt/" (uiop:temporary-directory))))
    (ensure-directories-exist (merge-pathnames "dummy" tmp-dir))
    (unwind-protect
         (let ((path (merge-pathnames "peers.dat" tmp-dir)))
           ;; Save valid file
           (bitcoin-lisp.networking:address-book-add
            book (make-test-peer-addr :d 1))
           (bitcoin-lisp.networking:save-address-book book path)
           ;; Corrupt a byte in the file
           (let ((data (alexandria:read-file-into-byte-vector path)))
             (setf (aref data 15) (logxor (aref data 15) #xFF))
             (with-open-file (out path :direction :output :if-exists :supersede
                                       :element-type '(unsigned-byte 8))
               (write-sequence data out)))
           ;; Loading should fail
           (let ((book2 (bitcoin-lisp.networking:make-address-book)))
             (is (null (bitcoin-lisp.networking:load-address-book book2 path)))
             (is (= 0 (bitcoin-lisp.networking:address-book-count book2)))))
      (uiop:delete-directory-tree tmp-dir :validate t :if-does-not-exist :ignore))))

(test handle-missing-file
  "Loading a non-existent peers.dat returns NIL gracefully."
  (let ((book (bitcoin-lisp.networking:make-address-book)))
    (is (null (bitcoin-lisp.networking:load-address-book
               book #P"/tmp/nonexistent-peers-12345.dat")))
    (is (= 0 (bitcoin-lisp.networking:address-book-count book)))))

(test ipv4-to-mapped-ipv6-conversion
  "IPv4 addresses are correctly mapped to IPv6."
  (let ((ip (bitcoin-lisp.networking:ipv4-to-mapped-ipv6 192 168 1 100)))
    (is (= 16 (length ip)))
    ;; First 10 bytes zero
    (is (every #'zerop (subseq ip 0 10)))
    ;; Bytes 10-11 are 0xFF
    (is (= #xFF (aref ip 10)))
    (is (= #xFF (aref ip 11)))
    ;; Last 4 bytes are the IPv4 address
    (is (= 192 (aref ip 12)))
    (is (= 168 (aref ip 13)))
    (is (= 1 (aref ip 14)))
    (is (= 100 (aref ip 15)))))
