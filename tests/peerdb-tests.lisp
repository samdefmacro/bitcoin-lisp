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

(test create-and-populate-address-book
  "Create an address book and add entries."
  (let ((book (bitcoin-lisp.networking:make-address-book)))
    (is (= 0 (bitcoin-lisp.networking:address-book-count book)))
    (bitcoin-lisp.networking:address-book-add book (make-test-peer-addr :d 1))
    (is (= 1 (bitcoin-lisp.networking:address-book-count book)))
    (bitcoin-lisp.networking:address-book-add book (make-test-peer-addr :d 2))
    (is (= 2 (bitcoin-lisp.networking:address-book-count book)))))

(test add-duplicate-peer-updates
  "Adding a duplicate peer updates the existing entry, not the count."
  (let ((book (bitcoin-lisp.networking:make-address-book)))
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
  "Save the address book, load it back, and verify entries + tried status survive."
  (let ((book (bitcoin-lisp.networking:make-address-book))
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
           (is (eq t (bitcoin-lisp.networking:save-address-book book path)))
           (let ((book2 (bitcoin-lisp.networking:make-address-book)))
             (is (eq t (bitcoin-lisp.networking:load-address-book book2 path)))
             (is (= 2 (bitcoin-lisp.networking:address-book-count book2)))
             (let ((addr (bitcoin-lisp.networking:address-book-lookup
                          book2
                          (bitcoin-lisp.networking:ipv4-to-mapped-ipv6 192 168 1 1)
                          8333)))
               (is (not (null addr)))
               (is (= 9 (bitcoin-lisp.networking:peer-address-services addr)))
               (is (= 999999 (bitcoin-lisp.networking:peer-address-last-seen addr)))
               ;; The promoted entry is restored to the tried table.
               (is-true (bitcoin-lisp.networking:peer-address-in-tried addr)))))
      (uiop:delete-directory-tree tmp-dir :validate t :if-does-not-exist :ignore))))

(test save-and-load-multi-bucket-refs
  "v3: an address referenced from several new buckets (added via multiple
source groups) keeps all its placements and its ref-count across save/load
(pre-v3, reload collapsed everything to a single bucket with ref-count 1)."
  (let ((book (bitcoin-lisp.networking:make-address-book))
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
  (let ((book (bitcoin-lisp.networking:make-address-book))
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
  (let ((book (bitcoin-lisp.networking:make-address-book)))
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
