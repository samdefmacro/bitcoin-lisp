(in-package #:bitcoin-lisp.tests)

(def-suite :peerdb-tests
  :description "Tests for the peer address records, IP helpers, and persistence"
  :in :bitcoin-lisp-tests)

(in-suite :peerdb-tests)

(defun make-test-peer-addr (&key (a 192) (b 168) (c 1) (d 1) (port 8333)
                                 (services 1) (last-seen 1000000))
  "Create a test peer address with IPv4-mapped IPv6."
  (bl.net:make-peer-address
   :ip (bl.net:ipv4-to-mapped-ipv6 a b c d)
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
    (bl.net:make-address-book :key k)))

(defun peerdb-book-rows (book)
  "Every record in BOOK as comparable field rows, sorted so hash-table
iteration order cannot affect a comparison. The fields are exactly what
save/load is contracted to preserve: identity (network + address bytes +
port), the advertised/attempt statistics, the tried flag, and the new-table
placement (ref-count + the bucket numbers themselves). LAST-ATTEMPT and
LAST-COUNT-ATTEMPT are deliberately absent -- like Core's m_last_try and
m_last_count_attempt, peers.dat does not carry them (addrman_impl.h:73-76)."
  (let ((rows '())
        (id-buckets (bl.net::%new-table-buckets book)))
    (maphash
     (lambda (id pa)
       (push (list (bl.net:peer-address-network pa)
                   (coerce (bl.net:peer-address-ip pa) 'list)
                   (bl.net:peer-address-port pa)
                   (bl.net:peer-address-services pa)
                   (bl.net:peer-address-last-seen pa)
                   (bl.net:peer-address-last-success pa)
                   (bl.net:peer-address-n-attempts pa)
                   (if (bl.net:peer-address-in-tried pa) :tried :new)
                   (bl.net:peer-address-ref-count pa)
                   (sort (copy-list (gethash id id-buckets)) #'<))
             rows))
     (bl.net:address-book-info book))
    (sort rows #'string< :key (lambda (row) (format nil "~S" row)))))

(test create-and-populate-address-book
  "Create an address book and add entries."
  (let ((book (make-test-address-book)))
    (is (= 0 (bl.net:address-book-count book)))
    (bl.net:address-book-add book (make-test-peer-addr :d 1))
    (is (= 1 (bl.net:address-book-count book)))
    (bl.net:address-book-add book (make-test-peer-addr :d 2))
    (is (= 2 (bl.net:address-book-count book)))))

(test add-duplicate-peer-updates
  "Adding a duplicate peer updates the existing entry, not the count."
  (let ((book (make-test-address-book)))
    (bl.net:address-book-add
     book (make-test-peer-addr :d 1 :services 1 :last-seen 1000))
    (bl.net:address-book-add
     book (make-test-peer-addr :d 1 :services 9 :last-seen 2000))
    (is (= 1 (bl.net:address-book-count book)))
    (let* ((ip (bl.net:ipv4-to-mapped-ipv6 192 168 1 1))
           (addr (bl.net:address-book-lookup book ip 8333)))
      (is (not (null addr)))
      ;; Services OR-merged, last-seen advanced.
      (is (= 9 (bl.net:peer-address-services addr)))
      (is (= 2000 (bl.net:peer-address-last-seen addr))))))

(test save-and-load-roundtrip
  "Save the address book, load it back, and verify the reloaded book is an
exact replica of the saved one — identity, statistics, tried status and
new-table placement — not merely that the entry count matches."
  (let ((book (make-test-address-book))
        (tmp-dir (merge-pathnames "test-peerdb/" (uiop:temporary-directory))))
    (ensure-directories-exist (merge-pathnames "dummy" tmp-dir))
    (unwind-protect
         (let ((path (merge-pathnames "peers.dat" tmp-dir)))
           (bl.net:address-book-add
            book (make-test-peer-addr :d 1 :port 8333 :services 9 :last-seen 999999))
           (bl.net:address-book-add
            book (make-test-peer-addr :d 2 :port 18333 :services 1 :last-seen 888888))
           ;; Promote the first entry into the tried table.
           (bl.net:address-book-good
            book (bl.net:ipv4-to-mapped-ipv6 192 168 1 1) 8333)
           ;; The pre-save book is the yardstick the reload has to reproduce;
           ;; with a pinned bucket key it is deterministic, so both entries are
           ;; always present and exactly one of them is tried.
           (let ((before (peerdb-book-rows book)))
             (is (= 2 (bl.net:address-book-count book)))
             (is (= 1 (bl.net:address-book-n-tried book)))
             (is (eq t (bl.net:save-address-book book path)))
             ;; book2 keeps its own random key on purpose: everything below
             ;; only works if load reads the key back out of the file.
             (let ((book2 (bl.net:make-address-book)))
               (is (eq t (bl.net:load-address-book book2 path)))
               (is (= 2 (bl.net:address-book-count book2)))
               (is (= 1 (bl.net:address-book-n-tried book2)))
               ;; Round-trip fidelity: what was saved is exactly what loads.
               (is (equal before (peerdb-book-rows book2)))
               (let ((addr (bl.net:address-book-lookup
                            book2
                            (bl.net:ipv4-to-mapped-ipv6 192 168 1 1)
                            8333)))
                 (is (not (null addr)))
                 ;; Guarded so a regression reports the missing entry above
                 ;; instead of aborting the test on a NIL accessor.
                 (when addr
                   (is (= 9 (bl.net:peer-address-services addr)))
                   (is (= 999999 (bl.net:peer-address-last-seen addr)))
                   ;; The promoted entry is restored to the tried table.
                   (is-true (bl.net:peer-address-in-tried addr)))))))
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
               (ip (bl.net:ipv4-to-mapped-ipv6 8 8 4 4)))
           ;; Add the same address from many distinct source /16s. Extra
           ;; placements are probabilistic (Core's 1/2^n gate), so loop until
           ;; multiplicity >= 2 — P(never) over 64 sources is ~2^-64.
           (loop for a from 1 to 64
                 do (bl.net:address-book-add
                     book
                     (bl.net:make-peer-address
                      :ip ip :port 8333 :services 1
                      :last-seen (bl.ser:get-unix-time))
                     (bl.net:ipv4-to-mapped-ipv6 a 7 1 1))
                 until (>= (bl.net:peer-address-ref-count
                            (bl.net:address-book-lookup book ip 8333))
                           2))
           (let* ((before (bl.net:address-book-lookup book ip 8333))
                  (refs (bl.net:peer-address-ref-count before)))
             (is (>= refs 2))
             (is (eq t (bl.net:save-address-book book path)))
             (let ((book2 (bl.net:make-address-book)))
               (is (eq t (bl.net:load-address-book book2 path)))
               (let ((after (bl.net:address-book-lookup book2 ip 8333)))
                 (is (not (null after)))
                 ;; Multiplicity survives, and the live new-table agrees.
                 (is (= refs (bl.net:peer-address-ref-count after)))
                 (let ((buckets (gethash (bl.net::peer-address-id after)
                                         (bl.net::%new-table-buckets book2))))
                   (is (= refs (length buckets))))))))
      (uiop:delete-directory-tree tmp-dir :validate t :if-does-not-exist :ignore))))

;;;; peers.dat in Core's format (addrdb.cpp, addrman.cpp Serialize/Unserialize)

(defun %core-peers-dat (&key (format 1) (lowest-compatible 4) (network :regtest)
                             (bucket-key 1) (len-new 0) (len-tried 0) mock-checksum)
  "feature_addrman.py's serialize_addrman (:16-41), byte for byte: an EMPTY
addrman in Core's layout -- message start, format, INCOMPATIBILITY_BASE +
lowest compatible, nKey, nNew, nTried, 1024 XOR 2^30 and 1024 empty buckets --
then SHA256d over all of it, or MOCK-CHECKSUM."
  (flet ((le (n bytes)
           (loop for i below bytes collect (ldb (byte 8 (* 8 i)) n))))
    (let* ((body (coerce (append (coerce (bl.chain:network-magic network) 'list)
                                 (list format (ldb (byte 8 0) (+ 32 lowest-compatible)))
                                 (le bucket-key 32)
                                 (le len-new 4) (le len-tried 4)
                                 (le (logxor 1024 (ash 1 30)) 4)
                                 (loop repeat 1024 append (le 0 4)))
                         '(simple-array (unsigned-byte 8) (*)))))
      (concatenate '(simple-array (unsigned-byte 8) (*))
                   body (or mock-checksum (bl.crypto:hash256 body))))))

(defun %write-octets (path bytes)
  (with-open-file (out path :direction :output :if-exists :supersede
                            :element-type '(unsigned-byte 8))
    (write-sequence bytes out)))

(defun %peers-dat-refusal (tmp-dir bytes)
  "Write BYTES as peers.dat under TMP-DIR and load it for regtest; the
INIT-ERROR's text, or :LOADED."
  (let ((path (merge-pathnames "peers.dat" tmp-dir)))
    (%write-octets path bytes)
    (handler-case (progn (bl.net:load-address-book (bl.net:make-address-book) path :regtest)
                         :loaded)
      (bl.err:init-error (e) (princ-to-string e)))))

(defun %peers-dat-sentence (reason path)
  "LoadAddrman's refusal (addrdb.cpp:224-226), without the Error: caption the
init reporter adds."
  (format nil "Invalid or corrupt peers.dat (~A). If you believe this is a bug, please report it to https://github.com/samdefmacro/bitcoin-lisp/issues. As a workaround, you can move the file (\"~A\") out of the way (rename, move, or delete) to have a new one created on the next start."
          reason (namestring path)))

(test core-peers-dat-mock-loads
  "feature_addrman.py:61-65: Core's own empty peers.dat loads -- it is not
backed up as an unknown format -- and its key is the one in the file."
  (let ((tmp-dir (merge-pathnames "test-peerdb-core-mock/" (uiop:temporary-directory))))
    (ensure-directories-exist (merge-pathnames "dummy" tmp-dir))
    (unwind-protect
         (let ((path (merge-pathnames "peers.dat" tmp-dir))
               (book (bl.net:make-address-book)))
           (%write-octets path (%core-peers-dat))
           (is (null (bl.net:load-address-book book path :regtest)))
           (is-false (probe-file (concatenate 'string (namestring path) ".bak"))
                     "a valid Core file must not be moved aside")
           (is (= 0 (bl.net:address-book-count book)))
           ;; nKey = uint256{1}: 01 then 31 zero bytes, at offset 6 of our own
           ;; encoding of the loaded book.
           (is (equalp (cons 1 (make-list 31 :initial-element 0))
                       (coerce (subseq (bl.net:encode-peers-dat book :regtest) 6 38)
                               'list))))
      (uiop:delete-directory-tree tmp-dir :validate t :if-does-not-exist :ignore))))

(test core-peers-dat-refusals-are-core-sentences
  "Every corrupt-file case of feature_addrman.py:67-146 refuses startup with
Core's sentence and Core's reason: ios_base::failure reasons carry libstdc++'s
': iostream error', runtime_error ones do not."
  (let ((tmp-dir (merge-pathnames "test-peerdb-core-refusals/" (uiop:temporary-directory))))
    (ensure-directories-exist (merge-pathnames "dummy" tmp-dir))
    (unwind-protect
         (let ((path (merge-pathnames "peers.dat" tmp-dir))
               (whole (%core-peers-dat)))
           (loop for (bytes reason) in
                 `((,(%core-peers-dat :lowest-compatible -32)
                    "Corrupted addrman database: The compat value (0) is lower than the expected minimum value 32.: iostream error")
                   (,(subseq whole 0 (1- (length whole)))
                    "AutoFile::read: end of file: iostream error")
                   (,(%core-peers-dat :network :signet)
                    "Invalid network magic number")
                   (,(%core-peers-dat :mock-checksum
                                      (make-array 64 :element-type '(unsigned-byte 8)
                                                     :initial-contents
                                                     (loop repeat 32 append (list 97 98))))
                    "Checksum mismatch, data corrupted")
                   (,(%core-peers-dat :len-tried -1)
                    "Corrupt AddrMan serialization: nTried=-1, should be in [0, 16384]: iostream error")
                   (,(%core-peers-dat :len-tried 16385)
                    "Corrupt AddrMan serialization: nTried=16385, should be in [0, 16384]: iostream error")
                   (,(%core-peers-dat :len-new -1)
                    "Corrupt AddrMan serialization: nNew=-1, should be in [0, 65536]: iostream error")
                   (,(%core-peers-dat :len-new 65537)
                    "Corrupt AddrMan serialization: nNew=65537, should be in [0, 65536]: iostream error")
                   (,(%core-peers-dat :bucket-key 0)
                    "Corrupt data. Consistency check failed with code -16: iostream error"))
                 do (is (equal (%peers-dat-sentence reason path)
                               (%peers-dat-refusal tmp-dir bytes)))))
      (uiop:delete-directory-tree tmp-dir :validate t :if-does-not-exist :ignore))))

(test core-peers-dat-from-the-future-is-replaced
  "feature_addrman.py:78-87: a file whose lowest compatible format is newer
than ours is backed up to peers.dat.bak, and a fresh Core-format file takes
its place; startup goes on."
  (let ((tmp-dir (merge-pathnames "test-peerdb-core-future/" (uiop:temporary-directory))))
    (ensure-directories-exist (merge-pathnames "dummy" tmp-dir))
    (unwind-protect
         (let* ((path (merge-pathnames "peers.dat" tmp-dir))
                (bak (concatenate 'string (namestring path) ".bak")))
           (is (eq :loaded (%peers-dat-refusal tmp-dir (%core-peers-dat :lowest-compatible 111))))
           (is-true (probe-file bak))
           (is-true (probe-file path))
           (is (eq :loaded (%peers-dat-refusal
                            tmp-dir (alexandria:read-file-into-byte-vector path)))
               "the replacement is itself a valid Core peers.dat"))
      (uiop:delete-directory-tree tmp-dir :validate t :if-does-not-exist :ignore))))

(test core-peers-dat-entry-bytes
  "One new entry written in Core's V2_DISK AddrInfo layout (protocol.h:413-454,
addrman_impl.h:73-76), assembled here by hand: disk version 220000|2^29,
nTime, CompactSize services, BIP155 IPv4 (net 1, 4 bytes), big-endian port,
the source CNetAddr, int64 m_last_success, int32 nAttempts. Then 1024 bucket
counts holding the one reference, the asmap version (none: zeros) and the
SHA256d."
  (let* ((book (make-test-address-book))
         (pa (bl.net:make-peer-address :ip (bl.net:ipv4-to-mapped-ipv6 1 2 3 4)
                                       :port 8333 :services 9 :last-seen #x65000000
                                       :source (cons :ipv4 (bl.net:ipv4-to-mapped-ipv6 5 6 7 8)))))
    (bl.net:address-book-add book pa)
    (let* ((bytes (bl.net:encode-peers-dat book :regtest))
           (entry '(#x60 #x5B #x03 #x20  #x00 #x00 #x00 #x65  #x09
                    #x01 #x04 1 2 3 4  #x20 #x8D
                    #x01 #x04 5 6 7 8
                    0 0 0 0 0 0 0 0  0 0 0 0))
           (head (append (coerce (bl.chain:network-magic :regtest) 'list)
                         (list 4 36)))
           (after-key 38)
           (buckets-at (+ after-key 12 (length entry)))
           (counts (loop with pos = buckets-at
                         repeat 1024
                         collect (let ((n (logior (aref bytes pos) (ash (aref bytes (1+ pos)) 8))))
                                   (incf pos (* 4 (1+ n)))
                                   n))))
      (is (equal head (coerce (subseq bytes 0 6) 'list)))
      (is (equal '(1 0 0 0  0 0 0 0  #x00 #x04 #x00 #x40)
                 (coerce (subseq bytes after-key (+ after-key 12)) 'list))
          "nNew 1, nTried 0, 1024 XOR 2^30")
      (is (equal entry (coerce (subseq bytes (+ after-key 12) buckets-at) 'list)))
      (is (= 1 (reduce #'+ counts)) "one bucket names the one entry")
      (is (= (length bytes) (+ buckets-at (* 4 1024) 4 32 32)))
      (is (equalp (bl.crypto:hash256 (subseq bytes 0 (- (length bytes) 32)))
                  (subseq bytes (- (length bytes) 32))))
      ;; And it reads back, source and all.
      (let ((book2 (bl.net:make-address-book)))
        (bl.net:decode-peers-dat bytes book2 :regtest)
        (let ((back (bl.net:address-book-lookup book2 (bl.net:ipv4-to-mapped-ipv6 1 2 3 4) 8333)))
          (is-true back)
          (when back
            (is (= 9 (bl.net:peer-address-services back)))
            (is (equalp (cons :ipv4 (bl.net:ipv4-to-mapped-ipv6 5 6 7 8))
                        (bl.net:peer-address-source back)))))))))

(test checkaddrman-logs-core-lines
  "CheckAddrman's timer lines (addrman.cpp:1067-1068, logging/timer.h):
feature_asmap.py:89-95 waits for `CheckAddrman: new 2, tried 2, total 4
started' and `CheckAddrman: completed' when -checkaddrman=1 runs the check on
getnodeaddresses' GetAddr."
  (let ((book (make-test-address-book)))
    (loop for a from 0 below 4
          do (bl.net:address-book-add
              book (bl.net:make-peer-address :ip (bl.net:ipv4-to-mapped-ipv6 101 a 0 0)
                                             :port 8333 :services 9
                                             :last-seen (bl.ser:get-unix-time)))
          when (< a 2)
            do (bl.net:address-book-good book (bl.net:ipv4-to-mapped-ipv6 101 a 0 0) 8333))
    (is (= 0 (bl.net:check-address-book book)) "a book built by the operations is consistent")
    (let ((text (nth-value 1 (log-text-of
                              "addrman"
                              (lambda ()
                                (let ((bl.net:*addrman-check-ratio* 1))
                                  (bl.net:address-book-get-addr book)))))))
      (is-true (search "CheckAddrman: new 2, tried 2, total 4 started" text))
      (is-true (search "CheckAddrman: completed" text)))))

(test handle-missing-file
  "Loading a non-existent peers.dat returns NIL gracefully."
  (let ((book (make-test-address-book)))
    (is (null (bl.net:load-address-book
               book #P"/tmp/nonexistent-peers-12345.dat")))
    (is (= 0 (bl.net:address-book-count book)))))

(test ipv4-to-mapped-ipv6-conversion
  "IPv4 addresses are correctly mapped to IPv6."
  (let ((ip (bl.net:ipv4-to-mapped-ipv6 192 168 1 100)))
    (is (= 16 (length ip)))
    (is (every #'zerop (subseq ip 0 10)))
    (is (= #xFF (aref ip 10)))
    (is (= #xFF (aref ip 11)))
    (is (= 192 (aref ip 12)))
    (is (= 168 (aref ip 13)))
    (is (= 1 (aref ip 14)))
    (is (= 100 (aref ip 15)))))

(test a-missing-peers-dat-is-created-and-says-so
  "Core's LoadAddrman meets a missing peers.dat as DbNotFoundError: it logs
`Creating peers.dat because the file was not found (\"<path>\")' and writes
the empty address book out at once (addrdb.cpp:208-212). The functional
framework waits for that line whenever it deletes the file
(test_framework.py:540-544; rpc_net.py:343 is the first to do it), and the
next start then reports `Loaded 0 addresses from peers.dat' reading the file
this one wrote (feature_addrman.py:65). Ours logged the Loaded line for a file
that was not there and wrote nothing."
  (let* ((tmp-dir (merge-pathnames (format nil "test-peerdb-missing-~D/" (random 1000000))
                                   (uiop:temporary-directory)))
         (path (merge-pathnames "peers.dat" tmp-dir)))
    (ensure-directories-exist tmp-dir)
    (unwind-protect
         (let ((lines (capture-log-lines
                       (lambda ()
                         (is-false (bl.net:load-address-book (bl.net:make-address-book) path)
                                   "control: nothing was loaded")))))
           (is-true (some (lambda (l)
                            (search (format nil "Creating peers.dat because the file was not found (\"~A\")"
                                            (namestring path))
                                    (princ-to-string l)))
                          lines))
           (is-false (some (lambda (l) (search "Loaded 0 addresses" (princ-to-string l))) lines))
           (is-true (probe-file path) "the empty address book is written out at once")
           (let ((lines (capture-log-lines
                         (lambda () (bl.net:load-address-book (bl.net:make-address-book) path)))))
             (is-true (some (lambda (l) (search "Loaded 0 addresses from peers.dat"
                                                (princ-to-string l)))
                            lines)
                      "the next start reads the file this one wrote")))
      (uiop:delete-directory-tree tmp-dir :validate t :if-does-not-exist :ignore))))
