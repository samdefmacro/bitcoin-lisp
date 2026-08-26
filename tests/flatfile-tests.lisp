(in-package #:bitcoin-lisp.tests)

(def-suite :flatfile-tests
  :description "Flat-file storage engine (Core flatfile.{h,cpp}, obfuscation.h)"
  :in :bitcoin-lisp-tests)

(in-suite :flatfile-tests)

(defmacro %with-flat-dir ((var) &body body)
  "A private empty directory, removed afterwards."
  `(let ((,var (ensure-directories-exist
                (merge-pathnames (format nil "bl-flatfile-~D/" (get-internal-real-time))
                                 (uiop:temporary-directory)))))
     (unwind-protect (progn ,@body)
       (uiop:delete-directory-tree ,var :validate t :if-does-not-exist :ignore))))

(defun %ff-bytes (&rest values)
  (coerce values '(vector (unsigned-byte 8))))

(defun %ff-read-file (path)
  (with-open-file (s path :element-type '(unsigned-byte 8))
    (let ((out (make-array (file-length s) :element-type '(unsigned-byte 8))))
      (read-sequence out s)
      out)))

;;; --- Obfuscation ------------------------------------------------------------

(test obfuscate-rejects-a-range-outside-the-vector
  "OBFUSCATE! runs its inner loop at SAFETY 0 because it is 8% of an offline
reindex. The range is therefore bounds-checked ONCE at entry: without that a
caller passing a bad START/END would write past the end of the vector instead
of getting an error, which is the only thing SAFETY 0 would have cost."
  (let ((data (make-array 16 :element-type '(unsigned-byte 8) :initial-element 1))
        (key (make-array 8 :element-type '(unsigned-byte 8)
                           :initial-contents '(1 2 3 4 5 6 7 8)))
        (inactive (make-array 8 :element-type '(unsigned-byte 8)
                                :initial-element 0)))
    (signals error (bitcoin-lisp.storage:obfuscate! data key :start 0 :end 17))
    (signals error (bitcoin-lisp.storage:obfuscate! data key :start 9 :end 4))
    (signals error (bitcoin-lisp.storage:obfuscate! data key :start -1 :end 4))
    ;; A short key is refused rather than read past its end. It must be
    ;; NON-ZERO: an all-zero key is inactive and short-circuits before any
    ;; check, which is the documented no-op contract and is why the first
    ;; version of this assertion did not fire.
    (signals error (bitcoin-lisp.storage:obfuscate!
                    data (make-array 4 :element-type '(unsigned-byte 8)
                                       :initial-element 9)))
    ;; An INACTIVE (all-zero) key is a no-op and must not signal even for a
    ;; range that would be invalid — it never touches the vector at all.
    (is (eq data (bitcoin-lisp.storage:obfuscate! data inactive :start 0 :end 17)))
    ;; And the ordinary path still round-trips, at every key alignment.
    (dotimes (offset 8)
      (let ((copy (copy-seq data)))
        (bitcoin-lisp.storage:obfuscate! copy key :key-offset offset)
        (is (not (equalp copy data)) "offset ~D did not change the data" offset)
        (bitcoin-lisp.storage:obfuscate! copy key :key-offset offset)
        (is (equalp copy data) "offset ~D did not round-trip" offset)))))

(test obfuscation-is-keyed-on-the-file-offset-mod-eight
  "plain[i] = disk[i] XOR key[(file_offset + i) mod 8]. Core reaches this
through a table of eight pre-rotated keys and a word-at-a-time XOR; the
identity is the format, the table is a speed trick. The case that distinguishes
a correct implementation from one that restarts the key at every call is a
buffer written at a non-zero, non-multiple-of-8 offset."
  (let ((key (%ff-bytes 1 2 3 4 5 6 7 8))
        (data (make-array 10 :element-type '(unsigned-byte 8) :initial-element 0)))
    (bitcoin-lisp.storage:obfuscate! data key :key-offset 3)
    ;; Byte 0 of the buffer sits at file offset 3, so it meets key byte 3.
    (is (equalp (%ff-bytes 4 5 6 7 8 1 2 3 4 5) data))))

(test obfuscation-is-its-own-inverse-at-any-offset
  (let ((key (%ff-bytes #xF1 #x23 #x45 #x67 #x89 #xAB #xCD #xEF)))
    (dolist (offset '(0 1 7 8 9 63 64 65 1000))
      (let* ((original (map '(vector (unsigned-byte 8)) (lambda (i) (mod (* i 37) 256))
                            (loop for i below 40 collect i)))
             (data (copy-seq original)))
        (bitcoin-lisp.storage:obfuscate! data key :key-offset offset)
        (is (not (equalp original data)) "an active key must actually change the bytes")
        (bitcoin-lisp.storage:obfuscate! data key :key-offset offset)
        (is (equalp original data))))))

(test obfuscation-splits-across-calls-exactly-as-across-one
  "Writing a record in two pieces must produce the same bytes as writing it in
one, or a buffered writer would corrupt every record it happened to split."
  (let* ((key (%ff-bytes 9 8 7 6 5 4 3 2))
         (whole (map '(vector (unsigned-byte 8)) (lambda (i) (mod (* i 11) 256))
                     (loop for i below 30 collect i)))
         (split (copy-seq whole)))
    (bitcoin-lisp.storage:obfuscate! whole key :key-offset 5)
    ;; Same data, same starting offset, but XORed in two calls.
    (bitcoin-lisp.storage:obfuscate! split key :key-offset 5 :start 0 :end 13)
    (bitcoin-lisp.storage:obfuscate! split key :key-offset (+ 5 13) :start 13)
    (is (equalp whole split))))

(test the-zero-key-means-no-obfuscation
  "Core treats an all-zero key as inactive (Obfuscation::operator bool), which
is what a blocksdir written before obfuscation existed gets — so its data stays
readable byte for byte."
  (let ((key (bitcoin-lisp.storage:zero-obfuscation-key))
        (data (%ff-bytes 1 2 3 4 5)))
    (is-false (bitcoin-lisp.storage:obfuscation-key-active-p key))
    (bitcoin-lisp.storage:obfuscate! data key :key-offset 3)
    (is (equalp (%ff-bytes 1 2 3 4 5) data))))

;;; --- xor.dat lifecycle ------------------------------------------------------

(test xor-key-is-created-only-for-a-fresh-blocksdir
  "Core generates a key only when the blocksdir is new, and a pre-existing
xor.dat always wins (blockstorage.cpp:1167-1222). Turning obfuscation on for a
directory that already holds plaintext would make every existing byte
unreadable, which is why the second case here matters more than the first."
  (%with-flat-dir (dir)
    (let ((key (bitcoin-lisp.storage:read-or-create-xor-key dir)))
      (is-true (bitcoin-lisp.storage:obfuscation-key-active-p key))
      (is (probe-file (merge-pathnames "xor.dat" dir)))
      ;; Second call returns the same key, not a new one.
      (is (equalp key (bitcoin-lisp.storage:read-or-create-xor-key dir)))))
  ;; A directory that already holds block data gets the inactive key.
  (%with-flat-dir (dir)
    (with-open-file (s (merge-pathnames "blk00000.dat" dir)
                       :direction :output :element-type '(unsigned-byte 8))
      (write-sequence (%ff-bytes 1 2 3) s))
    (let ((key (bitcoin-lisp.storage:read-or-create-xor-key dir)))
      (is-false (bitcoin-lisp.storage:obfuscation-key-active-p key))
      (is-false (probe-file (merge-pathnames "xor.dat" dir))))))

(test a-wrong-sized-xor-key-is-refused
  "Reading a truncated key and padding it would silently decrypt every block
wrongly, so the size is a hard error."
  (%with-flat-dir (dir)
    (with-open-file (s (merge-pathnames "xor.dat" dir)
                       :direction :output :element-type '(unsigned-byte 8))
      (write-sequence (%ff-bytes 1 2 3) s))
    (signals error (bitcoin-lisp.storage:read-or-create-xor-key dir)))
  (%with-flat-dir (dir)
    (with-open-file (s (merge-pathnames "xor.dat" dir)
                       :direction :output :element-type '(unsigned-byte 8))
      (write-sequence (%ff-bytes 1 2 3 4 5 6 7 8 9) s))
    (signals error (bitcoin-lisp.storage:read-or-create-xor-key dir))))

;;; --- FlatFileSeq ------------------------------------------------------------

(test flat-file-names-are-core-s
  "blk00000.dat / rev00007.dat: five zero-padded digits (FlatFileSeq::FileName)."
  (%with-flat-dir (dir)
    (let ((blk (bitcoin-lisp.storage:make-flat-file-seq dir "blk" 1024))
          (rev (bitcoin-lisp.storage:make-flat-file-seq dir "rev" 1024)))
      (is (string= "blk00000.dat"
                   (file-namestring (bitcoin-lisp.storage:flat-file-name
                                     blk (bitcoin-lisp.storage:make-flat-file-pos 0 0)))))
      (is (string= "rev00007.dat"
                   (file-namestring (bitcoin-lisp.storage:flat-file-name
                                     rev (bitcoin-lisp.storage:make-flat-file-pos 7 999)))))
      (is (string= "blk12345.dat"
                   (file-namestring (bitcoin-lisp.storage:flat-file-name
                                     blk (bitcoin-lisp.storage:make-flat-file-pos 12345 0))))))))

(test allocation-rounds-up-to-whole-chunks
  "Core allocates in multiples of the sequence chunk size, and does nothing when
the request already fits inside the chunks already allocated."
  (%with-flat-dir (dir)
    (let ((seq (bitcoin-lisp.storage:make-flat-file-seq dir "blk" 1024))
          (pos (bitcoin-lisp.storage:make-flat-file-pos 0 0)))
      ;; 100 bytes at offset 0 => one 1024-byte chunk.
      (is (= 1024 (bitcoin-lisp.storage:flat-file-allocate seq pos 100)))
      (is (= 1024 (length (%ff-read-file (bitcoin-lisp.storage:flat-file-name seq pos)))))
      ;; Another 100 bytes still inside that chunk => no growth.
      (let ((pos2 (bitcoin-lisp.storage:make-flat-file-pos 0 100)))
        (is (= 0 (bitcoin-lisp.storage:flat-file-allocate seq pos2 100)))
        (is (= 1024 (length (%ff-read-file (bitcoin-lisp.storage:flat-file-name seq pos))))))
      ;; A request that crosses the boundary grows to the next multiple.
      (let ((pos3 (bitcoin-lisp.storage:make-flat-file-pos 0 1000)))
        (is (= 1048 (bitcoin-lisp.storage:flat-file-allocate seq pos3 100)))
        (is (= 2048 (length (%ff-read-file (bitcoin-lisp.storage:flat-file-name seq pos)))))))))

(test finalize-truncates-the-preallocated-tail
  "The point of the finalize flag: a rolled-over block file must not keep the
zeros it preallocated, or every full file would carry up to a chunk of padding
forever."
  (%with-flat-dir (dir)
    (let* ((seq (bitcoin-lisp.storage:make-flat-file-seq dir "blk" 1024))
           (pos (bitcoin-lisp.storage:make-flat-file-pos 0 0))
           (path (bitcoin-lisp.storage:flat-file-name seq pos)))
      (bitcoin-lisp.storage:flat-file-allocate seq pos 100)
      (with-open-file (s path :direction :io :element-type '(unsigned-byte 8)
                              :if-exists :overwrite)
        (write-sequence (%ff-bytes 7 7 7 7 7) s))
      (is (= 1024 (length (%ff-read-file path))))
      ;; A non-final flush leaves the preallocation alone.
      (bitcoin-lisp.storage:flat-file-flush
       seq (bitcoin-lisp.storage:make-flat-file-pos 0 5))
      (is (= 1024 (length (%ff-read-file path))))
      ;; Finalizing cuts it back to the written length.
      (bitcoin-lisp.storage:flat-file-flush
       seq (bitcoin-lisp.storage:make-flat-file-pos 0 5) :finalize t)
      (is (equalp (%ff-bytes 7 7 7 7 7) (%ff-read-file path))))))

;;; --- Record framing ---------------------------------------------------------

(test record-framing-is-magic-then-little-endian-length
  "Core's 8-byte storage header (STORAGE_HEADER_BYTES): 4-byte network magic,
then the payload length as a little-endian uint32."
  (let* ((magic (%ff-bytes #xF9 #xBE #xB4 #xD9))
         (payload (%ff-bytes 1 2 3))
         (record (bitcoin-lisp.storage:flat-record-bytes magic payload)))
    (is (= 11 (length record)))
    (is (equalp (%ff-bytes #xF9 #xBE #xB4 #xD9 3 0 0 0 1 2 3) record))
    (multiple-value-bind (found-magic length)
        (bitcoin-lisp.storage:parse-flat-record-header record)
      (is (equalp magic found-magic))
      (is (= 3 length))))
  ;; A length that needs all four bytes, so a byte-order slip cannot hide.
  (let* ((magic (%ff-bytes 1 2 3 4))
         (record (bitcoin-lisp.storage:flat-record-bytes
                  magic (make-array #x01020304 :element-type '(unsigned-byte 8)
                                               :initial-element 0))))
    (is (equalp (%ff-bytes 4 3 2 1) (subseq record 4 8)))
    (is (= #x01020304 (nth-value 1 (bitcoin-lisp.storage:parse-flat-record-header record))))))

(test undo-checksum-binds-the-previous-block-hash
  "Core hashes the PREVIOUS block's hash together with the undo data
(blockstorage.cpp:996-999). Without that, a rev record would verify against any
block; with it, a record moved or mismatched fails."
  (let ((undo (%ff-bytes 1 2 3 4 5))
        (prev-a (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xAA))
        (prev-b (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xBB)))
    (let ((sum-a (bitcoin-lisp.storage:undo-record-checksum prev-a undo))
          (sum-b (bitcoin-lisp.storage:undo-record-checksum prev-b undo)))
      (is (= 32 (length sum-a)))
      (is (not (equalp sum-a sum-b))
          "a different previous block must give a different checksum")
      ;; It is exactly SHA256d over the concatenation, nothing else.
      (is (equalp sum-a
                  (bitcoin-lisp.crypto:hash256
                   (concatenate '(vector (unsigned-byte 8)) prev-a undo)))))))

(test undo-record-is-header-payload-checksum
  "Layout, and the overhead constant that sizes the allocation for it."
  (let* ((magic (%ff-bytes #xF9 #xBE #xB4 #xD9))
         (undo (%ff-bytes 9 9 9))
         (prev (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
         (record (bitcoin-lisp.storage:undo-record-bytes magic prev undo)))
    (is (= (+ (length undo) bitcoin-lisp.storage:+undo-data-disk-overhead+)
           (length record)))
    (is (equalp magic (subseq record 0 4)))
    (is (equalp undo (subseq record 8 11)))
    (is (equalp (bitcoin-lisp.storage:undo-record-checksum prev undo)
                (subseq record 11)))))

;;; --- The magic hunt ---------------------------------------------------------

(test the-reader-resyncs-to-the-next-magic-through-garbage
  "What makes a full -reindex possible: a block file can contain a torn write,
a preallocated zero tail, or another network's data, so Core's
LoadExternalBlockFile scans byte-wise for the next magic rather than giving up
(validation.cpp:4988-5155)."
  (let* ((magic (%ff-bytes #xF9 #xBE #xB4 #xD9))
         (payload (%ff-bytes 11 22 33))
         (record (bitcoin-lisp.storage:flat-record-bytes magic payload))
         (stream (concatenate '(vector (unsigned-byte 8))
                              ;; leading junk, including three of the four
                              ;; magic bytes so a naive scanner mis-syncs
                              (%ff-bytes 0 0 #xF9 #xBE #xB4 0 7 7)
                              record
                              ;; trailing zeros, i.e. unwritten preallocation
                              (make-array 16 :element-type '(unsigned-byte 8)
                                             :initial-element 0))))
    (multiple-value-bind (start length) (bitcoin-lisp.storage:find-next-record stream magic)
      (is (= 3 length))
      (is (equalp payload (subseq stream start (+ start length)))))
    ;; Nothing to find once past it.
    (is-false (bitcoin-lisp.storage:find-next-record
               stream magic :start (+ 8 (length record))))
    ;; A header whose length runs past the end of the data is not a record.
    (let ((truncated (subseq stream 0 (+ 8 8 2))))
      (is-false (bitcoin-lisp.storage:find-next-record truncated magic)))))

(test obfuscated-records-round-trip-through-a-file
  "The combination P2 will actually use: frame a record, obfuscate it at its
file offset, write it, read it back, de-obfuscate, and get the payload."
  (%with-flat-dir (dir)
    (let* ((key (bitcoin-lisp.storage:read-or-create-xor-key dir))
           (seq (bitcoin-lisp.storage:make-flat-file-seq dir "blk" 1024))
           (magic (%ff-bytes #xF9 #xBE #xB4 #xD9))
           (first-payload (%ff-bytes 1 2 3 4 5))
           (second-payload (%ff-bytes 6 7 8))
           (r1 (bitcoin-lisp.storage:flat-record-bytes magic first-payload))
           (r2 (bitcoin-lisp.storage:flat-record-bytes magic second-payload))
           (pos (bitcoin-lisp.storage:make-flat-file-pos 0 0))
           (path (bitcoin-lisp.storage:flat-file-name seq pos)))
      ;; Written at their real file offsets, which differ — the second record's
      ;; key alignment depends on the first record's length.
      (let ((d1 (bitcoin-lisp.storage:obfuscate! (copy-seq r1) key :key-offset 0))
            (d2 (bitcoin-lisp.storage:obfuscate! (copy-seq r2) key
                                                 :key-offset (length r1))))
        (with-open-file (s path :direction :output :element-type '(unsigned-byte 8)
                                :if-exists :supersede :if-does-not-exist :create)
          (write-sequence d1 s)
          (write-sequence d2 s)))
      (let ((raw (%ff-read-file path)))
        ;; On disk it is not plaintext.
        (is (not (equalp magic (subseq raw 0 4))))
        (let ((plain (bitcoin-lisp.storage:obfuscate! (copy-seq raw) key :key-offset 0)))
          (is (equalp r1 (subseq plain 0 (length r1))))
          (is (equalp r2 (subseq plain (length r1))))
          (multiple-value-bind (start length)
              (bitcoin-lisp.storage:find-next-record plain magic :start (length r1))
            (is (equalp second-payload (subseq plain start (+ start length))))))))))

;;; --- The block store on top of it -------------------------------------------

(defun %ff-test-block (seed)
  "A small but real block, so the store's own serializer and deserializer are
what round-trips.

The reorg fixture stamps a LABEL into the header's cached hash rather than the
real one, which is fine for tests that only compare labels — but a flat file
holds bytes, and the startup scan recovers a block's identity by hashing the 80
header bytes it finds. So clear the label and let the real hash stand, which is
what production data always has."
  (let ((block (make-reorg-test-block
                (make-array 32 :element-type '(unsigned-byte 8) :initial-element seed)
                (make-array 32 :element-type '(unsigned-byte 8) :initial-element (1+ seed))
                1)))
    (setf (bitcoin-lisp.serialization::block-header-cached-hash
           (bitcoin-lisp.serialization:bitcoin-block-header block))
          nil)
    block))

(defmacro %with-flat-store ((store dir &key (flat t)) &body body)
  `(%with-flat-dir (,dir)
     (let* ((bitcoin-lisp.storage:*flat-block-files* ,flat)
            (,store (bitcoin-lisp.storage:init-block-store ,dir)))
       ,@body)))

(test flat-store-round-trips-a-block-through-a-blk-file
  "Written into blk00000.dat, obfuscated, and read back — through the ordinary
STORE-BLOCK / GET-BLOCK API, which does not change."
  (%with-mainnet-network
   (%with-flat-store (store dir)
     (let* ((block (%ff-test-block 40))
            (hash (bitcoin-lisp.storage:store-block store block)))
       (is (probe-file (merge-pathnames "blocks/blk00000.dat" dir)))
       (is-true (bitcoin-lisp.storage:block-exists-p store hash))
       (let ((back (bitcoin-lisp.storage:get-block store hash)))
         (is-true back)
         (is (equalp hash (bitcoin-lisp.serialization:block-header-hash
                           (bitcoin-lisp.serialization:bitcoin-block-header back)))))
       ;; And the position reported is Core's: past the 8-byte header.
       (multiple-value-bind (h pos) (bitcoin-lisp.storage:store-block store (%ff-test-block 50))
         (declare (ignore h))
         (is (typep pos 'bitcoin-lisp.storage::flat-file-pos))
         (is (plusp (bitcoin-lisp.storage:flat-file-pos-pos pos))))))))

(test flat-store-survives-a-restart-by-scanning-its-files
  "A blk file is self-describing: reopening the store rebuilds the hash ->
position map by walking the records, so nothing outside the file is needed to
find a block again. This is most of what a full -reindex does."
  (%with-mainnet-network
   (%with-flat-dir (dir)
     (let ((hashes '()))
       (let* ((bitcoin-lisp.storage:*flat-block-files* t)
              (store (bitcoin-lisp.storage:init-block-store dir)))
         (dolist (seed '(60 70 80))
           (push (bitcoin-lisp.storage:store-block store (%ff-test-block seed)) hashes)))
       ;; A fresh store over the same directory.
       (let* ((bitcoin-lisp.storage:*flat-block-files* t)
              (store2 (bitcoin-lisp.storage:init-block-store dir)))
         (dolist (h hashes)
           (is-true (bitcoin-lisp.storage:block-exists-p store2 h))
           (is-true (bitcoin-lisp.storage:get-block store2 h)))
         ;; The cursor resumed at the end, so the next block appends rather
         ;; than overwriting the last one.
         (let ((extra (bitcoin-lisp.storage:store-block store2 (%ff-test-block 90))))
           (is-true (bitcoin-lisp.storage:get-block store2 extra))
           (dolist (h hashes)
             (is-true (bitcoin-lisp.storage:get-block store2 h)
                      "an append must not have landed on top of an existing record"))))))))

(test the-store-reads-both-forms-at-once
  "Dual read, which is what makes the transition survivable: blocks written
before the flat files stay readable after the switch, and blocks written after
it stay readable if the flag is turned back off."
  (%with-mainnet-network
   (%with-flat-dir (dir)
     (let (legacy-hash flat-hash)
       ;; One block the old way.
       (let* ((bitcoin-lisp.storage:*flat-block-files* nil)
              (store (bitcoin-lisp.storage:init-block-store dir)))
         (setf legacy-hash (bitcoin-lisp.storage:store-block store (%ff-test-block 100))))
       ;; One the new way, same directory.
       (let* ((bitcoin-lisp.storage:*flat-block-files* t)
              (store (bitcoin-lisp.storage:init-block-store dir)))
         (setf flat-hash (bitcoin-lisp.storage:store-block store (%ff-test-block 110)))
         (is-true (bitcoin-lisp.storage:get-block store legacy-hash)
                  "the pre-existing per-block file must still be readable"))
       ;; Flag off again: both still resolve.
       (let* ((bitcoin-lisp.storage:*flat-block-files* nil)
              (store (bitcoin-lisp.storage:init-block-store dir)))
         (is-true (bitcoin-lisp.storage:get-block store legacy-hash))
         (is-true (bitcoin-lisp.storage:get-block store flat-hash)
                  "a flat record must stay readable with the flag off"))))))

(test a-blocksdir-with-flat-records-never-acquires-a-key
  "A key is created only when there is no FLAT data yet. Legacy per-block files
are read without the obfuscation layer, so they neither need nor forbid one —
but an existing blk?????.dat written without a key must never acquire one, or
every record already in it becomes unreadable."
  (%with-mainnet-network
   ;; Fresh: obfuscated, and the magic is not visible on disk.
   (%with-flat-store (store dir)
     (bitcoin-lisp.storage:store-block store (%ff-test-block 120))
     (let ((raw (%ff-read-file (merge-pathnames "blocks/blk00000.dat" dir))))
       (is (not (equalp (bitcoin-lisp:network-magic :mainnet) (subseq raw 0 4)))
           "a fresh blocksdir writes obfuscated records")))
   ;; Flat records written with no key: a later start must not create one.
   (%with-flat-dir (dir)
     (let (first-hash)
       (let* ((bitcoin-lisp.storage:*flat-block-files* t)
              (store (bitcoin-lisp.storage:init-block-store dir)))
         ;; Force the unobfuscated case the way an older node would have left
         ;; it: no xor.dat, so the key is inactive.
         (setf (bitcoin-lisp.storage::block-store-xor-key store)
               (bitcoin-lisp.storage:zero-obfuscation-key))
         (ignore-errors (delete-file (merge-pathnames "blocks/xor.dat" dir)))
         (setf first-hash (bitcoin-lisp.storage:store-block store (%ff-test-block 130)))
         (let ((raw (%ff-read-file (merge-pathnames "blocks/blk00000.dat" dir))))
           (is (equalp (bitcoin-lisp:network-magic :mainnet) (subseq raw 0 4)))))
       ;; Reopening must NOT generate a key, or the record above is lost.
       (let* ((bitcoin-lisp.storage:*flat-block-files* t)
              (store (bitcoin-lisp.storage:init-block-store dir)))
         (is-false (probe-file (merge-pathnames "blocks/xor.dat" dir)))
         (is-true (bitcoin-lisp.storage:get-block store first-hash)
                  "the unobfuscated record must still be readable"))))
   ;; Legacy per-block files do not block a key: they are read without the
   ;; obfuscation layer, so new flat records can still be obfuscated.
   (%with-flat-dir (dir)
     (let (legacy)
       (let* ((bitcoin-lisp.storage:*flat-block-files* nil)
              (store (bitcoin-lisp.storage:init-block-store dir)))
         (setf legacy (bitcoin-lisp.storage:store-block store (%ff-test-block 135))))
       (let* ((bitcoin-lisp.storage:*flat-block-files* t)
              (store (bitcoin-lisp.storage:init-block-store dir))
              (flat (bitcoin-lisp.storage:store-block store (%ff-test-block 140))))
         (is (probe-file (merge-pathnames "blocks/xor.dat" dir)))
         (is-true (bitcoin-lisp.storage:get-block store legacy))
         (is-true (bitcoin-lisp.storage:get-block store flat)))))))

(test pruning-refuses-a-flat-stored-block-rather-than-failing-quietly
  "Per-block pruning cannot cut a record out of a flat file — that is P3. The
refusal has to be visible: returning NIL is how the caller says `already gone',
so a silent NIL would let a pruned node stop reclaiming space without a word.
This is also why the flag is off by default."
  (%with-mainnet-network
   (%with-flat-store (store dir)
     (declare (ignorable dir))
     (let ((hash (bitcoin-lisp.storage:store-block store (%ff-test-block 150))))
       (is-false (bitcoin-lisp.storage:prune-block store hash))
       (is-true (bitcoin-lisp.storage:get-block store hash)
                "and the block is still there, not half-removed")))))

;;; --- File-granular pruning (P3) ---------------------------------------------

(test a-flat-file-is-prunable-only-when-its-whole-range-is
  "Pruning a flat file is all or nothing, so the test is on the file's ENTIRE
height range, not on individual blocks. A file holding one block above the
window keeps the whole file — which is the trade the format makes, and the
reason Core's unit is the file."
  (%with-mainnet-network
   (%with-flat-store (store dir)
     (declare (ignorable dir))
     ;; File 0 gets heights 10..12, and (pretending it rolled over) file 1
     ;; gets 20..22 by hand.
     (dolist (h '(10 11 12))
       (bitcoin-lisp.storage:store-block store (%ff-test-block (+ 160 h)) :height h))
     (let ((info (gethash 0 (bitcoin-lisp.storage:block-store-file-info store))))
       (is (= 3 (bitcoin-lisp.storage:block-file-info-blocks info)))
       (is (= 10 (bitcoin-lisp.storage:block-file-info-height-first info)))
       (is (= 12 (bitcoin-lisp.storage:block-file-info-height-last info))))
     ;; Entirely inside the window: prunable.
     (is (equal '(0) (bitcoin-lisp.storage::%prunable-flat-files store 5 20)))
     ;; The window ends one block too early: the file stays whole.
     (is (null (bitcoin-lisp.storage::%prunable-flat-files store 5 11)))
     ;; The window starts one block too late: likewise.
     (is (null (bitcoin-lisp.storage::%prunable-flat-files store 11 20))))))

(test a-block-stored-without-a-height-makes-its-file-unprunable
  "The safe direction. A file whose range is unknown can never be SHOWN to lie
inside the window, so it is never deleted — the alternative is dropping a block
the chain still needs. Storing without a height still stores the block."
  (%with-mainnet-network
   (%with-flat-store (store dir)
     (declare (ignorable dir))
     (let ((hash (bitcoin-lisp.storage:store-block store (%ff-test-block 170))))
       (is-true (bitcoin-lisp.storage:get-block store hash))
       (let ((info (gethash 0 (bitcoin-lisp.storage:block-store-file-info store))))
         (is (= 1 (bitcoin-lisp.storage:block-file-info-blocks info)))
         (is (null (bitcoin-lisp.storage:block-file-info-height-first info))))
       (is (null (bitcoin-lisp.storage::%prunable-flat-files store 0 1000000)))))))

(test pruning-a-flat-file-removes-both-halves-and-forgets-its-blocks
  "The blk and rev files go together — a pruned node cannot reorg below its
window, so undo data there is dead weight — and every block in the file leaves
the index, so the download path can re-request it."
  (%with-mainnet-network
   (%with-flat-store (store dir)
     (let ((hashes (loop for h from 30 to 32
                         collect (bitcoin-lisp.storage:store-block
                                  store (%ff-test-block (+ 180 h)) :height h))))
       ;; Give file 0 a rev half so the pair is real.
       (with-open-file (s (merge-pathnames "blocks/rev00000.dat" dir)
                          :direction :output :element-type '(unsigned-byte 8)
                          :if-exists :supersede :if-does-not-exist :create)
         (write-sequence (%ff-bytes 1 2 3 4) s))
       (let ((seen '()))
         (let ((freed (bitcoin-lisp.storage:prune-flat-block-file
                       store 0 :on-prune (lambda (h) (push h seen)))))
           (is (plusp freed))
           (is (= 3 (length seen)) "every block in the file must be reported"))
         (is-false (probe-file (merge-pathnames "blocks/blk00000.dat" dir)))
         (is-false (probe-file (merge-pathnames "blocks/rev00000.dat" dir))
                   "the rev half goes with the blk half")
         (dolist (h hashes)
           (is-false (bitcoin-lisp.storage:block-exists-p store h))
           (is-false (bitcoin-lisp.storage:get-block store h)))
         (is-false (gethash 0 (bitcoin-lisp.storage:block-store-file-info store))))))))

(test file-accounting-is-recovered-from-the-files-and-the-header-index
  "Neither half knows enough alone: the flat files know WHERE each block is,
the header index knows WHAT HEIGHT it is, and pruning needs both. Core persists
this in its block-index database; deriving it means there is no second file to
fall out of step."
  (%with-mainnet-network
   (%with-flat-dir (dir)
     (let ((blocks '()))
       ;; Store three blocks and record them in a chain state at known heights.
       (let* ((bitcoin-lisp.storage:*flat-block-files* t)
              (store (bitcoin-lisp.storage:init-block-store dir))
              (cs (bitcoin-lisp.storage:init-chain-state dir)))
         (loop for h from 40 to 42
               do (let* ((b (%ff-test-block (+ 190 h)))
                         (hash (bitcoin-lisp.storage:store-block store b :height h)))
                    (push (cons hash h) blocks)
                    (bitcoin-lisp.storage:add-block-index-entry
                     cs (bitcoin-lisp.storage:make-block-index-entry
                         :hash hash :height h :status :valid))))
         (bitcoin-lisp.storage:save-header-index cs))
       ;; A fresh store and chain state, as a restart would give.
       (let* ((bitcoin-lisp.storage:*flat-block-files* t)
              (store2 (bitcoin-lisp.storage:init-block-store dir))
              (cs2 (bitcoin-lisp.storage:init-chain-state dir)))
         (is-true (bitcoin-lisp.storage:load-header-index cs2))
         ;; Before the join, the store has positions but no heights.
         (is (null (bitcoin-lisp.storage::%prunable-flat-files store2 0 1000000)))
         (is (= 1 (bitcoin-lisp.storage:rebuild-block-file-info store2 cs2)))
         (let ((info (gethash 0 (bitcoin-lisp.storage:block-store-file-info store2))))
           (is (= 40 (bitcoin-lisp.storage:block-file-info-height-first info)))
           (is (= 42 (bitcoin-lisp.storage:block-file-info-height-last info)))
           (is (plusp (bitcoin-lisp.storage:block-file-info-size info))))
         (is (equal '(0) (bitcoin-lisp.storage::%prunable-flat-files store2 0 100))))))))

(test every-store-block-call-passes-a-height
  "A structural guard, for the same reason as the txindex one. A block stored
without its height silently makes its whole FILE unprunable, and a pruned node
that stops reclaiming space says nothing about it until the disk fills. There
are five call sites; a sixth that forgets is how this returns."
  (let ((sites '()))
    (dolist (rel '("src/validation/block.lisp" "src/networking/ibd.lisp"))
      (let ((src (uiop:read-file-string
                  (merge-pathnames rel (asdf:system-source-directory :bitcoin-lisp)))))
        (loop with start = 0
              for pos = (search "bitcoin-lisp.storage:store-block" src :start2 start)
              while pos
              do (push (subseq src pos (min (length src) (+ pos 400))) sites)
                 (setf start (+ pos 10)))))
    (is (= 5 (length sites))
        "expected 5 store-block call sites; a new one needs :height too")
    (dolist (form sites)
      (is (search ":height" form)
          "a store-block call omits :height, which makes its block file
           unprunable forever"))))

(test prune-old-blocks-actually-prunes-a-flat-file
  "The seam. %PRUNABLE-FLAT-FILES being right is worthless if the node's
pruning entry point never calls it — which is the failure mode this project
keeps finding. Drive the real PRUNE-OLD-BLOCKS with a target of zero and
require the file to be gone."
  (%with-mainnet-network
   (%with-flat-dir (dir)
     (let* ((bitcoin-lisp.storage:*flat-block-files* t)
            (store (bitcoin-lisp.storage:init-block-store dir))
            (cs (bitcoin-lisp.storage:init-chain-state dir))
            (genesis (bitcoin-lisp.storage:best-block-hash cs))
            (prev (bitcoin-lisp.storage:make-block-index-entry
                   :hash genesis :height 0 :chain-work 1 :status :valid)))
       (bitcoin-lisp.storage:add-block-index-entry cs prev)
       ;; A chain well above +min-blocks-to-keep+, so the early heights are
       ;; genuinely prunable.
       (let ((tip-height (+ bitcoin-lisp:+min-blocks-to-keep+ 40)))
         (loop for h from 1 to 3
               do (let* ((b (%ff-test-block (+ 200 h)))
                         (hash (bitcoin-lisp.storage:store-block store b :height h))
                         (entry (bitcoin-lisp.storage:make-block-index-entry
                                 :hash hash :height h :chain-work (1+ h)
                                 :status :valid :prev-entry prev)))
                    (bitcoin-lisp.storage:add-block-index-entry cs entry)
                    (setf prev entry)))
         ;; Claim a far-ahead tip so the stored blocks are below the horizon.
         (bitcoin-lisp.storage:update-chain-tip
          cs (bitcoin-lisp.storage:block-index-entry-hash prev) tip-height)
         (is (probe-file (merge-pathnames "blocks/blk00000.dat" dir)))
         ;; 550 MiB is the smallest target that means AUTOMATIC pruning —
         ;; below it, -prune is manual-only and this path returns 0 without
         ;; looking at anything. The first draft of this test used 1 and
         ;; "passed" its zero-pruned assertion for that reason alone.
         (let ((bitcoin-lisp:*prune-target-mib* 550)
               (bitcoin-lisp:*prune-after-height* 0)
               (swept '()))
           ;; Storage is a few kilobytes, far under the target: nothing goes.
           (is (= 0 (bitcoin-lisp.storage:prune-old-blocks store cs)))
           (is (probe-file (merge-pathnames "blocks/blk00000.dat" dir)))
           ;; Claim usage above the target and the file must go, whole.
           (setf (bitcoin-lisp.storage:block-store-total-bytes store)
                 (* 600 1024 1024))
           (let ((pruned (bitcoin-lisp.storage:prune-old-blocks
                          store cs :on-prune (lambda (h) (push h swept)))))
             (is (= 3 pruned) "all three blocks in the file are pruned together")
             ;; At least three: the legacy per-block walk runs afterwards while
             ;; usage is still above target and re-reports the same heights.
             ;; That is harmless — on-prune is always delete-undo-file, which
             ;; is idempotent — and the exact per-file count is asserted
             ;; directly in the PRUNE-FLAT-BLOCK-FILE test above.
             (is (>= (length swept) 3) "each pruned block is reported for undo cleanup"))
           (is-false (probe-file (merge-pathnames "blocks/blk00000.dat" dir)))
           (is (= 3 (bitcoin-lisp.storage::chain-state-pruned-height cs))
               "the prune horizon advances to the file's last height")))))))

;;; --- Rebuilding the index from the files (P5) ---------------------------------

(defun %ff-chain-block (prev-hash seed height)
  "A block whose header genuinely links to PREV-HASH, so a rebuilt index can
follow the chain. The reorg fixture's cached-hash label is cleared for the same
reason as elsewhere: reindexing recovers identity from BYTES."
  (let ((b (make-reorg-test-block
            prev-hash
            (make-array 32 :element-type '(unsigned-byte 8) :initial-element seed)
            height)))
    (setf (bitcoin-lisp.serialization::block-header-cached-hash
           (bitcoin-lisp.serialization:bitcoin-block-header b))
          nil)
    b))

(test the-block-index-can-be-rebuilt-from-the-block-files
  "The capability the flat files were worth having for. Delete the whole header
index, keep the blocks, and the chain comes back — which turns a lost index
from a full resync into local work."
  (%with-mainnet-network
   (%with-flat-dir (dir)
     (let* ((bitcoin-lisp.storage:*flat-block-files* t)
            (store (bitcoin-lisp.storage:init-block-store dir))
            (cs (bitcoin-lisp.storage:init-chain-state dir))
            (genesis (bitcoin-lisp.storage:best-block-hash cs))
            (hashes '()))
       (bitcoin-lisp.storage:add-block-index-entry
        cs (bitcoin-lisp.storage:make-block-index-entry
            :hash genesis :height 0 :chain-work 1 :status :valid))
       ;; A five-block chain, each linking to the last.
       (let ((prev genesis))
         (loop for h from 1 to 5
               do (let* ((b (%ff-chain-block prev (+ 210 h) h))
                         (hash (bitcoin-lisp.storage:store-block store b :height h)))
                    (push hash hashes)
                    (setf prev hash))))
       (setf hashes (nreverse hashes))
       ;; Now lose the index entirely — only genesis survives, as it would on a
       ;; fresh start.
       (let* ((store2 (bitcoin-lisp.storage:init-block-store dir))
              (cs2 (bitcoin-lisp.storage:init-chain-state dir)))
         (bitcoin-lisp.storage:add-block-index-entry
          cs2 (bitcoin-lisp.storage:make-block-index-entry
               :hash genesis :height 0 :chain-work 1 :status :valid))
         (is (= 1 (hash-table-count
                   (bitcoin-lisp.storage::chain-state-block-index cs2)))
             "starting from an index that knows only genesis")
         (multiple-value-bind (added orphans)
             (bitcoin-lisp.storage:reindex-block-index store2 cs2)
           (is (= 5 added) "every stored block must come back")
           (is (= 0 orphans)))
         ;; And the tree is linked, with heights and work derived from it.
         (loop for hash in hashes
               for h from 1
               do (let ((e (bitcoin-lisp.storage:get-block-index-entry cs2 hash)))
                    (is-true e "block at height ~D was not rebuilt" h)
                    (when e
                      (is (= h (bitcoin-lisp.storage:block-index-entry-height e)))
                      (is-true (bitcoin-lisp.storage:block-index-entry-header e))
                      (is-true (bitcoin-lisp.storage:block-index-entry-prev-entry e))
                      ;; Not re-validated, so the entry claims only its header.
                      (is (eq :header-valid
                              (bitcoin-lisp.storage:block-index-entry-status e)))
                      (is (> (bitcoin-lisp.storage:block-index-entry-chain-work e) 0))))))))))

(test reindexing-does-not-care-what-order-the-blocks-were-stored-in
  "Blocks are stored in the order they ARRIVED, so a block's parent can be
later in the file. Core parks such records by their parent's hash and drains
them once it lands; without that, reindexing a node that saw a block out of
order would silently lose the rest of the chain behind it."
  (%with-mainnet-network
   (%with-flat-dir (dir)
     (let* ((bitcoin-lisp.storage:*flat-block-files* t)
            (store (bitcoin-lisp.storage:init-block-store dir))
            (cs (bitcoin-lisp.storage:init-chain-state dir))
            (genesis (bitcoin-lisp.storage:best-block-hash cs))
            (blocks '()))
       (bitcoin-lisp.storage:add-block-index-entry
        cs (bitcoin-lisp.storage:make-block-index-entry
            :hash genesis :height 0 :chain-work 1 :status :valid))
       ;; Build the chain in memory first, then store it BACKWARDS.
       (let ((prev genesis))
         (loop for h from 1 to 5
               do (let ((b (%ff-chain-block prev (+ 220 h) h)))
                    (push (cons b h) blocks)
                    (setf prev (bitcoin-lisp.serialization:block-header-hash
                                (bitcoin-lisp.serialization:bitcoin-block-header b))))))
       ;; BLOCKS is already newest-first: store the child before the parent.
       (dolist (pair blocks)
         (bitcoin-lisp.storage:store-block store (car pair) :height (cdr pair)))
       (let ((store2 (bitcoin-lisp.storage:init-block-store dir))
             (cs2 (bitcoin-lisp.storage:init-chain-state dir)))
         (bitcoin-lisp.storage:add-block-index-entry
          cs2 (bitcoin-lisp.storage:make-block-index-entry
               :hash genesis :height 0 :chain-work 1 :status :valid))
         (multiple-value-bind (added orphans)
             (bitcoin-lisp.storage:reindex-block-index store2 cs2)
           (is (= 5 added) "reverse storage order must still rebuild the whole chain")
           (is (= 0 orphans))))))))

(test a-record-whose-parent-is-gone-is-reported-not-treated-as-corruption
  "On a pruned node the chain below the horizon is deleted, so records with no
reachable parent are EXPECTED. Reporting the count lets an operator tell that
apart from a genuinely broken file; refusing would make reindex useless on
exactly the nodes that most need it."
  (%with-mainnet-network
   (%with-flat-dir (dir)
     (let* ((bitcoin-lisp.storage:*flat-block-files* t)
            (store (bitcoin-lisp.storage:init-block-store dir))
            (cs (bitcoin-lisp.storage:init-chain-state dir))
            (genesis (bitcoin-lisp.storage:best-block-hash cs)))
       (bitcoin-lisp.storage:add-block-index-entry
        cs (bitcoin-lisp.storage:make-block-index-entry
            :hash genesis :height 0 :chain-work 1 :status :valid))
       ;; A block whose parent is a hash nothing in the store produces.
       (bitcoin-lisp.storage:store-block
        store (%ff-chain-block (make-array 32 :element-type '(unsigned-byte 8)
                                              :initial-element #xEE)
                               230 1)
        :height 1)
       (let ((store2 (bitcoin-lisp.storage:init-block-store dir))
             (cs2 (bitcoin-lisp.storage:init-chain-state dir)))
         (bitcoin-lisp.storage:add-block-index-entry
          cs2 (bitcoin-lisp.storage:make-block-index-entry
               :hash genesis :height 0 :chain-work 1 :status :valid))
         (multiple-value-bind (added orphans)
             (bitcoin-lisp.storage:reindex-block-index store2 cs2)
           (is (= 0 added))
           (is (= 1 orphans) "the unreachable record is counted, not an error")))))))

(test reindexing-is-additive-and-idempotent
  "It never discards what is already known: a node that threw away a good index
to rebuild it would be strictly worse off if the files turned out to be
incomplete. Running it twice adds nothing the second time."
  (%with-mainnet-network
   (%with-flat-dir (dir)
     (let* ((bitcoin-lisp.storage:*flat-block-files* t)
            (store (bitcoin-lisp.storage:init-block-store dir))
            (cs (bitcoin-lisp.storage:init-chain-state dir))
            (genesis (bitcoin-lisp.storage:best-block-hash cs)))
       (bitcoin-lisp.storage:add-block-index-entry
        cs (bitcoin-lisp.storage:make-block-index-entry
            :hash genesis :height 0 :chain-work 1 :status :valid))
       (let ((prev genesis))
         (loop for h from 1 to 3
               do (let ((b (%ff-chain-block prev (+ 240 h) h)))
                    (bitcoin-lisp.storage:store-block store b :height h)
                    (setf prev (bitcoin-lisp.serialization:block-header-hash
                                (bitcoin-lisp.serialization:bitcoin-block-header b))))))
       ;; The index already holds everything, having been built as we stored.
       (is (= 3 (bitcoin-lisp.storage:reindex-block-index store cs))
           "the first rebuild fills an index that only knew genesis")
       (is (= 0 (bitcoin-lisp.storage:reindex-block-index store cs))
           "and a second pass adds nothing")))))

;;; --- Migrating legacy per-block files into flat files (P4) --------------------

(defun %ff-migration-chain (dir n &key (seed-base 250))
  "Store an N-block active chain as LEGACY per-block files and return the chain
state, the store, and the hashes in height order."
  (let* ((bitcoin-lisp.storage:*flat-block-files* nil)
         (store (bitcoin-lisp.storage:init-block-store dir))
         (cs (bitcoin-lisp.storage:init-chain-state dir))
         (genesis (bitcoin-lisp.storage:best-block-hash cs))
         (prev-entry (bitcoin-lisp.storage:make-block-index-entry
                      :hash genesis :height 0 :chain-work 1 :status :valid))
         (hashes '()))
    (bitcoin-lisp.storage:add-block-index-entry cs prev-entry)
    (let ((prev genesis))
      (loop for h from 1 to n
            do (let* ((b (%ff-chain-block prev (+ seed-base h) h))
                      (hash (bitcoin-lisp.storage:store-block store b :height h))
                      (entry (bitcoin-lisp.storage:make-block-index-entry
                              :hash hash :height h :chain-work (1+ h)
                              :status :valid :prev-entry prev-entry)))
                 (bitcoin-lisp.storage:add-block-index-entry cs entry)
                 (push hash hashes)
                 (setf prev hash prev-entry entry))))
    (bitcoin-lisp.storage:update-chain-tip
     cs (bitcoin-lisp.storage:block-index-entry-hash prev-entry) n)
    (values cs store (nreverse hashes))))

(test migration-converts-legacy-blocks-and-keeps-them-readable
  "The whole point: after migrating, every block still comes back byte-identical
and the per-block files are gone. Reading the blocks back is the assertion that
matters — a migration that updated the index but wrote nothing usable would
pass any count-based check."
  (%with-mainnet-network
   (%with-flat-dir (dir)
     (multiple-value-bind (cs store hashes) (%ff-migration-chain dir 5)
       ;; Capture the blocks as the legacy store serves them.
       (let ((before (mapcar (lambda (h)
                               (bitcoin-lisp.serialization:serialize-witness-block
                                (bitcoin-lisp.storage:get-block store h)))
                             hashes)))
         (is (= 5 (bitcoin-lisp.storage:count-legacy-blocks store)))
         (is-false (probe-file (merge-pathnames "blocks/blk00000.dat" dir)))
         (multiple-value-bind (migrated next remaining)
             (bitcoin-lisp.storage:migrate-blocks-to-flat-files store cs)
           (is (= 5 migrated))
           (is (= 6 next) "resumes above the tip once everything is converted")
           (is (= 0 remaining)))
         (is (probe-file (merge-pathnames "blocks/blk00000.dat" dir)))
         ;; Every per-block file is gone...
         (dolist (h hashes)
           (is-false (probe-file (bitcoin-lisp.storage::block-file-path store h))
                     "a per-block file survived the migration"))
         ;; ...and every block reads back identically, through the flat path.
         (loop for h in hashes
               for original in before
               do (let ((got (bitcoin-lisp.storage:get-block store h)))
                    (is-true got "block ~A is gone after migration"
                             (bitcoin-lisp.crypto:bytes-to-hex h))
                    (when got
                      (is (equalp original
                                  (bitcoin-lisp.serialization:serialize-witness-block got)))))))))))

(test migration-survives-a-restart-that-loses-the-in-memory-index
  "The converted blocks have to be findable by a process that never saw the
migration — otherwise the migration is only true of the running image, and the
next restart loses the chain."
  (%with-mainnet-network
   (%with-flat-dir (dir)
     (multiple-value-bind (cs store hashes) (%ff-migration-chain dir 4 :seed-base 60)
       (bitcoin-lisp.storage:migrate-blocks-to-flat-files store cs)
       (let* ((bitcoin-lisp.storage:*flat-block-files* t)
              (store2 (bitcoin-lisp.storage:init-block-store dir)))
         (is (= 0 (bitcoin-lisp.storage:count-legacy-blocks store2)))
         (dolist (h hashes)
           (is-true (bitcoin-lisp.storage:get-block store2 h)
                    "a migrated block is not findable after a restart")))))))

(test migration-honors-its-budget-and-resumes-where-it-stopped
  "An operator converting a live node needs to stop after a slice and continue
later. The resume height is the contract; if it were wrong the next call would
either redo work or skip blocks."
  (%with-mainnet-network
   (%with-flat-dir (dir)
     (multiple-value-bind (cs store hashes) (%ff-migration-chain dir 6 :seed-base 70)
       (declare (ignore hashes))
       (multiple-value-bind (migrated next remaining)
           (bitcoin-lisp.storage:migrate-blocks-to-flat-files
            store cs :max-blocks 2)
         (is (= 2 migrated))
         (is (= 3 next) "two blocks converted means heights 1 and 2 are done")
         (is (= 4 remaining)))
       (multiple-value-bind (migrated next remaining)
           (bitcoin-lisp.storage:migrate-blocks-to-flat-files
            store cs :max-blocks 2 :start-height 3)
         (is (= 2 migrated))
         (is (= 5 next))
         (is (= 2 remaining)))
       (multiple-value-bind (migrated next remaining)
           (bitcoin-lisp.storage:migrate-blocks-to-flat-files
            store cs :max-blocks 100 :start-height 5)
         (is (= 2 migrated))
         (is (= 0 remaining)))))))

(test migration-is-idempotent
  "Re-running must be free, not destructive. A resumable job that converts
already-converted blocks would rewrite the whole chain on every retry."
  (%with-mainnet-network
   (%with-flat-dir (dir)
     (multiple-value-bind (cs store) (%ff-migration-chain dir 3 :seed-base 80)
       (is (= 3 (bitcoin-lisp.storage:migrate-blocks-to-flat-files store cs)))
       (let ((size (bitcoin-lisp.storage::file-size-bytes
                    (merge-pathnames "blocks/blk00000.dat" dir))))
         (is (= 0 (bitcoin-lisp.storage:migrate-blocks-to-flat-files store cs))
             "a second pass converts nothing")
         (is (= size (bitcoin-lisp.storage::file-size-bytes
                      (merge-pathnames "blocks/blk00000.dat" dir)))
             "and writes nothing"))))))

(test migration-in-height-order-leaves-the-file-prunable
  "The reason the walk is ordered at all. A flat file is prunable only when its
whole height range is below the horizon; converting in arrival order would give
file 0 a range spanning the chain, and a pruned node would quietly stop
reclaiming space. Assert the range, not the order."
  (%with-mainnet-network
   (%with-flat-dir (dir)
     (multiple-value-bind (cs store) (%ff-migration-chain dir 5 :seed-base 90)
       (bitcoin-lisp.storage:migrate-blocks-to-flat-files store cs)
       (let ((info (gethash 0 (bitcoin-lisp.storage:block-store-file-info store))))
         (is-true info "the migrated file has no height bookkeeping at all")
         (when info
           (is (= 1 (bitcoin-lisp.storage:block-file-info-height-first info)))
           (is (= 5 (bitcoin-lisp.storage:block-file-info-height-last info)))))
       ;; And it is genuinely selectable for pruning below a horizon above it.
       (is (equal '(0) (bitcoin-lisp.storage::%prunable-flat-files store 0 100)))))))

(test migration-does-not-touch-blocks-off-the-active-chain
  "Side-chain blocks have no height in a flat file's range, and converting them
would poison that range. They stay per-block, and dual read keeps them served."
  (%with-mainnet-network
   (%with-flat-dir (dir)
     (multiple-value-bind (cs store hashes) (%ff-migration-chain dir 3 :seed-base 100)
       ;; A block that is in the store but not on the active chain.
       (let* ((bitcoin-lisp.storage:*flat-block-files* nil)
              (side (bitcoin-lisp.storage:store-block
                     store (%ff-chain-block (first hashes) 199 2) :height 2)))
         (multiple-value-bind (migrated next remaining)
             (bitcoin-lisp.storage:migrate-blocks-to-flat-files store cs)
           (declare (ignore next))
           (is (= 3 migrated))
           (is (= 1 remaining) "the side-chain block is still a per-block file"))
         (is-true (probe-file (bitcoin-lisp.storage::block-file-path store side)))
         (is-true (bitcoin-lisp.storage:get-block store side)
                  "and it is still readable"))))))

(test migration-keeps-the-storage-total-honest
  "The running byte total drives automatic pruning. STORE-BLOCK already replaces
the legacy file's contribution when it writes the flat record, so decrementing
again at the unlink — the obvious thing to write — would drive the total toward
zero and disable pruning on a node that has just been migrated."
  (%with-mainnet-network
   (%with-flat-dir (dir)
     (multiple-value-bind (cs store) (%ff-migration-chain dir 4 :seed-base 110)
       (bitcoin-lisp.storage:migrate-blocks-to-flat-files store cs)
       (let ((on-disk (bitcoin-lisp.storage::file-size-bytes
                       (merge-pathnames "blocks/blk00000.dat" dir)))
             (accounted (bitcoin-lisp.storage:block-store-total-bytes store)))
         (is (plusp accounted) "the total must not have been driven to zero")
         ;; The file is preallocated in 16 MiB chunks, so on-disk >= accounted;
         ;; what matters is that the accounted total matches the RECORDS.
         (is (<= accounted on-disk))
         (let* ((bitcoin-lisp.storage:*flat-block-files* t)
                (fresh (bitcoin-lisp.storage:init-block-store dir)))
           (is (= accounted (bitcoin-lisp.storage:block-store-total-bytes fresh))
               "a fresh scan of the same files must agree with the running total")))))))

(test a-block-that-fails-to-read-back-stops-the-migration-with-its-file-intact
  "The one failure this must handle without losing data. If the flat record
cannot be read back, the per-block file is the only surviving copy — so it is
kept, and the walk stops rather than converting more blocks through a path just
shown not to work."
  (%with-mainnet-network
   (%with-flat-dir (dir)
     (multiple-value-bind (cs store hashes) (%ff-migration-chain dir 4 :seed-base 120)
       (let* ((victim (second hashes))
              (real #'bitcoin-lisp.storage:get-block)
              (seen 0))
         ;; Fail the READ-BACK of height 2 only: the first call for a hash is
         ;; the migrator loading the legacy block, the second is the verify.
         (let ((calls (make-hash-table :test 'equalp)))
           (handler-bind ()
             (let ((wrapper (lambda (s h)
                              (let ((n (incf (gethash h calls 0))))
                                (if (and (equalp h victim) (= n 2))
                                    (progn (incf seen) nil)
                                    (funcall real s h))))))
               (unwind-protect
                    (progn
                      (setf (fdefinition 'bitcoin-lisp.storage:get-block) wrapper)
                      (multiple-value-bind (migrated next remaining)
                          (bitcoin-lisp.storage:migrate-blocks-to-flat-files store cs)
                        (is (= 1 migrated) "only height 1 converted before the failure")
                        (is (= 2 next) "and the retry resumes at the block that failed")
                        ;; Three still legacy: the victim plus the two above it.
                        ;; The victim counts only because the index was put back
                        ;; -- STORE-BLOCK had already repointed it at the flat
                        ;; record, and leaving it there would have made dual
                        ;; read serve the copy that just failed.
                        (is (= 3 remaining))))
                 (setf (fdefinition 'bitcoin-lisp.storage:get-block) real)))))
         (is (= 1 seen) "the injected failure must actually have fired")
         ;; The victim's per-block file is still there, and still readable.
         (is-true (probe-file (bitcoin-lisp.storage::block-file-path store victim)))
         (is-true (funcall real store victim)))))))

(test the-migration-is-reachable-as-an-rpc
  "The seam. A migration nothing can invoke is the same bug this project has now
found seven times — correct code with no caller. The operator's only handle on a
live node is the RPC, so assert it is registered and validates its arguments."
  (bitcoin-lisp.rpc::register-all-methods)
  (is-true (gethash "migrateblocks" bitcoin-lisp.rpc::*rpc-methods*)
           "migrateblocks is not registered, so nothing can start a migration")
  (let ((handler (gethash "migrateblocks" bitcoin-lisp.rpc::*rpc-methods*)))
    ;; Bad arguments are rejected before any node state is touched, so NIL for
    ;; the node is enough to prove the guard runs first.
    (signals bitcoin-lisp.rpc::rpc-error (funcall handler nil '(0)))
    (signals bitcoin-lisp.rpc::rpc-error (funcall handler nil '(10 -1)))))

(test a-crash-between-the-flat-write-and-the-unlink-is-swept-on-the-next-pass
  "The crash window. INIT-BLOCK-STORE indexes per-block files first and flat
records second, so after a crash in that window the flat record wins the index
and the per-block file becomes an orphan nothing reads — but its bytes still
count toward the pruning total, so a pruned node prunes earlier than it should.
Re-running the migration must sweep it."
  (%with-mainnet-network
   (%with-flat-dir (dir)
     (multiple-value-bind (cs store hashes) (%ff-migration-chain dir 3 :seed-base 130)
       (bitcoin-lisp.storage:migrate-blocks-to-flat-files store cs)
       ;; Recreate exactly what the crash leaves behind: the flat record is
       ;; there and indexed, and the per-block file is back on disk.
       (let* ((victim (second hashes))
              (orphan (bitcoin-lisp.storage::block-file-path store victim)))
         (with-open-file (out orphan :direction :output
                                     :element-type '(unsigned-byte 8)
                                     :if-exists :supersede)
           (write-sequence (bitcoin-lisp.serialization:serialize-witness-block
                            (bitcoin-lisp.storage:get-block store victim))
                           out))
         ;; A restart double-counts it, which is the harm.
         (let* ((bitcoin-lisp.storage:*flat-block-files* t)
                (store2 (bitcoin-lisp.storage:init-block-store dir))
                (inflated (bitcoin-lisp.storage:block-store-total-bytes store2)))
           (is (= 0 (bitcoin-lisp.storage:count-legacy-blocks store2))
               "the flat record wins the index, so nothing looks unmigrated")
           (multiple-value-bind (migrated) 
               (bitcoin-lisp.storage:migrate-blocks-to-flat-files store2 cs)
             (is (= 0 migrated) "there is nothing left to convert"))
           (is-false (probe-file orphan) "the orphaned per-block file was not swept")
           (is (< (bitcoin-lisp.storage:block-store-total-bytes store2) inflated)
               "and its bytes stopped counting toward the pruning total")
           (is-true (bitcoin-lisp.storage:get-block store2 victim)
                    "sweeping the orphan must not cost the block")))))))

(test which-copy-wins-a-duplicate-is-decided-by-which-one-reads
  "The other half of the crash window. If the flat record is the corrupt one,
sweeping the per-block file because the index names the flat copy would delete
the only readable copy of the block. The index goes back onto the file that
reads, which also lets the migration retry it."
  (%with-mainnet-network
   (%with-flat-dir (dir)
     (multiple-value-bind (cs store hashes) (%ff-migration-chain dir 3 :seed-base 140)
       (bitcoin-lisp.storage:migrate-blocks-to-flat-files store cs)
       (let* ((victim (second hashes))
              (legacy (bitcoin-lisp.storage::block-file-path store victim))
              (body (bitcoin-lisp.serialization:serialize-witness-block
                     (bitcoin-lisp.storage:get-block store victim)))
              (real #'bitcoin-lisp.storage:get-block))
         ;; Put the per-block file back, as the crash would leave it.
         (with-open-file (out legacy :direction :output
                                     :element-type '(unsigned-byte 8)
                                     :if-exists :supersede)
           (write-sequence body out))
         ;; And make the flat copy unreadable for this hash only.
         (let ((wrapper (lambda (s h)
                          (if (equalp h victim)
                              (if (bitcoin-lisp.storage::flat-file-pos-p
                                   (gethash h (bitcoin-lisp.storage::block-store-index s)))
                                  nil
                                  (funcall real s h))
                              (funcall real s h)))))
           (unwind-protect
                (progn
                  (setf (fdefinition 'bitcoin-lisp.storage:get-block) wrapper)
                  (bitcoin-lisp.storage:migrate-blocks-to-flat-files store cs))
             (setf (fdefinition 'bitcoin-lisp.storage:get-block) real)))
         (is-true (probe-file legacy)
                  "the readable per-block copy must not have been swept")
         (is (= 1 (bitcoin-lisp.storage:count-legacy-blocks store))
             "and the index must point back at it, so the migration can retry")
         (is-true (funcall real store victim)))))))

(test pruneblockchain-prunes-a-flat-file
  "The MANUAL prune entry point had the same seam the automatic one has a test
for, and failed it: every block went to PRUNE-BLOCK, which refuses for a flat
record and returns NIL, so pruneblockchain reported success and freed nothing.
Core's FindFilesToPruneManual selects whole FILES whose last height is at or
below the target (node/blockstorage.cpp:292-319).

This is what blocked rolling the flat format out to the pruned mainnet node:
its operator would have had a -prune node that silently stopped reclaiming."
  (%with-mainnet-network
   (%with-flat-dir (dir)
     (let* ((bitcoin-lisp.storage:*flat-block-files* t)
            (store (bitcoin-lisp.storage:init-block-store dir))
            (cs (bitcoin-lisp.storage:init-chain-state dir))
            (genesis (bitcoin-lisp.storage:best-block-hash cs))
            (prev (bitcoin-lisp.storage:make-block-index-entry
                   :hash genesis :height 0 :chain-work 1 :status :valid)))
       (bitcoin-lisp.storage:add-block-index-entry cs prev)
       (let ((tip-height (+ bitcoin-lisp:+min-blocks-to-keep+ 40)))
         (loop for h from 1 to 3
               do (let* ((b (%ff-test-block (+ 210 h)))
                         (hash (bitcoin-lisp.storage:store-block store b :height h))
                         (entry (bitcoin-lisp.storage:make-block-index-entry
                                 :hash hash :height h :chain-work (1+ h)
                                 :status :valid :prev-entry prev)))
                    (bitcoin-lisp.storage:add-block-index-entry cs entry)
                    (setf prev entry)))
         (bitcoin-lisp.storage:update-chain-tip
          cs (bitcoin-lisp.storage:block-index-entry-hash prev) tip-height)
         (is (probe-file (merge-pathnames "blocks/blk00000.dat" dir)))
         ;; Manual pruning works at any -prune target, unlike the automatic
         ;; path which is off below 550 MiB.
         (let ((bitcoin-lisp:*prune-target-mib* 1)
               (bitcoin-lisp:*prune-after-height* 0)
               (swept '()))
           (let ((pruned (bitcoin-lisp.storage:prune-blocks-to-height
                          store cs 3 :on-prune (lambda (h) (push h swept)))))
             (is (= 3 pruned) "the file's three blocks were not pruned"))
           (is-false (probe-file (merge-pathnames "blocks/blk00000.dat" dir))
                     "pruneblockchain left the flat file on disk")
           (is (>= (length swept) 3)
               "each pruned block must be reported so its undo data goes too")
           (is (= 3 (bitcoin-lisp.storage::chain-state-pruned-height cs))
               "the prune horizon did not advance to the file's last height")))))))

(test get-block-serves-the-genesis-body-nobody-stores
  "The genesis block is never RECEIVED, so nothing ever calls STORE-BLOCK for
it — but Core has it on disk from initialisation and every Core reader can
fetch it. getblock(getbestblockhash()) on a fresh node IS genesis, which is how
Core's functional tests open: p2p_invalid_block.py:45 and p2p_invalid_tx.py:54
both did, and both died on -5 'Block not found'.

Rebuilt in GET-BLOCK rather than at the twelve RPC/REST sites that want a block
body — one of them would have been missed."
  (dolist (network '(:regtest :testnet4 :mainnet))
    (let ((bitcoin-lisp:*network* network))
      (%with-flat-store (store dir)
        (declare (ignore dir))
        (let* ((hash (bitcoin-lisp.storage:network-genesis-hash network))
               (block (bitcoin-lisp.storage:get-block store hash)))
          (is-true block "~A: genesis body not served" network)
          (when block
            (is (equalp hash
                        (bitcoin-lisp.serialization:block-header-hash
                         (bitcoin-lisp.serialization:bitcoin-block-header block)))
                "~A: served a block that is not genesis" network))))))
  ;; A hash that is nobody's genesis is still absent.
  (let ((bitcoin-lisp:*network* :regtest))
    (%with-flat-store (store dir)
      (declare (ignore dir))
      (is-false (bitcoin-lisp.storage:get-block
                 store (make-array 32 :element-type '(unsigned-byte 8)
                                      :initial-element 42))))))

;;;; --- prune locks (Core BlockManager::m_prune_locks) ---

(defmacro %with-clean-prune-locks (&body body)
  "Run BODY with a private prune-lock table, so a test can never leave a lock
behind for the next one.

:SYNCHRONIZED like the real one — a test that exercised a plain table would not
be exercising what production runs, and the synchronization is the whole reason
that variable is allowed to be global."
  `(let ((bitcoin-lisp.storage:*prune-locks*
           (make-hash-table :test 'equal :synchronized t)))
     ,@body))

(test prune-lock-ceiling-with-no-locks-is-the-chain-height
  "With nothing registered, pruning is unconstrained — the ceiling is the tip."
  (%with-clean-prune-locks
    (is (= 1000 (bitcoin-lisp.storage:prune-lock-ceiling 1000)))))

(test prune-lock-ceiling-subtracts-the-buffer-and-one
  "Core: lock_height = height_first - PRUNE_LOCK_BUFFER - 1
\(validation.cpp:2727). An index at height 500 protects 489 upward."
  (%with-clean-prune-locks
    (bitcoin-lisp.storage:register-prune-lock "idx" (lambda () 500))
    (is (= (- 500 bitcoin-lisp.storage:+prune-lock-buffer+ 1)
           (bitcoin-lisp.storage:prune-lock-ceiling 1000)))
    (is (= 489 (bitcoin-lisp.storage:prune-lock-ceiling 1000)))))

(test prune-lock-ceiling-takes-the-lowest-lock
  "Several locks: the most-behind index wins, because pruning past it would
destroy undo data it still has to read."
  (%with-clean-prune-locks
    (bitcoin-lisp.storage:register-prune-lock "fast" (lambda () 900))
    (bitcoin-lisp.storage:register-prune-lock "slow" (lambda () 300))
    (is (= 289 (bitcoin-lisp.storage:prune-lock-ceiling 1000)))))

(test prune-lock-ceiling-never-exceeds-the-chain-height
  "A lock ahead of the tip does not RAISE the ceiling — Core seeds last_prune
with the chain height and only ever lowers it."
  (%with-clean-prune-locks
    (bitcoin-lisp.storage:register-prune-lock "ahead" (lambda () 5000))
    (is (= 100 (bitcoin-lisp.storage:prune-lock-ceiling 100)))))

(test prune-lock-ceiling-floors-at-one
  "Core floors last_prune at 1 (max(1, min(...))), so an index near genesis
cannot drive the ceiling negative."
  (%with-clean-prune-locks
    (bitcoin-lisp.storage:register-prune-lock "new" (lambda () 3))
    (is (= 1 (bitcoin-lisp.storage:prune-lock-ceiling 1000)))))

(test prune-lock-with-no-height-does-not-constrain
  "A registered-but-empty index is Core's height_first == INT_MAX: it imposes
no constraint. Reading -1 as a height instead would clamp the ceiling to 1 and
stop a pruned node from ever reclaiming space."
  (%with-clean-prune-locks
    (bitcoin-lisp.storage:register-prune-lock "empty" (lambda () nil))
    (is (= 1000 (bitcoin-lisp.storage:prune-lock-ceiling 1000)))))

(test prune-lock-registration-replaces-by-name
  "Re-registering the same name replaces, so a node restart cannot stack two
locks for one index."
  (%with-clean-prune-locks
    (bitcoin-lisp.storage:register-prune-lock "idx" (lambda () 300))
    (bitcoin-lisp.storage:register-prune-lock "idx" (lambda () 900))
    (is (= 889 (bitcoin-lisp.storage:prune-lock-ceiling 1000)))
    (bitcoin-lisp.storage:clear-prune-locks)
    (is (= 1000 (bitcoin-lisp.storage:prune-lock-ceiling 1000)))))

(test prune-lock-signalling-thunk-does-not-break-pruning
  "A thunk that errors (a closed index DB after shutdown, say) is treated as
absent rather than taking the node's pruning down with it."
  (%with-clean-prune-locks
    (bitcoin-lisp.storage:register-prune-lock
     "broken" (lambda () (error "index closed")))
    (is (= 1000 (bitcoin-lisp.storage:prune-lock-ceiling 1000)))))

(test prune-lock-stops-a-real-flat-file-prune
  "The seam for prune locks: PRUNE-LOCK-CEILING being right is worthless if
PRUNE-OLD-BLOCKS never consults it. Drive the real entry point with usage far
over target and an index parked at height 1, and require the file to SURVIVE —
then drop the lock and require the same call to delete it.

Without this, a filter index that had not caught up would have its undo data
deleted out from under it, and the only symptom would be the index failing to
build much later."
  (%with-mainnet-network
   (%with-flat-dir (dir)
     (let* ((bitcoin-lisp.storage:*flat-block-files* t)
            (bitcoin-lisp.storage:*prune-locks*
              (make-hash-table :test 'equal :synchronized t))
            (store (bitcoin-lisp.storage:init-block-store dir))
            (cs (bitcoin-lisp.storage:init-chain-state dir))
            (genesis (bitcoin-lisp.storage:best-block-hash cs))
            (prev (bitcoin-lisp.storage:make-block-index-entry
                   :hash genesis :height 0 :chain-work 1 :status :valid)))
       (bitcoin-lisp.storage:add-block-index-entry cs prev)
       (let ((tip-height (+ bitcoin-lisp:+min-blocks-to-keep+ 40)))
         (loop for h from 1 to 3
               do (let* ((b (%ff-test-block (+ 100 h)))
                         (hash (bitcoin-lisp.storage:store-block store b :height h))
                         (entry (bitcoin-lisp.storage:make-block-index-entry
                                 :hash hash :height h :chain-work (1+ h)
                                 :status :valid :prev-entry prev)))
                    (bitcoin-lisp.storage:add-block-index-entry cs entry)
                    (setf prev entry)))
         (bitcoin-lisp.storage:update-chain-tip
          cs (bitcoin-lisp.storage:block-index-entry-hash prev) tip-height)
         (let ((path (merge-pathnames "blocks/blk00000.dat" dir))
               (bitcoin-lisp:*prune-target-mib* 550)
               (bitcoin-lisp:*prune-after-height* 0))
           (is-true (probe-file path))
           (setf (bitcoin-lisp.storage:block-store-total-bytes store)
                 (* 600 1024 1024))
           ;; An index at height 1 protects everything from 1 - 10 - 1 = -10
           ;; upward, floored at 1 — so nothing at all may be pruned.
           (bitcoin-lisp.storage:register-prune-lock "slowindex" (lambda () 1))
           (is (= 0 (bitcoin-lisp.storage:prune-old-blocks store cs))
               "a lagging index must hold the whole prune off")
           (is-true (probe-file path) "the blk file must survive the lock")
           ;; And the HORIZON must not move either. It used to: the legacy
           ;; per-block walk ran over the same heights, PRUNE-BLOCK refused
           ;; each one for being in a flat file, and the walk advanced
           ;; PRUNED-HEIGHT anyway — which both claims a prune that never
           ;; happened and pushes the walk start past the file's first height,
           ;; after which %PRUNABLE-FLAT-FILES never offers the file again and
           ;; the node stops reclaiming space permanently.
           (is (= 0 (bitcoin-lisp.storage::chain-state-pruned-height cs))
               "the prune horizon must not advance over blocks still on disk")
           ;; The same call, with the lock gone, deletes it — which is what
           ;; proves the survival above came from the lock and not from some
           ;; unrelated refusal.
           (bitcoin-lisp.storage:clear-prune-locks)
           (is (= 3 (bitcoin-lisp.storage:prune-old-blocks store cs)))
           (is-false (probe-file path))))))))

(test prune-lock-stops-a-manual-prune-too
  "Core caps FindFilesToPruneManual by the same lock-limited last_prune
(validation.cpp:2740-2745), so pruneblockchain cannot step around an index
either."
  (%with-mainnet-network
   (%with-flat-dir (dir)
     (let* ((bitcoin-lisp.storage:*flat-block-files* t)
            (bitcoin-lisp.storage:*prune-locks*
              (make-hash-table :test 'equal :synchronized t))
            (store (bitcoin-lisp.storage:init-block-store dir))
            (cs (bitcoin-lisp.storage:init-chain-state dir))
            (genesis (bitcoin-lisp.storage:best-block-hash cs))
            (prev (bitcoin-lisp.storage:make-block-index-entry
                   :hash genesis :height 0 :chain-work 1 :status :valid)))
       (bitcoin-lisp.storage:add-block-index-entry cs prev)
       (let ((tip-height (+ bitcoin-lisp:+min-blocks-to-keep+ 40)))
         (loop for h from 1 to 3
               do (let* ((b (%ff-test-block (+ 150 h)))
                         (hash (bitcoin-lisp.storage:store-block store b :height h))
                         (entry (bitcoin-lisp.storage:make-block-index-entry
                                 :hash hash :height h :chain-work (1+ h)
                                 :status :valid :prev-entry prev)))
                    (bitcoin-lisp.storage:add-block-index-entry cs entry)
                    (setf prev entry)))
         (bitcoin-lisp.storage:update-chain-tip
          cs (bitcoin-lisp.storage:block-index-entry-hash prev) tip-height)
         (let ((path (merge-pathnames "blocks/blk00000.dat" dir))
               (bitcoin-lisp:*prune-target-mib* 1))   ; manual-only mode
           (bitcoin-lisp.storage:register-prune-lock "slowindex" (lambda () 1))
           (is (= 0 (bitcoin-lisp.storage:prune-blocks-to-height store cs 100))
               "pruneblockchain must respect the lock as well")
           (is-true (probe-file path))
           (bitcoin-lisp.storage:clear-prune-locks)
           (is (= 3 (bitcoin-lisp.storage:prune-blocks-to-height store cs 100)))
           (is-false (probe-file path))))))))

;;;; --- reading blocks out of an external file (Core -loadblock) ---

(defun %ff-external-file (dir records &key (junk 0))
  "Write RECORDS (serialized blocks) into a bootstrap-style file under DIR,
each framed as Core frames them: magic, 4-byte LE size, block. JUNK bytes of
garbage are written first, to prove the reader hunts rather than assuming the
file starts on a record."
  (let ((path (merge-pathnames "bootstrap.dat" dir))
        (magic (bitcoin-lisp.storage::block-network-magic)))
    (with-open-file (out path :direction :output :element-type '(unsigned-byte 8)
                              :if-exists :supersede :if-does-not-exist :create)
      (dotimes (i junk) (write-byte (mod (+ 17 i) 256) out))
      (dolist (bytes records)
        (write-sequence magic out)
        (let ((n (length bytes)))
          (write-byte (ldb (byte 8 0) n) out)
          (write-byte (ldb (byte 8 8) n) out)
          (write-byte (ldb (byte 8 16) n) out)
          (write-byte (ldb (byte 8 24) n) out))
        (write-sequence bytes out)))
    path))

(test external-block-file-reads-every-record
  "The framing Core's contrib/linearize writes into bootstrap.dat, which is the
same framing a blk file uses minus the XOR."
  (%with-mainnet-network
   (%with-flat-dir (dir)
     (let* ((blocks (loop for h from 1 to 3
                          collect (bitcoin-lisp.serialization:serialize-witness-block
                                   (%ff-test-block (+ 30 h)))))
            (path (%ff-external-file dir blocks))
            (seen '()))
       (is (= 3 (bitcoin-lisp.storage:map-external-block-file
                 path (lambda (b) (push b seen)))))
       (is (= 3 (length seen)))
       (is (equalp (first blocks) (first (last seen))))))))

(test external-block-file-hunts-past-junk
  "Leading garbage must not cost the file: Core scans for the magic a byte at a
time so a partially-downloaded or concatenated bootstrap.dat still yields every
whole record in it."
  (%with-mainnet-network
   (%with-flat-dir (dir)
     (let* ((blocks (loop for h from 1 to 2
                          collect (bitcoin-lisp.serialization:serialize-witness-block
                                   (%ff-test-block (+ 60 h)))))
            (path (%ff-external-file dir blocks :junk 37))
            (count 0))
       (is (= 2 (bitcoin-lisp.storage:map-external-block-file
                 path (lambda (b) (declare (ignore b)) (incf count)))))
       (is (= 2 count))))))

(test external-block-file-stops-at-a-truncated-record
  "A record whose length runs past the end of the file is not a record. Core
treats it as a coincidence in the data and keeps hunting, which is what lets a
half-downloaded file still deliver the blocks that ARE complete."
  (%with-mainnet-network
   (%with-flat-dir (dir)
     (let* ((blocks (loop for h from 1 to 2
                          collect (bitcoin-lisp.serialization:serialize-witness-block
                                   (%ff-test-block (+ 90 h)))))
            (path (%ff-external-file dir blocks)))
       ;; Chop the last record in half.
       (let ((all (with-open-file (in path :element-type '(unsigned-byte 8))
                    (let ((b (make-array (file-length in)
                                         :element-type '(unsigned-byte 8))))
                      (read-sequence b in) b))))
         (with-open-file (out path :direction :output :element-type '(unsigned-byte 8)
                                   :if-exists :supersede)
           (write-sequence all out :end (- (length all) 20))))
       (let ((count 0))
         (bitcoin-lisp.storage:map-external-block-file
          path (lambda (b) (declare (ignore b)) (incf count)))
         (is (= 1 count) "the complete record survives a truncated one after it"))))))

(test external-block-file-that-does-not-exist-reads-nothing
  "Core warns and moves on to the next -loadblock rather than refusing to
start (blockstorage.cpp:1306)."
  (%with-mainnet-network
   (%with-flat-dir (dir)
     (is (= 0 (bitcoin-lisp.storage:map-external-block-file
               (merge-pathnames "no-such-file.dat" dir)
               (lambda (b) (declare (ignore b)) (error "must not be called"))))))))
