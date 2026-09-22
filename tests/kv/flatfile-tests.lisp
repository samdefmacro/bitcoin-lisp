(in-package #:bitcoin-lisp.tests)

(def-suite :flatfile-tests
  :description "Flat-file storage engine (Core flatfile.{h,cpp}, obfuscation.h)"
  :in :bitcoin-lisp-tests)

(in-suite :flatfile-tests)

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
    (signals error (bl.store:obfuscate! data key :start 0 :end 17))
    (signals error (bl.store:obfuscate! data key :start 9 :end 4))
    (signals error (bl.store:obfuscate! data key :start -1 :end 4))
    ;; A short key is refused rather than read past its end. It must be
    ;; NON-ZERO: an all-zero key is inactive and short-circuits before any
    ;; check, which is the documented no-op contract and is why the first
    ;; version of this assertion did not fire.
    (signals error (bl.store:obfuscate!
                    data (make-array 4 :element-type '(unsigned-byte 8)
                                       :initial-element 9)))
    ;; An INACTIVE (all-zero) key is a no-op and must not signal even for a
    ;; range that would be invalid — it never touches the vector at all.
    (is (eq data (bl.store:obfuscate! data inactive :start 0 :end 17)))
    ;; And the ordinary path still round-trips, at every key alignment.
    (dotimes (offset 8)
      (let ((copy (copy-seq data)))
        (bl.store:obfuscate! copy key :key-offset offset)
        (is (not (equalp copy data)) "offset ~D did not change the data" offset)
        (bl.store:obfuscate! copy key :key-offset offset)
        (is (equalp copy data) "offset ~D did not round-trip" offset)))))

(test obfuscation-is-keyed-on-the-file-offset-mod-eight
  "plain[i] = disk[i] XOR key[(file_offset + i) mod 8]. Core reaches this
through a table of eight pre-rotated keys and a word-at-a-time XOR; the
identity is the format, the table is a speed trick. The case that distinguishes
a correct implementation from one that restarts the key at every call is a
buffer written at a non-zero, non-multiple-of-8 offset."
  (let ((key (%ff-bytes 1 2 3 4 5 6 7 8))
        (data (make-array 10 :element-type '(unsigned-byte 8) :initial-element 0)))
    (bl.store:obfuscate! data key :key-offset 3)
    ;; Byte 0 of the buffer sits at file offset 3, so it meets key byte 3.
    (is (equalp (%ff-bytes 4 5 6 7 8 1 2 3 4 5) data))))

(test obfuscation-is-its-own-inverse-at-any-offset
  (let ((key (%ff-bytes #xF1 #x23 #x45 #x67 #x89 #xAB #xCD #xEF)))
    (dolist (offset '(0 1 7 8 9 63 64 65 1000))
      (let* ((original (map '(vector (unsigned-byte 8)) (lambda (i) (mod (* i 37) 256))
                            (loop for i below 40 collect i)))
             (data (copy-seq original)))
        (bl.store:obfuscate! data key :key-offset offset)
        (is (not (equalp original data)) "an active key must actually change the bytes")
        (bl.store:obfuscate! data key :key-offset offset)
        (is (equalp original data))))))

(test obfuscation-splits-across-calls-exactly-as-across-one
  "Writing a record in two pieces must produce the same bytes as writing it in
one, or a buffered writer would corrupt every record it happened to split."
  (let* ((key (%ff-bytes 9 8 7 6 5 4 3 2))
         (whole (map '(vector (unsigned-byte 8)) (lambda (i) (mod (* i 11) 256))
                     (loop for i below 30 collect i)))
         (split (copy-seq whole)))
    (bl.store:obfuscate! whole key :key-offset 5)
    ;; Same data, same starting offset, but XORed in two calls.
    (bl.store:obfuscate! split key :key-offset 5 :start 0 :end 13)
    (bl.store:obfuscate! split key :key-offset (+ 5 13) :start 13)
    (is (equalp whole split))))

(test the-zero-key-means-no-obfuscation
  "Core treats an all-zero key as inactive (Obfuscation::operator bool), which
is what a blocksdir written before obfuscation existed gets — so its data stays
readable byte for byte."
  (let ((key (bl.store:zero-obfuscation-key))
        (data (%ff-bytes 1 2 3 4 5)))
    (is-false (bl.store:obfuscation-key-active-p key))
    (bl.store:obfuscate! data key :key-offset 3)
    (is (equalp (%ff-bytes 1 2 3 4 5) data))))

;;; --- xor.dat lifecycle ------------------------------------------------------

(test xor-key-is-created-only-for-a-fresh-blocksdir
  "Core generates a key only when the blocksdir is new, and a pre-existing
xor.dat always wins (blockstorage.cpp:1167-1222). Turning obfuscation on for a
directory that already holds plaintext would make every existing byte
unreadable, which is why the second case here matters more than the first."
  (with-temp-directory (dir)
    (let ((key (bl.store:read-or-create-xor-key dir)))
      (is-true (bl.store:obfuscation-key-active-p key))
      (is (probe-file (merge-pathnames "xor.dat" dir)))
      ;; Second call returns the same key, not a new one.
      (is (equalp key (bl.store:read-or-create-xor-key dir)))))
  ;; A directory that already holds block data gets the INACTIVE key — and the
  ;; file is still written. Core creates xor.dat whenever it is missing,
  ;; whatever key it chose (blockstorage.cpp:1195-1206); its presence holding
  ;; zeros is what records that obfuscation was considered and declined here.
  (with-temp-directory (dir)
    (with-open-file (s (merge-pathnames "blk00000.dat" dir)
                       :direction :output :element-type '(unsigned-byte 8))
      (write-sequence (%ff-bytes 1 2 3) s))
    (let ((key (bl.store:read-or-create-xor-key dir)))
      (is-false (bl.store:obfuscation-key-active-p key))
      (is-true (probe-file (merge-pathnames "xor.dat" dir))))))

(test a-blocksdir-that-already-holds-blocks-is-not-a-first-run
  "Core's first-run test is \"the blocksdir holds only hidden files\"
(blockstorage.cpp:1173-1183), so a directory that already has block data — in
EITHER form — gets the null key rather than a random one. Reaching this state
means an older node wrote blocks before xor.dat existed; generating a key now
would make every one of them unreadable."
  (dolist (name '("blk00000.dat" "rev00000.dat"
                  "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff.blk"))
    (with-temp-directory (dir)
      (with-open-file (s (merge-pathnames name dir)
                         :direction :output :element-type '(unsigned-byte 8))
        (write-sequence (%ff-bytes 1 2 3) s))
      (let ((key (bl.store:read-or-create-xor-key dir)))
        (is-false (bl.store:obfuscation-key-active-p key)
                  "~A in the blocksdir must prevent a random key" name)
        (is-true (probe-file (merge-pathnames "xor.dat" dir))
                 "the null key is still written to disk"))))
  ;; And a genuinely fresh one does get a random key.
  (with-temp-directory (dir)
    (is-true (bl.store:obfuscation-key-active-p
              (bl.store:read-or-create-xor-key dir)))))

(test blocksxor-zero-over-a-stored-random-key-is-refused
  "Core refuses rather than honouring -blocksxor=0 on a blocksdir that already
has a random key (blockstorage.cpp:1213-1219): reading those files without the
key returns garbage, and a node that started anyway would conclude its whole
block store was corrupt. Now that a fresh datadir gets a key by default, this
is the ordinary way an operator meets it."
  (with-network (:mainnet)
   (with-temp-directory (dir)
     (let* ((bl.store:*flat-block-files* t)
            (store (bl.store:init-block-store dir)))
       (is-true (bl.store:obfuscation-key-active-p
                 (bl.store::block-store-xor-key store))))
     (let ((bl.store:*blocks-xor* nil))
       (signals error (bl.store:init-block-store dir)))
     ;; With the key gone it is allowed again, and the null key is recorded —
     ;; which is exactly what feature_blocksxor.py deletes and then checks for.
     (delete-file (merge-pathnames "blocks/xor.dat" dir))
     (let* ((bl.store:*blocks-xor* nil)
            (store (bl.store:init-block-store dir)))
       (is-false (bl.store:obfuscation-key-active-p
                  (bl.store::block-store-xor-key store)))
       (is-true (probe-file (merge-pathnames "blocks/xor.dat" dir)))))))

(test a-wrong-sized-xor-key-is-refused
  "Reading a truncated key and padding it would silently decrypt every block
wrongly, so the size is a hard error."
  (with-temp-directory (dir)
    (with-open-file (s (merge-pathnames "xor.dat" dir)
                       :direction :output :element-type '(unsigned-byte 8))
      (write-sequence (%ff-bytes 1 2 3) s))
    (signals error (bl.store:read-or-create-xor-key dir)))
  (with-temp-directory (dir)
    (with-open-file (s (merge-pathnames "xor.dat" dir)
                       :direction :output :element-type '(unsigned-byte 8))
      (write-sequence (%ff-bytes 1 2 3 4 5 6 7 8 9) s))
    (signals error (bl.store:read-or-create-xor-key dir))))

;;; --- FlatFileSeq ------------------------------------------------------------

(test flat-file-names-are-core-s
  "blk00000.dat / rev00007.dat: five zero-padded digits (FlatFileSeq::FileName)."
  (with-temp-directory (dir)
    (let ((blk (bl.store:make-flat-file-seq dir "blk" 1024))
          (rev (bl.store:make-flat-file-seq dir "rev" 1024)))
      (is (string= "blk00000.dat"
                   (file-namestring (bl.store:flat-file-name
                                     blk (bl.store:make-flat-file-pos 0 0)))))
      (is (string= "rev00007.dat"
                   (file-namestring (bl.store:flat-file-name
                                     rev (bl.store:make-flat-file-pos 7 999)))))
      (is (string= "blk12345.dat"
                   (file-namestring (bl.store:flat-file-name
                                     blk (bl.store:make-flat-file-pos 12345 0))))))))

(test allocation-rounds-up-to-whole-chunks
  "Core allocates in multiples of the sequence chunk size, and does nothing when
the request already fits inside the chunks already allocated."
  (with-temp-directory (dir)
    (let ((seq (bl.store:make-flat-file-seq dir "blk" 1024))
          (pos (bl.store:make-flat-file-pos 0 0)))
      ;; 100 bytes at offset 0 => one 1024-byte chunk.
      (is (= 1024 (bl.store:flat-file-allocate seq pos 100)))
      (is (= 1024 (length (%ff-read-file (bl.store:flat-file-name seq pos)))))
      ;; Another 100 bytes still inside that chunk => no growth.
      (let ((pos2 (bl.store:make-flat-file-pos 0 100)))
        (is (= 0 (bl.store:flat-file-allocate seq pos2 100)))
        (is (= 1024 (length (%ff-read-file (bl.store:flat-file-name seq pos))))))
      ;; A request that crosses the boundary grows to the next multiple.
      (let ((pos3 (bl.store:make-flat-file-pos 0 1000)))
        (is (= 1048 (bl.store:flat-file-allocate seq pos3 100)))
        (is (= 2048 (length (%ff-read-file (bl.store:flat-file-name seq pos)))))))))

(test finalize-truncates-the-preallocated-tail
  "The point of the finalize flag: a rolled-over block file must not keep the
zeros it preallocated, or every full file would carry up to a chunk of padding
forever."
  (with-temp-directory (dir)
    (let* ((seq (bl.store:make-flat-file-seq dir "blk" 1024))
           (pos (bl.store:make-flat-file-pos 0 0))
           (path (bl.store:flat-file-name seq pos)))
      (bl.store:flat-file-allocate seq pos 100)
      (with-open-file (s path :direction :io :element-type '(unsigned-byte 8)
                              :if-exists :overwrite)
        (write-sequence (%ff-bytes 7 7 7 7 7) s))
      (is (= 1024 (length (%ff-read-file path))))
      ;; A non-final flush leaves the preallocation alone.
      (bl.store:flat-file-flush
       seq (bl.store:make-flat-file-pos 0 5))
      (is (= 1024 (length (%ff-read-file path))))
      ;; Finalizing cuts it back to the written length.
      (bl.store:flat-file-flush
       seq (bl.store:make-flat-file-pos 0 5) :finalize t)
      (is (equalp (%ff-bytes 7 7 7 7 7) (%ff-read-file path))))))

;;; --- Record framing ---------------------------------------------------------

(test record-framing-is-magic-then-little-endian-length
  "Core's 8-byte storage header (STORAGE_HEADER_BYTES): 4-byte network magic,
then the payload length as a little-endian uint32."
  (let* ((magic (%ff-bytes #xF9 #xBE #xB4 #xD9))
         (payload (%ff-bytes 1 2 3))
         (record (bl.store:flat-record-bytes magic payload)))
    (is (= 11 (length record)))
    (is (equalp (%ff-bytes #xF9 #xBE #xB4 #xD9 3 0 0 0 1 2 3) record))
    (multiple-value-bind (found-magic length)
        (bl.store:parse-flat-record-header record)
      (is (equalp magic found-magic))
      (is (= 3 length))))
  ;; A length that needs all four bytes, so a byte-order slip cannot hide.
  (let* ((magic (%ff-bytes 1 2 3 4))
         (record (bl.store:flat-record-bytes
                  magic (make-array #x01020304 :element-type '(unsigned-byte 8)
                                               :initial-element 0))))
    (is (equalp (%ff-bytes 4 3 2 1) (subseq record 4 8)))
    (is (= #x01020304 (nth-value 1 (bl.store:parse-flat-record-header record))))))

(test undo-checksum-binds-the-previous-block-hash
  "Core hashes the PREVIOUS block's hash together with the undo data
(blockstorage.cpp:996-999). Without that, a rev record would verify against any
block; with it, a record moved or mismatched fails."
  (let ((undo (%ff-bytes 1 2 3 4 5))
        (prev-a (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xAA))
        (prev-b (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xBB)))
    (let ((sum-a (bl.store:undo-record-checksum prev-a undo))
          (sum-b (bl.store:undo-record-checksum prev-b undo)))
      (is (= 32 (length sum-a)))
      (is (not (equalp sum-a sum-b))
          "a different previous block must give a different checksum")
      ;; It is exactly SHA256d over the concatenation, nothing else.
      (is (equalp sum-a
                  (bl.crypto:hash256
                   (concatenate '(vector (unsigned-byte 8)) prev-a undo)))))))

(test undo-record-is-header-payload-checksum
  "Layout, and the overhead constant that sizes the allocation for it."
  (let* ((magic (%ff-bytes #xF9 #xBE #xB4 #xD9))
         (undo (%ff-bytes 9 9 9))
         (prev (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
         (record (bl.store:undo-record-bytes magic prev undo)))
    (is (= (+ (length undo) bl.store:+undo-data-disk-overhead+)
           (length record)))
    (is (equalp magic (subseq record 0 4)))
    (is (equalp undo (subseq record 8 11)))
    (is (equalp (bl.store:undo-record-checksum prev undo)
                (subseq record 11)))))

;;; --- The magic hunt ---------------------------------------------------------

(test the-reader-resyncs-to-the-next-magic-through-garbage
  "What makes a full -reindex possible: a block file can contain a torn write,
a preallocated zero tail, or another network's data, so Core's
LoadExternalBlockFile scans byte-wise for the next magic rather than giving up
(validation.cpp:4988-5155)."
  (let* ((magic (%ff-bytes #xF9 #xBE #xB4 #xD9))
         (payload (%ff-bytes 11 22 33))
         (record (bl.store:flat-record-bytes magic payload))
         (stream (concatenate '(vector (unsigned-byte 8))
                              ;; leading junk, including three of the four
                              ;; magic bytes so a naive scanner mis-syncs
                              (%ff-bytes 0 0 #xF9 #xBE #xB4 0 7 7)
                              record
                              ;; trailing zeros, i.e. unwritten preallocation
                              (make-array 16 :element-type '(unsigned-byte 8)
                                             :initial-element 0))))
    (multiple-value-bind (start length) (bl.store:find-next-record stream magic)
      (is (= 3 length))
      (is (equalp payload (subseq stream start (+ start length)))))
    ;; Nothing to find once past it.
    (is-false (bl.store:find-next-record
               stream magic :start (+ 8 (length record))))
    ;; A header whose length runs past the end of the data is not a record.
    (let ((truncated (subseq stream 0 (+ 8 8 2))))
      (is-false (bl.store:find-next-record truncated magic)))))

(test obfuscated-records-round-trip-through-a-file
  "The combination P2 will actually use: frame a record, obfuscate it at its
file offset, write it, read it back, de-obfuscate, and get the payload."
  (with-temp-directory (dir)
    (let* ((key (bl.store:read-or-create-xor-key dir))
           (seq (bl.store:make-flat-file-seq dir "blk" 1024))
           (magic (%ff-bytes #xF9 #xBE #xB4 #xD9))
           (first-payload (%ff-bytes 1 2 3 4 5))
           (second-payload (%ff-bytes 6 7 8))
           (r1 (bl.store:flat-record-bytes magic first-payload))
           (r2 (bl.store:flat-record-bytes magic second-payload))
           (pos (bl.store:make-flat-file-pos 0 0))
           (path (bl.store:flat-file-name seq pos)))
      ;; Written at their real file offsets, which differ — the second record's
      ;; key alignment depends on the first record's length.
      (let ((d1 (bl.store:obfuscate! (copy-seq r1) key :key-offset 0))
            (d2 (bl.store:obfuscate! (copy-seq r2) key
                                                 :key-offset (length r1))))
        (with-open-file (s path :direction :output :element-type '(unsigned-byte 8)
                                :if-exists :supersede :if-does-not-exist :create)
          (write-sequence d1 s)
          (write-sequence d2 s)))
      (let ((raw (%ff-read-file path)))
        ;; On disk it is not plaintext.
        (is (not (equalp magic (subseq raw 0 4))))
        (let ((plain (bl.store:obfuscate! (copy-seq raw) key :key-offset 0)))
          (is (equalp r1 (subseq plain 0 (length r1))))
          (is (equalp r2 (subseq plain (length r1))))
          (multiple-value-bind (start length)
              (bl.store:find-next-record plain magic :start (length r1))
            (is (equalp second-payload (subseq plain start (+ start length))))))))))

;;; --- The block store on top of it -------------------------------------------

(defun %ff-unlabelled (block)
  "BLOCK with the reorg fixture's cached-hash LABEL cleared, so the real hash
stands. Every fixture here needs it: a flat file holds bytes, and both the
startup scan and a rebuilt index recover a block's identity by hashing the 80
header bytes they find, which is what production data always has."
  (setf (bl.ser:block-header-cached-hash
         (bl.ser:bitcoin-block-header block))
        nil)
  block)

(defun %ff-test-block (seed)
  "A small but real block, so the store's own serializer and deserializer are
what round-trips. SEED is a byte; %FF-NUMBERED-BLOCK covers a wider range."
  (%ff-unlabelled
   (make-reorg-test-block
    (make-array 32 :element-type '(unsigned-byte 8) :initial-element seed)
    (make-array 32 :element-type '(unsigned-byte 8) :initial-element (1+ seed))
    1)))

(defmacro %with-flat-store ((store dir &key (flat t)) &body body)
  `(with-temp-directory (,dir)
     (let* ((bl.store:*flat-block-files* ,flat)
            (,store (bl.store:init-block-store ,dir)))
       ,@body)))

(test flat-store-round-trips-a-block-through-a-blk-file
  "Written into blk00000.dat, obfuscated, and read back — through the ordinary
STORE-BLOCK / GET-BLOCK API, which does not change."
  (with-network (:mainnet)
   (%with-flat-store (store dir)
     (let* ((block (%ff-test-block 40))
            (hash (bl.store:store-block store block)))
       (is (probe-file (merge-pathnames "blocks/blk00000.dat" dir)))
       (is-true (bl.store:block-exists-p store hash))
       (let ((back (bl.store:get-block store hash)))
         (is-true back)
         (is (equalp hash (bl.ser:block-header-hash
                           (bl.ser:bitcoin-block-header back)))))
       ;; And the position reported is Core's: past the 8-byte header.
       (multiple-value-bind (h pos) (bl.store:store-block store (%ff-test-block 50))
         (declare (ignore h))
         (is (typep pos 'bl.kv:flat-file-pos))
         (is (plusp (bl.store:flat-file-pos-pos pos))))))))

(test flat-store-survives-a-restart-by-scanning-its-files
  "A blk file is self-describing: reopening the store rebuilds the hash ->
position map by walking the records, so nothing outside the file is needed to
find a block again. This is most of what a full -reindex does."
  (with-network (:mainnet)
   (with-temp-directory (dir)
     (let ((hashes '()))
       (let* ((bl.store:*flat-block-files* t)
              (store (bl.store:init-block-store dir)))
         (dolist (seed '(60 70 80))
           (push (bl.store:store-block store (%ff-test-block seed)) hashes)))
       ;; A fresh store over the same directory.
       (let* ((bl.store:*flat-block-files* t)
              (store2 (bl.store:init-block-store dir)))
         (dolist (h hashes)
           (is-true (bl.store:block-exists-p store2 h))
           (is-true (bl.store:get-block store2 h)))
         ;; The cursor resumed at the end, so the next block appends rather
         ;; than overwriting the last one.
         (let ((extra (bl.store:store-block store2 (%ff-test-block 90))))
           (is-true (bl.store:get-block store2 extra))
           (dolist (h hashes)
             (is-true (bl.store:get-block store2 h)
                      "an append must not have landed on top of an existing record"))))))))

(defun %ff-numbered-block (n)
  "A test block unique in N for any N below 2^24, so a few hundred of them fit
in one store. %FF-TEST-BLOCK's byte seed runs out at 256."
  (flet ((label (m)
           (let ((a (make-array 32 :element-type '(unsigned-byte 8)
                                   :initial-element 0)))
             (setf (aref a 0) (ldb (byte 8 0) m)
                   (aref a 1) (ldb (byte 8 8) m)
                   (aref a 2) (ldb (byte 8 16) m))
             a)))
    (%ff-unlabelled (make-reorg-test-block (label 0) (label n) n))))

(defun %ff-fill-two-blk-files (store)
  "Store blocks into STORE until it has rolled over into blk00001.dat, under
-fastprune's 64 KiB file cap -- Core's own way of producing several block files
without mining a real chain. Returns the hashes that landed above file 0.
500 blocks of about 180 bytes each clear the cap with room to spare."
  (let ((survivors '()))
    (loop for n from 1 to 500
          do (multiple-value-bind (hash pos)
                 (bl.store:store-block store (%ff-numbered-block n) :height n)
               (when (and (bl.kv:flat-file-pos-p pos)
                          (plusp (bl.store:flat-file-pos-file pos)))
                 (push hash survivors))))
    (nreverse survivors)))

(test a-prune-hole-in-the-blk-numbering-keeps-the-later-files-addressable
  "Pruning deletes the lowest-numbered blk/rev pair first, so the blk numbering
has holes -- and the restart scan used to count from 0 and stop at the first
name that was not there, which after the first prune is blk00000.dat. Every
block in the surviving files then vanished from the index: unservable to peers,
unreadable for undo and reorg, invisible to the coinbase-probe crash recovery;
BLOCK-STORE-TOTAL-BYTES read 0 so automatic pruning stopped; and the write
cursor rewound to (0, 0), so a later rollover would open a live higher-numbered
file at offset 0 with :IF-EXISTS :OVERWRITE.

Core never has the problem: LoadBlockIndexGuts restores nFile/nDataPos from the
block-index database and it scans blk files only under -reindex
(node/blockstorage.cpp:120-145). Re-deriving the map by walking is the same
thing by another route, but only if the walk ENUMERATES what is on disk --
which is what %SCAN-FLAT-UNDO-FILES was already doing next door."
  (with-network (:mainnet)
   (with-temp-directory (dir)
     (let ((survivors '()))
       (let* ((bl.store:*flat-block-files* t)
              (bl.store:*fast-prune* t)
              (store (bl.store:init-block-store dir)))
         (setf survivors (%ff-fill-two-blk-files store)))
       (is-true (probe-file (merge-pathnames "blocks/blk00001.dat" dir))
                "the fixture must actually have rolled over to a second file")
       (is (plusp (length survivors))
           "the fixture must have put blocks above file 0")
       ;; Exactly what an automatic prune leaves behind.
       (delete-file (merge-pathnames "blocks/blk00000.dat" dir))
       (let* ((bl.store:*flat-block-files* t)
              (bl.store:*fast-prune* t)
              (store2 (bl.store:init-block-store dir)))
         (dolist (h survivors)
           (is-true (bl.store:block-exists-p store2 h)
                    "a block in a surviving file is missing from the index")
           (is-true (bl.store:get-block store2 h)
                    "a block in a surviving file cannot be read back"))
         (is (plusp (bl.store:block-store-total-bytes store2))
             "the byte total must account for the surviving files, or ~
              automatic pruning stops")
         ;; The cursor resumed past the last surviving record rather than
         ;; rewinding to (0, 0): the next append must not land on live data.
         (let ((extra (bl.store:store-block store2 (%ff-numbered-block 9999)
                                            :height 9999)))
           (is-true (bl.store:get-block store2 extra))
           (dolist (h survivors)
             (is-true (bl.store:get-block store2 h)
                      "an append overwrote a record in a surviving file"))))))))

(test the-store-reads-both-forms-at-once
  "Dual read, which is what makes the transition survivable: blocks written
before the flat files stay readable after the switch, and blocks written after
it stay readable if the flag is turned back off."
  (with-network (:mainnet)
   (with-temp-directory (dir)
     (let (legacy-hash flat-hash)
       ;; One block the old way.
       (let* ((bl.store:*flat-block-files* nil)
              (store (bl.store:init-block-store dir)))
         (setf legacy-hash (bl.store:store-block store (%ff-test-block 100))))
       ;; One the new way, same directory.
       (let* ((bl.store:*flat-block-files* t)
              (store (bl.store:init-block-store dir)))
         (setf flat-hash (bl.store:store-block store (%ff-test-block 110)))
         (is-true (bl.store:get-block store legacy-hash)
                  "the pre-existing per-block file must still be readable"))
       ;; Flag off again: both still resolve.
       (let* ((bl.store:*flat-block-files* nil)
              (store (bl.store:init-block-store dir)))
         (is-true (bl.store:get-block store legacy-hash))
         (is-true (bl.store:get-block store flat-hash)
                  "a flat record must stay readable with the flag off"))))))

(test a-blocksdir-with-flat-records-never-acquires-a-key
  "A key is created only when there is no FLAT data yet. Legacy per-block files
are read without the obfuscation layer, so they neither need nor forbid one —
but an existing blk?????.dat written without a key must never acquire one, or
every record already in it becomes unreadable."
  (with-network (:mainnet)
   ;; Fresh: obfuscated, and the magic is not visible on disk.
   (%with-flat-store (store dir)
     (bl.store:store-block store (%ff-test-block 120))
     (let ((raw (%ff-read-file (merge-pathnames "blocks/blk00000.dat" dir))))
       (is (not (equalp (bl:network-magic :mainnet) (subseq raw 0 4)))
           "a fresh blocksdir writes obfuscated records")))
   ;; Flat records written with no key: a later start must not create one.
   (with-temp-directory (dir)
     (let (first-hash)
       (let* ((bl.store:*flat-block-files* t)
              (store (bl.store:init-block-store dir)))
         ;; Force the unobfuscated case the way an older node would have left
         ;; it: no xor.dat, so the key is inactive.
         (setf (bl.store::block-store-xor-key store)
               (bl.store:zero-obfuscation-key))
         (ignore-errors (delete-file (merge-pathnames "blocks/xor.dat" dir)))
         (setf first-hash (bl.store:store-block store (%ff-test-block 130)))
         (let ((raw (%ff-read-file (merge-pathnames "blocks/blk00000.dat" dir))))
           (is (equalp (bl:network-magic :mainnet) (subseq raw 0 4)))))
       ;; Reopening must not generate an ACTIVE key, or the record above is
       ;; lost. Core does write the file — holding zeros — which changes
       ;; nothing about how the existing record reads.
       (let* ((bl.store:*flat-block-files* t)
              (store (bl.store:init-block-store dir)))
         (is-false (bl.store:obfuscation-key-active-p
                    (bl.store::block-store-xor-key store)))
         (is-true (bl.store:get-block store first-hash)
                  "the unobfuscated record must still be readable"))))
   ;; Legacy and flat records coexisting under one key. The key here is the
   ;; RANDOM one: the directory was empty when the store first opened, so that
   ;; start was a first run and Core would have generated one too — the key is
   ;; chosen before any block exists, not after. What matters is that adding
   ;; flat records later does not disturb the legacy file, and that both forms
   ;; still read back.
   (with-temp-directory (dir)
     (let (legacy)
       (let* ((bl.store:*flat-block-files* nil)
              (store (bl.store:init-block-store dir)))
         (setf legacy (bl.store:store-block store (%ff-test-block 135))))
       (let* ((bl.store:*flat-block-files* t)
              (store (bl.store:init-block-store dir))
              (flat (bl.store:store-block store (%ff-test-block 140))))
         (is-true (probe-file (merge-pathnames "blocks/xor.dat" dir)))
         (is-true (bl.store:get-block store legacy))
         (is-true (bl.store:get-block store flat)))))))

(test pruning-refuses-a-flat-stored-block-rather-than-failing-quietly
  "Per-block pruning cannot cut a record out of a flat file — that is P3. The
refusal has to be visible: returning NIL is how the caller says `already gone',
so a silent NIL would let a pruned node stop reclaiming space without a word.
This is also why the flag is off by default."
  (with-network (:mainnet)
   (%with-flat-store (store dir)
     (declare (ignorable dir))
     (let ((hash (bl.store:store-block store (%ff-test-block 150))))
       (is-false (bl.store:prune-block store hash))
       (is-true (bl.store:get-block store hash)
                "and the block is still there, not half-removed")))))

;;; --- File-granular pruning (P3) ---------------------------------------------

(test a-flat-file-is-prunable-only-when-its-whole-range-is
  "Pruning a flat file is all or nothing, so the test is on the file's ENTIRE
height range, not on individual blocks. A file holding one block above the
window keeps the whole file — which is the trade the format makes, and the
reason Core's unit is the file."
  (with-network (:mainnet)
   (%with-flat-store (store dir)
     (declare (ignorable dir))
     ;; File 0 gets heights 10..12, and (pretending it rolled over) file 1
     ;; gets 20..22 by hand.
     (dolist (h '(10 11 12))
       (bl.store:store-block store (%ff-test-block (+ 160 h)) :height h))
     (let ((info (gethash 0 (bl.store:block-store-file-info store))))
       (is (= 3 (bl.store:block-file-info-blocks info)))
       (is (= 10 (bl.store:block-file-info-height-first info)))
       (is (= 12 (bl.store:block-file-info-height-last info))))
     ;; Entirely inside the window: prunable.
     (is (equal '(0) (bl.store::%prunable-flat-files store 5 20)))
     ;; The window ends one block too early: the file stays whole.
     (is (null (bl.store::%prunable-flat-files store 5 11)))
     ;; The window starts one block too late: likewise.
     (is (null (bl.store::%prunable-flat-files store 11 20))))))

(test a-block-stored-without-a-height-makes-its-file-unprunable
  "The safe direction. A file whose range is unknown can never be SHOWN to lie
inside the window, so it is never deleted — the alternative is dropping a block
the chain still needs. Storing without a height still stores the block."
  (with-network (:mainnet)
   (%with-flat-store (store dir)
     (declare (ignorable dir))
     (let ((hash (bl.store:store-block store (%ff-test-block 170))))
       (is-true (bl.store:get-block store hash))
       (let ((info (gethash 0 (bl.store:block-store-file-info store))))
         (is (= 1 (bl.store:block-file-info-blocks info)))
         (is (null (bl.store:block-file-info-height-first info))))
       (is (null (bl.store::%prunable-flat-files store 0 1000000)))))))

(test pruning-a-flat-file-removes-both-halves-and-forgets-its-blocks
  "The blk and rev files go together — a pruned node cannot reorg below its
window, so undo data there is dead weight — and every block in the file leaves
the index, so the download path can re-request it."
  (with-network (:mainnet)
   (%with-flat-store (store dir)
     (let ((hashes (loop for h from 30 to 32
                         collect (bl.store:store-block
                                  store (%ff-test-block (+ 180 h)) :height h))))
       ;; Give file 0 a rev half so the pair is real.
       (with-open-file (s (merge-pathnames "blocks/rev00000.dat" dir)
                          :direction :output :element-type '(unsigned-byte 8)
                          :if-exists :supersede :if-does-not-exist :create)
         (write-sequence (%ff-bytes 1 2 3 4) s))
       (let ((seen '()))
         (let ((freed (bl.store:prune-flat-block-file
                       store 0 :on-prune (lambda (h) (push h seen)))))
           (is (plusp freed))
           (is (= 3 (length seen)) "every block in the file must be reported"))
         (is-false (probe-file (merge-pathnames "blocks/blk00000.dat" dir)))
         (is-false (probe-file (merge-pathnames "blocks/rev00000.dat" dir))
                   "the rev half goes with the blk half")
         (dolist (h hashes)
           (is-false (bl.store:block-exists-p store h))
           (is-false (bl.store:get-block store h)))
         (is-false (gethash 0 (bl.store:block-store-file-info store))))))))

(test file-accounting-is-recovered-from-the-files-and-the-header-index
  "Neither half knows enough alone: the flat files know WHERE each block is,
the header index knows WHAT HEIGHT it is, and pruning needs both. Core persists
this in its block-index database; deriving it means there is no second file to
fall out of step."
  (with-network (:mainnet)
   (with-temp-directory (dir)
     (let ((blocks '()))
       ;; Store three blocks and record them in a chain state at known heights.
       (let* ((bl.store:*flat-block-files* t)
              (store (bl.store:init-block-store dir))
              (cs (bl.store:init-chain-state dir)))
         (loop for h from 40 to 42
               do (let* ((b (%ff-test-block (+ 190 h)))
                         (hash (bl.store:store-block store b :height h)))
                    (push (cons hash h) blocks)
                    (bl.store:add-block-index-entry
                     cs (bl.store:make-block-index-entry
                         :hash hash :height h :status :valid))))
         (bl.store:save-header-index cs))
       ;; A fresh store and chain state, as a restart would give.
       (let* ((bl.store:*flat-block-files* t)
              (store2 (bl.store:init-block-store dir))
              (cs2 (bl.store:init-chain-state dir)))
         (is-true (bl.store:load-header-index cs2))
         ;; Before the join, the store has positions but no heights.
         (is (null (bl.store::%prunable-flat-files store2 0 1000000)))
         (is (= 1 (bl.store:rebuild-block-file-info store2 cs2)))
         (let ((info (gethash 0 (bl.store:block-store-file-info store2))))
           (is (= 40 (bl.store:block-file-info-height-first info)))
           (is (= 42 (bl.store:block-file-info-height-last info)))
           (is (plusp (bl.store:block-file-info-size info))))
         (is (equal '(0) (bl.store::%prunable-flat-files store2 0 100))))))))

(test every-store-block-call-passes-a-height
  "A structural guard, for the same reason as the txindex one. A block stored
without its height silently makes its whole FILE unprunable, and a pruned node
that stops reclaiming space says nothing about it until the disk fills. There
are five call sites -- two in ACTIVATE-BLOCK collapsed onto
%STORE-ACCEPTED-BLOCK-BODY when Core's AcceptBlock gate landed in front of
them, and %REFETCH-PRUNED-BODY writes back the body of a block whose own file
was pruned (getblockfrompeer) -- and a sixth that forgets is how this returns."
  (let ((sites '()))
    (dolist (rel '("src/validation/block.lisp" "src/networking/ibd.lisp"))
      (let ((src (uiop:read-file-string
                  (merge-pathnames rel (asdf:system-source-directory :bitcoin-lisp)))))
        (loop with start = 0
              for pos = (search "bl.store:store-block" src :start2 start)
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
  (with-network (:mainnet)
   (with-temp-directory (dir)
     (let* ((bl.store:*flat-block-files* t)
            (store (bl.store:init-block-store dir))
            (cs (bl.store:init-chain-state dir))
            (genesis (bl.store:best-block-hash cs))
            (prev (bl.store:make-block-index-entry
                   :hash genesis :height 0 :chain-work 1 :status :valid)))
       (bl.store:add-block-index-entry cs prev)
       ;; A chain well above +min-blocks-to-keep+, so the early heights are
       ;; genuinely prunable.
       (let ((tip-height (+ bl:+min-blocks-to-keep+ 40)))
         (loop for h from 1 to 3
               do (let* ((b (%ff-test-block (+ 200 h)))
                         (hash (bl.store:store-block store b :height h))
                         (entry (bl.store:make-block-index-entry
                                 :hash hash :height h :chain-work (1+ h)
                                 :status :valid :prev-entry prev)))
                    (bl.store:add-block-index-entry cs entry)
                    (setf prev entry)))
         ;; Claim a far-ahead tip so the stored blocks are below the horizon.
         (bl.store:update-chain-tip
          cs (bl.store:block-index-entry-hash prev) tip-height)
         (is (probe-file (merge-pathnames "blocks/blk00000.dat" dir)))
         ;; 550 MiB is the smallest target that means AUTOMATIC pruning —
         ;; below it, -prune is manual-only and this path returns 0 without
         ;; looking at anything. The first draft of this test used 1 and
         ;; "passed" its zero-pruned assertion for that reason alone.
         (let ((bl:*prune-target-mib* 550)
               (bl:*prune-after-height* 0)
               (swept '()))
           ;; Storage is a few kilobytes, far under the target: nothing goes.
           (is (= 0 (bl.store:prune-old-blocks store cs)))
           (is (probe-file (merge-pathnames "blocks/blk00000.dat" dir)))
           ;; Claim usage above the target and the file must go, whole.
           (setf (bl.store:block-store-total-bytes store)
                 (* 600 1024 1024))
           (let ((pruned (bl.store:prune-old-blocks
                          store cs :on-prune (lambda (h) (push h swept)))))
             (is (= 3 pruned) "all three blocks in the file are pruned together")
             ;; At least three: the legacy per-block walk runs afterwards while
             ;; usage is still above target and re-reports the same heights.
             ;; That is harmless — on-prune is always delete-undo-file, which
             ;; is idempotent — and the exact per-file count is asserted
             ;; directly in the PRUNE-FLAT-BLOCK-FILE test above.
             (is (>= (length swept) 3) "each pruned block is reported for undo cleanup"))
           (is-false (probe-file (merge-pathnames "blocks/blk00000.dat" dir)))
           (is (= 3 (bl.store:chain-state-pruned-height cs))
               "the prune horizon advances to the file's last height")))))))

(test the-flat-prune-window-starts-at-genesis-as-cores-does
  "Core's GetPruneRange returns prune_start = 0 for an ordinary chainstate
(validation.cpp:6366-6379) and FindFilesToPrune skips a file only when
`nHeightFirst < min_block_to_prune' (node/blockstorage.cpp:386), so the file
holding genesis -- nHeightFirst 0 -- is prunable like any other once its whole
range is inside the window.

We passed the prune WALK cursor as the floor instead, read as `1+', so the
floor was 1 on a node that had never pruned and blk00000.dat failed the test
forever. Its height-first is 0 because ENSURE-GENESIS-ON-DISK writes genesis
into it, and the cursor only rises, so the pair was retained for the life of
the datadir while an equal volume of NEWER history was pruned in its place --
and its permanent presence is what shaped the restart-scan failure above."
  (with-network (:mainnet)
   (with-temp-directory (dir)
     (let* ((bl.store:*flat-block-files* t)
            (store (bl.store:init-block-store dir))
            (cs (bl.store:init-chain-state dir))
            (genesis (bl.store:best-block-hash cs))
            (prev (bl.store:make-block-index-entry
                   :hash genesis :height 0 :chain-work 1 :status :valid)))
       ;; Genesis into blk00000.dat, exactly as node start-up leaves it.
       (bl.store:ensure-genesis-on-disk store)
       (bl.store:add-block-index-entry cs prev)
       (loop for h from 1 to 3
             do (let* ((b (%ff-test-block (+ 210 h)))
                       (hash (bl.store:store-block store b :height h))
                       (entry (bl.store:make-block-index-entry
                               :hash hash :height h :chain-work (1+ h)
                               :status :valid :prev-entry prev)))
                  (bl.store:add-block-index-entry cs entry)
                  (setf prev entry)))
       (bl.store:update-chain-tip
        cs (bl.store:block-index-entry-hash prev)
        (+ bl:+min-blocks-to-keep+ 40))
       (let ((info (gethash 0 (bl.store:block-store-file-info store))))
         (is (= 0 (bl.store:block-file-info-height-first info))
             "genesis is what makes the first file's range start at 0")
         (is (= 3 (bl.store:block-file-info-height-last info))))
       (let ((bl:*prune-target-mib* 550)
             (bl:*prune-after-height* 0))
         (setf (bl.store:block-store-total-bytes store) (* 600 1024 1024))
         (is (= 4 (bl.store:prune-old-blocks store cs))
             "the file holding genesis must be prunable like any other")
         (is-false (probe-file (merge-pathnames "blocks/blk00000.dat" dir))))))))

(test a-pruned-restart-does-not-write-genesis-again
  "Core\'s LoadGenesisBlock returns early when the genesis hash is already in
m_block_index (validation.cpp:4968-4969) -- the block-tree DATABASE, which is
empty on exactly one occasion, the first start on this datadir. Ours asked
whether genesis was in the BODY map, which a PRUNED node answers no to
forever: the file holding genesis is the first one deleted, so every restart
after the first prune wrote genesis again, into a new blk file at the end of
the store. feature_remove_pruned_files_on_startup.py:64 counts the blk/rev
files a pruned node keeps across a restart and found five where Core keeps
four, the fifth holding one 293-byte record -- genesis.

The condition is now `the store is empty\', which is the same occasion and the
only one that can serve the purpose: genesis belongs at offset 0 of
blk00000.dat, and once anything else is there it has nowhere to go."
  (with-network (:mainnet)
   ;; Control: a fresh store still takes genesis, at the head of file 0.
   (with-temp-directory (fresh)
     (let* ((bl.store:*flat-block-files* t)
            (store (bl.store:init-block-store fresh))
            (genesis (bl.store:best-block-hash (bl.store:init-chain-state fresh))))
       (bl.store:ensure-genesis-on-disk store)
       (is-true (bl.store:block-exists-p store genesis)
                "a fresh store takes genesis")
       (is-true (probe-file (merge-pathnames "blocks/blk00000.dat" fresh)))))
   (with-temp-directory (dir)
     (let ((genesis nil))
       (let* ((bl.store:*flat-block-files* t)
              (bl.store:*fast-prune* t)
              (store (bl.store:init-block-store dir)))
         (setf genesis (bl.store:best-block-hash (bl.store:init-chain-state dir)))
         (bl.store:ensure-genesis-on-disk store)
         (%ff-fill-two-blk-files store))
       (is-true (probe-file (merge-pathnames "blocks/blk00001.dat" dir))
                "the fixture must actually have rolled over to a second file")
       ;; Exactly what a prune leaves behind: the file holding genesis is gone.
       (delete-file (merge-pathnames "blocks/blk00000.dat" dir))
       (let* ((bl.store:*flat-block-files* t)
              (bl.store:*fast-prune* t)
              (reopened (bl.store:init-block-store dir))
              (before (length (directory (merge-pathnames "blocks/blk*.dat" dir)))))
         (is-false (bl.store:block-exists-p reopened genesis)
                   "the pruned restart has no genesis body, by construction")
         (bl.store:ensure-genesis-on-disk reopened)
         (is-false (bl.store:block-exists-p reopened genesis)
                   "and start-up must not write it back")
         (is (= before (length (directory (merge-pathnames "blocks/blk*.dat" dir))))
             "so no blk file is opened for it"))))))

;;; --- Rebuilding the index from the files (P5) ---------------------------------

(defun %ff-chain-block (prev-hash seed height)
  "A block whose header genuinely links to PREV-HASH, so a rebuilt index can
follow the chain."
  (%ff-unlabelled
   (make-reorg-test-block
    prev-hash
    (make-array 32 :element-type '(unsigned-byte 8) :initial-element seed)
    height)))

(test the-block-index-can-be-rebuilt-from-the-block-files
  "The capability the flat files were worth having for. Delete the whole header
index, keep the blocks, and the chain comes back — which turns a lost index
from a full resync into local work."
  (with-network (:mainnet)
   (with-temp-directory (dir)
     (let* ((bl.store:*flat-block-files* t)
            (store (bl.store:init-block-store dir))
            (cs (bl.store:init-chain-state dir))
            (genesis (bl.store:best-block-hash cs))
            (hashes '()))
       (bl.store:add-block-index-entry
        cs (bl.store:make-block-index-entry
            :hash genesis :height 0 :chain-work 1 :status :valid))
       ;; A five-block chain, each linking to the last.
       (let ((prev genesis))
         (loop for h from 1 to 5
               do (let* ((b (%ff-chain-block prev (+ 210 h) h))
                         (hash (bl.store:store-block store b :height h)))
                    (push hash hashes)
                    (setf prev hash))))
       (setf hashes (nreverse hashes))
       ;; Now lose the index entirely — only genesis survives, as it would on a
       ;; fresh start.
       (let* ((store2 (bl.store:init-block-store dir))
              (cs2 (bl.store:init-chain-state dir)))
         (bl.store:add-block-index-entry
          cs2 (bl.store:make-block-index-entry
               :hash genesis :height 0 :chain-work 1 :status :valid))
         (is (= 1 (hash-table-count
                   (bl.store:chain-state-block-index cs2)))
             "starting from an index that knows only genesis")
         (multiple-value-bind (added orphans)
             (bl.store:reindex-block-index store2 cs2)
           (is (= 5 added) "every stored block must come back")
           (is (= 0 orphans)))
         ;; And the tree is linked, with heights and work derived from it.
         (loop for hash in hashes
               for h from 1
               do (let ((e (bl.store:get-block-index-entry cs2 hash)))
                    (is-true e "block at height ~D was not rebuilt" h)
                    (when e
                      (is (= h (bl.store:block-index-entry-height e)))
                      (is-true (bl.store:block-index-entry-header e))
                      (is-true (bl.store:block-index-entry-prev-entry e))
                      ;; Not re-validated, so the entry claims only its header.
                      (is (eq :header-valid
                              (bl.store:block-index-entry-status e)))
                      (is (> (bl.store:block-index-entry-chain-work e) 0))))))))))

(test reindexing-does-not-care-what-order-the-blocks-were-stored-in
  "Blocks are stored in the order they ARRIVED, so a block's parent can be
later in the file. Core parks such records by their parent's hash and drains
them once it lands; without that, reindexing a node that saw a block out of
order would silently lose the rest of the chain behind it."
  (with-network (:mainnet)
   (with-temp-directory (dir)
     (let* ((bl.store:*flat-block-files* t)
            (store (bl.store:init-block-store dir))
            (cs (bl.store:init-chain-state dir))
            (genesis (bl.store:best-block-hash cs))
            (blocks '()))
       (bl.store:add-block-index-entry
        cs (bl.store:make-block-index-entry
            :hash genesis :height 0 :chain-work 1 :status :valid))
       ;; Build the chain in memory first, then store it BACKWARDS.
       (let ((prev genesis))
         (loop for h from 1 to 5
               do (let ((b (%ff-chain-block prev (+ 220 h) h)))
                    (push (cons b h) blocks)
                    (setf prev (bl.ser:block-header-hash
                                (bl.ser:bitcoin-block-header b))))))
       ;; BLOCKS is already newest-first: store the child before the parent.
       (dolist (pair blocks)
         (bl.store:store-block store (car pair) :height (cdr pair)))
       (let ((store2 (bl.store:init-block-store dir))
             (cs2 (bl.store:init-chain-state dir)))
         (bl.store:add-block-index-entry
          cs2 (bl.store:make-block-index-entry
               :hash genesis :height 0 :chain-work 1 :status :valid))
         (multiple-value-bind (added orphans)
             (bl.store:reindex-block-index store2 cs2)
           (is (= 5 added) "reverse storage order must still rebuild the whole chain")
           (is (= 0 orphans))))))))

(test reindexing-names-the-out-of-order-blocks-as-core-names-them
  "Core's LoadExternalBlockFile judges each record AS IT IS READ, against the
index as it stands at that point: a block whose parent is not known yet is
logged and parked under its parent's hash (validation.cpp:5048-5054), and when
the parent lands every block parked under it -- and under those in turn -- is
processed at once, one log line each (:5110-5134). Ours read every record into
one table first and drained afterwards, which reaches the same index but can
say nothing about which blocks were out of order.

feature_reindex.py:69-73 swaps two blocks inside blk00000.dat and then asserts
BOTH sentences appear in debug.log, so the wording is the contract. The chain
below is stored newest-first, so blocks 5..2 are each out of order on arrival
and block 1 releases all four."
  (with-network (:mainnet)
   (with-temp-directory (dir)
     (let* ((bl.store:*flat-block-files* t)
            (store (bl.store:init-block-store dir))
            (cs (bl.store:init-chain-state dir))
            (genesis (bl.store:best-block-hash cs))
            (blocks '()))
       (bl.store:add-block-index-entry
        cs (bl.store:make-block-index-entry
            :hash genesis :height 0 :chain-work 1 :status :valid))
       (let ((prev genesis))
         (loop for h from 1 to 5
               do (let ((b (%ff-chain-block prev (+ 240 h) h)))
                    (push (cons b h) blocks)
                    (setf prev (bl.ser:block-header-hash
                                (bl.ser:bitcoin-block-header b))))))
       ;; BLOCKS is newest-first: every child is stored before its parent.
       (dolist (pair blocks)
         (bl.store:store-block store (car pair) :height (cdr pair)))
       (let* ((store2 (bl.store:init-block-store dir))
              (cs2 (bl.store:init-chain-state dir))
              (added 0)
              ;; The two lines are Core's LogDebug(BCLog::REINDEX), so the
              ;; category has to be on for them to be written at all -- the
              ;; functional framework starts every node with -debug
              ;; (test_node.py:151).
              (lines (unwind-protect
                          (progn
                            (bl.log:enable-log-category "reindex")
                            (capture-log-lines
                             (lambda ()
                               (bl.store:add-block-index-entry
                                cs2 (bl.store:make-block-index-entry
                                     :hash genesis :height 0 :chain-work 1
                                     :status :valid))
                               (setf added (bl.store:reindex-block-index store2 cs2)))))
                       (bl.log:disable-log-category "reindex"))))
         (flet ((saying (text)
                  (count-if (lambda (l) (search text l)) lines)))
           (is (= 5 added) "the whole chain is still rebuilt")
           (is (= 4 (saying "LoadExternalBlockFile: Out of order block"))
               "one line per record read before its parent; lines were ~S" lines)
           (is (= 4 (saying "LoadExternalBlockFile: Processing out of order child"))
               "and one per parked record released when its parent landed")
           (is (= 4 (saying ", parent "))
               "Core names the parent in the out-of-order line")
           ;; The hashes are Core's spelling: big-endian, as every RPC prints
           ;; one. The tail block of the chain is the FIRST record in the file.
           (let ((newest (bl.crypto:bytes-to-hex
                          (bl.crypto:reverse-bytes
                           (bl.ser:block-header-hash
                            (bl.ser:bitcoin-block-header (car (first blocks))))))))
             (is (plusp (saying (format nil "Out of order block ~A," newest)))
                 "the hash is spelled big-endian, as uint256::ToString spells it"))))))))

(test the-out-of-order-lines-do-not-depend-on-the-index-being-empty
  "feature_reindex.py:71-74 swaps two blocks inside blk00000.dat, restarts with
-reindex and waits for BOTH of Core's sentences. Core can decide `out of order'
by asking its block index, because -reindex WIPED it: there, `not in the index'
and `not read yet' are the same question. Ours is additive -- the index still
holds all twelve blocks -- so asking the index answered `known' for every
record, nothing was ever parked, and neither sentence was written: the test
failed at :106 against a rebuild that was working correctly.

The judgement is therefore made on FILE POSITION, which is the question Core is
really asking: a parent that sits after this record has not been read yet. A
record already in the index is parked all the same and adds nothing when it is
drained, so the rebuild stays additive and idempotent -- which is what the
second half of this test measures."
  (with-network (:mainnet)
   (with-temp-directory (dir)
     (let* ((bl.store:*flat-block-files* t)
            (store (bl.store:init-block-store dir))
            (cs (bl.store:init-chain-state dir))
            (genesis (bl.store:best-block-hash cs))
            (prev genesis)
            (blocks '()))
       (bl.store:add-block-index-entry
        cs (bl.store:make-block-index-entry
            :hash genesis :height 0 :chain-work 1 :status :valid))
       (loop for h from 1 to 3
             do (let ((b (%ff-chain-block prev (+ 250 h) h)))
                  (push (cons b h) blocks)
                  (setf prev (bl.ser:block-header-hash
                              (bl.ser:bitcoin-block-header b)))))
       ;; Store the second block before the first, as the swap in
       ;; blk00000.dat leaves them, and build the index as we go -- so by the
       ;; end it holds every record, the state a -reindex actually starts from.
       (setf blocks (nreverse blocks))
       (let ((ordered (list (second blocks) (first blocks) (third blocks)))
             (entries (list (cons genesis
                                  (bl.store:get-block-index-entry cs genesis)))))
         (dolist (pair ordered)
           (bl.store:store-block store (car pair) :height (cdr pair)))
         ;; The index knows all three, linked correctly, whatever order the
         ;; file holds them in.
         (dolist (pair blocks)
           (let* ((hdr (bl.ser:bitcoin-block-header (car pair)))
                  (hash (bl.ser:block-header-hash hdr))
                  (parent (cdr (assoc (bl.ser:block-header-prev-block hdr)
                                      entries :test #'equalp)))
                  (entry (bl.store:make-block-index-entry
                          :hash hash :height (cdr pair) :header hdr
                          :prev-entry parent :chain-work (1+ (cdr pair))
                          :status :valid)))
             (bl.store:add-block-index-entry cs entry)
             (push (cons hash entry) entries)))
         (is (= 4 (hash-table-count (bl.store:chain-state-block-index cs)))
             "the fixture must start from a FULL index, or this test asks ~
nothing about the additive case")
         (let* ((added nil)
                (lines (unwind-protect
                            (progn
                              (bl.log:enable-log-category "reindex")
                              (capture-log-lines
                               (lambda ()
                                 (setf added
                                       (bl.store:reindex-block-index store cs)))))
                         (bl.log:disable-log-category "reindex"))))
           (flet ((saying (text) (count-if (lambda (l) (search text l)) lines)))
             (is (= 1 (saying "LoadExternalBlockFile: Out of order block"))
                 "the record stored before its parent was not named; lines were ~S"
                 lines)
             (is (= 1 (saying "LoadExternalBlockFile: Processing out of order child"))
                 "and nothing was reported when its parent landed"))
           (is (= 0 added)
               "an index that already holds every record must gain nothing")
           (is (= 4 (hash-table-count (bl.store:chain-state-block-index cs)))
               "the additive rebuild changed the index it was given")))))))

(test a-record-whose-parent-is-gone-is-reported-not-treated-as-corruption
  "On a pruned node the chain below the horizon is deleted, so records with no
reachable parent are EXPECTED. Reporting the count lets an operator tell that
apart from a genuinely broken file; refusing would make reindex useless on
exactly the nodes that most need it."
  (with-network (:mainnet)
   (with-temp-directory (dir)
     (let* ((bl.store:*flat-block-files* t)
            (store (bl.store:init-block-store dir))
            (cs (bl.store:init-chain-state dir))
            (genesis (bl.store:best-block-hash cs)))
       (bl.store:add-block-index-entry
        cs (bl.store:make-block-index-entry
            :hash genesis :height 0 :chain-work 1 :status :valid))
       ;; A block whose parent is a hash nothing in the store produces.
       (bl.store:store-block
        store (%ff-chain-block (make-array 32 :element-type '(unsigned-byte 8)
                                              :initial-element #xEE)
                               230 1)
        :height 1)
       (let ((store2 (bl.store:init-block-store dir))
             (cs2 (bl.store:init-chain-state dir)))
         (bl.store:add-block-index-entry
          cs2 (bl.store:make-block-index-entry
               :hash genesis :height 0 :chain-work 1 :status :valid))
         (multiple-value-bind (added orphans)
             (bl.store:reindex-block-index store2 cs2)
           (is (= 0 added))
           (is (= 1 orphans) "the unreachable record is counted, not an error")))))))

(test reindexing-is-additive-and-idempotent
  "It never discards what is already known: a node that threw away a good index
to rebuild it would be strictly worse off if the files turned out to be
incomplete. Running it twice adds nothing the second time."
  (with-network (:mainnet)
   (with-temp-directory (dir)
     (let* ((bl.store:*flat-block-files* t)
            (store (bl.store:init-block-store dir))
            (cs (bl.store:init-chain-state dir))
            (genesis (bl.store:best-block-hash cs)))
       (bl.store:add-block-index-entry
        cs (bl.store:make-block-index-entry
            :hash genesis :height 0 :chain-work 1 :status :valid))
       (let ((prev genesis))
         (loop for h from 1 to 3
               do (let ((b (%ff-chain-block prev (+ 240 h) h)))
                    (bl.store:store-block store b :height h)
                    (setf prev (bl.ser:block-header-hash
                                (bl.ser:bitcoin-block-header b))))))
       ;; The index already holds everything, having been built as we stored.
       (is (= 3 (bl.store:reindex-block-index store cs))
           "the first rebuild fills an index that only knew genesis")
       (is (= 0 (bl.store:reindex-block-index store cs))
           "and a second pass adds nothing")))))

(defun %ff-datadir-with-three-blocks (dir)
  "DIR as a datadir holding three stored blocks above genesis and NO persisted
header index -- the shape a node comes back in after losing blocks/index.
Returns the hashes, oldest first."
  (let* ((store (bl.store:init-block-store dir))
         (cs (bl.store:init-chain-state dir))
         (prev (bl.store:best-block-hash cs))
         (hashes '()))
    (loop for h from 1 to 3
          do (let ((b (%ff-chain-block prev (+ 240 h) h)))
               (bl.store:store-block store b :height h)
               (setf prev (bl.ser:block-header-hash
                           (bl.ser:bitcoin-block-header b)))
               (push prev hashes)))
    (nreverse hashes)))

(defun %ff-load-chain-once (dir)
  "Run the shipped start-up step %INIT-LOAD-CHAIN over DIR with NO -reindex,
and return how many entries the block index ended up with. The coins DB it
opens is closed again, so the next run over the same directory can open it."
  (let ((node (bl:make-node :network :mainnet :data-directory dir)))
    (let ((bl:*node* node))
      (unwind-protect
           (progn
             (bl::%init-load-chain :mainnet nil nil nil)
             (hash-table-count
              (bl.store:chain-state-block-index (bl:node-chain-state node))))
        (ignore-errors
         (bl.store:close-chainstate-coins-view (bl:node-chain-state node)))))))

(test an-interrupted-reindex-resumes-on-the-next-start-without-the-option
  "Core records an unfinished reindex ON DISK and resumes it: the block tree db
carries DB_REINDEX_FLAG 'R' (node/blockstorage.cpp:61), written when the db is
wiped for -reindex (:1234-1236 over WriteReindexing, :73-80) and erased only
once ImportBlocks has read every block file (:1288-1290). LoadBlockIndexDB
reads it back and clears m_blockfiles_indexed (:583-586), so the NEXT start
reindexes with no option given at all.

Ours had no such record, so a reindex killed partway came back as an ordinary
start: an additive rebuild stops wherever it died, the block index is missing
every record the walk had not reached, and nothing anywhere says so. The
option is not the interesting input here -- the MARKER is, which is why the
control below runs the same start-up step over the same three blocks with the
marker absent."
  (with-network (:mainnet)
    (let ((bl.store:*flat-block-files* t))
      ;; Control: no marker, no option -- the rebuild must NOT run, so the
      ;; index start-up produces holds genesis and nothing else.
      (with-temp-directory (dir)
        (%ff-datadir-with-three-blocks dir)
        (is (= 1 (%ff-load-chain-once dir))
            "a start with neither the option nor a marker reindexed anyway"))
      ;; The marker an interrupted reindex leaves behind, written as bytes so
      ;; this test does not depend on the writer it is checking.
      (with-temp-directory (dir)
        (%ff-datadir-with-three-blocks dir)
        (let ((marker (merge-pathnames
                       "reindex" (bl.store:datadir-block-index-path dir))))
          (ensure-directories-exist marker)
          (with-open-file (out marker :direction :output
                                      :element-type '(unsigned-byte 8)
                                      :if-exists :supersede
                                      :if-does-not-exist :create)
            (write-byte (char-code #\1) out))
          (is (= 4 (%ff-load-chain-once dir))
              "the recorded reindex was not resumed: genesis plus three blocks ~
were expected in the index")
          (is-false (probe-file marker)
                    "the marker survived a rebuild that finished")))
      ;; Last, the reader and writer by name: a control that fails here has
      ;; already told us what it had to about the behaviour.
      (with-temp-directory (dir)
        (is-false (bl.store:reindex-flag-set-p dir))
        (bl.store:write-reindex-flag dir t)
        (is-true (bl.store:reindex-flag-set-p dir))
        (is-true (probe-file (bl.store:reindex-flag-path dir)))
        (bl.store:write-reindex-flag dir nil)
        (is-false (bl.store:reindex-flag-set-p dir))))))

;;; --- Migrating legacy per-block files into flat files (P4) --------------------

(defun %ff-migration-chain (dir n &key (seed-base 250))
  "Store an N-block active chain as LEGACY per-block files and return the chain
state, the store, and the hashes in height order."
  (let* ((bl.store:*flat-block-files* nil)
         (store (bl.store:init-block-store dir))
         (cs (bl.store:init-chain-state dir))
         (genesis (bl.store:best-block-hash cs))
         (prev-entry (bl.store:make-block-index-entry
                      :hash genesis :height 0 :chain-work 1 :status :valid))
         (hashes '()))
    (bl.store:add-block-index-entry cs prev-entry)
    (let ((prev genesis))
      (loop for h from 1 to n
            do (let* ((b (%ff-chain-block prev (+ seed-base h) h))
                      (hash (bl.store:store-block store b :height h))
                      (entry (bl.store:make-block-index-entry
                              :hash hash :height h :chain-work (1+ h)
                              :status :valid :prev-entry prev-entry)))
                 (bl.store:add-block-index-entry cs entry)
                 (push hash hashes)
                 (setf prev hash prev-entry entry))))
    (bl.store:update-chain-tip
     cs (bl.store:block-index-entry-hash prev-entry) n)
    (values cs store (nreverse hashes))))

(test migration-converts-legacy-blocks-and-keeps-them-readable
  "The whole point: after migrating, every block still comes back byte-identical
and the per-block files are gone. Reading the blocks back is the assertion that
matters — a migration that updated the index but wrote nothing usable would
pass any count-based check."
  (with-network (:mainnet)
   (with-temp-directory (dir)
     (multiple-value-bind (cs store hashes) (%ff-migration-chain dir 5)
       ;; Capture the blocks as the legacy store serves them.
       (let ((before (mapcar (lambda (h)
                               (bl.ser:serialize-witness-block
                                (bl.store:get-block store h)))
                             hashes)))
         (is (= 5 (bl.store:count-legacy-blocks store)))
         (is-false (probe-file (merge-pathnames "blocks/blk00000.dat" dir)))
         (multiple-value-bind (migrated next remaining)
             (bl.store:migrate-blocks-to-flat-files store cs)
           (is (= 5 migrated))
           (is (= 6 next) "resumes above the tip once everything is converted")
           (is (= 0 remaining)))
         (is (probe-file (merge-pathnames "blocks/blk00000.dat" dir)))
         ;; Every per-block file is gone...
         (dolist (h hashes)
           (is-false (probe-file (bl.store::block-file-path store h))
                     "a per-block file survived the migration"))
         ;; ...and every block reads back identically, through the flat path.
         (loop for h in hashes
               for original in before
               do (let ((got (bl.store:get-block store h)))
                    (is-true got "block ~A is gone after migration"
                             (bl.crypto:bytes-to-hex h))
                    (when got
                      (is (equalp original
                                  (bl.ser:serialize-witness-block got)))))))))))

(test migration-survives-a-restart-that-loses-the-in-memory-index
  "The converted blocks have to be findable by a process that never saw the
migration — otherwise the migration is only true of the running image, and the
next restart loses the chain."
  (with-network (:mainnet)
   (with-temp-directory (dir)
     (multiple-value-bind (cs store hashes) (%ff-migration-chain dir 4 :seed-base 60)
       (bl.store:migrate-blocks-to-flat-files store cs)
       (let* ((bl.store:*flat-block-files* t)
              (store2 (bl.store:init-block-store dir)))
         (is (= 0 (bl.store:count-legacy-blocks store2)))
         (dolist (h hashes)
           (is-true (bl.store:get-block store2 h)
                    "a migrated block is not findable after a restart")))))))

(test migration-honors-its-budget-and-resumes-where-it-stopped
  "An operator converting a live node needs to stop after a slice and continue
later. The resume height is the contract; if it were wrong the next call would
either redo work or skip blocks."
  (with-network (:mainnet)
   (with-temp-directory (dir)
     (multiple-value-bind (cs store hashes) (%ff-migration-chain dir 6 :seed-base 70)
       (declare (ignore hashes))
       (multiple-value-bind (migrated next remaining)
           (bl.store:migrate-blocks-to-flat-files
            store cs :max-blocks 2)
         (is (= 2 migrated))
         (is (= 3 next) "two blocks converted means heights 1 and 2 are done")
         (is (= 4 remaining)))
       (multiple-value-bind (migrated next remaining)
           (bl.store:migrate-blocks-to-flat-files
            store cs :max-blocks 2 :start-height 3)
         (is (= 2 migrated))
         (is (= 5 next))
         (is (= 2 remaining)))
       (multiple-value-bind (migrated next remaining)
           (bl.store:migrate-blocks-to-flat-files
            store cs :max-blocks 100 :start-height 5)
         (is (= 2 migrated))
         (is (= 0 remaining)))))))

(test migration-is-idempotent
  "Re-running must be free, not destructive. A resumable job that converts
already-converted blocks would rewrite the whole chain on every retry."
  (with-network (:mainnet)
   (with-temp-directory (dir)
     (multiple-value-bind (cs store) (%ff-migration-chain dir 3 :seed-base 80)
       (is (= 3 (bl.store:migrate-blocks-to-flat-files store cs)))
       (let ((size (bl.store::file-size-bytes
                    (merge-pathnames "blocks/blk00000.dat" dir))))
         (is (= 0 (bl.store:migrate-blocks-to-flat-files store cs))
             "a second pass converts nothing")
         (is (= size (bl.store::file-size-bytes
                      (merge-pathnames "blocks/blk00000.dat" dir)))
             "and writes nothing"))))))

(test migration-in-height-order-leaves-the-file-prunable
  "The reason the walk is ordered at all. A flat file is prunable only when its
whole height range is below the horizon; converting in arrival order would give
file 0 a range spanning the chain, and a pruned node would quietly stop
reclaiming space. Assert the range, not the order."
  (with-network (:mainnet)
   (with-temp-directory (dir)
     (multiple-value-bind (cs store) (%ff-migration-chain dir 5 :seed-base 90)
       (bl.store:migrate-blocks-to-flat-files store cs)
       (let ((info (gethash 0 (bl.store:block-store-file-info store))))
         (is-true info "the migrated file has no height bookkeeping at all")
         (when info
           (is (= 1 (bl.store:block-file-info-height-first info)))
           (is (= 5 (bl.store:block-file-info-height-last info)))))
       ;; And it is genuinely selectable for pruning below a horizon above it.
       (is (equal '(0) (bl.store::%prunable-flat-files store 0 100)))))))

(test migration-does-not-touch-blocks-off-the-active-chain
  "Side-chain blocks have no height in a flat file's range, and converting them
would poison that range. They stay per-block, and dual read keeps them served."
  (with-network (:mainnet)
   (with-temp-directory (dir)
     (multiple-value-bind (cs store hashes) (%ff-migration-chain dir 3 :seed-base 100)
       ;; A block that is in the store but not on the active chain.
       (let* ((bl.store:*flat-block-files* nil)
              (side (bl.store:store-block
                     store (%ff-chain-block (first hashes) 199 2) :height 2)))
         (multiple-value-bind (migrated next remaining)
             (bl.store:migrate-blocks-to-flat-files store cs)
           (declare (ignore next))
           (is (= 3 migrated))
           (is (= 1 remaining) "the side-chain block is still a per-block file"))
         (is-true (probe-file (bl.store::block-file-path store side)))
         (is-true (bl.store:get-block store side)
                  "and it is still readable"))))))

(test migration-keeps-the-storage-total-honest
  "The running byte total drives automatic pruning. STORE-BLOCK already replaces
the legacy file's contribution when it writes the flat record, so decrementing
again at the unlink — the obvious thing to write — would drive the total toward
zero and disable pruning on a node that has just been migrated."
  (with-network (:mainnet)
   (with-temp-directory (dir)
     (multiple-value-bind (cs store) (%ff-migration-chain dir 4 :seed-base 110)
       (bl.store:migrate-blocks-to-flat-files store cs)
       (let ((on-disk (bl.store::file-size-bytes
                       (merge-pathnames "blocks/blk00000.dat" dir)))
             (accounted (bl.store:block-store-total-bytes store)))
         (is (plusp accounted) "the total must not have been driven to zero")
         ;; The file is preallocated in 16 MiB chunks, so on-disk >= accounted;
         ;; what matters is that the accounted total matches the RECORDS.
         (is (<= accounted on-disk))
         (let* ((bl.store:*flat-block-files* t)
                (fresh (bl.store:init-block-store dir)))
           (is (= accounted (bl.store:block-store-total-bytes fresh))
               "a fresh scan of the same files must agree with the running total")))))))

(test a-block-that-fails-to-read-back-stops-the-migration-with-its-file-intact
  "The one failure this must handle without losing data. If the flat record
cannot be read back, the per-block file is the only surviving copy — so it is
kept, and the walk stops rather than converting more blocks through a path just
shown not to work."
  (with-network (:mainnet)
   (with-temp-directory (dir)
     (multiple-value-bind (cs store hashes) (%ff-migration-chain dir 4 :seed-base 120)
       (let* ((victim (second hashes))
              (real #'bl.store:get-block)
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
                      (setf (fdefinition 'bl.store:get-block) wrapper)
                      (multiple-value-bind (migrated next remaining)
                          (bl.store:migrate-blocks-to-flat-files store cs)
                        (is (= 1 migrated) "only height 1 converted before the failure")
                        (is (= 2 next) "and the retry resumes at the block that failed")
                        ;; Three still legacy: the victim plus the two above it.
                        ;; The victim counts only because the index was put back
                        ;; -- STORE-BLOCK had already repointed it at the flat
                        ;; record, and leaving it there would have made dual
                        ;; read serve the copy that just failed.
                        (is (= 3 remaining))))
                 (setf (fdefinition 'bl.store:get-block) real)))))
         (is (= 1 seen) "the injected failure must actually have fired")
         ;; The victim's per-block file is still there, and still readable.
         (is-true (probe-file (bl.store::block-file-path store victim)))
         (is-true (funcall real store victim)))))))

(test the-migration-is-reachable-as-an-rpc
  "The seam. A migration nothing can invoke is the same bug this project has now
found seven times — correct code with no caller. The operator's only handle on a
live node is the RPC, so assert it is registered and validates its arguments."
  (bl.rpc::register-all-methods)
  (is-true (gethash "migrateblocks" bl.rpc::*rpc-methods*)
           "migrateblocks is not registered, so nothing can start a migration")
  (let ((handler (gethash "migrateblocks" bl.rpc::*rpc-methods*)))
    ;; Bad arguments are rejected before any node state is touched, so NIL for
    ;; the node is enough to prove the guard runs first.
    (signals bl.rpc:rpc-error (funcall handler nil '(0)))
    (signals bl.rpc:rpc-error (funcall handler nil '(10 -1)))))

(test a-crash-between-the-flat-write-and-the-unlink-is-swept-on-the-next-pass
  "The crash window. INIT-BLOCK-STORE indexes per-block files first and flat
records second, so after a crash in that window the flat record wins the index
and the per-block file becomes an orphan nothing reads — but its bytes still
count toward the pruning total, so a pruned node prunes earlier than it should.
Re-running the migration must sweep it."
  (with-network (:mainnet)
   (with-temp-directory (dir)
     (multiple-value-bind (cs store hashes) (%ff-migration-chain dir 3 :seed-base 130)
       (bl.store:migrate-blocks-to-flat-files store cs)
       ;; Recreate exactly what the crash leaves behind: the flat record is
       ;; there and indexed, and the per-block file is back on disk.
       (let* ((victim (second hashes))
              (orphan (bl.store::block-file-path store victim)))
         (with-open-file (out orphan :direction :output
                                     :element-type '(unsigned-byte 8)
                                     :if-exists :supersede)
           (write-sequence (bl.ser:serialize-witness-block
                            (bl.store:get-block store victim))
                           out))
         ;; A restart double-counts it, which is the harm.
         (let* ((bl.store:*flat-block-files* t)
                (store2 (bl.store:init-block-store dir))
                (inflated (bl.store:block-store-total-bytes store2)))
           (is (= 0 (bl.store:count-legacy-blocks store2))
               "the flat record wins the index, so nothing looks unmigrated")
           (multiple-value-bind (migrated) 
               (bl.store:migrate-blocks-to-flat-files store2 cs)
             (is (= 0 migrated) "there is nothing left to convert"))
           (is-false (probe-file orphan) "the orphaned per-block file was not swept")
           (is (< (bl.store:block-store-total-bytes store2) inflated)
               "and its bytes stopped counting toward the pruning total")
           (is-true (bl.store:get-block store2 victim)
                    "sweeping the orphan must not cost the block")))))))

(test which-copy-wins-a-duplicate-is-decided-by-which-one-reads
  "The other half of the crash window. If the flat record is the corrupt one,
sweeping the per-block file because the index names the flat copy would delete
the only readable copy of the block. The index goes back onto the file that
reads, which also lets the migration retry it."
  (with-network (:mainnet)
   (with-temp-directory (dir)
     (multiple-value-bind (cs store hashes) (%ff-migration-chain dir 3 :seed-base 140)
       (bl.store:migrate-blocks-to-flat-files store cs)
       (let* ((victim (second hashes))
              (legacy (bl.store::block-file-path store victim))
              (body (bl.ser:serialize-witness-block
                     (bl.store:get-block store victim)))
              (real #'bl.store:get-block))
         ;; Put the per-block file back, as the crash would leave it.
         (with-open-file (out legacy :direction :output
                                     :element-type '(unsigned-byte 8)
                                     :if-exists :supersede)
           (write-sequence body out))
         ;; And make the flat copy unreadable for this hash only.
         (let ((wrapper (lambda (s h)
                          (if (equalp h victim)
                              (if (bl.kv:flat-file-pos-p
                                   (gethash h (bl.store::block-store-index s)))
                                  nil
                                  (funcall real s h))
                              (funcall real s h)))))
           (unwind-protect
                (progn
                  (setf (fdefinition 'bl.store:get-block) wrapper)
                  (bl.store:migrate-blocks-to-flat-files store cs))
             (setf (fdefinition 'bl.store:get-block) real)))
         (is-true (probe-file legacy)
                  "the readable per-block copy must not have been swept")
         (is (= 1 (bl.store:count-legacy-blocks store))
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
  (with-network (:mainnet)
   (with-temp-directory (dir)
     (let* ((bl.store:*flat-block-files* t)
            (store (bl.store:init-block-store dir))
            (cs (bl.store:init-chain-state dir))
            (genesis (bl.store:best-block-hash cs))
            (prev (bl.store:make-block-index-entry
                   :hash genesis :height 0 :chain-work 1 :status :valid)))
       (bl.store:add-block-index-entry cs prev)
       (let ((tip-height (+ bl:+min-blocks-to-keep+ 40)))
         (loop for h from 1 to 3
               do (let* ((b (%ff-test-block (+ 210 h)))
                         (hash (bl.store:store-block store b :height h))
                         (entry (bl.store:make-block-index-entry
                                 :hash hash :height h :chain-work (1+ h)
                                 :status :valid :prev-entry prev)))
                    (bl.store:add-block-index-entry cs entry)
                    (setf prev entry)))
         (bl.store:update-chain-tip
          cs (bl.store:block-index-entry-hash prev) tip-height)
         (is (probe-file (merge-pathnames "blocks/blk00000.dat" dir)))
         ;; Manual pruning works at any -prune target, unlike the automatic
         ;; path which is off below 550 MiB.
         (let ((bl:*prune-target-mib* 1)
               (bl:*prune-after-height* 0)
               (swept '()))
           (let ((pruned (bl.store:prune-blocks-to-height
                          store cs 3 :on-prune (lambda (h) (push h swept)))))
             (is (= 3 pruned) "the file's three blocks were not pruned"))
           (is-false (probe-file (merge-pathnames "blocks/blk00000.dat" dir))
                     "pruneblockchain left the flat file on disk")
           (is (>= (length swept) 3)
               "each pruned block must be reported so its undo data goes too")
           (is (= 3 (bl.store:chain-state-pruned-height cs))
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
    (let ((bl:*network* network))
      (%with-flat-store (store dir)
        (declare (ignore dir))
        (let* ((hash (bl.store:network-genesis-hash network))
               (block (bl.store:get-block store hash)))
          (is-true block "~A: genesis body not served" network)
          (when block
            (is (equalp hash
                        (bl.ser:block-header-hash
                         (bl.ser:bitcoin-block-header block)))
                "~A: served a block that is not genesis" network))))))
  ;; A hash that is nobody's genesis is still absent.
  (let ((bl:*network* :regtest))
    (%with-flat-store (store dir)
      (declare (ignore dir))
      (is-false (bl.store:get-block
                 store (make-array 32 :element-type '(unsigned-byte 8)
                                      :initial-element 42))))))

;;;; --- prune locks (Core BlockManager::m_prune_locks) ---

(defmacro %with-clean-prune-locks (&body body)
  "Run BODY with a private prune-lock table, so a test can never leave a lock
behind for the next one.

:SYNCHRONIZED like the real one — a test that exercised a plain table would not
be exercising what production runs, and the synchronization is the whole reason
that variable is allowed to be global."
  `(let ((bl.store:*prune-locks*
           (make-hash-table :test 'equal :synchronized t))
         (bl.store:*prune-lock-caps*
           (make-hash-table :test 'equal :synchronized t)))
     ,@body))

(test prune-lock-ceiling-with-no-locks-is-the-chain-height
  "With nothing registered, pruning is unconstrained — the ceiling is the tip."
  (%with-clean-prune-locks
    (is (= 1000 (bl.store:prune-lock-ceiling 1000)))))

(test prune-lock-ceiling-subtracts-the-buffer-and-one
  "Core: lock_height = height_first - PRUNE_LOCK_BUFFER - 1
\(validation.cpp:2727). An index at height 500 protects 489 upward."
  (%with-clean-prune-locks
    (bl.store:register-prune-lock "idx" (lambda () 500))
    (is (= (- 500 bl.store:+prune-lock-buffer+ 1)
           (bl.store:prune-lock-ceiling 1000)))
    (is (= 489 (bl.store:prune-lock-ceiling 1000)))))

(test prune-lock-ceiling-takes-the-lowest-lock
  "Several locks: the most-behind index wins, because pruning past it would
destroy undo data it still has to read."
  (%with-clean-prune-locks
    (bl.store:register-prune-lock "fast" (lambda () 900))
    (bl.store:register-prune-lock "slow" (lambda () 300))
    (is (= 289 (bl.store:prune-lock-ceiling 1000)))))

(test prune-lock-ceiling-never-exceeds-the-chain-height
  "A lock ahead of the tip does not RAISE the ceiling — Core seeds last_prune
with the chain height and only ever lowers it."
  (%with-clean-prune-locks
    (bl.store:register-prune-lock "ahead" (lambda () 5000))
    (is (= 100 (bl.store:prune-lock-ceiling 100)))))

(test prune-lock-ceiling-floors-at-one
  "Core floors last_prune at 1 (max(1, min(...))), so an index near genesis
cannot drive the ceiling negative."
  (%with-clean-prune-locks
    (bl.store:register-prune-lock "new" (lambda () 3))
    (is (= 1 (bl.store:prune-lock-ceiling 1000)))))

(test prune-lock-with-no-height-does-not-constrain
  "A registered-but-empty index is Core's height_first == INT_MAX: it imposes
no constraint. Reading -1 as a height instead would clamp the ceiling to 1 and
stop a pruned node from ever reclaiming space."
  (%with-clean-prune-locks
    (bl.store:register-prune-lock "empty" (lambda () nil))
    (is (= 1000 (bl.store:prune-lock-ceiling 1000)))))

(test prune-lock-registration-replaces-by-name
  "Re-registering the same name replaces, so a node restart cannot stack two
locks for one index."
  (%with-clean-prune-locks
    (bl.store:register-prune-lock "idx" (lambda () 300))
    (bl.store:register-prune-lock "idx" (lambda () 900))
    (is (= 889 (bl.store:prune-lock-ceiling 1000)))
    (bl.store:clear-prune-locks)
    (is (= 1000 (bl.store:prune-lock-ceiling 1000)))))

(test prune-lock-that-was-the-limit-names-itself-in-the-log
  "Core logs `%s limited pruning to height %d' under BCLog::PRUNE whenever a
prune lock ended up being the limit (validation.cpp:2734-2736), and
feature_index_prune.py:99 requires the line -- with the height -- in debug.log
while it prunes a node whose index is behind the tip. Nothing was logged here
at all, so an operator whose pruneblockchain freed less than it asked for had
no way to learn which index held the horizon down.

Core sets limiting_lock only when last_prune EQUALS that lock's own height
(:2731), so a lock the floor overrides names nobody, and the locks are visited
in NAME order so a tie always names the same one."
  (%with-clean-prune-locks
    (let ((bl.log:*current-log-level* :debug))
      (flet ((lines (height)
               (capture-log-lines (lambda () (bl.store:prune-lock-ceiling height)))))
        ;; No lock at all: nothing to name, so no line.
        (is (null (remove-if-not (lambda (l) (search "limited pruning" l))
                                 (lines 1000)))
            "a node with no prune lock logged a limit")
        (bl.store:register-prune-lock "coinstatsindex" (lambda () 700))
        (let ((line (find-if (lambda (l) (search "limited pruning" l))
                             (lines 1000))))
          (is-true line "the limiting lock logged nothing")
          (when line
            (is-true (search "coinstatsindex limited pruning to height 689" line)
                     "the line reads ~S" line)))
        ;; The LOWEST lock is the one that ended up being the limit, and it is
        ;; the one named -- not merely the last one visited.
        (bl.store:register-prune-lock "basic block filter index" (lambda () 300))
        (let ((line (find-if (lambda (l) (search "limited pruning" l))
                             (lines 1000))))
          (is-true line)
          (when line
            (is-true (search "basic block filter index limited pruning to height 289"
                             line)
                     "the line reads ~S" line)))
        ;; A lock the floor overrides: Core's last_prune is 1 and does not equal
        ;; that lock's own height, so limiting_lock stays unset.
        (bl.store:clear-prune-locks)
        (bl.store:register-prune-lock "coinstatsindex" (lambda () 3))
        (is (null (remove-if-not (lambda (l) (search "limited pruning" l))
                                 (lines 1000)))
            "a lock the floor overrode named itself anyway")))))

(test prune-lock-signalling-thunk-does-not-break-pruning
  "A thunk that errors (a closed index DB after shutdown, say) is treated as
absent rather than taking the node's pruning down with it."
  (%with-clean-prune-locks
    (bl.store:register-prune-lock
     "broken" (lambda () (error "index closed")))
    (is (= 1000 (bl.store:prune-lock-ceiling 1000)))))

(test prune-lock-stops-a-real-flat-file-prune
  "The seam for prune locks: PRUNE-LOCK-CEILING being right is worthless if
PRUNE-OLD-BLOCKS never consults it. Drive the real entry point with usage far
over target and an index parked at height 1, and require the file to SURVIVE —
then drop the lock and require the same call to delete it.

Without this, a filter index that had not caught up would have its undo data
deleted out from under it, and the only symptom would be the index failing to
build much later."
  (with-network (:mainnet)
   (with-temp-directory (dir)
     (let* ((bl.store:*flat-block-files* t)
            (bl.store:*prune-locks*
              (make-hash-table :test 'equal :synchronized t))
            (store (bl.store:init-block-store dir))
            (cs (bl.store:init-chain-state dir))
            (genesis (bl.store:best-block-hash cs))
            (prev (bl.store:make-block-index-entry
                   :hash genesis :height 0 :chain-work 1 :status :valid)))
       (bl.store:add-block-index-entry cs prev)
       (let ((tip-height (+ bl:+min-blocks-to-keep+ 40)))
         (loop for h from 1 to 3
               do (let* ((b (%ff-test-block (+ 100 h)))
                         (hash (bl.store:store-block store b :height h))
                         (entry (bl.store:make-block-index-entry
                                 :hash hash :height h :chain-work (1+ h)
                                 :status :valid :prev-entry prev)))
                    (bl.store:add-block-index-entry cs entry)
                    (setf prev entry)))
         (bl.store:update-chain-tip
          cs (bl.store:block-index-entry-hash prev) tip-height)
         (let ((path (merge-pathnames "blocks/blk00000.dat" dir))
               (bl:*prune-target-mib* 550)
               (bl:*prune-after-height* 0))
           (is-true (probe-file path))
           (setf (bl.store:block-store-total-bytes store)
                 (* 600 1024 1024))
           ;; An index at height 1 protects everything from 1 - 10 - 1 = -10
           ;; upward, floored at 1 — so nothing at all may be pruned.
           (bl.store:register-prune-lock "slowindex" (lambda () 1))
           (is (= 0 (bl.store:prune-old-blocks store cs))
               "a lagging index must hold the whole prune off")
           (is-true (probe-file path) "the blk file must survive the lock")
           ;; And the HORIZON must not move either. It used to: the legacy
           ;; per-block walk ran over the same heights, PRUNE-BLOCK refused
           ;; each one for being in a flat file, and the walk advanced
           ;; PRUNED-HEIGHT anyway — which both claims a prune that never
           ;; happened and pushes the walk start past the file's first height,
           ;; after which %PRUNABLE-FLAT-FILES never offers the file again and
           ;; the node stops reclaiming space permanently.
           (is (= 0 (bl.store:chain-state-pruned-height cs))
               "the prune horizon must not advance over blocks still on disk")
           ;; The same call, with the lock gone, deletes it — which is what
           ;; proves the survival above came from the lock and not from some
           ;; unrelated refusal.
           (bl.store:clear-prune-locks)
           (is (= 3 (bl.store:prune-old-blocks store cs)))
           (is-false (probe-file path))))))))

(test prune-lock-stops-a-manual-prune-too
  "Core caps FindFilesToPruneManual by the same lock-limited last_prune
(validation.cpp:2740-2745), so pruneblockchain cannot step around an index
either."
  (with-network (:mainnet)
   (with-temp-directory (dir)
     (let* ((bl.store:*flat-block-files* t)
            (bl.store:*prune-locks*
              (make-hash-table :test 'equal :synchronized t))
            (store (bl.store:init-block-store dir))
            (cs (bl.store:init-chain-state dir))
            (genesis (bl.store:best-block-hash cs))
            (prev (bl.store:make-block-index-entry
                   :hash genesis :height 0 :chain-work 1 :status :valid)))
       (bl.store:add-block-index-entry cs prev)
       (let ((tip-height (+ bl:+min-blocks-to-keep+ 40)))
         (loop for h from 1 to 3
               do (let* ((b (%ff-test-block (+ 150 h)))
                         (hash (bl.store:store-block store b :height h))
                         (entry (bl.store:make-block-index-entry
                                 :hash hash :height h :chain-work (1+ h)
                                 :status :valid :prev-entry prev)))
                    (bl.store:add-block-index-entry cs entry)
                    (setf prev entry)))
         (bl.store:update-chain-tip
          cs (bl.store:block-index-entry-hash prev) tip-height)
         (let ((path (merge-pathnames "blocks/blk00000.dat" dir))
               (bl:*prune-target-mib* 1))   ; manual-only mode
           (bl.store:register-prune-lock "slowindex" (lambda () 1))
           (is (= 0 (bl.store:prune-blocks-to-height store cs 100))
               "pruneblockchain must respect the lock as well")
           (is-true (probe-file path))
           (bl.store:clear-prune-locks)
           (is (= 3 (bl.store:prune-blocks-to-height store cs 100)))
           (is-false (probe-file path))))))))

;;;; --- reading blocks out of an external file (Core -loadblock) ---

(defun %ff-external-file (dir records &key (junk 0))
  "Write RECORDS (serialized blocks) into a bootstrap-style file under DIR,
each framed as Core frames them: magic, 4-byte LE size, block. JUNK bytes of
garbage are written first, to prove the reader hunts rather than assuming the
file starts on a record."
  (let ((path (merge-pathnames "bootstrap.dat" dir))
        (magic (bl.store::block-network-magic)))
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
  (with-network (:mainnet)
   (with-temp-directory (dir)
     (let* ((blocks (loop for h from 1 to 3
                          collect (bl.ser:serialize-witness-block
                                   (%ff-test-block (+ 30 h)))))
            (path (%ff-external-file dir blocks))
            (seen '()))
       (is (= 3 (bl.store:map-external-block-file
                 path (lambda (b) (push b seen)))))
       (is (= 3 (length seen)))
       (is (equalp (first blocks) (first (last seen))))))))

(test external-block-file-hunts-past-junk
  "Leading garbage must not cost the file: Core scans for the magic a byte at a
time so a partially-downloaded or concatenated bootstrap.dat still yields every
whole record in it."
  (with-network (:mainnet)
   (with-temp-directory (dir)
     (let* ((blocks (loop for h from 1 to 2
                          collect (bl.ser:serialize-witness-block
                                   (%ff-test-block (+ 60 h)))))
            (path (%ff-external-file dir blocks :junk 37))
            (count 0))
       (is (= 2 (bl.store:map-external-block-file
                 path (lambda (b) (declare (ignore b)) (incf count)))))
       (is (= 2 count))))))

(test external-block-file-stops-at-a-truncated-record
  "A record whose length runs past the end of the file is not a record. Core
treats it as a coincidence in the data and keeps hunting, which is what lets a
half-downloaded file still deliver the blocks that ARE complete."
  (with-network (:mainnet)
   (with-temp-directory (dir)
     (let* ((blocks (loop for h from 1 to 2
                          collect (bl.ser:serialize-witness-block
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
         (bl.store:map-external-block-file
          path (lambda (b) (declare (ignore b)) (incf count)))
         (is (= 1 count) "the complete record survives a truncated one after it"))))))

(test external-block-file-that-does-not-exist-reads-nothing
  "Core warns and moves on to the next -loadblock rather than refusing to
start (blockstorage.cpp:1306)."
  (with-network (:mainnet)
   (with-temp-directory (dir)
     (is (= 0 (bl.store:map-external-block-file
               (merge-pathnames "no-such-file.dat" dir)
               (lambda (b) (declare (ignore b)) (error "must not be called"))))))))

(test a-disconnect-moves-a-prune-lock-back-until-its-index-rewinds
  "Core's DisconnectTip moves every prune lock that began above the new tip
back to it, and logs `<name> prune lock moved back to <h>' under the prune
category (validation.cpp:2954-2962; feature_index_prune.py:201). The lock then
follows the index again once SetBestBlockIndex has run on the rewound index
(index/base.cpp:489-497). Ours reads the index's height at prune time, and the
index rewinds only on the next connect, so without the move a prune between
the two could delete the blocks its rewind needs."
  (%with-clean-prune-locks
    (let ((index-height 2500)
          (bl.log:*current-log-level* :debug))
      (bl.store:register-prune-lock "basic block filter index" (lambda () index-height))
      (bl.store:register-prune-lock "behind" (lambda () 100))
      (let ((lines (capture-log-lines
                    (lambda () (bl.store:move-prune-locks-back 2479)))))
        (is-true (find "basic block filter index prune lock moved back to 2479"
                       lines :test #'search))
        ;; A lock already below the new tip does not move.
        (is-false (find "behind prune lock moved back" lines :test #'search)))
      ;; Held at the new tip while the index still reads 2500.
      (setf (gethash "behind" bl.store:*prune-locks*) (lambda () nil))
      (is (= (- 2479 bl.store:+prune-lock-buffer+ 1) (bl.store:prune-lock-ceiling 3000)))
      ;; The index rewinds to the fork point: the lock follows it again ...
      (setf index-height 2470)
      (is (= (- 2470 bl.store:+prune-lock-buffer+ 1) (bl.store:prune-lock-ceiling 3000)))
      ;; ... up as well as down, once the cap is gone.
      (setf index-height 2600)
      (is (= (- 2600 bl.store:+prune-lock-buffer+ 1) (bl.store:prune-lock-ceiling 3000))))))

(test a-full-flush-leaves-the-current-block-file-its-rev-file
  "FlushStateToDisk's full flush commits the current block file and its undo
file through FlatFileSeq::Flush, which OPENS -- and so creates -- the file it
commits (validation.cpp:2784, node/blockstorage.cpp:742-790,
flatfile.cpp:87-107). A node that has written only genesis therefore stops
with blk00000.dat AND rev00000.dat, which is what
feature_remove_pruned_files_on_startup.py:68 lists after a pruned -reindex.
Ours created a rev file only when an undo record was written."
  (with-network (:regtest)
    (with-temp-directory (dir)
      (let* ((bl.store:*flat-block-files* t)
             (store (bl.store:init-block-store dir))
             (rev (merge-pathnames "blocks/rev00000.dat" dir)))
        ;; Nothing written yet: nothing to flush, and no file conjured.
        (is-false (bl.store:flush-chainstate-block-file store))
        (bl.store:ensure-genesis-on-disk store)
        (is-true (probe-file (merge-pathnames "blocks/blk00000.dat" dir)))
        (is-false (probe-file rev) "control: genesis alone writes no undo")
        (is-true (bl.store:flush-chainstate-block-file store))
        (is-true (probe-file rev))))))

(test a-block-already-on-disk-is-not-written-again
  "Core AcceptBlock returns early for a block it already has
(validation.cpp:4350 fAlreadyHave, :4367), so a body is written to a blk file
once. Ours appended a second record every time a stored block was stored again
(an out-of-order or competing-fork body that connect-block later re-stores),
and the running total -- which replaced the old record's size rather than
adding the new one -- never counted the copy. feature_pruning.py:223 measured
725 MiB on disk (173 MiB of it duplicate records) against a total that said
the node was under its 550 MiB target, so pruning stopped."
  (with-network (:regtest)
    (with-temp-directory (dir)
      (let* ((bl.store:*flat-block-files* t)
             (store (bl.store:init-block-store dir))
             (block (%ff-chain-block (make-array 32 :element-type '(unsigned-byte 8)
                                                    :initial-element 7)
                                     41 1)))
        (multiple-value-bind (hash first-pos)
            (bl.store:store-block store block :height 1)
          (let ((total (bl.store:block-store-total-bytes store)))
            (multiple-value-bind (hash2 second-pos)
                (bl.store:store-block store block :height 1)
              (is (equalp hash hash2))
              (is (equalp first-pos second-pos)
                  "the block keeps the record it already has")
              (is (= total (bl.store:block-store-total-bytes store))))
            (is (= 1 (bl.store:block-file-info-blocks
                      (gethash 0 (bl.store:block-store-file-info store)))))
            ;; What pruning is measured against: the files on disk hold no
            ;; more than the running total says.
            (is (= total (bl.store:block-store-total-bytes
                          (bl.store:init-block-store dir))))
            (is-true (bl.store:get-block store hash))))))))

(test a-block-stored-without-its-height-gets-it-when-stored-again
  "A body stored before its header was indexed has no height, so its blk
file's range does not cover it; when the block is stored again with its height
the range takes it, without a second record."
  (with-network (:regtest)
    (with-temp-directory (dir)
      (let* ((bl.store:*flat-block-files* t)
             (store (bl.store:init-block-store dir))
             (block (%ff-chain-block (make-array 32 :element-type '(unsigned-byte 8)
                                                    :initial-element 8)
                                     42 5)))
        (bl.store:store-block store block)
        (bl.store:store-block store block :height 5)
        (let ((info (gethash 0 (bl.store:block-store-file-info store))))
          (is (= 1 (bl.store:block-file-info-blocks info)))
          (is (eql 5 (bl.store:block-file-info-height-first info)))
          (is (eql 5 (bl.store:block-file-info-height-last info))))))))
