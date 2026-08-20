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
