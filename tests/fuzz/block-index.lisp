(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/chain.cpp and block_index.cpp at the pin: the block
;;;; index entry decoded from a CDiskBlockIndex and asked everything, and the
;;;; block tree database (blocks/index) written and read back.

(def-suite :fuzz-block-index-tests :in :bitcoin-lisp-tests
  :description "Core fuzz chain.cpp and block_index.cpp over our block index and blocks/index")

(in-suite :fuzz-block-index-tests)

(defun %fuzz-disk-block-index-bytes (fdp)
  "A CDiskBlockIndex value: the VARINT header fields, the positions its
nStatus says are there, and an 80-byte header."
  (let* ((bb (bl.ser:make-byte-buf))
         (nstatus (consume-integral fdp :u32)))
    (bl.ser:bb-write-core-varint bb (consume-integral-in-range fdp 0 #x7fffffff))
    (bl.ser:bb-write-core-varint bb (consume-integral-in-range fdp 0 #x7fffffff))
    (bl.ser:bb-write-core-varint bb nstatus)
    (bl.ser:bb-write-core-varint bb (consume-integral fdp :u32))
    (when (logtest nstatus #x18) (bl.ser:bb-write-core-varint bb (consume-integral-in-range fdp 0 #x7fffffff)))
    (when (logtest nstatus #x08) (bl.ser:bb-write-core-varint bb (consume-integral fdp :u32)))
    (when (logtest nstatus #x10) (bl.ser:bb-write-core-varint bb (consume-integral fdp :u32)))
    (bl.ser:bb-write-bytes bb (bl.ser:serialize-block-header (consume-block-header fdp)))
    (bl.ser:bb-finish bb)))

(define-fuzz-target chain
    (buffer :core "chain.cpp:14-64" :iterations 5000 :max-len 160
            :corpus (lambda (fdp) (fdp-random-length-bytes (%fuzz-disk-block-index-bytes fdp))))
  "A CDiskBlockIndex read from the buffer answers every question Core's
CBlockIndex does -- its hash (ConstructBlockHash: the header's hash256), its
positions, its time and median time past, its nStatus -- and writes back as a
record that reads to the same entry."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (entry (consume-deserializable fdp #'bl.store:decode-disk-block-index)))
    (when entry
      (let ((header (bl.store:block-index-entry-header entry)))
        (fuzz-assert (equalp (fuzz-sabotage (bl.store:block-index-entry-hash entry))
                             (bl.crypto:hash256 (bl.ser:serialize-block-header header)))
                     "the entry's hash is not its header's")
        (bl.store:block-index-entry-file entry)
        (bl.store:block-index-entry-data-pos entry)
        (bl.store:block-index-entry-undo-pos entry)
        (bl.val:compute-median-time-past-from-entry entry)
        (let* ((nstatus (bl.store:entry-disk-status entry))
               (again (bl.store:decode-disk-block-index (bl.store:encode-disk-block-index entry))))
          ;; What a flush writes, a restart reads back: the same fields, and a
          ;; record that encodes to the same bytes.
          (fuzz-assert (= nstatus (bl.store:entry-disk-status again))
                       "nStatus ~D reads back as ~D" nstatus (bl.store:entry-disk-status again))
          (fuzz-assert (equalp (bl.store:encode-disk-block-index again)
                               (bl.store:encode-disk-block-index entry)))
          (fuzz-assert (equal (list (bl.store:block-index-entry-height again)
                                    (bl.store:block-index-entry-status again)
                                    (bl.store:block-index-entry-tx-count again)
                                    (bl.store:block-index-entry-file again)
                                    (bl.store:block-index-entry-data-pos again)
                                    (bl.store:block-index-entry-undo-pos again))
                               (list (bl.store:block-index-entry-height entry)
                                     (bl.store:block-index-entry-status entry)
                                     (bl.store:block-index-entry-tx-count entry)
                                     (bl.store:block-index-entry-file entry)
                                     (bl.store:block-index-entry-data-pos entry)
                                     (bl.store:block-index-entry-undo-pos entry)))))))))

(defparameter +fuzz-block-index-statuses+ '(:valid :header-valid :invalid :unknown))

(defun %fuzz-block-index-entry (fdp prev height)
  "Core's ConsumeBlockHeader (block_index.cpp:32-42) on regtest's nBits,
ground until it meets its own target (Core points every index at the genesis
hash instead), as an entry at HEIGHT on PREV with a fuzzed status, tx count
and positions."
  (let* ((header (grind-header-pow
                  (bl.ser:make-block-header
                   :version (consume-integral fdp :i32)
                   :prev-block (if prev (bl.store:block-index-entry-hash prev)
                                   (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
                   :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7)
                   :timestamp (consume-integral fdp :u32)
                   :bits #x207fffff
                   :nonce (consume-integral fdp :u32))))
         (data (consume-bool fdp))
         (undo (and data (consume-bool fdp))))
    (bl.store:make-block-index-entry
     :hash (bl.ser:block-header-hash header) :height height :header header :prev-entry prev
     :status (pick-value-in-array fdp +fuzz-block-index-statuses+)
     :tx-count (consume-integral-in-range fdp 0 #xffff)
     :file (when data (consume-integral-in-range fdp 0 9))
     :data-pos (when data (consume-integral fdp :u32))
     :undo-pos (when undo (consume-integral fdp :u32)))))

(defun %fuzz-block-index-corpus (fdp)
  "A buffer whose front holds N well-formed CBlockFileInfo records and whose
last byte asks for N files, the rest random: the shape a corpus gives Core's
target, which otherwise stops at the first record that does not decode."
  (let ((n (consume-integral-in-range fdp 1 5)))
    (concatenate '(simple-array (unsigned-byte 8) (*))
                 (apply #'concatenate '(simple-array (unsigned-byte 8) (*))
                        (loop repeat n
                              collect (fdp-random-length-bytes
                                       (let ((bb (bl.ser:make-byte-buf)))
                                         (dotimes (k 7)
                                           (bl.ser:bb-write-core-varint bb (consume-integral fdp :u32)))
                                         (bl.ser:bb-finish bb)))))
                 (consume-bytes fdp 300)
                 (fdp-integral-bytes `((,n 1 5))))))

(define-fuzz-target block-index
    (buffer :core "block_index.cpp:48-133" :iterations 40 :max-len 600
            :corpus #'%fuzz-block-index-corpus)
  "The block tree database written in one batch -- block file records and a
chain of block index records -- reads back what was written: each file's
record, the last file number, the reindexing flag set and cleared, an unknown
flag absent, and every block index record with its height, status, positions
and header (LoadBlockIndexGuts succeeds)."
  (let ((fdp (make-fuzzed-data-provider buffer)))
    (with-network (:regtest)
      (with-temp-directory (dir "fuzz-block-index")
        (let* ((files-count (consume-integral-in-range fdp 1 5))
               (store (bl.store:init-block-store dir))
               (cs (bl.store:init-chain-state dir :network :regtest))
               (files '()))
          ;; The block files, each a CBlockFileInfo from the buffer.
          (dotimes (i files-count)
            (let ((info (consume-deserializable fdp #'bl.store:decode-block-file-info)))
              (unless info (return-from fuzz-target/block-index))
              (setf (gethash i (bl.store:block-store-file-info store)) info)
              (push (cons i info) files)))
          ;; The block headers, a chain.
          (let ((prev nil))
            (dotimes (h (consume-integral-in-range fdp (* 2 files-count) (* 6 files-count)))
              (let ((e (%fuzz-block-index-entry fdp prev h)))
                (bl.store:add-block-index-entry cs e)
                (setf prev e))))
          (bl.store:save-header-index cs :force-full t :block-store store)
          ;; Every block file record reads back as stored, and nLastFile. The
          ;; file the store appends to (file 0 in a fresh store) is written
          ;; with the store's cursor as its nSize -- Core keeps that file's
          ;; nSize current as it writes, we keep it in the cursor -- so its
          ;; size is the one field not compared.
          (multiple-value-bind (last-file table) (bl.store:read-block-tree-file-info dir)
            (dolist (f files)
              (let ((back (gethash (car f) table)))
                (fuzz-assert (and back
                                  (equalp (fuzz-sabotage (bl.store:encode-block-file-info back))
                                          (if (zerop (car f))
                                              (bl.store:encode-block-file-info
                                               (cdr f) :size (bl.store:block-file-info-size back))
                                              (bl.store:encode-block-file-info (cdr f)))))
                             "block file ~D reads back as ~S" (car f) back)))
            (fuzz-assert (= last-file (1- files-count))
                         "the last block file reads as ~D of ~D" last-file files-count))
          ;; The reindexing flag.
          (bl.store:write-reindex-flag dir t)
          (fuzz-assert (fuzz-sabotage (bl.store:reindex-flag-set-p dir)))
          (bl.store:write-reindex-flag dir nil)
          (fuzz-assert (not (bl.store:reindex-flag-set-p dir)))
          ;; A flag nothing wrote is absent.
          (let ((name (map 'string (lambda (c) (code-char (1+ (mod (char-code c) 126))))
                           (consume-random-length-string fdp 100))))
            (fuzz-assert (not (nth-value 1 (bl.store:read-block-tree-flag dir name)))
                         "flag ~S is present" name))
          ;; LoadBlockIndexGuts: every record, as written.
          (let ((reloaded (bl.store:init-chain-state dir :network :regtest)))
            (multiple-value-bind (loaded reason) (bl.store:load-header-index reloaded)
              (fuzz-assert (fuzz-sabotage loaded) "the index did not load: ~A" reason))
            ;; LoadBlockIndex marks every descendant of a failed block failed
            ;; (node/blockstorage.cpp:489-494): so does the expected entry.
            (maphash
             (lambda (hash e)
               (let ((back (bl.store:get-block-index-entry reloaded hash))
                     (want (bl.store:decode-disk-block-index (bl.store:encode-disk-block-index e))))
                 (when (loop for p = (bl.store:block-index-entry-prev-entry e)
                               then (bl.store:block-index-entry-prev-entry p)
                             while p thereis (eq (bl.store:block-index-entry-status p) :invalid))
                   (bl.store:mark-entry-failed want))
                 (fuzz-assert (and back
                                   (equalp (fuzz-sabotage (bl.store:encode-disk-block-index back))
                                           (bl.store:encode-disk-block-index want)))
                              "block ~A at height ~D reads back as ~A, written ~A"
                              (bl.crypto:bytes-to-hex hash) (bl.store:block-index-entry-height e)
                              (and back (bl.crypto:bytes-to-hex (bl.store:encode-disk-block-index back)))
                              (bl.crypto:bytes-to-hex (bl.store:encode-disk-block-index want)))))
             (bl.store:chain-state-block-index cs))))))))
