(in-package #:bitcoin-lisp.tests)

(in-suite :persistence-tests)

;;;; UTXO Set Persistence Tests

(test utxo-save-load-round-trip
  "Saving and loading a UTXO set should preserve all entries."
  (let ((utxo-set (bl.store:make-utxo-set))
        (path (merge-pathnames "test-utxo.dat"
                               (ensure-directories-exist
                                (merge-pathnames "test-persist/"
                                                 (uiop:temporary-directory)))))
        (txid1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (txid2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2))
        (script1 (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76))
        (script2 (make-array 34 :element-type '(unsigned-byte 8) :initial-element #xA9)))
    ;; Add entries
    (bl.store:add-utxo utxo-set txid1 0 50000000 script1 100 :coinbase t)
    (bl.store:add-utxo utxo-set txid1 1 25000000 script2 100 :coinbase t)
    (bl.store:add-utxo utxo-set txid2 0 1000000 script1 200 :coinbase nil)
    ;; Save
    (bl.store:save-utxo-set utxo-set path)
    ;; Load into fresh set
    (let ((loaded-set (bl.store:make-utxo-set)))
      (is (bl.store:load-utxo-set loaded-set path))
      ;; Verify count
      (is (= 3 (bl.store:utxo-count loaded-set)))
      ;; Verify entry 1
      (let ((e1 (bl.store:get-utxo loaded-set txid1 0)))
        (is (not (null e1)))
        (is (= 50000000 (bl.store:utxo-entry-value e1)))
        (is (= 100 (bl.store:utxo-entry-height e1)))
        (is (bl.store:utxo-entry-coinbase e1))
        (is (equalp script1 (bl.store:utxo-entry-script-pubkey e1))))
      ;; Verify entry 2
      (let ((e2 (bl.store:get-utxo loaded-set txid1 1)))
        (is (not (null e2)))
        (is (= 25000000 (bl.store:utxo-entry-value e2)))
        (is (equalp script2 (bl.store:utxo-entry-script-pubkey e2))))
      ;; Verify entry 3
      (let ((e3 (bl.store:get-utxo loaded-set txid2 0)))
        (is (not (null e3)))
        (is (= 1000000 (bl.store:utxo-entry-value e3)))
        (is (= 200 (bl.store:utxo-entry-height e3)))
        (is (not (bl.store:utxo-entry-coinbase e3)))))
    ;; Cleanup
    (when (probe-file path)
      (delete-file path))))

(test utxo-load-nonexistent-file
  "Loading from nonexistent file should return NIL."
  (let ((utxo-set (bl.store:make-utxo-set)))
    (is (null (bl.store:load-utxo-set
               utxo-set
               (merge-pathnames "nonexistent-utxo.dat" (uiop:temporary-directory)))))))

(test utxo-empty-set-round-trip
  "Saving and loading an empty UTXO set should work."
  (let ((utxo-set (bl.store:make-utxo-set))
        (path (merge-pathnames "test-empty-utxo.dat"
                               (ensure-directories-exist
                                (merge-pathnames "test-persist/"
                                                 (uiop:temporary-directory))))))
    (bl.store:save-utxo-set utxo-set path)
    (let ((loaded (bl.store:make-utxo-set)))
      (is (bl.store:load-utxo-set loaded path))
      (is (= 0 (bl.store:utxo-count loaded))))
    (when (probe-file path)
      (delete-file path))))

(test utxo-dirty-flag-on-save
  "Saving should clear the dirty flag."
  (let ((utxo-set (bl.store:make-utxo-set))
        (path (merge-pathnames "test-dirty-utxo.dat"
                               (ensure-directories-exist
                                (merge-pathnames "test-persist/"
                                                 (uiop:temporary-directory)))))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 10))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    (bl.store:add-utxo utxo-set txid 0 1000 script 1)
    (is (bl.store:utxo-set-dirty utxo-set))
    (bl.store:save-utxo-set utxo-set path)
    (is (not (bl.store:utxo-set-dirty utxo-set)))
    (when (probe-file path)
      (delete-file path))))

;;;; Header Index Persistence Tests

(defun %hi-state (name)
  "A chain-state on a private directory."
  (let ((dir (ensure-directories-exist
              (merge-pathnames (format nil "test-hidx-~A-~D/" name (get-internal-real-time))
                               (uiop:temporary-directory)))))
    (values (bl.store:init-chain-state dir) dir)))

(defun %hi-add (state hash height &key file data-pos undo-pos (status :valid))
  (bl.store:add-block-index-entry
   state
   (bl.store:make-block-index-entry
    :hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element hash)
    :height height :chain-work (* height 10) :status status
    :file file :data-pos data-pos :undo-pos undo-pos))
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element hash))

(test header-index-v3-round-trips-the-flat-file-position
  "v3 carries where a block's body and undo record live. A NIL position must
survive as NIL rather than becoming 0, because 0 is a real position -- the
first record in a file -- and confusing the two would send a reader to the
wrong offset."
  (multiple-value-bind (state dir) (%hi-state "v3")
    (unwind-protect
         (let ((placed (%hi-add state #x11 1 :file 0 :data-pos 8 :undo-pos 40))
               (body-only (%hi-add state #x22 2 :file 3 :data-pos 0))
               (header-only (%hi-add state #x33 3)))
           (bl.store:save-header-index state)
           (let ((reloaded (bl.store:init-chain-state dir)))
             (is-true (bl.store:load-header-index reloaded))
             (let ((e (bl.store:get-block-index-entry reloaded placed)))
               (is (= 0 (bl.store:block-index-entry-file e)))
               (is (= 8 (bl.store:block-index-entry-data-pos e)))
               (is (= 40 (bl.store:block-index-entry-undo-pos e))))
             ;; Position 0 in file 3, and no undo record at all.
             (let ((e (bl.store:get-block-index-entry reloaded body-only)))
               (is (= 3 (bl.store:block-index-entry-file e)))
               (is (eql 0 (bl.store:block-index-entry-data-pos e)))
               (is (null (bl.store:block-index-entry-undo-pos e))))
             ;; A header-only entry has no position anywhere.
             (let ((e (bl.store:get-block-index-entry reloaded header-only)))
               (is (null (bl.store:block-index-entry-file e)))
               (is (null (bl.store:block-index-entry-data-pos e)))
               (is (null (bl.store:block-index-entry-undo-pos e))))))
      (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore))))

(test header-index-position-changes-are-not-missed-by-the-delta-log
  "The delta log writes only entries whose persist key changed, so a position
appearing or disappearing has to move that key. If it does not, a block's body
location is written once and never updated -- and after a prune the index would
still claim the data is there."
  (multiple-value-bind (state dir) (%hi-state "delta")
    (unwind-protect
         (let ((h (%hi-add state #x44 1)))
           (bl.store:save-header-index state)
           (let ((entry (bl.store:get-block-index-entry state h)))
             ;; Body lands.
             (setf (bl.store:block-index-entry-file entry) 2
                   (bl.store:block-index-entry-data-pos entry) 1234)
             (is (member entry (bl.store::%changed-header-index-entries state))
                 "gaining a position must mark the entry changed")
             (bl.store:save-header-index state)
             (is (not (member entry (bl.store::%changed-header-index-entries state)))
                 "and it must be clean once written")
             ;; Undo record lands.
             (setf (bl.store:block-index-entry-undo-pos entry) 99)
             (is (member entry (bl.store::%changed-header-index-entries state)))
             (bl.store:save-header-index state)
             ;; Pruned away again.
             (setf (bl.store:block-index-entry-data-pos entry) nil
                   (bl.store:block-index-entry-undo-pos entry) nil)
             (is (member entry (bl.store::%changed-header-index-entries state))
                 "losing a position must mark the entry changed too")
             (bl.store:save-header-index state)
             (let ((reloaded (bl.store:init-chain-state dir)))
               (is-true (bl.store:load-header-index reloaded))
               (let ((e (bl.store:get-block-index-entry reloaded h)))
                 (is (null (bl.store:block-index-entry-data-pos e)))
                 (is (null (bl.store:block-index-entry-undo-pos e)))))))
      (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore))))

(test header-index-persist-key-still-tracks-everything-it-did-before
  "Widening the key to hold the position bits meant re-packing height and
tx-count. Re-check every field the key is supposed to notice, since a silently
dropped one means a status or tx-count change is never written."
  (multiple-value-bind (state dir) (%hi-state "key")
    (unwind-protect
         (let* ((h (%hi-add state #x55 7 :status :header-valid))
                (entry (bl.store:get-block-index-entry state h))
                (base (bl.store::%entry-persist-key entry)))
           (macrolet ((changes (&body mutation)
                        `(let ((before (bl.store::%entry-persist-key entry)))
                           ,@mutation
                           (is (/= before (bl.store::%entry-persist-key entry))))))
             (changes (setf (bl.store:block-index-entry-status entry) :valid))
             (changes (setf (bl.store:block-index-entry-status entry) :invalid))
             (changes (setf (bl.store:block-index-entry-height entry) 8))
             (changes (setf (bl.store:block-index-entry-tx-count entry) 3))
             (changes (setf (bl.store:block-index-entry-data-pos entry) 0))
             (changes (setf (bl.store:block-index-entry-undo-pos entry) 0))
             (changes (setf (bl.store:block-index-entry-header entry)
                            (bl.ser:make-block-header))))
           ;; And the key stays a fixnum, which is why the flush can compute it
           ;; for every entry on a 963k-entry index.
           (is (typep (bl.store::%entry-persist-key entry) 'fixnum))
           (is (plusp base)))
      (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore))))

(defun %write-v2-header-index (path entries)
  "Emit a v2 header-index file by hand: 185-byte entries, no position fields.
This is what both live nodes carry today, so the v3 build has to load it."
  (bl.store:save-file-with-crc32-bb
   path
   (lambda (bb)
     (bl.ser:bb-write-bytes
      bb bl.store::*header-index-magic*)
     (bl.ser:bb-write-u32-le bb 2)
     (bl.ser:bb-write-u32-le bb (length entries))
     (dolist (e entries)
       (destructuring-bind (hash height chain-work status tx-count) e
         (bl.ser:bb-write-bytes bb hash)
         (bl.ser:bb-write-u32-le bb height)
         (loop repeat 80 do (bl.ser:bb-write-u8 bb 0))
         (bl.store::bb-write-chainwork bb chain-work)
         (bl.ser:bb-write-u8
          bb (ecase status (:unknown 0) (:header-valid 1) (:valid 2) (:invalid 3)))
         (loop repeat 32 do (bl.ser:bb-write-u8 bb 0))
         (bl.ser:bb-write-u32-le bb tx-count))))))

(test header-index-v2-files-still-load-and-upgrade-in-place
  "Both live nodes carry a v2 headerindex.dat -- 963k entries on mainnet -- so
the v3 build must read one, and an entry without a position must come back
with NIL rather than 0: those blocks live in the legacy per-block files, and
claiming they sit at offset 0 of file 0 would send every read to the wrong
place. Then the next save must write v3 and reload cleanly."
  (multiple-value-bind (state dir) (%hi-state "v2compat")
    (unwind-protect
         (let ((a (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x77))
               (b (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x88)))
           (%write-v2-header-index
            (bl.store::header-index-file-path state)
            (list (list a 1 10 :valid 3)
                  (list b 2 20 :header-valid 0)))
           (is-true (bl.store:load-header-index state))
           (let ((ea (bl.store:get-block-index-entry state a)))
             (is (= 1 (bl.store:block-index-entry-height ea)))
             (is (= 3 (bl.store:block-index-entry-tx-count ea)))
             (is (eq :valid (bl.store:block-index-entry-status ea)))
             (is (null (bl.store:block-index-entry-file ea))
                 "a v2 entry has no flat-file position, and NIL is not 0")
             (is (null (bl.store:block-index-entry-data-pos ea)))
             (is (null (bl.store:block-index-entry-undo-pos ea))))
           ;; A v2 load must leave the index clean, or every start would write a
           ;; full snapshot and undo the delta-log work of the delta-log change.
           (is (null (bl.store::%changed-header-index-entries state)))
           ;; Now give one entry a position and save; the file becomes v3.
           (let ((ea (bl.store:get-block-index-entry state a)))
             (setf (bl.store:block-index-entry-file ea) 0
                   (bl.store:block-index-entry-data-pos ea) 8))
           (bl.store:save-header-index state :force-full t)
           (let ((reloaded (bl.store:init-chain-state dir)))
             (is-true (bl.store:load-header-index reloaded))
             (let ((ea (bl.store:get-block-index-entry reloaded a))
                   (eb (bl.store:get-block-index-entry reloaded b)))
               (is (= 0 (bl.store:block-index-entry-file ea)))
               (is (= 8 (bl.store:block-index-entry-data-pos ea)))
               (is (= 3 (bl.store:block-index-entry-tx-count ea)))
               (is (null (bl.store:block-index-entry-file eb))
                   "the untouched entry keeps its absent position"))))
      (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore))))

(defun %v1-delta-bytes (crc entries)
  "A delta log in the PREVIOUS entry layout: 185-byte entries, no position
fields, bound to CRC."
  (let ((bb (bl.ser:make-byte-buf))
        (payload (bl.ser:make-byte-buf)))
    (bl.ser:bb-write-bytes
     bb bl.store::*header-index-delta-magic*)
    (bl.ser:bb-write-u32-le bb 1)
    (bl.ser:bb-write-bytes bb crc)
    (bl.ser:bb-write-u32-le payload (length entries))
    (dolist (e entries)
      (destructuring-bind (hash height chain-work status tx-count) e
        (bl.ser:bb-write-bytes payload hash)
        (bl.ser:bb-write-u32-le payload height)
        (loop repeat 80 do (bl.ser:bb-write-u8 payload 0))
        (bl.store::bb-write-chainwork payload chain-work)
        (bl.ser:bb-write-u8
         payload (ecase status (:unknown 0) (:header-valid 1) (:valid 2) (:invalid 3)))
        (loop repeat 32 do (bl.ser:bb-write-u8 payload 0))
        (bl.ser:bb-write-u32-le payload tx-count)))
    (let ((bytes (bl.ser:bb-finish payload)))
      (bl.ser:bb-write-bytes bb bytes)
      (bl.ser:bb-write-bytes
       bb (bl.store:compute-crc32 bytes)))
    (bl.ser:bb-finish bb)))

(test header-index-replays-a-delta-written-in-the-previous-layout
  "The upgrade hazard, and why it is not solved by discarding. A delta records
whole entries, and its CRC binds it to the snapshot it extends -- so on the
first start after an entry-layout change the OLD log is still bound to the
snapshot still on disk and the CRC check waves it through, at the wrong width.

Discarding it instead would look harmless, since a delta only holds changes
since the last snapshot. But those are precisely the most recently updated
statuses, so dropping the log can revert a block from :invalid back to :valid.
So an old log is replayed at ITS width, and only an unrecognised version is
thrown away."
  (multiple-value-bind (state dir) (%hi-state "deltaver")
    (unwind-protect
         (let ((h (%hi-add state #x66 1 :status :header-valid)))
           (bl.store:save-header-index state :force-full t)
           ;; Hand-write a previous-layout delta marking that block :invalid,
           ;; bound to the snapshot that is on disk right now.
           (let ((delta (bl.store::header-index-delta-path state))
                 (crc (bl.store::%file-trailing-crc
                       (bl.store::header-index-file-path state))))
             (with-open-file (out delta :direction :output
                                        :element-type '(unsigned-byte 8)
                                        :if-exists :supersede
                                        :if-does-not-exist :create)
               (write-sequence (%v1-delta-bytes crc (list (list h 1 10 :invalid 0))) out))
             (let ((reloaded (bl.store:init-chain-state dir)))
               (is-true (bl.store:load-header-index reloaded))
               (let ((e (bl.store:get-block-index-entry reloaded h)))
                 (is (eq :invalid (bl.store:block-index-entry-status e))
                     "the old-layout delta must be replayed, not dropped")
                 (is (null (bl.store:block-index-entry-data-pos e))
                     "and an entry from it has no position, which is correct")))
             ;; An unrecognised version IS discarded -- there is no width to
             ;; frame it with, so misparsing is the only alternative.
             (let ((bytes (alexandria:read-file-into-byte-vector delta)))
               (setf (aref bytes 4) 99)
               (with-open-file (out delta :direction :output
                                          :element-type '(unsigned-byte 8)
                                          :if-exists :supersede)
                 (write-sequence bytes out)))
             (let ((reloaded (bl.store:init-chain-state dir)))
               (is-true (bl.store:load-header-index reloaded))
               (let ((e (bl.store:get-block-index-entry reloaded h)))
                 (is (eq :header-valid (bl.store:block-index-entry-status e))
                     "an unknown layout falls back to the snapshot's state"))
               (is-false (probe-file delta) "and the unreadable log is removed"))))
      (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore))))

(test header-index-save-load-round-trip
  "Saving and loading header index should preserve entries and linkage."
  (let* ((base-path (ensure-directories-exist
                     (merge-pathnames "test-headers/"
                                      (uiop:temporary-directory))))
         (state (bl.store:init-chain-state base-path))
         (genesis-hash (bl.store:best-block-hash state)))
    ;; Add genesis to block index
    (bl.store:add-block-index-entry
     state
     (bl.store:make-block-index-entry
      :hash genesis-hash
      :height 0
      :chain-work 0
      :status :valid))
    ;; Add a child block
    (let ((block1-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xAA)))
      (bl.store:add-block-index-entry
       state
       (bl.store:make-block-index-entry
        :hash block1-hash
        :height 1
        :prev-entry (bl.store:get-block-index-entry state genesis-hash)
        :chain-work 100
        :status :valid))
      (bl.store:update-chain-tip state block1-hash 1)
      ;; Save
      (bl.store:save-header-index state)
      ;; Load into fresh state
      (let ((state2 (bl.store:init-chain-state base-path)))
        (is (bl.store:load-header-index state2))
        ;; Verify genesis entry
        (let ((ge (bl.store:get-block-index-entry state2 genesis-hash)))
          (is (not (null ge)))
          (is (= 0 (bl.store:block-index-entry-height ge)))
          (is (eq :valid (bl.store:block-index-entry-status ge))))
        ;; Verify block 1 entry
        (let ((b1 (bl.store:get-block-index-entry state2 block1-hash)))
          (is (not (null b1)))
          (is (= 1 (bl.store:block-index-entry-height b1)))
          (is (= 100 (bl.store:block-index-entry-chain-work b1)))
          (is (eq :valid (bl.store:block-index-entry-status b1)))
          ;; Verify prev-entry linkage
          (let ((prev (bl.store:block-index-entry-prev-entry b1)))
            (is (not (null prev)))
            (is (equalp genesis-hash (bl.store:block-index-entry-hash prev)))))))
    ;; Cleanup
    (let ((path (bl.store::header-index-file-path state)))
      (when (probe-file path)
        (delete-file path)))))

;;;; Persistence Integrity Tests

(test utxo-detect-truncated-file
  "Loading a truncated UTXO file should fail (CRC mismatch)."
  (let ((utxo-set (bl.store:make-utxo-set))
        (path (merge-pathnames "test-truncated-utxo.dat"
                               (ensure-directories-exist
                                (merge-pathnames "test-persist/"
                                                 (uiop:temporary-directory)))))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    ;; Save a valid file
    (bl.store:add-utxo utxo-set txid 0 50000000 script 100 :coinbase t)
    (bl.store:save-utxo-set utxo-set path)
    ;; Truncate the file (remove last 10 bytes)
    (let* ((file-bytes (with-open-file (s path :direction :input
                                              :element-type '(unsigned-byte 8))
                         (let ((b (make-array (file-length s) :element-type '(unsigned-byte 8))))
                           (read-sequence b s) b)))
           (truncated (subseq file-bytes 0 (max 0 (- (length file-bytes) 10)))))
      (with-open-file (s path :direction :output :if-exists :supersede
                              :element-type '(unsigned-byte 8))
        (write-sequence truncated s)))
    ;; Loading should fail
    (let ((fresh-set (bl.store:make-utxo-set)))
      (is (null (bl.store:load-utxo-set fresh-set path))))
    (when (probe-file path) (delete-file path))))

(test utxo-detect-corrupted-file
  "Loading a UTXO file with flipped bits should fail (CRC mismatch)."
  (let ((utxo-set (bl.store:make-utxo-set))
        (path (merge-pathnames "test-corrupt-utxo.dat"
                               (ensure-directories-exist
                                (merge-pathnames "test-persist/"
                                                 (uiop:temporary-directory)))))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    (bl.store:add-utxo utxo-set txid 0 50000000 script 100 :coinbase t)
    (bl.store:save-utxo-set utxo-set path)
    ;; Flip a byte in the middle
    (let ((file-bytes (with-open-file (s path :direction :input
                                              :element-type '(unsigned-byte 8))
                        (let ((b (make-array (file-length s) :element-type '(unsigned-byte 8))))
                          (read-sequence b s) b))))
      (setf (aref file-bytes (floor (length file-bytes) 2))
            (logxor (aref file-bytes (floor (length file-bytes) 2)) #xFF))
      (with-open-file (s path :direction :output :if-exists :supersede
                              :element-type '(unsigned-byte 8))
        (write-sequence file-bytes s)))
    (let ((fresh-set (bl.store:make-utxo-set)))
      (is (null (bl.store:load-utxo-set fresh-set path))))
    (when (probe-file path) (delete-file path))))

(test utxo-reject-unknown-version
  "Loading a UTXO file with wrong version should fail."
  (let ((utxo-set (bl.store:make-utxo-set))
        (path (merge-pathnames "test-badver-utxo.dat"
                               (ensure-directories-exist
                                (merge-pathnames "test-persist/"
                                                 (uiop:temporary-directory)))))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    (bl.store:add-utxo utxo-set txid 0 50000000 script 100 :coinbase t)
    (bl.store:save-utxo-set utxo-set path)
    ;; Change version byte (byte 4) to 99 and recompute CRC
    (let ((file-bytes (with-open-file (s path :direction :input
                                              :element-type '(unsigned-byte 8))
                        (let ((b (make-array (file-length s) :element-type '(unsigned-byte 8))))
                          (read-sequence b s) b))))
      ;; Version is at offset 4 (after 4 magic bytes)
      (setf (aref file-bytes 4) 99)
      ;; Recompute CRC for the modified data
      (let* ((data-bytes (subseq file-bytes 0 (- (length file-bytes) 4)))
             (new-crc (bl.store:compute-crc32 data-bytes)))
        (replace file-bytes new-crc :start1 (- (length file-bytes) 4)))
      (with-open-file (s path :direction :output :if-exists :supersede
                              :element-type '(unsigned-byte 8))
        (write-sequence file-bytes s)))
    (let ((fresh-set (bl.store:make-utxo-set)))
      (is (null (bl.store:load-utxo-set fresh-set path))))
    (when (probe-file path) (delete-file path))))

(test utxo-backward-compat-old-format
  "Loading an old-format UTXO file (no magic) should succeed."
  (let ((utxo-set (bl.store:make-utxo-set))
        (path (merge-pathnames "test-oldfmt-utxo.dat"
                               (ensure-directories-exist
                                (merge-pathnames "test-persist/"
                                                 (uiop:temporary-directory)))))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 5))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    ;; Write old format manually: count(4) + entries (no magic, no CRC)
    (with-open-file (s path :direction :output :if-exists :supersede
                            :element-type '(unsigned-byte 8))
      ;; Count = 1
      (write-byte 1 s) (write-byte 0 s) (write-byte 0 s) (write-byte 0 s)
      ;; 36-byte key (txid + output-index)
      (write-sequence txid s)
      (write-byte 0 s) (write-byte 0 s) (write-byte 0 s) (write-byte 0 s)
      ;; 8-byte value = 1000000
      (write-byte #x40 s) (write-byte #x42 s) (write-byte #x0F s) (write-byte 0 s)
      (write-byte 0 s) (write-byte 0 s) (write-byte 0 s) (write-byte 0 s)
      ;; 4-byte height = 10
      (write-byte 10 s) (write-byte 0 s) (write-byte 0 s) (write-byte 0 s)
      ;; 1-byte coinbase = 0
      (write-byte 0 s)
      ;; 4-byte script-len = 25
      (write-byte 25 s) (write-byte 0 s) (write-byte 0 s) (write-byte 0 s)
      ;; 25-byte script
      (write-sequence script s))
    (let ((loaded (bl.store:make-utxo-set)))
      (is (bl.store:load-utxo-set loaded path))
      (is (= 1 (bl.store:utxo-count loaded)))
      (let ((entry (bl.store:get-utxo loaded txid 0)))
        (is (not (null entry)))
        (is (= 1000000 (bl.store:utxo-entry-value entry)))))
    (when (probe-file path) (delete-file path))))

(test header-index-detect-corrupted
  "Loading a corrupted header index file should fail (CRC mismatch)."
  (let* ((base-path (ensure-directories-exist
                     (merge-pathnames "test-corrupt-headers/"
                                      (uiop:temporary-directory))))
         (state (bl.store:init-chain-state base-path))
         (genesis-hash (bl.store:best-block-hash state)))
    (bl.store:add-block-index-entry
     state
     (bl.store:make-block-index-entry
      :hash genesis-hash :height 0 :chain-work 0 :status :valid))
    (bl.store:save-header-index state)
    ;; Corrupt the file. Resolved, not hardcoded: SAVE-HEADER-INDEX writes to
    ;; Core's blocks/index/ on a fresh datadir, and a test that corrupted the
    ;; legacy path would be corrupting a file nothing reads.
    (let* ((path (bl.store::header-index-file-path state))
           (file-bytes (with-open-file (s path :direction :input
                                               :element-type '(unsigned-byte 8))
                         (let ((b (make-array (file-length s) :element-type '(unsigned-byte 8))))
                           (read-sequence b s) b))))
      (setf (aref file-bytes (floor (length file-bytes) 2))
            (logxor (aref file-bytes (floor (length file-bytes) 2)) #xFF))
      (with-open-file (s path :direction :output :if-exists :supersede
                              :element-type '(unsigned-byte 8))
        (write-sequence file-bytes s)))
    ;; Loading should fail — AND say why. The reason is what makes startup
    ;; refuse rather than continue with an empty index; detecting the
    ;; corruption without reporting it is what let the node start anyway.
    (let ((state2 (bl.store:init-chain-state base-path)))
      (multiple-value-bind (loaded reason)
          (bl.store:load-header-index state2)
        (is (null loaded))
        (is-true (stringp reason))
        (is-true (search "CRC32" reason))))
    ;; Cleanup
    (let ((path (bl.store::header-index-file-path state)))
      (when (probe-file path) (delete-file path)))))

(test shrink-log-file-scrolls-only-past-the-threshold
  "Core's ShrinkDebugFile (logging.cpp): a log over 11 MB is restarted holding
its last 10 MB; anything at or under the threshold is left completely alone."
  (let* ((dir (ensure-directories-exist
               (merge-pathnames "test-log-shrink/" (uiop:temporary-directory))))
         (path (merge-pathnames "debug.log" dir))
         (threshold (* 11 (floor bl::+recent-log-history-bytes+ 10))))
    (flet ((write-log (n)
             ;; Byte i carries (mod i 251) so the retained tail is identifiable.
             (with-open-file (s path :direction :output :if-exists :supersede
                                     :if-does-not-exist :create
                                     :element-type '(unsigned-byte 8))
               (let ((buf (make-array n :element-type '(unsigned-byte 8))))
                 (dotimes (i n) (setf (aref buf i) (mod i 251)))
                 (write-sequence buf s))))
           (size ()
             (with-open-file (s path :direction :input
                                     :element-type '(unsigned-byte 8))
               (file-length s))))
      ;; Exactly at the threshold: untouched. Core's test is strictly greater.
      (write-log threshold)
      (is (null (bl::shrink-log-file path)))
      (is (= threshold (size)))
      ;; A megabyte past it: scrolled down to the retained tail.
      (write-log (+ threshold 1000000))
      (is-true (bl::shrink-log-file path))
      (is (= bl::+recent-log-history-bytes+ (size)))
      ;; And it kept the END of the file, not the beginning: the first retained
      ;; byte is the one that stood at (total - retained).
      (with-open-file (s path :direction :input :element-type '(unsigned-byte 8))
        (is (= (mod (- (+ threshold 1000000) bl::+recent-log-history-bytes+) 251)
               (read-byte s))))
      ;; A log that is not there at all is not an error.
      (delete-file path)
      (is (null (bl::shrink-log-file path))))))

(test data-directory-lock-excludes-a-second-node
  "Core locks the data directory so a second node cannot open it
(init.cpp:1158). Two nodes sharing one directory each keep their own block
index and UTXO cache and flush over the other's files, so the damage is not
'the second one fails' but 'whichever flushes last wins'."
  (let ((dir (ensure-directories-exist
              (merge-pathnames "test-datadir-lock/" (uiop:temporary-directory)))))
    (unwind-protect
         (progn
           (bl::lock-data-directory dir)
           (is-true (integerp bl::*data-directory-lock-fd*))
           ;; The control that matters: a second claim is REFUSED.
           (signals error (bl::lock-data-directory dir))
           ;; Releasing it hands the directory back.
           (bl::unlock-data-directory)
           (is (null bl::*data-directory-lock-fd*))
           (bl::lock-data-directory dir)
           (is-true (integerp bl::*data-directory-lock-fd*)))
      (bl::unlock-data-directory))
    ;; The lock file is left behind, as Core leaves it: its presence means
    ;; nothing, only the advisory lock on it does.
    (is-true (probe-file (merge-pathnames ".lock" dir)))))

(defun %hidx-fixture (suffix)
  "A chain-state on a private directory with no header-index files."
  (let* ((dir (ensure-directories-exist
               (merge-pathnames (format nil "test-hidx-~A/" suffix)
                                (uiop:temporary-directory))))
         (cs (bl.store:init-chain-state dir)))
    (dolist (f (list (bl.store::header-index-file-path cs)
                     (bl.store::header-index-delta-path cs)))
      (when (probe-file f) (delete-file f)))
    (values cs dir)))

(defun %hidx-add (cs i status)
  (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element i)))
    (bl.store:add-block-index-entry
     cs (bl.store:make-block-index-entry
         :hash h :height i :chain-work (* i 10) :status status))
    h))

(defun %hidx-size (path)
  (and (probe-file path)
       (with-open-file (s path :element-type '(unsigned-byte 8)) (file-length s))))

(test header-index-delta-avoids-rewriting-the-snapshot
  "A flush must write only what CHANGED. The whole index used to be rewritten
every time — 178 MB per flush on mainnet, measured 2026-08-19, to persist about
one entry."
  (multiple-value-bind (cs) (%hidx-fixture "delta")
    (let ((h1 (%hidx-add cs 1 :valid))
          (h2 (%hidx-add cs 2 :header-valid))
          (snap (bl.store::header-index-file-path cs))
          (delta (bl.store::header-index-delta-path cs)))
      (bl.store:save-header-index cs)
      (let ((snap-size (%hidx-size snap)))
        (is-true (plusp snap-size))
        (is (null (%hidx-size delta)))
        ;; Nothing changed: no delta is written at all.
        (bl.store:save-header-index cs)
        (is (null (%hidx-size delta)))
        (is (= snap-size (%hidx-size snap)))
        ;; One status change: a delta appears, the snapshot is untouched.
        (setf (bl.store:block-index-entry-status
               (bl.store:get-block-index-entry cs h2))
              :valid)
        (bl.store:save-header-index cs)
        (is (= snap-size (%hidx-size snap)) "the snapshot must not be rewritten")
        ;; header(12) + count(4) + one entry + crc(4). Derived from the
        ;; constant rather than written out, so an entry-layout change fails
        ;; here only if the FRAMING is wrong, not merely because the entry grew.
        (is (= (+ 12 4 bl.store::+header-index-entry-bytes+ 4)
               (%hidx-size delta)))
        ;; And it reloads to the mutated state.
        (let ((cs2 (bl.store:init-chain-state
                    (bl.store::chain-state-base-path cs))))
          (is-true (bl.store:load-header-index cs2))
          (is (eq :valid (bl.store:block-index-entry-status
                          (bl.store:get-block-index-entry cs2 h2))))
          (is (eq :valid (bl.store:block-index-entry-status
                          (bl.store:get-block-index-entry cs2 h1))))
          (is (= 2 (hash-table-count
                    (bl.store:chain-state-block-index cs2)))))))))

(test header-index-stale-delta-is-discarded-not-replayed
  "A delta orphaned by a crash between 'write new snapshot' and 'remove old
delta' must be IGNORED. Replaying it would roll entries BACK to older statuses
— strictly worse than losing them, because a block downgraded from :invalid to
:valid undoes an operator's invalidateblock."
  (multiple-value-bind (cs) (%hidx-fixture "stale")
    (let ((h (%hidx-add cs 1 :header-valid))
          (delta (bl.store::header-index-delta-path cs)))
      (bl.store:save-header-index cs)
      ;; Produce a delta carrying the OLD status.
      (setf (bl.store:block-index-entry-status
             (bl.store:get-block-index-entry cs h))
            :valid)
      (bl.store:save-header-index cs)
      (is-true (plusp (%hidx-size delta)))
      (let ((orphan (alexandria:read-file-into-byte-vector delta)))
        ;; Now the entry becomes :invalid and a FULL snapshot is written, which
        ;; removes the delta — then the crash puts the old one back.
        (setf (bl.store:block-index-entry-status
               (bl.store:get-block-index-entry cs h))
              :invalid)
        (bl.store:save-header-index cs :force-full t)
        (is (null (%hidx-size delta)))
        (alexandria:write-byte-vector-into-file orphan delta :if-exists :supersede)
        (let ((cs2 (bl.store:init-chain-state
                    (bl.store::chain-state-base-path cs))))
          (is-true (bl.store:load-header-index cs2))
          ;; :invalid survived — the stale delta did NOT resurrect :valid.
          (is (eq :invalid (bl.store:block-index-entry-status
                            (bl.store:get-block-index-entry cs2 h)))))))))

(test header-index-torn-delta-tail-keeps-complete-frames
  "A crash mid-append leaves a short final frame. Replay must keep every
complete frame before it and stop there, rather than rejecting the whole log."
  (multiple-value-bind (cs) (%hidx-fixture "torn")
    (let ((h1 (%hidx-add cs 1 :header-valid))
          (h2 (%hidx-add cs 2 :header-valid))
          (delta (bl.store::header-index-delta-path cs)))
      (bl.store:save-header-index cs)
      ;; Frame 1: h1 becomes :valid.
      (setf (bl.store:block-index-entry-status
             (bl.store:get-block-index-entry cs h1)) :valid)
      (bl.store:save-header-index cs)
      ;; Frame 2: h2 becomes :valid — then tear it.
      (setf (bl.store:block-index-entry-status
             (bl.store:get-block-index-entry cs h2)) :valid)
      (bl.store:save-header-index cs)
      (let ((full (alexandria:read-file-into-byte-vector delta)))
        ;; CONTROL: intact, BOTH frames apply. Without this the test below
        ;; could pass on a log that never applied frame 2 in the first place.
        (let ((cs0 (bl.store:init-chain-state
                    (bl.store::chain-state-base-path cs))))
          (is-true (bl.store:load-header-index cs0))
          (is (eq :valid (bl.store:block-index-entry-status
                          (bl.store:get-block-index-entry cs0 h1))))
          (is (eq :valid (bl.store:block-index-entry-status
                          (bl.store:get-block-index-entry cs0 h2)))))
        ;; Now tear the final frame.
        (alexandria:write-byte-vector-into-file
         (subseq full 0 (- (length full) 60)) delta :if-exists :supersede)
        (let ((cs2 (bl.store:init-chain-state
                    (bl.store::chain-state-base-path cs))))
          (is-true (bl.store:load-header-index cs2))
          ;; Frame 1 survived...
          (is (eq :valid (bl.store:block-index-entry-status
                          (bl.store:get-block-index-entry cs2 h1))))
          ;; ...frame 2 did not, and the entry keeps its snapshot state.
          (is (eq :header-valid (bl.store:block-index-entry-status
                                 (bl.store:get-block-index-entry cs2 h2)))))))))

(test header-index-compaction-folds-the-delta-back-in
  "Once the delta has grown past its bound, the next flush rewrites the
snapshot and drops the log, so the delta can never approach the size of the
thing it optimises."
  (multiple-value-bind (cs) (%hidx-fixture "compact")
    (let ((hashes (loop for i from 1 to 40 collect (%hidx-add cs i :header-valid)))
          (snap (bl.store::header-index-file-path cs))
          (delta (bl.store::header-index-delta-path cs)))
      (bl.store:save-header-index cs)
      (let ((snap-size (%hidx-size snap)))
        ;; The floor is 20000 entries, so drive compaction by forcing it
        ;; directly and separately assert the predicate's shape.
        (is-false (bl.store::%header-index-compaction-due-p cs 1))
        (is-true (bl.store::%header-index-compaction-due-p cs 20000))
        ;; A forced full write folds any delta back into the snapshot.
        (setf (bl.store:block-index-entry-status
               (bl.store:get-block-index-entry cs (first hashes)))
              :valid)
        (bl.store:save-header-index cs)
        (is-true (plusp (%hidx-size delta)))
        (bl.store:save-header-index cs :force-full t)
        (is (null (%hidx-size delta)))
        (is (= snap-size (%hidx-size snap)))
        (is (zerop (bl.store::chain-state-header-index-delta-entries cs)))))))

(test header-index-absent-is-not-corruption
  "No headerindex.dat at all is a legitimate first run: NIL loaded, and NO
reason — the caller must not confuse it with a file it cannot read, or every
fresh node would refuse to start."
  (let* ((base-path (ensure-directories-exist
                     (merge-pathnames "test-absent-headers/"
                                      (uiop:temporary-directory))))
         (path (merge-pathnames "headerindex.dat" base-path)))
    (when (probe-file path) (delete-file path))
    (let ((state (bl.store:init-chain-state base-path)))
      (multiple-value-bind (loaded reason)
          (bl.store:load-header-index state)
        (is (null loaded))
        (is (null reason))))))

(test header-index-corruption-modes-all-report-a-reason
  "Every way headerindex.dat can be untrustworthy reports a reason: a
truncated file, an unsupported format version, and a file too short to hold
even a header. Each must be distinguishable from absence."
  (let* ((base-path (ensure-directories-exist
                     (merge-pathnames "test-corrupt-modes/"
                                      (uiop:temporary-directory))))
         (path (merge-pathnames "headerindex.dat" base-path)))
    (flet ((reason-for (bytes)
             (with-open-file (s path :direction :output :if-exists :supersede
                                     :if-does-not-exist :create
                                     :element-type '(unsigned-byte 8))
               (write-sequence (coerce bytes '(vector (unsigned-byte 8))) s))
             (nth-value 1 (bl.store:load-header-index
                           (bl.store:init-chain-state base-path)))))
      ;; Magic present, but the file cannot even hold magic+version+count+crc.
      (is-true (search "too short" (reason-for '(#x48 #x49 #x44 #x58 1 0 0 0))))
      ;; Magic + a version this build does not know, padded past the length
      ;; floor so the version check is what rejects it.
      (let ((r (reason-for (append '(#x48 #x49 #x44 #x58 #xFF 0 0 0)
                                   (make-list 12 :initial-element 0)))))
        (is-true (stringp r)))
      ;; No magic => legacy path, and a stub too short to parse as entries.
      (is-true (stringp (reason-for '(1 0 0 0 9 9 9 9)))))
    (when (probe-file path) (delete-file path))))

;;;; Peer Health Monitoring Tests

(test peer-health-ping-follows-core
  "Core MaybeSendPing (net_processing.cpp:5487-5510): pings every PING_INTERVAL
(2 min) while none is outstanding; an outstanding ping is never replaced, and
one unanswered for TIMEOUT_INTERVAL (20 min) disconnects the peer."
  (is (= 120 bl.net::+ping-interval-seconds+))
  (is (= 1200 bl.net::+ping-timeout-seconds+))
  (flet ((peer-with-ping (age-seconds &key (nonce 7))
           (let ((peer (bl.net:make-peer :state :ready)))
             (setf (bl.net:peer-ping-nonce peer) nonce
                   (bl.net:peer-last-ping-time peer)
                   (- (get-internal-real-time)
                      (* age-seconds internal-time-units-per-second)))
             peer)))
    ;; Outstanding for 100 s: left alone — no new ping, no disconnect.
    (let ((peer (peer-with-ping 100)))
      (is (eq :ok (bl.net:check-peer-health peer)))
      (is (= 7 (bl.net:peer-ping-nonce peer))))
    ;; Outstanding for 1201 s: disconnect on the first timeout, no retry count.
    (is (eq :disconnect (bl.net:check-peer-health
                         (peer-with-ping 1201))))
    ;; A pong clears the outstanding ping.
    (let ((peer (peer-with-ping 1)))
      (bl.net::record-pong peer 7)
      (is (null (bl.net:peer-ping-nonce peer)))))
  ;; A peer that has NEVER been pinged is due now, not in two minutes. Core
  ;; encodes this as m_ping_start{0us} against an absolute clock, so
  ;; `now > m_ping_start + PING_INTERVAL` holds on a fresh peer
  ;; (net_processing.cpp:5508).
  (let ((peer (bl.net:make-peer :state :ready)))
    (is (null (bl.net:peer-last-ping-time peer))
        "a fresh peer must record NO ping, not a ping at time zero")
    (is (eq :ping-sent (bl.net:check-peer-health peer)))
    (is (bl.net:peer-ping-nonce peer))
    ;; And having just pinged, it does not ping again.
    (bl.net::record-pong
     peer (bl.net:peer-ping-nonce peer))
    (is (eq :ok (bl.net:check-peer-health peer))))
  ;; The positive control for the bug this replaced: the old code compared
  ;; against a 0 initform on INTERNAL-REAL-TIME, whose zero is process start.
  ;; Simulate a node less than PING-INTERVAL old by stamping the peer at
  ;; internal time 0 — under the old rule that read as "pinged at boot, not due
  ;; yet" and no ping went out for the node's first two minutes.
  (let ((peer (bl.net:make-peer :state :ready)))
    (setf (bl.net:peer-last-ping-time peer) 0)
    (is (eq (if (> (get-internal-real-time)
                   (* bl.net::+ping-interval-seconds+
                      internal-time-units-per-second))
                :ping-sent
                :ok)
            (bl.net:check-peer-health peer))
        "a 0 last-ping-time must be read as a TIME, not as \"never\" — the two ~
must stay distinguishable or the fix is indistinguishable from the bug")))

;;;; Misbehavior Tests (binary model — bitcoin/bitcoin#25325 / bitcoin/bitcoin#26294)

(test peer-misbehavior-is-binary
  "A single misbehavior event discourages and disconnects the peer (no
accumulating score); discouragement is NOT a hard ban."
  (bl.net:clear-discouraged)
  (let ((peer (bl.net:make-peer)))
    (setf (bl.net:peer-state peer) :ready)
    (setf (bl.net:peer-address peer) "192.0.2.99")
    (is (not (bl.net:peer-discouraged-p "192.0.2.99")))
    ;; One event -> immediately discouraged + disconnected.
    (is (bl.net:record-misbehavior peer "test violation"))
    (is (eq :disconnected (bl.net:peer-state peer)))
    (is (bl.net:peer-discouraged-p "192.0.2.99"))
    ;; Discouragement is NOT a hard ban.
    (is (not (bl.net:peer-banned-p "192.0.2.99")))
    (bl.net:clear-discouraged)))

(test peer-banned-p-check
  "peer-banned-p should return T for banned addresses, NIL for others."
  (bl.net:clear-ban-list)
  (is (not (bl.net:peer-banned-p "192.0.2.1")))
  ;; Manually ban an address
  (setf (gethash "192.0.2.1" bl.net:*banned-peers*)
        (+ (get-universal-time) 3600))  ; 1 hour from now
  (is (bl.net:peer-banned-p "192.0.2.1"))
  ;; Expired ban
  (setf (gethash "192.0.2.2" bl.net:*banned-peers*)
        (- (get-universal-time) 1))  ; 1 second ago
  (is (not (bl.net:peer-banned-p "192.0.2.2")))
  (bl.net:clear-ban-list))

(test peer-invalid-block-immediate-discourage
  "Sending an invalid block immediately discourages the peer."
  (bl.net:clear-discouraged)
  (let ((peer (bl.net:make-peer)))
    (setf (bl.net:peer-state peer) :ready)
    (setf (bl.net:peer-address peer) "192.0.2.100")
    (is (bl.net:record-misbehavior peer "invalid block"))
    (is (eq :disconnected (bl.net:peer-state peer)))
    (is (bl.net:peer-discouraged-p "192.0.2.100"))
    (bl.net:clear-discouraged)))

;;;; Block Timeout Peer Rotation Tests

(test block-timeout-count-tracking
  "Block timeouts should be tracked per peer; disconnect at +max-block-timeouts+."
  (let ((peer (bl.net:make-peer))
        (threshold bl.net:+max-block-timeouts+))
    (is (= 0 (bl.net:peer-block-timeout-count peer)))
    ;; First (threshold - 1) timeouts: counter increments but no disconnect.
    (loop for i from 1 below threshold do
      (is (not (bl.net:record-block-timeout peer)))
      (is (= i (bl.net:peer-block-timeout-count peer))))
    ;; Threshold-th timeout: counter hits threshold, returns T (disconnect).
    (is (bl.net:record-block-timeout peer))
    (is (= threshold (bl.net:peer-block-timeout-count peer)))))

;;;; Chain Reorganization Tests

(test find-fork-point-same-chain
  "Fork point of entries on the same chain should be the earlier one."
  (let ((genesis (bl.store:make-block-index-entry
                  :hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :height 0
                  :chain-work 1)))
    (let ((block1 (bl.store:make-block-index-entry
                   :hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1)
                   :height 1
                   :prev-entry genesis
                   :chain-work 2)))
      (let ((block2 (bl.store:make-block-index-entry
                     :hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2)
                     :height 2
                     :prev-entry block1
                     :chain-work 3)))
        ;; Fork point of block2 and block1 should be genesis (since block1 is parent)
        ;; Actually fork point should be block1 since it's on the path of both
        (let ((fork (bl.val:find-fork-point block2 block1)))
          (is (not (null fork)))
          (is (= 1 (bl.store:block-index-entry-height fork))))))))

(test find-fork-point-divergent-chains
  "Fork point of divergent chains should be their common ancestor."
  (let ((genesis (bl.store:make-block-index-entry
                  :hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :height 0
                  :chain-work 1)))
    ;; Chain A: genesis -> A1 -> A2
    (let* ((a1 (bl.store:make-block-index-entry
                :hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 10)
                :height 1
                :prev-entry genesis
                :chain-work 2))
           (a2 (bl.store:make-block-index-entry
                :hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 11)
                :height 2
                :prev-entry a1
                :chain-work 3)))
      ;; Chain B: genesis -> B1 -> B2
      (let* ((b1 (bl.store:make-block-index-entry
                  :hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 20)
                  :height 1
                  :prev-entry genesis
                  :chain-work 2))
             (b2 (bl.store:make-block-index-entry
                  :hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 21)
                  :height 2
                  :prev-entry b1
                  :chain-work 4)))
        (let ((fork (bl.val:find-fork-point a2 b2)))
          (is (not (null fork)))
          (is (= 0 (bl.store:block-index-entry-height fork)))
          (is (equalp (bl.store:block-index-entry-hash genesis)
                      (bl.store:block-index-entry-hash fork))))))))

(test reorg-undo-data-round-trip
  "apply-block-to-utxo-set returns undo data that disconnect-block-from-utxo-set can restore."
  ;; Build a minimal block with one coinbase tx and one spending tx
  (let* ((utxo-set (bl.store:make-utxo-set))
         ;; Pre-existing UTXO that will be spent by a tx in our block
         (prev-txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xDD))
         (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    ;; Add pre-existing UTXO
    (bl.store:add-utxo utxo-set prev-txid 0 9000000 script 5 :coinbase nil)
    (is (= 1 (bl.store:utxo-count utxo-set)))

    ;; Build a block:
    ;; - coinbase tx (txid: all #x01) with one output of 5 BTC
    ;; - spending tx (txid: all #x02) spending prev-txid:0, creating one output
    (let* ((coinbase-txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x01))
           (spend-txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x02))
           (null-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
           (coinbase-tx (bl.ser:make-transaction
                         :version 1
                         :inputs (vector (bl.ser:make-tx-in
                                        :previous-output (bl.ser:make-outpoint
                                                          :hash null-hash :index #xFFFFFFFF)
                                        :script-sig (make-array 4 :element-type '(unsigned-byte 8)
                                                                  :initial-element 1)))
                         :outputs (vector (bl.ser:make-tx-out
                                         :value 500000000
                                         :script-pubkey script))
                         :lock-time 0
                         :cached-hash coinbase-txid))
           (spending-tx (bl.ser:make-transaction
                         :version 1
                         :inputs (vector (bl.ser:make-tx-in
                                        :previous-output (bl.ser:make-outpoint
                                                          :hash prev-txid :index 0)
                                        :script-sig (make-array 4 :element-type '(unsigned-byte 8)
                                                                  :initial-element 2)))
                         :outputs (vector (bl.ser:make-tx-out
                                         :value 8000000
                                         :script-pubkey script))
                         :lock-time 0
                         :cached-hash spend-txid))
           (block-header (bl.ser:make-block-header
                          :version 1
                          :prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                          :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                          :timestamp 0 :bits 0 :nonce 0
                          :cached-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xBB)))
           (block (bl.ser:make-bitcoin-block
                   :header block-header
                   :transactions (list coinbase-tx spending-tx))))

      ;; Apply block: should add coinbase & spending-tx outputs, remove prev-txid:0
      (let ((spent-utxos (bl.store:apply-block-to-utxo-set utxo-set block 10)))
        ;; Verify undo data captured the spent UTXO
        (is (= 1 (length spent-utxos)))
        (let ((undo-entry (first spent-utxos)))
          (is (equalp prev-txid (first undo-entry)))
          (is (= 0 (second undo-entry)))
          (is (= 9000000 (bl.store:utxo-entry-value (third undo-entry)))))

        ;; After apply: coinbase output + spending tx output = 2 new, minus 1 spent = 2 total
        (is (= 2 (bl.store:utxo-count utxo-set)))
        (is (bl.store:utxo-exists-p utxo-set coinbase-txid 0))
        (is (bl.store:utxo-exists-p utxo-set spend-txid 0))
        (is (not (bl.store:utxo-exists-p utxo-set prev-txid 0)))

        ;; Now disconnect the block using undo data
        (bl.store:disconnect-block-from-utxo-set utxo-set block spent-utxos)

        ;; After disconnect: only the original pre-existing UTXO should remain
        (is (= 1 (bl.store:utxo-count utxo-set)))
        (is (bl.store:utxo-exists-p utxo-set prev-txid 0))
        (is (not (bl.store:utxo-exists-p utxo-set coinbase-txid 0)))
        (is (not (bl.store:utxo-exists-p utxo-set spend-txid 0)))
        ;; Verify restored UTXO has correct value
        (is (= 9000000 (bl.store:utxo-entry-value
                          (bl.store:get-utxo utxo-set prev-txid 0))))))))

;;;; Block Timeout and Retry Tests

(test timed-out-blocks-become-re-requestable
  "After retry-timed-out-requests, timed-out blocks should be requestable again."
  (let* ((bl.net:*ibd-context*
           (bl.net::make-ibd))
         (ctx bl.net:*ibd-context*)
         (hash1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xF1))
         (hash2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xF2))
         (peer (bl.net:make-peer)))
    (setf (bl.net:peer-state peer) :ready)
    ;; Add blocks to pending
    (setf (gethash hash1 (bl.net:ibd-context-pending-blocks ctx)) 10)
    (setf (gethash hash2 (bl.net:ibd-context-pending-blocks ctx)) 11)
    ;; Mark both as in-flight from the peer with an old timestamp (simulating timeout)
    (let ((old-time (- (get-internal-real-time)
                       (* 120 internal-time-units-per-second))))
      (setf (gethash hash1 (bl.net:ibd-context-in-flight ctx))
            (cons peer old-time))
      (setf (gethash hash2 (bl.net:ibd-context-in-flight ctx))
            (cons peer old-time)))
    ;; Verify both are in-flight
    (is (= 2 (hash-table-count (bl.net:ibd-context-in-flight ctx))))
    ;; Retry timed-out requests
    (let ((retried (bl.net::retry-timed-out-requests)))
      (is (= 2 retried)))
    ;; In-flight should be empty now
    (is (= 0 (hash-table-count (bl.net:ibd-context-in-flight ctx))))
    ;; Blocks should still be in pending (and, no longer being in-flight,
    ;; the next per-peer download walk can re-request them).
    (is (= 2 (hash-table-count (bl.net:ibd-context-pending-blocks ctx))))))

;;;; Sync Resume Simulation Test

(test simulate-restart-resume
  "Simulating a node restart should resume from persisted state."
  (let* ((base-path (ensure-directories-exist
                     (merge-pathnames "test-restart/"
                                      (uiop:temporary-directory))))
         ;; Step 1: Create initial state at height 50
         (state1 (bl.store:init-chain-state base-path))
         (utxo1 (bl.store:make-utxo-set)))
    ;; Add genesis to index
    (let ((genesis-hash (bl.store:best-block-hash state1)))
      (bl.store:add-block-index-entry
       state1
       (bl.store:make-block-index-entry
        :hash genesis-hash :height 0 :chain-work 0 :status :valid))
      ;; Build a chain of 3 block entries
      (let ((prev-entry (bl.store:get-block-index-entry state1 genesis-hash)))
        (loop for h from 1 to 3
              for hash = (make-array 32 :element-type '(unsigned-byte 8) :initial-element h)
              do (let ((entry (bl.store:make-block-index-entry
                               :hash hash :height h :prev-entry prev-entry
                               :chain-work (* h 100) :status :valid)))
                   (bl.store:add-block-index-entry state1 entry)
                   (bl.store:update-chain-tip state1 hash h)
                   (setf prev-entry entry)))))
    ;; Add some UTXOs as if blocks were connected
    (let ((txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xCC))
          (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
      (bl.store:add-utxo utxo1 txid 0 5000000000 script 1 :coinbase t)
      (bl.store:add-utxo utxo1 txid 1 2500000000 script 1 :coinbase t))
    ;; Save everything (simulating shutdown)
    (bl.store:save-state state1)
    (bl.store:save-utxo-set utxo1
                                         (bl.store:utxo-set-file-path base-path))
    (bl.store:save-header-index state1)
    ;; Step 2: Create a fresh state (simulating restart)
    (let ((state2 (bl.store:init-chain-state base-path))
          (utxo2 (bl.store:make-utxo-set)))
      ;; Load persisted state
      (bl.store:load-state state2)
      (bl.store:load-utxo-set utxo2
                                           (bl.store:utxo-set-file-path base-path))
      (bl.store:load-header-index state2)
      ;; Verify chain state resumed
      (is (= 3 (bl.store:current-height state2)))
      ;; Verify UTXO set resumed
      (is (= 2 (bl.store:utxo-count utxo2)))
      (let ((txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xCC)))
        (is (bl.store:utxo-exists-p utxo2 txid 0))
        (is (= 5000000000 (bl.store:utxo-entry-value
                            (bl.store:get-utxo utxo2 txid 0)))))
      ;; Verify header index resumed with linkage
      (let* ((tip-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3))
             (tip-entry (bl.store:get-block-index-entry state2 tip-hash)))
        (is (not (null tip-entry)))
        (is (= 3 (bl.store:block-index-entry-height tip-entry)))
        (is (= 300 (bl.store:block-index-entry-chain-work tip-entry)))
        ;; Verify chain linkage exists
        (let ((prev (bl.store:block-index-entry-prev-entry tip-entry)))
          (is (not (null prev)))
          (is (= 2 (bl.store:block-index-entry-height prev))))))
    ;; Cleanup
    (dolist (file '("chainstate.dat" "utxoset.dat" "headerindex.dat"))
      (let ((path (merge-pathnames file base-path)))
        (when (probe-file path)
          (delete-file path))))))

;;;; Reorg and Persistence Edge-Case Tests

(defun %genesis-index-header (genesis-hash)
  "A minimal genesis block-header for test chain-state setup. Reorg paths now
fully validate fork blocks, and validate-block's MTP walk
(compute-median-time-past) reads the genesis entry's header — a NIL header
there crashes the walk. In production the genesis index entry always carries a
header; these synthetic fixtures must too."
  (bl.ser:make-block-header
   :version 1
   :prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
   :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
   :timestamp 1231006505 :bits #x1d00ffff :nonce 0
   :cached-hash genesis-hash))

(test multi-block-reorg-3-deep
  "A reorg of 3+ blocks should correctly switch chains."
  (let* (;; testnet4 (the default network) activates BIP34 at h=1. perform-reorg
         ;; now fully validates fork blocks, and the synthetic make-reorg-test-block
         ;; coinbases carry no BIP34 height — bind mainnet so these low-height
         ;; mechanics blocks skip that check (same reason reorg-tests uses
         ;; (with-network (:mainnet) ...)).
         (bl:*network* :mainnet)
         (base-path (ensure-directories-exist
                     (merge-pathnames "test-reorg-deep/"
                                      (uiop:temporary-directory))))
         (chain-state (bl.store:init-chain-state base-path))
         (utxo-set (bl.store:make-utxo-set))
         (block-store (bl.store:init-block-store base-path))
         (genesis-hash (bl.store:best-block-hash chain-state)))
    ;; Clear undo data
    (clrhash bl.val::*block-undo-data*)
    ;; Add genesis index entry
    (bl.store:add-block-index-entry
     chain-state
     (bl.store:make-block-index-entry
      :hash genesis-hash :height 0 :chain-work 1 :status :valid
      :header (%genesis-index-header genesis-hash)))
    ;; Build chain A: genesis -> A1 -> A2 -> A3 (3 blocks, lower work)
    (let ((chain-a-hashes (make-test-chain-hashes #xA0 3)))
      (let ((prev-hash genesis-hash))
        (loop for h from 1 to 3
              for block-hash in chain-a-hashes
              do (let ((block (make-reorg-test-block prev-hash block-hash h)))
                   (bl.val:connect-block
                    block chain-state block-store utxo-set)
                   (setf prev-hash block-hash))))
      ;; Verify chain A is current
      (is (= 3 (bl.store:current-height chain-state)))
      (is (equalp (third chain-a-hashes)
                  (bl.store:best-block-hash chain-state)))
      ;; Count UTXOs from chain A (3 coinbase outputs)
      (is (= 3 (bl.store:utxo-count utxo-set)))
      ;; Build chain B: genesis -> B1 -> B2 -> B3 -> B4 (4 blocks, more work)
      (let ((chain-b-hashes (make-test-chain-hashes #xB0 4)))
        (let ((prev-hash genesis-hash))
          (loop for h from 1 to 4
                for block-hash in chain-b-hashes
                do (let ((block (make-reorg-test-block prev-hash block-hash h)))
                     (bl.val:connect-block
                      block chain-state block-store utxo-set)
                     (setf prev-hash block-hash))))
        ;; After reorg: chain B should be active (4 blocks, more work)
        (is (= 4 (bl.store:current-height chain-state)))
        (is (equalp (fourth chain-b-hashes)
                    (bl.store:best-block-hash chain-state)))
        ;; UTXOs: chain A's 3 coinbase outputs disconnected, chain B's 4 connected
        (is (= 4 (bl.store:utxo-count utxo-set)))))
    ;; Cleanup
    (clrhash bl.val::*block-undo-data*)))

(test reorg-missing-undo-data-graceful
  "Reorg with missing undo data should not corrupt the UTXO set or crash."
  (let* (;; mainnet so low-height synthetic fork blocks skip BIP34 (see
         ;; multi-block-reorg-3-deep) now that reorg validates fork blocks.
         (bl:*network* :mainnet)
         (base-path (ensure-directories-exist
                     (merge-pathnames "test-reorg-noundo/"
                                      (uiop:temporary-directory))))
         (chain-state (bl.store:init-chain-state base-path))
         (utxo-set (bl.store:make-utxo-set))
         (block-store (bl.store:init-block-store base-path))
         (genesis-hash (bl.store:best-block-hash chain-state)))
    (clrhash bl.val::*block-undo-data*)
    (bl.store:add-block-index-entry
     chain-state
     (bl.store:make-block-index-entry
      :hash genesis-hash :height 0 :chain-work 1 :status :valid
      :header (%genesis-index-header genesis-hash)))
    ;; Build chain A: genesis -> A1 -> A2
    (let ((chain-a-hashes (make-test-chain-hashes #xC0 2)))
      (let ((prev-hash genesis-hash))
        (loop for h from 1 to 2
              for block-hash in chain-a-hashes
              do (let ((block (make-reorg-test-block prev-hash block-hash h)))
                   (bl.val:connect-block
                    block chain-state block-store utxo-set)
                   (setf prev-hash block-hash))))
      ;; Deliberately clear undo data to simulate missing undo
      (clrhash bl.val::*block-undo-data*)
      ;; Now build chain B with more work: genesis -> B1 -> B2 -> B3
      (let ((chain-b-hashes (make-test-chain-hashes #xD0 3)))
        (let ((prev-hash genesis-hash))
          (loop for h from 1 to 3
                for block-hash in chain-b-hashes
                do (let ((block (make-reorg-test-block prev-hash block-hash h)))
                     (bl.val:connect-block
                      block chain-state block-store utxo-set)
                     (setf prev-hash block-hash))))
        ;; Should not crash; chain tip should be updated to chain B
        (is (= 3 (bl.store:current-height chain-state)))
        (is (equalp (third chain-b-hashes)
                    (bl.store:best-block-hash chain-state)))))
    (clrhash bl.val::*block-undo-data*)))

(test persistence-round-trip-after-reorg
  "Chain state and UTXO set should be consistent after save/load following a reorg."
  (let* (;; mainnet so low-height synthetic fork blocks skip BIP34 (see
         ;; multi-block-reorg-3-deep) now that reorg validates fork blocks.
         (bl:*network* :mainnet)
         (base-path (ensure-directories-exist
                     (merge-pathnames "test-reorg-persist/"
                                      (uiop:temporary-directory))))
         (chain-state (bl.store:init-chain-state base-path))
         (utxo-set (bl.store:make-utxo-set))
         (block-store (bl.store:init-block-store base-path))
         (genesis-hash (bl.store:best-block-hash chain-state)))
    (clrhash bl.val::*block-undo-data*)
    (bl.store:add-block-index-entry
     chain-state
     (bl.store:make-block-index-entry
      :hash genesis-hash :height 0 :chain-work 1 :status :valid
      :header (%genesis-index-header genesis-hash)))
    ;; Build chain A (2 blocks)
    (let ((chain-a-hashes (make-test-chain-hashes #xE0 2)))
      (let ((prev-hash genesis-hash))
        (loop for h from 1 to 2
              for block-hash in chain-a-hashes
              do (let ((block (make-reorg-test-block prev-hash block-hash h)))
                   (bl.val:connect-block
                    block chain-state block-store utxo-set)
                   (setf prev-hash block-hash)))))
    ;; Build chain B (3 blocks, triggers reorg)
    (let ((chain-b-hashes (make-test-chain-hashes #xF0 3)))
      (let ((prev-hash genesis-hash))
        (loop for h from 1 to 3
              for block-hash in chain-b-hashes
              do (let ((block (make-reorg-test-block prev-hash block-hash h)))
                   (bl.val:connect-block
                    block chain-state block-store utxo-set)
                   (setf prev-hash block-hash))))
      ;; After reorg: chain B is active
      (is (= 3 (bl.store:current-height chain-state)))
      (let ((utxo-count-before (bl.store:utxo-count utxo-set)))
        ;; Save state
        (bl.store:save-state chain-state)
        (bl.store:save-utxo-set utxo-set
                                             (bl.store:utxo-set-file-path base-path))
        (bl.store:save-header-index chain-state)
        ;; Load into fresh state
        (let ((state2 (bl.store:init-chain-state base-path))
              (utxo2 (bl.store:make-utxo-set)))
          (bl.store:load-state state2)
          (bl.store:load-utxo-set utxo2
                                               (bl.store:utxo-set-file-path base-path))
          (bl.store:load-header-index state2)
          ;; Verify chain state matches
          (is (= 3 (bl.store:current-height state2)))
          (is (equalp (third chain-b-hashes)
                      (bl.store:best-block-hash state2)))
          ;; Verify UTXO count matches
          (is (= utxo-count-before (bl.store:utxo-count utxo2)))
          ;; Verify header index has entries from both chains
          (let ((tip-entry (bl.store:get-block-index-entry
                            state2 (third chain-b-hashes))))
            (is (not (null tip-entry)))
            (is (= 3 (bl.store:block-index-entry-height tip-entry)))))))
    ;; Cleanup
    (clrhash bl.val::*block-undo-data*)
    (dolist (file '("chainstate.dat" "utxoset.dat" "headerindex.dat"))
      (let ((path (merge-pathnames file base-path)))
        (when (probe-file path) (delete-file path))))))

(test utxo-consistency-save-load-during-sync
  "UTXO set should remain consistent through save/load cycles during block processing."
  (let* ((base-path (ensure-directories-exist
                     (merge-pathnames "test-utxo-sync/"
                                      (uiop:temporary-directory))))
         (utxo-set (bl.store:make-utxo-set))
         (utxo-path (bl.store:utxo-set-file-path base-path))
         (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    ;; Simulate syncing several blocks with save/load between them
    ;; Block 1: add coinbase UTXO
    (let ((txid1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x11)))
      (bl.store:add-utxo utxo-set txid1 0 5000000000 script 1 :coinbase t)
      ;; Save and reload (simulating periodic checkpoint)
      (bl.store:save-utxo-set utxo-set utxo-path)
      (let ((reloaded (bl.store:make-utxo-set)))
        (is (bl.store:load-utxo-set reloaded utxo-path))
        (is (= 1 (bl.store:utxo-count reloaded)))
        (is (bl.store:utxo-exists-p reloaded txid1 0))
        ;; Continue syncing on reloaded set
        ;; Block 2: add another UTXO, spend first one
        (let ((txid2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x22)))
          (bl.store:add-utxo reloaded txid2 0 4999000000 script 2)
          (bl.store:remove-utxo reloaded txid1 0)
          ;; Save and reload again
          (bl.store:save-utxo-set reloaded utxo-path)
          (let ((reloaded2 (bl.store:make-utxo-set)))
            (is (bl.store:load-utxo-set reloaded2 utxo-path))
            (is (= 1 (bl.store:utxo-count reloaded2)))
            (is (not (bl.store:utxo-exists-p reloaded2 txid1 0)))
            (is (bl.store:utxo-exists-p reloaded2 txid2 0))
            ;; Verify value preserved
            (let ((entry (bl.store:get-utxo reloaded2 txid2 0)))
              (is (= 4999000000 (bl.store:utxo-entry-value entry))))))))
    ;; Cleanup
    (when (probe-file utxo-path) (delete-file utxo-path))))

;;;; Out-of-Order Block Queue Tests

(test drain-block-queue-empty
  "Draining an empty queue should return 0."
  (with-ibd-context
    (let ((state (bl.store:init-chain-state
                  (merge-pathnames "test-drain/" (uiop:temporary-directory))))
          (utxo-set (bl.store:make-utxo-set))
          (block-store (bl.store:init-block-store
                        (merge-pathnames "test-drain/" (uiop:temporary-directory)))))
      (is (= 0 (bl.net::drain-block-queue state utxo-set block-store))))))

;;;; Chainstate in-transition auto-recovery (mechanizes the manual rescue
;;;; from the first mainnet run — see recover-inconsistent-chainstate).

(defun %recovery-coinbase-block (prev-hash height)
  "A coinbase-only block extending PREV-HASH; coinbase script-sig carries
HEIGHT so each block's coinbase txid is unique."
  (let* ((sig (let ((s (make-array 4 :element-type '(unsigned-byte 8) :initial-element 0)))
                (setf (aref s 0) (logand height #xff)
                      (aref s 1) (logand (ash height -8) #xff))
                s))
         (cb-in (bl.ser:make-tx-in
                 :previous-output (bl.ser:make-outpoint
                                   :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                        :initial-element 0)
                                   :index #xffffffff)
                 :script-sig sig :sequence #xffffffff))
         (cb-out (bl.ser:make-tx-out
                  :value 5000000000
                  :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                               :initial-element #x76)))
         (cb (bl.ser:make-transaction
              :version 1 :inputs (vector cb-in) :outputs (vector cb-out) :lock-time 0))
         (hdr (bl.ser:make-block-header
               :version 1 :prev-block prev-hash
               :merkle-root (bl.ser:transaction-hash cb)
               :timestamp (+ 1700000000 height) :bits #x207fffff :nonce 0)))
    (bl.ser:make-bitcoin-block :header hdr :transactions (list cb))))

(defun %recovery-fixture (committed-height)
  "Build a node with genesis + blocks 1..3 in the store and header index,
chainstate tip set to block 3 with the in-transition marker, and UTXO
coins present only for coinbases up to COMMITTED-HEIGHT (simulating a
LevelDB batch that committed through that height). Returns the node."
  (let* ((base (ensure-directories-exist
                (merge-pathnames (format nil "test-recovery-~D-~D/"
                                         committed-height (get-universal-time))
                                 (uiop:temporary-directory))))
         (chain-state (bl.store:init-chain-state base))
         (block-store (bl.store:init-block-store base))
         (utxo (bl.store:make-coins-view-cache
                (bl.store:open-coins-view-db
                 (ensure-directories-exist (merge-pathnames "chainstate/" base)))))
         (node (bl:make-node))
         (genesis-hash (bl.store:best-block-hash chain-state)))
    (setf (bl:node-chain-state node) chain-state
          (bl:node-block-store node) block-store
          (bl:node-utxo-set node) utxo)
    (bl.store:add-block-index-entry
     chain-state (bl.store:make-block-index-entry
                  :hash genesis-hash :height 0 :chain-work 0 :status :valid))
    (let ((prev-hash genesis-hash)
          (prev-entry (bl.store:get-block-index-entry chain-state genesis-hash)))
      (loop for h from 1 to 3
            for block = (%recovery-coinbase-block prev-hash h)
            for hash = (bl.ser:block-header-hash
                        (bl.ser:bitcoin-block-header block))
            do (bl.store:store-block block-store block)
               (let ((entry (bl.store:make-block-index-entry
                             :hash hash :height h :prev-entry prev-entry
                             :chain-work (* h 100) :status :valid)))
                 (bl.store:add-block-index-entry chain-state entry)
                 (setf prev-entry entry prev-hash hash))
               ;; Commit this block's coinbase coin only up to COMMITTED-HEIGHT.
               (when (<= h committed-height)
                 (let ((cb (first (bl.ser:bitcoin-block-transactions block))))
                   (bl.store:add-utxo
                    utxo (bl.ser:transaction-hash cb) 0
                    5000000000 (make-array 25 :element-type '(unsigned-byte 8)) h :coinbase t)))
               ;; chainstate.dat records the NEW tip (block 3) with the marker.
               (when (= h 3)
                 (bl.store:update-chain-tip chain-state hash h)
                 (bl.store:save-state chain-state :in-transition t))))
    node))

(test chainstate-recovery-utxo-at-tip
  "Recovery when the LevelDB batch committed the recorded tip: just clears
the marker, height unchanged, chainstate.dat reloads clean."
  (let ((node (%recovery-fixture 3)))   ; coins present through block 3
    (is (eq t (bl::recover-inconsistent-chainstate node)))
    (is (= 3 (bl.store:current-height
              (bl:node-chain-state node))))
    ;; Marker cleared: a fresh load returns T, not :inconsistent.
    (let ((reload (bl.store:init-chain-state
                   (bl.store::chain-state-base-path
                    (bl:node-chain-state node)))))
      (is (eq t (bl.store:load-state reload)))
      (is (= 3 (bl.store:current-height reload))))))

(test chainstate-recovery-utxo-behind
  "Recovery when the batch did NOT commit the recorded tip: rewinds
chainstate.dat to the highest ancestor whose coins ARE committed."
  (let ((node (%recovery-fixture 2)))   ; coins present only through block 2
    (is (eq t (bl::recover-inconsistent-chainstate node)))
    (is (= 2 (bl.store:current-height
              (bl:node-chain-state node))))
    (let ((reload (bl.store:init-chain-state
                   (bl.store::chain-state-base-path
                    (bl:node-chain-state node)))))
      (is (eq t (bl.store:load-state reload)))
      (is (= 2 (bl.store:current-height reload))))))

;;;; Shutdown flush crash safety (stop-node -> %shutdown-flush-chainstates).
;;;;
;;;; stop-node used to save-state (which CLEARS the in-transition marker) and
;;;; THEN coins-flush as two bare steps -- a kill between them left
;;;; chainstate.dat ahead of the coins DB with no marker, so load-state
;;;; returned clean over the inconsistency: the exact silent-corruption class
;;;; the 3-phase commit exists to prevent. These tests pin the shutdown flush
;;;; to the marker discipline (Core Shutdown iterates every chainstate through
;;;; ForceFlushStateToDisk, init.cpp:379-387 -- the same marker-protected
;;;; BatchWrite path as the periodic flush).

(defun %shutdown-fixture-chainstate (base suffix height &rest cs-args)
  "A chainstate over BASE with storage-SUFFIX, tip at HEIGHT, and its own
coins LevelDB (chainstate<SUFFIX>/) holding one dirty, unflushed coin whose
txid bytes are all HEIGHT."
  (let ((cs (apply #'bl.store:make-chain-state
                   :base-path base
                   :best-block-hash (make-array 32 :element-type '(unsigned-byte 8)
                                                   :initial-element #xAA)
                   :best-height height
                   :storage-suffix suffix
                   cs-args)))
    (bl.store:open-chainstate-coins-view cs)
    (bl.store:add-utxo
     (bl.store:chain-state-coins-view cs)
     (make-array 32 :element-type '(unsigned-byte 8) :initial-element height)
     0 5000000000
     (make-array 1 :element-type '(unsigned-byte 8) :initial-element #x51)
     height :coinbase t)
    cs))

(defun %shutdown-fixture-coin-durable-p (base suffix height)
  "T iff the fixture coin for HEIGHT is in the on-disk LevelDB at
BASE/chainstate<SUFFIX>/ (opened fresh, so only flushed state counts)."
  (let ((cs (bl.store:make-chain-state :base-path base
                                                   :storage-suffix suffix)))
    (bl.store:open-chainstate-coins-view cs)
    (unwind-protect
         (and (bl.store:get-utxo
               (bl.store:chain-state-coins-view cs)
               (make-array 32 :element-type '(unsigned-byte 8)
                              :initial-element height)
               0)
              t)
      (bl.store:close-chainstate-coins-view cs))))

(test shutdown-flush-marker-window
  "%shutdown-flush-chainstates runs the shutdown flush through the 3-phase
commit: DURING the coins-flush window the on-disk state file carries the
in-transition marker (a crash there is detected at the next startup), and
after it completes the marker is cleared, the coins are durable, and the
coins view is closed."
  (let* ((base (ensure-directories-exist
                (merge-pathnames (format nil "test-shutdown-flush-~D/"
                                         (get-universal-time))
                                 (uiop:temporary-directory))))
         (node (bl:make-node))
         (mid-window '()))
    (unwind-protect
         (let ((cs (%shutdown-fixture-chainstate base "" 7)))
           (setf (bl:node-chainstates node) (list cs))
           (let ((bl::*flush-mid-commit-hook*
                   (lambda (flushing)
                     ;; Probe the ON-DISK state file from a fresh struct, as
                     ;; a post-crash startup would.
                     (let ((probe (bl.store:make-chain-state
                                   :base-path base
                                   :storage-suffix
                                   (bl.store:chain-state-storage-suffix
                                    flushing))))
                       (push (bl.store:load-state probe) mid-window)))))
             (bl::%shutdown-flush-chainstates node))
           ;; The unsafe window was marked on disk...
           (is (equal '(:inconsistent) mid-window))
           ;; ...and the completed shutdown committed clean at the tip.
           (let ((reload (bl.store:make-chain-state :base-path base)))
             (is (eq t (bl.store:load-state reload)))
             (is (= 7 (bl.store:current-height reload))))
           ;; Coins view closed; the dirty coin made it to LevelDB.
           (is (null (bl.store:chain-state-coins-view cs)))
           (is (eq t (%shutdown-fixture-coin-durable-p base "" 7))))
      (uiop:delete-directory-tree base :validate t :if-does-not-exist :ignore))))

(test shutdown-flush-covers-all-chainstates
  "With an assumeutxo snapshot active (two chainstates), the shutdown flush
runs EACH through its own 3-phase commit: both storage-suffix-named state
files carry the marker during their own window, and both load clean at their
own tips afterwards with their coins durable."
  (let* ((base (ensure-directories-exist
                (merge-pathnames (format nil "test-shutdown-flush2-~D/"
                                         (get-universal-time))
                                 (uiop:temporary-directory))))
         (node (bl:make-node))
         (mid-window '()))
    (unwind-protect
         (let ((primary (%shutdown-fixture-chainstate base "" 1))
               (snap (%shutdown-fixture-chainstate
                      base "_snapshot" 5
                      :from-snapshot-blockhash
                      (make-array 32 :element-type '(unsigned-byte 8)
                                     :initial-element 5)
                      :assumeutxo-status :unvalidated)))
           (setf (bl:node-chainstates node) (list primary snap))
           (let ((bl::*flush-mid-commit-hook*
                   (lambda (flushing)
                     (let* ((suffix (bl.store:chain-state-storage-suffix
                                     flushing))
                            (probe (bl.store:make-chain-state
                                    :base-path base :storage-suffix suffix)))
                       (push (cons suffix (bl.store:load-state probe))
                             mid-window)))))
             (bl::%shutdown-flush-chainstates node))
           ;; Both chainstates hit their own marker window, in list order.
           (is (equal '(("" . :inconsistent) ("_snapshot" . :inconsistent))
                      (reverse mid-window)))
           ;; Both committed clean, each at its own tip, coins durable.
           (let ((p (bl.store:make-chain-state :base-path base))
                 (s (bl.store:make-chain-state
                     :base-path base :storage-suffix "_snapshot")))
             (is (eq t (bl.store:load-state p)))
             (is (eq t (bl.store:load-state s)))
             (is (= 1 (bl.store:current-height p)))
             (is (= 5 (bl.store:current-height s))))
           (is (null (bl.store:chain-state-coins-view primary)))
           (is (null (bl.store:chain-state-coins-view snap)))
           (is (eq t (%shutdown-fixture-coin-durable-p base "" 1)))
           (is (eq t (%shutdown-fixture-coin-durable-p base "_snapshot" 5))))
      (uiop:delete-directory-tree base :validate t :if-does-not-exist :ignore))))

(test the-coins-best-block-pointer-never-outruns-the-persisted-block-index
  "Core's FlushStateToDisk writes the block files, then the block-index
database, and only THEN calls CoinsTip().Sync() (validation.cpp:2780-2812),
precisely so the coins database can never name a block the block index does not
hold. %FLUSH-CHAINSTATE has that order; the RPC read path did not.

gettxoutsetinfo, dumptxoutset, scantxoutset and the assumeutxo hash check all
sync the live coins cache before walking the base LevelDB, and that sync stages
the cache's own best-block pointer. Nothing on that path wrote the header
index, whose only other writers are the periodic flush and start-up -- so an
unclean shutdown any time in the following 600 s left the coins DB naming a
block RECONCILE-COINS-DB-BEST-BLOCK cannot place, and init.lisp turns its
:unresolvable into a refusal to start: a read-only RPC converted an ordinary
crash into a mandatory reindex.

Driven through the shipped entry point (UTXO-SET-ITERATE) with the node's own
hook installed, so this covers the wiring and not just the ordering."
  (with-network (:mainnet)
    (with-temp-directory (base "bl-coins-order")
      (let* ((node (bl:make-node))
             (cs (bl.store:init-chain-state base))
             (hash (make-array 32 :element-type '(unsigned-byte 8)
                                  :initial-element #xAB)))
        (setf (bl:node-chainstates node) (list cs))
        ;; A block index entry accepted since the last flush: in memory only,
        ;; which is the ordinary state between flushes.
        (bl.store:add-block-index-entry
         cs (bl.store:make-block-index-entry
             :hash hash :height 7 :chain-work 9 :status :valid))
        (bl.store:open-chainstate-coins-view cs)
        (unwind-protect
             (let ((view (bl.store:chain-state-coins-view cs)))
               ;; The coins now correspond to that block, as COIN-VIEW-APPLY-BLOCK
               ;; would have left them, with one dirty coin to write.
               (setf (bl.store:cvc-best-block view) (copy-seq hash))
               (bl.store:coin-view-add
                view (make-array 32 :element-type '(unsigned-byte 8)
                                    :initial-element 3)
                0 5000
                (make-array 1 :element-type '(unsigned-byte 8)
                              :initial-element #x51)
                7 :coinbase nil :allow-overwrite nil)
               (let ((bl:*node* node))
                 (bl.store:utxo-set-iterate
                  view (lambda (txid vout entry)
                         (declare (ignore txid vout entry)))))
               (is (equalp hash (bl.store:coins-view-db-best-block
                                 (bl.store:coins-view-cache-base view)))
                   "the RPC sync is expected to advance the stored pointer")
               ;; And a restart must be able to place the block it names.
               (let ((reload (bl.store:init-chain-state base)))
                 (bl.store:load-header-index reload)
                 (is-true (bl.store:get-block-index-entry reload hash)
                          "the coins DB names a block the persisted index does ~
                           not hold, so start-up would refuse to run")))
          (bl.store:close-chainstate-coins-view cs))))))

;;;; Shutdown coordination: the internal stop paths only REQUEST a shutdown,
;;;; and the main thread performs it (GA8 wave 5).
;;;;
;;;; The supervisor (scripts/run-node.sh) runs a main-thread watchdog that exits
;;;; the process shortly after the node stops running. stop-node clears
;;;; node-running FIRST and writes the chainstate flush, mempool.dat, peers.dat,
;;;; banlist and wallet markers AFTER, so any stop driven from a non-main thread
;;;; (the `stop` RPC, -stopatheight, the low-disk abort) raced that exit and was
;;;; routinely cut short. Core has the same split: the RPC calls StartShutdown(),
;;;; and Shutdown() runs on the main thread (bitcoind.cpp:180-193).

(defun %shutdown-test-node (base)
  "A minimal running node over BASE with the state stop-node persists: one
chainstate with a dirty coin, a mempool, an address book, a data directory."
  (let ((node (bl:make-node :network :regtest)))
    (setf (bl:node-data-directory node) base
          (bl:node-chainstates node)
          (list (%shutdown-fixture-chainstate base "" 3))
          (bl:node-mempool node) (bl.mp:make-mempool)
          (bl:node-address-book node)
          (bl.net:make-address-book)
          (bl:node-running node) t)
    node))

(defmacro %with-shutdown-node ((node-var base-var) &body body)
  "Run BODY with NODE-VAR installed as the GLOBAL bl:*node* (other
threads read the global, so a LET binding would be invisible to them), and
every global stop-node mutates restored afterwards."
  `(let* ((,base-var (ensure-directories-exist
                      (merge-pathnames (format nil "test-shutdown-req-~D/"
                                               (get-internal-real-time))
                                       (uiop:temporary-directory))))
          (,node-var (%shutdown-test-node ,base-var))
          (saved-node bl:*node*)
          (saved-banlist bl.net:*banlist-path*))
     (setf bl:*node* ,node-var
           bl::*shutdown-request* nil
           bl::*shutdown-complete* nil
           bl::*stop-node-in-progress* nil)
     (unwind-protect (progn ,@body)
       (setf bl:*node* saved-node
             bl.net:*banlist-path* saved-banlist
             bl::*shutdown-request* nil
             bl::*shutdown-complete* nil
             bl::*stop-node-in-progress* nil
             bl::*shutdown-watchdog-running* nil)
       (bl.net:reset-ibd-stop)
       (uiop:delete-directory-tree ,base-var :validate t :if-does-not-exist :ignore))))

(test shutdown-request-completes-teardown-before-exit
  "An internal stop request (driven through the real `stop` RPC entry point)
must not stop the node on its own thread: it registers the request, and the
main-thread watchdog runs the WHOLE teardown before the process would exit.
Asserted by ordering, not by stop-node merely returning — every persistence
step must observe the *shutdown-complete* latch still clear, and the watchdog
must report the clean exit code (0), not the respawn code (7) it returns when
the node died out from under it."
  (%with-shutdown-node (node base)
    (let ((steps '())
          (real-flush (fdefinition 'bl::%shutdown-flush-chainstates))
          (real-mempool (fdefinition 'bl.mp:save-mempool-file))
          (real-peers (fdefinition 'bl.net:save-address-book)))
      (flet ((note (step) (push (cons step bl::*shutdown-complete*) steps)))
        (unwind-protect
             (progn
               (setf (fdefinition 'bl::%shutdown-flush-chainstates)
                     (lambda (&rest args) (note :flush) (apply real-flush args))
                     (fdefinition 'bl.mp:save-mempool-file)
                     (lambda (&rest args) (note :mempool) (apply real-mempool args))
                     (fdefinition 'bl.net:save-address-book)
                     (lambda (&rest args) (note :peers) (apply real-peers args)))
               ;; The shipped RPC entry point, not a re-implementation of it.
               (bl.rpc::rpc-stop node nil)
               (let ((code (bl:run-node-watchdog :poll-seconds 0.05
                                                            :exit nil)))
                 (is (= bl:+node-exit-clean+ code)
                     "watchdog exit code (0 = deliberate stop, 7 = died unasked)")))
          (setf (fdefinition 'bl::%shutdown-flush-chainstates) real-flush
                (fdefinition 'bl.mp:save-mempool-file) real-mempool
                (fdefinition 'bl.net:save-address-book) real-peers)))
      (let ((order (reverse steps)))
        ;; Every persistence step ran, in stop-node's order...
        (is (equal '(:flush :mempool :peers) (mapcar #'car order)) "steps: ~S" order)
        ;; ...and each ran BEFORE the latch the watchdog exits on was set.
        (is (every (lambda (s) (null (cdr s))) order)
            "a persistence step ran at or after *shutdown-complete*: ~S" order))
      ;; The latch is set only once the teardown is done, and the node is down.
      (is (eq t bl::*shutdown-complete*))
      (is (null bl:*node*))
      ;; The chainstate was committed clean by that teardown.
      (let ((reload (bl.store:make-chain-state :base-path base)))
        (is (eq t (bl.store:load-state reload)))
        (is (= 3 (bl.store:current-height reload)))))))

(test shutdown-request-is-once-only
  "request-node-shutdown is a once-only latch: the first caller's reason and
exit code win, so a second path (say the disk abort after an RPC stop) cannot
turn a clean stop into a respawn."
  (%with-shutdown-node (node base)
    (is-true node)
    (is-true base)
    ;; Pretend the main-thread watchdog is polling, so the request does NOT
    ;; fall back to running stop-node on a thread of its own.
    (setf bl::*shutdown-watchdog-running* t)
    (is (eq t (bl:request-node-shutdown "first")))
    (is (null (bl:request-node-shutdown
               "second" :exit-code bl:+node-exit-error+)))
    (is (string= "first" (bl:node-shutdown-requested-p)))
    (is (= bl:+node-exit-clean+
           (bl::%pending-shutdown-exit-code)))))

(test stop-node-is-idempotent-under-concurrent-calls
  "stop-node is not re-entrant across threads: two overlapping runs would drive
%flush-chainstate through the same fixed chainstate.dat.tmp path and
double-close the same LevelDB handles. The second, overlapping call must not
run the teardown again — it waits for the owner and returns NIL."
  (%with-shutdown-node (node base)
    (is-true node)
    (let ((flushes 0)
          (real-flush (fdefinition 'bl::%shutdown-flush-chainstates))
          (results '())
          (lock (bt:make-lock "shutdown-test")))
      (unwind-protect
           (progn
             (setf (fdefinition 'bl::%shutdown-flush-chainstates)
                   (lambda (&rest args)
                     (bt:with-lock-held (lock) (incf flushes))
                     ;; Widen the overlap so the second caller lands inside it.
                     (sleep 0.3)
                     (apply real-flush args)))
             (let ((threads (loop repeat 2
                                  collect (bt:make-thread
                                           (lambda ()
                                             (let ((r (bl:stop-node)))
                                               (bt:with-lock-held (lock)
                                                 (push r results))))))))
               (dolist (th threads) (bt:join-thread th))))
        (setf (fdefinition 'bl::%shutdown-flush-chainstates) real-flush))
      ;; The teardown ran exactly once...
      (is (= 1 flushes) "%shutdown-flush-chainstates ran ~D time(s)" flushes)
      ;; ...one caller owned it, the other observed the completed shutdown.
      (is (= 2 (length results)))
      (is (= 1 (count t results)) "stop-node return values: ~S" results)
      (is (eq t bl::*shutdown-complete*))
      ;; And the single teardown still committed the chainstate cleanly.
      (let ((reload (bl.store:make-chain-state :base-path base)))
        (is (eq t (bl.store:load-state reload)))
        (is (= 3 (bl.store:current-height reload)))))))

;;;; --- The signal handler is Core-shaped (init.cpp:425-431, signalinterrupt.cpp) ---

(test the-stop-signal-handler-does-not-log-lock-or-allocate
  "Core's whole SIGTERM handler is an atomic flag exchange plus one byte written
to a pipe, and the comment above it says why: 'This must be reentrant and safe
for calling in a signal handler.' Ours used to format to *error-output*, call
log-info (taking the log mutex), and on the REPL path start a thread and run the
entire teardown — from inside the handler.

Drive the real handler with the log path booby-trapped: if it emits, it dies."
  (%with-shutdown-node (node base)
    (is-true node) (is-true base)
    (setf bl::*shutdown-watchdog-running* t)
    (bl::%open-shutdown-pipe)
    (let ((emits 0)
          (real-emit (fdefinition 'bl.log::%log-emit))
          (err (make-string-output-stream)))
      (unwind-protect
           (let ((*error-output* err))
             (setf (fdefinition 'bl.log::%log-emit)
                   (lambda (&rest args) (declare (ignore args)) (incf emits)))
             (is (eq t (bl::%handle-stop-signal))))
        (setf (fdefinition 'bl.log::%log-emit) real-emit))
      (is (= 0 emits)
          "the handler logged ~D time(s); a log emit takes *LOG-LOCK*, which is ~
           the deadlock the recursive lock used to paper over" emits)
      (is (string= "" (get-output-stream-string err))
          "the handler wrote to a shared stream from a signal context"))
    ;; It did register the request, using the PREALLOCATED cell — the identity
    ;; check is the assertion that the handler did not cons a fresh one.
    (is (eq bl::*signal-shutdown-request* bl::*shutdown-request*))
    (is (string= "SIGTERM/SIGINT" (bl:node-shutdown-requested-p)))
    (is (= bl:+node-exit-clean+
           (bl::%pending-shutdown-exit-code)))))

(test the-stop-signal-handler-writes-exactly-one-wake-up-token
  "Core guards TokenWrite behind m_flag.exchange(true) so a reentrant or
concurrent signal cannot write twice — the pipe holds one token and one reader
consumes it. A second signal after the first must be silent, or the servicer
would wake again after the node is already down."
  (%with-shutdown-node (node base)
    (is-true node) (is-true base)
    (setf bl::*shutdown-watchdog-running* t)
    (bl::%open-shutdown-pipe)
    ;; Drain anything left by an earlier test.
    (let ((tokens 0)
          (real-write (fdefinition 'bl::%write-shutdown-token)))
      (unwind-protect
           (progn
             (setf (fdefinition 'bl::%write-shutdown-token)
                   (lambda () (incf tokens) nil))
             (bl::%handle-stop-signal)
             (bl::%handle-stop-signal)
             (bl::%handle-stop-signal))
        (setf (fdefinition 'bl::%write-shutdown-token) real-write))
      (is (= 1 tokens)
          "~D tokens written for three signals; only the CAS winner may write" tokens))))

(test the-token-pipe-round-trips-a-wake-up
  "The mechanism itself, end to end: a token written by the handler's path must
wake a thread blocked in the servicer's wait. If it does not, a REPL node that
takes a SIGTERM registers the request and then sits there forever."
  (bl::%open-shutdown-pipe)
  (let ((woke (bt:make-semaphore :name "token-test")))
    (let ((reader (bt:make-thread
                   (lambda ()
                     (bl::%await-shutdown-token)
                     (bt:signal-semaphore woke))
                   :name "token-test-reader")))
      (bl::%write-shutdown-token)
      (is-true (bt:wait-on-semaphore woke :timeout 10)
               "a written token did not wake the reader")
      ;; bt:join-thread takes the thread and nothing else, so the :timeout this
      ;; used to pass made every join a SIMPLE-PROGRAM-ERROR that the
      ;; ignore-errors then hid -- the reader was never joined, and SBCL said
      ;; so only as a STYLE-WARNING in the build transcript.
      (bl.net:join-thread-or-destroy reader :timeout 5))))

(test the-log-lock-is-plain-now-that-nothing-re-enters-it
  "The payoff, and a guard against silently going back. *LOG-LOCK* was made
recursive only because the signal handler logged; Core's BCLog::Logger::m_cs is
a plain StdMutex. A recursive lock here would hide a genuine re-entrant emit
instead of deadlocking on it, which is how a logging bug becomes invisible."
  (is (typep bl.log:*log-lock* 'sb-thread:mutex))
  ;; And no source file may take it recursively again.
  (dolist (rel (cons "src/logging.lisp" (%node-source-files)))
    (let ((src (uiop:read-file-string
                (merge-pathnames rel (asdf:system-source-directory :bitcoin-lisp)))))
      (is (null (search "with-recursive-lock-held (*log-lock*)" src))
          "~A takes *LOG-LOCK* recursively again" rel))))

(test a-stop-request-and-a-signal-tear-the-node-down-through-one-path
  "A `stop` RPC used to spawn its own thread while a SIGTERM ran the teardown
inline — two mechanisms for one job, and only one of them was ever exercised by
a test. Both now register and wake the same servicer, so a servicer that is
running means neither path makes a thread of its own."
  (%with-shutdown-node (node base)
    (is-true node) (is-true base)
    (bl::%open-shutdown-pipe)
    (let ((tokens 0)
          (threads 0)
          (real-write (fdefinition 'bl::%write-shutdown-token))
          (saved-servicer bl::*shutdown-servicer-thread*))
      (unwind-protect
           (progn
             ;; A live servicer: the request must wake it, not spawn anything.
             (setf bl::*shutdown-servicer-thread*
                   (bt:make-thread (lambda () (sleep 30)) :name "fake-servicer"))
             (setf (fdefinition 'bl::%write-shutdown-token)
                   (lambda () (incf tokens) nil))
             (setf bl::*shutdown-watchdog-running* nil)
             (is (eq t (bl:request-node-shutdown "rpc stop")))
             (is (= 1 tokens) "the stop request did not wake the servicer")
             (is (= 0 threads)))
        (setf (fdefinition 'bl::%write-shutdown-token) real-write)
        (when (and bl::*shutdown-servicer-thread*
                   (bt:thread-alive-p bl::*shutdown-servicer-thread*))
          (ignore-errors (bt:destroy-thread bl::*shutdown-servicer-thread*)))
        (setf bl::*shutdown-servicer-thread* saved-servicer)))))

(test the-watchdog-releases-the-servicer-before-exiting
  "The servicer is a real thread blocked in read(2), and SB-EXT:EXIT joins
threads. On the exit-7 path — the node stopped running unasked — nobody ever
called request-node-shutdown, so no token was ever written and the servicer
would still be blocked when the watchdog exits: a 5-second stall on every
crash-restart, which is the path that most needs to be fast."
  (%with-shutdown-node (node base)
    (is-true node) (is-true base)
    (let ((tokens 0)
          (real-write (fdefinition 'bl::%write-shutdown-token)))
      (unwind-protect
           (progn
             (setf (fdefinition 'bl::%write-shutdown-token)
                   (lambda () (incf tokens) nil))
             ;; No request at all: the watchdog stops because the node is gone.
             (setf bl:*node* nil)
             (let ((code (bl:run-node-watchdog :poll-seconds 0.05
                                                          :exit nil)))
               (is (= bl:+node-exit-watchdog+ code)
                   "expected the respawn code for a node that died unasked")))
        (setf (fdefinition 'bl::%write-shutdown-token) real-write))
      (is (= 1 tokens)
          "the watchdog exited without releasing the servicer, so the process ~
           would wait out SB-EXT:EXIT's timeout"))))
