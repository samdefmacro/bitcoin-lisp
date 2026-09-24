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

;;;; The block tree database (blocks/index, Core BlockTreeDB)

(defun %btdb-hex-octets (hex)
  (coerce (bl.crypto:hex-to-bytes hex) '(simple-array (unsigned-byte 8) (*))))

(defparameter *core-block-1-record*
  '("62b588c58b15dd34fe2701f79293931c9714cc0ae6790450ac5353a23e2244811a"
    "8eed3c01801d0100812d080000002006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f436c2bd7168dfaab8016bc169aef2639a048837d6d218d453fe7cee83c87492e938cb46affff7f2001000000")
  "Key and value of block 1's 'b' record in a blocks/index written by Bitcoin
Core v28.2 (/releases/v28.2/bin/bitcoind -regtest, generatetoaddress 5, clean
stop; 2026-09-24).")

(test block-index-record-is-cores-byte-for-byte
  "The contract is byte-exactness against Core, so the test is Core's own
bytes. The value decodes to what Core wrote -- client version 259900, height 1,
nStatus 157 (SCRIPTS | HAVE_DATA | HAVE_UNDO | OPT_WITNESS), one transaction,
the block at offset 301 of blk00000 and its undo at offset 8 of rev00000 --
and the hash CDiskBlockIndex::ConstructBlockHash computes from the header is the
key it is stored under. Re-encoding the decoded entry gives the same bytes."
  (destructuring-bind (key-hex value-hex) *core-block-1-record*
    (let ((key (%btdb-hex-octets key-hex))
          (value (%btdb-hex-octets value-hex)))
      (multiple-value-bind (entry prev-hash nstatus)
          (bl.store:decode-disk-block-index value)
        (is (= 157 nstatus))
        (is (= 1 (bl.store:block-index-entry-height entry)))
        (is (eq :valid (bl.store:block-index-entry-status entry)))
        (is (= 1 (bl.store:block-index-entry-tx-count entry)))
        (is (eql 0 (bl.store:block-index-entry-file entry)))
        (is (eql 301 (bl.store:block-index-entry-data-pos entry)))
        (is (eql 8 (bl.store:block-index-entry-undo-pos entry)))
        (is (= bl.store:+block-opt-witness+
               (bl.store:block-index-entry-status-flags entry)))
        (is (equalp (subseq key 1) (bl.store:block-index-entry-hash entry))
            "the recomputed hash is not the record's key")
        (is (equalp (bl.store:network-genesis-hash :regtest) prev-hash))
        (is (equalp value (bl.store:encode-disk-block-index entry))
            "re-encoding a Core record changed its bytes")))))

(test block-file-record-is-cores-byte-for-byte
  "Core's 'f' record for blk00000 after the same six blocks: seven VARINTs,
nBlocks 6, nSize 1573, nUndoSize 205, heights 0..5, then the header times."
  (let* ((value (%btdb-hex-octets "068b25804d000583e9a6ca5a85d4d19815"))
         (info (bl.store:decode-block-file-info value)))
    (is (= 6 (bl.store:block-file-info-blocks info)))
    (is (= 1573 (bl.store:block-file-info-size info)))
    (is (= 0 (bl.store:block-file-info-height-first info)))
    (is (= 5 (bl.store:block-file-info-height-last info)))
    (is (< (bl.store:block-file-info-time-first info)
           (bl.store:block-file-info-time-last info)))
    (is (equalp value (bl.store:encode-block-file-info info)))))

(test entry-status-maps-onto-cores-nstatus-and-back
  "Each status keyword, with and without a body and an undo record, encodes to
the nStatus Core would hold for that block and decodes back to itself. A body
we hold has passed BLOCK_VALID_TRANSACTIONS; :valid is BLOCK_VALID_SCRIPTS;
:invalid is BLOCK_FAILED_VALID over the level reached."
  (with-network (:regtest)
    (let* ((cs (bl.store:make-chain-state))
           (entry (first (add-mined-chain cs (add-regtest-genesis-entry cs) 1))))
      (loop for (status data undo expected)
              in '((:unknown nil nil 0) (:header-valid nil nil 2)
                   (:header-valid 8 nil 11) (:valid 8 40 29) (:valid nil nil 5)
                   (:invalid nil nil 34) (:invalid 8 nil 43))
            do (setf (bl.store:block-index-entry-status entry) status
                     (bl.store:block-index-entry-file entry) (and (or data undo) 0)
                     (bl.store:block-index-entry-data-pos entry) data
                     (bl.store:block-index-entry-undo-pos entry) undo)
               (is (= expected (bl.store:entry-disk-status entry))
                   "~A data=~A undo=~A" status data undo)
               (let ((back (bl.store:decode-disk-block-index
                            (bl.store:encode-disk-block-index entry))))
                 (is (eq status (bl.store:block-index-entry-status back)))
                 (is (eql data (bl.store:block-index-entry-data-pos back)))
                 (is (eql undo (bl.store:block-index-entry-undo-pos back))))))))

(test block-index-round-trips-through-the-block-tree-db
  "A saved index reloads with every entry, the parent links rebuilt from the
headers, and the chain work RECOMPUTED -- blocks/index stores neither hash nor
work. A NIL position must survive as NIL rather than becoming 0, because 0 is a
real position, the first record in a file."
  (with-network (:regtest)
    (with-temp-directory (dir "bl-btdb")
      (let* ((cs (bl.store:init-chain-state dir :network :regtest))
             (chain (add-mined-chain cs (add-regtest-genesis-entry cs) 3))
             (placed (first chain)) (body-only (second chain)) (header-only (third chain)))
        (setf (bl.store:block-index-entry-file placed) 0
              (bl.store:block-index-entry-data-pos placed) 8
              (bl.store:block-index-entry-undo-pos placed) 40
              (bl.store:block-index-entry-file body-only) 3
              (bl.store:block-index-entry-data-pos body-only) 0
              (bl.store:block-index-entry-status header-only) :header-valid)
        (bl.store:save-header-index cs)
        (let ((reloaded (bl.store:init-chain-state dir :network :regtest)))
          (is-true (bl.store:load-header-index reloaded))
          (is (= 4 (hash-table-count (bl.store:chain-state-block-index reloaded))))
          (flet ((back (e) (bl.store:get-block-index-entry
                            reloaded (bl.store:block-index-entry-hash e))))
            (let ((e (back placed)))
              (is (= 0 (bl.store:block-index-entry-file e)))
              (is (= 8 (bl.store:block-index-entry-data-pos e)))
              (is (= 40 (bl.store:block-index-entry-undo-pos e))))
            (let ((e (back body-only)))
              (is (= 3 (bl.store:block-index-entry-file e)))
              (is (eql 0 (bl.store:block-index-entry-data-pos e)))
              (is (null (bl.store:block-index-entry-undo-pos e))))
            (let ((e (back header-only)))
              (is (eq :header-valid (bl.store:block-index-entry-status e)))
              (is (null (bl.store:block-index-entry-file e)))
              (is (null (bl.store:block-index-entry-data-pos e)))
              (is (= (bl.store:block-index-entry-chain-work header-only)
                     (bl.store:block-index-entry-chain-work e))
                  "chain work recomputed on load must equal what was built")
              (is (eq (back body-only) (bl.store:block-index-entry-prev-entry e))
                  "the parent link must resolve to the reloaded parent object")
              (is (> (bl.store:block-index-entry-chain-work e)
                     (bl.store:block-index-entry-chain-work (back body-only)))
                  "each block adds its proof to its parent's work"))))))))

(test only-changed-entries-are-rewritten
  "A flush writes the 'b' record of each entry that changed since it was last
written (Core's m_dirty_blockindex), so a position appearing or disappearing,
and a status change, must each be seen. Missing one means an index that
claims a pruned body is still there, or an :invalid block that comes back
:valid after a restart."
  (with-network (:regtest)
    (with-temp-directory (dir "bl-btdb-dirty")
      (let* ((cs (bl.store:init-chain-state dir :network :regtest))
             (entry (first (add-mined-chain cs (add-regtest-genesis-entry cs) 1))))
        (bl.store:save-header-index cs)
        (is (null (bl.store::%changed-header-index-entries cs)))
        (setf (bl.store:block-index-entry-file entry) 2
              (bl.store:block-index-entry-data-pos entry) 1234)
        (is (member entry (bl.store::%changed-header-index-entries cs))
            "gaining a position must mark the entry changed")
        (bl.store:save-header-index cs)
        (setf (bl.store:block-index-entry-data-pos entry) nil
              (bl.store:block-index-entry-status entry) :invalid)
        (is (member entry (bl.store::%changed-header-index-entries cs)))
        (bl.store:save-header-index cs)
        (let ((reloaded (bl.store:init-chain-state dir :network :regtest)))
          (is-true (bl.store:load-header-index reloaded))
          (let ((e (bl.store:get-block-index-entry
                    reloaded (bl.store:block-index-entry-hash entry))))
            (is (null (bl.store:block-index-entry-data-pos e)))
            (is (eq :invalid (bl.store:block-index-entry-status e)))))))))

(test header-index-persist-key-still-tracks-everything-it-did-before
  "Re-check every field the change detector is supposed to notice, since a
silently dropped one means a status, tx-count or witness mark is never written."
  (let* ((entry (bl.store:make-block-index-entry
                 :hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 5)
                 :height 7 :status :header-valid))
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
                     (bl.ser:make-block-header)))
      (changes (setf (bl.store:block-index-entry-status-flags entry)
                     bl.store:+block-opt-witness+)))
    ;; And the key stays a fixnum, which is why the flush can compute it for
    ;; every entry on a 963k-entry index.
    (is (typep (bl.store::%entry-persist-key entry) 'fixnum))
    (is (plusp base))))

(test block-file-records-are-written-with-the-index
  "Core writes each changed CBlockFileInfo and nLastFile in the SAME batch as
the block index (BlockTreeDB::WriteBatchSync), and a Core node opening this
datadir reads them to know where its next block goes: an 'f' record short of
the bytes in use would have it write over live blocks. The file being appended
to reports the store's cursor, not its preallocated length on disk."
  (with-network (:regtest)
    (with-temp-directory (dir "bl-btdb-files")
      (let* ((bl.store:*flat-block-files* t)
             (store (bl.store:init-block-store dir))
             (cs (bl.store:init-chain-state dir :network :regtest)))
        (bl.store:ensure-genesis-on-disk store)
        (add-regtest-genesis-entry cs)
        (bl.store:rebuild-block-file-info store cs)
        (bl.store:save-header-index cs :block-store store)
        (multiple-value-bind (last-file table) (bl.store:read-block-tree-file-info dir)
          (is (= 0 last-file))
          (let ((info (gethash 0 table)))
            (is-true info)
            (is (= 1 (bl.store:block-file-info-blocks info)))
            (is (= 0 (bl.store:block-file-info-height-first info)))
            (is (plusp (bl.store:block-file-info-size info)))
            (is (< (bl.store:block-file-info-size info)
                   bl.kv:+blockfile-chunk-size+)
                "nSize is the used length, not the preallocated chunk")))))))

(test a-missing-block-index-is-a-first-run-not-corruption
  "No block index records at all is a legitimate first run: NIL loaded, and NO
reason -- the caller must not confuse it with a database it cannot read, or
every fresh node would refuse to start."
  (with-temp-directory (dir "bl-btdb-absent")
    (multiple-value-bind (loaded reason)
        (bl.store:load-header-index (bl.store:init-chain-state dir))
      (is (null loaded))
      (is (null reason)))))

(test an-untrustworthy-block-index-reports-a-reason
  "Core refuses to start on a block index it cannot load, `Error loading block
database' (node/chainstate.cpp:42-45), for three reasons among others: a header
that fails its own proof of work (LoadBlockIndexGuts, blockstorage.cpp:148-151),
a height with no entry below one that has (LoadBlockIndex, :457-460), and table
data that fails its checksum. Each must report a reason, distinguishable from
absence."
  (with-network (:regtest)
    ;; A header that does not meet its nBits.
    (with-temp-directory (dir "bl-btdb-pow")
      (let* ((cs (bl.store:init-chain-state dir :network :regtest))
             (entry (first (add-mined-chain cs (add-regtest-genesis-entry cs) 1)))
             (header (bl.store:block-index-entry-header entry)))
        ;; Tighten the target until this header no longer meets it.
        (setf (bl.ser:block-header-bits header) #x1d00ffff
              (bl.ser:block-header-cached-hash header) nil)
        (bl.store:save-header-index cs :force-full t)
        (let ((reason (nth-value 1 (bl.store:load-header-index
                                    (bl.store:init-chain-state dir :network :regtest)))))
          (is-true (and reason (search "CheckProofOfWork" reason))))))
    ;; A hole in the heights.
    (with-temp-directory (dir "bl-btdb-hole")
      (let* ((cs (bl.store:init-chain-state dir :network :regtest))
             (chain (add-mined-chain cs (add-regtest-genesis-entry cs) 3)))
        (remhash (bl.store:block-index-entry-hash (second chain))
                 (bl.store:chain-state-block-index cs))
        (bl.store:save-header-index cs)
        (let ((reason (nth-value 1 (bl.store:load-header-index
                                    (bl.store:init-chain-state dir :network :regtest)))))
          (is-true (and reason (search "non-contiguous" reason))))))
    ;; Table data overwritten on disk, as feature_init.py:202 perturbs it.
    (with-temp-directory (dir "bl-btdb-ldb")
      (let ((cs (bl.store:init-chain-state dir :network :regtest)))
        (add-mined-chain cs (add-regtest-genesis-entry cs) 40)
        (bl.store:save-header-index cs)
        ;; A reopen replays the log into a table file, which is what gets hit.
        (is-true (bl.store:load-header-index (bl.store:init-chain-state dir :network :regtest)))
        (let ((tables (directory (merge-pathnames "*.ldb" (bl.store:block-tree-db-path dir)))))
          (is-true tables)
          (dolist (table tables)
            (with-open-file (out table :direction :io :element-type '(unsigned-byte 8)
                                       :if-exists :overwrite)
              (file-position out 150)
              (write-sequence (make-array 200 :element-type '(unsigned-byte 8)
                                              :initial-element (char-code #\1))
                              out))))
        (let ((reason (nth-value 1 (bl.store:load-header-index
                                    (bl.store:init-chain-state dir :network :regtest)))))
          (is-true (stringp reason)))))))

(test descendants-of-a-failed-block-load-as-failed
  "Core LoadBlockIndex marks every descendant of a BLOCK_FAILED_VALID block
failed as it walks the heights (node/blockstorage.cpp:488-492)."
  (with-network (:regtest)
    (with-temp-directory (dir "bl-btdb-failed")
      (let* ((cs (bl.store:init-chain-state dir :network :regtest))
             (chain (add-mined-chain cs (add-regtest-genesis-entry cs) 3)))
        (setf (bl.store:block-index-entry-status (first chain)) :invalid)
        (bl.store:save-header-index cs)
        (let ((reloaded (bl.store:init-chain-state dir :network :regtest)))
          (is-true (bl.store:load-header-index reloaded))
          (is (eq :invalid (bl.store:block-index-entry-status
                            (bl.store:get-block-index-entry
                             reloaded (bl.store:block-index-entry-hash (third chain)))))))))))

(test a-chain-without-the-witness-mark-needs-redownload
  "Core NeedsRedownload (validation.cpp:4892-4908): walking down from the tip
while segwit is active, a block without BLOCK_OPT_WITNESS means the chain was
accepted without enforcing segwit. The mark is set when a body is stored at a
segwit-active height (ReceivedBlockTransactions, :3817-3819)."
  (with-network (:regtest)
    (let* ((bl.store:*segwit-height-fn* (constantly 2))
           (cs (bl.store:make-chain-state))
           (chain (add-mined-chain cs (add-regtest-genesis-entry cs) 3))
           (tip (third chain)))
      (setf (bl.store:chain-state-best-block-hash cs) (bl.store:block-index-entry-hash tip)
            (bl.store:chain-state-best-height cs) 3)
      (is-true (bl.store:chain-needs-redownload-p cs)
               "blocks 2 and 3 were never marked")
      (dolist (e chain) (bl.store:note-block-witness-received e))
      (is (zerop (bl.store:block-index-entry-status-flags (first chain)))
          "block 1 is below the activation height and is not marked")
      (is-false (bl.store:chain-needs-redownload-p cs))
      (let ((bl.store:*segwit-height-fn* (constantly 1)))
        (is-true (bl.store:chain-needs-redownload-p cs)
                 "a lower activation height reaches the unmarked block 1")))))

(defun %legacy-header-index-bytes (entries)
  "A v3 headerindex.dat by hand: magic, version, count, 197-byte entries,
CRC32 -- the format both live nodes carried until the block index moved into
blocks/index. ENTRIES are block-index-entries."
  (let ((bb (bl.ser:make-byte-buf)))
    (bl.ser:bb-write-bytes bb (map '(vector (unsigned-byte 8)) #'char-code "HIDX"))
    (bl.ser:bb-write-u32-le bb 3)
    (bl.ser:bb-write-u32-le bb (length entries))
    (dolist (e entries)
      (bl.ser:bb-write-bytes bb (bl.store:block-index-entry-hash e))
      (bl.ser:bb-write-u32-le bb (bl.store:block-index-entry-height e))
      (bl.ser:bb-write-bytes bb (bl.ser:serialize-block-header
                                 (bl.store:block-index-entry-header e)))
      (let ((work (bl.store:block-index-entry-chain-work e)))
        (loop for i from 31 downto 0
              do (bl.ser:bb-write-u8 bb (ldb (byte 8 (* 8 i)) work))))
      (bl.ser:bb-write-u8 bb (ecase (bl.store:block-index-entry-status e)
                               (:unknown 0) (:header-valid 1) (:valid 2) (:invalid 3)))
      (let ((prev (bl.store:block-index-entry-prev-entry e)))
        (bl.ser:bb-write-bytes bb (if prev
                                      (bl.store:block-index-entry-hash prev)
                                      (make-array 32 :element-type '(unsigned-byte 8)
                                                     :initial-element 0))))
      (bl.ser:bb-write-u32-le bb (bl.store:block-index-entry-tx-count e))
      (bl.ser:bb-write-i32-le bb (or (bl.store:block-index-entry-file e) -1))
      (bl.ser:bb-write-u32-le bb (or (bl.store:block-index-entry-data-pos e) #xFFFFFFFF))
      (bl.ser:bb-write-u32-le bb (or (bl.store:block-index-entry-undo-pos e) #xFFFFFFFF)))
    (let ((payload (bl.ser:bb-finish bb)))
      (concatenate '(vector (unsigned-byte 8)) payload (bl.store:compute-crc32 payload)))))

(defun %btdb-write-octets (path octets)
  (ensure-directories-exist path)
  (with-open-file (out path :direction :output :element-type '(unsigned-byte 8)
                            :if-exists :supersede :if-does-not-exist :create)
    (write-sequence octets out)))

(test a-legacy-header-index-migrates-into-the-block-tree-db
  "A datadir that still holds headerindex.dat is converted at start-up, in
place: every entry written to blocks/index, the count read back, and the old
file renamed headerindex.dat.migrated -- kept for a downgrade, never read
again. Entries the node stored or connected get BLOCK_OPT_WITNESS where segwit
applies, which the old format never recorded; without it the first start after
the migration would refuse the chain as needing a redownload."
  (with-network (:regtest)
    (with-temp-directory (dir "bl-btdb-migrate")
      (let* ((bl.store:*segwit-height-fn* (constantly 0))
             (source (bl.store:make-chain-state))
             (chain (add-mined-chain source (add-regtest-genesis-entry source) 3))
             (legacy (merge-pathnames "blocks/index/headerindex.dat" dir)))
        (setf (bl.store:block-index-entry-file (first chain)) 0
              (bl.store:block-index-entry-data-pos (first chain)) 8
              (bl.store:block-index-entry-status (third chain)) :header-valid)
        (%btdb-write-octets legacy (%legacy-header-index-bytes
                               (loop for e being the hash-values
                                       of (bl.store:chain-state-block-index source)
                                     collect e)))
        (let ((cs (bl.store:init-chain-state dir :network :regtest)))
          (is (= 4 (bl.store:migrate-legacy-header-index cs)))
          (is-false (probe-file legacy) "the old file must be renamed away")
          (is-true (probe-file (merge-pathnames "blocks/index/headerindex.dat.migrated" dir)))
          (is (null (bl.store:migrate-legacy-header-index cs))
              "a second start has nothing to migrate")
          (is-true (bl.store:load-header-index cs))
          (is (= 4 (hash-table-count (bl.store:chain-state-block-index cs))))
          (flet ((back (e) (bl.store:get-block-index-entry
                            cs (bl.store:block-index-entry-hash e))))
            (is (= 8 (bl.store:block-index-entry-data-pos (back (first chain)))))
            (is (eq :header-valid (bl.store:block-index-entry-status (back (third chain)))))
            (is (logtest bl.store:+block-opt-witness+
                         (bl.store:block-index-entry-status-flags (back (second chain))))
                "a connected block must carry the witness mark after migration")
            (is (zerop (bl.store:block-index-entry-status-flags (back (third chain))))
                "a header-only block was never received and is not marked")))))))

(test a-legacy-delta-log-is-part-of-the-migration
  "headerindex.delta holds the entries changed since the last snapshot -- the
most recent statuses, an operator's invalidateblock among them -- so migrating
the snapshot alone could turn an :invalid block :valid again. The migration
replays the delta bound to the snapshot on disk before it writes anything."
  (with-network (:regtest)
    (with-temp-directory (dir "bl-btdb-migrate-delta")
      (let* ((source (bl.store:make-chain-state))
             (chain (add-mined-chain source (add-regtest-genesis-entry source) 2))
             (entries (loop for e being the hash-values
                              of (bl.store:chain-state-block-index source) collect e))
             (snapshot (%legacy-header-index-bytes entries))
             (legacy (merge-pathnames "blocks/index/headerindex.dat" dir)))
        (%btdb-write-octets legacy snapshot)
        ;; The delta: header, then one CRC-framed batch marking block 2 invalid.
        (setf (bl.store:block-index-entry-status (second chain)) :invalid)
        (let* ((framed (%legacy-header-index-bytes (list (second chain))))
               ;; One v3 entry is the 197 bytes after the 12-byte file header.
               (entry-bytes (subseq framed 12 (+ 12 197)))
               (payload (concatenate '(vector (unsigned-byte 8))
                                     #(1 0 0 0) entry-bytes)))
          (%btdb-write-octets (merge-pathnames "headerindex.delta" dir)
                         (concatenate '(vector (unsigned-byte 8))
                                      (map 'vector #'char-code "HIDD")
                                      #(2 0 0 0)
                                      (subseq snapshot (- (length snapshot) 4))
                                      payload
                                      (bl.store:compute-crc32 payload))))
        (let ((cs (bl.store:init-chain-state dir :network :regtest)))
          (is (= 3 (bl.store:migrate-legacy-header-index cs)))
          (is-false (probe-file (merge-pathnames "headerindex.delta" dir)))
          (is-true (bl.store:load-header-index cs))
          (is (eq :invalid (bl.store:block-index-entry-status
                            (bl.store:get-block-index-entry
                             cs (bl.store:block-index-entry-hash (second chain)))))
              "the delta's status must survive the migration"))))))

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
    (flet ((claim (d) (claim-directory d))
           (release () (release-directory-locks))
           (held () (directory-locks-held)))
      (unwind-protect
           (progn
             (claim dir)
             (is (= 1 (held)))
             ;; The control that matters: a second claim is REFUSED.
             (signals error (claim dir))
             ;; Releasing it hands the directory back.
             (release)
             (is (zerop (held)))
             (claim dir)
             (is (= 1 (held))))
        (release)))
    ;; The lock file is left behind, as Core leaves it: its presence means
    ;; nothing, only the advisory lock on it does.
    (is-true (probe-file (merge-pathnames ".lock" dir)))))

(test directory-lock-refusal-is-worded-and-punctuated-as-cores
  "Core: `Cannot obtain a lock on directory %s. %s is probably already
running.' with fs::PathToString of the directory (init.cpp:1165).
feature_filelock.py:33 builds that whole sentence from the path it passed and
compares it to stderr, so a Lisp DIRECTORY pathname's trailing separator --
`.../regtest/' where Core prints `.../regtest' -- failed the test on one
character."
  (let ((dir (ensure-directories-exist
              (merge-pathnames "test-datadir-lock-text/" (uiop:temporary-directory)))))
    (unwind-protect
         (progn
           (claim-directory dir)
           (let ((message (handler-case (progn (claim-directory dir) nil)
                            (error (e) (princ-to-string e)))))
             (is-true message "a second claim must be refused")
             (is (search (format nil "Cannot obtain a lock on directory ~A. ~
bitcoin-lisp is probably already running."
                                 (string-right-trim "/" (namestring dir)))
                         message)
                 "Core's sentence, verbatim; got ~S" message)
             (is (null (search "/. bitcoin-lisp" message))
                 "no trailing separator before the full stop; got ~S" message)))
      (release-directory-locks))))

(test blocks-directory-is-locked-as-well-as-the-datadir
  "Core's LockDirectories claims GetDataDirNet() AND GetBlocksDirPath()
(init.cpp:1170-1174). -blocksdir can put the blk/rev files on a volume two
nodes share while their data directories differ, and those files are exactly
what a second writer corrupts; feature_filelock.py:37 starts a second node
with only -blocksdir pointing at a running node's directory."
  (let* ((root (ensure-directories-exist
                (merge-pathnames "test-blocksdir-lock/" (uiop:temporary-directory))))
         (data (ensure-directories-exist (merge-pathnames "data/" root)))
         (blocks (ensure-directories-exist (merge-pathnames "blocks/" root))))
    (unwind-protect
         (progn
           (claim-data-directories data blocks)
           (is (= 2 (directory-locks-held))
               "both directories claimed")
           (signals error (claim-directory blocks)))
      (release-directory-locks))
    ;; A blocks directory that IS the data directory is one lock, not two --
    ;; the same process must not deadlock against its own claim.
    (unwind-protect
         (progn
           (claim-data-directories data data)
           (is (= 1 (directory-locks-held))
               "one directory, one lock"))
      (release-directory-locks))))

;;;; Peer Health Monitoring Tests

(test peer-health-ping-follows-core
  "Core MaybeSendPing (net_processing.cpp:5487-5510): pings every PING_INTERVAL
(2 min) while none is outstanding; an outstanding ping is never replaced, and
one unanswered for TIMEOUT_INTERVAL (20 min) disconnects the peer."
  (is (= 120 bl.net::+ping-interval-seconds+))
  (is (= 1200 bl.net::+ping-timeout-seconds+))
  ;; Every peer here is stamped as long-connected: the ping TIMEOUT is behind
  ;; Core's ShouldRunInactivityChecks (net.cpp:2003-2006, and MaybeSendPing's
  ;; own first line), so a peer still inside its -peertimeout grace period is
  ;; not judged at all. PEERTIMEOUT-GATES-EVERY-LIVENESS-VERDICT covers the
  ;; gate itself; this test is the ladder behind it.
  (flet ((peer-with-ping (age-seconds &key (nonce 7))
           (let ((peer (bl.net:make-peer :state :ready)))
             (setf (bl.net:peer-connected-at peer) (- (bl.ser:get-unix-time) 3600)
                   (bl.net:peer-ping-nonce peer) nonce
                   (bl.net:peer-last-ping-time peer)
                   (- (bl.ser:get-time-micros) (* age-seconds 1000000)))
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
  ;; against a 0 initform, so a 0 stamp read as "never". A 0 stamp is a TIME
  ;; (the epoch, on the microsecond clock), so the ping is long overdue.
  (let ((peer (bl.net:make-peer :state :ready)))
    (setf (bl.net:peer-last-ping-time peer) 0)
    (is (eq :ping-sent
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
  ;; Ban through the shipped entry point: the list is keyed by CSubNet and
  ;; carries a BAN-ENTRY, so a raw hash write would build the wrong shape.
  (bl.net:ban-address "192.0.2.1" 3600)
  (is (bl.net:peer-banned-p "192.0.2.1"))
  ;; Expired ban: still on the list, but past its time.
  (bl.net:ban-address "192.0.2.2" -1)
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
            (list (cons peer old-time)))
      (setf (gethash hash2 (bl.net:ibd-context-in-flight ctx))
            (list (cons peer old-time))))
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
  (with-network (:regtest)
    (with-temp-directory (base-path "bl-restart")
      (let* ((state1 (bl.store:init-chain-state base-path :network :regtest))
             (utxo1 (bl.store:make-utxo-set))
             (chain (add-mined-chain state1 (add-regtest-genesis-entry state1) 3))
             (tip (third chain)))
        (bl.store:update-chain-tip state1 (bl.store:block-index-entry-hash tip) 3)
        ;; Add some UTXOs as if blocks were connected
        (let ((txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xCC))
              (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
          (bl.store:add-utxo utxo1 txid 0 5000000000 script 1 :coinbase t)
          (bl.store:add-utxo utxo1 txid 1 2500000000 script 1 :coinbase t))
        ;; Save everything (simulating shutdown)
        (bl.store:save-state state1)
        (bl.store:save-utxo-set utxo1 (bl.store:utxo-set-file-path base-path))
        (bl.store:save-header-index state1)
        ;; Step 2: Create a fresh state (simulating restart)
        (let ((state2 (bl.store:init-chain-state base-path :network :regtest))
              (utxo2 (bl.store:make-utxo-set)))
          (bl.store:load-state state2)
          (bl.store:load-utxo-set utxo2 (bl.store:utxo-set-file-path base-path))
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
          (let ((tip-entry (bl.store:get-block-index-entry
                            state2 (bl.store:block-index-entry-hash tip))))
            (is (not (null tip-entry)))
            (is (= 3 (bl.store:block-index-entry-height tip-entry)))
            (is (= (bl.store:block-index-entry-chain-work tip)
                   (bl.store:block-index-entry-chain-work tip-entry)))
            ;; Verify chain linkage exists
            (let ((prev (bl.store:block-index-entry-prev-entry tip-entry)))
              (is (not (null prev)))
              (is (= 2 (bl.store:block-index-entry-height prev))))))))))

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
    (clear-undo-cache)
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
    (clear-undo-cache)))

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
    (clear-undo-cache)
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
      (clear-undo-cache)
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
    (clear-undo-cache)))

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
    (clear-undo-cache)
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
        ;; The block index is not reloaded here: these fixture blocks carry
        ;; made-up hashes, which blocks/index cannot hold -- it stores no hash
        ;; and recomputes each from its header. BLOCK-INDEX-ROUND-TRIPS-THROUGH-
        ;; THE-BLOCK-TREE-DB covers that half with mined headers.
        (let ((state2 (bl.store:init-chain-state base-path))
              (utxo2 (bl.store:make-utxo-set)))
          (bl.store:load-state state2)
          (bl.store:load-utxo-set utxo2
                                               (bl.store:utxo-set-file-path base-path))
          ;; Verify chain state matches
          (is (= 3 (bl.store:current-height state2)))
          (is (equalp (third chain-b-hashes)
                      (bl.store:best-block-hash state2)))
          ;; Verify UTXO count matches
          (is (= utxo-count-before (bl.store:utxo-count utxo2))))))
    ;; Cleanup
    (clear-undo-cache)
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

(test periodic-flush-empties-the-coins-cache-only-on-the-size-trigger
  "MAYBE-PERIODIC-FLUSH passes Core's empty_cache down, so which trigger fired
decides whether the warm coins cache survives the write. Core computes
empty_cache = FORCE_FLUSH || fCacheLarge || fCacheCritical
(validation.cpp:2761-2766) and then picks
`empty_cache ? CoinsTip().Flush() : CoinsTip().Sync()' (:2812); fPeriodicWrite
-- the DATABASE_WRITE_INTERVAL timer, whose analogue here is the 600-second /
25000-block pair -- is deliberately NOT in it, because a write driven by the
clock has no reason to throw away entries that cost pull-through reads to
rebuild.

Both directions are asserted, so neither can pass vacuously: the
time-triggered flush must leave the entry in the table AND commit it to the
base view (a flush that did nothing would fail the second half), and the
size-triggered flush must empty the table."
  (let* ((base (ensure-directories-exist
                (merge-pathnames (format nil "test-periodic-flush-~D/"
                                         (get-universal-time))
                                 (uiop:temporary-directory))))
         (node (bl:make-node)))
    (unwind-protect
         (let ((cs (%shutdown-fixture-chainstate base "" 3))
               (bl:*node* node))
           (setf (bl:node-chainstates node) (list cs))
           (let* ((view (bl.store:chain-state-coins-view cs))
                  (entries (coins-cache-entries view))
                  (key (bl.store:make-utxo-key
                        (make-array 32 :element-type (quote (unsigned-byte 8))
                                       :initial-element 3)
                        0)))
             (is (= 1 (hash-table-count entries))
                 "the fixture starts with one cached coin")
             ;; The CLOCK alone. The cache is nowhere near its budget, so this
             ;; is Core's fPeriodicWrite with fCacheLarge false.
             (let ((bl::*blocks-since-flush* 0)
                   (bl::*last-flush-universal-time*
                     (- (bl.ser:get-node-time) 1200)))
               (bl:maybe-periodic-flush cs nil 3))
             (is (= 1 (hash-table-count entries))
                 "a time-triggered flush emptied the coins cache Core would have kept")
             (is (not (null (bl.store:coins-view-db-get
                             (bl.store:coins-view-cache-base view) key)))
                 "the time-triggered flush left the coin uncommitted")
             ;; The SIZE tier. A budget below the cache's own usage makes
             ;; LARGE-COINS-CACHE-THRESHOLD fire, which is Core's fCacheLarge
             ;; and the one trigger that IS empty_cache.
             (let ((bl::*coins-cache-budget-bytes* 100))
               (is (>= (bl.store:view-mem-bytes view)
                       (bl:chainstate-coins-cache-budget cs))
                   "the fixture did not reach the size trigger")
               (bl:maybe-periodic-flush cs nil 3))
             (is (zerop (hash-table-count entries))
                 "a size-triggered flush kept the coins cache Core would have emptied")))
      (uiop:delete-directory-tree base :validate t :if-does-not-exist :ignore))))

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
  (with-network (:regtest)
    (with-temp-directory (base "bl-coins-order")
      (let* ((node (bl:make-node))
             (cs (bl.store:init-chain-state base :network :regtest))
             ;; A block index entry accepted since the last flush: in memory
             ;; only, which is the ordinary state between flushes.
             (hash (bl.store:block-index-entry-hash
                    (first (add-mined-chain cs (add-regtest-genesis-entry cs) 1)))))
        (setf (bl:node-chainstates node) (list cs))
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
chainstate with a dirty coin, a mempool, an address book, a data directory.

It stands in for a node that has FINISHED starting, so the mempool load-tried
latch is set the way the startup path sets it (Core SetLoadTried after
LoadMempool, init.cpp:2048). Without it the shutdown dump is correctly skipped
-- Core does not overwrite a good mempool.dat from a node that never read one
-- and a test about teardown ORDERING would be measuring the persist gate
instead. That gate has its own test, on both branches."
  (setf bl.mp:*mempool-load-tried* t)
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

(test a-stop-during-start-up-waits-for-start-up-to-return
  "A SIGTERM during start-up is only registered; the teardown runs once
START-NODE has returned (Core: AppInitMain returns, then Shutdown runs,
bitcoind.cpp:180-193). The servicer used to run stop-node at once, closing the
index databases under the index threads start-up was still starting -- a
memory fault and exit code 1 at feature_init.py:73's `scheduler thread start'.
It now waits while *NODE-STARTING* is set, and stops waiting when start-up
ends or a watchdog takes over."
  (let* ((starting 'bl::*node-starting*)
         (watchdog 'bl::*shutdown-watchdog-running*)
         (await 'bl::%await-start-up-end)
         (saved (list (symbol-value starting) (symbol-value watchdog))))
    (flet ((waiter ()
             (bt:make-thread (lambda () (funcall await :poll-seconds 0.01))
                             :name "await-start-up-test"))
           (ends-p (thread)
             (loop repeat 50 while (bt:thread-alive-p thread) do (sleep 0.1))
             (not (bt:thread-alive-p thread))))
      (unwind-protect
           (progn
             (setf (symbol-value starting) t
                   (symbol-value watchdog) nil)
             (let ((thread (waiter)))
               (sleep 0.3)
               (is-true (bt:thread-alive-p thread) "still waiting while start-up runs")
               (setf (symbol-value starting) nil)
               (is-true (ends-p thread) "start-up's end releases it"))
             ;; A watchdog taking over releases it too.
             (setf (symbol-value starting) t)
             (let ((thread (waiter)))
               (setf (symbol-value watchdog) t)
               (is-true (ends-p thread))))
        (setf (symbol-value starting) (first saved)
              (symbol-value watchdog) (second saved))))))

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

(test a-serviced-shutdown-request-interrupts-the-sync-loops-at-once
  "Core runs Interrupt(node) the moment the shutdown signal's wait returns
(bitcoind.cpp:283-286, init.cpp:268-286): the message handler stops at its
next message. Ours waited for the watchdog's once-a-second poll to reach
stop-node, and the sync thread meanwhile connected 40 blocks past -stopatheight
and validated an assumeutxo background chainstate in a node told to stop
(feature_assumeutxo.py:695). The servicer now sets the sync loops' stop flag
itself when it wakes, even while a watchdog owns the teardown."
  (%with-shutdown-node (node base)
    (is-true node) (is-true base)
    (bl::%open-shutdown-pipe)
    (let ((servicer nil))
      (unwind-protect
           (progn
             ;; A watchdog owns the teardown, so the servicer runs no stop-node.
             (setf bl::*shutdown-watchdog-running* t
                   bl::*shutdown-request* (cons "-stopatheight=1 reached" 0))
             (is-false (bl.net:ibd-stop-requested-p) "the flag was already set")
             (setf servicer (bt:make-thread #'bl::%run-shutdown-servicer
                                            :name "servicer-under-test"))
             (bl::%write-shutdown-token)
             (loop repeat 100 while (bt:thread-alive-p servicer) do (sleep 0.05))
             (is-false (bt:thread-alive-p servicer) "the servicer never woke")
             (is-true (bl.net:ibd-stop-requested-p)
                      "the sync loops were not interrupted until stop-node"))
        (when (and servicer (bt:thread-alive-p servicer))
          (ignore-errors (bt:destroy-thread servicer)))))))

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
