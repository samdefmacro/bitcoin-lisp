(in-package #:bitcoin-lisp.tests)

(def-suite :block-undo-tests
  :description "Core's CBlockUndo record (undo.h)"
  :in :bitcoin-lisp-tests)

(in-suite :block-undo-tests)

;;;; Bitcoin Core ships no CBlockUndo test vectors, so byte-exactness is
;;;; established by layering rather than by a golden file:
;;;;
;;;; - TxOutCompression (the amount and script codecs) is already verified
;;;;   against Core's own compress_tests.cpp in :compressor-tests;
;;;; - Core's VARINT is verified there too, including the canonical examples
;;;;   from serialize.h;
;;;; - CompactSize is exercised across the whole serialization suite.
;;;;
;;;; What is NEW here is the COMPOSITION -- Core's field order, its nesting,
;;;; and the dummy byte's condition -- so that is what these assert, against
;;;; the already-verified primitives rather than against hand-computed bytes.
;;;; A hand-copied vector has already presented as a phantom bug once in this
;;;; project; deriving from verified pieces avoids repeating that.

(defun %bu-entry (&key (value 50000) (height 100) coinbase (script #(#x51)))
  (bl.store:make-utxo-entry
   :value value
   :script-pubkey (coerce script '(simple-array (unsigned-byte 8) (*)))
   :height height
   :coinbase coinbase))

(defun %bu-expected-coin-bytes (entry)
  "The bytes Core's TxInUndoFormatter::Ser produces, assembled here from the
primitives that are individually verified against Core."
  (let ((bb (bl.ser:make-byte-buf)))
    (bl.ser:bb-write-core-varint
     bb (+ (* (bl.store:utxo-entry-height entry) 2)
           (if (bl.store:utxo-entry-coinbase entry) 1 0)))
    (when (plusp (bl.store:utxo-entry-height entry))
      (bl.ser:bb-write-u8 bb 0))
    (bl.ser:bb-write-compressed-tx-out
     bb (bl.store:utxo-entry-value entry)
     (bl.store:utxo-entry-script-pubkey entry))
    (bl.ser:bb-finish bb)))

;;; --- Layout -----------------------------------------------------------------

(test block-undo-layout-is-core-s-nesting
  "CompactSize(tx count), then per transaction CompactSize(input count), then
each Coin. Nothing else -- in particular no outpoint, which is the whole point
of the format: position names the coin."
  (let* ((a (%bu-entry :value 1000 :height 5))
         (b (%bu-entry :value 2000 :height 6))
         (c (%bu-entry :value 3000 :height 7))
         (bytes (bl.store:serialize-block-undo (list (list a b) (list c))))
         (expected (concatenate '(vector (unsigned-byte 8))
                                #(2)            ; two transactions
                                #(2)            ; first has two inputs
                                (%bu-expected-coin-bytes a)
                                (%bu-expected-coin-bytes b)
                                #(1)            ; second has one input
                                (%bu-expected-coin-bytes c))))
    (is (equalp expected bytes))))

(test block-undo-dummy-byte-appears-exactly-when-height-is-positive
  "Core writes a zero byte after the height/coinbase code iff height > 0, for
compatibility with an undo format that kept a transaction version there
(undo.h:26-33). The condition is the whole rule, so pin both sides of it."
  (let* ((at-zero (%bu-entry :height 0))
         (above-zero (%bu-entry :height 1))
         (b0 (bl.store:serialize-block-undo (list (list at-zero))))
         (b1 (bl.store:serialize-block-undo (list (list above-zero)))))
    ;; VARINT(0) and VARINT(2) are both one byte, and the outputs are identical
    ;; apart from the code and the dummy, so the length difference is exactly
    ;; the dummy byte.
    (is (= (1+ (length b0)) (length b1)))
    ;; And it really is a zero byte, in the right place: after the code.
    (is (= 0 (aref b1 3)))
    (is (= 2 (aref b1 2)))))

(test block-undo-round-trips-including-the-awkward-values
  "Round-trip through the codec preserves every field, for the cases most
likely to be mishandled: height 0, a coinbase coin, the maximum money value,
an empty script, and a script long enough to leave the compressed special
forms behind."
  (let ((cases (list (%bu-entry :height 0 :value 0 :script #())
                     (%bu-entry :height 1 :coinbase t)
                     (%bu-entry :height #xFFFFFFFF :value 2100000000000000)
                     (%bu-entry :value 1 :script (make-array 100 :initial-element #xAB))
                     ;; A P2PKH script, which the compressor stores in a
                     ;; special form rather than raw.
                     (%bu-entry :script (concatenate 'list
                                                     '(#x76 #xA9 #x14)
                                                     (make-list 20 :initial-element #x11)
                                                     '(#x88 #xAC))))))
    (let* ((bytes (bl.store:serialize-block-undo (list cases)))
           (back (first (bl.store:deserialize-block-undo bytes))))
      (is (= (length cases) (length back)))
      (loop for want in cases
            for got in back
            do (is (= (bl.store:utxo-entry-value want)
                      (bl.store:utxo-entry-value got)))
               (is (= (bl.store:utxo-entry-height want)
                      (bl.store:utxo-entry-height got)))
               (is (eq (and (bl.store:utxo-entry-coinbase want) t)
                       (and (bl.store:utxo-entry-coinbase got) t)))
               (is (equalp (bl.store:utxo-entry-script-pubkey want)
                           (bl.store:utxo-entry-script-pubkey got)))))))

(test block-undo-handles-a-block-with-nothing-to-undo
  "A coinbase-only block has an empty vtxundo, which must serialize to a single
zero CompactSize and read back as the empty list -- not as a failure."
  (let ((bytes (bl.store:serialize-block-undo '())))
    (is (equalp #(0) bytes))
    (is (null (bl.store:deserialize-block-undo bytes))))
  ;; A transaction with no inputs is not a thing a real block contains, but the
  ;; nesting must still be unambiguous.
  (let ((bytes (bl.store:serialize-block-undo (list '()))))
    (is (equalp #(1 0) bytes))
    (is (equal '(()) (bl.store:deserialize-block-undo bytes)))))

;;; --- The bridge from our (txid index entry) triples --------------------------

(defun %bu-test-block (input-counts)
  "A block with a coinbase plus one transaction per element of INPUT-COUNTS,
each spending that many distinct outpoints."
  (let ((txs (list (make-mempool-test-tx :input-id 0))))
    (loop for count in input-counts
          for tx-i from 1
          do (push (bl.ser:make-transaction
                    :version 1
                    :inputs (coerce
                             (loop for j below count
                                   collect (bl.ser:make-tx-in
                                            :previous-output
                                            (bl.ser:make-outpoint
                                             :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                  :initial-element (+ (* tx-i 16) j))
                                             :index j)
                                            :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                                            :sequence #xFFFFFFFF))
                             'vector)
                    :outputs (vector (bl.ser:make-tx-out
                                      :value 1000
                                      :script-pubkey (coerce #(#x51) '(simple-array (unsigned-byte 8) (*)))))
                    :lock-time 0)
                   txs))
    (bl.ser:make-bitcoin-block
     :header (bl.ser:make-block-header)
     :transactions (nreverse txs))))

(defun %bu-spent-for (block)
  "The (txid index entry) triples APPLY-BLOCK-TO-UTXO-SET would produce for
BLOCK: every non-coinbase input, in apply order."
  (let ((out '()))
    (loop for tx in (rest (bl.ser:bitcoin-block-transactions block))
          for h from 10
          do (bl.ser:dovector
                 (input (bl.ser:transaction-inputs tx))
               (let ((prevout (bl.ser:tx-in-previous-output input)))
                 (push (list (bl.ser:outpoint-hash prevout)
                             (bl.ser:outpoint-index prevout)
                             (%bu-entry :height h
                                        :value (+ 500 (bl.ser:outpoint-index
                                                       prevout))))
                       out))))
    (nreverse out)))

(test block-undo-bridge-round-trips-our-triples
  "Grouping our flat triples into Core's shape and back must reproduce them
exactly -- outpoints included, even though the format stores none of them."
  (let* ((block (%bu-test-block '(1 3 2)))
         (spent (%bu-spent-for block))
         (grouped (bl.store:block-undo-from-spent-utxos block spent))
         (back (bl.store:spent-utxos-from-block-undo block grouped)))
    (is (equal '(1 3 2) (mapcar #'length grouped)))
    (is (= (length spent) (length back)))
    (loop for want in spent
          for got in back
          do (is (equalp (first want) (first got)))
             (is (= (second want) (second got)))
             (is (= (bl.store:utxo-entry-value (third want))
                    (bl.store:utxo-entry-value (third got)))))
    ;; And through the wire format, which is the combination that P2 will use.
    (let ((decoded (bl.store:deserialize-block-undo
                    (bl.store:serialize-block-undo grouped))))
      (is (equal '(1 3 2) (mapcar #'length decoded))))))

(test block-undo-bridge-refuses-inconsistent-input
  "Core makes both mismatches DISCONNECT_FAILED (validation.cpp:2187, 2224),
because the position of a coin is the only thing naming it: a short, long or
misaligned list would restore the WRONG coins rather than fail. So the
conversion must refuse, not truncate."
  (let* ((block (%bu-test-block '(2 2)))
         (spent (%bu-spent-for block)))
    (signals error (bl.store:block-undo-from-spent-utxos block (rest spent)))
    (signals error (bl.store:block-undo-from-spent-utxos
                    block (append spent (list (first spent)))))
    ;; Misaligned: right length, wrong outpoints (two entries swapped).
    (let ((swapped (copy-list spent)))
      (rotatef (nth 0 swapped) (nth 1 swapped))
      (signals error (bl.store:block-undo-from-spent-utxos block swapped)))
    ;; The reverse direction checks the same two invariants.
    (let ((grouped (bl.store:block-undo-from-spent-utxos block spent)))
      (signals error (bl.store:spent-utxos-from-block-undo block (rest grouped)))
      (signals error (bl.store:spent-utxos-from-block-undo
                      block (list (first grouped) (rest (second grouped))))))))

(test block-undo-is-smaller-than-the-format-it-will-replace
  "The reason Core's format is worth adopting: it stores no outpoint and
compresses the amount and script, against the 32-byte txid + 4-byte index +
uncompressed fields written today. Asserted rather than asserted-in-prose so
a regression in the compressor shows up here too."
  (let* ((block (%bu-test-block '(4 4 4)))
         (spent (%bu-spent-for block))
         (core-bytes (length (bl.store:serialize-block-undo
                              (bl.store:block-undo-from-spent-utxos block spent))))
         ;; What save-undo-data-to-disk writes for the same data, per entry:
         ;; 32-byte txid + 4-byte index + i64 value + u32 height + u8 coinbase
         ;; + u32 script length + script.
         (ours (+ 4 4 4                       ; magic + version + count
                  (* (length spent) (+ 32 4 8 4 1 4 1)))))
    (is (< core-bytes ours))))

;;;; P6: undo data in rev?????.dat
;;;;
;;;; The tests above prove the CODEC. These prove the WIRING: that the codec is
;;;; what actually reaches the disk, that the legacy format still reads, and
;;;; that a restart does not overwrite live undo data.

(defmacro %with-undo-store ((store chain-state dir) &body body)
  "A temp data directory with a flat-file block store, a chain state, and the
undo specials bound to them."
  `(let* ((,dir (merge-pathnames
                 (format nil "bl-undo-~D/" (get-internal-real-time))
                 (uiop:temporary-directory)))
          (bl.store:*flat-block-files* t))
     (unwind-protect
          (progn
            (ensure-directories-exist ,dir)
            (let* ((,store (bl.store:init-block-store ,dir))
                   (,chain-state (bl.store:make-chain-state))
                   (bl.val::*undo-block-store* ,store)
                   (bl.val::*undo-chain-state* ,chain-state)
                   (bl.val::*undo-base-path*
                     (merge-pathnames "undo/" ,dir)))
              ;; Declared here so a body that uses only some of the three need
              ;; not open with a DECLARE of its own — spliced in below, it would
              ;; not be at the head of a binding form.
              (declare (ignorable ,store ,chain-state))
              (ensure-directories-exist bl.val::*undo-base-path*)
              ,@body))
       (ignore-errors (uiop:delete-directory-tree ,dir :validate t
                                                      :if-does-not-exist :ignore)))))

(defun %undo-store-block (store chain-state block height)
  "Store BLOCK flat, add its index entry, and record nFile/nDataPos — the state
save-undo-data-to-disk needs before it can write a rev record."
  (let ((hash (bl.ser:block-header-hash
               (bl.ser:bitcoin-block-header block))))
    (let ((located (nth-value 1 (bl.store:store-block
                                 store block :height height))))
      (bl.store:add-block-index-entry
       chain-state
       (bl.store:make-block-index-entry
        :hash hash :height height
        :header (bl.ser:bitcoin-block-header block)
        :status :valid))
      (bl.store:note-block-position chain-state hash located)
      hash)))

(test undo-round-trips-through-a-rev-file
  "The connect path writes Core's CBlockUndo into the rev file paired with the
block's blk file, and the disconnect path reads the same triples back.

This is the wiring the codec was written for: before it, save-undo-data-to-disk
wrote (txid, index, entry) triples into one file per block, and the codec had
no caller at all."
  (%with-undo-store (store chain-state dir)
    (let* ((block (%bu-test-block '(2 1 3)))
           (spent (%bu-spent-for block))
           (hash (%undo-store-block store chain-state block 7)))
      (let ((pos (bl.val::save-undo-data-to-disk
                  hash spent :block block)))
        (is-true pos "the undo record did not go to a rev file")
        ;; nUndoPos is recorded on the index entry, which is the ONLY thing
        ;; that can find the record again.
        (let ((entry (bl.store:get-block-index-entry chain-state hash)))
          (is-true (bl.store:block-index-entry-undo-pos entry))
          (is (eql (bl.store:block-index-entry-file entry)
                   (bl.store:flat-file-pos-file pos))
              "the undo record must live in the block's own file number"))
        ;; No legacy file was written.
        (is-false (probe-file (bl.val::undo-file-path hash))
                  "a rev record was written AND a legacy file"))
      (let ((back (bl.val::load-undo-data-from-disk hash)))
        (is (= (length spent) (length back)))
        (is-true (bl.val::%undo-lists-equal-p spent back)
                 "the triples did not survive the rev-file round trip")))))

(test undo-falls-back-to-the-legacy-file-and-still-reads-it
  "Two fallbacks, both of which a live store depends on. Without a block the
Core format cannot be written at all (it has no outpoints, so grouping needs
the block); and a block that is not in a flat file has no rev file to pair
with, since an undo record must go in its block's file number."
  (%with-undo-store (store chain-state dir)
    (let* ((block (%bu-test-block '(1 2)))
           (spent (%bu-spent-for block))
           (hash (%undo-store-block store chain-state block 3)))
      ;; No block supplied: legacy format, and it reads back.
      (is-false (bl.val::save-undo-data-to-disk hash spent)
                "wrote a rev record with no block to group by")
      (is-true (probe-file (bl.val::undo-file-path hash)))
      (is-true (bl.val::%undo-lists-equal-p
                spent (bl.val::load-undo-data-from-disk hash)))
      ;; Flat files off: legacy, even with the block in hand.
      (let ((bl.store:*flat-block-files* nil))
        (is-false (bl.val::save-undo-data-to-disk
                   hash spent :block block)
                  "wrote a rev record with the flat files off")))))

(test undo-dual-read-prefers-the-rev-record
  "A store that has ever had the flat files on holds both forms, and the
migration writes the rev record BEFORE deleting the legacy file. Preferring the
rev record is what makes a half-migrated store read the copy that is certainly
complete — and what makes a failed migration recoverable by clearing nUndoPos."
  (%with-undo-store (store chain-state dir)
    (let* ((block (%bu-test-block '(2)))
           (spent (%bu-spent-for block))
           (hash (%undo-store-block store chain-state block 5)))
      ;; Both forms on disk, with DIFFERENT contents so the answer identifies
      ;; which one was read.
      (bl.val::save-undo-data-to-disk hash spent)
      (is-true (probe-file (bl.val::undo-file-path hash)))
      (let ((altered (mapcar (lambda (triple)
                               (destructuring-bind (txid index entry) triple
                                 (list txid index
                                       (%bu-entry :value 424242
                                                  :height (bl.store:utxo-entry-height entry)))))
                             spent)))
        (bl.val::save-undo-data-to-disk hash altered :block block)
        (let ((back (bl.val::load-undo-data-from-disk hash)))
          (is-true (bl.val::%undo-lists-equal-p altered back)
                   "the legacy file was read even though a rev record existed")))
      ;; Clearing nUndoPos falls back to the legacy file, which is exactly how
      ;; a failed migration keeps serving the trustworthy copy.
      (let ((entry (bl.store:get-block-index-entry chain-state hash)))
        (setf (bl.store:block-index-entry-undo-pos entry) nil))
      (is-true (bl.val::%undo-lists-equal-p
                spent (bl.val::load-undo-data-from-disk hash))))))

(test undo-record-checksum-is-verified
  "Core checksums every undo record with SHA256d(prev block hash || payload)
and treats a mismatch as a failed read (UndoReadFromDisk,
blockstorage.cpp:1075-1096). The prev hash is not stored in the record, so the
checksum also binds the record to the block that claims it."
  (%with-undo-store (store chain-state dir)
    (let* ((payload (coerce #(1 2 3 4 5) '(simple-array (unsigned-byte 8) (*))))
           (prev (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9))
           (other (make-array 32 :element-type '(unsigned-byte 8) :initial-element 8))
           (pos (bl.store:store-undo-flat store 0 prev payload)))
      (is (equalp payload (bl.store:read-undo-flat store pos prev)))
      (is-false (bl.store:read-undo-flat store pos other)
                "a record read with the wrong prev hash passed its checksum")
      ;; A position that is not a record at all reads as absent, not as an error.
      (is-false (bl.store:read-undo-flat
                 store (bl.store:make-flat-file-pos 0 4000) prev)))))

(test undo-append-cursor-survives-a-restart
  "A rev record carries no block hash, so nothing can rebuild the hash->record
map by scanning — but the APPEND CURSOR still has to be recovered, or the first
undo record written after a restart lands on top of the records already there.
Core persists nUndoSize per file; we re-derive it by walking the framing."
  (%with-undo-store (store chain-state dir)
    (let* ((prev (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3))
           (a (coerce #(10 11 12) '(simple-array (unsigned-byte 8) (*))))
           (b (coerce #(20 21 22 23 24) '(simple-array (unsigned-byte 8) (*))))
           (pos-a (bl.store:store-undo-flat store 0 prev a)))
      ;; Reopen the store, as a restart would.
      (let ((reopened (bl.store:init-block-store dir)))
        (let ((pos-b (bl.store:store-undo-flat reopened 0 prev b)))
          (is (> (bl.store:flat-file-pos-pos pos-b)
                 (bl.store:flat-file-pos-pos pos-a))
              "the second record was written at or before the first")
          ;; Both records are intact — the point of recovering the cursor.
          (is (equalp a (bl.store:read-undo-flat reopened pos-a prev))
              "the restart overwrote the record already in the file")
          (is (equalp b (bl.store:read-undo-flat reopened pos-b prev))))))))

(test undo-migrates-out-of-a-legacy-file
  "migrateblocks moves a block's undo data into the matching rev file, and only
deletes the legacy file once the rev record has been read back and compared —
the same safety rule the block migration follows, because until then the legacy
file is the only copy."
  (%with-undo-store (store chain-state dir)
    (let* ((block (%bu-test-block '(3 1)))
           (spent (%bu-spent-for block))
           (hash (%undo-store-block store chain-state block 11)))
      (bl.val::save-undo-data-to-disk hash spent)
      (is-true (probe-file (bl.val::undo-file-path hash)))
      (is (eq :migrated (bl.val:migrate-undo-to-flat hash)))
      (is-false (probe-file (bl.val::undo-file-path hash))
                "the legacy undo file survived a successful migration")
      (is-true (bl.val::%undo-lists-equal-p
                spent (bl.val::load-undo-data-from-disk hash)))
      ;; Nothing to migrate is not a failure.
      (is (eq :skipped (bl.val:migrate-undo-to-flat hash))))))

(test undo-append-cursor-survives-the-real-startup-sequence
  "The live node runs init-block-store AND THEN rebuild-block-file-info, which
opens with a clrhash of the per-file table. Recovering the rev cursors in
init-block-store alone is therefore not enough — and the first version of this
work did exactly that.

What went wrong is worth stating precisely, because a green suite hid it: with
UNDO-SIZE back at 0, the next undo record written to a file allocated from
offset 0, and flat-file-allocate PREALLOCATES A WHOLE CHUNK OF ZEROS — one MiB
straight over the records already there. Every block whose nUndoPos fell in
that MiB then failed its checksum, get-undo-data returned NIL, and perform-reorg
refused permanently. Once per restart, per rev file."
  (%with-undo-store (store chain-state dir)
    (let* ((block (%bu-test-block '(2 2)))
           (spent (%bu-spent-for block))
           (hash (%undo-store-block store chain-state block 4)))
      (is-true (bl.val::save-undo-data-to-disk
                hash spent :block block))
      (let ((entry (bl.store:get-block-index-entry chain-state hash)))
        ;; Restart, exactly as the node does it.
        (let ((reopened (bl.store:init-block-store dir)))
          (bl.store:rebuild-block-file-info reopened chain-state)
          (let ((bl.val::*undo-block-store* reopened))
            ;; The cursor must be past the existing record.
            (let* ((prev (make-array 32 :element-type '(unsigned-byte 8)
                                        :initial-element 7))
                   (pos (bl.store:store-undo-flat
                         reopened
                         (bl.store:block-index-entry-file entry)
                         prev (coerce #(1 2 3) '(simple-array (unsigned-byte 8) (*))))))
              (is (> (bl.store:flat-file-pos-pos pos)
                     (bl.store:block-index-entry-undo-pos entry))
                  "the post-restart write landed on top of the existing record"))
            ;; And the original record still reads, which is the real assertion.
            (is-true (bl.val::%undo-lists-equal-p
                      spent (bl.val::load-undo-data-from-disk hash))
                     "the restart destroyed undo data that was already on disk")))))))

(test undo-is-written-once-per-block
  "Core writes undo data only when the block has none: `if (block.GetUndoPos()
.IsNull())` (blockstorage.cpp:970). Without that guard a block disconnected and
reconnected by a reorg appends a second full record every time — and nUndoPos
changes VALUE while its presence is unchanged, which the header index's delta
log keys on, so the persisted offset silently stays a generation behind."
  (%with-undo-store (store chain-state dir)
    (let* ((block (%bu-test-block '(1 1)))
           (spent (%bu-spent-for block))
           (hash (%undo-store-block store chain-state block 6))
           (first-pos (bl.val::save-undo-data-to-disk
                       hash spent :block block))
           (bytes-after-first (bl.store:block-storage-size-mib store)))
      (let ((second-pos (bl.val::save-undo-data-to-disk
                         hash spent :block block)))
        (is (= (bl.store:flat-file-pos-pos first-pos)
               (bl.store:flat-file-pos-pos second-pos))
            "a second connect appended a duplicate undo record"))
      (is (= bytes-after-first (bl.store:block-storage-size-mib store))
          "the skipped write still grew the storage total")
      (is-true (bl.val::%undo-lists-equal-p
                spent (bl.val::load-undo-data-from-disk hash))))))

(test undo-migration-verifies-against-the-legacy-copy
  "The read-back check must compare the rev record against the LEGACY file, so
it has to read the legacy file specifically. Reading through the dual-read path
returns the rev record once nUndoPos is set — the check would then compare that
record against itself, pass for that reason alone, and delete a legacy file
nothing had verified."
  (%with-undo-store (store chain-state dir)
    (let* ((block (%bu-test-block '(2)))
           (spent (%bu-spent-for block))
           (hash (%undo-store-block store chain-state block 9)))
      ;; Both forms present, with DIFFERENT contents: legacy is the truth.
      (bl.val::save-undo-data-to-disk hash spent)
      (let ((wrong (mapcar (lambda (triple)
                             (destructuring-bind (txid index entry) triple
                               (declare (ignore entry))
                               (list txid index (%bu-entry :value 1 :height 1))))
                           spent)))
        (bl.val::save-undo-data-to-disk hash wrong :block block))
      ;; The rev record now disagrees with the legacy file. Migration must
      ;; notice and keep the legacy copy.
      (is-false (eq :migrated (bl.val:migrate-undo-to-flat hash))
                "migration accepted a rev record that disagrees with the legacy file")
      (is-true (probe-file (bl.val::undo-file-path hash))
               "migration deleted an unverified legacy undo file")
      ;; And with nUndoPos cleared by the failure, the legacy copy is served.
      (is-true (bl.val::%undo-lists-equal-p
                spent (bl.val::load-undo-data-from-disk hash))))))

(test undo-bytes-count-toward-the-storage-total
  "Core's CalculateCurrentUsage sums nSize + nUndoSize (blockstorage.cpp:793-802)
and prunes on that figure. Ours must too: prune-flat-block-file frees the
blk/rev PAIR and decrements by both, so a write path that never added the rev
bytes walks the running total down at every prune until it decides it is
already under target and stops pruning — silently, while the disk fills."
  (%with-undo-store (store chain-state dir)
    (let* ((block (%bu-test-block '(3)))
           (spent (%bu-spent-for block))
           (hash (%undo-store-block store chain-state block 2))
           (before (bl.store:block-store-total-bytes store)))
      (bl.val::save-undo-data-to-disk hash spent :block block)
      (is (> (bl.store:block-store-total-bytes store) before)
          "the undo record did not count toward the storage total")
      ;; A restart re-derives the same figure rather than a different one.
      (let ((reopened (bl.store:init-block-store dir)))
        (is (= (bl.store:block-store-total-bytes store)
               (bl.store:block-store-total-bytes reopened))
            "the live total and the re-derived total disagree")))))

(test tx-spent-coins-in-block-indexes-past-the-coinbase
  "The undo list has one entry per NON-coinbase transaction, so a transaction's
coins are at (position - 1) in it. Indexing by the transaction's own position
would hand every transaction the PREVIOUS one's coins — and the coinbase, which
has no entry at all, the first real transaction's.

Core returns early for a coinbase for exactly this reason
(rawtransaction.cpp:354) and subtracts one for the rest (:369)."
  (let* ((block (%bu-test-block '(1 2)))          ; coinbase + 2 spenders
         (txs (bl.ser:bitcoin-block-transactions block))
         (spent (%bu-spent-for block)))
    ;; Prime the undo data the way a connected block would have.
    (let ((bl.val::*block-undo-data*
            (make-hash-table :test 'equalp)))
      (setf (gethash (bl.ser:block-header-hash
                      (bl.ser:bitcoin-block-header block))
                     bl.val::*block-undo-data*)
            spent)
      ;; The coinbase gets nothing.
      (is-false (bl.rpc::%tx-spent-coins-in-block block (first txs))
                "the coinbase was given coins it never spent")
      ;; Transaction 1 spends one input, transaction 2 spends two.
      (is (= 1 (length (bl.rpc::%tx-spent-coins-in-block
                        block (second txs)))))
      (is (= 2 (length (bl.rpc::%tx-spent-coins-in-block
                        block (third txs)))))
      ;; And they are the RIGHT coins. SPENT is in apply order across the whole
      ;; block: entry 1 is transaction 1's only input, entries 2 and 3 are
      ;; transaction 2's two. Off-by-one here is the bug the indexing exists to
      ;; avoid, so compare the coins themselves rather than just the count.
      (let ((all (mapcar #'third spent)))
        (is (equalp (list (second all) (third all))
                    (bl.rpc::%tx-spent-coins-in-block block (third txs)))
            "transaction 2 was given the wrong coins")
        (is (equalp (list (first all))
                    (bl.rpc::%tx-spent-coins-in-block block (second txs)))
            "transaction 1 was given the wrong coins")))))
