(in-package #:bitcoin-lisp.storage)

;;;; Rebuilding the block index from the block files (Core -reindex)
;;;;
;;;; The capability the flat block files were worth having for. Until now a
;;;; corrupt or lost headerindex.dat meant re-downloading the chain: the node
;;;; refuses to start rather than run with an empty index that contradicts its
;;;; chainstate (#358), and there was nothing to rebuild it from — one file per
;;;; block, named by a hash, with no way to know what was in them without
;;;; opening all of them.
;;;;
;;;; A blk file is self-describing, so the index is recoverable: walk the
;;;; records, read each 80-byte header, and rebuild the tree. Together with
;;;; -reindex-chainstate (which rebuilds the UTXO set from the index) that is a
;;;; full -reindex, and it turns "lost index" from a resync into minutes of
;;;; local work.
;;;;
;;;; Core's ImportBlocks does the same thing and hits the same problem: blocks
;;;; are stored in the order they ARRIVED, so a block's parent may be later in
;;;; the file, or in a later file. Core parks such blocks in a multimap keyed
;;;; by their parent's hash and drains it recursively after each accepted
;;;; block; so does this.

(defun %reindex-header-of-record (store pos)
  "Read just the 80-byte header at POS, de-obfuscated. Returns (values header
hash) or NIL — a block's identity needs nothing more, and deserializing whole
blocks to rebuild an index would read the entire chain into memory."
  (let* ((seq (%blk-seq store))
         (path (flat-file-name seq pos)))
    (when (probe-file path)
      (with-open-file (in path :direction :input :element-type '(unsigned-byte 8))
        (when (<= (+ (flat-file-pos-pos pos) 80) (file-length in))
          (file-position in (flat-file-pos-pos pos))
          (let ((bytes (make-array 80 :element-type '(unsigned-byte 8))))
            (read-sequence bytes in)
            (obfuscate! bytes (block-store-xor-key store)
                        :key-offset (flat-file-pos-pos pos))
            (handler-case
                (let ((header (flexi-streams:with-input-from-sequence (hs bytes)
                                (bitcoin-lisp.serialization::read-block-header hs))))
                  (values header (bitcoin-lisp.crypto:hash256 bytes)))
              (error () nil))))))))

(defun reindex-block-index (store chain-state)
  "Rebuild CHAIN-STATE's block index from STORE's block files.

Returns (values entries-added orphans-left). Orphans are records whose parent
never turned up: on a pruned node that is expected — the chain below the prune
horizon is gone — and they are reported rather than treated as corruption.

The genesis entry is assumed to be present already; every other block is linked
to its parent, which is what supplies its height and chain work. A block whose
parent has not been seen yet is parked by prev-hash and drained as soon as the
parent lands, so file order does not matter."
  (let ((pending (make-hash-table :test 'equalp))   ; prev-hash -> list of (hash header)
        (added 0))
    ;; Collect every record's header first. The store's index already knows
    ;; where each block is — that map is rebuilt by the startup scan — so this
    ;; walks it rather than re-reading the files record by record.
    (let ((records '()))
      (maphash (lambda (hash located)
                 (when (flat-file-pos-p located)
                   (push (cons hash located) records)))
               (block-store-index store))
      (dolist (record records)
        (multiple-value-bind (header hash) (%reindex-header-of-record store (cdr record))
          (when (and header hash)
            ;; The record's position travels with the header: the entry built
            ;; below is the only thing that will ever carry nFile/nDataPos, and
            ;; without them a reindexed datadir writes undo data in the legacy
            ;; format forever. Core drives the same field from its reindex path
            ;; (UpdateBlockInfo, blockstorage.cpp:923-940, called from
            ;; AcceptBlock's reindex branch, validation.cpp:4402-4403).
            (push (list hash header (cdr record))
                  (gethash (bitcoin-lisp.serialization:block-header-prev-block header)
                           pending))))))
    ;; Drain from every parent already in the index, adding children and then
    ;; their children. A queue rather than recursion: a chain is hundreds of
    ;; thousands deep and recursion would exhaust the stack.
    (let ((queue '()))
      (maphash (lambda (hash entry)
                 (declare (ignore entry))
                 (when (gethash hash pending) (push hash queue)))
               (chain-state-block-index chain-state))
      (loop while queue
            do (let* ((parent-hash (pop queue))
                      (children (gethash parent-hash pending))
                      (parent (get-block-index-entry chain-state parent-hash)))
                 (remhash parent-hash pending)
                 (when parent
                   (dolist (child children)
                     (destructuring-bind (hash header located) child
                       (unless (get-block-index-entry chain-state hash)
                         (let ((entry (make-block-index-entry
                                       :hash hash
                                       :height (1+ (block-index-entry-height parent))
                                       :header header
                                       :prev-entry parent
                                       :chain-work (calculate-chain-work
                                                    (bitcoin-lisp.serialization:block-header-bits
                                                     header)
                                                    (block-index-entry-chain-work parent))
                                       ;; The body is on disk but nothing has
                                       ;; been re-validated, so the entry claims
                                       ;; only that its header is good. The
                                       ;; chainstate rebuild is what promotes
                                       ;; blocks to :valid by re-applying them.
                                       :status :header-valid)))
                           (%record-block-position entry located)
                           (add-block-index-entry chain-state entry)
                           (incf added)))
                       (when (gethash hash pending) (push hash queue)))))))
      (values added
              (let ((left 0))
                (maphash (lambda (k v) (declare (ignore k)) (incf left (length v))) pending)
                left)))))

;;;; Reading blocks out of an EXTERNAL file (Core -loadblock)
;;;;
;;;; Same framing as a blk file — magic, 4-byte size, block — but nothing else
;;;; can be assumed. The file was produced by another tool (contrib/linearize
;;;; writes bootstrap.dat), it carries no xor.dat, and it may hold garbage
;;;; between records or be truncated mid-block. Core therefore HUNTS the magic
;;;; a byte at a time and treats any failure as "resume scanning one byte
;;;; further", which is what makes the reader tolerant of a partial download
;;;; (LoadExternalBlockFile, validation.cpp:4988-5060).

(defconstant +max-block-serialized-size+ 4000000
  "Core MAX_BLOCK_SERIALIZED_SIZE. A size field outside [80, this] is not a
record, so the scan resumes hunting rather than trying to read it.")

(defun map-external-block-file (path fn)
  "Call FN with each serialized block found in the file at PATH, in file order.
Returns the number of records handed over.

FN receives the raw bytes; deserializing is the caller's business, and a caller
that only wants to count or index need not pay for it.

Records are located by hunting the network magic, so leading junk, trailing
junk, and a record that fails to read all leave the rest of the file readable —
the property that makes this usable on a bootstrap.dat someone stopped
downloading halfway."
  (let ((magic (block-network-magic))
        (found 0))
    (with-open-file (in path :direction :input :element-type '(unsigned-byte 8)
                             :if-does-not-exist nil)
      (unless in (return-from map-external-block-file 0))
      (let ((length (file-length in))
            (window (make-array 8 :element-type '(unsigned-byte 8)))
            (pos 0))
        (loop
          (when (> (+ pos 8) length) (return))
          (file-position in pos)
          (read-sequence window in)
          (cond
            ((not (loop for i below 4 always (= (aref window i) (aref magic i))))
             ;; Not a record here. One byte further, as Core does — a record
             ;; can start at any offset once the file has junk in it.
             (incf pos))
            (t
             (let ((size (logior (aref window 4)
                                 (ash (aref window 5) 8)
                                 (ash (aref window 6) 16)
                                 (ash (aref window 7) 24))))
               (cond
                 ((or (< size 80) (> size +max-block-serialized-size+)
                      (> (+ pos 8 size) length))
                  ;; A plausible magic with an implausible length is a
                  ;; coincidence in the data, not a record.
                  (incf pos))
                 (t
                  (let ((bytes (make-array size :element-type '(unsigned-byte 8))))
                    (read-sequence bytes in)
                    (funcall fn bytes)
                    (incf found)
                    (setf pos (+ pos 8 size)))))))))))
    found))
