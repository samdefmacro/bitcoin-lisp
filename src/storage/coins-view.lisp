(in-package #:bitcoin-lisp.storage)

;;; Coins-view-db: LevelDB-backed UTXO view.
;;;
;;; Mirrors Bitcoin Core's CCoinsViewDB (refs/bitcoin/src/txdb.cpp:53).
;;; This is the persistent layer: every operation hits LevelDB. A future
;;; PR will add an in-memory caching layer on top (Core's
;;; CCoinsViewCache) so reads/writes during a block's validation pass
;;; don't all round-trip to disk.
;;;
;;; Key encoding follows Core's CoinEntry (txdb.cpp:43-49): a single
;;; namespacing byte ('C' = 0x43) followed by the outpoint. Core uses
;;; VARINT for the vout; we use a fixed 4-byte LE vout for simplicity
;;; and to match our in-memory key layout. A future PR can switch to
;;; VARINT for closer Core compatibility if/when that matters.
;;;
;;; Value encoding reuses our existing utxo-entry layout (i64 value,
;;; u32 height, u8 coinbase, u32 script-len + script bytes). Core uses
;;; TxOutCompression for value/script compression; we leave that for
;;; a future optimization PR — it's domain-specific compression that
;;; doesn't affect correctness, just disk footprint.

(defconstant +db-prefix-coin+ #x43          ; 'C' — same as Core's DB_COIN
  "1-byte namespacing prefix for coin entries in the LevelDB. Distinct
prefixes will be added later for DB_BEST_BLOCK ('B') and DB_HEAD_BLOCKS
('H') when those move into the same LevelDB.")

(defconstant +coin-key-bytes+ 37
  "LevelDB key size: 1 prefix + 32 txid + 4 vout.")

(defconstant +coin-key-vout-offset+ 33
  "Byte offset of the 4-byte LE vout within a coin key.")

(defconstant +coin-value-fixed-bytes+ 17
  "Fixed-size part of an encoded coin value: 8 value + 4 height + 1
coinbase + 4 script-len. Variable part is the script bytes that follow.")

(declaim (inline encode-coin-key))
(defun encode-coin-key (utxo-key)
  "Encode UTXO-KEY as the 37-byte LevelDB key (prefix + txid + LE vout)."
  (declare (type utxo-key utxo-key))
  (let ((bytes (make-array +coin-key-bytes+ :element-type '(unsigned-byte 8))))
    (setf (aref bytes 0) +db-prefix-coin+)
    (write-u64-le-into bytes 1 (uk-a utxo-key))
    (write-u64-le-into bytes 9 (uk-b utxo-key))
    (write-u64-le-into bytes 17 (uk-c utxo-key))
    (write-u64-le-into bytes 25 (uk-d utxo-key))
    (write-u32-le-into bytes +coin-key-vout-offset+ (uk-vout utxo-key))
    bytes))

(defun encode-coin-value (entry)
  "Encode a utxo-entry to bytes. Format matches what save-utxo-set
writes per entry, so a migration tool can read both layouts."
  (declare (type utxo-entry entry))
  (let* ((script (utxo-entry-script-pubkey entry))
         (script-len (length script))
         (bytes (make-array (+ +coin-value-fixed-bytes+ script-len)
                            :element-type '(unsigned-byte 8))))
    (declare (type (simple-array (unsigned-byte 8) (*)) script))
    ;; Inlined to avoid byte-buf's 1024-byte default allocation when the
    ;; typical UTXO value is ~42 bytes.
    (let ((value (utxo-entry-value entry)))
      (declare (type (signed-byte 64) value))
      (let ((uv (logand value #xFFFFFFFFFFFFFFFF)))
        (declare (type (unsigned-byte 64) uv))
        (write-u64-le-into bytes 0 uv)))
    (write-u32-le-into bytes 8 (utxo-entry-height entry))
    (setf (aref bytes 12) (if (utxo-entry-coinbase entry) 1 0))
    (write-u32-le-into bytes 13 script-len)
    (replace bytes script :start1 +coin-value-fixed-bytes+)
    bytes))

(defun decode-coin-value (bytes)
  "Inverse of encode-coin-value. Direct aref reads — no byte-reader
struct alloc on the per-block hot path."
  (declare (type (simple-array (unsigned-byte 8) (*)) bytes)
           (optimize (speed 3) (safety 1)))
  (let* ((value-u64 (logior (aref bytes 0)
                            (ash (aref bytes 1) 8)
                            (ash (aref bytes 2) 16)
                            (ash (aref bytes 3) 24)
                            (ash (aref bytes 4) 32)
                            (ash (aref bytes 5) 40)
                            (ash (aref bytes 6) 48)
                            (ash (aref bytes 7) 56)))
         ;; Convert u64 → i64 (utxo-entry-value is signed-byte 64).
         (value (if (zerop (logand value-u64 (ash 1 63)))
                    value-u64
                    (- value-u64 (ash 1 64))))
         (height (logior (aref bytes 8)
                         (ash (aref bytes 9) 8)
                         (ash (aref bytes 10) 16)
                         (ash (aref bytes 11) 24)))
         (coinbase (= (aref bytes 12) 1))
         (script-len (logior (aref bytes 13)
                             (ash (aref bytes 14) 8)
                             (ash (aref bytes 15) 16)
                             (ash (aref bytes 16) 24)))
         (script (subseq bytes
                         +coin-value-fixed-bytes+
                         (+ +coin-value-fixed-bytes+ script-len))))
    (make-utxo-entry :value value
                     :script-pubkey script
                     :height height
                     :coinbase coinbase)))

;;;; Public API
;;;;
;;;; coins-view-db is opaque from the outside; callers use the
;;;; coins-view-db-* functions. The struct itself is just a handle.

(defstruct (coins-view-db (:conc-name cvdb-))
  (db nil))

(defun open-coins-view-db (path)
  "Open or create the coins-view LevelDB at PATH. Caller must call
close-coins-view-db. Use with-coins-view-db for RAII-style scope."
  (make-coins-view-db :db (leveldb-open path)))

(defun close-coins-view-db (view)
  (when (cvdb-db view)
    (leveldb-close (cvdb-db view))
    (setf (cvdb-db view) nil)))

(defmacro with-coins-view-db ((var path) &body body)
  `(let ((,var (open-coins-view-db ,path)))
     (unwind-protect (progn ,@body)
       (close-coins-view-db ,var))))

(declaim (inline coins-view-db-get
                 coins-view-db-put
                 coins-view-db-erase
                 coins-view-db-has-p))

(defun coins-view-db-get (view utxo-key)
  "Return the utxo-entry stored under UTXO-KEY, or NIL if absent.
Mirrors CCoinsViewDB::GetCoin (txdb.cpp:72)."
  (declare (type coins-view-db view) (type utxo-key utxo-key))
  (let ((bytes (leveldb-get (cvdb-db view) (encode-coin-key utxo-key))))
    (when bytes (decode-coin-value bytes))))

(defun coins-view-db-put (view utxo-key entry)
  "Write ENTRY under UTXO-KEY. NOT atomic with other ops — use
coins-view-db-write-batch for multi-op atomicity."
  (declare (type coins-view-db view)
           (type utxo-key utxo-key)
           (type utxo-entry entry))
  (leveldb-put (cvdb-db view)
               (encode-coin-key utxo-key)
               (encode-coin-value entry)))

(defun coins-view-db-erase (view utxo-key)
  (declare (type coins-view-db view) (type utxo-key utxo-key))
  (leveldb-delete (cvdb-db view) (encode-coin-key utxo-key)))

(defun coins-view-db-has-p (view utxo-key)
  "Mirrors CCoinsViewDB::HaveCoin (txdb.cpp:81)."
  (declare (type coins-view-db view) (type utxo-key utxo-key))
  (not (null (leveldb-get (cvdb-db view) (encode-coin-key utxo-key)))))

;;;; Batch writes — the CDBBatch equivalent. The expected pattern is:
;;;; build a list of ops during a block's validation pass (adds + erases
;;;; for each input/output), then commit them atomically. Core's
;;;; CCoinsViewCache::BatchWrite drives this via CDBBatch under the hood.

(defun coins-view-db-write-batch (view ops &key sync)
  "Atomically apply OPS to VIEW. Each op is either
  (:put utxo-key utxo-entry) or (:erase utxo-key).
SYNC=T forces fsync (used during the chainstate atomic-flush)."
  (declare (type coins-view-db view))
  (with-leveldb-writebatch (batch)
    (dolist (op ops)
      (ecase (first op)
        (:put
         (leveldb-writebatch-put batch
                                 (encode-coin-key (second op))
                                 (encode-coin-value (third op))))
        (:erase
         (leveldb-writebatch-delete batch
                                    (encode-coin-key (second op))))))
    (leveldb-write (cvdb-db view) batch :sync sync)))
