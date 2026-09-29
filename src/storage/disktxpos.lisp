(in-package #:bitcoin-lisp.storage)

;;;; CDiskTxPos (Core index/disktxpos.h): where a transaction lives on disk --
;;;; the FlatFilePos of its block's payload in blk?????.dat plus nTxOffset,
;;;; the number of bytes from the END of the 80-byte header to the
;;;; transaction (the CompactSize transaction count included). The txindex
;;;; stores one per transaction (index/txindex.cpp:78-89) and the spender
;;;; index one per spending input inside its KEY (index/txospenderindex.cpp:
;;;; 95-107); both read the transaction back the same way: open the block
;;;; file at nPos, read the header, skip nTxOffset bytes, read one
;;;; transaction (txindex.cpp:103-123, txospenderindex.cpp:115-131).
;;;;
;;;; Serialized as FlatFilePos -- VARINT(nFile, NONNEGATIVE_SIGNED),
;;;; VARINT(nPos) (flatfile.h:22) -- then VARINT(nTxOffset): Core's MSB
;;;; base-128 VARINT, not a CompactSize.
;;;;
;;;; A block this node still keeps in a LEGACY per-block file (a node whose
;;;; storage predates the flat block files and has not finished
;;;; migrate-blocks-to-flat-files) has no FlatFilePos, so no CDiskTxPos can
;;;; name its transactions. The indexes give such a transaction a record of
;;;; their own under a key prefix Core never reads, locating it by (block
;;;; hash, position in the block) -- see txindex.lisp and
;;;; txospenderindex.lisp. A Core node started on such a datadir could not
;;;; read those blocks anyway.

(defstruct (disk-tx-pos (:constructor make-disk-tx-pos (file pos tx-offset)))
  "Core CDiskTxPos: the block payload's FILE and POS, and TX-OFFSET past its
header."
  (file 0 :type (integer 0 #x7fffffff))
  (pos 0 :type (unsigned-byte 32))
  (tx-offset 0 :type (unsigned-byte 32)))

(defun bb-write-disk-tx-pos (bb dtp)
  "Serialize DTP into BB as Core does: three VARINTs."
  (bl.ser:bb-write-core-varint bb (disk-tx-pos-file dtp))
  (bl.ser:bb-write-core-varint bb (disk-tx-pos-pos dtp))
  (bl.ser:bb-write-core-varint bb (disk-tx-pos-tx-offset dtp)))

(defun br-read-disk-tx-pos (br)
  "Read a serialized CDiskTxPos from BR."
  (let* ((file (bl.ser:br-read-core-varint br))
         (pos (bl.ser:br-read-core-varint br))
         (offset (bl.ser:br-read-core-varint br)))
    (unless (and (<= file #x7fffffff) (<= pos #xffffffff) (<= offset #xffffffff))
      (serialization-error "CDiskTxPos out of range"))
    (make-disk-tx-pos file pos offset)))

(defun encode-disk-tx-pos (dtp)
  (let ((bb (bl.ser:make-byte-buf)))
    (bb-write-disk-tx-pos bb dtp)
    (bl.ser:bb-finish bb)))

(defun decode-disk-tx-pos (bytes)
  "The CDiskTxPos BYTES holds, which must be the whole of BYTES, or NIL."
  (ignore-errors
   (let ((br (bl.ser:make-byte-reader-from bytes)))
     (let ((dtp (br-read-disk-tx-pos br)))
       (and (bl.ser:br-eof-p br) dtp)))))

(defun block-flat-position (store hash)
  "Where STORE keeps HASH's block payload, as the FLAT-FILE-POS Core records
in nFile/nDataPos, or NIL when the block is not in a flat file (absent, or a
legacy per-block file). Read from the store's own hash -> position map, the
one place that is always current (see BLOCK-FLAT-FILE-NUMBER)."
  (let ((located (gethash hash (block-store-index store))))
    (and (flat-file-pos-p located) located)))

(defun block-disk-tx-positions (block position)
  "The CDiskTxPos of each of BLOCK's transactions, in block order, for a block
whose payload starts at POSITION (a FLAT-FILE-POS): the first sits right after
the CompactSize count, each next one after the previous transaction's
TX_WITH_WITNESS bytes (txindex.cpp:81-87)."
  (let* ((txs (bl.ser:bitcoin-block-transactions block))
         (offset (bl.ser:compact-size-length (length txs)))
         (file (flat-file-pos-file position))
         (pos (flat-file-pos-pos position)))
    (loop for tx in txs
          collect (make-disk-tx-pos file pos offset)
          do (incf offset (length (bl.ser:transaction-wire-bytes tx))))))

(defun read-tx-at-disk-pos (store dtp)
  "Core TxIndex::FindTx's read (index/txindex.cpp:103-123): open the block file
DTP names, read the 80-byte header at nPos, skip nTxOffset bytes and read one
transaction. Returns (values tx block-hash), or NIL when the file, the record
or the transaction cannot be read. The caller checks the txid, as Core's does."
  (ignore-errors
   (let* ((seq (%blk-seq store))
          (payload-pos (disk-tx-pos-pos dtp))
          (path (flat-file-name seq (make-flat-file-pos (disk-tx-pos-file dtp)
                                                        payload-pos)))
          (record-start (- payload-pos +storage-header-bytes+))
          (key (block-store-xor-key store)))
     (when (and (>= record-start 0) (probe-file path))
       (with-open-file (in path :direction :input :element-type '(unsigned-byte 8))
         (file-position in record-start)
         (let ((frame (make-array +storage-header-bytes+ :element-type '(unsigned-byte 8))))
           (read-sequence frame in)
           (obfuscate! frame key :key-offset record-start)
           (multiple-value-bind (magic length) (parse-flat-record-header frame)
             (let ((tx-start (+ payload-pos 80 (disk-tx-pos-tx-offset dtp)))
                   (end (+ payload-pos length)))
               (when (and (equalp magic (block-network-magic))
                          (<= end (file-length in))
                          (< tx-start end))
                 (let ((header (make-array 80 :element-type '(unsigned-byte 8)))
                       (body (make-array (- end tx-start) :element-type '(unsigned-byte 8))))
                   (read-sequence header in)
                   (obfuscate! header key :key-offset payload-pos)
                   (file-position in tx-start)
                   (read-sequence body in)
                   (obfuscate! body key :key-offset tx-start)
                   (values (bl.ser:br-read-transaction (bl.ser:make-byte-reader-from body))
                           (bl.crypto:hash256 header))))))))))))
