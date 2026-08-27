(in-package #:bitcoin-lisp.serialization)

;;; Bitcoin protocol data structures
;;;
;;; This module defines the core data types used in the Bitcoin protocol:
;;; - Outpoint: Reference to a previous transaction output
;;; - TxIn: Transaction input
;;; - TxOut: Transaction output
;;; - Transaction: Complete transaction
;;; - BlockHeader: Block header (80 bytes)
;;; - Block: Complete block with transactions

;;;; Outpoint - reference to a previous transaction output

(defstruct outpoint
  "Reference to a transaction output.
HASH is the 32-byte transaction hash.
INDEX is the output index within that transaction."
  (hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
        :type (simple-array (unsigned-byte 8) (32)))
  (index 0 :type (unsigned-byte 32)))

(defun read-outpoint (stream)
  "Read an outpoint from STREAM."
  (make-outpoint :hash (read-hash256 stream)
                 :index (read-uint32-le stream)))

(defun write-outpoint (stream outpoint)
  "Write an outpoint to STREAM."
  (write-hash256 stream (outpoint-hash outpoint))
  (write-uint32-le stream (outpoint-index outpoint)))

(declaim (inline bb-write-outpoint))
(defun bb-write-outpoint (bb outpoint)
  "Write an outpoint into byte-buf BB (32-byte hash + 4-byte LE index)."
  (bb-write-bytes bb (outpoint-hash outpoint))
  (bb-write-u32-le bb (outpoint-index outpoint)))

(declaim (inline br-read-outpoint))
(defun br-read-outpoint (br)
  "Read an outpoint from a byte-reader (32-byte hash + 4-byte LE index)."
  (make-outpoint :hash (br-read-bytes br 32)
                 :index (br-read-u32-le br)))

(defun null-outpoint-p (outpoint)
  "Check if OUTPOINT is null (references no previous output)."
  (and (every #'zerop (outpoint-hash outpoint))
       (= (outpoint-index outpoint) #xFFFFFFFF)))

;;;; TxIn - Transaction input

(defstruct tx-in
  "A transaction input.
PREVIOUS-OUTPUT: Outpoint referencing the output being spent.
SCRIPT-SIG: Unlocking script (signature).
SEQUENCE: Sequence number for replacement/locktime."
  (previous-output (make-outpoint) :type outpoint)
  (script-sig #() :type (simple-array (unsigned-byte 8) (*)))
  (sequence #xFFFFFFFF :type (unsigned-byte 32)))

(defun read-tx-in (stream)
  "Read a transaction input from STREAM."
  (make-tx-in :previous-output (read-outpoint stream)
              :script-sig (read-var-bytes stream)
              :sequence (read-uint32-le stream)))

(defun write-tx-in (stream tx-in)
  "Write a transaction input to STREAM."
  (write-outpoint stream (tx-in-previous-output tx-in))
  (write-var-bytes stream (tx-in-script-sig tx-in))
  (write-uint32-le stream (tx-in-sequence tx-in)))

(declaim (inline bb-write-tx-in))
(defun bb-write-tx-in (bb tx-in)
  "Write a transaction input into byte-buf BB."
  (bb-write-outpoint bb (tx-in-previous-output tx-in))
  (let ((script (tx-in-script-sig tx-in)))
    (bb-write-varint bb (length script))
    (bb-write-bytes bb script))
  (bb-write-u32-le bb (tx-in-sequence tx-in)))

(declaim (inline br-read-tx-in))
(defun br-read-tx-in (br)
  "Read a transaction input from a byte-reader."
  (make-tx-in :previous-output (br-read-outpoint br)
              :script-sig (br-read-var-bytes br)
              :sequence (br-read-u32-le br)))

(defun coinbase-input-p (tx-in)
  "Check if TX-IN is a coinbase input."
  (null-outpoint-p (tx-in-previous-output tx-in)))

;;;; TxOut - Transaction output

(defun script-push-data (data)
  "The minimal CScript push of DATA (Core CScript::operator<<(const
std::vector<unsigned char>&), script.h): a direct push for 0-75 bytes,
OP_PUSHDATA1 to 255, OP_PUSHDATA2 to 65535, OP_PUSHDATA4 above."
  (let ((n (length data)))
    (concatenate '(simple-array (unsigned-byte 8) (*))
                 (cond ((<= n 75) (vector n))
                       ((<= n #xff) (vector #x4c n))
                       ((<= n #xffff) (vector #x4d (logand n #xff) (ash n -8)))
                       (t (vector #x4e (logand n #xff) (logand (ash n -8) #xff)
                                  (logand (ash n -16) #xff) (ash n -24))))
                 data)))

(defstruct tx-out
  "A transaction output.
VALUE: Amount in satoshis.
SCRIPT-PUBKEY: Locking script."
  (value 0 :type (signed-byte 64))
  (script-pubkey #() :type (simple-array (unsigned-byte 8) (*))))

(defun read-tx-out (stream)
  "Read a transaction output from STREAM."
  (make-tx-out :value (read-int64-le stream)
               :script-pubkey (read-var-bytes stream)))

(defun write-tx-out (stream tx-out)
  "Write a transaction output to STREAM."
  (write-int64-le stream (tx-out-value tx-out))
  (write-var-bytes stream (tx-out-script-pubkey tx-out)))

(declaim (inline bb-write-tx-out))
(defun bb-write-tx-out (bb tx-out)
  "Write a transaction output into byte-buf BB."
  (bb-write-i64-le bb (tx-out-value tx-out))
  (let ((script (tx-out-script-pubkey tx-out)))
    (bb-write-varint bb (length script))
    (bb-write-bytes bb script)))

(declaim (inline br-read-tx-out))
(defun br-read-tx-out (br)
  "Read a transaction output from a byte-reader."
  (make-tx-out :value (br-read-i64-le br)
               :script-pubkey (br-read-var-bytes br)))

;;;; Transaction

(defstruct transaction
  "A Bitcoin transaction.
VERSION: Transaction version (currently 1 or 2).
INPUTS: Simple-vector of transaction inputs.
OUTPUTS: Simple-vector of transaction outputs.
LOCK-TIME: Block height or timestamp for time-locked transactions.
WITNESS: Simple-vector of witness stacks, one per input. Each stack is a
  list of byte vectors. NIL (not #()) means no witness data (legacy
  transaction) — truthiness selects the BIP 144 serialization format.
Inputs/outputs are vectors so per-input consensus paths (sighash) index
in O(1); they were lists, making large-input txs O(n^2) (B.1-vectorize)."
  (version 1 :type (signed-byte 32))
  (inputs #() :type simple-vector)
  (outputs #() :type simple-vector)
  (lock-time 0 :type (unsigned-byte 32))
  (witness nil :type (or null simple-vector))
  ;; Cached hash (computed lazily)
  (cached-hash nil)
  ;; Cached weight (BIP 141). transaction-weight requires two full re-
  ;; serializations of the tx; profiling showed this was ~16% of CPU on
  ;; testnet4 stress blocks. Compute once, reuse forever.
  (cached-weight nil)
  ;; Cached wtxid (BIP 141). transaction-wtxid re-serializes the witness
  ;; tx on every call; May 2026 stress-region profile pinned it at ~2% of
  ;; CPU (called per-tx from compute-witness-merkle-root and wtxid relay).
  ;; Same shape as cached-weight: compute once, reuse forever.
  (cached-wtxid nil))

(defun transaction-has-witness-p (tx)
  "Check if TX has witness data."
  (and (transaction-witness tx)
       (some (lambda (stack) (and stack (not (null stack))))
             (transaction-witness tx))))

(defmacro dovector ((var vector &optional result) &body body)
  "DOLIST-shaped iteration over a vector: bind VAR to each element of
VECTOR, evaluate BODY, return RESULT. Exists so the many former dolist
consumers of transaction-inputs/-outputs/-witness (now simple-vectors)
keep their shape."
  `(progn
     (map nil (lambda (,var) ,@body) ,vector)
     ,result))

(defmacro %read-n-vector (count &body body)
  "Evaluate BODY COUNT times, returning the results as a simple-vector.
Reads item-by-item into a list first so a hostile COUNT from untrusted
input fails fast on truncation instead of pre-allocating a huge vector."
  `(coerce (loop repeat ,count collect (progn ,@body)) 'simple-vector))

(defun read-witness-stack (stream)
  "Read a single witness stack (for one input) from STREAM.
Returns a list of byte vectors."
  (let ((item-count (read-compact-size stream)))
    (loop repeat item-count
          collect (read-var-bytes stream))))

(defun write-witness-stack (stream stack)
  "Write a single witness stack (list of byte vectors) to STREAM."
  (write-compact-size stream (length stack))
  (dolist (item stack)
    (write-var-bytes stream item)))

(defun br-read-witness-stack (br)
  "Read a single witness stack (one input's worth) from a byte-reader."
  (let ((item-count (br-read-compact-size br)))
    (loop repeat item-count
          collect (br-read-var-bytes br))))

(defun br-read-transaction (br)
  "Read a transaction from a byte-reader. Auto-detects BIP 144 witness
format by checking for marker byte 0x00 where the input count would be.
Hot path: called per tx during block parsing — index-based reads avoid
flexi-streams' Gray-stream input dispatch."
  (let* ((version (br-read-i32-le br))
         (marker (br-read-u8 br)))
    (if (zerop marker)
        ;; Witness format: marker=0x00, flag=0x01
        (let ((flag (br-read-u8 br)))
          (unless (= flag 1)
            (error "Invalid witness flag byte: ~D" flag))
          (let* ((input-count (br-read-compact-size br))
                 (inputs (%read-n-vector input-count (br-read-tx-in br)))
                 (output-count (br-read-compact-size br))
                 (outputs (%read-n-vector output-count (br-read-tx-out br)))
                 (witness (%read-n-vector input-count
                            (br-read-witness-stack br)))
                 (lock-time (br-read-u32-le br)))
            (make-transaction :version version
                              :inputs inputs
                              :outputs outputs
                              :lock-time lock-time
                              :witness witness)))
        ;; Legacy format: marker was the first byte of input-count.
        (let* ((input-count
                 (cond ((< marker 253) marker)
                       ((= marker 253)
                        (let ((v (br-read-u16-le br)))
                          (when (< v 253)
                            (error "non-canonical ReadCompactSize"))
                          v))
                       ((= marker 254)
                        (let ((v (br-read-u32-le br)))
                          (when (< v #x10000)
                            (error "non-canonical ReadCompactSize"))
                          v))
                       (t
                        (let ((v (br-read-u64-le br)))
                          (when (< v #x100000000)
                            (error "non-canonical ReadCompactSize"))
                          v))))
               (inputs (%read-n-vector input-count (br-read-tx-in br)))
               (output-count (br-read-compact-size br))
               (outputs (%read-n-vector output-count (br-read-tx-out br)))
               (lock-time (br-read-u32-le br)))
          (make-transaction :version version
                            :inputs inputs
                            :outputs outputs
                            :lock-time lock-time)))))

(defun read-transaction (stream)
  "Read a transaction from STREAM.
Auto-detects BIP 144 witness format by checking for marker byte 0x00
where the input count would normally be."
  (let* ((version (read-int32-le stream))
         (marker (read-uint8 stream)))
    (if (zerop marker)
        ;; Possible witness format: marker=0x00, check flag
        (let ((flag (read-uint8 stream)))
          (unless (= flag 1)
            (error "Invalid witness flag byte: ~D" flag))
          ;; Witness format: inputs, outputs, witness stacks, lock-time
          (let* ((input-count (read-compact-size stream))
                 (inputs (%read-n-vector input-count (read-tx-in stream)))
                 (output-count (read-compact-size stream))
                 (outputs (%read-n-vector output-count (read-tx-out stream)))
                 (witness (%read-n-vector input-count
                            (read-witness-stack stream)))
                 (lock-time (read-uint32-le stream)))
            (make-transaction :version version
                              :inputs inputs
                              :outputs outputs
                              :lock-time lock-time
                              :witness witness)))
        ;; Legacy format: marker was actually the first byte of input-count
        ;; Re-parse input count using marker as the compact-size value
        (let* ((input-count (decode-compact-size-from-first-byte marker stream))
               (inputs (%read-n-vector input-count (read-tx-in stream)))
               (output-count (read-compact-size stream))
               (outputs (%read-n-vector output-count (read-tx-out stream)))
               (lock-time (read-uint32-le stream)))
          (make-transaction :version version
                            :inputs inputs
                            :outputs outputs
                            :lock-time lock-time)))))

(defun decode-compact-size-from-first-byte (first-byte stream)
  "Decode a CompactSize integer given that FIRST-BYTE has already been read.
Enforces non-canonical rejection and the MAX_SIZE cap, mirroring
read-compact-size and Bitcoin Core's ReadCompactSize (serialize.h:330-360)."
  (let ((value (cond
                 ((< first-byte 253) first-byte)
                 ((= first-byte 253)
                  (let ((v (read-uint16-le stream)))
                    (when (< v 253)
                      (error "non-canonical ReadCompactSize"))
                    v))
                 ((= first-byte 254)
                  (let ((v (read-uint32-le stream)))
                    (when (< v #x10000)
                      (error "non-canonical ReadCompactSize"))
                    v))
                 (t
                  (let ((v (read-uint64-le stream)))
                    (when (< v #x100000000)
                      (error "non-canonical ReadCompactSize"))
                    v)))))
    (when (> value +max-compact-size+)
      (error "ReadCompactSize: size too large (~D > ~D)"
             value +max-compact-size+))
    value))

(defun write-transaction (stream tx)
  "Write a transaction to STREAM in legacy format (no witness).
Used for txid computation."
  (write-int32-le stream (transaction-version tx))
  (write-compact-size stream (length (transaction-inputs tx)))
  (loop for input across (transaction-inputs tx)
        do (write-tx-in stream input))
  (write-compact-size stream (length (transaction-outputs tx)))
  (loop for output across (transaction-outputs tx)
        do (write-tx-out stream output))
  (write-uint32-le stream (transaction-lock-time tx)))

(defun write-witness-transaction (stream tx)
  "Write a transaction to STREAM in BIP 144 witness format."
  (write-int32-le stream (transaction-version tx))
  ;; Marker and flag
  (write-uint8 stream #x00)
  (write-uint8 stream #x01)
  ;; Inputs
  (write-compact-size stream (length (transaction-inputs tx)))
  (loop for input across (transaction-inputs tx)
        do (write-tx-in stream input))
  ;; Outputs
  (write-compact-size stream (length (transaction-outputs tx)))
  (loop for output across (transaction-outputs tx)
        do (write-tx-out stream output))
  ;; Witness stacks
  (let ((witness (transaction-witness tx)))
    (loop for i below (length (transaction-inputs tx))
          for stack = (if (and witness (< i (length witness)))
                          (svref witness i)
                          '())
          do (write-witness-stack stream stack)))
  ;; Lock time
  (write-uint32-le stream (transaction-lock-time tx)))

(defun bb-write-transaction-legacy (bb tx)
  "Write transaction TX into byte-buf BB in legacy format (no witness)."
  (bb-write-i32-le bb (transaction-version tx))
  (let ((inputs (transaction-inputs tx)))
    (bb-write-varint bb (length inputs))
    (loop for input across inputs
          do (bb-write-tx-in bb input)))
  (let ((outputs (transaction-outputs tx)))
    (bb-write-varint bb (length outputs))
    (loop for output across outputs
          do (bb-write-tx-out bb output)))
  (bb-write-u32-le bb (transaction-lock-time tx)))

(defun serialize-transaction (tx)
  "Serialize transaction TX to a byte vector in legacy format (for txid).

Hot path: called from transaction-hash on every tx, and twice from
transaction-weight (legacy + witness sizes). Direct byte-buf writes
replace flexi-streams' per-byte CLOS dispatch — May 2 profile pinned
flexi-streams at ~50% of CPU during validation."
  (let ((bb (make-byte-buf)))
    (bb-write-transaction-legacy bb tx)
    (bb-finish bb)))

(defun serialize-witness-transaction (tx)
  "Serialize transaction TX to a byte vector in BIP 144 witness format."
  (let ((bb (make-byte-buf))
        (inputs (transaction-inputs tx))
        (outputs (transaction-outputs tx))
        (witness (transaction-witness tx)))
    (bb-write-i32-le bb (transaction-version tx))
    ;; Marker + flag
    (bb-write-u8 bb #x00)
    (bb-write-u8 bb #x01)
    (bb-write-varint bb (length inputs))
    (loop for input across inputs
          do (bb-write-tx-in bb input))
    (bb-write-varint bb (length outputs))
    (loop for output across outputs
          do (bb-write-tx-out bb output))
    ;; Witness stacks (one per input)
    (loop for i below (length inputs)
          for stack = (if (and witness (< i (length witness)))
                          (svref witness i)
                          '())
          do (bb-write-varint bb (length stack))
             (dolist (item stack)
               (bb-write-varint bb (length item))
               (bb-write-bytes bb item)))
    (bb-write-u32-le bb (transaction-lock-time tx))
    (bb-finish bb)))

(defun transaction-wire-bytes (tx)
  "TX in its wire encoding: BIP 144 witness form only when the tx carries
witness data, legacy otherwise. This is Core's TX_WITH_WITNESS serialization
(SerializeTransaction, primitives/transaction.h:241 — the marker/flag pair is
emitted only when HasWitness()), the encoding EncodeHexTx uses for every RPC
hex field. Serializing a witnessless tx in extended form would make Core
reject it with \"Superfluous witness record\"."
  (if (transaction-has-witness-p tx)
      (serialize-witness-transaction tx)
      (serialize-transaction tx)))

(defun transaction-hash (tx)
  "Compute the transaction hash (txid).
This is the double-SHA256 of the legacy serialized transaction (no witness)."
  (or (transaction-cached-hash tx)
      (let ((hash (bl.crypto:hash256 (serialize-transaction tx))))
        (setf (transaction-cached-hash tx) hash)
        hash)))

(defun transaction-wtxid (tx)
  "Compute the witness transaction ID (wtxid).
For transactions with witness data, this is the double-SHA256 of the
witness-serialized transaction. For coinbase transactions, returns 32 zero bytes.
For legacy transactions without witness, wtxid equals txid. Cached on the tx."
  (or (transaction-cached-wtxid tx)
      (setf (transaction-cached-wtxid tx)
            (cond
              ;; Coinbase: wtxid is all zeros
              ((and (plusp (length (transaction-inputs tx)))
                    (coinbase-input-p (aref (transaction-inputs tx) 0)))
               (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
              ;; Has witness: hash the witness serialization
              ((transaction-has-witness-p tx)
               (bl.crypto:hash256 (serialize-witness-transaction tx)))
              ;; No witness: wtxid = txid
              (t (transaction-hash tx))))))

(defun transaction-weight (tx)
  "Calculate the weight of a transaction in weight units (BIP 141).
Weight = (base_size * 3) + total_size, where base_size excludes witness data.
For legacy transactions: weight = total_size * 4. Cached on the tx struct."
  (or (transaction-cached-weight tx)
      (setf (transaction-cached-weight tx)
            (if (transaction-has-witness-p tx)
                (let* ((base-size (length (serialize-transaction tx)))
                       (total-size (length (serialize-witness-transaction tx))))
                  (+ (* 3 base-size) total-size))
                (* 4 (length (serialize-transaction tx)))))))

(defun transaction-vsize (tx)
  "Calculate the virtual size (vsize) of a transaction in vbytes.
vsize = ceiling(weight / 4). This is the metric used for fee rate calculation."
  (ceiling (transaction-weight tx) 4))

;;;; Block Header

(defstruct block-header
  "A Bitcoin block header (80 bytes).
VERSION: Block version.
PREV-BLOCK: Hash of the previous block.
MERKLE-ROOT: Merkle root of transactions.
TIMESTAMP: Block timestamp (Unix time).
BITS: Encoded difficulty target.
NONCE: Proof-of-work nonce."
  (version 1 :type (signed-byte 32))
  (prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
              :type (simple-array (unsigned-byte 8) (32)))
  (merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
               :type (simple-array (unsigned-byte 8) (32)))
  (timestamp 0 :type (unsigned-byte 32))
  (bits 0 :type (unsigned-byte 32))
  (nonce 0 :type (unsigned-byte 32))
  ;; Cached hash
  (cached-hash nil))

(defun read-block-header (stream)
  "Read a block header from STREAM."
  (make-block-header :version (read-int32-le stream)
                     :prev-block (read-hash256 stream)
                     :merkle-root (read-hash256 stream)
                     :timestamp (read-uint32-le stream)
                     :bits (read-uint32-le stream)
                     :nonce (read-uint32-le stream)))

(declaim (inline br-read-block-header))
(defun br-read-block-header (br)
  "Read a block header from a byte-reader (80 bytes)."
  (make-block-header :version (br-read-i32-le br)
                     :prev-block (br-read-bytes br 32)
                     :merkle-root (br-read-bytes br 32)
                     :timestamp (br-read-u32-le br)
                     :bits (br-read-u32-le br)
                     :nonce (br-read-u32-le br)))

(defun write-block-header (stream header)
  "Write a block header to STREAM."
  (write-int32-le stream (block-header-version header))
  (write-hash256 stream (block-header-prev-block header))
  (write-hash256 stream (block-header-merkle-root header))
  (write-uint32-le stream (block-header-timestamp header))
  (write-uint32-le stream (block-header-bits header))
  (write-uint32-le stream (block-header-nonce header)))

(declaim (inline bb-write-block-header))
(defun bb-write-block-header (bb header)
  "Write an 80-byte block header into byte-buf BB."
  (bb-write-i32-le bb (block-header-version header))
  (bb-write-bytes bb (block-header-prev-block header))
  (bb-write-bytes bb (block-header-merkle-root header))
  (bb-write-u32-le bb (block-header-timestamp header))
  (bb-write-u32-le bb (block-header-bits header))
  (bb-write-u32-le bb (block-header-nonce header)))

(defun serialize-block-header (header)
  "Serialize block header to a byte vector (80 bytes).
Hot path: called on every block-header-hash. Direct buffer writes to
avoid flexi-streams CLOS dispatch — the 80-byte cost is small but it
fires once per block on the IBD validation path."
  (let ((bb (make-byte-buf)))
    (bb-write-block-header bb header)
    (bb-finish bb)))

(defun block-header-hash (header)
  "Compute the block hash from the header.
This is the double-SHA256 of the 80-byte header."
  (or (block-header-cached-hash header)
      (let ((hash (bl.crypto:hash256 (serialize-block-header header))))
        (setf (block-header-cached-hash header) hash)
        hash)))

;;;; Block

(defstruct bitcoin-block
  "A complete Bitcoin block.
HEADER: The 80-byte block header.
TRANSACTIONS: List of transactions in the block."
  (header (make-block-header) :type block-header)
  (transactions '() :type list))

(defun read-bitcoin-block (stream)
  "Read a complete block from STREAM."
  (let* ((header (read-block-header stream))
         (tx-count (read-compact-size stream))
         (transactions (loop repeat tx-count collect (read-transaction stream))))
    (make-bitcoin-block :header header
                        :transactions transactions)))

(defun br-read-bitcoin-block (br)
  "Read a complete block from a byte-reader. Hot path (per inbound block)."
  (let* ((header (br-read-block-header br))
         (tx-count (br-read-compact-size br))
         (transactions (loop repeat tx-count collect (br-read-transaction br))))
    (make-bitcoin-block :header header
                        :transactions transactions)))

(defun write-bitcoin-block (stream block)
  "Write a complete block to STREAM."
  (write-block-header stream (bitcoin-block-header block))
  (write-compact-size stream (length (bitcoin-block-transactions block)))
  (dolist (tx (bitcoin-block-transactions block))
    (write-transaction stream tx)))

(defun serialize-witness-block (block)
  "Serialize a complete BLOCK to bytes in BIP 144 form: each transaction is
witness-serialized when it carries witness data (legacy otherwise). This is the
wire/`submitblock` form and the inverse of read-bitcoin-block (read-transaction
auto-detects the per-tx witness marker)."
  (flexi-streams:with-output-to-sequence (s)
    (write-block-header s (bitcoin-block-header block))
    (write-compact-size s (length (bitcoin-block-transactions block)))
    (dolist (tx (bitcoin-block-transactions block))
      (if (transaction-has-witness-p tx)
          (write-witness-transaction s tx)
          (write-transaction s tx)))))

;;;; Generic serialization interface

(defgeneric serialize (object)
  (:documentation "Serialize OBJECT to a byte vector."))

(defgeneric deserialize (type stream)
  (:documentation "Deserialize an object of TYPE from STREAM."))

(defmethod serialize ((tx transaction))
  (serialize-transaction tx))

(defmethod serialize ((header block-header))
  (serialize-block-header header))

(defmethod serialize ((block bitcoin-block))
  ;; LEGACY (witness-stripped) block form — only correct for answering a
  ;; MSG_BLOCK getdata (make-block-message :witness nil). Anything that must
  ;; reproduce the block's real bytes (disk storage, RPC hex) wants
  ;; serialize-witness-block instead. Build into a byte-buf, writing each tx
  ;; in-place to avoid the per-tx intermediate byte-vector allocation that
  ;; bb-write-bytes (serialize-transaction tx) would do.
  (let ((bb (make-byte-buf))
        (txs (bitcoin-block-transactions block)))
    (bb-write-block-header bb (bitcoin-block-header block))
    (bb-write-varint bb (length txs))
    (dolist (tx txs)
      (bb-write-transaction-legacy bb tx))
    (bb-finish bb)))
