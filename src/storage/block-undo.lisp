(in-package #:bitcoin-lisp.storage)

;;;; Core's CBlockUndo record (undo.h)
;;;;
;;;; The on-disk shape of a block's undo data in Bitcoin Core:
;;;;
;;;;   CBlockUndo := vector<CTxUndo>   -- one per NON-COINBASE transaction
;;;;   CTxUndo    := vector<Coin>      -- one per input, in input order
;;;;   Coin       := VARINT(height*2 + coinbase)
;;;;                 [one 0x00 byte, iff height > 0]
;;;;                 TxOutCompression(value, scriptPubKey)
;;;;
;;;; Two things are notable next to the format this node writes today
;;;; (validation/block.lisp save-undo-data-to-disk), which is a flat list of
;;;; (txid, index, entry) triples:
;;;;
;;;; - Core stores NO outpoint. The position of a Coin inside the nested
;;;;   vectors names it: transaction i+1 of the block, input j. That is why
;;;;   DisconnectBlock hard-errors unless vtxundo.size() + 1 == vtx.size() and
;;;;   each vprevout.size() == vin.size() (validation.cpp:2187, 2224) -- the
;;;;   correspondence is the addressing scheme, so a mismatch is unrecoverable
;;;;   rather than merely suspicious. BLOCK-UNDO-FROM-SPENT-UTXOS enforces the
;;;;   same two invariants when converting.
;;;;
;;;; - The dummy byte exists only for compatibility with an undo format that
;;;;   predates per-coin heights, where this field held a transaction version.
;;;;   Core writes a literal zero byte but READS a VARINT (undo.h:29,44); for
;;;;   the value zero those agree, and this port keeps both sides as Core has
;;;;   them rather than tidying the asymmetry away.
;;;;
;;;; This is the P0 codec of docs/block-file-format-plan.md. It is a pure
;;;; function pair: nothing writes this format to disk yet.

(defun bb-write-undo-coin (bb entry)
  "Serialize one spent output into BB (Core TxInUndoFormatter::Ser, undo.h:26-33)."
  (bl.ser:bb-write-core-varint
   bb (+ (* (utxo-entry-height entry) 2) (if (utxo-entry-coinbase entry) 1 0)))
  (when (plusp (utxo-entry-height entry))
    (bl.ser:bb-write-u8 bb 0))
  (bl.ser:bb-write-compressed-tx-out
   bb (utxo-entry-value entry) (utxo-entry-script-pubkey entry)))

(defun br-read-undo-coin (br)
  "Read one spent output from BR (Core TxInUndoFormatter::Unser, undo.h:35-48).
Returns a UTXO-ENTRY."
  (let* ((code (bl.ser:br-read-core-varint br))
         (height (ash code -1))
         (coinbase (logtest code 1)))
    (when (plusp height)
      (bl.ser:br-read-core-varint br))
    (multiple-value-bind (value script)
        (bl.ser:br-read-compressed-tx-out br)
      (make-utxo-entry :value value
                       :script-pubkey script
                       :height height
                       :coinbase coinbase))))

(defun serialize-block-undo (tx-undos)
  "Serialize TX-UNDOS -- a list with one element per non-coinbase transaction,
each a list of UTXO-ENTRY in input order -- as Core's CBlockUndo."
  (let ((bb (bl.ser:make-byte-buf)))
    (bl.ser:bb-write-varint bb (length tx-undos))
    (dolist (tx-undo tx-undos)
      (bl.ser:bb-write-varint bb (length tx-undo))
      (dolist (entry tx-undo)
        (bb-write-undo-coin bb entry)))
    (bl.ser:bb-finish bb)))

(defun deserialize-block-undo (bytes)
  "Parse Core's CBlockUndo from BYTES. Returns a list with one element per
non-coinbase transaction, each a list of UTXO-ENTRY in input order."
  (let* ((br (bl.ser:make-byte-reader-from bytes))
         (tx-count (bl.ser:br-read-compact-size br))
         (result '()))
    (dotimes (i tx-count)
      (let ((input-count (bl.ser:br-read-compact-size br))
            (coins '()))
        (dotimes (j input-count)
          (push (br-read-undo-coin br) coins))
        (push (nreverse coins) result)))
    (nreverse result)))

;;;; Bridging our (txid index entry) triples

(defun block-undo-from-spent-utxos (block spent-utxos)
  "Group SPENT-UTXOS -- (txid index entry) triples in apply order, as
APPLY-BLOCK-TO-UTXO-SET returns them -- into Core's per-transaction shape.

Signals an error unless the triples account for every input of every
non-coinbase transaction, in order and with matching outpoints. Core treats
both mismatches as DISCONNECT_FAILED (validation.cpp:2187, 2224) because the
position of a Coin is the only thing naming it: a short or misaligned list
would silently restore the wrong coins."
  (let ((remaining spent-utxos)
        (result '()))
    (loop for tx in (rest (bl.ser:bitcoin-block-transactions block))
          for tx-index from 1
          do (let ((coins '()))
               (bl.ser:dovector
                   (input (bl.ser:transaction-inputs tx))
                 (let* ((prevout (bl.ser:tx-in-previous-output input))
                        (triple (pop remaining)))
                   (unless triple
                     (storage-error "undo data is short: transaction ~D has more inputs than the ~
                             spent-utxo list accounts for" tx-index))
                   (destructuring-bind (txid index entry) triple
                     (unless (and (equalp txid
                                          (bl.ser:outpoint-hash prevout))
                                  (= index
                                     (bl.ser:outpoint-index prevout)))
                       (storage-error "undo data is misaligned at transaction ~D: the spent-utxo ~
                               list does not match the block's inputs" tx-index))
                     (push entry coins))))
               (push (nreverse coins) result)))
    (when remaining
      (storage-error "undo data is long: ~D spent-utxo entries past the block's last input"
             (length remaining)))
    (nreverse result)))

(defun spent-utxos-from-block-undo (block tx-undos)
  "The inverse of BLOCK-UNDO-FROM-SPENT-UTXOS: recover (txid index entry)
triples in apply order by reading the outpoints back out of BLOCK."
  (let ((txs (rest (bl.ser:bitcoin-block-transactions block)))
        (result '()))
    (unless (= (length txs) (length tx-undos))
      (storage-error "block and undo data inconsistent: ~D non-coinbase transactions, ~
              ~D undo records" (length txs) (length tx-undos)))
    (loop for tx in txs
          for tx-undo in tx-undos
          for tx-index from 1
          do (let ((inputs (bl.ser:transaction-inputs tx)))
               (unless (= (length inputs) (length tx-undo))
                 (storage-error "transaction and undo data inconsistent at transaction ~D: ~
                         ~D inputs, ~D undo coins"
                        tx-index (length inputs) (length tx-undo)))
               (loop for entry in tx-undo
                     for input-index from 0
                     do (let ((prevout (bl.ser:tx-in-previous-output
                                        (aref inputs input-index))))
                          (push (list (bl.ser:outpoint-hash prevout)
                                      (bl.ser:outpoint-index prevout)
                                      entry)
                                result)))))
    (nreverse result)))
