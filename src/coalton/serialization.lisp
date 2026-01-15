;;;; Typed Bitcoin protocol structures and serialization
;;;;
;;;; This module defines algebraic data types for Bitcoin protocol structures,
;;;; providing compile-time type safety for transaction and block handling.

(in-package #:bitcoin-lisp.coalton.serialization)

(named-readtables:in-readtable coalton:coalton)

(coalton-toplevel

  ;;;; Helper for empty lists (for FFI/testing)

  (declare empty-tx-in-list (Unit -> (List TxIn)))
  (define (empty-tx-in-list)
    "Return an empty list of TxIn."
    Nil)

  (declare empty-tx-out-list (Unit -> (List TxOut)))
  (define (empty-tx-out-list)
    "Return an empty list of TxOut."
    Nil)

  (declare empty-transaction-list (Unit -> (List Transaction)))
  (define (empty-transaction-list)
    "Return an empty list of Transactions."
    Nil)

  ;;;; Outpoint - Reference to a previous transaction output

  (define-type Outpoint
    "Reference to a specific output in a previous transaction."
    (Outpoint Hash256 U32))

  (declare make-outpoint (Hash256 -> U32 -> Outpoint))
  (define (make-outpoint hash index)
    "Create an Outpoint from a transaction hash and output index."
    (Outpoint hash index))

  (declare outpoint-hash (Outpoint -> Hash256))
  (define (outpoint-hash op)
    (match op
      ((Outpoint h _) h)))

  (declare outpoint-index (Outpoint -> U32))
  (define (outpoint-index op)
    (match op
      ((Outpoint _ i) i)))

  ;;;; TxIn - Transaction input

  (define-type TxIn
    "A transaction input."
    (TxIn Outpoint (Vector U8) U32))

  (declare make-tx-in (Outpoint -> (Vector U8) -> U32 -> TxIn))
  (define (make-tx-in prev-output script-sig sequence)
    (TxIn prev-output script-sig sequence))

  (declare tx-in-previous-output (TxIn -> Outpoint))
  (define (tx-in-previous-output txin)
    (match txin
      ((TxIn op _ _) op)))

  (declare tx-in-script-sig (TxIn -> (Vector U8)))
  (define (tx-in-script-sig txin)
    (match txin
      ((TxIn _ sig _) sig)))

  (declare tx-in-sequence (TxIn -> U32))
  (define (tx-in-sequence txin)
    (match txin
      ((TxIn _ _ seq) seq)))

  ;;;; TxOut - Transaction output

  (define-type TxOut
    "A transaction output."
    (TxOut Satoshi (Vector U8)))

  (declare make-tx-out (Satoshi -> (Vector U8) -> TxOut))
  (define (make-tx-out value script-pubkey)
    (TxOut value script-pubkey))

  (declare tx-out-value (TxOut -> Satoshi))
  (define (tx-out-value txout)
    (match txout
      ((TxOut v _) v)))

  (declare tx-out-script-pubkey (TxOut -> (Vector U8)))
  (define (tx-out-script-pubkey txout)
    (match txout
      ((TxOut _ script) script)))

  ;;;; Transaction

  (define-type Transaction
    "A Bitcoin transaction."
    (Transaction I32 (List TxIn) (List TxOut) U32))

  (declare make-transaction (I32 -> (List TxIn) -> (List TxOut) -> U32 -> Transaction))
  (define (make-transaction version inputs outputs lock-time)
    (Transaction version inputs outputs lock-time))

  (declare transaction-version (Transaction -> I32))
  (define (transaction-version tx)
    (match tx
      ((Transaction v _ _ _) v)))

  (declare transaction-inputs (Transaction -> (List TxIn)))
  (define (transaction-inputs tx)
    (match tx
      ((Transaction _ ins _ _) ins)))

  (declare transaction-outputs (Transaction -> (List TxOut)))
  (define (transaction-outputs tx)
    (match tx
      ((Transaction _ _ outs _) outs)))

  (declare transaction-lock-time (Transaction -> U32))
  (define (transaction-lock-time tx)
    (match tx
      ((Transaction _ _ _ lock-time) lock-time)))

  ;;;; BlockHeader

  (define-type BlockHeader
    "An 80-byte Bitcoin block header."
    (BlockHeader I32 Hash256 Hash256 U32 U32 U32))

  (declare make-block-header (I32 -> Hash256 -> Hash256 -> U32 -> U32 -> U32 -> BlockHeader))
  (define (make-block-header version prev-block merkle-root timestamp bits nonce)
    (BlockHeader version prev-block merkle-root timestamp bits nonce))

  (declare block-header-version (BlockHeader -> I32))
  (define (block-header-version bh)
    (match bh
      ((BlockHeader v _ _ _ _ _) v)))

  (declare block-header-prev-block (BlockHeader -> Hash256))
  (define (block-header-prev-block bh)
    (match bh
      ((BlockHeader _ pb _ _ _ _) pb)))

  (declare block-header-merkle-root (BlockHeader -> Hash256))
  (define (block-header-merkle-root bh)
    (match bh
      ((BlockHeader _ _ mr _ _ _) mr)))

  (declare block-header-timestamp (BlockHeader -> U32))
  (define (block-header-timestamp bh)
    (match bh
      ((BlockHeader _ _ _ ts _ _) ts)))

  (declare block-header-bits (BlockHeader -> U32))
  (define (block-header-bits bh)
    (match bh
      ((BlockHeader _ _ _ _ bits _) bits)))

  (declare block-header-nonce (BlockHeader -> U32))
  (define (block-header-nonce bh)
    (match bh
      ((BlockHeader _ _ _ _ _ n) n)))

  ;;;; BitcoinBlock

  (define-type BitcoinBlock
    "A complete Bitcoin block."
    (BitcoinBlock BlockHeader (List Transaction)))

  (declare make-bitcoin-block (BlockHeader -> (List Transaction) -> BitcoinBlock))
  (define (make-bitcoin-block header transactions)
    (BitcoinBlock header transactions))

  (declare bitcoin-block-header (BitcoinBlock -> BlockHeader))
  (define (bitcoin-block-header block)
    (match block
      ((BitcoinBlock h _) h)))

  (declare bitcoin-block-transactions (BitcoinBlock -> (List Transaction)))
  (define (bitcoin-block-transactions block)
    (match block
      ((BitcoinBlock _ txs) txs)))

  ;;;; ================================================================
  ;;;; Serialization - Write protocol types to byte vectors
  ;;;; ================================================================

  (declare serialize-outpoint (Outpoint -> (Vector U8)))
  (define (serialize-outpoint op)
    "Serialize an Outpoint to 36 bytes (32 byte hash + 4 byte index)."
    (concat-bytes (hash256-bytes (outpoint-hash op))
                  (write-u32-le (outpoint-index op))))

  (declare serialize-tx-in (TxIn -> (Vector U8)))
  (define (serialize-tx-in txin)
    "Serialize a transaction input."
    (let ((outpoint-bytes (serialize-outpoint (tx-in-previous-output txin)))
          (script (tx-in-script-sig txin))
          (script-len (lisp U64 (script) (cl:length script)))
          (sequence-bytes (write-u32-le (tx-in-sequence txin))))
      (concat-bytes outpoint-bytes
                    (concat-bytes (write-compact-size script-len)
                                  (concat-bytes script sequence-bytes)))))

  (declare satoshi-to-u64 (Satoshi -> U64))
  (define (satoshi-to-u64 sat)
    "Convert Satoshi to U64 for serialization."
    (let ((v (satoshi-value sat)))
      (lisp U64 (v) v)))

  (declare serialize-tx-out (TxOut -> (Vector U8)))
  (define (serialize-tx-out txout)
    "Serialize a transaction output."
    (let ((value-bytes (write-u64-le (satoshi-to-u64 (tx-out-value txout))))
          (script (tx-out-script-pubkey txout))
          (script-len (lisp U64 (script) (cl:length script))))
      (concat-bytes value-bytes
                    (concat-bytes (write-compact-size script-len)
                                  script))))

  (declare serialize-tx-inputs ((List TxIn) -> (Vector U8)))
  (define (serialize-tx-inputs inputs)
    "Serialize a list of transaction inputs."
    (match inputs
      ((Nil) (lisp (Vector U8) () (cl:vector)))
      ((Cons head tail)
       (concat-bytes (serialize-tx-in head)
                     (serialize-tx-inputs tail)))))

  (declare serialize-tx-outputs ((List TxOut) -> (Vector U8)))
  (define (serialize-tx-outputs outputs)
    "Serialize a list of transaction outputs."
    (match outputs
      ((Nil) (lisp (Vector U8) () (cl:vector)))
      ((Cons head tail)
       (concat-bytes (serialize-tx-out head)
                     (serialize-tx-outputs tail)))))

  (declare list-length-txin ((List TxIn) -> U64))
  (define (list-length-txin lst)
    "Get the length of a TxIn list as U64."
    (match lst
      ((Nil) 0)
      ((Cons _ tail) (+ 1 (list-length-txin tail)))))

  (declare list-length-txout ((List TxOut) -> U64))
  (define (list-length-txout lst)
    "Get the length of a TxOut list as U64."
    (match lst
      ((Nil) 0)
      ((Cons _ tail) (+ 1 (list-length-txout tail)))))

  (declare list-length-tx ((List Transaction) -> U64))
  (define (list-length-tx lst)
    "Get the length of a Transaction list as U64."
    (match lst
      ((Nil) 0)
      ((Cons _ tail) (+ 1 (list-length-tx tail)))))

  (declare serialize-transaction (Transaction -> (Vector U8)))
  (define (serialize-transaction tx)
    "Serialize a transaction to bytes."
    (let ((version-bytes (write-i32-le (transaction-version tx)))
          (inputs (transaction-inputs tx))
          (outputs (transaction-outputs tx))
          (locktime-bytes (write-u32-le (transaction-lock-time tx))))
      (let ((input-count (list-length-txin inputs))
            (output-count (list-length-txout outputs)))
        (concat-bytes version-bytes
                      (concat-bytes (write-compact-size input-count)
                                    (concat-bytes (serialize-tx-inputs inputs)
                                                  (concat-bytes (write-compact-size output-count)
                                                                (concat-bytes (serialize-tx-outputs outputs)
                                                                              locktime-bytes))))))))

  (declare serialize-block-header (BlockHeader -> (Vector U8)))
  (define (serialize-block-header bh)
    "Serialize a block header to 80 bytes."
    (let ((version (write-i32-le (block-header-version bh)))
          (prev-block (hash256-bytes (block-header-prev-block bh)))
          (merkle-root (hash256-bytes (block-header-merkle-root bh)))
          (timestamp (write-u32-le (block-header-timestamp bh)))
          (bits (write-u32-le (block-header-bits bh)))
          (nonce (write-u32-le (block-header-nonce bh))))
      (concat-bytes version
                    (concat-bytes prev-block
                                  (concat-bytes merkle-root
                                                (concat-bytes timestamp
                                                              (concat-bytes bits nonce)))))))

  (declare serialize-transactions ((List Transaction) -> (Vector U8)))
  (define (serialize-transactions txs)
    "Serialize a list of transactions."
    (match txs
      ((Nil) (lisp (Vector U8) () (cl:vector)))
      ((Cons head tail)
       (concat-bytes (serialize-transaction head)
                     (serialize-transactions tail)))))

  (declare serialize-block (BitcoinBlock -> (Vector U8)))
  (define (serialize-block block)
    "Serialize a complete block to bytes."
    (let ((header-bytes (serialize-block-header (bitcoin-block-header block)))
          (txs (bitcoin-block-transactions block)))
      (let ((tx-count (list-length-tx txs)))
        (concat-bytes header-bytes
                      (concat-bytes (write-compact-size tx-count)
                                    (serialize-transactions txs))))))

  ;;;; ================================================================
  ;;;; Deserialization - Read protocol types from byte vectors
  ;;;; ================================================================

  (declare make-hash256-unsafe ((Vector U8) -> Hash256))
  (define (make-hash256-unsafe bytes)
    "Create Hash256 without length check (use only when you know length is 32)."
    (lisp Hash256 (bytes)
      (bitcoin-lisp.coalton.types::Hash256 bytes)))

  (declare deserialize-outpoint ((Vector U8) -> UFix -> (ReadResult Outpoint)))
  (define (deserialize-outpoint bytes pos)
    "Deserialize an Outpoint from bytes at position."
    (let ((hash-result (read-bytes bytes pos 32)))
      (let ((hash-bytes (read-result-value hash-result))
            (pos2 (read-result-position hash-result)))
        (let ((index-result (read-u32-le bytes pos2)))
          (let ((index (read-result-value index-result))
                (pos3 (read-result-position index-result)))
            (ReadResult (make-outpoint (make-hash256-unsafe hash-bytes) index)
                        pos3))))))

  (declare u64-to-ufix (U64 -> UFix))
  (define (u64-to-ufix n)
    "Convert U64 to UFix."
    (lisp UFix (n) n))

  (declare deserialize-tx-in ((Vector U8) -> UFix -> (ReadResult TxIn)))
  (define (deserialize-tx-in bytes pos)
    "Deserialize a transaction input from bytes at position."
    (let ((outpoint-result (deserialize-outpoint bytes pos)))
      (let ((outpoint (read-result-value outpoint-result))
            (pos2 (read-result-position outpoint-result)))
        (let ((script-len-result (read-compact-size bytes pos2)))
          (let ((script-len (read-result-value script-len-result))
                (pos3 (read-result-position script-len-result)))
            (let ((script-result (read-bytes bytes pos3 (u64-to-ufix script-len))))
              (let ((script (read-result-value script-result))
                    (pos4 (read-result-position script-result)))
                (let ((seq-result (read-u32-le bytes pos4)))
                  (let ((sequence (read-result-value seq-result))
                        (pos5 (read-result-position seq-result)))
                    (ReadResult (make-tx-in outpoint script sequence)
                                pos5))))))))))

  (declare u64-to-integer (U64 -> Integer))
  (define (u64-to-integer n)
    "Convert U64 to Integer."
    (lisp Integer (n) n))

  (declare deserialize-tx-out ((Vector U8) -> UFix -> (ReadResult TxOut)))
  (define (deserialize-tx-out bytes pos)
    "Deserialize a transaction output from bytes at position."
    (let ((value-result (read-u64-le bytes pos)))
      (let ((value (read-result-value value-result))
            (pos2 (read-result-position value-result)))
        (let ((script-len-result (read-compact-size bytes pos2)))
          (let ((script-len (read-result-value script-len-result))
                (pos3 (read-result-position script-len-result)))
            (let ((script-result (read-bytes bytes pos3 (u64-to-ufix script-len))))
              (let ((script (read-result-value script-result))
                    (pos4 (read-result-position script-result)))
                (ReadResult (make-tx-out (make-satoshi (u64-to-integer value)) script)
                            pos4))))))))

  (declare deserialize-tx-inputs ((Vector U8) -> UFix -> U64 -> (ReadResult (List TxIn))))
  (define (deserialize-tx-inputs bytes pos count)
    "Deserialize count transaction inputs from bytes."
    (if (== count 0)
        (ReadResult Nil pos)
        (let ((input-result (deserialize-tx-in bytes pos)))
          (let ((input (read-result-value input-result))
                (pos2 (read-result-position input-result)))
            (let ((rest-result (deserialize-tx-inputs bytes pos2 (- count 1))))
              (let ((rest (read-result-value rest-result))
                    (pos3 (read-result-position rest-result)))
                (ReadResult (Cons input rest) pos3)))))))

  (declare deserialize-tx-outputs ((Vector U8) -> UFix -> U64 -> (ReadResult (List TxOut))))
  (define (deserialize-tx-outputs bytes pos count)
    "Deserialize count transaction outputs from bytes."
    (if (== count 0)
        (ReadResult Nil pos)
        (let ((output-result (deserialize-tx-out bytes pos)))
          (let ((output (read-result-value output-result))
                (pos2 (read-result-position output-result)))
            (let ((rest-result (deserialize-tx-outputs bytes pos2 (- count 1))))
              (let ((rest (read-result-value rest-result))
                    (pos3 (read-result-position rest-result)))
                (ReadResult (Cons output rest) pos3)))))))

  (declare deserialize-transaction ((Vector U8) -> UFix -> (ReadResult Transaction)))
  (define (deserialize-transaction bytes pos)
    "Deserialize a transaction from bytes at position."
    (let ((version-result (read-i32-le bytes pos)))
      (let ((version (read-result-value version-result))
            (pos2 (read-result-position version-result)))
        (let ((input-count-result (read-compact-size bytes pos2)))
          (let ((input-count (read-result-value input-count-result))
                (pos3 (read-result-position input-count-result)))
            (let ((inputs-result (deserialize-tx-inputs bytes pos3 input-count)))
              (let ((inputs (read-result-value inputs-result))
                    (pos4 (read-result-position inputs-result)))
                (let ((output-count-result (read-compact-size bytes pos4)))
                  (let ((output-count (read-result-value output-count-result))
                        (pos5 (read-result-position output-count-result)))
                    (let ((outputs-result (deserialize-tx-outputs bytes pos5 output-count)))
                      (let ((outputs (read-result-value outputs-result))
                            (pos6 (read-result-position outputs-result)))
                        (let ((locktime-result (read-u32-le bytes pos6)))
                          (let ((locktime (read-result-value locktime-result))
                                (pos7 (read-result-position locktime-result)))
                            (ReadResult (make-transaction version inputs outputs locktime)
                                        pos7))))))))))))))

  (declare deserialize-block-header ((Vector U8) -> UFix -> (ReadResult BlockHeader)))
  (define (deserialize-block-header bytes pos)
    "Deserialize a block header from bytes at position."
    (let ((version-result (read-i32-le bytes pos)))
      (let ((version (read-result-value version-result))
            (pos2 (read-result-position version-result)))
        (let ((prev-result (read-bytes bytes pos2 32)))
          (let ((prev-bytes (read-result-value prev-result))
                (pos3 (read-result-position prev-result)))
            (let ((merkle-result (read-bytes bytes pos3 32)))
              (let ((merkle-bytes (read-result-value merkle-result))
                    (pos4 (read-result-position merkle-result)))
                (let ((timestamp-result (read-u32-le bytes pos4)))
                  (let ((timestamp (read-result-value timestamp-result))
                        (pos5 (read-result-position timestamp-result)))
                    (let ((bits-result (read-u32-le bytes pos5)))
                      (let ((bits (read-result-value bits-result))
                            (pos6 (read-result-position bits-result)))
                        (let ((nonce-result (read-u32-le bytes pos6)))
                          (let ((nonce (read-result-value nonce-result))
                                (pos7 (read-result-position nonce-result)))
                            (ReadResult (make-block-header version
                                                           (make-hash256-unsafe prev-bytes)
                                                           (make-hash256-unsafe merkle-bytes)
                                                           timestamp bits nonce)
                                        pos7))))))))))))))

  (declare deserialize-transactions ((Vector U8) -> UFix -> U64 -> (ReadResult (List Transaction))))
  (define (deserialize-transactions bytes pos count)
    "Deserialize count transactions from bytes."
    (if (== count 0)
        (ReadResult Nil pos)
        (let ((tx-result (deserialize-transaction bytes pos)))
          (let ((tx (read-result-value tx-result))
                (pos2 (read-result-position tx-result)))
            (let ((rest-result (deserialize-transactions bytes pos2 (- count 1))))
              (let ((rest (read-result-value rest-result))
                    (pos3 (read-result-position rest-result)))
                (ReadResult (Cons tx rest) pos3)))))))

  (declare deserialize-block ((Vector U8) -> UFix -> (ReadResult BitcoinBlock)))
  (define (deserialize-block bytes pos)
    "Deserialize a complete block from bytes at position."
    (let ((header-result (deserialize-block-header bytes pos)))
      (let ((header (read-result-value header-result))
            (pos2 (read-result-position header-result)))
        (let ((tx-count-result (read-compact-size bytes pos2)))
          (let ((tx-count (read-result-value tx-count-result))
                (pos3 (read-result-position tx-count-result)))
            (let ((txs-result (deserialize-transactions bytes pos3 tx-count)))
              (let ((txs (read-result-value txs-result))
                    (pos4 (read-result-position txs-result)))
                (ReadResult (make-bitcoin-block header txs)
                            pos4)))))))))
