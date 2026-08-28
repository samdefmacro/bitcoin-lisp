;;;; Tests for Coalton serialization types
;;;;
;;;; Verifies that protocol structures (Outpoint, TxIn, TxOut, Transaction,
;;;; BlockHeader, BitcoinBlock) work correctly.

(in-package #:bitcoin-lisp.coalton.tests)

(in-suite coalton-tests)

(test outpoint-creation
  "Test Outpoint type creation and accessors."
  (is (= 0 (coalton:coalton
            (bl.cser:outpoint-index
             (bl.cser:make-outpoint
              (bl.ctypes:hash256-zero)
              0))))))

(test outpoint-index-value
  "Test Outpoint with non-zero index."
  (is (= 5 (coalton:coalton
            (bl.cser:outpoint-index
             (bl.cser:make-outpoint
              (bl.ctypes:hash256-zero)
              5))))))

(test transaction-version
  "Test Transaction version accessor."
  (is (= 1 (coalton:coalton
            (bl.cser:transaction-version
             (bl.cser:make-transaction
              1
              (bl.cser:empty-tx-in-list)
              (bl.cser:empty-tx-out-list)
              0))))))

(test transaction-lock-time
  "Test Transaction lock-time accessor."
  (is (= 500000 (coalton:coalton
                 (bl.cser:transaction-lock-time
                  (bl.cser:make-transaction
                   1
                   (bl.cser:empty-tx-in-list)
                   (bl.cser:empty-tx-out-list)
                   500000))))))

(test block-header-version
  "Test BlockHeader version accessor."
  (is (= 1 (coalton:coalton
            (bl.cser:block-header-version
             (bl.cser:make-block-header
              1
              (bl.ctypes:hash256-zero)
              (bl.ctypes:hash256-zero)
              1231006505
              486604799
              2083236893))))))

(test block-header-timestamp
  "Test BlockHeader timestamp accessor with genesis value."
  (is (= 1231006505 (coalton:coalton
                     (bl.cser:block-header-timestamp
                      (bl.cser:make-block-header
                       1
                       (bl.ctypes:hash256-zero)
                       (bl.ctypes:hash256-zero)
                       1231006505
                       486604799
                       2083236893))))))

(test block-header-nonce
  "Test BlockHeader nonce accessor."
  (is (= 2083236893 (coalton:coalton
                     (bl.cser:block-header-nonce
                      (bl.cser:make-block-header
                       1
                       (bl.ctypes:hash256-zero)
                       (bl.ctypes:hash256-zero)
                       1231006505
                       486604799
                       2083236893))))))

(test bitcoin-block-header-version
  "Test BitcoinBlock header accessor."
  (is (= 1 (coalton:coalton
            (bl.cser:block-header-version
             (bl.cser:bitcoin-block-header
              (bl.cser:make-bitcoin-block
               (bl.cser:make-block-header
                1
                (bl.ctypes:hash256-zero)
                (bl.ctypes:hash256-zero)
                0 0 0)
               (bl.cser:empty-transaction-list))))))))

;;;; Serialization/Deserialization roundtrip tests

(test serialize-outpoint-length
  "Test that serialized Outpoint is 36 bytes."
  (let* ((op (bl.cser:make-outpoint
              (bl.ctypes:hash256-zero coalton:Unit)
              5))
         (bytes (bl.cser:serialize-outpoint op)))
    (is (= 36 (length bytes)))))

(test serialize-outpoint-roundtrip
  "Test Outpoint serialization roundtrip."
  (let* ((op (bl.cser:make-outpoint
              (bl.ctypes:hash256-zero coalton:Unit)
              42))
         (bytes (bl.cser:serialize-outpoint op))
         (result (bl.cser:deserialize-outpoint bytes 0))
         (op2 (get-read-result-value result)))
    (is (= 42 (bl.cser:outpoint-index op2)))
    (is (= 36 (get-read-result-position result)))))

(test serialize-block-header-length
  "Test that serialized BlockHeader is 80 bytes."
  (let* ((bh (bl.cser:make-block-header
              1  ; version
              (bl.ctypes:hash256-zero coalton:Unit)  ; prev
              (bl.ctypes:hash256-zero coalton:Unit)  ; merkle
              1231006505  ; timestamp (genesis)
              #x1d00ffff  ; bits (genesis)
              2083236893))  ; nonce (genesis)
         (bytes (bl.cser:serialize-block-header bh)))
    (is (= 80 (length bytes)))))

(test serialize-block-header-roundtrip
  "Test BlockHeader serialization roundtrip."
  (let* ((bh (bl.cser:make-block-header
              1  ; version
              (bl.ctypes:hash256-zero coalton:Unit)  ; prev
              (bl.ctypes:hash256-zero coalton:Unit)  ; merkle
              1231006505  ; timestamp
              #x1d00ffff  ; bits
              2083236893))  ; nonce
         (bytes (bl.cser:serialize-block-header bh))
         (result (bl.cser:deserialize-block-header bytes 0))
         (bh2 (get-read-result-value result)))
    (is (= 1 (bl.cser:block-header-version bh2)))
    (is (= 1231006505 (bl.cser:block-header-timestamp bh2)))
    (is (= #x1d00ffff (bl.cser:block-header-bits bh2)))
    (is (= 2083236893 (bl.cser:block-header-nonce bh2)))
    (is (= 80 (get-read-result-position result)))))

(test serialize-tx-out-roundtrip
  "Test TxOut serialization roundtrip."
  (let* ((script (make-array 5 :initial-contents '(#x76 #xa9 #x14 #x00 #x00)))
         (txout (bl.cser:make-tx-out
                 (bl.ctypes:make-satoshi 50000000)  ; 0.5 BTC
                 script))
         (bytes (bl.cser:serialize-tx-out txout))
         (result (bl.cser:deserialize-tx-out bytes 0))
         (txout2 (get-read-result-value result)))
    ;; Value should be 50000000
    (is (= 50000000
           (bl.ctypes:satoshi-value
            (bl.cser:tx-out-value txout2))))
    ;; Script should be same length
    (is (= 5 (length (bl.cser:tx-out-script-pubkey txout2))))))

(test serialize-tx-in-roundtrip
  "Test TxIn serialization roundtrip."
  (let* ((outpoint (bl.cser:make-outpoint
                    (bl.ctypes:hash256-zero coalton:Unit)
                    0))
         (script (make-array 3 :initial-contents '(#x01 #x02 #x03)))
         (txin (bl.cser:make-tx-in outpoint script #xFFFFFFFF))
         (bytes (bl.cser:serialize-tx-in txin))
         (result (bl.cser:deserialize-tx-in bytes 0))
         (txin2 (get-read-result-value result)))
    (is (= #xFFFFFFFF (bl.cser:tx-in-sequence txin2)))
    (is (= 3 (length (bl.cser:tx-in-script-sig txin2))))))

(test serialize-empty-transaction
  "Test Transaction with no inputs/outputs serialization."
  (let* ((tx (bl.cser:make-transaction
              1  ; version
              (bl.cser:empty-tx-in-list coalton:Unit)
              (bl.cser:empty-tx-out-list coalton:Unit)
              0))  ; locktime
         (bytes (bl.cser:serialize-transaction tx))
         (result (bl.cser:deserialize-transaction bytes 0))
         (tx2 (get-read-result-value result)))
    (is (= 1 (bl.cser:transaction-version tx2)))
    (is (= 0 (bl.cser:transaction-lock-time tx2)))))

(test serialize-empty-block
  "Test Block with no transactions serialization."
  (let* ((header (bl.cser:make-block-header
                  1
                  (bl.ctypes:hash256-zero coalton:Unit)
                  (bl.ctypes:hash256-zero coalton:Unit)
                  0 0 0))
         (block (bl.cser:make-bitcoin-block
                 header
                 (bl.cser:empty-transaction-list coalton:Unit)))
         (bytes (bl.cser:serialize-block block))
         (result (bl.cser:deserialize-block bytes 0))
         (block2 (get-read-result-value result)))
    (is (= 1 (bl.cser:block-header-version
              (bl.cser:bitcoin-block-header block2))))
    ;; 80 bytes header + 1 byte tx count (0)
    (is (= 81 (get-read-result-position result)))))
