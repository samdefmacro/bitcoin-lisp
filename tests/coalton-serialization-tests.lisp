;;;; Tests for Coalton serialization types
;;;;
;;;; Verifies that protocol structures (Outpoint, TxIn, TxOut, Transaction,
;;;; BlockHeader, BitcoinBlock) work correctly.

(in-package #:bitcoin-lisp.coalton.tests)

(in-suite coalton-tests)

(test outpoint-creation
  "Test Outpoint type creation and accessors."
  (is (= 0 (coalton:coalton
            (bitcoin-lisp.coalton.serialization:outpoint-index
             (bitcoin-lisp.coalton.serialization:make-outpoint
              (bitcoin-lisp.coalton.types:hash256-zero)
              0))))))

(test outpoint-index-value
  "Test Outpoint with non-zero index."
  (is (= 5 (coalton:coalton
            (bitcoin-lisp.coalton.serialization:outpoint-index
             (bitcoin-lisp.coalton.serialization:make-outpoint
              (bitcoin-lisp.coalton.types:hash256-zero)
              5))))))

(test transaction-version
  "Test Transaction version accessor."
  (is (= 1 (coalton:coalton
            (bitcoin-lisp.coalton.serialization:transaction-version
             (bitcoin-lisp.coalton.serialization:make-transaction
              1
              (bitcoin-lisp.coalton.serialization:empty-tx-in-list)
              (bitcoin-lisp.coalton.serialization:empty-tx-out-list)
              0))))))

(test transaction-lock-time
  "Test Transaction lock-time accessor."
  (is (= 500000 (coalton:coalton
                 (bitcoin-lisp.coalton.serialization:transaction-lock-time
                  (bitcoin-lisp.coalton.serialization:make-transaction
                   1
                   (bitcoin-lisp.coalton.serialization:empty-tx-in-list)
                   (bitcoin-lisp.coalton.serialization:empty-tx-out-list)
                   500000))))))

(test block-header-version
  "Test BlockHeader version accessor."
  (is (= 1 (coalton:coalton
            (bitcoin-lisp.coalton.serialization:block-header-version
             (bitcoin-lisp.coalton.serialization:make-block-header
              1
              (bitcoin-lisp.coalton.types:hash256-zero)
              (bitcoin-lisp.coalton.types:hash256-zero)
              1231006505
              486604799
              2083236893))))))

(test block-header-timestamp
  "Test BlockHeader timestamp accessor with genesis value."
  (is (= 1231006505 (coalton:coalton
                     (bitcoin-lisp.coalton.serialization:block-header-timestamp
                      (bitcoin-lisp.coalton.serialization:make-block-header
                       1
                       (bitcoin-lisp.coalton.types:hash256-zero)
                       (bitcoin-lisp.coalton.types:hash256-zero)
                       1231006505
                       486604799
                       2083236893))))))

(test block-header-nonce
  "Test BlockHeader nonce accessor."
  (is (= 2083236893 (coalton:coalton
                     (bitcoin-lisp.coalton.serialization:block-header-nonce
                      (bitcoin-lisp.coalton.serialization:make-block-header
                       1
                       (bitcoin-lisp.coalton.types:hash256-zero)
                       (bitcoin-lisp.coalton.types:hash256-zero)
                       1231006505
                       486604799
                       2083236893))))))

(test bitcoin-block-header-version
  "Test BitcoinBlock header accessor."
  (is (= 1 (coalton:coalton
            (bitcoin-lisp.coalton.serialization:block-header-version
             (bitcoin-lisp.coalton.serialization:bitcoin-block-header
              (bitcoin-lisp.coalton.serialization:make-bitcoin-block
               (bitcoin-lisp.coalton.serialization:make-block-header
                1
                (bitcoin-lisp.coalton.types:hash256-zero)
                (bitcoin-lisp.coalton.types:hash256-zero)
                0 0 0)
               (bitcoin-lisp.coalton.serialization:empty-transaction-list))))))))

;;;; Serialization/Deserialization roundtrip tests

(defun get-read-result-value (rr)
  "Extract value from ReadResult."
  (bitcoin-lisp.coalton.binary:read-result-value rr))

(defun get-read-result-position (rr)
  "Extract position from ReadResult."
  (bitcoin-lisp.coalton.binary:read-result-position rr))

(test serialize-outpoint-length
  "Test that serialized Outpoint is 36 bytes."
  (let* ((op (bitcoin-lisp.coalton.serialization:make-outpoint
              (bitcoin-lisp.coalton.types:hash256-zero coalton:Unit)
              5))
         (bytes (bitcoin-lisp.coalton.serialization:serialize-outpoint op)))
    (is (= 36 (length bytes)))))

(test serialize-outpoint-roundtrip
  "Test Outpoint serialization roundtrip."
  (let* ((op (bitcoin-lisp.coalton.serialization:make-outpoint
              (bitcoin-lisp.coalton.types:hash256-zero coalton:Unit)
              42))
         (bytes (bitcoin-lisp.coalton.serialization:serialize-outpoint op))
         (result (bitcoin-lisp.coalton.serialization:deserialize-outpoint bytes 0))
         (op2 (get-read-result-value result)))
    (is (= 42 (bitcoin-lisp.coalton.serialization:outpoint-index op2)))
    (is (= 36 (get-read-result-position result)))))

(test serialize-block-header-length
  "Test that serialized BlockHeader is 80 bytes."
  (let* ((bh (bitcoin-lisp.coalton.serialization:make-block-header
              1  ; version
              (bitcoin-lisp.coalton.types:hash256-zero coalton:Unit)  ; prev
              (bitcoin-lisp.coalton.types:hash256-zero coalton:Unit)  ; merkle
              1231006505  ; timestamp (genesis)
              #x1d00ffff  ; bits (genesis)
              2083236893))  ; nonce (genesis)
         (bytes (bitcoin-lisp.coalton.serialization:serialize-block-header bh)))
    (is (= 80 (length bytes)))))

(test serialize-block-header-roundtrip
  "Test BlockHeader serialization roundtrip."
  (let* ((bh (bitcoin-lisp.coalton.serialization:make-block-header
              1  ; version
              (bitcoin-lisp.coalton.types:hash256-zero coalton:Unit)  ; prev
              (bitcoin-lisp.coalton.types:hash256-zero coalton:Unit)  ; merkle
              1231006505  ; timestamp
              #x1d00ffff  ; bits
              2083236893))  ; nonce
         (bytes (bitcoin-lisp.coalton.serialization:serialize-block-header bh))
         (result (bitcoin-lisp.coalton.serialization:deserialize-block-header bytes 0))
         (bh2 (get-read-result-value result)))
    (is (= 1 (bitcoin-lisp.coalton.serialization:block-header-version bh2)))
    (is (= 1231006505 (bitcoin-lisp.coalton.serialization:block-header-timestamp bh2)))
    (is (= #x1d00ffff (bitcoin-lisp.coalton.serialization:block-header-bits bh2)))
    (is (= 2083236893 (bitcoin-lisp.coalton.serialization:block-header-nonce bh2)))
    (is (= 80 (get-read-result-position result)))))

(test serialize-tx-out-roundtrip
  "Test TxOut serialization roundtrip."
  (let* ((script (make-array 5 :initial-contents '(#x76 #xa9 #x14 #x00 #x00)))
         (txout (bitcoin-lisp.coalton.serialization:make-tx-out
                 (bitcoin-lisp.coalton.types:make-satoshi 50000000)  ; 0.5 BTC
                 script))
         (bytes (bitcoin-lisp.coalton.serialization:serialize-tx-out txout))
         (result (bitcoin-lisp.coalton.serialization:deserialize-tx-out bytes 0))
         (txout2 (get-read-result-value result)))
    ;; Value should be 50000000
    (is (= 50000000
           (bitcoin-lisp.coalton.types:satoshi-value
            (bitcoin-lisp.coalton.serialization:tx-out-value txout2))))
    ;; Script should be same length
    (is (= 5 (length (bitcoin-lisp.coalton.serialization:tx-out-script-pubkey txout2))))))

(test serialize-tx-in-roundtrip
  "Test TxIn serialization roundtrip."
  (let* ((outpoint (bitcoin-lisp.coalton.serialization:make-outpoint
                    (bitcoin-lisp.coalton.types:hash256-zero coalton:Unit)
                    0))
         (script (make-array 3 :initial-contents '(#x01 #x02 #x03)))
         (txin (bitcoin-lisp.coalton.serialization:make-tx-in outpoint script #xFFFFFFFF))
         (bytes (bitcoin-lisp.coalton.serialization:serialize-tx-in txin))
         (result (bitcoin-lisp.coalton.serialization:deserialize-tx-in bytes 0))
         (txin2 (get-read-result-value result)))
    (is (= #xFFFFFFFF (bitcoin-lisp.coalton.serialization:tx-in-sequence txin2)))
    (is (= 3 (length (bitcoin-lisp.coalton.serialization:tx-in-script-sig txin2))))))

(test serialize-empty-transaction
  "Test Transaction with no inputs/outputs serialization."
  (let* ((tx (bitcoin-lisp.coalton.serialization:make-transaction
              1  ; version
              (bitcoin-lisp.coalton.serialization:empty-tx-in-list coalton:Unit)
              (bitcoin-lisp.coalton.serialization:empty-tx-out-list coalton:Unit)
              0))  ; locktime
         (bytes (bitcoin-lisp.coalton.serialization:serialize-transaction tx))
         (result (bitcoin-lisp.coalton.serialization:deserialize-transaction bytes 0))
         (tx2 (get-read-result-value result)))
    (is (= 1 (bitcoin-lisp.coalton.serialization:transaction-version tx2)))
    (is (= 0 (bitcoin-lisp.coalton.serialization:transaction-lock-time tx2)))))

(test serialize-empty-block
  "Test Block with no transactions serialization."
  (let* ((header (bitcoin-lisp.coalton.serialization:make-block-header
                  1
                  (bitcoin-lisp.coalton.types:hash256-zero coalton:Unit)
                  (bitcoin-lisp.coalton.types:hash256-zero coalton:Unit)
                  0 0 0))
         (block (bitcoin-lisp.coalton.serialization:make-bitcoin-block
                 header
                 (bitcoin-lisp.coalton.serialization:empty-transaction-list coalton:Unit)))
         (bytes (bitcoin-lisp.coalton.serialization:serialize-block block))
         (result (bitcoin-lisp.coalton.serialization:deserialize-block bytes 0))
         (block2 (get-read-result-value result)))
    (is (= 1 (bitcoin-lisp.coalton.serialization:block-header-version
              (bitcoin-lisp.coalton.serialization:bitcoin-block-header block2))))
    ;; 80 bytes header + 1 byte tx count (0)
    (is (= 81 (get-read-result-position result)))))
