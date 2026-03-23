(in-package #:bitcoin-lisp.tests)

(def-suite :new-features-tests
  :description "Tests for Bitcoin Core comparison features (PRs #13-#21)"
  :in :bitcoin-lisp-tests)

(in-suite :new-features-tests)

;;;; Undo Data Persistence Tests

(defun make-test-undo-dir ()
  "Create a temporary directory for undo data tests."
  (let ((path (merge-pathnames "test-undo/"
                               (uiop:temporary-directory))))
    (ensure-directories-exist path)
    path))

(defun make-sample-spent-utxos ()
  "Create a sample list of spent UTXOs for testing."
  (let ((txid1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xAA))
        (txid2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xBB))
        (script1 (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76))
        (script2 (make-array 34 :element-type '(unsigned-byte 8) :initial-element #xA9)))
    (list (list txid1 0
                (bitcoin-lisp.storage:make-utxo-entry
                 :value 50000000
                 :script-pubkey script1
                 :height 100
                 :coinbase t))
          (list txid2 3
                (bitcoin-lisp.storage:make-utxo-entry
                 :value 1500000
                 :script-pubkey script2
                 :height 200
                 :coinbase nil)))))

(test undo-data-save-load-round-trip
  "Saving and loading undo data should preserve all entries."
  (let* ((base-path (make-test-undo-dir))
         (block-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x42))
         (spent-utxos (make-sample-spent-utxos)))
    (unwind-protect
         (progn
           ;; Initialize undo storage
           (bitcoin-lisp.validation:initialize-undo-storage base-path)
           ;; Store
           (bitcoin-lisp.validation::store-undo-data block-hash spent-utxos 500)
           ;; Clear in-memory cache to force disk load
           (clrhash bitcoin-lisp.validation::*block-undo-data*)
           (clrhash bitcoin-lisp.validation::*undo-cache-heights*)
           ;; Load from disk
           (let ((loaded (bitcoin-lisp.validation::get-undo-data block-hash)))
             (is (not (null loaded)))
             (is (= 2 (length loaded)))
             ;; Verify first entry
             (destructuring-bind (txid index utxo) (first loaded)
               (is (equalp (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xAA) txid))
               (is (= 0 index))
               (is (= 50000000 (bitcoin-lisp.storage:utxo-entry-value utxo)))
               (is (= 100 (bitcoin-lisp.storage:utxo-entry-height utxo)))
               (is (bitcoin-lisp.storage:utxo-entry-coinbase utxo))
               (is (= 25 (length (bitcoin-lisp.storage:utxo-entry-script-pubkey utxo)))))
             ;; Verify second entry
             (destructuring-bind (txid index utxo) (second loaded)
               (is (equalp (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xBB) txid))
               (is (= 3 index))
               (is (= 1500000 (bitcoin-lisp.storage:utxo-entry-value utxo)))
               (is (= 200 (bitcoin-lisp.storage:utxo-entry-height utxo)))
               (is (not (bitcoin-lisp.storage:utxo-entry-coinbase utxo)))
               (is (= 34 (length (bitcoin-lisp.storage:utxo-entry-script-pubkey utxo)))))))
      ;; Cleanup
      (setf bitcoin-lisp.validation::*undo-base-path* nil)
      (uiop:delete-directory-tree base-path :validate t :if-does-not-exist :ignore))))

(test undo-data-cache-hit
  "Getting undo data should return from cache without disk access."
  (let* ((base-path (make-test-undo-dir))
         (block-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x43))
         (spent-utxos (make-sample-spent-utxos)))
    (unwind-protect
         (progn
           (bitcoin-lisp.validation:initialize-undo-storage base-path)
           (bitcoin-lisp.validation::store-undo-data block-hash spent-utxos 501)
           ;; Should hit cache (not disk)
           (let ((loaded (bitcoin-lisp.validation::get-undo-data block-hash)))
             (is (not (null loaded)))
             (is (= 2 (length loaded)))))
      (setf bitcoin-lisp.validation::*undo-base-path* nil)
      (uiop:delete-directory-tree base-path :validate t :if-does-not-exist :ignore))))

(test undo-data-crc-integrity
  "Corrupted undo data file should return NIL on load."
  (let* ((base-path (make-test-undo-dir))
         (block-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x44))
         (spent-utxos (make-sample-spent-utxos)))
    (unwind-protect
         (progn
           (bitcoin-lisp.validation:initialize-undo-storage base-path)
           (bitcoin-lisp.validation::store-undo-data block-hash spent-utxos 502)
           ;; Clear cache
           (clrhash bitcoin-lisp.validation::*block-undo-data*)
           (clrhash bitcoin-lisp.validation::*undo-cache-heights*)
           ;; Corrupt the file
           (let ((path (bitcoin-lisp.validation::undo-file-path block-hash)))
             (with-open-file (f path :direction :output
                                     :element-type '(unsigned-byte 8)
                                     :if-exists :overwrite)
               ;; Write garbage at offset 20
               (file-position f 20)
               (write-byte #xFF f)))
           ;; Load should fail (CRC mismatch)
           (let ((loaded (bitcoin-lisp.validation::get-undo-data block-hash)))
             (is (null loaded))))
      (setf bitcoin-lisp.validation::*undo-base-path* nil)
      (uiop:delete-directory-tree base-path :validate t :if-does-not-exist :ignore))))

(test undo-data-nonexistent-block
  "Getting undo data for unknown block should return NIL."
  (let ((base-path (make-test-undo-dir))
        (block-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xFF)))
    (unwind-protect
         (progn
           (bitcoin-lisp.validation:initialize-undo-storage base-path)
           (clrhash bitcoin-lisp.validation::*block-undo-data*)
           (is (null (bitcoin-lisp.validation::get-undo-data block-hash))))
      (setf bitcoin-lisp.validation::*undo-base-path* nil)
      (uiop:delete-directory-tree base-path :validate t :if-does-not-exist :ignore))))

(test undo-data-empty-list
  "Saving empty spent-utxos list should produce a valid file on disk."
  (let* ((base-path (make-test-undo-dir))
         (block-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x45)))
    (unwind-protect
         (progn
           (bitcoin-lisp.validation:initialize-undo-storage base-path)
           (bitcoin-lisp.validation::store-undo-data block-hash '() 503)
           ;; Verify the file was written
           (let ((path (bitcoin-lisp.validation::undo-file-path block-hash)))
             (is (not (null (probe-file path)))))
           ;; Cache should have the empty list
           (let ((cached (bitcoin-lisp.validation::get-undo-data block-hash)))
             ;; Empty list from cache is NIL (which is '()), this is correct
             (is (null cached))))
      (setf bitcoin-lisp.validation::*undo-base-path* nil)
      (uiop:delete-directory-tree base-path :validate t :if-does-not-exist :ignore))))

;;;; Taproot Activation Height Tests

(test taproot-flag-below-activation
  "TAPROOT flag should not be present below activation height."
  (let ((bitcoin-lisp:*network* :testnet3))
    (let ((flags (bitcoin-lisp.validation:compute-script-flags-for-height 100)))
      (is (or (null flags)
              (not (search "TAPROOT" flags)))))))

(test taproot-flag-at-activation
  "TAPROOT flag should be present at activation height."
  (let ((bitcoin-lisp:*network* :testnet3))
    (let ((flags (bitcoin-lisp.validation:compute-script-flags-for-height 2346882)))
      (is (not (null flags)))
      (is (search "TAPROOT" flags)))))

(test taproot-flag-above-activation
  "TAPROOT flag should be present above activation height."
  (let ((bitcoin-lisp:*network* :mainnet))
    (let ((flags (bitcoin-lisp.validation:compute-script-flags-for-height 800000)))
      (is (not (null flags)))
      (is (search "TAPROOT" flags)))))

(test taproot-mainnet-activation-height
  "Mainnet taproot activation should be at block 709632."
  (let ((bitcoin-lisp:*network* :mainnet))
    ;; One below: no TAPROOT
    (let ((flags-below (bitcoin-lisp.validation:compute-script-flags-for-height 709631)))
      (is (or (null flags-below)
              (not (search "TAPROOT" flags-below)))))
    ;; At activation: TAPROOT present
    (let ((flags-at (bitcoin-lisp.validation:compute-script-flags-for-height 709632)))
      (is (search "TAPROOT" flags-at)))))

;;;; BIP 30 Duplicate TXID Check Tests

(test bip30-any-utxo-for-txid
  "any-utxo-for-txid-p should find existing UTXOs by txid."
  (let ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xDD))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    ;; Empty set
    (is (not (bitcoin-lisp.storage:any-utxo-for-txid-p utxo-set txid)))
    ;; Add a UTXO
    (bitcoin-lisp.storage:add-utxo utxo-set txid 0 50000000 script 100)
    ;; Should find it
    (is (bitcoin-lisp.storage:any-utxo-for-txid-p utxo-set txid))
    ;; Different txid should not be found
    (let ((other-txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xEE)))
      (is (not (bitcoin-lisp.storage:any-utxo-for-txid-p utxo-set other-txid))))))

(test bip30-multiple-outputs-same-txid
  "any-utxo-for-txid-p should find txid with multiple output indexes."
  (let ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xCC))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    ;; Add multiple outputs for same txid
    (bitcoin-lisp.storage:add-utxo utxo-set txid 0 50000000 script 100)
    (bitcoin-lisp.storage:add-utxo utxo-set txid 1 25000000 script 100)
    ;; Remove one
    (bitcoin-lisp.storage:remove-utxo utxo-set txid 0)
    ;; Should still find it (output 1 exists)
    (is (bitcoin-lisp.storage:any-utxo-for-txid-p utxo-set txid))
    ;; Remove the other
    (bitcoin-lisp.storage:remove-utxo utxo-set txid 1)
    ;; Now should not find it
    (is (not (bitcoin-lisp.storage:any-utxo-for-txid-p utxo-set txid)))))

;;;; Legacy Block Size Limit Tests

(test compact-size-length-values
  "compact-size-length should return correct byte lengths."
  (is (= 1 (bitcoin-lisp.serialization:compact-size-length 0)))
  (is (= 1 (bitcoin-lisp.serialization:compact-size-length 252)))
  (is (= 3 (bitcoin-lisp.serialization:compact-size-length 253)))
  (is (= 3 (bitcoin-lisp.serialization:compact-size-length 65535)))
  (is (= 5 (bitcoin-lisp.serialization:compact-size-length 65536)))
  (is (= 5 (bitcoin-lisp.serialization:compact-size-length #xFFFFFFFF)))
  (is (= 9 (bitcoin-lisp.serialization:compact-size-length #x100000000))))

;;;; Feefilter Message Tests (BIP 133)

(test feefilter-message-round-trip
  "Feefilter message should serialize and parse correctly."
  (let* ((fee-rate 12345)
         (msg (bitcoin-lisp.serialization:make-feefilter-message fee-rate))
         ;; Message = 24-byte header + 8-byte payload
         (payload (subseq msg 24)))
    (is (= fee-rate (bitcoin-lisp.serialization:parse-feefilter-payload payload)))))

(test feefilter-large-fee-rate
  "Feefilter should handle large fee rates."
  (let* ((fee-rate 100000000000)  ; 100 BTC/kB
         (msg (bitcoin-lisp.serialization:make-feefilter-message fee-rate))
         (payload (subseq msg 24)))
    (is (= fee-rate (bitcoin-lisp.serialization:parse-feefilter-payload payload)))))

(test feefilter-zero-rate
  "Feefilter with zero rate should round-trip."
  (let* ((msg (bitcoin-lisp.serialization:make-feefilter-message 0))
         (payload (subseq msg 24)))
    (is (= 0 (bitcoin-lisp.serialization:parse-feefilter-payload payload)))))

;;;; Sendheaders Message Tests (BIP 130)

(test sendheaders-message-format
  "Sendheaders message should have empty payload (24-byte header only)."
  (let ((msg (bitcoin-lisp.serialization:make-sendheaders-message)))
    ;; 24 bytes header, 0 bytes payload
    (is (= 24 (length msg)))))

;;;; Wtxidrelay Message Tests (BIP 339)

(test wtxidrelay-message-format
  "Wtxidrelay message should have empty payload (24-byte header only)."
  (let ((msg (bitcoin-lisp.serialization:make-wtxidrelay-message)))
    (is (= 24 (length msg)))))
