(in-package #:bitcoin-lisp.tests)

(def-suite :new-features-tests
  :description "Tests for Bitcoin Core comparison features (the Core-comparison PRs)"
  :in :bitcoin-lisp-tests)

(in-suite :new-features-tests)

;;;; Unspendable-output detection (Core CScript::IsUnspendable)

(test script-unspendable-p-classification
  "OP_RETURN-first scripts and scripts over MAX_SCRIPT_SIZE are unspendable;
normal scripts (P2PKH, P2WPKH, bare pubkey, empty) are not."
  (flet ((mk (&rest bytes) (make-array (length bytes) :element-type '(unsigned-byte 8)
                                                      :initial-contents bytes)))
    ;; OP_RETURN (0x6a) first byte -> unspendable, regardless of what follows.
    (is-true (bl.store:script-unspendable-p (mk #x6a)))
    (is-true (bl.store:script-unspendable-p (mk #x6a #x24 #xaa #x21 #xa9 #xed)))
    ;; A witness-commitment style OP_RETURN.
    (is-true (bl.store:script-unspendable-p
              (make-array 38 :element-type '(unsigned-byte 8)
                             :initial-contents (list* #x6a #x24 (make-list 36 :initial-element #xaa)))))
    ;; Oversized script (> 10000 bytes) -> unspendable.
    (is-true (bl.store:script-unspendable-p
              (make-array 10001 :element-type '(unsigned-byte 8) :initial-element #x51)))
    ;; Spendable scripts.
    (is-false (bl.store:script-unspendable-p (mk #x51)))        ; OP_TRUE
    (is-false (bl.store:script-unspendable-p                    ; P2PKH-ish
               (mk #x76 #xa9 #x14 #x00 #x00 #x00)))
    (is-false (bl.store:script-unspendable-p                    ; exactly 10000
               (make-array 10000 :element-type '(unsigned-byte 8) :initial-element #x51)))
    (is-false (bl.store:script-unspendable-p (mk)))))           ; empty

;;;; Undo Data Persistence Tests

(defun make-sample-spent-utxos ()
  "Create a sample list of spent UTXOs for testing."
  (let ((txid1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xAA))
        (txid2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xBB))
        (script1 (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76))
        (script2 (make-array 34 :element-type '(unsigned-byte 8) :initial-element #xA9)))
    (list (list txid1 0
                (bl.store:make-utxo-entry
                 :value 50000000
                 :script-pubkey script1
                 :height 100
                 :coinbase t))
          (list txid2 3
                (bl.store:make-utxo-entry
                 :value 1500000
                 :script-pubkey script2
                 :height 200
                 :coinbase nil)))))

(test undo-data-save-load-round-trip
  "Saving and loading undo data should preserve all entries."
  (let* ((base-path (make-temp-directory))
         (block-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x42))
         (spent-utxos (make-sample-spent-utxos)))
    (unwind-protect
         (progn
           ;; Initialize undo storage
           (bl.val:initialize-undo-storage base-path)
           ;; Store
           (bl.val::store-undo-data block-hash spent-utxos 500)
           ;; Clear in-memory cache to force disk load
           (clrhash bl.val::*block-undo-data*)
           (clrhash bl.val::*undo-cache-heights*)
           ;; Load from disk
           (let ((loaded (bl.val:get-undo-data block-hash)))
             (is (not (null loaded)))
             (is (= 2 (length loaded)))
             ;; Verify first entry
             (destructuring-bind (txid index utxo) (first loaded)
               (is (equalp (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xAA) txid))
               (is (= 0 index))
               (is (= 50000000 (bl.store:utxo-entry-value utxo)))
               (is (= 100 (bl.store:utxo-entry-height utxo)))
               (is (bl.store:utxo-entry-coinbase utxo))
               (is (= 25 (length (bl.store:utxo-entry-script-pubkey utxo)))))
             ;; Verify second entry
             (destructuring-bind (txid index utxo) (second loaded)
               (is (equalp (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xBB) txid))
               (is (= 3 index))
               (is (= 1500000 (bl.store:utxo-entry-value utxo)))
               (is (= 200 (bl.store:utxo-entry-height utxo)))
               (is (not (bl.store:utxo-entry-coinbase utxo)))
               (is (= 34 (length (bl.store:utxo-entry-script-pubkey utxo)))))))
      ;; Cleanup
      (setf bl.val::*undo-base-path* nil)
      (uiop:delete-directory-tree base-path :validate t :if-does-not-exist :ignore))))

(test undo-data-cache-hit
  "Getting undo data should return from cache without disk access."
  (let* ((base-path (make-temp-directory))
         (block-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x43))
         (spent-utxos (make-sample-spent-utxos)))
    (unwind-protect
         (progn
           (bl.val:initialize-undo-storage base-path)
           (bl.val::store-undo-data block-hash spent-utxos 501)
           ;; Should hit cache (not disk)
           (let ((loaded (bl.val:get-undo-data block-hash)))
             (is (not (null loaded)))
             (is (= 2 (length loaded)))))
      (setf bl.val::*undo-base-path* nil)
      (uiop:delete-directory-tree base-path :validate t :if-does-not-exist :ignore))))

(test get-undo-data-disk-load-not-cached
  "A disk load via get-undo-data must NOT populate *block-undo-data*: the read
path does no height bookkeeping, so evict-undo-cache (which iterates
*undo-cache-heights*) could never evict such entries. The block filter
backfill read every spending block's undo this way and accumulated ~4.5 GiB
of permanently-live undo lists before exhausting a 6 GiB heap (testnet4,
2026-07-02)."
  (let* ((base-path (make-temp-directory))
         (block-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x45))
         (spent-utxos (make-sample-spent-utxos)))
    (unwind-protect
         (progn
           (bl.val:initialize-undo-storage base-path)
           (bl.val::store-undo-data block-hash spent-utxos 503)
           (clrhash bl.val::*block-undo-data*)
           (clrhash bl.val::*undo-cache-heights*)
           (let ((loaded (bl.val:get-undo-data block-hash)))
             (is (= 2 (length loaded))))
           (is (zerop (hash-table-count bl.val::*block-undo-data*)))
           (is (zerop (hash-table-count bl.val::*undo-cache-heights*))))
      (setf bl.val::*undo-base-path* nil)
      (uiop:delete-directory-tree base-path :validate t :if-does-not-exist :ignore))))

(test undo-data-crc-integrity
  "Corrupted undo data file should return NIL on load."
  (let* ((base-path (make-temp-directory))
         (block-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x44))
         (spent-utxos (make-sample-spent-utxos)))
    (unwind-protect
         (progn
           (bl.val:initialize-undo-storage base-path)
           (bl.val::store-undo-data block-hash spent-utxos 502)
           ;; Clear cache
           (clrhash bl.val::*block-undo-data*)
           (clrhash bl.val::*undo-cache-heights*)
           ;; Corrupt the file
           (let ((path (bl.val::undo-file-path block-hash)))
             (with-open-file (f path :direction :output
                                     :element-type '(unsigned-byte 8)
                                     :if-exists :overwrite)
               ;; Write garbage at offset 20
               (file-position f 20)
               (write-byte #xFF f)))
           ;; Load should fail (CRC mismatch)
           (let ((loaded (bl.val:get-undo-data block-hash)))
             (is (null loaded))))
      (setf bl.val::*undo-base-path* nil)
      (uiop:delete-directory-tree base-path :validate t :if-does-not-exist :ignore))))

(test undo-data-nonexistent-block
  "Getting undo data for unknown block should return NIL."
  (let ((base-path (make-temp-directory))
        (block-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xFF)))
    (unwind-protect
         (progn
           (bl.val:initialize-undo-storage base-path)
           (clrhash bl.val::*block-undo-data*)
           (is (null (bl.val:get-undo-data block-hash))))
      (setf bl.val::*undo-base-path* nil)
      (uiop:delete-directory-tree base-path :validate t :if-does-not-exist :ignore))))

(test undo-data-empty-list
  "Saving empty spent-utxos list should produce a valid file on disk."
  (let* ((base-path (make-temp-directory))
         (block-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x45)))
    (unwind-protect
         (progn
           (bl.val:initialize-undo-storage base-path)
           (bl.val::store-undo-data block-hash '() 503)
           ;; Verify the file was written
           (let ((path (bl.val::undo-file-path block-hash)))
             (is (not (null (probe-file path)))))
           ;; Cache should have the empty list
           (let ((cached (bl.val:get-undo-data block-hash)))
             ;; Empty list from cache is NIL (which is '()), this is correct
             (is (null cached))))
      (setf bl.val::*undo-base-path* nil)
      (uiop:delete-directory-tree base-path :validate t :if-does-not-exist :ignore))))

;;;; Taproot Activation Height Tests

(test p2sh-witness-taproot-are-on-for-every-block
  "Core sets P2SH|WITNESS|TAPROOT for EVERY block and overrides only for the
block hashes in script_flag_exceptions (GetBlockScriptFlags,
validation.cpp:2259). It does NOT gate them on activation height.

Gating them, as this node did until now, is a consensus divergence in the
permissive direction: below segwit activation a spend of a v0 witness program
with an empty scriptSig and no witness is WITNESS_PROGRAM_WITNESS_EMPTY to Core
and anyone-can-spend to a node with WITNESS off. The proof that Core means
always-on is its own comment at validation.cpp:2256-2257 — `For simplicity,
always leave P2SH+WITNESS+TAPROOT on except for the two violating blocks.'"
  (dolist (network '(:mainnet :testnet3 :testnet4 :signet :regtest))
    (let ((bl:*network* network))
      (dolist (height '(0 1 100 170060 692261 709631 709632 900000))
        (let ((flags (bl.val:block-script-flags-list nil height)))
          (dolist (always '("P2SH" "WITNESS" "TAPROOT"))
            (is-true (member always flags :test #'string=)
                     "~A missing at ~A height ~D: ~S" always network height flags)))))))

(test height-gated-flags-are-only-dersig-cltv-csv-nulldummy
  "The four Core actually gates on height (validation.cpp:2266-2285). Each must
be absent one block below its activation and present at it."
  (let ((bl:*network* :mainnet))
    (flet ((has (height flag)
             (and (member flag (bl.val:block-script-flags-list nil height)
                          :test #'string=)
                  t)))
      ;; mainnet: BIP66 363725, BIP65 388381, CSV 419328, segwit 481824
      (is-false (has 363724 "DERSIG"))
      (is-true  (has 363725 "DERSIG"))
      (is-false (has 388380 "CHECKLOCKTIMEVERIFY"))
      (is-true  (has 388381 "CHECKLOCKTIMEVERIFY"))
      (is-false (has 419327 "CHECKSEQUENCEVERIFY"))
      (is-true  (has 419328 "CHECKSEQUENCEVERIFY"))
      ;; BIP147 keys on the SEGWIT deployment, not one of its own.
      (is-false (has 481823 "NULLDUMMY"))
      (is-true  (has 481824 "NULLDUMMY")))))

(test script-flag-exception-replaces-the-base-set-and-keeps-the-height-gated-ones
  "Core does `flags = it->second' — the exception REPLACES the always-on set —
and then still ORs the height-gated flags on top (validation.cpp:2260-2285).
So the mainnet taproot exception block is verified with SIX flags, not the two
in its table entry: at height 692,261 DERSIG, CLTV, CSV and NULLDUMMY are all
long active. Substituting a bare \"P2SH,WITNESS\", as this node did, dropped
four consensus rules for that block."
  (let* ((bl:*network* :mainnet)
         (flags (bl.val:block-script-flags-list
                 bl.val::*taproot-exception-mainnet* 692261)))
    (is (equal '("CHECKLOCKTIMEVERIFY" "CHECKSEQUENCEVERIFY" "DERSIG"
                 "NULLDUMMY" "P2SH" "WITNESS")
               flags))
    (is-false (member "TAPROOT" flags :test #'string=)
              "the exception must disable TAPROOT and nothing else")))

(test bip16-exception-blocks-are-script-verify-none-not-skipped
  "Core maps both BIP16 exception blocks to SCRIPT_VERIFY_NONE
(kernel/chainparams.cpp:85-86 mainnet, :218-219 testnet3). NONE means run every
script with no flags — the scripts must still evaluate true. It does NOT mean
skip validation, which is what this node did: it returned success without
executing anything, accepting blocks Core rejects.

At their heights no deployment has activated, so nothing is ORed back on and
the flag set really is empty."
  ;; The table entry itself, independent of any height — each on its OWN chain,
  ;; because the table is per-chain consensus data.
  (dolist (pair (list (cons :mainnet bl.val::*bip16-exception-mainnet*)
                      (cons :testnet3 bl.val::*bip16-exception-testnet*)))
    (let ((bl:*network* (car pair)))
      (multiple-value-bind (flags found)
          (bl.val:script-flag-exception (cdr pair))
        (is-true found "~A did not recognise its own BIP16 exception" (car pair))
        (is (null flags) "the entry is SCRIPT_VERIFY_NONE"))))
  ;; And at the mainnet block's height (170,060) no deployment has activated,
  ;; so nothing is ORed back on and the effective set really is empty.
  (let ((bl:*network* :mainnet))
    (is (null (bl.val:block-script-flags-list
               bl.val::*bip16-exception-mainnet* 170060)))
    (is (string= "" (bl.val:block-script-flags
                     bl.val::*bip16-exception-mainnet* 170060)))))

(test the-exception-table-is-per-chain-consensus-data
  "script_flag_exceptions is a member of Consensus::Params (params.h:93) and is
populated per chain: mainnet emplaces two (chainparams.cpp:85,87, inside
CMainParams at :78), testnet3 one (:218, inside CTestNetParams at :211), and
CTestNet4Params (:320), SigNetParams (:433) and CRegTestParams (:559) emplace
NOTHING.

A network-blind lookup would hand a regtest or signet block an exemption its
own chain never granted — which on regtest is reachable by anyone who can mine,
since the hash is the only thing being matched."
  ;; Each chain sees only its own entries.
  (let ((bl:*network* :mainnet))
    (is-true (nth-value 1 (bl.val:script-flag-exception
                           bl.val::*bip16-exception-mainnet*)))
    (is-true (nth-value 1 (bl.val:script-flag-exception
                           bl.val::*taproot-exception-mainnet*)))
    ;; testnet3's entry is not mainnet's.
    (is-false (nth-value 1 (bl.val:script-flag-exception
                            bl.val::*bip16-exception-testnet*))))
  (let ((bl:*network* :testnet3))
    (is-true (nth-value 1 (bl.val:script-flag-exception
                           bl.val::*bip16-exception-testnet*)))
    (is-false (nth-value 1 (bl.val:script-flag-exception
                            bl.val::*taproot-exception-mainnet*))))
  ;; And the three chains with no table grant nothing to any hash.
  (dolist (network '(:testnet4 :signet :regtest))
    (let ((bl:*network* network))
      (dolist (hash (list bl.val::*bip16-exception-mainnet*
                          bl.val::*bip16-exception-testnet*
                          bl.val::*taproot-exception-mainnet*))
        (is-false (nth-value 1 (bl.val:script-flag-exception hash))
                  "~A has no exception table but granted one" network))))
  (let ((bl:*network* :mainnet))
    (multiple-value-bind (flags found)
        (bl.val:script-flag-exception
         (bl.crypto:hex-to-bytes
          "00000000000000000000000000000000000000000000000000000000deadbeef"))
      (is-false found "an unrelated hash must not be an exception")
      (is (null flags)))
    ;; Same height as the taproot exception, different block: full seven.
    (is (equal '("CHECKLOCKTIMEVERIFY" "CHECKSEQUENCEVERIFY" "DERSIG"
                 "NULLDUMMY" "P2SH" "TAPROOT" "WITNESS")
               (bl.val:block-script-flags-list nil 692261)))))

(test getdeploymentinfo-script-flags-is-an-array-even-when-empty
  "Core's GetScriptFlagNames returns an empty vector for SCRIPT_VERIFY_NONE
(interpreter.cpp:2200-2203) and blockchain.cpp:1530-1533 pushes it into a
UniValue::VARR, so the field is `[]', never null.

Making the always-on set exception-overridable is what made an EMPTY list
reachable here for the first time, and a bare NIL renders as JSON null
(see JSON-ARRAY, rpc/accessors.lisp:184)."
  (let* ((bl:*network* :mainnet)
         (empty (bl.val:block-script-flags-list
                 bl.val::*bip16-exception-mainnet* 170060)))
    (is (null empty))
    (is (equalp #() (bl.rpc:json-array empty)))
    (is (string= "[]" (with-output-to-string (s)
                        (yason:encode (bl.rpc:json-array empty) s))))))

(test taproot-flag-at-activation
  "TAPROOT flag should be present at activation height."
  (let ((bl:*network* :testnet3))
    (let ((flags (bl.val:compute-script-flags-for-height 2346882)))
      (is (not (null flags)))
      (is (search "TAPROOT" flags)))))

(test taproot-flag-above-activation
  "TAPROOT flag should be present above activation height."
  (let ((bl:*network* :mainnet))
    (let ((flags (bl.val:compute-script-flags-for-height 800000)))
      (is (not (null flags)))
      (is (search "TAPROOT" flags)))))

;;;; BIP 30 Duplicate TXID Check Tests

(test bip30-any-utxo-for-txid
  "any-utxo-for-txid-p should find existing UTXOs by txid."
  (let ((utxo-set (bl.store:make-utxo-set))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xDD))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    ;; Empty set
    (is (not (bl.store:any-utxo-for-txid-p utxo-set txid)))
    ;; Add a UTXO
    (bl.store:add-utxo utxo-set txid 0 50000000 script 100)
    ;; Should find it
    (is (bl.store:any-utxo-for-txid-p utxo-set txid))
    ;; Different txid should not be found
    (let ((other-txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xEE)))
      (is (not (bl.store:any-utxo-for-txid-p utxo-set other-txid))))))

(test bip30-multiple-outputs-same-txid
  "any-utxo-for-txid-p should find txid with multiple output indexes."
  (let ((utxo-set (bl.store:make-utxo-set))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xCC))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    ;; Add multiple outputs for same txid
    (bl.store:add-utxo utxo-set txid 0 50000000 script 100)
    (bl.store:add-utxo utxo-set txid 1 25000000 script 100)
    ;; Remove one
    (bl.store:remove-utxo utxo-set txid 0)
    ;; Should still find it (output 1 exists)
    (is (bl.store:any-utxo-for-txid-p utxo-set txid))
    ;; Remove the other
    (bl.store:remove-utxo utxo-set txid 1)
    ;; Now should not find it
    (is (not (bl.store:any-utxo-for-txid-p utxo-set txid)))))

;;;; Legacy Block Size Limit Tests

(test compact-size-length-values
  "compact-size-length should return correct byte lengths."
  (is (= 1 (bl.ser:compact-size-length 0)))
  (is (= 1 (bl.ser:compact-size-length 252)))
  (is (= 3 (bl.ser:compact-size-length 253)))
  (is (= 3 (bl.ser:compact-size-length 65535)))
  (is (= 5 (bl.ser:compact-size-length 65536)))
  (is (= 5 (bl.ser:compact-size-length #xFFFFFFFF)))
  (is (= 9 (bl.ser:compact-size-length #x100000000))))

;;;; Feefilter Message Tests (BIP 133)

(test feefilter-message-round-trip
  "Feefilter message should serialize and parse correctly."
  (let* ((fee-rate 12345)
         (msg (bl.ser:make-feefilter-message fee-rate))
         ;; Message = 24-byte header + 8-byte payload
         (payload (subseq msg 24)))
    (is (= fee-rate (bl.ser:parse-feefilter-payload payload)))))

(test feefilter-large-fee-rate
  "Feefilter should handle large fee rates."
  (let* ((fee-rate 100000000000)  ; 100 BTC/kB
         (msg (bl.ser:make-feefilter-message fee-rate))
         (payload (subseq msg 24)))
    (is (= fee-rate (bl.ser:parse-feefilter-payload payload)))))

(test feefilter-zero-rate
  "Feefilter with zero rate should round-trip."
  (let* ((msg (bl.ser:make-feefilter-message 0))
         (payload (subseq msg 24)))
    (is (= 0 (bl.ser:parse-feefilter-payload payload)))))

;;;; Sendheaders Message Tests (BIP 130)

(test sendheaders-message-format
  "Sendheaders message should have empty payload (24-byte header only)."
  (let ((msg (bl.ser:make-sendheaders-message)))
    ;; 24 bytes header, 0 bytes payload
    (is (= 24 (length msg)))))

;;;; Wtxidrelay Message Tests (BIP 339)

(test wtxidrelay-message-format
  "Wtxidrelay message should have empty payload (24-byte header only)."
  (let ((msg (bl.ser:make-wtxidrelay-message)))
    (is (= 24 (length msg)))))
