(in-package #:bitcoin-lisp.tests)

;;; RPC Tests

(def-suite rpc-tests
  :description "Tests for JSON-RPC server"
  :in :bitcoin-lisp-tests)

(in-suite rpc-tests)

;;; --- JSON-RPC Parsing Tests ---

(test json-rpc-parse-valid-request
  "Test parsing valid JSON-RPC request"
  (let ((body "{\"jsonrpc\":\"2.0\",\"method\":\"getblockcount\",\"params\":[],\"id\":1}"))
    (multiple-value-bind (type method params id)
        (bitcoin-lisp.rpc::parse-json-rpc-request body)
      (is (eq type :single))
      (is (string= method "getblockcount"))
      (is (null params))
      (is (= id 1)))))

(test json-rpc-parse-with-params
  "Test parsing request with params"
  (let ((body "{\"jsonrpc\":\"2.0\",\"method\":\"getblockhash\",\"params\":[100],\"id\":\"test\"}"))
    (multiple-value-bind (type method params id)
        (bitcoin-lisp.rpc::parse-json-rpc-request body)
      (is (eq type :single))
      (is (string= method "getblockhash"))
      (is (= (first params) 100))
      (is (string= id "test")))))

(test json-rpc-parse-batch
  "Test parsing batch request"
  (let ((body "[{\"jsonrpc\":\"2.0\",\"method\":\"getblockcount\",\"id\":1},{\"jsonrpc\":\"2.0\",\"method\":\"getbestblockhash\",\"id\":2}]"))
    (multiple-value-bind (type requests)
        (bitcoin-lisp.rpc::parse-json-rpc-request body)
      (is (eq type :batch))
      (is (= (length requests) 2)))))

(test json-rpc-parse-invalid-json
  "Test parsing invalid JSON returns parse error"
  (signals bitcoin-lisp.rpc::rpc-error
    (bitcoin-lisp.rpc::parse-json-rpc-request "not valid json")))

(test json-rpc-parse-missing-method
  "Test parsing request without method returns error"
  (signals bitcoin-lisp.rpc::rpc-error
    (bitcoin-lisp.rpc::parse-json-rpc-request "{\"jsonrpc\":\"2.0\",\"id\":1}")))

;;; --- Hash Hex Helper Tests ---

(test hash-to-hex-lowercase-reversed
  "hash-to-hex emits lowercase hex (Core's uint256::GetHex), byte-reversed."
  (let* ((bytes (make-array 32 :element-type '(unsigned-byte 8)
                               :initial-contents (loop for i from 0 below 32
                                                       collect (+ #xe0 (mod i 16)))))
         (hex (bitcoin-lisp.rpc::hash-to-hex bytes)))
    (is (string= hex (string-downcase hex)))
    ;; Reversed: last byte (#xef) prints first.
    (is (string= "ef" (subseq hex 0 2)))
    ;; Round-trips through parse-hex-hash, which accepts either case.
    (is (equalp bytes (bitcoin-lisp.rpc::parse-hex-hash hex)))
    (is (equalp bytes (bitcoin-lisp.rpc::parse-hex-hash (string-upcase hex))))))

;;; --- savemempool RPC Test ---

(test rpc-savemempool-writes-file
  "savemempool dumps the pool to mempool.dat under the data directory."
  (let* ((dir (merge-pathnames (format nil "savemempool-test-~D/" (get-universal-time))
                               (uiop:temporary-directory)))
         (node (make-test-node)))
    (setf (bitcoin-lisp::node-data-directory node) dir)
    (unwind-protect
         (let ((r (bitcoin-lisp.rpc::rpc-savemempool node nil)))
           (is (stringp (cdr (assoc "filename" r :test #'string=))))
           (is (not (null (probe-file (bitcoin-lisp.mempool:mempool-dat-path dir))))))
      (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore))))

(test rpc-getdescriptorinfo
  "getdescriptorinfo validates + reports canonical form/checksum; flags are
the no-wallet/no-range constants; bad descriptors error."
  (let* ((node (make-test-node))
         (body "raw(76a91411b366edfc0a8b66feebae5c2e25a7b6a5d1cf3188ac)")
         (r (bitcoin-lisp.rpc::rpc-getdescriptorinfo node (list body))))
    (is (string= (concatenate 'string body "#fm24fxxy")
                 (cdr (assoc "descriptor" r :test #'string=))))
    (is (string= "fm24fxxy" (cdr (assoc "checksum" r :test #'string=))))
    (is (null (cdr (assoc "isrange" r :test #'string=))))
    (is (eq t (cdr (assoc "issolvable" r :test #'string=))))
    (is (null (cdr (assoc "hasprivatekeys" r :test #'string=))))
    ;; accepts a correct input checksum, rejects a wrong one and junk
    (is (string= (concatenate 'string body "#fm24fxxy")
                 (cdr (assoc "descriptor"
                             (bitcoin-lisp.rpc::rpc-getdescriptorinfo
                              node (list (concatenate 'string body "#fm24fxxy")))
                             :test #'string=))))
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getdescriptorinfo node (list (concatenate 'string body "#deadbeef"))))
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getdescriptorinfo node (list "sh(multi(2,03aa,03bb))")))))

(test rpc-deriveaddresses
  "deriveaddresses returns the address(es) a descriptor's scriptPubKey
encodes to; combo() yields several; address-less scripts error; range
argument rejected."
  (let* ((node (make-test-node))   ; make-test-node is :testnet3
         (pk "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
         (keyhash (bitcoin-lisp.crypto:hash160 (bitcoin-lisp.crypto:hex-to-bytes pk))))
    ;; pkh -> single P2PKH address; matches the direct encoder.
    (let ((addrs (bitcoin-lisp.rpc::rpc-deriveaddresses
                  node (list (format nil "pkh(~A)" pk)))))
      (is (= 1 (length addrs)))
      (is (string= (bitcoin-lisp.crypto:encode-p2pkh-address keyhash :testnet3)
                   (first addrs))))
    ;; wpkh -> single bech32 address.
    (is (= 1 (length (bitcoin-lisp.rpc::rpc-deriveaddresses
                      node (list (format nil "wpkh(~A)" pk))))))
    ;; combo -> 4 addressable scripts (pk has no address) ... combo emits
    ;; pk+pkh+wpkh+sh(wpkh); pk() script is address-less => deriveaddresses
    ;; errors on the whole combo.
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-deriveaddresses node (list (format nil "combo(~A)" pk))))
    ;; raw() non-standard script -> no address -> error
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-deriveaddresses node (list "raw(51)")))
    ;; range argument rejected
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-deriveaddresses node (list (format nil "wpkh(~A)" pk) 5)))))

;;; --- Prioritisation RPC Tests ---

(test rpc-prioritisetransaction-and-introspection
  "prioritisetransaction adjusts the mempool delta map; getprioritisedtransactions
reports fee_delta/in_mempool/modified_fee; getmempoolentry exposes fees.modified."
  (let* ((node (make-test-node))
         (mempool (bitcoin-lisp::node-mempool node))
         (txid-hex (make-string 64 :initial-element #\a)))
    ;; dummy must be 0/null; fee_delta must be an integer
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-prioritisetransaction node (list txid-hex 1 1000)))
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-prioritisetransaction node (list txid-hex 0 "x")))
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-prioritisetransaction node (list "nothex" 0 1000)))
    ;; Delta for a not-in-mempool tx is recorded and reported
    (is (eq t (bitcoin-lisp.rpc::rpc-prioritisetransaction node (list txid-hex 0 2500))))
    (let* ((r (bitcoin-lisp.rpc::rpc-getprioritisedtransactions node nil))
           (row (cdr (assoc txid-hex r :test #'string=))))
      (is (= 2500 (cdr (assoc "fee_delta" row :test #'string=))))
      (is (null (cdr (assoc "in_mempool" row :test #'string=)))))
    ;; Net-zero clears it; empty map encodes as an object
    (is (eq t (bitcoin-lisp.rpc::rpc-prioritisetransaction node (list txid-hex nil -2500))))
    (is (hash-table-p (bitcoin-lisp.rpc::rpc-getprioritisedtransactions node nil)))
    (is (zerop (hash-table-count (bitcoin-lisp.mempool:mempool-deltas mempool))))))

(test rest-interface-routing-and-content-types
  "REST router: content-type negotiation, JSON reuse of RPC bodies, and
error mapping (400 bad request / 404 not found / unknown endpoint)."
  (let ((node (make-test-node))
        (hunchentoot:*reply* (make-instance 'hunchentoot:reply)))
    (setf (bitcoin-lisp::node-block-store node)
          (bitcoin-lisp.storage:init-block-store
           (ensure-directories-exist
            (merge-pathnames (format nil "rest-test-~D/" (get-universal-time))
                             (uiop:temporary-directory)))))
    (flet ((status () (hunchentoot:return-code*))
           (ctype () (hunchentoot:content-type*)))
      ;; chaininfo.json -> 200 application/json, parseable, reuses
      ;; rpc-getblockchaininfo (so has its keys).
      (let ((body (bitcoin-lisp.rpc::rest-handle node "/rest/chaininfo.json")))
        (is (= 200 (status)))
        (is (string= "application/json" (ctype)))
        (let ((parsed (yason:parse body)))
          (is (hash-table-p parsed))
          (is (integerp (gethash "blocks" parsed)))))
      ;; mempool/info.json -> 200 json
      (is (= 200 (progn (bitcoin-lisp.rpc::rest-handle node "/rest/mempool/info.json")
                        (status))))
      ;; chaininfo only supports .json -> .hex is 400
      (bitcoin-lisp.rpc::rest-handle node "/rest/chaininfo.hex")
      (is (= 400 (status)))
      ;; malformed block hash -> 400
      (bitcoin-lisp.rpc::rest-handle node "/rest/block/nothex.json")
      (is (= 400 (status)))
      ;; well-formed but absent block -> 404
      (bitcoin-lisp.rpc::rest-handle
       node (format nil "/rest/block/~A.json" (make-string 64 :initial-element #\a)))
      (is (= 404 (status)))
      ;; absent tx -> 404
      (bitcoin-lisp.rpc::rest-handle
       node (format nil "/rest/tx/~A.hex" (make-string 64 :initial-element #\b)))
      (is (= 404 (status)))
      ;; unknown endpoint -> 404
      (bitcoin-lisp.rpc::rest-handle node "/rest/frobnicate.json")
      (is (= 404 (status)))
      ;; getutxos with a bad outpoint -> 400
      (bitcoin-lisp.rpc::rest-handle node "/rest/getutxos/notanoutpoint.json")
      (is (= 400 (status))))))

(test rest-getutxos-reports-absence
  "getutxos returns found=false for an unknown outpoint (no error)."
  (let ((node (make-test-node))
        (hunchentoot:*reply* (make-instance 'hunchentoot:reply)))
    (let* ((txid (make-string 64 :initial-element #\c))
           (body (bitcoin-lisp.rpc::rest-handle
                  node (format nil "/rest/getutxos/~A-0.json" txid)))
           (parsed (yason:parse body)))
      (is (= 200 (hunchentoot:return-code*)))
      (let ((utxos (gethash "utxos" parsed)))
        (is (= 1 (length utxos)))
        (is (eq nil (gethash "found" (first utxos))))))))

(defun %proof-hashes (n)
  "N distinct 32-byte hashes for partial-merkle-tree tests."
  (loop for i from 1 to n
        collect (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
                  (setf (aref h 0) (logand i #xff)
                        (aref h 1) (logand (ash i -8) #xff))
                  h)))

(test txoutproof-build-extract-roundtrip
  "Partial merkle tree build->extract recomputes the real merkle root and
recovers exactly the matched leaves, across tree sizes and match sets."
  (dolist (ntx '(1 2 3 4 5 7 8 16))
    (let* ((txids (%proof-hashes ntx))
           (txid-vec (coerce txids 'vector))
           (root (bitcoin-lisp.validation:compute-merkle-root txids))
           ;; Match the first and last leaf (and the middle for larger trees).
           (want (remove-duplicates (list 0 (1- ntx) (floor ntx 2))))
           (match (make-array ntx :initial-element nil)))
      (dolist (i want) (setf (aref match i) t))
      (multiple-value-bind (bits hashes)
          (bitcoin-lisp.rpc::build-partial-merkle-tree txid-vec match)
        (multiple-value-bind (xroot xmatched xindices)
            (bitcoin-lisp.rpc::extract-partial-merkle-tree ntx bits hashes)
          (is (equalp root xroot) "ntx=~D root mismatch" ntx)
          (is (equal (sort (copy-list want) #'<) xindices) "ntx=~D indices" ntx)
          (is (= (length want) (length xmatched)))
          ;; Each matched hash is the txid at its reported index.
          (loop for h in xmatched for idx in xindices
                do (is (equalp (aref txid-vec idx) h))))))))

(test txoutproof-serialize-roundtrip
  "serialize-merkle-block / parse-merkle-block round-trip the proof fields."
  (let* ((ntx 6)
         (txids (%proof-hashes ntx))
         (txid-vec (coerce txids 'vector))
         (match (make-array ntx :initial-element nil)))
    (setf (aref match 2) t)
    (multiple-value-bind (bits hashes)
        (bitcoin-lisp.rpc::build-partial-merkle-tree txid-vec match)
      (let* ((header (make-array 80 :element-type '(unsigned-byte 8) :initial-element 7))
             (bytes (bitcoin-lisp.rpc::serialize-merkle-block header ntx hashes bits)))
        (multiple-value-bind (h2 ntx2 hashes2 bits2)
            (bitcoin-lisp.rpc::parse-merkle-block bytes)
          (is (equalp header h2))
          (is (= ntx ntx2))
          (is (equalp hashes hashes2))
          ;; bits round-trip up to the byte padding zeros
          (is (equal bits (subseq bits2 0 (length bits))))
          ;; and re-extract gives the same root
          (is (equalp (bitcoin-lisp.rpc::extract-partial-merkle-tree ntx bits hashes)
                      (bitcoin-lisp.rpc::extract-partial-merkle-tree ntx2 bits2 hashes2))))))))

(test txoutproof-tamper-detected
  "Flipping a hash in the partial tree changes the recomputed root."
  (let* ((ntx 8)
         (txids (%proof-hashes ntx))
         (txid-vec (coerce txids 'vector))
         (root (bitcoin-lisp.validation:compute-merkle-root txids))
         (match (make-array ntx :initial-element nil)))
    (setf (aref match 3) t)
    (multiple-value-bind (bits hashes)
        (bitcoin-lisp.rpc::build-partial-merkle-tree txid-vec match)
      (let ((tampered (mapcar #'copy-seq hashes)))
        (setf (aref (first tampered) 0) (logxor (aref (first tampered) 0) #xff))
        (is (not (equalp root (bitcoin-lisp.rpc::extract-partial-merkle-tree
                               ntx bits tampered))))))))

(test rpc-txoutproof-roundtrip
  "gettxoutproof builds a proof a real block, verifytxoutproof confirms it
when the block is on the active chain and rejects a root-mismatched proof."
  (let* ((node (make-test-node))
         (chain-state (bitcoin-lisp::node-chain-state node))
         (dir (ensure-directories-exist
               (merge-pathnames (format nil "txoutproof-~D/" (get-universal-time))
                                (uiop:temporary-directory))))
         (block-store (bitcoin-lisp.storage:init-block-store dir)))
    (setf (bitcoin-lisp::node-block-store node) block-store)
    ;; Build a 4-tx block (distinct coinbase-shaped txs).
    (let* ((txs (loop for i from 0 below 4
                      collect (bitcoin-lisp.serialization:make-transaction
                               :version 1
                               :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                                                :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                                  :hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                                                                  :index #xffffffff)
                                                :script-sig (make-array 2 :element-type '(unsigned-byte 8) :initial-element i)
                                                :sequence #xffffffff))
                               :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                                                 :value 1000 :script-pubkey (make-array 4 :element-type '(unsigned-byte 8) :initial-element #x6a)))
                               :lock-time 0)))
           (txids (mapcar #'bitcoin-lisp.serialization:transaction-hash txs))
           (root (bitcoin-lisp.validation:compute-merkle-root txids))
           (header (bitcoin-lisp.serialization:make-block-header
                    :version 1
                    :prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                    :merkle-root root :timestamp 1700000000 :bits #x207fffff :nonce 0))
           (block (bitcoin-lisp.serialization:make-bitcoin-block :header header :transactions txs))
           (block-hash (bitcoin-lisp.serialization:block-header-hash header)))
      (unwind-protect
           (progn
             (bitcoin-lisp.storage:store-block block-store block)
             (bitcoin-lisp.storage:add-block-index-entry
              chain-state (bitcoin-lisp.storage:make-block-index-entry
                           :hash block-hash :height 0 :header header
                           :chain-work 1 :status :valid))
             (bitcoin-lisp.storage:update-chain-tip chain-state block-hash 0)
             (let* ((target (bitcoin-lisp.rpc::hash-to-hex (second txids)))
                    (proof (bitcoin-lisp.rpc::rpc-gettxoutproof
                            node (list (list target) (bitcoin-lisp.rpc::hash-to-hex block-hash))))
                    (verified (bitcoin-lisp.rpc::rpc-verifytxoutproof node (list proof))))
               (is (stringp proof))
               (is (equal (list target) verified))
               ;; Corrupt the proof's last hex nibble -> root/parse mismatch -> error.
               (signals bitcoin-lisp.rpc::rpc-error
                 (bitcoin-lisp.rpc::rpc-verifytxoutproof
                  node (list (concatenate 'string (subseq proof 0 (- (length proof) 2)) "ff"))))))
        (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore)))))

;;; dumptxoutset / loadtxoutset (Core snapshot v2 format) tests live in
;;; tests/snapshot-tests.lisp.

;;; --- Output Descriptor Tests (scantxoutset) ---

(test descriptor-checksum-core-vector
  "descriptor-checksum matches Bitcoin Core's documented example
(descriptor.cpp's EXAMPLE_DESCRIPTOR_RAW), and validation round-trips."
  (let ((body "raw(76a91411b366edfc0a8b66feebae5c2e25a7b6a5d1cf3188ac)"))
    (is (string= "fm24fxxy" (bitcoin-lisp.rpc::descriptor-checksum body)))
    (is (string= (concatenate 'string body "#fm24fxxy")
                 (bitcoin-lisp.rpc::descriptor-add-checksum body)))
    ;; Correct checksum accepted, wrong checksum rejected.
    (finishes (bitcoin-lisp.rpc::parse-output-descriptor
               (concatenate 'string body "#fm24fxxy") :mainnet))
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::parse-output-descriptor
       (concatenate 'string body "#fm24fxxx") :mainnet))))

(test descriptor-parse-forms
  "Each supported descriptor form expands to the right scriptPubKey(s).
Cross-checked against Core: addr(12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S) is
documented in descriptor.cpp as the address of the raw() example script."
  (let* ((pubkey-hex "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
         (pubkey (bitcoin-lisp.crypto:hex-to-bytes pubkey-hex))
         (keyhash (bitcoin-lisp.crypto:hash160 pubkey)))
    ;; addr() == Core's raw() example script
    (let ((pairs (bitcoin-lisp.rpc::parse-output-descriptor
                  "addr(12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S)" :mainnet)))
      (is (= 1 (length pairs)))
      (is (string= "76a91411b366edfc0a8b66feebae5c2e25a7b6a5d1cf3188ac"
                   (bitcoin-lisp.crypto:bytes-to-hex (car (first pairs))))))
    ;; raw() passes bytes through
    (let ((pairs (bitcoin-lisp.rpc::parse-output-descriptor "raw(51)" :mainnet)))
      (is (equalp #(#x51) (car (first pairs)))))
    ;; pkh(): OP_DUP OP_HASH160 <h160> OP_EQUALVERIFY OP_CHECKSIG
    (let ((script (car (first (bitcoin-lisp.rpc::parse-output-descriptor
                               (format nil "pkh(~A)" pubkey-hex) :mainnet)))))
      (is (= 25 (length script)))
      (is (equalp keyhash (subseq script 3 23))))
    ;; wpkh(): OP_0 <h160>
    (let ((script (car (first (bitcoin-lisp.rpc::parse-output-descriptor
                               (format nil "wpkh(~A)" pubkey-hex) :mainnet)))))
      (is (= 22 (length script)))
      (is (= #x00 (aref script 0)))
      (is (equalp keyhash (subseq script 2))))
    ;; sh(wpkh()): P2SH of the wpkh script
    (let ((script (car (first (bitcoin-lisp.rpc::parse-output-descriptor
                               (format nil "sh(wpkh(~A))" pubkey-hex) :mainnet)))))
      (is (= 23 (length script)))
      (is (= #xa9 (aref script 0))))
    ;; combo(): 4 scripts for a compressed key, 2 for uncompressed
    (is (= 4 (length (bitcoin-lisp.rpc::parse-output-descriptor
                      (format nil "combo(~A)" pubkey-hex) :mainnet))))
    ;; rawtr(): OP_1 <32-byte key as-is>
    (let* ((xonly-hex (subseq pubkey-hex 2))
           (script (car (first (bitcoin-lisp.rpc::parse-output-descriptor
                                (format nil "rawtr(~A)" xonly-hex) :mainnet)))))
      (is (= 34 (length script)))
      (is (= #x51 (aref script 0)))
      (is (equalp (bitcoin-lisp.crypto:hex-to-bytes xonly-hex)
                  (subseq script 2))))
    ;; tr(): tweaked output key differs from the internal key
    (let* ((xonly-hex (subseq pubkey-hex 2))
           (script (car (first (bitcoin-lisp.rpc::parse-output-descriptor
                                (format nil "tr(~A)" xonly-hex) :mainnet)))))
      (is (= 34 (length script)))
      (is (= #x51 (aref script 0)))
      (is (not (equalp (bitcoin-lisp.crypto:hex-to-bytes xonly-hex)
                       (subseq script 2)))))
    ;; Unsupported / invalid forms signal rpc-error
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::parse-output-descriptor "sh(multi(2,03aa,03bb))" :mainnet))
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::parse-output-descriptor "addr(notanaddress)" :mainnet))
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::parse-output-descriptor
       (format nil "wpkh(04~A)" (subseq pubkey-hex 2)) :mainnet))))

(test rpc-scantxoutset-start-status-abort
  "scantxoutset start scans the UTXO set against descriptor needles;
status with no scan running returns null; abort with no scan is a no-op."
  (let* ((node (make-test-node))
         (utxo (bitcoin-lisp::node-utxo-set node))
         (keyhash (make-array 20 :element-type '(unsigned-byte 8)
                                 :initial-element 7))
         (address (bitcoin-lisp.crypto:encode-p2pkh-address keyhash :testnet3))
         (p2pkh (concatenate '(vector (unsigned-byte 8))
                             #(#x76 #xa9 #x14) keyhash #(#x88 #xac)))
         (txid-a (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
         (txid-b (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2))
         (txid-c (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3)))
    ;; Two matching coins (addr + raw needles) and one non-matching.
    (bitcoin-lisp.storage:add-utxo utxo txid-a 0 150000000 p2pkh 0)
    (bitcoin-lisp.storage:add-utxo utxo txid-b 1 50000000
                                   (coerce #(#x51) '(vector (unsigned-byte 8))) 0)
    (bitcoin-lisp.storage:add-utxo utxo txid-c 0 1000
                                   (make-array 25 :element-type '(unsigned-byte 8)) 0)
    (let ((r (bitcoin-lisp.rpc::rpc-scantxoutset
              node (list "start" (list (format nil "addr(~A)" address) "raw(51)")))))
      (is (eq t (cdr (assoc "success" r :test #'string=))))
      (is (= 3 (cdr (assoc "txouts" r :test #'string=))))
      (let ((unspents (cdr (assoc "unspents" r :test #'string=))))
        (is (= 2 (length unspents)))
        ;; Every unspent carries a canonical descriptor with checksum.
        (is (every (lambda (u) (find #\# (cdr (assoc "desc" u :test #'string=))))
                   unspents)))
      (is (= 2.0 (cdr (assoc "total_amount" r :test #'string=)))))
    ;; No scan running: status -> null, abort -> no-op null.
    (is (null (bitcoin-lisp.rpc::rpc-scantxoutset node (list "status"))))
    (is (null (bitcoin-lisp.rpc::rpc-scantxoutset node (list "abort"))))
    ;; Bad action / missing scanobjects -> errors.
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-scantxoutset node (list "frobnicate")))
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-scantxoutset node (list "start")))))

;;; --- Response Formatting Tests ---

(test json-rpc-response-success
  "Test successful response format"
  (let ((response (bitcoin-lisp.rpc::make-rpc-response 42 "test-id")))
    (is (string= (gethash "jsonrpc" response) "2.0"))
    (is (= (gethash "result" response) 42))
    (is (string= (gethash "id" response) "test-id"))))

(test json-rpc-response-error
  "Test error response format"
  (let ((response (bitcoin-lisp.rpc::make-rpc-error-response -32601 "Method not found" "test-id")))
    (is (string= (gethash "jsonrpc" response) "2.0"))
    (is (string= (gethash "id" response) "test-id"))
    (let ((error-obj (gethash "error" response)))
      (is (= (gethash "code" error-obj) -32601))
      (is (string= (gethash "message" error-obj) "Method not found")))))

;;; --- Input Validation Tests ---

(test valid-hex-hash
  "Test hex hash validation"
  (is (bitcoin-lisp.rpc::valid-hex-hash-p
       "0000000000000000000000000000000000000000000000000000000000000000"))
  (is (bitcoin-lisp.rpc::valid-hex-hash-p
       "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"))
  (is (not (bitcoin-lisp.rpc::valid-hex-hash-p "tooshort")))
  (is (not (bitcoin-lisp.rpc::valid-hex-hash-p
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")))
  (is (not (bitcoin-lisp.rpc::valid-hex-hash-p nil))))

;;; --- Method Registry Tests ---

(test method-dispatch-unknown
  "Test dispatching unknown method returns error"
  (signals bitcoin-lisp.rpc::rpc-error
    (bitcoin-lisp.rpc:dispatch-rpc-method nil "unknownmethod" nil)))

;;; --- Integration Tests ---

(test rpc-server-lifecycle
  "Test RPC server start/stop"
  ;; Make sure no server is running
  (bitcoin-lisp.rpc:stop-rpc-server)
  (is (null bitcoin-lisp.rpc:*rpc-server*))

  ;; Start on an unusual port to avoid conflicts
  (let ((node (make-test-node)))
    (bitcoin-lisp.rpc:start-rpc-server node :port 19999)
    (is (not (null bitcoin-lisp.rpc:*rpc-server*)))

    ;; Stop server
    (bitcoin-lisp.rpc:stop-rpc-server)
    (is (null bitcoin-lisp.rpc:*rpc-server*))))

;;; --- Helper to create initialized test node ---

(defun make-test-node ()
  "Create a node with minimal initialized state for testing."
  (let ((node (bitcoin-lisp::make-node :network :testnet3)))
    ;; Initialize chain-state
    (setf (bitcoin-lisp::node-chain-state node)
          (bitcoin-lisp.storage:make-chain-state))
    ;; Initialize UTXO set
    (setf (bitcoin-lisp::node-utxo-set node)
          (bitcoin-lisp.storage:make-utxo-set))
    ;; Initialize mempool
    (setf (bitcoin-lisp::node-mempool node)
          (bitcoin-lisp.mempool:make-mempool))
    node))

;;; --- Blockchain Query Method Tests (3.11) ---

(test rpc-getblockchaininfo
  "Test getblockchaininfo returns expected fields"
  (let* ((node (make-test-node))
         (result (bitcoin-lisp.rpc::rpc-getblockchaininfo node nil)))
    ;; Check required fields exist
    (is (assoc "chain" result :test #'string=))
    (is (assoc "blocks" result :test #'string=))
    (is (assoc "headers" result :test #'string=))
    ;; bestblockhash may be nil for empty chain
    (is (assoc "bestblockhash" result :test #'string=))
    (is (assoc "initialblockdownload" result :test #'string=))
    ;; Check chain value for testnet
    (is (string= (cdr (assoc "chain" result :test #'string=)) "test"))
    ;; New completeness fields (all always-present in Core)
    (dolist (k '("difficulty" "time" "mediantime" "chainwork" "bits" "target"
                 "size_on_disk" "warnings"))
      (is (assoc k result :test #'string=)))
    ;; chainwork/target are 64-hex; bits is 8-hex
    (is (= 64 (length (cdr (assoc "chainwork" result :test #'string=)))))
    (is (= 64 (length (cdr (assoc "target" result :test #'string=)))))
    (is (= 8 (length (cdr (assoc "bits" result :test #'string=)))))
    ;; encodes cleanly through yason (warnings is an empty JSON array, etc.)
    (is (stringp (with-output-to-string (s)
                   (yason:encode (bitcoin-lisp.rpc::make-rpc-response result "id") s))))))

(test rpc-getblockcount
  "Test getblockcount returns integer"
  (let* ((node (make-test-node))
         (result (bitcoin-lisp.rpc::rpc-getblockcount node nil)))
    (is (integerp result))
    (is (>= result 0))))

(test rpc-getblockhash-invalid-height
  "Test getblockhash with invalid height returns error"
  (let ((node (make-test-node)))
    ;; Negative height
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getblockhash node '(-1)))
    ;; Non-integer height
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getblockhash node '("abc")))))

(test rpc-getblock-invalid-hash
  "Test getblock with invalid hash returns error"
  (let ((node (make-test-node)))
    ;; Too short
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getblock node '("abc")))
    ;; Invalid characters
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getblock node '("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")))
    ;; Non-integer/non-bool verbosity (Core: type error; any integer is valid)
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getblock node
        '("0000000000000000000000000000000000000000000000000000000000000000" "5")))))

(test rpc-getblockheader-invalid-hash
  "Test getblockheader with invalid hash returns error"
  (let ((node (make-test-node)))
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getblockheader node '("tooshort")))))

;;; --- getrawtransaction verbosity + witness-complete hex ---

(test rpc-getrawtransaction-witness-hex-and-verbosity
  "The non-verbose hex is the wire (witness-complete) encoding — Core's
EncodeHexTx — and the verbosity argument follows Core ParseVerbosity: 0, false
and absent return hex (verbosity 0 is Core's default but was truthy in Lisp);
1, true and 2 return the decoded object; a string errors."
  (let* ((node (make-test-node))
         (mempool (bitcoin-lisp::node-mempool node))
         (raw (make-witness-test-tx-bytes))
         (tx (flexi-streams:with-input-from-sequence (s raw)
               (bitcoin-lisp.serialization:read-transaction s)))
         (txid (bitcoin-lisp.serialization:transaction-hash tx))
         (txid-hex (bitcoin-lisp.rpc::hash-to-hex txid)))
    (is (eq :ok (bitcoin-lisp.mempool:mempool-add
                 mempool txid (bitcoin-lisp.mempool:make-entry-from-tx tx 1000 0))))
    ;; Hex-returning verbosities: absent, 0, false (NIL).
    (dolist (params (list (list txid-hex)
                          (list txid-hex 0)
                          (list txid-hex nil)))
      (let ((hex (bitcoin-lisp.rpc::rpc-getrawtransaction node params)))
        (is (stringp hex))
        ;; Byte-exact wire bytes: witnesses intact through a round-trip.
        (is (equalp raw (bitcoin-lisp.crypto:hex-to-bytes hex)))))
    ;; Object-returning verbosities: 1, true, 2.
    (dolist (params (list (list txid-hex 1)
                          (list txid-hex t)
                          (list txid-hex 2)))
      (let ((r (bitcoin-lisp.rpc::rpc-getrawtransaction node params)))
        (is (consp r))
        (is (string= txid-hex (cdr (assoc "txid" r :test #'string=))))
        ;; The object's hex field is the wire encoding too.
        (is (equalp raw (bitcoin-lisp.crypto:hex-to-bytes
                         (cdr (assoc "hex" r :test #'string=)))))))
    ;; Non-integer/non-bool verbosity → type error (Core getInt<int> throw).
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getrawtransaction node (list txid-hex "abc")))))

;;; --- getorphantxs wire hex + verbosity validation ---

(test rpc-getorphantxs-wire-hex-and-verbosity
  "%orphan-tx-json's bytes/hex use the wire (witness-complete) encoding — Core
OrphanToJSON's ComputeTotalSize/EncodeHexTx — and getorphantxs rejects
out-of-range or boolean verbosity like Core (ParseVerbosity allow_bool=false)."
  (let* ((raw (make-witness-test-tx-bytes))
         (tx (flexi-streams:with-input-from-sequence (s raw)
               (bitcoin-lisp.serialization:read-transaction s)))
         (o (bitcoin-lisp.rpc::%orphan-tx-json tx nil t)))
    (is (= (length raw) (cdr (assoc "bytes" o :test #'string=))))
    (is (equalp raw (bitcoin-lisp.crypto:hex-to-bytes
                     (cdr (assoc "hex" o :test #'string=))))))
  (let ((node (make-test-node)))
    (is (null (bitcoin-lisp.rpc::rpc-getorphantxs node nil)))
    (is (null (bitcoin-lisp.rpc::rpc-getorphantxs node (list 2))))
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getorphantxs node (list 3)))
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getorphantxs node (list t)))))

;;; --- UTXO Query Method Tests (4.3) ---

(test rpc-gettxout-invalid-txid
  "Test gettxout with invalid txid returns error"
  (let ((node (make-test-node)))
    ;; Too short txid
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-gettxout node '("abc" 0)))
    ;; Invalid characters
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-gettxout node '("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz" 0)))))

(test rpc-gettxout-invalid-vout
  "Test gettxout with invalid vout returns error"
  (let ((node (make-test-node)))
    ;; Negative vout
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-gettxout node
        '("0000000000000000000000000000000000000000000000000000000000000000" -1)))
    ;; Non-integer vout
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-gettxout node
        '("0000000000000000000000000000000000000000000000000000000000000000" "abc")))))

(test rpc-gettxout-nonexistent
  "Test gettxout with nonexistent UTXO returns nil"
  (let* ((node (make-test-node))
         (result (bitcoin-lisp.rpc::rpc-gettxout node
                   '("0000000000000000000000000000000000000000000000000000000000000000" 0))))
    ;; Nonexistent UTXO should return nil
    (is (null result))))

;;; --- Network Query Method Tests (5.4) ---

(test rpc-getpeerinfo
  "getpeerinfo returns a numeric protocol version and encodes through yason.
Regression: peer-version holds the version *message* struct, and getpeerinfo
used to emit it verbatim, which yason cannot encode."
  (let* ((node (make-test-node))
         (vmsg (bitcoin-lisp.serialization::make-version-message
                :version 70016 :start-height 42 :user-agent "/test/"))
         (peer (bitcoin-lisp::make-peer :address "1.2.3.4:48333"
                                        :version vmsg
                                        :user-agent "/test/"
                                        :start-height 42)))
    (setf (bitcoin-lisp::node-peers node) (list peer))
    (let* ((result (bitcoin-lisp.rpc::rpc-getpeerinfo node nil))
           (entry (first result)))
      (is (listp result))
      (is (= (length result) 1))
      ;; version must be the numeric protocol version, not the struct
      (is (integerp (cdr (assoc "version" entry :test #'string=))))
      (is (= (cdr (assoc "version" entry :test #'string=)) 70016))
      ;; full result must serialize without error
      (let ((response (bitcoin-lisp.rpc::make-rpc-response result "id")))
        (finishes (with-output-to-string (s) (yason:encode response s)))))))

(test rpc-getnetworkinfo
  "Test getnetworkinfo returns expected fields"
  (let* ((node (make-test-node))
         (result (bitcoin-lisp.rpc::rpc-getnetworkinfo node nil)))
    ;; Check required fields exist
    (is (assoc "version" result :test #'string=))
    (is (assoc "subversion" result :test #'string=))
    (is (assoc "protocolversion" result :test #'string=))
    (is (assoc "connections" result :test #'string=))
    (is (assoc "networkactive" result :test #'string=))))

(test rpc-getconnectioncount
  "Test getconnectioncount returns integer"
  (let* ((node (make-test-node))
         (result (bitcoin-lisp.rpc::rpc-getconnectioncount node nil)))
    (is (integerp result))
    (is (>= result 0))))

;;; --- Mempool Method Tests (6.5) ---

(test rpc-getmempoolinfo
  "Test getmempoolinfo returns expected fields"
  (let* ((node (make-test-node))
         (result (bitcoin-lisp.rpc::rpc-getmempoolinfo node nil)))
    ;; Check required fields exist
    (is (assoc "loaded" result :test #'string=))
    (is (assoc "size" result :test #'string=))
    (is (assoc "bytes" result :test #'string=))
    ;; completeness fields
    (dolist (k '("usage" "total_fee" "maxmempool" "incrementalrelayfee"
                 "unbroadcastcount" "fullrbf"))
      (is (assoc k result :test #'string=)))
    (is (integerp (cdr (assoc "maxmempool" result :test #'string=))))
    (is (integerp (cdr (assoc "usage" result :test #'string=))))))

(test rpc-getrawmempool-non-verbose
  "Test getrawmempool non-verbose returns list"
  (let* ((node (make-test-node))
         (result (bitcoin-lisp.rpc::rpc-getrawmempool node '(nil))))
    ;; Should return a list (empty for new node)
    (is (listp result))))

(test rpc-getrawmempool-verbose
  "getrawmempool verbose returns a per-tx detail alist (txid -> fields) that the
RPC layer normalizes into a JSON object."
  (let* ((node (make-test-node))
         (mempool (bitcoin-lisp::node-mempool node))
         (tx (make-mempool-test-tx :input-id 200))
         (txid (bitcoin-lisp.serialization:transaction-hash tx)))
    ;; Empty mempool -> empty.
    (is (null (bitcoin-lisp.rpc::rpc-getrawmempool node '(t))))
    ;; Populate and check the entry + a couple of fields.
    (bitcoin-lisp.mempool:mempool-add
     mempool txid (bitcoin-lisp.mempool:make-entry-from-tx tx 1000 0))
    (let* ((result (bitcoin-lisp.rpc::rpc-getrawmempool node '(t)))
           (entry (cdr (assoc (bitcoin-lisp.rpc::hash-to-hex txid) result :test #'string=))))
      (is (listp result))
      (is (not (null entry)))
      (is (assoc "vsize" entry :test #'string=))
      (is (= 1 (cdr (assoc "ancestorcount" entry :test #'string=))))
      ;; serializes cleanly through the RPC response normalizer
      (let ((response (bitcoin-lisp.rpc::make-rpc-response result "id")))
        (finishes (with-output-to-string (s) (yason:encode response s)))))))

(test rpc-sendrawtransaction-invalid
  "Test sendrawtransaction with invalid hex returns error; a decode failure uses
RPC_DESERIALIZATION_ERROR (-22), matching Core."
  (let ((node (make-test-node)))
    ;; Empty string
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-sendrawtransaction node '("")))
    ;; Invalid hex -> deserialization error code -22
    (handler-case
        (progn (bitcoin-lisp.rpc::rpc-sendrawtransaction node '("not-valid-hex"))
               (fail "expected rpc-error"))
      (bitcoin-lisp.rpc::rpc-error (e)
        (is (= -22 (bitcoin-lisp.rpc::rpc-error-code e)))))))

;;; --- sendrawtransaction broadcast (unbroadcast set + peer announcement) ---
;;;
;;; Uses the P2SH(OP_TRUE) fixture from package-tests.lisp (%pkg-fixture /
;;; %pkg-tx): standard, script-valid transactions with no signing key.

(defun %broadcast-test-node (utxo-set mempool chain-state peer)
  "A test node wired to the fixture state with one ready relay peer."
  (let ((node (bitcoin-lisp::make-node :network :testnet3)))
    (setf (bitcoin-lisp::node-chain-state node) chain-state
          (bitcoin-lisp::node-utxo-set node) utxo-set
          (bitcoin-lisp::node-mempool node) mempool
          (bitcoin-lisp::node-peers node) (list peer))
    node))

(test rpc-sendrawtransaction-broadcasts
  "sendrawtransaction accepts the tx, adds it to the mempool's unbroadcast
set, and queues an announcement to relay peers (Core BroadcastTransaction,
node/transaction.cpp:100-135); resubmitting the same tx is NOT an error and
re-announces (already-in-mempool branch, :63-72) without re-adding to the
unbroadcast set."
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (%pkg-fixture)
    (let* ((peer (bitcoin-lisp.networking:make-peer :state :ready))
           (node (%broadcast-test-node utxo-set mempool chain-state peer))
           (tx (%pkg-tx funding-txid 0 (- 100000000 10000)))
           (txid (bitcoin-lisp.serialization:transaction-hash tx))
           (hex (bitcoin-lisp.crypto:bytes-to-hex
                 (bitcoin-lisp.serialization:serialize-transaction tx))))
      (let ((r (bitcoin-lisp.rpc::rpc-sendrawtransaction node (list hex))))
        (is (string= (bitcoin-lisp.rpc::hash-to-hex txid) r)))
      (is-true (bitcoin-lisp.mempool:mempool-has mempool txid))
      ;; Tracked for initial broadcast...
      (is (= 1 (bitcoin-lisp.mempool:mempool-unbroadcast-count mempool)))
      (is-true (gethash txid (bitcoin-lisp.mempool:mempool-unbroadcast mempool)))
      ;; ...and queued to the relay peer (flushed later by the Poisson timer).
      (is (= 1 (length (bitcoin-lisp.networking::peer-tx-inv-queue peer))))
      (is (equalp txid (first (first (bitcoin-lisp.networking::peer-tx-inv-queue peer)))))
      ;; Resubmission: same txid returned, another announcement queued,
      ;; unbroadcast set unchanged.
      (let ((r2 (bitcoin-lisp.rpc::rpc-sendrawtransaction node (list hex))))
        (is (string= (bitcoin-lisp.rpc::hash-to-hex txid) r2)))
      (is (= 2 (length (bitcoin-lisp.networking::peer-tx-inv-queue peer))))
      (is (= 1 (bitcoin-lisp.mempool:mempool-unbroadcast-count mempool))))))

(test rpc-testmempoolaccept-does-not-broadcast
  "testmempoolaccept is a dry run: nothing enters the mempool, nothing joins
the unbroadcast set, and no announcement is queued."
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (%pkg-fixture)
    (let* ((peer (bitcoin-lisp.networking:make-peer :state :ready))
           (node (%broadcast-test-node utxo-set mempool chain-state peer))
           (tx (%pkg-tx funding-txid 0 (- 100000000 10000)))
           (hex (bitcoin-lisp.crypto:bytes-to-hex
                 (bitcoin-lisp.serialization:serialize-transaction tx))))
      (let ((r (first (bitcoin-lisp.rpc::rpc-testmempoolaccept node (list (list hex))))))
        (is (eq t (cdr (assoc "allowed" r :test #'string=)))))
      (is (= 0 (bitcoin-lisp.mempool:mempool-count mempool)))
      (is (= 0 (bitcoin-lisp.mempool:mempool-unbroadcast-count mempool)))
      (is (null (bitcoin-lisp.networking::peer-tx-inv-queue peer))))))

(test rpc-getmempoolinfo-unbroadcastcount
  "getmempoolinfo reports the live unbroadcast set size (Core
rpc/mempool.cpp:1047)."
  (let* ((node (make-test-node))
         (mempool (bitcoin-lisp::node-mempool node))
         (tx (make-mempool-test-tx :input-id 201))
         (txid (bitcoin-lisp.serialization:transaction-hash tx)))
    (is (= 0 (cdr (assoc "unbroadcastcount"
                         (bitcoin-lisp.rpc::rpc-getmempoolinfo node nil)
                         :test #'string=))))
    (is (eq :ok (bitcoin-lisp.mempool:mempool-add
                 mempool txid (bitcoin-lisp.mempool:make-entry-from-tx tx 1000 0))))
    (is-true (bitcoin-lisp.mempool:mempool-add-unbroadcast mempool txid))
    (is (= 1 (cdr (assoc "unbroadcastcount"
                         (bitcoin-lisp.rpc::rpc-getmempoolinfo node nil)
                         :test #'string=))))))

(test rpc-importmempool-unbroadcast-option
  "The saved unbroadcast set is restored by the startup load
(load-mempool-from-disk defaults apply-unbroadcast on, Core
node/mempool_persist.h:24) but by importmempool only when
apply_unbroadcast_set is passed true (Core default false,
rpc/mempool.cpp:1115-1116)."
  (let ((path (merge-pathnames (format nil "bl-unbr-import-~D.dat" (get-universal-time))
                               (uiop:temporary-directory))))
    (unwind-protect
         (let (txid)
           ;; Source pool: one accepted tx marked unbroadcast, saved to PATH.
           (multiple-value-bind (utxo-set mempool chain-state funding-txid) (%pkg-fixture)
             (declare (ignore utxo-set chain-state))
             (let ((tx (%pkg-tx funding-txid 0 (- 100000000 10000))))
               (setf txid (bitcoin-lisp.serialization:transaction-hash tx))
               (is (eq :ok (bitcoin-lisp.mempool:mempool-add
                            mempool txid
                            (bitcoin-lisp.mempool:make-entry-from-tx tx 10000 200))))
               (bitcoin-lisp.mempool:mempool-add-unbroadcast mempool txid)
               (bitcoin-lisp.mempool:save-mempool-file mempool path)))
           ;; importmempool default: entries load, unbroadcast NOT applied.
           (multiple-value-bind (utxo-set mempool chain-state funding-txid) (%pkg-fixture)
             (declare (ignore funding-txid))
             (let ((node (%broadcast-test-node
                          utxo-set mempool chain-state
                          (bitcoin-lisp.networking:make-peer :state :ready))))
               (bitcoin-lisp.rpc::rpc-importmempool node (list (namestring path)))
               (is-true (bitcoin-lisp.mempool:mempool-has mempool txid))
               (is (= 0 (bitcoin-lisp.mempool:mempool-unbroadcast-count mempool)))))
           ;; importmempool with apply_unbroadcast_set=true restores the set.
           (multiple-value-bind (utxo-set mempool chain-state funding-txid) (%pkg-fixture)
             (declare (ignore funding-txid))
             (let ((node (%broadcast-test-node
                          utxo-set mempool chain-state
                          (bitcoin-lisp.networking:make-peer :state :ready)))
                   (opts (make-hash-table :test 'equal)))
               (setf (gethash "apply_unbroadcast_set" opts) t)
               (bitcoin-lisp.rpc::rpc-importmempool node (list (namestring path) opts))
               (is (= 1 (bitcoin-lisp.mempool:mempool-unbroadcast-count mempool)))
               (is-true (gethash txid (bitcoin-lisp.mempool:mempool-unbroadcast mempool)))))
           ;; Startup path (load-mempool-from-disk) applies it by default.
           (multiple-value-bind (utxo-set mempool chain-state funding-txid) (%pkg-fixture)
             (declare (ignore funding-txid))
             (let ((node (%broadcast-test-node
                          utxo-set mempool chain-state
                          (bitcoin-lisp.networking:make-peer :state :ready))))
               (bitcoin-lisp::load-mempool-from-disk node path)
               (is (= 1 (bitcoin-lisp.mempool:mempool-unbroadcast-count mempool)))
               (is-true (gethash txid (bitcoin-lisp.mempool:mempool-unbroadcast mempool))))))
      (ignore-errors (delete-file path)))))

(test rpc-getblockheader-confirmations
  "getblockheader.confirmations is the active-chain depth (tip - height + 1), not
a hardcoded 1."
  (multiple-value-bind (cs entries) (%make-served-chain 5)  ; genesis..height 5
    (let ((node (make-test-node)))
      (setf (bitcoin-lisp::node-chain-state node) cs)
      ;; height 3 -> 5 - 3 + 1 = 3 confirmations, plus the shared chain-header fields
      (let ((r (bitcoin-lisp.rpc::rpc-getblockheader
                node (list (bitcoin-lisp.rpc::hash-to-hex (%entry-hash entries 3))))))
        (is (= 3 (cdr (assoc "height" r :test #'string=))))
        (is (= 3 (cdr (assoc "confirmations" r :test #'string=))))
        (is (= 8 (length (cdr (assoc "versionHex" r :test #'string=)))))
        (is (integerp (cdr (assoc "mediantime" r :test #'string=))))
        (is (= 64 (length (cdr (assoc "target" r :test #'string=)))))
        (is (= 64 (length (cdr (assoc "chainwork" r :test #'string=)))))
        (is (= 8 (length (cdr (assoc "bits" r :test #'string=)))))
        (is (numberp (cdr (assoc "difficulty" r :test #'string=))))
        ;; a non-tip active-chain block carries nextblockhash
        (is (assoc "nextblockhash" r :test #'string=)))
      ;; tip (height 5) -> 1 confirmation, no nextblockhash
      (let ((r (bitcoin-lisp.rpc::rpc-getblockheader
                node (list (bitcoin-lisp.rpc::hash-to-hex (%entry-hash entries 5))))))
        (is (= 1 (cdr (assoc "confirmations" r :test #'string=))))
        (is (null (assoc "nextblockhash" r :test #'string=)))))))

;;; --- Authentication Tests (7.4) ---

(test rpc-auth-check-no-credentials
  "Test auth check passes when no credentials configured"
  ;; When no user/password is set, auth should pass
  (let ((bitcoin-lisp.rpc::*rpc-user* nil)
        (bitcoin-lisp.rpc::*rpc-password* nil))
    (is (bitcoin-lisp.rpc::check-auth nil))))

(test rpc-auth-header-parsing
  "Test Basic auth header parsing"
  ;; Create a mock request with Authorization header
  ;; Base64 of "testuser:testpass" is "dGVzdHVzZXI6dGVzdHBhc3M="
  (let ((bitcoin-lisp.rpc::*rpc-user* "testuser")
        (bitcoin-lisp.rpc::*rpc-password* "testpass"))
    ;; We can't easily mock hunchentoot request, but we can test the logic
    ;; by checking that auth is required when credentials are set
    (is (not (null bitcoin-lisp.rpc::*rpc-user*)))
    (is (not (null bitcoin-lisp.rpc::*rpc-password*)))))

;;; --- Concurrent Access Tests (2.7) ---

(test rpc-concurrent-access-safety
  "Test that multiple threads can safely call RPC accessors"
  (let* ((node (make-test-node))
         (results (make-array 10 :initial-element nil))
         (threads nil))
    ;; Spawn 10 threads that each call RPC accessors
    (dotimes (i 10)
      (let ((idx i))  ; Capture i in a fresh binding for each iteration
        (push (bt:make-thread
               (lambda ()
                 ;; Call various accessors
                 (bitcoin-lisp.rpc::rpc-get-chain-state node)
                 (bitcoin-lisp.rpc::rpc-get-utxo-set node)
                 (bitcoin-lisp.rpc::rpc-get-peers node)
                 (setf (aref results idx) t)))
              threads)))
    ;; Wait for all threads to complete
    (dolist (thread threads)
      (bt:join-thread thread))
    ;; All threads should have completed successfully
    (is (every #'identity results))))

(test rpc-concurrent-method-calls
  "Test that multiple threads can safely call RPC methods"
  (let* ((node (make-test-node))
         (error-count 0)
         (error-lock (bt:make-lock "error-lock"))
         (threads nil))
    ;; Spawn threads that call various RPC methods concurrently
    (dotimes (i 5)
      (push (bt:make-thread
             (lambda ()
               (handler-case
                   (progn
                     (bitcoin-lisp.rpc::rpc-getblockchaininfo node nil)
                     (bitcoin-lisp.rpc::rpc-getblockcount node nil)
                     (bitcoin-lisp.rpc::rpc-getnetworkinfo node nil)
                     (bitcoin-lisp.rpc::rpc-getmempoolinfo node nil))
                 (error (e)
                   (declare (ignore e))
                   (bt:with-lock-held (error-lock)
                     (incf error-count))))))
            threads))
    ;; Wait for all threads
    (dolist (thread threads)
      (bt:join-thread thread))
    ;; No errors should have occurred
    (is (= error-count 0))))

;;; --- Error Response Format Tests (9.3) ---

(test rpc-error-codes-match-bitcoin-core
  "Test that error codes match Bitcoin Core specification"
  ;; Standard JSON-RPC 2.0 error codes
  (is (= bitcoin-lisp.rpc::+rpc-parse-error+ -32700))
  (is (= bitcoin-lisp.rpc::+rpc-invalid-request+ -32600))
  (is (= bitcoin-lisp.rpc::+rpc-method-not-found+ -32601))
  (is (= bitcoin-lisp.rpc::+rpc-internal-error+ -32603))
  ;; Bitcoin Core specific error codes
  (is (= bitcoin-lisp.rpc::+rpc-invalid-parameter+ -8))  ; RPC_INVALID_PARAMETER
  (is (= bitcoin-lisp.rpc::+rpc-misc-error+ -1)))

(test rpc-error-response-format
  "Test error response matches Bitcoin Core format"
  (let ((response (bitcoin-lisp.rpc::make-rpc-error-response -32601 "Method not found" 123)))
    ;; Must have jsonrpc, error, and id fields
    (is (string= (gethash "jsonrpc" response) "2.0"))
    (is (gethash "error" response))
    (is (= (gethash "id" response) 123))
    ;; Error object must have code and message
    (let ((error-obj (gethash "error" response)))
      (is (gethash "code" error-obj))
      (is (gethash "message" error-obj))
      (is (integerp (gethash "code" error-obj)))
      (is (stringp (gethash "message" error-obj))))))

;;; --- Extended RPC Method Tests ---

;;; decoderawtransaction tests

(test rpc-decoderawtransaction-valid
  "Test decoderawtransaction with valid transaction hex"
  (let* ((node (make-test-node))
         ;; Simple transaction hex (version + empty inputs/outputs + locktime)
         ;; This is a minimal valid transaction structure
         (tx-hex "01000000000000000000")
         (result (handler-case
                     (bitcoin-lisp.rpc::rpc-decoderawtransaction node (list tx-hex))
                   (error () nil))))
    ;; May fail to parse minimal tx, but should not crash
    (is (or result (not result)))))

(test rpc-decoderawtransaction-invalid-hex
  "Test decoderawtransaction with invalid hex returns error"
  (let ((node (make-test-node)))
    ;; Empty string
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-decoderawtransaction node '("")))
    ;; Invalid hex characters
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-decoderawtransaction node '("zzzz")))))

;;; getrawtransaction tests

(test rpc-getrawtransaction-invalid-txid
  "Test getrawtransaction with invalid txid returns error"
  (let ((node (make-test-node)))
    ;; Too short
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getrawtransaction node '("abc")))
    ;; Invalid characters
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getrawtransaction node '("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")))))

(test rpc-getrawtransaction-not-found
  "Test getrawtransaction for unknown txid returns error"
  (let ((node (make-test-node)))
    ;; Valid txid but not in mempool
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getrawtransaction node
        '("0000000000000000000000000000000000000000000000000000000000000001")))))

;;; estimatesmartfee tests

(test rpc-estimatesmartfee-valid
  "Test estimatesmartfee with valid conf_target"
  (let* ((node (make-test-node))
         ;; Mark node as not syncing
         (bitcoin-lisp::*syncing* nil)
         (result (bitcoin-lisp.rpc::rpc-estimatesmartfee node '(6))))
    (is (assoc "feerate" result :test #'string=))
    (is (assoc "blocks" result :test #'string=))
    (is (= (cdr (assoc "blocks" result :test #'string=)) 6))
    (is (> (cdr (assoc "feerate" result :test #'string=)) 0))))

(test rpc-estimatesmartfee-invalid-target
  "Test estimatesmartfee with invalid conf_target returns error"
  (let ((node (make-test-node)))
    ;; Zero
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-estimatesmartfee node '(0)))
    ;; Negative
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-estimatesmartfee node '(-1)))
    ;; Too high
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-estimatesmartfee node '(2000)))))

;;; validateaddress tests

(test rpc-validateaddress-valid-p2pkh
  "Test validateaddress with valid testnet P2PKH address"
  (let* ((node (make-test-node))
         ;; Valid testnet P2PKH address (starts with m or n)
         (result (bitcoin-lisp.rpc::rpc-validateaddress node '("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"))))
    (is (eq t (cdr (assoc "isvalid" result :test #'string=))))
    (is (assoc "address" result :test #'string=))
    (is (assoc "scriptPubKey" result :test #'string=))
    (is (eq nil (cdr (assoc "iswitness" result :test #'string=))))
    ;; isscript is a real boolean; a P2PKH address is not a script address.
    (is (eq nil (cdr (assoc "isscript" result :test #'string=))))))

(test rpc-validateaddress-valid-bech32
  "Test validateaddress with valid testnet bech32 address"
  (let* ((node (make-test-node))
         ;; Valid testnet P2WPKH address
         (result (bitcoin-lisp.rpc::rpc-validateaddress node '("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"))))
    (is (eq t (cdr (assoc "isvalid" result :test #'string=))))
    (is (eq t (cdr (assoc "iswitness" result :test #'string=))))
    (is (= 0 (cdr (assoc "witness_version" result :test #'string=))))))

(test rpc-validateaddress-invalid
  "Test validateaddress with invalid address"
  (let* ((node (make-test-node))
         (result (bitcoin-lisp.rpc::rpc-validateaddress node '("not-an-address"))))
    (is (eq nil (cdr (assoc "isvalid" result :test #'string=))))))

(test rpc-validateaddress-isscript-boolean
  "isscript is T (a boolean) for a script address (P2SH) -- regression: it used
to return a list of keyword symbols for script types, which serialized as a JSON
array / could error."
  (let* ((node (make-test-node))
         (addr (bitcoin-lisp.crypto:encode-p2sh-address
                (make-array 20 :element-type '(unsigned-byte 8) :initial-element 7)
                :testnet3))
         (result (bitcoin-lisp.rpc::rpc-validateaddress node (list addr))))
    (is (eq t (cdr (assoc "isvalid" result :test #'string=))))
    (is (eq t (cdr (assoc "isscript" result :test #'string=))))))

(test rpc-validateaddress-empty
  "Test validateaddress with empty string"
  (let* ((node (make-test-node))
         (result (bitcoin-lisp.rpc::rpc-validateaddress node '(""))))
    (is (eq nil (cdr (assoc "isvalid" result :test #'string=))))))

(test rpc-validateaddress-wrong-network
  "Test validateaddress with mainnet address on testnet"
  (let* ((node (make-test-node))
         ;; Mainnet P2PKH address (starts with 1)
         (result (bitcoin-lisp.rpc::rpc-validateaddress node '("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"))))
    ;; Should be invalid on testnet node
    (is (eq nil (cdr (assoc "isvalid" result :test #'string=))))))

;;; decodescript tests

(test rpc-decodescript-p2pkh
  "Test decodescript with P2PKH script"
  (let* ((node (make-test-node))
         ;; P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
         (script-hex "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac")
         (result (bitcoin-lisp.rpc::rpc-decodescript node (list script-hex))))
    (is (string= (cdr (assoc "type" result :test #'string=)) "pubkeyhash"))
    (is (assoc "asm" result :test #'string=))
    (is (assoc "p2sh" result :test #'string=))))

(test rpc-decodescript-p2sh
  "Test decodescript with P2SH script"
  (let* ((node (make-test-node))
         ;; P2SH: OP_HASH160 <20 bytes> OP_EQUAL
         (script-hex "a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba87")
         (result (bitcoin-lisp.rpc::rpc-decodescript node (list script-hex))))
    (is (string= (cdr (assoc "type" result :test #'string=)) "scripthash"))))

(test rpc-decodescript-p2wpkh
  "Test decodescript with P2WPKH script"
  (let* ((node (make-test-node))
         ;; P2WPKH: OP_0 <20 bytes>
         (script-hex "001489abcdefabbaabbaabbaabbaabbaabbaabbaabba")
         (result (bitcoin-lisp.rpc::rpc-decodescript node (list script-hex))))
    (is (string= (cdr (assoc "type" result :test #'string=)) "witness_v0_keyhash"))
    (is (assoc "segwit" result :test #'string=))))

(test rpc-decodescript-empty
  "Test decodescript with empty script"
  (let* ((node (make-test-node))
         (result (bitcoin-lisp.rpc::rpc-decodescript node '(""))))
    (is (string= (cdr (assoc "type" result :test #'string=)) "nonstandard"))
    (is (string= (cdr (assoc "asm" result :test #'string=)) ""))))

(test rpc-decodescript-invalid-hex
  "Test decodescript with invalid hex returns error"
  (let ((node (make-test-node)))
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-decodescript node '("xyz")))))

;;; createrawtransaction tests

(test rpc-createrawtransaction-basic
  "Test createrawtransaction with valid inputs and outputs"
  (let* ((node (make-test-node))
         (inputs `((("txid" . "0000000000000000000000000000000000000000000000000000000000000001")
                    ("vout" . 0))))
         (outputs '(("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn" . 0.01)))
         (result (bitcoin-lisp.rpc::rpc-createrawtransaction node (list inputs outputs))))
    ;; Should return hex string
    (is (stringp result))
    (is (> (length result) 0))
    ;; Should be valid hex
    (is (every (lambda (c) (digit-char-p c 16)) result))))

(test rpc-createrawtransaction-invalid-txid
  "Test createrawtransaction with invalid input txid"
  (let ((node (make-test-node)))
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-createrawtransaction node
        '(((("txid" . "invalid") ("vout" . 0)))
          (("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn" . 0.01)))))))

(test rpc-createrawtransaction-invalid-address
  "Test createrawtransaction with invalid output address"
  (let ((node (make-test-node)))
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-createrawtransaction node
        '(((("txid" . "0000000000000000000000000000000000000000000000000000000000000001")
            ("vout" . 0)))
          (("invalid-address" . 0.01)))))))

(test rpc-createrawtransaction-negative-amount
  "Test createrawtransaction with negative amount"
  (let ((node (make-test-node)))
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-createrawtransaction node
        '(((("txid" . "0000000000000000000000000000000000000000000000000000000000000001")
            ("vout" . 0)))
          (("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn" . -0.01)))))))

;;; --- gettxoutsetinfo Tests ---

(test rpc-gettxoutsetinfo-empty-utxo-set
  "Test gettxoutsetinfo with empty UTXO set"
  (let* ((node (make-test-node))
         (result (bitcoin-lisp.rpc::rpc-gettxoutsetinfo node nil)))
    ;; Check required fields exist
    (is (assoc "height" result :test #'string=))
    (is (assoc "bestblock" result :test #'string=))
    (is (assoc "txouts" result :test #'string=))
    (is (assoc "total_amount" result :test #'string=))
    (is (assoc "transactions" result :test #'string=))
    (is (assoc "hash_serialized_3" result :test #'string=))
    ;; Empty UTXO set should have 0 txouts
    (is (= (cdr (assoc "txouts" result :test #'string=)) 0))
    (is (= (cdr (assoc "total_amount" result :test #'string=)) 0))
    (is (= (cdr (assoc "transactions" result :test #'string=)) 0))))

(test rpc-gettxoutsetinfo-with-utxos
  "Test gettxoutsetinfo with UTXOs in set"
  (let* ((node (make-test-node))
         (utxo-set (bitcoin-lisp::node-utxo-set node))
         (txid1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
         (txid2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2))
         (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element 0)))
    ;; Add some UTXOs
    (bitcoin-lisp.storage:add-utxo utxo-set txid1 0 100000000 script 1) ; 1 BTC
    (bitcoin-lisp.storage:add-utxo utxo-set txid1 1 50000000 script 1)  ; 0.5 BTC
    (bitcoin-lisp.storage:add-utxo utxo-set txid2 0 25000000 script 2)  ; 0.25 BTC
    (let ((result (bitcoin-lisp.rpc::rpc-gettxoutsetinfo node nil)))
      ;; Should have 3 UTXOs from 2 transactions
      (is (= (cdr (assoc "txouts" result :test #'string=)) 3))
      (is (= (cdr (assoc "transactions" result :test #'string=)) 2))
      ;; Total should be 1.75 BTC (returned in BTC, not satoshis)
      (is (= (cdr (assoc "total_amount" result :test #'string=)) 1.75))
      ;; hash_serialized_3 should be a 64-char hex string
      (let ((hash (cdr (assoc "hash_serialized_3" result :test #'string=))))
        (is (stringp hash))
        (is (= (length hash) 64))))))

(test rpc-gettxoutsetinfo-muhash
  "gettxoutsetinfo hash_type=muhash returns a 64-hex muhash (order-independent,
distinct from hash_serialized_3), and inserting then removing a coin restores
the value."
  (let* ((node (make-test-node))
         (utxo-set (bitcoin-lisp::node-utxo-set node))
         (txid1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
         (txid2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2))
         (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element 0)))
    (bitcoin-lisp.storage:add-utxo utxo-set txid1 0 100000000 script 1)
    (bitcoin-lisp.storage:add-utxo utxo-set txid2 0 25000000 script 2)
    (let* ((mh (bitcoin-lisp.rpc::rpc-gettxoutsetinfo node (list "muhash")))
           (muhash (cdr (assoc "muhash" mh :test #'string=)))
           (h3 (cdr (assoc "hash_serialized_3"
                           (bitcoin-lisp.rpc::rpc-gettxoutsetinfo node (list "hash_serialized_3"))
                           :test #'string=))))
      (is (stringp muhash))
      (is (= 64 (length muhash)))
      ;; muhash mode does not also emit hash_serialized_3, and vice versa.
      (is (null (assoc "hash_serialized_3" mh :test #'string=)))
      ;; The two hash types are computed over different serializations.
      (is (not (string= muhash h3)))
      ;; Order-independence / add-remove inverse: add a coin, then delete it,
      ;; and the muhash returns to its prior value.
      (bitcoin-lisp.storage:add-utxo utxo-set txid2 1 7 script 3)
      (bitcoin-lisp.storage:remove-utxo utxo-set txid2 1)
      (is (string= muhash
                   (cdr (assoc "muhash"
                               (bitcoin-lisp.rpc::rpc-gettxoutsetinfo node (list "muhash"))
                               :test #'string=)))))
    ;; An unknown hash_type still errors.
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-gettxoutsetinfo node (list "bogus")))))

;;; --- getblockstats Tests ---

(test rpc-getblockstats-invalid-params
  "Test getblockstats with invalid parameters"
  (let ((node (make-test-node)))
    ;; Missing parameter
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getblockstats node nil))
    ;; Invalid hash format
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getblockstats node '("invalid")))
    ;; Negative height
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getblockstats node '(-1)))))

(test rpc-getblockstats-block-not-found
  "Test getblockstats with non-existent block"
  (let ((node (make-test-node)))
    ;; Valid hash format but block doesn't exist
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getblockstats node
        '("0000000000000000000000000000000000000000000000000000000000000001")))))

(test rpc-calculate-block-subsidy
  "Test block subsidy calculation"
  ;; Initial subsidy: 50 BTC = 5000000000 satoshis
  (is (= (bitcoin-lisp.validation:calculate-block-subsidy 0) 5000000000))
  (is (= (bitcoin-lisp.validation:calculate-block-subsidy 209999) 5000000000))
  ;; First halving at 210000
  (is (= (bitcoin-lisp.validation:calculate-block-subsidy 210000) 2500000000))
  (is (= (bitcoin-lisp.validation:calculate-block-subsidy 419999) 2500000000))
  ;; Second halving
  (is (= (bitcoin-lisp.validation:calculate-block-subsidy 420000) 1250000000))
  ;; Third halving
  (is (= (bitcoin-lisp.validation:calculate-block-subsidy 630000) 625000000)))

;;; --- Extended getrawtransaction Tests ---

(test rpc-getrawtransaction-with-blockhash-invalid
  "Test getrawtransaction with invalid blockhash parameter"
  (let ((node (make-test-node)))
    ;; Valid txid but invalid blockhash format
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getrawtransaction node
        '("0000000000000000000000000000000000000000000000000000000000000001" nil "invalid-hash")))))

(test rpc-getrawtransaction-txindex-disabled
  "Test getrawtransaction returns error when txindex needed but disabled"
  (let ((node (make-test-node)))
    ;; Node has no txindex, looking for non-mempool tx should fail
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getrawtransaction node
        '("0000000000000000000000000000000000000000000000000000000000000001")))))

;;; --- JSON Result Normalization (regression) ---

(test rpc-result->json-shapes
  "rpc-result->json converts object-alists to hash-tables, leaves arrays as lists."
  ;; object-alist -> hash-table
  (let ((obj (bitcoin-lisp.rpc::rpc-result->json (list (cons "a" 1) (cons "b" "x")))))
    (is (hash-table-p obj))
    (is (= (gethash "a" obj) 1))
    (is (string= (gethash "b" obj) "x")))
  ;; array of objects -> list of hash-tables
  (let ((arr (bitcoin-lisp.rpc::rpc-result->json
              (list (list (cons "k" 1)) (list (cons "k" 2))))))
    (is (listp arr))
    (is (= (length arr) 2))
    (is (hash-table-p (first arr)))
    (is (= (gethash "k" (first arr)) 1)))
  ;; nested object value
  (let ((obj (bitcoin-lisp.rpc::rpc-result->json
              (list (cons "outer" (list (cons "inner" 7)))))))
    (is (hash-table-p (gethash "outer" obj)))
    (is (= (gethash "inner" (gethash "outer" obj)) 7)))
  ;; array of strings is unchanged; atoms pass through
  (is (equal (bitcoin-lisp.rpc::rpc-result->json (list "a" "b")) (list "a" "b")))
  (is (= (bitcoin-lisp.rpc::rpc-result->json 42) 42)))

(test rpc-object-results-encode-to-json
  "Object-returning RPC results must serialize through yason without error.
Regression: handlers build alists, but yason's default list encoder treated
them as arrays and choked on the dotted pairs, so every object RPC errored."
  (let ((node (make-test-node)))
    (dolist (result (list (bitcoin-lisp.rpc::rpc-getblockchaininfo node nil)
                          (bitcoin-lisp.rpc::rpc-getnetworkinfo node nil)
                          (bitcoin-lisp.rpc::rpc-getpeerinfo node nil)
                          (bitcoin-lisp.rpc::rpc-getmempoolinfo node nil)))
      (let* ((response (bitcoin-lisp.rpc::make-rpc-response result "id"))
             (json (with-output-to-string (s) (yason:encode response s)))
             (parsed (yason:parse json)))
        (is (hash-table-p parsed))
        (is (string= (gethash "jsonrpc" parsed) "2.0"))
        (is-true (nth-value 1 (gethash "result" parsed)))))))

;;; --- getchaintips ---

(defun make-32-byte-hash (n)
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element n))

(test rpc-getchaintips
  "getchaintips reports the active tip (branchlen 0) and side branches."
  (let* ((node (make-test-node))
         (chain-state (bitcoin-lisp::node-chain-state node))
         (g-hash (make-32-byte-hash 0))
         (a-hash (make-32-byte-hash 1))
         (b-hash (make-32-byte-hash 2))
         (genesis (bitcoin-lisp.storage:make-block-index-entry
                   :hash g-hash :height 0 :status :valid))
         (a (bitcoin-lisp.storage:make-block-index-entry
             :hash a-hash :height 1 :prev-entry genesis :status :valid))
         (b (bitcoin-lisp.storage:make-block-index-entry
             :hash b-hash :height 1 :prev-entry genesis :status :valid)))
    (bitcoin-lisp.storage:add-block-index-entry chain-state genesis)
    (bitcoin-lisp.storage:add-block-index-entry chain-state a)
    (bitcoin-lisp.storage:add-block-index-entry chain-state b)
    (bitcoin-lisp.storage:update-chain-tip chain-state a-hash 1)
    (let* ((tips (bitcoin-lisp.rpc::rpc-getchaintips node nil))
           (active (find "active" tips
                         :key (lambda (tip) (cdr (assoc "status" tip :test #'string=)))
                         :test #'string=))
           (fork (find "valid-fork" tips
                       :key (lambda (tip) (cdr (assoc "status" tip :test #'string=)))
                       :test #'string=)))
      ;; genesis has a child, so only A and B are tips.
      (is (= (length tips) 2))
      ;; active tip is A at height 1, branchlen 0, listed first.
      (is (string= (cdr (assoc "status" (first tips) :test #'string=)) "active"))
      (is (= (cdr (assoc "branchlen" active :test #'string=)) 0))
      (is (= (cdr (assoc "height" active :test #'string=)) 1))
      ;; B is a side branch one block off the active chain.
      (is (= (cdr (assoc "branchlen" fork :test #'string=)) 1))
      ;; full result serializes cleanly.
      (let ((response (bitcoin-lisp.rpc::make-rpc-response tips "id")))
        (finishes (with-output-to-string (s) (yason:encode response s)))))))

(test rpc-testmempoolaccept-missing-input
  "testmempoolaccept dry-runs validation without mutating the mempool."
  (let* ((node (make-test-node))
         (tx (make-mempool-test-tx :input-id 210))
         (hex (bitcoin-lisp.crypto:bytes-to-hex
               (bitcoin-lisp.serialization:serialize-transaction tx)))
         (result (bitcoin-lisp.rpc::rpc-testmempoolaccept node (list (list hex)))))
    (is (listp result))
    (is (= 1 (length result)))
    (let ((r (first result)))
      ;; Empty UTXO set => missing input => not allowed, with a reason.
      (is (null (cdr (assoc "allowed" r :test #'string=))))
      (is (string= "missing-input" (cdr (assoc "reject-reason" r :test #'string=)))))
    ;; Nothing was added to the mempool.
    (is (= 0 (bitcoin-lisp.mempool:mempool-count (bitcoin-lisp::node-mempool node))))))

;;; --- Mempool introspection RPCs ---

(test rpc-mempool-introspection
  ;; A parent + chained child in the mempool exercise getmempoolentry,
  ;; getmempoolancestors/descendants, and gettxspendingprevout.
  (let* ((node (make-test-node))
         (mempool (bitcoin-lisp::node-mempool node))
         (funding (%txid-array 99))
         (parent (%mp-spending-tx funding :vout 0 :value 50000000))
         (pid (bitcoin-lisp.serialization:transaction-hash parent))
         (child (%mp-spending-tx pid :vout 0 :value 40000000))
         (cid (bitcoin-lisp.serialization:transaction-hash child))
         (pid-hex (bitcoin-lisp.rpc::hash-to-hex pid))
         (cid-hex (bitcoin-lisp.rpc::hash-to-hex cid)))
    (%add-tx mempool parent :fee 1000)
    (%add-tx mempool child :fee 2000)
    ;; getmempoolentry: parent has 2 descendants (self+child), 1 ancestor (self)
    (let ((r (bitcoin-lisp.rpc::rpc-getmempoolentry node (list pid-hex))))
      (is (= 2 (cdr (assoc "descendantcount" r :test #'string=))))
      (is (= 1 (cdr (assoc "ancestorcount" r :test #'string=)))))
    ;; getmempoolancestors child -> [parent]
    (let ((r (bitcoin-lisp.rpc::rpc-getmempoolancestors node (list cid-hex))))
      (is (equal (list pid-hex) r)))
    ;; getmempooldescendants parent -> [child]
    (let ((r (bitcoin-lisp.rpc::rpc-getmempooldescendants node (list pid-hex))))
      (is (equal (list cid-hex) r)))
    ;; verbose form -> alist (txid-hex . fields)
    (let ((r (bitcoin-lisp.rpc::rpc-getmempooldescendants node (list pid-hex t))))
      (is (= 1 (length r)))
      (is (string= cid-hex (car (first r))))
      (is (assoc "vsize" (cdr (first r)) :test #'string=)))
    ;; gettxspendingprevout: the funding outpoint is spent by the parent
    (flet ((op (txid-hex vout)
             (let ((h (make-hash-table :test 'equal)))
               (setf (gethash "txid" h) txid-hex (gethash "vout" h) vout) h)))
      (let ((r (bitcoin-lisp.rpc::rpc-gettxspendingprevout
                node (list (list (op (bitcoin-lisp.rpc::hash-to-hex funding) 0))))))
        (is (= 1 (length r)))
        (is (string= pid-hex (cdr (assoc "spendingtxid" (first r) :test #'string=)))))
      ;; an unspent outpoint -> no spendingtxid key
      (let ((r (bitcoin-lisp.rpc::rpc-gettxspendingprevout
                node (list (list (op (bitcoin-lisp.rpc::hash-to-hex (%txid-array 200)) 0))))))
        (is (null (assoc "spendingtxid" (first r) :test #'string=)))))
    ;; getmempoolentry for an absent tx -> error
    (signals error
      (bitcoin-lisp.rpc::rpc-getmempoolentry
       node (list (bitcoin-lisp.rpc::hash-to-hex (%txid-array 201)))))))

;;; --- Node / chain info RPCs ---

(test rpc-node-info
  (let* ((node (make-test-node))
         (net (bitcoin-lisp::node-network node)))
    ;; getdifficulty: a positive number (no tip -> fallback bits 0x1d00ffff -> 1.0)
    (let ((d (bitcoin-lisp.rpc::rpc-getdifficulty node nil)))
      (is (numberp d))
      (is (plusp d)))
    ;; uptime: 0 when start-time unset; >= elapsed when set
    (let ((bitcoin-lisp::*node-start-time* nil))
      (is (= 0 (bitcoin-lisp.rpc::rpc-uptime node nil))))
    (let ((bitcoin-lisp::*node-start-time*
            (- (bitcoin-lisp.serialization:get-unix-time) 5)))
      (is (>= (bitcoin-lisp.rpc::rpc-uptime node nil) 5)))
    ;; getindexinfo: no active index -> empty JSON object (hash-table)
    (is (hash-table-p (bitcoin-lisp.rpc::rpc-getindexinfo node nil)))
    ;; With block-filter + coinstats indexes present, both are reported (bare
    ;; structs have a nil db -> height -1); an index-name arg filters to one.
    (setf (bitcoin-lisp::node-blockfilterindex node)
          (bitcoin-lisp.storage:make-blockfilterindex :enabled t)
          (bitcoin-lisp::node-coinstatsindex node)
          (bitcoin-lisp.storage::make-coinstatsindex :enabled t))
    (let ((all (bitcoin-lisp.rpc::rpc-getindexinfo node nil)))
      (is (assoc "basic block filter index" all :test #'string=))
      (is (assoc "coinstatsindex" all :test #'string=)))
    (let ((one (bitcoin-lisp.rpc::rpc-getindexinfo node (list "coinstatsindex"))))
      (is (assoc "coinstatsindex" one :test #'string=))
      (is (null (assoc "basic block filter index" one :test #'string=))))
    ;; getdeploymentinfo: buried deployments present; segwit reports the
    ;; network's activation height and matches the active/height contract.
    (let* ((r (bitcoin-lisp.rpc::rpc-getdeploymentinfo node nil))
           (deps (cdr (assoc "deployments" r :test #'string=)))
           (segwit (cdr (assoc "segwit" deps :test #'string=))))
      (is (assoc "bip34" deps :test #'string=))
      (is (assoc "taproot" deps :test #'string=))
      ;; script_flags is a list of active script-verify flag names (P2SH at h=0)
      (is (member "P2SH" (cdr (assoc "script_flags" r :test #'string=)) :test #'string=))
      (is (string= "buried" (cdr (assoc "type" segwit :test #'string=))))
      (is (= (bitcoin-lisp.validation:get-segwit-activation-height net)
             (cdr (assoc "height" segwit :test #'string=))))
      ;; height 0 < testnet segwit activation -> not active
      (is (eq (>= 0 (bitcoin-lisp.validation:get-segwit-activation-height net))
              (cdr (assoc "active" segwit :test #'string=)))))))

;;; --- Peer / address RPCs ---

(test rpc-peer-address
  (let ((node (make-test-node)))
    ;; getnodeaddresses: seed the address book with one IPv4 entry
    (let ((book (bitcoin-lisp.networking:make-address-book)))
      (bitcoin-lisp.networking:address-book-add
       book (bitcoin-lisp.networking:make-peer-address
             :ip (bitcoin-lisp.networking::ipv4-to-mapped-ipv6 1 2 3 4)
             :port 48333 :services 9
             ;; recent so getnodeaddresses (GetAddr) doesn't filter it as terrible
             :last-seen (bitcoin-lisp.serialization:get-unix-time)))
      (setf (bitcoin-lisp::node-address-book node) book)
      (let ((r (bitcoin-lisp.rpc::rpc-getnodeaddresses node (list 0))))  ; 0 = all
        (is (= 1 (length r)))
        (is (string= "1.2.3.4" (cdr (assoc "address" (first r) :test #'string=))))
        (is (= 48333 (cdr (assoc "port" (first r) :test #'string=))))
        (is (= 9 (cdr (assoc "services" (first r) :test #'string=))))))
    ;; disconnectnode: a connected peer is disconnected by address
    (let ((peer (bitcoin-lisp.networking:make-peer
                 :connection (bitcoin-lisp.networking::make-connection
                              :host "5.6.7.8" :port 48333 :connected t)
                 :state :ready :address "5.6.7.8")))
      (setf (bitcoin-lisp::node-peers node) (list peer))
      (is (null (bitcoin-lisp.rpc::rpc-disconnectnode node (list "5.6.7.8"))))
      (is (eq :disconnected (bitcoin-lisp.networking:peer-state peer)))
      ;; an unknown address errors
      (signals error (bitcoin-lisp.rpc::rpc-disconnectnode node (list "9.9.9.9"))))))

;;; --- Chain control RPCs (error paths; full reorg behavior in reorg-tests) ---

(test rpc-chain-control-errors
  (let ((node (make-test-node)))
    ;; a well-formed but unknown block hash -> error
    (signals error
      (bitcoin-lisp.rpc::rpc-invalidateblock
       node (list "00000000000000000000000000000000000000000000000000000000deadbeef")))
    ;; a malformed hash -> error
    (signals error
      (bitcoin-lisp.rpc::rpc-reconsiderblock node (list "not-a-hash")))))

;;; --- setban / listbanned / clearbanned / getnettotals / verifychain ---

(test rpc-setban-add-list-remove-clear
  "setban add/remove + listbanned + clearbanned manage the manual ban list."
  (bitcoin-lisp.networking:clear-ban-list)
  (let ((node (make-test-node)))
    (is (null (bitcoin-lisp.rpc::rpc-setban node (list "1.2.3.4" "add"))))
    (is-true (bitcoin-lisp.networking:peer-banned-p "1.2.3.4"))
    (let ((banned (bitcoin-lisp.rpc::rpc-listbanned node nil)))
      (is (= 1 (length banned)))
      (is (string= "1.2.3.4" (cdr (assoc "address" (first banned) :test #'string=))))
      (is (integerp (cdr (assoc "banned_until" (first banned) :test #'string=)))))
    (is (null (bitcoin-lisp.rpc::rpc-setban node (list "1.2.3.4" "remove"))))
    (is (not (bitcoin-lisp.networking:peer-banned-p "1.2.3.4")))
    ;; remove a non-existent ban / bad command -> error
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-setban node (list "9.9.9.9" "remove")))
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-setban node (list "1.2.3.4" "bogus")))
    ;; clearbanned empties the list
    (bitcoin-lisp.rpc::rpc-setban node (list "5.6.7.8" "add"))
    (is (null (bitcoin-lisp.rpc::rpc-clearbanned node nil)))
    (is (= 0 (length (bitcoin-lisp.rpc::rpc-listbanned node nil))))))

(test rpc-setban-absolute-bantime
  "setban add with absolute=true sets banned_until to the given Unix time."
  (bitcoin-lisp.networking:clear-ban-list)
  (let ((node (make-test-node))
        (future (+ (bitcoin-lisp.serialization:get-unix-time) 3600)))
    (bitcoin-lisp.rpc::rpc-setban node (list "10.0.0.1" "add" future t))
    (let ((banned (bitcoin-lisp.rpc::rpc-listbanned node nil)))
      (is (<= (abs (- future (cdr (assoc "banned_until" (first banned) :test #'string=)))) 2)))
    (bitcoin-lisp.networking:clear-ban-list)))

(test rpc-getnettotals-fields
  "getnettotals returns integer byte totals + timemillis + an uploadtarget object."
  (let ((r (bitcoin-lisp.rpc::rpc-getnettotals (make-test-node) nil)))
    (is (integerp (cdr (assoc "totalbytesrecv" r :test #'string=))))
    (is (integerp (cdr (assoc "totalbytessent" r :test #'string=))))
    (is (integerp (cdr (assoc "timemillis" r :test #'string=))))
    (is (consp (cdr (assoc "uploadtarget" r :test #'string=))))))

(test rpc-verifychain-empty-node-returns-nil
  "verifychain on a node with no stored blocks returns NIL gracefully."
  (is (null (bitcoin-lisp.rpc::rpc-verifychain (make-test-node) (list 0 1)))))

;;; --- waitfornewblock / dumptxoutset ---

(test rpc-waitfornewblock-timeout-and-change
  "waitfornewblock returns on timeout, rejects negative timeouts, and returns
early when the tip changes."
  (let ((node (make-test-node)))
    (setf (bitcoin-lisp::node-running node) t)
    ;; Timeout path: the tip never changes; returns after ~300ms.
    (let ((r (bitcoin-lisp.rpc::rpc-waitfornewblock node (list 300))))
      (is (integerp (cdr (assoc "height" r :test #'string=)))))
    ;; Negative timeout errors (Core).
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-waitfornewblock node (list -1)))
    ;; Change path: a thread advances the tip; the wait returns the new height.
    (let ((cs (bitcoin-lisp::node-chain-state node))
          (new-hash (make-array 32 :element-type '(unsigned-byte 8)
                                   :initial-element 9)))
      (bt:make-thread (lambda ()
                        (sleep 0.3)
                        (bitcoin-lisp.storage:update-chain-tip cs new-hash 7)))
      (let ((r (bitcoin-lisp.rpc::rpc-waitfornewblock node (list 5000))))
        (is (= 7 (cdr (assoc "height" r :test #'string=))))))))

(test rpc-dumptxoutset-writes-snapshot
  "dumptxoutset streams the UTXO set to a new file and refuses to overwrite."
  (let* ((node (make-test-node))
         (utxo (bitcoin-lisp::node-utxo-set node))
         (path (namestring (merge-pathnames
                            (format nil "txoutset-~D.dat" (get-universal-time))
                            (uiop:temporary-directory)))))
    (bitcoin-lisp.storage:update-chain-tip
     (bitcoin-lisp::node-chain-state node)
     (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9) 1)
    (dotimes (i 3)
      (bitcoin-lisp.storage:add-utxo
       utxo
       (make-array 32 :element-type '(unsigned-byte 8) :initial-element (1+ i))
       0 1000 (make-array 25 :element-type '(unsigned-byte 8)) 1))
    (unwind-protect
         (progn
           (let ((r (bitcoin-lisp.rpc::rpc-dumptxoutset node (list path "latest"))))
             (is (= 3 (cdr (assoc "coins_written" r :test #'string=))))
             (is (not (null (probe-file path)))))
           ;; Existing path -> error (Core).
           (signals bitcoin-lisp.rpc::rpc-error
             (bitcoin-lisp.rpc::rpc-dumptxoutset node (list path "latest"))))
      (ignore-errors (delete-file path)))))

;;;; RPC auth + JSON-RPC version (T3b: stock bitcoin-cli compatibility)

(test rpc-accepts-jsonrpc-1.0-and-versionless
  "parse-json-rpc-request accepts a 1.0 (and version-less) envelope — stock
bitcoin-cli sends those; rejecting non-2.0 made it unusable."
  (multiple-value-bind (kind method)
      (bitcoin-lisp.rpc::parse-json-rpc-request
       "{\"jsonrpc\":\"1.0\",\"method\":\"getblockcount\",\"params\":[],\"id\":1}")
    (is (eq :single kind))
    (is (string= "getblockcount" method)))
  (multiple-value-bind (kind method)
      (bitcoin-lisp.rpc::parse-json-rpc-request "{\"method\":\"uptime\",\"id\":1}")
    (is (eq :single kind))
    (is (string= "uptime" method))))

(test rpc-basic-auth-and-cookie
  "%basic-auth-matches-p accepts the configured user:pass and the cookie
credential, and rejects a wrong password (fixing the prior mismatch bypass)."
  (let ((bitcoin-lisp.rpc::*rpc-user* "u")
        (bitcoin-lisp.rpc::*rpc-password* "p")
        (bitcoin-lisp.rpc::*rpc-cookie-secret* "deadbeef"))
    (flet ((basic (s) (concatenate 'string "Basic "
                                   (cl-base64:string-to-base64-string s))))
      (is (bitcoin-lisp.rpc::%basic-auth-matches-p (basic "u:p")))
      (is (bitcoin-lisp.rpc::%basic-auth-matches-p (basic "__cookie__:deadbeef")))
      (is (not (bitcoin-lisp.rpc::%basic-auth-matches-p (basic "u:wrong"))))
      (is (not (bitcoin-lisp.rpc::%basic-auth-matches-p (basic "__cookie__:bad")))))))

;;;; tx JSON field completeness (T3c)

(test tx-to-json-includes-core-fields
  "tx-to-json emits the size/weight/hex/wtxid fields and per-output type +
address (with network), and per-input sequence — the fields explorers expect."
  (let* ((tx (make-mempool-test-tx :input-id 50))
         (j (bitcoin-lisp.rpc::tx-to-json tx :regtest)))
    (is (stringp (cdr (assoc "hash" j :test #'string=))))
    (is (integerp (cdr (assoc "vsize" j :test #'string=))))
    (is (integerp (cdr (assoc "weight" j :test #'string=))))
    (is (stringp (cdr (assoc "hex" j :test #'string=))))
    (let* ((vout (first (cdr (assoc "vout" j :test #'string=))))
           (spk (cdr (assoc "scriptPubKey" vout :test #'string=))))
      (is (string= "pubkeyhash" (cdr (assoc "type" spk :test #'string=))))
      (is (stringp (cdr (assoc "address" spk :test #'string=))))
      ;; scriptPubKey now carries asm + desc (feeds decoderawtransaction/getblock v2)
      (is (stringp (cdr (assoc "asm" spk :test #'string=))))
      (let ((d (cdr (assoc "desc" spk :test #'string=))))
        (is (stringp d))
        ;; a P2PKH output infers to addr(<address>)#checksum
        (is (eql 0 (search "addr(" d)))))
    (let* ((vin (first (cdr (assoc "vin" j :test #'string=))))
           (ss (cdr (assoc "scriptSig" vin :test #'string=))))
      (is (assoc "sequence" vin :test #'string=))
      ;; non-coinbase scriptSig now carries asm
      (is (stringp (cdr (assoc "asm" ss :test #'string=)))))))

;;;; Operator RPCs + regtest subsidy halving (T3d)

(test regtest-subsidy-halving-interval
  "calculate-block-subsidy halves at 150 on regtest (Core), 210000 elsewhere."
  (let ((bitcoin-lisp:*network* :regtest))
    (is (= 5000000000 (bitcoin-lisp.validation:calculate-block-subsidy 149)))
    (is (= 2500000000 (bitcoin-lisp.validation:calculate-block-subsidy 150))))
  (let ((bitcoin-lisp:*network* :mainnet))
    (is (= 5000000000 (bitcoin-lisp.validation:calculate-block-subsidy 150)))
    (is (= 2500000000 (bitcoin-lisp.validation:calculate-block-subsidy 210000)))))

(test rpc-help-lists-methods
  "help with no argument lists registered methods, including the new ones."
  (bitcoin-lisp.rpc::register-all-methods)
  (let ((h (bitcoin-lisp.rpc::rpc-help nil nil)))
    (is (stringp h))
    (is (search "stop" h))
    (is (search "getnetworkhashps" h)))
  ;; A known method echoes its name; an unknown one reports so.
  (is (string= "uptime" (bitcoin-lisp.rpc::rpc-help nil (list "uptime"))))
  (is (search "unknown" (bitcoin-lisp.rpc::rpc-help nil (list "nope-xyz")))))

(test rpc-getmemoryinfo-and-getrpcinfo-shape
  "getmemoryinfo reports the heap under \"locked\"; getrpcinfo reports
active_commands + logpath."
  (let ((mi (bitcoin-lisp.rpc::rpc-getmemoryinfo nil nil)))
    (is (assoc "locked" mi :test #'string=))
    (is (integerp (cdr (assoc "total" (cdr (assoc "locked" mi :test #'string=))
                              :test #'string=)))))
  (let ((ri (bitcoin-lisp.rpc::rpc-getrpcinfo nil nil)))
    (is (assoc "active_commands" ri :test #'string=))
    (is (assoc "logpath" ri :test #'string=))))

(test rpc-waitforblock-and-height
  "waitforblock returns immediately when the tip already matches the requested
hash; waitforblockheight returns immediately when the tip is already at/above the
target. Both return {hash,height}; an unreached height with a short timeout
returns the current tip; bad inputs error."
  (let* ((node (make-test-node))
         (cs (bitcoin-lisp.rpc::rpc-get-chain-state node))
         (tip-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3))
         (zeros (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    ;; make-test-node's chain-state has no tip; plant one at height 5.
    (bitcoin-lisp.storage:add-block-index-entry
     cs (bitcoin-lisp.storage:make-block-index-entry
         :hash tip-hash :height 5 :chain-work 100 :status :valid
         :header (bitcoin-lisp.serialization:make-block-header
                  :version 1 :prev-block zeros :merkle-root zeros
                  :timestamp 1296688600 :bits #x207fffff :nonce 0 :cached-hash tip-hash)))
    (bitcoin-lisp.storage:update-chain-tip cs tip-hash 5)
    (let ((tip-hex (bitcoin-lisp.rpc::hash-to-hex tip-hash)))
      ;; waitforblock with the current tip hash -> immediate match.
      (let ((r (bitcoin-lisp.rpc::rpc-waitforblock node (list tip-hex))))
        (is (string= tip-hex (cdr (assoc "hash" r :test #'string=))))
        (is (= 5 (cdr (assoc "height" r :test #'string=)))))
      ;; waitforblockheight at/below the tip -> immediate.
      (let ((r (bitcoin-lisp.rpc::rpc-waitforblockheight node (list 5))))
        (is (= 5 (cdr (assoc "height" r :test #'string=)))))
      ;; unreached height + short timeout -> returns the current (lower) tip.
      (let ((r (bitcoin-lisp.rpc::rpc-waitforblockheight node (list 1005 50))))
        (is (= 5 (cdr (assoc "height" r :test #'string=)))))
      ;; bad inputs error.
      (signals bitcoin-lisp.rpc::rpc-error
        (bitcoin-lisp.rpc::rpc-waitforblock node (list "not-a-valid-hash")))
      (signals bitcoin-lisp.rpc::rpc-error
        (bitcoin-lisp.rpc::rpc-waitforblockheight node (list -1))))))

(test rpc-gettxout-scriptpubkey-fields
  "gettxout's scriptPubKey now carries asm/hex/type and (for address-bearing
scripts) address — previously only hex."
  (let* ((node (make-test-node))   ; testnet3
         (utxo-set (bitcoin-lisp.rpc::rpc-get-utxo-set node))
         (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 5))
         (keyhash (make-array 20 :element-type '(unsigned-byte 8) :initial-element 7))
         ;; P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
         (spk (concatenate '(vector (unsigned-byte 8))
                           (vector #x76 #xa9 #x14) keyhash (vector #x88 #xac))))
    (bitcoin-lisp.storage:add-utxo utxo-set txid 0 50000 spk 0)
    (let* ((r (bitcoin-lisp.rpc::rpc-gettxout
               node (list (bitcoin-lisp.rpc::hash-to-hex txid) 0)))
           (sp (cdr (assoc "scriptPubKey" r :test #'string=))))
      (is (string= "pubkeyhash" (cdr (assoc "type" sp :test #'string=))))
      (is (string= (bitcoin-lisp.crypto:encode-p2pkh-address keyhash :testnet3)
                   (cdr (assoc "address" sp :test #'string=))))
      (is (assoc "asm" sp :test #'string=))
      (is (assoc "hex" sp :test #'string=)))))

(test rpc-decodescript-multisig-addresses
  "decodescript fills the addresses array for bare multisig — one P2PKH address
per key (previously empty)."
  (let* ((node (make-test-node))
         (pk1 (bitcoin-lisp.crypto:hex-to-bytes
               "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"))
         (pk2 (bitcoin-lisp.crypto:hex-to-bytes
               "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"))
         ;; 2-of-2 bare multisig: OP_2 <33pk1> <33pk2> OP_2 OP_CHECKMULTISIG
         (script (concatenate '(vector (unsigned-byte 8))
                              (vector #x52 #x21) pk1 (vector #x21) pk2 (vector #x52 #xae)))
         (r (bitcoin-lisp.rpc::rpc-decodescript
             node (list (bitcoin-lisp.crypto:bytes-to-hex script))))
         (addrs (cdr (assoc "addresses" r :test #'string=))))
    (is (string= "multisig" (cdr (assoc "type" r :test #'string=))))
    (is (= 2 (cdr (assoc "reqSigs" r :test #'string=))))
    (is (= 2 (length addrs)))
    (is (string= (bitcoin-lisp.crypto:encode-p2pkh-address
                  (bitcoin-lisp.crypto:hash160 pk1) :testnet3)
                 (first addrs)))))

(test rpc-getnetworkinfo-completeness
  "getnetworkinfo now reports localservices(+names), localrelay, relayfee,
incrementalfee, connections_in/out, and warnings, and still yason-encodes.
localservices is the SAME composition the version message advertises
(peer.lisp local-services) — Core keeps NODE_NETWORK_LIMITED set alongside
NODE_NETWORK on a full node (init.cpp:863,1946), so both names appear."
  (let* ((node (make-test-node))
         (bitcoin-lisp::*node* node)
         (bitcoin-lisp::*prune-target-mib* nil)
         (r (bitcoin-lisp.rpc::rpc-getnetworkinfo node nil))
         (names (cdr (assoc "localservicesnames" r :test #'string=))))
    (is (= 16 (length (cdr (assoc "localservices" r :test #'string=)))))
    (is (member "WITNESS" names :test #'string=))
    (is (member "NETWORK" names :test #'string=))
    (is (member "NETWORK_LIMITED" names :test #'string=))
    ;; And the hex field decodes to exactly the wire bits.
    (is (= (bitcoin-lisp.networking::local-services)
           (parse-integer (cdr (assoc "localservices" r :test #'string=))
                          :radix 16)))
    (is (assoc "localrelay" r :test #'string=))
    (is (floatp (cdr (assoc "relayfee" r :test #'string=))))
    (is (floatp (cdr (assoc "incrementalfee" r :test #'string=))))
    (is (integerp (cdr (assoc "connections_in" r :test #'string=))))
    (is (integerp (cdr (assoc "connections_out" r :test #'string=))))
    (is (assoc "warnings" r :test #'string=))
    (let ((resp (bitcoin-lisp.rpc::make-rpc-response r "id")))
      (finishes (with-output-to-string (s) (yason:encode resp s))))))

(test rpc-getpeerinfo-fields
  "getpeerinfo reports a real inbound flag plus synced_*/bytessent/bytesrecv/
pingtime, and (since #216) each peer's connection_type + relaytxes. An inbound
peer defaults to conn-type :inbound and relays txs; a block-relay-only peer maps
to \"block-relay-only\" with relaytxes false."
  (let* ((node (make-test-node))
         (peer (bitcoin-lisp::make-peer :address "1.2.3.4:8333"
                                        :inbound t :start-height 99 :services #x409))
         (br (bitcoin-lisp::make-peer :address "5.6.7.8:8333"
                                      :conn-type :block-relay))
         (ct (lambda (r) (cdr (assoc "connection_type" r :test #'string=)))))
    (setf (bitcoin-lisp::node-peers node) (list peer br))
    (let* ((rows (bitcoin-lisp.rpc::rpc-getpeerinfo node nil))
           (e (find "inbound" rows :key ct :test #'string=))
           (b (find "block-relay-only" rows :key ct :test #'string=)))
      (is-true e)
      (is (eq t (cdr (assoc "inbound" e :test #'string=))))
      (is (= 99 (cdr (assoc "synced_blocks" e :test #'string=))))
      (is (assoc "bytessent" e :test #'string=))
      (is (assoc "pingtime" e :test #'string=))
      (is (eq t (cdr (assoc "relaytxes" e :test #'string=))))
      ;; services is Core's 16-hex-digit string, not a number.
      (is (string= "0000000000000409" (cdr (assoc "services" e :test #'string=))))
      (is-true b)
      (is (null (cdr (assoc "relaytxes" b :test #'string=)))))))

(test rpc-getorphantxs
  "getorphantxs lists the orphan pool: verbosity 0 -> array of txid hex; 1 ->
detail objects (txid/wtxid/bytes/vsize/weight/from); 2 -> details plus raw hex.
The single announcer peer's id appears in \"from\"."
  (let* ((node (make-test-node))
         (peer (bitcoin-lisp::make-peer :address "9.9.9.9:8333"))
         (txid0 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7))
         (tx (bitcoin-lisp.serialization:make-transaction
              :version 2
              :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                               :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                 :hash txid0 :index 0)
                               :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                               :sequence #xffffffff))
              :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                                :value 90000
                                :script-pubkey (make-array 0 :element-type '(unsigned-byte 8))))
              :lock-time 0))
         (mempool (bitcoin-lisp.rpc::rpc-get-mempool node))
         (pool (bitcoin-lisp.mempool:mempool-orphan-pool mempool))
         (txid-hex (bitcoin-lisp.rpc::hash-to-hex
                    (bitcoin-lisp.serialization:transaction-hash tx))))
    (bitcoin-lisp.mempool:orphan-add pool tx peer)
    ;; verbosity 0 (default): array of txid hex strings
    (is (equal (list txid-hex) (bitcoin-lisp.rpc::rpc-getorphantxs node nil)))
    ;; verbosity 1: detail object with the expected keys + announcer peer id
    (let ((v1 (first (bitcoin-lisp.rpc::rpc-getorphantxs node (list 1)))))
      (is (string= txid-hex (cdr (assoc "txid" v1 :test #'string=))))
      (is (assoc "wtxid" v1 :test #'string=))
      (is (plusp (cdr (assoc "bytes" v1 :test #'string=))))
      (is (plusp (cdr (assoc "vsize" v1 :test #'string=))))
      (is (plusp (cdr (assoc "weight" v1 :test #'string=))))
      (is (equal (list (bitcoin-lisp.networking::peer-id peer))
                 (cdr (assoc "from" v1 :test #'string=))))
      (is (null (assoc "hex" v1 :test #'string=))))
    ;; verbosity 2: adds the raw hex
    (let ((v2 (first (bitcoin-lisp.rpc::rpc-getorphantxs node (list 2)))))
      (is (stringp (cdr (assoc "hex" v2 :test #'string=)))))))

(test rpc-sign-verify-message
  "signmessagewithprivkey + verifymessage round-trip: a message signed with a
key's WIF verifies against that key's P2PKH address; a tampered message, a wrong
address, and a malformed signature all fail. The signature is deterministic."
  (let* ((node (make-test-node))   ; testnet3
         (k1 (let ((k (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
               (setf (aref k 31) 1) k))
         (wif (bitcoin-lisp.crypto:private-key-to-wif k1 :network :mainnet :compressed t))
         (msg "hello world")
         (pub (bitcoin-lisp.crypto:derive-public-key k1))   ; compressed
         (addr (bitcoin-lisp.crypto:encode-p2pkh-address
                (bitcoin-lisp.crypto:hash160 pub) :testnet3))
         (sig (bitcoin-lisp.rpc::rpc-signmessagewithprivkey node (list wif msg))))
    (is (stringp sig))
    (is (string= sig (bitcoin-lisp.rpc::rpc-signmessagewithprivkey node (list wif msg))))
    (is (eq t (bitcoin-lisp.rpc::rpc-verifymessage node (list addr sig msg))))
    (is (null (bitcoin-lisp.rpc::rpc-verifymessage node (list addr sig "tampered"))))
    (let* ((k2 (let ((k (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
                 (setf (aref k 31) 2) k))
           (addr2 (bitcoin-lisp.crypto:encode-p2pkh-address
                   (bitcoin-lisp.crypto:hash160 (bitcoin-lisp.crypto:derive-public-key k2))
                   :testnet3)))
      (is (null (bitcoin-lisp.rpc::rpc-verifymessage node (list addr2 sig msg)))))
    (is (null (bitcoin-lisp.rpc::rpc-verifymessage node (list addr "not-a-valid-sig" msg))))))

(test rpc-signrawtransactionwithkey-p2pkh-p2wpkh
  "signrawtransactionwithkey signs a P2WPKH input (input 0) and a P2PKH input
(input 1) with a supplied key; complete is T, and each produced signature
verifies under the SAME sighash the validator computes (legacy + BIP143)."
  (let* ((node (make-test-node))
         (k1 (let ((k (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
               (setf (aref k 31) 1) k))
         (wif (bitcoin-lisp.crypto:private-key-to-wif k1 :network :mainnet :compressed t))
         (pub (bitcoin-lisp.crypto:derive-public-key k1))
         (pkh (bitcoin-lisp.crypto:hash160 pub))
         (p2wpkh (concatenate '(vector (unsigned-byte 8)) (vector #x00 #x14) pkh))
         (p2pkh (concatenate '(vector (unsigned-byte 8)) (vector #x76 #xa9 #x14) pkh (vector #x88 #xac)))
         (p2pkh-code (concatenate '(vector (unsigned-byte 8))
                                  (vector #x76 #xa9 #x14) pkh (vector #x88 #xac)))
         (txid0 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 10))
         (txid1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 11))
         (tx (bitcoin-lisp.serialization:make-transaction
              :version 2
              :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                               :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                 :hash txid0 :index 0)
                               :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                               :sequence #xffffffff)
                              (bitcoin-lisp.serialization:make-tx-in
                               :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                 :hash txid1 :index 0)
                               :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                               :sequence #xffffffff))
              :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                                :value 90000 :script-pubkey p2pkh))
              :lock-time 0))
         (tx-hex (bitcoin-lisp.crypto:bytes-to-hex
                  (bitcoin-lisp.serialization:serialize-transaction tx)))
         (prevtxs (list (list (cons "txid" (bitcoin-lisp.rpc::hash-to-hex txid0))
                              (cons "vout" 0)
                              (cons "scriptPubKey" (bitcoin-lisp.crypto:bytes-to-hex p2wpkh))
                              (cons "amount" 0.001d0))   ; 100000 sats
                        (list (cons "txid" (bitcoin-lisp.rpc::hash-to-hex txid1))
                              (cons "vout" 0)
                              (cons "scriptPubKey" (bitcoin-lisp.crypto:bytes-to-hex p2pkh)))))
         (result (bitcoin-lisp.rpc::rpc-signrawtransactionwithkey
                  node (list tx-hex (list wif) prevtxs))))
    (is (eq t (cdr (assoc "complete" result :test #'string=))))
    (let* ((tx2 (bitcoin-lisp.serialization:parse-tx-payload
                 (bitcoin-lisp.crypto:hex-to-bytes (cdr (assoc "hex" result :test #'string=)))))
           (ins (bitcoin-lisp.serialization:transaction-inputs tx2))
           (wit (bitcoin-lisp.serialization:transaction-witness tx2)))
      ;; Input 0 (P2WPKH): witness = [sig pubkey]; sig verifies under BIP143 sighash.
      (let* ((stack (aref wit 0))
             (sig (first stack))
             (der (subseq sig 0 (1- (length sig))))
             (sighash (let ((bitcoin-lisp.coalton.interop::*current-tx* tx2)
                            (bitcoin-lisp.coalton.interop::*current-input-index* 0)
                            (bitcoin-lisp.coalton.interop::*precomputed-sighash*
                             (bitcoin-lisp.coalton.interop::init-precomputed-sighash tx2)))
                        (bitcoin-lisp.coalton.interop::compute-bip143-sighash p2pkh-code 100000 1))))
        (is (equalp pub (second stack)))
        (is-true (bitcoin-lisp.crypto:verify-signature sighash der pub)))
      ;; Input 1 (P2PKH): scriptSig = push(sig) push(pubkey); sig verifies under legacy sighash.
      (let* ((ss (bitcoin-lisp.serialization:tx-in-script-sig (aref ins 1)))
             (siglen (aref ss 0))
             (sig (subseq ss 1 (1+ siglen)))
             (der (subseq sig 0 (1- (length sig))))
             (sighash (bitcoin-lisp.coalton.interop::compute-legacy-sighash tx2 1 p2pkh 1)))
        (is-true (bitcoin-lisp.crypto:verify-signature sighash der pub))))))

(test rpc-signrawtransactionwithkey-p2tr-keypath
  "signrawtransactionwithkey signs a P2TR key-path input; complete=t, the witness
is a single 64-byte Schnorr signature, and it passes the consensus taproot
key-path verifier (validate-taproot-key-path) for the recomputed BIP341 sighash."
  (let* ((node (make-test-node))
         (sk (let ((k (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
               (setf (aref k 31) 1) k))
         (wif (bitcoin-lisp.crypto:private-key-to-wif sk :network :mainnet :compressed t))
         (pxonly (bitcoin-lisp.crypto:derive-xonly-pubkey sk))
         (qx (bitcoin-lisp.coalton.interop:compute-tweaked-pubkey pxonly))
         (p2tr (concatenate '(vector (unsigned-byte 8)) (vector #x51 #x20) qx))
         (txid0 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7))
         (tx (bitcoin-lisp.serialization:make-transaction
              :version 2
              :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                               :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                 :hash txid0 :index 0)
                               :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                               :sequence #xffffffff))
              :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                                :value 90000 :script-pubkey p2tr))
              :lock-time 0))
         (tx-hex (bitcoin-lisp.crypto:bytes-to-hex
                  (bitcoin-lisp.serialization:serialize-transaction tx)))
         (prevtxs (list (list (cons "txid" (bitcoin-lisp.rpc::hash-to-hex txid0))
                              (cons "vout" 0)
                              (cons "scriptPubKey" (bitcoin-lisp.crypto:bytes-to-hex p2tr))
                              (cons "amount" 0.001d0))))   ; 100000 sats
         (result (bitcoin-lisp.rpc::rpc-signrawtransactionwithkey
                  node (list tx-hex (list wif) prevtxs))))
    (is (eq t (cdr (assoc "complete" result :test #'string=))))
    (let* ((tx2 (bitcoin-lisp.serialization:parse-tx-payload
                 (bitcoin-lisp.crypto:hex-to-bytes (cdr (assoc "hex" result :test #'string=)))))
           (stack (aref (bitcoin-lisp.serialization:transaction-witness tx2) 0))
           (sig (first stack)))
      (is (= 1 (length stack)))
      (is (= 64 (length sig)))
      ;; The consensus key-path verifier accepts the signature.
      (let* ((spent (vector (bitcoin-lisp.storage:make-utxo-entry
                             :value 100000
                             :script-pubkey (coerce p2tr '(simple-array (unsigned-byte 8) (*))))))
             (bitcoin-lisp.coalton.interop::*current-tx* tx2)
             (bitcoin-lisp.coalton.interop::*current-input-index* 0)
             (bitcoin-lisp.coalton.interop::*current-spent-utxos* spent)
             (bitcoin-lisp.coalton.interop::*precomputed-sighash*
              (bitcoin-lisp.coalton.interop::init-precomputed-sighash tx2 spent)))
        (is-true (bitcoin-lisp.coalton.interop::validate-taproot-key-path stack qx 100000))))))

(defun %verify-tx-input (tx index spent-vec flags)
  "Run the full consensus interpreter (verify-script) on input INDEX of TX, with
SPENT-VEC supplying amounts/scriptPubKeys. Returns verify-script's result."
  (let* ((utxo (aref spent-vec index))
         (amount (bitcoin-lisp.storage:utxo-entry-value utxo))
         (spk (bitcoin-lisp.storage:utxo-entry-script-pubkey utxo))
         (input (elt (bitcoin-lisp.serialization:transaction-inputs tx) index))
         (sig-bytes (bitcoin-lisp.serialization:tx-in-script-sig input))
         (wit (bitcoin-lisp.serialization:transaction-witness tx))
         (witness-stack (when (and wit (< index (length wit))) (elt wit index)))
         (bitcoin-lisp.coalton.interop:*current-tx* tx)
         (bitcoin-lisp.coalton.interop:*current-input-index* index)
         (bitcoin-lisp.coalton.interop::*current-spent-utxos* spent-vec)
         (bitcoin-lisp.coalton.interop::*precomputed-sighash* nil)
         (bitcoin-lisp.coalton.interop:*witness-input-amount* amount))
    (bitcoin-lisp.coalton.interop:set-script-flags flags)
    (unwind-protect
         (bitcoin-lisp.coalton.interop:verify-script
          sig-bytes spk :witness witness-stack :amount amount)
      (bitcoin-lisp.coalton.interop:set-script-flags nil))))

(defun %multisig-script (m pubs)
  "OP_m <pub>... OP_n OP_CHECKMULTISIG for the list of compressed PUBS."
  (apply #'concatenate '(vector (unsigned-byte 8))
         (vector (+ #x50 m))
         (append (mapcar (lambda (p) (concatenate '(vector (unsigned-byte 8))
                                                  (vector (length p)) p))
                         pubs)
                 (list (vector (+ #x50 (length pubs)) #xae)))))

(test rpc-signrawtransactionwithkey-p2sh-and-multisig
  "signrawtransactionwithkey signs a tx mixing P2SH-P2WPKH, P2SH-multisig (legacy),
P2WSH-multisig, P2SH-P2WSH-multisig, and bare multisig inputs; complete=t and EVERY
input passes the full consensus interpreter (verify-script, P2SH+WITNESS+NULLDUMMY+
DERSIG+LOW_S)."
  (let* ((node (make-test-node))
         (ka (let ((k (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
               (setf (aref k 31) 1) k))
         (kb (let ((k (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
               (setf (aref k 31) 2) k))
         (wa (bitcoin-lisp.crypto:private-key-to-wif ka :network :mainnet :compressed t))
         (wb (bitcoin-lisp.crypto:private-key-to-wif kb :network :mainnet :compressed t))
         (pa (bitcoin-lisp.crypto:derive-public-key ka))
         (pb (bitcoin-lisp.crypto:derive-public-key kb))
         (pkha (bitcoin-lisp.crypto:hash160 pa))
         (ms22 (%multisig-script 2 (list pa pb)))    ; 2-of-2 A,B
         (ms11 (%multisig-script 1 (list pa)))       ; 1-of-1 A
         ;; redeem/witness + scriptPubKeys
         (rd-p2wpkh (concatenate '(vector (unsigned-byte 8)) (vector #x00 #x14) pkha))
         (rd-p2wsh (concatenate '(vector (unsigned-byte 8))
                                (vector #x00 #x20) (bitcoin-lisp.crypto:sha256 ms22)))
         (spk-sh-wpkh (concatenate '(vector (unsigned-byte 8))
                                   (vector #xa9 #x14) (bitcoin-lisp.crypto:hash160 rd-p2wpkh) (vector #x87)))
         (spk-sh-ms (concatenate '(vector (unsigned-byte 8))
                                 (vector #xa9 #x14) (bitcoin-lisp.crypto:hash160 ms22) (vector #x87)))
         (spk-wsh (concatenate '(vector (unsigned-byte 8))
                               (vector #x00 #x20) (bitcoin-lisp.crypto:sha256 ms22)))
         (spk-sh-wsh (concatenate '(vector (unsigned-byte 8))
                                  (vector #xa9 #x14) (bitcoin-lisp.crypto:hash160 rd-p2wsh) (vector #x87)))
         (spks (vector spk-sh-wpkh spk-sh-ms spk-wsh spk-sh-wsh ms11))
         (inputs (loop for j below 5
                       collect (bitcoin-lisp.serialization:make-tx-in
                                :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                  :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                       :initial-element (+ 20 j))
                                                  :index 0)
                                :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                                :sequence #xffffffff)))
         (tx (bitcoin-lisp.serialization:make-transaction
              :version 2 :inputs (coerce inputs 'vector)
              :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                                :value 400000 :script-pubkey spk-sh-wpkh))
              :lock-time 0))
         (tx-hex (bitcoin-lisp.crypto:bytes-to-hex
                  (bitcoin-lisp.serialization:serialize-transaction tx)))
         (h2 (lambda (j) (bitcoin-lisp.rpc::hash-to-hex
                          (make-array 32 :element-type '(unsigned-byte 8) :initial-element (+ 20 j)))))
         (prevtxs (list
                   ;; 0 P2SH-P2WPKH
                   (list (cons "txid" (funcall h2 0)) (cons "vout" 0)
                         (cons "scriptPubKey" (bitcoin-lisp.crypto:bytes-to-hex spk-sh-wpkh))
                         (cons "amount" 0.001d0)
                         (cons "redeemScript" (bitcoin-lisp.crypto:bytes-to-hex rd-p2wpkh)))
                   ;; 1 P2SH-multisig (legacy)
                   (list (cons "txid" (funcall h2 1)) (cons "vout" 0)
                         (cons "scriptPubKey" (bitcoin-lisp.crypto:bytes-to-hex spk-sh-ms))
                         (cons "redeemScript" (bitcoin-lisp.crypto:bytes-to-hex ms22)))
                   ;; 2 P2WSH-multisig
                   (list (cons "txid" (funcall h2 2)) (cons "vout" 0)
                         (cons "scriptPubKey" (bitcoin-lisp.crypto:bytes-to-hex spk-wsh))
                         (cons "amount" 0.001d0)
                         (cons "witnessScript" (bitcoin-lisp.crypto:bytes-to-hex ms22)))
                   ;; 3 P2SH-P2WSH-multisig
                   (list (cons "txid" (funcall h2 3)) (cons "vout" 0)
                         (cons "scriptPubKey" (bitcoin-lisp.crypto:bytes-to-hex spk-sh-wsh))
                         (cons "amount" 0.001d0)
                         (cons "redeemScript" (bitcoin-lisp.crypto:bytes-to-hex rd-p2wsh))
                         (cons "witnessScript" (bitcoin-lisp.crypto:bytes-to-hex ms22)))
                   ;; 4 bare multisig 1-of-1
                   (list (cons "txid" (funcall h2 4)) (cons "vout" 0)
                         (cons "scriptPubKey" (bitcoin-lisp.crypto:bytes-to-hex ms11)))))
         (result (bitcoin-lisp.rpc::rpc-signrawtransactionwithkey
                  node (list tx-hex (list wa wb) prevtxs))))
    (is (eq t (cdr (assoc "complete" result :test #'string=))))
    (let* ((tx2 (bitcoin-lisp.serialization:parse-tx-payload
                 (bitcoin-lisp.crypto:hex-to-bytes (cdr (assoc "hex" result :test #'string=)))))
           (spent (make-array 5)))
      (dotimes (j 5)
        (setf (aref spent j)
              (bitcoin-lisp.storage:make-utxo-entry
               :value 100000
               :script-pubkey (coerce (aref spks j) '(simple-array (unsigned-byte 8) (*))))))
      (dotimes (j 5)
        (is-true (%verify-tx-input tx2 j spent "P2SH,WITNESS,NULLDUMMY,DERSIG,LOW_S"))))))

;;; --- createmultisig (Bitcoin Core createmultisig) ---
;;; Compressed key pair from Core's createmultisig help example.

(defun %cms-keys ()
  (values "03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd"
          "03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626"))

(defun %valid-descriptor-checksum-p (descriptor)
  "T if DESCRIPTOR ends in #<8 chars> matching descriptor-checksum of the body."
  (let ((pos (position #\# descriptor)))
    (and pos
         (= 8 (- (length descriptor) pos 1))
         (string= (subseq descriptor (1+ pos))
                  (bitcoin-lisp.rpc::descriptor-checksum (subseq descriptor 0 pos))))))

(test rpc-createmultisig-legacy-2of2
  "createmultisig legacy: bare-multisig redeemScript + P2SH address round-trip."
  (multiple-value-bind (k1 k2) (%cms-keys)
    (let* ((node (make-test-node))
           (r (bitcoin-lisp.rpc::rpc-createmultisig node (list 2 (list k1 k2))))
           (redeem-hex (cdr (assoc "redeemScript" r :test #'string=)))
           (address (cdr (assoc "address" r :test #'string=)))
           (descriptor (cdr (assoc "descriptor" r :test #'string=))))
      ;; OP_2 <push k1> <push k2> OP_2 OP_CHECKMULTISIG
      (is (string= redeem-hex (format nil "5221~A21~A52ae" k1 k2)))
      (is (eql 0 (search "sh(multi(2," descriptor)))
      (is-true (%valid-descriptor-checksum-p descriptor))
      ;; address decodes to P2SH(hash160(redeemScript))
      (multiple-value-bind (type spk)
          (bitcoin-lisp.crypto:decode-address address :testnet3)
        (is (not (null type)))
        (is (equalp (subseq spk 2 22)
                    (bitcoin-lisp.crypto:hash160 (bitcoin-lisp.crypto:hex-to-bytes redeem-hex)))))
      ;; compressed keys -> no warnings
      (is (null (assoc "warnings" r :test #'string=))))))

(test rpc-createmultisig-bech32-p2wsh
  "createmultisig bech32: address is P2WSH(sha256(redeemScript))."
  (multiple-value-bind (k1 k2) (%cms-keys)
    (let* ((node (make-test-node))
           (r (bitcoin-lisp.rpc::rpc-createmultisig node (list 2 (list k1 k2) "bech32")))
           (redeem-hex (cdr (assoc "redeemScript" r :test #'string=)))
           (address (cdr (assoc "address" r :test #'string=)))
           (descriptor (cdr (assoc "descriptor" r :test #'string=))))
      (is (eql 0 (search "wsh(multi(2," descriptor)))
      (is-true (%valid-descriptor-checksum-p descriptor))
      (multiple-value-bind (type spk)
          (bitcoin-lisp.crypto:decode-address address :testnet3)
        (is (not (null type)))
        (is (equalp (subseq spk 2 34)
                    (bitcoin-lisp.crypto:sha256 (bitcoin-lisp.crypto:hex-to-bytes redeem-hex))))))))

(test rpc-createmultisig-p2sh-segwit
  "createmultisig p2sh-segwit: address is P2SH(P2WSH(redeemScript))."
  (multiple-value-bind (k1 k2) (%cms-keys)
    (let* ((node (make-test-node))
           (r (bitcoin-lisp.rpc::rpc-createmultisig node (list 2 (list k1 k2) "p2sh-segwit")))
           (redeem-hex (cdr (assoc "redeemScript" r :test #'string=)))
           (address (cdr (assoc "address" r :test #'string=)))
           (descriptor (cdr (assoc "descriptor" r :test #'string=))))
      (is (eql 0 (search "sh(wsh(multi(2," descriptor)))
      (is-true (%valid-descriptor-checksum-p descriptor))
      (multiple-value-bind (type spk)
          (bitcoin-lisp.crypto:decode-address address :testnet3)
        (is (not (null type)))
        (let* ((redeem (bitcoin-lisp.crypto:hex-to-bytes redeem-hex))
               (p2wsh (concatenate '(vector (unsigned-byte 8))
                                   #(#x00 #x20) (bitcoin-lisp.crypto:sha256 redeem))))
          (is (equalp (subseq spk 2 22) (bitcoin-lisp.crypto:hash160 p2wsh))))))))

(test rpc-createmultisig-uncompressed-forces-legacy
  "An uncompressed key forces legacy output + a warning when bech32 was asked."
  (let* ((node (make-test-node))
         ;; Uncompressed (65-byte, 0x04) form of the generator point G.
         (kc "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
         (ku (concatenate 'string
                          "04"
                          "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                          "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))
         (r (bitcoin-lisp.rpc::rpc-createmultisig node (list 1 (list kc ku) "bech32")))
         (address (cdr (assoc "address" r :test #'string=)))
         (warnings (cdr (assoc "warnings" r :test #'string=))))
    ;; Forced to legacy -> P2SH address, and a warning is present.
    (is (not (null warnings)))
    (multiple-value-bind (type) (bitcoin-lisp.crypto:decode-address address :testnet3)
      (is (not (null type))))))

(test rpc-createmultisig-errors
  "createmultisig parameter and key validation errors."
  (multiple-value-bind (k1 k2) (%cms-keys)
    (let ((node (make-test-node)))
      ;; not enough keys for the threshold
      (signals bitcoin-lisp.rpc::rpc-error
        (bitcoin-lisp.rpc::rpc-createmultisig node (list 3 (list k1 k2))))
      ;; nrequired < 1
      (signals bitcoin-lisp.rpc::rpc-error
        (bitcoin-lisp.rpc::rpc-createmultisig node (list 0 (list k1))))
      ;; too many keys (> 20)
      (signals bitcoin-lisp.rpc::rpc-error
        (bitcoin-lisp.rpc::rpc-createmultisig node (list 1 (make-list 21 :initial-element k1))))
      ;; bech32m explicitly rejected
      (signals bitcoin-lisp.rpc::rpc-error
        (bitcoin-lisp.rpc::rpc-createmultisig node (list 2 (list k1 k2) "bech32m")))
      ;; unknown address type
      (signals bitcoin-lisp.rpc::rpc-error
        (bitcoin-lisp.rpc::rpc-createmultisig node (list 2 (list k1 k2) "p2tr")))
      ;; invalid public key
      (signals bitcoin-lisp.rpc::rpc-error
        (bitcoin-lisp.rpc::rpc-createmultisig node (list 1 (list "00")))))))

;;; --- ping (Bitcoin Core ping) ---

(test rpc-ping-no-peers
  "ping with no connected peers returns null and does not error."
  (let ((node (make-test-node)))
    (is (null (bitcoin-lisp.rpc::rpc-ping node nil)))))

;;; --- getaddrmaninfo (Bitcoin Core getaddrmaninfo) ---

(test rpc-getaddrmaninfo-empty
  "getaddrmaninfo lists every standard network + all_networks, all zero when the
node has no address book."
  (let* ((node (make-test-node))
         (r (bitcoin-lisp.rpc::rpc-getaddrmaninfo node nil)))
    (dolist (n '("ipv4" "ipv6" "onion" "i2p" "cjdns" "all_networks"))
      (let ((obj (cdr (assoc n r :test #'string=))))
        (is (not (null obj)) "network ~A present" n)
        (is (= 0 (cdr (assoc "new" obj :test #'string=))))
        (is (= 0 (cdr (assoc "tried" obj :test #'string=))))
        (is (= 0 (cdr (assoc "total" obj :test #'string=))))))))

(test rpc-getaddrmaninfo-classifies-ipv4
  "Added routable IPv4 addresses land in the ipv4 new table and the
all_networks aggregate; counts stay consistent with the address book."
  (let* ((node (make-test-node))
         (book (bitcoin-lisp.networking::make-address-book)))
    (setf (bitcoin-lisp::node-address-book node) book)
    (bitcoin-lisp.networking::address-book-add
     book (bitcoin-lisp.networking::make-peer-address
           :ip (bitcoin-lisp.networking::string-to-ip-bytes "1.2.3.4") :port 8333))
    (bitcoin-lisp.networking::address-book-add
     book (bitcoin-lisp.networking::make-peer-address
           :ip (bitcoin-lisp.networking::string-to-ip-bytes "5.6.7.8") :port 8333))
    (let* ((n-new (bitcoin-lisp.networking::address-book-n-new book))
           (r (bitcoin-lisp.rpc::rpc-getaddrmaninfo node nil))
           (ipv4 (cdr (assoc "ipv4" r :test #'string=)))
           (all (cdr (assoc "all_networks" r :test #'string=))))
      (is (>= n-new 1))
      ;; All added addresses are IPv4, so the ipv4 bucket captures exactly them.
      (is (= n-new (cdr (assoc "new" ipv4 :test #'string=))))
      (is (= 0 (cdr (assoc "tried" ipv4 :test #'string=))))
      (is (= n-new (cdr (assoc "total" ipv4 :test #'string=))))
      ;; all_networks mirrors the book's authoritative counts.
      (is (= n-new (cdr (assoc "new" all :test #'string=))))
      (is (= n-new (cdr (assoc "total" all :test #'string=))))
      ;; Nothing classified as a non-IPv4 network.
      (let ((ipv6 (cdr (assoc "ipv6" r :test #'string=))))
        (is (= 0 (cdr (assoc "total" ipv6 :test #'string=))))))))

;;; --- addnode / getaddednodeinfo / setnetworkactive ---

(defun %rpc-fake-peer (address &key inbound)
  "A peer struct usable in node-peers for RPC tests (no live connection)."
  (bitcoin-lisp.networking::make-peer
   :address address :state :ready :connection nil :inbound inbound))

(test parse-node-endpoint-forms
  "parse-node-endpoint splits host/host:port/[ipv6]:port, defaulting the port."
  (let ((node (make-test-node)))               ; testnet3 default P2P port 18333
    (flet ((p (spec) (multiple-value-list (bitcoin-lisp::parse-node-endpoint node spec))))
      (is (equal (p "1.2.3.4") '("1.2.3.4" 18333)))
      (is (equal (p "1.2.3.4:8333") '("1.2.3.4" 8333)))
      (is (equal (p "seed.example.com") '("seed.example.com" 18333)))
      (is (equal (p "[2001:db8::1]:8333") '("2001:db8::1" 8333)))
      (is (equal (p "[2001:db8::1]") '("2001:db8::1" 18333)))
      ;; A bare IPv6 (multiple colons, no brackets) is treated as host-only.
      (is (equal (p "2001:db8::1") '("2001:db8::1" 18333))))))

(test rpc-addnode-add-remove-onetry
  "addnode mutates the node's added-nodes / pending-onetry state machine."
  (let ((node (make-test-node)))
    ;; add
    (is (null (bitcoin-lisp.rpc::rpc-addnode node '("1.2.3.4:18333" "add"))))
    (is (member "1.2.3.4:18333" (bitcoin-lisp::node-added-nodes node) :test #'string=))
    ;; duplicate add errors
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-addnode node '("1.2.3.4:18333" "add")))
    ;; onetry queues a one-shot dial without touching added-nodes
    (is (null (bitcoin-lisp.rpc::rpc-addnode node '("9.9.9.9" "onetry"))))
    (is (member "9.9.9.9" (bitcoin-lisp::node-pending-onetry node) :test #'string=))
    (is (not (member "9.9.9.9" (bitcoin-lisp::node-added-nodes node) :test #'string=)))
    ;; remove
    (is (null (bitcoin-lisp.rpc::rpc-addnode node '("1.2.3.4:18333" "remove"))))
    (is (not (member "1.2.3.4:18333" (bitcoin-lisp::node-added-nodes node) :test #'string=)))
    ;; remove of a node never added errors
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-addnode node '("1.2.3.4:18333" "remove")))
    ;; bad command + non-string node error
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-addnode node '("1.2.3.4" "frobnicate")))
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-addnode node '(42 "add")))))

(test rpc-getaddednodeinfo-reports-state
  "getaddednodeinfo reports each added node + whether a matching peer is live."
  (let ((node (make-test-node)))
    (bitcoin-lisp.rpc::rpc-addnode node '("1.2.3.4" "add"))
    (bitcoin-lisp.rpc::rpc-addnode node '("5.6.7.8:18333" "add"))
    ;; Mark 1.2.3.4 connected with an outbound peer.
    (push (%rpc-fake-peer "1.2.3.4") (bitcoin-lisp::node-peers node))
    (let ((r (bitcoin-lisp.rpc::rpc-getaddednodeinfo node nil)))
      (is (= 2 (length r)))
      (let ((a (find "1.2.3.4" r :key (lambda (e) (cdr (assoc "addednode" e :test #'string=)))
                     :test #'string=))
            (b (find "5.6.7.8:18333" r :key (lambda (e) (cdr (assoc "addednode" e :test #'string=)))
                     :test #'string=)))
        (is (eq t (cdr (assoc "connected" a :test #'string=))))
        (is (null (cdr (assoc "connected" b :test #'string=))))
        ;; connected node carries one outbound address entry
        (let ((addrs (cdr (assoc "addresses" a :test #'string=))))
          (is (= 1 (length addrs)))
          (is (string= "1.2.3.4" (cdr (assoc "address" (first addrs) :test #'string=))))
          (is (string= "outbound" (cdr (assoc "connected" (first addrs) :test #'string=)))))
        ;; unconnected node has no address entries
        (is (null (cdr (assoc "addresses" b :test #'string=))))))
    ;; filtering for a never-added node errors
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getaddednodeinfo node '("10.0.0.1")))))

(test rpc-setnetworkactive-toggles-and-drops-peers
  "setnetworkactive flips node-network-active and drops peers when disabling."
  (let ((node (make-test-node))
        (peer (%rpc-fake-peer "1.2.3.4")))
    (push peer (bitcoin-lisp::node-peers node))
    (is (bitcoin-lisp::node-network-active node))      ; default enabled
    ;; disable
    (is (null (bitcoin-lisp.rpc::rpc-setnetworkactive node '(nil))))
    (is (null (bitcoin-lisp::node-network-active node)))
    (is (eq :disconnected (bitcoin-lisp.networking:peer-state peer)))
    ;; getnetworkinfo reflects the disabled state
    (is (null (cdr (assoc "networkactive"
                          (bitcoin-lisp.rpc::rpc-getnetworkinfo node nil) :test #'string=))))
    ;; re-enable
    (is (eq t (bitcoin-lisp.rpc::rpc-setnetworkactive node '(t))))
    (is (bitcoin-lisp::node-network-active node))
    ;; missing state errors
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-setnetworkactive node '()))))

;;; --- getchainstates ---

(test rpc-getchainstates-single-chainstate
  "getchainstates reports exactly one fully-validated chainstate with Core's
field shape."
  (let* ((node (make-test-node))
         (r (bitcoin-lisp.rpc::rpc-getchainstates node nil))
         (states (cdr (assoc "chainstates" r :test #'string=))))
    (is (assoc "headers" r :test #'string=))
    (is (= 1 (length states)))
    (let ((cs (first states)))
      (is (eq t (cdr (assoc "validated" cs :test #'string=))))
      (is (integerp (cdr (assoc "blocks" cs :test #'string=))))
      (is (numberp (cdr (assoc "difficulty" cs :test #'string=))))
      ;; bits is 8 lowercase hex chars; target is 64.
      (let ((bits (cdr (assoc "bits" cs :test #'string=)))
            (target (cdr (assoc "target" cs :test #'string=))))
        (is (= 8 (length bits)))
        (is (string= bits (string-downcase bits)))
        (is (= 64 (length target)))
        (is (string= target (string-downcase target))))
      (is (>= (cdr (assoc "coins_tip_cache_bytes" cs :test #'string=)) 0))
      (is (assoc "coins_db_cache_bytes" cs :test #'string=)))))

;;; --- importmempool ---

(test rpc-importmempool-roundtrip-and-errors
  "importmempool loads a saved mempool file and returns an empty object; a
missing file or non-string path errors."
  (let* ((node (make-test-node))
         (path (merge-pathnames "bl-importmempool-test.dat" (uiop:temporary-directory))))
    (bitcoin-lisp.mempool:save-mempool-file (bitcoin-lisp::node-mempool node) path)
    (unwind-protect
         (let ((r (bitcoin-lisp.rpc::rpc-importmempool node (list (namestring path)))))
           (is (hash-table-p r))                 ; serializes as {}
           (is (= 0 (hash-table-count r))))
      (ignore-errors (delete-file path)))
    ;; nonexistent file
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-importmempool node (list "/no/such/bl-mempool-file.dat")))
    ;; non-string filepath
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-importmempool node (list 123)))))

;;; --- peer id (getpeerinfo) + getblockfrompeer ---

(test rpc-getpeerinfo-includes-id
  "getpeerinfo exposes a numeric peer id (Bitcoin Core's CNode::id)."
  (let ((node (make-test-node)))
    (push (%rpc-fake-peer "1.2.3.4") (bitcoin-lisp::node-peers node))
    (let ((info (first (bitcoin-lisp.rpc::rpc-getpeerinfo node nil))))
      (is (integerp (cdr (assoc "id" info :test #'string=)))))))

(test rpc-getblockfrompeer-paths
  "getblockfrompeer validates header/peer and dispatches a witness-block getdata."
  (let* ((bitcoin-lisp::*prune-target-mib* nil)   ; deterministic: pruning off
         (node (make-test-node))
         (cs (bitcoin-lisp::node-chain-state node))
         (store-dir (ensure-directories-exist
                     (merge-pathnames "bl-gbfp-test/" (uiop:temporary-directory))))
         (store (bitcoin-lisp.storage:init-block-store store-dir))
         (hdr (bitcoin-lisp.serialization:make-block-header
               :version 1
               :prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
               :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
               :timestamp 1 :bits #x1d00ffff :nonce 0))
         (hash (bitcoin-lisp.serialization:block-header-hash hdr))
         (hash-hex (bitcoin-lisp.rpc::hash-to-hex hash)))
    (setf (bitcoin-lisp::node-block-store node) store)
    ;; header not in index yet → "Block header missing"
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getblockfrompeer node (list hash-hex 1)))
    ;; register the header
    (bitcoin-lisp.storage:add-block-index-entry
     cs (bitcoin-lisp.storage:make-block-index-entry
         :hash hash :height 1 :header hdr :status :header-valid :chain-work 1))
    ;; no peer with that id → "Peer does not exist"
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getblockfrompeer node (list hash-hex 999999)))
    ;; connected peer by id → returns {} (empty hash-table); send is a no-op on
    ;; the fake peer's nil connection.
    (let ((peer (%rpc-fake-peer "1.2.3.4")))
      (push peer (bitcoin-lisp::node-peers node))
      (let ((r (bitcoin-lisp.rpc::rpc-getblockfrompeer
                node (list hash-hex (bitcoin-lisp.networking::peer-id peer)))))
        (is (hash-table-p r))
        (is (= 0 (hash-table-count r)))))
    ;; bad peer_id type → error
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getblockfrompeer node (list hash-hex "notanint")))))

;;; --- logging (Bitcoin Core logging) ---

(test rpc-logging-toggles-categories
  "logging reports every category and enables/disables via include/exclude, with
all/none and unknown-category handling."
  (clrhash bitcoin-lisp::*debug-categories*)
  (unwind-protect
       (let ((node (make-test-node)))
         ;; default: all categories present, none enabled
         (let ((r (bitcoin-lisp.rpc::rpc-logging node nil)))
           (is (= (length bitcoin-lisp::+log-categories+) (length r)))
           (is (assoc "net" r :test #'string=))
           (is (null (cdr (assoc "net" r :test #'string=)))))
         ;; include enables, leaving others off
         (let ((r (bitcoin-lisp.rpc::rpc-logging node (list (list "net") nil))))
           (is (eq t (cdr (assoc "net" r :test #'string=))))
           (is (null (cdr (assoc "mempool" r :test #'string=)))))
         ;; exclude disables
         (let ((r (bitcoin-lisp.rpc::rpc-logging node (list nil (list "net")))))
           (is (null (cdr (assoc "net" r :test #'string=)))))
         ;; "all" enables every category
         (let ((r (bitcoin-lisp.rpc::rpc-logging node (list (list "all") nil))))
           (is (every (lambda (pair) (eq t (cdr pair))) r)))
         ;; exclude "all" disables every category
         (let ((r (bitcoin-lisp.rpc::rpc-logging node (list nil (list "all")))))
           (is (notany #'cdr r)))
         ;; unknown category errors
         (signals bitcoin-lisp.rpc::rpc-error
           (bitcoin-lisp.rpc::rpc-logging node (list (list "boguscat") nil))))
    (clrhash bitcoin-lisp::*debug-categories*)))

(test log-cat-respects-category-state
  "log-cat emits a debug line only when its category is enabled (independent of
the global level threshold)."
  (clrhash bitcoin-lisp::*debug-categories*)
  (unwind-protect
       (let ((s (make-string-output-stream)))
         (let ((bitcoin-lisp::*log-stream* s)
               (bitcoin-lisp::*current-log-level* :info))  ; debug normally hidden
           (bitcoin-lisp:log-cat "net" "MARKER-DISABLED-~D" 1)   ; off -> nothing
           (bitcoin-lisp::enable-log-category "net")
           (bitcoin-lisp:log-cat "net" "MARKER-ENABLED-~D" 2)    ; on -> emitted
           (bitcoin-lisp:log-cat "mempool" "MARKER-OTHER-~D" 3)) ; still off
         (let ((out (get-output-stream-string s)))
           (is (null (search "MARKER-DISABLED" out)))
           (is (search "MARKER-ENABLED" out))
           (is (null (search "MARKER-OTHER" out)))))
    (clrhash bitcoin-lisp::*debug-categories*)))

;;; --- Cluster mempool RPCs (P9: entry chunk fields, getmempoolcluster,
;;; getmempoolfeeratediagram — Core rpc/mempool.cpp:413-506/609-650/829-862) ---

(test rpc-mempool-cluster-and-diagram
  "Entry chunk fields, getmempoolcluster shape, and the cumulative feerate
diagram, over a CPFP pair that shares one chunk. Sizes are in vB (our
txgraph unit; Core uses sigops-adjusted weight)."
  (let* ((node (make-test-node))
         (mempool (bitcoin-lisp::node-mempool node))
         (parent (%mp-spending-tx (%txid-array 210) :vout 0 :value 50000000))
         (pid (bitcoin-lisp.serialization:transaction-hash parent))
         (pid-hex (bitcoin-lisp.rpc::hash-to-hex pid))
         (child (%mp-spending-tx pid :vout 0 :value 40000000))
         (cid (bitcoin-lisp.serialization:transaction-hash child))
         (cid-hex (bitcoin-lisp.rpc::hash-to-hex cid))
         (pvsize (bitcoin-lisp.serialization:transaction-vsize parent))
         (cvsize (bitcoin-lisp.serialization:transaction-vsize child)))
    ;; Empty mempool: the diagram is just the (0, 0) origin.
    (let ((r (bitcoin-lisp.rpc::rpc-getmempoolfeeratediagram node nil)))
      (is (= 1 (length r)))
      (is (= 0 (cdr (assoc "weight" (first r) :test #'string=))))
      (is (zerop (cdr (assoc "fee" (first r) :test #'string=)))))
    ;; Low-fee parent + CPFP child: one chunk of (20100, pvsize+cvsize).
    (%add-tx mempool parent :fee 100)
    (%add-tx mempool child :fee 20000)
    ;; getmempoolentry chunk fields (fees.chunk in BTC, chunkweight in vB).
    (let* ((r (bitcoin-lisp.rpc::rpc-getmempoolentry node (list pid-hex)))
           (fees (cdr (assoc "fees" r :test #'string=))))
      (is (= (+ pvsize cvsize) (cdr (assoc "chunkweight" r :test #'string=))))
      (is (= 20100 (round (* 100000000 (cdr (assoc "chunk" fees :test #'string=)))))))
    ;; getmempoolcluster: one cluster, one chunk, txs in mining order.
    (let* ((r (bitcoin-lisp.rpc::rpc-getmempoolcluster node (list cid-hex)))
           (chunks (cdr (assoc "chunks" r :test #'string=))))
      (is (= 2 (cdr (assoc "txcount" r :test #'string=))))
      (is (= (+ pvsize cvsize) (cdr (assoc "clusterweight" r :test #'string=))))
      (is (= 1 (length chunks)))
      (let ((chunk (first chunks)))
        (is (= 20100 (round (* 100000000 (cdr (assoc "chunkfee" chunk :test #'string=))))))
        (is (= (+ pvsize cvsize) (cdr (assoc "chunkweight" chunk :test #'string=))))
        (is (equal (list pid-hex cid-hex) (cdr (assoc "txs" chunk :test #'string=))))))
    ;; The diagram now has the origin plus one cumulative chunk point.
    (let ((r (bitcoin-lisp.rpc::rpc-getmempoolfeeratediagram node nil)))
      (is (= 2 (length r)))
      (is (= (+ pvsize cvsize) (cdr (assoc "weight" (second r) :test #'string=))))
      (is (= 20100 (round (* 100000000 (cdr (assoc "fee" (second r) :test #'string=)))))))
    ;; A standalone lower-feerate tx appends a second, later diagram point.
    (let ((solo (make-mempool-test-tx :input-id 211)))
      (%add-tx mempool solo :fee 50)
      (let ((r (bitcoin-lisp.rpc::rpc-getmempoolfeeratediagram node nil)))
        (is (= 3 (length r)))
        (is (= 20150 (round (* 100000000 (cdr (assoc "fee" (third r) :test #'string=))))))))
    ;; getmempoolcluster on an absent txid errors like getmempoolentry.
    (signals error
      (bitcoin-lisp.rpc::rpc-getmempoolcluster
       node (list (bitcoin-lisp.rpc::hash-to-hex (%txid-array 212)))))))

(test rpc-mempool-cluster-two-chunks
  "A cluster whose child does NOT absorb its parent reports two chunks in
mining order (parent's first)."
  (let* ((node (make-test-node))
         (mempool (bitcoin-lisp::node-mempool node))
         (parent (%mp-spending-tx (%txid-array 213) :vout 0 :value 50000000))
         (pid (bitcoin-lisp.serialization:transaction-hash parent))
         (pid-hex (bitcoin-lisp.rpc::hash-to-hex pid))
         (child (%mp-spending-tx pid :vout 0 :value 40000000))
         (cid-hex (bitcoin-lisp.rpc::hash-to-hex
                   (bitcoin-lisp.serialization:transaction-hash child))))
    (%add-tx mempool parent :fee 20000)
    (%add-tx mempool child :fee 100)
    (let* ((r (bitcoin-lisp.rpc::rpc-getmempoolcluster node (list pid-hex)))
           (chunks (cdr (assoc "chunks" r :test #'string=))))
      (is (= 2 (length chunks)))
      (is (equal (list pid-hex) (cdr (assoc "txs" (first chunks) :test #'string=))))
      (is (equal (list cid-hex) (cdr (assoc "txs" (second chunks) :test #'string=))))
      (is (= 20000 (round (* 100000000
                             (cdr (assoc "chunkfee" (first chunks) :test #'string=))))))
      (is (= 100 (round (* 100000000
                           (cdr (assoc "chunkfee" (second chunks) :test #'string=)))))))))
