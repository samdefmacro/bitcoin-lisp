(in-package #:bitcoin-lisp.tests)

;;; Mining / regtest tests.
;;;
;;; PR0 (this file's first section): regtest network params + the no-retarget
;;; difficulty rule + the network-aware PoW limit. Later mining PRs (block
;;; assembler, getblocktemplate, submitblock) add to this suite.

(in-suite :mining-tests)

(defun %zeros (n) (make-array n :element-type '(unsigned-byte 8) :initial-element 0))

;;;; Regtest network parameters

(test regtest-network-params
  (is (equalp bitcoin-lisp.serialization:+regtest-magic+
              (bitcoin-lisp::network-magic :regtest)))
  (is (= 18444 (bitcoin-lisp::network-port :regtest)))
  (is (= 18443 (bitcoin-lisp::network-rpc-port :regtest)))
  (is (null (bitcoin-lisp::network-dns-seeds :regtest))))

(test regtest-genesis-hash-matches-core
  ;; make-genesis-header must hash to Core's regtest genesis
  ;; 0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206.
  (let* ((hdr (bitcoin-lisp::make-genesis-header :regtest))
         (hash (bitcoin-lisp.serialization:block-header-hash hdr)))
    (is (equalp hash (bitcoin-lisp.storage:network-genesis-hash :regtest)))
    (is (string-equal
         "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
         (bitcoin-lisp.crypto:bytes-to-hex (reverse hash))))))

;;;; Network-aware PoW limit

(test regtest-pow-limit-accepts-trivial-bits
  ;; 0x207fffff decodes to a target above the standard PoW limit, so it is
  ;; rejected on testnet/mainnet but accepted under the regtest limit.
  (let ((bitcoin-lisp.storage:*pow-limit-target* bitcoin-lisp.storage:+pow-limit-target+))
    (is (null (bitcoin-lisp.storage:derive-target #x207fffff))))
  (let ((bitcoin-lisp.storage:*pow-limit-target* bitcoin-lisp.storage:+regtest-pow-limit-target+))
    (is-true (bitcoin-lisp.storage:derive-target #x207fffff))))

;;;; No-retarget difficulty (fPowNoRetargeting)

(test regtest-difficulty-never-retargets
  ;; Every regtest block inherits the previous block's bits — even at what would
  ;; be a 2016-block retarget boundary on other networks.
  (let* ((hdr (bitcoin-lisp.serialization:make-block-header
               :version 1 :prev-block (%zeros 32) :merkle-root (%zeros 32)
               :timestamp 1296688602 :bits #x207fffff :nonce 0))
         (prev (bitcoin-lisp.storage:make-block-index-entry
                :hash (%zeros 32) :header hdr :height 0)))
    (let ((bitcoin-lisp:*network* :regtest))
      ;; non-boundary
      (is (= #x207fffff (bitcoin-lisp.validation::get-expected-bits 1 prev)))
      ;; boundary height — regtest still inherits, no retarget
      (is (= #x207fffff (bitcoin-lisp.validation::get-expected-bits 2016 prev))))))

;;;; Block assembler

(defun %mining-fixture ()
  "(values chain-state mempool) — a regtest chain-state sitting at genesis, plus
an empty mempool."
  (let* ((cs (bitcoin-lisp.storage:make-chain-state))
         (ghash (bitcoin-lisp.storage:network-genesis-hash :regtest))
         (ghdr (bitcoin-lisp::make-genesis-header :regtest))
         (gentry (bitcoin-lisp.storage:make-block-index-entry
                  :hash ghash :header ghdr :height 0)))
    (bitcoin-lisp.storage:add-block-index-entry cs gentry)
    (bitcoin-lisp.storage:update-chain-tip cs ghash 0)
    (values cs (bitcoin-lisp.mempool:make-mempool))))

(defun %mine-add (mempool tx fee)
  "Add TX to MEMPOOL with FEE (bypassing validation, like the mempool tests).
Returns the txid."
  (let ((txid (bitcoin-lisp.serialization:transaction-hash tx)))
    (bitcoin-lisp.mempool:mempool-add
     mempool txid
     (bitcoin-lisp.mempool:make-entry-from-tx tx fee 1 :entry-time 1))
    txid))

(test assembler-empty-mempool
  (let ((bitcoin-lisp:*network* :regtest))
    (multiple-value-bind (cs mp) (%mining-fixture)
      (let ((tmpl (bitcoin-lisp.mining:assemble-block-template cs mp)))
        (is (= 1 (bitcoin-lisp.mining:block-template-height tmpl)))
        (is (= #x207fffff (bitcoin-lisp.mining:block-template-bits tmpl)))
        (is (null (bitcoin-lisp.mining:block-template-transactions tmpl)))
        ;; empty block: coinbase value is exactly the height-1 subsidy (50 BTC)
        (is (= (bitcoin-lisp.validation:calculate-block-subsidy 1)
               (bitcoin-lisp.mining:block-template-coinbase-value tmpl)))
        ;; default witness commitment script is the 38-byte OP_RETURN form
        (let ((s (bitcoin-lisp.mining:block-template-default-witness-commitment-script tmpl)))
          (is (= 38 (length s)))
          (is (= #x6a (aref s 0)))
          (is (= #xaa (aref s 2))))))))

(test assembler-cpfp-package-parents-first
  ;; A low-fee parent + high-fee child are both selected, parent before child,
  ;; and the coinbase value includes both fees.
  (let ((bitcoin-lisp:*network* :regtest))
    (multiple-value-bind (cs mp) (%mining-fixture)
      (let* ((funding (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7))
             (parent (%pkg-tx funding 0 (- 100000000 100)))
             (pid (bitcoin-lisp.serialization:transaction-hash parent))
             (child (%pkg-tx pid 0 (- (- 100000000 100) 50000)))
             (cid (bitcoin-lisp.serialization:transaction-hash child)))
        (%mine-add mp parent 100)
        (%mine-add mp child 50000)
        (let* ((tmpl (bitcoin-lisp.mining:assemble-block-template cs mp))
               (txs (bitcoin-lisp.mining:block-template-transactions tmpl))
               (txids (mapcar (lambda (e)
                                (bitcoin-lisp.serialization:transaction-hash
                                 (bitcoin-lisp.mempool:mempool-entry-transaction e)))
                              txs)))
          (is (= 2 (length txs)))
          ;; parent must precede child (topological order)
          (is (equalp pid (first txids)))
          (is (equalp cid (second txids)))
          (is (= (+ 100 50000)
                 (bitcoin-lisp.mining:block-template-total-fees tmpl)))
          (is (= (+ (bitcoin-lisp.validation:calculate-block-subsidy 1) 100 50000)
                 (bitcoin-lisp.mining:block-template-coinbase-value tmpl))))))))

;;;; Mining RPCs

(test rpc-getblocktemplate-shape
  (let ((bitcoin-lisp:*network* :regtest))
    (multiple-value-bind (cs mp) (%mining-fixture)
      (let ((node (bitcoin-lisp::make-node :network :regtest)))
        (setf (bitcoin-lisp::node-chain-state node) cs
              (bitcoin-lisp::node-mempool node) mp
              (bitcoin-lisp::node-utxo-set node) (bitcoin-lisp.storage:make-utxo-set))
        (let ((r (bitcoin-lisp.rpc::rpc-getblocktemplate node nil)))
          (is (= 1 (cdr (assoc "height" r :test #'string=))))
          (is (stringp (cdr (assoc "previousblockhash" r :test #'string=))))
          (is (= (bitcoin-lisp.validation:calculate-block-subsidy 1)
                 (cdr (assoc "coinbasevalue" r :test #'string=))))
          (is (string= "207fffff" (cdr (assoc "bits" r :test #'string=))))
          (is (= 4000000 (cdr (assoc "weightlimit" r :test #'string=))))
          ;; 38-byte commitment script → 76 hex chars, 6a24aa21a9ed prefix
          (let ((dwc (cdr (assoc "default_witness_commitment" r :test #'string=))))
            (is (= 76 (length dwc)))
            (is (string= "6a24aa21a9ed" (subseq dwc 0 12)))))))))

(test rpc-getmininginfo-shape
  (let ((bitcoin-lisp:*network* :regtest))
    (multiple-value-bind (cs mp) (%mining-fixture)
      (let ((node (bitcoin-lisp::make-node :network :regtest)))
        (setf (bitcoin-lisp::node-chain-state node) cs
              (bitcoin-lisp::node-mempool node) mp)
        (let ((r (bitcoin-lisp.rpc::rpc-getmininginfo node nil)))
          (is (= 0 (cdr (assoc "blocks" r :test #'string=))))
          (is (string= "regtest" (cdr (assoc "chain" r :test #'string=))))
          (is (= 0 (cdr (assoc "pooledtx" r :test #'string=))))
          (is (stringp (cdr (assoc "bits" r :test #'string=)))))))))
