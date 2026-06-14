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

(test regtest-startup-dispatchers-handle-regtest
  ;; Per-network dispatchers reached during node startup / validation must
  ;; handle :regtest (a missing ecase case crashed start-node).
  (is (integerp (bitcoin-lisp::prune-after-height :regtest)))
  (is (null (bitcoin-lisp.networking::network-checkpoints :regtest))))

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
            (is (string= "6a24aa21a9ed" (subseq dwc 0 12))))
          ;; rules: regtest activates all soft forks by height 1.
          (let ((rules (cdr (assoc "rules" r :test #'string=))))
            (is (member "csv" rules :test #'string=))
            (is (member "!segwit" rules :test #'string=))
            (is (member "taproot" rules :test #'string=)))
          (is (= 0 (cdr (assoc "vbrequired" r :test #'string=))))
          (is (stringp (cdr (assoc "longpollid" r :test #'string=)))))))))

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

;;;; Block construction + CPU mining + submitblock (regtest, disk-backed)

(defmacro %with-regtest (&body body)
  "Bind *network* and the active PoW limit to regtest for BODY."
  `(let ((bitcoin-lisp:*network* :regtest)
         (bitcoin-lisp.storage:*pow-limit-target*
           bitcoin-lisp.storage:+regtest-pow-limit-target+))
     ,@body))

(defun %regtest-node-fixture (suffix)
  "(values node) — a regtest node at genesis with disk-backed chain-state /
block-store / utxo-set, ready for activate-block. Call inside %with-regtest."
  (let* ((base (ensure-directories-exist
                (merge-pathnames (format nil "test-regtest-mine-~A/" suffix)
                                 (uiop:temporary-directory))))
         (cs (bitcoin-lisp.storage:init-chain-state base :network :regtest))
         (store (bitcoin-lisp.storage:init-block-store base))
         (ghash (bitcoin-lisp.storage:best-block-hash cs))
         (ghdr (bitcoin-lisp::make-genesis-header :regtest))
         (node (bitcoin-lisp::make-node :network :regtest)))
    (clrhash bitcoin-lisp.validation::*block-undo-data*)
    (bitcoin-lisp.storage:add-block-index-entry
     cs (bitcoin-lisp.storage:make-block-index-entry
         :hash ghash :height 0 :chain-work 1 :status :valid :header ghdr))
    (setf (bitcoin-lisp::node-chain-state node) cs
          (bitcoin-lisp::node-utxo-set node) (bitcoin-lisp.storage:make-utxo-set)
          (bitcoin-lisp::node-block-store node) store
          (bitcoin-lisp::node-mempool node) (bitcoin-lisp.mempool:make-mempool))
    node))

(test build-coinbase-transaction-shape
  (%with-regtest
   (let* ((spk (%p2sh-optrue-spk))
          (commit (bitcoin-lisp.mining:build-witness-commitment-script (%zeros 32)))
          (cb (bitcoin-lisp.mining:build-coinbase-transaction
               1 5000000000 :script-pubkey spk :witness-commitment-script commit)))
     ;; one input, null prevout, BIP34 height-1 (OP_1) scriptSig >= 2 bytes
     (let ((in (elt (bitcoin-lisp.serialization:transaction-inputs cb) 0)))
       (is-true (bitcoin-lisp.serialization:coinbase-input-p in))
       (is (>= (length (bitcoin-lisp.serialization:tx-in-script-sig in)) 2))
       (is (= #x51 (aref (bitcoin-lisp.serialization:tx-in-script-sig in) 0))))
     ;; payout + commitment outputs
     (is (= 2 (length (bitcoin-lisp.serialization:transaction-outputs cb))))
     (is (= 5000000000 (bitcoin-lisp.serialization:tx-out-value
                        (elt (bitcoin-lisp.serialization:transaction-outputs cb) 0))))
     ;; reserved witness value present (so it serializes as a segwit tx)
     (is-true (bitcoin-lisp.serialization:transaction-has-witness-p cb)))))

(test mine-block-satisfies-pow
  (%with-regtest
   (let ((node (%regtest-node-fixture "mine")))
     (let ((block (bitcoin-lisp.mining:assemble-full-block
                   (bitcoin-lisp::node-chain-state node)
                   (bitcoin-lisp::node-mempool node)
                   :coinbase-script-pubkey (%p2sh-optrue-spk))))
       (is-true (bitcoin-lisp.mining:mine-block block))
       (is-true (bitcoin-lisp.validation:check-proof-of-work
                 (bitcoin-lisp.serialization:bitcoin-block-header block)))))))

(test submitblock-round-trip
  ;; Build + mine a regtest block at the genesis tip, serialize it, submit the
  ;; hex via the RPC — accepted (null), tip advances, resubmit → "duplicate".
  (%with-regtest
   (let* ((node (%regtest-node-fixture "submit"))
          (block (bitcoin-lisp.mining:assemble-full-block
                  (bitcoin-lisp::node-chain-state node)
                  (bitcoin-lisp::node-mempool node)
                  :coinbase-script-pubkey (%p2sh-optrue-spk))))
     (bitcoin-lisp.mining:mine-block block)
     (let ((hex (bitcoin-lisp.crypto:bytes-to-hex
                 (bitcoin-lisp.serialization:serialize-witness-block block))))
       ;; accepted → null
       (is (null (bitcoin-lisp.rpc::rpc-submitblock node (list hex))))
       (is (= 1 (bitcoin-lisp.storage:current-height
                 (bitcoin-lisp::node-chain-state node))))
       ;; resubmit the same block → duplicate
       (is (string= "duplicate" (bitcoin-lisp.rpc::rpc-submitblock node (list hex))))))))

(test generatetoaddress-advances-chain
  (%with-regtest
   (let* ((node (%regtest-node-fixture "gen"))
          (addr (bitcoin-lisp.crypto:encode-p2pkh-address
                 (make-array 20 :element-type '(unsigned-byte 8) :initial-element 3)
                 :regtest))
          (hashes (bitcoin-lisp.rpc::rpc-generatetoaddress node (list 3 addr))))
     (is (= 3 (length hashes)))
     (is (every #'stringp hashes))
     (is (= 3 (bitcoin-lisp.storage:current-height
               (bitcoin-lisp::node-chain-state node))))
     ;; the tip is the last generated hash
     (is (string= (car (last hashes))
                  (bitcoin-lisp.rpc::hash-to-hex
                   (bitcoin-lisp.storage:best-block-hash
                    (bitcoin-lisp::node-chain-state node))))))))
