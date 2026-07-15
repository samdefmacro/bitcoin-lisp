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

(defun %mine-add-entry (mempool tx fee &key (sigops 0))
  "Add TX to MEMPOOL with FEE and SIGOPS (bypassing validation). Returns the
mempool-add result keyword."
  (bitcoin-lisp.mempool:mempool-add
   mempool (bitcoin-lisp.serialization:transaction-hash tx)
   (bitcoin-lisp.mempool:make-entry-from-tx tx fee 1 :sigops sigops :entry-time 1)))

(defun %mine-add (mempool tx fee)
  "Add TX to MEMPOOL with FEE (bypassing validation, like the mempool tests).
Returns the txid."
  (%mine-add-entry mempool tx fee)
  (bitcoin-lisp.serialization:transaction-hash tx))

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

;;;; Cluster-mempool chunk-walk builder (P4)

(defun %mine-locktime-tx (input-id locktime sequence)
  "A standalone test tx with the given LOCKTIME and input SEQUENCE."
  (bitcoin-lisp.serialization:make-transaction
   :version 1
   :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                    :previous-output (bitcoin-lisp.serialization:make-outpoint
                                      :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                           :initial-element input-id)
                                      :index 0)
                    :script-sig (%zeros 10)
                    :sequence sequence))
   :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                     :value 40000000
                     :script-pubkey (%zeros 25)))
   :lock-time locktime))

(defun %template-txids (tmpl)
  (mapcar (lambda (e)
            (bitcoin-lisp.serialization:transaction-hash
             (bitcoin-lisp.mempool:mempool-entry-transaction e)))
          (bitcoin-lisp.mining:block-template-transactions tmpl)))

(test assembler-blockmintxfee-early-out
  "Selection stops at the first chunk whose feerate is strictly below
*block-min-tx-fee-rate* (Core blockMinFeeRate, miner.cpp:299-303); a
zero-fee tx is excluded even by the default 1 sat/kvB floor."
  (let ((bitcoin-lisp:*network* :regtest))
    (multiple-value-bind (cs mp) (%mining-fixture)
      (let* ((rich (make-mempool-test-tx :input-id 30))
             (cheap (make-mempool-test-tx :input-id 31)))
        (%mine-add mp rich 50000)              ; ~526,000 sat/kvB
        (%mine-add mp cheap 2000)              ; ~21,000 sat/kvB
        ;; Floor above CHEAP but below RICH: only RICH is mined.
        (let* ((bitcoin-lisp.mining:*block-min-tx-fee-rate* 100000)
               (txids (%template-txids
                       (bitcoin-lisp.mining:assemble-block-template cs mp))))
          (is (equal (list (bitcoin-lisp.serialization:transaction-hash rich))
                     txids)))
        ;; Default floor (1 sat/kvB): both are mined.
        (is (= 2 (length (%template-txids
                          (bitcoin-lisp.mining:assemble-block-template cs mp)))))))
    ;; A zero-fee tx falls below the default floor.
    (multiple-value-bind (cs mp) (%mining-fixture)
      (%mine-add mp (make-mempool-test-tx :input-id 32) 0)
      (is (null (%template-txids
                 (bitcoin-lisp.mining:assemble-block-template cs mp)))))))

(test assembler-locktime-nonfinal-excluded
  "A chunk containing a non-final transaction (future locktime, non-final
sequence) is skipped (Core TestChunkTransactions/IsFinalTx,
miner.cpp:257-263) without ending selection: worse-feerate final txs are
still mined."
  (let ((bitcoin-lisp:*network* :regtest))
    (multiple-value-bind (cs mp) (%mining-fixture)
      (let* ((nonfinal (%mine-locktime-tx 33 1000 0)) ; height 1000 > next block 1
             (final (make-mempool-test-tx :input-id 34)))
        (%mine-add mp nonfinal 50000)     ; best feerate, but not final
        (%mine-add mp final 1000)
        (let ((txids (%template-txids
                      (bitcoin-lisp.mining:assemble-block-template cs mp))))
          (is (equal (list (bitcoin-lisp.serialization:transaction-hash final))
                     txids)))))))

(test assembler-skip-suppresses-rest-of-cluster
  "A skipped chunk suppresses the LATER chunks of its cluster - including
them without it could be topologically invalid - while other clusters keep
being considered (Core BlockBuilder Skip semantics, txgraph.cpp:3241-3251).
The parent chunk here busts the sigops budget; the child chunk would fit
easily but must not appear."
  (let ((bitcoin-lisp:*network* :regtest))
    (multiple-value-bind (cs mp) (%mining-fixture)
      (let* ((p (make-mempool-test-tx :input-id 35))
             (ptxid (bitcoin-lisp.serialization:transaction-hash p))
             (c (%mp-spending-tx ptxid))
             (x (make-mempool-test-tx :input-id 36)))
        ;; Chunks by feerate: [P] (skipped: 400 + 79601 >= 80000 sigops),
        ;; [X] (included), [C] (suppressed with P's cluster; C alone would fit).
        (is (eq :ok (%mine-add-entry mp p 50000 :sigops 79601)))
        (is (eq :ok (%mine-add-entry mp c 10)))          ; lower feerate than P: own chunk
        (is (eq :ok (%mine-add-entry mp x 2000)))
        (let ((txids (%template-txids
                      (bitcoin-lisp.mining:assemble-block-template cs mp))))
          (is (equal (list (bitcoin-lisp.serialization:transaction-hash x))
                     txids)))))))

(defun %ab-reference-greedy-fees (mempool)
  "The pre-cluster ancestor-package greedy selection (the old
assemble-block-template), kept as the A/B reference: rank txs by
ancestor-package feerate (txid-ascending tiebreak) and include each with its
not-yet-included ancestors when the package fits the weight and sigops
budgets. Returns the total fees collected."
  (let ((included (make-hash-table :test 'equalp))
        (weight bitcoin-lisp.mining:+block-reserved-weight+)
        (sigops bitcoin-lisp.mining::+coinbase-reserved-sigops+)
        (fees 0)
        (ranked '()))
    (bitcoin-lisp.mempool:mempool-for-each
     mempool
     (lambda (txid e) (declare (ignore e))
       (push (cons txid (bitcoin-lisp.mempool:mempool-ancestor-fee-rate mempool txid))
             ranked)))
    (setf ranked (sort ranked (lambda (a b)
                                (cond ((> (cdr a) (cdr b)) t)
                                      ((< (cdr a) (cdr b)) nil)
                                      (t (%shp-txid< (car a) (car b)))))))
    (dolist (pair ranked fees)
      (let ((txid (car pair)))
        (unless (gethash txid included)
          (let ((pkg (list txid))
                (pkg-weight 0) (pkg-sigops 0) (pkg-fees 0))
            (maphash (lambda (a v) (declare (ignore v))
                       (unless (gethash a included) (push a pkg)))
                     (bitcoin-lisp.mempool:mempool-ancestors mempool txid))
            (dolist (t2 pkg)
              (let ((e (bitcoin-lisp.mempool:mempool-get mempool t2)))
                (incf pkg-weight (bitcoin-lisp.serialization:transaction-weight
                                  (bitcoin-lisp.mempool:mempool-entry-transaction e)))
                (incf pkg-sigops (bitcoin-lisp.mempool:mempool-entry-sigops e))
                (incf pkg-fees (bitcoin-lisp.mempool:mempool-entry-fee e))))
            (when (and (<= (+ weight pkg-weight)
                           bitcoin-lisp.validation:+max-block-weight+)
                       (<= (+ sigops pkg-sigops)
                           bitcoin-lisp.validation:+max-block-sigops-cost+))
              (dolist (t2 pkg) (setf (gethash t2 included) t))
              (incf weight pkg-weight)
              (incf sigops pkg-sigops)
              (incf fees pkg-fees))))))))

(defun %ab-populate (rng mempool n max-sigops)
  "Fill MEMPOOL with N seeded-random txs - fresh roots and children spending
1-2 live parents (CPFP chains) - with random fees and sigop costs up to
MAX-SIGOPS. Returns the total fee accepted."
  (let ((live '())
        (next-vout (make-hash-table :test 'equalp))
        (total 0))
    (flet ((fresh-vout (parent)
             (1- (incf (gethash parent next-vout 0)))))
      (dotimes (i n total)
        (let* ((tx (if (or (null live) (< (funcall rng 10) 4))
                       (%shp-root-tx (+ 3000 i))
                       (let* ((k (length live))
                              (p1 (nth (funcall rng k) live))
                              (p2 (when (and (> k 1) (zerop (funcall rng 3)))
                                    (nth (funcall rng k) live))))
                         (%shp-tx (cons (cons p1 (fresh-vout p1))
                                        (when (and p2 (not (equalp p1 p2)))
                                          (list (cons p2 (fresh-vout p2)))))))))
               (fee (+ 1000 (funcall rng 50000)))
               (sigops (if (plusp max-sigops) (funcall rng max-sigops) 0)))
          (when (eq :ok (%mine-add-entry mempool tx fee :sigops sigops))
            (push (bitcoin-lisp.serialization:transaction-hash tx) live)
            (incf total fee)))))))

(test assembler-chunk-walk-ab-vs-greedy
  "A/B property test (cluster mempool P4): on seeded random mempools - CPFP
chains, random fees, sigop costs heavy enough that the sigops budget forces
real selection - the chunk-walk builder collects at least as much fee as the
old ancestor-package greedy it replaced, its template is topologically
valid, and the consensus budgets hold. Without resource pressure both
builders take the entire pool.

The fee comparison is asserted over the aggregate of the seed set, not per
seed: at the very edge of a budget the chunk walk consumes whole chunks and
a skip suppresses the chunk's cluster, so the old greedy can occasionally
squeeze one small package into the final gap that the chunk walk passed
over (seed 981 here loses ~1% that way while the others win 0-6%). Core's
miner accepts exactly this granularity trade-off - its guarantee is the
chunk feerate diagram, not boundary knapsack optimality."
  (let ((bitcoin-lisp:*network* :regtest)
        (new-total 0)
        (old-total 0))
    (dolist (seed '(981 4550 77143 260201 11 3333))
      (multiple-value-bind (cs mp) (%mining-fixture)
        (%ab-populate (%cl-make-rng seed) mp 60 3000)
        (let* ((tmpl (bitcoin-lisp.mining:assemble-block-template cs mp))
               (txs (bitcoin-lisp.mining:block-template-transactions tmpl)))
          (incf new-total (bitcoin-lisp.mining:block-template-total-fees tmpl))
          (incf old-total (%ab-reference-greedy-fees mp))
          ;; Consensus budgets (Core's strict < on both).
          (is (< (bitcoin-lisp.mining:block-template-total-weight tmpl)
                 bitcoin-lisp.validation:+max-block-weight+))
          (is (< (bitcoin-lisp.mining:block-template-total-sigops tmpl)
                 bitcoin-lisp.validation:+max-block-sigops-cost+))
          ;; Topological validity: every selected tx's in-mempool parents
          ;; are selected, and earlier.
          (let ((seen (make-hash-table :test 'equalp)))
            (dolist (e txs)
              (let ((txid (bitcoin-lisp.serialization:transaction-hash
                           (bitcoin-lisp.mempool:mempool-entry-transaction e))))
                (maphash (lambda (p v) (declare (ignore v))
                           (when (bitcoin-lisp.mempool:mempool-has mp p)
                             (is-true (gethash p seen))))
                         (bitcoin-lisp.mempool:mempool-entry-parents e))
                (setf (gethash txid seen) t)))))))
    ;; Fee-optimality vs the old builder, over the whole seed set.
    (is (>= new-total old-total))
    ;; No resource pressure: both builders take everything.
    (multiple-value-bind (cs mp) (%mining-fixture)
      (let ((total (%ab-populate (%cl-make-rng 60259) mp 30 0)))
        (is (= total (bitcoin-lisp.mining:block-template-total-fees
                      (bitcoin-lisp.mining:assemble-block-template cs mp))))
        (is (= total (%ab-reference-greedy-fees mp)))))))

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
          (is (= 4000000 (cdr (assoc "sizelimit" r :test #'string=))))
          (is (member "proposal" (cdr (assoc "capabilities" r :test #'string=)) :test #'string=))
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

(test submitblock-header-only-entry-proceeds
  ;; Standard pool flow: submitheader, then submitblock. The header-only index
  ;; entry must NOT short-circuit as "duplicate" (Core returns "duplicate" only
  ;; when the entry has BLOCK_HAVE_DATA — AcceptBlock fAlreadyHave,
  ;; validation.cpp:4351); a known-invalid block returns "duplicate-invalid"
  ;; (AcceptBlockHeader, validation.cpp:4231-4235).
  (%with-regtest
   (let* ((node (%regtest-node-fixture "subhdrblk"))
          (cs (bitcoin-lisp::node-chain-state node))
          (block (bitcoin-lisp.mining:assemble-full-block
                  cs (bitcoin-lisp::node-mempool node)
                  :coinbase-script-pubkey (%p2sh-optrue-spk))))
     (bitcoin-lisp.mining:mine-block block)
     (let* ((hdr (bitcoin-lisp.serialization:bitcoin-block-header block))
            (hash (bitcoin-lisp.serialization:block-header-hash hdr))
            (hdr-hex (bitcoin-lisp.crypto:bytes-to-hex
                      (flexi-streams:with-output-to-sequence (s)
                        (bitcoin-lisp.serialization::write-block-header s hdr))))
            (blk-hex (bitcoin-lisp.crypto:bytes-to-hex
                      (bitcoin-lisp.serialization:serialize-witness-block block))))
       ;; submitheader indexes the header only.
       (is (null (bitcoin-lisp.rpc::rpc-submitheader node (list hdr-hex))))
       (let ((entry (bitcoin-lisp.storage:get-block-index-entry cs hash)))
         (is (not (null entry)))
         (is (eq :header-valid (bitcoin-lisp.storage:block-index-entry-status entry))))
       ;; submitblock proceeds to full processing — the mined block is not lost.
       (is (null (bitcoin-lisp.rpc::rpc-submitblock node (list blk-hex))))
       (is (= 1 (bitcoin-lisp.storage:current-height cs)))
       ;; Now the data is on disk → resubmit is a true duplicate.
       (is (string= "duplicate" (bitcoin-lisp.rpc::rpc-submitblock node (list blk-hex))))
       ;; A known-invalid entry short-circuits before the data check.
       (setf (bitcoin-lisp.storage:block-index-entry-status
              (bitcoin-lisp.storage:get-block-index-entry cs hash))
             :invalid)
       (is (string= "duplicate-invalid"
                    (bitcoin-lisp.rpc::rpc-submitblock node (list blk-hex))))))))

(test rpc-getblock-v0-witness-round-trip
  ;; getblock verbosity 0 must return the block's wire (witness-complete)
  ;; bytes — Core reads the raw on-disk block (GetRawBlockChecked) — and the
  ;; verbosity argument follows Core ParseVerbosity: booleans allowed
  ;; (false→0, true→1), default 1, verbosity >= 2 gives tx details.
  (%with-regtest
   (let* ((node (%regtest-node-fixture "getblockv0"))
          (block (bitcoin-lisp.mining:assemble-full-block
                  (bitcoin-lisp::node-chain-state node)
                  (bitcoin-lisp::node-mempool node)
                  :coinbase-script-pubkey (%p2sh-optrue-spk))))
     (bitcoin-lisp.mining:mine-block block)
     (let* ((wire (bitcoin-lisp.serialization:serialize-witness-block block))
            (hash-hex (bitcoin-lisp.rpc::hash-to-hex
                       (bitcoin-lisp.serialization:block-header-hash
                        (bitcoin-lisp.serialization:bitcoin-block-header block)))))
       (is (null (bitcoin-lisp.rpc::rpc-submitblock
                  node (list (bitcoin-lisp.crypto:bytes-to-hex wire)))))
       ;; Verbosity 0 → hex of the exact wire bytes; the segwit coinbase's
       ;; witness (reserved value) survives a round-trip.
       (let ((hex (bitcoin-lisp.rpc::rpc-getblock node (list hash-hex 0))))
         (is (stringp hex))
         (is (equalp wire (bitcoin-lisp.crypto:hex-to-bytes hex)))
         (let ((parsed (flexi-streams:with-input-from-sequence
                           (s (bitcoin-lisp.crypto:hex-to-bytes hex))
                         (bitcoin-lisp.serialization:read-bitcoin-block s))))
           (is (bitcoin-lisp.serialization:transaction-has-witness-p
                (first (bitcoin-lisp.serialization:bitcoin-block-transactions parsed))))))
       ;; Boolean/legacy verbosity: false → hex, true → object; absent → object.
       (is (stringp (bitcoin-lisp.rpc::rpc-getblock node (list hash-hex nil))))
       (let ((r (bitcoin-lisp.rpc::rpc-getblock node (list hash-hex t))))
         (is (consp r))
         (is (string= hash-hex (cdr (assoc "hash" r :test #'string=)))))
       (is (consp (bitcoin-lisp.rpc::rpc-getblock node (list hash-hex))))
       ;; Core accepts any integer: 3 behaves like 2 (details; prevout data
       ;; unsupported), negative returns hex.
       (is (consp (bitcoin-lisp.rpc::rpc-getblock node (list hash-hex 3))))
       (is (stringp (bitcoin-lisp.rpc::rpc-getblock node (list hash-hex -1))))
       ;; Non-integer/non-bool verbosity → type error.
       (signals bitcoin-lisp.rpc::rpc-error
         (bitcoin-lisp.rpc::rpc-getblock node (list hash-hex "x")))))))

(test gbt-transactions-data-uses-wire-encoding
  ;; getblocktemplate transactions[].data must be the wire encoding (Core
  ;; EncodeHexTx): a witnessless tx carries NO marker/flag — extended-form
  ;; data makes the miner's reconstructed block fail Core deserialization
  ;; ("Superfluous witness record") — while a segwit tx keeps its witness.
  (let* ((legacy-tx (make-mempool-test-tx))
         (witness-raw (make-witness-test-tx-bytes))
         (witness-tx (flexi-streams:with-input-from-sequence (s witness-raw)
                       (bitcoin-lisp.serialization:read-transaction s)))
         (template (bitcoin-lisp.mining::make-block-template
                    :transactions
                    (list (bitcoin-lisp.mempool:make-entry-from-tx legacy-tx 1000 0)
                          (bitcoin-lisp.mempool:make-entry-from-tx witness-tx 1000 0))))
         (txs (bitcoin-lisp.rpc::%gbt-transactions template)))
    (let ((legacy-data (bitcoin-lisp.crypto:hex-to-bytes
                        (cdr (assoc "data" (first txs) :test #'string=)))))
      (is (equalp (bitcoin-lisp.serialization:serialize-transaction legacy-tx)
                  legacy-data))
      ;; byte 4 is the input count in legacy form — 0x00 would be a marker.
      (is (/= #x00 (aref legacy-data 4))))
    (is (equalp witness-raw
                (bitcoin-lisp.crypto:hex-to-bytes
                 (cdr (assoc "data" (second txs) :test #'string=)))))))

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

(test generatetodescriptor-advances-chain
  ;; Mine to a descriptor-derived coinbase script (raw(51) = OP_TRUE) and confirm
  ;; the chain advances, mirroring generatetoaddress.
  (%with-regtest
   (let* ((node (%regtest-node-fixture "gendesc"))
          (hashes (bitcoin-lisp.rpc::rpc-generatetodescriptor node (list 2 "raw(51)"))))
     (is (= 2 (length hashes)))
     (is (every #'stringp hashes))
     (is (= 2 (bitcoin-lisp.storage:current-height
               (bitcoin-lisp::node-chain-state node))))
     (is (string= (car (last hashes))
                  (bitcoin-lisp.rpc::hash-to-hex
                   (bitcoin-lisp.storage:best-block-hash
                    (bitcoin-lisp::node-chain-state node)))))
     ;; bad descriptor + non-positive count error
     (signals bitcoin-lisp.rpc::rpc-error
       (bitcoin-lisp.rpc::rpc-generatetodescriptor node (list 1 "frobnicate(03ab)")))
     (signals bitcoin-lisp.rpc::rpc-error
       (bitcoin-lisp.rpc::rpc-generatetodescriptor node (list 0 "raw(51)"))))))

(test submitheader-accepts-valid-rejects-orphan
  ;; A mined header whose parent is known validates and is added to the index;
  ;; a header with an unknown parent and malformed hex both error.
  (%with-regtest
   (let* ((node (%regtest-node-fixture "subhdr"))
          (block (bitcoin-lisp.mining:assemble-full-block
                  (bitcoin-lisp::node-chain-state node)
                  (bitcoin-lisp::node-mempool node)
                  :coinbase-script-pubkey (%p2sh-optrue-spk))))
     (bitcoin-lisp.mining:mine-block block)
     (let* ((hdr (bitcoin-lisp.serialization:bitcoin-block-header block))
            (hash (bitcoin-lisp.serialization:block-header-hash hdr))
            (bytes (flexi-streams:with-output-to-sequence (s)
                     (bitcoin-lisp.serialization::write-block-header s hdr)))
            (hex (bitcoin-lisp.crypto:bytes-to-hex bytes)))
       (is (= 80 (length bytes)))
       (is (null (bitcoin-lisp.storage:get-block-index-entry
                  (bitcoin-lisp::node-chain-state node) hash)))
       ;; valid → null, now present
       (is (null (bitcoin-lisp.rpc::rpc-submitheader node (list hex))))
       (is-true (bitcoin-lisp.storage:get-block-index-entry
                 (bitcoin-lisp::node-chain-state node) hash))
       ;; already-known → still null
       (is (null (bitcoin-lisp.rpc::rpc-submitheader node (list hex)))))
     ;; header with an unknown parent → verify error
     (let* ((orphan (bitcoin-lisp.serialization:make-block-header
                     :version 1
                     :prev-block (make-array 32 :element-type '(unsigned-byte 8)
                                                :initial-element 7)
                     :merkle-root (%zeros 32) :timestamp 1296688602
                     :bits #x207fffff :nonce 0))
            (obytes (flexi-streams:with-output-to-sequence (s)
                      (bitcoin-lisp.serialization::write-block-header s orphan))))
       (signals bitcoin-lisp.rpc::rpc-error
         (bitcoin-lisp.rpc::rpc-submitheader
          node (list (bitcoin-lisp.crypto:bytes-to-hex obytes)))))
     ;; malformed hex → deserialization error
     (signals bitcoin-lisp.rpc::rpc-error
       (bitcoin-lisp.rpc::rpc-submitheader node (list "zz"))))))

(test generateblock-empty-submit-advances-chain
  ;; generateblock with no extra txs mines an empty block to the descriptor
  ;; output and (submit=true) advances the chain.
  (%with-regtest
   (let* ((node (%regtest-node-fixture "genblk"))
          (r (bitcoin-lisp.rpc::rpc-generateblock node (list "raw(51)" '()))))
     (is (stringp (cdr (assoc "hash" r :test #'string=))))
     (is (null (assoc "hex" r :test #'string=)))   ; no hex when submitted
     (is (= 1 (bitcoin-lisp.storage:current-height
               (bitcoin-lisp::node-chain-state node))))
     (is (string= (cdr (assoc "hash" r :test #'string=))
                  (bitcoin-lisp.rpc::hash-to-hex
                   (bitcoin-lisp.storage:best-block-hash
                    (bitcoin-lisp::node-chain-state node))))))))

(test generateblock-no-submit-returns-hex-without-advancing
  ;; submit=false returns {hash, hex} and does NOT change the tip.
  (%with-regtest
   (let* ((node (%regtest-node-fixture "genblk-ns"))
          (h0 (bitcoin-lisp.storage:current-height (bitcoin-lisp::node-chain-state node)))
          (r (bitcoin-lisp.rpc::rpc-generateblock node (list "raw(51)" '() nil))))
     (is (stringp (cdr (assoc "hash" r :test #'string=))))
     (is (stringp (cdr (assoc "hex" r :test #'string=))))
     ;; the hex round-trips to a block whose header hashes to the reported hash
     (let* ((bytes (bitcoin-lisp.crypto:hex-to-bytes (cdr (assoc "hex" r :test #'string=))))
            (blk (flexi-streams:with-input-from-sequence (s bytes)
                   (bitcoin-lisp.serialization:read-bitcoin-block s))))
       (is (string= (cdr (assoc "hash" r :test #'string=))
                    (bitcoin-lisp.rpc::hash-to-hex
                     (bitcoin-lisp.serialization:block-header-hash
                      (bitcoin-lisp.serialization:bitcoin-block-header blk))))))
     ;; tip unchanged
     (is (= h0 (bitcoin-lisp.storage:current-height
                (bitcoin-lisp::node-chain-state node)))))))

(test generateblock-includes-raw-tx-and-rejects-bad-output
  ;; A raw (non-coinbase) tx is included and the witness commitment is computed
  ;; over it (submit=false, so consensus validity isn't required); a bogus output
  ;; errors.
  (%with-regtest
   (let* ((node (%regtest-node-fixture "genblk-tx"))
          (tx (bitcoin-lisp.serialization:make-transaction
               :version 1
               :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                                :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                  :hash (%zeros 32) :index 0)
                                :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                                :sequence #xffffffff))
               :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                                 :value 1000
                                 :script-pubkey (coerce #(#x51) '(vector (unsigned-byte 8)))))
               :lock-time 0))
          (tx-hex (bitcoin-lisp.crypto:bytes-to-hex
                   (bitcoin-lisp.serialization:serialize-transaction tx)))
          (r (bitcoin-lisp.rpc::rpc-generateblock node (list "raw(51)" (list tx-hex) nil)))
          (blk (flexi-streams:with-input-from-sequence
                   (s (bitcoin-lisp.crypto:hex-to-bytes (cdr (assoc "hex" r :test #'string=))))
                 (bitcoin-lisp.serialization:read-bitcoin-block s))))
     ;; coinbase + the one supplied tx
     (is (= 2 (length (bitcoin-lisp.serialization:bitcoin-block-transactions blk))))
     ;; bogus output (neither address nor descriptor) errors
     (signals bitcoin-lisp.rpc::rpc-error
       (bitcoin-lisp.rpc::rpc-generateblock node (list "not-an-output" '()))))))
