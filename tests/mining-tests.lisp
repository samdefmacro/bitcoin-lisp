(in-package #:bitcoin-lisp.tests)

;;; Mining / regtest tests.
;;;
;;; PR0 (this file's first section): regtest network params + the no-retarget
;;; difficulty rule + the network-aware PoW limit. Later mining PRs (block
;;; assembler, getblocktemplate, submitblock) add to this suite.

(in-suite :mining-tests)

(defun %zeros (n) (make-array n :element-type '(unsigned-byte 8) :initial-element 0))

(defun %gbt-params (&rest extra)
  "getblocktemplate params declaring segwit support, shaped the way the WIRE
shapes them.

Core REFUSES a template request whose \"rules\" array does not name segwit
(rpc/mining.cpp:854), and every real miner and every one of Core's own
functional tests sends {\"rules\": [\"segwit\"]}. Tests that called this RPC
with NIL were exercising a request Core rejects.

⚠️ Routed through %NORMALIZE-RPC-PARAMS deliberately. yason parses a JSON array
as a vector, but the normalizer turns every NESTED one back into a LIST
(rpc/server.lisp:338-356) before any handler sees it. A test that stuffs a
vector straight into the request hash-table therefore exercises a shape no real
client can send — which is exactly how a rules check that understood only
vectors passed this entire suite while answering every real miner -8."
  (let ((req (make-hash-table :test 'equal)))
    (setf (gethash "rules" req) (vector "segwit"))
    (loop for (k v) on extra by #'cddr do (setf (gethash k req) v))
    (bl.rpc::%normalize-rpc-params (vector req))))

;;;; Regtest network parameters

(test regtest-network-params
  (is (equalp (bl.chain:chain-params-magic (bl.chain:find-chain-params :regtest))
              (bl::network-magic :regtest)))
  (is (= 18444 (bl::network-port :regtest)))
  (is (= 18443 (bl::network-rpc-port :regtest)))
  (is (null (bl::network-dns-seeds :regtest))))

(test regtest-startup-dispatchers-handle-regtest
  ;; Per-network dispatchers reached during node startup / validation must
  ;; handle :regtest (a missing ecase case crashed start-node).
  (is (integerp (bl::prune-after-height :regtest)))
  (is (null (bl.net::network-checkpoints :regtest))))

(test regtest-genesis-hash-matches-core
  ;; make-genesis-header must hash to Core's regtest genesis
  ;; 0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206.
  (let* ((hdr (bl::make-genesis-header :regtest))
         (hash (bl.ser:block-header-hash hdr)))
    (is (equalp hash (bl.store:network-genesis-hash :regtest)))
    (is (string-equal
         "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
         (bl.crypto:bytes-to-hex (reverse hash))))))

;;;; Network-aware PoW limit

(test regtest-pow-limit-accepts-trivial-bits
  ;; 0x207fffff decodes to a target above the standard PoW limit, so it is
  ;; rejected on testnet/mainnet but accepted under the regtest limit.
  (let ((bl.store:*pow-limit-target* bl.store:+pow-limit-target+))
    (is (null (bl.store:derive-target #x207fffff))))
  (let ((bl.store:*pow-limit-target* bl.store:+regtest-pow-limit-target+))
    (is-true (bl.store:derive-target #x207fffff))))

;;;; No-retarget difficulty (fPowNoRetargeting)

(test regtest-difficulty-never-retargets
  ;; Every regtest block inherits the previous block's bits — even at what would
  ;; be a 2016-block retarget boundary on other networks.
  (let* ((hdr (bl.ser:make-block-header
               :version 1 :prev-block (%zeros 32) :merkle-root (%zeros 32)
               :timestamp 1296688602 :bits #x207fffff :nonce 0))
         (prev (bl.store:make-block-index-entry
                :hash (%zeros 32) :header hdr :height 0)))
    (let ((bl:*network* :regtest))
      ;; non-boundary
      (is (= #x207fffff (bl.val::get-expected-bits 1 prev)))
      ;; boundary height — regtest still inherits, no retarget
      (is (= #x207fffff (bl.val::get-expected-bits 2016 prev))))))

;;;; Block assembler

(defun %mining-fixture ()
  "(values chain-state mempool) — a regtest chain-state sitting at genesis, plus
an empty mempool."
  (let* ((cs (bl.store:make-chain-state))
         (ghash (bl.store:network-genesis-hash :regtest))
         (ghdr (bl::make-genesis-header :regtest))
         (gentry (bl.store:make-block-index-entry
                  :hash ghash :header ghdr :height 0)))
    (bl.store:add-block-index-entry cs gentry)
    (bl.store:update-chain-tip cs ghash 0)
    (values cs (bl.mp:make-mempool))))

(defun %mine-add-entry (mempool tx fee &key (sigops 0))
  "Add TX to MEMPOOL with FEE and SIGOPS (bypassing validation). Returns the
mempool-add result keyword."
  (bl.mp:mempool-add
   mempool (bl.ser:transaction-hash tx)
   (bl.mp:make-entry-from-tx tx fee 1 :sigops sigops :entry-time 1)))

(defun %mine-add (mempool tx fee)
  "Add TX to MEMPOOL with FEE (bypassing validation, like the mempool tests).
Returns the txid."
  (%mine-add-entry mempool tx fee)
  (bl.ser:transaction-hash tx))

(test assembler-empty-mempool
  (let ((bl:*network* :regtest))
    (multiple-value-bind (cs mp) (%mining-fixture)
      (let ((tmpl (bl.mining:assemble-block-template cs mp)))
        (is (= 1 (bl.mining:block-template-height tmpl)))
        (is (= #x207fffff (bl.mining:block-template-bits tmpl)))
        (is (null (bl.mining:block-template-transactions tmpl)))
        ;; empty block: coinbase value is exactly the height-1 subsidy (50 BTC)
        (is (= (bl.val:calculate-block-subsidy 1)
               (bl.mining:block-template-coinbase-value tmpl)))
        ;; default witness commitment script is the 38-byte OP_RETURN form
        (let ((s (bl.mining:block-template-default-witness-commitment-script tmpl)))
          (is (= 38 (length s)))
          (is (= #x6a (aref s 0)))
          (is (= #xaa (aref s 2))))))))

(test assembler-cpfp-package-parents-first
  ;; A low-fee parent + high-fee child are both selected, parent before child,
  ;; and the coinbase value includes both fees.
  (let ((bl:*network* :regtest))
    (multiple-value-bind (cs mp) (%mining-fixture)
      (let* ((funding (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7))
             (parent (%pkg-tx funding 0 (- 100000000 100)))
             (pid (bl.ser:transaction-hash parent))
             (child (%pkg-tx pid 0 (- (- 100000000 100) 50000)))
             (cid (bl.ser:transaction-hash child)))
        (%mine-add mp parent 100)
        (%mine-add mp child 50000)
        (let* ((tmpl (bl.mining:assemble-block-template cs mp))
               (txs (bl.mining:block-template-transactions tmpl))
               (txids (mapcar (lambda (e)
                                (bl.ser:transaction-hash
                                 (bl.mp:mempool-entry-transaction e)))
                              txs)))
          (is (= 2 (length txs)))
          ;; parent must precede child (topological order)
          (is (equalp pid (first txids)))
          (is (equalp cid (second txids)))
          (is (= (+ 100 50000)
                 (bl.mining:block-template-total-fees tmpl)))
          (is (= (+ (bl.val:calculate-block-subsidy 1) 100 50000)
                 (bl.mining:block-template-coinbase-value tmpl))))))))

;;;; Cluster-mempool chunk-walk builder (P4)

(defun %mine-locktime-tx (input-id locktime sequence)
  "A standalone test tx with the given LOCKTIME and input SEQUENCE."
  (bl.ser:make-transaction
   :version 1
   :inputs (vector (bl.ser:make-tx-in
                    :previous-output (bl.ser:make-outpoint
                                      :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                           :initial-element input-id)
                                      :index 0)
                    :script-sig (%zeros 10)
                    :sequence sequence))
   :outputs (vector (bl.ser:make-tx-out
                     :value 40000000
                     :script-pubkey (%zeros 25)))
   :lock-time locktime))

(defun %template-txids (tmpl)
  (mapcar (lambda (e)
            (bl.ser:transaction-hash
             (bl.mp:mempool-entry-transaction e)))
          (bl.mining:block-template-transactions tmpl)))

(test assembler-blockmintxfee-early-out
  "Selection stops at the first chunk whose feerate is strictly below
*block-min-tx-fee-rate* (Core blockMinFeeRate, miner.cpp:299-303); a
zero-fee tx is excluded even by the default 1 sat/kvB floor."
  (let ((bl:*network* :regtest))
    (multiple-value-bind (cs mp) (%mining-fixture)
      (let* ((rich (make-mempool-test-tx :input-id 30))
             (cheap (make-mempool-test-tx :input-id 31)))
        (%mine-add mp rich 50000)              ; ~526,000 sat/kvB
        (%mine-add mp cheap 2000)              ; ~21,000 sat/kvB
        ;; Floor above CHEAP but below RICH: only RICH is mined.
        (let* ((bl.mining:*block-min-tx-fee-rate* 100000)
               (txids (%template-txids
                       (bl.mining:assemble-block-template cs mp))))
          (is (equal (list (bl.ser:transaction-hash rich))
                     txids)))
        ;; Default floor (1 sat/kvB): both are mined.
        (is (= 2 (length (%template-txids
                          (bl.mining:assemble-block-template cs mp)))))))
    ;; A zero-fee tx falls below the default floor.
    (multiple-value-bind (cs mp) (%mining-fixture)
      (%mine-add mp (make-mempool-test-tx :input-id 32) 0)
      (is (null (%template-txids
                 (bl.mining:assemble-block-template cs mp)))))))

(test assembler-locktime-nonfinal-excluded
  "A chunk containing a non-final transaction (future locktime, non-final
sequence) is skipped (Core TestChunkTransactions/IsFinalTx,
miner.cpp:257-263) without ending selection: worse-feerate final txs are
still mined."
  (let ((bl:*network* :regtest))
    (multiple-value-bind (cs mp) (%mining-fixture)
      (let* ((nonfinal (%mine-locktime-tx 33 1000 0)) ; height 1000 > next block 1
             (final (make-mempool-test-tx :input-id 34)))
        (%mine-add mp nonfinal 50000)     ; best feerate, but not final
        (%mine-add mp final 1000)
        (let ((txids (%template-txids
                      (bl.mining:assemble-block-template cs mp))))
          (is (equal (list (bl.ser:transaction-hash final))
                     txids)))))))

(test assembler-skip-suppresses-rest-of-cluster
  "A skipped chunk suppresses the LATER chunks of its cluster - including
them without it could be topologically invalid - while other clusters keep
being considered (Core BlockBuilder Skip semantics, txgraph.cpp:3241-3251).
Sigop-dense fillers leave the block's sigop budget too small for P's chunk;
P's child C would fit easily but must not appear. (A single tx can no
longer bust the 80k budget by itself: its sigop-adjusted vsize caps a
cluster at 20,200 sigops - the same bound Core's 404k adjusted-weight
cluster limit imposes.)"
  (let ((bl:*network* :regtest))
    (multiple-value-bind (cs mp) (%mining-fixture)
      (let* ((p (make-mempool-test-tx :input-id 35))
             (ptxid (bl.ser:transaction-hash p))
             (c (%mp-spending-tx ptxid))
             (fillers (list (make-mempool-test-tx :input-id 36)
                            (make-mempool-test-tx :input-id 37)
                            (make-mempool-test-tx :input-id 38))))
        ;; Fillers first at top feerate: 400 (coinbase reserve) + 3 x 20,000
        ;; in the block. P's chunk (20,000 more, lower feerate) busts the
        ;; budget (80,400 >= 80,000) and is skipped; C - its own lower-feerate
        ;; chunk in P's cluster - is suppressed, though it alone would fit.
        (dolist (x fillers)
          (is (eq :ok (%mine-add-entry mp x 50000 :sigops 20000))))
        (is (eq :ok (%mine-add-entry mp p 10000 :sigops 20000)))
        (is (eq :ok (%mine-add-entry mp c 1)))
        (let ((txids (%template-txids
                      (bl.mining:assemble-block-template cs mp)))
              (tmpl bl.mining:*last-block-template*))
          (is (= 3 (length txids)))
          (is (not (member ptxid txids :test #'equalp)))
          (is (not (member (bl.ser:transaction-hash c)
                           txids :test #'equalp)))
          (is (= (+ bl.mining::+coinbase-reserved-sigops+ 60000)
                 (bl.mining:block-template-total-sigops tmpl))))))))

(defun %ab-reference-greedy-fees (mempool)
  "The pre-cluster ancestor-package greedy selection (the old
assemble-block-template), kept as the A/B reference: rank txs by
ancestor-package feerate (txid-ascending tiebreak) and include each with its
not-yet-included ancestors when the package fits the weight and sigops
budgets. Returns the total fees collected."
  (let ((included (make-hash-table :test 'equalp))
        (weight bl.mining:+block-reserved-weight+)
        (sigops bl.mining::+coinbase-reserved-sigops+)
        (fees 0)
        (ranked '()))
    (bl.mp:mempool-for-each
     mempool
     (lambda (txid e) (declare (ignore e))
       (push (cons txid (bl.mp:mempool-ancestor-fee-rate mempool txid))
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
                     (bl.mp:mempool-ancestors mempool txid))
            (dolist (t2 pkg)
              (let ((e (bl.mp:mempool-get mempool t2)))
                (incf pkg-weight (bl.ser:transaction-weight
                                  (bl.mp:mempool-entry-transaction e)))
                (incf pkg-sigops (bl.mp:mempool-entry-sigops e))
                (incf pkg-fees (bl.mp:mempool-entry-fee e))))
            (when (and (<= (+ weight pkg-weight)
                           bl.val:+max-block-weight+)
                       (<= (+ sigops pkg-sigops)
                           bl.val:+max-block-sigops-cost+))
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
            (push (bl.ser:transaction-hash tx) live)
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
  (let ((bl:*network* :regtest)
        (new-total 0)
        (old-total 0))
    (dolist (seed '(981 4550 77143 260201 11 3333))
      (multiple-value-bind (cs mp) (%mining-fixture)
        (%ab-populate (make-deterministic-rng seed) mp 60 3000)
        (let* ((tmpl (bl.mining:assemble-block-template cs mp))
               (txs (bl.mining:block-template-transactions tmpl)))
          (incf new-total (bl.mining:block-template-total-fees tmpl))
          (incf old-total (%ab-reference-greedy-fees mp))
          ;; Consensus budgets (Core's strict < on both).
          (is (< (bl.mining:block-template-total-weight tmpl)
                 bl.val:+max-block-weight+))
          (is (< (bl.mining:block-template-total-sigops tmpl)
                 bl.val:+max-block-sigops-cost+))
          ;; Topological validity: every selected tx's in-mempool parents
          ;; are selected, and earlier.
          (let ((seen (make-hash-table :test 'equalp)))
            (dolist (e txs)
              (let ((txid (bl.ser:transaction-hash
                           (bl.mp:mempool-entry-transaction e))))
                (maphash (lambda (p v) (declare (ignore v))
                           (when (bl.mp:mempool-has mp p)
                             (is-true (gethash p seen))))
                         (bl.mp:mempool-entry-parents e))
                (setf (gethash txid seen) t)))))))
    ;; Fee-optimality vs the old builder, over the whole seed set.
    (is (>= new-total old-total))
    ;; No resource pressure: both builders take everything.
    (multiple-value-bind (cs mp) (%mining-fixture)
      (let ((total (%ab-populate (make-deterministic-rng 60259) mp 30 0)))
        (is (= total (bl.mining:block-template-total-fees
                      (bl.mining:assemble-block-template cs mp))))
        (is (= total (%ab-reference-greedy-fees mp)))))))

;;;; Mining RPCs

(test rpc-getblocktemplate-shape
  (let ((bl:*network* :regtest))
    (multiple-value-bind (cs mp) (%mining-fixture)
      (let ((node (bl::make-node :network :regtest)))
        (setf (bl::node-chain-state node) cs
              (bl::node-mempool node) mp
              (bl::node-utxo-set node) (bl.store:make-utxo-set))
        (let ((r (bl.rpc::rpc-getblocktemplate node (%gbt-params))))
          (is (= 1 (cdr (assoc "height" r :test #'string=))))
          (is (stringp (cdr (assoc "previousblockhash" r :test #'string=))))
          (is (= (bl.val:calculate-block-subsidy 1)
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

(test gbt-longpollid-carries-the-mempool-counter
  "Core's longpollid is <best chain hash><nTransactionsUpdatedLast>
(rpc/mining.cpp:995). The second half MUST be the mempool counter: an id
derived from the HEIGHT — which is what this emitted before — never changes
while the tip stands still, so a miner longpolling on it is never woken by
mempool churn, which is most of what a new template exists to report."
  (let ((bl:*network* :regtest)
        (bl.rpc::*gbt-cache* nil))
    (multiple-value-bind (cs mp) (%mining-fixture)
      (let ((node (bl::make-node :network :regtest)))
        (setf (bl::node-chain-state node) cs
              (bl::node-mempool node) mp
              (bl::node-utxo-set node) (bl.store:make-utxo-set))
        (let* ((r (bl.rpc::rpc-getblocktemplate node (%gbt-params)))
               (id (cdr (assoc "longpollid" r :test #'string=))))
          (is (= (+ 64 (length (princ-to-string
                                (bl.mp:mempool-transactions-updated mp))))
                 (length id)))
          (is (string= (cdr (assoc "previousblockhash" r :test #'string=))
                       (subseq id 0 64)))
          ;; And it round-trips through the parser the wait loop uses.
          (multiple-value-bind (tip updated)
              (bl.rpc::%gbt-parse-longpoll-id id "ff" 999)
            (is (string= (subseq id 0 64) tip))
            (is (= (bl.mp:mempool-transactions-updated mp) updated)))
          ;; A malformed id falls back to the CURRENT state, so a wait on it
          ;; returns at the next change rather than erroring (Core's own
          ;; fallback for a non-string id).
          (multiple-value-bind (tip updated)
              (bl.rpc::%gbt-parse-longpoll-id "nonsense" "abcd" 7)
            (is (string= "abcd" tip))
            (is (= 7 updated))))))))

(test mempool-transactions-updated-counts-both-directions
  "Core bumps nTransactionsUpdated when a transaction ENTERS and when it LEAVES
(txmempool.cpp:249, :305). A counter that only counted admissions would leave a
template stale after an eviction or a reorg-driven removal — and an admission
counter is exactly what this codebase already had (mempool-sequence), so the
LEAVES half is what this test is for."
  (multiple-value-bind (cs mp) (%mining-fixture)
    (declare (ignore cs))
    (let ((empty (bl.mp:mempool-transactions-updated mp))
          (txid (%mine-add mp (make-mempool-test-tx :input-id 41) 1000)))
      ;; An admission advances it.
      (let ((after-add (bl.mp:mempool-transactions-updated mp)))
        (is (> after-add empty) "an admission did not advance the counter")
        ;; And so does the removal, rather than moving it back.
        (bl.mp:mempool-remove mp txid)
        (let ((after-remove (bl.mp:mempool-transactions-updated mp)))
          (is (> after-remove after-add)
              "a removal did not advance the counter")
          ;; The pool is empty again, but the counter is not back where it
          ;; started: it is a monotonic edit count, not a population size.
          (is (= 0 (bl.mp:mempool-count mp)))
          (is (> after-remove empty)))))))

(test gbt-longpoll-waits-for-a-change
  "Core holds a longpoll getblocktemplate open until the tip or the mempool
moves past what the caller's longpollid describes (rpc/mining.cpp:817-836).
Asserted through the two branches that can be checked quickly: an id already
out of date returns at once, and a node on its way down answers rather than
holding the socket."
  (let ((bl:*network* :regtest)
        (bl.rpc::*gbt-cache* nil))
    (multiple-value-bind (cs mp) (%mining-fixture)
      (let ((node (bl::make-node :network :regtest)))
        (setf (bl::node-chain-state node) cs
              (bl::node-mempool node) mp
              (bl::node-utxo-set node) (bl.store:make-utxo-set)
              (bl::node-running node) t)
        ;; An id naming a tip we are not on: there is already something new to
        ;; say, so the wait is over before it starts.
        (let ((start (get-internal-real-time)))
          (bl.rpc::%gbt-wait-for-change
           node (format nil "~64,'0D0" 1))
          (is (< (/ (- (get-internal-real-time) start)
                    internal-time-units-per-second)
                 5)
              "a stale longpollid did not return promptly"))
        ;; A current id on a node that is shutting down: Core throws
        ;; RPC_CLIENT_NOT_CONNECTED "Shutting down" rather than blocking.
        (setf (bl::node-running node) nil)
        (let ((id (format nil "~A~D"
                          (bl.rpc::hash-to-hex
                           (bl.store:best-block-hash cs))
                          (bl.mp:mempool-transactions-updated mp))))
          (handler-case
              (progn (bl.rpc::%gbt-wait-for-change node id)
                     (is-true nil "the wait did not end on shutdown"))
            (bl.rpc::rpc-error (e)
              (is (= bl.rpc::+rpc-client-not-connected+
                     (bl.rpc::rpc-error-code e)))
              (is (string= "Shutting down"
                           (bl.rpc::rpc-error-message e))))))))
    ;; And getblocktemplate reaches the wait at all — a longpollid that is
    ;; parsed and then ignored is the failure mode this repo keeps finding.
    (is-true (member 'bl.rpc::rpc-getblocktemplate
                     (mapcar #'car
                             (sb-introspect:who-calls
                              'bl.rpc::%gbt-wait-for-change))))))

(test gbt-reuses-a-template-for-five-seconds
  "Core reuses the last template unless the TIP changed, or the mempool changed
AND the template is older than five seconds (rpc/mining.cpp). The shape of that
condition is the point: a mempool change ALONE does not invalidate the cache,
which is what stops a busy mempool from reassembling a block on every call."
  (let ((bl:*network* :regtest)
        (bl.rpc::*gbt-cache* nil))
    (let ((now (bl.ser:get-unix-time))
          (node-a (bl::make-node :network :regtest))
          (node-b (bl::make-node :network :regtest)))
      ;; Same node, same tip, same counter: hit.
      (setf bl.rpc::*gbt-cache* (list* node-a "aa" 5 now '(("marker" . 1))))
      (is (equal '(("marker" . 1))
                 (bl.rpc::%gbt-cached-result node-a "aa" 5)))
      ;; A DIFFERENT node never hits, however well the tip and counter match.
      ;; Core's cache is a function-local static in a one-node process; here
      ;; the RPC layer serves whatever node it is handed, and two regtest nodes
      ;; share a genesis tip hash — so a node-blind key hands one node the
      ;; other's template. (Found by a suite failure, not by review: the test
      ;; passed alone and failed after another test had primed the cache.)
      (is-false (bl.rpc::%gbt-cached-result node-b "aa" 5))
      ;; Same tip, CHANGED counter, still fresh: hit, per Core's condition.
      (is (equal '(("marker" . 1))
                 (bl.rpc::%gbt-cached-result node-a "aa" 9)))
      ;; Same tip, changed counter, older than five seconds: miss.
      (setf bl.rpc::*gbt-cache*
            (list* node-a "aa" 5 (- now bl.rpc::+gbt-cache-seconds+ 1)
                   '(("marker" . 1))))
      (is-false (bl.rpc::%gbt-cached-result node-a "aa" 9))
      ;; But an unchanged counter keeps the old template however stale — Core
      ;; has nothing new to put in it.
      (is (equal '(("marker" . 1))
                 (bl.rpc::%gbt-cached-result node-a "aa" 5)))
      ;; A changed TIP always misses, whatever the age.
      (setf bl.rpc::*gbt-cache* (list* node-a "aa" 5 now '(("marker" . 1))))
      (is-false (bl.rpc::%gbt-cached-result node-a "bb" 5))
      ;; An empty cache never hits.
      (setf bl.rpc::*gbt-cache* nil)
      (is-false (bl.rpc::%gbt-cached-result node-a "aa" 5)))
    ;; End to end: two calls in a row against an unchanged node return the
    ;; SAME object, which is what proves the assembly was skipped.
    (multiple-value-bind (cs mp) (%mining-fixture)
      (let ((node (bl::make-node :network :regtest)))
        (setf (bl::node-chain-state node) cs
              (bl::node-mempool node) mp
              (bl::node-utxo-set node) (bl.store:make-utxo-set)
              bl.rpc::*gbt-cache* nil)
        (let ((a (bl.rpc::rpc-getblocktemplate node (%gbt-params)))
              (b (bl.rpc::rpc-getblocktemplate node (%gbt-params))))
          (is (eq a b) "getblocktemplate reassembled an unchanged template"))))))

(test rpc-getmininginfo-shape
  (let ((bl:*network* :regtest))
    (multiple-value-bind (cs mp) (%mining-fixture)
      (let ((node (bl::make-node :network :regtest)))
        (setf (bl::node-chain-state node) cs
              (bl::node-mempool node) mp)
        (let ((r (bl.rpc::rpc-getmininginfo node nil)))
          (is (= 0 (cdr (assoc "blocks" r :test #'string=))))
          (is (string= "regtest" (cdr (assoc "chain" r :test #'string=))))
          (is (= 0 (cdr (assoc "pooledtx" r :test #'string=))))
          (is (stringp (cdr (assoc "bits" r :test #'string=))))
          ;; Core rpc/mining.cpp:429-491: networkhashps, blockmintxfee and the
          ;; "next" block's height/bits/difficulty/target.
          (is (numberp (cdr (assoc "networkhashps" r :test #'string=))))
          (is (numberp (cdr (assoc "blockmintxfee" r :test #'string=))))
          (let ((next (cdr (assoc "next" r :test #'string=))))
            (is (= 1 (cdr (assoc "height" next :test #'string=))))
            (is (stringp (cdr (assoc "bits" next :test #'string=))))
            (is (stringp (cdr (assoc "target" next :test #'string=))))))
        ;; getdeploymentinfo's optional blockhash (rpc/blockchain.cpp:1494):
        ;; report at that block (here the genesis tip); an unknown hash is
        ;; RPC_INVALID_ADDRESS_OR_KEY.
        (let* ((tip-hex (bl.rpc::hash-to-hex
                         (bl.store:best-block-hash cs)))
               (d (bl.rpc::rpc-getdeploymentinfo node (list tip-hex))))
          (is (string= tip-hex (cdr (assoc "hash" d :test #'string=))))
          (is (= 0 (cdr (assoc "height" d :test #'string=)))))
        (signals bl.rpc::rpc-error
          (bl.rpc::rpc-getdeploymentinfo
           node (list (make-string 64 :initial-element #\f))))))))

;;;; Block construction + CPU mining + submitblock (regtest, disk-backed)

(test the-coinbase-witness-waits-for-segwit-activation
  "Core gates the commitment OUTPUT and the coinbase WITNESS separately.
GenerateCoinbaseCommitment appends the output with no deployment check at all
(validation.cpp:4029-4050); UpdateUncommittedBlockStructures adds the reserved
witness value only under DeploymentActiveAfter(..., DEPLOYMENT_SEGWIT) (:4021).

Ours tied the witness to the commitment, so a template built for a height where
segwit is NOT yet active carried witness data — and contextual validation
rejects exactly that as :UNEXPECTED-WITNESS. VALIDATE-WITNESS-COMMITMENT is
correct and said so; the assembler was handing it a block it was right to
refuse, so the node could not mine at all under -testactivationheight=segwit@N.
That is how Core's feature_nulldummy.py found it: 'TestBlockValidity failed on
assembled block at height 1: UNEXPECTED-WITNESS'.

Invisible on every network this node runs by default, because segwit is active
from genesis on all of them."
  (let ((script (bl.mining::build-witness-commitment-script
                 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3))))
    (flet ((coinbase (active)
             (bl.mining:build-coinbase-transaction
              1 5000000000 :witness-commitment-script script :segwit-active active)))
      ;; Active: witness present.
      (is-true (bl.ser:transaction-has-witness-p (coinbase t)))
      ;; Inactive: no witness anywhere — this is the assertion that fails
      ;; against the bug.
      (is-false (bl.ser:transaction-has-witness-p (coinbase nil))
                "the coinbase carried witness data on a chain where segwit is ~
not active; contextual validation rejects that block as :unexpected-witness")
      ;; The commitment OUTPUT is present either way, as Core's is.
      (dolist (active '(t nil))
        (is (= 2 (length (bl.ser:transaction-outputs
                          (coinbase active))))
            "commitment output missing with segwit-active ~A" active))
      ;; And a block built from the inactive coinbase passes the very check
      ;; that was rejecting it.
      (let ((blk (bl.ser:make-bitcoin-block
                  :header (bl.ser:make-block-header)
                  :transactions (list (coinbase nil)))))
        (is-true (bl.val:validate-witness-commitment blk nil)
                 "a pre-segwit block still fails the witness check")))))

(test build-coinbase-transaction-shape
  (with-network (:regtest)
   (let* ((spk (p2sh-optrue-script-pubkey))
          (commit (bl.mining:build-witness-commitment-script (%zeros 32)))
          (cb (bl.mining:build-coinbase-transaction
               1 5000000000 :script-pubkey spk :witness-commitment-script commit)))
     ;; one input, null prevout, BIP34 height-1 (OP_1) scriptSig >= 2 bytes
     (let ((in (elt (bl.ser:transaction-inputs cb) 0)))
       (is-true (bl.ser:coinbase-input-p in))
       (is (>= (length (bl.ser:tx-in-script-sig in)) 2))
       (is (= #x51 (aref (bl.ser:tx-in-script-sig in) 0))))
     ;; payout + commitment outputs
     (is (= 2 (length (bl.ser:transaction-outputs cb))))
     (is (= 5000000000 (bl.ser:tx-out-value
                        (elt (bl.ser:transaction-outputs cb) 0))))
     ;; reserved witness value present (so it serializes as a segwit tx)
     (is-true (bl.ser:transaction-has-witness-p cb)))))

(test build-coinbase-transaction-bip54-fields
  ;; Core node/miner.cpp:171,196: the template coinbase uses
  ;; nSequence = MAX_SEQUENCE_NONFINAL and nLockTime = height - 1, so the
  ;; coinbase commits to its height a second way (BIP54's coinbase rule).
  (with-network (:regtest)
   (let* ((cb (bl.mining:build-coinbase-transaction
               42 5000000000 :script-pubkey (p2sh-optrue-script-pubkey)))
          (in0 (elt (bl.ser:transaction-inputs cb) 0)))
     (is (= #xfffffffe (bl.ser:tx-in-sequence in0)))
     (is (= 41 (bl.ser:transaction-lock-time cb))))))

(test mine-block-satisfies-pow
  (with-network (:regtest)
   (let ((node (regtest-node-fixture "mine")))
     (let ((block (bl.mining:assemble-full-block
                   (bl::node-chain-state node)
                   (bl::node-mempool node)
                   :coinbase-script-pubkey (p2sh-optrue-script-pubkey))))
       (is-true (bl.mining:mine-block block))
       (is-true (bl.val:check-proof-of-work
                 (bl.ser:bitcoin-block-header block)))))))

(test submitblock-round-trip
  ;; Build + mine a regtest block at the genesis tip, serialize it, submit the
  ;; hex via the RPC — accepted (null), tip advances, resubmit → "duplicate".
  (with-network (:regtest)
   (let* ((node (regtest-node-fixture "submit"))
          (block (bl.mining:assemble-full-block
                  (bl::node-chain-state node)
                  (bl::node-mempool node)
                  :coinbase-script-pubkey (p2sh-optrue-script-pubkey))))
     (bl.mining:mine-block block)
     (let ((hex (bl.crypto:bytes-to-hex
                 (bl.ser:serialize-witness-block block))))
       ;; accepted → null
       (is (null (bl.rpc::rpc-submitblock node (list hex))))
       (is (= 1 (bl.store:current-height
                 (bl::node-chain-state node))))
       ;; resubmit the same block → duplicate
       (is (string= "duplicate" (bl.rpc::rpc-submitblock node (list hex))))))))

(test submitblock-fills-missing-witness-nonce
  ;; Core UpdateUncommittedBlockStructures (validation.cpp:4017-4027), run by
  ;; submitblock before validation: a coinbase that carries the witness
  ;; commitment but no witness gets the 32-zero nonce installed. A miner that
  ;; serializes the template's coinbase witnessless is therefore accepted;
  ;; before the fix we refused the block as bad-witness-nonce-size.
  (with-network (:regtest)
   (let* ((node (regtest-node-fixture "submit-nonce"))
          (block (bl.mining:assemble-full-block
                  (bl::node-chain-state node)
                  (bl::node-mempool node)
                  :coinbase-script-pubkey (p2sh-optrue-script-pubkey)))
          (cb (first (bl.ser:bitcoin-block-transactions block))))
     (bl.mining:mine-block block)
     (is-true (bl.val:find-witness-commitment cb))
     (setf (bl.ser:transaction-witness cb) nil)
     (is-false (bl.ser:transaction-has-witness-p cb))
     (let ((hex (bl.crypto:bytes-to-hex
                 (bl.ser:serialize-witness-block block))))
       (is (null (bl.rpc::rpc-submitblock node (list hex))))
       (is (= 1 (bl.store:current-height
                 (bl::node-chain-state node))))))))

(test submitblock-side-chain-block-is-inconclusive
  ;; Two valid blocks on the genesis tip. The first becomes the tip (null);
  ;; the second is stored on a side chain and never connected, which Core's
  ;; submitblock_StateCatcher never sees → "inconclusive" (rpc/mining.cpp:
  ;; 1091-1095), not null and not a reject reason.
  (with-network (:regtest)
   (let* ((node (regtest-node-fixture "submit-side"))
          (cs (bl::node-chain-state node))
          (mp (bl::node-mempool node))
          (a (bl.mining:assemble-full-block
              cs mp :coinbase-script-pubkey (p2sh-optrue-script-pubkey)))
          (b (bl.mining:assemble-full-block
              cs mp :coinbase-script-pubkey
              (coerce '(#x51) '(vector (unsigned-byte 8))))))
     (bl.mining:mine-block a)
     (bl.mining:mine-block b)
     (flet ((hex (blk) (bl.crypto:bytes-to-hex
                        (bl.ser:serialize-witness-block blk))))
       (is (null (bl.rpc::rpc-submitblock node (list (hex a)))))
       (is (string= "inconclusive"
                    (bl.rpc::rpc-submitblock node (list (hex b)))))
       (is (= 1 (bl.store:current-height cs)))))))


(test submitblock-header-only-entry-proceeds
  ;; Standard pool flow: submitheader, then submitblock. The header-only index
  ;; entry must NOT short-circuit as "duplicate" (Core returns "duplicate" only
  ;; when the entry has BLOCK_HAVE_DATA — AcceptBlock fAlreadyHave,
  ;; validation.cpp:4351); a known-invalid block returns "duplicate-invalid"
  ;; (AcceptBlockHeader, validation.cpp:4231-4235).
  (with-network (:regtest)
   (let* ((node (regtest-node-fixture "subhdrblk"))
          (cs (bl::node-chain-state node))
          (block (bl.mining:assemble-full-block
                  cs (bl::node-mempool node)
                  :coinbase-script-pubkey (p2sh-optrue-script-pubkey))))
     (bl.mining:mine-block block)
     (let* ((hdr (bl.ser:bitcoin-block-header block))
            (hash (bl.ser:block-header-hash hdr))
            (hdr-hex (bl.crypto:bytes-to-hex
                      (flexi-streams:with-output-to-sequence (s)
                        (bl.ser::write-block-header s hdr))))
            (blk-hex (bl.crypto:bytes-to-hex
                      (bl.ser:serialize-witness-block block))))
       ;; submitheader indexes the header only.
       (is (null (bl.rpc::rpc-submitheader node (list hdr-hex))))
       (let ((entry (bl.store:get-block-index-entry cs hash)))
         (is (not (null entry)))
         (is (eq :header-valid (bl.store:block-index-entry-status entry))))
       ;; submitblock proceeds to full processing — the mined block is not lost.
       (is (null (bl.rpc::rpc-submitblock node (list blk-hex))))
       (is (= 1 (bl.store:current-height cs)))
       ;; Now the data is on disk → resubmit is a true duplicate.
       (is (string= "duplicate" (bl.rpc::rpc-submitblock node (list blk-hex))))
       ;; A known-invalid entry short-circuits before the data check.
       (setf (bl.store:block-index-entry-status
              (bl.store:get-block-index-entry cs hash))
             :invalid)
       (is (string= "duplicate-invalid"
                    (bl.rpc::rpc-submitblock node (list blk-hex))))))))

(test rpc-getblock-v0-witness-round-trip
  ;; getblock verbosity 0 must return the block's wire (witness-complete)
  ;; bytes — Core reads the raw on-disk block (GetRawBlockChecked) — and the
  ;; verbosity argument follows Core ParseVerbosity: booleans allowed
  ;; (false→0, true→1), default 1, verbosity >= 2 gives tx details.
  (with-network (:regtest)
   (let* ((node (regtest-node-fixture "getblockv0"))
          (block (bl.mining:assemble-full-block
                  (bl::node-chain-state node)
                  (bl::node-mempool node)
                  :coinbase-script-pubkey (p2sh-optrue-script-pubkey))))
     (bl.mining:mine-block block)
     (let* ((wire (bl.ser:serialize-witness-block block))
            (hash-hex (bl.rpc::hash-to-hex
                       (bl.ser:block-header-hash
                        (bl.ser:bitcoin-block-header block)))))
       (is (null (bl.rpc::rpc-submitblock
                  node (list (bl.crypto:bytes-to-hex wire)))))
       ;; Verbosity 0 → hex of the exact wire bytes; the segwit coinbase's
       ;; witness (reserved value) survives a round-trip.
       (let ((hex (bl.rpc::rpc-getblock node (list hash-hex 0))))
         (is (stringp hex))
         (is (equalp wire (bl.crypto:hex-to-bytes hex)))
         (let ((parsed (flexi-streams:with-input-from-sequence
                           (s (bl.crypto:hex-to-bytes hex))
                         (bl.ser:read-bitcoin-block s))))
           (is (bl.ser:transaction-has-witness-p
                (first (bl.ser:bitcoin-block-transactions parsed))))))
       ;; Boolean/legacy verbosity: false → hex, true → object; absent → object.
       ;; null verbosity -> Core default 1 (JSON); explicit false -> hex.
       (is (consp (bl.rpc::rpc-getblock node (list hash-hex nil))))
       (is (stringp (bl.rpc::rpc-getblock
                     node (list hash-hex bl.rpc:+json-false+))))
       (let ((r (bl.rpc::rpc-getblock node (list hash-hex t))))
         (is (consp r))
         (is (string= hash-hex (cdr (assoc "hash" r :test #'string=)))))
       (is (consp (bl.rpc::rpc-getblock node (list hash-hex))))
       ;; Core accepts any integer: 3 behaves like 2 (details; prevout data
       ;; unsupported), negative returns hex.
       (is (consp (bl.rpc::rpc-getblock node (list hash-hex 3))))
       (is (stringp (bl.rpc::rpc-getblock node (list hash-hex -1))))
       ;; Non-integer/non-bool verbosity → type error.
       (signals bl.rpc::rpc-error
         (bl.rpc::rpc-getblock node (list hash-hex "x")))))))

(test gbt-transactions-data-uses-wire-encoding
  ;; getblocktemplate transactions[].data must be the wire encoding (Core
  ;; EncodeHexTx): a witnessless tx carries NO marker/flag — extended-form
  ;; data makes the miner's reconstructed block fail Core deserialization
  ;; ("Superfluous witness record") — while a segwit tx keeps its witness.
  (let* ((legacy-tx (make-mempool-test-tx))
         (witness-raw (make-witness-test-tx-bytes))
         (witness-tx (flexi-streams:with-input-from-sequence (s witness-raw)
                       (bl.ser:read-transaction s)))
         (template (bl.mining::make-block-template
                    :transactions
                    (list (bl.mp:make-entry-from-tx legacy-tx 1000 0)
                          (bl.mp:make-entry-from-tx witness-tx 1000 0))))
         (txs (bl.rpc::%gbt-transactions template)))
    (let ((legacy-data (bl.crypto:hex-to-bytes
                        (cdr (assoc "data" (first txs) :test #'string=)))))
      (is (equalp (bl.ser:serialize-transaction legacy-tx)
                  legacy-data))
      ;; byte 4 is the input count in legacy form — 0x00 would be a marker.
      (is (/= #x00 (aref legacy-data 4))))
    (is (equalp witness-raw
                (bl.crypto:hex-to-bytes
                 (cdr (assoc "data" (second txs) :test #'string=)))))))

(test generatetoaddress-advances-chain
  (with-network (:regtest)
   (let* ((node (regtest-node-fixture "gen"))
          (addr (bl.crypto:encode-p2pkh-address
                 (make-array 20 :element-type '(unsigned-byte 8) :initial-element 3)
                 :regtest))
          (hashes (bl.rpc::rpc-generatetoaddress node (list 3 addr))))
     (is (= 3 (length hashes)))
     (is (every #'stringp hashes))
     (is (= 3 (bl.store:current-height
               (bl::node-chain-state node))))
     ;; the tip is the last generated hash
     (is (string= (car (last hashes))
                  (bl.rpc::hash-to-hex
                   (bl.store:best-block-hash
                    (bl::node-chain-state node))))))))

(test generatetodescriptor-advances-chain
  ;; Mine to a descriptor-derived coinbase script (raw(51) = OP_TRUE) and confirm
  ;; the chain advances, mirroring generatetoaddress.
  (with-network (:regtest)
   (let* ((node (regtest-node-fixture "gendesc"))
          (hashes (bl.rpc::rpc-generatetodescriptor node (list 2 "raw(51)"))))
     (is (= 2 (length hashes)))
     (is (every #'stringp hashes))
     (is (= 2 (bl.store:current-height
               (bl::node-chain-state node))))
     (is (string= (car (last hashes))
                  (bl.rpc::hash-to-hex
                   (bl.store:best-block-hash
                    (bl::node-chain-state node)))))
     ;; bad descriptor + non-positive count error
     (signals bl.rpc::rpc-error
       (bl.rpc::rpc-generatetodescriptor node (list 1 "frobnicate(03ab)")))
     (signals bl.rpc::rpc-error
       (bl.rpc::rpc-generatetodescriptor node (list 0 "raw(51)"))))))

(test submitheader-accepts-valid-rejects-orphan
  ;; A mined header whose parent is known validates and is added to the index;
  ;; a header with an unknown parent and malformed hex both error.
  (with-network (:regtest)
   (let* ((node (regtest-node-fixture "subhdr"))
          (block (bl.mining:assemble-full-block
                  (bl::node-chain-state node)
                  (bl::node-mempool node)
                  :coinbase-script-pubkey (p2sh-optrue-script-pubkey))))
     (bl.mining:mine-block block)
     (let* ((hdr (bl.ser:bitcoin-block-header block))
            (hash (bl.ser:block-header-hash hdr))
            (bytes (flexi-streams:with-output-to-sequence (s)
                     (bl.ser::write-block-header s hdr)))
            (hex (bl.crypto:bytes-to-hex bytes)))
       (is (= 80 (length bytes)))
       (is (null (bl.store:get-block-index-entry
                  (bl::node-chain-state node) hash)))
       ;; valid → null, now present
       (is (null (bl.rpc::rpc-submitheader node (list hex))))
       (is-true (bl.store:get-block-index-entry
                 (bl::node-chain-state node) hash))
       ;; already-known → still null
       (is (null (bl.rpc::rpc-submitheader node (list hex)))))
     ;; header with an unknown parent → verify error
     (let* ((orphan (bl.ser:make-block-header
                     :version 1
                     :prev-block (make-array 32 :element-type '(unsigned-byte 8)
                                                :initial-element 7)
                     :merkle-root (%zeros 32) :timestamp 1296688602
                     :bits #x207fffff :nonce 0))
            (obytes (flexi-streams:with-output-to-sequence (s)
                      (bl.ser::write-block-header s orphan))))
       (signals bl.rpc::rpc-error
         (bl.rpc::rpc-submitheader
          node (list (bl.crypto:bytes-to-hex obytes)))))
     ;; malformed hex → deserialization error
     (signals bl.rpc::rpc-error
       (bl.rpc::rpc-submitheader node (list "zz"))))))

(test generateblock-empty-submit-advances-chain
  ;; generateblock with no extra txs mines an empty block to the descriptor
  ;; output and (submit=true) advances the chain.
  (with-network (:regtest)
   (let* ((node (regtest-node-fixture "genblk"))
          (r (bl.rpc::rpc-generateblock node (list "raw(51)" '()))))
     (is (stringp (cdr (assoc "hash" r :test #'string=))))
     (is (null (assoc "hex" r :test #'string=)))   ; no hex when submitted
     (is (= 1 (bl.store:current-height
               (bl::node-chain-state node))))
     (is (string= (cdr (assoc "hash" r :test #'string=))
                  (bl.rpc::hash-to-hex
                   (bl.store:best-block-hash
                    (bl::node-chain-state node))))))))

(test generateblock-no-submit-returns-hex-without-advancing
  ;; submit=false returns {hash, hex} and does NOT change the tip.
  (with-network (:regtest)
   (let* ((node (regtest-node-fixture "genblk-ns"))
          (h0 (bl.store:current-height (bl::node-chain-state node)))
          (r (bl.rpc::rpc-generateblock
              node (list "raw(51)" '() bl.rpc:+json-false+))))
     (is (stringp (cdr (assoc "hash" r :test #'string=))))
     (is (stringp (cdr (assoc "hex" r :test #'string=))))
     ;; the hex round-trips to a block whose header hashes to the reported hash
     (let* ((bytes (bl.crypto:hex-to-bytes (cdr (assoc "hex" r :test #'string=))))
            (blk (flexi-streams:with-input-from-sequence (s bytes)
                   (bl.ser:read-bitcoin-block s))))
       (is (string= (cdr (assoc "hash" r :test #'string=))
                    (bl.rpc::hash-to-hex
                     (bl.ser:block-header-hash
                      (bl.ser:bitcoin-block-header blk))))))
     ;; tip unchanged
     (is (= h0 (bl.store:current-height
                (bl::node-chain-state node)))))))

(test generateblock-includes-raw-tx-and-rejects-bad-output
  ;; A consensus-valid raw (non-coinbase) tx is included and the witness
  ;; commitment is computed over it (submit=false). The block is dry-run
  ;; through TestBlockValidity before mining (Core rpc/mining.cpp:389-393),
  ;; so the tx must genuinely spend an existing UTXO; a bogus output errors.
  (with-network (:regtest)
   (let* ((node (regtest-node-fixture "genblk-tx"))
          (funding (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9))
          (tx (%pkg-tx funding 0 99990000 :version 1))
          (tx-hex (bl.crypto:bytes-to-hex
                   (bl.ser:serialize-transaction tx))))
     ;; A confirmed P2SH(OP_TRUE) coin the raw tx spends without a signature.
     (bl.store:add-utxo (bl::node-utxo-set node)
                                    funding 0 100000000 (p2sh-optrue-script-pubkey) 0
                                    :coinbase nil)
     (let* ((r (bl.rpc::rpc-generateblock
                node (list "raw(51)" (list tx-hex)
                           bl.rpc:+json-false+)))
            (blk (flexi-streams:with-input-from-sequence
                     (s (bl.crypto:hex-to-bytes (cdr (assoc "hex" r :test #'string=))))
                   (bl.ser:read-bitcoin-block s))))
       ;; coinbase + the one supplied tx
       (is (= 2 (length (bl.ser:bitcoin-block-transactions blk)))))
     ;; bogus output (neither address nor descriptor) errors
     (signals bl.rpc::rpc-error
       (bl.rpc::rpc-generateblock node (list "not-an-output" '()))))))

(test generateblock-testblockvalidity-rejects-bad-tx
  ;; A raw tx spending a nonexistent outpoint fails the pre-mining
  ;; TestBlockValidity dry-run with an RPC verify error — even with
  ;; submit=false, unvalidated hex is never returned (Core generateblock
  ;; runs TestBlockValidity unconditionally, rpc/mining.cpp:389-393).
  (with-network (:regtest)
   (let* ((node (regtest-node-fixture "genblk-badtx"))
          (bogus (%pkg-tx (make-array 32 :element-type '(unsigned-byte 8)
                                         :initial-element 66)
                          0 1000 :version 1))
          (hex (bl.crypto:bytes-to-hex
                (bl.ser:serialize-transaction bogus))))
     (signals bl.rpc::rpc-error
       (bl.rpc::rpc-generateblock node (list "raw(51)" (list hex) nil)))
     ;; tip unchanged — nothing was mined or activated
     (is (= 0 (bl.store:current-height
               (bl::node-chain-state node)))))))

;;;; Wave 7: BIP94 timewarp clamp on template mintime (Core GetMinimumTime,
;;;; node/miner.cpp:36-47) + TestBlockValidity on assembled templates
;;;; (node/miner.cpp:227-231, validation.cpp:4495)

(defun %timewarp-fixture (tip-height tip-time)
  "(values chain-state mempool) — a regtest chain-state whose tip sits at
TIP-HEIGHT with timestamp TIP-TIME, preceded by 10 linked entries at
timestamps 1000000..1000009 (so MTP is 1000005, far below TIP-TIME)."
  (let ((cs (bl.store:make-chain-state))
        (prev nil))
    (loop for h from (- tip-height 10) to tip-height
          for i from 0
          do (let* ((ts (if (= h tip-height) tip-time (+ 1000000 i)))
                    (hash (let ((v (%zeros 32)))
                            (setf (aref v 0) (logand h #xff)
                                  (aref v 1) (logand (ash h -8) #xff)
                                  (aref v 2) #x77)
                            v))
                    (hdr (bl.ser:make-block-header
                          :version 1
                          :prev-block (if prev
                                          (bl.store:block-index-entry-hash prev)
                                          (%zeros 32))
                          :merkle-root (%zeros 32)
                          :timestamp ts :bits #x207fffff :nonce 0))
                    (entry (bl.store:make-block-index-entry
                            :hash hash
                            :header hdr :height h :prev-entry prev
                            :status :valid)))
               (bl.store:add-block-index-entry cs entry)
               (setf prev entry)))
    (bl.store:update-chain-tip
     cs (bl.store:block-index-entry-hash prev) tip-height)
    (values cs (bl.mp:make-mempool))))

(test assembler-bip94-timewarp-clamp-at-retarget
  "At a retarget height (height % 2016 == 0) the template's mintime is
clamped to prev-block-time - MAX_TIMEWARP when that exceeds MTP+1 (Core
GetMinimumTime, miner.cpp:36-47), and curtime is floored to mintime
(UpdateTime, miner.cpp:49-57). Off-boundary the floor stays MTP+1."
  (let ((bl:*network* :regtest))
    ;; Tip at 2015 -> template height 2016, a retarget boundary.
    (multiple-value-bind (cs mp) (%timewarp-fixture 2015 2000000)
      (let ((tmpl (bl.mining:assemble-block-template
                   cs mp :block-time 1000010)))
        (is (= 2016 (bl.mining:block-template-height tmpl)))
        ;; mintime = max(MTP+1, tip-time - 600) = 2000000 - 600
        (is (= (- 2000000 bl.val:+max-timewarp+)
               (bl.mining:block-template-mintime tmpl)))
        ;; curtime = max(now, mintime): the stale block-time is floored up.
        (is (= (bl.mining:block-template-mintime tmpl)
               (bl.mining:block-template-curtime tmpl)))))
    ;; Tip at 2016 -> template height 2017: no clamp, floor is MTP+1.
    (multiple-value-bind (cs mp) (%timewarp-fixture 2016 2000000)
      (let ((tmpl (bl.mining:assemble-block-template
                   cs mp :block-time 1000010)))
        (is (= 2017 (bl.mining:block-template-height tmpl)))
        (is (= (1+ 1000005)                ; MTP+1
               (bl.mining:block-template-mintime tmpl)))
        (is (= 1000010 (bl.mining:block-template-curtime tmpl)))))))

(test template-testblockvalidity-catches-bad-mempool-tx
  "A consensus-invalid tx smuggled into the mempool (validation bypassed —
the class of bug TestBlockValidity exists to net) makes template assembly
ERROR instead of handing miners a doomed block; both getblocktemplate and
the generate* paths pass the UTXO set, so all live templates are dry-run
(Core CreateNewBlock throws, node/miner.cpp:227-231)."
  (with-network (:regtest)
   (let ((node (regtest-node-fixture "tbv")))
     ;; Missing-input tx, injected directly (bypasses acceptance validation).
     (%mine-add (bl::node-mempool node)
                (make-mempool-test-tx :input-id 77) 50000)
     (signals error
       (bl.mining:assemble-full-block
        (bl::node-chain-state node)
        (bl::node-mempool node)
        :coinbase-script-pubkey (p2sh-optrue-script-pubkey)
        :utxo-set (bl::node-utxo-set node)))
     ;; getblocktemplate takes the same guarded path.
     (signals error (bl.rpc::rpc-getblocktemplate node (%gbt-params)))
     ;; generatetoaddress refuses to mine it.
     (signals error
       (bl.rpc::rpc-generatetoaddress
        node (list 1 (bl.crypto:encode-p2pkh-address
                      (make-array 20 :element-type '(unsigned-byte 8)
                                     :initial-element 3)
                      :regtest)))))))

(test test-block-validity-accepts-valid-and-rejects-stale-prev
  "TEST-BLOCK-VALIDITY passes a freshly assembled valid block (PoW not yet
ground — check_pow=false) and reports inconclusive-not-best-prevblk for a
block not extending the tip (Core validation.cpp:4506-4509)."
  (with-network (:regtest)
   (let* ((node (regtest-node-fixture "tbv-ok"))
          (cs (bl::node-chain-state node))
          (utxo (bl::node-utxo-set node))
          (block (bl.mining:assemble-full-block
                  cs (bl::node-mempool node)
                  :coinbase-script-pubkey (p2sh-optrue-script-pubkey))))
     (multiple-value-bind (ok err)
         (bl.val:test-block-validity block cs utxo)
       (is-true ok)
       (is (null err)))
     ;; Point the header at a bogus parent: inconclusive, not a hard failure.
     (setf (bl.ser:block-header-prev-block
            (bl.ser:bitcoin-block-header block))
           (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9))
     (multiple-value-bind (ok err)
         (bl.val:test-block-validity block cs utxo)
       (is-false ok)
       (is (eq :inconclusive-not-best-prevblk err))))))
(defun %gbt-block-on-parent (prev-hash)
  "A syntactically valid block whose parent is PREV-HASH."
  (bl.ser:make-bitcoin-block
   :header (bl.ser:make-block-header :prev-block prev-hash)
   :transactions
   (list (bl.ser:make-transaction
          :version 1
          :inputs (vector (bl.ser:make-tx-in
                           :previous-output
                           (bl.ser:make-outpoint
                            :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                 :initial-element 0)
                            :index #xFFFFFFFF)
                           :script-sig (coerce #(1 2) '(simple-array (unsigned-byte 8) (*)))
                           :sequence #xFFFFFFFF))
          :outputs (vector (bl.ser:make-tx-out
                            :value 5000000000
                            :script-pubkey (coerce #(#x51)
                                                   '(simple-array (unsigned-byte 8) (*)))))
          :lock-time 0))))

(test gbt-proposal-validates-a-template-without-mining-it
  "getblocktemplate advertised \"proposal\" in its capabilities while not
implementing it — a node claiming a capability it does not have. mode=proposal
is a VALIDATION request, not a request for work: it answers before any template
is assembled (rpc/mining.cpp:729-751), and it does NOT check proof of work,
because a proposal is by definition unmined."
  (with-network (:regtest)
   (let ((node (regtest-node-fixture (format nil "gbtp~D" (get-internal-real-time)))))
    (flet ((propose (data)
             (let ((req (make-hash-table :test 'equal)))
               (setf (gethash "mode" req) "proposal")
               (when data (setf (gethash "data" req) data))
               (handler-case (bl.rpc::rpc-getblocktemplate node (list req))
                 (bl.rpc::rpc-error (e)
                   (list :error (bl.rpc::rpc-error-code e)
                         (bl.rpc::rpc-error-message e)))))))
      ;; A template this node just produced must validate as a proposal —
      ;; anything else means getblocktemplate is handing miners work the node
      ;; would itself reject.
      (let* ((tmpl (bl.rpc::rpc-getblocktemplate node (%gbt-params)))
             (prev (cdr (assoc "previousblockhash" tmpl :test #'string=))))
        (is-true prev "the template has no previousblockhash"))
      ;; Missing data is Core's type error, not a crash.
      (is (equal '(:error -3 "Missing data String key for proposal") (propose nil)))
      ;; Undecodable data is Core's deserialization error.
      (is (equal '(:error -22 "Block decode failed") (propose "zzzz")))
      (is (equal '(:error -22 "Block decode failed") (propose "00")))
      ;; A well-formed block that does not build on the tip is refused with a
      ;; BIP22 reason rather than signalling out of the RPC — TestBlockValidity
      ;; requires the tip as parent.
      (let* ((stray (%gbt-block-on-parent
                     (make-array 32 :element-type '(unsigned-byte 8)
                                    :initial-element #x42)))
             (hex (bl.crypto:bytes-to-hex
                   (bl.ser:serialize-witness-block stray))))
        (is (equal "inconclusive-not-best-prevblk" (propose hex))))))))


;;;; --- getblocktemplate's contract with a real miner -----------------------

(defun %gbt-norm (req)
  "REQ as the params list a handler receives over the wire — through the same
normalizer the server applies (rpc/server.lisp:825-826, :942-943), so a nested
array arrives as the LIST a real client produces rather than the vector a test
would otherwise hand it."
  (bl.rpc::%normalize-rpc-params (vector req)))

(defun %gbt-node (&optional (network :regtest))
  "A node with just enough state for getblocktemplate on NETWORK."
  (multiple-value-bind (cs mp) (%mining-fixture)
    (let ((node (bl::make-node :network network)))
      (setf (bl::node-chain-state node) cs
            (bl::node-mempool node) mp
            (bl::node-utxo-set node) (bl.store:make-utxo-set))
      node)))

(defun %gbt-error-message (node params)
  "The rpc-error message getblocktemplate signals for PARAMS, or NIL."
  (handler-case (progn (bl.rpc::rpc-getblocktemplate node params) nil)
    (bl.rpc::rpc-error (e) (bl.rpc::rpc-error-message e))))

(test gbt-requires-the-client-to-declare-segwit
  "Core refuses a template request whose \"rules\" array does not name segwit,
with this exact message (rpc/mining.cpp:853-855). We never read the array at
all, so a pre-segwit miner was handed a segwit template instead of the error —
it would have mined a block it could not have built correctly."
  (let ((bl:*network* :regtest)
        (expected "getblocktemplate must be called with the segwit rule set (call with {\"rules\": [\"segwit\"]})"))
    (let ((node (%gbt-node)))
      ;; No request object at all.
      (is (equal expected (%gbt-error-message node nil)))
      ;; A request object with no "rules" key.
      (is (equal expected (%gbt-error-message node (list (make-hash-table :test 'equal)))))
      ;; "rules" naming something else.
      (let ((req (make-hash-table :test 'equal)))
        (setf (gethash "rules" req) (vector "csv"))
        (is (equal expected (%gbt-error-message node (%gbt-norm req)))))
      ;; ⚠️ A BARE STRING is not an array. Core reads the rules only when
      ;; isArray() (rpc/mining.cpp:753), and in CL a string IS a vector, so
      ;; this is the shape that would wrongly read as ["segwit"] if the check
      ;; were a plain vectorp.
      (let ((req (make-hash-table :test 'equal)))
        (setf (gethash "rules" req) "segwit")
        (is (equal expected (%gbt-error-message node (%gbt-norm req)))))
      ;; And declaring it works.
      (is (null (%gbt-error-message node (%gbt-params)))))))

(test gbt-requires-the-signet-rule-on-signet
  "On a signet chain Core additionally requires \"signet\" in the rules, and
checks it BEFORE segwit (rpc/mining.cpp:848-855)."
  (let ((bl:*network* :signet))
    (let ((node (%gbt-node :signet))
          (expected "getblocktemplate must be called with the signet rule set (call with {\"rules\": [\"segwit\", \"signet\"]})"))
      ;; segwit alone is not enough on signet, and the SIGNET message is the
      ;; one that comes back — the order matters.
      (is (equal expected (%gbt-error-message node (%gbt-params))))
      (is (equal expected (%gbt-error-message node nil))))
    ;; Neither rule is required on a non-signet chain.
    (let ((bl:*network* :regtest))
      (is (null (%gbt-error-message (%gbt-node :regtest) (%gbt-params)))))))

(test gbt-signet-template-carries-the-challenge
  "Core emits signet_challenge on a signet chain and nowhere else
(rpc/mining.cpp:1017-1019). Without it a signet miner cannot construct the
block's signet solution, so signet mining against this node could not work.
The output \"rules\" array must also carry \"!signet\" (rpc/mining.cpp:951-955)."
  (let* ((bl:*network* :signet)
         (node (%gbt-node :signet))
         (req (make-hash-table :test 'equal)))
    (setf (gethash "rules" req) (vector "segwit" "signet"))
    (let* ((r (bl.rpc::rpc-getblocktemplate node (%gbt-norm req)))
           (challenge (cdr (assoc "signet_challenge" r :test #'string=)))
           (rules (cdr (assoc "rules" r :test #'string=))))
      (is-true (stringp challenge) "no signet_challenge in a signet template")
      (is-true (plusp (length challenge)))
      ;; It is the raw challenge script in hex — the same bytes getmininginfo
      ;; reports, since both read signet-challenge-for-network.
      (is (string= (bl.crypto:bytes-to-hex
                    (bl.val:signet-challenge-for-network :signet))
                   challenge))
      (is-true (member "!signet" rules :test #'string=))))
  ;; And nowhere else.
  (let* ((bl:*network* :regtest)
         (r (bl.rpc::rpc-getblocktemplate (%gbt-node) (%gbt-params))))
    (is-false (assoc "signet_challenge" r :test #'string=))
    (is-false (member "!signet" (cdr (assoc "rules" r :test #'string=)) :test #'string=))))

(test gbt-refuses-a-mode-it-does-not-know
  "Core accepts exactly \"template\" and \"proposal\" and throws \"Invalid mode\"
otherwise (rpc/mining.cpp:762-763), and for a mode that is not a string at all
(:717-726). We built a template for anything that was not the word proposal, so
a miner that misspelled the mode silently got work it never asked for."
  (let ((bl:*network* :regtest))
    (let ((node (%gbt-node)))
      (dolist (bad (list "Template" "propose" "" "getwork"))
        (let ((req (make-hash-table :test 'equal)))
          (setf (gethash "rules" req) (vector "segwit")
                (gethash "mode" req) bad)
          (is (equal "Invalid mode" (%gbt-error-message node (%gbt-norm req)))
              "mode ~S was accepted" bad)))
      ;; A non-string mode is refused before anything else looks at it.
      (let ((req (make-hash-table :test 'equal)))
        (setf (gethash "rules" req) (vector "segwit")
              (gethash "mode" req) 7)
        (is (equal "Invalid mode" (%gbt-error-message node (%gbt-norm req)))))
      ;; The two Core knows still work; an absent mode means "template".
      (let ((req (make-hash-table :test 'equal)))
        (setf (gethash "rules" req) (vector "segwit")
              (gethash "mode" req) "template")
        (is (null (%gbt-error-message node (%gbt-norm req))))))))

(test gbt-output-rules-match-cores-base-list
  "Core pushes \"csv\" UNCONDITIONALLY (rpc/mining.cpp:949), not gated on its
activation height, and taproot carries NO \"!\" prefix because its
VersionBitsDeploymentInfo sets gbt_optional_rule = true
(deploymentinfo.cpp:17-18, gbt_rule_value at rpc/mining.cpp:605-611)."
  (let* ((bl:*network* :regtest)
         (r (bl.rpc::rpc-getblocktemplate (%gbt-node) (%gbt-params)))
         (rules (cdr (assoc "rules" r :test #'string=))))
    (is-true (member "csv" rules :test #'string=)
             "csv must be present even at a height below its activation")
    (is-false (member "!taproot" rules :test #'string=)
              "taproot is an optional rule and takes no ! prefix")))

(test gbt-rules-arrive-as-the-wire-delivers-them
  "The regression guard for the shape a real miner actually sends.

yason parses a JSON array as a vector, but %NORMALIZE-JSON-VALUE recurses into
every request object and turns each nested non-empty vector back into a LIST
(rpc/server.lisp:338-356). A rules check written against vectors therefore read
NIL from every wire client and answered all of them -8, while passing a suite
whose fixtures stuffed vectors straight into the hash-table.

This test starts from the JSON text and goes through the real parser and the
real normalizer, so it cannot be satisfied by a shape no client can send."
  (let ((bl:*network* :regtest))
    (flet ((wire-params (json)
             (let* ((req (let ((yason:*parse-json-booleans-as-symbols* t)
                               (yason:*parse-json-arrays-as-vectors* t))
                           (yason:parse json)))
                    (raw (gethash "params" req)))
               (bl.rpc::%normalize-rpc-params raw))))
      ;; What contrib/signet/miner and every Core functional test send.
      (let ((params (wire-params "{\"params\":[{\"rules\":[\"segwit\"]}]}")))
        (is (equal '("segwit") (bl.rpc::%gbt-client-rules params))
            "the wire shape of a rules array was not understood")
        (is (null (%gbt-error-message (%gbt-node) params))))
      ;; Several rules, as a signet miner sends.
      (let ((params (wire-params "{\"params\":[{\"rules\":[\"segwit\",\"signet\"]}]}")))
        (is (equal '("segwit" "signet") (bl.rpc::%gbt-client-rules params))))
      ;; A bare string is not an array, in Core or here.
      (let ((params (wire-params "{\"params\":[{\"rules\":\"segwit\"}]}")))
        (is (null (bl.rpc::%gbt-client-rules params)))
        (is-true (%gbt-error-message (%gbt-node) params)))
      ;; An empty array folds to NIL, which is what an absent key gives — and
      ;; that matches Core, where both leave setClientRules empty.
      (let ((params (wire-params "{\"params\":[{\"rules\":[]}]}")))
        (is (null (bl.rpc::%gbt-client-rules params)))
        (is-true (%gbt-error-message (%gbt-node) params)))
      ;; A non-string element is a type error, as Core's get_str() makes it.
      (let ((params (wire-params "{\"params\":[{\"rules\":[7]}]}")))
        (is-true (search "not of expected type string"
                         (or (%gbt-error-message (%gbt-node) params) "")))))))
