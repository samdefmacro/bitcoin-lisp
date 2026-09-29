(in-package #:bitcoin-lisp.tests)

;;;; coinstatsindex tests (regtest integration).
;;;;
;;;; The load-bearing invariant: the index's incrementally-maintained MuHash at
;;;; the tip must equal the MuHash computed directly over the whole UTXO set
;;;; (compute-utxo-set-muhash), and its amount/count tallies must match the
;;;; node's actual UTXO totals. If the per-block add/remove folding is wrong,
;;;; this diverges. Reuses the regtest fixture from mining-tests.lisp.

(def-suite :coinstatsindex-tests
  :description "coinstatsindex per-height UTXO stats + MuHash"
  :in :bitcoin-lisp-tests)

(in-suite :coinstatsindex-tests)

(defun %txoutsetinfo (node params)
  "gettxoutsetinfo through the exported dispatcher rather than the handler
symbol -- the same door a client comes through, so the argument normalisation
and Core's declared-type gate are part of what these tests exercise."
  (bl.rpc:dispatch-rpc-method node "gettxoutsetinfo" params))

(test coinstatsindex-muhash-matches-full-set
  "Backfilling the index over a mined regtest chain yields a tip MuHash equal
to the direct whole-UTXO-set MuHash, and tip tallies equal to the live UTXO
set's txout count and total amount."
  (with-network (:regtest)
   (let ((node (regtest-node-fixture (format nil "csi~D" (get-internal-real-time)))))
     (let ((bl:*node* node))
       ;; Mine spendable coinbases, then a chain of blocks. Coinbase outputs on
       ;; regtest raw(51) are spendable, so this builds a non-trivial UTXO set.
       (generate-regtest-blocks node 8)
       (let* ((cs (bl:node-chain-state node))
              (store (bl:node-block-store node))
              (utxo (bl:node-utxo-set node))
              (tip (bl.store:current-height cs))
              (idxbase (merge-pathnames (format nil "test-csi-~D/" (get-internal-real-time))
                                        (uiop:temporary-directory)))
              (csi (bl.store:init-coinstatsindex idxbase :enabled t))
              (n (bl.store:build-coinstatsindex
                  csi cs store #'bl.val:get-undo-data
                  #'bl.val:calculate-block-subsidy)))
         ;; Indexed heights 1..tip (genesis is synthesized, not counted).
         (is (= tip n))
         (is (= tip (bl.store:coinstatsindex-height csi)))
         (let* ((stats (bl.store:coinstatsindex-get-stats csi tip))
                (index-muhash (bl.store:coinstats-muhash-hash stats))
                (direct-muhash (bl.store:compute-utxo-set-muhash utxo)))
           ;; THE invariant: incremental == whole-set.
           (is (equalp direct-muhash index-muhash))
           ;; Tallies match the live UTXO set.
           (is (= (bl.store:utxo-count utxo)
                  (bl.store:coinstats-txout-count stats)))
           (is (= (bl.store:utxo-set-total-amount utxo)
                  (bl.store:coinstats-total-amount stats)))
           ;; Core's GetBogoSize is 50 + scriptPubKey (kernel/coinstats.cpp:
           ;; 36-44): 32 txid + 4 vout + 4 height/coinbase + 8 amount + 2
           ;; scriptPubKey length. The index counted 44, six short per coin,
           ;; so feature_coinstatsindex.py:91 -- which compares the index's
           ;; answer with the coins view's, field by field -- saw the two
           ;; differ by 6 times the coin count.
           (is (= (nth-value 1 (bl.store:utxo-set-total-amount utxo))
                  (bl.store:coinstats-bogo-size stats))
               "the index's bogosize must be the whole-set walk's")
           ;; Every regtest block subsidy summed (genesis..tip).
           (is (= (loop for h from 0 to tip
                        sum (bl.val:calculate-block-subsidy h))
                  (bl.store:coinstats-total-subsidy stats))))
         (bl.store:close-coinstatsindex csi))))))

(test coinstatsindex-per-height-history
  "Each indexed height's record reflects that height's UTXO state: the txout
count is monotonically non-decreasing across a coinbase-only chain, and each
height's MuHash is retrievable and distinct from its predecessor."
  (with-network (:regtest)
   (let ((node (regtest-node-fixture (format nil "csih~D" (get-internal-real-time)))))
     (let ((bl:*node* node))
       (generate-regtest-blocks node 4)
       (let* ((cs (bl:node-chain-state node))
              (store (bl:node-block-store node))
              (tip (bl.store:current-height cs))
              (idxbase (merge-pathnames (format nil "test-csih-~D/" (get-internal-real-time))
                                        (uiop:temporary-directory)))
              (csi (bl.store:init-coinstatsindex idxbase :enabled t)))
         (bl.store:build-coinstatsindex
          csi cs store #'bl.val:get-undo-data
          #'bl.val:calculate-block-subsidy)
         (let ((prev-count -1) (prev-hash nil))
           (loop for h from 1 to tip
                 for stats = (bl.store:coinstatsindex-get-stats csi h)
                 for hh = (bl.crypto:bytes-to-hex (bl.store:coinstats-muhash-hash stats))
                 do (is-true stats)
                    (is (>= (bl.store:coinstats-txout-count stats) prev-count))
                    (is (not (equal hh prev-hash)))
                    (setf prev-count (bl.store:coinstats-txout-count stats)
                          prev-hash hh)))
         (bl.store:close-coinstatsindex csi))))))

(test coinstatsindex-connect-hook-and-rpc
  "With the index enabled on a node, the connect-time hook advances it as
blocks are mined, and gettxoutsetinfo <height> serves matching historical
stats from the index (muhash equal to the direct whole-set muhash at the tip)."
  (with-network (:regtest)
   (let* ((tag (format nil "csirpc~D" (get-internal-real-time)))
          (node (regtest-node-fixture tag))
          (idxbase (merge-pathnames (format nil "test-csirpc-~A/" tag)
                                    (uiop:temporary-directory))))
     (ensure-directories-exist idxbase)
     (setf (bl:node-coinstatsindex node)
           (bl.store:init-coinstatsindex idxbase :enabled t))
     ;; Seed genesis so the connect hook (which needs the parent record) can
     ;; start at height 1, mirroring start-node's backfill seed.
     (bl.store:coinstatsindex-seed-genesis
      (bl:node-coinstatsindex node)
      (bl.val:calculate-block-subsidy 0)
      (bl.store:network-genesis-hash :regtest))
     (let ((bl:*node* node))
       ;; The connect hook fires as generatetodescriptor connects each block.
       (generate-regtest-blocks node 6)
       (let* ((csi (bl:node-coinstatsindex node))
              (cs (bl:node-chain-state node))
              (utxo (bl:node-utxo-set node))
              (tip (bl.store:current-height cs)))
         ;; The hook kept the index at the tip.
         (is (= tip (bl.store:coinstatsindex-height csi)))
         ;; gettxoutsetinfo <tip> from the index matches the direct whole set.
         (let* ((res (%txoutsetinfo node (list "muhash" tip)))
                (direct (bl.rpc:hash-to-hex
                         (bl.store:compute-utxo-set-muhash utxo))))
           (is (= tip (cdr (assoc "height" res :test #'string=))))
           (is (string= direct (cdr (assoc "muhash" res :test #'string=))))
           (is (= (bl.store:utxo-count utxo)
                  (cdr (assoc "txouts" res :test #'string=))))
           ;; block_info is present with the per-block deltas.
           (is-true (assoc "block_info" res :test #'string=))
           (is-true (assoc "unspendables" (cdr (assoc "block_info" res :test #'string=))
                           :test #'string=)))
         ;; The TIP is index-backed too, with no height argument at all.
         ;; Core's gate is `index_requested && g_coin_stats_index'
         ;; (rpc/blockchain.cpp:1101, :1113); a height is not part of it, and
         ;; an index-backed answer carries block_info and
         ;; total_unspendable_amount where an index-free one carries
         ;; transactions and disk_size (:1128-1130).
         ;; feature_coinstatsindex.py:87 reads block_info out of the plain
         ;; call, which we answered from the coins view.
         (let ((res (%txoutsetinfo node (list "muhash"))))
           (is-true (assoc "block_info" res :test #'string=)
                    "the tip must come from the index when one is enabled")
           (is-true (assoc "total_unspendable_amount" res :test #'string=))
           (is (null (assoc "disk_size" res :test #'string=))
               "an index answer has no disk_size")
           (is (null (assoc "transactions" res :test #'string=))
               "an index answer has no transactions"))
         ;; use_index=false takes the coins view instead, and that answer is
         ;; the OTHER shape.
         ;; Explicit false, as the wire delivers it: the sentinel, not NIL --
         ;; NIL is Core's isNull(), which means "use the default".
         (let ((res (%txoutsetinfo
                     node (list "muhash" nil bl.rpc:+json-false+))))
           (is-true (assoc "disk_size" res :test #'string=))
           (is-true (assoc "transactions" res :test #'string=))
           (is (null (assoc "block_info" res :test #'string=))))
         ;; A height above the tip errors.
         (signals bl.rpc:rpc-error
           (%txoutsetinfo node (list "muhash" (+ tip 100))))
         ;; hash_serialized_3 is not index-backed, and Core says so in its own
         ;; words (rpc/blockchain.cpp:1091) -- for every spelling of use_index,
         ;; because that gate comes AFTER this one (:1095). Ours refused the
         ;; explicit false first, so feature_coinstatsindex.py:302 read
         ;; "Cannot set use_index to false when querying for a specific block"
         ;; for a call whose fault Core names as the hash type.
         (dolist (use-index (list :omitted t bl.rpc:+json-false+))
           (signals-rpc-error
               (:code -8 :exact-message
                      "hash_serialized_3 hash type cannot be queried for a specific block")
             (%txoutsetinfo node (if (eq use-index :omitted)
                                     (list "hash_serialized_3" 1)
                                     (list "hash_serialized_3" 1 use-index)))))
         ;; An unknown hash type is Core's ParseHashType sentence, which quotes
         ;; the text it was given (rpc/blockchain.cpp:975); rpc_blockchain.py
         ;; :420 asks for it with a value carrying a space.
         (signals-rpc-error (:code -8 :exact-message
                                   "'foo hash' is not a valid hash_type")
           (%txoutsetinfo node (list "foo hash")))
         (bl.store:close-coinstatsindex csi))))))

(test block-apply-drops-unspendable-outputs
  "After mining regtest blocks (whose coinbases carry a witness-commitment
OP_RETURN output), the UTXO set contains NO unspendable outputs -- block
application drops them, matching Core's AddCoin. The txout count reflects only
the spendable coinbase reward outputs."
  (with-network (:regtest)
   (let ((node (regtest-node-fixture (format nil "unsp~D" (get-internal-real-time)))))
     (let ((bl:*node* node))
       (generate-regtest-blocks node 5)
       (let ((utxo (bl:node-utxo-set node))
             (unspendable-found 0)
             (total 0))
         (bl.store:utxo-set-iterate
          utxo
          (lambda (txid vout entry)
            (declare (ignore txid vout))
            (incf total)
            (when (bl.store:script-unspendable-p
                   (bl.store:utxo-entry-script-pubkey entry))
              (incf unspendable-found))))
         ;; No OP_RETURN / oversized outputs made it into the set.
         (is (zerop unspendable-found))
         ;; 5 blocks, one spendable coinbase reward output each (the commitment
         ;; OP_RETURN was dropped) -- so 5, not 10.
         (is (= 5 total))
         (is (= 5 (bl.store:utxo-count utxo))))))))

(defun %csi-height-key (height)
  "Core's DBHeightKey: 't' || height u32 BE."
  (let ((key (make-array 5 :element-type '(unsigned-byte 8))))
    (setf (aref key 0) (char-code #\t))
    (dotimes (i 4 key)
      (setf (aref key (- 4 i)) (ldb (byte 8 (* 8 i)) height)))))

(defun %csi-raw-record (csi height)
  "The stored height record at HEIGHT as raw bytes (NIL if absent)."
  (bl.kv:leveldb-get (bl.store:coinstatsindex-db csi) (%csi-height-key height)))

(defun %csi-fixture (tag blocks)
  "(values node csi cs tip) — a regtest node with BLOCKS mined blocks and a
coinstats index built over them, installed on the node. Call inside
(with-network (:regtest) ...)."
  (let* ((node (regtest-node-fixture tag))
         (idxbase (merge-pathnames (format nil "test-csi-rw-~A/" tag)
                                   (uiop:temporary-directory))))
    (let ((bl:*node* node))
      (generate-regtest-blocks node blocks))
    (let* ((cs (bl:node-chain-state node))
           (csi (bl.store:init-coinstatsindex idxbase :enabled t)))
      (bl.store:build-coinstatsindex
       csi cs (bl:node-block-store node)
       #'bl.val:get-undo-data
       #'bl.val:calculate-block-subsidy)
      (setf (bl:node-coinstatsindex node) csi)
      (values node csi cs (bl.store:current-height cs)))))

(test coinstatsindex-records-are-cores
  "Each height's record is Core's: 't' || height BE -> block hash || DBVal, the
DBVal 32 + 4*8 + 3*32 + 4*8 = 192 bytes whose first 32 are the FINALIZED
MuHash and whose three running amounts are uint256 (coinstatsindex.cpp:44-80);
the running fraction is written once, under 'M', beside the locator at a
commit, as numerator || denominator, 384 little-endian bytes each."
  (with-network (:regtest)
    (multiple-value-bind (node csi cs tip)
        (%csi-fixture (format nil "csirec~D" (get-internal-real-time)) 3)
      (declare (ignore node))
      (let ((raw (%csi-raw-record csi tip))
            (stats (bl.store:coinstatsindex-get-stats csi tip)))
        (is (= (+ 32 192) (length raw)))
        (is (equalp (bl.store:block-index-entry-hash (bl.store:get-block-at-height cs tip))
                    (subseq raw 0 32)))
        (is (equalp (bl.store:coinstats-muhash-hash stats) (subseq raw 32 64)))
        ;; txouts u64 LE right after the digest.
        (is (= (bl.store:coinstats-txout-count stats)
               (loop for i below 8 sum (ash (aref raw (+ 64 i)) (* 8 i))))))
      (bl.store:commit-index csi cs)
      (let ((m (bl.kv:leveldb-get (bl.store:coinstatsindex-db csi)
                                  (make-array 1 :element-type '(unsigned-byte 8)
                                                :initial-element (char-code #\M)))))
        (is (= 768 (length m)))
        (is (equalp (bl.crypto:muhash-finalize
                     (bl.crypto:make-muhash-raw
                      :numerator (bl.crypto:bytes-to-le-integer (subseq m 0 384))
                      :denominator (bl.crypto:bytes-to-le-integer (subseq m 384 768))))
                    (bl.store:coinstats-muhash-hash (bl.store:coinstatsindex-get-stats csi tip)))
            "'M' is the fraction the best record's digest finalizes"))
      (bl.store:close-coinstatsindex csi))))

(defun %csi-old-record (stats block-hash)
  "STATS in this tree's pre-2026-09-29 layout: numerator || denominator (384 LE
each), eleven i64 LE tallies, then the block hash."
  (let ((v (make-array (+ 768 88 32) :element-type '(unsigned-byte 8)))
        (mu (bl.store:coinstats-muhash stats)))
    (replace v (bl.crypto:le-integer-to-bytes (bl.crypto:muhash-numerator mu) 384))
    (replace v (bl.crypto:le-integer-to-bytes (bl.crypto:muhash-denominator mu) 384) :start1 384)
    (loop for off from 768 by 8
          for val in (list (bl.store:coinstats-txout-count stats)
                           (bl.store:coinstats-bogo-size stats)
                           (bl.store:coinstats-total-amount stats)
                           (bl.store:coinstats-total-subsidy stats)
                           (bl.store:coinstats-total-prevout-spent stats)
                           (bl.store:coinstats-total-new-outputs-ex-coinbase stats)
                           (bl.store:coinstats-total-coinbase stats)
                           (bl.store:coinstats-unspendable-genesis stats)
                           (bl.store:coinstats-unspendable-bip30 stats)
                           (bl.store:coinstats-unspendable-scripts stats)
                           (bl.store:coinstats-unspendable-unclaimed stats))
          do (dotimes (i 8) (setf (aref v (+ off i)) (ldb (byte 8 (* 8 i)) val))))
    (replace v block-hash :start1 (+ 768 88))
    v))

(test coinstatsindex-migrates-the-old-full-state-records
  "An index written before 2026-09-29 kept the whole running state per height
under 'S' || height. The migration writes 'M' from the best height's old record
and every height's record in Core's form, in place; the result is byte for byte
what the index writes today, and the running state loads from it."
  (with-network (:regtest)
    (multiple-value-bind (node csi cs tip)
        (%csi-fixture (format nil "csimig~D" (get-internal-real-time)) 4)
      (let* ((db (bl.store:coinstatsindex-db csi))
             (store (bl:node-block-store node))
             (core (loop for h from 0 to tip collect (%csi-raw-record csi h)))
             (subsidy0 (bl.val:calculate-block-subsidy 0))
             (running (bl.store::make-coinstats :total-subsidy subsidy0
                                                :unspendable-genesis subsidy0)))
        ;; Replace every record by the old layout, folding the chain afresh.
        (loop for h from 0 to tip
              for hash = (bl.store:block-index-entry-hash (bl.store:get-block-at-height cs h))
              do (when (plusp h)
                   (bl.store:apply-block-to-coinstats
                    running (bl.store:get-block store hash) hash h
                    (bl.val:get-undo-data hash) (bl.val:calculate-block-subsidy h)))
                 (bl.kv:leveldb-delete db (%csi-height-key h))
                 (bl.kv:leveldb-put db (concatenate '(vector (unsigned-byte 8))
                                                    (vector (char-code #\S))
                                                    (subseq (%csi-height-key h) 1))
                                    (%csi-old-record running hash)))
        (bl.kv:leveldb-delete db (make-array 1 :element-type '(unsigned-byte 8)
                                               :initial-element (char-code #\M)))
        (is-true (bl.store:coinstatsindex-needs-migration-p csi))
        (is (= (1+ tip) (bl.store:migrate-coinstatsindex csi cs)))
        (is (null (bl.store:coinstatsindex-needs-migration-p csi)))
        (is (equalp core (loop for h from 0 to tip collect (%csi-raw-record csi h))))
        (bl.store:coinstatsindex-clear-best csi)
        (bl.store:coinstatsindex-set-best
         csi tip (bl.store:block-index-entry-hash (bl.store:get-block-at-height cs tip)))
        (is-true (bl.store:coinstatsindex-load-running csi)
                 "the running state loads from the migrated 'M' and best record"))
      (bl.store:close-coinstatsindex csi))))

;;;; Rewind (Core BaseIndex::Rewind over CoinStatsIndex::CustomRemove /
;;;; RevertBlock, index/coinstatsindex.cpp:245-262, 329-399). The index keeps
;;;; Core's running state; going back means reversing blocks with their bodies
;;;; and undo data, checked against the parent's record.

(defmacro %csi-counting-calls ((count-var fname) &body body)
  "Run BODY with calls to FNAME counted in COUNT-VAR (the real function still
runs), restoring FNAME afterwards."
  (let ((real (gensym "REAL")))
    `(let ((,count-var 0)
           (,real (fdefinition ,fname)))
       (unwind-protect
            (progn
              (setf (fdefinition ,fname)
                    (lambda (&rest args) (incf ,count-var) (apply ,real args)))
              ,@body)
         (setf (fdefinition ,fname) ,real)))))

(test coinstatsindex-reverts-blocks-an-index-is-ahead-by
  "The unclean-shutdown shape: the index reached blocks the restored chainstate
tip has not, on the SAME chain. The catch-up reverses them one by one (Core's
RevertBlock: the outputs they created leave the MuHash, the coins they spent
return, the tallies come back from the parent's record) and lands on the tip
without re-indexing anything -- and a second catch-up after the tip moves on
re-indexes exactly the blocks above it."
  (with-network (:regtest)
    (multiple-value-bind (node csi cs tip)
        (%csi-fixture (format nil "csiahd~D" (get-internal-real-time)) 5)
      (let* ((top (bl.store:get-block-at-height cs tip))
             (back (bl.store:get-block-at-height cs (- tip 2)))
             (records (loop for h from 0 to tip collect (%csi-raw-record csi h))))
        ;; The chainstate restored two blocks below where the index got.
        (bl.store:update-chain-tip cs (bl.store:block-index-entry-hash back) (- tip 2))
        (%csi-counting-calls (adds 'bl.store:coinstatsindex-add-block)
          (bl:catch-up-index node csi)
          (is (= 0 adds) "reverting re-indexed ~D block(s)" adds))
        (is (= (- tip 2) (bl.store:coinstatsindex-height csi)))
        (is (equalp (bl.store:block-index-entry-hash back)
                    (nth-value 1 (bl.store:coinstatsindex-best csi))))
        ;; The chainstate catches up again: the two blocks are folded back in,
        ;; and every record is what it was.
        (bl.store:update-chain-tip cs (bl.store:block-index-entry-hash top) tip)
        (%csi-counting-calls (adds 'bl.store:coinstatsindex-add-block)
          (bl:catch-up-index node csi)
          (is (= 2 adds)))
        (is (equalp records (loop for h from 0 to tip collect (%csi-raw-record csi h))))
        (is (equalp (bl.store:compute-utxo-set-muhash (bl:node-utxo-set node))
                    (bl.store:coinstats-muhash-hash (bl.store:coinstatsindex-get-stats csi tip)))))
      (bl.store:close-coinstatsindex csi))))

(test coinstatsindex-rebuilds-when-its-branch-cannot-be-reversed
  "A best block the header index cannot place, or one whose blocks are not on
disk, cannot be reversed. The index is then rebuilt from genesis -- and the
rebuild writes exactly the records a consistent index holds."
  (with-network (:regtest)
    (multiple-value-bind (node csi cs tip)
        (%csi-fixture (format nil "csirb~D" (get-internal-real-time)) 4)
      (let ((records (loop for h from 0 to tip collect (%csi-raw-record csi h))))
        (bl.store:coinstatsindex-set-best
         csi tip (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xE7))
        (%csi-counting-calls (adds 'bl.store:coinstatsindex-add-block)
          (bl:catch-up-index node csi)
          (is (= tip adds) "the rebuild indexed ~D block(s)" adds))
        (is (= tip (bl.store:coinstatsindex-height csi)))
        (is (equalp records (loop for h from 0 to tip collect (%csi-raw-record csi h)))))
      (bl.store:close-coinstatsindex csi))))

(test coinstatsindex-consistent-index-is-not-rebuilt
  "Control: a consistent index must NOT rewind and must NOT re-index a single
block -- a fix that always rebuilt would be hours on a real chain."
  (with-network (:regtest)
    (multiple-value-bind (node csi cs tip)
        (%csi-fixture (format nil "csictl~D" (get-internal-real-time)) 5)
      (declare (ignore cs))
      (%csi-counting-calls (adds 'bl.store:coinstatsindex-add-block)
        (bl:catch-up-index node csi)
        (is (= 0 adds) "a consistent index re-indexed ~D block(s)" adds))
      (is (= tip (bl.store:coinstatsindex-height csi)))
      (bl.store:close-coinstatsindex csi))))

(defun %csi-fake-branch (cs from-height to-height seed)
  "Add synthetic block-index entries for a competing branch over
FROM-HEIGHT+1..TO-HEIGHT, forking off the active chain at FROM-HEIGHT.
Returns the branch tip's hash."
  (let ((prev (bl.store:get-block-at-height cs from-height))
        (tip-hash nil))
    (loop for h from (1+ from-height) to to-height
          for hash = (make-array 32 :element-type '(unsigned-byte 8)
                                    :initial-element (+ seed h))
          do (let ((entry (bl.store:make-block-index-entry
                           :hash hash :height h :chain-work 1 :status :valid
                           :prev-entry prev
                           :header (bl.store:block-index-entry-header
                                    (bl.store:get-block-at-height cs h)))))
               (bl.store:add-block-index-entry cs entry)
               (setf prev entry tip-hash hash)))
    tip-hash))

(test coinstatsindex-answers-a-block-a-reorg-took-off-the-chain
  "Core\'s index keeps a reorged-out block\'s record: the height key holds the
block hash beside the value, and CustomRemove copies the record under that
hash before another branch claims the height (coinstatsindex.cpp:216-234), so
LookUpOne answers by hash afterwards (index/db_key.h:96-113). Ours was keyed by
height ALONE, so the RPC had to refuse a stale-branch hash outright rather than
serve the active chain\'s numbers under it -- and
feature_coinstatsindex.py:279-281 invalidates two blocks, mines two more, and
asks for the invalidated tip by hash.

The two records are made distinguishable by indexing the branch with a
different subsidy, so a lookup that silently fell back to the height record
would report the other one\'s cumulative total."
  (with-network (:regtest)
   (multiple-value-bind (node csi cs tip)
       (%csi-fixture (format nil "csireorg~D" (get-internal-real-time)) 4)
     (let* ((active-entry (bl.store:get-block-at-height cs tip))
            (active-hash (bl.store:block-index-entry-hash active-entry))
            (block (bl.store:get-block (bl:node-block-store node) active-hash))
            (undo (bl.val:get-undo-data active-hash))
            (subsidy (bl.val:calculate-block-subsidy tip))
            (branch-hash (%csi-fake-branch cs (1- tip) tip 150))
            ;; Read through the HEIGHT key, which still names the active
            ;; block at this point, so the baseline needs no new function.
            (active-subsidy (bl.store:coinstats-total-subsidy
                             (bl.store:coinstatsindex-get-stats csi tip))))
       (is-true block "the fixture must have the tip block on disk")
       ;; Back to the parent (Core's CustomRemove for the tip) ...
       (is-true (bl.store:coinstatsindex-revert-block csi block active-hash tip undo))
       ;; ... the competing block holds the height, with a subsidy of its own
       ;; so the two records cannot be confused ...
       (bl.store:coinstatsindex-add-block csi block branch-hash tip undo
                                          (1+ subsidy))
       ;; ... and is reversed in its turn when the active block reclaims the
       ;; height, which is the moment Core copies what the height held under
       ;; its own hash.
       (is-true (bl.store:coinstatsindex-revert-block csi block branch-hash tip undo))
       (bl.store:coinstatsindex-add-block csi block active-hash tip undo subsidy)
       ;; End to end first, so a run against the previous code fails on the
       ;; ANSWER and not on a symbol this change introduces.
       (let ((res (%txoutsetinfo node (list "muhash" (bl.rpc:hash-to-hex branch-hash)))))
         (is (= tip (cdr (assoc "height" res :test #'string=))))
         (is (string= (bl.rpc:hash-to-hex branch-hash)
                      (cdr (assoc "bestblock" res :test #'string=)))
             "and reports the block that was asked for"))
       (is (= active-subsidy
              (bl.store:coinstats-total-subsidy
               (bl.store:coinstatsindex-get-stats csi tip)))
           "the height-keyed read still answers for the active chain")
       (let ((by-active (bl.store:coinstatsindex-get-block-stats csi active-hash tip))
             (by-branch (bl.store:coinstatsindex-get-block-stats csi branch-hash tip)))
         (is (= active-subsidy (bl.store:coinstats-total-subsidy by-active))
             "the height record is the active chain\'s again")
         (is-true by-branch
                  "the reorged-out block\'s record must survive under its hash")
         (when by-branch
           (is (= (1+ active-subsidy) (bl.store:coinstats-total-subsidy by-branch))
               "and it must be the branch\'s own record, not the height\'s")))
       (bl.store:close-coinstatsindex csi)))))

(test coinstatsindex-rpc-refuses-a-branch-it-never-indexed
  "The other half of the rule: a hash the header index resolves but the
coinstats index has never held -- a branch whose blocks were never connected --
has no record under either key, so it is refused rather than answered with
whatever the height happens to hold now. Control: the active-chain hash at the
same height still works."
  (with-network (:regtest)
   (multiple-value-bind (node csi cs tip)
       (%csi-fixture (format nil "csirpc2~D" (get-internal-real-time)) 4)
     (let* ((stale (%csi-fake-branch cs (1- tip) tip 150))
            (active (bl.store:block-index-entry-hash
                     (bl.store:get-block-at-height cs tip))))
       (signals bl.rpc:rpc-error
         (%txoutsetinfo
          node (list "muhash" (bl.rpc:hash-to-hex stale))))
       (let ((res (%txoutsetinfo
                   node (list "muhash" (bl.rpc:hash-to-hex active)))))
         (is (= tip (cdr (assoc "height" res :test #'string=)))))
       ;; A height above the best marker is not vouched for either.
       (bl.store:coinstatsindex-set-best
        csi (1- tip) (bl.store:block-index-entry-hash
                      (bl.store:get-block-at-height cs (1- tip))))
       (signals bl.rpc:rpc-error
         (%txoutsetinfo node (list "muhash" tip)))
       (bl.store:close-coinstatsindex csi)))))
