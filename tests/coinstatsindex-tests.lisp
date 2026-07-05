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

(test coinstatsindex-muhash-matches-full-set
  "Backfilling the index over a mined regtest chain yields a tip MuHash equal
to the direct whole-UTXO-set MuHash, and tip tallies equal to the live UTXO
set's txout count and total amount."
  (%with-regtest
   (let ((node (%regtest-node-fixture (format nil "csi~D" (get-internal-real-time)))))
     (let ((bitcoin-lisp::*node* node))
       ;; Mine spendable coinbases, then a chain of blocks. Coinbase outputs on
       ;; regtest raw(51) are spendable, so this builds a non-trivial UTXO set.
       (bitcoin-lisp.rpc::rpc-generatetodescriptor node (list 8 "raw(51)"))
       (let* ((cs (bitcoin-lisp::node-chain-state node))
              (store (bitcoin-lisp::node-block-store node))
              (utxo (bitcoin-lisp::node-utxo-set node))
              (tip (bitcoin-lisp.storage:current-height cs))
              (idxbase (merge-pathnames (format nil "test-csi-~D/" (get-internal-real-time))
                                        (uiop:temporary-directory)))
              (csi (bitcoin-lisp.storage:init-coinstatsindex idxbase :enabled t))
              (n (bitcoin-lisp.storage:build-coinstatsindex
                  csi cs store #'bitcoin-lisp.validation:get-undo-data
                  #'bitcoin-lisp.validation:calculate-block-subsidy)))
         ;; Indexed heights 1..tip (genesis is synthesized, not counted).
         (is (= tip n))
         (is (= tip (bitcoin-lisp.storage:coinstatsindex-height csi)))
         (let* ((stats (bitcoin-lisp.storage:coinstatsindex-get-stats csi tip))
                (index-muhash (bitcoin-lisp.crypto:muhash-finalize
                               (bitcoin-lisp.storage:coinstats-muhash stats)))
                (direct-muhash (bitcoin-lisp.storage:compute-utxo-set-muhash utxo)))
           ;; THE invariant: incremental == whole-set.
           (is (equalp direct-muhash index-muhash))
           ;; Tallies match the live UTXO set.
           (is (= (bitcoin-lisp.storage:utxo-count utxo)
                  (bitcoin-lisp.storage:coinstats-txout-count stats)))
           (is (= (bitcoin-lisp.storage:utxo-set-total-amount utxo)
                  (bitcoin-lisp.storage:coinstats-total-amount stats)))
           ;; Every regtest block subsidy summed (genesis..tip).
           (is (= (loop for h from 0 to tip
                        sum (bitcoin-lisp.validation:calculate-block-subsidy h))
                  (bitcoin-lisp.storage:coinstats-total-subsidy stats))))
         (bitcoin-lisp.storage:close-coinstatsindex csi))))))

(test coinstatsindex-per-height-history
  "Each indexed height's record reflects that height's UTXO state: the txout
count is monotonically non-decreasing across a coinbase-only chain, and each
height's MuHash is retrievable and distinct from its predecessor."
  (%with-regtest
   (let ((node (%regtest-node-fixture (format nil "csih~D" (get-internal-real-time)))))
     (let ((bitcoin-lisp::*node* node))
       (bitcoin-lisp.rpc::rpc-generatetodescriptor node (list 4 "raw(51)"))
       (let* ((cs (bitcoin-lisp::node-chain-state node))
              (store (bitcoin-lisp::node-block-store node))
              (tip (bitcoin-lisp.storage:current-height cs))
              (idxbase (merge-pathnames (format nil "test-csih-~D/" (get-internal-real-time))
                                        (uiop:temporary-directory)))
              (csi (bitcoin-lisp.storage:init-coinstatsindex idxbase :enabled t)))
         (bitcoin-lisp.storage:build-coinstatsindex
          csi cs store #'bitcoin-lisp.validation:get-undo-data
          #'bitcoin-lisp.validation:calculate-block-subsidy)
         (let ((prev-count -1) (prev-hash nil))
           (loop for h from 1 to tip
                 for stats = (bitcoin-lisp.storage:coinstatsindex-get-stats csi h)
                 for hh = (bitcoin-lisp.crypto:bytes-to-hex
                           (bitcoin-lisp.crypto:muhash-finalize
                            (bitcoin-lisp.storage:coinstats-muhash stats)))
                 do (is-true stats)
                    (is (>= (bitcoin-lisp.storage:coinstats-txout-count stats) prev-count))
                    (is (not (equal hh prev-hash)))
                    (setf prev-count (bitcoin-lisp.storage:coinstats-txout-count stats)
                          prev-hash hh)))
         (bitcoin-lisp.storage:close-coinstatsindex csi))))))

(test coinstatsindex-connect-hook-and-rpc
  "With the index enabled on a node, the connect-time hook advances it as
blocks are mined, and gettxoutsetinfo <height> serves matching historical
stats from the index (muhash equal to the direct whole-set muhash at the tip)."
  (%with-regtest
   (let* ((tag (format nil "csirpc~D" (get-internal-real-time)))
          (node (%regtest-node-fixture tag))
          (idxbase (merge-pathnames (format nil "test-csirpc-~A/" tag)
                                    (uiop:temporary-directory))))
     (ensure-directories-exist idxbase)
     (setf (bitcoin-lisp::node-coinstatsindex node)
           (bitcoin-lisp.storage:init-coinstatsindex idxbase :enabled t))
     ;; Seed genesis so the connect hook (which needs the parent record) can
     ;; start at height 1, mirroring start-node's backfill seed.
     (bitcoin-lisp.storage:coinstatsindex-seed-genesis
      (bitcoin-lisp::node-coinstatsindex node)
      (bitcoin-lisp.validation:calculate-block-subsidy 0)
      (bitcoin-lisp.storage:network-genesis-hash :regtest))
     (let ((bitcoin-lisp::*node* node))
       ;; The connect hook fires as generatetodescriptor connects each block.
       (bitcoin-lisp.rpc::rpc-generatetodescriptor node (list 6 "raw(51)"))
       (let* ((csi (bitcoin-lisp::node-coinstatsindex node))
              (cs (bitcoin-lisp::node-chain-state node))
              (utxo (bitcoin-lisp::node-utxo-set node))
              (tip (bitcoin-lisp.storage:current-height cs)))
         ;; The hook kept the index at the tip.
         (is (= tip (bitcoin-lisp.storage:coinstatsindex-height csi)))
         ;; gettxoutsetinfo <tip> from the index matches the direct whole set.
         (let* ((res (bitcoin-lisp.rpc::rpc-gettxoutsetinfo node (list "muhash" tip)))
                (direct (bitcoin-lisp.rpc::hash-to-hex
                         (bitcoin-lisp.storage:compute-utxo-set-muhash utxo))))
           (is (= tip (cdr (assoc "height" res :test #'string=))))
           (is (string= direct (cdr (assoc "muhash" res :test #'string=))))
           (is (= (bitcoin-lisp.storage:utxo-count utxo)
                  (cdr (assoc "txouts" res :test #'string=))))
           ;; block_info is present with the per-block deltas.
           (is-true (assoc "block_info" res :test #'string=))
           (is-true (assoc "unspendables" (cdr (assoc "block_info" res :test #'string=))
                           :test #'string=)))
         ;; A height above the tip errors.
         (signals bitcoin-lisp.rpc::rpc-error
           (bitcoin-lisp.rpc::rpc-gettxoutsetinfo node (list "muhash" (+ tip 100))))
         ;; hash_serialized_3 is not index-backed.
         (signals bitcoin-lisp.rpc::rpc-error
           (bitcoin-lisp.rpc::rpc-gettxoutsetinfo node (list "hash_serialized_3" 1)))
         (bitcoin-lisp.storage:close-coinstatsindex csi))))))

(test block-apply-drops-unspendable-outputs
  "After mining regtest blocks (whose coinbases carry a witness-commitment
OP_RETURN output), the UTXO set contains NO unspendable outputs -- block
application drops them, matching Core's AddCoin. The txout count reflects only
the spendable coinbase reward outputs."
  (%with-regtest
   (let ((node (%regtest-node-fixture (format nil "unsp~D" (get-internal-real-time)))))
     (let ((bitcoin-lisp::*node* node))
       (bitcoin-lisp.rpc::rpc-generatetodescriptor node (list 5 "raw(51)"))
       (let ((utxo (bitcoin-lisp::node-utxo-set node))
             (unspendable-found 0)
             (total 0))
         (bitcoin-lisp.storage:utxo-set-iterate
          utxo
          (lambda (txid vout entry)
            (declare (ignore txid vout))
            (incf total)
            (when (bitcoin-lisp.storage:script-unspendable-p
                   (bitcoin-lisp.storage:utxo-entry-script-pubkey entry))
              (incf unspendable-found))))
         ;; No OP_RETURN / oversized outputs made it into the set.
         (is (zerop unspendable-found))
         ;; 5 blocks, one spendable coinbase reward output each (the commitment
         ;; OP_RETURN was dropped) -- so 5, not 10.
         (is (= 5 total))
         (is (= 5 (bitcoin-lisp.storage:utxo-count utxo))))))))

(test coinstatsindex-record-roundtrip
  "A coinstats record survives encode/decode with all fields intact, including
the full MuHash numerator/denominator fraction."
  (let* ((mu (bitcoin-lisp.crypto:make-muhash))
         (e1 (make-array 4 :element-type '(unsigned-byte 8) :initial-contents '(1 2 3 4)))
         (e2 (make-array 3 :element-type '(unsigned-byte 8) :initial-contents '(9 8 7))))
    (bitcoin-lisp.crypto:muhash-insert mu e1)
    (bitcoin-lisp.crypto:muhash-remove mu e2)
    (let* ((stats (bitcoin-lisp.storage::make-coinstats
                   :muhash mu :txout-count 12345 :bogo-size 67890
                   :total-amount 2100000000000000 :total-subsidy 5000000000
                   :total-prevout-spent 42 :total-new-outputs-ex-coinbase 7
                   :total-coinbase 9 :unspendable-genesis 5000000000
                   :unspendable-bip30 100 :unspendable-scripts 200
                   :unspendable-unclaimed 300))
           (decoded (bitcoin-lisp.storage::%csi-decode-stat
                     (bitcoin-lisp.storage::%csi-encode-stat stats))))
      (is (= (bitcoin-lisp.crypto:muhash-numerator mu)
             (bitcoin-lisp.crypto:muhash-numerator (bitcoin-lisp.storage:coinstats-muhash decoded))))
      (is (= (bitcoin-lisp.crypto:muhash-denominator mu)
             (bitcoin-lisp.crypto:muhash-denominator (bitcoin-lisp.storage:coinstats-muhash decoded))))
      (is (= 12345 (bitcoin-lisp.storage:coinstats-txout-count decoded)))
      (is (= 2100000000000000 (bitcoin-lisp.storage:coinstats-total-amount decoded)))
      (is (= 300 (bitcoin-lisp.storage:coinstats-unspendable-unclaimed decoded)))
      ;; Finalized MuHash is preserved through the roundtrip.
      (is (equalp (bitcoin-lisp.crypto:muhash-finalize mu)
                  (bitcoin-lisp.crypto:muhash-finalize
                   (bitcoin-lisp.storage:coinstats-muhash decoded)))))))
