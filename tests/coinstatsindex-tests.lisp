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
