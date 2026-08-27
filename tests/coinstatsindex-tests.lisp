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
     (let ((bl::*node* node))
       ;; Mine spendable coinbases, then a chain of blocks. Coinbase outputs on
       ;; regtest raw(51) are spendable, so this builds a non-trivial UTXO set.
       (bl.rpc::rpc-generatetodescriptor node (list 8 "raw(51)"))
       (let* ((cs (bl::node-chain-state node))
              (store (bl::node-block-store node))
              (utxo (bl::node-utxo-set node))
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
                (index-muhash (bl.crypto:muhash-finalize
                               (bl.store:coinstats-muhash stats)))
                (direct-muhash (bl.store:compute-utxo-set-muhash utxo)))
           ;; THE invariant: incremental == whole-set.
           (is (equalp direct-muhash index-muhash))
           ;; Tallies match the live UTXO set.
           (is (= (bl.store:utxo-count utxo)
                  (bl.store:coinstats-txout-count stats)))
           (is (= (bl.store:utxo-set-total-amount utxo)
                  (bl.store:coinstats-total-amount stats)))
           ;; Every regtest block subsidy summed (genesis..tip).
           (is (= (loop for h from 0 to tip
                        sum (bl.val:calculate-block-subsidy h))
                  (bl.store:coinstats-total-subsidy stats))))
         (bl.store:close-coinstatsindex csi))))))

(test coinstatsindex-per-height-history
  "Each indexed height's record reflects that height's UTXO state: the txout
count is monotonically non-decreasing across a coinbase-only chain, and each
height's MuHash is retrievable and distinct from its predecessor."
  (%with-regtest
   (let ((node (%regtest-node-fixture (format nil "csih~D" (get-internal-real-time)))))
     (let ((bl::*node* node))
       (bl.rpc::rpc-generatetodescriptor node (list 4 "raw(51)"))
       (let* ((cs (bl::node-chain-state node))
              (store (bl::node-block-store node))
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
                 for hh = (bl.crypto:bytes-to-hex
                           (bl.crypto:muhash-finalize
                            (bl.store:coinstats-muhash stats)))
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
  (%with-regtest
   (let* ((tag (format nil "csirpc~D" (get-internal-real-time)))
          (node (%regtest-node-fixture tag))
          (idxbase (merge-pathnames (format nil "test-csirpc-~A/" tag)
                                    (uiop:temporary-directory))))
     (ensure-directories-exist idxbase)
     (setf (bl::node-coinstatsindex node)
           (bl.store:init-coinstatsindex idxbase :enabled t))
     ;; Seed genesis so the connect hook (which needs the parent record) can
     ;; start at height 1, mirroring start-node's backfill seed.
     (bl.store:coinstatsindex-seed-genesis
      (bl::node-coinstatsindex node)
      (bl.val:calculate-block-subsidy 0)
      (bl.store:network-genesis-hash :regtest))
     (let ((bl::*node* node))
       ;; The connect hook fires as generatetodescriptor connects each block.
       (bl.rpc::rpc-generatetodescriptor node (list 6 "raw(51)"))
       (let* ((csi (bl::node-coinstatsindex node))
              (cs (bl::node-chain-state node))
              (utxo (bl::node-utxo-set node))
              (tip (bl.store:current-height cs)))
         ;; The hook kept the index at the tip.
         (is (= tip (bl.store:coinstatsindex-height csi)))
         ;; gettxoutsetinfo <tip> from the index matches the direct whole set.
         (let* ((res (bl.rpc::rpc-gettxoutsetinfo node (list "muhash" tip)))
                (direct (bl.rpc::hash-to-hex
                         (bl.store:compute-utxo-set-muhash utxo))))
           (is (= tip (cdr (assoc "height" res :test #'string=))))
           (is (string= direct (cdr (assoc "muhash" res :test #'string=))))
           (is (= (bl.store:utxo-count utxo)
                  (cdr (assoc "txouts" res :test #'string=))))
           ;; block_info is present with the per-block deltas.
           (is-true (assoc "block_info" res :test #'string=))
           (is-true (assoc "unspendables" (cdr (assoc "block_info" res :test #'string=))
                           :test #'string=)))
         ;; A height above the tip errors.
         (signals bl.rpc::rpc-error
           (bl.rpc::rpc-gettxoutsetinfo node (list "muhash" (+ tip 100))))
         ;; hash_serialized_3 is not index-backed.
         (signals bl.rpc::rpc-error
           (bl.rpc::rpc-gettxoutsetinfo node (list "hash_serialized_3" 1)))
         (bl.store:close-coinstatsindex csi))))))

(test block-apply-drops-unspendable-outputs
  "After mining regtest blocks (whose coinbases carry a witness-commitment
OP_RETURN output), the UTXO set contains NO unspendable outputs -- block
application drops them, matching Core's AddCoin. The txout count reflects only
the spendable coinbase reward outputs."
  (%with-regtest
   (let ((node (%regtest-node-fixture (format nil "unsp~D" (get-internal-real-time)))))
     (let ((bl::*node* node))
       (bl.rpc::rpc-generatetodescriptor node (list 5 "raw(51)"))
       (let ((utxo (bl::node-utxo-set node))
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

(test coinstatsindex-record-roundtrip
  "A coinstats record survives encode/decode with all fields intact, including
the full MuHash numerator/denominator fraction."
  (let* ((mu (bl.crypto:make-muhash))
         (e1 (make-array 4 :element-type '(unsigned-byte 8) :initial-contents '(1 2 3 4)))
         (e2 (make-array 3 :element-type '(unsigned-byte 8) :initial-contents '(9 8 7))))
    (bl.crypto:muhash-insert mu e1)
    (bl.crypto:muhash-remove mu e2)
    (let* ((stats (bl.store::make-coinstats
                   :muhash mu :txout-count 12345 :bogo-size 67890
                   :total-amount 2100000000000000 :total-subsidy 5000000000
                   :total-prevout-spent 42 :total-new-outputs-ex-coinbase 7
                   :total-coinbase 9 :unspendable-genesis 5000000000
                   :unspendable-bip30 100 :unspendable-scripts 200
                   :unspendable-unclaimed 300))
           (decoded (bl.store::%csi-decode-stat
                     (bl.store::%csi-encode-stat stats))))
      (is (= (bl.crypto:muhash-numerator mu)
             (bl.crypto:muhash-numerator (bl.store:coinstats-muhash decoded))))
      (is (= (bl.crypto:muhash-denominator mu)
             (bl.crypto:muhash-denominator (bl.store:coinstats-muhash decoded))))
      (is (= 12345 (bl.store:coinstats-txout-count decoded)))
      (is (= 2100000000000000 (bl.store:coinstats-total-amount decoded)))
      (is (= 300 (bl.store:coinstats-unspendable-unclaimed decoded)))
      ;; Finalized MuHash is preserved through the roundtrip.
      (is (equalp (bl.crypto:muhash-finalize mu)
                  (bl.crypto:muhash-finalize
                   (bl.store:coinstats-muhash decoded)))))))

;;;; Rewind on a divergent index (GA8 wave 5, Core BaseIndex::Rewind).
;;;;
;;;; Records are keyed by HEIGHT with no block hash and there is no disconnect
;;;; hook, while index writes reach the OS immediately and the chainstate tip
;;;; only becomes durable at a flush (a reorg does not trigger one). A process
;;;; kill in that window leaves records holding an ABANDONED chain's state at
;;;; heights at or below the tip that startup restores; the repair loop this
;;;; replaced blessed them by existence and overwrote the stored meta hash —
;;;; the one piece of evidence that could have detected the divergence.

(defun %csi-fixture (tag blocks)
  "(values node csi cs tip) — a regtest node with BLOCKS mined blocks and a
coinstats index built over them, installed on the node. Call inside
%with-regtest."
  (let* ((node (%regtest-node-fixture tag))
         (idxbase (merge-pathnames (format nil "test-csi-rw-~A/" tag)
                                   (uiop:temporary-directory))))
    (let ((bl::*node* node))
      (bl.rpc::rpc-generatetodescriptor node (list blocks "raw(51)")))
    (let* ((cs (bl::node-chain-state node))
           (csi (bl.store:init-coinstatsindex idxbase :enabled t)))
      (bl.store:build-coinstatsindex
       csi cs (bl::node-block-store node)
       #'bl.val:get-undo-data
       #'bl.val:calculate-block-subsidy)
      (setf (bl::node-coinstatsindex node) csi)
      (values node csi cs (bl.store:current-height cs)))))

(defmacro %csi-counting-calls ((count-var fname) &body body)
  "Run BODY with calls to FNAME counted in COUNT-VAR (the real function still
runs), restoring FNAME afterwards. Lets a test assert which of two rewind
paths did the work — and that the counter can move at all."
  (let ((real (gensym "REAL")))
    `(let ((,count-var 0)
           (,real (fdefinition ,fname)))
       (unwind-protect
            (progn
              (setf (fdefinition ,fname)
                    (lambda (&rest args) (incf ,count-var) (apply ,real args)))
              ,@body)
         (setf (fdefinition ,fname) ,real)))))

(defun %csi-raw-record (csi height)
  "The stored record at HEIGHT as raw bytes (NIL if absent)."
  (bl.store::leveldb-get
   (bl.store:coinstatsindex-db csi)
   (bl.store::%csi-stat-key height)))

(defun %csi-put-raw-record (csi height bytes)
  (bl.store::leveldb-put
   (bl.store:coinstatsindex-db csi)
   (bl.store::%csi-stat-key height) bytes))

(defun %csi-fake-branch (cs from-height to-height seed)
  "Add synthetic block-index entries for a competing branch over
FROM-HEIGHT+1..TO-HEIGHT, forking off the active chain at FROM-HEIGHT.
Returns the branch tip's hash. Models a reorg whose headers the node still
knows (they were persisted by an earlier flush)."
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

(defun %csi-divergent-state (csi fork-height tip branch-hash)
  "Make the index look like it followed an abandoned branch above FORK-HEIGHT:
records at FORK-HEIGHT+1..TIP replaced by a lower height's record, and the best
marker naming BRANCH-HASH at TIP. Returns the correct records (an alist of
height -> bytes) so the test can assert they are rebuilt."
  (let ((correct (loop for h from (1+ fork-height) to tip
                       collect (cons h (%csi-raw-record csi h))))
        (wrong (%csi-raw-record csi (1- fork-height))))
    (loop for h from (1+ fork-height) to tip
          do (%csi-put-raw-record csi h wrong))
    (bl.store:coinstatsindex-set-best csi tip branch-hash)
    correct))

(test coinstatsindex-rewinds-to-fork-point-when-branch-is-known
  "A best marker naming a block that is NOT the active chain's block at that
height must be rewound to the last common ancestor and the records above it
rebuilt — not blessed in place with the active chain's hash written over the
evidence. Here the abandoned branch's headers are still in the header index,
so the fork point comes from the cheap ancestor walk (Core's pprev walk in
BaseIndex::Rewind)."
  (%with-regtest
   (multiple-value-bind (node csi cs tip)
       (%csi-fixture (format nil "csirw~D" (get-internal-real-time)) 6)
     (let* ((fork (- tip 2))
            (branch (%csi-fake-branch cs fork tip 200))
            (correct (%csi-divergent-state csi fork tip branch)))
       ;; Precondition: the index now serves the wrong records.
       (is (not (equalp (cdr (assoc tip correct)) (%csi-raw-record csi tip))))
       ;; Drive the shipped startup entry point: it must rewind and rebuild
       ;; every record above the fork, exactly.
       (bl::%catch-up-coinstatsindex node)
       (is (= tip (bl.store:coinstatsindex-height csi)))
       (dolist (entry correct)
         (is (equalp (cdr entry) (%csi-raw-record csi (car entry)))
             "record at height ~D was not rebuilt" (car entry)))
       ;; The best marker names the ACTIVE chain's tip again.
       (multiple-value-bind (h hash) (bl.store:coinstatsindex-best csi)
         (is (= tip h))
         (is (equalp (bl.store:block-index-entry-hash
                      (bl.store:get-block-at-height cs tip))
                     hash)))
       ;; Re-diverge to observe the rewind itself: it lands on the fork point,
       ;; and gets there from the header index alone — no record recomputed, so
       ;; this path is measured separately from the fallback in the next test.
       (%csi-divergent-state csi fork tip branch)
       (%csi-counting-calls
           (verifications 'bl.store:coinstatsindex-record-matches-block-p)
         (is (eql fork (bl::%rewind-coinstatsindex node)))
         (is (= 0 verifications)
             "the header-index ancestor walk did not resolve the fork (~D recomputations)"
             verifications))
       (is (= fork (bl.store:coinstatsindex-height csi)))
       (bl.store:close-coinstatsindex csi)))))

(test coinstatsindex-rewinds-when-branch-headers-are-lost
  "Same divergence, but the abandoned branch's headers are NOT in the header
index — the realistic case, since headers are only persisted at flush time, so
the crash that strands the marker also loses the branch it names. The rewind
must still find the fork point, by recomputing each record from its stored
parent and the active block at that height."
  (%with-regtest
   (multiple-value-bind (node csi cs tip)
       (%csi-fixture (format nil "csirwu~D" (get-internal-real-time)) 6)
     (let* ((fork (- tip 2))
            (unknown (make-array 32 :element-type '(unsigned-byte 8)
                                    :initial-element #xE7))
            (correct (%csi-divergent-state csi fork tip unknown)))
       (is (null (bl.store:get-block-index-entry cs unknown)))
       ;; The shipped entry point rewinds and rebuilds, as above.
       (bl::%catch-up-coinstatsindex node)
       (is (= tip (bl.store:coinstatsindex-height csi)))
       (dolist (entry correct)
         (is (equalp (cdr entry) (%csi-raw-record csi (car entry)))
             "record at height ~D was not rebuilt" (car entry)))
       ;; Re-diverge to observe the rewind itself: it lands on the fork point,
       ;; and gets there by recomputation — one per height from the tip down to
       ;; the fork, the path the header-index walk cannot cover here.
       (%csi-divergent-state csi fork tip unknown)
       (%csi-counting-calls
           (verifications 'bl.store:coinstatsindex-record-matches-block-p)
         (is (eql fork (bl::%rewind-coinstatsindex node)))
         (is (= 3 verifications)
             "expected one recomputation per height from the tip down to the fork, got ~D"
             verifications))
       (bl.store:close-coinstatsindex csi)))))

(test coinstatsindex-consistent-index-is-not-rebuilt
  "Control: a consistent index must NOT rewind and must NOT re-index a single
block — a fix that always rebuilt would be a severe performance regression
(hours on a real chain). The same counter proves it can see work happening,
by re-running against a divergent index."
  (%with-regtest
   (multiple-value-bind (node csi cs tip)
       (%csi-fixture (format nil "csictl~D" (get-internal-real-time)) 5)
     (%csi-counting-calls (adds 'bl.store:coinstatsindex-add-block)
       ;; Consistent: no rewind, no work at all.
       (is (null (bl::%rewind-coinstatsindex node)))
       (bl::%catch-up-coinstatsindex node)
       (is (= 0 adds) "a consistent index re-indexed ~D block(s)" adds)
       (is (= tip (bl.store:coinstatsindex-height csi)))
       ;; Positive control: the counter does move when there IS work.
       (let ((fork (- tip 2)))
         (%csi-divergent-state csi fork tip (%csi-fake-branch cs fork tip 100))
         (bl::%catch-up-coinstatsindex node)
         (is (= 2 adds) "divergent index re-indexed ~D block(s)" adds)))
     (bl.store:close-coinstatsindex csi))))

(test coinstatsindex-ahead-of-tip-rewinds-to-tip
  "The ordinary unclean-shutdown shape: index writes are durable immediately,
the chainstate tip only at a flush, so after a kill the marker sits above the
restored tip on the SAME chain. That must cost one verification and a marker
move to the tip — not a rebuild from genesis."
  (%with-regtest
   (multiple-value-bind (node csi cs tip)
       (%csi-fixture (format nil "csiahd~D" (get-internal-real-time)) 5)
     (let ((tip-record (%csi-raw-record csi tip)))
       ;; Two blocks' worth of records above the restored tip, marker on a
       ;; block the (stale) header index never saw.
       (%csi-put-raw-record csi (+ tip 1) tip-record)
       (%csi-put-raw-record csi (+ tip 2) tip-record)
       (bl.store:coinstatsindex-set-best
        csi (+ tip 2) (make-array 32 :element-type '(unsigned-byte 8)
                                     :initial-element #xC3))
       (%csi-counting-calls (adds 'bl.store:coinstatsindex-add-block)
         (is (eql tip (bl::%rewind-coinstatsindex node)))
         (bl::%catch-up-coinstatsindex node)
         (is (= 0 adds) "an index merely ahead of the tip re-indexed ~D block(s)" adds))
       ;; Marker back on the active tip, its record untouched.
       (multiple-value-bind (h hash) (bl.store:coinstatsindex-best csi)
         (is (= tip h))
         (is (equalp (bl.store:block-index-entry-hash
                      (bl.store:get-block-at-height cs tip))
                     hash)))
       (is (equalp tip-record (%csi-raw-record csi tip)))
       (bl.store:close-coinstatsindex csi)))))

(test coinstatsindex-rpc-refuses-stale-branch-hash
  "gettxoutsetinfo resolves a block hash to a height through the header index,
which also resolves STALE-BRANCH hashes — and the index holds active-chain
statistics only. Asking by a stale-branch hash must error rather than serve the
active chain's numbers under that hash. Control: the active-chain hash at the
same height still works."
  (%with-regtest
   (multiple-value-bind (node csi cs tip)
       (%csi-fixture (format nil "csirpc2~D" (get-internal-real-time)) 4)
     (let* ((stale (%csi-fake-branch cs (1- tip) tip 150))
            (active (bl.store:block-index-entry-hash
                     (bl.store:get-block-at-height cs tip))))
       (signals bl.rpc::rpc-error
         (bl.rpc::rpc-gettxoutsetinfo
          node (list "muhash" (bl.rpc::hash-to-hex stale))))
       (let ((res (bl.rpc::rpc-gettxoutsetinfo
                   node (list "muhash" (bl.rpc::hash-to-hex active)))))
         (is (= tip (cdr (assoc "height" res :test #'string=)))))
       ;; A height above the best marker is not vouched for either.
       (bl.store:coinstatsindex-set-best
        csi (1- tip) (bl.store:block-index-entry-hash
                      (bl.store:get-block-at-height cs (1- tip))))
       (signals bl.rpc::rpc-error
         (bl.rpc::rpc-gettxoutsetinfo node (list "muhash" tip)))
       (bl.store:close-coinstatsindex csi)))))
