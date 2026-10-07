(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/utxo_snapshot.cpp at the pin, its utxo_snapshot_invalid
;;;; half: a snapshot file whose metadata and coins are the fuzzer's through
;;;; ActivateSnapshot, which must refuse it and leave nothing behind. Ours is
;;;; the loadtxoutset RPC on the process_message fixture node, whose header
;;;; chain is extended to regtest's height-110 assumeutxo block (its hash is
;;;; Core's, kernel/chainparams.cpp) so a snapshot naming it passes every
;;;; precondition and streams its coins through the population checks --
;;;; the per-coin height, vout and MoneyRange checks, the coins-count and EOF
;;;; checks, and the hash_serialized_3 comparison, which a fuzzed coin set
;;;; does not pass.
;;;;
;;;; In this half a load that SUCCEEDS is itself the failure. The valid half,
;;;; utxo_snapshot, follows at the end of the file over Core's own 200-block
;;;; test chain.

(def-suite :fuzz-utxo-snapshot-tests :in :bitcoin-lisp-tests
  :description "Core fuzz utxo_snapshot.cpp (both halves) over loadtxoutset")

(in-suite :fuzz-utxo-snapshot-tests)

(defun %regtest-assumeutxo-base ()
  "(height . hash) of regtest's first assumeutxo entry, the hash as the
snapshot metadata carries it."
  (let ((au (first (bl:network-assumeutxo-data :regtest))))
    (cons (bl:assumeutxo-data-height au) (bl:assumeutxo-data-blockhash au))))

(defun %extend-headers-to (node height hash)
  "Header-only entries on NODE's tip up to HEIGHT, the last one indexed under
HASH: a best header chain whose block at HEIGHT is the assumeutxo base."
  (let* ((cs (bl:node-chain-state node))
         (prev (bl.store:get-block-index-entry cs (bl.store:best-block-hash cs))))
    (loop for h from (1+ (bl.store:block-index-entry-height prev)) to height
          do (let* ((header (bl.ser:make-block-header
                             :version #x20000000
                             :prev-block (bl.store:block-index-entry-hash prev)
                             :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3)
                             :timestamp (+ 1610000000 h) :bits #x207fffff :nonce h))
                    (entry-hash (if (= h height) hash (bl.ser:block-header-hash header)))
                    (entry (bl.store:make-block-index-entry
                            :hash entry-hash :height h :header header :prev-entry prev
                            :status :header-valid
                            :chain-work (+ 2 (bl.store:block-index-entry-chain-work prev)))))
               (bl.store:add-block-index-entry cs entry)
               (setf prev entry)))))

(defun %fuzz-snapshot-bytes (fdp base-hash)
  "A snapshot file: metadata (Core's layout with a fuzzed base -- usually the
assumeutxo block -- and coins count, or raw bytes) and a coin stream (txid
groups of compressed coins, heights and vouts sometimes out of range, or raw
bytes)."
  (flexi-streams:with-output-to-sequence (s :element-type '(unsigned-byte 8))
    (if (zerop (consume-integral-in-range fdp 0 7))
        (write-sequence (consume-random-length-byte-vector fdp 60) s)
        (progn
          (write-sequence #(#x75 #x74 #x78 #x6f #xff) s)
          (bl.ser:write-uint16-le s (pick-value-in-array fdp (list 2 2 2 (consume-integral fdp :u16))))
          (write-sequence (if (plusp (consume-integral-in-range fdp 0 7))
                              (bl.chain:network-magic :regtest)
                              (bl.chain:network-magic :mainnet))
                          s)
          (write-sequence (if (plusp (consume-integral-in-range fdp 0 7)) base-hash (consume-uint256 fdp)) s)
          (bl.ser:write-uint64-le s (consume-integral-in-range fdp 0 12))))
    (if (zerop (consume-integral-in-range fdp 0 7))
        (write-sequence (consume-random-length-byte-vector fdp 200) s)
        (loop repeat (consume-integral-in-range fdp 0 6)
              do (write-sequence (consume-uint256 fdp) s)
                 (let ((n (consume-integral-in-range fdp 0 3)))
                   (bl.ser:write-compact-size s n)
                   (dotimes (i n)
                     (bl.ser:write-compact-size s (pick-value-in-array fdp (list i 0 (consume-integral fdp :u32))))
                     (let ((bb (bl.ser:make-byte-buf)))
                       (bl.ser:bb-write-core-varint
                        bb (+ (* 2 (pick-value-in-array fdp (list (consume-integral-in-range fdp 0 110)
                                                                  (consume-integral-in-range fdp 111 #x7fffffff))))
                              (if (consume-bool fdp) 1 0)))
                       (write-sequence (bl.ser:bb-finish bb) s))
                     (write-sequence (%compressed-tx-out-bytes (consume-money fdp) (consume-script fdp)) s)))))
    (when (consume-bool fdp)
      (write-sequence (consume-random-length-byte-vector fdp 20) s))))

(define-fuzz-target utxo-snapshot-invalid
    (buffer :core "utxo_snapshot.cpp:103-231 (utxo_snapshot_invalid)" :iterations 30 :max-len 1500)
  "A snapshot of any metadata and coins is refused by loadtxoutset with an RPC
error -- never another condition -- leaves no snapshot chainstate and no
chainstate_snapshot directory behind, and is refused again on a second try."
  (let ((fdp (make-fuzzed-data-provider buffer)))
    (with-fuzz-p2p-node (p2p)
      (with-temp-directory (dir "fuzz-utxo-snapshot")
        (let* ((node (fp-node p2p))
               (base (%regtest-assumeutxo-base))
               (path (merge-pathnames "snapshot.dat" dir)))
          (setf (bl:node-data-directory node) dir)
          (%extend-headers-to node (car base) (cdr base))
          (with-open-file (out path :direction :output :element-type '(unsigned-byte 8))
            (write-sequence (%fuzz-snapshot-bytes fdp (cdr base)) out))
          (flet ((load-once ()
                   (handler-case
                       (progn (bl.rpc:dispatch-rpc-method node "loadtxoutset" (list (namestring path)))
                              :loaded)
                     (bl.rpc:rpc-error () :refused))))
            (fuzz-assert (eq (fuzz-sabotage (load-once)) :refused)
                         "a fuzzed snapshot was loaded")
            (fuzz-assert (and (= 1 (length (bl:node-chainstates node)))
                              (null (bl.store:chain-state-from-snapshot-blockhash
                                     (bl:node-chain-state node))))
                         "a refused snapshot left a snapshot chainstate")
            (fuzz-assert (null (directory (merge-pathnames "**/chainstate_snapshot/" dir)))
                         "a refused snapshot left its chainstate directory")
            (fuzz-assert (eq (load-once) :refused) "the second load was not refused")))))))

;;; --- utxo_snapshot (valid): Core's 200-block test chain ----------------------------
;;;
;;; Core's valid half (utxo_snapshot.cpp:105-216) writes the coins of its own
;;; 200-block regtest chain -- CreateBlockChain (test/util/mining.cpp:37-70),
;;; whose UTXO commitment is regtest's height-200 assumeutxo entry
;;; (kernel/chainparams.cpp) -- as a snapshot, with the metadata, coins and
;;; header chain each either right or the fuzzer's, and asserts that a snapshot
;;; which activates is the whole chain's coins on the base. The chain is a
;;; pure function of regtest's parameters, so ours builds the same blocks,
;;; byte for byte: CORE-TEST-BLOCK-CHAIN. Core's init first connects it and
;;; checks the commitment (sanity_check_snapshot, :48-67); that is the test
;;; UTXO-SNAPSHOT-CHAIN-COMMITS-TO-REGTEST-S-ASSUMEUTXO-ENTRY below, an oracle
;;; for our block connection and hash_serialized_3 together.
;;;
;;; Each buffer gets a fresh regtest node at genesis (Core resets its
;;; chainman whenever a run dirtied it). Where Core asserts the coins cache
;;; holds the 200 coins, ours asserts the snapshot chainstate does: our
;;; population flushes the cache into the chainstate's database.

(defvar *core-test-block-chains* '()
  "Memo of CORE-TEST-BLOCK-CHAIN: (height . blocks). The chain is a pure
function of its height and regtest's parameters.")

(defun core-test-block-chain (total-height)
  "Core CreateBlockChain(TOTAL-HEIGHT, regtest) (test/util/mining.cpp:37-70):
blocks 1..TOTAL-HEIGHT on regtest's genesis, each a version-4 block holding one
coinbase -- nLockTime the block's height less one with a non-final sequence,
scriptSig `CScript() << height << OP_0', the subsidy to P2WSH(OP_TRUE) -- one
second after its parent, its nonce counted up to regtest's target."
  (or (cdr (assoc total-height *core-test-block-chains*))
      (with-network (:regtest)
        (let ((time (bl.ser:block-header-timestamp
                     (bl.ser:bitcoin-block-header (bl.store:make-genesis-block :regtest))))
              (prev (bl.store:network-genesis-hash :regtest))
              (blocks '()))
          (dotimes (height total-height)
            (let* ((coinbase
                     (bl.ser:make-transaction
                      :version 2 :lock-time height
                      :inputs (vector (bl.ser:make-tx-in
                                       :previous-output (bl.ser:make-outpoint
                                                         :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                              :initial-element 0)
                                                         :index #xffffffff)
                                       :script-sig (concatenate '(simple-array (unsigned-byte 8) (*))
                                                                (bl.val:encode-bip34-height (1+ height))
                                                                #(0))
                                       :sequence #xfffffffe))
                      :outputs (vector (bl.ser:make-tx-out
                                        :value (bl.val:calculate-block-subsidy (1+ height))
                                        :script-pubkey +p2wsh-op-true+))))
                   (header (grind-header-pow
                            (bl.ser:make-block-header
                             :version 4 :prev-block prev
                             :merkle-root (bl.val:compute-merkle-root (list (bl.ser:transaction-hash coinbase)))
                             :timestamp (incf time) :bits bl.store:+regtest-pow-limit-bits+ :nonce 0))))
              (push (bl.ser:make-bitcoin-block :header header :transactions (list coinbase)) blocks)
              (setf prev (bl.ser:block-header-hash header))))
          (let ((chain (nreverse blocks)))
            (push (cons total-height chain) *core-test-block-chains*)
            chain)))))

(defun %submit-core-chain (node blocks)
  "Connect BLOCKS to NODE through submitblock, as Core's ProcessBlock."
  (dolist (block blocks)
    (bl.rpc:dispatch-rpc-method node "submitblock"
                                (list (bl.crypto:bytes-to-hex (bl.ser:serialize-witness-block block))))))

(test utxo-snapshot-chain-commits-to-regtest-s-assumeutxo-entry
  "Core sanity_check_snapshot (utxo_snapshot.cpp:48-67): Core's 200-block
test chain, connected, has the UTXO set regtest's height-200 assumeutxo entry
commits to -- height 200, 200 transactions with unspent outputs (201 in the
chain with genesis), the entry's block hash and hash_serialized_3."
  (let ((suffix (format nil "core-chain-~D" (random 1000000000))))
    (with-network (:regtest)
      (unwind-protect
           (let* ((node (regtest-node-fixture suffix))
                  (blocks (core-test-block-chain 200))
                  (au (find 200 (bl:network-assumeutxo-data :regtest) :key #'bl:assumeutxo-data-height)))
             (%submit-core-chain node blocks)
             (let ((info (yason:parse (rpc-result-json
                                       (bl.rpc:dispatch-rpc-method node "gettxoutsetinfo"
                                                                   (list "hash_serialized_3"))))))
               (is (= 200 (gethash "height" info)) "the chain connected to ~S" (gethash "height" info))
               (is (= (bl:assumeutxo-data-chain-tx-count au) (1+ (gethash "transactions" info))))
               (is (equalp (bl:assumeutxo-data-blockhash au)
                           (bl.crypto:reverse-bytes (bl.crypto:hex-to-bytes (gethash "bestblock" info)))))
               (is (equalp (bl:assumeutxo-data-hash-serialized au)
                           (bl.crypto:reverse-bytes (bl.crypto:hex-to-bytes (gethash "hash_serialized_3" info))))
                   "hash_serialized_3 ~A" (gethash "hash_serialized_3" info))))
        (uiop:delete-directory-tree (regtest-node-base-path suffix)
                                    :validate t :if-does-not-exist :ignore)))))

(defun %core-snapshot-bytes (fdp blocks magic)
  "The snapshot utxo_snapshot.cpp:121-158 writes (the valid target): metadata
-- the fuzzer's bytes, or Core's SnapshotMetadata naming the block at a fuzzed
height of BLOCKS with a fuzzed coins count -- then coins -- the fuzzer's
bytes, or every block's coinbase output as Core's per-txid coin groups.
Returns the bytes, (height . coins-count) when the metadata is Core's, and
whether the coins are."
  (let ((shape nil) (core-coins nil))
    (values
     (flexi-streams:with-output-to-sequence (s :element-type '(unsigned-byte 8))
       (if (consume-bool fdp)
           (write-sequence (consume-random-length-byte-vector fdp) s)
           (let ((height (consume-integral-in-range fdp 1 200 32))
                 (count (consume-integral-in-range fdp 1 300)))
             (setf shape (cons height count))
             (write-sequence #(#x75 #x74 #x78 #x6f #xff) s)
             (bl.ser:write-uint16-le s 2)
             (write-sequence magic s)
             (write-sequence (bl.ser:block-header-hash (bl.ser:bitcoin-block-header (nth (1- height) blocks))) s)
             (bl.ser:write-uint64-le s count)))
       (if (consume-bool fdp)
           (write-sequence (consume-random-length-byte-vector fdp) s)
           (loop initially (setf core-coins t)
                 for block in blocks
                 for height from 1
                 for coinbase = (first (bl.ser:bitcoin-block-transactions block))
                 for out = (aref (bl.ser:transaction-outputs coinbase) 0)
                 do (write-sequence (bl.ser:transaction-hash coinbase) s)
                    (bl.ser:write-compact-size s 1)
                    (bl.ser:write-compact-size s 0)
                    (let ((bb (bl.ser:make-byte-buf)))
                      (bl.ser:bb-write-core-varint bb (1+ (* 2 height)))
                      (write-sequence (bl.ser:bb-finish bb) s))
                    (write-sequence (%compressed-tx-out-bytes (bl.ser:tx-out-value out)
                                                              (bl.ser:tx-out-script-pubkey out))
                                    s))))
     shape
     core-coins)))

(defun %utxo-snapshot-corpus (fdp)
  "A buffer that steers the valid target: usually Core's metadata on the
height-200 block with 200 coins, Core's coins and the header chain loaded --
a snapshot that activates -- and otherwise one choice off (another height or
count, the fuzzer's bytes, no headers)."
  (let* ((tail (make-fdp-tail))
         (raw-metadata (zerop (consume-integral-in-range fdp 0 7)))
         (raw-coins (zerop (consume-integral-in-range fdp 0 7)))
         (front (concatenate '(simple-array (unsigned-byte 8) (*))
                             (if raw-metadata (fdp-random-length-bytes (consume-bytes fdp 40)) #())
                             (if raw-coins (fdp-random-length-bytes (consume-bytes fdp 40)) #()))))
    (fdp-tail-integral tail (consume-integral-in-range fdp 1296688602 1700000000) 1296688602 4133980799)
    (fdp-tail-bool tail raw-metadata)
    (unless raw-metadata
      (fdp-tail-integral tail (if (zerop (consume-integral-in-range fdp 0 7))
                                  (consume-integral-in-range fdp 1 200)
                                  200)
                         1 200 32)
      (fdp-tail-integral tail (if (zerop (consume-integral-in-range fdp 0 7))
                                  (consume-integral-in-range fdp 1 300)
                                  200)
                         1 300))
    (fdp-tail-bool tail raw-coins)
    (fdp-tail-bool tail (plusp (consume-integral-in-range fdp 0 5)))
    (concatenate '(simple-array (unsigned-byte 8) (*)) front (fdp-tail-bytes tail))))

(defun %check-activated-snapshot (node blocks base-height)
  "utxo_snapshot.cpp:186-203: the active chainstate is the snapshot's, holds
every block's coinbase coin and nothing else, and no block below the tip has
a transaction count -- the base's chain count is the commitment's."
  (let* ((cs (bl:node-chain-state node))
         (view (bl.store:chain-state-coins-view cs))
         (base-hash (bl.ser:block-header-hash (bl.ser:bitcoin-block-header (nth (1- base-height) blocks))))
         (au (bl:assumeutxo-data-for-blockhash :regtest base-hash)))
    (fuzz-assert (equalp (fuzz-sabotage (bl.store:chain-state-from-snapshot-blockhash cs)) base-hash)
                 "the active chainstate is not the snapshot's")
    (dolist (block blocks)
      (let ((entry (bl.store:get-block-index-entry cs (bl.ser:block-header-hash (bl.ser:bitcoin-block-header block)))))
        (fuzz-assert (bl.store:coin-view-has-p view (bl.ser:transaction-hash
                                                     (first (bl.ser:bitcoin-block-transactions block)))
                                               0)
                     "a coinbase coin is missing from the snapshot chainstate")
        (fuzz-assert (and entry (member (bl.store:block-index-entry-tx-count entry) '(0 nil)))
                     "a block of the snapshot chain has a transaction count")))
    (fuzz-assert (and au (= (bl:assumeutxo-data-height au) base-height)))
    (let ((info (yason:parse (rpc-result-json (bl.rpc:dispatch-rpc-method node "gettxoutsetinfo" nil)))))
      (fuzz-assert (= (gethash "txouts" info) (length blocks))
                   "the snapshot chainstate holds ~D coins for ~D blocks" (gethash "txouts" info) (length blocks)))))

(define-fuzz-target utxo-snapshot
    (buffer :core "utxo_snapshot.cpp:103-231 (utxo_snapshot, valid)" :corpus #'%utxo-snapshot-corpus
            :iterations 25 :max-len 200)
  "A snapshot of Core's 200-block chain whose metadata, coins and header chain
are each right or the fuzzer's activates exactly when all three are right and
name the height-200 commitment; an activated snapshot is the whole chain's
coins on its base; a refused one leaves nothing behind; a second load is
refused either way."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (blocks (core-test-block-chain 200))
         (suffix (format nil "fuzz-utxo-snapshot-~D" (random 1000000000))))
    (with-network (:regtest)
      (with-temp-directory (dir "fuzz-utxo-snapshot")
        (let ((node (regtest-node-fixture suffix)))
          (unwind-protect
             (let ((bl.ser:*mock-time* (consume-integral-in-range fdp 1296688602 4133980799))
                   (path (merge-pathnames "fuzzed_snapshot.dat" dir)))
               (setf (bl:node-data-directory node) dir)
               (multiple-value-bind (bytes shape core-coins)
                   (%core-snapshot-bytes fdp blocks (bl.chain:network-magic :regtest))
                 (with-open-file (out path :direction :output :element-type '(unsigned-byte 8))
                   (write-sequence bytes out))
                 (let ((headers (consume-bool fdp)))
                   (when headers
                     (dolist (block blocks)
                       (bl.rpc:dispatch-rpc-method
                        node "submitheader"
                        (list (bl.crypto:bytes-to-hex (bl.ser:serialize-block-header (bl.ser:bitcoin-block-header block)))))))
                   (flet ((activate ()
                            (handler-case
                                (progn (bl.rpc:dispatch-rpc-method node "loadtxoutset" (list (namestring path)))
                                       t)
                              (bl.rpc:rpc-error () nil))))
                     (let ((activated (activate))
                           (expected (and headers core-coins (equal shape '(200 . 200)))))
                       (fuzz-assert (eq (fuzz-sabotage activated) expected)
                                    "the snapshot ~:[was refused~;activated~] (metadata ~S, ~:[raw~;Core's~] coins, headers ~:[not ~;~]loaded)"
                                    activated shape core-coins headers)
                       (if activated
                           (%check-activated-snapshot node blocks (car shape))
                           (fuzz-assert (and (null (bl.store:chain-state-from-snapshot-blockhash
                                                    (bl:node-chain-state node)))
                                             (null (directory (merge-pathnames "**/chainstate_snapshot/" dir))))
                                        "a refused snapshot left a snapshot chainstate behind"))
                       ;; Snapshot should refuse to load a second time regardless of validity.
                       (fuzz-assert (not (activate)) "the second load was not refused"))))))
            (dolist (cs (bl:node-chainstates node))
              (when (bl.store:chain-state-from-snapshot-blockhash cs)
                (bl.store:close-chainstate-coins-view cs)))
            (uiop:delete-directory-tree (regtest-node-base-path suffix)
                                        :validate t :if-does-not-exist :ignore)))))))
