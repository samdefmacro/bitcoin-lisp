(in-package #:bitcoin-lisp.test-support)

;;;; Synthetic blocks and chains, and the disk-backed node they connect into

(defun make-test-chain-hashes (prefix count)
  "Generate COUNT unique 32-byte hashes with PREFIX byte for chain identification."
  (loop for i from 1 to count
        collect (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
                  (setf (aref h 0) prefix)
                  (setf (aref h 1) i)
                  h)))

(defun make-versionbits-chain (n &key (network :regtest) (signal-bit nil) (base-time 1000000))
  "(values chain-state last-entry) for a synthetic chain of N blocks.

Every header carries the versionbits top bits, and SIGNAL-BIT additionally sets
that deployment bit — which is what CONDITION counts."
  (declare (ignore network))
  (let ((cs (bl.store:make-chain-state))
        (prev nil))
    (dotimes (i n)
      (let* ((version (logior #x20000000 (if signal-bit (ash 1 signal-bit) 0)))
             (header (bl.ser:make-block-header
                      :version version
                      :prev-block (make-array 32 :element-type '(unsigned-byte 8)
                                                 :initial-element 0)
                      :merkle-root (make-array 32 :element-type '(unsigned-byte 8)
                                                  :initial-element 0)
                      :timestamp (+ base-time (* i 600))
                      :bits #x207fffff :nonce 0))
             (hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
        (setf (aref hash 0) (logand i #xFF)
              (aref hash 1) (logand (ash i -8) #xFF))
        (let ((e (bl.store:make-block-index-entry
                  :hash hash :height i :prev-entry prev :header header
                  :status :valid)))
          (bl.store:add-block-index-entry cs e)
          (setf prev e))))
    (values cs prev)))

(defun make-reorg-test-block (prev-hash block-hash height
                              &key (value 5000000000)
                                   (timestamp (+ 1231006505 (* height 600)))
                                   (lock-time 0)
                                   (sequence #xFFFFFFFF))
  "Create a minimal test block for reorg tests.

LOCK-TIME and SEQUENCE default to the always-final coinbase every caller
wants; pass a future LOCK-TIME with a non-final SEQUENCE to build a block
Core's ContextualCheckBlock rejects bad-txns-nonfinal.

The coinbase's script-sig is derived from BLOCK-HASH so each block's
coinbase tx SERIALIZES uniquely. Without that, every coinbase produced
by this helper would serialize to identical bytes and hash to the same
real txid after a block round-trips through the store (which
serializes then deserializes, dropping any cached tx hash). The
collapsed-txid bug let reorg tests pass by coincidence: A's outputs
were never disconnected (stored under cached-hash keys, looked up
under real-hash keys) and B's collapsed to one entry, so the final
count happened to equal the number-of-B-blocks the test expected.

We still set cached-hash on the coinbase as a small optimization for
tests that compare txids before any disk round-trip — it must match
the real hash256(serialize-tx) which it now does, since the unique
script-sig makes the serialization deterministic per block."
  (let* ((script-sig (let ((s (make-array 4 :element-type '(unsigned-byte 8))))
                       (replace s block-hash :start2 0 :end2 4)
                       s))
         (coinbase-tx (bl.ser:make-transaction
                       :version 1
                       :inputs (vector (bl.ser:make-tx-in
                                      :previous-output (bl.ser:make-outpoint
                                                        :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                          :initial-element 0)
                                                        :index #xFFFFFFFF)
                                      :script-sig script-sig
                                      :sequence sequence))
                       :outputs (vector (bl.ser:make-tx-out
                                       :value value
                                       :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                                  :initial-element #x76)))
                       :lock-time lock-time))
         (merkle-root (bl.val:compute-merkle-root
                       (list (bl.ser:transaction-hash coinbase-tx))))
         (header (bl.ser:make-block-header
                  :version 1
                  :prev-block prev-hash
                  :merkle-root merkle-root
                  :timestamp timestamp
                  :bits #x1d00ffff
                  :nonce 0
                  :cached-hash block-hash)))
    (bl.ser:make-bitcoin-block
     :header header
     :transactions (list coinbase-tx))))

(defun %sibling-block-hash (block-hash)
  "A hash differing from BLOCK-HASH in a byte MAKE-REORG-TEST-BLOCK reads into
the coinbase script-sig, so the sibling's coinbase serializes -- and therefore
hashes -- differently. Flipping a byte outside those four would leave the two
coinbases identical and every forged body below would silently be honest."
  (let ((h (copy-seq block-hash)))
    (setf (aref h 2) (logxor (aref h 2) #xFF))
    h))

(defun make-forged-body-block (prev-hash block-hash height)
  "(values FORGED HONEST): a forged BODY under an HONEST header. FORGED carries
the header of the block MAKE-REORG-TEST-BLOCK would build at HEIGHT over an
unrelated block's transaction list, so the header's merkle root commits to a
different tx set -- Core CheckMerkleRoot's bad-txnmrklroot, classed
BLOCK_MUTATED because the header itself is untouched. HONEST is the block that
header really commits to, the positive control for any assertion about FORGED."
  (let ((honest (make-reorg-test-block prev-hash block-hash height))
        (other (make-reorg-test-block prev-hash
                                      (%sibling-block-hash block-hash)
                                      height)))
    (values (bl.ser:make-bitcoin-block
             :header (bl.ser:bitcoin-block-header honest)
             :transactions (bl.ser:bitcoin-block-transactions other))
            honest)))

(defun make-two-coinbase-block (prev-hash block-hash height)
  "A block carrying TWO coinbase transactions, with a merkle root that commits
to both. Core CheckBlock's bad-cb-multiple: a BLOCK_CONSENSUS verdict the block
hash authenticates, so unlike a forged body it is safe to mark permanently
invalid."
  (let* ((a (make-reorg-test-block prev-hash block-hash height))
         (b (make-reorg-test-block prev-hash
                                   (%sibling-block-hash block-hash)
                                   height))
         (txs (list (first (bl.ser:bitcoin-block-transactions a))
                    (first (bl.ser:bitcoin-block-transactions b))))
         (header (bl.ser:bitcoin-block-header a)))
    (bl.ser:make-bitcoin-block
     :header (bl.ser:make-block-header
              :version (bl.ser:block-header-version header)
              :prev-block (bl.ser:block-header-prev-block header)
              :merkle-root (bl.val:compute-merkle-root
                            (mapcar #'bl.ser:transaction-hash txs))
              :timestamp (bl.ser:block-header-timestamp header)
              :bits (bl.ser:block-header-bits header)
              :nonce (bl.ser:block-header-nonce header)
              :cached-hash block-hash)
     :transactions txs)))

(defun deliver-block (block chain-state utxo-set block-store
                      &key requested peer)
  "Hand BLOCK to the IBD receive path the way DISPATCH-IBD-MESSAGE does when a
`block' message arrives. REQUESTED says we had asked for this block, which
lifts the out-of-order anti-DoS gate; PEER is the peer that sent the body, and
is punished when the body fails Core's AcceptBlock gate. Call inside
WITH-IBD-CONTEXT. Returns what PROCESS-RECEIVED-BLOCK returns: T only when the
block became the new active tip."
  (bl.net::process-received-block block chain-state utxo-set block-store
                                  :requested requested :peer peer))

(defun regtest-node-base-path (suffix)
  "Where REGTEST-NODE-FIXTURE with SUFFIX keeps its chain state and block
store. Keyed by SUFFIX on purpose: a test that stops a node and builds a
second one with the same suffix reopens the same on-disk state."
  (ensure-directories-exist
   (merge-pathnames (format nil "test-regtest-mine-~A/" suffix)
                    (uiop:temporary-directory))))

(defun regtest-node-fixture (suffix)
  ;; The directory is keyed by SUFFIX on purpose: a test that stops a node
  ;; and builds a second one with the same suffix reopens the same on-disk
  ;; state. Callers pick a suffix unique to the test.
  "(values node) — a regtest node at genesis with disk-backed chain-state /
block-store / utxo-set, ready for activate-block. Call inside (with-network (:regtest) ...)."
  (let* ((base (regtest-node-base-path suffix))
         (cs (bl.store:init-chain-state base :network :regtest))
         (store (bl.store:init-block-store base))
         (ghash (bl.store:best-block-hash cs))
         (ghdr (bl::make-genesis-header :regtest))
         (node (bl:make-node :network :regtest)))
    (clrhash bl.val::*block-undo-data*)
    (bl.store:add-block-index-entry
     cs (bl.store:make-block-index-entry
         :hash ghash :height 0 :chain-work 1 :status :valid :header ghdr))
    (setf (bl:node-chain-state node) cs
          (bl:node-utxo-set node) (bl.store:make-utxo-set)
          (bl:node-block-store node) store
          (bl:node-mempool node) (bl.mp:make-mempool))
    node))

(defun generate-regtest-blocks (node n)
  "Mine N regtest blocks to the anyone-can-spend descriptor raw(51) through the
shipped generatetodescriptor handler, returning its list of block hashes.

The same three-token call had been copied into every suite that needs a real
mined chain (reindex, coinstatsindex, blockfilter); one helper is what keeps
the handler's argument shape in one place."
  (bl.rpc::rpc-generatetodescriptor node (list n "raw(51)")))

(defun coins-db-node-fixture (tag)
  "(values node coins-db-path chain-base-path) — a regtest node whose UTXO set
is a LevelDB-backed coins-view-cache (matching the live node), with undo
storage initialized so mining can connect blocks. The fixture the reindex and
VerifyDB suites share: both need the coins DATABASE, not the in-memory
utxo-set that REGTEST-NODE-FIXTURE gives on its own. The third value is where
REGTEST-NODE-FIXTURE put the block store, for a test that has to reach the
blk files themselves."
  (let* ((node (regtest-node-fixture tag))
         (base (merge-pathnames (format nil "test-reindex-~A/" tag)
                                (uiop:temporary-directory)))
         (cspath (namestring (merge-pathnames "chainstate/" base)))
         (undopath (merge-pathnames "undo/" base)))
    (ensure-directories-exist cspath)
    (ensure-directories-exist undopath)
    (setf (bl:node-utxo-set node)
          (bl.store:make-coins-view-cache
           (bl.store:open-coins-view-db cspath)))
    (bl.val:initialize-undo-storage undopath)
    (values node cspath (regtest-node-base-path tag))))

(defun activate-block-base-path (suffix)
  "The directory an activate-block fixture with SUFFIX lives in -- keyed by
SUFFIX so a test can reopen the same on-disk state with a second fixture."
  (ensure-directories-exist
   (merge-pathnames (format nil "test-activate-block-~A/" suffix)
                    (uiop:temporary-directory))))

(defun make-activate-block-fixture (suffix &optional view)
  "Returns (values chain-state utxo-set block-store genesis-hash). The
genesis index entry has a dummy header so validate-block's MTP walk
doesn't trip on a NIL header. VIEW overrides the default in-memory
utxo-set (pass a coins-view-cache to exercise the LevelDB surface)."
  (let* ((base-path (activate-block-base-path suffix))
         (chain-state (bl.store:init-chain-state base-path))
         (utxo-set (or view (bl.store:make-utxo-set)))
         (block-store (bl.store:init-block-store base-path))
         (genesis-hash (bl.store:best-block-hash chain-state))
         (genesis-header
           (bl.ser:make-block-header
            :version 1
            :prev-block (make-array 32 :element-type '(unsigned-byte 8)
                                       :initial-element 0)
            :merkle-root (make-array 32 :element-type '(unsigned-byte 8)
                                        :initial-element 0)
            :timestamp 1231006505 :bits #x1d00ffff :nonce 0
            :cached-hash genesis-hash)))
    (clrhash bl.val::*block-undo-data*)
    (bl.store:add-block-index-entry
     chain-state
     (bl.store:make-block-index-entry
      :hash genesis-hash :height 0 :chain-work 1 :status :valid
      :header genesis-header))
    (values chain-state utxo-set block-store genesis-hash)))

(defun build-and-connect (chain-state block-store utxo-set genesis-hash hashes)
  "Build a chain of coinbase-only blocks from GENESIS-HASH using HASHES,
connecting each via connect-block. Returns the list of (block . index-entry)
pairs in connect order."
  (let ((prev-hash genesis-hash)
        (results '()))
    (loop for h from 1
          for block-hash in hashes
          do (let ((block (make-reorg-test-block prev-hash block-hash h)))
               (bl.val:connect-block
                block chain-state block-store utxo-set)
               (push (cons block (bl.store:get-block-index-entry
                                  chain-state block-hash))
                     results)
               (setf prev-hash block-hash)))
    (nreverse results)))
