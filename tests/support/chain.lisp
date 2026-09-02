(in-package #:bitcoin-lisp.test-support)

;;;; Synthetic blocks and chains, and the disk-backed node they connect into

(defun make-test-chain-hashes (prefix count)
  "Generate COUNT unique 32-byte hashes with PREFIX byte for chain identification."
  (loop for i from 1 to count
        collect (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
                  (setf (aref h 0) prefix)
                  (setf (aref h 1) i)
                  h)))

(defun make-reorg-test-block (prev-hash block-hash height
                              &key (value 5000000000)
                                   (timestamp (+ 1231006505 (* height 600))))
  "Create a minimal test block for reorg tests.

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
                                      :script-sig script-sig))
                       :outputs (vector (bl.ser:make-tx-out
                                       :value value
                                       :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                                  :initial-element #x76)))
                       :lock-time 0))
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

(defun regtest-node-fixture (suffix)
  ;; The directory is keyed by SUFFIX on purpose: a test that stops a node
  ;; and builds a second one with the same suffix reopens the same on-disk
  ;; state. Callers pick a suffix unique to the test.
  "(values node) — a regtest node at genesis with disk-backed chain-state /
block-store / utxo-set, ready for activate-block. Call inside (with-network (:regtest) ...)."
  (let* ((base (ensure-directories-exist
                (merge-pathnames (format nil "test-regtest-mine-~A/" suffix)
                                 (uiop:temporary-directory))))
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
