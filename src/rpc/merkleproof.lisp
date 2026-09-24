(in-package #:bitcoin-lisp.rpc)

;;; Transaction-inclusion proofs: gettxoutproof / verifytxoutproof.
;;;
;;; A proof is a serialized CMerkleBlock (Bitcoin Core merkleblock.cpp):
;;;   block header (80 bytes)
;;;   + CPartialMerkleTree { nTransactions:u32, vHash:[32]*, vBits:bytes }
;;; The partial tree carries just the hashes on the authentication path to
;;; the matched txids, plus a flag-bit stream describing the traversal, so a
;;; verifier can recompute the merkle root and confirm membership. This is
;;; the SPV proof structure; the algorithm here mirrors CPartialMerkleTree
;;; exactly (CalcHash / TraverseAndBuild / TraverseAndExtract).

;;; --- RPCs ---

(defconstant +max-outputs-per-block+ (floor 4000000 36)
  "Core MAX_OUTPUTS_PER_BLOCK (coins.cpp:384): MAX_BLOCK_WEIGHT over the
weight of the smallest serializable output, the bound AccessByTxid walks
when it looks for any unspent output of a txid.")

(defun %block-hash-of-unspent-output (node chain-state txids)
  "The hash of the block holding the first of TXIDS that still has an unspent
output, or NIL: Core's gettxoutproof without a blockhash (txoutproof.cpp:
71-80) walks each txid's outputs through AccessByTxid (coins.cpp:386-394) and
takes the active chain's block at the coin's height."
  (let ((view (rpc-get-utxo-set node)))
    (when view
      (dolist (txid txids)
        (loop for n from 0 below +max-outputs-per-block+
              for coin = (bl.store:get-utxo view txid n)
              when coin
                do (let ((entry (bl.store:get-block-at-height
                                 chain-state (bl.store:utxo-entry-height coin))))
                     (return-from %block-hash-of-unspent-output
                       (and entry (bl.store:block-index-entry-hash entry)))))))))

(define-rpc "gettxoutproof" (node ((txids :array) blockhash-hex))
  "Build a merkle proof that the given TXIDs are in a block (Bitcoin Core
gettxoutproof). PARAMS: (txids [blockhash]). On this pruned node the block
must be locatable: pass BLOCKHASH, or have txindex enabled. Returns the
hex-encoded CMerkleBlock.

The argument is Core's std::set<Txid> (txoutproof.cpp:46-56): an empty array
and a repeated txid are each refused by name before any lookup, and the set is
what the found-count below is compared against."
  (unless (and (listp txids) txids)
    (error 'rpc-error :code +rpc-invalid-parameter+
                      :message "Parameter 'txids' cannot be empty"))
  (let ((wanted '())
        (chain-state (rpc-get-chain-state node))
        (block-store (rpc-get-block-store node)))
    ;; setTxids.insert: a second copy of one txid is refused, naming it
    ;; (txoutproof.cpp:51-56, rpc_txoutproof.py:88).
    (dolist (h txids)
      (let ((hash (parse-hash-v h "txid")))
        (when (member hash wanted :test #'equalp)
          (error 'rpc-error :code +rpc-invalid-parameter+
                            :message (format nil "Invalid parameter, duplicated txid: ~A" h)))
        (push hash wanted)))
    (setf wanted (nreverse wanted))
    ;; Locate the block: explicit hash, else txindex on the first txid.
    (let* ((block-hash
             (cond
               (blockhash-hex (parse-hash-v blockhash-hex "blockhash"))
               ;; No blockhash: Core looks for an UNSPENT output of any of the
               ;; txids in the coins view and takes the block at its height
               ;; (txoutproof.cpp:71-80, AccessByTxid), then asks the txindex,
               ;; and only then says `Transaction not yet in block` (:88-91).
               ((%block-hash-of-unspent-output node chain-state wanted))
               ((let ((ti (rpc-get-tx-index node)))
                  (and ti (bl.store:tx-index-enabled ti)
                       (let ((loc (bl.store:txindex-lookup ti (first wanted))))
                         (and loc (bl.store:tx-location-block-hash loc))))))
               (t (error 'rpc-error :code +rpc-invalid-address-or-key+
                                    :message "Transaction not yet in block"))))
           ;; CheckBlockDataAvailability + ReadBlock (txoutproof.cpp:101-107).
           (block (block-body-checked chain-state block-store block-hash)))
      (let* ((txs (bl.ser:bitcoin-block-transactions block))
             (txids-vec (map 'vector #'bl.ser:transaction-hash txs))
             (match (make-array (length txids-vec) :initial-element nil)))
        ;; Core counts how many of the block's transactions are in setTxids
        ;; and rejects once, on the COUNT, naming the block it read rather
        ;; than the txid it missed: the block may be one it retrieved itself
        ;; from a coin or the txindex, not one the caller specified
        ;; (txoutproof.cpp:109-118, rpc_txoutproof.py:84).
        (let ((found 0))
          (dolist (w wanted)
            (let ((idx (position w txids-vec :test #'equalp)))
              (when idx
                (incf found)
                (setf (aref match idx) t))))
          (unless (= found (length wanted))
            (error 'rpc-error :code +rpc-invalid-address-or-key+
                              :message "Not all transactions found in specified or retrieved block")))
        (multiple-value-bind (bits hashes) (bl.net:build-partial-merkle-tree txids-vec match)
          (let ((header-bytes (bl.ser:serialize-block-header
                               (bl.ser:bitcoin-block-header block))))
            (bl.crypto:bytes-to-hex
             (bl.net:serialize-merkle-block header-bytes (length txids-vec) hashes bits))))))))

(define-rpc "verifytxoutproof" (node (proof-hex))
  "Verify a merkle proof from gettxoutproof and return the txids it proves,
provided the proof's block is on the active chain (Bitcoin Core
verifytxoutproof). PARAMS: (proof-hex). Returns the list of txid hex
strings, or an empty list if the block isn't in the active chain."
  (let ((bytes (parse-hex-v proof-hex "proof")))
    (multiple-value-bind (header-bytes ntx hashes bits) (bl.net:parse-merkle-block bytes)
      (multiple-value-bind (root matched) (bl.net:extract-partial-merkle-tree ntx bits hashes)
        (unless root
          (error 'rpc-error :code +rpc-invalid-parameter+ :message "Invalid merkle proof"))
        ;; The recomputed root must equal the header's, and the block must
        ;; be a known active-chain block (Core checks it's in mapBlockIndex
        ;; and on the active chain).
        (let* ((header-root (subseq header-bytes 36 68))
               (chain-state (rpc-get-chain-state node))
               (block-hash (bl.crypto:hash256 header-bytes))
               (entry (bl.store:get-block-index-entry chain-state block-hash)))
          (unless (equalp root header-root)
            (error 'rpc-error :code +rpc-invalid-parameter+
                              :message "Merkle root mismatch — proof does not match its header"))
          ;; Core throws here rather than returning an empty result
          ;; (rpc/txoutproof.cpp:160-163):
          ;;
          ;;   if (!pindex || !ActiveChain().Contains(pindex) || pindex->nTx == 0)
          ;;       throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found in chain");
          ;;
          ;; The comment previously here asserted "Core returns []", which is
          ;; simply not what Core does. A caller asking whether a txid is
          ;; committed to by a block cannot distinguish "no" from "I have no
          ;; idea what block that is" when both render as [].
          (unless (and entry
                       (bl.store:entry-on-active-chain-p chain-state entry)
                       (plusp (bl.store:block-index-entry-tx-count entry)))
            (error 'rpc-error :code +rpc-invalid-address-or-key+
                              :message "Block not found in chain"))
          ;; THE proof check (rpc/txoutproof.cpp:165-170, "Check if proof is
          ;; valid, only add results if so"): the count the proof CLAIMS must
          ;; equal the count the block actually has.
          ;;
          ;; Without this the RPC could be made to prove anything about a
          ;; real block. CPartialMerkleTree's shape is a pure function of the
          ;; claimed nTransactions, so understating it reinterprets INTERNAL
          ;; nodes of the real tree as leaves: for a 4-tx block with root
          ;; H(H(t0,t1), H(t2,t3)), a proof claiming 2 transactions with
          ;; hashes [H(t0||t1), H(t2||t3)] recomputes the header's real root
          ;; exactly, passes every structural bound we have, and made us
          ;; return an internal node as a "proven txid". Anyone running
          ;; deposit, bridge or attestation logic through this RPC got a
          ;; forged yes for the cost of one call -- no chain access, no
          ;; hashpower.
          (if (= ntx (bl.store:block-index-entry-tx-count entry))
              (json-array (mapcar #'hash-to-hex matched))
              (json-array nil)))))))
