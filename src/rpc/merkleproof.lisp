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

(defun %mp-hash-pair (a b)
  "double-SHA256 of A||B (32-byte halves) — internal merkle combiner."
  (let ((c (make-array 64 :element-type '(unsigned-byte 8))))
    (replace c a :start1 0)
    (replace c b :start1 32)
    (bitcoin-lisp.crypto:hash256 c)))

(defun %mp-tree-width (ntx height)
  "Number of nodes at HEIGHT in a merkle tree over NTX leaves."
  (ash (+ ntx (1- (ash 1 height))) (- height)))

(defun %mp-tree-height (ntx)
  "Height of the merkle tree over NTX leaves (0 => single node)."
  (let ((h 0))
    (loop while (> (%mp-tree-width ntx h) 1) do (incf h))
    h))

(defun %mp-calc-hash (txids ntx height pos)
  "Merkle node hash at (HEIGHT, POS) over the full TXIDS vector (Core
CalcHash): leaves at height 0, last node duplicated when a level is odd."
  (if (zerop height)
      (aref txids pos)
      (let ((left (%mp-calc-hash txids ntx (1- height) (* pos 2))))
        (%mp-hash-pair
         left
         (if (< (1+ (* pos 2)) (%mp-tree-width ntx (1- height)))
             (%mp-calc-hash txids ntx (1- height) (1+ (* pos 2)))
             left)))))

(defun build-partial-merkle-tree (txids match)
  "Build a partial merkle tree over TXIDS (vector of 32-byte hashes, block
order) selecting the leaves flagged in MATCH (parallel bit-vector).
Returns (values bits hashes) — BITS a list of booleans (the flag stream),
HASHES a list of 32-byte vectors. Mirrors Core's TraverseAndBuild."
  (let ((ntx (length txids))
        (bits '())
        (hashes '()))
    (labels ((traverse (height pos)
               (let ((parent-of-match nil))
                 (loop for p from (ash pos height) below (min (ash (1+ pos) height) ntx)
                       do (when (aref match p) (setf parent-of-match t)))
                 (push parent-of-match bits)
                 (if (or (zerop height) (not parent-of-match))
                     (push (%mp-calc-hash txids ntx height pos) hashes)
                     (progn
                       (traverse (1- height) (* pos 2))
                       (when (< (1+ (* pos 2)) (%mp-tree-width ntx (1- height)))
                         (traverse (1- height) (1+ (* pos 2)))))))))
      (traverse (%mp-tree-height ntx) 0))
    (values (nreverse bits) (nreverse hashes))))

(defun extract-partial-merkle-tree (ntx bits hashes)
  "Recompute the merkle root from a partial tree and collect the matched
leaves (Core TraverseAndExtract + ExtractMatches validation). Returns
(values root matched-txids matched-indices) or NIL on a malformed proof.
ROOT is a 32-byte vector; MATCHED-TXIDS a list of 32-byte vectors."
  (when (zerop ntx)
    (return-from extract-partial-merkle-tree nil))
  ;; Core CPartialMerkleTree::ExtractMatches (merkleblock.cpp:157-159):
  ;; "check for excessively high numbers of transactions". The claimed count
  ;; drives the tree shape, so an absurd value makes us build an absurd tree
  ;; before any other bound can reject it.
  ;; MAX_BLOCK_WEIGHT / MIN_TRANSACTION_WEIGHT = 4000000 / (4 * 60).
  (when (> ntx (floor 4000000 (* 4 60)))
    (return-from extract-partial-merkle-tree nil))
  ;; one bit per node and at least one node per hash, hashes <= ntx
  (let ((bits (coerce bits 'vector))
        (hashv (coerce hashes 'vector)))
    (when (or (> (length hashv) ntx) (< (length bits) (length hashv)))
      (return-from extract-partial-merkle-tree nil))
    (let ((bit-pos 0) (hash-pos 0) (bad nil)
          (matched '()) (indices '()))
      (labels ((traverse (height pos)
                 (when (>= bit-pos (length bits)) (setf bad t) (return-from traverse nil))
                 (let ((parent-of-match (aref bits bit-pos)))
                   (incf bit-pos)
                   (if (or (zerop height) (not parent-of-match))
                       (progn
                         (when (>= hash-pos (length hashv))
                           (setf bad t) (return-from traverse nil))
                         (let ((h (aref hashv hash-pos)))
                           (incf hash-pos)
                           (when (and (zerop height) parent-of-match)
                             (push h matched) (push pos indices))
                           h))
                       (let ((left (traverse (1- height) (* pos 2))) (right nil))
                         (if (< (1+ (* pos 2)) (%mp-tree-width ntx (1- height)))
                             (progn
                               (setf right (traverse (1- height) (1+ (* pos 2))))
                               (when (and left right (equalp left right)) (setf bad t)))
                             (setf right left))
                         (and left right (%mp-hash-pair left right)))))))
        (let ((root (traverse (%mp-tree-height ntx) 0)))
          ;; all hashes consumed; bits consumed up to byte padding
          (when (or bad
                    (null root)
                    (/= hash-pos (length hashv))
                    ;; All bits consumed except the byte padding (Core:
                    ;; (nBitsUsed+7)/8 == (vBits.size()+7)/8).
                    (/= (ceiling (length bits) 8)
                        (ceiling bit-pos 8)))
            (return-from extract-partial-merkle-tree nil))
          (values root (nreverse matched) (nreverse indices)))))))

(defun %mp-pack-bits (bits)
  "Pack a list of booleans into bytes, LSB-first within each byte (Core's
vBits serialization)."
  (let* ((n (length bits))
         (bytes (make-array (ceiling n 8) :element-type '(unsigned-byte 8)
                                          :initial-element 0)))
    (loop for b in bits for i from 0
          do (when b (setf (aref bytes (floor i 8))
                           (logior (aref bytes (floor i 8)) (ash 1 (mod i 8))))))
    bytes))

(defun %mp-unpack-bits (bytes)
  "Inverse of %mp-pack-bits: bytes -> list of (* 8 (length bytes)) booleans."
  (loop for i from 0 below (* 8 (length bytes))
        collect (logbitp (mod i 8) (aref bytes (floor i 8)))))

(defun serialize-merkle-block (header-bytes ntx hashes bits)
  "Serialize a CMerkleBlock: header(80) + ntx(u32) + vHash + vBits."
  (let ((bb (bitcoin-lisp.serialization:make-byte-buf)))
    (bitcoin-lisp.serialization:bb-write-bytes bb header-bytes)
    (bitcoin-lisp.serialization:bb-write-u32-le bb ntx)
    (bitcoin-lisp.serialization:bb-write-varint bb (length hashes))
    (dolist (h hashes) (bitcoin-lisp.serialization:bb-write-bytes bb h))
    (let ((packed (%mp-pack-bits bits)))
      (bitcoin-lisp.serialization:bb-write-varint bb (length packed))
      (bitcoin-lisp.serialization:bb-write-bytes bb packed))
    (bitcoin-lisp.serialization:bb-finish bb)))

(defun parse-merkle-block (bytes)
  "Parse a serialized CMerkleBlock. Returns
(values header-bytes ntx hashes bits) or signals on truncation."
  (let ((br (bitcoin-lisp.serialization:make-byte-reader-from bytes)))
    (let* ((header (bitcoin-lisp.serialization:br-read-bytes br 80))
           (ntx (bitcoin-lisp.serialization:br-read-u32-le br))
           (nhash (bitcoin-lisp.serialization:br-read-compact-size br))
           (hashes (loop repeat nhash
                         collect (bitcoin-lisp.serialization:br-read-bytes br 32)))
           (nbits-bytes (bitcoin-lisp.serialization:br-read-compact-size br))
           (bit-bytes (bitcoin-lisp.serialization:br-read-bytes br nbits-bytes)))
      (values header ntx hashes (%mp-unpack-bits bit-bytes)))))

;;; --- RPCs ---

(defun rpc-gettxoutproof (node params)
  "Build a merkle proof that the given TXIDs are in a block (Bitcoin Core
gettxoutproof). PARAMS: (txids [blockhash]). On this pruned node the block
must be locatable: pass BLOCKHASH, or have txindex enabled. Returns the
hex-encoded CMerkleBlock."
  (let ((txids (first params))
        (blockhash-hex (second params)))
    (unless (and (listp txids) txids)
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "txids must be a non-empty array"))
    (let ((wanted (mapcar (lambda (h)
                            (unless (valid-hex-hash-p h)
                              (error 'rpc-error :code +rpc-invalid-parameter+
                                                :message (format nil "Invalid txid ~A" h)))
                            (parse-hex-hash h))
                          txids))
          (chain-state (rpc-get-chain-state node))
          (block-store (rpc-get-block-store node)))
      ;; Locate the block: explicit hash, else txindex on the first txid.
      (let* ((block-hash
               (cond
                 (blockhash-hex
                  (unless (valid-hex-hash-p blockhash-hex)
                    (error 'rpc-error :code +rpc-invalid-parameter+ :message "Invalid blockhash"))
                  (parse-hex-hash blockhash-hex))
                 ((let ((ti (rpc-get-tx-index node)))
                    (and ti (bitcoin-lisp.storage:tx-index-enabled ti)))
                  (let ((loc (bitcoin-lisp.storage:txindex-lookup
                              (rpc-get-tx-index node) (first wanted))))
                    (unless loc
                      (error 'rpc-error :code +rpc-invalid-address-or-key+
                                        :message "Transaction not in txindex; pass a blockhash"))
                    (bitcoin-lisp.storage:tx-location-block-hash loc)))
                 (t (error 'rpc-error :code +rpc-invalid-parameter+
                                      :message "Need a blockhash (no txindex on this node)"))))
             (block (bitcoin-lisp.storage:get-block block-store block-hash)))
        (unless block
          (error 'rpc-error :code +rpc-invalid-address-or-key+
                            :message "Block not found (pruned?)"))
        (let* ((txs (bitcoin-lisp.serialization:bitcoin-block-transactions block))
               (txids-vec (map 'vector #'bitcoin-lisp.serialization:transaction-hash txs))
               (match (make-array (length txids-vec) :initial-element nil)))
          ;; Flag the requested txids; every one must be in the block.
          (dolist (w wanted)
            (let ((idx (position w txids-vec :test #'equalp)))
              (unless idx
                (error 'rpc-error :code +rpc-invalid-address-or-key+
                                  :message "Not all txids found in the specified block"))
              (setf (aref match idx) t)))
          (multiple-value-bind (bits hashes) (build-partial-merkle-tree txids-vec match)
            (let ((header-bytes (bitcoin-lisp.serialization:serialize-block-header
                                 (bitcoin-lisp.serialization:bitcoin-block-header block))))
              (bitcoin-lisp.crypto:bytes-to-hex
               (serialize-merkle-block header-bytes (length txids-vec) hashes bits)))))))))

(defun rpc-verifytxoutproof (node params)
  "Verify a merkle proof from gettxoutproof and return the txids it proves,
provided the proof's block is on the active chain (Bitcoin Core
verifytxoutproof). PARAMS: (proof-hex). Returns the list of txid hex
strings, or an empty list if the block isn't in the active chain."
  (let ((proof-hex (first params)))
    (unless (stringp proof-hex)
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "proof must be a hex string"))
    (let ((bytes (handler-case (bitcoin-lisp.crypto:hex-to-bytes proof-hex)
                   (error () (error 'rpc-error :code +rpc-invalid-parameter+
                                              :message "Invalid proof hex")))))
      (multiple-value-bind (header-bytes ntx hashes bits) (parse-merkle-block bytes)
        (multiple-value-bind (root matched) (extract-partial-merkle-tree ntx bits hashes)
          (unless root
            (error 'rpc-error :code +rpc-invalid-parameter+ :message "Invalid merkle proof"))
          ;; The recomputed root must equal the header's, and the block must
          ;; be a known active-chain block (Core checks it's in mapBlockIndex
          ;; and on the active chain).
          (let* ((header-root (subseq header-bytes 36 68))
                 (chain-state (rpc-get-chain-state node))
                 (block-hash (bitcoin-lisp.crypto:hash256 header-bytes))
                 (entry (bitcoin-lisp.storage:get-block-index-entry chain-state block-hash)))
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
                         (bitcoin-lisp.storage:entry-on-active-chain-p chain-state entry)
                         (plusp (bitcoin-lisp.storage:block-index-entry-tx-count entry)))
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
            (if (= ntx (bitcoin-lisp.storage:block-index-entry-tx-count entry))
                (json-array (mapcar #'hash-to-hex matched))
                (json-array nil))))))))
