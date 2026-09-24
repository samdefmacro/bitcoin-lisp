(in-package #:bitcoin-lisp.networking)

;;;; CMerkleBlock / CPartialMerkleTree (Bitcoin Core merkleblock.{h,cpp}).
;;;
;;; A serialized CMerkleBlock is the block header (80 bytes) + a
;;; CPartialMerkleTree { nTransactions:u32, vHash:[32]*, vBits:bytes }: just
;;; the hashes on the authentication paths to the matched txids plus a flag-bit
;;; stream describing the traversal, so a verifier can recompute the merkle
;;; root and confirm membership. It is the BIP37 `merkleblock' message and the
;;; gettxoutproof proof alike; the algorithms mirror CPartialMerkleTree exactly
;;; (CalcHash / TraverseAndBuild / TraverseAndExtract).

(defun %mp-hash-pair (a b)
  "double-SHA256 of A||B (32-byte halves) — internal merkle combiner."
  (let ((c (make-array 64 :element-type '(unsigned-byte 8))))
    (replace c a :start1 0)
    (replace c b :start1 32)
    (bl.crypto:hash256 c)))

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
  (let ((bb (bl.ser:make-byte-buf)))
    (bl.ser:bb-write-bytes bb header-bytes)
    (bl.ser:bb-write-u32-le bb ntx)
    (bl.ser:bb-write-varint bb (length hashes))
    (dolist (h hashes) (bl.ser:bb-write-bytes bb h))
    (let ((packed (%mp-pack-bits bits)))
      (bl.ser:bb-write-varint bb (length packed))
      (bl.ser:bb-write-bytes bb packed))
    (bl.ser:bb-finish bb)))

(defun parse-merkle-block (bytes)
  "Parse a serialized CMerkleBlock. Returns
(values header-bytes ntx hashes bits) or signals on truncation."
  (let ((br (bl.ser:make-byte-reader-from bytes)))
    (let* ((header (bl.ser:br-read-bytes br 80))
           (ntx (bl.ser:br-read-u32-le br))
           (nhash (bl.ser:br-read-compact-size br))
           (hashes (loop repeat nhash
                         collect (bl.ser:br-read-bytes br 32)))
           (nbits-bytes (bl.ser:br-read-compact-size br))
           (bit-bytes (bl.ser:br-read-bytes br nbits-bytes)))
      (values header ntx hashes (%mp-unpack-bits bit-bytes)))))


(defun make-merkle-block (block filter)
  "Core CMerkleBlock(block, filter) (merkleblock.cpp:30-55): every
transaction FILTER finds relevant -- IsRelevantAndUpdate, which may grow the
filter as it goes, in block order -- is a match. Returns (VALUES
merkleblock-payload matched), MATCHED being Core's vMatchedTxn as a list of
(index . txid)."
  (let* ((txs (bl.ser:bitcoin-block-transactions block))
         (txids (map 'vector #'bl.ser:transaction-hash txs))
         (match (make-array (length txids) :initial-element nil))
         (matched '()))
    (loop for tx in txs
          for i from 0
          do (when (bloom-relevant-and-update-p filter tx)
               (setf (aref match i) t)
               (push (cons i (aref txids i)) matched)))
    (multiple-value-bind (bits hashes) (build-partial-merkle-tree txids match)
      (values (serialize-merkle-block
               (bl.ser:serialize-block-header (bl.ser:bitcoin-block-header block))
               (length txids) hashes bits)
              (nreverse matched)))))
