;;;; BIP325 signet block-solution validation.
;;;;
;;;; A byte-for-byte port of Bitcoin Core's src/signet.cpp
;;;; (CheckSignetBlockSolution / SignetTxs::Create). Each signet block commits a
;;;; signature (the "signet solution") over the block, made with the network's
;;;; signet challenge key(s). Validation reconstructs a pair of BIP322-style
;;;; virtual transactions (to_spend / to_sign) and runs the script interpreter:
;;;; the challenge scriptPubKey must be satisfied by the solution's
;;;; scriptSig + witness, with the sighash taken over the modified block. Without
;;;; this check :signet would follow any low-difficulty chain (BIP325 is signet's
;;;; whole consensus point). Core call site: validation.cpp CheckBlock ->
;;;;   if (signet_blocks && fCheckPOW && !CheckSignetBlockSolution(...)) reject.

(in-package #:bitcoin-lisp.validation)

(defparameter *signet-header*
  (make-array 4 :element-type '(unsigned-byte 8)
                :initial-contents '(#xec #xc7 #xda #xa2))
  "SIGNET_HEADER (signet.cpp): the 4-byte tag prefixing the signet-solution push
inside the coinbase's witness-commitment output.")

(defparameter *default-signet-challenge*
  (bl.crypto:hex-to-bytes
   "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae")
  "Default public signet challenge (Core SigNetParams): a 1-of-2 bare multisig.")

(defparameter *signet-challenge* *default-signet-challenge*
  "Active signet challenge scriptPubKey. Rebind for a custom signet
(Core -signetchallenge); the default is the public signet challenge.")

(defun signet-challenge-for-network (network)
  "The signet challenge scriptPubKey for NETWORK, or NIL if NETWORK is not signet."
  (when (eq network :signet) *signet-challenge*))

;;; --- minimal script pushes (matches CScript::operator<< encoding) ---

(defun %minimal-push (data)
  "Encode DATA as a minimal Bitcoin script data push, exactly like CScript's
operator<< (direct push for <76 bytes, else OP_PUSHDATA1/2/4). An empty DATA
encodes as OP_0 (0x00), matching Core."
  (let ((n (length data)))
    (cond
      ((< n 76)
       (let ((out (make-array (1+ n) :element-type '(unsigned-byte 8))))
         (setf (aref out 0) n) (replace out data :start1 1) out))
      ((<= n #xff)
       (let ((out (make-array (+ n 2) :element-type '(unsigned-byte 8))))
         (setf (aref out 0) #x4c (aref out 1) n) (replace out data :start1 2) out))
      ((<= n #xffff)
       (let ((out (make-array (+ n 3) :element-type '(unsigned-byte 8))))
         (setf (aref out 0) #x4d (aref out 1) (ldb (byte 8 0) n) (aref out 2) (ldb (byte 8 8) n))
         (replace out data :start1 3) out))
      (t
       (let ((out (make-array (+ n 5) :element-type '(unsigned-byte 8))))
         (setf (aref out 0) #x4e
               (aref out 1) (ldb (byte 8 0) n) (aref out 2) (ldb (byte 8 8) n)
               (aref out 3) (ldb (byte 8 16) n) (aref out 4) (ldb (byte 8 24) n))
         (replace out data :start1 5) out)))))

(defun %next-script-op (script pos)
  "Decode the script element at POS. Returns (VALUES opcode pushdata next-pos),
where PUSHDATA is the pushed byte-vector for a data push (0x01..0x4e) or NIL for
a bare opcode. Returns NIL opcode on truncation (a push claiming past the end)."
  (let* ((len (length script))
         (op (aref script pos)))
    (cond
      ((<= op 75)                       ; OP_0 (0) or direct push 1..75
       (let ((end (+ pos 1 op)))
         (if (<= end len)
             (values op (subseq script (1+ pos) end) end)
             (values nil nil len))))
      ((= op 76)                        ; OP_PUSHDATA1
       (if (< (1+ pos) len)
           (let* ((n (aref script (1+ pos))) (start (+ pos 2)) (end (+ start n)))
             (if (<= end len) (values op (subseq script start end) end) (values nil nil len)))
           (values nil nil len)))
      ((= op 77)                        ; OP_PUSHDATA2
       (if (< (+ pos 2) len)
           (let* ((n (logior (aref script (1+ pos)) (ash (aref script (+ pos 2)) 8)))
                  (start (+ pos 3)) (end (+ start n)))
             (if (<= end len) (values op (subseq script start end) end) (values nil nil len)))
           (values nil nil len)))
      ((= op 78)                        ; OP_PUSHDATA4
       (if (< (+ pos 4) len)
           (let* ((n (logior (aref script (1+ pos)) (ash (aref script (+ pos 2)) 8)
                             (ash (aref script (+ pos 3)) 16) (ash (aref script (+ pos 4)) 24)))
                  (start (+ pos 5)) (end (+ start n)))
             (if (<= end len) (values op (subseq script start end) end) (values nil nil len)))
           (values nil nil len)))
      (t (values op nil (1+ pos))))))   ; bare opcode

(defun %concat-bytes (chunks)
  "Concatenate a list of byte-vectors into one (unsigned-byte 8) simple-array."
  (let* ((total (reduce #'+ chunks :key #'length :initial-value 0))
         (out (make-array total :element-type '(unsigned-byte 8)))
         (i 0))
    (dolist (c chunks out)
      (replace out c :start1 i) (incf i (length c)))))

(defun fetch-and-clear-signet-solution (witness-commitment)
  "Core FetchAndClearCommitmentSection(SIGNET_HEADER, ...). Scan the
WITNESS-COMMITMENT scriptPubKey for the first data push that begins with
*signet-header* AND carries data beyond it; return (VALUES solution cleared t)
where SOLUTION is that push minus the 4-byte header and CLEARED is the script
with that push truncated back to just the header (so the coinbase matches what
the miner signed). If none is found, return (VALUES #() witness-commitment NIL)."
  (let ((len (length witness-commitment))
        (pos 0)
        (result (make-array 0 :element-type '(unsigned-byte 8)))
        (parts '())
        (found nil)
        (hlen (length *signet-header*)))
    (loop while (< pos len) do
      (multiple-value-bind (op pushdata next) (%next-script-op witness-commitment pos)
        (when (null op) (return))       ; truncation: stop, like GetOp returning false
        (cond
          ((and pushdata (plusp (length pushdata)))
           (if (and (not found)
                    (> (length pushdata) hlen)
                    (equalp (subseq pushdata 0 hlen) *signet-header*))
               (progn
                 (setf result (subseq pushdata hlen)
                       found t)
                 (push (%minimal-push (subseq pushdata 0 hlen)) parts)) ; truncate to header
               (push (%minimal-push pushdata) parts)))
          (t (push (make-array 1 :element-type '(unsigned-byte 8) :initial-element op) parts)))
        (setf pos next)))
    (if found
        (values result (%concat-bytes (nreverse parts)) t)
        (values result witness-commitment nil))))

;;; --- witness commitment output (Core GetWitnessCommitmentIndex) ---

(defun %signet-witness-commitment-index (coinbase-tx)
  "Index of the LAST output whose scriptPubKey is a BIP141 witness commitment
(OP_RETURN, push-36, header 0xaa21a9ed), or NIL. The scriptPubKey may be longer
than 38 bytes when a signet push is appended."
  (let ((outputs (bl.ser:transaction-outputs coinbase-tx))
        (idx nil))
    (dotimes (i (length outputs) idx)
      (let ((s (bl.ser:tx-out-script-pubkey (aref outputs i))))
        (when (and (>= (length s) 38)
                   (= (aref s 0) #x6a) (= (aref s 1) #x24)
                   (equalp (subseq s 2 6) *witness-commitment-header*))
          (setf idx i))))))

(defun %coinbase-with-cleared-commitment (coinbase idx cleared-script)
  "A copy of COINBASE with output IDX's scriptPubKey replaced by CLEARED-SCRIPT,
for computing the modified (solution-free) coinbase txid. Witness is irrelevant
to the txid, so it is dropped."
  (let* ((outs (bl.ser:transaction-outputs coinbase))
         (new-outs (make-array (length outs))))
    (dotimes (i (length outs))
      (setf (aref new-outs i)
            (if (= i idx)
                (bl.ser:make-tx-out
                 :value (bl.ser:tx-out-value (aref outs i))
                 :script-pubkey cleared-script)
                (aref outs i))))
    (bl.ser:make-transaction
     :version (bl.ser:transaction-version coinbase)
     :inputs (bl.ser:transaction-inputs coinbase)
     :outputs new-outs
     :lock-time (bl.ser:transaction-lock-time coinbase))))

(defun %compute-modified-signet-merkle (modified-coinbase block)
  "Core ComputeModifiedMerkleRoot: the transaction merkle root using the modified
(solution-cleared) coinbase's txid in place of the real coinbase's."
  (let* ((txs (bl.ser:bitcoin-block-transactions block))
         (leaves (list (bl.ser:transaction-hash modified-coinbase))))
    (dolist (tx (rest txs))
      (push (bl.ser:transaction-hash tx) leaves))
    (values (compute-merkle-root (nreverse leaves)))))

;;; --- block_data and the to_spend / to_sign virtual transactions ---

(defun %serialize-signet-block-data (header signet-merkle)
  "Core block_data: nVersion (int32 LE) || hashPrevBlock (32) || signet-merkle (32)
|| nTime (uint32 LE) = 72 bytes."
  (let ((out (make-array 72 :element-type '(unsigned-byte 8)))
        (v (bl.ser:block-header-version header))
        (tm (bl.ser:block-header-timestamp header)))
    (dotimes (i 4) (setf (aref out i) (ldb (byte 8 (* 8 i)) (logand v #xffffffff))))
    (replace out (bl.ser:block-header-prev-block header) :start1 4)
    (replace out signet-merkle :start1 36)
    (dotimes (i 4) (setf (aref out (+ 68 i)) (ldb (byte 8 (* 8 i)) tm)))
    out))

(defun %parse-signet-solution (solution)
  "Deserialize SOLUTION as scriptSig (CScript) followed by a witness stack, per
Core (SpanReader >> scriptSig >> scriptWitness.stack). Returns
(VALUES script-sig witness-stack) on success, or (VALUES NIL NIL) if it does not
parse or has trailing bytes."
  (handler-case
      (let ((br (bl.ser:make-byte-reader-from solution)))
        (let ((script-sig (bl.ser:br-read-var-bytes br))
              (witness (bl.ser:br-read-witness-stack br)))
          (if (bl.ser::br-eof-p br)
              (values script-sig witness)
              (values nil nil))))        ; extraneous data
    (error () (values nil nil))))

(defun make-signet-txs (block challenge)
  "Core SignetTxs::Create. Build the (to_spend, to_sign) virtual transactions for
BLOCK under CHALLENGE (a scriptPubKey byte-vector). Returns (VALUES to-spend
to-sign) or (VALUES NIL NIL) on any failure (no coinbase, no witness commitment,
or a malformed signet solution)."
  (let ((txs (bl.ser:bitcoin-block-transactions block)))
    (when (null txs) (return-from make-signet-txs (values nil nil)))
    (let* ((coinbase (first txs))
           (cidx (%signet-witness-commitment-index coinbase)))
      (when (null cidx) (return-from make-signet-txs (values nil nil)))
      (let ((commitment (bl.ser:tx-out-script-pubkey
                         (aref (bl.ser:transaction-outputs coinbase) cidx)))
            (sol-script-sig (make-array 0 :element-type '(unsigned-byte 8)))
            (sol-witness '()))
        (multiple-value-bind (solution cleared found)
            (fetch-and-clear-signet-solution commitment)
          (when found
            (multiple-value-bind (ss wit) (%parse-signet-solution solution)
              (when (null ss) (return-from make-signet-txs (values nil nil)))
              (setf sol-script-sig ss sol-witness wit)))
          (let* ((mod-cb (%coinbase-with-cleared-commitment coinbase cidx cleared))
                 (signet-merkle (%compute-modified-signet-merkle mod-cb block))
                 (block-data (%serialize-signet-block-data
                              (bl.ser:bitcoin-block-header block)
                              signet-merkle))
                 ;; to_spend: scriptSig = OP_0 <block-data>
                 (to-spend-scriptsig (%concat-bytes
                                      (list (make-array 1 :element-type '(unsigned-byte 8)
                                                          :initial-element #x00)
                                            (%minimal-push block-data))))
                 (to-spend (bl.ser:make-transaction
                            :version 0 :lock-time 0
                            :inputs (vector (bl.ser:make-tx-in
                                             :previous-output (bl.ser:make-outpoint
                                                               :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                                    :initial-element 0)
                                                               :index #xffffffff)
                                             :script-sig to-spend-scriptsig
                                             :sequence 0))
                            :outputs (vector (bl.ser:make-tx-out
                                              :value 0 :script-pubkey challenge))))
                 (to-spend-txid (bl.ser:transaction-hash to-spend))
                 (to-sign (bl.ser:make-transaction
                           :version 0 :lock-time 0
                           :inputs (vector (bl.ser:make-tx-in
                                            :previous-output (bl.ser:make-outpoint
                                                              :hash to-spend-txid :index 0)
                                            :script-sig sol-script-sig :sequence 0))
                           :outputs (vector (bl.ser:make-tx-out
                                             :value 0
                                             :script-pubkey (make-array 1 :element-type '(unsigned-byte 8)
                                                                          :initial-element #x6a)))
                           :witness (when sol-witness (vector sol-witness)))))
            (values to-spend to-sign)))))))

;;; --- the check ---

(defun check-signet-block-solution (block &optional (challenge *signet-challenge*)
                                              (genesis-hash bl.store:*signet-genesis-hash*))
  "Core CheckSignetBlockSolution. Return T iff BLOCK carries a valid signet
solution for CHALLENGE (or is the signet genesis, whose solution is trivially
valid). Reconstructs the to_spend/to_sign transactions and runs the script
interpreter with BLOCK_SCRIPT_VERIFY_FLAGS (P2SH|WITNESS|DERSIG|NULLDUMMY)."
  (let ((header (bl.ser:bitcoin-block-header block)))
    (when (equalp (bl.ser:block-header-hash header) genesis-hash)
      (return-from check-signet-block-solution t))
    (multiple-value-bind (to-spend to-sign) (make-signet-txs block challenge)
      (when (null to-spend) (return-from check-signet-block-solution nil))
      (let* ((in0 (aref (bl.ser:transaction-inputs to-sign) 0))
             (script-sig (bl.ser:tx-in-script-sig in0))
             (wit (bl.ser:transaction-witness to-sign))
             (witness (when (and wit (plusp (length wit))) (aref wit 0)))
             (bl.interop:*current-tx* to-sign)
             (bl.interop:*current-input-index* 0)
             (bl.interop:*script-flags* "P2SH,WITNESS,DERSIG,NULLDUMMY"))
        (declare (ignorable to-spend))
        (values (bl.interop:verify-script
                 script-sig challenge :witness witness :amount 0))))))
