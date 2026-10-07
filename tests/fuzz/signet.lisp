(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/signet.cpp at the pin: CheckSignetBlockSolution and
;;;; SignetTxs::Create (signet.cpp:66-155) over any deserialized block and
;;;; challenge. Ours: CHECK-SIGNET-BLOCK-SOLUTION and MAKE-SIGNET-TXS.
;;;;
;;;; Core asserts that both return. Ours also builds blocks whose coinbase
;;;; witness commitment carries a signet solution (SIGNET_HEADER ecc7daa2 and
;;;; a serialized scriptSig and witness stack) among other pushes and
;;;; opcodes, and holds SignetTxs to what BIP325 says they are: the
;;;; to_spend scriptSig is OP_0 and a push of the 72-byte block data, whose
;;;; merkle root is the block's with the solution cut from the commitment --
;;;; computed here from the block as the generator built it, with the
;;;; solution push reduced to the bare header; the to_sign input carries the
;;;; solution's scriptSig and witness; a solution with bytes left over is no
;;;; solution; and with an OP_TRUE challenge an empty solution is valid.

(def-suite :fuzz-signet-tests :in :bitcoin-lisp-tests
  :description "Core fuzz signet.cpp")

(in-suite :fuzz-signet-tests)

(defparameter +signet-header+ (coerce #(#xec #xc7 #xda #xa2) '(simple-array (unsigned-byte 8) (*)))
  "Core SIGNET_HEADER (signet.cpp:25).")

(defun %signet-push (data)
  "CScript << DATA for non-empty DATA (script.h:483-510)."
  (bl.ser:script-push-data data))

(defun %signet-block (fdp)
  "A block whose coinbase carries a witness commitment, and maybe a signet
solution in it. Returns the block, the commitment script with the solution
cut to the bare header (or NIL when there is none), the solution's scriptSig
and witness, and whether the solution has trailing bytes."
  (let* ((script-sig (consume-random-length-byte-vector fdp 20))
         (witness (loop repeat (consume-integral-in-range fdp 0 3)
                        collect (consume-random-length-byte-vector fdp 20)))
         (trailing (zerop (consume-integral-in-range fdp 0 5)))
         (solution (%concat-octets
                    (list (%ser #'bl.bytes:bb-write-var-bytes script-sig)
                          (%ser #'bl.ser:bb-write-varint (length witness))
                          (%concat-octets (mapcar (lambda (w) (%ser #'bl.bytes:bb-write-var-bytes w)) witness))
                          (if trailing (vector (consume-integral fdp :u8)) #()))))
         (with-solution (plusp (consume-integral-in-range fdp 0 5)))
         (before (loop repeat (consume-integral-in-range fdp 0 2)
                       collect (call-one-of fdp
                                 (vector (pick-value-in-array fdp '(#x61 #x6a #x51 #xac)))
                                 (%signet-push (consume-random-length-byte-vector fdp 8)))))
         (after (loop repeat (consume-integral-in-range fdp 0 2)
                      collect (%signet-push (consume-random-length-byte-vector fdp 8))))
         (head (%concat-octets (list #(#x6a #x24 #xaa #x21 #xa9 #xed) (consume-uint256 fdp))))
         (commitment (%concat-octets
                      (append (list head) before
                              (when with-solution
                                (list (%signet-push (%concat-octets (list +signet-header+ solution)))))
                              after)))
         (cleared (when with-solution
                    (%concat-octets (append (list head) before (list (%signet-push +signet-header+)) after))))
         (coinbase (bl.ser:make-transaction
                    :version 1 :lock-time 0
                    :inputs (vector (bl.ser:make-tx-in
                                     :previous-output (bl.ser:make-outpoint
                                                       :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                            :initial-element 0)
                                                       :index #xffffffff)
                                     :script-sig (consume-random-length-byte-vector fdp 10)))
                    :outputs (vector (bl.ser:make-tx-out :value 5000000000 :script-pubkey +p2wsh-op-true+)
                                     (bl.ser:make-tx-out :value 0 :script-pubkey commitment))))
         (txs (cons coinbase (loop repeat (consume-integral-in-range fdp 0 2)
                                   collect (consume-transaction fdp :max-num-in 2 :max-num-out 2)))))
    (values (bl.ser:make-bitcoin-block
             :header (bl.ser:make-block-header :version (consume-integral fdp :i32)
                                               :prev-block (consume-uint256 fdp)
                                               :merkle-root (consume-uint256 fdp)
                                               :timestamp (consume-integral fdp :u32)
                                               :bits #x1e0377ae :nonce 0)
             :transactions txs)
            cleared script-sig witness trailing)))

(define-fuzz-target signet
    (buffer :core "signet.cpp:27-40" :iterations 3000 :max-len 600)
  "SignetTxs of any block answer or refuse, never fail otherwise, and of a
block carrying a signet solution they are BIP325's: the block data commits
to the merkle root with the solution cut out, the spending input carries the
solution, leftover bytes refuse it, and an OP_TRUE challenge accepts an
empty one."
  (let ((fdp (make-fuzzed-data-provider buffer)))
    (if (zerop (consume-integral-in-range fdp 0 3))
        (let ((block (or (consume-deserializable
                          fdp (lambda (b) (bl.ser:br-read-bitcoin-block (bl.ser:make-byte-reader-from b))))
                         (fuzz-reject)))
              (challenge (consume-script fdp)))
          (bl.val:check-signet-block-solution block challenge)
          (bl.val:make-signet-txs block challenge))
        (multiple-value-bind (block cleared script-sig witness trailing) (%signet-block fdp)
          (let ((challenge (if (consume-bool fdp) (coerce #(#x51) '(simple-array (unsigned-byte 8) (*)))
                               (consume-script fdp))))
            (multiple-value-bind (to-spend to-sign) (bl.val:make-signet-txs block challenge)
              (cond
                ((and cleared trailing)
                 (fuzz-assert (null (fuzz-sabotage to-spend)) "a solution with bytes left over was taken"))
                (t
                 (fuzz-assert to-spend "SignetTxs refused a well-formed block")
                 (let* ((txs (bl.ser:bitcoin-block-transactions block))
                        (coinbase (first txs))
                        (stripped (if cleared
                                      (bl.ser:make-transaction
                                       :version 1 :lock-time 0
                                       :inputs (bl.ser:transaction-inputs coinbase)
                                       :outputs (vector (aref (bl.ser:transaction-outputs coinbase) 0)
                                                        (bl.ser:make-tx-out :value 0 :script-pubkey cleared)))
                                      coinbase))
                        (root (bl.val:compute-merkle-root
                               (cons (bl.ser:transaction-hash stripped)
                                     (mapcar #'bl.ser:transaction-hash (rest txs)))))
                        (spend-sig (bl.ser:tx-in-script-sig (aref (bl.ser:transaction-inputs to-spend) 0)))
                        (in (aref (bl.ser:transaction-inputs to-sign) 0)))
                   (fuzz-assert (and (= 74 (length spend-sig)) (= 0 (aref spend-sig 0)) (= 72 (aref spend-sig 1))
                                     (equalp (subseq spend-sig 38 70) (fuzz-sabotage root)))
                                "to_spend does not commit to the merkle root without the solution")
                   (when cleared
                     (fuzz-assert (equalp (bl.ser:tx-in-script-sig in) script-sig)
                                  "to_sign's scriptSig is not the solution's")
                     (fuzz-assert (equalp (coerce (let ((w (bl.ser:transaction-witness to-sign)))
                                                    (and w (plusp (length w)) (aref w 0)))
                                                  'list)
                                          witness)
                                  "to_sign's witness is not the solution's"))
                   (when (and (equalp challenge #(#x51)) (or (null cleared)
                                                             (and (zerop (length script-sig)) (null witness))))
                     (fuzz-assert (bl.val:check-signet-block-solution block challenge)
                                  "an empty solution does not satisfy OP_TRUE")))))))))))
