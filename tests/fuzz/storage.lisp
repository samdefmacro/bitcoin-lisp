(in-package #:bitcoin-lisp.tests)

;;;; Core's deserialize.cpp targets over the storage records: CTxUndo/CBlockUndo
;;;; (the rev files), CDiskBlockIndex and CBlockFileInfo (blocks/index).

(def-suite :fuzz-storage-tests :in :bitcoin-lisp-tests
  :description "Core fuzz deserialize.cpp targets over the storage records")

(in-suite :fuzz-storage-tests)

(define-fuzz-target blockundo-deserialize
    (buffer :core "deserialize.cpp:231-238" :iterations 20000 :max-len 200
            :corpus (lambda (fdp)
                      (bl.store:serialize-block-undo
                       (loop repeat (consume-integral-in-range fdp 0 3)
                             collect (loop repeat (consume-integral-in-range fdp 0 3)
                                           collect (bl.store:make-utxo-entry
                                                    :value (consume-money fdp)
                                                    :script-pubkey (consume-script fdp)
                                                    :height (consume-integral-in-range fdp 0 #x7fffffff 32)
                                                    :coinbase (consume-bool fdp)))))))
  "CBlockUndo, a vector of CTxUndo (txundo_deserialize is its inner half), each
a vector of coins in TxInUndoFormatter: it decodes or is refused, and a
decoded record serializes; one whose amounts are consensus-valid survives
deser(ser(undo)) (see coins-deserialize for why the bytes, and a wrapped
amount, need not)."
  (let* ((undo (fuzz-deserialize (bl.store:deserialize-block-undo buffer)))
         (bytes (bl.store:serialize-block-undo undo)))
    (assert-nonempty-reserialization buffer bytes)
    (when (every (lambda (tx-undo)
                   (every (lambda (e) (bl.val:money-range-p (bl.store:utxo-entry-value e))) tx-undo))
                 undo)
      (fuzz-assert (equalp (fuzz-sabotage bytes)
                           (bl.store:serialize-block-undo (bl.store:deserialize-block-undo bytes)))
                   "block undo does not survive a round trip"))))

(define-fuzz-target diskblockindex-deserialize
    (buffer :core "deserialize.cpp:334-337" :iterations 20000 :max-len 140
            :corpus (lambda (fdp)
                      (let ((bb (bl.ser:make-byte-buf)))
                        (dotimes (k 6) (bl.ser:bb-write-core-varint bb (consume-integral fdp :u32)))
                        (bl.ser:bb-write-bytes bb (bl.ser:serialize-block-header (consume-block-header fdp)))
                        (bl.ser:bb-finish bb))))
  "CDiskBlockIndex, the value of a blocks/index `b' record: it decodes or is
refused, and a decoded record serializes."
  (let ((entry (fuzz-deserialize (bl.store:decode-disk-block-index buffer))))
    (assert-nonempty-reserialization buffer (bl.store:encode-disk-block-index entry))))

(define-fuzz-target block-file-info-deserialize
    (buffer :core "deserialize.cpp:123-126" :iterations 20000 :max-len 60
            :corpus (lambda (fdp)
                      (let ((bb (bl.ser:make-byte-buf)))
                        (dotimes (k 7) (bl.ser:bb-write-core-varint bb (consume-integral fdp :u32)))
                        (bl.ser:bb-finish bb))))
  "CBlockFileInfo, the value of a blocks/index `f' record: seven VARINTs; it
decodes or is refused, and a decoded record serializes."
  (let ((info (fuzz-deserialize (bl.store:decode-block-file-info buffer))))
    (assert-nonempty-reserialization buffer (bl.store:encode-block-file-info info))))
