(in-package #:bitcoin-lisp.test-support)

;;;; Synthetic transactions

(defun make-mempool-test-tx (&key (input-id 1) (input-index 0) (value 50000000))
  "Create a test transaction for mempool tests.
INPUT-ID controls the prev outpoint hash byte, creating distinct inputs."
  (let ((input (bl.ser:make-tx-in
                :previous-output (bl.ser:make-outpoint
                                  :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                    :initial-element input-id)
                                  :index input-index)
                :script-sig (make-array 10 :element-type '(unsigned-byte 8)
                                        :initial-element #x00)
                :sequence #xFFFFFFFF))
        ;; P2PKH output script (standard)
        (output (bl.ser:make-tx-out
                 :value value
                 :script-pubkey (let ((s (make-array 25 :element-type '(unsigned-byte 8)
                                                    :initial-element 0)))
                                  (setf (aref s 0) #x76)   ; OP_DUP
                                  (setf (aref s 1) #xa9)   ; OP_HASH160
                                  (setf (aref s 2) #x14)   ; push 20 bytes
                                  (setf (aref s 23) #x88)  ; OP_EQUALVERIFY
                                  (setf (aref s 24) #xac)  ; OP_CHECKSIG
                                  s))))
    (bl.ser:make-transaction
     :version 1
     :inputs (vector input)
     :outputs (vector output)
     :lock-time 0)))

(defun make-witness-test-tx-bytes ()
  "Build raw bytes for a synthetic BIP 144 witness transaction."
  (coerce
   (bl.bytes:with-byte-buf (s)
     ;; Version = 2
     (bl.bytes:bb-write-i32-le s 2)
     ;; Marker + flag
     (bl.bytes:bb-write-u8 s #x00)
     (bl.bytes:bb-write-u8 s #x01)
     ;; 1 input
     (bl.bytes:bb-write-varint s 1)
     ;; prev outpoint: txid (32 bytes of 0x11), index 0
     (bl.bytes:bb-write-bytes s (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x11))
     (bl.bytes:bb-write-u32-le s 0)
     ;; empty scriptSig
     (bl.bytes:bb-write-varint s 0)
     ;; sequence
     (bl.bytes:bb-write-u32-le s #xFFFFFFFE)
     ;; 1 output
     (bl.bytes:bb-write-varint s 1)
     ;; value: 49999 satoshis
     (bl.bytes:bb-write-i64-le s 49999)
     ;; 25-byte scriptPubKey (P2PKH placeholder)
     (bl.bytes:bb-write-varint s 25)
     (bl.bytes:bb-write-bytes s (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76))
     ;; Witness for input 0: 2 items
     (bl.bytes:bb-write-varint s 2)
     ;; Item 1: 72-byte signature placeholder
     (bl.bytes:bb-write-varint s 72)
     (bl.bytes:bb-write-bytes s (make-array 72 :element-type '(unsigned-byte 8) :initial-element #xAA))
     ;; Item 2: 33-byte pubkey placeholder
     (bl.bytes:bb-write-varint s 33)
     (bl.bytes:bb-write-bytes s (make-array 33 :element-type '(unsigned-byte 8) :initial-element #xBB))
     ;; Locktime: 500000
     (bl.bytes:bb-write-u32-le s 500000))
   '(simple-array (unsigned-byte 8) (*))))

(defun make-spending-test-tx (parent-txid &key (vout 0) (value 40000000))
  "A tx spending PARENT-TXID's output VOUT, paying a standard P2PKH output."
  (bl.ser:make-transaction
   :version 1
   :inputs (vector (bl.ser:make-tx-in
                  :previous-output (bl.ser:make-outpoint
                                    :hash parent-txid :index vout)
                  :script-sig (make-array 10 :element-type '(unsigned-byte 8) :initial-element 0)
                  :sequence #xFFFFFFFF))
   :outputs (vector (bl.ser:make-tx-out
                   :value value
                   :script-pubkey (let ((s (make-array 25 :element-type '(unsigned-byte 8)
                                                       :initial-element 0)))
                                    (setf (aref s 0) #x76 (aref s 1) #xa9 (aref s 2) #x14
                                          (aref s 23) #x88 (aref s 24) #xac) s)))
   :lock-time 0))
