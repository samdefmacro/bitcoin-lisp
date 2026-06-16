(in-package #:bitcoin-lisp.tests)

;;; Serialize <-> deserialize round-trip property tests.
;;;
;;; For each wire type, assert that deserializing then re-serializing reproduces
;;; the exact bytes (and that derived hashes are stable). This catches asymmetry
;;; bugs — a field written one way but read another, or a length encoding that
;;; differs across a compact-size boundary. Inputs are seeded-random structured
;;; values so the script/witness/count sizes cross the encoding boundaries.

(in-suite :roundtrip-tests)

(defun %rt-rand-bytes (n state)
  (let ((v (make-array n :element-type '(unsigned-byte 8))))
    (dotimes (i n v) (setf (aref v i) (random 256 state)))))

(defun %rt-rand-tx (state &key witness)
  "A structurally-valid random transaction. Script lengths range 0..300 so they
cross the 0xfd compact-size boundary (253). When WITNESS, every input gets a
witness stack and the first is non-empty (so transaction-has-witness-p holds)."
  (let* ((nin (1+ (random 4 state)))
         (nout (1+ (random 4 state)))
         (inputs (loop repeat nin collect
                       (bitcoin-lisp.serialization:make-tx-in
                        :previous-output (bitcoin-lisp.serialization:make-outpoint
                                          :hash (%rt-rand-bytes 32 state)
                                          :index (random #x100000000 state))
                        :script-sig (%rt-rand-bytes (random 301 state) state)
                        :sequence (random #x100000000 state))))
         (outputs (loop repeat nout collect
                        (bitcoin-lisp.serialization:make-tx-out
                         :value (random 2100000000000000 state)
                         :script-pubkey (%rt-rand-bytes (random 301 state) state)))))
    (bitcoin-lisp.serialization:make-transaction
     :version (1+ (random 3 state))
     :inputs (coerce inputs 'simple-vector)
     :outputs (coerce outputs 'simple-vector)
     :lock-time (random #x100000000 state)
     :witness (when witness
                (coerce (loop for k from 0 below nin collect
                              (if (zerop k)
                                  (list (%rt-rand-bytes (1+ (random 40 state)) state))
                                  (loop repeat (random 3 state)
                                        collect (%rt-rand-bytes (random 40 state) state))))
                        'simple-vector)))))

;;;; CompactSize

(test roundtrip-compact-size
  ;; Boundary values that round-trip with the default range check (<= the
  ;; +max-compact-size+ cap of 0x02000000).
  (dolist (v '(0 1 76 252 253 254 255 65535 65536 65537 16777215 16777216 33554432))
    (let ((bytes (flexi-streams:with-output-to-sequence (s)
                   (bitcoin-lisp.serialization:write-compact-size s v))))
      (is (= v (flexi-streams:with-input-from-sequence (s bytes)
                 (bitcoin-lisp.serialization:read-compact-size s))))))
  ;; Encoding correctness across the full u64 range (range check disabled).
  (dolist (v '(4294967295 4294967296 4294967297 1099511627776 18446744073709551615))
    (let ((bytes (flexi-streams:with-output-to-sequence (s)
                   (bitcoin-lisp.serialization:write-compact-size s v))))
      (is (= v (flexi-streams:with-input-from-sequence (s bytes)
                 (bitcoin-lisp.serialization:read-compact-size s :range-check nil)))))))

;;;; Transactions

(test roundtrip-transaction-legacy
  (let ((state (sb-ext:seed-random-state 101)))
    (dotimes (i 60)
      (let* ((tx (%rt-rand-tx state))
             (bytes (bitcoin-lisp.serialization:serialize-transaction tx))
             (tx2 (flexi-streams:with-input-from-sequence (s bytes)
                    (bitcoin-lisp.serialization:read-transaction s)))
             (bytes2 (bitcoin-lisp.serialization:serialize-transaction tx2)))
        (is (equalp bytes bytes2))
        (is (equalp (bitcoin-lisp.serialization:transaction-hash tx)
                    (bitcoin-lisp.serialization:transaction-hash tx2)))))))

(test roundtrip-transaction-witness
  (let ((state (sb-ext:seed-random-state 202))
        (covered 0))
    (dotimes (i 60)
      (let ((tx (%rt-rand-tx state :witness t)))
        (is-true (bitcoin-lisp.serialization:transaction-has-witness-p tx))
        (incf covered)
        (let* ((bytes (bitcoin-lisp.serialization:serialize-witness-transaction tx))
               (tx2 (flexi-streams:with-input-from-sequence (s bytes)
                      (bitcoin-lisp.serialization:read-transaction s)))
               (bytes2 (bitcoin-lisp.serialization:serialize-witness-transaction tx2)))
          (is (equalp bytes bytes2))
          (is (equalp (bitcoin-lisp.serialization:transaction-wtxid tx)
                      (bitcoin-lisp.serialization:transaction-wtxid tx2)))
          (is (equalp (bitcoin-lisp.serialization:transaction-hash tx)
                      (bitcoin-lisp.serialization:transaction-hash tx2))))))
    (is (= 60 covered))))

;;;; Block header + full block

(test roundtrip-block-header
  (let ((state (sb-ext:seed-random-state 303)))
    (dotimes (i 50)
      (let* ((hdr (bitcoin-lisp.serialization:make-block-header
                   :version (random #x80000000 state)
                   :prev-block (%rt-rand-bytes 32 state)
                   :merkle-root (%rt-rand-bytes 32 state)
                   :timestamp (random #x100000000 state)
                   :bits (random #x100000000 state)
                   :nonce (random #x100000000 state)))
             (bytes (bitcoin-lisp.serialization:serialize-block-header hdr))
             (hdr2 (flexi-streams:with-input-from-sequence (s bytes)
                     (bitcoin-lisp.serialization::read-block-header s)))
             (bytes2 (bitcoin-lisp.serialization:serialize-block-header hdr2)))
        (is (= 80 (length bytes)))
        (is (equalp bytes bytes2))))))

(test roundtrip-block
  (let ((state (sb-ext:seed-random-state 404)))
    (dotimes (i 25)
      (let* ((txs (cons (%rt-rand-tx state)
                        (loop repeat (random 4 state)
                              collect (%rt-rand-tx state :witness (= 1 (random 2 state))))))
             (hdr (bitcoin-lisp.serialization:make-block-header
                   :version (random #x80000000 state)
                   :prev-block (%rt-rand-bytes 32 state)
                   :merkle-root (%rt-rand-bytes 32 state)
                   :timestamp (random #x100000000 state)
                   :bits (random #x100000000 state)
                   :nonce (random #x100000000 state)))
             (blk (bitcoin-lisp.serialization:make-bitcoin-block :header hdr :transactions txs))
             (bytes (bitcoin-lisp.serialization:serialize-witness-block blk))
             (blk2 (flexi-streams:with-input-from-sequence (s bytes)
                     (bitcoin-lisp.serialization:read-bitcoin-block s)))
             (bytes2 (bitcoin-lisp.serialization:serialize-witness-block blk2)))
        (is (equalp bytes bytes2))
        (is (= (length txs)
               (length (bitcoin-lisp.serialization:bitcoin-block-transactions blk2))))
        (is (equalp (bitcoin-lisp.serialization:block-header-hash hdr)
                    (bitcoin-lisp.serialization:block-header-hash
                     (bitcoin-lisp.serialization:bitcoin-block-header blk2))))))))

;;;; Inv vectors (inv/getdata payload)

(test roundtrip-inv-vectors
  (let ((state (sb-ext:seed-random-state 505)))
    (dotimes (i 30)
      (let* ((n (1+ (random 20 state)))
             (vecs (loop repeat n collect
                         (bitcoin-lisp.serialization:make-inv-vector
                          :type (random 5 state) :hash (%rt-rand-bytes 32 state))))
             (payload (flexi-streams:with-output-to-sequence (s)
                        (bitcoin-lisp.serialization:write-compact-size s n)
                        (dolist (v vecs)
                          (bitcoin-lisp.serialization::write-inv-vector s v))))
             (parsed (bitcoin-lisp.serialization:parse-inv-payload payload)))
        (is (= n (length parsed)))
        (loop for a in vecs for b in parsed do
          (is (= (bitcoin-lisp.serialization:inv-vector-type a)
                 (bitcoin-lisp.serialization:inv-vector-type b)))
          (is (equalp (bitcoin-lisp.serialization:inv-vector-hash a)
                      (bitcoin-lisp.serialization:inv-vector-hash b))))))))

(test make-block-message-witness
  "make-block-message :witness t wraps the witness-serialized block (the form
served for a MSG_WITNESS_BLOCK getdata); :witness nil is legacy. For a segwit
block the witness message is larger, and its payload round-trips to a block whose
transaction retains witness data."
  (let* ((state (sb-ext:seed-random-state 717))
         (wtx (%rt-rand-tx state :witness t))
         (hdr (bitcoin-lisp.serialization:make-block-header
               :version 1 :prev-block (%rt-rand-bytes 32 state)
               :merkle-root (%rt-rand-bytes 32 state)
               :timestamp 1700000000 :bits #x207fffff :nonce 0))
         (blk (bitcoin-lisp.serialization:make-bitcoin-block
               :header hdr :transactions (list wtx)))
         (wmsg (bitcoin-lisp.serialization:make-block-message blk :witness t))
         (lmsg (bitcoin-lisp.serialization:make-block-message blk :witness nil)))
    (is-true (bitcoin-lisp.serialization:transaction-has-witness-p wtx))
    (is (> (length wmsg) (length lmsg))
        "witness block message must be larger than the legacy one")
    ;; Strip the 24-byte message header, parse the payload back to a block.
    (let* ((payload (subseq wmsg 24))
           (blk2 (bitcoin-lisp.serialization:parse-block-payload payload))
           (rtx (first (bitcoin-lisp.serialization:bitcoin-block-transactions blk2))))
      (is-true (bitcoin-lisp.serialization:transaction-has-witness-p rtx)
               "witness must survive the make-block-message round-trip"))))

(test make-blocktxn-message-witness
  "make-blocktxn-message :witness t serializes the requested txs witness-complete
(BIP152 serve side) and round-trips via parse-blocktxn-payload, preserving order,
block hash, and per-tx witness."
  (let* ((state (sb-ext:seed-random-state 919))
         (bh (%rt-rand-bytes 32 state))
         (wtx (%rt-rand-tx state :witness t))
         (ltx (%rt-rand-tx state :witness nil))
         (msg (bitcoin-lisp.serialization:make-blocktxn-message bh (list wtx ltx) :witness t))
         (resp (bitcoin-lisp.serialization:parse-blocktxn-payload (subseq msg 24)))
         (rtxs (bitcoin-lisp.serialization:block-txn-response-transactions resp)))
    (is (equalp bh (bitcoin-lisp.serialization:block-txn-response-block-hash resp)))
    (is (= 2 (length rtxs)))
    (is-true (bitcoin-lisp.serialization:transaction-has-witness-p (first rtxs))
             "witness tx must round-trip with witness intact")
    (is (equalp (bitcoin-lisp.serialization:serialize-witness-transaction wtx)
                (bitcoin-lisp.serialization:serialize-witness-transaction (first rtxs))))))
