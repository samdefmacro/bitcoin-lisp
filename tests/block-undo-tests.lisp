(in-package #:bitcoin-lisp.tests)

(def-suite :block-undo-tests
  :description "Core's CBlockUndo record (undo.h)"
  :in :bitcoin-lisp-tests)

(in-suite :block-undo-tests)

;;;; Bitcoin Core ships no CBlockUndo test vectors, so byte-exactness is
;;;; established by layering rather than by a golden file:
;;;;
;;;; - TxOutCompression (the amount and script codecs) is already verified
;;;;   against Core's own compress_tests.cpp in :compressor-tests;
;;;; - Core's VARINT is verified there too, including the canonical examples
;;;;   from serialize.h;
;;;; - CompactSize is exercised across the whole serialization suite.
;;;;
;;;; What is NEW here is the COMPOSITION -- Core's field order, its nesting,
;;;; and the dummy byte's condition -- so that is what these assert, against
;;;; the already-verified primitives rather than against hand-computed bytes.
;;;; A hand-copied vector has already presented as a phantom bug once in this
;;;; project; deriving from verified pieces avoids repeating that.

(defun %bu-entry (&key (value 50000) (height 100) coinbase (script #(#x51)))
  (bitcoin-lisp.storage:make-utxo-entry
   :value value
   :script-pubkey (coerce script '(simple-array (unsigned-byte 8) (*)))
   :height height
   :coinbase coinbase))

(defun %bu-expected-coin-bytes (entry)
  "The bytes Core's TxInUndoFormatter::Ser produces, assembled here from the
primitives that are individually verified against Core."
  (let ((bb (bitcoin-lisp.serialization:make-byte-buf)))
    (bitcoin-lisp.serialization:bb-write-core-varint
     bb (+ (* (bitcoin-lisp.storage:utxo-entry-height entry) 2)
           (if (bitcoin-lisp.storage:utxo-entry-coinbase entry) 1 0)))
    (when (plusp (bitcoin-lisp.storage:utxo-entry-height entry))
      (bitcoin-lisp.serialization:bb-write-u8 bb 0))
    (bitcoin-lisp.serialization:bb-write-compressed-tx-out
     bb (bitcoin-lisp.storage:utxo-entry-value entry)
     (bitcoin-lisp.storage:utxo-entry-script-pubkey entry))
    (bitcoin-lisp.serialization:bb-finish bb)))

;;; --- Layout -----------------------------------------------------------------

(test block-undo-layout-is-core-s-nesting
  "CompactSize(tx count), then per transaction CompactSize(input count), then
each Coin. Nothing else -- in particular no outpoint, which is the whole point
of the format: position names the coin."
  (let* ((a (%bu-entry :value 1000 :height 5))
         (b (%bu-entry :value 2000 :height 6))
         (c (%bu-entry :value 3000 :height 7))
         (bytes (bitcoin-lisp.storage:serialize-block-undo (list (list a b) (list c))))
         (expected (concatenate '(vector (unsigned-byte 8))
                                #(2)            ; two transactions
                                #(2)            ; first has two inputs
                                (%bu-expected-coin-bytes a)
                                (%bu-expected-coin-bytes b)
                                #(1)            ; second has one input
                                (%bu-expected-coin-bytes c))))
    (is (equalp expected bytes))))

(test block-undo-dummy-byte-appears-exactly-when-height-is-positive
  "Core writes a zero byte after the height/coinbase code iff height > 0, for
compatibility with an undo format that kept a transaction version there
(undo.h:26-33). The condition is the whole rule, so pin both sides of it."
  (let* ((at-zero (%bu-entry :height 0))
         (above-zero (%bu-entry :height 1))
         (b0 (bitcoin-lisp.storage:serialize-block-undo (list (list at-zero))))
         (b1 (bitcoin-lisp.storage:serialize-block-undo (list (list above-zero)))))
    ;; VARINT(0) and VARINT(2) are both one byte, and the outputs are identical
    ;; apart from the code and the dummy, so the length difference is exactly
    ;; the dummy byte.
    (is (= (1+ (length b0)) (length b1)))
    ;; And it really is a zero byte, in the right place: after the code.
    (is (= 0 (aref b1 3)))
    (is (= 2 (aref b1 2)))))

(test block-undo-round-trips-including-the-awkward-values
  "Round-trip through the codec preserves every field, for the cases most
likely to be mishandled: height 0, a coinbase coin, the maximum money value,
an empty script, and a script long enough to leave the compressed special
forms behind."
  (let ((cases (list (%bu-entry :height 0 :value 0 :script #())
                     (%bu-entry :height 1 :coinbase t)
                     (%bu-entry :height #xFFFFFFFF :value 2100000000000000)
                     (%bu-entry :value 1 :script (make-array 100 :initial-element #xAB))
                     ;; A P2PKH script, which the compressor stores in a
                     ;; special form rather than raw.
                     (%bu-entry :script (concatenate 'list
                                                     '(#x76 #xA9 #x14)
                                                     (make-list 20 :initial-element #x11)
                                                     '(#x88 #xAC))))))
    (let* ((bytes (bitcoin-lisp.storage:serialize-block-undo (list cases)))
           (back (first (bitcoin-lisp.storage:deserialize-block-undo bytes))))
      (is (= (length cases) (length back)))
      (loop for want in cases
            for got in back
            do (is (= (bitcoin-lisp.storage:utxo-entry-value want)
                      (bitcoin-lisp.storage:utxo-entry-value got)))
               (is (= (bitcoin-lisp.storage:utxo-entry-height want)
                      (bitcoin-lisp.storage:utxo-entry-height got)))
               (is (eq (and (bitcoin-lisp.storage:utxo-entry-coinbase want) t)
                       (and (bitcoin-lisp.storage:utxo-entry-coinbase got) t)))
               (is (equalp (bitcoin-lisp.storage:utxo-entry-script-pubkey want)
                           (bitcoin-lisp.storage:utxo-entry-script-pubkey got)))))))

(test block-undo-handles-a-block-with-nothing-to-undo
  "A coinbase-only block has an empty vtxundo, which must serialize to a single
zero CompactSize and read back as the empty list -- not as a failure."
  (let ((bytes (bitcoin-lisp.storage:serialize-block-undo '())))
    (is (equalp #(0) bytes))
    (is (null (bitcoin-lisp.storage:deserialize-block-undo bytes))))
  ;; A transaction with no inputs is not a thing a real block contains, but the
  ;; nesting must still be unambiguous.
  (let ((bytes (bitcoin-lisp.storage:serialize-block-undo (list '()))))
    (is (equalp #(1 0) bytes))
    (is (equal '(()) (bitcoin-lisp.storage:deserialize-block-undo bytes)))))

;;; --- The bridge from our (txid index entry) triples --------------------------

(defun %bu-test-block (input-counts)
  "A block with a coinbase plus one transaction per element of INPUT-COUNTS,
each spending that many distinct outpoints."
  (let ((txs (list (make-mempool-test-tx :input-id 0))))
    (loop for count in input-counts
          for tx-i from 1
          do (push (bitcoin-lisp.serialization:make-transaction
                    :version 1
                    :inputs (coerce
                             (loop for j below count
                                   collect (bitcoin-lisp.serialization:make-tx-in
                                            :previous-output
                                            (bitcoin-lisp.serialization:make-outpoint
                                             :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                  :initial-element (+ (* tx-i 16) j))
                                             :index j)
                                            :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                                            :sequence #xFFFFFFFF))
                             'vector)
                    :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                                      :value 1000
                                      :script-pubkey (coerce #(#x51) '(simple-array (unsigned-byte 8) (*)))))
                    :lock-time 0)
                   txs))
    (bitcoin-lisp.serialization:make-bitcoin-block
     :header (bitcoin-lisp.serialization:make-block-header)
     :transactions (nreverse txs))))

(defun %bu-spent-for (block)
  "The (txid index entry) triples APPLY-BLOCK-TO-UTXO-SET would produce for
BLOCK: every non-coinbase input, in apply order."
  (let ((out '()))
    (loop for tx in (rest (bitcoin-lisp.serialization:bitcoin-block-transactions block))
          for h from 10
          do (bitcoin-lisp.serialization:dovector
                 (input (bitcoin-lisp.serialization:transaction-inputs tx))
               (let ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input)))
                 (push (list (bitcoin-lisp.serialization:outpoint-hash prevout)
                             (bitcoin-lisp.serialization:outpoint-index prevout)
                             (%bu-entry :height h
                                        :value (+ 500 (bitcoin-lisp.serialization:outpoint-index
                                                       prevout))))
                       out))))
    (nreverse out)))

(test block-undo-bridge-round-trips-our-triples
  "Grouping our flat triples into Core's shape and back must reproduce them
exactly -- outpoints included, even though the format stores none of them."
  (let* ((block (%bu-test-block '(1 3 2)))
         (spent (%bu-spent-for block))
         (grouped (bitcoin-lisp.storage:block-undo-from-spent-utxos block spent))
         (back (bitcoin-lisp.storage:spent-utxos-from-block-undo block grouped)))
    (is (equal '(1 3 2) (mapcar #'length grouped)))
    (is (= (length spent) (length back)))
    (loop for want in spent
          for got in back
          do (is (equalp (first want) (first got)))
             (is (= (second want) (second got)))
             (is (= (bitcoin-lisp.storage:utxo-entry-value (third want))
                    (bitcoin-lisp.storage:utxo-entry-value (third got)))))
    ;; And through the wire format, which is the combination that P2 will use.
    (let ((decoded (bitcoin-lisp.storage:deserialize-block-undo
                    (bitcoin-lisp.storage:serialize-block-undo grouped))))
      (is (equal '(1 3 2) (mapcar #'length decoded))))))

(test block-undo-bridge-refuses-inconsistent-input
  "Core makes both mismatches DISCONNECT_FAILED (validation.cpp:2187, 2224),
because the position of a coin is the only thing naming it: a short, long or
misaligned list would restore the WRONG coins rather than fail. So the
conversion must refuse, not truncate."
  (let* ((block (%bu-test-block '(2 2)))
         (spent (%bu-spent-for block)))
    (signals error (bitcoin-lisp.storage:block-undo-from-spent-utxos block (rest spent)))
    (signals error (bitcoin-lisp.storage:block-undo-from-spent-utxos
                    block (append spent (list (first spent)))))
    ;; Misaligned: right length, wrong outpoints (two entries swapped).
    (let ((swapped (copy-list spent)))
      (rotatef (nth 0 swapped) (nth 1 swapped))
      (signals error (bitcoin-lisp.storage:block-undo-from-spent-utxos block swapped)))
    ;; The reverse direction checks the same two invariants.
    (let ((grouped (bitcoin-lisp.storage:block-undo-from-spent-utxos block spent)))
      (signals error (bitcoin-lisp.storage:spent-utxos-from-block-undo block (rest grouped)))
      (signals error (bitcoin-lisp.storage:spent-utxos-from-block-undo
                      block (list (first grouped) (rest (second grouped))))))))

(test block-undo-is-smaller-than-the-format-it-will-replace
  "The reason Core's format is worth adopting: it stores no outpoint and
compresses the amount and script, against the 32-byte txid + 4-byte index +
uncompressed fields written today. Asserted rather than asserted-in-prose so
a regression in the compressor shows up here too."
  (let* ((block (%bu-test-block '(4 4 4)))
         (spent (%bu-spent-for block))
         (core-bytes (length (bitcoin-lisp.storage:serialize-block-undo
                              (bitcoin-lisp.storage:block-undo-from-spent-utxos block spent))))
         ;; What save-undo-data-to-disk writes for the same data, per entry:
         ;; 32-byte txid + 4-byte index + i64 value + u32 height + u8 coinbase
         ;; + u32 script length + script.
         (ours (+ 4 4 4                       ; magic + version + count
                  (* (length spent) (+ 32 4 8 4 1 4 1)))))
    (is (< core-bytes ours))))
