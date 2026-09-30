(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/validation_load_mempool.cpp at the pin: LoadMempool
;;;; over a mempool.dat whose every byte is the fuzzer's (FuzzedFileProvider),
;;;; then DumpMempool. Ours is LOAD-MEMPOOL-FROM-DISK -- the start-up load,
;;;; every entry through the acceptance path -- on the regtest node fixture of
;;;; the process_message targets, then SAVE-MEMPOOL-FILE.
;;;;
;;;; Core asserts only that both return. Beside that: whatever was loaded
;;;; leaves the mempool consistent (every transaction spends coins that exist
;;;; and is recorded as their spender), and the dump reads back as exactly the
;;;; mempool's transactions.

(def-suite :fuzz-validation-load-mempool-tests :in :bitcoin-lisp-tests
  :description "Core fuzz validation_load_mempool.cpp over our mempool.dat load and dump")

(in-suite :fuzz-validation-load-mempool-tests)

(defun %fuzz-mempool-dat (fdp p2p)
  "A mempool.dat: one draw in four raw bytes; otherwise Core's format (version 1,
or 2 with a key) holding transactions that spend the node's coins, entry times,
fee deltas, residual deltas and an unbroadcast set -- cut short or with a byte
changed now and then."
  (if (zerop (consume-integral-in-range fdp 0 3))
      (consume-remaining-bytes fdp)
      (let* ((v1 (consume-bool fdp))
             (key (consume-bytes fdp 8))
             (key (if (= (length key) 8) key (make-array 8 :element-type '(unsigned-byte 8) :initial-element 0)))
             (txs (loop repeat (consume-integral-in-range fdp 0 5) collect (%fuzz-spend fdp p2p)))
             (payload (coerce
                       (flexi-streams:with-output-to-sequence (s :element-type '(unsigned-byte 8))
                        (bl.ser:write-uint64-le s (length txs))
                        (dolist (tx txs)
                          (write-sequence (bl.ser:transaction-wire-bytes tx) s)
                          (bl.ser:write-uint64-le s (+ 1610000000 (consume-integral-in-range fdp -2000000 1000)))
                          (bl.ser:write-uint64-le s (ldb (byte 64 0) (consume-integral-in-range fdp -1000 1000))))
                        (let ((deltas (consume-integral-in-range fdp 0 2)))
                          (bl.ser:write-compact-size s deltas)
                          (dotimes (i deltas)
                            (write-sequence (%fuzz-known-hash fdp p2p) s)
                            (bl.ser:write-uint64-le s (ldb (byte 64 0) (consume-integral-in-range fdp -1000 1000)))))
                        (let ((unbroadcast (if (and txs (consume-bool fdp)) (list (bl.ser:transaction-hash (first txs))) '())))
                          (bl.ser:write-compact-size s (length unbroadcast))
                          (dolist (id unbroadcast) (write-sequence id s))))
                       '(simple-array (unsigned-byte 8) (*))))
             (file (coerce
                    (flexi-streams:with-output-to-sequence (s :element-type '(unsigned-byte 8))
                     (bl.ser:write-uint64-le s (if v1 1 2))
                     (unless v1
                       (bl.ser:write-compact-size s 8)
                       (write-sequence key s)
                       (bl.store:obfuscate! payload key :key-offset 17))
                     (write-sequence payload s))
                    '(simple-array (unsigned-byte 8) (*)))))
        (case (consume-integral-in-range fdp 0 7)
          (0 (subseq file 0 (consume-integral-in-range fdp 0 (length file))))
          (1 (let ((i (consume-integral-in-range fdp 0 (max 0 (1- (length file))))))
               (when (plusp (length file))
                 (setf (aref file i) (logxor (aref file i) (consume-integral-in-range fdp 1 255))))
               file))
          (t file)))))

(define-fuzz-target validation-load-mempool
    (buffer :core "validation_load_mempool.cpp:36-62" :iterations 40 :max-len 1200)
  "A mempool.dat of any bytes -- or a well-formed one, cut short or damaged --
loads without a crash; the mempool it leaves is consistent; and the dump that
follows reads back as exactly the mempool's transactions."
  (let ((fdp (make-fuzzed-data-provider buffer)))
    (with-fuzz-p2p-node (p2p)
      (with-temp-directory (dir "fuzz-load-mempool")
        (let ((path (merge-pathnames "mempool.dat" dir))
              (node (fp-node p2p)))
          (with-open-file (out path :direction :output :element-type '(unsigned-byte 8))
            (write-sequence (%fuzz-mempool-dat fdp p2p) out))
          (bl:load-mempool-from-disk node path)
          (%check-p2p-invariants p2p "the load")
          (let* ((mempool (bl:node-mempool node))
                 (saved (merge-pathnames "saved.dat" dir))
                 (count (bl.mp:save-mempool-file mempool saved))
                 (in-pool (let (l) (bl.mp:mempool-for-each mempool (lambda (k e) (declare (ignore e)) (push k l))) l)))
            (fuzz-assert (eql count (length in-pool)) "the dump wrote ~S of ~D entries" count (length in-pool))
            (multiple-value-bind (entries residual ok) (bl.mp:read-mempool-file saved)
              (declare (ignore residual))
              (fuzz-assert ok "the dump does not read back")
              (fuzz-assert (null (set-exclusive-or (mapcar (lambda (e) (bl.ser:transaction-hash (first e))) entries)
                                                   (fuzz-sabotage in-pool) :test #'equalp))
                           "the dump reads back ~D transactions for a mempool of ~D"
                           (length entries) (length in-pool)))))))))
