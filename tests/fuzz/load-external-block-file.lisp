(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/load_external_block_file.cpp at the pin:
;;;; LoadExternalBlockFile over a file whose every byte is the fuzzer's.
;;;; Ours is the -loadblock reader, MAP-EXTERNAL-BLOCK-FILE, feeding each record
;;;; it finds through the block deserializer and ACTIVATE-SUBMITTED-BLOCK --
;;;; the three steps of the import loop (%IMPORT-EXTERNAL-BLOCK-FILES) -- on the
;;;; regtest node fixture of the process_message targets.
;;;;
;;;; Beyond Core's no-crash: the records the reader hands over are exactly the
;;;; ones Core's scan (validation.cpp:4988-5042, restated in
;;;; %EXTERNAL-FILE-REFERENCE-RECORDS) reads a whole record for, in the same
;;;; order, and the chain the import leaves is consistent.

(def-suite :fuzz-load-external-block-file-tests :in :bitcoin-lisp-tests
  :description "Core fuzz load_external_block_file.cpp over our -loadblock reader")

(in-suite :fuzz-load-external-block-file-tests)

(defun %external-file-reference-records (bytes magic)
  "The (start . size) of every record Core's LoadExternalBlockFile reads whole
from BYTES: hunt the first magic byte from the rewind point, match all four,
read a size in [80, 4000000]; a header that cannot be read rewinds to one
past the magic byte, a record whose body runs past the end ends the scan
(validation.cpp:5005-5042)."
  (let ((rewind 0) (n (length bytes)) (out '()))
    (loop
      (when (>= rewind n) (return))
      (let ((p (position (aref magic 0) bytes :start rewind)))
        (unless p (return))
        (setf rewind (1+ p))
        (unless (<= (+ p 8) n) (return))   ; the magic or the size cannot be read
        (when (equalp (subseq bytes p (+ p 4)) magic)
          (let ((size (logior (aref bytes (+ p 4)) (ash (aref bytes (+ p 5)) 8)
                              (ash (aref bytes (+ p 6)) 16) (ash (aref bytes (+ p 7)) 24)))
                (start (+ p 8)))
            (when (<= 80 size 4000000)
              (cond ((< (- n start) 80))              ; the header cannot be read
                    ((> (+ start size) n) (return))    ; SkipTo past the end
                    (t (push (cons start size) out)
                       (setf rewind (+ start size)))))))))
    (nreverse out)))

(defun %fuzz-external-block-file (fdp p2p magic)
  "A file of records: mined blocks on the node's tip, magic with a size that
is no record, junk, and now and then a record cut short."
  (let ((parts '()))
    (loop repeat (consume-integral-in-range fdp 0 4)
          do (push (call-one-of fdp
                     (let ((block (bl.ser:serialize (%fuzz-block fdp p2p))))
                       (concatenate '(simple-array (unsigned-byte 8) (*))
                                    magic (%le32 (length block)) block))
                     (concatenate '(simple-array (unsigned-byte 8) (*))
                                  magic (%le32 (consume-integral fdp :u32))
                                  (consume-random-length-byte-vector fdp 100))
                     (consume-random-length-byte-vector fdp 100)
                     (concatenate '(simple-array (unsigned-byte 8) (*))
                                  magic (%le32 (consume-integral-in-range fdp 80 200))
                                  (consume-random-length-byte-vector fdp 150)))
                   parts))
    (let ((file (apply #'concatenate '(simple-array (unsigned-byte 8) (*)) (nreverse parts))))
      (if (and (plusp (length file)) (zerop (consume-integral-in-range fdp 0 3)))
          (subseq file 0 (consume-integral-in-range fdp 0 (length file)))
          file))))

(defun %le32 (n)
  (let ((v (make-array 4 :element-type '(unsigned-byte 8))))
    (dotimes (i 4 v) (setf (aref v i) (ldb (byte 8 (* 8 i)) n)))))

(define-fuzz-target load-external-block-file
    (buffer :core "load_external_block_file.cpp:26-46" :iterations 40 :max-len 800)
  "Whatever bytes a -loadblock file holds, the reader hands over exactly the
records Core's scan reads, in order; each goes through the block import
without a crash; and the chain it leaves is consistent."
  (let ((fdp (make-fuzzed-data-provider buffer)))
    (with-fuzz-p2p-node (p2p)
      (with-temp-directory (dir "fuzz-loadblock")
        (let* ((magic (bl.chain:network-magic bl:*network*))
               (bytes (%fuzz-external-block-file fdp p2p magic))
               (path (merge-pathnames "bootstrap.dat" dir))
               (seen '()))
          (with-open-file (out path :direction :output :element-type '(unsigned-byte 8))
            (write-sequence bytes out))
          (bl.store:map-external-block-file
           path
           (lambda (record)
             (push record seen)
             (let ((block (handler-case (bl.ser:br-read-bitcoin-block (bl.ser:make-byte-reader-from record))
                            (bl.err:serialization-error () nil))))
               (when block
                 (bl.rpc:activate-submitted-block (fp-node p2p) block)))))
          (let ((want (mapcar (lambda (r) (subseq bytes (car r) (+ (car r) (cdr r))))
                              (%external-file-reference-records bytes magic))))
            (fuzz-assert (equalp (fuzz-sabotage (reverse seen)) want)
                         "the reader handed over ~D record~:P (~{~D~^ ~} bytes) where Core reads ~D (~{~D~^ ~})"
                         (length seen) (mapcar #'length (reverse seen))
                         (length want) (mapcar #'length want)))
          (%check-p2p-invariants p2p "the import"))))))
