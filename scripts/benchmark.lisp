;;;; Validation hot-path microbenchmarks (track C item 2, the "measure first" half).
;;;;
;;;; Run in the project container:
;;;;   scripts/benchmark.sh
;;;;
;;;; These are MICRObenchmarks of the validation and serialization hot paths
;;;; (track C, then the byte-I/O consolidation of the 2026-08-27 cleanup). They are not the
;;;; whole of item 2 — the plan's benchmark of record is a -reindex-chainstate
;;;; over testnet4 against Core on the same box, which needs that machine's
;;;; data and is driven by scripts/benchmark-reindex.sh. What these give is the
;;;; part that is measurable anywhere, deterministically, in seconds: whether a
;;;; cache that was added for speed is actually faster, and by how much.

(in-package #:cl-user)

(defmacro %bench (name iterations &body body)
  "Time ITERATIONS of BODY and report ns/op. Returns the ns/op as a double."
  `(let ((start (get-internal-real-time)))
     (dotimes (%i ,iterations) ,@body)
     (let* ((elapsed (/ (- (get-internal-real-time) start)
                        (float internal-time-units-per-second 1d0)))
            (per-op (if (zerop ,iterations) 0d0
                        (/ (* elapsed 1d9) ,iterations))))
       (format t "~&  ~34A ~10,1F ns/op  (~D iterations, ~,3Fs)~%"
               ,name per-op ,iterations elapsed)
       (finish-output)
       per-op)))

(defun %bytes (n fill)
  (make-array n :element-type '(unsigned-byte 8) :initial-element fill))

(defun %bench-fixture ()
  "(values sighash der-sig pubkey) — one real secp256k1 signature."
  (let* ((privkey (%bytes 32 7))
         (pubkey (bitcoin-lisp.crypto:derive-public-key privkey))
         (sighash (%bytes 32 9)))
    (values sighash (bitcoin-lisp.crypto:sign-ecdsa privkey sighash) pubkey)))

(defun bench-signature-cache ()
  (multiple-value-bind (sighash der pubkey) (%bench-fixture)
    (format t "~&Signature verification (secp256k1 + the #453 cache)~%")
    (let* ((miss (let ((bitcoin-lisp.coalton.interop::*signature-cache-enabled* nil))
                   (%bench "verify, cache disabled" 2000
                     (bitcoin-lisp.coalton.interop::cached-verify-ecdsa
                      sighash der pubkey :strict t :low-s t))))
           (hit (progn
                  (bitcoin-lisp.coalton.interop::clear-signature-cache)
                  (bitcoin-lisp.coalton.interop::cached-verify-ecdsa
                   sighash der pubkey :strict t :low-s t)
                  (%bench "verify, cache hit" 20000
                    (bitcoin-lisp.coalton.interop::cached-verify-ecdsa
                     sighash der pubkey :strict t :low-s t))))
           (keying (%bench "cache key construction" 20000
                     (bitcoin-lisp.coalton.interop::make-sig-cache-key
                      #x45 sighash der pubkey))))
      (format t "~&  => a hit is ~,1Fx cheaper than a verify, and ~D% of ~
that hit is key construction~%"
              (if (plusp hit) (/ miss hit) 0d0)
              (if (plusp hit) (round (* 100 (/ keying hit))) 0)))))

(defun bench-script-execution-cache ()
  (format t "~&~%Script-execution cache (#454)~%")
  (let ((wtxid (%bytes 32 3)))
    (let ((keying (%bench "cache key construction" 20000
                    (bitcoin-lisp.coalton.interop::make-script-execution-cache-key
                     wtxid "P2SH,WITNESS,TAPROOT")))
          (lookup (let ((key (bitcoin-lisp.coalton.interop::make-script-execution-cache-key
                              wtxid "P2SH,WITNESS,TAPROOT")))
                    (bitcoin-lisp.coalton.interop::script-execution-cache-store key)
                    (%bench "hit (key + lookup)" 20000
                      (bitcoin-lisp.coalton.interop::script-execution-cached-p
                       (bitcoin-lisp.coalton.interop::make-script-execution-cache-key
                        wtxid "P2SH,WITNESS,TAPROOT"))))))
      (format t "~&  => the whole-transaction short-circuit costs ~,1F ns,~%~
                 ~5T i.e. it pays for itself against a single signature verify~%"
              lookup)
      (values keying lookup))))

(defun bench-sha256 ()
  (format t "~&~%Primitives~%")
  (let ((buf (%bytes 1024 42)))
    (%bench "sha256, 1 KiB" 20000 (bitcoin-lisp.crypto:sha256 buf))
    (%bench "hash256 (double SHA), 1 KiB" 20000 (bitcoin-lisp.crypto:hash256 buf))))

(defun %bench-tx-fixture ()
  "A 10-in / 10-out transaction with P2PKH-shaped scripts: big enough that
serialization, not fixed overhead, dominates."
  (flet ((bytes (n fill) (%bytes n fill)))
    (bitcoin-lisp.serialization:make-transaction
     :version 2
     :inputs (coerce (loop for i below 10
                           collect (bitcoin-lisp.serialization:make-tx-in
                                    :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                      :hash (bytes 32 (1+ i)) :index i)
                                    :script-sig (bytes 107 #x48)
                                    :sequence #xFFFFFFFD))
                     'simple-vector)
     :outputs (coerce (loop for i below 10
                            collect (bitcoin-lisp.serialization:make-tx-out
                                     :value (* 100000 (1+ i))
                                     :script-pubkey (bytes 25 #x76)))
                      'simple-vector)
     :lock-time 0)))

(defun bench-serialization ()
  "The byte-buf / byte-reader paths (docs/refactoring-plan-2026-08-27.md P1):
serialize, parse, legacy sighash, and the raw buffer primitives underneath."
  (format t "~&~%Serialization (byte-buf / byte-reader)~%")
  (let* ((tx (%bench-tx-fixture))
         (raw (bitcoin-lisp.serialization:serialize-transaction tx))
         ;; the scriptCode is a real output script of the fixture
         (subscript (bitcoin-lisp.serialization:tx-out-script-pubkey
                     (aref (bitcoin-lisp.serialization:transaction-outputs tx) 0))))
    (format t "~&  (fixture tx is ~D bytes)~%" (length raw))
    (%bench "serialize-tx, 10-in/10-out" 200000
      (bitcoin-lisp.serialization:serialize-transaction tx))
    (%bench "br-read-transaction, same bytes" 200000
      (bitcoin-lisp.serialization:br-read-transaction
       (bitcoin-lisp.serialization:make-byte-reader-from raw)))
    (%bench "legacy sighash, input 0" 200000
      (bitcoin-lisp.coalton.interop:compute-legacy-sighash tx 0 subscript 1))
    (%bench "byte-buf: 256 x u32 + finish" 200000
      (let ((b (bitcoin-lisp.serialization:make-byte-buf)))
        (dotimes (i 256) (bitcoin-lisp.serialization:bb-write-u32-le b i))
        (bitcoin-lisp.serialization:bb-finish b)))))

(defun run-benchmarks ()
  (format t "~&bitcoin-lisp validation microbenchmarks~%~
             SBCL ~A on ~A~%~
             GET-INTERNAL-REAL-TIME reports ~D units/second, but observed ~
granularity here is~%~
             coarser than that, so 20k-iteration figures move by tens of ns ~
between runs.~%~
             Treat every number below as an ORDER OF MAGNITUDE, not a ~
measurement to three digits.~%~%"
          (lisp-implementation-version) (machine-type)
          internal-time-units-per-second)
  (bench-signature-cache)
  (bench-script-execution-cache)
  (bench-sha256)
  (bench-serialization)
  (format t "~&~%Note: these are microbenchmarks of the validation and serialization hot paths.~%~
             The benchmark of RECORD for IBD is scripts/benchmark-reindex.sh,~%~
             which needs a real chain and, for the Core comparison, the test~%~
             server. Nothing here speaks to end-to-end IBD time.~%")
  (finish-output))
