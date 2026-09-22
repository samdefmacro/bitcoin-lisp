(in-package #:bitcoin-lisp.tools)

;;;; bitcoin-util (Core src/bitcoin-util.cpp): one command, `grind', which
;;;; finds a nonce that satisfies a block header's own nBits. contrib/signet/
;;;; miner calls it for every block it mines (tool_signet_miner.py:78-81,
;;;; `--grind-cmd=bitcoin-util grind'), and tool_utils.py runs the five
;;;; argument-error vectors of test/functional/data/util/bitcoin-util-test.json.

(defun %compact-target (bits)
  "arith_uint256::SetCompact (arith_uint256.cpp:203-224) as (values target
negative overflow)."
  (let* ((size (ash bits -24))
         (word (logand bits #x7fffff)))
    (values (bl.store:bits-to-target bits)
            (and (/= word 0) (/= (logand bits #x800000) 0))
            (and (/= word 0)
                 (or (> size 34)
                     (and (> word #xff) (> size 33))
                     (and (> word #xffff) (> size 32)))))))

(defun %target-bytes (target)
  "TARGET as 32 little-endian bytes, the layout a block hash has."
  (let ((bytes (make-array 32 :element-type '(unsigned-byte 8))))
    (dotimes (i 32 bytes)
      (setf (aref bytes i) (ldb (byte 8 (* 8 i)) target)))))

(defun %hash-meets-target-p (hash target-bytes)
  "UintToArith256(hash) <= target, both 32 little-endian bytes: compared from
the most significant byte down, so no bignum is built per nonce."
  (loop for i from 31 downto 0
        for h = (aref hash i)
        for g = (aref target-bytes i)
        do (cond ((< h g) (return t))
                 ((> h g) (return nil)))
        finally (return t)))

(defun %grind-task (header target offset step found)
  "Core grind_task (bitcoin-util.cpp:88-110): try nonces OFFSET, OFFSET+STEP,
... below Core's `finish', and publish the first that meets TARGET (32
little-endian bytes) in FOUND
(a one-element vector the tasks share; the first CAS wins). HEADER is this
task's own copy of the 80 bytes."
  (let* ((finish (- #xffffffff step))
         (finish (+ (- finish (mod finish step)) offset)))
    (loop for nonce from offset below finish by step
          until (aref found 0)
          do (setf (aref header 76) (ldb (byte 8 0) nonce)
                   (aref header 77) (ldb (byte 8 8) nonce)
                   (aref header 78) (ldb (byte 8 16) nonce)
                   (aref header 79) (ldb (byte 8 24) nonce))
             (when (%hash-meets-target-p (bl.crypto:hash256 header) target)
               (sb-ext:compare-and-swap (svref found 0) nil nonce)
               (return)))))

(defun %grind-thread-count ()
  "Core's max(1, hardware_concurrency()): sysconf(_SC_NPROCESSORS_ONLN)."
  (max 1 (or (ignore-errors
              (sb-alien:alien-funcall
               (sb-alien:extern-alien "sysconf" (function sb-alien:long sb-alien:int))
               #+linux 84 #+darwin 58 #-(or linux darwin) 84))
             1)))

(defun %hex-p (text)
  "Core IsHex: non-empty, even length, hex digits only."
  (and (plusp (length text)) (evenp (length text))
       (every (lambda (c) (digit-char-p c 16)) text)))

(defun %grind (args)
  "Core Grind (bitcoin-util.cpp:112-150): (values exit-code text)."
  (unless (= (length args) 1)
    (return-from %grind (values 1 "Must specify block header to grind")))
  ;; DecodeHexBlockHeader (core_io.cpp): hex, then the 80-byte header read
  ;; from the front; trailing bytes are not an error.
  (let* ((hex (first args))
         (bytes (and (%hex-p hex)
                     (bl.crypto:hex-to-bytes hex))))
    (unless (and bytes (>= (length bytes) 80))
      (return-from %grind (values 1 "Could not decode block header")))
    (let* ((header (subseq bytes 0 80))
           (bits (logior (aref header 72) (ash (aref header 73) 8)
                         (ash (aref header 74) 16) (ash (aref header 75) 24)))
           (found (vector nil)))
      (multiple-value-bind (target negative overflow) (%compact-target bits)
        ;; grind_task returns at once for an unusable target, and every
        ;; task doing so is "Could not satisfy difficulty target".
        (unless (or (zerop target) negative overflow)
          (let* ((n (%grind-thread-count))
                 (threads
                   (loop for i below n
                         collect (let ((offset i) (copy (copy-seq header)))
                                   (bordeaux-threads:make-thread
                                    (lambda () (%grind-task copy (%target-bytes target) offset n found))
                                    :name "bitcoin-util grind")))))
            (mapc #'bordeaux-threads:join-thread threads))))
      (let ((nonce (aref found 0)))
        (if nonce
            (progn
              (setf (aref header 76) (ldb (byte 8 0) nonce)
                    (aref header 77) (ldb (byte 8 8) nonce)
                    (aref header 78) (ldb (byte 8 16) nonce)
                    (aref header 79) (ldb (byte 8 24) nonce))
              (values 0 (bl.crypto:bytes-to-hex header)))
            (values 1 "Could not satisfy difficulty target"))))))

(defun run-bitcoin-util (argv &key (out *standard-output*) (err *error-output*))
  "Core bitcoin-util's main (bitcoin-util.cpp:152-195) over ARGV, the
arguments after the program name: write what Core writes to OUT and ERR and
return Core's exit code."
  (multiple-value-bind (args error)
      (parse-tool-args argv :options '("version") :commands '("grind"))
    (unless args
      (format err "Error parsing command line arguments: ~A~%" error)
      (return-from run-bitcoin-util 1))
    ;; AppInitUtil (:44-86): help and -version print the banner and exit.
    (when (or (tool-help-requested-p args) (tool-bool-arg args "version"))
      (write-string (tool-version-banner "bitcoin-util") out)
      (if (tool-bool-arg args "version")
          (write-string (tool-license-info) out)
          (format out "~%The bitcoin-util tool provides bitcoin related ~
functionality that does not rely on the ability to access a running node. ~
Available [commands] are listed below.~%~%~
Usage:  bitcoin-util [options] [command]~%~
or:     bitcoin-util [options] grind <hex-block-header>~%"))
      (when (null argv)
        (format err "Error: too few parameters~%")
        (return-from run-bitcoin-util 1))
      (return-from run-bitcoin-util 0))
    (handler-case (tool-args-network args)
      (error (e)
        (format err "Error: ~A~%" e)
        (return-from run-bitcoin-util 1)))
    (let ((command (tool-args-command args)))
      (unless command
        (format err "Error: must specify a command~%")
        (return-from run-bitcoin-util 1))
      (multiple-value-bind (rc text) (%grind (rest command))
        (when (plusp (length text))
          (format (if (zerop rc) out err) "~A~%" text))
        rc))))
