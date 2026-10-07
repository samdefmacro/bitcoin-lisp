(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/integer.cpp at the pin: a grab bag of the integer
;;;; helpers over random values. The ones with a counterpart here, with
;;;; Core's assertions: amount compression round-trips every amount up to
;;;; MAX_MONEY and stays within the compression of MAX_MONEY - 1
;;;; (compressor.cpp); ParseMoney reads FormatMoney's text back
;;;; (util/moneystr.cpp); GetSizeOfCompactSize is the size WriteCompactSize
;;;; writes; the fixed-width integer codecs round-trip. And GetCompact
;;;; (arith_uint256.cpp:184-207), which Core only calls, is held to its own
;;;; definition restated here, and SetCompact of it to the target truncated
;;;; to its mantissa. The C++-only rest -- memusage, timeval conversion,
;;;; CScriptNum's operators, char classification, ServiceFlags helpers -- has
;;;; no counterpart.

(def-suite :fuzz-integer-tests :in :bitcoin-lisp-tests
  :description "Core fuzz integer.cpp")

(in-suite :fuzz-integer-tests)

(defun %core-get-compact (target)
  "arith_uint256::GetCompact(false) (arith_uint256.cpp:184-207)."
  (let* ((size (ceiling (integer-length target) 8))
         (compact (if (<= size 3)
                      (ldb (byte 64 0) (ash target (* 8 (- 3 size))))
                      (ldb (byte 64 0) (ash target (- (* 8 (- size 3))))))))
    (when (logtest compact #x00800000)
      (setf compact (ash compact -8))
      (incf size))
    (logior compact (ash size 24))))

(define-fuzz-target integer
    (buffer :core "integer.cpp:51-262" :iterations 6000 :max-len 120)
  "Amount compression round-trips every amount, FormatMoney's text parses
back, the CompactSize size is the size written, the fixed-width codecs
round-trip, and nBits encodes a target as GetCompact does and decodes to it
truncated to the mantissa."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (u256 (consume-uint256 fdp))
         (u64 (consume-integral fdp :u64))
         (i64 (consume-integral fdp :i64))
         (target (bl.crypto:bytes-to-le-integer u256)))
    (if (<= u64 bl.val:+max-money+)
        (let ((compressed (bl.ser:compress-amount u64)))
          (fuzz-assert (= (fuzz-sabotage (bl.ser:decompress-amount compressed)) u64)
                       "~D compresses to ~D, which decompresses elsewhere" u64 compressed)
          (fuzz-assert (<= compressed (bl.ser:compress-amount (1- bl.val:+max-money+)))))
        (bl.ser:compress-amount u64))
    (bl.ser:decompress-amount u64)
    (let ((parsed (bl.cfg:conf-parse-money (bl.bytes:format-money i64))))
      (fuzz-assert (if (<= 0 i64 bl.val:+max-money+) (eql parsed i64) (null parsed))
                   "FormatMoney ~D reads back as ~S" i64 parsed))
    (fuzz-assert (= (bl.ser:compact-size-length u64) (length (%ser #'bl.ser:bb-write-varint u64))))
    (dolist (spec (list (list u64 #'bl.ser:bb-write-u64-le #'bl.ser:br-read-u64-le)
                        (list i64 #'bl.ser:bb-write-i64-le #'bl.ser:br-read-i64-le)
                        (list (ldb (byte 32 0) u64) #'bl.ser:bb-write-u32-le #'bl.ser:br-read-u32-le)
                        (list (- (ldb (byte 32 0) u64) (ash 1 31)) #'bl.ser:bb-write-i32-le #'bl.ser:br-read-i32-le)
                        (list (ldb (byte 16 0) u64) #'bl.ser:bb-write-u16-le #'bl.ser:br-read-u16-le)
                        (list (ldb (byte 8 0) u64) #'bl.ser:bb-write-u8 #'bl.ser:br-read-u8)))
      (destructuring-bind (value writer reader) spec
        (let ((br (bl.ser:make-byte-reader-from (%ser writer value))))
          (fuzz-assert (and (eql (funcall reader br) value) (bl.ser:br-eof-p br))
                       "~D does not round-trip its codec" value))))
    (let* ((bits (bl.store:target-to-bits target))
           (size (ceiling (integer-length target) 8))
           (shift (max 0 (* 8 (- size 3))))
           (shift (if (>= (ash target (- shift)) (ash 1 23)) (+ shift 8) shift)))
      (fuzz-assert (= (fuzz-sabotage bits) (%core-get-compact target))
                   "target ~X encodes as ~8,'0X, GetCompact ~8,'0X" target bits (%core-get-compact target))
      (fuzz-assert (= (bl.store:bits-to-target bits) (ash (ash target (- shift)) shift))
                   "~8,'0X decodes to ~X, not ~X truncated" bits (bl.store:bits-to-target bits) target))))
