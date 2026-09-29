(in-package #:bitcoin-lisp.tests)

;;;; Core's structured consume helpers (src/test/fuzz/util.{h,cpp} at the pin),
;;;; over the FuzzedDataProvider port in fuzz.lisp. They are what a target
;;;; uses to build a well-formed object out of fuzz bytes -- a script, a
;;;; transaction, an amount -- and what a CORPUS function uses to generate the
;;;; valid encodings that stand in for qa-assets.

(defun script-builder ()
  "An empty CScript under construction (appended to with the script-<< helpers)."
  (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))

(defun script-bytes (builder)
  (make-array (length builder) :element-type '(unsigned-byte 8)
                               :initial-contents builder))

(defun script-append (builder bytes)
  (loop for b across bytes do (vector-push-extend b builder))
  builder)

(defun script-num-serialize (n)
  "CScriptNum::serialize (script/script.h:350-380): little-endian magnitude,
the sign in the top bit of the last byte, an extra byte when that bit is
already taken; zero is the empty vector."
  (if (zerop n)
      (make-array 0 :element-type '(unsigned-byte 8))
      (let* ((neg (minusp n))
             (bytes (loop for a = (abs n) then (ash a -8)
                          while (plusp a) collect (ldb (byte 8 0) a))))
        (if (logbitp 7 (car (last bytes)))
            (setf bytes (append bytes (list (if neg #x80 0))))
            (when neg
              (setf (car (last bytes)) (logior #x80 (car (last bytes))))))
        (make-array (length bytes) :element-type '(unsigned-byte 8)
                                   :initial-contents bytes))))

(defun script-<<-bytes (builder bytes)
  "CScript::operator<<(std::vector<unsigned char>): a push of BYTES in the
smallest of the four push encodings, never an OP_n (script.h:483-510)."
  (script-append builder (bl.ser:script-push-data bytes)))

(defun script-<<-int64 (builder n)
  "CScript::push_int64 (script.h:433-448): OP_1NEGATE and OP_1..OP_16 for
their values, OP_0 for zero, a CScriptNum push otherwise."
  (cond ((or (= n -1) (<= 1 n 16)) (vector-push-extend (+ n #x50) builder))
        ((zerop n) (vector-push-extend 0 builder))
        (t (script-<<-bytes builder (script-num-serialize n))))
  builder)

(defun script-<<-opcode (builder opcode)
  (vector-push-extend opcode builder)
  builder)

(defun consume-opcode-type (fdp)
  "Core ConsumeOpcodeType: 0..MAX_OPCODE (OP_NOP10, script.h:216)."
  (consume-integral-in-range fdp 0 #xb9 32))

(defun consume-money (fdp &optional (max bl.val:+max-money+))
  "Core ConsumeMoney: an amount in [0, MAX]."
  (consume-integral-in-range fdp 0 max))

(defun consume-uint256 (fdp)
  "Core ConsumeUInt256: 32 bytes, or zero when fewer remain."
  (let ((v (consume-bytes fdp 32)))
    (if (= (length v) 32) v (make-array 32 :element-type '(unsigned-byte 8)
                                           :initial-element 0))))

(defun consume-uint160 (fdp)
  (let ((v (consume-bytes fdp 20)))
    (if (= (length v) 20) v (make-array 20 :element-type '(unsigned-byte 8)
                                           :initial-element 0))))

(defun consume-sequence (fdp)
  "Core ConsumeSequence: one of the three meaningful nSequence values, or any."
  (if (consume-bool fdp)
      (pick-value-in-array fdp '(#xffffffff #xfffffffe #xfffffffd))
      (consume-integral fdp :u32)))

(defun construct-pubkey-bytes (fdp buffer compressed)
  "Core ConstructPubKeyBytes (test/fuzz/util.cpp:16-28): the first 33 or 65
bytes of BUFFER with a key-type byte in front."
  (let ((pk (subseq buffer 0 (if compressed 33 65))))
    (setf (aref pk 0) (if compressed
                          (pick-value-in-array fdp '(#x02 #x03))
                          (pick-value-in-array fdp '(#x04 #x06 #x07))))
    pk))

(defun consume-script (fdp &key maybe-p2wsh)
  "Core ConsumeScript (test/fuzz/util.cpp:98-155): a loop of raw inserts,
pushes, multisig templates, integers, opcodes and script numbers drawn from a
128-byte scratch buffer the input can rewrite -- then, with MAYBE-P2WSH, maybe
the P2WSH of the result."
  (let ((script (script-builder))
        (buffer (make-array 128 :element-type '(unsigned-byte 8)
                                :initial-element (char-code #\a))))
    (loop while (consume-bool fdp)
          do (call-one-of fdp
               (script-append script
                              (subseq buffer 0 (consume-integral-in-range fdp 0 128 32)))
               (script-<<-bytes script
                                (subseq buffer 0 (consume-integral-in-range fdp 0 128 32)))
               (progn
                 (script-<<-int64 script (consume-integral-in-range fdp 0 22))
                 (let ((num-data (consume-integral-in-range fdp 1 22 32)))
                   (loop while (plusp num-data)
                         do (decf num-data)
                            (let ((pk (construct-pubkey-bytes fdp buffer (consume-bool fdp))))
                              (when (consume-bool fdp)
                                (setf (aref pk (1- (length pk))) num-data))
                              (script-<<-bytes script pk))))
                 (script-<<-int64 script (consume-integral-in-range fdp 0 22)))
               (let ((v (consume-random-length-byte-vector fdp 128)))
                 (replace buffer v))
               (script-<<-int64 script (consume-integral fdp :i64))
               (script-<<-opcode script (consume-opcode-type fdp))
               (script-<<-bytes script (script-num-serialize (consume-integral fdp :i64)))))
    (let ((bytes (script-bytes script)))
      (if (and maybe-p2wsh (consume-bool fdp))
          (p2wsh-script (bl.crypto:sha256 bytes))
          bytes))))

(defun p2wsh-script (hash32)
  (let ((s (script-builder)))
    (script-<<-opcode s 0)
    (script-<<-bytes s hash32)
    (script-bytes s)))

(defparameter +p2wsh-op-true+
  (p2wsh-script (bl.crypto:sha256 (make-array 1 :element-type '(unsigned-byte 8)
                                                :initial-element #x51)))
  "Core P2WSH_OP_TRUE (test/util/script.h): the P2WSH of the one-byte script OP_TRUE.")

(defun consume-script-witness (fdp &optional (max-stack-elem-size 32))
  "Core ConsumeScriptWitness: up to MAX-STACK-ELEM-SIZE random-length items."
  (loop repeat (consume-integral-in-range fdp 0 max-stack-elem-size)
        collect (consume-random-length-byte-vector fdp)))

(defun %u32->i32 (v)
  (if (logbitp 31 v) (- v (ash 1 32)) v))

(defun consume-transaction (fdp &key prevout-txids (max-num-in 10) (max-num-out 10))
  "Core ConsumeTransaction (test/fuzz/util.cpp:47-86), as a BL.SER:TRANSACTION.
Core's nVersion is a uint32; the struct keeps the same 32 bits signed."
  (let* ((p2wsh-op-true (consume-bool fdp))
         (version (if (consume-bool fdp) 2 (%u32->i32 (consume-integral fdp :u32))))
         (lock-time (consume-integral fdp :u32))
         (num-in (consume-integral-in-range fdp 0 max-num-in 32))
         (num-out (consume-integral-in-range fdp 0 max-num-out 32))
         (inputs '()) (witness '()) (outputs '()))
    (dotimes (i num-in)
      (declare (ignorable i))
      (let* ((txid (if prevout-txids
                       (pick-value-in-array fdp prevout-txids)
                       (consume-uint256 fdp)))
             (index (consume-integral-in-range fdp 0 max-num-out 32))
             (sequence (consume-sequence fdp))
             (script-sig (if p2wsh-op-true
                             (make-array 0 :element-type '(unsigned-byte 8))
                             (consume-script fdp)))
             (stack (if p2wsh-op-true
                        (list (make-array 1 :element-type '(unsigned-byte 8)
                                            :initial-element #x51))
                        (consume-script-witness fdp))))
        (push (bl.ser:make-tx-in :previous-output (bl.ser:make-outpoint :hash txid :index index)
                                 :script-sig script-sig :sequence sequence)
              inputs)
        (push stack witness)))
    (dotimes (i num-out)
      (declare (ignorable i))
      (let ((amount (consume-integral-in-range fdp -10 (+ (* 50 100000000) 10)))
            (script-pubkey (if p2wsh-op-true +p2wsh-op-true+
                               (consume-script fdp :maybe-p2wsh t))))
        (push (bl.ser:make-tx-out :value amount :script-pubkey script-pubkey) outputs)))
    (bl.ser:make-transaction
     :version version :lock-time lock-time
     :inputs (coerce (nreverse inputs) 'simple-vector)
     :outputs (coerce (nreverse outputs) 'simple-vector)
     :witness (let ((w (coerce (nreverse witness) 'simple-vector)))
                (when (some #'identity w) w)))))

(defun consume-uint128 (fdp)
  "Sixteen bytes (an IPv6 address), zero-filled when fewer remain."
  (let ((v (consume-bytes fdp 16))
        (out (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace out v)))

(defun fdp-random-length-bytes (bytes)
  "The bytes a FuzzedDataProvider's ConsumeRandomLengthString reads back as
BYTES: every backslash doubled, then a backslash and a non-backslash byte to
end the string. How a CORPUS function writes a value for a target that
consumes it with CONSUME-RANDOM-LENGTH-BYTE-VECTOR (or CONSUME-DESERIALIZABLE)."
  (let ((out '()))
    (loop for b across bytes
          do (push b out)
             (when (= b 92) (push 92 out)))
    (push 92 out)
    (push 0 out)
    (make-array (length out) :element-type '(unsigned-byte 8)
                             :initial-contents (nreverse out))))
