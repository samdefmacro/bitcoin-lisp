(in-package #:bitcoin-lisp.tests)

;;;; The harness Core's fuzz targets run in, ported: src/test/fuzz/fuzz.{h,cpp}
;;;; and FuzzedDataProvider.h at the pin (d3056bc149).
;;;;
;;;; A Core fuzz target is a function of one byte buffer that ASSERTS invariants;
;;;; libFuzzer feeds it buffers and reports any buffer that makes an assertion
;;;; fail or the process crash. We have no coverage-guided engine and no
;;;; qa-assets corpus, so the buffers come from a SEEDED generator instead:
;;;; raw random bytes, plus -- for targets that name a CORPUS function --
;;;; valid encodings built by the target's own consume helpers and then
;;;; mutated the way libFuzzer's byte mutators mutate a corpus entry. What
;;;; ports unchanged is the part that matters: each target's body and its
;;;; assertions, which read like the C++ because the consume API below has the
;;;; FuzzedDataProvider's shape and semantics (integral values are taken from
;;;; the END of the buffer, byte strings from the front, and every consume
;;;; answers something once the buffer runs dry).
;;;;
;;;; Three outcomes per buffer, as in Core:
;;;;   - the body returns: the buffer was fine;
;;;;   - the body REJECTS the buffer through a declared condition -- Core's
;;;;     `catch (const std::ios_base::failure&) { return; }', here
;;;;     FUZZ-DESERIALIZE catching BL.ERR:SERIALIZATION-ERROR -- and returns;
;;;;   - anything else is a FAILURE: a FUZZ-ASSERT that does not hold (Core's
;;;;     assert()), or any other condition escaping the body (Core's crash:
;;;;     an exception no one declared, a stack exhaustion).
;;;;
;;;; Every target runs twice. Once for real: no failures, and at least
;;;; MIN-REACHED assertions actually executed, so a generator that never gets
;;;; past the parser cannot pass vacuously. And once SABOTAGED: FUZZ-SABOTAGE
;;;; perturbs the value each target hands its assertion (an inverted byte, an
;;;; off-by-one integer, a negated verdict) -- or, for a target whose only
;;;; property is that parsing never crashes, FUZZ-DESERIALIZE turns a
;;;; successful parse into an undeclared condition; that run must FAIL, which
;;;; proves the assertion is reached with live data and can go red. A target
;;;; whose control stays green is a target that tests nothing.
;;;;
;;;; A failure report names the target, the seed, the iteration and the buffer
;;;; in hex; (REPLAY-FUZZ-TARGET 'NAME "hex") re-runs exactly that buffer.

;;; --- The byte source ----------------------------------------------------

(defvar *fuzz-rng-state* 1
  "xorshift64* state. CL:RANDOM is not specified to produce the same stream on
every host; a failing buffer that cannot be regenerated is a rumour.")

(defun fuzz-rng-seed (n)
  (setf *fuzz-rng-state* (logior 1 (ldb (byte 64 0) (* (1+ n) 6364136223846793005)))))

(defun fuzz-rng-u64 ()
  (let ((x *fuzz-rng-state*))
    (setf x (ldb (byte 64 0) (logxor x (ash x 13))))
    (setf x (logxor x (ash x -7)))
    (setf x (ldb (byte 64 0) (logxor x (ash x 17))))
    (setf *fuzz-rng-state* x)
    (ldb (byte 64 0) (* x 2685821657736338717))))

(defun fuzz-rng-below (n)
  (if (<= n 1) 0 (mod (fuzz-rng-u64) n)))

(defun fuzz-random-bytes (n)
  (let ((out (make-array n :element-type '(unsigned-byte 8))))
    (dotimes (i n out)
      (setf (aref out i) (ldb (byte 8 0) (fuzz-rng-u64))))))

(defun fuzz-name-seed (name)
  "FNV-1a of NAME's characters: a seed per target that does not depend on
SXHASH, whose values an implementation may change between releases."
  (let ((h #xcbf29ce484222325))
    (loop for c across (string name)
          do (setf h (ldb (byte 64 0) (* (logxor h (char-code c)) #x100000001b3))))
    h))

;;; --- FuzzedDataProvider (FuzzedDataProvider.h) --------------------------

(defstruct (fuzzed-data-provider (:constructor %make-fdp (data remaining))
                                 (:conc-name fdp-))
  "Core's FuzzedDataProvider over DATA: byte strings are consumed from the
front (POS advances), integral values from the back (REMAINING shrinks)."
  (data (make-array 0 :element-type '(unsigned-byte 8)) :type (simple-array (unsigned-byte 8) (*)))
  (pos 0 :type fixnum)
  (remaining 0 :type fixnum))

(defun make-fuzzed-data-provider (bytes)
  (let ((data (make-array (length bytes) :element-type '(unsigned-byte 8)
                                         :initial-contents bytes)))
    (%make-fdp data (length data))))

(defun remaining-bytes (fdp)
  (fdp-remaining fdp))

(defun %fdp-advance (fdp n)
  (incf (fdp-pos fdp) n)
  (decf (fdp-remaining fdp) n))

(defun consume-integral-in-range (fdp min max &optional (bits 64))
  "FuzzedDataProvider::ConsumeIntegralInRange<T>(min, max) for a T of BITS
bits: bytes are taken from the END of the remaining data, most significant
first, only as many as RANGE needs, and the value is reduced modulo RANGE+1
unless RANGE is the whole 64-bit span. An exhausted provider yields MIN."
  (when (> min max) (error "consume-integral-in-range: min ~D > max ~D" min max))
  (let ((range (- max min))
        (result 0)
        (offset 0))
    (loop while (and (< offset bits)
                     (plusp (ash range (- offset)))
                     (plusp (fdp-remaining fdp)))
          do (decf (fdp-remaining fdp))
             (setf result (logior (ash result 8)
                                  (aref (fdp-data fdp)
                                        (+ (fdp-pos fdp) (fdp-remaining fdp)))))
             (incf offset 8))
    (unless (= range (1- (ash 1 64)))
      (setf result (mod result (1+ range))))
    (+ min result)))

(defun consume-integral (fdp type)
  "FuzzedDataProvider::ConsumeIntegral<T>() for TYPE one of :u8 :i8 :u16 :i16
:u32 :i32 :u64 :i64 -- the whole range of T."
  (ecase type
    (:u8 (consume-integral-in-range fdp 0 #xff 8))
    (:i8 (consume-integral-in-range fdp -128 127 8))
    (:u16 (consume-integral-in-range fdp 0 #xffff 16))
    (:i16 (consume-integral-in-range fdp -32768 32767 16))
    (:u32 (consume-integral-in-range fdp 0 #xffffffff 32))
    (:i32 (consume-integral-in-range fdp (- (ash 1 31)) (1- (ash 1 31)) 32))
    (:u64 (consume-integral-in-range fdp 0 (1- (ash 1 64)) 64))
    (:i64 (consume-integral-in-range fdp (- (ash 1 63)) (1- (ash 1 63)) 64))))

(defun consume-bool (fdp)
  "FuzzedDataProvider::ConsumeBool: the low bit of one integral byte."
  (logbitp 0 (consume-integral fdp :u8)))

(defun consume-probability (fdp)
  "FuzzedDataProvider::ConsumeProbability<double>: a uint64 over its maximum."
  (/ (coerce (consume-integral fdp :u64) 'double-float)
     (coerce (1- (ash 1 64)) 'double-float)))

(defun consume-bytes (fdp n)
  "FuzzedDataProvider::ConsumeBytes: up to N bytes from the front."
  (let* ((n (min n (fdp-remaining fdp)))
         (out (make-array n :element-type '(unsigned-byte 8))))
    (replace out (fdp-data fdp) :start2 (fdp-pos fdp))
    (%fdp-advance fdp n)
    out))

(defun consume-remaining-bytes (fdp)
  (consume-bytes fdp (fdp-remaining fdp)))

(defun consume-random-length-byte-vector (fdp &optional max-length)
  "FuzzedDataProvider::ConsumeRandomLengthString(max_length), as bytes (Core's
ConsumeRandomLengthByteVector): a backslash followed by anything but a
backslash ENDS the string, so a buffer chooses its own lengths; a doubled
backslash is one backslash."
  (let ((max (or max-length (fdp-remaining fdp)))
        (out (make-array 16 :element-type '(unsigned-byte 8)
                            :adjustable t :fill-pointer 0)))
    (loop for i from 0
          while (and (< i max) (plusp (fdp-remaining fdp)))
          do (let ((next (aref (fdp-data fdp) (fdp-pos fdp))))
               (%fdp-advance fdp 1)
               (when (and (= next 92) (plusp (fdp-remaining fdp)))
                 (setf next (aref (fdp-data fdp) (fdp-pos fdp)))
                 (%fdp-advance fdp 1)
                 (unless (= next 92)
                   (loop-finish)))
               (vector-push-extend next out)))
    (make-array (length out) :element-type '(unsigned-byte 8)
                             :initial-contents out)))

(defun consume-random-length-string (fdp &optional max-length)
  "FuzzedDataProvider::ConsumeRandomLengthString: the same bytes as characters
(code points 0-255), so every octet is a character a text parser must face."
  (map 'string #'code-char (consume-random-length-byte-vector fdp max-length)))

(defun pick-value-in-array (fdp sequence)
  "FuzzedDataProvider::PickValueInArray."
  (elt sequence (consume-integral-in-range fdp 0 (1- (length sequence)))))

(defmacro call-one-of (fdp &body alternatives)
  "Core CallOneOf (test/fuzz/util.h): evaluate one of ALTERNATIVES, chosen by a
size_t drawn from FDP."
  (let ((n (length alternatives)))
    `(case (consume-integral-in-range ,fdp 0 ,(1- n))
       ,@(loop for form in alternatives for i from 0
               collect `(,i ,form)))))

(defmacro limited-while ((condition max-iterations) &body body)
  "Core LIMITED_WHILE (test/fuzz/fuzz.h): WHILE, but never more than
MAX-ITERATIONS times."
  (let ((count (gensym "COUNT")))
    `(loop for ,count from 0
           while (and (< ,count ,max-iterations) ,condition)
           do (progn ,@body))))

;;; --- Mutation: libFuzzer's byte mutators, over a generated corpus entry --

(defun fuzz-mutate (bytes)
  "Apply zero to three of libFuzzer's elementary mutations to a copy of BYTES:
change a bit or a byte, insert or erase a byte, truncate, duplicate a slice,
or plant a boundary byte (0, 0x7f, 0x80, 0xfd-0xff -- the CompactSize tags).
Zero mutations is kept on purpose: a VALID encoding is where the round-trip
assertions live."
  (let ((v (coerce bytes 'list)))
    (dotimes (k (fuzz-rng-below 4))
      (declare (ignorable k))
      (let ((n (length v)))
        (setf v
              (case (fuzz-rng-below 7)
                (0 (if (zerop n) v
                       (let ((i (fuzz-rng-below n)))
                         (append (subseq v 0 i)
                                 (list (logxor (nth i v) (ash 1 (fuzz-rng-below 8))))
                                 (nthcdr (1+ i) v)))))
                (1 (if (zerop n) v
                       (let ((i (fuzz-rng-below n)))
                         (append (subseq v 0 i) (list (fuzz-rng-below 256))
                                 (nthcdr (1+ i) v)))))
                (2 (let ((i (fuzz-rng-below (1+ n))))
                     (append (subseq v 0 i) (list (fuzz-rng-below 256))
                             (nthcdr i v))))
                (3 (if (zerop n) v
                       (let ((i (fuzz-rng-below n)))
                         (append (subseq v 0 i) (nthcdr (1+ i) v)))))
                (4 (subseq v 0 (fuzz-rng-below (1+ n))))
                (5 (if (zerop n) v
                       (let* ((i (fuzz-rng-below n))
                              (j (+ i (fuzz-rng-below (min 16 (- n i))))))
                         (append (subseq v 0 j) (subseq v i j) (nthcdr j v)))))
                (t (if (zerop n) v
                       (let ((i (fuzz-rng-below n)))
                         (append (subseq v 0 i)
                                 (list (elt #(0 #x7f #x80 #xfd #xfe #xff)
                                            (fuzz-rng-below 6)))
                                 (nthcdr (1+ i) v)))))))))
    (make-array (length v) :element-type '(unsigned-byte 8) :initial-contents v)))

;;; --- Assertions, rejection and the positive control ---------------------

(define-condition fuzz-invariant-violation (serious-condition)
  ((message :initarg :message :reader fuzz-invariant-violation-message))
  (:report (lambda (c s) (write-string (fuzz-invariant-violation-message c) s)))
  (:documentation "A FUZZ-ASSERT that did not hold: Core's assert() in a fuzz
target. A SERIOUS-CONDITION and not an ERROR, so a HANDLER-CASE for ERROR
inside a target body -- or inside the code under test -- cannot swallow it."))

(defvar *fuzz-checks-reached* 0
  "How many FUZZ-ASSERTs ran in the current target run.")

(defvar *fuzz-sabotage* nil
  "Non-NIL while a target runs as its own positive control. :ASSERT --
FUZZ-SABOTAGE perturbs the values the target's assertions compare. :PARSE --
for a target whose only property is that parsing never crashes,
FUZZ-DESERIALIZE turns a successful parse into an undeclared condition.")

(defmacro fuzz-assert (form &optional control &rest args)
  "Core's assert(FORM) inside a fuzz target. CONTROL and ARGS format the
failure message; without them the message is FORM itself."
  (let ((args (if control args (list (list 'quote form))))
        (control (or control "~S")))
    `(progn
       (incf *fuzz-checks-reached*)
       (unless ,form
         (signal-fuzz-violation
          (format nil "assertion failed: ~A" (format nil ,control ,@args)))))))

(defun signal-fuzz-violation (message)
  (error 'fuzz-invariant-violation :message message))

(defun fuzz-sabotage (value)
  "VALUE, or -- in the positive-control run -- a VALUE that differs from it in
the way a defect would: a byte vector with its first byte inverted (or one
byte where there were none), an integer off by one, a string with a
character appended, a generalized boolean negated, a list with an extra
element."
  (cond ((not (eq *fuzz-sabotage* :assert)) value)
        ((typep value '(vector (unsigned-byte 8)))
         (if (zerop (length value))
             (make-array 1 :element-type '(unsigned-byte 8) :initial-element 0)
             (let ((copy (copy-seq value)))
               (setf (aref copy 0) (logxor #xff (aref copy 0)))
               copy)))
        ((integerp value) (1+ value))
        ((stringp value) (concatenate 'string value "~"))
        ((listp value) (if value (cons :sabotaged value) t))
        (t nil)))

(defun fuzz-reject ()
  "Leave the target body: this buffer is not an input the target is about
(Core's `return' after a caught std::ios_base::failure)."
  (throw 'fuzz-reject nil))

(defmacro fuzz-deserialize (form &key (declared ''bl.err:serialization-error))
  "Evaluate FORM, a deserialization of the fuzz input. A condition of a
DECLARED type (Core's std::ios_base::failure: BL.ERR:SERIALIZATION-ERROR)
rejects the buffer; any other condition escapes and is a crash. In the
positive control of a :PARSE target a SUCCESSFUL parse signals an undeclared
condition, so a target whose parse never succeeds cannot pass its control."
  (let ((c (gensym "C")))
    `(multiple-value-prog1
         (handler-case ,form
           (error (,c)
             (if (typep ,c ,declared) (fuzz-reject) (error ,c))))
       (when (eq *fuzz-sabotage* :parse)
         (error "positive control: an undeclared condition after a successful parse")))))

(defmacro consume-deserializable (fdp reader &key max-length (declared ''bl.err:serialization-error))
  "Core ConsumeDeserializable<T> (test/fuzz/util.h:100-125): READER applied
to a random-length byte vector from FDP, or NIL when it signals a DECLARED
condition. Any other condition escapes as a crash."
  (let ((c (gensym "C")) (bytes (gensym "BYTES")))
    `(let ((,bytes (consume-random-length-byte-vector ,fdp ,max-length)))
       (handler-case (funcall ,reader ,bytes)
         (error (,c)
           (if (typep ,c ,declared) nil (error ,c)))))))

;;; --- Targets --------------------------------------------------------------

(defvar *fuzz-targets* (make-hash-table :test 'eq)
  "Target name -> plist (:function :corpus :iterations :max-len :min-reached :core).")

(defmacro define-fuzz-target (name (buffer &key corpus (iterations 1000) (max-len 256)
                                              min-reached core (control :assert))
                              docstring &body body)
  "Define Core's FUZZ_TARGET(NAME) as a function of BUFFER (a byte vector) and
a fiveam test FUZZ-NAME that runs it ITERATIONS times over seeded buffers of
up to MAX-LEN random bytes -- or, three draws in four when CORPUS (a function
of a FUZZED-DATA-PROVIDER returning a byte vector) is given, a mutated corpus
entry -- and then once more as its own positive control, sabotaged the CONTROL
way (see *FUZZ-SABOTAGE*). CORE is the Core file:line the target ports; the
docstring states the invariant."
  (let* ((fn (intern (format nil "FUZZ-TARGET/~A" (symbol-name name))))
         (test-name (intern (format nil "FUZZ-~A" (symbol-name name))))
         ;; A LAMBDA corpus becomes a named function, so every call it makes
         ;; has a caller in this package (the orphan-export sweep in
         ;; structural-tests tells test callers apart by their names).
         (corpus-fn (when (and (consp corpus) (eq (first corpus) 'lambda))
                      (intern (format nil "FUZZ-CORPUS/~A" (symbol-name name))))))
    `(progn
       ,@(when corpus-fn
           `((defun ,corpus-fn ,@(rest corpus))))
       (defun ,fn (,buffer)
         ,docstring
         (declare (type (simple-array (unsigned-byte 8) (*)) ,buffer)
                  (ignorable ,buffer))
         ,@body)
       (setf (gethash ',name *fuzz-targets*)
             (list :function ',fn :corpus ,(if corpus-fn `',corpus-fn corpus)
                   :iterations ,iterations
                   :max-len ,max-len :core ,core :control ,control
                   :min-reached ,(or min-reached `(max 1 (floor ,iterations 20)))))
       (test ,test-name
         ,(format nil "Core fuzz target ~(~A~) (~A).~%~%~A" name core docstring)
         (check-fuzz-target ',name)))))

(defun %fuzz-buffer (corpus max-len)
  (let ((raw (fuzz-random-bytes (fuzz-rng-below (1+ max-len)))))
    (if (and corpus (plusp (fuzz-rng-below 4)))
        (fuzz-mutate (funcall corpus (make-fuzzed-data-provider raw)))
        raw)))

(defvar *fuzz-iteration-scale* 4
  "Every target runs this many times its own ITERATIONS. 4 keeps the whole
fuzz battery near a minute and a quarter of the cold run; bind it higher for
a longer local campaign -- the seeds stay the same, the buffers extend.")

(defun run-fuzz-target (name &key iterations stop-at-first)
  "Run target NAME over its seeded buffers. Returns a plist: :failures (a list
of (iteration hex message)), :reached (FUZZ-ASSERTs executed), :iterations."
  (destructuring-bind (&key function corpus ((:iterations default-iterations))
                         max-len &allow-other-keys)
      (gethash name *fuzz-targets*)
    (let ((iterations (or iterations (* *fuzz-iteration-scale* default-iterations)))
          (*fuzz-checks-reached* 0)
          (failures '()))
      (fuzz-rng-seed (fuzz-name-seed name))
      (dotimes (i iterations)
        (let* ((buffer (%fuzz-buffer corpus max-len))
               (failure (%fuzz-run-one function buffer)))
          (when failure
            (push (list i (bl.crypto:bytes-to-hex buffer) failure) failures)
            (when stop-at-first (return)))))
      (list :failures (nreverse failures) :reached *fuzz-checks-reached*
            :iterations iterations))))

(defun %fuzz-run-one (function buffer)
  "NIL when FUNCTION accepted or rejected BUFFER; else a string saying why not."
  (catch 'fuzz-reject
    (handler-case (progn (funcall function buffer) nil)
      (fuzz-invariant-violation (c) (princ-to-string c))
      (serious-condition (c)
        (format nil "crash: ~S: ~A" (type-of c)
                (handler-case (princ-to-string c)
                  (error () "<unprintable condition>")))))))

(defun replay-fuzz-target (name hex)
  "Run target NAME on the one buffer HEX (as a failure report prints it).
Returns NIL, or the failure string."
  (%fuzz-run-one (getf (gethash name *fuzz-targets*) :function)
                 (bl.crypto:hex-to-bytes hex)))

(defun check-fuzz-target (name)
  "The fiveam body of FUZZ-NAME: the real run and the positive control."
  (destructuring-bind (&key min-reached core control &allow-other-keys)
      (gethash name *fuzz-targets*)
    (destructuring-bind (&key failures reached iterations)
        (run-fuzz-target name)
      (is (null failures)
          "~(~A~) (~A): ~D of ~D buffers failed; first at iteration ~D: ~A~%  replay: (replay-fuzz-target '~A ~S)"
          name core (length failures) iterations
          (first (first failures)) (third (first failures))
          name (second (first failures)))
      (is (>= reached (* *fuzz-iteration-scale* min-reached))
          "~(~A~): only ~D assertions ran in ~D buffers (want ~D) -- the property is vacuous"
          name reached iterations (* *fuzz-iteration-scale* min-reached)))
    (let ((run (let ((*fuzz-sabotage* control))
                 (run-fuzz-target name :stop-at-first t))))
      (is (getf run :failures)
          "~(~A~): the ~(~A~)-sabotaged positive control found nothing in ~D buffers -- the property cannot fail"
          name control (getf run :iterations)))))

(defun consume-floating-point-in-range (fdp min max)
  "FuzzedDataProvider::ConsumeFloatingPointInRange<double>(MIN, MAX)
(FuzzedDataProvider.h): MIN plus a ConsumeProbability share of the range; a
range too wide for a double is split in half first, one ConsumeBool choosing
the half."
  (let ((min (coerce min 'double-float))
        (max (coerce max 'double-float))
        (result 0d0)
        (range 0d0))
    (when (> min max) (error "consume-floating-point-in-range: min ~A > max ~A" min max))
    (setf result min)
    (if (and (> max 0d0) (< min 0d0) (> max (+ min most-positive-double-float)))
        (progn
          (setf range (- (/ max 2d0) (/ min 2d0)))
          (when (consume-bool fdp) (incf result range)))
        (setf range (- max min)))
    (+ result (* range (consume-probability fdp)))))

(defun consume-floating-point (fdp)
  "FuzzedDataProvider::ConsumeFloatingPoint<double>(): any finite double, from
lowest() to max()."
  (consume-floating-point-in-range fdp most-negative-double-float most-positive-double-float))

;;; --- Writing the integral end of a buffer -------------------------------------

(defun make-fdp-tail ()
  "A writer for the END of a fuzz buffer, where a FuzzedDataProvider takes its
integral values: record values in the order a target will consume them with
FDP-TAIL-INTEGRAL / FDP-TAIL-BOOL, then FDP-TAIL-BYTES lays them out so the
provider reads each back exactly. For a corpus that has to steer a target's
choices (how many rounds a loop runs, a field's size) rather than leave them
to random bytes."
  (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))

(defun fdp-tail-integral (tail value min max &optional (bits 64))
  "Record VALUE (in MIN..MAX) for a CONSUME-INTEGRAL-IN-RANGE of MIN MAX BITS:
the bytes that call reads, most significant first."
  (let ((range (- max min))
        (raw (- value min))
        (n 0))
    (assert (<= 0 raw range))
    (loop for offset from 0 by 8
          while (and (< offset bits) (plusp (ash range (- offset))))
          do (incf n))
    (loop for k from (1- n) downto 0
          do (vector-push-extend (ldb (byte 8 (* 8 k)) raw) tail))
    tail))

(defun fdp-tail-bool (tail value)
  "Record a CONSUME-BOOL answering VALUE."
  (fdp-tail-integral tail (if value 1 0) 0 255 8))

(defun fdp-tail-bytes (tail)
  "The recorded values as the end of a buffer: the provider reads backwards
from the last byte, so the record is reversed."
  (let ((out (make-array (length tail) :element-type '(unsigned-byte 8))))
    (dotimes (i (length tail) out)
      (setf (aref out i) (aref tail (- (length tail) 1 i))))))
