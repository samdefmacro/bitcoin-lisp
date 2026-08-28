(in-package #:bitcoin-lisp.networking)

;;;; Minisketch — set reconciliation sketches over GF(2^32)
;;;;
;;;; A sketch is a fixed-size "set checksum" with two properties nothing else
;;;; has: XORing two sketches gives a sketch of the two sets' SYMMETRIC
;;;; DIFFERENCE, and a sketch of capacity c recovers any difference of up to c
;;;; elements. That is what makes BIP-330 reconciliation cheaper than
;;;; announcing every transaction to every peer.
;;;;
;;;; Ported from the specification in refs/bitcoin/src/minisketch/doc/math.md
;;;; rather than from the library's code: the library is heavily optimized C++
;;;; with auto-generated per-field-size tables, and the fast paths are speed,
;;;; not format. The format is: a capacity-c sketch of b-bit elements is the
;;;; list of ODD power sums [s1, s3, ..., s(2c-1)], each a b-bit field element.
;;;;
;;;; ⚠️ INTEROP IS UNVERIFIED. These sketches have been checked against an
;;;; independently written reference implementation (tests/data/
;;;; minisketch_vectors.json) and against round-trips of this code, but NOT
;;;; against Bitcoin Core's minisketch library, which cannot be built in this
;;;; project's container. That is acceptable only because Core has not merged
;;;; the reconciliation protocol either — there is no peer to be wrong with
;;;; yet. Before Erlay is ever enabled against a Core node, generate vectors
;;;; from the C library and check them here.

;;;; --- GF(2^32) -----------------------------------------------------------

(defconstant +ms-field-bits+ 32)
(defconstant +ms-field-mask+ #xFFFFFFFF)

(defconstant +ms-field-modulus+ #x8D
  "The reduction polynomial x^32 + x^7 + x^3 + x^2 + 1, with the x^32 term
implied. Minisketch's own choice for the 32-bit field
(fields/generic_4bytes.cpp: Field<uint32_t, 32, 141, ...>) — and the field
size BIP-330 uses, since a 32-bit short ID is what gets reconciled.")

(declaim (inline ms-add))
(defun ms-add (a b)
  "Addition in a characteristic-2 field is XOR, and so is subtraction — which
is why two sketches combine into a sketch of the symmetric difference by
XORing, and why an element added twice cancels itself out."
  (logxor a b))

(defun ms-mul (a b)
  "Carry-less multiply, reduced by the field polynomial."
  (declare (type (unsigned-byte 32) a b)
           (optimize (speed 3) (safety 1)))
  (let ((r 0))
    (declare (type (unsigned-byte 32) r))
    (loop while (plusp b)
          do (when (logbitp 0 b) (setf r (logxor r a)))
             (setf b (ash b -1))
             (let ((carry (logbitp (1- +ms-field-bits+) a)))
               (setf a (logand (ash a 1) +ms-field-mask+))
               (when carry (setf a (logxor a +ms-field-modulus+)))))
    r))

(declaim (inline ms-sqr))
(defun ms-sqr (a) (ms-mul a a))

(defun ms-pow (a e)
  "Exponentiation by squaring."
  (let ((r 1))
    (loop while (plusp e)
          do (when (logbitp 0 e) (setf r (ms-mul r a)))
             (setf a (ms-sqr a))
             (setf e (ash e -1)))
    r))

(defun ms-inv (a)
  "Multiplicative inverse, by Fermat: a^(2^32 - 2).

The library uses an addition chain; this uses the plain exponentiation, which
costs ~32 squarings and ~31 multiplies. Decoding a sketch needs one inverse per
recovered element and reconciliation sketches hold tens of elements, so the
difference is not worth a second implementation to get wrong."
  (assert (plusp a) () "zero has no inverse in GF(2^~D)" +ms-field-bits+)
  (ms-pow a (- (ash 1 +ms-field-bits+) 2)))

;;;; --- Sketches -----------------------------------------------------------

(defun ms-make-sketch (capacity)
  "An empty sketch: CAPACITY odd power sums, all zero."
  (make-array capacity :element-type '(unsigned-byte 32) :initial-element 0))

(defun ms-sketch-add (sketch element)
  "Fold ELEMENT into SKETCH, in place.

Adds m, m^3, m^5, ... to the accumulators. Only the ODD powers are stored,
because in characteristic 2 the even ones are free: s(2i) = s(i)^2, since
squaring is additive here. That halves the sketch, making it exactly as large
as sending the elements themselves would be — which is the whole economy of the
scheme."
  (assert (and (plusp element) (<= element +ms-field-mask+)) ()
          "minisketch elements are in [1, 2^~D-1]; 0 has no sketch"
          +ms-field-bits+)
  (let ((p element)
        (sq (ms-sqr element)))
    (dotimes (i (length sketch) sketch)
      (setf (aref sketch i) (ms-add (aref sketch i) p))
      (setf p (ms-mul p sq)))))

(defun ms-sketch-merge (a b)
  "The sketch of the symmetric difference of A's and B's sets."
  (assert (= (length a) (length b)) () "sketch capacities differ")
  (let ((out (ms-make-sketch (length a))))
    (dotimes (i (length a) out)
      (setf (aref out i) (ms-add (aref a i) (aref b i))))))

(defun ms-sketch-serialize (sketch)
  "Wire form: each term as a little-endian 32-bit word."
  (let ((out (make-array (* 4 (length sketch)) :element-type '(unsigned-byte 8))))
    (dotimes (i (length sketch) out)
      (let ((v (aref sketch i)))
        (setf (aref out (* 4 i)) (ldb (byte 8 0) v)
              (aref out (+ (* 4 i) 1)) (ldb (byte 8 8) v)
              (aref out (+ (* 4 i) 2)) (ldb (byte 8 16) v)
              (aref out (+ (* 4 i) 3)) (ldb (byte 8 24) v))))))

(defun ms-sketch-deserialize (bytes)
  (assert (zerop (mod (length bytes) 4)) () "sketch length must be a multiple of 4")
  (let* ((n (floor (length bytes) 4))
         (sketch (ms-make-sketch n)))
    (dotimes (i n sketch)
      (setf (aref sketch i)
            (logior (aref bytes (* 4 i))
                    (ash (aref bytes (+ (* 4 i) 1)) 8)
                    (ash (aref bytes (+ (* 4 i) 2)) 16)
                    (ash (aref bytes (+ (* 4 i) 3)) 24))))))

;;;; --- Decoding -----------------------------------------------------------
;;;;
;;;; Recovering the set from a sketch, in three steps (math.md "Putting it all
;;;; together"):
;;;;
;;;;   1. Rebuild the even power sums: s(2i) = s(i)^2.
;;;;   2. Find the shortest polynomial L with L(0)=1 whose coefficients satisfy
;;;;      the recurrence the power sums impose — Berlekamp-Massey. L factors
;;;;      into (1 - m_i x) over the set elements.
;;;;   3. Find L's roots. Each root is 1/m_i, so the elements are their
;;;;      inverses.

(defun %ms-full-syndromes (sketch)
  "The 2c power sums s1..s2c, from the c odd ones that were transmitted."
  (let* ((c (length sketch))
         (s (make-array (* 2 c) :element-type '(unsigned-byte 32)
                                :initial-element 0)))
    (dotimes (i c)
      ;; s(2i+1) came over the wire.
      (setf (aref s (* 2 i)) (aref sketch i)))
    ;; s(2i) = s(i)^2, filling the even slots from the already-known ones.
    ;; Index j in S is the sum s(j+1), so an even power 2k sits at index 2k-1
    ;; and is the square of what sits at index k-1.
    (loop for k from 1 to c
          for even-index = (1- (* 2 k))
          when (< even-index (* 2 c))
            do (setf (aref s even-index) (ms-sqr (aref s (1- k)))))
    s))

(defun %ms-berlekamp-massey (syndromes max-degree)
  "The connection polynomial of the shortest LFSR generating SYNDROMES.

Returns a vector of coefficients l0..ln with l0 = 1. Over GF(2^m) the usual
sign handling disappears — subtraction is addition — so this is the plain
algorithm with XOR throughout."
  (let* ((n (length syndromes))
         (current (make-array (1+ max-degree) :element-type '(unsigned-byte 32)
                                              :initial-element 0))
         (previous (make-array (1+ max-degree) :element-type '(unsigned-byte 32)
                                               :initial-element 0))
         (l 0)          ; current LFSR length
         (m 1)          ; steps since PREVIOUS was updated
         (b 1))         ; the discrepancy when PREVIOUS was last updated
    (setf (aref current 0) 1
          (aref previous 0) 1)
    (dotimes (i n)
      ;; Discrepancy between the recurrence's prediction and s(i).
      (let ((d (aref syndromes i)))
        (loop for j from 1 to l
              do (setf d (ms-add d (ms-mul (aref current j)
                                           (aref syndromes (- i j))))))
        (cond
          ((zerop d) (incf m))
          ((<= (* 2 l) i)
           ;; The LFSR must grow: keep a copy of the old one to correct with.
           (let ((copy (copy-seq current))
                 (scale (ms-mul d (ms-inv b))))
             (loop for j from 0 to max-degree
                   for target = (+ j m)
                   when (<= target max-degree)
                     do (setf (aref current target)
                              (ms-add (aref current target)
                                      (ms-mul scale (aref previous j)))))
             (setf l (- (1+ i) l)
                   previous copy
                   b d
                   m 1)))
          (t
           (let ((scale (ms-mul d (ms-inv b))))
             (loop for j from 0 to max-degree
                   for target = (+ j m)
                   when (<= target max-degree)
                     do (setf (aref current target)
                              (ms-add (aref current target)
                                      (ms-mul scale (aref previous j)))))
             (incf m))))))
    (values current l)))

(defun %ms-poly-eval (coeffs x degree)
  "Horner evaluation of COEFFS (low to high) at X."
  (let ((r 0))
    (loop for i from degree downto 0
          do (setf r (ms-add (ms-mul r x) (aref coeffs i))))
    r))

(defun %ms-poly-degree (p)
  "Index of the highest nonzero coefficient, or -1 for the zero polynomial."
  (loop for i from (1- (length p)) downto 0
        when (plusp (aref p i)) do (return i)
        finally (return -1)))

(defun %ms-poly-trim (p)
  (let ((d (%ms-poly-degree p)))
    (if (< d 0)
        (make-array 1 :element-type '(unsigned-byte 32) :initial-element 0)
        (subseq p 0 (1+ d)))))

(defun %ms-poly-mod (a m)
  "A mod M, by repeated subtraction of shifted multiples. Subtraction is XOR."
  (let* ((a (copy-seq a))
         (dm (%ms-poly-degree m)))
    (when (< dm 0) (internal-error "division by the zero polynomial"))
    (let ((lead-inv (ms-inv (aref m dm))))
      (loop for da = (%ms-poly-degree a)
            while (>= da dm)
            do (let ((scale (ms-mul (aref a da) lead-inv))
                     (shift (- da dm)))
                 (loop for i from 0 to dm
                       do (setf (aref a (+ i shift))
                                (ms-add (aref a (+ i shift))
                                        (ms-mul scale (aref m i))))))))
    (%ms-poly-trim a)))

(defun %ms-poly-mul (a b)
  (let ((out (make-array (max 1 (+ (length a) (length b) -1))
                         :element-type '(unsigned-byte 32) :initial-element 0)))
    (dotimes (i (length a))
      (unless (zerop (aref a i))
        (dotimes (j (length b))
          (unless (zerop (aref b j))
            (setf (aref out (+ i j))
                  (ms-add (aref out (+ i j)) (ms-mul (aref a i) (aref b j))))))))
    (%ms-poly-trim out)))

(defun %ms-poly-mulmod (a b m) (%ms-poly-mod (%ms-poly-mul a b) m))

(defun %ms-poly-gcd (a b)
  (let ((a (%ms-poly-trim a)) (b (%ms-poly-trim b)))
    (loop until (< (%ms-poly-degree b) 0)
          do (let ((r (%ms-poly-mod a b)))
               (setf a b b r)))
    ;; Normalize to a monic polynomial so equality tests are meaningful.
    (let ((d (%ms-poly-degree a)))
      (if (< d 0)
          a
          (let ((inv (ms-inv (aref a d))))
            (dotimes (i (1+ d) a)
              (setf (aref a i) (ms-mul (aref a i) inv))))))))

(defun %ms-poly-divide (a b)
  "Exact quotient A/B; B must divide A."
  (let* ((a (copy-seq a))
         (db (%ms-poly-degree b))
         (da (%ms-poly-degree a)))
    (when (< da db)
      (return-from %ms-poly-divide
        (make-array 1 :element-type '(unsigned-byte 32) :initial-element 0)))
    (let ((q (make-array (1+ (- da db)) :element-type '(unsigned-byte 32)
                                        :initial-element 0))
          (lead-inv (ms-inv (aref b db))))
      (loop for d = (%ms-poly-degree a)
            while (>= d db)
            do (let ((scale (ms-mul (aref a d) lead-inv))
                     (shift (- d db)))
                 (setf (aref q shift) scale)
                 (loop for i from 0 to db
                       do (setf (aref a (+ i shift))
                                (ms-add (aref a (+ i shift))
                                        (ms-mul scale (aref b i)))))))
      (%ms-poly-trim q))))

(defun %ms-trace-map (r poly)
  "Tr(r*x) mod POLY, where Tr(y) = y + y^2 + y^4 + ... + y^(2^31).

The Berlekamp trace algorithm's engine: the trace of a field element is 0 or 1,
so gcd(POLY, Tr(r*x)) collects exactly the roots whose trace under r is zero —
about half of them, for a random r. Repeating with fresh r splits the
polynomial completely."
  (let ((term (make-array 2 :element-type '(unsigned-byte 32)
                            :initial-contents (list 0 r))))
    (let ((acc (copy-seq term))
          (cur (copy-seq term)))
      (dotimes (i (1- +ms-field-bits+))
        (setf cur (%ms-poly-mulmod cur cur poly))
        (let ((sum (make-array (max (length acc) (length cur))
                               :element-type '(unsigned-byte 32)
                               :initial-element 0)))
          (dotimes (j (length acc)) (setf (aref sum j) (aref acc j)))
          (dotimes (j (length cur))
            (setf (aref sum j) (ms-add (aref sum j) (aref cur j))))
          (setf acc (%ms-poly-trim sum))))
      acc)))

(defvar *ms-root-rng-state* 1
  "Deterministic source for the trace algorithm's random multipliers. The
choice of r affects only how quickly the polynomial splits, never the answer,
so a fixed sequence keeps decoding reproducible.")

(defun %ms-next-r ()
  (setf *ms-root-rng-state*
        (logand (+ (* *ms-root-rng-state* 6364136223846793005) 1442695040888963407)
                +ms-field-mask+))
  (max 1 *ms-root-rng-state*))

(defun %ms-find-roots (poly)
  "Every root of POLY in GF(2^32), or NIL if it does not split into distinct
linear factors.

Brute force is out of the question — 2^32 evaluations per decode — so this is
the Berlekamp trace algorithm: split with gcd(POLY, Tr(r*x)) for random r,
recurse on both halves, and stop when a factor is linear.

A refusal to split is NOT an error. It is exactly how the receiver learns the
difference was larger than the sketch's capacity, which BIP-330 answers with an
extension round rather than a failure."
  (let ((roots '())
        (work (list (%ms-poly-trim poly)))
        (budget (* 64 (max 1 (%ms-poly-degree poly)))))
    (loop while work
          do (when (minusp (decf budget))
               (return-from %ms-find-roots nil))
             (let* ((p (pop work))
                    (d (%ms-poly-degree p)))
               (cond
                 ((<= d 0))            ; a constant contributes no root
                 ((= d 1)
                  ;; c1 x + c0 = 0  =>  x = c0 / c1
                  (push (ms-mul (aref p 0) (ms-inv (aref p 1))) roots))
                 (t
                  (let* ((r (%ms-next-r))
                         (g (%ms-poly-gcd p (%ms-trace-map r p)))
                         (dg (%ms-poly-degree g)))
                    (if (or (<= dg 0) (= dg d))
                        ;; No split this time; try again with a fresh r.
                        (push p work)
                        (progn (push g work)
                               (push (%ms-poly-divide p g) work))))))))
    ;; A sketch decodes only when the locator splits completely and its roots
    ;; are distinct; anything else means the difference exceeded the capacity.
    (let ((unique (remove-duplicates roots)))
      (when (= (length unique) (%ms-poly-degree poly))
        unique))))

(defun ms-decode (sketch &key (max-elements (length sketch)))
  "A set of elements consistent with SKETCH, or NIL if none was found.

Two things this does NOT promise. NIL is the ordinary outcome for an over-full
sketch rather than a failure — BIP-330 answers it with an extension round, and
treating it as an error would turn a normal protocol step into one. And a
non-NIL answer is a set that REPRODUCES the sketch, which for a difference
larger than the capacity need not be the set that was encoded (see the note at
the re-sketch check below)."
  (let* ((c (length sketch)))
    (when (every #'zerop sketch)
      (return-from ms-decode '()))
    (let ((syndromes (%ms-full-syndromes sketch)))
      (multiple-value-bind (locator degree) (%ms-berlekamp-massey syndromes c)
        (when (or (zerop degree) (> degree max-elements))
          (return-from ms-decode nil))
        (let ((roots (%ms-find-roots (subseq locator 0 (1+ degree)))))
          (when roots
            ;; Each root is 1/m, so the elements are the roots inverted.
            (let ((elements (mapcar #'ms-inv roots)))
              ;; Re-sketch and compare. This catches a locator whose roots do
              ;; not actually reproduce the sketch — but it CANNOT catch the
              ;; other failure, and it is worth being exact about which:
              ;;
              ;; a capacity-c sketch does not determine its set when the set is
              ;; larger than c. {1,2,3,4,5} and {6,7} have the SAME capacity-2
              ;; sketch, so decoding the first returns the second, consistently
              ;; and wrongly. That is inherent to the scheme, not a defect
              ;; here, and no check at this layer can see it — minisketch's own
              ;; doc/false_positives.h is about exactly this probability.
              ;;
              ;; The protocol above must therefore treat a decoded set as a
              ;; CLAIM to be checked, which BIP-330 does: the peers exchange
              ;; the resulting short IDs and discover the mismatch.
              (let ((check (ms-make-sketch c)))
                (dolist (e elements) (ms-sketch-add check e))
                (when (equalp check sketch) elements)))))))))
