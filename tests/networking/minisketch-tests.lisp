(in-package #:bitcoin-lisp.tests)

(def-suite :minisketch-tests
  :description "Set reconciliation sketches over GF(2^32) (BIP-330), against
Bitcoin Core's vendored minisketch"
  :in :bitcoin-lisp-tests)

(in-suite :minisketch-tests)

;;;; The oracle is Core's, not ours, and it is two programs:
;;;;
;;;;  - tests/data/minisketch_cpp_vectors.json, written by Core's minisketch
;;;;    C++ LIBRARY (refs/bitcoin/src/minisketch/, compiled as Core compiles
;;;;    it) through tests/data/minisketch_cpp_vectors.cpp -- the code a Core
;;;;    node links;
;;;;  - tests/data/minisketch_core_vectors.json, written by Core's vendored
;;;;    pyminisketch.py (the authors' Python reimplementation) through
;;;;    tests/data/minisketch_core_vectors.py.
;;;;
;;;; Both generators draw the same inputs (the C++ one carries a port of
;;;; CPython's Mersenne Twister), so every section they share must agree, and
;;;; the port is held to BOTH, byte for byte. scripts/minisketch-cpp-vectors.sh
;;;; rebuilds the C++ library in a derived image and regenerates the two files;
;;;; the battery only reads them. The field tables are the C library's own
;;;; (fields/generic_4bytes.cpp:89-90).
;;;;
;;;; A decode verdict is compared as Core states it: a sorted list of
;;;; elements, or :NULL for the library's -1. An EMPTY list is a success.

(defun %msk-vectors (which)
  "The parsed vector file WHICH names: :CPP (the C++ library) or :PY (pyminisketch)."
  (yason:parse (project-source-text (ecase which
                                      (:cpp "tests/data/minisketch_cpp_vectors.json")
                                      (:py "tests/data/minisketch_core_vectors.json")))
               :json-nulls-as-keyword t))

(defun %msk-decode-verdict (sketch max-elements)
  "MS-DECODE's answer in the vectors' terms: the sorted elements, or :NULL."
  (multiple-value-bind (elements ok) (bl.net:ms-decode sketch :max-elements max-elements)
    (if ok (sort (copy-list elements) #'<) :null)))

(defun %msk-hex (sketch)
  (string-downcase (bl.crypto:bytes-to-hex (bl.net:ms-sketch-serialize sketch))))

(defun %msk-sketch-of (elements capacity)
  (let ((sk (bl.net:ms-make-sketch capacity)))
    (dolist (e elements sk) (bl.net:ms-sketch-add sk e))))

(defun %msk-json-equal (a b)
  "Strict equality of two parsed JSON values: EQUALP would fold the case of a
hex string, EQUAL does not look inside hash tables."
  (cond ((and (hash-table-p a) (hash-table-p b))
         (and (= (hash-table-count a) (hash-table-count b))
              (loop for k being the hash-keys of a using (hash-value v)
                    always (multiple-value-bind (w present) (gethash k b)
                             (and present (%msk-json-equal v w))))))
        ((and (consp a) (consp b))
         (and (%msk-json-equal (car a) (car b)) (%msk-json-equal (cdr a) (cdr b))))
        (t (equal a b))))

(defun %msk-sketch-mismatches (entries)
  "The ENTRIES (each with elements, capacity, hex and, when present, decoded
and a max_count / decoded_max pair) whose sketch bytes or decode verdicts the
port does not reproduce."
  (let ((wrong '()))
    (dolist (v entries (nreverse wrong))
      (let* ((cap (gethash "capacity" v))
             (sk (%msk-sketch-of (gethash "elements" v) cap)))
        (unless (string= (gethash "hex" v) (%msk-hex sk))
          (push (list :hex (gethash "elements" v) cap) wrong))
        (multiple-value-bind (want present) (gethash "decoded" v)
          (when present
            (let ((got (%msk-decode-verdict sk cap)))
              (unless (equal want got)
                (push (list :decoded cap :got got :core want) wrong)))))
        (multiple-value-bind (want present) (gethash "decoded_max" v)
          (when present
            (let ((got (%msk-decode-verdict sk (gethash "max_count" v))))
              (unless (equal want got)
                (push (list :decoded-max cap (gethash "max_count" v) :got got :core want)
                      wrong)))))))))

(test minisketch-python-and-cpp-vectors-agree
  "The two oracles, compared: every section both files carry (field products
and inverses, serializations, merges, decode verdicts, capacity edges, random
sets, Core's reconciliation scenario at both ranges) is the same data, entry
for entry. They are generated independently -- pyminisketch.py in Python, the
C++ library through its C API -- from the same draws, so a disagreement is a
pyminisketch-vs-library divergence and must be reported, not regenerated
away."
  (let* ((cpp (%msk-vectors :cpp))
         (py (%msk-vectors :py))
         (shared (sort (loop for k being the hash-keys of cpp
                             when (and (nth-value 1 (gethash k py)) (string/= k "source"))
                               collect k)
                       #'string<)))
    (is (equal '("capacity" "decode" "inv" "mul" "random" "reconcile" "reconcile_wide" "sketch")
               shared))
    (dolist (section shared)
      (is (= (length (gethash section cpp)) (length (gethash section py))) "~A" section)
      (is-true (%msk-json-equal (gethash section cpp) (gethash section py))
               "section ~A differs between the C++ library and pyminisketch" section))))

(test minisketch-field-arithmetic-matches-core
  "GF(2^32) mod x^32 + x^7 + x^3 + x^2 + 1: products and inverses against the
C++ library's Field32 (GFMul, InvExtGCD) and pyminisketch's GF2Ops, squaring
against the C library's SQR_TABLE_32 (the square of each basis element x^i),
and Qrt against its QRT_TABLE_32."
  (dolist (which '(:cpp :py))
    (let ((v (%msk-vectors which)))
      (dolist (m (gethash "mul" v))
        (is (= (gethash "r" m) (bl.net:ms-mul (gethash "a" m) (gethash "b" m)))
            "~A: ~X * ~X" which (gethash "a" m) (gethash "b" m)))
      (dolist (m (gethash "inv" v))
        (is (= (gethash "r" m) (bl.net:ms-inv (gethash "a" m))) "~A: 1/~X" which (gethash "a" m)))))
  (let ((sqr-table-32
          '(#x1 #x4 #x10 #x40 #x100 #x400 #x1000 #x4000 #x10000 #x40000 #x100000
            #x400000 #x1000000 #x4000000 #x10000000 #x40000000 #x8d #x234 #x8d0
            #x2340 #x8d00 #x23400 #x8d000 #x234000 #x8d0000 #x2340000 #x8d00000
            #x23400000 #x8d000000 #x3400011a #xd0000468 #x40001037)))
    (is (equal sqr-table-32
               (loop for i below 32 collect (bl.net:ms-sqr (ash 1 i))))))
  ;; Qrt solves r^2 + r = a whenever a has trace zero, which every a of the
  ;; form r^2 + r does; the answer may be the other root, r + 1.
  (let ((*random-state* (sb-ext:seed-random-state 330)))
    (is (loop repeat 64
              for r = (random #x100000000)
              for a = (logxor (bl.net:ms-sqr r) r)
              for s = (bl.net:ms-qrt a)
              always (= a (logxor (bl.net:ms-sqr s) s)))))
  (signals error (bl.net:ms-inv 0)))

(test minisketch-sketches-serialize-to-core-bytes
  "The wire form, byte for byte: c odd power sums, each 4 bytes little-endian,
for fixed and random sets -- empty, a pair that cancels, capacity 0."
  (dolist (which '(:cpp :py))
    (dolist (v (gethash "sketch" (%msk-vectors which)))
      (is (string= (gethash "hex" v)
                   (%msk-hex (%msk-sketch-of (gethash "elements" v) (gethash "capacity" v))))
          "~A: sketch of ~S at capacity ~D" which (gethash "elements" v) (gethash "capacity" v)))))

(defun %msk-reconcile-mismatches (entries)
  "Core's minisketch_tests.cpp:21-47 scenario, one ENTRY at a time: two
overlapping integer ranges sketched at capacity 10, merged through the wire
form, decoded with max_count = the difference size. The entries whose
sketches, merge or decoded difference the port does not reproduce."
  (let ((wrong '()))
    (dolist (v entries (nreverse wrong))
      (let* ((a (%msk-sketch-of (loop for i from (gethash "start_a" v) below (gethash "end_a" v)
                                      collect i)
                                10))
             (b (%msk-sketch-of (loop for i from (gethash "start_b" v) below (gethash "end_b" v)
                                      collect i)
                                10))
             (merged (bl.net:ms-sketch-merge
                      (bl.net:ms-sketch-deserialize (bl.net:ms-sketch-serialize a))
                      (bl.net:ms-sketch-deserialize (bl.net:ms-sketch-serialize b)))))
        (unless (and (string= (gethash "hex_a" v) (%msk-hex a))
                     (string= (gethash "hex_b" v) (%msk-hex b))
                     (string= (gethash "hex_merged" v) (%msk-hex merged))
                     (equal (gethash "decoded" v)
                            (%msk-decode-verdict merged (gethash "max_count" v))))
          (push (gethash "start_a" v) wrong))))))

(test minisketch-reconciles-cores-own-scenario
  "Core's minisketch_tests.cpp scenario with its draws taken by the
generators: at a shared range below 60 (reconcile) and at Core's own range
below 10000 (reconcile_wide). Every sketch, the merge and the decoded
difference must be the library's."
  (dolist (which '(:cpp :py))
    (let ((v (%msk-vectors which)))
      (dolist (section '("reconcile" "reconcile_wide"))
        (is (plusp (length (gethash section v))))
        (let ((wrong (%msk-reconcile-mismatches (gethash section v))))
          (is (null wrong) "~A ~A: scenarios starting at ~S differ" which section wrong))))))

(test minisketch-decode-verdicts-match-core
  "116 decodes, every failure shape included: capacity 0, the all-zero sketch
(the EMPTY set, a success), an over-full sketch that decodes to a different
set, one element past the capacity, max_count below the true size, an LFSR
that outgrows the capacity (which used to index past our coefficient vector),
full sketches, and 96 random byte strings. Success and failure must be the
library's and so must every decoded element. The C++ generator decoded each
under six splitting bases and found one verdict for all of them."
  (dolist (which '(:cpp :py))
    (let ((wrong '()))
      (dolist (v (gethash "decode" (%msk-vectors which)))
        (let* ((sketch (bl.net:ms-sketch-deserialize (bl.crypto:hex-to-bytes (gethash "hex" v))))
               (max (if (eq :null (gethash "max_count" v)) (length sketch) (gethash "max_count" v)))
               (got (handler-case (%msk-decode-verdict sketch max)
                      (error (e) (list :error (princ-to-string e))))))
          (unless (equal got (gethash "decoded" v))
            (push (list (gethash "why" v) (gethash "hex" v) :got got :core (gethash "decoded" v))
                  wrong))))
      (is (null wrong) "~A: ~D verdicts differ from Core's: ~S" which (length wrong) wrong))))

(test minisketch-capacity-edges-match-the-cpp-library
  "Capacities 0, 1, 2, 128, 129 and 256, each sketched full and one element
past full, byte for byte, then decoded at max_count = capacity. 128 is the
largest first sketch this node's reconciliation sizes or accepts
(+RECON-MAX-SKETCH-CAPACITY+) and 256 the doubled capacity an extension
decodes at; 129 is a capacity the library takes and only our reconciliation
layer refuses (txreconciliation-set-tests), so the sketch code itself must
still answer it as the library does."
  (dolist (which '(:cpp :py))
    (let ((entries (gethash "capacity" (%msk-vectors which))))
      (is (equal '(0 0 1 1 2 2 128 128 129 129 256 256)
                 (mapcar (lambda (v) (gethash "capacity" v)) entries)))
      (let ((wrong (%msk-sketch-mismatches entries)))
        (is (null wrong) "~A: ~S" which wrong)))))

(test minisketch-element-edges-match-the-cpp-library
  "Elements the field cannot hold as given, against the C++ library alone
(pyminisketch's add takes 1 <= element < 2^32 only): 0 is a no-op, and a
value at or above 2^32 loses its high bits (Field::FromUint64 masks), so
2^32 is 0 again, 2^32 + 1 cancels 1, and 2^64 - 1 is 2^32 - 1."
  (let ((entries (gethash "element_edges" (%msk-vectors :cpp))))
    (is (= 10 (length entries)))
    (is (some (lambda (v) (some (lambda (e) (>= e (ash 1 32))) (gethash "elements" v))) entries))
    (let ((wrong (%msk-sketch-mismatches entries)))
      (is (null wrong) "~S" wrong))))

(test minisketch-random-sets-match-the-cpp-library
  "48 random sets from a fixed seed, capacities 1..40, sizes up to two past the
capacity: the sketch bytes, the verdict at max_count = capacity and the
verdict at a random max_count, as the C++ library and pyminisketch give them."
  (dolist (which '(:cpp :py))
    (let ((entries (gethash "random" (%msk-vectors which))))
      (is (= 48 (length entries)))
      (let ((wrong (%msk-sketch-mismatches entries)))
        (is (null wrong) "~A: ~S" which wrong)))))

(test minisketch-add-masks-and-ignores-zero-as-core-does
  "minisketch.h:117-128: an element wider than the field loses its high bits,
and 0 -- after that -- is a no-op; a sketch cannot hold it. A refusal would
turn a value the library accepts into an error."
  (let ((sk (bl.net:ms-make-sketch 3)))
    (bl.net:ms-sketch-add sk 0)
    (is (every #'zerop sk))
    (bl.net:ms-sketch-add sk #x100000000)
    (is (every #'zerop sk) "2^32 masks to 0, so it too is a no-op")
    (bl.net:ms-sketch-add sk #x1DEADBEEF)
    (is (equalp (%msk-sketch-of '(#xDEADBEEF) 3) sk))))

(test minisketch-merge-keeps-the-smaller-capacity
  "minisketch.h:132-137: merging a lower-capacity sketch reduces the result to
that capacity -- the syndromes both carry -- rather than failing."
  (let ((merged (bl.net:ms-sketch-merge (%msk-sketch-of '(1 2 3) 5)
                                        (%msk-sketch-of '(2 3 4) 2))))
    (is (= 2 (length merged)))
    (is (equalp (%msk-sketch-of '(1 4) 2) merged))))

(test a-sketch-round-trips-through-serialization
  (let ((sk (%msk-sketch-of '(#xDEADBEEF #x12345678 1 #xFFFFFFFF) 4)))
    (is (equalp sk (bl.net:ms-sketch-deserialize (bl.net:ms-sketch-serialize sk))))))

(test adding-an-element-twice-removes-it
  "The property the whole scheme rests on: addition is XOR, so an element added
twice cancels. That is why merging two sketches yields their symmetric
difference rather than their union."
  (let ((sk (bl.net:ms-make-sketch 4)))
    (bl.net:ms-sketch-add sk #xDEADBEEF)
    (is (notevery #'zerop sk))
    (bl.net:ms-sketch-add sk #xDEADBEEF)
    (is (every #'zerop sk))))

(test an-empty-difference-is-a-successful-decode
  "Two sides holding the same set cancel to a zero sketch, and that decodes --
to nothing. It must not read as the failure it shares an empty list with."
  (multiple-value-bind (elements ok)
      (bl.net:ms-decode (bl.net:ms-sketch-merge (%msk-sketch-of '(5 6 7) 4)
                                                (%msk-sketch-of '(7 6 5) 4)))
    (is (null elements))
    (is-true ok))
  (multiple-value-bind (elements ok)
      (bl.net:ms-decode (%msk-sketch-of '(1 2 3 4 5 6) 4))
    (is (null elements))
    (is-false ok "six elements do not fit a capacity-4 sketch")))

(test decoding-works-across-difference-sizes
  "From an empty difference up to the full capacity."
  (let ((cap 6))
    (loop for n from 0 to cap
          for elements = (loop for i from 1 to n collect (+ #x1000 (* i 7919)))
          do (is (equal (sort (copy-list elements) #'<)
                        (%msk-decode-verdict (%msk-sketch-of elements cap) cap))
                 "a ~D-element difference must decode at capacity ~D" n cap))))

(test a-decoded-set-is-a-claim-not-a-guarantee
  "A capacity-c sketch does not DETERMINE its set once the set is larger than
c: {1,2,3,4,5} and {6,7} share a capacity-2 sketch, so decoding the first
yields the second, consistently and wrongly -- Core's decoder included (the
vectors carry this case). BIP-330 has the peers exchange the resulting short
IDs afterwards for exactly this reason."
  (let ((over (%msk-sketch-of '(1 2 3 4 5) 2)))
    (is (equalp over (%msk-sketch-of '(6 7) 2)))
    (is (equal '(6 7) (%msk-decode-verdict over 2)))))

(test decoding-is-deterministic
  "The root finder's splitting basis is random, as in the library; it changes
the path, never the answer."
  (let* ((sk (%msk-sketch-of '(#x1234 #xABCD #x99999999 #x2 #xFFFFFFFE) 5))
         (first (%msk-decode-verdict sk 5)))
    (is (equal '(#x2 #x1234 #xABCD #x99999999 #xFFFFFFFE) first))
    (dotimes (i 5)
      (is (equal first (%msk-decode-verdict sk 5))))))
