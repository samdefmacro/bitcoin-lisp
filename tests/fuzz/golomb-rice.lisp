(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/golomb_rice.cpp at the pin: a set of up to 512
;;;; elements hashed into [0, N*M) with Core's fixed SipHash keys, sorted, and
;;;; Golomb-Rice coded with BIP158's P; and a decoder over random bytes.
;;;;
;;;; Ours builds the coded set with BUILD-GCS-FILTER (the BIP158 filters'
;;;; encoder). Core compares the deltas it encoded with the ones it decodes;
;;;; ours holds the bytes to the coding restated bit by bit (CompactSize N,
;;;; then per delta q ones, a zero and the low P bits, most significant bit
;;;; first, zero-padded to a byte) and decodes them through matching, where
;;;; every element must be found. Random bytes must decode or be refused as a
;;;; stream failure (Core's std::ios_base::failure), never fail otherwise.

(def-suite :fuzz-golomb-rice-tests :in :bitcoin-lisp-tests
  :description "Core fuzz golomb_rice.cpp")

(in-suite :fuzz-golomb-rice-tests)

(defconstant +golomb-fuzz-k0+ #x0706050403020100 "Core's HashToRange key, first half.")
(defconstant +golomb-fuzz-k1+ #x0F0E0D0C0B0A0908 "Core's HashToRange key, second half.")

(defun %reference-golomb-coding (elements p m)
  "BIP158's coded set restated: CompactSize(N), then each delta of the sorted
hashed set as q = delta >> P one bits, a zero and the low P bits, most
significant first, zero-padded to a whole byte."
  (let* ((n (length elements))
         (values (sort (mapcar (lambda (e)
                                 (bl.store:gcs-fast-range
                                  (bl.crypto:siphash-2-4 +golomb-fuzz-k0+ +golomb-fuzz-k1+ e) (* n m)))
                               elements)
                       #'<))
         (bits '())
         (last 0))
    (dolist (v values)
      (let ((delta (- v last)))
        (loop repeat (ash delta (- p)) do (push 1 bits))
        (push 0 bits)
        (loop for i from (1- p) downto 0 do (push (ldb (byte 1 i) delta) bits))
        (setf last v)))
    (setf bits (nreverse bits))
    (%concat-octets
     (list (%ser #'bl.ser:bb-write-varint n)
           (loop while bits
                 collect (loop for i from 7 downto 0
                               sum (ash (or (pop bits) 0) i)))))))

(define-fuzz-target golomb-rice
    (buffer :core "golomb_rice.cpp:42-87" :iterations 600 :max-len 1200)
  "Up to 512 distinct elements code to exactly BIP158's bytes, every element
decodes back out of the coded set, and random bytes decode or are refused as a stream
failure."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (elements (remove-duplicates
                    (loop repeat (consume-integral-in-range fdp 0 512)
                          collect (consume-random-length-byte-vector fdp 16))
                    :test #'equalp))
         (coded (bl.store:build-gcs-filter elements +golomb-fuzz-k0+ +golomb-fuzz-k1+)))
    (fuzz-assert (equalp (fuzz-sabotage coded)
                         (%reference-golomb-coding elements bl.store:+basic-filter-p+ bl.store:+basic-filter-m+))
                 "~D elements code differently from BIP158" (length elements))
    (loop for e in elements repeat 8      ; each match decodes the whole set
          do (fuzz-assert (bl.store:gcs-filter-match coded +golomb-fuzz-k0+ +golomb-fuzz-k1+ e)
                          "an element of the set does not match it"))
    (let ((random (consume-random-length-byte-vector fdp 1024)))
      (fuzz-deserialize
       (bl.store:gcs-filter-match-any random +golomb-fuzz-k0+ +golomb-fuzz-k1+
                                      (list (consume-random-length-byte-vector fdp 16)))))))
