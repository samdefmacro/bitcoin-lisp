(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/asmap_direct.cpp at the pin: an asmap and an address
;;;; given one bit per byte, split by 0xFF. When SanityCheckAsmap accepts the
;;;; map for the address's length, no proper prefix of it (other than one
;;;; that only drops zero padding in the last byte) may pass, and Interpret
;;;; must run to a RETURN on any address. Ours: ASMAP-SANE-P and
;;;; ASMAP-INTERPRET.
;;;;
;;;; Random bytes are almost never a sane map, so a corpus writes maps that
;;;; are: a random binary trie of ASNs, each inner node a JUMP over its left
;;;; subtree and each leaf a RETURN, in Core's variable-length bit encoding
;;;; (%ASMAP-ENCODE-BITS, the inverse of DecodeBits) -- so the prefix
;;;; property is exercised on real maps and not only on the rare random one.

(def-suite :fuzz-asmap-direct-tests :in :bitcoin-lisp-tests
  :description "Core fuzz asmap_direct.cpp")

(in-suite :fuzz-asmap-direct-tests)

(defun %asmap-encode-bits (value minval bit-sizes)
  "Core's variable-length integer encoding (util/asmap.cpp's DecodeBits
inverse): k one-bits for class k, a zero unless k is the last class, then the
offset in the class big-endian. A list of bits."
  (let ((v (- value minval)))
    (loop for (size . more) on (coerce bit-sizes 'list)
          for k from 0
          if (< v (ash 1 size))
            return (append (make-list k :initial-element 1)
                           (when more (list 0))
                           (loop for b from (1- size) downto 0 collect (ldb (byte 1 b) v)))
          else do (decf v (ash 1 size)))))

(defun %asmap-encode-trie (trie)
  "TRIE (an ASN, or a cons of the subtrees for bit 0 and bit 1) as bytecode
bits: RETURN asn, or JUMP over the left subtree's bits, left, right."
  (if (integerp trie)
      (append '(0) (%asmap-encode-bits trie 1 #(15 16 17 18 19 20 21 22 23 24)))
      (let ((left (%asmap-encode-trie (car trie)))
            (right (%asmap-encode-trie (cdr trie))))
        (append '(1 0) (%asmap-encode-bits (length left) 17 (loop for s from 5 to 30 collect s))
                left right))))

(defun %asmap-random-trie (fdp depth)
  (if (or (zerop depth) (zerop (consume-integral-in-range fdp 0 2)))
      (consume-integral-in-range fdp 1 70000)
      (cons (%asmap-random-trie fdp (1- depth)) (%asmap-random-trie fdp (1- depth)))))

(defun %asmap-bits-to-bytes (bits)
  "Core BitsToBytes (asmap_direct.cpp:17-32): little-endian within a byte."
  (let ((out (make-array (ceiling (length bits) 8) :element-type '(unsigned-byte 8) :initial-element 0)))
    (loop for bit in bits for i from 0
          do (setf (aref out (floor i 8)) (logior (aref out (floor i 8)) (ash (logand bit 1) (mod i 8)))))
    out))

(defun %asmap-direct-corpus (fdp)
  "A sane map, 0xFF, an address of at least the trie's depth in bits."
  (let* ((depth (consume-integral-in-range fdp 1 6))
         (bits (%asmap-encode-trie (%asmap-random-trie fdp depth)))
         (ip-len (consume-integral-in-range fdp depth 16)))
    (%concat-octets (list (coerce bits '(simple-array (unsigned-byte 8) (*)))
                          #(#xff)
                          (loop repeat ip-len collect (consume-integral-in-range fdp 0 1))))))

(define-fuzz-target asmap-direct
    (buffer :core "asmap_direct.cpp:35-71" :corpus #'%asmap-direct-corpus :iterations 3000 :max-len 400)
  "A map Core's sanity check accepts has no proper prefix it accepts, and
Interpret answers an ASN for any address of the checked length."
  (let ((sep (position #xff buffer)))
    (unless (and sep (= 1 (count #xff buffer)) (every (lambda (b) (or (<= b 1) (= b #xff))) buffer))
      (fuzz-reject))
    (let ((ip-len (- (length buffer) sep 1)))
      (when (> ip-len 128) (fuzz-reject))
      (let ((asmap (%asmap-bits-to-bytes (coerce (subseq buffer 0 sep) 'list))))
        (when (bl.net:asmap-sane-p asmap ip-len)
          (loop for prefix-len from (1- sep) downto 1
                for prefix = (%asmap-bits-to-bytes (coerce (subseq buffer 0 prefix-len) 'list))
                unless (= (length prefix) (length asmap))
                  do (fuzz-assert (not (fuzz-sabotage (bl.net:asmap-sane-p prefix ip-len)))
                                  "a ~D-bit prefix of a sane ~D-bit map is sane" prefix-len sep))
          (let ((asn (bl.net:asmap-interpret asmap (%asmap-bits-to-bytes (coerce (subseq buffer (1+ sep)) 'list)))))
            (fuzz-assert (integerp asn) "Interpret answered ~S" asn)))))))
