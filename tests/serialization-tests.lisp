(in-package #:bitcoin-lisp.tests)

(in-suite :serialization-tests)

(test read-uint32-le
  "Read uint32 little-endian should decode correctly."
  (let ((bytes #(#x01 #x02 #x03 #x04)))
    (flexi-streams:with-input-from-sequence (stream bytes)
      (is (= (bitcoin-lisp.serialization:read-uint32-le stream)
             #x04030201)))))

(test write-uint32-le
  "Write uint32 little-endian should encode correctly."
  (let ((result (flexi-streams:with-output-to-sequence (stream)
                  (bitcoin-lisp.serialization:write-uint32-le stream #x04030201))))
    (is (equalp result #(#x01 #x02 #x03 #x04)))))

(test compact-size-small
  "CompactSize encoding for small values (< 253)."
  (let ((result (flexi-streams:with-output-to-sequence (stream)
                  (bitcoin-lisp.serialization:write-compact-size stream 100))))
    (is (equalp result #(#x64)))))

(test compact-size-medium
  "CompactSize encoding for medium values (253-65535)."
  (let ((result (flexi-streams:with-output-to-sequence (stream)
                  (bitcoin-lisp.serialization:write-compact-size stream 1000))))
    (is (equalp result #(#xFD #xE8 #x03)))))

(test compact-size-roundtrip
  "CompactSize encode then decode should return original value."
  (dolist (value '(0 1 100 252 253 1000 65535 65536 1000000))
    (let* ((encoded (flexi-streams:with-output-to-sequence (stream)
                      (bitcoin-lisp.serialization:write-compact-size stream value)))
           (decoded (flexi-streams:with-input-from-sequence (stream encoded)
                      (bitcoin-lisp.serialization:read-compact-size stream))))
      (is (= decoded value)))))
