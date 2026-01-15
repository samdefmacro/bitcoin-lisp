;;;; Tests for Coalton binary serialization primitives
;;;;
;;;; Verifies that typed binary read/write operations work correctly
;;;; for Bitcoin protocol serialization.

(in-package #:bitcoin-lisp.coalton.tests)

(in-suite coalton-tests)

;;;; Helper to call Coalton binary functions from CL

(defun call-read-u8 (bytes pos)
  "Call Coalton read-u8 from CL."
  (bitcoin-lisp.coalton.binary:read-u8 bytes pos))

(defun call-read-u16-le (bytes pos)
  "Call Coalton read-u16-le from CL."
  (bitcoin-lisp.coalton.binary:read-u16-le bytes pos))

(defun call-read-u32-le (bytes pos)
  "Call Coalton read-u32-le from CL."
  (bitcoin-lisp.coalton.binary:read-u32-le bytes pos))

(defun call-read-u64-le (bytes pos)
  "Call Coalton read-u64-le from CL."
  (bitcoin-lisp.coalton.binary:read-u64-le bytes pos))

(defun call-read-i32-le (bytes pos)
  "Call Coalton read-i32-le from CL."
  (bitcoin-lisp.coalton.binary:read-i32-le bytes pos))

(defun call-read-i64-le (bytes pos)
  "Call Coalton read-i64-le from CL."
  (bitcoin-lisp.coalton.binary:read-i64-le bytes pos))

(defun call-read-compact-size (bytes pos)
  "Call Coalton read-compact-size from CL."
  (bitcoin-lisp.coalton.binary:read-compact-size bytes pos))

(defun call-read-bytes (bytes pos count)
  "Call Coalton read-bytes from CL."
  (bitcoin-lisp.coalton.binary:read-bytes bytes pos count))

(defun get-read-result-value (rr)
  "Extract value from ReadResult."
  (bitcoin-lisp.coalton.binary:read-result-value rr))

(defun get-read-result-position (rr)
  "Extract position from ReadResult."
  (bitcoin-lisp.coalton.binary:read-result-position rr))

;;;; Read tests

(test binary-read-u8
  "Test reading a single unsigned byte."
  (let* ((bytes (make-array 4 :initial-contents '(42 0 0 0)))
         (result (call-read-u8 bytes 0)))
    (is (= 42 (get-read-result-value result)))
    (is (= 1 (get-read-result-position result)))))

(test binary-read-u16-le
  "Test reading 16-bit little-endian unsigned integer."
  ;; 0x1234 = 4660 decimal, stored as [0x34 0x12] in little-endian
  (let* ((bytes (make-array 4 :initial-contents '(#x34 #x12 0 0)))
         (result (call-read-u16-le bytes 0)))
    (is (= #x1234 (get-read-result-value result)))
    (is (= 2 (get-read-result-position result)))))

(test binary-read-u32-le
  "Test reading 32-bit little-endian unsigned integer."
  ;; 0x12345678 stored as [0x78 0x56 0x34 0x12] in little-endian
  (let* ((bytes (make-array 4 :initial-contents '(#x78 #x56 #x34 #x12)))
         (result (call-read-u32-le bytes 0)))
    (is (= #x12345678 (get-read-result-value result)))
    (is (= 4 (get-read-result-position result)))))

(test binary-read-u64-le
  "Test reading 64-bit little-endian unsigned integer."
  (let* ((bytes (make-array 8 :initial-contents '(#x08 #x07 #x06 #x05 #x04 #x03 #x02 #x01)))
         (result (call-read-u64-le bytes 0)))
    (is (= #x0102030405060708 (get-read-result-value result)))
    (is (= 8 (get-read-result-position result)))))

(test binary-read-i32-le-positive
  "Test reading positive signed 32-bit integer."
  ;; 12345 = 0x3039, little-endian [0x39 0x30 0x00 0x00]
  (let* ((bytes (make-array 4 :initial-contents '(#x39 #x30 #x00 #x00)))
         (result (call-read-i32-le bytes 0)))
    (is (= 12345 (get-read-result-value result)))))

(test binary-read-i32-le-negative
  "Test reading negative signed 32-bit integer."
  ;; -1 in two's complement is 0xFFFFFFFF
  (let* ((bytes (make-array 4 :initial-contents '(#xFF #xFF #xFF #xFF)))
         (result (call-read-i32-le bytes 0)))
    (is (= -1 (get-read-result-value result)))))

(test binary-read-i64-le-negative
  "Test reading negative signed 64-bit integer."
  ;; -1 in two's complement is 0xFFFFFFFFFFFFFFFF
  (let* ((bytes (make-array 8 :initial-contents '(#xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF)))
         (result (call-read-i64-le bytes 0)))
    (is (= -1 (get-read-result-value result)))))

;;;; CompactSize tests

(test binary-compact-size-single-byte
  "Test reading CompactSize for value < 253."
  (let* ((bytes (make-array 3 :initial-contents '(100 0 0)))
         (result (call-read-compact-size bytes 0)))
    (is (= 100 (get-read-result-value result)))
    (is (= 1 (get-read-result-position result)))))

(test binary-compact-size-two-bytes
  "Test reading CompactSize with 0xFD prefix (2-byte value)."
  ;; 0xFD followed by 2 bytes little-endian for 0x0102 = 258
  (let* ((bytes (make-array 3 :initial-contents '(#xFD #x02 #x01)))
         (result (call-read-compact-size bytes 0)))
    (is (= 258 (get-read-result-value result)))
    (is (= 3 (get-read-result-position result)))))

(test binary-compact-size-four-bytes
  "Test reading CompactSize with 0xFE prefix (4-byte value)."
  ;; 0xFE followed by 4 bytes little-endian for 0x00010000 = 65536
  (let* ((bytes (make-array 5 :initial-contents '(#xFE #x00 #x00 #x01 #x00)))
         (result (call-read-compact-size bytes 0)))
    (is (= 65536 (get-read-result-value result)))
    (is (= 5 (get-read-result-position result)))))

;;;; Write tests

(test binary-write-u8
  "Test writing unsigned 8-bit integer."
  (let ((result (bitcoin-lisp.coalton.binary:write-u8 42)))
    (is (= 1 (length result)))
    (is (= 42 (aref result 0)))))

(test binary-write-u16-le
  "Test writing unsigned 16-bit little-endian integer."
  (let ((result (bitcoin-lisp.coalton.binary:write-u16-le #x1234)))
    (is (= 2 (length result)))
    (is (= #x34 (aref result 0)))
    (is (= #x12 (aref result 1)))))

(test binary-write-u32-le
  "Test writing unsigned 32-bit little-endian integer."
  (let ((result (bitcoin-lisp.coalton.binary:write-u32-le #x12345678)))
    (is (= 4 (length result)))
    (is (= #x78 (aref result 0)))
    (is (= #x56 (aref result 1)))
    (is (= #x34 (aref result 2)))
    (is (= #x12 (aref result 3)))))

(test binary-write-u64-le
  "Test writing unsigned 64-bit little-endian integer."
  (let ((result (bitcoin-lisp.coalton.binary:write-u64-le #x0102030405060708)))
    (is (= 8 (length result)))
    (is (= #x08 (aref result 0)))
    (is (= #x07 (aref result 1)))
    (is (= #x06 (aref result 2)))
    (is (= #x05 (aref result 3)))
    (is (= #x04 (aref result 4)))
    (is (= #x03 (aref result 5)))
    (is (= #x02 (aref result 6)))
    (is (= #x01 (aref result 7)))))

(test binary-write-i32-le-negative
  "Test writing negative signed 32-bit integer."
  (let ((result (bitcoin-lisp.coalton.binary:write-i32-le -1)))
    (is (= 4 (length result)))
    (is (= #xFF (aref result 0)))
    (is (= #xFF (aref result 1)))
    (is (= #xFF (aref result 2)))
    (is (= #xFF (aref result 3)))))

(test binary-write-compact-size-small
  "Test writing small CompactSize value."
  (let ((result (bitcoin-lisp.coalton.binary:write-compact-size 100)))
    (is (= 1 (length result)))
    (is (= 100 (aref result 0)))))

(test binary-write-compact-size-medium
  "Test writing medium CompactSize value (>= 253)."
  (let ((result (bitcoin-lisp.coalton.binary:write-compact-size 300)))
    (is (= 3 (length result)))
    (is (= #xFD (aref result 0)))  ; Prefix for 2-byte encoding
    (is (= #x2C (aref result 1)))  ; 300 = 0x012C
    (is (= #x01 (aref result 2)))))

;;;; Position tracking tests

(test binary-read-position-advances
  "Test that read position advances correctly."
  (let* ((bytes (make-array 6 :initial-contents '(#x78 #x56 #x34 #x12 #x00 #x00)))
         (result (call-read-u32-le bytes 0)))
    (is (= 4 (get-read-result-position result)))))

(test binary-read-at-offset
  "Test reading at non-zero offset."
  (let* ((bytes (make-array 4 :initial-contents '(#x00 #x00 #x34 #x12)))
         (result (call-read-u16-le bytes 2)))
    (is (= #x1234 (get-read-result-value result)))
    (is (= 4 (get-read-result-position result)))))

;;;; Concat bytes test

(test binary-concat-bytes
  "Test byte vector concatenation."
  (let* ((a (make-array 3 :initial-contents '(1 2 3)))
         (b (make-array 2 :initial-contents '(4 5)))
         (result (bitcoin-lisp.coalton.binary:concat-bytes a b)))
    (is (= 5 (length result)))
    (is (= 1 (aref result 0)))
    (is (= 2 (aref result 1)))
    (is (= 3 (aref result 2)))
    (is (= 4 (aref result 3)))
    (is (= 5 (aref result 4)))))

;;;; Read bytes test

(test binary-read-bytes
  "Test reading a slice of bytes."
  (let* ((bytes (make-array 5 :initial-contents '(10 20 30 40 50)))
         (result (call-read-bytes bytes 1 3)))
    (is (= 3 (length (get-read-result-value result))))
    (is (= 20 (aref (get-read-result-value result) 0)))
    (is (= 30 (aref (get-read-result-value result) 1)))
    (is (= 40 (aref (get-read-result-value result) 2)))
    (is (= 4 (get-read-result-position result)))))

;;;; Roundtrip tests

(test binary-roundtrip-u32
  "Test that write-u32-le and read-u32-le are inverses."
  (let* ((original #xDEADBEEF)
         (bytes (bitcoin-lisp.coalton.binary:write-u32-le original))
         (result (call-read-u32-le bytes 0)))
    (is (= original (get-read-result-value result)))))

(test binary-roundtrip-compact-size
  "Test that write-compact-size and read-compact-size are inverses."
  (dolist (value '(0 100 252 253 300 65535 65536 100000))
    (let* ((bytes (bitcoin-lisp.coalton.binary:write-compact-size value))
           (result (call-read-compact-size bytes 0)))
      (is (= value (get-read-result-value result))))))
