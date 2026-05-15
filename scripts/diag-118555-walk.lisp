;;; Walk scriptPubKey, find OP_CODESEPARATOR (0xab) opcodes (vs data bytes).
(asdf:load-system :bitcoin-lisp)
(defpackage #:diag-walk (:use :cl))
(in-package #:diag-walk)

(defparameter *spk-hex-path* "/tmp/118555-spk.hex")

(defun hex->bytes (s) (bitcoin-lisp.crypto:hex-to-bytes s))

(defun walk (script)
  (let ((pos 0) (len (length script)) (codeseps '()))
    (loop while (< pos len)
          do (let ((op (aref script pos)))
               (cond
                 ((<= 1 op 75) (incf pos (1+ op)))
                 ((= op #x4c) (let ((n (aref script (1+ pos)))) (incf pos (+ 2 n))))
                 ((= op #x4d) (let ((n (logior (aref script (1+ pos))
                                                (ash (aref script (+ 2 pos)) 8))))
                                (incf pos (+ 3 n))))
                 ((= op #x4e) (incf pos 5))
                 (t (when (= op #xab) (push pos codeseps)) (incf pos)))))
    (nreverse codeseps)))

(let ((spk (hex->bytes
            (string-trim '(#\Space #\Newline #\Tab)
                         (with-open-file (in *spk-hex-path*)
                           (with-output-to-string (out)
                             (loop for line = (read-line in nil nil)
                                   while line do (write-string line out))))))))
  (format t "scriptPubKey len: ~D bytes~%" (length spk))
  (let ((cs (walk spk)))
    (format t "OP_CODESEPARATOR positions: ~A~%" cs)))
