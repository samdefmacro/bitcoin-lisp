;;; Diagnostic for testnet4 h=118555 tx-idx=3 input-idx=1 script failure.
;;; Loads the failing scriptPubKey + scriptSig hex from the node log,
;;; disassembles both, runs the script, prints what fails.

(asdf:load-system :bitcoin-lisp)

(defpackage #:diag-118555 (:use :cl))
(in-package #:diag-118555)

(defparameter *spk-hex-path* "/tmp/118555-spk.hex")
(defparameter *ssig-hex-path* "/tmp/118555-ssig.hex")

(defun read-hex-file (path)
  (let ((s (with-open-file (in path :direction :input)
             (with-output-to-string (out)
               (loop for line = (read-line in nil nil)
                     while line do (write-string line out))))))
    (bitcoin-lisp.crypto:hex-to-bytes (string-trim '(#\Space #\Newline #\Tab) s))))

(defun count-pushes (script)
  "Walk SCRIPT (byte vector) and return ((opcode . arg-bytes) ...)."
  (let ((pos 0)
        (len (length script))
        (items '()))
    (loop while (< pos len)
          do (let ((op (aref script pos)))
               (incf pos)
               (cond
                 ((<= 1 op 75)
                  (let ((data (subseq script pos (min (+ pos op) len))))
                    (push (cons :push data) items)
                    (incf pos op)))
                 ((= op #x4c)
                  (let ((n (aref script pos)))
                    (incf pos)
                    (push (cons :push (subseq script pos (+ pos n))) items)
                    (incf pos n)))
                 ((= op #x4d)
                  (let ((n (logior (aref script pos)
                                   (ash (aref script (1+ pos)) 8))))
                    (incf pos 2)
                    (push (cons :push (subseq script pos (+ pos n))) items)
                    (incf pos n)))
                 (t
                  (push (cons :op op) items)))))
    (nreverse items)))

(defun summarize-script (label script &key (start 0) (count 30) show-positions)
  (format t "~%=== ~A: ~D bytes (showing tokens from byte ~D, count=~D) ===~%"
          label (length script) start count)
  (let ((pos start)
        (len (length script))
        (i 0))
    (loop while (and (< pos len) (< i count))
          do (let ((op (aref script pos))
                   (op-pos pos))
               (incf pos)
               (cond
                 ((<= 1 op 75)
                  (let ((data (subseq script pos (min (+ pos op) len))))
                    (let ((h (bitcoin-lisp.crypto:bytes-to-hex data)))
                      (format t "  ~@[~D ~]PUSH ~D: ~A~%"
                              (and show-positions op-pos)
                              (length data)
                              (if (> (length h) 60) (subseq h 0 60) h)))
                    (incf pos op)))
                 ((= op #x4c)
                  (let ((n (aref script pos)))
                    (incf pos)
                    (format t "  ~@[~D ~]PUSHDATA1 ~D bytes~%"
                            (and show-positions op-pos) n)
                    (incf pos n)))
                 ((= op #x4d)
                  (let ((n (logior (aref script pos)
                                   (ash (aref script (1+ pos)) 8))))
                    (incf pos 2)
                    (format t "  ~@[~D ~]PUSHDATA2 ~D bytes~%"
                            (and show-positions op-pos) n)
                    (incf pos n)))
                 (t
                  (format t "  ~@[~D ~]OP_~X (~A)~%"
                          (and show-positions op-pos)
                          op
                          (or (gethash op bitcoin-lisp.validation::*opcode-names*) "?"))))
               (incf i)))))

(defun run ()
  (let ((spk (read-hex-file *spk-hex-path*))
        (ssig (read-hex-file *ssig-hex-path*)))
    (format t "~%=== context around fail-pos 3954 in scriptPubKey ===~%")
    ;; Show 25 tokens starting from a reasonable offset before pos=3954.
    (summarize-script "scriptPubKey @ ~3900" spk
                      :start 3900 :count 30 :show-positions t)
    (format t "~%=== running (with fail-trace) ===~%")
    (let ((bitcoin-lisp.coalton.interop::*script-fail-trace* t))
      (multiple-value-bind (ok err)
          (bitcoin-lisp.coalton.interop:run-scripts-with-p2sh ssig spk t)
        (format t "ok=~A err=~A~%" ok err)))))

(run)
