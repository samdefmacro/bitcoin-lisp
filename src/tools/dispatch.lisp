(in-package #:bitcoin-lisp.tools)

;;;; Which tool the executable is. Core builds bitcoind, bitcoin-tx,
;;;; bitcoin-util and bitcoin-wallet as four programs; this project saves ONE
;;;; image, and NODE-MAIN asks TOOL-FOR-PROGRAM-NAME about argv[0] before it
;;;; does anything a node does. scripts/conformance-config.sh links each tool's
;;;; name to the node binary under BUILDDIR/bin/, which is where Core's
;;;; framework looks for it (test_framework/util.py:317-343).

(defparameter +tools+
  (list (cons "bitcoin-util" #'run-bitcoin-util)
        (cons "bitcoin-tx" #'run-bitcoin-tx))
  "Program name -> the function that runs that tool over its arguments.")

(defun tool-for-program-name (argv0)
  "The tool function ARGV0 names, or NIL for the node itself. Only the file
name counts, and a trailing .exe (Core's EXEEXT) is ignored."
  (let* ((name (file-namestring (or argv0 "")))
         (base (if (and (> (length name) 4)
                        (string-equal ".exe" name :start2 (- (length name) 4)))
                   (subseq name 0 (- (length name) 4))
                   name)))
    (cdr (assoc base +tools+ :test #'string=))))

(defun tool-main (tool argv)
  "Run TOOL over ARGV as the whole process: its output on the process's
streams, then exit with its code. Nothing of the node has started, so the
exit need not unwind anything."
  (let ((code (handler-case (funcall tool argv)
                (error (e)
                  ;; Core's PrintExceptionContinue: an exception no command
                  ;; caught still says what it was.
                  (format *error-output* "~%~%************************~%EXCEPTION: ~A~%~%" e)
                  1))))
    (finish-output *standard-output*)
    (finish-output *error-output*)
    (sb-ext:exit :code code :abort t)))
