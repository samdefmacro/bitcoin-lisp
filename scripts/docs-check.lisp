;;;; scripts/docs-check.lisp — verify PAX documentation transcripts
;;;; (cl-agent-repl template: replace the EDIT-ME markers).
;;;;
;;;; Usage: sbcl --non-interactive --load scripts/docs-check.lisp
;;;;        (or: scripts/dev.sh docs-check)
;;;;
;;;; Two gates, both required:
;;;;   GREEN: every section in *CHECKED-SECTIONS* must document cleanly —
;;;;          a transcript whose recorded output/values drift from reality
;;;;          signals TRANSCRIPTION-CONSISTENCY-ERROR and fails the run.
;;;;   RED:   the deliberately broken self-test section must FAIL; if it
;;;;          passes, checking is silently off and the run fails.
;;;;
;;;; (ql:quickload "mgl-pax/full") is required — plain "mgl-pax" autoloads
;;;; its document extension through bare ASDF, which cannot fetch missing
;;;; dependencies.

(require :asdf)

(let ((quicklisp-setup (merge-pathnames "quicklisp/setup.lisp" (user-homedir-pathname))))
  (unless (probe-file quicklisp-setup)
    (error "Quicklisp setup file not found at ~A" quicklisp-setup))
  (load quicklisp-setup))

(let ((here (uiop:ensure-directory-pathname (uiop:getcwd))))
  (pushnew here asdf:*central-registry* :test #'equal))

(funcall (find-symbol "QUICKLOAD" "QL") '("mgl-pax/full") :silent t)
(asdf:load-system "EDIT-ME-project-system")
;; Load docs files directly (purely additive — no ASDF system required):
(load (merge-pathnames "docs/EDIT-ME-manual.lisp" (uiop:getcwd)))

(defparameter *checked-sections*
  '(EDIT-ME-docs-package:@EDIT-ME-manual))

(defun section-documents-cleanly-p (section-name)
  (handler-case
      (progn
        (uiop:symbol-call "MGL-PAX" "DOCUMENT" (symbol-value section-name)
                          :format :markdown :stream (make-broadcast-stream))
        t)
    (serious-condition (e)
      (format t "~&;; ~A failed: ~A~%" section-name e)
      nil)))

(let ((ok t))
  (dolist (section *checked-sections*)
    (if (section-documents-cleanly-p section)
        (format t "~&;; GREEN ok: ~A~%" section)
        (setf ok nil)))
  (let ((selftest (find-symbol "@DOCS-CHECK-SELFTEST" "EDIT-ME-DOCS-PACKAGE")))
    (if (section-documents-cleanly-p selftest)
        (progn
          (format t "~&;; RED SELF-TEST FAILED: the broken section passed — ~
                     transcript checking is silently OFF.~%")
          (setf ok nil))
        (format t "~&;; RED ok: broken section failed as it must.~%")))
  (if ok
      (format t "~&;; docs-check PASSED~%")
      (progn
        (format t "~&;; docs-check FAILED~%")
        (uiop:quit 1))))
