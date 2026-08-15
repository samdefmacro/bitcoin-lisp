;;;; scripts/docs-check.lisp — verify PAX documentation transcripts.
;;;;
;;;; Usage: scripts/dev.sh docs-check   (cold container via docker-sbcl.sh)
;;;;        sbcl --non-interactive --load scripts/docs-check.lisp
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

;; In the project container /root/.sbclrc has already loaded /opt/quicklisp;
;; bootstrap Quicklisp only when it is genuinely absent (e.g. --script runs,
;; which skip the userinit file).
(unless (find-package "QL")
  (let ((quicklisp-setup (merge-pathnames "quicklisp/setup.lisp" (user-homedir-pathname))))
    (unless (probe-file quicklisp-setup)
      (error "Quicklisp setup file not found at ~A" quicklisp-setup))
    (load quicklisp-setup)))

(let ((here (uiop:ensure-directory-pathname (uiop:getcwd))))
  (pushnew here asdf:*central-registry* :test #'equal))

(funcall (find-symbol "QUICKLOAD" "QL") '("mgl-pax/full") :silent t)
(asdf:load-system "bitcoin-lisp")
;; Load docs files directly (purely additive — no ASDF system required):
(load (merge-pathnames "docs/manual.lisp" (uiop:getcwd)))

(defparameter *checked-sections*
  '(bitcoin-lisp.docs:@bitcoin-lisp-manual))

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
  (let ((selftest (find-symbol "@DOCS-CHECK-SELFTEST" "BITCOIN-LISP.DOCS")))
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
