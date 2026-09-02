;;;; scripts/docs-check.lisp — verify PAX documentation transcripts.
;;;;
;;;; Usage: scripts/dev.sh docs-check   (cold container via docker-sbcl.sh)
;;;;        sbcl --non-interactive --load scripts/docs-check.lisp
;;;;
;;;; Three gates, all required:
;;;;   GREEN: every section in *CHECKED-SECTIONS* must document cleanly —
;;;;          a transcript whose recorded output/values drift from reality
;;;;          signals TRANSCRIPTION-CONSISTENCY-ERROR, and an entry naming a
;;;;          symbol that does not exist (or is not the kind the locative
;;;;          says) is a LOCATE-ERROR; either fails the run.
;;;;   RED:   the deliberately broken transcript section must FAIL, and so
;;;;          must the deliberately dangling-reference section; if either
;;;;          passes, that check is silently off and the run fails.
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
  (let ((dangling (find-symbol "@DOCS-CHECK-DANGLING-SELFTEST" "BITCOIN-LISP.DOCS")))
    (if (section-documents-cleanly-p dangling)
        (progn
          (format t "~&;; RED SELF-TEST FAILED: the dangling-reference section passed — ~
                     entry-point checking is silently OFF.~%")
          (setf ok nil))
        (format t "~&;; RED ok: dangling reference failed as it must.~%")))
  ;; Every src/ module -- each directory and each top-level file -- must be
  ;; named somewhere in the manual's text, so a new layer cannot go
  ;; undocumented (src/zmq.lisp was, for a month, with no way to tell).
  (let* ((root (uiop:getcwd))
         (manual (uiop:read-file-string (merge-pathnames "docs/manual.lisp" root)))
         (missing '()))
    ;; A module is named by its directory (src/NAME/) or its package
    ;; (bitcoin-lisp.NAME); a top-level file by its name (NAME.lisp) or the
    ;; package it defines.
    (flet ((named-p (name)
             (or (search (format nil "src/~A/" name) manual)
                 (search (format nil "~A.lisp" name) manual)
                 (search (format nil "bitcoin-lisp.~A" name) manual))))
      (dolist (dir (uiop:subdirectories (merge-pathnames "src/" root)))
        (let ((name (car (last (pathname-directory dir)))))
          (unless (named-p name)
            (push (format nil "src/~A/" name) missing))))
      (dolist (file (uiop:directory-files (merge-pathnames "src/" root) "*.lisp"))
        (let ((name (pathname-name file)))
          (unless (or (string= name "package") (named-p name))
            (push (format nil "src/~A.lisp" name) missing))))
    (if missing
        (progn (format t "~&;; RED: no manual section names ~{~A~^, ~}~%" missing)
               (setf ok nil))
        (format t "~&;; GREEN ok: every src/ module is named in the manual~%"))
    ;; The check can actually fail: a module no section names must be missed.
    (if (named-p "no-such-module-probe")
        (progn (format t "~&;; RED SELF-TEST FAILED: the coverage check accepts a module nothing names.~%")
               (setf ok nil))
        (format t "~&;; RED ok: an unnamed module is reported as it must.~%"))))
  (if ok
      (format t "~&;; docs-check PASSED~%")
      (progn
        (format t "~&;; docs-check FAILED~%")
        (uiop:quit 1))))
