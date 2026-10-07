(in-package #:bitcoin-lisp.tests)

;;;; The positive control of scripts/ghost-check.lisp, the warm image's
;;;; deleted-definition guard (`scripts/dev.sh ghost-check').
;;;;
;;;; A guard that cannot fail is no guard: each reason the check gives is
;;;; produced here on purpose, by a probe definition made the way the trap
;;;; makes one, and the check must name exactly that probe -- and must not
;;;; name a definition the build still has.

(def-suite :ghost-check-tests :in :bitcoin-lisp-tests
  :description "Positive control of the warm image's deleted-definition guard")

(in-suite :ghost-check-tests)

(defun %ghost-check-find (&rest args)
  "BL-GHOST-CHECK:FIND-GHOSTS, the script loaded first. The script's package
does not exist when this file is compiled, so the call goes by name."
  (load (asdf:system-relative-pathname "bitcoin-lisp" "scripts/ghost-check.lisp"))
  (apply #'uiop:symbol-call :bl-ghost-check :find-ghosts args))

(defun %ghost-reason (name ghosts)
  "The reason GHOSTS gives for NAME, or NIL when NAME is not among them."
  (third (find name ghosts :key #'first :test #'equal)))

(defun %ghost-probe-load (path text &key later)
  "Write TEXT to PATH, then compile and load it as ASDF would: COMPILE-FILE
records the file's write date in every function it compiles. LATER dates the
file ten seconds ahead, past the write date's one-second resolution, as an
edit made later would be."
  (with-open-file (out path :direction :output :if-exists :supersede)
    (write-string text out))
  (when later
    (let ((unix (+ (- (get-universal-time) 2208988800) 10)))
      (sb-posix:utime (namestring path) unix unix)))
  (let ((*standard-output* (make-broadcast-stream))
        (*error-output* (make-broadcast-stream)))
    (load (compile-file path :verbose nil :print nil))))

(test ghost-check-names-a-definition-compiled-from-no-file
  "A DEFUN typed into an eval exists in the image and nowhere in the source."
  (unwind-protect
       (progn
         (compile 'ghost-check-probe-no-source '(lambda () :ghost))
         (let ((ghosts (%ghost-check-find)))
           (is (eq :no-source (%ghost-reason 'ghost-check-probe-no-source ghosts))
               "an eval-defined function was not reported")
           (is-false (%ghost-reason 'bl.mp:estimate-fee-rate ghosts)
                     "negative control: a definition the build has was reported")))
    (fmakunbound 'ghost-check-probe-no-source)))

(test ghost-check-names-a-definition-deleted-from-its-file
  "The trap itself: a file loses a DEFUN and is compiled and loaded again. The
function that is still there is redefined from the new compile; the deleted
one keeps the definition the OLD compile gave it, which is what tells them
apart. A probe file outside the build is also reported as such until it is
declared part of it."
  (let* ((dir (uiop:ensure-directory-pathname
               (merge-pathnames (format nil "ghost-check-~D/" (get-internal-real-time))
                                (uiop:temporary-directory))))
         (path (merge-pathnames "probe.lisp" (ensure-directories-exist dir)))
         (head "(in-package #:bitcoin-lisp.tests)
(defun ghost-check-probe-kept () :kept)
"))
    (unwind-protect
         (progn
           (%ghost-probe-load path (concatenate 'string head "
(defun ghost-check-probe-deleted () :deleted)
"))
           (%ghost-probe-load path head :later t)
           (let ((ghosts (%ghost-check-find :extra-sources (list path))))
             (is (eq :deleted-from-file
                     (%ghost-reason 'ghost-check-probe-deleted ghosts))
                 "the deleted definition was not reported")
             (is-false (%ghost-reason 'ghost-check-probe-kept ghosts)
                       "a definition the file still has was reported"))
           (is (eq :not-in-build
                   (%ghost-reason 'ghost-check-probe-kept (%ghost-check-find)))
               "a file outside the build was taken for part of it"))
      (fmakunbound 'ghost-check-probe-kept)
      (fmakunbound 'ghost-check-probe-deleted)
      (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore))))
