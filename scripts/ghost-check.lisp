;;;; scripts/ghost-check.lisp -- the warm image's deleted-definition guard.
;;;;
;;;; A function deleted from the source keeps its definition in a warm image:
;;;; every caller that was missed still reaches it, so the warm suites stay
;;;; green while the cold build fails with UNDEFINED-FUNCTION -- or, inside an
;;;; IGNORE-ERRORS, quietly does something else. Reloading cannot remove it;
;;;; only this check can say it is there.
;;;;
;;;; Every function, macro and generic-function method named by a symbol whose
;;;; home is one of the project's packages (BITCOIN-LISP and BITCOIN-LISP.*)
;;;; must have been compiled from a file of one of the project's ASDF systems,
;;;; and from that file's latest load. SBCL records, for each compiled
;;;; function, the file it came from and that file's write date when it was
;;;; compiled (the debug source's NAMESTRING and CREATED). A definition is a
;;;; GHOST when:
;;;;
;;;;   :no-source          it was compiled from no file (a defun typed into an
;;;;                       eval);
;;;;   :file-deleted       its file no longer exists;
;;;;   :not-in-build       its file is not a component of any bitcoin-lisp
;;;;                       system (a probe or a pre-fix copy loaded from build/);
;;;;   :deleted-from-file  its file has been compiled again since -- another
;;;;                       definition from it carries a later CREATED -- and
;;;;                       this one was not redefined: the reload no longer
;;;;                       contains it.
;;;;
;;;; A file whose write date is newer than every definition compiled from it
;;;; has been edited and not reloaded; that is reported as STALE, not as a
;;;; ghost -- its deletions are not known until it is compiled.
;;;;
;;;; Loaded on demand by `scripts/dev.sh ghost-check' (and after every system
;;;; load through the dev.sh eval path); the package is not a project package,
;;;; so loading this file adds nothing for the check to find. Its positive
;;;; control is tests/ghost-check-tests.lisp.

(defpackage #:bl-ghost-check
  (:use #:cl)
  (:export #:find-ghosts #:report))

(in-package #:bl-ghost-check)

(defun project-package-p (package)
  (let ((name (package-name package)))
    (or (string= name "BITCOIN-LISP")
        (and (> (length name) 13) (string= "BITCOIN-LISP." name :end2 13)))))

(defun build-source-files ()
  "The truenames (as strings) of every CL source file of every bitcoin-lisp
ASDF system loaded in this image."
  (let ((files (make-hash-table :test 'equal)))
    (labels ((walk (component)
               (typecase component
                 (asdf:cl-source-file
                  (let ((p (probe-file (asdf:component-pathname component))))
                    (when p (setf (gethash (namestring p) files) t))))
                 (asdf:parent-component
                  (mapc #'walk (asdf:component-children component))))))
      (dolist (name (asdf:registered-systems))
        (when (or (string= name "bitcoin-lisp")
                  (and (> (length name) 13) (string= "bitcoin-lisp/" name :end2 13)))
          (let ((system (asdf:registered-system name)))
            (when system (walk system))))))
    files))

(defun function-source (function)
  "(values namestring created) of the file FUNCTION was compiled from, or NIL
when it was compiled from none."
  (let* ((fun (sb-kernel:%fun-fun function))
         (code (sb-kernel:fun-code-header fun))
         (info (and code (sb-kernel:%code-debug-info code))))
    (when (typep info 'sb-c::compiled-debug-info)
      (let ((source (sb-c::debug-info-source info)))
        (values (sb-c::debug-source-namestring source)
                (sb-c::debug-source-created source))))))

(defun method-body (method)
  "The function METHOD's DEFMETHOD compiled: PCL wraps it, and the wrapper's
code is PCL's own."
  (let ((mf (sb-mop:method-function method)))
    (or (and (typep mf 'sb-pcl::%method-function)
             (sb-pcl::%method-function-fast-function mf))
        mf)))

(defun sbcl-generated-p (function)
  "True when FUNCTION's code is SBCL's own (a logical SYS: source)."
  (let ((file (ignore-errors (function-source function))))
    (and file (eql 0 (search "SYS:" file)))))

(defun class-name-or-eql (specializer)
  (if (typep specializer 'class)
      (class-name specializer)
      specializer))

(defun definitions ()
  "Every (name kind function) the check judges: each fbound symbol homed in a
project package -- its function or macro, its SETF function -- and each method
of a project generic function."
  (let ((out '()))
    (dolist (package (list-all-packages))
      (when (project-package-p package)
        (do-symbols (symbol package)
          (when (eq (symbol-package symbol) package)
            (let ((setf-name (list 'setf symbol)))
              (when (and (fboundp symbol) (not (special-operator-p symbol)))
                (let ((f (or (macro-function symbol) (fdefinition symbol))))
                  (if (typep f 'generic-function)
                      (dolist (m (sb-mop:generic-function-methods f))
                        ;; A slot or condition reader's method belongs to its
                        ;; class definition, and SBCL builds it from its own
                        ;; code, not from a file of ours.
                        (let ((body (method-body m)))
                          (unless (or (typep m 'sb-mop:standard-accessor-method)
                                      (sbcl-generated-p body))
                            (push (list (list symbol (mapcar #'class-name-or-eql
                                                             (sb-mop:method-specializers m)))
                                        :method body)
                                  out))))
                      (push (list symbol (if (macro-function symbol) :macro :function) f)
                            out))))
              (when (fboundp setf-name)
                (let ((f (fdefinition setf-name)))
                  (unless (typep f 'generic-function)
                    (push (list setf-name :function f) out)))))))))
    out))

(defun judge (definitions build-files)
  "(values ghosts stale-files). GHOSTS is a list of (name kind reason file)."
  (let ((newest (make-hash-table :test 'equal))  ; truename -> latest CREATED
        (truenames (make-hash-table :test 'equal)) ; namestring -> truename, once
        (sourced '())
        (ghosts '()))
    (dolist (d definitions)
      (destructuring-bind (name kind function) d
        (multiple-value-bind (file created) (ignore-errors (function-source function))
          (let ((true (and file
                           (multiple-value-bind (cached found) (gethash file truenames)
                             (if found
                                 cached
                                 (setf (gethash file truenames) (probe-file file)))))))
            (cond
              ((null file) (push (list name kind :no-source nil) ghosts))
              ((null true) (push (list name kind :file-deleted file) ghosts))
              ((not (gethash (namestring true) build-files))
               (push (list name kind :not-in-build file) ghosts))
              (t (let ((key (namestring true)))
                   (setf (gethash key newest) (max created (gethash key newest 0)))
                   (push (list name kind key created) sourced))))))))
    (dolist (s sourced)
      (destructuring-bind (name kind key created) s
        (when (< created (gethash key newest))
          (push (list name kind :deleted-from-file key) ghosts))))
    (values ghosts
            (loop for key being the hash-keys of newest using (hash-value created)
                  when (> (file-write-date key) created) collect key))))

(defun find-ghosts (&key extra-sources)
  "The ghost definitions in this image, as (name kind reason file) lists, and
the stale files as a second value. EXTRA-SOURCES are files to accept as part
of the build (the positive control's probe file)."
  (let ((files (build-source-files)))
    (dolist (f extra-sources)
      (setf (gethash (namestring (truename f)) files) t))
    (judge (definitions) files)))

(defun report (&key (signal t))
  "Find the ghosts; return a one-line verdict when there are none, else (with
SIGNAL) signal an error whose message lists them -- a batch eval client
reports a signalled condition but drops the output printed before it."
  (multiple-value-bind (ghosts stale) (find-ghosts)
    (let ((text (with-output-to-string (s)
                  (dolist (g (sort (copy-list ghosts) #'string<
                                   :key (lambda (g) (prin1-to-string (first g)))))
                    (destructuring-bind (name kind reason file) g
                      (format s "ghost-check: ~S (~(~A~)) ~(~A~)~@[ ~A~]~%"
                              name kind reason file)))
                  (dolist (f stale)
                    (format s "ghost-check: stale ~A (edited since it was last compiled)~%" f))
                  (format s "ghost-check: ~D ghost definition~:P, ~D stale file~:P"
                          (length ghosts) (length stale)))))
      (if (and ghosts signal)
          (error "~A" text)
          text))))
