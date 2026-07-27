;;;; check-parens.lisp — lexical delimiter-balance check for CL source files.
;;;; Pure character scan: no READ (safe against #. eval, no package dependence).
;;;; Understands: strings (with escapes), ;-comments, nested #| |# comments,
;;;; #\ character literals (incl. #\( and named chars), |...| symbol escapes.
;;;; Usage: sbcl --script check-parens.lisp FILE...   Exit 0 clean, 1 unbalanced.

(defun check-file (path)
  "Return NIL if balanced, else an error-description string."
  (with-open-file (in path :external-format :utf-8)
    (let ((stack '())            ; entries: (char line col)
          (line 1) (col 0)
          (state :normal)        ; :normal :string :line-comment :block-comment :bars
          (block-depth 0)
          (prev nil))
      (labels ((matching (open) (ecase open (#\( #\)) (#\[ #\]) (#\{ #\}))))
        (loop for ch = (read-char in nil nil)
              while ch do
          (if (char= ch #\Newline)
              (setf line (1+ line) col 0)
              (incf col))
          (ecase state
            (:string
             (cond ((and prev (char= prev #\\)) (setf prev nil))
                   ((char= ch #\\) (setf prev ch))
                   ((char= ch #\") (setf state :normal prev nil))
                   (t (setf prev nil))))
            (:bars
             (cond ((and prev (char= prev #\\)) (setf prev nil))
                   ((char= ch #\\) (setf prev ch))
                   ((char= ch #\|) (setf state :normal prev nil))
                   (t (setf prev nil))))
            (:line-comment
             (when (char= ch #\Newline) (setf state :normal))
             (setf prev nil))
            (:block-comment
             (cond ((and prev (char= prev #\#) (char= ch #\|)) (incf block-depth) (setf prev nil))
                   ((and prev (char= prev #\|) (char= ch #\#))
                    (decf block-depth)
                    (when (zerop block-depth) (setf state :normal))
                    (setf prev nil))
                   (t (setf prev (if (member ch '(#\# #\|)) ch nil)))))
            (:normal
             (cond
               ;; #\ character literal: consume next char unconditionally,
               ;; then any following alphanumerics (named chars like #\Space).
               ((and prev (char= prev #\#) (char= ch #\\))
                (let ((c (read-char in nil nil)))
                  (when c
                    (if (char= c #\Newline) (setf line (1+ line) col 0) (incf col))
                    (loop for peek = (peek-char nil in nil nil)
                          while (and peek (or (alphanumericp peek) (char= peek #\-)))
                          do (read-char in) (incf col))))
                (setf prev nil))
               ((and prev (char= prev #\#) (char= ch #\|))
                (setf state :block-comment block-depth 1 prev nil))
               ((char= ch #\") (setf state :string prev nil))
               ((char= ch #\|) (setf state :bars prev nil))
               ((char= ch #\;) (setf state :line-comment prev nil))
               ((member ch '(#\( #\[ #\{))
                (push (list ch line col) stack)
                (setf prev nil))
               ((member ch '(#\) #\] #\}))
                (let ((top (pop stack)))
                  (cond ((null top)
                         (return-from check-file
                           (format nil "~A:~D:~D: unmatched closing '~C'" path line col ch)))
                        ((char/= ch (matching (first top)))
                         (return-from check-file
                           (format nil "~A:~D:~D: '~C' closes '~C' opened at ~D:~D"
                                   path line col ch (first top) (second top) (third top))))))
                (setf prev nil))
               (t (setf prev ch)))))))
      (cond ((eq state :string) (format nil "~A: unterminated string at EOF" path))
            ((eq state :block-comment) (format nil "~A: unterminated #| comment at EOF" path))
            (stack (destructuring-bind (ch ln cl) (first stack)
                     (format nil "~A: unclosed '~C' opened at ~D:~D (~D unclosed total)"
                             path ch ln cl (length stack))))
            (t nil)))))

;; --script mode: no UIOP; *posix-argv* is ("sbcl" FILE...) with lisp options removed.
(let ((errors '()))
  (dolist (path (cdr sb-ext:*posix-argv*))
    (let ((err (ignore-errors (check-file path))))
      (when err (push err errors))))
  (cond (errors
         (format *error-output* "PAREN-CHECK FAILED:~%~{  ~A~%~}" (nreverse errors))
         (sb-ext:exit :code 1))
        (t (sb-ext:exit :code 0))))
