;;;; Persistent Swank development image for bitcoin-lisp.
;;;;
;;;; Runs INSIDE the project container (started by scripts/dev.sh via
;;;; docker run): the image's .sbclrc already loads /opt/quicklisp. Swank is
;;;; not baked into the image, so the first start of each container
;;;; quickloads it (small download). Listens on 0.0.0.0 in-container — the
;;;; container's loopback is unreachable from the host — but dev.sh
;;;; publishes the port to the HOST's 127.0.0.1 only, so the security
;;;; boundary is unchanged.

(defun getenv/default (name default)
  (or (sb-ext:posix-getenv name) default))

(let ((port (parse-integer (getenv/default "DEV_SWANK_PORT" "4007"))))
  (funcall (find-symbol "QUICKLOAD" "QL") "swank" :silent t)
  (format t "~&;;; Loading bitcoin-lisp/tests (Coalton compile on cold FASL volume takes minutes)~%")
  (asdf:load-system "bitcoin-lisp/tests")
  (format t "~&;;; Starting Swank on 0.0.0.0:~D (in-container)~%" port)
  (funcall (find-symbol "CREATE-SERVER" "SWANK")
           :interface "0.0.0.0" :port port :dont-close t)
  (format t "~&;;; bitcoin-lisp Swank dev image ready.~%")
  (loop (sleep 3600)))
