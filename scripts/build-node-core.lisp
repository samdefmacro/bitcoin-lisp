;;;; Build the bitcoin-lisp node executable (save-lisp-and-die).
;;;;
;;;; Run inside the project container via scripts/build-node.sh. Produces a
;;;; bitcoind-shaped binary: it takes Core's command line, runs a node, and
;;;; exits with a code the caller can act on.
;;;;
;;;; The system is loaded and the toplevel is named in SEPARATE top-level
;;;; forms, and the toplevel is looked up with FIND-SYMBOL rather than written
;;;; as BITCOIN-LISP:NODE-MAIN: LOAD reads a whole form before evaluating it,
;;;; so a reference to the package inside the same form as the LOAD-SYSTEM call
;;;; is a READ error ("Package BITCOIN-LISP does not exist").

(require :asdf)

(asdf:load-system "bitcoin-lisp")

(defparameter *output*
  (or (second sb-ext:*posix-argv*) "build/bitcoin-lisp-node"))

(ensure-directories-exist *output*)

(format t "~&Saving executable to ~A~%" *output*)
(finish-output)

;;;; :save-runtime-options t is what makes the result bitcoind-shaped rather
;;;; than sbcl-shaped — without it the SBCL runtime consumes --datadir-style
;;;; arguments itself instead of passing them to the program, and the heap size
;;;; baked in here would be overridable by anyone passing --dynamic-space-size.
(sb-ext:save-lisp-and-die *output*
                          :executable t
                          :toplevel (symbol-function
                                     (or (find-symbol "NODE-MAIN" "BITCOIN-LISP")
                                         (error "bitcoin-lisp:node-main is missing")))
                          :save-runtime-options t
                          :compression nil)
