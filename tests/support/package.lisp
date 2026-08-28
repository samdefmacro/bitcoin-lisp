;;;; Package bitcoin-lisp.test-support -- the fixtures every test file shares.
;;;;
;;;; Loaded before tests/package.lisp, which :USEs it, so a test file names
;;;; a fixture unqualified. A fixture belongs here the moment a second test
;;;; file wants it: the same temp-directory macro had been written seven
;;;; times, and the regtest bindings three, each file depending on whichever
;;;; other file happened to define them earlier in the load. White-box tests
;;;; keep reaching internals with :: -- that is legitimate and the structural
;;;; ratchet only asks that the count not grow.

(defpackage #:bitcoin-lisp.test-support
  (:documentation "Shared test fixtures: temporary directories, network
bindings, the minimal test node. tests/support/.")
  (:use #:cl)
  (:export
   #:with-temp-directory
   #:make-temp-directory
   #:with-network
   #:make-test-node))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (bitcoin-lisp.nicknames:install-package-nicknames))
