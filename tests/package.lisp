(in-package #:bitcoin-lisp.tests)

(def-suite :bitcoin-lisp-tests
  :description "Test suite for bitcoin-lisp")

(def-suite :crypto-tests
  :description "Tests for cryptographic functions"
  :in :bitcoin-lisp-tests)

(def-suite :serialization-tests
  :description "Tests for serialization functions"
  :in :bitcoin-lisp-tests)

(defun run-tests ()
  "Run all bitcoin-lisp tests."
  (run! :bitcoin-lisp-tests))
