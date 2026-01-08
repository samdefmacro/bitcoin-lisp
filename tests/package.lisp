(defpackage #:bitcoin-lisp.tests
  (:use #:cl #:fiveam)
  (:export #:run-tests
           #:run-unit-tests
           #:run-integration-tests))

(in-package #:bitcoin-lisp.tests)

(def-suite :bitcoin-lisp-tests
  :description "Test suite for bitcoin-lisp")

(def-suite :crypto-tests
  :description "Tests for cryptographic functions"
  :in :bitcoin-lisp-tests)

(def-suite :serialization-tests
  :description "Tests for serialization functions"
  :in :bitcoin-lisp-tests)

(def-suite :storage-tests
  :description "Tests for storage operations"
  :in :bitcoin-lisp-tests)

(def-suite :validation-tests
  :description "Tests for validation operations"
  :in :bitcoin-lisp-tests)

(def-suite :integration-tests
  :description "Integration tests with testnet"
  :in :bitcoin-lisp-tests)

(defun run-tests ()
  "Run all bitcoin-lisp tests."
  (run! :bitcoin-lisp-tests))

(defun run-unit-tests ()
  "Run unit tests only (excludes integration tests)."
  (run! :crypto-tests)
  (run! :serialization-tests)
  (run! :storage-tests)
  (run! :validation-tests))

(defun run-integration-tests ()
  "Run integration tests only (requires network)."
  (run! :integration-tests))
