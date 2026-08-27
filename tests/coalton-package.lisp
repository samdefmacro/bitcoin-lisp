;;;; Coalton test package definitions
;;;;
;;;; This file sets up the test packages for Coalton-based Bitcoin types.

(defpackage #:bitcoin-lisp.coalton.tests
  (:documentation "Test suite for Coalton Bitcoin types.")
  (:use #:cl #:fiveam)
  (:export #:coalton-tests))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (bitcoin-lisp.nicknames:install-package-nicknames))

(in-package #:bitcoin-lisp.coalton.tests)

;;; Define the test suite for Coalton tests
(def-suite coalton-tests
  :description "Tests for Coalton-typed Bitcoin code"
  :in :bitcoin-lisp-tests)

(defun get-read-result-value (rr)
  "Extract value from ReadResult."
  (bl.cbin:read-result-value rr))

(defun get-read-result-position (rr)
  "Extract position from ReadResult."
  (bl.cbin:read-result-position rr))
