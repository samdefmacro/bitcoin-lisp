;;;; Coalton test package definitions
;;;;
;;;; This file sets up the test packages for Coalton-based Bitcoin types.

(defpackage #:bitcoin-lisp.coalton.tests
  (:documentation "Test suite for Coalton Bitcoin types.")
  (:use #:cl #:fiveam)
  (:export #:coalton-tests))

(in-package #:bitcoin-lisp.coalton.tests)

;;; Define the test suite for Coalton tests
(def-suite coalton-tests
  :description "Tests for Coalton-typed Bitcoin code"
  :in :bitcoin-lisp-tests)
