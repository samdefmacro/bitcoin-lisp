;;;; Common Lisp interop for Coalton Bitcoin types
;;;;
;;;; This module provides CL-side wrapper functions that make it easy
;;;; to use Coalton types (Satoshi, BlockHeight) from regular Common Lisp code.
;;;;
;;;; Coalton functions can be called directly as CL functions since
;;;; Coalton compiles to CL.

(defpackage #:bitcoin-lisp.coalton.interop
  (:documentation "CL wrapper functions for Coalton Bitcoin types.")
  (:use #:cl)
  (:export
   ;; Satoshi operations
   #:wrap-satoshi
   #:unwrap-satoshi
   #:satoshi+
   #:satoshi-
   #:satoshi<
   #:satoshi<=
   #:satoshi>
   #:satoshi>=
   #:satoshi=
   #:zero-satoshi
   ;; BlockHeight operations
   #:wrap-block-height
   #:unwrap-block-height
   #:block-height+
   #:block-height<
   #:block-height<=
   #:block-height>
   #:block-height>=
   #:block-height=
   #:zero-block-height
   #:next-block-height
   ;; Constants
   #:+max-money+
   #:+coin+
   #:+coinbase-maturity+))

(in-package #:bitcoin-lisp.coalton.interop)

;;; Bitcoin constants
(defconstant +coin+ 100000000
  "Number of satoshis per bitcoin.")

(defconstant +max-money+ (* 21000000 +coin+)
  "Maximum total supply in satoshis (21 million BTC).")

(defconstant +coinbase-maturity+ 100
  "Number of blocks before coinbase outputs can be spent.")

;;; Satoshi operations
;;; Coalton functions are directly callable from CL

(defun wrap-satoshi (value)
  "Convert an integer to a Satoshi type."
  (bitcoin-lisp.coalton.types:make-satoshi value))

(defun unwrap-satoshi (sat)
  "Extract the integer value from a Satoshi."
  (bitcoin-lisp.coalton.types:satoshi-value sat))

(defun satoshi+ (a b)
  "Add two Satoshi values."
  (bitcoin-lisp.coalton.types:satoshi-add a b))

(defun satoshi- (a b)
  "Subtract Satoshi values."
  (bitcoin-lisp.coalton.types:satoshi-sub a b))

(defun satoshi< (a b)
  "Compare Satoshi values."
  (< (unwrap-satoshi a) (unwrap-satoshi b)))

(defun satoshi<= (a b)
  "Compare Satoshi values."
  (<= (unwrap-satoshi a) (unwrap-satoshi b)))

(defun satoshi> (a b)
  "Compare Satoshi values."
  (> (unwrap-satoshi a) (unwrap-satoshi b)))

(defun satoshi>= (a b)
  "Compare Satoshi values."
  (>= (unwrap-satoshi a) (unwrap-satoshi b)))

(defun satoshi= (a b)
  "Check Satoshi equality."
  (= (unwrap-satoshi a) (unwrap-satoshi b)))

(defun zero-satoshi ()
  "Return zero satoshis."
  (wrap-satoshi 0))

;;; BlockHeight operations

(defun wrap-block-height (height)
  "Convert an integer to a BlockHeight type."
  (bitcoin-lisp.coalton.types:make-block-height height))

(defun unwrap-block-height (bh)
  "Extract the integer value from a BlockHeight."
  (bitcoin-lisp.coalton.types:block-height-value bh))

(defun block-height+ (bh n)
  "Add N to a BlockHeight."
  (wrap-block-height (+ (unwrap-block-height bh) n)))

(defun block-height< (a b)
  "Compare BlockHeight values."
  (< (unwrap-block-height a) (unwrap-block-height b)))

(defun block-height<= (a b)
  "Compare BlockHeight values."
  (<= (unwrap-block-height a) (unwrap-block-height b)))

(defun block-height> (a b)
  "Compare BlockHeight values."
  (> (unwrap-block-height a) (unwrap-block-height b)))

(defun block-height>= (a b)
  "Compare BlockHeight values."
  (>= (unwrap-block-height a) (unwrap-block-height b)))

(defun block-height= (a b)
  "Check BlockHeight equality."
  (= (unwrap-block-height a) (unwrap-block-height b)))

(defun zero-block-height ()
  "Return block height zero (genesis)."
  (wrap-block-height 0))

(defun next-block-height (bh)
  "Return the next block height."
  (bitcoin-lisp.coalton.types:block-height-next bh))
