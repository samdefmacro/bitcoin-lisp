;;;; Package bitcoin-lisp.mining -- the public API of src/mining/.
;;;;
;;;; Loaded with the other package files before any code (bitcoin-lisp.asd,
;;;; the "packages" phase): src/config.lisp loads third and already names
;;;; most of these packages, and every package must exist before
;;;; src/package.lisp installs the bl.* nicknames. Add an export here when a
;;;; definition in src/mining/ becomes API; keep %-prefixed names internal.

(defpackage #:bitcoin-lisp.mining
  (:use #:cl)
  (:export
   #:assemble-block-template
   #:next-block-required-bits
   #:next-block-mintime
   #:build-witness-commitment-script
   #:*last-block-template*
   #:*block-min-tx-fee-rate*
   ;; block construction + mining (builder.lisp)
   #:build-coinbase-transaction
   #:assemble-full-block
   #:mine-block
   ;; block-template struct + accessors
   #:block-template
   #:block-template-height
   #:block-template-prev-hash
   #:block-template-bits
   #:block-template-version
   #:block-template-curtime
   #:block-template-mintime
   #:block-template-transactions
   #:block-template-total-fees
   #:block-template-total-weight
   #:block-template-total-sigops
   #:block-template-coinbase-value
   #:block-template-witness-commitment
   #:block-template-default-witness-commitment-script
   ;; constants
   #:+block-reserved-weight+
   #:+minimum-block-reserved-weight+
   #:*block-reserved-weight*
   #:*block-max-weight*))
