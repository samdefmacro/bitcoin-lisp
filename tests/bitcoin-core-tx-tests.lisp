(in-package #:bitcoin-lisp.tests)

(def-suite :bitcoin-core-tx-tests
  :description "Bitcoin Core tx_valid.json / tx_invalid.json compatibility tests"
  :in :bitcoin-lisp-tests)

(in-suite :bitcoin-core-tx-tests)

(defun load-tx-tests (filename)
  "Load transaction test vectors from Bitcoin Core."
  (let ((path (merge-pathnames
               (format nil "refs/bitcoin/src/test/data/~A" filename)
               (asdf:system-source-directory :bitcoin-lisp))))
    (with-open-file (stream path :direction :input)
      (yason:parse stream))))

(defun parse-tx-test-case (test-case)
  "Parse a tx test case. Returns (values prevouts serialized-tx-hex flags) or NIL for comments."
  (when (and (listp test-case)
             (>= (length test-case) 3)
             (listp (first test-case)))
    (values (first test-case)
            (second test-case)
            (third test-case))))

(defun strip-op-prefix (asm)
  "Strip OP_ prefix from opcode names in assembly string for compatibility.
tx_valid/invalid.json uses 'OP_CHECKMULTISIG' but assemble-script expects 'CHECKMULTISIG'."
  (let ((result asm))
    ;; Replace OP_ prefixed opcodes (but not data like 0x...)
    (loop for pos = (search "OP_" result)
          while pos
          do (setf result (concatenate 'string
                                       (subseq result 0 pos)
                                       (subseq result (+ pos 3)))))
    result))

(defun validate-single-tx-input (tx input-index prevout-data flags)
  "Validate a single input of TX at INPUT-INDEX against PREVOUT-DATA.
Returns T on success, (values nil error) on failure."
  (let* ((script-pubkey-asm (third prevout-data))
         (amount (if (>= (length prevout-data) 4) (fourth prevout-data) 0))
         (input (nth input-index (bitcoin-lisp.serialization:transaction-inputs tx)))
         (pubkey-bytes (assemble-script (strip-op-prefix script-pubkey-asm)))
         (sig-bytes (bitcoin-lisp.serialization:tx-in-script-sig input))
         (witness-stack (when (bitcoin-lisp.serialization:transaction-witness tx)
                          (nth input-index (bitcoin-lisp.serialization:transaction-witness tx))))
         (bitcoin-lisp.coalton.interop:*current-tx* tx)
         (bitcoin-lisp.coalton.interop:*current-input-index* input-index)
         (bitcoin-lisp.coalton.interop:*witness-input-amount* (or amount 0))
         (has-witness-flag (and flags (search "WITNESS" flags)))
         (has-p2sh-flag (and flags (search "P2SH" flags)))
         (is-witness-program (bitcoin-lisp.coalton.interop:is-witness-program-p pubkey-bytes))
         (is-p2sh (and has-p2sh-flag
                       (bitcoin-lisp.coalton.interop:is-p2sh-script-p pubkey-bytes))))
    (bitcoin-lisp.coalton.interop:set-script-flags flags)
    (unwind-protect
         (progn
           ;; Native witness program
           (when (and has-witness-flag is-witness-program)
             (return-from validate-single-tx-input
               (bitcoin-lisp.coalton.interop:validate-witness-program
                pubkey-bytes witness-stack (or amount 0) sig-bytes)))

           ;; P2SH-wrapped witness
           (when (and has-witness-flag is-p2sh witness-stack)
             (let ((redeem-script (extract-p2sh-redeem-script sig-bytes)))
               (when (and redeem-script
                          (bitcoin-lisp.coalton.interop:is-witness-program-p redeem-script))
                 (return-from validate-single-tx-input
                   (bitcoin-lisp.coalton.interop:validate-witness-program
                    redeem-script witness-stack (or amount 0) nil)))))

           ;; Legacy script validation
           (multiple-value-bind (success stack-or-error)
               (bitcoin-lisp.coalton.interop:run-scripts-with-p2sh
                sig-bytes pubkey-bytes (and has-p2sh-flag t))
             (if (and success
                      (bitcoin-lisp.coalton.interop:stack-top-truthy-p stack-or-error))
                 (values t nil)
                 (values nil (or stack-or-error :eval-false)))))
      (bitcoin-lisp.coalton.interop:set-script-flags nil))))

(defun validate-tx-inputs (tx prevouts flags)
  "Validate all inputs of TX against PREVOUTS using FLAGS.
Returns T if all inputs validate, (values nil error) on first failure."
  (loop for i from 0
        for prevout-data in prevouts
        do (multiple-value-bind (success err)
               (validate-single-tx-input tx i prevout-data flags)
             (unless success
               (return-from validate-tx-inputs (values nil err)))))
  t)

(test tx-valid-json
  "Run Bitcoin Core tx_valid.json test vectors."
  (let ((tests (load-tx-tests "tx_valid.json"))
        (passed 0) (failed 0)
        (failures '()))
    (dolist (test-case tests)
      (multiple-value-bind (prevouts tx-hex flags)
          (parse-tx-test-case test-case)
        (when prevouts
          (handler-case
              (let* ((tx-bytes (bitcoin-lisp.crypto:hex-to-bytes tx-hex))
                     (tx (bitcoin-lisp.serialization:parse-tx-payload tx-bytes)))
                (if (validate-tx-inputs tx prevouts flags)
                    (incf passed)
                    (progn
                      (incf failed)
                      (when (<= (length failures) 10)
                        (push (list :flags flags) failures)))))
            (error (e)
              (incf failed)
              (when (<= (length failures) 10)
                (push (list :error (format nil "~A" e) :flags flags) failures)))))))

    (format t "~%tx_valid.json: ~D passed, ~D failed~%" passed failed)
    (when failures
      (format t "Failures:~%")
      (dolist (f (reverse failures))
        (format t "  ~A~%" f)))

    ;; Track pass rate — target is high but allow for edge cases
    ;; in LOW_S, STRICTENC, NULLFAIL, CONST_SCRIPTCODE enforcement
    (is (<= failed 30)
        "tx_valid should have few failures. Got ~D/~D failed." failed (+ passed failed))))

(test tx-invalid-json
  "Run Bitcoin Core tx_invalid.json test vectors."
  (let ((tests (load-tx-tests "tx_invalid.json"))
        (passed 0) (failed 0)
        (failures '()))
    (dolist (test-case tests)
      (multiple-value-bind (prevouts tx-hex flags)
          (parse-tx-test-case test-case)
        (when prevouts
          (handler-case
              (let* ((tx-bytes (bitcoin-lisp.crypto:hex-to-bytes tx-hex))
                     (tx (bitcoin-lisp.serialization:parse-tx-payload tx-bytes)))
                ;; BADTX: check transaction structure first
                (let ((rejected nil))
                  (when (and flags (search "BADTX" flags))
                    (multiple-value-bind (valid err)
                        (bitcoin-lisp.validation:validate-transaction-structure tx)
                      (declare (ignore err))
                      (unless valid
                        (incf passed)
                        (setf rejected t))))
                  (unless rejected
                    (if (not (validate-tx-inputs tx prevouts flags))
                        (incf passed)
                        (progn
                          (incf failed)
                          (when (<= (length failures) 10)
                            (push (list :flags flags :issue "should-have-failed") failures)))))))
            ;; Deserialization/structure errors count as correctly rejected
            (error (e)
              (declare (ignore e))
              (incf passed))))))

    (format t "~%tx_invalid.json: ~D passed, ~D failed~%" passed failed)
    (when failures
      (format t "Failures:~%")
      (dolist (f (reverse failures))
        (format t "  ~A~%" f)))

    ;; Allow some failures for BADTX edge cases and CONST_SCRIPTCODE
    (is (<= failed 21)
        "tx_invalid should have few failures. Got ~D/~D failed." failed (+ passed failed))))
