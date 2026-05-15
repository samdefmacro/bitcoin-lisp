;; Diagnose which tx_invalid.json cases now wrongly pass after the
;; CHECKMULTISIG FindAndDelete-all-sigs fix.
(asdf:load-system :bitcoin-lisp/tests)
(in-package :bitcoin-lisp.tests)

(let ((tests (load-tx-tests "tx_invalid.json"))
      (case-num 0))
  (dolist (test-case tests)
    (incf case-num)
    (multiple-value-bind (prevouts tx-hex flags)
        (parse-tx-test-case test-case)
      (when prevouts
        (handler-case
            (let* ((tx-bytes (bitcoin-lisp.crypto:hex-to-bytes tx-hex))
                   (tx (bitcoin-lisp.serialization:parse-tx-payload tx-bytes))
                   (rejected nil))
              (when (and flags (search "BADTX" flags))
                (multiple-value-bind (valid err)
                    (bitcoin-lisp.validation:validate-transaction-structure tx)
                  (declare (ignore err))
                  (unless valid (setf rejected t))))
              (unless rejected
                (when (validate-tx-inputs tx prevouts flags)
                  (cl:format cl:t "~&[wrong-pass] case=~D flags=~A tx-hex=~A~%"
                             case-num flags
                             (cl:if (cl:> (cl:length tx-hex) 80)
                                    (cl:subseq tx-hex 0 80)
                                    tx-hex))
                  (when prevouts
                    (cl:format cl:t "  prevouts:~%")
                    (dolist (po prevouts)
                      (cl:format cl:t "    ~A~%" po))))))
          (error (e) (declare (ignore e))))))))
