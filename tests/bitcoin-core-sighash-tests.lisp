(in-package #:bitcoin-lisp.tests)

(def-suite :bitcoin-core-sighash-tests
  :description "Bitcoin Core sighash.json compatibility tests"
  :in :bitcoin-lisp-tests)

(in-suite :bitcoin-core-sighash-tests)

(defun load-sighash-tests ()
  "Load sighash test vectors from Bitcoin Core's sighash.json."
  (let ((path (merge-pathnames
               "refs/bitcoin/src/test/data/sighash.json"
               (asdf:system-source-directory :bitcoin-lisp))))
    (with-open-file (stream path :direction :input)
      (yason:parse stream))))

(test sighash-json-vectors
  "Run all Bitcoin Core sighash.json test vectors."
  (let ((tests (load-sighash-tests))
        (passed 0)
        (failed 0)
        (failures '()))
    (dolist (test-case tests)
      ;; Skip the header comment (first element is a list of strings)
      (when (and (listp test-case)
                 (= (length test-case) 5)
                 (stringp (first test-case)))
        (let* ((raw-tx-hex (first test-case))
               (script-hex (second test-case))
               (input-index (third test-case))
               (hash-type-raw (fourth test-case))
               (expected-hex (fifth test-case)))
          (handler-case
              (let* ((tx-bytes (bitcoin-lisp.crypto:hex-to-bytes raw-tx-hex))
                     (tx (bitcoin-lisp.serialization:parse-tx-payload tx-bytes))
                     (subscript (bitcoin-lisp.crypto:hex-to-bytes script-hex))
                     ;; hashType can be negative (signed int32), mask to unsigned
                     (hash-type (logand hash-type-raw #xFFFFFFFF))
                     (computed (bitcoin-lisp.coalton.interop:compute-legacy-sighash
                                tx input-index subscript hash-type))
                     ;; sighash.json uses display byte order (reversed from internal)
                     (expected (reverse (bitcoin-lisp.crypto:hex-to-bytes expected-hex))))
                (if (equalp computed expected)
                    (incf passed)
                    (progn
                      (incf failed)
                      (when (<= (length failures) 10)
                        (push (list :index (+ passed failed)
                                    :input-index input-index
                                    :hash-type hash-type
                                    :expected expected-hex
                                    :computed (bitcoin-lisp.crypto:bytes-to-hex computed))
                              failures)))))
            (error (e)
              (incf failed)
              (when (<= (length failures) 10)
                (push (list :index (+ passed failed)
                            :error (format nil "~A" e))
                      failures)))))))

    (format t "~%Sighash Tests: ~D passed, ~D failed~%" passed failed)
    (when failures
      (format t "~%Failures (first ~D):~%" (length failures))
      (dolist (f (reverse failures))
        (format t "  ~A~%" f)))

    (is (zerop failed)
        "All sighash tests must pass. ~D failed." failed)))
