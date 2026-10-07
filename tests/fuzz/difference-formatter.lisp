(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/difference_formatter.cpp at the pin: a fixed block hash
;;;; followed by the buffer, read as a BlockTransactionsRequest -- its indexes
;;;; DifferenceFormatter-coded (blockencodings.h:23-40). A request that reads
;;;; names the hash it was written with and indexes that strictly increase;
;;;; anything else is a stream failure. Ours: PARSE-GETBLOCKTXN-PAYLOAD.

(def-suite :fuzz-difference-formatter-tests :in :bitcoin-lisp-tests
  :description "Core fuzz difference_formatter.cpp")

(in-suite :fuzz-difference-formatter-tests)

(define-fuzz-target difference-formatter
    (buffer :core "difference_formatter.cpp:14-33" :iterations 20000 :max-len 120
            :corpus (lambda (fdp)
                      (%concat-octets
                       (cons (%ser #'bl.ser:bb-write-varint (consume-integral-in-range fdp 0 8))
                             (loop repeat 8
                                   collect (%ser #'bl.ser:bb-write-varint
                                                 (pick-value-in-array fdp (list 0 1 (consume-integral-in-range fdp 0 70000)))))))))
  "Indexes read off a getblocktxn request strictly increase, under the block
hash they were sent with; anything else is refused as a stream failure."
  (let* ((hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x5a))
         (request (fuzz-deserialize (bl.ser:parse-getblocktxn-payload (%concat-octets (list hash buffer))))))
    (fuzz-assert (equalp (fuzz-sabotage (bl.ser:block-txn-request-block-hash request)) hash)
                 "the request names another block")
    (loop for (a b) on (bl.ser:block-txn-request-indexes request)
          while b
          do (fuzz-assert (> b a) "indexes ~D then ~D" a b))))
