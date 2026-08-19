(in-package #:bitcoin-lisp.tests)

(def-suite :zmq-tests
  :description "ZMQ notification publishers (Bitcoin Core src/zmq/)"
  :in :bitcoin-lisp-tests)

(in-suite :zmq-tests)

;;;; Every publisher test below is checked by pyzmq, NOT by a Lisp subscriber.
;;;; A wire protocol verified against itself proves only self-consistency; what
;;;; matters is that an independent ZeroMQ implementation accepts our frames.

(defun %zmq-subscriber-script ()
  (namestring (merge-pathnames "tests/zmq/subscriber.py"
                               (asdf:system-source-directory :bitcoin-lisp))))

(defun %zmq-test-address (name)
  "A private ipc:// endpoint. ipc rather than tcp so concurrent test runs
cannot collide on a port."
  (let ((path (format nil "/tmp/bl-zmqtest-~A-~D.sock" name (random 1000000))))
    (ignore-errors (delete-file path))
    (values (format nil "ipc://~A" path) path)))

(defun %zmq-collect (address topic count publisher-thunk)
  "Run PUBLISHER-THUNK repeatedly until an independent subscriber has read
COUNT messages, or time out. The repetition is required, not sloppiness: a PUB
socket silently drops everything sent before a subscriber has finished
connecting (ZeroMQ's 'slow joiner'), so a single send would be a coin flip."
  (let ((sub (uiop:launch-program
              (list "python3" (%zmq-subscriber-script) address topic
                    (princ-to-string count))
              :output :stream :error-output :stream)))
    (unwind-protect
         (progn
           (sleep 1)
           (let ((lines '()))
             (loop repeat 40
                   until (>= (length lines) count)
                   do (funcall publisher-thunk)
                      (sleep 0.05)
                      (loop while (and (< (length lines) count)
                                       (listen (uiop:process-info-output sub)))
                            do (push (read-line (uiop:process-info-output sub) nil nil)
                                     lines)))
             ;; Drain whatever is still buffered.
             (loop while (and (< (length lines) count)
                              (uiop:process-alive-p sub))
                   repeat 20
                   do (sleep 0.1)
                      (loop while (listen (uiop:process-info-output sub))
                            do (push (read-line (uiop:process-info-output sub) nil nil)
                                     lines)))
             (nreverse (remove nil lines))))
      (ignore-errors (uiop:terminate-process sub))
      (ignore-errors (uiop:wait-process sub)))))

(test zmq-publishes-a-block-hash-an-independent-subscriber-accepts
  "The end-to-end contract: three frames — topic, body, little-endian uint32
sequence — read by pyzmq. The hash goes out REVERSED, in display order, as
Core sends it (zmqpublishnotifier.cpp:221); a subscriber comparing against a
block explorer would otherwise see a mirrored hash and match nothing."
  (multiple-value-bind (address path) (%zmq-test-address "hashblock")
    (let ((hash (make-array 32 :element-type '(unsigned-byte 8))))
      (dotimes (i 32) (setf (aref hash i) i))
      (unwind-protect
           (progn
             (is (= 1 (bitcoin-lisp::zmq-start-publishers
                       (list (list "hashblock" address 1000)))))
             (let ((lines (%zmq-collect address "hashblock" 1
                                        (lambda () (bitcoin-lisp::zmq-notify-hash-block hash)))))
               (is (= 1 (length lines)) "an independent subscriber must receive the message")
               (let ((parts (uiop:split-string (first lines) :separator " ")))
                 (is (string= "OK" (first parts)))
                 (is (string= "hashblock" (second parts)))
                 ;; 00,01,...,1f went in; 1f,...,01,00 must come out.
                 (is (string= "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
                              (third parts))))))
        (bitcoin-lisp::zmq-stop-publishers)
        (ignore-errors (delete-file path))))))

(test zmq-sequence-numbers-advance-so-a-subscriber-can-see-a-gap
  "The third frame is a per-topic counter, incremented only after a successful
send (Core :205). Its purpose is that a subscriber can tell it MISSED
something; if it never advanced, a dropped message would be invisible."
  (multiple-value-bind (address path) (%zmq-test-address "seq")
    (let ((hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7)))
      (unwind-protect
           (progn
             (bitcoin-lisp::zmq-start-publishers (list (list "hashtx" address 1000)))
             (let ((lines (%zmq-collect address "hashtx" 3
                                        (lambda () (bitcoin-lisp::zmq-notify-hash-tx hash)))))
               (is (<= 3 (length lines)))
               (when (<= 3 (length lines))
                 (let ((seqs (mapcar (lambda (l)
                                       (parse-integer (fourth (uiop:split-string l :separator " "))))
                                     (subseq lines 0 3))))
                   ;; Strictly increasing by one, whatever the starting point
                   ;; (the first sends land before the subscriber attaches).
                   (is (equal (list (1+ (first seqs)) (+ 2 (first seqs)))
                              (rest seqs))
                       "sequence numbers must advance by one per message")))))
        (bitcoin-lisp::zmq-stop-publishers)
        (ignore-errors (delete-file path))))))

(test zmq-sequence-topic-carries-the-label-and-optional-counter
  "Core's sequence payload: 32-byte hash, a one-character label, and for the
mempool events an 8-byte little-endian counter. The block events carry no
counter, so the message is 33 bytes rather than 41 — a subscriber distinguishes
them by length."
  (multiple-value-bind (address path) (%zmq-test-address "seqtopic")
    (let ((hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xAB)))
      (unwind-protect
           (progn
             (bitcoin-lisp::zmq-start-publishers (list (list "sequence" address 1000)))
             ;; Block connected: label C, no counter -> 33 bytes.
             (let ((lines (%zmq-collect address "sequence" 1
                                        (lambda ()
                                          (bitcoin-lisp::zmq-notify-sequence hash #\C)))))
               (is (= 1 (length lines)))
               (when lines
                 (let ((body (third (uiop:split-string (first lines) :separator " "))))
                   (is (= 66 (length body)) "33 bytes: hash + label, no counter")
                   (is (string= "43" (subseq body 64 66)) "label C"))))
             ;; Tx added: label A with a mempool counter -> 41 bytes.
             (let ((lines (%zmq-collect address "sequence" 1
                                        (lambda ()
                                          (bitcoin-lisp::zmq-notify-sequence hash #\A 258)))))
               (is (= 1 (length lines)))
               (when lines
                 (let ((body (third (uiop:split-string (first lines) :separator " "))))
                   (is (= 82 (length body)) "41 bytes: hash + label + counter")
                   (is (string= "41" (subseq body 64 66)) "label A")
                   ;; 258 = 0x0102, little-endian over 8 bytes.
                   (is (string= "0201000000000000" (subseq body 66 82)))))))
        (bitcoin-lisp::zmq-stop-publishers)
        (ignore-errors (delete-file path))))))

(test zmq-config-asks-for-nothing-when-no-topic-is-set
  "The property that keeps libzmq off the startup path: with no -zmqpub*
option there are no publishers to start, so the library is never loaded and a
host without it runs the node perfectly well."
  (is (null (bitcoin-lisp::zmq-specs-from-config '())))
  (is (null (bitcoin-lisp::zmq-specs-from-config '(("zmqpubhashblock" . "")))))
  ;; Per-topic address and per-topic hwm, in Core's topic order.
  (is (equal '(("hashblock" "tcp://127.0.0.1:28332" 1000)
               ("rawtx" "ipc:///tmp/x.sock" 50))
             (bitcoin-lisp::zmq-specs-from-config
              '(("zmqpubrawtx" . "ipc:///tmp/x.sock")
                ("zmqpubrawtxhwm" . "50")
                ("zmqpubhashblock" . "tcp://127.0.0.1:28332")))))
  (signals error
    (bitcoin-lisp::zmq-specs-from-config
     '(("zmqpubhashtx" . "ipc:///tmp/y.sock") ("zmqpubhashtxhwm" . "-1")))))

(test zmq-getzmqnotifications-reports-active-publishers
  "getzmqnotifications must report what is actually bound, with Core's 'pub'
prefix on the type."
  (is (equalp #() (bitcoin-lisp.rpc::rpc-getzmqnotifications nil nil))
      "no publishers -> an empty array, not null")
  (multiple-value-bind (address path) (%zmq-test-address "rpc")
    (unwind-protect
         (progn
           (bitcoin-lisp::zmq-start-publishers (list (list "rawblock" address 42)))
           (let ((result (bitcoin-lisp.rpc::rpc-getzmqnotifications nil nil)))
             (is (= 1 (length result)))
             (let ((entry (elt result 0)))
               (is (string= "pubrawblock" (cdr (assoc "type" entry :test #'string=))))
               (is (string= address (cdr (assoc "address" entry :test #'string=))))
               (is (= 42 (cdr (assoc "hwm" entry :test #'string=)))))))
      (bitcoin-lisp::zmq-stop-publishers)
      (ignore-errors (delete-file path)))))
