(in-package #:bitcoin-lisp.tests)

;;; Robustness / malformed-input tests.
;;;
;;; The node is network-facing: a malformed or adversarial peer message must be
;;; rejected with a clean error, never silently parsed as garbage, never crash
;;; or hang the node, and never force an unbounded allocation. These tests feed
;;; truncated, oversized, and random input to the deserializers and assert they
;;; fail safely.

(in-suite :robustness-tests)

(defun %concat-bytes (&rest seqs)
  (apply #'concatenate '(vector (unsigned-byte 8)) seqs))

;;;; Truncated input must error, not return zero-padded garbage

(test read-bytes-rejects-short-read
  ;; read-bytes used to silently return a zero-padded vector on a short read;
  ;; truncated peer/disk input must error instead.
  (signals error
    (bl.bytes:with-byte-reader (s (%bytes 1 2 3 4))
      (bl.bytes:br-read-bytes s 1000))))

(test read-transaction-truncated-errors
  ;; version + a compact-size claiming 65535 inputs, then EOF.
  (signals error
    (bl.bytes:with-byte-reader
        (s (%concat-bytes (%bytes 2 0 0 0) (%bytes 253 255 255)))
      (bl.ser:read-transaction s))))

(test read-bitcoin-block-truncated-errors
  ;; 80-byte zero header + tx-count 1000, no tx bytes.
  (signals error
    (bl.bytes:with-byte-reader
        (s (%concat-bytes (make-array 80 :element-type '(unsigned-byte 8) :initial-element 0)
                          (%bytes 253 232 3)))  ; 0xfd 0x03e8 = 1000
      (bl.ser:read-bitcoin-block s))))

;;;; Oversized length / count fields must be rejected

(test read-compact-size-rejects-oversized
  ;; 0xff + 8 bytes encoding a value far above +max-compact-size+.
  (signals error
    (bl.bytes:with-byte-reader
        (s (%bytes 255 255 255 255 255 255 255 255 255))
      (bl.ser:read-compact-size s))))

(test br-read-bytes-rejects-overrun
  ;; Bounds-checked before allocating, so this errors rather than allocating a
  ;; huge buffer ahead of the overrun.
  (signals error
    (let ((br (bl.ser:make-byte-reader-from (%bytes 1 2 3 4))))
      (bl.ser:br-read-bytes br 33554432))))

(test inv-payload-rejects-oversized-count
  ;; compact-size 50001 (0xfe + LE32) — exceeds MAX_INV_SZ (50000).
  (signals error
    (bl.ser:parse-inv-payload
     (%bytes #xfe #x51 #xc3 0 0))))   ; 50001 = 0x0000c351

(test headers-payload-rejects-oversized-count
  ;; compact-size 2001 (0xfd + LE16) — exceeds MAX_HEADERS_RESULTS (2000).
  (signals error
    (bl.ser:parse-headers-payload
     (%bytes #xfd #xd1 #x07))))       ; 2001 = 0x07d1

;;;; Block-relay message count caps (compact block / getblocktxn / blocktxn)

;; compact-size for 50001 (just over +max-block-tx-count+), in its CANONICAL
;; 0xfd + LE16 form. The former 0xfe + LE32 spelling was non-canonical, so the
;; three tests below were passing on "non-canonical ReadCompactSize" and never
;; reached the count cap they exist to prove.
(defparameter +over-block-tx-count-cs+ (%bytes #xfd #x51 #xc3))

(test compact-block-rejects-oversized-shortids
  ;; 80-byte header + 8-byte nonce + an over-limit short-ids count.
  (signals error
    (bl.bytes:with-byte-reader
        (s (%concat-bytes (make-array 88 :element-type '(unsigned-byte 8) :initial-element 0)
                          +over-block-tx-count-cs+))
      (bl.ser:read-compact-block s))))

(test getblocktxn-rejects-oversized-count
  ;; 32-byte block hash + an over-limit index count.
  (signals error
    (bl.bytes:with-byte-reader
        (s (%concat-bytes (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                          +over-block-tx-count-cs+))
      (bl.ser::read-block-txn-request s))))

(test blocktxn-rejects-oversized-count
  (signals error
    (bl.bytes:with-byte-reader
        (s (%concat-bytes (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                          +over-block-tx-count-cs+))
      (bl.ser::read-block-txn-response s))))

(test addrv2-rejects-oversized-count
  ;; addrv2 now rejects (not silently truncates) above MAX_ADDR_TO_SEND (1000).
  ;; compact-size 1001 = 0xfd + LE16 0x07e9... (1001 = 0x03e9 -> bytes e9 03).
  (signals error
    (bl.ser:parse-addrv2-payload
     (%bytes #xfd #xe9 #x03))))

;;;; Fuzz: random/truncated input must terminate with a handled error

(defun %random-bytes (n state)
  (let ((v (make-array n :element-type '(unsigned-byte 8))))
    (dotimes (i n v)
      (setf (aref v i) (random 256 state)))))

(test fuzz-deserializers-terminate-cleanly
  ;; Feed many deterministic-pseudorandom byte vectors to the tx/block
  ;; deserializers (both the stream and byte-reader paths). Each call must
  ;; TERMINATE (no hang) and any failure must be a catchable ERROR (no escaping
  ;; serious-condition). Reaching the final assertion proves all 400 iterations
  ;; terminated; the errored>0 check confirms the inputs actually exercised the
  ;; rejection paths (not all trivially returning).
  (let ((state (sb-ext:seed-random-state 20260529))
        (done 0) (errored 0))
    (flet ((try (thunk)
             (handler-case (progn (funcall thunk) nil)
               (error () (incf errored)))))
      (dotimes (i 400)
        (let ((bytes (%random-bytes (random 280 state) state)))
          (try (lambda () (bl.bytes:with-byte-reader (s bytes)
                            (bl.ser:br-read-transaction s))))
          (try (lambda () (bl.bytes:with-byte-reader (s bytes)
                            (bl.ser:br-read-bitcoin-block s))))
          (try (lambda () (bl.ser:br-read-transaction
                           (bl.ser:make-byte-reader-from bytes))))
          (incf done))))
    (is (= 400 done))
    (is (plusp errored))))

;;;; End-to-end: which malformed messages cost the peer its connection
;;;;
;;;; Core's split, and ours since the dispatch was given Core's shape: a
;;;; payload that simply fails to decode is caught by ProcessMessages, logged
;;;; at debug and FORGIVEN (net_processing.cpp:5269-5287), while a protocol
;;;; vector declaring more elements than the message may carry is a named rule
;;;; inside the handler and calls Misbehaving (inv :4128, getdata :4219,
;;;; headers, addr).

(defun %fake-ready-peer ()
  "A peer object in the :ready state with a socket-less (but 'connected')
connection -- enough to drive dispatch + disconnect without a real socket."
  (let ((conn (make-test-connection
               :host "127.0.0.1" :port 48333 :connected t))
        (peer nil))
    (setf peer (bl.net:make-peer
                :connection conn :state :ready :address "127.0.0.1"))
    peer))

(defun %dispatch-to-fake-peer (command payload &optional (peer (%fake-ready-peer)))
  "Drive COMMAND/PAYLOAD through the shipped per-peer dispatch isolation the
drain loop uses. Returns (values still-connected peer)."
  (values (bl.net::safely-dispatch-peer-message
           peer command payload (bl.ctx:make-node-context) (bl.net::make-ibd))
          peer))

(defun %arm-ping (peer nonce)
  "Give PEER an outstanding ping carrying NONCE, the way SEND-PING leaves it:
the nonce AND the send time, without which RECORD-PONG has no clock to
subtract and raises for a reason that has nothing to do with the payload."
  (setf (bl.net:peer-ping-nonce peer) nonce
        (bl.net:peer-last-ping-time peer) (bl.ser:get-time-micros))
  peer)

(defun %outstanding-ping (peer)
  "PEER's unanswered ping nonce, or NIL once the round trip is closed."
  (bl.net:peer-ping-nonce peer))

(defun %handler-error-count (command)
  "How many handler errors for COMMAND the dispatch has swallowed."
  (gethash command bl.net::*message-handler-errors* 0))

(test over-limit-protocol-vector-misbehaves
  "An inv/getdata/headers count above the protocol maximum is Misbehaving, so
the peer is disconnected -- Core checks the same limits in the handler itself."
  ;; 50001 = MAX_INV_SZ + 1, written CANONICALLY (0xfd + 2 bytes). The
  ;; non-canonical 4-byte form this test used to send never reached the count
  ;; check at all: ReadCompactSize rejected the encoding first, so the test
  ;; proved a different rejection than the one it named. Assert the condition,
  ;; not just the outcome.
  (let ((inv-50001 (%bytes #xfd #x51 #xc3))
        (headers-2001 (%bytes #xfd #xd1 #x07)))
    (signals bl.err:protocol-limit-error (bl.ser:parse-inv-payload inv-50001))
    (signals bl.err:protocol-limit-error (bl.ser:parse-headers-payload headers-2001))
    (dolist (case (list (cons "inv" inv-50001)
                        (cons "getdata" inv-50001)
                        (cons "headers" headers-2001)))
      (multiple-value-bind (still-connected peer)
          (%dispatch-to-fake-peer (car case) (cdr case))
        (is (null still-connected) "~A: an over-limit count must cost the connection" (car case))
        (is (eq :disconnected (bl.net:peer-state peer))
            "~A: an over-limit count must disconnect the peer" (car case))))))

(test an-over-limit-vector-is-punished-in-cores-words
  "Core's words for an over-limit vector are behaviour: p2p_invalid_messages.py
:262 waits for `Misbehaving' and `inv message size = 50001' (likewise getdata
and headers, net_processing.cpp:4130, :4221, :4829), and a getheaders or
getblocks locator over MAX_LOCATOR_SZ is NOT Misbehaving at all but a plain
disconnect logged `getheaders locator size 102 > 101' (:4399-4402, :4272-4275)
-- the address is not discouraged. Ours wrote the parser's text for all of
them and discouraged the locator sender too."
  (dolist (case (list (list "inv" (%bytes #xfd #x51 #xc3) "inv message size = 50001")
                      (list "getdata" (%bytes #xfd #x51 #xc3) "getdata message size = 50001")
                      (list "headers" (%bytes #xfd #xd1 #x07) "headers message size = 2001")))
    (destructuring-bind (command payload expected) case
      (let ((text (nth-value 1 (log-text-of "net" (lambda ()
                                                    (%dispatch-to-fake-peer command payload))))))
        (is-true (search "Misbehaving" text) "~A: not Misbehaving: ~A" command text)
        (is-true (search expected text) "~A: ~A not in ~A" command expected text))))
  (dolist (command '("getheaders" "getblocks"))
    (bl.net:clear-discouraged)
    ;; version, then a locator count of 102
    (multiple-value-bind (result text)
        (log-text-of "net" (lambda ()
                             (multiple-value-list
                              (%dispatch-to-fake-peer command (%bytes 0 0 0 0 102)))))
      (destructuring-bind (still-connected peer) result
        (is (null still-connected))
        (is (eq :disconnected (bl.net:peer-state peer)))
        (is-true (search (format nil "~A locator size 102 > 101" command) text)
                 "~A: ~A" command text)
        (is-false (search "Misbehaving" text))
        (is-false (bl.net:peer-discouraged-p "127.0.0.1")
                  "~A: a long locator disconnects, it does not discourage" command))))
  (bl.net:clear-discouraged))

(test undecodable-payload-keeps-the-peer
  "A payload that merely fails to decode is caught and forgiven, the way Core's
ProcessMessages catch does -- it logs and never sets fDisconnect."
  ;; An inv promising two vectors and carrying none: a plain deserialization
  ;; failure, NOT an over-limit vector. This is the control that says the
  ;; over-limit test above measures the limit and not "any error at all".
  (let* ((truncated (%bytes 2))
         (raised (handler-case (progn (bl.ser:parse-inv-payload truncated) nil)
                   (error (c) c))))
    (is-true raised "the control payload must still fail to decode")
    (is-false (typep raised 'bl.err:protocol-limit-error)
              "the control payload must NOT be an over-limit vector, or this ~
test would be measuring the same rule as the one above")
    (multiple-value-bind (still-connected peer)
        (%dispatch-to-fake-peer "inv" truncated)
      (is (eq t still-connected))
      (is (eq :ready (bl.net:peer-state peer)))
      (is-true (bl.net:peer-connection peer)))))

(test short-fixed-width-payloads-keep-the-peer
  "ping, pong, feefilter, sendcmpct and notfound all read a fixed-width field
with no length check. Core forgives every one of them (:4970, :4990, :5123,
:3907, :5150 deserialize unguarded and rely on the ProcessMessages catch);
dropping the peer instead turned one implementation's framing quirk into an
endless connect/disconnect cycle we caused."
  (dolist (case (list (cons "ping" (%bytes))
                      (cons "ping" (%bytes 1 2 3))
                      (cons "pong" (%bytes))
                      (cons "pong" (%bytes 0 0 0 0))
                      (cons "feefilter" (%bytes 1 2 3))
                      (cons "sendcmpct" (%bytes 1))
                      (cons "notfound" (%bytes))))
    (multiple-value-bind (still-connected peer)
        (%dispatch-to-fake-peer (car case) (cdr case))
      (is (eq t still-connected)
          "~A/~D bytes must be forgiven" (car case) (length (cdr case)))
      (is (eq :ready (bl.net:peer-state peer))
          "~A/~D bytes must keep the peer" (car case) (length (cdr case))))))

(test wellformed-message-keeps-peer-connected
  "Control: a well-formed message dispatches without error, so the peer stays
connected -- the isolation forgives on FAILURE, it does not simply never act."
  ;; A benign unknown command, and a well-formed 8-byte pong that closes the
  ;; outstanding ping. The pong is the load-bearing control for the short-pong
  ;; case above: it proves the fixture can deliver a pong that IS processed.
  (multiple-value-bind (still-connected peer) (%dispatch-to-fake-peer "xyzzy" (%bytes))
    (is (eq t still-connected))
    (is (eq :ready (bl.net:peer-state peer)))
    (is-true (bl.net:peer-connection peer)))
  (let ((peer (%fake-ready-peer)))
    (%arm-ping peer #x3039)
    (is (eq t (%dispatch-to-fake-peer "pong" (%bytes #x39 #x30 0 0 0 0 0 0) peer)))
    (is (eq :ready (bl.net:peer-state peer)))
    (is (null (%outstanding-ping peer))
        "a well-formed pong closes the outstanding ping")))

(test short-pong-cancels-the-outstanding-ping
  "Core's PONG short-payload branch (net_processing.cpp:5030-5035): fewer than
8 bytes cancels the outstanding ping, logs at debug, and keeps the peer."
  (let ((peer (%fake-ready-peer)))
    (%arm-ping peer #x3039)
    (is (eq t (%dispatch-to-fake-peer "pong" (%bytes 0 0 0 0) peer)))
    (is (eq :ready (bl.net:peer-state peer)))
    (is (null (%outstanding-ping peer))
        "a short pong cancels the ping instead of leaving it outstanding")))

(test pong-problems-are-cores
  "Core's PONG handler (net_processing.cpp:4990-5049): a pong with no ping
outstanding is `Unsolicited pong without ping'; a different nonce is `Nonce
mismatch' and leaves the ping outstanding; a zero nonce is `Nonce zero' and
cancels it; each is one net-category line in hex, as p2p_ping.py:60-83 reads
them. Ours cancelled the ping on any nonce and logged only the short case."
  (flet ((pong-log (peer bytes)
           (nth-value 1 (log-text-of "net" (lambda () (%dispatch-to-fake-peer "pong" bytes peer))))))
    (let ((peer (%fake-ready-peer)))
      (is (search "Unsolicited pong without ping, 0 expected, 0 received, 8 bytes"
                  (pong-log peer (%bytes 0 0 0 0 0 0 0 0))))
      (%arm-ping peer #x3039)
      (is (search "Nonce mismatch, 3039 expected, 3038 received, 8 bytes"
                  (pong-log peer (%bytes #x38 #x30 0 0 0 0 0 0))))
      (is (eql #x3039 (%outstanding-ping peer)) "a mismatched pong leaves the ping outstanding")
      (is (search "Nonce zero, 3039 expected, 0 received, 8 bytes"
                  (pong-log peer (%bytes 0 0 0 0 0 0 0 0))))
      (is (null (%outstanding-ping peer)) "a zero nonce cancels it"))))

(test swallowed-handler-errors-are-counted
  "Forgiving a handler error hides OUR bugs too, so each one is counted per
command and the count rides the net debug line."
  (let ((bl.net::*message-handler-errors* (make-hash-table :test 'equal)))
    (%dispatch-to-fake-peer "feefilter" (%bytes 1 2 3))
    (%dispatch-to-fake-peer "feefilter" (%bytes 1 2 3))
    (%dispatch-to-fake-peer "notfound" (%bytes))
    (is (= 2 (%handler-error-count "feefilter")))
    (is (= 1 (%handler-error-count "notfound")))
    ;; Positive control: a message that does NOT raise must not be counted.
    (%dispatch-to-fake-peer "xyzzy" (%bytes))
    (is (= 0 (%handler-error-count "xyzzy")))))

(test a-named-handler-rule-still-disconnects
  "The dispatch is forgiving, not toothless: a rule written inside a handler
still drops the peer. Core disconnects a peer that sends sendaddrv2 or
wtxidrelay after verack (the BIP155/BIP339 negotiation window is over) and so
do we -- and the payload is empty, so nothing about the bytes can be blamed."
  (dolist (command (list "sendaddrv2" "wtxidrelay"))
    (multiple-value-bind (still-connected peer) (%dispatch-to-fake-peer command (%bytes))
      (is (null still-connected) "~A after verack must cost the connection" command)
      (is (eq :disconnected (bl.net:peer-state peer))
          "~A after verack must disconnect the peer" command))))

(test fuzz-message-vector-parsers-terminate
  ;; Random payloads to the inv/headers parsers must terminate (the count caps +
  ;; EOF errors bound them).
  (let ((state (sb-ext:seed-random-state 777))
        (done 0))
    (dotimes (i 200)
      (let ((bytes (%random-bytes (random 200 state) state)))
        (ignore-errors (bl.ser:parse-inv-payload bytes))
        (ignore-errors (bl.ser:parse-headers-payload bytes))
        (incf done)))
    (is (= 200 done))))
