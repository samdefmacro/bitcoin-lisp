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
    (flexi-streams:with-input-from-sequence (s (%bytes 1 2 3 4))
      (bitcoin-lisp.serialization:read-bytes s 1000))))

(test read-transaction-truncated-errors
  ;; version + a compact-size claiming 65535 inputs, then EOF.
  (signals error
    (flexi-streams:with-input-from-sequence
        (s (%concat-bytes (%bytes 2 0 0 0) (%bytes 253 255 255)))
      (bitcoin-lisp.serialization:read-transaction s))))

(test read-bitcoin-block-truncated-errors
  ;; 80-byte zero header + tx-count 1000, no tx bytes.
  (signals error
    (flexi-streams:with-input-from-sequence
        (s (%concat-bytes (make-array 80 :element-type '(unsigned-byte 8) :initial-element 0)
                          (%bytes 253 232 3)))  ; 0xfd 0x03e8 = 1000
      (bitcoin-lisp.serialization:read-bitcoin-block s))))

;;;; Oversized length / count fields must be rejected

(test read-compact-size-rejects-oversized
  ;; 0xff + 8 bytes encoding a value far above +max-compact-size+.
  (signals error
    (flexi-streams:with-input-from-sequence
        (s (%bytes 255 255 255 255 255 255 255 255 255))
      (bitcoin-lisp.serialization:read-compact-size s))))

(test br-read-bytes-rejects-overrun
  ;; Bounds-checked before allocating, so this errors rather than allocating a
  ;; huge buffer ahead of the overrun.
  (signals error
    (let ((br (bitcoin-lisp.serialization::make-byte-reader-from (%bytes 1 2 3 4))))
      (bitcoin-lisp.serialization::br-read-bytes br 33554432))))

(test inv-payload-rejects-oversized-count
  ;; compact-size 50001 (0xfe + LE32) — exceeds MAX_INV_SZ (50000).
  (signals error
    (bitcoin-lisp.serialization::parse-inv-payload
     (%bytes #xfe #x51 #xc3 0 0))))   ; 50001 = 0x0000c351

(test headers-payload-rejects-oversized-count
  ;; compact-size 2001 (0xfd + LE16) — exceeds MAX_HEADERS_RESULTS (2000).
  (signals error
    (bitcoin-lisp.serialization::parse-headers-payload
     (%bytes #xfd #xd1 #x07))))       ; 2001 = 0x07d1

;;;; Block-relay message count caps (compact block / getblocktxn / blocktxn)

;; compact-size for 50001 (just over +max-block-tx-count+): 0xfe + LE32 0x0000c351
(defparameter +over-block-tx-count-cs+ (%bytes #xfe #x51 #xc3 0 0))

(test compact-block-rejects-oversized-shortids
  ;; 80-byte header + 8-byte nonce + an over-limit short-ids count.
  (signals error
    (flexi-streams:with-input-from-sequence
        (s (%concat-bytes (make-array 88 :element-type '(unsigned-byte 8) :initial-element 0)
                          +over-block-tx-count-cs+))
      (bitcoin-lisp.serialization:read-compact-block s))))

(test getblocktxn-rejects-oversized-count
  ;; 32-byte block hash + an over-limit index count.
  (signals error
    (flexi-streams:with-input-from-sequence
        (s (%concat-bytes (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                          +over-block-tx-count-cs+))
      (bitcoin-lisp.serialization::read-block-txn-request s))))

(test blocktxn-rejects-oversized-count
  (signals error
    (flexi-streams:with-input-from-sequence
        (s (%concat-bytes (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                          +over-block-tx-count-cs+))
      (bitcoin-lisp.serialization::read-block-txn-response s))))

(test addrv2-rejects-oversized-count
  ;; addrv2 now rejects (not silently truncates) above MAX_ADDR_TO_SEND (1000).
  ;; compact-size 1001 = 0xfd + LE16 0x07e9... (1001 = 0x03e9 -> bytes e9 03).
  (signals error
    (bitcoin-lisp.serialization:parse-addrv2-payload
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
          (try (lambda () (flexi-streams:with-input-from-sequence (s bytes)
                            (bitcoin-lisp.serialization:read-transaction s))))
          (try (lambda () (flexi-streams:with-input-from-sequence (s bytes)
                            (bitcoin-lisp.serialization:read-bitcoin-block s))))
          (try (lambda () (bitcoin-lisp.serialization::br-read-transaction
                           (bitcoin-lisp.serialization::make-byte-reader-from bytes))))
          (incf done))))
    (is (= 400 done))
    (is (plusp errored))))

;;;; End-to-end: a malformed message disconnects the peer, not the node

(defun %fake-ready-peer ()
  "A peer object in the :ready state with a socket-less (but 'connected')
connection — enough to drive dispatch + disconnect without a real socket."
  (let ((conn (bitcoin-lisp.networking::make-connection
               :host "127.0.0.1" :port 48333 :connected t)))
    (bitcoin-lisp.networking:make-peer
     :connection conn :state :ready :address "127.0.0.1")))

(test malformed-message-disconnects-peer
  ;; Drive an oversized inv (count 50001 > MAX_INV_SZ) through the REAL per-peer
  ;; dispatch isolation used by the drain loop (safely-dispatch-peer-message).
  ;; The parse error must be caught and disconnect only this peer — never escape
  ;; to the caller (which in production is the sync thread). Validates #109.
  (let ((peer (%fake-ready-peer))
        (ctx (bitcoin-lisp.networking::make-ibd)))
    (let ((still-connected
            (bitcoin-lisp.networking::safely-dispatch-peer-message
             peer "inv" (%bytes #xfe #x51 #xc3 0 0) nil nil nil ctx)))
      (is (null still-connected))
      (is (eq :disconnected (bitcoin-lisp.networking:peer-state peer)))
      (is (null (bitcoin-lisp.networking::peer-connection peer))))))

(test wellformed-message-keeps-peer-connected
  ;; Control: a benign (unknown, ignored) message dispatches without error, so
  ;; the peer stays connected — proving the isolation disconnects on FAILURE, not
  ;; unconditionally.
  (let ((peer (%fake-ready-peer))
        (ctx (bitcoin-lisp.networking::make-ibd)))
    (let ((still-connected
            (bitcoin-lisp.networking::safely-dispatch-peer-message
             peer "xyzzy" (%bytes) nil nil nil ctx)))
      (is (eq t still-connected))
      (is (eq :ready (bitcoin-lisp.networking:peer-state peer)))
      (is-true (bitcoin-lisp.networking::peer-connection peer)))))

(test fuzz-message-vector-parsers-terminate
  ;; Random payloads to the inv/headers parsers must terminate (the count caps +
  ;; EOF errors bound them).
  (let ((state (sb-ext:seed-random-state 777))
        (done 0))
    (dotimes (i 200)
      (let ((bytes (%random-bytes (random 200 state) state)))
        (ignore-errors (bitcoin-lisp.serialization::parse-inv-payload bytes))
        (ignore-errors (bitcoin-lisp.serialization::parse-headers-payload bytes))
        (incf done)))
    (is (= 200 done))))
