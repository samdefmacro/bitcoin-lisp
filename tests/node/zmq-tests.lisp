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
             (is (= 1 (bl:zmq-start-publishers
                       (list (list "hashblock" address 1000)))))
             (let ((lines (%zmq-collect address "hashblock" 1
                                        (lambda () (bl::zmq-notify-hash-block hash)))))
               (is (= 1 (length lines)) "an independent subscriber must receive the message")
               (let ((parts (uiop:split-string (first lines) :separator " ")))
                 (is (string= "OK" (first parts)))
                 (is (string= "hashblock" (second parts)))
                 ;; 00,01,...,1f went in; 1f,...,01,00 must come out.
                 (is (string= "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
                              (third parts))))))
        (bl:zmq-stop-publishers)
        (ignore-errors (delete-file path))))))

(test zmq-sequence-numbers-advance-so-a-subscriber-can-see-a-gap
  "The third frame is a per-topic counter, incremented only after a successful
send (Core :205). Its purpose is that a subscriber can tell it MISSED
something; if it never advanced, a dropped message would be invisible."
  (multiple-value-bind (address path) (%zmq-test-address "seq")
    (let ((hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7)))
      (unwind-protect
           (progn
             (bl:zmq-start-publishers (list (list "hashtx" address 1000)))
             (let ((lines (%zmq-collect address "hashtx" 3
                                        (lambda () (bl::zmq-notify-hash-tx hash)))))
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
        (bl:zmq-stop-publishers)
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
             (bl:zmq-start-publishers (list (list "sequence" address 1000)))
             ;; Block connected: label C, no counter -> 33 bytes.
             (let ((lines (%zmq-collect address "sequence" 1
                                        (lambda ()
                                          (bl::zmq-notify-sequence hash #\C)))))
               (is (= 1 (length lines)))
               (when lines
                 (let ((body (third (uiop:split-string (first lines) :separator " "))))
                   (is (= 66 (length body)) "33 bytes: hash + label, no counter")
                   (is (string= "43" (subseq body 64 66)) "label C"))))
             ;; Tx added: label A with a mempool counter -> 41 bytes.
             (let ((lines (%zmq-collect address "sequence" 1
                                        (lambda ()
                                          (bl::zmq-notify-sequence hash #\A 258)))))
               (is (= 1 (length lines)))
               (when lines
                 (let ((body (third (uiop:split-string (first lines) :separator " "))))
                   (is (= 82 (length body)) "41 bytes: hash + label + counter")
                   (is (string= "41" (subseq body 64 66)) "label A")
                   ;; 258 = 0x0102, little-endian over 8 bytes.
                   (is (string= "0201000000000000" (subseq body 66 82)))))))
        (bl:zmq-stop-publishers)
        (ignore-errors (delete-file path))))))

(test zmq-config-asks-for-nothing-when-no-topic-is-set
  "The property that keeps libzmq off the startup path: with no -zmqpub*
option there are no publishers to start, so the library is never loaded and a
host without it runs the node perfectly well."
  (is (null (bl:zmq-specs-from-config '())))
  (is (null (bl:zmq-specs-from-config '(("zmqpubhashblock" . "")))))
  ;; Per-topic address and per-topic hwm, in Core's topic order.
  (is (equal '(("hashblock" "tcp://127.0.0.1:28332" 1000)
               ("rawtx" "ipc:///tmp/x.sock" 50))
             (bl:zmq-specs-from-config
              '(("zmqpubrawtx" . "ipc:///tmp/x.sock")
                ("zmqpubrawtxhwm" . "50")
                ("zmqpubhashblock" . "tcp://127.0.0.1:28332")))))
  (signals error
    (bl:zmq-specs-from-config
     '(("zmqpubhashtx" . "ipc:///tmp/y.sock") ("zmqpubhashtxhwm" . "-1")))))

(test zmq-getzmqnotifications-reports-active-publishers
  "getzmqnotifications must report what is actually bound, with Core's 'pub'
prefix on the type."
  (is (equalp #() (bl.rpc::rpc-getzmqnotifications nil nil))
      "no publishers -> an empty array, not null")
  (multiple-value-bind (address path) (%zmq-test-address "rpc")
    (unwind-protect
         (progn
           (bl:zmq-start-publishers (list (list "rawblock" address 42)))
           (let ((result (bl.rpc::rpc-getzmqnotifications nil nil)))
             (is (= 1 (length result)))
             (let ((entry (elt result 0)))
               (is (string= "pubrawblock" (cdr (assoc "type" entry :test #'string=))))
               (is (string= address (cdr (assoc "address" entry :test #'string=))))
               (is (= 42 (cdr (assoc "hwm" entry :test #'string=)))))))
      (bl:zmq-stop-publishers)
      (ignore-errors (delete-file path)))))

;;;; --- The hooks must be CONNECTED ---
;;;;
;;;; Publishers that work are worth nothing if nothing in the node calls them.
;;;; These drive the REAL paths -- accept-validated-tx, mempool-remove,
;;;; connect-block, the reorg disconnect -- with a live publisher bound and an
;;;; independent subscriber reading, and require the message to arrive.

(defun %zmq-open-subscriber (address topic count)
  (uiop:launch-program
   (list "python3" (%zmq-subscriber-script) address topic (princ-to-string count))
   :output :stream :error-output :stream))

(defun %zmq-drain (sub &optional (limit 50))
  (let ((lines '()))
    (loop repeat limit
          while (listen (uiop:process-info-output sub))
          do (push (read-line (uiop:process-info-output sub) nil nil) lines))
    (nreverse (remove nil lines))))

(defun %zmq-await-attached (sub warmup-thunk)
  "Publish WARMUP-THUNK until the subscriber proves it is attached. A PUB
socket silently drops everything sent before a subscriber finishes connecting,
so without this the tests below would be coin flips rather than tests."
  (sleep 0.5)
  (loop repeat 60
        do (funcall warmup-thunk)
           (sleep 0.05)
           (let ((lines (%zmq-drain sub)))
             (when lines (return t)))))

(defmacro %with-zmq-hook-test ((address topic sub &key (count 40)) &body body)
  "Bind one publisher on TOPIC, attach an independent subscriber, and run BODY."
  (let ((path (gensym "PATH")))
    `(multiple-value-bind (,address ,path) (%zmq-test-address ,topic)
       (unwind-protect
            (progn
              (bl:zmq-start-publishers (list (list ,topic ,address 1000)))
              (let ((,sub (%zmq-open-subscriber ,address ,topic ,count)))
                (unwind-protect (progn ,@body)
                  (ignore-errors (uiop:terminate-process ,sub))
                  (ignore-errors (uiop:wait-process ,sub)))))
         (bl:zmq-stop-publishers)
         (ignore-errors (delete-file ,path))))))

(test zmq-mempool-acceptance-is-wired-to-the-publisher
  "accept-validated-tx must publish. Without this the node runs with ZMQ
'enabled' and a subscriber that never hears a thing."
  (%with-zmq-hook-test (address "sequence" sub)
    (let ((mempool (bl.mp:make-mempool))
          (warm (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1)))
      (is-true (%zmq-await-attached
                sub (lambda () (bl::zmq-notify-sequence warm #\C))))
      ;; The real path.
      (let* ((tx (make-mempool-test-tx :input-id 150))
             (txid (bl.ser:transaction-hash tx)))
        (bl.mp:accept-validated-tx mempool txid tx 5000 300)
        (sleep 0.5)
        (let* ((lines (%zmq-drain sub))
               (wanted (string-downcase
                        (bl.crypto:bytes-to-hex (reverse (copy-seq txid))))))
          (is-true
           (some (lambda (l)
                   (let ((body (third (uiop:split-string l :separator " "))))
                     (and body
                          (>= (length body) 64)
                          (string= wanted (subseq body 0 64))
                          ;; label A: a mempool acceptance
                          (string= "41" (subseq body 64 66)))))
                 lines)
           "accept-validated-tx must publish a sequence 'A' for the accepted tx"))))))

(test zmq-mempool-removal-is-wired-but-a-mined-tx-is-not-reported-twice
  "A non-block removal publishes sequence 'R'. A removal BY A BLOCK must not:
the block notification announces those, and reporting here as well would show
subscribers a removal that never happened (Core :172, \"called for all
non-block inclusion reasons\")."
  (%with-zmq-hook-test (address "sequence" sub)
    (let ((mempool (bl.mp:make-mempool))
          (warm (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2)))
      (is-true (%zmq-await-attached
                sub (lambda () (bl::zmq-notify-sequence warm #\C))))
      (flet ((removal-labels-for (tx reason)
               (let ((txid (bl.ser:transaction-hash tx)))
                 (bl.mp:accept-validated-tx mempool txid tx 5000 300)
                 (sleep 0.3)
                 (%zmq-drain sub)               ; discard the acceptance
                 (let ((bl.mp:*mempool-removal-reason* reason))
                   (bl.mp:mempool-remove mempool txid))
                 (sleep 0.5)
                 (let ((wanted (string-downcase
                                (bl.crypto:bytes-to-hex (reverse (copy-seq txid))))))
                   (loop for l in (%zmq-drain sub)
                         for body = (third (uiop:split-string l :separator " "))
                         when (and body (>= (length body) 66)
                                   (string= wanted (subseq body 0 64)))
                           collect (subseq body 64 66))))))
        ;; Evicted: an 'R' (0x52) is published.
        (is (member "52" (removal-labels-for (make-mempool-test-tx :input-id 151) :size-limit)
                    :test #'string=)
            "a non-block removal must publish sequence 'R'")
        ;; Mined: nothing.
        (is (null (removal-labels-for (make-mempool-test-tx :input-id 152) :block))
            "a removal by a block must NOT publish a removal")))))

(test zmq-connect-block-is-wired-to-the-publisher
  "connect-block must publish hashblock. Drives the real validation path.

hashblock is Core's UpdatedBlockTip notification, which says nothing during
initial block download (zmqnotificationinterface.cpp:151-159), so the node
stands outside IBD here."
  (with-network (:mainnet)
   (with-tx-relay-out-of-ibd
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (make-activate-block-fixture "zmq-connect")
     (%with-zmq-hook-test (address "hashblock" sub)
       (let ((warm (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3)))
         (is-true (%zmq-await-attached
                   sub (lambda () (bl::zmq-notify-hash-block warm))))
         (let* ((hash (first (make-test-chain-hashes #xD0 1)))
                (block1 (make-reorg-test-block genesis-hash hash 1)))
           (bl.val:connect-block block1 chain-state block-store utxo-set)
           (sleep 0.5)
           (let ((wanted (string-downcase
                          (bl.crypto:bytes-to-hex (reverse (copy-seq hash))))))
             (is-true (some (lambda (l)
                              (string= wanted (third (uiop:split-string l :separator " "))))
                            (%zmq-drain sub))
                      "connect-block must publish the connected block's hash")))))
     (clear-undo-cache)))))

(test zmq-connect-block-publishes-each-transaction-in-the-block
  "The per-transaction half of BlockConnected, which the hashblock test above
cannot reach: with neither hashtx nor rawtx subscribed, zmq-notify-block-
connected skips the loop over the block's transactions entirely. That loop read
BITCOIN-BLOCK-TRANSACTIONS -- a LIST (types.lisp:534) -- with LOOP ... ACROSS,
so the first block published with hashtx enabled would have signalled a type
error instead of notifying. The compiler said so on every clean build; nothing
executed it."
  (with-network (:mainnet)
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (make-activate-block-fixture "zmq-blocktx")
     (%with-zmq-hook-test (address "hashtx" sub)
       (let ((warm (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9)))
         (is-true (%zmq-await-attached
                   sub (lambda () (bl::zmq-notify-hash-tx warm))))
         (let* ((hash (first (make-test-chain-hashes #xD4 1)))
                (block1 (make-reorg-test-block genesis-hash hash 1))
                (coinbase (first (bl.ser:bitcoin-block-transactions
                                  block1)))
                (txid (bl.ser:transaction-hash coinbase)))
           (bl.val:connect-block block1 chain-state block-store utxo-set)
           (sleep 0.5)
           (let ((wanted (string-downcase
                          (bl.crypto:bytes-to-hex (reverse (copy-seq txid))))))
             (is-true (some (lambda (l)
                              (let ((body (third (uiop:split-string l :separator " "))))
                                (and body (string= wanted (subseq body 0 (min 64 (length body)))))))
                            (%zmq-drain sub))
                      "connect-block must publish the txid of every transaction
                       in the connected block")))))
     (clear-undo-cache))))

(test zmq-publisher-specs-reach-the-node-from-config
  "apply-config-globals must record what -zmqpub* asked for, or start-node has
nothing to bind and the option is silently inert."
  (let ((bl::*zmq-publisher-specs* '()))
    (apply-config-globals '())
    (is (null bl::*zmq-publisher-specs*)
        "no -zmqpub option means no publishers, and libzmq stays unloaded")
    (apply-config-globals
     '(("zmqpubhashblock" . "tcp://127.0.0.1:28332") ("zmqpubhashblockhwm" . "7")))
    (is (equal '(("hashblock" "tcp://127.0.0.1:28332" 7))
               bl::*zmq-publisher-specs*))))

(test zmq-binds-a-unix-socket-address-spelled-cores-way
  "Core documents a unix socket for -zmqpub* as `unix:<path>' (doc/zmq.md:87),
and interface_zmq.py:148 starts the node with that spelling while its own
subscribers connect to `ipc://<path>' -- one socket file under two names.
libzmq binds only the `ipc://' spelling here and answers EINVAL for the other,
so every unix-socket publisher failed to bind: the node published nothing and
the test's ipc half received no notification at all.

Only the prefix is rewritten, and it is rewritten where Core rewrites it: in
the address the notifier is given (zmq/zmqnotificationinterface.cpp:60-67), so
getzmqnotifications reports `ipc://<path>', which interface_zmq.py:254 reads.
An earlier version of this test pinned the configured spelling instead."
  (multiple-value-bind (address path) (%zmq-test-address "unix-spelling")
    (declare (ignore address))
    (let ((configured (format nil "unix:~A" path)))
      (unwind-protect
           (progn
             (is (= 1 (bl:zmq-start-publishers (list (list "hashblock" configured 1000))))
                 "a unix:<path> publisher must bind")
             ;; Reported as rewritten, as Core reports it.
             (is (equal (list (list "pubhashblock" (format nil "ipc://~A" path) 1000))
                        (bl:zmq-notifications-info)))
             ;; And it really publishes: an independent subscriber on the
             ;; ipc:// spelling of the same path reads the frame.
             (let* ((hash (make-array 32 :element-type '(unsigned-byte 8)
                                         :initial-element #xcd))
                    (lines (%zmq-collect (format nil "ipc://~A" path) "hashblock" 1
                                         (lambda () (bl::zmq-notify-hash-block hash)))))
               (is (= 1 (length lines))
                   "nothing arrived on the socket the operator named")))
        (bl:zmq-stop-publishers)
        (ignore-errors (delete-file path))))
    ;; Controls: every other spelling is passed through untouched.
    (is (equal "tcp://127.0.0.1:28332"
               (bl::%zmq-bind-endpoint "tcp://127.0.0.1:28332")))
    (is (equal "ipc:///tmp/x.sock" (bl::%zmq-bind-endpoint "ipc:///tmp/x.sock")))))

(test zmq-rawtx-is-cores-with-witness-serialization
  "Core publishes rawtx as TX_WITH_WITNESS (zmqpublishnotifier.cpp:251), the
same encoding every RPC hex field uses. Ours published the LEGACY bytes, so a
subscriber comparing the rawtx it received against the same transaction from
getrawtransaction or getblock saw two different encodings for every segwit
transaction -- the coinbase of every block mined since segwit activated
included, since it carries the BIP141 reserved witness item.

interface_zmq.py's sync-up loop is exactly that comparison (:161-173: the
notification is matched against the block hash, the coinbase txid, the raw
block and the raw coinbase), so the rawtx subscriber ignored one notification
and then timed out, once per generated block, until the test's own deadline. It
was not a message arriving late -- it was a message that could never match.

Read back with the independent pyzmq subscriber, like every publisher test here."
  (multiple-value-bind (address path) (%zmq-test-address "rawtx-witness")
    (unwind-protect
         (let* ((tx (bl.bytes:with-byte-reader (r (make-witness-test-tx-bytes))
                      (bl.ser:br-read-transaction r)))
                (witness-hex (bl.crypto:bytes-to-hex
                              (bl.ser:transaction-wire-bytes tx)))
                (legacy-hex (bl.crypto:bytes-to-hex
                             (bl.ser:serialize-transaction tx))))
           ;; The fixture must really carry a witness, or the two encodings are
           ;; equal and this test proves nothing.
           (is-true (bl.ser:transaction-has-witness-p tx))
           (is (string/= witness-hex legacy-hex)
               "the fixture's two encodings are identical, so this is vacuous")
           (is (= 1 (bl:zmq-start-publishers (list (list "rawtx" address 1000)))))
           (let ((lines (%zmq-collect address "rawtx" 1
                                      (lambda ()
                                        (bl:zmq-notify-tx-accepted
                                         tx (bl.ser:transaction-hash tx) 1)))))
             (is (= 1 (length lines)))
             ;; "OK <topic> <body-hex> <sequence>"
             (let ((body (and lines (third (uiop:split-string (first lines) :separator " ")))))
               (is-true (and body (string-equal witness-hex body))
                        "rawtx must carry the witness serialization, got ~S" body)
               (is-false (and body (string-equal legacy-hex body))
                         "rawtx is still the legacy serialization"))))
      (bl:zmq-stop-publishers)
      (ignore-errors (delete-file path)))))

(test zmq-topics-on-one-address-share-one-socket
  "Core binds an ADDRESS once and every topic published to it shares that
socket (CZMQAbstractPublishNotifier::Initialize, zmq/zmqpublishnotifier.cpp:
74-101 -- `reuse the socket of the notifier already bound to this address').

We bound per TOPIC, so the second and every later topic on one endpoint failed
with `Address already in use' and was silently not published. That is the
ORDINARY configuration -- `-zmqpubhashblock=X -zmqpubhashtx=X
-zmqpubrawblock=X -zmqpubrawtx=X' on one endpoint -- and it is what
interface_zmq.py uses throughout; the test never received its first
notification and timed out."
  (multiple-value-bind (address path) (%zmq-test-address "shared")
    (unwind-protect
         (progn
           (is (= 4 (bl:zmq-start-publishers
                     (list (list "hashblock" address 1000)
                           (list "hashtx" address 1000)
                           (list "rawblock" address 1000)
                           (list "rawtx" address 1000))))
               "all four topics on one endpoint must start")
           (let ((sockets (remove-duplicates
                           (mapcar #'bl::zmq-publisher-socket bl::*zmq-publishers*)
                           :test #'cffi:pointer-eq)))
             (is (= 1 (length sockets))
                 "one address is one socket, shared by every topic on it"))
           ;; And a DIFFERENT address is a different socket, so the sharing is
           ;; by address and not a blanket single-socket bug.
           (multiple-value-bind (address2 path2) (%zmq-test-address "shared2")
             (unwind-protect
                  (progn
                    (is (= 1 (bl:zmq-start-publishers
                              (list (list "sequence" address2 1000)))))
                    (is (= 2 (length (remove-duplicates
                                      (mapcar #'bl::zmq-publisher-socket
                                              bl::*zmq-publishers*)
                                      :test #'cffi:pointer-eq)))
                        "a second address must bind its own socket"))
               (ignore-errors (delete-file path2))))
           ;; A subscriber on the shared endpoint receives a topic that is NOT
           ;; the first one bound -- the ones that used to fail to bind.
           (let ((hash (make-array 32 :element-type '(unsigned-byte 8)
                                      :initial-element #xab)))
             (let ((lines (%zmq-collect address "hashtx" 1
                                        (lambda () (bl::zmq-notify-hash-tx hash)))))
               (is (= 1 (length lines))
                   "a topic bound after the first must still publish"))))
      (bl:zmq-stop-publishers)
      (ignore-errors (delete-file path)))))

(test zmq-hashblock-announces-the-tip-once-per-step
  "Core publishes hashblock/rawblock from UpdatedBlockTip, not BlockConnected
(zmqnotificationinterface.cpp:151-159, :180-196): once per activation step,
for the new tip, and not at all during initial block download or for a step
that connected nothing. interface_zmq.py:291 reads ONE hashblock across a
two-block reorg; ours published one per connected block."
  (%with-zmq-hook-test (address "hashblock" sub)
    (let* ((warm (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7))
           (a-block (make-reorg-test-block (make-array 32 :element-type '(unsigned-byte 8)
                                                          :initial-element 0)
                                           (first (make-test-chain-hashes #xE1 1)) 1))
           (tip (first (make-test-chain-hashes #xE2 1)))
           (no-block (lambda () nil)))
      (is-true (%zmq-await-attached sub (lambda () (bl::zmq-notify-hash-block warm))))
      (%zmq-drain sub)
      (flet ((heard ()
               (sleep 0.4)
               (let ((wanted (string-downcase
                              (bl.crypto:bytes-to-hex (reverse (copy-seq tip))))))
                 (count-if (lambda (l) (search wanted l)) (%zmq-drain sub)))))
        ;; Two blocks connect in one step: no hashblock until the tip moves,
        ;; then exactly one, for the tip.
        (bl:zmq-notify-block-connected a-block (first (make-test-chain-hashes #xE1 1)))
        (bl:zmq-notify-block-connected a-block tip)
        (is (= 0 (heard)) "a connected block is not a hashblock")
        (bl:zmq-notify-updated-block-tip tip nil no-block)
        (is (= 1 (heard)))
        ;; A step that connected nothing (a pure disconnect) says nothing.
        (bl:zmq-notify-updated-block-tip tip nil no-block)
        (is (= 0 (heard)))
        ;; Nor does one during initial block download.
        (bl:zmq-notify-block-connected a-block tip)
        (bl:zmq-notify-updated-block-tip tip t no-block)
        (is (= 0 (heard)))))))
