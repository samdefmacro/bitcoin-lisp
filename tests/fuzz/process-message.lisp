(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/process_message.cpp and process_messages.cpp at the
;;;; pin: messages from fuzzed peers through the node's message processing,
;;;; on a regtest node with a mined chain.
;;;;
;;;; Core's harness: a TestingSetup chain (200 blocks), a fresh PeerManager,
;;;; one to three CNodes filled with random handshake state (FillNode), then
;;;; one message (process_message) or up to thirty (process_messages) of a
;;;; fuzzed type and payload, each run through ProcessMessagesOnce and
;;;; SendMessages. Core's assertions are the node's own: every Assume/assert
;;;; reachable from a message. The harness itself asserts nothing, and a
;;;; std::exception a handler throws is ProcessMessages' to catch and log.
;;;;
;;;; Ours: a regtest node with three mined blocks and synthetic P2WSH(OP_TRUE)
;;;; coins its transactions can spend, fresh for every buffer (so a failure
;;;; replays alone), and peers in the READY state with fuzzed services,
;;;; version, relay and compact-block settings. Each message goes through the
;;;; shipped IBD dispatcher (DISPATCH-IBD-MESSAGE, which SAFELY-DISPATCH-PEER-
;;;; MESSAGE wraps on the live path). The message types are Core's
;;;; ALL_NET_MESSAGE_TYPES, one draw in sixteen a random type; the payloads are
;;;; one draw in four raw bytes and otherwise well-formed messages of the type
;;;; built on the node's own chain -- headers and blocks that connect, a
;;;; transaction that spends a real coin, a getdata for a block we have --
;;;; which is what a libFuzzer corpus gets Core's target past the parsers to.
;;;;
;;;; Where Core's crashes are sanitizer reports and failed asserts, ours are:
;;;; a condition that is not a declared refusal escaping a handler (a TYPE-ERROR,
;;;; an array index out of bounds, a wrong-arity call, an unbound variable, an
;;;; INTERNAL-ERROR -- ProcessMessages would catch and log these, and so does
;;;; SAFELY-DISPATCH-PEER-MESSAGE, which is why the target calls beneath it),
;;;; and a node invariant that no longer holds after a message: the active tip
;;;; is indexed at the best height and its chain links down to genesis, the
;;;; best chain's work never falls, every mempool transaction spends coins
;;;; that exist (in the UTXO set or the mempool) and is the recorded spender of
;;;; each, and a peer once dropped or discouraged stays so.

(def-suite :fuzz-process-message-tests :in :bitcoin-lisp-tests
  :description "Core fuzz process_message.cpp and process_messages.cpp over our P2P dispatch")

(in-suite :fuzz-process-message-tests)

(defparameter +fuzz-net-message-types+
  '("version" "verack" "addr" "addrv2" "sendaddrv2" "inv" "getdata" "merkleblock"
    "getblocks" "getheaders" "tx" "headers" "block" "getaddr" "mempool" "ping" "pong"
    "notfound" "filterload" "filteradd" "filterclear" "sendheaders" "feefilter"
    "sendcmpct" "cmpctblock" "getblocktxn" "blocktxn" "getcfilters" "cfilter"
    "getcfheaders" "cfheaders" "getcfcheckpt" "cfcheckpt" "wtxidrelay" "sendtxrcncl")
  "Core ALL_NET_MESSAGE_TYPES (protocol.h:270-306).")

(defparameter +fuzz-deep-message-types+
  '("tx" "block" "headers" "inv" "getdata" "getheaders" "cmpctblock" "getblocktxn"
    "blocktxn" "notfound" "ping" "feefilter" "addr" "addrv2" "sendcmpct")
  "The types a well-behaved peer sends all the time and whose handlers reach
the chain and the mempool; half the draws come from these, so a sequence is
not over at the first filterload a node without bloom services answers by
disconnecting (as Core's does).")

;;; --- The node and its peers ---------------------------------------------------

(defstruct (fuzz-p2p (:conc-name fp-))
  "One buffer's node: the node-context the dispatcher acts on, the coins its
transactions may spend -- (txid vout value) -- and the chain work last seen."
  ctx node (coins '()) (work 0) (peers '()))

(defmacro with-fuzz-p2p-node ((var) &body body)
  "Run BODY with VAR bound to a FUZZ-P2P over a fresh regtest node: three
mined blocks, eight P2WSH(OP_TRUE) coins in its UTXO set, an empty mempool,
out of initial block download, a fresh IBD context, the clock mocked. The
node's directory is removed afterwards."
  (let ((suffix (gensym "SUFFIX")) (node (gensym "NODE")))
    `(with-network (:regtest)
       (let ((,suffix (format nil "fuzz-p2p-~D-~D" (get-universal-time) (random 1000000000)))
             ;; Core's SetMockTime(1610000000): every clock the node reads,
             ;; block times included, is the buffer's, so a failure replays.
             (bl.ser:*mock-time* 1610000000)
             (bl.net:*highest-header-seen* bl.net:*highest-header-seen*))
         ;; The tx-request tracker and the last block's transaction map are
         ;; process-wide: start from empty and leave nothing for the suites
         ;; that run after this one.
         (bl.net:reset-txdownloadman)
         (unwind-protect
              (with-ibd-context
                (with-tx-relay-out-of-ibd
                  (let ((,node (regtest-node-fixture ,suffix)))
                    (generate-regtest-blocks ,node 3)
                    (let ((,var (%make-fuzz-p2p ,node)))
                      ;; The pump is what hands the node's mempool to the IBD
                      ;; context the block-connect path reads it from; a pass
                      ;; over no peers does that and nothing else.
                      (bl.net:pump-peer-messages '() (fp-ctx ,var) bl.net:*ibd-context*)
                      ,@body))))
           (bl.net:reset-txdownloadman)
           (clear-recent-block-txs)
           (uiop:delete-directory-tree (regtest-node-base-path ,suffix)
                                       :validate t :if-does-not-exist :ignore))))))

(defun %fuzz-coin-txid (i)
  (bl.crypto:sha256 (map '(vector (unsigned-byte 8)) #'char-code (format nil "fuzz-p2p-coin-~D" i))))

(defun %make-fuzz-p2p (node)
  (let ((utxo (bl:node-utxo-set node))
        (coins '()))
    (dotimes (i 8)
      (let ((txid (%fuzz-coin-txid i)))
        (bl.store:add-utxo utxo txid 0 100000000 +p2wsh-op-true+ 1)
        (push (list txid 0 100000000) coins)))
    (let ((ctx (bl.ctx:make-node-context
                :chain-state (bl:node-chain-state node)
                :utxo-set utxo
                :block-store (bl:node-block-store node)
                :mempool (bl:node-mempool node))))
      (make-fuzz-p2p :ctx ctx :node node :coins (nreverse coins)
                     :work (%fuzz-tip-work ctx)))))

(defun %fuzz-tip (ctx)
  (let ((cs (bl.ctx:node-context-chain-state ctx)))
    (bl.store:get-block-index-entry cs (bl.store:best-block-hash cs))))

(defun %fuzz-tip-work (ctx)
  (let ((tip (%fuzz-tip ctx)))
    (if tip (bl.store:block-index-entry-chain-work tip) 0)))

(defun %fuzz-p2p-peer (fdp id)
  "Core ConsumeNode + FillNode for a peer past its handshake. One peer in four
is wholly fuzzed -- services, version, relay, direction, connection type and
negotiated features; the rest are the ordinary full-relay peer (NODE_NETWORK
and NODE_WITNESS, protocol 70016, relaying), the shape a corpus would favour
because it is the one whose messages every handler takes."
  (let* ((random (zerop (consume-integral-in-range fdp 0 3)))
         (services (if random (consume-integral fdp :u64) #x409))
         (peer (bl.net:make-peer
                :id id
                :connection (make-test-connection :host "127.0.0.1" :port (+ 18444 id) :connected t)
                :state :ready
                :address "127.0.0.1"
                :services services
                :version (bl.bytes:with-byte-reader
                             (in (bl.ser:make-version-message-bytes
                                  :version (if random (consume-integral-in-range fdp 31800 #x7fffffff) 70016)
                                  :services services
                                  :relay (or (not random) (consume-bool fdp))))
                           (bl.ser:read-version-message in))
                :inbound (consume-bool fdp)
                :conn-type (if random
                               (pick-value-in-array fdp '(:inbound :outbound-full-relay :block-relay
                                                          :feeler :addr-fetch :manual))
                               (pick-value-in-array fdp '(:inbound :outbound-full-relay)))
                :start-height (consume-integral-in-range fdp 0 10))))
    (setf (bl.net:peer-addr-relay-enabled peer) (or (not random) (consume-bool fdp))
          (bl.net:peer-wtxid-relay peer) (consume-bool fdp)
          (bl.net:peer-prefers-headers peer) (consume-bool fdp)
          (bl.net:peer-wants-addrv2 peer) (consume-bool fdp)
          (bl.net:peer-compact-block-version peer) (pick-value-in-array fdp '(0 1 2)))
    peer))

;;; --- The messages -------------------------------------------------------------------

(defun %payload (framed) (subseq framed 24))

(defun %fuzz-known-hash (fdp p2p)
  "A hash the node knows -- a block of its chain, a coin's txid, a mempool
transaction -- or 32 random bytes."
  (let* ((ctx (fp-ctx p2p))
         (tip (%fuzz-tip ctx)))
    (call-one-of fdp
      (bl.store:block-index-entry-hash tip)
      (let ((e (bl.store:entry-ancestor-at-height
                tip (consume-integral-in-range fdp 0 (bl.store:block-index-entry-height tip)))))
        (bl.store:block-index-entry-hash e))
      (first (pick-value-in-array fdp (fp-coins p2p)))
      (let ((txids '()))
        (bl.mp:mempool-for-each (bl.ctx:node-context-mempool ctx)
                                (lambda (txid e) (declare (ignore e)) (push txid txids)))
        (if txids (pick-value-in-array fdp txids) (consume-uint256 fdp)))
      (consume-uint256 fdp))))

(defun %fuzz-inv-list (fdp p2p)
  (loop repeat (consume-integral-in-range fdp 0 6)
        collect (bl.ser:make-inv-vector
                 :type (pick-value-in-array fdp (list 1 2 3 4 5 #x40000001 #x40000002 #x40000003
                                                      (consume-integral fdp :u32)))
                 :hash (%fuzz-known-hash fdp p2p))))

(defun %fuzz-header-on (fdp prev-entry)
  "A header on PREV-ENTRY, its time just after the parent's (or anywhere):
usually on regtest's nBits and ground to meet it, else with nBits from the
buffer and whatever proof of work that leaves."
  (let* ((regtest-bits (consume-bool fdp))
         (header (bl.ser:make-block-header
                  :version (if (consume-bool fdp) #x20000000 (consume-integral fdp :i32))
                  :prev-block (bl.store:block-index-entry-hash prev-entry)
                  :merkle-root (consume-uint256 fdp)
                  :timestamp (if (consume-bool fdp)
                                 (min #xffffffff
                                      (+ (bl.ser:block-header-timestamp
                                          (bl.store:block-index-entry-header prev-entry))
                                         (consume-integral-in-range fdp 1 7200)))
                                 (consume-integral fdp :u32))
                  :bits (if regtest-bits #x207fffff (consume-integral fdp :u32))
                  :nonce (consume-integral-in-range fdp 0 #xffff))))
    (if regtest-bits (grind-header-pow header) header)))

(defun %fuzz-spend (fdp p2p)
  "A transaction spending one or two of the node's coins into one or two
P2WSH(OP_TRUE) outputs, the fee drawn from the buffer; its outputs become
coins a later message may spend."
  (let* ((coins (loop repeat (consume-integral-in-range fdp 1 2)
                      collect (pick-value-in-array fdp (fp-coins p2p))))
         (coins (remove-duplicates coins :test #'equal))
         (in-value (reduce #'+ coins :key #'third))
         (fee (consume-integral-in-range fdp 0 100000))
         (n-out (consume-integral-in-range fdp 1 2))
         (each (floor (max 0 (- in-value fee)) n-out))
         (tx (bl.ser:make-transaction
              :version 2 :lock-time 0
              :inputs (coerce (loop for (txid vout) in coins
                                    collect (bl.ser:make-tx-in
                                             :previous-output (bl.ser:make-outpoint :hash txid :index vout)
                                             :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                                             :sequence (consume-sequence fdp)))
                              'simple-vector)
              :outputs (coerce (loop repeat n-out
                                     collect (bl.ser:make-tx-out :value each
                                                                 :script-pubkey +p2wsh-op-true+))
                               'simple-vector)
              :witness (coerce (loop repeat (length coins)
                                     collect (list (make-array 1 :element-type '(unsigned-byte 8)
                                                                 :initial-element #x51)))
                               'simple-vector))))
    (let ((txid (bl.ser:transaction-hash tx)))
      (dotimes (i n-out)
        (push (list txid i each) (fp-coins p2p))))
    tx))

(defun %fuzz-block (fdp p2p)
  "A block on the node's tip, mined: the template's transactions and maybe
one more spend of the node's coins."
  (let* ((ctx (fp-ctx p2p))
         (block (bl.mining:assemble-full-block
                 (bl.ctx:node-context-chain-state ctx) (bl.ctx:node-context-mempool ctx)
                 :coinbase-script-pubkey (make-array 1 :element-type '(unsigned-byte 8)
                                                       :initial-element #x51))))
    (when (consume-bool fdp)
      ;; An extra transaction the template did not choose: the merkle root is
      ;; left as it was, so a consumer must refuse the body as mutated.
      (setf (bl.ser:bitcoin-block-transactions block)
            (append (bl.ser:bitcoin-block-transactions block) (list (%fuzz-spend fdp p2p)))))
    (or (bl.mining:mine-block block :max-tries 1000) block)))

(defun %fuzz-message (fdp p2p)
  "(values COMMAND PAYLOAD): a message type from Core's list (one in sixteen a
random type, seven in sixteen one of +FUZZ-DEEP-MESSAGE-TYPES+), with raw
bytes (one in four) or a well-formed payload of that type built on the node's
state."
  (let* ((command (case (consume-integral-in-range fdp 0 15)
                    (0 (map 'string (lambda (b) (code-char (logand b #x7f)))
                            (remove 0 (consume-bytes fdp 12))))
                    ((1 2 3 4 5 6 7) (pick-value-in-array fdp +fuzz-deep-message-types+))
                    (t (pick-value-in-array fdp +fuzz-net-message-types+))))
         (raw (zerop (consume-integral-in-range fdp 0 3))))
    (values command
            (if raw
                (consume-random-length-byte-vector fdp 4000)
                (%fuzz-payload command fdp p2p)))))

(defun %fuzz-payload (command fdp p2p)
  (let ((tip (%fuzz-tip (fp-ctx p2p))))
    (flet ((hash () (%fuzz-known-hash fdp p2p))
           (u32 () (consume-integral fdp :u32))
           (u64 () (consume-integral fdp :u64)))
      (cond
        ((string= command "version")
         (bl.ser:make-version-message-bytes
          :version (consume-integral-in-range fdp 0 80000) :services (u64)
          :timestamp (u32) :start-height (consume-integral-in-range fdp 0 100)
          :relay (consume-bool fdp) :nonce (u64)))
        ((member command '("inv" "getdata" "notfound") :test #'string=)
         (%payload (bl.ser:make-inv-message (%fuzz-inv-list fdp p2p))))
        ((member command '("getheaders" "getblocks") :test #'string=)
         (%payload (bl.ser:make-getheaders-message
                    (loop repeat (consume-integral-in-range fdp 0 4) collect (hash))
                    (if (consume-bool fdp) nil (hash)))))
        ((string= command "headers")
         (let ((prev (if (consume-bool fdp)
                         tip
                         (bl.store:entry-ancestor-at-height
                          tip (consume-integral-in-range fdp 0 (bl.store:block-index-entry-height tip))))))
           (%payload (bl.ser:make-headers-message
                      (loop repeat (consume-integral-in-range fdp 1 3)
                            collect (let ((h (%fuzz-header-on fdp prev)))
                                      (setf prev (bl.store:make-block-index-entry
                                                  :hash (bl.ser:block-header-hash h)
                                                  :height (1+ (bl.store:block-index-entry-height prev))
                                                  :header h))
                                      h))))))
        ((string= command "block")
         (%payload (bl.ser:make-block-message (%fuzz-block fdp p2p) :witness (consume-bool fdp))))
        ((string= command "cmpctblock")
         (%payload (bl.ser:make-cmpctblock-message (%fuzz-block fdp p2p) :nonce (u64))))
        ((string= command "getblocktxn")
         (%payload (bl.ser:make-getblocktxn-message
                    (hash) (sort (remove-duplicates
                                  (loop repeat (consume-integral-in-range fdp 0 4)
                                        collect (consume-integral-in-range fdp 0 5)))
                                 #'<))))
        ((string= command "blocktxn")
         (%payload (bl.ser:make-blocktxn-message
                    (hash) (loop repeat (consume-integral-in-range fdp 0 2) collect (%fuzz-spend fdp p2p))
                    :witness t)))
        ((string= command "tx")
         (let ((tx (%fuzz-spend fdp p2p)))
           (%payload (bl.ser:make-tx-message tx :witness (consume-bool fdp)))))
        ((member command '("ping" "pong") :test #'string=)
         (%payload (bl.ser:make-pong-message (u64))))
        ((string= command "feefilter")
         (%payload (bl.ser:make-feefilter-message (consume-integral-in-range fdp 0 (ash 1 40)))))
        ((string= command "sendcmpct")
         (%payload (bl.ser:make-sendcmpct-message (consume-bool fdp)
                                                  (pick-value-in-array fdp (list 1 2 (u64))))))
        ((string= command "sendtxrcncl")
         (%payload (bl.ser:make-sendtxrcncl-message (u64) (pick-value-in-array fdp (list 1 (u32))))))
        ((string= command "addr")
         (%payload (bl.ser:make-addr-message
                    (loop repeat (consume-integral-in-range fdp 0 5)
                          collect (list (bl.ser:make-net-addr :services (u64) :ip (consume-uint128 fdp)
                                                              :port (consume-integral fdp :u16))
                                        (u32))))))
        ((string= command "addrv2")
         (%payload (bl.ser:make-addrv2-message
                    (loop repeat (consume-integral-in-range fdp 0 5)
                          collect (let ((ip (consume-uint128 fdp)))
                                    (setf (aref ip 10) #xff (aref ip 11) #xff)
                                    (list (bl.ser:make-net-addr :services (u64) :ip ip
                                                                :port (consume-integral fdp :u16))
                                          1 (u32)))))))
        ((string= command "filterload")
         (let ((bb (bl.ser:make-byte-buf)))
           (bl.bytes:bb-write-var-bytes bb (consume-random-length-byte-vector fdp 600))
           (bl.ser:bb-write-u32-le bb (consume-integral-in-range fdp 0 60))
           (bl.ser:bb-write-u32-le bb (u32))
           (bl.ser:bb-write-u8 bb (consume-integral-in-range fdp 0 3))
           (bl.ser:bb-finish bb)))
        ((string= command "filteradd")
         (let ((bb (bl.ser:make-byte-buf)))
           (bl.bytes:bb-write-var-bytes bb (consume-random-length-byte-vector fdp 600))
           (bl.ser:bb-finish bb)))
        ((member command '("getcfilters" "getcfheaders") :test #'string=)
         (let ((bb (bl.ser:make-byte-buf)))
           (bl.ser:bb-write-u8 bb (pick-value-in-array fdp (list 0 (consume-integral fdp :u8))))
           (bl.ser:bb-write-u32-le bb (consume-integral-in-range fdp 0 5))
           (bl.ser:bb-write-bytes bb (hash))
           (bl.ser:bb-finish bb)))
        ((string= command "getcfcheckpt")
         (let ((bb (bl.ser:make-byte-buf)))
           (bl.ser:bb-write-u8 bb (pick-value-in-array fdp (list 0 (consume-integral fdp :u8))))
           (bl.ser:bb-write-bytes bb (hash))
           (bl.ser:bb-finish bb)))
        ;; verack, sendaddrv2, getaddr, mempool, filterclear, sendheaders,
        ;; wtxidrelay carry nothing; merkleblock, cfilter, cfheaders and
        ;; cfcheckpt are answers we never asked for.
        ((member command '("merkleblock" "cfilter" "cfheaders" "cfcheckpt") :test #'string=)
         (consume-random-length-byte-vector fdp 400))
        (t (make-array 0 :element-type '(unsigned-byte 8)))))))

;;; --- Running one message, and the invariants after it --------------------------

(defun %declared-refusal-p (condition)
  "Whether CONDITION is a refusal the code under test signals on purpose --
a BITCOIN-LISP-ERROR other than INTERNAL-ERROR, or a plain ERROR with a
message -- rather than Core's crash: a type, bounds, arity or unbound-name
error, or an invariant we maintain found broken."
  (and (or (typep condition 'bl.err:bitcoin-lisp-error)
           (eq (type-of condition) 'simple-error))
       (not (typep condition 'bl.err:internal-error))))

(defun %fuzz-deliver (p2p peer command payload)
  "One message through the IBD dispatcher. A declared refusal is Core's
ProcessMessages catch; anything else is a crash."
  (handler-case
      (captured-sends
       (lambda () (deliver-ibd-message peer command payload (fp-ctx p2p))))
    (error (c)
      (unless (%declared-refusal-p c)
        (signal-fuzz-violation
         (format nil "crash: ~S from a ~A message of ~D bytes: ~A" (type-of c) command
                 (length payload) (handler-case (princ-to-string c) (error () "<unprintable>"))))))))

(defun %check-p2p-invariants (p2p command)
  (let* ((ctx (fp-ctx p2p))
         (cs (bl.ctx:node-context-chain-state ctx))
         (utxo (bl.ctx:node-context-utxo-set ctx))
         (mempool (bl.ctx:node-context-mempool ctx))
         (tip (%fuzz-tip ctx)))
    ;; The active tip is indexed, at the best height, and links to genesis.
    (fuzz-assert (and tip (= (fuzz-sabotage (bl.store:chain-state-best-height cs))
                             (bl.store:block-index-entry-height tip)))
                 "after ~A: the tip ~S is not the indexed entry at the best height ~D"
                 command tip (bl.store:chain-state-best-height cs))
    (fuzz-assert (loop for e = tip then (bl.store:block-index-entry-prev-entry e)
                       for h downfrom (bl.store:block-index-entry-height tip)
                       while e
                       always (= h (bl.store:block-index-entry-height e))
                       finally (return (= h -1)))
                 "after ~A: the active chain does not link down to genesis" command)
    ;; The best chain's work never falls.
    (let ((work (bl.store:block-index-entry-chain-work tip)))
      (fuzz-assert (>= work (fp-work p2p)) "after ~A: the chain work fell from ~D to ~D"
                   command (fp-work p2p) work)
      (setf (fp-work p2p) work))
    ;; Every mempool transaction spends coins that exist, and is their spender.
    (bl.mp:mempool-for-each
     mempool
     (lambda (txid entry)
       (bl.ser:dovector (in (bl.ser:transaction-inputs (bl.mp:mempool-entry-transaction entry)))
         (let* ((op (bl.ser:tx-in-previous-output in))
                (ptxid (bl.ser:outpoint-hash op))
                (pvout (bl.ser:outpoint-index op))
                (parent (bl.mp:mempool-get mempool ptxid)))
           (fuzz-assert (or (bl.store:get-utxo utxo ptxid pvout)
                            (and parent
                                 (< pvout (length (bl.ser:transaction-outputs
                                                   (bl.mp:mempool-entry-transaction parent))))))
                        "after ~A: mempool tx ~A spends ~A:~D, which exists nowhere" command
                        (bl.crypto:bytes-to-hex txid) (bl.crypto:bytes-to-hex ptxid) pvout)
           (fuzz-assert (equalp (bl.mp:mempool-spending-tx mempool ptxid pvout) txid)
                        "after ~A: ~A:~D is not recorded as spent by ~A" command
                        (bl.crypto:bytes-to-hex ptxid) pvout (bl.crypto:bytes-to-hex txid))))))
    ;; A peer dropped stays dropped.
    (dolist (cell (fp-peers p2p))
      (let ((peer (car cell)))
        (when (eq (cdr cell) :disconnected)
          (fuzz-assert (eq (bl.net:peer-state peer) :disconnected)
                       "after ~A: peer ~D came back from disconnected" command (bl.net:peer-id peer)))
        (setf (cdr cell) (bl.net:peer-state peer))))))

(defun %fuzz-process (fdp p2p peer)
  "One message from PEER, unless PEER is gone: a dropped connection's queue is
never processed (Core's fDisconnect skip)."
  (unless (eq (bl.net:peer-state peer) :disconnected)
    ;; Core's SetMockTime(ConsumeTime(...)) before each message.
    (setf bl.ser:*mock-time* (+ 1610000000 (consume-integral-in-range fdp 0 100000)))
    (multiple-value-bind (command payload) (%fuzz-message fdp p2p)
      (%fuzz-deliver p2p peer command payload)
      (%check-p2p-invariants p2p command))))

(define-fuzz-target process-message
    (buffer :core "process_message.cpp:57-123" :iterations 80 :max-len 800)
  "One message of a fuzzed type and payload from a fuzzed ready peer, through
the node's dispatcher: no crash, and the chain, mempool and peer invariants
hold after it."
  (let ((fdp (make-fuzzed-data-provider buffer)))
    (with-fuzz-p2p-node (p2p)
      (let ((peer (%fuzz-p2p-peer fdp 1)))
        (push (cons peer :ready) (fp-peers p2p))
        (setf (bl.ctx:node-context-peers (fp-ctx p2p)) (list peer))
        (%fuzz-process fdp p2p peer)))))

(define-fuzz-target process-messages
    (buffer :core "process_messages.cpp:52-123" :iterations 40 :max-len 3000)
  "Up to thirty messages from one to three fuzzed peers, each through the
dispatcher: no crash, and the invariants hold after every one."
  (let ((fdp (make-fuzzed-data-provider buffer)))
    (with-fuzz-p2p-node (p2p)
      (let ((peers (loop for i from 1 to (consume-integral-in-range fdp 1 3)
                         collect (%fuzz-p2p-peer fdp i))))
        (dolist (p peers) (push (cons p :ready) (fp-peers p2p)))
        (setf (bl.ctx:node-context-peers (fp-ctx p2p)) peers)
        (limited-while ((plusp (consume-integral-in-range fdp 0 15)) 30)
          (%fuzz-process fdp p2p (pick-value-in-array fdp peers)))))))
