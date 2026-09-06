(in-package #:bitcoin-lisp.test-support)

;;;; Temporary directories

(defun make-temp-directory (&optional (prefix "bl-test"))
  "A fresh, private directory under the system temporary directory,
PREFIX-<time>-<random>/, created and returned. The caller removes it;
WITH-TEMP-DIRECTORY does that on unwind. Never a fixed name: two test
processes on one machine would share it."
  (ensure-directories-exist
   (merge-pathnames (format nil "~A-~D-~D/" prefix (get-universal-time) (random 1000000))
                    (uiop:temporary-directory))))

(defmacro with-temp-directory ((var &optional (prefix "bl-test")) &body body)
  "Run BODY with VAR bound to a fresh temporary directory (MAKE-TEMP-DIRECTORY),
removed with everything in it afterwards. A data directory for a node under
test, a flat-file store, a snapshot dump -- and every START-RPC-SERVER call
needs one, because the .cookie written there is the credential when no
rpcuser/rpcpassword is configured."
  `(let ((,var (make-temp-directory ,prefix)))
     (unwind-protect (progn ,@body)
       (uiop:delete-directory-tree ,var :validate t :if-does-not-exist :ignore))))

;;;; The chain under test

(defmacro with-network ((network) &body body)
  "Run BODY with BL:*NETWORK* bound to NETWORK. For :REGTEST the proof-of-work
limit is bound to regtest's as well, so a #x207fffff target is valid and
synthetic headers reach the contextual checks; :MAINNET is what version-1
test blocks need to pass the BIP34 activation check (testnet4 activates
BIP34 at height 1)."
  (let ((n (gensym "NETWORK")))
    `(let* ((,n ,network)
            (bl:*network* ,n)
            (bl.store:*pow-limit-target*
              (if (eq ,n :regtest)
                  bl.store:+regtest-pow-limit-target+
                  bl.store:*pow-limit-target*)))
       ,@body)))

;;;; The minimal node

(defun make-test-node (&key (network :testnet3))
  "Create a node with minimal initialized state for testing."
  (let ((node (bl:make-node :network network)))
    ;; Initialize chain-state
    (setf (bl:node-chain-state node)
          (bl.store:make-chain-state))
    ;; Initialize UTXO set
    (setf (bl:node-utxo-set node)
          (bl.store:make-utxo-set))
    ;; Initialize mempool
    (setf (bl:node-mempool node)
          (bl.mp:make-mempool))
    node))

;;;; Node-global state a fixture has to reset

(defun clear-undo-cache ()
  "Empty the in-memory undo cache validation keeps for recently connected
blocks. Every fixture that builds a chain starts from an empty one, or a
previous test's undo entries answer for a block this one just built."
  (clrhash bl.val::*block-undo-data*))

;;;; Reproducible randomness

(defun make-deterministic-rng (seed)
  "Deterministic xorshift64 PRNG closure: (funcall rng n) => [0, n). No
dependence on the global *random-state*, so runs are reproducible."
  (let ((state seed))
    (lambda (n)
      (setf state (ldb (byte 64 0) (logxor state (ash state 13))))
      (setf state (logxor state (ash state -7)))
      (setf state (ldb (byte 64 0) (logxor state (ash state 17))))
      (mod state n))))

;;;; The IBD context

(defmacro with-ibd-context (&body body)
  "Run BODY with BL.NET:*IBD-CONTEXT* bound to a fresh IBD context -- the
binding every headers-sync, block-download and reorg-through-IBD test opens
with; nineteen of them wrote the LET themselves."
  `(let ((bl.net:*ibd-context* (bl.net::make-ibd)))
     ,@body))

;;;; RPC errors

(defmacro signals-rpc-error ((&key code message exact-message) &body body)
  "Assert that BODY signals an RPC-ERROR carrying Core error CODE and/or a
message containing MESSAGE (or equal to EXACT-MESSAGE); BODY returning
normally is a failure. At least one check is required: the plain
(signals bl.rpc:rpc-error ...) accepts any RPC error, which is how a test
stays green when a type-check error preempts the check it was written for."
  (unless (or code message exact-message)
    (error "signals-rpc-error needs :code, :message or :exact-message -- a ~
bare form is (signals bl.rpc:rpc-error ...)"))
  (let ((e (gensym "E")))
    `(handler-case (progn ,@body
                          (fiveam:fail "expected an rpc-error~@[ with code ~D~]~@[ mentioning ~S~], got a normal return"
                                       ,code ,(or message exact-message)))
       (bl.rpc:rpc-error (,e)
         ,@(when code
             `((fiveam:is (= ,code (bl.rpc:rpc-error-code ,e))
                          "expected rpc-error code ~D, got ~D (~A)"
                          ,code (bl.rpc:rpc-error-code ,e) (bl.rpc:rpc-error-message ,e))))
         ,@(when message
             `((fiveam:is (search ,message (bl.rpc:rpc-error-message ,e))
                          "expected the rpc-error message to mention ~S, got ~S"
                          ,message (bl.rpc:rpc-error-message ,e))))
         ,@(when exact-message
             `((fiveam:is (string= ,exact-message (bl.rpc:rpc-error-message ,e))
                          "expected the rpc-error message ~S, got ~S"
                          ,exact-message (bl.rpc:rpc-error-message ,e))))))))

(defun rpc-error-code-of (thunk)
  "The rpc-error code THUNK signals, or NIL if it returns normally."
  (handler-case (progn (funcall thunk) nil)
    (bl.rpc:rpc-error (e) (bl.rpc:rpc-error-code e))))

;;;; Coins-view-cache white-box readers

;;; The cache's DIRTY/FRESH bookkeeping is internal to BL.STORE, and both
;;; tests/storage/ and tests/kv/ assert on it. Naming each accessor once here
;;; keeps those `::' out of the test files (the structural ratchet
;;; TEST-INTERNAL-REFERENCES-DO-NOT-GROW) and gives the assertions one
;;; vocabulary for the flags whose meaning is stated in coins-view-cache.lisp.

(defun coins-cache-entries (cache)
  "The cache's entry table, keyed by utxo-key. HASH-TABLE-COUNT it for the
cache's size, GETHASH a key out of it for one entry, MAPHASH it for all."
  (bl.store::cvc-entries cache))

(defun coins-cache-fresh-count (cache)
  "How many entries the cache counts as FRESH — absent from the base view, so
a spend may drop them outright instead of staging an erase."
  (bl.store::cvc-fresh-count cache))

(defun coins-cache-dirty-count (cache)
  "How many entries the cache counts as DIRTY — changed since the last write
to the base view."
  (bl.store::cvc-dirty-count cache))

(defun coins-cache-entry-fresh-p (entry)
  "Whether one cache entry carries the FRESH flag."
  (bl.store::ce-fresh entry))

(defun coins-cache-entry-dirty-p (entry)
  "Whether one cache entry carries the DIRTY flag."
  (bl.store::ce-dirty entry))

;;;; The configuration a command line and a bitcoin.conf produce

(defun start-node-plist (&optional args conf-text settings-rows)
  "The START-NODE keyword plist ARGS and CONF-TEXT resolve to, plus the merged
config alist and the network as second and third values — the pure half of
START-NODE-FROM-ARGS. CONF-TEXT is one bitcoin.conf's contents or a list of
them; SETTINGS-ROWS is a settings.json source (BL:SETTINGS-CONFIG-ROWS).

Five test files ask this question, which is why it is a fixture rather than
fifty-four reaches into the same internal."
  (bl::args->start-node-plist args conf-text settings-rows))

;;;; P2P message handlers

(defun deliver-getdata (peer payload ctx)
  "Drive one getdata message PAYLOAD through the shipped handler (Core's
GETDATA branch, which appends the invs to the peer's pending queue and then
runs ProcessGetData over it).

Three test files ask this question, which is why it is a fixture rather than
a reach into the handler from each of them."
  (bl.net::handle-getdata peer payload ctx))

(defun deliver-tx (peer payload ctx)
  "Drive one tx message PAYLOAD through the shipped handler (Core's TX branch
of ProcessMessage): the IBD gate, the rejects and recently-confirmed checks,
mempool validation, orphan intake and relay.

Four test files ask this question, which is why it is a fixture rather than
thirty-seven reaches into the handler."
  (bl.net::handle-tx peer payload ctx))

(defun deliver-inv (peer payload ctx)
  "Drive one inv message PAYLOAD through the shipped handler (Core's INV
branch: block availability, AddTxAnnouncement, and the getdata it triggers)."
  (bl.net::handle-inv peer payload ctx))

(defun deliver-notfound (peer payload ctx)
  "Drive one notfound message PAYLOAD through the shipped handler (Core's
NOTFOUND branch -> ReceivedNotFound)."
  (bl.net::handle-notfound peer payload ctx))

(defmacro with-tx-request-salt ((k0 k1) &body body)
  "Run BODY with the node's tx-request SipHash key fixed at (K0 . K1), so the
candidate ranking is reproducible (Core PriorityComputer's m_k0/m_k1, drawn
once per process from a FastRandomContext)."
  `(let ((bl.net::*tx-request-salt* (cons ,k0 ,k1)))
     ,@body))

(defmacro with-tx-relay-out-of-ibd (&body body)
  "Run BODY as a node that has LEFT initial block download. Core's TX handler
returns before deserialising the transaction while IsInitialBlockDownload()
is true (net_processing.cpp:4479-4483), and a synthetic chainstate carrying no
chain work is in IBD by construction -- so a test that drives a transaction
through the P2P path has to say which side of that gate it stands on. The
gate's own test leaves the latch alone."
  `(let ((bl.net:*cached-is-ibd* nil))
     ,@body))

(defun deliver-ibd-message (peer command payload node-ctx
                            &optional (ibd-ctx bl.net:*ibd-context*))
  "Drive one wire message through the IBD dispatcher -- the routing a live
node uses while it is still syncing, which handles block and headers itself
and hands everything else to the generic handler."
  (bl.net::dispatch-ibd-message peer command payload node-ctx ibd-ctx))

;;;; The tx-request tracker (Core TxRequestTracker)
;;;
;;; White-box readers for a structure with no public accessors: the state a
;;; tx-relay test asserts on is the tracker's, and every one of these
;;; questions was being asked from several test files at once.

(defun tx-request-in-flight-peer (hash)
  "The peer holding the outstanding getdata for HASH (Core's REQUESTED
announcement), or NIL when nothing is in flight for it."
  (car (gethash hash bl.net::*tx-in-flight*)))

(defun tx-request-announcement-peers (hash &key completed)
  "The peers with an announcement of HASH, newest first. By default only the
LIVE ones (Core's non-COMPLETED states, what GetCandidatePeers returns); with
COMPLETED true, every announcement the tracker still holds for the hash."
  (loop for ann in (gethash hash bl.net::*tx-announcers*)
        when (or completed (not (bl.net::tx-ann-completed ann)))
          collect (bl.net::tx-ann-peer ann)))

(defun tx-request-completed-p (hash peer)
  "T when PEER's announcement of HASH exists and is COMPLETED -- Core's
State::COMPLETED, the slot a failed peer keeps."
  (let ((ann (find peer (gethash hash bl.net::*tx-announcers*)
                   :key #'bl.net::tx-ann-peer :test #'eq)))
    (and ann (bl.net::tx-ann-completed ann) t)))

(defun tx-request-wtxid-entry-p (hash)
  "T when HASH is tracked as a wtxid (MSG_WTX) announcement rather than a
txid one -- what decides the inv type of its getdata."
  (gethash hash bl.net::*tx-request-wtxid-p*))

(defun backdate-tx-announcements (hash &optional (seconds 1))
  "Make every announcement of HASH due, as if its NONPREF/TXID/OVERLOADED
delay had elapsed SECONDS ago, so the next scheduler pass may grant it. Every
announcement gets the SAME ready time, which is what lets a test ask which
one the tracker picks without announcement time deciding it. Returns the
number of announcements moved."
  (let ((ready (- (get-internal-real-time)
                  (max 1 (* seconds internal-time-units-per-second))))
        (n 0))
    (dolist (ann (gethash hash bl.net::*tx-announcers*) n)
      (incf n)
      (setf (bl.net::tx-ann-ready ann) ready))))

(defun expire-tx-request (hash &optional (seconds 120))
  "Backdate HASH's in-flight request SECONDS into the past, so the next
RETRY-TIMED-OUT-TX-REQUESTS sees it past GETDATA_TX_INTERVAL. Returns the
peer whose request was backdated, or NIL if nothing was in flight."
  (let ((entry (gethash hash bl.net::*tx-in-flight*)))
    (when entry
      (setf (cdr entry) (- (get-internal-real-time)
                           (* seconds internal-time-units-per-second)))
      (car entry))))

(defun (setf tx-request-peer-count) (n peer)
  "Put PEER's tracked-announcement count at N (Core m_peerinfo[peer].m_total)
so a cap test does not need N real announcements."
  (setf (gethash peer bl.net::*tx-peer-announcements*) n))

(defun (setf tx-request-peer-in-flight-count) (n peer)
  "Put PEER's in-flight request count at N (Core CountInFlight), the input to
the OVERLOADED_PEER_TX_DELAY."
  (setf (gethash peer bl.net::*tx-peer-in-flight*) n))

(defun drain-peer-once (peer node-ctx &optional ibd-ctx)
  "Run the shipped per-peer message pump over PEER exactly once (Core's
per-peer ProcessMessages pass): serve whatever getdata the last pass left
parked, then read and dispatch what is readable, then reap the peer if its
connection has died.

Three test files ask this question, which is why it is a fixture rather than
a reach into the pump from each of them."
  (bl.net::drain-and-reap-peer peer node-ctx ibd-ctx))

(defun ingest-gossiped-addresses (peer entries announced-count address-book peers)
  "Drive the shipped addr/addrv2 ingestion loop over ENTRIES, a list of
(net-addr . timestamp) as the parsers produce them (Core's per-address loop in
the ADDR handler: the token bucket, the shuffle, storage and relay). PEER is
the announcer, ANNOUNCED-COUNT the message's declared address count, PEERS the
relay candidates. Returns the number of addresses stored.

Two test files ask this question, which is why it is a fixture rather than a
reach into the loop from each of them."
  (bl.net::%process-gossiped-addresses peer entries announced-count
                                       address-book peers))

(defun peer-pending-getdata (peer)
  "The inv vectors PEER has asked for and we have not answered yet (Core
Peer::m_getdata_requests) -- what a send-paused serve left behind."
  (bl.net::peer-getdata-queue peer))

(defun send-buffer-bytes (conn)
  "CONN's buffered-unsent-byte counter (Core CNode::m_send_memusage).
SETF-able so a test can put a connection over the send-pause cap without a
jammed socket."
  (bl.net::connection-send-queue-bytes conn))

(defun (setf send-buffer-bytes) (n conn)
  (setf (bl.net::connection-send-queue-bytes conn) n))

;;;; The REST interface

(defun rest-request (node uri)
  "Drive one /rest/ URI through the REST router (Core's rest.cpp dispatch) and
return (values body status content-type).

URI may carry a query string. REST-HANDLE takes the script name, as it does
under Hunchentoot, while the parameters reach the handlers the way they do in
a live request -- through HUNCHENTOOT:GET-PARAMETER on the bound request, which
is how /rest/headers, /rest/blockpart and /rest/mempool read theirs.

Outside a real HTTP request nothing has bound the request and reply objects the
handlers read their parameters from and write their status and content type
onto, so this binds them; a caller that already bound its own reply keeps it,
which is what lets a test make several requests and go on reading
HUNCHENTOOT:RETURN-CODE* itself. The acceptor binding is what makes the request
object constructible at all: HUNCHENTOOT:REQUEST's initializer reaches for
*ACCEPTOR* and fails to build a request without one.

Two test files ask this question, which is why it is a fixture rather than a
reach into the router from each of them."
  (let* ((hunchentoot:*acceptor* (make-instance 'hunchentoot:acceptor))
         (hunchentoot:*request*
           (make-instance 'hunchentoot:request
                          :uri uri
                          :acceptor hunchentoot:*acceptor*
                          :headers-in nil
                          :method :get
                          :server-protocol :http/1.1
                          :remote-addr "127.0.0.1"
                          :remote-port 0))
         (hunchentoot:*reply*
           (if (boundp 'hunchentoot:*reply*)
               hunchentoot:*reply*
               (make-instance 'hunchentoot:reply))))
    (values (bl.rpc::rest-handle node (hunchentoot:script-name*))
            (hunchentoot:return-code*)
            (hunchentoot:content-type*))))
