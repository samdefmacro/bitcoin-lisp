(in-package #:bitcoin-lisp.tests)

;;;; Wave 9A: P2P eclipse/DoS hardening
;;;;
;;;; Covers the four gap-analysis items:
;;;;  1. outbound full-relay slot accounting excludes inbound/block-relay/feeler
;;;;  2. non-blocking send path with a per-peer buffer, pause cap, stall timeout
;;;;  3. per-ADDRESS addr/addrv2 token bucket (Core MAX_ADDR_RATE_PER_SECOND)
;;;;  4. low-work presync anti-DoS on the generic announcement headers path

(def-suite :eclipse-dos-tests
  :description "Eclipse/DoS hardening: outbound accounting, non-blocking send, addr rate limit, generic-path presync"
  :in :bitcoin-lisp-tests)

(in-suite :eclipse-dos-tests)

;;; ============================================================
;;; 1. Outbound full-relay slot accounting (anti-eclipse)
;;; ============================================================

(defun %mk-peer (conn-type inbound &optional (state :ready))
  (bitcoin-lisp.networking:make-peer :conn-type conn-type
                                     :inbound inbound
                                     :state state))

(test outbound-full-relay-peer-p-classification
  "Only a ready, non-inbound, outbound-full-relay peer counts as an outbound
full-relay slot (Core IsFullOutboundConn)."
  (is-true  (bitcoin-lisp::outbound-full-relay-peer-p
             (%mk-peer :outbound-full-relay nil)))
  ;; Inbound peers never count, even if mislabeled full-relay.
  (is-false (bitcoin-lisp::outbound-full-relay-peer-p
             (%mk-peer :outbound-full-relay t)))
  ;; Block-relay and feeler outbound peers are a separate pool.
  (is-false (bitcoin-lisp::outbound-full-relay-peer-p
             (%mk-peer :block-relay nil)))
  (is-false (bitcoin-lisp::outbound-full-relay-peer-p
             (%mk-peer :feeler nil)))
  ;; Not-yet-ready peers don't count.
  (is-false (bitcoin-lisp::outbound-full-relay-peer-p
             (%mk-peer :outbound-full-relay nil :handshaking))))

(test inbound-peers-do-not-satisfy-outbound-target
  "The eclipse primitive: 8 inbound connections must NOT count toward the
outbound full-relay target (they previously did, suppressing replacement
dials). Only the two genuine outbound full-relay peers are counted."
  (let ((peers (append
                ;; 8 attacker inbound peers.
                (loop repeat 8 collect (%mk-peer :inbound t))
                ;; 2 honest outbound full-relay peers.
                (list (%mk-peer :outbound-full-relay nil)
                      (%mk-peer :outbound-full-relay nil))
                ;; block-relay + feeler outbound peers (separate pool).
                (list (%mk-peer :block-relay nil)
                      (%mk-peer :feeler nil)))))
    (is (= 2 (bitcoin-lisp::count-outbound-full-relay-peers peers)))
    ;; With max-peers 8, needing replacements is (8 - 2) = 6 despite 12
    ;; total connections — inbound never masks the shortfall.
    (is (= 6 (- 8 (bitcoin-lisp::count-outbound-full-relay-peers peers))))))

;;; ============================================================
;;; 2. Non-blocking send path
;;; ============================================================

(test send-paused-predicate-tracks-cap
  "connection-send-paused-p flips exactly at the send-buffer cap (Core
fPauseSend on nSendBufferMaxSize)."
  (let ((conn (bitcoin-lisp.networking::make-connection)))
    (setf (bitcoin-lisp.networking::connection-send-queue-bytes conn) 0)
    (is-false (bitcoin-lisp.networking:connection-send-paused-p conn))
    (setf (bitcoin-lisp.networking::connection-send-queue-bytes conn)
          bitcoin-lisp.networking:+max-send-buffer-bytes+)
    (is-false (bitcoin-lisp.networking:connection-send-paused-p conn))
    (setf (bitcoin-lisp.networking::connection-send-queue-bytes conn)
          (1+ bitcoin-lisp.networking:+max-send-buffer-bytes+))
    (is-true (bitcoin-lisp.networking:connection-send-paused-p conn))))

(test send-stall-predicate-needs-pending-and-timeout
  "connection-send-stalled-p triggers only when data is buffered AND the socket
has made no send progress for the stall timeout (Core socket sending timeout)."
  (let ((conn (bitcoin-lisp.networking::make-connection))
        (units internal-time-units-per-second))
    ;; No pending data: never stalled, even with an ancient progress time.
    (setf (bitcoin-lisp.networking::connection-send-queue-bytes conn) 0
          (bitcoin-lisp.networking::connection-last-send-progress conn)
          (- (get-internal-real-time)
             (* (1+ bitcoin-lisp.networking::+send-stall-timeout-seconds+) units)))
    (is-false (bitcoin-lisp.networking:connection-send-stalled-p conn))
    ;; Pending data but recent progress: not stalled.
    (setf (bitcoin-lisp.networking::connection-send-queue-bytes conn) 500
          (bitcoin-lisp.networking::connection-last-send-progress conn)
          (get-internal-real-time))
    (is-false (bitcoin-lisp.networking:connection-send-stalled-p conn))
    ;; Pending data AND stale progress: stalled.
    (setf (bitcoin-lisp.networking::connection-last-send-progress conn)
          (- (get-internal-real-time)
             (* (1+ bitcoin-lisp.networking::+send-stall-timeout-seconds+) units)))
    (is-true (bitcoin-lisp.networking:connection-send-stalled-p conn))))

(test close-connection-frees-send-queue
  "Closing a connection releases any buffered unsent bytes."
  (let ((conn (bitcoin-lisp.networking::make-connection)))
    (setf (bitcoin-lisp.networking::connection-send-queue-in conn)
          (list #(1 2 3))
          (bitcoin-lisp.networking::connection-send-queue-out conn)
          (list #(4 5))
          (bitcoin-lisp.networking::connection-send-queue-bytes conn) 5)
    (bitcoin-lisp.networking:close-connection conn)
    (is (null (bitcoin-lisp.networking::connection-send-queue-in conn)))
    (is (null (bitcoin-lisp.networking::connection-send-queue-out conn)))
    (is (= 0 (bitcoin-lisp.networking::connection-send-queue-bytes conn)))))

(test send-bytes-buffers-and-never-blocks-on-jammed-socket
  "A peer whose TCP window is jammed must not pin the caller: send-bytes writes
what the kernel takes, queues the rest, and returns promptly. Once the buffer
exceeds the cap the peer is send-paused and further messages are dropped
(returns NIL) instead of blocking the shared thread."
  (let ((srv (bitcoin-lisp.networking:open-listener "127.0.0.1" 0)))
    (is-true srv)
    (when srv
      (unwind-protect
          (let* ((port (usocket:get-local-port srv))
                 (client-sock (usocket:socket-connect
                               "127.0.0.1" port
                               :element-type '(unsigned-byte 8)))
                 ;; Accept the server side but NEVER read from it — jam the pipe.
                 (server-conn (usocket:socket-accept srv :element-type '(unsigned-byte 8)))
                 (conn (bitcoin-lisp.networking::make-connection
                        :socket client-sock :host "127.0.0.1" :port port
                        :connected t)))
            (declare (ignorable server-conn))
            (bitcoin-lisp.networking::set-socket-non-blocking client-sock)
            ;; Run the sends in a bounded worker so a regression (a blocking
            ;; write) can be caught as a timeout rather than hanging the suite.
            (let* ((chunk (make-array 200000 :element-type '(unsigned-byte 8)
                                             :initial-element 7))
                   (dropped nil)
                   (sends-done nil)
                   (worker (bt:make-thread
                            (lambda ()
                              ;; ~4MB total: far past the 1MB cap on a loopback
                              ;; socket whose kernel buffer is well under that.
                              (dotimes (_ 20)
                                (let ((r (bitcoin-lisp.networking:send-bytes conn chunk)))
                                  (when (null r) (setf dropped t))))
                              (setf sends-done t))
                            :name "eclipse-send-worker")))
              ;; Bounded join: the worker must finish quickly (non-blocking).
              (bitcoin-lisp.networking:join-thread-or-destroy worker :timeout 10)
              (is-true sends-done "send-bytes must not block on a jammed socket")
              ;; Data backed up into the per-connection buffer.
              (is-true (plusp (bitcoin-lisp.networking::connection-send-queue-bytes conn)))
              ;; The buffer went over the cap, so the peer is send-paused and at
              ;; least one later message was dropped rather than queued forever.
              (is-true (bitcoin-lisp.networking:connection-send-paused-p conn))
              (is-true dropped "over-cap messages must be dropped, not queued")
              (bitcoin-lisp.networking:close-connection conn)
              (ignore-errors (usocket:socket-close server-conn))))
        (bitcoin-lisp.networking:close-listener srv)))))

;;; ============================================================
;;; 3. Per-address addr/addrv2 rate limit
;;; ============================================================

(test addr-token-bucket-fresh-value
  "A fresh peer's addr token bucket starts at 1.0 (Core m_addr_token_bucket
initial value)."
  (let ((p (bitcoin-lisp.networking:make-peer)))
    (is (= 1.0d0 (bitcoin-lisp.networking::peer-addr-token-bucket p)))))

(test addr-token-bucket-refills-at-core-rate
  "The bucket refills at 0.1 tokens/sec (MAX_ADDR_RATE_PER_SECOND), clamped to
the 1000-token soft cap."
  (let ((p (bitcoin-lisp.networking:make-peer)))
    (setf (bitcoin-lisp.networking::peer-addr-token-bucket p) 0.0d0
          (bitcoin-lisp.networking::peer-addr-token-timestamp p)
          (- (get-internal-real-time) (* 100 internal-time-units-per-second)))
    (bitcoin-lisp.networking::%refill-addr-token-bucket p)
    ;; 100s * 0.1/s = 10 tokens.
    (is (< 9.9d0 (bitcoin-lisp.networking::peer-addr-token-bucket p) 10.1d0)))
  ;; Clamp: a huge elapsed time never exceeds the soft cap.
  (let ((p (bitcoin-lisp.networking:make-peer)))
    (setf (bitcoin-lisp.networking::peer-addr-token-bucket p) 0.0d0
          (bitcoin-lisp.networking::peer-addr-token-timestamp p)
          (- (get-internal-real-time) (* 10000000 internal-time-units-per-second)))
    (bitcoin-lisp.networking::%refill-addr-token-bucket p)
    (is (= (coerce bitcoin-lisp.networking::+max-addr-processing-token-bucket+ 'double-float)
           (bitcoin-lisp.networking::peer-addr-token-bucket p)))))

(defun %addr-entries (n &key (base 10))
  "N distinct routable IPv4 net-addr / timestamp conses (fresh timestamps)."
  (let ((now (bitcoin-lisp.serialization:get-unix-time)))
    (loop for i below n
          collect (cons (bitcoin-lisp.serialization:make-net-addr
                         :services 1
                         :ip (bitcoin-lisp.networking:ipv4-to-mapped-ipv6
                              base 0 (floor i 256) (mod i 256))
                         :port 8333)
                        now))))

(test addr-beyond-bucket-are-dropped
  "Addresses beyond the token bucket are dropped, not queued: with a bucket of
5, exactly 5 of 20 announced addresses are processed and 15 are rate-limited,
and the counters are surfaced (Core rate_limited branch + m_addr_processed /
m_addr_rate_limited)."
  (let ((bitcoin-lisp.networking:*reachable-networks* '(:ipv4 :ipv6))
        (book (bitcoin-lisp.networking:make-address-book))
        (p (bitcoin-lisp.networking:make-peer :conn-type :outbound-full-relay)))
    ;; Depleted-ish bucket, timestamp now so refill is ~0.
    (setf (bitcoin-lisp.networking::peer-addr-token-bucket p) 5.0d0
          (bitcoin-lisp.networking::peer-addr-token-timestamp p)
          (get-internal-real-time))
    (let ((added (bitcoin-lisp.networking::%process-gossiped-addresses
                  p (%addr-entries 20) 20 book nil)))
      (is (= 5 added) "only 5 addresses fit the bucket")
      (is (= 5 (bitcoin-lisp.networking::peer-addr-processed p)))
      (is (= 15 (bitcoin-lisp.networking::peer-addr-rate-limited p)))
      ;; Upper bound only: the 20 test addresses share one /16 and one
      ;; source, so addrman maps them all into a single 64-slot new bucket
      ;; (bucket keys on the (addr-group, source-group) pair) and 5 inserts
      ;; slot-collide with p~15% per run — a colliding insert correctly
      ;; REPLACES the earlier entry, making exact-count flaky. The rate
      ;; limit's storage-layer guarantee is that no more than 5 ever reach
      ;; the book; placement within addrman is addrman's own contract.
      (is (<= (bitcoin-lisp.networking:address-book-count book) 5)))))

(test addr-full-bucket-processes-all
  "With a full bucket a normal small announcement is fully processed and
nothing is rate-limited."
  (let ((bitcoin-lisp.networking:*reachable-networks* '(:ipv4 :ipv6))
        (book (bitcoin-lisp.networking:make-address-book))
        (p (bitcoin-lisp.networking:make-peer :conn-type :outbound-full-relay)))
    (setf (bitcoin-lisp.networking::peer-addr-token-bucket p) 1000.0d0
          (bitcoin-lisp.networking::peer-addr-token-timestamp p)
          (get-internal-real-time))
    (let ((added (bitcoin-lisp.networking::%process-gossiped-addresses
                  p (%addr-entries 10) 10 book nil)))
      (is (= 10 added))
      (is (= 10 (bitcoin-lisp.networking::peer-addr-processed p)))
      (is (= 0 (bitcoin-lisp.networking::peer-addr-rate-limited p))))))

(test getaddr-solicitation-clears-on-nonfull-message
  "A non-full (<1000) addr message answers our outstanding getaddr (clears
m_getaddr_sent); a full (1000) one does not."
  (let ((book (bitcoin-lisp.networking:make-address-book))
        (p (bitcoin-lisp.networking:make-peer :conn-type :outbound-full-relay)))
    (setf (bitcoin-lisp.networking::peer-addr-token-bucket p) 1000.0d0
          (bitcoin-lisp.networking::peer-getaddr-requested p) t)
    ;; Non-full announced-count clears the flag.
    (bitcoin-lisp.networking::%process-gossiped-addresses p (%addr-entries 3) 3 book nil)
    (is-false (bitcoin-lisp.networking::peer-getaddr-requested p))
    ;; A full 1000-count message leaves it set (more may follow).
    (setf (bitcoin-lisp.networking::peer-getaddr-requested p) t
          (bitcoin-lisp.networking::peer-addr-token-bucket p) 1000.0d0)
    (bitcoin-lisp.networking::%process-gossiped-addresses p (%addr-entries 3) 1000 book nil)
    (is-true (bitcoin-lisp.networking::peer-getaddr-requested p))))

(test getaddr-bump-exempts-solicited-response-from-bucket
  "Sending our getaddr bumps the bucket by MAX_ADDR_TO_SEND (1000), so a full
solicited response processes despite the ~0.1/s steady-state refill (Core
net_processing.cpp:3772)."
  (let ((bitcoin-lisp.networking:*reachable-networks* '(:ipv4 :ipv6))
        (book (bitcoin-lisp.networking:make-address-book))
        (p (bitcoin-lisp.networking:make-peer :conn-type :outbound-full-relay)))
    ;; Steady-state bucket, then apply the getaddr bump manually (as
    ;; send-post-handshake-messages does).
    (setf (bitcoin-lisp.networking::peer-addr-token-bucket p) 1.0d0
          (bitcoin-lisp.networking::peer-addr-token-timestamp p)
          (get-internal-real-time))
    (incf (bitcoin-lisp.networking::peer-addr-token-bucket p)
          (coerce bitcoin-lisp.serialization:+max-addr-count+ 'double-float))
    (let ((added (bitcoin-lisp.networking::%process-gossiped-addresses
                  p (%addr-entries 500) 500 book nil)))
      (is (= 500 added) "solicited addresses processed under the bump")
      (is (= 0 (bitcoin-lisp.networking::peer-addr-rate-limited p))))))

(test handle-addr-ignores-block-relay-peer
  "A block-relay-only peer participates in no addr relay: handle-addr /
handle-addrv2 ignore its addresses entirely (Core SetupAddressRelay)."
  (let ((book (bitcoin-lisp.networking:make-address-book))
        (p (bitcoin-lisp.networking:make-peer :conn-type :block-relay))
        (payload (coerce
                  (flexi-streams:with-output-to-sequence (s)
                    (bitcoin-lisp.serialization:write-compact-size s 1)
                    (bitcoin-lisp.serialization:write-net-addr
                     s (bitcoin-lisp.serialization:make-net-addr
                        :services 1
                        :ip (bitcoin-lisp.networking:ipv4-to-mapped-ipv6 10 0 0 1)
                        :port 8333)
                     :with-timestamp t
                     :timestamp (bitcoin-lisp.serialization:get-unix-time)))
                  '(simple-array (unsigned-byte 8) (*)))))
    (is (= 0 (bitcoin-lisp.networking:handle-addr p payload book)))
    (is (= 0 (bitcoin-lisp.networking:address-book-count book)))))

(test handle-addr-oversized-is-misbehavior
  "An addr message announcing more than 1000 addresses is misbehavior (Core
Misbehaving on vAddr.size() > MAX_ADDR_TO_SEND): the peer is disconnected and
nothing is stored."
  (let ((book (bitcoin-lisp.networking:make-address-book))
        (p (bitcoin-lisp.networking:make-peer :conn-type :outbound-full-relay
                                              :address "203.0.113.9"))
        (payload (coerce
                  (flexi-streams:with-output-to-sequence (s)
                    (bitcoin-lisp.serialization:write-compact-size s 1001))
                  '(simple-array (unsigned-byte 8) (*)))))
    (is (= 0 (bitcoin-lisp.networking:handle-addr p payload book)))
    (is (eq :disconnected (bitcoin-lisp.networking:peer-state p)))
    (is (= 0 (bitcoin-lisp.networking:address-book-count book)))))

;;; ============================================================
;;; 4. Generic-path low-work presync anti-DoS
;;; ============================================================

(defun %regtest-chain-state (dir)
  "A fresh regtest chain-state with a genesis index entry (chain-work 1)."
  (let* ((state (bitcoin-lisp.storage:init-chain-state
                 (merge-pathnames dir (uiop:temporary-directory))))
         (genesis-hash (bitcoin-lisp.storage:best-block-hash state))
         (zeros (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (bitcoin-lisp.storage:add-block-index-entry
     state (bitcoin-lisp.storage:make-block-index-entry
            :hash genesis-hash :height 0 :chain-work 1 :status :valid
            :header (bitcoin-lisp.serialization:make-block-header
                     :version 1 :prev-block zeros :merkle-root zeros
                     :timestamp 1296688600 :bits #x207fffff :nonce 0
                     :cached-hash genesis-hash)))
    (values state genesis-hash)))

(defun %pow-header (prev-hash &key (timestamp 1296688700) (version 4) (merkle 1))
  "A regtest header off PREV-HASH ground to a valid PoW nonce."
  (let ((mr (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref mr 0) (logand merkle #xff))
    (let ((hdr (bitcoin-lisp.serialization:make-block-header
                :version version :prev-block prev-hash :merkle-root mr
                :timestamp timestamp :bits #x207fffff :nonce 0)))
      (loop for nonce from 0 below 5000
            do (setf (bitcoin-lisp.serialization:block-header-nonce hdr) nonce
                     (bitcoin-lisp.serialization:block-header-cached-hash hdr) nil)
            when (bitcoin-lisp.validation:check-proof-of-work hdr)
              do (return hdr)
            finally (return hdr)))))

(test maybe-start-presync-reports-low-work
  "maybe-start-presync's second value flags a connecting sub-threshold chain
even when no sync starts (a non-full batch): the caller must then IGNORE the
batch rather than storing it. A full batch additionally yields a sync object."
  (let ((bitcoin-lisp:*network* :regtest)
        (bitcoin-lisp.storage:*pow-limit-target*
          bitcoin-lisp.storage:+regtest-pow-limit-target+))
    (multiple-value-bind (state genesis-hash) (%regtest-chain-state "test-presync-lw/")
      ;; Force the anti-DoS threshold sky-high so any real chain is "low work".
      (let* ((bitcoin-lisp::*minimum-chain-work-override* (expt 2 240))
             (h1 (%pow-header genesis-hash)))
        ;; Sub-batch (full-batch-p nil): low-work-p T, but no sync started.
        (multiple-value-bind (sync low-work)
            (bitcoin-lisp.networking::maybe-start-presync (list h1) state nil)
          (is (null sync) "a non-full batch must not start a sync")
          (is-true low-work "connecting sub-threshold chain is flagged low-work"))
        ;; Full batch (full-batch-p t): a sync is created.
        (multiple-value-bind (sync low-work)
            (bitcoin-lisp.networking::maybe-start-presync (list h1) state t)
          (is-true low-work)
          (is-true (bitcoin-lisp.networking::headers-sync-state-p sync)
                   "a full low-work batch starts a presync"))))))

(test generic-path-ignores-sub-batch-low-work-headers
  "The generic announcement path (ingest-headers-from-peer) must store NOTHING
for a connecting but sub-threshold, non-full header batch — the from-genesis
memory-exhaustion DoS this item fixes. Previously such headers were committed
to the index because the validated-tip work gate was off during IBD."
  (let ((bitcoin-lisp:*network* :regtest)
        (bitcoin-lisp.storage:*pow-limit-target*
          bitcoin-lisp.storage:+regtest-pow-limit-target+))
    (multiple-value-bind (state genesis-hash) (%regtest-chain-state "test-presync-ignore/")
      (let* ((bitcoin-lisp::*minimum-chain-work-override* (expt 2 240))
             (p (bitcoin-lisp.networking:make-peer :conn-type :outbound-full-relay))
             (h1 (%pow-header genesis-hash))
             (h1-hash (bitcoin-lisp.serialization:block-header-hash h1)))
        (let ((added (bitcoin-lisp.networking::ingest-headers-from-peer p (list h1) state)))
          (is (= 0 added) "sub-threshold low-work headers must not be stored")
          (is (null (bitcoin-lisp.storage:get-block-index-entry state h1-hash))
              "the low-work header must not enter the block index"))))))

(test generic-path-stores-above-threshold-headers
  "Above the work threshold, the generic path validates and stores normally —
steady-state tip announcements are unaffected by the anti-DoS gate."
  (let ((bitcoin-lisp:*network* :regtest)
        (bitcoin-lisp.storage:*pow-limit-target*
          bitcoin-lisp.storage:+regtest-pow-limit-target+))
    (multiple-value-bind (state genesis-hash) (%regtest-chain-state "test-presync-store/")
      ;; Threshold 0 (regtest default): the genesis-anchored chain meets it.
      (let* ((bitcoin-lisp::*minimum-chain-work-override* 0)
             (p (bitcoin-lisp.networking:make-peer :conn-type :outbound-full-relay))
             (h1 (%pow-header genesis-hash :timestamp 1296688700))
             (h1-hash (bitcoin-lisp.serialization:block-header-hash h1)))
        (let ((added (bitcoin-lisp.networking::ingest-headers-from-peer p (list h1) state)))
          (is (= 1 added) "above-threshold header is stored")
          (is (not (null (bitcoin-lisp.storage:get-block-index-entry state h1-hash)))
              "above-threshold header enters the block index"))))))

(test generic-path-unconnecting-headers-store-nothing
  "A header batch that does not connect to our index (unknown prev-block)
stores nothing and does not error — Core HandleUnconnectingHeaders sends a
getheaders and stages availability, committing nothing."
  (let ((bitcoin-lisp:*network* :regtest)
        (bitcoin-lisp.storage:*pow-limit-target*
          bitcoin-lisp.storage:+regtest-pow-limit-target+))
    (multiple-value-bind (state genesis-hash) (%regtest-chain-state "test-presync-unconn/")
      (declare (ignore genesis-hash))
      (let* ((bitcoin-lisp::*minimum-chain-work-override* 0)
             (p (bitcoin-lisp.networking:make-peer :conn-type :outbound-full-relay))
             (orphan-prev (make-array 32 :element-type '(unsigned-byte 8)
                                         :initial-element 99))
             (h1 (%pow-header orphan-prev))
             (h1-hash (bitcoin-lisp.serialization:block-header-hash h1)))
        (let ((added (bitcoin-lisp.networking::ingest-headers-from-peer p (list h1) state)))
          (is (= 0 added))
          (is (null (bitcoin-lisp.storage:get-block-index-entry state h1-hash))
              "an unconnecting header must not enter the index"))))))

;;;; ============================================================
;;;; G7-18: drop outbound peers on sub-minchainwork chains during IBD
;;;; ============================================================

(defun %g718-state-with-work (work)
  "A chain-state holding one header entry with WORK chain-work, and a peer
whose best-known block is that entry."
  (let* ((state (bitcoin-lisp.storage:make-chain-state))
         (hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 21)))
    (bitcoin-lisp.storage:add-block-index-entry
     state (bitcoin-lisp.storage:make-block-index-entry
            :hash hash :height 1 :chain-work work :status :header-valid))
    (values state hash)))

(defun %g718-peer (&key (conn-type :outbound-full-relay) inbound manual best-hash)
  (let ((p (bitcoin-lisp.networking:make-peer :inbound inbound)))
    (setf (bitcoin-lisp.networking:peer-conn-type p) conn-type
          (bitcoin-lisp.networking:peer-manual p) manual
          (bitcoin-lisp.networking:peer-state p) :ready)
    (when best-hash
      (setf (bitcoin-lisp.networking::peer-best-known-block-hash p) best-hash))
    p))

(test g7-18-outbound-or-block-relay-predicate
  "Core IsOutboundOrBlockRelayConn (net.h:771-785). Both halves matter: it must
INCLUDE :block-relay, and it must EXCLUDE manual (-addnode) peers — ours are
typed :outbound-full-relay, and connect-added-nodes redials them every ~30s, so
a plain not-inbound test would loop connect/disconnect against a peer the
operator pinned."
  (is-true (bitcoin-lisp.networking:peer-outbound-or-block-relay-p
            (%g718-peer :conn-type :outbound-full-relay)))
  (is-true (bitcoin-lisp.networking:peer-outbound-or-block-relay-p
            (%g718-peer :conn-type :block-relay))
           ":block-relay must be included")
  (is-false (bitcoin-lisp.networking:peer-outbound-or-block-relay-p
             (%g718-peer :conn-type :outbound-full-relay :manual t))
            "manual -addnode peers must be excluded")
  (is-false (bitcoin-lisp.networking:peer-outbound-or-block-relay-p
             (%g718-peer :conn-type :feeler)))
  (is-false (bitcoin-lisp.networking:peer-outbound-or-block-relay-p
             (%g718-peer :inbound t))))

(test g7-18-low-work-outbound-disconnected-in-ibd
  "G7-18: we refused to DOWNLOAD from a sub-minchainwork peer but never
disconnected it, so a toy-chain peer could pin an outbound slot for the whole
of IBD — a step toward IBD eclipse."
  (let ((bitcoin-lisp:*network* :regtest)
        (bitcoin-lisp:*minimum-chain-work-override* 1000))
    (multiple-value-bind (state hash) (%g718-state-with-work 10)
      ;; Low work + non-full batch + outbound + IBD => dropped.
      (let ((p (%g718-peer :best-hash hash)))
        (is-true (bitcoin-lisp.networking::maybe-disconnect-low-work-outbound
                  p state nil))
        (is (eq :disconnected (bitcoin-lisp.networking:peer-state p))))
      ;; A FULL batch means more headers may follow — we have not seen their
      ;; tip yet, so we must not judge them.
      (let ((p (%g718-peer :best-hash hash)))
        (is-false (bitcoin-lisp.networking::maybe-disconnect-low-work-outbound
                   p state t)
                  "a full batch must not trigger the drop"))
      ;; Manual and inbound peers are exempt.
      (let ((p (%g718-peer :best-hash hash :manual t)))
        (is-false (bitcoin-lisp.networking::maybe-disconnect-low-work-outbound
                   p state nil)
                  "manual peers must never be auto-dropped"))
      (let ((p (%g718-peer :best-hash hash :inbound t)))
        (is-false (bitcoin-lisp.networking::maybe-disconnect-low-work-outbound
                   p state nil)))
      ;; A peer that never announced anything is never judged (Core :2930).
      (let ((p (%g718-peer)))
        (is-false (bitcoin-lisp.networking::maybe-disconnect-low-work-outbound
                   p state nil)
                  "a peer with no best-known block must not be judged")))))

(test g7-18-minimum-chain-work-comparison-is-strict
  "The comparison is STRICTLY less than minimum-chain-work: a peer whose chain
exactly meets the floor is kept. (The obvious version of this test — pointing a
FRESH peer at a raised floor — asserts nothing, because a fresh peer has no
best-known block and is skipped for that reason rather than the work one.)"
  (let ((bitcoin-lisp:*network* :regtest))
    ;; Work exactly equal to the floor: kept.
    (multiple-value-bind (state hash) (%g718-state-with-work 1000)
      (let ((bitcoin-lisp:*minimum-chain-work-override* 1000)
            (p (%g718-peer :best-hash hash)))
        (is-false (bitcoin-lisp.networking::maybe-disconnect-low-work-outbound
                   p state nil)
                  "equal work must be kept, not dropped")
        (is (eq :ready (bitcoin-lisp.networking:peer-state p)))))
    ;; One unit below the floor: dropped.
    (multiple-value-bind (state hash) (%g718-state-with-work 999)
      (let ((bitcoin-lisp:*minimum-chain-work-override* 1000)
            (p (%g718-peer :best-hash hash)))
        (is-true (bitcoin-lisp.networking::maybe-disconnect-low-work-outbound
                  p state nil))))))

(test g7-18-not-applied-outside-ibd
  "Past IBD the rule does not apply — a peer on a short chain is no longer
occupying a slot we need for syncing."
  (let ((bitcoin-lisp:*network* :regtest)
        (bitcoin-lisp:*minimum-chain-work-override* 1000))
    (multiple-value-bind (state hash) (%g718-state-with-work 10)
      ;; Force the IBD latch off for this check.
      (let ((bitcoin-lisp.networking::*cached-is-ibd* nil)
            (p (%g718-peer :best-hash hash)))
        (is-false (bitcoin-lisp.networking::maybe-disconnect-low-work-outbound
                   p state nil)
                  "outside IBD the peer must be kept")))))

;;;; ============================================================
;;;; G7-08 P1/P2: outbound chain-sync eviction + protection
;;;; ============================================================

(defun %g708-chain (tip-work)
  "A chain-state whose tip has TIP-WORK, plus a lower-work entry a peer can
claim as its best-known."
  (let* ((state (bitcoin-lisp.storage:make-chain-state))
         (tip-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 8))
         (low-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9)))
    (bitcoin-lisp.storage:add-block-index-entry
     state (bitcoin-lisp.storage:make-block-index-entry
            :hash tip-hash :height 100 :chain-work tip-work :status :valid))
    (bitcoin-lisp.storage:add-block-index-entry
     state (bitcoin-lisp.storage:make-block-index-entry
            :hash low-hash :height 50 :chain-work (floor tip-work 2) :status :valid))
    (bitcoin-lisp.storage:update-chain-tip state tip-hash 100)
    (values state tip-hash low-hash)))

(defun %g708-peer (&key (conn-type :outbound-full-relay) inbound manual best-hash protect)
  (let ((p (bitcoin-lisp.networking:make-peer :inbound inbound :address "test")))
    (setf (bitcoin-lisp.networking:peer-conn-type p) conn-type
          (bitcoin-lisp.networking:peer-manual p) manual
          (bitcoin-lisp.networking:peer-state p) :ready
          (bitcoin-lisp.networking::peer-chain-sync-protect p) protect)
    (when best-hash
      (setf (bitcoin-lisp.networking::peer-best-known-block-hash p) best-hash))
    p))

(test g7-08-chain-sync-arms-probes-then-disconnects
  "G7-08 P1 (Core ConsiderEviction): a live-but-SILENT outbound peer sitting
below our tip's work is given a 20-minute budget, then probed once with a
getheaders, then dropped after a further 2 minutes. Such peers answer pings, so
nothing else evicts them — an adversary filling our outbound slots with them
pins us on a stale tip indefinitely."
  (multiple-value-bind (state tip-hash low-hash) (%g708-chain 1000)
    (declare (ignore tip-hash))
    (let ((peer (%g708-peer :best-hash low-hash))
          (sent 0))
      (let ((real (fdefinition 'bitcoin-lisp.networking::send-message)))
        (unwind-protect
             (progn
               (setf (fdefinition 'bitcoin-lisp.networking::send-message)
                     (lambda (p m) (declare (ignore p m)) (incf sent)))
               ;; First sweep arms the timer.
               (is (eq :armed (bitcoin-lisp.networking:consider-chain-sync-eviction
                               peer state 1000)))
               (is (= 0 sent) "arming must not send anything")
               ;; Before the deadline: nothing happens (still armed, no re-arm).
               (is (null (bitcoin-lisp.networking:consider-chain-sync-eviction
                          peer state 1500)))
               ;; Past 20 minutes: probe with a getheaders, do NOT disconnect.
               (is (eq :probed (bitcoin-lisp.networking:consider-chain-sync-eviction
                                peer state (+ 1000 1201))))
               (is (= 1 sent) "the probe must send exactly one getheaders")
               (is (eq :ready (bitcoin-lisp.networking:peer-state peer))
                   "the probe must not disconnect")
               ;; A further 2 minutes with no improvement: drop it.
               (is (eq :disconnected (bitcoin-lisp.networking:consider-chain-sync-eviction
                                      peer state (+ 1000 1201 121))))
               (is (eq :disconnected (bitcoin-lisp.networking:peer-state peer))))
          (setf (fdefinition 'bitcoin-lisp.networking::send-message) real))))))

(test g7-08-good-chain-clears-the-timer
  "A peer whose best-known work reaches our tip clears its timer entirely — it
has answered for itself."
  (multiple-value-bind (state tip-hash) (%g708-chain 1000)
    (let ((peer (%g708-peer :best-hash tip-hash)))
      (setf (bitcoin-lisp.networking::peer-chain-sync-timeout peer) 500)
      (is (eq :cleared (bitcoin-lisp.networking:consider-chain-sync-eviction
                        peer state 1000)))
      (is (zerop (bitcoin-lisp.networking::peer-chain-sync-timeout peer))))))

(test g7-08-exempt-peers-are-never-evicted
  "Manual, inbound and protected peers are outside the eviction logic. Manual
matters most: connect-added-nodes redials them every ~30s, so evicting one
would loop forever against a peer the operator pinned."
  (multiple-value-bind (state tip-hash low-hash) (%g708-chain 1000)
    (declare (ignore tip-hash))
    (dolist (peer (list (%g708-peer :best-hash low-hash :manual t)
                        (%g708-peer :best-hash low-hash :inbound t)
                        (%g708-peer :best-hash low-hash :protect t)
                        (%g708-peer :best-hash low-hash :conn-type :feeler)))
      (is (null (bitcoin-lisp.networking:consider-chain-sync-eviction
                 peer state 1000))
          "exempt peers must not even be armed"))
    ;; A block-relay peer IS a candidate (Core keeps them subject to the logic).
    (is (eq :armed (bitcoin-lisp.networking:consider-chain-sync-eviction
                    (%g708-peer :best-hash low-hash :conn-type :block-relay)
                    state 1000)))))

(test g7-08-protection-is-capped-at-four-and-released
  "Core protects at most MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT (4)
outbound FULL-RELAY peers; block-relay peers are deliberately never protected."
  (let ((bitcoin-lisp.networking::*protected-outbound-count* 0))
    (let ((peers (loop repeat 6 collect (%g708-peer))))
      (dolist (p peers) (bitcoin-lisp.networking:maybe-protect-outbound-peer p))
      (is (= 4 (count-if #'bitcoin-lisp.networking::peer-chain-sync-protect peers))
          "at most 4 peers may hold protection")
      (is (= 4 bitcoin-lisp.networking::*protected-outbound-count*))
      ;; Releasing frees a slot for another peer.
      (bitcoin-lisp.networking:release-outbound-protection (first peers))
      (is (= 3 bitcoin-lisp.networking::*protected-outbound-count*))
      (is (bitcoin-lisp.networking:maybe-protect-outbound-peer (%g708-peer))
          "a freed slot must be reusable"))
    ;; Block-relay peers are not eligible.
    (let ((bitcoin-lisp.networking::*protected-outbound-count* 0))
      (is (null (bitcoin-lisp.networking:maybe-protect-outbound-peer
                 (%g708-peer :conn-type :block-relay)))
          "block-relay peers must stay subject to the eviction logic"))))
