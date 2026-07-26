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
;;;; GA8 W3: the low-work drop must fire only where Core evaluates it
;;;;
;;;; Core reaches the disconnect solely through
;;;; UpdatePeerStateForReceivedHeaders (net_processing.cpp:2926-2944), which
;;;; ProcessHeadersMessage calls only on the STORED path (:3113). It returns
;;;; early — never judging the peer — for an empty message (:2969-2981), for an
;;;; unconnecting BIP130 announcement (:3029-3040) and for a batch swallowed by
;;;; TryLowWorkHeadersSync (:3065-3074). Conversely a batch of headers we
;;;; already have sets already_validated_work (:3049-3054), BYPASSES
;;;; TryLowWorkHeadersSync and DOES reach the disconnect — Core's own comment at
;;;; :2786-2790 spells that interaction out.
;;;; ============================================================

(defmacro %w3-with-regtest (&body body)
  "Regtest network + regtest PoW limit + the IBD latch forced ON, so these
assertions cannot be made vacuous by whatever an earlier test left in the
globals."
  `(let ((bitcoin-lisp:*network* :regtest)
         (bitcoin-lisp.storage:*pow-limit-target*
           bitcoin-lisp.storage:+regtest-pow-limit-target+)
         (bitcoin-lisp.networking::*cached-is-ibd* t))
     ,@body))

(defun %w3-stored-header (dir)
  "A regtest chain-state (genesis chain-work 1) with one real header H1 stored
off genesis via the production ingest path at a zero work floor. Returns
(values state genesis-hash h1 h1-hash). H1's chain-work is tiny (regtest block
proof), so raising the floor afterwards makes it sub-minchainwork."
  (multiple-value-bind (state genesis-hash) (%regtest-chain-state dir)
    (let* ((bitcoin-lisp:*minimum-chain-work-override* 0)
           (h1 (%pow-header genesis-hash))
           (h1-hash (bitcoin-lisp.serialization:block-header-hash h1)))
      (bitcoin-lisp.networking::ingest-headers-from-peer
       (%g718-peer) (list h1) state)
      (values state genesis-hash h1 h1-hash))))

(test w3-unconnecting-announcement-does-not-disconnect-outbound
  "GA8 W3 (S2), the regression. Early mainnet IBD, our chain still below
nMinimumChainWork: outbound peer B's best-known block is a low-work header (the
pprev priming sweep set it). A new block is mined and B sends a 1-header BIP130
announcement whose parent we lack. Core runs HandleUnconnectingHeaders and
RETURNS (net_processing.cpp:3029-3040). We ran the drop after EVERY branch of
ingest-headers-from-peer, and the unconnecting branch only stages
hash-last-unknown — best-known stays at its stale sub-floor value — so the
check fired with a non-full batch and dropped B. Every announcing outbound peer
could be churned this way during the most eclipse-sensitive phase."
  (%w3-with-regtest
    (multiple-value-bind (state genesis-hash)
        (%regtest-chain-state "test-w3-unconn-nodrop/")
      (let* ((bitcoin-lisp:*minimum-chain-work-override* 1000)
             ;; Genesis carries chain-work 1, three orders below the floor.
             (p (%g718-peer :best-hash genesis-hash))
             (orphan-prev (make-array 32 :element-type '(unsigned-byte 8)
                                         :initial-element 77))
             (announced (%pow-header orphan-prev)))
        (is-true (bitcoin-lisp.networking:initial-block-download-p state)
                 "fixture must be in IBD, or the whole assertion is vacuous")
        (is (= 0 (bitcoin-lisp.networking::ingest-headers-from-peer
                  p (list announced) state))
            "an unconnecting header stores nothing")
        (is (eq :ready (bitcoin-lisp.networking:peer-state p))
            "a BIP130 announcement with an unknown parent must NOT drop the peer")))))

(test w3-empty-headers-message-does-not-disconnect-outbound
  "An empty headers message is Core's nCount==0 early return
(net_processing.cpp:2969-2981) — the peer is never judged. We judged it, so a
peer answering \"I have nothing more\" during IBD was dropped on the spot."
  (%w3-with-regtest
    (multiple-value-bind (state genesis-hash)
        (%regtest-chain-state "test-w3-empty-nodrop/")
      (let ((bitcoin-lisp:*minimum-chain-work-override* 1000)
            (p (%g718-peer :best-hash genesis-hash)))
        (is (= 0 (bitcoin-lisp.networking::ingest-headers-from-peer p nil state)))
        (is (eq :ready (bitcoin-lisp.networking:peer-state p))
            "an empty headers message must NOT drop the peer")))))

(test w3-low-work-diverted-batch-does-not-disconnect-outbound
  "A connecting batch whose claimed work is below the anti-DoS threshold is
swallowed by TryLowWorkHeadersSync, which returns true and makes
ProcessHeadersMessage return (net_processing.cpp:3065-3074, :2800-2807) — no
peer-state update, no disconnect. Nothing was stored, so there is no
pindexLast to judge the peer on."
  (%w3-with-regtest
    (multiple-value-bind (state genesis-hash)
        (%regtest-chain-state "test-w3-lowwork-nodrop/")
      (let* ((bitcoin-lisp:*minimum-chain-work-override* 1000)
             (p (%g718-peer :best-hash genesis-hash))
             (h1 (%pow-header genesis-hash))
             (h1-hash (bitcoin-lisp.serialization:block-header-hash h1)))
        (is (= 0 (bitcoin-lisp.networking::ingest-headers-from-peer
                  p (list h1) state)))
        (is (null (bitcoin-lisp.storage:get-block-index-entry state h1-hash))
            "the low-work header must not enter the index")
        (is (eq :ready (bitcoin-lisp.networking:peer-state p))
            "an ignored low-work batch must NOT drop the peer")))))

(test w3-low-work-outbound-still-dropped-on-stored-batch
  "The control: the feature must still fire where Core fires it. A batch we
already hold sets already_validated_work (net_processing.cpp:3046-3054),
bypasses TryLowWorkHeadersSync and reaches
UpdatePeerStateForReceivedHeaders — so the outbound peer whose whole chain sits
below the floor IS dropped. Deleting the check outright would redden this."
  (%w3-with-regtest
    (multiple-value-bind (state genesis-hash h1 h1-hash)
        (%w3-stored-header "test-w3-stored-drop/")
      (declare (ignore genesis-hash))
      (is (not (null (bitcoin-lisp.storage:get-block-index-entry state h1-hash)))
          "fixture must have stored H1, or the already-known branch is not taken")
      (let ((bitcoin-lisp:*minimum-chain-work-override* 1000)
            (p (%g718-peer)))
        (is (= 0 (bitcoin-lisp.networking::ingest-headers-from-peer
                  p (list h1) state))
            "an already-known header adds nothing to the index")
        (is (equalp h1-hash (bitcoin-lisp.networking::peer-best-known-block-hash p))
            "the stored path must have refreshed availability first")
        (is (eq :disconnected (bitcoin-lisp.networking:peer-state p))
            "a stored non-full batch leaving best-known below the floor must drop")))))

(test w3-solicited-phase1-path-drops-low-work-outbound
  "GA8 W3 (S3), the other half: handle-header-batch — the solicited Phase-1
path — never applied the drop at all, and %maybe-divert-to-presync had no
known-ancestor skip, so the CLASSIC case never fired: an outbound peer pinned
on a low-work fork answers our getheaders with a short batch of headers we
already hold. Core sets already_validated_work for exactly that shape
(net_processing.cpp:3046-3054, and the comment at :2786-2790), skipping
TryLowWorkHeadersSync and reaching the disconnect."
  (%w3-with-regtest
    (multiple-value-bind (state genesis-hash h1 h1-hash)
        (%w3-stored-header "test-w3-phase1-drop/")
      (declare (ignore genesis-hash h1-hash))
      (let ((bitcoin-lisp:*minimum-chain-work-override* 1000))
        (let* ((p (%g718-peer))
               (added 0)
               (done (bitcoin-lisp.networking::handle-header-batch
                      p state (list h1) nil (lambda (n) (incf added n)))))
          (is-true done "a non-full batch ends header sync with this peer")
          (is (= 0 added) "an already-known batch adds nothing")
          (is (eq :disconnected (bitcoin-lisp.networking:peer-state p))
              "the solicited path must drop a sub-minchainwork outbound peer"))
        ;; Same batch declared FULL: may_have_more_headers, so the peer is kept
        ;; (Core's !may_have_more_headers guard) — but sync still ends, because
        ;; nothing entered the index and our locator is built from our own
        ;; header tip, so re-asking would fetch this very batch again.
        (let ((p (%g718-peer)))
          (is-true (bitcoin-lisp.networking::handle-header-batch
                    p state (list h1) t (lambda (n) (declare (ignore n))))
                   "an all-known batch ends sync even when the message was full")
          (is (eq :ready (bitcoin-lisp.networking:peer-state p))
              "a full batch must not drop the peer"))))))

;;;; ============================================================
;;;; GA8 W3 review: already_validated_work is Core's ANCESTOR test, not plain
;;;; index membership.
;;;;
;;;; Core skips the anti-DoS work gate only when the last received header
;;;; IsAncestorOfBestHeaderOrTip (net_processing.cpp:3046-3054, :2813-2823) —
;;;; i.e. only for headers on our own best-header / active chain. A batch of
;;;; headers we hold only on a FORK still reaches TryLowWorkHeadersSync and
;;;; still presyncs (:2769-2800).
;;;;
;;;; Testing plain membership instead swallowed the fork class and ended header
;;;; sync with that peer, with no resume path: our locator is built from our own
;;;; header tip, which an all-known batch does not move, so the next round
;;;; reproduced the identical request and the identical batch — for ever — and
;;;; the BIP130 announcement path dead-ends the same way (its getheaders uses
;;;; that same locator). This is the deep-fork non-convergence failure mode this
;;;; project already lost days to on testnet4.
;;;; ============================================================

(defun %w3-fork-fixture (dir)
  "A regtest chain-state holding TWO branches off genesis, both admitted through
the production ingest path at a zero work floor: A1..A3 — the most-work header
chain, so Core's m_best_header — and a shorter fork B1..B2, in the index but on
neither the best-header chain nor the active chain. Returns (values state
a-headers b-headers)."
  (multiple-value-bind (state genesis-hash) (%regtest-chain-state dir)
    (let* ((bitcoin-lisp:*minimum-chain-work-override* 0)
           (a1 (%pow-header genesis-hash :timestamp 1296688700 :merkle 1))
           (a2 (%pow-header (bitcoin-lisp.serialization:block-header-hash a1)
                            :timestamp 1296689300 :merkle 2))
           (a3 (%pow-header (bitcoin-lisp.serialization:block-header-hash a2)
                            :timestamp 1296689900 :merkle 3))
           (b1 (%pow-header genesis-hash :timestamp 1296688701 :merkle 11))
           (b2 (%pow-header (bitcoin-lisp.serialization:block-header-hash b1)
                            :timestamp 1296689301 :merkle 12)))
      (bitcoin-lisp.networking::ingest-headers-from-peer
       (%g718-peer) (list a1 a2 a3) state)
      (bitcoin-lisp.networking::ingest-headers-from-peer
       (%g718-peer) (list b1 b2) state)
      (values state (list a1 a2 a3) (list b1 b2)))))

(defun %w3-entry (state header)
  (bitcoin-lisp.storage:get-block-index-entry
   state (bitcoin-lisp.serialization:block-header-hash header)))

(test w3-ancestor-of-best-header-or-tip-predicate
  "Core PeerManagerImpl::IsAncestorOfBestHeaderOrTip (net_processing.cpp:2813-
2823), all three arms plus the NIL case. The fork arm is what the GA8 W3 review
was about: a header we HOLD is not thereby a header on our chain."
  (%w3-with-regtest
    (multiple-value-bind (state a-headers b-headers)
        (%w3-fork-fixture "test-w3-ancestor-pred/")
      (let ((a1 (%w3-entry state (first a-headers)))
            (a3 (%w3-entry state (third a-headers)))
            (b2 (%w3-entry state (second b-headers))))
        (is (not (null a3)) "fixture must have stored the A branch")
        (is (not (null b2)) "fixture must have stored the B fork")
        (is-false (bitcoin-lisp.networking::%ancestor-of-best-header-or-tip-p
                   state nil)
                  "a header we do not have at all is an ancestor of nothing")
        (is-true (bitcoin-lisp.networking::%ancestor-of-best-header-or-tip-p
                  state a3)
                 "m_best_header itself qualifies")
        (is-true (bitcoin-lisp.networking::%ancestor-of-best-header-or-tip-p
                  state a1)
                 "an ancestor of m_best_header qualifies (GetAncestor arm)")
        (is-false (bitcoin-lisp.networking::%ancestor-of-best-header-or-tip-p
                   state b2)
                  "a header held only on a FORK does NOT qualify")
        ;; Third arm: ActiveChain().Contains(). Move the active tip onto the
        ;; fork, as a reorg does; B2 is then on the active chain even though it
        ;; is still off the best-header branch.
        (bitcoin-lisp.storage:update-chain-tip
         state (bitcoin-lisp.storage:block-index-entry-hash b2) 2)
        (is-true (bitcoin-lisp.networking::%ancestor-of-best-header-or-tip-p
                  state b2)
                 "a header on the ACTIVE chain qualifies even off the best-header branch")))))

(test w3-all-known-fork-batch-must-not-end-header-sync
  "THE REGRESSION. We hold a fork B1..B2 below our header tip (an aborted
presync, a peer rotation, or a restart mid-fork leaves exactly this). Phase 1
asks with a locator off the A-branch tip; the fork peer matches the fork point
and answers with a FULL batch of B headers — all of which we already have.

Plain index membership ended header sync there and returned DONE. Nothing
entered the index, so the next run-ibd cycle built the identical locator, got
the identical batch and stopped again: the fork could never be synced. Core
sends this shape to TryLowWorkHeadersSync (net_processing.cpp:2769-2800), which
starts a presync whose own locator anchors on the peer's chain and advances."
  (%w3-with-regtest
    (multiple-value-bind (state a-headers b-headers)
        (%w3-fork-fixture "test-w3-fork-presync/")
      (declare (ignore a-headers))
      (let* ((bitcoin-lisp:*minimum-chain-work-override* 1000)
             (b-last-hash (bitcoin-lisp.serialization:block-header-hash
                           (car (last b-headers))))
             (p (%g718-peer)))
        ;; Preconditions: the batch really is all-known, and really is off our
        ;; best-header/active chain — else the assertions below are vacuous.
        (is (not (null (bitcoin-lisp.storage:get-block-index-entry
                        state b-last-hash)))
            "fixture must already hold the whole fork batch")
        (is-false (bitcoin-lisp.networking::%ancestor-of-best-header-or-tip-p
                   state (bitcoin-lisp.storage:get-block-index-entry
                          state b-last-hash))
                  "the fork tip must be off our best-header/active chain")
        (let ((done (bitcoin-lisp.networking::handle-header-batch
                     p state b-headers t (lambda (n) (declare (ignore n))))))
          (is-false done
                    "an all-known FULL batch on a fork must NOT end header sync"))
        ;; And the next round actually makes progress: the follow-up getheaders
        ;; is anchored on the fork header just processed (Core
        ;; NextHeadersRequestLocator), not on our own header tip — a different
        ;; request from the one that produced this batch. Guarded, so that a
        ;; regression reads as failed assertions rather than an error inside
        ;; hss-locator-hashes.
        (let ((hss (bitcoin-lisp.networking::peer-headers-sync p)))
          (is (not (null hss))
              "it must divert into a presync, as Core's TryLowWorkHeadersSync does")
          (when hss
            (let ((next (bitcoin-lisp.networking::hss-locator-hashes hss))
                  (ours (bitcoin-lisp.networking::build-header-locator state)))
              (is (equalp b-last-hash (first next))
                  "the presync locator anchors on the peer's fork, advancing into its chain")
              (is-false (equalp (first next) (first ours))
                        "and differs from the header-tip locator that would repeat this batch"))))))))

(test w3-all-known-fork-batch-non-full-is-not-judged
  "The same class, non-full: Core's TryLowWorkHeadersSync logs \"Ignoring
low-work chain\" and returns true, so ProcessHeadersMessage returns without ever
reaching UpdatePeerStateForReceivedHeaders — no availability update and, above
all, no disconnect. Plain index membership sent this batch down the store path
instead and dropped an outbound peer Core keeps."
  (%w3-with-regtest
    (multiple-value-bind (state a-headers b-headers)
        (%w3-fork-fixture "test-w3-fork-nonfull/")
      (declare (ignore a-headers))
      (let ((bitcoin-lisp:*minimum-chain-work-override* 1000)
            (p (%g718-peer)))
        (is-true (bitcoin-lisp.networking:initial-block-download-p state)
                 "fixture must be in IBD, or the drop could not fire either way")
        (is-true (bitcoin-lisp.networking::handle-header-batch
                  p state b-headers nil (lambda (n) (declare (ignore n))))
                 "an ignored low-work batch ends header sync with this peer")
        (is (null (bitcoin-lisp.networking::peer-best-known-block-hash p))
            "an ignored batch must not update availability (Core never gets there)")
        (is (eq :ready (bitcoin-lisp.networking:peer-state p))
            "and must NOT drop the peer")))))

(test w3-all-known-batch-on-our-own-chain-still-ends-sync
  "The anti-DoS control the narrowing must NOT lose. A FULL batch of headers we
already hold ON OUR OWN CHAIN is Core's already_validated_work: the work gate is
skipped, no presync is started, and this loop stops asking — our locator is
built from our header tip, which the batch did not move, so re-asking would
fetch this very batch again (free round-trips for a peer replaying our own chain
at us)."
  (%w3-with-regtest
    (multiple-value-bind (state a-headers b-headers)
        (%w3-fork-fixture "test-w3-own-chain-stop/")
      (declare (ignore b-headers))
      (let* ((bitcoin-lisp:*minimum-chain-work-override* 1000)
             (a-last-hash (bitcoin-lisp.serialization:block-header-hash
                           (car (last a-headers))))
             (p (%g718-peer))
             (added 0))
        (is-true (bitcoin-lisp.networking::handle-header-batch
                  p state a-headers t (lambda (n) (incf added n)))
                 "an all-known FULL batch on our own chain must still end sync")
        (is (null (bitcoin-lisp.networking::peer-headers-sync p))
            "and must NOT start a presync — that is the suppression's whole point")
        (is (= 0 added) "an already-known batch adds nothing to the index")
        (is (equalp a-last-hash
                    (bitcoin-lisp.networking::peer-best-known-block-hash p))
            "the store path still ran, refreshing availability")
        (is (eq :ready (bitcoin-lisp.networking:peer-state p))
            "a full batch must not drop the peer")))))

(test w3-known-ancestor-batch-still-drops-low-work-outbound
  "The genuine low-work disconnect must still fire, and through the ANCESTOR arm
rather than an identity check: this batch ends at A1, an ancestor of our best
header A3 and not the best header itself. Core sets already_validated_work,
bypasses TryLowWorkHeadersSync, stores (nothing new) and reaches
UpdatePeerStateForReceivedHeaders — which drops the sub-minchainwork outbound
peer that has nothing more to give."
  (%w3-with-regtest
    (multiple-value-bind (state a-headers b-headers)
        (%w3-fork-fixture "test-w3-ancestor-drop/")
      (declare (ignore b-headers))
      (let* ((bitcoin-lisp:*minimum-chain-work-override* 1000)
             (a1 (first a-headers))
             (a1-hash (bitcoin-lisp.serialization:block-header-hash a1))
             (p (%g718-peer)))
        (is-true (bitcoin-lisp.networking:initial-block-download-p state)
                 "fixture must be in IBD, or the whole assertion is vacuous")
        (is (= 0 (bitcoin-lisp.networking::ingest-headers-from-peer
                  p (list a1) state))
            "an already-known header adds nothing to the index")
        (is (equalp a1-hash (bitcoin-lisp.networking::peer-best-known-block-hash p))
            "the store path must have refreshed availability from the known ancestor")
        (is (eq :disconnected (bitcoin-lisp.networking:peer-state p))
            "a sub-minchainwork outbound peer with nothing more to give is dropped")))))
