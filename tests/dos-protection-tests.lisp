(in-package #:bitcoin-lisp.tests)

(in-suite :dos-protection-tests)

;;;; ============================================================
;;;; 1. Token Bucket Rate Limiter Tests
;;;; ============================================================

(test token-bucket-creation
  "Token bucket should initialize with full tokens."
  (let ((bucket (bitcoin-lisp:make-rate-limiter 10.0 20.0)))
    (is (= 10.0 (bitcoin-lisp:token-bucket-rate bucket)))
    (is (= 20.0 (bitcoin-lisp:token-bucket-burst bucket)))
    ;; Starts full (tokens = burst)
    (is (= 20.0 (bitcoin-lisp:token-bucket-tokens bucket)))))

(test token-bucket-allows-within-burst
  "Token bucket should allow requests within burst capacity."
  (let ((bucket (bitcoin-lisp:make-rate-limiter 10.0 5.0)))
    ;; Should allow 5 requests (burst capacity)
    (dotimes (i 5)
      (is (bitcoin-lisp:token-bucket-allow-p bucket)))))

(test token-bucket-rejects-when-depleted
  "Token bucket should reject when tokens are depleted."
  (let ((bucket (bitcoin-lisp:make-rate-limiter 10.0 3.0)))
    ;; Consume all tokens
    (dotimes (i 3)
      (bitcoin-lisp:token-bucket-allow-p bucket))
    ;; Next request should be rejected
    (is (not (bitcoin-lisp:token-bucket-allow-p bucket)))))

(test token-bucket-refills-over-time
  "Token bucket should refill tokens based on elapsed time."
  (let ((bucket (bitcoin-lisp:make-rate-limiter 1000.0 5.0)))
    ;; Consume all tokens
    (dotimes (i 5)
      (bitcoin-lisp:token-bucket-allow-p bucket))
    ;; With a high rate (1000/sec), even a tiny delay should refill
    ;; Force a refill by manipulating last-refill time
    (setf (bitcoin-lisp::token-bucket-last-refill bucket)
          (- (get-internal-real-time) (* 2 internal-time-units-per-second)))
    ;; Should now allow (2 seconds at 1000/sec = 2000 tokens, capped at burst=5)
    (is (bitcoin-lisp:token-bucket-allow-p bucket))))

(test token-bucket-burst-caps-refill
  "Refilled tokens should not exceed burst capacity."
  (let ((bucket (bitcoin-lisp:make-rate-limiter 1000.0 3.0)))
    ;; Consume one token
    (bitcoin-lisp:token-bucket-allow-p bucket)
    ;; Simulate long delay
    (setf (bitcoin-lisp::token-bucket-last-refill bucket)
          (- (get-internal-real-time) (* 100 internal-time-units-per-second)))
    ;; Should allow exactly 3 (burst) then reject
    (dotimes (i 3)
      (is (bitcoin-lisp:token-bucket-allow-p bucket)))
    (is (not (bitcoin-lisp:token-bucket-allow-p bucket)))))

;;;; ============================================================
;;;; 2. Per-Peer Rate Limiting Tests
;;;; ============================================================

(test peer-rate-limiters-initialized
  "Peer rate limiters should be initialized from config."
  (let ((peer (bitcoin-lisp.networking::make-peer)))
    (bitcoin-lisp.networking:init-peer-rate-limiters peer)
    ;; All rate limiters should be non-nil
    (is (not (null (bitcoin-lisp.networking::peer-rate-limit-inv peer))))
    (is (not (null (bitcoin-lisp.networking::peer-rate-limit-tx peer))))
    (is (not (null (bitcoin-lisp.networking::peer-rate-limit-addr peer))))
    (is (not (null (bitcoin-lisp.networking::peer-rate-limit-getdata peer))))
    (is (not (null (bitcoin-lisp.networking::peer-rate-limit-headers peer))))))

(test check-peer-rate-limit-allows-normal
  "Rate limit check should allow messages within limits."
  (let ((peer (bitcoin-lisp.networking::make-peer)))
    (bitcoin-lisp.networking:init-peer-rate-limiters peer)
    ;; Each message type should allow at least one message
    (is (bitcoin-lisp.networking:check-peer-rate-limit peer "inv"))
    (is (bitcoin-lisp.networking:check-peer-rate-limit peer "tx"))
    (is (bitcoin-lisp.networking:check-peer-rate-limit peer "addr"))
    (is (bitcoin-lisp.networking:check-peer-rate-limit peer "addrv2"))
    (is (bitcoin-lisp.networking:check-peer-rate-limit peer "getdata"))
    (is (bitcoin-lisp.networking:check-peer-rate-limit peer "headers"))))

(test check-peer-rate-limit-unknown-command
  "Rate limit check for unknown commands should always pass."
  (let ((peer (bitcoin-lisp.networking::make-peer)))
    (bitcoin-lisp.networking:init-peer-rate-limiters peer)
    (is (bitcoin-lisp.networking:check-peer-rate-limit peer "ping"))
    (is (bitcoin-lisp.networking:check-peer-rate-limit peer "pong"))
    (is (bitcoin-lisp.networking:check-peer-rate-limit peer "version"))))

(test check-peer-rate-limit-rejects-flood
  "Rate limit check should reject when burst is exceeded."
  (let ((peer (bitcoin-lisp.networking::make-peer)))
    ;; Use a very low burst for testing
    (let ((bitcoin-lisp:*rate-limit-addr* '(1.0 . 2.0)))
      (bitcoin-lisp.networking:init-peer-rate-limiters peer)
      ;; Consume the burst
      (dotimes (i 2)
        (bitcoin-lisp.networking:check-peer-rate-limit peer "addr"))
      ;; Next should fail
      (is (not (bitcoin-lisp.networking:check-peer-rate-limit peer "addr"))))))

;;;; ============================================================
;;;; 3. Handshake Timeout Tests
;;;; ============================================================

(test handshake-timeout-ok-when-ready
  "Ready peers should not be flagged for handshake timeout."
  (let ((peer (bitcoin-lisp.networking::make-peer :state :ready)))
    ;; check-handshake-timeout is only called for non-ready peers
    ;; via check-peer-health, which returns early for ready peers
    (is (eq :ok (bitcoin-lisp.networking:check-handshake-timeout peer)))))

(test handshake-timeout-ok-when-recent
  "Peers with recent connect time should be ok."
  (let ((peer (bitcoin-lisp.networking::make-peer
               :state :handshaking
               :connect-time (get-internal-real-time))))
    (is (eq :ok (bitcoin-lisp.networking:check-handshake-timeout peer)))))

(test handshake-timeout-disconnect-when-expired
  "Peers that exceeded handshake timeout should be flagged for disconnect."
  (let* ((past-time (- (get-internal-real-time)
                       (* (1+ bitcoin-lisp:+handshake-timeout-seconds+)
                          internal-time-units-per-second)))
         (peer (bitcoin-lisp.networking::make-peer
                :state :handshaking
                :connect-time past-time)))
    (is (eq :disconnect (bitcoin-lisp.networking:check-handshake-timeout peer)))))

(test handshake-timeout-not-checked-for-zero-connect-time
  "Peers with connect-time 0 (default) should not be timed out."
  (let ((peer (bitcoin-lisp.networking::make-peer
               :state :connecting
               :connect-time 0)))
    (is (eq :ok (bitcoin-lisp.networking:check-handshake-timeout peer)))))

;;;; ============================================================
;;;; 4. Maximum Message Payload Tests
;;;; ============================================================

(test max-message-payload-constant
  "Max message payload should be 4,000,000 bytes (Core MAX_PROTOCOL_MESSAGE_LENGTH,
decimal 4e6 -- not 4 MiB)."
  (is (= (* 4 1000 1000) bitcoin-lisp:+max-message-payload+)))

;;;; ============================================================
;;;; 5. Recent Transaction Rejects Filter Tests
;;;; ============================================================

(defun make-test-txid (byte-val)
  "Create a test txid with a specific byte value."
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element byte-val))

(test recent-rejects-creation
  "Recent rejects filter should be created correctly."
  (let ((filter (bitcoin-lisp:make-rejects-filter 100)))
    (is (not (null filter)))
    ;; Empty filter should not match anything
    (is (not (bitcoin-lisp:recent-reject-p filter (make-test-txid 1))))))

(test recent-rejects-add-and-check
  "Adding a hash should make it detectable."
  (let ((filter (bitcoin-lisp:make-rejects-filter 100))
        (txid (make-test-txid 42)))
    ;; Not present yet
    (is (not (bitcoin-lisp:recent-reject-p filter txid)))
    ;; Add it
    (is (bitcoin-lisp:add-recent-reject filter txid))
    ;; Now present
    (is (bitcoin-lisp:recent-reject-p filter txid))))

(test recent-rejects-duplicate-add
  "Adding an already-present hash should return NIL."
  (let ((filter (bitcoin-lisp:make-rejects-filter 100))
        (txid (make-test-txid 42)))
    ;; First add succeeds
    (is (bitcoin-lisp:add-recent-reject filter txid))
    ;; Duplicate add returns NIL
    (is (not (bitcoin-lisp:add-recent-reject filter txid)))))

(test recent-rejects-eviction
  "Filter should evict oldest entry when at capacity."
  (let ((filter (bitcoin-lisp:make-rejects-filter 3)))
    ;; Fill to capacity
    (bitcoin-lisp:add-recent-reject filter (make-test-txid 1))
    (bitcoin-lisp:add-recent-reject filter (make-test-txid 2))
    (bitcoin-lisp:add-recent-reject filter (make-test-txid 3))
    ;; All present
    (is (bitcoin-lisp:recent-reject-p filter (make-test-txid 1)))
    (is (bitcoin-lisp:recent-reject-p filter (make-test-txid 2)))
    (is (bitcoin-lisp:recent-reject-p filter (make-test-txid 3)))
    ;; Add one more - should evict oldest (1)
    (bitcoin-lisp:add-recent-reject filter (make-test-txid 4))
    (is (not (bitcoin-lisp:recent-reject-p filter (make-test-txid 1))))
    (is (bitcoin-lisp:recent-reject-p filter (make-test-txid 4)))))

(test recent-rejects-clear
  "Clearing filter should remove all entries."
  (let ((filter (bitcoin-lisp:make-rejects-filter 100)))
    (bitcoin-lisp:add-recent-reject filter (make-test-txid 1))
    (bitcoin-lisp:add-recent-reject filter (make-test-txid 2))
    ;; Clear
    (bitcoin-lisp:clear-recent-rejects filter)
    ;; Should be empty
    (is (not (bitcoin-lisp:recent-reject-p filter (make-test-txid 1))))
    (is (not (bitcoin-lisp:recent-reject-p filter (make-test-txid 2))))))

(test recent-rejects-nil-filter-safe
  "Operations on NIL filter should be safe (no errors)."
  (is (not (bitcoin-lisp:recent-reject-p nil (make-test-txid 1))))
  (is (not (bitcoin-lisp:add-recent-reject nil (make-test-txid 1))))
  (finishes (bitcoin-lisp:clear-recent-rejects nil)))

;;;; ============================================================
;;;; 6. RPC Rate Limiting Tests
;;;; ============================================================

(test rpc-rate-limiter-initialization
  "RPC rate limiter should be initialized from config."
  (let ((bitcoin-lisp:*rpc-rate-limit* '(10.0 . 5.0))
        (bitcoin-lisp.rpc::*rpc-rate-limiter* nil))
    (bitcoin-lisp.rpc::init-rpc-rate-limiter)
    (is (not (null bitcoin-lisp.rpc::*rpc-rate-limiter*)))
    ;; Should allow requests within burst
    (is (bitcoin-lisp.rpc::rpc-rate-limit-check))
    ;; Cleanup
    (setf bitcoin-lisp.rpc::*rpc-rate-limiter* nil)))

(test rpc-rate-limiter-rejects-flood
  "RPC rate limiter should reject when burst exceeded."
  (let ((bitcoin-lisp:*rpc-rate-limit* '(1.0 . 3.0))
        (bitcoin-lisp.rpc::*rpc-rate-limiter* nil))
    (bitcoin-lisp.rpc::init-rpc-rate-limiter)
    ;; Consume burst
    (dotimes (i 3)
      (bitcoin-lisp.rpc::rpc-rate-limit-check))
    ;; Next should fail
    (is (not (bitcoin-lisp.rpc::rpc-rate-limit-check)))
    ;; Cleanup
    (setf bitcoin-lisp.rpc::*rpc-rate-limiter* nil)))

(test rpc-rate-limiter-nil-allows-all
  "When rate limiter is nil, all requests should be allowed."
  (let ((bitcoin-lisp.rpc::*rpc-rate-limiter* nil))
    (is (bitcoin-lisp.rpc::rpc-rate-limit-check))))

;;;; ============================================================
;;;; 7. RPC Body Size Limit Tests
;;;; ============================================================

(test max-rpc-body-size-constant
  "Max RPC body size should be 1 MB."
  (is (= (* 1 1024 1024) bitcoin-lisp:+max-rpc-body-size+)))

;;;; ============================================================
;;;; Configuration Tests
;;;; ============================================================

(test dos-config-defaults
  "Default DoS configuration values should be reasonable."
  ;; Rate limits are (rate . burst) cons cells
  (is (consp bitcoin-lisp:*rate-limit-inv*))
  (is (consp bitcoin-lisp:*rate-limit-tx*))
  (is (consp bitcoin-lisp:*rate-limit-addr*))
  (is (consp bitcoin-lisp:*rate-limit-getdata*))
  (is (consp bitcoin-lisp:*rate-limit-headers*))
  (is (consp bitcoin-lisp:*rpc-rate-limit*))
  ;; Constants
  (is (> bitcoin-lisp:+max-message-payload+ 0))
  (is (> bitcoin-lisp:+max-rpc-body-size+ 0))
  (is (> bitcoin-lisp:+handshake-timeout-seconds+ 0)))

;;;; ============================================================
;;;; Discouragement (soft-ban) Tests
;;;; ============================================================

(test discourage-and-check
  "discourage-peer marks an address; peer-discouraged-p reports it."
  (bitcoin-lisp.networking:clear-discouraged)
  (is (not (bitcoin-lisp.networking:peer-discouraged-p "203.0.113.7")))
  (bitcoin-lisp.networking:discourage-peer "203.0.113.7")
  (is (bitcoin-lisp.networking:peer-discouraged-p "203.0.113.7"))
  ;; Unrelated address is unaffected.
  (is (not (bitcoin-lisp.networking:peer-discouraged-p "203.0.113.8")))
  (bitcoin-lisp.networking:clear-discouraged)
  (is (not (bitcoin-lisp.networking:peer-discouraged-p "203.0.113.7"))))

(test discourage-ignores-empty-address
  "Empty/blank addresses are never discouraged."
  (bitcoin-lisp.networking:clear-discouraged)
  (bitcoin-lisp.networking:discourage-peer "")
  (is (not (bitcoin-lisp.networking:peer-discouraged-p ""))))

(test connect-peer-refuses-discouraged
  "connect-peer returns NIL for a discouraged host (never dial it)."
  (bitcoin-lisp.networking:clear-discouraged)
  (bitcoin-lisp.networking:discourage-peer "192.0.2.123")
  ;; 192.0.2.0/24 (TEST-NET-1) never routes, so a non-discouraged dial here would
  ;; fail at connect time anyway — but the discouraged guard returns NIL first.
  (is (null (bitcoin-lisp.networking:connect-peer "192.0.2.123" 18333)))
  (bitcoin-lisp.networking:clear-discouraged))

;;;; ============================================================
;;;; Serve-request rate limiting (getheaders/getblocks/getaddr)
;;;; ============================================================

(test rate-limit-serve-config-present
  "The shared serve-request rate-limit config is a (rate . burst) pair."
  (is (consp bitcoin-lisp:*rate-limit-serve*)))

(test rate-limit-serve-throttles-getheaders-flood
  "A flood of getheaders is throttled (eventually denied), and getblocks/getaddr
share the same bucket — once it's drained, they are denied too."
  (let ((peer (bitcoin-lisp.networking:make-peer)))
    (bitcoin-lisp.networking::init-peer-rate-limiters peer)
    ;; The first call is allowed (full burst); drive well past the burst rapidly.
    (is-true (bitcoin-lisp.networking::check-peer-rate-limit peer "getheaders"))
    (let ((denied nil))
      (dotimes (i 100)
        (unless (bitcoin-lisp.networking::check-peer-rate-limit peer "getheaders")
          (setf denied t)))
      (is-true denied))
    ;; Bucket is shared: getblocks and getaddr are now denied as well.
    (is-false (bitcoin-lisp.networking::check-peer-rate-limit peer "getblocks"))
    (is-false (bitcoin-lisp.networking::check-peer-rate-limit peer "getaddr"))))

(test rate-limit-unrelated-command-unaffected
  "Draining the serve bucket does not throttle an unrelated command (ping)."
  (let ((peer (bitcoin-lisp.networking:make-peer)))
    (bitcoin-lisp.networking::init-peer-rate-limiters peer)
    (dotimes (i 100) (bitcoin-lisp.networking::check-peer-rate-limit peer "getheaders"))
    ;; ping has no bucket -> always allowed.
    (is-true (bitcoin-lisp.networking::check-peer-rate-limit peer "ping"))))

;;;; ============================================================
;;;; Concurrency hardening (recursive node-lock, ban-lock, node-peers)
;;;; ============================================================

(test recursive-lock-nesting-works
  "A recursive lock can be re-acquired by the same thread (the mechanism
node-lock now uses); a non-recursive lock would deadlock here."
  (let ((lock (bt:make-recursive-lock "test")))
    (is (eq :ok (bt:with-recursive-lock-held (lock)
                  (bt:with-recursive-lock-held (lock) :ok))))))

(test node-lock-is-recursive
  "node-lock is recursive: nested acquisition on the real node lock succeeds."
  (let ((node (bitcoin-lisp::make-node)))
    (is (eq :ok (bt:with-recursive-lock-held ((bitcoin-lisp::node-lock node))
                  (bt:with-recursive-lock-held ((bitcoin-lisp::node-lock node))
                    :ok))))))

(defun %inbound-peer (addr ping connect-time)
  (bitcoin-lisp.networking:make-peer
   :address addr :inbound t :state :ready
   :ping-latency ping :connect-time connect-time))

(test anchors-save-load-roundtrip
  "save-anchors persists up to +max-anchors+ ready outbound peers; load-anchors
restores them (in order) for priority reconnection. Inbound peers excluded."
  (let* ((dir (ensure-directories-exist
               (merge-pathnames "test-anchors/" (uiop:temporary-directory))))
         (node (bitcoin-lisp::make-node)))
    (setf (bitcoin-lisp::node-data-directory node) dir)
    (setf (bitcoin-lisp::node-peers node)
          (list (bitcoin-lisp.networking:make-peer :address "1.2.3.4" :inbound nil :state :ready)
                (bitcoin-lisp.networking:make-peer :address "5.6.7.8" :inbound nil :state :ready)
                (bitcoin-lisp.networking:make-peer :address "9.9.9.9" :inbound nil :state :ready)
                (bitcoin-lisp.networking:make-peer :address "7.7.7.7" :inbound t   :state :ready)))
    (bitcoin-lisp::save-anchors node)        ; saves the first 2 ready outbound
    (let ((bitcoin-lisp::*pending-anchor-addresses* nil))
      (bitcoin-lisp::load-anchors node)
      (is (equal '("1.2.3.4" "5.6.7.8") bitcoin-lisp::*pending-anchor-addresses*)))))

(test anchors-load-missing-file-noop
  "load-anchors on a directory with no anchors.dat doesn't crash or set anchors."
  (let* ((dir (ensure-directories-exist
               (merge-pathnames "test-anchors-empty/" (uiop:temporary-directory))))
         (node (bitcoin-lisp::make-node)))
    (setf (bitcoin-lisp::node-data-directory node) dir)
    (ignore-errors (delete-file (bitcoin-lisp::anchors-dat-path dir)))
    (let ((bitcoin-lisp::*pending-anchor-addresses* nil))
      (bitcoin-lisp::load-anchors node)
      (is (null bitcoin-lisp::*pending-anchor-addresses*)))))

(test evict-least-valuable-inbound-protects-best
  "evict-least-valuable-inbound shields the most valuable inbound peers (lowest
ping, longest connected) and evicts an unprotected one — the youngest in the
most-represented netgroup — so inbound slots churn toward better peers instead
of an attacker's cheap, sticky connections holding them."
  (let ((node (bitcoin-lisp::make-node)))
    ;; A-D: low ping + old (protected on both dimensions). E,F: high ping +
    ;; young, same /16 netgroup (the eviction candidates).
    (let ((a (%inbound-peer "1.1.1.1" 10 100))
          (b (%inbound-peer "2.2.2.2" 20 200))
          (c (%inbound-peer "3.3.3.3" 30 300))
          (d (%inbound-peer "4.4.4.4" 40 400))
          (e (%inbound-peer "10.0.0.1" 1000 5000))
          (f (%inbound-peer "10.0.0.2" 2000 6000)))   ; youngest candidate
      (setf (bitcoin-lisp::node-peers node) (list a b c d e f))
      (is (eq t (bitcoin-lisp::evict-least-valuable-inbound node)))
      ;; F (youngest in the populous netgroup) evicted; everyone else kept.
      (let ((remaining (bitcoin-lisp::node-peers node)))
        (is (not (member f remaining)))
        (is (member e remaining))
        (dolist (p (list a b c d)) (is (member p remaining)))))))

(test evict-least-valuable-inbound-noop-when-all-protected
  "With too few inbound peers (all protected), nothing is evicted."
  (let ((node (bitcoin-lisp::make-node)))
    (setf (bitcoin-lisp::node-peers node)
          (list (%inbound-peer "1.1.1.1" 10 100)
                (%inbound-peer "2.2.2.2" 20 200)))
    (is (null (bitcoin-lisp::evict-least-valuable-inbound node)))
    (is (= 2 (length (bitcoin-lisp::node-peers node))))))

(test ban-lock-concurrent-stress
  "Many threads hammering the discourage/ban globals do not crash or corrupt
the shared structures (the *ban-lock* serializes their mutations)."
  (bitcoin-lisp.networking:clear-discouraged)
  (bitcoin-lisp.networking:clear-ban-list)
  (let ((threads '()))
    (dotimes (i 8)
      (push (bt:make-thread
             (lambda ()
               (dotimes (j 2000)
                 (let ((addr (format nil "10.0.~D.~D" (mod j 5) i)))
                   (bitcoin-lisp.networking:discourage-peer addr)
                   (bitcoin-lisp.networking:peer-discouraged-p addr)
                   (bitcoin-lisp.networking:peer-banned-p addr)))))
            threads))
    (dolist (th threads) (bt:join-thread th))
    ;; Still functional after the contention.
    (bitcoin-lisp.networking:discourage-peer "203.0.113.50")
    (is-true (bitcoin-lisp.networking:peer-discouraged-p "203.0.113.50"))
    (bitcoin-lisp.networking:clear-discouraged)))

(test node-peers-concurrent-stress
  "A writer mutating node-peers and a reader copy-listing it (both under
node-lock) run concurrently without crashing or deadlocking."
  (let ((node (bitcoin-lisp::make-node)))
    (let ((writer (bt:make-thread
                   (lambda ()
                     (dotimes (i 3000)
                       (bt:with-recursive-lock-held ((bitcoin-lisp::node-lock node))
                         (push (bitcoin-lisp.networking:make-peer)
                               (bitcoin-lisp::node-peers node)))
                       (bt:with-recursive-lock-held ((bitcoin-lisp::node-lock node))
                         (when (bitcoin-lisp::node-peers node)
                           (setf (bitcoin-lisp::node-peers node)
                                 (rest (bitcoin-lisp::node-peers node)))))))))
          (reader (bt:make-thread
                   (lambda ()
                     (dotimes (i 3000)
                       (bt:with-recursive-lock-held ((bitcoin-lisp::node-lock node))
                         (length (copy-list (bitcoin-lisp::node-peers node)))))))))
      (bt:join-thread writer)
      (bt:join-thread reader)
      (is-true t))))
