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
  "Max RPC body size is Core's MAX_SIZE = 32 MiB (httpserver.cpp:410,
serialize.h:32) — the old 1 MiB cap broke submitblock for mainnet blocks."
  (is (= #x02000000 bitcoin-lisp:+max-rpc-body-size+)))

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
    (let ((bitcoin-lisp::*pending-anchor-addresses* nil)
          ;; Connection-less test peers save the network default port; load
          ;; yields (host . stored-port) dial candidates.
          (dp (bitcoin-lisp::network-port (bitcoin-lisp::node-network node))))
      (bitcoin-lisp::load-anchors node)
      (is (equal (list (cons "1.2.3.4" dp) (cons "5.6.7.8" dp))
                 bitcoin-lisp::*pending-anchor-addresses*)))))

(test anchors-v1-file-migrates-on-load
  "A pre-P1 anchors.dat (magic ANC1, bare IP strings, no port) still loads:
entries parse to typed addresses and become dial candidates; the next save
writes the v2 network-typed format."
  (let* ((dir (ensure-directories-exist
               (merge-pathnames "test-anchors-v1/" (uiop:temporary-directory))))
         (node (bitcoin-lisp::make-node))
         (path (bitcoin-lisp::anchors-dat-path dir)))
    (setf (bitcoin-lisp::node-data-directory node) dir)
    ;; Byte-faithful ANC1 writer (the pre-P1 save-anchors format): magic,
    ;; count, then len-prefixed address strings — via the same CRC32 wrapper.
    (bitcoin-lisp.storage:save-file-with-crc32
     path
     (lambda (stream)
       (loop for shift in '(24 16 8 0)
             do (write-byte (ldb (byte 8 shift) bitcoin-lisp::+anchors-magic-v1+) stream))
       (write-byte 3 stream)
       (dolist (a '("203.0.113.7" "2001:db8::7" "not-an-address.example"))
         (let ((bytes (map '(vector (unsigned-byte 8)) #'char-code a)))
           (write-byte (length bytes) stream)
           (write-sequence bytes stream)))))
    (let ((bitcoin-lisp::*pending-anchor-addresses* nil)
          (bitcoin-lisp.networking:*reachable-networks* '(:ipv4 :ipv6)))
      (bitcoin-lisp::load-anchors node)
      ;; IP entries survive (the hostname is dropped — never representable).
      ;; Our IPv6 rendering is the full uncompressed form (no RFC5952 "::").
      ;; Migrated v1 entries carry port NIL (dial at the network default).
      (is (equal '(("203.0.113.7" . nil)
                   ("2001:0db8:0000:0000:0000:0000:0000:0007" . nil))
                 bitcoin-lisp::*pending-anchor-addresses*)))
    ;; Re-save from live peers: the file is rewritten as v2.
    (setf (bitcoin-lisp::node-peers node)
          (list (bitcoin-lisp.networking:make-peer :address "203.0.113.7"
                                                   :inbound nil :state :ready)))
    (bitcoin-lisp::save-anchors node)
    (let ((bytes (bitcoin-lisp.storage:load-file-with-crc32 path 6)))
      (is (= bitcoin-lisp::+anchors-magic-v2+
             (logior (ash (aref bytes 0) 24) (ash (aref bytes 1) 16)
                     (ash (aref bytes 2) 8) (aref bytes 3)))))))

(test anchors-v2-round-trip-typed-and-filtered
  "The v2 anchors format round-trips (net, bytes, port); on load only
networks dialable under the current config (and reachable) become dial
candidates, and each is dialed at its STORED port — an onion anchor yields
a dial target iff a Tor proxy is configured."
  (let* ((dir (ensure-directories-exist
               (merge-pathnames "test-anchors-v2/" (uiop:temporary-directory))))
         (node (bitcoin-lisp::make-node))
         (path (bitcoin-lisp::anchors-dat-path dir))
         (onion-pk (bitcoin-lisp.crypto:hex-to-bytes
                    "79bcc625184b05194975c28b66b66b0469f7f6556fb1ac3189a79b40dda32f1f"))
         (onion-str (bitcoin-lisp.networking:onion-address-string onion-pk))
         ;; Distinct non-default ports prove the STORED port is what loads.
         (entries (list (list :ipv4 (bitcoin-lisp.networking:ipv4-to-mapped-ipv6 9 9 9 9) 4567)
                        (list :torv3 onion-pk 8333))))
    (setf (bitcoin-lisp::node-data-directory node) dir)
    (bitcoin-lisp::save-anchor-entries path entries)
    ;; Byte-level round trip.
    (let ((parsed (bitcoin-lisp::parse-anchor-entries
                   (bitcoin-lisp.storage:load-file-with-crc32 path 6))))
      (is (= 2 (length parsed)))
      (destructuring-bind (net bytes port) (first parsed)
        (is (eq :ipv4 net))
        (is (equalp (bitcoin-lisp.networking:ipv4-to-mapped-ipv6 9 9 9 9) bytes))
        (is (= 4567 port)))
      (destructuring-bind (net bytes port) (second parsed)
        (is (eq :torv3 net))
        (is (equalp onion-pk bytes))
        (is (= 8333 port))))
    ;; No Tor proxy: only the IPv4 anchor comes back, at its stored port.
    (let ((bitcoin-lisp::*pending-anchor-addresses* nil)
          (bitcoin-lisp.networking:*onion-proxy* nil)
          (bitcoin-lisp.networking:*reachable-networks*
            (copy-list bitcoin-lisp.networking:+bip155-networks+)))
      (bitcoin-lisp::load-anchors node)
      (is (equal '(("9.9.9.9" . 4567)) bitcoin-lisp::*pending-anchor-addresses*)))
    ;; With a Tor proxy the onion anchor becomes a dial candidate too —
    ;; formatted .onion string + stored port (the P2 anchors redial path).
    (let ((bitcoin-lisp::*pending-anchor-addresses* nil)
          (bitcoin-lisp.networking:*onion-proxy*
            (bitcoin-lisp.networking:make-proxy :host "127.0.0.1" :port 9050))
          (bitcoin-lisp.networking:*reachable-networks*
            (copy-list bitcoin-lisp.networking:+bip155-networks+)))
      (bitcoin-lisp::load-anchors node)
      (is (equal (list '("9.9.9.9" . 4567) (cons onion-str 8333))
                 bitcoin-lisp::*pending-anchor-addresses*)))))

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

;;;; ============================================================
;;;; Live-wedge regressions (2026-08-16)
;;;;
;;;; Three defects that between them froze both production nodes. All were
;;;; found on live processes, so each test reproduces the observed condition
;;;; and carries a control that must fail without the fix.
;;;; ============================================================

(defun %silent-peer-connection (announced-bytes delivered-bytes)
  "A loopback peer that delivers DELIVERED-BYTES and then goes silent forever,
while the reader is about to ask for ANNOUNCED-BYTES. Returns
(VALUES connection client-socket server-socket listener)."
  (let* ((listener (usocket:socket-listen "127.0.0.1" 0
                                          :element-type '(unsigned-byte 8)))
         (port (usocket:get-local-port listener))
         (client (usocket:socket-connect "127.0.0.1" port
                                         :element-type '(unsigned-byte 8)))
         (server (usocket:socket-accept listener :element-type '(unsigned-byte 8))))
    (declare (ignore announced-bytes))
    (write-sequence (make-array delivered-bytes :element-type '(unsigned-byte 8)
                                                :initial-element 7)
                    (usocket:socket-stream client))
    (force-output (usocket:socket-stream client))
    (sleep 0.2)
    (values (bitcoin-lisp.networking::make-connection :socket server :connected t)
            client server listener)))

(defun %run-bounded (thunk &key (limit 8))
  "Run THUNK in a thread. Returns (VALUES finished-p result). A thunk still
running at LIMIT seconds is destroyed and reported as unfinished."
  (let* ((done (bt:make-semaphore))
         (result nil)
         (thread (bt:make-thread (lambda ()
                                   (setf result (ignore-errors (funcall thunk)))
                                   (bt:signal-semaphore done)))))
    (let ((finished (bt:wait-on-semaphore done :timeout limit)))
      (unless finished (bt:destroy-thread thread))
      (values (and finished t) result))))

(test receive-bytes-bounds-a-peer-that-stalls-mid-message
  "A peer that announces a large payload, sends a few bytes and then goes
silent must not pin the reader. Before the fix this hung forever in poll():
READ-SEQUENCE fills the whole buffer or blocks, while WAIT-FOR-INPUT only
promises one readable byte. Because the message pump is serial, one such peer
froze a live node's entire network layer for five days."
  (multiple-value-bind (conn client server listener)
      (%silent-peer-connection 1000 3)
    (unwind-protect
         (multiple-value-bind (finished result)
             (%run-bounded (lambda ()
                             (bitcoin-lisp.networking::receive-bytes
                              conn 1000 :timeout 2))
                           :limit 8)
           (is-true finished
                    "receive-bytes must return, not block past its timeout")
           (is (null result) "a stalled read reports failure")
           ;; The aborted read consumed an unknown number of bytes, so the
           ;; stream can never be resynchronized: the connection must be dead.
           (is-false (bitcoin-lisp.networking::connection-connected conn)))
      (usocket:socket-close client)
      (usocket:socket-close server)
      (usocket:socket-close listener))))

(test receive-bytes-control-unbounded-read-still-hangs
  "Control for the test above: the pre-fix shape (WAIT-FOR-INPUT then a bare
READ-SEQUENCE) must still be running when the observation window closes. If
this ever 'passes' quickly, the test above has stopped proving anything."
  (multiple-value-bind (conn client server listener)
      (%silent-peer-connection 1000 3)
    (unwind-protect
         (multiple-value-bind (finished result)
             (%run-bounded
              (lambda ()
                (let ((buffer (make-array 1000 :element-type '(unsigned-byte 8))))
                  (usocket:wait-for-input
                   (bitcoin-lisp.networking::connection-socket conn)
                   :timeout 2 :ready-only t)
                  (read-sequence buffer
                                 (bitcoin-lisp.networking::connection-stream conn))))
              :limit 4)
           (declare (ignore result))
           (is-false finished
                     "an unbounded read must still be blocked — otherwise the
regression test above is vacuous"))
      (usocket:socket-close client)
      (usocket:socket-close server)
      (usocket:socket-close listener))))

(test sync-blockchain-survives-a-peer-list-of-only-dead-peers
  "Peers enter NODE-PEERS only after a successful handshake, but they stay
there once they go :DISCONNECTED — reaping happens in MAINTAIN-PEERS, which the
sync loop runs AFTER sync-blockchain. So a list of nothing but dead peers is
reachable, FIND-BEST-PEER returns NIL for it, and the old code handed that NIL
to the PEER-START-HEIGHT accessor. The resulting type error unwound the sync
iteration, so maintain-peers never ran, so the dead peers were never reaped or
redialed — the failure fed itself. A live node logged it every five seconds for
nineteen days."
  (let ((node (bitcoin-lisp::make-node)))
    (setf (bitcoin-lisp::node-peers node)
          (list (bitcoin-lisp.networking:make-peer :state :disconnected)
                (bitcoin-lisp.networking:make-peer :state :disconnected)))
    ;; Control: the precondition the bug needs must actually hold here.
    (is (null (bitcoin-lisp::find-best-peer node))
        "no peer is :READY, so this exercises the NIL path")
    (is (= 0 (bitcoin-lisp::sync-blockchain node))
        "the cycle is skipped cleanly instead of signalling a type error")))

(test inbound-admission-counts-the-pending-handoff-queue
  "Accepted peers wait in PENDING-INBOUND-PEERS until the sync thread merges
them. Admission used to count only merged peers, so a stalled sync thread let
the queue — and its file descriptors — grow without bound: the live wedge left
751 sockets rotting in CLOSE-WAIT. Admission must count the backlog too."
  (let ((node (bitcoin-lisp::make-node)))
    ;; Control: an empty backlog admits.
    (is-true (bitcoin-lisp::inbound-connection-allowed-p node "198.51.100.7"))
    (setf (bitcoin-lisp::node-pending-inbound-peers node)
          (loop repeat bitcoin-lisp::*max-inbound-connections*
                collect (bitcoin-lisp.networking:make-peer :inbound t)))
    (multiple-value-bind (allowed reason)
        (bitcoin-lisp::inbound-connection-allowed-p node "198.51.100.7")
      (is-false allowed "a full hand-off queue must stop admitting")
      (is (eq :backlog reason)))))

(test receive-bytes-tolerates-a-slow-but-progressing-peer
  "TIMEOUT bounds stalling, not total transfer time. A 1 MiB message arriving
in chunks over several seconds — far longer than the caller's one-second
timeout, but always progressing and comfortably above the rate floor — must
complete. A total-time cap would look like a fix for the stall bug while
quietly breaking block download, so this is the counterweight to the tests
above."
  (let* ((listener (usocket:socket-listen "127.0.0.1" 0
                                          :element-type '(unsigned-byte 8)))
         (port (usocket:get-local-port listener))
         (client (usocket:socket-connect "127.0.0.1" port
                                         :element-type '(unsigned-byte 8)))
         (server (usocket:socket-accept listener :element-type '(unsigned-byte 8)))
         (conn (bitcoin-lisp.networking::make-connection :socket server :connected t))
         (chunk (* 100 1024))
         (chunks 10)
         (total (* chunk chunks))
         (sender (bt:make-thread
                  (lambda ()
                    ;; ~340 KiB/s overall: well above the floor, and no gap
                    ;; anywhere near the one-second stall bound, but the whole
                    ;; transfer takes about three seconds.
                    (dotimes (i chunks)
                      (handler-case
                          (progn
                            (write-sequence
                             (make-array chunk :element-type '(unsigned-byte 8)
                                               :initial-element 9)
                             (usocket:socket-stream client))
                            (force-output (usocket:socket-stream client)))
                        (error () (return)))
                      (sleep 0.3))))))
    (unwind-protect
         (multiple-value-bind (finished result)
             (%run-bounded (lambda ()
                             (bitcoin-lisp.networking::receive-bytes
                              conn total :timeout 1))
                           :limit 30)
           (is-true finished "the read must terminate")
           (is (and result (= total (length result)))
               "a peer that keeps making progress delivers its whole message")
           (is-true (bitcoin-lisp.networking::connection-connected conn)
                    "and keeps its connection"))
      (ignore-errors (bt:join-thread sender))
      (usocket:socket-close client)
      (usocket:socket-close server)
      (usocket:socket-close listener))))

(test receive-bytes-idle-poll-does-not-disconnect
  "The pump polls peers with a short timeout; a peer that is simply idle must
survive it. Only a read that already consumed part of a message may kill the
connection (the stream cannot be resynchronized after that) — getting this
backwards would disconnect every quiet peer on every poll."
  (let* ((listener (usocket:socket-listen "127.0.0.1" 0
                                          :element-type '(unsigned-byte 8)))
         (port (usocket:get-local-port listener))
         (client (usocket:socket-connect "127.0.0.1" port
                                         :element-type '(unsigned-byte 8)))
         (server (usocket:socket-accept listener :element-type '(unsigned-byte 8)))
         (conn (bitcoin-lisp.networking::make-connection :socket server :connected t)))
    (unwind-protect
         (progn
           ;; Nothing sent at all: a pure idle poll.
           (is (null (bitcoin-lisp.networking::receive-bytes conn 24 :timeout 1)))
           (is-true (bitcoin-lisp.networking::connection-connected conn)
                    "an idle peer keeps its connection"))
      (usocket:socket-close client)
      (usocket:socket-close server)
      (usocket:socket-close listener))))

(test socks5-recv-bounds-a-proxy-that-stalls-mid-reply
  "%SOCKS5-RECV was written to mirror RECEIVE-BYTES and inherited its defect:
a proxy that answers partially and then goes quiet blocked inside READ-SEQUENCE
forever, so the deadline the function computes could never be consulted again.
An outbound connection attempt through a hostile or broken proxy must fail,
not hang."
  (let* ((listener (usocket:socket-listen "127.0.0.1" 0
                                          :element-type '(unsigned-byte 8)))
         (port (usocket:get-local-port listener))
         (client (usocket:socket-connect "127.0.0.1" port
                                         :element-type '(unsigned-byte 8)))
         (proxy-side (usocket:socket-accept listener :element-type '(unsigned-byte 8))))
    (unwind-protect
         (progn
           ;; The "proxy" sends one byte of a two-byte reply, then nothing.
           (write-byte 5 (usocket:socket-stream proxy-side))
           (force-output (usocket:socket-stream proxy-side))
           (sleep 0.2)
           (multiple-value-bind (finished result)
               (%run-bounded
                (lambda ()
                  (handler-case
                      (bitcoin-lisp.networking::%socks5-recv
                       client 2
                       (+ (get-internal-real-time)
                          (* 1 internal-time-units-per-second))
                       :test)
                    (error () :failed-cleanly)))
                :limit 8)
             (is-true finished "the proxy read must terminate, not hang")
             (is (eq :failed-cleanly result)
                 "a stalled proxy reply is reported as an error")))
      (usocket:socket-close client)
      (usocket:socket-close proxy-side)
      (usocket:socket-close listener))))

(test receive-bytes-refuses-a-dribbling-slow-loris
  "A stall timeout alone is renewable: any progress resets it, so a peer that
sends one byte just inside every window holds the serial pump forever at ~1 B/s
— an infinite hang traded for a slow-loris. The whole-message budget
(+MIN-RECEIVE-BYTES-PER-SECOND+) is what makes the hold finite, so this test
fails if only the stall bound is present."
  (let* ((listener (usocket:socket-listen "127.0.0.1" 0
                                          :element-type '(unsigned-byte 8)))
         (port (usocket:get-local-port listener))
         (client (usocket:socket-connect "127.0.0.1" port
                                         :element-type '(unsigned-byte 8)))
         (server (usocket:socket-accept listener :element-type '(unsigned-byte 8)))
         (conn (bitcoin-lisp.networking::make-connection :socket server :connected t))
         (stop nil)
         ;; Ask for more than the rate floor allows within the stall window, so
         ;; the two bounds are distinguishable: 200 KiB at 32 KiB/s = ~6.4s.
         (wanted (* 200 1024))
         (dribbler (bt:make-thread
                    (lambda ()
                      ;; One byte every 0.3s: never a full second of silence,
                      ;; so the stall bound alone would never fire.
                      (loop until stop
                            do (handler-case
                                   (progn
                                     (write-byte 1 (usocket:socket-stream client))
                                     (force-output (usocket:socket-stream client)))
                                 (error () (return)))
                               (sleep 0.3))))))
    (unwind-protect
         (multiple-value-bind (finished result)
             (%run-bounded (lambda ()
                             (bitcoin-lisp.networking::receive-bytes
                              conn wanted :timeout 1))
                           :limit 30)
           (is-true finished "a dribbling peer must not hold the reader open")
           (is (null result) "and delivers no message"))
      (setf stop t)
      (ignore-errors (bt:join-thread dribbler))
      (usocket:socket-close client)
      (usocket:socket-close server)
      (usocket:socket-close listener))))

(test receive-message-never-waits-for-a-trickling-peer
  "The production path, end to end: a peer sends a well-formed 24-byte header
announcing a large payload, delivers a few bytes, and goes silent. This is
exactly what froze a live node for five days.

The reader is now RESUMABLE (Core CNode::vRecvMsg), so the bar is higher than
'gives up within the caller\'s budget': it must not spend the budget at all. It
takes what has arrived, parks it on the connection, and says :INCOMPLETE — the
peer keeps its partial message and the pump moves on. Dropping the peer is then
the pump\'s job, once the budget lapses (connection-receive-expired-p), because a
peer that has gone silent produces nothing readable and would otherwise never be
looked at again.

Trap worth remembering: announcing MORE than +MAX-MESSAGE-PAYLOAD+ makes this
test vacuous — the oversize guard rejects the header before the payload read is
ever reached, and the test passes in 9 ms without exercising the fix at all.
Announce just under the limit."
  (let* ((listener (usocket:socket-listen "127.0.0.1" 0
                                          :element-type '(unsigned-byte 8)))
         (port (usocket:get-local-port listener))
         (attacker (usocket:socket-connect "127.0.0.1" port
                                           :element-type '(unsigned-byte 8)))
         (victim-socket (usocket:socket-accept listener
                                               :element-type '(unsigned-byte 8)))
         (conn (bitcoin-lisp.networking::make-connection :socket victim-socket
                                                        :connected t))
         (peer (bitcoin-lisp.networking:make-peer :connection conn :state :ready))
         (announced (1- bitcoin-lisp:+max-message-payload+))
         (header (bitcoin-lisp.serialization::make-message-header
                  :magic (copy-seq bitcoin-lisp.serialization:*network-magic*)
                  :command "block"
                  :payload-length announced
                  :checksum (make-array 4 :element-type '(unsigned-byte 8)))))
    (unwind-protect
         (progn
           (let ((header-bytes
                   (flexi-streams:with-output-to-sequence (s)
                     (bitcoin-lisp.serialization::write-message-header s header))))
             (write-sequence header-bytes (usocket:socket-stream attacker))
             (write-sequence (make-array 3 :element-type '(unsigned-byte 8))
                             (usocket:socket-stream attacker))
             (force-output (usocket:socket-stream attacker)))
           (sleep 0.3)
           (let ((start (get-internal-real-time)))
             (multiple-value-bind (command detail)
                 (bitcoin-lisp.networking:receive-message peer :timeout 5)
               (let ((elapsed (/ (- (get-internal-real-time) start)
                                 internal-time-units-per-second)))
                 (is (null command) "no message is produced")
                 (is (eq :incomplete detail)
                     "the partial message is kept, not failed")
                 ;; The whole point: it returned without consuming its budget.
                 ;; The old reader sat here for the full stall window.
                 (is (< elapsed 1)
                     "the reader must return at once, not wait out the budget"))))
           (is-true (bitcoin-lisp.networking::connection-connected conn)
                    "an incomplete message is not yet a reason to disconnect")
           (is (= 3 (bitcoin-lisp.networking::connection-recv-filled conn))
               "the bytes that did arrive are retained for the next pass")
           ;; Now the pump\'s half: a peer that has delivered nothing toward
           ;; its message for +receive-stall-timeout-seconds+ is reaped.
           ;; Backdate the last-progress stamp rather than sleeping for minutes.
           (setf (bitcoin-lisp.networking::connection-recv-last-progress conn)
                 (- (get-internal-real-time)
                    (* (1+ bitcoin-lisp.networking::+receive-stall-timeout-seconds+)
                       internal-time-units-per-second)))
           (is-true (bitcoin-lisp.networking::connection-receive-expired-p conn)
                    "an abandoned message eventually expires")
           (bitcoin-lisp.networking::drain-and-reap-peer peer nil nil nil nil)
           (is-false (bitcoin-lisp.networking::connection-connected conn)
                     "and the pump drops the peer")
           (is (eq :disconnected (bitcoin-lisp.networking:peer-state peer))
               "peer state reflects the disconnect, so maintenance replaces it"))
      (usocket:socket-close attacker)
      (usocket:socket-close victim-socket)
      (usocket:socket-close listener))))

(test one-trickling-peer-does-not-stall-another
  "THE regression this refactor exists for. Two peers: one announces a large
payload and delivers almost none of it, the other sends a complete message. A
pass over both must deliver the second peer\'s message — and quickly.

With the old synchronous reader the first peer owned the shared pump for its
whole budget (timeout + size/+MIN-RECEIVE-BYTES-PER-SECOND+, minutes for a large
message) before the second was even looked at. That serial pump is what turned
one silent peer into a node-wide freeze; bounding the wait made the freeze
finite, and this makes it nonexistent."
  (let* ((listener (usocket:socket-listen "127.0.0.1" 0
                                          :element-type '(unsigned-byte 8)))
         (port (usocket:get-local-port listener))
         (slow-sender (usocket:socket-connect "127.0.0.1" port
                                              :element-type '(unsigned-byte 8)))
         (slow-socket (usocket:socket-accept listener
                                             :element-type '(unsigned-byte 8)))
         (fast-sender (usocket:socket-connect "127.0.0.1" port
                                              :element-type '(unsigned-byte 8)))
         (fast-socket (usocket:socket-accept listener
                                             :element-type '(unsigned-byte 8)))
         (slow-conn (bitcoin-lisp.networking::make-connection :socket slow-socket
                                                             :connected t))
         (fast-conn (bitcoin-lisp.networking::make-connection :socket fast-socket
                                                             :connected t))
         (slow-peer (bitcoin-lisp.networking:make-peer :connection slow-conn
                                                      :state :ready))
         (fast-peer (bitcoin-lisp.networking:make-peer :connection fast-conn
                                                      :state :ready)))
    (unwind-protect
         (progn
           ;; Slow peer: header for a big payload, then 3 bytes and silence.
           (let* ((header (bitcoin-lisp.serialization::make-message-header
                           :magic (copy-seq bitcoin-lisp.serialization:*network-magic*)
                           :command "block"
                           :payload-length (1- bitcoin-lisp:+max-message-payload+)
                           :checksum (make-array 4 :element-type '(unsigned-byte 8))))
                  (header-bytes (flexi-streams:with-output-to-sequence (s)
                                  (bitcoin-lisp.serialization::write-message-header
                                   s header))))
             (write-sequence header-bytes (usocket:socket-stream slow-sender))
             (write-sequence (make-array 3 :element-type '(unsigned-byte 8))
                             (usocket:socket-stream slow-sender))
             (force-output (usocket:socket-stream slow-sender)))
           ;; Fast peer: one complete, well-formed message.
           (write-sequence (bitcoin-lisp.serialization:make-ping-message 12345)
                           (usocket:socket-stream fast-sender))
           (force-output (usocket:socket-stream fast-sender))
           (sleep 0.3)
           (let ((start (get-internal-real-time)))
             ;; One pass over both peers, slow one first — the worst order.
             (multiple-value-bind (slow-command slow-detail)
                 (bitcoin-lisp.networking:receive-message slow-peer :timeout 30)
               (is (null slow-command))
               (is (eq :incomplete slow-detail)))
             (multiple-value-bind (fast-command payload)
                 (bitcoin-lisp.networking:receive-message fast-peer :timeout 30)
               (declare (ignore payload))
               (is (equal "ping" fast-command)
                   "the second peer is served despite the first being mid-message"))
             (is (< (/ (- (get-internal-real-time) start)
                       internal-time-units-per-second)
                    1)
                 "and the pass costs no waiting at all")))
      (usocket:socket-close slow-sender)
      (usocket:socket-close slow-socket)
      (usocket:socket-close fast-sender)
      (usocket:socket-close fast-socket)
      (usocket:socket-close listener))))

(test a-slow-pump-cycle-does-not-reap-peers-mid-message
  "The reap budget must measure the PEER\'s silence, never our own latency.

An earlier draft of the resumable reader anchored a per-message deadline at the
first byte and checked it BEFORE draining. During IBD one pump cycle is minutes
of block validation across peers, so every peer that happened to be mid-message
— a 24-byte header straddling two TCP segments is routine, not adversarial —
came back expired and was disconnected as \"stalled\", while its remaining bytes
sat unread in our own receive buffer. Two properties keep that from returning:
the budget runs from the last byte that ARRIVED, and the pump drains before it
consults expiry."
  (let* ((listener (usocket:socket-listen "127.0.0.1" 0
                                          :element-type '(unsigned-byte 8)))
         (port (usocket:get-local-port listener))
         (sender (usocket:socket-connect "127.0.0.1" port
                                         :element-type '(unsigned-byte 8)))
         (victim-socket (usocket:socket-accept listener
                                               :element-type '(unsigned-byte 8)))
         (conn (bitcoin-lisp.networking::make-connection :socket victim-socket
                                                        :connected t))
         (peer (bitcoin-lisp.networking:make-peer :connection conn :state :ready))
         (payload (make-array 100 :element-type '(unsigned-byte 8)
                                  :initial-element 7))
         (header (bitcoin-lisp.serialization::make-message-header
                  :magic (copy-seq bitcoin-lisp.serialization:*network-magic*)
                  :command "ping"
                  :payload-length (length payload)
                  :checksum (subseq (bitcoin-lisp.serialization:compute-checksum
                                     payload)
                                    0 4))))
    (unwind-protect
         (progn
           ;; Peer sends its header and, a moment later, the payload — it is
           ;; never silent for long.
           (let ((header-bytes
                   (flexi-streams:with-output-to-sequence (s)
                     (bitcoin-lisp.serialization::write-message-header s header))))
             (write-sequence header-bytes (usocket:socket-stream sender))
             (force-output (usocket:socket-stream sender)))
           (sleep 0.2)
           (multiple-value-bind (command detail)
               (bitcoin-lisp.networking:receive-message peer :timeout 5)
             (is (null command))
             (is (eq :incomplete detail)))
           ;; The payload arrives while we are busy elsewhere.
           (write-sequence payload (usocket:socket-stream sender))
           (force-output (usocket:socket-stream sender))
           ;; Simulate a long pump cycle: far longer than the pump\'s own
           ;; :timeout 5, which the old per-message deadline was built from.
           (sleep 1.2)
           (is-false (bitcoin-lisp.networking::connection-receive-expired-p conn)
                     "a peer whose bytes are already here is not stalled")
           ;; And the drain — not a disconnect — is what happens next.
           (bitcoin-lisp.networking::drain-and-reap-peer peer nil nil nil nil)
           (is-true (bitcoin-lisp.networking::connection-connected conn)
                    "a busy pump must not cost a healthy peer its connection"))
      (usocket:socket-close sender)
      (usocket:socket-close victim-socket)
      (usocket:socket-close listener))))

(test receive-message-keeps-its-framing-across-passes
  "A message is TWO reads, so framing is a per-MESSAGE property the byte reader
cannot see. With a resumable reader the header may be parsed one pass and the
payload completed several passes later, so the parsed header is parked on the
CONNECTION — if it were dropped, the next pass would read payload bytes as a
header and every later pass would eat 24 more bytes of garbage, forever.

The old failure mode this replaces: the reader gave up between header and
payload and left the connection ALIVE and permanently out of frame."
  (let* ((listener (usocket:socket-listen "127.0.0.1" 0
                                          :element-type '(unsigned-byte 8)))
         (port (usocket:get-local-port listener))
         (sender (usocket:socket-connect "127.0.0.1" port
                                         :element-type '(unsigned-byte 8)))
         (victim-socket (usocket:socket-accept listener
                                               :element-type '(unsigned-byte 8)))
         (conn (bitcoin-lisp.networking::make-connection :socket victim-socket
                                                        :connected t))
         (peer (bitcoin-lisp.networking:make-peer :connection conn :state :ready))
         (payload (make-array 100 :element-type '(unsigned-byte 8)
                                  :initial-element 3))
         (header (bitcoin-lisp.serialization::make-message-header
                  :magic (copy-seq bitcoin-lisp.serialization:*network-magic*)
                  :command "ping"
                  :payload-length (length payload)
                  :checksum (subseq (bitcoin-lisp.serialization:compute-checksum
                                     payload)
                                    0 4))))
    (unwind-protect
         (progn
           ;; Pass 1: header only.
           (let ((header-bytes
                   (flexi-streams:with-output-to-sequence (s)
                     (bitcoin-lisp.serialization::write-message-header s header))))
             (write-sequence header-bytes (usocket:socket-stream sender))
             (force-output (usocket:socket-stream sender)))
           (sleep 0.2)
           (multiple-value-bind (command detail)
               (bitcoin-lisp.networking:receive-message peer :timeout 30)
             (is (null command))
             (is (eq :incomplete detail)))
           (is-true (bitcoin-lisp.networking::connection-recv-framing conn)
                    "the parsed header survives the gap")
           (is-true (bitcoin-lisp.networking::connection-connected conn)
                    "and the peer is not dropped for being mid-message")
           ;; Pass 2: the payload arrives, and the message completes normally.
           (write-sequence payload (usocket:socket-stream sender))
           (force-output (usocket:socket-stream sender))
           (sleep 0.2)
           (multiple-value-bind (command received)
               (bitcoin-lisp.networking:receive-message peer :timeout 30)
             (is (equal "ping" command)
                 "the message completes from the parked framing state")
             (is (equalp payload received)))
           (is-false (bitcoin-lisp.networking::connection-recv-framing conn)
                     "and the framing state is consumed with it"))
      (usocket:socket-close sender)
      (usocket:socket-close victim-socket)
      (usocket:socket-close listener))))

(test receive-message-keeps-a-peer-after-a-bad-checksum
  "Core's explicit choice: \"Message deserialization failed. Drop the message but
don't disconnect the peer.\" (net.cpp:678-683, reached for a wrong checksum at
net.cpp:819-825). A full message was consumed, so unlike every other failure in
receive-message the framing is intact and there is nothing to resynchronize.
Disconnecting here would also turn any bug in our own payload handling into
node-wide peer churn. Bad magic is the opposite case and is covered below."
  (let* ((listener (usocket:socket-listen "127.0.0.1" 0
                                          :element-type '(unsigned-byte 8)))
         (port (usocket:get-local-port listener))
         (sender (usocket:socket-connect "127.0.0.1" port
                                         :element-type '(unsigned-byte 8)))
         (victim-socket (usocket:socket-accept listener
                                               :element-type '(unsigned-byte 8)))
         (conn (bitcoin-lisp.networking::make-connection :socket victim-socket
                                                        :connected t))
         (peer (bitcoin-lisp.networking:make-peer :connection conn :state :ready))
         (payload (make-array 8 :element-type '(unsigned-byte 8)
                                :initial-element 1))
         (header (bitcoin-lisp.serialization::make-message-header
                  :magic (copy-seq bitcoin-lisp.serialization:*network-magic*)
                  :command "ping"
                  :payload-length (length payload)
                  ;; deliberately wrong
                  :checksum (make-array 4 :element-type '(unsigned-byte 8)
                                          :initial-element 99))))
    (unwind-protect
         (progn
           (let ((header-bytes
                   (flexi-streams:with-output-to-sequence (s)
                     (bitcoin-lisp.serialization::write-message-header s header))))
             (write-sequence header-bytes (usocket:socket-stream sender))
             (write-sequence payload (usocket:socket-stream sender))
             (force-output (usocket:socket-stream sender)))
           (sleep 0.2)
           (is (null (bitcoin-lisp.networking:receive-message peer :timeout 1))
               "the corrupt message is dropped")
           (is-true (bitcoin-lisp.networking::connection-connected conn)
                    "but the peer survives, as in Core")
           (is (eq :ready (bitcoin-lisp.networking:peer-state peer))))
      (usocket:socket-close sender)
      (usocket:socket-close victim-socket)
      (usocket:socket-close listener))))

(test receive-message-drops-a-peer-on-bad-magic
  "Bad magic means 24 bytes were consumed at an unknown offset, so the stream
cannot be trusted to sit on a message boundary. Returning NIL without
disconnecting left the peer :READY and eating 24 bytes of garbage per pass
forever."
  (let* ((listener (usocket:socket-listen "127.0.0.1" 0
                                          :element-type '(unsigned-byte 8)))
         (port (usocket:get-local-port listener))
         (sender (usocket:socket-connect "127.0.0.1" port
                                         :element-type '(unsigned-byte 8)))
         (victim-socket (usocket:socket-accept listener
                                               :element-type '(unsigned-byte 8)))
         (conn (bitcoin-lisp.networking::make-connection :socket victim-socket
                                                        :connected t))
         (peer (bitcoin-lisp.networking:make-peer :connection conn :state :ready)))
    (unwind-protect
         (progn
           (write-sequence (make-array 24 :element-type '(unsigned-byte 8)
                                          :initial-element 255)
                           (usocket:socket-stream sender))
           (force-output (usocket:socket-stream sender))
           (sleep 0.2)
           (is (null (bitcoin-lisp.networking:receive-message peer :timeout 1)))
           (is-false (bitcoin-lisp.networking::connection-connected conn)
                     "a peer talking a foreign protocol is dropped"))
      (usocket:socket-close sender)
      (usocket:socket-close victim-socket)
      (usocket:socket-close listener))))

(test receive-does-not-reserve-megabytes-for-bytes-not-sent
  "A message announces its own size, and that is the peer's word, not a fact.
Allocating it up front let a peer turn a few bytes into megabytes of our memory,
held for as long as the stall budget allows — 3 bytes of BIP324 length
descriptor reserving 4 MB for 5 minutes, times every inbound slot. The blocking
reader's byte-rate floor used to cut that short in seconds; the resumable reader
has no rate floor on purpose (charging peers for our own latency is what reaped
healthy peers), so the bound must be on the ALLOCATION.

Core's rule and Core's number: MAX_RESERVE_AHEAD = 256 KiB above what the peer
has actually sent (net.cpp:1323-1324)."
  (let* ((listener (usocket:socket-listen "127.0.0.1" 0
                                          :element-type '(unsigned-byte 8)))
         (port (usocket:get-local-port listener))
         (sender (usocket:socket-connect "127.0.0.1" port
                                         :element-type '(unsigned-byte 8)))
         (victim-socket (usocket:socket-accept listener
                                               :element-type '(unsigned-byte 8)))
         (conn (bitcoin-lisp.networking::make-connection :socket victim-socket
                                                        :connected t))
         (announced (1- bitcoin-lisp:+max-message-payload+)))
    (unwind-protect
         (progn
           ;; One byte delivered against a ~4 MB announcement.
           (write-byte 42 (usocket:socket-stream sender))
           (force-output (usocket:socket-stream sender))
           (sleep 0.2)
           (is (eq :incomplete
                   (bitcoin-lisp.networking::receive-bytes-resumable conn announced))
               "the read is in progress, not complete")
           (is (= 1 (bitcoin-lisp.networking::connection-recv-filled conn)))
           (is (<= (length (bitcoin-lisp.networking::connection-recv-buffer conn))
                   bitcoin-lisp.networking::+recv-reserve-ahead+)
               "one delivered byte must not reserve the whole announced size")
           (is (< (length (bitcoin-lisp.networking::connection-recv-buffer conn))
                  announced)
               "control: the announcement really is far larger than the reserve")
           ;; An honest peer that keeps delivering gets the room it earns.
           (write-sequence (make-array (* 300 1024) :element-type '(unsigned-byte 8))
                           (usocket:socket-stream sender))
           (force-output (usocket:socket-stream sender))
           (sleep 0.4)
           (bitcoin-lisp.networking::receive-bytes-resumable conn announced)
           (bitcoin-lisp.networking::receive-bytes-resumable conn announced)
           (is (> (bitcoin-lisp.networking::connection-recv-filled conn)
                  bitcoin-lisp.networking::+recv-reserve-ahead+)
               "the buffer grows as the peer earns it")
           (is-true (bitcoin-lisp.networking::connection-connected conn)
                    "and a progressing peer is not dropped"))
      (usocket:socket-close sender)
      (usocket:socket-close victim-socket)
      (usocket:socket-close listener))))

;;;; ------------------------------------------------------------------
;;;; Non-I/O receive failures must be diagnosable
;;;;
;;;; receive-bytes-resumable catches errors with a deliberately wide net,
;;;; because a dead socket surfaces as several condition types. A wide net also
;;;; swallows OUR bugs as "the peer went away": mainnet spent 2026-08-17/18
;;;; losing every connection to a TYPE-ERROR reported only as a one-line
;;;; message, with no way to tell where it came from. These cover the backtrace
;;;; capture that answers that question.

(test recv-backtrace-only-fires-for-our-own-bugs
  "The capture must discriminate exactly as the log line does. Peers hanging up
is the normal case and vastly the common one; capturing a backtrace for every
closed socket would bury the log under noise and teach the reader to ignore it."
  (let ((bitcoin-lisp.networking::*recv-backtrace-remaining* nil)
        (bitcoin-lisp.networking::*recv-backtrace-budget* 10))
    (is (null (bitcoin-lisp.networking:capture-recv-backtrace
               (make-condition 'end-of-file :stream *standard-output*)))
        "end-of-file is a peer going away, not a bug")
    (is-true (stringp (bitcoin-lisp.networking:capture-recv-backtrace
                       (make-condition 'type-error :datum 3122
                                                   :expected-type '(unsigned-byte 10))))
             "a TYPE-ERROR is ours and must be captured")))

(test recv-backtrace-is-budgeted
  "Bounded on purpose: the failure repeats once per failing peer — ~15k times in
200k log lines during the mainnet incident — so an unbounded backtrace would
bury the log it exists to explain. The budget is per process, not per peer."
  (let ((bitcoin-lisp.networking::*recv-backtrace-remaining* nil)
        (bitcoin-lisp.networking::*recv-backtrace-budget* 2))
    (flet ((cap () (bitcoin-lisp.networking:capture-recv-backtrace
                    (make-condition 'type-error :datum 1 :expected-type 'string))))
      (is-true (stringp (cap)) "1st capture allowed")
      (is-true (stringp (cap)) "2nd capture allowed")
      (is (null (cap)) "3rd must be refused — the budget is spent")
      (is (null (cap)) "and it stays spent"))))

(defun %recv-backtrace-canary ()
  "Signals, purely so the test has a frame name it can look for. Top-level and
NOT a LABELS: SBCL inlines a local function into its caller, so a local canary
never appears in the trace and the test fails for a reason that has nothing to
do with the capture."
  (error "canary"))

(test recv-backtrace-captures-the-signalling-frames
  "The point of capturing from a HANDLER-BIND: the trace must name the function
that signalled, not just the recovery path. Asserted on a distinctly-named
frame so this cannot pass on an empty or truncated string."
  (let ((bitcoin-lisp.networking::*recv-backtrace-remaining* nil)
        (bitcoin-lisp.networking::*recv-backtrace-budget* 5)
        (trace nil))
    (ignore-errors
     (handler-bind ((error (lambda (c)
                             (setf trace (bitcoin-lisp.networking:capture-recv-backtrace c)))))
       (%recv-backtrace-canary)))
    (is-true (stringp trace) "a backtrace must have been produced")
    (is-true (search "RECV-BACKTRACE-CANARY" trace)
             "the signalling frame must appear in the captured trace")))

(test socket-readiness-survives-a-descriptor-above-the-select-ceiling
  "The mainnet outage of 2026-08-17/18, in miniature.

usocket:wait-for-input goes through select(2), whose fd_set is a fixed
1024-bit bitmap, so SBCL type-checks the descriptor as (unsigned-byte 10) and a
socket on fd >= 1024 SIGNALS rather than being waited on. Mainnet held ~3100
open LevelDB tables, every new socket landed above the ceiling, and the node
lost every peer to `The value <fd+1> is not of type (UNSIGNED-BYTE 10)'.

This holds 1200 descriptors open so the socket under test is allocated above
the ceiling, then checks both halves: that the old path really does fail there
(otherwise the test proves nothing) and that ours reports readiness correctly
in both directions — NIL before data, T after. Asserting only the T would pass
for a function that always returns T."
  (let ((hogs (ignore-errors
               (loop repeat 1200 collect (open "/dev/null" :direction :input)))))
    (unwind-protect
         (let* ((listener (usocket:socket-listen "127.0.0.1" 0 :reuse-address t
                                                 :element-type '(unsigned-byte 8)))
                (port (usocket:get-local-port listener))
                (client (usocket:socket-connect "127.0.0.1" port
                                                :element-type '(unsigned-byte 8)))
                (server (usocket:socket-accept listener
                                               :element-type '(unsigned-byte 8))))
           (unwind-protect
                (let ((fd (sb-bsd-sockets:socket-file-descriptor (usocket:socket server))))
                  ;; If the environment would not give us a high descriptor
                  ;; (a tight ulimit, say) the reproduction is not set up and
                  ;; asserting anything about it would be theatre.
                  (when (> fd 1023)
                    (is (eq :failed
                            (handler-case
                                (progn (usocket:wait-for-input server :timeout 0
                                                                      :ready-only t)
                                       :ok)
                              (type-error () :failed)))
                        "control: the select-based path must still fail above the ceiling, ~
                         or this test is no longer reproducing the bug")
                    (is-false (bitcoin-lisp.networking:socket-input-ready-p server :timeout 0)
                              "no data yet: must report NOT ready")
                    (write-sequence (coerce '(104 105) '(vector (unsigned-byte 8)))
                                    (usocket:socket-stream client))
                    (force-output (usocket:socket-stream client))
                    (sleep 0.5)
                    (is-true (bitcoin-lisp.networking:socket-input-ready-p server :timeout 0)
                             "data arrived: must report ready, above the ceiling")))
             (usocket:socket-close client)
             (usocket:socket-close server)
             (usocket:socket-close listener)))
      (mapc #'close hogs))))
