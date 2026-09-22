(in-package #:bitcoin-lisp.tests)

;;; Serving peer requests: getheaders / getblocks / getaddr.
;;;
;;; The responder side mirrors Bitcoin Core's net_processing handlers — find the
;;; fork point of the peer's locator in our active chain, then walk forward
;;; answering with headers (getheaders) or an inv of block hashes (getblocks),
;;; and answer getaddr from the address book (inbound-only, once per connection).
;;; These tests build a synthetic active chain and exercise the pure response
;;; builders plus the getaddr gating, with no sockets involved.

(in-suite :serve-requests-tests)

;;;; Helpers

(defun %zero32 ()
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))

(defun %uniq-hash (id)
  "A distinct 32-byte hash from an integer ID (for synthetic chains/locators)."
  (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref h 0) (logand id #xFF))
    (setf (aref h 1) (logand (ash id -8) #xFF))
    (setf (aref h 2) (logand (ash id -16) #xFF))
    h))

(defun %make-served-chain (n)
  "Build a fresh chain-state with a genesis block plus N further blocks, each
carrying a real header chained by prev-block hash and set as the active tip.
Returns (VALUES chain-state entries) with ENTRIES ascending (genesis first)."
  (let* ((entries '())
         (prev-hash (%zero32))
         (prev-entry nil)
         (cs nil))
    (dotimes (h (1+ n))
      (let* ((merkle (%uniq-hash (+ 5000 h)))
             (header (bl.ser:make-block-header
                      :version 1 :prev-block prev-hash :merkle-root merkle
                      :timestamp (+ 1700000000 h) :bits #x1d00ffff :nonce h))
             (hash (bl.ser:block-header-hash header))
             (entry (bl.store:make-block-index-entry
                     :hash hash :height h :header header
                     :prev-entry prev-entry :chain-work (1+ h) :status :valid)))
        (when (zerop h)
          (setf cs (bl.store:make-chain-state
                    :genesis-hash hash :best-block-hash hash :best-height 0)))
        (bl.store:add-block-index-entry cs entry)
        (bl.store:update-chain-tip cs hash h)
        (push entry entries)
        (setf prev-hash hash prev-entry entry)))
    (values cs (nreverse entries))))

(defun %entry-hash (entries height)
  (bl.store:block-index-entry-hash (nth height entries)))

(defun %getheaders-payload (locator-hashes &optional stop-hash)
  "Build the on-wire payload (header stripped) of a getheaders message."
  (subseq (bl.ser:make-getheaders-message locator-hashes stop-hash)
          24))

(defun %getblocks-payload (locator-hashes &optional stop-hash)
  (subseq (bl.ser:make-getblocks-message locator-hashes stop-hash)
          24))

(defun %message-payload (msg)
  "Return the payload bytes of a serialized P2P message (strip 24-byte header)."
  (bl.bytes:with-byte-reader (s msg)
    (let ((hdr (bl.ser:read-message-header s)))
      (subseq msg 24 (+ 24 (bl.ser:message-header-payload-length hdr))))))

(defun %message-command (msg)
  (bl.bytes:with-byte-reader (s msg)
    (bl.ser:message-header-command
     (bl.ser:read-message-header s))))

;;;; find-fork-in-active-chain

(test fork-returns-tip-when-locator-has-tip
  (multiple-value-bind (cs entries) (%make-served-chain 5)
    (let ((fork (bl.store:find-fork-in-active-chain
                 cs (list (%entry-hash entries 5)))))
      (is (= 5 (bl.store:block-index-entry-height fork))))))

(test fork-returns-highest-on-chain-hash
  (multiple-value-bind (cs entries) (%make-served-chain 5)
    ;; Locator most-recent-first: an unknown hash, then block 3, then block 1.
    (let ((fork (bl.store:find-fork-in-active-chain
                 cs (list (%uniq-hash 999999)
                          (%entry-hash entries 3)
                          (%entry-hash entries 1)))))
      (is (= 3 (bl.store:block-index-entry-height fork))))))

(test fork-falls-back-to-genesis
  (multiple-value-bind (cs entries) (%make-served-chain 5)
    (declare (ignore entries))
    (let ((fork (bl.store:find-fork-in-active-chain
                 cs (list (%uniq-hash 111) (%uniq-hash 222)))))
      (is (= 0 (bl.store:block-index-entry-height fork))))))

;;;; active-chain-entries-from

(test active-chain-entries-ascending-and-bounded
  (multiple-value-bind (cs entries) (%make-served-chain 5)
    (declare (ignore entries))
    (let ((got (bl.store:active-chain-entries-from cs 1 100)))
      (is (= 5 (length got)))
      (is (equal '(1 2 3 4 5)
                 (mapcar #'bl.store:block-index-entry-height got))))
    ;; Limit caps the count, still from FROM-HEIGHT ascending.
    (let ((got (bl.store:active-chain-entries-from cs 2 2)))
      (is (equal '(2 3)
                 (mapcar #'bl.store:block-index-entry-height got))))
    ;; Above the tip => empty.
    (is (null (bl.store:active-chain-entries-from cs 6 100)))))

;;;; getheaders-response-message

(test getheaders-from-genesis-returns-rest-of-chain
  (multiple-value-bind (cs entries) (%make-served-chain 5)
    (let* ((payload (%getheaders-payload (list (%entry-hash entries 0))))
           (msg (bl.net::getheaders-response-message payload cs))
           (headers (bl.ser:parse-headers-payload
                     (%message-payload msg))))
      (is (string= "headers" (%message-command msg)))
      (is (= 5 (length headers)))
      ;; Headers are blocks 1..5 in order, matching our index hashes.
      (loop for header in headers
            for height from 1
            do (is (equalp (%entry-hash entries height)
                           (bl.ser:block-header-hash header)))))))

(test getheaders-at-tip-returns-empty
  (multiple-value-bind (cs entries) (%make-served-chain 5)
    (let* ((payload (%getheaders-payload (list (%entry-hash entries 5))))
           (msg (bl.net::getheaders-response-message payload cs))
           (headers (bl.ser:parse-headers-payload
                     (%message-payload msg))))
      (is (null headers)))))

(test getheaders-stop-hash-is-inclusive
  (multiple-value-bind (cs entries) (%make-served-chain 5)
    (let* ((payload (%getheaders-payload (list (%entry-hash entries 0))
                                         (%entry-hash entries 2)))
           (msg (bl.net::getheaders-response-message payload cs))
           (headers (bl.ser:parse-headers-payload
                     (%message-payload msg))))
      ;; Blocks 1 and 2 — stop hash (block 2) is included.
      (is (= 2 (length headers)))
      (is (equalp (%entry-hash entries 2)
                  (bl.ser:block-header-hash
                   (car (last headers))))))))

(test a-getheaders-at-our-tip-makes-the-next-block-a-headers-announcement
  "Core's GETHEADERS handler RESETS the peer's pindexBestHeaderSent to the last
header it sent, or to our tip when the answer is empty
(net_processing.cpp:4455-4468), and PeerHasHeader reads it (:1352-1359). So a
sendheaders peer that asked for headers at our tip already has the next
block's parent, and that block is announced as a header, not an inv
(p2p_sendheaders.py:300-309). Ours never recorded what a getheaders sent."
  (multiple-value-bind (cs entries) (%make-served-chain 6)
    (let ((bl:*network* :regtest)
          (peer (bl.net:make-peer :address "test" :state :ready))
          (tip5 (%entry-hash entries 5))
          (tip6 (%entry-hash entries 6)))
      (bl.net:init-peer-rate-limiters peer)
      (setf (bl.net:peer-prefers-headers peer) t)
      ;; Our tip is block 5 when the peer asks.
      (bl.store:update-chain-tip cs tip5 5)
      (with-ibd-context
        (captured-sends
         (lambda ()
           (deliver-ibd-message peer "getheaders" (%getheaders-payload (list tip5))
                                (bl.ctx:make-node-context :chain-state cs)))))
      (is (equalp tip5 (bl.net:peer-best-header-sent-hash peer))
          "an empty answer records our tip")
      ;; Block 6 connects and is announced.
      (bl.store:update-chain-tip cs tip6 6)
      (bl.net:queue-block-announcement peer tip6)
      (let ((sent (captured-sends
                   (lambda () (bl.net:flush-block-announcements (list peer) cs)))))
        (is (equal '("headers") (mapcar #'%message-command sent)))
        (is (equalp (list tip6)
                    (mapcar #'bl.ser:block-header-hash
                            (bl.ser:parse-headers-payload
                             (%message-payload (first sent))))))))))

(test a-reorg-announces-every-new-block-oldest-first
  "Core's UpdatedBlockTip queues every block from the new tip back to the fork
point with the previous tip, oldest first, at most MAX_BLOCKS_TO_ANNOUNCE of
them (net_processing.cpp:2169-2188). A reorg is one tip update, so we queued
its tip alone; the tip's parent then looked unknown to a sendheaders peer and
the announcement fell back to an inv (p2p_sendheaders.py:371-375 mines a
7-block reorg and expects all 7 headers)."
  (multiple-value-bind (cs entries) (%make-served-chain 3)   ; genesis, A1..A3
    (let* ((genesis (first entries))
           (branch (loop with prev = genesis
                         for h from 1 to 10
                         collect (let* ((header (bl.ser:make-block-header
                                                 :version 1
                                                 :prev-block (bl.store:block-index-entry-hash prev)
                                                 :merkle-root (%uniq-hash (+ 9000 h))
                                                 :timestamp (+ 1700001000 h)
                                                 :bits #x1d00ffff :nonce h))
                                        (entry (bl.store:make-block-index-entry
                                                :hash (bl.ser:block-header-hash header)
                                                :height h :header header :prev-entry prev
                                                :chain-work (+ 100 h) :status :valid)))
                                   (bl.store:add-block-index-entry cs entry)
                                   (setf prev entry))))
           (hash-of #'bl.store:block-index-entry-hash))
      ;; A 7-block reorg from A3: B1..B7, oldest first.
      (is (equalp (mapcar hash-of (subseq branch 0 7))
                  (bl:blocks-to-announce cs (nth 6 branch)
                                         (%entry-hash entries 3))))
      ;; A plain extension: the new block alone.
      (is (equalp (list (%entry-hash entries 3))
                  (bl:blocks-to-announce cs (nth 3 entries) (%entry-hash entries 2))))
      ;; A 10-block reorg is cut at MAX_BLOCKS_TO_ANNOUNCE = 8, keeping the top.
      (is (equalp (mapcar hash-of (subseq branch 2 10))
                  (bl:blocks-to-announce cs (nth 9 branch) (%entry-hash entries 3))))
      ;; No previous tip known: the tip alone.
      (is (equalp (list (funcall hash-of (nth 6 branch)))
                  (bl:blocks-to-announce cs (nth 6 branch) nil))))))

(test headers-for-an-equal-work-sibling-of-the-tip-fetch-its-block
  "Core's HeadersDirectFetchBlocks (net_processing.cpp:2844-2902) asks the
announcing peer at once for the blocks between the active chain and its last
header when that header has AT LEAST our tip's work (`<='), our tip is recent
(CanDirectFetch) and the walk reaches the active chain.
feature_chain_tiebreaks.py:76 announces B1, an equal-work sibling of our tip
whose header we already hold, and waits for the getdata; our download walk
only looks above the tip, so nobody ever asked for it.

Controls: a sibling with LESS work, and the same sibling while our tip is
stale, are not fetched."
  (multiple-value-bind (cs entries) (%make-served-chain 2)   ; tip at height 2
    (flet ((sibling (work nonce)
             (let* ((parent (nth 1 entries))
                    (header (bl.ser:make-block-header
                             :version 1 :prev-block (bl.store:block-index-entry-hash parent)
                             :merkle-root (%uniq-hash (+ 7000 nonce))
                             :timestamp 1700000002 :bits #x1d00ffff :nonce nonce))
                    (entry (bl.store:make-block-index-entry
                            :hash (bl.ser:block-header-hash header) :height 2
                            :header header :prev-entry parent
                            :chain-work work :status :header-valid)))
               (bl.store:add-block-index-entry cs entry)
               entry))
           (getdata-hashes (sent)
             (loop for msg in sent
                   when (string= "getdata" (%message-command msg))
                     append (mapcar #'bl.ser:inv-vector-hash
                                    (bl.ser:parse-inv-payload (%message-payload msg))))))
      (let ((peer (bl.net:make-peer :address "test" :state :ready
                                    :services bl.ser:+node-witness+))
            (equal-work (sibling 3 1))       ; the tip's chain-work is 3
            (less-work (sibling 2 2)))
        (with-ibd-context
          (let ((bl.ser:*mock-time* 1700000100))
            (is (null (getdata-hashes
                       (captured-sends
                        (lambda () (bl.net:headers-direct-fetch peer cs less-work)))))
                "less work than the tip: not fetched")
            (is (equalp (list (bl.store:block-index-entry-hash equal-work))
                        (getdata-hashes
                         (captured-sends
                          (lambda () (bl.net:headers-direct-fetch peer cs equal-work))))))
            ;; The node keeps ONE context for its life (every pump pass works
            ;; in it and a sync pass carries its in-flight table over;
            ;; the-receive-pump-keeps-the-nodes-ibd-context), as Core keeps one
            ;; mapBlocksInFlight: the request is still there for the next
            ;; headers message (p2p_sendheaders.py:497-504).
            (is (null (getdata-hashes
                       (captured-sends
                        (lambda () (bl.net:headers-direct-fetch peer cs equal-work)))))
                "a block already in flight is not asked for twice")))
        ;; A new peer in a new context; a stale tip then still refuses.
        (setf (bl.net:peer-state peer) :disconnected)
        (let ((other (bl.net:make-peer :address "test2" :state :ready
                                       :services bl.ser:+node-witness+)))
          (with-ibd-context
            (let ((bl.ser:*mock-time* (+ 1700000100 (* 60 60 24))))
              (is (null (getdata-hashes
                         (captured-sends
                          (lambda () (bl.net:headers-direct-fetch other cs equal-work)))))
                  "our tip is stale: no direct fetch"))
            ;; Positive control for the line above: the same call with a
            ;; recent tip does fetch it from the new peer.
            (let ((bl.ser:*mock-time* 1700000100))
              (is (equalp (list (bl.store:block-index-entry-hash equal-work))
                          (getdata-hashes
                           (captured-sends
                            (lambda () (bl.net:headers-direct-fetch other cs equal-work)))))))
            (setf (bl.net:peer-state other) :disconnected)))))))

(test getheaders-null-locator-returns-stop-header
  (multiple-value-bind (cs entries) (%make-served-chain 5)
    (let* ((payload (%getheaders-payload '() (%entry-hash entries 3)))
           (msg (bl.net::getheaders-response-message payload cs))
           (headers (bl.ser:parse-headers-payload
                     (%message-payload msg))))
      (is (= 1 (length headers)))
      (is (equalp (%entry-hash entries 3)
                  (bl.ser:block-header-hash (first headers)))))))

(defun %fork-off-the-tip (cs entries)
  "Reorg CS one block back: the old tip entry stays in the index with the
:VALID it earned, and a sibling of equal height becomes the active tip. Returns
the now-stale entry.

Built the way a real reorg leaves the index -- Core's DisconnectTip does not
lower nStatus -- so the serving rules below are asked the question they are
actually asked in the field."
  (let* ((stale (car (last entries)))
         (parent (nth (- (length entries) 2) entries))
         (header (bl.ser:make-block-header
                  :version 1
                  :prev-block (bl.store:block-index-entry-hash parent)
                  :merkle-root (%uniq-hash 9999)
                  :timestamp (bl.ser:block-header-timestamp
                              (bl.store:block-index-entry-header stale))
                  :bits #x1d00ffff :nonce #xbeef))
         (hash (bl.ser:block-header-hash header))
         (sibling (bl.store:make-block-index-entry
                   :hash hash
                   :height (bl.store:block-index-entry-height stale)
                   :header header :prev-entry parent
                   :chain-work (1+ (bl.store:block-index-entry-chain-work stale))
                   :status :valid)))
    (bl.store:add-block-index-entry cs sibling)
    (bl.store:update-chain-tip cs hash (bl.store:block-index-entry-height sibling))
    stale))

(test getheaders-null-locator-serves-a-recent-stale-header
  "Core's GETHEADERS null-locator branch gates the stop block on
BlockRequestAllowed (net_processing.cpp:4429-4436), the same rule the getdata
path uses -- so a block RECENTLY reorged off the chain is still served, and an
old one is not. Ours asked only whether the block was on the active chain, so
p2p_fingerprint.py:97 waited out its three seconds for the header of a block
the node had just reorged away from.

The refusal sends NOTHING, as Core's `return' does -- not an empty headers
message."
  (multiple-value-bind (cs entries) (%make-served-chain 5)
    (let* ((stale (%fork-off-the-tip cs entries))
           (stale-hash (bl.store:block-index-entry-hash stale)))
      (is-false (bl.store:entry-on-active-chain-p cs stale)
                "the block really is off the active chain now")
      (let* ((msg (bl.net::getheaders-response-message
                   (%getheaders-payload '() stale-hash) cs)))
        (is-true msg "a recent stale header is still served")
        (when msg
          (let ((headers (bl.ser:parse-headers-payload (%message-payload msg))))
            (is (= 1 (length headers)))
            (is (equalp stale-hash
                        (bl.ser:block-header-hash (first headers)))))))
      ;; Control: a block we do not know at all gets no message whatsoever.
      (is-false (bl.net::getheaders-response-message
                 (%getheaders-payload '() (%uniq-hash 4242)) cs)
                "and an unknown stop hash is answered with nothing at all"))))

(test stale-block-stays-servable-after-a-reorg
  "Core's BlockRequestAllowed asks IsValid(BLOCK_VALID_SCRIPTS) for a block off
the active chain (net_processing.cpp:1953-1960), and that validity is MONOTONE
-- DisconnectTip never lowers nStatus. Ours downgraded a disconnected block to
:header-valid inside perform-reorg, so the gate refused a block this node had
itself validated and p2p_fingerprint.py:93 timed out waiting for it.

The age half of the rule is the control: the same entry, aged past
STALE_RELAY_AGE_LIMIT relative to the best header, is refused."
  (multiple-value-bind (cs entries) (%make-served-chain 5)
    (let* ((stale (%fork-off-the-tip cs entries))
           (best (bl.store:best-header-entry cs)))
      (is (eq :valid (bl.store:block-index-entry-status stale))
          "a reorged-off block keeps the validity it earned")
      (is-true (block-request-allowed-p cs stale best)
               "so a recent stale block is servable")
      ;; Control 1: never fully validated => refused.
      (setf (bl.store:block-index-entry-status stale) :header-valid)
      (is-false (block-request-allowed-p cs stale best))
      (setf (bl.store:block-index-entry-status stale) :valid)
      ;; Control 2: valid, but older than a month relative to the best header.
      (setf (bl.ser:block-header-timestamp
             (bl.store:block-index-entry-header stale))
            (- (bl.ser:block-header-timestamp
                (bl.store:block-index-entry-header best))
               (* 31 24 60 60)))
      (is-false (block-request-allowed-p cs stale best)
                "an old stale block is a fingerprint, not a service"))))

;;;; getblocks-response-message

(test getblocks-from-genesis-returns-inv
  (multiple-value-bind (cs entries) (%make-served-chain 5)
    (let* ((payload (%getblocks-payload (list (%entry-hash entries 0))))
           (msg (bl.net::getblocks-response-message payload cs))
           (invs (bl.ser:parse-inv-payload (%message-payload msg))))
      (is (string= "inv" (%message-command msg)))
      (is (= 5 (length invs)))
      (loop for inv in invs
            for height from 1
            do (is (= bl.ser:+inv-type-block+
                      (bl.ser:inv-vector-type inv)))
               (is (equalp (%entry-hash entries height)
                           (bl.ser:inv-vector-hash inv)))))))

(test getblocks-stop-hash-is-exclusive
  (multiple-value-bind (cs entries) (%make-served-chain 5)
    (let* ((payload (%getblocks-payload (list (%entry-hash entries 0))
                                        (%entry-hash entries 2)))
           (msg (bl.net::getblocks-response-message payload cs))
           (invs (bl.ser:parse-inv-payload (%message-payload msg))))
      ;; Only block 1 — the inv stops before the stop hash (block 2).
      (is (= 1 (length invs)))
      (is (equalp (%entry-hash entries 1)
                  (bl.ser:inv-vector-hash (first invs)))))))

(test getblocks-at-tip-returns-nil
  (multiple-value-bind (cs entries) (%make-served-chain 5)
    (let ((payload (%getblocks-payload (list (%entry-hash entries 5)))))
      (is (null (bl.net::getblocks-response-message payload cs))))))

;;;; truncate-entries-at-stop

(test truncate-zero-hash-keeps-all
  (multiple-value-bind (cs entries) (%make-served-chain 3)
    (declare (ignore cs))
    (is (= 4 (length (bl.net::truncate-entries-at-stop
                      entries (%zero32) t))))))

(test truncate-missing-stop-keeps-all
  (multiple-value-bind (cs entries) (%make-served-chain 3)
    (declare (ignore cs))
    (is (= 4 (length (bl.net::truncate-entries-at-stop
                      entries (%uniq-hash 424242) t))))))

;;;; getaddr gating + addr response building

(defun %make-test-peer-address (a b c d port)
  (bl.net:make-peer-address
   :ip (bl.net:ipv4-to-mapped-ipv6 a b c d)
   :port port :services 1 :last-seen 1700000000))

(test getaddr-only-once-and-inbound-only
  "Core answers getaddr only from an inbound peer and only once per
connection, and LOGS both refusals under net (net_processing.cpp:4910-4924):
p2p_addr_relay.py:307 waits for `Ignoring repeated \"getaddr\".'."
  (let ((bl:*node* nil))    ; book resolves to NIL: gating only, no send
    ;; Outbound peer: never marked as answered.
    (let ((outbound (bl.net:make-peer :inbound nil :conn-type :block-relay)))
      (is (search "Ignoring \"getaddr\" from block-relay-only connection."
                  (nth-value 1 (log-text-of
                                "net"
                                (lambda ()
                                  (bl.net::handle-getaddr outbound #() (bl.ctx:make-node-context)))))))
      (is (null (bl.net:peer-getaddr-sent outbound))))
    ;; Inbound peer: answered exactly once (flag latches on first call).
    (let ((inbound (bl.net:make-peer :inbound t)))
      (is (null (bl.net:peer-getaddr-sent inbound)))
      (bl.net::handle-getaddr inbound #() (bl.ctx:make-node-context))
      (is-true (bl.net:peer-getaddr-sent inbound))
      ;; Second call is a no-op; flag stays set, and it says so.
      (is (search "Ignoring repeated \"getaddr\"."
                  (nth-value 1 (log-text-of
                                "net"
                                (lambda ()
                                  (bl.net::handle-getaddr inbound #() (bl.ctx:make-node-context)))))))
      (is-true (bl.net:peer-getaddr-sent inbound)))))

(test build-addrv2-response-round-trips
  (let ((peer (bl.net:make-peer :wants-addrv2 t))
        (addrs (list (%make-test-peer-address 203 0 113 7 18333)
                     (%make-test-peer-address 198 51 100 9 48333))))
    (let* ((msg (bl.net::build-addr-response peer addrs))
           (parsed (bl.ser:parse-addrv2-payload (%message-payload msg))))
      (is (string= "addrv2" (%message-command msg)))
      (is (= 2 (length parsed)))
      ;; Ports survive the round trip.
      (is (equal '(18333 48333)
                 (mapcar (lambda (e) (bl.ser:net-addr-port (first e)))
                         parsed))))))

(test build-addr-v1-response-has-addr-command
  (let ((peer (bl.net:make-peer :wants-addrv2 nil))
        (addrs (list (%make-test-peer-address 203 0 113 7 18333))))
    (is (string= "addr" (%message-command
                         (bl.net::build-addr-response peer addrs))))))

(test notfound-message-roundtrip
  "make-notfound-message builds a \"notfound\" message whose payload parses as
inv vectors (same shape as inv) -- the reply for unserved tx getdata."
  (let* ((inv (bl.ser:make-inv-vector
               :type bl.ser:+inv-type-wtx+
               :hash (%uniq-hash 777)))
         (msg (bl.ser:make-notfound-message (list inv))))
    (is (string= "notfound" (%message-command msg)))
    (let ((parsed (bl.ser:parse-inv-payload (%message-payload msg))))
      (is (= 1 (length parsed)))
      (is (= bl.ser:+inv-type-wtx+
             (bl.ser:inv-vector-type (first parsed))))
      (is (equalp (%uniq-hash 777)
                  (bl.ser:inv-vector-hash (first parsed)))))))

(defun %relay-address (peer-addr source peers &rest args)
  "Core RelayAddress. The one reach into it in this file."
  (apply #'bl.net::relay-address peer-addr source peers args))

(defun %addr-queue (peer)
  "PEER's pending addr gossip (Core Peer::m_addrs_to_send)."
  (bl.net::peer-addrs-to-send peer))

(defun %addr-send-deadline (peer)
  "PEER's next addr-flush deadline (Core Peer::m_next_addr_send). SETF-able so
a test can make a peer due without waiting out an exponential draw."
  (bl.net::peer-next-addr-send peer))

(defun (setf %addr-send-deadline) (ticks peer)
  (setf (bl.net::peer-next-addr-send peer) ticks))

(defun %flush-addrs-now (peers)
  "Drive the shipped addr flush (Core MaybeSendAddr's queue half) with every
peer's Poisson deadline already expired."
  (dolist (peer peers)
    (setf (%addr-send-deadline peer) 0))
  (bl.net:flush-addr-announcements peers))

(defmacro %with-captured-sends ((sends) &body body)
  "Run BODY with SEND-MESSAGE recording instead of writing. SENDS is bound to a
fill-pointer vector collecting (peer . message-bytes) in send order, which is
what tells \"queued for later\" apart from \"already on the wire\"."
  (let ((real (gensym "REAL")))
    `(let ((,sends (make-array 0 :adjustable t :fill-pointer 0))
           (,real (fdefinition 'bl.net:send-message)))
       (unwind-protect
            (progn
              (setf (fdefinition 'bl.net:send-message)
                    (lambda (peer bytes)
                      (vector-push-extend (cons peer bytes) ,sends)
                      t))
              ,@body)
         (setf (fdefinition 'bl.net:send-message) ,real)))))

(test relay-address-fanout-and-dedup
  "relay-address (Core RelayAddress) forwards a fresh address to exactly 2
eligible peers -- skipping the source, block-relay/feeler peers, and peers that
already know it. A target is marked when its outgoing queue is flushed, on the
pass that filters it (Core MaybeSendAddr, net_processing.cpp:5582-5589); the
ANNOUNCER is marked by the ADDR handler, not here (Core AddAddressKnown,
:4093 -- see ADDR-INGEST-COUNTS-AND-MARKS-WHAT-CORE-DOES)."
  (let* ((source (bl.net:make-peer :state :ready :address "9.9.9.9:8333"))
         (full (loop for i below 4
                     collect (bl.net:make-peer
                              :state :ready :addr-relay-enabled t
                              :address (format nil "1.1.1.~D:8333" i))))
         (br (bl.net:make-peer :state :ready :conn-type :block-relay))
         (peers (append (list source br) full))
         (pa (bl.net:make-peer-address
              :ip (let ((ip (make-array 16 :element-type '(unsigned-byte 8)
                                           :initial-element 0)))
                    (setf (aref ip 10) #xff (aref ip 11) #xff (aref ip 12) 8) ip)
              :port 8333 :services 1
              :last-seen (bl.ser:get-unix-time)))
         (key (bl.net::%addr-gossip-key pa))
         (sent (%relay-address pa source peers)))
    ;; exactly 2 targets chosen (4 eligible; source + block-relay excluded)
    (is (= 2 sent))
    ;; no target is marked yet: the address is only QUEUED to them.
    (is (= 0 (count-if (lambda (p)
                         (bl:recent-reject-p
                          (bl.net:peer-known-addrs p) key))
                       full)))
    (%flush-addrs-now peers)
    ;; exactly 2 of the full-relay peers know it; the block-relay peer doesn't
    (is (= 2 (count-if (lambda (p)
                         (bl:recent-reject-p
                          (bl.net:peer-known-addrs p) key))
                       full)))
    (is-false (bl:recent-reject-p
               (bl.net:peer-known-addrs br) key))
    ;; Relaying the same address again inside its rotation period: the SAME
    ;; two peers are picked, both know it, and PushAddress does nothing --
    ;; Core queues to its picked nodes and stops there (net_processing.cpp:
    ;; 2322-2336). Walking further down the ranking for two peers that do not
    ;; know it yet, which is what this did, hands a peer that repeats an
    ;; address the wider propagation the 24h rotation exists to deny it.
    (let ((sent2 (%relay-address pa source peers)))
      (is (= 0 sent2) "a repeat inside the rotation period queues nothing")
      (%flush-addrs-now peers)
      (is (= 2 (count-if (lambda (p)
                           (bl:recent-reject-p
                            (bl.net:peer-known-addrs p) key))
                         full))
          "and the address still has exactly two destinations")
      (is (= 0 (%relay-address pa source peers))))))

(defmacro %with-relay-salt ((k0 k1) &body body)
  "Run BODY with the node's address-relay SipHash key fixed at (K0 . K1), so
the destination ranking is reproducible (Core CConnman::nSeed0/nSeed1, drawn
once per process)."
  `(let ((bl.net::*address-relay-salt* (cons ,k0 ,k1)))
     ,@body))

(defun %relay-destinations (pa source peers &rest args)
  "The ids of the peers RELAY-ADDRESS queues PA on, every queue emptied first
so the answer belongs to this call. Nothing is flushed, so no target is ever
marked as knowing the address and repeated measurements stay comparable."
  (dolist (p peers) (setf (fill-pointer (%addr-queue p)) 0))
  (apply #'%relay-address pa source peers args)
  (sort (loop for p in peers
              when (plusp (length (%addr-queue p)))
                collect (bl.net:peer-id p))
        #'<))

(defun %relay-peer-set (n)
  "SOURCE plus N eligible addr-relay peers, as (VALUES source peers)."
  (let* ((source (bl.net:make-peer :state :ready :address "9.9.9.9:8333"))
         (targets (loop for i below n
                        collect (bl.net:make-peer
                                 :state :ready :addr-relay-enabled t
                                 :address (format nil "1.1.~D.~D:8333"
                                                  (floor i 256) (mod i 256))))))
    (values source (cons source targets))))

(test relay-address-rotation-instant-is-per-address
  "Core offsets the rotation epoch by the address\'s own hash --
`(count_seconds(current_time) + hash_addr) / count_seconds(
ROTATE_ADDR_RELAY_DEST_INTERVAL)`, net_processing.cpp:2293-2297, commented
\"adding address hash makes exact rotation time different per address, while
preserving periodicity\". Ours divided the bare clock, so EVERY address in the
network changed destinations at the same instant, 00:00 UTC: one moment a day
when the whole gossip topology turns over at once.

Two instants inside one UTC day. Under the old rule no address can differ
between them, because both floor to the same epoch. The salt is pinned so the
ranking is reproducible."
  (%with-relay-salt (#x0706050403020100 #x0f0e0d0c0b0a0908)
    (multiple-value-bind (source peers) (%relay-peer-set 6)
      (let* ((day-start (* 20000 86400))
             (rotated
               (loop for i below 24
                     for pa = (%make-test-peer-address 8 0 (floor i 256)
                                                       (mod i 256) 8333)
                     count (not (equal (%relay-destinations pa source peers
                                                            :now (+ day-start 10))
                                       (%relay-destinations pa source peers
                                                            :now (+ day-start 86000)))))))
        (is (plusp rotated)
            "no address rotated inside the day: the epoch ignores the address ~
             hash, so all ~D of them turn over together at 00:00 UTC" 24)))))

(test relay-address-ranking-is-keyed-by-the-node-secret
  "Core ranks relay destinations with the node\'s deterministic randomizer --
CSipHasher(nSeed0, nSeed1).Write(RANDOMIZER_ID_ADDRESS_RELAY)...
(net_processing.cpp:2298-2313) -- so which peers an address reaches cannot be
computed from public inputs. Ours ranked by a bare sha256 over the address,
the day and the peer id, all of them public: an attacker could work out in
advance which two of our peers any address would reach, and choose addresses
to steer its own fan-out.

The same address and the same peers, under two node secrets, must not always
pick the same destinations."
  (multiple-value-bind (source peers) (%relay-peer-set 6)
    (let ((differing
            (loop for i below 12
                  for pa = (%make-test-peer-address 9 0 (floor i 256)
                                                    (mod i 256) 8333)
                  count (not (equal
                              (%with-relay-salt (1 2)
                                (%relay-destinations pa source peers))
                              (%with-relay-salt (#xdeadbeefcafef00d #x0123456789abcdef)
                                (%relay-destinations pa source peers)))))))
      (is (plusp differing)
          "the destination ranking ignored the node secret for all 12 addresses"))))

(test relay-address-unreachable-fanout-is-one-or-two
  "Core: `unsigned int nRelayNodes = (fReachable || (hasher.Finalize() & 1))
? 2 : 1` (net_processing.cpp:2301-2302) -- a reachable address always goes to
two peers, an unreachable one to one OR two, decided by the low bit of the
same hasher. Ours took a caller-supplied count and the ingest path passed a
flat 1 for every unreachable address, so an address on a network we cannot
dial propagated at half Core\'s rate with no exceptions."
  (%with-relay-salt (#x1122334455667788 #x99aabbccddeeff00)
    (multiple-value-bind (source peers) (%relay-peer-set 6)
      (let ((reachable-counts '())
            (unreachable-counts '()))
        (dotimes (i 24)
          (let ((pa (%make-test-peer-address 10 0 (floor i 256) (mod i 256) 8333)))
            (push (length (%relay-destinations pa source peers :reachable t))
                  reachable-counts)
            (push (length (%relay-destinations pa source peers :reachable nil))
                  unreachable-counts)))
        (is (every (lambda (n) (= n 2)) reachable-counts)
            "a reachable address always reaches two peers")
        (is-true (member 1 unreachable-counts)
                 "some unreachable addresses reach one peer")
        (is-true (member 2 unreachable-counts)
                 "and some reach two -- a flat 1 is not Core\'s rule")))))

(test relay-address-queues-and-only-the-flush-sends
  "a4680ae1 / 0c05f5d0: Core RelayAddress calls PushAddress and nothing else
(net_processing.cpp:2325-2327, 1128-1141). The address lands in the chosen
peer's m_addrs_to_send and waits for MaybeSendAddr's exponential deadline;
sending inside the relay call instead welds the instant we pass an address on
to the instant we learned it, which is the timing correlation
AVG_ADDRESS_BROADCAST_INTERVAL exists to destroy."
  (let* ((source (bl.net:make-peer :state :ready :address "9.9.9.9:8333"))
         (targets (loop for i below 2
                        collect (bl.net:make-peer
                                 :state :ready :addr-relay-enabled t
                                 :address (format nil "1.1.1.~D:8333" i))))
         (peers (cons source targets))
         (pa (%make-test-peer-address 8 0 0 1 8333)))
    (%with-captured-sends (sends)
      (is (= 2 (%relay-address pa source peers)))
      (is (= 0 (length sends))
          "relay-address must put nothing on the wire")
      (is (= 2 (count-if (lambda (p) (plusp (length (%addr-queue p)))) targets))
          "both chosen peers must have it queued instead")
      ;; The flush is what sends, and it is one message per peer.
      (%flush-addrs-now peers)
      (is (= 2 (length sends)) "the flush sends, once per peer")
      (is (= 0 (count-if (lambda (p) (plusp (length (%addr-queue p)))) targets))
          "and empties the queues it sent"))))

(test addr-flush-batches-its-queue-into-one-message
  "Core MaybeSendAddr flushes the WHOLE accumulated vector as ONE addr/addrv2
(net_processing.cpp:5592-5599). Three separately-relayed addresses reach a
peer as one message carrying three entries, not as three messages."
  (let* ((source (bl.net:make-peer :state :ready :address "9.9.9.9:8333"))
         (target (bl.net:make-peer :state :ready :addr-relay-enabled t
                                   :wants-addrv2 t :address "1.1.1.1:8333"))
         (peers (list source target)))
    (%with-captured-sends (sends)
      (dotimes (i 3)
        (%relay-address (%make-test-peer-address 8 0 0 (1+ i) 8333) source peers))
      (is (= 0 (length sends)))
      (%flush-addrs-now peers)
      (is (= 1 (length sends)) "one message, not one per address")
      (let ((msg (cdr (aref sends 0))))
        (is (string= "addrv2" (%message-command msg)))
        (is (= 3 (length (bl.ser:parse-addrv2-payload (%message-payload msg)))))))))

(test addr-flush-deadline-is-on-the-mockable-clock
  "Core's MaybeSendAddr reads current_time = GetTime<microseconds>(), the
MOCKABLE clock, for m_next_addr_send and m_next_local_addr_send
(net_processing.cpp:5737, :5535-5573). p2p_addr_relay.py:128-136 moves
setmocktime 600 s forward to make every receiver's flush due and then pings
each one; on the process clock ours kept its real-time schedule and only 3 of
the 20 relayed addresses arrived (p2p_addr_relay.py:175)."
  (let* ((t0 1700000000)
         (bl.ser:*mock-time* t0)
         (source (bl.net:make-peer :state :ready :address "9.9.9.9:8333"))
         (target (bl.net:make-peer :state :ready :addr-relay-enabled t
                                   :address "1.1.1.1:8333"))
         (peers (list source target)))
    (%with-captured-sends (sends)
      (bl.net:flush-addr-announcements peers)   ; arms the deadline
      (%relay-address (%make-test-peer-address 8 0 0 1 8333) source peers)
      (bl.net:flush-addr-announcements peers)
      (is (= 0 (length sends)) "not due at the same mock instant")
      (setf bl.ser:*mock-time* (+ t0 600))
      (bl.net:flush-addr-announcements peers)
      (is (= 1 (length sends)) "600 mock seconds later the flush is due")
      ;; A clock moved far BACKWARDS re-arms rather than stalling forever.
      (setf bl.ser:*mock-time* (- t0 100000))
      (%relay-address (%make-test-peer-address 8 0 0 2 8333) source peers)
      (bl.net:flush-addr-announcements peers)
      (is (= 2 (length sends)) "a deadline stranded in the future is re-armed"))))

(test addr-flush-waits-out-its-poisson-deadline
  "The flush is a schedule, not a drain: a peer whose m_next_addr_send has not
passed is skipped and keeps its queue (net_processing.cpp:5571-5573). The
deadline is re-drawn on every due pass, including one that finds the queue
empty -- which is what arms a freshly-ready peer's first interval."
  (let* ((source (bl.net:make-peer :state :ready :address "9.9.9.9:8333"))
         (target (bl.net:make-peer :state :ready :addr-relay-enabled t
                                   :address "1.1.1.1:8333"))
         (peers (list source target))
         (pa (%make-test-peer-address 8 0 0 1 8333)))
    (%with-captured-sends (sends)
      ;; Nothing queued yet, but the pass still arms the timer.
      (bl.net:flush-addr-announcements peers)
      (is (= 0 (length sends)))
      (is (plusp (%addr-send-deadline target))
          "an empty pass still re-draws the deadline")
      (%relay-address pa source peers)
      ;; Not due: skipped, and the queue is kept rather than dropped.
      (bl.net:flush-addr-announcements peers)
      (is (= 0 (length sends)) "an undue peer is skipped")
      (is (= 1 (length (%addr-queue target))) "and keeps what was queued")
      ;; Due: the same queue goes out.
      (%flush-addrs-now peers)
      (is (= 1 (length sends))))))

(test addr-queue-is-bounded-at-max-addr-to-send
  "Core PushAddress replaces a uniformly random entry once m_addrs_to_send
holds MAX_ADDR_TO_SEND (net_processing.cpp:1135-1138), so the queue is
bounded and which addresses survive a flood is not the flooder's choice."
  (let ((peer (bl.net:make-peer :state :ready :addr-relay-enabled t
                               :address "1.1.1.1:8333")))
    (dotimes (i (+ bl.ser:+max-addr-count+ 5))
      (bl.net::push-address peer (%make-test-peer-address
                                  10 0 (ldb (byte 8 8) i) (ldb (byte 8 0) i)
                                  8333)))
    (is (= bl.ser:+max-addr-count+ (length (%addr-queue peer))))))

;;;; ============================================================
;;;; G7-20: per-network getaddr response cache
;;;; ============================================================

(defun %g720-book (n)
  "An address book seeded with N routable addresses spread across /16s, with
RECENT last-seen stamps — addrman excludes 'terrible' (stale) entries from
GetAddr, so a fixed 2023 timestamp yields an empty sample.

NB the book may hold FEWER than N — addrman buckets collide by design — so
these tests never assert an exact count (a standing rule in this project)."
  (let ((book (bl.net:make-address-book))
        (now (bl.ser:get-unix-time)))
    (dotimes (i n)
      (bl.net:address-book-add
       book (bl.net:make-peer-address
             :ip (bl.net:ipv4-to-mapped-ipv6
                  203 (mod i 250) (floor i 250) 7)
             :port (+ 18333 i) :services 1 :last-seen now)))
    book))

(defun %cached-addrs (&rest args)
  "The getaddr response cache lookup (BL.NET's CACHED-GETADDR-RESPONSE), the
one reach into it for this file."
  (apply #'bl.net::cached-getaddr-response args))

(test g7-20-getaddr-response-is-cached-per-network
  "G7-20: re-sampling addrman on every getaddr let an attacker reconnect
repeatedly and harvest many independent samples — enough to reconstruct the
table and watch timestamps churn. Core answers every requestor on one network
with the SAME snapshot for 21-27h (net.cpp:3694-3730), which is what makes
reconnecting pointless."
  (bl.net::clear-addr-response-caches)
  (let* ((book (%g720-book 200))
         (now 1700000000))
    (let ((r1 (%cached-addrs book :ipv4 now))
          (r2 (%cached-addrs book :ipv4 (+ now 60)))
          (r3 (%cached-addrs
               book :ipv4 (+ now (* 3 60 60)))))
      (is (eq r1 r2) "a second requestor inside the window gets the SAME snapshot")
      (is (eq r1 r3) "still the same snapshot hours later"))
    ;; A different requestor network gets its own snapshot and its own expiry.
    (let ((v4 (%cached-addrs book :ipv4 now))
          (onion (%cached-addrs book :torv3 now)))
      (is (not (eq v4 onion))
          "networks must not share a cache entry"))
    (is (= 2 (hash-table-count bl.net::*addr-response-caches*)))
    ;; ...and so does each accepting SOCKET on one network (Core's key is
    ;; (network, local bind), net.cpp:1832-1836): p2p_getaddr_caching.py binds
    ;; two onion targets and expects two snapshots.
    (let ((onion1 (%cached-addrs book :torv3 now 21001))
          (onion2 (%cached-addrs book :torv3 now 21002)))
      (is (eq onion1 (%cached-addrs book :torv3 (+ now 60) 21001))
          "control: one socket keeps its own snapshot")
      (is (not (eq onion1 onion2))
          "two sockets on one network must not share a cache entry"))))

(test g7-20-cache-expires-between-21h-and-27h
  "Expiry is 21h + rand(6h) (Core's m_cache_entry_expiration), so the refresh
instant is not predictable and cannot itself be used as a clock signal."
  (bl.net::clear-addr-response-caches)
  (let ((book (%g720-book 60))
        (now 1700000000))
    (let ((first (%cached-addrs book :ipv4 now)))
      ;; Just under the minimum lifetime: still the same object.
      (is (eq first (%cached-addrs
                     book :ipv4 (+ now (* 21 60 60) -60))))
      ;; Past the maximum lifetime: refilled.
      (let ((refreshed (%cached-addrs
                        book :ipv4 (+ now (* 27 60 60) 60))))
        (is (not (eq first refreshed)) "must refill after the maximum lifetime")))
    ;; The stored expiry must sit inside [21h, 27h].
    (bl.net::clear-addr-response-caches)
    (%cached-addrs book :ipv4 now)
    (let ((expiry (cdr (gethash (cons :ipv4 nil) bl.net::*addr-response-caches*))))
      (is (>= expiry (+ now (* 21 60 60))))
      (is (<= expiry (+ now (* 27 60 60)))))))

(test g7-20-ban-filter-runs-at-fill-time-only
  "Core filters banned/discouraged inside GetAddressesUnsafe (net.cpp:3686-3690),
which runs ONLY on a cache miss; a hit returns the cached list verbatim
(net.cpp:3729). Re-filtering per hit would make responses differ between
requestors inside one window whenever a ban landed mid-window — exactly the
fingerprinting signal the cache exists to erase. The visible consequence is
that a banned address keeps being gossiped for up to 27h. That is
Core-identical and intended, so it is asserted here rather than 'fixed'."
  (bl.net::clear-addr-response-caches)
  (bl.net:clear-discouraged)
  (let* ((book (%g720-book 40))
         (now 1700000000)
         (filled (%cached-addrs book :ipv4 now)))
    (is (plusp (length filled)) "precondition: the cache filled with something")
    ;; Discourage an address that IS in the cached snapshot.
    (let ((victim (bl.net:peer-address-string (first filled))))
      (bl.net:discourage-peer victim)
      (let ((hit (%cached-addrs book :ipv4 (+ now 60))))
        (is (eq filled hit)
            "a cache HIT must be returned verbatim, not re-filtered"))
      ;; ...but a refill after expiry drops it.
      (let ((refilled (%cached-addrs
                       book :ipv4 (+ now (* 28 60 60)))))
        (is (notany (lambda (pa)
                      (string= victim (bl.net:peer-address-string pa)))
                    refilled)
            "a refill must apply the ban/discourage filter"))
      (bl.net:clear-discouraged))))

(test g7-20-getnodeaddresses-stays-uncached
  "Core's rpc/net.cpp:956 deliberately calls the UNCACHED GetAddressesUnsafe:
the operator asking their own node must see live addrman state, not a snapshot
frozen for a day. Guard against 'helpfully' routing it through the cache."
  (let ((src (%rpc-source-text)))
    (let ((start (search "define-rpc \"getnodeaddresses\"" src)))
      (is (integerp start) "rpc-getnodeaddresses must exist")
      (when start
        (let ((body (subseq src start (min (length src) (+ start 2000)))))
          (is (null (search "cached-getaddr-response" body))
              "getnodeaddresses must not use the getaddr cache"))))))

(test relay-address-skips-peers-without-addr-relay
  "Core RelayAddress (net_processing.cpp:2311) gossips only to peers with
address relay set up: an inbound peer that never sent addr/getaddr — so
SetupAddressRelay never ran for it — receives nothing, even though it relays
transactions."
  (let* ((source (bl.net:make-peer :state :ready :address "9.9.9.9:8333"))
         (with (bl.net:make-peer :state :ready :addr-relay-enabled t
                                                   :address "1.1.1.1:8333"))
         (without (bl.net:make-peer :state :ready
                                                      :address "1.1.1.2:8333"))
         (pa (%make-test-peer-address 8 0 0 0 8333))
         (key (bl.net::%addr-gossip-key pa)))
    (is (= 1 (%relay-address pa source (list source with without))))
    (%flush-addrs-now (list source with without))
    (is-true (bl:recent-reject-p
              (bl.net:peer-known-addrs with) key))
    (is-false (bl:recent-reject-p
               (bl.net:peer-known-addrs without) key))))

(test feefilter-above-max-money-is-ignored
  "Core applies a feefilter only when MoneyRange(newFeeFilter)
(net_processing.cpp:5126); a rate above MAX_MONEY is ignored rather than
stored, where it would silently suppress every announcement to the peer."
  (let ((peer (bl.net:make-peer :state :ready :address "1.1.1.3:8333"))
        (ok (%message-payload (bl.ser:make-feefilter-message 1000)))
        (absurd (%message-payload (bl.ser:make-feefilter-message
                                   (1+ bl.val:+max-money+)))))
    (bl.net:handle-message peer "feefilter" ok (bl.ctx:make-node-context))
    (is (= 1000 (bl.net:peer-feefilter-rate peer)))
    (bl.net:handle-message peer "feefilter" absurd (bl.ctx:make-node-context))
    (is (= 1000 (bl.net:peer-feefilter-rate peer)))))

(test automatic-inbound-capacity-follows-core
  "Core CConnman::Init (net.h:1110-1113): -maxconnections is the automatic
total; inbound = total - (full-relay + block-relay-only + feeler), floored at 0."
  (is (= 114 (bl::automatic-inbound-capacity 125 8)))
  (is (= 5 (bl::automatic-inbound-capacity 16 8)))
  (is (= 0 (bl::automatic-inbound-capacity 8 8))))

(test capturemessages-writes-cores-record-format
  "-capturemessages appends every sent and received message to
<datadir>/message_capture/<addr with : as _>/msgs_{sent,recv}.dat as Core's
CaptureMessageToFile writes it: 8-byte LE microseconds, the type NUL-padded to
12 bytes, a 4-byte LE length and the payload (net.cpp:4184-4218).
p2p_message_capture.py:60-65 globs for those files; we accepted the option
and wrote nothing."
  (let* ((dir (merge-pathnames (format nil "bl-capture-~D/" (random 1000000000))
                               (uiop:temporary-directory)))
         (bl.net:*capture-messages-directory* dir)
         (bl.ser:*mock-time* 1700000000)
         (peer (bl.net:make-peer
                :address "127.0.0.1"
                :connection (make-test-connection :host "127.0.0.1" :port 18444
                                                  :connected t :socket nil))))
    (unwind-protect
         (progn
           (bl.net:capture-message peer "ping" #(1 2 3 4 5 6 7 8) t)
           (bl.net:capture-message peer "verack" #() nil)
           (let ((recv (merge-pathnames "127.0.0.1_18444/msgs_recv.dat" dir))
                 (sent (merge-pathnames "127.0.0.1_18444/msgs_sent.dat" dir)))
             (is-true (probe-file recv))
             (is-true (probe-file sent))
             (with-open-file (in recv :element-type '(unsigned-byte 8))
               (let ((bytes (make-array (file-length in) :element-type '(unsigned-byte 8))))
                 (read-sequence bytes in)
                 (is (= (+ 8 12 4 8) (length bytes)))
                 (is (= (* 1700000000 1000000)
                        (loop for i below 8 sum (ash (aref bytes i) (* 8 i)))))
                 (is (string= "ping" (map 'string #'code-char
                                          (remove 0 (subseq bytes 8 20)))))
                 (is (= 8 (loop for i below 4 sum (ash (aref bytes (+ 20 i)) (* 8 i)))))))))
      (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore))))

(test getaddr-response-is-queued-for-the-addr-flush
  "Core answers getaddr by PushAddress-ing the sample onto the peer's addr
queue (after clearing it) and lets MaybeSendAddr send it
(net_processing.cpp:4926-4936) -- which also sends a first self-announcement
due on the same pass BEFORE the queue, alone; p2p_addr_selfannouncement.py:
48-54 asserts the self-announcement is the first addr message. Ours sent the
reply from the handler, ahead of everything."
  ;; An IPv6 requestor: the per-network response cache the other getaddr
  ;; tests fill is keyed :ipv4 / :torv3, and any :ipv6 snapshot left by an
  ;; earlier run of this test is just as non-empty.
  (let ((bl:*node* nil)
        (book (%g720-book 50))
        (peer (bl.net:init-peer-rate-limiters
               (bl.net:make-peer :state :ready :inbound t :address "2600::1"
                                 :addr-relay-enabled t))))
    (%with-captured-sends (sends)
      (with-ibd-context
        (deliver-ibd-message peer "getaddr" #()
                             (bl.ctx:make-node-context :address-book book)))
      (is (= 0 (length sends)) "nothing is sent from the handler")
      (is (plusp (length (%addr-queue peer))) "the sample is queued")
      (%flush-addrs-now (list peer))
      (is (= 1 (length sends)) "and leaves with the next flush"))))

(test a-block-inv-asks-for-headers-from-our-valid-best-header
  "Core builds the getheaders a block inv triggers from m_best_header
(net_processing.cpp:4198), which is never an invalid block: marking one
invalid recalculates it (validation.cpp:3638-3668, 6275-6283). Our header tip
was the highest-HEIGHT index entry, so after a block failed validation every
locator started at that block; p2p_segwit.py:376 announces a block on the real
tip and waits for a getheaders whose locator starts at the tip."
  (multiple-value-bind (cs entries) (%make-served-chain 3)   ; tip at height 3
    (let* ((tip (nth 3 entries))
           (bad-header (bl.ser:make-block-header
                        :version 1 :prev-block (bl.store:block-index-entry-hash tip)
                        :merkle-root (%uniq-hash 8801) :timestamp 1700000004
                        :bits #x1d00ffff :nonce 1))
           (peer (bl.net:init-peer-rate-limiters
                  (bl.net:make-peer :address "test" :state :ready
                                    :services bl.ser:+node-witness+)))
           ;; A FRESH hash each run: the inv handler remembers the last block
           ;; that triggered a pre-sync getheaders, process-wide, and a repeat
           ;; of it is (rightly) not asked about again.
           (announced (let ((h (make-array 32 :element-type '(unsigned-byte 8))))
                        (dotimes (i 32 h) (setf (aref h i) (random 256))))))
      ;; A rejected block one above the tip, still in the index.
      (bl.store:add-block-index-entry
       cs (bl.store:make-block-index-entry
           :hash (bl.ser:block-header-hash bad-header) :height 4 :header bad-header
           :prev-entry tip :chain-work 5 :status :invalid))
      (let* ((sent (captured-sends
                    (lambda ()
                      (with-ibd-context
                        (deliver-ibd-message
                         peer "inv"
                         (%message-payload
                          (bl.ser:make-inv-message
                           (list (bl.ser:make-inv-vector :type bl.ser:+inv-type-block+
                                                         :hash announced))))
                         (bl.ctx:make-node-context :chain-state cs))))))
             (getheaders (find "getheaders" sent :key #'%message-command :test #'string=)))
        (is-true getheaders "the unknown block is answered with a getheaders")
        (when getheaders
          (is (equalp (bl.store:block-index-entry-hash tip)
                      (first (bl.ser:parse-block-locator-payload
                              (%message-payload getheaders))))
              "the locator starts at our valid tip, not at the rejected block"))))))
