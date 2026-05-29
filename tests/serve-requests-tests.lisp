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
             (header (bitcoin-lisp.serialization:make-block-header
                      :version 1 :prev-block prev-hash :merkle-root merkle
                      :timestamp (+ 1700000000 h) :bits #x1d00ffff :nonce h))
             (hash (bitcoin-lisp.serialization:block-header-hash header))
             (entry (bitcoin-lisp.storage:make-block-index-entry
                     :hash hash :height h :header header
                     :prev-entry prev-entry :chain-work (1+ h) :status :valid)))
        (when (zerop h)
          (setf cs (bitcoin-lisp.storage:make-chain-state
                    :genesis-hash hash :best-block-hash hash :best-height 0)))
        (bitcoin-lisp.storage:add-block-index-entry cs entry)
        (bitcoin-lisp.storage:update-chain-tip cs hash h)
        (push entry entries)
        (setf prev-hash hash prev-entry entry)))
    (values cs (nreverse entries))))

(defun %entry-hash (entries height)
  (bitcoin-lisp.storage:block-index-entry-hash (nth height entries)))

(defun %getheaders-payload (locator-hashes &optional stop-hash)
  "Build the on-wire payload (header stripped) of a getheaders message."
  (subseq (bitcoin-lisp.serialization:make-getheaders-message locator-hashes stop-hash)
          24))

(defun %getblocks-payload (locator-hashes &optional stop-hash)
  (subseq (bitcoin-lisp.serialization:make-getblocks-message locator-hashes stop-hash)
          24))

(defun %message-payload (msg)
  "Return the payload bytes of a serialized P2P message (strip 24-byte header)."
  (flexi-streams:with-input-from-sequence (s msg)
    (let ((hdr (bitcoin-lisp.serialization:read-message-header s)))
      (subseq msg 24 (+ 24 (bitcoin-lisp.serialization:message-header-payload-length hdr))))))

(defun %message-command (msg)
  (flexi-streams:with-input-from-sequence (s msg)
    (bitcoin-lisp.serialization:message-header-command
     (bitcoin-lisp.serialization:read-message-header s))))

;;;; find-fork-in-active-chain

(test fork-returns-tip-when-locator-has-tip
  (multiple-value-bind (cs entries) (%make-served-chain 5)
    (let ((fork (bitcoin-lisp.storage:find-fork-in-active-chain
                 cs (list (%entry-hash entries 5)))))
      (is (= 5 (bitcoin-lisp.storage:block-index-entry-height fork))))))

(test fork-returns-highest-on-chain-hash
  (multiple-value-bind (cs entries) (%make-served-chain 5)
    ;; Locator most-recent-first: an unknown hash, then block 3, then block 1.
    (let ((fork (bitcoin-lisp.storage:find-fork-in-active-chain
                 cs (list (%uniq-hash 999999)
                          (%entry-hash entries 3)
                          (%entry-hash entries 1)))))
      (is (= 3 (bitcoin-lisp.storage:block-index-entry-height fork))))))

(test fork-falls-back-to-genesis
  (multiple-value-bind (cs entries) (%make-served-chain 5)
    (declare (ignore entries))
    (let ((fork (bitcoin-lisp.storage:find-fork-in-active-chain
                 cs (list (%uniq-hash 111) (%uniq-hash 222)))))
      (is (= 0 (bitcoin-lisp.storage:block-index-entry-height fork))))))

;;;; active-chain-entries-from

(test active-chain-entries-ascending-and-bounded
  (multiple-value-bind (cs entries) (%make-served-chain 5)
    (declare (ignore entries))
    (let ((got (bitcoin-lisp.storage:active-chain-entries-from cs 1 100)))
      (is (= 5 (length got)))
      (is (equal '(1 2 3 4 5)
                 (mapcar #'bitcoin-lisp.storage:block-index-entry-height got))))
    ;; Limit caps the count, still from FROM-HEIGHT ascending.
    (let ((got (bitcoin-lisp.storage:active-chain-entries-from cs 2 2)))
      (is (equal '(2 3)
                 (mapcar #'bitcoin-lisp.storage:block-index-entry-height got))))
    ;; Above the tip => empty.
    (is (null (bitcoin-lisp.storage:active-chain-entries-from cs 6 100)))))

;;;; getheaders-response-message

(test getheaders-from-genesis-returns-rest-of-chain
  (multiple-value-bind (cs entries) (%make-served-chain 5)
    (let* ((payload (%getheaders-payload (list (%entry-hash entries 0))))
           (msg (bitcoin-lisp.networking::getheaders-response-message payload cs))
           (headers (bitcoin-lisp.serialization:parse-headers-payload
                     (%message-payload msg))))
      (is (string= "headers" (%message-command msg)))
      (is (= 5 (length headers)))
      ;; Headers are blocks 1..5 in order, matching our index hashes.
      (loop for header in headers
            for height from 1
            do (is (equalp (%entry-hash entries height)
                           (bitcoin-lisp.serialization:block-header-hash header)))))))

(test getheaders-at-tip-returns-empty
  (multiple-value-bind (cs entries) (%make-served-chain 5)
    (let* ((payload (%getheaders-payload (list (%entry-hash entries 5))))
           (msg (bitcoin-lisp.networking::getheaders-response-message payload cs))
           (headers (bitcoin-lisp.serialization:parse-headers-payload
                     (%message-payload msg))))
      (is (null headers)))))

(test getheaders-stop-hash-is-inclusive
  (multiple-value-bind (cs entries) (%make-served-chain 5)
    (let* ((payload (%getheaders-payload (list (%entry-hash entries 0))
                                         (%entry-hash entries 2)))
           (msg (bitcoin-lisp.networking::getheaders-response-message payload cs))
           (headers (bitcoin-lisp.serialization:parse-headers-payload
                     (%message-payload msg))))
      ;; Blocks 1 and 2 — stop hash (block 2) is included.
      (is (= 2 (length headers)))
      (is (equalp (%entry-hash entries 2)
                  (bitcoin-lisp.serialization:block-header-hash
                   (car (last headers))))))))

(test getheaders-null-locator-returns-stop-header
  (multiple-value-bind (cs entries) (%make-served-chain 5)
    (let* ((payload (%getheaders-payload '() (%entry-hash entries 3)))
           (msg (bitcoin-lisp.networking::getheaders-response-message payload cs))
           (headers (bitcoin-lisp.serialization:parse-headers-payload
                     (%message-payload msg))))
      (is (= 1 (length headers)))
      (is (equalp (%entry-hash entries 3)
                  (bitcoin-lisp.serialization:block-header-hash (first headers)))))))

;;;; getblocks-response-message

(test getblocks-from-genesis-returns-inv
  (multiple-value-bind (cs entries) (%make-served-chain 5)
    (let* ((payload (%getblocks-payload (list (%entry-hash entries 0))))
           (msg (bitcoin-lisp.networking::getblocks-response-message payload cs))
           (invs (bitcoin-lisp.serialization:parse-inv-payload (%message-payload msg))))
      (is (string= "inv" (%message-command msg)))
      (is (= 5 (length invs)))
      (loop for inv in invs
            for height from 1
            do (is (= bitcoin-lisp.serialization:+inv-type-block+
                      (bitcoin-lisp.serialization:inv-vector-type inv)))
               (is (equalp (%entry-hash entries height)
                           (bitcoin-lisp.serialization:inv-vector-hash inv)))))))

(test getblocks-stop-hash-is-exclusive
  (multiple-value-bind (cs entries) (%make-served-chain 5)
    (let* ((payload (%getblocks-payload (list (%entry-hash entries 0))
                                        (%entry-hash entries 2)))
           (msg (bitcoin-lisp.networking::getblocks-response-message payload cs))
           (invs (bitcoin-lisp.serialization:parse-inv-payload (%message-payload msg))))
      ;; Only block 1 — the inv stops before the stop hash (block 2).
      (is (= 1 (length invs)))
      (is (equalp (%entry-hash entries 1)
                  (bitcoin-lisp.serialization:inv-vector-hash (first invs)))))))

(test getblocks-at-tip-returns-nil
  (multiple-value-bind (cs entries) (%make-served-chain 5)
    (let ((payload (%getblocks-payload (list (%entry-hash entries 5)))))
      (is (null (bitcoin-lisp.networking::getblocks-response-message payload cs))))))

;;;; truncate-entries-at-stop

(test truncate-zero-hash-keeps-all
  (multiple-value-bind (cs entries) (%make-served-chain 3)
    (declare (ignore cs))
    (is (= 4 (length (bitcoin-lisp.networking::truncate-entries-at-stop
                      entries (%zero32) t))))))

(test truncate-missing-stop-keeps-all
  (multiple-value-bind (cs entries) (%make-served-chain 3)
    (declare (ignore cs))
    (is (= 4 (length (bitcoin-lisp.networking::truncate-entries-at-stop
                      entries (%uniq-hash 424242) t))))))

;;;; getaddr gating + addr response building

(defun %make-test-peer-address (a b c d port)
  (bitcoin-lisp.networking:make-peer-address
   :ip (bitcoin-lisp.networking::ipv4-to-mapped-ipv6 a b c d)
   :port port :services 1 :last-seen 1700000000))

(test getaddr-only-once-and-inbound-only
  (let ((bitcoin-lisp::*node* nil))    ; book resolves to NIL: gating only, no send
    ;; Outbound peer: never marked as answered.
    (let ((outbound (bitcoin-lisp.networking:make-peer :inbound nil)))
      (bitcoin-lisp.networking::handle-getaddr outbound)
      (is (null (bitcoin-lisp.networking:peer-getaddr-sent outbound))))
    ;; Inbound peer: answered exactly once (flag latches on first call).
    (let ((inbound (bitcoin-lisp.networking:make-peer :inbound t)))
      (is (null (bitcoin-lisp.networking:peer-getaddr-sent inbound)))
      (bitcoin-lisp.networking::handle-getaddr inbound)
      (is-true (bitcoin-lisp.networking:peer-getaddr-sent inbound))
      ;; Second call is a no-op; flag stays set.
      (bitcoin-lisp.networking::handle-getaddr inbound)
      (is-true (bitcoin-lisp.networking:peer-getaddr-sent inbound)))))

(test build-addrv2-response-round-trips
  (let ((peer (bitcoin-lisp.networking:make-peer :wants-addrv2 t))
        (addrs (list (%make-test-peer-address 203 0 113 7 18333)
                     (%make-test-peer-address 198 51 100 9 48333))))
    (let* ((msg (bitcoin-lisp.networking::build-addr-response peer addrs))
           (parsed (bitcoin-lisp.serialization:parse-addrv2-payload (%message-payload msg))))
      (is (string= "addrv2" (%message-command msg)))
      (is (= 2 (length parsed)))
      ;; Ports survive the round trip.
      (is (equal '(18333 48333)
                 (mapcar (lambda (e) (bitcoin-lisp.serialization:net-addr-port (first e)))
                         parsed))))))

(test build-addr-v1-response-has-addr-command
  (let ((peer (bitcoin-lisp.networking:make-peer :wants-addrv2 nil))
        (addrs (list (%make-test-peer-address 203 0 113 7 18333))))
    (is (string= "addr" (%message-command
                         (bitcoin-lisp.networking::build-addr-response peer addrs))))))
