(in-package #:bitcoin-lisp.tests)

(def-suite :compact-block-tests
  :description "Tests for Compact Block Relay (BIP 152)"
  :in :bitcoin-lisp-tests)

(in-suite :compact-block-tests)

;;;; Helper functions

(defun make-mock-peer ()
  "Create a mock peer for testing."
  (bl.net:make-peer
   :state :ready
   :address "127.0.0.1"))

(defun make-mock-mempool-with-txs (txs)
  "Create a mempool with the given transactions.
   TXS is a list of (txid . transaction) pairs."
  (let ((mempool (bl.mp:make-mempool)))
    (dolist (pair txs)
      (let ((txid (car pair))
            (tx (cdr pair)))
        (bl.mp:mempool-add
         mempool txid
         (bl.mp:make-entry-from-tx tx 1000 0))))
    mempool))

(defun make-simple-tx (id-byte)
  "Create a simple transaction with a unique identifier byte."
  (bl.ser:make-transaction
   :version 2
   :inputs (vector (bl.ser:make-tx-in
                  :previous-output (bl.ser:make-outpoint
                                    :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                      :initial-element id-byte)
                                    :index 0)
                  :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                  :sequence #xffffffff))
   :outputs (vector (bl.ser:make-tx-out
                   :value 50000
                   :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                              :initial-element #x76)))
   :lock-time 0))

;;;; Protocol Negotiation Tests

(test sendcmpct-updates-peer-version
  "handle-sendcmpct accepts ONLY compact-block version 2 (witness), matching
Bitcoin Core's CMPCTBLOCKS_VERSION gate. A v1 (non-witness) sendcmpct is ignored:
a v1 compact block delivers a witness-stripped prefilled coinbase, so the
reconstructed block fails BIP141 validation (bad-witness-nonce-size). Accepting v1
is what wedged the testnet4 node ~1800 blocks behind the chain."
  (let ((peer (make-mock-peer)))
    ;; Initially no compact block support
    (is (= (bl.net:peer-compact-block-version peer) 0))
    ;; v1 is ignored — peer stays unsupported (we fall back to full witness blocks)
    (let ((payload (subseq (bl.ser:make-sendcmpct-message nil 1) 24)))
      (bl.net::handle-sendcmpct peer payload nil))
    (is (= (bl.net:peer-compact-block-version peer) 0))
    ;; v2 is accepted
    (let ((payload (subseq (bl.ser:make-sendcmpct-message nil 2) 24)))
      (bl.net::handle-sendcmpct peer payload nil))
    (is (= (bl.net:peer-compact-block-version peer) 2))))

(test sendcmpct-rejects-invalid-version
  "handle-sendcmpct ignores every version other than 2 — v1 and future/unknown
versions alike (mirrors Core's `if (version != CMPCTBLOCKS_VERSION) return;`)."
  (let ((peer (make-mock-peer)))
    ;; v3 (unknown/future) ignored
    (let ((payload (bl.bytes:with-byte-buf (s)
                     (bl.bytes:bb-write-u8 s 0)  ; low-bandwidth
                     (bl.bytes:bb-write-u64-le s 3))))  ; version 3
      (bl.net::handle-sendcmpct peer payload nil))
    (is (= (bl.net:peer-compact-block-version peer) 0))
    ;; v1 ignored too
    (let ((payload (subseq (bl.ser:make-sendcmpct-message nil 1) 24)))
      (bl.net::handle-sendcmpct peer payload nil))
    (is (= (bl.net:peer-compact-block-version peer) 0))))

(test sendcmpct-tracks-high-bandwidth
  "handle-sendcmpct tracks the high-bandwidth preference from a (v2) sendcmpct."
  (let ((peer (make-mock-peer)))
    (is (null (bl.net:peer-compact-block-high-bandwidth peer)))
    ;; Receive high-bandwidth request (v2 — the only version we accept)
    (let ((payload (subseq (bl.ser:make-sendcmpct-message t 2) 24)))
      (bl.net::handle-sendcmpct peer payload nil))
    (is (bl.net:peer-compact-block-high-bandwidth peer))
    (is (= 2 (bl.net:peer-compact-block-version peer)))))

;;;; Short ID Map Building Tests

(test build-shortid-map-indexes-mempool
  "build-shortid-map should create mapping from short IDs to transactions."
  (let* ((tx1 (make-simple-tx #x11))
         (tx2 (make-simple-tx #x22))
         (txid1 (bl.ser:transaction-hash tx1))
         (txid2 (bl.ser:transaction-hash tx2))
         (mempool (make-mock-mempool-with-txs (list (cons txid1 tx1)
                                                    (cons txid2 tx2))))
         (k0 #x0706050403020100)
         (k1 #x0f0e0d0c0b0a0908))
    (multiple-value-bind (map collision)
        (bl.net::build-shortid-map mempool k0 k1 nil)
      (is (not collision))
      (is (= (hash-table-count map) 2))
      ;; Each entry should be (tx . full-id)
      (let ((short-id1 (bl.crypto:compute-short-txid k0 k1 txid1)))
        (is (gethash short-id1 map))))))

(test build-shortid-map-detects-collision
  "build-shortid-map should detect collisions within mempool."
  ;; This is hard to test directly without crafting collision inputs,
  ;; but we can verify the collision flag mechanism works
  (let* ((tx1 (make-simple-tx #x11))
         (txid1 (bl.ser:transaction-hash tx1))
         (mempool (make-mock-mempool-with-txs (list (cons txid1 tx1)))))
    (multiple-value-bind (map collision)
        (bl.net::build-shortid-map mempool 0 0 nil)
      (declare (ignore map))
      ;; With just one tx, no collision expected
      (is (not collision)))))

(test build-shortid-map-uses-wtxid-for-v2
  "build-shortid-map should use wtxid when use-wtxid is true."
  (let* ((tx (make-simple-tx #x33))
         (txid (bl.ser:transaction-hash tx))
         (wtxid (bl.ser:transaction-wtxid tx))
         (mempool (make-mock-mempool-with-txs (list (cons txid tx))))
         (k0 #x1234)
         (k1 #x5678))
    ;; With use-wtxid=nil, should use txid
    (multiple-value-bind (map1 collision1)
        (bl.net::build-shortid-map mempool k0 k1 nil)
      (declare (ignore collision1))
      (let ((short-id-txid (bl.crypto:compute-short-txid k0 k1 txid)))
        (is (gethash short-id-txid map1))))
    ;; With use-wtxid=t, should use wtxid
    (multiple-value-bind (map2 collision2)
        (bl.net::build-shortid-map mempool k0 k1 t)
      (declare (ignore collision2))
      (let ((short-id-wtxid (bl.crypto:compute-short-txid k0 k1 wtxid)))
        (is (gethash short-id-wtxid map2))))))

;;;; Block Reconstruction Tests

(test reconstruct-with-all-txs-in-mempool
  "Block should reconstruct successfully when all txs are in mempool."
  (let* ((tx1 (make-simple-tx #x11))
         (tx2 (make-simple-tx #x22))
         (txid1 (bl.ser:transaction-hash tx1))
         (txid2 (bl.ser:transaction-hash tx2))
         (mempool (make-mock-mempool-with-txs (list (cons txid1 tx1)
                                                    (cons txid2 tx2))))
         (header (bl.ser:make-block-header
                  :version 1
                  :prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :timestamp 0
                  :bits #x1d00ffff
                  :nonce 0))
         (nonce #x1234567890abcdef)
         (header-bytes (bl.ser:serialize-block-header header)))
    ;; Compute short IDs for our transactions
    (multiple-value-bind (k0 k1)
        (bl.crypto:compute-siphash-key header-bytes nonce)
      (let* ((short-id1 (bl.crypto:compute-short-txid k0 k1 txid1))
             (short-id2 (bl.crypto:compute-short-txid k0 k1 txid2))
             (compact-block (bl.ser:make-compact-block
                             :header header
                             :nonce nonce
                             :short-ids (list short-id1 short-id2)
                             :prefilled-txs '())))
        (multiple-value-bind (block missing partial)
            (bl.net::reconstruct-compact-block compact-block mempool nil)
          (declare (ignore partial))
          (is-true block)
          (is (null missing))
          (is (= (length (bl.ser:bitcoin-block-transactions block)) 2)))))))

(test reconstruct-with-missing-txs
  "Reconstruction should return missing indexes when txs not in mempool."
  (let* ((mempool (bl.mp:make-mempool))  ; Empty mempool
         (header (bl.ser:make-block-header
                  :version 1
                  :prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :timestamp 0
                  :bits #x1d00ffff
                  :nonce 0))
         (compact-block (bl.ser:make-compact-block
                         :header header
                         :nonce 0
                         :short-ids (list #x112233445566 #xaabbccddeeff)
                         :prefilled-txs '())))
    (multiple-value-bind (block missing partial)
        (bl.net::reconstruct-compact-block compact-block mempool nil)
      (is (null block))
      (is (equal missing '(0 1)))  ; Both indexes missing
      (is-true partial))))  ; Partial array returned

(test reconstruct-with-prefilled-coinbase
  "Reconstruction should place prefilled transactions correctly."
  (let* ((coinbase-tx (make-simple-tx #x00))
         (tx1 (make-simple-tx #x11))
         (txid1 (bl.ser:transaction-hash tx1))
         (mempool (make-mock-mempool-with-txs (list (cons txid1 tx1))))
         (header (bl.ser:make-block-header
                  :version 1
                  :prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :timestamp 0
                  :bits #x1d00ffff
                  :nonce 0))
         (nonce #x1234567890abcdef)
         (header-bytes (bl.ser:serialize-block-header header)))
    (multiple-value-bind (k0 k1)
        (bl.crypto:compute-siphash-key header-bytes nonce)
      (let* ((short-id1 (bl.crypto:compute-short-txid k0 k1 txid1))
             (prefilled (bl.ser:make-prefilled-tx
                         :index 0
                         :transaction coinbase-tx))
             (compact-block (bl.ser:make-compact-block
                             :header header
                             :nonce nonce
                             :short-ids (list short-id1)
                             :prefilled-txs (list prefilled))))
        (multiple-value-bind (block missing partial)
            (bl.net::reconstruct-compact-block compact-block mempool nil)
          (declare (ignore partial))
          (is-true block)
          (is (null missing))
          ;; First tx should be coinbase (prefilled), second should be tx1
          (is (= (length (bl.ser:bitcoin-block-transactions block)) 2)))))))

;;;; Timeout Handling Tests

(test compact-block-timeout-clears-pending
  "check-compact-block-timeout should clear expired pending state."
  (let ((peer (make-mock-peer)))
    ;; Set up pending state with old timestamp
    (setf (bl.net:peer-pending-compact-block peer)
          (bl.net:make-pending-compact-block
           :block-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xab)
           :request-time (- (get-internal-real-time)
                            (* 20 internal-time-units-per-second))))  ; 20 seconds ago
    (is (bl.net:peer-pending-compact-block peer))
    ;; Check timeout (should clear and request full block)
    ;; Note: This will try to send a message which will fail, but state should clear
    (handler-case
        (bl.net:check-compact-block-timeout peer)
      (error () nil))
    (is (null (bl.net:peer-pending-compact-block peer)))))

(test compact-block-timeout-preserves-fresh-pending
  "check-compact-block-timeout should not clear fresh pending state."
  (let ((peer (make-mock-peer)))
    ;; Set up pending state with recent timestamp
    (setf (bl.net:peer-pending-compact-block peer)
          (bl.net:make-pending-compact-block
           :block-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xab)
           :request-time (get-internal-real-time)))  ; Just now
    (bl.net:check-compact-block-timeout peer)
    ;; Should still have pending state
    (is (bl.net:peer-pending-compact-block peer))))

;;;; Metrics Tests

(test compact-block-stats-returns-metrics
  "compact-block-stats should return current metrics."
  (let ((stats (bl.net:compact-block-stats)))
    (is (listp stats))
    (is (member :successes stats))
    (is (member :failures stats))
    (is (member :collisions stats))))

;;;; Clear pending state test

(test clear-pending-compact-block
  "clear-pending-compact-block should remove pending state."
  (let ((peer (make-mock-peer)))
    (setf (bl.net:peer-pending-compact-block peer)
          (bl.net:make-pending-compact-block
           :block-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (is (bl.net:peer-pending-compact-block peer))
    (bl.net:clear-pending-compact-block peer)
    (is (null (bl.net:peer-pending-compact-block peer)))))

;;;; =============================================================
;;;; Compact-block punishment policy (GA8 wave 4)
;;;;
;;;; Core's MaybePunishNodeForBlock skips BLOCK_CONSENSUS / BLOCK_MUTATED
;;;; whenever via_compact_block is true (net_processing.cpp:1920-1926), and
;;;; both compact-block call sites set it (mapBlockSource emplaced with
;;;; /*punish=*/false at :4778 cmpctblock and :3516 blocktxn, inverted at
;;;; :2211, versus true for the BLOCK message at :4893). Punishment on the
;;;; compact path is therefore reserved for structurally malformed messages
;;;; (READ_STATUS_INVALID), and an unknown-parent compact block is answered
;;;; with getheaders before any scoring can happen (:4571-4577).
;;;;
;;;; %WITH-REGTEST (mining-tests.lisp, loaded earlier) binds *network* and the
;;;; active PoW limit so #x207fffff is a legal target -- without it
;;;; derive-target rejects these fixture headers and every test would stop at
;;;; :BAD-PROOF-OF-WORK instead of the check it is about.
;;;; ====================================================================

(defun %cbp-capture-sends (thunk)
  "Call THUNK with SEND-MESSAGE replaced by a recorder; return the list of
message command strings it sent, in order. Restores the real definition under
UNWIND-PROTECT. Needed because a test peer owns no socket, so the production
SEND-MESSAGE silently drops everything and would assert nothing."
  (let ((sent '())
        (real (fdefinition 'bl.net:send-message)))
    (unwind-protect
         (progn
           (setf (fdefinition 'bl.net:send-message)
                 (lambda (peer bytes)
                   (declare (ignore peer))
                   (push (bl.ser:bytes-to-command
                          (subseq bytes 4 16))
                         sent)
                   t))
           (funcall thunk))
      (setf (fdefinition 'bl.net:send-message) real))
    (nreverse sent)))

(defun %cbp-peer (address)
  "A ready, compact-block-v2 peer at ADDRESS. Each punishment test uses its own
address: the discourage filter is a process-global rolling set."
  (let ((p (bl.net:make-peer :state :ready :address address)))
    (setf (bl.net:peer-compact-block-version p) 2)
    p))

(defun %cbp-hash (byte)
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element byte))

(defun %cbp-header (prev-hash timestamp)
  "A regtest-difficulty header on PREV-HASH. Version 4 clears the BIP34/66/65
gates (BIP34 is active from height 1 on regtest), so the checks under test are
never pre-empted by :BAD-VERSION. Call inside %WITH-REGTEST."
  (bl.ser:make-block-header
   :version 4
   :prev-block prev-hash
   :merkle-root (%cbp-hash 0)
   :timestamp timestamp
   :bits #x207fffff
   :nonce 0))

(defun %cbp-grind (header)
  "Find a nonce that satisfies HEADER's own bits. The regtest pow-limit target
passes roughly half of all nonces, so a fixed nonce would flake ~50% of runs on
:BAD-PROOF-OF-WORK instead of reaching the check under test. Returns HEADER."
  (loop for nonce from 0 below 500
        do (setf (bl.ser:block-header-nonce header) nonce
                 (bl.ser:block-header-cached-hash header) nil)
        when (bl.val:check-proof-of-work header)
          do (return header)
        finally (return header)))

(defun %cbp-payload (compact-block)
  (bl.bytes:with-byte-buf (s)
    (bl.ser:write-compact-block s compact-block)))

(defun %cbp-state-with-parent (parent-hash parent-timestamp &key (status :valid))
  "A chain-state holding only PARENT-HASH at height 0, with a real header (the
MTP walk and the difficulty check both dereference it). BEST-BLOCK-HASH stays
NIL so ACCEPT-DOWNLOADED-BLOCK takes its side-branch path, which is the one
that consults the parent index entry. STATUS :INVALID makes the parent a block
we rejected — Core's BLOCK_INVALID_PREV."
  (let ((state (bl.store:make-chain-state)))
    (bl.store:add-block-index-entry
     state (bl.store:make-block-index-entry
            :hash parent-hash :height 0 :chain-work 1 :status status
            :header (%cbp-header (%cbp-hash 0) parent-timestamp)))
    state))

(defun %cbp-one-tx-compact-block-with-header (header prefilled-index tx)
  "A compact block carrying HEADER, exactly one prefilled transaction and no
short IDs, so tx-count is 1. PREFILLED-INDEX 0 reconstructs; anything else is
out of bounds and is Core's READ_STATUS_INVALID."
  (bl.ser:make-compact-block
   :header header
   :nonce 7
   :short-ids '()
   :prefilled-txs (list (bl.ser:make-prefilled-tx
                         :index prefilled-index :transaction tx))))

(defun %cbp-one-tx-compact-block (prev-hash prefilled-index tx)
  "As above, on a mined regtest header extending PREV-HASH."
  (%cbp-one-tx-compact-block-with-header
   (%cbp-grind (%cbp-header prev-hash 1296688700)) prefilled-index tx))

(defun %cbp-count-shortid-passes (thunk)
  "Call THUNK with BUILD-SHORTID-MAP counted; return (VALUES result count).
BUILD-SHORTID-MAP SipHashes EVERY mempool entry under a key derived from the
announced header, so it is the per-message cost an unpunished attacker buys.
The real definition still runs, so nothing downstream is disturbed."
  (let ((calls 0)
        (real (fdefinition 'bl.net::build-shortid-map)))
    (unwind-protect
         (progn
           (setf (fdefinition 'bl.net::build-shortid-map)
                 (lambda (&rest args) (incf calls) (apply real args)))
           (let ((result (funcall thunk)))
             (values result calls)))
      (setf (fdefinition 'bl.net::build-shortid-map) real))))

(test cmpctblock-unknown-parent-asks-for-headers-and-never-punishes
  "GA8 W4 (the finding). A cmpctblock whose PARENT is not in the block index
must produce a getheaders and nothing else -- no reconstruction, no validation,
no discouragement.

NO ATTACKER IS NEEDED to reach this shape. BIP152 high-bandwidth relay outruns
headers announcements by design, so with tip = N-1 and block N still inside a
getblocktxn round-trip, an HB peer's cmpctblock(N+1) arrives while N is absent
from the index. Before this fix reconstruction ran anyway, ACCEPT-DOWNLOADED-
BLOCK returned :ORPHAN-BLOCK (no parent entry => no branch height, no difficulty
context), and RECORD-MISBEHAVIOR -- which is binary and immediate -- discouraged
the address and dropped the connection, permanently exiling our FASTEST honest
block-relay peer. Core answers this shape with MaybeSendGetHeaders and an early
return, before anything can be scored (net_processing.cpp:4571-4577); its
BLOCK_MISSING_PREV punishment (:1938-1944) is unreachable via the compact path."
  (with-network (:regtest)
   (let* ((bl.net:*cached-is-ibd* nil)
          (addr "203.0.113.41")
          (peer (%cbp-peer addr))
          (state (bl.store:make-chain-state))
          (utxo (bl.store:make-utxo-set))
          (cb (%cbp-one-tx-compact-block (%cbp-hash #xAA) 0 (make-simple-tx #x11)))
          (sent (%cbp-capture-sends
                 (lambda ()
                   (bl.net::handle-cmpctblock peer (%cbp-payload cb) (bl.ctx:make-node-context :chain-state state :utxo-set utxo :mempool (bl.mp:make-mempool)))))))
     (is (equal '("getheaders") sent)
         "unknown-parent cmpctblock must send exactly one getheaders, sent: ~S" sent)
     (is-false (bl.net:peer-discouraged-p addr)
               "an honest peer relaying ahead of our headers must not be discouraged")
     (is (eq :ready (bl.net:peer-state peer))))))

(test cmpctblock-unknown-parent-sends-no-getheaders-during-ibd
  "GA8 W4. Core gates the unknown-parent getheaders on
!IsInitialBlockDownload() (net_processing.cpp:4572-4574) — during IBD the
header sync owns the locator and an unsolicited getheaders per stray
cmpctblock is pure noise. The early return, and the absence of punishment,
still hold. Without this test the IBD gate is an unasserted clause: the
unknown-parent test above pins *cached-is-ibd* to NIL and cannot distinguish a
gated getheaders from an ungated one."
  (with-network (:regtest)
   (let* ((bl.net:*cached-is-ibd* t)
          (addr "203.0.113.47")
          (peer (%cbp-peer addr))
          ;; No tip at all ⇒ initial-block-download-p stays latched at T.
          (state (bl.store:make-chain-state))
          (utxo (bl.store:make-utxo-set))
          (cb (%cbp-one-tx-compact-block (%cbp-hash #xAB) 0 (make-simple-tx #x14)))
          (sent (%cbp-capture-sends
                 (lambda ()
                   (bl.net::handle-cmpctblock peer (%cbp-payload cb) (bl.ctx:make-node-context :chain-state state :utxo-set utxo :mempool (bl.mp:make-mempool)))))))
     (is-true bl.net:*cached-is-ibd*
              "fixture must still be in IBD or this test asserts nothing")
     (is (null sent)
         "no getheaders may be sent for an unknown-parent cmpctblock during IBD, sent: ~S"
         sent)
     (is-false (bl.net:peer-discouraged-p addr))
     (is (eq :ready (bl.net:peer-state peer))))))

(test cmpctblock-invalid-reconstruction-refetches-instead-of-discouraging
  "GA8 W4. When the parent IS known and reconstruction succeeds but the block
fails validation, fall back to a full-block getdata -- never discourage.

BIP152 lets a peer relay a compact block having validated only the header, so
Core records the source with via_compact_block=true and MaybePunishNodeForBlock
then skips BLOCK_CONSENSUS / BLOCK_MUTATED outright (net_processing.cpp:
1920-1926). The refetch mirrors what Core does one layer down for the same
shape: a reconstruction that yields a mutated block is READ_STATUS_FAILED, and
Core answers that with a plain getdata (:4683-4694). If the block really is
bad, the full copy arrives on the BLOCK path where punishment is correct.

Doubles as the anti-vacuity control for the unknown-parent test above: the
parent guard must be narrow enough that a KNOWN parent still reaches
reconstruction -- otherwise this test would see a getheaders here."
  (with-network (:regtest)
   (let* ((bl.net:*cached-is-ibd* nil)
          (bl.net::*compact-block-success-count* 0)
          (bl.net::*compact-block-failure-count* 0)
          (addr "203.0.113.42")
          (peer (%cbp-peer addr))
          (parent (%cbp-hash #xA1))
          (state (%cbp-state-with-parent parent 1296688600))
          (utxo (bl.store:make-utxo-set))
          ;; The single prefilled transaction is NOT a coinbase: reconstruction
          ;; succeeds, then validate-block rejects with :FIRST-TX-NOT-COINBASE.
          (cb (%cbp-one-tx-compact-block parent 0 (make-simple-tx #x12)))
          (sent (%cbp-capture-sends
                 (lambda ()
                   (bl.net::handle-cmpctblock peer (%cbp-payload cb) (bl.ctx:make-node-context :chain-state state :utxo-set utxo :mempool (bl.mp:make-mempool)))))))
     (is (= 1 bl.net::*compact-block-success-count*)
         "the compact block must have been reconstructed (parent guard too broad?)")
     (is (equal '("getdata") sent)
         "an invalid reconstruction must be refetched in full, sent: ~S" sent)
     (is (= 1 bl.net::*compact-block-failure-count*))
     (is-false (bl.net:peer-discouraged-p addr)
               "a compact block that fails validation must not discourage its sender")
     (is (eq :ready (bl.net:peer-state peer))))))

(test cmpctblock-structurally-malformed-still-punishes
  "GA8 W4 control: removing the punishment for INVALID blocks must not remove
the punishment for INVALID MESSAGES. A prefilled transaction whose index lies
outside the block is Core's READ_STATUS_INVALID (blockencodings.cpp:78-84),
which net_processing answers with Misbehaving (:4679-4683) -- no honest peer can
produce it. Before this change our reconstruction reported it as :COLLISION,
i.e. the same value as an innocent short-ID clash in our own mempool, so it got
a polite full-block getdata instead."
  (with-network (:regtest)
   (let* ((bl.net:*cached-is-ibd* nil)
          (addr "203.0.113.43")
          (peer (%cbp-peer addr))
          (parent (%cbp-hash #xA2))
          (state (%cbp-state-with-parent parent 1296688600))
          (utxo (bl.store:make-utxo-set))
          ;; tx-count = 1 (one prefilled, no short IDs), prefilled index 3.
          (cb (%cbp-one-tx-compact-block parent 3 (make-simple-tx #x13)))
          (sent (%cbp-capture-sends
                 (lambda ()
                   (bl.net::handle-cmpctblock peer (%cbp-payload cb) (bl.ctx:make-node-context :chain-state state :utxo-set utxo :mempool (bl.mp:make-mempool)))))))
     (is-true (bl.net:peer-discouraged-p addr)
              "a structurally malformed cmpctblock must still discourage the sender")
     (is (eq :disconnected (bl.net:peer-state peer)))
     (is (null sent)
         "a malformed message must not earn a full-block refetch, sent: ~S" sent))))

(test blocktxn-invalid-completed-block-refetches-instead-of-discouraging
  "GA8 W4. The blocktxn half of the same rule: a completed reconstruction that
fails validation is still a compact-block delivery (Core emplaces mapBlockSource
with /*punish=*/false at net_processing.cpp:3516, and says so in the comment
right above it), so it gets a full-block refetch, not a discouragement."
  (with-network (:regtest)
   (let* ((addr "203.0.113.44")
          (peer (%cbp-peer addr))
          (block-hash (%cbp-hash #xB1))
          (state (bl.store:make-chain-state))
          (utxo (bl.store:make-utxo-set)))
     (setf (bl.net:peer-pending-compact-block peer)
           (bl.net:make-pending-compact-block
            :block-hash block-hash
            ;; Parent unknown => ACCEPT-DOWNLOADED-BLOCK returns :ORPHAN-BLOCK,
            ;; which is precisely the verdict that used to exile the peer.
            :header (%cbp-grind (%cbp-header (%cbp-hash #xBB) 1296688700))
            :transactions (make-array 1 :initial-element nil)
            :missing-indexes '(0)
            :request-time (get-internal-real-time)
            :use-wtxid t))
     (let ((sent (%cbp-capture-sends
                  (lambda ()
                    (bl.net::handle-blocktxn peer (subseq (bl.ser:make-blocktxn-message
                              block-hash (list (make-simple-tx #x21)))
                             24) (bl.ctx:make-node-context :chain-state state :utxo-set utxo :mempool (bl.mp:make-mempool)))))))
       (is (equal '("getdata") sent)
           "an invalid completed block must be refetched in full, sent: ~S" sent)
       (is-false (bl.net:peer-discouraged-p addr)
                 "a completed compact block that fails validation must not discourage")
       (is (eq :ready (bl.net:peer-state peer)))))))

(test blocktxn-non-matching-transaction-count-punishes
  "GA8 W4 control for the blocktxn side: a blocktxn that does not answer the
getblocktxn we sent is structurally malformed -- Core's FillBlock returns
READ_STATUS_INVALID for both too few and too many transactions
(blockencodings.cpp:198-217) and Misbehaves (net_processing.cpp:3487-3491).
Previously we treated it as a mere reconstruction miss and sent a getdata."
  (with-network (:regtest)
   (let* ((addr "203.0.113.45")
          (peer (%cbp-peer addr))
          (block-hash (%cbp-hash #xB2))
          (state (bl.store:make-chain-state))
          (utxo (bl.store:make-utxo-set)))
     (setf (bl.net:peer-pending-compact-block peer)
           (bl.net:make-pending-compact-block
            :block-hash block-hash
            :header (%cbp-grind (%cbp-header (%cbp-hash #xBC) 1296688700))
            :transactions (make-array 2 :initial-element nil)
            :missing-indexes '(0 1)          ; we asked for TWO
            :request-time (get-internal-real-time)
            :use-wtxid t))
     (let ((sent (%cbp-capture-sends
                  (lambda ()
                    (bl.net::handle-blocktxn peer (subseq (bl.ser:make-blocktxn-message
                              block-hash (list (make-simple-tx #x22)))  ; got ONE
                             24) (bl.ctx:make-node-context :chain-state state :utxo-set utxo :mempool (bl.mp:make-mempool)))))))
       (is-true (bl.net:peer-discouraged-p addr)
                "a non-matching blocktxn must discourage the sender")
       (is (eq :disconnected (bl.net:peer-state peer)))
       (is (null (bl.net:peer-pending-compact-block peer)))
       (is (null sent)
           "a malformed blocktxn must not earn a full-block refetch, sent: ~S" sent)))))

(test handle-block-still-punishes-orphan-block
  "CORE PARITY CONTROL -- must be unchanged by the compact-block work. A block
arriving on the BLOCK message path is recorded with via_compact_block=false
(mapBlockSource emplaced /*punish=*/true, net_processing.cpp:4893), so
MaybePunishNodeForBlock DOES punish BLOCK_MISSING_PREV (:1938-1944). This is
the asymmetry the fix depends on: the full-block refetch that now replaces
compact-block punishment still ends in punishment when the block is genuinely
bad. This test passes both before and after the fix; it is a regression guard,
not mutation evidence."
  (with-network (:regtest)
   (let* ((addr "203.0.113.46")
          (peer (%cbp-peer addr))
          (state (bl.store:make-chain-state))
          (utxo (bl.store:make-utxo-set))
          (blk (bl.ser:make-bitcoin-block
                :header (%cbp-grind (%cbp-header (%cbp-hash #xCC) 1296688700))
                :transactions (list (make-simple-tx #x31)))))
     (bl.net::handle-block peer (subseq (bl.ser:make-block-message blk) 24) (bl.ctx:make-node-context :chain-state state :utxo-set utxo))
     (is-true (bl.net:peer-discouraged-p addr)
              "the BLOCK path must keep punishing :ORPHAN-BLOCK (Core parity)")
     (is (eq :disconnected (bl.net:peer-state peer))))))

;;;; ====================================================================
;;;; Per-reason punishment on the compact path (GA8 W4, review finding)
;;;;
;;;; Core's MaybePunishNodeForBlock is a SWITCH, and via_compact_block exempts
;;;; three of its seven arms (net_processing.cpp:1908-1950): BLOCK_CONSENSUS,
;;;; BLOCK_MUTATED and — conditionally — BLOCK_CACHED_INVALID. BLOCK_INVALID_
;;;; HEADER, BLOCK_INVALID_PREV and BLOCK_MISSING_PREV call Misbehaving
;;;; unconditionally (:1936-1945), and the compact path reaches them: the
;;;; cmpctblock handler runs the announced header through ProcessNewBlockHeaders
;;;; (:4589) and punishes the result with via_compact_block=true (:4591).
;;;;
;;;; The first cut of this PR replaced punishment with a getdata for EVERY
;;;; non-valid verdict. Measured regression, same input as the tests below:
;;;;   origin/main    -> sent=NIL          discouraged=T   state=:DISCONNECTED
;;;;   over-broad fix -> sent=("getdata")  discouraged=NIL state=:READY
;;;; Nothing downstream scores a compact block, so that peer replays forever on
;;;; one connection, each message costing a full BUILD-SHORTID-MAP pass.
;;;; ====================================================================

(defun %cbp-bad-pow-header (prev-hash)
  "The reviewer's probe header verbatim: regtest chain, bits #x1d00ffff. That
target is far BELOW the regtest pow limit, so DERIVE-TARGET accepts the bits and
the hash then misses the target with overwhelming probability — Core's high-hash,
BLOCK_INVALID_HEADER (validation.cpp:3864). Each test asserts the miss."
  (let ((h (%cbp-header prev-hash 1296688700)))
    (setf (bl.ser:block-header-bits h) #x1d00ffff
          (bl.ser:block-header-cached-hash h) nil)
    h))

(test cmpctblock-invalid-header-punishes-and-never-hashes-the-mempool
  "GA8 W4 blocker. A cmpctblock whose HEADER fails proof of work, announced on a
parent we DO have, must discourage and disconnect its sender — through the
compact path, exactly as Core does at net_processing.cpp:4589-4591 — and must
not earn a getdata.

Also pins the DoS property the over-broad fix created: five such messages on ONE
connection must cost ZERO BUILD-SHORTID-MAP passes. That pass SipHashes every
mempool entry under a key derived from the attacker's own header+nonce, so it
must happen only after the header is known good. The valid-header control at the
end proves the counter is wired to something real (it goes to exactly 1)."
  (with-network (:regtest)
   (let* ((bl.net:*cached-is-ibd* nil)
          (bl.net::*compact-block-success-count* 0)
          (bl.net::*compact-block-failure-count* 0)
          (addr "203.0.113.48")
          (peer (%cbp-peer addr))
          (parent (%cbp-hash #xA4))
          (state (%cbp-state-with-parent parent 1296688600))
          (utxo (bl.store:make-utxo-set))
          (mempool (bl.mp:make-mempool))
          (hdr (%cbp-bad-pow-header parent))
          (cb (%cbp-one-tx-compact-block-with-header hdr 0 (make-simple-tx #x41)))
          (payload (%cbp-payload cb)))
     (is-false (bl.val:check-proof-of-work hdr)
               "fixture must actually fail PoW or this test asserts nothing")
     (multiple-value-bind (sent passes)
         (%cbp-count-shortid-passes
          (lambda ()
            (%cbp-capture-sends
             (lambda ()
               (dotimes (i 5)
                 (bl.net::handle-cmpctblock peer payload (bl.ctx:make-node-context :chain-state state :utxo-set utxo :mempool mempool)))))))
       (is-true (bl.net:peer-discouraged-p addr)
                "an invalid-PoW cmpctblock header must discourage its sender (Core BLOCK_INVALID_HEADER)")
       (is (eq :disconnected (bl.net:peer-state peer)))
       (is (null sent)
           "an invalid header must not earn a getdata or a getheaders, sent: ~S" sent)
       (is (zerop passes)
           "5 replays hashed the mempool ~D times; an invalid header must be rejected before BUILD-SHORTID-MAP"
           passes)
       (is (zerop bl.net::*compact-block-success-count*)
           "no reconstruction may be attempted for a header we reject"))
     ;; Control: the counter seam is real. A well-formed header on the same
     ;; parent DOES reach reconstruction, hashing the mempool exactly once.
     (let ((ok-peer (%cbp-peer "203.0.113.49"))
           (ok-cb (%cbp-one-tx-compact-block parent 0 (make-simple-tx #x42))))
       (multiple-value-bind (sent passes)
           (%cbp-count-shortid-passes
            (lambda ()
              (%cbp-capture-sends
               (lambda ()
                 (bl.net::handle-cmpctblock ok-peer (%cbp-payload ok-cb) (bl.ctx:make-node-context :chain-state state :utxo-set utxo :mempool mempool))))))
         (is (= 1 passes)
             "control: a valid header must still reach BUILD-SHORTID-MAP, passes: ~D" passes)
         (is (equal '("getdata") sent)
             "control: a consensus-invalid reconstruction is still refetched, sent: ~S" sent)
         (is-false (bl.net:peer-discouraged-p "203.0.113.49")
                   "control: the honest-peer exemption must survive this fix"))))))

(test cmpctblock-stale-timestamp-header-punishes
  "GA8 W4. :BAD-PROOF-OF-WORK is not the only BLOCK_INVALID_HEADER arm, and a
fix that special-cased PoW would be a different bug. A timestamp at or below the
median-time-past is Core's time-too-old (validation.cpp:4125): same arm, same
unconditional Misbehaving. The header's PoW is mined, so nothing pre-empts it."
  (with-network (:regtest)
   (let* ((bl.net:*cached-is-ibd* nil)
          (addr "203.0.113.50")
          (peer (%cbp-peer addr))
          (parent (%cbp-hash #xA5))
          ;; The parent's timestamp is the whole MTP window here, so a header
          ;; timestamped 1296688500 is <= MTP.
          (state (%cbp-state-with-parent parent 1296688600))
          (utxo (bl.store:make-utxo-set))
          (hdr (%cbp-grind (%cbp-header parent 1296688500)))
          (cb (%cbp-one-tx-compact-block-with-header hdr 0 (make-simple-tx #x43))))
     (is-true (bl.val:check-proof-of-work hdr)
              "fixture must pass PoW or it would test the wrong arm")
     (multiple-value-bind (sent passes)
         (%cbp-count-shortid-passes
          (lambda ()
            (%cbp-capture-sends
             (lambda ()
               (bl.net::handle-cmpctblock peer (%cbp-payload cb) (bl.ctx:make-node-context :chain-state state :utxo-set utxo :mempool (bl.mp:make-mempool)))))))
       (is-true (bl.net:peer-discouraged-p addr)
                "a time-too-old cmpctblock header must discourage its sender")
       (is (eq :disconnected (bl.net:peer-state peer)))
       (is (null sent) "sent: ~S" sent)
       (is (zerop passes) "passes: ~D" passes)))))

(test cmpctblock-header-on-invalid-parent-punishes
  "GA8 W4. BLOCK_INVALID_PREV: a header building on a block we already rejected
is Core's bad-prevblk (validation.cpp:4251-4255), the arm right beside
BLOCK_INVALID_HEADER and equally exempt from the via_compact_block amnesty."
  (with-network (:regtest)
   (let* ((bl.net:*cached-is-ibd* nil)
          (addr "203.0.113.51")
          (peer (%cbp-peer addr))
          (parent (%cbp-hash #xA6))
          (state (%cbp-state-with-parent parent 1296688600 :status :invalid))
          (utxo (bl.store:make-utxo-set))
          (cb (%cbp-one-tx-compact-block parent 0 (make-simple-tx #x44))))
     (multiple-value-bind (sent passes)
         (%cbp-count-shortid-passes
          (lambda ()
            (%cbp-capture-sends
             (lambda ()
               (bl.net::handle-cmpctblock peer (%cbp-payload cb) (bl.ctx:make-node-context :chain-state state :utxo-set utxo :mempool (bl.mp:make-mempool)))))))
       (is-true (bl.net:peer-discouraged-p addr)
                "a cmpctblock extending a known-invalid block must discourage its sender")
       (is (eq :disconnected (bl.net:peer-state peer)))
       (is (null sent) "sent: ~S" sent)
       (is (zerop passes) "passes: ~D" passes)))))

(test cmpctblock-future-timestamp-header-is-neither-punished-nor-refetched
  "GA8 W4 control in the OTHER direction: restoring header punishment must not
punish every header-level verdict. A timestamp too far ahead is BLOCK_TIME_FUTURE
(validation.cpp:4141), whose MaybePunishNodeForBlock arm is a bare break
(net_processing.cpp:1946-1947) — no discouragement. Nor may it be refetched: a
getdata would deliver the same block on the BLOCK path, where HANDLE-BLOCK
punishes unconditionally, converting Core's no-op into an exile one message
later."
  (with-network (:regtest)
   (let* ((bl.net:*cached-is-ibd* nil)
          (addr "203.0.113.52")
          (peer (%cbp-peer addr))
          (parent (%cbp-hash #xA7))
          (state (%cbp-state-with-parent parent 1296688600))
          (utxo (bl.store:make-utxo-set))
          ;; +3h: past Core's MAX_FUTURE_BLOCK_TIME of 2h.
          (hdr (%cbp-grind (%cbp-header parent (+ (bl.ser:get-unix-time)
                                                  10800))))
          (cb (%cbp-one-tx-compact-block-with-header hdr 0 (make-simple-tx #x45))))
     (is-true (bl.val:check-proof-of-work hdr)
              "fixture must pass PoW or it would test the wrong arm")
     (multiple-value-bind (sent passes)
         (%cbp-count-shortid-passes
          (lambda ()
            (%cbp-capture-sends
             (lambda ()
               (bl.net::handle-cmpctblock peer (%cbp-payload cb) (bl.ctx:make-node-context :chain-state state :utxo-set utxo :mempool (bl.mp:make-mempool)))))))
       (is-false (bl.net:peer-discouraged-p addr)
                 "BLOCK_TIME_FUTURE must not discourage (our clock, not their fault)")
       (is (eq :ready (bl.net:peer-state peer)))
       (is (null sent)
           "a future-timestamped block must not be refetched either, sent: ~S" sent)
       (is (zerop passes) "passes: ~D" passes)))))

(test cmpctblock-known-invalid-block-is-dropped-without-punishment
  "GA8 W4. BLOCK_CACHED_INVALID: a compact block for a hash we already marked
invalid. Core exempts it whenever via_compact_block is true
(net_processing.cpp:1926-1935), so no discouragement — and no refetch, since
re-downloading a block we have already rejected is a self-inflicted DoS. Core
reaches it inside AcceptBlockHeader (validation.cpp:4229-4237), i.e. after the
handler's own parent lookup and anti-DoS work floor, which is where our verdict
checks it too."
  (with-network (:regtest)
   (let* ((bl.net:*cached-is-ibd* nil)
          (addr "203.0.113.53")
          (peer (%cbp-peer addr))
          (parent (%cbp-hash #xA8))
          (state (%cbp-state-with-parent parent 1296688600))
          (utxo (bl.store:make-utxo-set))
          (cb (%cbp-one-tx-compact-block parent 0 (make-simple-tx #x46)))
          (block-hash (bl.ser:block-header-hash
                       (bl.ser:compact-block-header cb))))
     (bl.store:add-block-index-entry
      state (bl.store:make-block-index-entry
             :hash block-hash :height 1 :chain-work 2 :status :invalid
             :header (bl.ser:compact-block-header cb)))
     (multiple-value-bind (sent passes)
         (%cbp-count-shortid-passes
          (lambda ()
            (%cbp-capture-sends
             (lambda ()
               (bl.net::handle-cmpctblock peer (%cbp-payload cb) (bl.ctx:make-node-context :chain-state state :utxo-set utxo :mempool (bl.mp:make-mempool)))))))
       (is-false (bl.net:peer-discouraged-p addr)
                 "BLOCK_CACHED_INVALID is exempt for compact-block senders")
       (is (eq :ready (bl.net:peer-state peer)))
       (is (null sent)
           "a block we already rejected must not be re-requested, sent: ~S" sent)
       (is (zerop passes) "passes: ~D" passes)))))

;;;; =============================================================
;;;; The cmpctblock admission gates Core runs before the mempool (GA10 S1)
;;;;
;;;; Core's handler order (net_processing.cpp:4569-4593) is: look the PARENT
;;;; up, apply GetAntiDoSWorkThreshold to
;;;; `prev_block->nChainWork + GetBlockProof(header)', THEN call
;;;; ProcessNewBlockHeaders -- which validates the header and, on success,
;;;; AddToBlockIndex'es it. We had neither the work floor nor the index write,
;;;; so a header ground at the minimum target reached BUILD-SHORTID-MAP and
;;;; stayed unknown across every replay.
;;;; =============================================================

(defun %cbp-compact-block-missing-one (header prefilled-tx)
  "A compact block on HEADER with PREFILLED-TX at index 0 and one short ID at
index 1 that no mempool entry can match (the test mempools below are empty).
Reconstruction returns missing index (1), which is the shape that sends a
getblocktxn and leaves a pending reconstruction behind — our counterpart of
Core's `already_in_flight' state for this peer."
  (bl.ser:make-compact-block
   :header header
   :nonce 7
   :short-ids (list #x112233445566)
   :prefilled-txs (list (bl.ser:make-prefilled-tx
                         :index 0 :transaction prefilled-tx))))

(defun %cbp-deliver (peer payload state utxo mempool)
  "One cmpctblock delivery, on the node context the tests in this section build
from the same four pieces every time."
  (bl.net::handle-cmpctblock
   peer payload
   (bl.ctx:make-node-context :chain-state state :utxo-set utxo
                            :mempool mempool)))

(test cmpctblock-low-work-header-is-ignored-before-the-mempool
  "GA10 S1. Core ignores a compact block whose announced chain misses the
anti-DoS work floor — `prev_block->nChainWork + GetBlockProof(cmpctblock.header)
< GetAntiDoSWorkThreshold()' (net_processing.cpp:4578-4582) — outright, before
ProcessNewBlockHeaders and long before the mempool.

We had no such floor anywhere on the compact path. A header ground at the
network's MINIMUM target, which costs its sender nothing, reached
BUILD-SHORTID-MAP: a SipHash of every mempool entry under a key derived from the
attacker's own header and nonce. Roughly 100 bytes of message, repeatable
without limit, with no misbehaviour score anywhere along it.

The control is the SAME message with the floor back at regtest's real value of
zero: it must reach the mempool exactly once, so a green run cannot come from a
fixture that never reconstructs anything."
  (with-network (:regtest)
   (let* ((bl.net:*cached-is-ibd* nil)
          (addr "203.0.113.60")
          (parent (%cbp-hash #xB1))
          (state (%cbp-state-with-parent parent 1296688600))
          (utxo (bl.store:make-utxo-set))
          (mempool (bl.mp:make-mempool))
          (cb (%cbp-one-tx-compact-block parent 0 (make-simple-tx #x51)))
          (payload (%cbp-payload cb))
          (block-hash (bl.ser:block-header-hash
                       (bl.ser:compact-block-header cb))))
     ;; A floor no synthetic regtest header can clear. Same shape as a live
     ;; node's, where the threshold is max(nMinimumChainWork, tip work minus
     ;; 144 tip proofs) and every mainnet/testnet header is far below it.
     (let ((bl:*minimum-chain-work-override* (expt 2 240))
           (peer (%cbp-peer addr)))
       (is (< (bl.store:calculate-chain-work
               (bl.ser:block-header-bits (bl.ser:compact-block-header cb))
               1)
              (bl.net::anti-dos-work-threshold state))
           "fixture must sit below the floor or this test asserts nothing")
       (multiple-value-bind (sent passes)
           (%cbp-count-shortid-passes
            (lambda ()
              (%cbp-capture-sends
               (lambda ()
                 (dotimes (i 5)
                   (%cbp-deliver peer payload state utxo mempool))))))
         (is (zerop passes)
             "5 low-work cmpctblocks hashed the mempool ~D time(s); the floor must be applied first"
             passes)
         (is (null sent)
             "a low-work compact block must not earn a message either, sent: ~S" sent)
         (is-false (bl.store:get-block-index-entry state block-hash)
                   "a header below the floor must not enter the block index")
         (is-false (bl.net:peer-discouraged-p addr)
                   "Core logs and returns: a peer far behind us relays low-work blocks honestly")
         (is (eq :ready (bl.net:peer-state peer)))))
     ;; Control: with regtest's real floor (0) the identical message IS
     ;; admitted and reaches the mempool exactly once.
     (let ((peer (%cbp-peer "203.0.113.61")))
       (multiple-value-bind (sent passes)
           (%cbp-count-shortid-passes
            (lambda ()
              (%cbp-capture-sends
               (lambda ()
                 (%cbp-deliver peer payload state utxo mempool)))))
         (declare (ignore sent))
         (is (= 1 passes)
             "control: with the floor at zero the same header must reach the mempool, passes: ~D"
             passes))))))

(test cmpctblock-indexes-the-announced-header-and-drops-the-replay
  "GA10 S1, the other half. Core's handler calls
ProcessNewBlockHeaders({{cmpctblock.header}}) (net_processing.cpp:4590), whose
AcceptBlockHeader ends in AddToBlockIndex — so the announced header is in the
index from the FIRST message on and every later copy is answered by the
already-known gates.

We never inserted it. `known' stayed NIL for an unseen header however many times
it arrived, which made the whole :ALREADY-HAVE arm unreachable on this path, and
each copy re-ran the header battery and then BUILD-SHORTID-MAP over the entire
mempool.

The replay pinned here is the one that survives the index write as well: a
header that beats our tip and whose body never arrived comes back through the
:ACCEPT arm, and Core drops it at \"Peer sent us compact block we were already
syncing!\" (:4670) because the peer already has that reconstruction in flight.

Both controls are inside the assertions: the first message must index the header
AND reach the mempool exactly once, so neither the index check nor the pass
count can pass on a fixture that does nothing."
  (with-network (:regtest)
   (let* ((bl.net:*cached-is-ibd* nil)
          (peer (%cbp-peer "203.0.113.62"))
          (parent (%cbp-hash #xB2))
          (state (%cbp-state-with-parent parent 1296688600))
          (utxo (bl.store:make-utxo-set))
          (mempool (bl.mp:make-mempool))
          (hdr (%cbp-grind (%cbp-header parent 1296688700)))
          (cb (%cbp-compact-block-missing-one hdr (make-simple-tx #x52)))
          (payload (%cbp-payload cb))
          (block-hash (bl.ser:block-header-hash hdr)))
     (is-true (bl.val:check-proof-of-work hdr)
              "fixture must pass PoW or it would test the wrong arm")
     (multiple-value-bind (sent passes)
         (%cbp-count-shortid-passes
          (lambda ()
            (%cbp-capture-sends
             (lambda ()
               (dotimes (i 5)
                 (%cbp-deliver peer payload state utxo mempool))))))
       (let ((entry (bl.store:get-block-index-entry state block-hash)))
         (is-true entry
                  "the announced header must be in the block index after the first cmpctblock")
         (when entry
           (is (eq :header-valid (bl.store:block-index-entry-status entry))
               "an announced header enters the index header-valid, not as a block we hold")
           (is (= 1 (bl.store:block-index-entry-height entry)))))
       (is (= 1 passes)
           "5 copies of one cmpctblock hashed the mempool ~D time(s); only the first may"
           passes)
       (is (equal '("getblocktxn") sent)
           "only the first copy may ask for the missing transactions, sent: ~S" sent)
       (is-false (bl.net:peer-discouraged-p "203.0.113.62")
                 "a replayed compact block is not a fault Core scores")
       (is (eq :ready (bl.net:peer-state peer)))))))

(test cmpctblock-invalid-header-is-punished-and-never-indexed
  "The risk the index write creates: the announced header may be inserted only
AFTER it passes the header battery. Core's order is exactly that —
AcceptBlockHeader inserts at its end, after CheckBlockHeader and
ContextualCheckBlockHeader, and returns without an insertion when either fails
(validation.cpp:4239-4259).

So a bad-PoW header must still discourage its sender (MaybePunishNodeForBlock at
net_processing.cpp:4589-4593, BLOCK_INVALID_HEADER, which via_compact_block does
not excuse) and must leave the index untouched: a peer able to plant index
entries by announcing junk headers would have traded a bounded mempool pass for
unbounded memory.

The control is a valid header on the same parent, which IS indexed — without it
the absence above could be a lookup that never had anything to find."
  (with-network (:regtest)
   (let* ((bl.net:*cached-is-ibd* nil)
          (addr "203.0.113.63")
          (peer (%cbp-peer addr))
          (parent (%cbp-hash #xB3))
          (state (%cbp-state-with-parent parent 1296688600))
          (utxo (bl.store:make-utxo-set))
          (mempool (bl.mp:make-mempool))
          (bad (%cbp-bad-pow-header parent))
          (bad-cb (%cbp-one-tx-compact-block-with-header
                   bad 0 (make-simple-tx #x53)))
          (good-cb (%cbp-one-tx-compact-block parent 0 (make-simple-tx #x54))))
     (is-false (bl.val:check-proof-of-work bad)
               "fixture must actually fail PoW or this test asserts nothing")
     (%cbp-capture-sends
      (lambda ()
        (%cbp-deliver peer (%cbp-payload bad-cb) state utxo mempool)))
     (is-true (bl.net:peer-discouraged-p addr)
              "an invalid-PoW cmpctblock header must still discourage its sender")
     (is-false (bl.store:get-block-index-entry
                state (bl.ser:block-header-hash bad))
               "a header we reject must never reach the block index")
     ;; Control: the accepted header on the same parent IS indexed, so the
     ;; assertion above is a verdict and not an empty index.
     (let ((ok-peer (%cbp-peer "203.0.113.64")))
       (%cbp-capture-sends
        (lambda ()
          (%cbp-deliver ok-peer (%cbp-payload good-cb) state utxo mempool)))
       (is-true (bl.store:get-block-index-entry
                 state (bl.ser:block-header-hash
                        (bl.ser:compact-block-header good-cb)))
                "control: an accepted header must be indexed")))))

(test compact-block-failure-action-matches-core-arms
  "GA8 W4. The mapping table itself, arm by arm against MaybePunishNodeForBlock
with via_compact_block=true (net_processing.cpp:1908-1950). Both handlers are
thin wrappers over this, so a wrong entry here is either an unpunished attack or
an exiled honest peer."
  (flet ((action (reason) (bl.net::compact-block-failure-action reason)))
    ;; BLOCK_INVALID_HEADER (validation.cpp:3864/4121/4125/4134/4148).
    (dolist (reason '(:bad-proof-of-work :bad-difficulty :time-too-old
                      :time-timewarp-attack :bad-version))
      (is (eq :punish (action reason))
          "~S is BLOCK_INVALID_HEADER and must punish, got ~S" reason (action reason)))
    ;; BLOCK_INVALID_PREV (validation.cpp:4254).
    (is (eq :punish (action :bad-prevblk)))
    ;; BLOCK_TIME_FUTURE (:4141) and BLOCK_CACHED_INVALID (:4232): break, no punish.
    (is (eq :ignore (action :time-too-new)))
    (is (eq :ignore (action :duplicate-invalid)))
    ;; BLOCK_CONSENSUS / BLOCK_MUTATED — the exempted class the GA8 finding was
    ;; about. :ORPHAN-BLOCK rides here too: Core punishes BLOCK_MISSING_PREV but
    ;; cannot reach that arm from a compact block, and it was one of the two
    ;; false positives that exiled honest peers.
    (dolist (reason '(:orphan-block :bad-merkle-root :bad-txns-duplicate
                      :first-tx-not-coinbase :bad-signet-solution :script-failed
                      :bad-witness-merkle-match :block-too-heavy))
      (is (eq :refetch (action reason))
          "~S is BLOCK_CONSENSUS/BLOCK_MUTATED and must not punish, got ~S"
          reason (action reason)))
    ;; A verdict nobody has classified must fail safe, never toward punishment.
    (is (eq :refetch (action :some-future-validation-keyword)))))
;;;; ============================================================
;;;; G7-16: BIP152 high-bandwidth selection
;;;; ============================================================

(defun %g716-peer (&key inbound (version 2))
  (let ((p (bl.net:make-peer :inbound inbound)))
    (setf (bl.net:peer-compact-block-version p) version
          (bl.net:peer-state p) :ready)
    p))

(defmacro %g716-quiet (&body body)
  "Run BODY with send-message stubbed out (no sockets)."
  `(let ((real (fdefinition 'bl.net:send-message)))
     (unwind-protect
          (progn (setf (fdefinition 'bl.net:send-message)
                       (lambda (peer msg) (declare (ignore peer msg)) t))
                 ,@body)
       (setf (fdefinition 'bl.net:send-message) real))))

(test g7-16-initial-sendcmpct-is-low-bandwidth
  "G7-16: high bandwidth is a SCARCE SELECTION (BIP152 allows 3), not a
capability handshake. We used to request HB from every compact-capable peer, so
every one of them pushed an unsolicited cmpctblock for every block instead of
about three."
  (let ((sent '())
        (peer (%g716-peer)))
    (let ((real (fdefinition 'bl.net:send-message)))
      (unwind-protect
           (progn
             (setf (fdefinition 'bl.net:send-message)
                   (lambda (p msg) (declare (ignore p)) (push msg sent)))
             (bl.net:send-compact-block-negotiation peer))
        (setf (fdefinition 'bl.net:send-message) real)))
    (is (= 1 (length sent)))
    ;; Assert on the ACTUAL sendcmpct byte on the wire, and on the peer that
    ;; was negotiated — checking a fresh peer's default-NIL flag would pass no
    ;; matter what this function does.
    (let ((payload (subseq (first sent) 24)))
      (is (zerop (aref payload 0))
          "the high-bandwidth byte of the initial sendcmpct must be 0"))
    (is (null (bl.net:peer-compact-block-high-bandwidth-to peer))
        "negotiation must not mark the peer HB")))

(test g7-16-hb-selection-capped-at-three-demoting-oldest
  "Core caps the HB set at 3 and demotes the OLDEST (front of
lNodesAnnouncingHeaderAndIDs). A peer already selected is only moved to the
back with NO sendcmpct re-sent — re-announcing every block would be a visible
protocol anomaly."
  (let ((bl.net::*hb-announcing-peers* '()))
    (%g716-quiet
      (let ((a (%g716-peer)) (b (%g716-peer)) (c (%g716-peer)) (d (%g716-peer)))
        (dolist (p (list a b c))
          (bl.net:maybe-set-peer-announcing-hb p))
        (is (equal (list a b c) bl.net::*hb-announcing-peers*))
        (is (every #'bl.net:peer-compact-block-high-bandwidth-to
                   (list a b c)))
        ;; Re-selecting an existing peer only reorders it.
        (bl.net:maybe-set-peer-announcing-hb a)
        (is (equal (list b c a) bl.net::*hb-announcing-peers*)
            "an already-selected peer moves to the back")
        ;; A fourth peer evicts the oldest (now b).
        (bl.net:maybe-set-peer-announcing-hb d)
        (is (equal (list c a d) bl.net::*hb-announcing-peers*))
        (is (null (bl.net:peer-compact-block-high-bandwidth-to b))
            "the evicted peer must be demoted to low bandwidth")))))

(test g7-16-inbound-promotion-protects-last-outbound-hb-peer
  "THE SUBTLE ONE (Core net_processing.cpp:1299-1310). When an INBOUND peer is
promoted, the set is full, and exactly ONE entry is outbound sitting at the
front, Core swaps the first two so the outbound HB peer is not evicted.

Without it a flood of inbound peers evicts every outbound HB peer in turn — an
eclipse/partition weakening, and the same class of ordering mistake as trimming
the wrong end of the reorg disconnect pool."
  (let ((bl.net::*hb-announcing-peers* '()))
    (%g716-quiet
      (let ((out (%g716-peer))
            (in1 (%g716-peer :inbound t))
            (in2 (%g716-peer :inbound t))
            (in3 (%g716-peer :inbound t)))
        ;; Outbound peer is at the FRONT and is the only outbound entry.
        (dolist (p (list out in1 in2))
          (bl.net:maybe-set-peer-announcing-hb p))
        (is (equal (list out in1 in2) bl.net::*hb-announcing-peers*))
        ;; Promoting another inbound peer must NOT evict the lone outbound one.
        (bl.net:maybe-set-peer-announcing-hb in3)
        (is (member out bl.net::*hb-announcing-peers*)
            "the last outbound HB peer must be protected from inbound eviction")
        (is-true (bl.net:peer-compact-block-high-bandwidth-to out))
        (is (null (bl.net:peer-compact-block-high-bandwidth-to in1))
            "the inbound peer in slot 1 is evicted instead")))))

(test g7-16-non-signalling-and-blocksonly-peers-not-promoted
  "Core gates promotion on m_provides_cmpctblocks and skips it entirely in
blocksonly mode — our mempool would not hold the transactions needed to
reconstruct the block."
  (let ((bl.net::*hb-announcing-peers* '()))
    (%g716-quiet
      (bl.net:maybe-set-peer-announcing-hb (%g716-peer :version 0))
      (is (null bl.net::*hb-announcing-peers*)
          "a peer that never signalled compact-block support is not eligible"))))

(test g7-16-disconnected-hb-peer-neither-counts-nor-squats
  "A disconnected HB peer must count as NEITHER inbound nor outbound, and must
not keep squatting one of the three slots.

Core's list holds NodeIds: once the peer is gone GetPeerRef returns null, so it
is skipped by the outbound census (net_processing.cpp:1297) and can never be
the protected front (:1303-1305). Ours holds live struct references, so before
this fix a DISCONNECTED outbound peer still counted as `the last outbound HB
peer' and triggered the inbound-protection swap in its own favour — evicting a
LIVE inbound HB peer to defend a corpse. Both halves below run the SAME
promotion; only the liveness of `out' differs, and it must flip the outcome."
  (%g716-quiet
    ;; CONTROL — `out' is alive: the protection swap fires, in1 is evicted.
    (let ((bl.net::*hb-announcing-peers* '()))
      (let ((out (%g716-peer))
            (in1 (%g716-peer :inbound t))
            (in2 (%g716-peer :inbound t))
            (in3 (%g716-peer :inbound t)))
        (dolist (p (list out in1 in2))
          (bl.net:maybe-set-peer-announcing-hb p))
        (bl.net:maybe-set-peer-announcing-hb in3)
        (is (equal (list out in2 in3) bl.net::*hb-announcing-peers*)
            "control: a LIVE lone outbound HB peer is protected, in1 is evicted")
        (is (null (bl.net:peer-compact-block-high-bandwidth-to in1)))))
    ;; FIX — identical shape, but `out' goes away through the production
    ;; disconnect path first. Nothing calls into the HB code on disconnect: the
    ;; list's only reader re-reads liveness, so it does not matter WHICH of the
    ;; several paths that kill a peer (disconnect-peer, record-misbehavior,
    ;; ban-peer) got there.
    (let ((bl.net::*hb-announcing-peers* '()))
      (let ((out (%g716-peer))
            (in1 (%g716-peer :inbound t))
            (in2 (%g716-peer :inbound t))
            (in3 (%g716-peer :inbound t)))
        (dolist (p (list out in1 in2))
          (bl.net:maybe-set-peer-announcing-hb p))
        (bl.net:disconnect-peer out)
        (bl.net:maybe-set-peer-announcing-hb in3)
        (is (equal (list in1 in2 in3) bl.net::*hb-announcing-peers*)
            "a dead peer must not be counted as outbound, protected, or kept")
        (is (null (member out bl.net::*hb-announcing-peers*))
            "the dead peer's slot must be reclaimed, not squatted")
        (is-true (bl.net:peer-compact-block-high-bandwidth-to in1)
                 "a LIVE inbound HB peer must not be evicted to defend a corpse")
        (is (= 3 (count-if #'bl.net::%hb-peer-live-p
                           bl.net::*hb-announcing-peers*))
            "all three slots hold peers that can actually announce")))))

;;;; ------------------------------------------------------------
;;;; G7-16: promotion is earned by a VALID delivery, on ANY transport
;;;; ------------------------------------------------------------

(defun %g716-mine-on (node spk)
  "Assemble + PoW-mine a block on NODE's tip paying the coinbase to SPK,
without connecting it."
  (let ((blk (bl.mining:assemble-full-block
              (bl:node-chain-state node)
              (bl:node-mempool node)
              :coinbase-script-pubkey spk)))
    (bl.mining:mine-block blk)
    blk))

(defun %g716-cmpctblock-payload (block)
  "A cmpctblock payload carrying BLOCK with every transaction PREFILLED and no
short ids, so handle-cmpctblock reconstructs it directly (the production
direct-reconstruction path) without needing the txs in our mempool.

Written by hand rather than through WRITE-COMPACT-BLOCK because that writer
serializes prefilled txs with WRITE-TRANSACTION — legacy, witness-stripped —
which drops the coinbase witness nonce and makes every reconstructed block fail
BIP141. It has no production caller (we parse cmpctblock, we never emit one),
so it is a latent bug in the emitter rather than one this test can assert on."
  (let ((txs (bl.ser:bitcoin-block-transactions block)))
    (bl.bytes:with-byte-buf (s)
      (bl.ser::bb-write-block-header
       s (bl.ser:bitcoin-block-header block))
      (bl.bytes:bb-write-u64-le s 0)     ; short-id nonce
      (bl.bytes:bb-write-varint s 0)  ; no short ids
      (bl.bytes:bb-write-varint s (length txs))
      (dolist (tx txs)
        ;; Differential index: consecutive prefilled txs all encode as 0.
        (bl.bytes:bb-write-varint s 0)
        (if (bl.ser:transaction-has-witness-p tx)
            (bl.bytes:bb-write-bytes s (bl.ser:serialize-witness-transaction tx))
            (bl.bytes:bb-write-bytes s (bl.ser:serialize-transaction tx)))))))

(defun %g716-block-payload (block)
  "The wire payload of a plain `block' message carrying BLOCK."
  (subseq (bl.ser:make-block-message block :witness t) 24))

(defun %g716-corrupt-block (block)
  "BLOCK's header (valid PoW, parent = our tip) over a bogus transaction list:
reconstruction/parsing still succeed, validation fails on the merkle root. The
shape an attacker uses to buy an HB slot with a block we will never connect."
  (bl.ser:make-bitcoin-block
   :header (bl.ser:bitcoin-block-header block)
   :transactions (list (make-simple-tx #x99))))

(defun %g716-delivering-peer (address)
  (let ((p (%g716-peer)))
    (setf (bl.net:peer-address p) address)
    p))

(defmacro %g716-with-fresh-hb (&body body)
  "Run BODY with an empty HB set and IBD latched off — maybe-promote-block-
deliverer skips everything during IBD, so a test that left it on would pass
whatever the promotion code did."
  `(let ((bl.net::*hb-announcing-peers* '())
         (bl.net:*cached-is-ibd* nil))
     ,@body))

(test g7-16-compact-block-promotes-only-after-the-block-validates
  "Core's BlockChecked promotes ONLY on the state.IsValid() arm
(net_processing.cpp:2218-2223); an invalid block goes to MaybePunishNodeForBlock
(:2207). Promotion used to run before accept-downloaded-block, so a peer that
delivered a reconstructible-but-INVALID compact block bought an HB slot — and
through the cap-of-3 eviction could demote an honest HB peer at will."
  (with-network (:regtest)
   (let* ((node (regtest-node-fixture "g716-cb"))
          (cs (bl:node-chain-state node))
          (utxo (bl:node-utxo-set node))
          (store (bl:node-block-store node))
          (mp (bl:node-mempool node))
          (good (%g716-mine-on node (p2sh-optrue-script-pubkey)))
          (bad (%g716-corrupt-block good)))
     (%g716-quiet
       ;; DEFECT: an invalid delivery earns nothing.
       (%g716-with-fresh-hb
        (let ((peer (%g716-delivering-peer "198.51.100.16")))
          (bl.net::handle-cmpctblock peer (%g716-cmpctblock-payload bad) (bl.ctx:make-node-context :chain-state cs :utxo-set utxo :block-store store :mempool mp))
          (is (= 0 (bl.store:current-height cs))
              "the bogus block must not have connected")
          (is (null bl.net::*hb-announcing-peers*)
              "a peer delivering an INVALID compact block must not be promoted")
          (is (null (bl.net:peer-compact-block-high-bandwidth-to peer)))))
       ;; CONTROL: the same path with a VALID block does promote — otherwise the
       ;; assertion above would hold even if promotion were deleted outright.
       (%g716-with-fresh-hb
        (let ((peer (%g716-delivering-peer "198.51.100.17")))
          (bl.net::handle-cmpctblock peer (%g716-cmpctblock-payload good) (bl.ctx:make-node-context :chain-state cs :utxo-set utxo :block-store store :mempool mp))
          (is (= 1 (bl.store:current-height cs))
              "the good block connected")
          (is (equal (list peer) bl.net::*hb-announcing-peers*)
              "a peer delivering a VALID compact block earns high bandwidth")
          (is-true (bl.net:peer-compact-block-high-bandwidth-to
                    peer))))))))

(test cmpctblock-message-round-trips-through-our-own-parser
  "make-cmpctblock-message emits a BIP152 HeaderAndShortIDs our own reader
accepts: the header survives, the nonce is the one we chose, the coinbase is
prefilled at index 0 (a peer's mempool can never hold it) and every other
transaction is represented by a short id. Short-id derivation itself is covered
by the receive-side tests and the SipHash vectors."
  (with-network (:regtest)
   (let* ((node (regtest-node-fixture "cb-msg"))
          (block (%g716-mine-on node (p2sh-optrue-script-pubkey)))
          (txs (bl.ser:bitcoin-block-transactions block))
          (msg (bl.ser:make-cmpctblock-message block :nonce 42))
          (cb (bl.ser:parse-cmpctblock-payload (subseq msg 24))))
     (is (equalp (bl.ser:block-header-hash
                  (bl.ser:bitcoin-block-header block))
                 (bl.ser:block-header-hash
                  (bl.ser:compact-block-header cb))))
     (is (= 42 (bl.ser:compact-block-nonce cb)))
     (let* ((prefilled (bl.ser:compact-block-prefilled-txs cb))
            (coinbase (and prefilled
                           (bl.ser:prefilled-tx-transaction
                            (first prefilled)))))
       (is (= 1 (length prefilled)))
       (is (= 0 (bl.ser:prefilled-tx-index (first prefilled))))
       ;; WTXID, not txid: BIP152 v2 prefills TX_WITH_WITNESS
       ;; (blockencodings.h:80) and the coinbase's witness is the BIP141
       ;; reserved value. A txid comparison passes even when the emitter drops
       ;; the witness — which it did until this change, leaving every
       ;; reconstruction to fail bad-witness-nonce-size.
       (is-true (bl.ser:transaction-has-witness-p coinbase)
                "the prefilled coinbase keeps its witness")
       (is (equalp (bl.ser:transaction-wtxid (first txs))
                   (bl.ser:transaction-wtxid coinbase))))
     (is (= (1- (length txs))
            (length (bl.ser:compact-block-short-ids cb)))))))

(test getdata-serves-cmpctblock-near-tip-and-a-full-block-deeper
  "We send sendcmpct to every peer, so a Core peer records us as providing
compact blocks and asks for MSG_CMPCT_BLOCK (net_processing.cpp:2891-2896).
handle-getdata served only MSG_BLOCK/MSG_WITNESS_BLOCK, so that request fell
through and the peer waited out its whole block timeout. Now the same path and
the same guards answer it, with Core's depth rule: within MAX_CMPCTBLOCK_DEPTH
of the tip a cmpctblock, deeper the full witness block, because a peer asking
for old blocks has no mempool that could reconstruct one (:2463-2476)."
  (with-network (:regtest)
   (let* ((node (regtest-node-fixture "cb-getdata"))
          (cs (bl:node-chain-state node))
          (store (bl:node-block-store node))
          ;; Seven blocks, so the first sits deeper than the depth rule allows.
          (hashes (bl.rpc::%generate-to-script-pubkey
                   node (p2sh-optrue-script-pubkey) 7 1000000))
          (deep-hash (bl.rpc:parse-hex-hash (first hashes))))
     (progn
       (is (= 7 (bl.store:current-height cs)))
       (let ((peer (%cbp-peer "198.51.100.30"))
             (tip (bl.store:best-block-hash cs)))
         (flet ((serve (hash type)
                  (%cbp-capture-sends
                   (lambda ()
                     (bl.net::handle-getdata peer (subseq (bl.ser:make-getdata-message
                                    (list (bl.ser:make-inv-vector
                                           :type type :hash hash)))
                                   24) (bl.ctx:make-node-context :chain-state cs :block-store store))))))
           (is (equal '("cmpctblock")
                      (serve tip bl.ser:+inv-type-cmpct-block+))
               "MSG_CMPCT_BLOCK at the tip is answered compactly")
           (is (equal '("block")
                      (serve deep-hash bl.ser:+inv-type-cmpct-block+))
               "deeper than MAX_CMPCTBLOCK_DEPTH falls back to the full block")
           ;; The ordinary block requests are unchanged.
           (is (equal '("block")
                      (serve tip bl.ser:+inv-type-witness-block+)))
           (is (equal '("block")
                      (serve tip bl.ser:+inv-type-block+)))))))))

(test g7-16-blocktxn-completion-promotes-only-after-the-block-validates
  "The OTHER compact path — a reconstruction completed by blocktxn — carried the
same defect and needs its own coverage: a dropped hunk there would disable the
fix on half the compact traffic without failing the cmpctblock test."
  (with-network (:regtest)
   (let* ((node (regtest-node-fixture "g716-btxn"))
          (cs (bl:node-chain-state node))
          (utxo (bl:node-utxo-set node))
          (store (bl:node-block-store node))
          (mp (bl:node-mempool node))
          (good (%g716-mine-on node (p2sh-optrue-script-pubkey)))
          (hash (bl.ser:block-header-hash
                 (bl.ser:bitcoin-block-header good))))
     (flet ((%deliver (peer txs)
              ;; Prime the pending reconstruction exactly as handle-cmpctblock
              ;; leaves it when the mempool holds none of the block's txs, then
              ;; feed the blocktxn that completes it.
              (setf (bl.net:peer-pending-compact-block peer)
                    (bl.net:make-pending-compact-block
                     :block-hash hash
                     :header (bl.ser:bitcoin-block-header good)
                     :transactions (make-array (length txs) :initial-element nil)
                     :missing-indexes (loop for i below (length txs) collect i)
                     :request-time (get-internal-real-time)
                     :use-wtxid t))
              (bl.net::handle-blocktxn peer (subseq (bl.ser:make-blocktxn-message
                        hash txs :witness t)
                       24) (bl.ctx:make-node-context :chain-state cs :utxo-set utxo :block-store store :mempool mp))))
       (%g716-quiet
         ;; DEFECT: the completed block does not validate — no promotion.
         (%g716-with-fresh-hb
          (let ((peer (%g716-delivering-peer "198.51.100.21")))
            (%deliver peer (list (make-simple-tx #x99)))
            (is (= 0 (bl.store:current-height cs)))
            (is (null bl.net::*hb-announcing-peers*)
                "an INVALID blocktxn completion must not be promoted")))
         ;; CONTROL: the real transactions complete a valid block — promoted.
         (%g716-with-fresh-hb
          (let ((peer (%g716-delivering-peer "198.51.100.22")))
            (%deliver peer (bl.ser:bitcoin-block-transactions good))
            (is (= 1 (bl.store:current-height cs))
                "the completed block connected")
            (is (equal (list peer) bl.net::*hb-announcing-peers*)
                "a VALID blocktxn completion earns high bandwidth"))))))))

(test g7-16-full-block-delivery-earns-hb-promotion
  "Core drives promotion off mapBlockSource (net_processing.cpp:2202,
2218-2223), which is filled for PLAIN block messages exactly as for compact
ones — HB is not a compact-block-only privilege. We only promoted on the two
compact reconstruction paths, so under systemic reconstruction failure (or
plain full-block downloads at the tip) our HB set stayed empty where Core keeps
three. Both live full-block entry points are exercised: handle-block (the
generic dispatcher, reached from the header-sync drains) and
dispatch-ibd-message's `block' branch (the block-download path)."
  (with-network (:regtest)
   (let* ((node (regtest-node-fixture "g716-full"))
          (cs (bl:node-chain-state node))
          (utxo (bl:node-utxo-set node))
          (store (bl:node-block-store node))
          (mp (bl:node-mempool node))
          (spk (p2sh-optrue-script-pubkey))
          (b1 (%g716-mine-on node spk)))
     (%g716-quiet
       ;; CONTROL: an INVALID full block earns nothing (same path, same peer
       ;; shape) — so the promotion assertions below cannot pass vacuously.
       (%g716-with-fresh-hb
        (let ((peer (%g716-delivering-peer "198.51.100.18")))
          (bl.net::handle-block peer (%g716-block-payload (%g716-corrupt-block b1)) (bl.ctx:make-node-context :chain-state cs :utxo-set utxo :block-store store :mempool mp))
          (is (= 0 (bl.store:current-height cs)))
          (is (null bl.net::*hb-announcing-peers*)
              "an invalid full block must not earn high bandwidth")))
       ;; handle-block with a VALID block: promoted.
       (%g716-with-fresh-hb
        (let ((peer (%g716-delivering-peer "198.51.100.19")))
          (bl.net::handle-block peer (%g716-block-payload b1) (bl.ctx:make-node-context :chain-state cs :utxo-set utxo :block-store store :mempool mp))
          (is (= 1 (bl.store:current-height cs))
              "the full block connected")
          (is (equal (list peer) bl.net::*hb-announcing-peers*)
              "a full-block delivery earns high bandwidth, like a compact one")
          (is-true (bl.net:peer-compact-block-high-bandwidth-to peer))))
       ;; The block-download path (dispatch-ibd-message "block"): its header is
       ;; in the index first, exactly as the real pipeline has it.
       (let ((b2 (%g716-mine-on node spk)))
         (let* ((hdr (bl.ser:bitcoin-block-header b2))
                (bhash (bl.ser:block-header-hash hdr))
                (prev (bl.store:get-block-index-entry
                       cs (bl.store:best-block-hash cs))))
           (bl.store:add-block-index-entry
            cs (bl.store:make-block-index-entry
                :hash bhash :height 2 :header hdr :prev-entry prev
                :chain-work (bl.store:calculate-chain-work
                             (bl.ser:block-header-bits hdr)
                             (bl.store:block-index-entry-chain-work prev))
                :status :header-valid)))
         (%g716-with-fresh-hb
          (with-ibd-context
            (let ((peer (%g716-delivering-peer "198.51.100.20")))
              (bl.net::dispatch-ibd-message peer "block" (%g716-block-payload b2) (bl.ctx:make-node-context :chain-state cs :utxo-set utxo :block-store store) bl.net:*ibd-context*)
              (is (= 2 (bl.store:current-height cs))
                  "the downloaded block connected")
              (is (equal (list peer) bl.net::*hb-announcing-peers*)
                  "the block-download path promotes too")
              (is-true (bl.net:peer-compact-block-high-bandwidth-to
                        peer))))))))))

;;;; ------------------------------------------------------------
;;;; G7-16: promotion needs the block to CONNECT, not merely to be accepted
;;;; ------------------------------------------------------------

(defun %g716-block-hash (block)
  (bl.ser:block-header-hash
   (bl.ser:bitcoin-block-header block)))

(defun %g716-other-spk ()
  "A second, DIFFERENT coinbase scriptPubKey. Two blocks assembled on the same
tip with different coinbase outputs get different merkle roots and therefore
different hashes — siblings, equal work."
  (let ((spk (copy-seq (p2sh-optrue-script-pubkey))))
    (setf (aref spk 2) (logxor (aref spk 2) 1))
    spk))

(defun %g716-blocktxn-deliver (peer block txs cs utxo store mp)
  "Drive the production blocktxn completion path for BLOCK: prime the pending
reconstruction exactly as handle-cmpctblock leaves it when our mempool holds
none of the block's transactions, then feed the blocktxn carrying TXS."
  (let ((hash (%g716-block-hash block)))
    (setf (bl.net:peer-pending-compact-block peer)
          (bl.net:make-pending-compact-block
           :block-hash hash
           :header (bl.ser:bitcoin-block-header block)
           :transactions (make-array (length txs) :initial-element nil)
           :missing-indexes (loop for i below (length txs) collect i)
           :request-time (get-internal-real-time)
           :use-wtxid t))
    (bl.net::handle-blocktxn peer (subseq (bl.ser:make-blocktxn-message hash txs :witness t) 24) (bl.ctx:make-node-context :chain-state cs :utxo-set utxo :block-store store :mempool mp))))

(test cmpctblock-replay-never-hashes-the-mempool
  "Core returns EARLY from the CMPCTBLOCK handler when
`pindex->nChainWork <= tip->nChainWork || pindex->nTx != 0` — we know something
better, or we have had this block's body at some point. In both cases our
mempool is the wrong tool.

Without that gate a peer can replay one cmpctblock forever and make us hash the
WHOLE MEMPOOL into a shortid map every time: an unbounded per-message cost for
a message that costs the sender nothing. Asserted by counting the shortid-map
builds, because \"nothing connected\" is ALSO true of the ungated path — the
replay was already harmless to the chain and expensive to us, which is exactly
why the hole survived this long."
  (with-network (:regtest)
   (let* ((node (regtest-node-fixture "cb-replay-cost"))
          (cs (bl:node-chain-state node))
          (utxo (bl:node-utxo-set node))
          (store (bl:node-block-store node))
          (mp (bl:node-mempool node))
          (spk (p2sh-optrue-script-pubkey))
          (b1 (%g716-mine-on node spk))
          (builds 0)
          ;; BIND the IBD latch. INITIAL-BLOCK-DOWNLOAD-P (protocol.lisp:695)
          ;; SETFs this global the first time it sees a recent tip past the
          ;; work floor — which connecting b1 on regtest (floor 0) does — and
          ;; the latch is one-way. Without a binding the write escapes this
          ;; test and every later test in the image that needs IBD fails,
          ;; nowhere near here. That is exactly what happened: three
          ;; eclipse-dos-tests went red in the cold battery while this suite
          ;; stayed green. The neighbouring g7-16 tests get the same
          ;; protection from %g716-with-fresh-hb.
          (bl.net:*cached-is-ibd* nil))
    (%g716-quiet
      ;; Count every shortid map built, whoever builds it.
      (let ((real (symbol-function 'bl.net::build-shortid-map)))
        (unwind-protect
             (progn
               (setf (symbol-function 'bl.net::build-shortid-map)
                     (lambda (&rest args) (incf builds) (apply real args)))
               ;; Control: the FIRST delivery is new to us, so it is
               ;; reconstructed — the gate must not swallow real work.
               (let ((a (%g716-delivering-peer "198.51.100.60")))
                 (bl.net::handle-cmpctblock a (%g716-cmpctblock-payload b1) (bl.ctx:make-node-context :chain-state cs :utxo-set utxo :block-store store :mempool mp)))
               (is (= 1 (bl.store:current-height cs))
                   "control: the first delivery of b1 connected")
               (is (plusp builds)
                   "control: the first delivery must actually reconstruct")
               ;; Now replay it ten times. Core returns before any of this.
               (let ((after-first builds)
                     (b (%g716-delivering-peer "198.51.100.61")))
                 (dotimes (i 10)
                   (bl.net::handle-cmpctblock b (%g716-cmpctblock-payload b1) (bl.ctx:make-node-context :chain-state cs :utxo-set utxo :block-store store :mempool mp)))
                 (is (= after-first builds)
                     "a replayed cmpctblock rebuilt the shortid map ~D time(s)"
                     (- builds after-first))
                 (is (= 1 (bl.store:current-height cs))
                     "the replays connected nothing")
                 ;; And the replaying peer is not punished: an honest peer
                 ;; relaying what it just accepted is the ordinary case.
                 (is-false (bl.net:peer-discouraged-p
                            "198.51.100.61"))
                 (is (eq :ready (bl.net:peer-state b)))))
          (setf (symbol-function 'bl.net::build-shortid-map)
                real)))))))

(test g7-16-replayed-block-earns-no-hb-promotion
  "A peer that REPLAYS a block already on our chain must earn nothing, on every
delivery path.

Core: BlockChecked's valid state is emitted only from ConnectTip
(validation.cpp:3070) — ProcessNewBlock's other emit (:4455) is the
AcceptBlock-failure path — and a block we already have short-circuits inside
AcceptBlock, so it never reaches ConnectTip and promotes nobody.

Ours gated on ACCEPT-DOWNLOADED-BLOCK's `valid', which is T for a re-delivered
block: it takes the :context-free-only side-branch arm, revalidates, stores,
and returns T with the tip untouched. Note that `(equalp (best-block-hash cs)
hash)' — the predicate handle-block already used for relay — does NOT close
this: for a replay of our own tip it is trivially true, because the tip already
IS that block. Only \"the tip MOVED onto this block\" does.

Consequence of the hole: any inbound peer that sent sendcmpct could echo our
own tip back and buy a high-bandwidth slot for free, repeatedly, and through
the cap-of-3 eviction choose which honest HB peer we demote — destroying the
property this whole change exists to establish. Each replay below carries its
own control: the FIRST, genuinely-connecting delivery of the same block on the
same path must promote."
  (with-network (:regtest)
   (let* ((node (regtest-node-fixture "g716-replay"))
          (cs (bl:node-chain-state node))
          (utxo (bl:node-utxo-set node))
          (store (bl:node-block-store node))
          (mp (bl:node-mempool node))
          (spk (p2sh-optrue-script-pubkey))
          (b1 (%g716-mine-on node spk)))
     (is (= 0 (bl.store:current-height cs)) "fixture starts at genesis")
     (%g716-quiet
       ;;; --- cmpctblock ------------------------------------------------
       (%g716-with-fresh-hb
        (let ((a (%g716-delivering-peer "198.51.100.30")))
          (bl.net::handle-cmpctblock a (%g716-cmpctblock-payload b1) (bl.ctx:make-node-context :chain-state cs :utxo-set utxo :block-store store :mempool mp))
          (is (= 1 (bl.store:current-height cs))
              "control: the first delivery of b1 connected")
          (is (equal (list a) bl.net::*hb-announcing-peers*)
              "control: a genuinely-connecting cmpctblock delivery promotes")))
       (%g716-with-fresh-hb
        (let ((b (%g716-delivering-peer "198.51.100.31")))
          (bl.net::handle-cmpctblock b (%g716-cmpctblock-payload b1) (bl.ctx:make-node-context :chain-state cs :utxo-set utxo :block-store store :mempool mp))
          (is (= 1 (bl.store:current-height cs))
              "the replay connected nothing")
          (is (eq :ready (bl.net:peer-state b))
              "the replayer is NOT punished, so nothing else stops the promotion")
          (is (null bl.net::*hb-announcing-peers*)
              "replaying our own tip as a cmpctblock must not buy an HB slot")
          (is (null (bl.net:peer-compact-block-high-bandwidth-to b)))))
       ;;; --- full block (handle-block) ---------------------------------
       (let ((b2 (%g716-mine-on node spk)))
         (%g716-with-fresh-hb
          (let ((c (%g716-delivering-peer "198.51.100.32")))
            (bl.net::handle-block c (%g716-block-payload b2) (bl.ctx:make-node-context :chain-state cs :utxo-set utxo :block-store store :mempool mp))
            (is (= 2 (bl.store:current-height cs))
                "control: the first delivery of b2 connected")
            (is (equal (list c) bl.net::*hb-announcing-peers*)
                "control: a genuinely-connecting full block promotes")))
         (%g716-with-fresh-hb
          (let ((d (%g716-delivering-peer "198.51.100.33")))
            (bl.net::handle-block d (%g716-block-payload b2) (bl.ctx:make-node-context :chain-state cs :utxo-set utxo :block-store store :mempool mp))
            (is (= 2 (bl.store:current-height cs))
                "the replay connected nothing")
            (is (eq :ready (bl.net:peer-state d))
                "the replayer is NOT punished")
            (is (null bl.net::*hb-announcing-peers*)
                "replaying our own tip as a full block must not buy an HB slot")
            (is (null (bl.net:peer-compact-block-high-bandwidth-to d))))))
       ;;; --- blocktxn completion ---------------------------------------
       (let* ((b3 (%g716-mine-on node spk))
              (txs (bl.ser:bitcoin-block-transactions b3)))
         (%g716-with-fresh-hb
          (let ((e (%g716-delivering-peer "198.51.100.34")))
            (%g716-blocktxn-deliver e b3 txs cs utxo store mp)
            (is (= 3 (bl.store:current-height cs))
                "control: the first blocktxn completion of b3 connected")
            (is (equal (list e) bl.net::*hb-announcing-peers*)
                "control: a genuinely-connecting blocktxn completion promotes")))
         (%g716-with-fresh-hb
          (let ((f (%g716-delivering-peer "198.51.100.35")))
            (%g716-blocktxn-deliver f b3 txs cs utxo store mp)
            (is (= 3 (bl.store:current-height cs))
                "the replay connected nothing")
            (is (eq :ready (bl.net:peer-state f))
                "the replayer is NOT punished")
            (is (null bl.net::*hb-announcing-peers*)
                "replaying our own tip as a blocktxn completion must not buy an HB slot")
            (is (null (bl.net:peer-compact-block-high-bandwidth-to
                       f))))))))))

(test g7-16-side-branch-block-earns-no-hb-promotion
  "The other half of the same defect: ACCEPT-DOWNLOADED-BLOCK also returns VALID
for a block it merely STORED on a side branch (the :context-free-only arm,
protocol.lisp), where Core runs no ConnectTip and therefore fires no valid
BlockChecked and promotes nobody. Unlike the replay case this one is not
addressable by any dedup guard — the block is genuinely new to us — so it pins
the connection gate on its own."
  (with-network (:regtest)
   (let* ((node (regtest-node-fixture "g716-side"))
          (cs (bl:node-chain-state node))
          (utxo (bl:node-utxo-set node))
          (store (bl:node-block-store node))
          (mp (bl:node-mempool node))
          ;; Two SIBLINGS assembled on genesis before either is connected:
          ;; equal work, so the second is stored and first-seen wins.
          (main (%g716-mine-on node (p2sh-optrue-script-pubkey)))
          (sibling (%g716-mine-on node (%g716-other-spk))))
     (is (not (equalp (%g716-block-hash main) (%g716-block-hash sibling)))
         "the fixture must really have built two DIFFERENT blocks")
     (%g716-quiet
       (%g716-with-fresh-hb
        (let ((a (%g716-delivering-peer "198.51.100.40")))
          (bl.net::handle-block a (%g716-block-payload main) (bl.ctx:make-node-context :chain-state cs :utxo-set utxo :block-store store :mempool mp))
          (is (= 1 (bl.store:current-height cs))
              "control: the first sibling connected")
          (is (equal (list a) bl.net::*hb-announcing-peers*)
              "control: the connecting sibling's deliverer is promoted")))
       (%g716-with-fresh-hb
        (let ((b (%g716-delivering-peer "198.51.100.41")))
          (bl.net::handle-block b (%g716-block-payload sibling) (bl.ctx:make-node-context :chain-state cs :utxo-set utxo :block-store store :mempool mp))
          (is (= 1 (bl.store:current-height cs))
              "the side branch did not become the tip")
          (is (equalp (bl.store:best-block-hash cs) (%g716-block-hash main))
              "the tip is still the first sibling")
          (is-true (bl.store:get-block-index-entry
                    cs (%g716-block-hash sibling))
                   "...but the side block WAS accepted and stored — this is the
valid-yet-unconnected case, not a rejection")
          (is (eq :ready (bl.net:peer-state b))
              "storing a side branch is not misbehaviour")
          (is (null bl.net::*hb-announcing-peers*)
              "a stored-but-unconnected block must not earn high bandwidth")
          (is (null (bl.net:peer-compact-block-high-bandwidth-to
                     b)))))))))
