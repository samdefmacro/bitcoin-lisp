(in-package #:bitcoin-lisp.tests)

(def-suite :compact-block-tests
  :description "Tests for Compact Block Relay (BIP 152)"
  :in :bitcoin-lisp-tests)

(in-suite :compact-block-tests)

;;;; Helper functions

(defun make-mock-peer ()
  "Create a mock peer for testing."
  (bitcoin-lisp.networking:make-peer
   :state :ready
   :address "127.0.0.1"))

(defun make-mock-mempool-with-txs (txs)
  "Create a mempool with the given transactions.
   TXS is a list of (txid . transaction) pairs."
  (let ((mempool (bitcoin-lisp.mempool:make-mempool)))
    (dolist (pair txs)
      (let ((txid (car pair))
            (tx (cdr pair)))
        (bitcoin-lisp.mempool:mempool-add
         mempool txid
         (bitcoin-lisp.mempool:make-entry-from-tx tx 1000 0))))
    mempool))

(defun make-simple-tx (id-byte)
  "Create a simple transaction with a unique identifier byte."
  (bitcoin-lisp.serialization:make-transaction
   :version 2
   :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                  :previous-output (bitcoin-lisp.serialization:make-outpoint
                                    :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                      :initial-element id-byte)
                                    :index 0)
                  :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                  :sequence #xffffffff))
   :outputs (vector (bitcoin-lisp.serialization:make-tx-out
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
    (is (= (bitcoin-lisp.networking:peer-compact-block-version peer) 0))
    ;; v1 is ignored — peer stays unsupported (we fall back to full witness blocks)
    (let ((payload (subseq (bitcoin-lisp.serialization:make-sendcmpct-message nil 1) 24)))
      (bitcoin-lisp.networking::handle-sendcmpct peer payload))
    (is (= (bitcoin-lisp.networking:peer-compact-block-version peer) 0))
    ;; v2 is accepted
    (let ((payload (subseq (bitcoin-lisp.serialization:make-sendcmpct-message nil 2) 24)))
      (bitcoin-lisp.networking::handle-sendcmpct peer payload))
    (is (= (bitcoin-lisp.networking:peer-compact-block-version peer) 2))))

(test sendcmpct-rejects-invalid-version
  "handle-sendcmpct ignores every version other than 2 — v1 and future/unknown
versions alike (mirrors Core's `if (version != CMPCTBLOCKS_VERSION) return;`)."
  (let ((peer (make-mock-peer)))
    ;; v3 (unknown/future) ignored
    (let ((payload (flexi-streams:with-output-to-sequence (s)
                     (write-byte 0 s)  ; low-bandwidth
                     (bitcoin-lisp.serialization:write-uint64-le s 3))))  ; version 3
      (bitcoin-lisp.networking::handle-sendcmpct peer payload))
    (is (= (bitcoin-lisp.networking:peer-compact-block-version peer) 0))
    ;; v1 ignored too
    (let ((payload (subseq (bitcoin-lisp.serialization:make-sendcmpct-message nil 1) 24)))
      (bitcoin-lisp.networking::handle-sendcmpct peer payload))
    (is (= (bitcoin-lisp.networking:peer-compact-block-version peer) 0))))

(test sendcmpct-tracks-high-bandwidth
  "handle-sendcmpct tracks the high-bandwidth preference from a (v2) sendcmpct."
  (let ((peer (make-mock-peer)))
    (is (null (bitcoin-lisp.networking:peer-compact-block-high-bandwidth peer)))
    ;; Receive high-bandwidth request (v2 — the only version we accept)
    (let ((payload (subseq (bitcoin-lisp.serialization:make-sendcmpct-message t 2) 24)))
      (bitcoin-lisp.networking::handle-sendcmpct peer payload))
    (is (bitcoin-lisp.networking:peer-compact-block-high-bandwidth peer))
    (is (= 2 (bitcoin-lisp.networking:peer-compact-block-version peer)))))

(test should-use-compact-blocks-checks-peer-support
  "should-use-compact-blocks-p should check if peer supports compact blocks."
  (let ((peer (make-mock-peer)))
    ;; No support
    (is (null (bitcoin-lisp.networking:should-use-compact-blocks-p peer)))
    ;; Add support (v2 — the only version we negotiate)
    (setf (bitcoin-lisp.networking:peer-compact-block-version peer) 2)
    ;; Now should be true (assuming not in IBD)
    (is (bitcoin-lisp.networking:should-use-compact-blocks-p peer))))

;;;; Short ID Map Building Tests

(test build-shortid-map-indexes-mempool
  "build-shortid-map should create mapping from short IDs to transactions."
  (let* ((tx1 (make-simple-tx #x11))
         (tx2 (make-simple-tx #x22))
         (txid1 (bitcoin-lisp.serialization:transaction-hash tx1))
         (txid2 (bitcoin-lisp.serialization:transaction-hash tx2))
         (mempool (make-mock-mempool-with-txs (list (cons txid1 tx1)
                                                    (cons txid2 tx2))))
         (k0 #x0706050403020100)
         (k1 #x0f0e0d0c0b0a0908))
    (multiple-value-bind (map collision)
        (bitcoin-lisp.networking::build-shortid-map mempool k0 k1 nil)
      (is (not collision))
      (is (= (hash-table-count map) 2))
      ;; Each entry should be (tx . full-id)
      (let ((short-id1 (bitcoin-lisp.crypto:compute-short-txid k0 k1 txid1)))
        (is (gethash short-id1 map))))))

(test build-shortid-map-detects-collision
  "build-shortid-map should detect collisions within mempool."
  ;; This is hard to test directly without crafting collision inputs,
  ;; but we can verify the collision flag mechanism works
  (let* ((tx1 (make-simple-tx #x11))
         (txid1 (bitcoin-lisp.serialization:transaction-hash tx1))
         (mempool (make-mock-mempool-with-txs (list (cons txid1 tx1)))))
    (multiple-value-bind (map collision)
        (bitcoin-lisp.networking::build-shortid-map mempool 0 0 nil)
      (declare (ignore map))
      ;; With just one tx, no collision expected
      (is (not collision)))))

(test build-shortid-map-uses-wtxid-for-v2
  "build-shortid-map should use wtxid when use-wtxid is true."
  (let* ((tx (make-simple-tx #x33))
         (txid (bitcoin-lisp.serialization:transaction-hash tx))
         (wtxid (bitcoin-lisp.serialization:transaction-wtxid tx))
         (mempool (make-mock-mempool-with-txs (list (cons txid tx))))
         (k0 #x1234)
         (k1 #x5678))
    ;; With use-wtxid=nil, should use txid
    (multiple-value-bind (map1 collision1)
        (bitcoin-lisp.networking::build-shortid-map mempool k0 k1 nil)
      (declare (ignore collision1))
      (let ((short-id-txid (bitcoin-lisp.crypto:compute-short-txid k0 k1 txid)))
        (is (gethash short-id-txid map1))))
    ;; With use-wtxid=t, should use wtxid
    (multiple-value-bind (map2 collision2)
        (bitcoin-lisp.networking::build-shortid-map mempool k0 k1 t)
      (declare (ignore collision2))
      (let ((short-id-wtxid (bitcoin-lisp.crypto:compute-short-txid k0 k1 wtxid)))
        (is (gethash short-id-wtxid map2))))))

;;;; Block Reconstruction Tests

(test reconstruct-with-all-txs-in-mempool
  "Block should reconstruct successfully when all txs are in mempool."
  (let* ((tx1 (make-simple-tx #x11))
         (tx2 (make-simple-tx #x22))
         (txid1 (bitcoin-lisp.serialization:transaction-hash tx1))
         (txid2 (bitcoin-lisp.serialization:transaction-hash tx2))
         (mempool (make-mock-mempool-with-txs (list (cons txid1 tx1)
                                                    (cons txid2 tx2))))
         (header (bitcoin-lisp.serialization:make-block-header
                  :version 1
                  :prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :timestamp 0
                  :bits #x1d00ffff
                  :nonce 0))
         (nonce #x1234567890abcdef)
         (header-bytes (bitcoin-lisp.serialization:serialize-block-header header)))
    ;; Compute short IDs for our transactions
    (multiple-value-bind (k0 k1)
        (bitcoin-lisp.crypto:compute-siphash-key header-bytes nonce)
      (let* ((short-id1 (bitcoin-lisp.crypto:compute-short-txid k0 k1 txid1))
             (short-id2 (bitcoin-lisp.crypto:compute-short-txid k0 k1 txid2))
             (compact-block (bitcoin-lisp.serialization:make-compact-block
                             :header header
                             :nonce nonce
                             :short-ids (list short-id1 short-id2)
                             :prefilled-txs '())))
        (multiple-value-bind (block missing partial)
            (bitcoin-lisp.networking::reconstruct-compact-block compact-block mempool nil)
          (declare (ignore partial))
          (is-true block)
          (is (null missing))
          (is (= (length (bitcoin-lisp.serialization:bitcoin-block-transactions block)) 2)))))))

(test reconstruct-with-missing-txs
  "Reconstruction should return missing indexes when txs not in mempool."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))  ; Empty mempool
         (header (bitcoin-lisp.serialization:make-block-header
                  :version 1
                  :prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :timestamp 0
                  :bits #x1d00ffff
                  :nonce 0))
         (compact-block (bitcoin-lisp.serialization:make-compact-block
                         :header header
                         :nonce 0
                         :short-ids (list #x112233445566 #xaabbccddeeff)
                         :prefilled-txs '())))
    (multiple-value-bind (block missing partial)
        (bitcoin-lisp.networking::reconstruct-compact-block compact-block mempool nil)
      (is (null block))
      (is (equal missing '(0 1)))  ; Both indexes missing
      (is-true partial))))  ; Partial array returned

(test reconstruct-with-prefilled-coinbase
  "Reconstruction should place prefilled transactions correctly."
  (let* ((coinbase-tx (make-simple-tx #x00))
         (tx1 (make-simple-tx #x11))
         (txid1 (bitcoin-lisp.serialization:transaction-hash tx1))
         (mempool (make-mock-mempool-with-txs (list (cons txid1 tx1))))
         (header (bitcoin-lisp.serialization:make-block-header
                  :version 1
                  :prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :timestamp 0
                  :bits #x1d00ffff
                  :nonce 0))
         (nonce #x1234567890abcdef)
         (header-bytes (bitcoin-lisp.serialization:serialize-block-header header)))
    (multiple-value-bind (k0 k1)
        (bitcoin-lisp.crypto:compute-siphash-key header-bytes nonce)
      (let* ((short-id1 (bitcoin-lisp.crypto:compute-short-txid k0 k1 txid1))
             (prefilled (bitcoin-lisp.serialization:make-prefilled-tx
                         :index 0
                         :transaction coinbase-tx))
             (compact-block (bitcoin-lisp.serialization:make-compact-block
                             :header header
                             :nonce nonce
                             :short-ids (list short-id1)
                             :prefilled-txs (list prefilled))))
        (multiple-value-bind (block missing partial)
            (bitcoin-lisp.networking::reconstruct-compact-block compact-block mempool nil)
          (declare (ignore partial))
          (is-true block)
          (is (null missing))
          ;; First tx should be coinbase (prefilled), second should be tx1
          (is (= (length (bitcoin-lisp.serialization:bitcoin-block-transactions block)) 2)))))))

;;;; Timeout Handling Tests

(test compact-block-timeout-clears-pending
  "check-compact-block-timeout should clear expired pending state."
  (let ((peer (make-mock-peer)))
    ;; Set up pending state with old timestamp
    (setf (bitcoin-lisp.networking:peer-pending-compact-block peer)
          (bitcoin-lisp.networking:make-pending-compact-block
           :block-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xab)
           :request-time (- (get-internal-real-time)
                            (* 20 internal-time-units-per-second))))  ; 20 seconds ago
    (is (bitcoin-lisp.networking:peer-pending-compact-block peer))
    ;; Check timeout (should clear and request full block)
    ;; Note: This will try to send a message which will fail, but state should clear
    (handler-case
        (bitcoin-lisp.networking:check-compact-block-timeout peer)
      (error () nil))
    (is (null (bitcoin-lisp.networking:peer-pending-compact-block peer)))))

(test compact-block-timeout-preserves-fresh-pending
  "check-compact-block-timeout should not clear fresh pending state."
  (let ((peer (make-mock-peer)))
    ;; Set up pending state with recent timestamp
    (setf (bitcoin-lisp.networking:peer-pending-compact-block peer)
          (bitcoin-lisp.networking:make-pending-compact-block
           :block-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xab)
           :request-time (get-internal-real-time)))  ; Just now
    (bitcoin-lisp.networking:check-compact-block-timeout peer)
    ;; Should still have pending state
    (is (bitcoin-lisp.networking:peer-pending-compact-block peer))))

;;;; Metrics Tests

(test compact-block-stats-returns-metrics
  "compact-block-stats should return current metrics."
  (let ((stats (bitcoin-lisp.networking:compact-block-stats)))
    (is (listp stats))
    (is (member :successes stats))
    (is (member :failures stats))
    (is (member :collisions stats))))

;;;; Clear pending state test

(test clear-pending-compact-block
  "clear-pending-compact-block should remove pending state."
  (let ((peer (make-mock-peer)))
    (setf (bitcoin-lisp.networking:peer-pending-compact-block peer)
          (bitcoin-lisp.networking:make-pending-compact-block
           :block-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (is (bitcoin-lisp.networking:peer-pending-compact-block peer))
    (bitcoin-lisp.networking:clear-pending-compact-block peer)
    (is (null (bitcoin-lisp.networking:peer-pending-compact-block peer)))))

;;;; ====================================================================
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
        (real (fdefinition 'bitcoin-lisp.networking:send-message)))
    (unwind-protect
         (progn
           (setf (fdefinition 'bitcoin-lisp.networking:send-message)
                 (lambda (peer bytes)
                   (declare (ignore peer))
                   (push (bitcoin-lisp.serialization:bytes-to-command
                          (subseq bytes 4 16))
                         sent)
                   t))
           (funcall thunk))
      (setf (fdefinition 'bitcoin-lisp.networking:send-message) real))
    (nreverse sent)))

(defun %cbp-peer (address)
  "A ready, compact-block-v2 peer at ADDRESS. Each punishment test uses its own
address: the discourage filter is a process-global rolling set."
  (let ((p (bitcoin-lisp.networking:make-peer :state :ready :address address)))
    (setf (bitcoin-lisp.networking:peer-compact-block-version p) 2)
    p))

(defun %cbp-hash (byte)
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element byte))

(defun %cbp-header (prev-hash timestamp)
  "A regtest-difficulty header on PREV-HASH. Version 4 clears the BIP34/66/65
gates (BIP34 is active from height 1 on regtest), so the checks under test are
never pre-empted by :BAD-VERSION. Call inside %WITH-REGTEST."
  (bitcoin-lisp.serialization:make-block-header
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
        do (setf (bitcoin-lisp.serialization:block-header-nonce header) nonce
                 (bitcoin-lisp.serialization:block-header-cached-hash header) nil)
        when (bitcoin-lisp.validation:check-proof-of-work header)
          do (return header)
        finally (return header)))

(defun %cbp-payload (compact-block)
  (flexi-streams:with-output-to-sequence (s)
    (bitcoin-lisp.serialization:write-compact-block s compact-block)))

(defun %cbp-state-with-parent (parent-hash parent-timestamp &key (status :valid))
  "A chain-state holding only PARENT-HASH at height 0, with a real header (the
MTP walk and the difficulty check both dereference it). BEST-BLOCK-HASH stays
NIL so ACCEPT-DOWNLOADED-BLOCK takes its side-branch path, which is the one
that consults the parent index entry. STATUS :INVALID makes the parent a block
we rejected — Core's BLOCK_INVALID_PREV."
  (let ((state (bitcoin-lisp.storage:make-chain-state)))
    (bitcoin-lisp.storage:add-block-index-entry
     state (bitcoin-lisp.storage:make-block-index-entry
            :hash parent-hash :height 0 :chain-work 1 :status status
            :header (%cbp-header (%cbp-hash 0) parent-timestamp)))
    state))

(defun %cbp-one-tx-compact-block-with-header (header prefilled-index tx)
  "A compact block carrying HEADER, exactly one prefilled transaction and no
short IDs, so tx-count is 1. PREFILLED-INDEX 0 reconstructs; anything else is
out of bounds and is Core's READ_STATUS_INVALID."
  (bitcoin-lisp.serialization:make-compact-block
   :header header
   :nonce 7
   :short-ids '()
   :prefilled-txs (list (bitcoin-lisp.serialization:make-prefilled-tx
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
        (real (fdefinition 'bitcoin-lisp.networking::build-shortid-map)))
    (unwind-protect
         (progn
           (setf (fdefinition 'bitcoin-lisp.networking::build-shortid-map)
                 (lambda (&rest args) (incf calls) (apply real args)))
           (let ((result (funcall thunk)))
             (values result calls)))
      (setf (fdefinition 'bitcoin-lisp.networking::build-shortid-map) real))))

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
  (%with-regtest
   (let* ((bitcoin-lisp.networking::*cached-is-ibd* nil)
          (addr "203.0.113.41")
          (peer (%cbp-peer addr))
          (state (bitcoin-lisp.storage:make-chain-state))
          (utxo (bitcoin-lisp.storage:make-utxo-set))
          (cb (%cbp-one-tx-compact-block (%cbp-hash #xAA) 0 (make-simple-tx #x11)))
          (sent (%cbp-capture-sends
                 (lambda ()
                   (bitcoin-lisp.networking::handle-cmpctblock
                    peer (%cbp-payload cb) state utxo nil
                    (bitcoin-lisp.mempool:make-mempool))))))
     (is (equal '("getheaders") sent)
         "unknown-parent cmpctblock must send exactly one getheaders, sent: ~S" sent)
     (is-false (bitcoin-lisp.networking:peer-discouraged-p addr)
               "an honest peer relaying ahead of our headers must not be discouraged")
     (is (eq :ready (bitcoin-lisp.networking:peer-state peer))))))

(test cmpctblock-unknown-parent-sends-no-getheaders-during-ibd
  "GA8 W4. Core gates the unknown-parent getheaders on
!IsInitialBlockDownload() (net_processing.cpp:4572-4574) — during IBD the
header sync owns the locator and an unsolicited getheaders per stray
cmpctblock is pure noise. The early return, and the absence of punishment,
still hold. Without this test the IBD gate is an unasserted clause: the
unknown-parent test above pins *cached-is-ibd* to NIL and cannot distinguish a
gated getheaders from an ungated one."
  (%with-regtest
   (let* ((bitcoin-lisp.networking::*cached-is-ibd* t)
          (addr "203.0.113.47")
          (peer (%cbp-peer addr))
          ;; No tip at all ⇒ initial-block-download-p stays latched at T.
          (state (bitcoin-lisp.storage:make-chain-state))
          (utxo (bitcoin-lisp.storage:make-utxo-set))
          (cb (%cbp-one-tx-compact-block (%cbp-hash #xAB) 0 (make-simple-tx #x14)))
          (sent (%cbp-capture-sends
                 (lambda ()
                   (bitcoin-lisp.networking::handle-cmpctblock
                    peer (%cbp-payload cb) state utxo nil
                    (bitcoin-lisp.mempool:make-mempool))))))
     (is-true bitcoin-lisp.networking::*cached-is-ibd*
              "fixture must still be in IBD or this test asserts nothing")
     (is (null sent)
         "no getheaders may be sent for an unknown-parent cmpctblock during IBD, sent: ~S"
         sent)
     (is-false (bitcoin-lisp.networking:peer-discouraged-p addr))
     (is (eq :ready (bitcoin-lisp.networking:peer-state peer))))))

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
  (%with-regtest
   (let* ((bitcoin-lisp.networking::*cached-is-ibd* nil)
          (bitcoin-lisp.networking::*compact-block-success-count* 0)
          (bitcoin-lisp.networking::*compact-block-failure-count* 0)
          (addr "203.0.113.42")
          (peer (%cbp-peer addr))
          (parent (%cbp-hash #xA1))
          (state (%cbp-state-with-parent parent 1296688600))
          (utxo (bitcoin-lisp.storage:make-utxo-set))
          ;; The single prefilled transaction is NOT a coinbase: reconstruction
          ;; succeeds, then validate-block rejects with :FIRST-TX-NOT-COINBASE.
          (cb (%cbp-one-tx-compact-block parent 0 (make-simple-tx #x12)))
          (sent (%cbp-capture-sends
                 (lambda ()
                   (bitcoin-lisp.networking::handle-cmpctblock
                    peer (%cbp-payload cb) state utxo nil
                    (bitcoin-lisp.mempool:make-mempool))))))
     (is (= 1 bitcoin-lisp.networking::*compact-block-success-count*)
         "the compact block must have been reconstructed (parent guard too broad?)")
     (is (equal '("getdata") sent)
         "an invalid reconstruction must be refetched in full, sent: ~S" sent)
     (is (= 1 bitcoin-lisp.networking::*compact-block-failure-count*))
     (is-false (bitcoin-lisp.networking:peer-discouraged-p addr)
               "a compact block that fails validation must not discourage its sender")
     (is (eq :ready (bitcoin-lisp.networking:peer-state peer))))))

(test cmpctblock-structurally-malformed-still-punishes
  "GA8 W4 control: removing the punishment for INVALID blocks must not remove
the punishment for INVALID MESSAGES. A prefilled transaction whose index lies
outside the block is Core's READ_STATUS_INVALID (blockencodings.cpp:78-84),
which net_processing answers with Misbehaving (:4679-4683) -- no honest peer can
produce it. Before this change our reconstruction reported it as :COLLISION,
i.e. the same value as an innocent short-ID clash in our own mempool, so it got
a polite full-block getdata instead."
  (%with-regtest
   (let* ((bitcoin-lisp.networking::*cached-is-ibd* nil)
          (addr "203.0.113.43")
          (peer (%cbp-peer addr))
          (parent (%cbp-hash #xA2))
          (state (%cbp-state-with-parent parent 1296688600))
          (utxo (bitcoin-lisp.storage:make-utxo-set))
          ;; tx-count = 1 (one prefilled, no short IDs), prefilled index 3.
          (cb (%cbp-one-tx-compact-block parent 3 (make-simple-tx #x13)))
          (sent (%cbp-capture-sends
                 (lambda ()
                   (bitcoin-lisp.networking::handle-cmpctblock
                    peer (%cbp-payload cb) state utxo nil
                    (bitcoin-lisp.mempool:make-mempool))))))
     (is-true (bitcoin-lisp.networking:peer-discouraged-p addr)
              "a structurally malformed cmpctblock must still discourage the sender")
     (is (eq :disconnected (bitcoin-lisp.networking:peer-state peer)))
     (is (null sent)
         "a malformed message must not earn a full-block refetch, sent: ~S" sent))))

(test blocktxn-invalid-completed-block-refetches-instead-of-discouraging
  "GA8 W4. The blocktxn half of the same rule: a completed reconstruction that
fails validation is still a compact-block delivery (Core emplaces mapBlockSource
with /*punish=*/false at net_processing.cpp:3516, and says so in the comment
right above it), so it gets a full-block refetch, not a discouragement."
  (%with-regtest
   (let* ((addr "203.0.113.44")
          (peer (%cbp-peer addr))
          (block-hash (%cbp-hash #xB1))
          (state (bitcoin-lisp.storage:make-chain-state))
          (utxo (bitcoin-lisp.storage:make-utxo-set)))
     (setf (bitcoin-lisp.networking:peer-pending-compact-block peer)
           (bitcoin-lisp.networking:make-pending-compact-block
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
                    (bitcoin-lisp.networking::handle-blocktxn
                     peer
                     (subseq (bitcoin-lisp.serialization:make-blocktxn-message
                              block-hash (list (make-simple-tx #x21)))
                             24)
                     state utxo nil (bitcoin-lisp.mempool:make-mempool))))))
       (is (equal '("getdata") sent)
           "an invalid completed block must be refetched in full, sent: ~S" sent)
       (is-false (bitcoin-lisp.networking:peer-discouraged-p addr)
                 "a completed compact block that fails validation must not discourage")
       (is (eq :ready (bitcoin-lisp.networking:peer-state peer)))))))

(test blocktxn-non-matching-transaction-count-punishes
  "GA8 W4 control for the blocktxn side: a blocktxn that does not answer the
getblocktxn we sent is structurally malformed -- Core's FillBlock returns
READ_STATUS_INVALID for both too few and too many transactions
(blockencodings.cpp:198-217) and Misbehaves (net_processing.cpp:3487-3491).
Previously we treated it as a mere reconstruction miss and sent a getdata."
  (%with-regtest
   (let* ((addr "203.0.113.45")
          (peer (%cbp-peer addr))
          (block-hash (%cbp-hash #xB2))
          (state (bitcoin-lisp.storage:make-chain-state))
          (utxo (bitcoin-lisp.storage:make-utxo-set)))
     (setf (bitcoin-lisp.networking:peer-pending-compact-block peer)
           (bitcoin-lisp.networking:make-pending-compact-block
            :block-hash block-hash
            :header (%cbp-grind (%cbp-header (%cbp-hash #xBC) 1296688700))
            :transactions (make-array 2 :initial-element nil)
            :missing-indexes '(0 1)          ; we asked for TWO
            :request-time (get-internal-real-time)
            :use-wtxid t))
     (let ((sent (%cbp-capture-sends
                  (lambda ()
                    (bitcoin-lisp.networking::handle-blocktxn
                     peer
                     (subseq (bitcoin-lisp.serialization:make-blocktxn-message
                              block-hash (list (make-simple-tx #x22)))  ; got ONE
                             24)
                     state utxo nil (bitcoin-lisp.mempool:make-mempool))))))
       (is-true (bitcoin-lisp.networking:peer-discouraged-p addr)
                "a non-matching blocktxn must discourage the sender")
       (is (eq :disconnected (bitcoin-lisp.networking:peer-state peer)))
       (is (null (bitcoin-lisp.networking:peer-pending-compact-block peer)))
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
  (%with-regtest
   (let* ((addr "203.0.113.46")
          (peer (%cbp-peer addr))
          (state (bitcoin-lisp.storage:make-chain-state))
          (utxo (bitcoin-lisp.storage:make-utxo-set))
          (blk (bitcoin-lisp.serialization:make-bitcoin-block
                :header (%cbp-grind (%cbp-header (%cbp-hash #xCC) 1296688700))
                :transactions (list (make-simple-tx #x31)))))
     (bitcoin-lisp.networking::handle-block
      peer (subseq (bitcoin-lisp.serialization:make-block-message blk) 24)
      state utxo nil)
     (is-true (bitcoin-lisp.networking:peer-discouraged-p addr)
              "the BLOCK path must keep punishing :ORPHAN-BLOCK (Core parity)")
     (is (eq :disconnected (bitcoin-lisp.networking:peer-state peer))))))

;;;; ====================================================================
;;;; Per-reason punishment on the compact path (GA8 W4, review finding on #326)
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
    (setf (bitcoin-lisp.serialization:block-header-bits h) #x1d00ffff
          (bitcoin-lisp.serialization:block-header-cached-hash h) nil)
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
  (%with-regtest
   (let* ((bitcoin-lisp.networking::*cached-is-ibd* nil)
          (bitcoin-lisp.networking::*compact-block-success-count* 0)
          (bitcoin-lisp.networking::*compact-block-failure-count* 0)
          (addr "203.0.113.48")
          (peer (%cbp-peer addr))
          (parent (%cbp-hash #xA4))
          (state (%cbp-state-with-parent parent 1296688600))
          (utxo (bitcoin-lisp.storage:make-utxo-set))
          (mempool (bitcoin-lisp.mempool:make-mempool))
          (hdr (%cbp-bad-pow-header parent))
          (cb (%cbp-one-tx-compact-block-with-header hdr 0 (make-simple-tx #x41)))
          (payload (%cbp-payload cb)))
     (is-false (bitcoin-lisp.validation:check-proof-of-work hdr)
               "fixture must actually fail PoW or this test asserts nothing")
     (multiple-value-bind (sent passes)
         (%cbp-count-shortid-passes
          (lambda ()
            (%cbp-capture-sends
             (lambda ()
               (dotimes (i 5)
                 (bitcoin-lisp.networking::handle-cmpctblock
                  peer payload state utxo nil mempool))))))
       (is-true (bitcoin-lisp.networking:peer-discouraged-p addr)
                "an invalid-PoW cmpctblock header must discourage its sender (Core BLOCK_INVALID_HEADER)")
       (is (eq :disconnected (bitcoin-lisp.networking:peer-state peer)))
       (is (null sent)
           "an invalid header must not earn a getdata or a getheaders, sent: ~S" sent)
       (is (zerop passes)
           "5 replays hashed the mempool ~D times; an invalid header must be rejected before BUILD-SHORTID-MAP"
           passes)
       (is (zerop bitcoin-lisp.networking::*compact-block-success-count*)
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
                 (bitcoin-lisp.networking::handle-cmpctblock
                  ok-peer (%cbp-payload ok-cb) state utxo nil mempool)))))
         (is (= 1 passes)
             "control: a valid header must still reach BUILD-SHORTID-MAP, passes: ~D" passes)
         (is (equal '("getdata") sent)
             "control: a consensus-invalid reconstruction is still refetched, sent: ~S" sent)
         (is-false (bitcoin-lisp.networking:peer-discouraged-p "203.0.113.49")
                   "control: the honest-peer exemption must survive this fix"))))))

(test cmpctblock-stale-timestamp-header-punishes
  "GA8 W4. :BAD-PROOF-OF-WORK is not the only BLOCK_INVALID_HEADER arm, and a
fix that special-cased PoW would be a different bug. A timestamp at or below the
median-time-past is Core's time-too-old (validation.cpp:4125): same arm, same
unconditional Misbehaving. The header's PoW is mined, so nothing pre-empts it."
  (%with-regtest
   (let* ((bitcoin-lisp.networking::*cached-is-ibd* nil)
          (addr "203.0.113.50")
          (peer (%cbp-peer addr))
          (parent (%cbp-hash #xA5))
          ;; The parent's timestamp is the whole MTP window here, so a header
          ;; timestamped 1296688500 is <= MTP.
          (state (%cbp-state-with-parent parent 1296688600))
          (utxo (bitcoin-lisp.storage:make-utxo-set))
          (hdr (%cbp-grind (%cbp-header parent 1296688500)))
          (cb (%cbp-one-tx-compact-block-with-header hdr 0 (make-simple-tx #x43))))
     (is-true (bitcoin-lisp.validation:check-proof-of-work hdr)
              "fixture must pass PoW or it would test the wrong arm")
     (multiple-value-bind (sent passes)
         (%cbp-count-shortid-passes
          (lambda ()
            (%cbp-capture-sends
             (lambda ()
               (bitcoin-lisp.networking::handle-cmpctblock
                peer (%cbp-payload cb) state utxo nil
                (bitcoin-lisp.mempool:make-mempool))))))
       (is-true (bitcoin-lisp.networking:peer-discouraged-p addr)
                "a time-too-old cmpctblock header must discourage its sender")
       (is (eq :disconnected (bitcoin-lisp.networking:peer-state peer)))
       (is (null sent) "sent: ~S" sent)
       (is (zerop passes) "passes: ~D" passes)))))

(test cmpctblock-header-on-invalid-parent-punishes
  "GA8 W4. BLOCK_INVALID_PREV: a header building on a block we already rejected
is Core's bad-prevblk (validation.cpp:4251-4255), the arm right beside
BLOCK_INVALID_HEADER and equally exempt from the via_compact_block amnesty."
  (%with-regtest
   (let* ((bitcoin-lisp.networking::*cached-is-ibd* nil)
          (addr "203.0.113.51")
          (peer (%cbp-peer addr))
          (parent (%cbp-hash #xA6))
          (state (%cbp-state-with-parent parent 1296688600 :status :invalid))
          (utxo (bitcoin-lisp.storage:make-utxo-set))
          (cb (%cbp-one-tx-compact-block parent 0 (make-simple-tx #x44))))
     (multiple-value-bind (sent passes)
         (%cbp-count-shortid-passes
          (lambda ()
            (%cbp-capture-sends
             (lambda ()
               (bitcoin-lisp.networking::handle-cmpctblock
                peer (%cbp-payload cb) state utxo nil
                (bitcoin-lisp.mempool:make-mempool))))))
       (is-true (bitcoin-lisp.networking:peer-discouraged-p addr)
                "a cmpctblock extending a known-invalid block must discourage its sender")
       (is (eq :disconnected (bitcoin-lisp.networking:peer-state peer)))
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
  (%with-regtest
   (let* ((bitcoin-lisp.networking::*cached-is-ibd* nil)
          (addr "203.0.113.52")
          (peer (%cbp-peer addr))
          (parent (%cbp-hash #xA7))
          (state (%cbp-state-with-parent parent 1296688600))
          (utxo (bitcoin-lisp.storage:make-utxo-set))
          ;; +3h: past Core's MAX_FUTURE_BLOCK_TIME of 2h.
          (hdr (%cbp-grind (%cbp-header parent (+ (bitcoin-lisp.serialization:get-unix-time)
                                                  10800))))
          (cb (%cbp-one-tx-compact-block-with-header hdr 0 (make-simple-tx #x45))))
     (is-true (bitcoin-lisp.validation:check-proof-of-work hdr)
              "fixture must pass PoW or it would test the wrong arm")
     (multiple-value-bind (sent passes)
         (%cbp-count-shortid-passes
          (lambda ()
            (%cbp-capture-sends
             (lambda ()
               (bitcoin-lisp.networking::handle-cmpctblock
                peer (%cbp-payload cb) state utxo nil
                (bitcoin-lisp.mempool:make-mempool))))))
       (is-false (bitcoin-lisp.networking:peer-discouraged-p addr)
                 "BLOCK_TIME_FUTURE must not discourage (our clock, not their fault)")
       (is (eq :ready (bitcoin-lisp.networking:peer-state peer)))
       (is (null sent)
           "a future-timestamped block must not be refetched either, sent: ~S" sent)
       (is (zerop passes) "passes: ~D" passes)))))

(test cmpctblock-known-invalid-block-is-dropped-without-punishment
  "GA8 W4. BLOCK_CACHED_INVALID: a compact block for a hash we already marked
invalid. Core exempts it whenever via_compact_block is true
(net_processing.cpp:1926-1935), so no discouragement — and no refetch, since
re-downloading a block we have already rejected is a self-inflicted DoS. Checked
before the parent lookup, mirroring AcceptBlockHeader (validation.cpp:4229-4237)."
  (%with-regtest
   (let* ((bitcoin-lisp.networking::*cached-is-ibd* nil)
          (addr "203.0.113.53")
          (peer (%cbp-peer addr))
          (parent (%cbp-hash #xA8))
          (state (%cbp-state-with-parent parent 1296688600))
          (utxo (bitcoin-lisp.storage:make-utxo-set))
          (cb (%cbp-one-tx-compact-block parent 0 (make-simple-tx #x46)))
          (block-hash (bitcoin-lisp.serialization:block-header-hash
                       (bitcoin-lisp.serialization:compact-block-header cb))))
     (bitcoin-lisp.storage:add-block-index-entry
      state (bitcoin-lisp.storage:make-block-index-entry
             :hash block-hash :height 1 :chain-work 2 :status :invalid
             :header (bitcoin-lisp.serialization:compact-block-header cb)))
     (multiple-value-bind (sent passes)
         (%cbp-count-shortid-passes
          (lambda ()
            (%cbp-capture-sends
             (lambda ()
               (bitcoin-lisp.networking::handle-cmpctblock
                peer (%cbp-payload cb) state utxo nil
                (bitcoin-lisp.mempool:make-mempool))))))
       (is-false (bitcoin-lisp.networking:peer-discouraged-p addr)
                 "BLOCK_CACHED_INVALID is exempt for compact-block senders")
       (is (eq :ready (bitcoin-lisp.networking:peer-state peer)))
       (is (null sent)
           "a block we already rejected must not be re-requested, sent: ~S" sent)
       (is (zerop passes) "passes: ~D" passes)))))

(test compact-block-failure-action-matches-core-arms
  "GA8 W4. The mapping table itself, arm by arm against MaybePunishNodeForBlock
with via_compact_block=true (net_processing.cpp:1908-1950). Both handlers are
thin wrappers over this, so a wrong entry here is either an unpunished attack or
an exiled honest peer."
  (flet ((action (reason) (bitcoin-lisp.networking::compact-block-failure-action reason)))
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
