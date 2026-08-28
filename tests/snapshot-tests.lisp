(in-package #:bitcoin-lisp.tests)

;;;; Assumeutxo snapshot format tests (Core dumptxoutset / loadtxoutset)
;;;;
;;;; Byte-level vectors for Core's snapshot v2 layout (node/
;;;; utxo_snapshot.h:28-106 + rpc/blockchain.cpp WriteUTXOSnapshot) with
;;;; the expected bytes assembled BY HAND from the format spec; a full
;;;; dump -> verified-load round trip through the assumeutxo-data
;;;; override hook; and the negative matrix from Core's
;;;; SnapshotMetadata::Unserialize + PopulateAndValidateSnapshot
;;;; (validation.cpp:5773-5973): bad magic/version/network, unknown or
;;;; missing base header, per-coin height/MoneyRange checks, coin-count
;;;; mismatch, truncation, trailing bytes, and hash_serialized_3
;;;; mismatch — each rejected with the node untouched.

(def-suite :snapshot-tests
  :description "Assumeutxo snapshot format (Core dumptxoutset/loadtxoutset)"
  :in :bitcoin-lisp-tests)

(in-suite :snapshot-tests)

;;;; Helpers

(defun %snap-fill (n byte)
  (make-array n :element-type '(unsigned-byte 8) :initial-element byte))

(defun %snap-cat (&rest pieces)
  "Concatenate byte-vector PIECES into one (unsigned-byte 8) vector."
  (apply #'concatenate '(vector (unsigned-byte 8)) pieces))

(defun %snap-p2pkh (hash160-byte)
  "P2PKH scriptPubKey whose key hash is 20 x HASH160-BYTE."
  (%snap-cat #(#x76 #xA9 #x14) (%snap-fill 20 hash160-byte) #(#x88 #xAC)))

(defun %snap-node (dir tip-hash tip-height)
  "A node backed by a fresh LevelDB chainstate at DIR, with genesis + a
base entry (TIP-HASH at TIP-HEIGHT, prev-linked to genesis) in the header
index. The chain tip is left at genesis (height 0) so loadtxoutset sees a
valid fast-forward. The node's data-directory is DIR — snapshot activation
creates its chainstate_snapshot/ LevelDB there."
  (let* ((chain-state (bl.store:init-chain-state dir))
         (utxo (bl.store:make-coins-view-cache
                (bl.store:open-coins-view-db
                 (ensure-directories-exist (merge-pathnames "chainstate/" dir)))))
         (node (make-test-node))
         (genesis (bl.store:best-block-hash chain-state))
         (genesis-entry (bl.store:make-block-index-entry
                         :hash genesis :height 0 :chain-work 0 :status :valid))
         (tip-entry (bl.store:make-block-index-entry
                     :hash tip-hash :height tip-height
                     :chain-work (* tip-height 100) :status :valid
                     :prev-entry genesis-entry)))
    (setf (bl::node-data-directory node) (pathname dir)
          (bl::node-chain-state node) chain-state
          (bl::node-utxo-set node) utxo
          (bl::node-block-store node)
          (bl.store:init-block-store dir))
    (bl.store:add-block-index-entry chain-state genesis-entry)
    (bl.store:add-block-index-entry chain-state tip-entry)
    node))

(defmacro %with-snap-dir ((dir) &body body)
  "Bind DIR to a fresh temp directory; delete the tree afterwards."
  `(let ((,dir (ensure-directories-exist
                (merge-pathnames (format nil "snap-~D-~D/" (get-universal-time)
                                         (random 1000000))
                                 (uiop:temporary-directory)))))
     (unwind-protect (progn ,@body)
       (uiop:delete-directory-tree ,dir :validate t :if-does-not-exist :ignore))))

(defun %snap-file-bytes (path)
  (with-open-file (in path :element-type '(unsigned-byte 8))
    (let ((bytes (make-array (file-length in) :element-type '(unsigned-byte 8))))
      (read-sequence bytes in)
      bytes)))

(defun %snap-write-bytes (path bytes)
  (with-open-file (out path :direction :output :if-exists :supersede
                            :element-type '(unsigned-byte 8))
    (write-sequence bytes out))
  path)

(defun %snap-patched (bytes offset replacement)
  "A copy of BYTES with REPLACEMENT spliced in at OFFSET."
  (let ((copy (copy-seq bytes)))
    (replace copy replacement :start1 offset)
    copy))

(defun %snap-write-file (path &key (magic #(#x75 #x74 #x78 #x6F #xFF))
                                   (version 2)
                                   (netmagic (bl.chain:chain-params-magic (bl.chain:find-chain-params :testnet3)))
                                   base-hash count groups (trailing #()))
  "Craft an arbitrary snapshot file. GROUPS is a list of (txid . coins),
each coin (vout height coinbase value script)."
  (with-open-file (out path :direction :output :if-exists :supersede
                            :element-type '(unsigned-byte 8))
    (write-sequence (coerce magic '(vector (unsigned-byte 8))) out)
    (bl.ser:write-uint16-le out version)
    (write-sequence netmagic out)
    (write-sequence base-hash out)
    (bl.ser:write-uint64-le out count)
    (dolist (group groups)
      (let ((buf (bl.ser:make-byte-buf)))
        (bl.ser:bb-write-bytes buf (car group))
        (bl.ser:bb-write-varint buf (length (cdr group)))
        (dolist (coin (cdr group))
          (destructuring-bind (vout height coinbase value script) coin
            (bl.ser:bb-write-varint buf vout)
            (bl.ser:bb-write-compressed-coin
             buf height coinbase value script)))
        (write-sequence (bl.ser:bb-finish buf) out)))
    (write-sequence (coerce trailing '(vector (unsigned-byte 8))) out))
  path)

(defun %snap-load-err (node path)
  "Run loadtxoutset; return the signalled rpc-error, or NIL on success."
  (handler-case
      (progn (bl.rpc::rpc-loadtxoutset node (list (namestring path)))
             nil)
    (bl.rpc::rpc-error (e) e)))

(defun %snap-err-matches (err code substring)
  (and err
       (= code (bl.rpc::rpc-error-code err))
       (search substring (bl.rpc::rpc-error-message err))))

(defun %snap-hash (coins)
  "hash_serialized_3 over COINS ((txid vout height coinbase value script)),
which must already be in cursor order: double-SHA256 of the concatenated
per-coin preimages (kernel/coinstats.cpp:46-52,111-181)."
  (bl.crypto:hash256
   (apply #'%snap-cat
          (mapcar (lambda (c)
                    (destructuring-bind (txid vout height coinbase value script) c
                      (bl.store:coin-muhash-element
                       txid vout height coinbase value
                       (coerce script '(simple-array (unsigned-byte 8) (*))))))
                  coins))))

(defun %snap-au (height blockhash hash-serialized &optional (chain-tx-count 1))
  (bl:make-assumeutxo-data
   :height height
   :blockhash blockhash
   :hash-serialized (coerce hash-serialized '(simple-array (unsigned-byte 8) (32)))
   :chain-tx-count chain-tx-count))

;;;; Tests

(test snapshot-dump-byte-exact
  "dumptxoutset writes Core's snapshot v2 layout byte-for-byte: 5-byte
magic, u16 version, network magic, base hash, u64 count, then txid groups
in cursor order with CompactSize vouts and compressed Coin records. The
expected bytes are assembled by hand from the format spec."
  (%with-snap-dir (dir)
    (let* ((h5 (%snap-fill 32 5))
           (txid-a (%snap-fill 32 #x11))
           (txid-b (%snap-fill 32 #x22))
           (node (%snap-node dir h5 5))
           (utxo (bl::node-utxo-set node))
           (snap (namestring (merge-pathnames "utxo.dat" dir))))
      ;; Give the tip entry a known per-block tx count so nchaintx (walk
      ;; to genesis: 3 + genesis' 1) is reportable.
      (setf (bl.store:block-index-entry-tx-count
             (bl.store:get-block-index-entry
              (bl::node-chain-state node) h5))
            3)
      (bl.store:update-chain-tip
       (bl::node-chain-state node) h5 5)
      ;; Insert in scrambled order; the dump cursor must normalize to
      ;; txid-lex + numeric-vout order (incl. vout 300 > 255, whose LE
      ;; byte order differs from numeric order).
      (bl.store:add-utxo utxo txid-b 1 0 (%snap-cat #(#x6A)) 5)
      (bl.store:add-utxo utxo txid-a 300 999 (%snap-cat #(#x51 #x52 #x53)) 4)
      (bl.store:add-utxo utxo txid-a 0 4200000000 (%snap-p2pkh #xAA) 3
                                     :coinbase t)
      (let ((r (bl.rpc::rpc-dumptxoutset node (list snap "latest")))
            (expected
              (%snap-cat
               ;; --- SnapshotMetadata ---
               #(#x75 #x74 #x78 #x6F #xFF)   ; "utxo" + 0xff
               #(#x02 #x00)                  ; version 2, u16 LE
               #(#x0B #x11 #x09 #x07)        ; testnet3 message magic
               (%snap-fill 32 5)             ; base blockhash
               #(3 0 0 0 0 0 0 0)            ; coin count, u64 LE
               ;; --- txid-a group (2 coins) ---
               (%snap-fill 32 #x11)
               #(#x02)
               #(#x00)                       ; vout 0 (CompactSize)
               #(#x07)                       ; VARINT(2*3+1): h=3, coinbase
               #(#x81 #x7B)                  ; VARINT(379) = amount 42e8 compressed
               #(#x00)                       ; P2PKH special form id
               (%snap-fill 20 #xAA)          ; key hash
               #(#xFD #x2C #x01)             ; vout 300 (CompactSize)
               #(#x08)                       ; VARINT(2*4): h=4
               #(#xC5 #x1F)                  ; VARINT(8991) = amount 999 compressed
               #(#x09 #x51 #x52 #x53)        ; raw script: VARINT(3+6) + bytes
               ;; --- txid-b group (1 coin) ---
               (%snap-fill 32 #x22)
               #(#x01)
               #(#x01)                       ; vout 1
               #(#x0A)                       ; VARINT(2*5): h=5
               #(#x00)                       ; amount 0 compressed
               #(#x07 #x6A))))               ; raw script: VARINT(1+6) + OP_RETURN
        (is (equalp expected (%snap-file-bytes snap)))
        (is (= 3 (cdr (assoc "coins_written" r :test #'string=))))
        (is (= 5 (cdr (assoc "base_height" r :test #'string=))))
        (is (string= (bl.rpc::hash-to-hex h5)
                     (cdr (assoc "base_hash" r :test #'string=))))
        ;; Same-pass hash matches the P1 whole-set hasher.
        (is (string= (bl.rpc::hash-to-hex
                      (bl.store:compute-utxo-set-hash utxo))
                     (cdr (assoc "txoutset_hash" r :test #'string=))))
        ;; nchaintx = tip 3 + genesis 1.
        (is (= 4 (cdr (assoc "nchaintx" r :test #'string=)))))
      ;; Existing path, rollback type, and unknown type are all refused.
      (signals bl.rpc::rpc-error
        (bl.rpc::rpc-dumptxoutset node (list snap "latest")))
      (signals bl.rpc::rpc-error
        (bl.rpc::rpc-dumptxoutset
         node (list (namestring (merge-pathnames "r.dat" dir)) "rollback")))
      (signals bl.rpc::rpc-error
        (bl.rpc::rpc-dumptxoutset
         node (list (namestring (merge-pathnames "t.dat" dir)) "bogus")))
      ;; The failed calls above must not leave .incomplete litter.
      (is (null (probe-file (concatenate 'string snap ".incomplete")))))))

(test snapshot-roundtrip-verified
  "dumptxoutset -> loadtxoutset round-trips through the full verification
gate: an injected assumeutxo-data entry carrying the real hash_serialized_3
accepts the snapshot into a NEW snapshot chainstate that becomes the current
chainstate at the base height, while the previous chainstate is retargeted
at the base (historical). The base entry's tx-count is seeded from nChainTx."
  (%with-snap-dir (src-dir)
    (%with-snap-dir (dst-dir)
      (let* ((bl:*prune-target-mib* nil) ; deterministic: pruning off
             (h5 (%snap-fill 32 5))
             (txid-a (%snap-fill 32 #x11))
             (txid-b (%snap-fill 32 #x22))
             (txid-s (%snap-fill 32 #xEE))   ; pre-existing coin, not in snapshot
             (spk-a (%snap-p2pkh #xAA))
             (spk-raw (%snap-cat #(#x51 #x52 #x53)))
             (src (%snap-node src-dir h5 5))
             (snap (namestring (merge-pathnames "utxo.dat" src-dir))))
        (bl.store:update-chain-tip
         (bl::node-chain-state src) h5 5)
        (let ((utxo (bl::node-utxo-set src)))
          (bl.store:add-utxo utxo txid-a 0 4200000000 spk-a 3 :coinbase t)
          (bl.store:add-utxo utxo txid-a 300 999 spk-raw 4)
          (bl.store:add-utxo utxo txid-b 1 12345 spk-raw 5))
        (let* ((expected-hash (bl.store:compute-utxo-set-hash
                               (bl::node-utxo-set src)))
               (r (bl.rpc::rpc-dumptxoutset src (list snap "latest"))))
          (is (string= (bl.rpc::hash-to-hex expected-hash)
                       (cdr (assoc "txoutset_hash" r :test #'string=))))
          (let* ((dst (%snap-node dst-dir h5 5))
                 (primary (bl::node-chain-state dst))
                 (primary-utxo (bl::node-utxo-set dst)))
            ;; Pre-existing primary-chainstate coin: must NOT appear in the
            ;; snapshot chainstate's view, but survives in the primary's.
            (bl.store:add-utxo primary-utxo txid-s 0 777 spk-raw 1)
            (bl.store:coins-view-cache-flush primary-utxo)
            (let ((bl:*assumeutxo-data-override*
                    (list (%snap-au 5 h5 expected-hash 4242))))
              (let ((r2 (bl.rpc::rpc-loadtxoutset dst (list snap))))
                (is (= 3 (cdr (assoc "coins_loaded" r2 :test #'string=))))
                (is (= 5 (cdr (assoc "base_height" r2 :test #'string=))))
                (is (string= (bl.rpc::hash-to-hex h5)
                             (cdr (assoc "tip_hash" r2 :test #'string=)))))
              ;; The CURRENT chainstate is now the snapshot chainstate at the
              ;; base; the primary became historical (target = base).
              (let ((current (bl::node-current-chainstate dst))
                    (historical (bl::node-historical-chainstate dst))
                    (dst-utxo (bl::node-utxo-set dst)))
                (is (not (eq current primary)))
                (is (eq historical primary))
                (is (= 2 (length (bl::node-chainstates dst))))
                (is (equalp h5 (bl.store:chain-state-from-snapshot-blockhash
                                current)))
                (is (eq :unvalidated
                        (bl.store:chain-state-assumeutxo-status current)))
                (is (string= "_snapshot"
                             (bl.store:chain-state-storage-suffix current)))
                (is (equalp h5 (bl.store:chain-state-target-blockhash
                                primary)))
                (is (eq primary (bl::node-validated-chainstate dst)))
                ;; Both chainstates share ONE block index (Core m_blockman).
                (is (eq (bl.store::chain-state-block-index primary)
                        (bl.store::chain-state-block-index current)))
                ;; Tip fast-forwarded; nChainTx seeded on the base entry.
                (is (= 5 (bl.store:current-height current)))
                (is (equalp h5 (bl.store:best-block-hash current)))
                (is (= 0 (bl.store:current-height primary)))
                (is (= 4242 (bl.store:block-index-entry-tx-count
                             (bl.store:get-block-index-entry current h5))))
                ;; The persistent base_blockhash marker exists and is exact.
                (let ((marker (bl.store:read-snapshot-base-blockhash
                               (bl.store:find-assumeutxo-chainstate-dir
                                dst-dir))))
                  (is (equalp h5 marker)))
                ;; Snapshot coins present and exact in the CURRENT view.
                (let ((a (bl.store:get-utxo dst-utxo txid-a 0))
                      (a300 (bl.store:get-utxo dst-utxo txid-a 300))
                      (b (bl.store:get-utxo dst-utxo txid-b 1)))
                  (is (and a (= 4200000000 (bl.store:utxo-entry-value a))))
                  (is (bl.store:utxo-entry-coinbase a))
                  (is (equalp spk-a (bl.store:utxo-entry-script-pubkey a)))
                  (is (and a300 (= 999 (bl.store:utxo-entry-value a300))))
                  (is (= 4 (bl.store:utxo-entry-height a300)))
                  (is (and b (= 12345 (bl.store:utxo-entry-value b))))
                  (is (not (bl.store:utxo-entry-coinbase b))))
                ;; The primary's coin is not in the snapshot view — and is
                ;; UNTOUCHED in the primary's own view (no wipe).
                (is (null (bl.store:get-utxo dst-utxo txid-s 0)))
                (let ((stale (bl.store:get-utxo primary-utxo txid-s 0)))
                  (is (and stale (= 777 (bl.store:utxo-entry-value stale)))))
                ;; The loaded set re-hashes to the committed value.
                (is (equalp expected-hash
                            (bl.store:compute-utxo-set-hash dst-utxo))))
              ;; Loading again fails: a snapshot chainstate already exists.
              (is (%snap-err-matches (%snap-load-err dst snap)
                                     -32603 "more than once")))))))))

(test snapshot-load-multibatch-straddle
  "A txid group that straddles a durable-load batch boundary must load, not
be rejected as a coins-count mismatch. The coin stream is committed to the
snapshot LevelDB in batches; Core's coins_per_txid>coins_left guard
(validation.cpp:5823) is against the GLOBAL remaining, so a group larger than
the batch budget is consumed whole. With the batch budget pinned to 2 and
txid-a carrying 3 coins, the group crosses the first commit — the exact shape
that made every real multi-batch public snapshot (>100k coins) fail before."
  (%with-snap-dir (src-dir)
    (%with-snap-dir (dst-dir)
      (let* ((bl:*prune-target-mib* nil)
             (bl.rpc::*snapshot-load-batch-coins* 2) ; tiny batches
             (h5 (%snap-fill 32 5))
             (txid-a (%snap-fill 32 #x11))
             (txid-b (%snap-fill 32 #x22))
             (spk-a (%snap-p2pkh #xAA))
             (spk-raw (%snap-cat #(#x51 #x52 #x53)))
             (src (%snap-node src-dir h5 5))
             (snap (namestring (merge-pathnames "utxo.dat" src-dir))))
        (bl.store:update-chain-tip
         (bl::node-chain-state src) h5 5)
        (let ((utxo (bl::node-utxo-set src)))
          ;; txid-a: 3 coins (straddles batch size 2); txid-b: 2 coins.
          (bl.store:add-utxo utxo txid-a 0 4200000000 spk-a 3 :coinbase t)
          (bl.store:add-utxo utxo txid-a 1 999 spk-raw 4)
          (bl.store:add-utxo utxo txid-a 2 1000 spk-raw 4)
          (bl.store:add-utxo utxo txid-b 0 12345 spk-raw 5)
          (bl.store:add-utxo utxo txid-b 1 6789 spk-raw 5))
        (let ((expected-hash (bl.store:compute-utxo-set-hash
                              (bl::node-utxo-set src))))
          (bl.rpc::rpc-dumptxoutset src (list snap "latest"))
          (let ((dst (%snap-node dst-dir h5 5))
                (bl:*assumeutxo-data-override*
                  (list (%snap-au 5 h5 expected-hash 4242))))
            (let ((r (bl.rpc::rpc-loadtxoutset dst (list snap))))
              (is (= 5 (cdr (assoc "coins_loaded" r :test #'string=))))
              (is (= 5 (cdr (assoc "base_height" r :test #'string=)))))
            (let ((dst-utxo (bl::node-utxo-set dst)))
              ;; Every coin landed and the set re-hashes to the commitment.
              (is (equalp expected-hash
                          (bl.store:compute-utxo-set-hash dst-utxo)))
              (is (bl.store:get-utxo dst-utxo txid-a 2))
              (is (bl.store:get-utxo dst-utxo txid-b 1)))))))))

(test snapshot-metadata-rejections
  "SnapshotMetadata parsing rejects bad magic, unsupported version, wrong
or unrecognized network magic, and a truncated header — all as
RPC_DESERIALIZATION_ERROR before any state is read (utxo_snapshot.h:73-106)."
  (%with-snap-dir (dir)
    (let* ((h5 (%snap-fill 32 5))
           (node (%snap-node dir h5 5))
           (base (%snap-file-bytes
                  (%snap-write-file (merge-pathnames "ok.dat" dir)
                                    :base-hash h5 :count 0)))
           (bad (merge-pathnames "bad.dat" dir)))
      ;; Missing file: invalid-parameter, not deserialization.
      (is (%snap-err-matches
           (%snap-load-err node (merge-pathnames "nope.dat" dir))
           -8 "Couldn't open file"))
      ;; Bad magic byte.
      (%snap-write-bytes bad (%snap-patched base 0 #(#x00)))
      (is (%snap-err-matches (%snap-load-err node bad)
                             -22 "Invalid UTXO set snapshot magic bytes"))
      ;; Unsupported version (1).
      (%snap-write-bytes bad (%snap-patched base 5 #(#x01 #x00)))
      (is (%snap-err-matches (%snap-load-err node bad)
                             -22 "Version of snapshot 1"))
      ;; Wrong (but known) network: mainnet snapshot on a testnet3 node.
      (%snap-write-bytes bad (%snap-patched base 7 #(#xF9 #xBE #xB4 #xD9)))
      (is (%snap-err-matches (%snap-load-err node bad)
                             -22 "network of the snapshot (main)"))
      ;; Unrecognized network magic.
      (%snap-write-bytes bad (%snap-patched base 7 #(#xDE #xAD #xBE #xEF)))
      (is (%snap-err-matches (%snap-load-err node bad)
                             -22 "unrecognized network"))
      ;; Truncated header.
      (%snap-write-bytes bad (subseq base 0 30))
      (is (%snap-err-matches (%snap-load-err node bad)
                             -22 "truncated snapshot header")))))

(test snapshot-precondition-rejections
  "ActivateSnapshot's preconditions (validation.cpp:5616-5650): unknown
assumeutxo hash, base header missing from the index, commitment/index
height mismatch, invalid base header, tip already at the base height, and
a non-empty mempool — all rejected before the coin stream is touched."
  (%with-snap-dir (dir)
    (let* ((bl:*prune-target-mib* nil) ; deterministic: pruning off
           (h5 (%snap-fill 32 5))
           (h7 (%snap-fill 32 7))
           (zero32 (%snap-fill 32 0))
           (node (%snap-node dir h5 5))
           (chain (bl::node-chain-state node))
           (snap5 (%snap-write-file (merge-pathnames "b5.dat" dir)
                                    :base-hash h5 :count 0))
           (snap7 (%snap-write-file (merge-pathnames "b7.dat" dir)
                                    :base-hash h7 :count 0)))
      ;; No assumeutxo-data entry for the base hash.
      (let ((bl:*assumeutxo-data-override*
              (list (%snap-au 7 h7 zero32))))
        (is (%snap-err-matches (%snap-load-err node snap5)
                               -32603 "not recognized"))
        ;; Entry exists but the base header is not in our block index.
        (is (%snap-err-matches (%snap-load-err node snap7)
                               -32603 "must appear in the headers chain")))
      ;; Commitment height disagrees with the indexed header's height.
      (let ((bl:*assumeutxo-data-override*
              (list (%snap-au 9 h5 zero32))))
        (is (%snap-err-matches (%snap-load-err node snap5)
                               -32603 "height in snapshot metadata not recognized")))
      (let ((bl:*assumeutxo-data-override*
              (list (%snap-au 5 h5 zero32)))
            (entry (bl.store:get-block-index-entry chain h5)))
        ;; Base header marked invalid.
        (setf (bl.store:block-index-entry-status entry) :invalid)
        (is (%snap-err-matches (%snap-load-err node snap5)
                               -32603 "part of an invalid chain"))
        (setf (bl.store:block-index-entry-status entry) :valid)
        ;; Mempool not empty.
        (let* ((tx (bl.ser:make-transaction
                    :version 1
                    :inputs (vector (bl.ser:make-tx-in
                                     :previous-output (bl.ser:make-outpoint
                                                       :hash zero32 :index #xffffffff)
                                     :script-sig (%snap-fill 1 #x51)
                                     :sequence #xffffffff))
                    :outputs (vector (bl.ser:make-tx-out
                                      :value 1000 :script-pubkey (%snap-cat #(#x6A))))
                    :lock-time 0))
               (mp (bl::node-mempool node)))
          ;; make-entry-from-tx: raw make-mempool-entry has vsize 0, which
          ;; the shadow txgraph (added in cluster mempool P3) rejects.
          (bl.mp:mempool-add
           mp (bl.ser:transaction-hash tx)
           (bl.mp:make-entry-from-tx tx 0 0))
          (is (%snap-err-matches (%snap-load-err node snap5)
                                 -32603 "mempool not empty"))
          (setf (bl::node-mempool node) (bl.mp:make-mempool)))
        ;; Tip already at the base height.
        (bl.store:update-chain-tip chain h5 5)
        (is (%snap-err-matches (%snap-load-err node snap5)
                               -32603 "Work does not exceed"))))))

(test snapshot-content-rejections
  "PopulateAndValidateSnapshot's per-coin and stream checks (validation.cpp
:5816-5936): coin height above the base, MoneyRange violation, group
claiming more coins than the metadata count, truncation, trailing bytes,
an out-of-range vout, and a hash_serialized_3 mismatch. Every rejection
leaves the node's UTXO set and tip untouched."
  (%with-snap-dir (dir)
    (let* ((bl:*prune-target-mib* nil) ; deterministic: pruning off
           (h5 (%snap-fill 32 5))
           (txid (%snap-fill 32 #x33))
           (txid-s (%snap-fill 32 #xEE))
           (spk (%snap-cat #(#x51)))
           (node (%snap-node dir h5 5))
           (chain (bl::node-chain-state node))
           (utxo (bl::node-utxo-set node))
           (good-coin (list txid 0 1 nil 1000 spk))
           (good-hash (%snap-hash (list good-coin)))
           (f (merge-pathnames "c.dat" dir)))
      ;; Pre-existing coin: must survive every failed load below.
      (bl.store:add-utxo utxo txid-s 0 777 spk 1)
      (bl.store:coins-view-cache-flush utxo)
      (let ((bl:*assumeutxo-data-override*
              (list (%snap-au 5 h5 good-hash))))
        (flet ((rejects (substring &rest file-args)
                 (apply #'%snap-write-file f :base-hash h5 file-args)
                 (let ((err (%snap-load-err node f)))
                   (is (%snap-err-matches err -32603 substring)
                       "expected ~S in: ~A" substring
                       (and err (bl.rpc::rpc-error-message err))))))
          ;; Coin height above the snapshot base.
          (rejects "Bad snapshot data after deserializing 0 coins"
                   :count 1 :groups `((,txid (0 6 nil 1000 ,spk))))
          ;; MoneyRange violation.
          (rejects "bad tx out value"
                   :count 1
                   :groups `((,txid (0 1 nil ,(1+ bl.val:+max-money+)
                                       ,spk))))
          ;; Group claims more coins than the metadata has left.
          (rejects "Mismatch in coins count"
                   :count 1 :groups `((,txid (0 1 nil 1000 ,spk)
                                             (1 1 nil 1000 ,spk))))
          ;; Truncated: metadata promises a second coin that isn't there.
          (rejects "truncated snapshot"
                   :count 2 :groups `((,txid (0 1 nil 1000 ,spk))))
          ;; Trailing bytes after the last coin.
          (rejects "coins left over"
                   :count 1 :groups `((,txid (0 1 nil 1000 ,spk)))
                   :trailing #(#x00))
          ;; vout beyond ReadCompactSize's MAX_SIZE range check.
          (rejects "Bad snapshot"
                   :count 1 :groups `((,txid (#x03000000 1 nil 1000 ,spk))))
          ;; Content hash mismatch (valid stream, wrong committed hash).
          (let ((bl:*assumeutxo-data-override*
                  (list (%snap-au 5 h5 (%snap-fill 32 0)))))
            (rejects "Bad snapshot content hash"
                     :count 1 :groups `((,txid (0 1 nil 1000 ,spk))))))
        ;; No partial state from any of the failures: the primary chainstate
        ;; is untouched AND the aborted snapshot chainstate dir was deleted
        ;; (Core cleanup_bad_snapshot).
        (is (null (bl.store:get-utxo utxo txid 0)))
        (let ((stale (bl.store:get-utxo utxo txid-s 0)))
          (is (and stale (= 777 (bl.store:utxo-entry-value stale)))))
        (is (= 0 (bl.store:current-height chain)))
        (is (= 1 (length (bl::node-chainstates node))))
        (is (null (bl.store:find-assumeutxo-chainstate-dir dir)))
        ;; Control: the same 1-coin file with the right hash loads cleanly
        ;; into a snapshot chainstate that becomes current.
        (%snap-write-file f :base-hash h5 :count 1
                            :groups `((,txid (0 1 nil 1000 ,spk))))
        (is (null (%snap-load-err node f)))
        (let ((current (bl::node-chain-state node))
              (current-utxo (bl::node-utxo-set node)))
          (is (not (eq current chain)))
          (is (= 5 (bl.store:current-height current)))
          (is (= 0 (bl.store:current-height chain)))
          (let ((c (bl.store:get-utxo current-utxo txid 0)))
            (is (and c (= 1000 (bl.store:utxo-entry-value c)))))
          (is (null (bl.store:get-utxo current-utxo txid-s 0))))))))

(test snapshot-assumeutxo-tables
  "The shipped assumeutxo-data tables mirror Bitcoin Core's
kernel/chainparams.cpp m_assumeutxo_data exactly (heights per network,
spot-checked hashes and chain tx counts)."
  (flet ((heights (net)
           (mapcar #'bl:assumeutxo-data-height
                   (bl:network-assumeutxo-data net)))
         (display (bytes)
           (bl.crypto:bytes-to-hex (reverse bytes))))
    (is (equal '(840000 880000 910000 935000) (heights :mainnet)))
    (is (equal '(2500000 4840000) (heights :testnet3)))
    (is (equal '(90000 120000) (heights :testnet4)))
    (is (equal '(160000 290000) (heights :signet)))
    (is (equal '(110 200 299) (heights :regtest)))
    (dolist (net '(:mainnet :testnet3 :testnet4 :signet :regtest))
      (dolist (e (bl:network-assumeutxo-data net))
        (is (= 32 (length (bl:assumeutxo-data-blockhash e))))
        (is (= 32 (length (bl:assumeutxo-data-hash-serialized e))))
        (is (plusp (bl:assumeutxo-data-chain-tx-count e)))))
    (let ((m840k (first (bl:network-assumeutxo-data :mainnet)))
          (t90k (first (bl:network-assumeutxo-data :testnet4))))
      (is (string= "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"
                   (display (bl:assumeutxo-data-blockhash m840k))))
      (is (string= "a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96"
                   (display (bl:assumeutxo-data-hash-serialized m840k))))
      (is (= 991032194 (bl:assumeutxo-data-chain-tx-count m840k)))
      (is (string= "0000000002ebe8bcda020e0dd6ccfbdfac531d2f6a81457191b99fc2df2dbe3b"
                   (display (bl:assumeutxo-data-blockhash t90k))))
      (is (= 11347043 (bl:assumeutxo-data-chain-tx-count t90k)))
      ;; Blockhash lookup finds the entry; a random hash doesn't. (The
      ;; table is rebuilt per call, so compare contents, not identity.)
      (is (equalp m840k (bl:assumeutxo-data-for-blockhash
                         :mainnet (bl:assumeutxo-data-blockhash m840k))))
      (is (null (bl:assumeutxo-data-for-blockhash
                 :mainnet (%snap-fill 32 #x99)))))
    ;; The override hook replaces the built-in table outright.
    (let ((bl:*assumeutxo-data-override*
            (list (%snap-au 42 (%snap-fill 32 1) (%snap-fill 32 2)))))
      (is (equal '(42) (heights :mainnet))))))

(test snapshot-stream-codec-parity
  "The stream-based compressed-coin readers match the byte-reader codec:
Core VARINT values round-trip, a compressed Coin record round-trips, and
an oversized raw script is skipped and replaced with OP_RETURN."
  ;; VARINT parity across the serialize.h example values.
  (dolist (n '(0 1 127 128 255 16383 16384 16511 65535 4294967295
               18446744073709551615))
    (let ((buf (bl.ser:make-byte-buf)))
      (bl.ser:bb-write-core-varint buf n)
      (flexi-streams:with-input-from-sequence
          (s (bl.ser:bb-finish buf))
        (is (= n (bl.ser:read-core-varint s))))))
  ;; Compressed Coin record round-trip through the stream reader.
  (let ((script (%snap-p2pkh #x42))
        (buf (bl.ser:make-byte-buf)))
    (bl.ser:bb-write-compressed-coin buf 1000 t 123456789 script)
    (flexi-streams:with-input-from-sequence
        (s (bl.ser:bb-finish buf))
      (multiple-value-bind (height coinbase value out-script)
          (bl.ser:read-compressed-coin s)
        (is (= 1000 height))
        (is (eq t (and coinbase t)))
        (is (= 123456789 value))
        (is (equalp script out-script)))))
  ;; Oversized raw script (> MAX_SCRIPT_SIZE): skipped, OP_RETURN returned,
  ;; stream left positioned exactly after it (compressor.h:87-90).
  (let ((big (%snap-fill 10001 #x00))
        (buf (bl.ser:make-byte-buf)))
    (bl.ser:bb-write-compressed-script buf big)
    (bl.ser:bb-write-core-varint buf 7)  ; sentinel after
    (flexi-streams:with-input-from-sequence
        (s (bl.ser:bb-finish buf))
      (is (equalp #(#x6A) (bl.ser:read-compressed-script s)))
      (is (= 7 (bl.ser:read-core-varint s))))))

;;;; Assumeutxo P6: pruned-node activation + dumptxoutset rollback

(test snapshot-load-on-pruned-node
  "loadtxoutset works on a pruned node (P6 lifts the P4 refusal; Core's
loadtxoutset has no pruned check — safety comes from the per-chainstate
prune floor, Chainstate::GetPruneRange, and the halved automatic target,
FindFilesToPrune). Activation also splits the coins-cache budget 95/5
toward the snapshot chainstate while the node is in IBD (Core
MaybeRebalanceCaches via ActivateSnapshot)."
  (%with-snap-dir (src-dir)
    (%with-snap-dir (dst-dir)
      (let* ((bl:*prune-target-mib* 550)   ; pruning ON
             (bl:*prune-after-height* 0)
             (h5 (%snap-fill 32 5))
             (txid (%snap-fill 32 #x33))
             (spk (%snap-cat #(#x51)))
             (src (%snap-node src-dir h5 5))
             (snap-path (namestring (merge-pathnames "utxo.dat" src-dir))))
        (bl.store:update-chain-tip
         (bl::node-chain-state src) h5 5)
        (bl.store:add-utxo (bl::node-utxo-set src)
                                       txid 0 1000 spk 1)
        (bl.rpc::rpc-dumptxoutset src (list snap-path "latest"))
        (let* ((hash (bl.store:compute-utxo-set-hash
                      (bl::node-utxo-set src)))
               (dst (%snap-node dst-dir h5 5))
               (bl:*assumeutxo-data-override*
                 (list (%snap-au 5 h5 hash 7)))
               (bl.net::*cached-is-ibd* t))
          (let ((r (bl.rpc::rpc-loadtxoutset dst (list snap-path))))
            (is (= 1 (cdr (assoc "coins_loaded" r :test #'string=)))))
          (is (= 2 (length (bl::node-chainstates dst))))
          (let ((current (bl::node-current-chainstate dst))
                (historical (bl::node-historical-chainstate dst))
                (store (bl::node-block-store dst)))
            ;; Per-chainstate prune ranges: the snapshot chainstate may never
            ;; prune at or below its base; the historical prunes from 0.
            (is (= 5 (bl.store:chain-state-prune-floor current)))
            (is (= 0 (bl.store:chain-state-prune-floor historical)))
            ;; An over-target automatic prune driven by the snapshot
            ;; chainstate deletes nothing at or below the base.
            (setf (bl.store:block-store-total-bytes store)
                  (* 600 1048576))
            (let ((bl::*node* dst))
              (is (= 0 (bl.store:prune-old-blocks
                        store current
                        :target-bytes (bl:effective-prune-target-bytes))))
              ;; The automatic target is halved (floored at 550 MiB) while
              ;; the historical chainstate exists.
              (is (= bl:+min-disk-space-for-block-files+
                     (bl:effective-prune-target-bytes)))
              (let ((bl:*prune-target-mib* 2000))
                (is (= (* 1000 1048576)
                       (bl:effective-prune-target-bytes)))))
            ;; Activation rebalanced the coins-cache budget: 95% to the
            ;; snapshot (current) chainstate during IBD, 5% historical.
            (let ((total bl::*coins-cache-budget-bytes*))
              (is (= (floor (* total 0.95d0))
                     (bl.store:chain-state-coins-cache-bytes current)))
              (is (= (floor (* total 0.05d0))
                     (bl.store:chain-state-coins-cache-bytes historical)))
              (is (= (floor (* total 0.95d0))
                     (bl::chainstate-coins-cache-budget current))))))))))

(test snapshot-dump-rollback-roundtrip
  "dumptxoutset with a rollback target (Core rpc/blockchain.cpp:3034-3196):
the active chain is temporarily rolled back via invalidateblock (network
activity suspended during, restored after — reverse RAII order), the UTXO
set is dumped at the target height, and the chain is restored with
reconsiderblock. The historical dump re-loads through loadtxoutset's full
verification gate on a fresh node."
  (%with-mainnet-network
   (%with-snap-dir (dst-dir)
     (multiple-value-bind (cs utxo store genesis-hash)
         (%make-activate-block-fixture "rollback-dump")
       (let* ((bl:*prune-target-mib* nil)
              (node (bl::make-node :network :testnet3))
              (hashes (make-test-chain-hashes #xD1 4))
              (h2 (second hashes))
              (dump-path (namestring (merge-pathnames "rollback.dat" dst-dir))))
         (setf (bl.store:chain-state-coins-view cs) utxo
               (bl::node-chainstates node) (list cs)
               (bl::node-block-store node) store)
         (%build-and-connect cs store utxo genesis-hash hashes)
         (is (= 4 (bl.store:current-height cs)))
         (let ((tip-hash (bl.store:best-block-hash cs))
               (pre-dump-hash (bl.store:compute-utxo-set-hash utxo))
               (opts (make-hash-table :test 'equal)))
           (setf (gethash "rollback" opts) 2)
           ;; --- Parameter/precondition matrix (before any state change) ---
           ;; A non-rollback type conflicting with the rollback option.
           (signals bl.rpc::rpc-error
             (bl.rpc::rpc-dumptxoutset
              node (list (namestring (merge-pathnames "x1.dat" dst-dir))
                         "latest" opts)))
           ;; Rollback target above the tip.
           (let ((bad (make-hash-table :test 'equal)))
             (setf (gethash "rollback" bad) 99)
             (signals bl.rpc::rpc-error
               (bl.rpc::rpc-dumptxoutset
                node (list (namestring (merge-pathnames "x2.dat" dst-dir))
                           "rollback" bad))))
           ;; Negative rollback target.
           (let ((bad (make-hash-table :test 'equal)))
             (setf (gethash "rollback" bad) -1)
             (signals bl.rpc::rpc-error
               (bl.rpc::rpc-dumptxoutset
                node (list (namestring (merge-pathnames "x3.dat" dst-dir))
                           "rollback" bad))))
           ;; Pruned refusal: block data below the target already gone.
           (let ((bl:*prune-target-mib* 550))
             (setf (bl.store:chain-state-pruned-height cs) 2)
             (let ((err (handler-case
                            (progn (bl.rpc::rpc-dumptxoutset
                                    node (list (namestring
                                                (merge-pathnames "x4.dat" dst-dir))
                                               "rollback" opts))
                                   nil)
                          (bl.rpc::rpc-error (e) e))))
               (is (%snap-err-matches err -1 "already pruned")))
             (setf (bl.store:chain-state-pruned-height cs) 0))
           ;; --- The real rollback dump (positional options form) ---
           (is (eq t (bl::node-network-active node)))
           (let ((r (bl.rpc::rpc-dumptxoutset
                     node (list dump-path "rollback" opts))))
             (is (= 2 (cdr (assoc "base_height" r :test #'string=))))
             (is (string= (bl.rpc::hash-to-hex h2)
                          (cdr (assoc "base_hash" r :test #'string=))))
             (is (= 2 (cdr (assoc "coins_written" r :test #'string=))))
             ;; Chain fully restored: original tip, nothing left invalid,
             ;; the UTXO set re-hashes to its pre-dump value, and network
             ;; activity is back on.
             (is (= 4 (bl.store:current-height cs)))
             (is (equalp tip-hash (bl.store:best-block-hash cs)))
             (is (not (eq :invalid (bl.store:block-index-entry-status
                                    (bl.store:get-block-index-entry
                                     cs (third hashes))))))
             (is (equalp pre-dump-hash
                         (bl.store:compute-utxo-set-hash utxo)))
             (is (eq t (bl::node-network-active node)))
             ;; --- Verified re-load of the historical dump ---
             (let* ((dump-hash (bl.rpc::parse-hex-hash
                                (cdr (assoc "txoutset_hash" r :test #'string=))))
                    (dst (%snap-node dst-dir h2 2))
                    (bl:*assumeutxo-data-override*
                      (list (%snap-au 2 h2 dump-hash 3)))
                    (bl.net::*cached-is-ibd* t))
               (let ((r2 (bl.rpc::rpc-loadtxoutset dst (list dump-path))))
                 (is (= 2 (cdr (assoc "coins_loaded" r2 :test #'string=))))
                 (is (= 2 (cdr (assoc "base_height" r2 :test #'string=)))))
               (let ((current (bl::node-current-chainstate dst)))
                 (is (= 2 (bl.store:current-height current)))
                 (is (equalp h2 (bl.store:best-block-hash current)))
                 (is (equalp dump-hash
                             (bl.store:compute-utxo-set-hash
                              (bl::node-utxo-set dst)))))))
           ;; --- Bare type "rollback": defaults to the highest available
           ;; assumeutxo snapshot height (GetAvailableSnapshotHeights) ---
           (let* ((bl:*assumeutxo-data-override*
                    (list (%snap-au 2 h2 (%snap-fill 32 0) 3)))
                  (path2 (namestring (merge-pathnames "rollback2.dat" dst-dir)))
                  (r (bl.rpc::rpc-dumptxoutset node (list path2 "rollback"))))
             (is (= 2 (cdr (assoc "base_height" r :test #'string=))))
             (is (= 4 (bl.store:current-height cs))))
           ;; --- An already-disabled network stays disabled afterwards ---
           (setf (bl::node-network-active node) nil)
           (let ((path3 (namestring (merge-pathnames "rollback3.dat" dst-dir))))
             (bl.rpc::rpc-dumptxoutset node (list path3 "" opts))
             (is (eq nil (bl::node-network-active node)))
             (is (= 4 (bl.store:current-height cs))))
           (setf (bl::node-network-active node) t))
         (clrhash bl.val::*block-undo-data*))))))
