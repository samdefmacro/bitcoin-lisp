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
valid fast-forward."
  (let* ((chain-state (bitcoin-lisp.storage:init-chain-state dir))
         (utxo (bitcoin-lisp.storage:make-coins-view-cache
                (bitcoin-lisp.storage:open-coins-view-db
                 (ensure-directories-exist (merge-pathnames "chainstate/" dir)))))
         (node (make-test-node))
         (genesis (bitcoin-lisp.storage:best-block-hash chain-state))
         (genesis-entry (bitcoin-lisp.storage:make-block-index-entry
                         :hash genesis :height 0 :chain-work 0 :status :valid))
         (tip-entry (bitcoin-lisp.storage:make-block-index-entry
                     :hash tip-hash :height tip-height
                     :chain-work (* tip-height 100) :status :valid
                     :prev-entry genesis-entry)))
    (setf (bitcoin-lisp::node-chain-state node) chain-state
          (bitcoin-lisp::node-utxo-set node) utxo
          (bitcoin-lisp::node-block-store node)
          (bitcoin-lisp.storage:init-block-store dir))
    (bitcoin-lisp.storage:add-block-index-entry chain-state genesis-entry)
    (bitcoin-lisp.storage:add-block-index-entry chain-state tip-entry)
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
                                   (netmagic bitcoin-lisp.serialization:+testnet3-magic+)
                                   base-hash count groups (trailing #()))
  "Craft an arbitrary snapshot file. GROUPS is a list of (txid . coins),
each coin (vout height coinbase value script)."
  (with-open-file (out path :direction :output :if-exists :supersede
                            :element-type '(unsigned-byte 8))
    (write-sequence (coerce magic '(vector (unsigned-byte 8))) out)
    (bitcoin-lisp.serialization:write-uint16-le out version)
    (write-sequence netmagic out)
    (write-sequence base-hash out)
    (bitcoin-lisp.serialization:write-uint64-le out count)
    (dolist (group groups)
      (let ((buf (bitcoin-lisp.serialization:make-byte-buf)))
        (bitcoin-lisp.serialization:bb-write-bytes buf (car group))
        (bitcoin-lisp.serialization:bb-write-varint buf (length (cdr group)))
        (dolist (coin (cdr group))
          (destructuring-bind (vout height coinbase value script) coin
            (bitcoin-lisp.serialization:bb-write-varint buf vout)
            (bitcoin-lisp.serialization:bb-write-compressed-coin
             buf height coinbase value script)))
        (write-sequence (bitcoin-lisp.serialization:bb-finish buf) out)))
    (write-sequence (coerce trailing '(vector (unsigned-byte 8))) out))
  path)

(defun %snap-load-err (node path)
  "Run loadtxoutset; return the signalled rpc-error, or NIL on success."
  (handler-case
      (progn (bitcoin-lisp.rpc::rpc-loadtxoutset node (list (namestring path)))
             nil)
    (bitcoin-lisp.rpc::rpc-error (e) e)))

(defun %snap-err-matches (err code substring)
  (and err
       (= code (bitcoin-lisp.rpc::rpc-error-code err))
       (search substring (bitcoin-lisp.rpc::rpc-error-message err))))

(defun %snap-hash (coins)
  "hash_serialized_3 over COINS ((txid vout height coinbase value script)),
which must already be in cursor order: double-SHA256 of the concatenated
per-coin preimages (kernel/coinstats.cpp:46-52,111-181)."
  (bitcoin-lisp.crypto:hash256
   (apply #'%snap-cat
          (mapcar (lambda (c)
                    (destructuring-bind (txid vout height coinbase value script) c
                      (bitcoin-lisp.storage:coin-muhash-element
                       txid vout height coinbase value
                       (coerce script '(simple-array (unsigned-byte 8) (*))))))
                  coins))))

(defun %snap-au (height blockhash hash-serialized &optional (chain-tx-count 1))
  (bitcoin-lisp:make-assumeutxo-data
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
           (utxo (bitcoin-lisp::node-utxo-set node))
           (snap (namestring (merge-pathnames "utxo.dat" dir))))
      ;; Give the tip entry a known per-block tx count so nchaintx (walk
      ;; to genesis: 3 + genesis' 1) is reportable.
      (setf (bitcoin-lisp.storage:block-index-entry-tx-count
             (bitcoin-lisp.storage:get-block-index-entry
              (bitcoin-lisp::node-chain-state node) h5))
            3)
      (bitcoin-lisp.storage:update-chain-tip
       (bitcoin-lisp::node-chain-state node) h5 5)
      ;; Insert in scrambled order; the dump cursor must normalize to
      ;; txid-lex + numeric-vout order (incl. vout 300 > 255, whose LE
      ;; byte order differs from numeric order).
      (bitcoin-lisp.storage:add-utxo utxo txid-b 1 0 (%snap-cat #(#x6A)) 5)
      (bitcoin-lisp.storage:add-utxo utxo txid-a 300 999 (%snap-cat #(#x51 #x52 #x53)) 4)
      (bitcoin-lisp.storage:add-utxo utxo txid-a 0 4200000000 (%snap-p2pkh #xAA) 3
                                     :coinbase t)
      (let ((r (bitcoin-lisp.rpc::rpc-dumptxoutset node (list snap "latest")))
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
        (is (string= (bitcoin-lisp.rpc::hash-to-hex h5)
                     (cdr (assoc "base_hash" r :test #'string=))))
        ;; Same-pass hash matches the P1 whole-set hasher.
        (is (string= (bitcoin-lisp.rpc::hash-to-hex
                      (bitcoin-lisp.storage:compute-utxo-set-hash utxo))
                     (cdr (assoc "txoutset_hash" r :test #'string=))))
        ;; nchaintx = tip 3 + genesis 1.
        (is (= 4 (cdr (assoc "nchaintx" r :test #'string=)))))
      ;; Existing path, rollback type, and unknown type are all refused.
      (signals bitcoin-lisp.rpc::rpc-error
        (bitcoin-lisp.rpc::rpc-dumptxoutset node (list snap "latest")))
      (signals bitcoin-lisp.rpc::rpc-error
        (bitcoin-lisp.rpc::rpc-dumptxoutset
         node (list (namestring (merge-pathnames "r.dat" dir)) "rollback")))
      (signals bitcoin-lisp.rpc::rpc-error
        (bitcoin-lisp.rpc::rpc-dumptxoutset
         node (list (namestring (merge-pathnames "t.dat" dir)) "bogus")))
      ;; The failed calls above must not leave .incomplete litter.
      (is (null (probe-file (concatenate 'string snap ".incomplete")))))))

(test snapshot-roundtrip-verified
  "dumptxoutset -> loadtxoutset round-trips through the full verification
gate: an injected assumeutxo-data entry carrying the real hash_serialized_3
accepts the snapshot, the UTXO set is REPLACED (stale coins dropped), the
tip fast-forwards, and the base entry's tx-count is seeded from nChainTx."
  (%with-snap-dir (src-dir)
    (%with-snap-dir (dst-dir)
      (let* ((h5 (%snap-fill 32 5))
             (txid-a (%snap-fill 32 #x11))
             (txid-b (%snap-fill 32 #x22))
             (txid-s (%snap-fill 32 #xEE))   ; stale coin, not in snapshot
             (spk-a (%snap-p2pkh #xAA))
             (spk-raw (%snap-cat #(#x51 #x52 #x53)))
             (src (%snap-node src-dir h5 5))
             (snap (namestring (merge-pathnames "utxo.dat" src-dir))))
        (bitcoin-lisp.storage:update-chain-tip
         (bitcoin-lisp::node-chain-state src) h5 5)
        (let ((utxo (bitcoin-lisp::node-utxo-set src)))
          (bitcoin-lisp.storage:add-utxo utxo txid-a 0 4200000000 spk-a 3 :coinbase t)
          (bitcoin-lisp.storage:add-utxo utxo txid-a 300 999 spk-raw 4)
          (bitcoin-lisp.storage:add-utxo utxo txid-b 1 12345 spk-raw 5))
        (let* ((expected-hash (bitcoin-lisp.storage:compute-utxo-set-hash
                               (bitcoin-lisp::node-utxo-set src)))
               (r (bitcoin-lisp.rpc::rpc-dumptxoutset src (list snap "latest"))))
          (is (string= (bitcoin-lisp.rpc::hash-to-hex expected-hash)
                       (cdr (assoc "txoutset_hash" r :test #'string=))))
          (let* ((dst (%snap-node dst-dir h5 5))
                 (dst-chain (bitcoin-lisp::node-chain-state dst))
                 (dst-utxo (bitcoin-lisp::node-utxo-set dst)))
            ;; Pre-existing state that must not survive the load.
            (bitcoin-lisp.storage:add-utxo dst-utxo txid-s 0 777 spk-raw 1)
            (bitcoin-lisp.storage:coins-view-cache-flush dst-utxo)
            (let ((bitcoin-lisp:*assumeutxo-data-override*
                    (list (%snap-au 5 h5 expected-hash 4242))))
              (let ((r2 (bitcoin-lisp.rpc::rpc-loadtxoutset dst (list snap))))
                (is (= 3 (cdr (assoc "coins_loaded" r2 :test #'string=))))
                (is (= 5 (cdr (assoc "base_height" r2 :test #'string=))))
                (is (string= (bitcoin-lisp.rpc::hash-to-hex h5)
                             (cdr (assoc "tip_hash" r2 :test #'string=)))))
              ;; Tip fast-forwarded; nChainTx seeded on the base entry.
              (is (= 5 (bitcoin-lisp.storage:current-height dst-chain)))
              (is (equalp h5 (bitcoin-lisp.storage:best-block-hash dst-chain)))
              (is (= 4242 (bitcoin-lisp.storage:block-index-entry-tx-count
                           (bitcoin-lisp.storage:get-block-index-entry dst-chain h5))))
              ;; Snapshot coins present and exact; stale coin replaced away.
              (let ((a (bitcoin-lisp.storage:get-utxo dst-utxo txid-a 0))
                    (a300 (bitcoin-lisp.storage:get-utxo dst-utxo txid-a 300))
                    (b (bitcoin-lisp.storage:get-utxo dst-utxo txid-b 1)))
                (is (and a (= 4200000000 (bitcoin-lisp.storage:utxo-entry-value a))))
                (is (bitcoin-lisp.storage:utxo-entry-coinbase a))
                (is (equalp spk-a (bitcoin-lisp.storage:utxo-entry-script-pubkey a)))
                (is (and a300 (= 999 (bitcoin-lisp.storage:utxo-entry-value a300))))
                (is (= 4 (bitcoin-lisp.storage:utxo-entry-height a300)))
                (is (and b (= 12345 (bitcoin-lisp.storage:utxo-entry-value b))))
                (is (not (bitcoin-lisp.storage:utxo-entry-coinbase b))))
              (is (null (bitcoin-lisp.storage:get-utxo dst-utxo txid-s 0)))
              ;; The loaded set re-hashes to the committed value.
              (is (equalp expected-hash
                          (bitcoin-lisp.storage:compute-utxo-set-hash dst-utxo)))
              ;; Loading again fails: already at the snapshot height.
              (is (%snap-err-matches (%snap-load-err dst snap)
                                     -32603 "Work does not exceed")))))))))

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
    (let* ((h5 (%snap-fill 32 5))
           (h7 (%snap-fill 32 7))
           (zero32 (%snap-fill 32 0))
           (node (%snap-node dir h5 5))
           (chain (bitcoin-lisp::node-chain-state node))
           (snap5 (%snap-write-file (merge-pathnames "b5.dat" dir)
                                    :base-hash h5 :count 0))
           (snap7 (%snap-write-file (merge-pathnames "b7.dat" dir)
                                    :base-hash h7 :count 0)))
      ;; No assumeutxo-data entry for the base hash.
      (let ((bitcoin-lisp:*assumeutxo-data-override*
              (list (%snap-au 7 h7 zero32))))
        (is (%snap-err-matches (%snap-load-err node snap5)
                               -32603 "not recognized"))
        ;; Entry exists but the base header is not in our block index.
        (is (%snap-err-matches (%snap-load-err node snap7)
                               -32603 "must appear in the headers chain")))
      ;; Commitment height disagrees with the indexed header's height.
      (let ((bitcoin-lisp:*assumeutxo-data-override*
              (list (%snap-au 9 h5 zero32))))
        (is (%snap-err-matches (%snap-load-err node snap5)
                               -32603 "height in snapshot metadata not recognized")))
      (let ((bitcoin-lisp:*assumeutxo-data-override*
              (list (%snap-au 5 h5 zero32)))
            (entry (bitcoin-lisp.storage:get-block-index-entry chain h5)))
        ;; Base header marked invalid.
        (setf (bitcoin-lisp.storage:block-index-entry-status entry) :invalid)
        (is (%snap-err-matches (%snap-load-err node snap5)
                               -32603 "part of an invalid chain"))
        (setf (bitcoin-lisp.storage:block-index-entry-status entry) :valid)
        ;; Mempool not empty.
        (let* ((tx (bitcoin-lisp.serialization:make-transaction
                    :version 1
                    :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                                     :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                       :hash zero32 :index #xffffffff)
                                     :script-sig (%snap-fill 1 #x51)
                                     :sequence #xffffffff))
                    :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                                      :value 1000 :script-pubkey (%snap-cat #(#x6A))))
                    :lock-time 0))
               (mp (bitcoin-lisp::node-mempool node)))
          (bitcoin-lisp.mempool:mempool-add
           mp (bitcoin-lisp.serialization:transaction-hash tx)
           (bitcoin-lisp.mempool:make-mempool-entry :transaction tx))
          (is (%snap-err-matches (%snap-load-err node snap5)
                                 -32603 "mempool not empty"))
          (setf (bitcoin-lisp::node-mempool node) (bitcoin-lisp.mempool:make-mempool)))
        ;; Tip already at the base height.
        (bitcoin-lisp.storage:update-chain-tip chain h5 5)
        (is (%snap-err-matches (%snap-load-err node snap5)
                               -32603 "Work does not exceed"))))))

(test snapshot-content-rejections
  "PopulateAndValidateSnapshot's per-coin and stream checks (validation.cpp
:5816-5936): coin height above the base, MoneyRange violation, group
claiming more coins than the metadata count, truncation, trailing bytes,
an out-of-range vout, and a hash_serialized_3 mismatch. Every rejection
leaves the node's UTXO set and tip untouched."
  (%with-snap-dir (dir)
    (let* ((h5 (%snap-fill 32 5))
           (txid (%snap-fill 32 #x33))
           (txid-s (%snap-fill 32 #xEE))
           (spk (%snap-cat #(#x51)))
           (node (%snap-node dir h5 5))
           (chain (bitcoin-lisp::node-chain-state node))
           (utxo (bitcoin-lisp::node-utxo-set node))
           (good-coin (list txid 0 1 nil 1000 spk))
           (good-hash (%snap-hash (list good-coin)))
           (f (merge-pathnames "c.dat" dir)))
      ;; Pre-existing coin: must survive every failed load below.
      (bitcoin-lisp.storage:add-utxo utxo txid-s 0 777 spk 1)
      (bitcoin-lisp.storage:coins-view-cache-flush utxo)
      (let ((bitcoin-lisp:*assumeutxo-data-override*
              (list (%snap-au 5 h5 good-hash))))
        (flet ((rejects (substring &rest file-args)
                 (apply #'%snap-write-file f :base-hash h5 file-args)
                 (let ((err (%snap-load-err node f)))
                   (is (%snap-err-matches err -32603 substring)
                       "expected ~S in: ~A" substring
                       (and err (bitcoin-lisp.rpc::rpc-error-message err))))))
          ;; Coin height above the snapshot base.
          (rejects "Bad snapshot data after deserializing 0 coins"
                   :count 1 :groups `((,txid (0 6 nil 1000 ,spk))))
          ;; MoneyRange violation.
          (rejects "bad tx out value"
                   :count 1
                   :groups `((,txid (0 1 nil ,(1+ bitcoin-lisp.validation:+max-money+)
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
          (let ((bitcoin-lisp:*assumeutxo-data-override*
                  (list (%snap-au 5 h5 (%snap-fill 32 0)))))
            (rejects "Bad snapshot content hash"
                     :count 1 :groups `((,txid (0 1 nil 1000 ,spk))))))
        ;; No partial state from any of the failures.
        (is (null (bitcoin-lisp.storage:get-utxo utxo txid 0)))
        (let ((stale (bitcoin-lisp.storage:get-utxo utxo txid-s 0)))
          (is (and stale (= 777 (bitcoin-lisp.storage:utxo-entry-value stale)))))
        (is (= 0 (bitcoin-lisp.storage:current-height chain)))
        ;; Control: the same 1-coin file with the right hash loads cleanly.
        (%snap-write-file f :base-hash h5 :count 1
                            :groups `((,txid (0 1 nil 1000 ,spk))))
        (is (null (%snap-load-err node f)))
        (is (= 5 (bitcoin-lisp.storage:current-height chain)))
        (let ((c (bitcoin-lisp.storage:get-utxo utxo txid 0)))
          (is (and c (= 1000 (bitcoin-lisp.storage:utxo-entry-value c)))))
        (is (null (bitcoin-lisp.storage:get-utxo utxo txid-s 0)))))))

(test snapshot-assumeutxo-tables
  "The shipped assumeutxo-data tables mirror Bitcoin Core's
kernel/chainparams.cpp m_assumeutxo_data exactly (heights per network,
spot-checked hashes and chain tx counts)."
  (flet ((heights (net)
           (mapcar #'bitcoin-lisp:assumeutxo-data-height
                   (bitcoin-lisp:network-assumeutxo-data net)))
         (display (bytes)
           (bitcoin-lisp.crypto:bytes-to-hex (reverse bytes))))
    (is (equal '(840000 880000 910000 935000) (heights :mainnet)))
    (is (equal '(2500000 4840000) (heights :testnet3)))
    (is (equal '(90000 120000) (heights :testnet4)))
    (is (equal '(160000 290000) (heights :signet)))
    (is (equal '(110 200 299) (heights :regtest)))
    (dolist (net '(:mainnet :testnet3 :testnet4 :signet :regtest))
      (dolist (e (bitcoin-lisp:network-assumeutxo-data net))
        (is (= 32 (length (bitcoin-lisp:assumeutxo-data-blockhash e))))
        (is (= 32 (length (bitcoin-lisp:assumeutxo-data-hash-serialized e))))
        (is (plusp (bitcoin-lisp:assumeutxo-data-chain-tx-count e)))))
    (let ((m840k (first (bitcoin-lisp:network-assumeutxo-data :mainnet)))
          (t90k (first (bitcoin-lisp:network-assumeutxo-data :testnet4))))
      (is (string= "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"
                   (display (bitcoin-lisp:assumeutxo-data-blockhash m840k))))
      (is (string= "a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96"
                   (display (bitcoin-lisp:assumeutxo-data-hash-serialized m840k))))
      (is (= 991032194 (bitcoin-lisp:assumeutxo-data-chain-tx-count m840k)))
      (is (string= "0000000002ebe8bcda020e0dd6ccfbdfac531d2f6a81457191b99fc2df2dbe3b"
                   (display (bitcoin-lisp:assumeutxo-data-blockhash t90k))))
      (is (= 11347043 (bitcoin-lisp:assumeutxo-data-chain-tx-count t90k)))
      ;; Blockhash lookup finds the entry; a random hash doesn't. (The
      ;; table is rebuilt per call, so compare contents, not identity.)
      (is (equalp m840k (bitcoin-lisp:assumeutxo-data-for-blockhash
                         :mainnet (bitcoin-lisp:assumeutxo-data-blockhash m840k))))
      (is (null (bitcoin-lisp:assumeutxo-data-for-blockhash
                 :mainnet (%snap-fill 32 #x99)))))
    ;; The override hook replaces the built-in table outright.
    (let ((bitcoin-lisp:*assumeutxo-data-override*
            (list (%snap-au 42 (%snap-fill 32 1) (%snap-fill 32 2)))))
      (is (equal '(42) (heights :mainnet))))))

(test snapshot-stream-codec-parity
  "The stream-based compressed-coin readers match the byte-reader codec:
Core VARINT values round-trip, a compressed Coin record round-trips, and
an oversized raw script is skipped and replaced with OP_RETURN."
  ;; VARINT parity across the serialize.h example values.
  (dolist (n '(0 1 127 128 255 16383 16384 16511 65535 4294967295
               18446744073709551615))
    (let ((buf (bitcoin-lisp.serialization:make-byte-buf)))
      (bitcoin-lisp.serialization:bb-write-core-varint buf n)
      (flexi-streams:with-input-from-sequence
          (s (bitcoin-lisp.serialization:bb-finish buf))
        (is (= n (bitcoin-lisp.serialization:read-core-varint s))))))
  ;; Compressed Coin record round-trip through the stream reader.
  (let ((script (%snap-p2pkh #x42))
        (buf (bitcoin-lisp.serialization:make-byte-buf)))
    (bitcoin-lisp.serialization:bb-write-compressed-coin buf 1000 t 123456789 script)
    (flexi-streams:with-input-from-sequence
        (s (bitcoin-lisp.serialization:bb-finish buf))
      (multiple-value-bind (height coinbase value out-script)
          (bitcoin-lisp.serialization:read-compressed-coin s)
        (is (= 1000 height))
        (is (eq t (and coinbase t)))
        (is (= 123456789 value))
        (is (equalp script out-script)))))
  ;; Oversized raw script (> MAX_SCRIPT_SIZE): skipped, OP_RETURN returned,
  ;; stream left positioned exactly after it (compressor.h:87-90).
  (let ((big (%snap-fill 10001 #x00))
        (buf (bitcoin-lisp.serialization:make-byte-buf)))
    (bitcoin-lisp.serialization:bb-write-compressed-script buf big)
    (bitcoin-lisp.serialization:bb-write-core-varint buf 7)  ; sentinel after
    (flexi-streams:with-input-from-sequence
        (s (bitcoin-lisp.serialization:bb-finish buf))
      (is (equalp #(#x6A) (bitcoin-lisp.serialization:read-compressed-script s)))
      (is (= 7 (bitcoin-lisp.serialization:read-core-varint s))))))
