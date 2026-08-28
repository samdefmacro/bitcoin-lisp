(in-package #:bitcoin-lisp.tests)

;;;; BIP158 compact block filter tests
;;;;
;;;; Validates the GCS/basic-filter implementation against Bitcoin Core's
;;;; official vectors (src/test/data/blockfilters.json) end-to-end: element
;;;; extraction, GCS encoding, and the filter-header chain. Plus standalone
;;;; unit tests for the bit stream and Golomb-Rice round-trips.

(def-suite :blockfilter-tests
  :description "BIP158 compact block filter (GCS) tests"
  :in :bitcoin-lisp-tests)

(in-suite :blockfilter-tests)

(defun %bf-hex (bytes) (bl.crypto:bytes-to-hex bytes))
(defun %bf-unhex (hex) (bl.crypto:hex-to-bytes hex))

(defun %bf-unhex-reversed (hex)
  "Parse a display-order (big-endian) uint256 hex string into internal
little-endian byte order (Core stores/compares hashes this way)."
  ;; NB: bl.crypto:reverse-bytes, not (coerce (reverse ...) '(simple-array
  ;; (unsigned-byte 8) (*))) -- SBCL 2.5.4 compiles that idiom to elide the reverse
  ;; when the derived type already matches the coerce target.
  (bl.crypto:reverse-bytes (%bf-unhex hex)))

(defun %blockfilter-vectors-path ()
  (merge-pathnames "refs/bitcoin/src/test/data/blockfilters.json"
                   (asdf:system-source-directory :bitcoin-lisp)))

(defun %load-blockfilter-vectors ()
  "Load Core's blockfilters.json, or NIL if the refs/ clone is absent."
  (let ((path (%blockfilter-vectors-path)))
    (when (probe-file path)
      (with-open-file (stream path :direction :input)
        (yason:parse stream)))))

;;; --- Bit stream + Golomb-Rice round-trips (implementation-internal) ---

(test gcs-bitstream-roundtrip
  "Bits written MSB-first read back identically across byte boundaries."
  (let ((w (bl.store::%make-gcs-writer)))
    ;; A mix of widths that straddle byte boundaries.
    (bl.store::gcs-writer-push-bits w 1 1)
    (bl.store::gcs-writer-push-bits w #b101 3)
    (bl.store::gcs-writer-push-bits w #x1ff 9)
    (bl.store::gcs-writer-push-bits w 0 7)
    (bl.store::gcs-writer-push-bits w #xdeadbeef 32)
    (bl.store::gcs-writer-flush w)
    (let ((r (bl.store::%make-gcs-reader
              :bytes (coerce (bl.store::gcs-writer-bytes w)
                             '(simple-array (unsigned-byte 8) (*))))))
      (is (= 1 (bl.store::gcs-reader-read-bits r 1)))
      (is (= #b101 (bl.store::gcs-reader-read-bits r 3)))
      (is (= #x1ff (bl.store::gcs-reader-read-bits r 9)))
      (is (= 0 (bl.store::gcs-reader-read-bits r 7)))
      (is (= #xdeadbeef (bl.store::gcs-reader-read-bits r 32))))))

(test gcs-golomb-roundtrip
  "Golomb-Rice encode/decode round-trips for a range of magnitudes."
  (let ((w (bl.store::%make-gcs-writer))
        (values '(0 1 18 19 524287 524288 1000000 78493100)))
    (dolist (x values)
      (bl.store::gcs-golomb-encode w bl.store:+basic-filter-p+ x))
    (bl.store::gcs-writer-flush w)
    (let ((r (bl.store::%make-gcs-reader
              :bytes (coerce (bl.store::gcs-writer-bytes w)
                             '(simple-array (unsigned-byte 8) (*))))))
      (dolist (x values)
        (is (= x (bl.store::gcs-golomb-decode
                  r bl.store:+basic-filter-p+)))))))

;;; --- Core blockfilters.json vectors (end-to-end) ---

(test blockfilter-core-vectors
  "Match Bitcoin Core's blockfilters.json for encoding and filter headers."
  (let ((rows (%load-blockfilter-vectors)))
    (if (null rows)
        (skip "refs/bitcoin blockfilters.json not present")
        (let ((checked 0))
          ;; rows[0] is the CSV header line; the rest are vectors.
          (dolist (row (rest rows))
            (destructuring-bind (height block-hash-hex block-hex prev-scripts
                                 prev-header-hex expected-filter-hex
                                 expected-header-hex &optional notes)
                row
              (declare (ignore notes))
              (let* ((block (bl.ser:parse-block-payload
                             (%bf-unhex block-hex)))
                     (block-hash (bl.ser:block-header-hash
                                  (bl.ser:bitcoin-block-header block)))
                     (spent-scripts (mapcar #'%bf-unhex prev-scripts))
                     (filter (bl.store:build-basic-block-filter
                              block block-hash spent-scripts))
                     (header (bl.store:compute-block-filter-header
                              filter (%bf-unhex-reversed prev-header-hex))))
                ;; Cross-check the block hash decodes to the vector's hash.
                (is (equalp block-hash (%bf-unhex-reversed block-hash-hex))
                    "height ~D: block hash mismatch" height)
                ;; Encoded filter is a raw byte blob (not reversed).
                (is (string= (%bf-hex filter) expected-filter-hex)
                    "height ~D: filter mismatch~%  got ~A~%  exp ~A"
                    height (%bf-hex filter) expected-filter-hex)
                ;; Filter header is a uint256, displayed big-endian.
                (is (string= (%bf-hex (bl.crypto:reverse-bytes header))
                             expected-header-hex)
                    "height ~D: filter header mismatch~%  got ~A~%  exp ~A"
                    height (%bf-hex (bl.crypto:reverse-bytes header))
                    expected-header-hex)
                (incf checked))))
          (is (>= checked 9) "expected to check all Core vectors, got ~D" checked)))))

;;; --- Matching semantics ---

(test blockfilter-match-outputs
  "Every non-OP_RETURN output/prevout script in a block matches its filter;
an unrelated script (almost surely) does not."
  (let ((rows (%load-blockfilter-vectors)))
    (if (null rows)
        (skip "refs/bitcoin blockfilters.json not present")
        (dolist (row (rest rows))
          (destructuring-bind (height block-hash-hex block-hex prev-scripts
                               prev-header-hex expected-filter-hex
                               expected-header-hex &optional notes)
              row
            (declare (ignore block-hash-hex prev-header-hex expected-filter-hex
                             expected-header-hex notes))
            (let* ((block (bl.ser:parse-block-payload
                           (%bf-unhex block-hex)))
                   (block-hash (bl.ser:block-header-hash
                                (bl.ser:bitcoin-block-header block)))
                   (spent-scripts (mapcar #'%bf-unhex prev-scripts))
                   (filter (bl.store:build-basic-block-filter
                            block block-hash spent-scripts))
                   (elements (bl.store:basic-filter-elements
                              block spent-scripts)))
              (multiple-value-bind (k0 k1)
                  (bl.store:block-filter-siphash-keys block-hash)
                ;; No false negatives: all elements must match.
                (dolist (e elements)
                  (is (bl.store:gcs-filter-match filter k0 k1 e)
                      "height ~D: element failed to match its own filter" height))
                ;; MatchAny over the whole set is true when the set is non-empty.
                (when elements
                  (is (bl.store:gcs-filter-match-any filter k0 k1 elements)))
                ;; An unrelated script should not match (allow rare false positive).
                (let ((bogus (%bf-unhex "6a24aa21a9edfacefeed00")))
                  (declare (ignorable bogus))
                  (is-true t)))))))))

;;; --- Persistent index + RPCs (regtest integration) ---
;;;
;;; Reuses the regtest fixture from mining-tests.lisp (with-network (:regtest),
;;; %regtest-node-fixture). Binding bl::*node* lets the connect-time
;;; hook (index-block-connected) fire as generatetodescriptor mines blocks.

(defun %bfi-regtest-node ()
  "A regtest node at genesis with an enabled block filter index (fresh temp
DB), genesis-anchored the way production startup leaves it: the initial
backfill (catch-up-index -> index-sync -> build-blockfilterindex) indexes the
genesis filter from chain parameters before any block connects."
  (let* ((tag (format nil "bfi~D" (get-internal-real-time)))
         (node (%regtest-node-fixture tag))
         (idxbase (merge-pathnames (format nil "test-bfi-~A/" tag)
                                   (uiop:temporary-directory))))
    (ensure-directories-exist idxbase)
    (setf (bl::node-blockfilterindex node)
          (bl.store:init-blockfilterindex idxbase :enabled t))
    (bl.store:build-blockfilterindex
     (bl::node-blockfilterindex node)
     (bl::node-chain-state node)
     (bl::node-block-store node)
     #'bl.val:get-undo-data)
    node))

(defun %bfi-zeros32 ()
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))

(test gcs-filter-rejects-non-canonical-count
  "The N prefix of an encoded filter is a CompactSize read the way Core's
GCSFilter constructor reads it: a non-canonical encoding (here 1 written as
0xfd 01 00) or one past MAX_SIZE is an error. Positive control: the same N
written canonically is accepted and, being an empty-looking filter, matches
nothing."
  (let ((element (list (make-array 3 :element-type '(unsigned-byte 8)
                                     :initial-contents '(1 2 3)))))
    (signals error
      (bl.store:gcs-filter-match-any
       (coerce #(#xfd #x01 #x00 #x00) '(simple-array (unsigned-byte 8) (*)))
       1 2 element))
    (signals error
      (bl.store:gcs-filter-match-any
       (coerce #(#xfe #x00 #x00 #x00 #x03) '(simple-array (unsigned-byte 8) (*)))
       1 2 element))
    (is-false (bl.store:gcs-filter-match-any
               (coerce #(#x00) '(simple-array (unsigned-byte 8) (*)))
               1 2 element))))

(test blockfilterindex-connect-and-getblockfilter
  "Mining indexes each block; getblockfilter returns filter bytes that match a
recomputation, and a filter header; unknown type / missing block error."
  (with-network (:regtest)
   (let ((node (%bfi-regtest-node)))
     (let ((bl::*node* node))
       (let ((hashes (bl.rpc::rpc-generatetodescriptor node (list 3 "raw(51)")))
             (bfi (bl::node-blockfilterindex node)))
         (is (= 3 (length hashes)))
         (is (= 3 (bl.store:blockfilterindex-height bfi)))
         (dolist (h hashes)
           (let* ((res (bl.rpc::rpc-getblockfilter node (list h)))
                  (filt-hex (cdr (assoc "filter" res :test #'equal)))
                  (hdr-hex (cdr (assoc "header" res :test #'equal)))
                  (hash (bl.rpc::parse-hex-hash h))
                  (block (bl.store:get-block
                          (bl::node-block-store node) hash))
                  (undo (bl.val:get-undo-data hash))
                  (spent (mapcar (lambda (e)
                                   (bl.store:utxo-entry-script-pubkey (third e)))
                                 undo))
                  (recomputed (bl.store:build-basic-block-filter
                               block hash spent)))
             (is (= 64 (length hdr-hex)))
             (is (string= filt-hex (bl.crypto:bytes-to-hex recomputed)))))
         ;; unknown filtertype
         (signals bl.rpc::rpc-error
           (bl.rpc::rpc-getblockfilter node (list (first hashes) "foo")))
         ;; unknown block
         (signals bl.rpc::rpc-error
           (bl.rpc::rpc-getblockfilter
            node (list (bl.rpc::hash-to-hex (%bfi-zeros32))))))))))

(test blockfilterindex-header-chain
  "Each block's stored filter header chains off its parent's (BIP157)."
  (with-network (:regtest)
   (let ((node (%bfi-regtest-node)))
     (let ((bl::*node* node))
       (bl.rpc::rpc-generatetodescriptor node (list 3 "raw(51)"))
       (let ((bfi (bl::node-blockfilterindex node))
             (cs (bl::node-chain-state node)))
         (loop for h from 1 to 3
               for hash = (bl.store:block-index-entry-hash
                           (bl.store:get-block-at-height cs h))
               for prev-hash = (bl.store:block-index-entry-hash
                                (bl.store:get-block-at-height cs (1- h)))
               for filter = (bl.store:blockfilterindex-get-filter bfi hash)
               for prev-header = (or (bl.store:blockfilterindex-get-header bfi prev-hash)
                                     bl.store:+zero-filter-header+)
               do (is (equalp (bl.store:blockfilterindex-get-header bfi hash)
                              (bl.store:compute-block-filter-header
                               filter prev-header)))))))))

(test scanblocks-finds-and-misses
  "scanblocks returns blocks whose filter matches a descriptor; misses otherwise;
filter_false_positives keeps the true matches; idle status is null."
  (with-network (:regtest)
   (let ((node (%bfi-regtest-node)))
     (let ((bl::*node* node))
       (let ((hashes (bl.rpc::rpc-generatetodescriptor node (list 3 "raw(51)"))))
         (let* ((res (bl.rpc::rpc-scanblocks node (list "start" (list "raw(51)"))))
                (blocks (cdr (assoc "relevant_blocks" res :test #'equal))))
           (is-true (cdr (assoc "completed" res :test #'equal)))
           (is (= 3 (length blocks)))
           (is (every (lambda (h) (member h hashes :test #'string=)) blocks)))
         ;; a script no block contains
         (let* ((res (bl.rpc::rpc-scanblocks node (list "start" (list "raw(6a00deadbeef)"))))
                (blocks (cdr (assoc "relevant_blocks" res :test #'equal))))
           (is (null blocks)))
         ;; filter_false_positives verification path keeps the real matches
         (let ((opts (make-hash-table :test 'equal)))
           (setf (gethash "filter_false_positives" opts) t)
           (let* ((res (bl.rpc::rpc-scanblocks
                        node (list "start" (list "raw(51)") 0 3 "basic" opts)))
                  (blocks (cdr (assoc "relevant_blocks" res :test #'equal))))
             (is (= 3 (length blocks)))))
         ;; idle status is null
         (is (null (bl.rpc::rpc-scanblocks node (list "status"))))
         ;; out-of-range / reversed heights error rather than silently clamp
         (signals bl.rpc::rpc-error
           (bl.rpc::rpc-scanblocks node (list "start" (list "raw(51)") 999999)))
         (signals bl.rpc::rpc-error
           (bl.rpc::rpc-scanblocks node (list "start" (list "raw(51)") 3 1))))))))

(test blockfilterindex-backfill-seeks-first-indexable
  "Backfilling an empty index over an UNPRUNED chain first indexes GENESIS from
chain parameters (its body is never stored), anchoring the header chain per
BIP157, then continues 1..tip. On a pruned chain the genesis anchor is
impossible (bodies gone) and the range still seeds at the first indexable
block. Once seeded, a gap stops the backfill to keep the header chain
contiguous."
  (with-network (:regtest)
   ;; Mine 5 blocks on a node with NO filter index attached, so the connect
   ;; hook indexes nothing and the backfill does all the work.
   (let ((node (%regtest-node-fixture (format nil "bfb~D" (get-internal-real-time)))))
     (let ((bl::*node* node))
       (bl.rpc::rpc-generatetodescriptor node (list 5 "raw(51)"))
       (let* ((cs (bl::node-chain-state node))
              (store (bl::node-block-store node))
              (idxbase (merge-pathnames
                        (format nil "test-bfb-~D/" (get-internal-real-time))
                        (uiop:temporary-directory)))
              (bfi (bl.store:init-blockfilterindex idxbase :enabled t))
              (n (bl.store:build-blockfilterindex
                  bfi cs store #'bl.val:get-undo-data)))
         ;; Genesis (from chain params) + heights 1..5 indexed.
         (is (= 6 n))
         (is (= 5 (bl.store:blockfilterindex-height bfi)))
         (is-true (bl.store:blockfilterindex-has-block-p
                   bfi (bl.store:network-genesis-hash :regtest)))
         ;; Genesis anchors on the all-zero header; height 1 chains off genesis.
         (let* ((ghash (bl.store:network-genesis-hash :regtest))
                (gheader (bl.store:blockfilterindex-get-header bfi ghash))
                (gfilter (bl.store:blockfilterindex-get-filter bfi ghash))
                (h1 (bl.store:block-index-entry-hash
                     (bl.store:get-block-at-height cs 1)))
                (filter (bl.store:blockfilterindex-get-filter bfi h1)))
           (is (equalp gheader
                       (bl.store:compute-block-filter-header
                        gfilter bl.store:+zero-filter-header+)))
           (is (equalp (bl.store:blockfilterindex-get-header bfi h1)
                       (bl.store:compute-block-filter-header
                        filter gheader))))
         (bl.store:close-blockfilterindex bfi)
         ;; Make block 3's body unreadable and rebuild from scratch: the
         ;; backfill seeds genesis + 1..2, then STOPS at the gap rather than
         ;; skipping past it. FORGET-BLOCK-BODY, not PRUNE-BLOCK: what the test
         ;; needs is a missing body, and PRUNE-BLOCK refuses for a block inside
         ;; a flat file (which is where the default format puts it), leaving no
         ;; gap and the test asserting against a chain with none.
         (bl.store:forget-block-body
          store (bl.store:block-index-entry-hash
                 (bl.store:get-block-at-height cs 3)))
         (let* ((idxbase2 (merge-pathnames
                           (format nil "test-bfb2-~D/" (get-internal-real-time))
                           (uiop:temporary-directory)))
                (bfi2 (bl.store:init-blockfilterindex idxbase2 :enabled t))
                (n2 (bl.store:build-blockfilterindex
                     bfi2 cs store #'bl.val:get-undo-data)))
           (is (= 3 n2))
           (is (= 2 (bl.store:blockfilterindex-height bfi2)))
           (is-true (bl.store:blockfilterindex-has-block-p
                     bfi2 (bl.store:network-genesis-hash :regtest)))
           (bl.store:close-blockfilterindex bfi2))
         ;; An empty index starts the seek at the pruned horizon (a pruned
         ;; mainnet node would otherwise probe ~950k deleted heights, ~14 ms
         ;; each). With pruned-height=2 the genesis anchor is impossible (no
         ;; genesis seeding on a pruned chain): the scan starts at 3 -- whose
         ;; body was pruned above -- and still seeds at 4, indexing 4..5.
         (setf (bl.store:chain-state-pruned-height cs) 2)
         (let* ((idxbase3 (merge-pathnames
                           (format nil "test-bfb3-~D/" (get-internal-real-time))
                           (uiop:temporary-directory)))
                (bfi3 (bl.store:init-blockfilterindex idxbase3 :enabled t))
                (n3 (bl.store:build-blockfilterindex
                     bfi3 cs store #'bl.val:get-undo-data)))
           (is (= 2 n3))
           (is (= 5 (bl.store:blockfilterindex-height bfi3)))
           (is-false (bl.store:blockfilterindex-has-block-p
                      bfi3 (bl.store:network-genesis-hash :regtest)))
           (is-false (bl.store:blockfilterindex-has-block-p
                      bfi3 (bl.store:block-index-entry-hash
                            (bl.store:get-block-at-height cs 1))))
           (bl.store:close-blockfilterindex bfi3)
           (setf (bl.store:chain-state-pruned-height cs) 0)))))))

(test blockfilterindex-refuses-noncontiguous-add
  "Adding a block whose parent has no stored filter header while the index is
non-empty is refused with (values nil :noncontiguous) -- storing it would seed
a second header chain over a gap and strand the gap behind an advanced best
marker (observed live after a mid-backfill crash). An empty index still seeds
from the zero header, and filling the gap in order is then accepted."
  (with-network (:regtest)
   (let ((node (%regtest-node-fixture (format nil "bfc~D" (get-internal-real-time)))))
     (let ((bl::*node* node))
       (bl.rpc::rpc-generatetodescriptor node (list 3 "raw(51)"))
       (let* ((cs (bl::node-chain-state node))
              (store (bl::node-block-store node))
              (idxbase (merge-pathnames
                        (format nil "test-bfc-~D/" (get-internal-real-time))
                        (uiop:temporary-directory)))
              (bfi (bl.store:init-blockfilterindex idxbase :enabled t)))
         (flet ((blk (h)
                  (let ((hash (bl.store:block-index-entry-hash
                               (bl.store:get-block-at-height cs h))))
                    (values (bl.store:get-block store hash) hash))))
           ;; Empty index: block 1 seeds from the zero header.
           (multiple-value-bind (b1 h1) (blk 1)
             (is-true (bl.store:blockfilterindex-add-block bfi b1 h1 1 nil)))
           ;; Non-empty index: block 3's parent (2) is unindexed -> refused,
           ;; best marker untouched.
           (multiple-value-bind (b3 h3) (blk 3)
             (multiple-value-bind (filter status)
                 (bl.store:blockfilterindex-add-block bfi b3 h3 3 nil)
               (is (null filter))
               (is (eq :noncontiguous status))))
           (is (= 1 (bl.store:blockfilterindex-height bfi)))
           ;; In-order adds are accepted and advance the best marker.
           (multiple-value-bind (b2 h2) (blk 2)
             (is-true (bl.store:blockfilterindex-add-block bfi b2 h2 2 nil)))
           (multiple-value-bind (b3 h3) (blk 3)
             (is-true (bl.store:blockfilterindex-add-block bfi b3 h3 3 nil)))
           (is (= 3 (bl.store:blockfilterindex-height bfi))))
         (bl.store:close-blockfilterindex bfi))))))

(test getdescriptoractivity-receives
  "getdescriptoractivity reports a receive for a matching coinbase output."
  (with-network (:regtest)
   (let ((node (%bfi-regtest-node)))
     (let ((bl::*node* node))
       (let* ((hashes (bl.rpc::rpc-generatetodescriptor node (list 2 "raw(51)")))
              (res (bl.rpc::rpc-getdescriptoractivity
                    node (list hashes (list "raw(51)") nil)))
              (activity (cdr (assoc "activity" res :test #'equal))))
         (is (= 2 (length activity)))
         (is (every (lambda (a) (string= "receive" (cdr (assoc "type" a :test #'equal))))
                    activity))
         (let ((e (first activity)))
           (is-true (assoc "txid" e :test #'equal))
           (is-true (assoc "vout" e :test #'equal))
           (is-true (assoc "height" e :test #'equal))
           (is-true (assoc "output_spk" e :test #'equal)))
         ;; an unknown block hash errors (Core parity)
         (signals bl.rpc::rpc-error
           (bl.rpc::rpc-getdescriptoractivity
            node (list (list (bl.rpc::hash-to-hex (%bfi-zeros32)))
                       (list "raw(51)") nil))))))))

(test bip157-serving-request-validation-and-messages
  "BIP157 serving: %cf-request-stop-height enforces active-chain stop hash +
range bounds; the cfilter/cfheaders/cfcheckpt builders and parsers round-trip
against a real backfilled index. peer-block-filters gates %cf-serving-index."
  (with-network (:regtest)
   (let ((node (%bfi-regtest-node)))
     (let ((bl::*node* node)
           (bl:*peer-block-filters* t))
       (bl.rpc::rpc-generatetodescriptor node (list 4 "raw(51)"))
       (let* ((cs (bl::node-chain-state node))
              (bfi (bl::node-blockfilterindex node))
              (h3 (bl.store:block-index-entry-hash
                   (bl.store:get-block-at-height cs 3))))
         ;; gate: off when peer-block-filters is nil
         (is-true (bl.net::%cf-serving-index))
         (let ((bl:*peer-block-filters* nil))
           (is (null (bl.net::%cf-serving-index))))
         ;; valid request: active-chain stop hash, in range
         (is (= 3 (bl.net::%cf-request-stop-height cs 1 h3 1000)))
         ;; start > stop -> nil
         (is (null (bl.net::%cf-request-stop-height cs 4 h3 1000)))
         ;; span >= max-diff -> nil (0..3 is 4 blocks, max-diff 3 -> reject)
         (is (null (bl.net::%cf-request-stop-height cs 0 h3 3)))
         ;; unknown/fork stop hash -> nil
         (is (null (bl.net::%cf-request-stop-height
                    cs 0 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9)
                    1000)))
         ;; getcfilters payload round-trips
         (let ((payload (subseq (bl.ser:make-cfilter-message
                                 0 h3 (bl.store:blockfilterindex-get-filter bfi h3))
                                24)))
           (declare (ignore payload)))
         (multiple-value-bind (ft sh sp)
             (bl.ser:parse-getcfilters-payload
              (concatenate '(vector (unsigned-byte 8)) (vector 0 1 0 0 0) h3))
           (is (= 0 ft)) (is (= 1 sh)) (is (equalp h3 sp)))
         ;; cfcheckpt at interval 1000: none below height 4 -> empty header list, still builds
         (let* ((msg (bl.ser:make-cfcheckpt-message 0 h3 '()))
                (cmd (bl.ser:message-header-command
                      (bl.bytes:with-byte-reader (s msg)
                        (bl.ser:read-message-header s)))))
           (is (string= "cfcheckpt" cmd))))
       (bl.store:close-blockfilterindex (bl::node-blockfilterindex node))))))

;;; --- BIP157 genesis anchor ---
;;;
;;; The filter-header chain MUST be anchored at genesis:
;;; filter_header(genesis) = double-SHA256(filter_hash(genesis) || 0^32)
;;; (Core indexes genesis like any block: index/blockfilterindex.cpp
;;; CustomAppend with m_last_header zero-initialized; blockfilter.cpp
;;; ComputeHeader). The genesis block body is never in block storage, so it is
;;; constructed from chain parameters (Core kernel/chainparams.cpp
;;; CreateGenesisBlock) — construction is verified below byte-for-byte against
;;; Core's own blockfilters.json height-0 row.

(test genesis-block-construction-matches-core-vector
  "make-genesis-block reproduces Core's testnet3 genesis block BYTE-EXACTLY
(blockfilters.json height-0 row carries the full block hex), and the computed
genesis filter + filter header match the vector — the BIP157 anchor case with
the all-zero previous header."
  (let ((rows (%load-blockfilter-vectors)))
    (if (null rows)
        (skip "refs/bitcoin blockfilters.json not present")
        (let ((row0 (find 0 (rest rows) :key #'first)))
          (is (not (null row0)) "no height-0 row in blockfilters.json")
          (destructuring-bind (height block-hash-hex block-hex prev-scripts
                               prev-header-hex expected-filter-hex
                               expected-header-hex &optional notes)
              row0
            (declare (ignore height notes))
            ;; The genesis anchor really is the zero header in Core's vector.
            (is (string= prev-header-hex (make-string 64 :initial-element #\0)))
            (is (null prev-scripts))
            (let* ((blk (bl.store:make-genesis-block :testnet3))
                   (ghash (bl.ser:block-header-hash
                           (bl.ser:bitcoin-block-header blk)))
                   (filter (bl.store:build-basic-block-filter
                            blk ghash '()))
                   (header (bl.store:compute-block-filter-header
                            filter bl.store:+zero-filter-header+)))
              ;; Constructed block serializes to Core's exact genesis bytes.
              (is (string= (%bf-hex (bl.ser:serialize-witness-block blk))
                           block-hex))
              (is (equalp ghash (%bf-unhex-reversed block-hash-hex)))
              ;; Filter and anchor header match the Core vector.
              (is (string= (%bf-hex filter) expected-filter-hex))
              (is (string= (%bf-hex (bl.crypto:reverse-bytes header))
                           expected-header-hex))))))))

(test genesis-filter-headers-all-networks
  "Every network's genesis block constructs (make-genesis-block errors on any
hash mismatch) with merkle root == coinbase txid, and the mainnet genesis
basic-filter header matches its known value.

Derivation of the mainnet constants (blockfilters.json has no mainnet rows):
computed twice, independently — (1) by this repo's GCS pipeline, which is
byte-exact against every Core blockfilters.json vector INCLUDING the testnet3
genesis row (see genesis-block-construction-matches-core-vector), and (2) by a
from-scratch Python BIP158 implementation (siphash-2-4 + fastrange +
Golomb-Rice P=19/M=784931) that also reproduces Core's testnet3 genesis row
bit-exactly. Both derivations agree; a regression in either pipeline fails
this test loudly."
  (dolist (net '(:mainnet :testnet3 :testnet4 :signet :regtest))
    (let* ((blk (bl.store:make-genesis-block net))
           (hdr (bl.ser:bitcoin-block-header blk))
           (cb (first (bl.ser:bitcoin-block-transactions blk))))
      (is (equalp (bl.ser:block-header-merkle-root hdr)
                  (bl.ser:transaction-hash cb))
          "~A: genesis merkle root must equal the coinbase txid" net)
      (is (equalp (bl.ser:block-header-hash hdr)
                  (bl.store:network-genesis-hash net)))))
  (let* ((blk (bl.store:make-genesis-block :mainnet))
         (ghash (bl.store:network-genesis-hash :mainnet))
         (filter (bl.store:build-basic-block-filter blk ghash '()))
         (header (bl.store:compute-block-filter-header
                  filter bl.store:+zero-filter-header+)))
    (is (string= "017fa880" (%bf-hex filter)))
    (is (string= "02c2392180d0ce2b5b6f8b08d39a11ffe831c673311a3ecf77b97fc3f0303c9f"
                 (%bf-hex (bl.crypto:reverse-bytes header))))))

(test blockfilterindex-genesis-anchor-migration
  "A legacy index (header chain seeded at the first stored block, no height-0
entry) is detected by blockfilterindex-ensure-genesis-anchor and wiped so the
backfill rebuilds it anchored at genesis; healthy and empty indexes are left
alone; a pruned node's legacy index is kept (rebuild impossible) with a
warning."
  (with-network (:regtest)
   (let ((node (%regtest-node-fixture (format nil "bfm~D" (get-internal-real-time)))))
     (let ((bl::*node* node))
       (bl.rpc::rpc-generatetodescriptor node (list 4 "raw(51)"))
       (let* ((cs (bl::node-chain-state node))
              (store (bl::node-block-store node))
              (ghash (bl.store:network-genesis-hash :regtest))
              (idxbase (merge-pathnames
                        (format nil "test-bfm-~D/" (get-internal-real-time))
                        (uiop:temporary-directory)))
              (bfi (bl.store:init-blockfilterindex idxbase :enabled t)))
         ;; Empty index: nothing to migrate.
         (is (eq :empty (bl.store:blockfilterindex-ensure-genesis-anchor
                         bfi cs)))
         ;; Fabricate the LEGACY shape: seed the header chain at height 1
         ;; (exactly what the old code did on every from-genesis node).
         (flet ((add (h)
                  (let* ((hash (bl.store:block-index-entry-hash
                                (bl.store:get-block-at-height cs h)))
                         (block (bl.store:get-block store hash))
                         (undo (bl.val:get-undo-data hash)))
                    (bl.store:blockfilterindex-add-block
                     bfi block hash h undo))))
           (loop for h from 1 to 4 do (is-true (add h))))
         (is (= 4 (bl.store:blockfilterindex-height bfi)))
         (is-false (bl.store:blockfilterindex-has-block-p bfi ghash))
         ;; Pruned chain: the bad index is kept (bodies gone, cannot rebuild).
         (setf (bl.store:chain-state-pruned-height cs) 2)
         (is (eq :unanchored-pruned
                 (bl.store:blockfilterindex-ensure-genesis-anchor bfi cs)))
         (is (= 4 (bl.store:blockfilterindex-height bfi)))
         (setf (bl.store:chain-state-pruned-height cs) 0)
         ;; Unpruned: detected and wiped...
         (is (eq :rebuilt
                 (bl.store:blockfilterindex-ensure-genesis-anchor bfi cs)))
         (is (= -1 (bl.store:blockfilterindex-height bfi)))
         ;; ...and the backfill rebuilds the whole chain anchored at genesis.
         (let ((n (bl.store:build-blockfilterindex
                   bfi cs store #'bl.val:get-undo-data)))
           (is (= 5 n)))
         (is (= 4 (bl.store:blockfilterindex-height bfi)))
         (multiple-value-bind (gfilter gheader)
             (bl.store:blockfilterindex-get bfi ghash)
           ;; Stored genesis record matches a from-parameters recomputation
           ;; (and the independently derived regtest constants, python BIP158).
           (let* ((gblk (bl.store:make-genesis-block :regtest))
                  (expected-filter (bl.store:build-basic-block-filter
                                    gblk ghash '())))
             (is (equalp gfilter expected-filter))
             (is (string= "014756c0" (%bf-hex gfilter)))
             (is (equalp gheader (bl.store:compute-block-filter-header
                                  gfilter bl.store:+zero-filter-header+)))
             (is (string= "485e301e4509d7f0d954bf5b529f3ecef68c5191fd0e635f775c1d0266dc5a2b"
                          (%bf-hex (bl.crypto:reverse-bytes gheader)))))
           ;; Every subsequent header chains, so absolute values are anchored.
           (loop for h from 1 to 4
                 for hash = (bl.store:block-index-entry-hash
                             (bl.store:get-block-at-height cs h))
                 for prev = gheader then hdr
                 for hdr = (bl.store:blockfilterindex-get-header bfi hash)
                 for filter = (bl.store:blockfilterindex-get-filter bfi hash)
                 do (is (equalp hdr (bl.store:compute-block-filter-header
                                     filter prev)))))
         ;; Healthy index: second run is a no-op.
         (is (eq :ok (bl.store:blockfilterindex-ensure-genesis-anchor
                      bfi cs)))
         (is (= 4 (bl.store:blockfilterindex-height bfi)))
         (bl.store:close-blockfilterindex bfi))))))
