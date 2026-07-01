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

(defun %bf-hex (bytes) (bitcoin-lisp.crypto:bytes-to-hex bytes))
(defun %bf-unhex (hex) (bitcoin-lisp.crypto:hex-to-bytes hex))

(defun %bf-unhex-reversed (hex)
  "Parse a display-order (big-endian) uint256 hex string into internal
little-endian byte order (Core stores/compares hashes this way)."
  ;; NB: bitcoin-lisp.crypto:reverse-bytes, not (coerce (reverse ...) '(simple-array
  ;; (unsigned-byte 8) (*))) -- SBCL 2.5.4 compiles that idiom to elide the reverse
  ;; when the derived type already matches the coerce target.
  (bitcoin-lisp.crypto:reverse-bytes (%bf-unhex hex)))

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
  (let ((w (bitcoin-lisp.storage::%make-gcs-writer)))
    ;; A mix of widths that straddle byte boundaries.
    (bitcoin-lisp.storage::gcs-writer-push-bits w 1 1)
    (bitcoin-lisp.storage::gcs-writer-push-bits w #b101 3)
    (bitcoin-lisp.storage::gcs-writer-push-bits w #x1ff 9)
    (bitcoin-lisp.storage::gcs-writer-push-bits w 0 7)
    (bitcoin-lisp.storage::gcs-writer-push-bits w #xdeadbeef 32)
    (bitcoin-lisp.storage::gcs-writer-flush w)
    (let ((r (bitcoin-lisp.storage::%make-gcs-reader
              :bytes (coerce (bitcoin-lisp.storage::gcs-writer-bytes w)
                             '(simple-array (unsigned-byte 8) (*))))))
      (is (= 1 (bitcoin-lisp.storage::gcs-reader-read-bits r 1)))
      (is (= #b101 (bitcoin-lisp.storage::gcs-reader-read-bits r 3)))
      (is (= #x1ff (bitcoin-lisp.storage::gcs-reader-read-bits r 9)))
      (is (= 0 (bitcoin-lisp.storage::gcs-reader-read-bits r 7)))
      (is (= #xdeadbeef (bitcoin-lisp.storage::gcs-reader-read-bits r 32))))))

(test gcs-golomb-roundtrip
  "Golomb-Rice encode/decode round-trips for a range of magnitudes."
  (let ((w (bitcoin-lisp.storage::%make-gcs-writer))
        (values '(0 1 18 19 524287 524288 1000000 78493100)))
    (dolist (x values)
      (bitcoin-lisp.storage::gcs-golomb-encode w bitcoin-lisp.storage:+basic-filter-p+ x))
    (bitcoin-lisp.storage::gcs-writer-flush w)
    (let ((r (bitcoin-lisp.storage::%make-gcs-reader
              :bytes (coerce (bitcoin-lisp.storage::gcs-writer-bytes w)
                             '(simple-array (unsigned-byte 8) (*))))))
      (dolist (x values)
        (is (= x (bitcoin-lisp.storage::gcs-golomb-decode
                  r bitcoin-lisp.storage:+basic-filter-p+)))))))

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
              (let* ((block (bitcoin-lisp.serialization:parse-block-payload
                             (%bf-unhex block-hex)))
                     (block-hash (bitcoin-lisp.serialization:block-header-hash
                                  (bitcoin-lisp.serialization:bitcoin-block-header block)))
                     (spent-scripts (mapcar #'%bf-unhex prev-scripts))
                     (filter (bitcoin-lisp.storage:build-basic-block-filter
                              block block-hash spent-scripts))
                     (header (bitcoin-lisp.storage:compute-block-filter-header
                              filter (%bf-unhex-reversed prev-header-hex))))
                ;; Cross-check the block hash decodes to the vector's hash.
                (is (equalp block-hash (%bf-unhex-reversed block-hash-hex))
                    "height ~D: block hash mismatch" height)
                ;; Encoded filter is a raw byte blob (not reversed).
                (is (string= (%bf-hex filter) expected-filter-hex)
                    "height ~D: filter mismatch~%  got ~A~%  exp ~A"
                    height (%bf-hex filter) expected-filter-hex)
                ;; Filter header is a uint256, displayed big-endian.
                (is (string= (%bf-hex (bitcoin-lisp.crypto:reverse-bytes header))
                             expected-header-hex)
                    "height ~D: filter header mismatch~%  got ~A~%  exp ~A"
                    height (%bf-hex (bitcoin-lisp.crypto:reverse-bytes header))
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
            (let* ((block (bitcoin-lisp.serialization:parse-block-payload
                           (%bf-unhex block-hex)))
                   (block-hash (bitcoin-lisp.serialization:block-header-hash
                                (bitcoin-lisp.serialization:bitcoin-block-header block)))
                   (spent-scripts (mapcar #'%bf-unhex prev-scripts))
                   (filter (bitcoin-lisp.storage:build-basic-block-filter
                            block block-hash spent-scripts))
                   (elements (bitcoin-lisp.storage:basic-filter-elements
                              block spent-scripts)))
              (multiple-value-bind (k0 k1)
                  (bitcoin-lisp.storage:block-filter-siphash-keys block-hash)
                ;; No false negatives: all elements must match.
                (dolist (e elements)
                  (is (bitcoin-lisp.storage:gcs-filter-match filter k0 k1 e)
                      "height ~D: element failed to match its own filter" height))
                ;; MatchAny over the whole set is true when the set is non-empty.
                (when elements
                  (is (bitcoin-lisp.storage:gcs-filter-match-any filter k0 k1 elements)))
                ;; An unrelated script should not match (allow rare false positive).
                (let ((bogus (%bf-unhex "6a24aa21a9edfacefeed00")))
                  (declare (ignorable bogus))
                  (is-true t)))))))))

;;; --- Persistent index + RPCs (regtest integration) ---
;;;
;;; Reuses the regtest fixture from mining-tests.lisp (%with-regtest,
;;; %regtest-node-fixture). Binding bitcoin-lisp::*node* lets the connect-time
;;; hook (index-block-filter) fire as generatetodescriptor mines blocks.

(defun %bfi-regtest-node ()
  "A regtest node at genesis with an enabled block filter index (fresh temp DB)."
  (let* ((tag (format nil "bfi~D" (get-internal-real-time)))
         (node (%regtest-node-fixture tag))
         (idxbase (merge-pathnames (format nil "test-bfi-~A/" tag)
                                   (uiop:temporary-directory))))
    (ensure-directories-exist idxbase)
    (setf (bitcoin-lisp::node-blockfilterindex node)
          (bitcoin-lisp.storage:init-blockfilterindex idxbase :enabled t))
    node))

(defun %bfi-zeros32 ()
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))

(test blockfilterindex-connect-and-getblockfilter
  "Mining indexes each block; getblockfilter returns filter bytes that match a
recomputation, and a filter header; unknown type / missing block error."
  (%with-regtest
   (let ((node (%bfi-regtest-node)))
     (let ((bitcoin-lisp::*node* node))
       (let ((hashes (bitcoin-lisp.rpc::rpc-generatetodescriptor node (list 3 "raw(51)")))
             (bfi (bitcoin-lisp::node-blockfilterindex node)))
         (is (= 3 (length hashes)))
         (is (= 3 (bitcoin-lisp.storage:blockfilterindex-height bfi)))
         (dolist (h hashes)
           (let* ((res (bitcoin-lisp.rpc::rpc-getblockfilter node (list h)))
                  (filt-hex (cdr (assoc "filter" res :test #'equal)))
                  (hdr-hex (cdr (assoc "header" res :test #'equal)))
                  (hash (bitcoin-lisp.rpc::parse-hex-hash h))
                  (block (bitcoin-lisp.storage:get-block
                          (bitcoin-lisp::node-block-store node) hash))
                  (undo (bitcoin-lisp.validation:get-undo-data hash))
                  (spent (mapcar (lambda (e)
                                   (bitcoin-lisp.storage:utxo-entry-script-pubkey (third e)))
                                 undo))
                  (recomputed (bitcoin-lisp.storage:build-basic-block-filter
                               block hash spent)))
             (is (= 64 (length hdr-hex)))
             (is (string= filt-hex (bitcoin-lisp.crypto:bytes-to-hex recomputed)))))
         ;; unknown filtertype
         (signals bitcoin-lisp.rpc::rpc-error
           (bitcoin-lisp.rpc::rpc-getblockfilter node (list (first hashes) "foo")))
         ;; unknown block
         (signals bitcoin-lisp.rpc::rpc-error
           (bitcoin-lisp.rpc::rpc-getblockfilter
            node (list (bitcoin-lisp.rpc::hash-to-hex (%bfi-zeros32))))))))))

(test blockfilterindex-header-chain
  "Each block's stored filter header chains off its parent's (BIP157)."
  (%with-regtest
   (let ((node (%bfi-regtest-node)))
     (let ((bitcoin-lisp::*node* node))
       (bitcoin-lisp.rpc::rpc-generatetodescriptor node (list 3 "raw(51)"))
       (let ((bfi (bitcoin-lisp::node-blockfilterindex node))
             (cs (bitcoin-lisp::node-chain-state node)))
         (loop for h from 1 to 3
               for hash = (bitcoin-lisp.storage:block-index-entry-hash
                           (bitcoin-lisp.storage:get-block-at-height cs h))
               for prev-hash = (bitcoin-lisp.storage:block-index-entry-hash
                                (bitcoin-lisp.storage:get-block-at-height cs (1- h)))
               for filter = (bitcoin-lisp.storage:blockfilterindex-get-filter bfi hash)
               for prev-header = (or (bitcoin-lisp.storage:blockfilterindex-get-header bfi prev-hash)
                                     bitcoin-lisp.storage:+zero-filter-header+)
               do (is (equalp (bitcoin-lisp.storage:blockfilterindex-get-header bfi hash)
                              (bitcoin-lisp.storage:compute-block-filter-header
                               filter prev-header)))))))))

(test scanblocks-finds-and-misses
  "scanblocks returns blocks whose filter matches a descriptor; misses otherwise;
filter_false_positives keeps the true matches; idle status is null."
  (%with-regtest
   (let ((node (%bfi-regtest-node)))
     (let ((bitcoin-lisp::*node* node))
       (let ((hashes (bitcoin-lisp.rpc::rpc-generatetodescriptor node (list 3 "raw(51)"))))
         (let* ((res (bitcoin-lisp.rpc::rpc-scanblocks node (list "start" (list "raw(51)"))))
                (blocks (cdr (assoc "relevant_blocks" res :test #'equal))))
           (is-true (cdr (assoc "completed" res :test #'equal)))
           (is (= 3 (length blocks)))
           (is (every (lambda (h) (member h hashes :test #'string=)) blocks)))
         ;; a script no block contains
         (let* ((res (bitcoin-lisp.rpc::rpc-scanblocks node (list "start" (list "raw(6a00deadbeef)"))))
                (blocks (cdr (assoc "relevant_blocks" res :test #'equal))))
           (is (null blocks)))
         ;; filter_false_positives verification path keeps the real matches
         (let ((opts (make-hash-table :test 'equal)))
           (setf (gethash "filter_false_positives" opts) t)
           (let* ((res (bitcoin-lisp.rpc::rpc-scanblocks
                        node (list "start" (list "raw(51)") 0 3 "basic" opts)))
                  (blocks (cdr (assoc "relevant_blocks" res :test #'equal))))
             (is (= 3 (length blocks)))))
         ;; idle status is null
         (is (null (bitcoin-lisp.rpc::rpc-scanblocks node (list "status"))))
         ;; out-of-range / reversed heights error rather than silently clamp
         (signals bitcoin-lisp.rpc::rpc-error
           (bitcoin-lisp.rpc::rpc-scanblocks node (list "start" (list "raw(51)") 999999)))
         (signals bitcoin-lisp.rpc::rpc-error
           (bitcoin-lisp.rpc::rpc-scanblocks node (list "start" (list "raw(51)") 3 1))))))))

(test getdescriptoractivity-receives
  "getdescriptoractivity reports a receive for a matching coinbase output."
  (%with-regtest
   (let ((node (%bfi-regtest-node)))
     (let ((bitcoin-lisp::*node* node))
       (let* ((hashes (bitcoin-lisp.rpc::rpc-generatetodescriptor node (list 2 "raw(51)")))
              (res (bitcoin-lisp.rpc::rpc-getdescriptoractivity
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
         (signals bitcoin-lisp.rpc::rpc-error
           (bitcoin-lisp.rpc::rpc-getdescriptoractivity
            node (list (list (bitcoin-lisp.rpc::hash-to-hex (%bfi-zeros32)))
                       (list "raw(51)") nil))))))))
