(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/utxo_snapshot.cpp at the pin, its utxo_snapshot_invalid
;;;; half: a snapshot file whose metadata and coins are the fuzzer's through
;;;; ActivateSnapshot, which must refuse it and leave nothing behind. Ours is
;;;; the loadtxoutset RPC on the process_message fixture node, whose header
;;;; chain is extended to regtest's height-110 assumeutxo block (its hash is
;;;; Core's, kernel/chainparams.cpp) so a snapshot naming it passes every
;;;; precondition and streams its coins through the population checks --
;;;; the per-coin height, vout and MoneyRange checks, the coins-count and EOF
;;;; checks, and the hash_serialized_3 comparison, which a fuzzed coin set
;;;; does not pass.
;;;;
;;;; Core's valid-snapshot half needs Core's own 200-block test chain, whose
;;;; commitment is the one in chainparams; ours cannot mine that chain, so a
;;;; load that SUCCEEDS is itself the failure here.

(def-suite :fuzz-utxo-snapshot-tests :in :bitcoin-lisp-tests
  :description "Core fuzz utxo_snapshot.cpp (invalid snapshots) over loadtxoutset")

(in-suite :fuzz-utxo-snapshot-tests)

(defun %regtest-assumeutxo-base ()
  "(height . hash) of regtest's first assumeutxo entry, the hash as the
snapshot metadata carries it."
  (let ((au (first (bl:network-assumeutxo-data :regtest))))
    (cons (bl:assumeutxo-data-height au) (bl:assumeutxo-data-blockhash au))))

(defun %extend-headers-to (node height hash)
  "Header-only entries on NODE's tip up to HEIGHT, the last one indexed under
HASH: a best header chain whose block at HEIGHT is the assumeutxo base."
  (let* ((cs (bl:node-chain-state node))
         (prev (bl.store:get-block-index-entry cs (bl.store:best-block-hash cs))))
    (loop for h from (1+ (bl.store:block-index-entry-height prev)) to height
          do (let* ((header (bl.ser:make-block-header
                             :version #x20000000
                             :prev-block (bl.store:block-index-entry-hash prev)
                             :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3)
                             :timestamp (+ 1610000000 h) :bits #x207fffff :nonce h))
                    (entry-hash (if (= h height) hash (bl.ser:block-header-hash header)))
                    (entry (bl.store:make-block-index-entry
                            :hash entry-hash :height h :header header :prev-entry prev
                            :status :header-valid
                            :chain-work (+ 2 (bl.store:block-index-entry-chain-work prev)))))
               (bl.store:add-block-index-entry cs entry)
               (setf prev entry)))))

(defun %fuzz-snapshot-bytes (fdp base-hash)
  "A snapshot file: metadata (Core's layout with a fuzzed base -- usually the
assumeutxo block -- and coins count, or raw bytes) and a coin stream (txid
groups of compressed coins, heights and vouts sometimes out of range, or raw
bytes)."
  (flexi-streams:with-output-to-sequence (s :element-type '(unsigned-byte 8))
    (if (zerop (consume-integral-in-range fdp 0 7))
        (write-sequence (consume-random-length-byte-vector fdp 60) s)
        (progn
          (write-sequence #(#x75 #x74 #x78 #x6f #xff) s)
          (bl.ser:write-uint16-le s (pick-value-in-array fdp (list 2 2 2 (consume-integral fdp :u16))))
          (write-sequence (if (plusp (consume-integral-in-range fdp 0 7))
                              (bl.chain:network-magic :regtest)
                              (bl.chain:network-magic :mainnet))
                          s)
          (write-sequence (if (plusp (consume-integral-in-range fdp 0 7)) base-hash (consume-uint256 fdp)) s)
          (bl.ser:write-uint64-le s (consume-integral-in-range fdp 0 12))))
    (if (zerop (consume-integral-in-range fdp 0 7))
        (write-sequence (consume-random-length-byte-vector fdp 200) s)
        (loop repeat (consume-integral-in-range fdp 0 6)
              do (write-sequence (consume-uint256 fdp) s)
                 (let ((n (consume-integral-in-range fdp 0 3)))
                   (bl.ser:write-compact-size s n)
                   (dotimes (i n)
                     (bl.ser:write-compact-size s (pick-value-in-array fdp (list i 0 (consume-integral fdp :u32))))
                     (let ((bb (bl.ser:make-byte-buf)))
                       (bl.ser:bb-write-core-varint
                        bb (+ (* 2 (pick-value-in-array fdp (list (consume-integral-in-range fdp 0 110)
                                                                  (consume-integral-in-range fdp 111 #x7fffffff))))
                              (if (consume-bool fdp) 1 0)))
                       (write-sequence (bl.ser:bb-finish bb) s))
                     (write-sequence (%compressed-tx-out-bytes (consume-money fdp) (consume-script fdp)) s)))))
    (when (consume-bool fdp)
      (write-sequence (consume-random-length-byte-vector fdp 20) s))))

(define-fuzz-target utxo-snapshot-invalid
    (buffer :core "utxo_snapshot.cpp:103-231 (utxo_snapshot_invalid)" :iterations 30 :max-len 1500)
  "A snapshot of any metadata and coins is refused by loadtxoutset with an RPC
error -- never another condition -- leaves no snapshot chainstate and no
chainstate_snapshot directory behind, and is refused again on a second try."
  (let ((fdp (make-fuzzed-data-provider buffer)))
    (with-fuzz-p2p-node (p2p)
      (with-temp-directory (dir "fuzz-utxo-snapshot")
        (let* ((node (fp-node p2p))
               (base (%regtest-assumeutxo-base))
               (path (merge-pathnames "snapshot.dat" dir)))
          (setf (bl:node-data-directory node) dir)
          (%extend-headers-to node (car base) (cdr base))
          (with-open-file (out path :direction :output :element-type '(unsigned-byte 8))
            (write-sequence (%fuzz-snapshot-bytes fdp (cdr base)) out))
          (flet ((load-once ()
                   (handler-case
                       (progn (bl.rpc:dispatch-rpc-method node "loadtxoutset" (list (namestring path)))
                              :loaded)
                     (bl.rpc:rpc-error () :refused))))
            (fuzz-assert (eq (fuzz-sabotage (load-once)) :refused)
                         "a fuzzed snapshot was loaded")
            (fuzz-assert (and (= 1 (length (bl:node-chainstates node)))
                              (null (bl.store:chain-state-from-snapshot-blockhash
                                     (bl:node-chain-state node))))
                         "a refused snapshot left a snapshot chainstate")
            (fuzz-assert (null (directory (merge-pathnames "**/chainstate_snapshot/" dir)))
                         "a refused snapshot left its chainstate directory")
            (fuzz-assert (eq (load-once) :refused) "the second load was not refused")))))))
