(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/headerssync.cpp at the pin: headers_sync_state, a
;;;; HeadersSyncState from mainnet's genesis (chain work 0, as the fuzz
;;;; target's bare CBlockIndex has) with a fuzzed commitment period,
;;;; redownload buffer, commitment offset and minimum work, fed batches of
;;;; headers -- fuzzed, now and then made continuous -- until it stops asking;
;;;; once it reaches REDOWNLOAD the batches are either fuzzed or slices of the
;;;; headers it presynced. Ours makes batches continuous seven times in eight
;;;; and replays three times in four (Core: one in two), since uniform bytes,
;;;; unlike a coverage-guided fuzzer, would seldom carry a sync that far. Core asserts that the presynced headers carry the
;;;; minimum work when the state turns to REDOWNLOAD. Ours: MAKE-HEADERS-SYNC
;;;; and HSS-PROCESS-NEXT-HEADERS, and beyond Core: the headers the
;;;; redownload releases are the presynced ones, in order -- a peer serving
;;;; the same chain twice is never refused a commitment it earned.

(def-suite :fuzz-headerssync-tests :in :bitcoin-lisp-tests
  :description "Core fuzz headerssync.cpp")

(in-suite :fuzz-headerssync-tests)

(defun %hss-fuzz-headers (fdp prev-hash genesis-bits continuous)
  "Up to 20 headers, mostly at genesis difficulty; chained to PREV-HASH when
CONTINUOUS (Core MakeHeadersContinuous)."
  (loop repeat (consume-integral-in-range fdp 1 20)
        collect (let ((h (bl.ser:make-block-header
                          :version (consume-integral fdp :i32)
                          :prev-block (if continuous prev-hash (consume-uint256 fdp))
                          :merkle-root (consume-uint256 fdp)
                          :timestamp (consume-integral fdp :u32)
                          :bits (if (plusp (consume-integral-in-range fdp 0 7))
                                    genesis-bits
                                    (consume-integral fdp :u32))
                          :nonce (consume-integral fdp :u32))))
                  (setf prev-hash (bl.ser:block-header-hash h))
                  h)))

(define-fuzz-target headers-sync-state
    (buffer :core "headerssync.cpp:42-109" :iterations 1500 :max-len 1500)
  "A headers sync presyncs any batches and turns to redownload only once the
presynced headers carry the minimum work; redownloading those same headers
releases exactly them, in order."
  (with-network (:mainnet)
    (let* ((fdp (make-fuzzed-data-provider buffer))
           (genesis (bl.ser:bitcoin-block-header (bl.store:make-genesis-block :mainnet)))
           (genesis-bits (bl.ser:block-header-bits genesis))
           (start (bl.store:make-block-index-entry
                   :hash (bl.ser:block-header-hash genesis) :height 0 :header genesis
                   :chain-work 0 :status :valid))
           (now (consume-integral-in-range fdp (bl.ser:block-header-timestamp genesis) 4133980799))
           (period (consume-integral-in-range fdp 1 (* 2 641)))
           (buffer-size (consume-integral-in-range fdp 0 (* 2 15218)))
           (proof (bl.store:calculate-chain-work genesis-bits 0))
           (min-work (if (consume-bool fdp)
                         (consume-integral-in-range fdp 0 (* 40 proof))
                         (bl.crypto:bytes-to-le-integer (consume-uint256 fdp))))
           (hss (bl.net:make-headers-sync start min-work :network :mainnet :now now
                                                         :salt (consume-bytes fdp 16)))
           (all '())
           (released '())
           (presync t)
           (replay 0)
           (request-more t))
      (setf (bl.net:hss-commitment-period hss) period
            (bl.net:hss-redownload-buffer-size hss) buffer-size
            (bl.net:hss-commit-offset hss) (consume-integral-in-range fdp 0 (1- period)))
      (loop while request-more
            do (let ((headers
                       (cond ((or presync (zerop (consume-integral-in-range fdp 0 3)))
                              (%hss-fuzz-headers fdp (if all (bl.ser:block-header-hash (car (last all)))
                                                         (bl.ser:block-header-hash genesis))
                                                 genesis-bits (plusp (consume-integral-in-range fdp 0 7))))
                             ((< replay (length all))
                              (let ((n (consume-integral-in-range fdp 1 (- (length all) replay))))
                                (prog1 (subseq all replay (+ replay n)) (incf replay n))))
                             (t nil))))
                 (unless headers (return))
                 (multiple-value-bind (success more ready)
                     (bl.net:hss-process-next-headers hss headers (consume-bool fdp))
                   (declare (ignore success))
                   (setf request-more more)
                   (setf released (append released ready))
                   (when more
                     (when presync
                       (setf all (append all headers))
                       (when (eq (bl.net:hss-state hss) :redownload)
                         (setf presync nil replay 0)
                         (fuzz-assert (fuzz-sabotage (>= (bl.net:claimed-headers-work start all) min-work))
                                      "redownload began with ~D headers short of the minimum work" (length all))))
                     (bl.net:hss-locator-hashes hss)))))
      (fuzz-assert (every #'equalp released (subseq all 0 (min (length all) (length released))))
                   "the redownload released headers other than the ones presynced"))))
