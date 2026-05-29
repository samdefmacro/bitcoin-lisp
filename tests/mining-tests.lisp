(in-package #:bitcoin-lisp.tests)

;;; Mining / regtest tests.
;;;
;;; PR0 (this file's first section): regtest network params + the no-retarget
;;; difficulty rule + the network-aware PoW limit. Later mining PRs (block
;;; assembler, getblocktemplate, submitblock) add to this suite.

(in-suite :mining-tests)

(defun %zeros (n) (make-array n :element-type '(unsigned-byte 8) :initial-element 0))

;;;; Regtest network parameters

(test regtest-network-params
  (is (equalp bitcoin-lisp.serialization:+regtest-magic+
              (bitcoin-lisp::network-magic :regtest)))
  (is (= 18444 (bitcoin-lisp::network-port :regtest)))
  (is (= 18443 (bitcoin-lisp::network-rpc-port :regtest)))
  (is (null (bitcoin-lisp::network-dns-seeds :regtest))))

(test regtest-genesis-hash-matches-core
  ;; make-genesis-header must hash to Core's regtest genesis
  ;; 0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206.
  (let* ((hdr (bitcoin-lisp::make-genesis-header :regtest))
         (hash (bitcoin-lisp.serialization:block-header-hash hdr)))
    (is (equalp hash (bitcoin-lisp.storage:network-genesis-hash :regtest)))
    (is (string-equal
         "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
         (bitcoin-lisp.crypto:bytes-to-hex (reverse hash))))))

;;;; Network-aware PoW limit

(test regtest-pow-limit-accepts-trivial-bits
  ;; 0x207fffff decodes to a target above the standard PoW limit, so it is
  ;; rejected on testnet/mainnet but accepted under the regtest limit.
  (let ((bitcoin-lisp.storage:*pow-limit-target* bitcoin-lisp.storage:+pow-limit-target+))
    (is (null (bitcoin-lisp.storage:derive-target #x207fffff))))
  (let ((bitcoin-lisp.storage:*pow-limit-target* bitcoin-lisp.storage:+regtest-pow-limit-target+))
    (is-true (bitcoin-lisp.storage:derive-target #x207fffff))))

;;;; No-retarget difficulty (fPowNoRetargeting)

(test regtest-difficulty-never-retargets
  ;; Every regtest block inherits the previous block's bits — even at what would
  ;; be a 2016-block retarget boundary on other networks.
  (let* ((hdr (bitcoin-lisp.serialization:make-block-header
               :version 1 :prev-block (%zeros 32) :merkle-root (%zeros 32)
               :timestamp 1296688602 :bits #x207fffff :nonce 0))
         (prev (bitcoin-lisp.storage:make-block-index-entry
                :hash (%zeros 32) :header hdr :height 0)))
    (let ((bitcoin-lisp:*network* :regtest))
      ;; non-boundary
      (is (= #x207fffff (bitcoin-lisp.validation::get-expected-bits 1 prev)))
      ;; boundary height — regtest still inherits, no retarget
      (is (= #x207fffff (bitcoin-lisp.validation::get-expected-bits 2016 prev))))))
