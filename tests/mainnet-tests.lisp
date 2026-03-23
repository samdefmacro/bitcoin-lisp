(in-package #:bitcoin-lisp.tests)

(in-suite :integration-tests)

;;;; Mainnet Support Tests
;;;; Tests for network parameter selection and mainnet-specific functionality.

;;; Task 7.1: network-genesis-hash tests

(test network-genesis-hash-testnet
  "network-genesis-hash should return testnet genesis for :testnet3"
  (let ((genesis (bitcoin-lisp.storage:network-genesis-hash :testnet3)))
    (is (= 32 (length genesis)))
    ;; Testnet genesis hash (little-endian)
    (is (equalp genesis bitcoin-lisp.storage:\*testnet3-genesis-hash\*))))

(test network-genesis-hash-mainnet
  "network-genesis-hash should return mainnet genesis for :mainnet."
  (let ((genesis (bitcoin-lisp.storage:network-genesis-hash :mainnet)))
    (is (= 32 (length genesis)))
    ;; Mainnet genesis hash (little-endian)
    (is (equalp genesis bitcoin-lisp.storage:*mainnet-genesis-hash*))
    ;; Verify it's different from testnet
    (is (not (equalp genesis bitcoin-lisp.storage:\*testnet3-genesis-hash\*)))))

(test mainnet-genesis-hash-value
  "Mainnet genesis hash should match known value."
  ;; Display format (big-endian): 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
  (let* ((genesis bitcoin-lisp.storage:*mainnet-genesis-hash*)
         (reversed (reverse genesis))
         (hex (bitcoin-lisp.crypto:bytes-to-hex reversed)))
    (is (string= "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f" hex))))

;;; Task 7.2: get-checkpoint-hash tests

(test get-checkpoint-hash-testnet
  "get-checkpoint-hash should return testnet checkpoints when on testnet."
  (let ((bitcoin-lisp:*network* :testnet3))
    ;; Height 546 is a testnet checkpoint
    (let ((hash (bitcoin-lisp.networking:get-checkpoint-hash 546)))
      (is-true hash "Testnet checkpoint at 546 should exist")
      (is (= 32 (length hash))))
    ;; Height 11111 is NOT a testnet checkpoint (it's mainnet)
    (let ((hash (bitcoin-lisp.networking:get-checkpoint-hash 11111)))
      (is-false hash "Height 11111 is not a testnet checkpoint"))))

(test get-checkpoint-hash-mainnet
  "get-checkpoint-hash should return mainnet checkpoints when on mainnet."
  (let ((bitcoin-lisp:*network* :mainnet))
    ;; Height 11111 is a mainnet checkpoint
    (let ((hash (bitcoin-lisp.networking:get-checkpoint-hash 11111)))
      (is-true hash "Mainnet checkpoint at 11111 should exist")
      (is (= 32 (length hash))))
    ;; Height 546 is NOT a mainnet checkpoint (it's testnet)
    (let ((hash (bitcoin-lisp.networking:get-checkpoint-hash 546)))
      (is-false hash "Height 546 is not a mainnet checkpoint"))))

(test last-checkpoint-height-testnet
  "last-checkpoint-height should return testnet's last checkpoint when on testnet."
  (let ((bitcoin-lisp:*network* :testnet3))
    (let ((height (bitcoin-lisp.networking:last-checkpoint-height)))
      ;; Testnet's last checkpoint is at 2000000
      (is (= 2000000 height)))))

(test last-checkpoint-height-mainnet
  "last-checkpoint-height should return mainnet's last checkpoint when on mainnet."
  (let ((bitcoin-lisp:*network* :mainnet))
    (let ((height (bitcoin-lisp.networking:last-checkpoint-height)))
      ;; Mainnet's last checkpoint is at 840000 (fourth halving)
      (is (= 840000 height)))))

;;; Task 7.3: get-bip34-activation-height tests

(test get-bip34-activation-height-testnet
  "get-bip34-activation-height should return 21111 for testnet."
  (is (= 21111 (bitcoin-lisp.validation:get-bip34-activation-height :testnet3))))

(test get-bip34-activation-height-mainnet
  "get-bip34-activation-height should return 227931 for mainnet."
  (is (= 227931 (bitcoin-lisp.validation:get-bip34-activation-height :mainnet))))

;;; Task 7.4: network-rpc-port tests

(test network-rpc-port-testnet
  "network-rpc-port should return 18332 for testnet."
  (is (= 18332 (bitcoin-lisp:network-rpc-port :testnet3))))

(test network-rpc-port-mainnet
  "network-rpc-port should return 8332 for mainnet."
  (is (= 8332 (bitcoin-lisp:network-rpc-port :mainnet))))

;;; Task 7.5: Mainnet genesis block header validation

(test mainnet-genesis-hash-valid
  "Mainnet genesis hash should be a valid 32-byte hash."
  (let ((genesis bitcoin-lisp.storage:*mainnet-genesis-hash*))
    (is (typep genesis '(simple-array (unsigned-byte 8) (32))))
    ;; Genesis hash should not be all zeros
    (is-false (every #'zerop genesis))))

;;; Additional: relay-enabled-p tests

(test relay-enabled-testnet
  "Relay should always be enabled on testnet."
  (let ((bitcoin-lisp:*network* :testnet3)
        (bitcoin-lisp:*mainnet-relay-enabled* nil))
    (is-true (bitcoin-lisp.networking:relay-enabled-p))))

(test relay-disabled-mainnet-default
  "Relay should be disabled on mainnet by default."
  (let ((bitcoin-lisp:*network* :mainnet)
        (bitcoin-lisp:*mainnet-relay-enabled* nil))
    (is-false (bitcoin-lisp.networking:relay-enabled-p))))

(test relay-enabled-mainnet-when-flag-set
  "Relay should be enabled on mainnet when flag is set."
  (let ((bitcoin-lisp:*network* :mainnet)
        (bitcoin-lisp:*mainnet-relay-enabled* t))
    (is-true (bitcoin-lisp.networking:relay-enabled-p))))

;;; Network parameter consistency tests

(test network-parameters-consistent
  "All network parameter functions should work for both networks."
  (dolist (network '(:testnet3 :mainnet))
    ;; All these should return valid values without error
    (is-true (bitcoin-lisp:network-magic network))
    (is-true (bitcoin-lisp:network-port network))
    (is-true (bitcoin-lisp:network-dns-seeds network))
    (is-true (bitcoin-lisp:network-rpc-port network))
    (is-true (bitcoin-lisp.storage:network-genesis-hash network))
    (is-true (bitcoin-lisp.networking:network-checkpoints network))
    (is-true (bitcoin-lisp.validation:get-bip34-activation-height network))))
