(in-package #:bitcoin-lisp.tests)

(def-suite :chainparams-tests
  :description "The chain-params table (src/util/chainparams.lisp): one
DEFINE-CHAIN-PARAMS per chain, consulted by everything that used to switch on
the network keyword."
  :in :bitcoin-lisp-tests)
(in-suite :chainparams-tests)

(test five-chains-are-defined
  (is (equal '(:mainnet :testnet3 :testnet4 :signet :regtest) (bl.chain:chain-names)))
  (signals error (bl.chain:find-chain-params :no-such-chain)))

(test chain-params-are-distinct-where-they-must-be
  "Magic bytes, P2P ports, RPC ports and data directories separate the chains
on the wire and on disk; two chains sharing any of them would talk to or
overwrite each other."
  (let ((all (mapcar #'bl.chain:find-chain-params (bl.chain:chain-names))))
    (flet ((distinct (accessor &key (test #'eql))
             (= (length all)
                (length (remove-duplicates (mapcar accessor all) :test test)))))
      (is-true (distinct #'bl.chain:chain-params-magic :test #'equalp))
      (is-true (distinct #'bl.chain:chain-params-port))
      (is-true (distinct #'bl.chain:chain-params-rpc-port))
      (is-true (distinct #'bl.chain:chain-params-core-name :test #'string=))
      (is-true (distinct #'bl.chain:chain-params-data-subdirectory :test #'equal))
      (is-true (distinct #'bl.chain:chain-params-genesis-hash :test #'equalp)))
    (dolist (p all)
      (let ((name (bl.chain:chain-params-name p))
            (hs (bl.chain:chain-params-headers-sync-params p)))
        (is (member (bl.chain:chain-params-bech32-hrp p) '("bc" "tb" "bcrt") :test #'string=))
        (is (and (integerp (car hs)) (plusp (car hs)) (integerp (cdr hs)) (> (cdr hs) (car hs)))
            "~A headers-sync-params ~S" name hs)
        (is (plusp (bl.chain:chain-params-prune-after-height p)))
        ;; the hex the consumers reverse: exactly 64 hex digits each, heights ascending
        (flet ((hex64-p (h) (and (stringp h) (= 64 (length h))
                                 (every (lambda (c) (digit-char-p c 16)) h)))
               (ascending-p (heights) (equal heights (sort (copy-list heights) #'<))))
          (is (or (null (bl.chain:chain-params-assumevalid-hex p))
                  (hex64-p (bl.chain:chain-params-assumevalid-hex p)))
              "~A assumevalid" name)
          (is (every (lambda (c) (hex64-p (cdr c))) (bl.chain:chain-params-checkpoints p))
              "~A checkpoints" name)
          (is (ascending-p (mapcar #'car (bl.chain:chain-params-checkpoints p)))
              "~A checkpoint heights" name)
          (is (every (lambda (e) (and (hex64-p (second e)) (hex64-p (third e))
                                      (integerp (first e)) (integerp (fourth e))))
                     (bl.chain:chain-params-assumeutxo p))
              "~A assumeutxo" name)
          (is (ascending-p (mapcar #'first (bl.chain:chain-params-assumeutxo p)))
              "~A assumeutxo heights" name))))))

(test chain-consumers-decode-every-chain
  "The two consumers that transform table data -- assumeutxo entries and the
assumevalid hash, both reversed from display order -- produce 32-byte hashes
for every chain."
  (dolist (name (bl.chain:chain-names))
    (dolist (entry (bl:network-assumeutxo-data name))
      (is (= 32 (length (bl:assumeutxo-data-blockhash entry))) "~A assumeutxo" name)
      (is (= 32 (length (bl:assumeutxo-data-hash-serialized entry))) "~A assumeutxo" name))
    (let ((av (bl:network-assumevalid name)))
      (is (or (null av) (= 32 (length av))) "~A assumevalid" name))))

(test every-chain-rebuilds-its-genesis-block
  "make-genesis-block is self-verifying: it recomputes the merkle root from the
timestamp message and checks the header hash against the table's genesis hash,
so a wrong nTime, nBits, nNonce or pszTimestamp in the table cannot pass."
  (dolist (name (bl.chain:chain-names))
    (finishes (bl.store:make-genesis-block name))))

(test chain-accessors-agree-with-core
  "Spot checks against kernel/chainparams.cpp for the values a typo would
silently corrupt: ports, activation heights, the mainnet assumevalid hash."
  (let ((main (bl.chain:find-chain-params :mainnet))
        (t4 (bl.chain:find-chain-params :testnet4))
        (reg (bl.chain:find-chain-params :regtest)))
    (is (= 8333 (bl.chain:chain-params-port main)))
    (is (= 48333 (bl.chain:chain-params-port t4)))
    (is (= 18444 (bl.chain:chain-params-port reg)))
    (is (= 227931 (bl.chain:chain-params-bip34-height main)))
    (is (= 481824 (bl.chain:chain-params-segwit-height main)))
    (is (= 709632 (bl.chain:chain-params-taproot-height main)))
    (is (= 0 (bl.chain:chain-params-segwit-height reg)))
    (is (= 0 (bl.chain:chain-params-taproot-height reg)))
    (is (null (bl.chain:chain-params-assumevalid-hex reg)))
    (is (zerop (bl.chain:chain-params-minimum-chain-work reg)))
    (is (= 13 (length (bl.chain:chain-params-checkpoints main))))
    (is (= 63 (length (bl.chain:chain-params-fixed-seeds t4))))
    ;; the consumers still answer through their old names
    (is (equal "main" (bl.cfg:conf-section-name :mainnet)))
    (is (= 18332 (bl:network-rpc-port :testnet3)))
    (is (= 1 (bl.val:get-segwit-activation-height :signet)))))
