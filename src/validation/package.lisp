;;;; Package bitcoin-lisp.validation -- the public API of src/validation/.
;;;;
;;;; Loaded with the other package files before any code (bitcoin-lisp.asd,
;;;; the "packages" phase): src/config.lisp loads third and already names
;;;; most of these packages, and every package must exist before
;;;; src/package.lisp installs the bl.* nicknames. Add an export here when a
;;;; definition in src/validation/ becomes API; keep %-prefixed names internal.

(defpackage #:bitcoin-lisp.validation
  (:use #:cl)
  (:export
   ;; Transaction validation
   #:validate-transaction-structure
   #:validate-transaction-contextual
   #:validate-transaction-scripts
   #:validate-transaction-for-mempool
   ;; Core's reject-reason vocabulary (keyword -> state.GetRejectReason())
   #:tx-reject-reason-string
   #:*tx-reject-reasons*
   ;; Package relay (submitpackage + opportunistic 1p1c)
   #:validate-package-for-mempool
   #:package-hash
   #:package-truc-checks
   #:package-well-formed
   #:package-child-with-parents-tree-p
   #:+max-package-count+
   #:+max-package-weight+
   #:package-tx-result
   #:package-tx-result-txid
   #:package-tx-result-wtxid
   #:package-tx-result-status
   #:package-tx-result-vsize
   #:package-tx-result-fee
   #:package-tx-result-effective-feerate
   #:package-tx-result-effective-includes
   #:package-tx-result-other-wtxid
   #:package-tx-result-error
   ;; Script execution and input validation
   #:execute-script
   #:script-is-witness-program-p
   #:get-input-witness
   #:validate-input-script
   ;; Script disassembly and classification
   #:disassemble-script
   #:classify-script
   #:script-type-to-string
   ;; Block validation
   #:validate-block-header
   #:validate-block
   #:test-block-validity
   #:stop-script-check-pool
   #:validate-block-scripts
   #:find-witness-commitment
   #:validate-witness-commitment
   #:update-uncommitted-block-structures
   #:witness-reserved-value
   #:block-witness-stripped-p
   #:compute-witness-merkle-root
   #:check-proof-of-work
   #:compute-merkle-root
   ;; BIP325 signet block-solution validation
   #:check-signet-block-solution
   #:make-signet-txs
   #:signet-challenge-for-network
   #:*signet-challenge*
   #:*default-signet-challenge*
   #:connect-block
   #:activate-block
   #:find-fork-point
   ;; Tx-relay tip structures (Core recent-confirmed filter +
   ;; most-recent-block tx map)
   #:recently-confirmed-p
   #:most-recent-block-tx
   #:most-recent-cmpctblock
   #:note-block-connected
   #:reset-recent-confirmed
   ;; The reconsiderable rejects filter (Core's second rejects filter)
   #:*recent-rejects-reconsiderable*
   #:reconsiderable-reject-p
   #:add-reconsiderable-reject
   #:clear-reconsiderable-rejects
   #:perform-reorg
   #:activate-best-chain
   #:best-valid-tip
   #:get-undo-data
   #:invalidate-block
   #:reconsider-block
   #:precious-block
   #:decode-coinbase-height
   #:get-bip34-activation-height
   #:apply-test-activation-heights
   #:parse-test-activation-height
   #:*test-activation-heights*
   #:get-bip66-activation-height
   #:get-bip65-activation-height
   #:get-csv-activation-height
   #:+max-future-block-time+
   #:+max-timewarp+
   #:get-taproot-activation-height
   #:initialize-undo-storage
   #:migrate-undo-to-flat
   #:delete-undo-file
   #:prune-stale-undo-files
   ;; Locktime validation
   #:check-transaction-final
   #:compute-median-time-past
   #:compute-median-time-past-from-entry
   #:header-time-too-old-p
   #:check-sequence-locks
   #:compute-script-flags-for-height
   ;; BIP9 / versionbits (reporting only; activation stays height-based)
   #:versionbits-deployments
   #:versionbits-state
   #:with-versionbits-cache
   #:versionbits-state-name
   #:versionbits-since-height
   #:versionbits-statistics
   #:vb-deployment-name
   #:vb-deployment-bit
   #:vb-deployment-start-time
   #:vb-deployment-timeout
   #:vb-deployment-min-activation-height
   #:vb-deployment-threshold
   #:vb-deployment-period
   #:+vb-always-active+
   #:+vb-never-active+
   #:+vb-no-timeout+
   #:block-script-flags-list
   #:block-script-flags
   #:script-flag-exception
   #:+always-on-block-script-flags+
   #:+standard-script-verify-flags+
   #:get-segwit-activation-height
   ;; Difficulty validation
   #:validate-difficulty
   #:bip94-timewarp-violation-p
   #:get-expected-bits
   #:testnet-min-difficulty-allowed-p
   #:testnet-walk-back-bits
   ;; Block weight
   #:script-checks-skippable-p
   #:calculate-block-weight
   #:+max-block-weight+
   ;; Sigops validation
   #:count-script-sigops
   #:count-transaction-sigops-cost
   #:+max-block-sigops-cost+
   #:+witness-scale-factor+
   ;; Dust / standardness (wallet spend path)
   #:dust-threshold
   #:+dust-relay-fee-rate+
   #:+max-standard-tx-weight+
   ;; Constants
   #:+coinbase-maturity+
   #:+max-money+
   ;; Coinbase / subsidy (for the block assembler)
   #:calculate-block-subsidy
   #:encode-bip34-height))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (bitcoin-lisp.nicknames:install-package-nicknames))
