

(defpackage #:bitcoin-lisp
  (:use #:cl #:bitcoin-lisp.conditions)
  (:use #:bitcoin-lisp.crypto)
  (:use #:bitcoin-lisp.serialization)
  (:use #:bitcoin-lisp.storage)
  (:use #:bitcoin-lisp.validation)
  (:use #:bitcoin-lisp.networking)
  (:local-nicknames (#:bt #:bordeaux-threads))
  (:export
   ;; Network parameters
   #:*network*
   #:+testnet3+
   #:+testnet4+
   #:+signet+
   #:+mainnet+
   #:network-magic
   #:network-port
   #:network-dns-seeds
   #:network-rpc-port
   #:*mainnet-relay-enabled*
   #:*blocksonly*
   ;; Wallet fee rails (config.lisp; consumed by the wallet spend path)
   #:*wallet-max-tx-fee*
   #:*wallet-fallback-fee*
   ;; Pruning
   #:*prune-target-mib*
   #:*prune-after-height*
   #:+min-blocks-to-keep+
   #:+min-disk-space-for-block-files+
   #:effective-prune-target-bytes
   #:*accept-datacarrier*
   #:*max-datacarrier-bytes*
   #:*permit-bare-multisig*
   #:*peer-block-filters*
   #:*tx-reconciliation*
   #:pruning-enabled-p
   #:automatic-pruning-p
   #:minimum-chain-work
   #:*minimum-chain-work-override*
   #:*assumevalid-override*
   #:network-assumevalid
   #:*p2p-port-override*
   #:*stop-at-height*
   #:*dns-seed-enabled*
   #:*fixed-seeds-enabled*
   #:check-cli-args
   #:cli-parse-error
   #:unknown-config-file-keys
   #:known-config-option-p
   #:defer-log
   #:*category-log-levels*
   #:category-log-level
   #:set-category-log-level
   #:clear-category-log-levels
   #:log-categories-string
   #:parse-loglevel-spec
   #:flush-deferred-log-lines
   #:*deferred-log-lines*
   #:parse-settings-json
   #:render-settings-json
   #:render-json-value
   #:settings-file-warning
   #:settings-alist->config-alist
   #:unknown-settings-keys
   #:validate-settings-values
   #:+settings-warning-key+
   #:+client-name+
   #:conf-parse-money
   #:conf-parse-user-hex
   #:ua-comment-safe-p
   #:+max-subversion-length+
   ;; Assumeutxo snapshot commitments (Core m_assumeutxo_data)
   #:assumeutxo-data
   #:make-assumeutxo-data
   #:assumeutxo-data-height
   #:assumeutxo-data-blockhash
   #:assumeutxo-data-hash-serialized
   #:assumeutxo-data-chain-tx-count
   #:*assumeutxo-data-override*
   #:network-assumeutxo-data
   #:assumeutxo-data-for-blockhash
   #:*parallel-block-validation*
   ;; Token bucket rate limiter
   #:token-bucket
   #:make-token-bucket
   #:make-rate-limiter
   #:token-bucket-allow-p
   #:token-bucket-rate
   #:token-bucket-burst
   #:token-bucket-tokens
   ;; Recent rejects filter
   #:recent-rejects
   #:make-rejects-filter
   #:recent-reject-p
   #:add-recent-reject
   #:clear-recent-rejects
   ;; DoS protection configuration
   #:*rate-limit-inv*
   #:*rate-limit-tx*
   #:*rate-limit-addr*
   #:*rate-limit-getdata*
   #:*rate-limit-headers*
   #:*rate-limit-serve*
   #:*rpc-rate-limit*
   #:+max-message-payload+
   #:+max-rpc-body-size+
   #:+handshake-timeout-seconds+
   #:*recent-rejects-max-size*
   ;; Node
   #:node
   #:*node*
   #:start-node
   #:start-node-from-args
   #:stop-node
   ;; Shutdown coordination (internal paths request; the main thread performs)
   #:request-node-shutdown
   #:node-shutdown-requested-p
   #:run-node-watchdog
   #:node-main
   #:notify-block-tip
   #:run-notify-command
   #:+node-exit-clean+
   #:+node-exit-error+
   #:+node-exit-watchdog+
   #:node-status
   #:node-fee-estimator
   #:node-recent-rejects
   #:sync-blockchain
   ;; Logging
   #:*log-stream*
   #:*current-log-level*
   #:node-log
   #:log-debug
   #:log-cat
   #:log-category-enabled-p
   #:apply-log-categories
   #:*log-time-micros*
   #:*log-thread-names*
   #:log-info
   #:log-warn
   #:log-error
   #:show-logs
   #:clear-logs
   #:enable-console-logging
   #:disable-console-logging
   #:start-file-logging
   #:stop-file-logging
   #:maybe-periodic-flush
   #:maybe-critical-flush
   #:maybe-stop-at-height
   ;; ZMQ notifications (G7-23)
   #:zmq-notify-block-connected
   #:zmq-notify-block-disconnected
   #:zmq-notify-tx-accepted
   #:zmq-notify-tx-removed
   #:zmq-start-publishers
   #:zmq-stop-publishers
   #:zmq-specs-from-config
   #:zmq-notifications-info
   #:zmq-topic-active-p
   ;; Cooperative-stop seam (config.lisp): the networking layer installs the
   ;; predicate, lower layers poll it — never the other way round.
   #:*interrupt-check*
   #:interrupt-requested-p
   #:listen-port
   #:index-block-connected
   #:index-block-disconnected
   #:node-indexes
   #:catch-up-index
   ;; Wallet chain-tracking hooks (wallet P2; defined in node/wallet-hooks.lisp, called
   ;; from connect-block / perform-reorg / the mempool like the index hooks)
   #:wallet-notify-block-connected
   #:wallet-notify-block-disconnected
   #:wallet-notify-mempool-tx-added
   #:wallet-notify-mempool-tx-removed
   #:maybe-validate-snapshot
   #:rebalance-caches-on-ibd-exit))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (bitcoin-lisp.nicknames:install-package-nicknames))
