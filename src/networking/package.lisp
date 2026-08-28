;;;; Package bitcoin-lisp.networking -- the public API of src/networking/.
;;;;
;;;; First component of the bitcoin-lisp/net sub-system (bitcoin-lisp.asd):
;;;; the package exists before any file in src/networking/ compiles, and the
;;;; INSTALL-PACKAGE-NICKNAMES call at the end of this file gives those files
;;;; their bl.* prefixes. The package spans two systems: the transport
;;;; (fd-wait ... torcontrol) is bitcoin-lisp/net and may name only the
;;;; layers below it; the protocol (txreconciliation-set, peer, protocol,
;;;; headers-sync, ibd) loads in the main system and may name validation and
;;;; the mempool. Add an export here when a definition in src/networking/
;;;; becomes API; keep %-prefixed names internal.

(defpackage #:bitcoin-lisp.networking
  (:use #:cl #:bitcoin-lisp.conditions)
  (:export
   ;; Connection
   #:connection
   #:connection-connected
   #:connection-host
   #:make-tcp-connection
   #:close-connection
   #:send-bytes
   #:receive-bytes
   ;; Non-blocking send buffer (Core vSendMsg / fPauseSend / SocketSendData)
   #:connection-send-paused-p
   #:connection-send-stalled-p
   #:flush-send-buffer
   #:flush-peer-send-buffers
   #:+max-send-buffer-bytes+
   ;; BIP324 v2 transport
   #:*v2-transport-enabled*
   #:v2-available-p
   ;; SOCKS5 outbound proxy (Core netbase.cpp Socks5)
   #:*proxy*
   #:*onion-proxy*
   #:proxy
   #:make-proxy
   #:proxy-host
   #:proxy-port
   #:proxy-randomize-credentials
   #:socks5-connect
   #:socks5-error
   #:socks5-error-phase
   #:next-proxy-credentials
   #:*onion-proxy-explicit*
   ;; Tor control client (Core torcontrol.cpp): inbound onion service
   #:tor-controller
   #:tor-controller-service-id
   #:tor-controller-running
   #:start-tor-control
   #:stop-tor-control
   #:parse-torcontrol-spec
   ;; Inbound listening
   #:open-listener
   #:close-listener
   #:accept-connection
   ;; Shutdown
   #:request-ibd-stop
   #:reset-ibd-stop
   #:ibd-stop-requested-p
   #:join-thread-or-destroy
   ;; Tx-request tracking
   #:retry-timed-out-tx-requests
   #:reset-tx-requests
   #:tx-request-wanted-p
   #:tx-request-received
   #:tx-request-notfound
   #:tx-request-disconnected-peer
   #:tx-request-count
   #:process-tx-requests
   ;; Steady-state message pump (post-IBD receive loop)
   #:pump-peer-messages
   #:ibd-context-headers-received
   #:*highest-header-seen*
   ;; Trickled tx announcement flushing
   #:flush-tx-announcements
   ;; Local-submission broadcast (unbroadcast set)
   #:announce-mempool-tx
   #:reattempt-initial-broadcast
   #:maybe-reattempt-initial-broadcast
   #:reset-initial-broadcast-schedule
   ;; Peer
   #:peer
   #:make-peer
   #:peer-state
   #:peer-version
   #:peer-services
   #:peer-start-height
   #:peer-user-agent
   #:peer-ping-latency
   #:peer-inbound
   #:peer-live-p
   #:release-outbound-protection
   #:maybe-protect-outbound-peer
   #:credit-block-announcement
   #:peer-last-block-announcement
   #:consider-chain-sync-eviction
   #:evict-extra-outbound-peers
   #:any-blocks-in-flight-p
   #:socket-input-ready-p
   #:capture-recv-backtrace
   #:*recv-backtrace-budget*
   #:select-extra-block-relay-eviction
   #:select-extra-full-relay-eviction
   #:maybe-set-peer-announcing-hb
   #:maybe-send-feefilter
   #:maybe-start-reconciliation
   #:fee-filter-round
   #:peer-manual
   #:peer-outbound-or-block-relay-p
   #:loopback-address-p
   #:peer-conn-type
   #:peer-relays-txs-p
   #:peer-tx-relay-p
   #:peer-last-inv-sequence
   #:peer-getaddr-sent
   #:connect-peer
   #:disconnect-peer
   #:make-inbound-peer
   #:send-message
   #:receive-message
   #:perform-handshake
   #:perform-inbound-handshake
   #:send-post-handshake-messages
   #:send-ping
   ;; Compact block peer state (BIP 152)
   #:peer-compact-block-version
   #:peer-compact-block-high-bandwidth
   #:peer-pending-compact-block
   #:pending-compact-block
   #:make-pending-compact-block
   #:pending-compact-block-block-hash
   #:pending-compact-block-header
   #:pending-compact-block-transactions
   #:pending-compact-block-missing-indexes
   #:pending-compact-block-request-time
   #:pending-compact-block-use-wtxid
   ;; Peer manager
   #:peer-manager
   #:make-peer-manager
   #:discover-peers
   #:diversify-by-netgroup
   #:ip-netgroup
   ;; Protocol
   #:handle-message
   #:ingest-headers-from-peer
   #:request-headers
   #:relay-transaction
   #:peer-announced-txs
   #:peer-known-addrs
   #:initial-block-download-p
   #:near-tip-p
   ;; Compact block relay (BIP 152)
   #:send-compact-block-negotiation
   #:check-compact-block-timeout
   #:clear-pending-compact-block
   #:compact-block-stats
   ;; Peer health
   #:check-peer-health
   #:record-block-timeout
   #:record-block-received-from-peer
   #:consider-peer-eviction
   #:peer-block-timeout-count
   #:peer-last-block-received-time
   #:peer-address
   #:+max-block-timeouts+
   ;; Peer database (peer-address struct shares symbol with peer accessor above)
   #:make-peer-address
   #:peer-address-net
   #:peer-address-network
   #:peer-address-string
   #:peer-address-ip
   #:peer-address-port
   #:peer-address-services
   #:peer-address-last-seen
   #:peer-address-last-attempt
   #:peer-address-last-success
   #:peer-address-n-attempts
   #:peer-address-ref-count
   #:peer-address-in-tried
   #:address-book
   #:make-address-book
   #:address-book-add
   #:address-book-lookup
   #:address-book-count
   #:address-book-good
   #:address-book-attempt
   #:address-book-connected
   #:address-book-select
   #:select-dialable-address
   #:address-book-get-addr
   #:resolve-tried-collisions
   #:select-tried-collision
   #:addr-info-terrible-p
   #:net-group-key
   #:make-address-key
   #:address-routable-p
   #:network-key-id
   #:key-id-network
   #:save-address-book
   #:load-address-book
   #:peers-dat-path
   #:ipv4-to-mapped-ipv6
   #:ip-bytes-to-string
   #:string-to-ip-bytes
   ;; Network-typed addresses (BIP155): codecs + reachability (netaddress.lisp)
   #:+bip155-networks+
   #:network-address-length
   #:*reachable-networks*
   #:*cjdns-reachable*
   #:*onlynet-networks*
   #:reachable-network-p
   #:dialable-network-p
   ;; Local addresses (Core mapLocalHost) + self-advertisement
   #:+local-manual+
   #:local-address
   #:make-local-address
   #:local-address-network
   #:local-address-bytes
   #:local-address-port
   #:local-address-score
   #:add-local
   #:remove-local
   #:clear-local-addresses
   #:local-addresses
   #:best-local-address
   #:privacy-network-p
   #:peer-inbound-onion
   ;; Read by the inbound evictor (GA9 S2-6): Core protects by MINIMUM ping
   ;; and by most-recent novel tx/block, all of which we already tracked.
   #:peer-min-ping-latency
   #:peer-last-tx-time
   #:peer-last-block-time
   #:peer-connected-through-network
   #:peer-next-local-addr-send
   #:get-local-addr-for-peer
   #:maybe-advertise-local-address
   #:local-services
   #:maybe-flip-ipv6-to-cjdns
   #:proxy-for-target
   #:base32-encode
   #:base32-decode
   #:onion-address-string
   #:parse-onion-address
   #:i2p-address-string
   #:parse-i2p-address
   #:network-address-to-string
   #:parse-network-address
   #:parse-subnet
   ;; -asmap
   #:load-asmap-file
   #:asmap-version
   #:asmap-interpret
   #:asmap-asn
   ;; Net permissions (-whitelist / -whitebind)
   #:parse-permission-flags
   #:parse-whitelist-entry
   #:permission-flag-names
   #:peer-permission-flags
   #:peer-has-permission-p
   #:+perm-bloom-filter+
   #:+perm-relay+
   #:+perm-force-relay+
   #:+perm-noban+
   #:+perm-mempool+
   #:+perm-download+
   #:+perm-addr+
   #:+perm-all+
   #:subnet-match-p
   #:address-in-subnets-p
   ;; ADDRv2 support (BIP 155)
   #:peer-wants-addrv2
   #:peer-prefers-headers
   #:peer-feefilter-rate
   #:peer-wtxid-relay
   #:handle-addr
   #:handle-addrv2
   ;; Misbehavior and banning
   #:record-misbehavior
   #:ban-peer
   #:peer-banned-p
   #:clear-ban-list
   #:ban-address
   #:*default-ban-time-seconds*
   #:*banlist-path*
   #:save-banlist
   #:load-banlist
   #:*external-ips*
   #:unban-address
   #:list-bans
   #:*total-bytes-sent*
   #:*total-bytes-received*
   #:discourage-peer
   #:peer-discouraged-p
   #:clear-discouraged
   #:*banned-peers*
   ;; DoS protection
   #:check-peer-rate-limit
   #:check-handshake-timeout
   #:init-peer-rate-limiters
   #:peer-connect-time
   ;; Network params
   #:*current-port*
   #:*dns-seeds*
   ;; Checkpoints
   #:network-checkpoints
   #:get-checkpoint-hash
   #:last-checkpoint-height
   #:relay-enabled-p
   #:ignore-incoming-txs-p))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (bitcoin-lisp.nicknames:install-package-nicknames))
