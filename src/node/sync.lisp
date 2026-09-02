(in-package #:bitcoin-lisp)

;;;; Blockchain Synchronization

(defun node->context (node chainstate)
  "The node-context (bl.ctx) a sync pass or receive pump acts on: CHAINSTATE
(the current one) with its coins view, and the node's shared pieces. One
builder for the sync pass and the between-cycles tick, so the two cannot
drift -- the first review of the node-context change found the tick still
calling the old signature and no production path filling PEERS."
  (bl.ctx:make-node-context
   :chain-state chainstate
   :utxo-set (bl.store:chain-state-coins-view chainstate)
   :block-store (node-block-store node)
   :mempool (node-mempool node)
   :peers (node-peers node)
   :fee-estimator (node-fee-estimator node)
   :address-book (node-address-book node)
   :recent-rejects (node-recent-rejects node)
   :historical-chainstate (node-historical-chainstate node)))

(defun sync-blockchain (node)
  "Run one IBD/follow-tip cycle against connected peers.

Doesn't short-circuit on `peer-start-height` since that value is frozen
at handshake and goes stale once the chain advances — start-ibd's
header-sync phase is what discovers new tips, and its block-download
phase exits quickly when there's nothing new to fetch."
  (unless (node-peers node)
    (log-warn "No peers connected, cannot sync")
    (return-from sync-blockchain 0))

  ;; A non-empty peer list is NOT enough. Peers enter NODE-PEERS only after a
  ;; successful handshake, but they stay in the list once they go
  ;; :DISCONNECTED — reaping is REPLACE-DISCONNECTED-PEERS' job, reached via
  ;; MAINTAIN-PEERS, which the sync loop runs AFTER this function. So a list of
  ;; nothing but dead peers is reachable, and FIND-BEST-PEER (which only counts
  ;; :READY) returns NIL for it. Handing that NIL to the PEER-START-HEIGHT
  ;; accessor is a type error that unwinds the whole sync iteration, so
  ;; maintain-peers never runs, so the dead peers are never reaped or redialed,
  ;; so the next iteration fails identically: the failure feeds itself. Proven
  ;; live — a node logged this type error every 5 seconds for 19 days, 333k
  ;; times, holding 8 peers it would never replace.
  (let ((best-peer (find-best-peer node)))
    (unless best-peer
      (log-warn "No peer has completed its handshake yet; skipping this sync cycle")
      (return-from sync-blockchain 0))

    ;; IBD drives the current chainstate (its tip and coins view). When an
    ;; assumeutxo background sync is active, the historical chainstate rides
    ;; along as a second download cursor inside the same IBD pass: run-ibd
    ;; queues its [historical-tip .. snapshot-base] range and routes received
    ;; blocks to whichever chainstate owns their height.
    (let ((chainstate (node-current-chainstate node))
          (peer-height (bl.net:peer-start-height best-peer)))
      (log-debug "Sync cycle: local height ~D, peer-start height ~D"
                 (bl.store:current-height chainstate)
                 peer-height)
      (bl.net:start-ibd
       (node-peers node)
       (node->context node chainstate)
       peer-height))))


(defun find-best-peer (node)
  "Find the best peer for syncing (highest block height)."
  (let ((ready-peers (remove-if-not
                      (lambda (p)
                        (eq (bl.net:peer-state p) :ready))
                      (node-peers node))))
    (when ready-peers
      (first (sort (copy-list ready-peers) #'>
                   :key #'bl.net:peer-start-height)))))

;;;; Status and Info

(defun node-status ()
  "Print the current node status."
  (unless *node*
    (format t "Node is not running.~%")
    (return-from node-status nil))

  (format t "~%=== Bitcoin-Lisp Node Status ===~%")
  (format t "Network: ~A~%" (node-network *node*))
  (format t "Running: ~A~%" (if (node-running *node*) "Yes" "No"))
  (format t "Syncing: ~A~%" (if (node-syncing *node*) "Yes" "No"))
  (when (node-sync-thread *node*)
    (format t "Sync thread: ~A~%"
            (if (bt:thread-alive-p (node-sync-thread *node*)) "Active" "Stopped")))
  (format t "Data directory: ~A~%" (node-data-directory *node*))
  (format t "~%Chain State:~%")
  (when (node-chain-state *node*)
    (format t "  Height: ~D~%"
            (bl.store:current-height (node-chain-state *node*)))
    (format t "  Best block: ~A~%"
            (bl.crypto:bytes-to-hex
             (bl.store:best-block-hash (node-chain-state *node*)))))
  (format t "~%UTXO Set:~%")
  (when (node-utxo-set *node*)
    (format t "  UTXOs: ~D~%"
            (bl.store:utxo-count (node-utxo-set *node*))))
  (format t "~%Mempool:~%")
  (when (node-mempool *node*)
    (format t "  Transactions: ~D~%"
            (bl.mp:mempool-count (node-mempool *node*)))
    (format t "  Size: ~:D vbytes (~:D bytes memory)~%"
            (bl.mp:mempool-total-size (node-mempool *node*))
            (bl.mp:mempool-dynamic-usage (node-mempool *node*))))
  (format t "~%Peers:~%")
  (if (node-peers *node*)
      (dolist (peer (node-peers *node*))
        (format t "  - ~A (height ~D, latency ~Dms)~%"
                (bl.net:peer-user-agent peer)
                (bl.net:peer-start-height peer)
                (bl.net:peer-ping-latency peer)))
      (format t "  (no peers connected)~%"))
  (format t "~%")
  t)
