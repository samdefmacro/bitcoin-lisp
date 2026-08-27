(in-package #:bitcoin-lisp)

(defun broadcast-transaction-to-peers (node txid)
  "Queue announcements of the in-mempool TXID to every connected
relay-capable peer — the broadcast tail of Core's BroadcastTransaction
(node/transaction.cpp:131-135 -> PeerManager::InitiateTxBroadcastToAll).
Nothing is sent directly: the sync loop's Poisson flusher
(flush-tx-announcements) drains the queues, respecting each peer's
wtxid-relay preference, fRelay, and BIP133 feefilter. Under the node lock
because RPC handler threads call this while the sync thread owns the same
queues. Returns T when the tx was found in the mempool and queued."
  (bt:with-recursive-lock-held ((node-lock node))
    (bl.net:announce-mempool-tx
     (node-peers node) (node-mempool node) txid)))

(defun load-mempool-from-disk
    (node &optional (path (bl.mp:mempool-dat-path (node-data-directory node)))
     &key (apply-unbroadcast t) (apply-fee-delta-priority t) (use-current-time nil))
  "Load a mempool.dat-format file through the normal acceptance path (Core
LoadMempool): prioritisation deltas first (so fee policy sees them), then per-tx
validation against the current UTXO set — stale entries (spent inputs, reorged
context) simply fail and are dropped. Entries are loaded regardless of age (no
expiry filter, unlike Core): mempool-expire prunes old entries on the next block
connection anyway. Residual deltas (txs not in the saved pool) are re-applied
last, then the saved unbroadcast set for txs that made it back into the pool
(Core node/mempool_persist.cpp:134-141) — unless APPLY-UNBROADCAST is NIL,
which is the importmempool RPC's default (Core apply_unbroadcast_set,
rpc/mempool.cpp:1115).

⚠️ The defaults here are the STARTUP ones, and all three are the OPPOSITE of
importmempool's. Core keeps two sets (node/mempool_persist.h:20-25 for the boot
load, rpc/mempool.cpp:1138-1141 for the RPC):

              startup   importmempool
  use_current_time          NIL         T
  apply_fee_delta_priority   T          NIL
  apply_unbroadcast_set      T          NIL

The reasoning is that a boot load is restoring THIS node's own mempool — it
wants the original entry times so expiry still means something, and it wants
its own prioritisation back — while importmempool is ingesting someone else's
file, where a foreign fee delta is not this operator's policy and a foreign
timestamp would misdate the entry. PATH defaults to the node's mempool.dat.
Returns
(values accepted failed residual-count) on success, or NIL if the file is
missing or corrupt."
  (when (and path (probe-file path))
      (multiple-value-bind (entries residual ok unbroadcast)
          (bl.mp:read-mempool-file path)
        (unless ok
          (log-warn "mempool file ~A unreadable or corrupt" path)
          (return-from load-mempool-from-disk nil))
        (let ((mempool (node-mempool node))
              (utxo-set (node-utxo-set node))
              (chain-state (node-chain-state node))
              (accepted 0) (failed 0) (unbroadcast-count 0)
              (total (length entries))
              (tried 0)
              (next-tenth 0))
          ;; Announce the size and report every 10% (Core mempool_persist.cpp:77-86).
          ;; Every entry is re-validated in full, so a large dump is minutes of
          ;; CPU — and this used to log nothing at all until it finished: an
          ;; 83 MB testnet4 mempool.dat took ~45 minutes of silence on the
          ;; 2026-08-16 deploy, indistinguishable from a wedge.
          (when (plusp total)
            (log-info "Loading ~D mempool transaction~:P from ~A..." total path))
          (dolist (rec entries)
            ;; Cooperative stop between transactions (Core checks m_interrupt per
            ;; tx, mempool_persist.cpp:122). Abandoning applies NEITHER the
            ;; residual deltas NOR the unbroadcast set — Core returns before
            ;; both, and half-restoring would leave prioritisation for
            ;; transactions that never came back. What was already accepted stays
            ;; in the pool and is dumped at shutdown, so the next start resumes
            ;; from a smaller file.
            (when (bl:interrupt-requested-p)
              (log-warn "Mempool import abandoned on a stop request after ~D of ~D transaction~:P (~D accepted, ~D failed); the remainder stays in ~A"
                        tried total accepted failed path)
              (return-from load-mempool-from-disk (values accepted failed 0)))
            (let* ((pct (floor (* 100 tried) total))
                   (tenth (floor pct 10)))
              (when (> tenth next-tenth)
                (setf next-tenth tenth)
                (log-info "Progress loading mempool transactions: ~D% (tried ~D, ~D remaining)"
                          pct tried (- total tried))))
            (incf tried)
            (destructuring-bind (tx entry-time delta) rec
              ;; Core overwrites the saved time with now BEFORE the fee delta
              ;; and the acceptance (mempool_persist.cpp:95-97).
              (when use-current-time
                (setf entry-time (bl.ser:get-unix-time)))
              (let ((txid (bl.ser:transaction-hash tx))
                    (height (bl.store:current-height chain-state)))
                (when (and apply-fee-delta-priority (not (zerop delta)))
                  (bl.mp:mempool-prioritise mempool txid delta))
                ;; CHAIN-STATE gates the finality/BIP68 checks — a saved tx
                ;; that is no longer minable in the next block must not
                ;; reload (Core LoadMempool goes through the full
                ;; AcceptToMemoryPool, node/mempool_persist.cpp:105).
                (multiple-value-bind (valid error fee replaced sigops)
                    ;; Core uncaches every prevout this pulled in when the
                    ;; result is not VALID (validation.cpp:851, 1787-1790):
                    ;; otherwise a stream of transactions that fail AFTER input
                    ;; fetch leaves one cache entry per distinct outpoint, with
                    ;; nothing evicting them until the next block connects.
                    (bl.store:with-coins-to-uncache (utxo-set)
                      (bl.val:validate-transaction-for-mempool
                       tx utxo-set mempool height :chain-state chain-state))
                  (declare (ignore error))
                  (cond
                    (valid
                     (if (eq :ok (bl.mp:accept-validated-tx
                                  mempool txid tx fee height
                                  :entry-time entry-time :sigops sigops
                                  :replaced replaced))
                         (incf accepted)
                         (incf failed)))
                    (t (incf failed)))))))
          ;; The residual map is gated on the same option as the per-entry
          ;; deltas (mempool_persist.cpp:128-132) — importmempool must not
          ;; import a foreign node's prioritisation by either route.
          (when apply-fee-delta-priority
            (dolist (pair residual)
              (bl.mp:mempool-prioritise mempool (car pair) (cdr pair))))
          ;; Restore the unbroadcast set for txs that were re-accepted; ids
          ;; whose tx failed to reload are dropped (mempool-add-unbroadcast's
          ;; membership gate) — Core node/mempool_persist.cpp:136-142.
          (when apply-unbroadcast
            (dolist (txid unbroadcast)
              (when (bl.mp:mempool-add-unbroadcast mempool txid)
                (incf unbroadcast-count))))
          (log-info "Imported mempool: ~D accepted, ~D failed, ~D residual deltas, ~D waiting for initial broadcast"
                    accepted failed (length residual) unbroadcast-count)
          (values accepted failed (length residual))))))
