(in-package #:bitcoin-lisp.rpc)

;;;; Mempool RPCs (Core rpc/mempool.cpp): queries, the raw-transaction submission
;;;; rails (sendrawtransaction / testmempoolaccept / submitpackage) and
;;;; mempool.dat persistence.

;;; --- Mempool Methods ---

(defun %orphan-tx-json (tx announcers verbose2)
  "OrphanDescription (Core getorphantxs verbosity 1/2) for orphan TX announced
by ANNOUNCERS (a list of peer objects, possibly containing nil for local
submissions). VERBOSE2 appends the raw hex. \"bytes\" and \"hex\" use the wire
(witness-complete) encoding — Core ComputeTotalSize / EncodeHexTx. \"from\"
lists every announcer's peer id (Core OrphanInfo::announcers)."
  (let* ((ser (bl.ser:transaction-wire-bytes tx))
         (base `(("txid" . ,(hash-to-hex (bl.ser:transaction-hash tx)))
                 ("wtxid" . ,(hash-to-hex (bl.ser:transaction-wtxid tx)))
                 ("bytes" . ,(length ser))
                 ("vsize" . ,(bl.ser:transaction-vsize tx))
                 ("weight" . ,(bl.ser:transaction-weight tx))
                 ("from" . ,(loop for peer in announcers
                                  when peer
                                    collect (bl.net:peer-id peer))))))
    (if verbose2
        (append base `(("hex" . ,(bl.crypto:bytes-to-hex ser))))
        base)))

(define-rpc "getorphantxs" (node params)
  "List the transactions in the orphan pool (Bitcoin Core getorphantxs, hidden).
PARAMS: ([verbosity]) -- 0 (default) an array of txids, 1 an array of orphan
detail objects, 2 the detail objects plus each transaction's raw hex."
  (let* ((verbosity (%parse-verbosity params 0 0))
         (mempool (rpc-get-mempool node))
         (pool (and mempool (bl.mp:mempool-orphan-pool mempool)))
         (result '()))
    (unless (member verbosity '(0 1 2))
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message (format nil "Invalid verbosity value ~A" verbosity)))
    ;; Node lock: the sync thread adds/erases orphans while handling txs;
    ;; iterating the pool's hash table concurrently is undefined.
    (when pool
      (with-node-lock (node)
        (maphash
         (lambda (wtxid entry)
           (declare (ignore wtxid))
           (let ((tx (bl.mp:orphan-entry-transaction entry))
                 (from (mapcar #'bl.mp:orphan-announcement-peer
                               (bl.mp:orphan-entry-announcements entry))))
             (push (case verbosity
                     (0 (hash-to-hex (bl.ser:transaction-hash tx)))
                     (1 (%orphan-tx-json tx from nil))
                     (t (%orphan-tx-json tx from t)))
                   result)))
         (bl.mp:orphan-pool-by-wtxid pool))))
    ;; Core returns a UniValue VARR: an empty orphanage is [], not null.
    (json-array (nreverse result))))

(define-rpc "getmempoolinfo" (node params)
  "Return mempool statistics."
  (declare (ignore params))
  (let ((mempool (rpc-get-mempool node))
        (incfee (satoshi->btc bl.mp:*incremental-relay-fee-rate*)))
    (if mempool
        ;; Rates are sat/kvB (Core CFeeRate); SATOSHI->BTC spells them
        ;; BTC/kvB the way ValueFromAmount does.
        ;; Node lock: count/bytes/total-fee must be one consistent snapshot
        ;; while the sync thread adds/evicts entries (Core getmempoolinfo
        ;; takes pool.cs via the stats getters).
        (with-node-lock (node)
         (let* ((min-fee-sat-kvb (bl.mp:mempool-effective-min-fee-rate mempool))
               (min-fee-btc-kvb (satoshi->btc min-fee-sat-kvb))
               ;; The pool's configured floor (Core m_min_relay_feerate).
               (relay-fee-btc-kvb (satoshi->btc (bl.mp:mempool-min-fee-rate mempool)))
               (count (bl.mp:mempool-count mempool))
               ;; Core "bytes" = GetTotalTxSize(), the sum of the entries'
               ;; sigop-adjusted VIRTUAL sizes (rpc/mempool.cpp:1040,
               ;; txmempool.h:191), not serialized bytes.
               (bytes (bl.mp:mempool-total-size mempool))
               (total-fee-sat 0))
          (bl.mp:mempool-for-each
           mempool (lambda (txid e) (declare (ignore txid))
                     (incf total-fee-sat (bl.mp:mempool-entry-fee e))))
          ;; Core pool.GetLoadTried() (rpc/mempool.cpp:1038): whether the
          ;; start-up replay of mempool.dat has been attempted, not whether a
          ;; mempool exists. The functional framework waits for it to turn
          ;; true before it calls a node started (test_node.py:292-310), and
          ;; that wait is what covers the -loadblock import (bl::%INITLOAD).
          `(("loaded" . ,(json-bool bl.mp:*mempool-load-tried*))
            ("size" . ,count)
            ("bytes" . ,bytes)
            ;; Core DynamicMemoryUsage(): the malloc-modeled memory usage the
            ;; -maxmempool cap is keyed on (rpc/mempool.cpp:1041).
            ("usage" . ,(bl.mp:mempool-dynamic-usage mempool))
            ("total_fee" . ,(satoshi->btc total-fee-sat))
            ("maxmempool" . ,(bl.mp:mempool-max-size mempool))
            ("mempoolminfee" . ,min-fee-btc-kvb)
            ("minrelaytxfee" . ,relay-fee-btc-kvb)
            ("incrementalrelayfee" . ,incfee)
            ;; Core rpc/mempool.cpp:1047: GetUnbroadcastTxs().size().
            ("unbroadcastcount" . ,(bl.mp:mempool-unbroadcast-count mempool))
            ;; Acceptance is unconditionally full-RBF since cluster mempool;
            ;; Core hardcodes true (rpc/mempool.cpp:1048, field DEPRECATED).
            ("fullrbf" . t)
            ("permitbaremultisig" . ,(json-bool bl:*permit-bare-multisig*))
            ;; The remaining four policy fields Core reports
            ;; (rpc/mempool.cpp:1050-1053). -datacarrier=0 is nullopt there
            ;; and value_or(0) here, so a node that relays no OP_RETURN says
            ;; 0 rather than its unused byte budget (mempool_args.cpp:94-98).
            ("maxdatacarriersize" . ,(if bl:*accept-datacarrier*
                                         bl:*max-datacarrier-bytes*
                                         0))
            ("limitclustercount" . ,(bl.mp:mempool-cluster-count-limit mempool))
            ("limitclustersize" . ,(bl.mp:mempool-cluster-size-limit mempool))
            ("optimal" . ,(json-bool (bl.mp:mempool-linearization-optimal-p mempool))))))
        `(("loaded" . ,+json-false+)
          ("size" . 0)
          ("bytes" . 0)
          ("usage" . 0)
          ("total_fee" . 0)
          ("maxmempool" . ,bl.mp:+default-max-mempool-bytes+)
          ("mempoolminfee" . 0.000001)
          ("minrelaytxfee" . 0.000001)
          ("incrementalrelayfee" . ,incfee)
          ("unbroadcastcount" . 0)
          ("fullrbf" . t)
          ("permitbaremultisig" . ,(json-bool bl:*permit-bare-multisig*))
          ("maxdatacarriersize" . ,(if bl:*accept-datacarrier*
                                       bl:*max-datacarrier-bytes*
                                       0))
          ("limitclustercount" . ,bl.mp:*cluster-count-limit*)
          ("limitclustersize" . ,bl.mp:*cluster-size-limit*)
          ("optimal" . t)))))

(define-rpc "getrawmempool" (node ((verbose :bool) (mempool-sequence :bool)))
  "Return mempool transaction IDs (verbose nil) or per-tx details (verbose t).

MEMPOOL_SEQUENCE (Core MempoolToJSON, rpc/mempool.cpp:571-605) wraps the
non-verbose id list in the snapshot object {\"txids\": [...],
\"mempool_sequence\": N}: it is what doc/zmq.md tells a mempool-mirroring
client to call so it can apply the ZMQ sequence stream from a known point,
with no gap and no duplicate. It is incompatible with VERBOSE, which Core
answers with -8 rather than a partial result."
  ;; Core raises this before it reads the pool at all (mempool.cpp:572-576).
  (when (and verbose mempool-sequence)
    (error 'rpc-error :code +rpc-invalid-parameter+
                      :message "Verbose results cannot contain mempool sequence values."))
  (let ((mempool (rpc-get-mempool node)))
    ;; Node lock: iterating entries (and, verbose, walking each entry's
    ;; ancestors/descendants/chunk) must not race the sync thread's
    ;; add/evict/reorg mutations (Core getrawmempool takes pool.cs). The
    ;; sequence counter is read under that same hold, as Core reads it inside
    ;; the pool.cs block that built the id list (:588-605) — a snapshot that
    ;; straddled an add or an eviction would defeat the argument's purpose.
    (with-node-lock (node)
      (let ((rows '()))
        (when mempool
          ;; In MINING order, as Core lists them: MempoolToJSON walks
          ;; entryAll(), which is GetSortedScoreWithTopology -- mapTx sorted
          ;; by the txgraph's CompareMainOrder (rpc/mempool.cpp:579/:593,
          ;; txmempool.cpp:572-598). Ours walked the entry table, i.e.
          ;; arrival order, so a reorg that re-adds the same transactions in
          ;; block order changed the answer; mempool_packages.py:244 asserts
          ;; it does not. Stable, and arrival order where there is no main
          ;; order to consult (an oversized graph).
          (let ((pairs '()))
            (bl.mp:mempool-for-each
             mempool (lambda (txid entry) (push (cons txid entry) pairs)))
            (setf pairs (nreverse pairs))
            (when (bl.mp:mempool-mining-order-available-p mempool)
              (setf pairs (stable-sort pairs
                                       (lambda (a b)
                                         (minusp (bl.mp:mempool-compare-mining-order
                                                  mempool a b)))
                                       :key #'car)))
            (dolist (pair pairs)
              (destructuring-bind (txid . entry) pair
                (push (if verbose
                          ;; (txid . field-alist); the RPC normalizer turns
                          ;; the whole thing into nested JSON objects.
                          (cons (hash-to-hex txid)
                                (%mempool-entry-fields mempool txid entry))
                          (hash-to-hex txid))
                      rows)))))
        (setf rows (nreverse rows))
        ;; An empty (or absent) mempool still answers with a collection of
        ;; the right shape — a VOBJ ({}) when verbose, a VARR ([]) otherwise.
        ;; A bare NIL would encode as null.
        (cond
          (verbose (json-object rows))
          (mempool-sequence
           ;; The id list is tagged as an array by BEING a vector: an alist
           ;; entry whose value is a list of strings is exactly the shape
           ;; RPC-OBJECT-ALIST-P cannot tell from a nested object, and a
           ;; vector settles it for yason either way.
           (json-object
            `(("txids" . ,(coerce rows 'vector))
              ("mempool_sequence" . ,(if mempool
                                         (bl.mp:mempool-sequence mempool)
                                         0)))))
          (t (json-array rows)))))))

(defun %mempool-entry-fields (mempool txid entry)
  "The verbose field alist for one mempool ENTRY (TXID) — vsize/weight/time/
height/fees{base,modified,ancestor,descendant,chunk}/ancestor+descendant
counts/chunkweight/wtxid/depends. Shared by getrawmempool (verbose),
getmempoolentry, getmempoolancestors, and getmempooldescendants.

The chunk fields (Core MempoolEntryDescription + entryToJSON,
rpc/mempool.cpp:433-465/508-541) report the txgraph chunk this entry mines
in: \"chunkweight\" is the chunk's total size and \"chunk\" its total
modified fees. Both are Core's units: the txgraph measures sigops-adjusted
WEIGHT on both sides, and Core reports feerate.size here without converting.
\"vsize\" and the ancestor/descendant sizes are the sigop-adjusted virtual
size, exactly Core's GetTxSize-based reporting."
  (multiple-value-bind (acount asize afees)
      (bl.mp:mempool-ancestor-stats mempool txid)
    (multiple-value-bind (dcount dsize dfees)
        (bl.mp:mempool-descendant-stats mempool txid)
      (let ((chunk (bl.mp:txgraph-get-main-chunk-feerate
                    (bl.mp:mempool-graph mempool)
                    (bl.mp:mempool-entry-graph-handle entry))))
        `(("vsize" . ,(bl.mp:mempool-entry-vsize entry))
          ("weight" . ,(bl.ser:transaction-weight
                        (bl.mp:mempool-entry-transaction entry)))
          ("time" . ,(bl.mp:mempool-entry-entry-time entry))
          ("height" . ,(bl.mp:mempool-entry-height entry))
          ("chunkweight" . ,(bl.mp:feefrac-size chunk))
          ("fees" . (("base" . ,(satoshi->btc (bl.mp:mempool-entry-fee entry)))
                     ("modified" . ,(satoshi->btc (bl.mp:mempool-entry-modified-fee entry)))
                     ("ancestor" . ,(satoshi->btc afees))
                     ("descendant" . ,(satoshi->btc dfees))
                     ("chunk" . ,(satoshi->btc (bl.mp:feefrac-fee chunk)))))
          ("ancestorcount" . ,acount)
          ("ancestorsize" . ,asize)
          ("descendantcount" . ,dcount)
          ("descendantsize" . ,dsize)
          ("wtxid" . ,(hash-to-hex (bl.mp:mempool-entry-wtxid entry)))
          ;; Both of these are UniValue VARRs in Core (entryToJSON,
          ;; rpc/mempool.cpp:494-506), so an entry with no unconfirmed parents
          ;; -- or, for the chain's last transaction, no unconfirmed children
          ;; -- answers [] and never null. JSON-ARRAY is what makes an empty
          ;; CL list encode as one: mempool_packages.py:108 compares
          ;; entry['spentby'] against the empty list.
          ("depends" . ,(json-array
                         (let ((deps '()))
                           (maphash (lambda (p v) (declare (ignore v))
                                      (push (hash-to-hex p) deps))
                                    (bl.mp:mempool-entry-parents entry))
                           deps)))
          ;; In-mempool txs that spend this tx's outputs (Core "spentby").
          ("spentby" . ,(json-array
                         (let ((sb '()))
                           (maphash (lambda (c v) (declare (ignore v))
                                      (push (hash-to-hex c) sb))
                                    (bl.mp:mempool-entry-children entry))
                           sb)))
          ;; BIP125: whether the tx or any unconfirmed ancestor SIGNALS
          ;; replaceability (Core IsRBFOptIn, reporting only — acceptance is
          ;; unconditionally full-RBF; rpc/mempool.cpp:456,567, DEPRECATED).
          ("bip125-replaceable"
           . ,(json-bool
               (bl.mp:mempool-tx-or-ancestor-signals-rbf-p mempool txid)))
          ;; Core IsUnbroadcastTx (rpc/mempool.cpp:568) — was hardcoded nil,
          ;; which both lied for locally-submitted txs and encoded as null.
          ("unbroadcast" . ,(json-bool
                             (bl.mp:mempool-unbroadcast-p mempool txid))))))))

(defun %mempool-txid-arg (params mempool)
  "Resolve the first param (a big-endian txid hex) to (values internal-txid
entry), erroring if malformed or not in the mempool."
  (let* ((txid (parse-hash-v (first params) "txid"))
         (entry (and mempool (bl.mp:mempool-get mempool txid))))
    (unless entry
      ;; Core: RPC_INVALID_ADDRESS_OR_KEY (-5), rpc/mempool.cpp:887.
      (error 'rpc-error :code +rpc-invalid-address-or-key+
                        :message "Transaction not in mempool"))
    (values txid entry)))

(define-rpc "getmempoolentry" (node params)
  "Return mempool details for transaction TXID (Bitcoin Core getmempoolentry)."
  (let ((mempool (rpc-get-mempool node)))
    (with-node-lock (node)
      (multiple-value-bind (txid entry) (%mempool-txid-arg params mempool)
        (%mempool-entry-fields mempool txid entry)))))

(defun %mempool-set->result (mempool txid-set verbose)
  "Format a hash-set of mempool txids as either an array of (big-endian) txid hex
strings or, when VERBOSE, an alist of txid-hex -> entry fields. An empty set is
Core's empty VARR/VOBJ ([] / {}), never null."
  (let ((result '()))
    (maphash (lambda (txid v) (declare (ignore v))
               (let ((entry (bl.mp:mempool-get mempool txid)))
                 (when entry
                   (push (if verbose
                             (cons (hash-to-hex txid) (%mempool-entry-fields mempool txid entry))
                             (hash-to-hex txid))
                         result))))
             txid-set)
    (if verbose (json-object result) (json-array result))))

(define-rpc "getmempoolancestors" (node params)
  "Return the in-mempool ancestors of TXID (Bitcoin Core getmempoolancestors).
PARAMS: (txid [verbose]). Array of txids, or txid->details when verbose."
  (let ((mempool (rpc-get-mempool node))
        (verbose (positional-bool (second params))))
    (with-node-lock (node)
      (multiple-value-bind (txid entry) (%mempool-txid-arg params mempool)
        (declare (ignore entry))
        (%mempool-set->result mempool (bl.mp:mempool-ancestors mempool txid) verbose)))))

(define-rpc "getmempooldescendants" (node params)
  "Return the in-mempool descendants of TXID (Bitcoin Core getmempooldescendants).
PARAMS: (txid [verbose]). Array of txids, or txid->details when verbose."
  (let ((mempool (rpc-get-mempool node))
        (verbose (positional-bool (second params))))
    (with-node-lock (node)
      (multiple-value-bind (txid entry) (%mempool-txid-arg params mempool)
        (declare (ignore entry))
        (%mempool-set->result mempool (bl.mp:mempool-descendants mempool txid) verbose)))))

(define-rpc "getmempoolcluster" (node params)
  "Return mempool data for the cluster containing TXID (Bitcoin Core
getmempoolcluster, rpc/mempool.cpp:829-862 + clusterToJSON :474-506):
clusterweight, txcount, and the cluster's chunks in mining order, each with
chunkfee (BTC), chunkweight, and its txids in mining order. Core's RPC layer
reconstructs chunk membership with a size countdown because its graph hides
chunks; ours exposes them (TXGRAPH-GET-CLUSTER-CHUNKS). clusterweight and
chunkweight are Core's sigops-adjusted WEIGHT (GetAdjustedWeight), which is
what the txgraph holds, so no conversion happens on the way out."
  (let ((mempool (rpc-get-mempool node)))
    ;; Node lock: the chunk walk reads the live txgraph, which the sync
    ;; thread relinearizes on every mempool mutation.
    (with-node-lock (node)
     (multiple-value-bind (txid entry) (%mempool-txid-arg params mempool)
      (declare (ignore txid))
      (let ((chunks (bl.mp:txgraph-get-cluster-chunks
                     (bl.mp:mempool-graph mempool)
                     (bl.mp:mempool-entry-graph-handle entry))))
        `(("clusterweight"
           . ,(reduce #'+ chunks
                      :key (lambda (c) (bl.mp:feefrac-size (cdr c)))))
          ("txcount" . ,(reduce #'+ chunks :key (lambda (c) (length (car c)))))
          ("chunks"
           . ,(mapcar (lambda (c)
                        `(("chunkfee" . ,(satoshi->btc (bl.mp:feefrac-fee (cdr c))))
                          ("chunkweight" . ,(bl.mp:feefrac-size (cdr c)))
                          ("txs" . ,(mapcar (lambda (h)
                                              (hash-to-hex
                                               (bl.mp:tx-handle-data h)))
                                            (car c)))))
                      chunks))))))))

(define-rpc "getmempoolfeeratediagram" (node params)
  "Return the feerate diagram for the whole mempool (Bitcoin Core
getmempoolfeeratediagram — a hidden RPC, rpc/mempool.cpp:609-650 +
CTxMemPool::GetFeerateDiagram, txmempool.cpp:1082-1102): the cumulative
(weight, fee-in-BTC) point after each chunk in mining order, starting from
the (0, 0) origin. The weight axis is Core's sigops-adjusted weight — its
GetFeerateDiagram returns FeePerWeight and the RPC reports f.size verbatim
(rpc/mempool.cpp:641-643), and so does this."
  (declare (ignore params))
  (let ((mempool (rpc-get-mempool node))
        (cum-weight 0)
        (cum-fee 0)
        (points (list `(("weight" . 0) ("fee" . 0.0d0)))))
    ;; Node lock: an active block builder forbids concurrent txgraph
    ;; mutation — the same exclusion the mining assembler's chunk walk
    ;; takes (assembler.lisp %with-mempool-lock).
    (when mempool
      (with-node-lock (node)
        (let ((builder (bl.mp:make-block-builder
                        (bl.mp:mempool-graph mempool))))
          (unwind-protect
               (loop for feerate = (bl.mp:block-builder-current-chunk-feerate
                                    builder)
                     while feerate
                     do (incf cum-weight (bl.mp:feefrac-size feerate))
                        (incf cum-fee (bl.mp:feefrac-fee feerate))
                        (push `(("weight" . ,cum-weight)
                                ("fee" . ,(satoshi->btc cum-fee)))
                              points)
                        (bl.mp:block-builder-include builder))
            (bl.mp:block-builder-finish builder)))))
    (nreverse points)))

(define-rpc "gettxspendingprevout" (node ((outpoints :array) options))
  "For each {txid, vout} outpoint in the array PARAM, report the transaction
spending it, if any (Bitcoin Core gettxspendingprevout). Returns an array of
{txid, vout, spendingtxid?, spendingtx?}.

The mempool is always consulted. A CONFIRMED spend is answered from the
txospenderindex, which is the only reason that index exists — without it this
RPC could only ever say `not found\' for an output spent in a block, which is
what this node did until the index landed.

OPTIONS mirror Core (rpc/mempool.cpp:912-916):
  mempool_only        default: true when the spender index is unavailable,
                      false when it is — so the answer improves by enabling the
                      index rather than by changing the call.
  return_spending_tx  default false; adds the full spending transaction as hex."
  (unless (and (listp outpoints) outpoints)
    (error 'rpc-error :code +rpc-invalid-parameter+
                      :message "Invalid parameter, outputs are missing"))
  ;; The options object is a CLOSED set (rpc/mempool.cpp:944-949: fAllowNull
  ;; true, fStrict true), so an unknown key is -3 rather than a field silently
  ;; ignored -- a caller who misspells mempool_only gets the index answer it
  ;; meant to suppress otherwise.
  (when options
    (rpc-type-check-obj options '(("mempool_only" . "bool")
                                  ("return_spending_tx" . "bool"))
                        :allow-null t :strict t))
  (let* ((mempool (rpc-get-mempool node))
         (index (bl:node-txospenderindex node))
         (index-live (and index (bl.store:txospender-index-enabled index)))
         (mempool-only (if (and (hash-table-p options)
                                (nth-value 1 (gethash "mempool_only" options)))
                           (and (gethash "mempool_only" options) t)
                           (not index-live)))
         (return-tx (and (hash-table-p options)
                         (gethash "return_spending_tx" options)
                         t)))
    ;; Node lock: one consistent spent-map snapshot across all queried
    ;; outpoints (Core gettxspendingprevout takes pool.cs once).
    (with-node-lock (node)
     (mapcar
      (lambda (op)
        ;; Each outpoint is a closed {txid, vout} object too (fAllowNull
        ;; false, fStrict true, rpc/mempool.cpp:964-968), and it runs BEFORE
        ;; ParseHashO so a numeric txid is the type error Core reports rather
        ;; than a hash-parse complaint.
        (rpc-type-check-obj op '(("txid" . "string") ("vout" . "number"))
                            :strict t)
        (let* ((txid-hex (obj-get op "txid"))
               (txid (parse-hash-v txid-hex "txid"))
               (vout (obj-get op "vout")))
          (when (minusp vout)
            (error 'rpc-error :code +rpc-invalid-parameter+
                              :message "Invalid parameter, vout cannot be negative"))
          (let* ((mem (and mempool
                           (bl.mp:mempool-spending-tx mempool txid vout)))
                 (spender-block-hash nil)
                 (spender-tx (and (not mem) (not mempool-only)
                                  (multiple-value-bind (tx block-hash)
                                      (%txospender-confirmed-spender node index txid vout)
                                    (setf spender-block-hash block-hash)
                                    tx))))
            (cond
              (mem `(("txid" . ,txid-hex)
                     ("vout" . ,vout)
                     ("spendingtxid" . ,(hash-to-hex mem))
                     ,@(when return-tx
                         (let* ((e (and mempool (bl.mp:mempool-get mempool mem)))
                                (tx (and e (bl.mp:mempool-entry-transaction e))))
                           (when tx
                             `(("spendingtx"
                                . ,(bl.crypto:bytes-to-hex
                                    (bl.ser:transaction-wire-bytes tx))))))))) 
              (spender-tx
               `(("txid" . ,txid-hex)
                 ("vout" . ,vout)
                 ("spendingtxid"
                  . ,(hash-to-hex (bl.ser:transaction-hash spender-tx)))
                 ;; The index answer names the BLOCK the spend is in, which
                 ;; the mempool answer above cannot (rpc/mempool.cpp:
                 ;; 1020-1021, o.pushKV("blockhash", ...)). It is the only
                 ;; thing that tells a caller the spend is confirmed, and
                 ;; rpc_gettxspendingprevout.py:132 compares the whole
                 ;; object.
                 ("blockhash" . ,(hash-to-hex spender-block-hash))
                 ,@(when return-tx
                     `(("spendingtx"
                        . ,(bl.crypto:bytes-to-hex
                            (bl.ser:transaction-wire-bytes spender-tx)))))))
              ;; Not in the mempool. Core answers "unspent" only when the caller
              ;; asked for the mempool alone; otherwise not having the index is
              ;; an ERROR, because silence would be indistinguishable from a
              ;; genuine answer (rpc/mempool.cpp:1010-1011).
              (mempool-only `(("txid" . ,txid-hex) ("vout" . ,vout)))
              ((not index-live)
               (error 'rpc-error :code +rpc-misc-error+
                                 :message (format nil "No spending tx for the outpoint ~A:~D in mempool, and txospenderindex is unavailable."
                                                  txid-hex vout)))
              (t `(("txid" . ,txid-hex) ("vout" . ,vout)))))))
      outpoints))))

(defun %txospender-confirmed-spender (node index txid vout)
  "(VALUES SPENDING-TX BLOCK-HASH) for the confirmed spend of TXID:VOUT from
the spender index, or NIL. The block hash is part of the answer, not a
by-product: it is what Core's caller reports as `blockhash\'
(rpc/mempool.cpp:1020-1021).

The index key is a SALTED HASH of the outpoint, so two different outpoints can
land under one key. Every candidate is read back from its block and checked
before it is believed — Core does the same for the same reason
(index/txospenderindex.cpp:141-156). A candidate that does not really spend the
outpoint is a hash collision; one whose block is no longer on the active chain
is a reorg the index has not been told about, and both are skipped."
  (let ((block-store (bl:node-block-store node)))
    (dolist (locator (bl.store:txospenderindex-locators index txid vout))
      (destructuring-bind (block-hash . position) locator
        (let ((block (and block-store
                          (bl.store:get-block block-store block-hash))))
          ;; KNOWN, not necessarily on the ACTIVE chain. Core's FindSpender
          ;; reads the transaction at the indexed position and returns it as
          ;; soon as one of its inputs is the outpoint
          ;; (index/txospenderindex.cpp:160-176); it asks nothing about the
          ;; chain, so an entry a reorg has left behind is answered until the
          ;; index is rewound, and the block hash it reports is that block's.
          ;; rpc_gettxspendingprevout.py:200 pins exactly that: after an
          ;; invalidateblock the RPC still names the spend from the abandoned
          ;; block, "still in txospender index which has not been rewound yet".
          ;; An active-chain gate here answered "unspent" instead, which is
          ;; Core's shape for "nothing spent it" and so indistinguishable from
          ;; a real answer -- the same confusion the index's own rewind test
          ;; was written about.
          (when block
            (let ((tx (%tx-at-block-position block position)))
              (when (and tx (%tx-spends-outpoint-p tx txid vout))
                (return-from %txospender-confirmed-spender
                  (values tx block-hash))))))))
    nil))

(defun %tx-at-block-position (block position)
  "The transaction at byte offset POSITION within BLOCK's transaction list, or
NIL when the offset does not land on one — which is what a stale index entry
looks like."
  (let ((offset 0))
    (dolist (tx (bl.ser:bitcoin-block-transactions block))
      (when (= offset position) (return-from %tx-at-block-position tx))
      (incf offset (length (bl.ser:transaction-wire-bytes tx))))
    nil))

(defun %tx-spends-outpoint-p (tx txid vout)
  (some (lambda (input)
          (let ((op (bl.ser:tx-in-previous-output input)))
            (and (equalp (bl.ser:outpoint-hash op) txid)
                 (= (bl.ser:outpoint-index op) vout))))
        (bl.ser:transaction-inputs tx)))

;;;; Raw-transaction safety rails (Core node/transaction.h:28-34)
;;;;
;;;; sendrawtransaction, testmempoolaccept and submitpackage each carry two
;;;; fat-finger rails that apply BEFORE a transaction can reach the mempool or
;;;; the wire: maxfeerate caps the absolute fee, and maxburnamount caps the
;;;; value an output may commit to a script that can never spend it. Both are
;;;; ON by default -- a caller switches the fee rail off by passing
;;;; maxfeerate=0, and raises the burn rail explicitly.

(defconstant +default-max-raw-tx-fee-rate+ 10000000
  "Core node::DEFAULT_MAX_RAW_TX_FEE_RATE (node/transaction.h:28) = COIN/10
satoshis per kvB.")

(defun %parse-max-fee-rate (params index)
  "Core ParseFeeRate (rpc/util.cpp:110-115) for the optional positional
maxfeerate at INDEX: a BTC/kvB amount defaulting to
DEFAULT_MAX_RAW_TX_FEE_RATE, which must stay strictly under 1 BTC/kvB.
Returns satoshis per kvB, where 0 means the caller disabled the rail."
  (let ((v (and (> (length params) index) (nth index params))))
    (if v
        (let ((sat (amount-from-value v)))
          (when (>= sat 100000000)
            (error 'rpc-error :code +rpc-invalid-parameter+
                              :message "Fee rates larger than or equal to 1BTC/kvB are not accepted"))
          sat)
        +default-max-raw-tx-fee-rate+)))

(defun %parse-max-burn-amount (params index)
  "Core's maxburnamount at INDEX (rpc/mempool.cpp:92), a BTC amount defaulting
to DEFAULT_MAX_BURN_AMOUNT (0) -- no burn is tolerated unless asked for."
  (let ((v (and (> (length params) index) (nth index params))))
    (if v (amount-from-value v) 0)))

(defun %check-max-burn (tx max-burn)
  "Signal Core's MAX_BURN_EXCEEDED when an output of TX commits more than
MAX-BURN satoshis to a script that can never spend it -- provably unspendable,
or one that does not even parse (rpc/mempool.cpp:99-103). Core runs this on the
DECODED transaction before any validation, so a burning transaction never
reaches the mempool."
  (loop for out across (bl.ser:transaction-outputs tx)
        for spk = (bl.ser:tx-out-script-pubkey out)
        when (and (or (bl.store:script-unspendable-p spk)
                      (not (bl.store:script-has-valid-ops-p spk)))
                  (> (bl.ser:tx-out-value out) max-burn))
          do (error 'rpc-error :code +rpc-verify-error+
                               :message "Unspendable output exceeds maximum configured by user (maxburnamount)")))

(defun %decode-package-member (hex)
  "One member of a testmempoolaccept / submitpackage array, or Core's -22
naming the hex that failed (rpc/mempool.cpp:332-335, 1371-1374). Both RPCs
abort the WHOLE call on a decode failure rather than returning a per-tx
allowed=false row."
  (decode-hex-tx-or-error
   hex (format nil "TX decode failed: ~A Make sure the tx has at least one input."
               (if (stringp hex) hex ""))))

(defun %testmempoolaccept-single (tx utxo-set mempool chain-state height)
  "One transaction is NOT a package: testmempoolaccept sends it through plain
single-transaction acceptance instead (Core rpc/mempool.cpp:343-346 ->
ChainstateManager::ProcessTransaction with test_accept), where replacement IS
allowed and sibling eviction IS on. That is why a lone BIP125 replacement is
reported as acceptable while the very same transaction inside a package is
`bip125-replacement-disallowed' (rpc_packages.py:318-326).

Returns the PACKAGE-TX-RESULT for TX, so both arms of the RPC render through
the same loop."
  (multiple-value-bind (valid error fee replaced sigops modified-fee)
      (bl.val:validate-transaction-for-mempool tx utxo-set mempool height
                                               :chain-state chain-state)
    (declare (ignore replaced))
    (let ((res (bl.val:make-package-tx-result
                :txid (bl.ser:transaction-hash tx)
                :wtxid (bl.ser:transaction-wtxid tx))))
      (if valid
          ;; Core reports ws.m_vsize — the sigop-adjusted size, not the raw
          ;; BIP141 vsize (validation.cpp:1383-1387) — and the effective
          ;; feerate is the MODIFIED fee (base plus any prioritisetransaction
          ;; delta) over that same vsize, covering this wtxid alone.
          (let ((vsize (bl.mp:sigop-adjusted-vsize
                        (bl.ser:transaction-weight tx) sigops)))
            (setf (bl.val:package-tx-result-status res) :valid
                  (bl.val:package-tx-result-vsize res) vsize
                  (bl.val:package-tx-result-fee res) (or fee 0)
                  (bl.val:package-tx-result-effective-feerate res)
                  (if (plusp vsize) (/ (or modified-fee fee 0) vsize) 0)
                  (bl.val:package-tx-result-effective-includes res)
                  (list (bl.ser:transaction-wtxid tx))))
          (setf (bl.val:package-tx-result-status res) :invalid
                (bl.val:package-tx-result-error res) error))
      res)))

(defun %testmempoolaccept-rows (results max-fee-rate package-error)
  "Core's testmempoolaccept output loop (rpc/mempool.cpp:352-402) over RESULTS,
one PACKAGE-TX-RESULT per member in the order they were submitted.

Three shapes come out of it:

  a member Core finished and accepted — allowed, its vsize, and the fees
  object; a member it rejected — allowed=false with the reject reason, plus
  the details for everything except missing inputs, whose reason this RPC
  spells `missing-inputs' where the state says
  `bad-txns-inputs-missingorspent'; and a member it never finished — txid and
  wtxid ALONE, which is how a caller can tell that the answer it did not get
  was never computed rather than lost.

MAX-FEE-RATE is the caller's fat-finger rail, in satoshis per kvB, and it is
applied HERE rather than inside validation (:376-381): a member over the rail
is reported as `max-fee-exceeded' and every member after it goes blank, because
a descendant's verdict is meaningless once an ancestor would not be submitted.

PACKAGE-ERROR, when the package validator gave one, is printed on EVERY row
(:360-362) — it is a statement about the package, not about any member."
  (let ((exit-early nil))
    (loop for res in results
          collect
          (let ((ids `(("txid" . ,(hash-to-hex (bl.val:package-tx-result-txid res)))
                       ("wtxid" . ,(hash-to-hex (bl.val:package-tx-result-wtxid res)))
                       ,@(when package-error
                           `(("package-error"
                              . ,(bl.val:tx-reject-reason-string package-error)))))))
            (case (if exit-early :not-validated (bl.val:package-tx-result-status res))
              (:valid
               (let* ((vsize (bl.val:package-tx-result-vsize res))
                      (fee (or (bl.val:package-tx-result-fee res) 0))
                      (max-fee (feerate-fee max-fee-rate vsize)))
                 (if (and (plusp max-fee) (> fee max-fee))
                     (progn
                       (setf exit-early t)
                       (append ids `(("allowed" . ,+json-false+)
                                     ("reject-reason" . "max-fee-exceeded"))))
                     (append ids
                             `(("allowed" . t)
                               ("vsize" . ,vsize)
                               ("fees"
                                . (("base" . ,(satoshi->btc fee))
                                   ;; CFeeRate(m_modified_fees, m_vsize).GetFeePerK():
                                   ;; satoshis per kvB truncated toward zero, then
                                   ;; rendered in BTC.
                                   ("effective-feerate"
                                    . ,(satoshi->btc
                                        (truncate
                                         (* (or (bl.val:package-tx-result-effective-feerate res) 0)
                                            1000))))
                                   ;; Whose fees that rate covers: for a single
                                   ;; transaction its own wtxid and nothing else.
                                   ("effective-includes"
                                    . ,(map 'vector #'hash-to-hex
                                            (bl.val:package-tx-result-effective-includes res))))))))))
              ((:invalid :mempool-entry :different-witness)
               (let ((error (bl.val:package-tx-result-error res)))
                 (append ids
                         `(("allowed" . ,+json-false+)
                           ;; The state's TWO fields, reported apart
                           ;; (:396-402): reject-reason is GetRejectReason(),
                           ;; the short verdict a client matches on, and
                           ;; reject-details is ToString(), that verdict plus
                           ;; the debug message the rejection built from its own
                           ;; values ("insufficient fee" vs "insufficient fee,
                           ;; rejecting replacement <txid>, ..."). Reporting
                           ;; ToString() as the reason gave a client a sentence
                           ;; to parse where Core gives it a token. Note the
                           ;; plural in missing-inputS: it is this surface only
                           ;; — sendrawtransaction reports the state's
                           ;; "bad-txns-inputs-missingorspent".
                           ,@(if (eq (bl.val:tx-reject-keyword error) :missing-input)
                                 `(("reject-reason" . "missing-inputs"))
                                 `(("reject-reason"
                                    . ,(bl.val:tx-reject-reason-only error))
                                   ("reject-details"
                                    . ,(bl.val:tx-reject-reason-string error))))))))
              (t ids))))))

(define-rpc "testmempoolaccept" (node ((txs :array)))
  "Dry-run mempool acceptance for one or more raw transactions (hex). Returns an
array of {txid, wtxid, allowed, reject-reason?, reject-details?, vsize,
fees{base, effective-feerate, effective-includes}} without adding anything to
the mempool.

More than one transaction is validated AS A PACKAGE (Core
MemPoolAccept::AcceptMultipleTransactions under ATMPArgs::PackageTestAccept,
validation.cpp:1429-1553): the members share one coin view, so a child spending
an in-package parent is judged on its merits, the context-free package rules
(sorted, no duplicates, no internal conflicts) get their own `package-error'
verdict on every row, and replacement is disallowed — a member conflicting with
a mempool transaction is `bip125-replacement-disallowed' however good a
replacement it would be alone. Fee policy stays individual, so a package answer
equals the members' individual answers (rpc_packages.py:100)."
  (let ((utxo-set (rpc-get-utxo-set node))
        (mempool (rpc-get-mempool node))
        (chain-state (rpc-get-chain-state node)))
    ;; An empty array IS an array, and gets the count error below rather than
    ;; the type error — which is what mempool_accept.py:100 asserts. NIL here
    ;; now means null/omitted only, so it is a type error as Core has it.
    (unless (%positional-array-p (first params))
      (json-type-error (first params) "array"))
    ;; Core caps the batch at package size (rpc/mempool.cpp:322).
    (when (or (null txs) (> (length txs) bl.val:+max-package-count+))
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message (format nil "Array must contain between 1 and ~D transactions."
                                         bl.val:+max-package-count+)))
    ;; Decode every tx up front: a decode failure aborts the WHOLE call with
    ;; -22 (Core DecodeHexTx -> RPC_DESERIALIZATION_ERROR, rpc/mempool.cpp:333),
    ;; it does not produce a per-tx allowed=false row.
    (let ((decoded (mapcar #'%decode-package-member txs)))
      ;; Node lock: validation reads the mempool + UTXO set + tip together;
      ;; a consistent view for the whole batch (Core ProcessTransaction
      ;; requires cs_main even for test_accept).
      (with-node-lock (node)
        (let ((height (bl.store:current-height chain-state))
              (max-fee-rate (%parse-max-fee-rate params 1)))
          (multiple-value-bind (package-error results)
              (if (> (length decoded) 1)
                  (bl.val:test-package-acceptance decoded utxo-set mempool
                                                  chain-state)
                  (values nil (list (%testmempoolaccept-single
                                     (first decoded) utxo-set mempool
                                     chain-state height))))
            (%testmempoolaccept-rows results max-fee-rate package-error)))))))

(defun %refuse-if-already-in-utxo-set (tx txid utxo-set)
  "Core BroadcastTransaction's first question (node/transaction.cpp:52-61): an
output of TX already in the coins view means TX is confirmed, and the answer
is TransactionError::ALREADY_IN_UTXO_SET -- -27 with common/messages.cpp:
134-135's sentence (rpc/util.cpp:396-397). rpc_rawtransaction.py:445 read -26
txn-already-known from us."
  (dotimes (o (length (bl.ser:transaction-outputs tx)))
    (when (bl.store:utxo-exists-p utxo-set txid o)
      (error 'rpc-error :code +rpc-verify-already-in-utxo-set+
                        :message "Transaction outputs already in utxo set"))))

(defun %refuse-private-broadcast ()
  "sendrawtransaction under -privatebroadcast. Core first refuses when neither
Tor nor I2P is reachable NOW (rpc/mempool.cpp:115-124, the proxy may have been
expected from the Tor daemon at start-up), in its words; otherwise it hands
the transaction to the private-broadcast queue WITHOUT the mempool. That queue
does not exist here, and the ordinary path would announce the transaction to
every peer from this node's own address -- what the operator asked us not to
do -- so the transaction is refused, not broadcast."
  (unless (or (bl.net:reachable-network-p :torv3) (bl.net:reachable-network-p :i2p))
    (error 'rpc-error :code +rpc-misc-error+
                      :message "-privatebroadcast is enabled, but none of the Tor or I2P networks is reachable. Maybe the location of the Tor proxy couldn't be retrieved from the Tor daemon at startup. Check whether the Tor daemon is running and that -torcontrol, -torpassword and -i2psam are configured properly."))
  (error 'rpc-error :code +rpc-misc-error+
                    :message "-privatebroadcast is enabled, but this node does not implement private broadcast; the transaction was neither added to the mempool nor broadcast"))

(defun %refuse-before-broadcast (tx txid utxo-set)
  "sendrawtransaction's two refusals in Core's order: the -privatebroadcast
gate (rpc/mempool.cpp:115-124) runs before BroadcastTransaction's first
question, the UTXO-set check (node/transaction.cpp:52-61)."
  (when bl:*private-broadcast*
    (%refuse-private-broadcast))
  (%refuse-if-already-in-utxo-set tx txid utxo-set))

(define-rpc "sendrawtransaction" (node (hex-str))
  "Submit a raw transaction to the mempool AND broadcast it: on acceptance the
txid joins the mempool's unbroadcast set and an announcement is queued to every
relay-capable peer (Core sendrawtransaction -> BroadcastTransaction,
node/transaction.cpp:100-135: AddUnbroadcastTx + InitiateTxBroadcastToAll). A
tx already in the mempool is not resubmitted but IS re-announced, so the RPC
doubles as a manual rebroadcast (node/transaction.cpp:63-72)."
  (let ((max-burn (%parse-max-burn-amount params 2)))
    (unless (and (stringp hex-str) (> (length hex-str) 0))
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "Invalid transaction hex"))
    (handler-case
        (let* ((tx (decode-hex-tx-or-error
                    hex-str
                    "TX decode failed. Make sure the tx has at least one input."))
               (txid (bl.ser:transaction-hash tx)))
          (%check-max-burn tx max-burn)
          ;; Node lock across validate -> accept -> unbroadcast -> announce:
          ;; the whole sequence mutates state the sync thread owns (Core
          ;; BroadcastTransaction runs under cs_main + pool.cs,
          ;; node/transaction.cpp:52). Without it, the tip/mempool can move
          ;; between validation and insertion, admitting an entry the
          ;; validation no longer justifies.
          (with-node-lock (node)
           (let* ((utxo-set (rpc-get-utxo-set node))
                  (mempool (rpc-get-mempool node))
                  (chain-state (rpc-get-chain-state node))
                  (current-height (bl.store:current-height chain-state))
                  ;; ParseFeeRate comes after the burn loop in Core (:107).
                  ;; The cap is taken on the PLAIN BIP141 vsize here
                  ;; (GetVirtualTransactionSize, :109) -- not the
                  ;; sigop-adjusted vsize testmempoolaccept reports.
                  (max-fee (feerate-fee
                            (%parse-max-fee-rate params 1)
                            (bl.ser:transaction-vsize tx))))
            (%refuse-before-broadcast tx txid utxo-set)
            ;; Core checks the mempool by TXID before validating at all
            ;; (node/transaction.cpp:63-72), skips submission and only
            ;; re-announces, with the POOL entry's wtxid. Asking VALIDATE
            ;; instead threw -26 txn-same-nonwitness-data-in-mempool where
            ;; Core answers the txid (mempool_accept_wtxid.py:82).
            (when (bl.mp:mempool-has mempool txid)
              (bl:broadcast-transaction-to-peers node txid)
              (return-from rpc-sendrawtransaction (hash-to-hex txid)))
            ;; Validate transaction for mempool
            (multiple-value-bind (valid error fee replaced sigops)
                (bl.val:validate-transaction-for-mempool
                 tx utxo-set mempool current-height :chain-state chain-state)
              (unless valid
                ;; Core reports the state's own reject reason, with no prefix
                ;; of its own: BroadcastTransaction sets err_string to
                ;; state.ToString() (node/transaction.cpp:21) and the RPC
                ;; prints exactly that (rpc/util.cpp:408-414). The CODE splits
                ;; on the result: TX_MISSING_INPUTS becomes
                ;; TransactionError::MISSING_INPUTS (:23-25), which maps to
                ;; RPC_TRANSACTION_ERROR = RPC_VERIFY_ERROR = -25
                ;; (rpc/util.cpp:391-401, protocol.h:54), and everything else
                ;; to -26. rpc_rawtransaction.py:354 pins the pair: -25 with
                ;; "bad-txns-inputs-missingorspent".
                (error 'rpc-error
                       :code (if (eq error :missing-input)
                                 +rpc-verify-error+
                                 +rpc-transaction-rejected+)
                       :message (bl.val:tx-reject-reason-string error)))
              ;; Core runs ATMP with test_accept FIRST and only submits for real
              ;; once the fee is under the rail (node/transaction.cpp:74-84), so
              ;; an over-paying transaction never enters the mempool and is
              ;; never announced. Our VALIDATE-TRANSACTION-FOR-MEMPOOL is
              ;; already the test-accept half: it computes FEE without
              ;; mutating the pool, and ACCEPT-VALIDATED-TX below is the
              ;; submission. A zero rate disables the rail (check_max_fee).
              (when (and (plusp max-fee) (> fee max-fee))
                (error 'rpc-error :code +rpc-verify-error+
                                  :message "Fee exceeds maximum configured by user (e.g. -maxtxfee, maxfeerate)"))
              (let ((add-result (bl.mp:accept-validated-tx
                                 mempool txid tx fee current-height
                                 :sigops sigops :replaced replaced
                                 :chainstate-current
                                 (bl.net:current-for-fee-estimation-p
                                  chain-state))))
                (unless (eq add-result :ok)
                  ;; The state's own reject reason, as on every other path:
                  ;; err_string is state.ToString() (node/transaction.cpp:21)
                  ;; and the RPC prints exactly that (rpc/util.cpp:408-414).
                  (error 'rpc-error :code +rpc-transaction-rejected+
                                    :message (bl.val:tx-reject-reason-string add-result)))
                ;; Track for best-effort initial broadcast (Core
                ;; node/transaction.cpp:100-104), then queue the announcement
                ;; to all relay peers.
                (bl.mp:mempool-add-unbroadcast mempool txid)
                (bl:broadcast-transaction-to-peers node txid)
                (hash-to-hex txid))))))
      ;; Re-raise our own rpc-errors (the -26 rejections above) unchanged; only a
      ;; genuine parse/deserialization failure maps to RPC_DESERIALIZATION_ERROR
      ;; (-22), which Core distinguishes from the -26 mempool rejections.
      (rpc-error (e) (error e))
      (error (e)
        (error 'rpc-error :code +rpc-deserialization-error+
                          :message (format nil "TX decode failed: ~A" e))))))

(defun %package-tx-result-fields (r &optional package-aborted)
  "Field alist for one package-tx-result, mirroring Bitcoin Core submitpackage's
per-wtxid object. Status drives which fields are present. PACKAGE-ABORTED is T
when NO member was processed -- Core's empty m_tx_results -- and only then is
a :not-validated member Core's `package-not-validated'; a placeholder beside
real results carries its own reason, as Core's per-tx evaluation would."
  (let ((status (if (and (eq (bl.val:package-tx-result-status r) :not-validated)
                         (not package-aborted))
                    :invalid
                    (bl.val:package-tx-result-status r)))
        (base (list (cons "txid" (hash-to-hex
                                  (bl.val:package-tx-result-txid r))))))
    (flet ((btc (sat) (satoshi->btc (or sat 0)))
           ;; sat/vB -> BTC/kvB, the unit Core reports feerates in. FLOOR,
           ;; because Core reports CFeeRate::GetFeePerK(), which is
           ;; FeeFrac::EvaluateFeeDown(1000) (policy/feerate.h:62) -- an
           ;; integer sat/kvB rounded DOWN, so the sub-satoshi remainder of a
           ;; rational sat/vB never reaches the wire.
           (feerate-btc-kvb (rate) (satoshi->btc (floor (* (or rate 0) 1000)))))
      (ecase status
        (:valid
         (append base
                 `(("vsize" . ,(bl.val:package-tx-result-vsize r))
                   ("fees" . (("base" . ,(btc (bl.val:package-tx-result-fee r)))
                              ("effective-feerate"
                               . ,(feerate-btc-kvb
                                   (bl.val:package-tx-result-effective-feerate r)))
                              ("effective-includes"
                               . ,(mapcar #'hash-to-hex
                                          (bl.val:package-tx-result-effective-includes r))))))))
        (:mempool-entry
         (append base
                 `(("vsize" . ,(bl.val:package-tx-result-vsize r))
                   ("fees" . (("base" . ,(btc (bl.val:package-tx-result-fee r))))))))
        (:different-witness
         (append base
                 `(("other-wtxid"
                    . ,(let ((ow (bl.val:package-tx-result-other-wtxid r)))
                         (if ow (hash-to-hex ow) ""))))))
        ;; A member the package never reached has NO per-tx result in Core,
        ;; and the RPC fills the fixed word in for it (rpc/mempool.cpp:
        ;; 1455-1463); the package's own reason is package_msg's.
        ;; rpc_packages.py:271.
        (:not-validated
         (append base '(("error" . "package-not-validated"))))
        (:invalid
         (append base
                 `(("error" . ,(let ((e (bl.val:package-tx-result-error r)))
                                 (if e
                                     (bl.val:tx-reject-reason-string e)
                                     "rejected"))))))))))

(define-rpc "submitpackage" (node ((hexes :array)))
  "Submit a package of raw transactions (a child with its unconfirmed parents)
to the mempool. PARAMS: (package-hex-array [maxfeerate] [maxburnamount]). The
array is topologically sorted with the child last. Mirrors Bitcoin Core's
submitpackage: returns {package_msg, tx-results{wtxid -> {...}},
replaced-transactions}. maxfeerate caps each member's modified feerate and
aborts the whole package on the first breach; maxburnamount caps the value any
member may send to a script that can never spend it."
  (let ((utxo-set (rpc-get-utxo-set node))
        (mempool (rpc-get-mempool node))
        (chain-state (rpc-get-chain-state node)))
    ;; One check, one sentence, Core's own, trailing period included
    ;; (rpc/mempool.cpp:1351-1354); rpc_packages.py:410/:411 match it for []
    ;; and for 26 members alike.
    (when (or (null hexes) (> (length hexes) bl.val:+max-package-count+))
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message (format nil "Array must contain between 1 and ~D transactions."
                                         bl.val:+max-package-count+)))
    (unless mempool
      ;; Core: RPC_CLIENT_MEMPOOL_DISABLED (-33), server_util.cpp:37.
      (error 'rpc-error :code +rpc-client-mempool-disabled+
                        :message "Mempool disabled or instance not found"))
    ;; Decode every tx up front; a single decode failure aborts the whole call.
    (let ((package (mapcar #'%decode-package-member hexes))
          ;; A maxfeerate of 0 disables the rail entirely (Core turns the
          ;; CFeeRate into nullopt, rpc/mempool.cpp:1358-1362).
          (client-maxfeerate (let ((r (%parse-max-fee-rate params 1)))
                               (and (plusp r) r)))
          (max-burn (%parse-max-burn-amount params 2)))
      ;; Every member is burn-checked before any validation runs
      ;; (rpc/mempool.cpp:1374-1380).
      (dolist (tx package)
        (%check-max-burn tx max-burn))
      ;; The topology gate is the RPC's, not the package validator's
      ;; (rpc/mempool.cpp:1385-1387): more than one transaction must be a
      ;; child with its parents, and no parent may spend another parent.
      ;; Core throws TransactionError::INVALID_PACKAGE, which
      ;; RPCErrorFromTransactionError maps to RPC_TRANSACTION_ERROR = -25
      ;; (rpc/util.cpp:391-401, protocol.h:47,54) -- an ERROR, not a result
      ;; object. VALIDATE-PACKAGE-FOR-MEMPOOL runs the same check for the P2P
      ;; 1p1c path and reports it as a package_msg, and that is what
      ;; submitpackage answered for a four-transaction chain: HTTP 200 with
      ;; "package-not-child-with-parents" in the body, where Core raises.
      (when (and (> (length package) 1)
                 (not (bl.val:package-child-with-parents-tree-p package)))
        (error 'rpc-error :code +rpc-verify-error+
                          :message "package topology disallowed. not child-with-parents or parents depend on each other."))
      ;; Node lock across validate-package -> mempool submission ->
      ;; broadcast: package acceptance mutates the mempool tx-by-tx and
      ;; must not interleave with the sync thread (Core AcceptPackage runs
      ;; entirely under cs_main + pool.cs).
      (multiple-value-bind (msg results replaced package-msg)
          (with-node-lock (node)
            (multiple-value-prog1
                (bl.val:validate-package-for-mempool
                 package utxo-set mempool chain-state
                 :client-maxfeerate client-maxfeerate)
              ;; Broadcast every package member that made it into (or already
              ;; was in) the mempool — Core submitpackage runs
              ;; BroadcastTransaction on each such tx (rpc/mempool.cpp:
              ;; 1423-1444). Those txs are in the pool by now, so Core's
              ;; already-in-mempool branch applies: relay only, no
              ;; unbroadcast-set add (node/transaction.cpp:63-72).
              (dolist (tx package)
                (let ((txid (bl.ser:transaction-hash tx)))
                  (when (bl.mp:mempool-has mempool txid)
                    (bl:broadcast-transaction-to-peers node txid))))))
        (declare (ignore msg))
        `(;; Core's package_msg is the PACKAGE state's ToString(), which for a
          ;; per-member failure is the fixed "transaction failed"
          ;; (rpc/mempool.cpp:1395-1400, validation.cpp:1447 and the other
          ;; PCKG_TX sites); only a verdict about the package itself keeps its
          ;; own word. Downcasing the member's keyword answered "dust" where
          ;; mempool_ephemeral_dust.py:160 reads "transaction failed".
          ("package_msg" . ,package-msg)
          ("tx-results"
           . ,(let ((aborted (every (lambda (r)
                                      (eq (bl.val:package-tx-result-status r)
                                          :not-validated))
                                    results)))
                (mapcar (lambda (r)
                          (cons (hash-to-hex (bl.val:package-tx-result-wtxid r))
                                (%package-tx-result-fields r aborted)))
                        results)))
          ;; Always present, [] when nothing was replaced (rpc/mempool.cpp
          ;; :1496-1498).
          ("replaced-transactions"
           . ,(json-array (mapcar #'hash-to-hex replaced))))))))

;;; --- Mempool persistence (Bitcoin Core savemempool) ---

(define-rpc "savemempool" (node params)
  "Dump the mempool to disk (Bitcoin Core savemempool). Returns the filename.
The same dump runs automatically on graceful shutdown."
  (declare (ignore params))
  (let ((path (bl.mp:mempool-dat-path
               (bl:node-data-directory node))))
    (unless path
      (error 'rpc-error :code +rpc-misc-error+
                        :message "Node has no data directory"))
    ;; Node lock: the dump iterates entries, deltas, and the unbroadcast
    ;; set; a concurrent sync-thread mutation would tear the snapshot
    ;; (Core DumpMempool snapshots under pool.cs).
    ;;
    ;; A dump that could not be written is Core's -1 "Unable to dump mempool
    ;; to disk" (rpc/mempool.cpp, savemempool: `if (!DumpMempool(...)) throw
    ;; JSONRPCError(RPC_MISC_ERROR, ...)'). DumpMempool itself never throws,
    ;; so the RPC is the only place the failure is reported.
    (unless (with-node-lock (node)
              (bl.mp:save-mempool-file (rpc-get-mempool node) path))
      (error 'rpc-error :code +rpc-misc-error+
                        :message "Unable to dump mempool to disk"))
    `(("filename" . ,(namestring path)))))

(define-rpc "importmempool" (node (filepath options))
  "Load transactions from a mempool.dat-format file at FILEPATH through the normal
acceptance path (Bitcoin Core importmempool). PARAMS: (filepath [options]).
Entries are validated against the current UTXO set; their prioritisation deltas
are applied. The options object supports apply_unbroadcast_set (default false,
Core rpc/mempool.cpp:1115-1116: only restore the file's unbroadcast set when
asked — unlike the startup load, where it defaults on), and now
apply_fee_delta_priority (default false) and use_current_time (default true),
both of which were accepted and ignored. Returns an empty object.

All three RPC defaults are the OPPOSITE of the startup load's
(node/mempool_persist.h:20-25 vs rpc/mempool.cpp:1138-1141), because this RPC
ingests someone else's file: a foreign fee delta is not this operator's policy,
and a foreign timestamp would misdate the entry.

⚠️ use_current_time defaults to TRUE, so absence and an explicit false must be
told apart — and a nested JSON false folds to NIL exactly like an absent key
(%NORMALIZE-RPC-PARAMS, rpc/server.lisp). GETHASH's second value is the only thing that
separates them."
  (unless (and (stringp filepath) (plusp (length filepath)))
    (error 'rpc-error :code +rpc-invalid-parameter+ :message "filepath must be a string"))
  (flet ((opt (name default)
           (if (hash-table-p options)
               (multiple-value-bind (v present) (gethash name options)
                 (if present (and v t) default))
               default)))
  (let ((path (probe-file filepath))
          (apply-unbroadcast (opt "apply_unbroadcast_set" nil))
          (apply-fee-delta (opt "apply_fee_delta_priority" nil))
          (use-current-time (opt "use_current_time" t)))
      (unless path
        (error 'rpc-error :code +rpc-invalid-parameter+
                          :message (format nil "Can't open mempool file ~A" filepath)))
      ;; Node lock: the import validates and inserts every entry against
      ;; the live UTXO set/mempool — it must not interleave with the sync
      ;; thread (Core importmempool holds cs_main + pool.cs through
      ;; LoadMempool, rpc/mempool.cpp:1130).
      (unless (with-node-lock (node)
                (bl:load-mempool-from-disk
                 node path
                 :apply-unbroadcast apply-unbroadcast
                 :apply-fee-delta-priority apply-fee-delta
                 :use-current-time use-current-time))
        (error 'rpc-error :code +rpc-misc-error+
                          :message "Unable to import mempool file (unreadable or corrupt)"))))
  ;; Core returns an empty object; an empty hash-table serializes as {}.
  (make-hash-table :test 'equal))
