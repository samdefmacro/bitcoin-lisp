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
        (incfee (/ bl.mp:*incremental-relay-fee-rate* 100000000.0d0)))
    (if mempool
        ;; Rates are sat/kvB (Core CFeeRate); convert to BTC/kvB via /1e8.
        ;; Node lock: count/bytes/total-fee must be one consistent snapshot
        ;; while the sync thread adds/evicts entries (Core getmempoolinfo
        ;; takes pool.cs via the stats getters).
        (with-node-lock (node)
         (let* ((min-fee-sat-kvb (bl.mp:mempool-effective-min-fee-rate mempool))
               (min-fee-btc-kvb (/ min-fee-sat-kvb 100000000.0d0))
               ;; The pool's configured floor (Core m_min_relay_feerate).
               (relay-fee-btc-kvb (/ (bl.mp:mempool-min-fee-rate mempool)
                                     100000000.0d0))
               (count (bl.mp:mempool-count mempool))
               ;; Core "bytes" = GetTotalTxSize(), the sum of the entries'
               ;; sigop-adjusted VIRTUAL sizes (rpc/mempool.cpp:1040,
               ;; txmempool.h:191), not serialized bytes.
               (bytes (bl.mp:mempool-total-size mempool))
               (total-fee-sat 0))
          (bl.mp:mempool-for-each
           mempool (lambda (txid e) (declare (ignore txid))
                     (incf total-fee-sat (bl.mp:mempool-entry-fee e))))
          `(("loaded" . t)
            ("size" . ,count)
            ("bytes" . ,bytes)
            ;; Core DynamicMemoryUsage(): the malloc-modeled memory usage the
            ;; -maxmempool cap is keyed on (rpc/mempool.cpp:1041).
            ("usage" . ,(bl.mp:mempool-dynamic-usage mempool))
            ("total_fee" . ,(/ total-fee-sat 100000000.0d0))
            ("maxmempool" . ,(bl.mp:mempool-max-size mempool))
            ("mempoolminfee" . ,min-fee-btc-kvb)
            ("minrelaytxfee" . ,relay-fee-btc-kvb)
            ("incrementalrelayfee" . ,incfee)
            ;; Core rpc/mempool.cpp:1047: GetUnbroadcastTxs().size().
            ("unbroadcastcount" . ,(bl.mp:mempool-unbroadcast-count mempool))
            ;; Acceptance is unconditionally full-RBF since cluster mempool;
            ;; Core hardcodes true (rpc/mempool.cpp:1048, field DEPRECATED).
            ("fullrbf" . t)
            ("permitbaremultisig" . ,(json-bool bl:*permit-bare-multisig*)))))
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
          ("permitbaremultisig" . ,(json-bool bl:*permit-bare-multisig*))))))

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
          (bl.mp:mempool-for-each
           mempool
           (lambda (txid entry)
             (push (if verbose
                       ;; (txid . field-alist); the RPC normalizer turns the
                       ;; whole thing into nested JSON objects.
                       (cons (hash-to-hex txid)
                             (%mempool-entry-fields mempool txid entry))
                       (hash-to-hex txid))
                   rows))))
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
in: \"chunkweight\" is the chunk's total size and fees.\"chunk\" its total
modified fees. UNIT DIVERGENCE: Core's txgraph measures sigops-adjusted
WEIGHT (GetAdjustedWeight), ours sigops-adjusted virtual bytes, so
\"chunkweight\" here is in vB (~ Core's value / 4). \"vsize\" and the
ancestor/descendant sizes are the sigop-adjusted virtual size, exactly
Core's GetTxSize-based reporting."
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
          ("fees" . (("base" . ,(/ (bl.mp:mempool-entry-fee entry) 100000000.0d0))
                     ("modified" . ,(/ (bl.mp:mempool-entry-modified-fee entry)
                                       100000000.0d0))
                     ("ancestor" . ,(/ afees 100000000.0d0))
                     ("descendant" . ,(/ dfees 100000000.0d0))
                     ("chunk" . ,(/ (bl.mp:feefrac-fee chunk)
                                    100000000.0d0))))
          ("ancestorcount" . ,acount)
          ("ancestorsize" . ,asize)
          ("descendantcount" . ,dcount)
          ("descendantsize" . ,dsize)
          ("wtxid" . ,(hash-to-hex (bl.mp:mempool-entry-wtxid entry)))
          ("depends" . ,(let ((deps '()))
                          (maphash (lambda (p v) (declare (ignore v))
                                     (push (hash-to-hex p) deps))
                                   (bl.mp:mempool-entry-parents entry))
                          deps))
          ;; In-mempool txs that spend this tx's outputs (Core "spentby").
          ("spentby" . ,(let ((sb '()))
                          (maphash (lambda (c v) (declare (ignore v))
                                     (push (hash-to-hex c) sb))
                                   (bl.mp:mempool-entry-children entry))
                          sb))
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
  (let ((txid-hex (first params)))
    (unless (stringp txid-hex)
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "txid must be a hex string"))
    (let ((txid (parse-hex-hash txid-hex)))
      (unless txid
        (error 'rpc-error :code +rpc-invalid-parameter+ :message "Invalid txid"))
      (let ((entry (and mempool (bl.mp:mempool-get mempool txid))))
        (unless entry
          ;; Core: RPC_INVALID_ADDRESS_OR_KEY (-5), rpc/mempool.cpp:887.
          (error 'rpc-error :code +rpc-invalid-address-or-key+
                            :message "Transaction not in mempool"))
        (values txid entry)))))

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
chunks; ours exposes them (TXGRAPH-GET-CLUSTER-CHUNKS). UNIT DIVERGENCE:
Core's clusterweight/chunkweight are sigops-adjusted WEIGHT
(GetAdjustedWeight); our txgraph measures BIP141 virtual bytes, so those
fields here are in vB (~ Core / 4)."
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
                        `(("chunkfee" . ,(/ (bl.mp:feefrac-fee (cdr c))
                                            100000000.0d0))
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
the (0, 0) origin. UNIT DIVERGENCE: Core's weight axis is sigops-adjusted
weight; ours is BIP141 virtual bytes (~ Core / 4)."
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
                                ("fee" . ,(/ cum-fee 100000000.0d0)))
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
    (unless (and (listp outpoints) outpoints)
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "Invalid parameter, outputs are missing"))
    ;; Node lock: one consistent spent-map snapshot across all queried
    ;; outpoints (Core gettxspendingprevout takes pool.cs once).
    (with-node-lock (node)
     (mapcar
      (lambda (op)
        (let* ((txid-hex (and (hash-table-p op) (gethash "txid" op)))
               (vout (and (hash-table-p op) (gethash "vout" op)))
               (txid (and (stringp txid-hex) (parse-hex-hash txid-hex))))
          (unless (and txid (integerp vout))
            (error 'rpc-error :code +rpc-invalid-parameter+
                              :message "Invalid parameter, outputs are missing"))
          (when (minusp vout)
            (error 'rpc-error :code +rpc-invalid-parameter+
                              :message "Invalid parameter, vout cannot be negative"))
          (let* ((mem (and mempool
                           (bl.mp:mempool-spending-tx mempool txid vout)))
                 (spender-tx (and (not mem) (not mempool-only)
                                  (%txospender-confirmed-spender node index txid vout))))
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
  "The confirmed transaction that spent TXID:VOUT, from the spender index, or
NIL.

The index key is a SALTED HASH of the outpoint, so two different outpoints can
land under one key. Every candidate is read back from its block and checked
before it is believed — Core does the same for the same reason
(index/txospenderindex.cpp:141-156). A candidate that does not really spend the
outpoint is a hash collision; one whose block is no longer on the active chain
is a reorg the index has not been told about, and both are skipped."
  (let ((chain-state (rpc-get-chain-state node))
        (block-store (bl:node-block-store node)))
    (dolist (locator (bl.store:txospenderindex-locators index txid vout))
      (destructuring-bind (block-hash . position) locator
        (let ((block (and block-store
                          (bl.store:get-block block-store block-hash))))
          ;; ⚠️ ACTIVE chain, not merely known. An index entry left behind by
          ;; a reorg names a block that is still on disk and still spends the
          ;; outpoint, so believing it would answer with a spender from an
          ;; abandoned chain. The disconnect hook erases those entries; this is
          ;; the belt to its braces. Reuses the %BLOCK-ON-ACTIVE-CHAIN-P this
          ;; file already had rather than adding a second one.
          (when (and block
                     (let ((entry (bl.store:get-block-index-entry
                                   chain-state block-hash)))
                       (and entry (%block-on-active-chain-p entry chain-state))))
            (let ((tx (%tx-at-block-position block position)))
              (when (and tx (%tx-spends-outpoint-p tx txid vout))
                (return-from %txospender-confirmed-spender tx)))))))
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

(define-rpc "testmempoolaccept" (node ((txs :array)))
  "Dry-run mempool acceptance for one or more raw transactions (hex). Returns an
array of {txid, wtxid, allowed, reject-reason?, vsize, fees{base}} without adding
anything to the mempool. Each tx is checked independently against current state
(package interdependence is not modeled — that needs submitpackage)."
  (let ((utxo-set (rpc-get-utxo-set node))
        (mempool (rpc-get-mempool node))
        (chain-state (rpc-get-chain-state node)))
    ;; An empty array IS an array, and gets the count error below rather than
    ;; the type error — which is what mempool_accept.py:100 asserts. NIL here
    ;; now means null/omitted only, so it is a type error as Core has it.
    (unless (%positional-array-p (first params))
      (%json-type-error (first params) "array"))
    ;; Core caps the batch at package size (rpc/mempool.cpp:322).
    (when (or (null txs) (> (length txs) bl.val:+max-package-count+))
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message (format nil "Array must contain between 1 and ~D transactions."
                                         bl.val:+max-package-count+)))
    ;; Decode every tx up front: a decode failure aborts the WHOLE call with
    ;; -22 (Core DecodeHexTx -> RPC_DESERIALIZATION_ERROR, rpc/mempool.cpp:333),
    ;; it does not produce a per-tx allowed=false row.
    (let ((decoded
            (mapcar (lambda (hex-str)
                      (decode-hex-tx-or-error
                       hex-str
                       (format nil "TX decode failed: ~A Make sure the tx has ~
at least one input."
                               (if (stringp hex-str) hex-str ""))))
                    txs)))
      ;; Node lock: validation reads the mempool + UTXO set + tip together;
      ;; a consistent view for the whole batch (Core ProcessTransaction
      ;; requires cs_main even for test_accept).
      (with-node-lock (node)
        (let ((height (bl.store:current-height chain-state))
              (max-fee-rate (%parse-max-fee-rate params 1))
              ;; Core stops filling in results after the first tx that breaches
              ;; the rail: a descendant's verdict is meaningless once an
              ;; ancestor would not be submitted (rpc/mempool.cpp:352-355,381).
              (exit-early nil)
              (results '()))
          (dolist (tx decoded (nreverse results))
            (push
             (let ((txid (bl.ser:transaction-hash tx))
                   (wtxid (bl.ser:transaction-wtxid tx)))
               (if exit-early
                   ;; Validation unfinished: txid and wtxid only, no verdict.
                   `(("txid" . ,(hash-to-hex txid))
                     ("wtxid" . ,(hash-to-hex wtxid)))
                   (multiple-value-bind (valid error fee replaced sigops)
                       (bl.val:validate-transaction-for-mempool
                        tx utxo-set mempool height :chain-state chain-state)
                     (declare (ignore replaced))
                     (if valid
                         ;; Core reports ws.m_vsize here — the sigop-adjusted
                         ;; size, not the raw BIP141 vsize (rpc/mempool.cpp:375)
                         ;; — and caps the fee against that same vsize (:376).
                         (let* ((vsize (bl.mp:sigop-adjusted-vsize
                                        (bl.ser:transaction-weight tx)
                                        sigops))
                                (max-fee (feerate-fee max-fee-rate vsize)))
                           (cond
                             ((and (plusp max-fee) (> (or fee 0) max-fee))
                              (setf exit-early t)
                              `(("txid" . ,(hash-to-hex txid))
                                ("wtxid" . ,(hash-to-hex wtxid))
                                ("allowed" . ,+json-false+)
                                ("reject-reason" . "max-fee-exceeded")))
                             (t
                              `(("txid" . ,(hash-to-hex txid))
                                ("wtxid" . ,(hash-to-hex wtxid))
                                ("allowed" . t)
                                ("vsize" . ,vsize)
                                ("fees"
                                 . (("base" . ,(satoshi->btc (or fee 0)))
                                    ;; The feerate the acceptance decision
                                    ;; actually used: CFeeRate(m_modified_fees,
                                    ;; m_vsize).GetFeePerK() for a single
                                    ;; transaction (validation.cpp:1383,1387),
                                    ;; i.e. MODIFIED fees — base plus any
                                    ;; prioritisetransaction delta — over the
                                    ;; sigop-adjusted vsize, truncated to
                                    ;; satoshis per kvB (feerate.cpp) and
                                    ;; rendered in BTC.
                                    ("effective-feerate"
                                     . ,(satoshi->btc (let ((modified
                                                      (+ (or fee 0)
                                                         (gethash txid (bl.mp:mempool-deltas mempool) 0))))
                                                (if (plusp vsize)
                                                    (truncate (* modified 1000) vsize)
                                                    0))))
                                    ;; Which transactions' fees that rate
                                    ;; covers. For a single transaction it is
                                    ;; its own wtxid and nothing else
                                    ;; (validation.cpp:1320,1387); a package
                                    ;; feerate would list every member.
                                    ("effective-includes"
                                     . ,(vector (hash-to-hex wtxid)))))))))
                         `(("txid" . ,(hash-to-hex txid))
                           ("wtxid" . ,(hash-to-hex wtxid))
                           ("allowed" . ,+json-false+)
                           ;; This RPC substitutes its own string for the
                           ;; missing-inputs result and prints the state's
                           ;; reason for everything else (rpc/mempool.cpp:
                           ;; 399-402). Note the plural: it is this surface
                           ;; only — sendrawtransaction reports the state's
                           ;; "bad-txns-inputs-missingorspent" instead.
                           ("reject-reason"
                            . ,(if (eq error :missing-input)
                                   "missing-inputs"
                                   (bl.val:tx-reject-reason-string error))))))))
             results)))))))

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
            ;; Validate transaction for mempool
            (multiple-value-bind (valid error fee replaced sigops)
                (bl.val:validate-transaction-for-mempool
                 tx utxo-set mempool current-height :chain-state chain-state)
              (when (and (not valid) (eq error :already-in-mempool))
                ;; Core doesn't reject a same-txid resubmission: it skips the
                ;; mempool submission but still relays, announcing the POOL
                ;; entry's wtxid (a same-txid/different-witness submission must
                ;; advertise the witness we can actually serve). No unbroadcast
                ;; add — Core's already-in-mempool branch skips it too.
                (bl:broadcast-transaction-to-peers node txid)
                (return-from rpc-sendrawtransaction (hash-to-hex txid)))
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
                                 :sigops sigops :replaced replaced)))
                (unless (eq add-result :ok)
                  (error 'rpc-error :code +rpc-transaction-rejected+
                                    :message (format nil "Mempool rejection: ~A" add-result)))
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

(defun %package-tx-result-fields (r)
  "Field alist for one package-tx-result, mirroring Bitcoin Core submitpackage's
per-wtxid object. Status drives which fields are present."
  (let ((status (bl.val:package-tx-result-status r))
        (base (list (cons "txid" (hash-to-hex
                                  (bl.val:package-tx-result-txid r))))))
    (flet ((btc (sat) (/ (or sat 0) 100000000.0d0))
           ;; sat/vB -> BTC/kvB, the unit Core reports feerates in.
           (feerate-btc-kvb (rate) (/ (* (or rate 0) 1000) 100000000.0d0)))
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
        ((:invalid :not-validated)
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
    (unless (and (listp hexes) hexes)
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "First parameter must be a non-empty array of tx hex"))
    (when (> (length hexes) bl.val:+max-package-count+)
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "Array must contain between 1 and 25 transactions"))
    (unless mempool
      ;; Core: RPC_CLIENT_MEMPOOL_DISABLED (-33), server_util.cpp:37.
      (error 'rpc-error :code +rpc-client-mempool-disabled+
                        :message "Mempool disabled or instance not found"))
    ;; Decode every tx up front; a single decode failure aborts the whole call.
    (let ((package
            ;; Core: RPC_DESERIALIZATION_ERROR (-22), rpc/mempool.cpp:1371-1374.
            (mapcar (lambda (hex)
                      (decode-hex-tx-or-error
                       hex
                       (format nil "TX decode failed: ~A Make sure the tx has ~
at least one input."
                               (if (stringp hex) hex ""))))
                    hexes))
            ;; A maxfeerate of 0 disables the rail entirely (Core turns the
            ;; CFeeRate into nullopt, rpc/mempool.cpp:1358-1362).
            (client-maxfeerate (let ((r (%parse-max-fee-rate params 1)))
                                 (and (plusp r) r)))
            (max-burn (%parse-max-burn-amount params 2)))
      ;; Every member is burn-checked before any validation runs
      ;; (rpc/mempool.cpp:1374-1380).
      (dolist (tx package)
        (%check-max-burn tx max-burn))
      ;; Node lock across validate-package -> mempool submission ->
      ;; broadcast: package acceptance mutates the mempool tx-by-tx and
      ;; must not interleave with the sync thread (Core AcceptPackage runs
      ;; entirely under cs_main + pool.cs).
      (multiple-value-bind (msg results replaced)
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
        `(("package_msg" . ,(if (eq msg :success) "success"
                                (string-downcase (symbol-name msg))))
          ("tx-results"
           . ,(mapcar (lambda (r)
                        (cons (hash-to-hex (bl.val:package-tx-result-wtxid r))
                              (%package-tx-result-fields r)))
                      results))
          ,@(when replaced
              `(("replaced-transactions" . ,(mapcar #'hash-to-hex replaced)))))))))

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
    (with-node-lock (node)
      (bl.mp:save-mempool-file (rpc-get-mempool node) path))
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
