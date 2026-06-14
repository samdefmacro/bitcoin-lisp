(in-package #:bitcoin-lisp.rpc)

;;; RPC Method Implementations
;;;
;;; Each method takes a node and params list, returns result or signals error.

;;; --- Input Validation ---

(defun valid-hex-hash-p (str)
  "Check if STR is a valid 64-character hex hash."
  (and (stringp str)
       (= (length str) 64)
       (every (lambda (c) (digit-char-p c 16)) str)))

(defun parse-hex-hash (str)
  "Parse a hex string to byte vector (reversed for internal use)."
  (when (valid-hex-hash-p str)
    (let ((bytes (make-array 32 :element-type '(unsigned-byte 8))))
      (loop for i from 0 below 32
            for j from 62 downto 0 by 2
            do (setf (aref bytes i)
                     (parse-integer str :start j :end (+ j 2) :radix 16)))
      bytes)))

(defun hash-to-hex (bytes)
  "Convert a 32-byte hash to lowercase hex string (reversed for display),
matching Bitcoin Core's uint256::GetHex."
  (bitcoin-lisp.crypto:bytes-to-hex (bitcoin-lisp.crypto:reverse-bytes bytes)))

;;; --- Blockchain Query Methods ---

(defun rpc-getblockchaininfo (node params)
  "Return blockchain state information."
  (declare (ignore params))
  (let* ((chain-state (rpc-get-chain-state node))
         (height (bitcoin-lisp.storage:current-height chain-state))
         (best-hash (bitcoin-lisp.storage:best-block-hash chain-state))
         (network (rpc-get-network node))
         (syncing (rpc-is-syncing node))
         (result `(("chain" . ,(%chain-name network))
                   ("blocks" . ,height)
                   ("headers" . ,height)
                   ("bestblockhash" . ,(if best-hash (hash-to-hex best-hash) nil))
                   ("initialblockdownload" . ,syncing)
                   ("verificationprogress" . ,(if syncing 0.0 1.0))
                   ("pruned" . ,(bitcoin-lisp:pruning-enabled-p)))))
    ;; Add pruning-specific fields when pruning is enabled
    (when (bitcoin-lisp:pruning-enabled-p)
      (let ((pruned-height (bitcoin-lisp.storage:chain-state-pruned-height chain-state)))
        (setf result
              (append result
                      ;; pruneheight = first UNpruned block (Bitcoin Core convention).
                      ;; Note: pruneblockchain RPC returns pruned-height (last pruned).
                      `(("pruneheight" . ,(1+ pruned-height))
                        ("automatic_pruning" . ,(bitcoin-lisp:automatic-pruning-p))
                        ("prune_target_size" . ,(if (bitcoin-lisp:automatic-pruning-p)
                                                    (* bitcoin-lisp:*prune-target-mib* 1048576)
                                                    0)))))))
    result))

(defun rpc-getbestblockhash (node params)
  "Return the hash of the best (tip) block."
  (declare (ignore params))
  (let* ((chain-state (rpc-get-chain-state node))
         (best-hash (bitcoin-lisp.storage:best-block-hash chain-state)))
    (if best-hash
        (hash-to-hex best-hash)
        (error 'rpc-error :code +rpc-misc-error+ :message "No blocks"))))

(defun rpc-getblockcount (node params)
  "Return the current block height."
  (declare (ignore params))
  (let ((chain-state (rpc-get-chain-state node)))
    (bitcoin-lisp.storage:current-height chain-state)))

(defun rpc-getblockhash (node params)
  "Return the hash of block at given height."
  (let ((height (first params)))
    (unless (and (integerp height) (>= height 0))
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "Invalid height parameter"))
    (let* ((chain-state (rpc-get-chain-state node))
           (current-height (bitcoin-lisp.storage:current-height chain-state)))
      (when (> height current-height)
        (error 'rpc-error :code +rpc-invalid-parameter+
                          :message (format nil "Block height ~A out of range" height)))
      (let ((entry (bitcoin-lisp.storage:get-block-at-height chain-state height)))
        (if entry
            (hash-to-hex (bitcoin-lisp.storage:block-index-entry-hash entry))
            (error 'rpc-error :code +rpc-misc-error+
                              :message "Block not found"))))))

(defun rpc-getblock (node params)
  "Return block data. Verbosity: 0=hex, 1=json, 2=json+tx details."
  (let ((hash-str (first params))
        (verbosity (or (second params) 1)))
    (unless (valid-hex-hash-p hash-str)
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "Invalid block hash"))
    (unless (member verbosity '(0 1 2))
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "Verbosity must be 0, 1, or 2"))
    (let* ((hash-bytes (parse-hex-hash hash-str))
           (block-store (rpc-get-block-store node))
           (block (bitcoin-lisp.storage:get-block block-store hash-bytes)))
      (unless block
        (error 'rpc-error :code +rpc-misc-error+
                          :message "Block not found"))
      (case verbosity
        (0 ;; Return hex-encoded raw block
         (bitcoin-lisp.crypto:bytes-to-hex
          (bitcoin-lisp.serialization:serialize block)))
        (1 ;; Return JSON with txids only
         (block-to-json block hash-str nil (rpc-get-network node)))
        (2 ;; Return JSON with full tx details
         (block-to-json block hash-str t (rpc-get-network node)))))))

(defun block-to-json (block hash-str include-tx-details &optional network)
  "Convert block to JSON representation. NETWORK enables output addresses in the
full-tx-detail (verbosity 2) form."
  (let* ((header (bitcoin-lisp.serialization:bitcoin-block-header block))
         (txs (bitcoin-lisp.serialization:bitcoin-block-transactions block)))
    `(("hash" . ,hash-str)
      ("version" . ,(bitcoin-lisp.serialization:block-header-version header))
      ("previousblockhash" . ,(hash-to-hex (bitcoin-lisp.serialization:block-header-prev-block header)))
      ("merkleroot" . ,(hash-to-hex (bitcoin-lisp.serialization:block-header-merkle-root header)))
      ("time" . ,(bitcoin-lisp.serialization:block-header-timestamp header))
      ("bits" . ,(bitcoin-lisp.serialization:block-header-bits header))
      ("nonce" . ,(bitcoin-lisp.serialization:block-header-nonce header))
      ("nTx" . ,(length txs))
      ("tx" . ,(if include-tx-details
                   (mapcar (lambda (tx) (tx-to-json tx network)) txs)
                   (mapcar #'tx-to-txid txs))))))

(defun tx-to-txid (tx)
  "Get transaction ID as hex string."
  (hash-to-hex (bitcoin-lisp.serialization:transaction-hash tx)))

(defun %tx-wire-bytes (tx)
  "TX in its wire encoding (witness form when it has witness data), for the
size/hex fields. Mirrors the mempool's tx-wire-bytes."
  (if (bitcoin-lisp.serialization:transaction-has-witness-p tx)
      (bitcoin-lisp.serialization:serialize-witness-transaction tx)
      (bitcoin-lisp.serialization:serialize-transaction tx)))

(defun %script-type (script)
  "Bitcoin Core scriptPubKey 'type' name for a standard SCRIPT, else
\"nonstandard\"."
  (let ((len (length script)))
    (flet ((b (i) (aref script i)))
      (cond
        ((and (= len 25) (= (b 0) #x76) (= (b 1) #xa9) (= (b 2) #x14)
              (= (b 23) #x88) (= (b 24) #xac)) "pubkeyhash")
        ((and (= len 23) (= (b 0) #xa9) (= (b 1) #x14) (= (b 22) #x87)) "scripthash")
        ((and (= len 22) (= (b 0) #x00) (= (b 1) #x14)) "witness_v0_keyhash")
        ((and (= len 34) (= (b 0) #x00) (= (b 1) #x20)) "witness_v0_scripthash")
        ((and (= len 34) (= (b 0) #x51) (= (b 1) #x20)) "witness_v1_taproot")
        ((and (>= len 1) (= (b 0) #x6a)) "nulldata")
        ((and (or (= len 35) (= len 67)) (= (b (1- len)) #xac)) "pubkey")
        (t "nonstandard")))))

(defun %tx-input-witness (tx index)
  "The witness stack (vector of byte vectors) for input INDEX of TX, or NIL."
  (let ((w (bitcoin-lisp.serialization:transaction-witness tx)))
    (when (and w (< index (length w)))
      (elt w index))))

(defun tx-to-json (tx &optional network)
  "Convert transaction to JSON. When NETWORK is supplied, output addresses are
derived. Includes the size/weight/hex fields explorers and fee tools expect."
  (let ((inputs (bitcoin-lisp.serialization:transaction-inputs tx))
        (outputs (bitcoin-lisp.serialization:transaction-outputs tx))
        (wire (%tx-wire-bytes tx)))
    `(("txid" . ,(tx-to-txid tx))
      ("hash" . ,(hash-to-hex (bitcoin-lisp.serialization:transaction-wtxid tx)))
      ("version" . ,(bitcoin-lisp.serialization:transaction-version tx))
      ("size" . ,(length wire))
      ("vsize" . ,(bitcoin-lisp.serialization:transaction-vsize tx))
      ("weight" . ,(bitcoin-lisp.serialization:transaction-weight tx))
      ("locktime" . ,(bitcoin-lisp.serialization:transaction-lock-time tx))
      ("vin" . ,(loop for input across inputs
                      for i from 0
                      collect (input-to-json input (%tx-input-witness tx i))))
      ("vout" . ,(loop for out across outputs
                       for i from 0
                       collect (output-to-json out i network)))
      ("hex" . ,(bitcoin-lisp.crypto:bytes-to-hex wire)))))

(defun input-to-json (input &optional witness-stack)
  "Convert transaction input to JSON, including sequence and (when present) the
witness stack; coinbase inputs emit a coinbase field instead of txid/vout."
  (let ((base
          (if (bitcoin-lisp.serialization:coinbase-input-p input)
              `(("coinbase" . ,(bitcoin-lisp.crypto:bytes-to-hex
                                (bitcoin-lisp.serialization:tx-in-script-sig input))))
              (let ((outpoint (bitcoin-lisp.serialization:tx-in-previous-output input)))
                `(("txid" . ,(hash-to-hex (bitcoin-lisp.serialization:outpoint-hash outpoint)))
                  ("vout" . ,(bitcoin-lisp.serialization:outpoint-index outpoint))
                  ("scriptSig" . (("hex" . ,(bitcoin-lisp.crypto:bytes-to-hex
                                             (bitcoin-lisp.serialization:tx-in-script-sig input))))))))))
    (when (and witness-stack (plusp (length witness-stack)))
      (setf base (append base
                         `(("txinwitness"
                            . ,(map 'list #'bitcoin-lisp.crypto:bytes-to-hex witness-stack))))))
    (append base `(("sequence" . ,(bitcoin-lisp.serialization:tx-in-sequence input))))))

(defun output-to-json (output index &optional network)
  "Convert transaction output to JSON, with scriptPubKey type and (when NETWORK
is supplied and the script is addressable) address."
  (let* ((spk (bitcoin-lisp.serialization:tx-out-script-pubkey output))
         (addr (and network (%script->address spk network)))
         (spk-json `(("hex" . ,(bitcoin-lisp.crypto:bytes-to-hex spk))
                     ("type" . ,(%script-type spk)))))
    (when addr
      (setf spk-json (append spk-json `(("address" . ,addr)))))
    `(("value" . ,(/ (bitcoin-lisp.serialization:tx-out-value output) 100000000.0d0))
      ("n" . ,index)
      ("scriptPubKey" . ,spk-json))))

(defun rpc-getblockheader (node params)
  "Return block header data."
  (let ((hash-str (first params))
        (verbose (if (>= (length params) 2) (second params) t)))
    (unless (valid-hex-hash-p hash-str)
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "Invalid block hash"))
    (let* ((hash-bytes (parse-hex-hash hash-str))
           (chain-state (rpc-get-chain-state node))
           (entry (bitcoin-lisp.storage:get-block-index-entry chain-state hash-bytes)))
      (unless entry
        (error 'rpc-error :code +rpc-misc-error+
                          :message "Block not found"))
      (if verbose
          (block-header-entry-to-json entry hash-str)
          ;; Non-verbose: return serialized header as hex
          (let ((block-store (rpc-get-block-store node)))
            (let ((block (bitcoin-lisp.storage:get-block block-store hash-bytes)))
              (if block
                  (bitcoin-lisp.crypto:bytes-to-hex
                   (bitcoin-lisp.serialization:serialize
                    (bitcoin-lisp.serialization:bitcoin-block-header block)))
                  (error 'rpc-error :code +rpc-misc-error+
                                    :message "Block data not found"))))))))

(defun block-header-entry-to-json (entry hash-str)
  "Convert block index entry to header JSON."
  (let ((header (bitcoin-lisp.storage:block-index-entry-header entry)))
    `(("hash" . ,hash-str)
      ("height" . ,(bitcoin-lisp.storage:block-index-entry-height entry))
      ("version" . ,(bitcoin-lisp.serialization:block-header-version header))
      ("previousblockhash" . ,(hash-to-hex (bitcoin-lisp.serialization:block-header-prev-block header)))
      ("merkleroot" . ,(hash-to-hex (bitcoin-lisp.serialization:block-header-merkle-root header)))
      ("time" . ,(bitcoin-lisp.serialization:block-header-timestamp header))
      ("bits" . ,(format nil "~8,'0x" (bitcoin-lisp.serialization:block-header-bits header)))
      ("nonce" . ,(bitcoin-lisp.serialization:block-header-nonce header))
      ("confirmations" . 1))))

(defun chaintip-status (entry on-active best-hash hash block-store)
  "Bitcoin Core getchaintips status for a tip ENTRY."
  (cond
    ((and on-active (equalp hash best-hash)) "active")
    (t (case (bitcoin-lisp.storage:block-index-entry-status entry)
         (:valid "valid-fork")
         (:invalid "invalid")
         (t (if (bitcoin-lisp.storage:get-block block-store hash)
                "valid-headers"
                "headers-only"))))))

(defun rpc-getchaintips (node params)
  "Return information about all known chain tips (active and side branches)."
  (declare (ignore params))
  (let* ((chain-state (rpc-get-chain-state node))
         (block-store (rpc-get-block-store node))
         (index (bitcoin-lisp.storage::chain-state-block-index chain-state))
         (best-hash (bitcoin-lisp.storage:best-block-hash chain-state))
         (has-child (make-hash-table :test 'equalp))
         (active (make-hash-table :test 'equalp))
         (tips '()))
    ;; Any block referenced as a parent has a child, so it is not a tip.
    (maphash (lambda (h entry)
               (declare (ignore h))
               (let ((prev (bitcoin-lisp.storage:block-index-entry-prev-entry entry)))
                 (when prev
                   (setf (gethash (bitcoin-lisp.storage:block-index-entry-hash prev)
                                  has-child)
                         t))))
             index)
    ;; Active-chain hash set (tip back to genesis) for O(1) membership tests.
    (loop for e = (and best-hash
                       (bitcoin-lisp.storage:get-block-index-entry chain-state best-hash))
            then (bitcoin-lisp.storage:block-index-entry-prev-entry e)
          while e
          do (setf (gethash (bitcoin-lisp.storage:block-index-entry-hash e) active) t))
    (maphash
     (lambda (h entry)
       (unless (gethash h has-child)
         (let ((on-active (gethash h active))
               (branchlen 0))
           ;; branchlen = blocks from this tip back to the active chain.
           (unless on-active
             (loop for e = entry
                     then (bitcoin-lisp.storage:block-index-entry-prev-entry e)
                   while (and e (not (gethash (bitcoin-lisp.storage:block-index-entry-hash e)
                                              active)))
                   do (incf branchlen)))
           (push `(("height" . ,(bitcoin-lisp.storage:block-index-entry-height entry))
                   ("hash" . ,(hash-to-hex h))
                   ("branchlen" . ,branchlen)
                   ("status" . ,(chaintip-status entry on-active best-hash h block-store)))
                 tips))))
     index)
    ;; Active tip first, then by descending height. A numeric sort key keeps
    ;; this a total order (the active tip gets the maximum key).
    (stable-sort tips #'>
                 :key (lambda (tip)
                        (if (string= (cdr (assoc "status" tip :test #'string=)) "active")
                            most-positive-fixnum
                            (cdr (assoc "height" tip :test #'string=)))))))

;;; --- UTXO Query Methods ---

(defun rpc-gettxout (node params)
  "Return UTXO info for given outpoint."
  (let ((txid-str (first params))
        (vout (second params)))
    (unless (valid-hex-hash-p txid-str)
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "Invalid txid"))
    (unless (and (integerp vout) (>= vout 0))
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "Invalid vout"))
    (let* ((txid-bytes (parse-hex-hash txid-str))
           (utxo-set (rpc-get-utxo-set node))
           (entry (bitcoin-lisp.storage:get-utxo utxo-set txid-bytes vout)))
      (if entry
          (let* ((chain-state (rpc-get-chain-state node))
                 (best-hash (bitcoin-lisp.storage:best-block-hash chain-state))
                 (height (bitcoin-lisp.storage:current-height chain-state))
                 (utxo-height (bitcoin-lisp.storage:utxo-entry-height entry)))
            `(("bestblock" . ,(if best-hash (hash-to-hex best-hash) ""))
              ("confirmations" . ,(1+ (- height utxo-height)))
              ("value" . ,(/ (bitcoin-lisp.storage:utxo-entry-value entry) 100000000.0d0))
              ("scriptPubKey" . (("hex" . ,(bitcoin-lisp.crypto:bytes-to-hex
                                            (bitcoin-lisp.storage:utxo-entry-script-pubkey entry)))))
              ("coinbase" . ,(bitcoin-lisp.storage:utxo-entry-coinbase entry))))
          nil)))) ; Return null for spent outputs

;;; --- Network Query Methods ---

(defun rpc-getpeerinfo (node params)
  "Return information about connected peers."
  (declare (ignore params))
  (let ((peers (rpc-get-peers node)))
    (mapcar (lambda (peer)
              ;; peer-version holds the received version *message* struct, not a
              ;; number — pull the numeric protocol version out of it.
              (let ((vmsg (bitcoin-lisp::peer-version peer)))
                `(("addr" . ,(bitcoin-lisp::peer-address peer))
                  ("version" . ,(if vmsg
                                    (bitcoin-lisp.serialization:version-message-version vmsg)
                                    0))
                  ("subver" . ,(or (bitcoin-lisp::peer-user-agent peer) ""))
                  ("services" . ,(bitcoin-lisp::peer-services peer))
                  ("inbound" . nil)
                  ("startingheight" . ,(or (bitcoin-lisp::peer-start-height peer) 0)))))
            peers)))

(defun rpc-getnetworkinfo (node params)
  "Return network state information."
  (declare (ignore params))
  (let ((network (rpc-get-network node))
        (peers (rpc-get-peers node)))
    `(("version" . 10000)
      ("subversion" . "/bitcoin-lisp:0.1.0/")
      ("protocolversion" . 70016)
      ("connections" . ,(length peers))
      ("networks" . ((("name" . ,(case network
                                   (:testnet3 "testnet")
                                   (:testnet4 "testnet4")
                                   (:signet "signet")
                                   (:regtest "regtest")
                                   (:mainnet "mainnet")
                                   (t "unknown")))
                      ("reachable" . t))))
      ("networkactive" . t))))

(defun rpc-getconnectioncount (node params)
  "Return the number of connected peers."
  (declare (ignore params))
  (length (rpc-get-peers node)))

;;; --- Mempool Methods ---

(defun rpc-getmempoolinfo (node params)
  "Return mempool statistics."
  (declare (ignore params))
  (let ((mempool (rpc-get-mempool node)))
    (if mempool
        ;; Convert sat/vB to BTC/kvB: sat/vB * 1000 / 100000000
        (let* ((min-fee-sat-vb (bitcoin-lisp.mempool:mempool-effective-min-fee-rate mempool))
               (min-fee-btc-kvb (/ (* min-fee-sat-vb 1000) 100000000.0d0))
               (relay-fee-btc-kvb (/ (* bitcoin-lisp.mempool:+default-min-relay-fee-rate+ 1000) 100000000.0d0)))
          `(("loaded" . t)
            ("size" . ,(bitcoin-lisp.mempool:mempool-count mempool))
            ("bytes" . ,(bitcoin-lisp.mempool:mempool-total-size mempool))
            ("usage" . 0)
            ("mempoolminfee" . ,min-fee-btc-kvb)
            ("minrelaytxfee" . ,relay-fee-btc-kvb)))
        `(("loaded" . nil)
          ("size" . 0)
          ("bytes" . 0)
          ("usage" . 0)
          ("mempoolminfee" . 0.00001)
          ("minrelaytxfee" . 0.00001)))))

(defun rpc-getrawmempool (node params)
  "Return mempool transaction IDs (verbose nil) or per-tx details (verbose t)."
  (let ((verbose (first params))
        (mempool (rpc-get-mempool node)))
    (cond
      ((null mempool) (if verbose '() '()))
      ((not verbose)
       (let ((ids '()))
         (bitcoin-lisp.mempool:mempool-for-each
          mempool (lambda (txid entry)
                    (declare (ignore entry))
                    (push (hash-to-hex txid) ids)))
         (nreverse ids)))
      (t
       ;; Verbose: an alist (txid -> field-alist); the RPC normalizer turns it
       ;; into nested JSON objects.
       (let ((result '()))
         (bitcoin-lisp.mempool:mempool-for-each
          mempool
          (lambda (txid entry)
            (push (cons (hash-to-hex txid) (%mempool-entry-fields mempool txid entry))
                  result)))
         result)))))

(defun %mempool-entry-fields (mempool txid entry)
  "The verbose field alist for one mempool ENTRY (TXID) — vsize/weight/time/
height/fees{base,ancestor,descendant}/ancestor+descendant counts/wtxid/depends.
Shared by getrawmempool (verbose), getmempoolentry, getmempoolancestors, and
getmempooldescendants."
  (multiple-value-bind (acount asize afees)
      (bitcoin-lisp.mempool:mempool-ancestor-stats mempool txid)
    (multiple-value-bind (dcount dsize dfees)
        (bitcoin-lisp.mempool:mempool-descendant-stats mempool txid)
      `(("vsize" . ,(bitcoin-lisp.mempool:mempool-entry-vsize entry))
        ("weight" . ,(bitcoin-lisp.serialization:transaction-weight
                      (bitcoin-lisp.mempool:mempool-entry-transaction entry)))
        ("time" . ,(bitcoin-lisp.mempool:mempool-entry-entry-time entry))
        ("height" . ,(bitcoin-lisp.mempool:mempool-entry-height entry))
        ("fees" . (("base" . ,(/ (bitcoin-lisp.mempool:mempool-entry-fee entry) 100000000.0d0))
                   ("modified" . ,(/ (bitcoin-lisp.mempool:mempool-entry-modified-fee entry)
                                     100000000.0d0))
                   ("ancestor" . ,(/ afees 100000000.0d0))
                   ("descendant" . ,(/ dfees 100000000.0d0))))
        ("ancestorcount" . ,acount)
        ("ancestorsize" . ,asize)
        ("descendantcount" . ,dcount)
        ("descendantsize" . ,dsize)
        ("wtxid" . ,(hash-to-hex (bitcoin-lisp.mempool:mempool-entry-wtxid entry)))
        ("depends" . ,(let ((deps '()))
                        (maphash (lambda (p v) (declare (ignore v))
                                   (push (hash-to-hex p) deps))
                                 (bitcoin-lisp.mempool:mempool-entry-parents entry))
                        deps))))))

(defun %mempool-txid-arg (params mempool)
  "Resolve the first param (a big-endian txid hex) to (values internal-txid
entry), erroring if malformed or not in the mempool."
  (let ((txid-hex (first params)))
    (unless (stringp txid-hex)
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "txid must be a hex string"))
    (let ((txid (parse-hex-hash txid-hex)))
      (unless txid
        (error 'rpc-error :code +rpc-invalid-parameter+ :message "Invalid txid"))
      (let ((entry (and mempool (bitcoin-lisp.mempool:mempool-get mempool txid))))
        (unless entry
          (error 'rpc-error :code +rpc-misc-error+ :message "Transaction not in mempool"))
        (values txid entry)))))

(defun rpc-getmempoolentry (node params)
  "Return mempool details for transaction TXID (Bitcoin Core getmempoolentry)."
  (let ((mempool (rpc-get-mempool node)))
    (multiple-value-bind (txid entry) (%mempool-txid-arg params mempool)
      (%mempool-entry-fields mempool txid entry))))

(defun %mempool-set->result (mempool txid-set verbose)
  "Format a hash-set of mempool txids as either an array of (big-endian) txid hex
strings or, when VERBOSE, an alist of txid-hex -> entry fields."
  (let ((result '()))
    (maphash (lambda (txid v) (declare (ignore v))
               (let ((entry (bitcoin-lisp.mempool:mempool-get mempool txid)))
                 (when entry
                   (push (if verbose
                             (cons (hash-to-hex txid) (%mempool-entry-fields mempool txid entry))
                             (hash-to-hex txid))
                         result))))
             txid-set)
    result))

(defun rpc-getmempoolancestors (node params)
  "Return the in-mempool ancestors of TXID (Bitcoin Core getmempoolancestors).
PARAMS: (txid [verbose]). Array of txids, or txid->details when verbose."
  (let ((mempool (rpc-get-mempool node))
        (verbose (second params)))
    (multiple-value-bind (txid entry) (%mempool-txid-arg params mempool)
      (declare (ignore entry))
      (%mempool-set->result mempool (bitcoin-lisp.mempool:mempool-ancestors mempool txid) verbose))))

(defun rpc-getmempooldescendants (node params)
  "Return the in-mempool descendants of TXID (Bitcoin Core getmempooldescendants).
PARAMS: (txid [verbose]). Array of txids, or txid->details when verbose."
  (let ((mempool (rpc-get-mempool node))
        (verbose (second params)))
    (multiple-value-bind (txid entry) (%mempool-txid-arg params mempool)
      (declare (ignore entry))
      (%mempool-set->result mempool (bitcoin-lisp.mempool:mempool-descendants mempool txid) verbose))))

(defun rpc-gettxspendingprevout (node params)
  "For each {txid, vout} outpoint in the array PARAM, report the mempool
transaction spending it, if any (Bitcoin Core gettxspendingprevout). Returns an
array of {txid, vout, spendingtxid?}."
  (let ((outpoints (first params))
        (mempool (rpc-get-mempool node)))
    (unless (and (listp outpoints) outpoints)
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "First parameter must be a non-empty array of outpoints"))
    (mapcar
     (lambda (op)
       (let* ((txid-hex (and (hash-table-p op) (gethash "txid" op)))
              (vout (and (hash-table-p op) (gethash "vout" op)))
              (txid (and (stringp txid-hex) (parse-hex-hash txid-hex))))
         (unless (and txid (integerp vout))
           (error 'rpc-error :code +rpc-invalid-parameter+
                             :message "Each outpoint needs a txid (hex) and vout (integer)"))
         (let ((spender (and mempool (bitcoin-lisp.mempool:mempool-spending-tx mempool txid vout))))
           `(("txid" . ,txid-hex)
             ("vout" . ,vout)
             ,@(when spender `(("spendingtxid" . ,(hash-to-hex spender))))))))
     outpoints)))

(defun rpc-testmempoolaccept (node params)
  "Dry-run mempool acceptance for one or more raw transactions (hex). Returns an
array of {txid, wtxid, allowed, reject-reason?, vsize, fees{base}} without adding
anything to the mempool. Each tx is checked independently against current state
(package interdependence is not modeled — that needs submitpackage)."
  (let ((txs (first params))
        (utxo-set (rpc-get-utxo-set node))
        (mempool (rpc-get-mempool node))
        (chain-state (rpc-get-chain-state node)))
    (unless (listp txs)
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "First parameter must be an array of tx hex"))
    (let ((height (bitcoin-lisp.storage:current-height chain-state))
          (results '()))
      (dolist (hex-str txs (nreverse results))
        (push
         (handler-case
             (let* ((tx-bytes (bitcoin-lisp.crypto:hex-to-bytes hex-str))
                    (tx (flexi-streams:with-input-from-sequence (stream tx-bytes)
                          (bitcoin-lisp.serialization:read-transaction stream)))
                    (txid (bitcoin-lisp.serialization:transaction-hash tx)))
               (multiple-value-bind (valid error fee)
                   (bitcoin-lisp.validation:validate-transaction-for-mempool
                    tx utxo-set mempool height :chain-state chain-state)
                 (if valid
                     `(("txid" . ,(hash-to-hex txid))
                       ("wtxid" . ,(hash-to-hex (bitcoin-lisp.serialization:transaction-wtxid tx)))
                       ("allowed" . t)
                       ("vsize" . ,(bitcoin-lisp.serialization:transaction-vsize tx))
                       ("fees" . (("base" . ,(/ (or fee 0) 100000000.0d0)))))
                     `(("txid" . ,(hash-to-hex txid))
                       ("wtxid" . ,(hash-to-hex (bitcoin-lisp.serialization:transaction-wtxid tx)))
                       ("allowed" . nil)
                       ("reject-reason" . ,(string-downcase (symbol-name error)))))))
           (error (e)
             `(("allowed" . nil)
               ("reject-reason" . ,(format nil "decode-failed: ~A" e)))))
         results)))))

(defun rpc-sendrawtransaction (node params)
  "Submit a raw transaction to the mempool."
  (let ((hex-str (first params)))
    (unless (and (stringp hex-str) (> (length hex-str) 0))
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "Invalid transaction hex"))
    (handler-case
        (let* ((tx-bytes (bitcoin-lisp.crypto:hex-to-bytes hex-str))
               (tx (flexi-streams:with-input-from-sequence (stream tx-bytes)
                     (bitcoin-lisp.serialization:read-transaction stream)))
               (txid (bitcoin-lisp.serialization:transaction-hash tx))
               (utxo-set (rpc-get-utxo-set node))
               (mempool (rpc-get-mempool node))
               (chain-state (rpc-get-chain-state node))
               (current-height (bitcoin-lisp.storage:current-height chain-state)))
          ;; Validate transaction for mempool
          (multiple-value-bind (valid error fee replaced)
              (bitcoin-lisp.validation:validate-transaction-for-mempool
               tx utxo-set mempool current-height :chain-state chain-state)
            (unless valid
              (error 'rpc-error :code +rpc-misc-error+
                                :message (format nil "Transaction rejected: ~A" error)))
            (let ((add-result (bitcoin-lisp.mempool:accept-validated-tx
                               mempool txid tx fee current-height
                               :replaced replaced)))
              (unless (eq add-result :ok)
                (error 'rpc-error :code +rpc-misc-error+
                                  :message (format nil "Mempool rejection: ~A" add-result)))
              (hash-to-hex txid))))
      (error (e)
        (error 'rpc-error :code +rpc-misc-error+
                          :message (format nil "TX decode failed: ~A" e))))))

(defun %package-tx-result-fields (r)
  "Field alist for one package-tx-result, mirroring Bitcoin Core submitpackage's
per-wtxid object. Status drives which fields are present."
  (let ((status (bitcoin-lisp.validation:package-tx-result-status r))
        (base (list (cons "txid" (hash-to-hex
                                  (bitcoin-lisp.validation:package-tx-result-txid r))))))
    (flet ((btc (sat) (/ (or sat 0) 100000000.0d0))
           ;; sat/vB -> BTC/kvB, the unit Core reports feerates in.
           (feerate-btc-kvb (rate) (/ (* (or rate 0) 1000) 100000000.0d0)))
      (ecase status
        (:valid
         (append base
                 `(("vsize" . ,(bitcoin-lisp.validation:package-tx-result-vsize r))
                   ("fees" . (("base" . ,(btc (bitcoin-lisp.validation:package-tx-result-fee r)))
                              ("effective-feerate"
                               . ,(feerate-btc-kvb
                                   (bitcoin-lisp.validation:package-tx-result-effective-feerate r)))
                              ("effective-includes"
                               . ,(mapcar #'hash-to-hex
                                          (bitcoin-lisp.validation:package-tx-result-effective-includes r))))))))
        (:mempool-entry
         (append base
                 `(("vsize" . ,(bitcoin-lisp.validation:package-tx-result-vsize r))
                   ("fees" . (("base" . ,(btc (bitcoin-lisp.validation:package-tx-result-fee r))))))))
        (:different-witness
         (append base
                 `(("other-wtxid"
                    . ,(let ((ow (bitcoin-lisp.validation:package-tx-result-other-wtxid r)))
                         (if ow (hash-to-hex ow) ""))))))
        ((:invalid :not-validated)
         (append base
                 `(("error" . ,(let ((e (bitcoin-lisp.validation:package-tx-result-error r)))
                                 (if e (string-downcase (symbol-name e)) "rejected"))))))))))

(defun rpc-submitpackage (node params)
  "Submit a package of raw transactions (a child with its unconfirmed parents)
to the mempool. PARAMS: (package-hex-array [maxfeerate] [maxburnamount]). The
array is topologically sorted with the child last. Mirrors Bitcoin Core's
submitpackage: returns {package_msg, tx-results{wtxid -> {...}},
replaced-transactions}. The maxfeerate/maxburnamount safety rails are accepted
for API compatibility but not enforced (matching sendrawtransaction here)."
  (let ((hexes (first params))
        (utxo-set (rpc-get-utxo-set node))
        (mempool (rpc-get-mempool node))
        (chain-state (rpc-get-chain-state node)))
    (unless (and (listp hexes) hexes)
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "First parameter must be a non-empty array of tx hex"))
    (when (> (length hexes) bitcoin-lisp.validation:+max-package-count+)
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "Array must contain between 1 and 25 transactions"))
    (unless mempool
      (error 'rpc-error :code +rpc-misc-error+ :message "Mempool unavailable"))
    ;; Decode every tx up front; a single decode failure aborts the whole call.
    (let ((package
            (handler-case
                (mapcar (lambda (hex)
                          (let ((bytes (bitcoin-lisp.crypto:hex-to-bytes hex)))
                            (flexi-streams:with-input-from-sequence (s bytes)
                              (bitcoin-lisp.serialization:read-transaction s))))
                        hexes)
              (error (e)
                (error 'rpc-error :code +rpc-misc-error+
                                  :message (format nil "TX decode failed: ~A" e))))))
      (multiple-value-bind (msg results replaced)
          (bitcoin-lisp.validation:validate-package-for-mempool
           package utxo-set mempool chain-state)
        `(("package_msg" . ,(if (eq msg :success) "success"
                                (string-downcase (symbol-name msg))))
          ("tx-results"
           . ,(mapcar (lambda (r)
                        (cons (hash-to-hex (bitcoin-lisp.validation:package-tx-result-wtxid r))
                              (%package-tx-result-fields r)))
                      results))
          ,@(when replaced
              `(("replaced-transactions" . ,(mapcar #'hash-to-hex replaced)))))))))

;;; --- Chain control RPCs ---

(defun %chain-control-block (node params op)
  "Shared driver for invalidateblock/reconsiderblock: resolve the blockhash param
and invoke OP (invalidate-block or reconsider-block) with the node's chain
context. Returns null on success; errors otherwise."
  (let ((hash-hex (first params)))
    (unless (stringp hash-hex)
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "blockhash must be a hex string"))
    (let ((hash (parse-hex-hash hash-hex)))
      (unless hash
        (error 'rpc-error :code +rpc-invalid-parameter+ :message "Invalid block hash"))
      (multiple-value-bind (ok reason)
          (funcall op
                   (rpc-get-chain-state node)
                   (rpc-get-block-store node)
                   (rpc-get-utxo-set node)
                   hash
                   :mempool (rpc-get-mempool node)
                   :tx-index (rpc-get-tx-index node))
        (unless ok
          (error 'rpc-error :code +rpc-misc-error+
                            :message (string-downcase (symbol-name reason))))
        nil))))

(defun rpc-invalidateblock (node params)
  "Mark a block (and its descendants) invalid and reorg the active chain away from
it (Bitcoin Core invalidateblock). PARAMS: (blockhash). Returns null."
  (%chain-control-block node params #'bitcoin-lisp.validation:invalidate-block))

(defun rpc-reconsiderblock (node params)
  "Clear a previously-invalidated block's status and reconsider the best chain
(Bitcoin Core reconsiderblock). PARAMS: (blockhash). Returns null."
  (%chain-control-block node params #'bitcoin-lisp.validation:reconsider-block))

(defun rpc-preciousblock (node params)
  "Treat a block as preferred over equal-work competitors, reorganizing to it
(Bitcoin Core preciousblock). PARAMS: (blockhash). Returns null."
  (%chain-control-block node params #'bitcoin-lisp.validation:precious-block))

;;; --- Peer / address RPCs ---

(defun rpc-getnodeaddresses (node params)
  "Return known peer addresses from the address book (Bitcoin Core
getnodeaddresses). PARAMS: ([count]) — max addresses (default 1; 0 = all)."
  (let* ((count (if (integerp (first params)) (first params) 1))
         (book (bitcoin-lisp::node-address-book node))
         ;; count=0 => all known addresses; count>0 => up to that many.
         (limited (and book (bitcoin-lisp.networking:address-book-get-addr
                             book :max (max count 0) :pct 100))))
    (mapcar
     (lambda (pa)
       `(("time" . ,(bitcoin-lisp.networking:peer-address-last-seen pa))
         ("services" . ,(bitcoin-lisp.networking:peer-address-services pa))
         ("address" . ,(bitcoin-lisp.networking:ip-bytes-to-string
                        (bitcoin-lisp.networking:peer-address-ip pa)))
         ("port" . ,(bitcoin-lisp.networking:peer-address-port pa))))
     limited)))

(defun rpc-disconnectnode (node params)
  "Disconnect a connected peer by ADDRESS (Bitcoin Core disconnectnode). Returns
null on success; errors if no connected peer has that address."
  (let ((address (first params)))
    (unless (stringp address)
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "address must be a string"))
    ;; Atomic against the sync thread's node-peers mutations: hold node-lock
    ;; across the find + disconnect so we don't act on a peer mid-removal.
    (bt:with-recursive-lock-held ((bitcoin-lisp::node-lock node))
      (let ((target (find address (bitcoin-lisp::node-peers node)
                          :key (lambda (p) (bitcoin-lisp::peer-address p)) :test #'string=)))
        (unless target
          (error 'rpc-error :code +rpc-misc-error+ :message "Node not found in connected peers"))
        (bitcoin-lisp.networking:disconnect-peer target)
        nil))))

;;; --- Manual ban management (Bitcoin Core setban/listbanned/clearbanned) ---
;;;
;;; The MANUAL ban list (*banned-peers*) is separate from the automatic,
;;; ephemeral discouragement filter (see record-misbehavior); these RPCs only
;;; touch manual bans. Addresses are matched exactly (no subnet/CIDR support).

(defun rpc-setban (node params)
  "Add or remove a manual ban (Bitcoin Core setban). PARAMS:
(address command [bantime] [absolute]). COMMAND is \"add\" or \"remove\". For add,
BANTIME is seconds from now (default 24h), or an absolute Unix time when ABSOLUTE
is true. Returns null."
  (declare (ignore node))
  (let ((address (first params))
        (command (second params))
        (bantime (third params))
        (absolute (fourth params)))
    (unless (and (stringp address) (plusp (length address)))
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "address required"))
    (cond
      ((equal command "add")
       (cond
         ((null bantime) (bitcoin-lisp.networking:ban-address address))
         ((not (integerp bantime))
          (error 'rpc-error :code +rpc-invalid-parameter+ :message "bantime must be an integer"))
         (absolute
          (bitcoin-lisp.networking:ban-address
           address (max 0 (- bantime (bitcoin-lisp.serialization:get-unix-time)))))
         (t (bitcoin-lisp.networking:ban-address address bantime)))
       nil)
      ((equal command "remove")
       (unless (bitcoin-lisp.networking:unban-address address)
         (error 'rpc-error :code +rpc-misc-error+
                           :message "Unban failed: address is not banned"))
       nil)
      (t (error 'rpc-error :code +rpc-invalid-parameter+
                           :message "command must be \"add\" or \"remove\"")))))

(defun rpc-listbanned (node params)
  "List active manual bans (Bitcoin Core listbanned)."
  (declare (ignore node params))
  (mapcar (lambda (ban)
            `(("address" . ,(car ban))
              ("banned_until" . ,(- (cdr ban)
                                    bitcoin-lisp.serialization:+universal-unix-epoch-offset+))))
          (bitcoin-lisp.networking:list-bans)))

(defun rpc-clearbanned (node params)
  "Clear all manual bans (Bitcoin Core clearbanned). Returns null."
  (declare (ignore node params))
  (bitcoin-lisp.networking:clear-ban-list)
  nil)

;;; --- Network totals (Bitcoin Core getnettotals) ---

(defun rpc-getnettotals (node params)
  "Cumulative network byte totals since startup (Bitcoin Core getnettotals)."
  (declare (ignore node params))
  `(("totalbytesrecv" . ,bitcoin-lisp.networking:*total-bytes-received*)
    ("totalbytessent" . ,bitcoin-lisp.networking:*total-bytes-sent*)
    ("timemillis" . ,(* (bitcoin-lisp.serialization:get-unix-time) 1000))
    ;; No upload limit is enforced; report the disabled-target shape Core uses.
    ("uploadtarget" . (("timeframe" . 86400)
                       ("target" . 0)
                       ("target_reached" . nil)
                       ("serve_historical_blocks" . t)
                       ("bytes_left_in_cycle" . 0)
                       ("time_left_in_cycle" . 0)))))

;;; --- Chain verification (Bitcoin Core verifychain) ---

(defun rpc-verifychain (node params)
  "Re-verify the last NBLOCKS blocks from the block store (Bitcoin Core
verifychain). PARAMS: ([checklevel] [nblocks]). At checklevel >= 1 each block is
re-read and its merkle root + proof-of-work re-checked; level 0 only confirms the
block reads back. Returns T if all checks pass, NIL otherwise."
  (let* ((checklevel (if (integerp (first params)) (first params) 3))
         (nblocks (if (integerp (second params)) (second params) 6))
         (chain-state (rpc-get-chain-state node))
         (block-store (rpc-get-block-store node))
         (tip (bitcoin-lisp.storage:current-height chain-state)))
    (when (or (<= nblocks 0) (> nblocks (1+ tip)))
      (setf nblocks (1+ tip)))
    (loop for height from tip downto (max 0 (- tip (1- nblocks)))
          do (let ((entry (bitcoin-lisp.storage:get-block-at-height chain-state height)))
               (unless entry (return-from rpc-verifychain nil))
               (let ((block (bitcoin-lisp.storage:get-block
                             block-store
                             (bitcoin-lisp.storage:block-index-entry-hash entry))))
                 (unless block (return-from rpc-verifychain nil))
                 (when (>= checklevel 1)
                   (let* ((header (bitcoin-lisp.serialization:bitcoin-block-header block))
                          (txids (mapcar #'bitcoin-lisp.serialization:transaction-hash
                                         (bitcoin-lisp.serialization:bitcoin-block-transactions block))))
                     (unless (and (equalp (bitcoin-lisp.validation:compute-merkle-root txids)
                                          (bitcoin-lisp.serialization:block-header-merkle-root header))
                                  (bitcoin-lisp.validation:check-proof-of-work header))
                       (return-from rpc-verifychain nil)))))))
    t))

;;; --- waitfornewblock / dumptxoutset (Bitcoin Core rpc/blockchain.cpp) ---

(defun rpc-waitfornewblock (node params)
  "Wait until the chain tip changes, then return it (Bitcoin Core
waitfornewblock). PARAMS: ([timeout-ms]) — 0 (the default) waits indefinitely.
Returns the current tip on change, timeout, or node shutdown. Polls the tip on
the RPC worker thread."
  (let ((timeout (if (integerp (first params)) (first params) 0)))
    (when (minusp timeout)
      (error 'rpc-error :code +rpc-misc-error+ :message "Negative timeout"))
    (let* ((chain-state (rpc-get-chain-state node))
           (start-hash (bitcoin-lisp.storage:best-block-hash chain-state))
           (deadline (when (plusp timeout)
                       (+ (get-internal-real-time)
                          (floor (* timeout internal-time-units-per-second) 1000)))))
      (loop while (and (bitcoin-lisp::node-running node)
                       (equalp (bitcoin-lisp.storage:best-block-hash chain-state)
                               start-hash)
                       (or (null deadline)
                           (< (get-internal-real-time) deadline)))
            do (sleep 0.25))
      (let ((hash (bitcoin-lisp.storage:best-block-hash chain-state)))
        `(("hash" . ,(if hash (hash-to-hex hash) ""))
          ("height" . ,(bitcoin-lisp.storage:current-height chain-state)))))))

(defun rpc-dumptxoutset (node params)
  "Write the full UTXO set to a snapshot file (Bitcoin Core dumptxoutset's
shape; the file uses our own versioned encoding, NOT Core's assumeutxo format —
loadtxoutset is unsupported). Streams entries in on-disk key order; like
gettxoutsetinfo this forces a coins-cache flush first. Errors if PATH exists.
(loadtxoutset reads this format back.)"
  (let ((path (first params)))
    (unless (and (stringp path) (plusp (length path)))
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "path required"))
    (when (probe-file path)
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message (format nil "~A already exists" path)))
    (let* ((chain-state (rpc-get-chain-state node))
           (utxo-set (rpc-get-utxo-set node))
           (base-hash (bitcoin-lisp.storage:best-block-hash chain-state))
           (base-height (bitcoin-lisp.storage:current-height chain-state))
           (count 0))
      (with-open-file (out path :direction :output :if-exists :error
                                :element-type '(unsigned-byte 8))
        ;; Header: magic + version + base hash + height + count (count is
        ;; back-patched after the streaming pass).
        (write-sequence (map '(vector (unsigned-byte 8)) #'char-code "UTXS") out)
        (bitcoin-lisp.serialization:write-uint32-le out 1)        ; format version
        (write-sequence (or base-hash (make-array 32 :element-type '(unsigned-byte 8)
                                                     :initial-element 0))
                        out)
        (bitcoin-lisp.serialization:write-uint32-le out base-height)
        (let ((count-pos (file-position out)))
          (bitcoin-lisp.serialization:write-uint32-le out 0)      ; placeholder
          (bitcoin-lisp.storage:utxo-set-iterate
           utxo-set
           (lambda (txid vout entry)
             (write-sequence txid out)
             (bitcoin-lisp.serialization:write-uint32-le out vout)
             (let ((v (bitcoin-lisp.storage::encode-coin-value entry)))
               (bitcoin-lisp.serialization:write-compact-size out (length v))
               (write-sequence v out))
             (incf count)))
          ;; Back-patch the entry count.
          (file-position out count-pos)
          (bitcoin-lisp.serialization:write-uint32-le out count)))
      `(("coins_written" . ,count)
        ("base_hash" . ,(if base-hash (hash-to-hex base-hash) ""))
        ("base_height" . ,base-height)
        ("path" . ,(namestring (truename path)))))))

(defun rpc-loadtxoutset (node params)
  "Load a dumptxoutset snapshot: bulk-populate the UTXO set and fast-forward
the chainstate tip to the snapshot's base. This TRUSTS the snapshot — it does
not re-validate the coins — so it is a bootstrap tool for our own dumps, NOT
Bitcoin Core's assumeutxo (no background validation, no commitment check).
PARAMS: (path). Preconditions: the snapshot's base block must already be a
known header at its recorded height (sync headers first), and the node must
be behind that height. Returns coins_loaded / base_hash / base_height."
  (let ((path (first params)))
    (unless (and (stringp path) (plusp (length path)))
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "path required"))
    (unless (probe-file path)
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message (format nil "~A not found" path)))
    (let* ((chain-state (rpc-get-chain-state node))
           (utxo-set (rpc-get-utxo-set node))
           (base-db (bitcoin-lisp.storage:coins-view-cache-base utxo-set)))
      (unless base-db
        (error 'rpc-error :code +rpc-misc-error+ :message "UTXO store has no LevelDB base"))
      (with-open-file (in path :direction :input :element-type '(unsigned-byte 8))
        (let ((magic (make-array 4 :element-type '(unsigned-byte 8))))
          (read-sequence magic in)
          (unless (equalp magic (map '(vector (unsigned-byte 8)) #'char-code "UTXS"))
            (error 'rpc-error :code +rpc-invalid-parameter+
                              :message "Not a UTXO snapshot (bad magic)")))
        (unless (= (bitcoin-lisp.serialization:read-uint32-le in) 1)
          (error 'rpc-error :code +rpc-invalid-parameter+
                            :message "Unsupported snapshot version"))
        (let* ((base-hash (let ((h (make-array 32 :element-type '(unsigned-byte 8))))
                            (read-sequence h in) h))
               (base-height (bitcoin-lisp.serialization:read-uint32-le in))
               (count (bitcoin-lisp.serialization:read-uint32-le in))
               (entry (bitcoin-lisp.storage:get-block-index-entry chain-state base-hash)))
          ;; Preconditions: structurally consistent + actually a fast-forward.
          (unless (and entry
                       (= (bitcoin-lisp.storage:block-index-entry-height entry) base-height))
            (error 'rpc-error :code +rpc-invalid-address-or-key+
                              :message "Snapshot base block not in the header index at its height; sync headers first"))
          (when (>= (bitcoin-lisp.storage:current-height chain-state) base-height)
            (error 'rpc-error :code +rpc-invalid-parameter+
                              :message "Node is already at or past the snapshot height"))
          ;; Flush any cached coins so the bulk load writes onto a clean base.
          (bitcoin-lisp.storage:coins-view-cache-flush utxo-set)
          ;; Stream coins in chunked write-batches to bound memory (the
          ;; mainnet dump is ~24M entries).
          (let ((loaded 0) (chunk 100000))
            (loop while (< loaded count)
                  do (bitcoin-lisp.storage:with-coins-view-batch (batch base-db)
                       (loop repeat chunk
                             while (< loaded count)
                             do (let* ((txid (let ((tx (make-array 32 :element-type '(unsigned-byte 8))))
                                               (read-sequence tx in) tx))
                                       (vout (bitcoin-lisp.serialization:read-uint32-le in))
                                       (vlen (bitcoin-lisp.serialization:read-compact-size in))
                                       (vbytes (bitcoin-lisp.serialization:read-bytes in vlen)))
                                  (bitcoin-lisp.storage:coins-view-batch-put
                                   batch
                                   (bitcoin-lisp.storage::make-utxo-key txid vout)
                                   (bitcoin-lisp.storage::decode-coin-value vbytes))
                                  (incf loaded)))))
            ;; Fast-forward the tip to the snapshot base.
            (bitcoin-lisp.storage:update-chain-tip chain-state base-hash base-height)
            (bitcoin-lisp::node-log :info "RPC loadtxoutset: loaded ~D coins, tip -> h=~D" loaded base-height)
            `(("coins_loaded" . ,loaded)
              ("base_hash" . ,(hash-to-hex base-hash))
              ("base_height" . ,base-height)
              ("tip_height" . ,(bitcoin-lisp.storage:current-height chain-state)))))))))

;;; --- Mempool persistence (Bitcoin Core savemempool) ---

(defun rpc-savemempool (node params)
  "Dump the mempool to disk (Bitcoin Core savemempool). Returns the filename.
The same dump runs automatically on graceful shutdown."
  (declare (ignore params))
  (let ((path (bitcoin-lisp.mempool:mempool-dat-path
               (bitcoin-lisp::node-data-directory node))))
    (unless path
      (error 'rpc-error :code +rpc-misc-error+
                        :message "Node has no data directory"))
    (bitcoin-lisp.mempool:save-mempool-file (rpc-get-mempool node) path)
    `(("filename" . ,(namestring path)))))

;;; --- Transaction prioritisation (Bitcoin Core prioritisetransaction) ---

(defun rpc-prioritisetransaction (node params)
  "Adjust TXID's effective fee for mining selection by FEE-DELTA satoshis
(Bitcoin Core prioritisetransaction). PARAMS: (txid [dummy] fee-delta) —
dummy must be 0 or null (legacy priority is gone). The delta also counts for
mempool acceptance and RBF scoring; the fee is not actually paid. Returns T."
  (let* ((txid-hex (first params))
         (dummy (second params))
         (fee-delta (third params))
         (txid (and (stringp txid-hex) (parse-hex-hash txid-hex))))
    (unless txid
      (error 'rpc-error :code +rpc-invalid-address-or-key+
                        :message "Invalid txid"))
    (unless (or (null dummy) (and (numberp dummy) (zerop dummy)))
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "Priority is no longer supported, dummy argument to prioritisetransaction must be 0."))
    (unless (integerp fee-delta)
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "Invalid fee_delta"))
    (let* ((mempool (rpc-get-mempool node))
           (entry (bitcoin-lisp.mempool:mempool-get mempool txid)))
      ;; Core: dust-output txs can't enter with a nonzero delta, so refuse to
      ;; prioritise them after the fact too.
      (when entry
        (let ((tx (bitcoin-lisp.mempool:mempool-entry-transaction entry)))
          (loop for out across (bitcoin-lisp.serialization:transaction-outputs tx)
                do (when (< (bitcoin-lisp.serialization:tx-out-value out)
                            (bitcoin-lisp.validation::dust-threshold
                             (bitcoin-lisp.serialization:tx-out-script-pubkey out)))
                     (error 'rpc-error :code +rpc-invalid-parameter+
                                       :message "Priority is not supported for transactions with dust outputs.")))))
      (bitcoin-lisp.mempool:mempool-prioritise mempool txid fee-delta)
      t)))

(defun rpc-getprioritisedtransactions (node params)
  "Map of all prioritisetransaction fee deltas by txid (Bitcoin Core
getprioritisedtransactions): fee_delta, in_mempool, and modified_fee when the
tx is currently in the mempool."
  (declare (ignore params))
  (let ((mempool (rpc-get-mempool node))
        (result '()))
    (maphash
     (lambda (txid delta)
       (let ((entry (bitcoin-lisp.mempool:mempool-get mempool txid)))
         (push
          (cons (hash-to-hex txid)
                `(("fee_delta" . ,delta)
                  ("in_mempool" . ,(and entry t))
                  ,@(when entry
                      `(("modified_fee" . ,(bitcoin-lisp.mempool:mempool-entry-modified-fee entry))))))
          result)))
     (bitcoin-lisp.mempool:mempool-deltas mempool))
    (or result (make-hash-table :test 'equal))))

;;; --- UTXO set scanning (Bitcoin Core scantxoutset) ---

(defvar *txoutset-scan-lock* (bt:make-lock "txoutset-scan")
  "Guards the scan-reservation state below (Core's CoinsViewScanReserver).")
(defvar *txoutset-scan-running* nil)
(defvar *txoutset-scan-progress* 0)
(defvar *txoutset-scan-abort* nil)

(defun %reserve-txoutset-scan ()
  "Reserve the single scan slot. Returns T if reserved, NIL if a scan is
already running."
  (bt:with-lock-held (*txoutset-scan-lock*)
    (if *txoutset-scan-running*
        nil
        (setf *txoutset-scan-abort* nil
              *txoutset-scan-progress* 0
              *txoutset-scan-running* t))))

(defun %release-txoutset-scan ()
  (bt:with-lock-held (*txoutset-scan-lock*)
    (setf *txoutset-scan-running* nil)))

(defun %scanobject-descriptor (scanobject)
  "The descriptor string of a scanobject: either a plain string or an
object {\"desc\": ..., [\"range\": ...]}. Ranged descriptors are not
supported (we have no derivable keys)."
  (cond
    ((stringp scanobject) scanobject)
    ((hash-table-p scanobject)
     (when (gethash "range" scanobject)
       (error 'rpc-error :code +rpc-invalid-parameter+
                         :message "Ranged descriptors are not supported"))
     (let ((desc (gethash "desc" scanobject)))
       (unless (stringp desc)
         (error 'rpc-error :code +rpc-invalid-parameter+
                           :message "Descriptor needs to be provided in scan object"))
       desc))
    (t (error 'rpc-error :code +rpc-invalid-parameter+
                         :message "Invalid scan object"))))

(defun rpc-scantxoutset (node params)
  "Scan the UTXO set for outputs matching descriptors (Bitcoin Core
scantxoutset). PARAMS: (action [scanobjects]) — action is \"start\",
\"status\" or \"abort\". Supports the descriptor subset documented in
descriptors.lisp (addr/raw/pk/pkh/wpkh/sh(wpkh)/combo/tr/rawtr). The scan
runs synchronously on the calling RPC thread; status/abort act from
another connection, mirroring Core."
  (let ((action (first params)))
    (cond
      ((equal action "status")
       (if (bt:with-lock-held (*txoutset-scan-lock*) *txoutset-scan-running*)
           `(("progress" . ,*txoutset-scan-progress*))
           nil))
      ((equal action "abort")
       (bt:with-lock-held (*txoutset-scan-lock*)
         (when *txoutset-scan-running*
           (setf *txoutset-scan-abort* t))))
      ((equal action "start")
       (let ((scanobjects (second params)))
         (unless (and scanobjects (listp scanobjects))
           (error 'rpc-error :code +rpc-misc-error+
                             :message "scanobjects argument is required for the start action"))
         (unless (%reserve-txoutset-scan)
           (error 'rpc-error :code +rpc-invalid-parameter+
                             :message "Scan already in progress, use action \"abort\" or \"status\""))
         (unwind-protect
              (let ((needles (make-hash-table :test 'equalp))
                    (network (rpc-get-network node)))
                ;; Expand every scanobject into needle scripts.
                (dolist (scanobject scanobjects)
                  (loop for (script . desc)
                          in (parse-output-descriptor
                              (%scanobject-descriptor scanobject) network)
                        do (setf (gethash script needles) desc)))
                (let* ((chain-state (rpc-get-chain-state node))
                       (utxo-set (rpc-get-utxo-set node))
                       (tip-height (bitcoin-lisp.storage:current-height chain-state))
                       (best-hash (bitcoin-lisp.storage:best-block-hash chain-state))
                       (count 0) (total-amount 0) (unspents '())
                       (height-hashes nil)
                       (aborted nil))
                  (flet ((blockhash-at (height)
                           ;; get-block-at-height walks tip->height, so per-match
                           ;; lookups would be O(matches * tip). One backward walk
                           ;; on first use builds the whole height->hex table.
                           (unless height-hashes
                             (setf height-hashes (make-hash-table))
                             (loop with e = (and best-hash
                                                 (bitcoin-lisp.storage:get-block-index-entry
                                                  chain-state best-hash))
                                   while e
                                   do (setf (gethash (bitcoin-lisp.storage:block-index-entry-height e)
                                                     height-hashes)
                                            (hash-to-hex
                                             (bitcoin-lisp.storage:block-index-entry-hash e)))
                                      (setf e (bitcoin-lisp.storage:block-index-entry-prev-entry e))))
                           (gethash height height-hashes)))
                  (block scan
                    (bitcoin-lisp.storage:utxo-set-iterate
                     utxo-set
                     (lambda (txid vout entry)
                       (when *txoutset-scan-abort*
                         (setf aborted t)
                         (return-from scan))
                       (incf count)
                       ;; Iteration is txid-lex-ordered (utxo-set-iterate's
                       ;; documented contract): the txid prefix is the scan
                       ;; position (Core's g_scan_progress).
                       (setf *txoutset-scan-progress*
                             (floor (* 100 (+ (* 256 (aref txid 0)) (aref txid 1)))
                                    65536))
                       (let ((desc (gethash
                                    (bitcoin-lisp.storage:utxo-entry-script-pubkey entry)
                                    needles)))
                         (when desc
                           (let ((height (bitcoin-lisp.storage:utxo-entry-height entry))
                                 (value (bitcoin-lisp.storage:utxo-entry-value entry)))
                             (incf total-amount value)
                             (push
                              `(("txid" . ,(hash-to-hex txid))
                                ("vout" . ,vout)
                                ("scriptPubKey"
                                 . ,(bitcoin-lisp.crypto:bytes-to-hex
                                     (bitcoin-lisp.storage:utxo-entry-script-pubkey entry)))
                                ("desc" . ,desc)
                                ("amount" . ,(/ value 100000000.0d0))
                                ("coinbase" . ,(bitcoin-lisp.storage:utxo-entry-coinbase entry))
                                ("height" . ,height)
                                ,@(let ((hex (blockhash-at height)))
                                    (when hex `(("blockhash" . ,hex))))
                                ("confirmations" . ,(1+ (- tip-height height))))
                              unspents))))))))
                  `(("success" . ,(not aborted))
                    ("txouts" . ,count)
                    ("height" . ,tip-height)
                    ("bestblock" . ,(if best-hash (hash-to-hex best-hash) ""))
                    ("unspents" . ,(nreverse unspents))
                    ("total_amount" . ,(/ total-amount 100000000.0d0)))))
           (%release-txoutset-scan))))
      (t
       (error 'rpc-error :code +rpc-invalid-parameter+
                         :message (format nil "Invalid action '~A'" action))))))

;;; --- Chain tx statistics (Bitcoin Core getchaintxstats) ---

(defun %entry-tx-count (entry block-store)
  "Per-block tx count for ENTRY, lazily backfilled by reading the block from
BLOCK-STORE when the index predates the v2 tx-count field. Returns NIL when
unknown (header-only entry whose block isn't readable, e.g. pruned)."
  (let ((n (bitcoin-lisp.storage:block-index-entry-tx-count entry)))
    (cond ((plusp n) n)
          ;; Genesis is never in the block store; it carries exactly its
          ;; coinbase (a v1-loaded index leaves its entry at 0).
          ((zerop (bitcoin-lisp.storage:block-index-entry-height entry))
           (setf (bitcoin-lisp.storage:block-index-entry-tx-count entry) 1))
          (t
           (let ((block (and block-store
                             (bitcoin-lisp.storage:get-block
                              block-store
                              (bitcoin-lisp.storage:block-index-entry-hash entry)))))
             (when block
               (setf (bitcoin-lisp.storage:block-index-entry-tx-count entry)
                     (length (bitcoin-lisp.serialization:bitcoin-block-transactions
                              block)))))))))

(defun rpc-getchaintxstats (node params)
  "Transaction count/rate statistics over a block window (Bitcoin Core
getchaintxstats). PARAMS: ([nblocks] [blockhash]) — the window is the NBLOCKS
blocks ending at BLOCKHASH (default one month of blocks ending at the tip); the
interval uses median-time-past, matching Core. txcount/window_tx_count are
omitted when a block in range is unreadable (mirrors Core's unknown nChainTx)."
  (let* ((chain-state (rpc-get-chain-state node))
         (block-store (rpc-get-block-store node))
         (final (if (stringp (second params))
                    (let ((e (bitcoin-lisp.storage:get-block-index-entry
                              chain-state (parse-hex-hash (second params)))))
                      (unless e
                        (error 'rpc-error :code +rpc-invalid-address-or-key+
                                          :message "Block not found"))
                      (unless (bitcoin-lisp.storage:entry-on-active-chain-p chain-state e)
                        (error 'rpc-error :code +rpc-invalid-parameter+
                                          :message "Block is not in main chain"))
                      e)
                    (bitcoin-lisp.storage:get-block-index-entry
                     chain-state (bitcoin-lisp.storage:best-block-hash chain-state)))))
    (unless final
      (error 'rpc-error :code +rpc-misc-error+ :message "Chain has no tip"))
    (let* ((final-height (bitcoin-lisp.storage:block-index-entry-height final))
           (blockcount
             (if (integerp (first params))
                 (let ((bc (first params)))
                   (when (or (minusp bc) (and (plusp bc) (>= bc final-height)))
                     (error 'rpc-error :code +rpc-invalid-parameter+
                                       :message "Invalid block count: should be between 0 and the block's height - 1"))
                   bc)
                 ;; Core default: one month of blocks (600s spacing) bounded by height.
                 (max 0 (min 4320 (1- final-height))))))
      ;; One backward walk from FINAL to genesis: total txcount, the window sum
      ;; over the first BLOCKCOUNT entries, and the window-start ancestor for
      ;; the MTP interval.
      (let ((txcount 0) (window-tx 0) (txcount-known t) (window-known t)
            (past nil) (entry final) (i 0))
        (loop while entry
              do (let ((n (%entry-tx-count entry block-store)))
                   (if n
                       (progn (incf txcount n)
                              (when (< i blockcount) (incf window-tx n)))
                       (progn (setf txcount-known nil)
                              (when (< i blockcount) (setf window-known nil)))))
                 (incf i)
                 (when (= i blockcount)
                   (setf past (bitcoin-lisp.storage:block-index-entry-prev-entry entry)))
                 (setf entry (bitcoin-lisp.storage:block-index-entry-prev-entry entry)))
        (let ((result
                `(("time" . ,(bitcoin-lisp.serialization:block-header-timestamp
                              (bitcoin-lisp.storage:block-index-entry-header final)))
                  ,@(when txcount-known `(("txcount" . ,txcount)))
                  ("window_final_block_hash"
                   . ,(hash-to-hex (bitcoin-lisp.storage:block-index-entry-hash final)))
                  ("window_final_block_height" . ,final-height)
                  ("window_block_count" . ,blockcount))))
          (when (and (plusp blockcount) past)
            (let ((interval (- (bitcoin-lisp.validation:compute-median-time-past
                                chain-state
                                (bitcoin-lisp.storage:block-index-entry-hash final))
                               (bitcoin-lisp.validation:compute-median-time-past
                                chain-state
                                (bitcoin-lisp.storage:block-index-entry-hash past)))))
              (setf result (append result `(("window_interval" . ,interval))))
              (when window-known
                (setf result (append result `(("window_tx_count" . ,window-tx))))
                (when (plusp interval)
                  (setf result
                        (append result
                                `(("txrate" . ,(/ (float window-tx) interval)))))))))
          result)))))

;;; --- Node / chain info RPCs ---

(defun rpc-getdifficulty (node params)
  "Return the proof-of-work difficulty of the current best block (Bitcoin Core
getdifficulty)."
  (declare (ignore params))
  (let* ((chain-state (rpc-get-chain-state node))
         (tip (bitcoin-lisp.storage:get-block-index-entry
               chain-state (bitcoin-lisp.storage:best-block-hash chain-state)))
         (bits (if (and tip (bitcoin-lisp.storage:block-index-entry-header tip))
                   (bitcoin-lisp.serialization:block-header-bits
                    (bitcoin-lisp.storage:block-index-entry-header tip))
                   #x1d00ffff)))
    (%difficulty-from-bits bits)))

(defun rpc-uptime (node params)
  "Seconds the node has been running (Bitcoin Core uptime)."
  (declare (ignore node params))
  (if bitcoin-lisp::*node-start-time*
      (max 0 (- (bitcoin-lisp.serialization:get-unix-time) bitcoin-lisp::*node-start-time*))
      0))

(defun rpc-getindexinfo (node params)
  "Report the status of optional indexes (Bitcoin Core getindexinfo). Currently
just txindex, when enabled."
  (declare (ignore params))
  (let ((tx-index (rpc-get-tx-index node))
        (height (bitcoin-lisp.storage:current-height (rpc-get-chain-state node))))
    (if (and tx-index (bitcoin-lisp.storage:tx-index-enabled tx-index))
        ;; The txindex is maintained inline as blocks connect, so it tracks the
        ;; tip: report synced at the current best height.
        `(("txindex" . (("synced" . t) ("best_block_height" . ,height))))
        ;; No active indexes -> empty JSON object.
        (make-hash-table :test 'equal))))

(defun %buried-deployment (active-height tip-height)
  "A buried-softfork deployment object: active once TIP-HEIGHT reaches
ACTIVE-HEIGHT."
  `(("type" . "buried")
    ("active" . ,(>= tip-height active-height))
    ("height" . ,active-height)))

(defun rpc-getdeploymentinfo (node params)
  "Report soft-fork deployment status at the tip (Bitcoin Core getdeploymentinfo).
Reports the buried deployments (bip34/bip66/bip65/csv/segwit/taproot) using this
node's per-network activation heights."
  (declare (ignore params))
  (let* ((chain-state (rpc-get-chain-state node))
         (network (bitcoin-lisp::node-network node))
         (height (bitcoin-lisp.storage:current-height chain-state))
         (best-hash (bitcoin-lisp.storage:best-block-hash chain-state)))
    `(("hash" . ,(if best-hash (hash-to-hex best-hash) ""))
      ("height" . ,height)
      ("deployments"
       . (("bip34" . ,(%buried-deployment (bitcoin-lisp.validation:get-bip34-activation-height network) height))
          ("bip66" . ,(%buried-deployment (bitcoin-lisp.validation:get-bip66-activation-height network) height))
          ("bip65" . ,(%buried-deployment (bitcoin-lisp.validation:get-bip65-activation-height network) height))
          ("csv" . ,(%buried-deployment (bitcoin-lisp.validation:get-csv-activation-height network) height))
          ("segwit" . ,(%buried-deployment (bitcoin-lisp.validation:get-segwit-activation-height network) height))
          ("taproot" . ,(%buried-deployment (bitcoin-lisp.validation:get-taproot-activation-height network) height)))))))

;;; --- Mining RPCs ---

(defun %bits-to-target-hex (bits)
  "The 256-bit target for BITS as 64 lowercase hex chars (Core hashTarget.GetHex)."
  (format nil "~(~64,'0x~)" (bitcoin-lisp.storage:bits-to-target bits)))

(defun %bits-hex (bits)
  "Compact BITS as 8 lowercase hex chars."
  (format nil "~(~8,'0x~)" bits))

(defun %difficulty-from-bits (bits)
  "Difficulty ratio relative to difficulty-1 (bits 0x1d00ffff), like Core's
GetDifficulty."
  (let ((cur (bitcoin-lisp.storage:bits-to-target bits))
        (one (bitcoin-lisp.storage:bits-to-target #x1d00ffff)))
    (if (zerop cur) 0d0 (/ (float one 1d0) (float cur 1d0)))))

(defun %chain-name (network)
  "Bitcoin Core GetChainTypeString for NETWORK."
  (ecase network
    (:mainnet "main")
    (:testnet3 "test")
    (:testnet4 "testnet4")
    (:signet "signet")
    (:regtest "regtest")))

(defun %gbt-transactions (template)
  "The getblocktemplate `transactions` array for TEMPLATE: one object per
selected tx with data/txid/hash/depends/fee/sigops/weight. `depends` holds the
1-based indices of the in-template txs each tx spends from."
  (let ((entries (bitcoin-lisp.mining:block-template-transactions template))
        (index-of (make-hash-table :test 'equalp)))
    ;; 1-based index of each selected txid (they are in parents-first order).
    (loop for e in entries
          for i from 1
          do (setf (gethash (bitcoin-lisp.serialization:transaction-hash
                             (bitcoin-lisp.mempool:mempool-entry-transaction e))
                            index-of)
                   i))
    (loop for e in entries
          for tx = (bitcoin-lisp.mempool:mempool-entry-transaction e)
          for depends = (let ((ds '()))
                          (bitcoin-lisp.serialization:dovector (in (bitcoin-lisp.serialization:transaction-inputs tx))
                            (let ((idx (gethash (bitcoin-lisp.serialization:outpoint-hash
                                                 (bitcoin-lisp.serialization:tx-in-previous-output in))
                                                index-of)))
                              (when idx (pushnew idx ds))))
                          (sort ds #'<))
          collect `(("data" . ,(bitcoin-lisp.crypto:bytes-to-hex
                                (bitcoin-lisp.serialization:serialize-witness-transaction tx)))
                    ("txid" . ,(hash-to-hex (bitcoin-lisp.serialization:transaction-hash tx)))
                    ("hash" . ,(hash-to-hex (bitcoin-lisp.serialization:transaction-wtxid tx)))
                    ("depends" . ,depends)
                    ("fee" . ,(bitcoin-lisp.mempool:mempool-entry-fee e))
                    ("sigops" . ,(bitcoin-lisp.mempool:mempool-entry-sigops e))
                    ("weight" . ,(bitcoin-lisp.serialization:transaction-weight tx))))))

(defun %gbt-rules (height)
  "Active versionbits soft-fork rule names for a block at HEIGHT, as Bitcoin
Core's getblocktemplate \"rules\" array. segwit carries the \"!\" prefix
(mandatory: a miner that doesn't understand it must not build the template),
mirroring Core. Without this array, segwit/taproot-aware miners reject the
template outright."
  (let ((net bitcoin-lisp:*network*) (rules '()))
    (when (>= height (bitcoin-lisp.validation:get-csv-activation-height net))
      (push "csv" rules))
    (when (>= height (bitcoin-lisp.validation:get-segwit-activation-height net))
      (push "!segwit" rules))
    (when (>= height (bitcoin-lisp.validation:get-taproot-activation-height net))
      (push "taproot" rules))
    (nreverse rules)))

(defun rpc-getblocktemplate (node params)
  "Return a block template assembled from the mempool (Bitcoin Core
getblocktemplate). The optional template-request object is accepted but only its
implicit default mode is supported (no longpoll / proposal). Fields mirror Core."
  (declare (ignore params))
  (let* ((chain-state (rpc-get-chain-state node))
         (mempool (rpc-get-mempool node))
         (template (bitcoin-lisp.mining:assemble-block-template chain-state mempool))
         (bits (bitcoin-lisp.mining:block-template-bits template)))
    `(("version" . ,(bitcoin-lisp.mining:block-template-version template))
      ("previousblockhash" . ,(hash-to-hex (bitcoin-lisp.mining:block-template-prev-hash template)))
      ("transactions" . ,(%gbt-transactions template))
      ("coinbaseaux" . ,(make-hash-table :test 'equal))
      ("coinbasevalue" . ,(bitcoin-lisp.mining:block-template-coinbase-value template))
      ("target" . ,(%bits-to-target-hex bits))
      ("mintime" . ,(bitcoin-lisp.mining:block-template-mintime template))
      ("mutable" . ("time" "transactions" "prevblock"))
      ("noncerange" . "00000000ffffffff")
      ("sigoplimit" . ,bitcoin-lisp.validation:+max-block-sigops-cost+)
      ("weightlimit" . ,bitcoin-lisp.validation:+max-block-weight+)
      ("curtime" . ,(bitcoin-lisp.mining:block-template-curtime template))
      ("bits" . ,(%bits-hex bits))
      ("height" . ,(bitcoin-lisp.mining:block-template-height template))
      ("default_witness_commitment"
       . ,(bitcoin-lisp.crypto:bytes-to-hex
           (bitcoin-lisp.mining:block-template-default-witness-commitment-script template)))
      ;; Active soft-fork rules + versionbits signaling state. No BIP9
      ;; deployment is currently pending on any of our networks, so
      ;; vbavailable is empty and vbrequired is 0.
      ("rules" . ,(%gbt-rules (bitcoin-lisp.mining:block-template-height template)))
      ("vbavailable" . ,(make-hash-table :test 'equal))
      ("vbrequired" . 0)
      ;; longpoll id: miners poll with this; we don't block on it, but emit a
      ;; tip-derived id so longpoll-aware miners are satisfied.
      ("longpollid" . ,(format nil "~A~D"
                               (hash-to-hex (bitcoin-lisp.mining:block-template-prev-hash template))
                               (bitcoin-lisp.mining:block-template-height template))))))

(defun rpc-getmininginfo (node params)
  "Return mining-related state (Bitcoin Core getmininginfo)."
  (declare (ignore params))
  (let* ((chain-state (rpc-get-chain-state node))
         (mempool (rpc-get-mempool node))
         (height (bitcoin-lisp.storage:current-height chain-state))
         (tip (bitcoin-lisp.storage:get-block-index-entry
               chain-state (bitcoin-lisp.storage:best-block-hash chain-state)))
         (bits (if tip
                   (bitcoin-lisp.serialization:block-header-bits
                    (bitcoin-lisp.storage:block-index-entry-header tip))
                   #x1d00ffff))
         ;; Report the last assembled template (Bitcoin Core m_last_block_*),
         ;; rather than re-assembling on every status call.
         (template bitcoin-lisp.mining:*last-block-template*))
    `(("blocks" . ,height)
      ("currentblockweight" . ,(if template (bitcoin-lisp.mining:block-template-total-weight template) 0))
      ("currentblocktx" . ,(if template (length (bitcoin-lisp.mining:block-template-transactions template)) 0))
      ("bits" . ,(%bits-hex bits))
      ("difficulty" . ,(%difficulty-from-bits bits))
      ("target" . ,(%bits-to-target-hex bits))
      ("pooledtx" . ,(if mempool (bitcoin-lisp.mempool:mempool-count mempool) 0))
      ("chain" . ,(%chain-name (bitcoin-lisp::node-network node)))
      ("warnings" . ""))))

(defun %activate-submitted-block (node block)
  "Validate+activate BLOCK through the consensus path. Returns the activate-block
(values ok reason)."
  (bitcoin-lisp.validation:activate-block
   block
   (rpc-get-chain-state node)
   (rpc-get-block-store node)
   (rpc-get-utxo-set node)
   :mempool (rpc-get-mempool node)
   :tx-index (rpc-get-tx-index node)))

(defun rpc-submitblock (node params)
  "Submit a mined block (Bitcoin Core submitblock). PARAMS: (block-hex). Returns
JSON null on acceptance, \"duplicate\" if already known, or a BIP22 reject reason
string. Routes through the same activate-block consensus path as network blocks."
  (let ((hex (first params)))
    (unless (and (stringp hex) (plusp (length hex)))
      (error 'rpc-error :code +rpc-misc-error+ :message "Block decode failed: empty"))
    (let ((block (handler-case
                     (let ((bytes (bitcoin-lisp.crypto:hex-to-bytes hex)))
                       (flexi-streams:with-input-from-sequence (s bytes)
                         (bitcoin-lisp.serialization:read-bitcoin-block s)))
                   (error (e)
                     (error 'rpc-error :code +rpc-misc-error+
                                       :message (format nil "Block decode failed: ~A" e)))))
          (chain-state (rpc-get-chain-state node)))
      (let ((hash (bitcoin-lisp.serialization:block-header-hash
                   (bitcoin-lisp.serialization:bitcoin-block-header block))))
        ;; Already in the block index → duplicate.
        (when (bitcoin-lisp.storage:get-block-index-entry chain-state hash)
          (return-from rpc-submitblock "duplicate"))
        (multiple-value-bind (ok reason) (%activate-submitted-block node block)
          (cond
            (ok nil)                        ; accepted → JSON null (BIP22 success)
            ;; A valid block stored on a weaker side chain is still accepted.
            ((eq reason :weaker-chain) nil)
            (t (string-downcase (symbol-name reason)))))))))

(defun rpc-generatetoaddress (node params)
  "Mine NBLOCKS blocks paying to ADDRESS and add them to the chain (Bitcoin Core
generatetoaddress; CPU mining, intended for regtest). PARAMS: (nblocks address
[maxtries]). Returns an array of the mined block hashes (hex)."
  (let ((nblocks (first params))
        (address (second params))
        (maxtries (or (third params) 1000000))
        (network (bitcoin-lisp::node-network node)))
    (unless (and (integerp nblocks) (plusp nblocks))
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "nblocks must be a positive integer"))
    (unless (stringp address)
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "address must be a string"))
    (multiple-value-bind (type script-pubkey) (bitcoin-lisp.crypto:decode-address address network)
      (declare (ignore type))
      (unless script-pubkey
        (error 'rpc-error :code +rpc-invalid-parameter+
                          :message (format nil "Invalid address for ~A" network)))
      (let ((chain-state (rpc-get-chain-state node))
            (mempool (rpc-get-mempool node))
            (hashes '()))
        (dotimes (i nblocks (nreverse hashes))
          (let ((block (bitcoin-lisp.mining:assemble-full-block
                        chain-state mempool :coinbase-script-pubkey script-pubkey)))
            (unless (bitcoin-lisp.mining:mine-block block :max-tries maxtries)
              (error 'rpc-error :code +rpc-misc-error+ :message "Failed to find a valid nonce"))
            (multiple-value-bind (ok reason) (%activate-submitted-block node block)
              (unless ok
                (error 'rpc-error :code +rpc-misc-error+
                                  :message (format nil "Mined block rejected: ~A" reason)))
              (push (hash-to-hex (bitcoin-lisp.serialization:block-header-hash
                                  (bitcoin-lisp.serialization:bitcoin-block-header block)))
                    hashes))))))))

;;; --- Extended RPC Methods ---

(defconstant +rpc-deserialization-error+ -22
  "RPC error code for deserialization/hex decode errors.")

(defconstant +rpc-invalid-address-or-key+ -5
  "RPC error code for invalid address or key.")

(defconstant +rpc-invalid-amount+ -3
  "RPC error code for invalid amount.")

(defun rpc-decoderawtransaction (node params)
  "Decode a raw transaction hex string to JSON."
  (let ((hex-str (first params)))
    (unless (and (stringp hex-str) (> (length hex-str) 0))
      (error 'rpc-error :code +rpc-deserialization-error+
                        :message "Invalid transaction hex"))
    (handler-case
        (let* ((tx-bytes (bitcoin-lisp.crypto:hex-to-bytes hex-str))
               (tx (flexi-streams:with-input-from-sequence (stream tx-bytes)
                     (bitcoin-lisp.serialization:read-transaction stream))))
          (tx-to-json tx (rpc-get-network node)))
      (error (e)
        (error 'rpc-error :code +rpc-deserialization-error+
                          :message (format nil "TX decode failed: ~A" e))))))

(defun rpc-getrawtransaction (node params)
  "Get raw transaction data by txid.
Searches mempool first, then txindex (if enabled), then blockhash hint."
  (let ((txid-str (first params))
        (verbose (second params))
        (blockhash-hint (third params)))
    (unless (valid-hex-hash-p txid-str)
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "Invalid transaction id"))
    (when (and blockhash-hint (not (valid-hex-hash-p blockhash-hint)))
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "Invalid blockhash"))
    (let* ((txid-bytes (parse-hex-hash txid-str))
           (mempool (rpc-get-mempool node))
           (mempool-entry (when mempool
                            (bitcoin-lisp.mempool:mempool-get mempool txid-bytes))))
      ;; Check mempool first
      (when mempool-entry
        (let ((tx (bitcoin-lisp.mempool:mempool-entry-transaction mempool-entry)))
          (return-from rpc-getrawtransaction
            (if verbose
                (tx-to-json tx (rpc-get-network node))
                (bitcoin-lisp.crypto:bytes-to-hex
                 (bitcoin-lisp.serialization:serialize tx))))))

      ;; Try blockhash hint if provided
      (when blockhash-hint
        (let* ((block-hash-bytes (parse-hex-hash blockhash-hint))
               (block-store (rpc-get-block-store node))
               (block (bitcoin-lisp.storage:get-block block-store block-hash-bytes)))
          (when block
            (let ((found-tx (find-tx-in-block block txid-bytes)))
              (when found-tx
                (return-from rpc-getrawtransaction
                  (if verbose
                      (tx-to-json-confirmed found-tx node block-hash-bytes)
                      (bitcoin-lisp.crypto:bytes-to-hex
                       (bitcoin-lisp.serialization:serialize found-tx)))))))))

      ;; Try txindex if enabled
      (let ((tx-index (rpc-get-tx-index node)))
        (when (and tx-index (bitcoin-lisp.storage:tx-index-enabled tx-index))
          (let ((location (bitcoin-lisp.storage:txindex-lookup tx-index txid-bytes)))
            (when location
              (let* ((block-hash (bitcoin-lisp.storage:tx-location-block-hash location))
                     (block-store (rpc-get-block-store node))
                     (block (bitcoin-lisp.storage:get-block block-store block-hash)))
                (when block
                  (let ((found-tx (find-tx-in-block block txid-bytes)))
                    (when found-tx
                      (return-from rpc-getrawtransaction
                        (if verbose
                            (tx-to-json-confirmed found-tx node block-hash)
                            (bitcoin-lisp.crypto:bytes-to-hex
                             (bitcoin-lisp.serialization:serialize found-tx))))))))))))

      ;; Not found
      (let ((tx-index (rpc-get-tx-index node)))
        (if (and tx-index (bitcoin-lisp.storage:tx-index-enabled tx-index))
            (error 'rpc-error :code +rpc-invalid-address-or-key+
                              :message "No such mempool or blockchain transaction")
            (error 'rpc-error :code +rpc-invalid-address-or-key+
                              :message "No such mempool transaction. Use -txindex or provide a blockhash"))))))

(defun find-tx-in-block (block txid)
  "Find a transaction in a block by txid. Returns the transaction or NIL."
  (let ((txs (bitcoin-lisp.serialization:bitcoin-block-transactions block)))
    (find-if (lambda (tx)
               (equalp txid (bitcoin-lisp.serialization:transaction-hash tx)))
             txs)))

(defun tx-to-json-confirmed (tx node block-hash)
  "Convert a confirmed transaction to JSON with block info."
  (let* ((chain-state (rpc-get-chain-state node))
         (block-entry (bitcoin-lisp.storage:get-block-index-entry chain-state block-hash))
         (current-height (bitcoin-lisp.storage:current-height chain-state))
         (block-height (if block-entry
                           (bitcoin-lisp.storage:block-index-entry-height block-entry)
                           0))
         (confirmations (if block-entry
                            (1+ (- current-height block-height))
                            0))
         (header (when block-entry
                   (bitcoin-lisp.storage:block-index-entry-header block-entry)))
         (block-time (when header
                       (bitcoin-lisp.serialization:block-header-timestamp header)))
         (base-json (tx-to-json tx (rpc-get-network node))))
    ;; Add confirmed transaction fields
    (append base-json
            `(("blockhash" . ,(hash-to-hex block-hash))
              ("confirmations" . ,confirmations)
              ("time" . ,block-time)
              ("blocktime" . ,block-time)))))

(defun rpc-estimatesmartfee (node params)
  "Estimate fee rate for confirmation in conf_target blocks.
PARAMS: [conf_target, estimate_mode]
- conf_target: Number of blocks (1-1008)
- estimate_mode: Optional, 'economical' or 'conservative' (default)
Returns: { feerate: BTC/kvB, blocks: number, errors?: [strings] }"
  (let* ((conf-target (first params))
         (mode-str (second params))
         (mode (cond
                 ((null mode-str) :conservative)
                 ((string-equal mode-str "economical") :economical)
                 ((string-equal mode-str "conservative") :conservative)
                 (t (error 'rpc-error :code +rpc-invalid-parameter+
                                      :message "Invalid estimate_mode (must be 'economical' or 'conservative')")))))
    (unless (and (integerp conf-target) (>= conf-target 1) (<= conf-target 1008))
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "Invalid conf_target (must be 1-1008)"))
    ;; Check if still syncing
    (when (rpc-is-syncing node)
      (return-from rpc-estimatesmartfee
        `(("blocks" . ,conf-target)
          ("errors" . #("Insufficient data (node still syncing)")))))
    ;; Get fee estimate
    (let ((fee-estimator (bitcoin-lisp:node-fee-estimator node)))
      (if (and fee-estimator (bitcoin-lisp.mempool:fee-estimator-ready-p fee-estimator))
          ;; Use fee estimator
          (multiple-value-bind (rate-sat-vb error-msg)
              (bitcoin-lisp.mempool:estimate-fee-rate fee-estimator conf-target :mode mode)
            ;; Convert sat/vB to BTC/kvB: sat/vB * 1000 / 100000000
            (let ((rate-btc-kvb (/ (* rate-sat-vb 1000) 100000000.0d0)))
              (if error-msg
                  `(("feerate" . ,rate-btc-kvb)
                    ("blocks" . ,conf-target)
                    ("errors" . ,(vector error-msg)))
                  `(("feerate" . ,rate-btc-kvb)
                    ("blocks" . ,conf-target)))))
          ;; Not enough data - return fallback
          `(("feerate" . 0.00001)  ; 1 sat/vB fallback
            ("blocks" . ,conf-target)
            ("errors" . #("Insufficient data for reliable fee estimation")))))))

(defun rpc-validateaddress (node params)
  "Validate a Bitcoin address and return metadata."
  (let ((address (first params))
        (network (rpc-get-network node)))
    (unless (and (stringp address) (> (length address) 0))
      (return-from rpc-validateaddress `(("isvalid" . nil))))
    (multiple-value-bind (type script-pubkey wit-ver wit-prog)
        (bitcoin-lisp.crypto:decode-address address network)
      (if type
          (let ((result `(("isvalid" . t)
                          ("address" . ,address)
                          ("scriptPubKey" . ,(bitcoin-lisp.crypto:bytes-to-hex script-pubkey))
                          ("isscript" . ,(member type '(:p2sh :p2wsh :witness-v0-scripthash)))
                          ("iswitness" . ,(not (null wit-ver))))))
            (when wit-ver
              (setf result (append result
                                   `(("witness_version" . ,wit-ver)
                                     ("witness_program" . ,(bitcoin-lisp.crypto:bytes-to-hex wit-prog))))))
            result)
          `(("isvalid" . nil))))))

(defun rpc-decodescript (node params)
  "Decode a hex-encoded script."
  (let ((hex-str (first params))
        (network (rpc-get-network node)))
    (unless (stringp hex-str)
      (error 'rpc-error :code +rpc-deserialization-error+
                        :message "Invalid script hex"))
    ;; Handle empty script
    (when (zerop (length hex-str))
      (return-from rpc-decodescript
        `(("asm" . "")
          ("type" . "nonstandard"))))
    (handler-case
        (let ((script (bitcoin-lisp.crypto:hex-to-bytes hex-str)))
          (multiple-value-bind (type data)
              (bitcoin-lisp.validation:classify-script script)
            (let ((result `(("asm" . ,(bitcoin-lisp.validation:disassemble-script script))
                            ("type" . ,(bitcoin-lisp.validation:script-type-to-string type)))))
              ;; Add type-specific fields
              (case type
                (:multisig
                 (setf result (append result
                                      `(("reqSigs" . ,(getf data :m))
                                        ("addresses" . ())))))  ; Would need pubkey-to-address
                ((:pubkeyhash :scripthash)
                 (let* ((hash (getf data :hash))
                        (addr (if (eq type :pubkeyhash)
                                  (bitcoin-lisp.crypto:encode-p2pkh-address hash network)
                                  (bitcoin-lisp.crypto:encode-p2sh-address hash network))))
                   (setf result (append result `(("addresses" . (,addr)))))))
                ((:witness-v0-keyhash :witness-v0-scripthash :witness-v1-taproot)
                 (let* ((prog (getf data :witness-program))
                        (ver (getf data :witness-version))
                        (hrp (if (eq network :testnet3) "tb" "bc"))
                        (addr (bitcoin-lisp.crypto:segwit-address-encode hrp ver prog)))
                   (setf result (append result `(("segwit" . (("address" . ,addr)))))))))
              ;; Add p2sh address (script wrapped in P2SH)
              (let* ((script-hash (bitcoin-lisp.crypto:hash160 script))
                     (p2sh-addr (bitcoin-lisp.crypto:encode-p2sh-address script-hash network)))
                (setf result (append result `(("p2sh" . ,p2sh-addr)))))
              result)))
      (error (e)
        (error 'rpc-error :code +rpc-deserialization-error+
                          :message (format nil "Script decode failed: ~A" e))))))

(defun rpc-createrawtransaction (node params)
  "Create an unsigned raw transaction."
  (let ((inputs (first params))
        (outputs (second params))
        (locktime (or (third params) 0))
        (network (rpc-get-network node)))
    ;; Validate inputs
    (unless (and (listp inputs) (> (length inputs) 0))
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "Invalid inputs"))
    ;; Validate locktime
    (unless (and (integerp locktime) (>= locktime 0))
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "Invalid locktime"))
    ;; Build transaction inputs
    (let ((tx-inputs
            (loop for inp in inputs
                  for txid-str = (cdr (assoc "txid" inp :test #'string=))
                  for vout = (cdr (assoc "vout" inp :test #'string=))
                  for sequence = (or (cdr (assoc "sequence" inp :test #'string=)) #xffffffff)
                  do (unless (valid-hex-hash-p txid-str)
                       (error 'rpc-error :code +rpc-invalid-parameter+
                                         :message "Invalid input txid"))
                     (unless (and (integerp vout) (>= vout 0))
                       (error 'rpc-error :code +rpc-invalid-parameter+
                                         :message "Invalid input vout"))
                  collect (bitcoin-lisp.serialization:make-tx-in
                           :previous-output (bitcoin-lisp.serialization:make-outpoint
                                             :hash (parse-hex-hash txid-str)
                                             :index vout)
                           :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                           :sequence sequence)))
          (tx-outputs '()))
      ;; Build transaction outputs
      (cond
        ;; Object format: {"address": amount, ...}
        ((and (listp outputs) (every #'consp outputs))
         (loop for (addr . amount) in outputs
               do (unless (and (stringp addr) (numberp amount))
                    (error 'rpc-error :code +rpc-invalid-parameter+
                                      :message "Invalid output format"))
                  (when (< amount 0)
                    (error 'rpc-error :code +rpc-invalid-amount+
                                      :message "Invalid amount (negative)"))
                  (when (> amount 21000000)
                    (error 'rpc-error :code +rpc-invalid-amount+
                                      :message "Invalid amount (exceeds max)"))
                  (multiple-value-bind (type script-pubkey)
                      (bitcoin-lisp.crypto:decode-address addr network)
                    (unless type
                      (error 'rpc-error :code +rpc-invalid-address-or-key+
                                        :message (format nil "Invalid address: ~A" addr)))
                    (push (bitcoin-lisp.serialization:make-tx-out
                           :value (round (* amount 100000000))  ; BTC to satoshis
                           :script-pubkey script-pubkey)
                          tx-outputs))))
        (t
         (error 'rpc-error :code +rpc-invalid-parameter+
                           :message "Invalid outputs format")))
      ;; Create transaction
      (let ((tx (bitcoin-lisp.serialization:make-transaction
                 :version 2
                 :inputs (coerce tx-inputs 'simple-vector)
                 :outputs (coerce (nreverse tx-outputs) 'simple-vector)
                 :lock-time locktime)))
        (bitcoin-lisp.crypto:bytes-to-hex
         (bitcoin-lisp.serialization:serialize tx))))))

;;; --- UTXO Set Statistics ---

(defun rpc-gettxoutsetinfo (node params)
  "Return statistics about the UTXO set."
  (let ((hash-type (or (first params) "hash_serialized_3"))
        (utxo-set (rpc-get-utxo-set node))
        (chain-state (rpc-get-chain-state node)))
    (unless (member hash-type '("hash_serialized_3" "none") :test #'string=)
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "Invalid hash_type (must be 'hash_serialized_3' or 'none')"))
    (let* ((height (bitcoin-lisp.storage:current-height chain-state))
           (best-hash (bitcoin-lisp.storage:best-block-hash chain-state))
           (txout-count (bitcoin-lisp.storage:utxo-count utxo-set))
           (tx-count (bitcoin-lisp.storage:utxo-set-distinct-txids utxo-set))
           (total-satoshis (bitcoin-lisp.storage:utxo-set-total-amount utxo-set))
           (total-btc (/ total-satoshis 100000000.0d0))
           (result `(("height" . ,height)
                     ("bestblock" . ,(if best-hash (hash-to-hex best-hash) ""))
                     ("transactions" . ,tx-count)
                     ("txouts" . ,txout-count)
                     ("total_amount" . ,total-btc))))
      ;; Add hash if requested
      (when (string= hash-type "hash_serialized_3")
        (let ((utxo-hash (bitcoin-lisp.storage:compute-utxo-set-hash utxo-set)))
          (setf result (append result
                               `(("hash_serialized_3" . ,(hash-to-hex utxo-hash)))))))
      result)))

;;; --- Block Statistics ---

(defun rpc-getblockstats (node params)
  "Return statistics about a block."
  (let ((hash-or-height (first params))
        (stats-filter (second params)))
    (unless hash-or-height
      (error 'rpc-error :code +rpc-invalid-params+
                        :message "Missing required parameter hash_or_height"))
    ;; Resolve block hash
    (let* ((chain-state (rpc-get-chain-state node))
           (block-store (rpc-get-block-store node)))
      (unless block-store
        (error 'rpc-error :code +rpc-misc-error+
                          :message "Block data not available"))
      (let* ((block-hash
               (cond
                 ;; Height provided
                 ((integerp hash-or-height)
                  (let ((entry (bitcoin-lisp.storage:get-block-at-height
                                chain-state hash-or-height)))
                    (unless entry
                      (error 'rpc-error :code +rpc-invalid-parameter+
                                        :message "Block height out of range"))
                    (bitcoin-lisp.storage:block-index-entry-hash entry)))
                 ;; Hash string provided
                 ((valid-hex-hash-p hash-or-height)
                  (parse-hex-hash hash-or-height))
                 (t
                  (error 'rpc-error :code +rpc-invalid-parameter+
                                    :message "Invalid hash_or_height parameter"))))
             (block (bitcoin-lisp.storage:get-block block-store block-hash)))
      (unless block
        (error 'rpc-error :code +rpc-invalid-address-or-key+
                          :message "Block not found"))
      (let* ((entry (bitcoin-lisp.storage:get-block-index-entry chain-state block-hash))
             (height (if entry
                         (bitcoin-lisp.storage:block-index-entry-height entry)
                         0))
             (header (bitcoin-lisp.serialization:bitcoin-block-header block))
             (txs (bitcoin-lisp.serialization:bitcoin-block-transactions block))
             (ntx (length txs))
             ;; Calculate stats
             (total-size (length (bitcoin-lisp.serialization:serialize block)))
             (total-ins 0)
             (total-outs 0)
             (total-out-value 0))
        ;; Count inputs/outputs
        (loop for tx in txs
              for tx-idx from 0
              do (unless (zerop tx-idx)  ; Skip coinbase inputs
                   (incf total-ins (length (bitcoin-lisp.serialization:transaction-inputs tx))))
                 (incf total-outs (length (bitcoin-lisp.serialization:transaction-outputs tx)))
                 (bitcoin-lisp.serialization:dovector (out (bitcoin-lisp.serialization:transaction-outputs tx))
                   (incf total-out-value (bitcoin-lisp.serialization:tx-out-value out))))
        ;; Calculate subsidy
        (let* ((subsidy (calculate-block-subsidy height))
               (avg-tx-size (if (> ntx 0)
                                (round (/ total-size ntx))
                                0))
               (all-stats `(("avgtxsize" . ,avg-tx-size)
                            ("blockhash" . ,(hash-to-hex block-hash))
                            ("height" . ,height)
                            ("ins" . ,total-ins)
                            ("outs" . ,total-outs)
                            ("subsidy" . ,subsidy)
                            ("time" . ,(bitcoin-lisp.serialization:block-header-timestamp header))
                            ("total_out" . ,total-out-value)
                            ("total_size" . ,total-size)
                            ("txs" . ,ntx))))
          ;; Filter stats if requested
          (if (and stats-filter (listp stats-filter))
              (remove-if-not (lambda (pair)
                               (member (car pair) stats-filter :test #'string=))
                             all-stats)
              all-stats)))))))

(defun calculate-block-subsidy (height)
  "Calculate block subsidy in satoshis for a given height."
  (let* ((halvings (floor height 210000))
         (initial-subsidy 5000000000))  ; 50 BTC in satoshis
    (if (>= halvings 64)
        0
        (ash initial-subsidy (- halvings)))))

;;; --- Pruning Methods ---

(defun rpc-pruneblockchain (node params)
  "Prune the blockchain up to a given block height.
PARAMS: [height]
Returns the height of the last pruned block."
  (unless (bitcoin-lisp:pruning-enabled-p)
    (error 'rpc-error :code +rpc-misc-error+
                      :message "Cannot prune: pruning is not enabled. Start with :prune 1 or :prune 550+"))
  (let ((target-height (first params)))
    (unless (and (integerp target-height) (>= target-height 0))
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "Invalid height parameter"))
    (let* ((chain-state (rpc-get-chain-state node))
           (block-store (rpc-get-block-store node))
           (pruned (bitcoin-lisp.storage:prune-blocks-to-height
                    block-store chain-state target-height
                    :on-prune #'bitcoin-lisp.validation:delete-undo-file)))
      (bitcoin-lisp::node-log :info "RPC pruneblockchain: pruned ~D blocks to height ~D"
                              pruned target-height)
      ;; Return the last pruned block height (matching Bitcoin Core).
      ;; Note: getblockchaininfo.pruneheight returns (1+ this) = first UNpruned block.
      (bitcoin-lisp.storage:chain-state-pruned-height chain-state))))
