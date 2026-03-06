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
  "Convert a 32-byte hash to hex string (reversed for display)."
  (with-output-to-string (s)
    (loop for i from 31 downto 0
          do (format s "~2,'0x" (aref bytes i)))))

;;; --- Blockchain Query Methods ---

(defun rpc-getblockchaininfo (node params)
  "Return blockchain state information."
  (declare (ignore params))
  (let* ((chain-state (rpc-get-chain-state node))
         (height (bitcoin-lisp.storage:current-height chain-state))
         (best-hash (bitcoin-lisp.storage:best-block-hash chain-state))
         (network (rpc-get-network node))
         (syncing (rpc-is-syncing node))
         (result `(("chain" . ,(case network
                                 (:testnet "test")
                                 (:mainnet "main")
                                 (t "unknown")))
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
         (block-to-json block hash-str nil))
        (2 ;; Return JSON with full tx details
         (block-to-json block hash-str t))))))

(defun block-to-json (block hash-str include-tx-details)
  "Convert block to JSON representation."
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
                   (mapcar #'tx-to-json txs)
                   (mapcar #'tx-to-txid txs))))))

(defun tx-to-txid (tx)
  "Get transaction ID as hex string."
  (hash-to-hex (bitcoin-lisp.serialization:transaction-hash tx)))

(defun tx-to-json (tx)
  "Convert transaction to JSON representation."
  (let ((inputs (bitcoin-lisp.serialization:transaction-inputs tx))
        (outputs (bitcoin-lisp.serialization:transaction-outputs tx)))
    `(("txid" . ,(tx-to-txid tx))
      ("version" . ,(bitcoin-lisp.serialization:transaction-version tx))
      ("vin" . ,(mapcar #'input-to-json inputs))
      ("vout" . ,(loop for out in outputs
                       for i from 0
                       collect (output-to-json out i)))
      ("locktime" . ,(bitcoin-lisp.serialization:transaction-lock-time tx)))))

(defun input-to-json (input)
  "Convert transaction input to JSON."
  (let ((outpoint (bitcoin-lisp.serialization:tx-in-previous-output input)))
    `(("txid" . ,(hash-to-hex (bitcoin-lisp.serialization:outpoint-hash outpoint)))
      ("vout" . ,(bitcoin-lisp.serialization:outpoint-index outpoint))
      ("scriptSig" . (("hex" . ,(bitcoin-lisp.crypto:bytes-to-hex
                                 (bitcoin-lisp.serialization:tx-in-script-sig input))))))))

(defun output-to-json (output index)
  "Convert transaction output to JSON."
  `(("value" . ,(/ (bitcoin-lisp.serialization:tx-out-value output) 100000000.0))
    ("n" . ,index)
    ("scriptPubKey" . (("hex" . ,(bitcoin-lisp.crypto:bytes-to-hex
                                  (bitcoin-lisp.serialization:tx-out-script-pubkey output)))))))

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
              ("value" . ,(/ (bitcoin-lisp.storage:utxo-entry-value entry) 100000000.0))
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
              `(("addr" . ,(bitcoin-lisp::peer-address peer))
                ("version" . ,(or (bitcoin-lisp::peer-version peer) 0))
                ("subver" . ,(or (bitcoin-lisp::peer-user-agent peer) ""))
                ("inbound" . nil)
                ("startingheight" . ,(or (bitcoin-lisp::peer-start-height peer) 0))))
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
                                   (:testnet "testnet")
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
        (let* ((min-fee-sat-vb (bitcoin-lisp.mempool:mempool-min-fee-rate mempool))
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
  "Return mempool transaction IDs or details."
  (let ((verbose (first params)))
    (let ((mempool (rpc-get-mempool node)))
      (if mempool
          (let ((txs (bitcoin-lisp.mempool:mempool-get-transactions mempool))
                (result (if verbose (make-hash-table :test 'equal) nil)))
            (dolist (tx txs)
              (let ((txid-hex (hash-to-hex (bitcoin-lisp.serialization:transaction-hash tx))))
                (if verbose
                    (setf (gethash txid-hex result)
                          `(("size" . 0)
                            ("fee" . 0)
                            ("time" . ,(get-universal-time))))
                    (push txid-hex result))))
            (if verbose result (nreverse result)))
          (if verbose (make-hash-table :test 'equal) nil)))))

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
          (multiple-value-bind (valid error fee)
              (bitcoin-lisp.validation:validate-transaction-for-mempool
               tx utxo-set mempool current-height)
            (unless valid
              (error 'rpc-error :code +rpc-misc-error+
                                :message (format nil "Transaction rejected: ~A" error)))
            ;; Add to mempool
            (let* ((tx-size (length tx-bytes))
                   (entry (bitcoin-lisp.mempool:make-mempool-entry
                           :transaction tx
                           :fee (or fee 0)
                           :size tx-size
                           :entry-time (get-universal-time)))
                   (add-result (bitcoin-lisp.mempool:mempool-add mempool txid entry)))
              (unless (eq add-result :ok)
                (error 'rpc-error :code +rpc-misc-error+
                                  :message (format nil "Mempool rejection: ~A" add-result)))
              (hash-to-hex txid))))
      (error (e)
        (error 'rpc-error :code +rpc-misc-error+
                          :message (format nil "TX decode failed: ~A" e))))))

;;; --- Extended RPC Methods ---

(defconstant +rpc-deserialization-error+ -22
  "RPC error code for deserialization/hex decode errors.")

(defconstant +rpc-invalid-address-or-key+ -5
  "RPC error code for invalid address or key.")

(defconstant +rpc-invalid-amount+ -3
  "RPC error code for invalid amount.")

(defun rpc-decoderawtransaction (node params)
  "Decode a raw transaction hex string to JSON."
  (declare (ignore node))
  (let ((hex-str (first params)))
    (unless (and (stringp hex-str) (> (length hex-str) 0))
      (error 'rpc-error :code +rpc-deserialization-error+
                        :message "Invalid transaction hex"))
    (handler-case
        (let* ((tx-bytes (bitcoin-lisp.crypto:hex-to-bytes hex-str))
               (tx (flexi-streams:with-input-from-sequence (stream tx-bytes)
                     (bitcoin-lisp.serialization:read-transaction stream))))
          (tx-to-json tx))
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
                (tx-to-json tx)
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
         (base-json (tx-to-json tx)))
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
                        (hrp (if (eq network :testnet) "tb" "bc"))
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
                 :inputs tx-inputs
                 :outputs (nreverse tx-outputs)
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
           (total-btc (/ total-satoshis 100000000.0))
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
                 (dolist (out (bitcoin-lisp.serialization:transaction-outputs tx))
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
                    block-store chain-state target-height)))
      (bitcoin-lisp::node-log :info "RPC pruneblockchain: pruned ~D blocks to height ~D"
                              pruned target-height)
      ;; Return the last pruned block height (matching Bitcoin Core).
      ;; Note: getblockchaininfo.pruneheight returns (1+ this) = first UNpruned block.
      (bitcoin-lisp.storage:chain-state-pruned-height chain-state))))
