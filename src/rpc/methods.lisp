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
         (syncing (rpc-is-syncing node)))
    `(("chain" . ,(case network
                    (:testnet "test")
                    (:mainnet "main")
                    (t "unknown")))
      ("blocks" . ,height)
      ("headers" . ,height)
      ("bestblockhash" . ,(if best-hash (hash-to-hex best-hash) nil))
      ("initialblockdownload" . ,syncing)
      ("verificationprogress" . ,(if syncing 0.0 1.0)))))

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
        `(("loaded" . t)
          ("size" . ,(bitcoin-lisp.mempool:mempool-count mempool))
          ("bytes" . ,(bitcoin-lisp.mempool:mempool-total-size mempool))
          ("usage" . 0))
        `(("loaded" . nil)
          ("size" . 0)
          ("bytes" . 0)
          ("usage" . 0)))))

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
