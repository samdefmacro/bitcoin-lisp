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
         (block-store (rpc-get-block-store node))
         (tip (and best-hash (bitcoin-lisp.storage:get-block-index-entry chain-state best-hash)))
         (tip-header (and tip (bitcoin-lisp.storage:block-index-entry-header tip)))
         (bits (if tip-header (bitcoin-lisp.serialization:block-header-bits tip-header) #x1d00ffff))
         (result `(("chain" . ,(%chain-name network))
                   ("blocks" . ,height)
                   ("headers" . ,height)
                   ("bestblockhash" . ,(if best-hash (hash-to-hex best-hash) nil))
                   ("difficulty" . ,(%difficulty-from-bits bits))
                   ("time" . ,(if tip-header
                                  (bitcoin-lisp.serialization:block-header-timestamp tip-header) 0))
                   ("mediantime" . ,(if best-hash
                                        (bitcoin-lisp.validation:compute-median-time-past
                                         chain-state best-hash)
                                        0))
                   ("verificationprogress" . ,(if syncing 0.0 1.0))
                   ("initialblockdownload" . ,syncing)
                   ("chainwork" . ,(string-downcase
                                    (format nil "~64,'0x"
                                            (if tip (bitcoin-lisp.storage:block-index-entry-chain-work tip) 0))))
                   ("size_on_disk" . ,(if block-store
                                          (round (* (bitcoin-lisp.storage:block-storage-size-mib block-store)
                                                    1048576))
                                          0))
                   ("bits" . ,(string-downcase (format nil "~8,'0x" bits)))
                   ("target" . ,(string-downcase
                                 (format nil "~64,'0x" (bitcoin-lisp.storage:bits-to-target bits))))
                   ("pruned" . ,(bitcoin-lisp:pruning-enabled-p))
                   ("warnings" . #()))))
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

(defun %getchainstates-entry (chain-state syncing)
  "Per-chainstate object for getchainstates — fields per Core's
RPCHelpForChainstate (rpc/blockchain.cpp): snapshot_blockhash appears only
for a snapshot chainstate, and validated reflects its assumeutxo status."
  (let* ((height (bitcoin-lisp.storage:current-height chain-state))
         (best-hash (bitcoin-lisp.storage:best-block-hash chain-state))
         (tip (and best-hash
                   (bitcoin-lisp.storage:get-block-index-entry chain-state best-hash)))
         (bits (if (and tip (bitcoin-lisp.storage:block-index-entry-header tip))
                   (bitcoin-lisp.serialization:block-header-bits
                    (bitcoin-lisp.storage:block-index-entry-header tip))
                   #x1d00ffff))
         (snapshot-hash (bitcoin-lisp.storage:chain-state-from-snapshot-blockhash
                         chain-state)))
    `(("blocks" . ,height)
      ("bestblockhash" . ,(if best-hash (hash-to-hex best-hash) nil))
      ("bits" . ,(string-downcase (format nil "~8,'0x" bits)))
      ("target" . ,(string-downcase
                    (format nil "~64,'0x" (bitcoin-lisp.storage:bits-to-target bits))))
      ("difficulty" . ,(%difficulty-from-bits bits))
      ;; Consistent with getblockchaininfo: 1.0 at tip, 0.0 while syncing.
      ("verificationprogress" . ,(if syncing 0.0d0 1.0d0))
      ;; We don't split a coinsdb vs coinstip cache; report the chainstate's
      ;; coins-cache budget (per-chainstate while an assumeutxo background
      ;; sync splits it — Core MaybeRebalanceCaches) for the tip cache and 0
      ;; for the db cache.
      ("coins_db_cache_bytes" . 0)
      ("coins_tip_cache_bytes" . ,(bitcoin-lisp::chainstate-coins-cache-budget
                                   chain-state))
      ,@(when snapshot-hash
          `(("snapshot_blockhash" . ,(hash-to-hex snapshot-hash))))
      ("validated" . ,(eq (bitcoin-lisp.storage:chain-state-assumeutxo-status
                           chain-state)
                          :validated)))))

(defun rpc-getchainstates (node params)
  "Report this node's chainstate(s) (Bitcoin Core getchainstates), derived
from the node's chainstates list in Core's order: the historical chainstate
first (when assumeutxo background validation is in progress), the current
(active) chainstate last."
  (declare (ignore params))
  (let* ((syncing (rpc-is-syncing node))
         (chainstates (rpc-get-chainstates node))
         (current (bitcoin-lisp.storage:select-current-chainstate chainstates))
         (historical (bitcoin-lisp.storage:select-historical-chainstate chainstates))
         ;; Core reports m_best_header's height, which can exceed every
         ;; chainstate's validated tip.
         (best-header (bitcoin-lisp.storage:best-header-entry current))
         (entries (append
                   (when historical
                     (list (%getchainstates-entry historical syncing)))
                   (list (%getchainstates-entry current syncing)))))
    `(("headers" . ,(if best-header
                        (bitcoin-lisp.storage:block-index-entry-height best-header)
                        (bitcoin-lisp.storage:current-height current)))
      ("chainstates" . ,entries))))

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

(defun %parse-verbosity (params index default &key allow-bool)
  "Core's ParseVerbosity (rpc/util.cpp:83) for the positional argument at INDEX
in PARAMS: an integer passes through, a boolean (where allowed) maps true→1 /
false→0, and a missing argument yields DEFAULT. Our JSON layer folds false and
null both to NIL, so a supplied NIL reads as false where booleans are allowed
and as null (→ DEFAULT) where they aren't."
  (if (< (length params) (1+ index))
      default
      (let ((v (nth index params)))
        (cond ((integerp v) v)
              ((null v) (if allow-bool 0 default))
              ((and allow-bool (eq v t)) 1)
              ((eq v t)
               (error 'rpc-error :code +rpc-type-error+
                                 :message "Verbosity was boolean but only integer allowed"))
              (t (error 'rpc-error :code +rpc-type-error+
                                   :message "JSON value is not an integer as expected"))))))

(defun rpc-getblock (node params)
  "Return block data (Bitcoin Core getblock). Verbosity <= 0 (or false) returns
the serialized block hex; 1 (or true) a JSON object with txids; >= 2 the object
with full transaction details (Core's verbosity-3 prevout data is not supported
and folds into 2)."
  (let ((hash-str (first params)))
    (unless (valid-hex-hash-p hash-str)
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "Invalid block hash"))
    (let* ((verbosity (%parse-verbosity params 1 1 :allow-bool t))
           (hash-bytes (parse-hex-hash hash-str))
           (block-store (rpc-get-block-store node))
           (block (and block-store
                       (bitcoin-lisp.storage:get-block block-store hash-bytes))))
      (unless block
        (error 'rpc-error :code +rpc-misc-error+
                          :message "Block not found"))
      (cond
        ((<= verbosity 0) ;; Hex of the block's wire (witness-complete) bytes
         (bitcoin-lisp.crypto:bytes-to-hex
          (bitcoin-lisp.serialization:serialize-witness-block block)))
        ((= verbosity 1) ;; JSON with txids only
         (block-to-json block hash-str nil (rpc-get-chain-state node) (rpc-get-network node)))
        (t ;; JSON with full tx details
         (block-to-json block hash-str t (rpc-get-chain-state node) (rpc-get-network node)))))))

(defun %block-on-active-chain-p (entry chain-state)
  "T if ENTRY is the block at its height on the active chain."
  (let ((at (bitcoin-lisp.storage:get-block-at-height
             chain-state (bitcoin-lisp.storage:block-index-entry-height entry))))
    (and at (equalp (bitcoin-lisp.storage:block-index-entry-hash at)
                    (bitcoin-lisp.storage:block-index-entry-hash entry)))))

(defun %chain-header-fields (entry chain-state)
  "The chain-context header fields Bitcoin Core shares between getblock and
getblockheader: confirmations, height, versionHex, mediantime, bits (hex),
target, difficulty, chainwork, and -- when the block is on the active chain and
not the tip -- nextblockhash."
  (let* ((header (bitcoin-lisp.storage:block-index-entry-header entry))
         (height (bitcoin-lisp.storage:block-index-entry-height entry))
         (bits (bitcoin-lisp.serialization:block-header-bits header))
         (on-active (%block-on-active-chain-p entry chain-state))
         (next (and on-active
                    (bitcoin-lisp.storage:get-block-at-height chain-state (1+ height)))))
    (append
     `(("confirmations" . ,(if on-active
                               (+ (- (bitcoin-lisp.storage:current-height chain-state) height) 1)
                               -1))
       ("height" . ,height)
       ("versionHex" . ,(string-downcase
                         (format nil "~8,'0x"
                                 (logand (bitcoin-lisp.serialization:block-header-version header)
                                         #xffffffff))))
       ("mediantime" . ,(bitcoin-lisp.validation:compute-median-time-past
                         chain-state (bitcoin-lisp.storage:block-index-entry-hash entry)))
       ("bits" . ,(string-downcase (format nil "~8,'0x" bits)))
       ("target" . ,(string-downcase
                     (format nil "~64,'0x" (bitcoin-lisp.storage:bits-to-target bits))))
       ("difficulty" . ,(%difficulty-from-bits bits))
       ("chainwork" . ,(string-downcase
                        (format nil "~64,'0x"
                                (bitcoin-lisp.storage:block-index-entry-chain-work entry)))))
     (when next
       `(("nextblockhash" . ,(hash-to-hex (bitcoin-lisp.storage:block-index-entry-hash next))))))))

(defun block-to-json (block hash-str include-tx-details chain-state &optional network)
  "Convert block to JSON representation. NETWORK enables output addresses in the
full-tx-detail (verbosity 2) form. CHAIN-STATE supplies the chain-context fields
(confirmations/height/mediantime/chainwork/nextblockhash) when the block is in
the index."
  (let* ((header (bitcoin-lisp.serialization:bitcoin-block-header block))
         (txs (bitcoin-lisp.serialization:bitcoin-block-transactions block))
         (ntx (length txs))
         (entry (bitcoin-lisp.storage:get-block-index-entry
                 chain-state (bitcoin-lisp.serialization:block-header-hash header)))
         (stripped (+ 80 (bitcoin-lisp.serialization:compact-size-length ntx)
                      (reduce #'+ txs :key (lambda (tx)
                                             (length (bitcoin-lisp.serialization:serialize-transaction tx))))))
         (size (+ 80 (bitcoin-lisp.serialization:compact-size-length ntx)
                  (reduce #'+ txs :key (lambda (tx)
                                         (length (bitcoin-lisp.serialization:transaction-wire-bytes tx)))))))
    (append
     `(("hash" . ,hash-str))
     (when entry (%chain-header-fields entry chain-state))
     `(("strippedsize" . ,stripped)
       ("size" . ,size)
       ("weight" . ,(bitcoin-lisp.validation:calculate-block-weight txs))
       ("version" . ,(bitcoin-lisp.serialization:block-header-version header))
       ("merkleroot" . ,(hash-to-hex (bitcoin-lisp.serialization:block-header-merkle-root header)))
       ("time" . ,(bitcoin-lisp.serialization:block-header-timestamp header))
       ("nonce" . ,(bitcoin-lisp.serialization:block-header-nonce header))
       ("nTx" . ,ntx)
       ("previousblockhash" . ,(hash-to-hex (bitcoin-lisp.serialization:block-header-prev-block header)))
       ("tx" . ,(if include-tx-details
                    (mapcar (lambda (tx) (tx-to-json tx network)) txs)
                    (mapcar #'tx-to-txid txs)))))))

(defun tx-to-txid (tx)
  "Get transaction ID as hex string."
  (hash-to-hex (bitcoin-lisp.serialization:transaction-hash tx)))

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
        ;; P2A (Core ANCHOR): OP_1 <0x4e73>
        ((and (= len 4) (= (b 0) #x51) (= (b 1) #x02) (= (b 2) #x4e) (= (b 3) #x73)) "anchor")
        ;; Future witness program v1..v16, 2..40-byte program (Core WITNESS_UNKNOWN)
        ((and (>= len 4) (<= len 42) (<= #x51 (b 0) #x60) (= (b 1) (- len 2))) "witness_unknown")
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
        (wire (bitcoin-lisp.serialization:transaction-wire-bytes tx)))
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
                  ("scriptSig" . (("asm" . ,(bitcoin-lisp.validation:disassemble-script
                                             (bitcoin-lisp.serialization:tx-in-script-sig input)))
                                  ("hex" . ,(bitcoin-lisp.crypto:bytes-to-hex
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
         (spk-json `(("asm" . ,(bitcoin-lisp.validation:disassemble-script spk))
                     ,@(when network `(("desc" . ,(scriptpubkey-desc spk network))))
                     ("hex" . ,(bitcoin-lisp.crypto:bytes-to-hex spk))
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
          (block-header-entry-to-json entry hash-str chain-state)
          ;; Non-verbose: return serialized header as hex
          (let ((block-store (rpc-get-block-store node)))
            (let ((block (bitcoin-lisp.storage:get-block block-store hash-bytes)))
              (if block
                  (bitcoin-lisp.crypto:bytes-to-hex
                   (bitcoin-lisp.serialization:serialize
                    (bitcoin-lisp.serialization:bitcoin-block-header block)))
                  (error 'rpc-error :code +rpc-misc-error+
                                    :message "Block data not found"))))))))

(defun block-header-entry-to-json (entry hash-str chain-state)
  "Convert block index entry to header JSON (Bitcoin Core getblockheader): the
shared chain-context fields plus the header's own version/merkleroot/time/nonce."
  (let ((header (bitcoin-lisp.storage:block-index-entry-header entry)))
    (append
     `(("hash" . ,hash-str))
     (%chain-header-fields entry chain-state)
     `(("version" . ,(bitcoin-lisp.serialization:block-header-version header))
       ("merkleroot" . ,(hash-to-hex (bitcoin-lisp.serialization:block-header-merkle-root header)))
       ("time" . ,(bitcoin-lisp.serialization:block-header-timestamp header))
       ("nonce" . ,(bitcoin-lisp.serialization:block-header-nonce header))
       ("previousblockhash" . ,(hash-to-hex (bitcoin-lisp.serialization:block-header-prev-block header)))))))

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
    ;; Node lock: the coin lookup and the bestblock/height it is reported
    ;; against must come from one consistent chain state (Core gettxout
    ;; holds cs_main, rpc/blockchain.cpp).
    (with-node-lock (node)
     (let* ((txid-bytes (parse-hex-hash txid-str))
           (utxo-set (rpc-get-utxo-set node))
           (entry (bitcoin-lisp.storage:get-utxo utxo-set txid-bytes vout)))
      (if entry
          (let* ((chain-state (rpc-get-chain-state node))
                 (best-hash (bitcoin-lisp.storage:best-block-hash chain-state))
                 (height (bitcoin-lisp.storage:current-height chain-state))
                 (utxo-height (bitcoin-lisp.storage:utxo-entry-height entry))
                 (spk (bitcoin-lisp.storage:utxo-entry-script-pubkey entry))
                 (network (rpc-get-network node))
                 (addr (%script->address spk network)))
            `(("bestblock" . ,(if best-hash (hash-to-hex best-hash) ""))
              ("confirmations" . ,(1+ (- height utxo-height)))
              ("value" . ,(/ (bitcoin-lisp.storage:utxo-entry-value entry) 100000000.0d0))
              ;; Core's scriptPubKey shape: asm/hex/type plus address when the
              ;; script encodes to one (previously only hex was returned).
              ("scriptPubKey" . (("asm" . ,(bitcoin-lisp.validation:disassemble-script spk))
                                 ("desc" . ,(scriptpubkey-desc spk network))
                                 ("hex" . ,(bitcoin-lisp.crypto:bytes-to-hex spk))
                                 ("type" . ,(%script-type spk))
                                 ,@(when addr `(("address" . ,addr)))))
              ("coinbase" . ,(bitcoin-lisp.storage:utxo-entry-coinbase entry))))
          nil))))) ; Return null for spent outputs

;;; --- Network Query Methods ---

(defun %connection-type-string (conn-type)
  "Core CNode::ConnectionTypeAsString for our peer conn-type keyword."
  (case conn-type
    (:inbound "inbound")
    (:outbound-full-relay "outbound-full-relay")
    (:block-relay "block-relay-only")
    (:feeler "feeler")
    (:manual "manual")
    (:addr-fetch "addr-fetch")
    (t (string-downcase (symbol-name conn-type)))))

(defun rpc-getpeerinfo (node params)
  "Return information about connected peers."
  (declare (ignore params))
  (let ((peers (rpc-get-peers node)))
    (mapcar (lambda (peer)
              ;; peer-version holds the received version *message* struct, not a
              ;; number — pull the numeric protocol version out of it.
              (let* ((vmsg (bitcoin-lisp::peer-version peer))
                     (conn (bitcoin-lisp.networking::peer-connection peer))
                     (ping (bitcoin-lisp.networking::peer-ping-latency peer))
                     (sh (or (bitcoin-lisp::peer-start-height peer) -1)))
                `(("id" . ,(bitcoin-lisp.networking::peer-id peer))
                  ("addr" . ,(bitcoin-lisp::peer-address peer))
                  ("version" . ,(if vmsg
                                    (bitcoin-lisp.serialization:version-message-version vmsg)
                                    0))
                  ("subver" . ,(or (bitcoin-lisp::peer-user-agent peer) ""))
                  ;; Core reports services as a 16-hex-digit string, not a number.
                  ("services" . ,(string-downcase
                                  (format nil "~16,'0X" (or (bitcoin-lisp::peer-services peer) 0))))
                  ;; Real inbound/outbound flag (was hardcoded nil).
                  ("inbound" . ,(bitcoin-lisp.networking::peer-inbound peer))
                  ;; Core ConnectionType string + whether we relay txs to this
                  ;; peer (block-relay-only/feeler peers get no tx relay -- #216).
                  ("connection_type" . ,(%connection-type-string
                                          (bitcoin-lisp.networking:peer-conn-type peer)))
                  ("relaytxes" . ,(and (bitcoin-lisp.networking:peer-relays-txs-p peer) t))
                  ("startingheight" . ,sh)
                  ;; Peer's advertised height as our best proxy for synced_*.
                  ("synced_headers" . ,sh)
                  ("synced_blocks" . ,sh)
                  ("bytessent" . ,(if conn (bitcoin-lisp.networking::connection-bytes-sent conn) 0))
                  ("bytesrecv" . ,(if conn (bitcoin-lisp.networking::connection-bytes-received conn) 0))
                  ;; Addr intake counters (Core m_addr_processed /
                  ;; m_addr_rate_limited; the rate-limited count is addresses
                  ;; dropped by the per-address token bucket).
                  ("addr_processed" . ,(bitcoin-lisp.networking::peer-addr-processed peer))
                  ("addr_rate_limited" . ,(bitcoin-lisp.networking::peer-addr-rate-limited peer))
                  ;; ping-latency is in internal-time units; report seconds (0 = unknown).
                  ("pingtime" . ,(if (and ping (plusp ping))
                                     (/ ping internal-time-units-per-second 1.0d0)
                                     0)))))
            peers)))

(defun rpc-getnetworkinfo (node params)
  "Return network state information (Bitcoin Core getnetworkinfo)."
  (declare (ignore params))
  (let* ((network (rpc-get-network node))
         (peers (rpc-get-peers node))
         ;; THE service bits we advertise on the wire (peer.lisp local-services,
         ;; Core g_local_services) — the one composition; do not duplicate it
         ;; here. Names in bit order per Core ServiceFlagsToStr (protocol.cpp).
         (services (bitcoin-lisp.networking::local-services))
         (service-names
           (loop for (bit name)
                   in `((,bitcoin-lisp.serialization:+node-network+ "NETWORK")
                        (,bitcoin-lisp.serialization:+node-witness+ "WITNESS")
                        (,bitcoin-lisp.serialization:+node-compact-filters+ "COMPACT_FILTERS")
                        (,bitcoin-lisp.serialization:+node-network-limited+ "NETWORK_LIMITED")
                        (,bitcoin-lisp.serialization:+node-p2p-v2+ "P2P_V2"))
                 when (logtest services bit) collect name))
         (in (count-if #'bitcoin-lisp.networking::peer-inbound peers))
         ;; +default-min-relay-fee-rate+ is sat/kvB -> BTC/kvB.
         (relayfee (/ bitcoin-lisp.mempool:+default-min-relay-fee-rate+
                      100000000.0d0))
         ;; +incremental-relay-fee-rate+ is sat/kvB -> BTC/kvB.
         (incfee (/ bitcoin-lisp.mempool::+incremental-relay-fee-rate+ 100000000.0d0)))
    `(("version" . 10000)
      ("subversion" . "/bitcoin-lisp:0.1.0/")
      ("protocolversion" . 70016)
      ("localservices" . ,(string-downcase (format nil "~16,'0X" services)))
      ("localservicesnames" . ,service-names)
      ;; relay-enabled-p returns a truthy list (member result), not a boolean —
      ;; coerce so it serializes as JSON true/false.
      ("localrelay" . ,(and (bitcoin-lisp.networking:relay-enabled-p) t))
      ("timeoffset" . 0)
      ("networkactive" . ,(bitcoin-lisp::node-network-active node))
      ("connections" . ,(length peers))
      ("connections_in" . ,in)
      ("connections_out" . ,(- (length peers) in))
      ("networks" . ((("name" . ,(case network
                                   (:testnet3 "testnet")
                                   (:testnet4 "testnet4")
                                   (:signet "signet")
                                   (:regtest "regtest")
                                   (:mainnet "mainnet")
                                   (t "unknown")))
                      ("reachable" . t))))
      ("relayfee" . ,relayfee)
      ("incrementalfee" . ,incfee)
      ("localaddresses" . ())
      ("warnings" . #()))))

(defun rpc-getconnectioncount (node params)
  "Return the number of connected peers."
  (declare (ignore params))
  (length (rpc-get-peers node)))

(defun rpc-ping (node params)
  "Queue a ping to every connected peer (Bitcoin Core ping). The round-trip
result later surfaces in getpeerinfo's pingtime. Returns null. send-ping is a
no-op on a peer whose connection has dropped, and ignore-errors guards against a
peer disconnecting mid-send."
  (declare (ignore params))
  (dolist (peer (rpc-get-peers node))
    (ignore-errors (bitcoin-lisp.networking:send-ping peer)))
  nil)

;;; --- Mempool Methods ---

(defun %orphan-tx-json (tx announcers verbose2)
  "OrphanDescription (Core getorphantxs verbosity 1/2) for orphan TX announced
by ANNOUNCERS (a list of peer objects, possibly containing nil for local
submissions). VERBOSE2 appends the raw hex. \"bytes\" and \"hex\" use the wire
(witness-complete) encoding — Core ComputeTotalSize / EncodeHexTx. \"from\"
lists every announcer's peer id (Core OrphanInfo::announcers)."
  (let* ((ser (bitcoin-lisp.serialization:transaction-wire-bytes tx))
         (base `(("txid" . ,(hash-to-hex (bitcoin-lisp.serialization:transaction-hash tx)))
                 ("wtxid" . ,(hash-to-hex (bitcoin-lisp.serialization:transaction-wtxid tx)))
                 ("bytes" . ,(length ser))
                 ("vsize" . ,(bitcoin-lisp.serialization:transaction-vsize tx))
                 ("weight" . ,(bitcoin-lisp.serialization:transaction-weight tx))
                 ("from" . ,(loop for peer in announcers
                                  when peer
                                    collect (bitcoin-lisp.networking::peer-id peer))))))
    (if verbose2
        (append base `(("hex" . ,(bitcoin-lisp.crypto:bytes-to-hex ser))))
        base)))

(defun rpc-getorphantxs (node params)
  "List the transactions in the orphan pool (Bitcoin Core getorphantxs, hidden).
PARAMS: ([verbosity]) -- 0 (default) an array of txids, 1 an array of orphan
detail objects, 2 the detail objects plus each transaction's raw hex."
  (let* ((verbosity (%parse-verbosity params 0 0))
         (mempool (rpc-get-mempool node))
         (pool (and mempool (bitcoin-lisp.mempool:mempool-orphan-pool mempool)))
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
           (let ((tx (bitcoin-lisp.mempool:orphan-entry-transaction entry))
                 (from (mapcar #'bitcoin-lisp.mempool::orphan-announcement-peer
                               (bitcoin-lisp.mempool::orphan-entry-announcements entry))))
             (push (case verbosity
                     (0 (hash-to-hex (bitcoin-lisp.serialization:transaction-hash tx)))
                     (1 (%orphan-tx-json tx from nil))
                     (t (%orphan-tx-json tx from t)))
                   result)))
         (bitcoin-lisp.mempool::orphan-pool-by-wtxid pool))))
    (nreverse result)))

(defun rpc-getmempoolinfo (node params)
  "Return mempool statistics."
  (declare (ignore params))
  (let ((mempool (rpc-get-mempool node))
        (incfee (/ bitcoin-lisp.mempool::+incremental-relay-fee-rate+ 100000000.0d0)))
    (if mempool
        ;; Rates are sat/kvB (Core CFeeRate); convert to BTC/kvB via /1e8.
        ;; Node lock: count/bytes/total-fee must be one consistent snapshot
        ;; while the sync thread adds/evicts entries (Core getmempoolinfo
        ;; takes pool.cs via the stats getters).
        (with-node-lock (node)
         (let* ((min-fee-sat-kvb (bitcoin-lisp.mempool:mempool-effective-min-fee-rate mempool))
               (min-fee-btc-kvb (/ min-fee-sat-kvb 100000000.0d0))
               (relay-fee-btc-kvb (/ bitcoin-lisp.mempool:+default-min-relay-fee-rate+ 100000000.0d0))
               (count (bitcoin-lisp.mempool:mempool-count mempool))
               ;; Core "bytes" = GetTotalTxSize(), the sum of the entries'
               ;; sigop-adjusted VIRTUAL sizes (rpc/mempool.cpp:1040,
               ;; txmempool.h:191), not serialized bytes.
               (bytes (bitcoin-lisp.mempool:mempool-total-size mempool))
               (total-fee-sat 0))
          (bitcoin-lisp.mempool:mempool-for-each
           mempool (lambda (txid e) (declare (ignore txid))
                     (incf total-fee-sat (bitcoin-lisp.mempool:mempool-entry-fee e))))
          `(("loaded" . t)
            ("size" . ,count)
            ("bytes" . ,bytes)
            ;; Core DynamicMemoryUsage(): the malloc-modeled memory usage the
            ;; -maxmempool cap is keyed on (rpc/mempool.cpp:1041).
            ("usage" . ,(bitcoin-lisp.mempool:mempool-dynamic-usage mempool))
            ("total_fee" . ,(/ total-fee-sat 100000000.0d0))
            ("maxmempool" . ,(bitcoin-lisp.mempool::mempool-max-size mempool))
            ("mempoolminfee" . ,min-fee-btc-kvb)
            ("minrelaytxfee" . ,relay-fee-btc-kvb)
            ("incrementalrelayfee" . ,incfee)
            ;; Core rpc/mempool.cpp:1047: GetUnbroadcastTxs().size().
            ("unbroadcastcount" . ,(bitcoin-lisp.mempool:mempool-unbroadcast-count mempool))
            ;; Acceptance is unconditionally full-RBF since cluster mempool;
            ;; Core hardcodes true (rpc/mempool.cpp:1048, field DEPRECATED).
            ("fullrbf" . t))))
        `(("loaded" . nil)
          ("size" . 0)
          ("bytes" . 0)
          ("usage" . 0)
          ("total_fee" . 0)
          ("maxmempool" . ,bitcoin-lisp.mempool:+default-max-mempool-bytes+)
          ("mempoolminfee" . 0.000001)
          ("minrelaytxfee" . 0.000001)
          ("incrementalrelayfee" . ,incfee)
          ("unbroadcastcount" . 0)
          ("fullrbf" . t)))))

(defun rpc-getrawmempool (node params)
  "Return mempool transaction IDs (verbose nil) or per-tx details (verbose t)."
  (let ((verbose (first params))
        (mempool (rpc-get-mempool node)))
    ;; Node lock: iterating entries (and, verbose, walking each entry's
    ;; ancestors/descendants/chunk) must not race the sync thread's
    ;; add/evict/reorg mutations (Core getrawmempool takes pool.cs).
    (with-node-lock (node)
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
         result))))))

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
      (bitcoin-lisp.mempool:mempool-ancestor-stats mempool txid)
    (multiple-value-bind (dcount dsize dfees)
        (bitcoin-lisp.mempool:mempool-descendant-stats mempool txid)
      (let ((chunk (bitcoin-lisp.mempool:txgraph-get-main-chunk-feerate
                    (bitcoin-lisp.mempool:mempool-graph mempool)
                    (bitcoin-lisp.mempool:mempool-entry-graph-handle entry))))
        `(("vsize" . ,(bitcoin-lisp.mempool:mempool-entry-vsize entry))
          ("weight" . ,(bitcoin-lisp.serialization:transaction-weight
                        (bitcoin-lisp.mempool:mempool-entry-transaction entry)))
          ("time" . ,(bitcoin-lisp.mempool:mempool-entry-entry-time entry))
          ("height" . ,(bitcoin-lisp.mempool:mempool-entry-height entry))
          ("chunkweight" . ,(bitcoin-lisp.mempool:feefrac-size chunk))
          ("fees" . (("base" . ,(/ (bitcoin-lisp.mempool:mempool-entry-fee entry) 100000000.0d0))
                     ("modified" . ,(/ (bitcoin-lisp.mempool:mempool-entry-modified-fee entry)
                                       100000000.0d0))
                     ("ancestor" . ,(/ afees 100000000.0d0))
                     ("descendant" . ,(/ dfees 100000000.0d0))
                     ("chunk" . ,(/ (bitcoin-lisp.mempool:feefrac-fee chunk)
                                    100000000.0d0))))
          ("ancestorcount" . ,acount)
          ("ancestorsize" . ,asize)
          ("descendantcount" . ,dcount)
          ("descendantsize" . ,dsize)
          ("wtxid" . ,(hash-to-hex (bitcoin-lisp.mempool:mempool-entry-wtxid entry)))
          ("depends" . ,(let ((deps '()))
                          (maphash (lambda (p v) (declare (ignore v))
                                     (push (hash-to-hex p) deps))
                                   (bitcoin-lisp.mempool:mempool-entry-parents entry))
                          deps))
          ;; In-mempool txs that spend this tx's outputs (Core "spentby").
          ("spentby" . ,(let ((sb '()))
                          (maphash (lambda (c v) (declare (ignore v))
                                     (push (hash-to-hex c) sb))
                                   (bitcoin-lisp.mempool::mempool-entry-children entry))
                          sb))
          ;; BIP125: whether the tx or any unconfirmed ancestor SIGNALS
          ;; replaceability (Core IsRBFOptIn, reporting only — acceptance is
          ;; unconditionally full-RBF; rpc/mempool.cpp:456,567, DEPRECATED).
          ("bip125-replaceable"
           . ,(and (bitcoin-lisp.mempool::mempool-tx-or-ancestor-signals-rbf-p mempool txid)
                   t))
          ("unbroadcast" . nil))))))

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
    (with-node-lock (node)
      (multiple-value-bind (txid entry) (%mempool-txid-arg params mempool)
        (%mempool-entry-fields mempool txid entry)))))

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
    (with-node-lock (node)
      (multiple-value-bind (txid entry) (%mempool-txid-arg params mempool)
        (declare (ignore entry))
        (%mempool-set->result mempool (bitcoin-lisp.mempool:mempool-ancestors mempool txid) verbose)))))

(defun rpc-getmempooldescendants (node params)
  "Return the in-mempool descendants of TXID (Bitcoin Core getmempooldescendants).
PARAMS: (txid [verbose]). Array of txids, or txid->details when verbose."
  (let ((mempool (rpc-get-mempool node))
        (verbose (second params)))
    (with-node-lock (node)
      (multiple-value-bind (txid entry) (%mempool-txid-arg params mempool)
        (declare (ignore entry))
        (%mempool-set->result mempool (bitcoin-lisp.mempool:mempool-descendants mempool txid) verbose)))))

(defun rpc-getmempoolcluster (node params)
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
      (let ((chunks (bitcoin-lisp.mempool:txgraph-get-cluster-chunks
                     (bitcoin-lisp.mempool:mempool-graph mempool)
                     (bitcoin-lisp.mempool:mempool-entry-graph-handle entry))))
        `(("clusterweight"
           . ,(reduce #'+ chunks
                      :key (lambda (c) (bitcoin-lisp.mempool:feefrac-size (cdr c)))))
          ("txcount" . ,(reduce #'+ chunks :key (lambda (c) (length (car c)))))
          ("chunks"
           . ,(mapcar (lambda (c)
                        `(("chunkfee" . ,(/ (bitcoin-lisp.mempool:feefrac-fee (cdr c))
                                            100000000.0d0))
                          ("chunkweight" . ,(bitcoin-lisp.mempool:feefrac-size (cdr c)))
                          ("txs" . ,(mapcar (lambda (h)
                                              (hash-to-hex
                                               (bitcoin-lisp.mempool:tx-handle-data h)))
                                            (car c)))))
                      chunks))))))))

(defun rpc-getmempoolfeeratediagram (node params)
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
        (let ((builder (bitcoin-lisp.mempool:make-block-builder
                        (bitcoin-lisp.mempool:mempool-graph mempool))))
          (unwind-protect
               (loop for feerate = (bitcoin-lisp.mempool:block-builder-current-chunk-feerate
                                    builder)
                     while feerate
                     do (incf cum-weight (bitcoin-lisp.mempool:feefrac-size feerate))
                        (incf cum-fee (bitcoin-lisp.mempool:feefrac-fee feerate))
                        (push `(("weight" . ,cum-weight)
                                ("fee" . ,(/ cum-fee 100000000.0d0)))
                              points)
                        (bitcoin-lisp.mempool:block-builder-include builder))
            (bitcoin-lisp.mempool:block-builder-finish builder)))))
    (nreverse points)))

(defun rpc-gettxspendingprevout (node params)
  "For each {txid, vout} outpoint in the array PARAM, report the mempool
transaction spending it, if any (Bitcoin Core gettxspendingprevout). Returns an
array of {txid, vout, spendingtxid?}."
  (let ((outpoints (first params))
        (mempool (rpc-get-mempool node)))
    (unless (and (listp outpoints) outpoints)
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "First parameter must be a non-empty array of outpoints"))
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
                              :message "Each outpoint needs a txid (hex) and vout (integer)"))
          (let ((spender (and mempool (bitcoin-lisp.mempool:mempool-spending-tx mempool txid vout))))
            `(("txid" . ,txid-hex)
              ("vout" . ,vout)
              ,@(when spender `(("spendingtxid" . ,(hash-to-hex spender))))))))
      outpoints))))

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
    ;; Node lock: validation reads the mempool + UTXO set + tip together;
    ;; a consistent view for the whole batch (Core ProcessTransaction
    ;; requires cs_main even for test_accept).
    (with-node-lock (node)
     (let ((height (bitcoin-lisp.storage:current-height chain-state))
          (results '()))
      (dolist (hex-str txs (nreverse results))
        (push
         (handler-case
             (let* ((tx-bytes (bitcoin-lisp.crypto:hex-to-bytes hex-str))
                    (tx (flexi-streams:with-input-from-sequence (stream tx-bytes)
                          (bitcoin-lisp.serialization:read-transaction stream)))
                    (txid (bitcoin-lisp.serialization:transaction-hash tx)))
               (multiple-value-bind (valid error fee replaced sigops)
                   (bitcoin-lisp.validation:validate-transaction-for-mempool
                    tx utxo-set mempool height :chain-state chain-state)
                 (declare (ignore replaced))
                 (if valid
                     `(("txid" . ,(hash-to-hex txid))
                       ("wtxid" . ,(hash-to-hex (bitcoin-lisp.serialization:transaction-wtxid tx)))
                       ("allowed" . t)
                       ;; Core reports ws.m_vsize here — the sigop-adjusted
                       ;; size, not the raw BIP141 vsize (rpc/mempool.cpp:375).
                       ("vsize" . ,(bitcoin-lisp.mempool:sigop-adjusted-vsize
                                    (bitcoin-lisp.serialization:transaction-weight tx)
                                    sigops))
                       ("fees" . (("base" . ,(/ (or fee 0) 100000000.0d0)))))
                     `(("txid" . ,(hash-to-hex txid))
                       ("wtxid" . ,(hash-to-hex (bitcoin-lisp.serialization:transaction-wtxid tx)))
                       ("allowed" . nil)
                       ("reject-reason" . ,(string-downcase (symbol-name error)))))))
           (error (e)
             `(("allowed" . nil)
               ("reject-reason" . ,(format nil "decode-failed: ~A" e)))))
         results))))))

(defun rpc-sendrawtransaction (node params)
  "Submit a raw transaction to the mempool AND broadcast it: on acceptance the
txid joins the mempool's unbroadcast set and an announcement is queued to every
relay-capable peer (Core sendrawtransaction -> BroadcastTransaction,
node/transaction.cpp:100-135: AddUnbroadcastTx + InitiateTxBroadcastToAll). A
tx already in the mempool is not resubmitted but IS re-announced, so the RPC
doubles as a manual rebroadcast (node/transaction.cpp:63-72)."
  (let ((hex-str (first params)))
    (unless (and (stringp hex-str) (> (length hex-str) 0))
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "Invalid transaction hex"))
    (handler-case
        (let* ((tx-bytes (bitcoin-lisp.crypto:hex-to-bytes hex-str))
               (tx (flexi-streams:with-input-from-sequence (stream tx-bytes)
                     (bitcoin-lisp.serialization:read-transaction stream)))
               (txid (bitcoin-lisp.serialization:transaction-hash tx)))
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
                  (current-height (bitcoin-lisp.storage:current-height chain-state)))
            ;; Validate transaction for mempool
            (multiple-value-bind (valid error fee replaced sigops)
                (bitcoin-lisp.validation:validate-transaction-for-mempool
                 tx utxo-set mempool current-height :chain-state chain-state)
              (when (and (not valid) (eq error :already-in-mempool))
                ;; Core doesn't reject a same-txid resubmission: it skips the
                ;; mempool submission but still relays, announcing the POOL
                ;; entry's wtxid (a same-txid/different-witness submission must
                ;; advertise the witness we can actually serve). No unbroadcast
                ;; add — Core's already-in-mempool branch skips it too.
                (bitcoin-lisp::broadcast-transaction-to-peers node txid)
                (return-from rpc-sendrawtransaction (hash-to-hex txid)))
              (unless valid
                (error 'rpc-error :code +rpc-transaction-rejected+
                                  :message (format nil "Transaction rejected: ~A" error)))
              (let ((add-result (bitcoin-lisp.mempool:accept-validated-tx
                                 mempool txid tx fee current-height
                                 :sigops sigops :replaced replaced)))
                (unless (eq add-result :ok)
                  (error 'rpc-error :code +rpc-transaction-rejected+
                                    :message (format nil "Mempool rejection: ~A" add-result)))
                ;; Track for best-effort initial broadcast (Core
                ;; node/transaction.cpp:100-104), then queue the announcement
                ;; to all relay peers.
                (bitcoin-lisp.mempool:mempool-add-unbroadcast mempool txid)
                (bitcoin-lisp::broadcast-transaction-to-peers node txid)
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
      ;; Node lock across validate-package -> mempool submission ->
      ;; broadcast: package acceptance mutates the mempool tx-by-tx and
      ;; must not interleave with the sync thread (Core AcceptPackage runs
      ;; entirely under cs_main + pool.cs).
      (multiple-value-bind (msg results replaced)
          (with-node-lock (node)
            (multiple-value-prog1
                (bitcoin-lisp.validation:validate-package-for-mempool
                 package utxo-set mempool chain-state)
              ;; Broadcast every package member that made it into (or already
              ;; was in) the mempool — Core submitpackage runs
              ;; BroadcastTransaction on each such tx (rpc/mempool.cpp:
              ;; 1423-1444). Those txs are in the pool by now, so Core's
              ;; already-in-mempool branch applies: relay only, no
              ;; unbroadcast-set add (node/transaction.cpp:63-72).
              (dolist (tx package)
                (let ((txid (bitcoin-lisp.serialization:transaction-hash tx)))
                  (when (bitcoin-lisp.mempool:mempool-has mempool txid)
                    (bitcoin-lisp::broadcast-transaction-to-peers node txid))))))
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
      ;; Node lock: these ops reorg the active chain, rewrite the UTXO set,
      ;; and re-add/evict mempool entries — the same mutations the sync
      ;; thread performs under the lock (Core invalidateblock/
      ;; reconsiderblock/preciousblock all hold cs_main).
      (with-node-lock (node)
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
          nil)))))

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
         ("address" . ,(bitcoin-lisp.networking:peer-address-string pa))
         ("port" . ,(bitcoin-lisp.networking:peer-address-port pa))
         ("network" . ,(or (%addrman-network-name pa) "unroutable"))))
     limited)))

(defun %addrman-network-name (pa)
  "Network bucket name (Bitcoin Core GetNetworkName) for a peer-address PA, or
NIL for an unroutable/empty address."
  (let ((network (bitcoin-lisp.networking:peer-address-network pa)))
    (when (bitcoin-lisp.networking:address-routable-p
           (bitcoin-lisp.networking:peer-address-ip pa) network)
      (ecase network
        (:ipv4 "ipv4") (:ipv6 "ipv6") (:torv3 "onion")
        (:i2p "i2p") (:cjdns "cjdns")))))

(defun rpc-getaddrmaninfo (node params)
  "Address-manager new/tried/total counts per network plus an all_networks
aggregate (Bitcoin Core getaddrmaninfo). Like Core, every standard network key
is always present (0 when empty); all_networks uses the address book's
authoritative running counts."
  (declare (ignore params))
  (let ((book (bitcoin-lisp::node-address-book node))
        ;; name -> (new . tried)
        (tally (make-hash-table :test 'equal))
        (networks '("ipv4" "ipv6" "onion" "i2p" "cjdns")))
    (dolist (n networks) (setf (gethash n tally) (cons 0 0)))
    (when book
      (maphash
       (lambda (id pa)
         (declare (ignore id))
         (let ((name (%addrman-network-name pa)))
           (when name
             (let ((cell (gethash name tally)))
               (if (bitcoin-lisp.networking:peer-address-in-tried pa)
                   (incf (cdr cell))
                   (incf (car cell)))))))
       (bitcoin-lisp.networking::address-book-info book)))
    (flet ((entry (new tried)
             `(("new" . ,new) ("tried" . ,tried) ("total" . ,(+ new tried)))))
      (let ((result (mapcar (lambda (n)
                              (let ((cell (gethash n tally)))
                                (cons n (entry (car cell) (cdr cell)))))
                            networks))
            (nn (if book (bitcoin-lisp.networking::address-book-n-new book) 0))
            (nt (if book (bitcoin-lisp.networking::address-book-n-tried book) 0)))
        (append result (list (cons "all_networks" (entry nn nt))))))))

(defun rpc-addnode (node params)
  "Manage manually-added peers (Bitcoin Core addnode). PARAMS:
(node command [v2transport]). COMMAND is \"add\" (remember the peer and keep it
connected), \"remove\", or \"onetry\" (dial once now). The actual dialing is
handed to the sync thread (via added-nodes / pending-onetry) so node-peers stays
single-writer. Returns null. v2transport is accepted and ignored — BIP324 v2
transport is not implemented."
  (let ((spec (first params))
        (command (second params)))
    (unless (and (stringp spec) (plusp (length spec)))
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "node must be a string"))
    (unless (member command '("add" "remove" "onetry") :test #'equal)
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "command must be \"add\", \"remove\", or \"onetry\""))
    (bt:with-recursive-lock-held ((bitcoin-lisp::node-lock node))
      (cond
        ((equal command "onetry")
         (push spec (bitcoin-lisp::node-pending-onetry node)))
        ((equal command "add")
         (when (member spec (bitcoin-lisp::node-added-nodes node) :test #'string=)
           (error 'rpc-error :code +rpc-client-node-already-added+
                             :message "Error: Node already added"))
         (setf (bitcoin-lisp::node-added-nodes node)
               (append (bitcoin-lisp::node-added-nodes node) (list spec))))
        ((equal command "remove")
         (unless (member spec (bitcoin-lisp::node-added-nodes node) :test #'string=)
           (error 'rpc-error :code +rpc-client-node-not-added+
                             :message "Error: Node could not be removed. It has not been added previously."))
         (setf (bitcoin-lisp::node-added-nodes node)
               (remove spec (bitcoin-lisp::node-added-nodes node) :test #'string=)))))
    nil))

(defun rpc-getaddednodeinfo (node params)
  "Report manually-added peers and their connection state (Bitcoin Core
getaddednodeinfo). PARAMS: ([node]) — restrict to one added node (errors if it
was never added). Returns an array of {addednode, connected, addresses}."
  (let ((filter (first params)))
    (when (and filter (not (stringp filter)))
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "node must be a string"))
    (let ((added (bt:with-recursive-lock-held ((bitcoin-lisp::node-lock node))
                   (copy-list (bitcoin-lisp::node-added-nodes node)))))
      (when filter
        (unless (member filter added :test #'string=)
          (error 'rpc-error :code +rpc-client-node-not-added+
                            :message "Error: Node has not been added."))
        (setf added (list filter)))
      (mapcar
       (lambda (spec)
         (let* ((host (bitcoin-lisp::parse-node-endpoint node spec))
                (peer (bt:with-recursive-lock-held ((bitcoin-lisp::node-lock node))
                        (find host (bitcoin-lisp::node-peers node)
                              :key #'bitcoin-lisp.networking:peer-address :test #'string=))))
           `(("addednode" . ,spec)
             ("connected" . ,(and peer t))
             ;; List (not vector): rpc-result->json recurses into lists to
             ;; normalize the nested address object; NIL renders as the empty set.
             ("addresses" . ,(when peer
                               (list `(("address" . ,(bitcoin-lisp.networking:peer-address peer))
                                       ("connected" . ,(if (bitcoin-lisp.networking::peer-inbound peer)
                                                           "inbound" "outbound")))))))))
       added))))

(defun %set-network-active (node state)
  "Flip the node's network-active flag (Core CConnman::SetNetworkActive).
When disabling, mark current peers disconnected (close socket + set state) —
Core's socket thread does the same as a consequence of the cleared flag
(net.cpp DisconnectNodes); the sync thread reaps them from node-peers,
keeping it single-writer. Shared by setnetworkactive and dumptxoutset's
rollback-time NetworkDisable. Returns STATE."
  (setf (bitcoin-lisp::node-network-active node) state)
  (unless state
    (dolist (peer (bt:with-recursive-lock-held ((bitcoin-lisp::node-lock node))
                    (copy-list (bitcoin-lisp::node-peers node))))
      (ignore-errors (bitcoin-lisp.networking:disconnect-peer peer))))
  state)

(defun rpc-setnetworkactive (node params)
  "Enable or disable all P2P network activity (Bitcoin Core setnetworkactive).
PARAMS: (state). Disabling drops all current peers and stops new inbound/outbound
connections until re-enabled. Returns the new state."
  (when (endp params)
    (error 'rpc-error :code +rpc-invalid-parameter+ :message "state is required"))
  (%set-network-active node (and (first params) t)))

(defun rpc-getblockfrompeer (node params)
  "Request block BLOCKHASH from the connected peer with id PEER-ID (Bitcoin Core
getblockfrompeer). PARAMS: (blockhash peer_id). We must already have the header,
the block must not already be downloaded, and the peer must be connected. Sends a
getdata(MSG_WITNESS_BLOCK) to that peer; the block arrives through the normal
block-processing path. Returns an empty object. The per-connection send lock makes
the cross-thread send safe."
  (let ((blockhash-hex (first params))
        (peer-id (second params)))
    (unless (and (stringp blockhash-hex) (valid-hex-hash-p blockhash-hex))
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "blockhash must be a hex string"))
    (unless (integerp peer-id)
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "peer_id must be an integer"))
    (let* ((hash (parse-hex-hash blockhash-hex))
           (chain-state (rpc-get-chain-state node))
           (block-store (rpc-get-block-store node))
           (entry (bitcoin-lisp.storage:get-block-index-entry chain-state hash)))
      (unless entry
        (error 'rpc-error :code +rpc-misc-error+ :message "Block header missing"))
      (when (and (bitcoin-lisp:pruning-enabled-p)
                 (> (bitcoin-lisp.storage:block-index-entry-height entry)
                    (bitcoin-lisp.storage:current-height chain-state)))
        (error 'rpc-error :code +rpc-misc-error+
                          :message "In prune mode, only blocks that the node has already synced previously can be fetched from a peer"))
      (when (and block-store (bitcoin-lisp.storage:block-exists-p block-store hash))
        (error 'rpc-error :code +rpc-misc-error+ :message "Block already downloaded"))
      (let ((peer (bt:with-recursive-lock-held ((bitcoin-lisp::node-lock node))
                    (find peer-id (bitcoin-lisp::node-peers node)
                          :key #'bitcoin-lisp.networking::peer-id))))
        (unless peer
          (error 'rpc-error :code +rpc-misc-error+ :message "Peer does not exist"))
        (bitcoin-lisp.networking:send-message
         peer
         (bitcoin-lisp.serialization:make-getdata-message
          (list (bitcoin-lisp.serialization:make-inv-vector
                 :type bitcoin-lisp.serialization:+inv-type-witness-block+
                 :hash hash)))))
      ;; Core returns an empty object; an empty hash-table serializes as {}.
      (make-hash-table :test 'equal))))

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
         (block-store (rpc-get-block-store node)))
    ;; Node lock: walk one consistent chain — a concurrent reorg on the
    ;; sync thread could otherwise splice entries from two tips (Core
    ;; VerifyDB holds cs_main throughout).
    (with-node-lock (node)
     (let ((tip (bitcoin-lisp.storage:current-height chain-state)))
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
      t))))

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

(defun %tip-result (chain-state)
  "The {hash, height} alist Core's waitfor* RPCs return for the current tip."
  (let ((hash (bitcoin-lisp.storage:best-block-hash chain-state)))
    `(("hash" . ,(if hash (hash-to-hex hash) ""))
      ("height" . ,(bitcoin-lisp.storage:current-height chain-state)))))

(defun %wait-deadline (timeout-ms)
  "Internal-real-time deadline for a TIMEOUT-MS wait, or NIL for wait-forever."
  (when (plusp timeout-ms)
    (+ (get-internal-real-time)
       (floor (* timeout-ms internal-time-units-per-second) 1000))))

(defun rpc-waitforblock (node params)
  "Wait until the given block hash becomes the chain tip (Bitcoin Core
waitforblock). PARAMS: (blockhash [timeout-ms]); timeout 0 (default) waits
indefinitely. Returns the tip on match, timeout, or node shutdown. Polls on the
RPC worker thread."
  (let ((hash-hex (first params))
        (timeout (if (integerp (second params)) (second params) 0)))
    (unless (stringp hash-hex)
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "blockhash (hex string) required"))
    (when (minusp timeout)
      (error 'rpc-error :code +rpc-misc-error+ :message "Negative timeout"))
    (let ((target (parse-hex-hash hash-hex)))
      (unless target
        (error 'rpc-error :code +rpc-invalid-parameter+
                          :message "blockhash must be a 64-character hex string"))
      (let* ((chain-state (rpc-get-chain-state node))
             (deadline (%wait-deadline timeout)))
        (loop while (and (bitcoin-lisp::node-running node)
                         (not (equalp (bitcoin-lisp.storage:best-block-hash chain-state)
                                      target))
                         (or (null deadline) (< (get-internal-real-time) deadline)))
              do (sleep 0.25))
        (%tip-result chain-state)))))

(defun rpc-waitforblockheight (node params)
  "Wait until the chain tip reaches at least HEIGHT (Bitcoin Core
waitforblockheight). PARAMS: (height [timeout-ms]); timeout 0 (default) waits
indefinitely. Returns the tip on reaching the height, timeout, or node shutdown."
  (let ((height (first params))
        (timeout (if (integerp (second params)) (second params) 0)))
    (unless (and (integerp height) (>= height 0))
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "height must be a non-negative integer"))
    (when (minusp timeout)
      (error 'rpc-error :code +rpc-misc-error+ :message "Negative timeout"))
    (let* ((chain-state (rpc-get-chain-state node))
           (deadline (%wait-deadline timeout)))
      (loop while (and (bitcoin-lisp::node-running node)
                       (< (bitcoin-lisp.storage:current-height chain-state) height)
                       (or (null deadline) (< (get-internal-real-time) deadline)))
            do (sleep 0.25))
      (%tip-result chain-state))))

;;; --- UTXO-set snapshots (Bitcoin Core dumptxoutset / loadtxoutset) ---
;;;
;;; Core snapshot v2 format (node/utxo_snapshot.h:28-106):
;;;   metadata: "utxo"+0xff (5) | version u16 = 2 | network magic (4) |
;;;             base blockhash (32) | coin count u64
;;;   body:     coins grouped per txid in UTXO cursor order (txid lex,
;;;             vout numerically ascending): txid (32) +
;;;             CompactSize(coins in group), then per coin
;;;             CompactSize(vout) + Coin (VARINT(2*height+coinbase) +
;;;             compressed TxOut) — the compressor module's codec.

(defparameter +snapshot-magic-bytes+
  (coerce #(#x75 #x74 #x78 #x6F #xFF) '(simple-array (unsigned-byte 8) (*)))
  "SNAPSHOT_MAGIC_BYTES {'u','t','x','o',0xff} (node/utxo_snapshot.h:28).")

(defconstant +snapshot-version+ 2
  "SnapshotMetadata::VERSION (node/utxo_snapshot.h:46).")

(defconstant +snapshot-count-offset+ 43
  "Byte offset of the metadata's u64 coin count: 5 magic + 2 version +
4 network magic + 32 base blockhash. Coins start 8 bytes later.")

(defun %network-for-magic (magic)
  "The network keyword whose P2P message magic is MAGIC, or NIL."
  (find-if (lambda (net) (equalp magic (bitcoin-lisp:network-magic net)))
           '(:mainnet :testnet3 :testnet4 :signet :regtest)))

(defun %chain-tx-count (tip-entry block-store)
  "Number of transactions in the chain up to and including TIP-ENTRY (Core
CBlockIndex::m_chain_tx_count), or NIL when any block's count is unknown
(header-only or pruned). Walks back to genesis summing per-block counts."
  (let ((total 0) (entry tip-entry))
    (loop while entry
          do (let ((n (%entry-tx-count entry block-store)))
               (unless n (return-from %chain-tx-count nil))
               (incf total n)
               (when (zerop (bitcoin-lisp.storage:block-index-entry-height entry))
                 (return-from %chain-tx-count total))
               (setf entry (bitcoin-lisp.storage:block-index-entry-prev-entry entry))))
    ;; The walk fell off a prev-entry link before reaching genesis.
    nil))

(defun %parse-hash-or-height-entry (chain-state param)
  "Resolve PARAM — a non-negative block height or a block-hash hex string —
to a block-index entry (Core ParseHashOrHeight, rpc/blockchain.cpp:126-152):
heights resolve on the ACTIVE chain and must not exceed the tip; hashes
resolve through the shared block index."
  (cond
    ((integerp param)
     (when (minusp param)
       (error 'rpc-error :code +rpc-invalid-parameter+
                         :message (format nil "Target block height ~D is negative" param)))
     (let ((tip-height (bitcoin-lisp.storage:current-height chain-state)))
       (when (> param tip-height)
         (error 'rpc-error :code +rpc-invalid-parameter+
                           :message (format nil "Target block height ~D after current tip ~D"
                                            param tip-height))))
     (or (bitcoin-lisp.storage:get-block-at-height chain-state param)
         (error 'rpc-error :code +rpc-invalid-address-or-key+
                           :message "Block not found")))
    ((and (stringp param) (valid-hex-hash-p param))
     (or (bitcoin-lisp.storage:get-block-index-entry
          chain-state (parse-hex-hash param))
         (error 'rpc-error :code +rpc-invalid-address-or-key+
                           :message "Block not found")))
    (t
     (error 'rpc-error :code +rpc-invalid-parameter+
                       :message "rollback must be a block height or a block hash"))))

(defun %dump-rollback-target-entry (node chain-state tip-entry type options)
  "The block-index entry dumptxoutset should dump at (Core rpc/
blockchain.cpp:3091-3110): an explicit options.rollback height/hash wins
(the type, if given, must then be \"rollback\"); bare type \"rollback\"
means the highest chainparams assumeutxo snapshot height
(GetAvailableSnapshotHeights); \"latest\" means the current tip; anything
else — including an omitted type — is refused."
  (multiple-value-bind (rollback-param rollback-supplied)
      (if (hash-table-p options)
          (gethash "rollback" options)
          (values nil nil))
    (cond
      (rollback-supplied
       (unless (or (string= type "") (string= type "rollback"))
         (error 'rpc-error :code +rpc-invalid-parameter+
                           :message (format nil "Invalid snapshot type \"~A\" specified with rollback option" type)))
       (%parse-hash-or-height-entry chain-state rollback-param))
      ((string= type "rollback")
       (let ((heights (mapcar #'bitcoin-lisp:assumeutxo-data-height
                              (bitcoin-lisp:network-assumeutxo-data
                               (rpc-get-network node)))))
         (unless heights
           (error 'rpc-error :code +rpc-misc-error+
                             :message "No assumeutxo snapshot heights are available for this network"))
         (%parse-hash-or-height-entry chain-state (reduce #'max heights))))
      ((string= type "latest") tip-entry)
      (t
       (error 'rpc-error :code +rpc-invalid-parameter+
                         :message (format nil "Invalid snapshot type \"~A\" specified. Please specify \"rollback\" or \"latest\"" type))))))

(defun %dump-txoutset-with-rollback (node chain-state target-entry path)
  "Temporarily roll the active chain back to TARGET-ENTRY, dump the UTXO set
at that height, and restore (Core dumptxoutset's NetworkDisable +
TemporaryRollback RAII pair, rpc/blockchain.cpp:3010-3045,3136-3196): network
activity is suspended so peers aren't punished for relaying data that only
looks wrong in the rolled-back state; the rollback is invalidateblock on the
active chain's block after the target, always undone with reconsiderblock in
reverse RAII order (rollback restored first, then the network re-enabled)."
  (let ((target-height (bitcoin-lisp.storage:block-index-entry-height target-entry))
        (target-hash (bitcoin-lisp.storage:block-index-entry-hash target-entry)))
    ;; A hash-resolved target must lie on the active chain — Core takes
    ;; ActiveChain().Next(target), which has no answer off-chain.
    (unless (eq (bitcoin-lisp.storage:get-block-at-height chain-state target-height)
                target-entry)
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "Block is not in the active chain"))
    ;; Pruned node: rolling back needs every block in (target, tip] (and its
    ;; undo) still on disk to disconnect down and reconnect afterwards (Core
    ;; checks GetFirstBlock(BLOCK_HAVE_MASK) <= target, rpc/blockchain.cpp:
    ;; 3139-3149). Our pruned horizon is the pruned-height cursor.
    (when (and (bitcoin-lisp:pruning-enabled-p)
               (<= target-height
                   (bitcoin-lisp.storage:chain-state-pruned-height chain-state)))
      (error 'rpc-error :code +rpc-misc-error+
                        :message "Could not roll back to requested height since necessary block data is already pruned."))
    (let ((invalidate-hash
            (bitcoin-lisp.storage:block-index-entry-hash
             (bitcoin-lisp.storage:get-block-at-height
              chain-state (1+ target-height))))
          (block-store (rpc-get-block-store node))
          (utxo-set (rpc-get-utxo-set node))
          (mempool (rpc-get-mempool node))
          (tx-index (rpc-get-tx-index node))
          (was-active (bitcoin-lisp::node-network-active node)))
      ;; NetworkDisable: skipped when the network is already off, so we don't
      ;; re-enable it behind the user's back at the end.
      (when was-active
        (%set-network-active node nil))
      (unwind-protect
           (unwind-protect
                (progn
                  ;; Node lock around the rollback mutation only, not the
                  ;; (long) snapshot streaming: with the network disabled no
                  ;; new blocks arrive, so the rolled-back chain stays put
                  ;; while the dump runs unlocked.
                  (with-node-lock (node)
                    (multiple-value-bind (ok reason)
                        (bitcoin-lisp.validation:invalidate-block
                         chain-state block-store utxo-set invalidate-hash
                         :mempool mempool :tx-index tx-index)
                      (unless ok
                        (error 'rpc-error :code +rpc-misc-error+
                                          :message (format nil "Could not roll back to requested height. (~A)"
                                                           (string-downcase (symbol-name reason))))))
                    ;; The new tip must be the target: a block-read failure or a
                    ;; stale equal-work sister of the invalidated block would
                    ;; land elsewhere (Core rpc/blockchain.cpp:3178-3187).
                    (unless (equalp (bitcoin-lisp.storage:best-block-hash chain-state)
                                    target-hash)
                      (error 'rpc-error :code +rpc-misc-error+
                                        :message "Could not roll back to requested height.")))
                  (%write-utxo-snapshot node chain-state utxo-set path))
             ;; ~TemporaryRollback: always reconsider, even on error —
             ;; harmless if the invalidation never took effect.
             (with-node-lock (node)
               (bitcoin-lisp.validation:reconsider-block
                chain-state block-store utxo-set invalidate-hash
                :mempool mempool :tx-index tx-index)))
        ;; ~NetworkDisable (runs after the rollback is undone, like Core's
        ;; reverse member-destruction order).
        (when was-active
          (%set-network-active node t))))))

(defun rpc-dumptxoutset (node params)
  "Write the UTXO set to PATH in Bitcoin Core's snapshot v2 format
(dumptxoutset, rpc/blockchain.cpp:3052-3323). PARAMS: (path [type]
[options]) — type \"latest\" dumps at the current tip; \"rollback\" (or an
options object {\"rollback\": height-or-hash}) temporarily rolls the active
chain back to a historical block (network suspended for the duration, then
restored) and dumps the historical UTXO set, defaulting to the highest
chainparams assumeutxo snapshot height. Like gettxoutsetinfo this forces a
coins-cache flush, then streams coins in cursor order while accumulating
hash_serialized_3 over the same pass. Writes to PATH.incomplete and renames
on completion. nchaintx is omitted when some block's tx count is unknown
(header-only/pruned ancestors; Core reports its cached nChainTx)."
  (let ((path (first params))
        (type (if (stringp (second params)) (second params) ""))
        (options (third params)))
    (unless (and (stringp path) (plusp (length path)))
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "path required"))
    (let* ((chain-state (rpc-get-chain-state node))
           (tip-hash (or (bitcoin-lisp.storage:best-block-hash chain-state)
                         (error 'rpc-error :code +rpc-misc-error+
                                           :message "Chain has no tip")))
           (tip-entry (bitcoin-lisp.storage:get-block-index-entry
                       chain-state tip-hash))
           (target-entry (%dump-rollback-target-entry
                          node chain-state tip-entry type options)))
      (when (probe-file path)
        (error 'rpc-error :code +rpc-invalid-parameter+
                          :message (format nil "~A already exists. If you are sure this is what you want, move it out of the way first" path)))
      ;; Dumping at the current tip needs no rollback at all (Core
      ;; rpc/blockchain.cpp:3136-3138).
      (if (eq target-entry tip-entry)
          (%write-utxo-snapshot node chain-state (rpc-get-utxo-set node) path)
          (%dump-txoutset-with-rollback node chain-state target-entry path)))))

(defun %write-utxo-snapshot (node chain-state utxo-set path)
  "Stream CHAIN-STATE's UTXO set to PATH in snapshot v2 format at its
current tip (Core PrepareUTXOSnapshot + WriteUTXOSnapshot, rpc/
blockchain.cpp:3208-3323) and return dumptxoutset's result alist."
  (let* ((base-hash (bitcoin-lisp.storage:best-block-hash chain-state))
         (base-height (bitcoin-lisp.storage:current-height chain-state))
         (base-entry (bitcoin-lisp.storage:get-block-index-entry chain-state base-hash))
         (temppath (concatenate 'string path ".incomplete"))
         (digest (ironclad:make-digest :sha256))
         (count 0)
         (renamed nil))
    (unwind-protect
         (progn
           (with-open-file (out temppath :direction :output :if-exists :supersede
                                         :element-type '(unsigned-byte 8))
             ;; SnapshotMetadata (node/utxo_snapshot.h:63-70); the coin
             ;; count is back-patched after the streaming pass.
             (write-sequence +snapshot-magic-bytes+ out)
             (bitcoin-lisp.serialization:write-uint16-le out +snapshot-version+)
             (write-sequence (bitcoin-lisp:network-magic (rpc-get-network node)) out)
             (write-sequence base-hash out)
             (bitcoin-lisp.serialization:write-uint64-le out 0)
             ;; Coins grouped per txid (WriteUTXOSnapshot, rpc/
             ;; blockchain.cpp:3246-3308). utxo-set-iterate's cursor
             ;; order contract makes groups contiguous and vouts
             ;; ascending; the same pass feeds hash_serialized_3.
             (let ((group-txid nil)
                   (group '()))
               (flet ((flush-group ()
                        (when group
                          (let ((buf (bitcoin-lisp.serialization:make-byte-buf)))
                            (bitcoin-lisp.serialization:bb-write-bytes buf group-txid)
                            (bitcoin-lisp.serialization:bb-write-varint buf (length group))
                            (dolist (pair (nreverse group))
                              (let ((vout (car pair))
                                    (entry (cdr pair)))
                                (bitcoin-lisp.serialization:bb-write-varint buf vout)
                                (bitcoin-lisp.serialization:bb-write-compressed-coin
                                 buf
                                 (bitcoin-lisp.storage:utxo-entry-height entry)
                                 (bitcoin-lisp.storage:utxo-entry-coinbase entry)
                                 (bitcoin-lisp.storage:utxo-entry-value entry)
                                 (bitcoin-lisp.storage:utxo-entry-script-pubkey entry))))
                            (write-sequence (bitcoin-lisp.serialization:bb-finish buf) out))
                          (setf group '()))))
                 (bitcoin-lisp.storage:utxo-set-iterate
                  utxo-set
                  (lambda (txid vout entry)
                    (unless (and group-txid (equalp txid group-txid))
                      (flush-group)
                      (setf group-txid txid))
                    (push (cons vout entry) group)
                    (ironclad:update-digest
                     digest (bitcoin-lisp.storage:coin-muhash-element* txid vout entry))
                    (incf count)))
                 (flush-group)))
             (file-position out +snapshot-count-offset+)
             (bitcoin-lisp.serialization:write-uint64-le out count))
           (rename-file temppath path)
           (setf renamed t))
      (unless renamed (ignore-errors (delete-file temppath))))
    (let ((hash (bitcoin-lisp.crypto:sha256 (ironclad:produce-digest digest)))
          (nchaintx (and base-entry
                         (%chain-tx-count base-entry (rpc-get-block-store node)))))
      `(("coins_written" . ,count)
        ("base_hash" . ,(hash-to-hex base-hash))
        ("base_height" . ,base-height)
        ("path" . ,(namestring (truename path)))
        ("txoutset_hash" . ,(hash-to-hex hash))
        ,@(when nchaintx `(("nchaintx" . ,nchaintx)))))))

(defun %read-snapshot-metadata (in network)
  "Read and validate a snapshot file's SnapshotMetadata against NETWORK
(node/utxo_snapshot.h:73-106 Unserialize). Returns (values base-blockhash
coins-count). Signals +rpc-deserialization-error+ on any mismatch, matching
Core loadtxoutset's \"Unable to parse metadata\" wrapper."
  (flet ((bad (fmt &rest args)
           (error 'rpc-error :code +rpc-deserialization-error+
                             :message (format nil "Unable to parse metadata: ~A"
                                              (apply #'format nil fmt args)))))
    (handler-case
        (progn
          (unless (equalp (bitcoin-lisp.serialization:read-bytes in 5)
                          +snapshot-magic-bytes+)
            (bad "Invalid UTXO set snapshot magic bytes. Please check if this is indeed a snapshot file or if you are using an outdated snapshot format."))
          (let ((version (bitcoin-lisp.serialization:read-uint16-le in)))
            (unless (= version +snapshot-version+)
              (bad "Version of snapshot ~D does not match any of the supported versions." version)))
          (let ((magic (bitcoin-lisp.serialization:read-bytes in 4)))
            (unless (equalp magic (bitcoin-lisp:network-magic network))
              (let ((theirs (%network-for-magic magic)))
                (if theirs
                    (bad "The network of the snapshot (~A) does not match the network of this node (~A)."
                         (%chain-name theirs) (%chain-name network))
                    (bad "This snapshot has been created for an unrecognized network. This could be a custom signet, a new testnet or possibly caused by data corruption.")))))
          (values (bitcoin-lisp.serialization:read-bytes in 32)
                  (bitcoin-lisp.serialization:read-uint64-le in)))
      (rpc-error (e) (error e))
      (error () (bad "truncated snapshot header")))))

(defparameter *snapshot-load-batch-coins* 100000
  "How many coins to stream into the snapshot chainstate's LevelDB per
durable write batch (%populate-snapshot-chainstate). This bounds only the
LevelDB commit cadence, NOT the coin-count accounting: a txid group is atomic
and may push a batch past this budget rather than straddle a commit. Tests
bind it small to exercise the multi-batch path.")

(defun %map-snapshot-coins (in global-remaining batch-budget coin-fn mismatch-fn)
  "Read whole txid groups from the snapshot coin stream IN, driving COIN-FN
(txid vout height coinbase value script) per coin, until at least
BATCH-BUDGET coins are consumed or GLOBAL-REMAINING is reached
(PopulateAndValidateSnapshot's read loop, validation.cpp:5816-5882). Groups
are atomic: the last group of a batch may push the tally past BATCH-BUDGET
and is still consumed whole, so a group NEVER straddles a durable-write
boundary. MISMATCH-FN (no args) fires when a group claims more coins than
GLOBAL-REMAINING has left — Core's coins_per_txid > coins_left guard
(validation.cpp:5823), which is against the GLOBAL remaining count, never a
per-batch budget. Returns the number of coins consumed in this call."
  (let ((consumed 0))
    (loop while (and (< consumed batch-budget) (< consumed global-remaining))
          do (let ((txid (bitcoin-lisp.serialization:read-bytes in 32))
                   (ncoins (bitcoin-lisp.serialization:read-compact-size in)))
               (when (> ncoins (- global-remaining consumed))
                 (funcall mismatch-fn))
               (dotimes (i ncoins)
                 (let ((vout (bitcoin-lisp.serialization:read-compact-size in)))
                   (multiple-value-bind (height coinbase value script)
                       (bitcoin-lisp.serialization:read-compressed-coin in)
                     (funcall coin-fn txid vout height coinbase value script)
                     (incf consumed))))))
    consumed))

(defun %populate-snapshot-chainstate (node in au base-hash base-entry
                                      base-height coins-count fail)
  "Populate + verify + adopt a snapshot chainstate from the coin stream IN
(Core PopulateAndValidateSnapshot, validation.cpp:5773-5973, plus the
adoption tail of ActivateSnapshot). Coins stream straight into the new
chainstate's own LevelDB in durable batches with Core's per-coin checks
(validation.cpp:5834-5845); the commitment hash is then computed over the
POPULATED set (Core hashes the new DB), so even a snapshot whose stream
order differs from cursor order verifies correctly. On success the tip is
set to the base, the base_blockhash marker and state file are written, the
base entry's tx-count is seeded from the commitment's nChainTx (Core
validation.cpp:5938-5967), and the chainstate is adopted as current. Any
failure tears the snapshot chainstate down (dir deleted) via FAIL, a
function of (format-string &rest args) that must signal."
  (let ((snap (bitcoin-lisp::create-snapshot-chainstate node base-hash))
        (adopted nil))
    (unwind-protect
         (let* ((view (bitcoin-lisp.storage:chain-state-coins-view snap))
                (base-db (bitcoin-lisp.storage:coins-view-cache-base view))
                (processed 0))
           (flet ((put-coin (batch txid vout height coinbase value script)
                    (when (or (> height base-height) (>= vout #xFFFFFFFF))
                      (funcall fail "Bad snapshot data after deserializing ~D coins"
                               processed))
                    (when (or (minusp value)
                              (> value bitcoin-lisp.validation:+max-money+))
                      (funcall fail "Bad snapshot data after deserializing ~D coins - bad tx out value"
                               processed))
                    (bitcoin-lisp.storage:coins-view-batch-put
                     batch
                     (bitcoin-lisp.storage::make-utxo-key txid vout)
                     (bitcoin-lisp.storage:make-utxo-entry
                      :value value :script-pubkey script
                      :height height :coinbase coinbase))
                    (incf processed)))
             (handler-case
                 (loop while (< processed coins-count)
                       do (bitcoin-lisp.storage:with-coins-view-batch
                              (batch base-db :sync t)
                            ;; GLOBAL remaining drives the mismatch guard; the
                            ;; batch budget only bounds this LevelDB commit, so
                            ;; a txid group can overrun it without tripping a
                            ;; false coins-count mismatch (put-coin advances
                            ;; PROCESSED as each coin lands).
                            (%map-snapshot-coins
                             in (- coins-count processed) *snapshot-load-batch-coins*
                             (lambda (txid vout height coinbase value script)
                               (put-coin batch txid vout height coinbase value script))
                             (lambda ()
                               (funcall fail "Mismatch in coins count in snapshot metadata and actual snapshot data")))))
               (rpc-error (e) (error e))
               (error ()
                 (funcall fail "Bad snapshot format or truncated snapshot after deserializing ~D coins"
                          processed))))
           (unless (eq :eof (read-byte in nil :eof))
             (funcall fail "Bad snapshot - coins left over after deserializing ~D coins"
                      coins-count))
           ;; hash_serialized_3 over the POPULATED set vs the chainparams
           ;; commitment (Core ComputeUTXOStats over the new DB,
           ;; validation.cpp:5921-5936).
           (let ((got (bitcoin-lisp.storage:compute-utxo-set-hash view))
                 (want (bitcoin-lisp:assumeutxo-data-hash-serialized au)))
             (unless (equalp got want)
               (funcall fail "Bad snapshot content hash: expected ~A, got ~A"
                        (hash-to-hex want) (hash-to-hex got))))
           ;; Verified: finalize and adopt.
           (bitcoin-lisp.storage:update-chain-tip snap base-hash base-height)
           (bitcoin-lisp.storage:write-snapshot-base-blockhash snap)
           (bitcoin-lisp.storage:save-state snap)
           (setf (bitcoin-lisp.storage:block-index-entry-tx-count base-entry)
                 (bitcoin-lisp:assumeutxo-data-chain-tx-count au))
           (bitcoin-lisp::add-snapshot-chainstate node snap)
           (setf adopted t)
           (bitcoin-lisp::node-log
            :info "RPC loadtxoutset: loaded ~D coins, hash_serialized_3 verified, snapshot chainstate active at h=~D"
            coins-count base-height))
      (unless adopted
        (bitcoin-lisp::abort-snapshot-chainstate node snap)))))

(defun rpc-loadtxoutset (node params)
  "Load a Bitcoin Core-format UTXO snapshot (loadtxoutset). PARAMS: (path).

This is Core's ActivateSnapshot + PopulateAndValidateSnapshot flow
(validation.cpp:5607-5973): preconditions (chainparams commitment, base
header known + on the best header chain + not invalid, empty mempool, more
work than the active tip), then the snapshot streams into a NEW chainstate's
own coins LevelDB at chainstate_snapshot/ with per-coin checks
(height/vout/MoneyRange), exact-EOF, and hash_serialized_3 over the
populated set compared to the committed hash. Any failure deletes the
snapshot chainstate dir and leaves the node untouched. On success the
base_blockhash marker is written (the only persistent snapshot-exists
marker, re-detected at startup), the snapshot chainstate becomes the
CURRENT chainstate following the network tip, and the previous chainstate is
retargeted at the base — it keeps validating history in the background. The
base entry's tx-count is seeded from the commitment's nChainTx, mirroring
Core's faked m_chain_tx_count (validation.cpp:5966).

The sync thread is paused for the duration (our stand-in for Core holding
cs_main), so the chainstates list never changes under a running IBD pass.
Pruned nodes are supported (P6): the snapshot chainstate's per-chainstate
prune floor (chain-state-prune-floor — Core Chainstate::GetPruneRange) keeps
every block at or below the base on disk until background validation
completes, and the automatic prune target is halved while the historical
chainstate exists (effective-prune-target-bytes)."
  (let ((path (first params)))
    (unless (and (stringp path) (plusp (length path)))
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "path required"))
    (unless (probe-file path)
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message (format nil "Couldn't open file ~A for reading." path)))
    (flet ((load-error (fmt &rest args)
             ;; Core wraps every activation failure as RPC_INTERNAL_ERROR
             ;; "Unable to load UTXO snapshot: <reason>. (<path>)".
             (error 'rpc-error :code +rpc-internal-error+
                               :message (format nil "Unable to load UTXO snapshot: ~A. (~A)"
                                                (apply #'format nil fmt args) path))))
      (let* ((network (rpc-get-network node))
             (chain-state (rpc-get-chain-state node))
             (mempool (rpc-get-mempool node)))
        (with-open-file (in path :direction :input :element-type '(unsigned-byte 8))
          (multiple-value-bind (base-hash coins-count)
              (%read-snapshot-metadata in network)
            ;; --- Preconditions (ActivateSnapshot, validation.cpp:5616-5650) ---
            (when (bitcoin-lisp.storage:chain-state-from-snapshot-blockhash chain-state)
              (load-error "Can't activate a snapshot-based chainstate more than once"))
            (let ((au (bitcoin-lisp:assumeutxo-data-for-blockhash network base-hash))
                  (base-entry (bitcoin-lisp.storage:get-block-index-entry
                               chain-state base-hash)))
              (unless au
                (load-error "assumeutxo block hash in snapshot metadata not recognized (hash: ~A). The following snapshot heights are available: ~{~D~^, ~}"
                            (hash-to-hex base-hash)
                            (sort (mapcar #'bitcoin-lisp:assumeutxo-data-height
                                          (bitcoin-lisp:network-assumeutxo-data network))
                                  #'<)))
              (unless base-entry
                (load-error "The base block header (~A) must appear in the headers chain. Make sure all headers are syncing, and call loadtxoutset again"
                            (hash-to-hex base-hash)))
              (when (eq (bitcoin-lisp.storage:block-index-entry-status base-entry) :invalid)
                (load-error "The base block header (~A) is part of an invalid chain"
                            (hash-to-hex base-hash)))
              (let ((base-height (bitcoin-lisp.storage:block-index-entry-height base-entry)))
                (unless (= base-height (bitcoin-lisp:assumeutxo-data-height au))
                  (load-error "Assumeutxo height in snapshot metadata not recognized (~D) - refusing to load snapshot"
                              base-height))
                ;; The base must lie on the best header chain (Core
                ;; m_best_header->GetAncestor(height) == base).
                (let ((best (bitcoin-lisp.storage:best-header-entry chain-state)))
                  (unless (and best
                               (eq (bitcoin-lisp.storage:entry-ancestor-at-height
                                    best base-height)
                                   base-entry))
                    (load-error "A forked headers-chain with more work than the chain with the snapshot base block header exists. Please proceed to sync without AssumeUtxo.")))
                ;; The snapshot must be a more-work chain than the active tip
                ;; (Core CBlockIndexWorkComparator; height as the tiebreak
                ;; for work-less synthetic chains in tests).
                (let* ((tip-entry (bitcoin-lisp.storage:get-block-index-entry
                                   chain-state
                                   (bitcoin-lisp.storage:best-block-hash chain-state)))
                       (tip-height (bitcoin-lisp.storage:current-height chain-state))
                       (tip-work (if tip-entry
                                     (bitcoin-lisp.storage:block-index-entry-chain-work
                                      tip-entry)
                                     0))
                       (base-work (bitcoin-lisp.storage:block-index-entry-chain-work
                                   base-entry)))
                  (unless (or (> base-work tip-work)
                              (and (= base-work tip-work) (> base-height tip-height)))
                    (load-error "Work does not exceed active chainstate (node already at or past height ~D)"
                                base-height)))
                (when (and mempool (plusp (bitcoin-lisp.mempool:mempool-count mempool)))
                  (load-error "Can't activate a snapshot when mempool not empty"))
                ;; --- Populate + verify into a NEW snapshot chainstate ---
                ;; (see %populate-snapshot-chainstate). Any failure leaves
                ;; the node untouched.
                (bitcoin-lisp::call-with-sync-paused
                 node
                 (lambda ()
                   (%populate-snapshot-chainstate
                    node in au base-hash base-entry base-height coins-count
                    #'load-error)))
                `(("coins_loaded" . ,coins-count)
                  ("tip_hash" . ,(hash-to-hex base-hash))
                  ("base_height" . ,base-height)
                  ("path" . ,(namestring (truename path))))))))))))

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
    ;; Node lock: the dump iterates entries, deltas, and the unbroadcast
    ;; set; a concurrent sync-thread mutation would tear the snapshot
    ;; (Core DumpMempool snapshots under pool.cs).
    (with-node-lock (node)
      (bitcoin-lisp.mempool:save-mempool-file (rpc-get-mempool node) path))
    `(("filename" . ,(namestring path)))))

(defun rpc-importmempool (node params)
  "Load transactions from a mempool.dat-format file at FILEPATH through the normal
acceptance path (Bitcoin Core importmempool). PARAMS: (filepath [options]).
Entries are validated against the current UTXO set; their prioritisation deltas
are applied. The options object supports apply_unbroadcast_set (default false,
Core rpc/mempool.cpp:1115-1116: only restore the file's unbroadcast set when
asked — unlike the startup load, where it defaults on);
apply_fee_delta_priority/use_current_time remain no-ops. Returns an empty
object."
  (let ((filepath (first params))
        (options (second params)))
    (unless (and (stringp filepath) (plusp (length filepath)))
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "filepath must be a string"))
    (let ((path (probe-file filepath))
          (apply-unbroadcast (and (hash-table-p options)
                                  (gethash "apply_unbroadcast_set" options)
                                  t)))
      (unless path
        (error 'rpc-error :code +rpc-invalid-parameter+
                          :message (format nil "Can't open mempool file ~A" filepath)))
      ;; Node lock: the import validates and inserts every entry against
      ;; the live UTXO set/mempool — it must not interleave with the sync
      ;; thread (Core importmempool holds cs_main + pool.cs through
      ;; LoadMempool, rpc/mempool.cpp:1130).
      (unless (with-node-lock (node)
                (bitcoin-lisp::load-mempool-from-disk
                 node path :apply-unbroadcast apply-unbroadcast))
        (error 'rpc-error :code +rpc-misc-error+
                          :message "Unable to import mempool file (unreadable or corrupt)")))
    ;; Core returns an empty object; an empty hash-table serializes as {}.
    (make-hash-table :test 'equal)))

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
    ;; Node lock: mempool-prioritise mutates the deltas table and the
    ;; entry's modified fee/txgraph position (Core PrioritiseTransaction
    ;; takes pool.cs).
    (with-node-lock (node)
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
      t))))

(defun rpc-getprioritisedtransactions (node params)
  "Map of all prioritisetransaction fee deltas by txid (Bitcoin Core
getprioritisedtransactions): fee_delta, in_mempool, and modified_fee when the
tx is currently in the mempool."
  (declare (ignore params))
  (let ((mempool (rpc-get-mempool node))
        (result '()))
    ;; Node lock: prioritisetransaction (RPC threads) and acceptance paths
    ;; (sync thread) both write the deltas table this iterates.
    (with-node-lock (node)
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
       (bitcoin-lisp.mempool:mempool-deltas mempool)))
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

(defun rpc-stop (node params)
  "Request a graceful node shutdown (Bitcoin Core stop). stop-node also stops the
RPC server serving this request, so defer it to a short-lived thread and let
this response flush first."
  (declare (ignore node params))
  (bt:make-thread (lambda () (sleep 0.3) (ignore-errors (bitcoin-lisp::stop-node)))
                  :name "rpc-stop")
  "Bitcoin-lisp server stopping")

(defun rpc-getnetworkhashps (node params)
  "Estimated network hashes/sec over the last N blocks (default 120), from the
chain-work and time spanned (Bitcoin Core getnetworkhashps)."
  (let* ((nblocks (let ((n (first params))) (if (and (integerp n) (> n 0)) n 120)))
         (chain-state (rpc-get-chain-state node))
         (height (bitcoin-lisp.storage:current-height chain-state))
         (tip (bitcoin-lisp.storage:get-block-index-entry
               chain-state (bitcoin-lisp.storage:best-block-hash chain-state))))
    (if (or (null tip) (<= height 0))
        0
        (let* ((window (min nblocks height))
               (start (bitcoin-lisp.storage:get-block-at-height chain-state (- height window))))
          (if (null start)
              0
              (let ((dwork (- (bitcoin-lisp.storage:block-index-entry-chain-work tip)
                              (bitcoin-lisp.storage:block-index-entry-chain-work start)))
                    (dtime (- (bitcoin-lisp.serialization:block-header-timestamp
                               (bitcoin-lisp.storage:block-index-entry-header tip))
                              (bitcoin-lisp.serialization:block-header-timestamp
                               (bitcoin-lisp.storage:block-index-entry-header start)))))
                (if (<= dtime 0) 0 (round dwork dtime))))))))

(defun rpc-getmemoryinfo (node params)
  "Report process memory use (Bitcoin Core getmemoryinfo). Reports the SBCL heap
under the \"locked\" object Core uses."
  (declare (ignore node params))
  (let ((used #+sbcl (sb-kernel:dynamic-usage) #-sbcl 0)
        (total #+sbcl (sb-ext:dynamic-space-size) #-sbcl 0))
    `(("locked" . (("used" . ,used)
                   ("total" . ,total)
                   ("free" . ,(max 0 (- total used)))
                   ("locked" . 0)
                   ("chunks_used" . 0)
                   ("chunks_free" . 0))))))

(defun rpc-logging (node params)
  "Get or set the active debug-logging categories (Bitcoin Core logging). PARAMS:
([include] [exclude]) — arrays of category names to enable / disable; \"all\"
(or \"1\") toggles every category. Returns an object mapping every category to
whether it is currently enabled. Errors on an unknown category."
  (declare (ignore node))
  (let ((include (first params))
        (exclude (second params)))
    (when (and include (not (listp include)))
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "include must be an array"))
    (when (and exclude (not (listp exclude)))
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "exclude must be an array"))
    (dolist (cat include)
      (unless (and (stringp cat) (bitcoin-lisp::enable-log-category cat))
        (error 'rpc-error :code +rpc-invalid-parameter+
                          :message (format nil "unknown logging category ~A" cat))))
    (dolist (cat exclude)
      (unless (and (stringp cat) (bitcoin-lisp::disable-log-category cat))
        (error 'rpc-error :code +rpc-invalid-parameter+
                          :message (format nil "unknown logging category ~A" cat))))
    (mapcar (lambda (c) (cons c (bitcoin-lisp:log-category-enabled-p c)))
            bitcoin-lisp::+log-categories+)))

(defun rpc-getrpcinfo (node params)
  "Report RPC server state (Bitcoin Core getrpcinfo): active commands (we don't
track in-flight requests, so empty) and the log file path."
  (declare (ignore node params))
  `(("active_commands" . #())
    ("logpath" . ,(or (and bitcoin-lisp::*log-file-stream*
                           (ignore-errors
                            (namestring (pathname bitcoin-lisp::*log-file-stream*))))
                      ""))))

(defun rpc-help (node params)
  "List available RPC methods, or echo the name of a known one (Bitcoin Core
help). A full per-method help text is out of scope."
  (declare (ignore node))
  (let ((method (first params)))
    (if (and method (stringp method))
        (if (gethash method *rpc-methods*)
            method
            (format nil "help: unknown command: ~A" method))
        (let ((names '()))
          (maphash (lambda (k v) (declare (ignore v)) (push k names)) *rpc-methods*)
          (format nil "~{~A~^~%~}" (sort names #'string<))))))

(defun rpc-getindexinfo (node params)
  "Report the status of optional indexes (Bitcoin Core getindexinfo): txindex,
the basic block filter index, and coinstatsindex -- each reported only when
enabled. An optional index-name argument filters to a single index (empty object
if it is not an enabled index). Every index is maintained inline as blocks
connect, so a present index normally tracks the tip; \"synced\" reflects whether
its best indexed block has reached the current tip."
  (let* ((name (and (consp params) (first params)))
         (tip (bitcoin-lisp.storage:current-height (rpc-get-chain-state node)))
         (tx-index (rpc-get-tx-index node))
         (bfi (rpc-get-blockfilterindex node))
         (csi (rpc-get-coinstatsindex node))
         (entries '()))
    (flet ((add (key enabled-p height)
             (when (and enabled-p (or (null name) (string= name key)))
               (push `(,key . (("synced" . ,(>= height tip))
                               ("best_block_height" . ,height)))
                     entries))))
      ;; txindex has no separate best-height accessor; it tracks the tip inline.
      (add "txindex"
           (and tx-index (bitcoin-lisp.storage:tx-index-enabled tx-index))
           tip)
      (add "basic block filter index"
           (and bfi (bitcoin-lisp.storage:blockfilterindex-enabled bfi))
           (if bfi (bitcoin-lisp.storage:blockfilterindex-height bfi) -1))
      (add "coinstatsindex"
           (and csi (bitcoin-lisp.storage:coinstatsindex-enabled csi))
           (if csi (bitcoin-lisp.storage:coinstatsindex-height csi) -1)))
    ;; No matching active index -> empty JSON object.
    (if entries (nreverse entries) (make-hash-table :test 'equal))))

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
      ;; Script-verify flags active for a block at the tip (Core script_flags).
      ("script_flags" . ,(bitcoin-lisp.validation::mandatory-script-flags-list height))
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
          ;; Wire encoding (Core EncodeHexTx): a witnessless tx must NOT carry
          ;; marker/flag or the reconstructed block fails Core deserialization
          ;; with "Superfluous witness record".
          collect `(("data" . ,(bitcoin-lisp.crypto:bytes-to-hex
                                (bitcoin-lisp.serialization:transaction-wire-bytes tx)))
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
implicit default mode is supported (no longpoll / proposal). Fields mirror Core.
The template is assembled as a full block around a dummy OP_TRUE coinbase (Core's
scriptDummy) and dry-run through TestBlockValidity (Core CreateNewBlock,
node/miner.cpp:227-231) — an invalid template errors here instead of reaching a
miner."
  (declare (ignore params))
  (let* ((chain-state (rpc-get-chain-state node))
         (mempool (rpc-get-mempool node))
         ;; Node lock around the whole assembly: the chunk walk locks
         ;; internally (assembler %with-mempool-lock), but the template's
         ;; height/prev/finality context and its TestBlockValidity dry run
         ;; must see the SAME tip the transactions were selected against
         ;; (Core CreateNewBlock holds cs_main + pool.cs end-to-end,
         ;; node/miner.cpp:151).
         (template (with-node-lock (node)
                     (nth-value 1 (bitcoin-lisp.mining:assemble-full-block
                                   chain-state mempool
                                   :coinbase-script-pubkey
                                   (make-array 1 :element-type '(unsigned-byte 8)
                                                 :initial-element #x51) ; OP_TRUE
                                   :utxo-set (rpc-get-utxo-set node)))))
         (bits (bitcoin-lisp.mining:block-template-bits template)))
    `(("capabilities" . ("proposal"))
      ("version" . ,(bitcoin-lisp.mining:block-template-version template))
      ("previousblockhash" . ,(hash-to-hex (bitcoin-lisp.mining:block-template-prev-hash template)))
      ("transactions" . ,(%gbt-transactions template))
      ("coinbaseaux" . ,(make-hash-table :test 'equal))
      ("coinbasevalue" . ,(bitcoin-lisp.mining:block-template-coinbase-value template))
      ("target" . ,(%bits-to-target-hex bits))
      ("mintime" . ,(bitcoin-lisp.mining:block-template-mintime template))
      ("mutable" . ("time" "transactions" "prevblock"))
      ("noncerange" . "00000000ffffffff")
      ("sigoplimit" . ,bitcoin-lisp.validation:+max-block-sigops-cost+)
      ("sizelimit" . 4000000)          ; MAX_BLOCK_SERIALIZED_SIZE
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
  (with-node-lock (node)                 ; consistent tip + pool count snapshot
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
      ("warnings" . #())))))

(defun %activate-submitted-block (node block)
  "Validate+activate BLOCK through the consensus path. Returns the activate-block
(values ok reason). Holds the node lock: activation mutates the chainstate,
UTXO set, and mempool exactly like a network block, which the sync thread
only ever does under the lock (Core ProcessNewBlock takes cs_main)."
  (with-node-lock (node)
    (bitcoin-lisp.validation:activate-block
     block
     (rpc-get-chain-state node)
     (rpc-get-block-store node)
     (rpc-get-utxo-set node)
     :mempool (rpc-get-mempool node)
     :tx-index (rpc-get-tx-index node))))

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
      ;; Node lock: the duplicate probe and the activation must see one
      ;; chain state (Core submitblock reads the index and calls
      ;; ProcessNewBlock under cs_main); the lock is recursive, so the
      ;; nested %activate-submitted-block lock is free.
      (with-node-lock (node)
       (let* ((hash (bitcoin-lisp.serialization:block-header-hash
                    (bitcoin-lisp.serialization:bitcoin-block-header block)))
             (entry (bitcoin-lisp.storage:get-block-index-entry chain-state hash)))
        (when entry
          ;; A known-invalid block short-circuits (Core AcceptBlockHeader,
          ;; validation.cpp:4231-4235 — BLOCK_FAILED_VALID → "duplicate-invalid").
          (when (eq (bitcoin-lisp.storage:block-index-entry-status entry) :invalid)
            (return-from rpc-submitblock "duplicate-invalid"))
          ;; "duplicate" only when we already HAVE the block data (Core
          ;; AcceptBlock fAlreadyHave = BLOCK_HAVE_DATA, validation.cpp:4351;
          ;; submitblock's accepted && !new_block, rpc/mining.cpp:1091-1093).
          ;; A header-only index entry (headers-sync / submitheader) must
          ;; proceed to full processing or the mined block is silently lost.
          (let ((store (rpc-get-block-store node)))
            (when (and store (bitcoin-lisp.storage:block-exists-p store hash))
              (return-from rpc-submitblock "duplicate"))))
        (multiple-value-bind (ok reason) (%activate-submitted-block node block)
          (cond
            (ok nil)                        ; accepted → JSON null (BIP22 success)
            ;; A valid block stored on a weaker side chain is still accepted.
            ((eq reason :weaker-chain) nil)
            (t (string-downcase (symbol-name reason))))))))))

(defun rpc-submitheader (node params)
  "Validate and add a block header to the header index (Bitcoin Core
submitheader). PARAMS: (hexdata) — an 80-byte serialized header. The previous
header must already be known. Returns null on success (including an already-known
header); errors if the parent is missing or the header fails validation."
  (let ((hex (first params)))
    (unless (and (stringp hex) (plusp (length hex)))
      (error 'rpc-error :code +rpc-deserialization-error+ :message "Block header decode failed"))
    (let ((header (handler-case
                      (let ((bytes (bitcoin-lisp.crypto:hex-to-bytes hex)))
                        (flexi-streams:with-input-from-sequence (s bytes)
                          (bitcoin-lisp.serialization::read-block-header s)))
                    (error ()
                      (error 'rpc-error :code +rpc-deserialization-error+
                                        :message "Block header decode failed"))))
          (chain-state (rpc-get-chain-state node)))
      ;; Node lock: process-headers mutates the header index the sync
      ;; thread's headers-sync also writes (Core ProcessNewBlockHeaders
      ;; takes cs_main).
      (with-node-lock (node)
       (let ((hash (bitcoin-lisp.serialization:block-header-hash header))
            (prev (bitcoin-lisp.serialization:block-header-prev-block header)))
        ;; Already known → success (Core returns null).
        (when (bitcoin-lisp.storage:get-block-index-entry chain-state hash)
          (return-from rpc-submitheader nil))
        ;; Parent must be present first (Core's LookupBlockIndex check).
        (unless (bitcoin-lisp.storage:get-block-index-entry chain-state prev)
          (error 'rpc-error :code +rpc-verify-error+
                            :message (format nil "Must submit previous header (~A) first"
                                             (hash-to-hex prev))))
        ;; Validate (PoW/MTP/difficulty) then add to the index.
        (multiple-value-bind (valid err)
            (bitcoin-lisp.networking::validate-header-chain (list header) chain-state)
          (unless valid
            (error 'rpc-error :code +rpc-verify-error+
                              :message (or err "header validation failed")))
          (bitcoin-lisp.networking::process-headers valid chain-state))
        nil)))))

(defun %generate-to-script-pubkey (node script-pubkey nblocks maxtries)
  "Mine NBLOCKS blocks whose coinbase pays SCRIPT-PUBKEY, activating each through
the normal consensus path. Returns the list of mined block hashes (hex). Shared
by generatetoaddress and generatetodescriptor."
  (let ((chain-state (rpc-get-chain-state node))
        (mempool (rpc-get-mempool node))
        (hashes '()))
    (dotimes (i nblocks (nreverse hashes))
      ;; Assemble under the node lock (one consistent tip+mempool view);
      ;; grind the nonce OUTSIDE it — Core likewise drops cs_main between
      ;; CreateNewBlock and ProcessNewBlock (rpc/mining.cpp GenerateBlocks),
      ;; and a stale-template block simply fails activation below.
      (let ((block (with-node-lock (node)
                     (bitcoin-lisp.mining:assemble-full-block
                      chain-state mempool :coinbase-script-pubkey script-pubkey
                      ;; TestBlockValidity before mining (Core CreateNewBlock).
                      :utxo-set (rpc-get-utxo-set node)))))
        (unless (bitcoin-lisp.mining:mine-block block :max-tries maxtries)
          (error 'rpc-error :code +rpc-misc-error+ :message "Failed to find a valid nonce"))
        (multiple-value-bind (ok reason) (%activate-submitted-block node block)
          (unless ok
            (error 'rpc-error :code +rpc-misc-error+
                              :message (format nil "Mined block rejected: ~A" reason)))
          (push (hash-to-hex (bitcoin-lisp.serialization:block-header-hash
                              (bitcoin-lisp.serialization:bitcoin-block-header block)))
                hashes))))))

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
      (%generate-to-script-pubkey node script-pubkey nblocks maxtries))))

(defun rpc-generatetodescriptor (node params)
  "Mine NUM-BLOCKS blocks whose coinbase pays the scriptPubKey of DESCRIPTOR
(Bitcoin Core generatetodescriptor; CPU mining, intended for regtest). PARAMS:
(num_blocks descriptor [maxtries]). The descriptor must expand to a single
script. Returns an array of the mined block hashes (hex)."
  (let ((nblocks (first params))
        (descriptor (second params))
        (maxtries (or (third params) 1000000))
        (network (bitcoin-lisp::node-network node)))
    (unless (and (integerp nblocks) (plusp nblocks))
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "num_blocks must be a positive integer"))
    (unless (stringp descriptor)
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "descriptor must be a string"))
    ;; parse-output-descriptor signals rpc-error on a bad descriptor; take the
    ;; first expanded script (Core's getScriptFromDescriptor).
    (let* ((pairs (parse-output-descriptor descriptor network))
           (script-pubkey (caar pairs)))
      (unless script-pubkey
        (error 'rpc-error :code +rpc-invalid-address-or-key+
                          :message "Descriptor does not expand to a script"))
      (%generate-to-script-pubkey node script-pubkey nblocks maxtries))))

(defun %resolve-coinbase-output-script (output network)
  "scriptPubKey for generateblock's OUTPUT — a descriptor (tried first, like
Core's getScriptFromDescriptor) or an address. Signals rpc-error if neither."
  (or (handler-case (caar (parse-output-descriptor output network))
        (rpc-error () nil))
      (handler-case
          (multiple-value-bind (type spk) (bitcoin-lisp.crypto:decode-address output network)
            (and type spk))
        (error () nil))
      (error 'rpc-error :code +rpc-invalid-address-or-key+
                        :message "Error: Invalid address or descriptor")))

(defun %resolve-generateblock-tx (node s)
  "Resolve a generateblock tx entry S: a 64-hex txid is looked up in the mempool,
otherwise S is decoded as a raw transaction (Bitcoin Core generateblock)."
  (unless (stringp s)
    (error 'rpc-error :code +rpc-deserialization-error+ :message "Transaction must be a hex string"))
  (if (valid-hex-hash-p s)
      (let* ((mempool (rpc-get-mempool node))
             (entry (and mempool (bitcoin-lisp.mempool:mempool-get
                                  mempool (parse-hex-hash s)))))
        (unless entry
          (error 'rpc-error :code +rpc-invalid-address-or-key+
                            :message (format nil "Transaction ~A not in mempool." s)))
        (bitcoin-lisp.mempool:mempool-entry-transaction entry))
      (handler-case
          (bitcoin-lisp.serialization:parse-tx-payload (bitcoin-lisp.crypto:hex-to-bytes s))
        (error ()
          (error 'rpc-error :code +rpc-deserialization-error+
                            :message (format nil "Transaction decode failed for ~A" s))))))

(defun %witness-commitment-script-for-txs (txs)
  "BIP141 witness-commitment scriptPubKey over a block whose coinbase wtxid is
zero and whose remaining transactions are TXS (Core GenerateCoinbaseCommitment)."
  (let* ((zeros (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
         (wtxids (cons zeros (mapcar #'bitcoin-lisp.serialization:transaction-wtxid txs)))
         (witness-root (bitcoin-lisp.validation:compute-merkle-root wtxids))
         (combined (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace combined witness-root)
    (bitcoin-lisp.mining:build-witness-commitment-script
     (bitcoin-lisp.crypto:hash256 combined))))

(defun rpc-generateblock (node params)
  "Mine a single block containing exactly the given transactions (Bitcoin Core
generateblock; CPU mining, intended for regtest). PARAMS: (output [tx,...]
[submit]). OUTPUT is an address or descriptor for the coinbase, which is paid the
block subsidy only (Core builds the template with use_mempool=false). Each tx is a
64-hex mempool txid or a raw-tx hex. The assembled block is dry-run through
TestBlockValidity BEFORE mining, exactly like Core (rpc/mining.cpp:389-393) —
so submit=false hex is consensus-valid too, not just decodable. When SUBMIT
(default true) the block is then activated through the normal consensus path
and {hash} is returned; otherwise {hash, hex}."
  (let ((output (first params))
        (txs-arg (second params))
        (submit (if (>= (length params) 3) (and (third params) t) t))
        (network (bitcoin-lisp::node-network node)))
    (unless (stringp output)
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "output must be a string"))
    (unless (listp txs-arg)
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "transactions must be an array"))
    (let* ((script-pubkey (%resolve-coinbase-output-script output network))
           ;; Node lock: mempool tx resolution, template assembly, and the
           ;; TestBlockValidity dry run all read the tip + mempool and must
           ;; see one consistent state; the nonce grind below runs OUTSIDE
           ;; the lock (Core drops cs_main between CreateNewBlock and the
           ;; grind too, rpc/mining.cpp) — a stale block fails activation.
           (block
             (with-node-lock (node)
               (let* ((txs (mapcar (lambda (s) (%resolve-generateblock-tx node s)) txs-arg))
                      (chain-state (rpc-get-chain-state node))
                      (mempool (rpc-get-mempool node))
                      ;; Reuse the assembler only for header fields (height/prev/
                      ;; bits/version/time); its tx selection and coinbase value
                      ;; are ignored.
                      (template (bitcoin-lisp.mining:assemble-block-template chain-state mempool))
                      (height (bitcoin-lisp.mining:block-template-height template))
                      (coinbase (bitcoin-lisp.mining:build-coinbase-transaction
                                 height
                                 (bitcoin-lisp.validation:calculate-block-subsidy height)
                                 :script-pubkey script-pubkey
                                 :witness-commitment-script (%witness-commitment-script-for-txs txs)))
                      (all-txs (cons coinbase txs))
                      (merkle (bitcoin-lisp.validation:compute-merkle-root
                               (mapcar #'bitcoin-lisp.serialization:transaction-hash all-txs)))
                      (header (bitcoin-lisp.serialization:make-block-header
                               :version (bitcoin-lisp.mining:block-template-version template)
                               :prev-block (bitcoin-lisp.mining:block-template-prev-hash template)
                               :merkle-root merkle
                               :timestamp (bitcoin-lisp.mining:block-template-curtime template)
                               :bits (bitcoin-lisp.mining:block-template-bits template)
                               :nonce 0))
                      (block (bitcoin-lisp.serialization:make-bitcoin-block
                              :header header :transactions all-txs)))
                 ;; TestBlockValidity before mining (Core rpc/mining.cpp:389-393): a
                 ;; consensus-invalid tx list errors instead of producing a doomed block.
                 (multiple-value-bind (ok reason)
                     (bitcoin-lisp.validation:test-block-validity
                      block chain-state (rpc-get-utxo-set node))
                   (unless ok
                     (error 'rpc-error :code +rpc-verify-error+
                                       :message (format nil "TestBlockValidity failed: ~A" reason))))
                 block))))
      (unless (bitcoin-lisp.mining:mine-block block)
        (error 'rpc-error :code +rpc-misc-error+ :message "Failed to find a valid nonce"))
      (let ((hash-hex (hash-to-hex (bitcoin-lisp.serialization:block-header-hash
                                    (bitcoin-lisp.serialization:bitcoin-block-header block)))))
        (if submit
            (multiple-value-bind (ok reason) (%activate-submitted-block node block)
              (unless (or ok (eq reason :weaker-chain))
                ;; Validity was already dry-run above; a failure here is the
                ;; activation itself (Core "ProcessNewBlock, block not
                ;; accepted", rpc/mining.cpp:158).
                (error 'rpc-error :code +rpc-verify-error+
                                  :message (format nil "Block not accepted: ~A" reason)))
              `(("hash" . ,hash-hex)))
            `(("hash" . ,hash-hex)
              ("hex" . ,(bitcoin-lisp.crypto:bytes-to-hex
                         (bitcoin-lisp.serialization:serialize-witness-block block)))))))))

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
  "Get raw transaction data by txid (Bitcoin Core getrawtransaction).
Verbosity <= 0 (or false, the default) returns the wire-serialized (witness-
complete) tx hex — Core's EncodeHexTx; >= 1 (or true) the decoded object
(Core's verbosity-2 fee/prevout fields are not supported and fold into 1).
Searches mempool first, then blockhash hint, then txindex (if enabled)."
  (let ((txid-str (first params))
        (blockhash-hint (third params)))
    (unless (valid-hex-hash-p txid-str)
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "Invalid transaction id"))
    (when (and blockhash-hint (not (valid-hex-hash-p blockhash-hint)))
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "Invalid blockhash"))
    (let* ((verbose (plusp (%parse-verbosity params 1 0 :allow-bool t)))
           (txid-bytes (parse-hex-hash txid-str))
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
                 (bitcoin-lisp.serialization:transaction-wire-bytes tx))))))

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
                      ;; With an explicit blockhash, Core adds in_active_chain.
                      (let* ((cs (rpc-get-chain-state node))
                             (entry (bitcoin-lisp.storage:get-block-index-entry cs block-hash-bytes)))
                        (append (tx-to-json-confirmed found-tx node block-hash-bytes)
                                `(("in_active_chain"
                                   . ,(and entry (%block-on-active-chain-p entry cs))))))
                      (bitcoin-lisp.crypto:bytes-to-hex
                       (bitcoin-lisp.serialization:transaction-wire-bytes found-tx)))))))))

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
                             (bitcoin-lisp.serialization:transaction-wire-bytes found-tx))))))))))))

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
  "Convert a confirmed transaction to JSON with block context, per Core's
TxToJSON (rpc/rawtransaction.cpp:58-86): blockhash is always present; when
the block index knows the block AND it is on the active chain, add
confirmations/time/blocktime; a known but STALE block (e.g. a txindex entry
pointing into a reorged-away branch — Core keeps those) gets confirmations 0
and NO time fields; an unknown block gets blockhash only."
  (let* ((chain-state (rpc-get-chain-state node))
         (block-entry (bitcoin-lisp.storage:get-block-index-entry chain-state block-hash))
         (base-json (tx-to-json tx (rpc-get-network node))))
    (append base-json
            `(("blockhash" . ,(hash-to-hex block-hash)))
            (cond ((null block-entry) '())
                  ((%block-on-active-chain-p block-entry chain-state)
                   (let* ((current-height (bitcoin-lisp.storage:current-height chain-state))
                          (block-height (bitcoin-lisp.storage:block-index-entry-height block-entry))
                          (header (bitcoin-lisp.storage:block-index-entry-header block-entry))
                          (block-time (when header
                                        (bitcoin-lisp.serialization:block-header-timestamp header))))
                     `(("confirmations" . ,(1+ (- current-height block-height)))
                       ("time" . ,block-time)
                       ("blocktime" . ,block-time))))
                  (t '(("confirmations" . 0)))))))

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

;;; --- createmultisig (Bitcoin Core rpc/output_script.cpp) ---

(defconstant +max-pubkeys-per-multisig+ 20
  "Bitcoin Core script.h MAX_PUBKEYS_PER_MULTISIG.")
(defconstant +max-script-element-size+ 520
  "Bitcoin Core script.h MAX_SCRIPT_ELEMENT_SIZE (legacy P2SH redeemScript cap).")

(defun %multisig-push-int (out v)
  "Append V to OUT the way Bitcoin Core's CScript::operator<<(int64_t) encodes a
small count: OP_0 for 0, OP_1..OP_16 for 1..16, else a minimal data push of the
CScriptNum bytes (single byte for the 17..20 range createmultisig allows)."
  (cond ((zerop v) (vector-push-extend #x00 out))
        ((<= 1 v 16) (vector-push-extend (+ #x50 v) out))
        (t (vector-push-extend 1 out) (vector-push-extend v out))))

(defun %multisig-redeem-script (m pubkeys)
  "Bitcoin Core GetScriptForMultisig: OP_m <pubkey>... OP_n OP_CHECKMULTISIG.
Pubkeys are appended in the given order (Core does not sort them)."
  (let ((out (make-array 0 :element-type '(unsigned-byte 8)
                           :adjustable t :fill-pointer 0)))
    (%multisig-push-int out m)
    (dolist (pk pubkeys)
      (vector-push-extend (length pk) out) ; 33/65 < OP_PUSHDATA1, one length byte
      (loop for b across pk do (vector-push-extend b out)))
    (%multisig-push-int out (length pubkeys))
    (vector-push-extend #xae out)          ; OP_CHECKMULTISIG
    (coerce out '(vector (unsigned-byte 8)))))

(defun %parse-multisig-pubkey (hex)
  "Parse a hex-encoded 33/65-byte public key for createmultisig, validating it is
a real point (Bitcoin Core HexToPubKey). Returns the key bytes; signals
rpc-error otherwise."
  (let ((bytes (handler-case (bitcoin-lisp.crypto:hex-to-bytes hex)
                 (error () nil))))
    (unless (and bytes (member (length bytes) '(33 65))
                 (bitcoin-lisp.crypto:public-key-valid-p bytes))
      (error 'rpc-error :code +rpc-invalid-address-or-key+
                        :message (format nil "Invalid public key: ~A" hex)))
    bytes))

(defun rpc-createmultisig (node params)
  "Create an m-of-n multisig address (Bitcoin Core createmultisig). PARAMS:
(nrequired [\"pubkeyhex\",...] [address_type]). address_type is \"legacy\" (P2SH,
default), \"p2sh-segwit\" (P2SH-P2WSH), or \"bech32\" (P2WSH). Returns
{address, redeemScript, descriptor [, warnings]}. The redeemScript is always the
bare multisig script regardless of address type. Uncompressed keys force legacy
(with a warning if another type was requested), matching Core."
  (let ((nrequired (first params))
        (keys (second params))
        (address-type (or (third params) "legacy"))
        (network (rpc-get-network node)))
    (unless (integerp nrequired)
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "nrequired must be an integer"))
    (unless (listp keys)
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "keys must be an array"))
    ;; Parse + validate keys first (Core order: HexToPubKey before type/size checks).
    (let* ((pubkeys (mapcar (lambda (k)
                              (unless (stringp k)
                                (error 'rpc-error :code +rpc-invalid-address-or-key+
                                                  :message "Invalid public key"))
                              (%parse-multisig-pubkey k))
                            keys))
           (requested (cond ((string= address-type "legacy") :legacy)
                            ((string= address-type "p2sh-segwit") :p2sh-segwit)
                            ((string= address-type "bech32") :bech32)
                            ((string= address-type "bech32m")
                             (error 'rpc-error :code +rpc-invalid-address-or-key+
                                               :message "createmultisig cannot create bech32m multisig addresses"))
                            (t (error 'rpc-error :code +rpc-invalid-address-or-key+
                                                 :message (format nil "Unknown address type '~A'" address-type))))))
      ;; AddAndGetMultisigDestination checks (rpc/util.cpp).
      (when (< nrequired 1)
        (error 'rpc-error :code +rpc-invalid-parameter+
                          :message "a multisignature address must require at least one key to redeem"))
      (when (< (length pubkeys) nrequired)
        (error 'rpc-error :code +rpc-invalid-parameter+
                          :message (format nil "not enough keys supplied (got ~D keys, but need at least ~D to redeem)"
                                           (length pubkeys) nrequired)))
      (when (> (length pubkeys) +max-pubkeys-per-multisig+)
        (error 'rpc-error :code +rpc-invalid-parameter+
                          :message (format nil "Number of keys involved in the multisignature address creation > ~D~%Reduce the number"
                                           +max-pubkeys-per-multisig+)))
      (let* ((redeem (%multisig-redeem-script nrequired pubkeys))
             ;; Any uncompressed key forces legacy output (Core).
             (forced-legacy (some (lambda (pk) (/= (length pk) 33)) pubkeys))
             (otype (if forced-legacy :legacy requested)))
        (when (and (eq otype :legacy) (> (length redeem) +max-script-element-size+))
          (error 'rpc-error :code +rpc-invalid-parameter+
                            :message (format nil "redeemScript exceeds size limit: ~D > ~D"
                                             (length redeem) +max-script-element-size+)))
        (let* ((hexkeys (mapcar #'bitcoin-lisp.crypto:bytes-to-hex pubkeys))
               (multi (format nil "multi(~D~{,~A~})" nrequired hexkeys))
               (sha (bitcoin-lisp.crypto:sha256 redeem))
               (address
                 (ecase otype
                   (:legacy (bitcoin-lisp.crypto:encode-p2sh-address
                             (bitcoin-lisp.crypto:hash160 redeem) network))
                   (:bech32 (bitcoin-lisp.crypto:encode-p2wsh-address sha network))
                   (:p2sh-segwit
                    (bitcoin-lisp.crypto:encode-p2sh-address
                     (bitcoin-lisp.crypto:hash160
                      (concatenate '(vector (unsigned-byte 8)) #(#x00 #x20) sha))
                     network))))
               (body (ecase otype
                       (:legacy (format nil "sh(~A)" multi))
                       (:bech32 (format nil "wsh(~A)" multi))
                       (:p2sh-segwit (format nil "sh(wsh(~A))" multi))))
               (result `(("address" . ,address)
                         ("redeemScript" . ,(bitcoin-lisp.crypto:bytes-to-hex redeem))
                         ("descriptor" . ,(descriptor-add-checksum body)))))
          ;; Core warns only when an explicitly-chosen type could not be produced.
          (if (and forced-legacy (not (eq requested :legacy)))
              (append result
                      `(("warnings" . ,(vector "Unable to make chosen address type, please ensure no uncompressed public keys are present."))))
              result))))))

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
                          ("isscript" . ,(and (member type '(:p2sh :p2wsh :witness-v0-scripthash)) t))
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
                 ;; Bare multisig: one P2PKH address per key (Core's classic
                 ;; decodescript "addresses" array; classify-script gives :pubkeys).
                 (setf result (append result
                                      `(("reqSigs" . ,(getf data :m))
                                        ("addresses"
                                         . ,(mapcar
                                             (lambda (pk)
                                               (bitcoin-lisp.crypto:encode-p2pkh-address
                                                (bitcoin-lisp.crypto:hash160 pk) network))
                                             (getf data :pubkeys)))))))
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

;;; --- Message signing (non-wallet): signmessagewithprivkey / verifymessage ---

(defun %bitcoin-message-hash (message)
  "Double-SHA256 of the Bitcoin Signed Message preimage:
compact-size(24) || \"Bitcoin Signed Message:\\n\" || compact-size(len) || message."
  ;; Magic = "Bitcoin Signed Message:" (23 ASCII bytes) followed by a single
  ;; newline (0x0A) — 24 bytes total, so its compact-size prefix is 0x18.
  (let* ((magic (concatenate '(vector (unsigned-byte 8))
                             (flexi-streams:string-to-octets "Bitcoin Signed Message:"
                                                             :external-format :ascii)
                             (vector 10)))
         (msg (flexi-streams:string-to-octets message :external-format :utf-8))
         (buf (flexi-streams:with-output-to-sequence (s)
                (bitcoin-lisp.serialization:write-compact-size s (length magic))
                (write-sequence magic s)
                (bitcoin-lisp.serialization:write-compact-size s (length msg))
                (write-sequence msg s))))
    (bitcoin-lisp.crypto:hash256 buf)))

(defun rpc-signmessagewithprivkey (node params)
  "Sign MESSAGE with the WIF private key (Bitcoin Core signmessagewithprivkey).
PARAMS: (privkey-wif message). Returns the base64 recoverable signature."
  (declare (ignore node))
  (let ((wif (first params))
        (message (second params)))
    (unless (and (stringp wif) (stringp message))
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "privkey (WIF) and message are required"))
    (multiple-value-bind (privkey compressed) (bitcoin-lisp.crypto:wif-to-private-key wif)
      (unless privkey
        (error 'rpc-error :code +rpc-invalid-parameter+ :message "Invalid private key"))
      (let ((hash (%bitcoin-message-hash message)))
        (multiple-value-bind (compact recid)
            (bitcoin-lisp.crypto:sign-recoverable-compact privkey hash)
          (let ((sig65 (concatenate '(vector (unsigned-byte 8))
                                    (vector (+ 27 recid (if compressed 4 0)))
                                    compact)))
            (cl-base64:usb8-array-to-base64-string sig65)))))))

(defun rpc-verifymessage (node params)
  "Verify a Bitcoin signed message (Bitcoin Core verifymessage). PARAMS:
(address signature-base64 message). Recovers the signing pubkey and checks its
P2PKH key-id matches ADDRESS. Returns T/NIL; a malformed signature returns NIL."
  (declare (ignore node))
  (let ((address (first params))
        (sig-b64 (second params))
        (message (third params)))
    (unless (and (stringp address) (stringp sig-b64) (stringp message))
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "address, signature and message are required"))
    (handler-case
        (let ((sig65 (cl-base64:base64-string-to-usb8-array sig-b64)))
          (unless (= (length sig65) 65)
            (return-from rpc-verifymessage nil))
          (let ((header (aref sig65 0)))
            (when (or (< header 27) (> header 34))
              (return-from rpc-verifymessage nil))
            (let* ((recid (logand (- header 27) 3))
                   (compressed (>= (- header 27) 4))
                   (compact (subseq sig65 1 65))
                   (hash (%bitcoin-message-hash message))
                   (pubkey (bitcoin-lisp.crypto:recover-public-key
                            compact recid hash :compressed compressed)))
              (when pubkey
                ;; Compare the recovered key's P2PKH key-id (hash160) to the
                ;; address's key-id — network-agnostic, like Core.
                (multiple-value-bind (ver payload)
                    (bitcoin-lisp.crypto:base58check-decode address)
                  (declare (ignore ver))
                  (and payload (= (length payload) 20)
                       (equalp payload (bitcoin-lisp.crypto:hash160 pubkey))
                       t))))))
      (error () nil))))

;;; --- signrawtransactionwithkey (non-wallet, P2PKH + P2WPKH) ---

(defun %parse-sighash-type (s)
  "Map a sighashtype string (default \"ALL\") to its byte: ALL=1 NONE=2 SINGLE=3,
with |ANYONECANPAY setting 0x80."
  (let* ((str (string-upcase (or s "ALL")))
         (acp (search "ANYONECANPAY" str))
         (base (cond ((search "ALL" str) 1)
                     ((search "NONE" str) 2)
                     ((search "SINGLE" str) 3)
                     (t (error 'rpc-error :code +rpc-invalid-parameter+
                                          :message "Invalid sighashtype")))))
    (logior base (if acp #x80 0))))

(defun %script-push (data)
  "Script push of DATA with the minimal pushdata encoding (direct for <=75 bytes,
OP_PUSHDATA1 for 76-255, OP_PUSHDATA2 above). Covers signatures, pubkeys, and the
larger redeem/witness scripts of multisig."
  (let ((len (length data)))
    (cond
      ((<= len 75) (concatenate '(vector (unsigned-byte 8)) (vector len) data))
      ((<= len 255) (concatenate '(vector (unsigned-byte 8)) (vector #x4c len) data))
      (t (concatenate '(vector (unsigned-byte 8))
                      (vector #x4d (logand len #xff) (logand (ash len -8) #xff))
                      data)))))

(defun %parse-multisig (script)
  "If SCRIPT is a bare multisig (OP_m <pubkey>...<pubkey> OP_n OP_CHECKMULTISIG),
return (values m n pubkeys) — pubkeys a list of the n 33/65-byte key vectors in
order; else NIL."
  (let ((len (length script)))
    (when (and (>= len 3) (= (aref script (1- len)) #xae))   ; OP_CHECKMULTISIG
      (let ((m-op (aref script 0))
            (n-op (aref script (- len 2))))
        (when (and (<= #x51 m-op #x60) (<= #x51 n-op #x60))  ; OP_1..OP_16
          (let ((m (- m-op #x50)) (n (- n-op #x50))
                (pubkeys '()) (i 1))
            (loop repeat n
                  while (< i (- len 2))
                  do (let ((plen (aref script i)))
                       (unless (or (= plen 33) (= plen 65))
                         (return-from %parse-multisig nil))
                       (when (> (+ i 1 plen) (- len 2))
                         (return-from %parse-multisig nil))
                       (push (subseq script (1+ i) (+ i 1 plen)) pubkeys)
                       (incf i (+ 1 plen))))
            (when (and (= i (- len 2)) (= (length pubkeys) n))
              (values m n (nreverse pubkeys)))))))))

(defun %collect-multisig-sigs (sighash pubmap pubkeys m sighash-byte)
  "ECDSA signatures (DER || sighash-byte) for the keys we hold among PUBKEYS, in
pubkey order, capped at M. CHECKMULTISIG requires sigs ordered as the pubkeys
appear, which iterating PUBKEYS in order preserves."
  (let ((sigs '()) (count 0))
    (dolist (pub pubkeys (nreverse sigs))
      (when (< count m)
        (let ((sk (gethash pub pubmap)))
          (when sk
            (push (concatenate '(vector (unsigned-byte 8))
                               (bitcoin-lisp.crypto:sign-ecdsa sk sighash)
                               (vector sighash-byte))
                  sigs)
            (incf count)))))))

(defun %multisig-scriptsig (subscript tx input-index sighash-byte pubmap &optional redeem)
  "Legacy multisig scriptSig for a multisig SUBSCRIPT (also the sighash subscript).
Returns (values scriptsig nil) = OP_0 <sig>... [push(redeem)] when we hold m keys,
else (values nil error-string). REDEEM (the P2SH redeemScript) is appended when
given; omit it for bare multisig. *current-tx* must be bound by the caller."
  (multiple-value-bind (m nn pubkeys) (%parse-multisig subscript)
    (declare (ignore nn))
    (if (null m)
        (values nil "script is not multisig")
        (let* ((sighash (bitcoin-lisp.coalton.interop::compute-legacy-sighash
                         tx input-index subscript sighash-byte))
               (sigs (%collect-multisig-sigs sighash pubmap pubkeys m sighash-byte)))
          (if (< (length sigs) m)
              (values nil (format nil "multisig needs ~D sigs, have ~D" m (length sigs)))
              (values (apply #'concatenate '(vector (unsigned-byte 8))
                             (vector 0)   ; CHECKMULTISIG NULLDUMMY
                             (append (mapcar #'%script-push sigs)
                                     (when redeem (list (%script-push redeem)))))
                      nil))))))

(defun %multisig-witness-stack (witscript amount input-index sighash-byte pubmap precomp)
  "P2WSH multisig witness stack for WITSCRIPT. Returns (values stack nil) =
(<empty> <sig>... witscript) when we hold m keys, else (values nil error-string).
*current-tx*/*current-spent-utxos* must be bound by the caller."
  (multiple-value-bind (m nn pubkeys) (%parse-multisig witscript)
    (declare (ignore nn))
    (cond
      ((null m) (values nil "witnessScript is not multisig"))
      ((null amount) (values nil "P2WSH requires amount"))
      (t (let* ((bitcoin-lisp.coalton.interop::*current-input-index* input-index)
                (bitcoin-lisp.coalton.interop::*precomputed-sighash* precomp)
                (sighash (bitcoin-lisp.coalton.interop::compute-bip143-sighash
                          witscript amount sighash-byte))
                (sigs (%collect-multisig-sigs sighash pubmap pubkeys m sighash-byte)))
           (if (< (length sigs) m)
               (values nil (format nil "multisig needs ~D sigs, have ~D" m (length sigs)))
               (values (concatenate 'list
                                    (list (make-array 0 :element-type '(unsigned-byte 8)))
                                    sigs (list witscript))
                       nil)))))))

(defun %build-spent-utxos (inputs prevmap)
  "Vector of storage:utxo-entry for every input (the spent outputs, needed for the
BIP341/taproot sighash which commits to all input amounts + scriptPubKeys), or NIL
if any input lacks a prevout-with-amount."
  (let* ((n (length inputs))
         (vec (make-array n)))
    (dotimes (i n vec)
      (let* ((in (aref inputs i))
             (op (bitcoin-lisp.serialization:tx-in-previous-output in))
             (prev (gethash (cons (bitcoin-lisp.serialization:outpoint-hash op)
                                  (bitcoin-lisp.serialization:outpoint-index op))
                            prevmap)))
        (unless (and prev (second prev))
          (return-from %build-spent-utxos nil))
        (setf (aref vec i)
              (bitcoin-lisp.storage:make-utxo-entry
               :value (second prev)
               :script-pubkey (coerce (first prev) '(simple-array (unsigned-byte 8) (*)))))))))

(defun rpc-signrawtransactionwithkey (node params)
  "Sign inputs of a raw transaction with the supplied WIF private keys (Bitcoin
Core signrawtransactionwithkey). Supports P2PKH, P2WPKH, P2TR key-path, bare
multisig, P2SH(-P2WPKH / -multisig / -P2WSH), and P2WSH multisig inputs.
PARAMS: (hexstring privkeys [prevtxs] [sighashtype]). Each prevtxs entry is
{txid, vout, scriptPubKey, amount?, redeemScript?, witnessScript?} for an output
being spent (amount, in BTC, is required for any segwit input; P2TR also needs
amounts on ALL inputs; redeemScript for P2SH; witnessScript for P2WSH). P2TR signs
with SIGHASH_DEFAULT (64-byte signature). Returns {hex, complete, errors?}."
  (declare (ignore node))
  (let ((hexstring (first params))
        (wifs (second params))
        (prevtxs (third params))
        (sighash-byte (%parse-sighash-type (fourth params))))
    (unless (stringp hexstring)
      (error 'rpc-error :code +rpc-deserialization-error+ :message "tx hex string required"))
    (unless (listp wifs)
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "privkeys must be an array"))
    (let* ((tx (handler-case
                   (bitcoin-lisp.serialization:parse-tx-payload
                    (bitcoin-lisp.crypto:hex-to-bytes hexstring))
                 (error () (error 'rpc-error :code +rpc-deserialization-error+
                                             :message "Transaction decode failed"))))
           (inputs (bitcoin-lisp.serialization:transaction-inputs tx))
           (n (length inputs))
           (keymap (make-hash-table :test 'equalp))   ; hash160(pubkey) -> (privkey . pubkey)
           (pubmap (make-hash-table :test 'equalp))   ; full pubkey bytes -> privkey (multisig)
           (tr-keymap (make-hash-table :test 'equalp)) ; tweaked taproot output key (32B) -> privkey
           (prevmap (make-hash-table :test 'equalp))   ; (txid . vout) -> (spk amount-sats redeem witness-script)
           (witness (make-array n :initial-element '()))
           (any-witness nil)
           (errors '()))
      ;; Key map: derive each WIF's pubkey (per its compression flag) -> key-id.
      (dolist (wif wifs)
        (multiple-value-bind (sk compressed) (bitcoin-lisp.crypto:wif-to-private-key wif)
          (unless sk
            (error 'rpc-error :code +rpc-invalid-parameter+ :message "Invalid private key"))
          (let ((pub (bitcoin-lisp.crypto:derive-public-key sk :compressed compressed)))
            (setf (gethash (bitcoin-lisp.crypto:hash160 pub) keymap) (cons sk pub))
            (setf (gethash pub pubmap) sk))
          ;; Taproot key-path output key (P + H_TapTweak(P)*G) -> privkey.
          (let ((qx (bitcoin-lisp.coalton.interop:compute-tweaked-pubkey
                     (bitcoin-lisp.crypto:derive-xonly-pubkey sk))))
            (when qx (setf (gethash qx tr-keymap) sk)))))
      ;; Prevout map from prevtxs (carries optional redeemScript / witnessScript).
      (dolist (pt (and (listp prevtxs) prevtxs))
        (let ((txid (cdr (assoc "txid" pt :test #'string=)))
              (vout (cdr (assoc "vout" pt :test #'string=)))
              (spk-hex (cdr (assoc "scriptPubKey" pt :test #'string=)))
              (amount (cdr (assoc "amount" pt :test #'string=)))
              (redeem-hex (cdr (assoc "redeemScript" pt :test #'string=)))
              (ws-hex (cdr (assoc "witnessScript" pt :test #'string=))))
          (when (and (stringp txid) (valid-hex-hash-p txid) (integerp vout) (stringp spk-hex))
            (setf (gethash (cons (parse-hex-hash txid) vout) prevmap)
                  (list (bitcoin-lisp.crypto:hex-to-bytes spk-hex)
                        (when (numberp amount) (round (* amount 100000000)))
                        (when (stringp redeem-hex) (bitcoin-lisp.crypto:hex-to-bytes redeem-hex))
                        (when (stringp ws-hex) (bitcoin-lisp.crypto:hex-to-bytes ws-hex)))))))
      ;; Sign each input we can. Precompute is built once for the whole tx; pass
      ;; spent-utxos (all inputs' outputs) so the BIP341 amount/scriptPubKey
      ;; commitments are available for taproot inputs.
      (let* ((spent-utxos (%build-spent-utxos inputs prevmap))
             (bitcoin-lisp.coalton.interop::*current-tx* tx)
             (bitcoin-lisp.coalton.interop::*current-spent-utxos* spent-utxos)
             (precomp (bitcoin-lisp.coalton.interop::init-precomputed-sighash tx spent-utxos)))
        (dotimes (i n)
          (let* ((in (aref inputs i))
                 (op (bitcoin-lisp.serialization:tx-in-previous-output in))
                 (prev (gethash (cons (bitcoin-lisp.serialization:outpoint-hash op)
                                      (bitcoin-lisp.serialization:outpoint-index op))
                                prevmap)))
            (if (null prev)
                (push (format nil "Input ~D: no prevtx scriptPubKey provided" i) errors)
                (let* ((spk (first prev)) (amount (second prev))
                       (redeem (third prev)) (witness-script (fourth prev))
                       (type (%script-type spk)))
                  (cond
                    ((string= type "pubkeyhash")
                     (let ((entry (gethash (subseq spk 3 23) keymap)))
                       (if (null entry)
                           (push (format nil "Input ~D: no key for P2PKH" i) errors)
                           (let* ((sighash (bitcoin-lisp.coalton.interop::compute-legacy-sighash
                                            tx i spk sighash-byte))
                                  (sig (concatenate '(vector (unsigned-byte 8))
                                                    (bitcoin-lisp.crypto:sign-ecdsa (car entry) sighash)
                                                    (vector sighash-byte))))
                             (setf (bitcoin-lisp.serialization:tx-in-script-sig in)
                                   (concatenate '(vector (unsigned-byte 8))
                                                (%script-push sig) (%script-push (cdr entry))))))))
                    ((string= type "witness_v0_keyhash")
                     (let ((entry (gethash (subseq spk 2 22) keymap)))
                       (cond
                         ((null entry) (push (format nil "Input ~D: no key for P2WPKH" i) errors))
                         ((null amount) (push (format nil "Input ~D: P2WPKH requires amount" i) errors))
                         (t
                          (let* ((pkh (subseq spk 2 22))
                                 ;; BIP143 scriptCode for P2WPKH is the implicit P2PKH script.
                                 (script-code (concatenate '(vector (unsigned-byte 8))
                                                           (vector #x76 #xa9 #x14) pkh (vector #x88 #xac)))
                                 (bitcoin-lisp.coalton.interop::*current-input-index* i)
                                 (bitcoin-lisp.coalton.interop::*precomputed-sighash* precomp)
                                 (sighash (bitcoin-lisp.coalton.interop::compute-bip143-sighash
                                           script-code amount sighash-byte))
                                 (sig (concatenate '(vector (unsigned-byte 8))
                                                   (bitcoin-lisp.crypto:sign-ecdsa (car entry) sighash)
                                                   (vector sighash-byte))))
                            (setf (aref witness i) (list sig (cdr entry)))
                            (setf any-witness t))))))
                    ((string= type "witness_v1_taproot")
                     (let ((sk (gethash (subseq spk 2 34) tr-keymap)))
                       (cond
                         ((null sk) (push (format nil "Input ~D: no key for P2TR (key path)" i) errors))
                         ((null spent-utxos)
                          (push (format nil "Input ~D: P2TR requires prevtx amounts for all inputs" i) errors))
                         (t
                          (let* ((bitcoin-lisp.coalton.interop::*current-input-index* i)
                                 (bitcoin-lisp.coalton.interop::*precomputed-sighash* precomp)
                                 ;; SIGHASH_DEFAULT (0x00): 64-byte signature, no appended byte.
                                 (sighash (bitcoin-lisp.coalton.interop::compute-bip341-sighash
                                           amount #x00 nil nil))
                                 (tsk (bitcoin-lisp.crypto:taproot-tweak-private-key sk))
                                 (sig (bitcoin-lisp.crypto:sign-schnorr tsk sighash)))
                            (setf (aref witness i) (list sig))
                            (setf any-witness t))))))
                    ((string= type "scripthash")   ; P2SH (wrapped)
                     (cond
                       ((null redeem)
                        (push (format nil "Input ~D: P2SH requires redeemScript" i) errors))
                       ((not (equalp (bitcoin-lisp.crypto:hash160 redeem) (subseq spk 2 22)))
                        (push (format nil "Input ~D: redeemScript hash mismatch" i) errors))
                       ;; P2SH-P2WPKH (nested segwit single-key)
                       ((and (= (length redeem) 22) (= (aref redeem 0) #x00) (= (aref redeem 1) #x14))
                        (let ((entry (gethash (subseq redeem 2 22) keymap)))
                          (cond
                            ((null entry) (push (format nil "Input ~D: no key for P2SH-P2WPKH" i) errors))
                            ((null amount) (push (format nil "Input ~D: P2SH-P2WPKH requires amount" i) errors))
                            (t (let* ((pkh (subseq redeem 2 22))
                                      (script-code (concatenate '(vector (unsigned-byte 8))
                                                                (vector #x76 #xa9 #x14) pkh (vector #x88 #xac)))
                                      (bitcoin-lisp.coalton.interop::*current-input-index* i)
                                      (bitcoin-lisp.coalton.interop::*precomputed-sighash* precomp)
                                      (sighash (bitcoin-lisp.coalton.interop::compute-bip143-sighash
                                                script-code amount sighash-byte))
                                      (sig (concatenate '(vector (unsigned-byte 8))
                                                        (bitcoin-lisp.crypto:sign-ecdsa (car entry) sighash)
                                                        (vector sighash-byte))))
                                 (setf (bitcoin-lisp.serialization:tx-in-script-sig in) (%script-push redeem))
                                 (setf (aref witness i) (list sig (cdr entry)))
                                 (setf any-witness t))))))
                       ;; P2SH-P2WSH (nested segwit multisig; witnessScript = real script)
                       ((and (= (length redeem) 34) (= (aref redeem 0) #x00) (= (aref redeem 1) #x20))
                        (cond
                          ((null witness-script)
                           (push (format nil "Input ~D: P2SH-P2WSH requires witnessScript" i) errors))
                          ((not (equalp (bitcoin-lisp.crypto:sha256 witness-script) (subseq redeem 2 34)))
                           (push (format nil "Input ~D: witnessScript hash mismatch (P2SH-P2WSH)" i) errors))
                          (t (multiple-value-bind (stack err)
                                 (%multisig-witness-stack witness-script amount i sighash-byte pubmap precomp)
                               (if err
                                   (push (format nil "Input ~D: ~A" i err) errors)
                                   (progn
                                     (setf (bitcoin-lisp.serialization:tx-in-script-sig in) (%script-push redeem))
                                     (setf (aref witness i) stack)
                                     (setf any-witness t)))))))
                       ;; P2SH-multisig (legacy)
                       ((%parse-multisig redeem)
                        (multiple-value-bind (ss err)
                            (%multisig-scriptsig redeem tx i sighash-byte pubmap redeem)
                          (if err
                              (push (format nil "Input ~D: P2SH-~A" i err) errors)
                              (setf (bitcoin-lisp.serialization:tx-in-script-sig in) ss))))
                       (t (push (format nil "Input ~D: unsupported redeemScript type" i) errors))))
                    ((string= type "witness_v0_scripthash")   ; native P2WSH
                     (cond
                       ((null witness-script)
                        (push (format nil "Input ~D: P2WSH requires witnessScript" i) errors))
                       ((not (equalp (bitcoin-lisp.crypto:sha256 witness-script) (subseq spk 2 34)))
                        (push (format nil "Input ~D: witnessScript hash mismatch" i) errors))
                       (t (multiple-value-bind (stack err)
                              (%multisig-witness-stack witness-script amount i sighash-byte pubmap precomp)
                            (if err
                                (push (format nil "Input ~D: ~A" i err) errors)
                                (progn (setf (aref witness i) stack) (setf any-witness t)))))))
                    ((%parse-multisig spk)   ; bare multisig
                     (multiple-value-bind (ss err)
                         (%multisig-scriptsig spk tx i sighash-byte pubmap)
                       (if err
                           (push (format nil "Input ~D: ~A" i err) errors)
                           (setf (bitcoin-lisp.serialization:tx-in-script-sig in) ss))))
                    (t (push (format nil "Input ~D: unsupported scriptPubKey type ~A" i type)
                             errors)))))))
        (when (or any-witness (bitcoin-lisp.serialization:transaction-witness tx))
          (setf (bitcoin-lisp.serialization:transaction-witness tx) witness))
        (let ((bytes (bitcoin-lisp.serialization:transaction-wire-bytes tx)))
          (append
           `(("hex" . ,(bitcoin-lisp.crypto:bytes-to-hex bytes))
             ("complete" . ,(null errors)))
           (when errors
             `(("errors" . ,(mapcar (lambda (e) `(("error" . ,e))) (nreverse errors)))))))))))

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
         (bitcoin-lisp.serialization:transaction-wire-bytes tx))))))

;;; --- UTXO Set Statistics ---

(defun %csi-amount-btc (satoshis)
  (/ satoshis 100000000.0d0))

(defun %gettxoutsetinfo-from-index (node hash-type hash-or-height)
  "Serve gettxoutsetinfo for a historical height from the coinstatsindex
(Core's use_index path). HASH-OR-HEIGHT is an integer height or a block-hash
hex. Returns the cumulative stats at that height plus a block_info object of
that block's deltas. Only the muhash hash_type is index-backed."
  (let* ((csi (rpc-get-coinstatsindex node))
         (chain-state (rpc-get-chain-state node)))
    (unless (and csi (bitcoin-lisp.storage:coinstatsindex-enabled csi))
      (error 'rpc-error :code +rpc-misc-error+
                        :message "Querying by block height/hash requires -coinstatsindex"))
    (when (string= hash-type "hash_serialized_3")
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "hash_serialized_3 is not available for historical heights; use 'muhash'"))
    (let* ((height (cond
                     ((integerp hash-or-height) hash-or-height)
                     ((and (stringp hash-or-height) (valid-hex-hash-p hash-or-height))
                      (let ((entry (bitcoin-lisp.storage:get-block-index-entry
                                    chain-state (parse-hex-hash hash-or-height))))
                        (unless entry
                          (error 'rpc-error :code +rpc-invalid-address-or-key+
                                            :message "Block not found"))
                        (bitcoin-lisp.storage:block-index-entry-height entry)))
                     (t (error 'rpc-error :code +rpc-invalid-parameter+
                                          :message "hash_or_height must be a height or block hash"))))
           (stats (bitcoin-lisp.storage:coinstatsindex-get-stats csi height))
           (prev (and (plusp height)
                      (bitcoin-lisp.storage:coinstatsindex-get-stats csi (1- height))))
           (entry (bitcoin-lisp.storage:get-block-at-height chain-state height)))
      (unless stats
        (error 'rpc-error :code +rpc-invalid-parameter+
                          :message "Height not in coinstatsindex (out of range or below the indexed horizon)"))
      (flet ((g (fn s) (if s (funcall fn s) 0)))
        (let* ((unspendable-total (+ (bitcoin-lisp.storage:coinstats-unspendable-genesis stats)
                                     (bitcoin-lisp.storage:coinstats-unspendable-bip30 stats)
                                     (bitcoin-lisp.storage:coinstats-unspendable-scripts stats)
                                     (bitcoin-lisp.storage:coinstats-unspendable-unclaimed stats)))
               ;; block_info = this block's deltas (cumulative[h] - cumulative[h-1]).
               (d-prevout (- (bitcoin-lisp.storage:coinstats-total-prevout-spent stats)
                             (g #'bitcoin-lisp.storage:coinstats-total-prevout-spent prev)))
               (d-coinbase (- (bitcoin-lisp.storage:coinstats-total-coinbase stats)
                              (g #'bitcoin-lisp.storage:coinstats-total-coinbase prev)))
               (d-newout (- (bitcoin-lisp.storage:coinstats-total-new-outputs-ex-coinbase stats)
                            (g #'bitcoin-lisp.storage:coinstats-total-new-outputs-ex-coinbase prev)))
               (d-uns-genesis (- (bitcoin-lisp.storage:coinstats-unspendable-genesis stats)
                                 (g #'bitcoin-lisp.storage:coinstats-unspendable-genesis prev)))
               (d-uns-bip30 (- (bitcoin-lisp.storage:coinstats-unspendable-bip30 stats)
                               (g #'bitcoin-lisp.storage:coinstats-unspendable-bip30 prev)))
               (d-uns-scripts (- (bitcoin-lisp.storage:coinstats-unspendable-scripts stats)
                                 (g #'bitcoin-lisp.storage:coinstats-unspendable-scripts prev)))
               (d-uns-unclaimed (- (bitcoin-lisp.storage:coinstats-unspendable-unclaimed stats)
                                   (g #'bitcoin-lisp.storage:coinstats-unspendable-unclaimed prev))))
          `(("height" . ,height)
            ("bestblock" . ,(if entry (hash-to-hex (bitcoin-lisp.storage:block-index-entry-hash entry)) ""))
            ("txouts" . ,(bitcoin-lisp.storage:coinstats-txout-count stats))
            ("bogosize" . ,(bitcoin-lisp.storage:coinstats-bogo-size stats))
            ("muhash" . ,(hash-to-hex (bitcoin-lisp.crypto:muhash-finalize
                                       (bitcoin-lisp.storage:coinstats-muhash stats))))
            ("total_amount" . ,(%csi-amount-btc (bitcoin-lisp.storage:coinstats-total-amount stats)))
            ("total_unspendable_amount" . ,(%csi-amount-btc unspendable-total))
            ("block_info"
             . (("prevout_spent" . ,(%csi-amount-btc d-prevout))
                ("coinbase" . ,(%csi-amount-btc d-coinbase))
                ("new_outputs_ex_coinbase" . ,(%csi-amount-btc d-newout))
                ("unspendable" . ,(%csi-amount-btc (+ d-uns-genesis d-uns-bip30
                                                      d-uns-scripts d-uns-unclaimed)))
                ("unspendables"
                 . (("genesis_block" . ,(%csi-amount-btc d-uns-genesis))
                    ("bip30" . ,(%csi-amount-btc d-uns-bip30))
                    ("scripts" . ,(%csi-amount-btc d-uns-scripts))
                    ("unclaimed_rewards" . ,(%csi-amount-btc d-uns-unclaimed))))))))))))

(defun rpc-gettxoutsetinfo (node params)
  "Return statistics about the UTXO set. With a second argument (height or
block hash) the stats are served for that historical height from the
coinstatsindex (Core's use_index path)."
  (let ((hash-type (or (first params) "hash_serialized_3"))
        (hash-or-height (second params))
        (utxo-set (rpc-get-utxo-set node))
        (chain-state (rpc-get-chain-state node)))
    (unless (member hash-type '("hash_serialized_3" "muhash" "none") :test #'string=)
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "Invalid hash_type (must be 'hash_serialized_3', 'muhash', or 'none')"))
    (when hash-or-height
      (return-from rpc-gettxoutsetinfo
        (%gettxoutsetinfo-from-index node hash-type hash-or-height)))
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
      ;; Add hash if requested (both hashes present the digest in display
      ;; byte order via hash-to-hex, matching Core's uint256 GetHex()).
      (cond
        ((string= hash-type "hash_serialized_3")
         (setf result (append result
                              `(("hash_serialized_3"
                                 . ,(hash-to-hex (bitcoin-lisp.storage:compute-utxo-set-hash
                                                  utxo-set)))))))
        ((string= hash-type "muhash")
         (setf result (append result
                              `(("muhash"
                                 . ,(hash-to-hex (bitcoin-lisp.storage:compute-utxo-set-muhash
                                                  utxo-set))))))))
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
        (let* ((subsidy (bitcoin-lisp.validation:calculate-block-subsidy height))
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

;; calculate-block-subsidy lives in bitcoin-lisp.validation (consensus, now
;; network-aware incl. the regtest 150-block halving). The duplicate that lived
;; here was removed; getblockstats above calls the consensus one directly.

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
    ;; Node lock: pruning rewrites the block store + pruned-height cursor
    ;; the sync thread reads when serving/connecting blocks (Core
    ;; pruneblockchain holds cs_main).
    (with-node-lock (node)
     (let* ((chain-state (rpc-get-chain-state node))
           (block-store (rpc-get-block-store node))
           (pruned (bitcoin-lisp.storage:prune-blocks-to-height
                    block-store chain-state target-height
                    :on-prune #'bitcoin-lisp.validation:delete-undo-file)))
      (bitcoin-lisp::node-log :info "RPC pruneblockchain: pruned ~D blocks to height ~D"
                              pruned target-height)
      ;; Return the last pruned block height (matching Bitcoin Core).
      ;; Note: getblockchaininfo.pruneheight returns (1+ this) = first UNpruned block.
      (bitcoin-lisp.storage:chain-state-pruned-height chain-state)))))

;;; --- BIP157/158 block filter RPCs ---

(defun rpc-getblockfilter (node params)
  "Return the BIP157 basic filter and filter header for a block.
PARAMS: (blockhash [filtertype]). Mirrors Bitcoin Core getblockfilter."
  (let* ((blockhash-hex (first params))
         (filtertype (or (second params) "basic"))
         (hash (and (stringp blockhash-hex) (parse-hex-hash blockhash-hex))))
    (unless hash
      (error 'rpc-error :code +rpc-invalid-address-or-key+
                        :message "blockhash must be a hex string of length 64"))
    (unless (string-equal filtertype "basic")
      (error 'rpc-error :code +rpc-invalid-address-or-key+
                        :message (format nil "Unknown filtertype ~A" filtertype)))
    (let ((bfi (rpc-get-blockfilterindex node)))
      (unless (and bfi (bitcoin-lisp.storage:blockfilterindex-enabled bfi))
        (error 'rpc-error :code +rpc-misc-error+
                          :message "Index is not enabled for filtertype basic"))
      (unless (bitcoin-lisp.storage:get-block-index-entry (rpc-get-chain-state node) hash)
        (error 'rpc-error :code +rpc-invalid-address-or-key+ :message "Block not found"))
      (multiple-value-bind (filter header)
          (bitcoin-lisp.storage:blockfilterindex-get bfi hash)
        (unless filter
          (error 'rpc-error :code +rpc-misc-error+
                            :message "Could not find block filter for the given block"))
        `(("filter" . ,(bitcoin-lisp.crypto:bytes-to-hex filter))
          ("header" . ,(hash-to-hex header)))))))

;;; scanblocks — return blockhashes whose filters match a descriptor set.

(defvar *scanblocks-lock* (bt:make-lock "scanblocks"))
(defvar *scanblocks-running* nil)
(defvar *scanblocks-progress* 0)
(defvar *scanblocks-current-height* 0)
(defvar *scanblocks-abort* nil)

(defun %reserve-scanblocks ()
  (bt:with-lock-held (*scanblocks-lock*)
    (if *scanblocks-running*
        nil
        (setf *scanblocks-abort* nil *scanblocks-progress* 0
              *scanblocks-current-height* 0 *scanblocks-running* t))))

(defun %release-scanblocks ()
  (bt:with-lock-held (*scanblocks-lock*)
    (setf *scanblocks-running* nil)))

(defun %needle-scripts (scanobjects network)
  "Expand SCANOBJECTS (descriptor strings/objects) into an equalp hash-table
mapping each script (byte vector) to its canonical descriptor."
  (let ((needles (make-hash-table :test 'equalp)))
    (dolist (scanobject scanobjects needles)
      (loop for (script . desc)
              in (parse-output-descriptor (%scanobject-descriptor scanobject) network)
            do (setf (gethash script needles) desc)))))

(defun %hash-table-keys (ht)
  (loop for k being the hash-keys of ht collect k))

(defun rpc-scanblocks (node params)
  "Return blockhashes relevant to a descriptor set using the block filter index.
PARAMS: (action [scanobjects] [start_height] [stop_height] [filtertype] [options]).
ACTION is \"start\", \"status\" or \"abort\". Mirrors Bitcoin Core scanblocks."
  (let ((action (first params)))
    (cond
      ((equal action "status")
       (bt:with-lock-held (*scanblocks-lock*)
         (if *scanblocks-running*
             `(("progress" . ,*scanblocks-progress*)
               ("current_height" . ,*scanblocks-current-height*))
             nil)))
      ((equal action "abort")
       (bt:with-lock-held (*scanblocks-lock*)
         (if *scanblocks-running* (progn (setf *scanblocks-abort* t) t) nil)))
      ((equal action "start")
       (let ((scanobjects (second params))
             (filtertype (or (fifth params) "basic"))
             (bfi (rpc-get-blockfilterindex node)))
         (unless (and scanobjects (listp scanobjects))
           (error 'rpc-error :code +rpc-misc-error+
                             :message "scanobjects argument is required for the start action"))
         (unless (string-equal filtertype "basic")
           (error 'rpc-error :code +rpc-invalid-address-or-key+
                             :message (format nil "Unknown filtertype ~A" filtertype)))
         (unless (and bfi (bitcoin-lisp.storage:blockfilterindex-enabled bfi))
           (error 'rpc-error :code +rpc-misc-error+
                             :message "Index is not enabled for filtertype basic"))
         (unless (%reserve-scanblocks)
           (error 'rpc-error :code +rpc-invalid-parameter+
                             :message "Scan already in progress, use action \"abort\" or \"status\""))
         (unwind-protect
              (let* ((chain-state (rpc-get-chain-state node))
                     (block-store (rpc-get-block-store node))
                     (network (rpc-get-network node))
                     (tip (bitcoin-lisp.storage:current-height chain-state))
                     (start (or (third params) 0))
                     (stop (or (fourth params) tip))
                     (options (sixth params))
                     (fp-check (and (hash-table-p options)
                                    (gethash "filter_false_positives" options)))
                     (needles (%needle-scripts scanobjects network))
                     (needle-list (%hash-table-keys needles))
                     (relevant '())
                     (scanned-to start)
                     (aborted nil))
                ;; Height bounds, matching Core (errors rather than clamping).
                (unless (and (integerp start) (<= 0 start tip))
                  (error 'rpc-error :code +rpc-misc-error+ :message "Invalid start_height"))
                (unless (and (integerp stop) (<= start stop tip))
                  (error 'rpc-error :code +rpc-misc-error+ :message "Invalid stop_height"))
                (loop for height from start to stop do
                  (when *scanblocks-abort* (setf aborted t) (return))
                  (setf *scanblocks-current-height* height
                        *scanblocks-progress*
                        (if (> stop start)
                            (floor (* 100 (- height start)) (- stop start))
                            100))
                  (let ((entry (bitcoin-lisp.storage:get-block-at-height chain-state height)))
                    (when entry
                      (let* ((hash (bitcoin-lisp.storage:block-index-entry-hash entry))
                             (filter (bitcoin-lisp.storage:blockfilterindex-get-filter bfi hash)))
                        (when filter
                          (multiple-value-bind (k0 k1)
                              (bitcoin-lisp.storage:block-filter-siphash-keys hash)
                            (when (bitcoin-lisp.storage:gcs-filter-match-any
                                   filter k0 k1 needle-list)
                              (when (or (not fp-check)
                                        (%block-matches-needles-p
                                         (bitcoin-lisp.storage:get-block block-store hash)
                                         hash needles))
                                (push (hash-to-hex hash) relevant))))))))
                  ;; Last fully-scanned height; on abort this is where we stopped.
                  (setf scanned-to height))
                `(("from_height" . ,start)
                  ("to_height" . ,scanned-to)
                  ("relevant_blocks" . ,(nreverse relevant))
                  ("completed" . ,(not aborted))))
           (%release-scanblocks))))
      (t
       (error 'rpc-error :code +rpc-invalid-parameter+
                         :message (format nil "Invalid action '~A'" action))))))

(defun %block-matches-needles-p (block block-hash needles)
  "T if BLOCK genuinely touches any script in NEEDLES (false-positive check).
Re-derives the block's basic-filter element set (outputs + spent prevouts, the
latter from undo data when available). When the block body is unavailable
(pruned), returns T -- we can't verify, so we keep the filter match rather than
risk a false negative."
  (if (null block)
      t
      (let* ((undo (bitcoin-lisp.validation:get-undo-data block-hash))
             (spent (mapcar (lambda (e) (bitcoin-lisp.storage:utxo-entry-script-pubkey (third e)))
                            undo)))
        (some (lambda (e) (gethash e needles))
              (bitcoin-lisp.storage:basic-filter-elements block spent)))))

;;; getdescriptoractivity — spend/receive activity for descriptors in blocks.

(defun %spk-object (script needles)
  "A scriptPubKey JSON object (hex, plus the matched descriptor when known)."
  `(("hex" . ,(bitcoin-lisp.crypto:bytes-to-hex script))
    ,@(let ((desc (gethash script needles))) (when desc `(("desc" . ,desc))))))

(defun %outpoint-key (txid index)
  (let ((k (make-array 36 :element-type '(unsigned-byte 8))))
    (replace k txid)
    (dotimes (i 4) (setf (aref k (+ 32 i)) (logand (ash index (* -8 i)) #xff)))
    k))

(defun %undo-prevout-table (undo)
  "Map (outpoint txid+index) -> utxo-entry for an undo list, for spend lookups."
  (let ((table (make-hash-table :test 'equalp)))
    (dolist (e undo table)
      (setf (gethash (%outpoint-key (first e) (second e)) table) (third e)))))

(defun %tx-activity (tx needles prevout-fn base-fields)
  "Collect spend+receive activity entries for TX. NEEDLES maps script->desc;
PREVOUT-FN maps (txid index) -> utxo-entry (or NIL); BASE-FIELDS is an alist of
common fields (blockhash/height, or nil for mempool). Returns a list of entries."
  (let ((txid (bitcoin-lisp.serialization:transaction-hash tx))
        (acc '()))
    ;; Spends: each non-coinbase input whose prevout script matches.
    (loop for in across (bitcoin-lisp.serialization:transaction-inputs tx)
          for vin from 0
          for prev = (bitcoin-lisp.serialization:tx-in-previous-output in)
          for phash = (bitcoin-lisp.serialization:outpoint-hash prev)
          for pindex = (bitcoin-lisp.serialization:outpoint-index prev)
          ;; Skip the coinbase's null prevout (index 0xffffffff, all-zero hash).
          unless (and (= pindex #xffffffff) (every #'zerop phash))
            do (let ((entry (funcall prevout-fn phash pindex)))
                 (when entry
                   (let ((spk (bitcoin-lisp.storage:utxo-entry-script-pubkey entry)))
                     (when (gethash spk needles)
                       (push `(("type" . "spend")
                               ("amount" . ,(/ (bitcoin-lisp.storage:utxo-entry-value entry)
                                               100000000.0d0))
                               ,@base-fields
                               ("spend_txid" . ,(hash-to-hex txid))
                               ("spend_vin" . ,vin)
                               ("prevout_txid" . ,(hash-to-hex phash))
                               ("prevout_vout" . ,pindex)
                               ("prevout_spk" . ,(%spk-object spk needles)))
                             acc))))))
    ;; Receives: each output whose script matches.
    (loop for out across (bitcoin-lisp.serialization:transaction-outputs tx)
          for vout from 0
          for spk = (bitcoin-lisp.serialization:tx-out-script-pubkey out)
          when (gethash spk needles)
            do (push `(("type" . "receive")
                       ("amount" . ,(/ (bitcoin-lisp.serialization:tx-out-value out)
                                       100000000.0d0))
                       ,@base-fields
                       ("txid" . ,(hash-to-hex txid))
                       ("vout" . ,vout)
                       ("output_spk" . ,(%spk-object spk needles)))
                     acc))
    (nreverse acc)))

(defun rpc-getdescriptoractivity (node params)
  "Return spend/receive activity for descriptors within the given blocks (and
optionally the mempool). PARAMS: (blockhashes scanobjects [include_mempool]
[options]). Mirrors Bitcoin Core getdescriptoractivity."
  (let* ((blockhashes (first params))
         (scanobjects (second params))
         (include-mempool (if (>= (length params) 3) (third params) t))
         (network (rpc-get-network node))
         (chain-state (rpc-get-chain-state node))
         (block-store (rpc-get-block-store node))
         (utxo-set (rpc-get-utxo-set node))
         (chunks '()))                  ; list of per-tx entry lists, reverse order
    (unless (and scanobjects (listp scanobjects))
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "scanobjects is required"))
    (let ((needles (%needle-scripts scanobjects network)))
      ;; Resolve + validate the requested blocks: each must be on the active
      ;; chain (Core rejects stale/fork blocks). Process them in ascending
      ;; height order regardless of the order given, matching Core.
      (let ((entries '()))
        (dolist (bhash-hex (and (listp blockhashes) blockhashes))
          (let* ((hash (and (stringp bhash-hex) (parse-hex-hash bhash-hex)))
                 (entry (and hash (bitcoin-lisp.storage:get-block-index-entry chain-state hash))))
            (unless entry
              (error 'rpc-error :code +rpc-invalid-address-or-key+
                                :message "Block not found"))
            (unless (bitcoin-lisp.storage:entry-on-active-chain-p chain-state entry)
              (error 'rpc-error :code +rpc-invalid-parameter+
                                :message "Block is not in main chain"))
            (push entry entries)))
        (dolist (entry (sort entries #'< :key #'bitcoin-lisp.storage:block-index-entry-height))
          (let* ((hash (bitcoin-lisp.storage:block-index-entry-hash entry))
                 (height (bitcoin-lisp.storage:block-index-entry-height entry))
                 (block (bitcoin-lisp.storage:get-block block-store hash))
                 (undo (bitcoin-lisp.validation:get-undo-data hash)))
            (unless block
              (error 'rpc-error :code +rpc-invalid-address-or-key+
                                :message "Block not available (pruned?)"))
            ;; A spending block with no undo data can't yield correct spend
            ;; activity; error rather than silently omitting spends (Core's
            ;; GetUndoChecked throws).
            (when (and (null undo)
                       (> (length (bitcoin-lisp.serialization:bitcoin-block-transactions block)) 1))
              (error 'rpc-error :code +rpc-misc-error+
                                :message "Undo data not available (pruned?)"))
            (let ((prevouts (%undo-prevout-table undo))
                  (base `(("blockhash" . ,(hash-to-hex hash)) ("height" . ,height))))
              (dolist (tx (bitcoin-lisp.serialization:bitcoin-block-transactions block))
                (push (%tx-activity tx needles
                                    (lambda (th ti) (gethash (%outpoint-key th ti) prevouts))
                                    base)
                      chunks))))))
      ;; Mempool (blockhash/height omitted).
      (when include-mempool
        (let ((mempool (rpc-get-mempool node)))
          (when mempool
            (bitcoin-lisp.mempool:mempool-for-each
             mempool
             (lambda (txid entry)
               (declare (ignore txid))
               (let ((tx (bitcoin-lisp.mempool:mempool-entry-transaction entry)))
                 (push (%tx-activity
                        tx needles
                        (lambda (th ti)
                          ;; prevout from the UTXO set, else an unconfirmed
                          ;; mempool parent's output.
                          (or (bitcoin-lisp.storage:get-utxo utxo-set th ti)
                              (let ((ptx (bitcoin-lisp.mempool:mempool-get mempool th)))
                                (when (and ptx
                                           (< ti (length (bitcoin-lisp.serialization:transaction-outputs
                                                          (bitcoin-lisp.mempool:mempool-entry-transaction ptx)))))
                                  (let ((o (aref (bitcoin-lisp.serialization:transaction-outputs
                                                  (bitcoin-lisp.mempool:mempool-entry-transaction ptx)) ti)))
                                    (bitcoin-lisp.storage:make-utxo-entry
                                     :value (bitcoin-lisp.serialization:tx-out-value o)
                                     :script-pubkey (bitcoin-lisp.serialization:tx-out-script-pubkey o)))))))
                        nil)
                       chunks)))))))
      ;; chunks is reverse-order lists of entries; flatten once (O(total)).
      `(("activity" . ,(apply #'append (nreverse chunks)))))))
