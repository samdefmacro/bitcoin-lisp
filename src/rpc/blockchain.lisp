(in-package #:bitcoin-lisp.rpc)

;;;; Blockchain RPCs (Core rpc/blockchain.cpp): chain and block queries, gettxout,
;;;; chain control, verifychain, the wait* family, UTXO-set snapshots and
;;;; scanning, getchaintxstats, gettxoutsetinfo, getblockstats, pruning, and
;;;; the BIP157/158 filter RPCs, getdifficulty, getdeploymentinfo and
;;;; getblockfrompeer. The input-validation helpers every RPC file uses come
;;;; first.

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
  (bl.crypto:bytes-to-hex (bl.crypto:reverse-bytes bytes)))

;;; --- Blockchain Query Methods ---

(define-rpc "getblockchaininfo" (node params)
  "Return blockchain state information."
  (declare (ignore params))
  (let* ((chain-state (rpc-get-chain-state node))
         (height (bl.store:current-height chain-state))
         (best-hash (bl.store:best-block-hash chain-state))
         (network (rpc-get-network node))
         (syncing (rpc-is-syncing node))
         (block-store (rpc-get-block-store node))
         (tip (and best-hash (bl.store:get-block-index-entry chain-state best-hash)))
         (tip-header (and tip (bl.store:block-index-entry-header tip)))
         (bits (if tip-header (bl.ser:block-header-bits tip-header) #x1d00ffff))
         ;; Report the best-HEADER height, not the validated-tip height, so a
         ;; download wedge is visible as blocks < headers (Core parity; matches
         ;; getchainstates). Reporting tip height for both hid exactly the
         ;; kind of stuck-tip-below-headers state the reorg wedge produced.
         (best-header (bl.store:best-header-entry chain-state))
         (headers-height (if best-header
                             (bl.store:block-index-entry-height best-header)
                             height))
         (result `(("chain" . ,(%chain-name network))
                   ("blocks" . ,height)
                   ("headers" . ,headers-height)
                   ("bestblockhash" . ,(if best-hash (hash-to-hex best-hash) nil))
                   ("difficulty" . ,(%difficulty-from-bits bits))
                   ("time" . ,(if tip-header
                                  (bl.ser:block-header-timestamp tip-header) 0))
                   ("mediantime" . ,(or (and best-hash
                                             (bl.val:compute-median-time-past
                                              chain-state best-hash))
                                        0))
                   ("verificationprogress" . ,(if syncing 0.0 1.0))
                   ("initialblockdownload" . ,(json-bool syncing))
                   ("chainwork" . ,(string-downcase
                                    (format nil "~64,'0x"
                                            (if tip (bl.store:block-index-entry-chain-work tip) 0))))
                   ("size_on_disk" . ,(if block-store
                                          (round (* (bl.store:block-storage-size-mib block-store)
                                                    1048576))
                                          0))
                   ("bits" . ,(string-downcase (format nil "~8,'0x" bits)))
                   ("target" . ,(string-downcase
                                 (format nil "~64,'0x" (bl.store:bits-to-target bits))))
                   ("pruned" . ,(json-bool (bl:pruning-enabled-p)))
                   ("warnings" . #()))))
    ;; Add pruning-specific fields when pruning is enabled
    (when (bl:pruning-enabled-p)
      (let ((pruned-height (bl.store:chain-state-pruned-height chain-state)))
        (setf result
              (append result
                      ;; pruneheight = first UNpruned block (Bitcoin Core convention).
                      ;; Note: pruneblockchain RPC returns pruned-height (last pruned).
                      `(("pruneheight" . ,(1+ pruned-height))
                        ("automatic_pruning" . ,(json-bool (bl:automatic-pruning-p)))
                        ("prune_target_size" . ,(if (bl:automatic-pruning-p)
                                                    (* bl:*prune-target-mib* 1048576)
                                                    0)))))))
    ;; Core reports the signet challenge here too, on a signet chain and
    ;; nowhere else (rpc/blockchain.cpp:1436-1440); feature_signet.py asserts
    ;; it. This is the third place the challenge belongs — getmininginfo had
    ;; it, getblocktemplate now does, and a client that only reads chain info
    ;; had no way to learn it.
    (when (eq (bl:node-network node) :signet)
      (let ((challenge (bl.val:signet-challenge-for-network
                        (bl:node-network node))))
        (when challenge
          (setf result
                (append result
                        `(("signet_challenge"
                           . ,(bl.crypto:bytes-to-hex challenge))))))))
    result))

(defun %getchainstates-entry (chain-state syncing)
  "Per-chainstate object for getchainstates — fields per Core's
RPCHelpForChainstate (rpc/blockchain.cpp): snapshot_blockhash appears only
for a snapshot chainstate, and validated reflects its assumeutxo status."
  (let* ((height (bl.store:current-height chain-state))
         (best-hash (bl.store:best-block-hash chain-state))
         (tip (and best-hash
                   (bl.store:get-block-index-entry chain-state best-hash)))
         (bits (if (and tip (bl.store:block-index-entry-header tip))
                   (bl.ser:block-header-bits
                    (bl.store:block-index-entry-header tip))
                   #x1d00ffff))
         (snapshot-hash (bl.store:chain-state-from-snapshot-blockhash
                         chain-state)))
    `(("blocks" . ,height)
      ("bestblockhash" . ,(if best-hash (hash-to-hex best-hash) nil))
      ("bits" . ,(string-downcase (format nil "~8,'0x" bits)))
      ("target" . ,(string-downcase
                    (format nil "~64,'0x" (bl.store:bits-to-target bits))))
      ("difficulty" . ,(%difficulty-from-bits bits))
      ;; Consistent with getblockchaininfo: 1.0 at tip, 0.0 while syncing.
      ("verificationprogress" . ,(if syncing 0.0d0 1.0d0))
      ;; We don't split a coinsdb vs coinstip cache; report the chainstate's
      ;; coins-cache budget (per-chainstate while an assumeutxo background
      ;; sync splits it — Core MaybeRebalanceCaches) for the tip cache and 0
      ;; for the db cache.
      ("coins_db_cache_bytes" . 0)
      ("coins_tip_cache_bytes" . ,(bl:chainstate-coins-cache-budget
                                   chain-state))
      ,@(when snapshot-hash
          `(("snapshot_blockhash" . ,(hash-to-hex snapshot-hash))))
      ("validated" . ,(json-bool
                       (eq (bl.store:chain-state-assumeutxo-status
                            chain-state)
                           :validated))))))

(define-rpc "getchainstates" (node params)
  "Report this node's chainstate(s) (Bitcoin Core getchainstates), derived
from the node's chainstates list in Core's order: the historical chainstate
first (when assumeutxo background validation is in progress), the current
(active) chainstate last."
  (declare (ignore params))
  (let* ((syncing (rpc-is-syncing node))
         (chainstates (rpc-get-chainstates node))
         (current (bl.store:select-current-chainstate chainstates))
         (historical (bl.store:select-historical-chainstate chainstates))
         ;; Core reports m_best_header's height, which can exceed every
         ;; chainstate's validated tip.
         (best-header (bl.store:best-header-entry current))
         (entries (append
                   (when historical
                     (list (%getchainstates-entry historical syncing)))
                   (list (%getchainstates-entry current syncing)))))
    `(("headers" . ,(if best-header
                        (bl.store:block-index-entry-height best-header)
                        (bl.store:current-height current)))
      ("chainstates" . ,entries))))

(define-rpc "getbestblockhash" (node params)
  "Return the hash of the best (tip) block."
  (declare (ignore params))
  (let* ((chain-state (rpc-get-chain-state node))
         (best-hash (bl.store:best-block-hash chain-state)))
    (if best-hash
        (hash-to-hex best-hash)
        (error 'rpc-error :code +rpc-misc-error+ :message "No blocks"))))

(define-rpc "getblockcount" (node params)
  "Return the current block height."
  (declare (ignore params))
  (let ((chain-state (rpc-get-chain-state node)))
    (bl.store:current-height chain-state)))

(define-rpc "getblockhash" (node (height))
  "Return the hash of block at given height."
  (unless (and (integerp height) (>= height 0))
    (error 'rpc-error :code +rpc-invalid-parameter+
                      :message "Invalid height parameter"))
  (let* ((chain-state (rpc-get-chain-state node))
         (current-height (bl.store:current-height chain-state)))
    (when (> height current-height)
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message (format nil "Block height ~A out of range" height)))
    (let ((entry (bl.store:get-block-at-height chain-state height)))
      (if entry
          (hash-to-hex (bl.store:block-index-entry-hash entry))
          (error 'rpc-error :code +rpc-misc-error+
                            :message "Block not found")))))

(defun %parse-verbosity (params index default &key allow-bool)
  "Core's ParseVerbosity (rpc/util.cpp:83) for the positional argument at INDEX
in PARAMS: an integer passes through, a boolean (where allowed) maps true→1 /
explicit false→0, and null/omitted yields DEFAULT (Core checks isNull BEFORE
the bool branch). Explicit false arrives as the +json-false+ sentinel."
  (if (< (length params) (1+ index))
      default
      (let ((v (nth index params)))
        (cond ((integerp v) v)
              ((null v) default)
              ((and allow-bool (eq v t)) 1)
              ((and allow-bool (eq v +json-false+)) 0)
              ((or (eq v t) (eq v +json-false+))
               (error 'rpc-error :code +rpc-type-error+
                                 :message "Verbosity was boolean but only integer allowed"))
              (t (%json-type-error v "number"))))))

(defun %json-type-name (value)
  "Core's uvTypeName (univalue.cpp:217-226) for VALUE as our decoder represents
it: null, bool, object, array, string, number.

NIL is \"null\", and it now means that: a top-level positional `[]` arrives as
+json-empty-array+ rather than folding into NIL, so this no longer has to
guess which of the two it is looking at. That guess is what made
getrawtransaction(txid, []) answer nothing at all where Core answers -3."
  (cond ((eq value +json-empty-array+) "array")
        ((null value) "null")
        ((eq value t) "bool")
        ((eq value +json-false+) "bool")
        ((stringp value) "string")
        ((numberp value) "number")
        ((hash-table-p value) "object")
        ((or (listp value) (vectorp value)) "array")
        (t "null")))

(defun %json-type-error (value expected)
  "Signal Core's canonical UniValue type error for VALUE where EXPECTED was
wanted: \"JSON value of type <actual> is not of expected type <expected>\"
(univalue.cpp:210-214).

One shape, because Core has one shape. Its functional tests match on this
string — rpc_rawtransaction.py looks for \"not of expected type number\",
mempool_accept.py for \"JSON value of type string is not of expected type
array\" — and each hand-written message here (\"First parameter must be an
array of tx hex\", \"JSON value is not an integer as expected\") was a
different sentence saying the same thing, so no caller could match any of them."
  (error 'rpc-error :code +rpc-type-error+
                    :message (format nil "JSON value of type ~A is not of expected type ~A"
                                     (%json-type-name value) expected)))

(define-rpc "getblock" (node (hash-str))
  "Return block data (Bitcoin Core getblock). Verbosity <= 0 (or false) returns
the serialized block hex; 1 (or true) a JSON object with txids; 2 the object
with full transaction details and each transaction's fee; 3 additionally the
prevout object per input (Core TxVerbosity::SHOW_DETAILS_AND_PREVOUT)."
  (unless (valid-hex-hash-p hash-str)
    (error 'rpc-error :code +rpc-invalid-parameter+
                      :message "Invalid block hash"))
  (let* ((verbosity (%parse-verbosity params 1 1 :allow-bool t))
         (hash-bytes (parse-hex-hash hash-str))
         (block-store (rpc-get-block-store node))
         (block (and block-store
                     (bl.store:get-block block-store hash-bytes))))
    (unless block
      ;; Core getblock: RPC_INVALID_ADDRESS_OR_KEY (-5), blockchain.cpp:855.
      (error 'rpc-error :code +rpc-invalid-address-or-key+
                        :message "Block not found"))
    (cond
      ((<= verbosity 0) ;; Hex of the block's wire (witness-complete) bytes
       (bl.crypto:bytes-to-hex
        (bl.ser:serialize-witness-block block)))
      ((= verbosity 1) ;; JSON with txids only
       (block-to-json block hash-str nil (rpc-get-chain-state node) (rpc-get-network node)))
      (t ;; verbosity 2: full tx details + fee; 3 adds the prevout objects
       (block-to-json block hash-str t (rpc-get-chain-state node)
                      (rpc-get-network node)
                      :prevouts (>= verbosity 3))))))

(defun %tx-spent-coins-in-block (block tx)
  "The coins TX's inputs spent, from BLOCK's undo data, or NIL when unavailable.

NIL for a coinbase: Core returns early for one (rawtransaction.cpp:354), and
the undo list has no entry for it — indexing it anyway would hand the coinbase
the FIRST real transaction's coins."
  (unless (let ((ins (bl.ser:transaction-inputs tx)))
            (and (plusp (length ins))
                 (bl.ser:coinbase-input-p (aref ins 0))))
    (let ((undos (%block-tx-undos block))
          (txid (bl.ser:transaction-hash tx)))
      (when undos
        (loop for candidate in (rest (bl.ser:bitcoin-block-transactions block))
              for i from 0
              when (equalp txid (bl.ser:transaction-hash candidate))
                return (nth i undos))))))

(defun %block-tx-undos (block)
  "BLOCK's undo data grouped per non-coinbase transaction, or NIL when it is not
available. Never signals: a pruned or missing undo record means the fee and
prevout fields are absent, which is what Core reports for a pruned block."
  (handler-case
      (let* ((hash (bl.ser:block-header-hash
                    (bl.ser:bitcoin-block-header block)))
             (undo (bl.val:get-undo-data hash)))
        (and undo
             (bl.store:block-undo-from-spent-utxos block undo)))
    (error () nil)))

(defun %block-on-active-chain-p (entry chain-state)
  "T if ENTRY is the block at its height on the active chain."
  (let ((at (bl.store:get-block-at-height
             chain-state (bl.store:block-index-entry-height entry))))
    (and at (equalp (bl.store:block-index-entry-hash at)
                    (bl.store:block-index-entry-hash entry)))))

(defun %chain-header-fields (entry chain-state)
  "The chain-context header fields Bitcoin Core shares between getblock and
getblockheader: confirmations, height, versionHex, mediantime, bits (hex),
target, difficulty, chainwork, and -- when the block is on the active chain and
not the tip -- nextblockhash."
  (let* ((header (bl.store:block-index-entry-header entry))
         (height (bl.store:block-index-entry-height entry))
         (bits (bl.ser:block-header-bits header))
         (on-active (%block-on-active-chain-p entry chain-state))
         (next (and on-active
                    (bl.store:get-block-at-height chain-state (1+ height)))))
    (append
     `(("confirmations" . ,(if on-active
                               (+ (- (bl.store:current-height chain-state) height) 1)
                               -1))
       ("height" . ,height)
       ("versionHex" . ,(string-downcase
                         (format nil "~8,'0x"
                                 (logand (bl.ser:block-header-version header)
                                         #xffffffff))))
       ("mediantime" . ,(or (bl.val:compute-median-time-past-from-entry
                             entry)
                            0))
       ("bits" . ,(string-downcase (format nil "~8,'0x" bits)))
       ("target" . ,(string-downcase
                     (format nil "~64,'0x" (bl.store:bits-to-target bits))))
       ("difficulty" . ,(%difficulty-from-bits bits))
       ("chainwork" . ,(string-downcase
                        (format nil "~64,'0x"
                                (bl.store:block-index-entry-chain-work entry)))))
     (when next
       `(("nextblockhash" . ,(hash-to-hex (bl.store:block-index-entry-hash next))))))))

(defun block-to-json (block hash-str include-tx-details chain-state
                      &optional network &key prevouts)
  "Convert block to JSON representation. NETWORK enables output addresses in the
full-tx-detail (verbosity 2) form. CHAIN-STATE supplies the chain-context fields
(confirmations/height/mediantime/chainwork/nextblockhash) when the block is in
the index.

With INCLUDE-TX-DETAILS the block's undo data is read and each transaction gets
its FEE, as Core does at verbosity 2 AND 3 (blockToJSON reads the undo for
both, rpc/blockchain.cpp). PREVOUTS additionally renders Core's verbosity-3
prevout object per input."
  (let* ((header (bl.ser:bitcoin-block-header block))
         (txs (bl.ser:bitcoin-block-transactions block))
         (ntx (length txs))
         (entry (bl.store:get-block-index-entry
                 chain-state (bl.ser:block-header-hash header)))
         (stripped (+ 80 (bl.ser:compact-size-length ntx)
                      (reduce #'+ txs :key (lambda (tx)
                                             (length (bl.ser:serialize-transaction tx))))))
         (size (+ 80 (bl.ser:compact-size-length ntx)
                  (reduce #'+ txs :key (lambda (tx)
                                         (length (bl.ser:transaction-wire-bytes tx)))))))
    (append
     `(("hash" . ,hash-str))
     (when entry (%chain-header-fields entry chain-state))
     `(("strippedsize" . ,stripped)
       ("size" . ,size)
       ("weight" . ,(bl.val:calculate-block-weight txs))
       ;; Core blockToJSON:211 pushes coinbase_tx at every verbosity it is
       ;; reached at (blockToJSON is only called for verbosity >= 1). Core
       ;; CHECK_NONFATALs the coinbase's existence; we simply omit the key for
       ;; a degenerate block rather than error out of an informational RPC.
       ,@(let ((coinbase (first txs)))
           (when (and coinbase
                      (plusp (length (bl.ser:transaction-inputs coinbase))))
             `(("coinbase_tx" . ,(%coinbase-tx-json coinbase)))))
       ("version" . ,(bl.ser:block-header-version header))
       ("merkleroot" . ,(hash-to-hex (bl.ser:block-header-merkle-root header)))
       ("time" . ,(bl.ser:block-header-timestamp header))
       ("nonce" . ,(bl.ser:block-header-nonce header))
       ("nTx" . ,ntx))
     ;; Same rule as getblockheader: blockToJSON delegates its header fields to
     ;; blockheaderToJSON, so genesis omits previousblockhash here too.
     (%previousblockhash-field entry header)
     `(("tx" . ,(if include-tx-details
                    (let ((undo (and include-tx-details
                                     (%block-tx-undos block))))
                      (loop for tx in txs
                            for i from 0
                            collect (tx-to-json tx network
                                                ;; The undo list has one entry
                                                ;; per NON-coinbase transaction,
                                                ;; so index i-1; the coinbase
                                                ;; spends nothing and has no fee.
                                                :spent-coins (and undo (plusp i)
                                                                  (nth (1- i) undo))
                                                :prevouts prevouts)))
                    (mapcar #'tx-to-txid txs)))))))

(defun %coinbase-tx-json (coinbase-tx)
  "Coinbase metadata object (Bitcoin Core coinbaseTxToJSON,
rpc/blockchain.cpp:185-200): version, locktime, the input's sequence and
scriptSig hex, and — only when the coinbase carries one — the single witness
stack item (the segwit reserved value, BIP141)."
  (let* ((vin0 (aref (bl.ser:transaction-inputs coinbase-tx) 0))
         (witness (tx-input-witness coinbase-tx 0)))
    (append
     `(("version" . ,(bl.ser:transaction-version coinbase-tx))
       ("locktime" . ,(bl.ser:transaction-lock-time coinbase-tx))
       ("sequence" . ,(bl.ser:tx-in-sequence vin0))
       ("coinbase" . ,(bl.crypto:bytes-to-hex
                       (bl.ser:tx-in-script-sig vin0))))
     (when (and witness (plusp (length witness)))
       `(("witness" . ,(bl.crypto:bytes-to-hex (elt witness 0))))))))

(defun tx-to-txid (tx)
  "Get transaction ID as hex string."
  (hash-to-hex (bl.ser:transaction-hash tx)))

(defun tx-input-witness (tx index)
  "The witness stack (vector of byte vectors) for input INDEX of TX, or NIL."
  (let ((w (bl.ser:transaction-witness tx)))
    (when (and w (< index (length w)))
      (elt w index))))

(defun tx-to-json (tx &optional network &key spent-coins prevouts)
  "Convert transaction to JSON. When NETWORK is supplied, output addresses are
derived. Includes the size/weight/hex fields explorers and fee tools expect.

SPENT-COINS is this transaction's undo data — a list of UTXO-ENTRY in input
order — which unlocks Core's two extra fields (TxToUniv, core_io.cpp:455-525):

  fee       whenever the coins are known, at verbosity 2 AND 3
  prevout   only when PREVOUTS is true, which is verbosity 3

Those two are gated separately in Core, so they are gated separately here: a
verbosity-2 caller gets the fee and no prevout objects."
  (let ((inputs (bl.ser:transaction-inputs tx))
        (outputs (bl.ser:transaction-outputs tx))
        (wire (bl.ser:transaction-wire-bytes tx)))
    `(("txid" . ,(tx-to-txid tx))
      ("hash" . ,(hash-to-hex (bl.ser:transaction-wtxid tx)))
      ("version" . ,(bl.ser:transaction-version tx))
      ("size" . ,(length wire))
      ("vsize" . ,(bl.ser:transaction-vsize tx))
      ("weight" . ,(bl.ser:transaction-weight tx))
      ("locktime" . ,(bl.ser:transaction-lock-time tx))
      ("vin" . ,(loop for input across inputs
                      for i from 0
                      collect (input-to-json input (tx-input-witness tx i)
                                             :prevout (and prevouts
                                                           (nth i spent-coins))
                                             :network network)))
      ("vout" . ,(loop for out across outputs
                       for i from 0
                       collect (output-to-json out i network)))
      ,@(when spent-coins
          ;; Core computes the fee from the spent coins whenever it has them,
          ;; independently of whether it renders the prevout objects.
          (let ((in-total (reduce #'+ spent-coins
                                  :key #'bl.store:utxo-entry-value
                                  :initial-value 0))
                (out-total (loop for o across outputs
                                 sum (bl.ser:tx-out-value o))))
            `(("fee" . ,(/ (- in-total out-total) 100000000.0d0)))))
      ("hex" . ,(bl.crypto:bytes-to-hex wire)))))

(defun input-to-json (input &optional witness-stack &key prevout network)
  "Convert transaction input to JSON, including sequence and (when present) the
witness stack; coinbase inputs emit a coinbase field instead of txid/vout.

PREVOUT is the UTXO-ENTRY this input spent; supplying it adds Core's
verbosity-3 prevout object (core_io.cpp:478-488)."
  (let ((base
          (if (bl.ser:coinbase-input-p input)
              `(("coinbase" . ,(bl.crypto:bytes-to-hex
                                (bl.ser:tx-in-script-sig input))))
              (let ((outpoint (bl.ser:tx-in-previous-output input)))
                `(("txid" . ,(hash-to-hex (bl.ser:outpoint-hash outpoint)))
                  ("vout" . ,(bl.ser:outpoint-index outpoint))
                  ("scriptSig" . (("asm" . ,(bl.val:disassemble-script
                                             (bl.ser:tx-in-script-sig input)))
                                  ("hex" . ,(bl.crypto:bytes-to-hex
                                             (bl.ser:tx-in-script-sig input))))))))))
    (when (and prevout (not (bl.ser:coinbase-input-p input)))
      (let ((spk (bl.store:utxo-entry-script-pubkey prevout)))
        (setf base
              (append base
                      `(("prevout"
                         . (("generated" . ,(json-bool
                                             (bl.store:utxo-entry-coinbase prevout)))
                            ("height" . ,(bl.store:utxo-entry-height prevout))
                            ("value" . ,(/ (bl.store:utxo-entry-value prevout)
                                           100000000.0d0))
                            ("scriptPubKey"
                             . ,(let ((addr (and network (script->address spk network))))
                                  (append
                                   `(("asm" . ,(bl.val:disassemble-script spk))
                                     ("hex" . ,(bl.crypto:bytes-to-hex spk))
                                     ("type" . ,(bl.val:script-type-name spk)))
                                   (when addr `(("address" . ,addr)))))))))))))
    (when (and witness-stack (plusp (length witness-stack)))
      (setf base (append base
                         `(("txinwitness"
                            . ,(map 'list #'bl.crypto:bytes-to-hex witness-stack))))))
    (append base `(("sequence" . ,(bl.ser:tx-in-sequence input))))))

(defun output-to-json (output index &optional network)
  "Convert transaction output to JSON, with scriptPubKey type and (when NETWORK
is supplied and the script is addressable) address."
  (let* ((spk (bl.ser:tx-out-script-pubkey output))
         (addr (and network (script->address spk network)))
         (spk-json `(("asm" . ,(bl.val:disassemble-script spk))
                     ,@(when network `(("desc" . ,(scriptpubkey-desc spk network))))
                     ("hex" . ,(bl.crypto:bytes-to-hex spk))
                     ("type" . ,(bl.val:script-type-name spk)))))
    (when addr
      (setf spk-json (append spk-json `(("address" . ,addr)))))
    `(("value" . ,(/ (bl.ser:tx-out-value output) 100000000.0d0))
      ("n" . ,index)
      ("scriptPubKey" . ,spk-json))))

(define-rpc "getblockheader" (node (hash-str (verbose :bool-or t)))
  "Return block header data."
  (unless (valid-hex-hash-p hash-str)
    (error 'rpc-error :code +rpc-invalid-parameter+
                      :message "Invalid block hash"))
  (let* ((hash-bytes (parse-hex-hash hash-str))
         (chain-state (rpc-get-chain-state node))
         (entry (bl.store:get-block-index-entry chain-state hash-bytes)))
    (unless entry
      ;; Core getblockheader: RPC_INVALID_ADDRESS_OR_KEY (-5),
      ;; blockchain.cpp:655.
      (error 'rpc-error :code +rpc-invalid-address-or-key+
                        :message "Block not found"))
    (if verbose
        (block-header-entry-to-json entry hash-str chain-state
                                    (rpc-get-block-store node))
        ;; Non-verbose: serialize the header straight from the index entry
        ;; (Core serializes pblockindex->GetBlockHeader() — no block-store
        ;; read, so header-only/pruned entries work too).
        (bl.crypto:bytes-to-hex
         (bl.ser:serialize
          (bl.store:block-index-entry-header entry))))))

(defun %previousblockhash-field (entry header)
  "Core blockheaderToJSON (rpc/blockchain.cpp:177-178) pushes previousblockhash
only `if (blockindex.pprev)`, so genesis OMITS the key rather than reporting 64
zeros. A client walking a chain backwards terminates on the missing key; given
the all-zero hash it instead asks for a block nobody has and gets an error.

The no-parent test is ENTRY's height, not our prev-entry back-link: height 0 is
exactly Core's pprev == nullptr, and unlike the back-link it stays correct for
an entry loaded without one (an assumeutxo base, a synthetic fixture). A NIL
ENTRY — a block we hold but have not indexed — always gets the key, since only
genesis lacks a parent and genesis is always indexed."
  (unless (and entry (zerop (bl.store:block-index-entry-height entry)))
    `(("previousblockhash"
       . ,(hash-to-hex (bl.ser:block-header-prev-block header))))))

(defun block-header-entry-to-json (entry hash-str chain-state &optional block-store)
  "Convert block index entry to header JSON (Bitcoin Core getblockheader): the
shared chain-context fields plus the header's own version/merkleroot/time/nonce,
nTx, and previousblockhash when the block has a parent. BLOCK-STORE, when given,
lets nTx be backfilled for an index entry that predates the tx-count field —
one block-store read per such entry, after which %entry-tx-count caches the
count on the entry."
  (let ((header (bl.store:block-index-entry-header entry)))
    (append
     `(("hash" . ,hash-str))
     (%chain-header-fields entry chain-state)
     `(("version" . ,(bl.ser:block-header-version header))
       ("merkleroot" . ,(hash-to-hex (bl.ser:block-header-merkle-root header)))
       ("time" . ,(bl.ser:block-header-timestamp header))
       ("nonce" . ,(bl.ser:block-header-nonce header))
       ;; Core blockheaderToJSON:175 pushes nTx unconditionally. It is 0 for a
       ;; header whose body we have never stored, matching Core's nTx, which
       ;; stays 0 until ReceivedBlockTransactions.
       ("nTx" . ,(or (%entry-tx-count entry block-store) 0)))
     (%previousblockhash-field entry header))))

(defun chaintip-status (entry on-active best-hash hash block-store)
  "Bitcoin Core getchaintips status for a tip ENTRY."
  (cond
    ((and on-active (equalp hash best-hash)) "active")
    (t (case (bl.store:block-index-entry-status entry)
         (:valid "valid-fork")
         (:invalid "invalid")
         (t (if (bl.store:get-block block-store hash)
                "valid-headers"
                "headers-only"))))))

(define-rpc "getchaintips" (node params)
  "Return information about all known chain tips (active and side branches)."
  (declare (ignore params))
  (let* ((chain-state (rpc-get-chain-state node))
         (block-store (rpc-get-block-store node))
         (index (bl.store:chain-state-block-index chain-state))
         (best-hash (bl.store:best-block-hash chain-state))
         (has-child (make-hash-table :test 'equalp))
         (active (make-hash-table :test 'equalp))
         (tips '()))
    ;; Any block referenced as a parent has a child, so it is not a tip.
    (maphash (lambda (h entry)
               (declare (ignore h))
               (let ((prev (bl.store:block-index-entry-prev-entry entry)))
                 (when prev
                   (setf (gethash (bl.store:block-index-entry-hash prev)
                                  has-child)
                         t))))
             index)
    ;; Active-chain hash set (tip back to genesis) for O(1) membership tests.
    (loop for e = (and best-hash
                       (bl.store:get-block-index-entry chain-state best-hash))
            then (bl.store:block-index-entry-prev-entry e)
          while e
          do (setf (gethash (bl.store:block-index-entry-hash e) active) t))
    (maphash
     (lambda (h entry)
       (unless (gethash h has-child)
         (let ((on-active (gethash h active))
               (branchlen 0))
           ;; branchlen = blocks from this tip back to the active chain.
           (unless on-active
             (loop for e = entry
                     then (bl.store:block-index-entry-prev-entry e)
                   while (and e (not (gethash (bl.store:block-index-entry-hash e)
                                              active)))
                   do (incf branchlen)))
           (push `(("height" . ,(bl.store:block-index-entry-height entry))
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

(defconstant +mempool-coin-height+ #x7FFFFFFF
  "Sentinel height for a coin created by a mempool transaction (Core
MEMPOOL_HEIGHT, txmempool.h:50; CCoinsViewMemPool::GetCoin returns
Coin(out, MEMPOOL_HEIGHT, false), txmempool.cpp:756).")

(defun %mempool-view-coin (mempool txid vout)
  "The unconfirmed coin TXID:VOUT created by a mempool transaction, as a
utxo-entry at +mempool-coin-height+ with coinbase=false (Core
CCoinsViewMemPool::GetCoin), or NIL."
  (let ((entry (and mempool (bl.mp:mempool-get mempool txid))))
    (when entry
      (let ((outputs (bl.ser:transaction-outputs
                      (bl.mp:mempool-entry-transaction entry))))
        (when (< vout (length outputs))
          (let ((out (aref outputs vout)))
            (bl.store:make-utxo-entry
             :value (bl.ser:tx-out-value out)
             :script-pubkey (bl.ser:tx-out-script-pubkey out)
             :height +mempool-coin-height+
             :coinbase nil)))))))

(define-rpc "gettxout" (node (txid-str vout (include-mempool :bool-or t)))
  "Return UTXO info for given outpoint (Core gettxout). PARAMS: (txid n
[include_mempool]). With include_mempool (the default), an outpoint SPENT by
a mempool transaction reports null, and an outpoint CREATED by one is
visible with 0 confirmations (Core's CCoinsViewMemPool +
mempool.isSpent, rpc/blockchain.cpp gettxout) — previously the argument was
accepted but ignored."
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
          (mempool (and include-mempool (rpc-get-mempool node)))
          (entry (cond
                   ;; include_mempool: a mempool spend hides the coin ...
                   ((and mempool
                         (bl.mp:mempool-spending-tx
                          mempool txid-bytes vout))
                    nil)
                   ;; ... and a mempool-created output is visible.
                   (t (or (bl.store:get-utxo utxo-set txid-bytes vout)
                          (and mempool
                               (%mempool-view-coin mempool txid-bytes vout)))))))
    (if entry
        (let* ((chain-state (rpc-get-chain-state node))
               ;; The COINS VIEW's own best block, not the chain tip: they
               ;; differ partway through a reorg's disconnect phase, and Core
               ;; reports the view's (rpc/blockchain.cpp:1083). Falls back to
               ;; the tip for a view that tracks no pointer.
               (best-hash (or (bl.store:coins-view-best-block utxo-set)
                              (bl.store:best-block-hash chain-state)))
               (height (bl.store:current-height chain-state))
               (utxo-height (bl.store:utxo-entry-height entry))
               (spk (bl.store:utxo-entry-script-pubkey entry))
               (network (rpc-get-network node))
               (addr (script->address spk network)))
          `(("bestblock" . ,(if best-hash (hash-to-hex best-hash) ""))
            ;; Mempool coins report 0 confirmations (Core: nHeight ==
            ;; MEMPOOL_HEIGHT -> 0).
            ("confirmations" . ,(if (= utxo-height +mempool-coin-height+)
                                    0
                                    (1+ (- height utxo-height))))
            ("value" . ,(/ (bl.store:utxo-entry-value entry) 100000000.0d0))
            ;; Core's scriptPubKey shape: asm/hex/type plus address when the
            ;; script encodes to one (previously only hex was returned).
            ("scriptPubKey" . (("asm" . ,(bl.val:disassemble-script spk))
                               ("desc" . ,(scriptpubkey-desc spk network))
                               ("hex" . ,(bl.crypto:bytes-to-hex spk))
                               ("type" . ,(bl.val:script-type-name spk))
                               ,@(when addr `(("address" . ,addr)))))
            ("coinbase" . ,(json-bool (bl.store:utxo-entry-coinbase entry)))))
        nil)))) ; Return null for spent/absent outputs

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
                     :mempool (rpc-get-mempool node))
          (unless ok
            (error 'rpc-error :code +rpc-misc-error+
                              :message (string-downcase (symbol-name reason))))
          nil)))))

(define-rpc "invalidateblock" (node params)
  "Mark a block (and its descendants) invalid and reorg the active chain away from
it (Bitcoin Core invalidateblock). PARAMS: (blockhash). Returns null."
  (%chain-control-block node params #'bl.val:invalidate-block))

(define-rpc "reconsiderblock" (node params)
  "Clear a previously-invalidated block's status and reconsider the best chain
(Bitcoin Core reconsiderblock). PARAMS: (blockhash). Returns null."
  (%chain-control-block node params #'bl.val:reconsider-block))

(define-rpc "preciousblock" (node params)
  "Treat a block as preferred over equal-work competitors, reorganizing to it
(Bitcoin Core preciousblock). PARAMS: (blockhash). Returns null."
  (%chain-control-block node params #'bl.val:precious-block))

;;; --- Chain verification (Bitcoin Core verifychain) ---

(define-rpc "verifychain" (node params)
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
     (let ((tip (bl.store:current-height chain-state)))
      (when (or (<= nblocks 0) (> nblocks (1+ tip)))
        (setf nblocks (1+ tip)))
      (loop for height from tip downto (max 0 (- tip (1- nblocks)))
            do (let ((entry (bl.store:get-block-at-height chain-state height)))
                 (unless entry (return-from rpc-verifychain +json-false+))
                 (let ((block (bl.store:get-block
                               block-store
                               (bl.store:block-index-entry-hash entry))))
                   (unless block (return-from rpc-verifychain +json-false+))
                   (when (>= checklevel 1)
                     (let* ((header (bl.ser:bitcoin-block-header block))
                            (txids (mapcar #'bl.ser:transaction-hash
                                           (bl.ser:bitcoin-block-transactions block))))
                       (unless (and (equalp (bl.val:compute-merkle-root txids)
                                            (bl.ser:block-header-merkle-root header))
                                    (bl.val:check-proof-of-work header))
                         (return-from rpc-verifychain +json-false+)))))))
      t))))

;;; --- waitfornewblock / dumptxoutset (Bitcoin Core rpc/blockchain.cpp) ---

(define-rpc "waitfornewblock" (node params)
  "Wait until the chain tip changes, then return it (Bitcoin Core
waitfornewblock). PARAMS: ([timeout-ms]) — 0 (the default) waits indefinitely.
Returns the current tip on change, timeout, or node shutdown. Polls the tip on
the RPC worker thread."
  (let ((timeout (if (integerp (first params)) (first params) 0)))
    (when (minusp timeout)
      (error 'rpc-error :code +rpc-misc-error+ :message "Negative timeout"))
    (let* ((chain-state (rpc-get-chain-state node))
           (start-hash (bl.store:best-block-hash chain-state))
           (deadline (when (plusp timeout)
                       (+ (get-internal-real-time)
                          (floor (* timeout internal-time-units-per-second) 1000)))))
      (loop while (and (bl:node-running node)
                       (equalp (bl.store:best-block-hash chain-state)
                               start-hash)
                       (or (null deadline)
                           (< (get-internal-real-time) deadline)))
            do (sleep 0.25))
      (let ((hash (bl.store:best-block-hash chain-state)))
        `(("hash" . ,(if hash (hash-to-hex hash) ""))
          ("height" . ,(bl.store:current-height chain-state)))))))

(defun %tip-result (chain-state)
  "The {hash, height} alist Core's waitfor* RPCs return for the current tip."
  (let ((hash (bl.store:best-block-hash chain-state)))
    `(("hash" . ,(if hash (hash-to-hex hash) ""))
      ("height" . ,(bl.store:current-height chain-state)))))

(defun %wait-deadline (timeout-ms)
  "Internal-real-time deadline for a TIMEOUT-MS wait, or NIL for wait-forever."
  (when (plusp timeout-ms)
    (+ (get-internal-real-time)
       (floor (* timeout-ms internal-time-units-per-second) 1000))))

(define-rpc "waitforblock" (node (hash-hex (timeout :integer-or 0)))
  "Wait until the given block hash becomes the chain tip (Bitcoin Core
waitforblock). PARAMS: (blockhash [timeout-ms]); timeout 0 (default) waits
indefinitely. Returns the tip on match, timeout, or node shutdown. Polls on the
RPC worker thread."
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
      (loop while (and (bl:node-running node)
                       (not (equalp (bl.store:best-block-hash chain-state)
                                    target))
                       (or (null deadline) (< (get-internal-real-time) deadline)))
            do (sleep 0.25))
      (%tip-result chain-state))))

(define-rpc "waitforblockheight" (node (height (timeout :integer-or 0)))
  "Wait until the chain tip reaches at least HEIGHT (Bitcoin Core
waitforblockheight). PARAMS: (height [timeout-ms]); timeout 0 (default) waits
indefinitely. Returns the tip on reaching the height, timeout, or node shutdown."
  (unless (and (integerp height) (>= height 0))
    (error 'rpc-error :code +rpc-invalid-parameter+
                      :message "height must be a non-negative integer"))
  (when (minusp timeout)
    (error 'rpc-error :code +rpc-misc-error+ :message "Negative timeout"))
  (let* ((chain-state (rpc-get-chain-state node))
         (deadline (%wait-deadline timeout)))
    (loop while (and (bl:node-running node)
                     (< (bl.store:current-height chain-state) height)
                     (or (null deadline) (< (get-internal-real-time) deadline)))
          do (sleep 0.25))
    (%tip-result chain-state)))

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

(alexandria:define-constant +snapshot-magic-bytes+ (coerce #(#x75 #x74 #x78 #x6F #xFF) '(simple-array (unsigned-byte 8) (*)))
  :test #'equalp :documentation "SNAPSHOT_MAGIC_BYTES {'u','t','x','o',0xff} (node/utxo_snapshot.h:28).")

(defconstant +snapshot-version+ 2
  "SnapshotMetadata::VERSION (node/utxo_snapshot.h:46).")

(defconstant +snapshot-count-offset+ 43
  "Byte offset of the metadata's u64 coin count: 5 magic + 2 version +
4 network magic + 32 base blockhash. Coins start 8 bytes later.")

(defun %network-for-magic (magic)
  "The network keyword whose P2P message magic is MAGIC, or NIL."
  (find-if (lambda (net) (equalp magic (bl:network-magic net)))
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
               (when (zerop (bl.store:block-index-entry-height entry))
                 (return-from %chain-tx-count total))
               (setf entry (bl.store:block-index-entry-prev-entry entry))))
    ;; The walk fell off a prev-entry link before reaching genesis.
    nil))

(defun %parse-hash-or-height-entry (chain-state param &optional (param-name "hash_or_height"))
  "Resolve PARAM — a non-negative block height or a block-hash hex string —
to a block-index entry (Core ParseHashOrHeight, rpc/blockchain.cpp:126-152):
heights resolve on the ACTIVE chain and must not exceed the tip; hashes
resolve through the shared block index. PARAM-NAME names the parameter in the
type-error message."
  (cond
    ((integerp param)
     (when (minusp param)
       (error 'rpc-error :code +rpc-invalid-parameter+
                         :message (format nil "Target block height ~D is negative" param)))
     (let ((tip-height (bl.store:current-height chain-state)))
       (when (> param tip-height)
         (error 'rpc-error :code +rpc-invalid-parameter+
                           :message (format nil "Target block height ~D after current tip ~D"
                                            param tip-height))))
     (or (bl.store:get-block-at-height chain-state param)
         (error 'rpc-error :code +rpc-invalid-address-or-key+
                           :message "Block not found")))
    ((and (stringp param) (valid-hex-hash-p param))
     (or (bl.store:get-block-index-entry
          chain-state (parse-hex-hash param))
         (error 'rpc-error :code +rpc-invalid-address-or-key+
                           :message "Block not found")))
    (t
     (error 'rpc-error :code +rpc-invalid-parameter+
                       :message (format nil "~A must be a block height or a block hash"
                                        param-name)))))

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
       (%parse-hash-or-height-entry chain-state rollback-param "rollback"))
      ((string= type "rollback")
       (let ((heights (mapcar #'bl:assumeutxo-data-height
                              (bl:network-assumeutxo-data
                               (rpc-get-network node)))))
         (unless heights
           (error 'rpc-error :code +rpc-misc-error+
                             :message "No assumeutxo snapshot heights are available for this network"))
         (%parse-hash-or-height-entry chain-state (reduce #'max heights) "rollback")))
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
  (let ((target-height (bl.store:block-index-entry-height target-entry))
        (target-hash (bl.store:block-index-entry-hash target-entry)))
    ;; A hash-resolved target must lie on the active chain — Core takes
    ;; ActiveChain().Next(target), which has no answer off-chain.
    (unless (eq (bl.store:get-block-at-height chain-state target-height)
                target-entry)
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "Block is not in the active chain"))
    ;; Pruned node: rolling back needs every block in (target, tip] (and its
    ;; undo) still on disk to disconnect down and reconnect afterwards (Core
    ;; checks GetFirstBlock(BLOCK_HAVE_MASK) <= target, rpc/blockchain.cpp:
    ;; 3139-3149). Our pruned horizon is the pruned-height cursor.
    (when (and (bl:pruning-enabled-p)
               (<= target-height
                   (bl.store:chain-state-pruned-height chain-state)))
      (error 'rpc-error :code +rpc-misc-error+
                        :message "Could not roll back to requested height since necessary block data is already pruned."))
    (let ((invalidate-hash
            (bl.store:block-index-entry-hash
             (bl.store:get-block-at-height
              chain-state (1+ target-height))))
          (block-store (rpc-get-block-store node))
          (utxo-set (rpc-get-utxo-set node))
          (mempool (rpc-get-mempool node))
          (was-active (bl:node-network-active node)))
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
                        (bl.val:invalidate-block
                         chain-state block-store utxo-set invalidate-hash
                         :mempool mempool)
                      (unless ok
                        (error 'rpc-error :code +rpc-misc-error+
                                          :message (format nil "Could not roll back to requested height. (~A)"
                                                           (string-downcase (symbol-name reason))))))
                    ;; The new tip must be the target: a block-read failure or a
                    ;; stale equal-work sister of the invalidated block would
                    ;; land elsewhere (Core rpc/blockchain.cpp:3178-3187).
                    (unless (equalp (bl.store:best-block-hash chain-state)
                                    target-hash)
                      (error 'rpc-error :code +rpc-misc-error+
                                        :message "Could not roll back to requested height.")))
                  (%write-utxo-snapshot node chain-state utxo-set path))
             ;; ~TemporaryRollback: always reconsider, even on error —
             ;; harmless if the invalidation never took effect.
             (with-node-lock (node)
               (bl.val:reconsider-block
                chain-state block-store utxo-set invalidate-hash
                :mempool mempool)))
        ;; ~NetworkDisable (runs after the rollback is undone, like Core's
        ;; reverse member-destruction order).
        (when was-active
          (%set-network-active node t))))))

(define-rpc "dumptxoutset" (node (path (type :string-or "") options))
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
  (unless (and (stringp path) (plusp (length path)))
    (error 'rpc-error :code +rpc-invalid-parameter+ :message "path required"))
  (let* ((chain-state (rpc-get-chain-state node))
         (tip-hash (or (bl.store:best-block-hash chain-state)
                       (error 'rpc-error :code +rpc-misc-error+
                                         :message "Chain has no tip")))
         (tip-entry (bl.store:get-block-index-entry
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
        (%dump-txoutset-with-rollback node chain-state target-entry path))))

(defun %write-utxo-snapshot (node chain-state utxo-set path)
  "Stream CHAIN-STATE's UTXO set to PATH in snapshot v2 format at its
current tip (Core PrepareUTXOSnapshot + WriteUTXOSnapshot, rpc/
blockchain.cpp:3208-3323) and return dumptxoutset's result alist."
  (let* ((base-hash (bl.store:best-block-hash chain-state))
         (base-height (bl.store:current-height chain-state))
         (base-entry (bl.store:get-block-index-entry chain-state base-hash))
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
             (bl.ser:write-uint16-le out +snapshot-version+)
             (write-sequence (bl:network-magic (rpc-get-network node)) out)
             (write-sequence base-hash out)
             (bl.ser:write-uint64-le out 0)
             ;; Coins grouped per txid (WriteUTXOSnapshot, rpc/
             ;; blockchain.cpp:3246-3308). utxo-set-iterate's cursor
             ;; order contract makes groups contiguous and vouts
             ;; ascending; the same pass feeds hash_serialized_3.
             (let ((group-txid nil)
                   (group '()))
               (flet ((flush-group ()
                        (when group
                          (let ((buf (bl.ser:make-byte-buf)))
                            (bl.ser:bb-write-bytes buf group-txid)
                            (bl.ser:bb-write-varint buf (length group))
                            (dolist (pair (nreverse group))
                              (let ((vout (car pair))
                                    (entry (cdr pair)))
                                (bl.ser:bb-write-varint buf vout)
                                (bl.ser:bb-write-compressed-coin
                                 buf
                                 (bl.store:utxo-entry-height entry)
                                 (bl.store:utxo-entry-coinbase entry)
                                 (bl.store:utxo-entry-value entry)
                                 (bl.store:utxo-entry-script-pubkey entry))))
                            (write-sequence (bl.ser:bb-finish buf) out))
                          (setf group '()))))
                 (bl.store:utxo-set-iterate
                  utxo-set
                  (lambda (txid vout entry)
                    (unless (and group-txid (equalp txid group-txid))
                      (flush-group)
                      (setf group-txid txid))
                    (push (cons vout entry) group)
                    (ironclad:update-digest
                     digest (bl.store:coin-muhash-element* txid vout entry))
                    (incf count)))
                 (flush-group)))
             (file-position out +snapshot-count-offset+)
             (bl.ser:write-uint64-le out count))
           (rename-file temppath path)
           (setf renamed t))
      (unless renamed (ignore-errors (delete-file temppath))))
    (let ((hash (bl.crypto:sha256 (ironclad:produce-digest digest)))
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
          (unless (equalp (bl.ser:read-bytes in 5)
                          +snapshot-magic-bytes+)
            (bad "Invalid UTXO set snapshot magic bytes. Please check if this is indeed a snapshot file or if you are using an outdated snapshot format."))
          (let ((version (bl.ser:read-uint16-le in)))
            (unless (= version +snapshot-version+)
              (bad "Version of snapshot ~D does not match any of the supported versions." version)))
          (let ((magic (bl.ser:read-bytes in 4)))
            (unless (equalp magic (bl:network-magic network))
              (let ((theirs (%network-for-magic magic)))
                (if theirs
                    (bad "The network of the snapshot (~A) does not match the network of this node (~A)."
                         (%chain-name theirs) (%chain-name network))
                    (bad "This snapshot has been created for an unrecognized network. This could be a custom signet, a new testnet or possibly caused by data corruption.")))))
          (values (bl.ser:read-bytes in 32)
                  (bl.ser:read-uint64-le in)))
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
          do (let ((txid (bl.ser:read-bytes in 32))
                   (ncoins (bl.ser:read-compact-size in)))
               (when (> ncoins (- global-remaining consumed))
                 (funcall mismatch-fn))
               (dotimes (i ncoins)
                 (let ((vout (bl.ser:read-compact-size in)))
                   (multiple-value-bind (height coinbase value script)
                       (bl.ser:read-compressed-coin in)
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
  (let ((snap (bl:create-snapshot-chainstate node base-hash))
        (adopted nil))
    (unwind-protect
         (let* ((view (bl.store:chain-state-coins-view snap))
                (base-db (bl.store:coins-view-cache-base view))
                (processed 0))
           (flet ((put-coin (batch txid vout height coinbase value script)
                    (when (or (> height base-height) (>= vout #xFFFFFFFF))
                      (funcall fail "Bad snapshot data after deserializing ~D coins"
                               processed))
                    (unless (bl.val:money-range-p value)
                      (funcall fail "Bad snapshot data after deserializing ~D coins - bad tx out value"
                               processed))
                    (bl.store:coins-view-batch-put
                     batch
                     (bl.store:make-utxo-key txid vout)
                     (bl.store:make-utxo-entry
                      :value value :script-pubkey script
                      :height height :coinbase coinbase))
                    (incf processed)))
             (handler-case
                 (loop while (< processed coins-count)
                       do (bl.store:with-coins-view-batch
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
           (let ((got (bl.store:compute-utxo-set-hash view))
                 (want (bl:assumeutxo-data-hash-serialized au)))
             (unless (equalp got want)
               (funcall fail "Bad snapshot content hash: expected ~A, got ~A"
                        (hash-to-hex want) (hash-to-hex got))))
           ;; Verified: finalize and adopt.
           ;;
           ;; Stamp the coins DB with the block these coins ARE, in the coins
           ;; DB itself. Core does this with coins_cache.SetBestBlock(
           ;; base_blockhash) plus a FORCE_FLUSH (validation.cpp:5889, :5963).
           ;; Without it the snapshot chainstate sits outside the invariant the
           ;; coins-DB work established — that the best-block pointer travels
           ;; in the same batch as the coins — so a crash after adoption leaves
           ;; a populated database claiming no block at all, and the startup
           ;; comparison of the two records has nothing to compare.
           (setf (bl.store:cvc-best-block view) (copy-seq base-hash))
           (bl.store:coins-view-cache-flush view :sync t)
           (bl.store:update-chain-tip snap base-hash base-height)
           (bl.store:write-snapshot-base-blockhash snap)
           (bl.store:save-state snap)
           (setf (bl.store:block-index-entry-tx-count base-entry)
                 (bl:assumeutxo-data-chain-tx-count au))
           (bl:add-snapshot-chainstate node snap)
           (setf adopted t)
           (bl:node-log
            :info "RPC loadtxoutset: loaded ~D coins, hash_serialized_3 verified, snapshot chainstate active at h=~D"
            coins-count base-height))
      (unless adopted
        (bl:abort-snapshot-chainstate node snap)))))

(define-rpc "loadtxoutset" (node (path))
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
          (when (bl.store:chain-state-from-snapshot-blockhash chain-state)
            (load-error "Can't activate a snapshot-based chainstate more than once"))
          (let ((au (bl:assumeutxo-data-for-blockhash network base-hash))
                (base-entry (bl.store:get-block-index-entry
                             chain-state base-hash)))
            (unless au
              (load-error "assumeutxo block hash in snapshot metadata not recognized (hash: ~A). The following snapshot heights are available: ~{~D~^, ~}"
                          (hash-to-hex base-hash)
                          (sort (mapcar #'bl:assumeutxo-data-height
                                        (bl:network-assumeutxo-data network))
                                #'<)))
            (unless base-entry
              (load-error "The base block header (~A) must appear in the headers chain. Make sure all headers are syncing, and call loadtxoutset again"
                          (hash-to-hex base-hash)))
            (when (eq (bl.store:block-index-entry-status base-entry) :invalid)
              (load-error "The base block header (~A) is part of an invalid chain"
                          (hash-to-hex base-hash)))
            (let ((base-height (bl.store:block-index-entry-height base-entry)))
              (unless (= base-height (bl:assumeutxo-data-height au))
                (load-error "Assumeutxo height in snapshot metadata not recognized (~D) - refusing to load snapshot"
                            base-height))
              ;; The base must lie on the best header chain (Core
              ;; m_best_header->GetAncestor(height) == base).
              (let ((best (bl.store:best-header-entry chain-state)))
                (unless (and best
                             (eq (bl.store:entry-ancestor-at-height
                                  best base-height)
                                 base-entry))
                  (load-error "A forked headers-chain with more work than the chain with the snapshot base block header exists. Please proceed to sync without AssumeUtxo.")))
              ;; The snapshot must be a more-work chain than the active tip
              ;; (Core CBlockIndexWorkComparator; height as the tiebreak
              ;; for work-less synthetic chains in tests).
              (let* ((tip-entry (bl.store:get-block-index-entry
                                 chain-state
                                 (bl.store:best-block-hash chain-state)))
                     (tip-height (bl.store:current-height chain-state))
                     (tip-work (if tip-entry
                                   (bl.store:block-index-entry-chain-work
                                    tip-entry)
                                   0))
                     (base-work (bl.store:block-index-entry-chain-work
                                 base-entry)))
                (unless (or (> base-work tip-work)
                            (and (= base-work tip-work) (> base-height tip-height)))
                  (load-error "Work does not exceed active chainstate (node already at or past height ~D)"
                              base-height)))
              (when (and mempool (plusp (bl.mp:mempool-count mempool)))
                (load-error "Can't activate a snapshot when mempool not empty"))
              ;; --- Populate + verify into a NEW snapshot chainstate ---
              ;; (see %populate-snapshot-chainstate). Any failure leaves
              ;; the node untouched.
              (bl:call-with-sync-paused
               node
               (lambda ()
                 (%populate-snapshot-chainstate
                  node in au base-hash base-entry base-height coins-count
                  #'load-error)))
              `(("coins_loaded" . ,coins-count)
                ("tip_hash" . ,(hash-to-hex base-hash))
                ("base_height" . ,base-height)
                ("path" . ,(namestring (truename path)))))))))))

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

(defun %scan-utxo-set-for-needles (node needles)
  "scantxoutset's `start' pass: one walk of the UTXO set, collecting the coins
whose scriptPubKey is a key of NEEDLES, and returning the reply alist.

Held under the node lock, for the reason Core holds cs_main over the same
span: Core takes it across the coins-cache flush, the cursor creation and the
tip read (rpc/blockchain.cpp:2410-2418) and only then walks. UTXO-SET-ITERATE
calls COINS-VIEW-CACHE-SYNC, whose documented caller contract is exactly that
pair -- the sync MAPHASHes and rewrites the live cache table that the
validation thread mutates under this same lock, so running it unlocked races
that thread over a hash table neither side is synchronising. Holding it also
makes the tip reported here (`height', `bestblock' and every
`confirmations') the tip the coins were read at, instead of one a block
connect could have moved underneath the walk.

Ours spans the walk as well, which Core's does not, because our iterator is
created inside UTXO-SET-ITERATE and cannot be handed out under the lock and
walked after it. The walk is bounded local work with no network I/O, and
`scantxoutset status'/`abort' from another connection take only
*TXOUTSET-SCAN-LOCK*, so they still answer while it runs."
  (with-node-lock (node)
    (let* ((chain-state (rpc-get-chain-state node))
           (utxo-set (rpc-get-utxo-set node))
           (tip-height (bl.store:current-height chain-state))
           (best-hash (bl.store:best-block-hash chain-state))
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
                                     (bl.store:get-block-index-entry
                                      chain-state best-hash))
                       while e
                       do (setf (gethash (bl.store:block-index-entry-height e)
                                         height-hashes)
                                (hash-to-hex
                                 (bl.store:block-index-entry-hash e)))
                          (setf e (bl.store:block-index-entry-prev-entry e))))
               (gethash height height-hashes)))
        (block scan
          (bl.store:utxo-set-iterate
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
                          (bl.store:utxo-entry-script-pubkey entry)
                          needles)))
               (when desc
                 (let ((height (bl.store:utxo-entry-height entry))
                       (value (bl.store:utxo-entry-value entry)))
                   (incf total-amount value)
                   (push
                    `(("txid" . ,(hash-to-hex txid))
                      ("vout" . ,vout)
                      ("scriptPubKey"
                       . ,(bl.crypto:bytes-to-hex
                           (bl.store:utxo-entry-script-pubkey entry)))
                      ("desc" . ,desc)
                      ("amount" . ,(/ value 100000000.0d0))
                      ("coinbase" . ,(json-bool (bl.store:utxo-entry-coinbase entry)))
                      ("height" . ,height)
                      ,@(let ((hex (blockhash-at height)))
                          (when hex `(("blockhash" . ,hex))))
                      ("confirmations" . ,(1+ (- tip-height height))))
                    unspents))))))))
      `(("success" . ,(json-bool (not aborted)))
        ("txouts" . ,count)
        ("height" . ,tip-height)
        ("bestblock" . ,(if best-hash (hash-to-hex best-hash) ""))
        ;; Core pushes a VARR: no matches is [], not null.
        ("unspents" . ,(json-array (nreverse unspents)))
        ("total_amount" . ,(/ total-amount 100000000.0d0))))))

(define-rpc "scantxoutset" (node (action (scanobjects :array)))
  "Scan the UTXO set for outputs matching descriptors (Bitcoin Core
scantxoutset). PARAMS: (action [scanobjects]) — action is \"start\",
\"status\" or \"abort\". Scanobjects are descriptor strings or
{\"desc\": ..., \"range\": ...} objects; ranged descriptors expand over
their range (default [0,1000], like Core). The scan runs synchronously on
the calling RPC thread; status/abort act from another connection,
mirroring Core."
  (cond
    ((equal action "status")
     (if (bt:with-lock-held (*txoutset-scan-lock*) *txoutset-scan-running*)
         `(("progress" . ,*txoutset-scan-progress*))
         nil))
    ((equal action "abort")
     ;; Bare bool: true when a running scan was told to abort, false when
     ;; none was running (Core scantxoutset abort returns the reserve test).
     (json-bool
      (bt:with-lock-held (*txoutset-scan-lock*)
        (when *txoutset-scan-running*
          (setf *txoutset-scan-abort* t)))))
    ((equal action "start")
     ;; An EMPTY scanobjects array is legal and means "scan for nothing":
     ;; Core still walks the UTXO set and reports success with the chain's
     ;; height, txouts and bestblock, which is what rpc_scantxoutset.py:62
     ;; asserts. Only null/omitted is the missing argument. Our decoder
     ;; used to give NIL for both, so the legal call was refused.
     (unless (%positional-array-p (second params))
       (error 'rpc-error :code +rpc-misc-error+
                         :message "scanobjects argument is required for the start action"))
     (unless (%reserve-txoutset-scan)
       (error 'rpc-error :code +rpc-invalid-parameter+
                         :message "Scan already in progress, use action \"abort\" or \"status\""))
     (unwind-protect
          (%scan-utxo-set-for-needles
           node (%needle-scripts scanobjects (rpc-get-network node)))
       (%release-txoutset-scan)))
    (t
     (error 'rpc-error :code +rpc-invalid-parameter+
                       :message (format nil "Invalid action '~A'" action)))))

;;; --- Chain tx statistics (Bitcoin Core getchaintxstats) ---

(defun %entry-tx-count (entry block-store)
  "Per-block tx count for ENTRY, lazily backfilled by reading the block from
BLOCK-STORE when the index predates the v2 tx-count field. Returns NIL when
unknown (header-only entry whose block isn't readable, e.g. pruned)."
  (let ((n (bl.store:block-index-entry-tx-count entry)))
    (cond ((plusp n) n)
          ;; Genesis is never in the block store; it carries exactly its
          ;; coinbase (a v1-loaded index leaves its entry at 0).
          ((zerop (bl.store:block-index-entry-height entry))
           (setf (bl.store:block-index-entry-tx-count entry) 1))
          (t
           (let ((block (and block-store
                             (bl.store:get-block
                              block-store
                              (bl.store:block-index-entry-hash entry)))))
             (when block
               (setf (bl.store:block-index-entry-tx-count entry)
                     (length (bl.ser:bitcoin-block-transactions
                              block)))))))))

(define-rpc "getchaintxstats" (node params)
  "Transaction count/rate statistics over a block window (Bitcoin Core
getchaintxstats). PARAMS: ([nblocks] [blockhash]) — the window is the NBLOCKS
blocks ending at BLOCKHASH (default one month of blocks ending at the tip); the
interval uses median-time-past, matching Core. txcount/window_tx_count are
omitted when a block in range is unreadable (mirrors Core's unknown nChainTx)."
  (let* ((chain-state (rpc-get-chain-state node))
         (block-store (rpc-get-block-store node))
         (final (if (stringp (second params))
                    (let ((e (bl.store:get-block-index-entry
                              chain-state (parse-hex-hash (second params)))))
                      (unless e
                        (error 'rpc-error :code +rpc-invalid-address-or-key+
                                          :message "Block not found"))
                      (unless (bl.store:entry-on-active-chain-p chain-state e)
                        (error 'rpc-error :code +rpc-invalid-parameter+
                                          :message "Block is not in main chain"))
                      e)
                    (bl.store:get-block-index-entry
                     chain-state (bl.store:best-block-hash chain-state)))))
    (unless final
      (error 'rpc-error :code +rpc-misc-error+ :message "Chain has no tip"))
    (let* ((final-height (bl.store:block-index-entry-height final))
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
                   (setf past (bl.store:block-index-entry-prev-entry entry)))
                 (setf entry (bl.store:block-index-entry-prev-entry entry)))
        (let ((result
                `(("time" . ,(bl.ser:block-header-timestamp
                              (bl.store:block-index-entry-header final)))
                  ,@(when txcount-known `(("txcount" . ,txcount)))
                  ("window_final_block_hash"
                   . ,(hash-to-hex (bl.store:block-index-entry-hash final)))
                  ("window_final_block_height" . ,final-height)
                  ("window_block_count" . ,blockcount))))
          (when (and (plusp blockcount) past)
            (let ((interval (- (or (bl.val:compute-median-time-past-from-entry
                                    final)
                                   0)
                               (or (bl.val:compute-median-time-past-from-entry
                                    past)
                                   0))))
              (setf result (append result `(("window_interval" . ,interval))))
              (when window-known
                (setf result (append result `(("window_tx_count" . ,window-tx))))
                (when (plusp interval)
                  (setf result
                        (append result
                                `(("txrate" . ,(/ (float window-tx) interval)))))))))
          result)))))

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
    (unless (and csi (bl.store:coinstatsindex-enabled csi))
      (error 'rpc-error :code +rpc-misc-error+
                        :message "Querying by block height/hash requires -coinstatsindex"))
    (when (string= hash-type "hash_serialized_3")
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "hash_serialized_3 is not available for historical heights; use 'muhash'"))
    (let* ((height (cond
                     ((integerp hash-or-height) hash-or-height)
                     ((and (stringp hash-or-height) (valid-hex-hash-p hash-or-height))
                      (let ((entry (bl.store:get-block-index-entry
                                    chain-state (parse-hex-hash hash-or-height))))
                        (unless entry
                          (error 'rpc-error :code +rpc-invalid-address-or-key+
                                            :message "Block not found"))
                        ;; The header index resolves STALE-BRANCH hashes too,
                        ;; and the index holds only active-chain statistics —
                        ;; serving the active chain's numbers under a
                        ;; stale-branch hash would be a silently wrong answer.
                        (unless (bl.store:entry-on-active-chain-p
                                 chain-state entry)
                          (error 'rpc-error :code +rpc-invalid-parameter+
                                            :message "Block is not on the active chain; the coinstatsindex holds active-chain statistics only"))
                        (bl.store:block-index-entry-height entry)))
                     (t (error 'rpc-error :code +rpc-invalid-parameter+
                                          :message "hash_or_height must be a height or block hash"))))
           (stats (bl.store:coinstatsindex-get-stats csi height))
           (prev (and (plusp height)
                      (bl.store:coinstatsindex-get-stats csi (1- height))))
           (entry (bl.store:get-block-at-height chain-state height)))
      ;; Records above the best marker are not vouched for: a rewind moves the
      ;; marker down and leaves the abandoned branch's records in place until
      ;; the backfill overwrites them.
      (unless (and stats (<= height (bl.store:coinstatsindex-height csi)))
        (error 'rpc-error :code +rpc-invalid-parameter+
                          :message "Height not in coinstatsindex (out of range or below the indexed horizon)"))
      (flet ((g (fn s) (if s (funcall fn s) 0)))
        (let* ((unspendable-total (+ (bl.store:coinstats-unspendable-genesis stats)
                                     (bl.store:coinstats-unspendable-bip30 stats)
                                     (bl.store:coinstats-unspendable-scripts stats)
                                     (bl.store:coinstats-unspendable-unclaimed stats)))
               ;; block_info = this block's deltas (cumulative[h] - cumulative[h-1]).
               (d-prevout (- (bl.store:coinstats-total-prevout-spent stats)
                             (g #'bl.store:coinstats-total-prevout-spent prev)))
               (d-coinbase (- (bl.store:coinstats-total-coinbase stats)
                              (g #'bl.store:coinstats-total-coinbase prev)))
               (d-newout (- (bl.store:coinstats-total-new-outputs-ex-coinbase stats)
                            (g #'bl.store:coinstats-total-new-outputs-ex-coinbase prev)))
               (d-uns-genesis (- (bl.store:coinstats-unspendable-genesis stats)
                                 (g #'bl.store:coinstats-unspendable-genesis prev)))
               (d-uns-bip30 (- (bl.store:coinstats-unspendable-bip30 stats)
                               (g #'bl.store:coinstats-unspendable-bip30 prev)))
               (d-uns-scripts (- (bl.store:coinstats-unspendable-scripts stats)
                                 (g #'bl.store:coinstats-unspendable-scripts prev)))
               (d-uns-unclaimed (- (bl.store:coinstats-unspendable-unclaimed stats)
                                   (g #'bl.store:coinstats-unspendable-unclaimed prev))))
          `(("height" . ,height)
            ("bestblock" . ,(if entry (hash-to-hex (bl.store:block-index-entry-hash entry)) ""))
            ("txouts" . ,(bl.store:coinstats-txout-count stats))
            ("bogosize" . ,(bl.store:coinstats-bogo-size stats))
            ("muhash" . ,(hash-to-hex (bl.crypto:muhash-finalize
                                       (bl.store:coinstats-muhash stats))))
            ("total_amount" . ,(%csi-amount-btc (bl.store:coinstats-total-amount stats)))
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

(define-rpc "gettxoutsetinfo" (node ((hash-type :or "hash_serialized_3") hash-or-height))
  "Return statistics about the UTXO set. With a second argument (height or
block hash) the stats are served for that historical height from the
coinstatsindex (Core's use_index path)."
  (let ((utxo-set (rpc-get-utxo-set node))
        (chain-state (rpc-get-chain-state node)))
    (unless (member hash-type '("hash_serialized_3" "muhash" "none") :test #'string=)
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "Invalid hash_type (must be 'hash_serialized_3', 'muhash', or 'none')"))
    (when hash-or-height
      (return-from rpc-gettxoutsetinfo
        (%gettxoutsetinfo-from-index node hash-type hash-or-height)))
    ;; Core holds cs_main across the coins-cache flush and the reads that
    ;; follow it (rpc/blockchain.cpp:1075-1084: ForceFlushStateToDisk, then
    ;; the coins view and the pindex it labels the answer with), and
    ;; COINS-VIEW-CACHE-SYNC -- which every walk below calls through
    ;; UTXO-SET-ITERATE -- states that contract for its own callers: the sync
    ;; MAPHASHes and rewrites the live cache table the validation thread
    ;; mutates under this lock. Unlocked, the three walks below (distinct
    ;; txids, total amount, set hash) each raced that thread over an
    ;; unsynchronised hash table AND each saw a different moment of the chain,
    ;; so the height, the coin count and the hash need not describe one UTXO
    ;; set at all. Local work only, no network I/O.
    (with-node-lock (node)
      (let* ((height (bl.store:current-height chain-state))
             ;; The COINS VIEW's own best block, as Core reports
             ;; (rpc/blockchain.cpp:1083). hash_serialized_3 IS the assumeutxo
             ;; commitment, so hashing one set of coins and labelling it with a
             ;; different block's hash commits to nothing — and the two genuinely
             ;; differ partway through a reorg's disconnect phase.
             (best-hash (or (bl.store:coins-view-best-block utxo-set)
                            (bl.store:best-block-hash chain-state)))
             (txout-count (bl.store:utxo-count utxo-set))
             (tx-count (bl.store:utxo-set-distinct-txids utxo-set))
             (total-satoshis (bl.store:utxo-set-total-amount utxo-set))
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
                                   . ,(hash-to-hex (bl.store:compute-utxo-set-hash
                                                    utxo-set)))))))
          ((string= hash-type "muhash")
           (setf result (append result
                                `(("muhash"
                                   . ,(hash-to-hex (bl.store:compute-utxo-set-muhash
                                                    utxo-set))))))))
        result))))

;;; --- Block Statistics ---
;;;
;;; Bitcoin Core getblockstats (rpc/blockchain.cpp:1934-2190). Two structural
;;; rules drive everything below and were both wrong here:
;;;
;;;  1. The per-transaction accumulators run AFTER `if (tx->IsCoinBase())
;;;     continue;` (:2075-2077), so total_out, total_size, total_weight, the
;;;     size extrema and every fee statistic EXCLUDE the coinbase, and the
;;;     averages divide by vtx.size()-1 (:2141,:2143). Only `outs` is counted
;;;     before the continue (:2054) and therefore includes it.
;;;  2. The sizes are per-transaction ComputeTotalSize() — the WITNESS-inclusive
;;;     serialization of each tx (:2085) — never the whole-block serialization,
;;;     which additionally carries the 80-byte header and the tx-count varint.

(defconstant +per-utxo-overhead+ 41
  "Core PER_UTXO_OVERHEAD (rpc/blockchain.cpp:1932):
sizeof(COutPoint) + sizeof(uint32_t) + sizeof(bool) = 36 + 4 + 1.")

(defun txout-serialize-size (script-pubkey)
  "GetSerializeSize(CTxOut) for an output with SCRIPT-PUBKEY: the 8-byte amount
plus the compact-size-prefixed script."
  (+ 8 (bl.ser:compact-size-length (length script-pubkey))
     (length script-pubkey)))

(defun %truncated-median (values)
  "Core CalculateTruncatedMedian (rpc/blockchain.cpp:1878-1892): 0 for an empty
sample, the (integer) mean of the two middle elements for an even count, the
middle element otherwise."
  ;; map (not coerce) so the destructive sort always gets a fresh vector.
  (let* ((v (sort (map 'vector #'identity values) #'<))
         (n (length v)))
    (cond ((zerop n) 0)
          ((evenp n) (truncate (+ (aref v (1- (truncate n 2))) (aref v (truncate n 2))) 2))
          (t (aref v (truncate n 2))))))

(defun %feerate-percentiles (scores total-weight)
  "Core CalculatePercentilesByWeight (rpc/blockchain.cpp:1894-1921): the feerate
at the 10th/25th/50th/75th/90th percentile WEIGHT unit. SCORES is a list of
(feerate . weight) conses, sorted here exactly as std::sort orders std::pair
(by feerate, then weight). Returns a 5-element list, all zeros for no scores."
  (let ((result (list 0 0 0 0 0)))
    (when scores
      (let* ((sorted (sort (copy-list scores)
                           (lambda (a b)
                             (or (< (car a) (car b))
                                 (and (= (car a) (car b)) (< (cdr a) (cdr b)))))))
             (cutoffs (list (/ total-weight 10.0d0)
                            (/ total-weight 4.0d0)
                            (/ total-weight 2.0d0)
                            (/ (* total-weight 3.0d0) 4.0d0)
                            (/ (* total-weight 9.0d0) 10.0d0)))
             (next 0)
             (cumulative 0))
        (dolist (score sorted)
          (incf cumulative (cdr score))
          (loop while (and (< next 5) (>= cumulative (nth next cutoffs)))
                do (setf (nth next result) (car score))
                   (incf next)))
        ;; Fill any remaining percentiles with the last (largest) feerate.
        (let ((last-feerate (car (car (last sorted)))))
          (loop for i from next below 5 do (setf (nth i result) last-feerate)))))
    result))

(defun %select-block-stats (all-stats stats-filter)
  "Core's stats selection (rpc/blockchain.cpp:2181-2189): no selection returns
everything; an unknown name is RPC_INVALID_PARAMETER (-8) rather than being
silently dropped, which is how a typo used to read as 'that statistic is
unavailable in this block'."
  (cond
    ((null stats-filter) all-stats)
    ((not (listp stats-filter))
     (error 'rpc-error :code +rpc-type-error+
                       :message "Expected type array for stats"))
    (t
     (mapcar
      (lambda (name)
        (unless (stringp name)
          (error 'rpc-error :code +rpc-type-error+
                            :message "Expected type string for selected statistic"))
        (or (assoc name all-stats :test #'string=)
            (error 'rpc-error :code +rpc-invalid-parameter+
                              :message (format nil "Invalid selected statistic '~A'" name))))
      stats-filter))))

(define-rpc "getblockstats" (node (hash-or-height stats-filter))
  "Per-block statistics (Bitcoin Core getblockstats, rpc/blockchain.cpp:1934-2190).
PARAMS: (hash_or_height [stats]) — STATS selects a subset of the keys; an
unknown name is an error. All amounts are in satoshis, feerates in sat/vB.
The fee statistics come from the block's undo data, so — as in Core, whose
GetUndoChecked runs unconditionally (:2016) — a spending block whose undo data
is unavailable (pruned) is an error rather than a silently wrong answer."
  (unless hash-or-height
    (error 'rpc-error :code +rpc-invalid-params+
                      :message "Missing required parameter hash_or_height"))
  (let* ((chain-state (rpc-get-chain-state node))
         (block-store (rpc-get-block-store node)))
    (unless block-store
      (error 'rpc-error :code +rpc-misc-error+
                        :message "Block data not available"))
    ;; Core resolves through ParseHashOrHeight, so the block must be in the
    ;; index — the old height-0 fallback for an unindexed block reported a
    ;; wrong subsidy and mediantime instead of erroring.
    (let* ((entry (%parse-hash-or-height-entry chain-state hash-or-height))
           (block-hash (bl.store:block-index-entry-hash entry))
           (block (bl.store:get-block block-store block-hash)))
      (unless block
        (error 'rpc-error :code +rpc-invalid-address-or-key+
                          :message "Block not found"))
      (let* ((height (bl.store:block-index-entry-height entry))
             (header (bl.ser:bitcoin-block-header block))
             (txs (bl.ser:bitcoin-block-transactions block))
             (ntx (length txs))
             (undo (bl.val:get-undo-data block-hash)))
        (when (and (> ntx 1) (null undo))
          ;; Core GetUndoChecked, rpc/blockchain.cpp:730-732.
          (error 'rpc-error :code +rpc-misc-error+
                            :message "Can't read undo data from disk"))
        (let ((prevouts (%undo-prevout-table undo))
              (maxfee 0) (minfee nil) (maxfeerate 0) (minfeerate nil)
              (total-out 0) (totalfee 0) (inputs 0) (outputs 0)
              (maxtxsize 0) (mintxsize nil)
              (swtotal-size 0) (swtotal-weight 0) (swtxs 0)
              (total-size 0) (total-weight 0)
              (utxos 0) (utxo-size-inc 0) (utxo-size-inc-actual 0)
              (fee-array '()) (feerate-array '()) (txsize-array '()))
          (loop
            for tx in txs
            for i from 0
            for coinbase-p = (zerop i)
            do (let ((tx-total-out 0))
                 ;; Outputs are counted for EVERY transaction, coinbase
                 ;; included — Core :2054, before the coinbase continue.
                 (incf outputs (length (bl.ser:transaction-outputs tx)))
                 (bl.ser:dovector
                     (out (bl.ser:transaction-outputs tx))
                   (let* ((spk (bl.ser:tx-out-script-pubkey out))
                          (out-size (+ (txout-serialize-size spk) +per-utxo-overhead+)))
                     (incf tx-total-out (bl.ser:tx-out-value out))
                     (incf utxo-size-inc out-size)
                     ;; Genesis and the BIP30-repeated coinbases never enter
                     ;; the UTXO set, and unspendable outputs are dropped
                     ;; from it, so neither counts toward the *_actual
                     ;; figures (Core :2064-2072).
                     (unless (or (zerop height)
                                 (and coinbase-p
                                      (bl.val:bip30-repeat-block-p height))
                                 (bl.store:script-unspendable-p spk))
                       (incf utxos)
                       (incf utxo-size-inc-actual out-size))))
                 ;; Everything below is non-coinbase only (Core :2075-2077).
                 (unless coinbase-p
                   (let* ((tx-size (length (bl.ser:transaction-wire-bytes tx)))
                          (weight (bl.ser:transaction-weight tx))
                          (tx-total-in 0))
                     (incf inputs (length (bl.ser:transaction-inputs tx)))
                     (incf total-out tx-total-out)
                     (push tx-size txsize-array)
                     (setf maxtxsize (max maxtxsize tx-size))
                     (setf mintxsize (if mintxsize (min mintxsize tx-size) tx-size))
                     (incf total-size tx-size)
                     (incf total-weight weight)
                     (when (bl.ser:transaction-has-witness-p tx)
                       (incf swtxs)
                       (incf swtotal-size tx-size)
                       (incf swtotal-weight weight))
                     (bl.ser:dovector
                         (in (bl.ser:transaction-inputs tx))
                       (let* ((outpoint (bl.ser:tx-in-previous-output in))
                              (coin (gethash (outpoint-key
                                              (bl.ser:outpoint-hash outpoint)
                                              (bl.ser:outpoint-index outpoint))
                                             prevouts)))
                         (unless coin
                           ;; Incomplete undo data: fail closed rather than
                           ;; report a fee total that is silently too high.
                           (error 'rpc-error :code +rpc-misc-error+
                                             :message "Can't read undo data from disk"))
                         (let ((prevout-size
                                 (+ (txout-serialize-size
                                     (bl.store:utxo-entry-script-pubkey coin))
                                    +per-utxo-overhead+)))
                           (incf tx-total-in (bl.store:utxo-entry-value coin))
                           (decf utxo-size-inc prevout-size)
                           (decf utxo-size-inc-actual prevout-size))))
                     (let* ((txfee (- tx-total-in tx-total-out))
                            (feerate (if (plusp weight)
                                         (truncate (* txfee 4) weight)
                                         0)))
                       (push txfee fee-array)
                       (setf maxfee (max maxfee txfee))
                       (setf minfee (if minfee (min minfee txfee) txfee))
                       (incf totalfee txfee)
                       (push (cons feerate weight) feerate-array)
                       (setf maxfeerate (max maxfeerate feerate))
                       (setf minfeerate (if minfeerate (min minfeerate feerate) feerate)))))))
          (let* ((non-coinbase (max 0 (1- ntx)))
                 (all-stats
                   `(("avgfee" . ,(if (plusp non-coinbase) (truncate totalfee non-coinbase) 0))
                     ("avgfeerate" . ,(if (plusp total-weight)
                                          (truncate (* totalfee 4) total-weight)
                                          0))
                     ("avgtxsize" . ,(if (plusp non-coinbase)
                                         (truncate total-size non-coinbase)
                                         0))
                     ("blockhash" . ,(hash-to-hex block-hash))
                     ("feerate_percentiles" . ,(%feerate-percentiles feerate-array total-weight))
                     ("height" . ,height)
                     ("ins" . ,inputs)
                     ("maxfee" . ,maxfee)
                     ("maxfeerate" . ,maxfeerate)
                     ("maxtxsize" . ,maxtxsize)
                     ("medianfee" . ,(%truncated-median fee-array))
                     ("mediantime" . ,(bl.val:compute-median-time-past
                                       chain-state block-hash))
                     ("mediantxsize" . ,(%truncated-median txsize-array))
                     ("minfee" . ,(or minfee 0))
                     ("minfeerate" . ,(or minfeerate 0))
                     ("mintxsize" . ,(or mintxsize 0))
                     ("outs" . ,outputs)
                     ("subsidy" . ,(bl.val:calculate-block-subsidy height))
                     ("swtotal_size" . ,swtotal-size)
                     ("swtotal_weight" . ,swtotal-weight)
                     ("swtxs" . ,swtxs)
                     ("time" . ,(bl.ser:block-header-timestamp header))
                     ("total_out" . ,total-out)
                     ("total_size" . ,total-size)
                     ("total_weight" . ,total-weight)
                     ("totalfee" . ,totalfee)
                     ("txs" . ,ntx)
                     ("utxo_increase" . ,(- outputs inputs))
                     ("utxo_size_inc" . ,utxo-size-inc)
                     ("utxo_increase_actual" . ,(- utxos inputs))
                     ("utxo_size_inc_actual" . ,utxo-size-inc-actual))))
            (%select-block-stats all-stats stats-filter)))))))

;; calculate-block-subsidy lives in bitcoin-lisp.validation (consensus, now
;; network-aware incl. the regtest 150-block halving). The duplicate that lived
;; here was removed; getblockstats above calls the consensus one directly.

;;; --- Pruning Methods ---

(define-rpc "pruneblockchain" (node params)
  "Prune the blockchain up to a given block height.
PARAMS: [height]
Returns the height of the last pruned block."
  (unless (bl:pruning-enabled-p)
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
           (pruned (bl.store:prune-blocks-to-height
                    block-store chain-state target-height
                    :on-prune #'bl.val:delete-undo-file)))
      (bl:node-log :info "RPC pruneblockchain: pruned ~D blocks to height ~D"
                              pruned target-height)
      ;; Return the last pruned block height (matching Bitcoin Core).
      ;; Note: getblockchaininfo.pruneheight returns (1+ this) = first UNpruned block.
      (bl.store:chain-state-pruned-height chain-state)))))

(define-rpc "migrateblocks" (node ((nblocks :or 1000) (start :or 0)))
  "Convert legacy per-block files into flat blk?????.dat files.
PARAMS: [nblocks]  (default 1000)

No Bitcoin Core counterpart: Core has only ever had the flat format, so it has
never needed a migration. Ours is a deliberately incremental, resumable job --
it converts a budget of blocks in ascending height order and returns where to
resume, so an operator can convert a live node in slices and watch it between
them. Run it again until \"remaining\" is 0.

The node lock is held for the whole call, so the budget is not a formality:
converting means reading and rewriting every block, and a large nblocks stalls
block connection for as long as that takes. Prefer several small calls."
  (unless (and (integerp nblocks) (plusp nblocks))
    (error 'rpc-error :code +rpc-invalid-parameter+
                      :message "nblocks must be a positive integer"))
  (unless (and (integerp start) (>= start 0))
    (error 'rpc-error :code +rpc-invalid-parameter+
                      :message "start_height must be a non-negative integer"))
  ;; The node lock for the same reason pruneblockchain takes it: this rewrites
  ;; the block store and its index under the sync thread's feet.
  (with-node-lock (node)
    (let ((store (rpc-get-block-store node))
          (chain-state (rpc-get-chain-state node)))
      (multiple-value-bind (migrated next remaining)
          (bl.store:migrate-blocks-to-flat-files
           store chain-state :max-blocks nblocks :start-height start
           ;; Each block's undo data follows it into the matching rev file.
           ;; Storage cannot do this itself: the undo format lives above it.
           :on-migrated
           (lambda (entry)
             (bl.val:migrate-undo-to-flat
              (bl.store:block-index-entry-hash entry))))
        (bl:node-log
         :info "RPC migrateblocks: converted ~D block~:P; resume at height ~D; ~D legacy file~:P left"
         migrated next remaining)
        `(("migrated" . ,migrated)
          ("next_height" . ,next)
          ("remaining" . ,remaining))))))

;;; --- BIP157/158 block filter RPCs ---

(define-rpc "getblockfilter" (node (blockhash-hex (filtertype :or "basic")))
  "Return the BIP157 basic filter and filter header for a block.
PARAMS: (blockhash [filtertype]). Mirrors Bitcoin Core getblockfilter."
  (let* ((hash (and (stringp blockhash-hex) (parse-hex-hash blockhash-hex))))
    (unless hash
      ;; Core ParseHashV: parse failures are -8 (util.cpp:117-125); only the
      ;; well-formed-but-unknown lookup below is -5.
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "blockhash must be a hex string of length 64"))
    (unless (string-equal filtertype "basic")
      (error 'rpc-error :code +rpc-invalid-address-or-key+
                        :message (format nil "Unknown filtertype ~A" filtertype)))
    (let ((bfi (rpc-get-blockfilterindex node)))
      (unless (and bfi (bl.store:blockfilterindex-enabled bfi))
        (error 'rpc-error :code +rpc-misc-error+
                          :message "Index is not enabled for filtertype basic"))
      (unless (bl.store:get-block-index-entry (rpc-get-chain-state node) hash)
        (error 'rpc-error :code +rpc-invalid-address-or-key+ :message "Block not found"))
      (multiple-value-bind (filter header)
          (bl.store:blockfilterindex-get bfi hash)
        (unless filter
          (error 'rpc-error :code +rpc-misc-error+
                            :message "Could not find block filter for the given block"))
        `(("filter" . ,(bl.crypto:bytes-to-hex filter))
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

(defun %hash-table-keys (ht)
  (loop for k being the hash-keys of ht collect k))

(define-rpc "scanblocks" (node (action (scanobjects :array) (start :or 0) stop (filtertype :or "basic") options))
  "Return blockhashes relevant to a descriptor set using the block filter index.
PARAMS: (action [scanobjects] [start_height] [stop_height] [filtertype] [options]).
ACTION is \"start\", \"status\" or \"abort\". Mirrors Bitcoin Core scanblocks."
  (cond
    ((equal action "status")
     (bt:with-lock-held (*scanblocks-lock*)
       (if *scanblocks-running*
           `(("progress" . ,*scanblocks-progress*)
             ("current_height" . ,*scanblocks-current-height*))
           nil)))
    ((equal action "abort")
     (bt:with-lock-held (*scanblocks-lock*)
       (json-bool
        (when *scanblocks-running* (setf *scanblocks-abort* t) t))))
    ((equal action "start")
     (let ((bfi (rpc-get-blockfilterindex node)))
       ;; Empty is an array, as in scantxoutset above; null/omitted is not.
       (unless (%positional-array-p (second params))
         (error 'rpc-error :code +rpc-misc-error+
                           :message "scanobjects argument is required for the start action"))
       (unless (string-equal filtertype "basic")
         (error 'rpc-error :code +rpc-invalid-address-or-key+
                           :message (format nil "Unknown filtertype ~A" filtertype)))
       (unless (and bfi (bl.store:blockfilterindex-enabled bfi))
         (error 'rpc-error :code +rpc-misc-error+
                           :message "Index is not enabled for filtertype basic"))
       (unless (%reserve-scanblocks)
         (error 'rpc-error :code +rpc-invalid-parameter+
                           :message "Scan already in progress, use action \"abort\" or \"status\""))
       (unwind-protect
            (let* ((chain-state (rpc-get-chain-state node))
                   (block-store (rpc-get-block-store node))
                   (network (rpc-get-network node))
                   (tip (bl.store:current-height chain-state))
                   (stop (or stop tip))
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
                (let ((entry (bl.store:get-block-at-height chain-state height)))
                  (when entry
                    (let* ((hash (bl.store:block-index-entry-hash entry))
                           (filter (bl.store:blockfilterindex-get-filter bfi hash)))
                      (when filter
                        (multiple-value-bind (k0 k1)
                            (bl.store:block-filter-siphash-keys hash)
                          (when (bl.store:gcs-filter-match-any
                                 filter k0 k1 needle-list)
                            (when (or (not fp-check)
                                      (%block-matches-needles-p
                                       (bl.store:get-block block-store hash)
                                       hash needles))
                              (push (hash-to-hex hash) relevant))))))))
                ;; Last fully-scanned height; on abort this is where we stopped.
                (setf scanned-to height))
              `(("from_height" . ,start)
                ("to_height" . ,scanned-to)
                ("relevant_blocks" . ,(nreverse relevant))
                ("completed" . ,(json-bool (not aborted)))))
         (%release-scanblocks))))
    (t
     (error 'rpc-error :code +rpc-invalid-parameter+
                       :message (format nil "Invalid action '~A'" action)))))

(defun %block-matches-needles-p (block block-hash needles)
  "T if BLOCK genuinely touches any script in NEEDLES (false-positive check).
Re-derives the block's basic-filter element set (outputs + spent prevouts, the
latter from undo data when available). When the block body is unavailable
(pruned), returns T -- we can't verify, so we keep the filter match rather than
risk a false negative."
  (if block
      (let* ((undo (bl.val:get-undo-data block-hash))
             (spent (mapcar (lambda (e) (bl.store:utxo-entry-script-pubkey (third e)))
                            undo)))
        (some (lambda (e) (gethash e needles))
              (bl.store:basic-filter-elements block spent)))
      t))

;;; getdescriptoractivity — spend/receive activity for descriptors in blocks.

(defun %spk-object (script needles)
  "A scriptPubKey JSON object (hex, plus the matched descriptor when known)."
  `(("hex" . ,(bl.crypto:bytes-to-hex script))
    ,@(let ((desc (gethash script needles))) (when desc `(("desc" . ,desc))))))

(defun outpoint-key (txid index)
  (let ((k (make-array 36 :element-type '(unsigned-byte 8))))
    (replace k txid)
    (dotimes (i 4) (setf (aref k (+ 32 i)) (logand (ash index (* -8 i)) #xff)))
    k))

(defun %undo-prevout-table (undo)
  "Map (outpoint txid+index) -> utxo-entry for an undo list, for spend lookups."
  (let ((table (make-hash-table :test 'equalp)))
    (dolist (e undo table)
      (setf (gethash (outpoint-key (first e) (second e)) table) (third e)))))

(defun %tx-activity (tx needles prevout-fn base-fields)
  "Collect spend+receive activity entries for TX. NEEDLES maps script->desc;
PREVOUT-FN maps (txid index) -> utxo-entry (or NIL); BASE-FIELDS is an alist of
common fields (blockhash/height, or nil for mempool). Returns a list of entries."
  (let ((txid (bl.ser:transaction-hash tx))
        (acc '()))
    ;; Spends: each non-coinbase input whose prevout script matches.
    (loop for in across (bl.ser:transaction-inputs tx)
          for vin from 0
          for prev = (bl.ser:tx-in-previous-output in)
          for phash = (bl.ser:outpoint-hash prev)
          for pindex = (bl.ser:outpoint-index prev)
          ;; Skip the coinbase's null prevout (index 0xffffffff, all-zero hash).
          unless (and (= pindex #xffffffff) (every #'zerop phash))
            do (let ((entry (funcall prevout-fn phash pindex)))
                 (when entry
                   (let ((spk (bl.store:utxo-entry-script-pubkey entry)))
                     (when (gethash spk needles)
                       (push `(("type" . "spend")
                               ("amount" . ,(/ (bl.store:utxo-entry-value entry)
                                               100000000.0d0))
                               ,@base-fields
                               ("spend_txid" . ,(hash-to-hex txid))
                               ("spend_vin" . ,vin)
                               ("prevout_txid" . ,(hash-to-hex phash))
                               ("prevout_vout" . ,pindex)
                               ("prevout_spk" . ,(%spk-object spk needles)))
                             acc))))))
    ;; Receives: each output whose script matches.
    (loop for out across (bl.ser:transaction-outputs tx)
          for vout from 0
          for spk = (bl.ser:tx-out-script-pubkey out)
          when (gethash spk needles)
            do (push `(("type" . "receive")
                       ("amount" . ,(/ (bl.ser:tx-out-value out)
                                       100000000.0d0))
                       ,@base-fields
                       ("txid" . ,(hash-to-hex txid))
                       ("vout" . ,vout)
                       ("output_spk" . ,(%spk-object spk needles)))
                     acc))
    (nreverse acc)))

(define-rpc "getdescriptoractivity" (node ((blockhashes :array) (scanobjects :array) (include-mempool :bool-or t)))
  "Return spend/receive activity for descriptors within the given blocks (and
optionally the mempool). PARAMS: (blockhashes scanobjects [include_mempool]
[options]). Mirrors Bitcoin Core getdescriptoractivity."
  (let* ((network (rpc-get-network node))
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
                 (entry (and hash (bl.store:get-block-index-entry chain-state hash))))
            (unless entry
              (error 'rpc-error :code +rpc-invalid-address-or-key+
                                :message "Block not found"))
            (unless (bl.store:entry-on-active-chain-p chain-state entry)
              (error 'rpc-error :code +rpc-invalid-parameter+
                                :message "Block is not in main chain"))
            (push entry entries)))
        (dolist (entry (sort entries #'< :key #'bl.store:block-index-entry-height))
          (let* ((hash (bl.store:block-index-entry-hash entry))
                 (height (bl.store:block-index-entry-height entry))
                 (block (bl.store:get-block block-store hash))
                 (undo (bl.val:get-undo-data hash)))
            (unless block
              (error 'rpc-error :code +rpc-invalid-address-or-key+
                                :message "Block not available (pruned?)"))
            ;; A spending block with no undo data can't yield correct spend
            ;; activity; error rather than silently omitting spends (Core's
            ;; GetUndoChecked throws).
            (when (and (null undo)
                       (> (length (bl.ser:bitcoin-block-transactions block)) 1))
              (error 'rpc-error :code +rpc-misc-error+
                                :message "Undo data not available (pruned?)"))
            (let ((prevouts (%undo-prevout-table undo))
                  (base `(("blockhash" . ,(hash-to-hex hash)) ("height" . ,height))))
              (dolist (tx (bl.ser:bitcoin-block-transactions block))
                (push (%tx-activity tx needles
                                    (lambda (th ti) (gethash (outpoint-key th ti) prevouts))
                                    base)
                      chunks))))))
      ;; Mempool (blockhash/height omitted).
      (when include-mempool
        (let ((mempool (rpc-get-mempool node)))
          (when mempool
            (bl.mp:mempool-for-each
             mempool
             (lambda (txid entry)
               (declare (ignore txid))
               (let ((tx (bl.mp:mempool-entry-transaction entry)))
                 (push (%tx-activity
                        tx needles
                        (lambda (th ti)
                          ;; prevout from the UTXO set, else an unconfirmed
                          ;; mempool parent's output.
                          (or (bl.store:get-utxo utxo-set th ti)
                              (let ((ptx (bl.mp:mempool-get mempool th)))
                                (when (and ptx
                                           (< ti (length (bl.ser:transaction-outputs
                                                          (bl.mp:mempool-entry-transaction ptx)))))
                                  (let ((o (aref (bl.ser:transaction-outputs
                                                  (bl.mp:mempool-entry-transaction ptx)) ti)))
                                    (bl.store:make-utxo-entry
                                     :value (bl.ser:tx-out-value o)
                                     :script-pubkey (bl.ser:tx-out-script-pubkey o)))))))
                        nil)
                       chunks)))))))
      ;; chunks is reverse-order lists of entries; flatten once (O(total)).
      `(("activity" . ,(apply #'append (nreverse chunks)))))))

;;; --- Difficulty, deployments, getblockfrompeer (Core rpc/blockchain.cpp) ---

(define-rpc "getdifficulty" (node params)
  "Return the proof-of-work difficulty of the current best block (Bitcoin Core
getdifficulty)."
  (declare (ignore params))
  (let* ((chain-state (rpc-get-chain-state node))
         (tip (bl.store:get-block-index-entry
               chain-state (bl.store:best-block-hash chain-state)))
         (bits (if (and tip (bl.store:block-index-entry-header tip))
                   (bl.ser:block-header-bits
                    (bl.store:block-index-entry-header tip))
                   #x1d00ffff)))
    (%difficulty-from-bits bits)))

(define-rpc "syncwithvalidationinterfacequeue" (node params)
  "Wait for the validation interface queue to drain (Bitcoin Core
syncwithvalidationinterfacequeue, rpc/node.cpp).

A no-op here, and correctly so: Core needs it because its validation callbacks
run on a background scheduler thread, so a test that just submitted a block can
race the notifications. We dispatch notifications inline on the thread that
connected the block, so by the time any RPC can be serviced the queue Core is
waiting on has no counterpart left to drain. The method still has to EXIST —
the framework calls it after generate* in many tests."
  (declare (ignore node params))
  :null)

(defun %buried-deployment (active-height tip-height)
  "A buried-softfork deployment object for the block at TIP-HEIGHT.

⚠️ ACTIVE is reported for the block AFTER this one, so it turns true one block
BEFORE the activation height — which is not a slip but Core's stated contract.
getdeploymentinfo calls DeploymentActiveAfter (rpc/blockchain.cpp:1303) with
the comment `getdeploymentinfo reports the softfork as active from when the
chain height is one below the activation height' (:1301-1302), and
DeploymentActiveAfter is `pindexPrev->nHeight + 1 >= DeploymentHeight'
(deploymentstatus.h:14-18).

We compared the height directly, so for exactly one block — the one at
activation height minus one — we answered false where every Core node answers
true. Purely a reporting helper: its six callers are all this RPC's output, and
nothing here decides when a rule actually activates."
  `(("type" . "buried")
    ("active" . ,(json-bool (>= (1+ tip-height) active-height)))
    ("height" . ,active-height)))

(define-rpc "getdeploymentinfo" (node params)
  "Report soft-fork deployment status at the tip, or at the block named by an
optional blockhash param (Bitcoin Core getdeploymentinfo, rpc/blockchain.cpp:
1489-1540). Reports the buried deployments (bip34/bip66/bip65/csv/segwit/
taproot) using this node's per-network activation heights."
  (let* ((chain-state (rpc-get-chain-state node))
         (network (bl:node-network node))
         ;; Core takes a hash only (no height form), hence the stringp guard
         ;; in front of the shared hash-or-height parser.
         (entry (let ((hex (first params)))
                  (when hex
                    (unless (stringp hex)
                      (error 'rpc-error :code +rpc-invalid-parameter+
                                        :message "blockhash must be hexadecimal string"))
                    (%parse-hash-or-height-entry chain-state hex "blockhash"))))
         (height (if entry
                     (bl.store:block-index-entry-height entry)
                     (bl.store:current-height chain-state)))
         (best-hash (if entry
                        (bl.store:block-index-entry-hash entry)
                        (bl.store:best-block-hash chain-state)))
         ;; With no blockhash argument Core still has a blockindex — the tip —
         ;; and the BIP9 objects are computed from it. Resolving it here rather
         ;; than leaving ENTRY nil is what keeps the deployments in the answer
         ;; for the no-argument call, which is how the RPC is almost always
         ;; used.
         (at-entry (or entry
                       (and best-hash
                            (bl.store:get-block-index-entry
                             chain-state best-hash)))))
    `(("hash" . ,(if best-hash (hash-to-hex best-hash) ""))
      ("height" . ,height)
      ;; Core reports GetScriptFlagNames(GetBlockScriptFlags(*blockindex, ...))
      ;; (rpc/blockchain.cpp:1530-1533) — the flags for THAT BLOCK, so the
      ;; script_flag_exceptions table applies and this must be keyed by hash,
      ;; not by height. An exception block reports the shorter list, and the
      ;; two BIP16 blocks report an empty array, exactly as GetScriptFlagNames
      ;; returns {} for SCRIPT_VERIFY_NONE (interpreter.cpp:2201-2203).
      ;; json-array, because SCRIPT_VERIFY_NONE is now REACHABLE here: an
      ;; exception block's list is empty, and a bare NIL renders as JSON null
      ;; where Core returns an empty array (GetScriptFlagNames returns an empty
      ;; vector for NONE, interpreter.cpp:2200-2203, pushed into a VARR).
      ("script_flags" . ,(json-array
                          (bl.val:block-script-flags-list
                           best-hash height)))
      ("deployments"
       . (("bip34" . ,(%buried-deployment (bl.val:get-bip34-activation-height network) height))
          ("bip66" . ,(%buried-deployment (bl.val:get-bip66-activation-height network) height))
          ("bip65" . ,(%buried-deployment (bl.val:get-bip65-activation-height network) height))
          ("csv" . ,(%buried-deployment (bl.val:get-csv-activation-height network) height))
          ("segwit" . ,(%buried-deployment (bl.val:get-segwit-activation-height network) height))
          ;; taproot is a BIP9 deployment in every one of Core's five chain
          ;; parameter sets (kernel/chainparams.cpp:110-115 and the four
          ;; others), so Core reports it with a bip9 object and we reported it
          ;; as "buried" — a caller reading this to learn the bit, the window or
          ;; the signalling count got nothing from us at all.
          ,@(%bip9-deployments chain-state at-entry network))))))

(defun %bip9-deployment (chain-state entry deployment)
  "One BIP9 softfork object (Core SoftForkDescPushBack, rpc/blockchain.cpp:1307-1359).

⚠️ The two states are for DIFFERENT blocks. Core's `status' is
GetStateFor(blockindex->pprev) — the state OF this block — and `status_next' is
GetStateFor(blockindex), the state of the NEXT one (versionbits.cpp:202-203).
Reporting one value twice is the easy mistake here."
  (let* ((prev (and entry (bl.store:block-index-entry-prev-entry entry)))
         (height (if entry (bl.store:block-index-entry-height entry) 0))
         (current (bl.val:versionbits-state chain-state prev deployment))
         (next (bl.val:versionbits-state chain-state entry deployment))
         (since (bl.val:versionbits-since-height chain-state prev deployment))
         ;; Statistics exist only while the window is being counted
         ;; (versionbits.cpp:210-212).
         (counting (member current '(:started :locked-in)))
         ;; ⚠️ Core has TWO ways a deployment is active-since
         ;; (versionbits.cpp:219-223): the state IS active, or the NEXT block's
         ;; state is. Dropping the second is the same off-by-one that
         ;; %BURIED-DEPLOYMENT had — for the block one below the activation
         ;; height Core emits a height and active:true where we emitted
         ;; neither. Reachable on the live mainnet node, which holds the header
         ;; at taproot's activation height minus one.
         (active-since (cond ((eq current :active) since)
                             ((eq next :active) (1+ height))))
         (bip9
           `(,@(when counting
                 `(("bit" . ,(bl.val:vb-deployment-bit deployment))))
             ("start_time" . ,(bl.val:vb-deployment-start-time deployment))
             ("timeout" . ,(bl.val:vb-deployment-timeout deployment))
             ("min_activation_height"
              . ,(bl.val:vb-deployment-min-activation-height deployment))
             ("status" . ,(bl.val:versionbits-state-name current))
             ("since" . ,since)
             ("status_next" . ,(bl.val:versionbits-state-name next))
             ,@(when counting
                 (multiple-value-bind (period threshold elapsed count possible)
                     (bl.val:versionbits-statistics chain-state entry deployment)
                   `(("statistics"
                      . (("period" . ,period)
                         ("elapsed" . ,elapsed)
                         ("count" . ,count)
                         ,@(when (or (plusp threshold) possible)
                             `(("threshold" . ,threshold)
                               ("possible" . ,(json-bool possible)))))))))))) 
    `(,@(when active-since `(("height" . ,active-since)))
      ;; Core: active_since <= blockindex->nHeight + 1 (blockchain.cpp:1355).
      ("active" . ,(json-bool (and active-since (<= active-since (1+ height)))))
      ("type" . "bip9")
      ("bip9" . ,bip9))))

(defun %bip9-deployments (chain-state entry network)
  "Every BIP9 deployment defined for NETWORK, as (name . object) pairs.

Core skips a deployment that is not enabled on this chain
(blockchain.cpp:1310). Its `blockindex == nullptr' guard on the line below is
not reproduced: Core always has one, because genesis is always in its index,
whereas a node here can be asked before any block exists — and dropping the
deployments entirely for that node would be a worse answer than reporting them
in their initial state."
  (bl.val:with-versionbits-cache
    (let ((bl:*network* network))
      (loop for d in (bl.val:versionbits-deployments network)
            ;; NEVER_ACTIVE is Core's DeploymentEnabled = false: the deployment
            ;; exists in the table but is not reported at all.
            unless (= (bl.val:vb-deployment-start-time d)
                      bl.val:+vb-never-active+)
              collect (cons (bl.val:vb-deployment-name d)
                            (%bip9-deployment chain-state entry d))))))

(define-rpc "getblockfrompeer" (node (blockhash-hex peer-id))
  "Request block BLOCKHASH from the connected peer with id PEER-ID (Bitcoin Core
getblockfrompeer). PARAMS: (blockhash peer_id). We must already have the header,
the block must not already be downloaded, and the peer must be connected. Sends a
getdata(MSG_WITNESS_BLOCK) to that peer; the block arrives through the normal
block-processing path. Returns an empty object. The per-connection send lock makes
the cross-thread send safe."
  (unless (and (stringp blockhash-hex) (valid-hex-hash-p blockhash-hex))
    (error 'rpc-error :code +rpc-invalid-parameter+ :message "blockhash must be a hex string"))
  (unless (integerp peer-id)
    (error 'rpc-error :code +rpc-invalid-parameter+ :message "peer_id must be an integer"))
  (let* ((hash (parse-hex-hash blockhash-hex))
         (chain-state (rpc-get-chain-state node))
         (block-store (rpc-get-block-store node))
         (entry (bl.store:get-block-index-entry chain-state hash)))
    (unless entry
      (error 'rpc-error :code +rpc-misc-error+ :message "Block header missing"))
    (when (and (bl:pruning-enabled-p)
               (> (bl.store:block-index-entry-height entry)
                  (bl.store:current-height chain-state)))
      (error 'rpc-error :code +rpc-misc-error+
                        :message "In prune mode, only blocks that the node has already synced previously can be fetched from a peer"))
    (when (and block-store (bl.store:block-exists-p block-store hash))
      (error 'rpc-error :code +rpc-misc-error+ :message "Block already downloaded"))
    (let ((peer (bt:with-recursive-lock-held ((bl:node-lock node))
                  (find peer-id (bl:node-peers node)
                        :key #'bl.net:peer-id))))
      (unless peer
        (error 'rpc-error :code +rpc-misc-error+ :message "Peer does not exist"))
      (bl.net:send-message
       peer
       (bl.ser:make-getdata-message
        (list (bl.ser:make-inv-vector
               :type bl.ser:+inv-type-witness-block+
               :hash hash)))))
    ;; Core returns an empty object; an empty hash-table serializes as {}.
    (make-hash-table :test 'equal)))
