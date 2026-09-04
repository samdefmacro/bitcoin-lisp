(in-package #:bitcoin-lisp.rpc)

;;;; Mining RPCs (Core rpc/mining.cpp): getblocktemplate, submitblock, submitheader,
;;;; the generate* family, getnetworkhashps and prioritisetransaction.

;;; --- Mining RPCs ---

(defun %bits-to-target-hex (bits)
  "The 256-bit target for BITS as 64 lowercase hex chars (Core hashTarget.GetHex)."
  (format nil "~(~64,'0x~)" (bl.store:bits-to-target bits)))

(defun %bits-hex (bits)
  "Compact BITS as 8 lowercase hex chars."
  (format nil "~(~8,'0x~)" bits))

(defun %difficulty-from-bits (bits)
  "Difficulty ratio relative to difficulty-1 (bits 0x1d00ffff), like Core's
GetDifficulty."
  (let ((cur (bl.store:bits-to-target bits))
        (one (bl.store:bits-to-target #x1d00ffff)))
    (if (zerop cur) 0d0 (/ (float one 1d0) (float cur 1d0)))))

(defun %chain-name (network)
  "Core's chain name for NETWORK (getblockchaininfo.chain): main, test,
testnet4, signet, regtest."
  (bl.chain:chain-params-core-name (bl.chain:find-chain-params network)))

(defun %gbt-transactions (template)
  "The getblocktemplate `transactions` array for TEMPLATE: one object per
selected tx with data/txid/hash/depends/fee/sigops/weight. `depends` holds the
1-based indices of the in-template txs each tx spends from."
  (let ((entries (bl.mining:block-template-transactions template))
        (index-of (make-hash-table :test 'equalp)))
    ;; 1-based index of each selected txid (they are in parents-first order).
    (loop for e in entries
          for i from 1
          do (setf (gethash (bl.ser:transaction-hash
                             (bl.mp:mempool-entry-transaction e))
                            index-of)
                   i))
    (loop for e in entries
          for tx = (bl.mp:mempool-entry-transaction e)
          for depends = (let ((ds '()))
                          (bl.ser:dovector (in (bl.ser:transaction-inputs tx))
                            (let ((idx (gethash (bl.ser:outpoint-hash
                                                 (bl.ser:tx-in-previous-output in))
                                                index-of)))
                              (when idx (pushnew idx ds))))
                          (sort ds #'<))
          ;; Wire encoding (Core EncodeHexTx): a witnessless tx must NOT carry
          ;; marker/flag or the reconstructed block fails Core deserialization
          ;; with "Superfluous witness record".
          collect `(("data" . ,(bl.crypto:bytes-to-hex
                                (bl.ser:transaction-wire-bytes tx)))
                    ("txid" . ,(hash-to-hex (bl.ser:transaction-hash tx)))
                    ("hash" . ,(hash-to-hex (bl.ser:transaction-wtxid tx)))
                    ("depends" . ,depends)
                    ("fee" . ,(bl.mp:mempool-entry-fee e))
                    ("sigops" . ,(bl.mp:mempool-entry-sigops e))
                    ("weight" . ,(bl.ser:transaction-weight tx))))))

(defun %gbt-rules (network height)
  "Active versionbits soft-fork rule names for a block at HEIGHT on NETWORK, as
Bitcoin Core's getblocktemplate \"rules\" array. segwit carries the \"!\" prefix
(mandatory: a miner that doesn't understand it must not build the template),
mirroring Core. Without this array, segwit/taproot-aware miners reject the
template outright.

NETWORK is a parameter rather than a read of the global `*network*' because the
other two places in this same response that depend on the chain — the
signet_challenge field and the client-rules check — read the NODE's network.
Two sources of truth for one consensus fact inside one reply can disagree the
moment `*network*' is dynamically bound, which tests do routinely, and the
template cache is keyed on the node."
  (let ((net network) (rules '()))
    ;; Core pushes "csv" UNCONDITIONALLY (rpc/mining.cpp:949), not gated on its
    ;; activation height.
    (push "csv" rules)
    (when (>= height (bl.val:get-segwit-activation-height net))
      (push "!segwit" rules))
    ;; "!signet" tells the miner it must understand signet rules to mine this
    ;; template at all (rpc/mining.cpp:951-955). Without it a signet miner has
    ;; no way to know, which is half of why signet mining could not work here.
    (when (eq net :signet)
      (push "!signet" rules))
    ;; taproot carries NO "!" prefix: its VersionBitsDeploymentInfo sets
    ;; gbt_optional_rule = true (deploymentinfo.cpp:17-18), and gbt_rule_value
    ;; only prefixes the mandatory ones (rpc/mining.cpp:605-611).
    (when (>= height (bl.val:get-taproot-activation-height net))
      (push "taproot" rules))
    (nreverse rules)))

(defun %gbt-client-rules (params)
  "The rule names the caller declared support for, as a list of strings.

Core reads them only when \"rules\" is an ARRAY (rpc/mining.cpp:752-758). Any
other shape — a bare string, a number, or the key being absent altogether —
leaves the set EMPTY, which is exactly what makes the segwit check below fire.

⚠️ A NESTED array does NOT reach a handler as a vector. yason parses arrays as
vectors, but %NORMALIZE-JSON-VALUE recurses into every request object and turns
each nested non-empty vector back into a LIST (%NORMALIZE-JSON-VALUE, rpc/server.lisp), on both
the single-request and the batch path. So over the wire `{\"rules\":[\"segwit\"]}'
arrives here as the LIST (\"segwit\"). A vector-only test read NIL from every
real miner and answered all of them -8 — while a unit test that stuffed a vector
straight into the request hash-table passed, because it never went through the
normalizer. Both shapes are accepted here, and the tests now build their
requests through the normalizer so that gap cannot reopen.

A string is excluded explicitly: in Common Lisp a string is a vector, so
`{\"rules\": \"segwit\"}' would otherwise read as the one-element array Core
refuses to see.

A nested EMPTY array folds to NIL (server.lisp:355), which is indistinguishable
from an absent key — and that is correct, because in Core both leave
setClientRules empty."
  (let ((req (first params)))
    (when (hash-table-p req)
      (let ((v (gethash "rules" req)))
        (let ((elements (cond ((stringp v) nil)
                              ((listp v) v)
                              ((vectorp v) (coerce v 'list)))))
          ;; Core calls get_str() on each element, so a non-string one is a
          ;; type error rather than a rule that silently does not match
          ;; (rpc/mining.cpp:756-757, univalue type_error).
          (dolist (e elements)
            (unless (stringp e) (%json-type-error e "string")))
          elements)))))

(defun %gbt-check-client-rules (node params)
  "Refuse a template request from a miner that has not declared the rules it
must understand to mine what we are about to hand it (rpc/mining.cpp:845-856).

Both messages and their ORDER are Core's: signet is checked first. Neither is
reachable from mode=\"proposal\", because Core parses the rules array only
AFTER the proposal branch has already returned (rpc/mining.cpp:729-758) — a
proposal is a validation request, not a request for work."
  (let ((rules (%gbt-client-rules params)))
    (flet ((declared-p (name) (and (member name rules :test #'string=) t)))
      (when (and (eq (bl:node-network node) :signet)
                 (not (declared-p "signet")))
        (error 'rpc-error :code +rpc-invalid-parameter+
                          :message "getblocktemplate must be called with the signet rule set (call with {\"rules\": [\"segwit\", \"signet\"]})"))
      (unless (declared-p "segwit")
        (error 'rpc-error :code +rpc-invalid-parameter+
                          :message "getblocktemplate must be called with the segwit rule set (call with {\"rules\": [\"segwit\"]})")))))

(defun %gbt-proposal (node data)
  "Validate a submitted block template (Core getblocktemplate mode=\"proposal\",
rpc/mining.cpp:729-751).

Returns JSON null for a template the node would accept, or a BIP22 reject
reason string. A block the index already knows never reaches validation: Core
answers \"duplicate\" when it is fully valid, \"duplicate-invalid\" when it is
known bad, and \"duplicate-inconclusive\" otherwise (:741-747).

PoW is NOT checked — a proposal is an unmined template, which is the entire
point of the mode (check_pow=false, :750)."
  (unless (stringp data)
    (error 'rpc-error :code +rpc-type-error+
                      :message "Missing data String key for proposal"))
  (let ((block (handler-case
                   (let ((bytes (bl.crypto:hex-to-bytes data)))
                     (flexi-streams:with-input-from-sequence (s bytes)
                       (bl.ser:read-bitcoin-block s)))
                 (error ()
                   (error 'rpc-error :code +rpc-deserialization-error+
                                     :message "Block decode failed")))))
    (with-node-lock (node)
      (let* ((chain-state (rpc-get-chain-state node))
             (hash (bl.ser:block-header-hash
                    (bl.ser:bitcoin-block-header block)))
             (entry (bl.store:get-block-index-entry chain-state hash)))
        (when entry
          (return-from %gbt-proposal
            (case (bl.store:block-index-entry-status entry)
              (:valid "duplicate")
              (:invalid "duplicate-invalid")
              (t "duplicate-inconclusive"))))
        ;; Core requires a proposal to build on the CURRENT tip; TestBlockValidity
        ;; asserts it, so check first and answer BIP22's reason rather than
        ;; signalling out of the RPC.
        (unless (equalp (bl.ser:block-header-prev-block
                         (bl.ser:bitcoin-block-header block))
                        (bl.store:best-block-hash chain-state))
          (return-from %gbt-proposal "inconclusive-not-best-prevblk"))
        (multiple-value-bind (ok reason)
            (handler-case
                (bl.val:test-block-validity
                 block chain-state (rpc-get-utxo-set node))
              (error () (values nil :rejected)))
          (if ok
              :null
              (string-downcase (symbol-name (or reason :rejected)))))))))

(defun %gbt-request-mode (params)
  "(VALUES mode data) from getblocktemplate's optional template-request object."
  (let ((req (first params)))
    (if (hash-table-p req)
        (values (gethash "mode" req) (gethash "data" req))
        (values nil nil))))

(defconstant +gbt-cache-seconds+ 5
  "How long a getblocktemplate result is reused when only the MEMPOOL has
changed (Core rpc/mining.cpp: `GetTime() - time_start > 5`). A changed tip
always rebuilds, whatever the age.")

(defconstant +gbt-longpoll-first-wait-seconds+ 60
  "Core's first longpoll interval before it rechecks the mempool counter
(rpc/mining.cpp `checktxtime{std::chrono::minutes(1)}`).")

(defconstant +gbt-longpoll-later-wait-seconds+ 10
  "Core's interval after the first (`checktxtime = std::chrono::seconds(10)`).")

(defvar *gbt-cache* nil
  "The last getblocktemplate answer, as (node tip-hash txs-updated built-at
. result), or NIL. A global for the same reason Core's is a function-local
`static`: it is one node's most recent template, and rebuilding it per call is
the cost the cache exists to avoid.

The NODE is part of the key, which Core's cannot be — it has exactly one. Here
the RPC layer serves whatever node it is handed, and two regtest nodes share a
genesis tip hash, so a node-blind key hands one node the other's template.")

(defvar *gbt-cache-lock* (bt:make-lock "gbt-cache")
  "Guards *gbt-cache*: two miners polling concurrently must not interleave a
read of one field with a write of another.")

(defun %gbt-longpoll-id (params)
  "The longpollid the caller passed in the template request, or NIL."
  (let ((request (first params)))
    (when (hash-table-p request)
      (let ((v (gethash "longpollid" request)))
        (and (stringp v) v)))))

(defun %gbt-parse-longpoll-id (id tip-hex txs-updated)
  "Split a longpollid into (values watched-tip-hex watched-txs-updated).

Core's format is <64 hex chars of the best chain><nTransactionsUpdatedLast>
(rpc/mining.cpp:803-809). Anything else is treated as the CURRENT state, which
makes the wait return as soon as either changes — Core's own fallback for a
non-string id, kept here for a malformed one too, because the alternative is
erroring on an id a miner may legitimately have never seen a format for."
  (if (and (stringp id) (>= (length id) 64)
           (every (lambda (c) (digit-char-p c 16)) (subseq id 0 64))
           (every #'digit-char-p (subseq id 64))
           (plusp (length (subseq id 64))))
      (values (string-downcase (subseq id 0 64))
              (parse-integer id :start 64))
      (values tip-hex txs-updated)))

(defun %gbt-wait-for-change (node id)
  "Block until the tip or the mempool has moved past what ID describes (Core
rpc/mining.cpp:817-836).

Holds NO lock while waiting — Core takes a REVERSE_LOCK around the same loop —
and gives up after Core's first interval plus a few of its later ones, so a
miner polling a node that never changes still gets an answer rather than a
socket timeout."
  (let* ((tip-hex (hash-to-hex (bl.store:best-block-hash
                                (rpc-get-chain-state node))))
         (updated (bl.mp:mempool-transactions-updated
                   (rpc-get-mempool node))))
    (multiple-value-bind (watched-tip watched-updated)
        (%gbt-parse-longpoll-id id tip-hex updated)
      (let ((deadline (+ (get-universal-time)
                         +gbt-longpoll-first-wait-seconds+
                         (* 3 +gbt-longpoll-later-wait-seconds+))))
        (loop
          (let ((now-tip (hash-to-hex (bl.store:best-block-hash
                                       (rpc-get-chain-state node))))
                (now-updated (bl.mp:mempool-transactions-updated
                              (rpc-get-mempool node))))
            (when (or (not (string= now-tip watched-tip))
                      (/= now-updated watched-updated))
              (return)))
          ;; A node on its way down answers rather than holding the socket.
          (unless (bl:node-running node)
            (error 'rpc-error :code +rpc-client-not-connected+
                              :message "Shutting down"))
          (when (>= (get-universal-time) deadline)
            (return))
          (sleep 0.25))))))

(define-rpc "getblocktemplate" (node params)
  "Return a block template assembled from the mempool (Bitcoin Core
getblocktemplate). The optional template-request object's mode=\"proposal\"
(validate a submitted template without mining it) and longpollid (block until a
fresh template would differ) are both supported. Fields mirror Core.
The template is assembled as a full block around a dummy OP_TRUE coinbase (Core's
scriptDummy) and dry-run through TestBlockValidity (Core CreateNewBlock,
node/miner.cpp:227-231) — an invalid template errors here instead of reaching a
miner."
  ;; mode="proposal" answers before anything is assembled: it is a VALIDATION
  ;; request, not a request for work (rpc/mining.cpp:729-751). A mode that is
  ;; neither of the two Core knows is an error, not a silent template
  ;; (rpc/mining.cpp:717-726 for a non-string mode, :762-763 for an unknown
  ;; one) — a miner that misspells it was getting work it never asked for.
  (multiple-value-bind (mode data) (%gbt-request-mode params)
    (unless (or (null mode) (stringp mode))
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "Invalid mode"))
    (when (and (stringp mode) (string= mode "proposal"))
      (return-from rpc-getblocktemplate (%gbt-proposal node data)))
    (unless (or (null mode) (string= mode "template"))
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "Invalid mode")))
  ;; Core rpc/mining.cpp:765-774: on a non-test chain (mainnet only — all
  ;; test networks have m_is_test_chain), refuse while unconnected (-9,
  ;; RPC_CLIENT_NOT_CONNECTED) or in initial block download (-10,
  ;; RPC_CLIENT_IN_INITIAL_DOWNLOAD). These come BEFORE the longpoll wait:
  ;; holding a request open for a node that cannot mine anyway is exactly what
  ;; Core avoids by checking first. This file previously did the reverse and
  ;; said it was Core's order.
  (when (eq (bl:node-network node) :mainnet)
    (when (zerop (length (rpc-get-peers node)))
      (error 'rpc-error :code +rpc-client-not-connected+
                        :message "Bitcoin is not connected!"))
    (when (rpc-is-syncing node)
      (error 'rpc-error :code +rpc-client-in-initial-download+
                        :message "Bitcoin is in initial sync and waiting for blocks...")))
  ;; longpoll: hold the request open until there is something new to say.
  (let ((id (%gbt-longpoll-id params)))
    (when id (%gbt-wait-for-change node id)))
  ;; The client's declared rules are checked AFTER the longpoll wait, as Core
  ;; does, and BEFORE the cache is consulted — a cached template must never be
  ;; handed to a caller whose request should have been refused.
  (%gbt-check-client-rules node params)
  (let* ((chain-state (rpc-get-chain-state node))
         (mempool (rpc-get-mempool node))
         (tip-hex (hash-to-hex (bl.store:best-block-hash chain-state)))
         (txs-updated (bl.mp:mempool-transactions-updated mempool))
         (cached (%gbt-cached-result node tip-hex txs-updated)))
    (when cached (return-from rpc-getblocktemplate cached))
    (%gbt-build-and-cache node chain-state mempool tip-hex txs-updated)))

(defun %gbt-cached-result (node tip-hex txs-updated)
  "The cached template when it is still good, else NIL (Core rpc/mining.cpp's
`if (!pindexPrev || pindexPrev->GetBlockHash() != tip || (txsUpdated != last &&
GetTime() - time_start > 5))`).

Note the shape of Core's condition: a mempool change alone does NOT invalidate
the cache — it invalidates it only once the template is also older than five
seconds. That is what keeps a busy mainnet mempool from making every
getblocktemplate call reassemble a block."
  (bt:with-lock-held (*gbt-cache-lock*)
    (let ((cache *gbt-cache*))
      (when cache
        (destructuring-bind (cached-node cached-tip cached-updated built-at . result) cache
          (when (and (eq cached-node node)
                     (string= cached-tip tip-hex)
                     (or (= cached-updated txs-updated)
                         (<= (- (bl.ser:get-unix-time) built-at)
                             +gbt-cache-seconds+)))
            result))))))

(defun %gbt-build-and-cache (node chain-state mempool tip-hex txs-updated)
  "Assemble a fresh template and cache it under the state it was built from."
  (let ((result (%gbt-assemble node chain-state mempool tip-hex txs-updated)))
    (bt:with-lock-held (*gbt-cache-lock*)
      (setf *gbt-cache* (list* node tip-hex txs-updated
                               (bl.ser:get-unix-time)
                               result)))
    result))

(defun %gbt-assemble (node chain-state mempool tip-hex txs-updated)
  "Build one getblocktemplate result. Split out of RPC-GETBLOCKTEMPLATE so the
cache above wraps exactly the expensive part and nothing else."
  (declare (ignorable tip-hex))
  (let* (;; Node lock around the whole assembly: the chunk walk locks
         ;; internally (assembler %with-mempool-lock), but the template's
         ;; height/prev/finality context and its TestBlockValidity dry run
         ;; must see the SAME tip the transactions were selected against
         ;; (Core CreateNewBlock holds cs_main + pool.cs end-to-end,
         ;; node/miner.cpp:151).
         (template (with-node-lock (node)
                     (nth-value 1 (bl.mining:assemble-full-block
                                   chain-state mempool
                                   :coinbase-script-pubkey
                                   (make-array 1 :element-type '(unsigned-byte 8)
                                                 :initial-element #x51) ; OP_TRUE
                                   :utxo-set (rpc-get-utxo-set node)))))
         (bits (bl.mining:block-template-bits template)))
    `(("capabilities" . ("proposal"))
      ("version" . ,(bl.mining:block-template-version template))
      ("previousblockhash" . ,(hash-to-hex (bl.mining:block-template-prev-hash template)))
      ("transactions" . ,(%gbt-transactions template))
      ("coinbaseaux" . ,(make-hash-table :test 'equal))
      ("coinbasevalue" . ,(bl.mining:block-template-coinbase-value template))
      ("target" . ,(%bits-to-target-hex bits))
      ("mintime" . ,(bl.mining:block-template-mintime template))
      ("mutable" . ("time" "transactions" "prevblock"))
      ("noncerange" . "00000000ffffffff")
      ("sigoplimit" . ,bl.val:+max-block-sigops-cost+)
      ("sizelimit" . 4000000)          ; MAX_BLOCK_SERIALIZED_SIZE
      ("weightlimit" . ,bl.val:+max-block-weight+)
      ("curtime" . ,(bl.mining:block-template-curtime template))
      ("bits" . ,(%bits-hex bits))
      ("height" . ,(bl.mining:block-template-height template))
      ;; Core emits signet_challenge on a signet chain and nowhere else
      ;; (rpc/mining.cpp:1017-1019), as the raw challenge script in hex. A
      ;; signet miner cannot build the block's signet solution without it, so
      ;; omitting it made signet mining against this node impossible; we
      ;; reported the challenge from getmininginfo only, which no miner reads.
      ,@(when (eq (bl:node-network node) :signet)
          (let ((challenge (bl.val:signet-challenge-for-network
                            (bl:node-network node))))
            (when challenge
              (list (cons "signet_challenge"
                          (bl.crypto:bytes-to-hex challenge))))))
      ("default_witness_commitment"
       . ,(bl.crypto:bytes-to-hex
           (bl.mining:block-template-default-witness-commitment-script template)))
      ;; Active soft-fork rules + versionbits signaling state. No BIP9
      ;; deployment is currently pending on any of our networks, so
      ;; vbavailable is empty and vbrequired is 0.
      ("rules" . ,(%gbt-rules (bl:node-network node)
                              (bl.mining:block-template-height template)))
      ("vbavailable" . ,(make-hash-table :test 'equal))
      ("vbrequired" . 0)
      ;; longpoll id: <best chain hash><nTransactionsUpdatedLast> (Core
      ;; rpc/mining.cpp:995). The second half MUST be the mempool counter, not
      ;; the height: a miner longpolling on a height-derived id would never be
      ;; woken by mempool churn, which is most of what a new template is for.
      ("longpollid" . ,(format nil "~A~D"
                               (hash-to-hex (bl.mining:block-template-prev-hash template))
                               txs-updated)))))

(define-rpc "getmininginfo" (node params)
  "Return mining-related state (Bitcoin Core getmininginfo)."
  (declare (ignore params))
  (with-node-lock (node)                 ; consistent tip + pool count snapshot
   (let* ((chain-state (rpc-get-chain-state node))
         (mempool (rpc-get-mempool node))
         (height (bl.store:current-height chain-state))
         (tip (bl.store:get-block-index-entry
               chain-state (bl.store:best-block-hash chain-state)))
         (bits (if tip
                   (bl.ser:block-header-bits
                    (bl.store:block-index-entry-header tip))
                   #x1d00ffff))
         ;; Report the last assembled template (Bitcoin Core m_last_block_*),
         ;; rather than re-assembling on every status call.
         (template bl.mining:*last-block-template*)
         (network (bl:node-network node))
         ;; Core getmininginfo "next" (rpc/mining.cpp:450-458): the block that
         ;; would extend the tip, timed as the assembler times it — UpdateTime's
         ;; max(GetMinimumTime, now) — so its bits match getblocktemplate's.
         (next-bits (if tip
                        (let* ((mtp (or (bl.val:compute-median-time-past-from-entry tip) 0))
                               (curtime (max (bl.ser:get-unix-time)
                                             (bl.mining:next-block-mintime tip (1+ height) mtp))))
                          (bl.mining:next-block-required-bits chain-state tip curtime))
                        bits))
         (challenge (bl.val:signet-challenge-for-network network)))
      `(("blocks" . ,height)
        ;; OMITTED, not zero, until a template has been assembled: Core's
        ;; m_last_block_weight / m_last_block_num_txs are std::optional and
        ;; getmininginfo pushes each key only when it holds a value
        ;; (rpc/mining.cpp:466-467, node/miner.h:95-99). A caller must be able
        ;; to tell "nothing assembled yet" from "the last template held no
        ;; transactions", and 0 says both.
        ,@(when template
            `(("currentblockweight" . ,(bl.mining:block-template-total-weight template))
              ("currentblocktx" . ,(length (bl.mining:block-template-transactions template)))))
        ("bits" . ,(%bits-hex bits))
        ("difficulty" . ,(%difficulty-from-bits bits))
        ("target" . ,(%bits-to-target-hex bits))
        ("networkhashps" . ,(rpc-getnetworkhashps node nil))
        ("pooledtx" . ,(if mempool (bl.mp:mempool-count mempool) 0))
        ;; BTC/kvB, as Core's ValueFromAmount renders blockMinFeeRate.
        ("blockmintxfee" . ,(/ bl.mining:*block-min-tx-fee-rate* 100000000.0d0))
        ("chain" . ,(%chain-name network))
        ("next" . (("height" . ,(1+ height))
                   ("bits" . ,(%bits-hex next-bits))
                   ("difficulty" . ,(%difficulty-from-bits next-bits))
                   ("target" . ,(%bits-to-target-hex next-bits))))
        ,@(when challenge
            `(("signet_challenge" . ,(bl.crypto:bytes-to-hex challenge))))
        ("warnings" . #())))))

(defun activate-submitted-block (node block)
  "Validate+activate BLOCK through the consensus path, then ANNOUNCE it if it
became the tip. Returns the activate-block (values ok reason). Holds the node
lock: activation mutates the chainstate, UTXO set, and mempool exactly like a
network block, which the sync thread only ever does under the lock (Core
ProcessNewBlock takes cs_main).

The announcement is the part that was missing. RELAY-BLOCK existed and was
called from exactly one place — the P2P receive path — so a block that arrived
over the network was forwarded and a block this node MINED was not. Core makes
no such distinction: submitblock goes through ProcessNewBlock like any other
block, and the resulting tip change is what drives the announcement.

Nothing about the node looked wrong. It mined, it validated, it connected, its
own getblockcount advanced. The block simply never left, and a peer learned of
it only on its next getheaders — which is throttled to one per two minutes per
peer, so Core's functional tests, which allow sixty seconds for two nodes to
agree on a tip, timed out on a node that was working perfectly in isolation."
  (with-node-lock (node)
    (let* ((chain-state (rpc-get-chain-state node))
           (result (multiple-value-list
                    (bl.val:activate-block
                     block
                     chain-state
                     (rpc-get-block-store node)
                     (rpc-get-utxo-set node)
                     :mempool (rpc-get-mempool node)))))
      (when (first result)
        (let ((header (bl.ser:bitcoin-block-header block))
              (peers (bl:node-peers node)))
          ;; Only when it is the ACTIVE tip, which is the same condition the
          ;; P2P path applies (protocol.lisp): a stored side block announces
          ;; nothing.
          (when (and peers
                     (equalp (bl.store:best-block-hash chain-state)
                             (bl.ser:block-header-hash header)))
            (handler-case
                (bl.net:relay-block header nil peers)
              ;; A send failure must not turn an accepted block into a
              ;; submitblock error: the block IS connected either way.
              (error (e)
                (bl:log-warn "Announcing submitted block failed: ~A" e))))))
      (values-list result))))

(define-rpc "submitblock" (node (hex))
  "Submit a mined block (Bitcoin Core submitblock). PARAMS: (block-hex). Returns
JSON null on acceptance, \"duplicate\" if already known, \"duplicate-invalid\"
if already known to be invalid, \"inconclusive\" for a valid block that was
stored without becoming the tip, or a BIP22 reject reason string. Routes through the same activate-block consensus path as network blocks."
  (unless (and (stringp hex) (plusp (length hex)))
    ;; Core: RPC_DESERIALIZATION_ERROR (-22) "Block decode failed".
    (error 'rpc-error :code +rpc-deserialization-error+
                      :message "Block decode failed"))
  (let ((block (handler-case
                   (let ((bytes (bl.crypto:hex-to-bytes hex)))
                     (flexi-streams:with-input-from-sequence (s bytes)
                       (bl.ser:read-bitcoin-block s)))
                 (error ()
                   (error 'rpc-error :code +rpc-deserialization-error+
                                     :message "Block decode failed"))))
        (chain-state (rpc-get-chain-state node)))
    ;; Node lock: the duplicate probe and the activation must see one
    ;; chain state (Core submitblock reads the index and calls
    ;; ProcessNewBlock under cs_main); the lock is recursive, so the
    ;; nested activate-submitted-block lock is free.
    (with-node-lock (node)
     (let* ((hash (bl.ser:block-header-hash
                  (bl.ser:bitcoin-block-header block)))
           (entry (bl.store:get-block-index-entry chain-state hash)))
      (when entry
        ;; A known-invalid block short-circuits (Core AcceptBlockHeader,
        ;; validation.cpp:4231-4235 — BLOCK_FAILED_VALID → "duplicate-invalid").
        (when (eq (bl.store:block-index-entry-status entry) :invalid)
          (return-from rpc-submitblock "duplicate-invalid"))
        ;; "duplicate" only when we already HAVE the block data (Core
        ;; AcceptBlock fAlreadyHave = BLOCK_HAVE_DATA, validation.cpp:4351;
        ;; submitblock's accepted && !new_block, rpc/mining.cpp:1091-1093).
        ;; A header-only index entry (headers-sync / submitheader) must
        ;; proceed to full processing or the mined block is silently lost.
        (let ((store (rpc-get-block-store node)))
          (when (and store (bl.store:block-exists-p store hash))
            (return-from rpc-submitblock "duplicate"))))
      (bl.val:update-uncommitted-block-structures block chain-state)
      (multiple-value-bind (ok reason) (activate-submitted-block node block)
        (cond
          (ok nil)                        ; accepted → JSON null (BIP22 success)
          ;; A valid block stored on a side chain never reaches Core's
          ;; submitblock_StateCatcher (BlockChecked fires only on a connect
          ;; attempt), so Core reports it "inconclusive" (rpc/mining.cpp:
          ;; 1091-1095): neither rejected nor the new tip.
          ((eq reason :weaker-chain) "inconclusive")
          (t (string-downcase (symbol-name reason)))))))))

(define-rpc "submitheader" (node (hex))
  "Validate and add a block header to the header index (Bitcoin Core
submitheader). PARAMS: (hexdata) — an 80-byte serialized header. The previous
header must already be known. Returns null on success (including an already-known
header); errors if the parent is missing or the header fails validation."
  (unless (and (stringp hex) (plusp (length hex)))
    (error 'rpc-error :code +rpc-deserialization-error+ :message "Block header decode failed"))
  (let ((header (handler-case
                    (let ((bytes (bl.crypto:hex-to-bytes hex)))
                      (flexi-streams:with-input-from-sequence (s bytes)
                        (bl.ser:read-block-header s)))
                  (error ()
                    (error 'rpc-error :code +rpc-deserialization-error+
                                      :message "Block header decode failed"))))
        (chain-state (rpc-get-chain-state node)))
    ;; Node lock: process-headers mutates the header index the sync
    ;; thread's headers-sync also writes (Core ProcessNewBlockHeaders
    ;; takes cs_main).
    (with-node-lock (node)
     (let ((hash (bl.ser:block-header-hash header))
          (prev (bl.ser:block-header-prev-block header)))
      ;; Already known → success (Core returns null).
      (when (bl.store:get-block-index-entry chain-state hash)
        (return-from rpc-submitheader nil))
      ;; Parent must be present first (Core's LookupBlockIndex check).
      (unless (bl.store:get-block-index-entry chain-state prev)
        (error 'rpc-error :code +rpc-verify-error+
                          :message (format nil "Must submit previous header (~A) first"
                                           (hash-to-hex prev))))
      ;; Validate (PoW/MTP/difficulty) then add to the index.
      (multiple-value-bind (valid err)
          (bl.net:validate-header-chain (list header) chain-state)
        (unless valid
          (error 'rpc-error :code +rpc-verify-error+
                            :message (or err "header validation failed")))
        (bl.net:process-headers valid chain-state))
      nil))))

(defun %generate-to-script-pubkey (node script-pubkey nblocks maxtries)
  "Mine NBLOCKS blocks whose coinbase pays SCRIPT-PUBKEY, activating each through
the normal consensus path. Returns the list of mined block hashes (hex). Shared
by generatetoaddress and generatetodescriptor.

Two things about MAXTRIES, both Core's (rpc/mining.cpp:161-181). It is ONE
budget for the whole call, threaded through every block, not a fresh allowance
per block. And running out of it is a NORMAL RESULT, not an error: Core's
generateBlocks breaks out of its loop and returns the array it has, so a
deliberately bounded call like `generatetoaddress(1, addr, 0)' answers [] and a
call that solved two of three blocks answers those two. Signalling instead
threw away blocks that were already mined AND activated.

The loop also gives up when the node is asked to stop (Core's
`!chainman.m_interrupt' at the head of the same loop), returning what it has."
  (let ((chain-state (rpc-get-chain-state node))
        (mempool (rpc-get-mempool node))
        (tries-left maxtries)
        (hashes '()))
    (loop repeat nblocks
          until (bl:interrupt-requested-p)
          ;; Assemble under the node lock (one consistent tip+mempool view);
          ;; grind the nonce OUTSIDE it — Core likewise drops cs_main between
          ;; CreateNewBlock and ProcessNewBlock (rpc/mining.cpp GenerateBlocks),
          ;; and a stale-template block simply fails activation below.
          do (let ((block (with-node-lock (node)
                            (bl.mining:assemble-full-block
                             chain-state mempool
                             :coinbase-script-pubkey script-pubkey
                             ;; TestBlockValidity before mining (Core
                             ;; CreateNewBlock).
                             :utxo-set (rpc-get-utxo-set node)))))
               (multiple-value-bind (mined tries)
                   (bl.mining:mine-block block :max-tries tries-left)
                 (decf tries-left tries)
                 (unless mined (loop-finish)))
               (multiple-value-bind (ok reason) (activate-submitted-block node block)
                 (unless ok
                   (error 'rpc-error :code +rpc-misc-error+
                                     :message (format nil "Mined block rejected: ~A" reason)))
                 (push (hash-to-hex (bl.ser:block-header-hash
                                     (bl.ser:bitcoin-block-header block)))
                       hashes)))
          finally (return (nreverse hashes)))))

(define-rpc "generatetoaddress" (node (nblocks address (maxtries :or 1000000)))
  "Mine NBLOCKS blocks paying to ADDRESS and add them to the chain (Bitcoin Core
generatetoaddress; CPU mining, intended for regtest). PARAMS: (nblocks address
[maxtries]). Returns an array of the mined block hashes (hex) -- shorter than
NBLOCKS, and empty when MAXTRIES was 0, if the try budget ran out or the node
is stopping."
  (let ((network (bl:node-network node)))
    (unless (and (integerp nblocks) (plusp nblocks))
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "nblocks must be a positive integer"))
    (unless (stringp address)
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "address must be a string"))
    (multiple-value-bind (type script-pubkey) (bl.crypto:decode-address address network)
      (declare (ignore type))
      (unless script-pubkey
        ;; Core: RPC_INVALID_ADDRESS_OR_KEY (-5), rpc/mining.cpp:291.
        (error 'rpc-error :code +rpc-invalid-address-or-key+
                          :message "Error: Invalid address"))
      (json-array
       (%generate-to-script-pubkey node script-pubkey nblocks maxtries)))))

(define-rpc "generatetodescriptor" (node (nblocks descriptor (maxtries :or 1000000)))
  "Mine NUM-BLOCKS blocks whose coinbase pays the scriptPubKey of DESCRIPTOR
(Bitcoin Core generatetodescriptor; CPU mining, intended for regtest). PARAMS:
(num_blocks descriptor [maxtries]). The descriptor must expand to a single
script. Returns an array of the mined block hashes (hex) -- shorter than
NUM-BLOCKS, and empty when MAXTRIES was 0, if the try budget ran out or the
node is stopping."
  (let ((network (bl:node-network node)))
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
      (json-array
       (%generate-to-script-pubkey node script-pubkey nblocks maxtries)))))

(defun %resolve-coinbase-output-script (output network)
  "scriptPubKey for generateblock's OUTPUT — a descriptor (tried first, like
Core's getScriptFromDescriptor) or an address. Signals rpc-error if neither."
  (or (handler-case (caar (parse-output-descriptor output network))
        (rpc-error () nil))
      (handler-case
          (multiple-value-bind (type spk) (bl.crypto:decode-address output network)
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
             (entry (and mempool (bl.mp:mempool-get
                                  mempool (parse-hex-hash s)))))
        (unless entry
          (error 'rpc-error :code +rpc-invalid-address-or-key+
                            :message (format nil "Transaction ~A not in mempool." s)))
        (bl.mp:mempool-entry-transaction entry))
      (handler-case
          (bl.ser:parse-tx-payload (bl.crypto:hex-to-bytes s))
        (error ()
          (error 'rpc-error :code +rpc-deserialization-error+
                            :message (format nil "Transaction decode failed for ~A" s))))))

(defun %witness-commitment-script-for-txs (txs)
  "BIP141 witness-commitment scriptPubKey over a block whose coinbase wtxid is
zero and whose remaining transactions are TXS (Core GenerateCoinbaseCommitment)."
  (let* ((zeros (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
         (wtxids (cons zeros (mapcar #'bl.ser:transaction-wtxid txs)))
         (witness-root (bl.val:compute-merkle-root wtxids))
         (combined (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace combined witness-root)
    (bl.mining:build-witness-commitment-script
     (bl.crypto:hash256 combined))))

(define-rpc "generateblock" (node (output txs-arg (submit :bool-or t)))
  "Mine a single block containing exactly the given transactions (Bitcoin Core
generateblock; CPU mining, intended for regtest). PARAMS: (output [tx,...]
[submit]). OUTPUT is an address or descriptor for the coinbase, which is paid the
block subsidy only (Core builds the template with use_mempool=false). Each tx is a
64-hex mempool txid or a raw-tx hex. The assembled block is dry-run through
TestBlockValidity BEFORE mining, exactly like Core (rpc/mining.cpp:389-393) —
so submit=false hex is consensus-valid too, not just decodable. When SUBMIT
(default true) the block is then activated through the normal consensus path
and {hash} is returned; otherwise {hash, hex}."
  (let ((network (bl:node-network node)))
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
                      (template (bl.mining:assemble-block-template chain-state mempool))
                      (height (bl.mining:block-template-height template))
                      (coinbase (bl.mining:build-coinbase-transaction
                                 height
                                 (bl.val:calculate-block-subsidy height)
                                 :script-pubkey script-pubkey
                                 :witness-commitment-script (%witness-commitment-script-for-txs txs)))
                      (all-txs (cons coinbase txs))
                      (merkle (bl.val:compute-merkle-root
                               (mapcar #'bl.ser:transaction-hash all-txs)))
                      (header (bl.ser:make-block-header
                               :version (bl.mining:block-template-version template)
                               :prev-block (bl.mining:block-template-prev-hash template)
                               :merkle-root merkle
                               :timestamp (bl.mining:block-template-curtime template)
                               :bits (bl.mining:block-template-bits template)
                               :nonce 0))
                      (block (bl.ser:make-bitcoin-block
                              :header header :transactions all-txs)))
                 ;; TestBlockValidity before mining (Core rpc/mining.cpp:389-393): a
                 ;; consensus-invalid tx list errors instead of producing a doomed block.
                 (multiple-value-bind (ok reason)
                     (bl.val:test-block-validity
                      block chain-state (rpc-get-utxo-set node))
                   (unless ok
                     (error 'rpc-error :code +rpc-verify-error+
                                       :message (format nil "TestBlockValidity failed: ~A" reason))))
                 block))))
      (unless (bl.mining:mine-block block)
        (error 'rpc-error :code +rpc-misc-error+ :message "Failed to find a valid nonce"))
      (let ((hash-hex (hash-to-hex (bl.ser:block-header-hash
                                    (bl.ser:bitcoin-block-header block)))))
        (if submit
            (multiple-value-bind (ok reason) (activate-submitted-block node block)
              (unless (or ok (eq reason :weaker-chain))
                ;; Validity was already dry-run above; a failure here is the
                ;; activation itself (Core "ProcessNewBlock, block not
                ;; accepted", rpc/mining.cpp:158).
                (error 'rpc-error :code +rpc-verify-error+
                                  :message (format nil "Block not accepted: ~A" reason)))
              `(("hash" . ,hash-hex)))
            `(("hash" . ,hash-hex)
              ("hex" . ,(bl.crypto:bytes-to-hex
                         (bl.ser:serialize-witness-block block)))))))))

;;; --- getnetworkhashps, generate (Core rpc/mining.cpp) ---

(defun %number-arg (value default)
  "VALUE as an integer parameter, DEFAULT when it was omitted (JSON null).
Anything else present is Core's RPC_TYPE_ERROR: its argument dispatcher
type-checks an RPCArg::Type::NUM before the handler runs, so
`getnetworkhashps(\"a\", [])' is -3 rather than an answer computed from the
defaults the bad arguments were silently replaced by."
  (cond ((null value) default)
        ((integerp value) value)
        (t (%json-type-error value "number"))))

(defun %block-entry-time (entry)
  "ENTRY's header timestamp (Core CBlockIndex::GetBlockTime)."
  (bl.ser:block-header-timestamp (bl.store:block-index-entry-header entry)))

(defun %network-hash-ps (chain-state network nblocks height)
  "Average network hashes per second over the NBLOCKS blocks ending at HEIGHT
-- Bitcoin Core GetNetworkHashPS (rpc/mining.cpp:65-109).

NBLOCKS is -1 for \"since the last difficulty change\", which expands to
`pb->nHeight % DifficultyAdjustmentInterval() + 1'; HEIGHT is -1 for the tip,
and any other height ANCHORS the window there, so the answer is the rate at the
time that block was found rather than the rate now. Out-of-range arguments are
errors, not defaults: a monitoring caller asking about a height that does not
exist must not be handed a plausible number about a different block.

Two details of the arithmetic are Core's and both matter. The result is a
DOUBLE: an integer division reports 0 for every rate below 0.5 H/s, which is
every rate a regtest chain ever has. And the timespan is max(block time) -
min(block time) OVER THE WINDOW, not the difference of its endpoints -- block
timestamps are not monotonic, so the endpoints can span less time than the
window really covers, or none at all."
  (when (or (< nblocks -1) (zerop nblocks))
    (error 'rpc-error :code +rpc-invalid-parameter+
                      :message "Invalid nblocks. Must be a positive number or -1."))
  (when (or (< height -1) (> height (bl.store:current-height chain-state)))
    (error 'rpc-error :code +rpc-invalid-parameter+
                      :message "Block does not exist at specified height"))
  (let ((pb (if (minusp height)
                (bl.store:get-block-index-entry
                 chain-state (bl.store:best-block-hash chain-state))
                (bl.store:get-block-at-height chain-state height))))
    ;; No chain, or the genesis block: no work has been done yet.
    (if (or (null pb) (zerop (bl.store:block-index-entry-height pb)))
        0
        (let* ((pb-height (bl.store:block-index-entry-height pb))
               (lookup (min pb-height
                            (if (= nblocks -1)
                                (1+ (mod pb-height
                                         (bl.store:difficulty-adjustment-interval network)))
                                nblocks)))
               (pb0 pb)
               (min-time (%block-entry-time pb))
               (max-time min-time))
          ;; LOOKUP is clamped to PB's height, so this walk reaches genesis at
          ;; the earliest and every step has a predecessor; a broken index
          ;; shortens the window rather than erroring out of a status RPC.
          (dotimes (i lookup)
            (let ((prev (bl.store:block-index-entry-prev-entry pb0)))
              (unless prev (return))
              (setf pb0 prev)
              (let ((time (%block-entry-time pb0)))
                (setf min-time (min time min-time)
                      max-time (max time max-time)))))
          (if (= min-time max-time)
              0                         ; Core's divide-by-zero guard.
              (/ (float (- (bl.store:block-index-entry-chain-work pb)
                           (bl.store:block-index-entry-chain-work pb0))
                        1d0)
                 (- max-time min-time)))))))

(define-rpc "getnetworkhashps" (node (nblocks height))
  "Estimated network hashes/sec over the last NBLOCKS blocks (default 120, or
-1 for the blocks since the last difficulty change) as of HEIGHT (default -1,
the tip), from the chain work and the time spanned (Bitcoin Core
getnetworkhashps)."
  (%network-hash-ps (rpc-get-chain-state node)
                    (bl:node-network node)
                    (%number-arg nblocks 120)
                    (%number-arg height -1)))

(define-rpc "generate" (node params)
  "Core keeps `generate' registered ONLY so that calling it explains itself
(rpc/mining.cpp:258-261): it throws RPC_METHOD_NOT_FOUND with the help text.

An unregistered method would answer `Method not found' with no explanation, and
rpc_generate.py asserts on the message — it is a deprecation notice, not an
absence."
  (declare (ignore node params))
  (error 'rpc-error :code +rpc-method-not-found+
                    :message "generate\n\nhas been replaced by the -generate cli option. Refer to -help for more information.\n"))

;;; --- Transaction prioritisation (Bitcoin Core prioritisetransaction) ---

(define-rpc "prioritisetransaction" (node (txid-hex dummy fee-delta))
  "Adjust TXID's effective fee for mining selection by FEE-DELTA satoshis
(Bitcoin Core prioritisetransaction). PARAMS: (txid [dummy] fee-delta) —
dummy must be 0 or null (legacy priority is gone). The delta also counts for
mempool acceptance and RBF scoring; the fee is not actually paid. Returns T."
  (let* ((txid (and (stringp txid-hex) (parse-hex-hash txid-hex))))
    (unless txid
      ;; Core ParseHashV: parse/format failures are -8, util.cpp:117-125.
      (error 'rpc-error :code +rpc-invalid-parameter+
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
           (entry (bl.mp:mempool-get mempool txid)))
      ;; Core: dust-output txs can't enter with a nonzero delta, so refuse to
      ;; prioritise them after the fact too.
      (when entry
        (let ((tx (bl.mp:mempool-entry-transaction entry)))
          (loop for out across (bl.ser:transaction-outputs tx)
                do (when (< (bl.ser:tx-out-value out)
                            (bl.val:dust-threshold
                             (bl.ser:tx-out-script-pubkey out)))
                     (error 'rpc-error :code +rpc-invalid-parameter+
                                       :message "Priority is not supported for transactions with dust outputs.")))))
      (bl.mp:mempool-prioritise mempool txid fee-delta)
      t))))

(define-rpc "getprioritisedtransactions" (node params)
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
         (let ((entry (bl.mp:mempool-get mempool txid)))
           (push
            (cons (hash-to-hex txid)
                  `(("fee_delta" . ,delta)
                    ("in_mempool" . ,(json-bool entry))
                    ,@(when entry
                        `(("modified_fee" . ,(bl.mp:mempool-entry-modified-fee entry))))))
            result)))
       (bl.mp:mempool-deltas mempool)))
    (or result (make-hash-table :test 'equal))))
