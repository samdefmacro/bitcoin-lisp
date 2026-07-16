(in-package #:bitcoin-lisp)

;;; Configuration
;;;
;;; Global configuration variables and constants that are referenced
;;; across multiple subsystems. Loaded early so that storage, validation,
;;; and networking modules can reference these symbols at compile time.

;;;; Block Pruning Configuration

(defconstant +min-blocks-to-keep+ 288
  "Minimum number of recent blocks to keep on disk (matches Bitcoin Core).")

(defconstant +min-disk-space-for-block-files+ (* 550 1024 1024)
  "Floor for the effective automatic-prune target in bytes (Bitcoin Core
MIN_DISK_SPACE_FOR_BLOCK_FILES, validation.h:87). The per-chainstate halving
while an assumeutxo historical chainstate exists never pushes the target
below this.")

(defvar *prune-target-mib* nil
  "Block pruning target in MiB.
NIL = pruning disabled (default).
1 = manual-only mode (pruneblockchain RPC works, no automatic pruning).
>= 550 = automatic pruning to this target size.
Any other value signals an error at startup.")

(defvar *prune-after-height* nil
  "Minimum chain height before pruning can begin.
Set automatically based on network: 100000 for mainnet, 1000 for testnet.")

(defun pruning-enabled-p ()
  "Return T if pruning is enabled (any mode)."
  (and *prune-target-mib* (> *prune-target-mib* 0)))

(defun automatic-pruning-p ()
  "Return T if automatic pruning is enabled (not manual-only)."
  (and *prune-target-mib* (>= *prune-target-mib* 550)))

(defun prune-after-height (network)
  "Return the minimum chain height before pruning begins for NETWORK."
  (ecase network
    (:mainnet 100000)
    ((:testnet3 :testnet4 :signet :regtest) 1000)))

(defvar *minimum-chain-work-override* nil
  "When non-NIL, overrides the per-network nMinimumChainWork. For tests (the
real per-network floors are ~10^25 work, unreachable by synthetic chains).")

(defvar *assumevalid-override* :unset
  "When not :UNSET, overrides the per-network defaultAssumeValid block hash: a
32-byte WIRE-order hash forces that assumevalid point, or NIL disables the
assumevalid script-skip entirely. :UNSET (the default) uses the built-in
per-network value. For tests, and for operators who want to disable assumevalid.")

;;;; Assumeutxo snapshot commitments
;;;;
;;;; Bitcoin Core's m_assumeutxo_data (kernel/chainparams.cpp:166-191,
;;;; 287-300, 400-413, 521-534, 646-667 @ d3056bc): the trusted UTXO-set
;;;; snapshot heights shipped with the release. loadtxoutset only accepts
;;;; a snapshot whose base block appears here AND whose hash_serialized_3
;;;; content hash matches — same trust model as assumevalid.

(defstruct assumeutxo-data
  "One trusted UTXO-snapshot commitment (Bitcoin Core AssumeutxoData,
kernel/chainparams.h:60-75)."
  (height 0 :type (unsigned-byte 32))
  ;; Base block hash, 32 bytes WIRE order (the block-index key form).
  (blockhash nil :type (or null (simple-array (unsigned-byte 8) (32))))
  ;; hash_serialized_3 over the full UTXO set at HEIGHT, 32 bytes in
  ;; internal digest order (compute-utxo-set-hash's return form).
  (hash-serialized nil :type (or null (simple-array (unsigned-byte 8) (32))))
  ;; Number of transactions in the chain up to and including the base
  ;; block (Core AssumeutxoData::m_chain_tx_count).
  (chain-tx-count 0 :type (unsigned-byte 64)))

(defvar *assumeutxo-data-override* nil
  "When non-NIL, a list of assumeutxo-data entries consulted INSTEAD of the
built-in per-network table. Core's regtest-entries pattern for tests: dump a
synthetic chain's UTXO set, inject its real base hash + hash_serialized_3
here, and load it back through the full verification gate.")

(defun %assumeutxo-entry (height blockhash-hex hash-serialized-hex chain-tx-count)
  "Build an assumeutxo-data from Core's display-order (uint256 GetHex) hex
strings, reversing both to our internal byte orders."
  (make-assumeutxo-data
   :height height
   :blockhash (reverse (bitcoin-lisp.crypto:hex-to-bytes blockhash-hex))
   :hash-serialized (reverse (bitcoin-lisp.crypto:hex-to-bytes hash-serialized-hex))
   :chain-tx-count chain-tx-count))

(defun network-assumeutxo-data (network)
  "NETWORK's assumeutxo-data entries, newest last. Values mirror Bitcoin
Core kernel/chainparams.cpp exactly. *assumeutxo-data-override* (when
non-NIL) takes precedence over the built-in table."
  (or *assumeutxo-data-override*
      (ecase network
        (:mainnet
         (list
          (%assumeutxo-entry 840000
                             "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"
                             "a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96"
                             991032194)
          (%assumeutxo-entry 880000
                             "000000000000000000010b17283c3c400507969a9c2afd1dcf2082ec5cca2880"
                             "dbd190983eaf433ef7c15f78a278ae42c00ef52e0fd2a54953782175fbadcea9"
                             1145604538)
          (%assumeutxo-entry 910000
                             "0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821"
                             "4daf8a17b4902498c5787966a2b51c613acdab5df5db73f196fa59a4da2f1568"
                             1226586151)
          (%assumeutxo-entry 935000
                             "0000000000000000000147034958af1652b2b91bba607beacc5e72a56f0fb5ee"
                             "e4b90ef9eae834f56c4b64d2d50143cee10ad87994c614d7d04125e2a6025050"
                             1305397408)))
        (:testnet3
         (list
          (%assumeutxo-entry 2500000
                             "0000000000000093bcb68c03a9a168ae252572d348a2eaeba2cdf9231d73206f"
                             "f841584909f68e47897952345234e37fcd9128cd818f41ee6c3ca68db8071be7"
                             66484552)
          (%assumeutxo-entry 4840000
                             "00000000000000f4971a7fb37fbdff89315b69a2e1920c467654a382f0d64786"
                             "ce6bb677bb2ee9789c4a1c9d73e6683c53fc20e8fdbedbdaaf468982a0c8db2a"
                             536078574)))
        (:testnet4
         (list
          (%assumeutxo-entry 90000
                             "0000000002ebe8bcda020e0dd6ccfbdfac531d2f6a81457191b99fc2df2dbe3b"
                             "784fb5e98241de66fdd429f4392155c9e7db5c017148e66e8fdbc95746f8b9b5"
                             11347043)
          (%assumeutxo-entry 120000
                             "000000000bd2317e51b3c5794981c35ba894ce27d3e772d5c39ecd9cbce01dc8"
                             "10b05d05ad468d0971162e1b222a4aa66caca89da2bb2a93f8f37fb29c4794b0"
                             14141057)))
        (:signet
         (list
          (%assumeutxo-entry 160000
                             "0000003ca3c99aff040f2563c2ad8f8ec88bd0fd6b8f0895cfaf1ef90353a62c"
                             "fe0a44309b74d6b5883d246cb419c6221bcccf0b308c9b59b7d70783dbdf928a"
                             2289496)
          (%assumeutxo-entry 290000
                             "0000000577f2741bb30cd9d39d6d71b023afbeb9764f6260786a97969d5c9ac0"
                             "97267e000b4b876800167e71b9123f1529d13b14308abec2888bbd2160d14545"
                             28547497)))
        (:regtest
         ;; Core's regtest entries reference chains produced by its own
         ;; unit/functional test frameworks; shipped for table parity.
         (list
          (%assumeutxo-entry 110
                             "6affe030b7965ab538f820a56ef56c8149b7dc1d1c144af57113be080db7c397"
                             "b952555c8ab81fec46f3d4253b7af256d766ceb39fb7752b9d18cdf4a0141327"
                             111)
          (%assumeutxo-entry 200
                             "385901ccbd69dff6bbd00065d01fb8a9e464dede7cfe0372443884f9b1dcf6b9"
                             "17dcc016d188d16068907cdeb38b75691a118d43053b8cd6a25969419381d13a"
                             201)
          (%assumeutxo-entry 299
                             "7cc695046fec709f8c9394b6f928f81e81fd3ac20977bb68760fa1faa7916ea2"
                             "d2b051ff5e8eef46520350776f4100dd710a63447a8e01d917e92e79751a63e2"
                             334))))))

(defun assumeutxo-data-for-blockhash (network blockhash)
  "The assumeutxo-data entry whose base block is BLOCKHASH (32-byte wire
order), or NIL (Core AssumeutxoForBlockhash, kernel/chainparams.cpp:727)."
  (find blockhash (network-assumeutxo-data network)
        :key #'assumeutxo-data-blockhash :test #'equalp))

(defvar *parallel-block-validation* nil
  "When NIL (default), block-script validation runs single-threaded.

The per-block worker-thread path is disabled by default after a production
crash: at mainnet block scale the concurrent libsecp CFFI calls across the
worker threads corrupt SBCL's global alien-type cache (SB-ALIEN::RECORD-TYPE=,
an EQ hash-table mutated under a system lock), which then faults during an
unrelated alien op — the sync thread's socket-connect (make-sockaddr-for) — and
spirals into a \"maximum interrupt nesting depth exceeded\" fatal. testnet4's
small blocks never crossed the threshold (3h+ stable), but mainnet crashed at
tip within minutes. Serial validation removes the concurrent alien-cache writes.

IBD was network/disk-bound (sig checks were never the top profile frames), so
the speed cost is small. Set T to re-enable parallel validation on a low-volume
chain where the speedup matters and the scale stays safe.")

(defun minimum-chain-work (network)
  "Return NETWORK's nMinimumChainWork — the anti-DoS work floor below which a
header chain is refused admission to the block index (Bitcoin Core
consensus.nMinimumChainWork, kernel/chainparams.cpp). Values mirror Core
exactly. 0 disables the gate (regtest / custom signet). A node already past
this floor rejects any header whose chain would fall below it, blocking a peer
from bloating the index with a long low-work fork; a node still below it (fresh
genesis sync) accepts headers normally until it crosses the floor."
  (or *minimum-chain-work-override*
      (ecase network
        (:mainnet  #x0000000000000000000000000000000000000001128750f82f4c366153a3a030)
        (:testnet3 #x0000000000000000000000000000000000000000000017dde1c649f3708d14b6)
        (:testnet4 #x0000000000000000000000000000000000000000000009a0fe15d0177d086304)
        (:signet   #x00000000000000000000000000000000000000000000000000000b463ea0a4b8)
        (:regtest  0))))

(defvar *accept-datacarrier* t
  "Mempool policy: accept OP_RETURN data-carrier outputs (Bitcoin Core
-datacarrier, default true). When NIL the shared *MAX-DATACARRIER-BYTES*
budget is treated as ZERO (Core mempool_args.cpp:95-98: max_datacarrier_bytes
= nullopt -> value_or(0)), so any transaction with an OP_RETURN output is
rejected \"datacarrier\"; the output's NULL_DATA classification itself is
unchanged.")

(defvar *max-datacarrier-bytes* 100000
  "Mempool policy: the SHARED byte budget for OP_RETURN (data-carrier)
outputs across a whole transaction (Bitcoin Core -datacarriersize). Every
NULL_DATA output's raw scriptPubKey size — OP_RETURN byte + push opcodes +
data — draws from the one budget, so multiple OP_RETURN outputs are standard
as long as their total fits (Core IsStandardTx tracks datacarrier_bytes_left
over all outputs, policy.cpp:136-150; the old per-output 83-byte cap and the
one-OP_RETURN-per-tx rule are gone since the 2025 relaxation). Default
MAX_OP_RETURN_RELAY = MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR =
100,000 (policy.h:81-83). Consensus is unaffected; this only gates mempool
standardness.")

(defvar *peer-block-filters* nil
  "When true (and the block filter index is enabled), serve BIP157 compact
filter messages (getcfilters/getcfheaders/getcfcheckpt) and advertise
NODE_COMPACT_FILTERS (Bitcoin Core -peerblockfilters, default false).")

(defvar *tx-reconciliation* nil
  "When true, negotiate BIP330 transaction reconciliation (Erlay) support via
the sendtxrcncl handshake (Bitcoin Core -txreconciliation, DEBUG_ONLY, default
false — net_processing.h:41, init.cpp:574). At Core ref d3056bc only the
handshake + per-peer salt storage exist (no sketch exchange); we match that.")

(defvar *permit-bare-multisig* t
  "Mempool policy: treat bare (non-P2SH) multisig outputs as standard
(Bitcoin Core -permitbaremultisig, DEFAULT_PERMIT_BAREMULTISIG = true in Core).
When NIL, bare multisig is non-standard. Consensus is unaffected.")

;;;; Token Bucket Rate Limiter

(defstruct token-bucket
  "Token bucket for rate limiting. Allows RATE tokens per second with
maximum BURST capacity. Tokens accumulate while idle."
  (rate 1.0 :type single-float)
  (burst 1.0 :type single-float)
  (tokens 0.0 :type single-float)
  (last-refill 0 :type integer))

(defun make-rate-limiter (rate burst)
  "Create a token bucket with RATE tokens/sec and BURST max capacity.
Starts full (tokens = burst) to avoid rejecting initial messages."
  (make-token-bucket :rate (float rate)
                     :burst (float burst)
                     :tokens (float burst)
                     :last-refill (get-internal-real-time)))

(defun token-bucket-allow-p (bucket)
  "Consume one token from BUCKET if available.
Returns T if allowed, NIL if rate limited.
Refills tokens based on elapsed time since last check."
  (let* ((now (get-internal-real-time))
         (elapsed (/ (float (- now (token-bucket-last-refill bucket)))
                     (float internal-time-units-per-second)))
         (refilled (min (token-bucket-burst bucket)
                        (+ (token-bucket-tokens bucket)
                           (* elapsed (token-bucket-rate bucket))))))
    (setf (token-bucket-last-refill bucket) now)
    (if (>= refilled 1.0)
        (progn
          (setf (token-bucket-tokens bucket) (- refilled 1.0))
          t)
        (progn
          (setf (token-bucket-tokens bucket) refilled)
          nil))))

;;;; Recent Transaction Rejects Filter

(defstruct recent-rejects
  "Bounded set of recently rejected transaction hashes.
Uses a hash table for O(1) lookup and a ring buffer for FIFO eviction."
  (table (make-hash-table :test 'equalp) :type hash-table)
  (ring nil :type (or null simple-vector))
  (index 0 :type fixnum)
  (max-size 50000 :type fixnum))

(defun make-rejects-filter (&optional (max-size *recent-rejects-max-size*))
  "Create a recent rejects filter with MAX-SIZE capacity."
  (make-recent-rejects :table (make-hash-table :test 'equalp)
                       :ring (make-array max-size :initial-element nil)
                       :max-size max-size))

(defun recent-reject-p (filter hash)
  "Return T if HASH is in the rejects filter."
  (and filter (gethash hash (recent-rejects-table filter))))

(defun add-recent-reject (filter hash)
  "Add HASH to the rejects filter. Evicts oldest entry if at capacity.
Returns T if added, NIL if already present."
  (when filter
    (let ((table (recent-rejects-table filter)))
      ;; Already present
      (when (gethash hash table)
        (return-from add-recent-reject nil))
      ;; Evict oldest if at capacity
      (let* ((ring (recent-rejects-ring filter))
             (idx (recent-rejects-index filter))
             (old (aref ring idx)))
        (when old
          (remhash old table))
        ;; Insert new entry
        (setf (aref ring idx) hash)
        (setf (gethash hash table) t)
        (setf (recent-rejects-index filter)
              (mod (1+ idx) (recent-rejects-max-size filter)))
        t))))

(defun clear-recent-rejects (filter)
  "Clear all entries from the rejects filter. O(1) when already empty — the
filter is now cleared on every block connect (Core ActiveTipChange resets
RecentRejectsFilter on every tip change), which during IBD would otherwise
wipe a 50k-slot ring per block for nothing."
  (when (and filter (plusp (hash-table-count (recent-rejects-table filter))))
    (clrhash (recent-rejects-table filter))
    (let ((ring (recent-rejects-ring filter)))
      (dotimes (i (length ring))
        (setf (aref ring i) nil)))
    (setf (recent-rejects-index filter) 0)))

;;;; DoS Protection Configuration

(defvar *rate-limit-inv* '(50.0 . 200.0)
  "Rate limit for INV messages: (rate-per-sec . burst).")

(defvar *rate-limit-tx* '(10.0 . 50.0)
  "Rate limit for TX messages: (rate-per-sec . burst).")

(defvar *rate-limit-addr* '(1.0 . 10.0)
  "Rate limit for ADDR/ADDRV2 messages: (rate-per-sec . burst).")

(defvar *rate-limit-getdata* '(20.0 . 100.0)
  "Rate limit for GETDATA messages: (rate-per-sec . burst).")

(defvar *rate-limit-headers* '(10.0 . 50.0)
  "Rate limit for HEADERS messages: (rate-per-sec . burst).")

(defvar *rate-limit-serve* '(5.0 . 20.0)
  "Rate limit for peer SERVE requests — getheaders/getblocks/getaddr, shared
bucket: (rate-per-sec . burst). These answer a peer from our chain/address
state; getheaders/getblocks each walk the active chain (O(tip-fork)), so a peer
spamming them could load the sync thread. A normal syncing peer sends a
getheaders per ~2000-block batch (well under this); a flood is throttled, then
disconnected by handle-message's rate-limit gate.")

(defvar *rpc-rate-limit* '(100.0 . 200.0)
  "Rate limit for RPC requests: (rate-per-sec . burst).")

(defconstant +max-message-payload+ (* 4 1000 1000)
  "Maximum P2P message payload size in bytes: 4,000,000, matching Bitcoin Core
MAX_PROTOCOL_MESSAGE_LENGTH (net.h). Not 4 MiB -- Core uses decimal 4e6.")

(defconstant +max-rpc-body-size+ (* 1 1024 1024)
  "Maximum RPC request body size in bytes (1 MB).")

(defconstant +handshake-timeout-seconds+ 30
  "Maximum seconds to complete version handshake.")

(defvar *recent-rejects-max-size* 50000
  "Maximum entries in the recent transaction rejects filter.")

;;;; -----------------------------------------------------------------------
;;;; bitcoin.conf and command-line argument parsing
;;;;
;;;; Bitcoin Core-style configuration: -key=value CLI arguments and a
;;;; bitcoin.conf file, both mapped onto start-node's keyword parameters by
;;;; start-node-from-args (node.lisp). The parsers here are pure string
;;;; functions so they can be unit-tested without launching a node.

(defun conf-parse-bool (value)
  "Interpret a config VALUE string as a boolean. \"1\"/\"true\"/\"yes\"/\"on\"
and the empty string (a bare -flag) are true; \"0\"/\"false\"/\"no\"/\"off\"
are false; anything else is true (matching Core's lenient -flag semantics)."
  (let ((v (string-downcase (string-trim '(#\Space #\Tab) value))))
    (cond ((member v '("0" "false" "no" "off") :test #'string=) nil)
          (t t))))

(defun conf-parse-int (value)
  "Parse a config VALUE as an integer, or signal an error."
  (let ((v (string-trim '(#\Space #\Tab) value)))
    (handler-case (parse-integer v)
      (error () (error "Invalid integer config value: ~S" value)))))

(defun conf-parse-loglevel (value)
  "Map a -loglevel value to one of :debug :info :warn :error."
  (let ((v (string-downcase (string-trim '(#\Space #\Tab) value))))
    (cond ((member v '("debug" "trace") :test #'string=) :debug)
          ((string= v "info") :info)
          ((member v '("warn" "warning") :test #'string=) :warn)
          ((member v '("error" "none") :test #'string=) :error)
          (t (error "Invalid loglevel: ~S (want debug/info/warn/error)" value)))))

(defconstant +default-proxy-port+ 9050
  "Default SOCKS5 proxy port when -proxy/-onion gives no :port (Tor's SOCKS
port; Bitcoin Core init.cpp:1721 Lookup(..., 9050, ...)).")

(defun conf-parse-proxy (value)
  "Parse a -proxy/-onion VALUE \"ip[:port]\" into (values host port), with
PORT defaulting to 9050. Returns NIL for \"0\" or the empty string — Core's
-noproxy / -proxy=0 'remove the proxy' convention (init.cpp:1700-1704).
Accepts \"[ipv6]:port\" / \"[ipv6]\"; a trailing :port is only honored when it
is all digits after a single colon, so a bare IPv6 address is host-only
(same splitting rules as parse-node-endpoint, node.lisp)."
  (let ((v (string-trim '(#\Space #\Tab) value)))
    (cond
      ((or (zerop (length v)) (string= v "0")) nil)
      ;; [ipv6]:port or [ipv6]
      ((char= (char v 0) #\[)
       (let ((close (position #\] v)))
         (if (null close)
             (values v +default-proxy-port+)
             (let ((host (subseq v 1 close))
                   (rest (subseq v (1+ close))))
               (if (and (plusp (length rest)) (char= (char rest 0) #\:)
                        (plusp (length (subseq rest 1)))
                        (every #'digit-char-p (subseq rest 1)))
                   (values host (parse-integer rest :start 1))
                   (values host +default-proxy-port+))))))
      (t
       (let ((colon (position #\: v :from-end t)))
         (if (and colon
                  (< (1+ colon) (length v))
                  (every #'digit-char-p (subseq v (1+ colon)))
                  ;; A single colon => host:port; multiple => bare IPv6.
                  (= colon (position #\: v)))
             (values (subseq v 0 colon) (parse-integer v :start (1+ colon)))
             (values v +default-proxy-port+)))))))

(defun conf-parse-network-name (value)
  "Map an -onlynet VALUE to a network keyword (Core ParseNetwork,
netbase.cpp: ipv4/ipv6/onion/i2p/cjdns; the old \"tor\" alias is gone)."
  (let ((v (string-downcase (string-trim '(#\Space #\Tab) value))))
    (cond ((string= v "ipv4") :ipv4)
          ((string= v "ipv6") :ipv6)
          ((string= v "onion") :torv3)
          ((string= v "i2p") :i2p)
          ((string= v "cjdns") :cjdns)
          (t (error "Unknown network specified in -onlynet: ~S" value)))))

(defun conf-section-name (network)
  "The bitcoin.conf [section] header that scopes options to NETWORK."
  (ecase network
    (:mainnet "main")
    (:testnet3 "test")
    (:testnet4 "testnet4")
    (:signet "signet")
    (:regtest "regtest")))

(defun parse-cli-args (args)
  "Parse Bitcoin Core-style CLI ARGS (a list of strings) into an alist of
 (lower-case-key . value-string), in order. Accepts -key=value and --key=value;
a bare -key means key=1 and -nokey means key=0. Non-flag tokens are ignored.
Later occurrences are kept too, so an assoc lookup returns the first (earliest)."
  (let ((out nil))
    (dolist (arg args (nreverse out))
      (when (and (stringp arg) (plusp (length arg)) (char= (char arg 0) #\-))
        (let* ((s (string-left-trim "-" arg))
               (eq-pos (position #\= s)))
          (cond
            ((zerop (length s)))                                   ; bare "-" / "--"
            (eq-pos
             (push (cons (string-downcase (subseq s 0 eq-pos))
                         (subseq s (1+ eq-pos)))
                   out))
            ;; Bare -noKEY negates; bare -KEY asserts.
            ((and (> (length s) 2) (string-equal (subseq s 0 2) "no"))
             (push (cons (string-downcase (subseq s 2)) "0") out))
            (t (push (cons (string-downcase s) "1") out))))))))

(defun parse-bitcoin-conf (text &optional network)
  "Parse bitcoin.conf TEXT into an alist of (lower-case-key . value-string).
Blank lines and #-comments are skipped. A [section] header scopes the keys that
follow to a network; only keys in the global area (before any section) or in the
section matching NETWORK are returned. When NETWORK is NIL, section headers are
ignored and every key is returned."
  (let ((out nil)
        (active t)
        (want (and network (conf-section-name network))))
    (with-input-from-string (in text)
      (loop for raw = (read-line in nil nil)
            while raw
            do (let ((line (string-trim '(#\Space #\Tab #\Return) raw)))
                 (cond
                   ((zerop (length line)))                          ; blank
                   ((char= (char line 0) #\#))                      ; comment
                   ((and (char= (char line 0) #\[)
                         (char= (char line (1- (length line))) #\]))
                    (let ((sec (string-downcase
                                (string-trim '(#\Space)
                                             (subseq line 1 (1- (length line)))))))
                      (setf active (or (null want) (string= sec want)))))
                   (active
                    (let ((eq-pos (position #\= line)))
                      (when eq-pos
                        (push (cons (string-downcase
                                     (string-trim '(#\Space #\Tab) (subseq line 0 eq-pos)))
                                    (string-trim '(#\Space #\Tab) (subseq line (1+ eq-pos))))
                              out))))))))
    (nreverse out)))

(defun resolve-network-from-config (alist &optional (default :testnet3))
  "Determine the network from a merged config ALIST. Honors -regtest/-signet/
-testnet4/-testnet flags (in Core's precedence) and -chain=main|test|testnet4|
signet|regtest, else returns DEFAULT."
  (flet ((flag (k) (let ((c (assoc k alist :test #'string=)))
                     (and c (conf-parse-bool (cdr c)))))
         (val (k) (let ((c (assoc k alist :test #'string=))) (and c (cdr c)))))
    (cond
      ((flag "regtest") :regtest)
      ((flag "signet") :signet)
      ((flag "testnet4") :testnet4)
      ((flag "testnet") :testnet3)
      ((val "chain")
       (let ((c (string-downcase (val "chain"))))
         (cond ((member c '("main" "mainnet") :test #'string=) :mainnet)
               ((member c '("test" "testnet" "testnet3") :test #'string=) :testnet3)
               ((string= c "testnet4") :testnet4)
               ((string= c "signet") :signet)
               ((string= c "regtest") :regtest)
               (t (error "Unknown -chain value: ~S" c)))))
      (t default))))

(defparameter *cli-option-spec*
  '(("datadir"           :data-directory     :string)
    ("txindex"           :txindex            :bool)
    ("blockfilterindex"  :blockfilterindex   :bool)
    ("coinstatsindex"    :coinstatsindex     :bool)
    ("prune"             :prune              :int)
    ("dbcache"           :dbcache-mib        :int)
    ("maxconnections"    :max-peers          :int)
    ("rpcport"           :rpc-port           :int)
    ("rpcbind"           :rpc-bind           :string)
    ("rpcuser"           :rpc-user           :string)
    ("rpcpassword"       :rpc-password       :string)
    ("listen"            :listen             :bool)
    ("bind"              :listen-bind        :string)
    ("listenonion"       :listen-onion       :bool)
    ("torcontrol"        :tor-control        :string)
    ("torpassword"       :tor-password       :string)
    ("v2transport"       :v2transport        :bool)
    ("reindexchainstate" :reindex-chainstate :bool)
    ("reindex-chainstate" :reindex-chainstate :bool)
    ("forcecompactdb"    :force-compact-db   :bool)
    ("peerblockfilters"  :peer-block-filters :bool)
    ("txreconciliation"  :tx-reconciliation  :bool)
    ("webui"             :webui              :bool)
    ("webuipath"         :webui-path         :string)
    ("webuiopen"         :webui-open         :bool)
    ("wallet"            :wallet             :bool)
    ("logfile"           :log-file           :string)
    ("loglevel"          :log-level          :loglevel)
    ("sync"              :sync               :bool))
  "Maps a Bitcoin Core-style option name to a start-node keyword and its value
type. Network selection (-chain/-testnet/...) and -server/-debug are handled
specially in config-alist->start-node-plist.")

(defun conf-effective-listen-flags (alist)
  "Replay Core's -proxy/-listen/-listenonion soft-set chain over a merged
config ALIST: -proxy soft-disables -listen (init.cpp:786-790), -listen=0
soft-disables -listenonion (init.cpp:808-809), and the explicit contradiction
-listen=0 -listenonion=1 is an init ERROR (init.cpp:1022-1024). Returns
(VALUES listen-p listen-onion-p). The ONE encoding of this chain — both the
start-node plist assembly and apply-config-globals' -onlynet=onion gate
derive from it, so the two can never drift."
  (flet ((lk (k) (let ((c (assoc k alist :test #'string=))) (and c (cdr c)))))
    (let* ((proxy-p (let ((v (lk "proxy"))) (and v (conf-parse-proxy v) t)))
           (listen-p (let ((v (lk "listen")))
                       (if v (conf-parse-bool v) (not proxy-p))))
           (lo (lk "listenonion"))
           (lo-p (and lo (conf-parse-bool lo))))
      (when (and (not listen-p) lo-p)
        (error "Cannot set -listen=0 together with -listenonion=1"))
      (values listen-p
              (and listen-p (if lo lo-p t))))))

(defun config-alist->start-node-plist (alist network)
  "Convert a merged config ALIST (CLI over file) into a plist of start-node
keyword arguments, coercing each value by its spec type. NETWORK is the already-
resolved network. Honors -server (enable RPC on the default port when no
-rpcport is given) and -debug (=> loglevel debug unless -loglevel is set)."
  (let ((plist (list :network network)))
    (flet ((lookup (k) (assoc k alist :test #'string=)))
      (dolist (spec *cli-option-spec*)
        (destructuring-bind (name keyword type) spec
          (let ((cell (lookup name)))
            (when cell
              (let ((raw (cdr cell)))
                (setf (getf plist keyword)
                      (ecase type
                        (:string raw)
                        (:bool (conf-parse-bool raw))
                        (:int (conf-parse-int raw))
                        (:loglevel (conf-parse-loglevel raw)))))))))
      ;; -debug is a shortcut for -loglevel=debug (unless loglevel was set).
      (let ((debug (lookup "debug")))
        (when (and debug (conf-parse-bool (cdr debug)) (not (lookup "loglevel")))
          (setf (getf plist :log-level) :debug)))
      ;; -server enables RPC; give it the network default port if none was set.
      (let ((server (lookup "server")))
        (when (and server (conf-parse-bool (cdr server))
                   (not (getf plist :rpc-port)))
          (setf (getf plist :rpc-port) (network-rpc-port network))))
      ;; -proxy soft-disables listening, to protect privacy (Bitcoin Core
      ;; init.cpp:786-790: SoftSetBoolArg("-listen", false)). Soft = only when
      ;; the user gave no explicit -listen; same only-if-unset pattern as
      ;; -server/-debug above. -proxy=0 (a cleared proxy) does not trigger it.
      (let ((proxy (lookup "proxy")))
        (when (and proxy
                   (conf-parse-proxy (cdr proxy))
                   (not (lookup "listen")))
          (setf (getf plist :listen) nil)))
      ;; -listen=0 (given, or soft-set by -proxy just above) disables the
      ;; onion service (conf-effective-listen-flags: the shared soft-set
      ;; chain, which also signals on -listen=0 -listenonion=1).
      (multiple-value-bind (listen-p listen-onion-p)
          (conf-effective-listen-flags alist)
        (declare (ignore listen-p))
        (unless listen-onion-p
          (setf (getf plist :listen-onion) nil))))
    plist))

(defun apply-config-globals (merged)
  "Set the process-global policy/consensus config specials from the MERGED config
alist. These options have no start-node keyword because they configure global
specials directly: -datacarrier, -datacarriersize, -permitbaremultisig,
-limitclustercount/-limitclustersize (cluster mempool acceptance limits),
-signetchallenge (a custom signet block-challenge), the SOCKS5 proxy
options -proxy/-onion/-proxyrandomize (networking's *proxy*/*onion-proxy*),
and the network-reachability options -onlynet (repeatable)/-cjdnsreachable
(networking's *reachable-networks*/*cjdns-reachable*).
CLI-over-file precedence is already applied in MERGED. Called at startup by
start-node-from-args."
  (flet ((lk (k) (let ((c (assoc k merged :test #'string=))) (and c (cdr c)))))
    (let ((v (lk "datacarrier")))
      (when v (setf *accept-datacarrier* (conf-parse-bool v))))
    (let ((v (lk "datacarriersize")))
      (when v (setf *max-datacarrier-bytes* (conf-parse-int v))))
    (let ((v (lk "permitbaremultisig")))
      (when v (setf *permit-bare-multisig* (conf-parse-bool v))))
    ;; Cluster mempool limits: -limitclustercount (transactions, hard-capped
    ;; at 64) and -limitclustersize (kvB) bound every connected component of
    ;; unconfirmed transactions (Core mempool_args.cpp:35-37 + the cap check
    ;; at :110-112, init.cpp:658-659). Read by make-mempool, which is created
    ;; after this runs at startup.
    (let ((v (lk "limitclustercount")))
      (when v
        (let ((n (conf-parse-int v)))
          (unless (<= 1 n 64)
            (error "limitclustercount must be between 1 and 64"))
          (setf bitcoin-lisp.mempool:*cluster-count-limit* n))))
    (let ((v (lk "limitclustersize")))
      (when v
        (let ((kvb (conf-parse-int v)))
          (unless (plusp kvb)
            (error "limitclustersize must be a positive number of kvB"))
          (setf bitcoin-lisp.mempool:*cluster-size-limit* (* kvb 1000)))))
    (let ((v (lk "signetchallenge")))
      (when v (setf bitcoin-lisp.validation:*signet-challenge*
                    (bitcoin-lisp.crypto:hex-to-bytes v))))
    ;; -proxy: run ALL outbound P2P connections through a SOCKS5 proxy
    ;; (Bitcoin Core init.cpp:1698-1762 sets it for every network).
    ;; -noproxy / -proxy=0 clears it. -proxyrandomize (default on) enables
    ;; Tor stream-isolation credentials (init.cpp:1698, netbase.cpp:748-810).
    ;; -onion overrides the proxy for reaching onion services, defaulting to
    ;; -proxy (init.cpp:1764-1790); stored for P1+, nothing dials .onion yet.
    (let ((randomize (let ((v (lk "proxyrandomize")))
                       (if v (conf-parse-bool v) t))))
      (flet ((parse-proxy (value)
               (multiple-value-bind (host port) (conf-parse-proxy value)
                 (when host
                   (bitcoin-lisp.networking:make-proxy
                    :host host :port port
                    :randomize-credentials randomize)))))
        (let ((v (lk "proxy")))
          (when v
            (setf bitcoin-lisp.networking:*proxy* (parse-proxy v))))
        (let ((v (lk "onion")))
          ;; The torcontrol client only auto-configures the onion proxy from
          ;; Tor's GETINFO when -onion was never given at all (Core's raw
          ;; GetArg("-onion","") == "" test) — record the raw fact.
          (setf bitcoin-lisp.networking:*onion-proxy-explicit* (and v t))
          (cond (v (setf bitcoin-lisp.networking:*onion-proxy* (parse-proxy v)))
                ;; No -onion: onion reachability follows -proxy when one was
                ;; given (Core init.cpp:1764 "An empty string is used to not
                ;; override the onion proxy").
                ((lk "proxy")
                 (setf bitcoin-lisp.networking:*onion-proxy*
                       bitcoin-lisp.networking:*proxy*))))))
    ;; Network reachability. -onlynet (repeatable) replaces the reachable set
    ;; (Core init.cpp:1529-1536 g_reachable_nets.RemoveAll + Add per value);
    ;; it restricts AUTOMATIC outbound selection and gossip storage only —
    ;; manual addnode/connect are unaffected. Gated nets then drop out unless
    ;; their transport is configured, and naming a gated net explicitly in
    ;; -onlynet is an init error (Core init.cpp:1541-1546, 1760-1800,
    ;; 2240-2245): onion needs a Tor proxy, I2P needs -i2psam (which we do
    ;; not support at all yet), CJDNS needs -cjdnsreachable.
    (setf bitcoin-lisp.networking:*cjdns-reachable*
          (let ((v (lk "cjdnsreachable"))) (and v (conf-parse-bool v))))
    (let* ((onlynets (loop for (k . v) in merged
                           when (string= k "onlynet")
                             collect (conf-parse-network-name v)))
           (nets (or onlynets
                     (copy-list bitcoin-lisp.networking:+bip155-networks+)))
           ;; Effective -listenonion via the shared soft-set chain.
           (listenonion-p (nth-value 1 (conf-effective-listen-flags merged))))
      ;; Keep the user's raw restriction for later transport arrivals (the
      ;; torcontrol GETINFO-discovered onion proxy re-admits :torv3 iff
      ;; -onlynet allows it — Core get_socks_cb).
      (setf bitcoin-lisp.networking:*onlynet-networks* onlynets)
      (unless bitcoin-lisp.networking:*onion-proxy*
        (when (member :torv3 onlynets)
          ;; Core init.cpp:1769-1773 / 1788-1798: -onion=0 explicitly forbids
          ;; the Tor route; otherwise -listenonion may still deliver a proxy
          ;; later via the torcontrol connection.
          (cond ((lk "onion")
                 (error "-onlynet=onion given but the proxy for reaching the Tor network is explicitly forbidden: -onion=0"))
                ((not listenonion-p)
                 (error "-onlynet=onion given but no Tor route is configured: none of -proxy, -onion or -listenonion is given"))))
        (setf nets (remove :torv3 nets)))
      (when (member :i2p onlynets)
        (error "-onlynet=i2p given but I2P (SAM) is not supported"))
      (setf nets (remove :i2p nets))
      (unless bitcoin-lisp.networking:*cjdns-reachable*
        (when (member :cjdns onlynets)
          (error "-onlynet=cjdns given without -cjdnsreachable"))
        (setf nets (remove :cjdns nets)))
      (setf bitcoin-lisp.networking:*reachable-networks* nets))))

(defun args->start-node-plist (args &optional conf-text)
  "Pure assembly of a start-node keyword plist from Bitcoin Core-style CLI ARGS
 (a list of strings) and optional CONF-TEXT (the contents of a bitcoin.conf).
CLI arguments override the file. The network is resolved from the CLI first, so
the config file's [network] section can be scoped, then finalized from the
merge. Returns (VALUES plist merged-alist network); start-node-from-args
(node.lisp) wraps this with the file I/O, apply-config-globals, and launch."
  (let* ((cli (parse-cli-args args))
         (cli-network (resolve-network-from-config cli))
         (conf (when conf-text (parse-bitcoin-conf conf-text cli-network)))
         (merged (append cli conf))                 ; CLI first => wins on assoc
         (network (resolve-network-from-config merged)))
    (values (config-alist->start-node-plist merged network) merged network)))
