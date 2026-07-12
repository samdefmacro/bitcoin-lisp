(in-package #:bitcoin-lisp)

;;; Configuration
;;;
;;; Global configuration variables and constants that are referenced
;;; across multiple subsystems. Loaded early so that storage, validation,
;;; and networking modules can reference these symbols at compile time.

;;;; Block Pruning Configuration

(defconstant +min-blocks-to-keep+ 288
  "Minimum number of recent blocks to keep on disk (matches Bitcoin Core).")

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
  "Mempool policy: accept OP_RETURN data-carrier outputs as standard
(Bitcoin Core -datacarrier, default true). When NIL, any OP_RETURN output
is non-standard and the tx is rejected from the mempool.")

(defvar *max-datacarrier-bytes* 83
  "Mempool policy: maximum total size of a standard OP_RETURN scriptPubKey
in bytes (Bitcoin Core -datacarriersize is the DATA size, 80; this is the
whole script = OP_RETURN + pushdata prefix + 80 data = 83). Consensus is
unaffected; this only gates mempool standardness.")

(defvar *peer-block-filters* nil
  "When true (and the block filter index is enabled), serve BIP157 compact
filter messages (getcfilters/getcfheaders/getcfcheckpt) and advertise
NODE_COMPACT_FILTERS (Bitcoin Core -peerblockfilters, default false).")

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
  "Clear all entries from the rejects filter."
  (when filter
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
    ("v2transport"       :v2transport        :bool)
    ("reindexchainstate" :reindex-chainstate :bool)
    ("reindex-chainstate" :reindex-chainstate :bool)
    ("forcecompactdb"    :force-compact-db   :bool)
    ("peerblockfilters"  :peer-block-filters :bool)
    ("logfile"           :log-file           :string)
    ("loglevel"          :log-level          :loglevel)
    ("sync"              :sync               :bool))
  "Maps a Bitcoin Core-style option name to a start-node keyword and its value
type. Network selection (-chain/-testnet/...) and -server/-debug are handled
specially in config-alist->start-node-plist.")

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
          (setf (getf plist :listen) nil))))
    plist))

(defun apply-config-globals (merged)
  "Set the process-global policy/consensus config specials from the MERGED config
alist. These options have no start-node keyword because they configure global
specials directly: -datacarrier, -datacarriersize, -permitbaremultisig,
-signetchallenge (a custom signet block-challenge), and the SOCKS5 proxy
options -proxy/-onion/-proxyrandomize (networking's *proxy*/*onion-proxy*).
CLI-over-file precedence is already applied in MERGED. Called at startup by
start-node-from-args."
  (flet ((lk (k) (let ((c (assoc k merged :test #'string=))) (and c (cdr c)))))
    (let ((v (lk "datacarrier")))
      (when v (setf *accept-datacarrier* (conf-parse-bool v))))
    (let ((v (lk "datacarriersize")))
      (when v (setf *max-datacarrier-bytes* (conf-parse-int v))))
    (let ((v (lk "permitbaremultisig")))
      (when v (setf *permit-bare-multisig* (conf-parse-bool v))))
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
          (cond (v (setf bitcoin-lisp.networking:*onion-proxy* (parse-proxy v)))
                ;; No -onion: onion reachability follows -proxy when one was
                ;; given (Core init.cpp:1764 "An empty string is used to not
                ;; override the onion proxy").
                ((lk "proxy")
                 (setf bitcoin-lisp.networking:*onion-proxy*
                       bitcoin-lisp.networking:*proxy*))))))))

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
