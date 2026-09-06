(in-package #:bitcoin-lisp)

;;;; From the parsed options to START-NODE (Core init.cpp: AppInitParameterInteraction,
;;;; InitParameterInteraction, and the ArgsManager reads spread through AppInitMain)
;;;
;;; The bitcoin-lisp/config sub-system parses the command line, bitcoin.conf
;;; and settings.json into one merged alist and knows nothing about the node.
;;; This file is where that alist meets the node: which keyword each option
;;; feeds, which process-global special it sets, and the interactions between
;;; options (-blocksonly shrinks the mempool, -proxy implies -listen=0, ...).
;;; It names the mempool and the transport, so it loads here, after them,
;;; rather than in config.lisp.

(defun config-alist->start-node-plist (alist network)
  "Convert a merged config ALIST (CLI over file) into a plist of start-node
keyword arguments, coercing each value by its option-table type. NETWORK is the already-
resolved network. Honors -server (enable RPC on the default port when no
-rpcport is given) and -debug (=> loglevel debug unless -loglevel is set)."
  (let ((plist (list :network network)))
    (flet ((lookup (k) (assoc k alist :test #'string=)))
      (dolist (option (scalar-key-options))
        (let ((cell (lookup (config-option-name option))))
          (when cell
            (setf (getf plist (config-option-key option))
                  (parse-option-value option (cdr cell))))))
      ;; -port must be a real port number (Core init.cpp InitError
      ;; "Invalid port specified in -port").
      (let ((port (getf plist :port)))
        (when (and port (not (<= 1 port 65535)))
          (config-error "Invalid port specified in -port: '~A'" port)))
      ;; Repeatable options whose value is just the string: keep every
      ;; occurrence, CLI and config file, the way Core's GetArgs does (the
      ;; :COLLECT rows of the option table). Each is validated where it is
      ;; used, not here.
      (dolist (option (collected-key-options))
        (let ((values (loop for (k . v) in alist
                            when (string= k (config-option-name option))
                              collect v)))
          (when values (setf (getf plist (config-option-collect option)) values))))
      ;; -disablewallet turns the wallet OFF (Core init.cpp). Inverted into
      ;; :wallet, and only when -wallet was not given explicitly: an operator
      ;; who wrote both said something contradictory, and Core lets the
      ;; explicit -wallet win by loading it anyway.
      (let ((disable (getf plist :disable-wallet)))
        (remf plist :disable-wallet)
        (when (and disable (not (lookup "wallet")))
          (setf (getf plist :wallet) nil)))
      ;; A category-specific -loglevel names no global level, so the scalar
      ;; parse yields NIL. Drop the key rather than passing NIL through: an
      ;; explicit NIL overrides START-NODE's :INFO default, and it only happens
      ;; to behave because LOG-LEVEL-VALUE's fallback is also 1.
      (when (and (member :log-level plist) (null (getf plist :log-level)))
        (remf plist :log-level))
      ;; -wallet carries two things at once. The NAMES to load are Core's
      ;; meaning. The second is ours: wallet support is default-OFF on mainnet
      ;; (docs/wallet-plan.md), and naming a wallet — or a bare -wallet, which
      ;; INTERPRET-ARG renders as "1" — is the operator's opt-in.
      ;;
      ;; `-nowallet` arrives as "0" and means "load no wallets" (Core:
      ;; "'-nowallet' accepts only '1' to disable all wallets"). It names
      ;; nothing and it does NOT turn the subsystem off: the wallet RPCs stay
      ;; registered, which is what wallet_multiwallet.py's first node relies on.
      (let* ((raw (getf plist :wallet-names))
             (names (remove-if (lambda (v) (member v '("0" "1") :test #'string=)) raw)))
        (setf (getf plist :wallet-names) names)
        (when (or names (member "1" raw :test #'string=))
          (setf (getf plist :wallet) t)))
      ;; -walletbroadcast under -blocksonly: Core soft-sets it to 0
      ;; (wallet/init.cpp:95-97, "Parameter interaction: -blocksonly=1 ->
      ;; setting -walletbroadcast=0"), because an operator who told the node to
      ;; carry no transactions on the wire did not mean "except my own". Soft:
      ;; the scalar scan above already took an explicit -walletbroadcast into
      ;; the plist, and this only fills the absent case. Here rather than in
      ;; APPLY-PARAMETER-INTERACTIONS because -walletbroadcast feeds a start-node
      ;; KEYWORD (so that every run starts from Core's default), and this is
      ;; where the other keyword soft-sets are decided.
      (let ((b (lookup "blocksonly")))
        (when (and b (conf-parse-bool (cdr b)) (not (lookup "walletbroadcast")))
          (setf (getf plist :wallet-broadcast) nil)
          (defer-log :info "Parameter interaction: -blocksonly=1 -> setting -walletbroadcast=0")))
      ;; -bind=<addr>[:<port>][=onion] (Core init.cpp; the functional framework
      ;; passes both forms, test_node.py:272-276). The scalar scan above already
      ;; took the last plain value into :listen-bind; re-derive it here so the
      ;; address is separated from its port, and so an =onion entry — which
      ;; names a Tor-only listener, not an address to bind — is not mistaken
      ;; for one.
      (let* ((specs (loop for (k . v) in alist when (string= k "bind") collect v))
             (parsed (loop for spec in specs
                           collect (multiple-value-list (parse-bind-option spec))))
             (plain (remove-if (lambda (p) (or (null (first p)) (third p))) parsed)))
        (when (and specs (null plain))
          ;; Every -bind was =onion or unparseable: do NOT leave the spec
          ;; scan's raw string (which still carries ":port=onion") in the
          ;; plist as a bind address.
          (remf plist :listen-bind))
        (when plain
          (destructuring-bind (host port onion-p) (first plain)
            (declare (ignore onion-p))
            (setf (getf plist :listen-bind) host)
            ;; A port on -bind overrides -port for the listener, as it does in
            ;; Core, where the bind address carries its own port.
            (when port (setf (getf plist :port) port)))))
      ;; -listen is decided in exactly one place: CONF-EFFECTIVE-LISTEN-FLAGS,
      ;; which replays Core's soft-set chain in Core's order (-bind beats
      ;; -connect beats -proxy). Deciding it here as well is how the -bind case
      ;; got lost the first time.
      ;;
      ;; (-connect's -dnsseed=0 half is applied in APPLY-CONFIG-GLOBALS, which
      ;; owns *dns-seed-enabled*.)
      ;; -debug also raises the log level, because a category's lines are
      ;; emitted at debug level: enabling a category without raising the level
      ;; turns on a switch that changes nothing. An explicit -loglevel wins.
      ;;
      ;; -debug=0/none does NOT raise it — that spelling turns everything off.
      ;; The old read was CONF-PARSE-BOOL of the value, and atoi("net") is 0, so
      ;; -debug=net used to do nothing at all.
      (let ((debug (getf plist :debug-categories)))
        (when (and debug
                   (notevery (lambda (d) (member d '("0" "none") :test #'string=))
                             debug)
                   (not (lookup "loglevel")))
          (setf (getf plist :log-level) :debug)))
      ;; -server enables RPC; give it the network default port if none was set.
      (let ((server (lookup "server")))
        (when (and server (conf-parse-bool (cdr server))
                   (not (getf plist :rpc-port)))
          (setf (getf plist :rpc-port) (network-rpc-port network))))
      ;; The listen chain, applied once, for both flags.
      (multiple-value-bind (listen-p listen-onion-p)
          (conf-effective-listen-flags alist)
        (setf (getf plist :listen) listen-p)
        (unless listen-onion-p
          (setf (getf plist :listen-onion) nil)))
      ;; -maxconnections: Core refuses a negative value outright
      ;; (init.cpp:1032-1036), AFTER the listen chain above has read it -- a
      ;; -maxconnections<=0 still soft-sets -listen=0 and -dnsseed=0, which is
      ;; how 0 stays a meaningful "no peer connections" setting. Below zero it
      ;; is a typo or a mangled shell argument, and clamping it to 0 (which
      ;; AUTOMATIC-INBOUND-CAPACITY does) starts a node with no inbound
      ;; capacity, no listener and no DNS seeding, with nothing in the log
      ;; naming the cause. Not the option table's :MIN, which carries the other
      ;; Core wording ("Invalid value for -x=y (must be a non-negative
      ;; integer)"); this option has an error message of its own.
      (let ((n (getf plist :max-connections)))
        (when (and n (minusp n))
          (config-error "-maxconnections must be greater or equal than zero"))))
    plist))

(defun apply-config-globals (merged)
  "Set the process-global policy/consensus config specials from the MERGED
config alist: first every option that stands alone (the :GLOBAL / :APPLY
rows of src/config-options.lisp -- policy, consensus overrides, networking
and mempool limits, in table order), then the options whose effect depends
on another option, in Core's order (APPLY-PARAMETER-INTERACTIONS).
CLI-over-file precedence is already applied in MERGED. Called at startup by
start-node-from-args."
  (apply-option-globals merged)
  (apply-parameter-interactions merged))

(defun apply-parameter-interactions (merged)
  "The options whose value depends on ANOTHER option (Core init.cpp Step 2
\"parameter interactions\" and the proxy / reachability block of Step 6),
applied after APPLY-OPTION-GLOBALS so each present-case row has already
run and only the soft-set and consistency halves remain, in this order:
the signet chain instantiated from -signetchallenge / -signetseednode,
the ZMQ publisher list, -maxmempool under -blocksonly, -dnsseed under
-connect / -maxconnections, -proxy / -onion / -proxyrandomize,
-cjdnsreachable, -onlynet with its clearnet privacy check, and last
-forcednsseed against the -dnsseed every one of those may have turned off."
  (flet ((lk (k) (let ((c (assoc k merged :test #'string=))) (and c (cdr c)))))
    ;; -signetchallenge / -signetseednode INSTANTIATE the signet chain (Core
    ;; ReadSigNetArgs -> SigNetParams(SigNetOptions), chainparams.cpp:26-40).
    ;; First, because everything below it reads a chain: the derived message
    ;; start, the seed list and the zeroed chain-work floor have to be in place
    ;; before init-node copies them into *network-magic* and *dns-seeds*.
    ;; Always assigned, NIL included, so a second start in the same image does
    ;; not inherit the first one's signet.
    (let ((challenge (and (lk "signetchallenge") bl.val:*signet-challenge*))
          (seeds (loop for (k . v) in merged
                       when (string= k "signetseednode") collect v)))
      (setf (bl.chain:chain-params-override :signet)
            (when (or challenge seeds)
              (signet-chain-params :challenge challenge :seeds seeds)))
      (when challenge
        ;; Core LogInfo("Signet with challenge %s", HexStr(bin)),
        ;; kernel/chainparams.cpp:467. Deferred: debug.log does not exist yet.
        (defer-log :info "Signet with challenge ~A"
                   (bl.crypto:bytes-to-hex challenge))))
    ;; -zmqpub<topic>=<address> [+ -zmqpub<topic>hwm]: recorded now, bound by
    ;; start-node. Nothing is loaded or opened here, so a node with no ZMQ
    ;; options never touches libzmq at all.
    (setf *zmq-publisher-specs* (zmq-specs-from-config merged))
    ;; -maxmempool under -blocksonly: Core soft-sets it to
    ;; DEFAULT_BLOCKSONLY_MAX_MEMPOOL_SIZE_MB = 5 (init.cpp:826) -- "soft",
    ;; so an explicit -maxmempool (applied by its row above) still wins.
    (unless (lk "maxmempool")
      (let ((b (lk "blocksonly")))
        (when (and b (conf-parse-bool b))
          (setf bl.mp:*max-mempool-bytes* (* 5 1000 1000)))))
    ;; -dnsseed under -connect / -maxconnections<=0: with only trusted nodes
    ;; to dial (or connections disabled outright) there is nothing for a DNS
    ;; seed to feed. Soft -- an explicit -dnsseed=1 was applied by its row
    ;; and still wins.
    (unless (lk "dnsseed")
      (when (or (lk "connect")
                (let ((m (lk "maxconnections")))
                  (and m (<= (conf-parse-int m) 0))))
        (setf *dns-seed-enabled* nil)))
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
                   (bl.net:make-proxy
                    :host host :port port
                    :randomize-credentials randomize)))))
        (let ((v (lk "proxy")))
          (when v
            (setf bl.net:*proxy* (parse-proxy v))))
        (let ((v (lk "onion")))
          ;; The torcontrol client only auto-configures the onion proxy from
          ;; Tor's GETINFO when -onion was never given at all (Core's raw
          ;; GetArg("-onion","") == "" test) — record the raw fact.
          (setf bl.net:*onion-proxy-explicit* (and v t))
          (cond (v (setf bl.net:*onion-proxy* (parse-proxy v)))
                ;; No -onion: onion reachability follows -proxy when one was
                ;; given (Core init.cpp:1764 "An empty string is used to not
                ;; override the onion proxy").
                ((lk "proxy")
                 (setf bl.net:*onion-proxy*
                       bl.net:*proxy*))))))
    ;; Network reachability. -onlynet (repeatable) replaces the reachable set
    ;; (Core init.cpp:1529-1536 g_reachable_nets.RemoveAll + Add per value);
    ;; it restricts AUTOMATIC outbound selection and gossip storage only —
    ;; manual addnode/connect are unaffected. Gated nets then drop out unless
    ;; their transport is configured, and naming a gated net explicitly in
    ;; -onlynet is an init error (Core init.cpp:1541-1546, 1760-1800,
    ;; 2240-2245): onion needs a Tor proxy, I2P needs -i2psam (which we do
    ;; not support at all yet), CJDNS needs -cjdnsreachable.
    (setf bl.net:*cjdns-reachable*
          (let ((v (lk "cjdnsreachable"))) (and v (conf-parse-bool v))))
    (let* ((onlynets (loop for (k . v) in merged
                           when (string= k "onlynet")
                             collect (conf-parse-network-name v)))
           (nets (or onlynets
                     (copy-list bl.net:+bip155-networks+)))
           ;; Effective -listenonion via the shared soft-set chain.
           (listenonion-p (nth-value 1 (conf-effective-listen-flags merged))))
      ;; Keep the user's raw restriction for later transport arrivals (the
      ;; torcontrol GETINFO-discovered onion proxy re-admits :torv3 iff
      ;; -onlynet allows it — Core get_socks_cb).
      (setf bl.net:*onlynet-networks* onlynets)
      (unless bl.net:*onion-proxy*
        (when (member :torv3 onlynets)
          ;; Core init.cpp:1769-1773 / 1788-1798: -onion=0 explicitly forbids
          ;; the Tor route; otherwise -listenonion may still deliver a proxy
          ;; later via the torcontrol connection.
          (cond ((lk "onion")
                 (config-error "-onlynet=onion given but the proxy for reaching the Tor network is explicitly forbidden: -onion=0"))
                ((not listenonion-p)
                 (config-error "-onlynet=onion given but no Tor route is configured: none of -proxy, -onion or -listenonion is given"))))
        (setf nets (remove :torv3 nets)))
      (when (member :i2p onlynets)
        (config-error "-onlynet=i2p given but I2P (SAM) is not supported"))
      (setf nets (remove :i2p nets))
      (unless bl.net:*cjdns-reachable*
        (when (member :cjdns onlynets)
          (config-error "-onlynet=cjdns given without -cjdnsreachable"))
        (setf nets (remove :cjdns nets)))
      (setf bl.net:*reachable-networks* nets)
      ;; PRIVACY: requesting DNS seeds entails clearnet. Resolving a seed
      ;; hostname is a plaintext DNS query to the local resolver, and the
      ;; addresses it returns are dialed directly over IPv4/IPv6 — so a
      ;; Tor-only node (-onlynet=onion with -listenonion and no -proxy) would
      ;; deanonymize itself on its very first start, defeating the point of
      ;; -onlynet. Core soft-sets -dnsseed=0 when -onlynet excludes IPv4 and
      ;; IPv6 (init.cpp:835-844) and aborts when -dnsseed=1 was given
      ;; explicitly (init.cpp:1691-1693). Soft-set semantics matter: an
      ;; explicit -dnsseed=0 must stay 0, and an explicit 1 is an error rather
      ;; than a silent override.
      (unless (or (member :ipv4 nets) (member :ipv6 nets))
        (cond ((not (lk "dnsseed"))
               (setf *dns-seed-enabled* nil))
              (*dns-seed-enabled*
               (config-error "Incompatible options: -dnsseed=1 was explicitly specified, but -onlynet forbids connections to IPv4/IPv6")))))
    ;; -forcednsseed with seeding off is a contradiction Core refuses to start
    ;; on (init.cpp:1010-1013), and it reads the EFFECTIVE -dnsseed, so it also
    ;; fires for the soft-set forms: -connect, -maxconnections<=0
    ;; (init.cpp:777-784) and a clearnet-free -onlynet (:833-842). Hence its
    ;; place here, after every one of those has run -- Core's own check sits
    ;; after all of InitParameterInteraction for the same reason. Without it
    ;; -forcednsseed silently does nothing (its one consumer requires
    ;; *DNS-SEED-ENABLED* too) and the operator believes seeding is forced.
    (when (and *force-dns-seed* (not *dns-seed-enabled*))
      (config-error "Cannot set -forcednsseed to true when setting -dnsseed to false."))))

(defun config-sources (args texts settings-rows network)
  "The four settings sources, as MERGED-CONFIG-ALIST wants them: (kind . rows)
in Core's precedence order — command line, read-write settings file, config
file [network] section, config file default section (settings.cpp:34-36).

Sections from EVERY config file form ONE span, and so do the default areas,
because Core accumulates all the files into a single ro_config[section][name]
map: the file boundary is not part of the precedence, only the section is."
  (let ((rows (loop for text in texts append (conf-settings-rows text)))
        (want (conf-section-name network)))
    (flet ((of-section (name)
             ;; Drop the section field: from here on a row is (name value json).
             (loop for (section . row) in rows
                   when (string= section name) collect row)))
      (list (cons :command-line (cli-settings-rows args))
            (cons :settings settings-rows)
            (cons :network-section (of-section want))
            (cons :default-section (of-section ""))))))

(defun check-unsuitable-section-only-options (sources network)
  "Refuse to start when a network-only option is set ONLY in bitcoin.conf's
default section and we are not on mainnet — Core init.cpp:944-951, one line
per option, verbatim. The alternative is what we used to do: apply a shared
config file's `rpcport=8332`, `port=8333` or `connect=<mainnet peer>` to a
testnet node, which binds the mainnet RPC port or isolates the node on the
wrong chain's peers. That accident is the whole reason the NETWORK_ONLY flag
and this error exist."
  (let ((unsuitable (unsuitable-section-only-options sources network)))
    (when unsuitable
      (let ((chain (conf-section-name network)))
        (config-error
         "~{~A~^~%~}"
         (loop for name in unsuitable
               collect (format nil "Config setting for -~A only applied on ~A ~
                                    network when in [~A] section."
                               name chain chain)))))))

(defun args->start-node-plist (args &optional conf-text settings-rows)
  ;; CONF-TEXT is the main bitcoin.conf, or a LIST of texts when -includeconf
  ;; pulled in more (main file first). See the docstring below.
  "Pure assembly of a start-node keyword plist from Bitcoin Core-style CLI ARGS
 (a list of strings) and CONF-TEXT — one bitcoin.conf's contents, or a LIST of
them (main file first) when -includeconf pulled in more.

SETTINGS-ROWS are the read-write settings file's rows (SETTINGS-CONFIG-ROWS).
Precedence is Core's (settings.cpp:36): command line, then the settings file,
then the [network] section of any config file, then its default section —
MERGED-CONFIG-ALIST resolves every option name across the four.

SETTINGS-ROWS deliberately does NOT take part in resolving the network: Core
reads its chain selectors from the command line and the config file's global
area only, and the settings file lives INSIDE the network directory — letting it
choose the network would make its own location depend on its contents.
Returns (VALUES plist merged-alist network); start-node-from-args (node/init.lisp)
wraps this with the file I/O, apply-config-globals, and launch."
  (let* ((texts (cond ((null conf-text) nil)
                      ((listp conf-text) conf-text)
                      (t (list conf-text))))
         ;; The network is resolved from the CLI plus the config file's GLOBAL
         ;; area — never from inside a section, which is Core's rule (it reads
         ;; the chain selectors with section="", args.cpp:825-829). Resolving it
         ;; from the CLI alone, as this used to, meant a `testnet4=1` written in
         ;; bitcoin.conf left us scoping the file to the DEFAULT network's
         ;; section and silently dropping the whole [testnet4] block.
         (network (resolve-network-from-config
                   (append (parse-cli-args args)
                           (loop for text in texts append (conf-global-entries text)))))
         (sources (config-sources args texts settings-rows network)))
    (check-unsuitable-section-only-options sources network)
    (multiple-value-bind (merged negated) (merged-config-alist sources network)
      ;; `-noconnect` is `-connect=0` at every drive site Core has: with an
      ;; empty list and IsArgNegated true, init.cpp:2215-2224 clears
      ;; m_use_addrman_outgoing and leaves m_specified_outgoing empty, which is
      ;; exactly what the single value "0" produces, and init.cpp:777 tests the
      ;; two the same way. doc/bitcoin-conf.md:66 names -connect as the list
      ;; whose negation has a side effect beyond clearing it. Rendering it as
      ;; that one value keeps the three readers of -connect here — the plist,
      ;; the -dnsseed soft-set and the -listen soft-set — reading one thing;
      ;; the negation always empties the list, so there is nothing to shadow.
      (when (member "connect" negated :test #'string=)
        (push (cons "connect" "0") merged))
      (values (config-alist->start-node-plist merged network) merged network))))
