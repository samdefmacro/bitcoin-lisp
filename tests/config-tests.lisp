(in-package #:bitcoin-lisp.tests)

(def-suite :config-tests
  :description "bitcoin.conf and CLI (-key=value) argument parsing"
  :in :bitcoin-lisp-tests)

(in-suite :config-tests)

(defun cfg (key alist) (cdr (assoc key alist :test #'string=)))

;;; --- value coercion ---------------------------------------------------------

(test conf-parse-bool-values
  "Boolean config values follow Core's lenient -flag semantics."
  (is-true  (bitcoin-lisp::conf-parse-bool "1"))
  (is-true  (bitcoin-lisp::conf-parse-bool "true"))
  (is-true  (bitcoin-lisp::conf-parse-bool "YES"))
  (is-true  (bitcoin-lisp::conf-parse-bool ""))       ; bare -flag
  (is-false (bitcoin-lisp::conf-parse-bool "0"))
  (is-false (bitcoin-lisp::conf-parse-bool "false"))
  (is-false (bitcoin-lisp::conf-parse-bool "no"))
  (is-false (bitcoin-lisp::conf-parse-bool "off")))

(test conf-parse-int-and-loglevel
  (is (= 2000 (bitcoin-lisp::conf-parse-int "2000")))
  (is (= 550 (bitcoin-lisp::conf-parse-int " 550 ")))
  (signals error (bitcoin-lisp::conf-parse-int "notanint"))
  (is (eq :debug (bitcoin-lisp::conf-parse-loglevel "debug")))
  (is (eq :info (bitcoin-lisp::conf-parse-loglevel "INFO")))
  (is (eq :warn (bitcoin-lisp::conf-parse-loglevel "warning")))
  (is (eq :error (bitcoin-lisp::conf-parse-loglevel "error")))
  (signals error (bitcoin-lisp::conf-parse-loglevel "verbose")))

;;; --- CLI parsing ------------------------------------------------------------

(test parse-cli-args-forms
  "CLI accepts -key=value, --key=value, bare -key (=1), and -nokey (=0)."
  (let ((a (bitcoin-lisp::parse-cli-args
            '("-txindex" "-dbcache=2000" "--rpcuser=bob" "-nolisten"
              "-chain=main" "notaflag" "-"))))
    (is (string= "1" (cfg "txindex" a)))
    (is (string= "2000" (cfg "dbcache" a)))
    (is (string= "bob" (cfg "rpcuser" a)))
    (is (string= "0" (cfg "listen" a)))           ; -nolisten
    (is (string= "main" (cfg "chain" a)))
    (is (null (assoc "notaflag" a :test #'string=)))))    ; non-flag ignored

(test parse-cli-args-value-with-equals
  "A value containing '=' is preserved after the first '='."
  (let ((a (bitcoin-lisp::parse-cli-args '("-rpcpassword=a=b=c"))))
    (is (string= "a=b=c" (cfg "rpcpassword" a)))))

;;; --- bitcoin.conf parsing ---------------------------------------------------

(test parse-bitcoin-conf-basic
  "Comments and blank lines are skipped; key=value pairs are trimmed."
  (let ((a (bitcoin-lisp::parse-bitcoin-conf
            (format nil "# a comment~%~%txindex=1~%  dbcache = 500  ~%"))))
    (is (string= "1" (cfg "txindex" a)))
    (is (string= "500" (cfg "dbcache" a)))))

(test parse-bitcoin-conf-network-sections
  "Section headers scope keys: only global + the matching network's section."
  (let ((text (format nil "txindex=1~%[main]~%rpcport=8888~%[test]~%rpcport=7777~%")))
    ;; Scoped to mainnet: global txindex + [main] rpcport, not [test].
    (let ((a (bitcoin-lisp::parse-bitcoin-conf text :mainnet)))
      (is (string= "1" (cfg "txindex" a)))
      (is (string= "8888" (cfg "rpcport" a))))
    ;; Scoped to testnet3 ([test]): the [test] section's rpcport.
    (let ((a (bitcoin-lisp::parse-bitcoin-conf text :testnet3)))
      (is (string= "7777" (cfg "rpcport" a))))
    ;; No network: sections ignored, both rpcports present (first wins on assoc).
    (let ((a (bitcoin-lisp::parse-bitcoin-conf text nil)))
      (is (string= "8888" (cfg "rpcport" a))))))

;;; --- network resolution -----------------------------------------------------

(test resolve-network-precedence
  (is (eq :testnet3 (bitcoin-lisp::resolve-network-from-config '())))          ; default
  (is (eq :mainnet (bitcoin-lisp::resolve-network-from-config '(("chain" . "main")))))
  (is (eq :testnet4 (bitcoin-lisp::resolve-network-from-config '(("testnet4" . "1")))))
  (is (eq :signet (bitcoin-lisp::resolve-network-from-config '(("signet" . "1")))))
  ;; -regtest flag outranks -chain (Core precedence).
  (is (eq :regtest (bitcoin-lisp::resolve-network-from-config
                    '(("chain" . "main") ("regtest" . "1")))))
  (signals error (bitcoin-lisp::resolve-network-from-config '(("chain" . "bogus")))))

;;; --- full plist assembly ----------------------------------------------------

(test config-alist-to-start-node-plist
  "A merged alist becomes typed start-node keyword arguments."
  (let ((plist (bitcoin-lisp::config-alist->start-node-plist
                '(("txindex" . "1") ("dbcache" . "2000") ("rpcuser" . "bob")
                  ("maxconnections" . "16") ("v2transport" . "0"))
                :mainnet)))
    (is (eq :mainnet (getf plist :network)))
    (is (eq t (getf plist :txindex)))
    (is (= 2000 (getf plist :dbcache-mib)))
    (is (string= "bob" (getf plist :rpc-user)))
    (is (= 16 (getf plist :max-peers)))
    (is (eq nil (getf plist :v2transport)))))

(test config-forcecompactdb-flag
  "-forcecompactdb (a hidden Core option) maps to the :force-compact-db start-node
keyword; absent from the plist when not given."
  (let ((on (bitcoin-lisp::config-alist->start-node-plist
             '(("forcecompactdb" . "1")) :mainnet))
        (off (bitcoin-lisp::config-alist->start-node-plist
              '(("txindex" . "1")) :mainnet)))
    (is (eq t (getf on :force-compact-db)))
    (is (null (getf off :force-compact-db)))))

(test config-plist-server-and-debug-shortcuts
  "-server enables RPC on the network default port; -debug => loglevel debug."
  (let ((plist (bitcoin-lisp::config-alist->start-node-plist
                '(("server" . "1") ("debug" . "1")) :testnet3)))
    (is (= 18332 (getf plist :rpc-port)))        ; testnet3 default RPC port
    (is (eq :debug (getf plist :log-level))))
  ;; Explicit -rpcport wins over -server's default.
  (let ((plist (bitcoin-lisp::config-alist->start-node-plist
                '(("server" . "1") ("rpcport" . "9999")) :mainnet)))
    (is (= 9999 (getf plist :rpc-port))))
  ;; Explicit -loglevel wins over -debug.
  (let ((plist (bitcoin-lisp::config-alist->start-node-plist
                '(("debug" . "1") ("loglevel" . "warn")) :mainnet)))
    (is (eq :warn (getf plist :log-level)))))

(test cli-overrides-config-file
  "In the merged alist (CLI appended before file), assoc returns the CLI value."
  (let* ((cli (bitcoin-lisp::parse-cli-args '("-txindex=1")))
         (conf (bitcoin-lisp::parse-bitcoin-conf (format nil "txindex=0~%dbcache=300~%")))
         (merged (append cli conf)))
    (is (eq t (bitcoin-lisp::conf-parse-bool (cfg "txindex" merged))))   ; CLI 1 wins
    (is (string= "300" (cfg "dbcache" merged)))))                        ; file-only key

(test args-to-start-node-plist-end-to-end
  "The full pure path: CLI + conf text -> typed start-node plist, CLI winning,
network resolved from the CLI and scoping the conf's [network] section."
  ;; CLI selects mainnet and overrides dbcache; conf provides txindex and a
  ;; [main]-scoped rpcport (a [test] rpcport must be ignored).
  (let* ((conf-text (format nil "txindex=1~%dbcache=300~%[main]~%rpcport=8888~%[test]~%rpcport=7777~%"))
         (plist (bitcoin-lisp::args->start-node-plist
                 '("-chain=main" "-dbcache=1000") conf-text)))
    (is (eq :mainnet (getf plist :network)))
    (is (eq t (getf plist :txindex)))               ; from conf
    (is (= 1000 (getf plist :dbcache-mib)))          ; CLI overrides conf's 300
    (is (= 8888 (getf plist :rpc-port))))            ; [main] section, not [test]
  ;; With no conf text, only CLI applies.
  (let ((plist (bitcoin-lisp::args->start-node-plist '("-regtest" "-txindex") nil)))
    (is (eq :regtest (getf plist :network)))
    (is (eq t (getf plist :txindex)))))

(test config-blocksonly-option
  "-blocksonly wires through to start-node's :blocksonly keyword (Core
DEFAULT_BLOCKSONLY = false: absent unless given; -noblocksonly negates)."
  (let ((plist (bitcoin-lisp::args->start-node-plist '("-regtest" "-blocksonly") nil)))
    (is (eq t (getf plist :blocksonly))))
  (let ((plist (bitcoin-lisp::args->start-node-plist '("-regtest" "-blocksonly=0") nil)))
    (is (null (getf plist :blocksonly)))
    (is-true (member :blocksonly plist)))          ; explicitly given as off
  (let ((plist (bitcoin-lisp::args->start-node-plist '("-regtest") nil)))
    (is (null (member :blocksonly plist)))))       ; default: not passed at all

(test config-apply-globals
  "apply-config-globals sets the process-global policy/consensus specials from a
merged config alist (options with no start-node keyword)."
  (let ((bitcoin-lisp::*accept-datacarrier* t)
        (bitcoin-lisp::*max-datacarrier-bytes* 83)
        (bitcoin-lisp::*permit-bare-multisig* nil)
        (bitcoin-lisp.validation:*signet-challenge*
          bitcoin-lisp.validation:*default-signet-challenge*))
    (bitcoin-lisp::apply-config-globals
     '(("datacarrier" . "0") ("datacarriersize" . "100000")
       ("permitbaremultisig" . "1") ("signetchallenge" . "5121ff")))
    (is (eq nil bitcoin-lisp::*accept-datacarrier*))
    (is (= 100000 bitcoin-lisp::*max-datacarrier-bytes*))
    (is (eq t bitcoin-lisp::*permit-bare-multisig*))
    (is (equalp (bitcoin-lisp.crypto:hex-to-bytes "5121ff")
                bitcoin-lisp.validation:*signet-challenge*))))

(test config-cluster-limit-knobs
  "-limitclustercount/-limitclustersize set the cluster-limit specials that
make-mempool reads when creating its txgraph (cluster mempool P6); the
count is hard-capped at 64 like Core (mempool_args.cpp:110-112)."
  (let ((bitcoin-lisp.mempool:*cluster-count-limit*
          bitcoin-lisp.mempool:*cluster-count-limit*)
        (bitcoin-lisp.mempool:*cluster-size-limit*
          bitcoin-lisp.mempool:*cluster-size-limit*))
    (bitcoin-lisp::apply-config-globals
     '(("limitclustercount" . "32") ("limitclustersize" . "50")))
    (is (= 32 bitcoin-lisp.mempool:*cluster-count-limit*))
    (is (= 50000 bitcoin-lisp.mempool:*cluster-size-limit*))    ; kvB -> vB
    ;; A mempool created under these settings carries them in its graph.
    (let ((graph (bitcoin-lisp.mempool:mempool-graph
                  (bitcoin-lisp.mempool:make-mempool))))
      (is (= 32 (bitcoin-lisp.mempool::txgraph-max-cluster-count graph)))
      (is (= 50000 (bitcoin-lisp.mempool::txgraph-max-cluster-size graph))))
    ;; Out-of-range values are init errors.
    (signals error (bitcoin-lisp::apply-config-globals
                    '(("limitclustercount" . "65"))))
    (signals error (bitcoin-lisp::apply-config-globals
                    '(("limitclustercount" . "0"))))
    (signals error (bitcoin-lisp::apply-config-globals
                    '(("limitclustersize" . "0"))))))

(test config-args-returns-merged-alist
  "args->start-node-plist returns the merged config alist as a second value, so
start-node-from-args can apply the global-only options."
  (multiple-value-bind (plist merged)
      (bitcoin-lisp::args->start-node-plist '("-datacarrier=0" "-signetchallenge=5121ff"))
    (declare (ignore plist))
    (is (equal "0" (cdr (assoc "datacarrier" merged :test #'string=))))
    (is (equal "5121ff" (cdr (assoc "signetchallenge" merged :test #'string=))))))

;;; --- -onlynet / -cjdnsreachable (network reachability) ----------------------

(test config-onlynet-reachability
  "-onlynet (repeatable) replaces the reachable-network set; gated nets
(onion without a proxy, i2p always, cjdns without -cjdnsreachable) drop out
of the default set; -cjdnsreachable admits cjdns."
  (let ((bitcoin-lisp.networking:*reachable-networks*
          bitcoin-lisp.networking:*reachable-networks*)
        (bitcoin-lisp.networking:*cjdns-reachable*
          bitcoin-lisp.networking:*cjdns-reachable*)
        (bitcoin-lisp.networking:*proxy* nil)
        (bitcoin-lisp.networking:*onion-proxy* nil))
    ;; Default: no -onlynet, no proxy, no flags => IP only.
    (bitcoin-lisp::apply-config-globals '())
    (is (equal '(:ipv4 :ipv6) bitcoin-lisp.networking:*reachable-networks*))
    (is (null bitcoin-lisp.networking:*cjdns-reachable*))
    ;; -proxy makes onion reachable (Core: onion proxy follows -proxy).
    (bitcoin-lisp::apply-config-globals '(("proxy" . "127.0.0.1:9050")))
    (is-true (bitcoin-lisp.networking:reachable-network-p :torv3))
    (is-false (bitcoin-lisp.networking:reachable-network-p :i2p))
    (setf bitcoin-lisp.networking:*proxy* nil
          bitcoin-lisp.networking:*onion-proxy* nil)
    ;; Repeatable -onlynet restricts the set.
    (bitcoin-lisp::apply-config-globals
     (bitcoin-lisp::parse-cli-args '("-onlynet=ipv4" "-onlynet=ipv6")))
    (is (equal '(:ipv4 :ipv6) bitcoin-lisp.networking:*reachable-networks*))
    (bitcoin-lisp::apply-config-globals
     (bitcoin-lisp::parse-cli-args '("-onlynet=ipv4")))
    (is (equal '(:ipv4) bitcoin-lisp.networking:*reachable-networks*))
    (is-false (bitcoin-lisp.networking:reachable-network-p :ipv6))
    ;; -cjdnsreachable admits cjdns to the default set.
    (bitcoin-lisp::apply-config-globals '(("cjdnsreachable" . "1")))
    (is-true bitcoin-lisp.networking:*cjdns-reachable*)
    (is-true (bitcoin-lisp.networking:reachable-network-p :cjdns))
    ;; -onlynet=onion with a proxy works; onion-only set results.
    (bitcoin-lisp::apply-config-globals
     (append (bitcoin-lisp::parse-cli-args '("-onlynet=onion"))
             '(("proxy" . "127.0.0.1:9050"))))
    (is (equal '(:torv3) bitcoin-lisp.networking:*reachable-networks*))
    (setf bitcoin-lisp.networking:*proxy* nil
          bitcoin-lisp.networking:*onion-proxy* nil)))

(test config-onlynet-errors
  "Init errors, per Core: unknown -onlynet name; -onlynet=onion without ANY
Tor route (none of -proxy/-onion/-listenonion — Core init.cpp:1788-1798; a
default -listenonion is a valid route since the torcontrol client can fetch
the onion proxy from Tor itself); -onlynet=i2p (unsupported); -onlynet=cjdns
without -cjdnsreachable."
  (let ((bitcoin-lisp.networking:*reachable-networks*
          bitcoin-lisp.networking:*reachable-networks*)
        (bitcoin-lisp.networking:*cjdns-reachable*
          bitcoin-lisp.networking:*cjdns-reachable*)
        (bitcoin-lisp.networking:*onlynet-networks*
          bitcoin-lisp.networking:*onlynet-networks*)
        (bitcoin-lisp.networking:*onion-proxy-explicit* nil)
        (bitcoin-lisp.networking:*proxy* nil)
        (bitcoin-lisp.networking:*onion-proxy* nil))
    (signals error (bitcoin-lisp::apply-config-globals '(("onlynet" . "tor"))))
    (signals error (bitcoin-lisp::apply-config-globals
                    '(("onlynet" . "onion") ("listenonion" . "0"))))
    ;; With the default -listenonion, -onlynet=onion alone is legal: the
    ;; onion proxy arrives later over the torcontrol connection.
    (finishes (bitcoin-lisp::apply-config-globals '(("onlynet" . "onion"))))
    (signals error (bitcoin-lisp::apply-config-globals '(("onlynet" . "i2p"))))
    (signals error (bitcoin-lisp::apply-config-globals '(("onlynet" . "cjdns"))))))

;;; --- G7-03: -onlynet clearnet exclusion must disable DNS seeding ------------
;;;
;;; A Tor-only node (-onlynet=onion) that still queries DNS seeds resolves a
;;; seed hostname in plaintext through the local resolver and then dials the
;;; returned peers over clearnet — deanonymizing itself on first start, which
;;; is precisely what -onlynet exists to prevent.

(defmacro %with-net-config-globals (&body body)
  "Run BODY with every global APPLY-CONFIG-GLOBALS mutates rebound, so these
tests cannot leak reachability or seed state into each other."
  `(let ((bitcoin-lisp.networking:*reachable-networks*
           bitcoin-lisp.networking:*reachable-networks*)
         (bitcoin-lisp.networking:*cjdns-reachable* nil)
         (bitcoin-lisp.networking:*onlynet-networks* nil)
         (bitcoin-lisp.networking:*onion-proxy-explicit* nil)
         (bitcoin-lisp.networking:*proxy* nil)
         (bitcoin-lisp.networking:*onion-proxy* nil)
         (bitcoin-lisp::*dns-seed-enabled* t)
         (bitcoin-lisp::*fixed-seeds-enabled* t))
     ,@body))

(defun %dnsseed-after (&rest cli)
  "Value of *dns-seed-enabled* after applying CLI, from a clean t default."
  (%with-net-config-globals
    (bitcoin-lisp::apply-config-globals (bitcoin-lisp::parse-cli-args cli))
    bitcoin-lisp::*dns-seed-enabled*))

(test config-onlynet-clearnet-exclusion-disables-dnsseed
  "G7-03: -onlynet excluding IPv4 and IPv6 soft-sets -dnsseed=0
(Core init.cpp:835-844)."
  ;; The standard Tor-only setup: onion-only via -listenonion, no -proxy.
  (is-false (%dnsseed-after "-onlynet=onion" "-listenonion=1"))
  ;; Onion-only with an explicit proxy.
  (is-false (%dnsseed-after "-onlynet=onion" "-proxy=127.0.0.1:9050"))
  ;; CJDNS-only is equally clearnet-free.
  (is-false (%dnsseed-after "-onlynet=cjdns" "-cjdnsreachable=1"))
  ;; Any clearnet net in the set leaves seeding alone.
  (is-true (%dnsseed-after "-onlynet=ipv4"))
  (is-true (%dnsseed-after "-onlynet=ipv6"))
  (is-true (%dnsseed-after "-onlynet=onion" "-onlynet=ipv6"
                           "-proxy=127.0.0.1:9050"))
  ;; No -onlynet at all: unchanged default.
  (is-true (%dnsseed-after)))

(test config-onlynet-dnsseed-soft-set-semantics
  "Soft-set semantics (Core SoftSetBoolArg + the explicit check at
init.cpp:1691-1693): an explicit -dnsseed=0 stays off, and an explicit
-dnsseed=1 under a clearnet-excluding -onlynet is an init error rather than a
silent override — the user asked for two incompatible things."
  ;; Explicit 0 with no clearnet: already off, no error.
  (is-false (%dnsseed-after "-onlynet=onion" "-listenonion=1" "-dnsseed=0"))
  ;; Explicit 1 with no clearnet: init error.
  (signals error
    (%dnsseed-after "-onlynet=onion" "-listenonion=1" "-dnsseed=1"))
  (signals error
    (%dnsseed-after "-onlynet=onion" "-proxy=127.0.0.1:9050" "-dnsseed=1"))
  (signals error
    (%dnsseed-after "-onlynet=cjdns" "-cjdnsreachable=1" "-dnsseed=1"))
  ;; Explicit 1 WITH clearnet reachable is fine — no error, stays on.
  (is-true (%dnsseed-after "-onlynet=ipv4" "-dnsseed=1"))
  (is-true (%dnsseed-after "-dnsseed=1"))
  ;; Explicit 0 with clearnet reachable stays off.
  (is-false (%dnsseed-after "-dnsseed=0")))

(test reachable-seed-addresses-filter
  "G7-03 (dial side): seed lists are clearnet by construction, so under an
-onlynet that forbids clearnet they must not become dial candidates. Core
never hits this because seeds enter addrman and every candidate is filtered by
g_reachable_nets at selection time; we build the dial list directly."
  (let* ((clearnet '("203.0.113.7" "2001:db8::1"))
         ;; Literal rather than netaddress-tests' +onion-str-1+: that file may
         ;; load after this one, which would make the reference a
         ;; compile-time undefined-variable warning.
         (onion '("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion")))
    ;; Default reachable set: clearnet seeds pass through untouched.
    (let ((bitcoin-lisp.networking:*reachable-networks* '(:ipv4 :ipv6)))
      (is (equal clearnet (bitcoin-lisp::%reachable-seed-addresses clearnet))))
    ;; Onion-only: every clearnet seed is dropped rather than dialed.
    (let ((bitcoin-lisp.networking:*reachable-networks* '(:torv3)))
      (is (null (bitcoin-lisp::%reachable-seed-addresses clearnet)))
      (is (equal onion (bitcoin-lisp::%reachable-seed-addresses onion))))
    ;; IPv4-only drops IPv6 seeds and keeps IPv4.
    (let ((bitcoin-lisp.networking:*reachable-networks* '(:ipv4)))
      (is (equal '("203.0.113.7")
                 (bitcoin-lisp::%reachable-seed-addresses clearnet))))
    ;; An address whose network cannot be determined is dropped, not dialed:
    ;; under an active restriction an unclassifiable candidate is exactly what
    ;; must not leak.
    (let ((bitcoin-lisp.networking:*reachable-networks* '(:ipv4 :ipv6)))
      (is (null (bitcoin-lisp::%reachable-seed-addresses
                 '("seed.example.invalid" "not an address")))))))
