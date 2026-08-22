(in-package #:bitcoin-lisp.tests)

(def-suite :config-tests
  :description "bitcoin.conf and CLI (-key=value) argument parsing"
  :in :bitcoin-lisp-tests)

(in-suite :config-tests)

(defun cfg (key alist) (cdr (assoc key alist :test #'string=)))

;;; --- value coercion ---------------------------------------------------------

(test conf-parse-bool-is-core-s-interpretbool-not-a-lenient-reading
  "Core's InterpretBool is `LocaleIndependentAtoi(v) != 0` (args.cpp:57-62), and
atoi(\"true\") is 0. So the word `true` is FALSE to Bitcoin Core — as are `yes`,
`on` and every other non-numeric spelling. We accepted all of them as true and
treated anything unrecognized as true too, which is the opposite answer on a
config an operator could reasonably write: `server=true` opened a listener here
and left it closed on Core.

Only the empty string (a bare -flag) is true without being a number."
  (is-true  (bitcoin-lisp::conf-parse-bool "1"))
  (is-true  (bitcoin-lisp::conf-parse-bool ""))       ; bare -flag
  (is-true  (bitcoin-lisp::conf-parse-bool "42"))
  (is-true  (bitcoin-lisp::conf-parse-bool "-1"))     ; non-zero, so true
  (is-true  (bitcoin-lisp::conf-parse-bool "1abc"))   ; longest integer prefix
  (is-false (bitcoin-lisp::conf-parse-bool "0"))
  (is-false (bitcoin-lisp::conf-parse-bool "true"))
  (is-false (bitcoin-lisp::conf-parse-bool "YES"))
  (is-false (bitcoin-lisp::conf-parse-bool "on"))
  (is-false (bitcoin-lisp::conf-parse-bool "false"))
  (is-false (bitcoin-lisp::conf-parse-bool "no"))
  (is-false (bitcoin-lisp::conf-parse-bool "off")))

(test locale-independent-atoi-matches-core
  "The integer reading the whole config system rests on (strencodings.h:118-143):
C-locale atoi with the undefined behaviour removed."
  (is (= 0   (bitcoin-lisp::locale-independent-atoi "true")))
  (is (= 1   (bitcoin-lisp::locale-independent-atoi "1abc")))
  (is (= -5  (bitcoin-lisp::locale-independent-atoi "-5")))
  (is (= 42  (bitcoin-lisp::locale-independent-atoi "  42  ")))
  (is (= 7   (bitcoin-lisp::locale-independent-atoi "+7")))
  (is (= 0   (bitcoin-lisp::locale-independent-atoi "+-3")))  ; Core returns 0
  (is (= 0   (bitcoin-lisp::locale-independent-atoi "")))
  (is (= 0   (bitcoin-lisp::locale-independent-atoi "abc"))))

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

(test the-network-section-outranks-the-global-area
  "Core's precedence is `command line > config network section > config default
section` (settings.cpp:36). We returned keys in file order and let the first
ASSOC win, so the GLOBAL value beat the section — the reverse of Core, on every
key an operator had bothered to scope. Scoping a value is a statement that it
should win; getting it backwards silently ignores the more specific setting."
  (let ((text (format nil "rpcport=7777~%[main]~%rpcport=8888~%")))
    (is (string= "8888" (cfg "rpcport" (bitcoin-lisp::parse-bitcoin-conf text :mainnet)))))
  ;; And a global key with no section counterpart still applies.
  (let ((text (format nil "txindex=1~%[main]~%rpcport=8888~%")))
    (let ((a (bitcoin-lisp::parse-bitcoin-conf text :mainnet)))
      (is (string= "1" (cfg "txindex" a)))
      (is (string= "8888" (cfg "rpcport" a))))))

(test an-inline-hash-comment-is-stripped
  "Core cuts the line at the first # wherever it appears (config.cpp:41-44). We
only skipped whole-line comments, so `datadir=/srv/btc  # mainnet` yielded a
datadir whose literal name contained the comment — and, because a missing
datadir was created rather than refused, that was a silent resync from genesis
into a junk directory."
  (let ((a (bitcoin-lisp::parse-bitcoin-conf
            (format nil "datadir=/srv/btc  # mainnet~%txindex=1 # on~%"))))
    (is (string= "/srv/btc" (cfg "datadir" a)))
    (is (string= "1" (cfg "txindex" a)))))

(test a-hash-in-an-rpcpassword-is-refused-rather-than-guessed
  "The one place Core will not silently strip: it cannot tell a comment from a
password character, so it refuses the file (config.cpp:58-61). Stripping would
silently shorten the password; keeping would silently include a comment."
  (signals bitcoin-lisp::config-parse-error
    (bitcoin-lisp::parse-bitcoin-conf (format nil "rpcpassword=abc#def~%"))))

(test malformed-config-lines-are-refused-as-core-refuses-them
  "Core returns false from GetConfigOptions and the node does not start
(config.cpp:52-72). A config this malformed half-applying is how an operator
ends up running settings they did not write."
  ;; A leading dash: the CLI spelling, in a file.
  (signals bitcoin-lisp::config-parse-error
    (bitcoin-lisp::parse-bitcoin-conf (format nil "-txindex=1~%")))
  ;; A non-empty line with no '='.
  (signals bitcoin-lisp::config-parse-error
    (bitcoin-lisp::parse-bitcoin-conf (format nil "txindex~%")))
  ;; Core adds a hint for the negated spelling; assert it reaches the operator.
  (handler-case (bitcoin-lisp::parse-bitcoin-conf (format nil "notxindex~%"))
    (bitcoin-lisp::config-parse-error (e)
      (is (search "notxindex=1"
                  (bitcoin-lisp::config-parse-error-message e))
          "the negated-option hint is missing from: ~A"
          (bitcoin-lisp::config-parse-error-message e)))))

(test a-network-selected-inside-the-config-file-still-scopes-its-own-section
  "The network was resolved from the CLI alone and the file was then parsed
against it. So a bitcoin.conf that selects the network itself — the normal way
to run a node from a config file — left us scoping to the DEFAULT network's
section and silently dropping the whole block the operator wrote.

Core reads the chain selectors from the global area only (section=\"\",
args.cpp:825-829) and then scopes, which is what this now does."
  (let ((text (format nil "testnet4=1~%rpcport=1111~%[testnet4]~%rpcport=48332~%")))
    (multiple-value-bind (plist merged network)
        (bitcoin-lisp::args->start-node-plist '() text)
      (declare (ignore plist))
      (is (eq :testnet4 network))
      (is (string= "48332" (cfg "rpcport" merged))
          "the [testnet4] section was dropped, so its rpcport never applied"))))

(test conflicting-chain-selectors-are-an-error-not-a-silent-priority
  "Core throws \"Invalid combination of -regtest, -signet, -testnet, -testnet4
and -chain. Can use at most one.\" (args.cpp:839-841). We resolved the conflict
by a silent priority order, so `-chain=regtest` on the command line plus a stale
`testnet=1` in bitcoin.conf started the node on PUBLIC TESTNET3 — a different
network from either of the two the operator named."
  (signals bitcoin-lisp::config-parse-error
    (bitcoin-lisp::resolve-network-from-config
     '(("chain" . "regtest") ("testnet" . "1"))))
  (signals bitcoin-lisp::config-parse-error
    (bitcoin-lisp::resolve-network-from-config '(("regtest" . "1") ("signet" . "1"))))
  ;; A selector explicitly turned OFF is not a selector.
  (is (eq :regtest (bitcoin-lisp::resolve-network-from-config
                    '(("regtest" . "1") ("testnet" . "0")))))
  ;; And one selector alone still works.
  (is (eq :testnet4 (bitcoin-lisp::resolve-network-from-config '(("testnet4" . "1"))))))

(test includeconf-merges-a-split-configuration
  "-includeconf was unimplemented: a split configuration loaded with everything
at defaults after one warning line, which on a running node is indistinguishable
from a config file that was read and understood. Core reads the includes into
the same settings map (config.cpp:162-199), so a section in an included file
outranks a global in the main one."
  (let ((main (format nil "includeconf=extra.conf~%rpcport=1111~%"))
        (extra (format nil "txindex=1~%[main]~%rpcport=8888~%")))
    (multiple-value-bind (plist merged network)
        (bitcoin-lisp::args->start-node-plist '("-chain=main") (list main extra))
      (declare (ignore plist))
      (is (eq :mainnet network))
      (is (string= "1" (cfg "txindex" merged))
          "the included file's global keys did not apply")
      (is (string= "8888" (cfg "rpcport" merged))
          "the included file's [main] section must outrank the main file's global"))))

(test each-config-file-gets-its-own-section-scope
  "Included files are separate STREAMS in Core, so a [section] left open at the
end of one file does not carry into the next. Concatenating the texts — the
obvious way to implement includes — would silently attribute the second file's
global keys to the first file's last section."
  (let ((main (format nil "[regtest]~%rpcport=1111~%"))
        (extra (format nil "txindex=1~%")))
    (multiple-value-bind (plist merged)
        (bitcoin-lisp::args->start-node-plist '("-chain=main") (list main extra))
      (declare (ignore plist))
      (is (string= "1" (cfg "txindex" merged))
          "the second file's global key was swallowed by the first file's section")
      (is (null (cfg "rpcport" merged))
          "a [regtest] key applied while running mainnet"))))

;;; --- network resolution -----------------------------------------------------

(test resolve-network-precedence
  (is (eq :testnet3 (bitcoin-lisp::resolve-network-from-config '())))          ; default
  (is (eq :mainnet (bitcoin-lisp::resolve-network-from-config '(("chain" . "main")))))
  (is (eq :testnet4 (bitcoin-lisp::resolve-network-from-config '(("testnet4" . "1")))))
  (is (eq :signet (bitcoin-lisp::resolve-network-from-config '(("signet" . "1")))))
  ;; -regtest AND -chain together is now an error, not a silent priority —
  ;; asserted in CONFLICTING-CHAIN-SELECTORS-ARE-AN-ERROR-NOT-A-SILENT-PRIORITY.
  (signals error (bitcoin-lisp::resolve-network-from-config '(("chain" . "bogus")))))

;;; --- full plist assembly ----------------------------------------------------

(test config-alist-to-start-node-plist
  "A merged alist becomes typed start-node keyword arguments."
  (let ((plist (bitcoin-lisp::config-alist->start-node-plist
                '(("txindex" . "1") ("dbcache" . "2000") ("rpcuser" . "bob")
                  ("maxconnections" . "16") ("v2transport" . "0")
                  ("acceptstalefeeestimates" . "1"))
                :mainnet)))
    (is (eq :mainnet (getf plist :network)))
    (is (eq t (getf plist :txindex)))
    (is (= 2000 (getf plist :dbcache-mib)))
    (is (string= "bob" (getf plist :rpc-user)))
    (is (= 16 (getf plist :max-connections)))
    (is (eq t (getf plist :accept-stale-fee-estimates)))
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
g_reachable_nets at selection time; we build the dial list directly.
No proxy is configured throughout: this is the direct-dial half of the
filter, where discover-peers only ever produces IP literals."
  (let* ((clearnet '("203.0.113.7" "2001:db8::1"))
         ;; Literal rather than netaddress-tests' +onion-str-1+: that file may
         ;; load after this one, which would make the reference a
         ;; compile-time undefined-variable warning.
         (onion '("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"))
         (bitcoin-lisp.networking:*proxy* nil))
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
    ;; With NO proxy an address whose network cannot be determined is dropped,
    ;; not dialed: nothing can resolve it inside a tunnel, and under an active
    ;; restriction an unclassifiable candidate is exactly what must not leak.
    (let ((bitcoin-lisp.networking:*reachable-networks* '(:ipv4 :ipv6)))
      (is (null (bitcoin-lisp::%reachable-seed-addresses
                 '("seed.example.invalid" "not an address")))))))

;;; --- GA8: proxied DNS seeding (bootstrap regression from #306) --------------

(test reachable-seed-addresses-proxy-hostnames
  "Under -proxy the seed list is deliberately the seed HOSTNAMES, left
unresolved so the SOCKS5 proxy resolves them inside the tunnel (ATYP
DOMAINNAME) — Core's `if (HaveNameProxy()) AddAddrFetch(seed)`
(net.cpp:2356-2357), where a proxied seed stays dialable BY NAME. Dropping
every candidate parse-network-address cannot classify (#306) therefore
discarded every DNS seed of a proxied node."
  (let ((seeds (bitcoin-lisp::network-dns-seeds :mainnet)))
    ;; The affected matrix, asserted rather than assumed: mainnet DNS seeds are
    ;; hostnames — exactly the shape the old predicate discarded — and mainnet
    ;; has no fixed-seed list to fall back on (testnet4 alone has one).
    (is-true seeds)
    (is-true (notany #'bitcoin-lisp.networking:parse-network-address seeds))
    (is-true (every #'bitcoin-lisp.networking:parse-network-address
                    bitcoin-lisp.networking:*testnet4-fixed-seeds*))
    ;; -proxy with no -onlynet: discover-peers returns the hostnames verbatim
    ;; (no DNS is performed on this branch, so the test does no network I/O)
    ;; and every one must survive the filter.
    (%with-net-config-globals
      (bitcoin-lisp::apply-config-globals
       (bitcoin-lisp::parse-cli-args '("-proxy=127.0.0.1:9050")))
      (let ((dns (bitcoin-lisp.networking:discover-peers seeds)))
        (is (equal seeds dns))
        (is (equal seeds (bitcoin-lisp::%reachable-seed-addresses dns))))
      ;; The literal branch is untouched by the proxy: still -onlynet-filtered.
      (is (equal '("203.0.113.7")
                 (bitcoin-lisp::%reachable-seed-addresses '("203.0.113.7"))))
      (let ((bitcoin-lisp.networking:*reachable-networks* '(:ipv4)))
        (is (null (bitcoin-lisp::%reachable-seed-addresses '("2001:db8::1"))))))
    ;; -proxy together with a clearnet-containing -onlynet: seeding stays on
    ;; (soft-set does not fire) and the hostnames stay dialable.
    (%with-net-config-globals
      (bitcoin-lisp::apply-config-globals
       (bitcoin-lisp::parse-cli-args '("-onlynet=onion" "-onlynet=ipv6"
                                       "-proxy=127.0.0.1:9050")))
      (is-true bitcoin-lisp::*dns-seed-enabled*)
      (is (equal seeds (bitcoin-lisp::%reachable-seed-addresses seeds))))))

(test reachable-seed-addresses-onion-only-no-clearnet-dial
  "G7-03 control for the change above: -onlynet=onion still yields no clearnet
dial candidate, in BOTH layers. Layer 1 — the DNS query never happens, because
an -onlynet excluding IPv4/IPv6 soft-sets -dnsseed=0 (Core init.cpp:835-844).
Layer 2 — even if a hostname reached the filter, it is a clearnet candidate
however the proxy resolves it (a DNS seed answers with A/AAAA records), so it
is dropped along with every clearnet literal."
  (let ((onion '("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"))
        (seeds (bitcoin-lisp::network-dns-seeds :mainnet)))
    (%with-net-config-globals
      (bitcoin-lisp::apply-config-globals
       (bitcoin-lisp::parse-cli-args '("-onlynet=onion" "-proxy=127.0.0.1:9050")))
      (is (equal '(:torv3) bitcoin-lisp.networking:*reachable-networks*))
      ;; Layer 1.
      (is-false bitcoin-lisp::*dns-seed-enabled*)
      ;; Layer 2: hostnames, clearnet literals and the fixed-seed list alike.
      (is (null (bitcoin-lisp::%reachable-seed-addresses seeds)))
      (is (null (bitcoin-lisp::%reachable-seed-addresses
                 '("203.0.113.7" "2001:db8::1"))))
      (is (null (bitcoin-lisp::%reachable-seed-addresses
                 bitcoin-lisp.networking:*testnet4-fixed-seeds*)))
      ;; An onion literal is of course still dialable.
      (is (equal onion (bitcoin-lisp::%reachable-seed-addresses onion))))
    ;; cjdns-only is equally clearnet-free with a proxy configured.
    (%with-net-config-globals
      (bitcoin-lisp::apply-config-globals
       (bitcoin-lisp::parse-cli-args '("-onlynet=cjdns" "-cjdnsreachable=1"
                                       "-proxy=127.0.0.1:9050")))
      (is-false bitcoin-lisp::*dns-seed-enabled*)
      (is (null (bitcoin-lisp::%reachable-seed-addresses seeds))))))

;;; --- datadir layout and lifecycle (Core chainparamsbase.cpp, args.cpp:789) ---

(defmacro %with-temp-datadir ((var) &body body)
  `(let ((,var (ensure-directories-exist
                (merge-pathnames (format nil "bl-datadir-~D/" (get-internal-real-time))
                                 (uiop:temporary-directory)))))
     (unwind-protect (progn ,@body)
       (uiop:delete-directory-tree ,var :validate t :if-does-not-exist :ignore))))

(defun %touch-chainstate (dir)
  (ensure-directories-exist dir)
  (with-open-file (s (merge-pathnames "chainstate.dat" dir)
                     :direction :output :if-exists :supersede)
    (write-line "x" s))
  dir)

(test the-datadir-layout-is-core-s
  "Core: mainnet at the datadir ROOT, testnet3 in testnet3/ (chainparamsbase.cpp
:40-55). Ours was the inverse for exactly those two — mainnet in mainnet/ and
testnet3 at the root — so pointing our node at a Core datadir with the default
network wrote testnet3 data into Core's MAINNET directory, and pointing Core at
ours found nothing and started a fresh sync. The other three already agreed."
  (%with-temp-datadir (dir)
    (is (equal dir (bitcoin-lisp::network-data-path dir :mainnet)))
    (is (equal (merge-pathnames "testnet3/" dir)
               (bitcoin-lisp::network-data-path dir :testnet3)))
    (is (equal (merge-pathnames "testnet4/" dir)
               (bitcoin-lisp::network-data-path dir :testnet4)))
    (is (equal (merge-pathnames "signet/" dir)
               (bitcoin-lisp::network-data-path dir :signet)))
    (is (equal (merge-pathnames "regtest/" dir)
               (bitcoin-lisp::network-data-path dir :regtest)))))

(test an-existing-node-keeps-its-legacy-layout-rather-than-losing-its-chain
  "The deliberate deviation. Adopting Core's layout unconditionally would show
an EMPTY datadir to a node that has one — on mainnet that is a synced chain
discarded and IBD restarted from genesis, measured in days. So a datadir that
already holds a chainstate in the old layout keeps using it (and says so)."
  (%with-temp-datadir (dir)
    (%touch-chainstate (merge-pathnames "mainnet/" dir))
    (is (equal (merge-pathnames "mainnet/" dir)
               (bitcoin-lisp::network-data-path dir :mainnet))
        "a synced mainnet node was pointed at an empty Core-layout directory")))

(test a-fresh-datadir-gets-core-s-layout-even-if-an-empty-legacy-dir-exists
  "The legacy check is for DATA, not for a directory: ensure-directories-exist
creates empty ones freely, and treating an empty mainnet/ as legacy would pin
every new node to the old layout forever."
  (%with-temp-datadir (dir)
    (ensure-directories-exist (merge-pathnames "mainnet/" dir))
    (is (equal dir (bitcoin-lisp::network-data-path dir :mainnet)))))

(test core-s-layout-wins-when-both-exist
  "If the node has already been moved, the Core-layout chainstate is the live
one and the leftover legacy directory must not pull it back."
  (%with-temp-datadir (dir)
    (%touch-chainstate (merge-pathnames "mainnet/" dir))
    (%touch-chainstate dir)
    (is (equal dir (bitcoin-lisp::network-data-path dir :mainnet)))))

(test a-named-datadir-that-does-not-exist-is-fatal
  "Core: CheckDataDirOption (args.cpp:789-793) refuses to start. We created it,
so a typo and an unmounted volume both presented as an empty datadir — which
means a silent full re-sync from genesis. Omitting -datadir is still fine: that
is the default path, and creating it is the intended behaviour."
  (signals bitcoin-lisp::config-parse-error
    (bitcoin-lisp::%check-datadir-option '(("datadir" . "/nonexistent/bl-typo-xyz"))))
  ;; No -datadir at all: not an error.
  (finishes (bitcoin-lisp::%check-datadir-option '()))
  (%with-temp-datadir (dir)
    (finishes (bitcoin-lisp::%check-datadir-option
               (list (cons "datadir" (namestring dir)))))))

(test config-rpcauth-and-rpcallowip-are-repeatable
  "-rpcauth and -rpcallowip are list options: every occurrence counts, from the
command line and from bitcoin.conf alike (Core GetArgs -> g_rpcauth,
httprpc.cpp:289; rpc_allow_subnets, httpserver.cpp:153). Collapsing them to the
last occurrence — what every non-repeatable option does here — would silently
drop all but one credential and all but one allowed subnet."
  (let ((plist (bitcoin-lisp::args->start-node-plist
                '("-regtest"
                  "-rpcauth=alice:aaaa$1111" "-rpcauth=bob:bbbb$2222"
                  "-rpcallowip=10.0.0.0/8" "-rpcallowip=192.168.1.5")
                nil)))
    (is (equal '("alice:aaaa$1111" "bob:bbbb$2222") (getf plist :rpc-auth)))
    (is (equal '("10.0.0.0/8" "192.168.1.5") (getf plist :rpc-allow-ip))))
  ;; from the config file, where the same key repeats on separate lines
  (let ((plist (bitcoin-lisp::args->start-node-plist
                '("-regtest")
                (format nil "rpcauth=alice:aaaa$1111~%rpcauth=bob:bbbb$2222~%~
rpcallowip=10.0.0.0/8~%rpcallowip=::/0~%"))))
    (is (equal '("alice:aaaa$1111" "bob:bbbb$2222") (getf plist :rpc-auth)))
    (is (equal '("10.0.0.0/8" "::/0") (getf plist :rpc-allow-ip))))
  ;; absent means absent, not an empty list that looks configured
  (let ((plist (bitcoin-lisp::args->start-node-plist '("-regtest") nil)))
    (is-false (member :rpc-auth plist))
    (is-false (member :rpc-allow-ip plist)))
  ;; and both are known options, so neither trips the unknown-option check
  (is-true (member "rpcauth" bitcoin-lisp::*known-config-options* :test #'string=))
  (is-true (member "rpcallowip" bitcoin-lisp::*known-config-options* :test #'string=))
  (is-true (member "rpcauth" bitcoin-lisp::*repeatable-config-options* :test #'string=))
  (is-true (member "rpcallowip" bitcoin-lisp::*repeatable-config-options*
                   :test #'string=)))

;;; --- Core command-line compatibility (track B P0) ---

(test core-options-are-accepted-not-rejected
  "Core's functional framework passes -logtimemicros, -logthreadnames,
-logsourcelocations, -debugexclude and -loglevel to EVERY node it starts
(test_node.py:68-108), plus 128 more flags across individual tests. An unknown
CLI option is a HARD error here, so before this the framework could not launch
this node at all."
  (dolist (option '("-logtimemicros" "-logthreadnames" "-logsourcelocations"
                    "-debugexclude=libevent" "-loglevel=trace" "-par=4"
                    "-checkblocks=0" "-whitelist=127.0.0.1" "-asmap=x"
                    "-maxuploadtarget=800" "-peertimeout=999"))
    (finishes (bitcoin-lisp::check-cli-args (list "-regtest" option))
              "~A was rejected" option))
  ;; Accepting is not implementing: the option is reported as supplied.
  ;; -asmap and -par have both since been IMPLEMENTED (#456, #462), so the
  ;; duplicate-collapsing behaviour is asserted with one that is still only
  ;; accepted. That an option LEAVES this list as it gains an implementation is
  ;; the point of the list, and this assertion has now been rewritten twice for
  ;; exactly that reason.
  (is (equal '("natpmp")
             (bitcoin-lisp::supplied-core-only-options
              '(("asmap" . "x") ("regtest" . "1")
                ("natpmp" . "1") ("natpmp" . "0")))))
  (is-false (bitcoin-lisp::supplied-core-only-options '(("regtest" . "1"))))
  ;; And a genuinely unknown option is still a hard error.
  (signals error (bitcoin-lisp::check-cli-args '("-notacoreoption"))))

(test disablewallet-turns-the-wallet-off
  "Core's -disablewallet is the negation of our -wallet. 62 functional tests
run wallet-less nodes with it."
  (let ((plist (bitcoin-lisp::args->start-node-plist '("-regtest" "-disablewallet") nil)))
    (is-true (member :wallet plist) "-disablewallet did not reach :wallet")
    (is-false (getf plist :wallet))
    (is-false (member :disable-wallet plist) "the raw key leaked into start-node"))
  ;; An explicit -wallet wins, as it does in Core.
  (let ((plist (bitcoin-lisp::args->start-node-plist
                '("-regtest" "-disablewallet" "-wallet=1") nil)))
    (is-true (getf plist :wallet)))
  (let ((plist (bitcoin-lisp::args->start-node-plist '("-regtest") nil)))
    (is-false (member :disable-wallet plist))))

(test bind-option-parses-core-s-forms
  "-bind=<addr>[:<port>][=onion] (test_node.py:272-276 passes both forms). An
IPv6 literal must be bracketed for its port to be separable, exactly as in
Core — otherwise ::1 would parse as host \"\" port 1."
  (flet ((parsed (spec) (multiple-value-list (bitcoin-lisp::parse-bind-option spec))))
    (is (equal '("127.0.0.1" nil nil) (parsed "127.0.0.1")))
    (is (equal '("127.0.0.1" 18445 nil) (parsed "127.0.0.1:18445")))
    (is (equal '("127.0.0.1" 18445 t) (parsed "127.0.0.1:18445=onion")))
    (is (equal '("127.0.0.1" nil t) (parsed "127.0.0.1=onion")))
    (is (equal '("::1" nil nil) (parsed "::1")))
    (is (equal '("::1" 8333 nil) (parsed "[::1]:8333")))
    (is (equal '("2001:db8::1" nil nil) (parsed "2001:db8::1")))
    (is (equal '("0.0.0.0" 1 nil) (parsed "0.0.0.0:1")))
    ;; Rejected: a port that is not one.
    (is (equal '(nil) (parsed "127.0.0.1:0")))
    (is (equal '(nil) (parsed "127.0.0.1:65536")))
    (is (equal '(nil) (parsed "127.0.0.1:http")))
    (is (equal '(nil) (parsed "")))
    (is (equal '(nil) (parsed nil)))))

(test bind-reaches-the-listener-address-and-port
  "The parsed host and port must actually reach start-node: a -bind carrying a
port overrides -port for the listener, as it does in Core."
  (let ((plist (bitcoin-lisp::args->start-node-plist
                '("-regtest" "-bind=127.0.0.1:18445") nil)))
    (is (string= "127.0.0.1" (getf plist :listen-bind)))
    (is (= 18445 (getf plist :port))))
  ;; No port on -bind leaves -port alone.
  (let ((plist (bitcoin-lisp::args->start-node-plist
                '("-regtest" "-bind=127.0.0.1" "-port=12345") nil)))
    (is (string= "127.0.0.1" (getf plist :listen-bind)))
    (is (= 12345 (getf plist :port))))
  ;; An =onion bind names a Tor-only listener, not an address to bind: the raw
  ;; string must not survive as one, or the node would try to bind
  ;; "127.0.0.1:18445=onion" as a hostname.
  (let ((plist (bitcoin-lisp::args->start-node-plist
                '("-regtest" "-bind=127.0.0.1:18445=onion") nil)))
    (is-false (getf plist :listen-bind)))
  ;; Repeatable: the first plain bind is used, and neither occurrence errors.
  (let ((plist (bitcoin-lisp::args->start-node-plist
                '("-regtest" "-bind=127.0.0.1:18445" "-bind=127.0.0.2:18446") nil)))
    (is (string= "127.0.0.1" (getf plist :listen-bind)))
    (is (= 18445 (getf plist :port)))))

(test log-file-defaults-to-debug-log-in-the-datadir
  "Core writes <datadir>/debug.log unless -debuglogfile says otherwise, and its
functional framework reads that file for every node it starts. We wrote no file
at all without an explicit -logfile."
  (is (string= "/data/dir/debug.log"
               (bitcoin-lisp::%resolve-log-file nil "/data/dir/")))
  (is (string= "/data/dir/debug.log"
               (bitcoin-lisp::%resolve-log-file nil "/data/dir")))
  ;; An explicit path wins.
  (is (string= "/tmp/custom.log"
               (bitcoin-lisp::%resolve-log-file "/tmp/custom.log" "/data/dir/")))
  ;; -debuglogfile=0 disables it, as in Core.
  (is-false (bitcoin-lisp::%resolve-log-file "0" "/data/dir/"))
  (is-false (bitcoin-lisp::%resolve-log-file "" "/data/dir/"))
  ;; No datadir, no default.
  (is-false (bitcoin-lisp::%resolve-log-file nil nil))
  ;; -debuglogfile is Core's spelling of -logfile and reaches the same key.
  (let ((plist (bitcoin-lisp::args->start-node-plist
                '("-regtest" "-debuglogfile=/tmp/x.log") nil)))
    (is (string= "/tmp/x.log" (getf plist :log-file)))))

(test datadir-without-a-trailing-separator-still-names-a-directory
  "Core accepts -datadir with or without a trailing separator. Ours parsed
\"/tmp/x\" as a FILE pathname whose NAME is \"x\", so merging \"regtest/chainstate/\"
onto it produced /tmp/regtest/chainstate/x — the node opened its databases
somewhere nobody asked for, and the first thing it reported was a LevelDB
NotFound on a path the operator had never typed.

Found by running the real binary the way the test framework runs it, which is
what track B exists for: every launcher in this repo happened to pass a
trailing slash."
  (dolist (spelling '("/tmp/bl-datadir-test" "/tmp/bl-datadir-test/"))
    (is (equal #P"/tmp/bl-datadir-test/regtest/"
               (bitcoin-lisp::network-data-path
                (uiop:ensure-directory-pathname spelling) :regtest))
        "~S" spelling))
  ;; And the normalization start-node-from-args applies to whatever the CLI,
  ;; the config file or the default produced.
  (is (equal "/tmp/bl-datadir-test/"
             (bitcoin-lisp::%normalize-datadir "/tmp/bl-datadir-test")))
  (is (equal "/tmp/bl-datadir-test/"
             (bitcoin-lisp::%normalize-datadir "/tmp/bl-datadir-test/")))
  (is-false (bitcoin-lisp::%normalize-datadir nil)))

(test executable-argv-helpers-recognise-core-s-spellings
  "-version and -help must be answered before anything is started, and the
option name has to be read the way Core's ArgsManager reads it: leading dashes
stripped, value after #\\= ignored."
  (is (equal "datadir" (bitcoin-lisp::%argv-option-name "-datadir=/tmp/x")))
  (is (equal "datadir" (bitcoin-lisp::%argv-option-name "--datadir=/tmp/x")))
  (is (equal "regtest" (bitcoin-lisp::%argv-option-name "-regtest")))
  (is-false (bitcoin-lisp::%argv-option-name "notanoption"))
  (is-false (bitcoin-lisp::%argv-option-name ""))
  (is-true (bitcoin-lisp::%argv-asks-for '("-regtest" "-version") '("version")))
  (is-true (bitcoin-lisp::%argv-asks-for '("-help") '("help" "h" "?")))
  (is-true (bitcoin-lisp::%argv-asks-for '("-?") '("help" "h" "?")))
  (is-false (bitcoin-lisp::%argv-asks-for '("-regtest" "-datadir=/x") '("version")))
  ;; A VALUE that looks like the option name must not trigger it.
  (is-false (bitcoin-lisp::%argv-asks-for '("-datadir=version") '("version"))))

(test testactivationheight-moves-buried-deployments
  "-testactivationheight=name@height lets a regtest chain be driven across a
buried deployment in a handful of blocks (Core chainparams.cpp:49-67). Without
it a test that wants pre-BIP66 behaviour cannot reach it at all on a chain that
activates at height 1 — which is why the plan counts this among the options
gating ~70 of Core's tests."
  (unwind-protect
       (progn
         (bitcoin-lisp.validation:apply-test-activation-heights
          '("csv@5" "segwit@7" "dersig@9" "cltv@11" "bip34@13"))
         (is (= 5 (bitcoin-lisp.validation:get-csv-activation-height :regtest)))
         (is (= 7 (bitcoin-lisp.validation:get-segwit-activation-height :regtest)))
         (is (= 9 (bitcoin-lisp.validation:get-bip66-activation-height :regtest)))
         (is (= 11 (bitcoin-lisp.validation:get-bip65-activation-height :regtest)))
         (is (= 13 (bitcoin-lisp.validation:get-bip34-activation-height :regtest)))
         ;; An untouched deployment keeps its chain default.
         (bitcoin-lisp.validation:apply-test-activation-heights '("csv@5"))
         (is (= 5 (bitcoin-lisp.validation:get-csv-activation-height :regtest)))
         (is (= 0 (bitcoin-lisp.validation:get-segwit-activation-height :regtest))))
    (bitcoin-lisp.validation:apply-test-activation-heights nil))
  ;; Cleared again, the defaults are back — an override must not outlive its run.
  (is (= 0 (bitcoin-lisp.validation:get-segwit-activation-height :regtest))))

(test testactivationheight-rejects-what-core-rejects
  "Core raises on a missing '@', a height that is not a non-negative integer,
and a name that is not a buried deployment (chainparams.cpp:51-66). Silently
ignoring a typo'd name is the worst outcome: the test then runs against the
very height it was trying to move, and passes for the wrong reason."
  (flet ((parsed (spec)
           (multiple-value-list
            (bitcoin-lisp.validation:parse-test-activation-height spec))))
    (is (equal '("csv" 5) (parsed "csv@5")))
    (is (equal '("segwit" 0) (parsed "segwit@0")))
    (dolist (bad '("csv" "csv@" "csv@-1" "csv@abc" "@5" "nosuch@5"
                   "CSV@5" "csv@5@6" "" nil))
      (is (equal '(nil) (parsed bad)) "accepted ~S" bad)))
  (dolist (bad '(("csv") ("nosuch@5") ("csv@-1")))
    (signals error (bitcoin-lisp.validation:apply-test-activation-heights bad)))
  (bitcoin-lisp.validation:apply-test-activation-heights nil))

(test testactivationheight-and-mocktime-are-repeatable-options
  "-testactivationheight is a LIST option: Core reads it with GetArgs and moves
one deployment per occurrence (chainparams.cpp:49). Collapsing to the last
occurrence would silently drop every override but one."
  (let ((plist (bitcoin-lisp::args->start-node-plist
                '("-regtest" "-testactivationheight=csv@5"
                  "-testactivationheight=segwit@7" "-mocktime=1700000000")
                nil)))
    (is (equal '("csv@5" "segwit@7") (getf plist :test-activation-heights)))
    (is (= 1700000000 (getf plist :mocktime))))
  ;; Both are known options now, so neither is reported as accepted-and-ignored.
  (is-false (bitcoin-lisp::core-only-option-p "mocktime"))
  (is-false (bitcoin-lisp::core-only-option-p "testactivationheight"))
  (is-true (bitcoin-lisp::known-config-option-p "mocktime"))
  (is-true (bitcoin-lisp::known-config-option-p "testactivationheight")))

(defmacro %with-clean-log-categories (&body body)
  "Run BODY with every logging category off, and restore them afterwards."
  `(let ((saved (remove-if-not #'bitcoin-lisp:log-category-enabled-p
                               bitcoin-lisp::+log-categories+)))
     (unwind-protect
          (progn (bitcoin-lisp:apply-log-categories
                  nil (copy-list bitcoin-lisp::+log-categories+))
                 ,@body)
       (bitcoin-lisp:apply-log-categories
        nil (copy-list bitcoin-lisp::+log-categories+))
       (bitcoin-lisp:apply-log-categories saved nil))))

(test debug-categories-are-applied-in-core-s-order
  "-debug enables, then -debugexclude removes (Core init/common.cpp). The order
is what lets `-debug=all -debugexclude=libevent` mean what an operator expects,
and it is the exact pair Core's own test framework passes to every node."
  (%with-clean-log-categories
    (is (equal '("mempool")
               (bitcoin-lisp:apply-log-categories '("net" "mempool") '("net"))))
    ;; "all" and a bare -debug (empty value) enable everything.
    (dolist (spelling '("all" "1" ""))
      (bitcoin-lisp:apply-log-categories nil (copy-list bitcoin-lisp::+log-categories+))
      (is (= (length bitcoin-lisp::+log-categories+)
             (length (bitcoin-lisp:apply-log-categories (list spelling) nil)))
          "~S did not enable every category" spelling))
    ;; ...minus the exclusions, which are applied after.
    (is-false (member "libevent"
                      (bitcoin-lisp:apply-log-categories '("all") '("libevent"))
                      :test #'string=))
    ;; "0"/"none" turn everything off, and a later include can re-enable.
    (is-false (bitcoin-lisp:apply-log-categories '("none") nil))
    (is (equal '("rpc") (bitcoin-lisp:apply-log-categories '("0" "rpc") nil)))))

(test unknown-debug-categories-are-refused
  "A silently-dropped -debug=nett is an operator staring at a log that will
never contain what they asked for. Core logs a warning; we refuse, because the
option has no other effect to notice."
  (%with-clean-log-categories
    (signals error (bitcoin-lisp:apply-log-categories '("nett") nil))
    (signals error (bitcoin-lisp:apply-log-categories nil '("nett")))
    ;; A real category is still fine either side.
    (finishes (bitcoin-lisp:apply-log-categories '("net") '("net")))))

(test debug-option-collects-categories-and-raises-the-level
  "-debug is REPEATABLE and carries a category. The previous read was
CONF-PARSE-BOOL of its value — and atoi(\"net\") is 0 — so -debug=net set no
category AND did not raise the level: it did nothing whatsoever."
  (let ((plist (bitcoin-lisp::args->start-node-plist
                '("-regtest" "-debug=net" "-debug=mempool"
                  "-debugexclude=libevent" "-logtimemicros" "-logthreadnames")
                nil)))
    (is (equal '("net" "mempool") (getf plist :debug-categories)))
    (is (equal '("libevent") (getf plist :debug-exclude)))
    (is (eq t (getf plist :log-time-micros)))
    (is (eq t (getf plist :log-thread-names)))
    ;; A category's lines are emitted at debug level, so enabling one without
    ;; raising the level would be a switch that changes nothing.
    (is (eq :debug (getf plist :log-level))))
  ;; A bare -debug still means "everything", as it always did. PARSE-CLI-ARGS
  ;; normalizes a valueless flag to "1", which APPLY-LOG-CATEGORIES treats as
  ;; all — same as Core, where -debug with no value is the "1" spelling.
  (let ((plist (bitcoin-lisp::args->start-node-plist '("-regtest" "-debug") nil)))
    (is (equal '("1") (getf plist :debug-categories)))
    (is (eq :debug (getf plist :log-level))))
  ;; -debug=0 must NOT raise the level: that spelling turns logging off.
  (let ((plist (bitcoin-lisp::args->start-node-plist '("-regtest" "-debug=0") nil)))
    (is-false (eq :debug (getf plist :log-level))))
  ;; An explicit -loglevel wins.
  (let ((plist (bitcoin-lisp::args->start-node-plist
                '("-regtest" "-debug=net" "-loglevel=info") nil)))
    (is (eq :info (getf plist :log-level)))))

(test log-format-flags-change-the-line
  "-logtimemicros appends a microsecond fraction and -logthreadnames inserts
the writing thread's name, as Core does. Asserted on the formatted line rather
than on the flags, since the flag existing is not the feature."
  (let ((plain (let ((bitcoin-lisp::*log-time-micros* nil)
                     (bitcoin-lisp::*log-thread-names* nil))
                 (bitcoin-lisp::format-log-entry :info "hello ~A" '(1)))))
    (is-true (search "INFO: hello 1" plain))
    ;; [YYYY-MM-DD HH:MM:SS] with no fraction
    (is-false (search "." (subseq plain 0 (1+ (position #\] plain))))))
  (let ((micros (let ((bitcoin-lisp::*log-time-micros* t)
                      (bitcoin-lisp::*log-thread-names* nil))
                  (bitcoin-lisp::format-log-entry :info "hello" '()))))
    (is-true (find #\. (subseq micros 0 (1+ (position #\] micros))))
             "no microsecond fraction in ~S" micros))
  (let ((named (let ((bitcoin-lisp::*log-time-micros* nil)
                     (bitcoin-lisp::*log-thread-names* t))
                 (bitcoin-lisp::format-log-entry :info "hello" '()))))
    ;; A second bracketed field appears between the timestamp and the level.
    (is (= 2 (count #\[ named)) "thread name missing from ~S" named)))

(test relay-policy-knobs-take-effect
  "-dustrelayfee, -incrementalrelayfee and -bytespersigop are relay POLICY, not
consensus, and Core exposes all three. Ours were compiled-in constants, so a
node could not be tuned at all — and two of them were DEFCONSTANTs, which in
this image means the value is folded into every caller and cannot be changed
even at the REPL without a restart.

Fee rates arrive as BTC/kvB on the command line, as every other Core fee option
does, and are stored as satoshis."
  (let ((saved (list bitcoin-lisp.validation::+dust-relay-fee-rate+
                     bitcoin-lisp.mempool::+incremental-relay-fee-rate+
                     bitcoin-lisp.mempool::+bytes-per-sigop+)))
    (unwind-protect
         (progn
           (bitcoin-lisp::apply-config-globals
            '(("dustrelayfee" . "0.00004")
              ("incrementalrelayfee" . "0.00002")
              ("bytespersigop" . "40")))
           (is (= 4000 bitcoin-lisp.validation::+dust-relay-fee-rate+))
           (is (= 2000 bitcoin-lisp.mempool::+incremental-relay-fee-rate+))
           (is (= 40 bitcoin-lisp.mempool::+bytes-per-sigop+))
           ;; And the sigop-adjusted size actually uses the new value, which is
           ;; the point — a knob nothing reads is the failure this repo keeps
           ;; finding.
           (is (= (ceiling (* 3 40) 4)
                  (bitcoin-lisp.mempool::sigop-adjusted-vsize 1 3))))
      (setf bitcoin-lisp.validation::+dust-relay-fee-rate+ (first saved)
            bitcoin-lisp.mempool::+incremental-relay-fee-rate+ (second saved)
            bitcoin-lisp.mempool::+bytes-per-sigop+ (third saved))))
  ;; Malformed values are refused, not silently ignored.
  (dolist (bad '((("dustrelayfee" . "notanumber"))
                 (("incrementalrelayfee" . "x"))
                 (("bytespersigop" . "0"))
                 (("bytespersigop" . "-1"))))
    (signals error (bitcoin-lisp::apply-config-globals bad)))
  ;; All three are known options and no longer reported as ignored.
  (dolist (name '("dustrelayfee" "incrementalrelayfee" "bytespersigop"))
    (is-true (bitcoin-lisp::known-config-option-p name) "~A unknown" name)
    (is-false (bitcoin-lisp::core-only-option-p name) "~A still ignored" name)))

(test validation-resource-knobs-take-effect
  "Track D's Validation & resources group over knobs that already existed as
constants. Each asserts the EFFECT, not the assignment."
  (let ((saved (list bitcoin-lisp.networking::+max-tip-age-seconds+
                     bitcoin-lisp.coalton.interop::+signature-cache-max-entries+
                     bitcoin-lisp.storage:*fast-prune*
                     bitcoin-lisp.storage:*blocks-xor*)))
    (unwind-protect
         (progn
           (bitcoin-lisp::apply-config-globals
            '(("maxtipage" . "3600") ("maxsigcachesize" . "4")
              ("fastprune" . "1") ("blocksxor" . "0")))
           ;; -maxtipage: how old the tip may be before the node still calls
           ;; itself in IBD (Core DEFAULT_MAX_TIP_AGE).
           (is (= 3600 bitcoin-lisp.networking::+max-tip-age-seconds+))
           ;; -maxsigcachesize is MiB; a cache entry is a 32-byte key, which is
           ;; what Core's CuckooCache element is too.
           (is (= (floor (* 4 1024 1024) 32)
                  bitcoin-lisp.coalton.interop::+signature-cache-max-entries+))
           ;; -fastprune changes the ROLLOVER threshold, which is the whole
           ;; point: 64 KiB instead of 128 MiB (blockstorage.cpp:858).
           (is-true bitcoin-lisp.storage:*fast-prune*)
           (is (= bitcoin-lisp.storage::+fast-prune-blockfile-size+
                  (bitcoin-lisp.storage:max-blockfile-size 100)))
           ;; ...and Core raises it past a record that would not otherwise fit,
           ;; because a block that fits in NO file could never be written.
           (is (= (1+ (* 200 1024))
                  (bitcoin-lisp.storage:max-blockfile-size (* 200 1024))))
           (is-false bitcoin-lisp.storage:*blocks-xor*))
      (setf bitcoin-lisp.networking::+max-tip-age-seconds+ (first saved)
            bitcoin-lisp.coalton.interop::+signature-cache-max-entries+ (second saved)
            bitcoin-lisp.storage:*fast-prune* (third saved)
            bitcoin-lisp.storage:*blocks-xor* (fourth saved))))
  ;; Default: the full 128 MiB rollover.
  (is (= bitcoin-lisp.storage::+max-blockfile-size+
         (bitcoin-lisp.storage:max-blockfile-size 100)))
  ;; Malformed values are refused.
  (dolist (bad '((("maxtipage" . "-1")) (("maxsigcachesize" . "0"))
                 (("maxsigcachesize" . "x"))))
    (signals error (bitcoin-lisp::apply-config-globals bad)))
  ;; All four are known and no longer reported as ignored.
  (dolist (name '("maxtipage" "maxsigcachesize" "fastprune" "blocksxor"))
    (is-true (bitcoin-lisp::known-config-option-p name) "~A unknown" name)
    (is-false (bitcoin-lisp::core-only-option-p name) "~A still ignored" name)))

(test rpc-http-config-knobs-take-effect
  "Track D's RPC/HTTP group. Applied by APPLY-RPC-CONFIG-GLOBALS rather than
its sibling for a load-order reason worth knowing: config.lisp compiles BEFORE
src/rpc/package.lisp, so a package-qualified reference to BITCOIN-LISP.RPC
there is a READ error, not a link error."
  (let ((saved (list bitcoin-lisp.rpc:*rpc-cookie-file*
                     bitcoin-lisp.rpc:*rpc-cookie-perms*
                     bitcoin-lisp.rpc:*rpc-threads*
                     bitcoin-lisp.rpc:*rpc-server-timeout*)))
    (unwind-protect
         (progn
           (bitcoin-lisp::apply-rpc-config-globals
            '(("rpccookiefile" . "/tmp/x.cookie") ("rpccookieperms" . "group")
              ("rpcthreads" . "8") ("rpcservertimeout" . "45")))
           (is (equal "/tmp/x.cookie" bitcoin-lisp.rpc:*rpc-cookie-file*))
           (is (eq :group bitcoin-lisp.rpc:*rpc-cookie-perms*))
           (is (= 8 bitcoin-lisp.rpc:*rpc-threads*))
           (is (= 45 bitcoin-lisp.rpc:*rpc-server-timeout*))
           ;; The perms name reaches an actual MODE — 0640 for group.
           (is (= #o640 (bitcoin-lisp.rpc::%cookie-file-mode)))
           ;; An absolute -rpccookiefile is used as given...
           (is (equal "/tmp/x.cookie"
                      (namestring (bitcoin-lisp.rpc::rpc-cookie-path "/data/dir/"))))
           ;; ...and a relative one hangs off the data directory, which is what
           ;; Core means by "prefixed by a net-specific datadir location".
           (setf bitcoin-lisp.rpc:*rpc-cookie-file* "sub/my.cookie")
           (is (equal "/data/dir/sub/my.cookie"
                      (namestring (bitcoin-lisp.rpc::rpc-cookie-path "/data/dir/"))))
           ;; Unset, it is the datadir's .cookie.
           (setf bitcoin-lisp.rpc:*rpc-cookie-file* nil)
           (is (equal "/data/dir/.cookie"
                      (namestring (bitcoin-lisp.rpc::rpc-cookie-path "/data/dir/"))))
           ;; 0 means no timeout, as in Core.
           (bitcoin-lisp::apply-rpc-config-globals '(("rpcservertimeout" . "0")))
           (is-false bitcoin-lisp.rpc:*rpc-server-timeout*))
      (setf bitcoin-lisp.rpc:*rpc-cookie-file* (first saved)
            bitcoin-lisp.rpc:*rpc-cookie-perms* (second saved)
            bitcoin-lisp.rpc:*rpc-threads* (third saved)
            bitcoin-lisp.rpc:*rpc-server-timeout* (fourth saved))))
  ;; Every audience maps to the mode Core documents.
  (is (eq :owner (bitcoin-lisp.rpc:parse-rpc-cookie-perms "owner")))
  (is (eq :group (bitcoin-lisp.rpc:parse-rpc-cookie-perms "GROUP")))
  (is (eq :all (bitcoin-lisp.rpc:parse-rpc-cookie-perms "all")))
  (is-false (bitcoin-lisp.rpc:parse-rpc-cookie-perms "everyone"))
  ;; Loosening who may read the cookie is loosening who may drive the RPC, so
  ;; an unrecognised audience is an error rather than a silent default.
  (dolist (bad '((("rpccookieperms" . "everyone")) (("rpcthreads" . "0"))
                 (("rpcservertimeout" . "-1"))))
    (signals error (bitcoin-lisp::apply-rpc-config-globals bad)))
  (dolist (name '("rpccookiefile" "rpccookieperms" "rpcthreads" "rpcservertimeout"))
    (is-true (bitcoin-lisp::known-config-option-p name) "~A unknown" name)
    (is-false (bitcoin-lisp::core-only-option-p name) "~A still ignored" name)))

(test notify-commands-substitute-only-shell-safe-values
  "Core replaces %s (and, for -walletnotify, %w/%b/%h) in a notify command and
runs the result through the shell (init.cpp:2014-2017, wallet.cpp:1125-1150).
The COMMAND is the operator's own, so the shell is the feature — but the
SUBSTITUTED VALUE is not necessarily, and a value containing `;` or a backtick
would be shell injection through a config option that looks inert. Every value
we substitute is a hash, a decimal height, the literal \"unconfirmed\", or a
wallet name (%VALID-WALLET-NAME-P already holds those to [A-Za-z0-9._-]), so
refusing anything outside that set costs nothing and closes the route. Core
instead shell-escapes %w and substitutes the rest raw."
  (flet ((sub (command &rest pairs)
           (bitcoin-lisp::%notify-substitute command pairs)))
    (is (equal "echo deadbeef" (sub "echo %s" (cons #\s "deadbeef"))))
    ;; Every occurrence, as ReplaceAll does.
    (is (equal "a beef b beef c" (sub "a %s b %s c" (cons #\s "beef"))))
    ;; A command with no %s is passed through untouched.
    (is (equal "touch /tmp/x" (sub "touch /tmp/x" (cons #\s "beef"))))
    ;; A lone trailing % is literal, not a truncated directive.
    (is (equal "echo 100%" (sub "echo 100%" (cons #\s "beef"))))
    ;; -walletnotify's four placeholders, including the unconfirmed forms.
    (is (equal "n beef mine unconfirmed -1"
               (sub "n %s %w %b %h"
                    (cons #\s "beef") (cons #\w "mine")
                    (cons #\b "unconfirmed") (cons #\h "-1"))))
    ;; An unlisted placeholder is left alone rather than eaten.
    (is (equal "%b" (sub "%b" (cons #\s "beef"))))
    ;; A value can never introduce a placeholder of its own: % is outside the
    ;; safe set, so the substitution is refused before the single pass that
    ;; would not have rescanned it anyway.
    (signals error (sub "x %s" (cons #\s "%w") (cons #\w "boom")))
    (dolist (bad '("dead; rm -rf /" "`id`" "$(id)" "dead beef" "" "a/b" "*" nil))
      (signals error (sub "echo %s" (cons #\s bad)))
      (signals error (sub "echo %w" (cons #\w bad))))))

(test notify-commands-reach-the-plist
  "-shutdownnotify is repeatable — Core reads it with GetArgs and joins EVERY
one (init.cpp:257-265) — while -blocknotify is a single command."
  (let ((p (bitcoin-lisp::args->start-node-plist
            '("-regtest" "-blocknotify=echo %s" "-startupnotify=touch /tmp/a"
              "-shutdownnotify=touch /tmp/b" "-shutdownnotify=touch /tmp/c")
            nil)))
    (is (equal "echo %s" (getf p :block-notify)))
    (is (equal '("touch /tmp/a") (getf p :startup-notify)))
    (is (equal '("touch /tmp/b" "touch /tmp/c") (getf p :shutdown-notify))))
  (dolist (name '("blocknotify" "startupnotify" "shutdownnotify"))
    (is-true (bitcoin-lisp::known-config-option-p name) "~A unknown" name)
    (is-false (bitcoin-lisp::core-only-option-p name) "~A still ignored" name)))

(test notify-commands-actually-run
  "A hook that is stored and never executed is the failure this repo keeps
finding, so this runs a real command and looks for its effect. -shutdownnotify
is WAITED for (Core joins), which is what makes the file observable
immediately; -blocknotify is detached, so it is polled for."
  (let* ((dir (merge-pathnames (format nil "bl-notify-~D/" (get-internal-real-time))
                               (uiop:temporary-directory)))
         (marker (merge-pathnames "ran" dir)))
    (unwind-protect
         (progn
           (ensure-directories-exist dir)
           ;; Waited: the file must exist the moment the call returns.
           (bitcoin-lisp::run-notify-command
            (format nil "touch ~A" (namestring marker)) :wait t)
           (is-true (probe-file marker) "a waited notify command did not run")
           ;; And the hash substitution reaches the command line.
           (let ((hashed (merge-pathnames "deadbeef" dir)))
             (bitcoin-lisp::run-notify-command
              (format nil "touch ~A%s" (namestring dir)) :value "deadbeef" :wait t)
             (is-true (probe-file hashed)
                      "%s was not substituted into the executed command")))
      (ignore-errors (uiop:delete-directory-tree dir :validate t
                                                    :if-does-not-exist :ignore))))
  ;; A failing hook is logged, never signalled: it must not fail whatever
  ;; triggered it.
  (is-true (bitcoin-lisp::run-notify-command "exit 1" :wait t))
  (is-false (bitcoin-lisp::run-notify-command "echo %s" :value "not hex")))

(test pid-file-is-written-and-removed
  "-pid (Core CreatePidFile/RemovePidFile, init.cpp:178-208). Asserted through
the FILE: a pid file that is computed and never written is exactly the kind of
option this repo keeps finding."
  (let ((dir (merge-pathnames (format nil "bl-pid-~D/" (get-internal-real-time))
                              (uiop:temporary-directory))))
    (unwind-protect
         (progn
           (ensure-directories-exist dir)
           ;; A relative -pid hangs off the datadir; the default name applies
           ;; when -pid is absent; an absolute path wins outright.
           (is (equal (merge-pathnames "node.pid" dir)
                      (bitcoin-lisp::pid-file-path "node.pid" dir)))
           (is (equal (merge-pathnames "bitcoin-lisp.pid" dir)
                      (bitcoin-lisp::pid-file-path nil dir)))
           (is (equal #p"/var/run/x.pid"
                      (bitcoin-lisp::pid-file-path "/var/run/x.pid" dir)))
           ;; -nopid parses to "0", which Core reads as IsArgNegated.
           (is-false (bitcoin-lisp::pid-file-path "0" dir))
           (let ((path (bitcoin-lisp::write-pid-file "node.pid" dir)))
             (is-true (probe-file path) "no pid file was written")
             (is (= (sb-posix:getpid)
                    (with-open-file (in path) (read in))))
             ;; Removal is by the path we recorded, and only for a file we
             ;; created — a second removal is a no-op, not a warning storm.
             (bitcoin-lisp::remove-pid-file)
             (is-false (probe-file path) "the pid file outlived shutdown")
             (is-false bitcoin-lisp::*pid-file-path*)
             (bitcoin-lisp::remove-pid-file))
           ;; A negated -pid writes nothing at all.
           (is-false (bitcoin-lisp::write-pid-file "0" dir))
           ;; An unwritable path is fatal, as Core's InitError is: an operator
           ;; who asked for a pid file and silently did not get one has a
           ;; supervisor that will never find this process.
           (signals error
             (bitcoin-lisp::write-pid-file "no-such-dir/deeper/x.pid" dir)))
      (setf bitcoin-lisp::*pid-file-path* nil)
      (ignore-errors (uiop:delete-directory-tree dir :validate t
                                                    :if-does-not-exist :ignore))))
  (dolist (name '("pid" "printtoconsole"))
    (is-true (bitcoin-lisp::known-config-option-p name) "~A unknown" name)
    (is-false (bitcoin-lisp::core-only-option-p name) "~A still ignored" name))
  ;; -printtoconsole reaches the plist as :console-log, and is ABSENT when not
  ;; given so START-NODE's default (on, since we never daemonize) applies.
  (is-false (getf (bitcoin-lisp::args->start-node-plist '("-printtoconsole=0"))
                  :console-log))
  (is (eq :absent (getf (bitcoin-lisp::args->start-node-plist '("-regtest"))
                        :console-log :absent))))

(test connect-disables-every-self-chosen-outbound-connection
  "-connect (Core init.cpp:777-784, 2214-2225; net.cpp:3540). The functional
test framework writes connect=0 into EVERY node's bitcoin.conf by default
(test_framework/util.py:581), so a node that parses -connect and then dials
addrman anyway is a node that cannot be tested against Core's suite at all.

Asserted through the DIALING paths, not the variable: each of the four is the
one Core's ThreadOpenConnections would have taken."
  (let ((saved-addrman bitcoin-lisp::*use-addrman-outgoing*)
        (saved-connect bitcoin-lisp::*connect-nodes*))
    (unwind-protect
         (let ((node (bitcoin-lisp::make-node :network :testnet3)))
           (setf (bitcoin-lisp::node-network-active node) t
                 (bitcoin-lisp::node-address-book node)
                 (bitcoin-lisp.networking:make-address-book))
           ;; Without -connect the node chooses its own peers.
           (setf bitcoin-lisp::*use-addrman-outgoing* t)
           (is-true (bitcoin-lisp::addrman-outgoing-enabled-p))
           ;; With it, every self-chosen path declines. replace-disconnected-peers
           ;; returning 0 is the load-bearing one: it is what would otherwise
           ;; refill the outbound set from the address book every cycle.
           (setf bitcoin-lisp::*use-addrman-outgoing* nil
                 bitcoin-lisp::*connect-nodes* '())
           (is-false (bitcoin-lisp::addrman-outgoing-enabled-p))
           (is (= 0 (bitcoin-lisp::replace-disconnected-peers node)))
           (is (= 0 (bitcoin-lisp::connect-to-peers node 8 :timeout 1)))
           ;; No block-relay slot is opened and no feeler is spent; both would
           ;; otherwise pick an address themselves.
           (bitcoin-lisp::maintain-block-relay-peers node)
           (bitcoin-lisp::maybe-do-feeler node)
           (is (= 0 (length (bitcoin-lisp::node-peers node)))))
      (setf bitcoin-lisp::*use-addrman-outgoing* saved-addrman
            bitcoin-lisp::*connect-nodes* saved-connect)))
  ;; The calls above return 0 for an empty address book too, so assert
  ;; STRUCTURALLY that every self-chosen dialing path consults the gate. This is
  ;; the check that goes red if a fifth path is added later without one, which
  ;; is exactly how the whole option quietly stops working.
  (dolist (caller '(bitcoin-lisp::replace-disconnected-peers
                    bitcoin-lisp::connect-to-peers
                    bitcoin-lisp::maintain-block-relay-peers
                    bitcoin-lisp::maybe-do-feeler))
    (is-true (member caller (mapcar #'car (sb-introspect:who-calls
                                          'bitcoin-lisp::addrman-outgoing-enabled-p)))
             "~A does not consult addrman-outgoing-enabled-p" caller))
  ;; And that the -connect targets are actually dialed by the maintenance loop.
  (is-true (member 'bitcoin-lisp::maintain-peers
                   (mapcar #'car (sb-introspect:who-calls
                                  'bitcoin-lisp::connect-specified-nodes))))
  ;; Every occurrence reaches the plist (Core reads -connect with GetArgs), and
  ;; -noconnect is the single "0" Core tests for.
  (let ((p (bitcoin-lisp::args->start-node-plist
            '("-regtest" "-connect=1.2.3.4" "-connect=5.6.7.8:1234") nil)))
    (is (equal '("1.2.3.4" "5.6.7.8:1234") (getf p :connect-nodes)))
    ;; Parameter interaction: -listen soft-set to 0.
    (is-false (getf p :listen)))
  (is (equal '("0") (getf (bitcoin-lisp::args->start-node-plist '("-noconnect") nil)
                          :connect-nodes)))
  (is (equal '("0") (getf (bitcoin-lisp::args->start-node-plist '("-connect=0") nil)
                          :connect-nodes)))
  ;; Soft, not forced: an explicit -listen=1 still wins, which is the whole
  ;; difference between Core's SoftSetBoolArg and a plain assignment.
  (is-true (getf (bitcoin-lisp::args->start-node-plist
                  '("-connect=1.2.3.4" "-listen=1") nil)
                 :listen))
  ;; -maxconnections=0 takes the same interaction (Core's condition is one
  ;; disjunction covering both).
  (is-false (getf (bitcoin-lisp::args->start-node-plist '("-maxconnections=0") nil)
                  :listen))
  ;; And the -dnsseed half, which lives in apply-config-globals because that is
  ;; what owns *dns-seed-enabled*.
  (let ((saved bitcoin-lisp:*dns-seed-enabled*))
    (unwind-protect
         (progn
           (setf bitcoin-lisp:*dns-seed-enabled* t)
           (bitcoin-lisp::apply-config-globals '(("connect" . "1.2.3.4")))
           (is-false bitcoin-lisp:*dns-seed-enabled*)
           (setf bitcoin-lisp:*dns-seed-enabled* t)
           (bitcoin-lisp::apply-config-globals '(("maxconnections" . "0")))
           (is-false bitcoin-lisp:*dns-seed-enabled*)
           ;; Explicit -dnsseed=1 wins over the interaction.
           (bitcoin-lisp::apply-config-globals
            '(("connect" . "1.2.3.4") ("dnsseed" . "1")))
           (is-true bitcoin-lisp:*dns-seed-enabled*))
      (setf bitcoin-lisp:*dns-seed-enabled* saved)))
  (is-true (bitcoin-lisp::known-config-option-p "connect"))
  (is-false (bitcoin-lisp::core-only-option-p "connect"))
  (is-true (member "connect" bitcoin-lisp::*repeatable-config-options*
                   :test #'string=)))

(test whitelist-and-whitebind-reach-the-node
  "-whitelist / -whitebind (Core init.cpp + net_permissions.cpp). Both are
repeatable — Core reads them with GetArgs — and a malformed spec is FATAL, as
Core's is: a typo'd range grants nothing and the operator never finds out."
  (let ((p (bitcoin-lisp::args->start-node-plist
            '("-regtest" "-whitelist=noban@10.0.0.0/8"
              "-whitelist=relay,mempool@192.168.0.0/16"
              "-whitebind=noban@127.0.0.1:1234")
            nil)))
    (is (equal '("noban@10.0.0.0/8" "relay,mempool@192.168.0.0/16")
               (getf p :whitelist)))
    (is (equal '("noban@127.0.0.1:1234") (getf p :whitebind))))
  (dolist (name '("whitelist" "whitebind" "whitelistrelay" "whitelistforcerelay"))
    (is-true (bitcoin-lisp::known-config-option-p name) "~A unknown" name)
    (is-false (bitcoin-lisp::core-only-option-p name) "~A still ignored" name))
  (dolist (name '("whitelist" "whitebind"))
    (is-true (member name bitcoin-lisp::*repeatable-config-options* :test #'string=)
             "~A is not repeatable" name))
  (let ((saved-relay bitcoin-lisp.networking::*whitelist-relay*)
        (saved-force bitcoin-lisp.networking::*whitelist-force-relay*))
    (unwind-protect
         (progn
           (bitcoin-lisp::apply-config-globals
            '(("whitelistrelay" . "0") ("whitelistforcerelay" . "1")))
           ;; -whitelistrelay defaults TRUE and -whitelistforcerelay FALSE, so
           ;; only these values prove the wiring.
           (is-false bitcoin-lisp.networking::*whitelist-relay*)
           (is-true bitcoin-lisp.networking::*whitelist-force-relay*))
      (setf bitcoin-lisp.networking::*whitelist-relay* saved-relay
            bitcoin-lisp.networking::*whitelist-force-relay* saved-force))))

(test seednode-and-forcednsseed
  "-seednode (Core connOptions.vSeedNodes, init.cpp:2212) and -forcednsseed
(DEFAULT_FORCEDNSSEED, net.h:97).

A -seednode is an ADDRESS SOURCE, not a peer: Core dials it as an ADDR_FETCH
connection and disconnects the moment it delivers more than one address. That
disconnect is the part worth pinning — without it -seednode would silently
become a second -addnode."
  ;; -seednode is repeatable and reaches the plist; -forcednsseed is a flag.
  (let ((p (bitcoin-lisp::args->start-node-plist
            '("-regtest" "-seednode=1.2.3.4" "-seednode=5.6.7.8:1234"
              "-forcednsseed=1")
            nil)))
    (is (equal '("1.2.3.4" "5.6.7.8:1234") (getf p :seednode))))
  (is-true (member "seednode" bitcoin-lisp::*repeatable-config-options*
                   :test #'string=))
  (let ((saved bitcoin-lisp::*force-dns-seed*))
    (unwind-protect
         (progn
           (bitcoin-lisp::apply-config-globals '(("forcednsseed" . "1")))
           (is-true bitcoin-lisp::*force-dns-seed*)
           (bitcoin-lisp::apply-config-globals '(("forcednsseed" . "0")))
           (is-false bitcoin-lisp::*force-dns-seed*))
      (setf bitcoin-lisp::*force-dns-seed* saved)))
  ;; The seed dial is gated on -connect exactly as Core's is by construction:
  ;; with -connect, ThreadOpenConnections never reaches the seed queue.
  (let ((saved-addrman bitcoin-lisp::*use-addrman-outgoing*)
        (saved-seeds bitcoin-lisp::*seed-nodes*))
    (unwind-protect
         (let ((node (bitcoin-lisp::make-node :network :testnet3)))
           (setf (bitcoin-lisp::node-network-active node) t
                 bitcoin-lisp::*seed-nodes* '("127.0.0.1:1")
                 bitcoin-lisp::*use-addrman-outgoing* nil)
           (bitcoin-lisp::connect-seed-nodes node)
           (is (= 0 (length (bitcoin-lisp::node-peers node))))
           ;; And it is reached from startup, not merely defined.
           (is-true (member 'bitcoin-lisp::start-node
                            (mapcar #'car
                                    (sb-introspect:who-calls
                                     'bitcoin-lisp::connect-seed-nodes)))))
      (setf bitcoin-lisp::*use-addrman-outgoing* saved-addrman
            bitcoin-lisp::*seed-nodes* saved-seeds)))
  ;; -forcednsseed does not override -dnsseed=0: a node told not to use DNS
  ;; must not be made to use it by a second flag.
  (let ((saved-force bitcoin-lisp::*force-dns-seed*)
        (saved-dns bitcoin-lisp:*dns-seed-enabled*))
    (unwind-protect
         (progn
           (bitcoin-lisp::apply-config-globals
            '(("forcednsseed" . "1") ("dnsseed" . "0")))
           (is-true bitcoin-lisp::*force-dns-seed*)
           (is-false bitcoin-lisp:*dns-seed-enabled*))
      (setf bitcoin-lisp::*force-dns-seed* saved-force
            bitcoin-lisp:*dns-seed-enabled* saved-dns)))
  (dolist (name '("seednode" "forcednsseed"))
    (is-true (bitcoin-lisp::known-config-option-p name) "~A unknown" name)
    (is-false (bitcoin-lisp::core-only-option-p name) "~A still ignored" name)))

(test maxuploadtarget-limits-what-the-node-serves
  "-maxuploadtarget (Core net.cpp:3877-3941, net_processing.cpp:2376-2383).

Core parses it with ParseByteUnits defaulting to M, so a bare number is
MEBIbytes. Reading it as bytes — the obvious mistake — would make every
ordinary command line set a target of a few hundred bytes, i.e. permanently
over budget from the first message."
  ;; ParseByteUnits: lowercase 1000-base, uppercase 1024-base, default M.
  (is (= (* 100 1024 1024) (bitcoin-lisp::conf-parse-byte-units "100")))
  ;; Core's ByteUnit::NOOP, where a bare number really is a byte count.
  (is (= 100 (bitcoin-lisp::conf-parse-byte-units "100" #\B)))
  (is (= (* 5 1000) (bitcoin-lisp::conf-parse-byte-units "5k")))
  (is (= (* 5 1024) (bitcoin-lisp::conf-parse-byte-units "5K")))
  (is (= (* 2 (expt 1000 3)) (bitcoin-lisp::conf-parse-byte-units "2g")))
  (is (= (* 2 (expt 1024 4)) (bitcoin-lisp::conf-parse-byte-units "2T")))
  (dolist (bad '("" "M" "1x" "-1" "1.5G" "one"))
    (signals error (bitcoin-lisp::conf-parse-byte-units bad)))
  (let ((saved-target bitcoin-lisp.networking::*max-upload-target*)
        (saved-start bitcoin-lisp.networking::*max-outbound-cycle-start*)
        (saved-bytes bitcoin-lisp.networking::*max-outbound-bytes-in-cycle*))
    (unwind-protect
         (progn
           ;; No target: every accessor reads as Core's disabled shape, and
           ;; nothing is ever "reached".
           (setf bitcoin-lisp.networking::*max-upload-target* 0
                 bitcoin-lisp.networking::*max-outbound-bytes-in-cycle* (* 999 1024 1024))
           (is-false (bitcoin-lisp.networking::outbound-target-reached-p nil))
           (is-false (bitcoin-lisp.networking::outbound-target-reached-p t))
           (is (= 0 (bitcoin-lisp.networking::outbound-target-bytes-left)))
           (is (= 0 (bitcoin-lisp.networking::max-outbound-time-left-in-cycle)))
           ;; A target reached by the hard limit.
           (bitcoin-lisp::apply-config-globals '(("maxuploadtarget" . "10")))
           (is (= (* 10 1024 1024) bitcoin-lisp.networking::*max-upload-target*))
           (setf bitcoin-lisp.networking::*max-outbound-cycle-start*
                 (bitcoin-lisp.serialization:get-unix-time)
                 bitcoin-lisp.networking::*max-outbound-bytes-in-cycle* 0)
           (is-false (bitcoin-lisp.networking::outbound-target-reached-p nil))
           (is (= (* 10 1024 1024)
                  (bitcoin-lisp.networking::outbound-target-bytes-left)))
           (setf bitcoin-lisp.networking::*max-outbound-bytes-in-cycle*
                 (* 10 1024 1024))
           (is-true (bitcoin-lisp.networking::outbound-target-reached-p nil))
           (is (= 0 (bitcoin-lisp.networking::outbound-target-bytes-left)))
           ;; The historical-serving limit trips FIRST and, for a target this
           ;; small, is already tripped at zero bytes sent: a full cycle's
           ;; buffer (one block per 10 minutes) exceeds 10 MiB outright, which
           ;; is Core's `buffer >= nMaxOutboundLimit` branch.
           (setf bitcoin-lisp.networking::*max-outbound-bytes-in-cycle* 0)
           (is-true (bitcoin-lisp.networking::outbound-target-reached-p t))
           ;; With a target large enough for the buffer, historical serving is
           ;; allowed again while the hard limit is far away.
           (bitcoin-lisp::apply-config-globals '(("maxuploadtarget" . "10T")))
           (is-false (bitcoin-lisp.networking::outbound-target-reached-p t))
           ;; The cycle counter rolls after 24h rather than accumulating
           ;; forever — a target that could only ever be reached once is not a
           ;; rolling budget.
           (setf bitcoin-lisp.networking::*max-outbound-bytes-in-cycle* 12345
                 bitcoin-lisp.networking::*max-outbound-cycle-start*
                 (- (bitcoin-lisp.serialization:get-unix-time) 86401))
           (bitcoin-lisp.networking::%record-outbound-cycle-bytes 7)
           (is (= 7 bitcoin-lisp.networking::*max-outbound-bytes-in-cycle*))
           ;; And accumulates within one cycle.
           (bitcoin-lisp.networking::%record-outbound-cycle-bytes 3)
           (is (= 10 bitcoin-lisp.networking::*max-outbound-bytes-in-cycle*)))
      (setf bitcoin-lisp.networking::*max-upload-target* saved-target
            bitcoin-lisp.networking::*max-outbound-cycle-start* saved-start
            bitcoin-lisp.networking::*max-outbound-bytes-in-cycle* saved-bytes)))
  ;; Every byte the node sends is counted, not just the ones a caller
  ;; remembers to count: the accounting hangs off the single send-progress
  ;; site, so this asserts the wiring rather than the arithmetic.
  (is-true (member 'bitcoin-lisp.networking::%record-send-progress
                   (mapcar #'car
                           (sb-introspect:who-calls
                            'bitcoin-lisp.networking::%record-outbound-cycle-bytes))))
  ;; And the historical-block gate is consulted where blocks are served.
  (is-true (member 'bitcoin-lisp.networking::handle-getdata
                   (mapcar #'car
                           (sb-introspect:who-calls
                            'bitcoin-lisp.networking::outbound-target-reached-p))))
  (is-true (bitcoin-lisp::known-config-option-p "maxuploadtarget"))
  (is-false (bitcoin-lisp::core-only-option-p "maxuploadtarget")))

(test p2p-config-knobs-take-effect
  "Track D's P2P group, the two options that map onto existing constants."
  (let ((saved (list bitcoin-lisp:+handshake-timeout-seconds+
                     bitcoin-lisp.networking::+max-send-buffer-bytes+)))
    (unwind-protect
         (progn
           (bitcoin-lisp::apply-config-globals
            '(("peertimeout" . "90") ("maxsendbuffer" . "2000")))
           (is (= 90 bitcoin-lisp:+handshake-timeout-seconds+))
           ;; Core's -maxsendbuffer is in KILOBYTES and it multiplies by 1000,
           ;; NOT 1024 (init.cpp:2105). Using 1024 here would silently give
           ;; every operator a 2.4% larger buffer than they asked for.
           (is (= 2000000 bitcoin-lisp.networking::+max-send-buffer-bytes+)))
      (setf bitcoin-lisp:+handshake-timeout-seconds+ (first saved)
            bitcoin-lisp.networking::+max-send-buffer-bytes+ (second saved))))
  ;; The handshake default is Core's 60, not the 30 it used to be: a peer on a
  ;; slow link that Core would keep, we dropped — and re-dialling costs more
  ;; than waiting.
  (is (= 60 bitcoin-lisp:+handshake-timeout-seconds+))
  (dolist (bad '((("peertimeout" . "0")) (("maxsendbuffer" . "-1"))
                 (("maxsendbuffer" . "x"))))
    (signals error (bitcoin-lisp::apply-config-globals bad)))
  (dolist (name '("peertimeout" "maxsendbuffer"))
    (is-true (bitcoin-lisp::known-config-option-p name) "~A unknown" name)
    (is-false (bitcoin-lisp::core-only-option-p name) "~A still ignored" name)))

(test wallet-config-knobs-take-effect
  "Track D's Wallet group, which the plan calls \"mostly knobs over existing
paths\" — and it is exactly that: every special here already existed with
Core's name and default. What was missing was the OPTION that sets it, so a
wallet could not be tuned at all.

Fee options are BTC/kvB on the command line and satoshis internally, matching
-maxtxfee and -fallbackfee, which apply-config-globals already handled."
  (let ((saved (list bitcoin-lisp.rpc::*wallet-min-tx-fee*
                     bitcoin-lisp.rpc::*wallet-discard-rate*
                     bitcoin-lisp.rpc::*wallet-consolidate-feerate*
                     bitcoin-lisp.rpc::*wallet-max-aps-fee*
                     bitcoin-lisp.rpc::*wallet-confirm-target*
                     bitcoin-lisp.rpc::*wallet-signal-rbf*
                     bitcoin-lisp.rpc::*wallet-spend-zero-conf-change*
                     bitcoin-lisp.rpc::*wallet-reject-long-chains*)))
    (unwind-protect
         (progn
           (bitcoin-lisp::apply-rpc-config-globals
            '(("mintxfee" . "0.00002") ("discardfee" . "0.0002")
              ("consolidatefeerate" . "0.0003") ("maxapsfee" . "0.0001")
              ("txconfirmtarget" . "12") ("walletrbf" . "0")
              ("spendzeroconfchange" . "0") ("walletrejectlongchains" . "0")))
           (is (= 2000 bitcoin-lisp.rpc::*wallet-min-tx-fee*))
           (is (= 20000 bitcoin-lisp.rpc::*wallet-discard-rate*))
           (is (= 30000 bitcoin-lisp.rpc::*wallet-consolidate-feerate*))
           (is (= 10000 bitcoin-lisp.rpc::*wallet-max-aps-fee*))
           (is (= 12 bitcoin-lisp.rpc::*wallet-confirm-target*))
           ;; The three booleans all default TRUE, so a test that only checked
           ;; "can be set" would pass without the option doing anything —
           ;; setting them to 0 is what proves the wiring.
           (is-false bitcoin-lisp.rpc::*wallet-signal-rbf*)
           (is-false bitcoin-lisp.rpc::*wallet-spend-zero-conf-change*)
           (is-false bitcoin-lisp.rpc::*wallet-reject-long-chains*))
      (setf bitcoin-lisp.rpc::*wallet-min-tx-fee* (first saved)
            bitcoin-lisp.rpc::*wallet-discard-rate* (second saved)
            bitcoin-lisp.rpc::*wallet-consolidate-feerate* (third saved)
            bitcoin-lisp.rpc::*wallet-max-aps-fee* (fourth saved)
            bitcoin-lisp.rpc::*wallet-confirm-target* (fifth saved)
            bitcoin-lisp.rpc::*wallet-signal-rbf* (sixth saved)
            bitcoin-lisp.rpc::*wallet-spend-zero-conf-change* (seventh saved)
            bitcoin-lisp.rpc::*wallet-reject-long-chains* (eighth saved))))
  ;; Malformed values are refused rather than silently leaving the default.
  (dolist (bad '((("mintxfee" . "notanumber")) (("txconfirmtarget" . "0"))
                 (("txconfirmtarget" . "x")) (("maxapsfee" . "zz"))))
    (signals error (bitcoin-lisp::apply-rpc-config-globals bad)))
  (dolist (name '("mintxfee" "discardfee" "consolidatefeerate" "maxapsfee"
                  "txconfirmtarget" "walletrbf" "spendzeroconfchange"
                  "walletrejectlongchains"))
    (is-true (bitcoin-lisp::known-config-option-p name) "~A unknown" name)
    (is-false (bitcoin-lisp::core-only-option-p name) "~A still ignored" name)))

(test rpc-config-keypool-and-walletdir
  "-keypool and -walletdir (Core init.cpp). Both are asserted through their
EFFECT — a freshly made wallet manager's keypool size, and the directory
WALLETS-DIRECTORY hands back — rather than through the variable, because the
keypool size is read as a struct slot DEFAULT and a test on the variable alone
would pass even if no struct ever consulted it."
  (let ((saved-keypool bitcoin-lisp.rpc::+default-keypool-size+)
        (saved-dir bitcoin-lisp.rpc::*wallet-directory*))
    (unwind-protect
         (progn
           (bitcoin-lisp::apply-rpc-config-globals '(("keypool" . "37")))
           (is (= 37 (bitcoin-lisp.rpc::wallet-manager-keypool-size
                      (bitcoin-lisp.rpc::make-wallet-manager
                       :data-directory #p"/tmp/kp/"))))
           ;; Relative -walletdir hangs off the data directory, absolute wins
           ;; outright, and NIL restores <datadir>/wallets/.
           (let ((manager (bitcoin-lisp.rpc::make-wallet-manager
                           :data-directory #p"/tmp/dd/")))
             (setf bitcoin-lisp.rpc::*wallet-directory* nil)
             (is (equal #p"/tmp/dd/wallets/"
                        (bitcoin-lisp.rpc::wallets-directory manager)))
             (bitcoin-lisp::apply-rpc-config-globals '(("walletdir" . "purses")))
             (is (equal #p"/tmp/dd/purses/"
                        (bitcoin-lisp.rpc::wallets-directory manager)))
             (bitcoin-lisp::apply-rpc-config-globals
              '(("walletdir" . "/srv/keys")))
             (is (equal #p"/srv/keys/"
                        (bitcoin-lisp.rpc::wallets-directory manager)))))
      (setf bitcoin-lisp.rpc::+default-keypool-size+ saved-keypool
            bitcoin-lisp.rpc::*wallet-directory* saved-dir)))
  ;; Core rejects -keypool=0; so do we, rather than making an unusable wallet.
  (dolist (bad '((("keypool" . "0")) (("keypool" . "-1")) (("keypool" . "x"))))
    (signals error (bitcoin-lisp::apply-rpc-config-globals bad)))
  (dolist (name '("keypool" "walletdir"))
    (is-true (bitcoin-lisp::known-config-option-p name) "~A unknown" name)
    (is-false (bitcoin-lisp::core-only-option-p name) "~A still ignored" name)))
