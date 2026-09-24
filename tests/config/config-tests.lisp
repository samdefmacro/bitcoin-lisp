(in-package #:bitcoin-lisp.tests)

(def-suite :config-tests
  :description "bitcoin.conf and CLI (-key=value) argument parsing"
  :in :bitcoin-lisp-tests)

(in-suite :config-tests)

(defun cfg (key alist) (cdr (assoc key alist :test #'string=)))

(defmacro %config-refusal (&body body)
  "The message the config-error BODY signals carries, or NIL when BODY
returns. Core's functional tests assert on the exact init error text, and so
do the tests here: (SIGNALS ERROR ...) is satisfied by any error at all,
including one raised for a different reason entirely."
  `(handler-case (progn ,@body nil)
     (bl.err:config-error (e) (princ-to-string e))))

;;; --- value coercion ---------------------------------------------------------

(test conf-parse-bool-is-core-s-interpretbool-not-a-lenient-reading
  "Core's InterpretBool is `LocaleIndependentAtoi(v) != 0` (args.cpp:57-62), and
atoi(\"true\") is 0. So the word `true` is FALSE to Bitcoin Core — as are `yes`,
`on` and every other non-numeric spelling. We accepted all of them as true and
treated anything unrecognized as true too, which is the opposite answer on a
config an operator could reasonably write: `server=true` opened a listener here
and left it closed on Core.

Only the empty string (a bare -flag) is true without being a number."
  (is-true  (bl.cfg:conf-parse-bool "1"))
  (is-true  (bl.cfg:conf-parse-bool ""))       ; bare -flag
  (is-true  (bl.cfg:conf-parse-bool "42"))
  (is-true  (bl.cfg:conf-parse-bool "-1"))     ; non-zero, so true
  (is-true  (bl.cfg:conf-parse-bool "1abc"))   ; longest integer prefix
  (is-false (bl.cfg:conf-parse-bool "0"))
  (is-false (bl.cfg:conf-parse-bool "true"))
  (is-false (bl.cfg:conf-parse-bool "YES"))
  (is-false (bl.cfg:conf-parse-bool "on"))
  (is-false (bl.cfg:conf-parse-bool "false"))
  (is-false (bl.cfg:conf-parse-bool "no"))
  (is-false (bl.cfg:conf-parse-bool "off")))

(test locale-independent-atoi-matches-core
  "The integer reading the whole config system rests on (strencodings.h:118-143):
C-locale atoi with the undefined behaviour removed."
  (is (= 0   (bl.cfg:locale-independent-atoi "true")))
  (is (= 1   (bl.cfg:locale-independent-atoi "1abc")))
  (is (= -5  (bl.cfg:locale-independent-atoi "-5")))
  (is (= 42  (bl.cfg:locale-independent-atoi "  42  ")))
  (is (= 7   (bl.cfg:locale-independent-atoi "+7")))
  (is (= 0   (bl.cfg:locale-independent-atoi "+-3")))  ; Core returns 0
  (is (= 0   (bl.cfg:locale-independent-atoi "")))
  (is (= 0   (bl.cfg:locale-independent-atoi "abc"))))

(test conf-parse-int-and-loglevel
  (is (= 2000 (bl.cfg:conf-parse-int "2000")))
  (is (= 550 (bl.cfg:conf-parse-int " 550 ")))
  (signals error (bl.cfg:conf-parse-int "notanint"))
  (is (eq :debug (bl.cfg:conf-parse-loglevel "debug")))
  (is (eq :info (bl.cfg:conf-parse-loglevel "INFO")))
  (is (eq :warn (bl.cfg:conf-parse-loglevel "warning")))
  (is (eq :error (bl.cfg:conf-parse-loglevel "error")))
  (signals error (bl.cfg:conf-parse-loglevel "verbose")))

;;; --- CLI parsing ------------------------------------------------------------

(test parse-cli-args-forms
  "CLI accepts -key=value, --key=value, bare -key (=1), and -nokey (=0)."
  (let ((a (bl.cfg:parse-cli-args
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
  (let ((a (bl.cfg:parse-cli-args '("-rpcpassword=a=b=c"))))
    (is (string= "a=b=c" (cfg "rpcpassword" a)))))

;;; --- bitcoin.conf parsing ---------------------------------------------------

(test parse-bitcoin-conf-basic
  "Comments and blank lines are skipped; key=value pairs are trimmed."
  (let ((a (bl.cfg:parse-bitcoin-conf
            (format nil "# a comment~%~%txindex=1~%  dbcache = 500  ~%"))))
    (is (string= "1" (cfg "txindex" a)))
    (is (string= "500" (cfg "dbcache" a)))))

(test parse-bitcoin-conf-network-sections
  "Section headers scope keys: only global + the matching network's section."
  (let ((text (format nil "txindex=1~%[main]~%rpcport=8888~%[test]~%rpcport=7777~%")))
    ;; Scoped to mainnet: global txindex + [main] rpcport, not [test].
    (let ((a (bl.cfg:parse-bitcoin-conf text :mainnet)))
      (is (string= "1" (cfg "txindex" a)))
      (is (string= "8888" (cfg "rpcport" a))))
    ;; Scoped to testnet3 ([test]): the [test] section's rpcport.
    (let ((a (bl.cfg:parse-bitcoin-conf text :testnet3)))
      (is (string= "7777" (cfg "rpcport" a))))
    ;; No network: sections ignored, both rpcports present (first wins on assoc).
    (let ((a (bl.cfg:parse-bitcoin-conf text nil)))
      (is (string= "8888" (cfg "rpcport" a))))))

(test the-network-section-outranks-the-global-area
  "Core's precedence is `command line > config network section > config default
section` (settings.cpp:36). We returned keys in file order and let the first
ASSOC win, so the GLOBAL value beat the section — the reverse of Core, on every
key an operator had bothered to scope. Scoping a value is a statement that it
should win; getting it backwards silently ignores the more specific setting."
  (let ((text (format nil "rpcport=7777~%[main]~%rpcport=8888~%")))
    (is (string= "8888" (cfg "rpcport" (bl.cfg:parse-bitcoin-conf text :mainnet)))))
  ;; And a global key with no section counterpart still applies.
  (let ((text (format nil "txindex=1~%[main]~%rpcport=8888~%")))
    (let ((a (bl.cfg:parse-bitcoin-conf text :mainnet)))
      (is (string= "1" (cfg "txindex" a)))
      (is (string= "8888" (cfg "rpcport" a))))))

(test a-dotted-key-is-a-section-setting-wherever-it-is-written
  "Core prefixes every config line with the current [header] and then splits the
result at its FIRST dot (config.cpp:47-56 + args.cpp:78-84), so a chain name
written into the key scopes it with no header at all —
doc/bitcoin-conf.md:44-46 documents the spelling and gives this worked example,
where `regtest.rpcport` is 3000. We handed `regtest.rpcport` to the option
lookup whole, failed it, and dropped the line with one `Ignoring unknown
configuration value` warning: a config Core reads and applies, discarded."
  (let ((text (format nil "regtest=1~%rpcport=2000~%regtest.rpcport=3000~%~
                           ~%[regtest]~%rpcport=4000~%")))
    (is (string= "3000" (cfg "rpcport" (bl.cfg:parse-bitcoin-conf text :regtest))))
    (is (= 3000 (getf (start-node-plist '() text) :rpc-port)))
    (is-false (member "regtest.rpcport" (bl:unknown-config-file-keys
                                         (bl.cfg:parse-bitcoin-conf text))
                      :test #'string=)))
  ;; The split happens BEFORE the `no` prefix is stripped (args.cpp:80-90), so a
  ;; dotted key can negate too.
  (is (string= "0" (cfg "listen" (bl.cfg:parse-bitcoin-conf
                                  (format nil "main.nolisten=1~%") :mainnet))))
  ;; Inside a section the header is the prefix, so the rest of a dotted key is
  ;; the NAME — unknown, exactly as in Core.
  (is (equal '(("main" "test.rpcport" "1" "\"1\""))
             (bl.cfg:conf-settings-rows (format nil "[main]~%test.rpcport=1~%")))))

(test conf-cannot-be-set-in-a-configuration-file
  "Core's IsConfSupported (common/config.cpp:79-83) refuses a `conf' key in a
config file, in any section and negated alike, once the whole file has parsed
(ReadConfigStream, :96-103) -- so a garbage line anywhere still reports its own
parse error first. feature_config_args.py:103-106 starts a node with
-conf=<a file holding conf=some.conf> and expects this error, not the
ignored-bitcoin.conf refusal that runs later."
  (let ((refused "Error reading configuration file: conf cannot be set in the configuration file; use includeconf= if you want to include additional config files"))
    (is (equal refused (%config-refusal (bl.cfg:conf-settings-rows (format nil "regtest=1~%conf=some.conf~%")))))
    (is (equal refused (%config-refusal (bl.cfg:conf-settings-rows (format nil "[regtest]~%conf=some.conf~%")))))
    (is (equal refused (%config-refusal (bl.cfg:conf-settings-rows (format nil "noconf=1~%")))))
    (is (equal "Error reading configuration file: parse error on line 2: garbage"
               (%config-refusal (bl.cfg:conf-settings-rows (format nil "conf=x~%garbage~%")))))
    ;; Control: includeconf is how a file names another, and is accepted.
    (is (null (%config-refusal (bl.cfg:conf-settings-rows (format nil "includeconf=other.conf~%"))))))
  ;; IsConfSupported's other arm (:84-89): reindex is accepted with Core's
  ;; warning (feature_config_args.py:128-132), and nothing else draws it.
  (let ((bl:*deferred-log-lines* nil))
    (bl.cfg:conf-settings-rows (format nil "includeconf=other.conf~%"))
    (is (null bl:*deferred-log-lines*))
    (bl.cfg:conf-settings-rows (format nil "reindex=1~%"))
    (is (equal '((:warn "reindex=1 is set in the configuration file, which will significantly slow down startup. Consider removing or commenting out this option for better performance, unless there is currently a condition which makes rebuilding the indexes necessary"))
               bl:*deferred-log-lines*))))

(test a-dotted-key-is-not-a-command-line-option
  "Core refuses any command-line key that InterpretKey split into a section:
`Invalid parameter` (args.cpp:232-237). The refusal is CHECK-CLI-ARGS' job, and
the parser must not quietly store it under the bare name either."
  (signals bl.cfg:cli-parse-error (bl.cfg:check-cli-args '("-main.rpcport=8332")))
  (is-false (bl.cfg:parse-cli-args '("-main.rpcport=8332")))
  (is (equal '(("txindex" . "1"))
             (bl.cfg:parse-cli-args '("-regtest.txindex=0" "-txindex")))))

(test an-inline-hash-comment-is-stripped
  "Core cuts the line at the first # wherever it appears (config.cpp:41-44). We
only skipped whole-line comments, so `datadir=/srv/btc  # mainnet` yielded a
datadir whose literal name contained the comment — and, because a missing
datadir was created rather than refused, that was a silent resync from genesis
into a junk directory."
  (let ((a (bl.cfg:parse-bitcoin-conf
            (format nil "datadir=/srv/btc  # mainnet~%txindex=1 # on~%"))))
    (is (string= "/srv/btc" (cfg "datadir" a)))
    (is (string= "1" (cfg "txindex" a)))))

(test a-hash-in-an-rpcpassword-is-refused-rather-than-guessed
  "The one place Core will not silently strip: it cannot tell a comment from a
password character, so it refuses the file (config.cpp:58-61). Stripping would
silently shorten the password; keeping would silently include a comment."
  (signals bl.cfg:config-parse-error
    (bl.cfg:parse-bitcoin-conf (format nil "rpcpassword=abc#def~%"))))

(test malformed-config-lines-are-refused-as-core-refuses-them
  "Core returns false from GetConfigOptions and the node does not start
(config.cpp:52-72). A config this malformed half-applying is how an operator
ends up running settings they did not write."
  ;; A leading dash: the CLI spelling, in a file.
  (signals bl.cfg:config-parse-error
    (bl.cfg:parse-bitcoin-conf (format nil "-txindex=1~%")))
  ;; A non-empty line with no '='.
  (signals bl.cfg:config-parse-error
    (bl.cfg:parse-bitcoin-conf (format nil "txindex~%")))
  ;; Core adds a hint for the negated spelling; assert it reaches the operator.
  (handler-case (bl.cfg:parse-bitcoin-conf (format nil "notxindex~%"))
    (bl.cfg:config-parse-error (e)
      (is (search "notxindex=1"
                  (bl.cfg:config-parse-error-message e))
          "the negated-option hint is missing from: ~A"
          (bl.cfg:config-parse-error-message e)))))

(test a-network-selected-inside-the-config-file-still-scopes-its-own-section
  "The network was resolved from the CLI alone and the file was then parsed
against it. So a bitcoin.conf that selects the network itself — the normal way
to run a node from a config file — left us scoping to the DEFAULT network's
section and silently dropping the whole block the operator wrote.

Core reads the chain selectors from the global area only (section=\"\",
args.cpp:825-829) and then scopes, which is what this now does."
  (let ((text (format nil "testnet4=1~%rpcport=1111~%[testnet4]~%rpcport=48332~%")))
    (multiple-value-bind (plist merged network)
        (start-node-plist '() text)
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
  (signals bl.cfg:config-parse-error
    (bl.cfg:resolve-network-from-config
     '(("chain" . "regtest") ("testnet" . "1"))))
  (signals bl.cfg:config-parse-error
    (bl.cfg:resolve-network-from-config '(("regtest" . "1") ("signet" . "1"))))
  ;; A selector explicitly turned OFF is not a selector.
  (is (eq :regtest (bl.cfg:resolve-network-from-config
                    '(("regtest" . "1") ("testnet" . "0")))))
  ;; And one selector alone still works.
  (is (eq :testnet4 (bl.cfg:resolve-network-from-config '(("testnet4" . "1"))))))

(test includeconf-merges-a-split-configuration
  "-includeconf was unimplemented: a split configuration loaded with everything
at defaults after one warning line, which on a running node is indistinguishable
from a config file that was read and understood. Core reads the includes into
the same settings map (config.cpp:162-199), so a section in an included file
outranks a global in the main one."
  (let ((main (format nil "includeconf=extra.conf~%rpcport=1111~%"))
        (extra (format nil "txindex=1~%[main]~%rpcport=8888~%")))
    (multiple-value-bind (plist merged network)
        (start-node-plist '("-chain=main") (list main extra))
      (declare (ignore plist))
      (is (eq :mainnet network))
      (is (string= "1" (cfg "txindex" merged))
          "the included file's global keys did not apply")
      (is (string= "8888" (cfg "rpcport" merged))
          "the included file's [main] section must outrank the main file's global"))))

(test includeconf-inside-an-included-file-warns-on-stderr
  "Core writes the recursive -includeconf warning to STDERR, not to the log
(common/config.cpp:212), because config files are read before debug.log exists.
Core's framework compares the WHOLE of a node's stderr against the expected
text at every stop (test_node.py:502-509), so feature_includeconf.py:59 asserts
on this sentence exactly; ours logged it, leaving stderr empty.

The text is the assertion: a warning with different wording, or one that went
somewhere else, is the same failure."
  (let ((out (with-output-to-string (s)
               (bl.cfg:warn-includeconf-from-included-file "relative2.conf" s))))
    (is (string= (format nil "warning: -includeconf cannot be used from ~
included files; ignoring -includeconf=relative2.conf~%")
                 out)))
  ;; It goes to *ERROR-OUTPUT* when no stream is named -- the whole point of
  ;; the change -- and NOT to standard output.
  (let* ((err (make-string-output-stream))
         (out (with-output-to-string (o)
                (let ((*error-output* err)
                      (*standard-output* o))
                  (bl.cfg:warn-includeconf-from-included-file "x.conf")))))
    (is (string= "" out))
    (is (search "ignoring -includeconf=x.conf" (get-output-stream-string err)))))

(test each-config-file-gets-its-own-section-scope
  "Included files are separate STREAMS in Core, so a [section] left open at the
end of one file does not carry into the next. Concatenating the texts — the
obvious way to implement includes — would silently attribute the second file's
global keys to the first file's last section."
  (let ((main (format nil "[regtest]~%rpcport=1111~%"))
        (extra (format nil "txindex=1~%")))
    (multiple-value-bind (plist merged)
        (start-node-plist '("-chain=main") (list main extra))
      (declare (ignore plist))
      (is (string= "1" (cfg "txindex" merged))
          "the second file's global key was swallowed by the first file's section")
      (is (null (cfg "rpcport" merged))
          "a [regtest] key applied while running mainnet"))))

;;; --- network resolution -----------------------------------------------------

(test resolve-network-precedence
  ;; No selector at all is MAINNET, as in Core (ArgsManager::GetChainType,
  ;; args.cpp:851); testnet3 was this node's default until 2026-09-13.
  (is (eq :mainnet (bl.cfg:resolve-network-from-config '())))
  (is (eq :testnet3 (bl.cfg:resolve-network-from-config '(("testnet" . "1")))))
  (is (= 8332 (getf (start-node-plist '("-server") nil) :rpc-port))
      "-server with no chain selector binds mainnet's RPC port, as Core does")
  (is (eq :mainnet (getf (start-node-plist '() nil) :network)))
  (is (eq :mainnet (bl.cfg:resolve-network-from-config '(("chain" . "main")))))
  (is (eq :testnet4 (bl.cfg:resolve-network-from-config '(("testnet4" . "1")))))
  (is (eq :signet (bl.cfg:resolve-network-from-config '(("signet" . "1")))))
  ;; -regtest AND -chain together is now an error, not a silent priority —
  ;; asserted in CONFLICTING-CHAIN-SELECTORS-ARE-AN-ERROR-NOT-A-SILENT-PRIORITY.
  (signals error (bl.cfg:resolve-network-from-config '(("chain" . "bogus")))))

;;; --- full plist assembly ----------------------------------------------------

(test config-alist-to-start-node-plist
  "A merged alist becomes typed start-node keyword arguments."
  (let ((plist (bl::config-alist->start-node-plist
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
  (let ((on (bl::config-alist->start-node-plist
             '(("forcecompactdb" . "1")) :mainnet))
        (off (bl::config-alist->start-node-plist
              '(("txindex" . "1")) :mainnet)))
    (is (eq t (getf on :force-compact-db)))
    (is (null (getf off :force-compact-db)))))


(test norpccookiefile-disables-the-cookie-file
  "-norpccookiefile reaches the RPC layer as the value \"0\" -- what Core makes
of -rpccookiefile=0 as well -- and GenerateAuthCookie then answers DISABLED
(rpc/request.cpp:115): no cookie file is written, InitRPCAuthentication logs
`RPC authentication cookie file generation is disabled.` and the node runs on
(httprpc.cpp:261-262); only -rpcauth users can authenticate. Ours dropped the
negation on the floor (a negated scalar has no row in the merged alist) and
wrote the cookie anyway, so rpc_users.py's test_norpccookiefile found the file
it asserted absent."
  ;; The merged alist already renders the negation as Core's "0"; the RPC
  ;; layer then read that as a cookie file NAMED 0.
  (is (equal "0" (cdr (assoc "rpccookiefile"
                             (nth-value 1 (start-node-plist '("-norpccookiefile") nil))
                             :test #'string=))))
  (let ((bl.rpc:*rpc-cookie-file* nil))
    (bl:apply-rpc-config-globals '(("rpccookiefile" . "0")))
    (is (eq :disabled bl.rpc:*rpc-cookie-file*)
        "\"0\" is the negation: no cookie file, not a file named 0")
    (bl:apply-rpc-config-globals '(("rpccookiefile" . "elsewhere.cookie")))
    (is (equal "elsewhere.cookie" bl.rpc:*rpc-cookie-file*)
        "control: a real name is still a path")))
(test config-plist-server-and-debug-shortcuts
  "-server enables RPC on the network default port; -debug => loglevel debug."
  (let ((plist (bl::config-alist->start-node-plist
                '(("server" . "1") ("debug" . "1")) :testnet3)))
    (is (= 18332 (getf plist :rpc-port)))        ; testnet3 default RPC port
    (is (eq :debug (getf plist :log-level))))
  ;; Explicit -rpcport wins over -server's default.
  (let ((plist (bl::config-alist->start-node-plist
                '(("server" . "1") ("rpcport" . "9999")) :mainnet)))
    (is (= 9999 (getf plist :rpc-port))))
  ;; Explicit -loglevel wins over -debug.
  (let ((plist (bl::config-alist->start-node-plist
                '(("debug" . "1") ("loglevel" . "warn")) :mainnet)))
    (is (eq :warn (getf plist :log-level)))))

(test cli-overrides-config-file
  "In the merged alist (CLI appended before file), assoc returns the CLI value."
  (let* ((cli (bl.cfg:parse-cli-args '("-txindex=1")))
         (conf (bl.cfg:parse-bitcoin-conf (format nil "txindex=0~%dbcache=300~%")))
         (merged (append cli conf)))
    (is (eq t (bl.cfg:conf-parse-bool (cfg "txindex" merged))))   ; CLI 1 wins
    (is (string= "300" (cfg "dbcache" merged)))))                        ; file-only key

(test args-to-start-node-plist-end-to-end
  "The full pure path: CLI + conf text -> typed start-node plist, CLI winning,
network resolved from the CLI and scoping the conf's [network] section."
  ;; CLI selects mainnet and overrides dbcache; conf provides txindex and a
  ;; [main]-scoped rpcport (a [test] rpcport must be ignored).
  (let* ((conf-text (format nil "txindex=1~%dbcache=300~%[main]~%rpcport=8888~%[test]~%rpcport=7777~%"))
         (plist (start-node-plist
                 '("-chain=main" "-dbcache=1000") conf-text)))
    (is (eq :mainnet (getf plist :network)))
    (is (eq t (getf plist :txindex)))               ; from conf
    (is (= 1000 (getf plist :dbcache-mib)))          ; CLI overrides conf's 300
    (is (= 8888 (getf plist :rpc-port))))            ; [main] section, not [test]
  ;; With no conf text, only CLI applies.
  (let ((plist (start-node-plist '("-regtest" "-txindex") nil)))
    (is (eq :regtest (getf plist :network)))
    (is (eq t (getf plist :txindex)))))

(test config-blocksonly-option
  "-blocksonly wires through to start-node's :blocksonly keyword (Core
DEFAULT_BLOCKSONLY = false: absent unless given; -noblocksonly negates)."
  (let ((plist (start-node-plist '("-regtest" "-blocksonly") nil)))
    (is (eq t (getf plist :blocksonly))))
  (let ((plist (start-node-plist '("-regtest" "-blocksonly=0") nil)))
    (is (null (getf plist :blocksonly)))
    (is-true (member :blocksonly plist)))          ; explicitly given as off
  (let ((plist (start-node-plist '("-regtest") nil)))
    (is (null (member :blocksonly plist)))))       ; default: not passed at all

(test config-apply-globals
  "apply-config-globals sets the process-global policy/consensus specials from a
merged config alist (options with no start-node keyword)."
  (let ((bl:*accept-datacarrier* t)
        (bl:*max-datacarrier-bytes* 83)
        (bl:*permit-bare-multisig* nil)
        (bl.val:*signet-challenge*
          bl.val:*default-signet-challenge*))
    (apply-config-globals
     '(("datacarrier" . "0") ("datacarriersize" . "100000")
       ("permitbaremultisig" . "1") ("signetchallenge" . "5121ff")))
    (is (eq nil bl:*accept-datacarrier*))
    (is (= 100000 bl:*max-datacarrier-bytes*))
    (is (eq t bl:*permit-bare-multisig*))
    (is (equalp (bl.crypto:hex-to-bytes "5121ff")
                bl.val:*signet-challenge*))))

(test config-cluster-limit-knobs
  "-limitclustercount/-limitclustersize set the cluster-limit specials that
make-mempool reads when creating its txgraph (cluster mempool P6); the
count is hard-capped at 64 like Core (mempool_args.cpp:110-112)."
  (let ((bl.mp:*cluster-count-limit*
          bl.mp:*cluster-count-limit*)
        (bl.mp:*cluster-size-limit*
          bl.mp:*cluster-size-limit*))
    (apply-config-globals
     '(("limitclustercount" . "32") ("limitclustersize" . "50")))
    (is (= 32 bl.mp:*cluster-count-limit*))
    (is (= 50000 bl.mp:*cluster-size-limit*))    ; kvB -> vB
    ;; A mempool created under these settings carries them in its graph -- the
    ;; count as configured, the size scaled to the graph's WEIGHT unit, as
    ;; Core's MakeTxGraph takes cluster_size_vbytes * WITNESS_SCALE_FACTOR
    ;; (txmempool.cpp:179-181).
    (let ((graph (bl.mp:mempool-graph
                  (bl.mp:make-mempool))))
      (is (= 32 (bl.mp::txgraph-max-cluster-count graph)))
      (is (= 200000 (bl.mp::txgraph-max-cluster-size graph))))
    ;; Out-of-range values are init errors.
    (signals error (apply-config-globals
                    '(("limitclustercount" . "65"))))
    (signals error (apply-config-globals
                    '(("limitclustercount" . "0"))))
    (signals error (apply-config-globals
                    '(("limitclustersize" . "0"))))))

(test config-args-returns-merged-alist
  "args->start-node-plist returns the merged config alist as a second value, so
start-node-from-args can apply the global-only options."
  (multiple-value-bind (plist merged)
      (start-node-plist '("-datacarrier=0" "-signetchallenge=5121ff"))
    (declare (ignore plist))
    (is (equal "0" (cdr (assoc "datacarrier" merged :test #'string=))))
    (is (equal "5121ff" (cdr (assoc "signetchallenge" merged :test #'string=))))))

(test a-second-signetchallenge-is-an-init-error-in-cores-words
  "Core ReadSigNetArgs (chainparams.cpp:31-40) reads -signetchallenge with
GetArgs, so EVERY occurrence counts -- two on the command line, two lines in
bitcoin.conf, or one of each -- and more than one is
`-signetchallenge cannot be multiple values.'; a value TryParseHex refuses
(util/strencodings.cpp:50-68: pairs of hex digits, whitespace between pairs
skipped) is `-signetchallenge must be hex, not '<value>'.'. Ours collapsed a
repeated value to one -- the LAST on the command line, the FIRST in a file --
and a non-hex value escaped as an ironclad error naming no option. Positive
controls: one value, from either source, still reaches the challenge."
  (flet ((apply-args (args &optional conf)
           ;; The refusal message, or the challenge the merged config applied.
           (let ((bl.val:*signet-challenge* bl.val:*default-signet-challenge*))
             (multiple-value-bind (plist merged) (start-node-plist args conf)
               (declare (ignore plist))
               (or (%config-refusal (apply-config-globals merged))
                   bl.val:*signet-challenge*)))))
    (let ((twice "-signetchallenge cannot be multiple values."))
      (is (equal twice (apply-args '("-signet" "-signetchallenge=5121ff"
                                     "-signetchallenge=5121fe"))))
      (is (equal twice (apply-args '("-signet" "-signetchallenge=5121ff")
                                   (format nil "signetchallenge=5121fe~%"))))
      (is (equal twice (apply-args '("-signet")
                                   (format nil "signetchallenge=5121ff~%~
signetchallenge=5121fe~%")))))
    (is (equal "-signetchallenge must be hex, not 'zz'."
               (apply-args '("-signet" "-signetchallenge=zz"))))
    (is (equal "-signetchallenge must be hex, not '5121f'."
               (apply-args '("-signet" "-signetchallenge=5121f"))))
    (is (equalp (bl.crypto:hex-to-bytes "5121ff")
                (apply-args '("-signet" "-signetchallenge=5121ff"))))
    (is (equalp (bl.crypto:hex-to-bytes "5121ff")
                (apply-args '("-signet") (format nil "signetchallenge=5121ff~%"))))
    ;; TryParseHex itself: whitespace between pairs is skipped, an odd digit
    ;; count and a non-hex character are refused, and the empty string is an
    ;; EMPTY script rather than a refusal.
    (is (equalp (bl.crypto:hex-to-bytes "5121ff") (bl.cfg:conf-try-parse-hex "51 21 ff")))
    (is (null (bl.cfg:conf-try-parse-hex "512")))
    (is (null (bl.cfg:conf-try-parse-hex "51zz")))
    (is (equalp #() (bl.cfg:conf-try-parse-hex "")))))

;;; --- -onlynet / -cjdnsreachable (network reachability) ----------------------

(test config-onlynet-reachability
  "-onlynet (repeatable) replaces the reachable-network set; gated nets
(onion without a proxy, i2p always, cjdns without -cjdnsreachable) drop out
of the default set; -cjdnsreachable admits cjdns."
  (let ((bl.net:*reachable-networks*
          bl.net:*reachable-networks*)
        (bl.net:*cjdns-reachable*
          bl.net:*cjdns-reachable*)
        (bl.net:*proxy* nil)
        (bl.net:*onion-proxy* nil))
    ;; Default: no -onlynet, no proxy, no flags => IP only.
    (apply-config-globals '())
    (is (equal '(:ipv4 :ipv6) bl.net:*reachable-networks*))
    (is (null bl.net:*cjdns-reachable*))
    ;; -proxy makes onion reachable (Core: onion proxy follows -proxy).
    (apply-config-globals '(("proxy" . "127.0.0.1:9050")))
    (is-true (bl.net:reachable-network-p :torv3))
    (is-false (bl.net:reachable-network-p :i2p))
    (setf bl.net:*proxy* nil
          bl.net:*onion-proxy* nil)
    ;; Repeatable -onlynet restricts the set.
    (apply-config-globals
     (bl.cfg:parse-cli-args '("-onlynet=ipv4" "-onlynet=ipv6")))
    (is (equal '(:ipv4 :ipv6) bl.net:*reachable-networks*))
    (apply-config-globals
     (bl.cfg:parse-cli-args '("-onlynet=ipv4")))
    (is (equal '(:ipv4) bl.net:*reachable-networks*))
    (is-false (bl.net:reachable-network-p :ipv6))
    ;; -cjdnsreachable admits cjdns to the default set.
    (apply-config-globals '(("cjdnsreachable" . "1")))
    (is-true bl.net:*cjdns-reachable*)
    (is-true (bl.net:reachable-network-p :cjdns))
    ;; -onlynet=onion with a proxy works; onion-only set results.
    (apply-config-globals
     (append (bl.cfg:parse-cli-args '("-onlynet=onion"))
             '(("proxy" . "127.0.0.1:9050"))))
    (is (equal '(:torv3) bl.net:*reachable-networks*))
    (setf bl.net:*proxy* nil
          bl.net:*onion-proxy* nil)))

(test config-onlynet-errors
  "Init errors, per Core: unknown -onlynet name; -onlynet=onion without ANY
Tor route (none of -proxy/-onion/-listenonion — Core init.cpp:1788-1798; a
default -listenonion is a valid route since the torcontrol client can fetch
the onion proxy from Tor itself); -onlynet=i2p (unsupported); -onlynet=cjdns
without -cjdnsreachable."
  (let ((bl.net:*reachable-networks*
          bl.net:*reachable-networks*)
        (bl.net:*cjdns-reachable*
          bl.net:*cjdns-reachable*)
        (bl.net:*onlynet-networks*
          bl.net:*onlynet-networks*)
        (bl.net:*onion-proxy-explicit* nil)
        (bl.net:*proxy* nil)
        (bl.net:*onion-proxy* nil))
    (signals error (apply-config-globals '(("onlynet" . "tor"))))
    (signals error (apply-config-globals
                    '(("onlynet" . "onion") ("listenonion" . "0"))))
    ;; With the default -listenonion, -onlynet=onion alone is legal: the
    ;; onion proxy arrives later over the torcontrol connection.
    (finishes (apply-config-globals '(("onlynet" . "onion"))))
    (signals error (apply-config-globals '(("onlynet" . "i2p"))))
    (signals error (apply-config-globals '(("onlynet" . "cjdns"))))))

(test config-dnsseed-conflict-is-reported-before-the-i2p-transport
  "Core checks an explicit -dnsseed=1 against a clearnet-free -onlynet at
init.cpp:1688-1693, long before it looks for -i2psam (:2240-2245), so
`-dnsseed=1 -onlynet=i2p' fails with the dnsseed conflict
(feature_config_args.py:336). Ours checked the I2P transport first."
  (let ((bl.net:*reachable-networks* bl.net:*reachable-networks*)
        (bl.net:*cjdns-reachable* bl.net:*cjdns-reachable*)
        (bl.net:*onlynet-networks* bl.net:*onlynet-networks*)
        (bl.net:*onion-proxy-explicit* nil)
        (bl.net:*proxy* nil)
        (bl.net:*onion-proxy* nil)
        (bl:*dns-seed-enabled* bl:*dns-seed-enabled*))
    (flet ((message (alist)
             (handler-case (progn (apply-config-globals alist) nil)
               (error (e) (princ-to-string e)))))
      (is (search "Incompatible options: -dnsseed=1 was explicitly specified"
                  (or (message '(("dnsseed" . "1") ("onlynet" . "i2p"))) "")))
      ;; Without the explicit -dnsseed=1 the I2P refusal is still the answer.
      (is (search "I2P" (or (message '(("onlynet" . "i2p"))) ""))))))

;;; --- G7-03: -onlynet clearnet exclusion must disable DNS seeding ------------
;;;
;;; A Tor-only node (-onlynet=onion) that still queries DNS seeds resolves a
;;; seed hostname in plaintext through the local resolver and then dials the
;;; returned peers over clearnet — deanonymizing itself on first start, which
;;; is precisely what -onlynet exists to prevent.

(defmacro %with-net-config-globals (&body body)
  "Run BODY with every global APPLY-CONFIG-GLOBALS mutates rebound, so these
tests cannot leak reachability or seed state into each other."
  `(let ((bl.net:*reachable-networks*
           bl.net:*reachable-networks*)
         (bl.net:*cjdns-reachable* nil)
         (bl.net:*onlynet-networks* nil)
         (bl.net:*onion-proxy-explicit* nil)
         (bl.net:*proxy* nil)
         (bl.net:*onion-proxy* nil)
         (bl:*dns-seed-enabled* t)
         (bl::*force-dns-seed* nil)
         (bl:*fixed-seeds-enabled* t)
         (bl.net:*external-ips* '())
         (bl.net:*discover* t)
         (bl:*bind-on-any* t)
         (bl:*listen-port-from-binds* nil))
     ,@body))

(defun %discover-after (&rest cli)
  "Value of -discover (bl.net:*discover*) after applying CLI."
  (%with-net-config-globals
    (apply-config-globals (bl.cfg:parse-cli-args cli))
    bl.net:*discover*))

(test discover-is-on-unless-proxy-listen-or-externalip-turn-it-off
  "Core's fDiscover defaults on (net.cpp:116, init.cpp:1578) and three
parameter interactions soft-set it off: a real -proxy (\"\" and \"0\" are none),
-listen=0, and any -externalip (init.cpp:786-819). An explicit -discover wins
over all three -- feature_bind_port_discover.py passes -discover with a -bind
and expects the bound address in localaddresses. Ours had no -discover at all:
the option was accepted and ignored, and discovery was permanently off."
  (is-true (%discover-after))
  (is-false (%discover-after "-proxy=127.0.0.1:9050"))
  (is-true (%discover-after "-proxy=0"))
  (is-false (%discover-after "-listen=0"))
  (is-false (%discover-after "-connect=1.2.3.4") "-connect turns -listen off")
  (is-false (%discover-after "-externalip=2.2.2.2"))
  (is-true (%discover-after "-externalip=2.2.2.2" "-discover"))
  (is-false (%discover-after "-discover=0")))

(defun %listen-port-from-binds-after (&rest cli)
  "Core GetListenPort's port from the bindings after applying CLI, or NIL."
  (%with-net-config-globals
    (apply-config-globals (bl.cfg:parse-cli-args cli))
    bl:*listen-port-from-binds*))

(test the-advertised-port-comes-from-a-bind-then-a-whitebind-then-port
  "Core GetListenPort (net.cpp:138-162): the first -bind with a port, else the
first -whitebind without noban, else -port. The rows are
feature_bind_port_externalip.py's EXPECTED table (NIL = -port decides), plus
the two exclusions: a noban -whitebind and an =onion -bind name no port."
  (is (null (%listen-port-from-binds-after "-port=30001")))
  (is (null (%listen-port-from-binds-after "-port=30002" "-bind=1.1.1.1")))
  (is (eql 30004 (%listen-port-from-binds-after "-port=30003" "-bind=1.1.1.1:30004")))
  (is (eql 30005 (%listen-port-from-binds-after "-bind=1.1.1.1:30005")))
  (is (eql 30017 (%listen-port-from-binds-after "-port=30016" "-bind=1.1.1.1:30017"
                                                "-whitebind=1.1.1.1:30018")))
  (is (eql 30020 (%listen-port-from-binds-after "-port=30019" "-whitebind=1.1.1.1:30020")))
  (is (null (%listen-port-from-binds-after "-port=30021" "-whitebind=noban@1.1.1.1:30022")))
  (is (null (%listen-port-from-binds-after "-bind=127.0.0.1:30023=onion")))
  ;; And GET-LISTEN-PORT falls through to -port when the bindings name none.
  (let ((bl:*listen-port-from-binds* nil)
        (bl:*p2p-port-override* 30009))
    (is (= 30009 (bl:get-listen-port :regtest))))
  (let ((bl:*listen-port-from-binds* 30020)
        (bl:*p2p-port-override* 30019))
    (is (= 30020 (bl:get-listen-port :regtest)))))

(defun %dnsseed-after (&rest cli)
  "Value of *dns-seed-enabled* after applying CLI, from a clean t default."
  (%with-net-config-globals
    (apply-config-globals (bl.cfg:parse-cli-args cli))
    bl:*dns-seed-enabled*))

(defun %interaction-lines-after (&rest cli)
  "The deferred log lines applying CLI queues."
  (let ((bl:*deferred-log-lines* nil))
    (%with-net-config-globals
      (apply-config-globals (bl.cfg:parse-cli-args cli)))
    (mapcar #'second bl:*deferred-log-lines*)))

(test connect-soft-disables-dnsseed-and-listen-in-cores-words
  "Core's -connect interaction (init.cpp:777-784) logs each soft-set that
takes: `parameter interaction: -connect or -maxconnections=0 set -> setting
-dnsseed=0' and `... -> setting -listen=0'; feature_config_args.py:400-405
waits for both under -connect=0 and -noconnect. An explicit -dnsseed or
-listen, or a -bind that soft-set -listen=1 first (:768-775), keeps its line
out; without -connect neither is said."
  (let ((dnsseed "parameter interaction: -connect or -maxconnections=0 set -> setting -dnsseed=0")
        (listen "parameter interaction: -connect or -maxconnections=0 set -> setting -listen=0"))
    (dolist (args '(("-noconnect") ("-connect=0") ("-connect=1.2.3.4") ("-maxconnections=0")))
      (let ((lines (apply #'%interaction-lines-after args)))
        (is (member dnsseed lines :test #'string=) "~A: no -dnsseed line" args)
        (is (member listen lines :test #'string=) "~A: no -listen line" args)))
    (let ((lines (%interaction-lines-after "-noconnect" "-dnsseed=1" "-bind=127.0.0.1")))
      (is-false (member dnsseed lines :test #'string=))
      (is-false (member listen lines :test #'string=)))
    (let ((lines (%interaction-lines-after "-noconnect" "-listen=1")))
      (is-false (member listen lines :test #'string=)))
    (let ((lines (%interaction-lines-after)))
      (is-false (member dnsseed lines :test #'string=))
      (is-false (member listen lines :test #'string=)))))

(defun %force-dns-seed-after (&rest cli)
  "Value of *force-dns-seed* after applying CLI, from a clean NIL default."
  (%with-net-config-globals
    (apply-config-globals (bl.cfg:parse-cli-args cli))
    bl::*force-dns-seed*))

(defun %reachable-seeds (addresses)
  "The seed ADDRESSES the dial loop may actually use under the -onlynet and
proxy settings in force. One reach for the whole file: the filter is internal
to BL -- its src caller is the seed half of the outbound refill -- and fourteen
assertions in the -onlynet tests below read it."
  (bl::%reachable-seed-addresses addresses))

(defun %config-globals-refusal (&rest cli)
  "The message APPLY-CONFIG-GLOBALS refuses CLI with, or NIL when it accepts
CLI."
  (%with-net-config-globals
    (%config-refusal (apply-config-globals (bl.cfg:parse-cli-args cli)))))

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
  (is-false (%dnsseed-after "-dnsseed=0"))
  ;; The contradiction is reported before any transport is judged, as Core
  ;; orders it (init.cpp:1688-1693 ahead of :1760-1800 and :2240):
  ;; feature_config_args.py:336 names I2P, which this node refuses on its
  ;; own account, and expects this sentence.
  (is (equal "Incompatible options: -dnsseed=1 was explicitly specified, but -onlynet forbids connections to IPv4/IPv6"
             (%config-globals-refusal "-dnsseed=1" "-onlynet=i2p" "-i2psam=127.0.0.1:7656"))))

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
         (bl.net:*proxy* nil))
    ;; Default reachable set: clearnet seeds pass through untouched.
    (let ((bl.net:*reachable-networks* '(:ipv4 :ipv6)))
      (is (equal clearnet (%reachable-seeds clearnet))))
    ;; Onion-only: every clearnet seed is dropped rather than dialed.
    (let ((bl.net:*reachable-networks* '(:torv3)))
      (is (null (%reachable-seeds clearnet)))
      (is (equal onion (%reachable-seeds onion))))
    ;; IPv4-only drops IPv6 seeds and keeps IPv4.
    (let ((bl.net:*reachable-networks* '(:ipv4)))
      (is (equal '("203.0.113.7")
                 (%reachable-seeds clearnet))))
    ;; With NO proxy an address whose network cannot be determined is dropped,
    ;; not dialed: nothing can resolve it inside a tunnel, and under an active
    ;; restriction an unclassifiable candidate is exactly what must not leak.
    (let ((bl.net:*reachable-networks* '(:ipv4 :ipv6)))
      (is (null (%reachable-seeds
                 '("seed.example.invalid" "not an address")))))))

;;; --- GA8: proxied DNS seeding (bootstrap regression, GA7 G7-03) --------------

(test reachable-seed-addresses-proxy-hostnames
  "Under -proxy the seed list is deliberately the seed HOSTNAMES, left
unresolved so the SOCKS5 proxy resolves them inside the tunnel (ATYP
DOMAINNAME) — Core's `if (HaveNameProxy()) AddAddrFetch(seed)`
(net.cpp:2356-2357), where a proxied seed stays dialable BY NAME. Dropping
every candidate parse-network-address cannot classify therefore
discarded every DNS seed of a proxied node."
  (let ((seeds (bl:network-dns-seeds :mainnet)))
    ;; The affected matrix, asserted rather than assumed: mainnet DNS seeds are
    ;; hostnames — exactly the shape the old predicate discarded — and mainnet
    ;; has no fixed-seed list to fall back on (testnet4 alone has one).
    (is-true seeds)
    (is-true (notany #'bl.net:parse-network-address seeds))
    (is-true (every #'bl.net:parse-network-address
                    (bl.chain:chain-params-fixed-seeds (bl.chain:find-chain-params :testnet4))))
    ;; -proxy with no -onlynet: discover-peers returns the hostnames verbatim
    ;; (no DNS is performed on this branch, so the test does no network I/O)
    ;; and every one must survive the filter.
    (%with-net-config-globals
      (apply-config-globals
       (bl.cfg:parse-cli-args '("-proxy=127.0.0.1:9050")))
      (let ((dns (bl.net:discover-peers seeds)))
        (is (equal seeds dns))
        (is (equal seeds (%reachable-seeds dns))))
      ;; The literal branch is untouched by the proxy: still -onlynet-filtered.
      (is (equal '("203.0.113.7")
                 (%reachable-seeds '("203.0.113.7"))))
      (let ((bl.net:*reachable-networks* '(:ipv4)))
        (is (null (%reachable-seeds '("2001:db8::1"))))))
    ;; -proxy together with a clearnet-containing -onlynet: seeding stays on
    ;; (soft-set does not fire) and the hostnames stay dialable.
    (%with-net-config-globals
      (apply-config-globals
       (bl.cfg:parse-cli-args '("-onlynet=onion" "-onlynet=ipv6"
                                       "-proxy=127.0.0.1:9050")))
      (is-true bl:*dns-seed-enabled*)
      (is (equal seeds (%reachable-seeds seeds))))))

(test reachable-seed-addresses-onion-only-no-clearnet-dial
  "G7-03 control for the change above: -onlynet=onion still yields no clearnet
dial candidate, in BOTH layers. Layer 1 — the DNS query never happens, because
an -onlynet excluding IPv4/IPv6 soft-sets -dnsseed=0 (Core init.cpp:835-844).
Layer 2 — even if a hostname reached the filter, it is a clearnet candidate
however the proxy resolves it (a DNS seed answers with A/AAAA records), so it
is dropped along with every clearnet literal."
  (let ((onion '("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"))
        (seeds (bl:network-dns-seeds :mainnet)))
    (%with-net-config-globals
      (apply-config-globals
       (bl.cfg:parse-cli-args '("-onlynet=onion" "-proxy=127.0.0.1:9050")))
      (is (equal '(:torv3) bl.net:*reachable-networks*))
      ;; Layer 1.
      (is-false bl:*dns-seed-enabled*)
      ;; Layer 2: hostnames, clearnet literals and the fixed-seed list alike.
      (is (null (%reachable-seeds seeds)))
      (is (null (%reachable-seeds
                 '("203.0.113.7" "2001:db8::1"))))
      (is (null (%reachable-seeds
                 (bl.chain:chain-params-fixed-seeds (bl.chain:find-chain-params :testnet4)))))
      ;; An onion literal is of course still dialable.
      (is (equal onion (%reachable-seeds onion))))
    ;; cjdns-only is equally clearnet-free with a proxy configured.
    (%with-net-config-globals
      (apply-config-globals
       (bl.cfg:parse-cli-args '("-onlynet=cjdns" "-cjdnsreachable=1"
                                       "-proxy=127.0.0.1:9050")))
      (is-false bl:*dns-seed-enabled*)
      (is (null (%reachable-seeds seeds))))))

;;; --- datadir layout and lifecycle (Core chainparamsbase.cpp, args.cpp:789) ---

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
  (with-temp-directory (dir)
    (is (equal dir (bl::network-data-path dir :mainnet)))
    (is (equal (merge-pathnames "testnet3/" dir)
               (bl::network-data-path dir :testnet3)))
    (is (equal (merge-pathnames "testnet4/" dir)
               (bl::network-data-path dir :testnet4)))
    (is (equal (merge-pathnames "signet/" dir)
               (bl::network-data-path dir :signet)))
    (is (equal (merge-pathnames "regtest/" dir)
               (bl::network-data-path dir :regtest)))))

(test an-existing-node-keeps-its-legacy-layout-rather-than-losing-its-chain
  "The deliberate deviation. Adopting Core's layout unconditionally would show
an EMPTY datadir to a node that has one — on mainnet that is a synced chain
discarded and IBD restarted from genesis, measured in days. So a datadir that
already holds a chainstate in the old layout keeps using it (and says so)."
  (with-temp-directory (dir)
    (%touch-chainstate (merge-pathnames "mainnet/" dir))
    (is (equal (merge-pathnames "mainnet/" dir)
               (bl::network-data-path dir :mainnet))
        "a synced mainnet node was pointed at an empty Core-layout directory")))

(test a-fresh-datadir-gets-core-s-layout-even-if-an-empty-legacy-dir-exists
  "The legacy check is for DATA, not for a directory: ensure-directories-exist
creates empty ones freely, and treating an empty mainnet/ as legacy would pin
every new node to the old layout forever."
  (with-temp-directory (dir)
    (ensure-directories-exist (merge-pathnames "mainnet/" dir))
    (is (equal dir (bl::network-data-path dir :mainnet)))))

(test core-s-layout-wins-when-both-exist
  "If the node has already been moved, the Core-layout chainstate is the live
one and the leftover legacy directory must not pull it back."
  (with-temp-directory (dir)
    (%touch-chainstate (merge-pathnames "mainnet/" dir))
    (%touch-chainstate dir)
    (is (equal dir (bl::network-data-path dir :mainnet)))))

(test a-named-datadir-that-does-not-exist-is-fatal
  "Core: CheckDataDirOption (args.cpp:789-793) refuses to start. We created it,
so a typo and an unmounted volume both presented as an empty datadir — which
means a silent full re-sync from genesis. Omitting -datadir is still fine: that
is the default path, and creating it is the intended behaviour."
  (signals bl.cfg:config-parse-error
    (bl::%check-datadir-option '(("datadir" . "/nonexistent/bl-typo-xyz"))))
  ;; No -datadir at all: not an error.
  (finishes (bl::%check-datadir-option '()))
  (with-temp-directory (dir)
    (finishes (bl::%check-datadir-option
               (list (cons "datadir" (namestring dir)))))))

(test config-rpcauth-and-rpcallowip-are-repeatable
  "-rpcauth and -rpcallowip are list options: every occurrence counts, from the
command line and from bitcoin.conf alike (Core GetArgs -> g_rpcauth,
httprpc.cpp:289; rpc_allow_subnets, httpserver.cpp:153). Collapsing them to the
last occurrence — what every non-repeatable option does here — would silently
drop all but one credential and all but one allowed subnet."
  (let ((plist (start-node-plist
                '("-regtest"
                  "-rpcauth=alice:aaaa$1111" "-rpcauth=bob:bbbb$2222"
                  "-rpcallowip=10.0.0.0/8" "-rpcallowip=192.168.1.5")
                nil)))
    (is (equal '("alice:aaaa$1111" "bob:bbbb$2222") (getf plist :rpc-auth)))
    (is (equal '("10.0.0.0/8" "192.168.1.5") (getf plist :rpc-allow-ip))))
  ;; from the config file, where the same key repeats on separate lines
  (let ((plist (start-node-plist
                '("-regtest")
                (format nil "rpcauth=alice:aaaa$1111~%rpcauth=bob:bbbb$2222~%~
rpcallowip=10.0.0.0/8~%rpcallowip=::/0~%"))))
    (is (equal '("alice:aaaa$1111" "bob:bbbb$2222") (getf plist :rpc-auth)))
    (is (equal '("10.0.0.0/8" "::/0") (getf plist :rpc-allow-ip))))
  ;; absent means absent, not an empty list that looks configured
  (let ((plist (start-node-plist '("-regtest") nil)))
    (is-false (member :rpc-auth plist))
    (is-false (member :rpc-allow-ip plist)))
  ;; and both are known options, so neither trips the unknown-option check
  (is-true (bl:known-config-option-p "rpcauth"))
  (is-true (bl:known-config-option-p "rpcallowip"))
  (is-true (bl.cfg:config-option-repeatable-p "rpcauth"))
  (is-true (bl.cfg:config-option-repeatable-p "rpcallowip")))

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
    (finishes (bl:check-cli-args (list "-regtest" option))
              "~A was rejected" option))
  ;; Accepting is not implementing: the option is reported as supplied.
  ;; -asmap and -par have both since been IMPLEMENTED, so the
  ;; duplicate-collapsing behaviour is asserted with one that is still only
  ;; accepted. That an option LEAVES this list as it gains an implementation is
  ;; the point of the list, and this assertion has now been rewritten twice for
  ;; exactly that reason.
  (is (equal '("natpmp")
             (bl.cfg:supplied-core-only-options
              '(("asmap" . "x") ("regtest" . "1")
                ("natpmp" . "1") ("natpmp" . "0")))))
  (is-false (bl.cfg:supplied-core-only-options '(("regtest" . "1"))))
  ;; And a genuinely unknown option is still a hard error.
  (signals error (bl:check-cli-args '("-notacoreoption"))))

(test cli-parse-errors-carry-cores-prefix
  "Core's bitcoind reports a command line it cannot parse as
\"Error parsing command line arguments: <detail>\" (bitcoind.cpp), and its
tests match on the PREFIX — feature_help.py asserts exactly
b'Error parsing command line arguments' on stderr after -fakearg, and never
looks at the detail. Ours said \"Invalid parameter -fakearg\" with no prefix,
so the message was right and unfindable."
  (flet ((message (args)
           (handler-case (progn (bl:check-cli-args args) nil)
             (bl:cli-parse-error (e) (princ-to-string e)))))
    (let ((m (message '("-fakearg"))))
      (is-true m "an unknown option was accepted")
      (is (eql 0 (search "Error parsing command line arguments: " m))
          "no Core prefix: ~S" m)
      (is (search "Invalid parameter -fakearg" m)
          "Core's own detail text drifted: ~S" m))
    ;; -includeconf is a config-FILE directive. Core refuses it on the command
    ;; line outright, and pins both spellings in argsman_tests.cpp:205-206.
    (is (equal (concatenate 'string
                            "Error parsing command line arguments: "
                            "-includeconf cannot be used from commandline; "
                            "-includeconf=\"\"")
               (message '("-includeconf")))
        "bare -includeconf: ~S" (message '("-includeconf")))
    (is (search "-includeconf=\"x.conf\"" (message '("-includeconf=x.conf")))
        "valued -includeconf: ~S" (message '("-includeconf=x.conf")))
    ;; The DOUBLE NEGATIVE means TRUE, and Core reports it as the JSON bool —
    ;; unquoted, unlike the string cases above. feature_includeconf.py:44-45
    ;; asserts exactly this spelling.
    (is (search "-includeconf=true" (message '("-noincludeconf=0")))
        "-noincludeconf=0: ~S" (message '("-noincludeconf=0")))
    ;; The NEGATED form stays legal — a false value CLEARS the settings span
    ;; (args.cpp:249-250), and it is how includes are suppressed from the
    ;; command line. Refusing it would break the one CLI spelling Core allows.
    (is (null (message '("-noincludeconf")))
        "-noincludeconf was refused; Core accepts it")
    (is (null (message '("-noincludeconf=1")))
        "-noincludeconf=1 was refused; it is the same suppression")))

(test valued-negation-parses-as-core-interprets-it
  "Core's InterpretKey strips a \"no\" prefix unconditionally and
InterpretValue then turns the negation into a value (common/args.cpp:105-126),
so all four spellings resolve to the same option.

The VALUED negated form was missing: a \"=\" took the branch that kept the key
as \"nolisten\", so `-nolisten=0` set an option nothing reads instead of
setting -listen. Silent both ways — the misspelled key was accepted (a
\"noKEY\" is a known option name) and the real one kept its default.

Core supports the double negative and warns about it, which is what
feature_config_args.py:232 looks for."
  (flet ((one (arg) (bl.cfg:parse-cli-args (list arg))))
    (is (equal '(("listen" . "1")) (one "-listen")))
    (is (equal '(("listen" . "1")) (one "-listen=1")))
    (is (equal '(("listen" . "0")) (one "-nolisten")))
    (is (equal '(("listen" . "0")) (one "-nolisten=1")))
    ;; The double negative: -nofoo=0 is TRUE.
    (is (equal '(("listen" . "1")) (one "-nolisten=0"))
        "-nolisten=0 must mean -listen=1")))

(test disablewallet-turns-the-wallet-off
  "Core's -disablewallet is the negation of our -wallet. 62 functional tests
run wallet-less nodes with it."
  (let ((plist (start-node-plist '("-regtest" "-disablewallet") nil)))
    (is-true (member :wallet plist) "-disablewallet did not reach :wallet")
    (is-false (getf plist :wallet))
    (is-false (member :disable-wallet plist) "the raw key leaked into start-node"))
  ;; An explicit -wallet wins, as it does in Core.
  (let ((plist (start-node-plist
                '("-regtest" "-disablewallet" "-wallet=1") nil)))
    (is-true (getf plist :wallet)))
  (let ((plist (start-node-plist '("-regtest") nil)))
    (is-false (member :disable-wallet plist))))

(test bind-option-parses-core-s-forms
  "-bind=<addr>[:<port>][=onion] (test_node.py:272-276 passes both forms). An
IPv6 literal must be bracketed for its port to be separable, exactly as in
Core — otherwise ::1 would parse as host \"\" port 1."
  (flet ((parsed (spec) (multiple-value-list (bl.cfg:parse-bind-option spec))))
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
  (let ((plist (start-node-plist
                '("-regtest" "-bind=127.0.0.1:18445") nil)))
    (is (string= "127.0.0.1" (getf plist :listen-bind)))
    (is (= 18445 (getf plist :port))))
  ;; No port on -bind leaves -port alone.
  (let ((plist (start-node-plist
                '("-regtest" "-bind=127.0.0.1" "-port=12345") nil)))
    (is (string= "127.0.0.1" (getf plist :listen-bind)))
    (is (= 12345 (getf plist :port))))
  ;; An =onion bind names the onion-service TARGET, not an address to bind:
  ;; the raw string must not survive as one (the node would try to bind
  ;; "127.0.0.1:18445=onion" as a hostname), the target must be carried
  ;; through as given (init.cpp:2141-2147), and NO ordinary listening socket
  ;; is opened at all -- bind_on_any is false as soon as any -bind is present
  ;; and vBinds is empty (init.cpp:2162). Binding 0.0.0.0 as well, which the
  ;; defaulted :LISTEN-BIND used to do, listens on a port nobody asked for;
  ;; feature_bind_extra.py:94 compares the process's sockets against exactly
  ;; what was asked for.
  (let ((plist (start-node-plist
                '("-regtest" "-bind=127.0.0.1:18445=onion") nil)))
    (is-true (member :listen-bind plist) "the key must be present and NIL")
    (is-false (getf plist :listen-bind))
    (is (equal '("127.0.0.1" . 18445) (getf plist :onion-bind))))
  ;; No port on the =onion bind: the chain's port + 1, Core's
  ;; default_bind_port_onion (init.cpp:2118).
  (let ((plist (start-node-plist '("-regtest" "-bind=127.0.0.1=onion") nil)))
    (is (equal '("127.0.0.1" . 18445) (getf plist :onion-bind))))
  ;; -rpcbind is repeatable: every value reaches the RPC server, in order
  ;; (httpserver.cpp:328-337).
  (is (equal '("127.0.0.1" "[::1]")
             (getf (start-node-plist '("-regtest" "-rpcbind=127.0.0.1" "-rpcbind=[::1]") nil)
                   :rpc-bind)))
  ;; ... and -port moves it: default_bind_port_onion is -port + 1
  ;; (init.cpp:2117-2118). feature_port.py:48 expects `Bound to
  ;; 127.0.0.1:{P+1}' from -port=P -bind=127.0.0.1=onion.
  (let ((plist (start-node-plist
                '("-regtest" "-port=12345" "-bind=127.0.0.1=onion") nil)))
    (is (equal '("127.0.0.1" . 12346) (getf plist :onion-bind))))
  ;; A plain -bind's own port is the listener's, not -port: the onion target
  ;; still follows -port.
  (let ((plist (start-node-plist
                '("-regtest" "-port=12345" "-bind=127.0.0.1:20000"
                  "-bind=127.0.0.1=onion") nil)))
    (is (= 20000 (getf plist :port)))
    (is (equal '("127.0.0.1" . 12346) (getf plist :onion-bind))))
  ;; Both forms together: the plain one binds, the =onion one is the target.
  (let ((plist (start-node-plist
                '("-regtest" "-bind=127.0.0.1:18455" "-bind=127.0.0.1:18456=onion") nil)))
    (is (string= "127.0.0.1" (getf plist :listen-bind)))
    (is (= 18455 (getf plist :port)))
    (is (equal '("127.0.0.1" . 18456) (getf plist :onion-bind))))
  ;; Repeatable: the first plain bind is used, and neither occurrence errors.
  (let ((plist (start-node-plist
                '("-regtest" "-bind=127.0.0.1:18445" "-bind=127.0.0.2:18446") nil)))
    (is (string= "127.0.0.1" (getf plist :listen-bind)))
    (is (= 18445 (getf plist :port))))
  ;; A -whitebind is bound too (Core vWhiteBinds, init.cpp:2154-2158), so an
  ;; =onion bind beside it still leaves its address listening:
  ;; p2p_permissions.py:61-66 dials exactly that address.
  (let ((plist (start-node-plist
                '("-regtest" "-whitebind=bloomfilter,forcerelay@127.0.0.1:18447"
                  "-bind=127.0.0.1:18448=onion") nil)))
    (is (string= "127.0.0.1" (getf plist :listen-bind)))
    (is (= 18447 (getf plist :port)))
    (is (equal '("127.0.0.1" . 18448) (getf plist :onion-bind))))
  ;; Two =onion binds: the first is the Tor target, and the second is bound
  ;; as well (Core binds every entry of onion_binds, CConnman::InitBinds;
  ;; p2p_getaddr_caching.py:47-51 connects to both).
  (let ((plist (start-node-plist
                '("-regtest" "-bind=127.0.0.1:18449=onion" "-bind=127.0.0.1:18450=onion") nil)))
    (is (equal '("127.0.0.1" . 18449) (getf plist :onion-bind)))
    (is (equal '(("127.0.0.1" . 18450)) (getf plist :extra-onion-binds)))))

(defun %start-node-plist-refusal (&rest args)
  "The message ARGS->START-NODE-PLIST refuses the command line ARGS with, or
NIL when it accepts it. The plist assembly is pure, so no global needs saving."
  (%config-refusal (start-node-plist args)))

(test duplicate-binding-configuration-is-an-init-error
  "Core CheckBindingConflicts (init.cpp:1271-1297) puts the whitebinds, the
plain -binds and the =onion binds into ONE set and refuses the first repeated
address:port, naming it (init.cpp:2250-2255). Two listeners on one address is
not a configuration a node can honour -- the second bind fails at the socket,
or one of the two permission sets silently wins -- so Core refuses rather than
starting half of what was asked for.

feature_bind_extra.py:99-103 asks for all six combinations of the three
options on ONE address; this covers each pair, and the positive controls are
the same options on DIFFERENT addresses."
  (let ((addr "127.0.0.1:11012")
        (other "127.0.0.1:11013"))
    (flet ((refusal (&rest args)
             (apply #'%start-node-plist-refusal "-regtest" args)))
      (dolist (pair (list (list (format nil "-bind=~A" addr) (format nil "-bind=~A" addr))
                          (list (format nil "-bind=~A" addr) (format nil "-bind=~A=onion" addr))
                          (list (format nil "-bind=~A" addr) (format nil "-whitebind=noban@~A" addr))
                          (list (format nil "-bind=~A=onion" addr) (format nil "-bind=~A=onion" addr))
                          (list (format nil "-bind=~A=onion" addr) (format nil "-whitebind=noban@~A" addr))
                          (list (format nil "-whitebind=noban@~A" addr) (format nil "-whitebind=noban@~A" addr))))
        (is (equal (format nil "Duplicate binding configuration for address ~A. ~
Please check your -bind, -bind=...=onion and -whitebind settings." addr)
                   (apply #'refusal pair))
            "~S was accepted" pair))
      ;; Positive controls: the same options on two DIFFERENT addresses are a
      ;; legitimate configuration, and so is one option alone.
      (is-false (refusal (format nil "-bind=~A" addr) (format nil "-bind=~A" other)))
      (is-false (refusal (format nil "-bind=~A" addr) (format nil "-bind=~A=onion" other)))
      (is-false (refusal (format nil "-bind=~A" addr)))
      ;; A -bind with no port takes the chain's default port, and the =onion
      ;; default is that port + 1, so the pair does NOT collide.
      (is-false (refusal "-bind=127.0.0.1" "-bind=127.0.0.1=onion"))
      ;; but two portless -binds name the same socket twice.
      (is (equal (format nil "Duplicate binding configuration for address 127.0.0.1:18444. ~
Please check your -bind, -bind=...=onion and -whitebind settings.")
                 (refusal "-bind=127.0.0.1" "-bind=127.0.0.1"))))))

(test bind-or-whitebind-with-listen-0-is-an-init-error
  "GA10 3911beba. `nUserBind != 0 && !GetBoolArg(\"-listen\", DEFAULT_LISTEN)`
=> InitError(\"Cannot set -bind or -whitebind together with -listen=0\")
(init.cpp:1016-1020), asserted by p2p_permissions.py:102.

Only an EXPLICIT -listen=0 can reach it: -bind soft-sets -listen=1 first
(init.cpp:768-775), so the pair is always something the operator asked for
twice. We used to record the bind address and start deaf on it, discarding the
-whitebind net permissions with it."
  (let ((message "Cannot set -bind or -whitebind together with -listen=0"))
    (is (string= message (%start-node-plist-refusal
                          "-regtest" "-bind=127.0.0.1" "-listen=0")))
    (is (string= message (%start-node-plist-refusal
                          "-regtest" "-bind=127.0.0.1" "-nolisten")))
    (is (string= message (%start-node-plist-refusal
                          "-regtest" "-whitebind=noban@127.0.0.1:19444" "-listen=0")))
    ;; Core sums the two lists, so either one alone is enough.
    (is (string= message (%start-node-plist-refusal
                          "-regtest" "-bind=127.0.0.1" "-whitebind=noban@127.0.0.1:19444"
                          "-listen=0")))
    ;; And it is refused BEFORE the duplicate-binding check, as in Core
    ;; (init.cpp:1016-1020 runs long before :2252): p2p_permissions.py:102
    ;; passes -bind=127.0.0.1 to a node whose bitcoin.conf already says
    ;; bind=127.0.0.1 -- the same socket twice -- and expects the -listen=0
    ;; refusal.
    (is (string= message
                 (%config-refusal
                  (start-node-plist
                   '("-regtest" "-whitebind=noban@127.0.0.1" "-bind=127.0.0.1" "-listen=0")
                   (format nil "[regtest]~%bind=127.0.0.1~%"))))))
  ;; The soft-set side is untouched: -bind still WINS over -connect and
  ;; -proxy, and a bind with no -listen at all listens.
  (is-false (%start-node-plist-refusal "-regtest" "-bind=127.0.0.1"))
  (is-true (getf (start-node-plist '("-regtest" "-bind=127.0.0.1"
                                     "-connect=1.2.3.4"))
                 :listen))
  ;; -listen=0 without a bind is an ordinary non-listening node.
  (is-false (%start-node-plist-refusal "-regtest" "-listen=0"))
  ;; A config-file bind is the same option through another source. -bind is
  ;; network-only, so off mainnet it has to be written in the [regtest]
  ;; section or a different init error refuses it first.
  (is (string= "Cannot set -bind or -whitebind together with -listen=0"
               (%config-refusal
                 (start-node-plist
                  '("-regtest")
                  (format nil "[regtest]~%bind=127.0.0.1~%listen=0~%"))))))

(test negative-maxconnections-is-an-init-error
  "GA10 32758a48. `if (user_max_connection < 0) return
InitError(\"-maxconnections must be greater or equal than zero\")`
(init.cpp:1032-1036).

Zero stays legal and keeps its meaning -- it soft-sets -listen=0 and
-dnsseed=0 (init.cpp:777-784), which is how an operator turns peer connections
off. Below zero is a typo or a mangled shell argument, and we used to clamp it:
AUTOMATIC-INBOUND-CAPACITY takes (max 0 ...), so the node started with no
inbound capacity, no listener and no DNS seeding, and nothing in the log said
why."
  (let ((message "-maxconnections must be greater or equal than zero"))
    (is (string= message (%start-node-plist-refusal "-regtest" "-maxconnections=-1")))
    (is (string= message (%start-node-plist-refusal "-regtest" "-maxconnections=-125"))))
  ;; Zero and above are accepted, and 0 still means "no peer connections".
  (is-false (%start-node-plist-refusal "-regtest" "-maxconnections=0"))
  (is-false (%start-node-plist-refusal "-regtest" "-maxconnections=125"))
  (let ((plist (start-node-plist '("-regtest" "-maxconnections=0"))))
    (is (= 0 (getf plist :max-connections)))
    (is-false (getf plist :listen)))
  (is (= 125 (getf (start-node-plist '("-regtest" "-maxconnections=125"))
                   :max-connections))))

(test log-file-defaults-to-debug-log-in-the-datadir
  "Core writes <datadir>/debug.log unless -debuglogfile says otherwise, and its
functional framework reads that file for every node it starts. We wrote no file
at all without an explicit -logfile."
  (is (string= "/data/dir/debug.log"
               (bl::%resolve-log-file nil "/data/dir/")))
  (is (string= "/data/dir/debug.log"
               (bl::%resolve-log-file nil "/data/dir")))
  ;; An explicit path wins.
  (is (string= "/tmp/custom.log"
               (bl::%resolve-log-file "/tmp/custom.log" "/data/dir/")))
  ;; -debuglogfile=0 disables it, as in Core.
  (is-false (bl::%resolve-log-file "0" "/data/dir/"))
  (is-false (bl::%resolve-log-file "" "/data/dir/"))
  ;; No datadir, no default.
  (is-false (bl::%resolve-log-file nil nil))
  ;; -debuglogfile is Core's spelling of -logfile and reaches the same key.
  (let ((plist (start-node-plist
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
               (bl::network-data-path
                (uiop:ensure-directory-pathname spelling) :regtest))
        "~S" spelling))
  ;; And the normalization start-node-from-args applies to whatever the CLI,
  ;; the config file or the default produced.
  (is (equal "/tmp/bl-datadir-test/"
             (bl::%normalize-datadir "/tmp/bl-datadir-test")))
  (is (equal "/tmp/bl-datadir-test/"
             (bl::%normalize-datadir "/tmp/bl-datadir-test/")))
  (is-false (bl::%normalize-datadir nil)))

(test executable-argv-helpers-recognise-core-s-spellings
  "-version and -help must be answered before anything is started, and the
option name has to be read the way Core's ArgsManager reads it: leading dashes
stripped, value after #\\= ignored."
  (is (equal "datadir" (bl::%argv-option-name "-datadir=/tmp/x")))
  (is (equal "datadir" (bl::%argv-option-name "--datadir=/tmp/x")))
  (is (equal "regtest" (bl::%argv-option-name "-regtest")))
  (is-false (bl::%argv-option-name "notanoption"))
  (is-false (bl::%argv-option-name ""))
  (is-true (bl::%argv-asks-for '("-regtest" "-version") '("version")))
  (is-true (bl::%argv-asks-for '("-help") '("help" "h" "?")))
  (is-true (bl::%argv-asks-for '("-?") '("help" "h" "?")))
  (is-false (bl::%argv-asks-for '("-regtest" "-datadir=/x") '("version")))
  ;; A VALUE that looks like the option name must not trigger it.
  (is-false (bl::%argv-asks-for '("-datadir=version") '("version"))))

(test testactivationheight-moves-buried-deployments
  "-testactivationheight=name@height lets a regtest chain be driven across a
buried deployment in a handful of blocks (Core chainparams.cpp:49-67). Without
it a test that wants pre-BIP66 behaviour cannot reach it at all on a chain that
activates at height 1 — which is why the plan counts this among the options
gating ~70 of Core's tests."
  (unwind-protect
       (progn
         (bl.val:apply-test-activation-heights
          '("csv@5" "segwit@7" "dersig@9" "cltv@11" "bip34@13"))
         (is (= 5 (bl.val:get-csv-activation-height :regtest)))
         (is (= 7 (bl.val:get-segwit-activation-height :regtest)))
         (is (= 9 (bl.val:get-bip66-activation-height :regtest)))
         (is (= 11 (bl.val:get-bip65-activation-height :regtest)))
         (is (= 13 (bl.val:get-bip34-activation-height :regtest)))
         ;; An untouched deployment keeps its chain default.
         (bl.val:apply-test-activation-heights '("csv@5"))
         (is (= 5 (bl.val:get-csv-activation-height :regtest)))
         (is (= 0 (bl.val:get-segwit-activation-height :regtest))))
    (bl.val:apply-test-activation-heights nil))
  ;; Cleared again, the defaults are back — an override must not outlive its run.
  (is (= 0 (bl.val:get-segwit-activation-height :regtest))))

(test testactivationheight-rejects-what-core-rejects
  "Core raises on a missing '@', a height that is not a non-negative integer,
and a name that is not a buried deployment (chainparams.cpp:51-66). Silently
ignoring a typo'd name is the worst outcome: the test then runs against the
very height it was trying to move, and passes for the wrong reason.

WHICH of the three it is matters as much as that it is one: Core checks in
that order and prints a different sentence for each, and rpc_blockchain.py:
179-190 starts a node three times to read all three back. `@5' is a NAME
refusal (its height parses) and `csv@5@6' a HEIGHT one (the field after the
FIRST '@' is `5@6')."
  (flet ((parsed (spec)
           (multiple-value-list
            (bl.val:parse-test-activation-height spec))))
    (is (equal '("csv" 5) (parsed "csv@5")))
    (is (equal '("segwit" 0) (parsed "segwit@0")))
    (dolist (row '(("csv" :format) ("" :format) (nil :format)
                   ("csv@" :height) ("csv@-1" :height) ("csv@abc" :height)
                   ("csv@5@6" :height) ("csv@2147483647" :height)
                   ("@5" :name) ("nosuch@5" :name) ("CSV@5" :name)))
      (is (equal (list nil (second row)) (parsed (first row)))
          "~S must be refused as ~S" (first row) (second row))))
  ;; Core's three sentences, verbatim (chainparams.cpp:52, :58, :65): the whole
  ;; argument in parentheses, never the half that was wrong.
  (flet ((refusal (spec)
           (handler-case (progn (bl.val:apply-test-activation-heights (list spec)) nil)
             (error (e) (princ-to-string e)))))
    (is (string= "Invalid name (name@2) for -testactivationheight=name@height."
                 (refusal "name@2")))
    (is (string= "Invalid height value (bip34@-2) for -testactivationheight=name@height."
                 (refusal "bip34@-2")))
    (is (string= "Invalid format () for -testactivationheight=name@height."
                 (refusal ""))))
  (bl.val:apply-test-activation-heights nil))

(test testactivationheight-and-mocktime-are-repeatable-options
  "-testactivationheight is a LIST option: Core reads it with GetArgs and moves
one deployment per occurrence (chainparams.cpp:49). Collapsing to the last
occurrence would silently drop every override but one."
  (let ((plist (start-node-plist
                '("-regtest" "-testactivationheight=csv@5"
                  "-testactivationheight=segwit@7" "-mocktime=1700000000")
                nil)))
    (is (equal '("csv@5" "segwit@7") (getf plist :test-activation-heights)))
    (is (= 1700000000 (getf plist :mocktime))))
  ;; Both are known options now, so neither is reported as accepted-and-ignored.
  (is-false (bl.cfg:core-only-option-p "mocktime"))
  (is-false (bl.cfg:core-only-option-p "testactivationheight"))
  (is-true (bl:known-config-option-p "mocktime"))
  (is-true (bl:known-config-option-p "testactivationheight")))

(defun %init-parameters-refusal (network txindex blockfilterindex prune
                                 dbcache-mib mocktime test-activation-heights
                                 vbparams test-options coinstatsindex
                                 txospenderindex reindex-chainstate
                                 peer-block-filters port)
  "The message %INIT-PARAMETERS refuses this start-up configuration with, or
NIL when it accepts it. The parameters are its own, in its own order, so a
signature change fails the wrong-arity gate here rather than silently shifting
a caller's arguments -- and one reach for the file, which is what the ::
ratchet asks of a second copy."
  (%config-refusal
    (bl::%init-parameters network txindex blockfilterindex prune dbcache-mib
                          mocktime test-activation-heights vbparams test-options
                          coinstatsindex txospenderindex reindex-chainstate
                          peer-block-filters port)))

(test prune-refusals-are-cores
  "An invalid -prune stops start-up in Core's words and order: first the
options a pruned node cannot serve (AppInitParameterInteraction,
init.cpp:1001-1008), then the value itself -- negative, or between 2 and 549
(ApplyArgsManOptions, node/blockmanager_args.cpp:22-33). -prune=0 is pruning
off. feature_pruning.py:118-133 asserts each sentence exactly; ours had its
own wording for every one. Two start-node tests in the pruning suite claimed
this and passed vacuously: they named the network :TESTNET, which has no
chain parameters, so start-up signalled before any prune check ran."
  (flet ((refusal (prune &key txindex txospenderindex reindex-chainstate)
           (%init-parameters-refusal :regtest txindex nil prune nil nil nil nil
                                     nil nil txospenderindex reindex-chainstate
                                     nil nil)))
    (is (equal "Prune configured below the minimum of 550 MiB.  Please use a higher number."
               (refusal 100)))
    (is (equal "Prune configured below the minimum of 550 MiB.  Please use a higher number."
               (refusal 549)))
    (is (equal "Prune cannot be configured with a negative value." (refusal -1)))
    (is (equal "Prune mode is incompatible with -txindex." (refusal 550 :txindex t)))
    (is (equal "Prune mode is incompatible with -txospenderindex."
               (refusal 550 :txospenderindex t)))
    (is (equal "Prune mode is incompatible with -reindex-chainstate. Use full -reindex instead."
               (refusal 550 :reindex-chainstate t)))
    ;; The incompatibility comes first, as Core's parameter interaction runs
    ;; before the block manager reads the value.
    (is (equal "Prune mode is incompatible with -txindex." (refusal -1 :txindex t)))
    ;; CONTROLS: manual, automatic and off are accepted. The global is put
    ;; back, since an accepted start-up assigns it.
    (let ((bl:*prune-target-mib* bl:*prune-target-mib*))
      (is (null (refusal 1)))
      (is (null (refusal 550)))
      (is (null (refusal 0)))
      (is (null bl:*prune-target-mib*) "-prune=0 is pruning off"))))

(test maxmempool-must-hold-one-cluster
  "Core refuses a -maxmempool below limits.cluster_size_vbytes * 40 -- the
size of one maximum cluster, which the pool could not otherwise admit --
and rounds the byte figure UP to whole megabytes for the message
(CTxMemPool's Flatten, txmempool.cpp:166-174). With the default 101 kvB
cluster limit that is 5 MB, and mempool_limit.py:284 starts a node with
-maxmempool=4 to read the sentence back.

The check belongs after every option has been applied, not inside either
argument's reader: -limitclustersize moves the floor, and Core makes the
comparison at mempool construction."
  (let ((bl.mp:*cluster-size-limit* 101000)
        (bl.mp:*max-mempool-bytes* (* 4 1000 1000)))
    (is (equal "-maxmempool must be at least 5 MB"
               (%init-parameters-refusal :regtest nil nil nil nil nil nil nil
                                         nil nil nil nil nil nil))))
  ;; The floor follows -limitclustersize, as Core's does.
  (let ((bl.mp:*cluster-size-limit* 300000)
        (bl.mp:*max-mempool-bytes* (* 5 1000 1000)))
    (is (equal "-maxmempool must be at least 12 MB"
               (%init-parameters-refusal :regtest nil nil nil nil nil nil nil
                                         nil nil nil nil nil nil))))
  ;; At the floor, and above it, and at zero (no cap at all), it is accepted.
  (dolist (bytes (list 0 (* 5 1000 1000) (* 300 1000 1000)))
    (let ((bl.mp:*cluster-size-limit* 101000)
          (bl.mp:*max-mempool-bytes* bytes))
      (is (null (%init-parameters-refusal :regtest nil nil nil nil nil nil nil
                                          nil nil nil nil nil nil))
          "-maxmempool=~D bytes must be accepted" bytes))))

(defun %vbparams-init (network specs)
  "The message %INIT-PARAMETERS refuses -vbparams=SPECS with on NETWORK, or
NIL when it accepts them. The override is cleared afterwards either way."
  (unwind-protect
       (%init-parameters-refusal network nil nil nil nil nil nil specs
                                 nil nil nil nil nil nil)
    (bl.val:apply-versionbits-parameters nil)))

(test vbparams-is-a-repeatable-regtest-only-option
  "-vbparams=deployment:start:end[:min_activation_height] is Core's
regtest-only BIP9 window override (chainparamsbase.cpp:22, parsed in
chainparams.cpp:69-105). Core reads it with GetArgs, so every occurrence
counts; it sat in this node's accept-and-drop table, which is a silent no-op
for a functional test that sets a deployment window and then asserts the
states that follow from it."
  (let ((plist (start-node-plist
                '("-regtest" "-vbparams=testdummy:1:2"
                  "-vbparams=taproot:3:4:5"))))
    (is (equal '("testdummy:1:2" "taproot:3:4:5") (getf plist :vbparams))))
  (is-false (bl.cfg:core-only-option-p "vbparams"))
  (is-true (bl:known-config-option-p "vbparams"))
  ;; On regtest the option is applied; anywhere else it is refused rather than
  ;; silently ignored, exactly as -testactivationheight is.
  (is (null (%vbparams-init :regtest '("testdummy:1:2"))))
  (is (equal "Version bits parameters malformed, expecting deployment:start:end[:min_activation_height]"
             (%vbparams-init :regtest '("testdummy:1"))))
  (dolist (network '(:mainnet :testnet3 :testnet4 :signet))
    (is (equal "-vbparams is for regression testing (-regtest mode) only"
               (%vbparams-init network '("testdummy:1:2")))))
  ;; And a start with no -vbparams clears an override a previous start left.
  (bl.val:apply-versionbits-parameters '("testdummy:1:2"))
  (is (null (%vbparams-init :regtest nil)))
  (is (= 0 (bl.val:vb-deployment-start-time
            (find "testdummy" (bl.val:versionbits-deployments :regtest)
                  :key #'bl.val:vb-deployment-name :test #'string=)))))

(defun %peerblockfilters-init (blockfilterindex peer-block-filters prune)
  "The message %INIT-PARAMETERS refuses this -blockfilterindex /
-peerblockfilters / -prune combination with, or NIL when it accepts it. Every
global the function assigns on its way past the gate is rebound, so a call
that gets through cannot leave a cache split or a prune target behind."
  (let ((bl.kv:*cache-sizes* bl.kv:*cache-sizes*)
        (bl::*coins-cache-budget-bytes* bl::*coins-cache-budget-bytes*)
        (bl:*prune-target-mib* bl:*prune-target-mib*)
        (bl:*p2p-port-override* bl:*p2p-port-override*))
    (%init-parameters-refusal :testnet4 nil blockfilterindex prune
                              nil nil nil nil nil nil nil nil
                              peer-block-filters nil)))

(test peerblockfilters-without-blockfilterindex-is-refused-on-any-node
  "GA10 d2099b36. Core runs the check UNCONDITIONALLY and gates the service bit
on it: `if (GetBoolArg(\"-peerblockfilters\")) { if (!filter types contain BASIC)
return InitError(...); g_local_services |= NODE_COMPACT_FILTERS; }`
(init.cpp:992-999), above and outside the -prune block at :1001-1008.
p2p_blockfilters.py:266-270 starts an UNPRUNED node to assert it.

Ours had the refusal nested inside `(when prune ...)`, so an unpruned
`-peerblockfilters=1` started happily and advertised NODE_COMPACT_FILTERS
while %CF-SERVING-INDEX returned NIL: every BIP157 client that picked us as a
filter server waited on a getcfilters that is dropped without a reply."
  (let ((message "Cannot set -peerblockfilters without -blockfilterindex."))
    ;; No -prune: the case the gate used to miss entirely.
    (is (string= message (%peerblockfilters-init nil t nil)))
    ;; With -prune: the case it did catch, still caught.
    (is (string= message (%peerblockfilters-init nil t 550))))
  ;; With the index, or without the serving flag, there is nothing to refuse --
  ;; so the assertions above are not passing on some unrelated error.
  (is-false (%peerblockfilters-init t t nil))
  (is-false (%peerblockfilters-init t t 550))
  (is-false (%peerblockfilters-init nil nil nil))
  (is-false (%peerblockfilters-init t nil nil))
  ;; And the flag really does reach that argument from a command line.
  (is-true (getf (start-node-plist '("-testnet4" "-peerblockfilters=1"))
                 :peer-block-filters)))

(test test-option-is-a-repeatable-regtest-only-switch
  "-test=<option> is a LIST option (Core reads it with GetArgs,
common/args.cpp:751), it is an ERROR off regtest (init.cpp:1109-1111) and only
a WARNING for a value the node does not know (:1117-1119) -- Core keeps
starting. It sat in the accepted-but-not-implemented list, so -test=bip94 was
silently a no-op and the BIP94 rule had no way to be turned on."
  (let ((plist (start-node-plist
                '("-regtest" "-test=bip94" "-test=nosuch") nil)))
    (is (equal '("bip94" "nosuch") (getf plist :test-options))))
  (is-false (bl.cfg:core-only-option-p "test"))
  (is-true (bl:known-config-option-p "test"))
  (unwind-protect
       (let ((bl.chain:*enforce-bip94-on-regtest* nil))
         (bl::%apply-test-options :regtest '("bip94"))
         (is-true bl.chain:*enforce-bip94-on-regtest*)
         (is-false bl.net:*deterministic-addrman*)
         ;; An unknown value warns and is otherwise ignored -- the node starts.
         ;; `addrman' is Core's third option: a deterministic address book
         ;; (addrdb.cpp:199).
         ;; The warning is Core's InitWarning (init.cpp:1118): on stderr too.
         (let ((err (make-string-output-stream)))
           (let ((*error-output* err) (bl:*deferred-log-lines* nil))
             (bl::%apply-test-options :regtest '("nosuch" "bip94" "addrman")))
           (is (equal (format nil "Warning: Unrecognised option \"nosuch\" provided in -test=<option>.~%")
                      (get-output-stream-string err))))
         (is-true bl.chain:*enforce-bip94-on-regtest*)
         (is-true bl.net:*deterministic-addrman*)
         ;; Absent, the flag is cleared: a previous run must not leak into this
         ;; one, and nothing else ever sets it back.
         (bl::%apply-test-options :regtest nil)
         (is-false bl.chain:*enforce-bip94-on-regtest*)
         (is-false bl.net:*deterministic-addrman*)
         ;; Off regtest the option is refused outright, on every other chain.
         (dolist (net '(:mainnet :testnet3 :testnet4 :signet))
           (signals error (bl::%apply-test-options net '("bip94")))))
    (setf bl.chain:*enforce-bip94-on-regtest* nil
          bl.net:*deterministic-addrman* nil)))

(test blockversion-is-a-known-option-that-sets-the-template-override
  "-blockversion is Core's forking-scenario knob (miner.cpp:141-145,
mining_basic.py:85). It was in the accepted-but-not-implemented list, so the
value was read and thrown away."
  (is-false (bl.cfg:core-only-option-p "blockversion"))
  (is-true (bl:known-config-option-p "blockversion"))
  (let ((bl.mining:*block-version-override* nil))
    (bl.cfg:apply-option-globals '(("blockversion" . "1337")))
    (is (= 1337 bl.mining:*block-version-override*))))

(defmacro %with-clean-log-categories (&body body)
  "Run BODY with every logging category off, and restore them afterwards."
  `(let ((saved (remove-if-not #'bl:log-category-enabled-p
                               bl.log:+log-categories+)))
     (unwind-protect
          (progn (bl:apply-log-categories
                  nil (copy-list bl.log:+log-categories+))
                 ,@body)
       (bl:apply-log-categories
        nil (copy-list bl.log:+log-categories+))
       (bl:apply-log-categories saved nil))))

(test debug-categories-are-applied-in-core-s-order
  "-debug enables, then -debugexclude removes (Core init/common.cpp). The order
is what lets `-debug=all -debugexclude=libevent` mean what an operator expects,
and it is the exact pair Core's own test framework passes to every node."
  (%with-clean-log-categories
    (is (equal '("mempool")
               (bl:apply-log-categories '("net" "mempool") '("net"))))
    ;; "all" and a bare -debug (empty value) enable everything.
    (dolist (spelling '("all" "1" ""))
      (bl:apply-log-categories nil (copy-list bl.log:+log-categories+))
      (is (= (length bl.log:+log-categories+)
             (length (bl:apply-log-categories (list spelling) nil)))
          "~S did not enable every category" spelling))
    ;; ...minus the exclusions, which are applied after.
    (is-false (member "libevent"
                      (bl:apply-log-categories '("all") '("libevent"))
                      :test #'string=))
    ;; "0"/"none" turn everything off, and a later include can re-enable.
    (is-false (bl:apply-log-categories '("none") nil))
    (is (equal '("rpc") (bl:apply-log-categories '("0" "rpc") nil)))))

(test unknown-debug-categories-are-refused
  "A silently-dropped -debug=nett is an operator staring at a log that will
never contain what they asked for. Core logs a warning; we refuse, because the
option has no other effect to notice."
  (%with-clean-log-categories
    (signals error (bl:apply-log-categories '("nett") nil))
    (signals error (bl:apply-log-categories nil '("nett")))
    ;; A real category is still fine either side.
    (finishes (bl:apply-log-categories '("net") '("net")))))

(test debug-option-collects-categories-and-raises-the-level
  "-debug is REPEATABLE and carries a category. The previous read was
CONF-PARSE-BOOL of its value — and atoi(\"net\") is 0 — so -debug=net set no
category AND did not raise the level: it did nothing whatsoever."
  (let ((plist (start-node-plist
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
  (let ((plist (start-node-plist '("-regtest" "-debug") nil)))
    (is (equal '("1") (getf plist :debug-categories)))
    (is (eq :debug (getf plist :log-level))))
  ;; -debug=0 must NOT raise the level: that spelling turns logging off.
  (let ((plist (start-node-plist '("-regtest" "-debug=0") nil)))
    (is-false (eq :debug (getf plist :log-level))))
  ;; An explicit -loglevel wins.
  (let ((plist (start-node-plist
                '("-regtest" "-debug=net" "-loglevel=info") nil)))
    (is (eq :info (getf plist :log-level)))))

(test log-format-flags-change-the-line
  "-logtimemicros appends a microsecond fraction and -logthreadnames inserts
the writing thread's name, as Core does. Asserted on the formatted line rather
than on the flags, since the flag existing is not the feature."
  (let ((plain (let ((bl.log:*log-time-micros* nil)
                     (bl.log:*log-thread-names* nil))
                 (bl.log::format-log-entry :info "hello ~A" '(1)))))
    ;; No level tag: Core prints none on an uncategorized info line
    ;; (BCLog::LogPrefix). The message follows the timestamp directly.
    (is-true (search "] hello 1" plain))
    (is-false (search "INFO" plain))
    ;; [YYYY-MM-DD HH:MM:SS] with no fraction
    (is-false (search "." (subseq plain 0 (1+ (position #\] plain))))))
  (let ((micros (let ((bl.log:*log-time-micros* t)
                      (bl.log:*log-thread-names* nil))
                  (bl.log::format-log-entry :info "hello" '()))))
    (is-true (find #\. (subseq micros 0 (1+ (position #\] micros))))
             "no microsecond fraction in ~S" micros))
  (let ((named (let ((bl.log:*log-time-micros* nil)
                     (bl.log:*log-thread-names* t))
                 (bl.log::format-log-entry :info "hello" '()))))
    ;; A second bracketed field appears after the timestamp. Two, not three:
    ;; an info line carries no level tag of its own.
    (is (= 2 (count #\[ named)) "thread name missing from ~S" named))
  ;; And with a level that DOES print a tag, the thread name sits between the
  ;; timestamp and it — Core's order.
  (let ((named-warn (let ((bl.log:*log-time-micros* nil)
                          (bl.log:*log-thread-names* t))
                      (bl.log::format-log-entry :warn "hello" '()))))
    (is (= 3 (count #\[ named-warn)) "expected timestamp, thread and level in ~S"
        named-warn)
    (is-true (search "[warning] hello" named-warn))))

(test logips-is-a-real-option-now
  "GA11 559c86ad. `logips' was a DEFINE-CORE-ONLY-OPTIONS row: accepted, named
once in the startup warning, never read -- so -logips=0 could not turn off
what -logips=1 could not turn on, and the addresses were in the log either way.
Core reads it with GetBoolArg and DEFAULT_LOGIPS is false (logging.h:28,
init/common.cpp:57), which is the DEFAULT the node has to reproduce.

A :KEY row rather than a :GLOBAL one: a :GLOBAL row is assigned only when the
option is present, and this flag must return to its default on every start."
  (multiple-value-bind (plist merged) (start-node-plist '("-regtest" "-logips=1"))
    ;; It reaches START-NODE, and it is no longer reported as merely accepted.
    (is (eq t (getf plist :log-ips)))
    (is (null (bl.cfg:supplied-core-only-options merged))))
  ;; -logips=0 is now a real off switch rather than an ignored string.
  (is (eq nil (getf (start-node-plist '("-regtest" "-logips=0")) :log-ips)))
  ;; And the default is off, which is the whole privacy model.
  (is (eq nil (getf (start-node-plist '("-regtest")) :log-ips))))

(test log-ip-is-cores-peeraddr-field
  "Core CNode::LogIP (net.cpp:704-707) is \" peeraddr=<addr>\" or \"\", with the
leading space, so a caller appends it to a line already ending in peer=<id> and
gets Core's spacing either way. NIL -- a peer reaped before its address was
recorded -- is the empty string too, never \" peeraddr=NIL\"."
  (let ((bl.log:*log-ips* nil))
    (is (string= "" (bl.log:log-ip "203.0.113.77:8333")))
    (is (string= "" (bl.log:log-ip nil))))
  (let ((bl.log:*log-ips* t))
    (is (string= " peeraddr=203.0.113.77:8333"
                 (bl.log:log-ip "203.0.113.77:8333")))
    (is (string= "" (bl.log:log-ip nil)))))

(test relay-policy-knobs-take-effect
  "-dustrelayfee, -incrementalrelayfee and -bytespersigop are relay POLICY, not
consensus, and Core exposes all three. Ours were compiled-in constants, so a
node could not be tuned at all — and two of them were DEFCONSTANTs, which in
this image means the value is folded into every caller and cannot be changed
even at the REPL without a restart.

Fee rates arrive as BTC/kvB on the command line, as every other Core fee option
does, and are stored as satoshis."
  (let ((saved (list bl.val:*dust-relay-fee-rate*
                     bl.mp:*incremental-relay-fee-rate*
                     bl.mp:*bytes-per-sigop*)))
    (unwind-protect
         (progn
           (apply-config-globals
            '(("dustrelayfee" . "0.00004")
              ("incrementalrelayfee" . "0.00002")
              ("bytespersigop" . "40")))
           (is (= 4000 bl.val:*dust-relay-fee-rate*))
           (is (= 2000 bl.mp:*incremental-relay-fee-rate*))
           (is (= 40 bl.mp:*bytes-per-sigop*))
           ;; And the sigop-adjusted size actually uses the new value, which is
           ;; the point — a knob nothing reads is the failure this repo keeps
           ;; finding.
           (is (= (ceiling (* 3 40) 4)
                  (bl.mp:sigop-adjusted-vsize 1 3))))
      (setf bl.val:*dust-relay-fee-rate* (first saved)
            bl.mp:*incremental-relay-fee-rate* (second saved)
            bl.mp:*bytes-per-sigop* (third saved))))
  ;; Malformed values are refused, not silently ignored.
  (dolist (bad '((("dustrelayfee" . "notanumber"))
                 (("incrementalrelayfee" . "x"))
                 (("bytespersigop" . "0"))
                 (("bytespersigop" . "-1"))))
    (signals error (apply-config-globals bad)))
  ;; All three are known options and no longer reported as ignored.
  (dolist (name '("dustrelayfee" "incrementalrelayfee" "bytespersigop"))
    (is-true (bl:known-config-option-p name) "~A unknown" name)
    (is-false (bl.cfg:core-only-option-p name) "~A still ignored" name)))

(test validation-resource-knobs-take-effect
  "Track D's Validation & resources group over knobs that already existed as
constants. Each asserts the EFFECT, not the assignment."
  (let ((saved (list bl.net:*max-tip-age-seconds*
                     bl.interop:*signature-cache-max-entries*
                     bl.store:*fast-prune*
                     bl.store:*blocks-xor*)))
    (unwind-protect
         (progn
           (apply-config-globals
            '(("maxtipage" . "3600") ("maxsigcachesize" . "4")
              ("fastprune" . "1") ("blocksxor" . "0")))
           ;; -maxtipage: how old the tip may be before the node still calls
           ;; itself in IBD (Core DEFAULT_MAX_TIP_AGE).
           (is (= 3600 bl.net:*max-tip-age-seconds*))
           ;; -maxsigcachesize is MiB; a cache entry is a 32-byte key, which is
           ;; what Core's CuckooCache element is too.
           (is (= (floor (* 4 1024 1024) 32)
                  bl.interop:*signature-cache-max-entries*))
           ;; -fastprune changes the ROLLOVER threshold, which is the whole
           ;; point: 64 KiB instead of 128 MiB (blockstorage.cpp:858).
           (is-true bl.store:*fast-prune*)
           (is (= bl.kv::+fast-prune-blockfile-size+
                  (bl.store:max-blockfile-size 100)))
           ;; ...and Core raises it past a record that would not otherwise fit,
           ;; because a block that fits in NO file could never be written.
           (is (= (1+ (* 200 1024))
                  (bl.store:max-blockfile-size (* 200 1024))))
           (is-false bl.store:*blocks-xor*))
      (setf bl.net:*max-tip-age-seconds* (first saved)
            bl.interop:*signature-cache-max-entries* (second saved)
            bl.store:*fast-prune* (third saved)
            bl.store:*blocks-xor* (fourth saved))))
  ;; Default: the full 128 MiB rollover.
  (is (= bl.kv:+max-blockfile-size+
         (bl.store:max-blockfile-size 100)))
  ;; Malformed values are refused.
  (dolist (bad '((("maxtipage" . "-1")) (("maxsigcachesize" . "0"))
                 (("maxsigcachesize" . "x"))))
    (signals error (apply-config-globals bad)))
  ;; All four are known and no longer reported as ignored.
  (dolist (name '("maxtipage" "maxsigcachesize" "fastprune" "blocksxor"))
    (is-true (bl:known-config-option-p name) "~A unknown" name)
    (is-false (bl.cfg:core-only-option-p name) "~A still ignored" name)))

(test rpc-http-config-knobs-take-effect
  "Track D's RPC/HTTP group. Applied by APPLY-RPC-CONFIG-GLOBALS rather than
its sibling for a load-order reason worth knowing: config.lisp compiles BEFORE
src/rpc/package.lisp, so a package-qualified reference to BITCOIN-LISP.RPC
there is a READ error, not a link error."
  (let ((saved (list bl.rpc:*rpc-cookie-file*
                     bl.rpc:*rpc-cookie-perms*
                     bl.rpc:*rpc-threads*
                     bl.rpc:*rpc-server-timeout*)))
    (unwind-protect
         (progn
           (bl:apply-rpc-config-globals
            '(("rpccookiefile" . "/tmp/x.cookie") ("rpccookieperms" . "group")
              ("rpcthreads" . "8") ("rpcservertimeout" . "45")))
           (is (equal "/tmp/x.cookie" bl.rpc:*rpc-cookie-file*))
           (is (eq :group bl.rpc:*rpc-cookie-perms*))
           (is (= 8 bl.rpc:*rpc-threads*))
           (is (= 45 bl.rpc:*rpc-server-timeout*))
           ;; The perms name reaches an actual MODE — 0640 for group.
           (is (= #o640 (bl.rpc::%cookie-file-mode)))
           ;; An absolute -rpccookiefile is used as given...
           (is (equal "/tmp/x.cookie"
                      (namestring (bl.rpc::rpc-cookie-path "/data/dir/"))))
           ;; ...and a relative one hangs off the data directory, which is what
           ;; Core means by "prefixed by a net-specific datadir location".
           (setf bl.rpc:*rpc-cookie-file* "sub/my.cookie")
           (is (equal "/data/dir/sub/my.cookie"
                      (namestring (bl.rpc::rpc-cookie-path "/data/dir/"))))
           ;; Unset, it is the datadir's .cookie.
           (setf bl.rpc:*rpc-cookie-file* nil)
           (is (equal "/data/dir/.cookie"
                      (namestring (bl.rpc::rpc-cookie-path "/data/dir/"))))
           ;; 0 means no timeout, as in Core.
           (bl:apply-rpc-config-globals '(("rpcservertimeout" . "0")))
           (is-false bl.rpc:*rpc-server-timeout*))
      (setf bl.rpc:*rpc-cookie-file* (first saved)
            bl.rpc:*rpc-cookie-perms* (second saved)
            bl.rpc:*rpc-threads* (third saved)
            bl.rpc:*rpc-server-timeout* (fourth saved))))
  ;; Every audience maps to the mode Core documents.
  (is (eq :owner (bl.rpc:parse-rpc-cookie-perms "owner")))
  (is (eq :group (bl.rpc:parse-rpc-cookie-perms "GROUP")))
  (is (eq :all (bl.rpc:parse-rpc-cookie-perms "all")))
  (is-false (bl.rpc:parse-rpc-cookie-perms "everyone"))
  ;; Loosening who may read the cookie is loosening who may drive the RPC, so
  ;; an unrecognised audience is an error rather than a silent default.
  (dolist (bad '((("rpccookieperms" . "everyone"))
                 (("rpcservertimeout" . "-1"))))
    (signals error (bl:apply-rpc-config-globals bad)))
  (dolist (name '("rpccookiefile" "rpccookieperms" "rpcthreads" "rpcservertimeout"))
    (is-true (bl:known-config-option-p name) "~A unknown" name)
    (is-false (bl.cfg:core-only-option-p name) "~A still ignored" name)))

(test rpcthreads-and-rpcworkqueue-are-at-least-one-never-an-error
  "Core reads -rpcthreads and -rpcworkqueue as
std::max(gArgs.GetArg(name, DEFAULT), 1) (httpserver.cpp:419, :440), and
GetArg's integer is LocaleIndependentAtoi: `0', `-3' and `abc' start the HTTP
server with one worker or a queue of one, and nothing is an init error. We
refused -rpcthreads=0 with an error of our own (a test pinned it), and
-rpcworkqueue was accepted and ignored. Absent, each takes Core's default:
DEFAULT_HTTP_THREADS 16 and DEFAULT_HTTP_WORKQUEUE 64 (httpserver.h:20, :26)."
  (let ((saved-threads bl.rpc:*rpc-threads*)
        (saved-queue bl.rpc:*rpc-work-queue*))
    (flet ((threads-for (value)
             (handler-case
                 (progn (bl:apply-rpc-config-globals (list (cons "rpcthreads" value)))
                        bl.rpc:*rpc-threads*)
               (error (e) (format nil "refused: ~A" e))))
           (queue-for (value)
             (handler-case
                 (progn (bl:apply-rpc-config-globals (list (cons "rpcworkqueue" value)))
                        bl.rpc:*rpc-work-queue*)
               (error (e) (format nil "refused: ~A" e)))))
      (unwind-protect
           (progn
             (is (eql 8 (threads-for "8")))
             (dolist (value '("0" "-3" "abc"))
               (is (eql 1 (threads-for value))
                   "-rpcthreads=~A is Core's max(atoi, 1) = 1" value))
             (is (eql 5 (queue-for "5")))
             (dolist (value '("0" "-1" "x"))
               (is (eql 1 (queue-for value))
                   "-rpcworkqueue=~A is Core's max(atoi, 1) = 1" value))
             (bl:apply-rpc-config-globals '())
             (is (eql 16 bl.rpc:*rpc-threads*) "Core DEFAULT_HTTP_THREADS")
             (is (eql 64 bl.rpc:*rpc-work-queue*) "Core DEFAULT_HTTP_WORKQUEUE")
             (is-true (bl:known-config-option-p "rpcworkqueue"))
             (is-false (bl.cfg:core-only-option-p "rpcworkqueue")
                       "-rpcworkqueue is still accepted and ignored"))
        (setf bl.rpc:*rpc-threads* saved-threads
              bl.rpc:*rpc-work-queue* saved-queue)))))

(test notify-commands-shell-escape-a-value-that-is-not-plain
  "Core replaces %s (and, for -walletnotify, %w/%b/%h) in a notify command and
runs the result through the shell (init.cpp:2014-2017, wallet.cpp:1125-1150).
The COMMAND is the operator's own, so the shell is the feature; the SUBSTITUTED
VALUE is not, and a value carrying `;` or a backtick would be shell injection
through a config option that looks inert. Core's answer is ShellEscape
(common/system.cpp:41-46) on %w -- single quotes, with an embedded quote
written as '\\\"'\\\"' -- and a raw substitution for the rest, whose values are
only ever hex, digits or the literal \"unconfirmed\".

Ours REFUSED anything outside [A-Za-z0-9._-], on the stated grounds that a
wallet name is held to that set too. It is not: the node's wallet-name rules
admit a great deal more, and feature_notifications.py:43 creates a wallet named
after every character from 1 to 127 and then waits for one -walletnotify file
per transaction. It got none, and the log carried one `Refusing to substitute'
line per block. Core's default wallet name -- the EMPTY string -- was refused
by the same rule.

A NUL is still refused: the command reaches /bin/sh as one argv element, which
ends at the first NUL, so substituting one would silently truncate the
operator's command."
  (flet ((sub (command &rest pairs)
           (bl.log::%notify-substitute command pairs)))
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
    ;; ShellEscape, in Core's own spelling.
    (is (equal "echo 'a b'" (sub "echo %w" (cons #\w "a b"))))
    (is (equal "echo 'it'\"'\"'s'" (sub "echo %w" (cons #\w "it's"))))
    ;; Core's default wallet name is the empty string, and it escapes to ''.
    (is (equal "echo ''" (sub "echo %w" (cons #\w ""))))
    ;; Every shape that used to be refused is now one quoted word.
    (dolist (nasty '("dead; rm -rf /" "`id`" "$(id)" "dead beef" "a/b" "*"))
      (is (equal (format nil "echo '~A'" nasty) (sub "echo %w" (cons #\w nasty)))
          "~S was not escaped as one word" nasty))
    ;; A value can never introduce a placeholder of its own -- the pass is
    ;; single, and the quoting keeps the % out of the shell's hands too.
    (is (equal "x '%w'" (sub "x %s" (cons #\s "%w") (cons #\w "boom"))))
    ;; A NUL, and a non-string, are still refused.
    (signals error (sub "echo %s" (cons #\s (format nil "a~Cb" (code-char 0)))))
    (signals error (sub "echo %s" (cons #\s nil)))))

(test a-notify-value-with-shell-syntax-runs-as-one-argument
  "The end of the escaping: a value carrying shell syntax must reach the
operator's command as ONE word and must not run anything of its own. Core's
own -walletnotify test names its wallet after every character from 1 to 127 and
then requires a file named `<wallet>_<txid>', which only a correctly escaped
and then quote-removed substitution can produce."
  (let* ((dir (merge-pathnames (format nil "bl-esc-~D/" (get-internal-real-time))
                               (uiop:temporary-directory)))
         (nasty "a b';touch PWNED;'c"))
    (unwind-protect
         (progn
           (ensure-directories-exist dir)
           ;; The value names the file: it must land under its LITERAL text.
           (bl.log:run-notify-command
            (format nil "touch ~A%w" (namestring dir))
            :substitutions (list (cons #\w nasty)) :wait t)
           (is-true (probe-file (merge-pathnames nasty dir))
                    "the escaped value did not reach the command as one word")
           ;; And its shell syntax ran nothing: no PWNED anywhere.
           (is (null (probe-file (merge-pathnames "PWNED" dir)))
               "a substituted value executed a command of its own")
           (is (null (probe-file (merge-pathnames "PWNED" (uiop:getcwd))))))
      (ignore-errors (uiop:delete-directory-tree dir :validate t
                                                    :if-does-not-exist :ignore)))))

(test every-notify-hook-quotes-or-substitutes-nothing
  "The audit the -walletnotify escaping asked for: the other operator hooks
must not be protected by prose.

Core's four hooks fall into three shapes, and each is checked here on the
value it really carries:

  -blocknotify     %s is blockHash.GetHex(), substituted raw (init.cpp:2013)
  -walletnotify    %s/%w/%b/%h, %w through ShellEscape (wallet.cpp:1146)
  -alertnotify     %s is SanitizeString'd to SAFE_CHARS_DEFAULT and then
                   wrapped in single quotes by AlertNotify itself
                   (kernel_notifications.cpp:36-42)
  -startupnotify   no substitution at all (init.cpp:255-266)
  -shutdownnotify  no substitution at all

-alertnotify is the one that waives the shell-safe check (RUN-NOTIFY-COMMAND
:CHECK NIL), on the grounds that its caller already quoted the value. That is
the same `the other layer restricts this too' reasoning the -walletnotify
allowlist was justified by before it turned out to be false, so it is pinned
mechanically here rather than argued: the safe set contains no quote, so a
message full of shell syntax comes out as one quoted word that runs nothing."
  (let* ((dir (merge-pathnames (format nil "bl-notify-audit-~D/"
                                       (get-internal-real-time))
                               (uiop:temporary-directory)))
         (nasty "boom '; touch PWNED; echo '"))
    (unwind-protect
         (progn
           (ensure-directories-exist dir)
           ;; -alertnotify's value, built exactly as ALERT-NOTIFY builds it
           ;; and run through the same waived-check path, WAITED for so the
           ;; assertion cannot race a detached process.
           (bl.log:run-notify-command
            (format nil "touch ~Aalert-%s" (namestring dir))
            :value (format nil "'~A'" (bl.bytes:sanitize-string nasty))
            :check nil :wait t)
           (is (null (probe-file (merge-pathnames "PWNED" dir)))
               "-alertnotify's message executed a command of its own")
           (is (null (probe-file (merge-pathnames "PWNED" (uiop:getcwd)))))
           ;; It did run, and made exactly ONE file: the sanitized message
           ;; reached touch as a single word.
           (let ((made (directory (merge-pathnames "alert-*" dir))))
             (is (= 1 (length made))
                 "-alertnotify produced ~D files, not one" (length made)))
           ;; -startupnotify and -shutdownnotify substitute NOTHING, as
           ;; Core's do not: a % in the operator's command stays literal.
           (bl.log:run-notify-command
            (format nil "touch ~Aplain-100%s" (namestring dir)) :wait t)
           (is-true (probe-file (merge-pathnames "plain-100%s" dir))
                    "a hook with no substitutions did not reach the shell verbatim"))
      (ignore-errors (uiop:delete-directory-tree dir :validate t
                                                    :if-does-not-exist :ignore))))
  ;; The sanitizer -alertnotify's quoting rests on really does drop every
  ;; quote, so the wrap cannot be broken out of -- with a control that it
  ;; keeps what it is supposed to keep.
  (dolist (ch (list #\' #\" #\` #\$ #\\))
    (is (null (find ch (bl.bytes:sanitize-string (format nil "a~Cb" ch))))
        "~C survived SanitizeString" ch))
  (is (equal "ab" (bl.bytes:sanitize-string "a`b")))
  (is (equal "a.b" (bl.bytes:sanitize-string "a.b")))
  ;; -blocknotify's and -walletnotify's values go through the shell-safe
  ;; check; the RAW path is now the reference's own character class, so a
  ;; non-ASCII letter is escaped rather than handed to the shell on a claim
  ;; about Unicode that this code never examined.
  (flet ((sub (command &rest pairs)
           (bl.log::%notify-substitute command pairs)))
    (is (equal "echo deadbeef" (sub "echo %s" (cons #\s "deadbeef"))))
    (is (equal (format nil "echo 'caf~A'" (code-char 233))
               (sub "echo %w"
                    (cons #\w (format nil "caf~A" (code-char 233))))))))

(test notify-commands-reach-the-plist
  "-shutdownnotify is repeatable — Core reads it with GetArgs and joins EVERY
one (init.cpp:257-265) — while -blocknotify is a single command."
  (let ((p (start-node-plist
            '("-regtest" "-blocknotify=echo %s" "-startupnotify=touch /tmp/a"
              "-shutdownnotify=touch /tmp/b" "-shutdownnotify=touch /tmp/c")
            nil)))
    (is (equal "echo %s" (getf p :block-notify)))
    (is (equal '("touch /tmp/a") (getf p :startup-notify)))
    (is (equal '("touch /tmp/b" "touch /tmp/c") (getf p :shutdown-notify))))
  (dolist (name '("blocknotify" "startupnotify" "shutdownnotify"))
    (is-true (bl:known-config-option-p name) "~A unknown" name)
    (is-false (bl.cfg:core-only-option-p name) "~A still ignored" name)))

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
           (bl.log:run-notify-command
            (format nil "touch ~A" (namestring marker)) :wait t)
           (is-true (probe-file marker) "a waited notify command did not run")
           ;; And the hash substitution reaches the command line.
           (let ((hashed (merge-pathnames "deadbeef" dir)))
             (bl.log:run-notify-command
              (format nil "touch ~A%s" (namestring dir)) :value "deadbeef" :wait t)
             (is-true (probe-file hashed)
                      "%s was not substituted into the executed command")))
      (ignore-errors (uiop:delete-directory-tree dir :validate t
                                                    :if-does-not-exist :ignore))))
  ;; A failing hook is logged, never signalled: it must not fail whatever
  ;; triggered it.
  (is-true (bl.log:run-notify-command "exit 1" :wait t))
  ;; A value that cannot be substituted at all -- one carrying a NUL, which
  ;; would truncate the argv element the command travels in -- is reported as a
  ;; failed hook rather than signalled. A value that merely carries shell
  ;; syntax is escaped and runs (see the escaping tests above).
  (is-false (bl.log:run-notify-command
             "echo %s" :value (format nil "a~Cb" (code-char 0)) :wait t)))

(defun %path-mode (path)
  "PATH's permission bits (the low nine of st_mode)."
  (logand (sb-posix:stat-mode (sb-posix:stat (namestring path))) #o777))

(test the-node-process-creates-owner-only-files
  "Core's main() runs SetupEnvironment before anything else, and its umask half
sets the process mask to 0077 (common/system.cpp:91-94, bitcoind.cpp:269), so
the data directory, the wallets directory, debug.log, the RPC cookie and every
block file come out owner-only without a chmod at any of those sites.

Ours ran under whatever mask the invoking shell had. On a default Linux or
macOS login that is 022, so the datadir was drwxr-xr-x and debug.log was
world-readable -- on a wallet-bearing node that publishes the operator's
transaction history to every account on the machine.
feature_posix_fs_permissions.py:25 asserts 0700 on the chain directory and the
wallets directory and 0600 on debug.log."
  (let* ((dir (merge-pathnames (format nil "bl-umask-~D/" (get-internal-real-time))
                               (uiop:temporary-directory)))
         (saved (sb-posix:umask #o022)))
    (unwind-protect
         (flet ((make-pair (name)
                  (let ((sub (merge-pathnames (format nil "~A/" name) dir)))
                    (ensure-directories-exist sub)
                    (with-open-file (out (merge-pathnames "f" sub)
                                         :direction :output
                                         :if-exists :supersede
                                         :if-does-not-exist :create)
                      (write-line "x" out))
                    (list (%path-mode sub) (%path-mode (merge-pathnames "f" sub))))))
           ;; Control: under the usual login mask, a directory and a file this
           ;; process creates are readable by everyone.
           (is (equal (list #o755 #o644) (make-pair "loose"))
               "the control mask did not produce group/world-readable modes")
           ;; With Core's mask installed, the same two creations are owner-only.
           (bl::setup-environment)
           (is (equal (list #o700 #o600) (make-pair "tight"))))
      (sb-posix:umask saved)
      (ignore-errors (uiop:delete-directory-tree dir :validate t
                                                    :if-does-not-exist :ignore))))
  ;; And the mask is installed by the executable's entry point, before it has
  ;; looked at an argument -- the datadir is created further down.
  (is-true (member 'bl:node-main
                   (mapcar #'car (sb-introspect:who-calls 'bl::setup-environment)))
           "node-main no longer installs Core's private umask"))

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
           ;; when -pid is absent; an absolute path wins outright; -nopid
           ;; parses to "0", which Core reads as IsArgNegated.
           ;;
           ;; And a relative one is NETWORK-specific: GetPidFile takes
           ;; AbsPathForConfigVal's default net_specific=true
           ;; (common/args.h:42, init.cpp:180), so on regtest the file lands in
           ;; <datadir>/regtest/ -- which is where feature_init.py:256 looks
           ;; for it (node.chain_path). Mainnet's network directory IS the
           ;; datadir root, so that spelling is unchanged, and an absolute path
           ;; is taken as given on every network.
           (loop for (arg net expected)
                   in (list (list "node.pid" nil (merge-pathnames "node.pid" dir))
                            ;; Core's BITCOIN_PID_FILENAME (init.cpp:171) is
                            ;; the default, and the functional framework looks
                            ;; for that exact name (test_node.py:61).
                            (list nil nil (merge-pathnames "bitcoind.pid" dir))
                            (list "/var/run/x.pid" nil #p"/var/run/x.pid")
                            (list "0" nil nil)
                            (list "node.pid" :regtest
                                  (merge-pathnames "regtest/node.pid" dir))
                            (list nil :regtest
                                  (merge-pathnames "regtest/bitcoind.pid" dir))
                            (list "node.pid" :mainnet (merge-pathnames "node.pid" dir))
                            (list "/var/run/x.pid" :regtest #p"/var/run/x.pid"))
                 do (is (equal expected (bl::pid-file-path arg dir net))
                        "-pid=~A on ~A resolved wrongly" arg net))
           (ensure-directories-exist (merge-pathnames "regtest/" dir))
           (let ((path (bl::write-pid-file "net.pid" dir :regtest)))
             (is (equal (merge-pathnames "regtest/net.pid" dir) path))
             (is-true (probe-file path) "the network-directory pid file is missing"))
           (bl::remove-pid-file)
           (let ((path (bl::write-pid-file "node.pid" dir)))
             (is-true (probe-file path) "no pid file was written")
             (is (= (sb-posix:getpid)
                    (with-open-file (in path) (read in))))
             ;; Removal is by the path we recorded, and only for a file we
             ;; created — a second removal is a no-op, not a warning storm.
             (bl::remove-pid-file)
             (is-false (probe-file path) "the pid file outlived shutdown")
             (is-false bl::*pid-file-path*)
             (bl::remove-pid-file))
           ;; A negated -pid writes nothing at all.
           (is-false (bl::write-pid-file "0" dir))
           ;; The DEFAULT onion target is bound only when no -bind was given:
           ;; Core pushes DefaultOnionServiceTarget into onion_binds only in
           ;; the branch where neither -bind=...=onion nor a plain -bind is
           ;; present (init.cpp:2174-2182). With an explicit -bind it binds
           ;; nothing extra -- and the functional framework's per-node ports
           ;; are consecutive, so <p2p_port>+1 is the NEXT node's p2p port.
           ;; An explicit -bind=...=onion is the other branch: that address IS
           ;; the target (init.cpp:2141-2147).
           (let* ((src (%node-source-text))
                  (guard (search "((not listen-bind-supplied-p)" src))
                  (explicit (search "(cond (onion-bind" src)))
             (is-true guard
                      "the DEFAULT onion-target bind is no longer gated on -bind being absent")
             (is-true explicit
                      "an explicit -bind=...=onion no longer names the onion target"))
           ;; And the WRITE happens after the directory lock, where Core's
           ;; does: bitcoind locks in AppInitLockDataDirectory and only then
           ;; reaches CreatePidFile, the first step of AppInitMain
           ;; (init.cpp:1431-1435). Written before it, a second node starting
           ;; on a running node's datadir overwrote the running node's pid
           ;; file with its own pid and deleted it on the way out
           ;; (feature_filelock.py:40-44).
           (let* ((src (%node-source-text))
                  (lock-at (search "(lock-data-directories (node-data-directory *node*)" src))
                  (pid-at (search "(let ((path (write-pid-file pid-file data-directory network)))" src)))
             (is-true lock-at "the directory-lock call is gone")
             (is-true pid-at "the pid-file write call is gone")
             (is (< lock-at pid-at)
                 "the pid file is written before the datadir lock again"))
           ;; An unwritable path is fatal, as Core's InitError is: an operator
           ;; who asked for a pid file and silently did not get one has a
           ;; supervisor that will never find this process.
           (signals error
             (bl::write-pid-file "no-such-dir/deeper/x.pid" dir)))
      (setf bl::*pid-file-path* nil)
      (ignore-errors (uiop:delete-directory-tree dir :validate t
                                                    :if-does-not-exist :ignore))))
  (dolist (name '("pid" "printtoconsole"))
    (is-true (bl:known-config-option-p name) "~A unknown" name)
    (is-false (bl.cfg:core-only-option-p name) "~A still ignored" name))
  ;; -printtoconsole reaches the plist as :console-log, and is ABSENT when not
  ;; given so START-NODE's default (on, since we never daemonize) applies.
  (is-false (getf (start-node-plist '("-printtoconsole=0"))
                  :console-log))
  (is (eq :absent (getf (start-node-plist '("-regtest"))
                        :console-log :absent))))

(test connect-disables-every-self-chosen-outbound-connection
  "-connect (Core init.cpp:777-784, 2214-2225; net.cpp:3540). The functional
test framework writes connect=0 into EVERY node's bitcoin.conf by default
(test_framework/util.py:581), so a node that parses -connect and then dials
addrman anyway is a node that cannot be tested against Core's suite at all.

Asserted through the DIALING paths, not the variable: each of the four is the
one Core's ThreadOpenConnections would have taken."
  (let ((saved-addrman bl::*use-addrman-outgoing*)
        (saved-connect bl::*connect-nodes*))
    (unwind-protect
         (let ((node (bl:make-node :network :testnet3)))
           (setf (bl:node-network-active node) t
                 (bl:node-address-book node)
                 (bl.net:make-address-book))
           ;; Without -connect the node chooses its own peers.
           (setf bl::*use-addrman-outgoing* t)
           (is-true (bl::addrman-outgoing-enabled-p))
           ;; With it, every self-chosen path declines. replace-disconnected-peers
           ;; returning 0 is the load-bearing one: it is what would otherwise
           ;; refill the outbound set from the address book every cycle.
           (setf bl::*use-addrman-outgoing* nil
                 bl::*connect-nodes* '())
           (is-false (bl::addrman-outgoing-enabled-p))
           (is (= 0 (bl::replace-disconnected-peers node)))
           (is (= 0 (bl::connect-to-peers node 8 :timeout 1)))
           ;; No block-relay slot is opened and no feeler is spent; both would
           ;; otherwise pick an address themselves.
           (bl::maintain-block-relay-peers node)
           (bl::maybe-do-feeler node)
           (is (= 0 (length (bl:node-peers node)))))
      (setf bl::*use-addrman-outgoing* saved-addrman
            bl::*connect-nodes* saved-connect)))
  ;; The calls above return 0 for an empty address book too, so assert
  ;; STRUCTURALLY that every self-chosen dialing path consults the gate. This is
  ;; the check that goes red if a fifth path is added later without one, which
  ;; is exactly how the whole option quietly stops working.
  (dolist (caller '(bl::replace-disconnected-peers
                    bl::connect-to-peers
                    bl::maintain-block-relay-peers
                    bl::maybe-do-feeler))
    (is-true (member caller (mapcar #'car (sb-introspect:who-calls
                                          'bl::addrman-outgoing-enabled-p)))
             "~A does not consult addrman-outgoing-enabled-p" caller))
  ;; And that the -connect targets are actually dialed by the maintenance loop.
  (is-true (member 'bl::maintain-peers
                   (mapcar #'car (sb-introspect:who-calls
                                  'bl::connect-specified-nodes))))
  ;; Every occurrence reaches the plist (Core reads -connect with GetArgs), and
  ;; -noconnect is the single "0" Core tests for.
  (let ((p (start-node-plist
            '("-regtest" "-connect=1.2.3.4" "-connect=5.6.7.8:1234") nil)))
    (is (equal '("1.2.3.4" "5.6.7.8:1234") (getf p :connect-nodes)))
    ;; Parameter interaction: -listen soft-set to 0.
    (is-false (getf p :listen)))
  (is (equal '("0") (getf (start-node-plist '("-noconnect") nil)
                          :connect-nodes)))
  (is (equal '("0") (getf (start-node-plist '("-connect=0") nil)
                          :connect-nodes)))
  ;; Soft, not forced: an explicit -listen=1 still wins, which is the whole
  ;; difference between Core's SoftSetBoolArg and a plain assignment.
  (is-true (getf (start-node-plist
                  '("-connect=1.2.3.4" "-listen=1") nil)
                 :listen))
  ;; -maxconnections=0 takes the same interaction (Core's condition is one
  ;; disjunction covering both).
  (is-false (getf (start-node-plist '("-maxconnections=0") nil)
                  :listen))
  ;; And the -dnsseed half, which lives in apply-config-globals because that is
  ;; what owns *dns-seed-enabled*.
  (let ((saved bl:*dns-seed-enabled*))
    (unwind-protect
         (progn
           (setf bl:*dns-seed-enabled* t)
           (apply-config-globals '(("connect" . "1.2.3.4")))
           (is-false bl:*dns-seed-enabled*)
           (setf bl:*dns-seed-enabled* t)
           (apply-config-globals '(("maxconnections" . "0")))
           (is-false bl:*dns-seed-enabled*)
           ;; Explicit -dnsseed=1 wins over the interaction.
           (apply-config-globals
            '(("connect" . "1.2.3.4") ("dnsseed" . "1")))
           (is-true bl:*dns-seed-enabled*))
      (setf bl:*dns-seed-enabled* saved)))
  (is-true (bl:known-config-option-p "connect"))
  (is-false (bl.cfg:core-only-option-p "connect"))
  (is-true (bl.cfg:config-option-repeatable-p "connect")))

(test whitelist-and-whitebind-reach-the-node
  "-whitelist / -whitebind (Core init.cpp + net_permissions.cpp). Both are
repeatable — Core reads them with GetArgs — and a malformed spec is FATAL, as
Core's is: a typo'd range grants nothing and the operator never finds out."
  (let ((p (start-node-plist
            '("-regtest" "-whitelist=noban@10.0.0.0/8"
              "-whitelist=relay,mempool@192.168.0.0/16"
              "-whitebind=noban@127.0.0.1:1234")
            nil)))
    (is (equal '("noban@10.0.0.0/8" "relay,mempool@192.168.0.0/16")
               (getf p :whitelist)))
    (is (equal '("noban@127.0.0.1:1234") (getf p :whitebind))))
  (dolist (name '("whitelist" "whitebind" "whitelistrelay" "whitelistforcerelay"))
    (is-true (bl:known-config-option-p name) "~A unknown" name)
    (is-false (bl.cfg:core-only-option-p name) "~A still ignored" name))
  (dolist (name '("whitelist" "whitebind"))
    (is-true (bl.cfg:config-option-repeatable-p name)
             "~A is not repeatable" name))
  (let ((saved-relay bl.net:*whitelist-relay*)
        (saved-force bl.net:*whitelist-force-relay*))
    (unwind-protect
         (progn
           (apply-config-globals
            '(("whitelistrelay" . "0") ("whitelistforcerelay" . "1")))
           ;; -whitelistrelay defaults TRUE and -whitelistforcerelay FALSE, so
           ;; only these values prove the wiring.
           (is-false bl.net:*whitelist-relay*)
           (is-true bl.net:*whitelist-force-relay*))
      (setf bl.net:*whitelist-relay* saved-relay
            bl.net:*whitelist-force-relay* saved-force))))

(test seednode-and-forcednsseed
  "-seednode (Core connOptions.vSeedNodes, init.cpp:2212) and -forcednsseed
(DEFAULT_FORCEDNSSEED, net.h:97).

A -seednode is an ADDRESS SOURCE, not a peer: Core dials it as an ADDR_FETCH
connection and disconnects the moment it delivers more than one address. That
disconnect is the part worth pinning — without it -seednode would silently
become a second -addnode."
  ;; -seednode is repeatable and reaches the plist; -forcednsseed is a flag.
  (let ((p (start-node-plist
            '("-regtest" "-seednode=1.2.3.4" "-seednode=5.6.7.8:1234"
              "-forcednsseed=1")
            nil)))
    (is (equal '("1.2.3.4" "5.6.7.8:1234") (getf p :seednode))))
  (is-true (bl.cfg:config-option-repeatable-p "seednode"))
  (is-true (%force-dns-seed-after "-forcednsseed=1"))
  (is-false (%force-dns-seed-after "-forcednsseed=0"))
  ;; The seed dial is gated on -connect exactly as Core's is by construction:
  ;; with -connect, ThreadOpenConnections never reaches the seed queue.
  (let ((saved-addrman bl::*use-addrman-outgoing*)
        (saved-seeds bl::*seed-nodes*))
    (unwind-protect
         (let ((node (bl:make-node :network :testnet3)))
           (setf (bl:node-network-active node) t
                 bl::*seed-nodes* '("127.0.0.1:1")
                 bl::*use-addrman-outgoing* nil)
           (bl::connect-seed-nodes node)
           (is (= 0 (length (bl:node-peers node))))
           ;; And it is reached from startup, not merely defined.
           (is-true (%reached-from-start-node-p 'bl::connect-seed-nodes)))
      (setf bl::*use-addrman-outgoing* saved-addrman
            bl::*seed-nodes* saved-seeds)))
  (dolist (name '("seednode" "forcednsseed"))
    (is-true (bl:known-config-option-p name) "~A unknown" name)
    (is-false (bl.cfg:core-only-option-p name) "~A still ignored" name)))

(test forcednsseed-without-dnsseed-is-an-init-error
  "GA10 631b90f9. Core refuses to start on the contradiction rather than
letting -forcednsseed quietly do nothing: `if (GetBoolArg(\"-forcednsseed\") &&
!GetBoolArg(\"-dnsseed\")) return InitError(...)` (init.cpp:1010-1013), asserted
verbatim by p2p_dns_seeds.py:39-51.

It reads the EFFECTIVE -dnsseed, so every soft-set that turns seeding off
fires it too: -connect and -maxconnections<=0 (init.cpp:777-784) and an
-onlynet with no clearnet (:833-842). Ours used to apply *FORCE-DNS-SEED* and
stop there; its one consumer also requires *DNS-SEED-ENABLED*, so the operator
who asked for forced seeding got none and was never told."
  (let ((message "Cannot set -forcednsseed to true when setting -dnsseed to false."))
    (is (string= message (%config-globals-refusal "-forcednsseed=1" "-dnsseed=0")))
    (is (string= message (%config-globals-refusal "-forcednsseed=1" "-connect=1.2.3.4")))
    (is (string= message (%config-globals-refusal "-forcednsseed=1" "-maxconnections=0")))
    (is (string= message (%config-globals-refusal "-forcednsseed=1" "-onlynet=onion"
                                                  "-listenonion=1"))))
  ;; The other side of the gate: neither flag alone, nor the two agreeing, is
  ;; refused -- so the assertions above cannot be passing on some other error.
  (is-false (%config-globals-refusal "-forcednsseed=1"))
  (is-false (%config-globals-refusal "-forcednsseed=1" "-dnsseed=1"))
  (is-false (%config-globals-refusal "-dnsseed=0"))
  (is-false (%config-globals-refusal "-connect=1.2.3.4"))
  ;; -forcednsseed=0 never contradicts anything, whatever -dnsseed says.
  (is-false (%config-globals-refusal "-forcednsseed=0" "-dnsseed=0")))

(test maxuploadtarget-limits-what-the-node-serves
  "-maxuploadtarget (Core net.cpp:3877-3941, net_processing.cpp:2376-2383).

Core parses it with ParseByteUnits defaulting to M, so a bare number is
MEBIbytes. Reading it as bytes — the obvious mistake — would make every
ordinary command line set a target of a few hundred bytes, i.e. permanently
over budget from the first message."
  ;; ParseByteUnits: lowercase 1000-base, uppercase 1024-base, default M.
  (is (= (* 100 1024 1024) (bl.cfg:conf-parse-byte-units "100")))
  ;; Core's ByteUnit::NOOP, where a bare number really is a byte count.
  (is (= 100 (bl.cfg:conf-parse-byte-units "100" #\B)))
  (is (= (* 5 1000) (bl.cfg:conf-parse-byte-units "5k")))
  (is (= (* 5 1024) (bl.cfg:conf-parse-byte-units "5K")))
  (is (= (* 2 (expt 1000 3)) (bl.cfg:conf-parse-byte-units "2g")))
  (is (= (* 2 (expt 1024 4)) (bl.cfg:conf-parse-byte-units "2T")))
  (dolist (bad '("" "M" "1x" "-1" "1.5G" "one"))
    (signals error (bl.cfg:conf-parse-byte-units bad)))
  (let ((saved-target bl.net:*max-upload-target*)
        (saved-start bl.net::*max-outbound-cycle-start*)
        (saved-bytes bl.net::*max-outbound-bytes-in-cycle*))
    (unwind-protect
         (progn
           ;; No target: every accessor reads as Core's disabled shape, and
           ;; nothing is ever "reached".
           (setf bl.net:*max-upload-target* 0
                 bl.net::*max-outbound-bytes-in-cycle* (* 999 1024 1024))
           (is-false (bl.net:outbound-target-reached-p nil))
           (is-false (bl.net:outbound-target-reached-p t))
           (is (= 0 (bl.net:outbound-target-bytes-left)))
           (is (= 0 (bl.net:max-outbound-time-left-in-cycle)))
           ;; A target reached by the hard limit.
           (apply-config-globals '(("maxuploadtarget" . "10")))
           (is (= (* 10 1024 1024) bl.net:*max-upload-target*))
           (setf bl.net::*max-outbound-cycle-start*
                 (bl.ser:get-unix-time)
                 bl.net::*max-outbound-bytes-in-cycle* 0)
           (is-false (bl.net:outbound-target-reached-p nil))
           (is (= (* 10 1024 1024)
                  (bl.net:outbound-target-bytes-left)))
           (setf bl.net::*max-outbound-bytes-in-cycle*
                 (* 10 1024 1024))
           (is-true (bl.net:outbound-target-reached-p nil))
           (is (= 0 (bl.net:outbound-target-bytes-left)))
           ;; The historical-serving limit trips FIRST and, for a target this
           ;; small, is already tripped at zero bytes sent: a full cycle's
           ;; buffer (one block per 10 minutes) exceeds 10 MiB outright, which
           ;; is Core's `buffer >= nMaxOutboundLimit` branch.
           (setf bl.net::*max-outbound-bytes-in-cycle* 0)
           (is-true (bl.net:outbound-target-reached-p t))
           ;; With a target large enough for the buffer, historical serving is
           ;; allowed again while the hard limit is far away.
           (apply-config-globals '(("maxuploadtarget" . "10T")))
           (is-false (bl.net:outbound-target-reached-p t))
           ;; The cycle counter rolls after 24h rather than accumulating
           ;; forever — a target that could only ever be reached once is not a
           ;; rolling budget.
           (setf bl.net::*max-outbound-bytes-in-cycle* 12345
                 bl.net::*max-outbound-cycle-start*
                 (- (bl.ser:get-unix-time) 86401))
           (bl.net::%record-outbound-cycle-bytes 7)
           (is (= 7 bl.net::*max-outbound-bytes-in-cycle*))
           ;; And accumulates within one cycle.
           (bl.net::%record-outbound-cycle-bytes 3)
           (is (= 10 bl.net::*max-outbound-bytes-in-cycle*)))
      (setf bl.net:*max-upload-target* saved-target
            bl.net::*max-outbound-cycle-start* saved-start
            bl.net::*max-outbound-bytes-in-cycle* saved-bytes)))
  ;; Every byte the node sends is counted, not just the ones a caller
  ;; remembers to count: the accounting hangs off the single send-progress
  ;; site, so this asserts the wiring rather than the arithmetic.
  (is-true (member 'bl.net::%record-send-progress
                   (mapcar #'car
                           (sb-introspect:who-calls
                            'bl.net::%record-outbound-cycle-bytes))))
  ;; And the historical-block gate is consulted where blocks are served --
  ;; which is the getdata QUEUE's server, not the message handler: a getdata
  ;; parked by send-pause is answered from PROCESS-PEER-GETDATA on a later
  ;; pass, and a gate wired only to the handler would let that answer past it.
  (is-true (member 'bl.net::process-peer-getdata
                   (mapcar #'car
                           (sb-introspect:who-calls
                            'bl.net:outbound-target-reached-p))))
  (is-true (bl:known-config-option-p "maxuploadtarget"))
  (is-false (bl.cfg:core-only-option-p "maxuploadtarget")))

(test p2p-config-knobs-take-effect
  "Track D's P2P group, the two options that map onto existing constants."
  (let ((saved (list bl:*handshake-timeout-seconds*
                     bl.net:*max-send-buffer-bytes*)))
    (unwind-protect
         (progn
           (apply-config-globals
            '(("peertimeout" . "90") ("maxsendbuffer" . "2000")))
           (is (= 90 bl:*handshake-timeout-seconds*))
           ;; Core's -maxsendbuffer is in KILOBYTES and it multiplies by 1000,
           ;; NOT 1024 (init.cpp:2105). Using 1024 here would silently give
           ;; every operator a 2.4% larger buffer than they asked for.
           (is (= 2000000 bl.net:*max-send-buffer-bytes*)))
      (setf bl:*handshake-timeout-seconds* (first saved)
            bl.net:*max-send-buffer-bytes* (second saved))))
  ;; The handshake default is Core's 60, not the 30 it used to be: a peer on a
  ;; slow link that Core would keep, we dropped — and re-dialling costs more
  ;; than waiting.
  (is (= 60 bl:*handshake-timeout-seconds*))
  (dolist (bad '((("peertimeout" . "0")) (("maxsendbuffer" . "-1"))
                 (("maxsendbuffer" . "x"))))
    (signals error (apply-config-globals bad)))
  ;; Core's own words for the refusal (init.cpp:1067-1069); p2p_timeouts.py:105
  ;; matches the whole stderr line.
  (let ((saved bl:*handshake-timeout-seconds*))
    (is (equal "peertimeout must be a positive integer."
               (handler-case (progn (apply-config-globals '(("peertimeout" . "0"))) nil)
                 (error (e) (princ-to-string e)))))
    (setf bl:*handshake-timeout-seconds* saved))
  (dolist (name '("peertimeout" "maxsendbuffer"))
    (is-true (bl:known-config-option-p name) "~A unknown" name)
    (is-false (bl.cfg:core-only-option-p name) "~A still ignored" name)))

(test wallet-config-knobs-take-effect
  "Track D's Wallet group, which the plan calls \"mostly knobs over existing
paths\" — and it is exactly that: every special here already existed with
Core's name and default. What was missing was the OPTION that sets it, so a
wallet could not be tuned at all.

Fee options are BTC/kvB on the command line and satoshis internally, matching
-maxtxfee and -fallbackfee, which apply-config-globals already handled."
  (let ((saved (list bl.wallet:*wallet-min-tx-fee*
                     bl.wallet:*wallet-discard-rate*
                     bl.wallet:*wallet-consolidate-feerate*
                     bl.wallet:*wallet-max-aps-fee*
                     bl.wallet:*wallet-confirm-target*
                     bl.wallet:*wallet-signal-rbf*
                     bl.wallet:*wallet-spend-zero-conf-change*
                     bl.wallet:*wallet-reject-long-chains*
                     bl.wallet:*wallet-cross-chain*)))
    (unwind-protect
         (progn
           (bl:apply-rpc-config-globals
            '(("mintxfee" . "0.00002") ("discardfee" . "0.0002")
              ("consolidatefeerate" . "0.0003") ("maxapsfee" . "0.0001")
              ("txconfirmtarget" . "12") ("walletrbf" . "0")
              ("spendzeroconfchange" . "0") ("walletrejectlongchains" . "0")
              ("walletcrosschain" . "1")))
           (is (= 2000 bl.wallet:*wallet-min-tx-fee*))
           (is (= 20000 bl.wallet:*wallet-discard-rate*))
           (is (= 30000 bl.wallet:*wallet-consolidate-feerate*))
           (is (= 10000 bl.wallet:*wallet-max-aps-fee*))
           (is (= 12 bl.wallet:*wallet-confirm-target*))
           ;; The three booleans all default TRUE, so a test that only checked
           ;; "can be set" would pass without the option doing anything —
           ;; setting them to 0 is what proves the wiring.
           (is-false bl.wallet:*wallet-signal-rbf*)
           (is-false bl.wallet:*wallet-spend-zero-conf-change*)
           (is-false bl.wallet:*wallet-reject-long-chains*)
           ;; -walletcrosschain defaults FALSE (Core DEFAULT_WALLETCROSSCHAIN,
           ;; wallet.h:135), so setting it to 1 is what proves ITS wiring.
           (is-true bl.wallet:*wallet-cross-chain*))
      (setf bl.wallet:*wallet-min-tx-fee* (first saved)
            bl.wallet:*wallet-discard-rate* (second saved)
            bl.wallet:*wallet-consolidate-feerate* (third saved)
            bl.wallet:*wallet-max-aps-fee* (fourth saved)
            bl.wallet:*wallet-confirm-target* (fifth saved)
            bl.wallet:*wallet-signal-rbf* (sixth saved)
            bl.wallet:*wallet-spend-zero-conf-change* (seventh saved)
            bl.wallet:*wallet-reject-long-chains* (eighth saved)
            bl.wallet:*wallet-cross-chain* (ninth saved))))
  ;; Malformed values are refused rather than silently leaving the default.
  (dolist (bad '((("mintxfee" . "notanumber")) (("txconfirmtarget" . "0"))
                 (("txconfirmtarget" . "x")) (("maxapsfee" . "zz"))))
    (signals error (bl:apply-rpc-config-globals bad)))
  (dolist (name '("mintxfee" "discardfee" "consolidatefeerate" "maxapsfee"
                  "txconfirmtarget" "walletrbf" "spendzeroconfchange"
                  "walletrejectlongchains" "walletcrosschain"))
    (is-true (bl:known-config-option-p name) "~A unknown" name)
    (is-false (bl.cfg:core-only-option-p name) "~A still ignored" name)))

(defmacro %with-private-broadcast-globals (&body body)
  "Run BODY with the specials a -privatebroadcast start-up check writes bound,
so a test's configuration does not leak into the next suite."
  `(let ((bl:*private-broadcast* nil)
         (bl.net:*reachable-networks* bl.net:*reachable-networks*)
         (bl.net:*proxy* nil)
         (bl.net:*onion-proxy* nil)
         (bl.net:*onion-proxy-explicit* nil)
         (bl.net:*discover* bl.net:*discover*)
         (bl:*deferred-log-lines* nil)
         (*error-output* (make-string-output-stream)))
     ,@body))

(test privatebroadcast-start-up-checks-are-cores
  "feature_config_args.py:414-435 over Core's -privatebroadcast checks
(init.cpp:2257-2280), in Core's order and words: with neither Tor nor I2P
reachable the node refuses to start; with a Tor route but -connect it refuses
again; with a Tor route and -proxyrandomize=0 it starts and says
`Warning: ...' on stderr. The broadcast mechanism is not implemented, so the
option is accepted only where Core accepts it and sendrawtransaction then
refuses (PRIVATEBROADCAST-SENDRAWTRANSACTION-REFUSES-RATHER-THAN-BROADCASTS)."
  (flet ((refusal (merged)
           (%with-private-broadcast-globals
             (handler-case (progn (apply-config-globals merged) nil)
               (error (e) (princ-to-string e))))))
    (is (equal "Private broadcast of own transactions requested (-privatebroadcast), but none of Tor or I2P networks is reachable"
               (refusal '(("privatebroadcast" . "1") ("listenonion" . "0")))))
    (is (equal "Private broadcast of own transactions requested (-privatebroadcast), but -connect is also configured. They are incompatible because the private broadcast needs to open new connections to randomly chosen Tor or I2P peers. Consider using -maxconnections=0 -addnode=... instead"
               (refusal '(("privatebroadcast" . "1") ("connect" . "127.0.0.1:8333")
                          ("onion" . "127.0.0.1:9050") ("listenonion" . "0")))))
    ;; -listenonion may still deliver a Tor route later, so Core does not
    ;; refuse then (init.cpp:2261).
    (is (null (refusal '(("privatebroadcast" . "1") ("listenonion" . "1")))))
    (%with-private-broadcast-globals
      (apply-config-globals '(("privatebroadcast" . "1") ("onion" . "127.0.0.1:9050")
                              ("proxyrandomize" . "0") ("listenonion" . "0")))
      (is (eq t bl:*private-broadcast*))
      (is (equal (format nil "Warning: Private broadcast of own transactions requested (-privatebroadcast) and -proxyrandomize is disabled. Tor circuits for private broadcast connections may be correlated to other connections over Tor. For maximum privacy set -proxyrandomize=1.~%")
                 (get-output-stream-string *error-output*))))
    ;; Control: -proxyrandomize left on starts without a word on stderr.
    (%with-private-broadcast-globals
      (apply-config-globals '(("privatebroadcast" . "1") ("onion" . "127.0.0.1:9050")
                              ("listenonion" . "0")))
      (is (equal "" (get-output-stream-string *error-output*))))
    (%with-private-broadcast-globals
      (finishes (apply-config-globals '(("privatebroadcast" . "0"))))
      (is (null bl:*private-broadcast*)))
    (is-true (bl:known-config-option-p "privatebroadcast"))
    (is-false (bl.cfg:core-only-option-p "privatebroadcast"))))

(test privatebroadcast-sendrawtransaction-refuses-rather-than-broadcasts
  "Under -privatebroadcast Core hands a sendrawtransaction to its private
Tor/I2P queue and never to the mempool (rpc/mempool.cpp:115-131). That queue
does not exist here, and the ordinary path would announce the transaction to
every peer from this node's own address, so the RPC refuses: Core's own error
when no Tor/I2P network is reachable, ours otherwise. The transaction reaches
neither the mempool nor a peer."
  (let* ((node (make-test-node))
         ;; One input spending an outpoint nobody has, one OP_TRUE output.
         (hex (concatenate 'string "0200000001"
                           (make-string 64 :initial-element #\1)
                           "0000000000ffffffff01e8030000000000000151"
                           "00000000")))
    (flet ((send () (rpc-error-of (lambda ()
                                    (bl.rpc:dispatch-rpc-method
                                     node "sendrawtransaction" (list hex))))))
      (let ((bl:*private-broadcast* t)
            (bl.net:*reachable-networks* '(:ipv4 :ipv6)))
        (is (equal '(-1 . "-privatebroadcast is enabled, but none of the Tor or I2P networks is reachable. Maybe the location of the Tor proxy couldn't be retrieved from the Tor daemon at startup. Check whether the Tor daemon is running and that -torcontrol, -torpassword and -i2psam are configured properly.")
                   (send))))
      (let ((bl:*private-broadcast* t)
            (bl.net:*reachable-networks* '(:ipv4 :ipv6 :torv3)))
        (let ((err (send)))
          (is (eql -1 (car err)))
          (is-true (search "does not implement private broadcast" (cdr err)))))
      ;; Control: without the option the same call reaches validation.
      (let ((bl:*private-broadcast* nil))
        (is (not (equal -1 (car (send)))))))))

(test dns-is-a-real-option
  "-dns left the accept-and-drop list (GA11 1f1f28b7). Core reads it into
fNameLookup (init.cpp:1696, DEFAULT_NAME_LOOKUP = true) and every local name
resolution is gated on it -- the dial target (net.cpp:406), -proxy, -onion,
-externalip, -i2psam and -torcontrol. It is NOT what gates the DNS seeds; those
are -dnsseed, and Core queries them with a hardcoded fAllowLookup
(net.cpp:2371), which is why the two rows stay independent here."
  (let ((saved bl.net:*name-lookup*)
        (saved-seed bl:*dns-seed-enabled*))
    (unwind-protect
         (progn
           ;; It defaults TRUE, so setting it to 0 is what proves the wiring.
           ;; Both specials are set here rather than read as they stand: a
           ;; :GLOBAL row is only ASSIGNED when its option is present, so an
           ;; earlier test in this suite leaves whatever it set.
           (setf bl.net:*name-lookup* t bl:*dns-seed-enabled* t)
           (apply-config-globals '(("dns" . "0")))
           (is-false bl.net:*name-lookup*)
           ;; And -dns=0 leaves -dnsseed alone: they are different options, and
           ;; Core's DNS-seed query is not gated on fNameLookup at all.
           (is-true bl:*dns-seed-enabled* "-dns must not touch -dnsseed")
           (apply-config-globals '(("dns" . "1")))
           (is-true bl.net:*name-lookup*)
           ;; The reverse, as the control: -dnsseed=0 leaves -dns alone.
           (apply-config-globals '(("dnsseed" . "0")))
           (is-false bl:*dns-seed-enabled*)
           (is-true bl.net:*name-lookup* "-dnsseed must not touch -dns"))
      (setf bl.net:*name-lookup* saved
            bl:*dns-seed-enabled* saved-seed)))
  (is-true bl.net:*name-lookup* "Core DEFAULT_NAME_LOOKUP is true")
  (is-true (bl:known-config-option-p "dns"))
  (is-false (bl.cfg:core-only-option-p "dns")))

(test addresstype-and-changetype-are-real-options
  "-addresstype and -changetype left the accept-and-drop list (GA11 4d28b231).
Core parses both with ParseOutputType in CWallet::LoadWalletArgs
(wallet.cpp:2955-2972) and refuses to load the wallet on an unknown value; ours
accepted them and hardcoded bech32 in both address RPCs."
  (let ((saved (list bl.wallet:*wallet-default-address-type*
                     bl.wallet:*wallet-default-change-type*)))
    (unwind-protect
         (progn
           (apply-config-globals '(("addresstype" . "bech32m")
                                   ("changetype" . "p2sh-segwit")))
           (is (eq :bech32m bl.wallet:*wallet-default-address-type*))
           (is (eq :p2sh-segwit bl.wallet:*wallet-default-change-type*))
           ;; Core's wording verbatim, and a refusal rather than the default.
           (dolist (bad '((("addresstype" . "p2tr")) (("changetype" . "p2tr"))))
             (signals error (apply-config-globals bad))))
      (setf bl.wallet:*wallet-default-address-type* (first saved)
            bl.wallet:*wallet-default-change-type* (second saved))))
  ;; Core's defaults: bech32 for the address type, and an EMPTY optional for
  ;; the change type -- which is not the same as bech32.
  (is (eq :bech32 bl.wallet:*wallet-default-address-type*))
  (is (null bl.wallet:*wallet-default-change-type*))
  (dolist (name '("addresstype" "changetype"))
    (is-true (bl:known-config-option-p name) "~A unknown" name)
    (is-false (bl.cfg:core-only-option-p name) "~A still ignored" name)))

(test avoidpartialspends-is-a-real-option
  "-avoidpartialspends left the accept-and-drop list (GA11 feecc533). Core
reads it with GetBoolArg(DEFAULT_AVOIDPARTIALSPENDS = false) in every
CCoinControl constructor (wallet/coincontrol.cpp:9-13), so it belongs in the
option table as a :GLOBAL row over the special the WCC slot takes its initform
from -- not at the call sites, which in Core can only ever RAISE the flag."
  (let ((saved bl.wallet:*wallet-avoid-partial-spends*))
    (unwind-protect
         (progn
           ;; It defaults FALSE, so setting it to 1 is what proves the wiring.
           (apply-config-globals '(("avoidpartialspends" . "1")))
           (is-true bl.wallet:*wallet-avoid-partial-spends*)
           (apply-config-globals '(("avoidpartialspends" . "0")))
           (is-false bl.wallet:*wallet-avoid-partial-spends*))
      (setf bl.wallet:*wallet-avoid-partial-spends* saved)))
  (is-false bl.wallet:*wallet-avoid-partial-spends*
            "Core DEFAULT_AVOIDPARTIALSPENDS is false")
  (is-true (bl:known-config-option-p "avoidpartialspends"))
  (is-false (bl.cfg:core-only-option-p "avoidpartialspends")))

(test rpc-config-keypool-and-walletdir
  "-keypool and -walletdir (Core init.cpp). Both are asserted through their
EFFECT — a freshly made wallet manager's keypool size, and the directory
WALLETS-DIRECTORY hands back — rather than through the variable, because the
keypool size is read as a struct slot DEFAULT and a test on the variable alone
would pass even if no struct ever consulted it."
  (let ((saved-keypool bl.wallet:*default-keypool-size*)
        (saved-dir bl.wallet:*wallet-directory*))
    (flet ((manager-keypool ()
             (bl.wallet::wallet-manager-keypool-size
              (bl.wallet::make-wallet-manager :data-directory #p"/tmp/kp/"))))
    (unwind-protect
         (progn
           (bl:apply-rpc-config-globals '(("keypool" . "37")))
           (is (= 37 (manager-keypool)))
           ;; CLAMPED, never refused. Core reads the option as
           ;; std::max(args.GetIntArg("-keypool", DEFAULT_KEYPOOL_SIZE),
           ;; int64_t{1}) (wallet/wallet.cpp:3066), and GetIntArg answers 0 for
           ;; a value it cannot read, so 0, a negative and a garbage string all
           ;; become 1. This test used to assert the OPPOSITE -- that we refuse
           ;; all three -- and refusing 0 stopped the node from STARTING, where
           ;; wallet_hd.py:21 runs its second node with -keypool=0 so that no
           ;; address is handed out before the test asks for one.
           (dolist (v '("0" "-1" "x"))
             (bl:apply-rpc-config-globals (list (cons "keypool" v)))
             (is (= 1 (manager-keypool))
                 "-keypool=~A did not clamp to 1" v))
           ;; Relative -walletdir hangs off the data directory, absolute wins
           ;; outright, and NIL restores <datadir>/wallets/.
           (let ((manager (bl.wallet::make-wallet-manager
                           :data-directory #p"/tmp/dd/")))
             (setf bl.wallet:*wallet-directory* nil)
             (is (equal #p"/tmp/dd/wallets/"
                        (bl.wallet::wallets-directory manager)))
             (bl:apply-rpc-config-globals '(("walletdir" . "purses")))
             (is (equal #p"/tmp/dd/purses/"
                        (bl.wallet::wallets-directory manager)))
             (bl:apply-rpc-config-globals
              '(("walletdir" . "/srv/keys")))
             (is (equal #p"/srv/keys/"
                        (bl.wallet::wallets-directory manager)))))
      (setf bl.wallet:*default-keypool-size* saved-keypool
            bl.wallet:*wallet-directory* saved-dir))))
  (dolist (name '("keypool" "walletdir"))
    (is-true (bl:known-config-option-p name) "~A unknown" name)
    (is-false (bl.cfg:core-only-option-p name) "~A still ignored" name)))

;;;; --- settings.json (Core's read-write settings file) ---

(test settings-json-parses-every-json-type
  "Core stores arbitrary JSON in settings.json and re-renders it verbatim in
its `Setting file arg:` lines, so both halves have to survive a round trip
(feature_settings.py asserts on the rendered form)."
  (multiple-value-bind (alist errors)
      (bl:parse-settings-json
       "{\"string\": \"string\", \"num\": 5, \"bool\": true, \"null\": null, \"list\": [6,7]}"
       "/d/settings.json")
    (is (null errors))
    (is (= 5 (length alist)))
    (flet ((rendered (name)
             (bl:render-json-value
              (cdr (assoc name alist :test #'string=)))))
      (is (string= "\"string\"" (rendered "string")))
      (is (string= "5" (rendered "num")))
      (is (string= "true" (rendered "bool")))
      (is (string= "null" (rendered "null")))
      (is (string= "[6,7]" (rendered "list"))))))

(test settings-json-strips-the-warning-key
  "_warning_ is Core's own comment, not a setting: ReadSettings erases it from
the map it hands back (settings.cpp:117). Leaving it in would make the node
warn about an unknown option it wrote itself."
  (multiple-value-bind (alist errors)
      (bl:parse-settings-json
       (format nil "{\"~A\": \"blah\", \"prune\": \"550\"}"
               bl:+settings-warning-key+)
       "/d/settings.json")
    (is (null errors))
    (is (equal '("prune") (mapcar #'car alist)))))

(test settings-json-rejects-invalid-json
  "Core's exact wording — feature_settings.py matches on it."
  (let ((errors (nth-value 1 (bl:parse-settings-json
                              "invalid json" "/d/settings.json"))))
    (is (= 1 (length errors)))
    (is-true (search "does not contain valid JSON. This is probably caused by disk corruption or a crash"
                     (first errors)))))

(test settings-json-rejects-a-non-object
  (let ((errors (nth-value 1 (bl:parse-settings-json
                              "\"string\"" "/d/settings.json"))))
    (is (= 1 (length errors)))
    (is-true (search "Found non-object value \"string\" in settings file"
                     (first errors)))))

(test settings-json-rejects-a-json-array
  "An array parses to a LIST, which is shaped like an alist of nothing — so
the object check cannot be emptiness alone."
  (let ((errors (nth-value 1 (bl:parse-settings-json
                              "[1,2]" "/d/settings.json"))))
    (is (= 1 (length errors)))
    (is-true (search "Found non-object value" (first errors)))))

(test settings-json-rejects-duplicate-keys
  "yason keeps both cells for a duplicate key when parsing as an alist, which
is what makes this detectable at all — a hash-table parse silently keeps the
last and the node would start with a setting the operator never sees."
  (let ((errors (nth-value 1 (bl:parse-settings-json
                              "{\"key\": 1, \"key\": 2}" "/d/settings.json"))))
    (is (= 1 (length errors)))
    (is-true (search "Found duplicate key key in settings file" (first errors)))))

(test settings-json-empty-object-is-valid-and-empty
  (multiple-value-bind (alist errors)
      (bl:parse-settings-json "{}" "/d/settings.json")
    (is (null errors))
    (is (null alist))))

(test settings-json-round-trips-through-render
  "What RENDER-SETTINGS-JSON writes must parse back to what went in — that is
the whole contract of a file the node rewrites on every start."
  (let* ((text "{\"string\": \"string\", \"num\": 5, \"bool\": true, \"null\": null, \"list\": [6,7]}")
         (alist (bl:parse-settings-json text "/d/settings.json"))
         (written (bl:render-settings-json alist)))
    (multiple-value-bind (again errors)
        (bl:parse-settings-json written "/d/settings.json")
      (is (null errors))
      (is (equal (mapcar #'car alist) (mapcar #'car again)))
      (is (equal (mapcar (lambda (c) (bl:render-json-value (cdr c))) alist)
                 (mapcar (lambda (c) (bl:render-json-value (cdr c))) again))))))

(test settings-json-default-file-holds-only-the-warning
  "feature_settings.py asserts a fresh datadir's settings.json equals exactly
{_warning_: ...} after one start and stop."
  (let ((text (bl:render-settings-json nil)))
    (let ((parsed (let ((yason:*parse-object-as* :alist)) (yason:parse text))))
      (is (= 1 (length parsed)))
      (is (string= bl:+settings-warning-key+ (car (first parsed))))
      (is (string= (bl:settings-file-warning) (cdr (first parsed)))))))

(test settings-json-warning-names-the-client
  "The framework interpolates CLIENT_NAME from config.ini into the string it
compares against, and scripts/conformance-config.sh publishes bitcoin-lisp."
  (is-true (search bl:+client-name+ (bl:settings-file-warning)))
  (is (string= "bitcoin-lisp" bl:+client-name+)))

(test settings-json-false-becomes-a-negation
  "A JSON false is how Core stores -nofoo, so it has to reach the config layer
as the \"0\" the option readers understand — not as the string \"false\" — while
the row keeps the stored `false` that tells the merge it is a NEGATION."
  (let ((rows (bl:settings-config-rows
               (bl:parse-settings-json
                "{\"listen\": false, \"prune\": \"550\", \"txindex\": true}"
                "/d/settings.json"))))
    (flet ((row (name) (assoc name rows :test #'string=)))
      (is (equal '("listen" "0" "false") (row "listen")))
      (is (equal '("prune" "550" "\"550\"") (row "prune")))
      (is (equal '("txindex" "1" "true") (row "txindex")))
      (is-true (bl.cfg:setting-row-negated-p (row "listen")))
      (is-false (bl.cfg:setting-row-negated-p (row "prune"))))))

(test a-settings-array-is-one-value-per-element
  "Core's GetSettingsList SPLICES an array setting into the result -- `if
(value.isArray()) result.insert(result.end(), value.getValues().begin(), ...)'
(common/settings.cpp:230-234) -- which is what makes settings.json's `wallet'
a LIST of wallets.

We rendered the value with RENDER-JSON-VALUE whenever it was not a string, so
the array itself became the option's string value: the node started with
`Loading 2 wallets at startup: \"[\\\"default_wallet\\\"]\", \"default_wallet\"',
one of them a wallet nobody could have created, and -wallet took a JSON array
as a file name.

The scalars are the control: a number and a JSON false keep their single row
(the false is a negation, which is what ends a settings span)."
  (let ((rows (bl:settings-config-rows
               (bl:parse-settings-json
                "{\"wallet\": [\"w1\", \"w2\"], \"prune\": 550, \"listen\": false}"
                "/d/settings.json"))))
    (is (equal '(("wallet" "w1" "\"w1\"")
                 ("wallet" "w2" "\"w2\"")
                 ("prune" "550" "550")
                 ("listen" "0" "false"))
               rows))
    ;; An empty array contributes nothing at all, as an empty span does.
    (is (null (remove "wallet" (bl:settings-config-rows
                                (bl:parse-settings-json "{\"wallet\": []}"
                                                        "/d/settings.json"))
                      :key #'first :test-not #'string=)))))

(test option-name-lookups-are-case-sensitive-like-core
  "Core folds an option name only on WIN32 (args.cpp:200-204), so
GetArgFlags (:258-268) is a case-SENSITIVE map lookup: `-LogSourceLocations`
is `Invalid parameter` on the command line, `Ignoring unknown configuration
value` in a file, and `Ignoring unknown rw_settings value` in settings.json.

CORE-ONLY-OPTION-P downcased its argument while FIND-CONFIG-OPTION, the
lookup KNOWN-CONFIG-OPTION-P uses, did not — so the two disagreed about the
same name. A settings.json key spelled `LogSourceLocations` was core-only and
unknown at once: reported as an ignored option AND warned about as
unrecognised. Both follow Core now, which for that key means the warning."
  (dolist (name '("LogSourceLocations" "CheckBlockIndex" "DataDir" "DbCache"))
    (is-false (bl.cfg:core-only-option-p name) "~A matched a table row" name)
    (is-false (bl:known-config-option-p name) "~A matched a table row" name))
  (is-true (bl.cfg:core-only-option-p "logsourcelocations"))
  (is-true (bl:known-config-option-p "logsourcelocations"))
  (is-true (bl:known-config-option-p "dbcache"))
  ;; The two predicates agree on every spelling, which is the invariant the
  ;; refactor broke.
  (dolist (name '("logsourcelocations" "LogSourceLocations" "dbcache" "DbCache"))
    (is (eq (and (bl.cfg:core-only-option-p name) t)
            (and (bl:known-config-option-p name) (bl.cfg:core-only-option-p name) t))
        "~A is core-only and unknown at once" name))
  ;; One reachable consequence: settings.json keys are the only ones no parser
  ;; downcases (Core does not fold them either, args.cpp:420-423).
  (is (equal '("LogSourceLocations")
             (bl:unknown-settings-keys '(("LogSourceLocations" . "1")
                                         ("logsourcelocations" . "1")
                                         ("dbcache" . "100")))))
  ;; And the CLI/config parsers still hand both predicates lower-case names,
  ;; so a mixed-case spelling from those sources keeps working.
  (is (equal '(("logsourcelocations" . "1"))
             (bl.cfg:parse-cli-args '("-LogSourceLocations=1"))))
  (is (equal '("logsourcelocations")
             (bl.cfg:supplied-core-only-options
              (bl.cfg:parse-cli-args '("-LogSourceLocations=1"))))))

(test settings-json-unknown-keys-are-reported
  "Core logs one `Ignoring unknown rw_settings value` per unrecognized key and
carries on (args.cpp:420-423) — unknown settings never abort startup."
  (let ((unknown (bl:unknown-settings-keys
                  (bl:parse-settings-json
                   "{\"prune\": \"550\", \"zzznotanoption\": 1}" "/d/settings.json"))))
    (is (equal '("zzznotanoption") unknown))))

;;;; --- negated options in bitcoin.conf ---

(test conf-file-negation-strips-the-no-prefix
  "Core runs InterpretKey over config-file keys exactly as over command-line
ones (config.cpp:63), so `nolisten=1` in bitcoin.conf is -listen=0. Without
this the file set an option named \"nolisten\" that nothing reads, and
bitcoin.conf could not negate anything at all."
  (let ((cells (bl.cfg:parse-bitcoin-conf-sections
                (format nil "regtest=1~%[regtest]~%nolisten=1~%nosettings=1~%")
                :regtest)))
    (is (string= "0" (cdr (assoc "listen" cells :test #'string=))))
    (is (string= "0" (cdr (assoc "settings" cells :test #'string=))))
    (is-false (assoc "nolisten" cells :test #'string=))))

(test conf-file-double-negative-means-true
  "`nofoo=0` is a double negative and means -foo=1, which Core supports and
warns about (args.cpp:114-118)."
  (let ((cells (bl.cfg:parse-bitcoin-conf-sections
                (format nil "[regtest]~%nolisten=0~%") :regtest)))
    (is (string= "1" (cdr (assoc "listen" cells :test #'string=))))))

(test conf-file-negation-is-unconditional-like-core
  "Core's InterpretKey strips `no` without consulting any option table
(args.cpp:86-89), and so does INTERPRET-ARG. Gating the strip on the remainder
being a known option would make what a line in bitcoin.conf MEANS depend on the
contents of a lookup table — adding an option would silently change the meaning
of config files already on disk. An unknown result is warned about and ignored,
which is also what Core does with it."
  (let ((cells (bl.cfg:parse-bitcoin-conf-sections
                (format nil "[regtest]~%nodetour=5~%") :regtest)))
    ;; `5' is truthy, so the negation stands: -detour=0.
    (is (string= "0" (cdr (assoc "detour" cells :test #'string=))))
    (is-false (assoc "nodetour" cells :test #'string=))
    (is (equal '("detour") (bl:unknown-config-file-keys cells)))))

(test one-interpreter-for-the-command-line-and-the-config-file
  "INTERPRET-ARG is the single home for Core's InterpretKey/InterpretValue. It
used to be written out three times — parse-cli-args, the config-file parser and
the arg-log renderer — and the copies had already drifted apart on whether the
`no` prefix was stripped at all, so the same string meant different things
depending on which parser saw it."
  (flet ((cli (&rest args) (bl.cfg:parse-cli-args args))
         (conf (text) (bl.cfg:parse-bitcoin-conf-sections text :regtest)))
    ;; Same option, same meaning, from either source.
    (is (equal (cdr (assoc "listen" (cli "-nolisten") :test #'string=))
               (cdr (assoc "listen" (conf (format nil "[regtest]~%nolisten=1~%"))
                           :test #'string=))))
    ;; And the same double-negative rule.
    (is (equal (cdr (assoc "listen" (cli "-nolisten=0") :test #'string=))
               (cdr (assoc "listen" (conf (format nil "[regtest]~%nolisten=0~%"))
                           :test #'string=))))))

(test cli-arg-log-renders-the-json-core-stored
  "Core logs the JSON VALUE it stored, not the string the option readers see:
a negation is `false`, a bare -flag is the empty string, and -flag=x is the
string \"x\" (args.cpp:105-126, 880-884)."
  (let ((cells (bl.cfg:cli-arg-log-cells
                (list "-nolisten" "-prune=550" "-txindex"))))
    (is (string= "false" (cdr (assoc "listen" cells :test #'string=))))
    (is (string= "\"550\"" (cdr (assoc "prune" cells :test #'string=))))
    (is (string= "\"\"" (cdr (assoc "txindex" cells :test #'string=))))))

(test sensitive-option-values-are-masked-in-the-arg-log
  "GA10 801f2ad3. Core tags -torpassword (init.cpp:602), -rpcauth (:707),
-rpcpassword (:712) and -rpcuser (:716) with ArgsManager::SENSITIVE, and
logArgsPrefix substitutes `****` for the value of any option carrying it:
`value_str = (*flags & SENSITIVE) ? \"****\" : value.write()`
(common/args.cpp:883). feature_config_args.py:236-254 asserts both halves --
the four masked lines, and that -rpcbind and -rpcallowip are NOT masked.

We logged the raw JSON for every known option, so every start wrote the RPC
password, the rpcauth salt$HMAC and the Tor control password into debug.log:
the file operators tail, ship to log aggregators and paste into bug reports."
  (dolist (name '("rpcuser" "rpcpassword" "rpcauth" "torpassword"))
    (is-true (bl.cfg:sensitive-config-option-p name) "-~A is not masked" name))
  ;; Tagging more than Core is a divergence of its own: these are asserted
  ;; UNMASKED by feature_config_args.py.
  (dolist (name '("rpcbind" "rpcallowip" "addnode" "rpcport" "server" "prune"))
    (is-false (bl.cfg:sensitive-config-option-p name) "-~A is masked" name))
  (is-false (bl.cfg:sensitive-config-option-p "notanoption"))
  ;; The wiring: the lines %LOG-ARGS queues for debug.log, from all three
  ;; sources Core logs.
  (let* ((bl:*deferred-log-lines* nil)
         (lines (progn
                  (bl::%log-args
                   '("-rpcpassword=clisecret" "-rpcuser=cliuser"
                     "-torpassword=torsecret" "-rpcauth=cliuser:d3adb33f$c0ffee"
                     "-rpcbind=127.0.0.1" "-addnode=some.node")
                   (list (format nil "rpcpassword=filesecret~%server=1~%"))
                   (list (cons "rpcuser" "settingsecret"))
                   :regtest)
                  (mapcar #'second bl:*deferred-log-lines*)))
         (log (format nil "~{~A~%~}" lines)))
    (dolist (secret '("clisecret" "cliuser" "torsecret" "d3adb33f" "c0ffee"
                      "filesecret" "settingsecret"))
      (is-false (search secret log) "~A reached the log" secret))
    (dolist (line '("Command-line arg: rpcpassword=****"
                    "Command-line arg: rpcuser=****"
                    "Command-line arg: rpcauth=****"
                    "Command-line arg: torpassword=****"
                    "Config file arg: rpcpassword=****"
                    "Setting file arg: rpcuser = ****"))
      (is-true (search line log) "missing ~S" line))
    ;; Positive control for the mask itself: the log DID run, and the options
    ;; Core leaves alone still carry their value.
    (dolist (line '("Command-line arg: rpcbind=\"127.0.0.1\""
                    "Command-line arg: addnode=\"some.node\""
                    "Config file arg: server=\"1\""))
      (is-true (search line log) "missing ~S" line))))

(test conf-file-negation-works-in-the-global-area-too
  "The global area is parsed by the same loop, so a negation before any
[section] header has to behave the same way."
  (let ((globals (bl.cfg:conf-global-entries
                  (format nil "nolisten=1~%regtest=1~%"))))
    (is (string= "0" (cdr (assoc "listen" globals :test #'string=))))))

(test a-negated-repeatable-option-clears-its-span
  "For a list option Core's GetSettingsList erases the span up to and including
the last negation (SettingsSpan::begin() = data + negated(), settings.cpp:264-274)
and stops reading lower-precedence sources (`done |= span.negated() > 0`, :240),
so `-rpcauth=a -rpcauth=b -norpcauth` answers with an EMPTY list.

We appended the negation to the list as the literal string \"0\", and every
consumer that parses a list element then chokes on it. rpc_users.py:178-181
restarts a node with exactly those three arguments and expects a live RPC
server with both credentials revoked; here PARSE-RPCAUTH-ENTRY rejected \"0\",
%PARSE-RPCAUTH-CREDENTIALS returned :INVALID and START-RPC-SERVER returned NIL
— the node came up with no RPC at all. -noonlynet and -nodebugexclude were
worse: `Unknown network specified in -onlynet: \"0\"` and `Unsupported logging
category -debugexclude=0.` are startup FAILURES on command lines Core accepts."
  (let ((auth (getf (start-node-plist
                     '("-rpcauth=u1:aa$bb" "-rpcauth=u2:cc$dd" "-norpcauth"))
                    :rpc-auth)))
    (is (null auth))
    ;; The consequence the finding names: an empty list is valid, ("0") is not.
    (is-false (eq :invalid (bl.rpc::%parse-rpcauth-credentials auth)))
    (is (eq :invalid (bl.rpc::%parse-rpcauth-credentials '("0")))))
  ;; -noonlynet leaves no network name to parse.
  (is-false (assoc "onlynet" (nth-value 1 (start-node-plist
                                           '("-onlynet=ipv4" "-noonlynet")))
                   :test #'string=))
  (is (null (getf (start-node-plist '("-debugexclude=libevent" "-nodebugexclude"))
                  :debug-exclude)))
  ;; A value AFTER the negation survives it — the span begins where the last
  ;; negation ends, it is not simply emptied.
  (is (equal '("libevent")
             (getf (start-node-plist '("-nodebugexclude" "-debugexclude=libevent"))
                   :debug-exclude))))

(test a-negation-blocks-the-lower-precedence-sources
  "A negation sets Core's `done` flag, so the config file's values for that
option are not read at all (settings.cpp:240), and the `prev_negated_empty`
gate at :243 suppresses even the \"zombie\" values a config file would
otherwise contribute. feature_config_args.py:395 restarts with -noconnect
against the framework's own bitcoin.conf, which already carries connect=0
(test_framework/util.py:580-581): we produced (\"0\" \"0\"), which is not EQUAL
to '(\"0\"), so instead of disabling outbound connections the node logged
`Connecting only to -connect peers: 0, 0` and dialed a host named \"0\".

With a real peer in the file the same shape meant -noconnect did not clear it:
we kept dialing the peer the operator had just disabled."
  ;; -connect is network-only, so the framework's conf writes it under the
  ;; chain's [section] and so does this.
  (is (equal '("0") (getf (start-node-plist '("-noconnect" "-chain=regtest")
                                            '("[regtest]
connect=0"))
                          :connect-nodes)))
  (is (equal '("0") (getf (start-node-plist '("-noconnect" "-chain=regtest")
                                            '("[regtest]
connect=10.0.0.5"))
                          :connect-nodes)))
  ;; settings.json is a source of negations too (a JSON false).
  (is (null (getf (start-node-plist '("-chain=regtest") '("rpcauth=u:s$h")
                                    (bl:settings-config-rows '(("rpcauth" . yason:false))))
                  :rpc-auth)))
  ;; Core's own documented exception: a non-negated value AFTER the negation
  ;; brings the config file's values back from the dead (settings.cpp:210-217).
  (is (equal '("9.9.9.9" "10.0.0.5")
             (getf (start-node-plist '("-noconnect" "-connect=9.9.9.9" "-chain=regtest")
                                     '("[regtest]
connect=10.0.0.5"))
                   :connect-nodes))))

(test network-only-options-do-not-leak-out-of-the-default-section
  "Core marks eight bitcoind options ArgsManager::NETWORK_ONLY -- -addnode
(init.cpp:539), -bind (:548), -connect (:550), -port (:575), -rpcbind (:708),
-rpcport (:713), -wallet and -walletdir (wallet/init.cpp:71,73). Off mainnet
UseDefaultSection (args.cpp:855-857) returns false for them, so a value in the
config file's DEFAULT section is dropped (settings.cpp:181-184); and if that is
the only place the option is set, GetUnsuitableSectionOnlyArgs (args.cpp:134-146)
makes init.cpp:944-951 refuse to start.

We had neither half. A shared bitcoin.conf whose global area carries
rpcport=8332, port=8333 or connect=<mainnet peer> was applied verbatim to a
testnet4 node, which then bound the mainnet RPC port or dialled the wrong
chain's peers -- exactly the accident the flag exists to prevent."
  (flet ((refusal (args conf)
           (handler-case (progn (start-node-plist args conf) nil)
             (bl.err:config-error (e) (princ-to-string e))))
         (only-on (name) (format nil "Config setting for -~A only applied on ~
testnet4 network when in [testnet4] section." name)))
    (let ((conf (format nil "rpcport=8332~%port=8333~%connect=1.2.3.4~%~
                             addnode=5.6.7.8~%wallet=mainwallet~%~
                             [testnet4]~%maxconnections=40~%")))
      ;; Core's message, one line per option, in table order.
      (let ((text (refusal '("-testnet4") conf)))
        (is-true text "a testnet4 node started on a mainnet default section")
        (dolist (name '("rpcport" "port" "connect" "addnode" "wallet"))
          (is-true (search (only-on name) (or text "")) "no line for -~A" name)))
      ;; On mainnet the default section IS the chain's section, so nothing is
      ;; unsuitable and every value applies.
      (let ((plist (start-node-plist '("-chain=main") conf)))
        (is (= 8332 (getf plist :rpc-port)))
        (is (equal '("1.2.3.4") (getf plist :connect-nodes)))))
    ;; Set on the command line too, so there is nothing to refuse -- and the
    ;; default section's value must then be IGNORED rather than merged in. A
    ;; list option is where that shows, because GetSettingsList concatenates
    ;; every source it does read.
    (let ((conf (format nil "connect=1.2.3.4~%")))
      (is-false (refusal '("-testnet4" "-connect=9.9.9.9") conf))
      (is (equal '("9.9.9.9")
                 (getf (start-node-plist '("-testnet4" "-connect=9.9.9.9") conf)
                       :connect-nodes)))
      (is (equal '("9.9.9.9" "1.2.3.4")
                 (getf (start-node-plist '("-chain=main" "-connect=9.9.9.9") conf)
                       :connect-nodes)))))
  ;; An option that is NOT network-only reads the default section on every
  ;; chain, which is the whole point of the flag sitting on only eight rows.
  (is (= 300 (getf (start-node-plist '("-testnet4") (format nil "dbcache=300~%"))
                   :dbcache-mib)))
  (dolist (name '("addnode" "bind" "connect" "port" "rpcbind" "rpcport"
                  "wallet" "walletdir"))
    (is-true (bl.cfg:network-only-option-p name) "-~A is not network-only" name)
    (is-false (bl.cfg:use-default-section-p name :testnet4))
    (is-true (bl.cfg:use-default-section-p name :mainnet)))
  (is-false (bl.cfg:network-only-option-p "dbcache"))
  ;; Weird behaviour Core preserves on purpose (settings.cpp:156-159): a
  ;; NEGATED default-section value still applies to a network-only option,
  ;; even though an ordinary value there does not.
  (let ((negation (list (cons :default-section (list (list "port" "0" "false")))))
        (value (list (cons :default-section (list (list "port" "8333" "\"8333\""))))))
    (is (equal '(nil t) (multiple-value-list (bl.cfg:merge-setting negation t))))
    (is (equal '(nil nil) (multiple-value-list (bl.cfg:merge-setting value t))))
    (is (equal "8333" (second (bl.cfg:merge-setting value nil))))))

(test noconnect-still-disables-automatic-connections
  "-noconnect is -connect=0 at every drive site Core has: with an empty list and
IsArgNegated true, init.cpp:2215-2224 clears m_use_addrman_outgoing and leaves
m_specified_outgoing empty, exactly as the single value \"0\" does, and
init.cpp:777 tests the two the same way. doc/bitcoin-conf.md:66 names -connect
as the list whose negation has a side effect beyond clearing it — so clearing
the span must not also lose the side effect."
  (dolist (args '(("-noconnect") ("-connect=0")))
    (is (equal '("0") (getf (start-node-plist args) :connect-nodes))
        "~S did not disable outbound connections" args)
    ;; The -listen soft-set half of the same interaction (init.cpp:777).
    (is-false (getf (start-node-plist args) :listen)
              "~S did not soft-set -listen=0" args)))

(test the-span-readers-follow-core-settings-cpp
  "MERGE-SETTING and MERGE-SETTINGS-LIST are Core's GetSetting and
GetSettingsList; the rules they encode are easier to pin here than through a
command line. A row is (name value json), and only the JSON `false` is a
negation — `connect=0` is an ordinary value."
  (flet ((row (value &optional (json (format nil "~S" value)))
           (list "x" value json))
         (neg () (list "x" "0" "false")))
    ;; A config-file span takes its FIRST value, a command-line span its LAST
    ;; (settings.cpp:165-169).
    (is (equal "a" (second (bl.cfg:merge-setting
                            (list (cons :network-section
                                        (list (row "a") (row "b"))))))))
    (is (equal "b" (second (bl.cfg:merge-setting
                            (list (cons :command-line
                                        (list (row "a") (row "b"))))))))
    ;; A trailing negation makes the span empty and the setting negated.
    (is (equal '(nil t) (multiple-value-list
                         (bl.cfg:merge-setting
                          (list (cons :command-line (list (row "a") (neg))))))))
    ;; ... and a value after it is an ordinary value again.
    (is (equal "b" (second (bl.cfg:merge-setting
                            (list (cons :command-line
                                        (list (row "a") (neg) (row "b"))))))))
    ;; The list reader drops everything up to the last negation, in every
    ;; source, and a "0" that is not a negation stays.
    (is (equal '("b") (mapcar #'second
                              (bl.cfg:merge-settings-list
                               (list (cons :command-line
                                           (list (row "a") (neg) (row "b"))))))))
    (is (equal '("0") (mapcar #'second
                              (bl.cfg:merge-settings-list
                               (list (cons :command-line (list (row "0"))))))))
    (is-false (bl.cfg:setting-row-negated-p (row "0")))
    (is-true (bl.cfg:setting-row-negated-p (neg)))
    ;; Without a negation the sources ACCUMULATE — GetArgs concatenates them.
    (is (equal '("a" "b")
               (mapcar #'second
                       (bl.cfg:merge-settings-list
                        (list (cons :command-line (list (row "a")))
                              (cons :default-section (list (row "b"))))))))))

(test settings-json-wallet-must-be-strings
  "Core validates the JSON TYPE of the wallet list rather than coercing it
(wallet/load.cpp:81-86): every element must be a string. feature_settings.py
drives all six shapes below and requires the node to refuse each one."
  (flet ((err (json)
           (bl:validate-settings-values
            (bl:parse-settings-json json "/d/settings.json"))))
    (dolist (bad '("{\"wallet\": [10]}"
                   "{\"wallet\": [true]}"
                   "{\"wallet\": [[]]}"
                   "{\"wallet\": [{}]}"
                   "{\"wallet\": [\"w1\", 10]}"
                   "{\"wallet\": [\"w1\", false]}"))
      (is-true (err bad) "~A must be refused" bad)
      (when (err bad)
        (is-true (search "'-wallet' requires a string value" (err bad)))))
    ;; And the valid shapes are not refused.
    (is-false (err "{\"wallet\": [\"w1\"]}"))
    (is-false (err "{\"wallet\": [\"w1\", \"w2\"]}"))
    (is-false (err "{\"wallet\": \"w1\"}"))
    ;; A JSON false is -nowallet, which is how Core disables all wallets.
    (is-false (err "{\"wallet\": false}"))
    ;; No wallet key at all is obviously fine.
    (is-false (err "{\"prune\": \"550\"}"))))

;;;; --- -wallet=<name> and -loadblock=<file> as Core reads them ---

(test wallet-option-names-wallets-rather-than-switching-the-subsystem
  "Core's -wallet=<name> is the list of wallets to LOAD (wallet/load.cpp:81);
the subsystem switch is -disablewallet. Ours treated -wallet as a boolean, so
`-wallet=w1` said nothing about w1 — it just meant \"true\"."
  (multiple-value-bind (plist)
      (start-node-plist '("-regtest" "-wallet=w1" "-wallet=w2"))
    (is (equal '("w1" "w2") (getf plist :wallet-names)))
    ;; Naming a wallet is also the opt-in to wallet support, which matters on
    ;; mainnet where the default is off.
    (is-true (getf plist :wallet))))

(test wallet-option-is-repeatable
  "Core reads it with GetArgs, so a repeated -wallet does not collapse to the
last one the way an ordinary option does."
  (is (equal '("a" "b" "c")
             (getf (start-node-plist
                    '("-regtest" "-wallet=a" "-wallet=b" "-wallet=c"))
                   :wallet-names))))

(test nowallet-loads-no-wallets-but-keeps-the-rpcs
  "Core defines -nowallet as \"disable all wallets\" — meaning load none — and
its own message says so: \"'-nowallet' accepts only '1' to disable all
wallets\". The wallet RPC surface stays up; -disablewallet is what removes it.

Treating -nowallet as a subsystem switch made wallet_multiwallet.py fail on its
FIRST call: it starts node0 with exactly -nowallet and then calls wallet RPCs
on it, and got 'Method not found (wallet support is disabled)'."
  (let ((plist (start-node-plist '("-regtest" "-nowallet"))))
    (is (null (getf plist :wallet-names)) "-nowallet names no wallet")
    ;; Not present at all, so START-NODE's network default decides — which on
    ;; regtest means wallet support stays ON.
    (is (eq :unset (getf plist :wallet :unset))
        "-nowallet must not decide whether the subsystem runs"))
  ;; -disablewallet is the one that does turn it off, and it says so explicitly.
  (let ((plist (start-node-plist '("-regtest" "-disablewallet"))))
    (is (null (getf plist :wallet :unset)))))

(test bare-wallet-flag-is-the-mainnet-opt-in
  "Wallet support is default-OFF on mainnet here (docs/wallet-plan.md), so a
bare -wallet has to keep meaning \"turn it on\" even though -wallet is now a
name list. INTERPRET-ARG renders a bare flag as \"1\", which names nothing."
  (let ((plist (start-node-plist '("-mainnet" "-wallet"))))
    (is (null (getf plist :wallet-names)))
    (is-true (getf plist :wallet))))

(test loadblock-is-repeatable-and-implemented
  "Every -loadblock= is imported in order (init.cpp:2022). It used to sit in
the accepted-but-unimplemented table, so passing one started the node and
imported nothing."
  (is (equal '("/a/one.dat" "/b/two.dat")
             (getf (start-node-plist
                    '("-regtest" "-loadblock=/a/one.dat" "-loadblock=/b/two.dat"))
                   :load-block)))
  (is-false (bl.cfg:core-only-option-p "loadblock")
            "-loadblock is implemented now and must not be reported as ignored")
  (is-true (bl:known-config-option-p "loadblock")))

(test define-option-rejects-a-contradictory-row
  "The two consistency checks DEFINE-OPTION makes at macroexpansion time
must actually fire: a :collect option that is not :repeatable would be
collected from an alist that kept only its last occurrence, and a :key
option without a :type has no parser in the scalar scan."
  (signals bl.cfg:option-definition-error
    (macroexpand-1 '(bl.cfg:define-option "probe" :collect :probe)))
  (signals bl.cfg:option-definition-error
    (macroexpand-1 '(bl.cfg:define-option "probe" :key :probe)))
  (finishes (macroexpand-1 '(bl.cfg:define-option "probe" :key :probe :type :bool))))

(test acceptnonstdtxn-refusal-names-the-chain-as-core-does
  "Core: `acceptnonstdtxn is not currently supported for %s chain' over
GetChainTypeString (mempool_args.cpp:102-104) -- `main', which
feature_config_args.py:149 compares whole. Ours printed our keyword,
`mainnet'. Control: a test chain accepts the option."
  (let ((bl:*network* :mainnet)
        (bl.val:*require-standard* bl.val:*require-standard*))
    (is (equal "acceptnonstdtxn is not currently supported for main chain"
               (%config-refusal (apply-config-globals '(("acceptnonstdtxn" . "1")))))))
  (let ((bl:*network* :regtest)
        (bl.val:*require-standard* bl.val:*require-standard*))
    (is (null (%config-refusal (apply-config-globals '(("acceptnonstdtxn" . "1"))))))))

(test network-is-set-before-the-config-globals-are-applied
  "-acceptnonstdtxn on mainnet is an init error (Core mempool_args.cpp:102-104,
asserted by feature_config_args.py); the check reads *NETWORK*. start-node-
from-args resolved the network but left *NETWORK* at its default until
init-node, which runs after apply-config-globals -- so on a mainnet command
line the check compared against the default network and never fired. Pinned
on the source, as the alternative is starting a node: the setf must precede
the apply inside start-node-from-args."
  (let* ((src (%node-source-text))
         (start (search "(defun start-node-from-args" src))
         (end (search "(defun " src :start2 (1+ start)))
         (body (subseq src start end))
         (set-pos (search "(setf *network* settings-network)" body))
         (apply-pos (search "(apply-config-globals merged)" body)))
    (is (and set-pos apply-pos (< set-pos apply-pos))
        "start-node-from-args must set *network* before apply-config-globals")))


(test condition-hierarchy-contract
  "The bl.err classes and their signalling functions (P4.1): a module error
is a BITCOIN-LISP-ERROR and a SIMPLE-ERROR, the message is the control string
formatted with the arguments -- exactly what the bare ERROR call gave -- and
the pre-existing conditions sit under the hierarchy."
  (signals bl.err:bitcoin-lisp-error (bl.err:config-error "x"))
  (signals bl.err:config-error (bl.err:config-error "x"))
  (let ((e (handler-case (bl.err:config-error "Invalid port ~A" 5) (error (e) e))))
    (is (typep e 'simple-error))
    (is (string= "Invalid port 5" (princ-to-string e))))
  (is-true (subtypep 'bl.cfg:config-parse-error 'bl.err:config-error))
  (is-true (subtypep 'bl:cli-parse-error 'bl.err:config-error))
  (is-true (subtypep 'bl.net:socks5-error 'bl.err:net-error))
  (is-true (subtypep 'bl.rpc:rpc-error 'bl.err:bitcoin-lisp-error))
  (is-true (subtypep 'bl.err:consensus-error 'bl.err:bitcoin-lisp-error))
  (is (eq :bad-txns-vin-empty
          (bl.err:error-reason (make-condition 'bl.err:consensus-error :reason :bad-txns-vin-empty)))))

;;; --- Core's InitConfig ordering: the config file that is NOT read ----------
;;; Finding 9e7729b8. Core records the original datadir and config path before
;;; the file is read (common/init.cpp:34-35), because a datadir= line inside it
;;; moves the datadir, and then refuses to start if the directory it moved to
;;; holds a bitcoin.conf of its own (:65-95).

(defun %write-conf (dir text)
  "Write TEXT as DIR/bitcoin.conf and return the path."
  (let ((path (merge-pathnames "bitcoin.conf" (uiop:ensure-directory-pathname dir))))
    (ensure-directories-exist path)
    (with-open-file (out path :direction :output :if-exists :supersede)
      (write-string text out))
    path))

(test conf-path-is-resolved-the-way-core-resolves-it
  "Core AbsPathForConfigVal (common/config.cpp:226-232): an absolute -conf
stands, a RELATIVE one is joined onto the base datadir -- not the working
directory. And an explicitly named -conf that cannot be opened is FATAL
(:139-142), where we fell through to no configuration at all."
  (with-temp-directory (dir)
    (let ((conf (%write-conf dir (format nil "prune=550~%"))))
      ;; relative, against the datadir
      (is (equal (namestring conf)
                 (namestring (bl::resolve-conf-path
                              (list (format nil "-datadir=~A" (namestring dir))
                                    "-conf=bitcoin.conf")
                              (list (cons "datadir" (namestring dir))
                                    (cons "conf" "bitcoin.conf"))
                              (namestring dir)))))
      ;; absolute, as given
      (is (equal (namestring conf)
                 (namestring (bl::resolve-conf-path
                              (list (format nil "-conf=~A" (namestring conf)))
                              (list (cons "conf" (namestring conf)))
                              (namestring dir)))))
      ;; no -conf: the datadir's own bitcoin.conf, and NOT explicit
      (multiple-value-bind (path explicit-p)
          (bl::resolve-conf-path '() '() (namestring dir))
        (is (equal (namestring conf) (namestring path)))
        (is (null explicit-p)))
      ;; -noconf: no file at all
      (is (null (bl::resolve-conf-path '("-noconf") '(("conf" . "0"))
                                       (namestring dir)))))))

(test a-config-file-that-is-a-directory-is-fatal-in-cores-words
  "Core ReadConfigFiles (common/config.cpp:134-141) has two refusals, in this
order and in these words: a DIRECTORY at the config path is `Config file
\"<path>\" is a directory.' whether -conf named it or it is the datadir's own
bitcoin.conf, and only then is an explicitly named file that cannot be opened
`specified config file \"<path>\" could not be opened.'. A directory used to
pass the check (PROBE-FILE answers a truename for one) and the read that
followed died with a stream error naming no option. Positive controls: a
readable file is handed back untouched, and the DEFAULT path may be absent.

Both sentences carry `Error reading configuration file: ', the prefix
ReadConfigFiles' only caller puts on everything it returns
(common/init.cpp:39). Core keeps the two halves apart internally; they never
reach an operator apart, and feature_config_args.py:52,559 compare the whole
of stderr against the joined text."
  (with-temp-directory (dir)
    (flet ((check (path explicit-p)
             (bl::check-config-file-readable path explicit-p)))
      (let* ((conf (%write-conf dir (format nil "prune=550~%")))
             (base (uiop:ensure-directory-pathname dir))
             (subdir (make-pathname :name "confdir" :defaults base))
             (missing (merge-pathnames "nope.conf" base)))
        (ensure-directories-exist (uiop:ensure-directory-pathname subdir))
        (is (eq conf (check conf t)))
        (is (eq conf (check conf nil)))
        (dolist (explicit-p '(t nil))
          (is (equal (format nil "Error reading configuration file: Config file ~
\"~A\" is a directory."
                             (namestring subdir))
                     (%config-refusal (check subdir explicit-p)))
              "a directory at the config path, explicit-p ~A" explicit-p))
        (is (equal (format nil "Error reading configuration file: specified config ~
file \"~A\" could not be opened."
                           (namestring missing))
                   (%config-refusal (check missing t))))
        (is (null (%config-refusal (check missing nil))))))))

(test a-config-file-parse-error-names-the-config-file
  "Core's three ReadConfigStream refusals (common/config.cpp:87-108) reach an
operator through ReadConfigFiles' only caller, which reports them as `Error
reading configuration file: <sentence>' (common/init.cpp:39). Ours reported the
sentence alone, so a node that died on `parse error on line 1: garbage' never
said WHICH file line 1 was in -- and feature_config_args.py:80,138,153,157
compares the whole of stderr against the joined text.

The prefix is the assertion; the sentences themselves were already Core's."
  (flet ((refusal (text)
           (handler-case (progn (bl.cfg:parse-bitcoin-conf text) nil)
             (bl.cfg:config-parse-error (c)
               (bl.cfg:config-parse-error-message c)))))
    (let ((leading-dash (refusal (format nil "-dash=1~%")))
          (no-equals (refusal (format nil "nono~%")))
          (hash-in-password (refusal (format nil "rpcpassword=foo#bar~%"))))
      (is (equal (format nil "Error reading configuration file: parse error on ~
line 1: -dash=1, options in configuration file must be specified without ~
leading -")
                 leading-dash))
      (is (equal (format nil "Error reading configuration file: parse error on ~
line 1: nono, if you intended to specify a negated option, use nono=1 instead")
                 no-equals))
      (is (equal (format nil "Error reading configuration file: parse error on ~
line 1, using # in rpcpassword can be ambiguous and should be avoided")
                 hash-in-password))
      ;; Positive control: a file Core accepts raises nothing at all, so the
      ;; three above cannot be passing because everything signals.
      (is (null (refusal (format nil "prune=550~%[regtest]~%rpcport=1~%")))))))

(test a-datadir-bitcoin-conf-that-is-not-the-file-we-read-is-fatal
  "Both of Core's shadowing shapes. The assertions are on the SETTING that
lives only in the shadowed file, not on the error text: what is lost is the
whole second file -- here a prune target, so an unpruned sync onto a disk
sized for a pruned one."
  (with-temp-directory (root)
    (let* ((a (merge-pathnames "dirA/" root))
           (b (merge-pathnames "dirB/" root))
           (c (merge-pathnames "dirC/" root))
           (alt (merge-pathnames "alt.conf" root)))
      (ensure-directories-exist b)
      (%write-conf a (format nil "chain=regtest~%datadir=~A~%prune=1000~%"
                             (namestring b)))
      (%write-conf b (format nil "chain=regtest~%prune=2000~%"))
      (%write-conf c (format nil "chain=regtest~%prune=550~%"))
      (with-open-file (out alt :direction :output :if-exists :supersede)
        (format out "chain=regtest~%"))
      ;; (1) conf-set datadir=: dirB's own prune=2000 is nowhere in the result.
      (let* ((text (alexandria:read-file-into-string
                    (merge-pathnames "bitcoin.conf" a)))
             (plist (start-node-plist '() text)))
        (is (= 1000 (getf plist :prune))
            "the file we read decided the prune target")
        (is (equal (namestring b) (namestring (uiop:ensure-directory-pathname
                                               (getf plist :data-directory))))
            "and it moved the data directory to one holding another config file")
        (let ((refusal (%config-refusal
                        (bl::check-ignored-config-file
                         a (merge-pathnames "bitcoin.conf" a) b '()))))
          (is (search "which is ignored" refusal))
          (is (search (format nil "Data directory \"~A\" contains"
                              (string-right-trim "/" (namestring b)))
                      refusal)
              "the ignored file's directory must be named as Core quotes it")
          (is (search "data directory" refusal)
              "with no -conf, Core attributes the override to the data directory")
          (is (search "allowignoredconf" refusal)))
        ;; -allowignoredconf=1 downgrades it to a warning, and the warning is
        ;; queued for debug.log rather than lost to the console.
        (let ((bl:*deferred-log-lines* nil))
          (is (null (%config-refusal
                     (bl::check-ignored-config-file
                      a (merge-pathnames "bitcoin.conf" a) b '()
                      :allow-ignored t))))
          (is (= 1 (length bl:*deferred-log-lines*)))
          (is (eq :warn (first (first bl:*deferred-log-lines*))))))
      ;; (2) -conf shadowing the datadir's file: the source clause names the
      ;; command line argument instead.
      (let ((refusal (%config-refusal
                      (bl::check-ignored-config-file
                       c alt c (list (cons "conf" (namestring alt)))))))
        (is (search "command line argument" refusal))
        (is (search "-conf=" refusal)))
      ;; (3) -noconf: Core logs, it does not refuse.
      (let ((bl:*deferred-log-lines* nil))
        (is (null (%config-refusal
                   (bl::check-ignored-config-file c nil c '()))))
        (is (= 1 (length bl:*deferred-log-lines*)))
        (is (eq :info (first (first bl:*deferred-log-lines*))))
        ;; Core's words, the directory quoted WITHOUT a trailing separator
        ;; (common/init.cpp:70-73, feature_config_args.py:86).
        (is (equal (format nil "Data directory \"~A\" contains a \"bitcoin.conf\" file which is explicitly ignored using -noconf."
                           (string-right-trim "/" (namestring c)))
                   (second (first bl:*deferred-log-lines*)))))
      ;; (4) POSITIVE CONTROL: the ordinary case -- the datadir's own file IS
      ;; the one we read -- must stay silent, or the check would refuse every
      ;; node that ever starts.
      (let ((bl:*deferred-log-lines* nil))
        (is (null (%config-refusal
                   (bl::check-ignored-config-file
                    c (merge-pathnames "bitcoin.conf" c) c '()))))
        (is (null bl:*deferred-log-lines*)))
      ;; (5) and a datadir with no bitcoin.conf at all is silent too.
      (is (null (%config-refusal
                 (bl::check-ignored-config-file root alt root '())))))))

(test allowignoredconf-is-a-real-option-now
  "It has to be, or the node reports the very flag that governs the check as
having no effect."
  (multiple-value-bind (plist merged)
      (start-node-plist '("-regtest" "-allowignoredconf=1"))
    (declare (ignore plist))
    (is (null (bl.cfg:supplied-core-only-options merged)))
    (is (equal "1" (cfg "allowignoredconf" merged)))))

(test i2psam-is-recorded-for-reporting-and-still-core-only
  "-i2psam names the I2P SAM proxy Core reports as the i2p network's proxy
(init.cpp:2232-2238 SetProxy(NET_I2P, ...), default port 7656; rpc/net.cpp:626),
so its value is kept -- but this node does not speak I2P, and the option stays
one startup names as accepted-and-unimplemented. A start without it clears
what an earlier start in the same image left."
  (let ((bl.net:*i2p-sam-proxy* :unset))
    (apply-config-globals '(("i2psam" . "127.0.0.1")))
    (is (equal "127.0.0.1:7656" bl.net:*i2p-sam-proxy*))
    (apply-config-globals '(("i2psam" . "127.0.0.1:7000")))
    (is (equal "127.0.0.1:7000" bl.net:*i2p-sam-proxy*))
    (apply-config-globals '())
    (is (null bl.net:*i2p-sam-proxy*)))
  (is (equal '("i2psam") (bl.cfg:supplied-core-only-options '(("i2psam" . "127.0.0.1"))))))

(test unrecognized-config-sections-are-cores-init-warning
  "Core records every section a config file names -- a [header], or the part
of a key before its last dot that lies past the header's prefix
(common/config.cpp:48-66) -- and warns about each one that is not a chain's
name (common/args.cpp:154-169, init.cpp:958-966), file and line first.
feature_config_args.py:176 compares the stopped node's whole stderr against
the two-file form of it. Ours read the sections and never said a word."
  (is (equal '(("testnot" "include.conf" 1))
             (bl.cfg:conf-unrecognized-sections
              (format nil "testnot.datadir=1~%") "include.conf")))
  (is (equal '(("testnet" "/x/include2.conf" 2) ("main.foo" "/x/include2.conf" 4))
             (bl.cfg:conf-unrecognized-sections
              (format nil "# a comment~%[testnet]~%[main]~%foo.bar=1~%") "/x/include2.conf")))
  ;; Control: every chain name Core knows, as a header and as a key prefix,
  ;; names nothing unrecognized; nor does a plain key in a known section.
  (is (null (bl.cfg:conf-unrecognized-sections
             (format nil "main.rpcport=1~%[main]~%[test]~%[testnet4]~%[signet]~%[regtest]~%port=1~%")
             "bitcoin.conf")))
  (is (equal (format nil "include.conf:1 Section [testnot] is not recognized.~%~
include2.conf:1 Section [testnet] is not recognized.~%")
             (bl.cfg:unrecognized-sections-warning
              (list (format nil "testnot.datadir=1~%") (format nil "[testnet]~%"))
              '("include.conf" "include2.conf"))))
  (is (null (bl.cfg:unrecognized-sections-warning (list "regtest=1") '("bitcoin.conf")))))

(test default-data-directory-is-home-dot-bitcoin-lisp
  "Core's GetDefaultDataDir reads $HOME, falling back to / when it is unset or
empty (common/args.cpp:774-779). Ours was the literal string ~/.bitcoin-lisp/,
which nothing expands, so a node started without -datadir could not create
its lock file. The directory NAME stays ours on purpose (see the docstring):
our chainstate is not Core's, and sharing ~/.bitcoin would corrupt one node."
  (let ((saved (uiop:getenv "HOME")))
    (unwind-protect
         (progn
           (sb-posix:setenv "HOME" "/tmp/bl-home-probe/" 1)
           (is (equal "/tmp/bl-home-probe/.bitcoin-lisp/" (bl.cfg:default-data-directory)))
           (sb-posix:setenv "HOME" "" 1)
           (is (equal "/.bitcoin-lisp/" (bl.cfg:default-data-directory)))
           (is (not (find #\~ (bl.cfg:default-data-directory)))))
      (if saved
          (sb-posix:setenv "HOME" saved 1)
          (sb-posix:unsetenv "HOME")))))

(test config-section-headers-compare-exact-case
  "Core keeps a [header] exactly as written (common/config.cpp:49) and
compares it exactly (common/args.cpp:157-167), so `[Main]' is not the main
section: its keys apply to no chain and the section is warned about. Ours
lower-cased the header and applied them to mainnet."
  (is (equal '(("rpcport" . "1234"))
             (bl.cfg:parse-bitcoin-conf (format nil "[main]~%rpcport=1234~%") :mainnet)))
  (is (null (bl.cfg:parse-bitcoin-conf (format nil "[Main]~%rpcport=1234~%") :mainnet)))
  (is (equal '(("Main" "bitcoin.conf" 1))
             (bl.cfg:conf-unrecognized-sections (format nil "[Main]~%rpcport=1234~%")
                                                "bitcoin.conf"))))

(test a-repeated-wallet-option-is-cores-initwarning
  "Core's VerifyWallets loads each -wallet once and warns about every repeat,
`Ignoring duplicate -wallet w1.' (wallet/load.cpp:90-93), an InitWarning, so
on stderr; wallet_multiwallet.py:172 stops the node expecting exactly that.
Ours dropped the repeat silently."
  (let ((err (make-string-output-stream)))
    (let ((*error-output* err) (bl:*deferred-log-lines* nil))
      (is (equal '("w1" "w2") (bl:startup-wallet-names '("w1" "w1" "w2")))))
    (is (equal (format nil "Warning: Ignoring duplicate -wallet w1.~%")
               (get-output-stream-string err))))
  ;; Control: no repeat, no word.
  (let ((err (make-string-output-stream)))
    (let ((*error-output* err) (bl:*deferred-log-lines* nil))
      (is (equal '("w1" "w2") (bl:startup-wallet-names '("w1" "w2")))))
    (is (equal "" (get-output-stream-string err)))))
