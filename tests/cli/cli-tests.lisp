(in-package #:bitcoin-lisp.tests)

;;;; bitcoin-cli (src/cli/): Core's bitcoin-cli.cpp, rpc/client.cpp and univalue
;;;
;;; Everything here runs RUN-CLI -- the whole program as a function of argv --
;;; against a stub transport, so the rendering, the argument conversion, the
;;; error texts and the exit codes are checked without a server. The live
;;; half is Core's own interface_bitcoin_cli.py, run through
;;; scripts/conformance.sh.

(def-suite :cli-tests
  :description "bitcoin-cli: arguments, conversion, rendering, exit codes"
  :in :bitcoin-lisp-tests)

(in-suite :cli-tests)

;;; --- Fixtures ---

(defvar *cli-calls* nil
  "Every call the stub transport saw, newest first: (host port path headers body).")

(defun %cli-request-method (body)
  "The method (or the list of methods, for a batch) of a request BODY."
  (let ((request (bl.cli:uv-read body)))
    (if (eq (car request) :arr)
        (mapcar (lambda (r) (bl.cli:uv-get r "method")) (cdr request))
        (bl.cli:uv-get request "method"))))

(defun %cli-stub (replies)
  "A transport answering each request from REPLIES, an alist of method (or
list of methods, for a batch) to (status . body-text) or to a function of the
request body returning one. A method it does not know is a 404 -32601."
  (lambda (host port path headers body timeout)
    (declare (ignore timeout))
    (push (list host port path headers body) *cli-calls*)
    (let* ((method (%cli-request-method body))
           (reply (cdr (assoc method replies :test #'equal))))
      (when (functionp reply) (setf reply (funcall reply body)))
      (if reply
          (values (car reply) (cdr reply))
          (values 404 "{\"result\":null,\"error\":{\"code\":-32601,\"message\":\"Method not found\"},\"id\":1}")))))

(defmacro with-cli-datadir ((dir &key (conf "regtest=1
[regtest]
rpcport=18555
") (cookie "__cookie__:secret")) &body body)
  "BODY with DIR a data directory holding bitcoin.conf CONF and, when COOKIE is
non-NIL, a regtest/.cookie with that content."
  `(with-temp-directory (,dir "bl-cli")
     (with-open-file (out (merge-pathnames "bitcoin.conf" ,dir) :direction :output)
       (write-string ,conf out))
     (when ,cookie
       (let ((path (merge-pathnames "regtest/.cookie" ,dir)))
         (ensure-directories-exist path)
         (with-open-file (out path :direction :output) (write-string ,cookie out))))
     ,@body))

(defun %cli (dir replies &rest args)
  "RUN-CLI with -datadir=DIR and ARGS against a stub answering REPLIES:
 (values stdout stderr code)."
  (let ((*cli-calls* nil)
        (bl.cli:*cli-transport* (%cli-stub replies)))
    (bl.cli:run-cli (cons (format nil "-datadir=~A" (namestring dir)) args))))

(defun %ok (json) (cons 200 (format nil "{\"result\":~A,\"error\":null,\"id\":1}" json)))

(defun %rpc-err (status code message)
  (cons status (format nil "{\"result\":null,\"error\":{\"code\":~D,\"message\":\"~A\"},\"id\":1}"
                       code message)))

;;; --- UniValue (univalue_read.cpp / univalue_write.cpp) ---

(test univalue-pretty-print-is-core-s-write-2
  "Core prints a result with UniValue::write(2): two spaces a level, `\"key\": '
with one space, and an EMPTY array or object still opened and closed on two
lines -- `[' newline `]' -- because writeArray emits the newline and the
closing indent unconditionally. A number is written back as the text it was
read from, so 2.50 stays 2.50 and an exponent stays an exponent."
  (is (string= (format nil "{~%  \"a\": [~%    1,~%    2.50,~%    {~%    }~%  ],~%  \"b\": [~%  ],~%  \"c\": 4.656542373906925e-10,~%  \"d\": null,~%  \"e\": true~%}")
               (bl.cli:uv-write (bl.cli:uv-read "{\"a\":[1,2.50,{}],\"b\":[],\"c\":4.656542373906925e-10,\"d\":null,\"e\":true}") 2)))
  (is (string= (format nil "[~%]") (bl.cli:uv-write (bl.cli:uv-read "[]") 2)))
  (is (string= "{\"a\":[1,\"x\"]}" (bl.cli:uv-write (bl.cli:uv-read " { \"a\" : [ 1 , \"x\" ] } ")))))

(test univalue-escapes-are-core-s-table
  "json_escape: the five short escapes, \\uXXXX for the other control
characters and DEL, and everything else -- `/' and non-ASCII included -- raw."
  (is (string= (format nil "\"a\\\"b\\\\c\\n\\t\\u0001\\u007f/~C\"" (code-char #xe9))
               (bl.cli:uv-write (coerce (list #\a #\" #\b #\\ #\c (code-char 10) (code-char 9)
                                              (code-char 1) (code-char 127) #\/ (code-char #xe9))
                                        'string))))
  (is (string= (coerce (list (code-char #x1F600)) 'string)
               (bl.cli:uv-read "\"\\ud83d\\ude00\""))))

(test univalue-read-is-strict-json
  "UniValue::read refuses what strict JSON refuses -- a trailing comma, a
leading zero, a bare word, a control character inside a string, a lone
surrogate, anything after the value -- and accepts any value at the top."
  (dolist (bad '("[1,]" "{\"a\":1,}" "01" "foo" "[1] x" "\"a
b\"" "\"\\ud800\"" "1." "-" "" "{\"a\"}" "[,1]"))
    (is (eq :failed (handler-case (progn (bl.cli:uv-read bad) :parsed)
                      (bl.cli:json-parse-failure () :failed)))
        "~S should not parse" bad))
  (is (equal '(:num . "-0.5e+3") (bl.cli:uv-read "-0.5e+3")))
  (is (string= "x" (bl.cli:uv-read " \"x\" ")))
  (is (eq :false (bl.cli:uv-read "false"))))

;;; --- Argument conversion (rpc/client.cpp) ---

(test positional-arguments-convert-by-core-s-table
  "RPCConvertValues: an argument is JSON only where vRPCConvertParams lists
its (method, position); everything else is sent as a string, even when it
looks like a number."
  (is (string= "[5]" (bl.cli:uv-write (bl.cli:rpc-convert-values "getblockhash" '("5")))))
  (is (string= "[\"1\",\"2\"]" (bl.cli:uv-write (bl.cli:rpc-convert-values "echo" '("1" "2")))))
  ;; JSON_OR_STRING: a hash is not JSON and goes as the string it is.
  (is (string= "[\"00ab\"]" (bl.cli:uv-write (bl.cli:rpc-convert-values "getblockstats" '("00ab")))))
  (is (string= "[101]" (bl.cli:uv-write (bl.cli:rpc-convert-values "getblockstats" '("101")))))
  (is (string= "Error parsing JSON: foo"
               (handler-case (bl.cli:rpc-convert-values "generatetoaddress" '("foo" "addr"))
                 (error (e) (princ-to-string e)))))
  (is (= 331 (length bl.cli:*rpc-convert-params*))))

(test named-arguments-follow-rpcconvertnamedvalues
  "RPCConvertNamedValues, on interface_bitcoin_cli.py's cases: bare arguments
are positional and go last under args; NAME=VALUE is named unless NAME is
unknown and the next positional slot is a JSON one the whole argument parses
as (echojson [\"key=value\"]) or a string one (createwallet my=wallet); a
later name overwrites an earlier one; an explicit args= meeting positional
arguments is sent TWICE, for the server to refuse (pushKVEnd appends)."
  (flet ((named (method &rest args)
           (bl.cli:uv-write (bl.cli:rpc-convert-named-values method args))))
    (is (string= "{\"arg3\":\"3\",\"arg5\":\"5\",\"args\":[\"0\",\"1\"]}"
                 (named "echo" "0" "1" "arg3=3" "arg5=5")))
    (is (string= "{\"arg0\":\"0\",\"arg1\":\"3\",\"arg2\":\"2\"}"
                 (named "echo" "arg0=0" "arg1=1" "arg2=2" "arg1=3")))
    (is (string= "{\"args\":[[\"key=value\"],42]}" (named "echojson" "[\"key=value\"]" "42")))
    (is (string= "{\"arg0\":[\"data=test\"],\"arg1\":42}"
                 (named "echojson" "arg0=[\"data=test\"]" "arg1=42")))
    (is (string= "{\"args\":[\"my=wallet\"]}" (named "createwallet" "my=wallet")))
    (is (string= "{\"args\":\"[0,1,2,3]\",\"args\":[\"4\",\"5\"]}"
                 (named "echo" "args=[0,1,2,3]" "4" "5")))))

;;; --- The command line (ParseParameters) ---

(test command-line-refusals-are-core-s
  "An unknown option, a section-scoped key and a forbidden negation stop the
client with EXIT_FAILURE and Core's text; option names are case-sensitive, and
--name is -name."
  (flet ((err (&rest args)
           (multiple-value-bind (out err code) (bl.cli:run-cli args)
             (declare (ignore out))
             (list err code))))
    (is (equal (list (format nil "Error parsing command line arguments: Invalid parameter -foo~%") 1)
               (err "-foo" "getblockcount")))
    (is (equal (list (format nil "Error parsing command line arguments: Invalid parameter -RPCPORT=1~%") 1)
               (err "-RPCPORT=1" "getblockcount")))
    (is (equal (list (format nil "Error parsing command line arguments: Invalid parameter -regtest.rpcport=1~%") 1)
               (err "-regtest.rpcport=1" "getblockcount")))
    (is (equal (list (format nil "Error parsing command line arguments: Negating of -datadir is meaningless and therefore forbidden~%") 1)
               (err "-nodatadir" "getblockcount")))
    (is (equal (list (format nil "Error: Specified data directory \"/nonexistent-bl-cli\" does not exist.~%") 1)
               (err "-datadir=/nonexistent-bl-cli" "getblockcount")))))

(test no-arguments-prints-usage-and-fails
  "AppInitRPC: with no arguments the usage goes to stdout, `Error: too few
parameters' to stderr, and the status is EXIT_FAILURE; -version and -help
print and succeed."
  (multiple-value-bind (out err code) (bl.cli:run-cli nil)
    (is (search "Usage: bitcoin-cli [options] <command> [params]" out))
    (is (string= (format nil "Error: too few parameters~%") err))
    (is (= 1 code)))
  (multiple-value-bind (out err code) (bl.cli:run-cli '("-version"))
    (is (search "bitcoin-lisp RPC client version v" out))
    (is (string= "" err))
    (is (= 0 code)))
  (is (= 0 (nth-value 2 (bl.cli:run-cli '("-h"))))))

;;; --- A call, its reply and its exit code ---

(test a-result-prints-as-core-prints-it
  "ParseResult: an object pretty-printed, a string bare (no quotes), a null
result nothing at all; the status is 0 and the request is JSON-RPC 2.0 with
id 1 to `/', authorised by the cookie."
  (with-cli-datadir (dir)
    (let ((*cli-calls* nil))
      (let ((bl.cli:*cli-transport* (%cli-stub (list (cons "getblockchaininfo" (%ok "{\"chain\":\"regtest\",\"blocks\":101}"))))))
        (multiple-value-bind (out err code) (bl.cli:run-cli (list (format nil "-datadir=~A" (namestring dir)) "getblockchaininfo"))
          (is (string= (format nil "{~%  \"chain\": \"regtest\",~%  \"blocks\": 101~%}~%") out))
          (is (string= "" err))
          (is (= 0 code))))
      (destructuring-bind (host port path headers body) (first *cli-calls*)
        (is (string= "127.0.0.1" host))
        (is (= 18555 port))             ; [regtest] rpcport= in bitcoin.conf
        (is (string= "/" path))
        (is (string= (format nil "Basic ~A" (cl-base64:string-to-base64-string "__cookie__:secret"))
                     (cdr (assoc "Authorization" headers :test #'string=))))
        (is (string= (format nil "{\"method\":\"getblockchaininfo\",\"params\":[],\"id\":1,\"jsonrpc\":\"2.0\"}~%")
                     body)))))
  (with-cli-datadir (dir)
    (is (equal (list (format nil "00ff~%") "" 0)
               (multiple-value-list (%cli dir (list (cons "getblockhash" (%ok "\"00ff\""))) "getblockhash" "0"))))
    (is (equal (list "" "" 0)
               (multiple-value-list (%cli dir (list (cons "echo" (%ok "null"))) "echo"))))))

(test an-rpc-error-exits-with-its-code
  "ParseError: `error code: N' and `error message:' on stderr -- the shape
the framework's TestNodeCLI matches -- and the absolute value of the code as
the exit status; -19 gains the CLI's own hint."
  (with-cli-datadir (dir)
    (is (equal (list "" (format nil "error code: -8~%error message:~%Parameter arg1 specified twice~%") 8)
               (multiple-value-list
                (%cli dir (list (cons "echo" (%rpc-err 500 -8 "Parameter arg1 specified twice"))) "echo"))))
    (multiple-value-bind (out err code)
        (%cli dir (list (cons "getbalance" (%rpc-err 500 -19 "Multiple wallets are loaded.")))
              "getbalance")
      (declare (ignore out))
      (is (= 19 code))
      (is (search "Multiple wallets are loaded. Or for the CLI, specify the \"-rpcwallet=<walletname>\" option before the command" err)))))

(test http-failures-are-core-s-texts
  "CallRPC's HTTP half: 401 is `Incorrect rpcuser or rpcpassword' when there
were credentials and `Could not locate RPC credentials' when the cookie could
not be read; no reply at all is a transient connection failure; all three
exit 1."
  (with-cli-datadir (dir)
    (multiple-value-bind (out err code)
        (%cli dir (list (cons "echo" (cons 401 ""))) "-rpcuser=u" "-rpcpassword=p" "echo")
      (declare (ignore out))
      (is (string= (format nil "error: Authorization failed: Incorrect rpcuser or rpcpassword~%") err))
      (is (= 1 code)))
    (multiple-value-bind (out err code)
        (%cli dir (list (cons "echo" (cons 401 ""))) "-rpccookiefile=does-not-exist" "-rpcpassword=" "echo")
      (declare (ignore out))
      (is (uiop:string-prefix-p "error: Could not locate RPC credentials. No authentication cookie could be found" err))
      (is (= 1 code)))
    (let ((bl.cli:*cli-transport*
            (lambda (&rest args) (declare (ignore args))
              (error 'bl.cli:cli-transport-failure :code 1))))
      (multiple-value-bind (out err code)
          (bl.cli:run-cli (list (format nil "-datadir=~A" (namestring dir)) "-rpcport=1" "echo"))
        (declare (ignore out))
        (is (uiop:string-prefix-p "error: timeout on transient error: Could not connect to the server 127.0.0.1:1 (error code 1 - \"EOF reached\")" err))
        (is (= 1 code))))))

(test ports-are-chosen-and-refused-as-in-core
  "-rpcport beats a port in -rpcconnect, which beats the chain default; an
invalid port in either is refused naming the argument as given."
  (with-cli-datadir (dir :conf "regtest=1
")
    (flet ((port-of (&rest args)
             (let ((*cli-calls* nil)
                   (bl.cli:*cli-transport* (%cli-stub (list (cons "echo" (%ok "[]"))))))
               (bl.cli:run-cli (append (list (format nil "-datadir=~A" (namestring dir))) args (list "echo")))
               (second (first *cli-calls*))))
           (err (&rest args)
             (nth-value 1 (%cli dir nil (first args) "echo"))))
      (is (= 18443 (port-of)))
      (is (= 18999 (port-of "-rpcconnect=127.0.0.1:18999")))
      (is (= 18000 (port-of "-rpcconnect=127.0.0.1:18999" "-rpcport=18000")))
      (dolist (bad '("notaport" "-1" "0" "65536"))
        (is (string= (format nil "error: Invalid port provided in -rpcport: ~A~%" bad)
                     (err (format nil "-rpcport=~A" bad))))
        (is (string= (format nil "error: Invalid port provided in -rpcconnect: 127.0.0.1:~A~%" bad)
                     (err (format nil "-rpcconnect=127.0.0.1:~A" bad)))))))
  (is (equal '("::1" 8332 t) (multiple-value-list (bl.cli:split-rpc-host-port "[::1]:8332"))))
  (is (equal '("::1" 0 t) (multiple-value-list (bl.cli:split-rpc-host-port "::1")))))

(test network-only-rpcport-ignores-the-default-section-off-mainnet
  "-rpcport is NETWORK_ONLY: on regtest a default-section rpcport= is not
read, the [regtest] one is; and conf= inside the file is refused."
  (with-cli-datadir (dir :conf "regtest=1
rpcport=7777
")
    (let ((*cli-calls* nil)
          (bl.cli:*cli-transport* (%cli-stub (list (cons "echo" (%ok "[]"))))))
      (bl.cli:run-cli (list (format nil "-datadir=~A" (namestring dir)) "echo"))
      (is (= 18443 (second (first *cli-calls*))))))
  (with-cli-datadir (dir :conf "conf=other.conf
")
    (is (string= (format nil "Error reading configuration file: conf cannot be set in the configuration file; use includeconf= if you want to include additional config files~%")
                 (nth-value 1 (%cli dir nil "echo"))))))

(test stdin-options-read-standard-input
  "-stdinrpcpass takes the first line as the password; -stdin appends every
further line as an argument."
  (with-cli-datadir (dir)
    (let ((*cli-calls* nil)
          (bl.cli:*cli-transport* (%cli-stub (list (cons "echo" (%ok "[\"foo\",\"bar\"]"))))))
      (bl.cli:run-cli (list (format nil "-datadir=~A" (namestring dir)) "-rpcuser=u" "-stdin" "-stdinrpcpass" "echo")
                      :stdin (make-string-input-stream (format nil "pw~%foo~%bar")))
      (destructuring-bind (host port path headers body) (first *cli-calls*)
        (declare (ignore host port path))
        (is (string= (format nil "Basic ~A" (cl-base64:string-to-base64-string "u:pw"))
                     (cdr (assoc "Authorization" headers :test #'string=))))
        (is (search "\"params\":[\"foo\",\"bar\"]" body))))))

(test rpcwallet-picks-the-endpoint
  "-rpcwallet=NAME posts to /wallet/<uri-encoded NAME>; -norpcwallet is no
wallet at all, not a wallet called 0."
  (with-cli-datadir (dir)
    (flet ((path-of (&rest args)
             (let ((*cli-calls* nil)
                   (bl.cli:*cli-transport* (%cli-stub (list (cons "getbalance" (%ok "1.0"))))))
               (bl.cli:run-cli (append (list (format nil "-datadir=~A" (namestring dir))) args (list "getbalance")))
               (third (first *cli-calls*)))))
      (is (string= "/wallet/my%20wallet%2F1" (path-of "-rpcwallet=my wallet/1")))
      (is (string= "/" (path-of "-norpcwallet"))))))

(test rpcwait-retries-a-warming-server
  "ConnectAndCallRPC: under -rpcwait an in-warmup reply (-28) is retried, and
the first real answer is printed."
  (with-cli-datadir (dir)
    (let ((n 0))
      (multiple-value-bind (out err code)
          (%cli dir (list (cons "getblockcount"
                                (lambda (body) (declare (ignore body))
                                  (if (< (incf n) 2)
                                      (%rpc-err 500 -28 "Loading block index...")
                                      (%ok "126")))))
                "-rpcwait" "getblockcount")
        (is (string= (format nil "126~%") out))
        (is (string= "" err))
        (is (= 0 code))
        (is (= 2 n))))))

(test generate-is-getnewaddress-then-generatetoaddress
  "-generate: the address from getnewaddress goes second, nblocks defaults to
1, and the bad-argument texts are Core's."
  (with-cli-datadir (dir)
    (let ((replies (list (cons "getnewaddress" (%ok "\"bcrt1qaddr\""))
                         (cons "generatetoaddress"
                               (lambda (body)
                                 (%ok (bl.cli:uv-write (bl.cli:uv-get (bl.cli:uv-read body) "params"))))))))
      (is (string= (format nil "{~%  \"address\": \"bcrt1qaddr\",~%  \"blocks\": [~%    1,~%    \"bcrt1qaddr\"~%  ]~%}~%")
                   (%cli dir replies "-generate")))
      (is (search "4," (%cli dir replies "-generate" "4" "1000")))
      (is (equal (list "" (format nil "error: Error parsing JSON: foo~%") 1)
                 (multiple-value-list (%cli dir replies "-generate" "foo"))))
      (is (equal (list "" (format nil "error: the first argument (number of blocks to generate, default: 1) must be an integer value greater than zero~%") 1)
                 (multiple-value-list (%cli dir replies "-generate" "0"))))
      (is (equal (list "" (format nil "error: too many arguments (maximum 2 for nblocks and maxtries)~%") 1)
                 (multiple-value-list (%cli dir replies "-generate" "1" "2" "3")))))))

(defun %getinfo-replies ()
  (list (cons (list "getnetworkinfo" "getblockchaininfo" "getwalletinfo" "getbalances")
              (cons 200 "[{\"result\":{\"version\":100,\"timeoffset\":0,\"connections\":0,\"connections_in\":0,\"connections_out\":0,\"networks\":[{\"name\":\"ipv4\",\"proxy\":\"127.0.0.1:9050\"},{\"name\":\"ipv6\",\"proxy\":\"127.0.0.1:9050\"},{\"name\":\"i2p\",\"proxy\":\"127.0.0.1:7656\"}],\"relayfee\":0.00001000,\"warnings\":[]},\"error\":null,\"id\":0},{\"result\":{\"chain\":\"regtest\",\"blocks\":101,\"headers\":101,\"verificationprogress\":1,\"difficulty\":4.656542373906925e-10},\"error\":null,\"id\":1},{\"result\":{\"walletname\":\"\",\"keypoolsize\":1},\"error\":null,\"id\":2},{\"result\":{\"mine\":{\"trusted\":50.00000000}},\"error\":null,\"id\":3}]"))
        (cons "listwallets" (%ok "[\"\"]"))))

(test getinfo-renders-core-s-dashboard
  "-getinfo: one batch of four calls, rendered as ParseGetInfoResult's lines;
-color=always adds the ANSI codes, -color=never does not, and another value
is refused."
  (with-cli-datadir (dir)
    (multiple-value-bind (out err code) (%cli dir (%getinfo-replies) "-getinfo" "-color=never")
      (is (string= "" err))
      (is (= 0 code))
      (is (search (format nil "Chain: regtest~%Blocks: 101~%Headers: 101~%Verification progress: 100.0000%~%Difficulty: 4.656542373906925e-10~%~%Network: in 0, out 0, total 0~%Version: 100~%Time offset (s): 0~%Proxies: 127.0.0.1:9050 (ipv4, ipv6), 127.0.0.1:7656 (i2p)~%Min tx relay fee rate (BTC/kvB): 0.00001000~%~%Wallet: \"\"~%Keypool size: 1~%Balance: 50.00000000~%~%Warnings: (none)~%") out))
      (is (not (find (code-char 27) out))))
    (is (search (format nil "~C[0m" (code-char 27)) (%cli dir (%getinfo-replies) "-getinfo" "-color=always")))
    (is (equal (list "" (format nil "error: Invalid value for -color option. Valid values: always, auto, never.~%") 1)
               (multiple-value-list (%cli dir (%getinfo-replies) "-getinfo" "-color=foo"))))
    (is (equal (list "" (format nil "error: -getinfo takes no arguments~%") 1)
               (multiple-value-list (%cli dir (%getinfo-replies) "-getinfo" "help"))))
    (is (equal (list "" (format nil "error: Only one of -getinfo, -netinfo may be specified.~%") 1)
               (multiple-value-list (%cli dir nil "-getinfo" "-netinfo"))))))

(test netinfo-header-carries-the-services-only-with-details
  "-netinfo: the header names the client, the chain and the server; the
local services are a line of their own at level 0 and move into the header,
as letters, at level 1 (interface_bitcoin_cli.py:92-104)."
  (with-cli-datadir (dir)
    (let ((replies (list (cons (list "getpeerinfo" "getnetworkinfo")
                               (cons 200 "[{\"result\":[],\"error\":null,\"id\":0},{\"result\":{\"version\":100,\"subversion\":\"/bitcoin-lisp:0.1.0/\",\"protocolversion\":70016,\"localservicesnames\":[\"NETWORK\",\"WITNESS\",\"NETWORK_LIMITED\"],\"networks\":[{\"name\":\"ipv4\",\"reachable\":true}],\"localaddresses\":[]},\"error\":null,\"id\":1}]")))))
      (let ((level0 (%cli dir replies "-netinfo"))
            (level1 (%cli dir replies "-netinfo" "1")))
        (is (uiop:string-prefix-p "bitcoin-lisp client v" level0))
        (is (search " regtest - server 70016/bitcoin-lisp:0.1.0/" (first (uiop:split-string level0 :separator '(#\Newline)))))
        (is (search "Local services: network, witness, network limited" level0))
        (is (uiop:string-suffix-p (first (uiop:split-string level1 :separator '(#\Newline))) " - services nwl"))
        (is (not (search "Local services:" level1)))))))

(test the-executable-is-the-client-under-its-name
  "node-main runs the client when argv[0] is bitcoin-cli, whatever directory
it was started from, and the node for any other name."
  (is-true (bl.cli:cli-program-name-p "/workspace/build/bin/bitcoin-cli"))
  (is-true (bl.cli:cli-program-name-p "bitcoin-cli"))
  (is-false (bl.cli:cli-program-name-p "/workspace/build/bin/bitcoind"))
  (is-false (bl.cli:cli-program-name-p "bitcoin-cli-old"))
  (is (string= "abc-._~%2F%C3%A9" (bl.cli:uri-encode (format nil "abc-._~~/~C" (code-char #xe9))))))
