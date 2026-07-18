(in-package #:bitcoin-lisp.tests)

;;; Web UI serving + RPC auth plumbing tests (docs/gui-plan.md P0):
;;; /ui/ path canonicalization, content types, disabled-flag behavior,
;;; the RPC Origin check, and a live-acceptor end-to-end pass.

(def-suite ui-tests
  :description "Web UI /ui/ serving + Origin-check plumbing (gui-plan P0)"
  :in :bitcoin-lisp-tests)

(in-suite ui-tests)

;;; --- Path canonicalization (%ui-resolve) ---

(test ui-resolve-rejects-traversal
  "Any path component that could escape the UI directory resolves to NIL:
dot-dot, absolute paths, dotfiles, backslashes, wildcards, empty segments."
  (let ((bitcoin-lisp.rpc::*ui-directory* #P"/tmp/ui-test/"))
    (dolist (bad '("../src/config.lisp"
                   "js/../../bitcoin-lisp.asd"
                   "js/../rpc.js"
                   ".."
                   "."
                   ".hidden"
                   "js/.hidden"
                   "/etc/passwd"
                   "js//rpc.js"
                   "js/"
                   "a\\b.js"
                   "*.lisp"
                   "js?.js"
                   "c:evil.js"
                   "a b.js"))
      (is (null (bitcoin-lisp.rpc::%ui-resolve bad))
          "path ~S must not resolve" bad))))

(test ui-resolve-accepts-safe-paths
  "Safe paths resolve to files under the UI directory; \"\" is index.html."
  (let ((bitcoin-lisp.rpc::*ui-directory* #P"/tmp/ui-test/"))
    (let ((index (bitcoin-lisp.rpc::%ui-resolve "")))
      (is (equal "index" (pathname-name index)))
      (is (equal "html" (pathname-type index))))
    (let ((nested (bitcoin-lisp.rpc::%ui-resolve "js/rpc.js")))
      (is (equal "rpc" (pathname-name nested)))
      (is (equal "js" (pathname-type nested)))
      ;; stays under the UI root, in its js/ subdirectory
      (is (equal "js" (car (last (pathname-directory nested)))))
      (is (alexandria:starts-with-subseq
           (namestring bitcoin-lisp.rpc::*ui-directory*)
           (namestring nested))))
    ;; interior dots are fine (app.min.js)
    (let ((minified (bitcoin-lisp.rpc::%ui-resolve "app.min.js")))
      (is (equal "app.min" (pathname-name minified)))
      (is (equal "js" (pathname-type minified))))))

;;; --- ui-handle: status codes + content types (against the repo ui/) ---

(defmacro with-ui-reply ((&key (enabled t) directory) &body body)
  "Run BODY with a fresh hunchentoot reply and the UI specials bound."
  `(let ((hunchentoot:*reply* (make-instance 'hunchentoot:reply))
         (bitcoin-lisp.rpc::*ui-enabled* ,enabled)
         (bitcoin-lisp.rpc::*ui-directory* ,directory))
     ,@body))

(test ui-handle-serves-index-and-content-types
  "/ui/ serves index.html as text/html; .js and .css get their types."
  (with-ui-reply ()
    (let ((body (bitcoin-lisp.rpc::ui-handle "/ui/")))
      (is (= 200 (hunchentoot:return-code*)))
      (is (alexandria:starts-with-subseq "text/html" (hunchentoot:content-type*)))
      (is (typep body '(vector (unsigned-byte 8))))
      (is (search "<title>" (flexi-streams:octets-to-string body :external-format :utf-8)))))
  (with-ui-reply ()
    (bitcoin-lisp.rpc::ui-handle "/ui/style.css")
    (is (= 200 (hunchentoot:return-code*)))
    (is (alexandria:starts-with-subseq "text/css" (hunchentoot:content-type*))))
  (with-ui-reply ()
    (bitcoin-lisp.rpc::ui-handle "/ui/js/rpc.js")
    (is (= 200 (hunchentoot:return-code*)))
    (is (alexandria:starts-with-subseq "text/javascript" (hunchentoot:content-type*)))))

(test ui-handle-serves-explorer-assets
  "The P2 explorer modules are served with the JS content type, and the
shell wires in the explorer views + universal search box."
  (dolist (path '("/ui/js/router.js" "/ui/js/explorer.js"))
    (with-ui-reply ()
      (let ((body (bitcoin-lisp.rpc::ui-handle path)))
        (is (= 200 (hunchentoot:return-code*)) "~S must be served" path)
        (is (alexandria:starts-with-subseq "text/javascript"
                                           (hunchentoot:content-type*)))
        (is (plusp (length body))))))
  (with-ui-reply ()
    (let* ((body (bitcoin-lisp.rpc::ui-handle "/ui/index.html"))
           (html (flexi-streams:octets-to-string body :external-format :utf-8)))
      (is (search "view-block" html))
      (is (search "view-tx" html))
      (is (search "view-explorer" html))
      (is (search "search-form" html)))))

(test ui-handle-serves-peers-assets
  "The P3 peers module is served with the JS content type, the shell wires
in the peers view + nav link + networking-disabled banner, and every RPC
method the page calls is a registered dispatcher method. (The page's
rendering/sort/action behavior is covered by the zero-dependency node
harness in tests/ui/peers.test.mjs — run: node --test tests/ui/peers.test.mjs.)"
  (with-ui-reply ()
    (let ((body (bitcoin-lisp.rpc::ui-handle "/ui/js/peers.js")))
      (is (= 200 (hunchentoot:return-code*)))
      (is (alexandria:starts-with-subseq "text/javascript"
                                         (hunchentoot:content-type*)))
      (is (plusp (length body)))))
  (with-ui-reply ()
    (let* ((body (bitcoin-lisp.rpc::ui-handle "/ui/index.html"))
           (html (flexi-streams:octets-to-string body :external-format :utf-8)))
      (is (search "view-peers" html))
      (is (search "#/peers" html))
      (is (search "net-banner" html))))
  (bitcoin-lisp.rpc::register-all-methods)
  (dolist (method '("getpeerinfo" "listbanned" "setban" "disconnectnode"
                    "setnetworkactive" "getnetworkinfo"))
    (is (not (null (gethash method bitcoin-lisp.rpc::*rpc-methods*)))
        "RPC method ~S (called by the peers page) must be registered" method)))

(test ui-handle-serves-console-assets
  "The P4 console module is served with the JS content type, the shell wires
in the console view + nav link, and `help` — the one RPC the page's
autocomplete depends on — is registered and emits the newline-separated
list of registered method names the page parses. (The page's parsing/
autocomplete/history/rendering behavior is covered by the zero-dependency
node harness in tests/ui/console.test.mjs — run: node --test
tests/ui/console.test.mjs.)"
  (with-ui-reply ()
    (let ((body (bitcoin-lisp.rpc::ui-handle "/ui/js/console.js")))
      (is (= 200 (hunchentoot:return-code*)))
      (is (alexandria:starts-with-subseq "text/javascript"
                                         (hunchentoot:content-type*)))
      (is (plusp (length body)))))
  (with-ui-reply ()
    (let* ((body (bitcoin-lisp.rpc::ui-handle "/ui/index.html"))
           (html (flexi-streams:octets-to-string body :external-format :utf-8)))
      (is (search "view-console" html))
      (is (search "#/console" html))))
  (bitcoin-lisp.rpc::register-all-methods)
  (is (not (null (gethash "help" bitcoin-lisp.rpc::*rpc-methods*)))
      "RPC method \"help\" (the console's autocomplete source) must be registered")
  ;; help with no params: one registered method name per line, sorted —
  ;; exactly the format console.js parseHelpText consumes.
  (let* ((text (bitcoin-lisp.rpc::rpc-help nil nil))
         (lines (uiop:split-string text :separator '(#\Newline))))
    (is (stringp text))
    (is (< 1 (length lines)))
    (is (member "getblockcount" lines :test #'string=))
    (is (member "help" lines :test #'string=))
    (is (notany (lambda (line)
                  (or (zerop (length line)) (find #\Space line)))
                lines)
        "every help line must be a single bare method name")
    (is (every (lambda (line)
                 (nth-value 1 (gethash line bitcoin-lisp.rpc::*rpc-methods*)))
               lines)
        "every help line must be a registered method")
    (is (equal lines (sort (copy-list lines) #'string<)))))

(test ui-handle-serves-wallet-assets
  "The P6a wallet + QR modules are served with the JS content type, the
shell wires in the wallet view + nav link, every RPC method the page calls
is a registered dispatcher method, and the /wallet/<name> endpoint parsing
the page's endpoint-aware rpc.js relies on resolves names. (The page's
selector/overview/receive/history/address-book behavior is covered by the
zero-dependency node harness in tests/ui/wallet.test.mjs, and the QR
encoder byte-exactly against reference vectors in tests/ui/qr.test.mjs —
run: node --test tests/ui/wallet.test.mjs tests/ui/qr.test.mjs.)"
  (dolist (path '("/ui/js/wallet.js" "/ui/js/qr.js"))
    (with-ui-reply ()
      (let ((body (bitcoin-lisp.rpc::ui-handle path)))
        (is (= 200 (hunchentoot:return-code*)) "~S must be served" path)
        (is (alexandria:starts-with-subseq "text/javascript"
                                           (hunchentoot:content-type*)))
        (is (plusp (length body))))))
  (with-ui-reply ()
    (let* ((body (bitcoin-lisp.rpc::ui-handle "/ui/index.html"))
           (html (flexi-streams:octets-to-string body :external-format :utf-8)))
      (is (search "view-wallet" html))
      (is (search "#/wallet" html))))
  (bitcoin-lisp.rpc::register-all-methods)
  (dolist (method '("listwallets" "listwalletdir" "loadwallet"
                    "getbalances" "getwalletinfo" "getblockcount"
                    "getnewaddress" "getaddressinfo"
                    "listtransactions" "gettransaction"
                    "listlabels" "getaddressesbylabel" "setlabel"))
    (is (not (null (gethash method bitcoin-lisp.rpc::*rpc-methods*)))
        "RPC method ~S (called by the wallet page) must be registered" method))
  ;; The page pins every wallet RPC to /wallet/<name>; the URI parsing it
  ;; rides must resolve names (and leave the base endpoint wallet-less).
  (is (equal "w1" (bitcoin-lisp.rpc::wallet-name-from-uri "/wallet/w1")))
  (is (null (bitcoin-lisp.rpc::wallet-name-from-uri "/")))
  (is (null (bitcoin-lisp.rpc::wallet-name-from-uri "/wallet/"))))

(test ui-handle-404s
  "Missing files, traversal attempts, and directories are all 404."
  (dolist (path '("/ui/nope.js"
                  "/ui/../src/rpc/server.lisp"
                  "/ui/js/../../bitcoin-lisp.asd"
                  "/ui/js"                       ; a directory, not a file
                  "/ui/js/"
                  "/ui/.git"))
    (with-ui-reply ()
      (bitcoin-lisp.rpc::ui-handle path)
      (is (= 404 (hunchentoot:return-code*)) "~S must 404" path))))

(test ui-handle-disabled-is-404
  "Flag off => /ui/ 404s even if the handler is somehow reached (the
dispatcher is additionally not registered at all when disabled)."
  (with-ui-reply (:enabled nil)
    (bitcoin-lisp.rpc::ui-handle "/ui/")
    (is (= 404 (hunchentoot:return-code*)))))

(test ui-handle-bare-prefix-redirects
  "/ui (no slash) 301s to /ui/ so relative asset URLs resolve."
  (with-ui-reply ()
    (bitcoin-lisp.rpc::ui-handle "/ui")
    (is (= 301 (hunchentoot:return-code*)))
    (is (string= "/ui/" (hunchentoot:header-out :location)))))

;;; --- Origin check (pure) ---

(test rpc-origin-check
  "Absent Origin always passes; a same-authority Origin passes; anything
else (foreign authority, \"null\", junk) is rejected."
  ;; curl / bitcoin-cli: no Origin header
  (is-true (bitcoin-lisp.rpc::rpc-origin-allowed-p nil "localhost:18332"))
  (is-true (bitcoin-lisp.rpc::rpc-origin-allowed-p nil nil))
  ;; same-origin browser POST
  (is-true (bitcoin-lisp.rpc::rpc-origin-allowed-p
            "http://localhost:18332" "localhost:18332"))
  (is-true (bitcoin-lisp.rpc::rpc-origin-allowed-p
            "http://127.0.0.1:8332" "127.0.0.1:8332"))
  ;; case-insensitive authority
  (is-true (bitcoin-lisp.rpc::rpc-origin-allowed-p
            "http://LOCALHOST:18332" "localhost:18332"))
  ;; hostile page
  (is-false (bitcoin-lisp.rpc::rpc-origin-allowed-p
             "http://evil.example" "localhost:18332"))
  (is-false (bitcoin-lisp.rpc::rpc-origin-allowed-p
             "http://localhost:1234" "localhost:18332"))
  ;; sandboxed iframe / data: URLs send the literal string "null"
  (is-false (bitcoin-lisp.rpc::rpc-origin-allowed-p "null" "localhost:18332"))
  ;; junk / missing Host
  (is-false (bitcoin-lisp.rpc::rpc-origin-allowed-p "garbage" "localhost:18332"))
  (is-false (bitcoin-lisp.rpc::rpc-origin-allowed-p "http://x" nil)))

;;; --- Config plumbing (-webui / -webuipath / -webuiopen) ---

(test webui-config-plumbing
  "-webui/-webuipath/-webuiopen map onto start-node keywords; -nowebui is a
supplied-but-false :webui; nothing is supplied when the flags are absent."
  (let ((plist (bitcoin-lisp::args->start-node-plist
                '("-regtest" "-webui" "-webuiopen" "-webuipath=/x/ui/" "-rpcport=1"))))
    (is (eq t (getf plist :webui)))
    (is (eq t (getf plist :webui-open)))
    (is (string= "/x/ui/" (getf plist :webui-path))))
  (let ((plist (bitcoin-lisp::args->start-node-plist '("-regtest" "-nowebui"))))
    (is (null (getf plist :webui)))
    (is (not (null (member :webui plist)))))
  (let ((plist (bitcoin-lisp::args->start-node-plist '("-regtest"))))
    (is (null (member :webui plist)))
    (is (null (member :webui-open plist)))))

;;; --- End-to-end over a real acceptor ---

(defun %http-raw-request (port lines &optional body)
  "Send an HTTP request (header LINES + optional BODY, CRLF framing) to
127.0.0.1:PORT and return the whole response as a string."
  (let ((request
          (with-output-to-string (s)
            (dolist (line lines)
              (write-string line s)
              (write-char #\Return s)
              (write-char #\Linefeed s))
            (write-char #\Return s)
            (write-char #\Linefeed s)
            (when body (write-string body s)))))
    (usocket:with-client-socket (socket stream "127.0.0.1" port
                                 :element-type '(unsigned-byte 8) :timeout 15)
      (write-sequence (flexi-streams:string-to-octets request :external-format :utf-8)
                      stream)
      (force-output stream)
      (let ((bytes (make-array 0 :element-type '(unsigned-byte 8)
                                 :adjustable t :fill-pointer 0)))
        (loop for b = (read-byte stream nil nil)
              while b do (vector-push-extend b bytes))
        (flexi-streams:octets-to-string
         (coerce bytes '(vector (unsigned-byte 8))) :external-format :utf-8)))))

(defun %http-status (response)
  "The status code of an \"HTTP/1.1 NNN ...\" response string."
  (parse-integer response :start 9 :junk-allowed t))

(defun %http-post-rpc (port json &key origin auth)
  "POST JSON to / on 127.0.0.1:PORT, optionally with Origin and Basic AUTH."
  (%http-raw-request
   port
   (append (list "POST / HTTP/1.1"
                 (format nil "Host: 127.0.0.1:~D" port))
           (when origin (list (format nil "Origin: ~A" origin)))
           (when auth
             (list (format nil "Authorization: Basic ~A"
                           (cl-base64:string-to-base64-string auth))))
           (list "Content-Type: application/json"
                 (format nil "Content-Length: ~D" (length json))
                 "Connection: close"))
   json))

(defun %http-get (port path)
  (%http-raw-request
   port
   (list (format nil "GET ~A HTTP/1.1" path)
         (format nil "Host: 127.0.0.1:~D" port)
         "Connection: close")))

(test ui-server-end-to-end
  "Live acceptor: /ui/ serves html, traversal 404s, Origin mismatch is 403
before auth, Origin-absent and same-origin POSTs pass, batch works with
cookie credentials."
  (bitcoin-lisp.rpc:stop-rpc-server)
  (let* ((port 19981)
         (dir (ensure-directories-exist
               (merge-pathnames (format nil "ui-e2e-~D/" (get-universal-time))
                                (uiop:temporary-directory))))
         (node (make-test-node)))
    (setf (bitcoin-lisp::node-data-directory node) dir)
    (unwind-protect
         (progn
           (is (not (null (bitcoin-lisp.rpc:start-rpc-server
                           node :port port :ui-enabled t))))
           ;; /ui/ -> 200 text/html with the shell
           (let ((r (%http-get port "/ui/")))
             (is (= 200 (%http-status r)))
             (is (search "content-type: text/html" (string-downcase r)))
             (is (search "<title>" r)))
           ;; asset with its own content type
           (let ((r (%http-get port "/ui/js/rpc.js")))
             (is (= 200 (%http-status r)))
             (is (search "content-type: text/javascript" (string-downcase r))))
           ;; traversal is rejected, repo sources are not reachable
           (let ((r (%http-get port "/ui/../src/rpc/server.lisp")))
             (is (= 404 (%http-status r)))
             (is (not (search "(in-package" r))))
           ;; cross-origin POST -> 403 (before auth; no WWW-Authenticate)
           (let ((r (%http-post-rpc
                     port "{\"method\":\"getblockcount\",\"id\":1}"
                     :origin "http://evil.example")))
             (is (= 403 (%http-status r))))
           ;; Origin absent (curl / bitcoin-cli style) -> works
           (let ((r (%http-post-rpc port "{\"method\":\"getblockcount\",\"id\":1}")))
             (is (= 200 (%http-status r)))
             (is (search "\"result\"" r)))
           ;; same-origin POST -> works
           (let ((r (%http-post-rpc
                     port "{\"method\":\"getblockcount\",\"id\":1}"
                     :origin (format nil "http://127.0.0.1:~D" port))))
             (is (= 200 (%http-status r))))
           ;; batch with the generated cookie credential (the UI login path)
           (let* ((cookie-path (merge-pathnames ".cookie" dir))
                  (cookie (alexandria:read-file-into-string cookie-path))
                  (r (%http-post-rpc
                      port
                      "[{\"method\":\"getblockcount\",\"id\":1},{\"method\":\"uptime\",\"id\":2}]"
                      :auth cookie)))
             (is (= 200 (%http-status r)))
             (let* ((json-start (position #\[ r))
                    (parsed (yason:parse (subseq r json-start))))
               (is (= 2 (length parsed)))
               (is (every (lambda (resp) (nth-value 1 (gethash "result" resp)))
                          parsed)))))
      (bitcoin-lisp.rpc:stop-rpc-server)
      (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore))))

(test ui-server-auth-still-enforced
  "With rpcuser/rpcpassword configured, wrong Basic credentials 401 and
correct ones pass — the Origin check must not weaken auth."
  (bitcoin-lisp.rpc:stop-rpc-server)
  (let ((port 19982)
        (node (make-test-node)))
    (unwind-protect
         (progn
           (is (not (null (bitcoin-lisp.rpc:start-rpc-server
                           node :port port :user "u" :password "p"
                                :ui-enabled t))))
           (let ((r (%http-post-rpc port "{\"method\":\"getblockcount\",\"id\":1}"
                                    :auth "u:wrong")))
             (is (= 401 (%http-status r))))
           (let ((r (%http-post-rpc port "{\"method\":\"getblockcount\",\"id\":1}"
                                    :auth "u:p")))
             (is (= 200 (%http-status r)))
             (is (search "\"result\"" r)))
           ;; Origin mismatch outranks even correct credentials
           (let ((r (%http-post-rpc port "{\"method\":\"getblockcount\",\"id\":1}"
                                    :auth "u:p" :origin "http://evil.example")))
             (is (= 403 (%http-status r)))))
      (bitcoin-lisp.rpc:stop-rpc-server))))

(test ui-server-disabled-not-registered
  "With the UI flag off, no /ui/ dispatcher exists — a GET lands on the
RPC prefix dispatcher and is refused (405), never served."
  (bitcoin-lisp.rpc:stop-rpc-server)
  (let ((port 19983)
        (node (make-test-node)))
    (unwind-protect
         (progn
           (is (not (null (bitcoin-lisp.rpc:start-rpc-server node :port port))))
           (is (null bitcoin-lisp.rpc::*ui-dispatcher*))
           (let ((r (%http-get port "/ui/")))
             (is (member (%http-status r) '(404 405))
                 "GET /ui/ with UI off must not serve (got ~A)" (%http-status r))
             (is (not (search "<title>" r)))))
      (bitcoin-lisp.rpc:stop-rpc-server))))
