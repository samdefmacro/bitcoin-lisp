(in-package #:bitcoin-lisp)

(defun %apply-rpc-pool-options (lookup)
  "-rpcthreads / -rpcworkqueue: the HTTP worker pool and the depth of the queue
in front of it, read through LOOKUP (option name -> value or NIL). Core reads
both as std::max(gArgs.GetArg(name, DEFAULT), 1) (httpserver.cpp:419, :440):
GetArg's integer is LocaleIndependentAtoi, so `0', `-3' and `abc' all start the
server with ONE, and nothing is refused. Set every time, absent included, so
the value never depends on an earlier call."
  (flet ((at-least-one (name default)
           (let ((v (funcall lookup name)))
             (max 1 (if v (bl.cfg:locale-independent-atoi v) default)))))
    (setf bl.rpc:*rpc-threads*
          (at-least-one "rpcthreads" bl.rpc:+default-http-threads+)
          bl.rpc:*rpc-work-queue*
          (at-least-one "rpcworkqueue" bl.rpc:+default-http-workqueue+))))

(defun apply-rpc-config-globals (alist)
  "Apply the process-global RPC options from a merged config ALIST.

Kept apart from the option table for now (its rows for these names are
name-only); folding them into src/config-options.lisp as :global / :apply
rows is a follow-up. Called from START-NODE-FROM-ARGS immediately after
APPLY-CONFIG-GLOBALS."
  (flet ((lk (k) (let ((c (assoc k alist :test #'string=))) (and c (cdr c)))))
    ;; -rpccookiefile: where the auth cookie goes (Core init.cpp:710). A
    ;; relative path hangs off the data directory.
    (let ((v (lk "rpccookiefile")))
      ;; "0" is the negation (-norpccookiefile): no cookie file at all, Core's
      ;; GenerateAuthCookieResult::DISABLED (rpc/request.cpp:115).
      (when v (setf bl.rpc:*rpc-cookie-file* (if (string= v "0") :disabled v))))
    ;; -rpccookieperms=owner|group|all (Core init.cpp:711). Loosening who may
    ;; read the cookie is loosening who may drive the RPC, so an unrecognised
    ;; audience is an error rather than a silent fall back to the default.
    (let ((v (lk "rpccookieperms")))
      (when v
        (let ((perms (bl.rpc:parse-rpc-cookie-perms v)))
          (unless perms
            (config-error "Invalid -rpccookieperms=~A (must be owner, group or all)" v))
          (setf bl.rpc:*rpc-cookie-perms* perms))))
    (%apply-rpc-pool-options #'lk)
    ;; -rpcservertimeout: seconds an idle RPC connection is held (Core
    ;; DEFAULT_HTTP_SERVER_TIMEOUT). 0 means no timeout, as in Core.
    (let ((v (lk "rpcservertimeout")))
      (when v
        (let ((n (conf-parse-int v)))
          (unless (and n (>= n 0))
            (config-error "Invalid value for -rpcservertimeout=~A (must be a non-negative integer)" v))
          (setf bl.rpc:*rpc-server-timeout* (if (zerop n) nil n)))))
    ;; --- Wallet knobs over paths that already exist (track D's Wallet group).
    ;; Every one of these has a special with Core's name and default already;
    ;; what was missing was the option that sets it.
    ;;
    ;; They live here rather than in the option table for now, with the RPC
    ;; knobs above (see the docstring).
    (macrolet ((fee-knob (option place)
                 ;; Core's fee options are BTC/kvB on the command line and
                 ;; satoshis internally, as -maxtxfee and -fallbackfee already
                 ;; are in apply-config-globals.
                 `(let ((v (lk ,option)))
                    (when v
                      (let ((sats (conf-parse-money v)))
                        (unless sats
                          (config-error "Invalid amount for -~A=~A" ,option v))
                        (setf ,place sats)))))
               (int-knob (option place &key (min 0))
                 `(let ((v (lk ,option)))
                    (when v
                      (let ((n (conf-parse-int v)))
                        (unless (and n (>= n ,min))
                          (config-error "Invalid value for -~A=~A" ,option v))
                        (setf ,place n)))))
               (bool-knob (option place)
                 `(let ((v (lk ,option)))
                    (when v (setf ,place (conf-parse-bool v))))))
      (fee-knob "mintxfee" bl.wallet:*wallet-min-tx-fee*)
      (fee-knob "discardfee" bl.wallet:*wallet-discard-rate*)
      (fee-knob "consolidatefeerate" bl.wallet:*wallet-consolidate-feerate*)
      (fee-knob "maxapsfee" bl.wallet:*wallet-max-aps-fee*)
      (int-knob "txconfirmtarget" bl.wallet:*wallet-confirm-target* :min 1)
      (bool-knob "walletrbf" bl.wallet:*wallet-signal-rbf*)
      (bool-knob "spendzeroconfchange" bl.wallet:*wallet-spend-zero-conf-change*)
      (bool-knob "walletrejectlongchains" bl.wallet:*wallet-reject-long-chains*)
      (bool-knob "walletcrosschain" bl.wallet:*wallet-cross-chain*)
      ;; -keypool sizes the keypool of wallets created AFTER it is set; an
      ;; existing wallet keeps the size it was made with, as in Core, where the
      ;; keypool size is per-wallet state.
      ;;
      ;; CLAMPED, never refused, so it gets no INT-KNOB: Core reads it as
      ;; std::max(args.GetIntArg("-keypool", DEFAULT_KEYPOOL_SIZE), int64_t{1})
      ;; (wallet/wallet.cpp:3066), and GetIntArg answers 0 for anything it
      ;; cannot read, so 0, a negative and a garbage value all become 1.
      ;; Refusing 0 as an invalid value stopped the node from starting at all:
      ;; wallet_hd.py:21 runs its second node with -keypool=0 precisely so no
      ;; address is handed out before the test asks for one.
      (let ((v (lk "keypool")))
        (when v
          (setf bl.wallet:*default-keypool-size*
                (max 1 (or (ignore-errors (conf-parse-int v)) 0))))))
    ;; -walletdir relocates <datadir>/wallets/ (Core init.cpp). Relative paths
    ;; hang off the data directory, as -rpccookiefile does.
    (let ((v (lk "walletdir")))
      (when v (setf bl.wallet:*wallet-directory* v)))
    ;; -walletnotify: an operator hook, fired from AddToWallet.
    (let ((v (lk "walletnotify")))
      (when v (setf bl.wallet:*wallet-notify-command* v)))
    alist))

;;; The server writes .cookie into the node's data directory; it asks through
;;; this generic function rather than naming the node struct.
(defmethod bl.rpc:rpc-server-data-directory ((node node))
  (node-data-directory node))

(defun start-rpc-early (node rpc-port rpc-bind rpc-bind-supplied-p
                         rpc-user rpc-password rpc-auth rpc-allow-ip
                         rpc-whitelist rpc-whitelist-default
                         rest-enabled network webui webui-supplied-p
                         webui-path webui-open)
  "Bring the RPC server up before the slow parts of startup.

Split out of START-NODE only because it is called from the middle of it now
rather than the end; the body is unchanged. The server is reachable from this
point and answers -28 for every method until FINISH-RPC-WARMUP."
  ;; Web UI default (gui-plan §2): on everywhere except mainnet, where
  ;; enabling it is the operator's explicit choice (-webui).
  (let* ((webui-enabled (if webui-supplied-p
                            (and webui t)
                            (not (eq network :mainnet))))
         (server (bl.rpc:start-rpc-server node
                                                    :port rpc-port
                                                    :bind rpc-bind
                                                    :bind-supplied-p
                                                    rpc-bind-supplied-p
                                                    :user rpc-user
                                                    :password rpc-password
                                                    :rpc-auth rpc-auth
                                                    :allow-ip rpc-allow-ip
                                                    :rpc-whitelist rpc-whitelist
                                                    :rpc-whitelist-default
                                                    rpc-whitelist-default
                                                    :rest-enabled rest-enabled
                                                    :ui-enabled webui-enabled
                                                    :ui-directory webui-path
                                                    :warmup "Loading...")))
    ;; Core: AppInitServers false -> InitError, and the node exits 1 with this
    ;; exact line on stderr (init.cpp:1559-1561). start-rpc-server has already
    ;; logged WHY (a malformed -rpcauth or -rpcallowip, a port in use, a
    ;; credential that would not install); a node that carried on without its
    ;; RPC server was alive, unreachable and, to the functional framework's
    ;; assert_start_raises_init_error, wrong for sixty seconds.
    (unless server
      (init-error "Unable to start HTTP server. See debug log for details."))
    ;; -webuiopen: pop the local browser at the dashboard. Logged, never
    ;; fatal (open-browser-to-ui catches everything).
    (when (and server webui-enabled webui-open)
      (bl.rpc:open-browser-to-ui rpc-port))
    server))
