(in-package #:bitcoin-lisp)

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
      (when v (setf bl.rpc:*rpc-cookie-file* v)))
    ;; -rpccookieperms=owner|group|all (Core init.cpp:711). Loosening who may
    ;; read the cookie is loosening who may drive the RPC, so an unrecognised
    ;; audience is an error rather than a silent fall back to the default.
    (let ((v (lk "rpccookieperms")))
      (when v
        (let ((perms (bl.rpc:parse-rpc-cookie-perms v)))
          (unless perms
            (config-error "Invalid -rpccookieperms=~A (must be owner, group or all)" v))
          (setf bl.rpc:*rpc-cookie-perms* perms))))
    ;; -rpcthreads: cap on concurrent RPC handler threads (Core
    ;; DEFAULT_HTTP_THREADS = 16).
    (let ((v (lk "rpcthreads")))
      (when v
        (let ((n (conf-parse-int v)))
          (unless (and n (plusp n))
            (config-error "Invalid value for -rpcthreads=~A (must be a positive integer)" v))
          (setf bl.rpc:*rpc-threads* n))))
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
      ;; -keypool sizes the keypool of wallets created AFTER it is set; an
      ;; existing wallet keeps the size it was made with, as in Core, where the
      ;; keypool size is per-wallet state.
      (int-knob "keypool" bl.wallet:*default-keypool-size* :min 1))
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

(defun %start-rpc-early (node rpc-port rpc-bind rpc-bind-supplied-p
                         rpc-user rpc-password rpc-auth rpc-allow-ip
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
                                                    :rest-enabled rest-enabled
                                                    :ui-enabled webui-enabled
                                                    :ui-directory webui-path
                                                    :warmup "Loading...")))
    ;; -webuiopen: pop the local browser at the dashboard. Logged, never
    ;; fatal (open-browser-to-ui catches everything).
    (when (and server webui-enabled webui-open)
      (bl.rpc:open-browser-to-ui rpc-port))
    server))
