(in-package #:bitcoin-lisp.tools)

;;;; bitcoin-wallet (Core src/bitcoin-wallet.cpp): the command line of the
;;;; offline wallet tool. The wallet work is BL.WALLET:WALLET-TOOL-EXECUTE
;;;; (src/wallet/wallet-tool.lisp, Core wallet/wallettool.cpp and dump.cpp).

(defparameter +wallet-tool-commands+ '("info" "create" "dump" "createfromdump")
  "Core SetupWalletToolArgs' AddCommand rows (bitcoin-wallet.cpp:43-46).")

(defun %bitcoin-wallet-usage (args out)
  "WalletAppInit's help / -version text (bitcoin-wallet.cpp:57-72)."
  (write-string (tool-version-banner "bitcoin-wallet") out)
  (if (tool-bool-arg args "version")
      (write-string (tool-license-info) out)
      (format out "~%bitcoin-wallet is an offline tool for creating and interacting ~
with bitcoin-lisp wallet files.~%~%By default bitcoin-wallet will act on wallets ~
in the default mainnet wallet directory in the datadir.~%~%To change the target ~
wallet, use the -datadir, -wallet and (test)chain selection arguments.~%~%~
Usage: bitcoin-wallet [options] <command>~%~%~%~
Commands:~%~%  create~%       Create a new descriptor wallet file~%~%  ~
createfromdump~%       Create new wallet file from dumped records~%~%  dump~%       ~
Print out all of the wallet key-value records~%~%  info~%       Get wallet info~%")))

(defun %tool-data-directory (args network)
  "The network's own data directory: -datadir (the node's default when it is
absent) plus the chain's subdirectory (chainparamsbase.cpp:40-55)."
  (let ((base (uiop:ensure-directory-pathname
               (tool-arg args "datadir" (bl.cfg:default-data-directory))))
        (subdirectory (bl.chain:chain-params-data-subdirectory
                       (bl.chain:find-chain-params network))))
    (if subdirectory (merge-pathnames subdirectory base) base)))

(defun run-bitcoin-wallet (argv &key (out *standard-output*) (err *error-output*))
  "Core bitcoin-wallet's main (bitcoin-wallet.cpp:48-130) over ARGV, the
arguments after the program name: write what Core writes to OUT and ERR and
return Core's exit code."
  (multiple-value-bind (args error)
      (parse-tool-args argv :options '("version" "datadir" "wallet" "dumpfile"
                                       "debug" "printtoconsole")
                            :commands +wallet-tool-commands+)
    (unless args
      (format err "Error parsing command line arguments: ~A~%" error)
      (return-from run-bitcoin-wallet 1))
    (when (or (null argv) (tool-help-requested-p args) (tool-bool-arg args "version"))
      (%bitcoin-wallet-usage args out)
      (when (null argv)
        (format err "Error: too few parameters~%")
        (return-from run-bitcoin-wallet 1))
      (return-from run-bitcoin-wallet 0))
    ;; CheckDataDirOption (common/args.cpp): a -datadir that is not a directory.
    (let ((datadir (tool-arg args "datadir")))
      (when (and datadir (not (uiop:directory-exists-p (uiop:ensure-directory-pathname datadir))))
        (format err "Error: Specified data directory \"~A\" does not exist.~%" datadir)
        (return-from run-bitcoin-wallet 1)))
    (let ((network (handler-case (tool-args-network args)
                     (error (e)
                       (format err "Error: ~A~%" e)
                       (return-from run-bitcoin-wallet 1))))
          (command (tool-args-command args)))
      (unless command
        (format err "No method provided. Run `bitcoin-wallet -help` for valid methods.~%")
        (return-from run-bitcoin-wallet 1))
      (when (rest command)
        (format err "Error: Additional arguments provided (~{~A~^, ~}). Methods do not take ~
arguments. Please refer to `-help`.~%" (rest command))
        (return-from run-bitcoin-wallet 1))
      (if (bl.wallet:wallet-tool-execute
           (first command) (%tool-data-directory args network) network
           :name (tool-arg args "wallet") :name-p (tool-arg-set-p args "wallet")
           :dumpfile (tool-arg args "dumpfile") :dumpfile-p (tool-arg-set-p args "dumpfile")
           :out out :err err)
          0
          1))))
