(in-package #:bitcoin-lisp.tests)

(def-suite :wallet-signer-tests
  :description "External signers: -signer, RunCommandParseJSON,
enumeratesigners, an external-signer wallet's setup and walletdisplayaddress
(Core external_signer.cpp, external_signer_scriptpubkeyman.cpp)"
  :in :bitcoin-lisp-tests)

(in-suite :wallet-signer-tests)

;;; A /bin/sh stand-in for Core's test/functional/mocks/signer.py: the same
;;; answers for enumerate / getdescriptors / displayaddress, keyed on the
;;; words of its command line the way the mock's argparse keys them.

(defparameter *mock-signer-xpub*
  "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B")

(defun %mock-signer-script (directory &key (fingerprint "00000001"))
  "Write the mock into DIRECTORY and return the -signer command that runs it.
Its displayaddress answers the right address for the first bech32 key and
`wrong_address' for anything else, which is how mocks/signer.py:52-64 tests
both arms."
  (let ((path (merge-pathnames "signer.sh" directory))
        (x *mock-signer-xpub*))
    (with-open-file (out path :direction :output :if-exists :supersede)
      (format out "#!/bin/sh~%case \"$*\" in~%")
      (format out "*enumerate*) cat <<'EOF'~%[{\"fingerprint\": \"~A\", \"type\": \"trezor\", \"model\": \"trezor_t\"}]~%EOF~%;;~%"
              fingerprint)
      (format out "*getdescriptors*) cat <<'EOF'~%{\"receive\": [\"pkh([00000001/44h/1h/0']~A/0/*)#aqllu46s\", \"sh(wpkh([00000001/49h/1h/0']~A/0/*))#5dh56mgg\", \"wpkh([00000001/84h/1h/0']~A/0/*)#h62dxaej\", \"tr([00000001/86h/1h/0']~A/0/*)#pcd5w87f\"], \"internal\": [\"pkh([00000001/44h/1h/0']~A/1/*)#v567pq2g\", \"sh(wpkh([00000001/49h/1h/0']~A/1/*))#pvezzyah\", \"wpkh([00000001/84h/1h/0']~A/1/*)#xw0vmgf2\", \"tr([00000001/86h/1h/0']~A/1/*)#svg4njw3\"]}~%EOF~%;;~%"
              x x x x x x x x)
      (format out "*displayaddress*wpkh*84h/1h/0h/0/0]*) echo '{\"address\": \"bcrt1qm90ugl4d48jv8n6e5t9ln6t9zlpm5th68x4f8g\"}';;~%")
      (format out "*displayaddress*) echo '{\"address\": \"wrong_address\"}';;~%")
      (format out "*) echo 'unexpected' >&2; exit 3;;~%esac~%"))
    (format nil "/bin/sh ~A" (namestring path))))

(defmacro with-mock-signer (() &body body)
  "BODY with -signer set to the /bin/sh mock, the directory removed after."
  (let ((dir (gensym "DIR")))
    `(let* ((,dir (make-temp-directory "bl-signer"))
            (bl.wallet:*signer-command* (%mock-signer-script ,dir)))
       (unwind-protect (progn ,@body)
         (uiop:delete-directory-tree ,dir :validate t :if-does-not-exist :ignore)))))

;;; --- RunCommandParseJSON (common/run_command.cpp:17-47) ---

(test run-command-parse-json-reports-cores-three-failures
  "A non-zero exit, output that is not JSON, and a program that cannot be
executed each give Core's sentence -- rpc_signer.py:50-60 and
wallet_signer.py:84 match on these."
  (flet ((failure (args)
           (handler-case (progn (bl.wallet:run-command-parse-json args) nil)
             (error (e) (princ-to-string e)))))
    (let ((exit (failure (list "/bin/sh" "-c" "echo oops >&2; exit 2"))))
      (is (search "RunCommandParseJSON error: process(/bin/sh -c echo oops >&2; exit 2) returned 2: oops"
                  exit)
          "got ~S" exit))
    (let ((junk (failure (list "/bin/sh" "-c" "echo '{\"invalid json\"}'"))))
      (is (equal "Unable to parse JSON: {\"invalid json\"}" junk) "got ~S" junk))
    (let ((missing (failure (list "no-such-signer.py" "enumerate"))))
      (is (equal "execve failed: No such file or directory" missing) "got ~S" missing))
    ;; Positive control: the first stdout line, as JSON.
    (is (equalp #(1 2) (bl.wallet:run-command-parse-json
                        (list "/bin/sh" "-c" "echo '[1,2]'; echo tail"))))))

;;; --- enumeratesigners (rpc/external_signer.cpp:20-65) ---

(test enumeratesigners-needs-signer-and-lists-the-device
  "Without -signer the RPC is -1 `Error: restart bitcoind with -signer=<cmd>'
(rpc_signer.py:46); with it, each device is its fingerprint and model."
  (let ((node (make-test-node :network :regtest)))
    (let ((bl.wallet:*signer-command* ""))
      (is (equal '(-1 . "Error: restart bitcoind with -signer=<cmd>")
                 (rpc-error-of (lambda () (bl.rpc:dispatch-rpc-method node "enumeratesigners" '()))))))
    (with-mock-signer ()
      (let ((signers (cdr (assoc "signers" (bl.rpc:dispatch-rpc-method
                                             node "enumeratesigners" '())
                                 :test #'string=))))
        (is (equalp '((("fingerprint" . "00000001") ("name" . "trezor_t")))
                    (coerce signers 'list)))))))

;;; --- An external-signer wallet (wallet_signer.py:67-119) ---

(test external-signer-wallet-takes-the-signers-descriptors
  "createwallet(external_signer=true) refuses private keys, takes its
descriptors from `getdescriptors', hands out the signer's addresses, and
walletdisplayaddress insists on the echo (wallet_signer.py:69-119)."
  (with-mock-signer ()
    (with-wallet-chain-node (node "signer")
      (flet ((rpc (method &rest params) (bl.rpc:dispatch-rpc-method node method params)))
        (is (equal '(-4 . "Private keys must be disabled when using an external signer")
                   (rpc-error-of (lambda ()
                                   (rpc "createwallet" "not_hww" nil nil nil nil t nil t)))))
        (rpc "createwallet" "hww" t nil nil nil t nil t)
        (with-rpc-wallet ("hww")
          (let ((info (rpc "getwalletinfo")))
            (is (eq t (cdr (assoc "external_signer" info :test #'string=))))
            ;; Four receive descriptors, keypool 5 each.
            (is (= 20 (cdr (assoc "keypoolsize" info :test #'string=)))))
          (let ((address (rpc "getnewaddress" nil "bech32")))
            (is (equal "bcrt1qm90ugl4d48jv8n6e5t9ln6t9zlpm5th68x4f8g" address))
            (is (equal `(("address" . ,address)) (rpc "walletdisplayaddress" address))))
          (let ((second (rpc "getnewaddress" nil "bech32")))
            (is (equal (cons -1 "Signer echoed unexpected address wrong_address")
                       (rpc-error-of (lambda () (rpc "walletdisplayaddress" second)))))))))))

(test external-signer-wallet-may-bumpfee
  "bumpfee refuses a keyless wallet -- unless an external signer holds its
keys (wallet/rpc/spend.cpp:1035), so an unknown txid gets the ordinary
not-in-wallet answer and not the private-keys one (wallet_signer.py:218)."
  (with-mock-signer ()
    (with-wallet-chain-node (node "signer-bump")
      (flet ((rpc (method &rest params) (bl.rpc:dispatch-rpc-method node method params)))
        (rpc "createwallet" "hww" t nil nil nil t nil t)
        (rpc "createwallet" "keyless" t)
        (let ((txid (make-string 64 :initial-element #\a)))
          ;; Control: a keyless wallet without a signer is refused outright.
          (with-rpc-wallet ("keyless")
            (is (eql -4 (car (rpc-error-of (lambda () (rpc "bumpfee" txid)))))))
          (with-rpc-wallet ("hww")
            (is (equal '(-5 . "Invalid or non-wallet transaction id")
                       (rpc-error-of (lambda () (rpc "bumpfee" txid)))))))))))
