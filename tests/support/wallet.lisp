(in-package #:bitcoin-lisp.test-support)

;;;; A regtest node with a wallet manager, for the chain-hook tests

(defvar *wallet-chain-counter* 0
  "Serial number for the wallet fixtures' directory names, so two nodes built
in the same second get different ones. Internal: a test that wants its own
directory calls MAKE-TEMP-DIRECTORY, which is already unique.")

(defun make-wallet-chain-node (suffix &key (keypool 5))
  "A regtest node at genesis with a wallet manager, the genesis block stored
(so rescans from height 0 can read it), ready for the chain hooks."
  (let* ((id (format nil "~A-~D-~D" suffix (get-universal-time)
                     (incf *wallet-chain-counter*)))
         (node (regtest-node-fixture (format nil "wallet-~A" id)))
         (wallet-dir (merge-pathnames (format nil "wallet-chain-~A/" id)
                                      (uiop:temporary-directory))))
    (bl.store:store-block
     (bl:node-block-store node)
     (bl.store:make-genesis-block :regtest))
    (setf (bl:node-wallet-manager node)
          (bl.wallet::make-wallet-manager
           :data-directory wallet-dir :network :regtest :keypool-size keypool))
    node))

(defmacro with-wallet-chain-node ((node suffix &key (keypool 5) wallet) &body body)
  "Run BODY under regtest bindings with NODE bound to a make-wallet-chain-node and
bl:*node* bound so the wallet chain hooks fire. With WALLET, a wallet of that
name is created first and *RPC-WALLET-NAME* is bound to NIL, so the wallet RPCs
in BODY address it the way an unqualified /wallet/ request does."
  `(with-network (:regtest)
    (let* ((,node (make-wallet-chain-node ,suffix :keypool ,keypool))
           (bl:*node* ,node)
           ,@(when wallet '((bl.wallet::*rpc-wallet-name* nil))))
      (unwind-protect
           (progn ,@(when wallet `((bl.wallet::rpc-createwallet ,node (list ,wallet))))
                  ,@body)
        (ignore-errors
         (bl.wallet:close-wallet-manager
          (bl:node-wallet-manager ,node)))))))
