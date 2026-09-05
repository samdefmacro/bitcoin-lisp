(in-package #:bitcoin-lisp.test-support)

;;;; The wallet spend path's deterministic PRNG

(defun make-wallet-rng (seed)
  "The wallet spend path's PRNG at SEED -- the value a test binds
*WALLET-RNG* to so coin selection and change positioning replay. Named once
here because two wallet test files draw from it."
  (bl.wallet::make-wrng seed))

;;;; Addressing one wallet through the RPC handlers

(defmacro with-rpc-wallet ((name) &body body)
  "Run BODY with the /wallet/<name> endpoint selected, so the wallet RPC
handlers called inside address NAME. NIL selects the single loaded wallet, the
way an unqualified /wallet/ request does. Named here because five wallet test
files bind the same special."
  `(let ((bl.wallet::*rpc-wallet-name* ,name))
     ,@body))

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
in BODY address it the way an unqualified /wallet/ request does.

*CACHED-IS-IBD* is BOUND here, not merely left alone: it is a process-global
ONE-WAY latch that connecting a block clears, so any test that mines under this
fixture leaves the whole image reporting 'not in initial block download' for
every suite that runs after it. Observed 2026-09-06: a new wallet end-to-end
test that mined 103 regtest blocks ran before the eclipse/DoS suite and turned
two of its IBD-only assertions red, in a file nothing had touched."
  `(with-network (:regtest)
    (let* ((,node (make-wallet-chain-node ,suffix :keypool ,keypool))
           (bl:*node* ,node)
           (bl.net:*cached-is-ibd* bl.net:*cached-is-ibd*)
           ,@(when wallet '((bl.wallet::*rpc-wallet-name* nil))))
      (unwind-protect
           (progn ,@(when wallet `((bl.wallet::rpc-createwallet ,node (list ,wallet))))
                  ,@body)
        (ignore-errors
         (bl.wallet:close-wallet-manager
          (bl:node-wallet-manager ,node)))))))

(defun regtest-wif (byte)
  "A deterministic regtest WIF, for the descriptor strings the wallet RPCs
parse. Regtest and not mainnet: DecodeSecret reads the network's own prefix,
so a mainnet WIF is simply not a key here."
  (bl.crypto:private-key-to-wif
   (make-array 32 :element-type '(unsigned-byte 8) :initial-element byte)
   :network :regtest))

;;;; The question every "the wallet gave out an address it cannot spend" finding asks

(defun descriptor-spend-e2e (descriptor &key (pay 100000000) (suffix "e2e"))
  "Import DESCRIPTOR into a private-key wallet on a fresh regtest node, pay it
PAY satoshis from a second wallet's own sendtoaddress, mine the payment in, and
spend that output back out through signrawtransactionwithwallet.

Returns a plist: :ADDRESS what deriveaddresses handed out, :BALANCE what the
receiving wallet counted, :COMPLETE and :ERRORS what the signer reported, and
:ACCEPTED the node's own sendrawtransaction verdict -- which is the full script
verification of the witness the wallet produced, over a real chain.

Shared because a funds finding of this shape is only answered in these terms:
an in-process call to the signer proves nothing about what an operator sees, so
the address, the balance and the signature all come out of the shipped RPCs
through DISPATCH-RPC-METHOD. A pre-fix run answers :COMPLETE NIL with the
address and the balance unchanged, which is exactly the trap -- the coins look
like the wallet's and are not spendable by it."
  (with-wallet-chain-node (node suffix)
    (flet ((rpc (wallet method &rest params)
             (let ((bl.wallet::*rpc-wallet-name* wallet))
               (bl.rpc:dispatch-rpc-method node method params)))
           (aval (key alist) (cdr (assoc key alist :test #'string=))))
      (rpc nil "createwallet" "fund")
      ;; Blank, so getbalance counts the imported descriptor and nothing else.
      (rpc nil "createwallet" "desc" nil t)
      (let ((optrue (bl.crypto:encode-p2sh-address
                     (bl.crypto:hash160 +optrue-redeem+) :regtest)))
        (rpc nil "generatetoaddress" 1 (rpc "fund" "getnewaddress" "" "bech32"))
        (rpc nil "generatetoaddress" 101 optrue)
        (let* ((checksummed (bl.rpc:descriptor-add-checksum descriptor))
               (request (let ((h (make-hash-table :test 'equal)))
                          (setf (gethash "desc" h) checksummed
                                (gethash "timestamp" h) "now")
                          h))
               (imported (first (rpc "desc" "importdescriptors" (list request))))
               (address (first (rpc nil "deriveaddresses" checksummed)))
               ;; An explicit fee rate: regtest has no fee history, and the
               ;; fallback is disabled.
               (bl.wallet::*wallet-rng* (make-wallet-rng 77)))
          (rpc "fund" "sendtoaddress" address (bl.rpc:satoshi->btc pay)
               nil nil nil nil nil nil nil 10)
          (rpc nil "generatetoaddress" 1 optrue)
          (let* ((balance (rpc "desc" "getbalance"))
                 (coin (first (rpc "desc" "listunspent")))
                 (spend (bl.ser:make-transaction
                         :version 2
                         :inputs (vector (bl.ser:make-tx-in
                                          :previous-output
                                          (bl.ser:make-outpoint
                                           :hash (bl.rpc:parse-hex-hash (aval "txid" coin))
                                           :index (aval "vout" coin))
                                          :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                                          :sequence #xfffffffd))
                         :outputs (vector (bl.ser:make-tx-out
                                           :value (- pay 10000)
                                           :script-pubkey (p2sh-optrue-script-pubkey)))
                         :lock-time 0))
                 (signed (rpc "desc" "signrawtransactionwithwallet"
                              (bl.crypto:bytes-to-hex
                               (bl.ser:transaction-wire-bytes spend))))
                 (complete (eq t (aval "complete" signed))))
            (list :imported (eq t (aval "success" imported))
                  :address address
                  :balance balance
                  :complete complete
                  :errors (mapcar (lambda (e) (aval "error" e)) (aval "errors" signed))
                  :accepted (and complete
                                 (stringp (rpc nil "sendrawtransaction"
                                               (aval "hex" signed)))))))))))
