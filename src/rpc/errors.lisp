(in-package #:bitcoin-lisp.rpc)

;;;; RPC error codes and the RPC-ERROR condition (Core rpc/protocol.h)
;;;
;;; Loaded right after the package so every RPC file names these without a
;;; forward reference. They used to sit in server.lisp -- the LAST file of
;;; the module -- so every (error 'rpc-error :code +rpc-...+) in the tree
;;; compiled against a constant that did not exist yet, and two of them were
;;; defined a second time in methods.lisp with the same value, which no
;;; redefinition warning reports.

;;; --- Error Codes ---

(defconstant +rpc-parse-error+ -32700)
(defconstant +rpc-invalid-request+ -32600)
(defconstant +rpc-method-not-found+ -32601)
(defconstant +rpc-invalid-params+ -32602)
(defconstant +rpc-internal-error+ -32603)
(defconstant +rpc-misc-error+ -1)
(defconstant +rpc-type-error+ -3)
(defconstant +rpc-invalid-address-or-key+ -5)
(defconstant +rpc-invalid-parameter+ -8)
(defconstant +rpc-client-not-connected+ -9)
(defconstant +rpc-client-in-initial-download+ -10)
(defconstant +rpc-deserialization-error+ -22)
(defconstant +rpc-client-node-already-added+ -23)
(defconstant +rpc-client-node-not-added+ -24)
(defconstant +rpc-verify-error+ -25)
(defconstant +rpc-transaction-rejected+ -26)
(defconstant +rpc-verify-already-in-utxo-set+ -27)
(defconstant +rpc-in-warmup+ -28)
(defconstant +rpc-client-node-not-connected+ -29)
(defconstant +rpc-client-invalid-ip-or-subnet+ -30)
(defconstant +rpc-method-deprecated+ -32)
(defconstant +rpc-client-mempool-disabled+ -33)
(defconstant +rpc-client-node-capacity-reached+ -34)

;;; --- RPC Error Condition ---

(define-condition rpc-error (error)
  ((code :initarg :code :reader rpc-error-code)
   (message :initarg :message :reader rpc-error-message)
   (data :initarg :data :initform nil :reader rpc-error-data))
  (:report (lambda (c s)
             (format s "RPC Error ~A: ~A" (rpc-error-code c) (rpc-error-message c)))))

;;; --- Wallet RPC error codes (Core rpc/protocol.h:71-86) ---

(defconstant +rpc-wallet-error+ -4)
(defconstant +rpc-wallet-insufficient-funds+ -6)
(defconstant +rpc-wallet-invalid-label-name+ -11)
(defconstant +rpc-wallet-keypool-ran-out+ -12)
(defconstant +rpc-wallet-unlock-needed+ -13)
(defconstant +rpc-wallet-passphrase-incorrect+ -14)
(defconstant +rpc-wallet-wrong-enc-state+ -15)
(defconstant +rpc-wallet-encryption-failed+ -16)
(defconstant +rpc-wallet-not-found+ -18)
(defconstant +rpc-wallet-not-specified+ -19)
(defconstant +rpc-wallet-already-loaded+ -35)
(defconstant +rpc-wallet-already-exists+ -36)

(defconstant +rpc-invalid-amount+ -3
  "RPC error code for invalid amount (Core RPC_TYPE_ERROR's value, used by
the amount parsers).")
