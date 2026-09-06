(defpackage #:bitcoin-lisp.nicknames
  (:documentation "The bl.* package-local nicknames every project package
carries, and the installer each package-defining file calls after its
DEFPACKAGE forms. First file in the load so that every later package file can
call it.")
  (:use #:cl)
  (:export #:*package-nicknames* #:install-package-nicknames))

(defpackage #:bitcoin-lisp.conditions
  (:documentation "The condition hierarchy every project package :USEs
(src/util/conditions.lisp): BITCOIN-LISP-ERROR at the root, one simple-error
subclass per module with a signalling function of the same name, and the
consensus / policy errors that carry Core's reject reason.")
  (:use #:cl)
  (:export
   #:bitcoin-lisp-error
   #:internal-error
   #:config-error
   #:init-error
   #:serialization-error
   #:protocol-limit-error
   #:storage-error
   #:net-error
   #:crypto-error
   #:wallet-error
   #:consensus-error
   #:policy-error
   #:error-reason))

(in-package #:bitcoin-lisp.nicknames)

;;;; Package-local nicknames
;;;
;;; Every project package sees every other one under a short name, so a
;;; cross-package reference is written with the bl.ser prefix instead of the
;;; full bitcoin-lisp.serialization one (about 5,300 of them in src/, 20,000
;;; in tests/). The names carry the bl. prefix on purpose: a bare crypto would
;;; shadow ironclad's global nickname CRYPTO inside our packages and read as
;;; ironclad to anyone who knows it.
;;;
;;; SBCL refuses a nickname for a package that does not exist yet, and a
;;; re-executed DEFPACKAGE (a warm-image reload of any package file) DROPS the
;;; package's local nicknames; so every package-defining file ends with
;;; (eval-when (:compile-toplevel :load-toplevel :execute)
;;;   (bitcoin-lisp.nicknames:install-package-nicknames))
;;; which adds every nickname whose target exists to every project package
;;; (re-adding an existing mapping is a no-op) -- at compile time too, because
;;; src/coalton/interop.lisp reads nicknames in the file that defines its
;;; package. scripts/refactor/apply-nicknames.sh rewrites a branch's explicit
;;; prefixes to these names.

(eval-when (:compile-toplevel :load-toplevel :execute)

(defparameter *package-nicknames*
  '(("BL" . "BITCOIN-LISP")
    ("BL.ERR" . "BITCOIN-LISP.CONDITIONS")
    ("BL.LOG" . "BITCOIN-LISP.LOGGING")
    ("BL.KV" . "BITCOIN-LISP.KV")
    ("BL.BYTES" . "BITCOIN-LISP.BYTES")
    ("BL.CHAIN" . "BITCOIN-LISP.CHAINPARAMS")
    ("BL.CTX" . "BITCOIN-LISP.CONTEXT")
    ("BL.RL" . "BITCOIN-LISP.RATELIMIT")
    ("BL.VI" . "BITCOIN-LISP.VALIDATION-INTERFACE")
    ("BL.CFG" . "BITCOIN-LISP.CONFIG")
    ("BL.CRYPTO" . "BITCOIN-LISP.CRYPTO")
    ("BL.SER" . "BITCOIN-LISP.SERIALIZATION")
    ("BL.STORE" . "BITCOIN-LISP.STORAGE")
    ("BL.VAL" . "BITCOIN-LISP.VALIDATION")
    ("BL.MP" . "BITCOIN-LISP.MEMPOOL")
    ("BL.MINING" . "BITCOIN-LISP.MINING")
    ("BL.NET" . "BITCOIN-LISP.NETWORKING")
    ("BL.RPC" . "BITCOIN-LISP.RPC")
    ("BL.WALLET" . "BITCOIN-LISP.WALLET")
    ("BL.CTYPES" . "BITCOIN-LISP.COALTON.TYPES")
    ("BL.CCRYPTO" . "BITCOIN-LISP.COALTON.CRYPTO")
    ("BL.CBIN" . "BITCOIN-LISP.COALTON.BINARY")
    ("BL.CSER" . "BITCOIN-LISP.COALTON.SERIALIZATION")
    ("BL.SCRIPT" . "BITCOIN-LISP.COALTON.SCRIPT")
    ("BL.INTEROP" . "BITCOIN-LISP.COALTON.INTEROP")
    ("BL.TESTS" . "BITCOIN-LISP.TESTS"))
  "(NICKNAME . package-name). Nicknames are matched case-sensitively against
the reader's upcased token, so they are upper-case here and are written in
lower case as prefixes in source. scripts/refactor/apply-nicknames.sh derives
its rewrite rules from this table and tests/structural-tests.lisp resolves
prefixes through it.")

(defun install-package-nicknames ()
  "Give every BITCOIN-LISP* package every nickname in *PACKAGE-NICKNAMES*
whose target package exists. Called after each file that defines packages."
  (dolist (package (list-all-packages))
    (let ((name (package-name package)))
      (when (uiop:string-prefix-p "BITCOIN-LISP" name)
        (loop for (nickname . target) in *package-nicknames*
              for target-package = (find-package target)
              ;; a package nicknames itself too: files in the top package
              ;; write bl:*node* like everyone else
              when target-package
                do (sb-ext:add-package-local-nickname nickname target-package package))))))

) ; eval-when

(in-package #:cl-user)

;;;; Package bitcoin-lisp.bytes -- the public API of src/util/.
;;;;
;;;; Loaded with the other package files before any code (bitcoin-lisp.asd,
;;;; the "packages" phase): src/config.lisp loads third and already names
;;;; most of these packages, and every package must exist before
;;;; src/package.lisp installs the bl.* nicknames. Add an export here when a
;;;; definition in src/util/ becomes API; keep %-prefixed names internal.

(defpackage #:bitcoin-lisp.bytes
  (:documentation "Index-based byte I/O: the byte-buf writer, the byte-reader,
the positional buf-set-* primitives and CompactSize, plus SANITIZE-STRING --
the filter Core keeps beside its encodings in util/strencodings.cpp, applied
wherever peer-supplied text becomes a log line or an RPC field. Loads before
every other package that does I/O (bitcoin-lisp.asd) so the hot paths that
inline these compile against them. src/util/bytes.lisp.")
  (:use #:cl #:bitcoin-lisp.conditions)
  (:export
   #:+max-compact-size+
   ;; positional writers into a pre-sized array
   #:buf-set-u8
   #:buf-set-u16-le
   #:buf-set-u32-le
   #:buf-set-u64-le
   #:buf-set-bytes
   #:buf-set-varint
   ;; auto-growing writer
   #:byte-buf
   #:make-byte-buf
   #:bb-data
   #:bb-pos
   #:bb-ensure
   #:bb-write-u8
   #:bb-write-u16-le
   #:bb-write-u32-le
   #:bb-write-u64-le
   #:bb-write-i32-le
   #:bb-write-i64-le
   #:bb-write-bytes
   #:bb-write-varint
   #:bb-write-var-bytes
   #:bb-write-hash256
   #:bb-finish
   #:with-byte-buf
   ;; zero-copy reader
   #:byte-reader
   #:make-byte-reader
   #:make-byte-reader-from
   #:br-data
   #:br-pos
   #:br-eof-p
   #:br-read-u8
   #:br-read-bool
   #:br-read-u16-le
   #:br-read-u32-le
   #:br-read-u64-le
   #:br-read-i32-le
   #:br-read-i64-le
   #:br-read-bytes
   #:br-read-compact-size
   #:br-read-var-bytes
   #:octets=
   #:octets-hash
   #:make-octets-hash-table
   #:with-byte-reader
   ;; Core SanitizeString (util/strencodings.cpp)
   #:sanitize-string))

(defpackage #:bitcoin-lisp.chainparams
  (:documentation "Per-chain parameters (Core CChainParams): one
DEFINE-CHAIN-PARAMS form per chain in src/util/chainparams.lisp, read through
FIND-CHAIN-PARAMS and the CHAIN-PARAMS-* accessors.")
  (:use #:cl #:bitcoin-lisp.conditions)
  (:export
   #:*network*
   #:network-magic
   #:network-port
   #:network-dns-seeds
   #:network-rpc-port
   #:*enforce-bip94-on-regtest*
   #:enforce-bip94-p
   #:chain-params
   #:define-chain-params
   #:find-chain-params
   #:chain-params-template
   #:chain-params-override
   #:*chain-params-overrides*
   #:copy-chain-params
   #:chain-names
   #:chain-params-p
   #:chain-params-name
   #:chain-params-core-name
   #:chain-params-data-subdirectory
   #:chain-params-magic
   #:chain-params-port
   #:chain-params-rpc-port
   #:chain-params-dns-seeds
   #:chain-params-fixed-seeds
   #:chain-params-genesis-hash
   #:chain-params-genesis-timestamp
   #:chain-params-genesis-bits
   #:chain-params-genesis-nonce
   #:chain-params-genesis-timestamp-message
   #:chain-params-pow-limit-bits
   #:chain-params-bip34-height
   #:chain-params-bip65-height
   #:chain-params-bip66-height
   #:chain-params-csv-height
   #:chain-params-segwit-height
   #:chain-params-taproot-height
   #:chain-params-checkpoints
   #:chain-params-headers-sync-params
   #:chain-params-minimum-chain-work
   #:chain-params-assumevalid-hex
   #:chain-params-assumeutxo
   #:chain-params-prune-after-height
   #:chain-params-bech32-hrp
   #:chain-params-base58-pubkey-prefix
   #:chain-params-base58-script-prefix
   #:chain-params-base58-secret-prefix
   #:chain-params-ext-public-prefix
   #:chain-params-ext-secret-prefix
   #:chain-params-bip44-coin-type
   #:chain-params-of-ext-prefix
   #:secret-prefix-known-p
   #:ext-public-prefix-known-p
   #:ext-secret-prefix-known-p))

(defpackage #:bitcoin-lisp.context
  (:documentation "node-context (Core NodeContext): the references a message
handler or sync pass acts on, as one value. src/util/context.lisp.")
  (:use #:cl #:bitcoin-lisp.conditions)
  (:export
   ;; The cooperative stop seam (Core util::SignalInterrupt)
   #:*interrupt-check*
   #:interrupt-requested-p
   #:node-context
   #:make-node-context
   #:copy-node-context
   #:node-context-p
   #:node-context-chain-state
   #:node-context-utxo-set
   #:node-context-block-store
   #:node-context-mempool
   #:node-context-peers
   #:node-context-fee-estimator
   #:node-context-address-book
   #:node-context-recent-rejects
   #:node-context-historical-chainstate
   #:with-node-context))

(defpackage #:bitcoin-lisp.ratelimit
  (:documentation "The token-bucket rate limiter the P2P protocol and the RPC
server both meter with. src/util/ratelimit.lisp.")
  (:use #:cl)
  (:export
   #:token-bucket
   #:make-token-bucket
   #:token-bucket-p
   #:token-bucket-rate
   #:token-bucket-burst
   #:token-bucket-tokens
   #:token-bucket-last-refill
   #:make-rate-limiter
   #:token-bucket-allow-p))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (bitcoin-lisp.nicknames:install-package-nicknames))
