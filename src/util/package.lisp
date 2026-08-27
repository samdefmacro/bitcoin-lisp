;;;; Package bitcoin-lisp.bytes -- the public API of src/util/.
;;;;
;;;; Loaded with the other package files before any code (bitcoin-lisp.asd,
;;;; the "packages" phase): src/config.lisp loads third and already names
;;;; most of these packages, and every package must exist before
;;;; src/package.lisp installs the bl.* nicknames. Add an export here when a
;;;; definition in src/util/ becomes API; keep %-prefixed names internal.

(defpackage #:bitcoin-lisp.bytes
  (:documentation "Index-based byte I/O: the byte-buf writer, the byte-reader,
the positional buf-set-* primitives and CompactSize. Loads before every other
package that does I/O (bitcoin-lisp.asd) so the hot paths that inline these
compile against them. src/util/bytes.lisp.")
  (:use #:cl)
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
   #:bb-finish
   ;; zero-copy reader
   #:byte-reader
   #:make-byte-reader
   #:make-byte-reader-from
   #:br-data
   #:br-pos
   #:br-eof-p
   #:br-read-u8
   #:br-read-u16-le
   #:br-read-u32-le
   #:br-read-u64-le
   #:br-read-i32-le
   #:br-read-i64-le
   #:br-read-bytes
   #:br-read-compact-size
   #:br-read-var-bytes))

(defpackage #:bitcoin-lisp.chainparams
  (:documentation "Per-chain parameters (Core CChainParams): one
DEFINE-CHAIN-PARAMS form per chain in src/util/chainparams.lisp, read through
FIND-CHAIN-PARAMS and the CHAIN-PARAMS-* accessors.")
  (:use #:cl)
  (:export
   #:chain-params
   #:define-chain-params
   #:find-chain-params
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
   #:chain-params-bech32-hrp))
