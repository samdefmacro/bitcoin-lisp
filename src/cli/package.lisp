;;;; Package bitcoin-lisp.cli -- the public API of src/cli/.
;;;;
;;;; First component of the bitcoin-lisp/cli sub-system (bitcoin-lisp.asd):
;;;; this node's bitcoin-cli, Core's src/bitcoin-cli.cpp. It is a CLIENT of the
;;;; JSON-RPC server and shares no code with it -- it builds on the config
;;;; layer's parsers (the command line and bitcoin.conf are read by Core's
;;;; ArgsManager in both programs) and on nothing above. The node executable
;;;; runs CLI-MAIN instead of the node when it is invoked under the name
;;;; bitcoin-cli (scripts/conformance-config.sh links build/bin/bitcoin-cli to
;;;; it), so one saved image serves both.

(in-package #:cl-user)

(defpackage #:bitcoin-lisp.cli
  (:documentation "bitcoin-cli: Core's command-line RPC client
 (src/bitcoin-cli.cpp, rpc/client.cpp, univalue). src/cli/.")
  (:use #:cl #:bitcoin-lisp.conditions)
  (:export
   ;; univalue.lisp -- Core's UniValue: numbers keep their text
   #:uv-read
   #:uv-write
   #:uv-num
   #:uv-obj
   #:uv-arr
   #:uv-get
   #:uv-null-p
   #:uv-val-str
   #:json-parse-failure
   ;; convert.lisp -- rpc/client.cpp
   #:*rpc-convert-params*
   #:rpc-convert-values
   #:rpc-convert-named-values
   ;; cli.lisp -- bitcoin-cli.cpp
   #:run-cli
   #:cli-main
   #:cli-program-name-p
   #:*cli-transport*
   #:cli-connection-failed
   #:cli-transport-failure
   #:split-rpc-host-port
   #:uri-encode))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (bitcoin-lisp.nicknames:install-package-nicknames))
