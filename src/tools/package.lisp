;;;; Package bitcoin-lisp.tools -- Core's side tools (src/tools/).
;;;;
;;;; bitcoin-util (Core src/bitcoin-util.cpp), bitcoin-tx (src/bitcoin-tx.cpp)
;;;; and bitcoin-wallet (src/bitcoin-wallet.cpp, wallet/wallettool.cpp,
;;;; wallet/dump.cpp). None of them is a separate program here: the node
;;;; executable runs one of them when it is STARTED UNDER ITS NAME (see
;;;; TOOL-FOR-PROGRAM-NAME and NODE-MAIN), which is how Core's functional test
;;;; framework finds them next to bitcoind (BUILDDIR/bin/<name>,
;;;; test_framework/util.py:317-343).
;;;;
;;;; Every tool is a function of its argument list and its standard input
;;;; that WRITES to two streams and RETURNS an exit code, so the unit suite
;;;; runs Core's own vectors in-process (tests/tools/) and only TOOL-MAIN, the
;;;; executable's side, exits.

(in-package #:cl-user)

(defpackage #:bitcoin-lisp.tools
  (:use #:cl)
  (:documentation "Core's command-line side tools on top of the node's layers:
bitcoin-util (grind), bitcoin-tx (create/modify/sign a transaction offline) and
bitcoin-wallet (info/create/dump/createfromdump on a wallet directory). Core
bitcoin-util.cpp, bitcoin-tx.cpp, bitcoin-wallet.cpp, wallet/wallettool.cpp,
wallet/dump.cpp. src/tools/.")
  (:export
   ;; The entry points, one per Core program
   #:run-bitcoin-util
   #:run-bitcoin-tx
   #:run-bitcoin-wallet
   #:tool-for-program-name
   #:tool-main
   ;; Core UniValue::write for the alist values the RPC layer builds
   #:univalue-write
   ;; Core ParseScript (core_io.cpp:63-130)
   #:parse-script-asm))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (bitcoin-lisp.nicknames:install-package-nicknames))
