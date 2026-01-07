(defsystem "bitcoin-lisp"
  :version "0.1.0"
  :author "samdefmacro"
  :license "MIT"
  :description "Bitcoin full node implementation in Common Lisp"
  :depends-on ("ironclad"
               "cffi"
               "usocket"
               "flexi-streams"
               "alexandria")
  :serial t
  :components ((:module "src"
                :components
                ((:file "package")
                 (:module "crypto"
                  :components ((:file "hash")
                               (:file "secp256k1")))
                 (:module "serialization"
                  :components ((:file "binary")
                               (:file "types")
                               (:file "messages")))
                 (:module "storage"
                  :components ((:file "blocks")
                               (:file "utxo")
                               (:file "chain")))
                 (:module "validation"
                  :components ((:file "script")
                               (:file "transaction")
                               (:file "block")))
                 (:module "networking"
                  :components ((:file "connection")
                               (:file "peer")
                               (:file "protocol"))))))
  :in-order-to ((test-op (test-op "bitcoin-lisp/tests"))))

(defsystem "bitcoin-lisp/tests"
  :depends-on ("bitcoin-lisp"
               "fiveam")
  :components ((:module "tests"
                :components ((:file "package")
                             (:file "crypto-tests")
                             (:file "serialization-tests"))))
  :perform (test-op (op c)
                    (symbol-call :fiveam :run! :bitcoin-lisp-tests)))
