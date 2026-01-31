;;; Ensure local coalton submodule is found by ASDF
;;; Use *load-pathname* since system isn't defined yet
(eval-when (:compile-toplevel :load-toplevel :execute)
  (let* ((this-file (or *compile-file-pathname* *load-pathname*))
         (coalton-path (when this-file
                         (merge-pathnames "coalton/" (make-pathname :directory (pathname-directory this-file))))))
    (when (and coalton-path (probe-file coalton-path))
      (pushnew coalton-path asdf:*central-registry* :test #'equal))))

(defsystem "bitcoin-lisp"
  :version "0.1.0"
  :author "samdefmacro"
  :license "MIT"
  :description "Bitcoin full node implementation in Common Lisp"
  :depends-on ("ironclad"
               "cffi"
               "usocket"
               "flexi-streams"
               "alexandria"
               "bordeaux-threads"
               "coalton"
               "hunchentoot"
               "yason"
               "cl-base64")
  :serial t
  :components ((:module "src"
                :components
                ((:file "package")
                 (:file "logging")
                 (:module "coalton"
                  :components ((:file "package")
                               (:file "types")
                               (:file "crypto")
                               (:file "binary")
                               (:file "serialization")
                               (:file "script")
                               (:file "interop")))
                 (:module "crypto"
                  :components ((:file "hash")
                               (:file "secp256k1")
                               (:file "address")))
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
                 (:module "mempool"
                  :components ((:file "mempool")))
                 (:module "networking"
                  :components ((:file "connection")
                               (:file "peer")
                               (:file "protocol")
                               (:file "ibd")))
                 (:module "rpc"
                  :components ((:file "package")
                               (:file "accessors")
                               (:file "methods")
                               (:file "server")))
                 (:file "node"))))
  :in-order-to ((test-op (test-op "bitcoin-lisp/tests"))))

(defsystem "bitcoin-lisp/tests"
  :depends-on ("bitcoin-lisp"
               "fiveam"
               "yason")
  :components ((:module "tests"
                :components ((:file "package")
                             (:file "crypto-tests")
                             (:file "serialization-tests")
                             (:file "storage-tests")
                             (:file "validation-tests")
                             (:file "integration-tests")
                             ;; Coalton tests
                             (:file "coalton-package")
                             (:file "coalton-types-tests")
                             (:file "coalton-crypto-tests")
                             (:file "coalton-serialization-tests")
                             (:file "coalton-binary-tests")
                             (:file "coalton-script-tests")
                             ;; Bitcoin Core compatibility tests
                             (:file "bitcoin-core-script-tests")
                             ;; IBD tests
                             (:file "ibd-tests")
                             ;; Mempool tests
                             (:file "mempool-tests")
                             ;; Persistence, peer health, reorg tests
                             (:file "persistence-tests")
                             ;; RPC tests
                             (:file "rpc-tests"))))
  :perform (test-op (op c)
                    (symbol-call :fiveam :run! :bitcoin-lisp-tests)))
