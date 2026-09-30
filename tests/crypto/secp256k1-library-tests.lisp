(in-package #:bitcoin-lisp.tests)

;;;; Which libsecp256k1 the process loaded, its modules, and MuSig2 without one
;;;;
;;;; Core links libsecp256k1 statically with its module set forced
;;;; (cmake/secp256k1.cmake:17-19), so it has nothing to compare here: a Core
;;;; binary cannot meet a library without the musig module. We load a shared
;;;; library chosen at run time (scripts/run-node.sh's BL_SECP_LIB), and the
;;;; live nodes ran v0.5.1 -- no musig module -- while the container had
;;;; v0.7.1. These tests pin the three places that must agree on the module
;;;; set (the image's build, the server's upgrade script, the node's probe
;;;; table), report what the loaded library has, and check that a missing
;;;; musig module is a named refusal instead of an undefined-alien error.

(def-suite :secp256k1-library-tests
  :description "The loaded libsecp256k1: modules, start-up line, MuSig2 refusal"
  :in :bitcoin-lisp-tests)

(in-suite :secp256k1-library-tests)

(defmacro %sl-without-symbols ((&rest names) &body body)
  "Run BODY as if the loaded libsecp256k1 did not export NAMES: every module
probe goes through BL.CRYPTO:*SECP256K1-SYMBOL-LOOKUP*."
  `(let ((bl.crypto:*secp256k1-symbol-lookup*
           (let ((hidden (list ,@names)))
             (lambda (name)
               (unless (member name hidden :test #'string=)
                 (cffi:foreign-symbol-pointer name))))))
     ,@body))

(defun %sl-missing-modules ()
  (loop for (module) in bl.crypto:*secp256k1-modules*
        unless (bl.crypto:secp256k1-module-available-p module)
          collect module))

(test secp256k1-library-exports-every-module
  "The loaded library exports one probe symbol per module the project builds
with. In the container this is v0.7.1 with all of them; on a host whose
library lacks one, the test SKIPS naming the library and the missing modules
-- the same answer `scripts/dev.sh eval '(bitcoin-lisp.crypto:secp256k1-startup-line)'`
gives the operator."
  (let ((path (bl.crypto:secp256k1-library-path)))
    ;; Positive control: the library's own entry point resolves, and dladdr
    ;; names a file that exists, so an all-absent answer below is the
    ;; library's and not a broken lookup.
    (is-true (cffi:foreign-symbol-pointer "secp256k1_context_create"))
    (is (and (stringp path) (search "libsecp256k1" path) (probe-file path) t)
        "dladdr names the loaded library file: ~S" path)
    (let ((missing (%sl-missing-modules)))
      (if missing
          (skip "libsecp256k1 ~A (~A) lacks the module~P ~{~(~A~)~^, ~}"
                (or (bl.crypto:secp256k1-library-version path) "of unknown version")
                path (length missing) missing)
          (is (= 6 (length bl.crypto:*secp256k1-modules*)))))))

(test secp256k1-startup-line-names-library-and-modules
  "The start-up line names the release, the file and the modules, and says
MuSig2 is unavailable when the musig module is missing."
  (let ((line (bl.crypto:secp256k1-startup-line))
        (path (bl.crypto:secp256k1-library-path)))
    (is (eql 0 (search "Using libsecp256k1 " line)) "~S" line)
    (is-true (search (format nil "(~A)" path) line))
    (dolist (module (set-difference (mapcar #'car bl.crypto:*secp256k1-modules*)
                                    (%sl-missing-modules)))
      (is-true (search (string-downcase module) line) "~A absent from ~S" module line)))
  (%sl-without-symbols ("secp256k1_musig_nonce_gen")
    (let ((line (bl.crypto:secp256k1-startup-line)))
      (is-false (bl.crypto:musig-available-p))
      (is-true (search "missing musig, so MuSig2 is not available" line) "~S" line)
      (is-false (search "musig " line))
      (is-false (search " musig;" line)))))

(test secp256k1-module-sets-agree
  "The container image's configure flags (docker/Dockerfile), the server
upgrade script's CMake flags and probe symbols, and the node's probe table
name the same modules -- the check that the server library is built as the
image's is. run-node.sh's BL_SECP_LIB default is the exact line the upgrade
script looks for in the deployed copy."
  (flet ((modules-after (text prefix)
           (loop with out = '()
                 for start = (search prefix text) then (search prefix text :start2 end)
                 for end = (and start
                                (position-if-not #'alpha-char-p text
                                                 :start (+ start (length prefix))))
                 while start
                 do (pushnew (intern (string-upcase (subseq text (+ start (length prefix)) end))
                                     :keyword)
                             out)
                 finally (return (sort out #'string<)))))
    (let ((dockerfile (project-source-text "docker/Dockerfile"))
          (script (project-source-text "scripts/server-secp-upgrade.sh"))
          (run-node (project-source-text "scripts/run-node.sh"))
          (ours (sort (mapcar #'car bl.crypto:*secp256k1-modules*) #'string<)))
      (is (= 6 (length ours)))
      (is (equal ours (modules-after dockerfile "--enable-module-")))
      (is (equal ours (modules-after script "-DSECP256K1_ENABLE_MODULE_")))
      (dolist (entry bl.crypto:*secp256k1-modules*)
        (is-true (search (cdr entry) script) "~A not probed by the script" (cdr entry)))
      (is-true (search "--branch v0.7.1" dockerfile))
      (is-true (search "SECP_VERSION=0.7.1" script))
      (is-true (search "BL_SECP_LIB=\"${BL_SECP_LIB:-$BL_ROOT/secp256k1-0.7.1/lib}\"" run-node)))))

(defparameter *sl-g* "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
  "The generator, as a 33-byte key.")
(defparameter *sl-2g* "02C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5"
  "2G, as a 33-byte key.")

(defun %sl-musig-refusals ()
  "The body of MUSIG-ENTRY-POINTS-REFUSE-WITHOUT-THE-MODULE, once the module is known present."
  (let* ((node (make-test-node))
         (keys (list (bl.crypto:hex-to-bytes *sl-g*) (bl.crypto:hex-to-bytes *sl-2g*)))
         (seckey (let ((k (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
                   (setf (aref k 31) 1) k))
         (msg (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7))
         (descriptor (format nil "tr(musig(~A,~A))" *sl-g* *sl-2g*))
         (cache (bl.crypto:musig-keyagg keys))
         (secnonce (bl.crypto:musig-nonce-gen
                    (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9)
                    (first keys) :seckey seckey :msg msg :keyagg-cache cache))
         (expected (format nil "MuSig2 is not available: libsecp256k1 ~A has no musig module"
                           (or (bl.crypto:secp256k1-library-version)
                               (bl.crypto:secp256k1-library-path)))))
    ;; Positive controls: with the module, the same calls work.
    (is-true cache)
    (is-true (bl.crypto:musig-aggregate-pubkeys keys))
    (is-true (bl.crypto:musig-secnonce-valid-p secnonce))
    (is-true (assoc "checksum" (bl.rpc:dispatch-rpc-method node "getdescriptorinfo"
                                                           (list descriptor))
                    :test #'equal))
    (unwind-protect
         (%sl-without-symbols ("secp256k1_musig_nonce_gen")
           (macrolet ((refused (form)
                        `(is (equal expected
                                    (handler-case (progn ,form :no-signal)
                                      (bl.crypto:musig-unavailable (e) (princ-to-string e))))
                             "~S" ',form)))
             (refused (bl.crypto:musig-aggregate-pubkeys keys))
             (refused (bl.crypto:musig-keyagg keys))
             (refused (bl.crypto:musig-nonce-gen msg (first keys)))
             (refused (bl.crypto:musig-nonce-agg (list (make-array 66 :initial-element 2))))
             (refused (bl.crypto:musig-nonce-process (make-array 66 :initial-element 2) msg cache))
             (refused (bl.crypto:musig-partial-sign secnonce seckey cache
                                                    (make-array 133 :initial-element 0)))
             (refused (bl.crypto:musig-partial-sig-verify (make-array 32 :initial-element 0)
                                                          (make-array 66 :initial-element 2)
                                                          (first keys) cache
                                                          (make-array 133 :initial-element 0)))
             (refused (bl.crypto:musig-partial-sig-agg (make-array 133 :initial-element 0)
                                                       (list (make-array 32 :initial-element 0))))
             (refused (bl.crypto:musig2-create-nonce seckey msg (first keys) keys)))
           ;; The refusal came before the nonce was taken.
           (is-true (bl.crypto:musig-secnonce-valid-p secnonce))
           ;; A musig() descriptor is refused at parse, as -1 with the same text.
           (let ((e (handler-case (bl.rpc:dispatch-rpc-method node "getdescriptorinfo"
                                                              (list descriptor))
                      (bl.rpc:rpc-error (e) e))))
             (is (typep e 'bl.rpc:rpc-error))
             (when (typep e 'bl.rpc:rpc-error)
               (is (= -1 (bl.rpc:rpc-error-code e)))
               (is (equal expected (bl.rpc:rpc-error-message e))))))
      (bl.crypto:musig-secnonce-invalidate secnonce))))

(test musig-entry-points-refuse-without-the-module
  "With the musig module hidden, every MuSig2 entry point signals
MUSIG-UNAVAILABLE naming the library before any foreign call (the real call
would succeed in the container, so a missing guard shows as no signal), a
secret nonce survives a refused signing call, and the RPC layer answers
RPC_MISC_ERROR with the same text."
  (if (not (bl.crypto:musig-available-p))
      (skip "the loaded libsecp256k1 has no musig module: nothing to hide")
      (%sl-musig-refusals)))
