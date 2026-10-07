(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/parse_hd_keypath.cpp at the pin: ParseHDKeypath over
;;;; the buffer as text, and FormatHDKeypath / WriteHDKeypath over a random
;;;; path. ParseHDKeypath's one caller is the legacy wallet's key-metadata
;;;; upgrade (wallet/walletdb.cpp:626), which a descriptor-only wallet does
;;;; not have; the WRITING half is decodepsbt's `path' (rawtransaction.cpp
;;;; :1194, :1415), ours %PSBT-KEYPATH-JSON. So the target writes a random
;;;; path into a PSBT input's BIP32 derivation and reads it back through
;;;; decodepsbt, where it must be WriteHDKeypath's text: m, then /index per
;;;; step, `h' after a hardened one (util/bip32.cpp:51-65, apostrophe=false).

(def-suite :fuzz-parse-hd-keypath-tests :in :bitcoin-lisp-tests
  :description "Core fuzz parse_hd_keypath.cpp (the WriteHDKeypath half)")

(in-suite :fuzz-parse-hd-keypath-tests)

(defun %write-hd-keypath (path)
  "Core WriteHDKeypath(PATH) with its default apostrophe=false."
  (format nil "m~{/~A~}" (mapcar (lambda (i)
                                   (format nil "~D~:[~;h~]" (ldb (byte 31 0) i) (logbitp 31 i)))
                                 path)))

(define-fuzz-target parse-hd-keypath
    (buffer :core "parse_hd_keypath.cpp:13-22 (the WriteHDKeypath half)" :iterations 600 :max-len 200)
  "Any derivation path, written into a PSBT input and decoded, reads back as
Core's WriteHDKeypath of it."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (path (loop repeat (consume-integral-in-range fdp 0 16)
                     collect (consume-integral fdp :u32)))
         (fingerprint (let ((v (make-array 4 :element-type '(unsigned-byte 8) :initial-element 0)))
                        (replace v (consume-bytes fdp 4))))
         (pubkey (bl.crypto:derive-public-key (bl.crypto:sha256 (consume-bytes fdp 32))))
         (tx (bl.ser:make-transaction
              :version 2 :lock-time 0
              :inputs (vector (bl.ser:make-tx-in :previous-output (bl.ser:make-outpoint
                                                                   :hash (consume-uint256 fdp) :index 0)))
              :outputs (vector (bl.ser:make-tx-out :value 1000 :script-pubkey +p2wsh-op-true+))))
         (psbt (bl.ser:make-empty-psbt tx)))
    (bl.ser:psbt-map-set (aref (bl.ser:psbt-inputs psbt) 0) bl.ser:+psbt-in-bip32+ pubkey
                         (%concat-octets (cons fingerprint
                                               (mapcar (lambda (i) (%ser #'bl.ser:bb-write-u32-le i)) path))))
    (let* ((decoded (yason:parse (rpc-result-json
                                  (bl.rpc:dispatch-rpc-method (make-test-node) "decodepsbt"
                                                              (list (bl.ser:encode-psbt psbt))))))
           (derivs (gethash "bip32_derivs" (first (gethash "inputs" decoded))))
           (written (gethash "path" (first derivs))))
      (fuzz-assert (equal (fuzz-sabotage written) (%write-hd-keypath path))
                   "decodepsbt writes ~S where Core writes ~S" written (%write-hd-keypath path)))))
