(in-package #:bitcoin-lisp.tests)

;;; Script flag-gating matrix.
;;;
;;; Bitcoin Core's comprehensive script_tests.json (run by bitcoin-core-script-
;;; tests) already exercises many flag/script combinations, but it mixes
;;; everything together and tests each script under a single flag string. These
;;; tests make the GATING explicit and per-rule: the SAME script must behave
;;; differently with a flag off vs on, proving each SCRIPT_VERIFY flag actually
;;; toggles its rule (and that a clean script survives the full flag set). They
;;; reuse the run-script-test / assemble-script harness and use only
;;; signature-free constructs.

(in-suite :script-flag-tests)

(defun %sf-ok (script-sig script-pubkey flags)
  "T iff SCRIPT-SIG then SCRIPT-PUBKEY verifies under FLAGS (a comma-separated
flag string), via the shared run-script-test harness."
  (values (run-script-test script-sig script-pubkey flags)))

(defun %sf-context-tx (version sequence locktime)
  "A minimal single-input tx supplying the locktime/sequence context that
CLTV/CSV read."
  (bitcoin-lisp.serialization:make-transaction
   :version version
   :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                  :previous-output (bitcoin-lisp.serialization:make-outpoint)
                  :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                  :sequence sequence))
   :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                   :value 0 :script-pubkey (make-array 0 :element-type '(unsigned-byte 8))))
   :lock-time locktime))

(defmacro %sf-with-tx ((tx) &body body)
  `(let ((bitcoin-lisp.coalton.interop:*current-tx* ,tx)
         (bitcoin-lisp.coalton.interop:*current-input-index* 0))
     ,@body))

;;;; Per-flag gating (signature-free)

(test flag-gate-discourage-upgradable-nops
  ;; OP_NOP1 is a no-op unless DISCOURAGE_UPGRADABLE_NOPS is set.
  (is-true  (%sf-ok "1" "NOP1" ""))
  (is-false (%sf-ok "1" "NOP1" "DISCOURAGE_UPGRADABLE_NOPS")))

(test flag-gate-cleanstack
  ;; A leftover stack element is allowed unless CLEANSTACK is set.
  (is-true  (%sf-ok "1 1" "" ""))
  (is-false (%sf-ok "1 1" "" "CLEANSTACK")))

(test flag-gate-sigpushonly
  ;; A non-push scriptSig (contains OP_DUP) is allowed unless SIGPUSHONLY is set.
  (is-true  (%sf-ok "1 DUP" "1" ""))
  (is-false (%sf-ok "1 DUP" "1" "SIGPUSHONLY")))

(test flag-gate-nulldummy
  ;; CHECKMULTISIG's extra dummy element may be non-empty unless NULLDUMMY is
  ;; set. 0-of-0 multisig ("0 0 CHECKMULTISIG") with a non-empty dummy (the
  ;; pushed 1) — needs no signatures.
  (is-true  (%sf-ok "1" "0 0 CHECKMULTISIG" ""))
  (is-false (%sf-ok "1" "0 0 CHECKMULTISIG" "NULLDUMMY")))

(test flag-gate-minimaldata
  ;; A non-minimal push (PUSHDATA1 of a single byte: 0x4c 0x01 0x05) is allowed
  ;; unless MINIMALDATA is set.
  (is-true  (%sf-ok "0x4c0105" "" ""))
  (is-false (%sf-ok "0x4c0105" "" "MINIMALDATA")))

;;;; CLTV / CSV gating (need locktime/sequence context)

(test flag-gate-checklocktimeverify
  ;; OP_NOP2 acts as CHECKLOCKTIMEVERIFY only when the flag is set. With a final
  ;; input sequence (0xffffffff) CLTV must fail when enforced; as a NOP it passes.
  (%sf-with-tx ((%sf-context-tx 2 #xffffffff 0))
    (is-true  (%sf-ok "" "1 CHECKLOCKTIMEVERIFY" ""))
    (is-false (%sf-ok "" "1 CHECKLOCKTIMEVERIFY" "CHECKLOCKTIMEVERIFY")))
  ;; ...and CLTV PASSES when satisfied (non-final sequence, threshold <= the
  ;; tx's height-based locktime), proving it isn't merely always-failing.
  (%sf-with-tx ((%sf-context-tx 2 0 100))
    (is-true (%sf-ok "" "100 CHECKLOCKTIMEVERIFY" "CHECKLOCKTIMEVERIFY"))))

(test flag-gate-checksequenceverify
  ;; OP_NOP3 acts as CHECKSEQUENCEVERIFY only when the flag is set. A version-1
  ;; tx fails CSV when enforced (CSV requires version >= 2); as a NOP it passes.
  (%sf-with-tx ((%sf-context-tx 1 0 0))
    (is-true  (%sf-ok "" "1 CHECKSEQUENCEVERIFY" ""))
    (is-false (%sf-ok "" "1 CHECKSEQUENCEVERIFY" "CHECKSEQUENCEVERIFY"))))

;;;; Combination sanity: a clean script survives the full mandatory flag set

(test flag-combo-clean-script-passes-all-flags
  ;; A trivial valid script triggers no rule, so enabling the whole flag set
  ;; must not break it.
  (is-true (%sf-ok "1" "1 EQUAL"
                   "P2SH,DERSIG,CHECKLOCKTIMEVERIFY,CHECKSEQUENCEVERIFY,WITNESS,NULLDUMMY,MINIMALDATA,CLEANSTACK,LOW_S,STRICTENC")))
