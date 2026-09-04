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
  (bl.ser:make-transaction
   :version version
   :inputs (vector (bl.ser:make-tx-in
                  :previous-output (bl.ser:make-outpoint)
                  :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                  :sequence sequence))
   :outputs (vector (bl.ser:make-tx-out
                   :value 0 :script-pubkey (make-array 0 :element-type '(unsigned-byte 8))))
   :lock-time locktime))

(defmacro %sf-with-tx ((tx) &body body)
  `(let ((bl.interop:*current-tx* ,tx)
         (bl.interop:*current-input-index* 0))
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

;;;; CONST_SCRIPTCODE: OP_CODESEPARATOR and FindAndDelete
;;;;
;;;; Bitcoin Core's script_tests.json carries NO CONST_SCRIPTCODE vector -- the
;;;; flag is policy-only and postdates that corpus -- so the vectors below are
;;;; ours, read off script/interpreter.cpp. They go through
;;;; bl.interop:verify-script and bl.interop:verify-checksig rather than
;;;; %sf-ok, whose harness reimplements the VerifyScript flow and never runs
;;;; verify-script's own pre-execution steps.

(defparameter +sf-pubkey-hex+
  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
  "A well-formed 33-byte compressed pubkey (the secp256k1 generator).")

(defun %sf-script (&rest hex-parts)
  "A script built from concatenated hex fragments."
  (bl.crypto:hex-to-bytes (apply #'concatenate 'string hex-parts)))

(defun %sf-cat (&rest parts)
  "One byte vector from byte vectors and single byte values."
  (coerce (loop for part in parts
                append (if (integerp part) (list part) (coerce part 'list)))
          '(simple-array (unsigned-byte 8) (*))))

(defun %sf-under-flags (flags thunk)
  "Both values of THUNK, called with FLAGS in effect, as a list. Owns the flag
lifecycle the way run-script-test does for %sf-ok."
  (bl.interop:set-script-flags flags)
  (unwind-protect (multiple-value-list (funcall thunk))
    (bl.interop:set-script-flags nil)))

(defun %sf-verify (script-sig script-pubkey flags)
  "(verify-script SCRIPT-SIG SCRIPT-PUBKEY) under FLAGS, as a list."
  (%sf-under-flags flags
                   (lambda () (bl.interop:verify-script script-sig script-pubkey))))

(defun %sf-checksig (flags sig script-code)
  "(verify-checksig SIG <pubkey> SCRIPT-CODE) under FLAGS, as a list."
  (%sf-under-flags flags
                   (lambda ()
                     (bl.interop:verify-checksig
                      sig (%sf-script +sf-pubkey-hex+) script-code))))

(defun %sf-p2sh-spend (redeem)
  "The (scriptSig scriptPubKey) list of a P2SH spend of REDEEM, the scriptSig
being the canonical single push Core requires."
  (list (%sf-cat (length redeem) redeem)
        (%sf-cat #xa9 #x14 (bl.crypto:hash160 redeem) #x87)))

(defun %sf-filler (n)
  "N bytes that parse as no DER signature -- only their PUSH is under test."
  (make-array n :element-type '(unsigned-byte 8) :initial-element #x41))

(test const-scriptcode-findanddelete-deletes-an-empty-signature
  ;; Core builds the delete pattern as `CScript() << vchSig' (interpreter.cpp:330).
  ;; For an EMPTY signature CScript::AppendDataSize (script.h:407-410) takes the
  ;; `size < OP_PUSHDATA1' branch and writes one 0x00 byte, so the pattern is
  ;; OP_0 and FindAndDelete's `if (b.empty()) return nFound' early-out
  ;; (interpreter.cpp:230-231) never fires: an OP_0 standing at an opcode
  ;; boundary in the scriptCode IS deleted, which CONST_SCRIPTCODE reports as
  ;; SCRIPT_ERR_SIG_FINDANDDELETE.
  (let ((empty (make-array 0 :element-type '(unsigned-byte 8)))
        ;; OP_0 <pubkey> CHECKSIG
        (with-op0 (%sf-script "00" "21" +sf-pubkey-hex+ "ac"))
        ;; <pubkey> CHECKSIG -- nothing to delete
        (without-op0 (%sf-script "21" +sf-pubkey-hex+ "ac"))
        ;; <0x0000> DROP <pubkey> CHECKSIG -- the 0x00 bytes are push PAYLOAD
        (op0-inside-push (%sf-script "020000" "75" "21" +sf-pubkey-hex+ "ac")))
    (is (equal '(nil :sig-findanddelete) (%sf-checksig "CONST_SCRIPTCODE" empty with-op0)))
    ;; The flag gates it, and nothing else about the spend changes.
    (is (equal '(nil nil) (%sf-checksig "" empty with-op0)))
    (is (equal '(nil nil) (%sf-checksig "CONST_SCRIPTCODE" empty without-op0)))
    ;; FindAndDelete matches at opcode boundaries only (interpreter.cpp:229-256).
    (is (equal '(nil nil) (%sf-checksig "CONST_SCRIPTCODE" empty op0-inside-push)))
    ;; SigVersion::BASE only: a witness v0 scriptCode is serialized untouched.
    (is (equal '(nil nil)
               (let ((bl.interop:*witness-v0-mode* t))
                 (%sf-checksig "CONST_SCRIPTCODE" empty with-op0))))))

(test const-scriptcode-findanddelete-pattern-carries-the-push-opcode
  ;; `CScript() << vchSig' emits the MINIMAL push: the length byte itself below
  ;; 76 bytes, `4c <len>' from 76 to 255 (script.h:407-416). Searching for the
  ;; bare signature bytes above 75 is no push encoding at all, so the 76-byte
  ;; twin of a matching 75-byte scriptCode was missed.
  (let* ((sig75 (%sf-filler 75))
         (sig76 (%sf-filler 76))
         ;; <sig> DROP <pubkey> CHECKSIG, the signature pushed as Core pushes it
         (tail (%sf-script "75" "21" +sf-pubkey-hex+ "ac"))
         (code75 (%sf-cat 75 sig75 tail))
         (code76 (%sf-cat #x4c 76 sig76 tail))
         ;; The same 76 bytes as the payload of one larger push: data, not a push
         ;; of the signature, so Core deletes nothing.
         (code76-as-data (%sf-cat #x4c 78 #x4c 76 sig76 #x75 tail)))
    (is (equal '(nil :sig-findanddelete) (%sf-checksig "CONST_SCRIPTCODE" sig75 code75)))
    (is (equal '(nil :sig-findanddelete) (%sf-checksig "CONST_SCRIPTCODE" sig76 code76)))
    (is (equal '(nil nil) (%sf-checksig "CONST_SCRIPTCODE" sig76 code76-as-data)))))

(test const-scriptcode-findanddelete-runs-for-every-checkmultisig-signature
  ;; Core deletes each of the nSigsCount signatures from the scriptCode before
  ;; a single one is checked (interpreter.cpp:1141-1150), empty ones included.
  ;; `OP_0 OP_0 OP_1 <pubkey> OP_1 CHECKMULTISIG' is dummy, one EMPTY signature,
  ;; m=1, one pubkey, n=1 -- and both OP_0s stand at opcode boundaries.
  (let ((script-sig (make-array 0 :element-type '(unsigned-byte 8)))
        (script-pubkey (%sf-script "00" "00" "51" "21" +sf-pubkey-hex+ "51" "ae")))
    ;; Consensus flags: the empty signature makes the multisig false in both
    ;; implementations whatever the scriptCode says.
    (is (equal '(nil :eval-false) (%sf-verify script-sig script-pubkey "")))
    ;; Policy flags: Core answers SCRIPT_ERR_SIG_FINDANDDELETE.
    (is (equal '(nil :error) (%sf-verify script-sig script-pubkey "CONST_SCRIPTCODE")))
    (is-true (bl.interop:last-checkmultisig-had-error-p))))

(test const-scriptcode-empty-signature-p2sh-spend-is-non-standard
  ;; The reachable relay case: redeemScript `OP_0 <pubkey> CHECKSIG NOT' is a
  ;; valid spend under the block flags (the empty signature makes CHECKSIG
  ;; false and OP_NOT makes the script true), and Core's PolicyScriptChecks
  ;; rejects it with SIG_FINDANDDELETE, so it must never be relayed.
  (destructuring-bind (script-sig script-pubkey)
      (%sf-p2sh-spend (%sf-script "00" "21" +sf-pubkey-hex+ "ac" "91"))
    (is (equal '(t nil) (%sf-verify script-sig script-pubkey "P2SH")))
    (is (equal '(nil :error) (%sf-verify script-sig script-pubkey "P2SH,CONST_SCRIPTCODE")))))
