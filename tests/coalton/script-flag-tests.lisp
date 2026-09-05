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

(defun %sf-checksig (flags sig script-code
                     &optional (pubkey (%sf-script +sf-pubkey-hex+)))
  "(verify-checksig SIG PUBKEY SCRIPT-CODE) under FLAGS, as a list. PUBKEY
defaults to the well-formed compressed key, so a caller passing one is asking
about the pubkey-encoding arms."
  (%sf-under-flags flags
                   (lambda ()
                     (bl.interop:verify-checksig sig pubkey script-code))))

(defun %sf-p2wpkh (flags sig pubkey)
  "(validate-p2wpkh (SIG PUBKEY)) against the program HASH160(PUBKEY) under
FLAGS, as a list -- the witness-v0 CHECKSIG path, reached the way the
interpreter reaches it."
  (%sf-under-flags flags
                   (lambda ()
                     (bl.interop:validate-p2wpkh (list sig pubkey)
                                                 (bl.crypto:hash160 pubkey)
                                                 100000))))

(defun %sf-der-sig (s hashtype)
  "A well-formed 71-byte DER signature: r is 32 bytes of 0x01, S is the
32-byte vector S, and HASHTYPE is the trailing byte Core's
CheckSignatureEncoding reads last."
  (%sf-cat #x30 #x44 #x02 #x20
           (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1)
           #x02 #x20 s hashtype))

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

(test const-scriptcode-rejects-a-codeseparator-in-every-legacy-script
  ;; Core's OP_CODESEPARATOR check sits in EvalScript's opcode loop ABOVE the
  ;; fExec guard (interpreter.cpp:474-476), and VerifyScript runs EvalScript
  ;; three times per legacy input: scriptSig (:2020), scriptPubKey (:2023) and
  ;; the P2SH redeem script (:2069). One in any of them is rejected, executed
  ;; or not. Only the scriptPubKey arm used to be checked.
  (let ((codesep-then-true (%sf-script "ab" "51"))          ; CODESEPARATOR 1
        (true-script (%sf-script "51"))
        (empty (make-array 0 :element-type '(unsigned-byte 8))))
    (destructuring-bind (p2sh-sig p2sh-pubkey) (%sf-p2sh-spend codesep-then-true)
      (is (equal '(nil :op-codeseparator)
                 (%sf-verify empty codesep-then-true "CONST_SCRIPTCODE")))
      (is (equal '(nil :op-codeseparator)
                 (%sf-verify codesep-then-true true-script "CONST_SCRIPTCODE")))
      ;; The redeem script is the arm a spender can reach: a scriptSig carrying
      ;; OP_CODESEPARATOR is not push-only and is non-standard already.
      (is (equal '(nil :op-codeseparator)
                 (%sf-verify p2sh-sig p2sh-pubkey "P2SH,CONST_SCRIPTCODE")))
      ;; Policy, not consensus: all three spend fine under the block flags.
      (is (equal '(t nil) (%sf-verify empty codesep-then-true "")))
      (is (equal '(t nil) (%sf-verify codesep-then-true true-script "")))
      (is (equal '(t nil) (%sf-verify p2sh-sig p2sh-pubkey "P2SH"))))))

(test const-scriptcode-codeseparator-check-ignores-fexec-and-push-payloads
  ;; Above the fExec guard means an unexecuted branch counts...
  (let ((unexecuted (%sf-script "00" "63" "ab" "68" "51"))  ; 0 IF CODESEP ENDIF 1
        ;; ...and 0xab inside a push payload is data, not an opcode.
        (payload (%sf-script "01ab" "75" "51")))            ; <0xab> DROP 1
    (is (equal '(nil :op-codeseparator) (%sf-verify (%sf-script "") unexecuted "CONST_SCRIPTCODE")))
    (is (equal '(t nil) (%sf-verify (%sf-script "") unexecuted "")))
    (is (equal '(t nil) (%sf-verify (%sf-script "") payload "CONST_SCRIPTCODE")))))

;;;; --- CheckSignatureEncoding / CheckPubKeyEncoding order -----------------

(test checksig-encoding-checks-run-in-cores-order
  "EvalChecksigPreTapscript runs CheckSignatureEncoding and only then
CheckPubKeyEncoding, in one `if' before CheckECDSASignature
(interpreter.cpp:336-339). Each is itself ordered: the signature check is
DER (SIG_DER), then LOW_S (SIG_HIGH_S), then the hashtype byte
(SIG_HASHTYPE) (:202-216); the pubkey check is STRICTENC (PUBKEYTYPE), then
WITNESS_PUBKEYTYPE (:218-227).

Every vector here fails at least two of those arms, so the assertion is about
which one answers. Both CHECKSIG paths had the low-S rejection AFTER the
verify -- and so after the pubkey arms -- and the witness path ran
WITNESS_PUBKEYTYPE before STRICTENC, the reverse of Core."
  (let* ((low-s (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
         (high-s (let ((a (make-array 32 :element-type '(unsigned-byte 8)
                                         :initial-element #xff)))
                   (setf (aref a 0) #x7f)  ; above n/2, still a positive DER integer
                   a))
         (sig-low (%sf-der-sig low-s #x01))
         (sig-high (%sf-der-sig high-s #x01))
         (sig-high-bad-hashtype (%sf-der-sig high-s #x05))
         (sig-low-bad-hashtype (%sf-der-sig low-s #x05))
         (empty (make-array 0 :element-type '(unsigned-byte 8)))
         ;; Ten bytes: neither a compressed nor an uncompressed encoding.
         (bad-key (%sf-script "07070707070707070707"))
         (uncompressed (%sf-cat #x04 (make-array 64 :element-type '(unsigned-byte 8)
                                                    :initial-element 3)))
         (compressed (%sf-script +sf-pubkey-hex+)))
    ;; Legacy: LOW_S answers before the pubkey is looked at.
    (is (equal '(nil :sig-high-s)
               (%sf-checksig "DERSIG,STRICTENC,LOW_S" sig-high empty bad-key)))
    ;; ... and before the hashtype byte, which is the arm after it.
    (is (equal '(nil :sig-high-s)
               (%sf-checksig "DERSIG,STRICTENC,LOW_S" sig-high-bad-hashtype empty
                             compressed)))
    ;; Controls: with a low S the later arms answer, in their own order.
    (is (equal '(nil :sig-hashtype)
               (%sf-checksig "DERSIG,STRICTENC,LOW_S" sig-low-bad-hashtype empty
                             bad-key)))
    (is (equal '(nil :pubkeytype)
               (%sf-checksig "DERSIG,STRICTENC,LOW_S" sig-low empty bad-key)))
    ;; And an empty signature still reaches the pubkey arms (CheckSignatureEncoding
    ;; passes it, interpreter.cpp:186-188).
    (is (equal '(nil :pubkeytype) (%sf-checksig "STRICTENC" empty empty bad-key)))
    ;; Witness v0, through the P2WPKH program the interpreter builds: same
    ;; order, and LOW_S again answers before the hashtype byte.
    (is (equal '(nil :sig-high-s)
               (%sf-p2wpkh "DERSIG,STRICTENC,LOW_S,WITNESS_PUBKEYTYPE"
                           sig-high-bad-hashtype compressed)))
    ;; Control: the same vector with a low S is SIG_HASHTYPE, so that arm is live.
    (is (equal '(nil :sig-hashtype)
               (%sf-p2wpkh "DERSIG,STRICTENC,LOW_S,WITNESS_PUBKEYTYPE"
                           sig-low-bad-hashtype compressed)))
    ;; Control: an uncompressed key is still refused for a witness v0 spend --
    ;; the WITNESS_PUBKEYTYPE arm fires, now from inside the CHECKSIG.
    (is (equal '(nil :witness-pubkeytype)
               (%sf-p2wpkh "DERSIG,STRICTENC,WITNESS_PUBKEYTYPE" sig-low
                           uncompressed)))
    ;; The STRICTENC arm precedes the WITNESS_PUBKEYTYPE one: a key that is
    ;; neither encoding is PUBKEYTYPE, not WITNESS_PUBKEYTYPE -- which is only
    ;; visible now that the P2WPKH path decides the pubkey encoding inside the
    ;; CHECKSIG, where Core decides it, instead of ahead of the program match.
    (is (equal '(nil :pubkeytype)
               (%sf-p2wpkh "DERSIG,STRICTENC,LOW_S,WITNESS_PUBKEYTYPE" sig-low
                           bad-key)))))
