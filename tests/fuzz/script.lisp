(in-package #:bitcoin-lisp.tests)

;;;; Core's script targets at the pin: fuzz/script.cpp, script_flags.cpp,
;;;; script_ops.cpp, eval_script.cpp, script_interpreter.cpp (script_interpreter
;;;; and sighash_cache) and script_format.cpp.

(def-suite :fuzz-script-tests :in :bitcoin-lisp-tests
  :description "Core fuzz script*.cpp / eval_script.cpp targets")

(in-suite :fuzz-script-tests)

;;; --- helpers ---------------------------------------------------------------

(defparameter +script-verify-flag-names+
  '("P2SH" "STRICTENC" "DERSIG" "LOW_S" "NULLDUMMY" "SIGPUSHONLY" "MINIMALDATA"
    "DISCOURAGE_UPGRADABLE_NOPS" "CLEANSTACK" "CHECKLOCKTIMEVERIFY"
    "CHECKSEQUENCEVERIFY" "WITNESS" "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM"
    "MINIMALIF" "NULLFAIL" "WITNESS_PUBKEYTYPE" "CONST_SCRIPTCODE" "TAPROOT"
    "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION" "DISCOURAGE_OP_SUCCESS"
    "DISCOURAGE_UPGRADABLE_PUBKEYTYPE")
  "script_verify_flag_name (script/interpreter.h:48-150): bit N is the Nth name.")

(defun script-flags-string (flags)
  "The comma-separated flag string the interpreter reads for the
script_verify_flags bit set FLAGS; bits past the enum have no name, as in Core."
  (format nil "~{~A~^,~}"
          (loop for name in +script-verify-flag-names+ for bit from 0
                when (logbitp bit flags) collect name)))

(defun valid-flag-combination-p (flags)
  "Core IsValidFlagCombination (test/util/script.cpp:8-13): CLEANSTACK needs
P2SH and WITNESS, WITNESS needs P2SH."
  (flet ((has (name) (logbitp (position name +script-verify-flag-names+ :test #'string=) flags)))
    (not (or (and (has "CLEANSTACK") (not (and (has "P2SH") (has "WITNESS"))))
             (and (has "WITNESS") (not (has "P2SH")))))))

(defparameter +fuzz-networks+ '(:mainnet :testnet3 :testnet4 :signet :regtest))

(defun consume-tx-destination (fdp)
  "Core ConsumeTxDestination (test/fuzz/util.cpp:189-233), as (values KIND
SCRIPT): the destination's GetScriptForDestination, NIL for CNoDestination."
  (flet ((push-script (prefix bytes)
           (let ((s (script-builder)))
             (dolist (op prefix) (script-<<-opcode s op))
             (script-<<-bytes s bytes)
             (script-bytes s))))
    (call-one-of fdp
      (values :none nil)
      (let* ((compressed (consume-bool fdp))
             (pk (construct-pubkey-bytes fdp (let ((v (make-array 65 :element-type '(unsigned-byte 8)
                                                                  :initial-element 0)))
                                                (replace v (consume-bytes fdp (if compressed 33 65))))
                                         compressed)))
        (values :pubkey (let ((s (script-builder)))
                          (script-<<-bytes s pk) (script-<<-opcode s #xac) (script-bytes s))))
      (values :pkhash (make-p2pkh-script (consume-uint160 fdp)))
      (values :scripthash (let ((s (script-builder)))
                            (script-<<-opcode s #xa9) (script-<<-bytes s (consume-uint160 fdp))
                            (script-<<-opcode s #x87) (script-bytes s)))
      (values :witness-v0-scripthash (push-script '(0) (consume-uint256 fdp)))
      (values :witness-v0-keyhash (push-script '(0) (consume-uint160 fdp)))
      (values :witness-v1-taproot (push-script '(#x51) (consume-uint256 fdp)))
      (values :anchor (%bytes #x51 #x02 #x4e #x73))
      (let ((program (consume-random-length-byte-vector fdp 40)))
        (when (< (length program) 2) (setf program (%bytes 0 0)))
        (values :witness-unknown
                (push-script (list (+ #x50 (consume-integral-in-range fdp 2 16 32))) program))))))

;;; --- script.cpp ------------------------------------------------------------

(define-fuzz-target script
    (buffer :core "script.cpp:40-186" :iterations 8000 :max-len 400)
  "The scriptPubKey predicates agree with one another as Core's do: a script
CompressScript takes decompresses to itself; IsStandard's verdict, Solver's
type, IsUnspendable and ExtractDestination (here SCRIPT->ADDRESS) imply each
other the ways script.cpp:45-81 asserts; and every destination -- decoded
from arbitrary text or built by ConsumeTxDestination -- survives
EncodeDestination/DecodeDestination (:130-147)."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (network (pick-value-in-array fdp +fuzz-networks+))
         (script (consume-script fdp)))
    ;; CompressScript / DecompressScript (:45-54)
    (let ((compressed (bl.ser:compress-script script)))
      (when compressed
        (let ((size (aref compressed 0)))
          (fuzz-assert (<= size 5) "compressed size id ~D > 5" size)
          (let ((decompressed (bl.ser:decompress-script size (subseq compressed 1))))
            (fuzz-assert (and decompressed (equalp (fuzz-sabotage decompressed) script))
                         "~A decompresses to ~A" (bl.crypto:bytes-to-hex script)
                         (and decompressed (bl.crypto:bytes-to-hex decompressed)))))))
    (let* ((type (bl.val:classify-script script))
           (standard (bl.val:standard-output-script-p script))
           (unspendable (bl.store:script-unspendable-p script))
           (address (bl.rpc:script->address script network)))
      ;; IsStandard / Solver / IsUnspendable (:56-71)
      (unless standard
        (fuzz-assert (member type '(:nonstandard :nulldata :multisig))
                     "~A is not standard but classifies as ~S" (bl.crypto:bytes-to-hex script) type))
      (when (eq type :nonstandard)
        (fuzz-assert (fuzz-sabotage (not standard)) "a NONSTANDARD script is standard"))
      (when (eq type :nulldata)
        (fuzz-assert unspendable "a NULL_DATA script is spendable"))
      (when unspendable
        (fuzz-assert (member type '(:nulldata :nonstandard))
                     "an unspendable script classifies as ~S" type))
      ;; ExtractDestination (:73-83)
      (unless address
        (fuzz-assert (member type '(:pubkey :nonstandard :nulldata :multisig))
                     "no destination for a ~S script" type))
      (when (member type '(:nonstandard :nulldata :multisig))
        (fuzz-assert (null address) "a ~S script has the address ~A" type address))
      ;; The address a script has decodes back to it.
      (when address
        (fuzz-assert (equalp (fuzz-sabotage (nth-value 1 (bl.crypto:decode-address address network)))
                             script)
                     "~A -> ~A -> another script" (bl.crypto:bytes-to-hex script) address)))
    ;; The sigop count, the witness-program and P2SH predicates (:87-98)
    (bl.val:count-script-sigops script :accurate nil)
    ;; Destinations (:130-157)
    (flet ((round-trip (kind dest-script)
             (let* ((encoded (or (and dest-script (bl.rpc:script->address dest-script network)) ""))
                    (valid (not (member kind '(:none :pubkey))))
                    (decoded (nth-value 1 (bl.crypto:decode-address encoded network))))
               (unless (eq kind :pubkey)
                 (fuzz-assert (eq (null dest-script) (fuzz-sabotage (not valid)))
                              "destination ~S: script ~A but valid ~A" kind dest-script valid)
                 (fuzz-assert (equalp decoded dest-script)
                              "destination ~S: ~A encodes as ~S, which decodes to ~A"
                              kind (and dest-script (bl.crypto:bytes-to-hex dest-script)) encoded
                              (and decoded (bl.crypto:bytes-to-hex decoded)))
                 (fuzz-assert (eq valid (and decoded t))
                              "destination ~S: IsValidDestinationString disagrees" kind)))))
      (if (consume-bool fdp)
          (let ((decoded (nth-value 1 (bl.crypto:decode-address
                                       (consume-random-length-string fdp) network))))
            (round-trip (if decoded (bl.val:classify-script decoded) :none) decoded))
          (multiple-value-call #'round-trip (consume-tx-destination fdp))))))

;;; --- script_flags.cpp --------------------------------------------------------

(defun %script-flags-corpus (fdp)
  "A transaction, two flag words and one spent output per input, laid out as
script_flags.cpp reads them. The spent outputs lean towards scripts the inputs
can satisfy -- P2WSH(OP_TRUE), OP_TRUE, bare -- so passing spends, where the
monotonicity half of the property lives, are common."
  (let* ((tx (consume-transaction fdp :max-num-in 4 :max-num-out 3))
         (bb (bl.ser:make-byte-buf)))
    (bl.ser:bb-write-bytes bb (bl.ser:transaction-wire-bytes tx))
    (bl.ser:bb-write-u64-le bb (consume-integral fdp :u64))
    (bl.ser:bb-write-u64-le bb (consume-integral fdp :u64))
    (dotimes (i (length (bl.ser:transaction-inputs tx)))
      (declare (ignorable i))
      (bl.ser:bb-write-tx-out
       bb (bl.ser:make-tx-out
           :value (consume-money fdp)
           :script-pubkey (call-one-of fdp
                            +p2wsh-op-true+
                            (%bytes #x51)
                            (make-array 0 :element-type '(unsigned-byte 8))
                            (consume-script fdp :maybe-p2wsh t)))))
    (bl.ser:bb-finish bb)))

(defun %verify-input (tx index spent flags)
  "Core VerifyScript for input INDEX of TX, the SPENT outputs all known, under
the script_verify_flags FLAGS: (values ok error-keyword)."
  (let* ((utxos (map 'vector (lambda (out)
                               (bl.store:make-utxo-entry :value (bl.ser:tx-out-value out)
                                                         :script-pubkey (bl.ser:tx-out-script-pubkey out)))
                     spent))
         (bl.interop:*script-flags* (script-flags-string flags))
         (bl.interop:*precomputed-sighash* (bl.interop:init-precomputed-sighash tx utxos))
         (bl.interop:*current-spent-utxos* utxos))
    (bl.val:validate-input-script tx index (aref utxos index))))

(define-fuzz-target script-flags
    (buffer :core "script_flags.cpp:27-82" :iterations 4000 :max-len 600
            :corpus #'%script-flags-corpus)
  "Every script verification flag is a soft fork: removing flags from a
passing input, or adding them to a failing one, never changes the verdict,
and the verdict and the error agree (ret == (serror == SCRIPT_ERR_OK)),
under every valid flag combination and every input."
  (when (> (length buffer) 100000) (fuzz-reject))
  (let* ((br (bl.ser:make-byte-reader-from buffer))
         (tx (fuzz-deserialize (bl.ser:br-read-transaction br)))
         (flags (fuzz-deserialize (bl.ser:br-read-u64-le br))))
    (unless (valid-flag-combination-p flags) (fuzz-reject))
    (let* ((fuzzed (fuzz-deserialize (bl.ser:br-read-u64-le br)))
           (spent (loop repeat (length (bl.ser:transaction-inputs tx))
                        collect (let ((out (fuzz-deserialize (bl.ser:br-read-tx-out br))))
                                  (unless (bl.val:money-range-p (bl.ser:tx-out-value out))
                                    (setf (bl.ser:tx-out-value out) 1))
                                  out))))
      (dotimes (i (length spent))
        (multiple-value-bind (ok err) (%verify-input tx i spent flags)
          (fuzz-assert (eq (and ok t) (null err)) "input ~D: verdict ~A with error ~S" i ok err)
          (setf flags (if ok (logandc2 flags fuzzed) (logior flags fuzzed)))
          (unless (valid-flag-combination-p flags) (return))
          (multiple-value-bind (ok2 err2) (%verify-input tx i spent flags)
            (fuzz-assert (eq (and ok2 t) (null err2)) "input ~D: verdict ~A with error ~S" i ok2 err2)
            (fuzz-assert (eq (and ok t) (fuzz-sabotage (and ok2 t)))
                         "input ~D ~:[failed~;passed~] under ~A but ~:[failed~;passed~] under ~A (~S)"
                         i ok (script-flags-string (if ok (logior flags fuzzed) (logandc2 flags fuzzed)))
                         ok2 (script-flags-string flags) err2)))))))

;;; --- script_ops.cpp ----------------------------------------------------------

(define-fuzz-target script-ops
    (buffer :core "script_ops.cpp:15-73" :iterations 8000 :max-len 400)
  "A script built by any sequence of CScript operations answers every
predicate script_ops.cpp calls, and the predicates agree with the Solver they
are the fast paths of: IsPayToScriptHash is SCRIPTHASH, IsWitnessProgram is a
witness type or P2A, and GetOp walks the script to its end or to a truncated
push."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (script (script-builder)))
    (script-append script (consume-script fdp))
    (limited-while ((plusp (remaining-bytes fdp)) 1000000)
      (call-one-of fdp
        (progn (setf (fill-pointer script) 0) (script-append script (consume-script fdp)))
        (progn (setf (fill-pointer script) 0) (script-append script (consume-script fdp)))
        (script-<<-int64 script (consume-integral fdp :i64))
        (script-<<-opcode script (consume-opcode-type fdp))
        (script-<<-bytes script (script-num-serialize (consume-integral fdp :i64)))
        (script-<<-bytes script (consume-random-length-byte-vector fdp))
        (setf (fill-pointer script) 0)))
    (let* ((script (script-bytes script))
           (type (bl.val:classify-script script)))
      (bl.val:count-script-sigops script :accurate nil)
      (bl.val:count-script-sigops script :accurate t)
      (bl.interop:script-is-push-only-p script)
      (bl.store:script-unspendable-p script)
      (fuzz-assert (eq (eq type :scripthash) (fuzz-sabotage (bl.val:script-is-p2sh-p script)))
                   "IsPayToScriptHash disagrees with Solver's ~S" type)
      ;; Solver (solver.cpp:141-176): a witness program is one of the four
      ;; witness types or P2A, or -- a version-0 program of an irregular
      ;; length -- NONSTANDARD; nothing else is.
      (let ((witness-type (member type '(:witness-v0-keyhash :witness-v0-scripthash
                                         :witness-v1-taproot :anchor :witness-unknown)))
            (witness-program (bl.val:output-witness-program-p script)))
        (when witness-type
          (fuzz-assert (fuzz-sabotage witness-program) "a ~S script is not a witness program" type))
        (when witness-program
          (fuzz-assert (or witness-type
                           (and (eq type :nonstandard)
                                (zerop (bl.val:witness-program-parts script))))
                       "witness program ~A classifies as ~S" (bl.crypto:bytes-to-hex script) type)))
      ;; GetOp from the start: every step advances, and the walk ends at the
      ;; end of the script or at a push that overruns it.
      (let ((pos 0) (steps 0))
        (loop
          (when (>= pos (length script)) (return))
          (let ((next (nth-value 2 (bl.val:next-script-op script pos))))
            (when (or (null next) (> next (length script))) (return))
            (fuzz-assert (> next pos) "GetOp did not advance at ~D" pos)
            (setf pos next)
            (incf steps)))
        (fuzz-assert (<= steps (length script)) "~D ops in ~D bytes" steps (length script))))))

;;; --- eval_script.cpp ---------------------------------------------------------

(define-fuzz-target eval-script
    (buffer :core "eval_script.cpp:14-35" :iterations 8000 :max-len 300
            :corpus (lambda (fdp)
                      (let ((bb (bl.ser:make-byte-buf)))
                        (bl.ser:bb-write-bytes bb (consume-script fdp))
                        (bl.ser:bb-write-u64-le bb (consume-integral fdp :u64))
                        (bl.ser:bb-finish bb))))
  "EvalScript over arbitrary bytes, under arbitrary flags, as BASE and as
WITNESS_V0, never escapes with a condition -- it fails with a script error or
succeeds -- and, a pure function of the script and the flags, gives the same
answer every time it is asked."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (flags (consume-integral fdp :u64))
         (script (consume-remaining-bytes fdp)))
    (dolist (witness-v0 '(nil t))
      (let ((bl.interop:*script-flags* (script-flags-string flags))
            (sigversion (if witness-v0
                            bl.script:SigVersionWitnessV0
                            bl.script:SigVersionBase)))
        (let ((first (multiple-value-list (bl.interop:run-script script sigversion)))
              (again (multiple-value-list (bl.interop:run-script script sigversion))))
          (fuzz-assert (eq (first first) (fuzz-sabotage (first again)))
                       "EvalScript ~A under ~A answered ~S then ~S"
                       (bl.crypto:bytes-to-hex script) bl.interop:*script-flags*
                       (first first) (first again)))))))

;;; --- script_interpreter.cpp --------------------------------------------------

(defun %script-interpreter-corpus (fdp)
  "A buffer script_interpreter.cpp reads as: no script code (the last byte,
ConsumeScript's first ConsumeBool, is even), a serialized ConsumeTransaction
transaction, input 0, and random hash type, amount and sigversion."
  (concatenate '(simple-array (unsigned-byte 8) (*))
               (fdp-random-length-bytes
                (bl.ser:transaction-wire-bytes (consume-transaction fdp :max-num-in 3 :max-num-out 3)))
               (consume-bytes fdp 9)
               (make-array 5 :element-type '(unsigned-byte 8) :initial-element 0)))

(define-fuzz-target script-interpreter
    (buffer :core "script_interpreter.cpp:25-56" :iterations 6000 :max-len 500
            :corpus #'%script-interpreter-corpus)
  "SignatureHash answers for any script code, deserialized transaction, input,
hash type, amount and sigversion; and CastToBool answers for any bytes -- the
two ports of it, the Coalton interpreter's on the consensus path and the
reference copy in src/validation/script.lisp, alike."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (script-code (consume-script fdp))
         (tx (consume-deserializable fdp #'bl.ser:parse-tx-payload)))
    (when tx
      (let ((in (consume-integral fdp :u32)))
        (when (< in (length (bl.ser:transaction-inputs tx)))
          ;; The hash type is the last byte of a signature wherever the
          ;; interpreter asks for a sighash, so its domain here is a byte.
          (%sighash tx in script-code (consume-integral fdp :u8) (consume-money fdp)
                    (pick-value-in-array fdp '(nil t)) nil))))
    (let ((bytes (consume-random-length-byte-vector fdp)))
      (fuzz-assert (eq (bl.val:cast-to-bool bytes)
                       (fuzz-sabotage (eq (bl.script:cast-to-bool
                                           (bl.interop:cl-array-to-coalton-vector bytes))
                                          coalton:True)))
                   "CastToBool ~A: the two ports disagree" (bl.crypto:bytes-to-hex bytes)))))

(defun %sighash (tx in script-code hash-type amount witness-v0 precomputed)
  "Core SignatureHash for input IN of TX: BIP143 when WITNESS-V0, the legacy
algorithm otherwise; with PRECOMPUTED, the transaction's precomputed data
(Core's PrecomputedTransactionData / SigHashCache) is bound."
  (let ((bl.interop:*current-tx* tx)
        (bl.interop:*current-input-index* in)
        (bl.interop:*precomputed-sighash* (and precomputed (bl.interop:init-precomputed-sighash tx))))
    (if witness-v0
        (bl.interop:compute-bip143-sighash script-code amount hash-type)
        (bl.interop:compute-legacy-sighash tx in script-code hash-type))))

(define-fuzz-target sighash-cache
    (buffer :core "script_interpreter.cpp:58-83" :iterations 3000 :max-len 500)
  "Differential SignatureHash: for a ConsumeTransaction transaction and a
hundred hash types, the hash computed with the transaction's precomputed data
is the hash computed without it, for BASE and WITNESS_V0 alike. (Core feeds
int8 and int32 hash types; the interpreter only ever asks with a signature's
last byte, so ours are that byte.)"
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (script-code (consume-script fdp))
         (tx (consume-transaction fdp)))
    (when (zerop (length (bl.ser:transaction-inputs tx))) (fuzz-reject))
    (let ((in (consume-integral-in-range fdp 0 (1- (length (bl.ser:transaction-inputs tx))) 32))
          (amount (consume-money fdp))
          (witness-v0 (= 1 (consume-integral-in-range fdp 0 1 32))))
      (dotimes (i 100)
        (let* ((hash-type (ldb (byte 8 0) (if (zerop (logand i 2))
                                               (consume-integral fdp :i8)
                                               (consume-integral fdp :i32))))
               (plain (%sighash tx in script-code hash-type amount witness-v0 nil))
               (cached (%sighash tx in script-code hash-type amount witness-v0 t)))
          (fuzz-assert (equalp plain (fuzz-sabotage cached))
                       "~:[legacy~;BIP143~] sighash of type ~D differs with the precomputed data"
                       witness-v0 hash-type))))))

;;; --- script_format.cpp --------------------------------------------------------

(defvar *fuzz-decodescript-node* nil
  "One minimal regtest node for every decodescript the script-format target asks.")

(define-fuzz-target script-format
    (buffer :core "script_format.cpp:23-38" :iterations 3000 :max-len 300)
  "FormatScript, ScriptToAsmStr (with and without sighash decoding) and
ScriptToUniv (decodescript) answer for every script ConsumeScript builds, and
ScriptToAsmStr prints one token per op GetOp decodes, plus `[error]' for a
push that runs off the end (core_io.cpp:357-400)."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (script (consume-script fdp)))
    (when (> (length script) (floor bl.val:+max-standard-tx-weight+ 4)) (fuzz-reject))
    (let* ((asm (bl.val:disassemble-script script :sighash-decode (consume-bool fdp)))
           (tokens (count-if #'plusp (mapcar #'length (uiop:split-string asm :separator " "))))
           (ops (let ((pos 0) (n 0))
                  (loop while (< pos (length script))
                        do (multiple-value-bind (op data next) (bl.val:next-script-op script pos)
                             (declare (ignore data))
                             (incf n)
                             (setf pos (if op next (length script)))))
                  n)))
      (fuzz-assert (= tokens (fuzz-sabotage ops))
                   "~A: ~D ops, ~D asm tokens: ~A" (bl.crypto:bytes-to-hex script) ops tokens asm))
    (let ((result (bl.rpc:dispatch-rpc-method
                   (or *fuzz-decodescript-node*
                       (setf *fuzz-decodescript-node* (make-test-node :network :regtest)))
                   "decodescript" (list (bl.crypto:bytes-to-hex script)))))
      (fuzz-assert (assoc "type" result :test #'string=) "decodescript answered no type"))))
