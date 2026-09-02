(in-package #:bitcoin-lisp.validation)

;;;; Output script classification (Core script/solver.cpp)
;;;
;;; ONE classifier. Before this file the scriptPubKey pattern table was
;;; transcribed in six places -- CLASSIFY-SCRIPT here (looser than Core:
;;; any 33/65-byte push was a pubkey, a v0 program of odd length was
;;; witness-unknown, OP_RETURN needed no push-only tail), the faithful
;;; CLASSIFY-OUTPUT-SCRIPT in transaction.lisp that standardness used, the
;;; RPC's own SCRIPT-TYPE (the only one that knew P2A), SCRIPT->ADDRESS in
;;; the descriptor code, and two matchers in psbt.lisp / compressor.lisp
;;; (those two are Core's own separate tables, tapscript leaves and script
;;; compression, and stay). The copies had already diverged: getblock
;;; reported "anchor" for an output that decodescript called
;;; "witness_unknown". CLASSIFY-SCRIPT is Solver, in Solver's order, with
;;; Solver's vSolutionsRet as a plist; everything else asks it.

;;; --- The matchers (Core Match*, IsPayToScriptHash, IsWitnessProgram) ---

(defun script-is-p2sh-p (script)
  "OP_HASH160 <20 bytes> OP_EQUAL (Core CScript::IsPayToScriptHash)."
  (and (= (length script) 23)
       (= (aref script 0) +op-hash160+)
       (= (aref script 1) 20)
       (= (aref script 22) +op-equal+)))

(defun output-witness-program-p (script-pubkey)
  "True if SCRIPT-PUBKEY is a witness program: a version byte (OP_0, or
OP_1..OP_16) followed by a single push of 2-40 bytes that consumes the rest
of the script (Core CScript::IsWitnessProgram)."
  (let ((len (length script-pubkey)))
    (and (>= len 4) (<= len 42)
         (let ((v (aref script-pubkey 0)))
           (or (= v #x00) (<= #x51 v #x60)))   ; OP_0 or OP_1..OP_16
         (let ((push (aref script-pubkey 1)))
           (and (<= 2 push 40) (= len (+ 2 push)))))))

(defun witness-program-parts (script)
  "If SCRIPT is a witness program, return (VALUES version program-bytes);
otherwise NIL. Version is 0 for OP_0, 1..16 for OP_1..OP_16."
  (when (output-witness-program-p script)
    (let ((v (aref script 0)))
      (values (if (= v #x00) 0 (- v #x50))   ; OP_1 (#x51) -> version 1
              (subseq script 2)))))

(defun pay-to-anchor-p (script-pubkey)
  "True for a pay-to-anchor (P2A) output: the witness-v1 program OP_1 <push-2
0x4e73>, byte-exactly #x51 #x02 #x4e #x73 (Core CScript::IsPayToAnchor,
script/script.h). Spending a P2A never requires witness data."
  (and (= (length script-pubkey) 4)
       (= (aref script-pubkey 0) #x51)
       (= (aref script-pubkey 1) #x02)
       (= (aref script-pubkey 2) #x4e)
       (= (aref script-pubkey 3) #x73)))

(defun %op-return-push-only-p (script)
  "T if the bytes after the leading OP_RETURN in SCRIPT are push-only (only data
pushes / OP_0 / OP_1NEGATE / OP_1..OP_16), matching Core CScript::IsPushOnly.
Any non-push opcode -- or a push that runs past the end -- fails."
  (let ((len (length script)) (i 1))    ; skip OP_RETURN at index 0
    (loop while (< i len) do
      (let ((op (aref script i)))
        (cond
          ((<= op #x4b) (incf i (+ 1 op)))                          ; OP_0 / direct push
          ((= op #x4c) (if (< (1+ i) len)                           ; OP_PUSHDATA1
                           (incf i (+ 2 (aref script (1+ i))))
                           (return-from %op-return-push-only-p nil)))
          ((= op #x4d) (if (< (+ i 2) len)                          ; OP_PUSHDATA2
                           (incf i (+ 3 (aref script (1+ i)) (ash (aref script (+ i 2)) 8)))
                           (return-from %op-return-push-only-p nil)))
          ((= op #x4e) (if (< (+ i 4) len)                          ; OP_PUSHDATA4
                           (incf i (+ 5 (aref script (1+ i)) (ash (aref script (+ i 2)) 8)
                                      (ash (aref script (+ i 3)) 16) (ash (aref script (+ i 4)) 24)))
                           (return-from %op-return-push-only-p nil)))
          ((<= op #x60) (incf i))                                   ; OP_1NEGATE / OP_1..OP_16
          (t (return-from %op-return-push-only-p nil)))))           ; non-push opcode
    (= i len)))                          ; NIL if a push overran the script end

(defun null-data-script-p (script-pubkey)
  "True for a NULL_DATA (OP_RETURN data-carrier) scriptPubKey: a leading
OP_RETURN whose remaining bytes are push-only (Core Solver's NULL_DATA
classification, script/solver.cpp). Size is deliberately NOT considered --
the -datacarriersize limit is a shared per-transaction budget, checked in
VALIDATE-TRANSACTION-FOR-MEMPOOL against each such output's whole script
size (Core IsStandardTx, policy.cpp:136-150)."
  (and (>= (length script-pubkey) 1)
       (= (aref script-pubkey 0) #x6a)   ; OP_RETURN
       (%op-return-push-only-p script-pubkey)))

(defun %match-p2pkh (script)
  "T for OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG (Core
MatchPayToPubkeyHash, solver.cpp:50-57)."
  (and (= (length script) 25)
       (= (aref script 0) #x76)    ; OP_DUP
       (= (aref script 1) #xa9)    ; OP_HASH160
       (= (aref script 2) #x14)    ; push 20 bytes
       (= (aref script 23) #x88)   ; OP_EQUALVERIFY
       (= (aref script 24) #xac))) ; OP_CHECKSIG

(defun %valid-pubkey-push-p (script pos)
  "The push at POS in SCRIPT carries a pubkey of valid SIZE (Core
CPubKey::ValidSize, via GetLen on the header byte): 33 bytes with header
02/03, or 65 bytes with header 04/06/07. A 33-byte push starting 04 is NOT a
pubkey. Returns the key length, or NIL."
  (let ((len (length script)))
    (when (< (1+ pos) len)
      (let ((plen (aref script pos))
            (header (aref script (1+ pos))))
        (cond ((and (= plen 33) (member header '(#x02 #x03))) 33)
              ((and (= plen 65) (member header '(#x04 #x06 #x07))) 65))))))

(defun %match-p2pk (script)
  "Pubkey length for a bare pay-to-pubkey SCRIPT (<push key> OP_CHECKSIG), or
NIL (Core MatchPayToPubkey, solver.cpp:36-47)."
  (let ((len (length script)))
    (and (or (= len 35) (= len 67))
         (= (aref script (1- len)) #xac)                  ; OP_CHECKSIG
         (eql (%valid-pubkey-push-p script 0) (- len 2)))))

(defun %match-multisig (script)
  "(values m n pubkeys) when SCRIPT is bare multisig -- OP_m <key>.. OP_n
OP_CHECKMULTISIG with 1<=m<=n<=16 and every key a push of valid pubkey size
-- else NIL.

This is Core MatchMultisig: the SHAPE only. The n<=3 cap is an IsStandard
rule for OUTPUTS, not part of the classification, and an input SPENDING a
larger bare multisig is still standard (AreInputsStandard only rejects
NONSTANDARD/WITNESS_UNKNOWN)."
  (let ((len (length script)))
    (when (and (>= len 4)
               (= (aref script (1- len)) #xae)          ; OP_CHECKMULTISIG
               (<= #x51 (aref script 0) #x60)           ; OP_m (1..16)
               (<= #x51 (aref script (- len 2)) #x60))  ; OP_n (1..16)
      (let ((m (- (aref script 0) #x50))
            (n (- (aref script (- len 2)) #x50))
            (pos 1)
            (keys '()))
        (when (<= 1 m n 16)
          ;; Walk the n key pushes between OP_m and OP_n.
          (loop while (< pos (- len 2))
                do (let ((plen (%valid-pubkey-push-p script pos)))
                     (unless (and plen (<= (+ pos 1 plen) (- len 2)))
                       (return-from %match-multisig nil))
                     (push (subseq script (1+ pos) (+ pos 1 plen)) keys)
                     (incf pos (1+ plen))
                     (when (> (length keys) n)
                       (return-from %match-multisig nil))))
          (when (and (= pos (- len 2)) (= (length keys) n))
            (values m n (nreverse keys))))))))

;;; --- Solver ---

(defun classify-script (script)
  "Classify SCRIPT the way Core's Solver does (solver.cpp:141), returning
(VALUES type data): TYPE is the TxoutType keyword -- :scripthash,
:witness-v0-keyhash, :witness-v0-scripthash, :witness-v1-taproot, :anchor,
:witness-unknown, :nulldata, :pubkey, :pubkeyhash, :multisig or
:nonstandard -- and DATA is vSolutionsRet as a plist: :hash for the two
hash forms, :witness-version and :witness-program for every witness
program (P2A included), :data for nulldata, :pubkey, and :m :n :pubkeys for
bare multisig.

The ORDER is Solver's and matters. P2SH is matched first (it is the most
constrained form). Witness programs come next, and note the asymmetry: an
IRREGULAR version-0 program is :nonstandard, while v1..v16 are
:witness-unknown -- standard as an OUTPUT (the forward-compat mechanism that
let segwit and taproot outputs relay before activation) but NOT standard to
SPEND. Only after that do the bare key forms match, so an OP_RETURN or a
witness program can never be read as a key script."
  (cond
    ((script-is-p2sh-p script)
     (values :scripthash (list :hash (subseq script 2 22))))
    ((output-witness-program-p script)
     (multiple-value-bind (version program) (witness-program-parts script)
       (let ((data (list :witness-version version :witness-program program)))
         (cond ((and (= version 0) (= (length program) 20)) (values :witness-v0-keyhash data))
               ((and (= version 0) (= (length program) 32)) (values :witness-v0-scripthash data))
               ((and (= version 1) (= (length program) 32)) (values :witness-v1-taproot data))
               ((pay-to-anchor-p script) (values :anchor data))
               ((/= version 0) (values :witness-unknown data))
               ;; Irregular v0 program: reserved, never relayed.
               (t (values :nonstandard nil))))))
    ;; OP_RETURN data carrier: NULL_DATA whenever the bytes after OP_RETURN
    ;; are push-only (solver.cpp:185) -- no size cap and no -datacarrier gate
    ;; here, those live in the SHARED per-transaction byte budget IsStandardTx
    ;; tracks across all NULL_DATA outputs (policy.cpp:136-150).
    ((null-data-script-p script)
     (values :nulldata (list :data (subseq script 1))))
    ((%match-p2pk script)
     (values :pubkey (list :pubkey (subseq script 1 (1- (length script))))))
    ((%match-p2pkh script)
     (values :pubkeyhash (list :hash (subseq script 3 23))))
    (t
     (multiple-value-bind (m n pubkeys) (%match-multisig script)
       (if m
           (values :multisig (list :m m :n n :pubkeys pubkeys))
           (values :nonstandard nil))))))

(defun script-type-to-string (type)
  "Core's GetTxnOutputType name for the TxoutType keyword TYPE."
  (case type
    (:pubkeyhash "pubkeyhash")
    (:scripthash "scripthash")
    (:witness-v0-keyhash "witness_v0_keyhash")
    (:witness-v0-scripthash "witness_v0_scripthash")
    (:witness-v1-taproot "witness_v1_taproot")
    (:anchor "anchor")
    (:witness-unknown "witness_unknown")
    (:multisig "multisig")
    (:nulldata "nulldata")
    (:pubkey "pubkey")
    (otherwise "nonstandard")))

(defun script-type-name (script)
  "Core's scriptPubKey \"type\" name for SCRIPT: SCRIPT-TYPE-TO-STRING of its
classification."
  (script-type-to-string (classify-script script)))
