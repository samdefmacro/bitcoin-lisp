(in-package #:bitcoin-lisp.rpc)

;;;; Core core_io.cpp: the RPC layer's serializers and deserializers.
;;;; ScriptToUniv builds the scriptPubKey object every RPC and REST surface
;;;; emits; DecodeHexTx / DecodeTx read the transaction hex every RPC that
;;;; takes one is handed. ScriptToAsmStr is BL.VAL:DISASSEMBLE-SCRIPT, next
;;;; to the interpreter whose opcode table and CScriptNum decode it shares.

(defun %infer-pubkey-hex (key)
  "Core InferPubkey (descriptor.cpp:2145-2161) with no signing provider, as
the hex a pk() or multi() argument carries: NIL for a key it refuses.

The refusal that matters here is IsValidNonHybrid -- header 06/07 is a valid
SIZE, so the solver reports such a script as PUBKEY, but a hybrid key has no
descriptor and Core falls through to raw(). The uncompressed-key rule below
it applies to P2WSH and tapscript, which this function never sees: with no
provider Core cannot reach a witness script at all."
  (and (plusp (length key))
       (member (aref key 0) '(#x02 #x03 #x04))
       (bl.crypto:bytes-to-hex key)))

(defun %infer-script-desc (script network ctx witness-scripts)
  "Core InferScript (descriptor.cpp:2691-2831) at parse context CTX, as the
descriptor BODY without its checksum -- or NIL when nothing can be inferred,
which is Core's nullptr and makes an enclosing wsh() fall back.

CTX is Core's ParseScriptContext: :TOP for the output itself, :P2WSH for the
script under a witness program. Which arms apply is per-context in Core and
the order is Core's own -- the TYPED inferences come first, and only at :TOP
does it end at ExtractDestination's addr() and then raw().

WITNESS-SCRIPTS stands in for Core's SigningProvider: a hash table from a
P2WSH program (the 32-byte SHA256 of the script) to that script. Core keys
its keystore by CScriptID and hashes the program again to reach it
(RIPEMD160(data[0]), :2756); keying on the program is the same lookup with
one hash fewer. NIL is the no-provider case, where Core reaches neither the
wsh() arm nor pkh()/wpkh() and lands on addr() exactly as this does."
  (multiple-value-bind (type data) (bl.val:classify-script script)
    (or
     ;; PUBKEY, at TOP / P2SH / P2WSH (descriptor.cpp:2706-2711).
     (when (eq type :pubkey)
       (let ((hex (%infer-pubkey-hex (getf data :pubkey))))
         (and hex (format nil "pk(~A)" hex))))
     ;; MULTISIG, at the same three (:2732-2745). Never sortedmulti(): that
     ;; descriptor REORDERS the keys it is given, and a script has already
     ;; fixed their order.
     (when (eq type :multisig)
       (let ((hexes (mapcar #'%infer-pubkey-hex (getf data :pubkeys))))
         (when (every #'identity hexes)
           (format nil "multi(~D~{,~A~})" (getf data :m) hexes))))
     ;; WITNESS_V0_SCRIPTHASH, at TOP or P2SH, and only when the provider
     ;; holds the script under the program (:2755-2762). The sub is inferred
     ;; in P2WSH context, and a sub that infers to nothing drops the whole
     ;; wsh() -- Core returns nullptr from the inner call and falls through.
     (when (and (eq type :witness-v0-scripthash) witness-scripts)
       (let ((sub (gethash (getf data :witness-program) witness-scripts)))
         (when sub
           (let ((body (%infer-script-desc sub network :p2wsh witness-scripts)))
             (and body (format nil "wsh(~A)" body))))))
     ;; WITNESS_V1_TAPROOT, TOP only (:2763-2803). Core builds RawTRDescriptor
     ;; only for a FULLY VALID x-only key (a point on the curve), so a v1
     ;; program that is not one keeps falling through to its address.
     (when (and (eq ctx :top) (eq type :witness-v1-taproot))
       (let ((program (getf data :witness-program)))
         (when (bl.crypto:xonly-pubkey-valid-p program)
           (format nil "rawtr(~A)" (bl.crypto:bytes-to-hex program)))))
     ;; Miniscript, in the P2WSH and tapscript contexts only (:2805-2818),
     ;; and only for a SANE node -- Core's `node && node->IsSane()'. This is
     ;; the arm that makes decodescript answer
     ;; wsh(and_v(and_v(v:hash160(..),v:pk(..)),older(1))) for an offered
     ;; HTLC instead of the addr() of its witness program
     ;; (rpc_decodescript.py:281).
     (when (eq ctx :p2wsh)
       (let ((node (bl.val:ms-from-script script :ctx :p2wsh)))
         (when (and node (bl.val:ms-node-sane-p node))
           (bl.val:ms-node-to-string node))))
     ;; Everything below is TOP-only: at any other context Core returns
     ;; nullptr rather than naming an address for a script that is not an
     ;; output (:2820-2822).
     (when (eq ctx :top)
       (or (let ((addr (script->address script network)))
             (and addr (format nil "addr(~A)" addr)))
           (format nil "raw(~A)" (bl.crypto:bytes-to-hex script)))))))

(defun scriptpubkey-desc (script network &key witness-scripts)
  "Core InferDescriptor (core_io.cpp:414, descriptor.cpp:2897-2900) with the
appended checksum: the `desc` field on every decoded output (gettxout,
decoderawtransaction, getblock verbosity 2/3, decodescript, /rest/getutxos).

WITNESS-SCRIPTS is the signing provider Core threads through -- see
%INFER-SCRIPT-DESC. Without one the provider-dependent arms (pkh, wpkh, sh,
wsh and a tr() tree) cannot fire and Core lands on addr() too."
  (descriptor-add-checksum
   (%infer-script-desc script network :top witness-scripts)))

(defun script-to-json (script &key (include-hex t) network witness-scripts)
  "Core ScriptToUniv (core_io.cpp:409-428): one script as the object every
scriptPubKey field in the RPC and REST surfaces carries, in Core's key order
-- asm, desc, hex, address, type.

NETWORK is Core's include_address: with it the object also carries the
inferred descriptor and, when the script has a well-defined destination, the
address. INCLUDE-HEX is Core's include_hex, whose default is likewise true;
decodescript is the one caller that passes false, because the caller supplied
the hex.

WITNESS-SCRIPTS is Core's `provider' argument (core_io.cpp:409): the scripts
a caller can name for a witness program it just built. decodescript is the
one caller with any -- it puts the script it was handed under the P2WSH
program it derived from it, exactly as Core does
(rpc/rawtransaction.cpp:571) -- so every other surface still infers with no
provider and lands where Core lands without one, on addr()."
  (let ((type (bl.val:classify-script script))
        (addr (and network (script->address script network))))
    `(("asm" . ,(bl.val:disassemble-script script))
      ,@(when network
          `(("desc" . ,(scriptpubkey-desc script network
                                          :witness-scripts witness-scripts))))
      ,@(when include-hex `(("hex" . ,(bl.crypto:bytes-to-hex script))))
      ,@(when addr `(("address" . ,addr)))
      ("type" . ,(bl.val:script-type-to-string type)))))

(defun %tx-scripts-sane-p (tx)
  "Core CheckTxScriptsSanity (core_io.cpp:135-153): every input and output
script parses and is within MAX_SCRIPT_SIZE. DECODE-TX's tie-break, and
nothing else -- it is not a validity rule."
  (and (or (bl.val:is-coinbase-tx tx)
           (every (lambda (in)
                    (let ((script (bl.ser:tx-in-script-sig in)))
                      (and (bl.store:script-has-valid-ops-p script)
                           (<= (length script) bl.store:+max-script-size+))))
                  (bl.ser:transaction-inputs tx)))
       (every (lambda (out)
                (let ((script (bl.ser:tx-out-script-pubkey out)))
                  (and (bl.store:script-has-valid-ops-p script)
                       (<= (length script) bl.store:+max-script-size+))))
              (bl.ser:transaction-outputs tx))))

(defun %decode-tx-fully (bytes allow-witness)
  "BYTES read as a transaction under ALLOW-WITNESS, but only when the reader
consumed every byte (Core's `if (ssData.empty()) ok = true'); else NIL."
  (handler-case
      (let ((br (bl.ser:make-byte-reader-from bytes)))
        (let ((tx (bl.ser:br-read-transaction br :allow-witness allow-witness)))
          (when (bl.ser:br-eof-p br) tx)))
    (error () nil)))

(defun decode-tx (bytes &key (try-no-witness t) (try-witness t))
  "Core DecodeTx (core_io.cpp:156-223): the transaction BYTES encode, or NIL.

BYTES is decoded TWICE -- once with the extended (witness) serialization and
once with the legacy one, restricted by TRY-WITNESS and TRY-NO-WITNESS, which
are what decoderawtransaction's `iswitness' argument sets. A decoding counts
only when it consumes the WHOLE input, which is why a valid transaction hex
with trailing bytes is a failure here and not a transaction whose txid belongs
to a prefix of what the caller sent. When both consume it, the one passing
CheckTxScriptsSanity wins, extended on a tie.

The two readings are genuinely different transactions, not two spellings of
one: `02000000 00 01 0000000000000000 066a0400010203 00000000' is a superfluous
witness record under the extended reading and 0 inputs / 1 output under the
legacy one."
  (let (extended legacy)
    (when try-witness
      (setf extended (%decode-tx-fully bytes t)))
    ;; Core's optimization: an extended decode that passes the sanity check
    ;; ends it, so the legacy decode is not even attempted.
    (when (and extended (%tx-scripts-sane-p extended))
      (return-from decode-tx extended))
    (when try-no-witness
      (setf legacy (%decode-tx-fully bytes nil)))
    (cond ((and legacy (%tx-scripts-sane-p legacy)) legacy)
          (extended extended)
          (legacy legacy))))

(defun decode-hex-tx (hex &key (try-no-witness t) (try-witness t))
  "Core DecodeHexTx (core_io.cpp:225-233): the transaction the hex string HEX
encodes, or NIL when HEX is not hex or no serialization consumes all of it."
  (let ((bytes (handler-case (bl.crypto:hex-to-bytes hex) (error () nil))))
    (and bytes (decode-tx bytes :try-no-witness try-no-witness
                                :try-witness try-witness))))

(defun decode-hex-tx-or-error (hex message &key (try-no-witness t) (try-witness t))
  "DECODE-HEX-TX, or Core's RPC_DESERIALIZATION_ERROR (-22) carrying MESSAGE.

MESSAGE is per call site because Core's is: decoderawtransaction,
converttopsbt and fundrawtransaction say \"TX decode failed\", the paths that
go on to SPEND the transaction add \"Make sure the tx has at least one
input.\", and simulaterawtransaction says something else again."
  (or (and (stringp hex)
           (decode-hex-tx hex :try-no-witness try-no-witness
                              :try-witness try-witness))
      (error 'rpc-error :code +rpc-deserialization-error+ :message message)))

(defun iswitness-flags (value)
  "The `iswitness' argument as Core's (try_no_witness, try_witness) pair
(rpc/rawtransaction.cpp:435-436): absent means try BOTH serializations, true
means witness only, false means legacy only."
  (if (null value)
      (values t t)
      (let ((witness (positional-bool value)))
        (values (not witness) witness))))
