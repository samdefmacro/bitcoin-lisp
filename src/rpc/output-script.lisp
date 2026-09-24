(in-package #:bitcoin-lisp.rpc)

;;;; Output-script RPCs (Core rpc/output_script.cpp): createmultisig and
;;;; validateaddress.

;;; --- createmultisig (Bitcoin Core rpc/output_script.cpp) ---

(defconstant +max-script-element-size+ 520
  "Bitcoin Core script.h MAX_SCRIPT_ELEMENT_SIZE (legacy P2SH redeemScript cap).")

(defun %multisig-push-int (out v)
  "Append V to OUT the way Bitcoin Core's CScript::operator<<(int64_t) encodes a
small count: OP_0 for 0, OP_1..OP_16 for 1..16, else a minimal data push of the
CScriptNum bytes (single byte for the 17..20 range createmultisig allows)."
  (cond ((zerop v) (vector-push-extend #x00 out))
        ((<= 1 v 16) (vector-push-extend (+ #x50 v) out))
        (t (vector-push-extend 1 out) (vector-push-extend v out))))

(defun %multisig-redeem-script (m pubkeys)
  "Bitcoin Core GetScriptForMultisig: OP_m <pubkey>... OP_n OP_CHECKMULTISIG.
Pubkeys are appended in the given order (Core does not sort them)."
  (let ((out (make-array 0 :element-type '(unsigned-byte 8)
                           :adjustable t :fill-pointer 0)))
    (%multisig-push-int out m)
    (dolist (pk pubkeys)
      (vector-push-extend (length pk) out) ; 33/65 < OP_PUSHDATA1, one length byte
      (loop for b across pk do (vector-push-extend b out)))
    (%multisig-push-int out (length pubkeys))
    (vector-push-extend #xae out)          ; OP_CHECKMULTISIG
    (coerce out '(vector (unsigned-byte 8)))))

(defun hex-to-pubkey (hex)
  "Core HexToPubKey (rpc/util.cpp:219-232): the bytes of a hex-encoded 33- or
65-byte public key that is a real point.

Core refuses in THREE steps and each one names the string it was handed --
not hex, then the wrong length, then not cryptographically valid -- and every
caller reports those words: createmultisig (rpc/output_script.cpp:130) and
fundrawtransaction's solving_data pubkeys (wallet/rpc/spend.cpp:600) are both
this function. We answered one sentence, `Invalid public key: <hex>', for all
three, so a caller could not tell a typo from a key off the curve;
wallet_fundrawtransaction.py:1054-1055 reads the first two.

Core's IsHex refuses the empty string and any odd length
(util/strencodings.cpp), so an empty string is not hex here either."
  (unless (and (stringp hex) (plusp (length hex)) (evenp (length hex))
               (every (lambda (ch) (digit-char-p ch 16)) hex))
    (error 'rpc-error :code +rpc-invalid-address-or-key+
                      :message (format nil "Pubkey \"~A\" must be a hex string" hex)))
  (unless (or (= (length hex) 66) (= (length hex) 130))
    (error 'rpc-error :code +rpc-invalid-address-or-key+
                      :message (format nil "Pubkey \"~A\" must have a length of either 33 or 65 bytes"
                                       hex)))
  (let ((bytes (bl.crypto:hex-to-bytes hex)))
    (unless (bl.crypto:public-key-valid-p bytes)
      (error 'rpc-error :code +rpc-invalid-address-or-key+
                        :message (format nil "Pubkey \"~A\" must be cryptographically valid."
                                         hex)))
    bytes))

(define-rpc "createmultisig" (node (nrequired (keys :array) (address-type :or "legacy")))
  "Create an m-of-n multisig address (Bitcoin Core createmultisig). PARAMS:
(nrequired [\"pubkeyhex\",...] [address_type]). address_type is \"legacy\" (P2SH,
default), \"p2sh-segwit\" (P2SH-P2WSH), or \"bech32\" (P2WSH). Returns
{address, redeemScript, descriptor [, warnings]}. The redeemScript is always the
bare multisig script regardless of address type. Uncompressed keys force legacy
(with a warning if another type was requested), matching Core."
  (let ((network (rpc-get-network node)))
    (unless (integerp nrequired)
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "nrequired must be an integer"))
    (unless (listp keys)
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "keys must be an array"))
    ;; Parse + validate keys first (Core order: HexToPubKey before type/size checks).
    (let* ((pubkeys (mapcar (lambda (k)
                              (unless (stringp k)
                                (error 'rpc-error :code +rpc-invalid-address-or-key+
                                                  :message "Invalid public key"))
                              (hex-to-pubkey k))
                            keys))
           (requested (cond ((string= address-type "legacy") :legacy)
                            ((string= address-type "p2sh-segwit") :p2sh-segwit)
                            ((string= address-type "bech32") :bech32)
                            ((string= address-type "bech32m")
                             (error 'rpc-error :code +rpc-invalid-address-or-key+
                                               :message "createmultisig cannot create bech32m multisig addresses"))
                            (t (error 'rpc-error :code +rpc-invalid-address-or-key+
                                                 :message (format nil "Unknown address type '~A'" address-type))))))
      ;; AddAndGetMultisigDestination checks (rpc/util.cpp).
      (when (< nrequired 1)
        (error 'rpc-error :code +rpc-invalid-parameter+
                          :message "a multisignature address must require at least one key to redeem"))
      (when (< (length pubkeys) nrequired)
        (error 'rpc-error :code +rpc-invalid-parameter+
                          :message (format nil "not enough keys supplied (got ~D keys, but need at least ~D to redeem)"
                                           (length pubkeys) nrequired)))
      (when (> (length pubkeys) +max-pubkeys-per-multisig+)
        (error 'rpc-error :code +rpc-invalid-parameter+
                          :message (format nil "Number of keys involved in the multisignature address creation > ~D~%Reduce the number"
                                           +max-pubkeys-per-multisig+)))
      (let* ((redeem (%multisig-redeem-script nrequired pubkeys))
             ;; Any uncompressed key forces legacy output (Core).
             (forced-legacy (some (lambda (pk) (/= (length pk) 33)) pubkeys))
             (otype (if forced-legacy :legacy requested)))
        (when (and (eq otype :legacy) (> (length redeem) +max-script-element-size+))
          (error 'rpc-error :code +rpc-invalid-parameter+
                            :message (format nil "redeemScript exceeds size limit: ~D > ~D"
                                             (length redeem) +max-script-element-size+)))
        (let* ((hexkeys (mapcar #'bl.crypto:bytes-to-hex pubkeys))
               (multi (format nil "multi(~D~{,~A~})" nrequired hexkeys))
               (sha (bl.crypto:sha256 redeem))
               (address
                 (ecase otype
                   (:legacy (bl.crypto:encode-p2sh-address
                             (bl.crypto:hash160 redeem) network))
                   (:bech32 (bl.crypto:encode-p2wsh-address sha network))
                   (:p2sh-segwit
                    (bl.crypto:encode-p2sh-address
                     (bl.crypto:hash160
                      (concatenate '(vector (unsigned-byte 8)) #(#x00 #x20) sha))
                     network))))
               (body (ecase otype
                       (:legacy (format nil "sh(~A)" multi))
                       (:bech32 (format nil "wsh(~A)" multi))
                       (:p2sh-segwit (format nil "sh(wsh(~A))" multi))))
               (result `(("address" . ,address)
                         ("redeemScript" . ,(bl.crypto:bytes-to-hex redeem))
                         ("descriptor" . ,(descriptor-add-checksum body)))))
          ;; Core warns only when an explicitly-chosen type could not be produced.
          (if (and forced-legacy (not (eq requested :legacy)))
              (append result
                      `(("warnings" . ,(vector "Unable to make chosen address type, please ensure no uncompressed public keys are present."))))
              result))))))

(defun %validateaddress-invalid (address network)
  "The validateaddress result for an undecodable address (Core
output_script.cpp:77-82): isvalid=false plus error_locations and an error
string; none of address/scriptPubKey/isscript/iswitness appear.

Both come from DecodeDestination, which says WHY it refused and, when a
bech32 string's checksum fails, WHERE (key_io.cpp:84-207, bech32::LocateErrors
at bech32.cpp:403). We answered one sentence for every rejection and an empty
error_locations always, so a mistyped address learned only that it was wrong;
rpc_invalid_address_message.py compares fourteen different sentences and the
positions that come with four of them."
  (multiple-value-bind (message locations)
      (bl.crypto:decode-address-error address network)
    `(("isvalid" . ,+json-false+)
      ("error_locations" . ,(coerce locations 'vector))
      ("error" . ,message))))

(defun describe-address-fields (type wit-ver wit-prog)
  "Core DescribeAddress (rpc/util.cpp:270-345): the isscript / iswitness /
witness_version / witness_program fields of a decoded destination, TYPE and
the witness version and program as DECODE-ADDRESS returns them. Shared by
validateaddress and the wallet's getaddressinfo, which Core both build from
this one visitor.

A taproot output is a SCRIPT in Core's vocabulary (isscript true), as is a
pay-to-anchor -- witness v1 with the two-byte program 4e73 (CScript::
IsPayToAnchor) -- which carries no witness_version or witness_program at all;
an unknown witness version has no isscript field."
  (flet ((witness (version)
           `(("witness_version" . ,version)
             ("witness_program" . ,(bl.crypto:bytes-to-hex wit-prog)))))
    (cond
      ((eq type :p2pkh) `(("isscript" . ,+json-false+) ("iswitness" . ,+json-false+)))
      ((eq type :p2sh) `(("isscript" . t) ("iswitness" . ,+json-false+)))
      ((eq type :p2wpkh) `(("isscript" . ,+json-false+) ("iswitness" . t) ,@(witness 0)))
      ((eq type :p2wsh) `(("isscript" . t) ("iswitness" . t) ,@(witness 0)))
      ((eq type :p2tr) `(("isscript" . t) ("iswitness" . t) ,@(witness 1)))
      ((and (eql wit-ver 1) (equalp wit-prog #(#x4e #x73)))
       `(("isscript" . t) ("iswitness" . t)))
      (wit-ver `(("iswitness" . t) ,@(witness wit-ver)))
      (t '()))))

;; The description opens with Core's own sentence for this method
;; (validateaddress's RPCHelpMan, rpc/output_script.cpp): a docstring here IS
;; the help document a client reads, and IS what a call with the wrong number
;; of arguments is answered with, so the wording is part of the interface.
;; rpc_invalid_address_message.py:103 calls validateaddress with no arguments
;; and looks for exactly that sentence in the -1 it gets back.
(define-rpc "validateaddress" (node (address))
  "Return information about the given bitcoin address.
Booleans are real JSON booleans; the invalid shape carries error/
error_locations like Core's."
  (let ((network (rpc-get-network node)))
    (unless (and (stringp address) (> (length address) 0))
      (return-from rpc-validateaddress
        (%validateaddress-invalid (if (stringp address) address "") network)))
    (multiple-value-bind (type script-pubkey wit-ver wit-prog)
        (bl.crypto:decode-address address network)
      (if type
          `(("isvalid" . t)
            ("address" . ,address)
            ("scriptPubKey" . ,(bl.crypto:bytes-to-hex script-pubkey))
            ,@(describe-address-fields type wit-ver wit-prog))
          (%validateaddress-invalid address network)))))

