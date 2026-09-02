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

(defun parse-multisig-pubkey (hex)
  "Parse a hex-encoded 33/65-byte public key for createmultisig, validating it is
a real point (Bitcoin Core HexToPubKey). Returns the key bytes; signals
rpc-error otherwise."
  (let ((bytes (handler-case (bl.crypto:hex-to-bytes hex)
                 (error () nil))))
    (unless (and bytes (member (length bytes) '(33 65))
                 (bl.crypto:public-key-valid-p bytes))
      (error 'rpc-error :code +rpc-invalid-address-or-key+
                        :message (format nil "Invalid public key: ~A" hex)))
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
                              (parse-multisig-pubkey k))
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

(defun %validateaddress-invalid ()
  "The validateaddress result for an undecodable address (Core
output_script.cpp:77-82): isvalid=false plus error_locations and an error
string; none of address/scriptPubKey/isscript/iswitness appear."
  `(("isvalid" . ,+json-false+)
    ("error_locations" . #())
    ("error" . "Invalid or unsupported Segwit (Bech32) or Base58 encoding.")))

(define-rpc "validateaddress" (node (address))
  "Validate a Bitcoin address and return metadata (Core validateaddress).
Booleans are real JSON booleans; the invalid shape carries error/
error_locations like Core's."
  (let ((network (rpc-get-network node)))
    (unless (and (stringp address) (> (length address) 0))
      (return-from rpc-validateaddress (%validateaddress-invalid)))
    (multiple-value-bind (type script-pubkey wit-ver wit-prog)
        (bl.crypto:decode-address address network)
      (if type
          (let ((result `(("isvalid" . t)
                          ("address" . ,address)
                          ("scriptPubKey" . ,(bl.crypto:bytes-to-hex script-pubkey))
                          ("isscript" . ,(json-bool
                                          (member type '(:p2sh :p2wsh :witness-v0-scripthash))))
                          ("iswitness" . ,(json-bool wit-ver)))))
            (when wit-ver
              (setf result (append result
                                   `(("witness_version" . ,wit-ver)
                                     ("witness_program" . ,(bl.crypto:bytes-to-hex wit-prog))))))
            result)
          (%validateaddress-invalid)))))

