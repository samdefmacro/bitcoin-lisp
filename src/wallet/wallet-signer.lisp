(in-package #:bitcoin-lisp.wallet)

;;;; The wallet side of -signer: Core ExternalSignerScriptPubKeyMan
;;;; (wallet/external_signer_scriptpubkeyman.cpp), the external-signer arm of
;;;; CWallet::SetupDescriptorScriptPubKeyMans (wallet.cpp:3620-3667), of
;;;; CWallet::DisplayAddress (wallet.cpp:2715-2729) and of FillPSBT(sign=true),
;;;; which FinishTransaction (wallet/rpc/spend.cpp:96-140) and
;;;; feebumper::SignTransaction (feebumper.cpp:329-347) sign through.

(defun wallet-setup-external-signer-spkms (wallet)
  "Core SetupDescriptorScriptPubKeyMans' external-signer branch: ask the ONE
connected signer for account 0's descriptors and make each an active,
topped-up SPKM for its output type -- `receive' external, `internal' change.
Signals EXTERNAL-SIGNER-ERROR with Core's text for a missing or ambiguous
signer, a malformed answer, or a descriptor that does not parse."
  (let* ((network (wallet-network wallet))
         (signer (get-external-signer network))
         (result (signer-get-descriptors signer 0))
         (now (bl.ser:get-unix-time)))
    (unless (and (consp result) (every #'consp result))
      (%signer-fail "SetupDescriptorScriptPubKeyMans: Unexpected result"))
    (bl.store:with-leveldb-writebatch (batch)
      (dolist (internal '(nil t))
        (let ((entries (%json-field result (if internal "internal" "receive"))))
          (unless (vectorp entries)
            (%signer-fail "SetupDescriptorScriptPubKeyMans: Unexpected result"))
          (loop for value across entries
                for desc-str = (if (stringp value) value (princ-to-string value))
                for desc = (handler-case (bl.rpc:parse-descriptor desc-str network)
                             (bl.rpc:rpc-error (e)
                               (%signer-fail "SetupDescriptorScriptPubKeyMans: Invalid descriptor \"~A\" (~A)"
                                             desc-str (bl.rpc:rpc-error-message e)))
                             (error (e)
                               (%signer-fail "SetupDescriptorScriptPubKeyMans: Invalid descriptor \"~A\" (~A)"
                                             desc-str e)))
                for type = (out-desc-output-type desc)
                ;; A descriptor with no output type (raw(), a bare multi())
                ;; is skipped, as Core `continue's.
                when type
                  do (let ((spkm (%make-spkm-from-descriptor desc now 0 0 0)))
                       (setf (gethash (desc-spkm-id spkm) (wallet-spkms wallet)) spkm)
                       (unless (spkm-top-up wallet spkm 0 batch)
                         (wallet-error "external signer setup: keypool top-up failed for ~A"
                                       desc-str))
                       (wallet-add-active-spkm wallet spkm type internal :batch batch)))))
      ;; SetupDescriptor ends with UnsetBlankWalletFlag.
      (when (wallet-flag-set-p wallet +wallet-flag-blank-wallet+)
        (setf (wallet-flags wallet)
              (logandc2 (wallet-flags wallet) +wallet-flag-blank-wallet+))
        (bl.store:leveldb-writebatch-put
         batch (wdb-key-simple +wdb-key-flags+) (wdb-uint64-value (wallet-flags wallet))))
      (bl.store:leveldb-write (wallet-db wallet) batch :sync t))
    (wallet-maybe-update-birth-time wallet now)))

;;; --- walletdisplayaddress (wallet/rpc/addresses.cpp:633-671) ---

(defun %wallet-display-address (wallet address script)
  "Core CWallet::DisplayAddress + ExternalSignerScriptPubKeyMan::DisplayAddress:
show the inferred descriptor of SCRIPT on the signer and insist that it echo
ADDRESS back. Returns NIL, or the error text for RPC_MISC_ERROR."
  (unless (and (wallet-flag-set-p wallet +wallet-flag-external-signer+)
               (%wallet-owning-spkm wallet script))
    (return-from %wallet-display-address
      "There is no ScriptPubKeyManager for this address"))
  (let* ((signer (get-external-signer (wallet-network wallet)))
         (descriptor (%wallet-inferred-descriptor wallet script))
         (result (signer-display-address signer (or descriptor "")))
         (error (%json-field result "error"))
         (echoed (%json-field result "address")))
    (cond ((stringp error) (format nil "Signer returned error: ~A" error))
          ((not (stringp echoed)) "Signer did not echo address")
          ((string/= echoed address)
           (format nil "Signer echoed unexpected address ~A" echoed)))))

(bl.rpc:define-rpc "walletdisplayaddress" (node params)
  "Display an address on the wallet's external signer for verification (Core
walletdisplayaddress). PARAMS: (address). Returns {address}."
  (let* ((wallet (wallet-for-request node))
         (address (first params))
         (script (and (stringp address)
                      (nth-value 1 (bl.crypto:decode-address address (wallet-network wallet))))))
    (unless script
      (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-address-or-key+
                               :message "Invalid address"))
    (let ((failure (with-wallet-lock (wallet)
                     (handler-case (%wallet-display-address wallet address script)
                       (external-signer-error (e) (external-signer-error-message e))))))
      (when failure
        (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-misc-error+ :message failure))
      `(("address" . ,address)))))

;;; --- Signing through the signer ---

(defun %psbt-input-fingerprints (map)
  "Every master-key fingerprint an input's BIP32 records name: the first four
bytes of a PSBT_IN_BIP32_DERIVATION value, and the four after the leaf-hash
list of a PSBT_IN_TAP_BIP32_DERIVATION value."
  (append
   (loop for (nil . value) in (bl.ser:psbt-map-collect map bl.ser:+psbt-in-bip32+)
         when (>= (length value) 4) collect (subseq value 0 4))
   (loop for (nil . value) in (bl.ser:psbt-map-collect map bl.ser:+psbt-in-tap-bip32+)
         for start = (%after-leaf-hashes value)
         when (and start (<= (+ start 4) (length value)))
           collect (subseq value start (+ start 4)))))

(defun %after-leaf-hashes (value)
  "The offset just past a tap-BIP32 value's compact-size count and its 32-byte
leaf hashes, where the key origin begins; NIL for a value too short to say."
  (when (plusp (length value))
    (let* ((b0 (aref value 0))
           (width (cond ((< b0 253) 0) ((= b0 253) 2) ((= b0 254) 4) (t 8))))
      (when (> (length value) width)
        (let ((n (if (zerop width)
                     b0
                     (loop for i from 1 to width
                           sum (ash (aref value i) (* 8 (1- i)))))))
          (+ 1 width (* 32 n)))))))

(defun %signer-sign-psbt (signer psbt)
  "Core ExternalSigner::SignTransaction (external_signer.cpp:77-127): the
signer's PSBT, or (values NIL reason)."
  (let ((fingerprint (bl.crypto:hex-to-bytes (external-signer-fingerprint signer)))
        (encoded (bl.ser:encode-psbt psbt)))
    (unless (some (lambda (map)
                    (member fingerprint (%psbt-input-fingerprints map) :test #'equalp))
                  (bl.ser:psbt-inputs psbt))
      (return-from %signer-sign-psbt
        (values nil (format nil "Signer fingerprint ~A does not match any of the inputs:~%~A"
                            (external-signer-fingerprint signer) encoded))))
    (let* ((result (run-command-parse-json
                    (append (external-signer-command signer)
                            (list "--stdin" "--fingerprint" (external-signer-fingerprint signer)
                                  "--chain" (external-signer-chain signer)))
                    (format nil "signtx ~A" encoded)))
           (error (%json-field result "error"))
           (signed (%json-field result "psbt")))
      (cond ((stringp error) (values nil error))
            ((not (stringp signed)) (values nil "Unexpected result from signer"))
            (t (handler-case (bl.ser:decode-psbt signed)
                 (error (e) (values nil (format nil "TX decode failed ~A" e)))))))))

(defun %external-signer-fill-psbt (node wallet tx)
  "FinishTransaction's two FillPSBT calls for an external-signer wallet: the
unsigned PSBT with UTXOs and BIP32 derivations, then the signer's signature
and FinalizePSBT. Returns (values psbt complete); signals Core's
JSONRPCPSBTError -- RPC_TRANSACTION_ERROR \"External signer not found\" or
\"External signer failed to sign\" -- when the signer cannot be reached or
refuses."
  (let ((psbt (bl.ser:decode-psbt (%wallet-unsigned-psbt node wallet tx t))))
    ;; Already complete if every input is signed: nothing to ask the device.
    (unless (every #'%psbt-input-signed-p (bl.ser:psbt-inputs psbt))
      (let ((signer (handler-case (get-external-signer (wallet-network wallet))
                      (external-signer-error (e)
                        (bl:log-warn "~A" (external-signer-error-message e))
                        (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-verify-error+
                                                 :message "External signer not found")))))
        (multiple-value-bind (signed reason)
            (handler-case (%signer-sign-psbt signer psbt)
              (external-signer-error (e) (values nil (external-signer-error-message e))))
          (unless signed
            (bl:log-warn "Failed to sign: ~A" reason)
            (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-verify-error+
                                     :message "External signer failed to sign"))
          (setf psbt signed))))
    (values psbt (%psbt-finalize-in-place psbt))))
