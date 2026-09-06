(in-package #:bitcoin-lisp.wallet)

;;;; signmessage with a wallet key (Core wallet/rpc/signmessage.cpp).

;;; --- Message signing (wallet): signmessage ---

(defun %wallet-signmessage-wif (wallet script keyid)
  "The WIF of the private key WALLET holds for the P2PKH KEYID owning SCRIPT,
or NIL. Resolves the key exactly like the spend path (wallet-spend.lisp
%wallet-sign-maps): the owning SPKM's expansion at range position POS gives
the (desc-key . derived-pubkey) pairs, %desc-key-priv-at derives each private
key, and the one whose derived pubkey hashes to KEYID is the signer. Caller
holds the wallet lock."
  (multiple-value-bind (spkm pos) (%wallet-owning-spkm wallet script)
    (when (and spkm (spkm-have-private-keys-p spkm))
      (multiple-value-bind (scripts pairs) (%spkm-expansion-pairs spkm pos)
        (declare (ignore scripts))
        (let ((provider (spkm-privkey-provider wallet spkm)))
          (loop for (key . pubkey) in pairs
                for priv = (%desc-key-priv-at key pos provider)
                when (and priv
                          (equalp keyid
                                  (bl.crypto:hash160
                                   (bl.crypto:derive-public-key
                                    priv :compressed (= (length pubkey) 33)))))
                  do (return
                       (bl.crypto:private-key-to-wif
                        priv :network (wallet-network wallet)
                             :compressed (= (length pubkey) 33)))))))))

(bl.rpc:define-rpc "signmessage" (node params)
  "Sign MESSAGE with the private key of a wallet address (Bitcoin Core wallet
signmessage). PARAMS: (address message). The address must be a legacy P2PKH
address the wallet owns; the private key is resolved from the owning
descriptor SPKM (the spend path) and the signing is delegated to
signmessagewithprivkey. Error codes mirror Core (wallet/rpc/signmessage.cpp):
an undecodable address -> -5 \"Invalid address\", a valid non-P2PKH address
-> -3 \"Address does not refer to key\", and an address whose key the wallet
does not hold -> -4 \"Private key not available\" (SigningResult
PRIVATE_KEY_NOT_AVAILABLE).

Core's ORDER, and not only its codes: the handler takes cs_wallet and calls
EnsureWalletIsUnlocked FIRST (signmessage.cpp:42-44), before it decodes the
address at all (:46-58). A locked wallet therefore answers -13 whatever the
address was, which is what lets a client branch on -13 to prompt for the
passphrase; checking the address first tells such a client its input is
wrong when Core would have told it the wallet is locked."
  (let ((wallet (wallet-for-request node))
        (address (first params))
        (message (second params)))
    (unless (and (stringp address) (stringp message))
      (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+
                        :message "address and message are required"))
    ;; One hold for the whole body, as Core's LOCK(cs_wallet) is: the unlock
    ;; demand, the address checks and the key resolution cannot be
    ;; interleaved with a relock.
    (let ((wif (with-wallet-lock (wallet)
                 (wallet-ensure-unlocked wallet)
                 (multiple-value-bind (type script wit-ver keyid)
                     (bl.crypto:decode-address address (wallet-network wallet))
                   (declare (ignore wit-ver))
                   ;; DecodeDestination / IsValidDestination.
                   (unless type
                     (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-address-or-key+
                                       :message "Invalid address"))
                   ;; std::get_if<PKHash>: only a P2PKH destination refers to a key.
                   (unless (eq type :p2pkh)
                     (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-type-error+
                                       :message "Address does not refer to key"))
                   ;; CWallet::SignMessage: locate the signing key.
                   (%wallet-signmessage-wif wallet script keyid)))))
      (unless wif
        ;; SigningResult::PRIVATE_KEY_NOT_AVAILABLE -> RPC_WALLET_ERROR.
        (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-wallet-error+
                          :message "Private key not available"))
      (bl.rpc:rpc-signmessagewithprivkey node (list wif message)))))
