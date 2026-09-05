(in-package #:bitcoin-lisp.rpc)

;;;; Message signing RPCs (Core rpc/signmessage.cpp); the wallet's signmessage is
;;;; src/wallet/signmessage.lisp.

;;; --- Message signing (non-wallet): signmessagewithprivkey / verifymessage ---

(defun %bitcoin-message-hash (message)
  "Double-SHA256 of the Bitcoin Signed Message preimage:
compact-size(24) || \"Bitcoin Signed Message:\\n\" || compact-size(len) || message."
  ;; Magic = "Bitcoin Signed Message:" (23 ASCII bytes) followed by a single
  ;; newline (0x0A) — 24 bytes total, so its compact-size prefix is 0x18.
  (let* ((magic (concatenate '(vector (unsigned-byte 8))
                             (flexi-streams:string-to-octets "Bitcoin Signed Message:"
                                                             :external-format :ascii)
                             (vector 10)))
         (msg (flexi-streams:string-to-octets message :external-format :utf-8))
         (buf (flexi-streams:with-output-to-sequence (s)
                (bl.ser:write-compact-size s (length magic))
                (write-sequence magic s)
                (bl.ser:write-compact-size s (length msg))
                (write-sequence msg s))))
    (bl.crypto:hash256 buf)))

(define-rpc "signmessagewithprivkey" (node params)
  "Sign MESSAGE with the WIF private key (Bitcoin Core signmessagewithprivkey).
PARAMS: (privkey-wif message). Returns the base64 recoverable signature."
  (declare (ignore node))
  (let ((wif (first params))
        (message (second params)))
    (unless (and (stringp wif) (stringp message))
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "privkey (WIF) and message are required"))
    (multiple-value-bind (privkey compressed) (bl.crypto:wif-to-private-key wif)
      (unless privkey
        ;; Core: RPC_INVALID_ADDRESS_OR_KEY (-5), rpc/signmessage.cpp.
        (error 'rpc-error :code +rpc-invalid-address-or-key+
                          :message "Invalid private key"))
      (let ((hash (%bitcoin-message-hash message)))
        (multiple-value-bind (compact recid)
            (bl.crypto:sign-recoverable-compact privkey hash)
          (let ((sig65 (concatenate '(vector (unsigned-byte 8))
                                    (vector (+ 27 recid (if compressed 4 0)))
                                    compact)))
            (cl-base64:usb8-array-to-base64-string sig65)))))))

(define-rpc "verifymessage" (node (address sig-b64 message))
  "Verify a Bitcoin signed message (Bitcoin Core verifymessage). PARAMS:
(address signature-base64 message). Recovers the signing pubkey and checks
its P2PKH key-id matches ADDRESS. Returns a bare JSON boolean; like Core
(rpc/signmessage.cpp:41-57 mapping MessageVerify results), an undecodable
address throws -5 \"Invalid address\", a non-P2PKH address -3 \"Address does
not refer to key\", and malformed base64 -5 \"Malformed base64 encoding\"."
  (unless (and (stringp address) (stringp sig-b64) (stringp message))
    (error 'rpc-error :code +rpc-invalid-parameter+
                      :message "address, signature and message are required"))
  ;; MessageVerify ERR_INVALID_ADDRESS / ERR_ADDRESS_NO_KEY: the address
  ;; must decode, and must be base58 P2PKH (only key-hash addresses can be
  ;; message-verified). base58check-decode's payload is the 20-byte key-id.
  (multiple-value-bind (ver payload)
      (handler-case (bl.crypto:base58check-decode address 21)
        (error () (values nil nil)))
    (declare (ignore ver))
    (unless (and payload (= (length payload) 20))
      (if (nth-value 0 (ignore-errors
                        (bl.crypto:decode-address
                         address (rpc-get-network node))))
          (error 'rpc-error :code +rpc-type-error+
                            :message "Address does not refer to key")
          (error 'rpc-error :code +rpc-invalid-address-or-key+
                            :message "Invalid address")))
    (let ((sig65 (handler-case (cl-base64:base64-string-to-usb8-array sig-b64)
                   (error ()
                     (error 'rpc-error :code +rpc-invalid-address-or-key+
                                       :message "Malformed base64 encoding")))))
      (json-bool
       (ignore-errors
        (and (= (length sig65) 65)
             (let ((header (aref sig65 0)))
               (and (<= 27 header 34)
                    (let* ((recid (logand (- header 27) 3))
                           (compressed (>= (- header 27) 4))
                           (compact (subseq sig65 1 65))
                           (hash (%bitcoin-message-hash message))
                           (pubkey (bl.crypto:recover-public-key
                                    compact recid hash :compressed compressed)))
                      (and pubkey
                           (equalp payload
                                   (bl.crypto:hash160 pubkey))))))))))))
