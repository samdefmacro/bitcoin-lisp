(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/message.cpp at the pin: MessageSign then MessageVerify
;;;; round-trip under any key and message, and MessageVerify over any address,
;;;; signature and message. Ours are the signmessagewithprivkey and
;;;; verifymessage RPCs (Core maps MessageVerify's results onto RPC errors,
;;;; rpc/signmessage.cpp:41-57).
;;;;
;;;; Beyond the round trip: the signature's header byte carries the recovery
;;;; id and the compression flag in its low three bits and nothing else
;;;; (CPubKey::RecoverCompact, pubkey.cpp:300-304), so the same signature with
;;;; the header moved by a multiple of 8 verifies too; a signature whose
;;;; base64 Core's DecodeBase64 refuses (util/strencodings.cpp:109-142) is
;;;; the -3 malformed-signature error whatever else is true of it; and any
;;;; address, signature and message are answered true, false or one of
;;;; Core's three errors.

(def-suite :fuzz-message-tests :in :bitcoin-lisp-tests
  :description "Core fuzz message.cpp over signmessagewithprivkey / verifymessage")

(in-suite :fuzz-message-tests)

(defun %verify-message (node address signature message)
  ":TRUE, :FALSE, or (CODE . MESSAGE) of the RPC error verifymessage answers."
  (handler-case (let ((r (bl.rpc:dispatch-rpc-method node "verifymessage" (list address signature message))))
                  (if (eq r t) :true :false))
    (bl.rpc:rpc-error (e) (cons (bl.rpc:rpc-error-code e) (bl.rpc:rpc-error-message e)))))

(define-fuzz-target message
    (buffer :core "message.cpp:23-50" :iterations 1500 :max-len 300)
  "A message signed with a key verifies against the key's P2PKH address, with
its header byte moved by any multiple of 8 too; a signature Core cannot
base64-decode is -3 `Malformed base64 encoding'; any other address,
signature and message are answered true, false or Core's errors."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (node (make-test-node))
         (message (consume-random-length-string fdp 1024))
         (key (%consume-private-key fdp)))
    (when key
      (let* ((signature (bl.rpc:dispatch-rpc-method
                         node "signmessagewithprivkey"
                         (list (bl.crypto:private-key-to-wif key :network :testnet3) message)))
             (address (bl.crypto:encode-p2pkh-address
                       (bl.crypto:hash160 (bl.crypto:derive-public-key key)) :testnet3))
             (bytes (bl.ser:decode-base64 signature)))
        (fuzz-assert (eq (fuzz-sabotage (%verify-message node address signature message)) :true)
                     "a message signed with a key does not verify")
        (setf (aref bytes 0) (ldb (byte 8 0) (+ (aref bytes 0) (* 8 (consume-integral-in-range fdp 1 31)))))
        (fuzz-assert (eq (%verify-message node address (bl.ser:encode-base64 bytes) message) :true)
                     "header byte ~D: Core recovers the key from its low three bits" (aref bytes 0))
        ;; The same signature with non-zero bits after its last byte: base64
        ;; Core's DecodeBase64 refuses (ConvertBits<6, 8, false>).
        (let* ((alphabet "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
               (last (position (char signature (- (length signature) 2)) alphabet))
               (loose (concatenate 'string (subseq signature 0 (- (length signature) 2))
                                   (string (char alphabet (logior (logandc2 last 3)
                                                                  (consume-integral-in-range fdp 1 3))))
                                   "=")))
          (fuzz-assert (equal (%verify-message node address loose message)
                              '(-3 . "Malformed base64 encoding"))
                       "~S is not base64 to Core" loose))))
    (let ((address (consume-random-length-string fdp 64))
          (signature (consume-random-length-string fdp 100)))
      (let ((outcome (%verify-message node address signature message)))
        (fuzz-assert (or (member outcome '(:true :false))
                         (member outcome '((-5 . "Invalid address") (-3 . "Address does not refer to key")
                                           (-3 . "Malformed base64 encoding"))
                                 :test #'equal))
                     "verifymessage answered ~S" outcome)))))
