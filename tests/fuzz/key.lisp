(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/key.cpp at the pin: key (:34-307), ellswift_roundtrip
;;;; (:309-325) and bip324_ecdh (:327-372) over our secp256k1 layer -- the
;;;; secret keys, WIF, BIP32 derivation, ECDSA and recoverable signatures,
;;;; the P2PK / multisig / P2PKH scripts a key goes into, ElligatorSwift and
;;;; the BIP324 ECDH.
;;;;
;;;; key: where Core checks private and public derivation separately, ours
;;;; also checks they agree (the public child of the parent's public key is
;;;; the private child's public key, with the same chain code). CKey's
;;;; container operations (size, begin/end, operator[]) and the
;;;; FillableSigningProvider have no counterpart; the DER private key Load of
;;;; the legacy wallet does not either (descriptor-only wallet).

(def-suite :fuzz-key-tests :in :bitcoin-lisp-tests
  :description "Core fuzz key.cpp")

(in-suite :fuzz-key-tests)

(defun %consume-private-key (fdp)
  "Core ConsumePrivateKey (test/fuzz/util.cpp:235-243): 32 bytes, zero-filled,
or NIL when they are not a secret key."
  (let ((k (%fuzz-key32 fdp)))
    (and (bl.crypto:valid-private-key-p k) k)))

(define-fuzz-target key
    (buffer :core "key.cpp:34-307" :corpus (lambda (fdp) (consume-bytes fdp 32))
            :iterations 1200 :max-len 40)
  "A buffer that is a secret key: its WIF round-trips compressed and
uncompressed; its BIP32 child is another key, derived privately and publicly
alike; its public key is valid, decompresses, and goes into a P2PK, a 1-of-1
multisig and a P2PKH address that classify and decode back; its ECDSA
signature verifies, is low-S, and fails truncated; its recoverable signature
recovers it."
  (unless (and (= (length buffer) 32) (bl.crypto:valid-private-key-p buffer))
    (fuzz-reject))
  (let* ((key (copy-seq buffer))
         (hash (bl.crypto:hash256 buffer))
         (pub (bl.crypto:derive-public-key key)))
    (multiple-value-bind (k compressed) (bl.crypto:wif-to-private-key (bl.crypto:private-key-to-wif key))
      (fuzz-assert (and (equalp (fuzz-sabotage k) key) compressed) "the compressed WIF does not round-trip"))
    (multiple-value-bind (k compressed)
        (bl.crypto:wif-to-private-key (bl.crypto:private-key-to-wif key :compressed nil))
      (fuzz-assert (and (equalp k key) (not compressed)) "the uncompressed WIF does not round-trip"))
    ;; Derive (key.cpp:93-100), and its public half (:247-257).
    (let* ((parent (bl.crypto:make-ext-key :version #x0488ade4 :chain-code hash
                                           :key (%concat-octets (list #(0) key)) :privatep t))
           (child (bl.crypto:bip32-derive-child parent 0))
           (public-child (bl.crypto:bip32-derive-child (bl.crypto:bip32-neuter parent) 0)))
      (fuzz-assert (and (not (equalp (subseq (bl.crypto:ext-key-key child) 1) key))
                        (not (equalp (bl.crypto:ext-key-chain-code child) hash)))
                   "the child is the parent")
      (fuzz-assert (and (equalp (bl.crypto:ext-key-public-bytes public-child)
                                (fuzz-sabotage (bl.crypto:ext-key-public-bytes child)))
                        (equalp (bl.crypto:ext-key-chain-code public-child) (bl.crypto:ext-key-chain-code child)))
                   "public and private derivation disagree"))
    ;; The public key (:102-134, :219-246).
    (fuzz-assert (and (= 33 (length pub)) (bl.crypto:public-key-valid-p pub)) "the public key is not valid")
    (let ((full (bl.crypto:decompress-public-key pub)))
      (fuzz-assert (equalp full (bl.crypto:derive-public-key key :compressed nil))
                   "the decompressed key is not the uncompressed one"))
    (let ((p2pk (%concat-octets (list #(33) pub #(#xac))))
          (multisig (%concat-octets (list #(#x51 33) pub #(#x51 #xae)))))
      (multiple-value-bind (type data) (bl.val:classify-script p2pk)
        (fuzz-assert (and (= 35 (length p2pk)) (eq type :pubkey) (equalp (getf data :pubkey) pub))
                     "P2PK classifies as ~S" type))
      (multiple-value-bind (type data) (bl.val:classify-script multisig)
        (fuzz-assert (and (= 37 (length multisig)) (eq type :multisig)
                          (equal (list (getf data :m) (getf data :n)) '(1 1))
                          (equalp (first (getf data :pubkeys)) pub))
                     "the 1-of-1 multisig classifies as ~S" type)))
    (let ((address (bl.crypto:encode-p2pkh-address (bl.crypto:hash160 pub) :mainnet)))
      (multiple-value-bind (type script) (bl.crypto:decode-address address :mainnet)
        (fuzz-assert (and (eq type :p2pkh) (= 25 (length script))
                          (eq (bl.val:classify-script script) :pubkeyhash))
                     "~A decodes as ~S" address type)))
    ;; Sign (:269-278) and SignCompact (:280-288).
    (let ((sig (bl.crypto:sign-ecdsa key hash)))
      (fuzz-assert (bl.crypto:verify-signature hash sig pub :strict t :low-s t)
                   "a signature does not verify")
      (fuzz-assert (not (bl.crypto:verify-signature hash (subseq sig 0 (1- (length sig))) pub :strict t))
                   "a truncated signature verifies"))
    (multiple-value-bind (compact recid) (bl.crypto:sign-recoverable-compact key hash)
      (fuzz-assert (equalp (bl.crypto:recover-public-key compact recid hash) pub)
                   "the recoverable signature recovers another key"))))

(define-fuzz-target ellswift-roundtrip
    (buffer :core "key.cpp:309-325" :iterations 1000 :max-len 120)
  "A key's ElligatorSwift encoding, under any entropy, decodes to the key's
public key, which verifies the key's signature."
  (unless (bl.crypto:ellswift-available-p)
    (return-from fuzz-target/ellswift-roundtrip))
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (key (or (%consume-private-key fdp) (fuzz-reject)))
         (decoded (bl.crypto:ellswift-decode (bl.crypto:ellswift-create key (%fuzz-key32 fdp))))
         (hash (consume-uint256 fdp)))
    (fuzz-assert (equalp (fuzz-sabotage decoded) (bl.crypto:derive-public-key key))
                 "the encoding decodes to another key")
    (fuzz-assert (bl.crypto:verify-signature hash (bl.crypto:sign-ecdsa key hash) decoded)
                 "the decoded key does not verify the key's signature")))

(define-fuzz-target bip324-ecdh
    (buffer :core "key.cpp:327-372" :iterations 1000 :max-len 200)
  "Two keys' BIP324 ECDH agrees on both sides; two encodings of one key are
equal exactly when their entropy is; acting as the wrong party, or using the
other encoding of their key, gives another secret."
  (unless (bl.crypto:ellswift-available-p)
    (return-from fuzz-target/bip324-ecdh))
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (k1 (or (%consume-private-key fdp) (fuzz-reject)))
         (k2 (or (%consume-private-key fdp) (fuzz-reject)))
         (ent1 (%fuzz-key32 fdp))
         (ent2 (%fuzz-key32 fdp))
         (ent2-bad (%fuzz-key32 fdp))
         (e1 (bl.crypto:ellswift-create k1 ent1))
         (e2 (bl.crypto:ellswift-create k2 ent2))
         (e2-bad (bl.crypto:ellswift-create k2 ent2-bad))
         (initiating (consume-bool fdp))
         (secret1 (bl.crypto:bip324-ecdh e2 e1 k1 initiating))
         (secret2 (bl.crypto:bip324-ecdh e1 e2 k2 (not initiating))))
    (fuzz-assert (eq (equalp ent2-bad ent2) (equalp e2-bad e2))
                 "two encodings of one key are equal iff their entropy is")
    (fuzz-assert (equalp (fuzz-sabotage secret1) secret2) "the two sides derive different secrets")
    (unless (equalp e1 e2)
      (fuzz-assert (not (equalp (bl.crypto:bip324-ecdh e2 e1 k1 (not initiating)) secret1))
                   "the wrong party derives the same secret"))
    (unless (equalp e2-bad e2)
      (fuzz-assert (not (equalp (bl.crypto:bip324-ecdh e2-bad e1 k1 initiating) secret1))
                   "the other encoding derives the same secret"))))
