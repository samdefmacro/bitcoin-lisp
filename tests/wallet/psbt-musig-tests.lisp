(in-package #:bitcoin-lisp.tests)

;;;; MuSig2 through the wallet's PSBT RPCs (Core SignMuSig2, script/sign.cpp:
;;;; 266-363, as wallet_musig.py drives it): three wallets, each holding one
;;;; participant's key of a musig() descriptor, contribute nonces, then partial
;;;; signatures, and a non-participant's finalizepsbt aggregates them. The
;;;; oracle for "the signature is right" is the node's own validation
;;;; (testmempoolaccept), which Core's script vectors pin.

(def-suite :psbt-musig-tests
  :description "MuSig2 nonce / partial-signature / aggregation rounds over PSBTs"
  :in :bitcoin-lisp-tests)

(in-suite :psbt-musig-tests)

(defparameter *musig-test-tprvs*
  '("tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK"
    "tprv8ZgxMBicQKsPeNLUGrbv3b7qhUk1LQJZAGMuk9gVuKh9sd4BWGp1eMsehUni6qGb8bjkdwBxCbgNGdh2bYGACK5C5dRTaif9KBKGVnSezxV"
    "tprv8ZgxMBicQKsPeZRHk4rTG6orPS2CRNFX3njhUXx5vj9qGog5ZMH4uGReDWN5kCkY3jmWEtWause41CDvBRXD1shKknAMKxT99o9qUTRVC6m"))

(defmacro with-musig-wallets ((rpc aval node suffix) &body body)
  "BODY on a regtest node with a funded wallet \"fund\", RPC calling a method
as (RPC WALLET METHOD . PARAMS) and AVAL reading a key of a JSON object."
  `(with-wallet-chain-node (,node ,suffix)
     (labels ((,rpc (wallet method &rest params)
                (with-rpc-wallet (wallet)
                  (bl.rpc:dispatch-rpc-method ,node method params)))
              (,aval (key alist) (cdr (assoc key alist :test #'string=))))
       (,rpc nil "createwallet" "fund")
       (,rpc nil "generatetoaddress" 1 (,rpc "fund" "getnewaddress" "" "bech32"))
       (,rpc nil "generatetoaddress" 101
             (bl.crypto:encode-p2sh-address (bl.crypto:hash160 +optrue-redeem+) :regtest))
       ,@body)))

(defun %musig-json-obj (&rest kv)
  (let ((h (make-hash-table :test 'equal)))
    (loop for (k v) on kv by #'cddr do (setf (gethash k h) v))
    h))

(defun %musig-session (node pattern &key (range nil))
  "Import PATTERN -- a descriptor with ~A where each participant goes, in
order -- into three blank wallets m0..m2, wallet i holding participant i's
tprv and the others' tpubs (RANGE: the import's range end, for a ranged
descriptor); fund its first address and return (values PSBT ADDRESS), PSBT
spending that coin to an anyone-can-spend output."
  (flet ((rpc (wallet method &rest params)
           (with-rpc-wallet (wallet)
             (bl.rpc:dispatch-rpc-method node method params)))
         (aval (key alist) (cdr (assoc key alist :test #'string=))))
    (let* ((tpubs (loop for tprv in *musig-test-tprvs*
                        for d = (aval "descriptor"
                                      (rpc nil "getdescriptorinfo" (format nil "pk(~A)" tprv)))
                        collect (subseq d 3 (search ")" d))))
           (descs (loop for i below 3
                        collect (bl.rpc:descriptor-add-checksum
                                 (apply #'format nil pattern
                                        (loop for j below 3
                                              collect (if (= i j)
                                                          (nth j *musig-test-tprvs*)
                                                          (nth j tpubs))))))))
      (loop for i below 3
            for name = (format nil "m~D" i)
            do (rpc nil "createwallet" name nil t)
               (let ((res (rpc name "importdescriptors"
                               (list (apply #'%musig-json-obj "desc" (nth i descs)
                                            "timestamp" "now"
                                            (when range (list "range" (list 0 range))))))))
                 (assert (eq t (aval "success" (first res))))))
      (let* ((address (first (coerce (if range
                                         (rpc nil "deriveaddresses" (first descs) (list 0 0))
                                         (rpc nil "deriveaddresses" (first descs)))
                                     'list)))
             (optrue (bl.crypto:encode-p2sh-address (bl.crypto:hash160 +optrue-redeem+)
                                                    :regtest))
             (txid (with-wallet-rng (41)
                     (rpc "fund" "sendtoaddress" address (bl.rpc:format-money 100000000)
                          nil nil nil nil nil nil nil 10))))
        (rpc nil "generatetoaddress" 1 optrue)
        (let ((coin (find txid (coerce (rpc "m0" "listunspent") 'list)
                          :key (lambda (c) (aval "txid" c)) :test #'equal)))
          (assert coin)
          (values (rpc nil "createpsbt"
                       (list (%musig-json-obj "txid" txid "vout" (aval "vout" coin)))
                       (list (%musig-json-obj optrue (bl.rpc:format-money 99990000))))
                  address))))))

(defun %musig-input-records (psbt keytype)
  "The (keydata . value) records of KEYTYPE on PSBT's first input."
  (bl.ser:psbt-map-collect (aref (bl.ser:psbt-inputs (bl.ser:decode-psbt psbt)) 0) keytype))

(defmacro %musig-rounds ((rpc aval) psbt &key (signers ''("m0" "m1" "m2")))
  "Run the nonce round and the partial-signature round of SIGNERS over PSBT:
(values NONCE-PSBT PSIG-PSBT NONCE-RESULTS PSIG-RESULTS)."
  `(let* ((nonce-results (mapcar (lambda (w) (,rpc w "walletprocesspsbt" ,psbt)) ,signers))
          (nonce-psbt (,rpc nil "combinepsbt" (mapcar (lambda (r) (,aval "psbt" r))
                                                      nonce-results)))
          (psig-results (mapcar (lambda (w) (,rpc w "walletprocesspsbt" nonce-psbt)) ,signers))
          (psig-psbt (,rpc nil "combinepsbt" (mapcar (lambda (r) (,aval "psbt" r))
                                                     psig-results))))
     (values nonce-psbt psig-psbt nonce-results psig-results)))

(test musig-key-path-signs-through-three-wallets
  "tr(musig(A,B,C)): each wallet contributes one BIP373 nonce record, then one
partial signature, and finalizepsbt -- which holds no key -- aggregates a
key-path signature the node's validation accepts. The records are Core's
layout byte for byte: PUB_NONCE keydata <participant 33><plain key 33> with a
66-byte value, PARTIAL_SIG the same keydata with a 32-byte value
(psbt.h:423-445), the plain key being the TWEAKED output key with its parity
prefix (script/sign.cpp:318-321). No round reports complete, and the pass
before any nonce exists produces no partial signature."
  (with-musig-wallets (rpc aval node "musig-keypath")
    (multiple-value-bind (psbt address) (%musig-session node "tr(musig(~A,~A,~A))")
      (let ((spk (bl.crypto:hex-to-bytes
                  (aval "scriptPubKey" (rpc nil "validateaddress" address)))))
      (multiple-value-bind (nonce-psbt psig-psbt nonce-results psig-results)
          (%musig-rounds (rpc aval) psbt)
        (is (notany (lambda (r) (eq t (aval "complete" r))) nonce-results))
        (is (notany (lambda (r) (eq t (aval "complete" r))) psig-results))
        (let ((nonces (%musig-input-records nonce-psbt bl.ser:+psbt-in-musig2-pub-nonce+))
              (psigs (%musig-input-records psig-psbt bl.ser:+psbt-in-musig2-partial-sig+))
              (participants (%musig-input-records nonce-psbt
                                                  bl.ser:+psbt-in-musig2-participant-pubkeys+)))
          (is (= 3 (length nonces)))
          (is (= 0 (length (%musig-input-records nonce-psbt bl.ser:+psbt-in-musig2-partial-sig+))))
          (is (= 3 (length psigs)))
          (is (= 1 (length participants)))
          (is (every (lambda (r) (and (= 66 (length (car r))) (= 66 (length (cdr r))))) nonces))
          (is (every (lambda (r) (and (= 66 (length (car r))) (= 32 (length (cdr r))))) psigs))
          (let ((parts (loop with v = (cdr (first participants))
                             for i below (floor (length v) 33)
                             collect (subseq v (* 33 i) (* 33 (1+ i))))))
            (is (equal (sort (mapcar (lambda (r) (bl.crypto:bytes-to-hex (subseq (car r) 0 33)))
                                     nonces)
                             #'string<)
                       (sort (mapcar #'bl.crypto:bytes-to-hex parts) #'string<))))
          (is (every (lambda (r) (equalp (subseq (car r) 34 66) (subseq spk 2 34))) nonces)
              "the session key of a key-path nonce is the tweaked OUTPUT key"))
        (let ((final (rpc nil "finalizepsbt" psig-psbt)))
          (is (eq t (aval "complete" final)))
          (is (eq t (aval "allowed" (first (rpc nil "testmempoolaccept"
                                                (list (aval "hex" final))))))))
        ;; Positive control for the aggregation: one partial signature
        ;; corrupted and the finalizer refuses to aggregate.
        (let* ((p (bl.ser:decode-psbt psig-psbt))
               (map (aref (bl.ser:psbt-inputs p) 0))
               (rec (first (bl.ser:psbt-map-collect map bl.ser:+psbt-in-musig2-partial-sig+)))
               (bad (copy-seq (cdr rec))))
          (setf (aref bad 31) (logxor (aref bad 31) 1))
          (bl.ser:psbt-map-set map bl.ser:+psbt-in-musig2-partial-sig+ (car rec) bad)
          (is (not (eq t (aval "complete" (rpc nil "finalizepsbt" (bl.ser:encode-psbt p))))))))))))

(test musig-secret-nonce-is-spent-once-and-dies-with-the-wallet
  "The session lifetime. A wallet asked for a SECOND nonce in a session it
already holds one for refuses rather than orphan either (Core Asserts it
cannot happen, signingprovider.cpp:127) and keeps the first; a wallet that is
unloaded and loaded again has no session left, so it can no longer make its
partial signature -- the secret nonce was never written anywhere; and a
wallet that has signed makes no second partial signature from the same
nonce PSBT, its secret nonce being spent."
  (with-musig-wallets (rpc aval node "musig-lifetime")
    (let* ((psbt (%musig-session node "tr(musig(~A,~A,~A))"))
           (n0 (aval "psbt" (rpc "m0" "walletprocesspsbt" psbt)))
           (n1 (aval "psbt" (rpc "m1" "walletprocesspsbt" psbt)))
           (again (handler-case (progn (rpc "m1" "walletprocesspsbt" psbt) nil)
                    (error (e) (princ-to-string e))))
           (n2 (aval "psbt" (rpc "m2" "walletprocesspsbt" psbt))))
      (is (and again (search "already has a secret nonce" again))
          "a second nonce for a live session must be refused: ~S" again)
      (rpc "m2" "unloadwallet")
      (rpc nil "loadwallet" "m2")
      (let ((nonces (rpc nil "combinepsbt" (list n0 n1 n2))))
        (is (= 3 (length (%musig-input-records nonces bl.ser:+psbt-in-musig2-pub-nonce+))))
        (flet ((psigs (wallet)
                 (length (%musig-input-records
                          (aval "psbt" (rpc wallet "walletprocesspsbt" nonces))
                          bl.ser:+psbt-in-musig2-partial-sig+))))
          ;; The control: m0 and m1 still hold their sessions and sign...
          (is (= 1 (psigs "m0")))
          (is (= 1 (psigs "m1")) "the refused second nonce must not cost m1 its first")
          ;; ...m2 lost its with the unload...
          (is (= 0 (psigs "m2")))
          ;; ...and m0, having signed, cannot sign again.
          (is (= 0 (psigs "m0"))))))))

(test musig-derived-and-script-path-sessions-finalize
  "Two more of wallet_musig.py's shapes. rawtr(musig(...)/0/*): the key is a
BIP328 child of the aggregate, reached by the plain tweaks SignMuSig2 derives
from the input's taproot derivation (script/sign.cpp:291-311) -- and a rawtr()
input carries NO internal key, as in Core. tr(H,pk(musig(...)/0/*)): the
session lives in the leaf, its records carry the 32-byte leaf hash (98-byte
keydata), and the finalized witness is a script-path spend. Both are
accepted by the node's validation."
  (dolist (case '(("rawtr(musig(~A,~A,~A)/0/*)" 1 nil)
                  ("tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,pk(musig(~A,~A,~A)/0/*))" 3 t)))
    (destructuring-bind (pattern witness-items script-path) case
      (with-musig-wallets (rpc aval node "musig-shapes")
        (let ((psbt (%musig-session node pattern :range 2)))
          (multiple-value-bind (nonce-psbt psig-psbt) (%musig-rounds (rpc aval) psbt)
            (let ((input (first (coerce (aval "inputs" (rpc nil "decodepsbt" nonce-psbt)) 'list)))
                  (nonces (%musig-input-records nonce-psbt bl.ser:+psbt-in-musig2-pub-nonce+)))
              (is (= 3 (length nonces)))
              (is (every (lambda (r) (= (if script-path 98 66) (length (car r)))) nonces))
              (unless script-path
                (is (null (aval "taproot_internal_key" input))
                    "a rawtr() input has no internal key: ~S" (aval "taproot_internal_key" input))))
            (is (= 3 (length (%musig-input-records psig-psbt bl.ser:+psbt-in-musig2-partial-sig+))))
            (let* ((final (rpc nil "finalizepsbt" psig-psbt bl.rpc:+json-false+))
                   (witness (aval "final_scriptwitness"
                                  (first (coerce (aval "inputs"
                                                       (rpc nil "decodepsbt" (aval "psbt" final)))
                                                 'list)))))
              (is (eq t (aval "complete" final)))
              (is (= witness-items (length witness))))
            (let ((hex (aval "hex" (rpc nil "finalizepsbt" psig-psbt))))
              (is (eq t (aval "allowed" (first (rpc nil "testmempoolaccept" (list hex)))))))))))))

(test musig-descriptorprocesspsbt-nonce-has-no-secret-kept
  "descriptorprocesspsbt signs from descriptors, whose provider has no
secret-nonce table: Core's SetMuSig2SecNonce returns on
`!Assume(musig2_secnonces)' (signingprovider.cpp:124) after the public nonce
was already made, so the nonce is published and its secret dropped. The
control is the partial-signature round: with every nonce in, the wallets make
theirs and the descriptor signer makes none."
  (with-musig-wallets (rpc aval node "musig-descproc")
    (let* ((psbt (%musig-session node "tr(musig(~A,~A,~A))"))
           (desc (bl.rpc:descriptor-add-checksum
                  (format nil "tr(musig(~{~A~^,~}))"
                          (cons (first *musig-test-tprvs*)
                                (loop for tprv in (rest *musig-test-tprvs*)
                                      for d = (aval "descriptor"
                                                    (rpc nil "getdescriptorinfo"
                                                         (format nil "pk(~A)" tprv)))
                                      collect (subseq d 3 (search ")" d)))))))
           (d0 (aval "psbt" (rpc nil "descriptorprocesspsbt" psbt (list desc))))
           (n1 (aval "psbt" (rpc "m1" "walletprocesspsbt" psbt)))
           (n2 (aval "psbt" (rpc "m2" "walletprocesspsbt" psbt))))
      (is (= 1 (length (%musig-input-records d0 bl.ser:+psbt-in-musig2-pub-nonce+))))
      (let ((nonces (rpc nil "combinepsbt" (list d0 n1 n2))))
        (is (= 3 (length (%musig-input-records nonces bl.ser:+psbt-in-musig2-pub-nonce+))))
        (is (= 1 (length (%musig-input-records
                          (aval "psbt" (rpc "m1" "walletprocesspsbt" nonces))
                          bl.ser:+psbt-in-musig2-partial-sig+))))
        (is (= 0 (length (%musig-input-records
                          (aval "psbt" (rpc nil "descriptorprocesspsbt" nonces (list desc)))
                          bl.ser:+psbt-in-musig2-partial-sig+))))))))

(test descriptorprocesspsbt-updates-a-taproot-input-as-cores-updater
  "ProcessPSBT's updater over a descriptor-solved taproot input
(rpc/rawtransaction.cpp:190-205 -> SignPSBTInput -> FromSignatureData,
psbt.cpp:196-206) writes the TaprootSpendData -- internal key, merkle root,
leaf scripts -- the MuSig2 participants, and, unless bip32derivs=false hides
the origins (HidingSigningProvider), the taproot derivations. It wrote the
internal key alone."
  (with-musig-wallets (rpc aval node "musig-updater")
    (let* ((psbt (%musig-session
                  node "tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,pk(musig(~A,~A,~A)/0/*))"
                  :range 2))
           (public (let ((d (aval "descriptor"
                                  (rpc nil "getdescriptorinfo"
                                       (aval "desc" (first (coerce (aval "descriptors"
                                                                         (rpc "m0" "listdescriptors"))
                                                                   'list)))))))
                     d))
           (request (list (%musig-json-obj "desc" public "range" (list 0 2)))))
      (flet ((input (derivs)
               (first (coerce (aval "inputs"
                                    (rpc nil "decodepsbt"
                                         (aval "psbt" (rpc nil "descriptorprocesspsbt" psbt request
                                                           "DEFAULT" derivs))))
                              'list))))
        (let ((full (input t))
              (hidden (input bl.rpc:+json-false+)))
          (is (aval "taproot_internal_key" full))
          (is (aval "taproot_merkle_root" full))
          (is (= 1 (length (coerce (aval "taproot_scripts" full) 'list))))
          (is (= 1 (length (coerce (aval "musig2_participant_pubkeys" full) 'list))))
          ;; the internal key H (a const key is its own origin), the leaf's
          ;; musig() key and its three participants
          (is (= 5 (length (coerce (aval "taproot_bip32_derivs" full) 'list))))
          ;; Origins hidden, the spend data and participants still there.
          (is (null (aval "taproot_bip32_derivs" hidden)))
          (is (aval "taproot_internal_key" hidden))
          (is (= 1 (length (coerce (aval "taproot_scripts" hidden) 'list))))
          (is (= 1 (length (coerce (aval "musig2_participant_pubkeys" hidden) 'list)))))))))
