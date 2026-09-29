(in-package #:bitcoin-lisp.wallet)

;;;; MuSig2 inside a PSBT (BIP373): Core's SignMuSig2 (script/sign.cpp:266-363)
;;;; and the three MutableTransactionSignatureCreator steps it drives
;;;; (:103-201), over ONE taproot input's PSBT records.
;;;;
;;;; One pass per input, run by every signer Core runs it from: the wallet
;;;; (walletprocesspsbt -- keys and the wallet's secret-nonce table), the
;;;; descriptor signer (descriptorprocesspsbt -- keys, NO table) and the
;;;; finalizer (finalizepsbt -- neither). For each musig() aggregate the input
;;;; names, in Core's order:
;;;;
;;;;   1. every participant's partial signature present -> AGGREGATE them
;;;;      into the key-path or script-path signature;
;;;;   2. else every nonce present -> each participant WE hold makes its
;;;;      partial signature, spending its secret nonce;
;;;;   3. else, when no partial signature exists yet, each participant we
;;;;      hold without a nonce CONTRIBUTES one, its secret nonce kept in the
;;;;      wallet's table under Core's session id.
;;;;
;;;; The secret nonces live only in memory (Core
;;;; DescriptorScriptPubKeyMan::m_musig2_secnonces, scriptpubkeyman.h:297-308:
;;;; "held only in memory and must not be written to disk"), so a restart
;;;; ends every session -- which is the point: a nonce reloaded from disk is a
;;;; nonce that can be made to sign twice.

(defstruct (mu2-context (:conc-name mu2-))
  "What one input's MuSig2 pass signs with. SIGHASH-FN maps a leaf hash (NIL
for the key path) to the 32-byte BIP341 sighash or NIL; HASHTYPE is the
sighash byte, appended to an aggregate signature when it is not
SIGHASH_DEFAULT (Core `if (nHashType) sig.push_back(nHashType)'). KEYS maps a
33-byte participant key to its 32-byte secret, or is NIL for a signer with no
keys (the finalizer). SECNONCES is the session-id -> MUSIG-SECNONCE table, or
NIL for a provider that has none (Core's FlatSigningProvider with
musig2_secnonces unset). PARTICIPANTS is Core's sigdata.musig2_pubkeys: a list
of (AGGREGATE . PARTICIPANTS), sorted by aggregate."
  map
  sighash-fn
  (hashtype 0)
  keys
  secnonces
  participants)

(defparameter *mu2-null-leaf*
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
  "The leaf hash a key-path session is filed under (Core's
`leaf_hash ? *leaf_hash : uint256()').")

(defun %mu2-octets (v) (coerce v '(simple-array (unsigned-byte 8) (*))))

(defun %mu2-session-records (map keytype plain leaf)
  "The PSBT_IN_MUSIG2_PUB_NONCE or _PARTIAL_SIG records (KEYTYPE) of MAP for
the session (PLAIN, LEAF) as an alist participant -> value, one entry per
participant. Keydata is <participant><aggregate>[<leaf hash>] (psbt.h:423-445);
a 98-byte key whose leaf hash is all zero is the KEY path, as it is in Core's
map (DeserializeMuSig2ParticipantDataIdentifier leaves it null)."
  (let ((want (or leaf *mu2-null-leaf*))
        (out '()))
    (loop for (kd . value) in (bl.ser:psbt-map-collect map keytype)
          do (when (and (member (length kd) '(66 98))
                        (equalp (subseq kd 33 66) plain)
                        (equalp (if (= (length kd) 98) (subseq kd 66 98) *mu2-null-leaf*)
                                want))
               (let ((part (subseq kd 0 33)))
                 (unless (assoc part out :test #'equalp)
                   (push (cons part value) out)))))
    (nreverse out)))

(defun %mu2-record! (map keytype part plain leaf value)
  "Record VALUE for PART in session (PLAIN, LEAF) unless MAP has one already
(Core's emplace, which never overwrites)."
  (unless (assoc part (%mu2-session-records map keytype plain leaf) :test #'equalp)
    (bl.ser:psbt-map-set map keytype
                         (concatenate '(simple-array (unsigned-byte 8) (*))
                                      part plain (or leaf #()))
                         value)))

(defun mu2-merge-participants (map extra)
  "Core sigdata.musig2_pubkeys for an input: the PSBT's own
PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS (FillSignatureData, psbt.cpp:152), then
EXTRA -- the signing provider's (aggregate . participants) -- for aggregates
the PSBT does not name (std::map::insert keeps the first). Sorted by
aggregate, the map's order."
  (let ((out '()))
    (loop for (agg . value) in (bl.ser:psbt-map-collect
                                map bl.ser:+psbt-in-musig2-participant-pubkeys+)
          do (unless (assoc agg out :test #'equalp)
               (push (cons agg (loop for i from 0 below (floor (length value) 33)
                                     collect (subseq value (* i 33) (* (1+ i) 33))))
                     out)))
    (loop for (agg . parts) in extra
          do (unless (assoc agg out :test #'equalp)
               (push (cons (%mu2-octets agg) (mapcar #'%mu2-octets parts)) out)))
    (sort out (lambda (a b)
                (let ((m (mismatch a b)))
                  (and m (< (aref a m) (aref b m)))))
          :key #'car)))

(defun %mu2-tap-origin (map xonly)
  "(values FINGERPRINT PATH) of the PSBT_IN_TAP_BIP32_DERIVATION record for
XONLY -- Core's sigdata.taproot_misc_pubkeys entry, the agg_info SignMuSig2
reads (script/sign.cpp:270-275) -- or NIL. The value is <n><n leaf
hashes><4-byte fingerprint><LE32 path>*."
  (let ((value (cdr (assoc xonly (bl.ser:psbt-map-collect map bl.ser:+psbt-in-tap-bip32+)
                           :test #'equalp))))
    (when value
      (ignore-errors
       (let* ((br (bl.ser:make-byte-reader-from value))
              (n (bl.ser:br-read-compact-size br)))
         (bl.ser:br-read-bytes br (* 32 n))
         (let ((fpr (bl.ser:br-read-bytes br 4)))
           (values fpr
                   (loop until (bl.ser:br-eof-p br)
                         collect (bl.ser:br-read-u32-le br)))))))))

;;; --- The three signature-creator steps (script/sign.cpp:103-201) -----------

(defun %mu2-nonce (ctx agg plain part leaf parts)
  "Core MutableTransactionSignatureCreator::CreateMuSig2Nonce: PART's public
nonce for session (PLAIN, LEAF), its secret nonce filed in the context's table
under MuSig2SessionID(PLAIN, PART, sighash); or NIL.

With no table the secret nonce is dropped on the spot, as Core's
SetMuSig2SecNonce drops it for a provider without one (`if
(!Assume(musig2_secnonces)) return;') -- the public nonce is still returned.
A session that already HAS a secret nonce is an error: Core Asserts it cannot
happen (signingprovider.cpp:125-127), because a second nonce for the same
session would orphan one of the two published ones."
  (let ((key (and (mu2-keys ctx) (funcall (mu2-keys ctx) part))))
    (when (and key (member part parts :test #'equalp))
      (let ((sighash (funcall (mu2-sighash-fn ctx) leaf)))
        (when sighash
          (multiple-value-bind (pubnonce secnonce)
              (bl.crypto:musig2-create-nonce key sighash agg parts)
            (when pubnonce
              (let ((table (mu2-secnonces ctx))
                    (id (bl.crypto:musig2-session-id plain part sighash)))
                (cond ((null table) (bl.crypto:musig-secnonce-invalidate secnonce))
                      ((gethash id table)
                       (bl.crypto:musig-secnonce-invalidate secnonce)
                       (wallet-error "a MuSig2 signing session for this input already has a secret nonce"))
                      (t (setf (gethash id table) secnonce)))
                pubnonce))))))))


(defun %mu2-partial-sig (ctx agg plain part leaf parts tweaks)
  "Core MutableTransactionSignatureCreator::CreateMuSig2PartialSig: PART's
partial signature for session (PLAIN, LEAF) once every participant's nonce is
in the PSBT, made with the secret nonce this signer filed for it -- which is
spent, and the session deleted (DeleteMuSig2Session). NIL when any of that is
missing, a secret nonce already spent included."
  (let ((key (and (mu2-keys ctx) (funcall (mu2-keys ctx) part)))
        (table (mu2-secnonces ctx)))
    (when (and key table (member part parts :test #'equalp))
      (let ((pubnonces (%mu2-session-records (mu2-map ctx) bl.ser:+psbt-in-musig2-pub-nonce+
                                             plain leaf)))
        (when (= (length pubnonces) (length parts))
          (let ((sighash (funcall (mu2-sighash-fn ctx) leaf)))
            (when sighash
              (let* ((id (bl.crypto:musig2-session-id plain part sighash))
                     (secnonce (gethash id table)))
                (when (and secnonce (bl.crypto:musig-secnonce-valid-p secnonce))
                  (let ((psig (bl.crypto:musig2-create-partial-sig
                               key sighash agg parts pubnonces secnonce tweaks)))
                    (when psig
                      (remhash id table)
                      psig)))))))))))

(defun %mu2-aggregate-sig (ctx agg plain leaf parts tweaks)
  "Core MutableTransactionSignatureCreator::CreateMuSig2AggregateSig: the
signature for session (PLAIN, LEAF) from its participants' nonces and partial
signatures, the sighash byte appended unless it is SIGHASH_DEFAULT; NIL until
every participant has both.

The aggregate is also checked against PLAIN, the key it must verify under,
before it is returned. Core leaves that to the VerifyScript at the end of
ProduceSignature; checking here means a wrong tweak can never put a
signature that does not verify into the PSBT."
  (let* ((map (mu2-map ctx))
         (pubnonces (%mu2-session-records map bl.ser:+psbt-in-musig2-pub-nonce+ plain leaf))
         (psigs (%mu2-session-records map bl.ser:+psbt-in-musig2-partial-sig+ plain leaf)))
    (when (and parts (= (length pubnonces) (length parts)) (= (length psigs) (length parts)))
      (let ((sighash (funcall (mu2-sighash-fn ctx) leaf)))
        (when sighash
          (let ((sig (bl.crypto:musig2-create-aggregate-sig parts agg tweaks sighash
                                                            pubnonces psigs)))
            (cond ((null sig) nil)
                  ((not (bl.crypto:verify-schnorr-signature sighash sig (subseq plain 1)))
                   (bl:log-warn "MuSig2: an aggregate signature does not verify under ~A; not recorded"
                                (bl.crypto:bytes-to-hex plain))
                   nil)
                  ((zerop (mu2-hashtype ctx)) sig)
                  (t (concatenate '(simple-array (unsigned-byte 8) (*))
                                  sig (vector (mu2-hashtype ctx)))))))))))

;;; --- SignMuSig2 (script/sign.cpp:266-363) ------------------------------------

(defun %mu2-session-key (agg script-pubkey keypath-root map)
  "SignMuSig2's derivation of the key an aggregate AGG actually signs as for
SCRIPT-PUBKEY (32-byte x-only), with the tweaks that get it there
(script/sign.cpp:291-322): (values PLAIN TWEAKS), NIL to skip this aggregate,
or :ABORT when a derivation step is impossible (Core returns false for the
whole call).

AGG itself when its x-only form IS the key; else a BIP328 child of it, when
the key's origin (from the PSBT's taproot derivations) is rooted at AGG's
fingerprint -- each step a plain tweak. KEYPATH-ROOT, for a key-path attempt,
adds the BIP341 TapTweak: :NONE for no script tree, else the 32-byte merkle
root."
  (let ((plain agg) (tweaks '()))
    (unless (equalp (subseq agg 1) script-pubkey)
      (multiple-value-bind (fpr path) (%mu2-tap-origin map script-pubkey)
        (unless (and path (equalp fpr (subseq (bl.crypto:hash160 agg) 0 4)))
          (return-from %mu2-session-key nil))
        (multiple-value-bind (steps derived) (bl.crypto:musig2-derivation-tweaks agg path)
          (unless steps (return-from %mu2-session-key :abort))
          ;; Core Asserts equality here; a PSBT that lies about the origin
          ;; must not take the node down, so the aggregate is skipped.
          (unless (equalp (subseq derived 1) script-pubkey)
            (return-from %mu2-session-key nil))
          (setf plain derived tweaks steps))))
    (when keypath-root
      (let ((tweak (bl.crypto:tap-tweak-hash script-pubkey
                                             (unless (eq keypath-root :none) keypath-root))))
        (multiple-value-bind (x parity) (bl.crypto:tweak-xonly-pubkey script-pubkey tweak)
          (unless x (return-from %mu2-session-key :abort))
          (setf tweaks (append tweaks (list (cons tweak t)))
                plain (concatenate '(simple-array (unsigned-byte 8) (*))
                                   (vector (if (eql parity 1) 3 2)) x)))))
    (values plain tweaks)))

(defun %mu2-sign (ctx script-pubkey keypath-root leaf)
  "Core SignMuSig2 for the 32-byte x-only SCRIPT-PUBKEY: the key path when
KEYPATH-ROOT is given (see %MU2-SESSION-KEY), the script leaf with hash LEAF
otherwise. For every aggregate whose derivation reaches SCRIPT-PUBKEY: the
aggregate signature if it can be made, else our partial signatures, else --
when none exists yet -- our nonces. Everything lands in the input's map."
  (let ((map (mu2-map ctx)))
    (loop for (agg . parts) in (mu2-participants ctx)
          do (when parts
               (multiple-value-bind (plain tweaks)
                   (%mu2-session-key agg script-pubkey keypath-root map)
                 (when (eq plain :abort) (return-from %mu2-sign nil))
                 (when plain
                   (let ((sig (%mu2-aggregate-sig ctx agg plain leaf parts tweaks)))
                     (cond
                       (sig
                        (let ((empty (make-array 0 :element-type '(unsigned-byte 8))))
                          (if leaf
                              (bl.ser:psbt-map-set
                               map bl.ser:+psbt-in-tap-script-sig+
                               (concatenate '(simple-array (unsigned-byte 8) (*))
                                            script-pubkey leaf)
                               sig)
                              (bl.ser:psbt-map-set map bl.ser:+psbt-in-tap-key-sig+
                                                   empty sig))))
                       (t
                        (dolist (part parts)
                          (let ((psig (%mu2-partial-sig ctx agg plain part leaf parts tweaks)))
                            (when psig
                              (%mu2-record! map bl.ser:+psbt-in-musig2-partial-sig+
                                            part plain leaf psig))))
                        (unless (%mu2-session-records map bl.ser:+psbt-in-musig2-partial-sig+
                                                      plain leaf)
                          (let ((have (%mu2-session-records
                                       map bl.ser:+psbt-in-musig2-pub-nonce+ plain leaf)))
                            (dolist (part parts)
                              (unless (assoc part have :test #'equalp)
                                (let ((pubnonce (%mu2-nonce ctx agg plain part leaf parts)))
                                  (when pubnonce
                                    (%mu2-record! map bl.ser:+psbt-in-musig2-pub-nonce+
                                                  part plain leaf pubnonce))))))))))))))))

(defun %mu2-script-pushes (script)
  "The data pushes of SCRIPT, in order; NIL past a truncated push."
  (let ((i 0) (n (length script)) (out '()))
    (loop while (< i n)
          do (let* ((op (aref script i))
                    (len (cond ((<= 1 op 75) op)
                               ((and (= op 76) (< (1+ i) n)) (aref script (1+ i)))
                               ((and (= op 77) (< (+ i 2) n))
                                (logior (aref script (1+ i)) (ash (aref script (+ i 2)) 8)))
                               (t nil)))
                    (start (+ i 1 (case op (76 1) (77 2) (t 0)))))
               (cond ((null len) (incf i))
                     ((> (+ start len) n) (return))
                     (t (push (subseq script start (+ start len)) out)
                        (setf i (+ start len))))))
    (nreverse out)))

(defun %mu2-leaf-keys (map script)
  "The x-only keys the tapscript leaf SCRIPT signs with, for which Core's
satisfier asks CreateTaprootScriptSig for a signature: every 32-byte push,
and every key of the input's taproot derivations whose HASH160 is a 20-byte
push (a pkh() fragment names its key only by hash, resolved through the
provider's known keys, script/sign.cpp:428-436)."
  (let ((pushes (%mu2-script-pushes script))
        (known (mapcar #'car (bl.ser:psbt-map-collect map bl.ser:+psbt-in-tap-bip32+)))
        (out '()))
    (dolist (p pushes)
      (case (length p)
        (32 (pushnew (%mu2-octets p) out :test #'equalp))
        (20 (dolist (k known)
              (when (and (= (length k) 32) (equalp (bl.crypto:hash160 k) p))
                (pushnew (%mu2-octets k) out :test #'equalp))))))
    (nreverse out)))

(defun psbt-input-sign-musig2 (ctx output-key internal-key merkle-root leaves)
  "The MuSig2 half of Core's SignTaproot (script/sign.cpp:576-612) for the
input whose map CTX carries: the key path through the INTERNAL-KEY tweaked by
MERKLE-ROOT (NIL for none), then through OUTPUT-KEY untweaked -- each tried
only while the input has no key-path signature -- and, while it still has
none, every key of every tapscript leaf in LEAVES, a list of (SCRIPT .
LEAF-HASH), that has no script signature yet.

Core only reaches SignMuSig2 for a key it cannot sign with directly
(CreateSchnorrSig first); the direct signatures are made before this runs, and
an aggregate is never a key anyone holds, so nothing here competes with them."
  (let ((map (mu2-map ctx)))
    (flet ((key-sig-p ()
             (plusp (length (or (bl.ser:psbt-map-find map bl.ser:+psbt-in-tap-key-sig+) #()))))
           (script-sig-p (key leaf-hash)
             (assoc (concatenate '(simple-array (unsigned-byte 8) (*)) key leaf-hash)
                    (bl.ser:psbt-map-collect map bl.ser:+psbt-in-tap-script-sig+)
                    :test #'equalp)))
      (unless (key-sig-p)
        (when internal-key
          (%mu2-sign ctx (%mu2-octets internal-key) (or merkle-root :none) nil))
        (unless (key-sig-p)
          (%mu2-sign ctx (%mu2-octets output-key) nil nil)))
      (unless (key-sig-p)
        (loop for (script . leaf-hash) in leaves
              do (dolist (key (%mu2-leaf-keys map script))
                   (unless (script-sig-p key leaf-hash)
                     (%mu2-sign ctx key nil (%mu2-octets leaf-hash)))))))))
