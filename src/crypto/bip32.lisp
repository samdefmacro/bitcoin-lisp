;;;; BIP32 hierarchical deterministic (HD) keys
;;;;
;;;; Master key from seed, child derivation (CKDpriv hardened+normal, CKDpub
;;;; normal), neuter (xprv -> xpub), and Base58Check xprv/xpub serialization.
;;;; Matches BIP32 (refs/bitcoin/src/key.cpp CKey/CExtKey + base58 encoding).

(in-package #:bitcoin-lisp.crypto)

;;; secp256k1 group order n.
(defconstant +secp256k1-order+
  #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)

;;; Indices >= 2^31 are hardened.
(defconstant +bip32-hardened+ #x80000000)

;;; Base58 version prefixes (the leading 4 serialization bytes).
(defconstant +xprv-mainnet+ #x0488ADE4)  ; "xprv"
(defconstant +xpub-mainnet+ #x0488B21E)  ; "xpub"
(defconstant +xprv-testnet+ #x04358394)  ; "tprv"
(defconstant +xpub-testnet+ #x043587CF)  ; "tpub"

(defstruct ext-key
  "A BIP32 extended key (private or public)."
  (version 0 :type (unsigned-byte 32))            ; serialization version prefix
  (depth 0 :type (unsigned-byte 8))
  (parent-fingerprint 0 :type (unsigned-byte 32)) ; first 4 bytes of hash160(parent pubkey)
  (child-number 0 :type (unsigned-byte 32))
  (chain-code nil)                                ; 32-byte vector
  (key nil)                                       ; 33 bytes: 0x00||priv32 (private) or compressed pubkey
  (privatep nil :type boolean))

;;; --- byte / integer helpers ---

(defun hmac-sha512 (key data)
  "HMAC-SHA512 of DATA keyed by KEY (both octet vectors). Returns 64 bytes."
  (let ((h (ironclad:make-hmac (coerce key '(simple-array (unsigned-byte 8) (*)))
                               :sha512)))
    (ironclad:update-hmac h (coerce data '(simple-array (unsigned-byte 8) (*))))
    (ironclad:hmac-digest h)))

(defun %u32-be (n)
  "N as 4 big-endian bytes."
  (let ((v (make-array 4 :element-type '(unsigned-byte 8))))
    (setf (aref v 0) (logand (ash n -24) #xff)
          (aref v 1) (logand (ash n -16) #xff)
          (aref v 2) (logand (ash n -8) #xff)
          (aref v 3) (logand n #xff))
    v))

(defun %be->int (bytes)
  "Big-endian BYTES -> integer."
  (let ((r 0)) (loop for b across bytes do (setf r (logior (ash r 8) b))) r))

(defun %int->32be (n)
  "Integer N -> 32 big-endian bytes."
  (let ((v (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (loop for i from 31 downto 0 do (setf (aref v i) (logand n #xff) n (ash n -8)))
    v))

(defun %xprv-version-p (v) (or (= v +xprv-mainnet+) (= v +xprv-testnet+)))
(defun %xprv->xpub-version (v) (if (= v +xprv-mainnet+) +xpub-mainnet+ +xpub-testnet+))

(defun ext-key-public-bytes (k)
  "The 33-byte compressed public key for K (derived if K is a private key)."
  (if (ext-key-privatep k)
      (derive-public-key (subseq (ext-key-key k) 1 33) :compressed t)
      (ext-key-key k)))

(defun %fingerprint (k)
  "First 4 bytes of hash160(pubkey of K), as a uint32 (BIP32 key fingerprint)."
  (%be->int (subseq (hash160 (ext-key-public-bytes k)) 0 4)))

;;; --- derivation ---

(defun bip32-master-key (seed &key (network :mainnet))
  "Master extended PRIVATE key from SEED (a 16-64 byte octet vector). NETWORK is
:mainnet or :testnet (selects the xprv/tprv version prefix)."
  (let* ((i (hmac-sha512 (flexi-streams:string-to-octets "Bitcoin seed"
                                                          :external-format :ascii)
                         seed))
         (il (subseq i 0 32))
         (ir (subseq i 32 64)))
    (unless (< 0 (%be->int il) +secp256k1-order+)
      (crypto-error "invalid seed: master key out of range"))
    (make-ext-key :version (if (eq network :mainnet) +xprv-mainnet+ +xprv-testnet+)
                  :chain-code ir
                  :key (concatenate '(vector (unsigned-byte 8)) #(0) il)
                  :privatep t)))

(defun bip32-derive-child (parent index)
  "Derive the child extended key of PARENT at INDEX. INDEX >= +bip32-hardened+
selects a hardened child (only possible from a private PARENT). From a public
PARENT this performs CKDpub (normal indices only). Signals an error for the rare
invalid-child case (IL >= n or zero key) — the caller should try the next index."
  (let* ((hardened (>= index +bip32-hardened+))
         (cc (ext-key-chain-code parent))
         (data (if hardened
                   (progn
                     (unless (ext-key-privatep parent)
                       (crypto-error "cannot derive a hardened child from a public key"))
                     (concatenate '(vector (unsigned-byte 8))
                                  (ext-key-key parent) (%u32-be index)))
                   (concatenate '(vector (unsigned-byte 8))
                                (ext-key-public-bytes parent) (%u32-be index))))
         (i (hmac-sha512 cc data))
         (il (subseq i 0 32))
         (ir (subseq i 32 64))
         (il-int (%be->int il))
         (fp (%fingerprint parent))
         (depth (1+ (ext-key-depth parent))))
    (when (>= il-int +secp256k1-order+)
      (crypto-error "invalid child (IL >= n); try the next index"))
    (if (ext-key-privatep parent)
        ;; CKDpriv: child key = (IL + kpar) mod n
        (let ((ki (mod (+ il-int (%be->int (subseq (ext-key-key parent) 1 33)))
                       +secp256k1-order+)))
          (when (zerop ki) (crypto-error "invalid child (zero key); try the next index"))
          (make-ext-key :version (ext-key-version parent) :depth depth
                        :parent-fingerprint fp :child-number index :chain-code ir
                        :key (concatenate '(vector (unsigned-byte 8)) #(0) (%int->32be ki))
                        :privatep t))
        ;; CKDpub: child pubkey = Kpar + IL*G
        (let ((kpub (tweak-add-public-key (ext-key-key parent) il)))
          (unless kpub (crypto-error "invalid child public key; try the next index"))
          (make-ext-key :version (ext-key-version parent) :depth depth
                        :parent-fingerprint fp :child-number index :chain-code ir
                        :key kpub :privatep nil)))))

(defun bip32-neuter (k)
  "The public (xpub) extended key for K; returns K unchanged if already public."
  (if (not (ext-key-privatep k))
      k
      (make-ext-key :version (%xprv->xpub-version (ext-key-version k))
                    :depth (ext-key-depth k)
                    :parent-fingerprint (ext-key-parent-fingerprint k)
                    :child-number (ext-key-child-number k)
                    :chain-code (ext-key-chain-code k)
                    :key (ext-key-public-bytes k)
                    :privatep nil)))

;;; --- serialization ---

(defun bip32-serialize (k)
  "Serialize K to its Base58Check xprv/xpub (tprv/tpub) string."
  (let* ((payload (concatenate '(vector (unsigned-byte 8))
                               (%u32-be (ext-key-version k))
                               (vector (ext-key-depth k))
                               (%u32-be (ext-key-parent-fingerprint k))
                               (%u32-be (ext-key-child-number k))
                               (ext-key-chain-code k)
                               (ext-key-key k)))
         (checksum (subseq (hash256 payload) 0 4)))
    (base58-encode (concatenate '(vector (unsigned-byte 8)) payload checksum))))

(defun %xpub-version-p (v) (or (= v +xpub-mainnet+) (= v +xpub-testnet+)))

(defun bip32-parse (str)
  "Parse a Base58Check xprv/xpub STR into an ext-key, or NIL if it is not a
valid extended key.

This used to check the checksum and nothing else, which meant it accepted 15 of
the 16 keys in BIP32's own test vector 5 (Core bip32_tests.cpp:104-122) — every
one of them except the deliberately corrupted checksum. A permissive extended-key
parser is not a cosmetic problem: it accepts keys that derive to something other
than what whoever wrote them intended, and a wallet imported from one produces
addresses nobody can spend.

Every rejection below corresponds to one of those vectors:

  - an unknown version prefix (neither xprv/tprv nor xpub/tpub);
  - a private key whose 33 bytes do not begin with the required 0x00 pad, or
    whose scalar is 0 or >= the group order (not a valid secret);
  - a public key that is not a valid compressed point — which covers the 0x04
    and 0x01 prefixes and the on-curve check, so an x that has no y is refused
    rather than carried around as 33 opaque bytes;
  - depth 0 with a non-zero parent fingerprint, or with a non-zero child index.
    A master key has no parent and is nobody's child; claiming otherwise makes
    the fingerprint chain a lie."
  (let ((bytes (base58-decode str)))
    (when (and bytes (= (length bytes) 82)
               (equalp (subseq bytes 78 82) (subseq (hash256 (subseq bytes 0 78)) 0 4)))
      (let* ((version (%be->int (subseq bytes 0 4)))
             (privatep (%xprv-version-p version))
             (depth (aref bytes 4))
             (fingerprint (%be->int (subseq bytes 5 9)))
             (child (%be->int (subseq bytes 9 13)))
             (key (subseq bytes 45 78)))
        (when (and (or privatep (%xpub-version-p version))
                   (if privatep
                       (and (zerop (aref key 0))
                            (let ((d (%be->int (subseq key 1 33))))
                              (and (plusp d) (< d +secp256k1-order+))))
                       (and (bl.crypto::parse-public-key key) t))
                   ;; A master key has no parent and no index.
                   (or (plusp depth)
                       (and (zerop fingerprint) (zerop child))))
          (make-ext-key :version version
                        :depth depth
                        :parent-fingerprint fingerprint
                        :child-number child
                        :chain-code (subseq bytes 13 45)
                        :key key
                        :privatep privatep))))))

;;; --- paths ---

(defun %parse-bip32-path (path)
  "Parse a derivation PATH string (\"m/44'/0'/0'/0/0\"; apostrophe or h = hardened)
into a list of integer child indices."
  (loop for p in (remove "" (uiop:split-string path :separator "/") :test #'string=)
        unless (string-equal p "m")
          collect (let* ((hardened (or (find #\' p) (find #\h p) (find #\H p)))
                         (num (parse-integer (string-trim "'hH" p))))
                    (if hardened (+ num +bip32-hardened+) num))))

(defun bip32-derive-path (k path)
  "Derive from K along PATH — a string like \"m/44'/0'/0'/0/0\" (apostrophe or h =
hardened) or a list of integer indices."
  (reduce #'bip32-derive-child
          (if (listp path) path (%parse-bip32-path path))
          :initial-value k))

;;; --- BIP341 taproot key tweak (signing side) ---
;;; Lives here because it needs the mod-n helpers above; tap-tweak-hash itself
;;; is in hash.lisp.

(defun taproot-tweak-private-key (privkey &optional merkle-root)
  "BIP341 output secret key for a key-path spend: the secret whose x-only public
key is the tweaked output key Q = P + H_TapTweak(P||merkle_root)*G, where P is the
internal key of the 32-byte PRIVKEY. MERKLE-ROOT is NIL for key-path-only outputs.
Returns the 32-byte tweaked secret (feed to sign-schnorr). Errors on the negligible
invalid cases (tweak >= n or zero result)."
  (let* ((p-xonly (derive-xonly-pubkey privkey))
         (full-pub (derive-public-key privkey :compressed t))
         (d (%be->int privkey))
         ;; BIP341: if the internal point P has odd Y, sign with n - d so the
         ;; effective base point has even Y.
         (d-even (if (= (aref full-pub 0) 2) d (- +secp256k1-order+ d)))
         (tweak (%be->int (tap-tweak-hash p-xonly merkle-root))))
    (when (>= tweak +secp256k1-order+) (crypto-error "invalid taproot tweak (>= n)"))
    (let ((out (mod (+ d-even tweak) +secp256k1-order+)))
      (when (zerop out) (crypto-error "invalid taproot output key (zero)"))
      (%int->32be out))))
