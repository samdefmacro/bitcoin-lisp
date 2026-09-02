(in-package #:bitcoin-lisp.rpc)

;;; Output descriptors (Bitcoin Core src/script/descriptor.cpp)
;;;
;;; Supported grammar (P0 descriptor engine):
;;;   addr(ADDRESS)  raw(HEX)
;;;   pk(KEY)  pkh(KEY)  wpkh(KEY)  combo(KEY)
;;;   multi(k,KEY,...)  sortedmulti(k,KEY,...)
;;;   sh(SCRIPT)  wsh(SCRIPT)  sh(wsh(SCRIPT))
;;;   tr(KEY)  tr(KEY,TREE)  rawtr(KEY)
;;;   multi_a(k,KEY,...)  sortedmulti_a(k,KEY,...)   [inside tr() only]
;;; where KEY is a hex pubkey (33/65 bytes; 32-byte x-only inside tr/rawtr),
;;; a WIF private key, or an xpub/xprv (tpub/tprv on test networks) with an
;;; optional [fingerprint/path] origin prefix, a derivation path using h or '
;;; hardened markers, and an optional ranged terminal /* or /*h; and TREE is a
;;; brace-nested taproot script tree.
;;;
;;; tr() trees are WATCH-ONLY: they parse, print, derive the right bech32m
;;; address and recognise their own outputs, but nothing here can produce a
;;; script-path spend. Still out of scope (match Core error text where Core has
;;; one, otherwise a clear "not supported"): multipath <a;b>, musig, and
;;; miniscript in a tapscript context.
;;;
;;; Nesting/context rules, key-count limits, and error messages follow Core's
;;; ParseScript/ParsePubkey exactly (descriptor.cpp:1745-2673).

;;; --- Descriptor checksum (descriptor.cpp PolyMod/DescriptorChecksum) ---

(alexandria:define-constant +descriptor-input-charset+
    (concatenate 'string
                 "0123456789()[],'/*abcdefgh@:$%{}"
                 "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~"
                 "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ")
  :test #'equal
  :documentation "Character set for descriptor checksums (Core's INPUT_CHARSET).")

(alexandria:define-constant +descriptor-checksum-charset+
    "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
  :test #'equal
  :documentation "Bech32 character set used for the checksum symbols themselves.")

(defun %descriptor-polymod (c val)
  "One step of the descriptor checksum LFSR (Core's PolyMod)."
  (let ((c0 (ash c -35))
        (c (logxor (ash (logand c #x7ffffffff) 5) val)))
    (when (logtest c0 1) (setf c (logxor c #xf5dee51989)))
    (when (logtest c0 2) (setf c (logxor c #xa9fdca3312)))
    (when (logtest c0 4) (setf c (logxor c #x1bab10e32d)))
    (when (logtest c0 8) (setf c (logxor c #x3706b1677a)))
    (when (logtest c0 16) (setf c (logxor c #x644d626ffd)))
    c))

(defun descriptor-checksum (string)
  "8-character checksum for descriptor STRING (Core's DescriptorChecksum),
or NIL if STRING contains a character outside the descriptor charset."
  (let ((c 1) (cls 0) (clscount 0))
    (loop for ch across string
          for pos = (position ch +descriptor-input-charset+)
          do (unless pos (return-from descriptor-checksum nil))
             (setf c (%descriptor-polymod c (logand pos 31)))
             (setf cls (+ (* cls 3) (ash pos -5)))
             (when (= (incf clscount) 3)
               (setf c (%descriptor-polymod c cls)
                     cls 0
                     clscount 0)))
    (when (plusp clscount)
      (setf c (%descriptor-polymod c cls)))
    (dotimes (j 8) (setf c (%descriptor-polymod c 0)))
    (setf c (logxor c 1))
    (coerce (loop for j below 8
                  collect (char +descriptor-checksum-charset+
                                (logand (ash c (- (* 5 (- 7 j)))) 31)))
            'string)))

(defun descriptor-add-checksum (body)
  "BODY with its computed #checksum appended (Core's AddChecksum)."
  (format nil "~A#~A" body (descriptor-checksum body)))

(defun %desc-error (fmt &rest args)
  (error 'rpc-error :code +rpc-invalid-address-or-key+
                    :message (apply #'format nil fmt args)))

(defun %check-descriptor-checksum (string require-checksum)
  "Validate and strip an optional trailing '#checksum' (Core's CheckChecksum).
Returns (values body computed-checksum). Signals rpc-error with Core's exact
messages on any checksum problem."
  (let ((parts (uiop:split-string string :separator "#")))
    (when (> (length parts) 2)
      (%desc-error "Multiple '#' symbols"))
    (when (and (= (length parts) 1) require-checksum)
      (%desc-error "Missing checksum"))
    (let ((body (first parts))
          (given (second parts)))
      (when (and given (/= (length given) 8))
        (%desc-error "Expected 8 character checksum, not ~D characters" (length given)))
      (let ((checksum (descriptor-checksum body)))
        (unless checksum
          (%desc-error "Invalid characters in payload"))
        (when (and given (not (equal given checksum)))
          (%desc-error "Provided checksum '~A' does not match computed checksum '~A'"
                       given checksum))
        (values body checksum)))))

;;; --- Expression splitting (script/parsing.cpp Expr/Func) ---

(defun %split-expr (s)
  "Split off the first top-level expression of S (Core's Expr): everything up
to the first ',' ')' or '}' outside of nested ()/{}  groups. Returns
(values expr rest) where REST retains the separator."
  (loop with level = 0
        for i from 0 below (length s)
        for ch = (char s i)
        do (cond ((or (char= ch #\() (char= ch #\{)) (incf level))
                 ((and (plusp level) (or (char= ch #\)) (char= ch #\}))) (decf level))
                 ((and (zerop level) (or (char= ch #\)) (char= ch #\}) (char= ch #\,)))
                  (return (values (subseq s 0 i) (subseq s i)))))
        finally (return (values s ""))))

(defun %func-inner (name s)
  "If S is exactly NAME(...) — first char after NAME is '(' and the last char
is ')' — return the text in between, else NIL (Core's Func). Like Core, no
balance check: the inner text is validated by the recursive parse."
  (let ((n (length name)))
    (when (and (>= (length s) (+ n 2))
               (string= name s :end2 n)
               (char= (char s n) #\()
               (char= (char s (1- (length s))) #\)))
      (subseq s (1+ n) (1- (length s))))))

(defun %with-desc-error-prefix (prefix thunk)
  "Run THUNK, re-signalling any rpc-error with PREFIX prepended to its message
(Core prefixes key-expression errors with e.g. \"pkh(): \" or \"Multi: \")."
  (handler-case (funcall thunk)
    (rpc-error (e)
      (error 'rpc-error :code (rpc-error-code e)
                        :message (concatenate 'string prefix (rpc-error-message e))))))

;;; --- Key expressions ---

(defstruct desc-key
  "One parsed KEY expression in a descriptor (Core's PubkeyProvider chain:
optional origin + const pubkey / WIF key / BIP32 extended key)."
  (origin-fingerprint nil)          ; 4-byte vector, or NIL if no [origin]
  (origin-path nil)                 ; list of uint32 (high bit = hardened)
  (pubkey nil)                      ; const pubkey bytes (33/65), NIL for BIP32 keys
  (xonly-p nil :type boolean)       ; print PUBKEY as 32-byte x-only hex
  ;; musig(K,K,...): the participant key expressions, in the order written.
  ;; Their AGGREGATE is this expression's pubkey — see %MUSIG-KEY-PUBKEY-AT.
  ;; PATH/DERIVE below then apply to the BIP328 synthetic xpub built from it,
  ;; which is why the aggregate lives on the key rather than being a descriptor
  ;; kind: musig() is a KEY expression, usable anywhere tr() takes a key.
  (musig-participants nil)
  (privkey nil)                     ; 32-byte WIF secret, or NIL
  (compressed-p t :type boolean)    ; WIF compression flag
  (extkey nil)                      ; public (neutered) root ext-key, or NIL
  (ext-privkey nil)                 ; private root ext-key if an xprv was given
  (path nil)                        ; derivation path after the key (uint32 list)
  (derive :none)                    ; :none | :unhardened (/*) | :hardened (/*h)
  (apostrophe nil :type boolean))   ; hardened marker style for printing

(defun %xonly-context-p (ctx)
  "T in a context whose keys are 32-byte x-only: the internal key of tr() and
every key inside a taproot script leaf.

Core has ONE context for both (ParseScriptContext::P2TR); we split it into :TR
and :TR-SCRIPT because the two differ in which FUNCTIONS they accept, not in
how they encode keys. Testing (eq ctx :tr) alone made every key in a tree leaf
fail to parse.

Returns T rather than the MEMBER tail: DESC-KEY's XONLY-P slot is declared
BOOLEAN, so a list there is a type error at construction."
  (and (member ctx '(:tr :tr-script)) t))

(defun %hex-string-p (s)
  "Core's IsHex: non-empty, even length, all hex digits."
  (and (plusp (length s))
       (evenp (length s))
       (every (lambda (ch) (digit-char-p ch 16)) s)))

(defun %space-char-p (ch)
  "Core's IsSpace: the six standard C whitespace characters."
  (member ch '(#\Space #\Tab #\Newline #\Return #\Page #.(code-char 11))))

(defun %parse-key-path-num (elem apostrophe-box)
  "Parse one path element (Core's ParseKeyPathNum): decimal uint31 with an
optional trailing ' or h hardened marker. Updates APOSTROPHE-BOX (a cons whose
car tracks the marker style; the last hardened marker seen wins, like Core)."
  (let* ((len (length elem))
         (last (and (plusp len) (char elem (1- len))))
         (hardened (and last (or (char= last #\') (char= last #\h))))
         (num-str (if hardened (subseq elem 0 (1- len)) elem)))
    (when hardened
      (setf (car apostrophe-box) (char= last #\')))
    (let ((num (and (plusp (length num-str))
                    (every #'digit-char-p num-str)
                    (parse-integer num-str))))
      (cond ((or (null num) (> num #xffffffff))
             (%desc-error "Key path value '~A' is not a valid uint32" num-str))
            ((> num #x7fffffff)
             (%desc-error "Key path value ~D is out of range" num)))
      (logior num (if hardened #x80000000 0)))))

(defun %parse-key-path (elems allow-multipath apostrophe-box)
  "Parse the path elements of a key expression (Core's ParseKeyPath, minus
multipath expansion — multipath descriptors are not supported at P0)."
  (loop for elem in elems
        collect (if (and (plusp (length elem))
                         (char= (char elem 0) #\<)
                         (char= (char elem (1- (length elem))) #\>))
                    (if allow-multipath
                        (%desc-error "Multipath descriptors are not supported")
                        (%desc-error "Key path value '~A' specifies multipath in a section where multipath is not allowed" elem))
                    (%parse-key-path-num elem apostrophe-box))))

(defun %wif-network-matches-p (wif-version network)
  "Core DecodeSecret: the WIF's version byte must be NETWORK's SECRET_KEY prefix."
  (= wif-version (bl.chain:chain-params-base58-secret-prefix
                  (bl.chain:find-chain-params network))))

(defun %extkey-valid-for-network-p (k network)
  "Check the version prefix of parsed ext-key K against NETWORK (Core's
DecodeExtKey/DecodeExtPubKey check chainparams EXT_SECRET_KEY/EXT_PUBLIC_KEY),
plus key-material sanity."
  (let ((version (bl.crypto:ext-key-version k))
        (key (bl.crypto:ext-key-key k)))
    (and (let ((params (bl.chain:find-chain-params network)))
           (or (= version (bl.chain:chain-params-ext-secret-prefix params))
               (= version (bl.chain:chain-params-ext-public-prefix params))))
         (if (bl.crypto:ext-key-privatep k)
             (and (zerop (aref key 0))
                  (< 0
                     (reduce (lambda (acc b) (logior (ash acc 8) b))
                             (subseq key 1) :initial-value 0)
                     bl.crypto:+secp256k1-order+))
             (and (member (aref key 0) '(2 3))
                  (bl.crypto:public-key-valid-p key))))))

(defun %parse-desc-key-inner (str ctx network apostrophe-box)
  "Parse a key expression without origin info (Core's ParsePubkeyInner).
CTX is the surrounding context: :top :sh :wsh :wpkh :tr :tr-script :musig.

:MUSIG is a musig() participant. It is deliberately NOT an x-only context —
see %XONLY-CONTEXT-P — because only the aggregate is x-only."
  (let* ((permit-uncompressed (member ctx '(:top :sh)))
         (elems (uiop:split-string str :separator "/"))
         (key-str (first elems))
         (path-elems (rest elems)))
    (when (zerop (length key-str))
      (%desc-error "No key provided"))
    (when (or (%space-char-p (char key-str 0))
              (%space-char-p (char key-str (1- (length key-str)))))
      (%desc-error "Key '~A' is invalid due to whitespace" key-str))
    (when (null path-elems)
      ;; Hex pubkey?
      (when (%hex-string-p key-str)
        (let* ((bytes (bl.crypto:hex-to-bytes key-str))
               (len (length bytes))
               (b0 (and (plusp len) (aref bytes 0)))
               (valid-header (or (and (= len 33) (member b0 '(2 3)))
                                 (and (= len 65) (member b0 '(4 6 7))))))
          (when (and valid-header (member b0 '(6 7)))
            (%desc-error "Hybrid public keys are not allowed"))
          (cond ((and valid-header (bl.crypto:public-key-valid-p bytes))
                 (if (or permit-uncompressed (= len 33))
                     (return-from %parse-desc-key-inner
                       (make-desc-key :pubkey bytes :xonly-p nil))
                     (%desc-error "Uncompressed keys are not allowed")))
                ((and (= len 32) (%xonly-context-p ctx))
                 (let ((full (concatenate '(vector (unsigned-byte 8)) #(2) bytes)))
                   (when (bl.crypto:public-key-valid-p full)
                     (return-from %parse-desc-key-inner
                       (make-desc-key :pubkey full :xonly-p t))))))
          (%desc-error "Pubkey '~A' is invalid" key-str)))
      ;; WIF private key?
      (multiple-value-bind (priv compressed wif-network)
          (bl.crypto:wif-to-private-key key-str)
        (when (and priv (%wif-network-matches-p wif-network network))
          (unless (or permit-uncompressed compressed)
            (%desc-error "Uncompressed keys are not allowed"))
          (return-from %parse-desc-key-inner
            (make-desc-key :pubkey (bl.crypto:derive-public-key
                                    priv :compressed compressed)
                           :xonly-p (%xonly-context-p ctx)
                           :privkey priv
                           :compressed-p compressed)))))
    ;; Extended key (with optional derivation path and ranged terminal).
    (let ((k (bl.crypto:bip32-parse key-str)))
      (unless (and k (%extkey-valid-for-network-p k network))
        (%desc-error "key '~A' is not valid" key-str))
      ;; Ranged terminal is popped before the path is parsed (Core's
      ;; ParseDeriveType runs first, so a later hardened path element's
      ;; marker style overrides the terminal's).
      (let ((derive :none))
        (let ((last (car (last path-elems))))
          (cond ((equal last "*")
                 (setf derive :unhardened
                       path-elems (butlast path-elems)))
                ((or (equal last "*'") (equal last "*h"))
                 (setf derive :hardened
                       (car apostrophe-box) (equal last "*'")
                       path-elems (butlast path-elems)))))
        (let ((path (%parse-key-path path-elems t apostrophe-box)))
          (if (bl.crypto:ext-key-privatep k)
              (make-desc-key :extkey (bl.crypto:bip32-neuter k)
                             :ext-privkey k
                             :path path :derive derive)
              (make-desc-key :extkey k :path path :derive derive)))))))

(defparameter *musig-chaincode-hex*
  "868087ca02a6f974c4598924c36b57762d32cb45717167e300622c7167e38965"
  "DEFPARAMETER and not DEFCONSTANT: SBCL compares a constant's old and new
values with EQL, and two string literals with identical contents are not EQL,
so a DEFCONSTANT string signals DEFCONSTANT-UNEQL on every reload — which
aborts a cold build outright.

BIP328's fixed chaincode for the synthetic xpub built over a MuSig2
aggregate key (Core MUSIG_CHAINCODE, musig.cpp:12). A real xpub's chaincode
carries entropy from its parent; an aggregate key has no parent, so BIP328
fixes one so every implementation derives the same children.")

(defun %musig-synthetic-xpub (aggregate-pubkey network)
  "The BIP328 synthetic xpub over AGGREGATE-PUBKEY: depth 0, zero fingerprint,
child 0, the fixed MuSig2 chaincode (Core CreateMuSig2SyntheticXpub,
musig.cpp:71). It is a derivation ROOT, not a key anyone published."
  (bl.crypto:make-ext-key
   :version (bl.chain:chain-params-ext-public-prefix
             (bl.chain:find-chain-params network))
   :depth 0
   :parent-fingerprint 0
   :child-number 0
   :chain-code (bl.crypto:hex-to-bytes *musig-chaincode-hex*)
   :key (coerce aggregate-pubkey '(simple-array (unsigned-byte 8) (*)))
   :privatep nil))

(defun %parse-musig-key (str ctx network)
  "Parse a musig(KEY,KEY,...) key expression, with an optional /PATH suffix
(Core ParsePubkey's musig branch, descriptor.cpp:1964-2044). Returns a DESC-KEY
whose MUSIG-PARTICIPANTS are the participant expressions in the order written.

Every error message here is Core's, verbatim."
  (unless (%xonly-context-p ctx)
    (%desc-error "musig() is only allowed in tr() and rawtr()"))
  ;; Core splits on ')' keeping the separator, so at most two pieces: the
  ;; musig(...) call and whatever derivation follows it.
  (let ((close (position #\) str)))
    (when (null close)
      (%desc-error "Invalid musig() expression"))
    (let ((call (subseq str 0 (1+ close)))
          (rest (subseq str (1+ close))))
      (when (find #\) rest)
        (%desc-error "Too many ')' in musig() expression"))
      (let ((inner (%func-inner "musig" call)))
        (unless inner
          (%desc-error "Invalid musig() expression"))
        ;; Participants. Core parses them in ParseScriptContext::MUSIG, which
        ;; differs from P2TR only in refusing a nested musig().
        (let ((participants '())
              (remaining inner))
          (loop
            (when (zerop (length remaining)) (return))
            (when participants
              (unless (char= (char remaining 0) #\,)
                (%desc-error "musig(): expected ',', got '~C'" (char remaining 0)))
              (setf remaining (subseq remaining 1)))
            (multiple-value-bind (arg tail) (%split-expr remaining)
              (setf remaining tail)
              (when (%func-inner "musig" arg)
                (%desc-error "musig(): musig() is not allowed in musig()"))
              ;; Core parses participants in ParseScriptContext::MUSIG, NOT
              ;; P2TR (descriptor.cpp:1994). The difference is real: MUSIG is
              ;; not an x-only context, so a participant is written and printed
              ;; as a 33-byte key, and a bare 32-byte one is refused. Only the
              ;; AGGREGATE is ever x-only.
              (push (%with-desc-error-prefix
                     "musig(): "
                     (lambda () (%parse-desc-key arg :musig network)))
                    participants)))
          (setf participants (nreverse participants))
          (unless participants
            (%desc-error "musig(): Must contain key expressions"))
          (let ((key (make-desc-key :musig-participants participants :xonly-p t)))
            (when (plusp (length rest))
              (unless (char= (char rest 0) #\/)
                (%desc-error "musig(): expected ',', got '~C'" (char rest 0)))
              (unless (every (lambda (p)
                               (or (desc-key-extkey p) (desc-key-ext-privkey p)))
                             participants)
                (%desc-error "musig(): derivation requires all participants to be xpubs or xprvs"))
              (when (some #'desc-key-ranged-p participants)
                (%desc-error "musig(): Cannot have ranged participant keys if musig() also has derivation"))
              (let ((elems (rest (uiop:split-string rest :separator "/")))
                    (apostrophe-box (list nil)))
                (let ((last (car (last elems))))
                  (cond ((equal last "*")
                         (setf (desc-key-derive key) :unhardened
                               elems (butlast elems)))
                        ((or (equal last "*'") (equal last "*h"))
                         (%desc-error "musig(): Cannot have hardened child derivation"))))
                (let ((path (%parse-key-path elems t apostrophe-box)))
                  (when (some (lambda (i) (logbitp 31 i)) path)
                    (%desc-error "musig(): cannot have hardened derivation steps"))
                  (setf (desc-key-path key) path))))
            key))))))

(defun %parse-desc-key (str ctx network)
  "Parse a key expression with optional [origin] prefix (Core's ParsePubkey)."
  ;; musig() cannot be nested inside an origin, so it is recognised before the
  ;; ']' split (Core descriptor.cpp:1962).
  (when (and (>= (length str) 6) (string= "musig(" (subseq str 0 6)))
    (return-from %parse-desc-key (%parse-musig-key str ctx network)))
  (let* ((parts (uiop:split-string str :separator "]"))
         (apostrophe-box (list nil)))
    (when (> (length parts) 2)
      (%desc-error "Multiple ']' characters found for a single pubkey"))
    (if (= (length parts) 1)
        (let ((key (%parse-desc-key-inner str ctx network apostrophe-box)))
          (setf (desc-key-apostrophe key) (car apostrophe-box))
          key)
        (let ((origin (first parts))
              (key-part (second parts)))
          (when (or (zerop (length origin))
                    (char/= (char origin 0) #\[))
            (%desc-error "Key origin start '[ character expected but not found, got '~C' instead"
                         (if (zerop (length origin)) #\] (char origin 0))))
          (let* ((origin-elems (uiop:split-string (subseq origin 1) :separator "/"))
                 (fpr-hex (first origin-elems)))
            (unless (= (length fpr-hex) 8)
              (%desc-error "Fingerprint is not 4 bytes (~D characters instead of 8 characters)"
                           (length fpr-hex)))
            (unless (%hex-string-p fpr-hex)
              (%desc-error "Fingerprint '~A' is not hex" fpr-hex))
            (let* ((origin-path (%parse-key-path (rest origin-elems)
                                                 nil apostrophe-box))
                   (key (%parse-desc-key-inner key-part ctx network apostrophe-box)))
              (setf (desc-key-origin-fingerprint key)
                    (bl.crypto:hex-to-bytes fpr-hex)
                    (desc-key-origin-path key) origin-path
                    (desc-key-apostrophe key) (car apostrophe-box))
              key))))))

(defun desc-key-ranged-p (key)
  ;; ⚠️ musig(A/0/*,B) is ranged through its PARTICIPANTS even when the musig()
  ;; expression itself has no /* — Core's MuSigPubkeyProvider::IsRange is
  ;; IsRangedDerivation() || m_ranged_participants (descriptor.cpp:696).
  (or (not (eq (desc-key-derive key) :none))
      (some #'desc-key-ranged-p (desc-key-musig-participants key))))

(defun desc-key-has-privkey-p (key)
  ;; A musig() expression holds no secret of its own; the participants do, and
  ;; a descriptor written with one WIF participant DOES have private keys.
  (and (or (desc-key-privkey key)
           (desc-key-ext-privkey key)
           (some #'desc-key-has-privkey-p (desc-key-musig-participants key)))
       t))

(defun %desc-key-size (key)
  "Serialized size of the pubkey(s) this expression produces (Core GetSize):
33 for BIP32/compressed, 65 for uncompressed constants."
  (if (desc-key-pubkey key) (length (desc-key-pubkey key)) 33))

;;; --- Key expression printing (public form, Core's ToString) ---

(defun format-key-path (path apostrophe)
  (with-output-to-string (s)
    (dolist (i path)
      (format s "/~D" (logand i #x7fffffff))
      (when (logbitp 31 i)
        (write-char (if apostrophe #\' #\h) s)))))

(defun desc-key-string (key &optional (style :public))
  "The canonical public string form of KEY: origins preserved, xprv shown as
xpub, WIF as its hex pubkey, hardened markers in the style used on input.
STYLE :compat forces apostrophe hardened markers (Core's StringType::COMPAT,
used only for DescriptorID stability across versions)."
  ;; musig() prints its participants in the order they were WRITTEN, not the
  ;; sorted order aggregation uses (Core MuSigPubkeyProvider::ToString,
  ;; descriptor.cpp:700). A descriptor that came back re-sorted would not
  ;; round-trip to the string the user handed in.
  (when (desc-key-musig-participants key)
    (return-from desc-key-string
      (format nil "musig(~{~A~^,~})~A~A"
              (mapcar (lambda (p) (desc-key-string p style))
                      (desc-key-musig-participants key))
              (format-key-path (desc-key-path key)
                                (if (eq style :compat) t (desc-key-apostrophe key)))
              (ecase (desc-key-derive key)
                (:none "")
                (:unhardened "/*")
                (:hardened "/*h")))))
  (let ((apostrophe (if (eq style :compat) t (desc-key-apostrophe key))))
    (concatenate
     'string
     (if (desc-key-origin-fingerprint key)
         (format nil "[~A~A]"
                 (bl.crypto:bytes-to-hex (desc-key-origin-fingerprint key))
                 (format-key-path (desc-key-origin-path key) apostrophe))
         "")
     (if (desc-key-pubkey key)
         (bl.crypto:bytes-to-hex
          (if (desc-key-xonly-p key)
              (subseq (desc-key-pubkey key) 1)
              (desc-key-pubkey key)))
         (bl.crypto:bip32-serialize (desc-key-extkey key)))
     (if (desc-key-extkey key)
         (format-key-path (desc-key-path key) apostrophe)
         "")
     (ecase (desc-key-derive key)
       (:none "")
       (:unhardened "/*")
       (:hardened (if apostrophe "/*'" "/*h"))))))

;;; --- Key expression expansion ---

(define-condition descriptor-derivation-error (bitcoin-lisp-error)
  ()
  (:documentation "Expansion needs private keys (hardened derivation from a
public-only descriptor) or hit an invalid BIP32 child."))

(defun %musig-key-pubkey-at (key pos)
  "The pubkey a musig() key expression produces at POS (Core
MuSigPubkeyProvider::GetPubKey, descriptor.cpp:633).

Two shapes, and they aggregate at different moments:

  musig(A,B)/0/*   — the participants are fixed, so the aggregate is fixed too;
                     POS derives from the BIP328 SYNTHETIC XPUB built over it.
  musig(A/0/*,B/0/*) — the participants derive first and the aggregate is a
                     different key at every POS.

Core forbids both at once, which is what makes the two exclusive here.

⚠️ The participants are SORTED before aggregating (descriptor.cpp:648), which is
BIP328's KeySort. BIP327 aggregation is order-sensitive, so without the sort the
same descriptor written two ways would be two different ADDRESSES."
  (let* ((participants (desc-key-musig-participants key))
         (ranged (some #'desc-key-ranged-p participants))
         (pubkeys (mapcar (lambda (p) (%desc-key-pubkey-at p (if ranged pos 0)))
                          participants))
         (aggregate (bl.crypto:musig-aggregate-pubkeys
                     (sort (copy-list pubkeys) #'pubkey-lessp))))
    (unless aggregate
      (error 'descriptor-derivation-error))
    (if (and (null (desc-key-path key)) (eq (desc-key-derive key) :none))
        aggregate
        (let ((root (%musig-synthetic-xpub aggregate
                                           (bl.chain:chain-params-name
                                            (bl.chain:chain-params-of-ext-prefix
                                             (bl.crypto:ext-key-version
                                              (or (desc-key-extkey (first participants))
                                                  (desc-key-ext-privkey (first participants)))))))))
          (let ((k (bl.crypto:bip32-derive-path root (desc-key-path key))))
            (when (eq (desc-key-derive key) :unhardened)
              (setf k (bl.crypto:bip32-derive-child k pos)))
            (bl.crypto:ext-key-key k))))))

(defun %desc-key-pubkey-at (key pos)
  "The pubkey bytes KEY produces at range position POS (Core GetPubKey).
Signals descriptor-derivation-error when hardened derivation is required but
only public key material is available.

Note: %desc-key-pubkey-at-cached below performs the same derivation through
the wallet's persistent xpub cache (Core folds both into one GetPubKey with
optional caches); keep the two derivation paths in sync."
  (when (desc-key-musig-participants key)
    (return-from %desc-key-pubkey-at (%musig-key-pubkey-at key pos)))
  (if (desc-key-pubkey key)
      (desc-key-pubkey key)
      (let* ((hardened (or (eq (desc-key-derive key) :hardened)
                           (some (lambda (i) (logbitp 31 i)) (desc-key-path key))))
             (root (cond ((and hardened (desc-key-ext-privkey key))
                          (desc-key-ext-privkey key))
                         (hardened (error 'descriptor-derivation-error))
                         (t (desc-key-extkey key)))))
        (handler-case
            (let ((k (bl.crypto:bip32-derive-path root (desc-key-path key))))
              (ecase (desc-key-derive key)
                (:none)
                (:unhardened
                 (setf k (bl.crypto:bip32-derive-child k pos)))
                (:hardened
                 (setf k (bl.crypto:bip32-derive-child
                          k (+ pos bl.crypto:+bip32-hardened+)))))
              (bl.crypto:ext-key-public-bytes k))
          (descriptor-derivation-error (e) (error e))
          (error () (error 'descriptor-derivation-error))))))

;;; --- Descriptor AST ---

(defstruct out-desc
  "A parsed output descriptor (Core's DescriptorImpl tree)."
  (kind nil)          ; :addr :raw :pk :pkh :wpkh :combo :multi :sortedmulti :sh :wsh :tr :rawtr
  (keys nil)          ; list of desc-key
  (threshold nil)     ; integer for multi/sortedmulti
  (sub nil)           ; out-desc for sh/wsh — exactly ONE, by grammar
  ;; The taproot script tree of tr(KEY,TREE): a list of (DEPTH . out-desc) in
  ;; Core's parse order, or NIL for a key-path-only tr().
  ;;
  ;; A separate slot rather than making SUB a list, on purpose: a tree is a
  ;; list of (depth . desc), not the single subscript sh()/wsh() has by
  ;; grammar, and conflating them would make every existing OUT-DESC-SUB site
  ;; handle a list it can never receive. %OUT-DESC-CHILDREN is where the two
  ;; become one thing for walkers.
  (tree nil)
  (script nil)        ; script bytes for raw/addr
  (address nil)       ; address string for addr
  ;; The parsed MS-NODE for :miniscript. Its keys are desc-keys, so one node
  ;; serves the whole range: the script is generated per index by handing the
  ;; generator a converter that derives at that index.
  (node nil)
  ;; :PK only — Core's PKDescriptor::m_xonly (descriptor.cpp:1143), set when the
  ;; pk() sits inside a taproot leaf, where it pushes 32 bytes and not 33.
  ;;
  ;; It lives on the DESCRIPTOR and not on the key, which is Core's shape and
  ;; not an accident: DESC-KEY's XONLY-P governs how a key PRINTS, and the two
  ;; disagree for an xpub in a tapscript leaf.  Core prints that leaf as
  ;; pk(xpub.../1/*) -- an xpub, not x-only hex -- while still pushing the
  ;; 32-byte form into the script (descriptor_tests.cpp:640).
  (xonly-script-p nil :type boolean))

(defconstant +max-pubkeys-per-multisig+ 20
  "Core MAX_PUBKEYS_PER_MULTISIG (script/script.h:36): CHECKMULTISIG's limit.")

(defconstant +max-pubkeys-per-multi-a+ 999
  "Core MAX_PUBKEYS_PER_MULTI_A (script/script.h:37). Far above the 20 of a
legacy CHECKMULTISIG because a tapscript CHECKSIGADD chain has no such limit —
the script is only bounded by what a spending transaction can carry.")

(defun %parse-multi-keys (inner ctx network name)
  "Parse \"k,KEY,KEY,...\" for multi/sortedmulti/multi_a/sortedmulti_a.
Returns (values threshold keys kind).

The four differ only in their key ceiling and in two checks specific to
contexts multi_a never appears in, so they share this parser rather than having
a near-copy each (descriptor.cpp:2347-2364 branches the same way). NAME alone
says which is which, so nothing else needs to be passed in."
  (multiple-value-bind (thres-str rest) (%split-expr inner)
    (let* ((kind (cond ((string= name "sortedmulti_a") :sortedmulti-a)
                       ((string= name "multi_a") :multi-a)
                       ((string= name "sortedmulti") :sortedmulti)
                       (t :multi)))
           (multi-a (member kind '(:multi-a :sortedmulti-a)))
           (limit (if multi-a +max-pubkeys-per-multi-a+ +max-pubkeys-per-multisig+))
           (threshold (and (plusp (length thres-str))
                          (every #'digit-char-p thres-str)
                          (parse-integer thres-str))))
      (unless (and threshold (<= threshold #xffffffff))
        (%desc-error "Multi threshold '~A' is not valid" thres-str))
      (let ((keys '()))
        (loop while (plusp (length rest))
              do (unless (char= (char rest 0) #\,)
                   (%desc-error "Multi: expected ',', got '~C'" (char rest 0)))
                 (multiple-value-bind (arg new-rest) (%split-expr (subseq rest 1))
                   (push (%with-desc-error-prefix
                          "Multi: " (lambda () (%parse-desc-key arg ctx network)))
                         keys)
                   (setf rest new-rest)))
        (setf keys (nreverse keys))
        (let ((n (length keys)))
          (when (or (zerop n) (> n limit))
            ;; Core writes "multi_a" for the tapscript form and "multisig" for
            ;; the legacy one (descriptor.cpp:2350,2354); byte-identical text.
            (%desc-error "Cannot have ~D keys in ~A; must have between 1 and ~D keys, inclusive"
                         n (if multi-a "multi_a" "multisig") limit))
          (when (< threshold 1)
            (%desc-error "Multisig threshold cannot be ~D, must be at least 1" threshold))
          (when (> threshold n)
            (%desc-error "Multisig threshold cannot be larger than the number of keys; threshold is ~D but only ~D keys specified"
                         threshold n))
          (when (and (eq ctx :top) (> n 3))
            (%desc-error "Cannot have ~D pubkeys in bare multisig; only at most 3 pubkeys" n))
          (when (eq ctx :sh)
            ;; Limits P2SH multisig to 15 compressed keys (redeemScript <= 520).
            (let ((script-size (+ 3 (reduce #'+ keys
                                            :key (lambda (k) (1+ (%desc-key-size k)))))))
              (when (> script-size 520)
                (%desc-error "P2SH script is too large, ~D bytes is larger than 520 bytes"
                             script-size))))
          (values threshold keys kind))))))

(defconstant +taproot-control-max-node-count+ 128
  "Core TAPROOT_CONTROL_MAX_NODE_COUNT (script/interpreter.h:245): the deepest
a taproot script tree may nest, because the control block carries one 32-byte
merkle path element per level.")

(defun %parse-tr-tree (expr network)
  "Parse the TREE argument of tr(KEY,TREE) into a list of (DEPTH . out-desc) in
Core's parse order (descriptor.cpp:2474-2515).

The algorithm is Core's exactly, and it is worth reading rather than
reinventing: BRANCHES is the path from the root to whatever is being parsed,
one boolean per level — NIL for `we are in the left branch here', T for the
right. An open brace pushes a new left branch, a parsed leaf records the
current depth, a closing brace pops every level whose right branch is finished,
and a comma flips the innermost level from left to right. The whole tree is
consumed exactly when BRANCHES empties again.

Depth is what a leaf needs: TaprootBuilder combines a leaf with its sibling
purely from the depth sequence, so no explicit tree object is ever built."
  (let ((branches '())          ; innermost first; NIL = left, T = right
        (leaves '())
        (rest expr))
    (flet ((take (ch)
             "Consume CH from the front of REST if it is there."
             (when (and (plusp (length rest)) (char= (char rest 0) ch))
               (setf rest (subseq rest 1))
               t)))
      (loop
        ;; Every open brace we can see opens a new left branch.
        (loop while (take #\{)
              do (push nil branches)
                 (when (> (length branches) +taproot-control-max-node-count+)
                   (%desc-error "tr() supports at most ~D nesting levels"
                                +taproot-control-max-node-count+)))
        ;; Exactly one leaf per iteration.
        (multiple-value-bind (leaf remainder) (%split-expr rest)
          (setf rest remainder)
          (push (cons (length branches)
                      (%parse-descriptor-body leaf :tr-script network))
                leaves))
        ;; Close out every level whose right branch we have just finished.
        (loop while (and branches (first branches))
              do (unless (take #\})
                   (%desc-error "tr(): expected '}' after script expression"))
                 (pop branches))
        ;; Still in a left branch: a comma moves us to its right sibling.
        (when (and branches (not (first branches)))
          (unless (take #\,)
            (%desc-error "tr(): expected ',' after script expression"))
          (setf (first branches) t))
        (unless branches (return)))
      (unless (zerop (length rest))
        (%desc-error "tr(): expected ')' after script expression")))
    (nreverse leaves)))

(defun %parse-descriptor-body (body ctx network)
  "Parse one script expression (Core's ParseScript). CTX is :top, :sh, :wsh or
:tr-script — the last being a leaf of a taproot script tree, Core's
ParseScriptContext::P2TR."
  (multiple-value-bind (expr rest) (%split-expr body)
    (unless (zerop (length rest))
      (%desc-error "'~A' is not a valid descriptor" body))
    (macrolet ((with-inner ((var name) &body forms)
                 `(let ((,var (%func-inner ,name expr)))
                    (when ,var ,@forms))))
      ;; pk(KEY) — any of our contexts
      (with-inner (inner "pk")
        (return-from %parse-descriptor-body
          (make-out-desc :kind :pk
                         ;; Core: ParseScript builds PKDescriptor(prov, /*xonly=*/
                         ;; ctx == ParseScriptContext::P2TR) (descriptor.cpp:2286).
                         :xonly-script-p (%xonly-context-p ctx)
                         :keys (list (%with-desc-error-prefix
                                      "pk(): "
                                      (lambda () (%parse-desc-key inner ctx network)))))))
      ;; pkh(KEY)
      ;;
      ;; ⚠️ Core gates the pkh() DESCRIPTOR on TOP/P2SH/P2WSH only
      ;; (descriptor.cpp:2290) — but a taproot leaf then reaches the miniscript
      ;; branch, where `pkh' is a fragment (c:pk_h), so Core accepts
      ;; tr(K,pkh(K2)) after all and hashes the 32-BYTE x-only key. Same script
      ;; either way; we get there without a miniscript parser, and the x-only
      ;; flag is what keeps the leaf hash — and so the ADDRESS — Core's.
      (with-inner (inner "pkh")
        (return-from %parse-descriptor-body
          (make-out-desc :kind :pkh
                         :xonly-script-p (%xonly-context-p ctx)
                         :keys (list (%with-desc-error-prefix
                                      "pkh(): "
                                      (lambda () (%parse-desc-key inner ctx network)))))))
      ;; combo(KEY) — top level only
      (with-inner (inner "combo")
        (unless (eq ctx :top)
          (%desc-error "Can only have combo() at top level"))
        (return-from %parse-descriptor-body
          (make-out-desc :kind :combo
                         :keys (list (%with-desc-error-prefix
                                      "combo(): "
                                      (lambda () (%parse-desc-key inner ctx network)))))))
      ;; multi(k,...) / sortedmulti(k,...) — NOT in a taproot leaf, where
      ;; BIP342 removed CHECKMULTISIG and multi_a() takes over. Core gates
      ;; these on TOP/P2SH/P2WSH and then names the failure explicitly
      ;; (descriptor.cpp:2402) rather than letting it reach the generic
      ;; "is not a valid descriptor function".
      (dolist (name '("multi" "sortedmulti"))
        (with-inner (inner name)
          (when (eq ctx :tr-script)
            (%desc-error
             "Can only have multi/sortedmulti at top level, in sh(), or in wsh()"))
          (multiple-value-bind (threshold keys kind)
              (%parse-multi-keys inner ctx network name)
            (return-from %parse-descriptor-body
              (make-out-desc :kind kind :threshold threshold :keys keys)))))
      ;; multi_a/sortedmulti_a live only in a taproot script leaf — Core gates
      ;; them on ParseScriptContext::P2TR (descriptor.cpp:2320).
      (dolist (name '("multi_a" "sortedmulti_a"))
        (with-inner (inner name)
          (unless (eq ctx :tr-script)
            (%desc-error "Can only have multi_a/sortedmulti_a inside tr()"))
          (multiple-value-bind (threshold keys kind)
              (%parse-multi-keys inner ctx network name)
            (return-from %parse-descriptor-body
              (make-out-desc :kind kind :threshold threshold :keys keys)))))
      ;; wpkh(KEY) — top level or inside sh()
      (with-inner (inner "wpkh")
        (unless (member ctx '(:top :sh))
          (%desc-error "Can only have wpkh() at top level or inside sh()"))
        (return-from %parse-descriptor-body
          (make-out-desc :kind :wpkh
                         :keys (list (%with-desc-error-prefix
                                      "wpkh(): "
                                      (lambda () (%parse-desc-key inner :wpkh network)))))))
      ;; sh(SCRIPT) — top level only
      (with-inner (inner "sh")
        (unless (eq ctx :top)
          (%desc-error "Can only have sh() at top level"))
        (return-from %parse-descriptor-body
          (make-out-desc :kind :sh :sub (%parse-descriptor-body inner :sh network))))
      ;; wsh(SCRIPT) — top level or inside sh()
      (with-inner (inner "wsh")
        (unless (member ctx '(:top :sh))
          (%desc-error "Can only have wsh() at top level or inside sh()"))
        (return-from %parse-descriptor-body
          (make-out-desc :kind :wsh :sub (%parse-descriptor-body inner :wsh network))))
      ;; addr(ADDRESS) — top level only
      (with-inner (inner "addr")
        (unless (eq ctx :top)
          (%desc-error "Can only have addr() at top level"))
        (multiple-value-bind (type script-pubkey)
            (bl.crypto:decode-address inner network)
          (unless type
            (%desc-error "Address is not valid"))
          (return-from %parse-descriptor-body
            (make-out-desc :kind :addr :address inner :script script-pubkey))))
      ;; tr(KEY) or tr(KEY,TREE) — top level only.
      (with-inner (inner "tr")
        (unless (eq ctx :top)
          (%desc-error "Can only have tr at top level"))
        (multiple-value-bind (arg tr-rest) (%split-expr inner)
          (let ((internal (%with-desc-error-prefix
                           "tr(): "
                           (lambda () (%parse-desc-key arg :tr network)))))
            (return-from %parse-descriptor-body
              (if (zerop (length tr-rest))
                  (make-out-desc :kind :tr :keys (list internal))
                  ;; Core expects the comma itself here, and its message for a
                  ;; missing one says `tr:' with no parentheses where every
                  ;; other message in this function says `tr():'
                  ;; (descriptor.cpp:2470-2472). Matched as written.
                  (progn
                    (unless (char= (char tr-rest 0) #\,)
                      (%desc-error "tr: expected ',', got '~C'" (char tr-rest 0)))
                    (make-out-desc :kind :tr :keys (list internal)
                                   :tree (%parse-tr-tree (subseq tr-rest 1) network))))))))
      ;; rawtr(KEY) — top level only
      (with-inner (inner "rawtr")
        (unless (eq ctx :top)
          (%desc-error "Can only have rawtr at top level"))
        (multiple-value-bind (arg rawtr-rest) (%split-expr inner)
          (unless (zerop (length rawtr-rest))
            (%desc-error "rawtr(): only one key expected."))
          (return-from %parse-descriptor-body
            (make-out-desc :kind :rawtr
                           :keys (list (%with-desc-error-prefix
                                        "rawtr(): "
                                        (lambda () (%parse-desc-key arg :tr network))))))))
      ;; raw(HEX) — top level only
      (with-inner (inner "raw")
        (unless (eq ctx :top)
          (%desc-error "Can only have raw() at top level"))
        (unless (%hex-string-p inner)
          (%desc-error "Raw script is not hex"))
        (return-from %parse-descriptor-body
          (make-out-desc :kind :raw
                         :script (bl.crypto:hex-to-bytes inner))))
      ;; Fallthrough. Inside wsh() Core tries miniscript here, which is what
      ;; makes policy descriptors -- timelocked recovery, decaying multisig --
      ;; expressible at all (Core descriptor.cpp ParseScript).
      (case ctx
        (:wsh (return-from %parse-descriptor-body
                (%parse-miniscript-descriptor expr network :p2wsh)))
        ;; A taproot leaf reaches miniscript too (Core gates the branch on
        ;; P2WSH || P2TR, descriptor.cpp:2601), in TAPSCRIPT context: different
        ;; legal fragments, different key serialization, different limits.
        (:tr-script (return-from %parse-descriptor-body
                      (%parse-miniscript-descriptor expr network :tapscript)))
        (:sh (%desc-error "A function is needed within P2SH"))
        (t (%desc-error "'~A' is not a valid descriptor function" expr))))))

(defun %parse-miniscript-descriptor (expr network ms-ctx)
  "Parse EXPR as a miniscript whose key arguments are descriptor key
expressions. Returns an :miniscript out-desc.

MS-CTX is :P2WSH (inside wsh()) or :TAPSCRIPT (a tr() leaf). Miniscript's type
rules, its legal fragments and its resource limits are all stated per context,
which is why the context travels with the node rather than being assumed."
  (let* ((keys '())
         (node (handler-case
                   (let ((bl.val:*ms-key-parser*
                           (lambda (text)
                             (let ((key (%with-desc-error-prefix
                                         "miniscript: "
                                         (lambda ()
                                           ;; The KEY context follows the script
                                           ;; context: a tapscript leaf accepts
                                           ;; 32-byte x-only keys, wsh() does not.
                                           (%parse-desc-key
                                            text
                                            (if (eq ms-ctx :tapscript) :tr :wsh)
                                            network)))))
                               (push key keys)
                               key))))
                     (bl.val:ms-parse expr :ctx ms-ctx))
                 ;; Not a miniscript expression at all -- a bare pubkey, say.
                 ;; Core only reports a miniscript error when the expression
                 ;; PARSED and then failed its rules (descriptor.cpp:2600);
                 ;; an unparseable one falls through to the generic message,
                 ;; which is far more useful for the common typo.
                 (bl.val:miniscript-parse-error ()
                   (%desc-error "A function is needed within ~A"
                                (if (eq ms-ctx :tapscript) "P2TR" "P2WSH"))))))
    (%check-miniscript-sane node)
    (make-out-desc :kind :miniscript :node node :keys (nreverse keys))))

(defun %check-miniscript-sane (node)
  "Core's acceptance gate for a miniscript descriptor (descriptor.cpp:2604-2628):
refuse unless `IsSane() && !IsNotSatisfiable()', and report which property
failed, naming the first insane subexpression.

We checked only IsValid and IsValidTopLevel, which is two of the seven things
IsSane composes. The other five were reachable but unenforced, so
importdescriptors accepted policies Core refuses: malleable ones (a third party
can rewrite the witness and change the txid), ones satisfiable with NO
signature at all, ones mixing block- and time-based locks in a single spend
path (which does not mean what its author thinks), ones repeating a key, and
ones whose satisfaction cannot fit the P2WSH resource limits.

The branch ORDER is Core's and is load-bearing: malleability is reported ahead
of the missing signature, and NeedsSignature is only ever blamed on the TOP
node (`insane_node == &node.value()'), because a sub that needs no signature is
fine as long as the whole expression does."
  (let ((v (bl.val:ms-node-sane-p node))
        (satisfiable (not (bl.val:ms-node-not-satisfiable-p node))))
    (when (and v satisfiable)
      (return-from %check-miniscript-sane node))
    (let* ((sub (bl.val:ms-find-insane-sub node))
           (blamed (or sub node))
           (text (bl.val:ms-node-to-string
                  blamed (lambda (k) (desc-key-string k :public)))))
      (%desc-error
       "~A"
       (concatenate
        'string text
        (cond
          ((not (bl.val:ms-node-valid-p blamed)) " is invalid")
          ((not v)
           (concatenate
            'string " is not sane"
            (cond
              ((not (bl.val:ms-node-non-malleable-p blamed))
               ": malleable witnesses exist")
              ((and (null sub)
                    (not (bl.val:ms-node-needs-signature-p blamed)))
               ": witnesses without signature exist")
              ((bl.val:ms-node-timelock-mix-p blamed)
               ": contains mixes of timelocks expressed in blocks and seconds")
              ((bl.val:ms-node-duplicate-keys-p blamed)
               ": contains duplicate public keys")
              ((not (bl.val:ms-node-valid-satisfactions-p blamed))
               ": needs witnesses that may exceed resource limits")
              (t ""))))
          (t " is not satisfiable")))))))

;;; --- Multipath descriptors, BIP389 (Core descriptor.cpp:1802-1851) ---
;;;
;;; `wpkh(xpub.../<0;1>/*)` is ONE string that means TWO descriptors — the
;;; receive chain and the change chain — and it is how Sparrow, Ledger Live,
;;; BlueWallet, BDK and modern Core exports write a wallet. A node that cannot
;;; read it cannot import from any of them.
;;;
;;; Core expands the string into N descriptors and parses each normally
;;; (Parse() returns a vector). Expanding here rather than threading N paths
;;; through the key structures keeps every downstream consumer — derivation,
;;; signing, printing, checksums — working on exactly the descriptors it
;;; already understands.

(defun %multipath-substitutes (elem)
  "The values inside a `<a;b;...>` path element, validated as Core validates
them (descriptor.cpp:1813-1833). Signals with Core's messages."
  (let* ((inner (subseq elem 1 (1- (length elem))))
         (parts (uiop:split-string inner :separator ";")))
    (when (< (length parts) 2)
      (%desc-error "Multipath key path specifiers must have at least two items"))
    (let ((seen '())
          (box (list nil)))
      (dolist (part parts (nreverse seen))
        ;; Parse for VALIDATION only — the substituted string keeps the
        ;; original spelling, so a hardened marker survives as written.
        (let ((num (%parse-key-path-num part box)))
          (when (member num seen :key #'car)
            (%desc-error "Duplicated key path value ~D in multipath specifier"
                         (logand num #x7FFFFFFF)))
          (push (cons num part) seen))))))

(defun expand-multipath-descriptor (string)
  "STRING expanded into the descriptors it denotes: a list of one for an
ordinary descriptor, or of N for a multipath one (Core Parse, which returns a
vector of descriptors, descriptor.cpp:1802-1851).

Any checksum is dropped, because it covered the multipath form and not the
expansions; each result is unchecksummed and the caller adds one if it needs to.

Core allows at most ONE multipath specifier per descriptor and requires at
least two, distinct, values — all three of those errors are its own text."
  (let* ((hash (position #\# string))
         (body (if hash (subseq string 0 hash) string))
         (start (position #\< body)))
    (if start
        (let ((end (position #\> body :start start)))
          (unless end
            (%desc-error "Key path value '~A' specifies multipath in a section where multipath is not allowed"
                         (subseq body start)))
          (when (position #\< body :start (1+ end))
            (%desc-error "Multiple multipath key path specifiers found"))
          (let ((prefix (subseq body 0 start))
                (suffix (subseq body (1+ end)))
                (elem (subseq body start (1+ end))))
            (mapcar (lambda (sub)
                      (concatenate 'string prefix (cdr sub) suffix))
                    (%multipath-substitutes elem))))
        (list string))))

(defun parse-descriptor (string network &key require-checksum)
  "Parse descriptor STRING (Core's Parse). Returns (values out-desc
input-checksum) where INPUT-CHECKSUM is the checksum computed over the input
body (private keys included, as getdescriptorinfo reports it). Signals
rpc-error with Core's messages on any problem."
  (multiple-value-bind (body checksum)
      (%check-descriptor-checksum string require-checksum)
    (values (%parse-descriptor-body body :top network) checksum)))

;;; --- Descriptor predicates + printing ---

(defun %out-desc-children (desc)
  "Every sub-descriptor of DESC: the single subscript of sh()/wsh(), or the
leaves of a tr() script tree.

One accessor so the walkers below cannot disagree about what a child is —
which is exactly how tr(KEY,TREE) would otherwise slip past every predicate
that only knew about SUB."
  (cond ((out-desc-tree desc) (mapcar #'cdr (out-desc-tree desc)))
        ((out-desc-sub desc) (list (out-desc-sub desc)))))

(defun out-desc-ranged-p (desc)
  (or (some #'desc-key-ranged-p (out-desc-keys desc))
      (some #'out-desc-ranged-p (%out-desc-children desc))))

(defun out-desc-solvable-p (desc)
  "Core IsSolvable: false for addr()/raw(), true for everything we can expand.

Recursing through %OUT-DESC-CHILDREN rather than listing the container kinds:
EVERY over no children is already T, so a leaf answers T without a special
case, and a container added later cannot report itself solvable while holding
an addr()/raw() child."
  (if (member (out-desc-kind desc) '(:addr :raw))
      nil
      (every #'out-desc-solvable-p (%out-desc-children desc))))

(defun out-desc-has-privkeys-p (desc)
  "Whether the descriptor contained at least one private key (WIF or xprv);
Core getdescriptorinfo's hasprivatekeys (provider.keys non-empty)."
  (or (some #'desc-key-has-privkey-p (out-desc-keys desc))
      (some #'out-desc-has-privkeys-p (%out-desc-children desc))))

(defun %out-desc-string-walk (desc keyfn)
  "The descriptor body of DESC with each key expression rendered by
(KEYFN desc-key) — the one structural walker behind the public/compat,
private, and normalized string forms (Core's ToStringHelper, parameterized
by StringType, descriptor.cpp:909)."
  (ecase (out-desc-kind desc)
    (:addr (format nil "addr(~A)" (out-desc-address desc)))
    (:raw (format nil "raw(~A)" (bl.crypto:bytes-to-hex (out-desc-script desc))))
    ((:pk :pkh :wpkh :combo :rawtr)
     (format nil "~(~A~)(~A)" (out-desc-kind desc)
             (funcall keyfn (first (out-desc-keys desc)))))
    (:tr
     (let ((internal (funcall keyfn (first (out-desc-keys desc)))))
       (if (out-desc-tree desc)
           (format nil "tr(~A,~A)" internal
                   (tr-tree-string (out-desc-tree desc)
                                   (lambda (leaf)
                                     (%out-desc-string-walk leaf keyfn))))
           (format nil "tr(~A)" internal))))
    ((:multi :sortedmulti :multi-a :sortedmulti-a)
     ;; The kind keywords carry a hyphen where the descriptor name has an
     ;; underscore, so the name is repaired before ~( ~) lowercases it.
     (format nil "~(~A~)(~D~{,~A~})"
             (substitute #\_ #\- (symbol-name (out-desc-kind desc)))
             (out-desc-threshold desc)
             (mapcar keyfn (out-desc-keys desc))))
    ((:sh :wsh)
     (format nil "~(~A~)(~A)" (out-desc-kind desc)
             (%out-desc-string-walk (out-desc-sub desc) keyfn)))
    ;; The miniscript renders itself, with each key expression rendered by the
    ;; same KEYFN the rest of the walk uses — so a policy descriptor's public,
    ;; private and normalized forms differ in exactly the way every other
    ;; descriptor's do.
    (:miniscript
     (bl.val:ms-node-to-string (out-desc-node desc) keyfn))))

(defun tr-tree-string (tree render-leaf)
  "Re-emit a taproot script tree's braces from its depth sequence — the inverse
of %PARSE-TR-TREE, transcribed from Core's TRDescriptor::ToStringSubScriptHelper
(descriptor.cpp:1492-1507). RENDER-LEAF turns one leaf out-desc into a string;
NIL from it means the whole tree cannot be rendered.

⚠️ Note the two asymmetries, which are what make a single leaf print as
`tr(KEY,pk(A))' with no braces at all: the FIRST push emits no `{'
(`if (path.size())'), and the LAST pop emits no `}' (`if (path.size() > 1)').

Parameterized by the leaf renderer rather than duplicated, because the brace
reconstruction is the error-prone half and the descriptor printer and the
wallet's InferDescriptor need the same one over different leaf renderings."
  (let ((path '())          ; innermost first, mirroring Core's vector back()
        (n 0)               ; (length path), maintained rather than recomputed
        (out (make-string-output-stream)))
    (loop for (depth . leaf) in tree
          for first = t then nil
          do (unless first (write-char #\, out))
             (loop while (<= n depth)
                   do (when path (write-char #\{ out))
                      (push nil path)
                      (incf n))
             (let ((text (funcall render-leaf leaf)))
               (unless text (return-from tr-tree-string nil))
               (write-string text out))
             (loop while (and path (first path))
                   do (when (> n 1) (write-char #\} out))
                      (pop path)
                      (decf n))
             (when path (setf (first path) t)))
    (get-output-stream-string out)))

(defun out-desc-string (desc &optional (style :public))
  "The canonical public descriptor body (no checksum): private keys replaced
by their public forms, origins and hardened-marker style preserved. STYLE
:compat forces apostrophe hardened markers (Core StringType::COMPAT)."
  (%out-desc-string-walk desc (lambda (k) (desc-key-string k style))))

(defun descriptor-id (desc)
  "The 32-byte descriptor ID: single SHA256 over the checksummed public string
in COMPAT format — apostrophe hardened markers regardless of input style
(Core DescriptorID, descriptor.cpp:2902: desc.ToString(/*compat_format=*/true)
then CSHA256 over the string). Keys wallet records for this descriptor."
  (bl.crypto:sha256
   (flexi-streams:string-to-octets
    (descriptor-add-checksum (out-desc-string desc :compat))
    :external-format :ascii)))

;;; --- Key expression enumeration (Core's m_expr_index) ---

(defun out-desc-ordered-keys (desc)
  "All desc-keys of DESC in parse order — the order Core assigns m_expr_index
to PubkeyProviders: a node's own keys first, then each child's in turn.

⚠️ tr(KEY,TREE) is the one shape carrying BOTH its own key and subexpressions,
and the own-keys-then-children order is what makes it come out right. This used
to be `keys OR the subscript's keys', which silently dropped every tree leaf.
Consumers that slice this list positionally depend on the order — see
%INFER-DESC-BODY."
  (append (out-desc-keys desc)
          (loop for child in (%out-desc-children desc)
                append (out-desc-ordered-keys child))))

(defun out-desc-key-indexes (desc)
  "EQ map from each desc-key of DESC to its key expression index."
  (let ((table (make-hash-table :test 'eq)))
    (loop for key in (out-desc-ordered-keys desc)
          for i from 0
          do (setf (gethash key table) i))
    table))

;;; --- Script construction ---

(defun %script-p2pk (pubkey)
  (concatenate '(vector (unsigned-byte 8))
               (vector (length pubkey)) pubkey #(#xac)))

(defun %script-p2pkh (pubkey)
  (concatenate '(vector (unsigned-byte 8))
               #(#x76 #xa9 #x14) (bl.crypto:hash160 pubkey) #(#x88 #xac)))

(defun %script-p2wpkh (pubkey)
  (concatenate '(vector (unsigned-byte 8))
               #(#x00 #x14) (bl.crypto:hash160 pubkey)))

(defun %script-p2sh (redeem-script)
  (concatenate '(vector (unsigned-byte 8))
               #(#xa9 #x14) (bl.crypto:hash160 redeem-script) #(#x87)))

(defun %script-p2wsh (witness-script)
  (concatenate '(vector (unsigned-byte 8))
               #(#x00 #x20) (bl.crypto:sha256 witness-script)))

(defun %script-p2tr (output-key32)
  (concatenate '(vector (unsigned-byte 8)) #(#x51 #x20) output-key32))

(defun %script-num (n)
  "The push a script builds for the positive integer N with `CScript << n'
(Core CScript::push_int64, script.h:433): OP_1..OP_16 for 1..16, otherwise a
minimal-length little-endian push of CScriptNum::serialize.

⚠️ The SIGN BYTE is what a one-byte-per-number shortcut gets wrong, and it is
reachable: multi_a allows a threshold up to MAX_PUBKEYS_PER_MULTI_A, and
CScriptNum::serialize(128) is 0x80 0x00 -- the trailing zero marks it positive,
because 0x80 alone reads as negative zero. Above 255 a single byte cannot hold
the value at all. Either way the leaf script differs from Core's, which means a
different leaf hash, a different merkle root and a different ADDRESS."
  (if (<= 1 n 16)
      (vector (+ #x50 n))
      (let ((bytes (loop with v = n
                         while (plusp v)
                         collect (logand v #xff)
                         do (setf v (ash v -8)))))
        (when (logbitp 7 (car (last bytes)))
          (setf bytes (append bytes (list 0))))
        (coerce (cons (length bytes) bytes)
                '(vector (unsigned-byte 8))))))

(defun pubkey-lessp (a b)
  "Lexicographic pubkey compare (CPubKey operator<; BIP67 sort order)."
  (loop for i below (min (length a) (length b))
        do (cond ((< (aref a i) (aref b i)) (return t))
                 ((> (aref a i) (aref b i)) (return nil)))
        finally (return (< (length a) (length b)))))

(defun %script-multisig (threshold pubkeys)
  (apply #'concatenate '(vector (unsigned-byte 8))
         (%script-num threshold)
         (append (mapcar (lambda (k)
                           (concatenate '(vector (unsigned-byte 8))
                                        (vector (length k)) k))
                         pubkeys)
                 (list (%script-num (length pubkeys)) #(#xae)))))

(defun key-xonly-bytes (pubkey)
  "The 32-byte x-only form of a 33-byte compressed pubkey."
  (subseq pubkey 1 33))

(defun %desc-script-pubkey (desc keyfn)
  "The pubkey DESC's script should embed: 32-byte x-only inside a taproot leaf
\(Core's m_xonly), the full 33/65-byte form everywhere else."
  (let ((pubkey (funcall keyfn (first (out-desc-keys desc)))))
    (if (out-desc-xonly-script-p desc)
        (key-xonly-bytes pubkey)
        pubkey)))

(defun %script-multi-a (threshold xkeys)
  "The tapscript k-of-n script (Core MultiADescriptor::MakeScripts,
descriptor.cpp:1325-1337):

    <x0> OP_CHECKSIG  (<xi> OP_CHECKSIGADD)*  <k> OP_NUMEQUAL

A CHECKSIGADD chain rather than CHECKMULTISIG, which BIP342 removed. Each key
is pushed x-only, so 32 bytes and not 33."
  (apply #'concatenate '(vector (unsigned-byte 8))
         (concatenate '(vector (unsigned-byte 8))
                      (vector 32) (first xkeys) (vector #xac))   ; OP_CHECKSIG
         (append (mapcar (lambda (k)
                           (concatenate '(vector (unsigned-byte 8))
                                        (vector 32) k (vector #xba))) ; OP_CHECKSIGADD
                         (rest xkeys))
                 (list (%script-num threshold) #(#x9c)))))       ; OP_NUMEQUAL

(defconstant +tapleaf-version-tapscript+ #xc0
  "BIP342's leaf version. The only one a descriptor can express.")

(defun %tap-combine (a b)
  "Core TaprootBuilder::Combine (script/signingprovider.cpp:352). A and B are
(HASH . LEAVES) where LEAVES is a list of (INDEX . PATH-SO-FAR).

Each side's leaves gain the OTHER side's hash: that sibling is precisely the
next element of their merkle path. PATH is accumulated by PUSH, so it comes out
outermost-first and is reversed once at the end rather than appended to L
times."
  (flet ((extend (leaves sibling)
           (loop for (index . path) in leaves
                 collect (cons index (cons sibling path)))))
    (cons (bl.crypto:tap-branch-hash (car a) (car b))
          (append (extend (cdr a) (car b))
                  (extend (cdr b) (car a))))))

(defun %taproot-tree (leaf-hashes &optional track-paths)
  "(values MERKLE-ROOT BRANCHES) for the taproot script tree described by
LEAF-HASHES — a list of (DEPTH . 32-byte tapleaf hash) in the order tr()'s tree
argument names them.

BRANCHES is one merkle path per leaf, in the same order: the sibling hashes
from the leaf upwards, which is exactly what a control block carries after its
internal key. It is NIL unless TRACK-PATHS — deriving an ADDRESS needs only the
root, and %TR-OUTPUT-KEY sits on the keypool derivation path, which walks a
whole range. With tracking off the per-leaf lists stay empty and %TAP-COMBINE's
loops over them cost nothing, so there is still one implementation of the fold.

Core's TaprootBuilder::Insert (script/signingprovider.cpp:384), and it is worth
seeing why no tree object is needed: M-BRANCH holds at most one pending node per
depth. Inserting at depth D combines with whatever is already pending at D —
that is D's left sibling, which by the parse order must already be there — and
the combined node moves up one level, repeating while a sibling waits. A
well-formed tree therefore ends with exactly one pending node at depth 0.

⚠️ TAP-BRANCH-HASH sorts each pair lexicographically (BIP341), so the ROOT does
not depend on left/right — but a PATH does. The path is built by the combine
step from the actual sibling, never re-derived from the root, which is what
keeps a leaf out of its own path."
  (let ((branch (make-array (1+ (reduce #'max leaf-hashes :key #'car :initial-value 0))
                            :initial-element nil))
        (size 0)
        (valid t))
    (loop for entry in leaf-hashes
          for index from 0
          while valid
          do (let ((depth (car entry))
                   (node (cons (cdr entry)
                               (when track-paths (list (cons index '()))))))
               ;; Core's first guard: a leaf cannot be inserted ABOVE an
               ;; unfinished deeper branch, because the Add() calls would then
               ;; not be a DFS traversal (signingprovider.cpp:390).
               (if (< (1+ depth) size)
                   (setf valid nil)
                   (progn
                     (loop while (and valid (> size depth) (aref branch depth))
                           do (setf node (%tap-combine node (aref branch depth))
                                    (aref branch depth) nil)
                              (decf size)
                              ;; Nothing propagates above the root. Core sets
                              ;; m_valid here and its `if (m_valid)' then skips
                              ;; the store; dropping out of the loop and storing
                              ;; anyway would leave exactly one node at depth 0
                              ;; and pass the completeness test below, so
                              ;; e.g. depths (1 1 0) would silently build a tree
                              ;; Core refuses.
                              (if (zerop depth)
                                  (setf valid nil)
                                  (decf depth)))
                     (when valid
                       (setf (aref branch depth) node
                             size (max size (1+ depth))))))))
    ;; Core asserts ValidDepths before building (descriptor.cpp:2517); reaching
    ;; here with anything but a single pending node at depth 0 means the depth
    ;; sequence did not describe a tree.
    (unless (and valid (= size 1) (aref branch 0))
      (%desc-error "tr(): malformed script tree"))
    (let ((root (aref branch 0)))
      (values (car root)
              (when track-paths
                (let ((by-index (cdr root)))
                  (loop for i from 0 below (length leaf-hashes)
                        collect (reverse (cdr (assoc i by-index))))))))))

(defun %taproot-control-block (leaf-version parity internal-key path)
  "The BIP341 control block for one leaf (Core TaprootBuilder::GetSpendData,
script/signingprovider.cpp:481): leaf version with the output key's parity in
its low bit, the 32-byte internal key, then the merkle path leaf-upwards."
  (apply #'concatenate '(vector (unsigned-byte 8))
         (vector (logior leaf-version parity))
         internal-key
         path))

(defun tr-leaf-satisfaction (leaf pubkeys sigfn)
  "The witness elements that satisfy the taproot script LEAF, or NIL when the
available keys cannot satisfy it.

PUBKEYS is the leaf's 33-byte pubkeys in LEAF's own key-expression order (what
the expansion produced for this range index). SIGFN is called with one 32-byte
x-only key and returns its 64/65-byte Schnorr signature, or NIL when that key is
not available for signing.

⚠️ Core reaches every leaf through miniscript::Satisfy on the leaf SCRIPT
(sign.cpp:529-540). We have no tapscript miniscript, so the leaf kinds our
tr() grammar can actually build are satisfied directly here, and anything else
reports UNSATISFIABLE rather than guessing at a witness.

⚠️ The multi_a stack is REVERSED against key order, and it is worth deriving
rather than trusting: the script is
    <x1> CHECKSIG <x2> CHECKSIGADD ... <xn> CHECKSIGADD <k> NUMEQUAL
and OP_CHECKSIG/OP_CHECKSIGADD each pop the signature from the TOP of the
stack. The witness elements go on bottom-first, so x1 -- checked first --
consumes the LAST element. A stack in key order spends nothing and, if it did,
would spend it with the wrong signatures against the wrong keys."
  (let ((xonly (mapcar #'key-xonly-bytes pubkeys)))
    ;; CASE and not ECASE: an unknown leaf kind is UNSATISFIABLE, which the
    ;; signer already reports, and not a type error surfacing as RPC -32603
    ;; in the middle of signing. This is also the single place the satisfiable
    ;; kinds are named -- a second list to keep in step is a leaf that becomes
    ;; either silently unspendable or an unhandled ECASE.
    (case (out-desc-kind leaf)
      ;; <x> CHECKSIG
      (:pk (let ((sig (funcall sigfn (first xonly))))
             (when sig (list sig))))
      ;; DUP HASH160 <hash160(x)> EQUALVERIFY CHECKSIG.
      ;;
      ;; ⚠️ The key goes on TOP, i.e. LAST in the element list: DUP acts on the
      ;; stack top, so the script reads the key before the signature. Witness
      ;; elements are pushed bottom-first, so "revealed key, then signature"
      ;; reads the right way round in prose and the wrong way round here.
      (:pkh (let ((sig (funcall sigfn (first xonly))))
              (when sig (list sig (first xonly)))))
      ((:multi-a :sortedmulti-a)
       (let* ((keys (if (eq (out-desc-kind leaf) :sortedmulti-a)
                        (sort (copy-list xonly) #'pubkey-lessp)
                        xonly))
              (threshold (out-desc-threshold leaf))
              (empty (make-array 0 :element-type '(unsigned-byte 8)))
              (taken 0)
              (elements
                (loop for key in keys
                      collect (let ((sig (and (< taken threshold)
                                              (funcall sigfn key))))
                                (cond (sig (incf taken) sig)
                                      (t empty))))))
         ;; Exactly THRESHOLD signatures: OP_NUMEQUAL tests equality, so an
         ;; extra valid signature fails the script just as a missing one does.
         (when (= taken threshold)
           (reverse elements)))))))

(defun %tr-tree-parts (desc pos keyfn track-paths)
  "The shared taproot computation behind %TR-OUTPUT-KEY and TR-SPEND-DATA, as
(values OUTPUT-KEY PARITY INTERNAL-KEY LEAVES PATHS), where LEAVES is one
(SCRIPT . LEAF-HASH) per leaf in tr()'s parse order. One walk of the tree, so
the address a descriptor DERIVES and the address its spend data is built for
can never disagree, and the leaf hashes the tree was folded from are handed
back rather than recomputed by the signer.

PATHS is NIL unless TRACK-PATHS — see %TAPROOT-TREE."
  (let* ((internal (key-xonly-bytes (funcall keyfn (first (out-desc-keys desc)))))
         (leaves (loop for entry in (out-desc-tree desc)
                       for script = (first (%out-desc-expand-1 (cdr entry) pos keyfn))
                       collect (cons script
                                     (bl.crypto:tap-leaf-hash
                                      +tapleaf-version-tapscript+ script))))
         (leaf-hashes (loop for entry in (out-desc-tree desc)
                            for leaf in leaves
                            collect (cons (car entry) (cdr leaf)))))
    (multiple-value-bind (root paths)
        (if leaf-hashes
            (%taproot-tree leaf-hashes track-paths)
            (values nil nil))
      (multiple-value-bind (output-key parity)
          (bl.crypto:tweak-xonly-pubkey
           internal (bl.crypto:tap-tweak-hash internal root))
        (unless output-key
          (error 'descriptor-derivation-error))
        (values output-key parity internal leaves paths)))))

(defun tr-spend-data (desc pos keyfn)
  "What it takes to SPEND the tr() descriptor DESC at range position POS
(Core's TaprootSpendData, script/signingprovider.h:31), as two values:

  OUTPUT-KEY  the 32-byte tweaked key, i.e. the witness program;
  LEAVES      one (SCRIPT LEAF-HASH CONTROL-BLOCK) per leaf, in tr()'s parse
              order; empty when there is no tree.

The output key's Y PARITY goes into each control block's first byte and is not
derivable from OUTPUT-KEY, which is x-only — it is consumed here rather than
returned, since no caller needs it on its own."
  (multiple-value-bind (output-key parity internal leaves paths)
      (%tr-tree-parts desc pos keyfn t)
    (values output-key
            (loop for (script . leaf-hash) in leaves
                  for path in paths
                  collect (list script leaf-hash
                                (%taproot-control-block
                                 +tapleaf-version-tapscript+ parity
                                 internal path))))))

(defun %tr-output-key (desc pos keyfn)
  "The 32-byte taproot output key for a tr() descriptor: the internal key
tweaked by the tree's merkle root, or by nothing at all when the descriptor is
key-path only."
  (values (%tr-tree-parts desc pos keyfn nil)))

(defun %out-desc-expand-1 (desc pos keyfn)
  "Expand DESC at range position POS into its scriptPubKey list (Core Expand),
resolving each key expression's pubkey via (KEYFN desc-key)."
  (ecase (out-desc-kind desc)
    ((:addr :raw) (list (out-desc-script desc)))
    ;; Core's PKDescriptor::MakeScripts branches on m_xonly: inside a taproot
    ;; leaf the key is the 32-byte x-only form, everywhere else the full
    ;; 33/65-byte one. pkh() reaches the same split through miniscript's
    ;; c:pk_h fragment, so both go through %DESC-SCRIPT-PUBKEY.
    (:pk (list (%script-p2pk (%desc-script-pubkey desc keyfn))))
    (:pkh (list (%script-p2pkh (%desc-script-pubkey desc keyfn))))
    (:wpkh (list (%script-p2wpkh (funcall keyfn (first (out-desc-keys desc))))))
    (:combo
     (let ((key (funcall keyfn (first (out-desc-keys desc)))))
       (append (list (%script-p2pk key)
                     (%script-p2pkh key))
               (when (= (length key) 33)
                 (list (%script-p2wpkh key)
                       (%script-p2sh (%script-p2wpkh key)))))))
    ((:multi :sortedmulti)
     (let ((pubkeys (mapcar keyfn (out-desc-keys desc))))
       (when (eq (out-desc-kind desc) :sortedmulti)
         (setf pubkeys (sort (copy-list pubkeys) #'pubkey-lessp)))
       (list (%script-multisig (out-desc-threshold desc) pubkeys))))
    (:sh (list (%script-p2sh (first (%out-desc-expand-1 (out-desc-sub desc) pos keyfn)))))
    (:wsh (list (%script-p2wsh (first (%out-desc-expand-1 (out-desc-sub desc) pos keyfn)))))
    (:tr (list (%script-p2tr (%tr-output-key desc pos keyfn))))
    ;; A tapscript leaf: <x0> CHECKSIG (<xi> CHECKSIGADD)* <k> NUMEQUAL
    ;; (descriptor.cpp:1325-1337). sortedmulti_a sorts the X-ONLY keys, after
    ;; the conversion, not the 33-byte forms.
    ((:multi-a :sortedmulti-a)
     (let ((xkeys (mapcar (lambda (k) (key-xonly-bytes (funcall keyfn k)))
                          (out-desc-keys desc))))
       (when (eq (out-desc-kind desc) :sortedmulti-a)
         (setf xkeys (sort (copy-list xkeys) #'pubkey-lessp)))
       (list (%script-multi-a (out-desc-threshold desc) xkeys))))
    (:rawtr
     (list (%script-p2tr (key-xonly-bytes
                          (funcall keyfn (first (out-desc-keys desc)))))))
    (:miniscript
     ;; One parsed node, a different script per range index: the converter is
     ;; what turns each key expression into the pubkey for THIS position.
     (list (bl.val:ms-node-script
            (out-desc-node desc) nil keyfn)))))

(defun %out-desc-expand-uncached (desc pos)
  "Expand DESC at range position POS into its scriptPubKey list (Core Expand)."
  (%out-desc-expand-1 desc pos (lambda (k) (%desc-key-pubkey-at k pos))))

;;; --- Expansion cache (Core DescriptorCache intent: repeat expansion of a
;;; ranged descriptor at the same index must not redo EC derivation; a bounded
;;; in-memory map at P0, persisted with the wallet at P1) ---

(defvar *descriptor-cache-lock* (bt:make-lock "descriptor-cache"))
(defvar *descriptor-expansion-cache* (make-hash-table :test 'equal)
  "(public-descriptor-body . index) -> list of scriptPubKeys.")
(defparameter *descriptor-cache-max-entries* 100000)

(defun %desc-key-needs-missing-privkey-p (key)
  ;; musig() itself cannot derive hardened (Core rejects it at parse), but its
  ;; PARTICIPANTS are ordinary key expressions and can.
  (or (some #'%desc-key-needs-missing-privkey-p (desc-key-musig-participants key))
      (and (desc-key-extkey key)
           (not (desc-key-ext-privkey key))
           (or (eq (desc-key-derive key) :hardened)
               (some (lambda (i) (logbitp 31 i)) (desc-key-path key))))))

(defun %out-desc-needs-missing-privkey-p (desc)
  (or (some #'%desc-key-needs-missing-privkey-p (out-desc-keys desc))
      (some #'%out-desc-needs-missing-privkey-p (%out-desc-children desc))))

(defun out-desc-expand (desc pos)
  "Expand DESC at POS, with caching keyed on the canonical public body (which
uniquely determines the scripts). Signals descriptor-derivation-error when
private keys would be required — checked before the cache, so a cache entry
warmed by the private descriptor never masks the error Core reports for its
public-only form."
  (when (%out-desc-needs-missing-privkey-p desc)
    (error 'descriptor-derivation-error))
  (let ((key (cons (out-desc-string desc) pos)))
    (or (bt:with-lock-held (*descriptor-cache-lock*)
          (gethash key *descriptor-expansion-cache*))
        (let ((scripts (%out-desc-expand-uncached desc pos)))
          (bt:with-lock-held (*descriptor-cache-lock*)
            (when (>= (hash-table-count *descriptor-expansion-cache*)
                      *descriptor-cache-max-entries*)
              (clrhash *descriptor-expansion-cache*))
            (setf (gethash key *descriptor-expansion-cache*) scripts))
          scripts))))

;;; --- DescriptorCache (Core descriptor.h DescriptorCache) ---
;;;
;;; The wallet's persistent expansion cache: per key expression index it holds
;;; the PARENT xpub (the extended key at the end of the fixed derivation path),
;;; DERIVED child xpubs per range position (only for hardened-ranged /*h keys),
;;; and the LAST-HARDENED xpub along the path. With these cached, a descriptor
;;; whose fixed path contains hardened steps (e.g. the default wallets'
;;; .../84h/1h/0h/0/*) expands without private keys. Persisted by the wallet
;;; as walletdescriptorcache / walletdescriptorlhcache records (wallet P1).

(defstruct descriptor-cache
  "Cached xpubs for one descriptor (Core DescriptorCache). All tables map a
key expression index (m_expr_index) to ext-key structs; derived-xpubs maps to
an inner table keyed by derivation (range) index."
  (parent-xpubs (make-hash-table :test 'eql) :type hash-table)
  (derived-xpubs (make-hash-table :test 'eql) :type hash-table)
  (last-hardened-xpubs (make-hash-table :test 'eql) :type hash-table))

(defun descriptor-cache-parent (cache expr-index)
  (gethash expr-index (descriptor-cache-parent-xpubs cache)))

(defun (setf descriptor-cache-parent) (xpub cache expr-index)
  (setf (gethash expr-index (descriptor-cache-parent-xpubs cache)) xpub))

(defun descriptor-cache-derived (cache expr-index der-index)
  (let ((inner (gethash expr-index (descriptor-cache-derived-xpubs cache))))
    (and inner (gethash der-index inner))))

(defun (setf descriptor-cache-derived) (xpub cache expr-index der-index)
  (let ((inner (or (gethash expr-index (descriptor-cache-derived-xpubs cache))
                   (setf (gethash expr-index (descriptor-cache-derived-xpubs cache))
                         (make-hash-table :test 'eql)))))
    (setf (gethash der-index inner) xpub)))

(defun descriptor-cache-last-hardened (cache expr-index)
  (gethash expr-index (descriptor-cache-last-hardened-xpubs cache)))

(defun (setf descriptor-cache-last-hardened) (xpub cache expr-index)
  (setf (gethash expr-index (descriptor-cache-last-hardened-xpubs cache)) xpub))

(defun %ext-key-equal-p (a b)
  (and (= (bl.crypto:ext-key-depth a)
          (bl.crypto:ext-key-depth b))
       (= (bl.crypto:ext-key-parent-fingerprint a)
          (bl.crypto:ext-key-parent-fingerprint b))
       (= (bl.crypto:ext-key-child-number a)
          (bl.crypto:ext-key-child-number b))
       (equalp (bl.crypto:ext-key-chain-code a)
               (bl.crypto:ext-key-chain-code b))
       (equalp (bl.crypto:ext-key-key a)
               (bl.crypto:ext-key-key b))))

(defun descriptor-cache-merge-and-diff (cache new-items)
  "Merge NEW-ITEMS into CACHE and return a fresh descriptor-cache holding only
the entries that were actually new (Core DescriptorCache::MergeAndDiff). A
conflicting entry — same slot, different xpub — signals an error, matching
Core's cache-corruption check."
  (let ((diff (make-descriptor-cache)))
    (maphash (lambda (expr-index xpub)
               (let ((existing (descriptor-cache-parent cache expr-index)))
                 (cond ((null existing)
                        (setf (descriptor-cache-parent cache expr-index) xpub
                              (descriptor-cache-parent diff expr-index) xpub))
                       ((not (%ext-key-equal-p existing xpub))
                        (internal-error "Attempted to overwrite a cached parent xpub with a different one")))))
             (descriptor-cache-parent-xpubs new-items))
    (maphash (lambda (expr-index inner)
               (maphash (lambda (der-index xpub)
                          (let ((existing (descriptor-cache-derived cache expr-index der-index)))
                            (cond ((null existing)
                                   (setf (descriptor-cache-derived cache expr-index der-index) xpub
                                         (descriptor-cache-derived diff expr-index der-index) xpub))
                                  ((not (%ext-key-equal-p existing xpub))
                                   (internal-error "Attempted to overwrite a cached derived xpub with a different one")))))
                        inner))
             (descriptor-cache-derived-xpubs new-items))
    (maphash (lambda (expr-index xpub)
               (let ((existing (descriptor-cache-last-hardened cache expr-index)))
                 (cond ((null existing)
                        (setf (descriptor-cache-last-hardened cache expr-index) xpub
                              (descriptor-cache-last-hardened diff expr-index) xpub))
                       ((not (%ext-key-equal-p existing xpub))
                        (internal-error "Attempted to overwrite a cached last hardened xpub with a different one")))))
             (descriptor-cache-last-hardened-xpubs new-items))
    diff))

;;; --- Cache/provider-aware key expansion (Core BIP32PubkeyProvider::GetPubKey) ---

(defun %desc-key-root-keyid (key)
  "hash160 of the root pubkey of a BIP32 key expression — the CKeyID under
which the wallet stores the root private key."
  (bl.crypto:hash160
   (bl.crypto:ext-key-public-bytes (desc-key-extkey key))))

(defun desc-key-root-xprv (key privkey-provider)
  "The root extended PRIVATE key for a BIP32 key expression, or NIL. Prefers
the xprv embedded at parse time; otherwise reconstructs it from the 32-byte
secret PRIVKEY-PROVIDER returns for the root pubkey's keyid (Core
BIP32PubkeyProvider::GetExtKey: copy depth/fingerprint/child/chaincode from
the xpub, substitute the private key material)."
  (or (desc-key-ext-privkey key)
      (when privkey-provider
        (let* ((pub (desc-key-extkey key))
               (priv (funcall privkey-provider (%desc-key-root-keyid key))))
          (when priv
            (bl.crypto:make-ext-key
             :version (bl.chain:chain-params-ext-secret-prefix
                       (bl.chain:chain-params-of-ext-prefix (bl.crypto:ext-key-version pub)))
             :depth (bl.crypto:ext-key-depth pub)
             :parent-fingerprint (bl.crypto:ext-key-parent-fingerprint pub)
             :child-number (bl.crypto:ext-key-child-number pub)
             :chain-code (bl.crypto:ext-key-chain-code pub)
             :key (concatenate '(vector (unsigned-byte 8)) #(0) priv)
             :privatep t))))))

(defun %desc-key-pubkey-at-cached (key expr-index pos read-cache write-cache privkey-provider)
  "The pubkey KEY produces at POS, via the wallet cache machinery (Core
BIP32PubkeyProvider::GetPubKey, descriptor.cpp:425-485). With READ-CACHE, only
cached xpubs are consulted (Core ExpandFromCache) — a miss signals
descriptor-derivation-error. Without it, hardened derivation pulls the root
xprv from PRIVKEY-PROVIDER, and WRITE-CACHE (when given) collects the parent /
derived / last-hardened xpubs exactly as Core caches them."
  (when (desc-key-pubkey key)
    (return-from %desc-key-pubkey-at-cached (desc-key-pubkey key)))
  (let* ((path (desc-key-path key))
         (derive (desc-key-derive key))
         (hardened-p (or (eq derive :hardened)
                         (some (lambda (i) (logbitp 31 i)) path)))
         (final nil)
         (parent nil)
         (last-hardened nil))
    (handler-case
        (cond
          (read-cache
           (let ((cached (descriptor-cache-derived read-cache expr-index pos)))
             (cond (cached (setf final cached))
                   ((eq derive :hardened) (error 'descriptor-derivation-error))
                   (t (let ((p (descriptor-cache-parent read-cache expr-index)))
                        (unless p (error 'descriptor-derivation-error))
                        (setf final (if (eq derive :unhardened)
                                        (bl.crypto:bip32-derive-child p pos)
                                        p)))))))
          (hardened-p
           (let ((xprv (desc-key-root-xprv key privkey-provider)))
             (unless xprv (error 'descriptor-derivation-error))
             (let ((k xprv) (lh nil))
               (dolist (entry path)
                 (setf k (bl.crypto:bip32-derive-child k entry))
                 (when (logbitp 31 entry) (setf lh k)))
               (setf parent (bl.crypto:bip32-neuter k))
               (ecase derive
                 (:none)
                 (:unhardened
                  (setf k (bl.crypto:bip32-derive-child k pos)))
                 (:hardened
                  (setf k (bl.crypto:bip32-derive-child
                           k (+ pos bl.crypto:+bip32-hardened+)))))
               (setf final (bl.crypto:bip32-neuter k))
               (when lh (setf last-hardened (bl.crypto:bip32-neuter lh))))))
          (t
           (let ((k (desc-key-extkey key)))
             (dolist (entry path)
               (setf k (bl.crypto:bip32-derive-child k entry)))
             (setf parent k)
             (setf final (if (eq derive :unhardened)
                             (bl.crypto:bip32-derive-child k pos)
                             k)))))
      (descriptor-derivation-error (e) (error e))
      (error () (error 'descriptor-derivation-error)))
    (when write-cache
      ;; Only cache the parent when there is any unhardened derivation; a
      ;; hardened-ranged terminal caches the derived child instead
      ;; (descriptor.cpp:471-483).
      (if (not (eq derive :hardened))
          (progn
            (setf (descriptor-cache-parent write-cache expr-index) parent)
            (when last-hardened
              (setf (descriptor-cache-last-hardened write-cache expr-index)
                    last-hardened)))
          (setf (descriptor-cache-derived write-cache expr-index pos) final)))
    (bl.crypto:ext-key-public-bytes final)))

(defun %out-desc-expand-cached (desc pos &key read-cache write-cache privkey-provider)
  "Expand DESC at POS through the wallet cache machinery. Returns
(values scripts pubkeys) where PUBKEYS lists the derived pubkey per key
expression, in expression order (feeds the SPKM's pubkey map). Signals
descriptor-derivation-error when a needed cache entry or private key is
missing (Core Expand/ExpandFromCache returning false)."
  (let* ((indexes (out-desc-key-indexes desc))
         ;; Indexed by EXPRESSION index, not filled in call order. Script
         ;; generation does not visit key expressions in parse order —
         ;; `andor(X,Y,Z)' emits X NOTIF Z ELSE Y ENDIF
         ;; (miniscript.lisp, the :ANDOR arm of the script builder) — so a
         ;; push/nreverse here returned Y's and Z's pubkeys transposed, while
         ;; %SPKM-EXPANSION-PAIRS zips this list against OUT-DESC-ORDERED-KEYS,
         ;; which IS parse order. The wallet then believed a pubkey belonged to
         ;; the wrong key expression: wrong origin in an inferred descriptor,
         ;; wrong provider consulted when signing.
         (slots (make-array (hash-table-count indexes) :initial-element nil))
         (scripts (%out-desc-expand-1
                   desc pos
                   (lambda (key)
                     (let* ((i (gethash key indexes))
                            (pk (%desc-key-pubkey-at-cached
                                 key i pos
                                 read-cache write-cache privkey-provider)))
                       (when i (setf (aref slots i) pk))
                       pk)))))
    (values scripts (coerce slots 'list))))

(defun out-desc-expand-from-cache (desc pos cache)
  "Expand DESC at POS strictly from CACHE (Core ExpandFromCache). Returns
(values scripts pubkeys), or NIL when the cache lacks a needed xpub."
  (handler-case (%out-desc-expand-cached desc pos :read-cache cache)
    (descriptor-derivation-error () nil)))

(defun out-desc-expand-with-provider (desc pos privkey-provider write-cache)
  "Expand DESC at POS deriving from key material — PRIVKEY-PROVIDER maps a
20-byte keyid to a 32-byte secret (or NIL) — collecting new cache entries into
WRITE-CACHE (Core Expand with a write cache). Signals
descriptor-derivation-error when required private keys are unavailable."
  (%out-desc-expand-cached desc pos :write-cache write-cache
                                    :privkey-provider privkey-provider))

;;; --- Private / normalized descriptor strings (Core ToPrivateString /
;;; ToNormalizedString) ---

(defun desc-key-privkey-for (key privkey-provider)
  "The (values priv32 compressed-p) for a const-pubkey KEY, from the parse
itself or PRIVKEY-PROVIDER. X-only keys try both parities (Core
XOnlyPubKey::GetKeyIDs)."
  (cond
    ((desc-key-privkey key)
     (values (desc-key-privkey key) (desc-key-compressed-p key)))
    ((null privkey-provider) nil)
    ((desc-key-xonly-p key)
     (let ((x (subseq (desc-key-pubkey key) 1)))
       (dolist (prefix '(2 3))
         (let* ((full (concatenate '(vector (unsigned-byte 8))
                                   (vector prefix) x))
                (priv (funcall privkey-provider
                               (bl.crypto:hash160 full))))
           (when priv (return (values priv t)))))))
    (t
     (let ((priv (funcall privkey-provider
                          (bl.crypto:hash160 (desc-key-pubkey key)))))
       (when priv (values priv (= (length (desc-key-pubkey key)) 33)))))))

(defun desc-key-private-string (key network privkey-provider)
  "KEY's private string form (Core PubkeyProvider::ToPrivateString): WIF for
const keys, xprv for BIP32 keys, hardened markers in input style. Returns
(values string has-priv-p); without private material the public form is
returned with HAS-PRIV-P nil."
  (let ((origin (if (desc-key-origin-fingerprint key)
                    (format nil "[~A~A]"
                            (bl.crypto:bytes-to-hex
                             (desc-key-origin-fingerprint key))
                            (format-key-path (desc-key-origin-path key)
                                              (desc-key-apostrophe key)))
                    "")))
    (if (desc-key-pubkey key)
        (multiple-value-bind (priv compressed)
            (desc-key-privkey-for key privkey-provider)
          (if priv
              (values (concatenate 'string origin
                                   (bl.crypto:private-key-to-wif
                                    priv
                                    :network network
                                    :compressed compressed))
                      t)
              (values (desc-key-string key) nil)))
        (let ((xprv (desc-key-root-xprv key privkey-provider)))
          (if xprv
              (values (concatenate
                       'string origin
                       (bl.crypto:bip32-serialize xprv)
                       (format-key-path (desc-key-path key)
                                         (desc-key-apostrophe key))
                       (ecase (desc-key-derive key)
                         (:none "")
                         (:unhardened "/*")
                         (:hardened (if (desc-key-apostrophe key) "/*'" "/*h"))))
                      t)
              (values (desc-key-string key) nil))))))

(defun desc-key-normalized-string (key expr-index cache privkey-provider)
  "KEY's normalized public form (Core ToNormalizedString): BIP32 keys with
hardened steps in their fixed path are rewritten as
[fingerprint/path-to-last-hardened]xpub-at-last-hardened/rest/*, merging with
any existing origin; hardened markers normalize to 'h'. Returns (values
string ok-p) — OK-P nil when the last-hardened xpub is unavailable (no cache
entry and no private key)."
  (flet ((wrap-origin (sub)
           ;; Core OriginPubkeyProvider::ToNormalizedString: merge our origin
           ;; with an origin the inner normalization produced.
           (if (desc-key-origin-fingerprint key)
               (let ((origin (format nil "~A~A"
                                     (bl.crypto:bytes-to-hex
                                      (desc-key-origin-fingerprint key))
                                     (format-key-path (desc-key-origin-path key) nil))))
                 (if (and (plusp (length sub)) (char= (char sub 0) #\[))
                     ;; strip "[" + 8-char fingerprint from SUB, keep its path
                     (concatenate 'string "[" origin (subseq sub 9))
                     (concatenate 'string "[" origin "]" sub)))
               sub)))
    (cond
      ;; Const pubkeys normalize to their public form.
      ((desc-key-pubkey key)
       (values (wrap-origin (desc-key-string key)) t))
      ;; Hardened-ranged: print public as-is with normalized markers.
      ((eq (desc-key-derive key) :hardened)
       (values (wrap-origin
                (concatenate 'string
                             (bl.crypto:bip32-serialize (desc-key-extkey key))
                             (format-key-path (desc-key-path key) nil)
                             "/*h"))
               t))
      (t
       (let* ((path (desc-key-path key))
              (last-hardened-pos (position-if (lambda (i) (logbitp 31 i)) path
                                              :from-end t)))
         (if (null last-hardened-pos)
             ;; No hardened derivation: the plain public form.
             (values (wrap-origin (desc-key-string key)) t)
             (let* ((origin-path (subseq path 0 (1+ last-hardened-pos)))
                    (end-path (subseq path (1+ last-hardened-pos)))
                    (fingerprint (subseq (%desc-key-root-keyid key) 0 4))
                    (xpub (or (and cache (descriptor-cache-last-hardened cache expr-index))
                              (let ((xprv (desc-key-root-xprv key privkey-provider)))
                                (when xprv
                                  (let ((k xprv))
                                    (dolist (entry origin-path
                                                   (bl.crypto:bip32-neuter k))
                                      (setf k (bl.crypto:bip32-derive-child
                                               k entry)))))))))
               (if (null xpub)
                   (values (desc-key-string key) nil)
                   (values (wrap-origin
                            (concatenate
                             'string
                             "[" (bl.crypto:bytes-to-hex fingerprint)
                             (format-key-path origin-path nil) "]"
                             (bl.crypto:bip32-serialize xpub)
                             (format-key-path end-path nil)
                             (if (eq (desc-key-derive key) :unhardened) "/*" "")))
                           t)))))))))

(defun out-desc-string-private (desc network privkey-provider)
  "The private descriptor body (Core ToPrivateString semantics): each key
prints its private form when available, its public form otherwise. Returns
(values body any-priv-p)."
  (let ((any nil))
    (values (%out-desc-string-walk
             desc
             (lambda (key)
               (multiple-value-bind (s ok)
                   (desc-key-private-string key network privkey-provider)
                 (when ok (setf any t))
                 s)))
            any)))

(defun out-desc-string-normalized (desc cache privkey-provider)
  "The normalized public descriptor body (Core ToNormalizedString). Returns
(values body ok-p)."
  (let ((indexes (out-desc-key-indexes desc))
        (ok t))
    (values (%out-desc-string-walk
             desc
             (lambda (key)
               (multiple-value-bind (s key-ok)
                   (desc-key-normalized-string key (gethash key indexes)
                                               cache privkey-provider)
                 (unless key-ok (setf ok nil))
                 s)))
            ok)))

;;; --- Range parameters (rpc/util.cpp ParseRange/ParseDescriptorRange) ---

(defun %range-error (fmt &rest args)
  (error 'rpc-error :code +rpc-invalid-parameter+
                    :message (apply #'format nil fmt args)))

(defun parse-descriptor-range (value)
  "Parse a deriveaddresses/scan range parameter: N means [0,N]; or [begin,end].
Returns (values begin end); Core's ParseRange + ParseDescriptorRange checks."
  (multiple-value-bind (low high)
      (cond ((integerp value) (values 0 value))
            ((and (listp value) (= (length value) 2)
                  (integerp (first value)) (integerp (second value)))
             (when (> (first value) (second value))
               (%range-error "Range specified as [begin,end] must not have begin after end"))
             (values (first value) (second value)))
            (t (%range-error "Range must be specified as end or as [begin,end]")))
    (when (< low 0)
      (%range-error "Range should be greater or equal than 0"))
    (unless (zerop (ash high -31))
      (%range-error "End of range is too high"))
    (when (>= high (+ low 1000000))
      (%range-error "Range is too large"))
    (values low high)))

;;; --- Consumer helpers ---

(defun parse-output-descriptor (string network)
  "Expand a non-ranged descriptor STRING into a list of
(script . canonical-descriptor) pairs, where the canonical descriptor carries
a computed checksum (Core's getScriptFromDescriptor shape, used by
generatetodescriptor/generateblock). Ranged descriptors are rejected like
Core's mining RPCs."
  (let ((desc (parse-descriptor string network)))
    (when (out-desc-ranged-p desc)
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "Ranged descriptor not accepted. Maybe pass through deriveaddresses first?"))
    (let ((canonical (descriptor-add-checksum (out-desc-string desc))))
      (mapcar (lambda (script) (cons script canonical))
              (handler-case (out-desc-expand desc 0)
                (descriptor-derivation-error ()
                  (error 'rpc-error :code +rpc-invalid-address-or-key+
                                    :message "Cannot derive script without private keys")))))))

(defun descriptor-scanobject-scripts (scanobject network)
  "Expand a scanobject — a descriptor string or {\"desc\": ..., \"range\": ...}
object — into (values scripts canonical-descriptor). Port of Core's
EvalDescriptorStringOrObject (rpc/util.cpp:1324): default range [0,1000] for
ranged descriptors, [0,0] for unranged."
  (multiple-value-bind (desc-str range)
      (cond ((stringp scanobject) (values scanobject nil))
            ((hash-table-p scanobject)
             (let ((d (gethash "desc" scanobject)))
               (unless (stringp d)
                 (error 'rpc-error :code +rpc-invalid-parameter+
                                   :message "Descriptor needs to be provided in scan object"))
               (values d (gethash "range" scanobject))))
            (t (error 'rpc-error :code +rpc-invalid-parameter+
                                 :message "Scan object needs to be either a string or an object")))
    (multiple-value-bind (low high)
        (if range (parse-descriptor-range range) (values 0 1000))
      (let* ((desc (parse-descriptor desc-str network))
             (canonical (descriptor-add-checksum (out-desc-string desc))))
        (unless (out-desc-ranged-p desc)
          (setf low 0 high 0))
        (values (loop for i from low to high
                      append (handler-case (out-desc-expand desc i)
                               (descriptor-derivation-error ()
                                 (error 'rpc-error
                                        :code +rpc-invalid-address-or-key+
                                        :message (format nil "Cannot derive script without private keys: '~A'"
                                                         desc-str)))))
                canonical)))))

(defun %needle-scripts (scanobjects network)
  "Expand SCANOBJECTS (descriptor strings/objects) into an equalp hash-table
mapping each expanded script (byte vector) to its canonical descriptor
(scantxoutset/scanblocks/getdescriptoractivity needle set)."
  (let ((needles (make-hash-table :test 'equalp)))
    (dolist (scanobject scanobjects needles)
      (multiple-value-bind (scripts canonical)
          (descriptor-scanobject-scripts scanobject network)
        (dolist (script scripts)
          (setf (gethash script needles) canonical))))))

;;; --- Script -> address / inferred descriptor ---

(defun script->address (script network)
  "Address string for a standard scriptPubKey SCRIPT, or NIL if the script
has no address representation (raw/pk/bare-multisig/anchor). Inverse of the
encoders in crypto/address.lisp, keyed on CLASSIFY-SCRIPT."
  (multiple-value-bind (type data) (bl.val:classify-script script)
    (case type
      (:pubkeyhash (bl.crypto:encode-p2pkh-address (getf data :hash) network))
      (:scripthash (bl.crypto:encode-p2sh-address (getf data :hash) network))
      (:witness-v0-keyhash (bl.crypto:encode-p2wpkh-address (getf data :witness-program) network))
      (:witness-v0-scripthash (bl.crypto:encode-p2wsh-address (getf data :witness-program) network))
      (:witness-v1-taproot (bl.crypto:encode-p2tr-address (getf data :witness-program) network))
      (t nil))))

(defun scriptpubkey-desc (script network)
  "Core InferDescriptor for a bare scriptPubKey (no key material available): an
addressable script infers to addr(<address>), anything else to raw(<hex>), each
with the appended descriptor checksum. This is the `desc` field on decoded
outputs (gettxout, decoderawtransaction, getblock verbosity 2, decodescript)."
  (let ((addr (script->address script network)))
    (descriptor-add-checksum
     (if addr
         (format nil "addr(~A)" addr)
         (format nil "raw(~A)" (bl.crypto:bytes-to-hex script))))))

;;; --- Descriptor RPCs (getdescriptorinfo / deriveaddresses) ---

(define-rpc "getdescriptorinfo" (node (desc-str))
  "Analyse a descriptor (Bitcoin Core getdescriptorinfo). PARAMS: (descriptor).
Reports the canonical public form (private keys stripped to public) with its
checksum, the checksum of the input as given, and the
isrange/issolvable/hasprivatekeys flags."
  (let ((network (rpc-get-network node)))
    (unless (stringp desc-str)
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "descriptor must be a string"))
    (multiple-value-bind (desc input-checksum) (parse-descriptor desc-str network)
      `(("descriptor" . ,(descriptor-add-checksum (out-desc-string desc)))
        ("checksum" . ,input-checksum)
        ("isrange" . ,(json-bool (out-desc-ranged-p desc)))
        ("issolvable" . ,(json-bool (out-desc-solvable-p desc)))
        ("hasprivatekeys" . ,(json-bool (out-desc-has-privkeys-p desc)))))))

(define-rpc "deriveaddresses" (node (desc-str range))
  "Derive the address(es) for a descriptor (Bitcoin Core deriveaddresses).
PARAMS: (descriptor [range]). The descriptor must carry a checksum. RANGE is
required for ranged descriptors (an end N meaning [0,N], or [begin,end]) and
rejected for unranged ones; combo() P2PK scripts are skipped like Core."
  (let* ((range-given (and (> (length params) 1) range t))
         (network (rpc-get-network node)))
    (unless (stringp desc-str)
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "descriptor must be a string"))
    ;; A multipath descriptor denotes SEVERAL descriptors, and Core returns one
    ;; address array per expansion — an array of arrays (rpc_deriveaddresses.py
    ;; :32-33). #426 built the expander for the wallet's import path;
    ;; deriveaddresses went on refusing multipath outright, because the refusal
    ;; lives in the key-path parser it reaches first.
    (let ((expansions (expand-multipath-descriptor desc-str)))
      (when (rest expansions)
        ;; The checksum covered the MULTIPATH form, so it is validated here,
        ;; once, and the expansions carry none — which is why they are derived
        ;; with require-checksum NIL. Requiring one per expansion answers
        ;; "Missing checksum" for a descriptor whose checksum was correct.
        (%check-descriptor-checksum desc-str t)
        (return-from rpc-deriveaddresses
          (coerce (mapcar (lambda (one)
                            (coerce (%derive-addresses-for one range range-given network
                                                           :require-checksum nil)
                                    'vector))
                          expansions)
                  'vector))))
    (%derive-addresses-for desc-str range range-given network)))

(defun %derive-addresses-for (desc-str range range-given network
                              &key (require-checksum t))
  "The single-descriptor half of DERIVEADDRESSES: DESC-STR's addresses over
RANGE, as a list."
  (multiple-value-bind (low high)
      (if range-given (parse-descriptor-range range) (values 0 0))
    (let ((desc (parse-descriptor desc-str network :require-checksum require-checksum)))
        (when (and (not (out-desc-ranged-p desc)) range-given)
          (error 'rpc-error :code +rpc-invalid-parameter+
                            :message "Range should not be specified for an un-ranged descriptor"))
        (when (and (out-desc-ranged-p desc) (not range-given))
          (error 'rpc-error :code +rpc-invalid-parameter+
                            :message "Range must be specified for a ranged descriptor"))
      (let ((addresses '()))
        (loop for i from low to high
              do (let ((scripts (handler-case (out-desc-expand desc i)
                                  (descriptor-derivation-error ()
                                    (error 'rpc-error
                                           :code +rpc-invalid-address-or-key+
                                           :message "Cannot derive script without private keys")))))
                   (dolist (script scripts)
                     (let ((addr (script->address script network)))
                       (cond (addr (push addr addresses))
                             ;; combo() emits P2PK; Core skips it rather than
                             ;; failing when other scripts have addresses.
                             ((and (> (length scripts) 1) (eq (bl.val:classify-script script) :pubkey)))
                             (t (error 'rpc-error
                                       :code +rpc-invalid-address-or-key+
                                       :message "Descriptor does not have a corresponding address")))))))
        (when (null addresses)
          (error 'rpc-error :code +rpc-misc-error+ :message "Unexpected empty result"))
        (nreverse addresses)))))
