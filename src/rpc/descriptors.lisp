(in-package #:bitcoin-lisp.rpc)

;;; Output descriptors (Bitcoin Core src/script/descriptor.cpp)
;;;
;;; Supported grammar (P0 descriptor engine):
;;;   addr(ADDRESS)  raw(HEX)
;;;   pk(KEY)  pkh(KEY)  wpkh(KEY)  combo(KEY)
;;;   multi(k,KEY,...)  sortedmulti(k,KEY,...)
;;;   sh(SCRIPT)  wsh(SCRIPT)  sh(wsh(SCRIPT))
;;;   tr(KEY)  rawtr(KEY)          [key-path only; no tapscript trees]
;;; where KEY is a hex pubkey (33/65 bytes; 32-byte x-only inside tr/rawtr),
;;; a WIF private key, or an xpub/xprv (tpub/tprv on test networks) with an
;;; optional [fingerprint/path] origin prefix, a derivation path using h or '
;;; hardened markers, and an optional ranged terminal /* or /*h.
;;; Out of scope at P0 (match Core error text where Core has one, otherwise a
;;; clear "not supported"): tapscript trees, miniscript, multipath <a;b>,
;;; multi_a/sortedmulti_a, musig.
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
  (privkey nil)                     ; 32-byte WIF secret, or NIL
  (compressed-p t :type boolean)    ; WIF compression flag
  (extkey nil)                      ; public (neutered) root ext-key, or NIL
  (ext-privkey nil)                 ; private root ext-key if an xprv was given
  (path nil)                        ; derivation path after the key (uint32 list)
  (derive :none)                    ; :none | :unhardened (/*) | :hardened (/*h)
  (apostrophe nil :type boolean))   ; hardened marker style for printing

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

(defun %wif-network-matches-p (wif-network network)
  (if (eq network :mainnet)
      (eq wif-network :mainnet)
      (eq wif-network :testnet)))

(defun %extkey-valid-for-network-p (k network)
  "Check the version prefix of parsed ext-key K against NETWORK (Core's
DecodeExtKey/DecodeExtPubKey check chainparams EXT_SECRET_KEY/EXT_PUBLIC_KEY),
plus key-material sanity."
  (let ((version (bitcoin-lisp.crypto:ext-key-version k))
        (key (bitcoin-lisp.crypto:ext-key-key k)))
    (and (if (eq network :mainnet)
             (member version (list bitcoin-lisp.crypto:+xprv-mainnet+
                                   bitcoin-lisp.crypto:+xpub-mainnet+))
             (member version (list bitcoin-lisp.crypto:+xprv-testnet+
                                   bitcoin-lisp.crypto:+xpub-testnet+)))
         (if (bitcoin-lisp.crypto:ext-key-privatep k)
             (and (zerop (aref key 0))
                  (< 0
                     (reduce (lambda (acc b) (logior (ash acc 8) b))
                             (subseq key 1) :initial-value 0)
                     bitcoin-lisp.crypto:+secp256k1-order+))
             (and (member (aref key 0) '(2 3))
                  (bitcoin-lisp.crypto:public-key-valid-p key))))))

(defun %parse-desc-key-inner (str ctx network apostrophe-box)
  "Parse a key expression without origin info (Core's ParsePubkeyInner).
CTX is the surrounding context: :top :sh :wsh :wpkh :tr."
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
        (let* ((bytes (bitcoin-lisp.crypto:hex-to-bytes key-str))
               (len (length bytes))
               (b0 (and (plusp len) (aref bytes 0)))
               (valid-header (or (and (= len 33) (member b0 '(2 3)))
                                 (and (= len 65) (member b0 '(4 6 7))))))
          (when (and valid-header (member b0 '(6 7)))
            (%desc-error "Hybrid public keys are not allowed"))
          (cond ((and valid-header (bitcoin-lisp.crypto:public-key-valid-p bytes))
                 (if (or permit-uncompressed (= len 33))
                     (return-from %parse-desc-key-inner
                       (make-desc-key :pubkey bytes :xonly-p nil))
                     (%desc-error "Uncompressed keys are not allowed")))
                ((and (= len 32) (eq ctx :tr))
                 (let ((full (concatenate '(vector (unsigned-byte 8)) #(2) bytes)))
                   (when (bitcoin-lisp.crypto:public-key-valid-p full)
                     (return-from %parse-desc-key-inner
                       (make-desc-key :pubkey full :xonly-p t))))))
          (%desc-error "Pubkey '~A' is invalid" key-str)))
      ;; WIF private key?
      (multiple-value-bind (priv compressed wif-network)
          (bitcoin-lisp.crypto:wif-to-private-key key-str)
        (when (and priv (%wif-network-matches-p wif-network network))
          (unless (or permit-uncompressed compressed)
            (%desc-error "Uncompressed keys are not allowed"))
          (return-from %parse-desc-key-inner
            (make-desc-key :pubkey (bitcoin-lisp.crypto:derive-public-key
                                    priv :compressed compressed)
                           :xonly-p (eq ctx :tr)
                           :privkey priv
                           :compressed-p compressed)))))
    ;; Extended key (with optional derivation path and ranged terminal).
    (let ((k (bitcoin-lisp.crypto:bip32-parse key-str)))
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
          (if (bitcoin-lisp.crypto:ext-key-privatep k)
              (make-desc-key :extkey (bitcoin-lisp.crypto:bip32-neuter k)
                             :ext-privkey k
                             :path path :derive derive)
              (make-desc-key :extkey k :path path :derive derive)))))))

(defun %parse-desc-key (str ctx network)
  "Parse a key expression with optional [origin] prefix (Core's ParsePubkey)."
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
                    (bitcoin-lisp.crypto:hex-to-bytes fpr-hex)
                    (desc-key-origin-path key) origin-path
                    (desc-key-apostrophe key) (car apostrophe-box))
              key))))))

(defun desc-key-ranged-p (key)
  (not (eq (desc-key-derive key) :none)))

(defun desc-key-has-privkey-p (key)
  (and (or (desc-key-privkey key)
           (desc-key-ext-privkey key))
       t))

(defun %desc-key-size (key)
  "Serialized size of the pubkey(s) this expression produces (Core GetSize):
33 for BIP32/compressed, 65 for uncompressed constants."
  (if (desc-key-pubkey key) (length (desc-key-pubkey key)) 33))

;;; --- Key expression printing (public form, Core's ToString) ---

(defun %format-key-path (path apostrophe)
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
  (let ((apostrophe (if (eq style :compat) t (desc-key-apostrophe key))))
    (concatenate
     'string
     (if (desc-key-origin-fingerprint key)
         (format nil "[~A~A]"
                 (bitcoin-lisp.crypto:bytes-to-hex (desc-key-origin-fingerprint key))
                 (%format-key-path (desc-key-origin-path key) apostrophe))
         "")
     (if (desc-key-pubkey key)
         (bitcoin-lisp.crypto:bytes-to-hex
          (if (desc-key-xonly-p key)
              (subseq (desc-key-pubkey key) 1)
              (desc-key-pubkey key)))
         (bitcoin-lisp.crypto:bip32-serialize (desc-key-extkey key)))
     (if (desc-key-extkey key)
         (%format-key-path (desc-key-path key) apostrophe)
         "")
     (ecase (desc-key-derive key)
       (:none "")
       (:unhardened "/*")
       (:hardened (if apostrophe "/*'" "/*h"))))))

;;; --- Key expression expansion ---

(define-condition descriptor-derivation-error (error)
  ()
  (:documentation "Expansion needs private keys (hardened derivation from a
public-only descriptor) or hit an invalid BIP32 child."))

(defun %desc-key-pubkey-at (key pos)
  "The pubkey bytes KEY produces at range position POS (Core GetPubKey).
Signals descriptor-derivation-error when hardened derivation is required but
only public key material is available.

Note: %desc-key-pubkey-at-cached below performs the same derivation through
the wallet's persistent xpub cache (Core folds both into one GetPubKey with
optional caches); keep the two derivation paths in sync."
  (if (desc-key-pubkey key)
      (desc-key-pubkey key)
      (let* ((hardened (or (eq (desc-key-derive key) :hardened)
                           (some (lambda (i) (logbitp 31 i)) (desc-key-path key))))
             (root (cond ((and hardened (desc-key-ext-privkey key))
                          (desc-key-ext-privkey key))
                         (hardened (error 'descriptor-derivation-error))
                         (t (desc-key-extkey key)))))
        (handler-case
            (let ((k (bitcoin-lisp.crypto:bip32-derive-path root (desc-key-path key))))
              (ecase (desc-key-derive key)
                (:none)
                (:unhardened
                 (setf k (bitcoin-lisp.crypto:bip32-derive-child k pos)))
                (:hardened
                 (setf k (bitcoin-lisp.crypto:bip32-derive-child
                          k (+ pos bitcoin-lisp.crypto:+bip32-hardened+)))))
              (bitcoin-lisp.crypto:ext-key-public-bytes k))
          (descriptor-derivation-error (e) (error e))
          (error () (error 'descriptor-derivation-error))))))

;;; --- Descriptor AST ---

(defstruct out-desc
  "A parsed output descriptor (Core's DescriptorImpl tree)."
  (kind nil)          ; :addr :raw :pk :pkh :wpkh :combo :multi :sortedmulti :sh :wsh :tr :rawtr
  (keys nil)          ; list of desc-key
  (threshold nil)     ; integer for multi/sortedmulti
  (sub nil)           ; out-desc for sh/wsh
  (script nil)        ; script bytes for raw/addr
  (address nil)       ; address string for addr
  ;; The parsed MS-NODE for :miniscript. Its keys are desc-keys, so one node
  ;; serves the whole range: the script is generated per index by handing the
  ;; generator a converter that derives at that index.
  (node nil))

(defun %parse-multi-keys (inner ctx network name)
  "Parse \"k,KEY,KEY,...\" for multi/sortedmulti. Returns (values threshold keys)."
  (multiple-value-bind (thres-str rest) (%split-expr inner)
    (let ((threshold (and (plusp (length thres-str))
                          (every #'digit-char-p thres-str)
                          (ignore-errors (parse-integer thres-str)))))
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
          (when (or (zerop n) (> n 20))
            (%desc-error "Cannot have ~D keys in multisig; must have between 1 and 20 keys, inclusive" n))
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
          (values threshold keys (if (string= name "sortedmulti") :sortedmulti :multi)))))))

(defun %parse-descriptor-body (body ctx network)
  "Parse one script expression (Core's ParseScript). CTX is :top, :sh or :wsh."
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
                         :keys (list (%with-desc-error-prefix
                                      "pk(): "
                                      (lambda () (%parse-desc-key inner ctx network)))))))
      ;; pkh(KEY)
      (with-inner (inner "pkh")
        (return-from %parse-descriptor-body
          (make-out-desc :kind :pkh
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
      ;; multi(k,...) / sortedmulti(k,...)
      (dolist (name '("multi" "sortedmulti"))
        (with-inner (inner name)
          (multiple-value-bind (threshold keys kind)
              (%parse-multi-keys inner ctx network name)
            (return-from %parse-descriptor-body
              (make-out-desc :kind kind :threshold threshold :keys keys)))))
      (when (or (%func-inner "multi_a" expr) (%func-inner "sortedmulti_a" expr))
        (%desc-error "Can only have multi_a/sortedmulti_a inside tr()"))
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
            (bitcoin-lisp.crypto:decode-address inner network)
          (unless type
            (%desc-error "Address is not valid"))
          (return-from %parse-descriptor-body
            (make-out-desc :kind :addr :address inner :script script-pubkey))))
      ;; tr(KEY) — top level only, key path only (no tapscript trees at P0)
      (with-inner (inner "tr")
        (unless (eq ctx :top)
          (%desc-error "Can only have tr at top level"))
        (multiple-value-bind (arg tr-rest) (%split-expr inner)
          (unless (zerop (length tr-rest))
            (%desc-error "tr(): script trees are not supported"))
          (return-from %parse-descriptor-body
            (make-out-desc :kind :tr
                           :keys (list (%with-desc-error-prefix
                                        "tr(): "
                                        (lambda () (%parse-desc-key arg :tr network))))))))
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
                         :script (bitcoin-lisp.crypto:hex-to-bytes inner))))
      ;; Fallthrough. Inside wsh() Core tries miniscript here, which is what
      ;; makes policy descriptors -- timelocked recovery, decaying multisig --
      ;; expressible at all (Core descriptor.cpp ParseScript).
      (case ctx
        (:wsh (return-from %parse-descriptor-body
                (%parse-miniscript-descriptor expr network)))
        (:sh (%desc-error "A function is needed within P2SH"))
        (t (%desc-error "'~A' is not a valid descriptor function" expr))))))

(defun %parse-miniscript-descriptor (expr network)
  "Parse EXPR as a miniscript whose key arguments are descriptor key
expressions. Returns an :miniscript out-desc.

Only inside wsh(): miniscript's type rules and its resource limits are stated
for a specific script context, and P2WSH is the one this implements. Core
refuses it elsewhere for the same reason."
  (let* ((keys '())
         (node (handler-case
                   (let ((bitcoin-lisp.validation::*ms-key-parser*
                           (lambda (text)
                             (let ((key (%with-desc-error-prefix
                                         "miniscript: "
                                         (lambda () (%parse-desc-key text :wsh network)))))
                               (push key keys)
                               key))))
                     (bitcoin-lisp.validation::ms-parse expr))
                 ;; Not a miniscript expression at all -- a bare pubkey, say.
                 ;; Core only reports a miniscript error when the expression
                 ;; PARSED and then failed its rules (descriptor.cpp:2600);
                 ;; an unparseable one falls through to the generic message,
                 ;; which is far more useful for the common typo.
                 (bitcoin-lisp.validation::miniscript-parse-error ()
                   (%desc-error "A function is needed within P2WSH")))))
    (unless (bitcoin-lisp.validation::ms-node-valid-p node)
      (%desc-error "Miniscript expression is not valid: '~A'" expr))
    (unless (bitcoin-lisp.validation::ms-node-valid-top-level-p node)
      (%desc-error "Miniscript expression is not valid at top level: '~A'" expr))
    (make-out-desc :kind :miniscript :node node :keys (nreverse keys))))

(defun parse-descriptor (string network &key require-checksum)
  "Parse descriptor STRING (Core's Parse). Returns (values out-desc
input-checksum) where INPUT-CHECKSUM is the checksum computed over the input
body (private keys included, as getdescriptorinfo reports it). Signals
rpc-error with Core's messages on any problem."
  (multiple-value-bind (body checksum)
      (%check-descriptor-checksum string require-checksum)
    (values (%parse-descriptor-body body :top network) checksum)))

;;; --- Descriptor predicates + printing ---

(defun out-desc-ranged-p (desc)
  (or (some #'desc-key-ranged-p (out-desc-keys desc))
      (and (out-desc-sub desc) (out-desc-ranged-p (out-desc-sub desc)))))

(defun out-desc-solvable-p (desc)
  "Core IsSolvable: false for addr()/raw(), true for everything we can expand."
  (case (out-desc-kind desc)
    ((:addr :raw) nil)
    ((:sh :wsh) (out-desc-solvable-p (out-desc-sub desc)))
    (t t)))

(defun out-desc-has-privkeys-p (desc)
  "Whether the descriptor contained at least one private key (WIF or xprv);
Core getdescriptorinfo's hasprivatekeys (provider.keys non-empty)."
  (or (some #'desc-key-has-privkey-p (out-desc-keys desc))
      (and (out-desc-sub desc) (out-desc-has-privkeys-p (out-desc-sub desc)))))

(defun %out-desc-string-walk (desc keyfn)
  "The descriptor body of DESC with each key expression rendered by
(KEYFN desc-key) — the one structural walker behind the public/compat,
private, and normalized string forms (Core's ToStringHelper, parameterized
by StringType, descriptor.cpp:909)."
  (ecase (out-desc-kind desc)
    (:addr (format nil "addr(~A)" (out-desc-address desc)))
    (:raw (format nil "raw(~A)" (bitcoin-lisp.crypto:bytes-to-hex (out-desc-script desc))))
    ((:pk :pkh :wpkh :combo :tr :rawtr)
     (format nil "~(~A~)(~A)" (out-desc-kind desc)
             (funcall keyfn (first (out-desc-keys desc)))))
    ((:multi :sortedmulti)
     (format nil "~(~A~)(~D~{,~A~})" (out-desc-kind desc) (out-desc-threshold desc)
             (mapcar keyfn (out-desc-keys desc))))
    ((:sh :wsh)
     (format nil "~(~A~)(~A)" (out-desc-kind desc)
             (%out-desc-string-walk (out-desc-sub desc) keyfn)))
    ;; The miniscript renders itself, with each key expression rendered by the
    ;; same KEYFN the rest of the walk uses — so a policy descriptor's public,
    ;; private and normalized forms differ in exactly the way every other
    ;; descriptor's do.
    (:miniscript
     (bitcoin-lisp.validation::ms-node-to-string (out-desc-node desc) keyfn))))

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
  (bitcoin-lisp.crypto:sha256
   (flexi-streams:string-to-octets
    (descriptor-add-checksum (out-desc-string desc :compat))
    :external-format :ascii)))

;;; --- Key expression enumeration (Core's m_expr_index) ---

(defun out-desc-ordered-keys (desc)
  "All desc-keys of DESC in parse order — the order Core assigns m_expr_index
to PubkeyProviders. Our grammar never mixes keys and subscripts in one node,
so this is simply the node's keys or its subscript's."
  (if (out-desc-sub desc)
      (out-desc-ordered-keys (out-desc-sub desc))
      (out-desc-keys desc)))

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
               #(#x76 #xa9 #x14) (bitcoin-lisp.crypto:hash160 pubkey) #(#x88 #xac)))

(defun %script-p2wpkh (pubkey)
  (concatenate '(vector (unsigned-byte 8))
               #(#x00 #x14) (bitcoin-lisp.crypto:hash160 pubkey)))

(defun %script-p2sh (redeem-script)
  (concatenate '(vector (unsigned-byte 8))
               #(#xa9 #x14) (bitcoin-lisp.crypto:hash160 redeem-script) #(#x87)))

(defun %script-p2wsh (witness-script)
  (concatenate '(vector (unsigned-byte 8))
               #(#x00 #x20) (bitcoin-lisp.crypto:sha256 witness-script)))

(defun %script-p2tr (output-key32)
  (concatenate '(vector (unsigned-byte 8)) #(#x51 #x20) output-key32))

(defun %script-num (n)
  "Push of small number N in a multisig script: OP_1..OP_16 opcodes, else a
minimal 1-byte push (CScript << int64_t for the 1..20 range used here)."
  (if (<= 1 n 16)
      (vector (+ #x50 n))
      (vector 1 n)))

(defun %pubkey-lessp (a b)
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

(defun %key-xonly-bytes (pubkey)
  "The 32-byte x-only form of a 33-byte compressed pubkey."
  (subseq pubkey 1 33))

(defun %out-desc-expand-1 (desc pos keyfn)
  "Expand DESC at range position POS into its scriptPubKey list (Core Expand),
resolving each key expression's pubkey via (KEYFN desc-key)."
  (ecase (out-desc-kind desc)
    ((:addr :raw) (list (out-desc-script desc)))
    (:pk (list (%script-p2pk (funcall keyfn (first (out-desc-keys desc))))))
    (:pkh (list (%script-p2pkh (funcall keyfn (first (out-desc-keys desc))))))
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
         (setf pubkeys (sort (copy-list pubkeys) #'%pubkey-lessp)))
       (list (%script-multisig (out-desc-threshold desc) pubkeys))))
    (:sh (list (%script-p2sh (first (%out-desc-expand-1 (out-desc-sub desc) pos keyfn)))))
    (:wsh (list (%script-p2wsh (first (%out-desc-expand-1 (out-desc-sub desc) pos keyfn)))))
    (:tr
     (let* ((internal (%key-xonly-bytes
                       (funcall keyfn (first (out-desc-keys desc)))))
            (tweak (bitcoin-lisp.crypto:tap-tweak-hash internal))
            (output-key (bitcoin-lisp.crypto:tweak-xonly-pubkey internal tweak)))
       (unless output-key
         (error 'descriptor-derivation-error))
       (list (%script-p2tr output-key))))
    (:rawtr
     (list (%script-p2tr (%key-xonly-bytes
                          (funcall keyfn (first (out-desc-keys desc)))))))
    (:miniscript
     ;; One parsed node, a different script per range index: the converter is
     ;; what turns each key expression into the pubkey for THIS position.
     (list (bitcoin-lisp.validation::ms-node-script
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
  (and (desc-key-extkey key)
       (not (desc-key-ext-privkey key))
       (or (eq (desc-key-derive key) :hardened)
           (some (lambda (i) (logbitp 31 i)) (desc-key-path key)))))

(defun %out-desc-needs-missing-privkey-p (desc)
  (or (some #'%desc-key-needs-missing-privkey-p (out-desc-keys desc))
      (and (out-desc-sub desc)
           (%out-desc-needs-missing-privkey-p (out-desc-sub desc)))))

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
  (and (= (bitcoin-lisp.crypto:ext-key-depth a)
          (bitcoin-lisp.crypto:ext-key-depth b))
       (= (bitcoin-lisp.crypto:ext-key-parent-fingerprint a)
          (bitcoin-lisp.crypto:ext-key-parent-fingerprint b))
       (= (bitcoin-lisp.crypto:ext-key-child-number a)
          (bitcoin-lisp.crypto:ext-key-child-number b))
       (equalp (bitcoin-lisp.crypto:ext-key-chain-code a)
               (bitcoin-lisp.crypto:ext-key-chain-code b))
       (equalp (bitcoin-lisp.crypto:ext-key-key a)
               (bitcoin-lisp.crypto:ext-key-key b))))

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
                        (error "Attempted to overwrite a cached parent xpub with a different one")))))
             (descriptor-cache-parent-xpubs new-items))
    (maphash (lambda (expr-index inner)
               (maphash (lambda (der-index xpub)
                          (let ((existing (descriptor-cache-derived cache expr-index der-index)))
                            (cond ((null existing)
                                   (setf (descriptor-cache-derived cache expr-index der-index) xpub
                                         (descriptor-cache-derived diff expr-index der-index) xpub))
                                  ((not (%ext-key-equal-p existing xpub))
                                   (error "Attempted to overwrite a cached derived xpub with a different one")))))
                        inner))
             (descriptor-cache-derived-xpubs new-items))
    (maphash (lambda (expr-index xpub)
               (let ((existing (descriptor-cache-last-hardened cache expr-index)))
                 (cond ((null existing)
                        (setf (descriptor-cache-last-hardened cache expr-index) xpub
                              (descriptor-cache-last-hardened diff expr-index) xpub))
                       ((not (%ext-key-equal-p existing xpub))
                        (error "Attempted to overwrite a cached last hardened xpub with a different one")))))
             (descriptor-cache-last-hardened-xpubs new-items))
    diff))

;;; --- Cache/provider-aware key expansion (Core BIP32PubkeyProvider::GetPubKey) ---

(defun %desc-key-root-keyid (key)
  "hash160 of the root pubkey of a BIP32 key expression — the CKeyID under
which the wallet stores the root private key."
  (bitcoin-lisp.crypto:hash160
   (bitcoin-lisp.crypto:ext-key-public-bytes (desc-key-extkey key))))

(defun %desc-key-root-xprv (key privkey-provider)
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
            (bitcoin-lisp.crypto:make-ext-key
             :version (if (= (bitcoin-lisp.crypto:ext-key-version pub)
                             bitcoin-lisp.crypto:+xpub-mainnet+)
                          bitcoin-lisp.crypto:+xprv-mainnet+
                          bitcoin-lisp.crypto:+xprv-testnet+)
             :depth (bitcoin-lisp.crypto:ext-key-depth pub)
             :parent-fingerprint (bitcoin-lisp.crypto:ext-key-parent-fingerprint pub)
             :child-number (bitcoin-lisp.crypto:ext-key-child-number pub)
             :chain-code (bitcoin-lisp.crypto:ext-key-chain-code pub)
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
                                        (bitcoin-lisp.crypto:bip32-derive-child p pos)
                                        p)))))))
          (hardened-p
           (let ((xprv (%desc-key-root-xprv key privkey-provider)))
             (unless xprv (error 'descriptor-derivation-error))
             (let ((k xprv) (lh nil))
               (dolist (entry path)
                 (setf k (bitcoin-lisp.crypto:bip32-derive-child k entry))
                 (when (logbitp 31 entry) (setf lh k)))
               (setf parent (bitcoin-lisp.crypto:bip32-neuter k))
               (ecase derive
                 (:none)
                 (:unhardened
                  (setf k (bitcoin-lisp.crypto:bip32-derive-child k pos)))
                 (:hardened
                  (setf k (bitcoin-lisp.crypto:bip32-derive-child
                           k (+ pos bitcoin-lisp.crypto:+bip32-hardened+)))))
               (setf final (bitcoin-lisp.crypto:bip32-neuter k))
               (when lh (setf last-hardened (bitcoin-lisp.crypto:bip32-neuter lh))))))
          (t
           (let ((k (desc-key-extkey key)))
             (dolist (entry path)
               (setf k (bitcoin-lisp.crypto:bip32-derive-child k entry)))
             (setf parent k)
             (setf final (if (eq derive :unhardened)
                             (bitcoin-lisp.crypto:bip32-derive-child k pos)
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
    (bitcoin-lisp.crypto:ext-key-public-bytes final)))

(defun %out-desc-expand-cached (desc pos &key read-cache write-cache privkey-provider)
  "Expand DESC at POS through the wallet cache machinery. Returns
(values scripts pubkeys) where PUBKEYS lists the derived pubkey per key
expression, in expression order (feeds the SPKM's pubkey map). Signals
descriptor-derivation-error when a needed cache entry or private key is
missing (Core Expand/ExpandFromCache returning false)."
  (let ((indexes (out-desc-key-indexes desc))
        (pubkeys '()))
    (let ((scripts (%out-desc-expand-1
                    desc pos
                    (lambda (key)
                      (let ((pk (%desc-key-pubkey-at-cached
                                 key (gethash key indexes) pos
                                 read-cache write-cache privkey-provider)))
                        (push pk pubkeys)
                        pk)))))
      (values scripts (nreverse pubkeys)))))

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

(defun %desc-key-privkey-for (key privkey-provider)
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
                               (bitcoin-lisp.crypto:hash160 full))))
           (when priv (return (values priv t)))))))
    (t
     (let ((priv (funcall privkey-provider
                          (bitcoin-lisp.crypto:hash160 (desc-key-pubkey key)))))
       (when priv (values priv (= (length (desc-key-pubkey key)) 33)))))))

(defun desc-key-private-string (key network privkey-provider)
  "KEY's private string form (Core PubkeyProvider::ToPrivateString): WIF for
const keys, xprv for BIP32 keys, hardened markers in input style. Returns
(values string has-priv-p); without private material the public form is
returned with HAS-PRIV-P nil."
  (let ((origin (if (desc-key-origin-fingerprint key)
                    (format nil "[~A~A]"
                            (bitcoin-lisp.crypto:bytes-to-hex
                             (desc-key-origin-fingerprint key))
                            (%format-key-path (desc-key-origin-path key)
                                              (desc-key-apostrophe key)))
                    "")))
    (if (desc-key-pubkey key)
        (multiple-value-bind (priv compressed)
            (%desc-key-privkey-for key privkey-provider)
          (if priv
              (values (concatenate 'string origin
                                   (bitcoin-lisp.crypto:private-key-to-wif
                                    priv
                                    :network (if (eq network :mainnet) :mainnet :testnet)
                                    :compressed compressed))
                      t)
              (values (desc-key-string key) nil)))
        (let ((xprv (%desc-key-root-xprv key privkey-provider)))
          (if xprv
              (values (concatenate
                       'string origin
                       (bitcoin-lisp.crypto:bip32-serialize xprv)
                       (%format-key-path (desc-key-path key)
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
                                     (bitcoin-lisp.crypto:bytes-to-hex
                                      (desc-key-origin-fingerprint key))
                                     (%format-key-path (desc-key-origin-path key) nil))))
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
                             (bitcoin-lisp.crypto:bip32-serialize (desc-key-extkey key))
                             (%format-key-path (desc-key-path key) nil)
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
                              (let ((xprv (%desc-key-root-xprv key privkey-provider)))
                                (when xprv
                                  (let ((k xprv))
                                    (dolist (entry origin-path
                                                   (bitcoin-lisp.crypto:bip32-neuter k))
                                      (setf k (bitcoin-lisp.crypto:bip32-derive-child
                                               k entry)))))))))
               (if (null xpub)
                   (values (desc-key-string key) nil)
                   (values (wrap-origin
                            (concatenate
                             'string
                             "[" (bitcoin-lisp.crypto:bytes-to-hex fingerprint)
                             (%format-key-path origin-path nil) "]"
                             (bitcoin-lisp.crypto:bip32-serialize xpub)
                             (%format-key-path end-path nil)
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

(defun %parse-descriptor-range (value)
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
        (if range (%parse-descriptor-range range) (values 0 1000))
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

(defun %script->address (script network)
  "Address string for a standard scriptPubKey SCRIPT, or NIL if the script
has no address representation (raw/pk/bare-multisig). Inverse of the
encoders in crypto/address.lisp."
  (let ((len (length script)))
    (flet ((b (i) (aref script i)))
      (cond
        ;; P2PKH: OP_DUP OP_HASH160 14 <20> OP_EQUALVERIFY OP_CHECKSIG
        ((and (= len 25) (= (b 0) #x76) (= (b 1) #xa9) (= (b 2) #x14)
              (= (b 23) #x88) (= (b 24) #xac))
         (bitcoin-lisp.crypto:encode-p2pkh-address (subseq script 3 23) network))
        ;; P2SH: OP_HASH160 14 <20> OP_EQUAL
        ((and (= len 23) (= (b 0) #xa9) (= (b 1) #x14) (= (b 22) #x87))
         (bitcoin-lisp.crypto:encode-p2sh-address (subseq script 2 22) network))
        ;; P2WPKH: OP_0 14 <20>
        ((and (= len 22) (= (b 0) #x00) (= (b 1) #x14))
         (bitcoin-lisp.crypto:encode-p2wpkh-address (subseq script 2 22) network))
        ;; P2WSH: OP_0 20 <32>
        ((and (= len 34) (= (b 0) #x00) (= (b 1) #x20))
         (bitcoin-lisp.crypto:encode-p2wsh-address (subseq script 2 34) network))
        ;; P2TR: OP_1 20 <32>
        ((and (= len 34) (= (b 0) #x51) (= (b 1) #x20))
         (bitcoin-lisp.crypto:encode-p2tr-address (subseq script 2 34) network))
        (t nil)))))

(defun %script-p2pk-p (script)
  "True for a pay-to-pubkey script: <33/65-byte push> OP_CHECKSIG."
  (let ((len (length script)))
    (and (member len '(35 67))
         (= (aref script 0) (- len 2))
         (= (aref script (1- len)) #xac))))

(defun scriptpubkey-desc (script network)
  "Core InferDescriptor for a bare scriptPubKey (no key material available): an
addressable script infers to addr(<address>), anything else to raw(<hex>), each
with the appended descriptor checksum. This is the `desc` field on decoded
outputs (gettxout, decoderawtransaction, getblock verbosity 2, decodescript)."
  (let ((addr (%script->address script network)))
    (descriptor-add-checksum
     (if addr
         (format nil "addr(~A)" addr)
         (format nil "raw(~A)" (bitcoin-lisp.crypto:bytes-to-hex script))))))

;;; --- Descriptor RPCs (getdescriptorinfo / deriveaddresses) ---

(defun rpc-getdescriptorinfo (node params)
  "Analyse a descriptor (Bitcoin Core getdescriptorinfo). PARAMS: (descriptor).
Reports the canonical public form (private keys stripped to public) with its
checksum, the checksum of the input as given, and the
isrange/issolvable/hasprivatekeys flags."
  (let ((desc-str (first params))
        (network (rpc-get-network node)))
    (unless (stringp desc-str)
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "descriptor must be a string"))
    (multiple-value-bind (desc input-checksum) (parse-descriptor desc-str network)
      `(("descriptor" . ,(descriptor-add-checksum (out-desc-string desc)))
        ("checksum" . ,input-checksum)
        ("isrange" . ,(json-bool (out-desc-ranged-p desc)))
        ("issolvable" . ,(json-bool (out-desc-solvable-p desc)))
        ("hasprivatekeys" . ,(json-bool (out-desc-has-privkeys-p desc)))))))

(defun rpc-deriveaddresses (node params)
  "Derive the address(es) for a descriptor (Bitcoin Core deriveaddresses).
PARAMS: (descriptor [range]). The descriptor must carry a checksum. RANGE is
required for ranged descriptors (an end N meaning [0,N], or [begin,end]) and
rejected for unranged ones; combo() P2PK scripts are skipped like Core."
  (let* ((desc-str (first params))
         (range (second params))
         (range-given (and (> (length params) 1) (not (null range))))
         (network (rpc-get-network node)))
    (unless (stringp desc-str)
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "descriptor must be a string"))
    (multiple-value-bind (low high)
        (if range-given (%parse-descriptor-range range) (values 0 0))
      (let ((desc (parse-descriptor desc-str network :require-checksum t)))
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
                       (let ((addr (%script->address script network)))
                         (cond (addr (push addr addresses))
                               ;; combo() emits P2PK; Core skips it rather than
                               ;; failing when other scripts have addresses.
                               ((and (> (length scripts) 1) (%script-p2pk-p script)))
                               (t (error 'rpc-error
                                         :code +rpc-invalid-address-or-key+
                                         :message "Descriptor does not have a corresponding address")))))))
          (when (null addresses)
            (error 'rpc-error :code +rpc-misc-error+ :message "Unexpected empty result"))
          (nreverse addresses))))))
