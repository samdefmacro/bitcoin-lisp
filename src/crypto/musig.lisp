(in-package #:bitcoin-lisp.crypto)

;;;; MuSig2 signing (BIP 327) through libsecp256k1's musig module
;;;;
;;;; Core: src/musig.{h,cpp} (MuSig2SecNonce, MuSig2SessionID,
;;;; CreateMuSig2AggregateSig) and CKey::CreateMuSig2Nonce /
;;;; CKey::CreateMuSig2PartialSig (key.cpp:353-472). Every primitive is
;;;; libsecp's; nothing here does field or scalar arithmetic.
;;;;
;;;; ⚠️ Two properties of libsecp that the whole file is shaped around:
;;;;
;;;; 1. A MuSig2 SECRET NONCE MUST NEVER SIGN TWICE. Two partial signatures
;;;;    from one nonce over two different challenges give away the secret
;;;;    key by subtraction. libsecp zeroes the secnonce inside
;;;;    secp256k1_musig_partial_sign, and Core wraps it in a move-only,
;;;;    secure-allocated MuSig2SecNonce that the wallet invalidates the
;;;;    moment it has signed. Here it is a MUSIG-SECNONCE: the secret lives
;;;;    only in foreign memory (never in the Lisp heap, which the GC copies
;;;;    about), the object is TAKEN atomically by the one signing call, and
;;;;    a second use signals MUSIG-SECNONCE-REUSED instead of reaching C.
;;;;
;;;; 2. libsecp's ARG_CHECK calls the ILLEGAL CALLBACK, whose default is
;;;;    abort(3) -- the whole node, not an error. A zeroed (used) secnonce,
;;;;    a secnonce made for another key, and any opaque struct whose magic
;;;;    is wrong all land there (session_impl.h:57-64, :680). So every
;;;;    precondition libsecp would ARG_CHECK is checked HERE first, in Lisp,
;;;;    and refused with a condition: the magic of every opaque object a
;;;;    caller hands back, the secnonce's liveness and its key.
;;;;
;;;; Opaque objects other than the secnonce -- the keyagg cache and the
;;;; session -- are public data and travel as octet vectors of the struct's
;;;; size. Nonces and partial signatures travel SERIALIZED (66 / 32 bytes),
;;;; as Core and the PSBT carry them.

(define-condition musig-secnonce-reused (crypto-error) ()
  (:documentation "A MuSig2 secret nonce was handed to a signing call after
it had already been used (or invalidated). Core's equivalent is the
!secnonce->get().IsValid() refusal in CreateMuSig2PartialSig
(script/sign.cpp:160-161); reaching libsecp instead would abort the process
from its illegal-argument callback, and signing twice would leak the key."))

(defconstant +musig-pubnonce-size+ 66
  "A serialized public nonce: two compressed points (Core MUSIG2_PUBNONCE_SIZE,
musig.h:17). An aggregate nonce serializes to the same size.")

;;; sizeof() of the opaque structs (secp256k1_musig.h:43-98).
(defconstant +musig-secnonce-struct-size+ 132)
(defconstant +musig-pubnonce-struct-size+ 132)
(defconstant +musig-aggnonce-struct-size+ 132)
(defconstant +musig-session-struct-size+ 133)
(defconstant +musig-partial-sig-struct-size+ 36)

(defun %magic (&rest bytes)
  (make-array 4 :element-type '(unsigned-byte 8) :initial-contents bytes))

;;; The first four bytes of each opaque struct, which libsecp ARG_CHECKs on
;;; every load (keyagg_impl.h:19, session_impl.h:48-171).
(defparameter *musig-keyagg-cache-magic* (%magic #xf4 #xad #xbb #xdf))
(defparameter *musig-secnonce-magic* (%magic #x22 #x0e #xdc #xf1))
(defparameter *musig-session-magic* (%magic #x9d #xed #xe9 #x17))

(defun %musig-opaque (bytes size magic what)
  "BYTES as an octet vector when it is a libsecp musig WHAT of SIZE bytes
carrying MAGIC; a CRYPTO-ERROR otherwise, before libsecp's ARG_CHECK could
abort the process over it."
  (let ((v (and (typep bytes 'vector) (%octets bytes))))
    (unless (and v (= (length v) size) (null (mismatch magic v :end2 4)))
      (crypto-error "not a libsecp256k1 musig ~A" what))
    v))

;;; --- FFI (secp256k1_musig.h) ------------------------------------------------

(cffi:defcfun ("secp256k1_musig_pubnonce_parse" secp256k1-musig-pubnonce-parse) :int
  (ctx :pointer) (nonce :pointer) (in66 :pointer))
(cffi:defcfun ("secp256k1_musig_pubnonce_serialize" secp256k1-musig-pubnonce-serialize) :int
  (ctx :pointer) (out66 :pointer) (nonce :pointer))
(cffi:defcfun ("secp256k1_musig_aggnonce_parse" secp256k1-musig-aggnonce-parse) :int
  (ctx :pointer) (nonce :pointer) (in66 :pointer))
(cffi:defcfun ("secp256k1_musig_aggnonce_serialize" secp256k1-musig-aggnonce-serialize) :int
  (ctx :pointer) (out66 :pointer) (nonce :pointer))
(cffi:defcfun ("secp256k1_musig_partial_sig_parse" secp256k1-musig-partial-sig-parse) :int
  (ctx :pointer) (sig :pointer) (in32 :pointer))
(cffi:defcfun ("secp256k1_musig_partial_sig_serialize" secp256k1-musig-partial-sig-serialize) :int
  (ctx :pointer) (out32 :pointer) (sig :pointer))
(cffi:defcfun ("secp256k1_musig_pubkey_ec_tweak_add" secp256k1-musig-pubkey-ec-tweak-add) :int
  (ctx :pointer) (output-pubkey :pointer) (keyagg-cache :pointer) (tweak32 :pointer))
(cffi:defcfun ("secp256k1_musig_pubkey_xonly_tweak_add" secp256k1-musig-pubkey-xonly-tweak-add) :int
  (ctx :pointer) (output-pubkey :pointer) (keyagg-cache :pointer) (tweak32 :pointer))
(cffi:defcfun ("secp256k1_musig_nonce_gen" secp256k1-musig-nonce-gen) :int
  (ctx :pointer) (secnonce :pointer) (pubnonce :pointer) (session-secrand32 :pointer)
  (seckey :pointer) (pubkey :pointer) (msg32 :pointer) (keyagg-cache :pointer)
  (extra-input32 :pointer))
(cffi:defcfun ("secp256k1_musig_nonce_agg" secp256k1-musig-nonce-agg) :int
  (ctx :pointer) (aggnonce :pointer) (pubnonces :pointer) (n-pubnonces :size))
(cffi:defcfun ("secp256k1_musig_nonce_process" secp256k1-musig-nonce-process) :int
  (ctx :pointer) (session :pointer) (aggnonce :pointer) (msg32 :pointer)
  (keyagg-cache :pointer))
(cffi:defcfun ("secp256k1_musig_partial_sign" secp256k1-musig-partial-sign) :int
  (ctx :pointer) (partial-sig :pointer) (secnonce :pointer) (keypair :pointer)
  (keyagg-cache :pointer) (session :pointer))
(cffi:defcfun ("secp256k1_musig_partial_sig_verify" secp256k1-musig-partial-sig-verify) :int
  (ctx :pointer) (partial-sig :pointer) (pubnonce :pointer) (pubkey :pointer)
  (keyagg-cache :pointer) (session :pointer))
(cffi:defcfun ("secp256k1_musig_partial_sig_agg" secp256k1-musig-partial-sig-agg) :int
  (ctx :pointer) (sig64 :pointer) (session :pointer) (partial-sigs :pointer)
  (n-sigs :size))

(defun %foreign-octets (ptr n)
  (let ((out (make-array n :element-type '(unsigned-byte 8))))
    (dotimes (i n out) (setf (aref out i) (cffi:mem-aref ptr :uint8 i)))))

(defun %foreign-zero (ptr n)
  "Overwrite N bytes at PTR with zeros through a foreign call, which no
compiler can prove dead (Core memory_cleanse)."
  (cffi:foreign-funcall "memset" :pointer ptr :int 0 :size n :pointer)
  ptr)

(defun %serialize-compressed (pkobj)
  "The 33-byte compressed serialization of the secp256k1_pubkey at PKOBJ."
  (cffi:with-foreign-objects ((out :uint8 33) (outlen :size))
    (setf (cffi:mem-ref outlen :size) 33)
    (secp256k1-ec-pubkey-serialize *secp256k1-context* out outlen pkobj
                                   +secp256k1-ec-compressed+)
    (%foreign-octets out 33)))

(defmacro %with-parsed-pubkeys ((ptrs block pubkeys &key (on-fail nil)) &body body)
  "Bind PTRS to a foreign array of pointers to the parsed secp256k1_pubkeys of
the list PUBKEYS, laid out in the foreign block BLOCK, around BODY; evaluate
ON-FAIL instead when any key does not parse."
  (let ((n (gensym "N")) (key (gensym "KEY")) (i (gensym "I")) (slot (gensym "SLOT")))
    `(let ((,n (length ,pubkeys)))
       (cffi:with-foreign-objects ((,block :uint8 (* (max 1 ,n) +secp256k1-pubkey-size+))
                                   (,ptrs :pointer (max 1 ,n)))
         (if (loop for ,key in ,pubkeys
                   for ,i from 0
                   for ,slot = (cffi:inc-pointer ,block (* ,i +secp256k1-pubkey-size+))
                   always (let ((,key (%octets ,key)))
                            (cffi:with-pointer-to-vector-data (in ,key)
                              (= 1 (secp256k1-ec-pubkey-parse
                                    *secp256k1-context* ,slot in (length ,key)))))
                   do (setf (cffi:mem-aref ,ptrs :pointer ,i) ,slot))
             (progn ,@body)
             ,on-fail)))))

;;; --- Key aggregation with tweaks --------------------------------------------

(defun musig-keyagg (pubkeys &optional tweaks)
  "BIP327 KeyAgg over PUBKEYS (33-byte keys, in the order given), then each of
TWEAKS -- a list of (TWEAK32 . XONLY-P), applied in order with
secp256k1_musig_pubkey_xonly_tweak_add (a BIP341 TapTweak) or
secp256k1_musig_pubkey_ec_tweak_add (a BIP32 step), as Core's signing
functions apply them (key.cpp:437-445).

Returns (values CACHE AGGREGATE UNTWEAKED): the 197-byte
secp256k1_musig_keyagg_cache every later step needs, the 33-byte compressed
aggregate after TWEAKS, and the one before them. On
failure (values NIL REASON), REASON being :PUBKEY for a key that does not
parse (or no keys at all -- libsecp would ARG_CHECK n_pubkeys > 0), :TWEAK for
a refused tweak, :OTHER otherwise -- the error classes of BIP327's own
vectors."
  (ensure-musig-available)
  (when (null pubkeys) (return-from musig-keyagg (values nil :pubkey)))
  (let ((cache (make-array +secp256k1-musig-keyagg-cache-size+
                           :element-type '(unsigned-byte 8) :initial-element 0)))
    (%with-parsed-pubkeys (ptrs block pubkeys
                           :on-fail (return-from musig-keyagg (values nil :pubkey)))
      (cffi:with-pointer-to-vector-data (cache-ptr cache)
        (flet ((aggregate ()
                 (cffi:with-foreign-object (agg :uint8 +secp256k1-pubkey-size+)
                   (unless (= 1 (secp256k1-musig-pubkey-get *secp256k1-context* agg cache-ptr))
                     (return-from musig-keyagg (values nil :other)))
                   (%serialize-compressed agg))))
          (unless (= 1 (secp256k1-musig-pubkey-agg *secp256k1-context* (cffi:null-pointer)
                                                   cache-ptr ptrs (length pubkeys)))
            (return-from musig-keyagg (values nil :other)))
          (let ((untweaked (aggregate)))
            (loop for (tweak . xonly-p) in tweaks
                  for tw = (%octets tweak)
                  do (unless (and (= (length tw) 32)
                                  (cffi:with-pointer-to-vector-data (tw-ptr tw)
                                    (= 1 (funcall (if xonly-p
                                                      #'secp256k1-musig-pubkey-xonly-tweak-add
                                                      #'secp256k1-musig-pubkey-ec-tweak-add)
                                                  *secp256k1-context* (cffi:null-pointer)
                                                  cache-ptr tw-ptr))))
                       (return-from musig-keyagg (values nil :tweak))))
            (values cache (if tweaks (aggregate) untweaked) untweaked)))))))

;;; --- The secret nonce (Core MuSig2SecNonce, musig.h:24-58) -------------------

(defstruct (musig-secnonce (:constructor %make-musig-secnonce (cell))
                           (:copier nil))
  "A MuSig2 secret nonce in its own foreign allocation (Core MuSig2SecNonce:
secure-allocated, move-only). CELL is a cons whose CAR is the foreign pointer
while the nonce is live and NIL once it has been used or invalidated; the
cons, not this object, is what the GC finalizer holds, so an abandoned nonce
is still zeroed and freed. There is no copier: Core deletes the copy
constructor so a nonce cannot be duplicated."
  (cell nil :type cons))

(defmethod print-object ((sn musig-secnonce) stream)
  (print-unreadable-object (sn stream :type t)
    (princ (if (musig-secnonce-valid-p sn) "live" "used") stream)))

(defun %free-secnonce-memory (ptr)
  (%foreign-zero ptr +musig-secnonce-struct-size+)
  (cffi:foreign-free ptr))

(defun %secnonce-cell-take (cell)
  "Detach the foreign pointer from CELL atomically and return it, or NIL when
it is already gone: whoever gets it owns the memory, and nobody else ever
will -- the one gate the signing call, INVALIDATE and the finalizer share."
  (let ((p (car cell)))
    (and p (eq p (sb-ext:compare-and-swap (car cell) p nil)) p)))

(defun musig-secnonce-adopt (ptr)
  "Wrap the foreign secnonce allocation PTR in a MUSIG-SECNONCE that owns it:
the object frees (after zeroing) the memory when it is taken or invalidated,
and a finalizer does so if it is dropped live."
  (let* ((cell (list ptr))
         (sn (%make-musig-secnonce cell)))
    (sb-ext:finalize sn (lambda ()
                          (let ((p (%secnonce-cell-take cell)))
                            (when p (%free-secnonce-memory p))))
                     :dont-save t)
    sn))

(defun musig-secnonce-valid-p (secnonce)
  "True while SECNONCE has not been used to sign and has not been invalidated
(Core MuSig2SecNonce::IsValid)."
  (and (car (musig-secnonce-cell secnonce)) t))

(defun %take-secnonce (secnonce)
  "The foreign pointer of SECNONCE, atomically detached from it -- after this
the object is invalid, whoever else holds it, and the CALLER owns (and must
zero and free) the memory. Signals MUSIG-SECNONCE-REUSED when it was already
taken: the one gate every signing path passes."
  (or (%secnonce-cell-take (musig-secnonce-cell secnonce))
      (error 'musig-secnonce-reused
             :format-control "MuSig2 secret nonce already used"
             :format-arguments '())))

(defun musig-secnonce-invalidate (secnonce)
  "Zero and free SECNONCE's secret now (Core MuSig2SecNonce::Invalidate).
Idempotent: an already-invalid nonce is left as it is."
  (let ((p (%secnonce-cell-take (musig-secnonce-cell secnonce))))
    (when p (%free-secnonce-memory p))
    nil))

;;; --- The BIP327 steps --------------------------------------------------------

(defun musig-nonce-gen (session-secrand pubkey &key seckey msg keyagg-cache extra)
  "BIP327 NonceGen through secp256k1_musig_nonce_gen: (values SECNONCE
PUBNONCE), the MUSIG-SECNONCE and the 66-byte public nonce, or NIL.

SESSION-SECRAND is 32 bytes that must be uniformly random and never reused;
like libsecp, which overwrites its buffer, this ZEROES the caller's vector on
success so it cannot be reused by accident. PUBKEY is the signer's 33-byte key
-- the nonce can only ever sign for it. SECKEY, MSG (32 bytes) and
KEYAGG-CACHE (from MUSIG-KEYAGG) are optional misuse-resistance inputs, as is
EXTRA (32 bytes). Core passes all of them except EXTRA (key.cpp:372)."
  (ensure-musig-available)
  (let ((rand (%octets session-secrand))
        (pk (%octets pubkey))
        (sk (and seckey (%octets seckey)))
        (msg (and msg (%octets msg)))
        (cache (and keyagg-cache
                    (%musig-opaque keyagg-cache +secp256k1-musig-keyagg-cache-size+
                                   *musig-keyagg-cache-magic* "keyagg cache")))
        (extra (and extra (%octets extra))))
    (unless (and (= (length rand) 32)
                 (or (null sk) (= (length sk) 32))
                 (or (null msg) (= (length msg) 32))
                 (or (null extra) (= (length extra) 32)))
      (crypto-error "musig nonce_gen: every input is 32 bytes"))
    (let ((secnonce (cffi:foreign-alloc :uint8 :count +musig-secnonce-struct-size+
                                               :initial-element 0))
          (ok nil))
      (unwind-protect
           (cffi:with-foreign-objects ((pkobj :uint8 +secp256k1-pubkey-size+)
                                       (pubnonce :uint8 +musig-pubnonce-struct-size+)
                                       (out :uint8 +musig-pubnonce-size+)
                                       (rand-buf :uint8 32))
             (cffi:with-pointer-to-vector-data (pk-ptr pk)
               (unless (= 1 (secp256k1-ec-pubkey-parse *secp256k1-context* pkobj pk-ptr
                                                       (length pk)))
                 (return-from musig-nonce-gen nil)))
             (dotimes (i 32) (setf (cffi:mem-aref rand-buf :uint8 i) (aref rand i)))
             (flet ((call (sk-ptr msg-ptr cache-ptr extra-ptr)
                      (= 1 (secp256k1-musig-nonce-gen *secp256k1-context* secnonce pubnonce
                                                      rand-buf sk-ptr pkobj msg-ptr
                                                      cache-ptr extra-ptr))))
               (macrolet ((maybe ((ptr vec) &body body)
                            `(if ,vec
                                 (cffi:with-pointer-to-vector-data (,ptr ,vec) ,@body)
                                 (let ((,ptr (cffi:null-pointer))) ,@body))))
                 (maybe (sk-ptr sk)
                   (maybe (msg-ptr msg)
                     (maybe (cache-ptr cache)
                       (maybe (extra-ptr extra)
                         (setf ok (call sk-ptr msg-ptr cache-ptr extra-ptr))))))))
             (%foreign-zero rand-buf 32)
             (when ok
               (fill rand 0)
               (secp256k1-musig-pubnonce-serialize *secp256k1-context* out pubnonce)
               (let ((sn (musig-secnonce-adopt secnonce)))
                 (setf secnonce nil)
                 (values sn (%foreign-octets out +musig-pubnonce-size+)))))
        (when secnonce (%free-secnonce-memory secnonce))))))

(defun %parse-pubnonce-into (slot nonce66)
  (let ((n (and (typep nonce66 'vector) (%octets nonce66))))
    (and n (= (length n) +musig-pubnonce-size+)
         (cffi:with-pointer-to-vector-data (in n)
           (= 1 (secp256k1-musig-pubnonce-parse *secp256k1-context* slot in))))))

(defun musig-nonce-agg (pubnonces)
  "BIP327 NonceAgg: the 66-byte aggregate of the list of 66-byte PUBNONCES,
or (values NIL INDEX) naming the first nonce that does not parse."
  (ensure-musig-available)
  (let ((n (length pubnonces)))
    (when (zerop n) (return-from musig-nonce-agg (values nil 0)))
    (cffi:with-foreign-objects ((block :uint8 (* n +musig-pubnonce-struct-size+))
                                (ptrs :pointer n)
                                (agg :uint8 +musig-aggnonce-struct-size+)
                                (out :uint8 +musig-pubnonce-size+))
      (loop for nonce in pubnonces
            for i from 0
            for slot = (cffi:inc-pointer block (* i +musig-pubnonce-struct-size+))
            do (unless (%parse-pubnonce-into slot nonce)
                 (return-from musig-nonce-agg (values nil i)))
               (setf (cffi:mem-aref ptrs :pointer i) slot))
      (unless (= 1 (secp256k1-musig-nonce-agg *secp256k1-context* agg ptrs n))
        (return-from musig-nonce-agg nil))
      (secp256k1-musig-aggnonce-serialize *secp256k1-context* out agg)
      (%foreign-octets out +musig-pubnonce-size+))))

(defun musig-nonce-process (aggnonce msg keyagg-cache)
  "BIP327 session context: the 133-byte secp256k1_musig_session for the
66-byte AGGNONCE, the 32-byte MSG and KEYAGG-CACHE (its tweaks included), or
NIL when the aggregate nonce does not parse."
  (ensure-musig-available)
  (let ((agg (%octets aggnonce))
        (msg (%octets msg))
        (cache (%musig-opaque keyagg-cache +secp256k1-musig-keyagg-cache-size+
                              *musig-keyagg-cache-magic* "keyagg cache"))
        (session (make-array +musig-session-struct-size+
                             :element-type '(unsigned-byte 8) :initial-element 0)))
    (unless (= (length msg) 32) (crypto-error "musig message must be 32 bytes"))
    (unless (= (length agg) +musig-pubnonce-size+) (return-from musig-nonce-process nil))
    (cffi:with-foreign-object (aggobj :uint8 +musig-aggnonce-struct-size+)
      (cffi:with-pointer-to-vector-data (in agg)
        (unless (= 1 (secp256k1-musig-aggnonce-parse *secp256k1-context* aggobj in))
          (return-from musig-nonce-process nil)))
      (cffi:with-pointer-to-vector-data (s-ptr session)
        (cffi:with-pointer-to-vector-data (m-ptr msg)
          (cffi:with-pointer-to-vector-data (c-ptr cache)
            (and (= 1 (secp256k1-musig-nonce-process *secp256k1-context* s-ptr aggobj
                                                     m-ptr c-ptr))
                 session)))))))

(defun %secnonce-signs-for-p (ptr pkobj)
  "Whether the secnonce at PTR is live and was made for the parsed pubkey at
PKOBJ: exactly what secp256k1_musig_partial_sign ARG_CHECKs (the magic, a
non-zero k1||k2, and pk == the keypair's key, session_impl.h:57-64, :680) and
answers with abort(). Only a boolean leaves the secret half."
  (and (loop for i below 4
             always (= (cffi:mem-aref ptr :uint8 i) (aref *musig-secnonce-magic* i)))
       (loop for i from 4 below 68
               thereis (/= 0 (cffi:mem-aref ptr :uint8 i)))
       (loop for i below +secp256k1-pubkey-size+
             always (= (cffi:mem-aref ptr :uint8 (+ 68 i)) (cffi:mem-aref pkobj :uint8 i)))))

(defun musig-partial-sign (secnonce seckey keyagg-cache session)
  "BIP327 Sign: the 32-byte partial signature of the signer holding SECKEY for
SESSION, or NIL. SECNONCE is USED UP by this call whatever it returns --
libsecp zeroes it before it can fail (session_impl.h:662-666), so it is taken
first and freed after; a second call signals MUSIG-SECNONCE-REUSED.

A secnonce that was made for another key is refused (NIL) before libsecp sees
it, as is one whose contents are not a live secnonce: libsecp answers both
with its illegal-argument callback, which aborts the process."
  (ensure-musig-available)
  (let ((sk (%octets seckey))
        (cache (%musig-opaque keyagg-cache +secp256k1-musig-keyagg-cache-size+
                              *musig-keyagg-cache-magic* "keyagg cache"))
        (session (%musig-opaque session +musig-session-struct-size+
                                *musig-session-magic* "session"))
        (ptr (%take-secnonce secnonce)))
    (unwind-protect
         (cffi:with-foreign-objects ((keypair :uint8 +secp256k1-keypair-size+)
                                     (pkobj :uint8 +secp256k1-pubkey-size+)
                                     (psig :uint8 +musig-partial-sig-struct-size+)
                                     (out :uint8 32))
           (when (and (= (length sk) 32)
                      (cffi:with-pointer-to-vector-data (sk-ptr sk)
                        (= 1 (secp256k1-keypair-create *secp256k1-context* keypair sk-ptr)))
                      (let ((pub (derive-public-key sk)))
                        (cffi:with-pointer-to-vector-data (in pub)
                          (= 1 (secp256k1-ec-pubkey-parse *secp256k1-context* pkobj in 33))))
                      (%secnonce-signs-for-p ptr pkobj)
                      (cffi:with-pointer-to-vector-data (c-ptr cache)
                        (cffi:with-pointer-to-vector-data (s-ptr session)
                          (= 1 (secp256k1-musig-partial-sign *secp256k1-context* psig ptr
                                                             keypair c-ptr s-ptr)))))
             (secp256k1-musig-partial-sig-serialize *secp256k1-context* out psig)
             (%foreign-octets out 32)))
      (%free-secnonce-memory ptr))))

(defun %parse-partial-sig-into (slot psig32)
  (let ((s (and (typep psig32 'vector) (%octets psig32))))
    (and s (= (length s) 32)
         (cffi:with-pointer-to-vector-data (in s)
           (= 1 (secp256k1-musig-partial-sig-parse *secp256k1-context* slot in))))))

(defun musig-partial-sig-verify (psig pubnonce pubkey keyagg-cache session)
  "BIP327 PartialSigVerifyInternal: whether the 32-byte PSIG is the partial
signature of the signer with 33-byte PUBKEY and 66-byte PUBNONCE in SESSION
under KEYAGG-CACHE. NIL, never an error, for a PSIG, PUBNONCE or PUBKEY that
does not parse."
  (ensure-musig-available)
  (let ((cache (%musig-opaque keyagg-cache +secp256k1-musig-keyagg-cache-size+
                              *musig-keyagg-cache-magic* "keyagg cache"))
        (session (%musig-opaque session +musig-session-struct-size+
                                *musig-session-magic* "session"))
        (pk (%octets pubkey)))
    (cffi:with-foreign-objects ((psigobj :uint8 +musig-partial-sig-struct-size+)
                                (nonceobj :uint8 +musig-pubnonce-struct-size+)
                                (pkobj :uint8 +secp256k1-pubkey-size+))
      (and (%parse-partial-sig-into psigobj psig)
           (%parse-pubnonce-into nonceobj pubnonce)
           (cffi:with-pointer-to-vector-data (in pk)
             (= 1 (secp256k1-ec-pubkey-parse *secp256k1-context* pkobj in (length pk))))
           (cffi:with-pointer-to-vector-data (c-ptr cache)
             (cffi:with-pointer-to-vector-data (s-ptr session)
               (= 1 (secp256k1-musig-partial-sig-verify *secp256k1-context* psigobj nonceobj
                                                        pkobj c-ptr s-ptr))))))))

(defun musig-partial-sig-agg (session psigs)
  "BIP327 PartialSigAgg: the 64-byte BIP340 signature the list of 32-byte
PSIGS add up to in SESSION -- which does NOT by itself mean it verifies -- or
(values NIL INDEX) naming the first partial signature that does not parse."
  (ensure-musig-available)
  (let ((session (%musig-opaque session +musig-session-struct-size+
                                *musig-session-magic* "session"))
        (n (length psigs)))
    (when (zerop n) (return-from musig-partial-sig-agg (values nil 0)))
    (cffi:with-foreign-objects ((block :uint8 (* n +musig-partial-sig-struct-size+))
                                (ptrs :pointer n)
                                (sig :uint8 64))
      (loop for psig in psigs
            for i from 0
            for slot = (cffi:inc-pointer block (* i +musig-partial-sig-struct-size+))
            do (unless (%parse-partial-sig-into slot psig)
                 (return-from musig-partial-sig-agg (values nil i)))
               (setf (cffi:mem-aref ptrs :pointer i) slot))
      (cffi:with-pointer-to-vector-data (s-ptr session)
        (and (= 1 (secp256k1-musig-partial-sig-agg *secp256k1-context* sig s-ptr ptrs n))
             (%foreign-octets sig 64))))))

;;; --- Core's signer-side functions (key.cpp, musig.cpp) -----------------------

(defun %musig-keyagg-matching (pubkeys aggregate-pubkey &optional tweaks)
  "Core MuSig2AggregatePubkeys with an expected aggregate (musig.cpp:54-63),
followed by TWEAKS: the keyagg cache of PUBKEYS when their UNTWEAKED
aggregate IS AGGREGATE-PUBKEY, else NIL."
  (multiple-value-bind (cache agg untweaked) (musig-keyagg pubkeys tweaks)
    (declare (ignore agg))
    (and cache (equalp untweaked aggregate-pubkey) cache)))

(defun musig2-session-id (script-pubkey participant-pubkey sighash)
  "Core MuSig2SessionID (musig.cpp:165-170): SHA256 of the two keys as
serialized CPubKeys -- each behind its CompactSize length -- and the 32-byte
sighash. The key a signing session's secret nonce is kept under."
  (flet ((ser (key) (concatenate '(vector (unsigned-byte 8)) (vector (length key)) key)))
    (sha256 (%octets (concatenate '(vector (unsigned-byte 8))
                                  (ser script-pubkey) (ser participant-pubkey) sighash)))))

(defun musig2-create-nonce (seckey sighash aggregate-pubkey pubkeys)
  "Core CKey::CreateMuSig2Nonce (key.cpp:353-384): a fresh nonce for the
signer holding SECKEY in the session over SIGHASH among PUBKEYS, whose
aggregate must be AGGREGATE-PUBKEY. Returns (values PUBNONCE SECNONCE), or NIL.

Exactly Core's inputs to secp256k1_musig_nonce_gen: 32 bytes from the OS
source as session_secrand, the secret key, the signer's pubkey, the sighash as
the message and the UNTWEAKED keyagg cache, and no extra input."
  (let ((cache (%musig-keyagg-matching pubkeys aggregate-pubkey)))
    (when cache
      (multiple-value-bind (secnonce pubnonce)
          (musig-nonce-gen (ironclad:random-data 32) (derive-public-key seckey)
                           :seckey seckey :msg sighash :keyagg-cache cache)
        (when secnonce (values pubnonce secnonce))))))

(defun %musig2-session (sighash aggregate-pubkey pubkeys pubnonces tweaks)
  "The half CreateMuSig2PartialSig and CreateMuSig2AggregateSig share
(key.cpp:392-452, musig.cpp:177-194): the cache of PUBKEYS checked against
AGGREGATE-PUBKEY, one nonce per participant looked up in the alist PUBNONCES,
their aggregate, TWEAKS applied, and the session over SIGHASH. Returns
(values CACHE SESSION NONCES) with NONCES in participant order, or NIL."
  (let ((cache (%musig-keyagg-matching pubkeys aggregate-pubkey tweaks)))
    (when (and cache (= (length pubnonces) (length pubkeys)))
      (let* ((nonces (loop for pk in pubkeys
                           for entry = (assoc pk pubnonces :test #'equalp)
                           unless (and entry (= (length (cdr entry)) +musig-pubnonce-size+))
                             do (return-from %musig2-session nil)
                           collect (cdr entry)))
             (aggnonce (musig-nonce-agg nonces))
             (session (and aggnonce (musig-nonce-process aggnonce sighash cache))))
        (when session (values cache session nonces))))))

(defun musig2-create-partial-sig (seckey sighash aggregate-pubkey pubkeys pubnonces
                                  secnonce tweaks)
  "Core CKey::CreateMuSig2PartialSig (key.cpp:386-472): the 32-byte partial
signature over SIGHASH of the participant holding SECKEY, or NIL. PUBNONCES is
an alist participant-pubkey -> 66-byte nonce with exactly one entry per member
of PUBKEYS; TWEAKS the (TWEAK32 . XONLY-P) list SignMuSig2 derived.

SECNONCE is consumed once signing is reached (Core invalidates it right after
secp256k1_musig_partial_sign) and survives every earlier refusal, as in Core.
The result is verified against our own nonce before it is returned; a
signature that does not verify is NIL, with the nonce spent."
  (let* ((our (derive-public-key seckey))
         (idx (position our pubkeys :test #'equalp)))
    (when idx
      (multiple-value-bind (cache session nonces)
          (%musig2-session sighash aggregate-pubkey pubkeys pubnonces tweaks)
        (when session
          (let ((psig (musig-partial-sign secnonce seckey cache session)))
            (when (and psig (musig-partial-sig-verify psig (nth idx nonces) our cache session))
              psig)))))))

(defun musig2-create-aggregate-sig (participants aggregate-pubkey tweaks sighash
                                    pubnonces partial-sigs)
  "Core CreateMuSig2AggregateSig (musig.cpp:172-213): the 64-byte signature
of the aggregate once every one of PARTICIPANTS has a nonce in the alist
PUBNONCES and a partial signature in the alist PARTIAL-SIGS, each partial
signature verified first; NIL otherwise."
  (when (and participants (= (length partial-sigs) (length participants)))
    (multiple-value-bind (cache session nonces)
        (%musig2-session sighash aggregate-pubkey participants pubnonces tweaks)
      (when session
        (let ((psigs (loop for pk in participants
                           for nonce in nonces
                           for entry = (assoc pk partial-sigs :test #'equalp)
                           unless (and entry
                                       (musig-partial-sig-verify (cdr entry) nonce pk
                                                                 cache session))
                             do (return-from musig2-create-aggregate-sig nil)
                           collect (cdr entry))))
          (musig-partial-sig-agg session psigs))))))

;;; --- BIP328: deriving from an aggregate key ----------------------------------

(defparameter *musig2-chaincode*
  (hex-to-bytes "868087ca02a6f974c4598924c36b57762d32cb45717167e300622c7167e38965")
  "BIP328's fixed chaincode for the synthetic xpub over a MuSig2 aggregate
(Core MUSIG_CHAINCODE, musig.cpp:12). A real xpub's chaincode carries entropy
from its parent; an aggregate has no parent, so BIP328 fixes one and every
implementation derives the same children. A DEFPARAMETER, not a constant: a
vector is never EQL to its reloaded self.")

(defun musig2-synthetic-xpub (aggregate-pubkey &optional (version 0))
  "The BIP328 synthetic xpub over the 33-byte AGGREGATE-PUBKEY: depth 0, zero
fingerprint, child 0, the fixed MuSig2 chaincode (Core
CreateMuSig2SyntheticXpub, musig.cpp:71). VERSION only matters to a caller
that serializes it. A derivation ROOT, not a key anyone published."
  (make-ext-key :version version :depth 0 :parent-fingerprint 0 :child-number 0
                :chain-code (copy-seq *musig2-chaincode*)
                :key (%octets aggregate-pubkey) :privatep nil))

(defun musig2-derivation-tweaks (aggregate-pubkey path)
  "SignMuSig2's BIP32 half (script/sign.cpp:298-311): walk PATH (a list of
child numbers) down from AGGREGATE-PUBKEY's synthetic xpub, collecting each
step's IL as a PLAIN tweak. Returns (values TWEAKS DERIVED-PUBKEY) -- TWEAKS a
list of (TWEAK32 . NIL) for MUSIG-KEYAGG -- or NIL when a step is hardened or
invalid (Core's `if (!extpub.Derive(...)) return false')."
  (let ((k (musig2-synthetic-xpub aggregate-pubkey))
        (tweaks '()))
    (dolist (i path (values (nreverse tweaks) (ext-key-key k)))
      (when (>= i +bip32-hardened+) (return-from musig2-derivation-tweaks nil))
      (multiple-value-bind (child il) (ignore-errors (bip32-derive-child k i))
        (unless child (return-from musig2-derivation-tweaks nil))
        (push (cons il nil) tweaks)
        (setf k child)))))
