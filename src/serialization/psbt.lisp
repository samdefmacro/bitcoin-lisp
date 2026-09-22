(in-package #:bitcoin-lisp.serialization)

;;;; BIP174 Partially Signed Bitcoin Transactions (PSBT)
;;;;
;;;; A PSBT is: magic (0x70 0x73 0x62 0x74 0xff), a global key-value map, then
;;;; one key-value map per transaction input, then one per output; every map is
;;;; terminated by a 0x00 separator (a zero-length key). Each record on the wire
;;;; is  <keylen CS><keytype CS + keydata><valuelen CS><value>. PSBTs are
;;;; exchanged base64-encoded. Mirrors Bitcoin Core src/psbt.{h,cpp}.
;;;;
;;;; We keep every map as an ordered list of raw (key-bytes . value-bytes)
;;;; records, so any PSBT round-trips byte-for-byte -- including fields we don't
;;;; interpret (taproot, musig, proprietary). Typed accessors interpret records
;;;; on demand, and record union by full key is exactly Core's Combine.

(defparameter *psbt-magic*
  (make-array 5 :element-type '(unsigned-byte 8)
                :initial-contents '(#x70 #x73 #x62 #x74 #xff))
  "The 5-byte PSBT magic prefix.")

;; Global key types.
(defconstant +psbt-global-unsigned-tx+ #x00)
(defconstant +psbt-global-xpub+ #x01)
(defconstant +psbt-global-version+ #xfb)
(defconstant +psbt-global-proprietary+ #xfc)

(defconstant +psbt-highest-version+ 0
  "Core PSBT_HIGHEST_VERSION (psbt.h:80): the highest PSBT_GLOBAL_VERSION this
decoder understands. A PSBT declaring more is refused, not read as a v0.")

;; Input key types.
(defconstant +psbt-in-non-witness-utxo+ #x00)
(defconstant +psbt-in-witness-utxo+ #x01)
(defconstant +psbt-in-partial-sig+ #x02)
(defconstant +psbt-in-sighash+ #x03)
(defconstant +psbt-in-redeem-script+ #x04)
(defconstant +psbt-in-witness-script+ #x05)
(defconstant +psbt-in-bip32+ #x06)
(defconstant +psbt-in-final-scriptsig+ #x07)
(defconstant +psbt-in-final-scriptwitness+ #x08)
(defconstant +psbt-in-ripemd160+ #x0a)
(defconstant +psbt-in-sha256+ #x0b)
(defconstant +psbt-in-hash160+ #x0c)
(defconstant +psbt-in-hash256+ #x0d)
(defconstant +psbt-in-tap-key-sig+ #x13)
(defconstant +psbt-in-tap-script-sig+ #x14)
(defconstant +psbt-in-tap-leaf-script+ #x15)
(defconstant +psbt-in-tap-bip32+ #x16)
(defconstant +psbt-in-tap-internal-key+ #x17)
(defconstant +psbt-in-tap-merkle-root+ #x18)
;;; MuSig2 (BIP373). Keydata layouts, from Core psbt.h:414-445:
;;;   PARTICIPANT_PUBKEYS  <33-byte aggregate>            value: n * 33 bytes
;;;   PUB_NONCE            <33 participant><33 aggregate>[<32 leaf hash>]
;;;   PARTIAL_SIG          <33 participant><33 aggregate>[<32 leaf hash>]
;;; The leaf hash is present for a script-path signature and absent for a key
;;; path, which is what makes the keydata length the discriminator.
(defconstant +psbt-in-musig2-participant-pubkeys+ #x1a)
(defconstant +psbt-in-musig2-pub-nonce+ #x1b)
(defconstant +psbt-in-musig2-partial-sig+ #x1c)
(defconstant +psbt-in-proprietary+ #xfc)

;; Output key types.
(defconstant +psbt-out-redeem-script+ #x00)
(defconstant +psbt-out-witness-script+ #x01)
(defconstant +psbt-out-bip32+ #x02)
(defconstant +psbt-out-tap-internal-key+ #x05)
(defconstant +psbt-out-tap-tree+ #x06)
(defconstant +psbt-out-tap-bip32+ #x07)
(defconstant +psbt-out-musig2-participant-pubkeys+ #x08)
(defconstant +psbt-out-proprietary+ #xfc)

(defstruct psbt-map
  "One PSBT key-value map (global, per-input, or per-output) as an ordered list
of raw (key-bytes . value-bytes) records."
  (records '() :type list))

(defstruct psbt
  "A parsed PSBT: the unsigned transaction plus the global/input/output maps."
  (tx nil)                          ; the unsigned transaction
  (global (make-psbt-map) :type psbt-map)
  (inputs #() :type simple-vector)  ; vector of psbt-map, one per tx input
  (outputs #() :type simple-vector)); vector of psbt-map, one per tx output

;;; --- record helpers ---

(defun psbt-key-type (key-bytes)
  "Return (values keytype keydata-offset) for a record key."
  (let ((br (make-byte-reader-from key-bytes)))
    (values (br-read-compact-size br) (br-pos br))))

(defun psbt-make-record (keytype keydata value)
  "Build a raw record (key-bytes . value-bytes) from a KEYTYPE (a small int),
KEYDATA (byte vector, may be empty) and VALUE (byte vector)."
  (let ((bb (make-byte-buf)))
    (bb-write-varint bb keytype)
    (when (plusp (length keydata)) (bb-write-bytes bb keydata))
    (cons (bb-finish bb) value)))

(defun psbt-map-find (map keytype)
  "The value bytes of the first record of KEYTYPE in MAP, or NIL."
  (dolist (rec (psbt-map-records map))
    (when (= (psbt-key-type (car rec)) keytype)
      (return (cdr rec)))))

(defun psbt-map-collect (map keytype)
  "List of (keydata . value) for every record of KEYTYPE in MAP."
  (let ((out '()))
    (dolist (rec (psbt-map-records map) (nreverse out))
      (multiple-value-bind (kt off) (psbt-key-type (car rec))
        (when (= kt keytype)
          (push (cons (subseq (car rec) off) (cdr rec)) out))))))

(defun psbt-map-set (map keytype keydata value)
  "Add or replace (by full key) a record of KEYTYPE/KEYDATA with VALUE in MAP."
  (let* ((rec (psbt-make-record keytype keydata value))
         (key (car rec)))
    (setf (psbt-map-records map)
          (append (remove key (psbt-map-records map) :key #'car :test #'equalp)
                  (list rec)))))

(defun psbt-map-remove-type (map keytype)
  "Remove every record of KEYTYPE from MAP."
  (setf (psbt-map-records map)
        (remove keytype (psbt-map-records map)
                :key (lambda (rec) (psbt-key-type (car rec))))))

;;; --- parse ---

(defun %psbt-validate-key (context keytype keydata-len)
  "Reject a known KEYTYPE whose key-data length is illegal for its map CONTEXT
(:global/:input/:output). Singleton types must carry no key data; keyed types
(partial sigs, derivations, preimages) must. Unknown/proprietary types are
unconstrained (preserved verbatim)."
  (flet ((empty () (when (plusp keydata-len)
                     (serialization-error "PSBT key type ~D must have empty key data" keytype)))
         (nonempty () (when (zerop keydata-len)
                        (serialization-error "PSBT key type ~D requires key data" keytype)))
         (exactly (n) (when (/= keydata-len n)
                        (serialization-error "PSBT key type ~D key data must be ~D bytes"
                                             keytype n)))
         (control-block ()
           (unless (and (>= keydata-len 33) (zerop (mod (1- keydata-len) 32)))
             (serialization-error
              "PSBT taproot leaf script key's control block size is not valid"))))
    (ecase context
      (:global (case keytype ((#x00 #xfb) (empty)) (#x01 (nonempty))))
      (:input (case keytype
                ((#x00 #x01 #x03 #x04 #x05 #x07 #x08 #x13 #x17 #x18) (empty))
                ((#x02 #x06 #x0a #x0b #x0c #x0d) (nonempty))
                (#x14 (exactly 64))    ; x-only pubkey + leaf hash
                (#x15 (control-block))
                (#x16 (exactly 32))))  ; x-only pubkey
      (:output (case keytype
                 ((#x00 #x01 #x05 #x06) (empty))
                 (#x02 (nonempty))
                 (#x07 (exactly 32)))))))

(defun %psbt-validate-value (context keytype value-len)
  "Reject a known KEYTYPE whose VALUE length is illegal for its map CONTEXT.

Core reads each of these into a fixed-width object, so the length is part of
the format and not a policy: a taproot signature is 64 bytes, or 65 with the
sighash byte appended (psbt.h:699-703 and :720-724); an x-only key or a merkle
root read through UnserializeFromVector is 32 and that reader refuses any
other length (:778, :788, :1029); a leaf script carries at least its one-byte
leaf version (:739-741)."
  (flet ((signature ()
           (unless (<= 64 value-len 65)
             (serialization-error "PSBT taproot signature must be 64 or 65 bytes")))
         (thirty-two ()
           (when (/= value-len 32)
             (serialization-error "PSBT taproot key type ~D value must be 32 bytes"
                                  keytype)))
         (at-least-one ()
           (when (zerop value-len)
             (serialization-error "PSBT taproot leaf script must be at least 1 byte"))))
    (ecase context
      (:global)
      (:input (case keytype
                ((#x13 #x14) (signature))
                (#x15 (at-least-one))
                ((#x17 #x18) (thirty-two))))
      (:output (case keytype (#x05 (thirty-two)))))))

(defun %psbt-tap-bip32-check (side value)
  "Core's PSBT_{IN,OUT}_TAP_BIP32_DERIVATION value reader (psbt.h:755-768,
:1075-1085): a compact-size count of 32-byte leaf hashes, then a key origin of
the REST of the stated length. The hashes are read first, so a count whose
hashes would overrun the value is \"<Side> Taproot BIP32 keypath has an
invalid length\", and the origin that remains must be a non-empty multiple of
four (DeserializeKeyOrigin, psbt.h:124-129)."
  (let* ((br (make-byte-reader-from value))
         (hashes-len (handler-case
                         (let* ((n (br-read-compact-size br))
                                (prefix (br-pos br)))
                           (+ prefix (* 32 n)))
                       (error () (1+ (length value))))))
    (when (> hashes-len (length value))
      (serialization-error "~A Taproot BIP32 keypath has an invalid length" side))
    (let ((origin-len (- (length value) hashes-len)))
      (when (or (zerop origin-len) (plusp (mod origin-len 4)))
        (serialization-error "Invalid length for HD key path")))))

(defun %psbt-tap-tree-check (value)
  "Core's PSBT_OUT_TAP_TREE reader (psbt.h:1036-1070): a non-empty run of
<depth><leaf version><compact-size script> leaves, each at most 128 deep with a
valid leaf version, that together make a COMPLETE binary tree -- the
TaprootBuilder Insert/IsComplete walk (script/signingprovider.cpp:411-431),
kept here as which depths currently hold a pending node."
  (when (zerop (length value))
    (serialization-error "Output Taproot tree must not be empty"))
  (let ((br (make-byte-reader-from value))
        (branch (make-array 0 :adjustable t :fill-pointer t))
        (valid t))
    (loop until (br-eof-p br)
          do (let ((depth (br-read-u8 br))
                   (leaf-ver (br-read-u8 br)))
               (br-read-var-bytes br)
               (when (> depth 128)
                 (serialization-error
                  "Output Taproot tree has as leaf greater than Taproot maximum depth"))
               (unless (zerop (logand leaf-ver 1))
                 (serialization-error
                  "Output Taproot tree has a leaf with an invalid leaf version"))
               (when valid
                 (if (< (1+ depth) (length branch))
                     (setf valid nil)
                     (progn
                       (loop while (and valid (> (length branch) depth)
                                        (aref branch depth))
                             do (vector-pop branch)
                                (when (zerop depth) (setf valid nil))
                                (decf depth))
                       (when valid
                         (loop while (<= (length branch) depth)
                               do (vector-push-extend nil branch))
                         (setf (aref branch depth) t)))))))
    (unless (and valid (or (zerop (length branch))
                           (and (= 1 (length branch)) (aref branch 0))))
      (serialization-error "Output Taproot tree is malformed"))))

(defun %psbt-musig2-participants-check (side keydata value)
  "Core DeserializeMuSig2ParticipantPubkeys (psbt.h:203-231) behind the
34-byte key check of PSBT_{IN,OUT}_MUSIG2_PARTICIPANT_PUBKEYS (:791-798,
:1088-1095): the key is a valid 33-byte aggregate, the value whole 33-byte
valid participants."
  (unless (= (length keydata) 33)
    (serialization-error
     "~A musig2 participants pubkeys aggregate key is not 34 bytes" side))
  (unless (bl.crypto:public-key-valid-p keydata)
    (serialization-error "~A musig2 aggregate pubkey is invalid" side))
  (loop for i from 0 to (- (length value) 33) by 33
        unless (bl.crypto:public-key-valid-p (subseq value i (+ i 33)))
          do (serialization-error "~A musig2 participant pubkey is invalid" side))
  (unless (zerop (mod (length value) 33))
    (serialization-error
     "~A musig2 participants pubkeys value size is not a multiple of 33" side)))

(defun %psbt-musig2-session-check (what keydata value)
  "PSBT_IN_MUSIG2_PUB_NONCE / _PARTIAL_SIG (Core psbt.h:801-836): key data is
<participant 33><aggregate 33>[<leaf hash 32>], the aggregate checked first
(DeserializeMuSig2ParticipantDataIdentifier, :237-256); a nonce is 66 bytes, a
partial signature one 32-byte UnserializeFromVector."
  (unless (member (length keydata) '(66 98))
    (serialization-error
     "Input musig2 ~A key is not expected size of 67 or 99 bytes" what))
  (unless (bl.crypto:public-key-valid-p (subseq keydata 33 66))
    (serialization-error "musig2 aggregate pubkey is invalid"))
  (unless (bl.crypto:public-key-valid-p (subseq keydata 0 33))
    (serialization-error "musig2 participant pubkey is invalid"))
  (if (string= what "pubnonce")
      (unless (= (length value) 66)
        (serialization-error "Input musig2 pubnonce value is not 66 bytes"))
      (unless (= (length value) 32)
        (serialization-error "Size of value was not the stated size"))))

(defun %psbt-validate-content (context keytype keydata value)
  "The typed-value readers Core runs on the taproot-derivation, taproot-tree
and MuSig2 records at parse time, with their own error sentences."
  (case context
    (:input (case keytype
              (#x16 (%psbt-tap-bip32-check "Input" value))
              (#x1a (%psbt-musig2-participants-check "Input" keydata value))
              (#x1b (%psbt-musig2-session-check "pubnonce" keydata value))
              (#x1c (%psbt-musig2-session-check "partial sig" keydata value))))
    (:output (case keytype
               (#x06 (%psbt-tap-tree-check value))
               (#x07 (%psbt-tap-bip32-check "Output" value))
               (#x08 (%psbt-musig2-participants-check "Output" keydata value))))))

(defun %psbt-read-map (br context)
  "Read records from BR until the 0x00 separator; return a psbt-map. CONTEXT is
:global/:input/:output for per-key validation. Signals on a duplicate key or an
illegal key-data length (Core rejects those)."
  (let ((records '()))
    (loop
      (let ((keylen (br-read-compact-size br)))
        (when (zerop keylen) (return))
        (let ((key (br-read-bytes br keylen))
              (value (br-read-var-bytes br)))
          (when (member key records :key #'car :test #'equalp)
            (serialization-error "Duplicate key in PSBT map"))
          (multiple-value-bind (kt off) (psbt-key-type key)
            (%psbt-validate-key context kt (- (length key) off))
            (%psbt-validate-value context kt (length value))
            (%psbt-validate-content context kt (subseq key off) value))
          (push (cons key value) records))))
    (make-psbt-map :records (nreverse records))))

(defun %psbt-read-unsigned-tx (bytes)
  "Read a legacy (no-witness) transaction from BYTES with NO witness
auto-detection. The PSBT unsigned tx is always TX_NO_WITNESS; a tx with zero
inputs would otherwise have its 0x00 input-count misread as the segwit marker."
  (let* ((br (make-byte-reader-from bytes))
         (version (br-read-i32-le br))
         (nin (br-read-compact-size br))
         (inputs (make-array nin)))
    (dotimes (i nin) (setf (aref inputs i) (br-read-tx-in br)))
    (let* ((nout (br-read-compact-size br))
           (outputs (make-array nout)))
      (dotimes (i nout) (setf (aref outputs i) (br-read-tx-out br)))
      (let ((lock-time (br-read-u32-le br)))
        (unless (br-eof-p br)
          (serialization-error "PSBT unsigned transaction has trailing/witness data"))
        (make-transaction :version version :inputs inputs :outputs outputs
                          :lock-time lock-time :witness nil)))))

(defun %psbt-validate-input (map tx-in)
  "Field-content checks on one input map that Core enforces at parse time."
  (let ((sh (psbt-map-find map +psbt-in-sighash+)))
    (when (and sh (/= (length sh) 4))
      (serialization-error "PSBT input sighash type must be 4 bytes")))
  (let ((wu (psbt-map-find map +psbt-in-witness-utxo+)))
    (when wu
      (let ((br (make-byte-reader-from wu)))
        (br-read-tx-out br)
        (unless (br-eof-p br) (serialization-error "PSBT witness_utxo has trailing data")))))
  (let ((nwu (psbt-map-find map +psbt-in-non-witness-utxo+)))
    (when nwu
      (let* ((br (make-byte-reader-from nwu))
             (prev (br-read-transaction br))
             (prevout (tx-in-previous-output tx-in)))
        (unless (br-eof-p br)
          (serialization-error "PSBT non_witness_utxo has trailing data"))
        (unless (equalp (transaction-hash prev) (outpoint-hash prevout))
          (serialization-error "PSBT non_witness_utxo does not match the input outpoint"))
        ;; The outpoint must name an output the previous transaction actually
        ;; has (Core psbt.h:1375-1377). Without this a PSBT can claim an index
        ;; past the end of its own authenticated previous tx, and every
        ;; consumer that resolves the prevout falls back to the UNAUTHENTICATED
        ;; witness_utxo instead.
        (unless (< (outpoint-index prevout) (length (transaction-outputs prev)))
          (serialization-error "Input specifies output index that does not exist")))))
  (dolist (ps (psbt-map-collect map +psbt-in-partial-sig+))
    (unless (member (length (car ps)) '(33 65))
      (serialization-error "PSBT partial signature has an invalid public key")))
  (dolist (d (psbt-map-collect map +psbt-in-bip32+))
    (unless (member (length (car d)) '(33 65))
      (serialization-error "PSBT input BIP32 derivation has an invalid public key"))))

(defun %psbt-validate-output (map)
  "Field-content checks on one output map that Core enforces at parse time.

The BIP32 keypath key is a PUBKEY, so DeserializeHDKeypaths refuses any size
but 33 or 65 (Core psbt.h:1018) -- the same rule the input side has always had
here. Without it a 32-byte key, which is what an x-only taproot key looks
like, was read as an ECDSA derivation."
  (dolist (d (psbt-map-collect map +psbt-out-bip32+))
    (unless (member (length (car d)) '(33 65))
      (serialization-error "PSBT output BIP32 derivation has an invalid public key"))))

(defun parse-psbt (bytes)
  "Parse a binary PSBT. Signals an error on any structural violation."
  (let ((br (make-byte-reader-from bytes)))
    (let ((magic (br-read-bytes br 5)))
      (unless (equalp magic *psbt-magic*)
        (serialization-error "Invalid PSBT magic")))
    (let* ((global (%psbt-read-map br :global))
           (tx-bytes (psbt-map-find global +psbt-global-unsigned-tx+))
           (ver (psbt-map-find global +psbt-global-version+)))
      (unless tx-bytes
        (serialization-error "PSBT is missing the global unsigned transaction"))
      (when ver
        (when (/= (length ver) 4)
          (serialization-error "PSBT global version must be 4 bytes"))
        ;; Core psbt.h:1322-1323: a version above PSBT_HIGHEST_VERSION is
        ;; refused, never silently decoded with the v0 rules.
        (when (> (br-read-u32-le (make-byte-reader-from ver))
                 +psbt-highest-version+)
          (serialization-error "Unsupported version number")))
      (let ((tx (%psbt-read-unsigned-tx tx-bytes)))
        ;; The global tx must be unsigned: empty scriptSigs (the legacy reader
        ;; above already rejects witness data).
        (loop for in across (transaction-inputs tx)
              do (when (plusp (length (tx-in-script-sig in)))
                   (serialization-error "PSBT unsigned transaction must have empty scriptSigs")))
        (let* ((nin (length (transaction-inputs tx)))
               (nout (length (transaction-outputs tx)))
               (inputs (make-array nin))
               (outputs (make-array nout)))
          (dotimes (i nin) (setf (aref inputs i) (%psbt-read-map br :input)))
          (dotimes (i nout) (setf (aref outputs i) (%psbt-read-map br :output)))
          (unless (br-eof-p br)
            (serialization-error "Trailing data after PSBT"))
          (dotimes (i nin)
            (%psbt-validate-input (aref inputs i) (aref (transaction-inputs tx) i)))
          (dotimes (i nout) (%psbt-validate-output (aref outputs i)))
          (make-psbt :tx tx :global global :inputs inputs :outputs outputs))))))

;;; --- serialize ---

(defparameter *psbt-field-order*
  '((:global #x00 #x01 #xfb #xfc)
    (:input #x00 #x01 #x02 #x03 #x04 #x05 #x06 #x0a #x0b #x0c #x0d
     #x13 #x14 #x15 #x16 #x17 #x18 #x1a #x1b #x1c #x07 #x08 #xfc)
    (:output #x00 #x01 #x02 #xfc #x05 #x06 #x07 #x08))
  "The order Core's Serialize methods write each map's fields in
(PartiallySignedTransaction psbt.h:1170-1212, PSBTInput :302-462, PSBTOutput
:896-962); anything else is `unknown' and goes last. Note the output map
writes its proprietary records BEFORE the taproot fields.")

(defun %psbt-le32-list (bytes start)
  (loop for i from start below (- (length bytes) 3) by 4
        collect (logior (aref bytes i) (ash (aref bytes (+ i 1)) 8)
                        (ash (aref bytes (+ i 2)) 16) (ash (aref bytes (+ i 3)) 24))))

(defun %psbt-record-sort-key (context rec)
  "Where Core's std::map / std::set iteration puts REC among the records of its
own field: a list of integers and byte vectors, compared element by element."
  (multiple-value-bind (kt off) (psbt-key-type (car rec))
    (let* ((key (car rec))
           (kd (subseq key off))
           (value (cdr rec))
           (order (cdr (assoc context *psbt-field-order*)))
           (rank (or (position kt order) (length order))))
      (cons rank
            (cond
              ((or (= kt #xfc) (= rank (length order))) (list key))
              ((eq context :global)
               (if (and (= kt #x01) (= (length kd) 78) (>= (length value) 4))
                   ;; map<KeyOriginInfo, set<CExtPubKey>> (keyorigin.h:21-37,
                   ;; pubkey.h:353-361): fingerprint, path length, path, then
                   ;; the xpub's key and chaincode.
                   (list (subseq value 0 4)
                         (floor (- (length value) 4) 4)
                         (%psbt-le32-list value 4)
                         (subseq kd 45 78) (subseq kd 13 45))
                   (list kd)))
              ((and (eq context :input) (= kt #x02))
               (list (bl.crypto:hash160 kd)))   ; map<CKeyID, SigPair>
              ((and (eq context :input) (= kt #x15) (plusp (length value)))
               ;; map<pair<CScript, int>, set<control block>>; a CScript
               ;; (prevector) compares by SIZE first (prevector.h:446-461).
               (list (1- (length value))
                     (subseq value 0 (1- (length value)))
                     (aref value (1- (length value)))
                     kd))
              ((and (eq context :input) (member kt '(#x1b #x1c)) (>= (length kd) 66))
               ;; map<pair<aggregate, leaf hash>, map<participant, ...>>
               (list (subseq kd 33 66)
                     (if (= (length kd) 98)
                         (subseq kd 66 98)
                         (make-array 32 :element-type '(unsigned-byte 8)
                                        :initial-element 0))
                     (subseq kd 0 33)))
              (t (list kd)))))))

(defun %psbt-sort-key< (a b)
  (loop for x in a for y in b
        do (cond ((and (integerp x) (integerp y))
                  (unless (= x y) (return (< x y))))
                 ((and (listp x) (listp y))
                  (unless (equal x y)
                    (return (%psbt-sort-key< (append x '(-1)) (append y '(-1))))))
                 (t
                  (let ((m (mismatch x y)))
                    (when m
                      (return (cond ((>= m (length x)) t)
                                    ((>= m (length y)) nil)
                                    (t (< (aref x m) (aref y m)))))))))
        finally (return (< (length a) (length b)))))

(defun %psbt-canonical-records (context map)
  "MAP's records in the order Core serializes them. A finalized input writes
only its utxos, its final scriptSig/witness, proprietary and unknown records
(psbt.h:312, the `final_script_sig.empty() && final_script_witness.IsNull()'
gate), and a PSBT_GLOBAL_VERSION of 0 is not written at all (:1188-1191)."
  (let* ((records (psbt-map-records map))
         (final (and (eq context :input)
                     (find-if (lambda (r) (member (psbt-key-type (car r)) '(#x07 #x08)))
                              records)))
         (kept (remove-if
                (lambda (r)
                  (let ((kt (psbt-key-type (car r))))
                    (or (and final
                             (member kt '(#x02 #x03 #x04 #x05 #x06 #x0a #x0b #x0c #x0d
                                          #x13 #x14 #x15 #x16 #x17 #x18 #x1a #x1b #x1c)))
                        (and (eq context :global) (= kt #xfb)
                             (every #'zerop (cdr r))))))
                records)))
    (stable-sort (mapcar (lambda (r) (cons (%psbt-record-sort-key context r) r)) kept)
                 #'%psbt-sort-key< :key #'car)))

(defun %psbt-write-map (bb map &optional (context :unordered))
  "Write MAP's records and its separator -- in Core's canonical order when
CONTEXT is :global/:input/:output. Core never writes the records it READ: it
parses them into typed fields and writes the fields back field by field, each
keyed field in its container's order, so a PSBT that came in with its records
in another order goes out in Core's. rpc_psbt.py:836 compares walletprocesspsbt's
answer with Core's own bytes, and ours carried the input's new partial
signature after its bip32 derivations."
  (dolist (rec (if (eq context :unordered)
                   (psbt-map-records map)
                   (mapcar #'cdr (%psbt-canonical-records context map))))
    (bb-write-varint bb (length (car rec)))
    (bb-write-bytes bb (car rec))
    (bb-write-varint bb (length (cdr rec)))
    (when (plusp (length (cdr rec))) (bb-write-bytes bb (cdr rec))))
  (bb-write-varint bb 0))                ; separator

(defun serialize-psbt (psbt)
  "Serialize PSBT to binary bytes."
  (let ((bb (make-byte-buf)))
    (bb-write-bytes bb *psbt-magic*)
    (%psbt-write-map bb (psbt-global psbt) :global)
    (loop for m across (psbt-inputs psbt) do (%psbt-write-map bb m :input))
    (loop for m across (psbt-outputs psbt) do (%psbt-write-map bb m :output))
    (bb-finish bb)))

;;; --- base64 wrapping ---

(defun encode-psbt (psbt)
  "Serialize PSBT and base64-encode it (the RPC wire form)."
  (cl-base64:usb8-array-to-base64-string (serialize-psbt psbt)))

(defun decode-psbt (base64-string)
  "Decode a base64 PSBT string into a psbt struct."
  (parse-psbt (coerce (cl-base64:base64-string-to-usb8-array base64-string)
                      '(simple-array (unsigned-byte 8) (*)))))

;;; --- constructing an empty PSBT from an unsigned transaction ---

(defun make-empty-psbt (tx)
  "Build a PSBT wrapping the unsigned transaction TX (empty scriptSigs, no
witness) with empty per-input and per-output maps -- the Creator role."
  (let ((global (make-psbt-map))
        (nin (length (transaction-inputs tx)))
        (nout (length (transaction-outputs tx))))
    (psbt-map-set global +psbt-global-unsigned-tx+
                  (make-array 0 :element-type '(unsigned-byte 8))
                  (serialize-transaction tx))
    (make-psbt :tx tx :global global
               :inputs (map-into (make-array nin) #'make-psbt-map)
               :outputs (map-into (make-array nout) #'make-psbt-map))))
