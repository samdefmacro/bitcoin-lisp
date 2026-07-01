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
(defconstant +psbt-in-tap-internal-key+ #x17)
(defconstant +psbt-in-proprietary+ #xfc)

;; Output key types.
(defconstant +psbt-out-redeem-script+ #x00)
(defconstant +psbt-out-witness-script+ #x01)
(defconstant +psbt-out-bip32+ #x02)
(defconstant +psbt-out-tap-internal-key+ #x05)
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
                     (error "PSBT key type ~D must have empty key data" keytype)))
         (nonempty () (when (zerop keydata-len)
                        (error "PSBT key type ~D requires key data" keytype))))
    (ecase context
      (:global (case keytype ((#x00 #xfb) (empty)) (#x01 (nonempty))))
      (:input (case keytype
                ((#x00 #x01 #x03 #x04 #x05 #x07 #x08 #x13 #x17 #x18) (empty))
                ((#x02 #x06 #x0a #x0b #x0c #x0d #x14 #x15 #x16) (nonempty))))
      (:output (case keytype
                 ((#x00 #x01 #x05 #x06) (empty))
                 ((#x02 #x07) (nonempty)))))))

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
            (error "Duplicate key in PSBT map"))
          (multiple-value-bind (kt off) (psbt-key-type key)
            (%psbt-validate-key context kt (- (length key) off)))
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
          (error "PSBT unsigned transaction has trailing/witness data"))
        (make-transaction :version version :inputs inputs :outputs outputs
                          :lock-time lock-time :witness nil)))))

(defun %psbt-validate-input (map tx-in)
  "Field-content checks on one input map that Core enforces at parse time."
  (let ((sh (psbt-map-find map +psbt-in-sighash+)))
    (when (and sh (/= (length sh) 4))
      (error "PSBT input sighash type must be 4 bytes")))
  (let ((wu (psbt-map-find map +psbt-in-witness-utxo+)))
    (when wu
      (let ((br (make-byte-reader-from wu)))
        (br-read-tx-out br)
        (unless (br-eof-p br) (error "PSBT witness_utxo has trailing data")))))
  (let ((nwu (psbt-map-find map +psbt-in-non-witness-utxo+)))
    (when nwu
      (let* ((br (make-byte-reader-from nwu))
             (prev (br-read-transaction br)))
        (unless (br-eof-p br)
          (error "PSBT non_witness_utxo has trailing data"))
        (unless (equalp (transaction-hash prev) (outpoint-hash (tx-in-previous-output tx-in)))
          (error "PSBT non_witness_utxo does not match the input outpoint")))))
  (dolist (ps (psbt-map-collect map +psbt-in-partial-sig+))
    (unless (member (length (car ps)) '(33 65))
      (error "PSBT partial signature has an invalid public key")))
  (dolist (d (psbt-map-collect map +psbt-in-bip32+))
    (unless (member (length (car d)) '(33 65))
      (error "PSBT input BIP32 derivation has an invalid public key"))))

(defun parse-psbt (bytes)
  "Parse a binary PSBT. Signals an error on any structural violation."
  (let ((br (make-byte-reader-from bytes)))
    (let ((magic (br-read-bytes br 5)))
      (unless (equalp magic *psbt-magic*)
        (error "Invalid PSBT magic")))
    (let* ((global (%psbt-read-map br :global))
           (tx-bytes (psbt-map-find global +psbt-global-unsigned-tx+))
           (ver (psbt-map-find global +psbt-global-version+)))
      (unless tx-bytes
        (error "PSBT is missing the global unsigned transaction"))
      (when (and ver (/= (length ver) 4))
        (error "PSBT global version must be 4 bytes"))
      (let ((tx (%psbt-read-unsigned-tx tx-bytes)))
        ;; The global tx must be unsigned: empty scriptSigs (the legacy reader
        ;; above already rejects witness data).
        (loop for in across (transaction-inputs tx)
              do (when (plusp (length (tx-in-script-sig in)))
                   (error "PSBT unsigned transaction must have empty scriptSigs")))
        (let* ((nin (length (transaction-inputs tx)))
               (nout (length (transaction-outputs tx)))
               (inputs (make-array nin))
               (outputs (make-array nout)))
          (dotimes (i nin) (setf (aref inputs i) (%psbt-read-map br :input)))
          (dotimes (i nout) (setf (aref outputs i) (%psbt-read-map br :output)))
          (unless (br-eof-p br)
            (error "Trailing data after PSBT"))
          (dotimes (i nin)
            (%psbt-validate-input (aref inputs i) (aref (transaction-inputs tx) i)))
          (make-psbt :tx tx :global global :inputs inputs :outputs outputs))))))

;;; --- serialize ---

(defun %psbt-write-map (bb map)
  (dolist (rec (psbt-map-records map))
    (bb-write-varint bb (length (car rec)))
    (bb-write-bytes bb (car rec))
    (bb-write-varint bb (length (cdr rec)))
    (when (plusp (length (cdr rec))) (bb-write-bytes bb (cdr rec))))
  (bb-write-varint bb 0))                ; separator

(defun serialize-psbt (psbt)
  "Serialize PSBT to binary bytes."
  (let ((bb (make-byte-buf)))
    (bb-write-bytes bb *psbt-magic*)
    (%psbt-write-map bb (psbt-global psbt))
    (loop for m across (psbt-inputs psbt) do (%psbt-write-map bb m))
    (loop for m across (psbt-outputs psbt) do (%psbt-write-map bb m))
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
