(in-package #:bitcoin-lisp.tests)

;;;; Core's descriptor and PSBT targets at the pin: fuzz/descriptor_parse.cpp
;;;; (descriptor_parse) and psbt.cpp.

(def-suite :fuzz-wallet-tests :in :bitcoin-lisp-tests
  :description "Core fuzz descriptor_parse.cpp / psbt.cpp targets")

(in-suite :fuzz-wallet-tests)

;;; --- descriptor_parse.cpp -------------------------------------------------------

(defun %descriptor-key (fdp network &key xonly)
  "A key expression Core's descriptor grammar accepts in some context -- hex
public keys (compressed, uncompressed, x-only), WIFs (over any 32 bytes, so
invalid scalars too), extended keys with fixed, ranged, hardened and BIP389
multipath suffixes, any of them behind a key origin."
  (let* ((scalar (consume-uint256 fdp))
         (valid (bl.crypto:valid-private-key-p scalar))
         (body
           (call-one-of fdp
             (if valid
                 (let ((pub (bl.crypto:derive-public-key scalar :compressed (or xonly (consume-bool fdp)))))
                   (bl.crypto:bytes-to-hex (if xonly (subseq pub 1) pub)))
                 (bl.crypto:bytes-to-hex scalar))
             (bl.crypto:private-key-to-wif scalar :network network :compressed (consume-bool fdp))
             (handler-case
                 (let ((k (bl.crypto:bip32-master-key (subseq (concatenate '(vector (unsigned-byte 8)) scalar scalar) 0 32)
                                                      :network network)))
                   (format nil "~A~A"
                           (bl.crypto:bip32-serialize (if (consume-bool fdp) (bl.crypto:bip32-neuter k) k))
                           (pick-value-in-array fdp '("" "/0" "/*" "/0/*" "/1h/*" "/*h" "/<0;1>/*" "/0'/2"))))
               (bl.err:crypto-error () "00")))))
    (if (consume-bool fdp)
        (format nil "[~(~8,'0x~)~A]~A" (consume-integral fdp :u32)
                (pick-value-in-array fdp '("" "/44h/0h" "/0'/1" "/2147483647h"))
                body)
        body)))

(defun %descriptor-corpus-string (fdp network)
  (flet ((key () (%descriptor-key fdp network))
         (xkey () (%descriptor-key fdp network :xonly (consume-bool fdp))))
    (call-one-of fdp
      (format nil "pk(~A)" (key))
      (format nil "pkh(~A)" (key))
      (format nil "wpkh(~A)" (key))
      (format nil "sh(wpkh(~A))" (key))
      (format nil "combo(~A)" (key))
      (format nil "sh(multi(~D,~A,~A))" (consume-integral-in-range fdp 0 3) (key) (key))
      (format nil "wsh(sortedmulti(~D,~A,~A,~A))" (consume-integral-in-range fdp 0 4) (key) (key) (key))
      (format nil "sh(wsh(pk(~A)))" (key))
      (format nil "tr(~A)" (xkey))
      (format nil "tr(~A,pk(~A))" (xkey) (xkey))
      (format nil "tr(~A,{pk(~A),pk(~A)})" (xkey) (xkey) (xkey))
      (format nil "rawtr(~A)" (xkey))
      (format nil "wsh(and_v(v:pk(~A),older(~D)))" (key) (consume-integral-in-range fdp 0 70000))
      (format nil "raw(~A)" (bl.crypto:bytes-to-hex (consume-script fdp)))
      (format nil "addr(~A)" (or (bl.rpc:script->address (consume-script fdp :maybe-p2wsh t) network)
                                 "bc1qxyz")))))

(defun %descriptor-corpus (fdp)
  (let* ((network (pick-value-in-array fdp +fuzz-networks+))
         (body (%descriptor-corpus-string fdp network)))
    (%octets-of-string
     (format nil "~A~A"
             (code-char (position network +fuzz-networks+))
             (if (consume-bool fdp) (bl.rpc:descriptor-add-checksum body) body)))))

(defun %parse-descriptors-or-nil (string network require-checksum)
  (handler-case (bl.rpc:parse-descriptors string network :require-checksum require-checksum)
    (bl.rpc:rpc-error () nil)))

(defun %expand-or-nil (desc pos)
  (handler-case (bl.rpc:out-desc-expand desc pos)
    (bl.rpc:descriptor-derivation-error () :needs-private-keys)))

(define-fuzz-target descriptor-parse
    (buffer :core "descriptor_parse.cpp:18-117" :iterations 4000 :max-len 300
            :corpus #'%descriptor-corpus)
  "Parse, with and without a required checksum, answers descriptors or Core's
error and nothing else; the descriptors one string yields -- a BIP389
multipath string yields several -- agree on IsRange and IsSolvable (Core's
TestDescriptor); each one's canonical string parses back to itself, also
behind the checksum we compute for it; and Expand either answers scripts or
asks for private keys -- the same scripts at every position when the
descriptor is not ranged."
  (when (zerop (length buffer)) (fuzz-reject))
  (let* ((network (nth (mod (aref buffer 0) 5) +fuzz-networks+))
         (string (map 'string #'code-char (subseq buffer 1))))
    (dolist (require-checksum '(t nil))
      (let ((descs (%parse-descriptors-or-nil string network require-checksum)))
        (when descs
          (let ((ranged (bl.rpc:out-desc-ranged-p (first descs)))
                (solvable (bl.rpc:out-desc-solvable-p (first descs))))
            (dolist (d descs)
              (fuzz-assert (eq (bl.rpc:out-desc-ranged-p d) ranged) "IsRange differs across ~S" string)
              (fuzz-assert (eq (bl.rpc:out-desc-solvable-p d) solvable) "IsSolvable differs across ~S" string)
              (let* ((canonical (bl.rpc:out-desc-string d))
                     (again (%parse-descriptors-or-nil canonical network nil))
                     (checked (%parse-descriptors-or-nil (bl.rpc:descriptor-add-checksum canonical) network t)))
                (fuzz-assert (and again (string= (fuzz-sabotage (bl.rpc:out-desc-string (first again))) canonical))
                             "~S prints as ~S, which does not parse back to itself" string canonical)
                (fuzz-assert (and checked (string= (bl.rpc:out-desc-string (first checked)) canonical))
                             "~S with our checksum does not parse back" canonical))
              (let ((at0 (%expand-or-nil d 0)))
                (unless (or ranged (eq at0 :needs-private-keys))
                  (fuzz-assert (equalp at0 (%expand-or-nil d 7))
                               "unranged ~S expands differently at 0 and 7" string))))))))))

;;; --- psbt.cpp ---------------------------------------------------------------------

(defparameter +psbt-input-keytypes+ '(0 1 2 3 4 5 6 7 8 #x13 #x14 #x15 #x16 #x17 #x18 #xfc)
  "PSBT_IN_* record types BIP174/371/373 define, and the proprietary type.")

(defun %psbt-random-value (fdp keytype)
  "A value of roughly the shape KEYTYPE's record carries."
  (case keytype
    ;; A previous transaction needs an input: with none, the witness-aware
    ;; reader takes its empty input count for the segwit marker.
    (0 (let ((tx (consume-transaction fdp :max-num-in 2 :max-num-out 3)))
         (when (zerop (length (bl.ser:transaction-inputs tx)))
           (setf (bl.ser:transaction-inputs tx) (vector (bl.ser:make-tx-in :script-sig (make-array 0 :element-type (quote (unsigned-byte 8)))))
                 (bl.ser:transaction-witness tx) nil)
           (bl.ser:invalidate-transaction-caches tx))
         (bl.ser:transaction-wire-bytes tx)))
    (1 (%ser #'bl.ser:bb-write-tx-out
             (bl.ser:make-tx-out :value (consume-money fdp)
                                 :script-pubkey (consume-script fdp :maybe-p2wsh t))))
    (3 (%bytes (consume-integral fdp :u8) 0 0 0))
    ((4 5) (consume-script fdp))
    (t (consume-random-length-byte-vector fdp 80))))

(defun %psbt-corpus (fdp)
  "An empty PSBT over a ConsumeTransaction transaction, with records of the
known types added to its inputs and outputs."
  (let* ((tx (consume-transaction fdp :max-num-in 3 :max-num-out 3))
         (psbt (progn
                 (loop for in across (bl.ser:transaction-inputs tx)
                       do (setf (bl.ser:tx-in-script-sig in) (make-array 0 :element-type '(unsigned-byte 8))))
                 (setf (bl.ser:transaction-witness tx) nil)
                 (bl.ser:invalidate-transaction-caches tx)
                 (bl.ser:make-empty-psbt tx))))
    (loop for map across (bl.ser:psbt-inputs psbt)
          do (loop repeat (consume-integral-in-range fdp 0 4)
                   do (let ((kt (pick-value-in-array fdp +psbt-input-keytypes+)))
                        (bl.ser:psbt-map-set map kt
                                             (if (member kt '(2 6 #x13 #x14 #x16 #x18))
                                                 (consume-random-length-byte-vector fdp 40)
                                                 (make-array 0 :element-type '(unsigned-byte 8)))
                                             (%psbt-random-value fdp kt)))))
    (loop for map across (bl.ser:psbt-outputs psbt)
          do (loop repeat (consume-integral-in-range fdp 0 2)
                   do (let ((kt (pick-value-in-array fdp '(0 1 2 5 6 7))))
                        (bl.ser:psbt-map-set map kt
                                             (if (member kt '(2 7))
                                                 (consume-random-length-byte-vector fdp 40)
                                                 (make-array 0 :element-type '(unsigned-byte 8)))
                                             (%psbt-random-value fdp kt)))))
    (bl.ser:serialize-psbt psbt)))

(defvar *fuzz-psbt-node* nil
  "One minimal regtest node for every PSBT RPC the psbt target asks.")

(defun %psbt-rpc (method &rest params)
  (handler-case (bl.rpc:dispatch-rpc-method
                 (or *fuzz-psbt-node* (setf *fuzz-psbt-node* (make-test-node :network :regtest)))
                 method params)
    (bl.rpc:rpc-error () :rpc-error)))

(define-fuzz-target psbt
    (buffer :core "psbt.cpp:26-110" :iterations 5000 :max-len 800
            :corpus #'%psbt-corpus)
  "A PSBT that decodes serializes to bytes that decode to a PSBT serializing
to the same bytes (the round trip is stable, psbt.cpp:36-47); and decodepsbt,
analyzepsbt, finalizepsbt and combinepsbt with a second PSBT -- Core's
AnalyzePSBT, FinalizePSBT, FinalizeAndExtractPSBT, Merge and CombinePSBTs --
answer, or refuse with an RPC error, and nothing else."
  (let* ((psbt (fuzz-deserialize (bl.ser:parse-psbt buffer)))
         (ser (bl.ser:serialize-psbt psbt))
         (again (bl.ser:serialize-psbt (bl.ser:parse-psbt ser))))
    (fuzz-assert (equalp ser (fuzz-sabotage again)) "the PSBT round trip is not stable")
    (let ((b64 (bl.ser:encode-psbt psbt)))
      (%psbt-rpc "decodepsbt" b64)
      (%psbt-rpc "analyzepsbt" b64)
      (%psbt-rpc "finalizepsbt" b64)
      (%psbt-rpc "combinepsbt" (list b64 b64)))))
