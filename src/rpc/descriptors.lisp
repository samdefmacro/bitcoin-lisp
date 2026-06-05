(in-package #:bitcoin-lisp.rpc)

;;; Output descriptors (minimal subset for scantxoutset)
;;;
;;; Bitcoin Core reference: src/script/descriptor.cpp. Supported forms:
;;;   addr(ADDRESS)   raw(HEX)   pk(PUBKEY)   pkh(PUBKEY)   wpkh(PUBKEY)
;;;   sh(wpkh(PUBKEY))   combo(PUBKEY)   tr(XONLY)   rawtr(XONLY)
;;; PUBKEY is a hex-encoded 33-byte compressed or 65-byte uncompressed key
;;; (wpkh/sh(wpkh)/combo's segwit expansions require compressed, like Core);
;;; XONLY is a hex 32-byte x-only key. No xpubs, derivation paths, multisig,
;;; or miniscript — those need wallet machinery that is out of scope.

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

(defun %split-descriptor-checksum (string)
  "Split \"desc#checksum\" into (values desc checksum-or-nil). Signals
rpc-error if the checksum part is present but malformed or wrong."
  (let ((hash (position #\# string)))
    (if (null hash)
        (values string nil)
        (let ((body (subseq string 0 hash))
              (check (subseq string (1+ hash))))
          (unless (and (= (length check) 8)
                       (equal check (descriptor-checksum body)))
            (error 'rpc-error :code +rpc-invalid-address-or-key+
                              :message (format nil "Invalid descriptor checksum in '~A'" string)))
          (values body check)))))

(defun descriptor-add-checksum (body)
  "BODY with its computed #checksum appended (Core's AddChecksum)."
  (format nil "~A#~A" body (descriptor-checksum body)))

;;; --- Script construction ---

(defun %desc-error (fmt &rest args)
  (error 'rpc-error :code +rpc-invalid-address-or-key+
                    :message (apply #'format nil fmt args)))

(defun %parse-desc-pubkey (hex what)
  "Parse and validate a hex-encoded 33/65-byte pubkey for descriptor WHAT.
Returns the key bytes."
  (let ((bytes (handler-case (bitcoin-lisp.crypto:hex-to-bytes hex)
                 (error () (%desc-error "'~A': invalid hex public key" what)))))
    (unless (and (member (length bytes) '(33 65))
                 (bitcoin-lisp.crypto:public-key-valid-p bytes))
      (%desc-error "'~A': invalid public key" what))
    bytes))

(defun %parse-desc-xonly (hex what)
  "Parse and validate a hex 32-byte x-only pubkey for descriptor WHAT."
  (let ((bytes (handler-case (bitcoin-lisp.crypto:hex-to-bytes hex)
                 (error () (%desc-error "'~A': invalid hex key" what)))))
    (unless (and (= (length bytes) 32)
                 (bitcoin-lisp.crypto:xonly-pubkey-valid-p bytes))
      (%desc-error "'~A': invalid x-only public key" what))
    bytes))

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

(defun %script-p2tr (output-key32)
  (concatenate '(vector (unsigned-byte 8)) #(#x51 #x20) output-key32))

(defun %inner-of (body prefix what)
  "The text inside \"PREFIX(...)\" of BODY, validating the closing paren."
  (unless (char= (char body (1- (length body))) #\))
    (%desc-error "'~A': missing closing parenthesis" what))
  (subseq body (1+ (length prefix)) (1- (length body))))

(defun parse-output-descriptor (string network)
  "Expand descriptor STRING into a list of (script . canonical-descriptor)
pairs, where script is the scriptPubKey byte vector and the canonical
descriptor carries a computed checksum. Mirrors the subset of Bitcoin Core's
descriptor language documented at the top of this file; anything else
signals rpc-error (unsupported descriptors include xpubs/derivation,
multisig, and miniscript)."
  (multiple-value-bind (body) (%split-descriptor-checksum string)
    (flet ((one (script &optional (desc body))
             (list (cons script (descriptor-add-checksum desc)))))
      (cond
        ;; addr(ADDRESS)
        ((alexandria:starts-with-subseq "addr(" body)
         (let ((addr (%inner-of body "addr" body)))
           (multiple-value-bind (type script-pubkey)
               (bitcoin-lisp.crypto:decode-address addr network)
             (unless type
               (%desc-error "'~A': invalid address for this network" body))
             (one script-pubkey))))
        ;; raw(HEX)
        ((alexandria:starts-with-subseq "raw(" body)
         (let* ((hex (%inner-of body "raw" body))
                (script (handler-case (bitcoin-lisp.crypto:hex-to-bytes hex)
                          (error () (%desc-error "'~A': invalid hex" body)))))
           (one script)))
        ;; pk(PUBKEY) — also accepts x-only (Core: 32-byte keys allowed in pk())
        ((alexandria:starts-with-subseq "pk(" body)
         (let ((hex (%inner-of body "pk" body)))
           (if (= (length hex) 64)
               (one (concatenate '(vector (unsigned-byte 8))
                                 #(#x20) (%parse-desc-xonly hex body) #(#xac)))
               (one (%script-p2pk (%parse-desc-pubkey hex body))))))
        ;; pkh(PUBKEY)
        ((alexandria:starts-with-subseq "pkh(" body)
         (one (%script-p2pkh (%parse-desc-pubkey (%inner-of body "pkh" body) body))))
        ;; wpkh(PUBKEY) — compressed only (Core rejects uncompressed in segwit)
        ((alexandria:starts-with-subseq "wpkh(" body)
         (let ((key (%parse-desc-pubkey (%inner-of body "wpkh" body) body)))
           (unless (= (length key) 33)
             (%desc-error "'~A': uncompressed keys are not allowed in wpkh" body))
           (one (%script-p2wpkh key))))
        ;; sh(wpkh(PUBKEY)) — P2SH-P2WPKH only; other sh() needs script support
        ((alexandria:starts-with-subseq "sh(wpkh(" body)
         (let* ((inner (%inner-of body "sh" body)) ; "wpkh(...)"
                (key (%parse-desc-pubkey (%inner-of inner "wpkh" body) body)))
           (unless (= (length key) 33)
             (%desc-error "'~A': uncompressed keys are not allowed in wpkh" body))
           (one (%script-p2sh (%script-p2wpkh key)))))
        ;; combo(PUBKEY) — pk + pkh, plus wpkh + sh(wpkh) for compressed keys
        ((alexandria:starts-with-subseq "combo(" body)
         (let* ((key (%parse-desc-pubkey (%inner-of body "combo" body) body))
                (canonical (descriptor-add-checksum body)))
           (append
            (list (cons (%script-p2pk key) canonical)
                  (cons (%script-p2pkh key) canonical))
            (when (= (length key) 33)
              (list (cons (%script-p2wpkh key) canonical)
                    (cons (%script-p2sh (%script-p2wpkh key)) canonical))))))
        ;; tr(XONLY) — key-path only: output key = taproot tweak of internal key
        ((alexandria:starts-with-subseq "tr(" body)
         (let ((inner (%inner-of body "tr" body)))
           (when (find #\, inner)
             (%desc-error "'~A': tr() script trees are not supported" body))
           (let* ((internal (%parse-desc-xonly inner body))
                  (tweak (bitcoin-lisp.crypto:tap-tweak-hash internal))
                  (output-key (bitcoin-lisp.crypto:tweak-xonly-pubkey internal tweak)))
             (unless output-key
               (%desc-error "'~A': taproot tweak failed" body))
             (one (%script-p2tr output-key)))))
        ;; rawtr(XONLY) — the key IS the output key
        ((alexandria:starts-with-subseq "rawtr(" body)
         (one (%script-p2tr (%parse-desc-xonly (%inner-of body "rawtr" body) body))))
        (t
         (%desc-error "'~A': unsupported descriptor (supported: addr, raw, pk, pkh, wpkh, sh(wpkh), combo, tr, rawtr)" body))))))
