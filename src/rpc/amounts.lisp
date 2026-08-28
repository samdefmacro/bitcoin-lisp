(in-package #:bitcoin-lisp.rpc)

;;;; Amounts and outputs (Core AmountFromValue / FormatMoney / ParseOutputs /
;;;; CFeeRate::GetFee): the money helpers every RPC file shares. They used to
;;;; live in the wallet files, which made mempool and rawtransaction RPCs
;;;; depend on the wallet for a BTC-to-satoshi parse.

(defun %amount-from-value (value)
  "Core AmountFromValue: a JSON number or decimal string in BTC to
satoshis, at most 8 fraction digits, within MoneyRange. Sub-satoshi
precision is REJECTED like Core (which parses the decimal text exactly):
rationals/integers are checked exactly; floats (JSON doubles, which cannot
carry the original decimal text) are accepted only when they sit within
double-representation noise of a whole satoshi — 0.001 sat at amounts
where doubles are satoshi-exact, scaling with magnitude above ~2^48 sats
where a double's nearest representation may be off by up to ~0.4 sat."
  (let ((satoshis
          (cond
            ((rationalp value)
             (let ((scaled (* (rational value) 100000000)))
               (unless (integerp scaled)
                 (error 'rpc-error :code +rpc-type-error+
                                   :message "Invalid amount"))
               scaled))
            ((floatp value)
             ;; JSON numbers arrive as double-floats; the 2^-48 relative
             ;; slack only covers double-representation noise. Wider
             ;; single-float slack exists solely for direct Lisp callers
             ;; (tests) whose literals default to single precision.
             (let* ((scaled (* (rational value) 100000000))
                    (nearest (round scaled))
                    (tolerance (max 1/1000
                                    (* (abs scaled)
                                       (if (typep value 'double-float)
                                           (expt 2 -48)
                                           (expt 2 -19))))))
               (unless (<= (abs (- scaled nearest)) tolerance)
                 (error 'rpc-error :code +rpc-type-error+
                                   :message "Invalid amount"))
               nearest))
            ((stringp value)
             (let* ((dot (position #\. value))
                    (whole (if dot (subseq value 0 dot) value))
                    (frac (if dot (subseq value (1+ dot)) "")))
               (unless (and (plusp (length whole))
                            (every #'digit-char-p whole)
                            (<= (length frac) 8)
                            (or (null dot) (plusp (length frac)))
                            (every #'digit-char-p frac))
                 (error 'rpc-error :code +rpc-type-error+
                                   :message "Invalid amount"))
               (+ (* (parse-integer whole) 100000000)
                  (if (plusp (length frac))
                      (* (parse-integer frac)
                         (expt 10 (- 8 (length frac))))
                      0))))
            (t (error 'rpc-error :code +rpc-type-error+
                                 :message "Amount is not a number or string")))))
    (unless (<= 0 satoshis bl.val:+max-money+)
      (error 'rpc-error :code +rpc-type-error+ :message "Amount out of range"))
    satoshis))

(defun %btc (satoshis)
  "Satoshis as the BTC double the RPC layer emits."
  (/ satoshis 100000000.0d0))

(defun %feerate-fee (rate-sat-kvb size)
  "Core CFeeRate::GetFee at d3056bc: ceil(RATE-SAT-KVB * SIZE / 1000) —
FeeFrac::EvaluateFeeUp (feerate.cpp:20-27, feefrac.h:196-223, \"rounding
up\"). Round-up is what makes per-part fee budgets additive: the sum of
rounded-up parts always covers the rounded-up whole, so the exact-fee loop's
fee_needed <= current_fee invariant holds. Pure integer math; negative
rates never occur in the wallet."
  (declare (type integer rate-sat-kvb size))
  (ceiling (* rate-sat-kvb size) 1000))

(defun %format-money (satoshis)
  "Core FormatMoney: BTC decimal string, trailing zeros trimmed but at
least two decimals kept."
  (multiple-value-bind (quotient remainder) (truncate (abs satoshis) 100000000)
    (let ((str (format nil "~D.~8,'0D" quotient remainder)))
      (let ((end (length str)))
        (loop while (and (char= (char str (1- end)) #\0)
                         (digit-char-p (char str (- end 3))))
              do (decf end))
        (concatenate 'string (if (minusp satoshis) "-" "") (subseq str 0 end))))))

(defstruct recipient
  address        ; destination string, or NIL for data outputs
  script         ; scriptPubKey bytes
  (amount 0 :type integer)
  sffo)

(defun %parse-outputs (network outputs-param)
  "Core ParseOutputs over the outputs argument: an object {address: amount,
\"data\": hex} or an array of single-pair objects. Returns
(values recipient-list key-strings). JSON objects arrive as hash tables
whose key order is NOT preserved (yason); the array-of-objects form
preserves order exactly — DIVERGENCE (cosmetic ordering only) noted in the
send/walletcreatefundedpsbt docstrings."
  (let ((pairs '()))
    (labels ((collect-object (obj)
               (cond
                 ((hash-table-p obj)
                  (maphash (lambda (k v) (push (cons k v) pairs)) obj))
                 ((and (listp obj) (every #'consp obj))
                  (dolist (pair obj) (push (cons (car pair) (cdr pair)) pairs)))
                 (t (error 'rpc-error :code +rpc-type-error+
                                      :message "Invalid parameter, outputs must be objects")))))
      (cond
        ((and (listp outputs-param) outputs-param
              (or (hash-table-p (first outputs-param))
                  (and (consp (first outputs-param))
                       (consp (car (first outputs-param))))))
         ;; Array of single-entry objects (order-preserving).
         (dolist (obj outputs-param) (collect-object obj)))
        (t (collect-object outputs-param))))
    (setf pairs (nreverse pairs))
    (let ((seen (make-hash-table :test 'equal))
          (recipients '())
          (keys '()))
      (loop for (key . value) in pairs
            do (unless (stringp key)
                 (error 'rpc-error :code +rpc-type-error+
                                   :message "Invalid parameter, key must be a string"))
               (when (gethash key seen)
                 (error 'rpc-error :code +rpc-invalid-parameter+
                                   :message (format nil "Invalid parameter, duplicated address: ~A" key)))
               (setf (gethash key seen) t)
               (push key keys)
               (if (string= key "data")
                   (let ((data (handler-case (bl.crypto:hex-to-bytes value)
                                 (error ()
                                   (error 'rpc-error :code +rpc-invalid-parameter+
                                                     :message "Data must be hexadecimal string")))))
                     (push (make-recipient :address nil
                                           :script (%op-return-script data)
                                           :amount 0)
                           recipients))
                   (multiple-value-bind (type script)
                       (bl.crypto:decode-address key network)
                     (declare (ignore type))
                     (unless script
                       (error 'rpc-error :code +rpc-invalid-address-or-key+
                                         :message (format nil "Invalid Bitcoin address: ~A" key)))
                     (push (make-recipient :address key :script script
                                           :amount (%amount-from-value value))
                           recipients))))
      (values (nreverse recipients) (nreverse keys)))))

(defun %op-return-script (data)
  "CScript() << OP_RETURN << data."
  (concatenate '(vector (unsigned-byte 8)) (vector #x6a) (bl.ser:script-push-data data)))
