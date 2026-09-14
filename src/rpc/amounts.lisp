(in-package #:bitcoin-lisp.rpc)

;;;; Core rpc/util.cpp: the argument parsers every RPC file shares.
;;;;
;;;; ParseHashV / ParseHexV for a hash- or hex-valued argument, and
;;;; AmountFromValue / FormatMoney / ParseOutputs / CFeeRate::GetFee for a
;;;; money-valued one. The money half used to live in the wallet files, which
;;;; made mempool and rawtransaction RPCs depend on the wallet for a
;;;; BTC-to-satoshi parse; the hash half used to be eleven per-call-site
;;;; spellings of the same check, none of them Core's.

;;; --- Hashes and hex (Core ParseHashV / ParseHexV, rpc/util.cpp:116-142) ---

(defun valid-hex-hash-p (str)
  "Check if STR is a valid 64-character hex hash."
  (and (stringp str)
       (= (length str) 64)
       (every (lambda (c) (digit-char-p c 16)) str)))

(defun parse-hex-hash (str)
  "Parse a hex string to byte vector (reversed for internal use)."
  (when (valid-hex-hash-p str)
    (let ((bytes (make-array 32 :element-type '(unsigned-byte 8))))
      (loop for i from 0 below 32
            for j from 62 downto 0 by 2
            do (setf (aref bytes i)
                     (parse-integer str :start j :end (+ j 2) :radix 16)))
      bytes)))

(defun hash-to-hex (bytes)
  "Convert a 32-byte hash to lowercase hex string (reversed for display),
matching Bitcoin Core's uint256::GetHex."
  (bl.crypto:bytes-to-hex (bl.crypto:reverse-bytes bytes)))

(defun hex-string-p (str)
  "Core IsHex (util/strencodings.cpp:41-47): every character a hex digit, the
length non-zero and even. The empty string is NOT hex, which is what makes
ParseHexV's message for a non-string argument end in `(not \'\')\'."
  (and (stringp str)
       (plusp (length str))
       (evenp (length str))
       (every (lambda (c) (digit-char-p c 16)) str)))

(defun parse-hash-v (value name)
  "Core ParseHashV (rpc/util.cpp:117-125): the 32-byte hash the argument
called NAME denotes, in internal (reversed) byte order.

NAME is the argument's name AT THE CORE CALL SITE -- \"hash\" for
getblockheader, \"blockhash\" for getblock, \"txid\" for gettxout,
\"parameter 3\" for getrawtransaction's blockhash -- because Core's
functional tests assert the whole sentence, not just the code. Core has
exactly two failure branches and this tree had eleven, one per call site
(\"Invalid block hash\", \"Invalid txid\", \"blockhash must be a hex
string\", ...), so no Core test could match any of them:
  - a wrong LENGTH is \"<name> must be of length 64 (not <n>, for '<value>')\";
  - the right length with a non-hex character is
    \"<name> must be hexadecimal string (not '<value>')\";
both RPC_INVALID_PARAMETER (-8). A non-string VALUE is get_str()'s
RPC_TYPE_ERROR (-3), not -8 -- Core's ExecuteCommand maps UniValue::type_error
to RPC_TYPE_ERROR (rpc/server.cpp:512-513).

The -8 is for a MALFORMED hash only. A well-formed hash naming no known block
or transaction is the caller's -5 \"Block not found\", so a handler calls this
first and looks the hash up afterwards."
  (unless (stringp value)
    (%json-type-error value "string"))
  (or (parse-hex-hash value)
      (if (/= (length value) 64)
          (error 'rpc-error :code +rpc-invalid-parameter+
                            :message (format nil "~A must be of length 64 (not ~D, for '~A')"
                                             name (length value) value))
          (error 'rpc-error :code +rpc-invalid-parameter+
                            :message (format nil "~A must be hexadecimal string (not '~A')"
                                             name value)))))

(defun parse-hex-v (value name)
  "Core ParseHexV (rpc/util.cpp:130-138): the bytes the hex argument called
NAME denotes.

Unlike PARSE-HASH-V this takes any even-length hex string and does NOT
type-error on a non-string: Core's ParseHexV leaves strHex empty when
`!v.isStr()\', so a number or an object produces the same
RPC_INVALID_PARAMETER as bad hex does, ending in `(not \'\')\'."
  (let ((hex (if (stringp value) value "")))
    (unless (hex-string-p hex)
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message (format nil "~A must be hexadecimal string (not '~A')"
                                         name hex)))
    (bl.crypto:hex-to-bytes hex)))

;;; --- Money (Core AmountFromValue / FormatMoney / ParseOutputs) ---

(defconstant +fixed-point-upper-bound+ (1- (expt 10 18))
  "Core's UPPER_BOUND (util/strencodings.cpp:252): 10^18-1, the largest
arbitrary 18-digit decimal that still fits a signed 64-bit integer. Every
overflow gate in PARSE-FIXED-POINT is against this, not against 2^63-1, so
9223372036854775807 is rejected exactly as Core rejects it.")

(defun %process-mantissa-digit (ch mantissa tzeros)
  "Core ProcessMantissaDigit (util/strencodings.cpp:262-276): fold digit CH
into MANTISSA, returning (values mantissa tzeros) or NIL on overflow.

A '0' is COUNTED rather than multiplied in, and the count is only paid for
when a non-zero digit follows -- which is why \"1.10000000000000000\" and
\"0.0000000100000000\" parse while carrying more than 18 digits."
  (if (char= ch #\0)
      (values mantissa (1+ tzeros))
      (let ((m mantissa)
            (limit (floor +fixed-point-upper-bound+ 10)))
        (dotimes (i (1+ tzeros))
          (when (> m limit)
            (return-from %process-mantissa-digit nil))
          (setf m (* m 10)))
        (values (+ m (- (char-code ch) (char-code #\0))) 0))))

(defun parse-fixed-point (text decimals)
  "Core ParseFixedPoint (util/strencodings.cpp:277-360): TEXT as an integer
count of 10^-DECIMALS units, or NIL when it does not parse.

One left-to-right scan in Core's order and nothing else is accepted: an
optional '-', then a mantissa that is either a SINGLE '0' or a 1-9 run (so
\"01\", \"00.1\" and \"000\" are refused and \".1\" has no leading digit),
then an optional '.' with at least one digit, then an optional e/E with an
optional sign and at least one digit, then end-of-string. Trailing garbage,
a lone '-', \"1.\" and \"1.1e\" all fail.

The scale check is Core's, not a digit count: the exponent, after subtracting
the fraction length and adding back the counted trailing zeros, plus DECIMALS,
must land in [0,18). Below 0 the value is finer than one unit (\"0.000000001\"
at 8 decimals); at 18 or above it cannot be represented (\"1e11\" in BTC).
That is why Core answers \"Invalid amount\" -- not \"Amount out of range\" --
for 10000000000 and 92233720368.54775808."
  (let ((mantissa 0)
        (exponent 0)
        (tzeros 0)
        (mantissa-sign nil)
        (exponent-sign nil)
        (ptr 0)
        (end (length text))
        (point-ofs 0))
    (labels ((peek () (and (< ptr end) (char text ptr)))
             (digitp (c) (and c (char<= #\0 c #\9)))
             (eat-mantissa-digit ()
               (multiple-value-bind (m z)
                   (%process-mantissa-digit (char text ptr) mantissa tzeros)
                 (unless m (return-from parse-fixed-point nil))
                 (setf mantissa m tzeros z)
                 (incf ptr))))
      (when (eql (peek) #\-)
        (setf mantissa-sign t)
        (incf ptr))
      (cond ((null (peek)) (return-from parse-fixed-point nil)) ; empty, or a lone '-'
            ((char= (char text ptr) #\0) (incf ptr))            ; a single leading 0
            ((digitp (char text ptr))
             (loop while (digitp (peek)) do (eat-mantissa-digit)))
            (t (return-from parse-fixed-point nil)))            ; missing expected digit
      (when (eql (peek) #\.)
        (incf ptr)
        (unless (digitp (peek)) (return-from parse-fixed-point nil))
        (loop while (digitp (peek))
              do (eat-mantissa-digit) (incf point-ofs)))
      (when (member (peek) '(#\e #\E))
        (incf ptr)
        (case (peek)
          (#\+ (incf ptr))
          (#\- (setf exponent-sign t) (incf ptr)))
        (unless (digitp (peek)) (return-from parse-fixed-point nil))
        (loop while (digitp (peek))
              do (when (> exponent (floor +fixed-point-upper-bound+ 10))
                   (return-from parse-fixed-point nil))
                 (setf exponent (+ (* exponent 10)
                                   (- (char-code (char text ptr)) (char-code #\0))))
                 (incf ptr)))
      (unless (= ptr end) (return-from parse-fixed-point nil)) ; trailing garbage
      (when exponent-sign (setf exponent (- exponent)))
      (setf exponent (+ (- exponent point-ofs) tzeros))
      (when mantissa-sign (setf mantissa (- mantissa)))
      (incf exponent decimals)
      (when (or (minusp exponent) (>= exponent 18))
        (return-from parse-fixed-point nil))
      (dotimes (i exponent)
        (when (> (abs mantissa) (floor +fixed-point-upper-bound+ 10))
          (return-from parse-fixed-point nil))
        (setf mantissa (* mantissa 10)))
      (when (> (abs mantissa) +fixed-point-upper-bound+)
        (return-from parse-fixed-point nil))
      mantissa)))

(defun %json-number-text (value &optional (decimals 8))
  "The text Core's UniValue holds for the JSON number VALUE, at DECIMALS
fraction digits.

UniValue keeps a number's SOURCE TEXT and getValStr() hands it back, so in
Core AmountFromValue's number path IS its string path: 1e-8 and 0.00000001
agree, and 10000000000 is refused by ParseFixedPoint's 18-digit rule rather
than by MoneyRange. Our decoder keeps only the parsed value, so the text is
rebuilt -- an integer prints exactly, and a float prints with SBCL's shortest
round-tripping digits, whose exponent marker (d/f/s/l) becomes the e
ParseFixedPoint reads. A RATIO never arrives over the wire; a Lisp caller's
1/2 is rendered exactly when it is a whole number of units and left to fail
otherwise. DECIMALS is the scale that decides what \"a whole number of
units\" means -- 8 for a BTC amount, 3 for a sat/vB fee rate."
  (etypecase value
    (integer (format nil "~D" value))
    (float (map 'string
                (lambda (c) (if (member c '(#\d #\D #\f #\F #\s #\S #\l #\L)) #\e c))
                (princ-to-string value)))
    (ratio (let ((units (* value (expt 10 decimals))))
             (if (integerp units)
                 (multiple-value-bind (whole rest) (truncate (abs units) (expt 10 decimals))
                   (format nil "~:[~;-~]~D.~V,'0D" (minusp units) whole decimals rest))
                 (princ-to-string value))))))

(defun amount-from-value (value &optional (decimals 8))
  "Core AmountFromValue (rpc/util.cpp:98-108, declared with
`int decimals = 8\' in rpc/util.h:125): a JSON number or decimal string to
an integer count of 10^-DECIMALS units -- BTC to satoshis at the default,
and sat/vB to sat/kvB at DECIMALS 3, which is the only other scale Core
asks for (wallet/rpc/spend.cpp:224, `Fee rates in sat/vB cannot represent
more than 3 significant digits\').

Three lines, because Core is three lines: a value that is neither a number nor
a string is \"Amount is not a number or string\"; text ParseFixedPoint refuses
is \"Invalid amount\"; a parsed value outside MoneyRange is \"Amount out of
range\". All three are RPC_TYPE_ERROR (-3), which is what Core's tests assert.

The distinction between the last two is Core's and is not cosmetic: \"1e-9\",
\"0.000000019\", \"10000000000\" and \"92233720368.54775808\" are INVALID
(the scale does not fit), while \"-1\" and \"21000001\" are OUT OF RANGE (they
parse fine and MoneyRange rejects them). This used to hand-parse the string as
whole-plus-fraction with no sign, no exponent and no leading-zero rule, so
Core's own vectors disagreed in both directions: \"1e-8\", \"0.19e-6\" and
\"1.10000000000000000\" were refused, and \"01\", \"00.1\" and \"000\" were
accepted."
  (unless (or (numberp value) (stringp value))
    (error 'rpc-error :code +rpc-type-error+
                      :message "Amount is not a number or string"))
  (let ((satoshis (parse-fixed-point (if (stringp value)
                                         value
                                         (%json-number-text value decimals))
                                     decimals)))
    (unless satoshis
      (error 'rpc-error :code +rpc-type-error+ :message "Invalid amount"))
    (unless (bl.val:money-range-p satoshis)
      (error 'rpc-error :code +rpc-type-error+ :message "Amount out of range"))
    satoshis))

(defun satoshi->btc (satoshis)
  "Core ValueFromAmount (core_io.cpp:286-296): SATOSHIS as the BTC amount the
RPC and REST surfaces emit -- a JSON number token spelled \"%s%d.%08d\",
always eight decimals, trailing zeros and all.

Core keeps that text in the UniValue and writes it back verbatim, so 1 BTC is
`1.00000000\' and a tenth is `0.10000000\'. Handing yason a double instead
let SBCL\'s float printer choose the spelling: the shortest text that
round-trips, which is `1.0\', `0.1\' and -- for one satoshi -- the
exponent form `1.0e-8\'. The VALUES agreed; the bytes did not, and Core\'s
own functional tests read these fields as Decimal, which is exactly why the
difference is invisible to them.

The sign comes from the satoshi count, not from the quotient, so -1000 sat
prints -0.00001000 rather than 0.00001000.

SATOSHIS is an INTEGER count, as Core's CAmount is: a double here would print
its own decimal point into the middle of the token."
  (declare (type integer satoshis))
  (multiple-value-bind (quotient remainder) (truncate (abs satoshis) 100000000)
    (make-json-number (format nil "~:[~;-~]~D.~8,'0D"
                              (minusp satoshis) quotient remainder))))

(defun feerate-fee (rate-sat-kvb size)
  "Core CFeeRate::GetFee at d3056bc: ceil(RATE-SAT-KVB * SIZE / 1000) —
FeeFrac::EvaluateFeeUp (feerate.cpp:20-27, feefrac.h:196-223, \"rounding
up\"). Round-up is what makes per-part fee budgets additive: the sum of
rounded-up parts always covers the rounded-up whole, so the exact-fee loop's
fee_needed <= current_fee invariant holds. Pure integer math; negative
rates never occur in the wallet."
  (declare (type integer rate-sat-kvb size))
  (ceiling (* rate-sat-kvb size) 1000))

;;; Core's FormatMoney is BL:FORMAT-MONEY, defined in the util layer and
;;; imported into this package (rpc/package.lisp). It lives down there because
;;; policy code far below the RPC layer writes money into its diagnostics too
;;; -- PaysForRBF's "not enough additional fees to relay; <a> < <b>"
;;; (policy/rbf.cpp:110-122) is a mempool string. BL.RPC:FORMAT-MONEY still
;;; names it, and every caller here and in the wallet is unchanged.

(defstruct recipient
  address        ; destination string, or NIL for data outputs
  script         ; scriptPubKey bytes
  (amount 0 :type integer)
  sffo)

(defun default-input-sequence (replaceable locktime)
  "The nSequence Core's AddInputs gives an input that names none
(rpc/rawtransaction_util.cpp:47-56).

REPLACEABLE is `rbf.value_or(true)\', so the DEFAULT is 0xfffffffd -- an
absent `replaceable\' argument is std::nullopt and value_or makes it true.
Only an explicit false falls through, and then the locktime decides:
0xfffffffe keeps nLockTime enforceable, 0xffffffff makes the input final.
Core has one AddInputs for createrawtransaction, createpsbt and
walletcreatefundedpsbt, so this has one caller per RPC and no second rule."
  (cond (replaceable #xfffffffd)
        ((> locktime 0) #xfffffffe)
        (t #xffffffff)))

(defun parse-outputs (network outputs-param)
  "Core ParseOutputs over the outputs argument: an object {address: amount,
\"data\": hex} or an array of single-pair objects. Returns
(values recipient-list key-strings). JSON objects arrive as hash tables
whose key order is NOT preserved (yason); the array-of-objects form
preserves order exactly — DIVERGENCE (cosmetic ordering only) noted in the
send/walletcreatefundedpsbt docstrings."
  (let ((pairs '()))
    (labels ((collect-object (obj &optional in-array)
               (cond
                 ((hash-table-p obj)
                  (maphash (lambda (k v) (push (cons k v) pairs)) obj))
                 ((and (listp obj) (every #'consp obj))
                  (dolist (pair obj) (push (cons (car pair) (cdr pair)) pairs)))
                 ;; Core NormalizeOutputs judges the two positions apart
                 ;; (rawtransaction_util.cpp:74-97): a MEMBER of the array
                 ;; that is not an object is -8, while the argument itself
                 ;; goes through get_array() and so answers UniValue's own
                 ;; type error. Ours said "Invalid parameter, outputs must be
                 ;; objects" for both, a sentence in no implementation;
                 ;; rpc_rawtransaction.py:293 passes the string "foo" and
                 ;; expects the type error.
                 (in-array
                  (error 'rpc-error :code +rpc-invalid-parameter+
                                    :message "Invalid parameter, key-value pair not an object as expected"))
                 (t (%json-type-error obj "array")))))
      (cond
        ;; A top-level `[]' arrives as the empty-array sentinel, which is
        ;; TRUTHY and is not a list: Core's get_array() accepts it and
        ;; ParseOutputs then walks no keys, so createrawtransaction([], [])
        ;; builds a transaction with no outputs rather than erroring
        ;; (rpc_rawtransaction.py:295).
        ((eq outputs-param +json-empty-array+))
        ((and (listp outputs-param) outputs-param
              (or (hash-table-p (first outputs-param))
                  (and (consp (first outputs-param))
                       (consp (car (first outputs-param))))))
         ;; Array of single-entry objects (order-preserving).
         (dolist (obj outputs-param) (collect-object obj t)))
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
                   ;; Core ParseOutputs (rawtransaction_util.cpp:113):
                   ;; ParseHexV of getValStr() under the name "Data", so the
                   ;; offending text comes back in the message and a
                   ;; non-string value reads as the empty string.
                   (let ((data (parse-hex-v value "Data")))
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
                                           :amount (amount-from-value value))
                           recipients))))
      (values (nreverse recipients) (nreverse keys)))))

(defun %op-return-script (data)
  "CScript() << OP_RETURN << data."
  (concatenate '(vector (unsigned-byte 8)) (vector #x6a) (bl.ser:script-push-data data)))

;;; --- Core RPCTypeCheckObj (rpc/util.cpp:56-80) ---

(defun rpc-type-check-obj (obj expected &key allow-null strict)
  "Core RPCTypeCheckObj (rpc/util.cpp:56-80): EXPECTED is
((key . uvTypeName) ...) in the order Core's std::map visits the keys --
SORTED by key, which decides which of two missing keys is named. A missing
key is -3 \"Missing <key>\"; a present key of another type is -3 \"JSON
value of type <actual> for field <key> is not of expected type <type>\".
ALLOW-NULL is fAllowNull: a missing key passes and only a present one is
typed. Absent and null are one thing here, as find_value's null makes them
in Core; a nested false or [] has folded to NIL too and reads as missing.

STRICT is fStrict (rpc/util.cpp:69-79): after the expected keys are checked,
every key of OBJ that EXPECTED does not name is -3 \"Unexpected key <k>\".
Core passes it wherever an object argument is a closed set of options, so a
typo in a caller's key is an error rather than a silently ignored field."
  (loop for (key . type) in expected
        for value = (obj-get obj key)
        do (cond ((null value)
                  (unless allow-null
                    (error 'rpc-error :code +rpc-type-error+
                                      :message (format nil "Missing ~A" key))))
                 ((string/= (json-type-name value) type)
                  (error 'rpc-error
                         :code +rpc-type-error+
                         :message (format nil "JSON value of type ~A for field ~A ~
is not of expected type ~A" (json-type-name value) key type)))))
  (when strict
    (dolist (k (obj-keys obj))
      (unless (assoc k expected :test #'string=)
        (error 'rpc-error :code +rpc-type-error+
                          :message (format nil "Unexpected key ~A" k))))))
