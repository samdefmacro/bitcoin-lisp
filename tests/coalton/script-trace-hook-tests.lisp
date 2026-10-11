;;;; The script trace hook, bl.interop:*script-trace-hook*
;;;;
;;;; An inspector binds the hook and validates one input; the interpreter and
;;;; the signature paths report frames, steps, signature hashes and signature
;;;; checks. The manual's script section is the contract. Each test pins an
;;;; event against the engine's own answer -- the EvalScripts VerifyScript
;;;; runs, the state before every opcode, the exact octets a sighash hashed,
;;;; the verifications it made -- and the corpus tests show that binding the
;;;; hook changes no verdict and no error name.

(in-package #:bitcoin-lisp.tests)

(def-suite :script-trace-hook-tests
  :description "The script trace hook: frames, steps, sighash preimages and signature checks"
  :in :bitcoin-lisp-tests)

(in-suite :script-trace-hook-tests)

;;; ------------------------------------------------------------------
;;; Recording
;;; ------------------------------------------------------------------

(defun th-record (thunk)
  "Call THUNK with *SCRIPT-TRACE-HOOK* recording every event. Returns
(values EVENTS RESULTS): EVENTS in order, each (EVENT . PLIST), and RESULTS the
list of THUNK's values."
  (let* ((events '())
         (results (let ((bl.interop:*script-trace-hook*
                          (lambda (event &rest plist)
                            (push (cons event plist) events))))
                    (multiple-value-list (funcall thunk)))))
    (values (nreverse events) results)))

(defun th-of (kind events)
  "The PLISTs of the EVENTS of KIND, in order."
  (loop for (event . plist) in events when (eq event kind) collect plist))

(defun th-frames (events)
  "EVENTS cut into frames, one (BEGIN STEPS END) per EvalScript: BEGIN and END
the two frame events' PLISTs, STEPS the PLISTs of the :STEP events between."
  (let ((frames '()) (begin nil) (steps '()))
    (dolist (event events (nreverse frames))
      (case (car event)
        (:frame-begin (setf begin (cdr event) steps '()))
        (:step (push (cdr event) steps))
        (:frame-end (push (list begin (nreverse steps) (cdr event)) frames))))))

(defun th-sigversions (events)
  "The :SIGVERSION of every frame in EVENTS, in order."
  (mapcar (lambda (frame) (getf (first frame) :sigversion)) (th-frames events)))

(defun th-field (key plists)
  "KEY of every event PLIST in PLISTS."
  (mapcar (lambda (plist) (getf plist key)) plists))

;;; ------------------------------------------------------------------
;;; Fixtures
;;; ------------------------------------------------------------------

;; tx_valid.json rows named by the txid of their first prevout: BIP 143's own
;; four examples, carried by Core's corpus, and two rows whose signing input has
;; no output of its index (Core's SIGHASH_SINGLE bug).
(defparameter +th-bip143-codesep-single+
  "6eb316926b1c5d567cd6f5e6a84fec606fc53d7b474526d1fff3948020c93dfe"
  "BIP 143 example: P2WSH with OP_CODESEPARATOR and out-of-range SIGHASH_SINGLE.")
(defparameter +th-bip143-unexecuted-codesep+
  "01c0cf7fba650638e55eb91261b183251fbb466f90dff17f10086817c542b5e9"
  "BIP 143 example: P2WSH with an unexecuted OP_CODESEPARATOR, SINGLE|ANYONECANPAY.")
(defparameter +th-bip143-swapped+
  "1b2a9a426ba603ba357ce7773cb5805cb9c7c2b386d100d1fc9263513188e680"
  "BIP 143 example: the previous one with its input-output pairs swapped.")
(defparameter +th-bip143-six-of-six+
  "6eb98797a21c6c10aa74edf29d618be109f48a8e94c694f3701e08ca69186436"
  "BIP 143 example: P2SH-P2WSH 6-of-6 signed with six different SIGHASH types.")

(defparameter +th-bip143-examples+
  (list +th-bip143-codesep-single+ +th-bip143-unexecuted-codesep+
        +th-bip143-swapped+ +th-bip143-six-of-six+)
  "The four BIP 143 examples in tx_valid.json.")

(defparameter +th-legacy-single-bug+
  "0000000000000000000000000000000000000000000000000000000000000200"
  "tx_valid.json: input 1 of 2 signs SIGHASH_SINGLE with only one output.")
(defparameter +th-legacy-single-bug-anyonecanpay+
  "437a1002eb125dec0f93f635763e0ae45f28ff8e81d82945753d0107611cd390"
  "tx_valid.json: input 2 of 3 signs SIGHASH_SINGLE|ANYONECANPAY with two outputs.")

(defun th-tx-valid-row (first-prevout-txid)
  "The tx_valid.json row whose first prevout spends FIRST-PREVOUT-TXID, as
(values TX PREVOUTS FLAGS), FLAGS already the effective set the row runs under."
  (dolist (row (load-tx-tests "tx_valid.json")
               (error "no tx_valid.json row spends ~A first" first-prevout-txid))
    (multiple-value-bind (prevouts tx-hex flags) (parse-tx-test-case row)
      (when (and prevouts (string= first-prevout-txid (first (first prevouts))))
        (return (values (bl.ser:parse-tx-payload (bl.crypto:hex-to-bytes tx-hex))
                        prevouts
                        (compute-effective-flags flags)))))))

(defun th-trace-tx-valid-input (first-prevout-txid index)
  "Validate input INDEX of a tx_valid.json row under the hook. Returns
(values EVENTS OK ERR)."
  (multiple-value-bind (tx prevouts flags) (th-tx-valid-row first-prevout-txid)
    (multiple-value-bind (events results)
        (th-record (lambda ()
                     (validate-single-tx-input tx index (nth index prevouts) flags)))
      (values events (first results) (second results)))))

(defun th-input-count (first-prevout-txid)
  "How many inputs the tx_valid.json row named by FIRST-PREVOUT-TXID has."
  (length (bl.ser:transaction-inputs (th-tx-valid-row first-prevout-txid))))

(defun th-taproot-vector (comment)
  "The taproot_spend_vectors.json record whose comment is COMMENT."
  (or (find comment (load-taproot-spend-vectors)
            :key (lambda (rec) (gethash "comment" rec)) :test #'string=)
      (error "no taproot spend vector ~S" comment)))

(defun th-key (fill)
  "A 32-byte private key of FILL octets."
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element fill))

(defun th-one-input-tx (spent-script)
  "A version-2 transaction with one input spending an output locked by
SPENT-SCRIPT, and one output. Returns (values tx utxo)."
  (values (bl.ser:make-transaction
           :version 2
           :inputs (vector (bl.ser:make-tx-in
                            :previous-output
                            (bl.ser:make-outpoint
                             :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                  :initial-element #x22)
                             :index 0)
                            :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                            :sequence #xffffffff))
           :outputs (vector (bl.ser:make-tx-out :value 90000
                                                :script-pubkey (%sh-cat #x51)))
           :lock-time 0)
          (bl.store:make-utxo-entry :value 100000 :script-pubkey spent-script
                                    :height 1)))

(defun th-two-of-three-spend ()
  "A bare 2-of-3 CHECKMULTISIG output spent with the first and the third key.
Core tries signature 1 against key 1 (a match), signature 2 against key 2 (no
match), then against key 3 (a match): three verifications. Returns
(values tx utxo)."
  (let* ((keys (mapcar #'th-key '(#x0a #x0b #x0c)))
         (pubs (mapcar (lambda (k) (bl.crypto:derive-public-key k :compressed t)) keys))
         (script (%sh-cat #x52 (%sh-var-bytes (first pubs)) (%sh-var-bytes (second pubs))
                          (%sh-var-bytes (third pubs)) #x53 #xae)))
    (multiple-value-bind (tx utxo) (th-one-input-tx script)
      (let* ((bl.interop:*current-tx* tx)
             (bl.interop:*current-input-index* 0)
             (digest (bl.interop:compute-legacy-sighash tx 0 script 1))
             (sig1 (%sh-cat (bl.crypto:sign-ecdsa (first keys) digest) 1))
             (sig3 (%sh-cat (bl.crypto:sign-ecdsa (third keys) digest) 1)))
        (setf (bl.ser:tx-in-script-sig (aref (bl.ser:transaction-inputs tx) 0))
              (%sh-cat #x00 (%sh-var-bytes sig1) (%sh-var-bytes sig3)))
        (values tx utxo)))))

(defun th-p2wpkh-spend ()
  "A signed P2WPKH spend, the sighash suite's fixture. Returns (values tx utxo)."
  (multiple-value-bind (tx utxo sk pub script-code) (%sh-bit31-p2wpkh)
    (let* ((bl.interop:*current-tx* tx)
           (bl.interop:*current-input-index* 0)
           (bl.interop:*precomputed-sighash* nil)
           (sig (%sh-cat (bl.crypto:sign-ecdsa
                          sk (bl.interop:compute-bip143-sighash
                              script-code (bl.store:utxo-entry-value utxo) 1))
                         1)))
      (setf (bl.ser:transaction-witness tx) (vector (list sig pub)))
      (values tx utxo))))

(defun th-p2tr-key-path-spend ()
  "A signed P2TR key-path spend, the sighash suite's fixture. Returns
(values tx utxo spent-utxos)."
  (multiple-value-bind (tx utxo tweaked) (%sh-bit31-p2tr)
    (let* ((spent (vector utxo))
           (bl.interop:*current-tx* tx)
           (bl.interop:*current-spent-utxos* spent)
           (bl.interop:*current-input-index* 0)
           (bl.interop:*precomputed-sighash* (bl.interop:init-precomputed-sighash tx spent))
           (sig (bl.crypto:sign-schnorr
                 tweaked (bl.interop:compute-bip341-sighash
                          (bl.store:utxo-entry-value utxo) 0 nil nil))))
      (setf (bl.ser:transaction-witness tx) (vector (list sig)))
      (values tx utxo spent))))

(defun th-trace-input (tx utxo &key spent-utxos (flags bl.val:+standard-script-verify-flags+))
  "VALIDATE-INPUT-SCRIPT on input 0 of TX under the hook. Returns
(values EVENTS OK ERR)."
  (multiple-value-bind (events results)
      (th-record (lambda ()
                   (let ((bl.interop:*script-flags* flags)
                         (bl.interop:*current-spent-utxos* spent-utxos)
                         (bl.interop:*precomputed-sighash* nil))
                     (bl.val:validate-input-script tx 0 utxo))))
    (values events (first results) (second results))))

(defun th-hex-push (bytes)
  "BYTES as an assembly token pair a script_tests.json script spells: the
one-octet length, then the data, both in hex."
  (format nil "0x~2,'0x 0x~A" (length bytes) (bl.crypto:bytes-to-hex bytes)))

(defparameter +th-generator-pubkey+
  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
  "A well-formed compressed public key (the curve's generator).")

;;; ------------------------------------------------------------------
;;; 1. Steps
;;; ------------------------------------------------------------------

(test a-step-precedes-every-opcode-a-skipped-push-included
  "Every :STEP is the state before the next opcode is read. A push inside an
IF branch that is not taken is reported, with :EXECUTING NIL, and the next step
lands past its data; the iteration that finds the script finished reports too."
  ;; scriptPubKey: IF <05 05> ELSE 3 ENDIF 3 EQUAL, run over a false scriptSig.
  (multiple-value-bind (events results)
      (th-record (lambda ()
                   (run-script-test "0" "IF 0x02 0x0505 ELSE 3 ENDIF 3 EQUAL" "P2SH")))
    (is (eq t (first results)) "the control spend must verify: ~S" results)
    (let* ((frames (th-frames events))
           (frame (second frames))
           (steps (second frame)))
      (is (= 2 (length frames)))
      (is (equal '(0 1 4 5 6 7 8 9) (th-field :position steps))
          "positions ~S" (th-field :position steps))
      (is (equal '(t nil nil t t t t t) (th-field :executing steps)))
      (is (equal '(0 1 1 1 1 0 0 0) (th-field :cond-depth steps)))
      (is (equal '(0 1 1 2 2 3 3 4) (th-field :op-count steps)))
      (is (equal '(1 0 0 0 1 1 2 1)
                 (mapcar #'length (th-field :main-stack steps))))
      (is (equal '(0 1 2 3 4 5 6 7) (th-field :opcode-index steps)))
      (is (equalp '(#(3)) (getf (nth 4 steps) :main-stack)))
      (is (equalp '(#()) (getf (first frame) :initial-stack)))
      (is (eq t (getf (third frame) :ok)))
      (is (equalp '(#(1)) (getf (third frame) :stack))))))

(test the-last-step-names-the-failing-opcode
  "On a failure the last :STEP sits at the opcode that failed, and :FRAME-END
carries Core's error name for it."
  (multiple-value-bind (events results)
      (th-record (lambda () (run-script-test "1" "2 EQUALVERIFY 1" "P2SH")))
    (is (null (first results)))
    (let* ((frame (second (th-frames events)))
           (steps (second frame)))
      (is (equal '(0 1) (th-field :position steps)))
      (is (null (getf (third frame) :ok)))
      (is (equal "EQUALVERIFY" (getf (third frame) :error))))))

(test frames-carry-their-script-and-initial-stack-top-first
  "Each EvalScript is a frame: :FRAME-BEGIN names the script and the stack it
starts on, top first, and :FRAME-END its final stack."
  (multiple-value-bind (events results)
      (th-record (lambda () (run-script-test "1 2" "ADD 3 EQUAL" "P2SH")))
    (is (eq t (first results)))
    (let ((frames (th-frames events)))
      (is (equal '(:base :base) (th-sigversions events)))
      (is (equalp #(#x51 #x52) (getf (first (first frames)) :script)))
      (is (equalp '() (getf (first (first frames)) :initial-stack)))
      (is (equalp '(#(2) #(1)) (getf (third (first frames)) :stack)))
      (is (equalp #(#x93 #x53 #x87) (getf (first (second frames)) :script)))
      (is (equalp '(#(2) #(1)) (getf (first (second frames)) :initial-stack))))))

(test an-oversized-script-is-a-frame-with-no-steps
  "MAX_SCRIPT_SIZE is checked inside the frame: an oversized BASE script still
opens and closes one, with SCRIPT_SIZE and no step. The same bytes as a
tapscript, which has no size limit, run step by step -- the control that the
frame would otherwise have steps."
  (let ((script (make-array 10001 :element-type '(unsigned-byte 8) :initial-element #x61)))
    (let ((events (th-record (lambda () (bl.interop:run-script script)))))
      (is (= 1 (length (th-of :frame-begin events))))
      (is (null (th-of :step events)))
      (is (equal "SCRIPT_SIZE" (getf (first (th-of :frame-end events)) :error))))
    (let ((events (th-record (lambda ()
                               (bl.interop:run-script script bl.script:SigVersionTapscript)))))
      (is (equal '(:tapscript) (th-sigversions events)))
      (is (= 10002 (length (th-of :step events))))
      (is (eq t (getf (first (th-of :frame-end events)) :ok))))))

(test the-code-separator-byte-position-moves-only-when-executed
  "BIP 143's second example has two inputs whose witness scripts differ only
in the branch holding OP_CODESEPARATOR: OP_0 IF CODESEPARATOR ENDIF leaves
:CODESEP-BYTE-POS at 0 for the whole frame, OP_1 IF CODESEPARATOR ENDIF moves it
to 3, the byte after the separator, from the next step on."
  (let ((seen '()))
    (dotimes (index (th-input-count +th-bip143-unexecuted-codesep+))
      (multiple-value-bind (events ok)
          (th-trace-tx-valid-input +th-bip143-unexecuted-codesep+ index)
        (is (eq t ok) "input ~D must verify" index)
        (let* ((frame (find :witness-v0 (th-frames events)
                            :key (lambda (f) (getf (first f) :sigversion))))
               (steps (second frame))
               (first-byte (aref (getf (first frame) :script) 0))
               (positions (th-field :codesep-byte-pos steps)))
          (push first-byte seen)
          (if (= first-byte #x51)
              (is (equal (mapcar (lambda (p) (if (> p 2) 3 0))
                                 (th-field :position steps))
                         positions)
                  "executed separator: ~S" positions)
              (is (every #'zerop positions) "unexecuted separator: ~S" positions)))))
    (is (equal '(#x00 #x51) (sort seen #'<)) "both inputs must be seen: ~S" seen)))

(test the-tapscript-sighash-names-the-separator-opcode-index
  "A script-path spend with OP_CODESEPARATOR after a push commits the
separator's opcode index (BIP 342), which the :SIGHASH event carries as
:CODESEP-OPCODE-INDEX -- the :OPCODE-INDEX of the step at that separator. Every
spend without one carries #xFFFFFFFF, the key paths included."
  (flet ((bip341-indexes (comment)
           (let ((events (th-record (lambda ()
                                      (run-taproot-spend-vector (th-taproot-vector comment))))))
             (values (mapcar (lambda (e) (getf e :codesep-opcode-index))
                             (remove :bip341 (th-of :sighash events)
                                     :key (lambda (e) (getf e :kind)) :test-not #'eq))
                     events))))
    (multiple-value-bind (indexes events) (bip341-indexes "scriptpath checksig codesep=True")
      (let* ((frame (find :tapscript (th-frames events)
                          :key (lambda (f) (getf (first f) :sigversion))))
             (script (getf (first frame) :script))
             (separator (find-if (lambda (step)
                                   (let ((p (getf step :position)))
                                     (and (< p (length script)) (= #xab (aref script p)))))
                                 (second frame))))
        (is-true separator "the leaf script must hold an OP_CODESEPARATOR")
        (when separator
          (is (<= 1 (getf separator :opcode-index)) "it follows a push")
          (is (equal (list (getf separator :opcode-index)) indexes)
              "indexes ~S, separator at opcode ~D" indexes (getf separator :opcode-index)))))
    (dolist (comment '("scriptpath checksig codesep=False" "keypath hashtype=0x00 annex=False"
                       "keypath hashtype=0x81 annex=False" "keypath hashtype=0x00 annex=True"))
      (is (equal (list #xffffffff) (bip341-indexes comment)) "~A" comment))))

(test the-step-reports-the-tapscript-signature-budget
  ":VALIDATION-WEIGHT-LEFT starts the tapscript frame at the witness size plus
50 and drops by 50 at every CHECKSIG with a non-empty signature; it is NIL in
every frame that is not a tapscript."
  (let* ((script (tapscript-weight-probe-script 2))
         (initial (captured-initial-tapscript-weight script)))
    (is (integerp initial) "the probe must reach tapscript execution: ~S" initial)
    (multiple-value-bind (events results) (th-record (lambda () (tapscript-leaf-spend script)))
      (is (eq t (first results)))
      (let ((weights (th-field :validation-weight-left (second (first (th-frames events))))))
        (is (eql initial (first weights)))
        (is (equal (list initial (- initial 50) (- initial 100))
                   (remove-duplicates weights :from-end t))
            "weights ~S" weights))))
  (let* ((events (th-record (lambda ()
                              (run-taproot-spend-vector
                               (th-taproot-vector "scriptpath checksig codesep=False")))))
         (frames (th-frames events)))
    (is (equal '(:base :base :tapscript) (th-sigversions events)))
    (dolist (frame (butlast frames))
      (is (every #'null (th-field :validation-weight-left (second frame)))))
    (is (every #'integerp (th-field :validation-weight-left (second (car (last frames))))))))

;;; ------------------------------------------------------------------
;;; 2. Frames
;;; ------------------------------------------------------------------

(test a-p2sh-spend-is-three-frames-and-no-more
  "A P2SH spend runs scriptSig, scriptPubKey and the redeem script, all BASE.
P2SH-REDEEM-SCRIPT evaluates the scriptSig a second time to look for a nested
witness program; that run is ours, and must not show as a fourth frame. The
flags carry WITNESS, without which that second run never happens."
  (let* ((redeem (%sh-cat #x51))
         (spk (%sh-cat #xa9 #x14 (bl.crypto:hash160 redeem) #x87)))
    (multiple-value-bind (events results)
        (th-record (lambda ()
                     (run-script-test "0x01 0x51"
                                      (format nil "HASH160 ~A EQUAL"
                                              (th-hex-push (bl.crypto:hash160 redeem)))
                                      "P2SH,WITNESS")))
      (is (eq t (first results)))
      (is (equal '(:base :base :base) (th-sigversions events)))
      (is (equalp (list (%sh-cat #x01 #x51) spk redeem)
                  (mapcar (lambda (f) (getf (first f) :script)) (th-frames events)))))))

(test witness-spends-open-with-their-two-base-frames
  "Every input runs its scriptSig and scriptPubKey as BASE frames first. A
P2WSH spend adds its witness script, a P2SH-P2WSH one its redeem script and its
witness script, a script-path spend its tapscript."
  (multiple-value-bind (events ok) (th-trace-tx-valid-input +th-bip143-unexecuted-codesep+ 0)
    (is (eq t ok))
    (is (equal '(:base :base :witness-v0) (th-sigversions events)))
    (is (zerop (length (getf (first (first (th-frames events))) :script)))
        "the native witness spend's scriptSig is empty"))
  (multiple-value-bind (events ok) (th-trace-tx-valid-input +th-bip143-six-of-six+ 0)
    (is (eq t ok))
    (is (equal '(:base :base :base :witness-v0) (th-sigversions events))))
  (let ((events (th-record (lambda ()
                             (run-taproot-spend-vector
                              (th-taproot-vector "scriptpath checksig codesep=False"))))))
    (is (equal '(:base :base :tapscript) (th-sigversions events)))))

(test the-p2wpkh-and-key-paths-have-no-frame-of-their-own
  "P2WPKH and the Taproot key path never reach EvalScript: only the two BASE
frames appear, then the signature hash and the verification."
  (multiple-value-bind (tx utxo) (th-p2wpkh-spend)
    (multiple-value-bind (events ok) (th-trace-input tx utxo)
      (is (eq t ok))
      (is (equal '(:base :base) (th-sigversions events)))
      (is (equal '(:bip143) (mapcar (lambda (e) (getf e :kind)) (th-of :sighash events))))
      (is (equal '((:ecdsa t)) (mapcar (lambda (e) (list (getf e :algorithm) (getf e :result)))
                                       (th-of :sigcheck events))))))
  (multiple-value-bind (tx utxo spent) (th-p2tr-key-path-spend)
    (multiple-value-bind (events ok) (th-trace-input tx utxo :spent-utxos spent)
      (is (eq t ok))
      (is (equal '(:base :base) (th-sigversions events)))
      (is (equal '(:bip341) (mapcar (lambda (e) (getf e :kind)) (th-of :sighash events))))
      (is (equal '((:schnorr t)) (mapcar (lambda (e) (list (getf e :algorithm) (getf e :result)))
                                         (th-of :sigcheck events)))))))

(test an-op-success-tapscript-opens-no-frame
  "A tapscript holding OP_SUCCESSx succeeds without running (BIP 342), so no
frame opens; the same leaf without it is one TAPSCRIPT frame."
  (multiple-value-bind (events results)
      (th-record (lambda () (tapscript-leaf-spend (tap-bytes #x75 #xbb)
                                                  :inputs (list (tap-filler 1)))))
    (is (eq t (first results)))
    (is (null (th-frames events))))
  (multiple-value-bind (events results)
      (th-record (lambda () (tapscript-leaf-spend (tap-bytes #x75 #x51)
                                                  :inputs (list (tap-filler 1)))))
    (is (eq t (first results)))
    (is (equal '(:tapscript) (th-sigversions events)))))

;;; ------------------------------------------------------------------
;;; 3. Preimages
;;; ------------------------------------------------------------------

(defparameter +th-constant-one+
  (let ((one (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref one 0) 1)
    one)
  "Core's uint256 one: the legacy digest of SIGHASH_SINGLE past the outputs.")

(test every-sighash-json-preimage-hashes-to-its-digest
  "For each of Core's sighash.json vectors the :SIGHASH event's preimage
hash256s to the event's digest, which is the function's answer and the vector's
expected hash. Core's generator gives a SIGHASH_SINGLE vector as many outputs as
inputs, so every vector has a preimage; SINGLE past the outputs is the next
test's. :SUBSCRIPT is the script as passed and :SCRIPT-CODE the one serialized,
shorter wherever the script holds an OP_CODESEPARATOR."
  (let ((vectors 0) (stripped 0) (failures '()))
    (dolist (row (load-sighash-tests))
      (when (and (listp row) (= 5 (length row)) (stringp (first row)))
        (destructuring-bind (tx-hex script-hex index hash-type expected-hex) row
          (let* ((tx (bl.ser:parse-tx-payload (bl.crypto:hex-to-bytes tx-hex)))
                 (subscript (bl.crypto:hex-to-bytes script-hex))
                 (expected (reverse (bl.crypto:hex-to-bytes expected-hex))))
            (multiple-value-bind (events results)
                (th-record (lambda ()
                             (bl.interop:compute-legacy-sighash
                              tx index subscript (logand hash-type #xffffffff))))
              (let* ((event (first (th-of :sighash events)))
                     (preimage (getf event :preimage))
                     (digest (getf event :digest)))
                (incf vectors)
                (when (< (length (getf event :script-code)) (length subscript))
                  (incf stripped))
                (unless (and (= 1 (length (th-of :sighash events)))
                             preimage
                             (equalp digest (first results))
                             (equalp digest expected)
                             (equalp digest (bl.crypto:hash256 preimage))
                             (equalp subscript (getf event :subscript)))
                  (push (list vectors expected-hex) failures))))))))
    (is (= 500 vectors) "sighash.json holds 500 vectors, not ~D" vectors)
    (is (= 210 stripped) "~D vectors' scripts lose an OP_CODESEPARATOR" stripped)
    (is (null failures) "~D vectors disagree: ~S" (length failures) (reverse failures))))

(test single-past-the-outputs-hashes-nothing
  "A legacy SIGHASH_SINGLE signature on an input with no output of its index
signs Core's constant one: the :SIGHASH event has no preimage and that constant
as its digest, and the :SIGCHECK after it verifies the signature over it."
  (dolist (case (list (list +th-legacy-single-bug+ 1 #x03)
                      (list +th-legacy-single-bug-anyonecanpay+ 2 #x83)))
    (destructuring-bind (txid index hash-type) case
      (multiple-value-bind (events ok) (th-trace-tx-valid-input txid index)
        (let ((sighash (first (th-of :sighash events)))
              (sigcheck (first (th-of :sigcheck events))))
          (is-true ok)
          (is (= 1 (length (th-of :sighash events))))
          (is (eq :legacy (getf sighash :kind)))
          (is (= hash-type (getf sighash :hash-type)))
          (is (= index (getf sighash :input-index)))
          (is (null (getf sighash :preimage)))
          (is (equalp +th-constant-one+ (getf sighash :digest)))
          (is (equalp +th-constant-one+ (getf sigcheck :digest)))
          (is (eq t (getf sigcheck :result))))))))

(test the-bip341-key-path-preimage-is-the-vectors-sigmsg
  "BIP 341's wallet vectors give the signature message of every key-path input:
the :SIGHASH event's preimage is that sigMsg octet for octet (its leading epoch
byte included), and its digest the vector's sigHash."
  (let* ((kps (first (gethash "keyPathSpending" (load-bip341-vectors))))
         (given (gethash "given" kps))
         (tx (flexi-streams:with-input-from-sequence
                 (s (bl.crypto:hex-to-bytes (gethash "rawUnsignedTx" given)))
               (bl.ser:read-transaction s)))
         (utxos (gethash "utxosSpent" given))
         (spent (map 'vector (lambda (u)
                               (bl.store:make-utxo-entry
                                :value (gethash "amountSats" u)
                                :script-pubkey (bl.crypto:hex-to-bytes
                                                (gethash "scriptPubKey" u))))
                     utxos))
         (checked 0))
    (let ((bl.interop:*current-tx* tx)
          (bl.interop:*current-spent-utxos* spent)
          (bl.interop:*precomputed-sighash* nil))
      (dolist (entry (gethash "inputSpending" kps))
        (let* ((g (gethash "given" entry))
               (inter (gethash "intermediary" entry))
               (bl.interop:*current-input-index* (gethash "txinIndex" g))
               (event (first (th-of :sighash
                                    (th-record (lambda ()
                                                 (bl.interop:compute-bip341-sighash
                                                  0 (gethash "hashType" g) nil nil)))))))
          (incf checked)
          (is (string-equal (gethash "sigMsg" inter)
                            (bl.crypto:bytes-to-hex (getf event :preimage))))
          (is (string-equal (gethash "sigHash" inter)
                            (bl.crypto:bytes-to-hex (getf event :digest)))))))
    (is (= 7 checked) "the vectors hold 7 key-path inputs, not ~D" checked)))

(test the-bip143-examples-preimages-hash-to-what-the-signatures-sign
  "Over the four BIP 143 examples in tx_valid.json, every :SIGHASH preimage
hash256s to its digest and every :SIGCHECK verifies. The signatures were made
by the examples' authors, so a preimage wrong by one octet could not verify:
together the two are a byte-exact check of the preimage."
  (let ((sighashes 0) (sigchecks 0))
    (dolist (txid +th-bip143-examples+)
      (dotimes (index (th-input-count txid))
        (multiple-value-bind (events ok) (th-trace-tx-valid-input txid index)
          (is (eq t ok) "~A input ~D must verify" txid index)
          (let ((hashes (th-of :sighash events))
                (checks (th-of :sigcheck events)))
            (incf sighashes (length hashes))
            (incf sigchecks (length checks))
            (is (= (length hashes) (length checks)) "~A input ~D" txid index)
            (dolist (event hashes)
              (is (equalp (getf event :digest) (bl.crypto:hash256 (getf event :preimage)))))
            (dolist (event checks)
              (is (eq t (getf event :result))))))))
    ;; 1 + 2 signatures, 1 + 1, 1 + 1, and six.
    (is (= 13 sighashes) "~D signature hashes" sighashes)
    (is (= 13 sigchecks) "~D signature checks" sigchecks)))

;;; ------------------------------------------------------------------
;;; 4. Re-hashing from inside an event
;;; ------------------------------------------------------------------

(defun th-rehash (event hash-type)
  "EVENT's signature hash recomputed under HASH-TYPE through the exported entry
points, with the hook unbound -- what an inspector does to show what another
hash type would have signed."
  (let ((bl.interop:*script-trace-hook* nil))
    (ecase (getf event :kind)
      (:legacy (bl.interop:compute-legacy-sighash bl.interop:*current-tx*
                                                  (getf event :input-index)
                                                  (getf event :subscript) hash-type))
      (:bip143 (bl.interop:compute-bip143-sighash (getf event :script-code)
                                                  (getf event :amount) hash-type))
      (:bip341 (bl.interop:compute-bip341-sighash 0 hash-type (getf event :tapleaf-hash)
                                                  (getf event :key-version))))))

(defun th-rehash-inside (thunk hash-types)
  "Run THUNK with a hook that, at every :SIGHASH event, recomputes it under
each of HASH-TYPES while the computation's own bindings are in force. Returns
(values REHASHES RESULTS): one (EVENT . DIGESTS) per event, and THUNK's values."
  (let* ((rehashes '())
         (results (let ((bl.interop:*script-trace-hook*
                          (lambda (event &rest plist)
                            (when (eq event :sighash)
                              (push (cons plist (mapcar (lambda (ht) (th-rehash plist ht))
                                                        hash-types))
                                    rehashes)))))
                    (multiple-value-list (funcall thunk)))))
    (values (nreverse rehashes) results)))

(test a-sighash-event-can-be-rehashed-under-every-hash-type
  "Inside a :SIGHASH event the computation's bindings are still in force, so
the exported entry points recompute it under any hash type. Each recomputation
equals the one made afterwards with the same bindings, the event's own type
gives back the event's digest, and the verification is unaffected."
  (let ((ecdsa-types '(1 2 3 #x81 #x82 #x83)))
    ;; Legacy: the 2-of-3 spend's three signature hashes.
    (multiple-value-bind (tx utxo) (th-two-of-three-spend)
      (multiple-value-bind (rehashes results)
          (th-rehash-inside (lambda ()
                              (let ((bl.interop:*script-flags* bl.val:+standard-script-verify-flags+))
                                (bl.val:validate-input-script tx 0 utxo)))
                            ecdsa-types)
        (is (eq t (first results)))
        (is (= 3 (length rehashes)))
        (let ((bl.interop:*current-tx* tx)
              (bl.interop:*current-input-index* 0))
          (dolist (row rehashes)
            (destructuring-bind (event . digests) row
              (is (equalp (mapcar (lambda (ht) (th-rehash event ht)) ecdsa-types) digests))
              (is (equalp (getf event :digest)
                          (nth (position (getf event :hash-type) ecdsa-types) digests))))))))
    ;; BIP 143: the six-of-six example signs once under each of the six types.
    (multiple-value-bind (tx prevouts flags) (th-tx-valid-row +th-bip143-six-of-six+)
      (multiple-value-bind (rehashes results)
          (th-rehash-inside (lambda () (validate-single-tx-input tx 0 (first prevouts) flags))
                            ecdsa-types)
        (is (eq t (first results)))
        (is (= 6 (length rehashes)))
        (is (equal ecdsa-types
                   (sort (mapcar (lambda (row) (getf (car row) :hash-type)) rehashes) #'<)))
        (let ((bl.interop:*current-tx* tx)
              (bl.interop:*current-input-index* 0)
              (bl.interop:*precomputed-sighash* nil))
          (dolist (row rehashes)
            (destructuring-bind (event . digests) row
              (is (equalp (mapcar (lambda (ht) (th-rehash event ht)) ecdsa-types) digests))
              (is (equalp (getf event :digest)
                          (nth (position (getf event :hash-type) ecdsa-types) digests)))))))))
  ;; BIP 341: a key-path spend, under all seven Taproot types.
  (let* ((schnorr-types '(0 1 2 3 #x81 #x82 #x83))
         (rec (th-taproot-vector "keypath hashtype=0x00 annex=False")))
    (multiple-value-bind (rehashes results)
        (th-rehash-inside (lambda () (run-taproot-spend-vector rec)) schnorr-types)
      (is (eq t (first results)))
      (is (= 1 (length rehashes)))
      (let* ((tx (flexi-streams:with-input-from-sequence
                     (s (bl.crypto:hex-to-bytes (gethash "tx" rec)))
                   (bl.ser:read-transaction s)))
             (spent (map 'vector (lambda (p)
                                   (bl.store:make-utxo-entry
                                    :value (gethash "amountSats" p)
                                    :script-pubkey (bl.crypto:hex-to-bytes
                                                    (gethash "scriptPubKey" p))))
                         (gethash "prevouts" rec)))
             (bl.interop:*current-tx* tx)
             (bl.interop:*current-spent-utxos* spent)
             (bl.interop:*current-input-index* (gethash "index" rec))
             (bl.interop:*precomputed-sighash* nil))
        (destructuring-bind (event . digests) (first rehashes)
          (is (equalp (mapcar (lambda (ht) (th-rehash event ht)) schnorr-types) digests))
          (is (equalp (getf event :digest) (first digests))))))))

;;; ------------------------------------------------------------------
;;; 5. Signature checks
;;; ------------------------------------------------------------------

(test checkmultisig-reports-each-attempt-after-its-sighash
  "A 2-of-3 CHECKMULTISIG signed by keys 1 and 3 makes Core's three attempts.
Each is a :SIGHASH then a :SIGCHECK over the same digest, in order, answering
match, no match, match."
  (multiple-value-bind (tx utxo) (th-two-of-three-spend)
    (multiple-value-bind (events ok)
        (let ((bl.interop:*signature-cache-enabled* nil))
          (th-trace-input tx utxo))
      (is (eq t ok))
      (let ((signature-events (remove-if-not (lambda (e) (member (car e) '(:sighash :sigcheck)))
                                             events)))
        (is (equal '(:sighash :sigcheck :sighash :sigcheck :sighash :sigcheck)
                   (mapcar #'car signature-events)))
        (loop for (hash check) on signature-events by #'cddr
              do (is (equalp (getf (cdr hash) :digest) (getf (cdr check) :digest))))
        (is (equal '(t nil t) (th-field :result (th-of :sigcheck events))))
        (is (equal '(nil nil nil) (th-field :cached (th-of :sigcheck events))))))))

(test a-cached-verification-is-still-reported
  "A verification the signature cache answers still sends :SIGCHECK, with
:CACHED true. After one run has stored the two matches, a second reports them
cached; the attempt that failed was never stored and is verified again."
  (multiple-value-bind (tx utxo) (th-two-of-three-spend)
    (let ((bl.interop:*signature-cache-enabled* t)
          (bl.interop:*signature-cache-store* t))
      (is (eq t (nth-value 1 (th-trace-input tx utxo))))
      (let ((checks (th-of :sigcheck (th-trace-input tx utxo))))
        (is (equal '(t nil t) (th-field :cached checks)))
        (is (equal '(t nil t) (th-field :result checks)))))))

(test a-signature-rejected-before-the-verify-sends-no-sigcheck
  "No :SIGCHECK for a signature that never reaches the cryptographic verify:
an empty one (CHECKSIG just answers false, and no sighash is computed), and
one that is not strict DER under DERSIG (the frame ends with SIG_DER, its last
step at the CHECKSIG)."
  (let ((pubkey-push (format nil "0x21 0x~A" +th-generator-pubkey+)))
    (multiple-value-bind (events results)
        (th-record (lambda ()
                     (run-script-test "0" (format nil "~A CHECKSIG NOT" pubkey-push) "")))
      (is (eq t (first results)))
      (is (null (th-of :sigcheck events)))
      (is (null (th-of :sighash events)))
      (let ((steps (second (second (th-frames events)))))
        ;; The step after CHECKSIG (pubkey push at 0, CHECKSIG at 34).
        (is (equalp '(#()) (getf (find 35 steps :key (lambda (s) (getf s :position)))
                                  :main-stack)))))
    (multiple-value-bind (events results)
        (th-record (lambda ()
                     (run-script-test "0x05 0x0102030401" (format nil "~A CHECKSIG" pubkey-push)
                                      "DERSIG")))
      (is (null (first results)))
      (is (null (th-of :sigcheck events)))
      (let ((frame (second (th-frames events))))
        (is (equal "SIG_DER" (getf (third frame) :error)))
        (is (= 34 (getf (car (last (second frame))) :position)))))))

;;; ------------------------------------------------------------------
;;; 6. Differential: the hook changes no answer
;;; ------------------------------------------------------------------

(defun th-frame-heads (events)
  "Each frame of EVENTS as (SIGVERSION . SCRIPT)."
  (mapcar (lambda (frame) (cons (getf (first frame) :sigversion) (getf (first frame) :script)))
          (th-frames events)))

(defun th-flag-p (flags name)
  "Whether the comma-separated FLAGS string names the flag NAME."
  (and (member name (uiop:split-string flags :separator ",") :test #'string=) t))

(defun th-script-corpus-rows ()
  "Every script_tests.json vector, run with the hook unbound and then bound to a
recorder: one (INDEX UNTRACED TRACED FRAME-HEADS STEPS WITNESS-P WITNESS-FLAG-P)
per vector, UNTRACED and TRACED the Core error names of the two runs."
  (loop for test in (load-script-tests)
        for index from 0
        nconc (multiple-value-bind (sig pubkey flags expected comment witness amount)
                  (parse-test-case test)
                (declare (ignore expected comment))
                (when sig
                  (multiple-value-bind (ok err) (run-script-test sig pubkey flags witness amount)
                    (multiple-value-bind (events results)
                        (th-record (lambda () (run-script-test sig pubkey flags witness amount)))
                      (list (list index
                                  (%script-error-name ok err)
                                  (%script-error-name (first results) (second results))
                                  (th-frame-heads events)
                                  (length (th-of :step events))
                                  (and amount t)
                                  (th-flag-p flags "WITNESS")))))))))

(defun th-p2wpkh-program-p (script)
  "Whether SCRIPT is a version-0 witness program of 20 bytes."
  (and (= 22 (length script)) (= 0 (aref script 0)) (= #x14 (aref script 1))))

(test the-hook-changes-no-script-corpus-answer
  "Every script_tests.json vector gives the same verdict and Core error name
with the hook bound as without it. The control that the hook ran: every vector
that executed a script reports steps, the frame counts by SigVersion are
pinned, a vector with no frame at all was refused before any script ran, and a
witness vector with no witness frame ran without the WITNESS flag, is a P2WPKH
spend, or was refused."
  (let* ((rows (th-script-corpus-rows))
         (mismatches (remove-if (lambda (row) (string= (second row) (third row))) rows))
         (framed (remove-if-not #'fourth rows))
         (unframed (remove-if #'fourth rows))
         (witness (remove-if-not #'sixth rows))
         (witness-unframed
           (remove-if (lambda (row)
                        (find-if (lambda (head) (member (car head) '(:witness-v0 :tapscript)))
                                 (fourth row)))
                      witness))
         (heads (mapcan (lambda (row) (copy-list (fourth row))) rows)))
    (is (= 1222 (length rows)))
    (is (null mismatches) "~D vectors answer differently with the hook bound: ~S"
        (length mismatches) mismatches)
    (is (every (lambda (row) (plusp (fifth row))) framed)
        "a framed vector reported no step")
    (is (equal '(:base 2451 :witness-v0 79 :tapscript 5)
               (loop for sv in '(:base :witness-v0 :tapscript)
                     nconc (list sv (count sv heads :key #'car))))
        "frames by SigVersion: ~S"
        (loop for sv in '(:base :witness-v0 :tapscript)
              nconc (list sv (count sv heads :key #'car))))
    (is (= 5 (length unframed)) "~D vectors with no frame" (length unframed))
    (is (every (lambda (row) (member (second row) '("SIG_PUSHONLY" "OP_CODESEPARATOR")
                                     :test #'string=))
               unframed)
        "unframed vectors: ~S" (mapcar (lambda (row) (list (first row) (second row))) unframed))
    (is (= 113 (length witness)))
    (let* ((unflagged (remove-if #'seventh witness-unframed))
           (flagged (remove-if-not #'seventh witness-unframed))
           (p2wpkh (remove-if-not (lambda (row)
                                    (find-if #'th-p2wpkh-program-p (fourth row) :key #'cdr))
                                  flagged))
           (refused (remove-if (lambda (row)
                                 (find-if #'th-p2wpkh-program-p (fourth row) :key #'cdr))
                               flagged)))
      (is (= 6 (length unflagged)) "~D witness vectors without the WITNESS flag"
          (length unflagged))
      (is (= 14 (length p2wpkh)) "~D P2WPKH witness vectors" (length p2wpkh))
      (is (every (lambda (row) (string/= "OK" (second row))) refused)
          "a witness vector with no witness frame that is not P2WPKH succeeded: ~S"
          (remove "OK" refused :key #'second :test-not #'string=))
      (is (= 9 (length refused)) "~D refused witness vectors" (length refused)))))

(defun th-answer (values)
  "VALUES of a validation as (OK ERR), with a signalled condition named by its
type: two runs that signal answer alike only through the type, never the object."
  (destructuring-bind (&optional ok err &rest more) values
    (declare (ignore more))
    (list ok (if (typep err 'condition) (type-of err) err))))

(defun th-tx-corpus-rows (filename effective-flags-p)
  "Every input of every FILENAME row validated with the hook unbound and then
bound: one (ROW INPUT UNTRACED TRACED STEPS) per input, UNTRACED and TRACED the
two answers as TH-ANSWER gives them. EFFECTIVE-FLAGS-P reads the flags column
as tx_valid.json does, as the flags to exclude."
  (let ((rows '()))
    (loop for row in (load-tx-tests filename)
          for row-index from 0
          do (multiple-value-bind (prevouts tx-hex flags) (parse-tx-test-case row)
               (when prevouts
                 (let ((tx (ignore-errors
                            (bl.ser:parse-tx-payload (bl.crypto:hex-to-bytes tx-hex))))
                       (flags (if effective-flags-p (compute-effective-flags flags) flags)))
                   (when tx
                     (loop for prevout in prevouts
                           for input from 0
                           below (length (bl.ser:transaction-inputs tx))
                           do (let ((untraced (multiple-value-list
                                               (ignore-errors
                                                (validate-single-tx-input tx input prevout flags)))))
                                (multiple-value-bind (events results)
                                    (th-record (lambda ()
                                                 (ignore-errors
                                                  (validate-single-tx-input tx input prevout flags))))
                                  (push (list row-index input
                                              (th-answer untraced)
                                              (th-answer results)
                                              (length (th-of :step events)))
                                        rows)))))))))
    (nreverse rows)))

(test the-hook-changes-no-tx-corpus-answer
  "Every input of tx_valid.json and tx_invalid.json validates the same with
the hook bound as without it, and the traced runs report the pinned number of
steps."
  (dolist (corpus '(("tx_valid.json" t 176 1265) ("tx_invalid.json" nil 110 600)))
    (destructuring-bind (filename effective-p inputs steps) corpus
      (let* ((rows (th-tx-corpus-rows filename effective-p))
             (mismatches (remove-if (lambda (row) (equal (third row) (fourth row))) rows))
             (total-steps (reduce #'+ rows :key #'fifth)))
        (is (= inputs (length rows)) "~A: ~D inputs" filename (length rows))
        (is (null mismatches) "~A: ~D inputs answer differently: ~S"
            filename (length mismatches) mismatches)
        (is (= steps total-steps) "~A: ~D steps" filename total-steps)))))

;;; ------------------------------------------------------------------
;;; 7. The hook's own conditions, and its thread
;;; ------------------------------------------------------------------

(define-condition th-hook-signal (error) ()
  (:documentation "Signalled by a test hook, to see where it arrives."))

(test a-condition-the-hook-signals-reaches-the-caller
  "VERIFY-SCRIPT turns no condition from the hook into a verdict: the hook's
own condition arrives at the caller. The same call without that hook verifies."
  (let ((bl.interop:*script-flags* "P2SH")
        (sig (assemble-script "1"))
        (spk (assemble-script "1")))
    (signals th-hook-signal
      (let ((bl.interop:*script-trace-hook*
              (lambda (event &rest plist)
                (declare (ignore plist))
                (when (eq event :step) (error 'th-hook-signal)))))
        (bl.interop:verify-script sig spk)))
    (is-true (bl.interop:verify-script sig spk))))

(test a-binding-is-seen-only-on-its-own-thread
  "The hook is bound per thread: a thread started inside the binding validates
untraced, while the binding thread's own run is traced."
  (let ((events 0) (thread-answer :never-ran))
    (let ((bl.interop:*script-trace-hook*
            (lambda (event &rest plist)
              (declare (ignore event plist))
              (incf events))))
      (let ((thread (bt:make-thread
                     (lambda ()
                       (handler-case (multiple-value-list (run-script-test "1" "1" "P2SH"))
                         (error (e) (list :error (princ-to-string e))))))))
        (setf thread-answer (bt:join-thread thread)))
      (is (zerop events) "the other thread's run reached the hook ~D times" events)
      (is (eq t (first (multiple-value-list (run-script-test "1" "1" "P2SH")))))
      (is (plusp events) "the binding thread's own run must reach the hook"))
    (is (eq t (first thread-answer)) "the other thread's run: ~S" thread-answer)))
