(in-package #:bitcoin-lisp.tests)

;;;; The differential lane against Bitcoin Core's own binaries
;;;;
;;;; GA11 left one harness lane open (docs/gap-analysis-11.md, "Harness
;;;; lanes"): comparing our transaction codec with Core's `bitcoin-tx' and
;;;; `bitcoin-util', which could not be built here. A released binary can be run
;;;; instead: scripts/get-previous-releases.sh fetches and verifies the
;;;; archives, scripts/previous-releases-volume.sh unpacks them inside the
;;;; container, and they appear at /releases/<tag>/bin/ (BL_CORE_BIN_DIR
;;;; overrides the default v28.2).
;;;;
;;;; Four questions, each over Core's own vectors:
;;;;   1. decode: `bitcoin-tx -json HEX' against decoderawtransaction plus our
;;;;      re-serialization, over every transaction in tx_valid.json,
;;;;      tx_invalid.json, sighash.json and test/functional/data/util/*.hex --
;;;;      same verdict, and when both decode, the same JSON with every number
;;;;      compared as TEXT (an amount's digits are part of the contract);
;;;;   2. create: `bitcoin-tx -create ...' against createrawtransaction for the
;;;;      create forms of Core's bitcoin-util-test.json both can express;
;;;;   3. sign: the `sign=ALL' forms of the same file against
;;;;      signrawtransactionwithkey -- RFC6979 and low-R grinding make the
;;;;      signatures, and so the whole transaction, byte-identical or wrong;
;;;;   4. grind: a header `bitcoin-util grind' solved passes our proof-of-work
;;;;      check and round-trips through our header codec.
;;;;
;;;; Without the binaries every test SKIPS (the ordinary battery), unless
;;;; BL_REQUIRE_CORE_BINARIES=1, which scripts/interop-test.sh sets: there an
;;;; absent binary is a failure, never a quiet pass.

(def-suite :core-binary-differential-tests
  :description "Our transaction codec and raw-transaction RPCs against Core's bitcoin-tx / bitcoin-util"
  :in :bitcoin-lisp-tests)

(in-suite :core-binary-differential-tests)

(defun %core-bin-dir ()
  (uiop:ensure-directory-pathname
   (or (uiop:getenv "BL_CORE_BIN_DIR") "/releases/v28.2/bin/")))

(defun %core-binary (name)
  "The path of Core's NAME binary under %CORE-BIN-DIR, or NIL."
  (let ((path (merge-pathnames name (%core-bin-dir))))
    (and (probe-file path) path)))

(defmacro %with-core-binary ((var name) &body body)
  "Run BODY with VAR bound to Core's NAME binary; without one, SKIP -- or FAIL
when BL_REQUIRE_CORE_BINARIES=1 (the named lane)."
  `(let ((,var (%core-binary ,name)))
     (cond (,var ,@body)
           ((equal (uiop:getenv "BL_REQUIRE_CORE_BINARIES") "1")
            (fail "~A not found under ~A, and BL_REQUIRE_CORE_BINARIES=1"
                  ,name (%core-bin-dir)))
           (t (skip "~A not found under ~A: Core's previous releases are not mounted"
                    ,name (%core-bin-dir))))))

(defun %run-core (binary &rest args)
  "Run BINARY with ARGS; (values stdout-trimmed exit-code stderr)."
  (multiple-value-bind (out err code)
      (uiop:run-program (cons (namestring binary) args)
                        :output :string :error-output :string
                        :ignore-error-status t)
    (values (string-trim '(#\Space #\Tab #\Newline #\Return) out) code err)))

(defun %core-data (relative)
  "RELATIVE under the pinned Core checkout, or NIL when refs/bitcoin is absent."
  (probe-file (merge-pathnames (concatenate 'string "refs/bitcoin/" relative)
                               (asdf:system-source-directory :bitcoin-lisp))))

;;; A JSON reader for COMPARISON: objects become key-sorted alists, and every
;;; number stays the TEXT it was written as, so 0.00001000 and 1e-05 differ
;;; the way they differ for a client. (yason would parse both to one float.)

(defun %json-canon (text)
  "TEXT as a comparable tree: (:object (key . value)...) with keys sorted,
(:array value...), (:atom \"literal\") for numbers/true/false/null, and a
Lisp string for a JSON string."
  (let ((pos 0) (n (length text))
        (delimiters (coerce '(#\, #\] #\} #\Space #\Tab #\Newline #\Return) 'string)))
    (labels ((skip-ws ()
               (loop while (and (< pos n)
                                (member (char text pos) '(#\Space #\Tab #\Newline #\Return)))
                     do (incf pos)))
             (peek () (skip-ws) (and (< pos n) (char text pos)))
             (expect (c)
               (unless (eql (peek) c) (error "JSON: expected ~A at ~D" c pos))
               (incf pos))
             (str ()
               (expect #\")
               (with-output-to-string (o)
                 (loop (let ((c (char text pos)))
                         (incf pos)
                         (cond ((char= c #\") (return))
                               ((char= c #\\)
                                (let ((e (char text pos)))
                                  (incf pos)
                                  (case e
                                    (#\n (write-char #\Newline o))
                                    (#\t (write-char #\Tab o))
                                    (#\r (write-char #\Return o))
                                    (#\b (write-char #\Backspace o))
                                    (#\f (write-char #\Page o))
                                    (#\u (write-char (code-char (parse-integer text :start pos
                                                                                    :end (+ pos 4)
                                                                                    :radix 16))
                                                     o)
                                     (incf pos 4))
                                    (t (write-char e o)))))
                               (t (write-char c o)))))))
             (value ()
               (case (peek)
                 (#\{ (incf pos)
                  (let ((members '()))
                    (unless (eql (peek) #\})
                      (loop (let ((k (str)))
                              (expect #\:)
                              (push (cons k (value)) members))
                            (if (eql (peek) #\,) (incf pos) (return))))
                    (expect #\})
                    (list* :object (sort members #'string< :key #'car))))
                 (#\[ (incf pos)
                  (let ((items '()))
                    (unless (eql (peek) #\])
                      (loop (push (value) items)
                            (if (eql (peek) #\,) (incf pos) (return))))
                    (expect #\])
                    (list* :array (nreverse items))))
                 (#\" (str))
                 (t (let ((start pos))
                      (loop while (and (< pos n) (not (find (char text pos) delimiters)))
                            do (incf pos))
                      (list :atom (subseq text start pos)))))))
      (prog1 (value)
        (skip-ws)
        (unless (= pos n) (error "JSON: trailing text at ~D" pos))))))

(test the-comparison-reader-keeps-number-text-and-ignores-key-order
  "The reader the lane compares with: numbers are compared as written, object
keys in any order. Runs without Core's binaries -- if this is wrong, every
agreement the lane reports is suspect."
  (is (equal (%json-canon "{\"b\":[1,\"x\"],\"a\":0.00001000}")
             (%json-canon " { \"a\" : 0.00001000 , \"b\" : [ 1 , \"x\" ] } ")))
  (is (not (equal (%json-canon "{\"a\":0.00001000}") (%json-canon "{\"a\":1e-05}")))
      "0.00001000 and 1e-05 are different JSON for a client")
  (is (not (equal (%json-canon "[\"1\"]") (%json-canon "[1]"))))
  (is (equal "a\"b" (%json-canon "\"a\\\"b\""))))

;;; 1. decode

(defun %corpus-transactions ()
  "Every serialized transaction in Core's vectors: tx_valid.json and
tx_invalid.json (the second field of each non-comment row), sighash.json (the
first), and test/functional/data/util/*.hex, de-duplicated, in that order."
  (let ((hexes '()))
    (flet ((json-rows (relative)
             (let ((path (%core-data relative)))
               (when path
                 (with-open-file (in path) (yason:parse in))))))
      (dolist (file '("src/test/data/tx_valid.json" "src/test/data/tx_invalid.json"))
        (dolist (row (json-rows file))
          (when (and (listp row) (>= (length row) 3) (stringp (second row)))
            (push (string-downcase (second row)) hexes))))
      (dolist (row (rest (json-rows "src/test/data/sighash.json")))
        (when (and (listp row) (stringp (first row)))
          (push (string-downcase (first row)) hexes)))
      (let ((dir (%core-data "test/functional/data/util/")))
        (when dir
          (dolist (file (directory (merge-pathnames "*.hex" dir)))
            (let ((text (string-trim '(#\Space #\Tab #\Newline #\Return)
                                     (uiop:read-file-string file))))
              (when (and (plusp (length text)) (every (lambda (c) (digit-char-p c 16)) text))
                (push (string-downcase text) hexes)))))))
    (remove-duplicates (nreverse hexes) :test #'string= :from-end t)))

(defun %our-decode-json (node hex)
  "decoderawtransaction's JSON for HEX plus the \"hex\" field bitcoin-tx adds
(TxToUniv with include_hex, core_io.cpp), as text; NIL when we refuse HEX."
  (handler-case
      (let ((result (bl.rpc:dispatch-rpc-method node "decoderawtransaction" (list hex)))
            (tx (bl.rpc:decode-hex-tx hex)))
        (rpc-result-json
         (append result
                 (list (cons "hex" (bl.crypto:bytes-to-hex
                                    (bl.ser:transaction-wire-bytes tx)))))))
    (bl.rpc:rpc-error () nil)))

(test bitcoin-tx-decodes-core-s-vectors-as-we-do
  "For every transaction in Core's own vectors, `bitcoin-tx -json' and our
decoderawtransaction reach the same verdict, and where both decode, the same
JSON: txid, wtxid, sizes, every input and output, scripts in asm and hex, the
amounts' digits, and the re-serialization."
  (%with-core-binary (bitcoin-tx "bitcoin-tx")
    (with-network (:mainnet)
      (let ((node (make-test-node :network :mainnet))
            (corpus (%corpus-transactions))
            (compared 0) (both-refused 0) (mismatches '()))
        ;; Shape control: the corpus is what the lane claims it is (672
        ;; distinct transactions at the pin); a parsing slip in the loader
        ;; would otherwise show up as a green run over nothing.
        (is (> (length corpus) 600) "only ~D transactions in the corpus" (length corpus))
        (dolist (hex corpus)
          (multiple-value-bind (core-out code) (%run-core bitcoin-tx "-json" hex)
            (let ((ours (%our-decode-json node hex)))
              (cond ((and (/= code 0) (null ours)) (incf both-refused))
                    ((or (/= code 0) (null ours))
                     (push (list hex :verdict (if ours :we-decode :core-decodes)) mismatches))
                    ((equal (%json-canon core-out) (%json-canon ours)) (incf compared))
                    (t (push (list hex :json core-out ours) mismatches))))))
        (is (> compared 600) "only ~D transactions decoded by both" compared)
        ;; The verdict branch, exercised: malformed encodings both must refuse
        ;; -- trailing bytes, a truncated body, an empty string, a superfluous
        ;; witness record (marker and flag with no witness data).
        (let ((sample (first corpus)))
          (dolist (bad (list (concatenate 'string sample "00")
                             (subseq sample 0 (- (length sample) 2))
                             ""
                             "0100000000010000000000"))
            (multiple-value-bind (core-out code) (%run-core bitcoin-tx "-json" bad)
              (declare (ignore core-out))
              (is (/= 0 code) "bitcoin-tx accepted malformed ~S" bad)
              (is (null (%our-decode-json node bad)) "we accepted malformed ~S" bad))))
        (is (null mismatches)
            "~D of ~D transactions disagree with bitcoin-tx; first: ~S"
            (length mismatches) (length corpus) (car (last mismatches)))
        (format *test-dribble* "~&; bitcoin-tx decode: ~D agree, ~D refused by both~%"
                compared both-refused)))))

;;; 2. create and 3. sign, over Core's bitcoin-util-test.json

(defun %util-test-cases ()
  "The rows of Core's test/functional/data/util/bitcoin-util-test.json."
  (let ((path (%core-data "test/functional/data/util/bitcoin-util-test.json")))
    (when path
      (with-open-file (in path) (yason:parse in :object-as :alist)))))

(defun %field (row name) (cdr (assoc name row :test #'string=)))

(defun %split-once (string char)
  (let ((i (position char string)))
    (if i (values (subseq string 0 i) (subseq string (1+ i))) (values string nil))))

(defun %table (&rest pairs)
  "A JSON object as the RPC dispatcher receives one (a hash table)."
  (let ((h (make-hash-table :test 'equal)))
    (loop for (k v) on pairs by #'cddr do (setf (gethash k h) v))
    h))

(defun %create-form->rpc (args)
  "bitcoin-tx -create ARGS as createrawtransaction's (inputs outputs locktime
replaceable version) plus the signing extras (privkeys prevtxs sighash), or NIL
for a form createrawtransaction cannot say. An input's sequence is always
passed: bitcoin-tx defaults it to SEQUENCE_FINAL while createrawtransaction
derives one from the locktime (rpc/rawtransaction_util.cpp), so leaving it out
would compare two defaults instead of two encoders."
  (let ((inputs '()) (outputs '()) (locktime 0) (version 2)
        (privkeys nil) (prevtxs nil) (sighash nil))
    (dolist (arg (rest args))
      (multiple-value-bind (key value) (%split-once arg #\=)
        (cond
          ((string= key "nversion") (setf version (parse-integer value)))
          ((string= key "locktime") (setf locktime (parse-integer value)))
          ((string= key "in")
           (let ((parts (uiop:split-string value :separator ":")))
             (push (%table "txid" (first parts)
                           "vout" (parse-integer (second parts))
                           "sequence" (if (third parts)
                                          (parse-integer (string-trim " " (third parts)))
                                          #xffffffff))
                   inputs)))
          ((string= key "outaddr")
           (multiple-value-bind (amount address) (%split-once value #\:)
             (push (%table address amount) outputs)))
          ((string= key "outdata")
           (multiple-value-bind (a b) (%split-once value #\:)
             ;; createrawtransaction's data output carries no value.
             (when (and b (string/= a "0")) (return-from %create-form->rpc nil))
             (push (%table "data" (or b a)) outputs)))
          ((string= key "set")
           (multiple-value-bind (what json) (%split-once value #\:)
             (cond ((string= what "privatekeys") (setf privkeys (yason:parse json)))
                   ((string= what "prevtxs") (setf prevtxs (yason:parse json)))
                   (t (return-from %create-form->rpc nil)))))
          ((string= key "sign") (setf sighash value))
          (t (return-from %create-form->rpc nil)))))
    ;; Vectors, through WIRE-PARAMS: a JSON array as the wire hands one over,
    ;; so an empty one is [] and not null.
    (list :create (list (coerce (nreverse inputs) 'vector)
                        (coerce (nreverse outputs) 'vector)
                        locktime nil version)
          :privkeys privkeys :prevtxs prevtxs :sighash sighash)))

(defparameter +extra-create-forms+
  '(("-create" "nversion=2" "locktime=500000"
     "in=5897de6bd6027a475eadd57019d4e6872c396d0716c4875a5f1a6fcfdf385c1f:3:4294967294"
     "outaddr=0.5:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    ("-create" "nversion=3"
     "in=bf829c6bcf84579331337659d31f89dfd138f7f7785802d5501c92333145ca7c:18:0"
     "outaddr=21000000:bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297"
     "outaddr=0.00000001:3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
     "outdata=0:00")
    ("-create" "locktime=4294967295"
     ;; bitcoin-tx caps vout at MAX_BLOCK_WEIGHT / (4 * 9) = 111111
     ;; (bitcoin-tx.cpp MutateTxAddInput); createrawtransaction does not.
     "in=22a6f904655d53ae2ff70e701a0bbd90aa3975c0f40bfc6cc996a9049e31cdfc:111111"
     "outaddr=0:bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"))
  "Create forms beyond Core's file, over what it leaves out: BIP173/BIP350
example addresses (P2WPKH, P2TR, P2WSH) and a P2SH one, a v3 transaction,
the extreme locktime, bitcoin-tx's largest vout, MAX_MONEY and one satoshi, an
explicit zero-value data output, and sequences at both ends.")

(defun %util-create-cases (&key signing)
  "The -create rows of bitcoin-util-test.json that succeed in Core and that
createrawtransaction can express, plus +EXTRA-CREATE-FORMS+: with SIGNING,
those that sign; without, those that do not. A row's -json flag is dropped:
the hex form is compared, the JSON form being the decode test's business."
  (loop for args in (append (loop for row in (%util-test-cases)
                                  when (and (equal (%field row "exec") "./bitcoin-tx")
                                            (null (%field row "return_code")))
                                    collect (remove "-json" (%field row "args")
                                                    :test #'string=))
                            +extra-create-forms+)
        for form = (and (equal (first args) "-create") (%create-form->rpc args))
        when (and form (eq (and (getf form :sighash) t) (and signing t)))
          ;; bitcoin-tx applies its arguments IN ORDER, and Core's sign rows
          ;; put sign=ALL before the outaddr= they add: the signature commits
          ;; to a transaction with no outputs, and the output appended after
          ;; it invalidates it (our interpreter rejects txcreatesignv1.hex:
          ;; EVAL_FALSE). createrawtransaction + signrawtransactionwithkey can
          ;; only sign the finished transaction, so bitcoin-tx is asked to sign
          ;; last too.
          collect (cons (append (remove-if (lambda (a) (uiop:string-prefix-p "sign=" a)) args)
                                (remove-if-not (lambda (a) (uiop:string-prefix-p "sign=" a)) args))
                        form)))

(defun %our-create (node form)
  (let ((hex (bl.rpc:dispatch-rpc-method node "createrawtransaction"
                                         (wire-params (getf form :create)))))
    (if (getf form :sighash)
        (%field (bl.rpc:dispatch-rpc-method
                 node "signrawtransactionwithkey"
                 (wire-params (list hex (getf form :privkeys) (getf form :prevtxs)
                                    (getf form :sighash))))
                "hex")
        hex)))

(defun %compare-create-forms (bitcoin-tx cases)
  "Run every case through bitcoin-tx and through our RPCs; the mismatches."
  (let ((node (make-test-node :network :mainnet)) (mismatches '()))
    (dolist (case cases (nreverse mismatches))
      (destructuring-bind (args . form) case
        (multiple-value-bind (core code) (apply #'%run-core bitcoin-tx args)
          (let ((ours (handler-case (%our-create node form)
                        (error (e) (format nil "ERROR: ~A" e)))))
            (unless (and (= code 0) (equal core ours))
              (push (list args :core core :exit code :ours ours) mismatches))))))))

(test bitcoin-tx-creates-what-createrawtransaction-creates
  "Core's own -create vectors (bitcoin-util-test.json) through bitcoin-tx and
through createrawtransaction: byte-identical transactions -- versions,
locktimes, inputs with their sequences, address and data outputs."
  (%with-core-binary (bitcoin-tx "bitcoin-tx")
    (with-network (:mainnet)
      (let ((cases (%util-create-cases)))
        (is (>= (length cases) 8) "only ~D create forms selected" (length cases))
        (let ((mismatches (%compare-create-forms bitcoin-tx cases)))
          (is (null mismatches) "~D of ~D create forms differ: ~S"
              (length mismatches) (length cases) mismatches))))))

(test bitcoin-tx-signs-what-signrawtransactionwithkey-signs
  "Core's own sign=ALL vectors: a P2PKH spend with an uncompressed key (v1 and
v2 transactions) and a P2WPKH spend. RFC6979 nonces and low-R grinding make a
correct signature unique, so the whole signed transaction must be Core's to the
byte."
  (%with-core-binary (bitcoin-tx "bitcoin-tx")
    (with-network (:mainnet)
      (let ((cases (%util-create-cases :signing t)))
        (is (>= (length cases) 3) "only ~D signing forms selected" (length cases))
        (let ((mismatches (%compare-create-forms bitcoin-tx cases)))
          (is (null mismatches) "~D of ~D signing forms differ: ~S"
              (length mismatches) (length cases) mismatches))))))

;;; 4. grind

(test bitcoin-util-grinds-a-header-our-proof-of-work-accepts
  "`bitcoin-util grind' (bitcoin-util.cpp:88-151: nonces from 0 upward, one
stride per thread, until the header hash meets its nBits) on the regtest
genesis header with a 1-in-65536 nBits and a zero nonce: the header it returns
decodes with our codec, re-encodes to the same 80 bytes, changes nothing but
the nonce, and passes our proof-of-work check. The zero-nonce header is the
control: it must NOT pass. (Which nonce is found depends on the thread count,
so only the verdict is compared.)"
  (%with-core-binary (bitcoin-util "bitcoin-util")
    (with-network (:regtest)
      (let* ((genesis (bl.ser:bitcoin-block-header (bl.store:make-genesis-block :regtest)))
             (cleared (bl.ser:make-block-header
                       :version (bl.ser:block-header-version genesis)
                       :prev-block (bl.ser:block-header-prev-block genesis)
                       :merkle-root (bl.ser:block-header-merkle-root genesis)
                       :timestamp (bl.ser:block-header-timestamp genesis)
                       ;; A 1-in-65536 target, not regtest's 1-in-2: grind
                       ;; still answers at once, and the nonce-0 control
                       ;; below can fail (regtest's genesis bits let it pass).
                       :bits #x1f00ffff
                       :nonce 0)))
        (let* ((cleared-hex (bl.crypto:bytes-to-hex (bl.ser:serialize-block-header cleared)))
               (ground-hex (%run-core bitcoin-util "grind" cleared-hex))
               (ground (flexi-streams:with-input-from-sequence
                           (in (bl.crypto:hex-to-bytes ground-hex))
                         (bl.ser:read-block-header in))))
          (is (= 160 (length ground-hex)) "bitcoin-util answered ~S" ground-hex)
          (is (string= ground-hex (bl.crypto:bytes-to-hex (bl.ser:serialize-block-header ground))))
          (is (string= (subseq cleared-hex 0 152) (subseq ground-hex 0 152))
              "only the nonce may change")
          (is-true (bl.val:check-proof-of-work ground))
          (is-false (bl.val:check-proof-of-work cleared)
                    "the nonce-0 control must fail, or the check proves nothing"))))))
