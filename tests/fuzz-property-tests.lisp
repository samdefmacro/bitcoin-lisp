(in-package #:bitcoin-lisp.tests)

;;;; Property tests over arbitrary bytes — the parsers a hostile peer reaches.
;;;;
;;;; Bitcoin Core has 133 libFuzzer targets and we have none: no coverage-guided
;;;; engine, no sanitizers, no corpus minimisation. This is NOT that, and calling
;;;; it fuzzing would overstate it. What it IS is the half of a fuzz target that
;;;; does not need the engine: Core's targets are a random-byte generator wired
;;;; to PROPERTY ASSERTIONS, and the assertions port directly.
;;;;
;;;; Two properties, both of which a network-facing parser must have:
;;;;
;;;;   TOTALITY — arbitrary bytes produce a value or a DECLARED condition, never
;;;;     an undeclared one and never a hang. An unhandled TYPE-ERROR out of a
;;;;     deserializer is a remote crash: every one of these is reachable from a
;;;;     P2P message body.
;;;;   ROUNDTRIP — whatever parses must re-encode to what was parsed. Core
;;;;     asserts this in base_encode_decode.cpp and deserialize.cpp; it is what
;;;;     catches a parser that silently drops or invents a field.
;;;;
;;;; The byte source is a SEEDED xorshift, so a failure names the exact seed and
;;;; iteration that produced it and can be replayed. That is the property this
;;;; harness cannot do without: an unreproducible failure is a rumour.

(def-suite :fuzz-property-tests :in :bitcoin-lisp-tests
  :description "Randomised totality/roundtrip properties over hostile input")

(in-suite :fuzz-property-tests)

(defvar *fuzz-state* 0)

(defun %fuzz-seed (n)
  (setf *fuzz-state* (logior 1 (ldb (byte 64 0) (* n 6364136223846793005)))))

(defun %fuzz-u64 ()
  "xorshift64*, so the sequence is reproducible from its seed on any host —
CL:RANDOM is not specified to be, and a corpus you cannot replay is a rumour."
  (let ((x *fuzz-state*))
    (setf x (ldb (byte 64 0) (logxor x (ash x 13))))
    (setf x (logxor x (ash x -7)))
    (setf x (ldb (byte 64 0) (logxor x (ash x 17))))
    (setf *fuzz-state* x)
    (ldb (byte 64 0) (* x 2685821657736338717))))

(defun %fuzz-bytes (max-len)
  "A byte vector of length 0..MAX-LEN.

Not uniform on purpose: a uniformly random blob almost never gets past a length
prefix, so most of the budget would be spent rejecting garbage at byte one.
A quarter of the draws are SMALL (the boundary cases: empty, one byte, a bare
compact-size), and a quarter are LOW-ENTROPY runs of one byte, which is what
reaches a length field big enough to matter."
  (let* ((r (%fuzz-u64))
         (mode (ldb (byte 2 0) r))
         (len (case mode
                (0 (mod (ash r -2) 4))
                (t (mod (ash r -2) (1+ max-len)))))
         (out (make-array len :element-type '(unsigned-byte 8))))
    (if (= mode 1)
        (let ((fill (ldb (byte 8 0) (%fuzz-u64))))
          (fill out fill))
        (dotimes (i len)
          (setf (aref out i) (ldb (byte 8 0) (%fuzz-u64)))))
    out))

(defmacro %fuzz-total ((label seed iterations bytes-var &key (max-len 256)) &body parse)
  "Assert that PARSE over arbitrary bytes never escapes with an undeclared
condition. ERROR is allowed — a parser saying `no' is correct. What is not
allowed is anything outside CL:ERROR (a control-stack exhaustion, a storage
condition) or a value that is not returned at all."
  (let ((i (gensym)) (caught (gensym)) (bad (gensym)))
    `(let ((,bad '()))
       (%fuzz-seed ,seed)
       (dotimes (,i ,iterations)
         (let ((,bytes-var (%fuzz-bytes ,max-len)))
           (let ((,caught (handler-case (progn ,@parse nil)
                            (error () nil)
                            (storage-condition (c) c)
                            (serious-condition (c) c))))
             (when ,caught
               (push (list ,i (bitcoin-lisp.crypto:bytes-to-hex ,bytes-var)
                           (type-of ,caught))
                     ,bad)))))
       (is (null ,bad)
           "~A: ~D of ~D inputs escaped with a non-ERROR condition; first: ~S"
           ,label (length ,bad) ,iterations (first (last ,bad))))))

(test fuzz-transaction-deserialisation-is-total
  "Every byte string a peer can put in a `tx' message. An undeclared condition
here is a remote crash, and the deserializer is the very first thing an
unauthenticated peer reaches."
  (%fuzz-total ("parse-tx-payload" 1 3000 bytes :max-len 512)
    (bitcoin-lisp.serialization:parse-tx-payload bytes)))

(test fuzz-block-deserialisation-is-total
  "The body of a `block' message, same reasoning."
  (%fuzz-total ("read-bitcoin-block" 2 2000 bytes :max-len 512)
    (bitcoin-lisp.serialization:br-read-bitcoin-block
     (bitcoin-lisp.serialization:make-byte-reader-from bytes))))

(test fuzz-script-classification-is-total
  "classify-script runs over every scriptPubKey in every block and every
scriptSig a peer sends; it has no length or shape guarantee at all."
  (%fuzz-total ("classify-script" 3 4000 bytes :max-len 256)
    (bitcoin-lisp.validation:classify-script bytes)))

(test fuzz-psbt-parsing-is-total
  "PSBTs arrive from wallets and hardware signers, i.e. from outside."
  (%fuzz-total ("parse-psbt" 4 2000 bytes :max-len 512)
    (bitcoin-lisp.serialization:parse-psbt bytes)))

(test fuzz-address-and-descriptor-parsing-are-total
  "Text parsers reachable from RPC. Bytes are read as latin-1 so every octet is
a legal character and the parser sees genuinely arbitrary text."
  (let ((bad '()))
    (%fuzz-seed 5)
    (dotimes (i 3000)
      (let* ((bytes (%fuzz-bytes 128))
             (s (map 'string #'code-char bytes)))
        (let ((caught (handler-case
                          (progn (bitcoin-lisp.crypto:bech32-decode s)
                                 (bitcoin-lisp.crypto:base58-decode s)
                                 (bitcoin-lisp.crypto:decode-address s :mainnet)
                                 (ignore-errors (bitcoin-lisp.rpc::parse-descriptor s :mainnet))
                                 nil)
                        (error () nil)
                        (serious-condition (c) c))))
          (when caught (push (list i s (type-of caught)) bad)))))
    (is (null bad) "~D of 3000 text inputs escaped: first ~S"
        (length bad) (first (last bad)))))

(test fuzz-base58-roundtrips-what-it-decodes
  "Core base_encode_decode.cpp: whatever decodes must re-encode to the same
string. A decoder that silently drops a leading zero byte passes every
hand-written vector and fails here."
  (let ((bad '()))
    (%fuzz-seed 6)
    (dotimes (i 3000)
      (let* ((bytes (%fuzz-bytes 64))
             (encoded (bitcoin-lisp.crypto:base58-encode bytes))
             (decoded (ignore-errors (bitcoin-lisp.crypto:base58-decode encoded))))
        (unless (and decoded (equalp (coerce decoded 'list) (coerce bytes 'list)))
          (push (list i (bitcoin-lisp.crypto:bytes-to-hex bytes) encoded) bad))))
    (is (null bad) "~D of 3000 base58 roundtrips lost data; first ~S"
        (length bad) (first (last bad)))))

(test fuzz-transaction-roundtrips-what-it-parses
  "Core deserialize.cpp's central assertion: a transaction that parses must
re-serialize to the bytes it came from. This is what catches a parser that
accepts a non-canonical encoding and then normalises it — the shape that has
produced consensus splits in other implementations.

Inputs are grown from a VALID transaction rather than drawn at random: a random
blob essentially never parses, so a roundtrip property over random bytes tests
nothing. Mutating a real one keeps the draw inside the parser.

The re-encoder is TRANSACTION-WIRE-BYTES, not SERIALIZE-WITNESS-TRANSACTION:
the latter is the raw BIP144 encoder and emits the marker/flag unconditionally,
which for a witnessless transaction is the encoding Core rejects as a
`Superfluous witness record'. Every caller in the tree guards it with
TRANSACTION-HAS-WITNESS-P; a test that did not would be measuring its own
mistake."
  (let* ((base (bitcoin-lisp.crypto:hex-to-bytes
                (concatenate 'string
                             "0200000001c1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1"
                             "e1e1e1e1e1e1e1e1e1e1e1e100000000006400000001"
                             "e803000000000000160014751e76e8199196d454941c45"
                             "d1b3a323f1433bd600000000")))
         (bad '())
         (parsed 0))
    (%fuzz-seed 7)
    (dotimes (i 2000)
      (let ((mutated (copy-seq base)))
        ;; One to three single-byte edits: enough to reach a different code
        ;; path, rarely enough to still parse.
        (dotimes (edit (1+ (mod (%fuzz-u64) 3)))
          (declare (ignore edit))
          (setf (aref mutated (mod (%fuzz-u64) (length mutated)))
                (ldb (byte 8 0) (%fuzz-u64))))
        (let ((tx (ignore-errors
                   (bitcoin-lisp.serialization:parse-tx-payload mutated))))
          (when tx
            (incf parsed)
            (let ((re (ignore-errors
                       (bitcoin-lisp.serialization:transaction-wire-bytes tx))))
              (unless (and re (equalp (coerce re 'list) (coerce mutated 'list)))
                (push (list i (bitcoin-lisp.crypto:bytes-to-hex mutated)) bad)))))))
    ;; The count matters: if nothing parsed, the property asserted nothing.
    (is (> parsed 50) "only ~D of 2000 mutants parsed — the property is vacuous"
        parsed)
    (is (null bad) "~D parsed transactions did not re-serialize to their input; first ~S"
        (length bad) (first (last bad)))))
