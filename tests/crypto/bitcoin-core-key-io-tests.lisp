(in-package #:bitcoin-lisp.tests)

(def-suite :bitcoin-core-key-io-tests
  :description "Bitcoin Core key_io and base58 vector compatibility tests"
  :in :bitcoin-lisp-tests)

(in-suite :bitcoin-core-key-io-tests)

;;;; Core's address/WIF/base58 corpora (src/test/data/, vendored under
;;;; tests/data/). These are the vectors key_io_tests.cpp and base58_tests.cpp
;;;; run: 70 valid encodings, 70 strings that must be rejected, and 21 raw
;;;; base58 round-trips.
;;;;
;;;; The invalid half is the half that matters. Every parser accepts what it is
;;;; supposed to; the bugs live in what it fails to reject.

(defun %key-io-data (name)
  (let ((path (merge-pathnames (format nil "tests/data/~A" name)
                               (asdf:system-source-directory :bitcoin-lisp))))
    (with-open-file (s path :direction :input) (yason:parse s))))

(defun %key-io-network (chain)
  "Core's chain name to ours. Core writes the address-version chain, so
testnet4 and signet share testnet's byte prefixes and 'tb' hrp."
  (cond ((string= chain "main") :mainnet)
        ((string= chain "testnet4") :testnet4)
        ((string= chain "test") :testnet3)
        ((string= chain "signet") :signet)
        ((string= chain "regtest") :regtest)
        (t (error "unknown chain ~S" chain))))

(defun %decodes-as-address-anywhere-p (string)
  "T if STRING decodes as an address on ANY network we support."
  (some (lambda (net)
          (and (bl.crypto:decode-address string net) t))
        '(:mainnet :testnet3 :testnet4 :signet :regtest)))

(test core-key-io-valid-vectors
  "key_io_valid.json: every address decodes to the stated scriptPubKey on its
own chain, and every WIF decodes to the stated secret with the stated
compression flag (Core key_io_tests.cpp)."
  (let ((vectors (%key-io-data "key_io_valid.json"))
        (checked 0))
    (dolist (v vectors)
      (destructuring-bind (encoded hex meta) v
        (let ((network (%key-io-network (gethash "chain" meta)))
              (expected (bl.crypto:hex-to-bytes hex)))
          (incf checked)
          (if (gethash "isPrivkey" meta)
              ;; WIF: secret bytes and the compression flag must both match.
              (multiple-value-bind (secret compressed)
                  (bl.crypto:wif-to-private-key encoded)
                (is (equalp expected secret)
                    "WIF ~A decoded to ~A, expected ~A"
                    encoded (and secret (bl.crypto:bytes-to-hex secret)) hex)
                (is (eq (and (gethash "isCompressed" meta) t) (and compressed t))
                    "WIF ~A compression flag mismatch" encoded)
                ;; Round-trip: re-encoding the decoded secret reproduces it.
                (when secret
                  (is (string= encoded
                               (bl.crypto:private-key-to-wif
                                secret
                                :network (if (eq network :mainnet) :mainnet :testnet3)
                                :compressed (and compressed t)))
                      "WIF ~A did not round-trip" encoded)))
              ;; Address: the scriptPubKey it stands for must match exactly.
              (multiple-value-bind (type spk)
                  (bl.crypto:decode-address encoded network)
                (declare (ignore type))
                (is (equalp expected spk)
                    "address ~A (~A) decoded to ~A, expected ~A"
                    encoded (gethash "chain" meta)
                    (and spk (bl.crypto:bytes-to-hex spk)) hex))))))
    (is (= 70 checked) "expected Core's 70 valid vectors, ran ~D" checked)))

(test core-key-io-invalid-vectors
  "key_io_invalid.json: none of these strings may decode as an address or as a
WIF on ANY network. This is the rejection half of the corpus — a decoder that
is merely permissive passes the valid vectors and fails only here."
  (let ((vectors (%key-io-data "key_io_invalid.json"))
        (checked 0))
    (dolist (v vectors)
      (let ((s (first v)))
        (incf checked)
        (is-false (%decodes-as-address-anywhere-p s)
                  "string ~S was accepted as an address but Core rejects it" s)
        (is-false (bl.crypto:wif-to-private-key s)
                  "string ~S was accepted as a WIF but Core rejects it" s)))
    (is (= 70 checked) "expected Core's 70 invalid vectors, ran ~D" checked)))

(test core-base58-encode-decode-vectors
  "base58_encode_decode.json: raw base58 (no checksum) round-trips both ways,
including the leading-zero cases that '1' padding exists for (Core
base58_tests.cpp)."
  (let ((vectors (%key-io-data "base58_encode_decode.json"))
        (checked 0))
    (dolist (v vectors)
      (destructuring-bind (hex b58) v
        (let ((bytes (bl.crypto:hex-to-bytes hex)))
          (incf checked)
          (is (string= b58 (bl.crypto:base58-encode bytes))
              "encoding ~S gave ~S, expected ~S"
              hex (bl.crypto:base58-encode bytes) b58)
          (is (equalp bytes (bl.crypto:base58-decode b58 256))
              "decoding ~S did not give ~S" b58 hex))))
    (is (= 21 checked) "expected Core's 21 base58 vectors, ran ~D" checked)))

(defun %base58-test-string (&rest parts)
  "PARTS joined, with an integer standing for the character of that code --
Core's base58_tests.cpp writes the six whitespace characters as C escapes, and
only space and tab have portable Lisp character names."
  (apply #'concatenate 'string
         (mapcar (lambda (p) (if (integerp p) (string (code-char p)) p)) parts)))

(test core-base58-decode-bounds-and-whitespace
  "base58_tests.cpp:64-83, the half of Core's DecodeBase58 contract that is not
about round-tripping: an invalid character or an embedded NUL is a rejection,
leading and trailing whitespace is skipped, whitespace anywhere else is not,
and MAX-RET-LEN is a real bound rather than a check on the finished result."
  (let ((nul (string (code-char 0))))
    ;; Invalid characters and NULs (base58.cpp:127-130 tests the whole string
    ;; for a NUL; our decoder reaches the same answer because NUL is not a
    ;; base58 digit).
    (is (null (bl.crypto:base58-decode "invalid" 100)))
    (is (null (bl.crypto:base58-decode (concatenate 'string "invalid" nul) 100)))
    (is (null (bl.crypto:base58-decode (concatenate 'string nul "invalid") 100)))
    (is-true (bl.crypto:base58-decode "good" 100))
    (is (null (bl.crypto:base58-decode "bad0IOl" 100)))
    (is (null (bl.crypto:base58-decode "goodbad0IOl" 100)))
    (is (null (bl.crypto:base58-decode
               (concatenate 'string "good" nul "bad0IOl") 100))))
  ;; " \t\n\v\f\r skip \r\f\v\n\t " decodes; the same string with a
  ;; trailing "a" does not, because the digits ended at the first space.
  (let ((skip (%base58-test-string " " 9 10 11 12 13 " skip " 13 12 11 10 9 " ")))
    (is (null (bl.crypto:base58-decode (concatenate 'string skip "a") 3)))
    (is (equalp (bl.crypto:hex-to-bytes "971a55")
                (bl.crypto:base58-decode skip 3))))
  ;; DecodeBase58Check's bound excludes the four checksum bytes.
  (is-true (bl.crypto:base58check-decode "3vQB7B6MrGQZaxCuFg4oh" 100))
  (is (null (bl.crypto:base58check-decode "3vQB7B6MrGQZaxCuFg4oi" 100)))
  (is (null (bl.crypto:base58check-decode "3vQB7B6MrGQZaxCuFg4oh0IOl" 100)))
  (is (null (bl.crypto:base58check-decode
             (concatenate 'string "3vQB7B6MrGQZaxCuFg4oh" (string (code-char 0)) "0IOl")
             100)))
  ;; The bound bites one byte early, on a string that is otherwise valid.
  (let ((addr "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"))
    (is (= 25 (length (bl.crypto:base58-decode addr 25))))
    (is (null (bl.crypto:base58-decode addr 24)))
    (is-true (bl.crypto:base58check-decode addr 21))
    (is (null (bl.crypto:base58check-decode addr 20))))
  ;; And leading '1's count against it before a single digit is processed
  ;; (base58.cpp:48-50).
  (is (null (bl.crypto:base58-decode (make-string 5000 :initial-element #\1) 21))))

(test address-decoding-follows-cores-whitespace-and-cost-rules
  "The two consequences at the entry point RPC callers reach. Core's
DecodeDestination accepts an address with whitespace around it (base58.cpp:42-43,
:73-74) and gives up on an over-long one after about thirty characters
(base58.cpp:71); before the bound existed this decoder accumulated one big
integer over the whole argument, which is quadratic -- 200,000 characters cost
3.0 s of the handler thread, and an RPC body may be 32 MiB."
  (is (eq :p2pkh (bl.crypto:decode-address "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2" :mainnet)))
  (is (eq :p2pkh (bl.crypto:decode-address " 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 " :mainnet))
      "Core skips the whitespace around an address; we must decode the same string")
  (is (eq :p2pkh (bl.crypto:decode-address
                  (%base58-test-string 9 13 "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2" 10 12) :mainnet)))
  (is (null (bl.crypto:decode-address "1BvB MSEYstWetqTFn5Au4m4GFg7xJaNVN2" :mainnet))
      "whitespace inside the digits still ends the string")
  (let* ((long (make-string 400000 :initial-element #\z))
         (start (get-internal-real-time))
         (result (bl.crypto:decode-address long :mainnet))
         (seconds (/ (- (get-internal-real-time) start)
                     internal-time-units-per-second)))
    (is (null result))
    (is (< seconds 3)
        "a ~D-character address argument took ~,2F s; the bound is what keeps ~
         this from being quadratic" (length long) seconds)))

;;;; BIP173 / BIP350 bech32 and bech32m vectors (Core bech32_tests.cpp).
;;;;
;;;; These are the generic string-level vectors, not segwit addresses: they
;;;; exercise the separator rules, the hrp character range, the case rules and
;;;; the checksum itself. The invalid list is the point — it is where a decoder
;;;; that merely "works on real addresses" comes apart.

(defun %bech32-case-insensitive-equal (a b)
  (string-equal a b))

(test core-bech32-valid-vectors
  "BIP173: each string decodes as BECH32 and re-encodes to itself, modulo case."
  (dolist (str '("A12UEL5L"
                 "a12uel5l"
                 "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs"
                 "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw"
                 "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j"
                 "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w"
                 "?1ezyfcl"))
    (multiple-value-bind (hrp data variant) (bl.crypto:bech32-decode str)
      (is (eq :bech32 variant) "~S decoded as ~S, expected :bech32" str variant)
      (when hrp
        (is-true (%bech32-case-insensitive-equal
                  str (bl.crypto:bech32-encode hrp data :bech32))
                 "~S did not re-encode to itself" str)))))

(test core-bech32m-valid-vectors
  "BIP350: each string decodes as BECH32M and re-encodes to itself."
  (dolist (str '("A1LQFN3A"
                 "a1lqfn3a"
                 "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6"
                 "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx"
                 "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8"
                 "split1checkupstagehandshakeupstreamerranterredcaperredlc445v"
                 "?1v759aa"))
    (multiple-value-bind (hrp data variant) (bl.crypto:bech32-decode str)
      (is (eq :bech32m variant) "~S decoded as ~S, expected :bech32m" str variant)
      (when hrp
        (is-true (%bech32-case-insensitive-equal
                  str (bl.crypto:bech32-encode hrp data :bech32m))
                 "~S did not re-encode to itself" str)))))

(test core-bech32-invalid-vectors
  "BIP173/BIP350: none of these decode. Each targets one rule — an hrp
character outside [33,126], an over-long string, a missing or misplaced
separator, a character outside the base32 set, mixed case, or a corrupted
checksum."
  (let ((cases (append
                ;; bech32 (BIP173)
                (list (format nil " 1nwldj5")
                      (concatenate 'string (string (code-char #x7f)) "1axkwrx")
                      (concatenate 'string (string (code-char #x80)) "1eym55h"))
                '("an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx"
                  "pzry9x0s0muk"
                  "1pzry9x0s0muk"
                  "x1b4n0q5v"
                  "li1dgmt3")
                (list (concatenate 'string "de1lg7wt" (string (code-char #xff))))
                '("A1G7SGD8"
                  "10a06t8"
                  "1qzzfhee"
                  "a12UEL5L"
                  "A12uEL5L"
                  "abcdef1qpzrz9x8gf2tvdw0s3jn54khce6mua7lmqqqxw"
                  "test1zg69w7y6hn0aqy352euf40x77qddq3dc")
                ;; bech32m (BIP350)
                (list (format nil " 1xj0phk")
                      (concatenate 'string (string (code-char #x7f)) "1g6xzxy")
                      (concatenate 'string (string (code-char #x80)) "1vctc34"))
                '("an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4"
                  "qyrz8wqd2c9m"
                  "1qyrz8wqd2c9m"
                  "y1b0jsk6g"
                  "lt1igcx5c0"
                  "in1muywd"
                  "mm1crxm3i"
                  "au1s5cgom"
                  "M1VUXWEZ"
                  "16plkw9"
                  "1p2gdwpf"
                  "abcdef1l7aum6echk45nj2s0wdvt2fg8x9yrzpqzd3ryx"
                  "test1zg69v7y60n00qy352euf40x77qcusag6"))))
    (dolist (str cases)
      (is-false (bl.crypto:bech32-decode str)
                "~S was accepted but BIP173/BIP350 reject it" str))
    (is (= 32 (length cases)) "expected 32 invalid vectors, had ~D" (length cases))))

;;;; bech32 error location (Core src/test/bech32_tests.cpp, the
;;;; bech32_testvectors_invalid and bech32m_testvectors_invalid cases).

(defparameter +bech32-invalid-vectors+
  ;; (string message locations) -- Core's CASES/ERRORS pairs, in order.
  '((" 1nwldj5" "Invalid character or mixed case" (0))
    (#.(format nil "~C1axkwrx" (code-char #x7f)) "Invalid character or mixed case" (0))
    (#.(format nil "~C1eym55h" (code-char #x80)) "Invalid character or mixed case" (0))
    ("an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx"
     "Bech32 string too long" (90))
    ("pzry9x0s0muk" "Missing separator" ())
    ("1pzry9x0s0muk" "Invalid separator position" (0))
    ("x1b4n0q5v" "Invalid Base 32 character" (2))
    ("li1dgmt3" "Invalid separator position" (2))
    (#.(format nil "de1lg7wt~C" (code-char #xff)) "Invalid character or mixed case" (8))
    ;; The checksum is computed over the uppercase form, so the whole string is
    ;; wrong rather than a few characters of it.
    ("A1G7SGD8" "Invalid checksum" ())
    ("10a06t8" "Invalid separator position" (0))
    ("1qzzfhee" "Invalid separator position" (0))
    ("a12UEL5L" "Invalid character or mixed case" (3 4 5 7))
    ("A12uEL5L" "Invalid character or mixed case" (3))
    ("abcdef1qpzrz9x8gf2tvdw0s3jn54khce6mua7lmqqqxw" "Invalid Bech32 checksum" (11))
    ("test1zg69w7y6hn0aqy352euf40x77qddq3dc" "Invalid Bech32 checksum" (9 16)))
  "Core bech32_tests.cpp bech32_testvectors_invalid (:57-95).")

(defparameter +bech32m-invalid-vectors+
  '((" 1xj0phk" "Invalid character or mixed case" (0))
    (#.(format nil "~C1g6xzxy" (code-char #x7f)) "Invalid character or mixed case" (0))
    (#.(format nil "~C1vctc34" (code-char #x80)) "Invalid character or mixed case" (0))
    ("an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4"
     "Bech32 string too long" (90))
    ("qyrz8wqd2c9m" "Missing separator" ())
    ("1qyrz8wqd2c9m" "Invalid separator position" (0))
    ("y1b0jsk6g" "Invalid Base 32 character" (2))
    ("lt1igcx5c0" "Invalid Base 32 character" (3))
    ("in1muywd" "Invalid separator position" (2))
    ("mm1crxm3i" "Invalid Base 32 character" (8))
    ("au1s5cgom" "Invalid Base 32 character" (7))
    ("M1VUXWEZ" "Invalid checksum" ())
    ("16plkw9" "Invalid separator position" (0))
    ("1p2gdwpf" "Invalid separator position" (0))
    ("abcdef1l7aum6echk45nj2s0wdvt2fg8x9yrzpqzd3ryx" "Invalid Bech32m checksum" (21))
    ("test1zg69v7y60n00qy352euf40x77qcusag6" "Invalid Bech32m checksum" (13 32)))
  "Core bech32_tests.cpp bech32m_testvectors_invalid (:107-145).")

(test bech32-locate-errors-matches-cores-vectors
  "A bech32 string whose checksum fails carries more than `no': the BCH code
locates one or two wrong characters, and Core reports those positions so a
user who mistyped an address is told WHERE (bech32::LocateErrors,
bech32.cpp:403-572). The arithmetic is in GF(1024) through log/exp tables
generated from the defining polynomial x^2+9x+23.

Core's own invalid vectors are the oracle, both encodings, message and
positions each. Note what they pin besides the happy path: the two encodings
are BOTH tried and the one with fewer located errors names the message, an
all-uppercase string is `Invalid checksum' with NO positions because the
checksum covers the case, and a string past 90 characters reports every
index past the limit."
  (dolist (vectors (list +bech32-invalid-vectors+ +bech32m-invalid-vectors+))
    (dolist (case vectors)
      (destructuring-bind (str message locations) case
        (multiple-value-bind (m l) (bl.crypto:bech32-locate-errors str)
          (is (string= message m) "~S: message ~S, expected ~S" str m message)
          (is (equal locations l) "~S: locations ~S, expected ~S" str l locations))))))

(test validateaddress-says-why-and-where-an-address-is-wrong
  "validateaddress returns DecodeDestination's own error_str, and its
error_locations when the fault is one or two bech32 characters
(key_io.cpp:84-207, rpc/output_script.cpp:77-82). We answered one sentence --
the generic encoding one -- for every rejection and an empty error_locations
always, so every one of these fourteen cases read the same.

The strings and the expected answers are rpc_invalid_address_message.py's
(:19-96), run against regtest as that test does."
  (with-network (:regtest)
    (let ((node (bl:make-node :network :regtest)))
      (flet ((check (address message &optional locations)
               (let ((r (bl.rpc:dispatch-rpc-method node "validateaddress"
                                                    (list address))))
                 (is (eq 'yason:false (cdr (assoc "isvalid" r :test #'string=)))
                     "~S was accepted" address)
                 (is (string= message (cdr (assoc "error" r :test #'string=)))
                     "~S: ~S" address (cdr (assoc "error" r :test #'string=)))
                 (is (equal locations
                            (coerce (cdr (assoc "error_locations" r :test #'string=))
                                    'list))
                     "~S: locations" address)))
             (valid (address)
               (let ((r (bl.rpc:dispatch-rpc-method node "validateaddress"
                                                    (list address))))
                 (is (eq t (cdr (assoc "isvalid" r :test #'string=)))
                     "~S was rejected: ~S" address
                     (cdr (assoc "error" r :test #'string=)))
                 (is (null (assoc "error" r :test #'string=)))
                 (is (null (assoc "error_locations" r :test #'string=))))))
        ;; Bech32 faults that are about the address, not the encoding.
        (check "bcrt1s0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav25430mtr"
               "Invalid Bech32 address program size (41 bytes)")
        (check "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx"
               "Invalid or unsupported Segwit (Bech32) or Base58 encoding.")
        (check "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqdmchcc"
               "Version 1+ witness address must use Bech32m checksum")
        (check "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7k35mrzd"
               "Version 0 witness address must use Bech32 checksum")
        (check "bcrt130xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqynjegk"
               "Invalid Bech32 address witness version")
        (check "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kqqq5k3my"
               "Invalid Bech32 v0 address program size (21 bytes), per BIP141")
        ;; And the faults that are about the string: these carry positions.
        (check "bcrt1q049edschfnwystcqnsvyfpj23mpsg3jcedq9xv049edschfnwystcqnsvyfpj23mpsg3jcedq9xv049edschfnwystcqnsvyfpj23m"
               "Bech32 string too long"
               (loop for i from 90 below 108 collect i))
        (check "bcrt1q049edschfnwystcqnsvyfpj23mpsg3jcedq9xv"
               "Invalid Bech32 checksum" '(9))
        (check "bcrt1qax9suht3qv95sw33xavx8crpxduefdrsvgsklu"
               "Invalid Bech32 checksum" '(22 43))
        (check "BCRT1QPLMTZKC2XHARPPZDLNPAQL78RSHJ68U32RAH7R"
               "Invalid Bech32 checksum" '(38))
        (check "bcrtq049ldschfnwystcqnsvyfpj23mpsg3jcedq9xv" "Missing separator")
        (check "bcrt1q04oldschfnwystcqnsvyfpj23mpsg3jcedq9xv"
               "Invalid Base 32 character" '(8))
        (check "bcrt1qdg3myrgvzw7ml8q0ejxhlkyxn7vl9r56yzkfgvzclrf4hkpx9yfqhpsuks"
               "Invalid Bech32 checksum" '(19 30))
        (check "bcrt1ptmp74ayg7p24uslctssvjm06q5phz4yrxucgnv"
               "Invalid Bech32 checksum" '(5))
        ;; Base58, whose three faults Core also tells apart.
        (check "17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYhem"
               "Invalid or unsupported Base58-encoded address.")
        (check "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJJfn"
               "Invalid checksum or length of Base58 address (P2PKH or P2SH)")
        (check "2VKf7XKMrp4bVNVmuRbyCewkP8FhGLP2E54LHDPakr9Sq5mtU2"
               "Invalid checksum or length of Base58 address (P2PKH or P2SH)")
        (check "asfah14i8fajz0123f"
               "Invalid or unsupported Segwit (Bech32) or Base58 encoding.")
        (check "1q049ldschfnwystcqnsvyfpj23mpsg3jcedq9xv"
               "Invalid or unsupported Segwit (Bech32) or Base58 encoding.")
        ;; The valid ones stay valid, and carry neither field.
        (valid "bcrt1qtmp74ayg7p24uslctssvjm06q5phz4yrxucgnv")
        (valid "bcrt1p424qxxyd0r")
        (valid "BCRT1QPLMTZKC2XHARPPZDLNPAQL78RSHJ68U33RAH7R")
        (valid "bcrt1qdg3myrgvzw7ml9q0ejxhlkyxm7vl9r56yzkfgvzclrf4hkpx9yfqhpsuks")
        (valid "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn")))))
