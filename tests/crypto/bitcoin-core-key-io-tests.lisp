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
