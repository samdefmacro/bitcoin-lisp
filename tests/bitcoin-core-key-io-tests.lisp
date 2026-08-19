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
          (and (bitcoin-lisp.crypto:decode-address string net) t))
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
              (expected (bitcoin-lisp.crypto:hex-to-bytes hex)))
          (incf checked)
          (if (gethash "isPrivkey" meta)
              ;; WIF: secret bytes and the compression flag must both match.
              (multiple-value-bind (secret compressed)
                  (bitcoin-lisp.crypto:wif-to-private-key encoded)
                (is (equalp expected secret)
                    "WIF ~A decoded to ~A, expected ~A"
                    encoded (and secret (bitcoin-lisp.crypto:bytes-to-hex secret)) hex)
                (is (eq (and (gethash "isCompressed" meta) t) (and compressed t))
                    "WIF ~A compression flag mismatch" encoded)
                ;; Round-trip: re-encoding the decoded secret reproduces it.
                (when secret
                  (is (string= encoded
                               (bitcoin-lisp.crypto:private-key-to-wif
                                secret
                                :network (if (eq network :mainnet) :mainnet :testnet3)
                                :compressed (and compressed t)))
                      "WIF ~A did not round-trip" encoded)))
              ;; Address: the scriptPubKey it stands for must match exactly.
              (multiple-value-bind (type spk)
                  (bitcoin-lisp.crypto:decode-address encoded network)
                (declare (ignore type))
                (is (equalp expected spk)
                    "address ~A (~A) decoded to ~A, expected ~A"
                    encoded (gethash "chain" meta)
                    (and spk (bitcoin-lisp.crypto:bytes-to-hex spk)) hex))))))
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
        (is-false (bitcoin-lisp.crypto:wif-to-private-key s)
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
        (let ((bytes (bitcoin-lisp.crypto:hex-to-bytes hex)))
          (incf checked)
          (is (string= b58 (bitcoin-lisp.crypto:base58-encode bytes))
              "encoding ~S gave ~S, expected ~S"
              hex (bitcoin-lisp.crypto:base58-encode bytes) b58)
          (is (equalp bytes (bitcoin-lisp.crypto:base58-decode b58))
              "decoding ~S did not give ~S" b58 hex))))
    (is (= 21 checked) "expected Core's 21 base58 vectors, ran ~D" checked)))
