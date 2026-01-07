(in-package #:bitcoin-lisp.tests)

(in-suite :crypto-tests)

(test sha256-empty-input
  "SHA256 of empty input should match known hash."
  (let ((result (bitcoin-lisp.crypto:sha256 #())))
    (is (equalp result
                (ironclad:hex-string-to-byte-array
                 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")))))

(test sha256-hello
  "SHA256 of 'hello' should match known hash."
  (let ((result (bitcoin-lisp.crypto:sha256
                 (flexi-streams:string-to-octets "hello" :external-format :ascii))))
    (is (equalp result
                (ironclad:hex-string-to-byte-array
                 "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")))))

(test hash256-double-sha256
  "Hash256 should compute double SHA256."
  (let* ((input (flexi-streams:string-to-octets "hello" :external-format :ascii))
         (single (bitcoin-lisp.crypto:sha256 input))
         (double (bitcoin-lisp.crypto:sha256 single))
         (hash256 (bitcoin-lisp.crypto:hash256 input)))
    (is (equalp hash256 double))))

(test ripemd160-hello
  "RIPEMD160 of 'hello' should match known hash."
  (let ((result (bitcoin-lisp.crypto:ripemd160
                 (flexi-streams:string-to-octets "hello" :external-format :ascii))))
    (is (equalp result
                (ironclad:hex-string-to-byte-array
                 "108f07b8382412612c048d07d13f814118445acd")))))

(test hash160-pubkey-hash
  "Hash160 should compute RIPEMD160(SHA256(x))."
  (let* ((input (flexi-streams:string-to-octets "test" :external-format :ascii))
         (sha (bitcoin-lisp.crypto:sha256 input))
         (ripe (bitcoin-lisp.crypto:ripemd160 sha))
         (hash160 (bitcoin-lisp.crypto:hash160 input)))
    (is (equalp hash160 ripe))))
