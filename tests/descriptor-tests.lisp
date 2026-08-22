(in-package #:bitcoin-lisp.tests)

;;; Descriptor engine v2 tests — vectors ported from Bitcoin Core
;;; src/test/descriptor_tests.cpp (descriptor_test) and
;;; test/functional/rpc_deriveaddresses.py. Each Check(prv, pub, ...) in Core
;;; becomes a %check-desc here: both the private and the public form must
;;; parse, print the same canonical public string, and expand to Core's
;;; expected scriptPubKeys; hardened vectors must fail to expand from the
;;; public-only form. CheckUnparsable becomes %check-unparsable with Core's
;;; exact error message.

(def-suite descriptor-tests
  :description "Output descriptor engine (Core descriptor.cpp vectors)"
  :in :bitcoin-lisp-tests)

(in-suite descriptor-tests)

(defun %desc-parse (s &optional (net :mainnet))
  (bitcoin-lisp.rpc::parse-descriptor s net))

(defun %desc-pub (s &optional (net :mainnet))
  (bitcoin-lisp.rpc::out-desc-string (%desc-parse s net)))

(defun %desc-scripts (s net pos)
  (mapcar #'bitcoin-lisp.crypto:bytes-to-hex
          (bitcoin-lisp.rpc::out-desc-expand (%desc-parse s net) pos)))

(defun %check-desc (prv pub scripts &key (net :mainnet) range hardened)
  "Port of Core's Check(): PRV and PUB must both parse and canonicalize to
PUB (checksum ignored); SCRIPTS is a list of per-index script-hex lists.
RANGE = expected isrange; HARDENED = expansion needs private keys, so the
PUB form must fail to expand."
  (let ((prv-desc (%desc-parse prv net))
        (pub-desc (%desc-parse pub net)))
    (is (string= pub (bitcoin-lisp.rpc::out-desc-string prv-desc))
        "private form ~A canonicalizes to ~A, wanted ~A"
        prv (bitcoin-lisp.rpc::out-desc-string prv-desc) pub)
    (is (string= pub (bitcoin-lisp.rpc::out-desc-string pub-desc)))
    (is (eq (and range t) (and (bitcoin-lisp.rpc::out-desc-ranged-p prv-desc) t)))
    (is (eq t (bitcoin-lisp.rpc::out-desc-solvable-p prv-desc)))
    (when (string/= prv pub)
      (is (eq t (bitcoin-lisp.rpc::out-desc-has-privkeys-p prv-desc)))
      (is (null (bitcoin-lisp.rpc::out-desc-has-privkeys-p pub-desc))))
    (loop for expected in scripts
          for i from 0
          do (is (equal expected (%desc-scripts prv net i))
                 "~A at index ~D expands to ~S, wanted ~S"
                 prv i (%desc-scripts prv net i) expected)
             (if hardened
                 (signals bitcoin-lisp.rpc::descriptor-derivation-error
                   (bitcoin-lisp.rpc::out-desc-expand pub-desc i))
                 (is (equal expected (%desc-scripts pub net i)))))))

(defun %check-unparsable (prv pub message &key (net :mainnet))
  "Port of Core's CheckUnparsable(): both forms must fail to parse, and the
error of the LAST form parsed (the public one, like Core's `error` variable)
must be exactly MESSAGE."
  (let ((forms (remove "" (list prv pub) :test #'string=)))
    (loop for s in forms
          for last-p = (eq s (car (last forms)))
          do (handler-case
                 (progn (%desc-parse s net)
                        (fail "~A parsed but should have failed with: ~A" s message))
               (bitcoin-lisp.rpc::rpc-error (e)
                 (when last-p
                   (is (string= message (bitcoin-lisp.rpc::rpc-error-message e))
                       "~A failed with ~S, wanted ~S"
                       s (bitcoin-lisp.rpc::rpc-error-message e) message)))))))

;;; --- descriptor_tests.cpp: single keys ---

(test desc-core-single-key-compressed
  "Basic single-key compressed constructions (WIF + hex forms)."
  (%check-desc "combo(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)"
               "combo(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)"
               '(("2103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bdac"
                  "76a9149a1c78a507689f6f54b847ad1cef1e614ee23f1e88ac"
                  "00149a1c78a507689f6f54b847ad1cef1e614ee23f1e"
                  "a91484ab21b1b2fd065d4504ff693d832434b6108d7b87")))
  (%check-desc "pk(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)"
               "pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)"
               '(("2103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bdac")))
  (%check-desc "pkh([deadbeef/1/2'/3/4']L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)"
               "pkh([deadbeef/1/2'/3/4']03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)"
               '(("76a9149a1c78a507689f6f54b847ad1cef1e614ee23f1e88ac")))
  (%check-desc "wpkh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)"
               "wpkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)"
               '(("00149a1c78a507689f6f54b847ad1cef1e614ee23f1e")))
  (%check-desc "sh(wpkh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1))"
               "sh(wpkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))"
               '(("a91484ab21b1b2fd065d4504ff693d832434b6108d7b87")))
  (%check-desc "tr(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)"
               "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)"
               '(("512077aab6e066f8a7419c5ab714c12c67d25007ed55a43cadcacb4d7a970a093f11")))
  (%check-unparsable "sh(wpkh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY2))"
                     "sh(wpkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5))"
                     "wpkh(): Pubkey '03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5' is invalid")
  (%check-unparsable "pkh(deadbeef/1/2'/3/4']L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)"
                     "pkh(deadbeef/1/2h/3/4h]03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)"
                     "pkh(): Key origin start '[ character expected but not found, got 'd' instead")
  (%check-unparsable "pkh([deadbeef]/1/2'/3/4']L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)"
                     "pkh([deadbeef]/1/2'/3/4']03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)"
                     "pkh(): Multiple ']' characters found for a single pubkey"))

(test desc-core-single-key-uncompressed
  "Uncompressed keys: allowed at top/sh, rejected inside witness contexts."
  (%check-desc "combo(5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss)"
               "combo(04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)"
               '(("4104a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235ac"
                  "76a914b5bd079c4d57cc7fc28ecf8213a6b791625b818388ac")))
  (%check-desc "pk(5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss)"
               "pk(04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)"
               '(("4104a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235ac")))
  (%check-desc "pkh(5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss)"
               "pkh(04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)"
               '(("76a914b5bd079c4d57cc7fc28ecf8213a6b791625b818388ac")))
  (%check-unparsable "wpkh(5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss)"
                     "wpkh(04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)"
                     "wpkh(): Uncompressed keys are not allowed")
  (%check-unparsable "wsh(pk(5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss))"
                     "wsh(pk(04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235))"
                     "pk(): Uncompressed keys are not allowed")
  (%check-unparsable "sh(wpkh(5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss))"
                     "sh(wpkh(04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235))"
                     "wpkh(): Uncompressed keys are not allowed"))

(test desc-core-hybrid-keys
  "Hybrid public keys (0x06/0x07) are rejected everywhere."
  (%check-unparsable ""
                     "combo(07a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)"
                     "combo(): Hybrid public keys are not allowed")
  (%check-unparsable ""
                     "pk(0623542d61708e3fc48ba78fbe8fcc983ba94a520bc33f82b8e45e51dbc47af2726bcf181925eee1bdd868b109314f3ea92a6fc23d6b66057d3acfba04d6b08b58)"
                     "pk(): Hybrid public keys are not allowed")
  (%check-unparsable ""
                     "pkh(07a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)"
                     "pkh(): Hybrid public keys are not allowed"))

(test desc-core-unconventional-nesting
  "pk/pkh nested in sh/wsh/sh(wsh(...)) — Core's unconventional constructions."
  (%check-desc "sh(pk(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1))"
               "sh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))"
               '(("a9141857af51a5e516552b3086430fd8ce55f7c1a52487")))
  (%check-desc "sh(pkh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1))"
               "sh(pkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))"
               '(("a9141a31ad23bf49c247dd531a623c2ef57da3c400c587")))
  (%check-desc "wsh(pk(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1))"
               "wsh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))"
               '(("00202e271faa2325c199d25d22e1ead982e45b64eeb4f31e73dbdf41bd4b5fec23fa")))
  (%check-desc "wsh(pkh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1))"
               "wsh(pkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))"
               '(("0020338e023079b91c58571b20e602d7805fb808c22473cbc391a41b1bd3a192e75b")))
  (%check-desc "sh(wsh(pk(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)))"
               "sh(wsh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)))"
               '(("a91472d0c5a3bfad8c3e7bd5303a72b94240e80b6f1787")))
  (%check-desc "sh(wsh(pkh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)))"
               "sh(wsh(pkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)))"
               '(("a914b61b92e2ca21bac1e72a3ab859a742982bea960a87"))))

;;; --- descriptor_tests.cpp: BIP32 derivations ---

(test desc-core-bip32-basic
  "xpub/xprv keys with origins, paths, and hardened steps."
  (%check-desc "combo([01234567]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc)"
               "combo([01234567]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL)"
               '(("2102d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0ac"
                  "76a91431a507b815593dfc51ffc7245ae7e5aee304246e88ac"
                  "001431a507b815593dfc51ffc7245ae7e5aee304246e"
                  "a9142aafb926eb247cb18240a7f4c07983ad1f37922687")))
  (%check-desc "pk(xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0)"
               "pk(xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0)"
               '(("210379e45b3cf75f9c5f9befd8e9506fb962f6a9d185ac87001ec44a8d3df8d4a9e3ac")))
  (%check-desc "pkh(xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483647'/0)"
               "pkh(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/2147483647'/0)"
               '(("76a914ebdc90806a9c4356c1c88e42216611e1cb4c1c1788ac"))
               :hardened t)
  (%check-desc "pkh([01234567/10/20]xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483647'/0)"
               "pkh([01234567/10/20]xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/2147483647'/0)"
               '(("76a914ebdc90806a9c4356c1c88e42216611e1cb4c1c1788ac"))
               :hardened t))

(test desc-core-bip32-ranged
  "Ranged descriptors: /* and /*h terminals expand per index."
  (%check-desc "wpkh([ffffffff/13']xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt/1/2/*)"
               "wpkh([ffffffff/13']xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/1/2/*)"
               '(("0014326b2249e3a25d5dc60935f044ee835d090ba859")
                 ("0014af0bd98abc2f2cae66e36896a39ffe2d32984fb7")
                 ("00141fa798efd1cbf95cebf912c031b8a4a6e9fb9f27"))
               :range t)
  (%check-desc "sh(wpkh(xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi/10/20/30/40/*'))"
               "sh(wpkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/10/20/30/40/*'))"
               '(("a9149a4d9901d6af519b2a23d4a2f51650fcba87ce7b87")
                 ("a914bed59fc0024fae941d6e20a3b44a109ae740129287")
                 ("a9148483aa1116eb9c05c482a72bada4b1db24af654387"))
               :range t :hardened t)
  (%check-desc "combo(xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334/*)"
               "combo(xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV/*)"
               '(("2102df12b7035bdac8e3bab862a3a83d06ea6b17b6753d52edecba9be46f5d09e076ac"
                  "76a914f90e3178ca25f2c808dc76624032d352fdbdfaf288ac"
                  "0014f90e3178ca25f2c808dc76624032d352fdbdfaf2"
                  "a91408f3ea8c68d4a7585bf9e8bda226723f70e445f087")
                 ("21032869a233c9adff9a994e4966e5b821fd5bac066da6c3112488dc52383b4a98ecac"
                  "76a914a8409d1b6dfb1ed2a3e8aa5e0ef2ff26b15b75b788ac"
                  "0014a8409d1b6dfb1ed2a3e8aa5e0ef2ff26b15b75b7"
                  "a91473e39884cb71ae4e5ac9739e9225026c99763e6687"))
               :range t))

(test desc-core-bip32-unparsable
  "Bad fingerprints and path elements."
  (%check-unparsable "combo([012345678]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc)"
                     "combo([012345678]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL)"
                     "combo(): Fingerprint is not 4 bytes (9 characters instead of 8 characters)")
  (%check-unparsable "pkh(xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483648)"
                     "pkh(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/2147483648)"
                     "pkh(): Key path value 2147483648 is out of range")
  (%check-unparsable "pkh(xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/1aa)"
                     "pkh(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1aa)"
                     "pkh(): Key path value '1aa' is not a valid uint32")
  (%check-unparsable "pkh(xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/+1)"
                     "pkh(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/+1)"
                     "pkh(): Key path value '+1' is not a valid uint32"))

(test desc-core-multipath-rejected
  "Multipath specifiers: rejected (P0 scope) with a clear error in key paths;
Core's own error where multipath is never allowed (origins)."
  (%check-unparsable "pkh(xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/<0;1>)"
                     "pkh(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/<0;1>)"
                     "pkh(): Multipath descriptors are not supported")
  (%check-unparsable "pkh([deadbeef/<0;1>]xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/0)"
                     "pkh([deadbeef/<0;1>]xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/0)"
                     "pkh(): Key path value '<0;1>' specifies multipath in a section where multipath is not allowed")
  ;; A malformed multipath (no closing '>') is an invalid uint32, like Core.
  (%check-unparsable "wpkh(xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/<0/*)"
                     "wpkh(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/<0/*)"
                     "wpkh(): Key path value '<0' is not a valid uint32")
  (%check-unparsable "wpkh(xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/0>/*)"
                     "wpkh(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/0>/*)"
                     "wpkh(): Key path value '0>' is not a valid uint32"))

;;; --- descriptor_tests.cpp: multisig ---

(test desc-core-multisig-basic
  "multi()/sortedmulti() with constant keys; BIP67 sorting at expansion time."
  (%check-desc "multi(1,L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1,5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss)"
               "multi(1,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)"
               '(("512103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd4104a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea23552ae")))
  (%check-desc "sortedmulti(1,L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1,5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss)"
               "sortedmulti(1,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)"
               '(("512103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd4104a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea23552ae")))
  ;; Same keys in the opposite order: sortedmulti yields the SAME script.
  (%check-desc "sortedmulti(1,5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss,L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)"
               "sortedmulti(1,04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)"
               '(("512103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd4104a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea23552ae")))
  (%check-desc "sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))"
               "sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))"
               '(("a91445a9a622a8b0a1269944be477640eedc447bbd8487")))
  (%check-desc "sortedmulti(2,xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc/*,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0/0/*)"
               "sortedmulti(2,xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/*,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0/0/*)"
               '(("5221025d5fc65ebb8d44a5274b53bac21ff8307fec2334a32df05553459f8b1f7fe1b62102fbd47cc8034098f0e6a94c6aeee8528abf0a2153a5d8e46d325b7284c046784652ae")
                 ("52210264fd4d1f5dea8ded94c61e9641309349b62f27fbffe807291f664e286bfbe6472103f4ece6dfccfa37b211eb3d0af4d0c61dba9ef698622dc17eecdf764beeb005a652ae")
                 ("5221022ccabda84c30bad578b13c89eb3b9544ce149787e5b538175b1d1ba259cbb83321024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c52ae"))
               :range t)
  (%check-desc "wsh(multi(2,xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483647'/0,xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt/1/2/*,xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi/10/20/30/40/*'))"
               "wsh(multi(2,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/2147483647'/0,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/1/2/*,xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/10/20/30/40/*'))"
               '(("0020b92623201f3bb7c3771d45b2ad1d0351ea8fbf8cfe0a0e570264e1075fa1948f")
                 ("002036a08bbe4923af41cf4316817c93b8d37e2f635dd25cfff06bd50df6ae7ea203")
                 ("0020a96e7ab4607ca6b261bfe3245ffda9c746b28d3f59e83d34820ec0e2b36c139c"))
               :range t :hardened t)
  ;; Mixed xpub and const pubkeys
  (%check-desc "wsh(multi(1,xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334/0,L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1))"
               "wsh(multi(1,xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV/0,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))"
               '(("0020cb155486048b23a6da976d4c6fe071a2dbc8a7b57aaf225b8955f2e2a27b5f00")))
  ;; Mixed ranged xpub and const pubkey in BARE multisig
  (%check-desc "multi(1,xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334/*,L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)"
               "multi(1,xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV/*,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)"
               '(("512102df12b7035bdac8e3bab862a3a83d06ea6b17b6753d52edecba9be46f5d09e0762103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd52ae")
                 ("5121032869a233c9adff9a994e4966e5b821fd5bac066da6c3112488dc52383b4a98ec2103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd52ae")
                 ("5121035d30b6c66dc1e036c45369da8287518cf7e0d6ed1e2b905171c605708f14ca032103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd52ae"))
               :range t))

(test desc-core-multisig-20-keys
  "20 keys allowed in P2WSH multisig (also wrapped in sh()); >15 rejected in
plain sh(); >3 rejected bare; >20 rejected everywhere."
  (%check-desc "sh(wsh(multi(16,KzoAz5CanayRKex3fSLQ2BwJpN7U52gZvxMyk78nDMHuqrUxuSJy,KwGNz6YCCQtYvFzMtrC6D3tKTKdBBboMrLTsjr2NYVBwapCkn7Mr,KxogYhiNfwxuswvXV66eFyKcCpm7dZ7TqHVqujHAVUjJxyivxQ9X,L2BUNduTSyZwZjwNHynQTF14mv2uz2NRq5n5sYWTb4FkkmqgEE9f,L1okJGHGn1kFjdXHKxXjwVVtmCMR2JA5QsbKCSpSb7ReQjezKeoD,KxDCNSST75HFPaW5QKpzHtAyaCQC7p9Vo3FYfi2u4dXD1vgMiboK,L5edQjFtnkcf5UWURn6UuuoFrabgDQUHdheKCziwN42aLwS3KizU,KzF8UWFcEC7BYTq8Go1xVimMkDmyNYVmXV5PV7RuDicvAocoPB8i,L3nHUboKG2w4VSJ5jYZ5CBM97oeK6YuKvfZxrefdShECcjEYKMWZ,KyjHo36dWkYhimKmVVmQTq3gERv3pnqA4xFCpvUgbGDJad7eS8WE,KwsfyHKRUTZPQtysN7M3tZ4GXTnuov5XRgjdF2XCG8faAPmFruRF,KzCUbGhN9LJhdeFfL9zQgTJMjqxdBKEekRGZX24hXdgCNCijkkap,KzgpMBwwsDLwkaC5UrmBgCYaBD2WgZ7PBoGYXR8KT7gCA9UTN5a3,KyBXTPy4T7YG4q9tcAM3LkvfRpD1ybHMvcJ2ehaWXaSqeGUxEdkP,KzJDe9iwJRPtKP2F2AoN6zBgzS7uiuAwhWCfGdNeYJ3PC1HNJ8M8,L1xbHrxynrqLKkoYc4qtoQPx6uy5qYXR5ZDYVYBSRmCV5piU3JG9)))"
               "sh(wsh(multi(16,03669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0,0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600,0362a74e399c39ed5593852a30147f2959b56bb827dfa3e60e464b02ccf87dc5e8,0261345b53de74a4d721ef877c255429961b7e43714171ac06168d7e08c542a8b8,02da72e8b46901a65d4374fe6315538d8f368557dda3a1dcf9ea903f3afe7314c8,0318c82dd0b53fd3a932d16e0ba9e278fcc937c582d5781be626ff16e201f72286,0297ccef1ef99f9d73dec9ad37476ddb232f1238aff877af19e72ba04493361009,02e502cfd5c3f972fe9a3e2a18827820638f96b6f347e54d63deb839011fd5765d,03e687710f0e3ebe81c1037074da939d409c0025f17eb86adb9427d28f0f7ae0e9,02c04d3a5274952acdbc76987f3184b346a483d43be40874624b29e3692c1df5af,02ed06e0f418b5b43a7ec01d1d7d27290fa15f75771cb69b642a51471c29c84acd,036d46073cbb9ffee90473f3da429abc8de7f8751199da44485682a989a4bebb24,02f5d1ff7c9029a80a4e36b9a5497027ef7f3e73384a4a94fbfe7c4e9164eec8bc,02e41deffd1b7cce11cde209a781adcffdabd1b91c0ba0375857a2bfd9302419f3,02d76625f7956a7fc505ab02556c23ee72d832f1bac391bcd2d3abce5710a13d06,0399eb0a5487515802dc14544cf10b3666623762fbed2ec38a3975716e2c29c232)))"
               '(("a9147fc63e13dc25e8a95a3cee3d9a714ac3afd96f1e87")))
  (%check-desc "wsh(multi(20,KzoAz5CanayRKex3fSLQ2BwJpN7U52gZvxMyk78nDMHuqrUxuSJy,KwGNz6YCCQtYvFzMtrC6D3tKTKdBBboMrLTsjr2NYVBwapCkn7Mr,KxogYhiNfwxuswvXV66eFyKcCpm7dZ7TqHVqujHAVUjJxyivxQ9X,L2BUNduTSyZwZjwNHynQTF14mv2uz2NRq5n5sYWTb4FkkmqgEE9f,L1okJGHGn1kFjdXHKxXjwVVtmCMR2JA5QsbKCSpSb7ReQjezKeoD,KxDCNSST75HFPaW5QKpzHtAyaCQC7p9Vo3FYfi2u4dXD1vgMiboK,L5edQjFtnkcf5UWURn6UuuoFrabgDQUHdheKCziwN42aLwS3KizU,KzF8UWFcEC7BYTq8Go1xVimMkDmyNYVmXV5PV7RuDicvAocoPB8i,L3nHUboKG2w4VSJ5jYZ5CBM97oeK6YuKvfZxrefdShECcjEYKMWZ,KyjHo36dWkYhimKmVVmQTq3gERv3pnqA4xFCpvUgbGDJad7eS8WE,KwsfyHKRUTZPQtysN7M3tZ4GXTnuov5XRgjdF2XCG8faAPmFruRF,KzCUbGhN9LJhdeFfL9zQgTJMjqxdBKEekRGZX24hXdgCNCijkkap,KzgpMBwwsDLwkaC5UrmBgCYaBD2WgZ7PBoGYXR8KT7gCA9UTN5a3,KyBXTPy4T7YG4q9tcAM3LkvfRpD1ybHMvcJ2ehaWXaSqeGUxEdkP,KzJDe9iwJRPtKP2F2AoN6zBgzS7uiuAwhWCfGdNeYJ3PC1HNJ8M8,L1xbHrxynrqLKkoYc4qtoQPx6uy5qYXR5ZDYVYBSRmCV5piU3JG9,KzRedjSwMggebB3VufhbzpYJnvHfHe9kPJSjCU5QpJdAW3NSZxYS,Kyjtp5858xL7JfeV4PNRCKy2t6XvgqNNepArGY9F9F1SSPqNEMs3,L2D4RLHPiHBidkHS8ftx11jJk1hGFELvxh8LoxNQheaGT58dKenW,KyLPZdwY4td98bKkXqEXTEBX3vwEYTQo1yyLjX2jKXA63GBpmSjv))"
               "wsh(multi(20,03669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0,0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600,0362a74e399c39ed5593852a30147f2959b56bb827dfa3e60e464b02ccf87dc5e8,0261345b53de74a4d721ef877c255429961b7e43714171ac06168d7e08c542a8b8,02da72e8b46901a65d4374fe6315538d8f368557dda3a1dcf9ea903f3afe7314c8,0318c82dd0b53fd3a932d16e0ba9e278fcc937c582d5781be626ff16e201f72286,0297ccef1ef99f9d73dec9ad37476ddb232f1238aff877af19e72ba04493361009,02e502cfd5c3f972fe9a3e2a18827820638f96b6f347e54d63deb839011fd5765d,03e687710f0e3ebe81c1037074da939d409c0025f17eb86adb9427d28f0f7ae0e9,02c04d3a5274952acdbc76987f3184b346a483d43be40874624b29e3692c1df5af,02ed06e0f418b5b43a7ec01d1d7d27290fa15f75771cb69b642a51471c29c84acd,036d46073cbb9ffee90473f3da429abc8de7f8751199da44485682a989a4bebb24,02f5d1ff7c9029a80a4e36b9a5497027ef7f3e73384a4a94fbfe7c4e9164eec8bc,02e41deffd1b7cce11cde209a781adcffdabd1b91c0ba0375857a2bfd9302419f3,02d76625f7956a7fc505ab02556c23ee72d832f1bac391bcd2d3abce5710a13d06,0399eb0a5487515802dc14544cf10b3666623762fbed2ec38a3975716e2c29c232,02bc2feaa536991d269aae46abb8f3772a5b3ad592314945e51543e7da84c4af6e,0318bf32e5217c1eb771a6d5ce1cd39395dff7ff665704f175c9a5451d95a2f2ca,02c681a6243f16208c2004bb81f5a8a67edfdd3e3711534eadeec3dcf0b010c759,0249fdd6b69768b8d84b4893f8ff84b36835c50183de20fcae8f366a45290d01fd))"
               '(("0020376bd8344b8b6ebe504ff85ef743eaa1aa9272178223bcb6887e9378efb341ac")))
  ;; 16 compressed keys make a 547-byte redeemScript: too large for P2SH.
  (%check-unparsable ""
                     "sh(multi(16,03669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0,0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600,0362a74e399c39ed5593852a30147f2959b56bb827dfa3e60e464b02ccf87dc5e8,0261345b53de74a4d721ef877c255429961b7e43714171ac06168d7e08c542a8b8,02da72e8b46901a65d4374fe6315538d8f368557dda3a1dcf9ea903f3afe7314c8,0318c82dd0b53fd3a932d16e0ba9e278fcc937c582d5781be626ff16e201f72286,0297ccef1ef99f9d73dec9ad37476ddb232f1238aff877af19e72ba04493361009,02e502cfd5c3f972fe9a3e2a18827820638f96b6f347e54d63deb839011fd5765d,03e687710f0e3ebe81c1037074da939d409c0025f17eb86adb9427d28f0f7ae0e9,02c04d3a5274952acdbc76987f3184b346a483d43be40874624b29e3692c1df5af,02ed06e0f418b5b43a7ec01d1d7d27290fa15f75771cb69b642a51471c29c84acd,036d46073cbb9ffee90473f3da429abc8de7f8751199da44485682a989a4bebb24,02f5d1ff7c9029a80a4e36b9a5497027ef7f3e73384a4a94fbfe7c4e9164eec8bc,02e41deffd1b7cce11cde209a781adcffdabd1b91c0ba0375857a2bfd9302419f3,02d76625f7956a7fc505ab02556c23ee72d832f1bac391bcd2d3abce5710a13d06,0399eb0a5487515802dc14544cf10b3666623762fbed2ec38a3975716e2c29c232))"
                     "P2SH script is too large, 547 bytes is larger than 520 bytes"))

(test desc-core-multisig-unparsable
  "Bad multisig thresholds, key counts, and key-origin errors."
  (%check-unparsable "multi(a,L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1,5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss)"
                     "multi(a,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)"
                     "Multi threshold 'a' is not valid")
  (%check-unparsable "multi(+1,L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1,5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss)"
                     "multi(+1,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)"
                     "Multi threshold '+1' is not valid")
  (%check-unparsable "multi(0,L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1,5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss)"
                     "multi(0,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)"
                     "Multisig threshold cannot be 0, must be at least 1")
  (%check-unparsable "multi(3,L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1,5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss)"
                     "multi(3,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)"
                     "Multisig threshold cannot be larger than the number of keys; threshold is 3 but only 2 keys specified")
  (%check-unparsable "" "multi(0)()" "Multi: expected ',', got ')'")
  (%check-unparsable "" "multi(123)"
                     "Cannot have 0 keys in multisig; must have between 1 and 20 keys, inclusive")
  (%check-unparsable "multi(3,KzoAz5CanayRKex3fSLQ2BwJpN7U52gZvxMyk78nDMHuqrUxuSJy,KwGNz6YCCQtYvFzMtrC6D3tKTKdBBboMrLTsjr2NYVBwapCkn7Mr,KxogYhiNfwxuswvXV66eFyKcCpm7dZ7TqHVqujHAVUjJxyivxQ9X,L2BUNduTSyZwZjwNHynQTF14mv2uz2NRq5n5sYWTb4FkkmqgEE9f)"
                     "multi(3,03669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0,0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600,0362a74e399c39ed5593852a30147f2959b56bb827dfa3e60e464b02ccf87dc5e8,0261345b53de74a4d721ef877c255429961b7e43714171ac06168d7e08c542a8b8)"
                     "Cannot have 4 pubkeys in bare multisig; only at most 3 pubkeys")
  ;; Key-origin errors inside multi get the "Multi: " prefix
  (%check-unparsable ""
                     "wsh(multi(2,[aaaaaaaa][aaaaaaaa]xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/2147483647h/0,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/1/2/*))"
                     "Multi: Multiple ']' characters found for a single pubkey")
  (%check-unparsable ""
                     "wsh(multi(2,[aaagaaaa]xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/2147483647h/0,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/1/2/*))"
                     "Multi: Fingerprint 'aaagaaaa' is not hex")
  (%check-unparsable ""
                     "wsh(multi(2,[aaaaaaaa],xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/1/2/*))"
                     "Multi: No key provided")
  (%check-unparsable ""
                     "wsh(multi(2,[aaaaaaa]xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/2147483647h/0))"
                     "Multi: Fingerprint is not 4 bytes (7 characters instead of 8 characters)")
  (%check-unparsable ""
                     "wsh(multi(2,[aaaaaaaaa]xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/2147483647h/0))"
                     "Multi: Fingerprint is not 4 bytes (9 characters instead of 8 characters)")
  ;; 21 keys is over the multisig maximum even in P2WSH
  (let ((keys (loop repeat 21
                    collect "03669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0")))
    (%check-unparsable ""
                       (format nil "wsh(multi(1~{,~A~}))" keys)
                       "Cannot have 21 keys in multisig; must have between 1 and 20 keys, inclusive"))
  (%check-unparsable "" "multi_a(1,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)"
                     "Can only have multi_a/sortedmulti_a inside tr()"))

;;; --- descriptor_tests.cpp: nesting rules ---

(test desc-core-invalid-nesting
  "Invalid nesting of script structures — Core's exact errors."
  (%check-unparsable "sh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)"
                     "sh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)"
                     "A function is needed within P2SH")
  (%check-unparsable "sh(combo(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1))"
                     "sh(combo(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))"
                     "Can only have combo() at top level")
  (%check-unparsable "wsh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)"
                     "wsh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)"
                     "A function is needed within P2WSH")
  (%check-unparsable "wsh(wpkh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1))"
                     "wsh(wpkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))"
                     "Can only have wpkh() at top level or inside sh()")
  (%check-unparsable "wsh(sh(pk(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)))"
                     "wsh(sh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)))"
                     "Can only have sh() at top level")
  (%check-unparsable "sh(sh(pk(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)))"
                     "sh(sh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)))"
                     "Can only have sh() at top level")
  (%check-unparsable "wsh(wsh(pk(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)))"
                     "wsh(wsh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)))"
                     "Can only have wsh() at top level or inside sh()"))

(test desc-core-whitespace
  "Whitespace inside key expressions is rejected with Core's message."
  (%check-unparsable ""
                     "multi(1, L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1,5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss)"
                     "Multi: Key ' L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1' is invalid due to whitespace")
  (%check-unparsable ""
                     "pk(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1 )"
                     "pk(): Key 'L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1 ' is invalid due to whitespace")
  (%check-unparsable ""
                     "pk( L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1 )"
                     "pk(): Key ' L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1 ' is invalid due to whitespace"))

;;; --- descriptor_tests.cpp: checksums ---

(test desc-core-checksums
  "Checksum validation on the sh(multi(...)) vector — Core's exact messages."
  (let ((prv "sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))")
        (pub "sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))"))
    ;; Core's known checksums for both forms
    (is (string= "ggrsrxfy" (bitcoin-lisp.rpc::descriptor-checksum prv)))
    (is (string= "tjg09x5t" (bitcoin-lisp.rpc::descriptor-checksum pub)))
    ;; Valid with correct checksum, with or without
    (finishes (%desc-parse (concatenate 'string prv "#ggrsrxfy")))
    (finishes (%desc-parse (concatenate 'string pub "#tjg09x5t")))
    (finishes (%desc-parse prv))
    (%check-unparsable (concatenate 'string prv "#")
                       (concatenate 'string pub "#")
                       "Expected 8 character checksum, not 0 characters")
    (%check-unparsable (concatenate 'string prv "#ggrsrxfyq")
                       (concatenate 'string pub "#tjg09x5tq")
                       "Expected 8 character checksum, not 9 characters")
    (%check-unparsable (concatenate 'string prv "#ggrsrxf")
                       (concatenate 'string pub "#tjg09x5")
                       "Expected 8 character checksum, not 7 characters")
    ;; Error in payload (2 -> 3) detected
    (handler-case
        (progn (%desc-parse (concatenate 'string
                                         "sh(multi(3"
                                         (subseq prv 10)
                                         "#ggrsrxfy"))
               (fail "bad payload accepted"))
      (bitcoin-lisp.rpc::rpc-error (e)
        (is (alexandria:starts-with-subseq "Provided checksum 'ggrsrxfy' does not match computed checksum"
                                           (bitcoin-lisp.rpc::rpc-error-message e)))))
    ;; Error in checksum detected
    (%check-unparsable (concatenate 'string prv "#ggssrxfy") ""
                       "Provided checksum 'ggssrxfy' does not match computed checksum 'ggrsrxfy'")
    (%check-unparsable (concatenate 'string prv "##ggssrxfy")
                       (concatenate 'string pub "##tjq09x4t")
                       "Multiple '#' symbols")))

;;; --- descriptor_tests.cpp: addr/raw/tr/rawtr ---

(test desc-core-addr-raw
  (%check-unparsable "" "addr(asdf)" "Address is not valid")
  (%check-unparsable "" "raw(asdf)" "Raw script is not hex")
  (%check-unparsable "" (format nil "raw(~C)#00000000" (code-char 220)) ; Ü
                     "Invalid characters in payload"))

(test desc-core-rawtr
  "rawtr(): key IS the output key; ranged hardened xprv vector with Core's
own checksums on both forms."
  (%check-desc "rawtr(xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt/86'/1'/0'/1/*)#a5gn3t7k"
               "rawtr(xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/86'/1'/0'/1/*)"
               '(("51205172af752f057d543ce8e4a6f8dcf15548ec6be44041bfa93b72e191cfc8c1ee")
                 ("51201b66f20b86f700c945ecb9ad9b0ad1662b73084e2bfea48bee02126350b8a5b1")
                 ("512063e70f66d815218abcc2306aa930aaca07c5cde73b75127eb27b5e8c16b58a25"))
               :range t :hardened t)
  ;; The pub form's checksum from Core: #4ur3xhft
  (finishes (%desc-parse "rawtr(xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/86'/1'/0'/1/*)#4ur3xhft"))
  (%check-desc "rawtr(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)"
               "rawtr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)"
               '(("5120a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd")))
  (%check-unparsable ""
                     "rawtr(xpub68FQ9imX6mCWacw6eNRjaa8q8ynnHmUd5i7MVR51ZMPP5JycyfVHSLQVFPHMYiTybWJnSBL2tCBpy6aJTR2DYrshWYfwAxs8SosGXd66d8/*, xpub69Mvq3QMipdvnd9hAyeTnT5jrkcBuLErV212nsGf3qr7JPWysc9HnNhCsazdzj1etSx28hPSE8D7DnceFbNdw4Kg8SyRfjE2HFLv1P8TSGc/*)"
                     "rawtr(): only one key expected."))

(test desc-tr-key-path-only
  "tr() stays key-path-only at P0: script trees are rejected."
  (%check-unparsable ""
                     "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,pk(669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0))"
                     "tr(): script trees are not supported")
  ;; x-only keys only valid inside tr()/rawtr()
  (%check-unparsable ""
                     "pk(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)"
                     "pk(): Pubkey 'a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd' is invalid"))

;;; --- Network gating of keys ---

(test desc-key-network-gating
  "WIF and extended keys must match the node's network."
  ;; tpub on mainnet rejected, accepted on testnet
  (%check-unparsable ""
                     "pkh(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1/1/0)"
                     "pkh(): key 'tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B' is not valid")
  (finishes (%desc-parse "pkh(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1/1/0)" :testnet3))
  ;; xpub on testnet rejected
  (%check-unparsable ""
                     "pk(xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0)"
                     "pk(): key 'xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y' is not valid"
                     :net :testnet3)
  ;; mainnet WIF on testnet rejected
  (%check-unparsable ""
                     "pk(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)"
                     "pk(): key 'L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1' is not valid"
                     :net :testnet3))

;;; --- Expansion cache ---

(test desc-expansion-cache
  "Repeat expansion of a ranged descriptor at the same index is served from
the cache; different descriptors/indices don't collide."
  (let* ((s "wpkh([ffffffff/13']xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/1/2/*)")
         (desc (%desc-parse s)))
    (let ((first-time (bitcoin-lisp.rpc::out-desc-expand desc 7)))
      ;; second expansion returns the identical (cached) list
      (is (eq first-time (bitcoin-lisp.rpc::out-desc-expand desc 7)))
      ;; a fresh parse of the same string hits the same cache entry
      (is (eq first-time (bitcoin-lisp.rpc::out-desc-expand (%desc-parse s) 7)))
      ;; a different index derives a different script
      (is (not (equalp (first first-time)
                       (first (bitcoin-lisp.rpc::out-desc-expand desc 8))))))))

;;; --- getdescriptorinfo (Core rpc/output_script.cpp behavior) ---

(test rpc-getdescriptorinfo-v2
  "getdescriptorinfo: canonical public descriptor + input checksum + flags."
  (let ((node (make-test-node))) ; :testnet3
    ;; Private ranged descriptor: xprv normalized to xpub in `descriptor`,
    ;; `checksum` is the checksum of the input as given.
    (let* ((prv "wpkh(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK/1/1/*)")
           (r (bitcoin-lisp.rpc::rpc-getdescriptorinfo node (list prv)))
           (reported (cdr (assoc "descriptor" r :test #'string=))))
      (is (eq t (cdr (assoc "isrange" r :test #'string=))))
      (is (eq t (cdr (assoc "issolvable" r :test #'string=))))
      (is (eq t (cdr (assoc "hasprivatekeys" r :test #'string=))))
      (is (string= (bitcoin-lisp.rpc::descriptor-checksum prv)
                   (cdr (assoc "checksum" r :test #'string=))))
      ;; The reported descriptor is public (tpub..., no tprv) and checksummed.
      (is (search "tpub" reported))
      (is (not (search "tprv" reported)))
      (is (char= #\# (char reported (- (length reported) 9))))
      ;; and it round-trips: parsing it yields the same canonical form.
      (is (string= reported
                   (cdr (assoc "descriptor"
                               (bitcoin-lisp.rpc::rpc-getdescriptorinfo
                                node (list reported))
                               :test #'string=)))))
    ;; Unranged public descriptor: no range, no private keys.
    (let ((r (bitcoin-lisp.rpc::rpc-getdescriptorinfo
              node
              (list "pkh(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1/1/0)"))))
      (is (eq 'yason:false (cdr (assoc "isrange" r :test #'string=))))
      (is (eq t (cdr (assoc "issolvable" r :test #'string=))))
      (is (eq 'yason:false (cdr (assoc "hasprivatekeys" r :test #'string=)))))
    ;; addr()/raw() are not solvable.
    (let ((r (bitcoin-lisp.rpc::rpc-getdescriptorinfo node (list "raw(51)"))))
      (is (eq 'yason:false (cdr (assoc "issolvable" r :test #'string=)))))
    ;; Bad checksum still rejected.
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getdescriptorinfo node (list "raw(51)#deadbeef")))))

;;; --- deriveaddresses (Core test/functional/rpc_deriveaddresses.py) ---

(defun %addr-script (address network)
  "scriptPubKey bytes of ADDRESS (used to compare against Core's documented
regtest bcrt1 addresses, whose witness programs are network-independent)."
  (multiple-value-bind (type script)
      (bitcoin-lisp.crypto:decode-address address network)
    (declare (ignore type))
    script))

(defun %derived-scripts (node args)
  "deriveaddresses -> scriptPubKeys of the returned addresses."
  (mapcar (lambda (a) (%addr-script a :testnet3))
          (bitcoin-lisp.rpc::rpc-deriveaddresses node args)))

(test rpc-deriveaddresses-core-functional
  "Port of Core's rpc_deriveaddresses.py: same tprv/tpub descriptors; the
expected witness programs come from decoding the bcrt1 addresses documented
in the Core test (bech32 HRP differs between our testnet node and Core's
regtest node, the underlying scriptPubKeys must match exactly)."
  (let* ((node (make-test-node))     ; :testnet3
         (tprv "tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK")
         (descsum (lambda (body) (bitcoin-lisp.rpc::descriptor-add-checksum body))))
    (flet ((expect-error (message &rest args)
             (handler-case
                 (progn (bitcoin-lisp.rpc::rpc-deriveaddresses node args)
                        (fail "expected error ~S for ~S" message args))
               (bitcoin-lisp.rpc::rpc-error (e)
                 (is (string= message (bitcoin-lisp.rpc::rpc-error-message e))
                     "got ~S wanted ~S" (bitcoin-lisp.rpc::rpc-error-message e) message)))))
      ;; No checksum -> error
      (expect-error "Missing checksum" "a")
      ;; Single wpkh
      (let ((desc (funcall descsum (format nil "wpkh(~A/1/1/0)" tprv))))
        (is (equalp (list (%addr-script "bcrt1qjqmxmkpmxt80xz4y3746zgt0q3u3ferr34acd5" :regtest))
                   (%derived-scripts node (list desc)))))
      ;; Ranged [1,2] and single-int 2 (= [0,2])
      (let ((ranged (funcall descsum (format nil "wpkh(~A/1/1/*)" tprv))))
        (is (equalp (list (%addr-script "bcrt1qhku5rq7jz8ulufe2y6fkcpnlvpsta7rq4442dy" :regtest)
                         (%addr-script "bcrt1qpgptk2gvshyl0s9lqshsmx932l9ccsv265tvaq" :regtest))
                   (%derived-scripts node (list ranged (list 1 2)))))
        (is (equalp (list (%addr-script "bcrt1qjqmxmkpmxt80xz4y3746zgt0q3u3ferr34acd5" :regtest)
                         (%addr-script "bcrt1qhku5rq7jz8ulufe2y6fkcpnlvpsta7rq4442dy" :regtest)
                         (%addr-script "bcrt1qpgptk2gvshyl0s9lqshsmx932l9ccsv265tvaq" :regtest))
                   (%derived-scripts node (list ranged 2))))
        ;; Range errors
        (expect-error "Range must be specified for a ranged descriptor" ranged)
        (expect-error "End of range is too high" ranged 10000000000)
        (expect-error "Range is too large" ranged (list 1000000000 2000000000))
        (expect-error "Range specified as [begin,end] must not have begin after end"
                      ranged (list 2 0))
        (expect-error "Range should be greater or equal than 0" ranged (list -1 0))
        ;; Large index derives
        (is (equalp (list (%addr-script "bcrt1qtzs23vgzpreks5gtygwxf8tv5rldxvvsyfpdkg" :regtest))
                   (%derived-scripts node (list ranged (list 2147483647 2147483647))))))
      ;; Range on an unranged descriptor
      (expect-error "Range should not be specified for an un-ranged descriptor"
                    (funcall descsum (format nil "wpkh(~A/1/1/0)" tprv)) (list 0 2))
      ;; combo(): P2PK is skipped, 3 addresses remain (base58 forms are
      ;; identical between regtest and testnet, compare them literally).
      (let ((addrs (bitcoin-lisp.rpc::rpc-deriveaddresses
                    node (list (funcall descsum (format nil "combo(~A/1/1/0)" tprv))))))
        (is (= 3 (length addrs)))
        (is (string= "mtfUoUax9L4tzXARpw1oTGxWyoogp52KhJ" (first addrs)))
        (is (equalp (%addr-script "bcrt1qjqmxmkpmxt80xz4y3746zgt0q3u3ferr34acd5" :regtest)
                    (%addr-script (second addrs) :testnet3)))
        (is (string= "2NDvEwGfpEqJWfybzpKPHF2XH3jwoQV3D7x" (third addrs))))
      ;; pk() has no address
      (expect-error "Descriptor does not have a corresponding address"
                    (funcall descsum (format nil "pk(~A)" tprv)))
      ;; Hardened derivation without private key
      (expect-error "Cannot derive script without private keys"
                    (funcall descsum "wpkh(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1'/1/0)"))
      ;; Bare multisig has no address
      (expect-error "Descriptor does not have a corresponding address"
                    (funcall descsum "multi(1,tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1/1/0,tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1/1/1)")))))

;;; --- scantxoutset with ranged descriptors ---

(test rpc-scantxoutset-ranged-descriptors
  "scantxoutset expands ranged descriptors over their range (default
[0,1000]); an explicit range object narrows/widens the window."
  (let* ((node (make-test-node))
         (utxo (bitcoin-lisp::node-utxo-set node))
         (desc "wpkh(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1/1/*)")
         (parsed (bitcoin-lisp.rpc::parse-descriptor desc :testnet3))
         (script-at-5 (first (bitcoin-lisp.rpc::out-desc-expand parsed 5)))
         (script-at-1500 (first (bitcoin-lisp.rpc::out-desc-expand parsed 1500)))
         (txid-a (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
         (txid-b (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2)))
    (bitcoin-lisp.storage:add-utxo utxo txid-a 0 100000000 script-at-5 0)
    (bitcoin-lisp.storage:add-utxo utxo txid-b 0 200000000 script-at-1500 0)
    ;; Default range [0,1000]: finds index 5, not index 1500.
    (let ((r (bitcoin-lisp.rpc::rpc-scantxoutset node (list "start" (list desc)))))
      (is (= 1 (length (cdr (assoc "unspents" r :test #'string=))))))
    ;; Explicit range through a scan object reaches index 1500.
    (let ((obj (make-hash-table :test 'equal)))
      (setf (gethash "desc" obj) desc
            (gethash "range" obj) (list 1400 1600))
      (let ((r (bitcoin-lisp.rpc::rpc-scantxoutset node (list "start" (list obj)))))
        (let ((unspents (cdr (assoc "unspents" r :test #'string=))))
          (is (= 1 (length unspents)))
          (is (string= (bitcoin-lisp.crypto:bytes-to-hex script-at-1500)
                       (cdr (assoc "scriptPubKey" (first unspents) :test #'string=)))))))
    ;; Narrow range that misses both.
    (let ((obj (make-hash-table :test 'equal)))
      (setf (gethash "desc" obj) desc
            (gethash "range" obj) (list 6 10))
      (let ((r (bitcoin-lisp.rpc::rpc-scantxoutset node (list "start" (list obj)))))
        (is (= 0 (length (cdr (assoc "unspents" r :test #'string=)))))))
    ;; Range validation errors propagate.
    (let ((obj (make-hash-table :test 'equal)))
      (setf (gethash "desc" obj) desc
            (gethash "range" obj) (list 0 2000000))
      (signals bitcoin-lisp.rpc::rpc-error
        (bitcoin-lisp.rpc::rpc-scantxoutset node (list "start" (list obj)))))))

;;; --- generatetodescriptor-style consumers reject ranged descriptors ---

(test desc-ranged-rejected-where-core-rejects
  "parse-output-descriptor (generatetodescriptor / generateblock path) keeps
Core's 'Ranged descriptor not accepted' behavior."
  (handler-case
      (progn (bitcoin-lisp.rpc::parse-output-descriptor
              "wpkh(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1/*)"
              :testnet3)
             (fail "ranged descriptor accepted"))
    (bitcoin-lisp.rpc::rpc-error (e)
      (is (string= "Ranged descriptor not accepted. Maybe pass through deriveaddresses first?"
                   (bitcoin-lisp.rpc::rpc-error-message e)))))
  ;; Unranged xpub descriptors now expand fine on this path.
  (let ((pairs (bitcoin-lisp.rpc::parse-output-descriptor
                "wpkh(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1/1/0)"
                :testnet3)))
    (is (= 1 (length pairs)))
    (is (= 22 (length (car (first pairs)))))))

;;;; Multipath descriptors (BIP389)

(defun %mp-expand (s)
  (handler-case (bitcoin-lisp.rpc::expand-multipath-descriptor s)
    (bitcoin-lisp.rpc::rpc-error (e)
      (list :error (bitcoin-lisp.rpc::rpc-error-message e)))))

(test multipath-descriptors-expand-into-one-descriptor-each
  "`wpkh(xpub/<0;1>/*)` is ONE string meaning TWO descriptors — the receive
chain and the change chain — and it is how Sparrow, Ledger Live, BlueWallet,
BDK and modern Core exports write a wallet. A node that cannot read it cannot
import from any of them.

Core expands the string and parses each result normally (Parse returns a
vector, descriptor.cpp:1802-1851); expanding at the string level is what keeps
derivation, signing, printing and checksums working on descriptors they already
understand."
  (is (equal '("wpkh(xpub661MyMwAqRbcF/0/*)")
             (%mp-expand "wpkh(xpub661MyMwAqRbcF/0/*)"))
      "a descriptor with no multipath must come back unchanged")
  (is (equal '("wpkh([deadbeef/84h/1h/0h]xpub/0/*)"
               "wpkh([deadbeef/84h/1h/0h]xpub/1/*)")
             (%mp-expand "wpkh([deadbeef/84h/1h/0h]xpub/<0;1>/*)")))
  (is (equal '("wpkh(xpub/0/*)" "wpkh(xpub/1/*)" "wpkh(xpub/2/*)")
             (%mp-expand "wpkh(xpub/<0;1;2>/*)")))
  ;; The substituted text is the ORIGINAL spelling, so a hardened marker
  ;; survives as written rather than being re-rendered.
  (is (equal '("wpkh(xpub/0h/*)" "wpkh(xpub/1h/*)")
             (%mp-expand "wpkh(xpub/<0h;1h>/*)")))
  ;; The input checksum covered the multipath form, not the expansions, so it
  ;; is dropped; each expansion gets its own when one is needed.
  (is (equal '("wpkh(xpub/0/*)" "wpkh(xpub/1/*)")
             (%mp-expand "wpkh(xpub/<0;1>/*)#abcdefgh"))))

(test multipath-rejects-what-core-rejects
  "All three messages are Core's own (descriptor.cpp:1809-1831)."
  (is (equal '(:error "Multipath key path specifiers must have at least two items")
             (%mp-expand "wpkh(xpub/<0>/*)")))
  (is (equal '(:error "Duplicated key path value 0 in multipath specifier")
             (%mp-expand "wpkh(xpub/<0;0>/*)")))
  (is (equal '(:error "Multiple multipath key path specifiers found")
             (%mp-expand "wsh(multi(2,xpub1/<0;1>/*,xpub2/<0;1>/*))")))
  ;; A non-numeric path value is still a path-value error.
  (is (eq :error (first (%mp-expand "wpkh(xpub/<0;x>/*)")))))

(test multipath-import-makes-the-second-path-the-change-chain
  "With exactly two expansions Core sets desc_internal = (j == 1) — the second
IS the change chain, whatever the request said (backup.cpp:230-231). That is
what makes a single wallet export configure both chains in one call, and it is
the reason a multipath import cannot carry a label (:203-206)."
  (let* ((seen '())
         (wallet :fake))
    ;; Drive the multipath path directly, recording what each expansion was
    ;; imported as. %PROCESS-DESCRIPTOR-IMPORT is stubbed: the assertion is
    ;; about which descriptor/internal pairs it is CALLED with.
    (flet ((fake-import (w data ts)
             (declare (ignore w ts))
             (push (cons (gethash "desc" data) (gethash "internal" data)) seen)
             '(("success" . t))))
      (let ((original (symbol-function 'bitcoin-lisp.rpc::%process-descriptor-import)))
        (unwind-protect
             (progn
               (setf (symbol-function 'bitcoin-lisp.rpc::%process-descriptor-import)
                     #'fake-import)
               (let ((data (make-hash-table :test 'equal)))
                 (setf (gethash "desc" data) "wpkh(xpub/<0;1>/*)")
                 (let ((result (bitcoin-lisp.rpc::%process-multipath-import
                                wallet data 1
                                '("wpkh(xpub/0/*)" "wpkh(xpub/1/*)"))))
                   (is (eq t (cdr (assoc "success" result :test #'string=)))))))
          (setf (symbol-function 'bitcoin-lisp.rpc::%process-descriptor-import)
                original))))
    (setf seen (nreverse seen))
    (is (= 2 (length seen)))
    (is-false (cdr (first seen)) "the first expansion must be the receive chain")
    (is-true (cdr (second seen)) "the second expansion must be the CHANGE chain")
    ;; Each expansion carries its own checksum, since the input's covered the
    ;; multipath form.
    (is-true (find #\# (car (first seen))) "expansion was imported unchecksummed")
    (is-true (find #\# (car (second seen))))))

(test multipath-import-refuses-a-label
  "Core: \"Multipath descriptors should not have a label\" (backup.cpp:203-206)."
  (let ((data (make-hash-table :test 'equal)))
    (setf (gethash "desc" data) "wpkh(xpub/<0;1>/*)"
          (gethash "label" data) "mine")
    (let ((result (bitcoin-lisp.rpc::%process-multipath-import
                   :fake data 1 '("wpkh(xpub/0/*)" "wpkh(xpub/1/*)"))))
      (is-false (cdr (assoc "success" result :test #'string=)))
      (is (string= "Multipath descriptors should not have a label"
                   (cdr (assoc "message"
                               (cdr (assoc "error" result :test #'string=))
                               :test #'string=))))))
  ;; More than two paths plus `internal` is Core's other refusal (:232-234).
  (let ((data (make-hash-table :test 'equal)))
    (setf (gethash "desc" data) "wpkh(xpub/<0;1;2>/*)"
          (gethash "internal" data) t)
    (let ((result (bitcoin-lisp.rpc::%process-multipath-import
                   :fake data 1 '("a" "b" "c"))))
      (is-false (cdr (assoc "success" result :test #'string=))))))
