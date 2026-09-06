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
  (bl.rpc:parse-descriptor s net))

(defun %desc-pub (s &optional (net :mainnet))
  (bl.rpc:out-desc-string (%desc-parse s net)))

(defun %desc-scripts (s net pos)
  (mapcar #'bl.crypto:bytes-to-hex
          (bl.rpc::out-desc-expand (%desc-parse s net) pos)))

(defun %check-desc (prv pub scripts &key (net :mainnet) range hardened)
  "Port of Core's Check(): PRV and PUB must both parse and canonicalize to
PUB (checksum ignored); SCRIPTS is a list of per-index script-hex lists.
RANGE = expected isrange; HARDENED = expansion needs private keys, so the
PUB form must fail to expand."
  (let ((prv-desc (%desc-parse prv net))
        (pub-desc (%desc-parse pub net)))
    (is (string= pub (bl.rpc:out-desc-string prv-desc))
        "private form ~A canonicalizes to ~A, wanted ~A"
        prv (bl.rpc:out-desc-string prv-desc) pub)
    (is (string= pub (bl.rpc:out-desc-string pub-desc)))
    (is (eq (and range t) (and (bl.rpc:out-desc-ranged-p prv-desc) t)))
    (is (eq t (bl.rpc:out-desc-solvable-p prv-desc)))
    (when (string/= prv pub)
      (is (eq t (bl.rpc::out-desc-has-privkeys-p prv-desc)))
      (is (null (bl.rpc::out-desc-has-privkeys-p pub-desc))))
    (loop for expected in scripts
          for i from 0
          do (is (equal expected (%desc-scripts prv net i))
                 "~A at index ~D expands to ~S, wanted ~S"
                 prv i (%desc-scripts prv net i) expected)
             (if hardened
                 (signals bl.rpc:descriptor-derivation-error
                   (bl.rpc::out-desc-expand pub-desc i))
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
               (bl.rpc:rpc-error (e)
                 (when last-p
                   (is (string= message (bl.rpc:rpc-error-message e))
                       "~A failed with ~S, wanted ~S"
                       s (bl.rpc:rpc-error-message e) message)))))))

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
    (is (string= "ggrsrxfy" (bl.rpc::descriptor-checksum prv)))
    (is (string= "tjg09x5t" (bl.rpc::descriptor-checksum pub)))
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
    (signals-rpc-error (:message "Provided checksum 'ggrsrxfy' does not match computed checksum")
      (%desc-parse (concatenate 'string
                                "sh(multi(3"
                                (subseq prv 10)
                                "#ggrsrxfy")))
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
  "A key-path-only tr(), and where its x-only keys may appear.

The tree rejection this test used to assert is gone: tr(KEY,TREE) parses, and
TR-SCRIPT-TREES-MATCH-CORE-VECTORS below holds it to Core's vectors."
  ;; A single leaf needs no braces. No expected script is asserted here on
  ;; purpose -- Core has no vector for this exact string, and an expectation
  ;; read back out of our own expander would prove nothing. Core's ranged
  ;; vector in TR-SCRIPT-TREES-MATCH-CORE-VECTORS is a braceless single leaf
  ;; and pins the same path against a real oracle.
  (finishes
    (%desc-parse "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,pk(669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0))"))
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
    (let ((first-time (bl.rpc::out-desc-expand desc 7)))
      ;; second expansion returns the identical (cached) list
      (is (eq first-time (bl.rpc::out-desc-expand desc 7)))
      ;; a fresh parse of the same string hits the same cache entry
      (is (eq first-time (bl.rpc::out-desc-expand (%desc-parse s) 7)))
      ;; a different index derives a different script
      (is (not (equalp (first first-time)
                       (first (bl.rpc::out-desc-expand desc 8))))))))

;;; --- getdescriptorinfo (Core rpc/output_script.cpp behavior) ---

(test rpc-getdescriptorinfo-v2
  "getdescriptorinfo: canonical public descriptor + input checksum + flags."
  (let ((node (make-test-node))) ; :testnet3
    ;; Private ranged descriptor: xprv normalized to xpub in `descriptor`,
    ;; `checksum` is the checksum of the input as given.
    (let* ((prv "wpkh(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK/1/1/*)")
           (r (bl.rpc::rpc-getdescriptorinfo node (list prv)))
           (reported (cdr (assoc "descriptor" r :test #'string=))))
      (is (eq t (cdr (assoc "isrange" r :test #'string=))))
      (is (eq t (cdr (assoc "issolvable" r :test #'string=))))
      (is (eq t (cdr (assoc "hasprivatekeys" r :test #'string=))))
      (is (string= (bl.rpc::descriptor-checksum prv)
                   (cdr (assoc "checksum" r :test #'string=))))
      ;; The reported descriptor is public (tpub..., no tprv) and checksummed.
      (is (search "tpub" reported))
      (is (not (search "tprv" reported)))
      (is (char= #\# (char reported (- (length reported) 9))))
      ;; and it round-trips: parsing it yields the same canonical form.
      (is (string= reported
                   (cdr (assoc "descriptor"
                               (bl.rpc::rpc-getdescriptorinfo
                                node (list reported))
                               :test #'string=)))))
    ;; Unranged public descriptor: no range, no private keys.
    (let ((r (bl.rpc::rpc-getdescriptorinfo
              node
              (list "pkh(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1/1/0)"))))
      (is (eq 'yason:false (cdr (assoc "isrange" r :test #'string=))))
      (is (eq t (cdr (assoc "issolvable" r :test #'string=))))
      (is (eq 'yason:false (cdr (assoc "hasprivatekeys" r :test #'string=)))))
    ;; addr()/raw() are not solvable.
    (let ((r (bl.rpc::rpc-getdescriptorinfo node (list "raw(51)"))))
      (is (eq 'yason:false (cdr (assoc "issolvable" r :test #'string=)))))
    ;; Bad checksum still rejected.
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-getdescriptorinfo node (list "raw(51)#deadbeef")))))

;;; --- deriveaddresses (Core test/functional/rpc_deriveaddresses.py) ---

(defun %addr-script (address network)
  "scriptPubKey bytes of ADDRESS (used to compare against Core's documented
regtest bcrt1 addresses, whose witness programs are network-independent)."
  (multiple-value-bind (type script)
      (bl.crypto:decode-address address network)
    (declare (ignore type))
    script))

(defun %derived-scripts (node args)
  "deriveaddresses -> scriptPubKeys of the returned addresses."
  (mapcar (lambda (a) (%addr-script a :testnet3))
          (bl.rpc::rpc-deriveaddresses node args)))

(test rpc-deriveaddresses-core-functional
  "Port of Core's rpc_deriveaddresses.py: same tprv/tpub descriptors; the
expected witness programs come from decoding the bcrt1 addresses documented
in the Core test (bech32 HRP differs between our testnet node and Core's
regtest node, the underlying scriptPubKeys must match exactly)."
  (let* ((node (make-test-node))     ; :testnet3
         (tprv "tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK")
         (descsum (lambda (body) (bl.rpc:descriptor-add-checksum body))))
    (flet ((expect-error (message &rest args)
             (signals-rpc-error (:exact-message message)
               (bl.rpc::rpc-deriveaddresses node args))))
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
      (let ((addrs (bl.rpc::rpc-deriveaddresses
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
         (utxo (bl:node-utxo-set node))
         (desc "wpkh(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1/1/*)")
         (parsed (bl.rpc:parse-descriptor desc :testnet3))
         (script-at-5 (first (bl.rpc::out-desc-expand parsed 5)))
         (script-at-1500 (first (bl.rpc::out-desc-expand parsed 1500)))
         (txid-a (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
         (txid-b (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2)))
    (bl.store:add-utxo utxo txid-a 0 100000000 script-at-5 0)
    (bl.store:add-utxo utxo txid-b 0 200000000 script-at-1500 0)
    ;; Default range [0,1000]: finds index 5, not index 1500.
    (let ((r (bl.rpc::rpc-scantxoutset node (list "start" (list desc)))))
      (is (= 1 (length (cdr (assoc "unspents" r :test #'string=))))))
    ;; Explicit range through a scan object reaches index 1500.
    (let ((obj (make-hash-table :test 'equal)))
      (setf (gethash "desc" obj) desc
            (gethash "range" obj) (list 1400 1600))
      (let ((r (bl.rpc::rpc-scantxoutset node (list "start" (list obj)))))
        (let ((unspents (cdr (assoc "unspents" r :test #'string=))))
          (is (= 1 (length unspents)))
          (is (string= (bl.crypto:bytes-to-hex script-at-1500)
                       (cdr (assoc "scriptPubKey" (first unspents) :test #'string=)))))))
    ;; Narrow range that misses both.
    (let ((obj (make-hash-table :test 'equal)))
      (setf (gethash "desc" obj) desc
            (gethash "range" obj) (list 6 10))
      (let ((r (bl.rpc::rpc-scantxoutset node (list "start" (list obj)))))
        (is (= 0 (length (cdr (assoc "unspents" r :test #'string=)))))))
    ;; Range validation errors propagate.
    (let ((obj (make-hash-table :test 'equal)))
      (setf (gethash "desc" obj) desc
            (gethash "range" obj) (list 0 2000000))
      (signals bl.rpc:rpc-error
        (bl.rpc::rpc-scantxoutset node (list "start" (list obj)))))))

;;; --- generatetodescriptor-style consumers reject ranged descriptors ---

(test desc-ranged-rejected-where-core-rejects
  "parse-output-descriptor (generatetodescriptor / generateblock path) keeps
Core's 'Ranged descriptor not accepted' behavior."
  (signals-rpc-error (:exact-message "Ranged descriptor not accepted. Maybe pass through deriveaddresses first?")
    (bl.rpc::parse-output-descriptor
     "wpkh(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1/*)"
     :testnet3))
  ;; Unranged xpub descriptors now expand fine on this path.
  (let ((pairs (bl.rpc::parse-output-descriptor
                "wpkh(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1/1/0)"
                :testnet3)))
    (is (= 1 (length pairs)))
    (is (= 22 (length (car (first pairs)))))))

;;;; Multipath descriptors (BIP389)

(defun %mp-expand (s)
  (handler-case (bl.rpc:expand-multipath-descriptor s)
    (bl.rpc:rpc-error (e)
      (list :error (bl.rpc:rpc-error-message e)))))

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
      (let ((original (symbol-function 'bl.wallet::%process-descriptor-import)))
        (unwind-protect
             (progn
               (setf (symbol-function 'bl.wallet::%process-descriptor-import)
                     #'fake-import)
               (let ((data (make-hash-table :test 'equal)))
                 (setf (gethash "desc" data) "wpkh(xpub/<0;1>/*)")
                 (let ((result (bl.wallet::%process-multipath-import
                                wallet data 1
                                '("wpkh(xpub/0/*)" "wpkh(xpub/1/*)"))))
                   (is (eq t (cdr (assoc "success" result :test #'string=)))))))
          (setf (symbol-function 'bl.wallet::%process-descriptor-import)
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
    (let ((result (bl.wallet::%process-multipath-import
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
    (let ((result (bl.wallet::%process-multipath-import
                   :fake data 1 '("a" "b" "c"))))
      (is-false (cdr (assoc "success" result :test #'string=))))))

;;;; --- Key expression order, and inference of wsh(<miniscript>) ------------

(defun %dt-expand-pairs (desc-string)
  "(values desc scripts pairs) for DESC-STRING at index 0, the way
%SPKM-EXPANSION-PAIRS builds them for the wallet."
  (let ((d (bl.rpc:parse-descriptor desc-string :mainnet)))
    (multiple-value-bind (scripts pubkeys)
        (bl.rpc::%out-desc-expand-cached d 0)
      (values d scripts
              (mapcar #'cons (bl.rpc:out-desc-ordered-keys d) pubkeys)))))

(test expansion-pubkeys-come-back-in-key-expression-order
  "%SPKM-EXPANSION-PAIRS zips the expansion's pubkey list against
OUT-DESC-ORDERED-KEYS, which is PARSE order, so the expansion must return parse
order too.

Script generation does not visit key expressions in parse order: andor(X,Y,Z)
compiles to `X NOTIF Z ELSE Y ENDIF', so a collector that pushes in keyfn call
order transposes Y and Z. The wallet then attributes a pubkey to the wrong key
expression — the wrong origin in an inferred descriptor, and the wrong provider
consulted when signing."
  (let* ((a "025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc")
         (b "03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65")
         (c "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"))
    (multiple-value-bind (desc scripts pairs)
        (%dt-expand-pairs (format nil "wsh(andor(pk(~A),pk(~A),pk(~A)))" a b c))
      (declare (ignore desc scripts))
      ;; Every pair must hold a key and the pubkey that key derives to.
      (dolist (pair pairs)
        (is (equalp (bl.rpc:desc-key-pubkey (car pair)) (cdr pair))
            "key expression paired with another expression's pubkey")))))

(test wsh-miniscript-can-be-inferred-instead-of-crashing
  "The subscript of wsh(<miniscript>) is an out-desc of kind :MINISCRIPT and the
:WSH clause of %INFER-DESC-BODY recurses into it. With no :MINISCRIPT clause
that recursion was an ECASE failure, i.e. RPC -32603 Internal error, reachable
from getaddressinfo and listunspent for any wallet holding a policy descriptor."
  (let* ((a "025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc")
         (b "03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65")
         (c "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"))
    (multiple-value-bind (desc scripts pairs)
        (%dt-expand-pairs (format nil "wsh(and_v(v:pk(~A),older(42)))" a))
      (let ((body (bl.wallet::%infer-desc-body desc (first scripts) scripts pairs 0)))
        (is-true (stringp body) "inference returned ~S" body)
        (is-true (search "wsh(and_v(v:pk(" body))
        (is-true (search "older(42))" body))
        (is-true (search a body) "the concrete key is not in the inferred body")))
    ;; And the andor case names each key in its own position, which is the
    ;; whole point of the ordering fix above: an inferred descriptor with two
    ;; keys transposed is a backup that restores a different wallet.
    (multiple-value-bind (desc scripts pairs)
        (%dt-expand-pairs (format nil "wsh(andor(pk(~A),pk(~A),pk(~A)))" a b c))
      (let ((body (bl.wallet::%infer-desc-body desc (first scripts) scripts pairs 0)))
        (is-true (stringp body))
        (let ((pa (search a body)) (pb (search b body)) (pc (search c body)))
          (is-true (and pa pb pc) "not every key appears in the inferred body")
          (is-true (< pa pb pc)
                   "inferred keys are out of parse order: ~S" body))))))

;;;; --- descriptor_tests.cpp: tr() script trees -----------------------------

(defparameter +tr-xonly+
  "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5"
  "Core's x-only test key. 32 bytes whose first byte happens to be 0x03, which
is why it reads like a compressed key and is not one.")

(defparameter +tr-xpub+
  "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL")

(defparameter +tr-xprv+
  "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc")

(test tr-script-trees-match-core-vectors
  "Core descriptor_tests.cpp Check() vectors for tr(KEY,TREE). The output key is
the internal key tweaked by the tree's merkle root, so a wrong leaf script, a
wrong depth or a wrong combine order all land on a DIFFERENT address rather
than on an error — only the vectors catch it."
  ;; descriptor_tests.cpp:625 — a nested tree mixing an x-only hex key with a
  ;; WIF one, which the public form prints as 32-byte x-only hex.
  (%check-desc
   (format nil "tr(~A,{pk(~A),{pk(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1),pk(~A)}})"
           +tr-xonly+ +tr-xonly+ +tr-xonly+)
   (format nil "tr(~A,{pk(~A),{pk(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd),pk(~A)}})"
           +tr-xonly+ +tr-xonly+ +tr-xonly+)
   '(("51201497ae16f30dacb88523ed9301bff17773b609e8a90518a3f96ea328a47d1500")))
  ;; descriptor_tests.cpp:993 — a single leaf that is multi_a(), i.e. the
  ;; CHECKSIGADD chain BIP342 replaced CHECKMULTISIG with.
  (%check-desc
   "tr(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1,multi_a(1,KzoAz5CanayRKex3fSLQ2BwJpN7U52gZvxMyk78nDMHuqrUxuSJy))"
   "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,multi_a(1,669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0))"
   '(("5120eb5bd3894327d75093891cc3a62506df7d58ec137fcd104cdd285d67816074f3")))
  ;; descriptor_tests.cpp:640 — a RANGED tree. The leaf key stays an xpub in the
  ;; descriptor string while its script push is 32 bytes: see the regression
  ;; test below for why those two must be decided separately.
  (%check-desc
   (format nil "tr(~A/0/*,pk(~A/1/*))" +tr-xprv+ +tr-xprv+)
   (format nil "tr(~A/0/*,pk(~A/1/*))" +tr-xpub+ +tr-xpub+)
   '(("512078bc707124daa551b65af74de2ec128b7525e10f374dc67b64e00ce0ab8b3e12")
     ("512001f0a02a17808c20134b78faab80ef93ffba82261ccef0a2314f5d62b6438f11")
     ("512021024954fcec88237a9386fce80ef2ced5f1e91b422b26c59ccfc174c8d1ad25"))
   :range t))

(test tr-script-tree-parse-errors-match-core
  "The tree grammar's error messages, verbatim from descriptor.cpp:2474-2515."
  ;; descriptor_tests.cpp:1006
  (%check-unparsable
   "" "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,multi_a(1))"
   "Cannot have 0 keys in multi_a; must have between 1 and 999 keys, inclusive")
  ;; A left branch that never gets its sibling.
  (%check-unparsable
   "" (format nil "tr(~A,{pk(~A)})" +tr-xonly+ +tr-xonly+)
   "tr(): expected ',' after script expression")
  ;; A right branch that never gets closed.
  (%check-unparsable
   "" (format nil "tr(~A,{pk(~A),pk(~A))" +tr-xonly+ +tr-xonly+ +tr-xonly+)
   "tr(): expected '}' after script expression")
  ;; A finished tree with something after it.
  (%check-unparsable
   "" (format nil "tr(~A,{pk(~A),pk(~A)},pk(~A))"
              +tr-xonly+ +tr-xonly+ +tr-xonly+ +tr-xonly+)
   "tr(): expected ')' after script expression")
  ;; multi/sortedmulti are not tapscript: BIP342 removed CHECKMULTISIG.
  (%check-unparsable
   "" (format nil "tr(~A,multi(1,~A))" +tr-xonly+ +tr-xonly+)
   "Can only have multi/sortedmulti at top level, in sh(), or in wsh()")
  ;; ...and multi_a is ONLY tapscript.
  (%check-unparsable
   "" "wsh(multi_a(1,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))"
   "Can only have multi_a/sortedmulti_a inside tr()"))

(test tr-leaf-pk-pushes-the-x-only-key-even-for-an-xpub
  "Core's PKDescriptor carries m_xonly (descriptor.cpp:1143), set from the
PARSE CONTEXT, and pk() inside a taproot leaf pushes 32 bytes.

The flag belongs to the DESCRIPTOR, not to the key, and an xpub leaf is what
proves it: DESC-KEY's XONLY-P decides how a key PRINTS, and Core prints this
leaf as pk(xpub.../1/*) while pushing the 32-byte form into the script. Deciding
the script from the print flag silently gives a 33-byte push here — a different
leaf hash, a different merkle root, and therefore a different ADDRESS."
  (let* ((d (%desc-parse (format nil "tr(~A/0/*,pk(~A/1/*))" +tr-xpub+ +tr-xpub+)))
         (leaf (cdr (first (bl.rpc:out-desc-tree d))))
         (script (first (bl.rpc::out-desc-expand leaf 0))))
    (is (= 34 (length script))
        "leaf script is ~D bytes, wanted 34 (push32 + CHECKSIG)" (length script))
    (is (= 32 (aref script 0)) "leaf pushes ~D bytes, wanted 32" (aref script 0))
    (is (= #xac (aref script 33)))
    ;; And the key still prints as an xpub, which is the half that must NOT
    ;; follow the script.
    (is-true (search +tr-xpub+ (bl.rpc:out-desc-string d))
             "the leaf key stopped printing as an xpub")))

(test tr-tree-inference-names-each-leafs-own-key
  "%INFER-DESC-BODY addresses PAIRS positionally — (first pairs) means `this
descriptor's key' — which holds only while the descriptor owns every pair. A
tr() tree breaks that: OUT-DESC-ORDERED-KEYS numbers the INTERNAL key first, so
handing every leaf the whole list makes all of them report the internal key.
An inferred descriptor is what a backup restores from, so a leaf naming the
wrong key restores a different wallet."
  (let* ((a "025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc")
         (b "03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65")
         (x-a (subseq a 2))
         (x-b (subseq b 2)))
    (multiple-value-bind (desc scripts pairs)
        (%dt-expand-pairs (format nil "tr(~A,{pk(~A),pk(~A)})" +tr-xonly+ a b))
      (let ((body (bl.wallet::%infer-desc-body desc (first scripts)
                                                      scripts pairs 0)))
        (is-true (stringp body) "inference returned ~S" body)
        ;; Each leaf reports its OWN key, x-only (Core builds the inferred
        ;; leaf as PKDescriptor(..., /*xonly=*/true), descriptor.cpp:2695).
        (let ((pa (search x-a body)) (pb (search x-b body)))
          (is-true pa "leaf key ~A missing from ~S" x-a body)
          (is-true pb "leaf key ~A missing from ~S" x-b body)
          (is-true (and pa pb (< pa pb))
                   "inferred leaves are out of parse order: ~S" body))
        (is-false (search a body)
                  "a leaf reported its key in 33-byte form: ~S" body)
        ;; The internal key appears exactly once — as the internal key.
        (is (= 1 (count-if (lambda (i) (declare (ignore i)) t)
                           (loop with start = 0
                                 for p = (search +tr-xonly+ body :start2 start)
                                 while p collect p do (setf start (1+ p)))))
            "the internal key appears more than once in ~S" body)))))

(test tr-tree-survives-the-checksum-and-the-string-forms
  "Braces are part of BIP380's INPUT_CHARSET, and all three string forms
(public, private, normalized) go through %OUT-DESC-STRING-WALK, so a tree that
prints wrong prints wrong everywhere at once — including in the checksum a
wallet backup is identified by."
  (let* ((node (make-test-node))          ; :testnet3
         (body (format nil "tr(~A,{pk(~A),multi_a(1,~A)})"
                       +tr-xonly+ +tr-xonly+ +tr-xonly+))
         (r (bl.rpc::rpc-getdescriptorinfo node (list body)))
         (reported (cdr (assoc "descriptor" r :test #'string=))))
    (is (string= (bl.rpc::descriptor-checksum body)
                 (cdr (assoc "checksum" r :test #'string=))))
    (is (eq t (cdr (assoc "issolvable" r :test #'string=))))
    ;; JSON false is a SENTINEL OBJECT, which is true in Lisp: IS-FALSE here
    ;; would pass on any value the RPC could ever return.
    (is (eq bl.rpc:+json-false+
            (cdr (assoc "isrange" r :test #'string=))))
    (is (eq bl.rpc:+json-false+
            (cdr (assoc "hasprivatekeys" r :test #'string=))))
    ;; The reported form keeps the tree and round-trips to itself.
    (is-true (search "{pk(" reported) "the tree vanished from ~S" reported)
    (is-true (search "multi_a(1," reported))
    (is (string= reported
                 (cdr (assoc "descriptor"
                             (bl.rpc::rpc-getdescriptorinfo
                              node (list reported))
                             :test #'string=))))))

;;;; --- tr() script-path spending -------------------------------------------

(defun %tr-sign-and-verify (desc-str held-wifs &key (sequence #xffffffff))
  "Sign a spend of DESC-STR's output at index 0 holding only HELD-WIFS, through
the real signer (%SIGN-TX-INPUTS), and verify the result with our own script
interpreter under STANDARD flags. SEQUENCE is the spending input's, which is
what a leaf carrying older() is satisfied (or not) against.

Returns (values error-messages witness-element-sizes verified-p).

The interpreter is the oracle here: it is held to Core's script/sighash/BIP341
vectors by the rest of this battery, so a witness it accepts under standard
flags is one Core accepts. A hand-written expected witness would only re-assert
whatever the signer happened to build."
  (let* ((desc (bl.rpc:parse-descriptor desc-str :mainnet))
         (spk (first (bl.rpc::out-desc-expand desc 0)))
         (amount 100000)
         (empty (make-array 0 :element-type '(unsigned-byte 8))))
    (multiple-value-bind (output-key leaves)
        (bl.rpc:tr-spend-data
         desc 0 (lambda (k) (bl.rpc::%desc-key-pubkey-at k 0)))
      (let* ((prev-txid (make-array 32 :element-type '(unsigned-byte 8)
                                       :initial-element 7))
             (tx (bl.ser:make-transaction
                  :version 2
                  :inputs (vector (bl.ser:make-tx-in
                                   :previous-output
                                   (bl.ser:make-outpoint
                                    :hash prev-txid :index 0)
                                   :script-sig empty :sequence sequence))
                  :outputs (vector (bl.ser:make-tx-out
                                    :value (- amount 1000)
                                    :script-pubkey
                                    (coerce (bl.crypto:hex-to-bytes
                                             "0014751e76e8199196d454941c45d1b3a323f1433bd6")
                                            '(simple-array (unsigned-byte 8) (*)))))))
             (prevmap (make-hash-table :test 'equalp))
             (keymap (make-hash-table :test 'equalp))
             (pubmap (make-hash-table :test 'equalp))
             (tr-keymap (make-hash-table :test 'equalp))
             (tr-scripts (make-hash-table :test 'equalp))
             (pairs (mapcar (lambda (k)
                              (cons k (bl.rpc::%desc-key-pubkey-at k 0)))
                            (bl.rpc:out-desc-ordered-keys desc)))
             (next (bl.wallet::%pairs-splitter (rest pairs))))
        (setf (gethash (cons prev-txid 0) prevmap) (list spk amount nil nil))
        (dolist (wif held-wifs)
          (let* ((sk (bl.crypto:wif-to-private-key wif))
                 (pub (bl.crypto:derive-public-key sk :compressed t)))
            (setf (gethash pub pubmap) sk)
            (setf (gethash (bl.crypto:hash160 pub) keymap) (cons sk pub))))
        (setf (gethash output-key tr-scripts)
              (loop for (script leaf-hash control) in leaves
                    for (nil . leaf) in (bl.rpc:out-desc-tree desc)
                    for own = (funcall next leaf)
                    collect (list script leaf-hash control
                                  (mapcar #'cdr own))))
        (let ((errs (bl.rpc:sign-tx-inputs
                     tx prevmap keymap pubmap tr-keymap 1 tr-scripts)))
          (values (mapcar #'cdr errs)
                  (map 'list (lambda (st) (mapcar #'length st))
                       (or (bl.ser:transaction-witness tx) #()))
                  (nth-value 0 (bl.wallet::%verify-tx-scripts tx prevmap))))))))

(test tr-script-path-spends-verify
  "A tr() output whose INTERNAL key we do not hold can only be spent through a
script path, and the spend must verify under standard flags.

Every element order here is one a green signer gets wrong silently: the multi_a
stack runs opposite to key order (CHECKSIGADD pops from the top), and pkh()
puts the revealed key ABOVE its signature (DUP reads the stack top). Both
produce a well-formed witness that simply does not spend."
  (let ((i "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
        (a "L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1")
        (b "KzoAz5CanayRKex3fSLQ2BwJpN7U52gZvxMyk78nDMHuqrUxuSJy")
        (c "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S"))
    (flet ((spends (label desc held &optional sizes)
             (multiple-value-bind (errs witness verified)
                 (%tr-sign-and-verify desc held)
               (is (null errs) "~A: signing reported ~S" label errs)
               (is-true verified "~A: the signed spend does not verify" label)
               (when sizes
                 (is (equal sizes (first witness))
                     "~A: witness element sizes ~S, wanted ~S"
                     label (first witness) sizes)))))
      ;; sig, 34-byte <x> CHECKSIG leaf, 33-byte control block (depth 0).
      (spends "pk leaf" (format nil "tr(~A,pk(~A))" i a) (list a) '(64 34 33))
      ;; sig, revealed 32-byte key, 25-byte pkh leaf, control block.
      (spends "pkh leaf" (format nil "tr(~A,pkh(~A))" i a) (list a) '(64 32 25 33))
      ;; Two signatures and one empty placeholder, in REVERSE key order: the
      ;; elements go on bottom-first and <a> CHECKSIG pops from the top, so
      ;; the LAST element is the FIRST key's slot. Which key gets the empty
      ;; slot is Core's tie-break, not a free choice -- where signing the
      ;; current key and dissatisfying it cost the same, operator| keeps the
      ;; stack that dissatisfies it (miniscript.h:1259-1284), so a 2-of-3
      ;; holding everything signs b and c and leaves a's slot empty.
      (spends "multi_a 2-of-3"
              (format nil "tr(~A,multi_a(2,~A,~A,~A))" i a b c) (list a b c)
              '(64 64 0 104 33))
      (spends "sortedmulti_a 1-of-2"
              (format nil "tr(~A,sortedmulti_a(1,~A,~A))" i a b) (list b))
      ;; A depth-2 leaf: the control block carries two merkle path elements,
      ;; 33 + 2*32 = 97 bytes. This is what a wrong merkle PATH breaks while
      ;; the address stays right, since TapBranch sorts each pair.
      (spends "nested tree, depth-2 leaf"
              (format nil "tr(~A,{multi_a(2,~A,~A),{pk(~A),pk(~A)}})" i a b c a)
              (list c) '(64 34 97)))))

(test tr-miniscript-leaves-spend-the-way-core-signs-them
  "A tr() leaf written as a miniscript parsed, passed the sanity gate and got
an address, and then could never be spent: TR-LEAF-SATISFACTION was a CASE over
four leaf KINDS and a :MINISCRIPT leaf fell through it as unsatisfiable. Core
has no such table -- SignTaprootScript infers a miniscript back out of the leaf
SCRIPT and satisfies that (sign.cpp:528-540) -- so every shape below now signs
through the same code the pk and multi_a leaves above do.

The interpreter is the oracle for each one; a witness that assembles is not a
witness that spends."
  (let ((i "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
        (a "L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1")
        (b "KzoAz5CanayRKex3fSLQ2BwJpN7U52gZvxMyk78nDMHuqrUxuSJy")
        (c "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S"))
    (flet ((spends (label desc held sizes &key (sequence #xffffffff))
             (multiple-value-bind (errs witness verified)
                 (%tr-sign-and-verify desc held :sequence sequence)
               (is (null errs) "~A: signing reported ~S" label errs)
               (is-true verified "~A: the signed spend does not verify" label)
               (is (equal sizes (first witness))
                   "~A: witness element sizes ~S, wanted ~S"
                   label (first witness) sizes)))
           (cannot (label desc held &key (sequence #xffffffff))
             (multiple-value-bind (errs witness verified)
                 (%tr-sign-and-verify desc held :sequence sequence)
               (is (equal '("no satisfiable script path for P2TR") errs)
                   "~A: reported ~S" label errs)
               (is (null (first witness)) "~A: emitted a witness anyway" label)
               (is-false verified label))))
      ;; The finding's own shape: a miniscript leaf beside a pk() leaf, spent
      ;; through the miniscript one. and_v puts the SECOND branch's elements
      ;; first, so c's signature is at the bottom and b's on top.
      (spends "and_v leaf in a two-leaf tree"
              (format nil "tr(~A,{pk(~A),and_v(v:pk(~A),pk(~A))})" i a b c)
              (list b c) '(64 64 68 65))
      ;; pkh() inside a tapscript leaf: the revealed key is 32 bytes, not 33,
      ;; and it is found by HASH160 OF THE X-ONLY key -- Core's
      ;; TapSatisfier::FromPKHBytes (sign.cpp:514-518), which is a different
      ;; index from the P2WSH one.
      (spends "pkh inside a miniscript leaf"
              (format nil "tr(~A,and_v(v:pkh(~A),pk(~A)))" i b c)
              (list b c) '(64 64 32 59 33))
      ;; A timelock leaf is satisfied against the SPENDING INPUT, which is why
      ;; the satisfier needs Core's TapSatisfier CheckOlder rather than
      ;; treating older() as free.
      (spends "matured older() leaf"
              (format nil "tr(~A,and_v(v:pk(~A),older(1)))" i b)
              (list b) '(64 36 33) :sequence 1)
      (cannot "older() not yet matured"
              (format nil "tr(~A,and_v(v:pk(~A),older(5)))" i b) (list b)
              :sequence 1)
      ;; A branching leaf takes the branch it holds a key for.
      (spends "or_d leaf, immediate branch"
              (format nil "tr(~A,or_d(pk(~A),and_v(v:pk(~A),older(1))))" i b c)
              (list b) '(64 73 33))
      ;; And holding the wrong key still reports itself rather than emitting
      ;; something that does not spend.
      (cannot "miniscript leaf, wrong key"
              (format nil "tr(~A,and_v(v:pk(~A),pk(~A)))" i b c) (list a)))))

(test tr-miniscript-leaf-is-spendable-through-the-wallet-rpcs
  "The finding end to end, in the terms an operator sees. Before this the
wallet imported the descriptor, deriveaddresses handed out a bech32m address,
the funding wallet's own sendtoaddress paid it, getbalance counted it -- and
signrawtransactionwithwallet answered complete:false with \"no satisfiable
script path for P2TR\", leaving the coins recoverable only by moving the
descriptor and keys to another implementation."
  (let ((result (descriptor-spend-e2e
                 (format nil "tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d5~
47bfee9ace803ac0,and_v(v:pk(~A),pk(~A)))"
                         (regtest-wif 21) (regtest-wif 22))
                 :suffix "tr-ms")))
    (is-true (getf result :imported) "importdescriptors refused: ~S" result)
    (is-true (getf result :address))
    (is (= 1.0d0 (getf result :balance))
        "the wallet must count the coin before the spend is even attempted")
    (is-true (getf result :complete)
             "signrawtransactionwithwallet reported ~S" (getf result :errors))
    (is-true (getf result :accepted)
             "the node refused the spend the wallet signed")))

(test tr-script-path-fails-loudly-without-the-keys
  "A leaf we cannot satisfy must report itself, never emit a witness. multi_a
below the threshold is the interesting one: signatures ARE produced, just not
enough, and a signer that shipped them would broadcast an unspendable input."
  (let ((i "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
        (a "L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1")
        (b "KzoAz5CanayRKex3fSLQ2BwJpN7U52gZvxMyk78nDMHuqrUxuSJy")
        (c "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S"))
    (flet ((cannot (label desc held)
             (multiple-value-bind (errs witness verified)
                 (%tr-sign-and-verify desc held)
               (is (equal '("no satisfiable script path for P2TR") errs)
                   "~A: reported ~S" label errs)
               (is (null (first witness)) "~A: emitted a witness anyway" label)
               (is-false verified label))))
      (cannot "wrong key" (format nil "tr(~A,pk(~A))" i a) (list b))
      (cannot "multi_a below threshold"
              (format nil "tr(~A,multi_a(2,~A,~A,~A))" i a b c) (list a)))))

;;;; --- bare P2PK, the shape combo() owns -----------------------------------

(test combo-bare-p2pk-coin-is-spendable-through-the-wallet-rpcs
  "combo() -- what Core's legacy-wallet migration emits, and the shape a
pre-2012 key is recovered in -- expands to a BARE P2PK script among its four.
The wallet owned that coin, counted it and let coin selection pick it, while
the node's only per-input signer had no TxoutType::PUBKEY case, so every path
out of the wallet ended in complete=false (sendtoaddress raised -6 \"Signing
transaction failed\").

Everything below goes through the shipped RPCs, because that is the only place
the finding is visible: an in-process call to the signer proves nothing about
what an operator sees. The coinbase is mined straight to pk(<pubkey>) so the
wallet's ONLY coin is the bare-P2PK one -- with a P2PKH coin alongside, the
sweep still fails but for a coin that looks fine."
  (with-wallet-chain-node (node "p2pk" :wallet "pk")
    (labels ((rpc (method &rest params)
               (with-rpc-wallet (nil)
                 (bl.rpc:dispatch-rpc-method node method params)))
             (aval (key alist) (cdr (assoc key alist :test #'string=))))
      (let* ((priv (make-array 32 :element-type '(unsigned-byte 8) :initial-element 42))
             (pub (bl.crypto:derive-public-key priv))
             (combo (bl.rpc:descriptor-add-checksum
                     (format nil "combo(~A)"
                             (bl.crypto:private-key-to-wif priv :network :regtest))))
             (request (let ((h (make-hash-table :test 'equal)))
                        (setf (gethash "desc" h) combo
                              (gethash "timestamp" h) "now")
                        h))
             (imported (first (rpc "importdescriptors" (list request)))))
        (is (eq t (aval "success" imported)) "importdescriptors refused: ~S" imported)
        ;; One coinbase to the bare P2PK script, then 100 blocks to mature it.
        (rpc "generatetodescriptor" 1
             (bl.rpc:descriptor-add-checksum
              (format nil "pk(~A)" (bl.crypto:bytes-to-hex pub))))
        (rpc "generatetoaddress" 100
             (bl.crypto:encode-p2sh-address
              (bl.crypto:hash160 +optrue-redeem+) :regtest))
        (let ((coin (first (rpc "listunspent"))))
          (is-true coin "the wallet does not even see the coin")
          (is (eq t (aval "spendable" coin))
              "the wallet reports the coin unspendable, so the finding is elsewhere")
          (is (= 50.0d0 (aval "amount" coin)))
          ;; The spend an operator asks for. Before the P2PK arm this raised
          ;; RPC -6 "Signing transaction failed" and moved nothing.
          (let ((txid (rpc "sendtoaddress"
                           (bl.crypto:encode-p2sh-address
                            (bl.crypto:hash160 +optrue-redeem+) :regtest)
                           1.0d0 nil nil t nil nil nil nil 10)))
            (is-true (stringp txid) "sendtoaddress answered ~S" txid)
            ;; It is in the mempool, i.e. the node's own script verification
            ;; accepted the scriptSig the wallet built.
            (is-true (find txid (coerce (rpc "getrawmempool") 'list)
                           :test #'string=)
                     "the node did not accept the transaction the wallet signed")))))))

(test script-num-serializes-like-cscriptnum
  "Core's CScript << int64_t (script.h:433) pushes CScriptNum::serialize, which
appends a 0x00 sign byte whenever the top bit of the last byte is set.

Reachable: multi_a allows a threshold up to MAX_PUBKEYS_PER_MULTI_A, so a
128-of-N tapscript leaf is a legal descriptor. A one-byte-per-number shortcut
builds a different leaf script there, hence a different leaf hash, merkle root
and ADDRESS — and above 255 it cannot hold the value at all."
  (flet ((hex (n) (bl.crypto:bytes-to-hex
                   (coerce (bl.rpc::%script-num n)
                           '(vector (unsigned-byte 8))))))
    ;; 1..16 are the OP_1..OP_16 opcodes.
    (is (string= "51" (hex 1)))
    (is (string= "60" (hex 16)))
    ;; 17..127 fit one byte with the top bit clear.
    (is (string= "0111" (hex 17)))
    (is (string= "017f" (hex 127)))
    ;; 128..255 need the sign byte: 0x80 alone is negative zero.
    (is (string= "028000" (hex 128)))
    (is (string= "02ff00" (hex 255)))
    ;; Beyond a byte, little-endian, sign byte only when the top one is set.
    (is (string= "020001" (hex 256)))
    (is (string= "02e703" (hex 999)))))

(test taproot-tree-rejects-a-depth-sequence-core-refuses
  "Core's TaprootBuilder::Insert clears m_valid rather than storing, in two
places we originally skipped: inserting above an unfinished deeper branch
(signingprovider.cpp:390), and propagating past the root (:399).

Both leave exactly one node pending at depth 0, so a builder that stores anyway
passes its own completeness test and returns a root for a tree Core asserts
against. No tr() STRING can produce these — brace nesting cannot — which is
precisely why the guard needs a test of its own rather than a caller."
  (let ((h (lambda (b) (make-array 32 :element-type '(unsigned-byte 8)
                                      :initial-element b))))
    ;; A well-formed tree still works.
    (is (= 32 (length (bl.rpc::%taproot-tree
                       (list (cons 1 (funcall h 1)) (cons 1 (funcall h 2)))))))
    ;; Propagating past the root.
    (signals bl.rpc:rpc-error
      (bl.rpc::%taproot-tree
       (list (cons 1 (funcall h 1)) (cons 1 (funcall h 2)) (cons 0 (funcall h 3)))))
    (signals bl.rpc:rpc-error
      (bl.rpc::%taproot-tree
       (list (cons 0 (funcall h 1)) (cons 0 (funcall h 2)))))
    ;; A leaf above an unfinished deeper branch.
    (signals bl.rpc:rpc-error
      (bl.rpc::%taproot-tree
       (list (cons 2 (funcall h 1)) (cons 1 (funcall h 2)))))
    ;; And an incomplete tree is still incomplete.
    (signals bl.rpc:rpc-error
      (bl.rpc::%taproot-tree (list (cons 1 (funcall h 1)))))))

;;;; --- musig() key aggregation (BIP327/BIP328) -----------------------------

(test musig-aggregation-matches-bip327-vectors
  "libsecp256k1's own BIP327 key-agg vectors (modules/musig/vectors.h:55).

Both orders are pinned on purpose: BIP327 aggregation is NOT symmetric, so the
same three keys in a different order are a different aggregate and therefore a
different ADDRESS. The primitive stays order-sensitive; BIP328's KeySort is
applied one level up, by the descriptor."
  (let ((x1 (bl.crypto:hex-to-bytes
             "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"))
        (x2 (bl.crypto:hex-to-bytes
             "03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659"))
        (x3 (bl.crypto:hex-to-bytes
             "023590a94e768f8e1815c2f24b4d80a8e3149316c3518ce7b7ad338368d038ca66")))
    (flet ((agg-xonly (keys)
             (let ((a (bl.crypto:musig-aggregate-pubkeys keys)))
               (and a (bl.crypto:bytes-to-hex (subseq a 1))))))
      (is (string= "90539eede565f5d054f32cc0c220126889ed1e5d193baf15aef344fe59d4610c"
                   (agg-xonly (list x1 x2 x3))))
      (is (string= "6204de8b083426dc6eaf9502d27024d53fc826bf7d2012148a0575435df54b2b"
                   (agg-xonly (list x3 x2 x1))))
      (is (string= "b436e3bad62b8cd409969a224731c193d051162d8c5ae8b109306127da3aa935"
                   (agg-xonly (list x1 x1 x1))))
      (is (string= "69bc22bfa5d106306e48a20679de1d7389386124d07571d0d872686028c26a3e"
                   (agg-xonly (list x1 x1 x2 x2)))))))

(test musig-descriptors-match-core-vectors
  "Core descriptor_tests.cpp:1160-1161. rawtr() takes the aggregate x-only key
directly; tr() tweaks it by BIP86's empty merkle root, so the two differ and
pin both halves.

The string round-trip pins the other half of BIP328: participants PRINT in the
order written, while aggregation SORTS them. A descriptor that came back
re-sorted would not round-trip to what its owner typed."
  (let ((body "musig(KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S,03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659,023590a94e768f8e1815c2f24b4d80a8e3149316c3518ce7b7ad338368d038ca66)")
        (pub "musig(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9,03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659,023590a94e768f8e1815c2f24b4d80a8e3149316c3518ce7b7ad338368d038ca66)"))
    (%check-desc (format nil "rawtr(~A)" body) (format nil "rawtr(~A)" pub)
                 '(("5120789d937bade6673538f3e28d8368dda4d0512f94da44cf477a505716d26a1575")))
    (%check-desc (format nil "tr(~A)" body) (format nil "tr(~A)" pub)
                 '(("512079e6c3e628c9bfbce91de6b7fb28e2aec7713d377cf260ab599dcbc40e542312")))))

(test musig-parse-errors-match-core
  "descriptor.cpp:1964-2044, verbatim."
  (let ((a "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")
        (b "03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659"))
    ;; Only inside tr()/rawtr().
    ;; Core prefixes with the function that asked for the key, as it does for
    ;; every other key-expression error (descriptor_tests.cpp:1260).
    (%check-unparsable "" (format nil "wsh(pk(musig(~A,~A)))" a b)
                       "pk(): musig() is only allowed in tr() and rawtr()")
    (%check-unparsable "" (format nil "pkh(musig(~A,~A))" a b)
                       "pkh(): musig() is only allowed in tr() and rawtr()")
    ;; No participants at all.
    (%check-unparsable "" "tr(musig()/0)" "tr(): musig(): Must contain key expressions")
    ;; Stray parentheses.
    ;; descriptor_tests.cpp:1279 verbatim — a fuzz-derived string, which is
    ;; exactly the kind that reaches this branch.
    (%check-unparsable
     "" "tr(musig(tuus(oldepk(gg)ggggfgg)<,z(((((((((((((((((((((st)"
     "tr(): Too many ')' in musig() expression")
    ;; Derivation needs xpubs.
    (%check-unparsable "" (format nil "tr(musig(~A,~A)/0)" a b)
                       "tr(): musig(): derivation requires all participants to be xpubs or xprvs")))

;;;; --- Miniscript in a tapscript context -----------------------------------

(test tr-leaf-miniscript-matches-core-vector
  "Core descriptor_tests.cpp:1143 — a tr() whose tree holds a MINISCRIPT leaf
and a multi_a leaf.

Miniscript's rules are stated per CONTEXT, and this vector exercises every way
the two differ at once: multi_a exists only under tapscript (BIP342 removed
CHECKMULTISIG), keys serialize x-only, and `d:'/size/stack limits all change.
A port that assumed P2WSH would build a different leaf script, hence a
different merkle root, hence a different ADDRESS — while still type-checking."
  (%check-desc
   "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,{and_v(and_v(v:hash256(ae253ca2a54debcac7ecf414f6734f48c56421a08bb59182ff9f39a6fffdb588),v:pk(KykUPmR5967F4URzMUeCv9kNMU9CNRWycrPmx3ZvfkWoQLabbimL)),older(42)),multi_a(2,adf586a32ad4b0674a86022b000348b681b4c97a811f67eefe4a6e066e55080c,KztMyyi1pXUtuZfJSB7JzVdmJMAz7wfGVFoSRUR5CVZxXxULXuGR)})"
   "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,{and_v(and_v(v:hash256(ae253ca2a54debcac7ecf414f6734f48c56421a08bb59182ff9f39a6fffdb588),v:pk(1c9bc926084382e76da33b5a52d17b1fa153c072aae5fb5228ecc2ccf89d79d5)),older(42)),multi_a(2,adf586a32ad4b0674a86022b000348b681b4c97a811f67eefe4a6e066e55080c,14fa4ad085cdee1e2fc73d491b36a96c192382b1d9a21108eb3533f630364f9f)})"
   '(("51209a3d79db56fbe3ba4d905d827b62e1ed31cd6df1198b8c759d589c0f4efc27bd"))))

(test miniscript-fragments-are-gated-by-context
  "multi is P2WSH-only and multi_a tapscript-only. Accepting either in the
wrong context is not a cosmetic error: `multi' under tapscript compiles to
CHECKMULTISIG, which BIP342 made an OP_SUCCESS-free failure, so the output
would be unspendable while the descriptor looked fine."
  (let ((a "025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc")
        (b "03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65")
        (i "a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"))
    ;; multi_a inside wsh(): rejected.
    (signals bl.rpc:rpc-error
      (%desc-parse (format nil "wsh(multi_a(1,~A,~A))" a b)))
    ;; multi inside a tr() leaf: rejected.
    (signals bl.rpc:rpc-error
      (%desc-parse (format nil "tr(~A,multi(1,~A,~A))" i a b)))
    ;; And each in its own context parses.
    (finishes (%desc-parse (format nil "wsh(multi(1,~A,~A))" a b)))
    (finishes (%desc-parse (format nil "tr(~A,multi_a(1,~A,~A))" i a b)))))

(test miniscript-tapscript-keys-are-x-only-in-the-script
  "Core: `In Tapscript keys always serialize as x-only, whether an x-only key
was used in the descriptor or not' (descriptor.cpp:1569). The leaf script of a
miniscript fragment must push 32 bytes, and pk_h must hash the 32-byte form —
the same split that produced a wrong address twice in the tr() work."
  (let* ((a "025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc")
         (i "a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd")
         (d (%desc-parse (format nil "tr(~A,and_v(v:pk(~A),older(42)))" i a)))
         (leaf (cdr (first (bl.rpc:out-desc-tree d))))
         (script (first (bl.rpc::out-desc-expand leaf 0))))
    ;; <32> <x> CHECKSIGVERIFY <42> CHECKSEQUENCEVERIFY
    (is (= 32 (aref script 0))
        "leaf pushes ~D bytes, wanted 32 (x-only)" (aref script 0))
    (is-false (search (bl.crypto:hex-to-bytes a) script)
              "the 33-byte key appears verbatim in a tapscript leaf")))
