(in-package #:bitcoin-lisp.tests)

;;;; BIP324 cipher suite tests
;;;;
;;;; Vector test bodies below the helpers are MACHINE-EXTRACTED from Bitcoin
;;;; Core src/test/crypto_tests.cpp (chacha20_testvector, poly1305_testvector,
;;;; chacha20poly1305_testvectors, hkdf_hmac_sha256_l32_tests), which embed
;;;; RFC 7539/8439 A.1-A.5, draft-agl-tls-chacha20poly1305-04, poly1305-donna,
;;;; and Core's own FSChaCha20{,Poly1305} rekeying vectors. Do not hand-edit
;;;; the hex constants; regenerate from the reference file instead
;;;; (hand transcription produced real errors the extraction caught).

(def-suite :bip324-crypto-tests
  :description "BIP324 cipher suite vs Bitcoin Core crypto test vectors"
  :in :bitcoin-lisp-tests)

(in-suite :bip324-crypto-tests)

(defun %bc-hex (hex) (bitcoin-lisp.crypto:hex-to-bytes hex))
(defun %bc-buf (n) (make-array n :element-type '(unsigned-byte 8) :initial-element 0))

(defun %check-chacha20 (msg-hex key-hex nonce1 nonce2 seek out-hex)
  "Core's TestChaCha20: keystream when MSG-HEX is empty, else crypt MSG; then
re-run split into fragments to exercise the one-block output buffer."
  (let* ((key (%bc-hex key-hex))
         (msg (%bc-hex msg-hex))
         (expect (%bc-hex out-hex))
         (n (length expect))
         (out (%bc-buf n))
         (c (bitcoin-lisp.crypto::make-chacha20 key)))
    (bitcoin-lisp.crypto::chacha20-seek c nonce1 nonce2 seek)
    (if (plusp (length msg))
        (bitcoin-lisp.crypto::chacha20-crypt c msg out)
        (bitcoin-lisp.crypto::chacha20-keystream c out))
    (is (equalp expect out))
    ;; Fragmented re-runs at deterministic split points.
    (dolist (cut (remove-duplicates
                  (list 1 (floor n 3) (max 1 (- n 2)) (floor n 2))))
      (when (< 0 cut n)
        (bitcoin-lisp.crypto::chacha20-seek c nonce1 nonce2 seek)
        (fill out 0)
        (if (plusp (length msg))
            (progn (bitcoin-lisp.crypto::chacha20-crypt c msg out :end cut)
                   (bitcoin-lisp.crypto::chacha20-crypt c msg out :start cut))
            (progn (bitcoin-lisp.crypto::chacha20-keystream c out :end cut)
                   (bitcoin-lisp.crypto::chacha20-keystream c out :start cut)))
        (is (equalp expect out))))))

(defun %check-poly1305 (msg-hex key-hex tag-hex)
  (let ((mac (ironclad:make-mac :poly1305 (%bc-hex key-hex))))
    (ironclad:update-mac mac (%bc-hex msg-hex))
    (is (string= tag-hex (bitcoin-lisp.crypto:bytes-to-hex (ironclad:produce-mac mac))))))

(defun %check-aead (plain-hex aad-hex key-hex nonce1 nonce2 cipher-hex)
  (let* ((plain (%bc-hex plain-hex))
         (aad (%bc-hex aad-hex))
         (key (%bc-hex key-hex))
         (expect (%bc-hex cipher-hex))
         (n (length plain))
         (cipher (%bc-buf (+ n 16)))
         (aead (bitcoin-lisp.crypto::make-aead-chacha20-poly1305 key)))
    ;; Single-segment encrypt.
    (bitcoin-lisp.crypto::aead-encrypt aead plain aad nonce1 nonce2 cipher)
    (is (equalp expect cipher))
    ;; Split-segment encrypt (plain1/plain2 at the midpoint).
    (let ((k (floor n 2)))
      (fill cipher 0)
      (bitcoin-lisp.crypto::aead-encrypt
       aead (subseq plain 0 k) aad nonce1 nonce2 cipher (subseq plain k))
      (is (equalp expect cipher)))
    ;; Decrypt round-trip.
    (let ((out (%bc-buf n)))
      (is-true (bitcoin-lisp.crypto::aead-decrypt aead cipher aad nonce1 nonce2 out))
      (is (equalp plain out)))
    ;; Keystream XOR property.
    (when (plusp n)
      (let ((ks (%bc-buf n)))
        (bitcoin-lisp.crypto::aead-keystream aead nonce1 nonce2 ks)
        (is (loop for i below n
                  always (= (logxor (aref plain i) (aref ks i)) (aref expect i))))))
    ;; Tampered tag must fail.
    (let ((bad (copy-seq cipher))
          (out (%bc-buf n)))
      (setf (aref bad (1- (length bad))) (logxor (aref bad (1- (length bad))) 1))
      (is-false (bitcoin-lisp.crypto::aead-decrypt aead bad aad nonce1 nonce2 out)))))

(defun %check-fschacha20 (plain-hex key-hex interval expect-hex)
  "Crypt the same plaintext INTERVAL+1 times; the final output (the first
chunk after the automatic rekey) must equal EXPECT-HEX."
  (let* ((plain (%bc-hex plain-hex))
         (fsc (bitcoin-lisp.crypto:make-fschacha20 (%bc-hex key-hex) interval))
         (out (%bc-buf (length plain))))
    (dotimes (i (1+ interval))
      (bitcoin-lisp.crypto:fschacha20-crypt fsc plain out))
    (is (string= expect-hex (bitcoin-lisp.crypto:bytes-to-hex out)))))

(defun %check-fsaead (plain-hex aad-hex key-hex msg-idx cipher-hex)
  "Core's TestFSChaCha20Poly1305: MSG-IDX empty dummy packets seek to the
target position (rekey interval 224, exercising key rotations), then the real
packet must match CIPHER-HEX; an independent receiver decrypts it."
  (let* ((plain (%bc-hex plain-hex))
         (aad (%bc-hex aad-hex))
         (key (%bc-hex key-hex))
         (expect (%bc-hex cipher-hex))
         (n (length plain))
         (dummy (%bc-buf 16))
         (empty (%bc-buf 0))
         (cipher (%bc-buf (+ n 16)))
         (enc (bitcoin-lisp.crypto:make-fschacha20poly1305 key 224))
         (dec (bitcoin-lisp.crypto:make-fschacha20poly1305 key 224)))
    (dotimes (i msg-idx)
      (bitcoin-lisp.crypto:fsaead-encrypt enc empty empty dummy))
    (bitcoin-lisp.crypto:fsaead-encrypt enc plain aad cipher)
    (is (equalp expect cipher))
    ;; Split-segment variant on a fresh instance.
    (when (plusp n)
      (let ((enc2 (bitcoin-lisp.crypto:make-fschacha20poly1305 key 224))
            (k (floor n 2)))
        (dotimes (i msg-idx)
          (bitcoin-lisp.crypto:fsaead-encrypt enc2 empty empty dummy))
        (fill cipher 0)
        (bitcoin-lisp.crypto:fsaead-encrypt
         enc2 (subseq plain 0 k) aad cipher (subseq plain k))
        (is (equalp expect cipher))))
    ;; Receiver side: dummy decrypts fail authentication but still advance
    ;; the packet counter, mirroring Core.
    (fill dummy 0)
    (dotimes (i msg-idx)
      (bitcoin-lisp.crypto:fsaead-decrypt dec dummy empty empty))
    (let ((out (%bc-buf n)))
      (is-true (bitcoin-lisp.crypto:fsaead-decrypt dec expect aad out))
      (is (equalp plain out)))))

(defun %check-hkdf (ikm-hex salt-hex info-hex okm-hex)
  (let* ((prk (bitcoin-lisp.crypto:hkdf-sha256-extract
               (%bc-hex salt-hex) (%bc-hex ikm-hex)))
         (okm (bitcoin-lisp.crypto:hkdf-sha256-expand32 prk (%bc-hex info-hex))))
    (is (string= okm-hex (bitcoin-lisp.crypto:bytes-to-hex okm)))))

;;; --- Structural tests (not vector-driven) ---

(test chacha20-midblock
  "Consuming 5+7+52 keystream bytes equals one straight 64-byte block."
  (let* ((key (%bc-buf 32))
         (c1 (bitcoin-lisp.crypto::make-chacha20 key))
         (c2 (bitcoin-lisp.crypto::make-chacha20 key))
         (block (%bc-buf 64))
         (b1 (%bc-buf 5)) (b2 (%bc-buf 7)) (b3 (%bc-buf 52)))
    (bitcoin-lisp.crypto::chacha20-keystream c1 block)
    (bitcoin-lisp.crypto::chacha20-keystream c2 b1)
    (bitcoin-lisp.crypto::chacha20-keystream c2 b2)
    (bitcoin-lisp.crypto::chacha20-keystream c2 b3)
    (is (equalp (subseq block 0 5) b1))
    (is (equalp (subseq block 5 12) b2))
    (is (equalp (subseq block 12 64) b3))))

(test poly1305-mac-of-macs
  "Core's aggregate test: mac over the macs of messages of length 0..255."
  (let ((total (ironclad:make-mac
                :poly1305
                (%bc-hex "01020304050607fffefdfcfbfaf9ffffffffffffffffffffffffffff00000000"))))
    (dotimes (i 256)
      (let ((mac (ironclad:make-mac
                  :poly1305
                  (make-array 32 :element-type '(unsigned-byte 8) :initial-element i))))
        (ironclad:update-mac mac (make-array i :element-type '(unsigned-byte 8)
                                               :initial-element i))
        (ironclad:update-mac total (ironclad:produce-mac mac))))
    (is (string= "64afe2e8d6ad7bbdd287f97c44623d39"
                 (bitcoin-lisp.crypto:bytes-to-hex (ironclad:produce-mac total))))))

;;; --- Machine-extracted vector tests (see file header) ---
(test chacha20-core-vectors
  (%check-chacha20 ""
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    #x09000000 #x000000004A000000 1
    "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e")
  (%check-chacha20 "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e"
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    #x00000000 #x000000004A000000 1
    "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d")
  (%check-chacha20 ""
    "0000000000000000000000000000000000000000000000000000000000000000"
    #x00000000 #x0000000000000000 0
    "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586")
  (%check-chacha20 ""
    "0000000000000000000000000000000000000000000000000000000000000000"
    #x00000000 #x0000000000000000 1
    "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f")
  (%check-chacha20 ""
    "0000000000000000000000000000000000000000000000000000000000000001"
    #x00000000 #x0000000000000000 1
    "3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a0")
  (%check-chacha20 ""
    "00ff000000000000000000000000000000000000000000000000000000000000"
    #x00000000 #x0000000000000000 2
    "72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbea1ae9af0ca13b25aa26cb4a648cb9b9d1be65b2c0924a66c54d545ec1b7374f4872e99f096")
  (%check-chacha20 ""
    "0000000000000000000000000000000000000000000000000000000000000000"
    #x00000000 #x0200000000000000 0
    "c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c78a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d")
  (%check-chacha20 "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    #x00000000 #x0000000000000000 0
    "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586")
  (%check-chacha20 "416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f"
    "0000000000000000000000000000000000000000000000000000000000000001"
    #x00000000 #x0200000000000000 1
    "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e52795042bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85ad00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221")
  (%check-chacha20 "2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e"
    "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0"
    #x00000000 #x0200000000000000 42
    "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553ebf39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f7704c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1")
  (%check-chacha20 ""
    "0000000000000000000000000000000000000000000000000000000000000000"
    #x00000000 #x0000000000000000 0
    "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7")
  (%check-chacha20 ""
    "0000000000000000000000000000000000000000000000000000000000000001"
    #x00000000 #x0200000000000000 0
    "ecfa254f845f647473d3cb140da9e87606cb33066c447b87bc2666dde3fbb739")
  (%check-chacha20 ""
    "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0"
    #x00000000 #x0200000000000000 0
    "965e3bc6f9ec7ed9560808f4d229f94b137ff275ca9b3fcbdd59deaad23310ae")
  (%check-chacha20 "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e"
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    #x00000000 #x000000004A000000 1
    "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d")
  (%check-chacha20 ""
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    #x00000000 #x000000004A000000 1
    "224f51f3401bd9e12fde276fb8631ded8c131f823d2c06e27e4fcaec9ef3cf788a3b0aa372600a92b57974cded2b9334794cba40c63e34cdea212c4cf07d41b769a6749f3f630f4122cafe28ec4dc47e26d4346d70b98c73f3e9c53ac40c5945398b6eda1a832c89c167eacd901d7e2bf363")
  (%check-chacha20 ""
    "0000000000000000000000000000000000000000000000000000000000000000"
    #x00000000 #x0000000000000000 0
    "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586")
  (%check-chacha20 ""
    "0000000000000000000000000000000000000000000000000000000000000001"
    #x00000000 #x0000000000000000 0
    "4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952ed432d41bbe2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea817e9ad275ae546963")
  (%check-chacha20 ""
    "0000000000000000000000000000000000000000000000000000000000000000"
    #x00000000 #x0100000000000000 0
    "de9cba7bf3d69ef5e786dc63973f653a0b49e015adbff7134fcb7df137821031e85a050278a7084527214f73efc7fa5b5277062eb7a0433e445f41e3")
  (%check-chacha20 ""
    "0000000000000000000000000000000000000000000000000000000000000000"
    #x00000000 #x0000000000000001 0
    "ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd138e50d32111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d6bbdb0041b2f586b")
  (%check-chacha20 ""
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    #x00000000 #x0706050403020100 0
    "f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a38008b9a26bc35941e2444177c8ade6689de95264986d95889fb60e84629c9bd9a5acb1cc118be563eb9b3a4a472f82e09a7e778492b562ef7130e88dfe031c79db9d4f7c7a899151b9a475032b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c507b138db853e3d6959660996546cc9c4a6eafdc777c040d70eaf46f76dad3979e5c5360c3317166a1c894c94a371876a94df7628fe4eaaf2ccb27d5aaae0ad7ad0f9d4b6ad3b54098746d4524d38407a6deb3ab78fab78c9")
  (%check-chacha20 ""
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    #x00000000 #xDEADBEEF12345678 4294967295
    "2d292c880513397b91221c3a647cfb0765a4815894715f411e3df5e0dd0ba9dffd565dea5addbdb914208fde7950f23e0385f9a727143f6a6ac51d84b1c0fb3e2e3b00b63d6841a1cc6d1538b1d3a74bef1eb2f54c7b7281e36e484dba89b351c8f572617e61e342879f211b0e4c515df50ea9d0771518fad96cd0baee62deb6")
)

(test fschacha20-rekey-vectors
  (%check-fschacha20
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    "0000000000000000000000000000000000000000000000000000000000000000"
    256
    "a93df4ef03011f3db95f60d996e1785df5de38fc39bfcb663a47bb5561928349")
  (%check-fschacha20
    "01"
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    5
    "ea")
  (%check-fschacha20
    "e93fdb5c762804b9a706816aca31e35b11d2aa3080108ef46a5b1f1508819c0a"
    "8ec4c3ccdaea336bdeb245636970be01266509b33f3d2642504eaf412206207a"
    4096
    "8bfaa4eacff308fdb4a94a5ff25bd9d0c1f84b77f81239f67ff39d6e1ac280c9")
)

(test poly1305-vectors
  (%check-poly1305
    "43727970746f6772617068696320466f72756d2052657365617263682047726f7570"
    "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"
    "a8061dc1305136c6c22b8baf0c0127a9")
  (%check-poly1305
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000")
  (%check-poly1305
    "416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f"
    "0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e"
    "36e5f6b5c5e06070f0efca96227a863e")
  (%check-poly1305
    "416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f"
    "36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000"
    "f3477e7cd95417af89a6b8794c310cf0")
  (%check-poly1305
    "2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e"
    "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0"
    "4541669a7eaaee61e708dc7cbcc5eb62")
  (%check-poly1305
    "ffffffffffffffffffffffffffffffff"
    "0200000000000000000000000000000000000000000000000000000000000000"
    "03000000000000000000000000000000")
  (%check-poly1305
    "02000000000000000000000000000000"
    "02000000000000000000000000000000ffffffffffffffffffffffffffffffff"
    "03000000000000000000000000000000")
  (%check-poly1305
    "fffffffffffffffffffffffffffffffff0ffffffffffffffffffffffffffffff11000000000000000000000000000000"
    "0100000000000000000000000000000000000000000000000000000000000000"
    "05000000000000000000000000000000")
  (%check-poly1305
    "fffffffffffffffffffffffffffffffffbfefefefefefefefefefefefefefefe01010101010101010101010101010101"
    "0100000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000")
  (%check-poly1305
    "fdffffffffffffffffffffffffffffff"
    "0200000000000000000000000000000000000000000000000000000000000000"
    "faffffffffffffffffffffffffffffff")
  (%check-poly1305
    "e33594d7505e43b900000000000000003394d7505e4379cd01000000000000000000000000000000000000000000000001000000000000000000000000000000"
    "0100000000000000040000000000000000000000000000000000000000000000"
    "14000000000000005500000000000000")
  (%check-poly1305
    "e33594d7505e43b900000000000000003394d7505e4379cd010000000000000000000000000000000000000000000000"
    "0100000000000000040000000000000000000000000000000000000000000000"
    "13000000000000000000000000000000")
  (%check-poly1305
    "8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74e355a5"
    "eea6a7251c1e72916d11c2cb214d3c252539121d8e234e652d651fa4c8cff880"
    "f3ffc7703f9400e52a7dfb4b3d3305d9")
  (%check-poly1305
    "000000000000000000000094000000000000b07c4300000000002c002600d50000000000000000000000000000bc58000000000000000000c9000000dd00000000000000000000d34c000000000000000000000000f9009100000000000000c24b0000e900000000000000000000000000000000000e000000270000740000000000000003000000000000f1000000000000dce20000000000000039000000000000000000000000000000000000000000000000000000520000000000000000000000000000000000000000009500000000000000000000000000cf00826700000000a9000000000000000000000000000000000000000000790000000000000000de0000004c000000000033000000000000000000000000002800aa00000000003300860000e000000000"
    "6e543496db3cf677592989891ab021f58390feb84fb419fbc7bb516a60bfa302"
    "7ea80968354d40d9d790b45310caf7f3")
  (%check-poly1305
    "0000005900000000c40000002f000000000000000000000000000000296900000000e8000037000000000000000000000000000b000000000000000000000000000000000000000000000000001800006e0000000000a400000000000000000000000000000000004d00000000000000b0000000000000000000005a000000000000000000b7c300000000000000540000000000000000000000000a0000000000005b0000000000000000000000000000000000002d00e70000000000000000000000000000003400006800d70000000000000000000036000000000000000000eb00000000000000000000000000000000000000000000000000002800000037000000000000000000000000000000000000000000000000000000008f0000000000000000000000000000"
    "f0b659a4f3143d8a1e1dacb9a409fe7e7cd501dfb58b16a2623046c5d337922a"
    "0e410fa9d7a40ac582e77546be9a72bb")
)

(test aead-chacha20poly1305-vectors
  (%check-aead
    "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e"
    "50515253c0c1c2c3c4c5c6c7"
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
    #x00000007 #x4746454443424140
    "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691")
  (%check-aead
    "496e7465726e65742d4472616674732061726520647261667420646f63756d656e74732076616c696420666f722061206d6178696d756d206f6620736978206d6f6e74687320616e64206d617920626520757064617465642c207265706c616365642c206f72206f62736f6c65746564206279206f7468657220646f63756d656e747320617420616e792074696d652e20497420697320696e617070726f70726961746520746f2075736520496e7465726e65742d447261667473206173207265666572656e6365206d6174657269616c206f7220746f2063697465207468656d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67726573732e2fe2809d"
    "f33388860000000000004e91"
    "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0"
    #x00000000 #x0807060504030201
    "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c8559797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523eaf4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a1049e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29a6ad5cb4022b02709beead9d67890cbb22392336fea1851f38")
  (%check-aead
    "8d2d6a8befd9716fab35819eaac83b33269afb9f1a00fddf66095a6c0cd91951a6b7ad3db580be0674c3f0b55f618e34"
    ""
    "72ddc73f07101282bbbcf853b9012a9f9695fc5d36b303a97fd0845d0314e0c3"
    #x3432B75F #xB3585537EB7F4024
    "f760b8224fb2a317b1b07875092606131232a5b86ae142df5df1c846a7f6341af2564483dd77f836be45e6230808ffe402a6f0a3e8be074b3d1f4ea8a7b09451")
  (%check-aead
    ""
    "36970d8a704c065de16250c18033de5a400520ac1b5842b24551e5823a3314f3946285171e04a81ebfbe3566e312e74ab80e94c7dd2ff4e10de0098a58d0f503"
    "77adda51d6730b9ad6c995658cbd49f581b2547e7c0c08fcc24ceec797461021"
    #x1F90DA88 #x75DAFA3EF84471A4
    "aaae5bb81e8407c94b2ae86ae0c7efbe")
)

(test fschacha20poly1305-rekey-vectors
  (%check-fsaead
    "d6a4cb04ef0f7c09c1866ed29dc24d820e75b0491032a51b4c3366f9ca35c19ea3047ec6be9d45f9637b63e1cf9eb4c2523a5aab7b851ebeba87199db0e839cf0d5c25e50168306377aedbe9089fd2463ded88b83211cf51b73b150608cc7a600d0f11b9a742948482e1b109d8faf15b450aa7322e892fa2208c6691e3fecf4c711191b14d75a72147"
    "786cb9b6ebf44288974cf0"
    "5c9e1c3951a74fba66708bf9d2c217571684556b6a6a3573bff2847d38612654"
    500
    "9dcebbd3281ea3dd8e9a1ef7d55a97abd6743e56ebc0c190cb2c4e14160b385e0bf508dddf754bd02c7c208447c131ce23e47a4a14dfaf5dd8bc601323950f754e05d46e9232f83fc5120fbbef6f5347a826ec79a93820718d4ec7a2b7cfaaa44b21e16d726448b62f803811aff4f6d827ed78e738ce8a507b81a8ae131311928039213de18a5120dc9b7370baca878f50ff254418de3da50c")
  (%check-fsaead
    "8349b7a2690b63d01204800c288ff1138a1d473c832c90ea8b3fc102d0bb3adc44261b247c7c3d6760bfbe979d061c305f46d94c0582ac3099f0bf249f8cb234"
    ""
    "3bd2093fcbcb0d034d8c569583c5425c1a53171ea299f8cc3bbf9ae3530adfce"
    60000
    "30a6757ff8439b975363f166a0fa0e36722ab35936abd704297948f45083f4d499433137ce931f7fca28a0acd3bc30f57b550acbc21cbd45bbef0739d9caf30c14b94829deb27f0b1923a2af704ae5d6")
)

(test hkdf-sha256-32-vectors
  (%check-hkdf
    "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
    "000102030405060708090a0b0c"
    "f0f1f2f3f4f5f6f7f8f9"
    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")
  (%check-hkdf
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
    "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
    "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c")
  (%check-hkdf
    "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
    ""
    ""
    "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d")
)

;;; --- ElligatorSwift (BIP324 key exchange) ---
;;;
;;; Gated on ellswift-available-p: distro libsecp256k1 builds may lack the
;;; module (the test-bitcoin-server system lib does), in which case these
;;; skip rather than fail — the v2 transport degrades to v1 the same way.

(defun %ellswift-vectors-path ()
  (merge-pathnames
   "refs/bitcoin/test/functional/test_framework/crypto/ellswift_decode_test_vectors.csv"
   (asdf:system-source-directory :bitcoin-lisp)))

(test ellswift-decode-core-vectors
  "All 76 decode vectors from Core's ellswift_decode_test_vectors.csv:
decode the 64-byte encoding, serialize compressed, compare the x coordinate."
  (if (not (bitcoin-lisp.crypto:ellswift-available-p))
      (skip "libsecp256k1 lacks the ellswift module")
      (let ((path (%ellswift-vectors-path)))
        (if (not (probe-file path))
            (skip "refs/bitcoin clone not present")
            (with-open-file (stream path)
              (read-line stream)      ; header
              (loop for line = (read-line stream nil)
                    while line
                    for comma1 = (position #\, line)
                    for comma2 = (position #\, line :start (1+ comma1))
                    for ell = (%bc-hex (subseq line 0 comma1))
                    for x-hex = (subseq line (1+ comma1) comma2)
                    for pubkey = (bitcoin-lisp.crypto:ellswift-decode ell)
                    do (is (string= x-hex
                                    (bitcoin-lisp.crypto:bytes-to-hex
                                     (subseq pubkey 1)))
                           "x mismatch for ~A" (subseq line 0 8))))))))

(test ellswift-create-decode-roundtrip
  "ellswift-create's encoding decodes back to the secret key's public key,
with and without auxiliary randomness, and distinct aux gives distinct
encodings of the same key."
  (if (not (bitcoin-lisp.crypto:ellswift-available-p))
      (skip "libsecp256k1 lacks the ellswift module")
      (dolist (priv-hex '("0000000000000000000000000000000000000000000000000000000000000001"
                          "00000000000000000000000000000000000000000000000000000000deadbeef"
                          "e93fdb5c762804b9a706816aca31e35b11d2aa3080108ef46a5b1f1508819c0a"))
        (let* ((priv (%bc-hex priv-hex))
               (expected (bitcoin-lisp.crypto:derive-public-key priv))
               (aux (%bc-buf 32))
               (ell-plain (bitcoin-lisp.crypto:ellswift-create priv)))
          (is-true ell-plain)
          (is (= 64 (length ell-plain)))
          (is (equalp expected (bitcoin-lisp.crypto:ellswift-decode ell-plain)))
          (fill aux 7)
          (let ((ell-aux (bitcoin-lisp.crypto:ellswift-create priv aux)))
            (is (equalp expected (bitcoin-lisp.crypto:ellswift-decode ell-aux)))
            ;; Different entropy -> different encoding of the same key.
            (is-false (equalp ell-plain ell-aux)))))))

(test bip324-ecdh-symmetry
  "Initiator and responder derive the same 32-byte shared secret; a third
party or a role mix-up does not."
  (if (not (bitcoin-lisp.crypto:ellswift-available-p))
      (skip "libsecp256k1 lacks the ellswift module")
      (let* ((priv-a (%bc-hex "1111111111111111111111111111111111111111111111111111111111111111"))
             (priv-b (%bc-hex "2222222222222222222222222222222222222222222222222222222222222222"))
             (priv-c (%bc-hex "3333333333333333333333333333333333333333333333333333333333333333"))
             (ell-a (bitcoin-lisp.crypto:ellswift-create priv-a))
             (ell-b (bitcoin-lisp.crypto:ellswift-create priv-b))
             ;; A initiates to B.
             (secret-a (bitcoin-lisp.crypto:bip324-ecdh ell-b ell-a priv-a t))
             (secret-b (bitcoin-lisp.crypto:bip324-ecdh ell-a ell-b priv-b nil)))
        (is (= 32 (length secret-a)))
        (is (equalp secret-a secret-b))
        ;; Wrong key: C using its key over A/B's encodings gets a different secret.
        (is-false (equalp secret-a
                          (bitcoin-lisp.crypto:bip324-ecdh ell-a ell-b priv-c nil)))
        ;; Role mix-up: both claiming initiator diverges.
        (is-false (equalp secret-a
                          (bitcoin-lisp.crypto:bip324-ecdh ell-a ell-b priv-b t))))))

(test bip324-ecdh-pinned-vectors
  "Exactness against the pure-Python reference (Core test_framework
ellswift_ecdh_xonly + TaggedHash, independent of libsecp256k1): fixed key
and fixed arbitrary 64-byte encodings, both roles. The 'ours' encoding only
enters the tagged hash, so no key correspondence is required."
  (if (not (bitcoin-lisp.crypto:ellswift-available-p))
      (skip "libsecp256k1 lacks the ellswift module")
      (let ((priv (%bc-hex "1111111111111111111111111111111111111111111111111111111111111111"))
            (theirs (make-array 64 :element-type '(unsigned-byte 8) :initial-element #xAA))
            (ours (make-array 64 :element-type '(unsigned-byte 8) :initial-element #xBB)))
        (is (string= "44ea2116a4c8badb83785c77ab0fb13917e022a0e04c42d9b102013d93ac7647"
                     (bitcoin-lisp.crypto:bytes-to-hex
                      (bitcoin-lisp.crypto:bip324-ecdh theirs ours priv t))))
        (is (string= "6cfd97979551cc7aeb682c4067d34f985f5e366eb49f69777e93cfc09292a627"
                     (bitcoin-lisp.crypto:bytes-to-hex
                      (bitcoin-lisp.crypto:bip324-ecdh theirs ours priv nil)))))))

;;; --- BIP324Cipher packet vectors ---

(defparameter *bip324-mainnet-magic*
  (coerce #(#xf9 #xbe #xb4 #xd9) '(simple-array (unsigned-byte 8) (*)))
  "Mainnet message start bytes: Core's bip324_tests.cpp vectors run under
BasicTestingSetup, which selects mainnet chain params.")

(defun %check-bip324-packet (idx priv-hex ours-hex theirs-hex initiating
                             contents-hex multiply aad-hex ignore
                             send-garbage-hex recv-garbage-hex session-id-hex
                             ciphertext-hex ciphertext-endswith-hex)
  "Mirror of Core's TestBIP324PacketVector: initialize from a fixed key and
fixed ellswift encodings, check session id + garbage terminators, seek IDX
dummy packets, encrypt CONTENTS x MULTIPLY with AAD/IGNORE, compare the
ciphertext (or its tail for long messages); then a self-decrypting instance
seeks the same way, decrypts it back, and rejects tampered copies."
  (let* ((priv (%bc-hex priv-hex))
         (ours (%bc-hex ours-hex))
         (theirs (%bc-hex theirs-hex))
         (base (%bc-hex contents-hex))
         (aad (%bc-hex aad-hex))
         (send-garbage (%bc-hex send-garbage-hex))
         (recv-garbage (%bc-hex recv-garbage-hex))
         (session-id (%bc-hex session-id-hex))
         (expect-ct (%bc-hex ciphertext-hex))
         (expect-tail (%bc-hex ciphertext-endswith-hex))
         (contents (let ((v (%bc-buf (* multiply (length base)))))
                     (dotimes (i multiply v)
                       (replace v base :start1 (* i (length base))))))
         (enc (bitcoin-lisp.crypto:make-bip324-cipher priv :our-ell64 ours))
         (dummies '()))
    (is-false (bitcoin-lisp.crypto:bip324-cipher-initialized-p enc))
    (is (equalp ours (bitcoin-lisp.crypto:bip324-cipher-our-pubkey enc)))
    (bitcoin-lisp.crypto:bip324-cipher-initialize enc theirs initiating
                                                  *bip324-mainnet-magic*)
    (is-true (bitcoin-lisp.crypto:bip324-cipher-initialized-p enc))
    (is (equalp session-id (bitcoin-lisp.crypto:bip324-cipher-session-id enc)))
    (is (equalp send-garbage
                (bitcoin-lisp.crypto:bip324-cipher-send-garbage-terminator enc)))
    (is (equalp recv-garbage
                (bitcoin-lisp.crypto:bip324-cipher-recv-garbage-terminator enc)))
    ;; Seek to the numbered packet with empty decoy packets.
    (dotimes (i idx)
      (push (bitcoin-lisp.crypto:bip324-cipher-encrypt enc (%bc-buf 0) (%bc-buf 0) t)
            dummies))
    (setf dummies (nreverse dummies))
    (let ((ciphertext (bitcoin-lisp.crypto:bip324-cipher-encrypt enc contents aad ignore)))
      (if (plusp (length expect-ct))
          (is (equalp expect-ct ciphertext))
          (progn
            (is (>= (length ciphertext) (length expect-tail)))
            (is (equalp expect-tail
                        (subseq ciphertext (- (length ciphertext)
                                              (length expect-tail)))))))
      ;; Self-decrypting instance: same key/role, send<->recv swapped.
      (flet ((make-decryptor ()
               (let ((dec (bitcoin-lisp.crypto:make-bip324-cipher priv :our-ell64 ours)))
                 (bitcoin-lisp.crypto:bip324-cipher-initialize
                  dec theirs initiating *bip324-mainnet-magic* :self-decrypt t)
                 (is (equalp session-id (bitcoin-lisp.crypto:bip324-cipher-session-id dec)))
                 (dolist (d dummies)
                   (bitcoin-lisp.crypto:bip324-cipher-decrypt-length dec (subseq d 0 3))
                   (bitcoin-lisp.crypto:bip324-cipher-decrypt dec (subseq d 3) (%bc-buf 0)))
                 dec)))
        ;; Successful decrypt round-trip.
        (let* ((dec (make-decryptor))
               (len (bitcoin-lisp.crypto:bip324-cipher-decrypt-length
                     dec (subseq ciphertext 0 3))))
          (is (= (length contents) len))
          (multiple-value-bind (plain dec-ignore)
              (bitcoin-lisp.crypto:bip324-cipher-decrypt dec (subseq ciphertext 3) aad)
            (is-true plain)
            (when plain
              (is (equalp contents plain))
              (is (eq (and ignore t) (and dec-ignore t))))))
        ;; A flipped ciphertext bit must fail authentication.
        (let* ((dec (make-decryptor))
               (bad (copy-seq ciphertext)))
          (setf (aref bad (+ 3 (mod 5 (- (length bad) 3))))
                (logxor (aref bad (+ 3 (mod 5 (- (length bad) 3)))) 1))
          (bitcoin-lisp.crypto:bip324-cipher-decrypt-length dec (subseq bad 0 3))
          (is-false (bitcoin-lisp.crypto:bip324-cipher-decrypt dec (subseq bad 3) aad)))
        ;; Damaged AAD must fail authentication.
        (when (plusp (length aad))
          (let ((dec (make-decryptor))
                (bad-aad (copy-seq aad)))
            (setf (aref bad-aad 0) (logxor (aref bad-aad 0) 1))
            (bitcoin-lisp.crypto:bip324-cipher-decrypt-length dec (subseq ciphertext 0 3))
            (is-false (bitcoin-lisp.crypto:bip324-cipher-decrypt
                       dec (subseq ciphertext 3) bad-aad))))))))
(test bip324-cipher-core-vectors
  "The official BIP324 packet vectors from Core bip324_tests.cpp (mainnet magic)."
  (if (not (bitcoin-lisp.crypto:ellswift-available-p))
      (skip "libsecp256k1 lacks the ellswift module")
      (progn
  (%check-bip324-packet 1
    "61062ea5071d800bbfd59e2e8b53d47d194b095ae5a4df04936b49772ef0d4d7"
    "ec0adff257bbfe500c188c80b4fdd640f6b45a482bbc15fc7cef5931deff0aa186f6eb9bba7b85dc4dcc28b28722de1e3d9108b985e2967045668f66098e475b"
    "a4a94dfce69b4a2a0a099313d10f9f7e7d649d60501c9e1d274c300e0d89aafaffffffffffffffffffffffffffffffffffffffffffffffffffffffff8faf88d5"
    t
    "8e"
    1
    ""
    nil
    "faef555dfcdb936425d84aba524758f3"
    "02cb8ff24307a6e27de3b4e7ea3fa65b"
    "ce72dffb015da62b0d0f5474cab8bc72605225b0cee3f62312ec680ec5f41ba5"
    "7530d2a18720162ac09c25329a60d75adf36eda3c3"
    "")
  (%check-bip324-packet 999
    "6f312890ec83bbb26798abaadd574684a53e74ccef7953b790fcc29409080246"
    "a8785af31c029efc82fa9fc677d7118031358d7c6a25b5779a9b900e5ccd94aac97eb36a3c5dbcdb2ca5843cc4c2fe0aaa46d10eb3d233a81c3dde476da00eef"
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f0000000000000000000000000000000000000000000000000000000000000000"
    nil
    "3eb1d4e98035cfd8eeb29bac969ed3824a"
    1
    ""
    nil
    "44737108aec5f8b6c1c277b31bbce9c1"
    "ca29b3a35237f8212bd13ed187a1da2e"
    "b0490e26111cb2d55bbff2ace00f7f644f64006539abb4e7513f05107bb10608"
    "d78adbcba0eebfb15cfbd8142c84dc729d233d0dc11b1d851e46a114122b8d5b96b7d59317"
    "")
  (%check-bip324-packet 0
    "846a784f1a03dea59cc679754a60a7145542fa130e3efbd815c81e909ce32933"
    "480eacf1536b52257bf8ce78d8f4ce09395d744767c6c129e7838947ee625af3245592c111275e877d5baae22584cb5f1153e67c16bcd7da767726cd0d0c846a"
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff22d5e441524d571a52b3def126189d3f416890a99d4da6ede2b0cde1760ce2c3f98457ae"
    t
    "054290a6c6ba8d80478172e89d32bf690913ae9835de6dcf206ff1f4d652286fe0ddf74deba41d55de3edc77c42a32af79bbea2c00bae7492264c60866ae5a"
    1
    "84932a55aac22b51e7b128d31d9f0550da28e6a3f394224707d878603386b2f9d0c6bcd8046679bfed7b68c517e7431e75d9dd34605727d2ef1c2babbf680ecc8d68d2c4886e9953a4034abde6da4189cd47c6bb3192242cf714d502ca6103ee84e08bc2ca4fd370d5ad4e7d06c7fbf496c6c7cc7eb19c40c61fb33df2a9ba48497a96c98d7b10c1f91098a6b7b16b4bab9687f27585ade1491ae0dba6a79e1e2d85dd9d9d45c5135ca5fca3f0f99a60ea39edbc9efc7923111c937913f225d67788d5f7e8852b697e26b92ec7bfcaa334a1665511c2b4c0a42d06f7ab98a9719516c8fd17f73804555ee84ab3b7d1762f6096b778d3cb9c799cbd49a9e4a325197b4e6cc4a5c4651f8b41ff88a92ec428354531f970263b467c77ed11312e2617d0d53fe9a8707f51f9f57a77bfb49afe3d89d85ec05ee17b9186f360c94ab8bb2926b65ca99dae1d6ee1af96cad09de70b6767e949023e4b380e66669914a741ed0fa420a48dbc7bfae5ef2019af36d1022283dd90655f25eec7151d471265d22a6d3f91dc700ba749bb67c0fe4bc0888593fbaf59d3c6fff1bf756a125910a63b9682b597c20f560ecb99c11a92c8c8c3f7fbfaa103146083a0ccaecf7a5f5e735a784a8820155914a289d57d8141870ffcaf588882332e0bcd8779efa931aa108dab6c3cce76691e345df4a91a03b71074d66333fd3591bff071ea099360f787bbe43b7b3dff2a59c41c7642eb79870222ad1c6f2e5a191ed5acea51134679587c9cf71c7d8ee290be6bf465c4ee47897a125708704ad610d8d00252d01959209d7cd04d5ecbbb1419a7e84037a55fefa13dee464b48a35c96bcb9a53e7ed461c3a1607ee00c3c302fd47cd73fda7493e947c9834a92d63dcfbd65aa7c38c3e3a2748bb5d9a58e7495d243d6b741078c8f7ee9c8813e473a323375702702b0afae1550c8341eedf5247627343a95240cb02e3e17d5dca16f8d8d3b2228e19c06399f8ec5c5e9dbe4caef6a0ea3ffb1d3c7eac03ae030e791fa12e537c80d56b55b764cadf27a8701052df1282ba8b5e3eb62b5dc7973ac40160e00722fa958d95102fc25c549d8c0e84bed95b7acb61ba65700c4de4feebf78d13b9682c52e937d23026fb4c6193e6644e2d3c99f91f4f39a8b9fc6d013f89c3793ef703987954dc0412b550652c01d922f525704d32d70d6d4079bc3551b563fb29577b3aecdc9505011701dddfd94830431e7a4918927ee44fb3831ce8c4513839e2deea1287f3fa1ab9b61a256c09637dbc7b4f0f8fbb783840f9c24526da883b0df0c473cf231656bd7bc1aaba7f321fec0971c8c2c3444bff2f55e1df7fea66ec3e440a612db9aa87bb505163a59e06b96d46f50d8120b92814ac5ab146bc78dbbf91065af26107815678ce6e33812e6bf3285d4ef3b7b04b076f21e7820dcbfdb4ad5218cf4ff6a65812d8fcb98ecc1e95e2fa58e3efe4ce26cd0bd400d6036ab2ad4f6c713082b5e3f1e04eb9e3b6c8f63f57953894b9e220e0130308e1fd91f72d398c1e7962ca2c31be83f31d6157633581a0a6910496de8d55d3d07090b6aa087159e388b7e7dec60f5d8a60d93ca2ae91296bd484d916bfaaa17c8f45ea4b1a91b37c82821199a2b7596672c37156d8701e7352aa48671d3b1bbbd2bd5f0a2268894a25b0cb2514af39c8743f8cce8ab4b523053739fd8a522222a09acf51ac704489cf17e4b7125455cb8f125b4d31af1eba1f8cf7f81a5a100a141a7ee72e8083e065616649c241f233645c5fc865d17f0285f5c52d9f45312c979bfb3ce5f2a1b951deddf280ffb3f370410cffd1583bfa90077835aa201a0712d1dcd1293ee177738b14e6b5e2a496d05220c3253bb6578d6aff774be91946a614dd7e879fb3dcf7451e0b9adb6a8c44f53c2c464bcc0019e9fad89cac7791a0a3f2974f759a9856351d4d2d7c5612c17cfc50f8479945df57716767b120a590f4bf656f4645029a525694d8a238446c5f5c2c1c995c09c1405b8b1eb9e0352ffdf766cc964f8dcf9f8f043dfab6d102cf4b298021abd78f1d9025fa1f8e1d710b38d9d1652f2d88d1305874ec41609b6617b65c5adb19b6295dc5c5da5fdf69f28144ea12f17c3c6fcce6b9b5157b3dfc969d6725fa5b098a4d9b1d31547ed4c9187452d281d0a5d456008caf1aa251fac8f950ca561982dc2dc908d3691ee3b6ad3ae3d22d002577264ca8e49c523bd51c4846be0d198ad9407bf6f7b82c79893eb2c05fe9981f687a97a4f01fe45ff8c8b7ecc551135cd960a0d6001ad35020be07ffb53cb9e731522ca8ae9364628914b9b8e8cc2f37f03393263603cc2b45295767eb0aac29b0930390eb89587ab2779d2e3decb8042acece725ba42eda650863f418f8d0d50d104e44fbbe5aa7389a4a144a8cecf00f45fb14c39112f9bfb56c0acbd44fa3ff261f5ce4acaa5134c2c1d0cca447040820c81ab1bcdc16aa075b7c68b10d06bbb7ce08b5b805e0238f24402cf24a4b4e00701935a0c68add3de090903f9b85b153cb179a582f57113bfc21c2093803f0cfa4d9d4672c2b05a24f7e4c34a8e9101b70303a7378b9c50b6cddd46814ef7fd73ef6923feceab8fc5aa8b0d185f2e83c7a99dcb1077c0ab5c1f5d5f01ba2f0420443f75c4417db9ebf1665efbb33dca224989920a64b44dc26f682cc77b4632c8454d49135e52503da855bc0f6ff8edc1145451a9772c06891f41064036b66c3119a0fc6e80dffeb65dc456108b7ca0296f4175fff3ed2b0f842cd46bd7e86f4c62dfaf1ddbf836263c00b34803de164983d0811cebfac86e7720c726d3048934c36c23189b02386a722ca9f0fe00233ab50db928d3bccea355cc681144b8b7edcaae4884d5a8f04425c0890ae2c74326e138066d8c05f4c82b29df99b034ea727afde590a1f2177ace3af99cfb1729d6539ce7f7f7314b046aab74497e63dd399e1f7d5f16517c23bd830d1fdee810f3c3b77573dd69c4b97d80d71fb5a632e00acdfa4f8e829faf3580d6a72c40b28a82172f8dcd4627663ebf6069736f21735fd84a226f427cd06bb055f94e7c92f31c48075a2955d82a5b9d2d0198ce0d4e131a112570a8ee40fb80462a81436a58e7db4e34b6e2c422e82f934ecda9949893da5730fc5c23c7c920f363f85ab28cc6a4206713c3152669b47efa8238fa826735f17b4e78750276162024ec85458cd5808e06f40dd9fd43775a456a3ff6cae90550d76d8b2899e0762ad9a371482b3e38083b1274708301d6346c22fea9bb4b73db490ff3ab05b2f7f9e187adef139a7794454b7300b8cc64d3ad76c0e4bc54e08833a4419251550655380d675bc91855aeb82585220bb97f03e976579c08f321b5f8f70988d3061f41465517d53ac571dbf1b24b94443d2e9a8e8a79b392b3d6a4ecdd7f626925c365ef6221305105ce9b5f5b6ecc5bed3d702bd4b7f5008aa8eb8c7aa3ade8ecf6251516fbefeea4e1082aa0e1848eddb31ffe44b04792d296054402826e4bd054e671f223e5557e4c94f89ca01c25c44f1a2ff2c05a70b43408250705e1b858bf0670679fdcd379203e36be3500dd981b1a6422c3cf15224f7fefdef0a5f225c5a09d15767598ecd9e262460bb33a4b5d09a64591efabc57c923d3be406979032ae0bc0997b65336a06dd75b253332ad6a8b63ef043f780a1b3fb6d0b6cad98b1ef4a02535eb39e14a866cfc5fc3a9c5deb2261300d71280ebe66a0776a151469551c3c5fa308757f956655278ec6330ae9e3625468c5f87e02cd9a6489910d4143c1f4ee13aa21a6859d907b788e28572fecee273d44e4a900fa0aa668dd861a60fb6b6b12c2c5ef3c8df1bd7ef5d4b0d1cdb8c15fffbb365b9784bd94abd001c6966216b9b67554ad7cb7f958b70092514f7800fc40244003e0fd1133a9b850fb17f4fcafde07fc87b07fb510670654a5d2d6fc9876ac74728ea41593beef003d6858786a52d3a40af7529596767c17000bfaf8dc52e871359f4ad8bf6e7b2853e5229bdf39657e213580294a5317c5df172865e1e17fe37093b585e04613f5f078f761b2b1752eb32983afda24b523af8851df9a02b37e77f543f18888a782a994a50563334282bf9cdfccc183fdf4fcd75ad86ee0d94f91ee2300a5befbccd14e03a77fc031a8cfe4f01e4c5290f5ac1da0d58ea054bd4837cfd93e5e34fc0eb16e48044ba76131f228d16cde9b0bb978ca7cdcd10653c358bdb26fdb723a530232c32ae0a4cecc06082f46e1c1d596bfe60621ad1e354e01e07b040cc7347c016653f44d926d13ca74e6cbc9d4ab4c99f4491c95c76fff5076b3936eb9d0a286b97c035ca88a3c6309f5febfd4cdaac869e4f58ed409b1e9eb4192fb2f9c2f12176d460fd98286c9d6df84598f260119fd29c63f800c07d8df83d5cc95f8c2fea2812e7890e8a0718bb1e031ecbebc0436dcf3e3b9a58bcc06b4c17f711f80fe1dffc3326a6eb6e00283055c6dabe20d311bfd5019591b7954f8163c9afad9ef8390a38f3582e0a79cdf0353de8eeb6b5f9f27b16ffdef7dd62869b4840ee226ccdce95e02c4545eb981b60571cd83f03dc5eaf8c97a0829a4318a9b3dc06c0e003db700b2260ff1fa8fee66890e637b109abb03ec901b05ca599775f48af50154c0e67d82bf0f558d7d3e0778dc38bea1eb5f74dc8d7f90abdf5511a424be66bf8b6a3cacb477d2e7ef4db68d2eba4d5289122d851f9501ba7e9c4957d8eba3be3fc8e785c4265a1d65c46f2809b70846c693864b169c9dcb78be26ea14b8613f145b01887222979a9e67aee5f800caa6f5c4229bdeefc901232ace6143c9865e4d9c07f51aa200afaf7e48a7d1d8faf366023beab12906ffcb3eaf72c0eb68075e4daf3c080e0c31911befc16f0cc4a09908bb7c1e26abab38bd7b788e1a09c0edf1a35a38d2ff1d3ed47fcdaae2f0934224694f5b56705b9409b6d3d64f3833b686f7576ec64bbdd6ff174e56c2d1edac0011f904681a73face26573fbba4e34652f7ae84acfb2fa5a5b3046f98178cd0831df7477de70e06a4c00e305f31aafc026ef064dd68fd3e4252b1b91d617b26c6d09b6891a00df68f105b5962e7f9d82da101dd595d286da721443b72b2aba2377f6e7772e33b3a5e3753da9c2578c5d1daab80187f55518c72a64ee150a7cb5649823c08c9f62cd7d020b45ec2cba8310db1a7785a46ab24785b4d54ff1660b5ca78e05a9a55edba9c60bf044737bc468101c4e8bd1480d749be5024adefca1d998abe33eaeb6b11fbb39da5d905fdd3f611b2e51517ccee4b8af72c2d948573505590d61a6783ab7278fc43fe55b1fcc0e7216444d3c8039bb8145ef1ce01c50e95a3f3feab0aee883fdb94cc13ee4d21c542aa795e18932228981690f4d4c57ca4db6eb5c092e29d8a05139d509a8aeb48baa1eb97a76e597a32b280b5e9d6c36859064c98ff96ef5126130264fa8d2f49213870d9fb036cff95da51f270311d9976208554e48ffd486470d0ecdb4e619ccbd8226147204baf8e235f54d8b1cba8fa34a9a4d055de515cdf180d2bb6739a175183c472e30b5c914d09eeb1b7dafd6872b38b48c6afc146101200e6e6a44fe5684e220adc11f5c403ddb15df8051e6bdef09117a3a5349938513776286473a3cf1d2788bb875052a2e6459fa7926da33380149c7f98d7700528a60c954e6f5ecb65842fde69d614be69eaa2040a4819ae6e756accf936e14c1e894489744a79c1f2c1eb295d13e2d767c09964b61f9cfe497649f712"
    nil
    "3ba1f51de6272aa28fd21059b91d3893"
    "faf3b317340de00e29f2181db270ff81"
    "d083d09c1bdf71795b39a9534601cf7c7a7e767e578c44a17dfaf43a3c18f98c"
    "6aa28bc4b6719eca144ac33a3f17859317d5450e4978db9365ce61e7085a617dd386ec18eb436c9056aa1d2d4736c9bffd25803d967fcae916ce1647ccae3d5258b17dfa1cdc7eb99581c48ff2898ef92d3aa1"
    "")
  (%check-bip324-packet 223
    "c0f15820459f64d98e5c48681d13340572c574533dd9f7161b85fcc8224fdf30"
    "682871104d694baca8b9c7990ae6288f49e1ff4feb21dd5cffad67db7752fdfb6c3608d6996c54be04b35feef037da09ee4d9dca2363b343bc2d4f6d0ea609da"
    "56bd0c06f10352c3a1a9f4b4c92f6fa2b26df124b57878353c1fc691c51abea77c8817daeeb9fa546b77c8daf79d89b22b0e1b87574ece42371f00237aa9d83a"
    nil
    "7e0e78eb6990b059e6cf0ded66ea93ef82e72aa2f18ac24f2fc6ebab561ae557420729da103f64cecfa20527e15f9fb669a49bbbf274ef0389b3e43c8c44e5f60bf2ac38e2b55e7ec4273dba15ba41d21f8f5b3ee1688b3c29951218caf847a97fb50d75a86515d445699497d968164bf740012679b8962de573be941c62b7ef"
    1
    ""
    t
    "8461c1dc173be7e6a2316d09710ebd8d"
    "dfa2d33623fe80e2347999e6de0f96fd"
    "279a96e6ce08e5074608fcad77d6a78f90c8b618a4520575435b1a37b1c56df9"
    ""
    "5afbd61f6e989833df2f12ff70c98f1a20ebe84acba2a05429cc6a57238dba87cdc432474f378889b2d0e95ade9f892eb1a1f6b03b73f903682476537f653f738f7a9f1cc9856ed75f3d69122bdeb00af48e66a64872f639a67fc109ee5ca124d0ee183da3c2b8f2da828850b50976b491f1add78d7f01e07565570621266852")
  (%check-bip324-packet 448
    "96cb391886681d1d3e23948e51987771a8ec3001b640c18fb994a855cea66b6e"
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffdde3a077a6fd73711a27250c439ba78ef63d89cd0918c0a0a75f301ed96aa2a43ecf3f61"
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffa7730be30000000000000000000000000000000000000000000000000000000000000000"
    t
    "00cf68f8f7ac49ffaa02c4864fdf6dfe7bbf2c740b88d98c50ebafe32c92f3427f57601ffcb21a3435979287db8fee6c302926741f9d5e464c647eeb9b7acaeda46e00abd7506fc9a719847e9a7328215801e96198dac141a15c7c2f68e0690dd1176292a0dded04d1f548aad88f1aebdc0a8f87da4bb22df32dd7c160c225b843e83f6525d6d484f502f16d923124fc538794e21da2eb689d18d87406ecced5b9f92137239ed1d37bcfa7836641a83cf5e0a1cf63f51b06f158e499a459ede41c"
    1
    ""
    nil
    "7bf55f6b58f73cdff19ee3292607239f"
    "d121874372c61a48fd87da6d01d89da4"
    "e9515794acced50e0550a3ebd95c170d2abd48b5f23fccca73bc597f00c88cf2"
    ""
    "33953941be2682da1c6d1b167cbf180d7cb8159c94c6ea1c52356716f1057af4df53321f18894c285f7b2fd85b2edc44a13c9295f310962fdfc8d944bd77c5500b10ca68ca5d0977d19d183a7def742c41cfeee763dc09ef985c96ab6e74e464f66992f752c9368e42082ad338705062ddfcad4ca1c9c54004b9345d8df25953")
  (%check-bip324-packet 673
    "4a7065c3ddbf84e29b8e20da0da3aaae1f708eae8ad1af4c4c00f46a7cda7b6b"
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff450012ec3aeecf516f4b374af2e7fbb040e92dc3c0f12eafd00c729a137f4e892e5293c3"
    "9652d78baefc028cd37a6a92625b8b8f85fde1e4c944ad3f20e198bef8c02f19fffffffffffffffffffffffffffffffffffffffffffffffffffffffff2e91870"
    nil
    "5c6272ee55da855bbbf7b1246d9885aa7aa601a715ab86fa46c50da533badf82b97597c968293ae04e"
    97561
    ""
    nil
    "1fec304dcaacf1f5b088325306272d78"
    "d2d16a8452807baa4f63b059b5804624"
    "dccb606c4f2a0f64bc164dbc00eb0f6cf1474575e89d7928be6346720bb53610"
    ""
    "58daef966f33c036740aeb3f6a4b31c0f0a070b25fd6a1abf82ef56fc2cb3ca8da8c434f23790c69349dd0cb4058f88a7bd0e333c8ceba3c80f21e951b9fdb1c84e2e7f49f43c21087566d58f1bcc42b041e0b462e37e927c0071caa9a2b650dccf448c9f88d73b62e80a3e5d5e4e46992e34b416ceb9590a7c8b7bfaccf37ab")
  (%check-bip324-packet 1024
    "0f69aeffeff6172647ee5aa80bfb418ee742f4e9f1a51b463ac7c120d620e37d"
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff04df0e67f9753e2cdb066b3b588a0069fde936a312e0d3f31acb335026b7072d8f2ad24c"
    "12a50f3fafea7c1eeada4cf8d33777704b77361453afc83bda91eef349ae044d20126c6200547ea5a6911776c05dee2a7f1a9ba7dfbabbbd273c3ef29ef46e46"
    t
    "5f67d15d22ca9b2804eeab0a66f7f8e3a10fa5de5809a046084348cbc5304e843ef96f59a59c7d7fdfe5946489f3ea297d941bac326225df316a25fc90f0e65b0d31a9c497e960fdbf8c482516bc8a9c1c77b7f6d0e1143810c737f76f9224e6f2c9af5186b4f7259c7e8d165b6e4fe3d38a60bdbdd4d06ecdcaaf62086070dbb68686b802d53dfd7db14b18743832605f5461ad81e2af4b7e8ff0eff0867a25b93cec7becf15c43131895fed09a83bf1ee4a87d44dd0f02a837bf5a1232e201cb882734eb9643dc2dc4d4e8b5690840766212c7ac8f38ad8a9ec47c7a9b3e022ae3eb6a32522128b518bd0d0085dd81c5"
    69615
    ""
    t
    "4dfac3b0a99401f6aad1a8df3cd7dd05"
    "e5d4905a8b6a5d18ec6cebbdecd703d3"
    "fc2431beb9a666bf888df0662276a4b6a1af5061072992ef408f2b686c86a2ac"
    ""
    "1a7f3fb83ad2b050b663b8df6b7c2cc2d8e169a869a58bf7ef5ab5db97a505c84a812e100d9445da4fc39a1176d6aed3995f6868631224b86f10603217c8d13270e0c6d054ad9e0d0b7dc0c8e59a37cd05a0a45faa14b4ffc8d12b641f62e6f1b71c1f72b737e9ce3fe74be779b25e70bf11d98766b3876d0fa28d3c669087fc"))))
