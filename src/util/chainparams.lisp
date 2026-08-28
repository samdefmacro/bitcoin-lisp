(in-package #:bitcoin-lisp.chainparams)

;;;; Chain parameters (Core kernel/chainparams.cpp, CChainParams)
;;;
;;; Everything that distinguishes one chain from another, as one table: one
;;; DEFINE-CHAIN-PARAMS form per chain, read through FIND-CHAIN-PARAMS. Before
;;; this file the same facts were spread over some thirty (ecase network ...)
;;; forms in eight files, so adding a chain meant touching all eight; now it
;;; is one form here. Consensus values are Core's (the Core member is named
;;; next to each field); the DNS seed lists are the ones this tree has always
;;; shipped and have drifted from Core's, and the checkpoints are ours (Core
;;; dropped checkpointData).
;;;
;;; This file loads before crypto, so it holds only literals and what ironclad
;;; (a dependency, loaded before everything) can decode: the genesis hash is
;;; bytes in wire order; assumevalid, checkpoints and assumeutxo stay hex
;;; strings in Core's display order, reversed by the consumer as before. The
;;; consumers -- network-genesis-hash, network-checkpoints, ... -- keep their
;;; names and signatures, so no call site changed.

(defstruct chain-params
  "One chain's parameters. Field comments name the Core member."
  (name nil :type keyword)                  ; :mainnet :testnet3 :testnet4 :signet :regtest
  (core-name "" :type string)               ; ChainTypeToString: "main" "test" "testnet4" "signet" "regtest"
  (data-subdirectory nil)                   ; chainparamsbase.cpp DataDir: NIL for mainnet, "testnet4/" ...
  (magic (make-array 4 :element-type '(unsigned-byte 8))
   :type (simple-array (unsigned-byte 8) (4))) ; pchMessageStart
  (port 0 :type fixnum)                     ; nDefaultPort
  (rpc-port 0 :type fixnum)                 ; chainparamsbase.cpp RPCPort
  (dns-seeds '())                           ; vSeeds
  (fixed-seeds '())                         ; vFixedSeeds (IPv4 strings; only testnet4 carries them here)
  (genesis-hash (make-array 32 :element-type '(unsigned-byte 8))
   :type (simple-array (unsigned-byte 8) (32))) ; hashGenesisBlock, WIRE byte order
  (genesis-timestamp 0)                     ; CreateGenesisBlock nTime
  (genesis-bits 0)                          ;                    nBits
  (genesis-nonce 0)                         ;                    nNonce
  (genesis-timestamp-message "" :type string) ; pszTimestamp
  (pow-limit-bits 0)                        ; powLimit, as compact bits
  (bip34-height 0)                          ; consensus.BIP34Height
  (bip65-height 0)                          ; consensus.BIP65Height
  (bip66-height 0)                          ; consensus.BIP66Height
  (csv-height 0)                            ; consensus.CSVHeight
  (segwit-height 0)                         ; consensus.SegwitHeight
  (taproot-height 0)                        ; vDeployments[DEPLOYMENT_TAPROOT] activation height
  (checkpoints '())                         ; our checkpoints (Core dropped checkpointData): ((height . display-hex) ...)
  (headers-sync-params nil)                 ; (commitment-period . lookahead) per headerssync_params.py
  (minimum-chain-work 0)                    ; consensus.nMinimumChainWork
  (assumevalid-hex nil)                     ; consensus.defaultAssumeValid, display order; NIL = disabled
  (assumeutxo '())                          ; m_assumeutxo_data: ((height blockhash-hex hash-serialized-hex chain-tx-count) ...)
  (prune-after-height 0)                    ; nPruneAfterHeight
  (bech32-hrp "" :type string))             ; bech32_hrp

(defvar *chain-params* '()
  "Every chain, in definition order; filled by DEFINE-CHAIN-PARAMS.")

(defmacro define-chain-params (name &rest fields)
  "Define the chain NAME (a keyword) from FIELDS, the keyword arguments of
MAKE-CHAIN-PARAMS, replacing an earlier definition of the same name."
  `(setf *chain-params*
         (append (remove ,name *chain-params* :key #'chain-params-name)
                 (list (make-chain-params :name ,name ,@fields)))))

(defun chain-names ()
  "Every defined chain, in definition order."
  (mapcar #'chain-params-name *chain-params*))

(defun find-chain-params (name)
  "The chain-params for NAME (:mainnet, :testnet3, :testnet4, :signet or
:regtest); an error for an unknown chain."
  (or (find name *chain-params* :key #'chain-params-name)
      (config-error "no chain parameters for ~S (known: ~{~S~^ ~})" name (chain-names))))

;;;; The chains (kernel/chainparams.cpp: CMainParams, CTestNetParams,
;;;; CTestNet4Params, SigNetParams, CRegTestParams). Genesis nTime/nBits/nNonce
;;;; and pszTimestamp per CreateGenesisBlock; the hash is checked when the
;;;; block is rebuilt (storage/chain.lisp make-genesis-block). Activation
;;;; heights: consensus.BIPnnHeight and the buried deployments. testnet4,
;;;; signet and regtest activate everything at height 1 (regtest: SegWit and
;;;; Taproot from genesis, ALWAYS_ACTIVE).

(define-chain-params :mainnet
  :core-name "main"
  :data-subdirectory nil
  :magic (make-array 4 :element-type '(unsigned-byte 8)
                       :initial-contents '(#xF9 #xBE #xB4 #xD9))
  :port 8333
  :rpc-port 8332
  :dns-seeds '("seed.bitcoin.sipa.be"
             "dnsseed.bluematt.me"
             "dnsseed.bitcoin.dashjr.org"
             "seed.bitcoinstats.com"
             "seed.bitcoin.jonasschnelli.ch")
  :fixed-seeds '()
  :genesis-hash (ironclad:hex-string-to-byte-array "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000")
  :genesis-timestamp 1231006505
  :genesis-bits #x1d00ffff
  :genesis-nonce 2083236893
  :genesis-timestamp-message "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
  :pow-limit-bits #x1d00ffff
  :bip34-height 227931
  :bip65-height 388381
  :bip66-height 363725
  :csv-height 419328
  :segwit-height 481824
  :taproot-height 709632
  :checkpoints '((11111 . "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d")
               (33333 . "000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6")
               (74000 . "0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20")
               (105000 . "00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97")
               (134444 . "00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe")
               (168000 . "000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763")
               (193000 . "000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317")
               (210000 . "000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e")
               (250000 . "000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214")
               (295000 . "00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632a983")
               (420000 . "000000000000000002cce816c0ab2c5c269cb081896b7dcb34b8422d6b74f112")
               (630000 . "000000000000000000024bead8df69990852c202db0e0097c1a12ea637d7e96d")
               (840000 . "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"))
  :headers-sync-params '(641 . 15218)
  :minimum-chain-work #x0000000000000000000000000000000000000001128750f82f4c366153a3a030
  :assumevalid-hex "00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac"
  :assumeutxo '(
               (840000 "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"
                "a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96"
                991032194)
               (880000 "000000000000000000010b17283c3c400507969a9c2afd1dcf2082ec5cca2880"
                "dbd190983eaf433ef7c15f78a278ae42c00ef52e0fd2a54953782175fbadcea9"
                1145604538)
               (910000 "0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821"
                "4daf8a17b4902498c5787966a2b51c613acdab5df5db73f196fa59a4da2f1568"
                1226586151)
               (935000 "0000000000000000000147034958af1652b2b91bba607beacc5e72a56f0fb5ee"
                "e4b90ef9eae834f56c4b64d2d50143cee10ad87994c614d7d04125e2a6025050"
                1305397408))
  :prune-after-height 100000
  :bech32-hrp "bc")

(define-chain-params :testnet3
  :core-name "test"
  :data-subdirectory "testnet3/"
  :magic (make-array 4 :element-type '(unsigned-byte 8)
                       :initial-contents '(#x0B #x11 #x09 #x07))
  :port 18333
  :rpc-port 18332
  :dns-seeds '("testnet-seed.bitcoin.jonasschnelli.ch"
             "seed.tbtc.petertodd.org"
             "seed.testnet.bitcoin.sprovoost.nl"
             "testnet-seed.bluematt.me")
  :fixed-seeds '()
  :genesis-hash (ironclad:hex-string-to-byte-array "43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000")
  :genesis-timestamp 1296688602
  :genesis-bits #x1d00ffff
  :genesis-nonce 414098458
  :genesis-timestamp-message "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
  :pow-limit-bits #x1d00ffff
  :bip34-height 21111
  :bip65-height 581885
  :bip66-height 330776
  :csv-height 770112
  :segwit-height 834624
  :taproot-height 2346882
  :checkpoints '((546 . "000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70")
               (100000 . "00000000009e2958c15ff9290d571bf9459e93b19765c6801ddeccadbb160a1e")
               (500000 . "000000000001a7c0aaa2630fbb2c0e476aafffc60f82177375b2aaa22209f606")
               (1000000 . "0000000000478e259a3eda2fafbeeb0106626f946347955e99278fe6cc848414")
               (1500000 . "00000000000000a33e21d6d82fe7cef5b35dfe75af01baafa5df7c11e69cf099")
               (2000000 . "0000000000000795a6501e606e3fd3b3f51c6d9e47d3a1ba83c3fb1e84d50b7a"))
  :headers-sync-params '(673 . 14460)
  :minimum-chain-work #x0000000000000000000000000000000000000000000017dde1c649f3708d14b6
  :assumevalid-hex "000000007a61e4230b28ac5cb6b5e5a0130de37ac1faf2f8987d2fa6505b67f4"
  :assumeutxo '(
               (2500000 "0000000000000093bcb68c03a9a168ae252572d348a2eaeba2cdf9231d73206f"
                "f841584909f68e47897952345234e37fcd9128cd818f41ee6c3ca68db8071be7"
                66484552)
               (4840000 "00000000000000f4971a7fb37fbdff89315b69a2e1920c467654a382f0d64786"
                "ce6bb677bb2ee9789c4a1c9d73e6683c53fc20e8fdbedbdaaf468982a0c8db2a"
                536078574))
  :prune-after-height 1000
  :bech32-hrp "tb")

(define-chain-params :testnet4
  :core-name "testnet4"
  :data-subdirectory "testnet4/"
  :magic (make-array 4 :element-type '(unsigned-byte 8)
                       :initial-contents '(#x1C #x16 #x3F #x28))
  :port 48333
  :rpc-port 48332
  :dns-seeds '("seed.testnet4.bitcoin.sprovoost.nl"
             "seed.testnet4.wiz.biz")
  :fixed-seeds '("2.59.134.244" "2.110.106.102" "5.182.4.106" "31.220.30.248"
               "34.232.194.104" "35.201.167.154" "38.102.86.40" "45.41.204.8"
               "45.50.223.112" "45.94.168.5" "51.158.61.33" "52.6.23.153"
               "54.76.27.166" "54.78.49.45" "62.84.190.200" "65.108.143.22"
               "67.81.240.18" "67.213.127.87" "69.26.129.172" "70.95.111.216"
               "71.13.92.62" "71.183.49.199" "74.133.9.162" "80.253.94.252"
               "82.67.102.15" "89.58.9.219" "94.183.188.204" "95.141.35.117"
               "95.182.100.206" "96.79.5.26" "103.69.87.64" "103.99.169.203"
               "103.99.169.204" "103.165.192.201" "103.165.192.210" "103.232.248.31"
               "104.237.131.138" "109.123.236.96" "121.98.22.147" "135.180.99.74"
               "142.160.218.208" "144.172.110.246" "148.51.196.40" "158.69.118.2"
               "158.69.211.155" "158.220.90.103" "162.220.166.82" "168.119.11.220"
               "173.53.122.49" "174.177.47.73" "176.169.208.187" "181.174.165.116"
               "185.254.97.76" "193.30.123.70" "195.154.199.2" "198.58.102.18"
               "203.51.4.72" "203.132.94.196" "208.68.4.50" "208.68.4.71"
               "208.73.202.78" "217.31.57.128" "222.66.94.2")
  :genesis-hash (ironclad:hex-string-to-byte-array "43f08bdab050e35b567c864b91f47f50ae725ae2de53bcfbbaf284da00000000")
  :genesis-timestamp 1714777860
  :genesis-bits #x1d00ffff
  :genesis-nonce 393743547
  :genesis-timestamp-message "03/May/2024 000000000000000000001ebd58c244970b3aa9d783bb001011fbe8ea8e98e00e"
  :pow-limit-bits #x1d00ffff
  :bip34-height 1
  :bip65-height 1
  :bip66-height 1
  :csv-height 1
  :segwit-height 1
  :taproot-height 1
  :checkpoints '()
  :headers-sync-params '(606 . 16092)
  :minimum-chain-work #x0000000000000000000000000000000000000000000009a0fe15d0177d086304
  :assumevalid-hex "0000000002368b1e4ee27e2e85676ae6f9f9e69579b29093e9a82c170bf7cf8a"
  :assumeutxo '(
               (90000 "0000000002ebe8bcda020e0dd6ccfbdfac531d2f6a81457191b99fc2df2dbe3b"
                "784fb5e98241de66fdd429f4392155c9e7db5c017148e66e8fdbc95746f8b9b5"
                11347043)
               (120000 "000000000bd2317e51b3c5794981c35ba894ce27d3e772d5c39ecd9cbce01dc8"
                "10b05d05ad468d0971162e1b222a4aa66caca89da2bb2a93f8f37fb29c4794b0"
                14141057))
  :prune-after-height 1000
  :bech32-hrp "tb")

(define-chain-params :signet
  :core-name "signet"
  :data-subdirectory "signet/"
  :magic (make-array 4 :element-type '(unsigned-byte 8)
                       :initial-contents '(#x0A #x03 #xCF #x40))
  :port 38333
  :rpc-port 38332
  :dns-seeds '("seed.signet.bitcoin.sprovoost.nl"
             "seed.signet.achownodes.xyz")
  :fixed-seeds '()
  :genesis-hash (ironclad:hex-string-to-byte-array "f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000")
  :genesis-timestamp 1598918400
  :genesis-bits #x1e0377ae
  :genesis-nonce 52613770
  :genesis-timestamp-message "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
  :pow-limit-bits #x1e0377ae
  :bip34-height 1
  :bip65-height 1
  :bip66-height 1
  :csv-height 1
  :segwit-height 1
  :taproot-height 1
  :checkpoints '()
  :headers-sync-params '(620 . 15724)
  :minimum-chain-work #x00000000000000000000000000000000000000000000000000000b463ea0a4b8
  :assumevalid-hex "00000008414aab61092ef93f1aacc54cf9e9f16af29ddad493b908a01ff5c329"
  :assumeutxo '(
               (160000 "0000003ca3c99aff040f2563c2ad8f8ec88bd0fd6b8f0895cfaf1ef90353a62c"
                "fe0a44309b74d6b5883d246cb419c6221bcccf0b308c9b59b7d70783dbdf928a"
                2289496)
               (290000 "0000000577f2741bb30cd9d39d6d71b023afbeb9764f6260786a97969d5c9ac0"
                "97267e000b4b876800167e71b9123f1529d13b14308abec2888bbd2160d14545"
                28547497))
  :prune-after-height 1000
  :bech32-hrp "tb")

(define-chain-params :regtest
  :core-name "regtest"
  :data-subdirectory "regtest/"
  :magic (make-array 4 :element-type '(unsigned-byte 8)
                       :initial-contents '(#xFA #xBF #xB5 #xDA))
  :port 18444
  :rpc-port 18443
  :dns-seeds '()
  :fixed-seeds '()
  :genesis-hash (ironclad:hex-string-to-byte-array "06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f")
  :genesis-timestamp 1296688602
  :genesis-bits #x207fffff
  :genesis-nonce 2
  :genesis-timestamp-message "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
  :pow-limit-bits #x207fffff
  :bip34-height 1
  :bip65-height 1
  :bip66-height 1
  :csv-height 1
  :segwit-height 0
  :taproot-height 0
  :checkpoints '()
  :headers-sync-params '(275 . 7017)
  :minimum-chain-work 0
  :assumevalid-hex nil
  :assumeutxo '(
               (110 "6affe030b7965ab538f820a56ef56c8149b7dc1d1c144af57113be080db7c397"
                "b952555c8ab81fec46f3d4253b7af256d766ceb39fb7752b9d18cdf4a0141327"
                111)
               (200 "385901ccbd69dff6bbd00065d01fb8a9e464dede7cfe0372443884f9b1dcf6b9"
                "17dcc016d188d16068907cdeb38b75691a118d43053b8cd6a25969419381d13a"
                201)
               (299 "7cc695046fec709f8c9394b6f928f81e81fd3ac20977bb68760fa1faa7916ea2"
                "d2b051ff5e8eef46520350776f4100dd710a63447a8e01d917e92e79751a63e2"
                334))
  :prune-after-height 1000
  :bech32-hrp "bcrt")

;;; The current chain, and the lookups every layer needs from it.

(defvar *network* :testnet4
  "Current network mode (:testnet3, :testnet4, :signet, :regtest, or :mainnet).")

(defun network-magic (network)
  "NETWORK's message-start bytes (chain-params-magic)."
  (chain-params-magic (find-chain-params network)))
