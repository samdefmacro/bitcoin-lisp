(in-package #:bitcoin-lisp.tests)

;;;; MuSig2 signing (BIP 327): known-answer vectors and the nonce lifetime
;;;;
;;;; The vectors are BIP327's, as libsecp256k1 carries them at Core's pin
;;;; (src/secp256k1/src/modules/musig/vectors.h, generated from the BIP's
;;;; JSON by tools/test_vectors_musig2_generate.py), driven the way its own
;;;; tests_impl.h:768-1100 drives them -- through the public API only, except
;;;; for the two places libsecp's test does too: a secret nonce the vector
;;;; FIXES (sign/verify, tweak) and a keyagg cache built from a bare x-only
;;;; aggregate (nonce_gen). Those two are assembled here from the struct
;;;; layouts of v0.7 (session_impl.h:50-55, keyagg_impl.h:31-44), which is
;;;; what makes this file, and only this file, layout-dependent.

(def-suite :musig-tests
  :description "MuSig2 (BIP327) vectors and secret-nonce lifetime"
  :in :bitcoin-lisp-tests)

(in-suite :musig-tests)

(defun %mu (hex) (bl.crypto:hex-to-bytes hex))

(defun %mu-list (&rest hexes) (mapcar #'%mu hexes))

(defun %mu-hex (bytes) (and bytes (string-upcase (bl.crypto:bytes-to-hex bytes))))

(defun %mu-pick (vector indices) (mapcar (lambda (i) (nth i vector)) indices))

(defun %mu-tweaks (tweaks indices xonly-flags)
  (mapcar (lambda (i x) (cons (nth i tweaks) (= x 1))) indices xonly-flags))

(defun %mu-secnonce-from-vector (secnonce97)
  "A live MUSIG-SECNONCE holding the vector's k1||k2 for the vector's 33-byte
key: libsecp's secnonce layout, magic 220edcf1 || k1 || k2 || the parsed
secp256k1_pubkey (secnonce_save, session_impl.h:50-55) -- what libsecp's own
musig_test_set_secnonce writes."
  (let ((ptr (cffi:foreign-alloc :uint8 :count 132 :initial-element 0))
        (parsed (bl.crypto:parse-public-key (subseq secnonce97 64 97))))
    (loop for b across (concatenate 'vector #(#x22 #x0e #xdc #xf1) (subseq secnonce97 0 64)
                                    (or parsed (make-array 64 :initial-element 0)))
          for i from 0
          do (setf (cffi:mem-aref ptr :uint8 i) b))
    (bl.crypto:musig-secnonce-adopt ptr)))

(defun %mu-secnonce-k-matches-p (k1k2-hex pubnonce)
  "Whether the vector's expected secret nonce k1||k2 is the one behind
PUBNONCE: a public nonce is k1*G || k2*G (BIP327 NonceGen), and a scalar in
[1,n-1] is fixed by its point, so a byte-exact public nonce whose halves are
these scalars' points proves the secret nonce byte for byte -- without
copying the secret out of its foreign memory."
  (let ((k (bl.crypto:hex-to-bytes k1k2-hex)))
    (equalp pubnonce (concatenate '(simple-array (unsigned-byte 8) (*))
                                  (bl.crypto:derive-public-key (subseq k 0 32))
                                  (bl.crypto:derive-public-key (subseq k 32 64))))))

(defun %mu-cache-from-aggpk (aggpk32)
  "A keyagg cache whose aggregate is the bare x-only AGGPK32 and whose other
fields are zero, as tests_impl.h:809-816 builds one for the nonce_gen vector:
magic f4adbbdf || the parsed point || zeros (keyagg_cache_save)."
  (concatenate '(simple-array (unsigned-byte 8) (*))
               #(#xf4 #xad #xbb #xdf)
               (bl.crypto:parse-xonly-pubkey aggpk32)
               (make-array 129 :initial-element 0)))

;;; --- KeyAgg (vectors.h:40-67) ---------------------------------------------

(defparameter *mu-keyagg-pubkeys*
  (%mu-list "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
            "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
            "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66"
            "020000000000000000000000000000000000000000000000000000000000000005"
            "02FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30"
            "04F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
            "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9"))

(defparameter *mu-keyagg-tweaks*
  (%mu-list "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
            "252E4BD67410A76CDF933D30EAA1608214037F1B105A013ECCD3C5C184A6110B"))

(test musig-keyagg-vectors
  "BIP327 key_agg_vectors: the four valid aggregates byte for byte, and each
error case refused for its own reason -- an invalid key as :PUBKEY, a tweak
out of range or one that cancels the key as :TWEAK."
  (loop for (indices expected)
          in '(((0 1 2) "90539EEDE565F5D054F32CC0C220126889ED1E5D193BAF15AEF344FE59D4610C")
               ((2 1 0) "6204DE8B083426DC6EAF9502D27024D53FC826BF7D2012148A0575435DF54B2B")
               ((0 0 0) "B436E3BAD62B8CD409969A224731C193D051162D8C5AE8B109306127DA3AA935")
               ((0 0 1 1) "69BC22BFA5D106306E48A20679DE1D7389386124D07571D0D872686028C26A3E"))
        do (multiple-value-bind (cache agg) (bl.crypto:musig-keyagg
                                             (%mu-pick *mu-keyagg-pubkeys* indices))
             (is (= 197 (length cache)))
             (is (string= expected (%mu-hex (subseq agg 1))))))
  (loop for (indices tweak-indices xonly reason)
          in '(((0 3) () () :pubkey)
               ((0 4) () () :pubkey)
               ((5 0) () () :pubkey)
               ((0 1) (0) (1) :tweak)
               ((6) (1) (0) :tweak))
        do (multiple-value-bind (cache why)
               (bl.crypto:musig-keyagg (%mu-pick *mu-keyagg-pubkeys* indices)
                                       (%mu-tweaks *mu-keyagg-tweaks* tweak-indices xonly))
             (is (null cache))
             (is (eq reason why)))))

;;; --- NonceGen (vectors.h:88-93) --------------------------------------------

(test musig-nonce-gen-vectors
  "BIP327 nonce_gen_vectors through secp256k1_musig_nonce_gen with the
vector's fixed session randomness: the public nonce AND the secret nonce's
k1||k2 byte for byte, and the randomness buffer zeroed once used (libsecp
invalidates it so it cannot be fed in twice)."
  (let ((rand (%mu "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F")))
    (multiple-value-bind (secnonce pubnonce)
        (bl.crypto:musig-nonce-gen
         rand (%mu "024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766")
         :seckey (%mu "0202020202020202020202020202020202020202020202020202020202020202")
         :msg (%mu "0101010101010101010101010101010101010101010101010101010101010101")
         :keyagg-cache (%mu-cache-from-aggpk
                        (%mu "0707070707070707070707070707070707070707070707070707070707070707"))
         :extra (%mu "0808080808080808080808080808080808080808080808080808080808080808"))
      (is (string= "02F7BE7089E8376EB355272368766B17E88E7DB72047D05E56AA881EA52B3B35DF02C29C8046FDD0DED4C7E55869137200FBDBFE2EB654267B6D7013602CAED3115A"
                   (%mu-hex pubnonce)))
      (is (%mu-secnonce-k-matches-p
           "B114E502BEAA4E301DD08A50264172C84E41650E6CB726B410C0694D59EFFB6495B5CAF28D045B973D63E3C99A44B807BDE375FD6CB39E46DC4A511708D0E9D2"
           pubnonce))
      (is (every #'zerop rand) "nonce_gen must invalidate the session randomness")
      (bl.crypto:musig-secnonce-invalidate secnonce)))
  (multiple-value-bind (secnonce pubnonce)
      (bl.crypto:musig-nonce-gen
       (%mu "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F")
       (%mu "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"))
    (is (string= "02C96E7CB1E8AA5DAC64D872947914198F607D90ECDE5200DE52978AD5DED63C000299EC5117C2D29EDEE8A2092587C3909BE694D5CFF0667D6C02EA4059F7CD9786"
                 (%mu-hex pubnonce)))
    (is (%mu-secnonce-k-matches-p
         "89BDD787D0284E5E4D5FC572E49E316BAB7E21E3B1830DE37DFE80156FA41A6D0B17AE8D024C53679699A6FD7944D9C4A366B514BAF43088E0708B1023DD2897"
         pubnonce))
    (bl.crypto:musig-secnonce-invalidate secnonce))
  ;; An all-zero session randomness is refused (secp256k1_musig_nonce_gen
  ;; returns 0 for it, session_impl.h:457), not turned into a nonce.
  (is (null (bl.crypto:musig-nonce-gen
             (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
             (%mu "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")))))

;;; --- NonceAgg (vectors.h:109-128) ------------------------------------------

(defparameter *mu-pnonces*
  (%mu-list "020151C80F435648DF67A22B749CD798CE54E0321D034B92B709B567D60A42E66603BA47FBC1834437B3212E89A84D8425E7BF12E0245D98262268EBDCB385D50641"
            "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60248C264CDD57D3C24D79990B0F865674EB62A0F9018277A95011B41BFC193B833"
            "020151C80F435648DF67A22B749CD798CE54E0321D034B92B709B567D60A42E6660279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
            "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60379BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
            "04FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60248C264CDD57D3C24D79990B0F865674EB62A0F9018277A95011B41BFC193B833"
            "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60248C264CDD57D3C24D79990B0F865674EB62A0F9018277A95011B41BFC193B831"
            "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A602FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30"))

(test musig-nonce-agg-vectors
  "BIP327 nonce_agg_vectors: both valid aggregates byte for byte over all 66
bytes -- the second sums to the point at infinity in its second half, which
serializes as 33 zero bytes -- and each invalid nonce named by its index."
  (is (string= "035FE1873B4F2967F52FEA4A06AD5A8ECCBE9D0FD73068012C894E2E87CCB5804B024725377345BDE0E9C33AF3C43C0A29A9249F2F2956FA8CFEB55C8573D0262DC8"
               (%mu-hex (bl.crypto:musig-nonce-agg (%mu-pick *mu-pnonces* '(0 1))))))
  (is (string= "035FE1873B4F2967F52FEA4A06AD5A8ECCBE9D0FD73068012C894E2E87CCB5804B000000000000000000000000000000000000000000000000000000000000000000"
               (%mu-hex (bl.crypto:musig-nonce-agg (%mu-pick *mu-pnonces* '(2 3))))))
  (loop for (indices bad) in '(((0 4) 1) ((5 1) 0) ((6 1) 0))
        do (multiple-value-bind (agg index)
               (bl.crypto:musig-nonce-agg (%mu-pick *mu-pnonces* indices))
             (is (null agg))
             (is (eql bad index)))))

;;; --- Sign / PartialSigVerify (vectors.h:174-226) ---------------------------

(defparameter *mu-sv-sk* (%mu "7FB9E0E687ADA1EEBF7ECFE2F21E73EBDB51A7D450948DFE8D76D7F2D1007671"))

(defparameter *mu-sv-pubkeys*
  (%mu-list "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9"
            "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
            "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA661"
            "020000000000000000000000000000000000000000000000000000000000000007"))

(defparameter *mu-sv-secnonces*
  (%mu-list "508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9"
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9"))

(defparameter *mu-sv-pubnonces*
  (%mu-list "0337C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA0287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480"
            "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817980279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
            "032DE2662628C90B03F5E720284EB52FF7D71F4284F627B68A853D78C78E1FFE9303E4C5524E83FFE1493B9077CF1CA6BEB2090C93D930321071AD40B2F44E599046"
            "0237C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA0387BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480"
            "0200000000000000000000000000000000000000000000000000000000000000090287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480"))

(defparameter *mu-sv-aggnonces*
  (%mu-list "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "048465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9"
            "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61020000000000000000000000000000000000000000000000000000000000000009"
            "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD6102FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30"))

(defparameter *mu-sv-msg* (%mu "F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF"))

(defun %mu-session (pubkeys aggnonce msg &optional tweaks)
  (let ((cache (bl.crypto:musig-keyagg pubkeys tweaks)))
    (values (and cache (bl.crypto:musig-nonce-process aggnonce msg cache)) cache)))

(test musig-sign-verify-vectors
  "BIP327 sign_verify_vectors: each valid case's partial signature byte for
byte from the vector's fixed secret nonce, and verifying; the error cases
refused where the BIP says -- and the used secnonce refused by us BEFORE
libsecp, which would abort the process on it."
  (loop for (indices aggnonce nil expected) ; the third column names the signer
          in '(((0 1 2) 0 0 "012ABBCB52B3016AC03AD82395A1A415C48B93DEF78718E62A7A90052FE224FB")
               ((1 0 2) 0 1 "9FF2F7AAA856150CC8819254218D3ADEEB0535269051897724F9DB3789513A52")
               ((1 2 0) 0 2 "FA23C359F6FAC4E7796BB93BC9F0532A95468C539BA20FF86D7C76ED92227900")
               ((0 1) 1 0 "AE386064B26105404798F75DE2EB9AF5EDA5387B064B83D049CB7C5E08879531"))
        do (multiple-value-bind (session cache)
               (%mu-session (%mu-pick *mu-sv-pubkeys* indices)
                            (nth aggnonce *mu-sv-aggnonces*) *mu-sv-msg*)
             (let* ((secnonce (%mu-secnonce-from-vector (first *mu-sv-secnonces*)))
                    (psig (bl.crypto:musig-partial-sign secnonce *mu-sv-sk* cache session)))
               (is (string= expected (%mu-hex psig)))
               (is-false (bl.crypto:musig-secnonce-valid-p secnonce))
               (is-true (bl.crypto:musig-partial-sig-verify
                         psig (first *mu-sv-pubnonces*) (first *mu-sv-pubkeys*) cache session)))))
  ;; sign_error_cases 1..5 (case 0, a signing key outside the key list, is
  ;; skipped by libsecp too: the primitive does not check membership --
  ;; CreateMuSig2PartialSig does, see MUSIG2-CORE-FLOW-REFUSES-A-NON-PARTICIPANT).
  (is (eq :pubkey (nth-value 1 (bl.crypto:musig-keyagg (%mu-pick *mu-sv-pubkeys* '(1 0 3))))))
  (dolist (bad '(2 3 4))
    (is (null (%mu-session (%mu-pick *mu-sv-pubkeys* '(1 2 0))
                           (nth bad *mu-sv-aggnonces*) *mu-sv-msg*))))
  (multiple-value-bind (session cache)
      (%mu-session (%mu-pick *mu-sv-pubkeys* '(0 1 2)) (first *mu-sv-aggnonces*) *mu-sv-msg*)
    (let ((used (%mu-secnonce-from-vector (second *mu-sv-secnonces*))))
      (is (null (bl.crypto:musig-partial-sign used *mu-sv-sk* cache session))
          "a zeroed secnonce must be refused in Lisp, not reach libsecp"))
    ;; verify_fail_cases: a wrong signature, the right one checked against the
    ;; wrong signer, and a value that is not a scalar at all.
    (let ((pks (%mu-pick *mu-sv-pubkeys* '(0 1 2)))
          (nonces (%mu-pick *mu-sv-pubnonces* '(0 1 2))))
      (is-false (bl.crypto:musig-partial-sig-verify
                 (%mu "FED54434AD4CFE953FC527DC6A5E5BE8F6234907B7C187559557CE87A0541C46")
                 (first nonces) (first pks) cache session))
      (is-false (bl.crypto:musig-partial-sig-verify
                 (%mu "012ABBCB52B3016AC03AD82395A1A415C48B93DEF78718E62A7A90052FE224FB")
                 (second nonces) (second pks) cache session))
      (is-false (bl.crypto:musig-partial-sig-verify
                 (%mu "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
                 (first nonces) (first pks) cache session))
      ;; Positive control for the three refusals: the valid case-0 signature
      ;; verifies under exactly these arguments.
      (is-true (bl.crypto:musig-partial-sig-verify
                (%mu "012ABBCB52B3016AC03AD82395A1A415C48B93DEF78718E62A7A90052FE224FB")
                (first nonces) (first pks) cache session))
      ;; verify_error_cases: an invalid public nonce, an invalid key.
      (is-false (bl.crypto:musig-partial-sig-verify
                 (%mu "012ABBCB52B3016AC03AD82395A1A415C48B93DEF78718E62A7A90052FE224FB")
                 (nth 4 *mu-sv-pubnonces*) (first pks) cache session))
      (is (eq :pubkey (nth-value 1 (bl.crypto:musig-keyagg (%mu-pick *mu-sv-pubkeys* '(3 1 2)))))))))

;;; --- Tweaks (vectors.h:252-285) --------------------------------------------

(test musig-tweak-vectors
  "BIP327 tweak_vectors: the signer's partial signature under one to four
plain and x-only tweaks, byte for byte and verifying; a tweak equal to the
group order refused as :TWEAK."
  (let ((pubkeys (%mu-list "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9"
                           "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
                           "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"))
        (tweaks (%mu-list "E8F791FF9225A2AF0102AFFF4A9A723D9612A682A25EBE79802B263CDFCD83BB"
                          "AE2EA797CC0FE72AC5B97B97F3C6957D7E4199A167A58EB08BCAFFDA70AC0455"
                          "F52ECBC565B3D8BEA2DFD5B75A4F457E54369809322E4120831626F290FA87E0"
                          "1969AD73CC177FA0B4FCED6DF1F7BF9907E665FDE9BA196A74FED0A3CF5AEF9D"
                          "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"))
        (aggnonce (%mu "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9"))
        (secnonce97 (first *mu-sv-secnonces*)))
    (loop for (tweak-indices xonly expected)
            in '(((0) (1) "E28A5C66E61E178C2BA19DB77B6CF9F7E2F0F56C17918CD13135E60CC848FE91")
                 ((0) (0) "38B0767798252F21BF5702C48028B095428320F73A4B14DB1E25DE58543D2D2D")
                 ((0 1) (0 1) "408A0A21C4A0F5DACAF9646AD6EB6FECD7F7A11F03ED1F48DFFF2185BC2C2408")
                 ((0 1 2 3) (0 0 1 1) "45ABD206E61E3DF2EC9E264A6FEC8292141A633C28586388235541F9ADE75435")
                 ((0 1 2 3) (1 0 1 0) "B255FDCAC27B40C7CE7848E2D3B7BF5EA0ED756DA81565AC804CCCA3E1D5D239"))
          do (multiple-value-bind (session cache)
                 (%mu-session (%mu-pick pubkeys '(1 2 0)) aggnonce *mu-sv-msg*
                              (%mu-tweaks tweaks tweak-indices xonly))
               (let ((psig (bl.crypto:musig-partial-sign
                            (%mu-secnonce-from-vector secnonce97) *mu-sv-sk* cache session)))
                 (is (string= expected (%mu-hex psig)))
                 (is-true (bl.crypto:musig-partial-sig-verify
                           psig (first *mu-sv-pubnonces*) (first pubkeys) cache session)))))
    (is (eq :tweak (nth-value 1 (bl.crypto:musig-keyagg (%mu-pick pubkeys '(1 2 0))
                                                        (%mu-tweaks tweaks '(4) '(0))))))))

;;; --- PartialSigAgg (vectors.h:312-345) -------------------------------------

(test musig-sig-agg-vectors
  "BIP327 sig_agg_vectors: each aggregate signature byte for byte, and a valid
BIP340 signature for the (tweaked) aggregate key; the invalid partial
signature named by its index."
  (let ((pubkeys (%mu-list "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9"
                           "02D2DC6F5DF7C56ACF38C7FA0AE7A759AE30E19B37359DFDE015872324C7EF6E05"
                           "03C7FB101D97FF930ACD0C6760852EF64E69083DE0B06AC6335724754BB4B0522C"
                           "02352433B21E7E05D3B452B81CAE566E06D2E003ECE16D1074AABA4289E0E3D581"))
        (tweaks (%mu-list "B511DA492182A91B0FFB9A98020D55F260AE86D7ECBD0399C7383D59A5F2AF7C"
                          "A815FE049EE3C5AAB66310477FBC8BCCCAC2F3395F59F921C364ACD78A2F48DC"
                          "75448A87274B056468B977BE06EB1E9F657577B7320B0A3376EA51FD420D18A8"))
        (psigs (%mu-list "B15D2CD3C3D22B04DAE438CE653F6B4ECF042F42CFDED7C41B64AAF9B4AF53FB"
                         "6193D6AC61B354E9105BBDC8937A3454A6D705B6D57322A5A472A02CE99FCB64"
                         "9A87D3B79EC67228CB97878B76049B15DBD05B8158D17B5B9114D3C226887505"
                         "66F82EA90923689B855D36C6B7E032FB9970301481B99E01CDB4D6AC7C347A15"
                         "4F5AEE41510848A6447DCD1BBC78457EF69024944C87F40250D3EF2C25D33EFE"
                         "DDEF427BBB847CC027BEFF4EDB01038148917832253EBC355FC33F4A8E2FCCE4"
                         "97B890A26C981DA8102D3BC294159D171D72810FDF7C6A691DEF02F0F7AF3FDC"
                         "53FA9E08BA5243CBCB0D797C5EE83BC6728E539EB76C2D0BF0F971EE4E909971"
                         "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"))
        (msg (%mu "599C67EA410D005B9DA90817CF03ED3B1C868E4DA4EDF00A5880B0082C237869")))
    (loop for (key-indices tweak-indices xonly aggnonce psig-indices expected)
            in '(((0 1) () ()
                  "0341432722C5CD0268D829C702CF0D1CBCE57033EED201FD335191385227C3210C03D377F2D258B64AADC0E16F26462323D701D286046A2EA93365656AFD9875982B"
                  (0 1)
                  "041DA22223CE65C92C9A0D6C2CAC828AAF1EEE56304FEC371DDF91EBB2B9EF0912F1038025857FEDEB3FF696F8B99FA4BB2C5812F6095A2E0004EC99CE18DE1E")
                 ((0 2) () ()
                  "0224AFD36C902084058B51B5D36676BBA4DC97C775873768E58822F87FE437D792028CB15929099EEE2F5DAE404CD39357591BA32E9AF4E162B8D3E7CB5EFE31CB20"
                  (2 3)
                  "1069B67EC3D2F3C7C08291ACCB17A9C9B8F2819A52EB5DF8726E17E7D6B52E9F01800260A7E9DAC450F4BE522DE4CE12BA91AEAF2B4279219EF74BE1D286ADD9")
                 ((0 2) (0) (0)
                  "0208C5C438C710F4F96A61E9FF3C37758814B8C3AE12BFEA0ED2C87FF6954FF186020B1816EA104B4FCA2D304D733E0E19CEAD51303FF6420BFD222335CAA402916D"
                  (4 5)
                  "5C558E1DCADE86DA0B2F02626A512E30A22CF5255CAEA7EE32C38E9A71A0E9148BA6C0E6EC7683B64220F0298696F1B878CD47B107B81F7188812D593971E0CC")
                 ((0 3) (0 1 2) (1 0 1)
                  "02B5AD07AFCD99B6D92CB433FBD2A28FDEB98EAE2EB09B6014EF0F8197CD58403302E8616910F9293CF692C49F351DB86B25E352901F0E237BAFDA11F1C1CEF29FFD"
                  (6 7)
                  "839B08820B681DBA8DAF4CC7B104E8F2638F9388F8D7A555DC17B6E6971D7426CE07BF6AB01F1DB50E4E33719295F4094572B79868E440FB3DEFD3FAC1DB589E"))
          do (multiple-value-bind (cache agg)
                 (bl.crypto:musig-keyagg (%mu-pick pubkeys key-indices)
                                         (%mu-tweaks tweaks tweak-indices xonly))
               (let* ((session (bl.crypto:musig-nonce-process (%mu aggnonce) msg cache))
                      (sig (bl.crypto:musig-partial-sig-agg session (%mu-pick psigs psig-indices))))
                 (is (string= expected (%mu-hex sig)))
                 (is-true (bl.crypto:verify-schnorr-signature msg sig (subseq agg 1))))))
    (multiple-value-bind (cache) (bl.crypto:musig-keyagg (%mu-pick pubkeys '(0 3))
                                                         (%mu-tweaks tweaks '(0 1 2) '(1 0 1)))
      (let ((session (bl.crypto:musig-nonce-process
                      (%mu "02B5AD07AFCD99B6D92CB433FBD2A28FDEB98EAE2EB09B6014EF0F8197CD58403302E8616910F9293CF692C49F351DB86B25E352901F0E237BAFDA11F1C1CEF29FFD")
                      msg cache)))
        (multiple-value-bind (sig index)
            (bl.crypto:musig-partial-sig-agg session (%mu-pick psigs '(7 8)))
          (is (null sig))
          (is (eql 1 index)))))))

;;; --- The secret nonce's lifetime --------------------------------------------

(test musig-secnonce-signs-once
  "The move-only MuSig2SecNonce as a consumed flag: a live nonce signs once,
is invalid from then on, and a second signing call SIGNALS rather than
reaching libsecp (which would abort) or signing again (which would leak the
key). Invalidation is idempotent and has the same effect."
  (multiple-value-bind (session cache)
      (%mu-session (%mu-pick *mu-sv-pubkeys* '(0 1 2)) (first *mu-sv-aggnonces*) *mu-sv-msg*)
    (let ((sn (%mu-secnonce-from-vector (first *mu-sv-secnonces*))))
      ;; Positive control: the fresh nonce is live and signs.
      (is-true (bl.crypto:musig-secnonce-valid-p sn))
      (is (= 32 (length (bl.crypto:musig-partial-sign sn *mu-sv-sk* cache session))))
      (is-false (bl.crypto:musig-secnonce-valid-p sn))
      (signals bl.crypto:musig-secnonce-reused
        (bl.crypto:musig-partial-sign sn *mu-sv-sk* cache session)))
    (let ((sn (%mu-secnonce-from-vector (first *mu-sv-secnonces*))))
      (bl.crypto:musig-secnonce-invalidate sn)
      (bl.crypto:musig-secnonce-invalidate sn)
      (is-false (bl.crypto:musig-secnonce-valid-p sn))
      (signals bl.crypto:musig-secnonce-reused
        (bl.crypto:musig-partial-sign sn *mu-sv-sk* cache session)))
    ;; A nonce made for ANOTHER key: libsecp's ARG_CHECK pk == keypair's key
    ;; would abort; we refuse, and the nonce is spent all the same.
    (let ((sn (%mu-secnonce-from-vector (first *mu-sv-secnonces*)))
          (other (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7)))
      (is (null (bl.crypto:musig-partial-sign sn other cache session)))
      (is-false (bl.crypto:musig-secnonce-valid-p sn)))
    ;; Opaque objects are checked before they reach C: a cache or session
    ;; with the wrong magic is an error here, an abort() inside libsecp.
    (let ((sn (%mu-secnonce-from-vector (first *mu-sv-secnonces*))))
      (signals bl.err:crypto-error
        (bl.crypto:musig-partial-sign sn *mu-sv-sk* cache
                                      (make-array 133 :element-type '(unsigned-byte 8)
                                                      :initial-element 0)))
      (signals bl.err:crypto-error
        (bl.crypto:musig-nonce-process (first *mu-sv-aggnonces*) *mu-sv-msg*
                                       (make-array 197 :element-type '(unsigned-byte 8)
                                                       :initial-element 0)))
      ;; The refused call never took the nonce.
      (is-true (bl.crypto:musig-secnonce-valid-p sn))
      (bl.crypto:musig-secnonce-invalidate sn))))

;;; --- Core's three signer steps end to end ------------------------------------

(defun %mu-signers (n)
  "N deterministic test signers as (seckey . pubkey), and their pubkeys."
  (let ((signers (loop for i from 1 to n
                       for sk = (bl.crypto:sha256 (make-array 1 :element-type '(unsigned-byte 8)
                                                                :initial-element i))
                       collect (cons sk (bl.crypto:derive-public-key sk)))))
    (values signers (mapcar #'cdr signers))))

(defun %mu-run-session (signers pubkeys sighash tweaks)
  "Every signer's nonce, then every partial signature, as Core's
CreateMuSig2Nonce / CreateMuSig2PartialSig produce them. Returns (values
AGGREGATE PUBNONCES PSIGS SECNONCES) with the alists keyed by pubkey."
  (let* ((agg (bl.crypto:musig-aggregate-pubkeys pubkeys))
         (made (loop for (sk . pk) in signers
                     collect (multiple-value-list
                              (bl.crypto:musig2-create-nonce sk sighash agg pubkeys))))
         (pubnonces (mapcar (lambda (s m) (cons (cdr s) (first m))) signers made))
         (psigs (loop for (sk . pk) in signers
                      for (nil secnonce) in made
                      collect (cons pk (bl.crypto:musig2-create-partial-sig
                                        sk sighash agg pubkeys pubnonces secnonce tweaks)))))
    (values agg pubnonces psigs (mapcar #'second made))))

(test musig2-core-flow-produces-a-valid-signature
  "Core's signer steps -- CKey::CreateMuSig2Nonce, CKey::CreateMuSig2PartialSig,
CreateMuSig2AggregateSig -- among three signers, plain and with a BIP341
x-only tweak: the aggregate is a BIP340 signature for the (tweaked) aggregate
key. Every secnonce is spent by its signature."
  (multiple-value-bind (signers pubkeys) (%mu-signers 3)
    (let ((sighash (bl.crypto:sha256 (bl.crypto:hex-to-bytes "0102"))))
      (dolist (tweaks (list '() (list (cons (bl.crypto:sha256 (bl.crypto:hex-to-bytes "03")) t))))
        (multiple-value-bind (agg pubnonces psigs secnonces)
            (%mu-run-session signers pubkeys sighash tweaks)
          (is (every (lambda (e) (= 66 (length (cdr e)))) pubnonces))
          (is (every (lambda (e) (= 32 (length (cdr e)))) psigs))
          (is (notany #'bl.crypto:musig-secnonce-valid-p secnonces))
          (let ((sig (bl.crypto:musig2-create-aggregate-sig pubkeys agg tweaks sighash
                                                            pubnonces psigs))
                (key (nth-value 1 (bl.crypto:musig-keyagg pubkeys tweaks))))
            (is (= 64 (length sig)))
            (is-true (bl.crypto:verify-schnorr-signature sighash sig (subseq key 1)))))))))

(test musig2-core-flow-refuses-a-wrong-nonce-or-participant-set
  "Positive controls for the aggregate: a partial signature made against one
set of nonces does not aggregate once another participant's nonce is swapped
(every partial signature is verified first, musig.cpp:199-204); a participant
set that does not aggregate to the expected key is refused outright; a missing
partial signature is refused."
  (multiple-value-bind (signers pubkeys) (%mu-signers 3)
    (let ((sighash (bl.crypto:sha256 (bl.crypto:hex-to-bytes "0405"))))
      (multiple-value-bind (agg pubnonces psigs) (%mu-run-session signers pubkeys sighash '())
        ;; The control: unchanged, it aggregates.
        (is (= 64 (length (bl.crypto:musig2-create-aggregate-sig pubkeys agg '() sighash
                                                                 pubnonces psigs))))
        (let ((swapped (list* (cons (car (first pubnonces))
                                    (bl.crypto:musig2-create-nonce
                                     (car (first signers)) sighash agg pubkeys))
                              (rest pubnonces))))
          (is (null (bl.crypto:musig2-create-aggregate-sig pubkeys agg '() sighash
                                                           swapped psigs))))
        (is (null (bl.crypto:musig2-create-aggregate-sig (reverse pubkeys) agg '() sighash
                                                         pubnonces psigs)))
        (is (null (bl.crypto:musig2-create-aggregate-sig pubkeys agg '() sighash
                                                         pubnonces (rest psigs))))))))

(test musig2-core-flow-refuses-a-non-participant
  "CreateMuSig2PartialSig's refusals that come BEFORE signing leave the secret
nonce live, as in Core (key.cpp:394-425 return before partial_sign): a key
that is not a participant, and a nonce set that is not complete."
  (multiple-value-bind (signers pubkeys) (%mu-signers 3)
    (let* ((sighash (bl.crypto:sha256 (bl.crypto:hex-to-bytes "0607")))
           (agg (bl.crypto:musig-aggregate-pubkeys pubkeys)))
      (multiple-value-bind (pubnonce secnonce)
          (bl.crypto:musig2-create-nonce (car (first signers)) sighash agg pubkeys)
        (let ((outsider (bl.crypto:sha256 (bl.crypto:hex-to-bytes "ff"))))
          (is (null (bl.crypto:musig2-create-partial-sig
                     outsider sighash agg pubkeys (list (cons (first pubkeys) pubnonce))
                     secnonce '())))
          (is (null (bl.crypto:musig2-create-partial-sig
                     (car (first signers)) sighash agg pubkeys
                     (list (cons (first pubkeys) pubnonce)) secnonce '())))
          (is-true (bl.crypto:musig-secnonce-valid-p secnonce))
          (bl.crypto:musig-secnonce-invalidate secnonce))))))

(test musig2-session-id-is-cores-hash
  "Core MuSig2SessionID (musig.cpp:165-170): HashWriter << CPubKey << CPubKey <<
uint256, one SHA256 -- each key behind its CompactSize length byte."
  (let ((spk (bl.crypto:hex-to-bytes
              "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"))
        (part (bl.crypto:hex-to-bytes
               "03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659"))
        (sighash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9)))
    (is (equalp (bl.crypto:sha256 (concatenate '(simple-array (unsigned-byte 8) (*))
                                               #(33) spk #(33) part sighash))
                (bl.crypto:musig2-session-id spk part sighash)))
    (is (not (equalp (bl.crypto:musig2-session-id spk part sighash)
                     (bl.crypto:musig2-session-id part spk sighash))))))

(test musig-secnonce-take-is-atomic
  "Eight threads race to sign with ONE secret nonce: exactly one partial
signature comes out and seven calls signal MUSIG-SECNONCE-REUSED -- the
compare-and-swap take is what makes the move-only nonce single-use under
concurrency, where a check-then-use would let two signers through (and hand
libsecp a zeroed nonce, which aborts the process)."
  (multiple-value-bind (session cache)
      (%mu-session (%mu-pick *mu-sv-pubkeys* '(0 1 2)) (first *mu-sv-aggnonces*) *mu-sv-msg*)
    (let* ((sn (%mu-secnonce-from-vector (first *mu-sv-secnonces*)))
           (results (make-array 8 :initial-element :none))
           (threads (loop for i below 8
                          collect (let ((i i))
                                    (bt:make-thread
                                     (lambda ()
                                       (setf (aref results i)
                                             (handler-case
                                                 (if (bl.crypto:musig-partial-sign
                                                      sn *mu-sv-sk* cache session)
                                                     :signed :refused)
                                               (bl.crypto:musig-secnonce-reused () :reused)
                                               (error (e) (princ-to-string e)))))
                                     :name "musig-race")))))
      (dolist (th threads) (sb-thread:join-thread th :default nil :timeout 30))
      (is (= 1 (count :signed results)) "results: ~S" results)
      (is (= 7 (count :reused results)) "results: ~S" results))))
