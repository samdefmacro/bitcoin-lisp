(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/descriptor_parse.cpp at the pin, its
;;;; mocked_descriptor_parse target (:84-101) -- descriptor_parse is in
;;;; wallet.lisp. The buffer is a descriptor with `%XX' standing for key XX of
;;;; MockedDescriptorConverter's 256 (test/fuzz/util/descriptor.cpp:17-83):
;;;; by XX mod 6 a compressed, uncompressed or x-only pubkey, a WIF, an xpub
;;;; or an xprv, all from the 32-byte seed 01 00 .. 00 XX on mainnet. So the
;;;; fuzzer composes deep descriptors and miniscript out of keys that are
;;;; always valid, which raw text almost never reaches.
;;;;
;;;; Every descriptor a string parses to is held to Core's TestDescriptor
;;;; (:20-61) where ours has the counterpart: the descriptors one string
;;;; yields agree on IsRange and IsSolvable; each one's string parses back to
;;;; itself; Expand answers scripts or asks for private keys, and an unranged
;;;; one expands the same at every position.

(def-suite :fuzz-descriptor-parse-tests :in :bitcoin-lisp-tests
  :description "Core fuzz descriptor_parse.cpp (mocked_descriptor_parse)")

(in-suite :fuzz-descriptor-parse-tests)

(defvar *mocked-descriptor-keys* nil
  "MockedDescriptorConverter::keys_str, built on first use.")

(defun %mocked-descriptor-keys ()
  "MockedDescriptorConverter::Init: key i from the data 01 00 .. 00 i -- by
i mod 6 a compressed, uncompressed or x-only pubkey's hex, a compressed WIF,
the seed's master xpub or xprv."
  (or *mocked-descriptor-keys*
      (setf *mocked-descriptor-keys*
            (coerce
             (loop for i below 256
                   collect (let ((data (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
                             (setf (aref data 0) 1 (aref data 31) i)
                             (case (mod i 6)
                               (0 (bl.crypto:bytes-to-hex (bl.crypto:derive-public-key data)))
                               (1 (bl.crypto:bytes-to-hex (bl.crypto:derive-public-key data :compressed nil)))
                               (2 (bl.crypto:bytes-to-hex (subseq (bl.crypto:derive-public-key data) 1)))
                               (3 (bl.crypto:private-key-to-wif data :network :mainnet))
                               (t (let ((master (bl.crypto:bip32-master-key data :network :mainnet)))
                                    (bl.crypto:bip32-serialize (if (= 4 (mod i 6))
                                                                   (bl.crypto:bip32-neuter master)
                                                                   master)))))))
             'simple-vector))))

(defun %mocked-descriptor (text)
  "MockedDescriptorConverter::GetDescriptor (:59-83): every `%XX' replaced by
key XX; NIL for a string under seven characters or a `%' not followed by
two hex digits."
  (when (>= (length text) 7)
    (with-output-to-string (out)
      (loop with i = 0
            while (< i (length text))
            do (if (char= (char text i) #\%)
                   (let ((idx (and (< (+ i 3) (length text))
                                   (every (lambda (c) (find c "0123456789abcdefABCDEF")) (subseq text (1+ i) (+ i 3)))
                                   (parse-integer text :start (1+ i) :end (+ i 3) :radix 16))))
                     (unless idx (return-from %mocked-descriptor nil))
                     (write-string (aref (%mocked-descriptor-keys) idx) out)
                     (incf i 3))
                   (progn (write-char (char text i) out) (incf i)))))))

(defun %mocked-descriptor-corpus (fdp)
  "A mocked descriptor: Core's descriptor and miniscript shapes over %XX keys,
with origins and derivation steps after the extended ones."
  (labels ((key ()
             (let ((k (consume-integral fdp :u8)))
               (format nil "~:[~;[deadbeef/0h]~]%~2,'0X~A" (zerop (consume-integral-in-range fdp 0 3)) k
                       (if (>= (mod k 6) 4) (pick-value-in-array fdp '("" "/0" "/*" "/1/*" "/0h/*" "/<0;1>/*")) ""))))
           (ms (depth)
             (if (zerop depth)
                 (call-one-of fdp
                   (format nil "pk(~A)" (key))
                   (format nil "pkh(~A)" (key))
                   (format nil "older(~D)" (consume-integral-in-range fdp 1 70000))
                   (format nil "sha256(~A)" (bl.crypto:bytes-to-hex (consume-uint256 fdp))))
                 (call-one-of fdp
                   (format nil "and_v(v:~A,~A)" (ms (1- depth)) (ms (1- depth)))
                   (format nil "or_d(~A,~A)" (ms (1- depth)) (ms (1- depth)))
                   (format nil "or_b(~A,s:~A)" (ms (1- depth)) (ms (1- depth)))
                   (format nil "thresh(~D,~A,s:~A)" (consume-integral-in-range fdp 1 2) (ms (1- depth)) (ms (1- depth)))
                   (format nil "multi(~D,~A,~A)" (consume-integral-in-range fdp 1 2) (key) (key))))))
    (%octets-of-string
     (call-one-of fdp
       (format nil "pk(~A)" (key))
       (format nil "wpkh(~A)" (key))
       (format nil "sh(wpkh(~A))" (key))
       (format nil "combo(~A)" (key))
       (format nil "sh(sortedmulti(~D,~A,~A,~A))" (consume-integral-in-range fdp 1 3) (key) (key) (key))
       (format nil "wsh(~A)" (ms (consume-integral-in-range fdp 0 3)))
       (format nil "sh(wsh(~A))" (ms (consume-integral-in-range fdp 0 2)))
       (format nil "tr(~A)" (key))
       (format nil "tr(~A,{pk(~A),multi_a(1,~A,~A)})" (key) (key) (key) (key))
       (format nil "tr(~A,~A)" (key) (ms (consume-integral-in-range fdp 0 2)))))))

(define-fuzz-target mocked-descriptor-parse
    (buffer :core "descriptor_parse.cpp:84-101" :corpus #'%mocked-descriptor-corpus
            :iterations 1500 :max-len 400)
  "A descriptor composed of valid keys parses to descriptors that agree on
IsRange and IsSolvable, print as strings that parse back to themselves, and
expand to scripts (the same at every position when unranged) or ask for
private keys."
  (let ((text (%mocked-descriptor (map 'string #'code-char buffer))))
    (unless text (fuzz-reject))
    (let ((descs (%parse-descriptors-or-nil text :mainnet nil)))
      (when descs
        (let ((ranged (bl.rpc:out-desc-ranged-p (first descs)))
              (solvable (bl.rpc:out-desc-solvable-p (first descs))))
          (dolist (d descs)
            (fuzz-assert (eq (fuzz-sabotage (bl.rpc:out-desc-ranged-p d)) ranged) "IsRange differs across ~S" text)
            (fuzz-assert (eq (bl.rpc:out-desc-solvable-p d) solvable) "IsSolvable differs across ~S" text)
            (let* ((canonical (bl.rpc:out-desc-string d))
                   (again (%parse-descriptors-or-nil canonical :mainnet nil)))
              (fuzz-assert (and again (string= (bl.rpc:out-desc-string (first again)) canonical))
                           "~S prints as ~S, which does not parse back to itself" text canonical))
            (let ((at0 (%expand-or-nil d 0)))
              (unless (or ranged (eq at0 :needs-private-keys))
                (fuzz-assert (equalp at0 (%expand-or-nil d 5))
                             "unranged ~S expands differently at 0 and 5" text)))))))))
