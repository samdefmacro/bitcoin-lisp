;;; Test ECDSA verify of the captured (sighash, sig) against ALL 9 pubkeys
;;; from the failing CHECKMULTISIG. If our sighash is correct (oracle confirmed),
;;; one of these MUST verify — Bitcoin Core accepts this block.

(asdf:load-system :bitcoin-lisp)

(defpackage #:diag-ecdsa (:use :cl))
(in-package #:diag-ecdsa)

(defparameter *sighash-hex*
  "b3a29cef574d19524a11845ae92d5a45bc5ecbcfe43fe8fba8577bdd840586cb")

(defparameter *sig-hex* ; 59 bytes (DER part only, hashtype already stripped)
  "303902153b78ce563f89a0ed9414f5aa28ad0d96d6795f9c630220337727dcdad75c1acb0ca731edaf9940a6ae0de52f137f94d94369f44522b81f")

;; The 9 pubkeys passed into verify-checkmultisig (in stack-pop order).
(defparameter *pubkeys-hex*
  '("033f4d9cffa30d2468cbba00ff53b3204660828708c98161a1417e6d1bf225750d"
    "02789c9853c2b45887ea265834fefdfd8434392c42504919a8864748b200e27995"
    "0283668b5d78a0b7393095e5e1a71d2dda30db124f88e26fe409c17ac4c5ffb687"
    "03c19a148747f4e270d27107cc696c45e3d286244bf85a87a3c30fe1402ee50135"
    "021d2cb68faebff30b3bb7eaabff9e92451df102d6de7a72c4773f046d4d2196b3"
    "039d57ae6f18806bd456c17e33c8ece64c1fb16ff7041de4121029b9d7e1bec123"
    "021b5584dc88386015d083bfd429db7933b7e4debb97b763b0ca685e60ee419e4e"
    "02b2d36bf1b0a0971a165269e520aa3efcf574484a58684c3a405db5461c11b626"
    "025d053203b5d92e8379a63d51b236d9b806b82e72640623b14abe337b29e56fdd"))

(defun run ()
  (let ((sighash (bitcoin-lisp.crypto:hex-to-bytes *sighash-hex*))
        (sig (bitcoin-lisp.crypto:hex-to-bytes *sig-hex*)))
    (loop for pkhex in *pubkeys-hex*
          for i from 0
          do (let ((pk (bitcoin-lisp.crypto:hex-to-bytes pkhex)))
               (multiple-value-bind (ok status)
                   (bitcoin-lisp.crypto:verify-signature sighash sig pk
                                                        :strict t :low-s nil)
                 (format t "pubkey[~D] = ~A...  ok=~A status=~A~%"
                         i (subseq pkhex 0 16) ok status))))))

(run)
