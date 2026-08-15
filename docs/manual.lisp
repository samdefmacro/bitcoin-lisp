;;;; docs/manual.lisp — PAX developer manual for bitcoin-lisp.
;;;;
;;;; Loaded by scripts/docs-check.lisp (purely additive — not part of the
;;;; bitcoin-lisp ASDF system). `scripts/dev.sh docs-check` verifies every
;;;; cl-transcript below in a cold container; a transcript whose recorded
;;;; values drift from reality fails the run.

(mgl-pax:define-package :bitcoin-lisp.docs
  (:use #:common-lisp #:mgl-pax)
  (:export #:@bitcoin-lisp-manual
           #:@docs-check-selftest))

(in-package :bitcoin-lisp.docs)

(defsection @bitcoin-lisp-manual (:title "bitcoin-lisp developer manual")
  "A Bitcoin full node implementation in Common Lisp (SBCL), layered
  crypto -> serialization -> storage/validation -> networking.
  Consensus-critical code matches Bitcoin Core behavior exactly;
  `refs/bitcoin/` is the canonical spec.

  Hashes cross the byte/hex boundary constantly (Bitcoin displays hashes
  in reverse byte order), and the crypto layer owns those conversions:

  ```cl-transcript
  (bitcoin-lisp.crypto:bytes-to-hex
   (bitcoin-lisp.crypto:hex-to-bytes \"00ff20\"))
  => \"00ff20\"
  ```")

(defsection @docs-check-selftest (:title "docs-check red self-test")
  "Deliberately broken transcript: the recorded value below is wrong, so
  verifying this section MUST fail. If it ever passes, transcript checking
  is silently off and scripts/docs-check.lisp fails the whole run.

  ```cl-transcript
  (+ 1 2)
  => 4
  ```")
