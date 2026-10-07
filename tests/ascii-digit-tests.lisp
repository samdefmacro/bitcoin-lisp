(in-package #:bitcoin-lisp.tests)

;;;; Core's digits are ASCII: IsDigit (util/strencodings.h:150), HexDigit
;;;; (util/strencodings.cpp:22-40) and the ToIntegral/ParseInt family built on
;;;; them. CL's DIGIT-CHAR-P and PARSE-INTEGER take every Unicode decimal digit
;;;; -- SBCL reads U+0663 ARABIC-INDIC DIGIT THREE as 3 -- and so did every
;;;; parser of outside input built on them. Cross-cutting: one representative
;;;; site per layer (RPC, CLI, config, the hex codec).

(def-suite :ascii-digit-tests
  :description "Core's ASCII-only digits at the parsers of outside input"
  :in :bitcoin-lisp-tests)

(in-suite :ascii-digit-tests)

(defparameter +arabic-indic-three+ (code-char #x663)
  "A character CL calls a decimal digit (weight 3) and Core does not.")

(test ascii-digit-predicates-are-cores
  "The predicates and the integer parser take 0-9 (and a-f, A-F) only."
  (is-true (every #'bl.bytes:ascii-digit-p "0123456789"))
  (is-true (every #'bl.bytes:ascii-hex-digit-p "0123456789abcdefABCDEF"))
  (is-false (bl.bytes:ascii-digit-p +arabic-indic-three+))
  (is-false (bl.bytes:ascii-hex-digit-p +arabic-indic-three+))
  (is-false (bl.bytes:ascii-hex-digit-p #\g))
  (is (= 12 (bl.bytes:parse-ascii-integer "12")))
  (is (equal '(1 1) (multiple-value-list
                     (bl.bytes:parse-ascii-integer (format nil "1~C" +arabic-indic-three+)
                                                   :junk-allowed t)))
      "a non-ASCII digit is junk, at the caller's own index")
  (signals error (bl.bytes:parse-ascii-integer (string +arabic-indic-three+))))

(test unicode-digits-are-refused-where-outside-input-is-parsed
  "Each site was red before: the RPC hash check accepted the hash, the CLI
took `:1<U+0663>' as port 13, -dbcache-style atoi read 13, and the hex codec
decoded the byte 0x03."
  (let ((three +arabic-indic-three+))
    (is-false (bl.rpc:valid-hex-hash-p
               (concatenate 'string (make-string 63 :initial-element #\a) (string three)))
              "RPC: a block hash is 64 ASCII hex digits (ParseHashV's IsHex)")
    (is-false (nth-value 2 (bl.cli:split-rpc-host-port (format nil "127.0.0.1:1~C" three)))
              "CLI: -rpcconnect's port is ToIntegral<uint16_t>")
    (is (= 1 (bl.cfg:locale-independent-atoi (format nil "1~C" three)))
        "config: LocaleIndependentAtoi stops at the first non-digit")
    (signals error (bl.crypto:hex-to-bytes (format nil "0~C" three))
      "the hex codec: ParseHex refuses a non-hex character")))
