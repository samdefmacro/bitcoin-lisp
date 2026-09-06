(in-package #:bitcoin-lisp.tests)

;;;; SanitizeString (Core util/strencodings.cpp:22-39).
;;;;
;;;; Core filters peer-supplied text to a fixed safe set at the BOUNDARY rather
;;;; than escaping it at every use: the subversion is stored as
;;;; SanitizeString(strSubVer) and every log line that prints a peer-supplied
;;;; message type wraps it the same way. That layer is what makes
;;;; LogEscapeMessage's deliberate newline pass-through safe -- without it a
;;;; peer writes extra debug.log lines of its own (GA11 1052063f).

(def-suite :sanitize-tests
  :description "Core SanitizeString: the safe-character rules, applied where peer bytes enter"
  :in :bitcoin-lisp-tests)

(in-suite :sanitize-tests)

(test sanitize-string-drops-the-characters-that-forge-a-log-line
  "Newline, carriage return and ESC are all outside SAFE_CHARS_DEFAULT, so a
user agent carrying them comes back as one line of ordinary text."
  (let* ((forged (concatenate 'string
                              "/Satoshi:27.0/" (string #\Newline)
                              "2026-09-06 FORGED Shutdown: done"
                              (string #\Return)
                              (string (code-char 27)) "[31m"))
         (clean (bl.bytes:sanitize-string forged)))
    (is (null (find #\Newline clean)) "a newline survived: ~S" clean)
    (is (null (find #\Return clean)) "a carriage return survived: ~S" clean)
    (is (null (find (code-char 27) clean)) "an ESC survived: ~S" clean)
    ;; The bracket of the ANSI sequence is not in the safe set either.
    (is (null (find #\[ clean)))
    ;; Positive control: the sanitizer must actually be dropping bytes here,
    ;; or the assertions above would hold for any input.
    (is (< (length clean) (length forged))
        "positive control: nothing was dropped from ~S" forged)
    ;; What a real user agent is made of survives untouched.
    (is (string= "/Satoshi:27.0/" (subseq clean 0 14)))))

(test sanitize-string-rules-are-cores-tables
  "The four rule sets, character for character (strencodings.cpp:22-27):
DEFAULT admits \" .,;-_/:?@()\", UA_COMMENT drops the slash, colon and
parentheses, FILENAME keeps only \".-_\", URI is the widest."
  (let ((punctuation " .,;-_/:?@()!*'&=+$#[]~%"))
    (is (string= " .,;-_/:?@()" (bl.bytes:sanitize-string punctuation :default)))
    (is (string= " .,;-_?@" (bl.bytes:sanitize-string punctuation :ua-comment)))
    (is (string= ".-_" (bl.bytes:sanitize-string punctuation :filename)))
    (is (string= ".,;-_/:?@()!*'&=+$#[]~%"
                 (bl.bytes:sanitize-string punctuation :uri))
        "SAFE_CHARS_URI admits everything here but the space"))
  ;; Alphanumerics pass under every rule.
  (dolist (rule '(:default :ua-comment :filename :uri))
    (is (string= "abcXYZ019" (bl.bytes:sanitize-string "abcXYZ019" rule)))))

(test sanitize-string-alphanumeric-means-ascii
  "Core's CHARS_ALPHA_NUM is a literal ASCII string, so a Latin-1 or CJK letter
is NOT alphanumeric and gets dropped. CL:ALPHANUMERICP is true of every Unicode
letter; a sanitizer written with it would admit characters Core drops, and the
node's -uacomment gate is the same test."
  (let ((s (coerce (list #\a (code-char 233) (code-char 20013) #\Z) 'string)))
    (is (string= "aZ" (bl.bytes:sanitize-string s))
        "non-ASCII letters must be dropped, got ~S" (bl.bytes:sanitize-string s))
    ;; Positive control on the premise: CL:ALPHANUMERICP does accept them, so
    ;; the assertion above is testing the rule and not the input.
    (is-true (alphanumericp (code-char 233)))
    (is-true (alphanumericp (code-char 20013))))
  ;; The -uacomment gate rides on the same rule (Core init.cpp:1676-1686).
  (is-false (bl:ua-comment-safe-p (coerce (list (code-char 233)) 'string)))
  (is-true (bl:ua-comment-safe-p "bitcoin-lisp node 1"))
  (is-false (bl:ua-comment-safe-p "no/slashes")))
