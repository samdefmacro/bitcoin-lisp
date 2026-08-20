(in-package #:bitcoin-lisp.tests)

(def-suite :miniscript-tests
  :description "Miniscript type system, script generation and parser"
  :in :bitcoin-lisp-tests)

(in-suite :miniscript-tests)

;;;; Driven by Bitcoin Core's own fixed_tests table (src/test/miniscript_tests.cpp),
;;;; extracted verbatim into tests/data/miniscript_vectors.json: 97 expressions
;;;; with their expected validity, non-malleability, signature necessity and
;;;; timelock-mix, and for 37 of them the exact P2WSH script.
;;;;
;;;; Adopting the corpus rather than writing expectations by hand is the point:
;;;; the type calculus is 25 fragment rules of boolean algebra, where a single
;;;; wrong conjunct produces a system that is self-consistent and wrong. Core's
;;;; table is the only independent check available.

(defun %ms-vectors ()
  (let ((path (merge-pathnames "tests/data/miniscript_vectors.json"
                               (asdf:system-source-directory :bitcoin-lisp))))
    (with-open-file (s path :direction :input) (yason:parse s))))

(defun %ms-flag (vector name)
  (and (member name (gethash "flags" vector) :test #'string=) t))

(defun %ms-try-parse (expr)
  "Parse EXPR, returning NIL if it is not even well-formed. An expression that
parses but does not type is a node, not an error — the caller distinguishes."
  (handler-case (bitcoin-lisp.validation::ms-parse expr)
    (bitcoin-lisp.validation::miniscript-parse-error () nil)
    ;; Some invalid vectors are malformed in ways that surface as ordinary
    ;; errors (a wrapper letter that does not exist, a bad argument count).
    (error () nil)))

(test miniscript-validity-matches-core-s-corpus
  "Which expressions type, and which do not."
  (let ((vectors (%ms-vectors))
        (mismatches '()))
    (dolist (v vectors)
      (let* ((expr (gethash "ms" v))
             ;; P2WSH is what this port implements, so a TAPSCRIPT_INVALID
             ;; vector is a VALID one here; P2WSH_INVALID is the opposite.
             (expect-valid (and (%ms-flag v "VALID")
                                (not (%ms-flag v "P2WSH_INVALID"))))
             (node (%ms-try-parse expr))
             (got-valid (and node
                             (bitcoin-lisp.validation::ms-node-valid-p node)
                             (bitcoin-lisp.validation::ms-node-valid-top-level-p node))))
        (unless (eq (and got-valid t) expect-valid)
          (push (format nil "~A: expected ~:[invalid~;valid~], got ~:[invalid~;valid~]"
                        expr expect-valid got-valid)
                mismatches))))
    (is (null mismatches) "~{~A~^~%~}" (reverse mismatches))
    (is (= 97 (length vectors)) "the corpus must not shrink unnoticed")))

(test miniscript-script-encoding-matches-core-s-corpus
  "The 37 vectors that carry an exact P2WSH script. This is where a wrong
opcode or a non-minimal push shows up, neither of which the type calculus can
see."
  (let ((checked 0) (mismatches '()))
    (dolist (v (%ms-vectors))
      (let ((expr (gethash "ms" v))
            (want (gethash "script" v)))
        (when (and want (%ms-flag v "VALID") (not (%ms-flag v "P2WSH_INVALID")))
          (let ((node (%ms-try-parse expr)))
            (when (and node (bitcoin-lisp.validation::ms-node-valid-p node))
              (incf checked)
              (let ((got (string-downcase
                          (bitcoin-lisp.crypto:bytes-to-hex
                           (bitcoin-lisp.validation::ms-node-script node)))))
                (unless (string= got (string-downcase want))
                  (push (format nil "~A~%  want ~A~%  got  ~A" expr want got)
                        mismatches))))))))
    (is (>= checked 30) "expected ~30 script vectors, checked ~D" checked)
    (is (null mismatches) "~{~A~^~%~}" (reverse mismatches))))

(test miniscript-properties-match-core-s-corpus
  "Non-malleability, signature necessity and timelock mixing — the three
properties Core's table records, and the reason the calculus tracks 15 of them
rather than just the four base types."
  (let ((nonmal '()) (needsig '()) (timelock '()))
    (dolist (v (%ms-vectors))
      (let* ((expr (gethash "ms" v))
             (node (and (%ms-flag v "VALID")
                        (not (%ms-flag v "P2WSH_INVALID"))
                        (%ms-try-parse expr))))
        (when (and node (bitcoin-lisp.validation::ms-node-valid-top-level-p node))
          (unless (eq (and (bitcoin-lisp.validation::ms-node-non-malleable-p node) t)
                      (%ms-flag v "NONMAL"))
            (push expr nonmal))
          (unless (eq (and (bitcoin-lisp.validation::ms-node-needs-signature-p node) t)
                      (%ms-flag v "NEEDSIG"))
            (push expr needsig))
          (unless (eq (and (bitcoin-lisp.validation::ms-node-timelock-mix-p node) t)
                      (%ms-flag v "TIMELOCKMIX"))
            (push expr timelock)))))
    (is (null nonmal) "malleability mismatch: ~{~A~^, ~}" (reverse nonmal))
    (is (null needsig) "signature-necessity mismatch: ~{~A~^, ~}" (reverse needsig))
    (is (null timelock) "timelock-mix mismatch: ~{~A~^, ~}" (reverse timelock))))

;;; --- Hand-checked specifics -------------------------------------------------

(test miniscript-sugar-expands-to-canonical-fragments
  "pk, pkh, and_n, t:, l: and u: have no fragments of their own — Core
represents them as their expansions, so anything walking the tree sees only
canonical forms. If they were kept as distinct fragments, every consumer would
have to know about them."
  (flet ((frag (expr) (bitcoin-lisp.validation::ms-node-fragment
                       (bitcoin-lisp.validation::ms-parse expr)))
         (subfrags (expr) (mapcar #'bitcoin-lisp.validation::ms-node-fragment
                                  (bitcoin-lisp.validation::ms-node-subs
                                   (bitcoin-lisp.validation::ms-parse expr)))))
    (let ((key "03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65"))
      ;; pk(K) = c:pk_k(K)
      (is (eq :wrap-c (frag (format nil "pk(~A)" key))))
      (is (equal '(:pk-k) (subfrags (format nil "pk(~A)" key))))
      ;; pkh(K) = c:pk_h(K)
      (is (eq :wrap-c (frag (format nil "pkh(~A)" key))))
      (is (equal '(:pk-h) (subfrags (format nil "pkh(~A)" key)))))
    ;; and_n(X,Y) = andor(X,Y,0)
    (is (eq :andor (frag "and_n(0,1)")))
    (is (equal '(:just-0 :just-1 :just-0) (subfrags "and_n(0,1)")))
    ;; t:X = and_v(X,1)
    (is (eq :and-v (frag "t:v:1")))
    (is (equal '(:wrap-v :just-1) (subfrags "t:v:1")))
    ;; l:X = or_i(0,X) and u:X = or_i(X,0)
    (is (equal '(:just-0 :older) (subfrags "l:older(1)")))
    (is (equal '(:after :just-0) (subfrags "u:after(1)")))))

(test miniscript-wrappers-apply-right-to-left
  "`vc:X' is v(c(X)), not c(v(X)). Getting this backwards produces a tree that
often still types, so it has to be checked directly."
  (let* ((key "03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65")
         (node (bitcoin-lisp.validation::ms-parse (format nil "vc:pk_k(~A)" key))))
    (is (eq :wrap-v (bitcoin-lisp.validation::ms-node-fragment node)))
    (let ((inner (first (bitcoin-lisp.validation::ms-node-subs node))))
      (is (eq :wrap-c (bitcoin-lisp.validation::ms-node-fragment inner)))
      (is (eq :pk-k (bitcoin-lisp.validation::ms-node-fragment
                     (first (bitcoin-lisp.validation::ms-node-subs inner))))))))

(test miniscript-verify-wrapper-converts-rather-than-appending
  "`v:' is free on an expression whose last opcode has a -VERIFY form — Core
switches the opcode instead of appending OP_VERIFY, and the 'x' property is
exactly the flag for `cannot do that'. So v:c:pk_k(K) must end in
OP_CHECKSIGVERIFY and be the same LENGTH as c:pk_k(K), while v:older(1) must
grow by one byte."
  (let* ((key "03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65")
         (plain (bitcoin-lisp.validation::ms-node-script
                 (bitcoin-lisp.validation::ms-parse (format nil "c:pk_k(~A)" key))))
         (verified (bitcoin-lisp.validation::ms-node-script
                    (bitcoin-lisp.validation::ms-parse (format nil "vc:pk_k(~A)" key)))))
    (is (= (length plain) (length verified)))
    (is (= #xac (aref plain (1- (length plain)))) "OP_CHECKSIG")
    (is (= #xad (aref verified (1- (length verified)))) "OP_CHECKSIGVERIFY"))
  ;; older() ends in OP_CHECKSEQUENCEVERIFY, which has no -VERIFY form: 'x'.
  (let ((plain (bitcoin-lisp.validation::ms-node-script
                (bitcoin-lisp.validation::ms-parse "older(1)")))
        (verified (bitcoin-lisp.validation::ms-node-script
                   (bitcoin-lisp.validation::ms-parse "v:older(1)"))))
    (is (= (1+ (length plain)) (length verified)))
    (is (= #x69 (aref verified (1- (length verified)))) "OP_VERIFY appended")))

(test miniscript-invalid-expressions-have-no-type-rather-than-erroring
  "The calculus's error channel is a type of zero, not a condition. That is why
a sub-expression that fails to type must poison its parent explicitly — a zero
would otherwise read as `no properties' and the parent could type fine."
  ;; andor requires X to be Bdu; `1' is Bu but not d.
  (let ((node (bitcoin-lisp.validation::ms-parse "andor(1,1,1)")))
    (is-true node)
    (is-false (bitcoin-lisp.validation::ms-node-valid-p node)))
  ;; A valid expression wrapped around an invalid one stays invalid.
  (let ((node (bitcoin-lisp.validation::ms-parse "and_v(v:andor(1,1,1),1)")))
    (is-true node)
    (is-false (bitcoin-lisp.validation::ms-node-valid-p node)))
  ;; Genuinely malformed input is a parse error, which is a different thing.
  (signals bitcoin-lisp.validation::miniscript-parse-error
    (bitcoin-lisp.validation::ms-parse "nosuchfragment(1)")))

;;; --- Inside a descriptor ----------------------------------------------------

;;; DEFPARAMETER, not DEFCONSTANT: defconstant compares with EQL, and two
;;; string literals with the same characters are not EQL — so reloading the
;;; compiled file signals DEFCONSTANT-UNEQL. The warm image never sees it
;;; (the form runs once); the cold battery does, on the second load.
(defparameter *ms-desc-key-a*
  "03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65")
(defparameter *ms-desc-key-b*
  "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556")

(defun %ms-desc-spk (string &optional (pos 0))
  (let ((d (bitcoin-lisp.rpc::parse-descriptor string :mainnet)))
    (string-downcase
     (bitcoin-lisp.crypto:bytes-to-hex
      (first (bitcoin-lisp.rpc::%out-desc-expand-uncached d pos))))))

(defun %ms-desc-witness-script (string &optional (pos 0))
  (let* ((d (bitcoin-lisp.rpc::parse-descriptor string :mainnet))
         (inner (bitcoin-lisp.rpc::out-desc-sub d)))
    (string-downcase
     (bitcoin-lisp.crypto:bytes-to-hex
      (first (bitcoin-lisp.rpc::%out-desc-expand-1
              inner pos
              (lambda (k) (bitcoin-lisp.rpc::%desc-key-pubkey-at k pos))))))))

(test wsh-accepts-a-miniscript-policy
  "The point of G7-41: a timelocked recovery policy is expressible as a
descriptor at all. wsh(and_v(v:pk(K),older(144))) compiles to
  <K> OP_CHECKSIGVERIFY <144> OP_CHECKSEQUENCEVERIFY
which is checked byte for byte here, because it exercises three things at once:
the -VERIFY conversion (0xad, not 0xac followed by OP_VERIFY), the minimal
CScriptNum encoding of 144 (0x9000 — two bytes, because 0x90 alone would read
as negative), and the fragment order."
  (let ((desc (format nil "wsh(and_v(v:pk(~A),older(144)))" *ms-desc-key-a*)))
    (is (string= (format nil "21~Aad029000b2" (string-downcase *ms-desc-key-a*))
                 (%ms-desc-witness-script desc)))
    ;; And the outer script is the ordinary P2WSH commitment to it.
    (let ((spk (%ms-desc-spk desc)))
      (is (= 68 (length spk)))
      (is (string= "0020" (subseq spk 0 4))))))

(test wsh-miniscript-covers-the-shapes-policy-wallets-use
  "or_d for a spend-or-recover branch, thresh for a decaying multisig, and a
nested and_v — the shapes G7-41 names as unimportable today."
  (dolist (expr (list
                 ;; Either key A signs, or after a delay key B does.
                 (format nil "or_d(pk(~A),and_v(v:pk(~A),older(1008)))"
                         *ms-desc-key-a* *ms-desc-key-b*)
                 ;; 2-of-2 by threshold rather than CHECKMULTISIG.
                 (format nil "thresh(2,pk(~A),s:pk(~A))"
                         *ms-desc-key-a* *ms-desc-key-b*)
                 ;; An absolute-height branch.
                 (format nil "or_i(pk(~A),and_v(v:pk(~A),after(500000)))"
                         *ms-desc-key-a* *ms-desc-key-b*)))
    (let ((desc (format nil "wsh(~A)" expr)))
      (let ((spk (%ms-desc-spk desc)))
        (is (= 68 (length spk)) "~A must expand to a P2WSH scriptPubKey" expr)
        (is (string= "0020" (subseq spk 0 4)))))))

(test wsh-miniscript-derives-a-whole-range-from-one-parsed-node
  "The design claim behind making the key converter a parameter: a miniscript
holds key EXPRESSIONS, so one parsed node serves every index of a ranged
descriptor and each index gets a different script."
  (let* ((xpub "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y")
         (desc (format nil "wsh(and_v(v:pk(~A/*),older(10)))" xpub))
         (s0 (%ms-desc-spk desc 0))
         (s1 (%ms-desc-spk desc 1))
         (s2 (%ms-desc-spk desc 2)))
    (is (= 68 (length s0)))
    (is (not (string= s0 s1)) "each range index must give its own script")
    (is (not (string= s1 s2)))
    ;; Re-deriving the same index is stable.
    (is (string= s0 (%ms-desc-spk desc 0)))))

(test miniscript-is-refused-outside-wsh
  "Core only accepts miniscript inside wsh(): the type rules and the resource
limits are stated for a specific script context, and P2WSH is the one this
implements. Accepting it at top level or inside sh() would produce scripts
whose limits were never checked."
  (let ((expr (format nil "and_v(v:pk(~A),older(144))" *ms-desc-key-a*)))
    (signals error (bitcoin-lisp.rpc::parse-descriptor expr :mainnet))
    (signals error (bitcoin-lisp.rpc::parse-descriptor
                    (format nil "sh(~A)" expr) :mainnet))
    ;; But sh(wsh(...)) is fine, since the miniscript is still in a wsh.
    (is-true (bitcoin-lisp.rpc::parse-descriptor
              (format nil "sh(wsh(~A))" expr) :mainnet))))

(test a-miniscript-that-does-not-type-is-refused-by-the-descriptor
  "An expression can be well-formed and still break the type rules. The
descriptor layer must reject it rather than build a script from a node whose
type is zero — that script would be unspendable or malleable, and the whole
point of miniscript is to know so in advance."
  ;; andor requires its first argument to be Bdu; `1' is not d.
  (signals error (bitcoin-lisp.rpc::parse-descriptor "wsh(andor(1,1,1))" :mainnet))
  ;; A K-type expression is not valid at top level; it needs a c: wrapper.
  (signals error (bitcoin-lisp.rpc::parse-descriptor
                  (format nil "wsh(pk_k(~A))" *ms-desc-key-a*) :mainnet))
  ;; older(0) is out of range.
  (signals error (bitcoin-lisp.rpc::parse-descriptor
                  (format nil "wsh(and_v(v:pk(~A),older(0)))" *ms-desc-key-a*)
                  :mainnet)))
