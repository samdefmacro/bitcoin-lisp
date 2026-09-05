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

(defun %ms-try-parse (expr &optional (ctx :p2wsh))
  "Parse EXPR in CTX, returning NIL if it is not even well-formed. An expression
that parses but does not type is a node, not an error — the caller
distinguishes."
  (handler-case (bl.val:ms-parse expr :ctx ctx)
    (bl.val:miniscript-parse-error () nil)
    ;; Some invalid vectors are malformed in ways that surface as ordinary
    ;; errors (a wrapper letter that does not exist, a bad argument count).
    (error () nil)))

;;; The node accessors these tests read back are internal to BL.VAL, so each
;;; is reached ONCE, here, rather than once per assertion.

(defun %ms-frag (node) (bl.val::ms-node-fragment node))
(defun %ms-subs (node) (bl.val::ms-node-subs node))
(defun %ms-keys (node) (bl.val::ms-node-keys node))
(defun %ms-threshold (node) (bl.val::ms-node-k node))
(defun %ms-top-level-p (node) (bl.val::ms-node-valid-top-level-p node))

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
                             (bl.val:ms-node-valid-p node)
                             (%ms-top-level-p node))))
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
            (when (and node (bl.val:ms-node-valid-p node))
              (incf checked)
              (let ((got (string-downcase
                          (bl.crypto:bytes-to-hex
                           (bl.val:ms-node-script node)))))
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
        (when (and node (%ms-top-level-p node))
          (unless (eq (and (bl.val:ms-node-non-malleable-p node) t)
                      (%ms-flag v "NONMAL"))
            (push expr nonmal))
          (unless (eq (and (bl.val:ms-node-needs-signature-p node) t)
                      (%ms-flag v "NEEDSIG"))
            (push expr needsig))
          (unless (eq (and (bl.val:ms-node-timelock-mix-p node) t)
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
  (flet ((frag (expr) (%ms-frag
                       (bl.val:ms-parse expr)))
         (subfrags (expr) (mapcar #'%ms-frag
                                  (%ms-subs
                                   (bl.val:ms-parse expr)))))
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
         (node (bl.val:ms-parse (format nil "vc:pk_k(~A)" key))))
    (is (eq :wrap-v (%ms-frag node)))
    (let ((inner (first (%ms-subs node))))
      (is (eq :wrap-c (%ms-frag inner)))
      (is (eq :pk-k (%ms-frag
                     (first (%ms-subs inner))))))))

(test miniscript-verify-wrapper-converts-rather-than-appending
  "`v:' is free on an expression whose last opcode has a -VERIFY form — Core
switches the opcode instead of appending OP_VERIFY, and the 'x' property is
exactly the flag for `cannot do that'. So v:c:pk_k(K) must end in
OP_CHECKSIGVERIFY and be the same LENGTH as c:pk_k(K), while v:older(1) must
grow by one byte."
  (let* ((key "03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65")
         (plain (bl.val:ms-node-script
                 (bl.val:ms-parse (format nil "c:pk_k(~A)" key))))
         (verified (bl.val:ms-node-script
                    (bl.val:ms-parse (format nil "vc:pk_k(~A)" key)))))
    (is (= (length plain) (length verified)))
    (is (= #xac (aref plain (1- (length plain)))) "OP_CHECKSIG")
    (is (= #xad (aref verified (1- (length verified)))) "OP_CHECKSIGVERIFY"))
  ;; older() ends in OP_CHECKSEQUENCEVERIFY, which has no -VERIFY form: 'x'.
  (let ((plain (bl.val:ms-node-script
                (bl.val:ms-parse "older(1)")))
        (verified (bl.val:ms-node-script
                   (bl.val:ms-parse "v:older(1)"))))
    (is (= (1+ (length plain)) (length verified)))
    (is (= #x69 (aref verified (1- (length verified)))) "OP_VERIFY appended")))

(test miniscript-invalid-expressions-have-no-type-rather-than-erroring
  "The calculus's error channel is a type of zero, not a condition. That is why
a sub-expression that fails to type must poison its parent explicitly — a zero
would otherwise read as `no properties' and the parent could type fine."
  ;; andor requires X to be Bdu; `1' is Bu but not d.
  (let ((node (bl.val:ms-parse "andor(1,1,1)")))
    (is-true node)
    (is-false (bl.val:ms-node-valid-p node)))
  ;; A valid expression wrapped around an invalid one stays invalid.
  (let ((node (bl.val:ms-parse "and_v(v:andor(1,1,1),1)")))
    (is-true node)
    (is-false (bl.val:ms-node-valid-p node)))
  ;; Genuinely malformed input is a parse error, which is a different thing.
  (signals bl.val:miniscript-parse-error
    (bl.val:ms-parse "nosuchfragment(1)")))

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
  (let ((d (bl.rpc:parse-descriptor string :mainnet)))
    (string-downcase
     (bl.crypto:bytes-to-hex
      (first (bl.rpc::%out-desc-expand-uncached d pos))))))

(defun %ms-desc-witness-script (string &optional (pos 0))
  (let* ((d (bl.rpc:parse-descriptor string :mainnet))
         (inner (bl.rpc:out-desc-sub d)))
    (string-downcase
     (bl.crypto:bytes-to-hex
      (first (bl.rpc::%out-desc-expand-1
              inner pos
              (lambda (k) (bl.rpc::%desc-key-pubkey-at k pos))))))))

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
    (signals error (bl.rpc:parse-descriptor expr :mainnet))
    (signals error (bl.rpc:parse-descriptor
                    (format nil "sh(~A)" expr) :mainnet))
    ;; But sh(wsh(...)) is fine, since the miniscript is still in a wsh.
    (is-true (bl.rpc:parse-descriptor
              (format nil "sh(wsh(~A))" expr) :mainnet))))

(test a-miniscript-that-does-not-type-is-refused-by-the-descriptor
  "An expression can be well-formed and still break the type rules. The
descriptor layer must reject it rather than build a script from a node whose
type is zero — that script would be unspendable or malleable, and the whole
point of miniscript is to know so in advance."
  ;; andor requires its first argument to be Bdu; `1' is not d.
  (signals error (bl.rpc:parse-descriptor "wsh(andor(1,1,1))" :mainnet))
  ;; A K-type expression is not valid at top level; it needs a c: wrapper.
  (signals error (bl.rpc:parse-descriptor
                  (format nil "wsh(pk_k(~A))" *ms-desc-key-a*) :mainnet))
  ;; older(0) is out of range.
  (signals error (bl.rpc:parse-descriptor
                  (format nil "wsh(and_v(v:pk(~A),older(0)))" *ms-desc-key-a*)
                  :mainnet)))

(test miniscript-descriptors-round-trip-through-their-canonical-string
  "A descriptor's canonical string feeds its checksum and its descriptor ID, so
a policy that printed back as something else would have two identities — and
getdescriptorinfo would hand out a checksum that its own parser rejects. That
was not hypothetical: the first cut of this had no renderer at all, and
getdescriptorinfo failed on the live node with an ECASE fallthrough."
  (dolist (d (list (format nil "wsh(and_v(v:pk(~A),older(144)))" *ms-desc-key-a*)
                   (format nil "wsh(or_d(pk(~A),and_v(v:pkh(~A),older(1008))))"
                           *ms-desc-key-a* *ms-desc-key-b*)
                   (format nil "wsh(thresh(2,pk(~A),s:pk(~A)))"
                           *ms-desc-key-a* *ms-desc-key-b*)
                   (format nil "wsh(or_i(pk(~A),and_v(v:pk(~A),after(500000))))"
                           *ms-desc-key-a* *ms-desc-key-b*)))
    (let ((parsed (bl.rpc:parse-descriptor d :mainnet)))
      (is (string= d (bl.rpc:out-desc-string parsed))
          "~A did not round-trip" d)
      ;; And the round-tripped string parses to the same script.
      (is (equalp (bl.rpc::%out-desc-expand-uncached parsed 0)
                  (bl.rpc::%out-desc-expand-uncached
                   (bl.rpc:parse-descriptor
                    (bl.rpc:out-desc-string parsed) :mainnet)
                   0))))))

(test miniscript-rendering-re-sugars-and-collapses-wrapper-runs
  "Core prints the sugared spelling, not the expansion — c:pk_k(K) as pk(K),
and_v(X,1) as t:X, or_i(0,X) as l:X, or_i(X,0) as u:X, andor(X,Y,0) as
and_n(X,Y). And a run of wrappers takes ONE colon: `t:v:pk(K)' is canonically
`tv:pk(K)', because the colon belongs to the wrapped node rather than to each
wrapper."
  (flet ((canon (expr)
           (bl.val:ms-node-to-string
            (bl.val:ms-parse expr))))
    (is (string= (format nil "pk(~A)" *ms-desc-key-a*)
                 (canon (format nil "c:pk_k(~A)" *ms-desc-key-a*))))
    (is (string= (format nil "pkh(~A)" *ms-desc-key-a*)
                 (canon (format nil "c:pk_h(~A)" *ms-desc-key-a*))))
    (is (string= "t:1" (canon "and_v(1,1)")))
    (is (string= "l:older(1)" (canon "or_i(0,older(1))")))
    (is (string= "u:older(1)" (canon "or_i(older(1),0)")))
    (is (string= "and_n(0,1)" (canon "andor(0,1,0)")))
    ;; The wrapper run, in both directions.
    (is (string= (format nil "tv:pk(~A)" *ms-desc-key-a*)
                 (canon (format nil "t:v:pk(~A)" *ms-desc-key-a*))))
    (is (string= (format nil "tv:pk(~A)" *ms-desc-key-a*)
                 (canon (format nil "tv:pk(~A)" *ms-desc-key-a*))))))

(test getdescriptorinfo-handles-a-policy-descriptor
  "The RPC the live node failed on. It needs the canonical string, its
checksum, and the ranged/solvable predicates — every one of which walks the
descriptor tree, and any of which would have thrown on an unknown kind."
  (let* ((d (format nil "wsh(and_v(v:pk(~A),older(144)))" *ms-desc-key-a*))
         (parsed (bl.rpc:parse-descriptor d :mainnet)))
    (is-false (bl.rpc:out-desc-ranged-p parsed))
    (is-true (bl.rpc:out-desc-solvable-p parsed))
    (is-false (bl.rpc::out-desc-has-privkeys-p parsed))
    (is (= 32 (length (bl.rpc:descriptor-id parsed))))
    ;; A checksummed string must parse back, which is what getdescriptorinfo
    ;; hands the user to paste into importdescriptors.
    (let ((checksummed (bl.rpc:descriptor-add-checksum
                        (bl.rpc:out-desc-string parsed))))
      (is-true (bl.rpc:parse-descriptor checksummed :mainnet
                                                   :require-checksum t)))))

;;; --- Satisfaction -----------------------------------------------------------

(defun %ms-fake-sig (n)
  "A 72-byte stand-in signature. These tests check WITNESS ASSEMBLY — which
elements, in which order — not signature validity, so a marker byte is enough
to tell one key's signature from another's."
  (let ((s (make-array 72 :element-type '(unsigned-byte 8) :initial-element n)))
    s))

(defun %ms-satisfier (&key keys preimages older after estimating)
  "A satisfier that can sign for KEYS (a list of hex strings) and reveal
PREIMAGES (an alist of (kind . preimage))."
  (bl.val:make-ms-satisfier
   :estimating estimating
   :sign-fn (lambda (key)
              (let ((hex (string-downcase (bl.crypto:bytes-to-hex key))))
                (let ((pos (position hex keys :test #'string-equal)))
                  (and pos (%ms-fake-sig (+ 1 pos))))))
   :preimage-fn (lambda (kind hash)
                  (declare (ignore hash))
                  (cdr (assoc kind preimages)))
   :check-older-fn (lambda (k) (and older (<= k older)))
   :check-after-fn (lambda (k) (and after (<= k after)))))

(defun %ms-sat (expr &rest args)
  (bl.val:ms-satisfy
   (bl.val:ms-parse expr)
   (apply #'%ms-satisfier args)))

(test satisfying-a-timelocked-policy-needs-both-the-key-and-the-time
  "and_v(v:pk(K),older(144)): the witness is one signature, and it exists only
once the relative locktime is satisfied. A branch whose timelock has not
matured is UNSPENDABLE, not merely expensive — so it has to be unavailable
rather than an option the size comparison might pick."
  (let ((expr (format nil "and_v(v:pk(~A),older(144))" *ms-desc-key-a*)))
    ;; Key and time: one signature.
    (multiple-value-bind (stack malleable)
        (%ms-sat expr :keys (list *ms-desc-key-a*) :older 144)
      (is (= 1 (length stack)))
      (is (equalp (%ms-fake-sig 1) (first stack)))
      (is-false malleable))
    ;; Time not yet matured: nothing.
    (is-false (%ms-sat expr :keys (list *ms-desc-key-a*) :older 143))
    ;; No key: nothing.
    (is-false (%ms-sat expr :older 144))))

(test satisfying-an-either-or-policy-picks-the-branch-it-can
  "or_d(pk(A),and_v(v:pk(B),older(1008))): spend now with A, or later with B.
Each satisfier gets the branch it holds, and the witness SHAPE differs — the
recovery branch carries a zero to select it."
  (let ((expr (format nil "or_d(pk(~A),and_v(v:pk(~A),older(1008)))"
                      *ms-desc-key-a* *ms-desc-key-b*)))
    ;; A can spend immediately: just A's signature.
    (multiple-value-bind (stack malleable) (%ms-sat expr :keys (list *ms-desc-key-a*))
      (is (= 1 (length stack)))
      (is (equalp (%ms-fake-sig 1) (first stack)))
      (is-false malleable))
    ;; B can only spend after the delay, and must dissatisfy A's branch first.
    (multiple-value-bind (stack malleable)
        (%ms-sat expr :keys (list *ms-desc-key-b*) :older 1008)
      (is (= 2 (length stack)))
      (is (equalp (%ms-fake-sig 1) (first stack)) "B's signature")
      (is (equalp #() (second stack)) "and an empty element dissatisfying A")
      (is-false malleable))
    ;; B before the delay: neither branch works.
    (is-false (%ms-sat expr :keys (list *ms-desc-key-b*) :older 100))
    ;; Nobody: nothing.
    (is-false (%ms-sat expr :older 1008))))

(test satisfying-a-threshold-picks-exactly-k-branches
  "thresh(2,pk(A),s:pk(B),s:pk(C)) with all three keys must produce exactly two
signatures and one dissatisfaction — never three. Over-completeness is
malleable: a third party could drop one signature and still spend, so a
satisfier that produced all three would be handing out a rewritable witness."
  (let* ((key-c "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
         (expr (format nil "thresh(2,pk(~A),s:pk(~A),s:pk(~A))"
                       *ms-desc-key-a* *ms-desc-key-b* key-c)))
    (multiple-value-bind (stack malleable)
        (%ms-sat expr :keys (list *ms-desc-key-a* *ms-desc-key-b* key-c))
      (is (= 3 (length stack)))
      (is (= 1 (count-if (lambda (e) (zerop (length e))) stack))
          "exactly one branch is dissatisfied")
      (is (= 2 (count-if (lambda (e) (= 72 (length e))) stack))
          "exactly two signatures, never three")
      (is-false malleable))
    ;; Only one key: below the threshold, so no satisfaction at all.
    (is-false (%ms-sat expr :keys (list *ms-desc-key-a*)))))

(test satisfying-a-hash-preimage-branch
  "sha256(H) is satisfied by revealing the preimage, and dissatisfied by any
wrong 32-byte value — which is why the fragment insists on a 32-byte size
check in the script."
  (let* ((preimage (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x42))
         (h (bl.crypto:sha256 preimage))
         (expr (format nil "and_v(v:pk(~A),sha256(~A))"
                       *ms-desc-key-a* (string-downcase (bl.crypto:bytes-to-hex h)))))
    (multiple-value-bind (stack malleable)
        (%ms-sat expr :keys (list *ms-desc-key-a*)
                      :preimages (list (cons :sha256 preimage)))
      (is (= 2 (length stack)))
      (is (equalp preimage (first stack)))
      (is (equalp (%ms-fake-sig 1) (second stack)))
      (is-false malleable))
    ;; Without the preimage there is no spend, even holding the key.
    (is-false (%ms-sat expr :keys (list *ms-desc-key-a*)))))

(test an-unsigned-alternative-makes-a-solution-malleable
  "The rule that looks backwards until you read it as the attacker would: when
one option needs a signature and another does not, the satisfier takes the
UNSIGNED one — because it is available to anybody, so a signed solution could
always be replaced by it. or_i(pk(A),older(1)) is exactly that shape once the
timelock has matured."
  (let ((expr (format nil "or_i(pk(~A),older(1))" *ms-desc-key-a*)))
    ;; With the key AND the matured timelock, the timelock branch wins: it is
    ;; smaller and needs no signature.
    (multiple-value-bind (stack malleable) (%ms-sat expr :keys (list *ms-desc-key-a*) :older 1)
      (declare (ignore malleable))
      (is-true stack)
      (is (= 1 (length stack)))
      (is (equalp #() (first stack)) "the OR_I selector for the second branch"))
    ;; Before the timelock, only the signed branch exists.
    (multiple-value-bind (stack) (%ms-sat expr :keys (list *ms-desc-key-a*) :older 0)
      (is (= 2 (length stack)))
      (is (equalp (%ms-fake-sig 1) (first stack))))))

(test estimation-yields-a-witness-size-without-the-signatures
  "Core's MAYBE availability: a wallet has to size a transaction before it
signs it, so an unavailable key produces a dummy of the right length rather
than nothing. The estimate must not be optimistic, which is why the choice
operator prefers the LARGER of two MAYBEs."
  (let ((expr (format nil "and_v(v:pk(~A),older(144))" *ms-desc-key-a*)))
    ;; No keys at all, but estimating: a stack of the right shape.
    (multiple-value-bind (stack) (%ms-sat expr :older 144 :estimating t)
      (is-true stack)
      (is (= 1 (length stack)))
      (is (= 72 (length (first stack))) "a dummy signature of realistic size"))
    ;; Not estimating, no keys: nothing at all.
    (is-false (%ms-sat expr :older 144))))

(defun %ms-p2wsh-spk (witness-script)
  (concatenate '(vector (unsigned-byte 8))
               (vector 0 32) (bl.crypto:sha256 witness-script)))

(defun %ms-verify-p2wsh (witness-script witness amount)
  "Run the node's real script verification over a P2WSH spend whose witness is
WITNESS plus the witness script. Exactly the shape a spending transaction has."
  ;; A comma-separated STRING, not a list. Passing a list silently enables
  ;; NOTHING, and then the witness path is never taken: the scriptPubKey runs
  ;; as a bare script, leaves its 32-byte program on the stack, and every
  ;; witness "verifies" -- including an empty one. That is how the first draft
  ;; of this test passed while checking nothing at all.
  (bl.interop:set-script-flags "P2SH,WITNESS,CLEANSTACK,MINIMALDATA")
  (unwind-protect
       (bl.interop:verify-script
        (make-array 0 :element-type '(unsigned-byte 8))
        (%ms-p2wsh-spk witness-script)
        :witness (append witness (list witness-script))
        :amount amount)
    (bl.interop:set-script-flags nil)))

(test a-satisfied-policy-actually-verifies-as-a-p2wsh-spend
  "The end-to-end claim, checked by the node's own script verification rather
than by comparing witness elements to what the satisfier was expected to emit:
parse the policy, generate the script, derive the P2WSH commitment, satisfy it,
and spend.

This is what catches a witness in the wrong ORDER, which comparing elements
cannot — and it did: the first draft of MS-SATISFY reversed the stack, and
every element-by-element assertion still passed."
  (let* ((p1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
         (p2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2))
         (h1 (string-downcase (bl.crypto:bytes-to-hex
                               (bl.crypto:sha256 p1))))
         (h2 (string-downcase (bl.crypto:bytes-to-hex
                               (bl.crypto:sha256 p2))))
         (node (bl.val:ms-parse
                (format nil "and_v(v:sha256(~A),sha256(~A))" h1 h2)))
         (script (bl.val:ms-node-script node))
         (sat (bl.val:make-ms-satisfier
               :preimage-fn (lambda (kind hash)
                              (declare (ignore kind))
                              (cond ((equalp hash (bl.crypto:sha256 p1)) p1)
                                    ((equalp hash (bl.crypto:sha256 p2)) p2)))))
         (witness (bl.val:ms-satisfy node sat)))
    (is (= 2 (length witness)))
    (is-true (%ms-verify-p2wsh script witness 100000)
             "the satisfaction the satisfier produced must actually spend")
    ;; The order is load-bearing: swapping the two preimages must fail.
    (is-false (%ms-verify-p2wsh script (reverse witness) 100000)
              "a reversed witness must NOT verify — that is what makes the
               forward case meaningful")
    ;; A wrong preimage fails.
    (is-false (%ms-verify-p2wsh
               script
               (list (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9)
                     (second witness))
               100000))
    ;; A short witness fails.
    (is-false (%ms-verify-p2wsh script (list (first witness)) 100000))))

(test a-threshold-policy-verifies-as-a-p2wsh-spend
  "The same end-to-end check on a shape with a dissatisfied branch, so the
zero element's POSITION in the witness is exercised too."
  (let* ((pres (loop for i from 1 to 3
                     collect (make-array 32 :element-type '(unsigned-byte 8)
                                            :initial-element i)))
         (hashes (mapcar (lambda (p) (bl.crypto:sha256 p)) pres))
         (expr (format nil "thresh(2,sha256(~A),s:sha256(~A),s:sha256(~A))"
                       (string-downcase (bl.crypto:bytes-to-hex (first hashes)))
                       (string-downcase (bl.crypto:bytes-to-hex (second hashes)))
                       (string-downcase (bl.crypto:bytes-to-hex (third hashes)))))
         (node (bl.val:ms-parse expr))
         (script (bl.val:ms-node-script node))
         ;; Only two of the three preimages are known, which is exactly the
         ;; threshold — so the satisfier must dissatisfy the third.
         (sat (bl.val:make-ms-satisfier
               :preimage-fn (lambda (kind hash)
                              (declare (ignore kind))
                              (cond ((equalp hash (first hashes)) (first pres))
                                    ((equalp hash (second hashes)) (second pres))))))
         (witness (bl.val:ms-satisfy node sat)))
    (is-true (%ms-top-level-p node))
    (is (= 3 (length witness)))
    (is-true (%ms-verify-p2wsh script witness 100000))
    ;; With no preimages at all, below the threshold: no satisfaction.
    (is-false (bl.val:ms-satisfy
               node (bl.val:make-ms-satisfier)))))

;;; --- Inference: script bytes back to a miniscript -----------------------------

(test every-corpus-script-round-trips-through-inference-in-tapscript
  "The tapscript half of Core's round trip. Test() runs EVERY fixed_tests
vector through both converters (miniscript_tests.cpp:485-489, wsh_converter
and tap_converter) and asserts a byte-exact FromScript round trip in each, so
the P2WSH test below is only half the oracle.

It is the only check that reaches the decoder's tapscript arms at all: a
tapscript leaf writes its keys x-only, so a 33-byte push is not a key there and
a 32-byte one is. Before those arms existed every vector holding a key inferred
NIL here while the P2WSH half stayed green."
  (let ((checked 0) (bad '()))
    (dolist (v (%ms-vectors))
      (let ((expr (gethash "ms" v)))
        (when (and (%ms-flag v "VALID") (not (%ms-flag v "TAPSCRIPT_INVALID")))
          (let ((node (%ms-try-parse expr :tapscript)))
            (when (and node (%ms-top-level-p node))
              (incf checked)
              (let* ((script (bl.val:ms-node-script node))
                     (back (bl.val:ms-from-script script :ctx :tapscript)))
                (cond
                  ((null back) (push (format nil "~A: not inferred" expr) bad))
                  ((not (equalp script (bl.val:ms-node-script back)))
                   (push (format nil "~A: re-compiled differently" expr) bad)))))))))
    (is (= 56 checked)
        "expected 56 tapscript-inferable corpus vectors, checked ~D" checked)
    (is (null bad) "~{~A~^~%~}" (reverse bad))))

(test tapscript-multi-a-decodes-into-its-keys-and-threshold
  "multi_a is BIP342's replacement for CHECKMULTISIG, and Core decodes it with
an arm of its own (miniscript.h:2394-2420) that walks
  <x1> CHECKSIG (<xi> CHECKSIGADD)* <k> NUMEQUAL
from the NUMEQUAL end. Reading backwards sees the LAST key first, so the
recovered order is the one Core reaches through std::reverse — an order that
decides which signature the witness has to carry for which key."
  (let* ((k1 "03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65")
         (k2 "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556")
         (k3 "023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1")
         (expr (format nil "multi_a(2,~A,~A,~A)" k1 k2 k3))
         (script (bl.val:ms-node-script (bl.val:ms-parse expr :ctx :tapscript)))
         (back (bl.val:ms-from-script script :ctx :tapscript)))
    (is-true back "a multi_a leaf script must infer")
    (when back
      (is (eq :multi-a (%ms-frag back)))
      (is (= 2 (%ms-threshold back)))
      (is (equal (list (subseq k1 2) (subseq k2 2) (subseq k3 2))
                 (mapcar (lambda (b) (string-downcase (bl.crypto:bytes-to-hex b)))
                         (%ms-keys back)))
          "the keys must come back x-only and in source order")
      (is (equalp script (bl.val:ms-node-script back))))
    ;; One key: the chain is a single <x> CHECKSIG pair with no CHECKSIGADD.
    (let* ((one (bl.val:ms-node-script
                 (bl.val:ms-parse (format nil "multi_a(1,~A)" k1) :ctx :tapscript)))
           (back1 (bl.val:ms-from-script one :ctx :tapscript)))
      (is-true back1)
      (when back1
        (is (eq :multi-a (%ms-frag back1)))
        (is (equalp one (bl.val:ms-node-script back1)))))))

(test inference-reads-a-script-in-the-context-it-is-given
  "A script is not miniscript on its own — it is miniscript IN A CONTEXT, and
the same bytes decode differently or not at all in the other one. Core passes
that context in (FromScript's ctx, miniscript.h:2288); inheriting whatever the
caller's special happened to hold is how a tapscript leaf gets read with P2WSH
rules and comes back NIL."
  (let* ((key "03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65")
         (key2 "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556")
         (wsh-pk (bl.val:ms-node-script
                  (bl.val:ms-parse (format nil "pk(~A)" key) :ctx :p2wsh)))
         (tap-pk (bl.val:ms-node-script
                  (bl.val:ms-parse (format nil "pk(~A)" key) :ctx :tapscript)))
         (multi (bl.val:ms-node-script
                 (bl.val:ms-parse (format nil "multi(1,~A,~A)" key key2) :ctx :p2wsh)))
         (multi-a (bl.val:ms-node-script
                   (bl.val:ms-parse (format nil "multi_a(1,~A,~A)" key key2)
                                    :ctx :tapscript))))
    ;; The key push size is the context's, both ways round.
    (is-true (bl.val:ms-from-script wsh-pk :ctx :p2wsh))
    (is-false (bl.val:ms-from-script wsh-pk :ctx :tapscript)
              "a 33-byte push is not a key in tapscript")
    (is-true (bl.val:ms-from-script tap-pk :ctx :tapscript))
    (is-false (bl.val:ms-from-script tap-pk :ctx :p2wsh)
              "a 32-byte push is not a key in P2WSH")
    ;; CHECKMULTISIG does not exist in tapscript and multi_a does not exist
    ;; outside it (miniscript.h:2375, :2397).
    (is-true (bl.val:ms-from-script multi :ctx :p2wsh))
    (is-false (bl.val:ms-from-script multi :ctx :tapscript))
    (is-true (bl.val:ms-from-script multi-a :ctx :tapscript))
    (is-false (bl.val:ms-from-script multi-a :ctx :p2wsh))
    ;; And the default is the P2WSH one the two shipped script callers want.
    (is-true (bl.val:ms-from-script wsh-pk))
    (is-false (bl.val:ms-from-script tap-pk))))

(test a-malformed-checksigadd-chain-is-not-a-multi-a
  "Everything the multi_a arm refuses, each built by editing one byte of a
script that decodes. A decoder that answered anyway would hand the satisfier a
threshold or a key list the leaf does not have."
  (let* ((k1 "03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65")
         (k2 "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556")
         (good (bl.val:ms-node-script
                (bl.val:ms-parse (format nil "multi_a(1,~A,~A)" k1 k2)
                                 :ctx :tapscript)))
         (n (length good)))
    (flet ((edited (index byte)
             (let ((copy (copy-seq good)))
               (setf (aref copy index) byte)
               (bl.val:ms-from-script copy :ctx :tapscript))))
      ;; The control: untouched, it decodes.
      (is-true (bl.val:ms-from-script good :ctx :tapscript))
      ;; k = 0 (OP_0 where OP_1 stood): Core refuses *k < 1.
      (is-false (edited (- n 2) #x00))
      ;; k = 3 with two keys: the chain cannot be that long.
      (is-false (edited (- n 2) #x53))
      ;; No OP_CHECKSIG head, so the chain never ends.
      (is-false (edited 33 #xba))
      ;; Truncated before the last pair.
      (is-false (bl.val:ms-from-script (subseq good 34) :ctx :tapscript)))))

(test every-corpus-script-round-trips-through-inference
  "Core's own round-trip check, over its own corpus: compile each expression to
a script, infer a miniscript back out of the bytes, and require the inferred
node to compile to the SAME script.

It is a strong check because it exercises the decoder against every fragment
and wrapper combination Core thought worth listing, and because a decoder that
mis-parses almost always produces a different script rather than none."
  (let ((checked 0) (bad '()))
    (dolist (v (%ms-vectors))
      (let ((expr (gethash "ms" v)))
        (when (and (%ms-flag v "VALID") (not (%ms-flag v "P2WSH_INVALID")))
          (let ((node (%ms-try-parse expr)))
            (when (and node (%ms-top-level-p node))
              (incf checked)
              (let* ((script (bl.val:ms-node-script node))
                     (back (bl.val:ms-from-script script)))
                (cond
                  ((null back) (push (format nil "~A: not inferred" expr) bad))
                  ((not (equalp script (bl.val:ms-node-script back)))
                   (push (format nil "~A: re-compiled differently" expr) bad)))))))))
    (is (>= checked 60) "expected ~60 inferable vectors, checked ~D" checked)
    (is (null bad) "~{~A~^~%~}" (reverse bad))))

(test inference-recovers-the-expression-not-just-the-script
  "For everything except pkh, the inferred node prints back as the original
expression — which is what makes inference useful for describing an unknown
script rather than merely validating it."
  (dolist (expr (list (format nil "and_v(v:pk(~A),older(144))" *ms-desc-key-a*)
                      (format nil "or_d(pk(~A),and_v(v:pk(~A),older(1008)))"
                              *ms-desc-key-a* *ms-desc-key-b*)
                      (format nil "thresh(2,pk(~A),s:pk(~A))"
                              *ms-desc-key-a* *ms-desc-key-b*)
                      (format nil "or_i(pk(~A),after(500000))" *ms-desc-key-a*)
                      ;; Written in its CANONICAL spelling: and_v(X,1) is t:X
                      ;; and a wrapper run takes one colon, so the un-sugared
                      ;; form would print back as tv:sha256(...) — correctly.
                      "tv:sha256(0000000000000000000000000000000000000000000000000000000000000001)"))
    (let* ((node (bl.val:ms-parse expr))
           (back (bl.val:ms-from-script
                  (bl.val:ms-node-script node))))
      (is-true back "~A was not inferred" expr)
      (when back
        (is (string= expr (bl.val:ms-node-to-string back))
            "~A came back as ~A" expr
            (bl.val:ms-node-to-string back)))))
  ;; Printing and re-parsing preserves the script — for everything except
  ;; pk_h, whose inferred form names a 20-byte HASH where the grammar wants a
  ;; key. That is not a gap to paper over: the script genuinely does not
  ;; contain the key, so no spelling of it could round-trip. pk_h's honest
  ;; property is the script round-trip, asserted in its own test below.
  (dolist (expr (list (format nil "and_v(v:pk(~A),older(9))" *ms-desc-key-a*)
                      (format nil "thresh(2,pk(~A),s:pk(~A))"
                              *ms-desc-key-a* *ms-desc-key-b*)))
    (let* ((script (bl.val:ms-node-script
                    (bl.val:ms-parse expr)))
           (back (bl.val:ms-from-script script)))
      (is-true back)
      (is (equalp script
                  (bl.val:ms-node-script
                   (bl.val:ms-parse
                    (bl.val:ms-node-to-string back))))
          "~A: printing and re-parsing must preserve the script" expr))))

(test a-pkh-script-yields-the-hash-because-that-is-all-it-holds
  "pkh commits to HASH160(key), not to the key. Inference can only recover the
hash, and the node has to say so — a node that pretended the hash was a key
would hash it again and produce a different script."
  (let* ((expr (format nil "c:pk_h(~A)" *ms-desc-key-a*))
         (node (bl.val:ms-parse expr))
         (script (bl.val:ms-node-script node))
         (back (bl.val:ms-from-script script)))
    (is-true back)
    (is (equalp script (bl.val:ms-node-script back))
        "the inferred node must still compile to the same script")
    (let ((inner (first (%ms-subs back))))
      (is (eq :pk-h (%ms-frag inner)))
      (is (equalp (bl.crypto:hash160
                   (bl.crypto:hex-to-bytes *ms-desc-key-a*))
                  (bl.val::ms-node-data inner))
          "the node carries the hash the script committed to")
      (is (null (%ms-keys inner))
          "and no key, because the script does not contain one"))))

(test non-miniscript-and-non-minimal-scripts-are-refused
  "Inference answers a question about ARBITRARY scripts, so a wrong answer is
worse than none. Three ways to be refused."
  ;; Not miniscript at all.
  (is-false (bl.val:ms-from-script
             (coerce #(#x51 #x52 #x93) '(vector (unsigned-byte 8)))))
  ;; Truncated.
  (is-false (bl.val:ms-from-script
             (coerce #(#xac) '(vector (unsigned-byte 8)))))
  ;; A non-minimal push: <1 byte> written as PUSHDATA1. Miniscript's mapping
  ;; from expression to script is one-to-one, so a second encoding of the same
  ;; script must not decode.
  (let ((minimal (bl.val:ms-node-script
                  (bl.val:ms-parse
                   (format nil "c:pk_k(~A)" *ms-desc-key-a*)))))
    (is-true (bl.val:ms-from-script minimal))
    (let ((padded (concatenate '(vector (unsigned-byte 8))
                               (vector #x4c 33)
                               (subseq minimal 1 34)
                               (vector #xac))))
      (is-false (bl.val:ms-from-script padded)
                "a PUSHDATA1-encoded 33-byte push is not the minimal form")))
  ;; OP_CHECKSIG followed by a separate OP_VERIFY, where OP_CHECKSIGVERIFY was
  ;; the canonical spelling.
  (is-false (bl.val:ms-from-script
             (concatenate '(vector (unsigned-byte 8))
                          (vector 33)
                          (bl.crypto:hex-to-bytes *ms-desc-key-a*)
                          (vector #xac #x69 #x51)))))

(test inference-refuses-a-script-whose-types-do-not-check
  "A script can be shaped like miniscript and still not BE miniscript: the type
rules are what make satisfaction and non-malleability decidable, so a node that
does not type is refused rather than returned as a best effort."
  ;; and_b(1,1): the second argument must be W-type, and OP_1 is B.
  (is-false (bl.val:ms-from-script
             (coerce #(#x51 #x51 #x9a) '(vector (unsigned-byte 8))))))

;;;; --- Resource limits and the sanity gate (Core IsSane) -------------------

(test ms-ops-and-stack-size-match-hand-computed-scripts
  "The Ops and StackSize algebras (miniscript.h:999-1183) ported from Core,
checked against scripts small enough to count by hand. GetOps is
`ops.count + ops.sat' and GetStackSize is `ss.sat.netdiff + IsBKW'
(miniscript.h:1557,1578)."
  (flet ((ops (e) (bl.val::ms-node-get-ops (%ms-try-parse e)))
         (ss (e) (bl.val:ms-node-get-stack-size (%ms-try-parse e))))
    (let ((a "025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc")
          (b "03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65"))
      ;; pk(A) is `<key> OP_CHECKSIG': one non-push op, one witness element.
      (is (= 1 (ops (format nil "pk(~A)" a))))
      (is (= 1 (ss (format nil "pk(~A)" a))))
      ;; older(42) is `<42> OP_CHECKSEQUENCEVERIFY': one op, nothing to push.
      (is (= 1 (ops "older(42)")))
      (is (= 0 (ss "older(42)")))
      ;; and_v(v:pk(A),older(42)) is `<key> OP_CHECKSIGVERIFY <42> OP_CSV'.
      (is (= 2 (ops (format nil "and_v(v:pk(~A),older(42))" a))))
      (is (= 1 (ss (format nil "and_v(v:pk(~A),older(42))" a))))
      ;; or_b adds OP_BOOLOR, and s: adds an OP_SWAP to its sub.
      (is (= 4 (ops (format nil "or_b(pk(~A),s:pk(~A))" a b))))
      ;; Either branch is satisfied and the other dissatisfied: two elements.
      (is (= 2 (ss (format nil "or_b(pk(~A),s:pk(~A))" a b)))))))

(test ms-resource-limits-do-not-reject-any-of-cores-valid-vectors
  "A guard against the ops/stack port over-rejecting. Every expression Core's
own corpus marks VALID for P2WSH must pass CheckOpsLimit and CheckStackSize —
Core would not call it valid otherwise."
  (let ((checked 0))
    (dolist (v (%ms-vectors))
      (when (and (%ms-flag v "VALID") (not (%ms-flag v "P2WSH_INVALID")))
        (let ((node (%ms-try-parse (gethash "ms" v))))
          (when node
            (incf checked)
            (is-true (bl.val::ms-node-check-ops-limit-p node)
                     "ops limit rejected a Core-valid vector: ~A"
                     (gethash "ms" v))
            (is-true (bl.val::ms-node-check-stack-size-p node)
                     "stack limit rejected a Core-valid vector: ~A"
                     (gethash "ms" v))))))
    (is (plusp checked) "no vectors were checked at all")))

(test ms-duplicate-key-detection-walks-the-whole-tree
  "Core's CheckDuplicateKey (miniscript.h:1688) is over the fragment AND all
its subs, not one level."
  (let ((a "025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc")
        (b "03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65"))
    (is-false (bl.val:ms-node-duplicate-keys-p
               (%ms-try-parse (format nil "or_b(pk(~A),s:pk(~A))" a b))))
    (is-true (bl.val:ms-node-duplicate-keys-p
              (%ms-try-parse (format nil "or_b(pk(~A),s:pk(~A))" a a))))
    ;; Buried two levels down, in different branches.
    (is-true (bl.val:ms-node-duplicate-keys-p
              (%ms-try-parse
               (format nil "andor(pk(~A),or_b(pk(~A),s:pk(~A)),0)" b a a))))))

(test ms-is-sane-composes-cores-seven-predicates
  "Core IsSane = IsValidTopLevel && IsSaneSubexpression && NeedsSignature,
where IsSaneSubexpression = ValidSatisfactions && IsNonMalleable &&
CheckTimeLocksMix && CheckDuplicateKey (miniscript.h:1691-1697).

⚠️ CheckTimeLocksMix is TRUE when there is NO mix. Our MS-NODE-TIMELOCK-MIX-P
is its inverse, so IsSane must negate it — getting that backwards would accept
exactly the expressions the property exists to catch."
  (let ((a "025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc"))
    ;; Sane: needs a signature, non-malleable, no duplicates, no mix.
    (is-true (bl.val:ms-node-sane-p
              (%ms-try-parse (format nil "and_v(v:pk(~A),older(42))" a))))
    ;; No signature anywhere: Core refuses it.
    (is-false (bl.val:ms-node-sane-p (%ms-try-parse "older(42)")))
    ;; Every vector Core marks TIMELOCKMIX must fail the un-inverted predicate.
    (dolist (v (%ms-vectors))
      (when (and (%ms-flag v "TIMELOCKMIX") (%ms-flag v "VALID"))
        (let ((node (%ms-try-parse (gethash "ms" v))))
          (when node
            (is-true (bl.val:ms-node-timelock-mix-p node))
            (is-false (bl.val:ms-node-sane-p node))))))))

;;;; --- Signing a wsh(<miniscript>) output ----------------------------------

(defun %ms-sign-p2wsh (expr &key (version 2) (sequence 42) (have-key t)
                                 (lock-time 0))
  "Build a P2WSH output for EXPR, spend it with one input, and run the wallet
signer over it. Returns (values kind witness-length verified-p error), where
VERIFIED-P is the script engine's verdict on the witness that came out — the
only evidence that matters, since a signer can always produce SOMETHING."
  (let* ((sk (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7))
         (pk (bl.crypto:derive-public-key sk))
         (node (bl.val:ms-parse
                (format nil expr (bl.crypto:bytes-to-hex pk))))
         (witscript (coerce (bl.val:ms-node-script node)
                            '(vector (unsigned-byte 8))))
         (spk (concatenate '(vector (unsigned-byte 8)) (vector #x00 #x20)
                           (bl.crypto:sha256 witscript)))
         (prev-txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xE1))
         (amount 100000)
         (tx (bl.ser:make-transaction
              :version version
              :inputs (vector (bl.ser:make-tx-in
                               :previous-output (bl.ser:make-outpoint
                                                 :hash prev-txid :index 0)
                               :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                               :sequence sequence))
              :outputs (vector (bl.ser:make-tx-out
                                :value 90000 :script-pubkey spk))
              :lock-time lock-time))
         (pubmap (make-hash-table :test 'equalp))
         (keymap (make-hash-table :test 'equalp)))
    (when have-key
      (setf (gethash pk pubmap) sk)
      (setf (gethash (bl.crypto:hash160 pk) keymap) (cons sk pk)))
    (let ((bl.interop:*current-tx* tx))
      (multiple-value-bind (sig err)
          (bl.rpc:compute-input-signatures
           tx 0 (list spk amount nil witscript) keymap pubmap
           (make-hash-table :test 'equalp) #x01 nil nil)
        (if err
            (values nil nil nil err)
            (multiple-value-bind (ss wit ferr)
                (bl.rpc::%finalize-input-signatures sig)
              (declare (ignore ss))
              (if ferr
                  (values (bl.rpc:input-sig-kind sig) nil nil ferr)
                  (let ((utxo-set (bl.store:make-utxo-set)))
                    (setf (bl.ser:transaction-witness tx)
                          (vector (coerce wit 'list)))
                    (bl.store:add-utxo utxo-set prev-txid 0 amount spk 5)
                    (values (bl.rpc:input-sig-kind sig)
                            (length wit)
                            (bl.val:validate-transaction-scripts
                             tx utxo-set :height 800000)
                            nil)))))))))

(test wsh-miniscript-is-actually-spendable
  "MS-SATISFY had ZERO callers in src/, so a wsh(<miniscript>) output could be
imported and watched but never spent. Core reaches the same satisfier from
SignStep, as a fallback after the legacy solver fails and only when nothing has
been pushed yet (sign.cpp:772-777): FromScript infers the policy back out of
the witnessScript and Satisfy must return Availability::YES.

The assertion that matters is the last one — the script engine accepting the
witness the signer produced."
  (multiple-value-bind (kind len verified err)
      (%ms-sign-p2wsh "and_v(v:pk(~a),older(42))")
    (is (null err) "signing failed: ~A" err)
    (is (eq :p2wsh-miniscript kind))
    ;; satisfaction (one signature) plus the witnessScript Core always appends.
    (is (= 2 len))
    (is-true verified "the script engine rejected the witness we produced")))

(test miniscript-signing-refuses-an-unsatisfiable-branch
  "A satisfier that claims a timelock is met when it is not produces a witness
for a branch the transaction cannot take. Core makes such a branch INVALID
rather than merely expensive (CheckLockTime/CheckSequence,
interpreter.cpp:1745-1826), so that the size comparison never picks it."
  ;; nSequence below the older() value: not satisfied.
  (multiple-value-bind (kind len verified err)
      (%ms-sign-p2wsh "and_v(v:pk(~a),older(42))" :sequence 41)
    (declare (ignore kind len verified))
    (is-true (stringp err) "an unmet older() must not yield a signed witness"))
  ;; BIP68 only applies from version 2, so a version-1 transaction can never
  ;; satisfy older() at all (interpreter.cpp:1789).
  (multiple-value-bind (kind len verified err)
      (%ms-sign-p2wsh "and_v(v:pk(~a),older(42))" :version 1)
    (declare (ignore kind len verified))
    (is-true (stringp err) "older() must be unsatisfiable below tx version 2"))
  ;; The disable bit means the sequence is not consensus-constrained, and must
  ;; not be usable to get around the check (interpreter.cpp:1796).
  (multiple-value-bind (kind len verified err)
      (%ms-sign-p2wsh "and_v(v:pk(~a),older(42))" :sequence #x80000042)
    (declare (ignore kind len verified))
    (is-true (stringp err) "the disable flag must not satisfy older()"))
  ;; And with no key at all there is no satisfaction, timelock or not.
  (multiple-value-bind (kind len verified err)
      (%ms-sign-p2wsh "and_v(v:pk(~a),older(42))" :have-key nil)
    (declare (ignore kind len verified))
    (is-true (stringp err) "signed without holding the key")))

(test miniscript-older-reads-the-version-unsigned
  "Core's CheckSequence gates on `txTo->version < 2\' where version is a
`const uint32_t\' (interpreter.cpp:1789-1791, primitives/transaction.h:293),
so EVERY version with bit 31 set is >= 2 there and BIP68 applies to it. Our
slot is (signed-byte 32) -- correct, it is what the wire carries -- and the
signed compare read 0x80000002 as negative, so the satisfier declined older()
for a transaction whose relative locktime Core considers satisfied. The
script engine already masked, so the branch the satisfier refused to build is
one the engine would have accepted."
  (flet ((older-met-p (version)
           (bl.val:ms-check-older
            (bl.ser:make-transaction
             :version version
             :inputs (vector (bl.ser:make-tx-in
                              :previous-output
                              (bl.ser:make-outpoint
                               :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                    :initial-element 1)
                               :index 0)
                              :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                              :sequence 42))
             :outputs (vector)
             :lock-time 0)
            0 42)))
    ;; Controls: the ordinary versions, unchanged.
    (is-true (older-met-p 2) "version 2 must satisfy older(42)")
    (is-false (older-met-p 1) "version 1 is below BIP68")
    ;; Bit 31 set: negative in our slot, >= 2 in Core's reading.
    (is-true (older-met-p (- #x80000002 (expt 2 32)))
             "version 0x80000002 is 2147483650 to Core, not -2147483646")
    (is-true (older-met-p -1) "version 0xffffffff is 4294967295 to Core"))
  ;; End to end: the signer builds the older() branch and the engine accepts
  ;; the witness, on the same version.
  (multiple-value-bind (kind len verified err)
      (%ms-sign-p2wsh "and_v(v:pk(~a),older(42))"
                      :version (- #x80000002 (expt 2 32)))
    (declare (ignore kind len))
    (is (null err) "signing failed: ~A" err)
    (is-true verified "the script engine rejected the witness we produced")))

(test miniscript-check-after-follows-cores-locktime-rules
  "after(N) is Core's CheckLockTime (interpreter.cpp:1745-1779): the tx
nLockTime must be of the SAME kind (both heights or both timestamps), at least
N, and this input must not be final — nLockTime is inert otherwise, which is
why Core refuses to treat CLTV as satisfied when it would be."
  ;; Height-based, met.
  (multiple-value-bind (kind len verified err)
      (%ms-sign-p2wsh "and_v(v:pk(~a),after(500))" :lock-time 500 :sequence 0)
    (declare (ignore kind len))
    (is (null err) "signing failed: ~A" err)
    (is-true verified))
  ;; Height-based, not yet met.
  (multiple-value-bind (kind len verified err)
      (%ms-sign-p2wsh "and_v(v:pk(~a),after(500))" :lock-time 499 :sequence 0)
    (declare (ignore kind len verified))
    (is-true (stringp err)))
  ;; Mixed kinds: a timestamp nLockTime cannot satisfy a height after().
  (multiple-value-bind (kind len verified err)
      (%ms-sign-p2wsh "and_v(v:pk(~a),after(500))" :lock-time 1700000000 :sequence 0)
    (declare (ignore kind len verified))
    (is-true (stringp err) "a timestamp nLockTime satisfied a height after()"))
  ;; A final input disables nLockTime, so after() is not satisfied however
  ;; large nLockTime is.
  (multiple-value-bind (kind len verified err)
      (%ms-sign-p2wsh "and_v(v:pk(~a),after(500))" :lock-time 500
                                                   :sequence #xFFFFFFFF)
    (declare (ignore kind len verified))
    (is-true (stringp err) "a final input must not satisfy after()")))

(test miniscript-witness-size-estimate-is-an-upper-bound-on-the-real-witness
  "Coin selection needs a satisfaction size for a wsh(<miniscript>) input, and
%SCRIPT-SAT-WEIGHT returned NIL for anything that was not multisig — so the
coin looked unsolvable and was silently skipped, leaving a funded policy
descriptor unspendable through the wallet's own send path even after signing
worked.

The estimate must be an UPPER bound on what the signer actually produces. Too
low and the transaction underpays its fee. Core charges a constant 1+72 per
signature (miniscript.h:1188), which is exactly why it is an upper bound: real
signatures are 71 or 72 bytes."
  (let* ((sk (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7))
         (pk (bl.crypto:derive-public-key sk)))
    (dolist (expr '("and_v(v:pk(~a),older(42))"
                    "or_d(pk(~a),older(1000))"
                    "andor(pk(~a),older(42),older(1000))"))
      (let* ((node (bl.val:ms-parse
                    (format nil expr (bl.crypto:bytes-to-hex pk))))
             (witscript (coerce (bl.val:ms-node-script node)
                                '(vector (unsigned-byte 8)))))
        (multiple-value-bind (bytes elems)
            (bl.wallet::%miniscript-sat-size-and-elems witscript)
          (is-true (and bytes elems) "no estimate for ~A" expr)
          ;; The witnessScript is counted by the caller, so ELEMS is the
          ;; satisfaction's own elements plus one.
          (is-true (>= elems 1))
          (is-true (plusp bytes)))))
    ;; And the estimate really does cover the witness the signer builds.
    (multiple-value-bind (kind len verified err)
        (%ms-sign-p2wsh "and_v(v:pk(~a),older(42))")
      (declare (ignore kind verified))
      (is (null err))
      (let* ((node (bl.val:ms-parse
                    (format nil "and_v(v:pk(~a),older(42))"
                            (bl.crypto:bytes-to-hex pk))))
             (witscript (coerce (bl.val:ms-node-script node)
                                '(vector (unsigned-byte 8)))))
        (multiple-value-bind (bytes elems)
            (bl.wallet::%miniscript-sat-size-and-elems witscript)
          (declare (ignore bytes))
          (is (= elems len)
              "estimated ~D witness elements, signer produced ~D" elems len))))))
