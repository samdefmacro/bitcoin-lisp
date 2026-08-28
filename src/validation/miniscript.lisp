(in-package #:bitcoin-lisp.validation)

;;;; Miniscript — the type system and node tree
;;;;
;;;; Port of Bitcoin Core's script/miniscript.{h,cpp}. Miniscript is a language
;;;; for a subset of Bitcoin Script whose structure makes three questions
;;;; decidable that raw script leaves open: is it valid, can it be satisfied
;;;; without a third party mangling the witness, and how big is that witness.
;;;; Wallets need all three to track and spend a policy — timelocked recovery
;;;; paths, decaying multisig — which is why a descriptor wallet that cannot
;;;; read `wsh(<miniscript>)' cannot import those at all (G7-41).
;;;;
;;;; This file carries the parts that are pure functions of the expression: the
;;;; type calculus, the node tree, and script generation. Satisfaction (turning
;;;; a node plus keys into a witness) and inference (script bytes back into a
;;;; node) build on these.

;;;; --- The type system (miniscript.h:36-208) -----------------------------
;;;;
;;;; Every expression has one of four BASE TYPES and a set of PROPERTIES, all
;;;; packed into one bitmask. Core spells these as string literals through a
;;;; consteval ""_mst operator; MST does the same job here, and is folded at
;;;; compile time wherever it is given a literal.
;;;;
;;;;   B base    V verify   K key      W wrapped
;;;;   z zero-arg          o one-arg           n nonzero
;;;;   d dissatisfiable    u unit              e expression
;;;;   f forced            s safe              m nonmalleable
;;;;   x expensive-verify
;;;;   g relative-time  h relative-height  i abs-time  j abs-height
;;;;   k no height/time timelock mix

(eval-when (:compile-toplevel :load-toplevel :execute)

(defparameter +mst-bits+
  '((#\B . 0) (#\V . 1) (#\K . 2) (#\W . 3)
    (#\z . 4) (#\o . 5) (#\n . 6) (#\d . 7) (#\u . 8) (#\e . 9)
    (#\f . 10) (#\s . 11) (#\m . 12) (#\x . 13)
    (#\g . 14) (#\h . 15) (#\i . 16) (#\j . 17) (#\k . 18))
  "Core's bit assignment for each type letter (miniscript.h:159-188). The exact
values do not escape this file, but keeping Core's makes the two diffable.")

(defun mst (string)
  "The type bitmask for STRING, a set of type letters (Core's \"...\"_mst)."
  (let ((flags 0))
    (loop for ch across string
          for bit = (cdr (assoc ch +mst-bits+))
          do (unless bit (internal-error "Unknown miniscript type character ~S" ch))
             (setf flags (logior flags (ash 1 bit))))
    flags))

(define-compiler-macro mst (&whole form string)
  (if (stringp string) (mst string) form))

) ; eval-when: MST must run at compile time for its own compiler macro to fold
  ; the literals, which is the point of having one.

(declaim (inline mst-subset-p mst-if))
(defun mst-subset-p (type properties)
  "Core's `type << properties': TYPE has ALL of PROPERTIES.
The subset rule is what makes the calculus compose — an expression with
properties X, Y and Z is valid anywhere an X, a Y, an XY, ... is expected."
  (= (logand type properties) properties))

(defun mst-if (condition properties)
  "Core's `properties.If(condition)': PROPERTIES when CONDITION, else nothing."
  (if condition properties 0))

;;;; --- Fragments (miniscript.h:211-243) ----------------------------------

(deftype miniscript-fragment ()
  '(member :just-0 :just-1 :pk-k :pk-h :older :after
    :sha256 :hash256 :ripemd160 :hash160
    :wrap-a :wrap-s :wrap-c :wrap-d :wrap-v :wrap-j :wrap-n
    :and-v :and-b :or-b :or-c :or-d :or-i :andor :thresh :multi :multi-a))

(defstruct (ms-node (:constructor %make-ms-node))
  "One node of a miniscript expression tree (Core miniscript::Node).

AND-N(X,Y) is ANDOR(X,Y,0), t: is AND_V(X,1), l: is OR_I(0,X) and u: is
OR_I(X,0) — Core represents those four as their expansions rather than as
fragments of their own, and so does this."
  (fragment :just-0 :type miniscript-fragment)
  ;; Sub-expressions, in Core's order.
  (subs '() :type list)
  ;; Public keys (PK_K, PK_H, MULTI, MULTI_A), as byte vectors.
  (keys '() :type list)
  ;; The threshold (THRESH, MULTI, MULTI_A) or locktime value (OLDER, AFTER).
  (k 0 :type (unsigned-byte 32))
  ;; The hash payload (SHA256, HASH256, RIPEMD160, HASH160).
  (data nil)
  ;; Computed once at construction.
  (node-type 0 :type (unsigned-byte 32))
  (script-size 0 :type (unsigned-byte 32))
  ;; :P2WSH or :TAPSCRIPT (Core MiniscriptContext, miniscript.h:251). The
  ;; context is not decoration: it changes which FRAGMENTS are legal (multi
  ;; versus multi_a), how a key SERIALIZES (33 bytes versus 32), what `d:'
  ;; types as, the script size ceiling, and the signature size the satisfier
  ;; costs a branch at. A node carries its own so a tree cannot be half of
  ;; each.
  (ctx :p2wsh :type (member :p2wsh :tapscript)))

(defun ms-tapscript-p (ctx)
  "Core IsTapscript (miniscript.h:257)."
  (eq ctx :tapscript))

(defvar *ms-context* :p2wsh
  "The miniscript context the current parse is in.

A special rather than a parameter threaded through all fifty-four node
constructions: threading it by hand is exactly the shape that gets forgotten at
one call site, and a tree half in each context would still TYPE-CHECK while
producing a script for neither. MS-PARSE binds it; MAKE-MS-NODE defaults from
it; nothing else has to remember.")

(defconstant +ms-locktime-threshold+ 500000000
  "Core LOCKTIME_THRESHOLD: below this an nLockTime is a height, at or above it
a Unix time.")

(defconstant +ms-sequence-locktime-type-flag+ (ash 1 22)
  "Core CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG: set means the relative locktime is
measured in 512-second units rather than blocks.")

(defconstant +ms-max-pubkeys-per-multisig+ 20)

(defconstant +ms-max-pubkeys-per-multi-a+ 999
  "Core MAX_PUBKEYS_PER_MULTI_A (script.h:37). A CHECKSIGADD chain has no
CHECKMULTISIG-style ceiling; only the script size limit bounds it.")

(defconstant +ms-sequence-final+ #xFFFFFFFF
  "Core CTxIn::SEQUENCE_FINAL.")

(defconstant +ms-sequence-locktime-disable-flag+ #x80000000
  "Core CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG.")

(defconstant +ms-sequence-locktime-mask+ #x0000FFFF
  "Core CTxIn::SEQUENCE_LOCKTIME_MASK.")

(defun ms-check-after (tx input-index value)
  "Core's CheckLockTime (interpreter.cpp:1745-1779), which is what a satisfier
answers for `after(VALUE)': is this absolute timelock ALREADY satisfied by the
transaction being built?

A satisfier that says yes when it is not produces a witness for a branch the
transaction cannot yet take — Core makes such a branch INVALID rather than
merely expensive, so that the size comparison never picks it."
  (let ((tx-locktime (bl.ser:transaction-lock-time tx))
        (inputs (bl.ser:transaction-inputs tx)))
    (and
     ;; Compare apples to apples: both heights, or both timestamps.
     (or (and (< tx-locktime +ms-locktime-threshold+)
              (< value +ms-locktime-threshold+))
         (and (>= tx-locktime +ms-locktime-threshold+)
              (>= value +ms-locktime-threshold+)))
     (<= value tx-locktime)
     ;; nLockTime is inert unless this input is non-final, so Core refuses to
     ;; treat CLTV as satisfied when the input would disable it.
     (< input-index (length inputs))
     (/= +ms-sequence-final+
         (bl.ser:tx-in-sequence (aref inputs input-index)))
     t)))

(defun ms-check-older (tx input-index value)
  "Core's CheckSequence (interpreter.cpp:1781-1826), which is what a satisfier
answers for `older(VALUE)': is this relative timelock already satisfied by the
input's own nSequence?"
  (let ((inputs (bl.ser:transaction-inputs tx)))
    (and
     (< input-index (length inputs))
     ;; BIP68 only applies from version 2.
     (>= (bl.ser:transaction-version tx) 2)
     (let ((seq (bl.ser:tx-in-sequence
                 (aref inputs input-index))))
       (and
        ;; A sequence with the disable bit set is not consensus-constrained,
        ;; and must not be usable to get around a CHECKSEQUENCEVERIFY.
        (zerop (logand seq +ms-sequence-locktime-disable-flag+))
        (let* ((mask (logior +ms-sequence-locktime-type-flag+
                             +ms-sequence-locktime-mask+))
               (seq-masked (logand seq mask))
               (value-masked (logand value mask)))
          (and
           ;; Both block-based, or both time-based.
           (or (and (< seq-masked +ms-sequence-locktime-type-flag+)
                    (< value-masked +ms-sequence-locktime-type-flag+))
               (and (>= seq-masked +ms-sequence-locktime-type-flag+)
                    (>= value-masked +ms-sequence-locktime-type-flag+)))
           (<= value-masked seq-masked)
           t)))))))

(defun ms-sanitize-type (type)
  "Core SanitizeType (miniscript.cpp:19-37): zero unless exactly one base type
is present, and check the properties that cannot coexist.

Returning 0 rather than signalling is the whole error-handling strategy of the
calculus: an expression that violates a rule simply has no type, and every
combining rule tests for the properties it needs, so invalidity propagates
outward on its own."
  (let ((num-types (+ (if (mst-subset-p type (mst "K")) 1 0)
                      (if (mst-subset-p type (mst "V")) 1 0)
                      (if (mst-subset-p type (mst "B")) 1 0)
                      (if (mst-subset-p type (mst "W")) 1 0))))
    (if (/= num-types 1)
        0
        (progn
          ;; These are Core's CHECK_NONFATALs. A violation means the calculus
          ;; itself is wrong, not the expression, so it must be loud.
          (assert (not (and (mst-subset-p type (mst "z")) (mst-subset-p type (mst "o")))))
          (assert (not (and (mst-subset-p type (mst "n")) (mst-subset-p type (mst "z")))))
          (assert (not (and (mst-subset-p type (mst "n")) (mst-subset-p type (mst "W")))))
          (assert (not (and (mst-subset-p type (mst "V")) (mst-subset-p type (mst "d")))))
          (assert (or (not (mst-subset-p type (mst "K"))) (mst-subset-p type (mst "u"))))
          (assert (not (and (mst-subset-p type (mst "V")) (mst-subset-p type (mst "u")))))
          (assert (not (and (mst-subset-p type (mst "e")) (mst-subset-p type (mst "f")))))
          (assert (or (not (mst-subset-p type (mst "e"))) (mst-subset-p type (mst "d"))))
          (assert (not (and (mst-subset-p type (mst "V")) (mst-subset-p type (mst "e")))))
          type))))

(defun %ms-timelock-mix-p (a b)
  "T when combining branches with types A and B mixes a height lock with a time
lock of the same kind — the condition that clears the 'k' property, and the
reason it exists: such a miniscript cannot mean what its author expects."
  (or (and (mst-subset-p a (mst "g")) (mst-subset-p b (mst "h")))
      (and (mst-subset-p a (mst "h")) (mst-subset-p b (mst "g")))
      (and (mst-subset-p a (mst "i")) (mst-subset-p b (mst "j")))
      (and (mst-subset-p a (mst "j")) (mst-subset-p b (mst "i")))))

;;;; --- The type calculus (miniscript.cpp:39-262) --------------------------
;;;;
;;;; One rule per fragment, each computing the parent's type from its
;;;; children's. Core's comments name the boolean identity each line encodes
;;;; (o=o_x*z_y+z_x*o_y and so on); those are kept because they, not the code,
;;;; are the specification.

(defun ms-compute-type (fragment x y z sub-types k data-size n-subs n-keys
                        &optional (ctx :p2wsh))
  "Core ComputeType. X, Y and Z are the first three sub-expression types (0 when
absent); SUB-TYPES is every sub-type, needed only by THRESH. CTX is the
miniscript context, which one rule depends on — see :WRAP-D."
  (declare (ignorable data-size n-keys))
  (macrolet ((m (s) `(mst ,s)))
    (ecase fragment
      (:pk-k (m "Konudemsxk"))
      (:pk-h (m "Knudemsxk"))
      (:older (logior (mst-if (logtest k +ms-sequence-locktime-type-flag+) (m "g"))
                      (mst-if (not (logtest k +ms-sequence-locktime-type-flag+)) (m "h"))
                      (m "Bzfmxk")))
      (:after (logior (mst-if (>= k +ms-locktime-threshold+) (m "i"))
                      (mst-if (< k +ms-locktime-threshold+) (m "j"))
                      (m "Bzfmxk")))
      ((:sha256 :ripemd160 :hash256 :hash160) (m "Bonudmk"))
      (:just-1 (m "Bzufmxk"))
      (:just-0 (m "Bzudemsxk"))
      (:wrap-a (logior (mst-if (mst-subset-p x (m "B")) (m "W"))
                       (logand x (m "ghijk"))
                       (logand x (m "udfems"))
                       (m "x")))
      (:wrap-s (logior (mst-if (mst-subset-p x (m "Bo")) (m "W"))
                       (logand x (m "ghijk"))
                       (logand x (m "udfemsx"))))
      (:wrap-c (logior (mst-if (mst-subset-p x (m "K")) (m "B"))
                       (logand x (m "ghijk"))
                       (logand x (m "ondfem"))
                       (m "us")))
      (:wrap-d (logior (mst-if (mst-subset-p x (m "Vz")) (m "B"))
                       (mst-if (mst-subset-p x (m "z")) (m "o"))
                       (mst-if (mst-subset-p x (m "f")) (m "e"))
                       (logand x (m "ghijk"))
                       (logand x (m "ms"))
                       ;; 'd:' is 'u' under Tapscript but NOT under P2WSH,
                       ;; where MINIMALIF is only a policy rule
                       ;; (miniscript.cpp:125-126).
                       (mst-if (ms-tapscript-p ctx) (m "u"))
                       (m "ndx")))
      (:wrap-v (logior (mst-if (mst-subset-p x (m "B")) (m "V"))
                       (logand x (m "ghijk"))
                       (logand x (m "zonms"))
                       (m "fx")))
      (:wrap-j (logior (mst-if (mst-subset-p x (m "Bn")) (m "B"))
                       (mst-if (mst-subset-p x (m "f")) (m "e"))
                       (logand x (m "ghijk"))
                       (logand x (m "oums"))
                       (m "ndx")))
      (:wrap-n (logior (logand x (m "ghijk"))
                       (logand x (m "Bzondfems"))
                       (m "ux")))
      (:and-v (logior (mst-if (mst-subset-p x (m "V")) (logand y (m "KVB")))
                      (logand x (m "n"))
                      (mst-if (mst-subset-p x (m "z")) (logand y (m "n")))
                      (mst-if (mst-subset-p (logior x y) (m "z"))
                              (logand (logior x y) (m "o")))
                      (logand x y (m "mz"))
                      (logand (logior x y) (m "s"))
                      (mst-if (or (mst-subset-p y (m "f")) (mst-subset-p x (m "s"))) (m "f"))
                      (logand y (m "ux"))
                      (logand (logior x y) (m "ghij"))
                      (mst-if (and (mst-subset-p (logand x y) (m "k"))
                                   (not (%ms-timelock-mix-p x y)))
                              (m "k"))))
      (:and-b (logior (mst-if (mst-subset-p y (m "W")) (logand x (m "B")))
                      (mst-if (mst-subset-p (logior x y) (m "z"))
                              (logand (logior x y) (m "o")))
                      (logand x (m "n"))
                      (mst-if (mst-subset-p x (m "z")) (logand y (m "n")))
                      (mst-if (mst-subset-p (logand x y) (m "s")) (logand x y (m "e")))
                      (logand x y (m "dzm"))
                      (mst-if (or (mst-subset-p (logand x y) (m "f"))
                                  (mst-subset-p x (m "sf"))
                                  (mst-subset-p y (m "sf")))
                              (m "f"))
                      (logand (logior x y) (m "s"))
                      (m "ux")
                      (logand (logior x y) (m "ghij"))
                      (mst-if (and (mst-subset-p (logand x y) (m "k"))
                                   (not (%ms-timelock-mix-p x y)))
                              (m "k"))))
      (:or-b (logior (mst-if (and (mst-subset-p x (m "Bd")) (mst-subset-p y (m "Wd"))) (m "B"))
                     (mst-if (mst-subset-p (logior x y) (m "z"))
                             (logand (logior x y) (m "o")))
                     (mst-if (and (mst-subset-p (logior x y) (m "s"))
                                  (mst-subset-p (logand x y) (m "e")))
                             (logand x y (m "m")))
                     (logand x y (m "zse"))
                     (m "dux")
                     (logand (logior x y) (m "ghij"))
                     (logand x y (m "k"))))
      (:or-d (logior (mst-if (mst-subset-p x (m "Bdu")) (logand y (m "B")))
                     (mst-if (mst-subset-p y (m "z")) (logand x (m "o")))
                     (mst-if (and (mst-subset-p x (m "e"))
                                  (mst-subset-p (logior x y) (m "s")))
                             (logand x y (m "m")))
                     (logand x y (m "zs"))
                     (logand y (m "ufde"))
                     (m "x")
                     (logand (logior x y) (m "ghij"))
                     (logand x y (m "k"))))
      (:or-c (logior (mst-if (mst-subset-p x (m "Bdu")) (logand y (m "V")))
                     (mst-if (mst-subset-p y (m "z")) (logand x (m "o")))
                     (mst-if (and (mst-subset-p x (m "e"))
                                  (mst-subset-p (logior x y) (m "s")))
                             (logand x y (m "m")))
                     (logand x y (m "zs"))
                     (m "fx")
                     (logand (logior x y) (m "ghij"))
                     (logand x y (m "k"))))
      (:or-i (logior (logand x y (m "VBKufs"))
                     (mst-if (mst-subset-p (logand x y) (m "z")) (m "o"))
                     (mst-if (mst-subset-p (logior x y) (m "f"))
                             (logand (logior x y) (m "e")))
                     (mst-if (mst-subset-p (logior x y) (m "s")) (logand x y (m "m")))
                     (logand (logior x y) (m "d"))
                     (m "x")
                     (logand (logior x y) (m "ghij"))
                     (logand x y (m "k"))))
      (:andor (logior (mst-if (mst-subset-p x (m "Bdu")) (logand y z (m "BKV")))
                      (logand x y z (m "z"))
                      (mst-if (mst-subset-p (logior x (logand y z)) (m "z"))
                              (logand (logior x (logand y z)) (m "o")))
                      (logand y z (m "u"))
                      (mst-if (or (mst-subset-p x (m "s")) (mst-subset-p y (m "f")))
                              (logand z (m "f")))
                      (logand z (m "d"))
                      (mst-if (or (mst-subset-p x (m "s")) (mst-subset-p y (m "f")))
                              (logand z (m "e")))
                      (mst-if (and (mst-subset-p x (m "e"))
                                   (mst-subset-p (logior x y z) (m "s")))
                              (logand x y z (m "m")))
                      (logand z (logior x y) (m "s"))
                      (m "x")
                      (logand (logior x y z) (m "ghij"))
                      (mst-if (and (mst-subset-p (logand x y z) (m "k"))
                                   (not (%ms-timelock-mix-p x y)))
                              (m "k"))))
      (:multi (m "Bnudemsk"))
      (:multi-a (m "Budemsk"))
      (:thresh
       (let ((all-e t) (all-m t) (args 0) (num-s 0) (acc-tl (m "k")))
         (loop for type in sub-types
               for i from 0
               do (unless (mst-subset-p type (if (plusp i) (m "Wdu") (m "Bdu")))
                    (return-from ms-compute-type 0))
                  (unless (mst-subset-p type (m "e")) (setf all-e nil))
                  (unless (mst-subset-p type (m "m")) (setf all-m nil))
                  (when (mst-subset-p type (m "s")) (incf num-s))
                  (incf args (cond ((mst-subset-p type (m "z")) 0)
                                   ((mst-subset-p type (m "o")) 1)
                                   (t 2)))
                  ;; A thresh mixes timelocks only when its threshold is above
                  ;; one AND two different children carry conflicting kinds:
                  ;; with k=1 only one branch is ever taken.
                  (setf acc-tl
                        (logior (logand (logior acc-tl type) (m "ghij"))
                                (mst-if (and (mst-subset-p (logand acc-tl type) (m "k"))
                                             (or (<= k 1)
                                                 (not (%ms-timelock-mix-p acc-tl type))))
                                        (m "k")))))
         (logior (m "Bdu")
                 (mst-if (= args 0) (m "z"))
                 (mst-if (= args 1) (m "o"))
                 (mst-if (and all-e (= num-s n-subs)) (m "e"))
                 (mst-if (and all-e all-m (>= num-s (- n-subs k))) (m "m"))
                 (mst-if (>= num-s (- n-subs k -1)) (m "s"))
                 acc-tl)))))
  )

;;;; --- Script generation (miniscript.h:800-865) ---------------------------
;;;;
;;;; Three opcodes the interpreter's table knows by value but that have no
;;;; named constant here yet.

(defconstant +ms-op-size+ #x82)
(defconstant +ms-op-checklocktimeverify+ #xb1)
(defconstant +ms-op-checksequenceverify+ #xb2)

(defun %ms-push-number (n)
  "Script bytes pushing the number N, using the minimal encoding the script
interpreter requires (Core's CScript::operator<<(int64_t))."
  (cond ((zerop n) (vector +op-0+))
        ((<= 1 n 16) (vector (+ (1- +op-1+) n)))
        (t (let ((bytes '()))
             ;; Little-endian minimal CScriptNum, with a sign byte when the top
             ;; bit of the last byte would otherwise read as negative.
             (loop with v = n
                   while (plusp v)
                   do (push (logand v #xFF) bytes)
                      (setf v (ash v -8)))
             (setf bytes (nreverse bytes))
             (when (logtest (car (last bytes)) #x80)
               (setf bytes (append bytes (list 0))))
             (concatenate 'vector (vector (length bytes)) bytes)))))

(defconstant +ms-op-checksigadd+ #xba
  "BIP342 OP_CHECKSIGADD. Only reachable in a tapscript context: under P2WSH it
is OP_SUCCESS-adjacent and multi_a does not exist there at all.")

(defun %ms-key-bytes (key ctx)
  "How KEY serializes into a script in CTX.

Core: `In Tapscript keys always serialize as x-only, whether an x-only key was
used in the descriptor or not' (descriptor.cpp:1569). The 33-byte form in a
tapscript leaf is a different script, a different leaf hash and a different
ADDRESS — the same trap the tr() descriptor work hit twice."
  (if (and (ms-tapscript-p ctx) (= (length key) 33))
      (subseq key 1 33)
      key))

(defun %ms-push-data (bytes)
  "Script bytes pushing BYTES as data, minimally encoded."
  (let ((n (length bytes)))
    (cond ((< n 76) (concatenate 'vector (vector n) bytes))
          ((< n 256) (concatenate 'vector (vector 76 n) bytes))
          (t (concatenate 'vector (vector 77 (logand n #xFF) (ash n -8)) bytes)))))

(defun %ms-cat (&rest parts)
  "Concatenate script fragments, where each part is a byte, a byte vector, or
a list of those."
  (let ((out (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (labels ((emit (p)
               (cond ((null p))
                     ((integerp p) (vector-push-extend p out))
                     ((listp p) (mapc #'emit p))
                     (t (loop for b across p do (vector-push-extend b out))))))
      (mapc #'emit parts))
    (coerce out '(simple-array (unsigned-byte 8) (*)))))

(defun %ms-identity-key (key)
  "The default key converter: keys are already 33-byte compressed pubkeys."
  key)

(defun ms-node-script (node &optional verify (key-fn #'%ms-identity-key))
  "The script NODE compiles to (Core Node::ToScript).

KEY-FN is Core's ToPKBytes converter (miniscript.h's Key template parameter
plus its context object). It exists because a miniscript inside a DESCRIPTOR
holds key EXPRESSIONS — an xpub with an origin and a range — not bytes, and the
same node compiles to a different script at every range index. Keeping the
conversion a parameter is what lets one parsed node serve a whole range.

VERIFY is Core's flag for the -VERIFY conversion: `v:' on a sub-expression
whose type lacks the 'x' property is free, because the sub's final opcode has a
-VERIFY form to switch to rather than needing an OP_VERIFY appended. The flag
has to travel INTO the sub for that, which is why it is a parameter here and
not something applied afterwards."
  (let ((subs (ms-node-subs node)))
    (flet ((sub (i &optional v) (ms-node-script (nth i subs) v key-fn))
           ;; Core's ToPKBytes is context-aware: a tapscript node serializes
           ;; every key x-only regardless of how it was written
           ;; (descriptor.cpp:1568). Doing it HERE rather than at the two
           ;; fragments that push keys means pk_k, pk_h and multi_a cannot
           ;; disagree about it.
           (pk (k) (%ms-key-bytes (funcall key-fn k) (ms-node-ctx node))))
      (ecase (ms-node-fragment node)
        (:just-0 (%ms-cat +op-0+))
        (:just-1 (%ms-cat +op-1+))
        (:pk-k (%ms-cat (%ms-push-data (pk (first (ms-node-keys node))))))
        ;; DATA set means the 20-byte key HASH is all that is known, which is
        ;; what inference recovers: the script only ever committed to the hash,
        ;; so the key itself is not in it. Hashing again would be wrong.
        (:pk-h (%ms-cat +op-dup+ +op-hash160+
                        (%ms-push-data (or (ms-node-data node)
                                           (bl.crypto:hash160
                                            (pk (first (ms-node-keys node))))))
                        +op-equalverify+))
        (:older (%ms-cat (%ms-push-number (ms-node-k node)) +ms-op-checksequenceverify+))
        (:after (%ms-cat (%ms-push-number (ms-node-k node)) +ms-op-checklocktimeverify+))
        ((:sha256 :ripemd160 :hash256 :hash160)
         (%ms-cat +ms-op-size+ (%ms-push-number 32) +op-equalverify+
                  (ecase (ms-node-fragment node)
                    (:sha256 +op-sha256+) (:ripemd160 +op-ripemd160+)
                    (:hash256 +op-hash256+) (:hash160 +op-hash160+))
                  (%ms-push-data (ms-node-data node))
                  (if verify +op-equalverify+ +op-equal+)))
        (:wrap-a (%ms-cat +op-toaltstack+ (sub 0) +op-fromaltstack+))
        (:wrap-s (%ms-cat +op-swap+ (sub 0)))
        (:wrap-c (%ms-cat (sub 0) (if verify +op-checksigverify+ +op-checksig+)))
        (:wrap-d (%ms-cat +op-dup+ +op-if+ (sub 0) +op-endif+))
        (:wrap-v (if (mst-subset-p (ms-node-node-type (first subs)) (mst "x"))
                     (%ms-cat (sub 0) +op-verify+)
                     (sub 0 t)))
        (:wrap-j (%ms-cat +ms-op-size+ +op-0notequal+ +op-if+ (sub 0) +op-endif+))
        (:wrap-n (%ms-cat (sub 0) +op-0notequal+))
        (:and-v (%ms-cat (sub 0) (sub 1)))
        (:and-b (%ms-cat (sub 0) (sub 1) +op-booland+))
        (:or-b (%ms-cat (sub 0) (sub 1) +op-boolor+))
        (:or-d (%ms-cat (sub 0) +op-ifdup+ +op-notif+ (sub 1) +op-endif+))
        (:or-c (%ms-cat (sub 0) +op-notif+ (sub 1) +op-endif+))
        (:or-i (%ms-cat +op-if+ (sub 0) +op-else+ (sub 1) +op-endif+))
        (:andor (%ms-cat (sub 0) +op-notif+ (sub 2) +op-else+ (sub 1) +op-endif+))
        (:multi (%ms-cat (%ms-push-number (ms-node-k node))
                         (mapcar (lambda (k) (%ms-push-data (pk k)))
                                 (ms-node-keys node))
                         (%ms-push-number (length (ms-node-keys node)))
                         (if verify +op-checkmultisigverify+ +op-checkmultisig+)))
        ;; <x0> CHECKSIG (<xi> CHECKSIGADD)* <k> NUMEQUAL — BIP342's
        ;; replacement for CHECKMULTISIG, which tapscript removed.
        (:multi-a
         (let ((keys (ms-node-keys node)))
           (%ms-cat (%ms-push-data (pk (first keys)))
                    +op-checksig+
                    (mapcar (lambda (k)
                              (list (%ms-push-data (pk k)) +ms-op-checksigadd+))
                            (rest keys))
                    (%ms-push-number (ms-node-k node))
                    (if verify +ms-op-numequalverify+ +ms-op-numequal+))))
        (:thresh (%ms-cat (sub 0)
                          (loop for i from 1 below (length subs)
                                collect (list (sub i) +op-add+))
                          (%ms-push-number (ms-node-k node))
                          (if verify +op-equalverify+ +op-equal+)))))))

;;;; --- Construction --------------------------------------------------------

(defun make-ms-node (fragment &key subs keys (k 0) data (ctx *ms-context*))
  "Build a node and compute its type. A node whose type is 0 is INVALID, which
is how every rule violation surfaces — there is no separate error channel.

CTX defaults to the *MS-CONTEXT* the parse is running in, so no construction
site has to pass it and none can disagree with its siblings."
  (let* ((sub-types (mapcar #'ms-node-node-type subs))
         (x (or (first sub-types) 0))
         (y (or (second sub-types) 0))
         (z (or (third sub-types) 0))
         ;; A sub-expression that failed to type makes the parent fail too:
         ;; the calculus would otherwise read a 0 as "no properties" rather
         ;; than "invalid", and could hand back a type for a broken tree.
         (type (if (some #'zerop sub-types)
                   0
                   (ms-sanitize-type
                    (ms-compute-type fragment x y z sub-types k
                                     (length data) (length subs) (length keys)
                                     ctx))))
         (node (%make-ms-node :fragment fragment :subs subs :keys keys
                              :k k :data data :node-type type :ctx ctx)))
    ;; The script size is only computable when the keys are already bytes; a
    ;; descriptor's key expressions have no size until they are derived, and a
    ;; node built from them reports 0 rather than guessing.
    (setf (ms-node-script-size node)
          (if (or (zerop type)
                  (notevery (lambda (k) (typep k 'sequence)) keys))
              0
              (handler-case (length (ms-node-script node)) (error () 0))))
    node))

(defconstant +ms-max-p2wsh-script-size+ 3600
  "Core MAX_STANDARD_P2WSH_SCRIPT_SIZE (policy/policy.h:51), which is what
internal::MaxScriptSize returns outside tapscript (miniscript.h:293).")

(defconstant +ms-max-tapscript-script-size+ 329482
  "Core MaxScriptSize under tapscript (miniscript.h:284-292). A tapscript leaf
has no explicit size limit; Core derives a conservative one from what a
standard spending transaction can still carry:

  MAX_STANDARD_TX_WEIGHT (400000) - TX_BODY_LEEWAY_WEIGHT (378)
    - MAX_TAPSCRIPT_SAT_SIZE (70135) = 329487, less its own compact-size (5).

Written out rather than recomputed because every input is a Core constant and
the arithmetic is Core's, not ours — a recomputation here could drift from it
silently while looking principled.")

(defun ms-max-script-size (ctx)
  "Core internal::MaxScriptSize (miniscript.h:282)."
  (if (ms-tapscript-p ctx)
      +ms-max-tapscript-script-size+
      +ms-max-p2wsh-script-size+))

(defconstant +ms-max-p2wsh-stack-items+ 100
  "Core MAX_STANDARD_P2WSH_STACK_ITEMS (policy/policy.h:53).")

(defconstant +ms-max-ops-per-script+ 201
  "Core MAX_OPS_PER_SCRIPT (script/script.h:31).")

(defun ms-node-valid-p (node)
  "Core Node::IsValid (miniscript.h:1670): the expression typed successfully
AND its script fits the context's size limit.

The size half was missing here. Core's IsValid is `GetType() != \"\" &&
ScriptSize() <= MaxScriptSize(ctx)', and outside tapscript MaxScriptSize is
MAX_STANDARD_P2WSH_SCRIPT_SIZE (miniscript.h:293). Without it every predicate
built on IsValid — IsValidTopLevel, ValidSatisfactions, IsSane — was weaker
than Core's."
  (and node
       (plusp (ms-node-node-type node))
       (<= (ms-node-script-size node) (ms-max-script-size (ms-node-ctx node)))))

(defun ms-node-valid-top-level-p (node)
  "Core Node::IsValidTopLevel: the outermost expression must be a B."
  (and (ms-node-valid-p node)
       (mst-subset-p (ms-node-node-type node) (mst "B"))))

(defun ms-node-non-malleable-p (node)
  "Core Node::IsNonMalleable: property 'm'."
  (and node (mst-subset-p (ms-node-node-type node) (mst "m"))))

(defun ms-node-needs-signature-p (node)
  "Core Node::NeedsSignature: property 's'."
  (and node (mst-subset-p (ms-node-node-type node) (mst "s"))))

(defun ms-node-timelock-mix-p (node)
  "T when the expression mixes height and time locks in one spend path — the
absence of property 'k'. Such a miniscript does not mean what its author
expects, which is the whole reason the property is tracked.

NOTE THE POLARITY: this is the INVERSE of Core's CheckTimeLocksMix
(miniscript.h:1685), which is true when there is NO mix. Callers composing
Core's IsSane must negate it."
  (and node (not (mst-subset-p (ms-node-node-type node) (mst "k")))))

;;;; --- Resource limits: ops and stack size (miniscript.h internal::) --------
;;;;
;;;; Core computes these once in the Node constructor and caches them in the
;;;; `ops' and `ss' members. We recompute by walking the tree, because caching
;;;; them would mean new MS-NODE slots and this project's FASL volume outlives
;;;; a fresh container, so a defstruct layout change breaks even a clean build.
;;;; The gate that needs them runs once per descriptor parse, never on a hot
;;;; path, so the walk costs nothing that matters.

;;; MaxInt<uint32_t> (miniscript.h:363-385). NIL is Core's invalid — "no such
;;; satisfaction exists" — and an integer is a present value.

(defun ms-mi+ (a b)
  "Core MaxInt operator+: absence propagates."
  (and a b (+ a b)))

(defun ms-mi-or (a b)
  "Core MaxInt operator|: whichever is present, the larger when both are."
  (cond ((null a) b) ((null b) a) (t (max a b))))

;;; SatInfo (miniscript.h:439-502) is a set of execution traces, represented as
;;; NIL for the empty set or (NETDIFF . EXEC) for a non-empty one. NETDIFF is
;;; how much higher the stack can be at the start than at the end; EXEC is how
;;; much higher it can get anywhere during execution than at the end.
;;;
;;; Note that Core's SatInfo::Empty() is (0 . 0) — a set containing the empty
;;; script — and is NOT the same thing as the empty set SatInfo{}, which is
;;; NIL here. THRESH's accumulator starts at Empty(), not at NIL.

(defun ms-si (netdiff exec) (cons netdiff exec))
(defun ms-si-netdiff (s) (car s))
(defun ms-si-exec (s) (cdr s))

(defun ms-si-or (a b)
  "Core SatInfo operator|, set union: componentwise max."
  (cond ((null a) b)
        ((null b) a)
        (t (ms-si (max (car a) (car b)) (max (cdr a) (cdr b))))))

(defun ms-si+ (a b)
  "Core SatInfo operator+, concatenation with A running FIRST. Not commutative:
`OP_1 OP_DROP' has exec 1 and `OP_DROP OP_1' has exec 0."
  (when (and a b)
    (ms-si (+ (car a) (car b))
           (max (cdr b) (+ (car b) (cdr a))))))

(defmacro %ms-si-cat (&rest parts)
  "Left-to-right concatenation of PARTS, preserving execution order."
  (reduce (lambda (acc p) `(ms-si+ ,acc ,p)) (rest parts) :initial-value (first parts)))

;;; The named single-opcode scripts (miniscript.h:481-501).
(defun ms-si-empty ()   (ms-si 0 0))
(defun ms-si-push ()    (ms-si -1 0))
(defun ms-si-hash ()    (ms-si 0 0))
(defun ms-si-nop ()     (ms-si 0 0))
(defun ms-si-if ()      (ms-si 1 1))
(defun ms-si-binop ()   (ms-si 1 1))
(defun ms-si-dup ()     (ms-si -1 0))
(defun ms-si-ifdup (nonzero) (ms-si (if nonzero -1 0) 0))
(defun ms-si-equalverify () (ms-si 2 2))
(defun ms-si-equal ()   (ms-si 1 1))
(defun ms-si-size ()    (ms-si -1 0))
(defun ms-si-checksig () (ms-si 1 1))
(defun ms-si-0notequal () (ms-si 0 0))
(defun ms-si-verify ()  (ms-si 1 1))

(defun ms-node-ops (node)
  "Core Node::CalcOps (miniscript.h:999-1071) as (COUNT SAT DSAT): the static
non-push opcode count, and the MaxInt number of additional ops in a
satisfaction and a dissatisfaction."
  (let* ((subs (ms-node-subs node))
         (o (mapcar #'ms-node-ops subs))
         (c (mapcar #'first o))
         (s (mapcar #'second o))
         (d (mapcar #'third o))
         (nkeys (length (ms-node-keys node))))
    (macrolet ((c (i) `(nth ,i c)) (s (i) `(nth ,i s)) (d (i) `(nth ,i d)))
      (ecase (ms-node-fragment node)
        (:just-1 (list 0 0 nil))
        (:just-0 (list 0 nil 0))
        (:pk-k (list 0 0 0))
        (:pk-h (list 3 0 0))
        ((:older :after) (list 1 0 nil))
        ((:sha256 :ripemd160 :hash256 :hash160) (list 4 0 nil))
        (:and-v (list (+ (c 0) (c 1)) (ms-mi+ (s 0) (s 1)) nil))
        (:and-b (list (+ 1 (c 0) (c 1)) (ms-mi+ (s 0) (s 1)) (ms-mi+ (d 0) (d 1))))
        (:or-b (list (+ 1 (c 0) (c 1))
                     (ms-mi-or (ms-mi+ (s 0) (d 1)) (ms-mi+ (s 1) (d 0)))
                     (ms-mi+ (d 0) (d 1))))
        (:or-d (list (+ 3 (c 0) (c 1))
                     (ms-mi-or (s 0) (ms-mi+ (s 1) (d 0)))
                     (ms-mi+ (d 0) (d 1))))
        (:or-c (list (+ 2 (c 0) (c 1))
                     (ms-mi-or (s 0) (ms-mi+ (s 1) (d 0)))
                     nil))
        (:or-i (list (+ 3 (c 0) (c 1))
                     (ms-mi-or (s 0) (s 1))
                     (ms-mi-or (d 0) (d 1))))
        (:andor (list (+ 3 (c 0) (c 1) (c 2))
                      (ms-mi-or (ms-mi+ (s 1) (s 0)) (ms-mi+ (d 0) (s 2)))
                      (ms-mi+ (d 0) (d 2))))
        (:multi (list 1 nkeys nkeys))
        (:multi-a (list (1+ nkeys) 0 0))
        ((:wrap-s :wrap-c :wrap-n) (list (+ 1 (c 0)) (s 0) (d 0)))
        (:wrap-a (list (+ 2 (c 0)) (s 0) (d 0)))
        (:wrap-d (list (+ 3 (c 0)) (s 0) 0))
        (:wrap-j (list (+ 4 (c 0)) (s 0) 0))
        (:wrap-v (list (+ (c 0) (if (mst-subset-p (ms-node-node-type (first subs)) (mst "x")) 1 0))
                       (s 0) nil))
        (:thresh
         (let ((count 0)
               (sats (vector 0)))
           (loop for sub-ops in o
                 do (incf count (1+ (first sub-ops)))
                    (let* ((ssat (second sub-ops))
                           (sdsat (third sub-ops))
                           (next (make-array (1+ (length sats)))))
                      (setf (aref next 0) (ms-mi+ (aref sats 0) sdsat))
                      (loop for j from 1 below (length sats)
                            do (setf (aref next j)
                                     (ms-mi-or (ms-mi+ (aref sats j) sdsat)
                                               (ms-mi+ (aref sats (1- j)) ssat))))
                      (setf (aref next (length sats))
                            (ms-mi+ (aref sats (1- (length sats))) ssat))
                      (setf sats next)))
           (list count (aref sats (ms-node-k node)) (aref sats 0))))))))

(defun ms-node-stack-size (node)
  "Core Node::CalcStackSize (miniscript.h:1073-1183) as (SAT . DSAT), each a
SatInfo."
  (let* ((subs (ms-node-subs node))
         (ss (mapcar #'ms-node-stack-size subs))
         (nkeys (length (ms-node-keys node)))
         (k (ms-node-k node)))
    (macrolet ((sat (i) `(car (nth ,i ss))) (dsat (i) `(cdr (nth ,i ss))))
      (flet ((both (x) (cons x x)))
        (ecase (ms-node-fragment node)
          (:just-0 (cons nil (ms-si-push)))
          (:just-1 (cons (ms-si-push) nil))
          ((:older :after) (cons (%ms-si-cat (ms-si-push) (ms-si-nop)) nil))
          (:pk-k (both (ms-si-push)))
          (:pk-h (both (%ms-si-cat (ms-si-dup) (ms-si-hash) (ms-si-push) (ms-si-equalverify))))
          ((:sha256 :ripemd160 :hash256 :hash160)
           (cons (%ms-si-cat (ms-si-size) (ms-si-push) (ms-si-equalverify)
                             (ms-si-hash) (ms-si-push) (ms-si-equal))
                 nil))
          (:andor (cons (ms-si-or (%ms-si-cat (sat 0) (ms-si-if) (sat 1))
                                  (%ms-si-cat (dsat 0) (ms-si-if) (sat 2)))
                        (%ms-si-cat (dsat 0) (ms-si-if) (dsat 2))))
          (:and-v (cons (ms-si+ (sat 0) (sat 1)) nil))
          (:and-b (cons (%ms-si-cat (sat 0) (sat 1) (ms-si-binop))
                        (%ms-si-cat (dsat 0) (dsat 1) (ms-si-binop))))
          (:or-b (cons (ms-si+ (ms-si-or (ms-si+ (sat 0) (dsat 1))
                                         (ms-si+ (dsat 0) (sat 1)))
                               (ms-si-binop))
                       (%ms-si-cat (dsat 0) (dsat 1) (ms-si-binop))))
          (:or-c (cons (ms-si-or (ms-si+ (sat 0) (ms-si-if))
                                 (%ms-si-cat (dsat 0) (ms-si-if) (sat 1)))
                       nil))
          (:or-d (cons (ms-si-or (%ms-si-cat (sat 0) (ms-si-ifdup t) (ms-si-if))
                                 (%ms-si-cat (dsat 0) (ms-si-ifdup nil) (ms-si-if) (sat 1)))
                       (%ms-si-cat (dsat 0) (ms-si-ifdup nil) (ms-si-if) (dsat 1))))
          (:or-i (cons (ms-si+ (ms-si-if) (ms-si-or (sat 0) (sat 1)))
                       (ms-si+ (ms-si-if) (ms-si-or (dsat 0) (dsat 1)))))
          ;; multi starts with k+1 elements, reaches n+k+3 after pushing the n
          ;; keys plus k and n, and ends with 1 (miniscript.h:1135-1138).
          (:multi (both (ms-si k (+ k nkeys 2))))
          (:multi-a (both (ms-si (1- nkeys) nkeys)))
          ((:wrap-a :wrap-n :wrap-s) (first ss))
          (:wrap-c (cons (ms-si+ (sat 0) (ms-si-checksig))
                         (ms-si+ (dsat 0) (ms-si-checksig))))
          (:wrap-d (cons (%ms-si-cat (ms-si-dup) (ms-si-if) (sat 0))
                         (%ms-si-cat (ms-si-dup) (ms-si-if))))
          (:wrap-v (cons (ms-si+ (sat 0) (ms-si-verify)) nil))
          (:wrap-j (cons (%ms-si-cat (ms-si-size) (ms-si-0notequal) (ms-si-if) (sat 0))
                         (%ms-si-cat (ms-si-size) (ms-si-0notequal) (ms-si-if))))
          (:thresh
           (let ((sats (vector (ms-si-empty))))
             (loop for sub in ss
                   for i from 0
                   do (let* ((add (if (plusp i) (ms-si-binop) (ms-si-empty)))
                             (next (make-array (1+ (length sats)))))
                        (setf (aref next 0)
                              (%ms-si-cat (aref sats 0) (cdr sub) add))
                        (loop for j from 1 below (length sats)
                              do (setf (aref next j)
                                       (ms-si+ (ms-si-or (ms-si+ (aref sats j) (cdr sub))
                                                         (ms-si+ (aref sats (1- j)) (car sub)))
                                               add)))
                        (setf (aref next (length sats))
                              (%ms-si-cat (aref sats (1- (length sats))) (car sub) add))
                        (setf sats next)))
             (cons (%ms-si-cat (aref sats k) (ms-si-push) (ms-si-equal))
                   (%ms-si-cat (aref sats 0) (ms-si-push) (ms-si-equal))))))))))

(defun ms-node-bkw-p (node)
  "Core Node::IsBKW (miniscript.h:1573): the node is a B, K or W — anything but
a V. An INTERSECTION test, not a subset one: any of the three qualifies."
  (/= 0 (logand (ms-node-node-type node) (mst "BKW"))))

(defun ms-node-get-ops (node)
  "Core Node::GetOps (miniscript.h:1557): total ops to satisfy non-malleably,
or NIL when no satisfaction exists."
  (destructuring-bind (count sat dsat) (ms-node-ops node)
    (declare (ignore dsat))
    (and sat (+ count sat))))

(defun ms-node-check-ops-limit-p (node)
  "Core Node::CheckOpsLimit (miniscript.h:1566). A node with no satisfaction
passes — IsNotSatisfiable is what rejects that, separately."
  (let ((ops (ms-node-get-ops node)))
    (or (null ops) (<= ops +ms-max-ops-per-script+))))

(defconstant +ms-p2wsh-sig-size+ 73
  "Core CalcWitnessSize's sig_size outside tapscript: 1 length byte + a 72-byte
signature (miniscript.h:1189).")

(defconstant +ms-p2wsh-pubkey-size+ 34
  "Core CalcWitnessSize's pubkey_size outside tapscript: 1 + 33.")

(defconstant +ms-tapscript-sig-size+ 66
  "1 + 65: a BIP340 signature with a sighash-type byte (miniscript.h:1189).")

(defconstant +ms-tapscript-pubkey-size+ 33
  "1 + 32: keys are x-only under tapscript (miniscript.h:1190).")

(defun ms-node-witness-size (node)
  "Core Node::CalcWitnessSize (miniscript.h:1187-1237) as (SAT . DSAT), each a
MaxInt: the maximum witness bytes to satisfy and to dissatisfy NODE
non-malleably. Excludes the witnessScript push, exactly as Core's does."
  (let* ((subs (ms-node-subs node))
         (w (mapcar #'ms-node-witness-size subs))
         (nkeys (length (ms-node-keys node)))
         (k (ms-node-k node))
         (tap (ms-tapscript-p (ms-node-ctx node)))
         (sig (if tap +ms-tapscript-sig-size+ +ms-p2wsh-sig-size+))
         (pub (if tap +ms-tapscript-pubkey-size+ +ms-p2wsh-pubkey-size+)))
    (macrolet ((sat (i) `(car (nth ,i w))) (dsat (i) `(cdr (nth ,i w))))
      (ecase (ms-node-fragment node)
        (:just-0 (cons nil 0))
        ((:just-1 :older :after) (cons 0 nil))
        (:pk-k (cons sig 1))
        (:pk-h (cons (+ sig pub) (+ 1 pub)))
        ((:sha256 :ripemd160 :hash256 :hash160) (cons (+ 1 32) nil))
        (:andor (cons (ms-mi-or (ms-mi+ (sat 0) (sat 1))
                                (ms-mi+ (dsat 0) (sat 2)))
                      (ms-mi+ (dsat 0) (dsat 2))))
        (:and-v (cons (ms-mi+ (sat 0) (sat 1)) nil))
        (:and-b (cons (ms-mi+ (sat 0) (sat 1)) (ms-mi+ (dsat 0) (dsat 1))))
        (:or-b (cons (ms-mi-or (ms-mi+ (dsat 0) (sat 1))
                               (ms-mi+ (sat 0) (dsat 1)))
                     (ms-mi+ (dsat 0) (dsat 1))))
        (:or-c (cons (ms-mi-or (sat 0) (ms-mi+ (dsat 0) (sat 1))) nil))
        (:or-d (cons (ms-mi-or (sat 0) (ms-mi+ (dsat 0) (sat 1)))
                     (ms-mi+ (dsat 0) (dsat 1))))
        ;; The +1/+2 are the branch selector pushed for OP_IF.
        (:or-i (cons (ms-mi-or (ms-mi+ (sat 0) 2) (ms-mi+ (sat 1) 1))
                     (ms-mi-or (ms-mi+ (dsat 0) 2) (ms-mi+ (dsat 1) 1))))
        (:multi (cons (+ (* k sig) 1) (+ k 1)))
        (:multi-a (cons (+ (* k sig) (- nkeys k)) nkeys))
        ((:wrap-a :wrap-n :wrap-s :wrap-c) (first w))
        (:wrap-d (cons (ms-mi+ 2 (sat 0)) 1))
        (:wrap-v (cons (sat 0) nil))
        (:wrap-j (cons (sat 0) 1))
        (:thresh
         (let ((sats (vector 0)))
           (dolist (sub w)
             (let ((next (make-array (1+ (length sats)))))
               (setf (aref next 0) (ms-mi+ (aref sats 0) (cdr sub)))
               (loop for j from 1 below (length sats)
                     do (setf (aref next j)
                              (ms-mi-or (ms-mi+ (aref sats j) (cdr sub))
                                        (ms-mi+ (aref sats (1- j)) (car sub)))))
               (setf (aref next (length sats))
                     (ms-mi+ (aref sats (1- (length sats))) (car sub)))
               (setf sats next)))
           (cons (aref sats k) (aref sats 0))))))))

(defun ms-node-get-witness-size (node)
  "Core Node::GetWitnessSize (miniscript.h:1606): witness bytes to satisfy NODE
non-malleably, or NIL when no satisfaction exists. Does NOT include the
witnessScript push."
  (car (ms-node-witness-size node)))

(defun ms-node-get-stack-size (node)
  "Core Node::GetStackSize (miniscript.h:1578): stack elements needed to
satisfy non-malleably, or NIL when no satisfaction exists."
  (let ((sat (car (ms-node-stack-size node))))
    (and sat (+ (ms-si-netdiff sat) (if (ms-node-bkw-p node) 1 0)))))

(defconstant +ms-max-stack-size+ 1000
  "Core MAX_STACK_SIZE (script.h:43) — the CONSENSUS stack limit, which is what
bounds a tapscript, since tapscript has no standardness limit on script or
witness size to bound it earlier.")

(defun ms-node-exec-stack-size (node)
  "Core Node::GetExecStackSize (miniscript.h:1584): the deepest the stack gets
while EXECUTING, as opposed to the number of witness items handed in."
  (let ((sat (car (ms-node-stack-size node))))
    (and sat (+ (ms-si-exec sat) (if (ms-node-bkw-p node) 1 0)))))

(defun ms-node-check-stack-size-p (node)
  "Core Node::CheckStackSize (miniscript.h:1590).

The two contexts check different things and it is worth seeing why: under
P2WSH the WITNESS ITEM COUNT is what standardness caps, so the input side is
the binding constraint. Under tapscript neither script nor witness size is
capped by standardness, so nothing stops execution from reaching the CONSENSUS
stack limit — which is the thing Core checks there instead."
  (if (ms-tapscript-p (ms-node-ctx node))
      (let ((exec (ms-node-exec-stack-size node)))
        (or (null exec) (<= exec +ms-max-stack-size+)))
      (let ((ss (ms-node-get-stack-size node)))
        (or (null ss) (<= ss +ms-max-p2wsh-stack-items+)))))

(defun ms-node-not-satisfiable-p (node)
  "Core Node::IsNotSatisfiable (miniscript.h:1602)."
  (null (ms-node-get-stack-size node)))

(defun ms-node-duplicate-keys-p (node)
  "T when any public key appears more than once anywhere in the expression —
the negation of Core's CheckDuplicateKey (miniscript.h:1688).

Core computes this with a bottom-up merge of per-subtree key sets
(miniscript.h:1505-1547) so it can share work across a parse; one flat walk is
the same answer for a single expression."
  (let ((seen (make-hash-table :test 'equalp))
        (dup nil))
    (labels ((walk (n)
               (when (and n (not dup))
                 (dolist (key (ms-node-keys n))
                   (let ((id key))
                     (when (gethash id seen) (setf dup t) (return))
                     (setf (gethash id seen) t)))
                 (mapc #'walk (ms-node-subs n)))))
      (walk node))
    dup))

(defun ms-node-valid-satisfactions-p (node)
  "Core Node::ValidSatisfactions (miniscript.h:1691)."
  (and (ms-node-valid-p node)
       (ms-node-check-ops-limit-p node)
       (ms-node-check-stack-size-p node)))

(defun ms-node-sane-subexpression-p (node)
  "Core Node::IsSaneSubexpression (miniscript.h:1694)."
  (and (ms-node-valid-satisfactions-p node)
       (ms-node-non-malleable-p node)
       (not (ms-node-timelock-mix-p node))   ; Core's CheckTimeLocksMix, un-inverted
       (not (ms-node-duplicate-keys-p node))))

(defun ms-node-sane-p (node)
  "Core Node::IsSane (miniscript.h:1697): safe as a script on its own."
  (and (ms-node-valid-top-level-p node)
       (ms-node-sane-subexpression-p node)
       (ms-node-needs-signature-p node)))

(defun ms-find-insane-sub (node)
  "Core Node::FindInsaneSub (miniscript.h:1618): the first subexpression, in
Core's post-order traversal, that is not a sane subexpression. NIL when every
sub is sane and the insanity is a property of NODE itself."
  (labels ((walk (n)
             (dolist (sub (ms-node-subs n))
               (let ((found (walk sub)))
                 (when found (return-from walk found))))
             (unless (ms-node-sane-subexpression-p n) n)))
    (let ((found (walk node)))
      (and found (not (eq found node)) found))))

;;;; --- Parsing (miniscript.h FromString) -----------------------------------
;;;;
;;;; The expression grammar is a fragment name, its arguments in parentheses,
;;;; optionally preceded by a colon-terminated run of single-letter wrappers:
;;;;
;;;;   and_v(v:pk(A),older(144))
;;;;   thresh(2,pk(A),s:pk(B),s:pk(C))
;;;;
;;;; Four spellings are pure sugar and expand at parse time, exactly as Core
;;;; does — the tree has no fragments for them, so anything walking it sees
;;;; only the canonical forms:
;;;;
;;;;   pk(K)     = c:pk_k(K)        pkh(K)    = c:pk_h(K)
;;;;   and_n(X,Y)= andor(X,Y,0)     t:X       = and_v(X,1)
;;;;   l:X       = or_i(0,X)        u:X       = or_i(X,0)

(define-condition miniscript-parse-error (bitcoin-lisp-error)
  ((message :initarg :message :reader miniscript-parse-error-message))
  (:report (lambda (c s) (format s "~A" (miniscript-parse-error-message c))))
  (:documentation "The expression could not be parsed at all. Distinct from an
expression that parses and then fails to type, which is not an error condition
but a node whose type is zero."))

(defun %ms-fail (fmt &rest args)
  (error 'miniscript-parse-error :message (apply #'format nil fmt args)))

(defun %ms-split-args (string)
  "Split a comma-separated argument list at top level, respecting nesting."
  (let ((args '()) (depth 0) (start 0))
    (loop for i from 0 below (length string)
          for ch = (char string i)
          do (case ch
               (#\( (incf depth))
               (#\) (decf depth)
               )
               (#\, (when (zerop depth)
                      (push (subseq string start i) args)
                      (setf start (1+ i))))))
    (push (subseq string start) args)
    (nreverse args)))

(defun %ms-parse-hex (string expected-bytes what)
  (unless (and (= (length string) (* 2 expected-bytes))
               (every (lambda (c) (digit-char-p c 16)) string))
    (%ms-fail "~A must be ~D hex characters, got ~S" what (* 2 expected-bytes) string))
  (bl.crypto:hex-to-bytes string))

(defun %ms-parse-number (string what)
  (let ((n (handler-case (parse-integer string) (error () nil))))
    (unless (and n (<= 0 n #xFFFFFFFF))
      (%ms-fail "~A must be a number, got ~S" what string))
    n))

(defvar *ms-key-parser* nil
  "When bound, the function used to turn a key argument's text into whatever a
node should hold. NIL means raw 33-byte compressed hex, which is what Core's
test vectors use. The descriptor layer binds it so a miniscript can hold key
EXPRESSIONS -- xpubs with origins and ranges -- instead.")

(defun %ms-parse-key (string)
  "A public key argument, via *MS-KEY-PARSER* or as raw compressed hex."
  (if *ms-key-parser*
      (funcall *ms-key-parser* string)
      (%ms-parse-hex string 33 "public key")))

(defun %ms-apply-wrappers (wrappers node)
  "Apply WRAPPERS right to left: `vc:X' is v(c(X)), not c(v(X))."
  (dolist (w (reverse wrappers) node)
    (setf node
          (case w
            (#\a (make-ms-node :wrap-a :subs (list node)))
            (#\s (make-ms-node :wrap-s :subs (list node)))
            (#\c (make-ms-node :wrap-c :subs (list node)))
            (#\d (make-ms-node :wrap-d :subs (list node)))
            (#\v (make-ms-node :wrap-v :subs (list node)))
            (#\j (make-ms-node :wrap-j :subs (list node)))
            (#\n (make-ms-node :wrap-n :subs (list node)))
            ;; Sugar: t: is and_v(X,1), l: is or_i(0,X), u: is or_i(X,0).
            (#\t (make-ms-node :and-v :subs (list node (make-ms-node :just-1))))
            (#\l (make-ms-node :or-i :subs (list (make-ms-node :just-0) node)))
            (#\u (make-ms-node :or-i :subs (list node (make-ms-node :just-0))))
            (t (%ms-fail "unknown miniscript wrapper ~S" w))))))

(defun ms-parse (string &key (ctx *ms-context*))
  "Parse a miniscript expression. Returns an MS-NODE, whose type is zero when
the expression is well-formed but does not satisfy the type rules. Signals
MINISCRIPT-PARSE-ERROR when it is not well-formed at all.

CTX is :P2WSH (the default, and what wsh() asks for) or :TAPSCRIPT (what a tr()
leaf asks for). It is bound for the whole recursive parse, so every node of one
expression shares it."
  (let ((*ms-context* ctx)
        (wrappers '()) (i 0))
    ;; Leading wrappers, up to the colon. A colon can only appear here, so the
    ;; search is unambiguous: find it before the first '(' if there is one.
    (let ((colon (position #\: string))
          (paren (position #\( string)))
      (when (and colon (or (null paren) (< colon paren)))
        (setf wrappers (coerce (subseq string 0 colon) 'list)
              i (1+ colon))
        (when (null wrappers) (%ms-fail "empty wrapper before ':' in ~S" string))
        ;; The remainder may carry wrappers of its own — `t:v:1' is t(v(1)) —
        ;; so it is parsed as a whole expression rather than as a fragment
        ;; name. Core's parser reaches the same shape by pushing a wrapper and
        ;; continuing on the rest.
        (return-from ms-parse
          (%ms-apply-wrappers wrappers (ms-parse (subseq string i))))))
    (let* ((body (subseq string i))
           (open (position #\( body))
           (name (if open (subseq body 0 open) body))
           (args (if open
                     (progn
                       (unless (char= (char body (1- (length body))) #\))
                         (%ms-fail "unbalanced parentheses in ~S" body))
                       (%ms-split-args (subseq body (1+ open) (1- (length body)))))
                     nil))
           (node
             (cond
               ((and (string= name "0") (null open)) (make-ms-node :just-0))
               ((and (string= name "1") (null open)) (make-ms-node :just-1))
               ((string= name "pk_k") (make-ms-node :pk-k :keys (list (%ms-parse-key (first args)))))
               ((string= name "pk_h") (make-ms-node :pk-h :keys (list (%ms-parse-key (first args)))))
               ;; Sugar: pk(K) is c:pk_k(K), pkh(K) is c:pk_h(K).
               ((string= name "pk")
                (make-ms-node :wrap-c
                              :subs (list (make-ms-node :pk-k
                                                        :keys (list (%ms-parse-key (first args)))))))
               ((string= name "pkh")
                (make-ms-node :wrap-c
                              :subs (list (make-ms-node :pk-h
                                                        :keys (list (%ms-parse-key (first args)))))))
               ((string= name "older")
                (let ((k (%ms-parse-number (first args) "older")))
                  (if (and (>= k 1) (< k #x80000000))
                      (make-ms-node :older :k k)
                      ;; Out of range is INVALID, not unparseable: Core's
                      ;; fixed_tests spell older(0) and older(2^31) as invalid
                      ;; expressions rather than as parse failures.
                      (%make-ms-node :fragment :older :k 0 :node-type 0))))
               ((string= name "after")
                (let ((k (%ms-parse-number (first args) "after")))
                  (if (and (>= k 1) (< k #x80000000))
                      (make-ms-node :after :k k)
                      (%make-ms-node :fragment :after :k 0 :node-type 0))))
               ((string= name "sha256")
                (make-ms-node :sha256 :data (%ms-parse-hex (first args) 32 "sha256")))
               ((string= name "hash256")
                (make-ms-node :hash256 :data (%ms-parse-hex (first args) 32 "hash256")))
               ((string= name "ripemd160")
                (make-ms-node :ripemd160 :data (%ms-parse-hex (first args) 20 "ripemd160")))
               ((string= name "hash160")
                (make-ms-node :hash160 :data (%ms-parse-hex (first args) 20 "hash160")))
               ((string= name "and_v") (make-ms-node :and-v :subs (mapcar #'ms-parse args)))
               ((string= name "and_b") (make-ms-node :and-b :subs (mapcar #'ms-parse args)))
               ((string= name "or_b") (make-ms-node :or-b :subs (mapcar #'ms-parse args)))
               ((string= name "or_c") (make-ms-node :or-c :subs (mapcar #'ms-parse args)))
               ((string= name "or_d") (make-ms-node :or-d :subs (mapcar #'ms-parse args)))
               ((string= name "or_i") (make-ms-node :or-i :subs (mapcar #'ms-parse args)))
               ((string= name "andor") (make-ms-node :andor :subs (mapcar #'ms-parse args)))
               ;; Sugar: and_n(X,Y) is andor(X,Y,0).
               ((string= name "and_n")
                (unless (= 2 (length args)) (%ms-fail "and_n takes two arguments"))
                (make-ms-node :andor :subs (list (ms-parse (first args))
                                                 (ms-parse (second args))
                                                 (make-ms-node :just-0))))
               ((string= name "thresh")
                (unless (>= (length args) 2) (%ms-fail "thresh needs a threshold and subs"))
                (let ((k (%ms-parse-number (first args) "thresh"))
                      (subs (mapcar #'ms-parse (rest args))))
                  (if (and (>= k 1) (<= k (length subs)))
                      (make-ms-node :thresh :k k :subs subs)
                      (%make-ms-node :fragment :thresh :k 0 :node-type 0))))
               ;; multi is P2WSH-only and multi_a tapscript-only: BIP342
               ;; removed CHECKMULTISIG and introduced CHECKSIGADD in its place
               ;; (miniscript.cpp, Fragment::MULTI / MULTI_A). A fragment used
               ;; in the wrong context is INVALID rather than unknown, so it
               ;; reports a zero type like every other rule violation.
               ((string= name "multi")
                (unless (>= (length args) 2) (%ms-fail "multi needs a threshold and keys"))
                (let ((k (%ms-parse-number (first args) "multi"))
                      (keys (mapcar #'%ms-parse-key (rest args))))
                  (if (and (not (ms-tapscript-p *ms-context*))
                           (>= k 1) (<= k (length keys))
                           (<= (length keys) +ms-max-pubkeys-per-multisig+))
                      (make-ms-node :multi :k k :keys keys)
                      (%make-ms-node :fragment :multi :k 0 :node-type 0))))
               ((string= name "multi_a")
                (unless (>= (length args) 2) (%ms-fail "multi_a needs a threshold and keys"))
                (let ((k (%ms-parse-number (first args) "multi_a"))
                      (keys (mapcar #'%ms-parse-key (rest args))))
                  (if (and (ms-tapscript-p *ms-context*)
                           (>= k 1) (<= k (length keys))
                           (<= (length keys) +ms-max-pubkeys-per-multi-a+))
                      (make-ms-node :multi-a :k k :keys keys)
                      (%make-ms-node :fragment :multi-a :k 0 :node-type 0))))
               (t (%ms-fail "unknown miniscript fragment ~S" name)))))
      (%ms-apply-wrappers wrappers node))))

;;;; --- Rendering (miniscript.h:890-995) ------------------------------------

(defun %ms-identity-key-string (key)
  (if (stringp key) key (string-downcase (bl.crypto:bytes-to-hex key))))

(defun %ms-key-or-hash-string (node key-fn)
  "How to name a pk_h's subject. A parsed node holds the key; an INFERRED one
holds only the 20-byte hash the script committed to, because the key is not in
the script. Printing the hash is what Core's inference does too — it is the
most that can honestly be said about the script."
  (if (ms-node-data node)
      (string-downcase (bl.crypto:bytes-to-hex (ms-node-data node)))
      (funcall key-fn (first (ms-node-keys node)))))

(defun ms-node-to-string (node &optional (key-fn #'%ms-identity-key-string) wrapped)
  "The canonical expression text for NODE (Core Node::ToString).

Re-sugars on the way out, exactly as Core does: c:pk_k(K) prints as pk(K),
and_v(X,1) as t:X, or_i(0,X) as l:X, or_i(X,0) as u:X and andor(X,Y,0) as
and_n(X,Y). A descriptor's canonical string feeds its checksum and its ID, so
printing the desugared form instead would give the same policy two identities.

WRAPPED is Core's flag for `my parent is a wrapper': the colon belongs to the
wrapped node, not to the wrapper, so `a' + `:pk(K)' composes to `a:pk(K)' and a
run of wrappers needs only one colon."
  (let ((subs (ms-node-subs node))
        (prefix (if wrapped ":" "")))
    (labels ((sub (i &optional w) (ms-node-to-string (nth i subs) key-fn w))
             (frag (i) (ms-node-fragment (nth i subs)))
             (key (k) (funcall key-fn k)))
      (case (ms-node-fragment node)
        ;; Wrappers: the letter, then the sub rendered as a wrapped node.
        (:wrap-a (concatenate 'string "a" (sub 0 t)))
        (:wrap-s (concatenate 'string "s" (sub 0 t)))
        (:wrap-c (case (frag 0)
                   (:pk-k (format nil "~Apk(~A)" prefix
                                  (key (first (ms-node-keys (nth 0 subs))))))
                   ;; An INFERRED pk_h has only the hash the script committed
                   ;; to; there is no key in the script to print.
                   (:pk-h (format nil "~Apkh(~A)" prefix
                                  (%ms-key-or-hash-string (nth 0 subs) key-fn)))
                   (t (concatenate 'string "c" (sub 0 t)))))
        (:wrap-d (concatenate 'string "d" (sub 0 t)))
        (:wrap-v (concatenate 'string "v" (sub 0 t)))
        (:wrap-j (concatenate 'string "j" (sub 0 t)))
        (:wrap-n (concatenate 'string "n" (sub 0 t)))
        (t
         (case (ms-node-fragment node)
           ;; Sugar that is a wrapper in the source text but a combinator here.
           (:and-v (if (eq (frag 1) :just-1)
                       (concatenate 'string "t" (sub 0 t))
                       (format nil "~Aand_v(~A,~A)" prefix (sub 0) (sub 1))))
           (:or-i (cond ((eq (frag 0) :just-0) (concatenate 'string "l" (sub 1 t)))
                        ((eq (frag 1) :just-0) (concatenate 'string "u" (sub 0 t)))
                        (t (format nil "~Aor_i(~A,~A)" prefix (sub 0) (sub 1)))))
           (:andor (if (eq (frag 2) :just-0)
                       (format nil "~Aand_n(~A,~A)" prefix (sub 0) (sub 1))
                       (format nil "~Aandor(~A,~A,~A)" prefix (sub 0) (sub 1) (sub 2))))
           (:just-0 (concatenate 'string prefix "0"))
           (:just-1 (concatenate 'string prefix "1"))
           (:pk-k (format nil "~Apk_k(~A)" prefix (key (first (ms-node-keys node)))))
           (:pk-h (format nil "~Apk_h(~A)" prefix
                          (%ms-key-or-hash-string node key-fn)))
           (:older (format nil "~Aolder(~D)" prefix (ms-node-k node)))
           (:after (format nil "~Aafter(~D)" prefix (ms-node-k node)))
           ((:sha256 :hash256 :ripemd160 :hash160)
            (format nil "~A~(~A~)(~A)" prefix (ms-node-fragment node)
                    (string-downcase (bl.crypto:bytes-to-hex (ms-node-data node)))))
           (:and-b (format nil "~Aand_b(~A,~A)" prefix (sub 0) (sub 1)))
           (:or-b (format nil "~Aor_b(~A,~A)" prefix (sub 0) (sub 1)))
           (:or-c (format nil "~Aor_c(~A,~A)" prefix (sub 0) (sub 1)))
           (:or-d (format nil "~Aor_d(~A,~A)" prefix (sub 0) (sub 1)))
           (:multi (format nil "~Amulti(~D~{,~A~})" prefix (ms-node-k node)
                           (mapcar #'key (ms-node-keys node))))
           ;; The tapscript sibling. Adding the FRAGMENT without adding its
           ;; rendering left a node that parses, types and compiles but cannot
           ;; be printed — and a descriptor is printed on every listdescriptors,
           ;; getaddressinfo and wallet backup, so the gap surfaced as RPC
           ;; -32603 rather than as anything about miniscript.
           (:multi-a (format nil "~Amulti_a(~D~{,~A~})" prefix (ms-node-k node)
                             (mapcar #'key (ms-node-keys node))))
           (:thresh (format nil "~Athresh(~D~{,~A~})" prefix (ms-node-k node)
                            (loop for i from 0 below (length subs) collect (sub i))))
           (t (internal-error "cannot render miniscript fragment ~S"
                     (ms-node-fragment node)))))))))

;;;; --- Satisfaction (miniscript.h:1242-1440, miniscript.cpp:298-366) -------
;;;;
;;;; Every node yields a PAIR: the best way to satisfy it and the best way to
;;;; dissatisfy it, each a witness stack. Combinators build theirs from their
;;;; children's, and the two operators below do all the choosing — which is why
;;;; miniscript can promise a non-malleable witness rather than hoping for one.
;;;;
;;;; Stacks are built INNERMOST-FIRST and reversed at the end: `a + b' means
;;;; a's elements followed by b's in Core's representation, which is the order
;;;; the script pops them, i.e. the reverse of the witness order.

(defconstant +ms-availability-no+ 0 "No such stack exists.")
(defconstant +ms-availability-yes+ 1 "The stack exists and is fully known.")
(defconstant +ms-availability-maybe+ 2
  "The stack's shape is known but a key or preimage is not available yet — used
for witness-size estimation, where dummy values stand in.")

(defstruct (ms-stack (:constructor %make-ms-stack))
  "One candidate witness stack (Core InputStack)."
  (available +ms-availability-yes+ :type (integer 0 2))
  ;; Whether this stack contains a signature. The satisfier must never trade a
  ;; signed solution for an unsigned one, because an unsigned one is by
  ;; definition available to anybody.
  (has-sig nil :type boolean)
  ;; Whether a third party can turn this into an equally valid other stack.
  (malleable nil :type boolean)
  ;; Known to be unnecessary for satisfaction; sanity checking only.
  (non-canon nil :type boolean)
  (size 0 :type integer)
  (elements '() :type list))

(defun ms-stack-invalid ()
  (%make-ms-stack :available +ms-availability-no+
                  :size most-positive-fixnum))

(defun ms-stack-empty () (%make-ms-stack))

(defun ms-stack-of (bytes)
  "A one-element stack. Core counts the element plus its length byte."
  (%make-ms-stack :size (1+ (length bytes)) :elements (list bytes)))

(defun ms-stack-zero ()
  "A single zero-length element, which the interpreter reads as 0."
  (ms-stack-of (make-array 0 :element-type '(unsigned-byte 8))))

(defun ms-stack-one ()
  (ms-stack-of (make-array 1 :element-type '(unsigned-byte 8) :initial-element 1)))

(defun ms-stack-zero32 ()
  "Thirty-two zero bytes: the canonical wrong preimage for a hash fragment."
  (ms-stack-of (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))

(defun ms-stack-available-p (s) (/= (ms-stack-available s) +ms-availability-no+))

(defun ms-stack-set-available (s avail)
  "Core InputStack::SetAvailable. Marking a stack unavailable ERASES it — the
elements, the signature flag, everything — so a later concatenation cannot
resurrect half of it."
  (setf (ms-stack-available s) avail)
  (when (= avail +ms-availability-no+)
    (setf (ms-stack-elements s) '()
          (ms-stack-size s) most-positive-fixnum
          (ms-stack-has-sig s) nil
          (ms-stack-malleable s) nil
          (ms-stack-non-canon s) nil))
  s)

(defun ms-stack+ (a b)
  "Core operator+: concatenate two stacks. Unavailable is contagious."
  (let ((r (%make-ms-stack
            :available (ms-stack-available a)
            :has-sig (or (ms-stack-has-sig a) (ms-stack-has-sig b))
            :malleable (or (ms-stack-malleable a) (ms-stack-malleable b))
            :non-canon (or (ms-stack-non-canon a) (ms-stack-non-canon b))
            :size (ms-stack-size a)
            :elements (append (ms-stack-elements a) (ms-stack-elements b)))))
    (when (and (ms-stack-available-p a) (ms-stack-available-p b))
      (incf (ms-stack-size r) (ms-stack-size b)))
    (cond ((or (not (ms-stack-available-p a)) (not (ms-stack-available-p b)))
           (ms-stack-set-available r +ms-availability-no+))
          ((or (= (ms-stack-available a) +ms-availability-maybe+)
               (= (ms-stack-available b) +ms-availability-maybe+))
           (ms-stack-set-available r +ms-availability-maybe+))
          (t r))))

(defun ms-stack-or (a b)
  "Core operator|: choose between two candidate stacks.

The preference order is the heart of the malleability guarantee, and its first
rule is the surprising one: if exactly one option carries a signature, take the
one WITHOUT it. That looks backwards until you read it as the attacker would —
an unsigned solution is available to anybody, so a solution that needs a
signature can always be replaced by it, and pretending otherwise would hide the
malleability rather than remove it."
  (cond
    ((not (ms-stack-available-p a)) b)
    ((not (ms-stack-available-p b)) a)
    ((and (not (ms-stack-has-sig a)) (ms-stack-has-sig b)) a)
    ((and (not (ms-stack-has-sig b)) (ms-stack-has-sig a)) b)
    (t
     (when (and (not (ms-stack-has-sig a)) (not (ms-stack-has-sig b)))
       ;; Neither needs a signature, so either can be swapped for the other.
       (setf (ms-stack-malleable a) t
             (ms-stack-malleable b) t))
     (cond
       ((and (ms-stack-has-sig a) (ms-stack-has-sig b)
             (ms-stack-malleable b) (not (ms-stack-malleable a))) a)
       ((and (ms-stack-has-sig a) (ms-stack-has-sig b)
             (ms-stack-malleable a) (not (ms-stack-malleable b))) b)
       ;; Otherwise the smaller of two YESes, the larger of two MAYBEs (a
       ;; MAYBE is a size ESTIMATE, and an estimate must not be optimistic),
       ;; and YES over MAYBE.
       ((and (= (ms-stack-available a) +ms-availability-yes+)
             (= (ms-stack-available b) +ms-availability-yes+))
        (if (<= (ms-stack-size a) (ms-stack-size b)) a b))
       ((and (= (ms-stack-available a) +ms-availability-maybe+)
             (= (ms-stack-available b) +ms-availability-maybe+))
        (if (>= (ms-stack-size a) (ms-stack-size b)) a b))
       ((= (ms-stack-available a) +ms-availability-yes+) a)
       (t b)))))

(defun %ms-mark (s &key malleable non-canon with-sig)
  (when malleable (setf (ms-stack-malleable s) t))
  (when non-canon (setf (ms-stack-non-canon s) t))
  (when with-sig (setf (ms-stack-has-sig s) t))
  s)

;;;; The satisfier's context: what the caller can supply.

(defstruct ms-satisfier
  "What a satisfier can produce, and what it knows about the spend (Core's Ctx).

SIGN-FN is called with a key and returns its signature bytes, or NIL. The
PREIMAGE-FN family answers the four hash fragments. CHECK-OLDER-FN and
CHECK-AFTER-FN say whether a relative or absolute locktime is already satisfied
by the transaction being built — a branch whose timelock has not matured is not
merely expensive, it is unspendable, so Core makes it INVALID rather than
letting the size comparison pick it."
  (sign-fn nil)
  (preimage-fn nil)
  (check-older-fn nil)
  (check-after-fn nil)
  ;; When true, an unavailable key or preimage yields a MAYBE stack with dummy
  ;; contents instead of nothing — which is how Core estimates a witness size
  ;; before the signatures exist.
  (estimating nil :type boolean))

(defconstant +ms-dummy-sig-size+ 72
  "Size Core assumes for a not-yet-made signature when estimating.")

(defun %ms-sign (sat key)
  "Returns (values bytes availability)."
  (let ((sig (and (ms-satisfier-sign-fn sat)
                  (funcall (ms-satisfier-sign-fn sat) key))))
    (cond (sig (values sig +ms-availability-yes+))
          ((ms-satisfier-estimating sat)
           (values (make-array +ms-dummy-sig-size+ :element-type '(unsigned-byte 8))
                   +ms-availability-maybe+))
          (t (values (make-array 0 :element-type '(unsigned-byte 8))
                     +ms-availability-no+)))))

(defun %ms-preimage (sat kind hash)
  (let ((pre (and (ms-satisfier-preimage-fn sat)
                  (funcall (ms-satisfier-preimage-fn sat) kind hash))))
    (cond (pre (values pre +ms-availability-yes+))
          ((ms-satisfier-estimating sat)
           (values (make-array 32 :element-type '(unsigned-byte 8))
                   +ms-availability-maybe+))
          (t (values (make-array 0 :element-type '(unsigned-byte 8))
                     +ms-availability-no+)))))

(defun %ms-sig-stack (sat key)
  (multiple-value-bind (sig avail) (%ms-sign sat key)
    (ms-stack-set-available (%ms-mark (ms-stack-of sig) :with-sig t) avail)))

(defun %ms-preimage-stack (sat kind hash)
  (multiple-value-bind (pre avail) (%ms-preimage sat kind hash)
    (ms-stack-set-available (ms-stack-of pre) avail)))

(defun ms-produce-input (node sat &optional (key-fn #'%ms-identity-key))
  "Return (values satisfaction dissatisfaction) for NODE (Core ProduceInput)."
  (let ((subs (mapcar (lambda (s)
                        (multiple-value-list (ms-produce-input s sat key-fn)))
                      (ms-node-subs node))))
    (flet ((xsat () (first (first subs)))   (xnsat () (second (first subs)))
           (ysat () (first (second subs)))  (ynsat () (second (second subs)))
           (zsat () (first (third subs)))   (znsat () (second (third subs))))
      (macrolet ((res (sat-form nsat-form) `(values ,sat-form ,nsat-form)))
        (ecase (ms-node-fragment node)
          (:just-0 (res (ms-stack-invalid) (ms-stack-empty)))
          (:just-1 (res (ms-stack-empty) (ms-stack-invalid)))
          (:pk-k (res (%ms-sig-stack sat (first (ms-node-keys node)))
                      (ms-stack-zero)))
          (:pk-h
           ;; The key itself is on the stack under the signature, because the
           ;; script only committed to its hash.
           (let ((key (ms-stack-of (funcall key-fn (first (ms-node-keys node))))))
             (res (ms-stack+ (%ms-sig-stack sat (first (ms-node-keys node))) key)
                  (ms-stack+ (ms-stack-zero) key))))
          (:older (res (if (and (ms-satisfier-check-older-fn sat)
                                (funcall (ms-satisfier-check-older-fn sat) (ms-node-k node)))
                           (ms-stack-empty)
                           (ms-stack-invalid))
                       (ms-stack-invalid)))
          (:after (res (if (and (ms-satisfier-check-after-fn sat)
                                (funcall (ms-satisfier-check-after-fn sat) (ms-node-k node)))
                           (ms-stack-empty)
                           (ms-stack-invalid))
                       (ms-stack-invalid)))
          ((:sha256 :ripemd160 :hash256 :hash160)
           (res (%ms-preimage-stack sat (ms-node-fragment node) (ms-node-data node))
                (ms-stack-zero32)))
          ;; The four transparent wrappers change the script, not the witness.
          ((:wrap-a :wrap-s :wrap-c :wrap-n) (res (xsat) (xnsat)))
          (:wrap-d (res (ms-stack+ (xsat) (ms-stack-one)) (ms-stack-zero)))
          (:wrap-v (res (xsat) (ms-stack-invalid)))
          (:wrap-j
           ;; Conservative: if the sub is dissatisfiable without a signature at
           ;; all, assume a nonzero-top dissatisfaction also exists and call
           ;; ours malleable. The dissatisfaction logic does not track
           ;; nonzeroness, so this cannot be decided; Core assumes the worse.
           (res (xsat)
                (%ms-mark (ms-stack-zero)
                          :malleable (and (ms-stack-available-p (xnsat))
                                          (not (ms-stack-has-sig (xnsat)))))))
          (:and-v (res (ms-stack+ (ysat) (xsat))
                       (%ms-mark (ms-stack+ (ynsat) (xsat)) :non-canon t)))
          (:and-b (res (ms-stack+ (ysat) (xsat))
                       (ms-stack-or
                        (ms-stack-or (ms-stack+ (ynsat) (xnsat))
                                     (%ms-mark (ms-stack+ (ysat) (xnsat))
                                               :malleable t :non-canon t))
                        (%ms-mark (ms-stack+ (ynsat) (xsat))
                                  :malleable t :non-canon t))))
          (:or-b (res (ms-stack-or
                       (ms-stack-or (ms-stack+ (ynsat) (xsat))
                                    (ms-stack+ (ysat) (xnsat)))
                       ;; Satisfying BOTH is overcomplete: an attacker can turn
                       ;; either half into a dissatisfaction and still spend.
                       (%ms-mark (ms-stack+ (ysat) (xsat))
                                 :malleable t :non-canon t))
                      (ms-stack+ (ynsat) (xnsat))))
          (:or-c (res (ms-stack-or (xsat) (ms-stack+ (ysat) (xnsat)))
                      (ms-stack-invalid)))
          (:or-d (res (ms-stack-or (xsat) (ms-stack+ (ysat) (xnsat)))
                      (ms-stack+ (ynsat) (xnsat))))
          (:or-i (res (ms-stack-or (ms-stack+ (xsat) (ms-stack-one))
                                   (ms-stack+ (ysat) (ms-stack-zero)))
                      (ms-stack-or (ms-stack+ (xnsat) (ms-stack-one))
                                   (ms-stack+ (ynsat) (ms-stack-zero)))))
          (:andor (res (ms-stack-or (ms-stack+ (ysat) (xsat))
                                    (ms-stack+ (zsat) (xnsat)))
                       (ms-stack-or (%ms-mark (ms-stack+ (ynsat) (xsat)) :non-canon t)
                                    (ms-stack+ (znsat) (xnsat)))))
          (:multi
           ;; Dynamic programming: SATS[j] is the best stack carrying j valid
           ;; signatures out of the keys seen so far. SATS[0] starts as one
           ;; zero because CHECKMULTISIG pops one element too many.
           (let ((sats (list (ms-stack-zero))))
             (dolist (key (ms-node-keys node))
               (let ((sig (%ms-sig-stack sat key))
                     (next (list (first sats))))
                 (loop for j from 1 below (length sats)
                       do (push (ms-stack-or (nth j sats)
                                             (ms-stack+ (nth (1- j) sats) sig))
                                next))
                 (push (ms-stack+ (car (last sats)) sig) next)
                 (setf sats (nreverse next))))
             (let ((nsat (ms-stack-zero)))
               (dotimes (i (ms-node-k node))
                 (setf nsat (ms-stack+ nsat (ms-stack-zero))))
               (res (nth (ms-node-k node) sats) nsat))))
          (:thresh
           ;; SATS[j] is the best stack satisfying j of the subexpressions seen
           ;; so far, walking them in REVERSE because the witness is built
           ;; innermost-first.
           (let ((sats (list (ms-stack-empty))))
             (dolist (sub (reverse subs))
               (let ((s (first sub)) (n (second sub))
                     (next '()))
                 (push (ms-stack+ (first sats) n) next)
                 (loop for j from 1 below (length sats)
                       do (push (ms-stack-or (ms-stack+ (nth j sats) n)
                                             (ms-stack+ (nth (1- j) sats) s))
                                next))
                 (push (ms-stack+ (car (last sats)) s) next)
                 (setf sats (nreverse next))))
             (let ((nsat (ms-stack-invalid)))
               (loop for i from 0 below (length sats)
                     do (unless (or (= i 0) (= i (ms-node-k node)))
                          ;; Any count other than 0 or k is over- or
                          ;; under-complete: available, but never the right
                          ;; choice, since the i=0 form always exists.
                          (%ms-mark (nth i sats) :malleable t :non-canon t))
                        (unless (= i (ms-node-k node))
                          (setf nsat (ms-stack-or nsat (nth i sats)))))
               (res (nth (ms-node-k node) sats) nsat)))))))))

(defun ms-satisfy (node sat &key (key-fn #'%ms-identity-key))
  "The witness stack that satisfies NODE, or NIL.

The list is in WITNESS order: element 0 is pushed first and ends up at the
bottom, so the LAST element is what the script's first opcode pops. That is
already the order the stacks are built in — `a + b' puts a's elements before
b's, and a combinator's own input goes after its sub-expressions' precisely
because it runs first and must find its input on top.

Returns (values stack malleable-p). A second value of T means a third party
could rewrite the witness into another equally valid one; a caller that cares
about transaction identity should refuse such a solution rather than broadcast
it."
  (multiple-value-bind (satisfaction nsat) (ms-produce-input node sat key-fn)
    (declare (ignore nsat))
    (when (ms-stack-available-p satisfaction)
      (values (copy-list (ms-stack-elements satisfaction))
              (ms-stack-malleable satisfaction)))))

;;;; --- Inference: script bytes back to a miniscript (Core DecodeScript) ----
;;;;
;;;; The decoder reads the script BACKWARDS. That is not a stylistic choice:
;;;; miniscript's combinators put their own opcode LAST (and_b is [X][Y]
;;;; OP_BOOLAND, or_d is [X] OP_IFDUP OP_NOTIF [Y] OP_ENDIF), so the last
;;;; opcode is the one that says which fragment this is. Forwards, you cannot
;;;; know what you are parsing until you have finished parsing it.
;;;;
;;;; It is a state machine rather than a recursive descent because the contexts
;;;; interleave: a wrapper's operand may itself be an and_v chain, and thresh
;;;; has to count its children. Core keeps a to-parse stack and a stack of
;;;; constructed nodes, and this follows it context for context.

(defstruct (ms-op (:constructor %make-ms-op (opcode data)))
  "One decomposed script element: an opcode and its push payload."
  (opcode 0 :type (unsigned-byte 8))
  (data nil))

(defconstant +ms-op-pushdata1+ 76)
(defconstant +ms-op-pushdata2+ 77)
(defconstant +ms-op-pushdata4+ 78)
(defconstant +ms-op-1negate+ 79)
(defconstant +ms-op-numequal+ #x9c)
(defconstant +ms-op-numequalverify+ #x9d)

(defun ms-decompose-script (script)
  "Split SCRIPT into MS-OPs, REVERSED, or NIL if it is not decomposable.

Three normalizations, all Core's:
- OP_1..OP_16 become pushes of their value, so a threshold and a small push
  read the same way.
- Every -VERIFY opcode is split into its base plus OP_VERIFY, which is what
  lets one `v:' rule handle both spellings.
- A base opcode already followed by OP_VERIFY is REJECTED, because it should
  have been written as the -VERIFY form: two encodings of one script would
  otherwise both parse, and miniscript's whole premise is that the mapping is
  one to one."
  (let ((ops '())
        (i 0)
        (n (length script)))
    (flet ((push-op (opcode data) (push (%make-ms-op opcode data) ops)))
      (loop while (< i n)
            do (let ((op (aref script i)))
                 (incf i)
                 (cond
                   ;; Direct pushes.
                   ;; The opcode is kept as the real byte, not normalized to
                   ;; zero: OP_0 IS zero, and conflating the two makes every
                   ;; data push look like a literal false.
                   ((and (>= op 1) (<= op 75))
                    (when (> (+ i op) n) (return-from ms-decompose-script nil))
                    (push-op op (subseq script i (+ i op)))
                    (incf i op))
                   ((= op +ms-op-pushdata1+)
                    (when (>= i n) (return-from ms-decompose-script nil))
                    (let ((len (aref script i)))
                      (incf i)
                      (when (or (> (+ i len) n) (< len 76))
                        ;; Non-minimal push: miniscript requires the shortest
                        ;; encoding, so accepting this would again admit two
                        ;; scripts for one expression.
                        (return-from ms-decompose-script nil))
                      (push-op +ms-op-pushdata1+ (subseq script i (+ i len)))
                      (incf i len)))
                   ((= op +ms-op-pushdata2+)
                    (when (> (+ i 2) n) (return-from ms-decompose-script nil))
                    (let ((len (logior (aref script i) (ash (aref script (1+ i)) 8))))
                      (incf i 2)
                      (when (or (> (+ i len) n) (< len 256))
                        (return-from ms-decompose-script nil))
                      (push-op +ms-op-pushdata2+ (subseq script i (+ i len)))
                      (incf i len)))
                   ((= op +ms-op-pushdata4+) (return-from ms-decompose-script nil))
                   ;; OP_0 pushes nothing; OP_1..OP_16 push their value.
                   ((= op +op-0+)
                    (push-op op (make-array 0 :element-type '(unsigned-byte 8))))
                   ((and (>= op +op-1+) (<= op +op-16+))
                    (push-op op (make-array 1 :element-type '(unsigned-byte 8)
                                              :initial-element (1+ (- op +op-1+)))))
                   ;; -VERIFY forms split in two.
                   ((= op +op-checksigverify+)
                    (push-op +op-checksig+ nil) (push-op +op-verify+ nil))
                   ((= op +op-checkmultisigverify+)
                    (push-op +op-checkmultisig+ nil) (push-op +op-verify+ nil))
                   ((= op +op-equalverify+)
                    (push-op +op-equal+ nil) (push-op +op-verify+ nil))
                   ((= op +ms-op-numequalverify+)
                    (push-op +ms-op-numequal+ nil) (push-op +op-verify+ nil))
                   (t
                    ;; A base opcode written separately from a following
                    ;; OP_VERIFY is the non-minimal spelling.
                    (when (and (member op (list +op-checksig+ +op-checkmultisig+
                                                +op-equal+ +ms-op-numequal+))
                               (< i n)
                               (= (aref script i) +op-verify+))
                      (return-from ms-decompose-script nil))
                    (push-op op nil))))))
    ;; PUSH-OP already built the list in reverse.
    (coerce ops 'vector)))

(defun %ms-op-number (op)
  "The number OP pushes, or NIL. OP_0 is 0; a push of up to 4 bytes is a
CScriptNum."
  (let ((data (ms-op-data op)))
    (cond ((null data) nil)
          ((zerop (length data)) 0)
          ((> (length data) 4) nil)
          (t
           (let ((v 0))
             (loop for i from (1- (length data)) downto 0
                   do (setf v (logior (ash v 8) (aref data i))))
             ;; Miniscript numbers are non-negative, so a set sign bit is not
             ;; a number here.
             (if (logtest (aref data (1- (length data))) #x80) nil v))))))

(defun %ms-op-is (ops i opcode)
  (and (< i (length ops)) (= (ms-op-opcode (aref ops i)) opcode)))

(defun %ms-op-push-size (ops i)
  (and (< i (length ops))
       (ms-op-data (aref ops i))
       (length (ms-op-data (aref ops i)))))

(defun ms-from-script (script)
  "Infer a miniscript from SCRIPT, or NIL.

Returns a node that is valid at top level; anything else — a script that is not
miniscript at all, one whose types do not check out, or one written in a
non-minimal encoding — comes back NIL rather than as an error, because callers
ask this question about arbitrary scripts."
  (let ((ops (ms-decompose-script script)))
    (when ops
      (let ((in 0)
            (last (length ops))
            (to-parse (list (list :bkv-expr -1 -1)))
            (constructed '()))
        (macrolet ((fail () '(return-from ms-from-script nil))
                   (emit (form) `(push ,form constructed))
                   (want (ctx &optional (n -1) (k -1))
                     `(push (list ,ctx ,n ,k) to-parse)))
          (labels ((op-at (i) (and (< (+ in i) last) (aref ops (+ in i))))
                   (opcode-at (i) (let ((o (op-at i))) (and o (ms-op-opcode o))))
                   (num-at (i) (let ((o (op-at i))) (and o (%ms-op-number o))))
                   (data-at (i) (let ((o (op-at i))) (and o (ms-op-data o))))
                   (remaining () (- last in))
                   (wrap (fragment)
                     (when (null constructed) (fail))
                     (setf (first constructed)
                           (make-ms-node fragment :subs (list (first constructed)))))
                   (combine (fragment arity)
                     (when (< (length constructed) arity) (fail))
                     ;; The constructed stack holds children in reverse, so
                     ;; take them off and hand them over in source order.
                     (let ((subs (loop repeat arity collect (pop constructed))))
                       (push (make-ms-node fragment :subs subs) constructed))))
            (loop while to-parse
                  do (when (and constructed (not (ms-node-valid-p (first constructed))))
                       ;; Bail as soon as anything fails to type: the calculus
                       ;; has no error channel, so a zero type propagates
                       ;; silently and would otherwise be discovered only at
                       ;; the very end, after arbitrary work.
                       (fail))
                     (destructuring-bind (ctx n k) (pop to-parse)
                       (ecase ctx
                         (:single-bkv-expr
                          (when (>= in last) (fail))
                          (let ((op (opcode-at 0)))
                            (cond
                              ((= op +op-1+) (incf in) (emit (make-ms-node :just-1)))
                              ((= op +op-0+) (incf in) (emit (make-ms-node :just-0)))
                              ;; A bare 33-byte push is a key.
                              ((eql 33 (%ms-op-push-size ops in))
                               (let ((key (data-at 0))) (incf in)
                                 (emit (make-ms-node :pk-k :keys (list key)))))
                              ;; DUP HASH160 <20> EQUAL VERIFY, reversed.
                              ((and (>= (remaining) 5)
                                    (= op +op-verify+)
                                    (%ms-op-is ops (+ in 1) +op-equal+)
                                    (%ms-op-is ops (+ in 3) +op-hash160+)
                                    (%ms-op-is ops (+ in 4) +op-dup+)
                                    (eql 20 (%ms-op-push-size ops (+ in 2))))
                               (let ((keyhash (data-at 2)))
                                 (incf in 5)
                                 ;; The script committed to a HASH, so the key
                                 ;; itself is not recoverable. The node carries
                                 ;; the hash in DATA — which script generation
                                 ;; uses directly rather than hashing a key —
                                 ;; and a satisfier looks the key up by it.
                                 (emit (make-ms-node :pk-h :data keyhash))))
                              ((and (>= (remaining) 2)
                                    (= op +ms-op-checksequenceverify+)
                                    (num-at 1))
                               (let ((v (num-at 1)))
                                 (incf in 2)
                                 (unless (and (>= v 1) (<= v #x7FFFFFFF)) (fail))
                                 (emit (make-ms-node :older :k v))))
                              ((and (>= (remaining) 2)
                                    (= op +ms-op-checklocktimeverify+)
                                    (num-at 1))
                               (let ((v (num-at 1)))
                                 (incf in 2)
                                 (unless (and (>= v 1) (<= v #x7FFFFFFF)) (fail))
                                 (emit (make-ms-node :after :k v))))
                              ;; SIZE <32> EQUAL VERIFY <hashop> <hash> EQUAL.
                              ((and (>= (remaining) 7)
                                    (= op +op-equal+)
                                    (%ms-op-is ops (+ in 3) +op-verify+)
                                    (%ms-op-is ops (+ in 4) +op-equal+)
                                    (eql 32 (num-at 5))
                                    (%ms-op-is ops (+ in 6) +ms-op-size+)
                                    (let ((h (opcode-at 2)) (sz (%ms-op-push-size ops (+ in 1))))
                                      (or (and (= h +op-sha256+) (eql sz 32))
                                          (and (= h +op-ripemd160+) (eql sz 20))
                                          (and (= h +op-hash256+) (eql sz 32))
                                          (and (= h +op-hash160+) (eql sz 20)))))
                               (let ((h (opcode-at 2)) (data (data-at 1)))
                                 (incf in 7)
                                 (emit (make-ms-node
                                        (cond ((= h +op-sha256+) :sha256)
                                              ((= h +op-ripemd160+) :ripemd160)
                                              ((= h +op-hash256+) :hash256)
                                              (t :hash160))
                                        :data data))))
                              ;; <k> <key>... <n> CHECKMULTISIG, reversed.
                              ((and (>= (remaining) 3) (= op +op-checkmultisig+))
                               (let ((count (num-at 1)))
                                 (unless (and count (>= (remaining) (+ 3 count))
                                              (>= count 1)
                                              (<= count +ms-max-pubkeys-per-multisig+))
                                   (fail))
                                 (let ((keys '()))
                                   (dotimes (j count)
                                     (unless (eql 33 (%ms-op-push-size ops (+ in 2 j))) (fail))
                                     (push (data-at (+ 2 j)) keys))
                                   (let ((threshold (num-at (+ 2 count))))
                                     (unless (and threshold (>= threshold 1)
                                                  (<= threshold count))
                                       (fail))
                                     (incf in (+ 3 count))
                                     ;; Collected while walking backwards, so
                                     ;; PUSH already restored source order.
                                     (emit (make-ms-node :multi :k threshold
                                                                :keys keys))))))
                              ;; Wrappers. SINGLE_BKV_EXPR, not BKV_EXPR: and_v
                              ;; commutes with these, so c:and_v(X,Y) and
                              ;; and_v(X,c:Y) compile identically and the and_v
                              ;; is left outside.
                              ((= op +op-checksig+)
                               (incf in) (want :check) (want :single-bkv-expr))
                              ((= op +op-verify+)
                               (incf in) (want :verify) (want :single-bkv-expr))
                              ((= op +op-0notequal+)
                               (incf in) (want :zero-notequal) (want :single-bkv-expr))
                              ((and (>= (remaining) 3) (= op +op-equal+) (num-at 1))
                               (let ((threshold (num-at 1)))
                                 (unless (>= threshold 1) (fail))
                                 (incf in 2)
                                 (want :thresh-w 0 threshold)))
                              ((= op +op-endif+)
                               (incf in) (want :endif) (want :bkv-expr))
                              ;; and_b / or_b take SINGLE_BKV_EXPR for the same
                              ;; commuting reason.
                              ((= op +op-booland+)
                               (incf in) (want :and-b) (want :single-bkv-expr) (want :w-expr))
                              ((= op +op-boolor+)
                               (incf in) (want :or-b) (want :single-bkv-expr) (want :w-expr))
                              (t (fail)))))
                         (:bkv-expr (want :maybe-and-v) (want :single-bkv-expr))
                         (:w-expr
                          (when (>= in last) (fail))
                          (if (= (opcode-at 0) +op-fromaltstack+)
                              (progn (incf in) (want :alt))
                              (want :swap))
                          (want :bkv-expr))
                         (:maybe-and-v
                          ;; None of these can END a well-formed miniscript, so
                          ;; seeing one means there is no further and_v child.
                          (when (and (< in last)
                                     (not (member (opcode-at 0)
                                                  (list +op-if+ +op-else+ +op-notif+
                                                        +op-toaltstack+ +op-swap+))))
                            (want :and-v) (want :bkv-expr)))
                         (:swap
                          (when (or (>= in last) (/= (opcode-at 0) +op-swap+)
                                    (null constructed))
                            (fail))
                          (incf in) (wrap :wrap-s))
                         (:alt
                          (when (or (>= in last) (/= (opcode-at 0) +op-toaltstack+)
                                    (null constructed))
                            (fail))
                          (incf in) (wrap :wrap-a))
                         (:check (wrap :wrap-c))
                         (:dup-if (wrap :wrap-d))
                         (:verify (wrap :wrap-v))
                         (:non-zero (wrap :wrap-j))
                         (:zero-notequal (wrap :wrap-n))
                         (:and-v (combine :and-v 2))
                         (:and-b (combine :and-b 2))
                         (:or-b (combine :or-b 2))
                         (:or-c (combine :or-c 2))
                         (:or-d (combine :or-d 2))
                         (:or-i (combine :or-i 2))
                         (:andor
                          (when (< (length constructed) 3) (fail))
                          (let* ((x (pop constructed))
                                 (z (pop constructed))
                                 (y (pop constructed)))
                            (push (make-ms-node :andor :subs (list x y z)) constructed)))
                         (:thresh-w
                          (when (>= in last) (fail))
                          (if (= (opcode-at 0) +op-add+)
                              (progn (incf in)
                                     (want :thresh-w (1+ n) k)
                                     (want :w-expr))
                              (progn (want :thresh-e (1+ n) k)
                                     ;; Every thresh child is 'd', so none can
                                     ;; be an and_v.
                                     (want :single-bkv-expr))))
                         (:thresh-e
                          (when (or (< k 1) (> k n) (< (length constructed) n)) (fail))
                          ;; Pop order IS source order here: reading backwards
                          ;; means the FIRST child was constructed last, so it
                          ;; is on top. Reversing would put the W-type children
                          ;; where the B-type one belongs.
                          (let ((subs (loop repeat n collect (pop constructed))))
                            (push (make-ms-node :thresh :k k :subs subs)
                                  constructed)))
                         (:endif
                          (when (>= in last) (fail))
                          (let ((op (opcode-at 0)))
                            (cond
                              ((= op +op-else+)
                               (incf in) (want :endif-else) (want :bkv-expr))
                              ((= op +op-if+)
                               (cond
                                 ((and (>= (remaining) 2) (%ms-op-is ops (+ in 1) +op-dup+))
                                  (incf in 2) (want :dup-if))
                                 ((and (>= (remaining) 3)
                                       (%ms-op-is ops (+ in 1) +op-0notequal+)
                                       (%ms-op-is ops (+ in 2) +ms-op-size+))
                                  (incf in 3) (want :non-zero))
                                 (t (fail))))
                              ((= op +op-notif+)
                               (incf in) (want :endif-notif))
                              (t (fail)))))
                         (:endif-notif
                          (when (>= in last) (fail))
                          (if (= (opcode-at 0) +op-ifdup+)
                              (progn (incf in) (want :or-d))
                              (want :or-c))
                          ;; Both need X to be 'd', so neither can be an and_v.
                          (want :single-bkv-expr))
                         (:endif-else
                          (when (>= in last) (fail))
                          (let ((op (opcode-at 0)))
                            (cond
                              ((= op +op-if+) (incf in) (combine :or-i 2))
                              ((= op +op-notif+)
                               (incf in) (want :andor) (want :single-bkv-expr))
                              (t (fail))))))))
            (unless (and (= 1 (length constructed))
                         (= in last)
                         (ms-node-valid-top-level-p (first constructed)))
              (return-from ms-from-script nil))
            (first constructed)))))))
