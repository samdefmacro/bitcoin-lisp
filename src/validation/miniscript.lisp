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
          do (unless bit (error "Unknown miniscript type character ~S" ch))
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
  (script-size 0 :type (unsigned-byte 32)))

(defconstant +ms-locktime-threshold+ 500000000
  "Core LOCKTIME_THRESHOLD: below this an nLockTime is a height, at or above it
a Unix time.")

(defconstant +ms-sequence-locktime-type-flag+ (ash 1 22)
  "Core CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG: set means the relative locktime is
measured in 512-second units rather than blocks.")

(defconstant +ms-max-pubkeys-per-multisig+ 20)

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

(defun ms-compute-type (fragment x y z sub-types k data-size n-subs n-keys)
  "Core ComputeType. X, Y and Z are the first three sub-expression types (0 when
absent); SUB-TYPES is every sub-type, needed only by THRESH."
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
                       ;; where MINIMALIF is only a policy rule. This port is
                       ;; P2WSH, so the bit is never set here.
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
           (pk (k) (funcall key-fn k)))
      (ecase (ms-node-fragment node)
        (:just-0 (%ms-cat +op-0+))
        (:just-1 (%ms-cat +op-1+))
        (:pk-k (%ms-cat (%ms-push-data (pk (first (ms-node-keys node))))))
        (:pk-h (%ms-cat +op-dup+ +op-hash160+
                        (%ms-push-data (bitcoin-lisp.crypto:hash160
                                        (pk (first (ms-node-keys node)))))
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
        (:thresh (%ms-cat (sub 0)
                          (loop for i from 1 below (length subs)
                                collect (list (sub i) +op-add+))
                          (%ms-push-number (ms-node-k node))
                          (if verify +op-equalverify+ +op-equal+)))))))

;;;; --- Construction --------------------------------------------------------

(defun make-ms-node (fragment &key subs keys (k 0) data)
  "Build a node and compute its type. A node whose type is 0 is INVALID, which
is how every rule violation surfaces — there is no separate error channel."
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
                                     (length data) (length subs) (length keys)))))
         (node (%make-ms-node :fragment fragment :subs subs :keys keys
                              :k k :data data :node-type type)))
    ;; The script size is only computable when the keys are already bytes; a
    ;; descriptor's key expressions have no size until they are derived, and a
    ;; node built from them reports 0 rather than guessing.
    (setf (ms-node-script-size node)
          (if (or (zerop type)
                  (notevery (lambda (k) (typep k 'sequence)) keys))
              0
              (handler-case (length (ms-node-script node)) (error () 0))))
    node))

(defun ms-node-valid-p (node)
  "T when NODE typed successfully."
  (and node (plusp (ms-node-node-type node))))

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
expects, which is the whole reason the property is tracked."
  (and node (not (mst-subset-p (ms-node-node-type node) (mst "k")))))

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

(define-condition miniscript-parse-error (error)
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
  (bitcoin-lisp.crypto:hex-to-bytes string))

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

(defun ms-parse (string)
  "Parse a miniscript expression. Returns an MS-NODE, whose type is zero when
the expression is well-formed but does not satisfy the type rules. Signals
MINISCRIPT-PARSE-ERROR when it is not well-formed at all."
  (let ((wrappers '()) (i 0))
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
               ((string= name "multi")
                (unless (>= (length args) 2) (%ms-fail "multi needs a threshold and keys"))
                (let ((k (%ms-parse-number (first args) "multi"))
                      (keys (mapcar #'%ms-parse-key (rest args))))
                  (if (and (>= k 1) (<= k (length keys))
                           (<= (length keys) +ms-max-pubkeys-per-multisig+))
                      (make-ms-node :multi :k k :keys keys)
                      (%make-ms-node :fragment :multi :k 0 :node-type 0))))
               (t (%ms-fail "unknown miniscript fragment ~S" name)))))
      (%ms-apply-wrappers wrappers node))))

;;;; --- Rendering (miniscript.h:890-995) ------------------------------------

(defun %ms-identity-key-string (key)
  (if (stringp key) key (string-downcase (bitcoin-lisp.crypto:bytes-to-hex key))))

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
                   (:pk-h (format nil "~Apkh(~A)" prefix
                                  (key (first (ms-node-keys (nth 0 subs))))))
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
           (:pk-h (format nil "~Apk_h(~A)" prefix (key (first (ms-node-keys node)))))
           (:older (format nil "~Aolder(~D)" prefix (ms-node-k node)))
           (:after (format nil "~Aafter(~D)" prefix (ms-node-k node)))
           ((:sha256 :hash256 :ripemd160 :hash160)
            (format nil "~A~(~A~)(~A)" prefix (ms-node-fragment node)
                    (string-downcase (bitcoin-lisp.crypto:bytes-to-hex (ms-node-data node)))))
           (:and-b (format nil "~Aand_b(~A,~A)" prefix (sub 0) (sub 1)))
           (:or-b (format nil "~Aor_b(~A,~A)" prefix (sub 0) (sub 1)))
           (:or-c (format nil "~Aor_c(~A,~A)" prefix (sub 0) (sub 1)))
           (:or-d (format nil "~Aor_d(~A,~A)" prefix (sub 0) (sub 1)))
           (:multi (format nil "~Amulti(~D~{,~A~})" prefix (ms-node-k node)
                           (mapcar #'key (ms-node-keys node))))
           (:thresh (format nil "~Athresh(~D~{,~A~})" prefix (ms-node-k node)
                            (loop for i from 0 below (length subs) collect (sub i))))
           (t (error "cannot render miniscript fragment ~S"
                     (ms-node-fragment node)))))))))
