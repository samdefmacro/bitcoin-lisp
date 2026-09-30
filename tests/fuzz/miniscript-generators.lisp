(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/miniscript.cpp at the pin: miniscript_stable and
;;;; miniscript_smart, the two targets that GENERATE miniscripts node by node
;;;; from the fuzz input (GenNode, :846-989) and then test each one (TestNode,
;;;; :1015-1188). miniscript_string and miniscript_script are in miniscript.lisp.
;;;;
;;;; The generator is Core's: a todo stack of (type needed, decided node), a
;;;; fragment chosen per required type -- by a fixed byte encoding
;;;; (ConsumeNodeStable, :371-501) or from recipe tables derived from the type
;;;; calculus itself (SmartInfo, :503-758, and ConsumeNodeSmart, :770-842) --
;;;; the script size and static op count predicted as the tree is built, and
;;;; every finished node checked for validity. Keys, hashes and preimages come
;;;; from Core's TestData (:47-86): 256 keys from the private keys 01 00..00 i,
;;;; the four hashes of each, a signature and a preimage available for every
;;;; odd i, timelocks satisfied when odd.
;;;;
;;;; TestNode's checks, ours: the text round trip, script size and static ops
;;;; against the predictions, the `x' property against the last opcode, the
;;;; script round trip of a valid top-level node (same script, same type), and
;;;; the satisfaction's bounds -- a non-malleable one within GetStackSize and
;;;; GetWitnessSize, a sane node satisfiable non-malleably exactly when
;;;; malleably, and a satisfaction existing exactly when the policy is
;;;; satisfiable by the test data (Core's IsSatisfiable). What is not here:
;;;; VerifyScript of the satisfaction. Core runs it against a checker that
;;;; accepts its dummy signatures by value; our interpreter checks real
;;;; signatures over a real sighash, and signing every generated script's
;;;; spend is out of this target's reach.

(def-suite :fuzz-miniscript-generators-tests :in :bitcoin-lisp-tests
  :description "Core fuzz miniscript.cpp miniscript_stable and miniscript_smart")

(in-suite :fuzz-miniscript-generators-tests)

;;; --- TestData ---------------------------------------------------------------

(defstruct (ms-test-data (:conc-name mtd-))
  keys key-index sha256 hash256 ripemd160 hash160 preimages)

(defvar *ms-test-data* nil "Core's TEST_DATA, built on first use.")

(defun %ms-test-data ()
  (or *ms-test-data*
      (setf *ms-test-data*
            (let ((d (make-ms-test-data :keys (make-array 256) :key-index (make-hash-table :test 'equalp)
                                        :sha256 (make-array 256) :hash256 (make-array 256)
                                        :ripemd160 (make-array 256) :hash160 (make-array 256)
                                        :preimages (make-hash-table :test 'equalp))))
              (dotimes (i 256 d)
                (let ((keydata (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
                  (setf (aref keydata 0) 1 (aref keydata 31) i)
                  (let ((pub (bl.crypto:derive-public-key keydata :compressed t)))
                    (setf (aref (mtd-keys d) i) pub
                          (gethash pub (mtd-key-index d)) i
                          (gethash (subseq pub 1) (mtd-key-index d)) i))
                  (flet ((put (vec hash)
                           (setf (aref vec i) hash)
                           (when (oddp i) (setf (gethash hash (mtd-preimages d)) keydata))))
                    (put (mtd-sha256 d) (bl.crypto:sha256 keydata))
                    (put (mtd-hash256 d) (bl.crypto:hash256 keydata))
                    (put (mtd-ripemd160 d) (bl.crypto:ripemd160 keydata))
                    (put (mtd-hash160 d) (bl.crypto:hash160 keydata)))))))))

(defun %ms-key-odd-p (key)
  "Core is_key_satisfiable: the key is a test key with an odd index."
  (let ((i (gethash key (mtd-key-index (%ms-test-data)))))
    (and i (oddp i))))

(defun %ms-fuzz-satisfier (ctx)
  "Core SatisfierContext: dummy signatures for odd keys (72 bytes, 65 under
tapscript), preimages for odd hashes, timelocks satisfied when odd."
  (bl.val:make-ms-satisfier
   :sign-fn (lambda (key)
              (when (%ms-key-odd-p key)
                (make-array (if (eq ctx :tapscript) 65 72) :element-type '(unsigned-byte 8)
                                                           :initial-element 1)))
   :preimage-fn (lambda (kind hash)
                  (declare (ignore kind))
                  (gethash hash (mtd-preimages (%ms-test-data))))
   :check-older-fn #'oddp
   :check-after-fn #'oddp))

(defun %ms-satisfiable-p (node)
  "Core Node::IsSatisfiable (miniscript.h:1658-1698) with TestNode's leaf
predicate (:1156-1185)."
  (let ((subs (bl.val:ms-node-subs node))
        (k (bl.val:ms-node-k node))
        (d (%ms-test-data)))
    (ecase (bl.val:ms-node-fragment node)
      (:just-0 nil)
      (:just-1 t)
      ((:pk-k :pk-h) (%ms-key-odd-p (first (bl.val:ms-node-keys node))))
      ((:multi :multi-a) (>= (count-if #'%ms-key-odd-p (bl.val:ms-node-keys node)) k))
      ((:older :after) (oddp k))
      ((:sha256 :hash256 :ripemd160 :hash160)
       (and (gethash (bl.val:ms-node-data node) (mtd-preimages d)) t))
      ((:wrap-a :wrap-s :wrap-c :wrap-d :wrap-v :wrap-j :wrap-n) (%ms-satisfiable-p (first subs)))
      ((:and-v :and-b) (and (%ms-satisfiable-p (first subs)) (%ms-satisfiable-p (second subs))))
      ((:or-b :or-c :or-d :or-i) (or (%ms-satisfiable-p (first subs)) (%ms-satisfiable-p (second subs))))
      (:andor (or (and (%ms-satisfiable-p (first subs)) (%ms-satisfiable-p (second subs)))
                  (%ms-satisfiable-p (third subs))))
      (:thresh (>= (count-if #'%ms-satisfiable-p subs) k)))))

;;; --- The generator (GenNode) ------------------------------------------------

(defstruct (ms-node-info (:conc-name mni-))
  "Core NodeInfo: a fragment, its k, keys, hash and required sub-types."
  fragment (k 0) (keys '()) (hash nil) (subtypes '()))

(defun %t (s) (bl.val:mst s))

(defun %mst<< (type props) (bl.val:mst-subset-p type props))

(defun %consume-timelock (fdp)
  "Core ConsumeTimeLock: a u32, refused when 0 or >= 2^31."
  (let ((k (consume-integral fdp :u32)))
    (and (< 0 k #x80000000) k)))

(defun %consume-node-stable (ctx fdp type-needed)
  "Core ConsumeNodeStable (:371-501)."
  (let* ((any (zerop type-needed))
         (allow-b (or any (%mst<< type-needed (%t "B"))))
         (allow-k (or any (%mst<< type-needed (%t "K"))))
         (allow-v (or any (%mst<< type-needed (%t "V"))))
         (allow-w (or any (%mst<< type-needed (%t "W"))))
         (tap (eq ctx :tapscript))
         (d (%ms-test-data)))
    (flet ((key () (aref (mtd-keys d) (consume-integral fdp :u8)))
           (info (&rest args) (apply #'make-ms-node-info args)))
      (case (consume-integral fdp :u8)
        (0 (and allow-b (info :fragment :just-0)))
        (1 (and allow-b (info :fragment :just-1)))
        (2 (and allow-k (info :fragment :pk-k :keys (list (key)))))
        (3 (and allow-k (info :fragment :pk-h :keys (list (key)))))
        (4 (and allow-b (let ((k (%consume-timelock fdp))) (and k (info :fragment :older :k k)))))
        (5 (and allow-b (let ((k (%consume-timelock fdp))) (and k (info :fragment :after :k k)))))
        (6 (and allow-b (info :fragment :sha256 :hash (aref (mtd-sha256 d) (consume-integral fdp :u8)))))
        (7 (and allow-b (info :fragment :hash256 :hash (aref (mtd-hash256 d) (consume-integral fdp :u8)))))
        (8 (and allow-b (info :fragment :ripemd160 :hash (aref (mtd-ripemd160 d) (consume-integral fdp :u8)))))
        (9 (and allow-b (info :fragment :hash160 :hash (aref (mtd-hash160 d) (consume-integral fdp :u8)))))
        (10 (and allow-b (not tap)
                 (let ((k (consume-integral fdp :u8)) (n (consume-integral fdp :u8)))
                   (and (<= n 20) (plusp k) (<= k n)
                        (info :fragment :multi :k k :keys (loop repeat n collect (key)))))))
        (11 (and (or allow-b allow-k allow-v)
                 (info :fragment :andor :subtypes (list (%t "B") type-needed type-needed))))
        (12 (and (or allow-b allow-k allow-v) (info :fragment :and-v :subtypes (list (%t "V") type-needed))))
        (13 (and allow-b (info :fragment :and-b :subtypes (list (%t "B") (%t "W")))))
        (15 (and allow-b (info :fragment :or-b :subtypes (list (%t "B") (%t "W")))))
        (16 (and allow-v (info :fragment :or-c :subtypes (list (%t "B") (%t "V")))))
        (17 (and allow-b (info :fragment :or-d :subtypes (list (%t "B") (%t "B")))))
        (18 (and (or allow-b allow-k allow-v) (info :fragment :or-i :subtypes (list type-needed type-needed))))
        (19 (and allow-b
                 (let ((k (consume-integral fdp :u8)) (n (consume-integral fdp :u8)))
                   (and (plusp k) (<= k n)
                        (info :fragment :thresh :k k
                              :subtypes (cons (%t "B") (loop repeat (1- n) collect (%t "W"))))))))
        (20 (and allow-w (info :fragment :wrap-a :subtypes (list (%t "B")))))
        (21 (and allow-w (info :fragment :wrap-s :subtypes (list (%t "B")))))
        (22 (and allow-b (info :fragment :wrap-c :subtypes (list (%t "K")))))
        (23 (and allow-b (info :fragment :wrap-d :subtypes (list (%t "V")))))
        (24 (and allow-v (info :fragment :wrap-v :subtypes (list (%t "B")))))
        (25 (and allow-b (info :fragment :wrap-j :subtypes (list (%t "B")))))
        (26 (and allow-b (info :fragment :wrap-n :subtypes (list (%t "B")))))
        (27 (and allow-b tap
                 (let ((k (consume-integral fdp :u16)) (n (consume-integral fdp :u16)))
                   (and (<= n 999) (plusp k) (<= k n)
                        (info :fragment :multi-a :k k :keys (loop repeat n collect (key)))))))
        (t nil)))))

(defparameter +ms-generator-ops+
  '((:just-0 . 0) (:just-1 . 0) (:pk-k . 0) (:pk-h . 3) (:older . 1) (:after . 1)
    (:ripemd160 . 4) (:sha256 . 4) (:hash160 . 4) (:hash256 . 4) (:andor . 3) (:and-v . 0)
    (:and-b . 1) (:or-b . 1) (:or-c . 2) (:or-d . 3) (:or-i . 3) (:multi . 1)
    (:wrap-a . 2) (:wrap-s . 1) (:wrap-c . 1) (:wrap-d . 3) (:wrap-v . 0) (:wrap-j . 4) (:wrap-n . 1))
  "GenNode's static op count per fragment (:888-957); THRESH adds one per
sub, MULTI_A one per key plus one.")

(defun %gen-node (ctx consume root-type &optional strict-valid)
  "Core GenNode (:846-989): a node of ROOT-TYPE built from CONSUME's choices,
or NIL. Asserts, as Core does, the predicted static ops and script size."
  (let ((stack '())
        (todo (list (cons root-type nil)))
        (ops 0)
        (scriptsize 1))
    (loop while todo
          do (destructuring-bind (type-needed . info) (first todo)
               (cond
                 ((null info)
                  (let ((info (funcall consume type-needed)))
                    (unless info (return-from %gen-node nil))
                    (incf scriptsize (1- (bl.val:ms-compute-script-len
                                          (mni-fragment info) 0 (length (mni-subtypes info))
                                          (mni-k info) (length (mni-subtypes info))
                                          (length (mni-keys info)) ctx)))
                    (when (> scriptsize 3600) (return-from %gen-node nil))
                    (incf ops (case (mni-fragment info)
                                (:thresh (length (mni-subtypes info)))
                                (:multi-a (1+ (length (mni-keys info))))
                                (t (cdr (assoc (mni-fragment info) +ms-generator-ops+)))))
                    (when (> ops 201) (return-from %gen-node nil))
                    (setf (cdr (first todo)) info)
                    ;; Children pushed so that the FIRST sub is generated first.
                    (dolist (st (reverse (mni-subtypes info)))
                      (push (cons st nil) todo))))
                 (t
                  (let* ((n (length (mni-subtypes info)))
                         (subs (reverse (subseq stack 0 n)))
                         (node (progn
                                 (setf stack (nthcdr n stack))
                                 (bl.val:make-ms-node (mni-fragment info)
                                                      :subs subs :keys (mni-keys info)
                                                      :k (mni-k info) :data (mni-hash info) :ctx ctx)))
                         (type (bl.val:ms-node-node-type node)))
                    (when (zerop (logand type (%t "KVWB")))
                      (fuzz-assert (not strict-valid)
                                   "the smart generator built an untyped ~S" (mni-fragment info))
                      (return-from %gen-node nil))
                    (unless (zerop type-needed)
                      (fuzz-assert (%mst<< type type-needed)
                                   "a ~S node lacks the type it was built for" (mni-fragment info)))
                    (unless (bl.val:ms-node-valid-p node) (return-from %gen-node nil))
                    (when (and (eq (mni-fragment info) :wrap-v)
                               (%mst<< (bl.val:ms-node-node-type (first subs)) (%t "x")))
                      (incf ops) (incf scriptsize))
                    (when (and (not (eq ctx :tapscript)) (> ops 201)) (return-from %gen-node nil))
                    (when (> scriptsize (bl.val:ms-max-script-size ctx)) (return-from %gen-node nil))
                    (push node stack)
                    (pop todo))))))
    (let ((node (first stack)))
      (fuzz-assert (= (fuzz-sabotage (first (bl.val:ms-node-ops node))) ops)
                   "static ops ~D, the generator predicted ~D" (first (bl.val:ms-node-ops node)) ops)
      (fuzz-assert (= (bl.val:ms-node-script-size node) scriptsize)
                   "script size ~D, the generator predicted ~D" (bl.val:ms-node-script-size node) scriptsize)
      node)))

;;; --- TestNode -----------------------------------------------------------------

(defun %witness-size (stack)
  "GetSerializeSize(stack) less the count's CompactSize."
  (loop for item in stack
        sum (+ (length item) (cond ((< (length item) 253) 1) ((< (length item) 65536) 3) (t 5)))))

(defun %test-ms-node (ctx node)
  "Core TestNode (:1015-1188), without VerifyScript."
  (when node
    (let* ((text (bl.val:ms-node-to-string node))
           (parsed (handler-case (bl.val:ms-parse text :ctx ctx)
                     (bl.val:miniscript-parse-error (e)
                       (signal-fuzz-violation (format nil "~A does not parse back under ~S: ~A" text ctx e)))))
           (script (bl.val:ms-node-script node)))
      (fuzz-assert (and parsed (string= (fuzz-sabotage (bl.val:ms-node-to-string parsed)) text)
                        (equalp (bl.val:ms-node-script parsed) script))
                   "~A does not survive its text round trip under ~S" text ctx)
      (fuzz-assert (= (bl.val:ms-node-script-size node) (length script))
                   "~A: script size ~D, script ~D bytes" text (bl.val:ms-node-script-size node) (length script))
      (let ((type (bl.val:ms-node-node-type node)))
        (unless (%mst<< type (%t "K"))
          (fuzz-assert (eq (not (%mst<< type (%t "x")))
                           (and (member (aref script (1- (length script))) '(#xac #xae #x87 #x9c)) t))
                       "~A: the x property disagrees with its last opcode" text))
        (when (bl.val:ms-node-valid-top-level-p node)
          (let ((decoded (bl.val:ms-from-script script :ctx ctx)))
            (fuzz-assert (and decoded (equalp (bl.val:ms-node-script decoded) script)
                              (= (bl.val:ms-node-node-type decoded) type))
                         "~A does not survive its script round trip under ~S" text ctx))
          (let ((sat (%ms-fuzz-satisfier ctx)))
            (multiple-value-bind (stack malleable has-sig available) (bl.val:ms-satisfy node sat)
              ;; Core Satisfy's two modes (miniscript.h:1704-1712).
              (let ((mal-success (and available t))
                    (nonmal-success (and available (not malleable) has-sig t)))
                (when nonmal-success
                  (fuzz-assert (<= (length stack) (+ (bl.val:ms-node-get-stack-size node) 1
                                                     (if (eq ctx :tapscript) 1 0)))
                               "~A: a satisfaction of ~D items, GetStackSize ~D" text (length stack)
                               (bl.val:ms-node-get-stack-size node))
                  (fuzz-assert (<= (%witness-size stack) (bl.val:ms-node-get-witness-size node))
                               "~A: a witness of ~D bytes, GetWitnessSize ~D" text (%witness-size stack)
                               (bl.val:ms-node-get-witness-size node)))
                (when (bl.val:ms-node-sane-p node)
                  (fuzz-assert (eq mal-success nonmal-success)
                               "~A is sane but satisfies only malleably" text))
                (fuzz-assert (eq mal-success (%ms-satisfiable-p node))
                             "~A: a satisfaction ~:[does not exist~;exists~] but the policy is ~:[un~;~]satisfiable"
                             text mal-success (%ms-satisfiable-p node))))))))))

;;; --- miniscript_stable ---------------------------------------------------------

(define-fuzz-target miniscript-stable
    (buffer :core "miniscript.cpp:1203-1212" :iterations 3000 :max-len 120
            ;; Bytes below 28 are all fragment choices ConsumeNodeStable knows:
            ;; a random byte names one 11% of the time and trees stay leaves.
            :corpus (lambda (fdp)
                      (map '(vector (unsigned-byte 8)) (lambda (b) (mod b 28))
                           (consume-remaining-bytes fdp))))
  "Nodes generated from the stable encoding, under P2WSH and under tapscript,
round-trip through text and script, size and count their ops as predicted,
and satisfy exactly as the test data allows."
  (dolist (ctx '(:p2wsh :tapscript))
    (let ((fdp (make-fuzzed-data-provider buffer)))
      (%test-ms-node ctx (%gen-node ctx (lambda (needed) (%consume-node-stable ctx fdp needed)) 0)))))

;;; --- miniscript_smart ----------------------------------------------------------

(defvar *ms-smart-tables* nil "SMARTINFO: ctx -> (type -> recipes), built on first use.")

(defparameter +ms-all-fragments+
  '(:just-0 :just-1 :pk-k :pk-h :older :after :sha256 :hash256 :ripemd160 :hash160
    :wrap-a :wrap-s :wrap-c :wrap-d :wrap-v :wrap-j :wrap-n
    :and-v :and-b :or-b :or-c :or-d :or-i :andor :thresh :multi :multi-a)
  "Core's Fragment enum order (miniscript.h:211-243).")

(defun %ms-smart-types ()
  "The interesting type requirements (:517-545): sections of BKVWzondu."
  (let ((types '()))
    (loop for base in '("B" "K" "V" "W") for bi from 0
          do (loop for zo in '("z" "o" "") for zi from 0
                   do (loop for n in '("" "n")
                            do (unless (or (and (= zi 0) (string= n "n")) (and (= bi 3) (string= n "n")))
                                 (loop for d in '("" "d")
                                       do (unless (and (= bi 2) (string= d "d"))
                                            (loop for u in '("" "u")
                                                  do (unless (and (= bi 2) (string= u "u"))
                                                       (push (%t (concatenate 'string base zo n d u)) types)))))))))
    (sort (remove-duplicates types) #'<)))

(defun %ms-build-smart-table (ctx)
  "Core SmartInfo::Init (:514-757) for CTX: a hash table from each useful,
constructible type to its recipes -- (fragment . subtypes) -- sorted fewest
subs first."
  (let* ((types (%ms-smart-types))
         (table (make-hash-table)))
    (flet ((super-of-p (a b)
             (and (eq (car a) (car b)) (= (length (cdr a)) (length (cdr b)))
                  (every (lambda (x y) (%mst<< y x)) (cdr a) (cdr b)))))
      (dolist (frag +ms-all-fragments+)
        (unless (or (and (not (eq ctx :tapscript)) (eq frag :multi-a))
                    (and (eq ctx :tapscript) (eq frag :multi)))
          (let ((sub-count 0) (sub-range 1) (data-size 0) (n-keys 0) (k 0))
            (case frag
              ((:pk-k :pk-h) (setf n-keys 1))
              ((:multi :multi-a) (setf n-keys 1 k 1))
              ((:older :after) (setf k 1))
              ((:sha256 :hash256) (setf data-size 32))
              ((:ripemd160 :hash160) (setf data-size 20))
              ((:wrap-a :wrap-s :wrap-c :wrap-d :wrap-v :wrap-j :wrap-n) (setf sub-count 1))
              ((:and-v :and-b :or-b :or-c :or-d :or-i) (setf sub-count 2))
              (:andor (setf sub-count 3))
              (:thresh (setf sub-count 1 sub-range 2 k 1)))
            (loop for subs from sub-count below (+ sub-count sub-range)
                  do (block per-count
                       (dolist (x types)
                         (dolist (y types)
                           (dolist (z types)
                             (let* ((subt (subseq (list x y z) 0 subs))
                                    (res (bl.val:ms-compute-type frag (if (> subs 0) x 0) (if (> subs 1) y 0)
                                                                 (if (> subs 2) z 0) subt k data-size subs
                                                                 n-keys ctx)))
                               (when (= 1 (+ (if (%mst<< res (%t "K")) 1 0) (if (%mst<< res (%t "V")) 1 0)
                                             (if (%mst<< res (%t "B")) 1 0) (if (%mst<< res (%t "W")) 1 0)))
                                 (let ((entry (cons frag subt)))
                                   (dolist (s types)
                                     (when (%mst<< (logand res (%t "BKVWzondu")) s)
                                       (unless (some (lambda (r) (super-of-p r entry)) (gethash s table))
                                         (setf (gethash s table) (append (gethash s table) (list entry)))))))))
                             (when (<= subs 2) (return)))
                           (when (<= subs 1) (return)))
                         (when (<= subs 0) (return-from per-count))))))))
      ;; Useful types: the closure of B, V, K, W over recipes.
      (let ((useful (list (%t "B") (%t "V") (%t "K") (%t "W"))))
        (loop (let ((before (length useful)))
                (maphash (lambda (type recipes)
                           (when (member type useful)
                             (dolist (r recipes) (dolist (st (cdr r)) (pushnew st useful)))))
                         table)
                (when (= before (length useful)) (return))))
        (maphash (lambda (type recipes) (declare (ignore recipes))
                   (unless (member type useful) (remhash type table)))
                 table))
      ;; Constructible types, and only recipes over them.
      (let ((constructible '()))
        (loop (let ((before (length constructible)))
                (maphash (lambda (type recipes)
                           (unless (member type constructible)
                             (when (some (lambda (r) (every (lambda (st) (member st constructible)) (cdr r)))
                                         recipes)
                               (push type constructible))))
                         table)
                (when (= before (length constructible)) (return))))
        (maphash (lambda (type recipes)
                   (let ((kept (remove-if-not (lambda (r) (every (lambda (st) (member st constructible)) (cdr r)))
                                              recipes)))
                     (if kept
                         (setf (gethash type table)
                               (stable-sort (copy-list kept)
                                            (lambda (a b)
                                              (or (< (length (cdr a)) (length (cdr b)))
                                                  (and (= (length (cdr a)) (length (cdr b)))
                                                       (%recipe< a b))))))
                         (remhash type table))))
                 table)))
    table))

(defun %recipe< (a b)
  "Core's recipe order, std::pair<Fragment, vector<Type>>'s operator<."
  (let ((fa (position (car a) +ms-all-fragments+)) (fb (position (car b) +ms-all-fragments+)))
    (cond ((/= fa fb) (< fa fb))
          (t (loop for x in (cdr a) for y in (cdr b)
                   do (cond ((< x y) (return t)) ((> x y) (return nil)))
                   finally (return (< (length (cdr a)) (length (cdr b)))))))))

(defun %ms-smart-table (ctx)
  (or (getf *ms-smart-tables* ctx)
      (setf (getf *ms-smart-tables* ctx) (%ms-build-smart-table ctx))))

(defun %consume-node-smart (ctx fdp type-needed)
  "Core ConsumeNodeSmart (:770-842)."
  (let* ((recipes (gethash type-needed (%ms-smart-table ctx)))
         (d (%ms-test-data)))
    (fuzz-assert recipes "no recipe for a type the table asked for")
    (destructuring-bind (frag . subt) (pick-value-in-array fdp recipes)
      (flet ((key () (aref (mtd-keys d) (consume-integral fdp :u8))))
        (case frag
          ((:pk-k :pk-h) (make-ms-node-info :fragment frag :keys (list (key))))
          (:multi (let* ((n (consume-integral-in-range fdp 1 20 8)) (k (consume-integral-in-range fdp 1 n 8)))
                    (make-ms-node-info :fragment frag :k k :keys (loop repeat n collect (key)))))
          (:multi-a (let* ((n (consume-integral-in-range fdp 1 999 16)) (k (consume-integral-in-range fdp 1 n 16)))
                      (make-ms-node-info :fragment frag :k k :keys (loop repeat n collect (key)))))
          ((:older :after) (make-ms-node-info :fragment frag :k (consume-integral-in-range fdp 1 #x7ffffff 32)))
          (:sha256 (make-ms-node-info :fragment frag :hash (pick-value-in-array fdp (mtd-sha256 d))))
          (:hash256 (make-ms-node-info :fragment frag :hash (pick-value-in-array fdp (mtd-hash256 d))))
          (:ripemd160 (make-ms-node-info :fragment frag :hash (pick-value-in-array fdp (mtd-ripemd160 d))))
          (:hash160 (make-ms-node-info :fragment frag :hash (pick-value-in-array fdp (mtd-hash160 d))))
          (:thresh (let* ((children (if (< (length subt) 2)
                                        (length subt)
                                        (consume-integral-in-range fdp 2 100 32)))
                          (k (consume-integral-in-range fdp 1 children 32))
                          (subs (copy-list subt)))
                     (loop while (< (length subs) children) do (setf subs (append subs (last subs))))
                     (make-ms-node-info :fragment frag :k k :subtypes subs)))
          (t (make-ms-node-info :fragment frag :subtypes subt)))))))

(define-fuzz-target miniscript-smart
    (buffer :core "miniscript.cpp:1215-1226" :iterations 2000 :max-len 200)
  "Nodes generated from the recipe tables the type calculus implies, of a
chosen base type and context: every one is valid for the type it was built
for, and passes TestNode's checks."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (ctx (if (consume-bool fdp) :tapscript :p2wsh)))
    (%test-ms-node ctx (%gen-node ctx (lambda (needed) (%consume-node-smart ctx fdp needed))
                                  (pick-value-in-array fdp (list (%t "B") (%t "V") (%t "K") (%t "W")))
                                  t))))
