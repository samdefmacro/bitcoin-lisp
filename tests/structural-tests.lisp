(in-package #:bitcoin-lisp.tests)

(def-suite :structural-tests :in :bitcoin-lisp-tests
  :description "Whole-tree structural invariants no single unit test can see.")
(in-suite :structural-tests)

;;;; ====================================================================
;;;; Exported functions with no production caller
;;;;
;;;; This project has shipped ten pieces of correct code that nothing called
;;;; -- the notfound disclaims, the CBlockUndo codec, the compact-block
;;;; emitter, build-tx-index, scan-for-op-success, connect-block's :tx-index
;;;; argument, and more. Every one was found by a live log line, a shipped
;;;; diagnostic or a manual sweep; NONE was found by the 30,000-check unit
;;;; suite, because a unit test calls the function itself and so proves only
;;;; that it works, never that anything uses it.
;;;;
;;;; This test closes that gap. It cannot tell a deliberate API entry point
;;;; from an accident, so it does not try: it pins the known set and fails on
;;;; ADDITIONS. It deliberately does not fail when an entry gains a caller --
;;;; that is the change we want, and a test that goes red on good news is one
;;;; whose baseline gets re-pasted wholesale rather than read, which is
;;;; exactly how an instrument like this stops detecting anything while still
;;;; reporting green. Resolved entries are printed instead; deleting their
;;;; lines is a one-commit chore.
;;;; ====================================================================

(defparameter *orphan-export-baseline*
  '(
    ;; Entry points reached from outside the image: the saved executable's
    ;; toplevel (scripts/build-node-core.lisp names it), the launcher
    ;; (scripts/run-node.sh) and an operator at the REPL.
    ;;
    ;; run-node-watchdog and start-node-from-args left this list when NODE-MAIN
    ;; started calling them — the sweep noticed, which is the point of it.
    "bitcoin-lisp:clear-logs"
    "bitcoin-lisp:disable-console-logging"
    "bitcoin-lisp:node-main"
    "bitcoin-lisp:node-status"
    "bitcoin-lisp:show-logs"
    "bitcoin-lisp:stop-file-logging"

    ;; Superseded, or written and never wired. Includes the legacy utxo-set
    ;; API that coins-view-cache replaced, REQUEST-HEADERS beside the live
    ;; REQUEST-HEADERS-FOR-IBD, and BAN-PEER, which nothing calls because
    ;; misbehaviour discourages and setban bans by address.
    ;; Called only from the top-level EVAL-WHEN form at the end of every
    ;; package file; xref records calls from named functions only.
    "bitcoin-lisp.nicknames:install-package-nicknames"
    "bitcoin-lisp.crypto:bip324-cipher-initialized-p"
    "bitcoin-lisp.crypto:ellswift-decode"
    "bitcoin-lisp.crypto:muhash-combine"
    "bitcoin-lisp.crypto:muhash-divide"
    "bitcoin-lisp.crypto:xonly-pubkey-valid-p"
    "bitcoin-lisp.mempool:ancestor-sort-linearization"
    "bitcoin-lisp.mempool:chunk-linearization"
    "bitcoin-lisp.mempool:depgraph-reduced-children"
    "bitcoin-lisp.mempool:feefrac-empty-p"
    "bitcoin-lisp.mempool:feefrac-evaluate-fee-down"
    "bitcoin-lisp.mempool:feefrac-evaluate-fee-up"
    "bitcoin-lisp.mempool:feefrac<"
    "bitcoin-lisp.mempool:feefrac<="
    "bitcoin-lisp.mempool:feefrac>="
    "bitcoin-lisp.mempool:mempool-ancestor-fee-rate"
    "bitcoin-lisp.mempool:mempool-descendant-fee-rate"
    "bitcoin-lisp.mempool:mempool-entry-fee-rate"
    "bitcoin-lisp.mempool:mempool-get-transactions"
    "bitcoin-lisp.mempool:orphan-announcements-from-peer"
    "bitcoin-lisp.mempool:orphan-announcers"
    "bitcoin-lisp.mempool:orphan-usage-by-peer"
    "bitcoin-lisp.mempool:topological-subset-p"
    "bitcoin-lisp.mempool:txgraph-compare-main-order"
    "bitcoin-lisp.mempool:txgraph-get-ancestors-union"
    "bitcoin-lisp.mempool:txgraph-get-descendants-union"
    "bitcoin-lisp.mempool:txgraph-get-individual-feerate"
    "bitcoin-lisp.networking:ban-peer"
    "bitcoin-lisp.networking:clear-discouraged"
    "bitcoin-lisp.networking:clear-pending-compact-block"
    "bitcoin-lisp.networking:compact-block-stats"
    "bitcoin-lisp.networking:last-checkpoint-height"
    "bitcoin-lisp.networking:local-addresses"
    "bitcoin-lisp.networking:request-headers"
    "bitcoin-lisp.networking:tor-controller-service-id"
    "bitcoin-lisp.serialization:bip155-network-keyword"
    "bitcoin-lisp.serialization:br-read-compressed-coin"
    "bitcoin-lisp.serialization:make-getblocks-message"
    "bitcoin-lisp.storage:add-utxo"
    "bitcoin-lisp.storage:any-utxo-for-txid-p"
    "bitcoin-lisp.storage:coins-view-db-erase"
    "bitcoin-lisp.storage:coins-view-db-has-p"
    "bitcoin-lisp.storage:coins-view-db-put"
    "bitcoin-lisp.storage:coins-view-db-write-batch"
    "bitcoin-lisp.storage:find-next-record"
    "bitcoin-lisp.storage:flat-file-pos-null-p"
    "bitcoin-lisp.storage:gcs-filter-match"
    "bitcoin-lisp.storage:leveldb-writebatch-clear"
    "bitcoin-lisp.storage:load-tx-index"
    "bitcoin-lisp.storage:remove-utxo"
    "bitcoin-lisp.storage:save-utxo-set"
    "bitcoin-lisp.storage:txindex-contains-p"
    "bitcoin-lisp.storage:txindex-remove-block"
    "bitcoin-lisp.storage:utxo-exists-p"
    "bitcoin-lisp.storage:write-utxo-entry-fields"
    "bitcoin-lisp.validation:decode-coinbase-height"
    "bitcoin-lisp.validation:execute-script")
  "Exported functions with no caller in src/ as of 2026-08-22, as
\"package:name\" strings -- strings rather than symbols so that unexporting one
is an ordinary test failure and not a READ error that kills compilation.")

(defun %bitcoin-lisp-packages ()
  "The project's own CL packages: everything named BITCOIN-LISP*, minus the
tests package and the Coalton ones. Derived rather than listed so a new package
cannot be silently excluded from the sweep -- but the Coalton packages are held
out on purpose: their exports are generated, and the several hundred that no CL
code calls would bury the finding this test exists to surface."
  (remove-if-not
   (lambda (p)
     (let ((n (package-name p)))
       (and (>= (length n) 12)
            (string= "BITCOIN-LISP" n :end2 12)
            (not (search ".COALTON" n))
            (not (string= "BITCOIN-LISP.TESTS" n)))))
   (list-all-packages)))

(defun %function-object-references (src)
  "The set of names SRC references as a function OBJECT, i.e. #'name.

Needed because xref records CALLS only: a function installed as a hook --
Core-style, e.g. (setf *peer-disconnect-hook* #'tx-request-disconnected-peer)
-- has no call site and would otherwise read as dead. Tokenised rather than
searched per symbol, so that #'request-headers-for-ibd cannot be mistaken for
a reference to REQUEST-HEADERS: a substring test would drop every name that is
a prefix of another, silently, which is the same failure mode as the dead code
it hunts."
  (let ((refs (make-hash-table :test #'equal))
        (i 0))
    (flet ((name-char-p (c)
             (or (alphanumericp c) (find c "-+*/<>=!?%_&.:"))))
      (loop while (setf i (search "#'" src :start2 i))
            do (let* ((start (+ i 2))
                      (end (or (position-if-not #'name-char-p src :start start)
                               (length src))))
                 (when (> end start)
                   (setf (gethash (subseq src start end) refs) t))
                 (setf i start))))
    refs))

(defvar *orphan-sweep-cache* nil
  "Memo for %ORPHAN-EXPORTED-FUNCTIONS: the sweep reads every file under src/
and nothing between the tests in this file can change its answer.")

(defun %orphan-exported-functions ()
  "Every exported function in the project's packages with no caller in src/.

A caller counts when SB-INTROSPECT:WHO-CALLS reports one whose own name is not
in the tests package, or when src/ references the function as an object (see
%FUNCTION-OBJECT-REFERENCES).

DEFSTRUCT-generated predicates and accessors are excluded: SBCL gives them a
source-transform and hand-written functions have none, so the two separate
cleanly and the many unused accessors do not bury the real finding."
  (or *orphan-sweep-cache*
      (setf *orphan-sweep-cache*
            (let* ((src (%source-text))
                   (refs (%function-object-references src))
                   (tests-package (find-package "BITCOIN-LISP.TESTS"))
                   (found '()))
              (labels ((root-symbol (name)
                         (cond ((symbolp name) name)
                               ((consp name) (root-symbol (find-if #'symbolp (cdr name))))
                               (t nil)))
                       (test-caller-p (caller)
                         (let ((r (root-symbol (car caller))))
                           (and r (eq (symbol-package r) tests-package))))
                       (orphan-p (sym)
                         (and (fboundp sym)
                              (not (macro-function sym))
                              (not (typep (fdefinition sym) 'generic-function))
                              (not (sb-int:info :function :source-transform sym))
                              (every #'test-caller-p (sb-introspect:who-calls sym))
                              (not (gethash (string-downcase (symbol-name sym)) refs)))))
                (dolist (pkg (%bitcoin-lisp-packages))
                  (do-external-symbols (sym pkg)
                    (when (orphan-p sym)
                      (pushnew (format nil "~(~A:~A~)"
                                       (package-name (symbol-package sym))
                                       (symbol-name sym))
                               found :test #'string=))))
                (sort found #'string<))))))

(test no-new-orphaned-exports
  "An exported function that nothing in src/ calls is either an entry point or
a bug, and this project's history says it is usually a bug -- ten times so far,
never once caught by a unit test."
  (let* ((current (%orphan-exported-functions))
         (new (set-difference current *orphan-export-baseline* :test #'string=))
         (resolved (set-difference *orphan-export-baseline* current :test #'string=)))
    (is (null new)
        "no caller in src/ for:~%~{  ~A~%~}Wire it up, or add it to ~
*ORPHAN-EXPORT-BASELINE* under the group that says why."
        new)
    ;; Progress, not a failure: report it so the list can be pruned.
    (when resolved
      (format *test-dribble*
              "~&; ~D *ORPHAN-EXPORT-BASELINE* entr~:@P now called from src/; ~
delete from the list:~%~{;   ~A~%~}" (length resolved) resolved))))

(test orphan-sweep-can-actually-fail
  "Positive control for NO-NEW-ORPHANED-EXPORTS, whose assertion is of the form
\"this set is empty\" -- exactly the shape that keeps passing once the machinery
underneath quietly stops working. Hide one known orphan from the comparison and
confirm the sweep still reports it. Independent of the baseline, so baseline
drift cannot turn this control into a false alarm."
  (let ((current (%orphan-exported-functions)))
    (is (plusp (length current)) "the orphan sweep found nothing at all")
    (is (= 1 (length (set-difference current (rest current) :test #'string=)))
        "a known orphan withheld from the comparison must surface as new")
    ;; And the object-reference scan must actually exclude something, or every
    ;; hook-installed function would read as dead.
    (let ((refs (%function-object-references "(setf *hook* #'tx-request-disconnected-peer)")))
      (is-true (gethash "tx-request-disconnected-peer" refs))
      (is-false (gethash "tx-request-disconnected" refs)
                "a prefix of a referenced name must not count as referenced"))))


;;;; ====================================================================
;;;; Global hash tables and thread safety
;;;;
;;;; A plain SBCL hash table taking concurrent read-through inserts corrupts
;;;; silently. #462 fixed one instance (the coins view's CVC-ENTRIES, written
;;;; by parallel script-check workers through COLLECT-SPENT-UTXOS) by resolving
;;;; the coins on the validation thread first. Two more survived that audit
;;;; because they live a layer down, inside the interpreter and the crypto
;;;; helpers rather than in the validation code that was being read.

(defparameter +parallel-path-caches+
  '(("bitcoin-lisp.coalton.interop" . "*signature-cache*")
    ("bitcoin-lisp.coalton.interop" . "*signature-cache-prev*")
    ("bitcoin-lisp.coalton.interop" . "*script-execution-cache*")
    ("bitcoin-lisp.coalton.interop" . "*script-execution-cache-prev*")
    ("bitcoin-lisp.coalton.interop" . "*flag-set-cache*")
    ("bitcoin-lisp.crypto" . "*tagged-hash-cache*"))
  "Global caches a parallel script-check worker reads or writes.

Every one of these is reached from inside a check thunk, so with -par above 1
they take concurrent traffic from every worker at once:

  *flag-set-cache*        FLAG-ENABLED-P, from the P2SH/WITNESS/SIGPUSHONLY
                          gates -- i.e. every script, the hottest path there is
  *tagged-hash-cache*     GET-TAG-HASH, from TapSighash and the
                          TapLeaf/TapBranch/TapTweak hashes -- every taproot input
  the sig/script caches   the verification short-circuits themselves

They must be :SYNCHRONIZED. Racing the VALUE is harmless in all six -- each is
a deterministic function of its key, so a lost store costs a recompute -- but
the table's own structure is not.")

(test parallel-path-caches-are-synchronized
  "The caches a script-check worker touches must survive concurrent inserts.

Asserted on the live tables rather than by grepping for :synchronized, because
what matters is the object the workers actually share."
  #+sbcl
  (dolist (entry +parallel-path-caches+)
    (let* ((sym (find-symbol (string-upcase (cdr entry))
                             (find-package (string-upcase (car entry)))))
           (table (and sym (boundp sym) (symbol-value sym))))
      (is-true (and table (hash-table-p table))
               "~A::~A is not a bound hash table" (car entry) (cdr entry))
      (when (and table (hash-table-p table))
        (is-true (sb-ext:hash-table-synchronized-p table)
                 "~A::~A is not :synchronized, and parallel workers insert into it"
                 (car entry) (cdr entry)))))
  #-sbcl (skip "SBCL-specific"))

(defparameter +known-unsynchronized-globals+
  '("BITCOIN-LISP.NETWORKING::*ADDR-RESPONSE-CACHES*"
    "BITCOIN-LISP.NETWORKING::*BANNED-PEERS*"
    "BITCOIN-LISP.NETWORKING::*BLOCK-FAILURE-COUNTS*"
    "BITCOIN-LISP.NETWORKING::*OUTBOUND-NONCES*"
    "BITCOIN-LISP.NETWORKING::*TX-ANNOUNCERS*"
    "BITCOIN-LISP.NETWORKING::*TX-IN-FLIGHT*"
    "BITCOIN-LISP.NETWORKING::*TX-PEER-ANNOUNCEMENTS*"
    "BITCOIN-LISP.NETWORKING::*TX-PEER-IN-FLIGHT*"
    "BITCOIN-LISP.NETWORKING::*TX-REQUEST-WTXID-P*"
    "BITCOIN-LISP.SERIALIZATION::*ADDRV2-ADDR-SIZES*"
    "BITCOIN-LISP.STORAGE::*LEVELDB-OWNED-RESOURCES*"
    "BITCOIN-LISP.VALIDATION::*BLOCK-UNDO-DATA*"
    "BITCOIN-LISP.VALIDATION::*MOST-RECENT-BLOCK-TXS*"
    "BITCOIN-LISP.VALIDATION::*OPCODE-NAMES*"
    "BITCOIN-LISP.VALIDATION::*TEST-ACTIVATION-HEIGHTS*"
    "BITCOIN-LISP.VALIDATION::*UNDO-CACHE-HEIGHTS*"
    "BITCOIN-LISP::*DEBUG-CATEGORIES*"
    "BITCOIN-LISP::*LOG-RATE-LOCATIONS*")
  "Global hash tables that are NOT :synchronized, and are fine as they are.

Each is either populated once at load or start-up and read-only afterwards
(*OPCODE-NAMES*, *ADDRV2-ADDR-SIZES*, *DEBUG-CATEGORIES*,
*TEST-ACTIVATION-HEIGHTS*), or written under an explicit lock
(*BANNED-PEERS* under *BAN-LOCK*, *LOG-RATE-LOCATIONS* under *LOG-LOCK*), or
touched only by the single sync/validation thread, or REPLACED WHOLESALE rather
than mutated (*MOST-RECENT-BLOCK-TXS*: the validation thread fills a fresh table
and only then assigns it, so a net thread serving a compact block reads a table
nobody is still writing to).

*MOST-RECENT-BLOCK-TXS* is NIL until the first block connects, so whether it
appears here at all depends on what ran before this test in the same image. It
is listed rather than left to chance — an entry that is absent costs a
trim-the-list failure, which is the cheaper direction to be wrong in.

The list is the audit. It exists so that ADDING an unsynchronized global is a
decision someone makes on purpose rather than a default nobody looked at --
which is exactly how the two caches above came to be raced.")

(test no-new-unsynchronized-globals
  "Pin the set of unsynchronized global hash tables.

Not a rule that they must all be synchronized -- most of these are correct as
they are, for reasons recorded next to the baseline. The point is that a NEW
one shows up here and has to be classified, instead of quietly joining the
worker path the way *FLAG-SET-CACHE* did."
  #+sbcl
  (let ((found '()))
    (dolist (pkg '("BITCOIN-LISP.COALTON.INTEROP" "BITCOIN-LISP.CRYPTO"
                   "BITCOIN-LISP.VALIDATION" "BITCOIN-LISP.SERIALIZATION"
                   "BITCOIN-LISP" "BITCOIN-LISP.STORAGE" "BITCOIN-LISP.MEMPOOL"
                   "BITCOIN-LISP.NETWORKING"))
      (let ((package (find-package pkg)))
        (when package
          (do-symbols (sym package)
            (when (and (eq (symbol-package sym) package)
                       (boundp sym)
                       (hash-table-p (symbol-value sym))
                       (not (sb-ext:hash-table-synchronized-p (symbol-value sym))))
              (pushnew (format nil "~A::~A" pkg (symbol-name sym))
                       found :test #'equal))))))
    (let* ((new (sort (set-difference found +known-unsynchronized-globals+
                                      :test #'equal)
                      #'string<))
           ;; A baseline entry counts as GONE only if its symbol is a hash
           ;; table right now and that table is synchronized. Some of these
           ;; start life as NIL and only become tables once the node has done
           ;; something (*MOST-RECENT-BLOCK-TXS* needs a block to connect), so
           ;; a symbol that is not a table says nothing about whether the entry
           ;; is stale — and reading it as "gone" made this test pass or fail
           ;; on which suites happened to run before it in the same image.
           (gone (sort (remove-if-not
                        (lambda (name)
                          (let* ((colons (search "::" name))
                                 (sym (and colons
                                           (find-symbol (subseq name (+ colons 2))
                                                        (subseq name 0 colons)))))
                            (and sym (boundp sym)
                                 (hash-table-p (symbol-value sym))
                                 (sb-ext:hash-table-synchronized-p (symbol-value sym)))))
                        (set-difference +known-unsynchronized-globals+ found
                                        :test #'equal))
                       #'string<)))
      (is (null new)
          "~D new unsynchronized global hash table~:P — classify each, and if a ~
parallel script-check worker can reach it, synchronize it: ~S"
          (length new) new)
      ;; Shrinking is good, but the baseline has to be trimmed with it or it
      ;; stops meaning anything.
      (is (null gone)
          "~D baseline entr~:@P no longer unsynchronized; trim the list: ~S"
          (length gone) gone)))
  #-sbcl (skip "SBCL-specific"))



;;;; ====================================================================
;;;; Refactoring ratchets (docs/refactoring-plan-2026-08-27.md, phase P0)
;;;;
;;;; The cleanup plan turns five observations about the tree into numbers and
;;;; pins each one so that it can only move in the intended direction:
;;;;
;;;;   duplicate definitions   the same DEFUN/DEFMACRO name defined in two files
;;;;   long functions          a top-level definition over 200 (or 100) lines
;;;;   serialization families  call sites of the byte-I/O APIs being retired
;;;;   bare error strings      (error "...") where a condition type should be
;;;;   layering                a file naming a package loaded after it
;;;;
;;;; Each baseline below is the state of main at the start of the cleanup. A
;;;; test fails when the tree gets WORSE (a new duplicate, a new 200-line
;;;; function, a new call into a family being retired). The named lists also
;;;; fail when an entry is resolved, so the baseline is trimmed in the same PR
;;;; that earns it -- the precedent is +KNOWN-UNSYNCHRONIZED-GLOBALS+ above.
;;;; The plain counts only report a decrease: they move incidentally in
;;;; unrelated PRs, and a red test on good news trains people to re-paste the
;;;; number without reading it.
;;;;
;;;; Everything is measured from one read of src/ (%SOURCE-CORPUS). Form
;;;; lengths come from the reader under *READ-SUPPRESS*, which interns nothing
;;;; and needs no package to exist, so it sees exactly the form a reviewer
;;;; sees -- including a docstring line that happens to begin with a paren.
;;;; ====================================================================

(defvar *source-corpus* nil
  "Memo: every file under src/ as (relative-name . lines), read once per image.
Nothing between the tests here edits src/.")

(defun %source-corpus ()
  (or *source-corpus*
      (setf *source-corpus*
            (let ((root (asdf:system-source-directory :bitcoin-lisp)))
              (loop for path in (sort (directory (merge-pathnames "src/**/*.lisp" root))
                                      #'string< :key #'namestring)
                    collect (cons (enough-namestring path root)
                                  (coerce (uiop:read-file-lines path :external-format :utf-8)
                                          'vector)))))))

(defvar *source-text* nil)

(defun %source-text ()
  "All of src/ as one downcased string, for call-site counting."
  (or *source-text*
      (setf *source-text*
            (with-output-to-string (o)
              (loop for (nil . lines) in (%source-corpus)
                    do (loop for l across lines do (write-line (string-downcase l) o)))))))

(defun %lines-text (lines)
  (with-output-to-string (o) (loop for l across lines do (write-line l o))))

(defun %count-occurrences (needle text)
  (loop with i = 0 and n = 0
        while (setf i (search needle text :start2 i))
        do (incf n) (incf i (length needle))
        finally (return n)))

(defun %check-pinned-set (current baseline baseline-name hint &key (test #'string=))
  "The shape shared by every pinned-list ratchet here: nothing new, and
nothing resolved without trimming BASELINE-NAME."
  (let ((new (set-difference current baseline :test test))
        (gone (set-difference baseline current :test test)))
    (is (null new) "~D new entr~:@P: ~S -- ~A" (length new) new hint)
    (is (null gone) "~D baseline entr~:@P resolved; trim ~A: ~S"
        (length gone) baseline-name gone)))

(defun %ratchet-down (label now then baseline-name hint)
  "A count that may only fall. Growth fails; a drop is reported so the
baseline can follow it."
  (is (<= now then) "~A: ~D, baseline ~D -- ~A" label now then hint)
  (when (< now then)
    (format *test-dribble* "~&; ~A down to ~D (baseline ~D); update ~A~%"
            label now then baseline-name)))

;;; --- top-level definitions ------------------------------------------------

(defparameter +definition-prefixes+
  '((:defun . "(defun ") (:defmacro . "(defmacro "))
  "A definition is a line that starts with one of these. Coalton's DEFINEs sit
inside COALTON-TOPLEVEL at indentation 2 and are therefore not counted, on
purpose: the interpreter is a deliberate port of one Core file.")

(defstruct (%definition (:conc-name %def-))
  kind name file line length)

(defun %definition-name (line prefix)
  "The name that follows PREFIX on LINE, downcased. A (setf foo) name is kept
whole, parentheses included."
  (let* ((start (position #\Space line :start (length prefix) :test-not #'char=))
         (end (cond ((null start) nil)
                    ((char= (char line start) #\()
                     (let ((close (position #\) line :start start)))
                       (and close (1+ close))))
                    (t (position-if (lambda (c) (member c '(#\Space #\( #\))))
                                    line :start start)))))
    (and start (string-downcase (subseq line start end)))))

(defun %form-line-count (text start)
  "Lines spanned by the form beginning at character START of TEXT. Read with
*READ-SUPPRESS* so no symbol is interned and no package need exist; strings,
comments, #| |# blocks and #\\x literals are the reader's problem, not ours.
:PRESERVE-WHITESPACE keeps the reader from eating the newline after the
closing paren, which would count as a line."
  (let ((end (let ((*read-suppress* t))
               (nth-value 1 (read-from-string text t nil :start start
                                              :preserve-whitespace t)))))
    (1+ (count #\Newline text :start start :end end))))

(defvar *toplevel-definitions-cache* nil)

(defun %toplevel-definitions ()
  "Every top-level DEFUN/DEFMACRO under src/, with its length in lines."
  (or *toplevel-definitions-cache*
      (setf *toplevel-definitions-cache*
            (loop for (file . lines) in (%source-corpus)
                  for text = (%lines-text lines)
                  nconc (loop with offset = 0
                              for line across lines
                              for lineno from 1
                              for entry = (find-if (lambda (e) (uiop:string-prefix-p (cdr e) line))
                                                   +definition-prefixes+)
                              when entry
                                collect (make-%definition
                                         :kind (car entry)
                                         :name (%definition-name line (cdr entry))
                                         :file file :line lineno
                                         :length (%form-line-count text offset))
                              do (incf offset (1+ (length line))))))))

;;; --- duplicate definitions -------------------------------------------

(defparameter +duplicate-definition-baseline+
  '()
  "Names defined by DEFUN or DEFMACRO in more than one file under src/. Empty
since the cleanup's P1.3: the eighteen it started with included two that
were the SAME package redefining a function -- FSYNC-DIRECTORY, where the
later copy fsynced a file when the callers of the earlier one meant its
parent directory, and TAGGED-HASH, a dead pure-Lisp copy -- which SBCL had
been warning about on every cold run. scripts/docker-test.sh now fails on
that warning; this test catches the cross-package case the warning cannot.")

(defun %duplicate-definition-names ()
  "Names with a top-level DEFUN/DEFMACRO in two or more distinct files."
  (let ((files-by-name (make-hash-table :test #'equal))
        (found '()))
    (dolist (d (%toplevel-definitions))
      (pushnew (%def-file d) (gethash (%def-name d) files-by-name) :test #'string=))
    (maphash (lambda (name files)
               (when (> (length files) 1) (push name found)))
             files-by-name)
    (sort found #'string<)))

(test no-new-duplicate-definitions
  "A DEFUN or DEFMACRO name defined in two files is one implementation too
many, or two things that should not share a name. Either way it is a decision
to make on purpose, so the set is pinned."
  (%check-pinned-set (%duplicate-definition-names) +duplicate-definition-baseline+
                     "+DUPLICATE-DEFINITION-BASELINE+" "merge them, or rename one"))

;;; --- long functions ----------------------------------------------------

(defparameter +long-function-lines+ 200
  "Above this a definition is on the named list.")

(defparameter +longish-function-lines+ 100
  "Above this a definition counts against +LONGISH-FUNCTION-CEILING+.")

(defparameter +long-function-baseline+
  '(("start-node" . 1332)                        ; node.lisp
    ("perform-reorg" . 465)                      ; validation/block.lisp
    ("%create-transaction-internal" . 442)       ; rpc/wallet-spend.lisp
    ("apply-config-globals" . 387)               ; config.lisp
    ("validate-transaction-for-mempool" . 358)   ; validation/transaction.lisp
    ("run-ibd" . 345)                            ; networking/ibd.lisp (+2: keeps node-context peers live, P2c)
    ("validate-block" . 307)                     ; validation/block.lisp
    ("process-received-block" . 300)             ; networking/ibd.lisp
    ("rpc-sendall" . 289)                        ; rpc/wallet-spend.lisp
    ("ms-from-script" . 243)                     ; validation/miniscript.lisp
    ("connect-block" . 215)                      ; validation/block.lisp
    ("activate-block" . 214))                    ; validation/block.lisp
  "(name . lines) of every top-level definition over +LONG-FUNCTION-LINES+ at
the start of the cleanup. Each is a phase-3 target
(docs/refactoring-plan-2026-08-27.md §4 P3): START-NODE becomes Core's
thirteen init steps, PERFORM-REORG becomes DisconnectTip/ConnectTip/
ActivateBestChainStep, and so on. The line count is pinned too, so an entry
may shrink but not grow while it waits its turn.")

(defparameter +longish-function-ceiling+ 62
  "How many definitions may exceed +LONGISH-FUNCTION-LINES+ lines. Lower it
when the count drops; the test says so.")

(defun %definitions-longer-than (lines)
  (sort (remove-if-not (lambda (d) (> (%def-length d) lines)) (%toplevel-definitions))
        #'> :key #'%def-length))

(test no-new-long-functions
  "A function over 200 lines is a file's worth of logic with one name. The
plan splits the existing ones along Core's own function boundaries; this test
keeps new ones from appearing, and the old ones from growing, while that
happens."
  (let ((long (%definitions-longer-than +long-function-lines+)))
    (%check-pinned-set (mapcar #'%def-name long) (mapcar #'car +long-function-baseline+)
                       "+LONG-FUNCTION-BASELINE+" "split along Core's function boundaries")
    (dolist (d long)
      (let ((pinned (cdr (assoc (%def-name d) +long-function-baseline+ :test #'string=))))
        (when pinned
          (%ratchet-down (%def-name d) (%def-length d) pinned
                         "+LONG-FUNCTION-BASELINE+" "a long function may not grow"))))))

(test longish-function-count-does-not-grow
  "The softer ratchet: how many definitions exceed 100 lines."
  (let ((long (%definitions-longer-than +longish-function-lines+)))
    (is (<= (length long) +longish-function-ceiling+)
        "~D definitions over ~D lines, ceiling is ~D: ~S"
        (length long) +longish-function-lines+ +longish-function-ceiling+
        (mapcar #'%def-name long))
    (when (< (length long) +longish-function-ceiling+)
      (format *test-dribble*
              "~&; ~D definitions over ~D lines; lower +LONGISH-FUNCTION-CEILING+ to ~D~%"
              (length long) +longish-function-lines+ (length long)))))

;;; --- serialization API families -----------------------------------------

(defparameter +stream-io-call-patterns+
  '("(read-uint8 " "(read-uint16-le " "(read-uint32-le " "(read-uint64-le "
    "(read-int32-le " "(read-int64-le "
    "(write-uint8 " "(write-uint16-le " "(write-uint32-le " "(write-uint64-le "
    "(write-int32-le " "(write-int64-le ")
  "Call sites of the stream-based integer codecs (serialization/binary.lisp,
top). They run through flexi-streams' gray-stream dispatch, which profiling
found to be the block-deserialization bottleneck (2026-08-22); the plan
retires them in favour of the byte-reader.")

(defparameter +retiring-serialization-family-baseline+
  '((:stream-io . 42)
    (:compact-size-definitions . 8))
  "Call-site counts, at the start of the cleanup, of the byte-I/O families the
plan retires (§4 P1). The byte-reader (br-read-*, 70 sites), the byte-buf
(bb-write-*, 102 sites) and the positional buf-set-* writers underneath them
are the one implementation that stays (src/util/bytes.lisp) and are not
pinned.
  :stream-io     the patterns above
  :compact-size-definitions  distinct DEFUN names containing compact-size or
                 varint, core-varint excluded (a different encoding)")

(defun %serialization-family-count (family text)
  (ecase family
    (:stream-io (reduce #'+ +stream-io-call-patterns+
                        :key (lambda (p) (%count-occurrences p text))))
    (:compact-size-definitions
     (length (remove-duplicates
              (loop for d in (%toplevel-definitions)
                    for name = (%def-name d)
                    when (and (eq (%def-kind d) :defun)
                              (or (search "compact-size" name) (search "varint" name))
                              (not (search "core-varint" name)))
                      collect name)
              :test #'string=)))))

(test retiring-serialization-families-do-not-grow
  "Four byte-I/O APIs do one job. New code goes through the byte-reader and
byte-buf; the stream codecs and interop's private buffer only lose call sites."
  (let ((text (%source-text)))
    (loop for (family . then) in +retiring-serialization-family-baseline+
          do (%ratchet-down family (%serialization-family-count family text) then
                            "+RETIRING-SERIALIZATION-FAMILY-BASELINE+"
                            "use the byte-reader/byte-buf"))))

;;; --- bare error strings -------------------------------------------------

(defparameter +bare-error-baseline+
  '(("src/config.lisp" . 36)
    ("src/crypto/" . 28)
    ("src/logging.lisp" . 3)
    ("src/mempool/" . 7)
    ("src/mining/" . 1)
    ("src/networking/" . 4)
    ("src/node.lisp" . 36)
    ("src/rpc/" . 14)
    ("src/serialization/" . 49)   ; 4 are macroexpansion-time errors in message-macro.lisp
    ("src/storage/" . 16)
    ("src/util/" . 7)
    ("src/validation/" . 3)
    ("src/zmq.lisp" . 1))
  "Count of (error \"...\") -- a string where a condition type belongs -- per
top-level src/ directory (or file, for src/*.lisp) at the start of the
cleanup. A place not listed tolerates none. A string cannot be handled
selectively or mapped to an RPC error code; the plan introduces a condition
hierarchy (§4 P4) and these only go down.")

(defun %bare-error-census ()
  "Alist of top-level src/ directory (or file) to its (error \"...\") count."
  (let ((counts (make-hash-table :test #'equal)))
    (loop for (file . lines) in (%source-corpus)
          for slash = (position #\/ file :start (length "src/"))
          for key = (if slash (subseq file 0 (1+ slash)) file)
          do (loop for l across lines
                   do (incf (gethash key counts 0) (%count-occurrences "(error \"" l))))
    (sort (loop for k being the hash-keys of counts using (hash-value v)
                collect (cons k v))
          #'string< :key #'car)))

(test bare-error-strings-do-not-grow
  "Signal a condition, not a string."
  (loop for (place . now) in (%bare-error-census)
        do (%ratchet-down place now
                          (or (cdr (assoc place +bare-error-baseline+ :test #'string=)) 0)
                          "+BARE-ERROR-BASELINE+" "define or reuse a condition type")))

;;; --- layering -------------------------------------------------------------

(defun %load-order ()
  "Each child of the src module in bitcoin-lisp.asd's order, as (path-prefix
. index): a file as \"src/name.lisp\", a module as \"src/name/\". Derived
from ASDF rather than copied, so a phase-4 reordering cannot leave a stale
list behind."
  (loop for child in (asdf:component-children (asdf:find-component :bitcoin-lisp "src"))
        for i from 0
        collect (cons (if (typep child 'asdf:module)
                          (format nil "src/~A/" (asdf:component-name child))
                          (format nil "src/~A.lisp" (asdf:component-name child)))
                      i)))

(defun %file-layer (file order)
  (cdr (find-if (lambda (e) (uiop:string-prefix-p (car e) file)) order)))

(defun %package-layer (package order)
  "The load position of the module that owns PACKAGE: bitcoin-lisp.NAME and
bitcoin-lisp.NAME.sub belong to src/NAME/. The top package BITCOIN-LISP is
placed at src/package.lisp, the last of the package files and still before
any code -- its files span the whole load (logging.lisp is first, node.lisp
last), so a reference INTO it is never counted as upward. That is a blind
spot this test accepts, not a claim."
  (if (string= package "bitcoin-lisp")
      (cdr (assoc "src/package.lisp" order :test #'string=))
      (let* ((start (length "bitcoin-lisp."))
             (module (subseq package start (position #\. package :start start))))
        (cdr (assoc (format nil "src/~A/" module) order :test #'string=)))))

(defun %resolve-package-prefix (token)
  "The project package TOKEN names as a prefix: a full bitcoin-lisp* name, or
one of the local nicknames in bitcoin-lisp.nicknames:*package-nicknames*; NIL for
anything else (keywords, other packages)."
  (if (uiop:string-prefix-p "bitcoin-lisp" token)
      token
      (let ((full (cdr (assoc token bitcoin-lisp.nicknames:*package-nicknames*
                              :test #'string-equal))))
        (and full (string-downcase full)))))

(defun %package-references (lines)
  "The project packages LINES name with an explicit prefix -- a full name or
a local nickname, followed by a colon, outside a ; comment. A prefix quoted in
a docstring still counts; the sources do not do that."
  (let ((found '()))
    (flet ((name-char-p (c) (or (alphanumericp c) (find c ".-"))))
      (loop for raw across lines
            for line = (string-downcase (subseq raw 0 (position #\; raw)))
            do (loop for colon = (position #\: line)
                       then (position #\: line :start (1+ colon))
                     while colon
                     do (let ((start (position-if-not #'name-char-p line
                                                      :end colon :from-end t)))
                          ;; the token is the name chars before this colon;
                          ;; the second colon of :: has none and is skipped
                          (let* ((token (subseq line (if start (1+ start) 0) colon))
                                 (package (and (plusp (length token))
                                               (%resolve-package-prefix token))))
                            (when package
                              (pushnew package found :test #'string=)))))))
    (sort found #'string<)))

(defparameter +layering-violation-baseline+
  '(("src/coalton/crypto.lisp" . "bitcoin-lisp.crypto")
    ("src/coalton/interop.lisp" . "bitcoin-lisp.crypto")
    ("src/coalton/interop.lisp" . "bitcoin-lisp.serialization")
    ("src/coalton/interop.lisp" . "bitcoin-lisp.storage")
    ("src/config.lisp" . "bitcoin-lisp.crypto")
    ("src/config.lisp" . "bitcoin-lisp.mempool")
    ("src/config.lisp" . "bitcoin-lisp.mining")
    ("src/config.lisp" . "bitcoin-lisp.networking")
    ("src/config.lisp" . "bitcoin-lisp.serialization")
    ("src/config.lisp" . "bitcoin-lisp.storage")
    ("src/config.lisp" . "bitcoin-lisp.validation")
    ("src/validation/block.lisp" . "bitcoin-lisp.mempool")
    ("src/validation/packages.lisp" . "bitcoin-lisp.mempool")
    ("src/validation/transaction.lisp" . "bitcoin-lisp.mempool")
    ("src/zmq.lisp" . "bitcoin-lisp.serialization"))
  "(file . package) pairs where a file names a package whose module loads
LATER, at the start of the cleanup. They compile because src/package.lisp
defines every package up front, so the reader interns the symbol and the call
resolves at run time -- which is exactly why nothing has ever flagged them.
This is also the plan's \"which file reaches which package\" table (§4 P4):
config.lisp loads second and names seven later packages.")

(defun %layering-violations ()
  (let ((order (%load-order)))
    (loop for (file . lines) in (%source-corpus)
          for layer = (%file-layer file order)
          when layer
            append (loop for package in (%package-references lines)
                         for package-layer = (%package-layer package order)
                         when (and package-layer (> package-layer layer))
                           collect (cons file package)))))

(test no-new-layering-violations
  "A file may name its own package and the ones loaded before it. Naming a
later one works only because src/package.lisp defines every package up front;
the plan's phase 4 splits the tree into ASDF systems, at which point each of
these becomes a compile error. Pinned so the list only shrinks until then."
  (%check-pinned-set (%layering-violations) +layering-violation-baseline+
                     "+LAYERING-VIOLATION-BASELINE+"
                     "pass the value in, or move the code down" :test #'equal))

(defparameter +chain-dispatch-ceiling+ 1
  "How many (ecase network ...) / (case network ...) forms whose branches name
a chain (:mainnet, :testnet4, ...) may exist outside src/util/chainparams.lisp.
One since P2a: rpc-getnetworkinfo's \"networks\" entry, which prints a chain
name where Core lists network TYPES (ipv4, onion, ...) -- a divergence for the
RPC work to fix, not a parameter to add to the table. Everything else reads
the table, and a new per-chain fact is a new field there, not a new dispatch.")

(defun %chain-dispatch-forms ()
  "(file . line) of every case/ecase over a network variable whose next lines
mention a chain keyword, outside the chain-params table itself."
  (let ((found '()))
    (loop for (file . lines) in (%source-corpus)
          unless (string= file "src/util/chainparams.lisp")
            do (loop for line across lines
                     for i from 0
                     when (and (search "case network" line)
                               (or (search "(ecase" line) (search "(case" line))
                               (loop for j from i below (min (length lines) (+ i 8))
                                     thereis (or (search ":mainnet" (aref lines j))
                                                 (search ":testnet4" (aref lines j))
                                                 (search ":regtest" (aref lines j)))))
                       do (push (cons file (1+ i)) found)))
    (nreverse found)))

(test no-chain-dispatch-outside-chainparams
  "Per-chain facts live in one table. A CASE over the network keyword whose
branches name chains is the shape this test retires -- there were 29 of them
in 8 files before src/util/chainparams.lisp."
  (let ((forms (%chain-dispatch-forms)))
    (is (<= (length forms) +chain-dispatch-ceiling+)
        "~D chain dispatch form~:P outside the table: ~S -- add a field to ~
chain-params instead" (length forms) forms)))

(test refactoring-ratchets-can-actually-fail
  "Positive controls: each scanner must find something on the real tree, and
the measuring functions must measure a known shape correctly."
  (is (plusp (length (%toplevel-definitions))) "no definitions scanned")
  (is (plusp (length (%definitions-longer-than +longish-function-lines+)))
      "no long definitions found -- a sweep that finds nothing proves nothing")
  (is (plusp (length (%layering-violations))) "no upward references found")
  (is (equal '(("probe.lisp" . 2))
             (let ((*source-corpus* (list (cons "probe.lisp"
                                                (vector "(defun f (network)"
                                                        "  (ecase network"
                                                        "    (:mainnet 1)"
                                                        "    (:regtest 2)))")))))
               (%chain-dispatch-forms)))
      "a case over the network keyword with chain branches must be found")
  (is (string= "(setf node-chain-state)"
               (%definition-name "(defun (setf node-chain-state) (value node)" "(defun "))
      "a setf function name must be kept whole")
  (is (string= "foo" (%definition-name "(defun foo (a b)" "(defun ")))
  (is (string= "bar" (%definition-name "(defmacro bar(x)" "(defmacro ")))
  (is (= 5 (%form-line-count
            (format nil "(defun f ()~%  \"doc with a line that starts like a form:~%~
(values a b) and a paren char #\\( and a semicolon ; here\"~%  ~
(list #\\) #| ) |# 1)~%  ) ; trailing comment~%(defun g () 2)")
            0))
      "strings, comments and char literals must not open or close a form")
  (is (equal '("bitcoin-lisp" "bitcoin-lisp.mempool" "bitcoin-lisp.storage")
             (%package-references
              (vector ";; bitcoin-lisp.validation in a comment does not count"
                      "(bitcoin-lisp.storage:current-height x) ; nor bitcoin-lisp.rpc:here"
                      "(bl.mp::internal bl::*node* :keyword #:uninterned other:pkg)")))
      "a package prefix counts, full name or nickname; a comment, a keyword ~
and a foreign package do not")
  (is (every (lambda (entry)
               (find-package (cdr entry)))
             bitcoin-lisp.nicknames:*package-nicknames*)
      "every nickname in the table must name a package that exists")
  (is (eq (find-package :bitcoin-lisp.serialization)
          (cdr (assoc "bl.ser" (sb-ext:package-local-nicknames :bitcoin-lisp.storage)
                      :test #'string-equal)))
      "the nicknames must actually be installed on the packages")
  (let ((order (%load-order)))
    (is (< (%package-layer "bitcoin-lisp.crypto" order)
           (%package-layer "bitcoin-lisp.storage" order)))
    (is (= (%package-layer "bitcoin-lisp.coalton.interop" order)
           (%file-layer "src/coalton/interop.lisp" order)))))
