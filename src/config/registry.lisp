(in-package #:bitcoin-lisp.config)

;;;; The option registry (Core ArgsManager::AddArg, init.cpp / common/args.cpp)
;;;
;;; The mechanism behind src/config-options.lisp, which registers one
;;; DEFINE-OPTION per option bitcoind accepts. The table answers the
;;; questions config.lisp used to answer from four separate lists that had
;;; drifted apart (two options were in two of them at once): is this name
;;; known at all (CHECK-CLI-ARGS), does every occurrence count
;;; (PARSE-CLI-ARGS, Core GetArgs), which start-node keyword does it feed
;;; and how is the value parsed (CONFIG-ALIST->START-NODE-PLIST), which
;;; process-global special does it set (APPLY-CONFIG-GLOBALS), and is it
;;; accepted-but-unimplemented (SUPPLIED-CORE-ONLY-OPTIONS).
;;;
;;; This file is the first code of the bitcoin-lisp/config sub-system; the
;;; table itself (src/config-options.lisp) loads in the main system, after
;;; every layer, so a row's :APPLY function can name any special or parser
;;; without a forward reference.

(defstruct (config-option (:constructor make-config-option))
  (name "" :type string)
  (key nil :type (or null keyword))        ; start-node keyword of a scalar
  (type nil :type (or null keyword))       ; see PARSE-OPTION-VALUE
  (min nil :type (or null integer))        ; lower bound of an :int
  (collect nil :type (or null keyword))    ; start-node keyword of a list
  (repeatable nil :type boolean)
  (kind :start-node :type keyword)
  (network-only nil :type boolean)         ; Core ArgsManager::NETWORK_ONLY
  (sensitive nil :type boolean)            ; Core ArgsManager::SENSITIVE
  (global nil :type symbol)                ; the special a :global row sets
  (apply nil :type (or null function))     ; the function a :apply row calls
  (core nil :type (or null string)))       ; Core reference, documentation only

(defparameter *config-options* '()
  "Every registered option, in definition order (the order the scalar scan
walks, which is what lets a later alias -- -debuglogfile after -logfile --
win when both are given). src/config-options.lisp resets it before its
rows, so a reload of the table rebuilds the list in file order; the in-place
replacement in REGISTER-CONFIG-OPTION is for a single re-evaluated form.")

(defun register-config-option (option)
  "Add OPTION to *CONFIG-OPTIONS*, replacing an earlier definition of the
same name in place so a warm reload never duplicates a row."
  (let ((cell (member (config-option-name option) *config-options*
                      :key #'config-option-name :test #'string=)))
    (if cell
        (setf (car cell) option)
        (setf *config-options* (append *config-options* (list option))))
    option))

(define-condition option-definition-error (program-error bitcoin-lisp-error)
  ((name :initarg :name :reader option-definition-error-name)
   (detail :initarg :detail :reader option-definition-error-detail))
  (:report (lambda (c stream)
             (format stream "define-option ~A: ~A"
                     (option-definition-error-name c)
                     (option-definition-error-detail c))))
  (:documentation "A DEFINE-OPTION form that contradicts itself, signalled
at macroexpansion time."))

(defmacro define-option (name &key key type min collect repeatable (kind nil kind-p)
                                   network-only sensitive global apply core)
  "Register the option NAME (lower-case, as it appears after the dash).

KEY/TYPE: the start-node keyword and value type of a scalar option, MIN the
lower bound of an :int. COLLECT: the keyword under which every occurrence
is listed (implies REPEATABLE). GLOBAL: the special APPLY-CONFIG-GLOBALS
sets to the parsed value when the option is present; APPLY: a function it
calls instead -- with the parsed value (the raw string when there is no
TYPE) for a scalar option, with the list of every raw value, present or
not, for a repeatable one. KIND defaults to :START-NODE when KEY or COLLECT
is given, :GLOBAL otherwise.

NETWORK-ONLY is Core's ArgsManager::NETWORK_ONLY flag (args.h:113-124): the
option means something different on every chain, so off mainnet its value in
a shared bitcoin.conf's DEFAULT section is ignored and the node refuses to
start. See USE-DEFAULT-SECTION-P and UNSUITABLE-SECTION-ONLY-OPTIONS.

SENSITIVE is Core's ArgsManager::SENSITIVE flag (args.h:126): the VALUE is a
secret, so the startup arg log prints `****` in its place. See
SENSITIVE-CONFIG-OPTION-P."
  (check-type name string)
  (flet ((bad (detail) (error 'option-definition-error :name name :detail detail)))
    (when (and collect (not repeatable)) (bad "a :collect option must be :repeatable"))
    (when (and key (null type)) (bad "a :key option needs a :type"))
    (when (and global apply) (bad ":global and :apply are alternatives"))
    (when (and min (not (eq type :int))) (bad ":min needs :type :int"))
    (when (and repeatable global) (bad "a repeatable option sets its special through :apply"))
    (when (and (or global apply) key) (bad "a :key option is applied by start-node, not here")))
  `(register-config-option
    (make-config-option :name ,name :key ,key :type ,type :min ,min :collect ,collect
                         :repeatable ,(and repeatable t)
                         :kind ,(if kind-p kind (if (or key collect) :start-node :global))
                         :network-only ,(and network-only t)
                         :sensitive ,(and sensitive t)
                         :global ',global
                         :apply ,apply
                         :core ,core)))

(defmacro define-core-only-options (&rest names)
  "Register NAMES as options bitcoind accepts that this node recognises but
does NOT implement. They exist so an unknown-option HARD ERROR does not stop
a node started with an ordinary Core command line -- Core's functional test
framework passes -logtimemicros, -logthreadnames, -logsourcelocations,
-debugexclude and -loglevel to EVERY node it starts (test_node.py:68-108),
and 128 more flags across individual tests. Accepting is not implementing:
SUPPLIED-CORE-ONLY-OPTIONS reports which of these an operator actually
passed so startup can say so out loud."
  `(progn ,@(loop for n in names
                  collect `(define-option ,n :kind :core-only))))

(defun find-config-option (name)
  "The registered option called NAME (lower-case, no dashes), or NIL."
  (find name *config-options* :key #'config-option-name :test #'string=))

(defun config-option-repeatable-p (name)
  "T when every occurrence of NAME is meaningful (Core GetArgs list-options);
all other repeated command-line options collapse to their LAST occurrence
(Core GetArg on the command line takes span.end()[-1], settings.cpp:193 -- a
repeated config-FILE key instead keeps the FIRST, which parse-bitcoin-conf's
in-order alist gives assoc for free)."
  (let ((o (find-config-option name)))
    (and o (config-option-repeatable o))))

(defun sensitive-config-option-p (name)
  "T when NAME's VALUE is a secret -- Core's ArgsManager::SENSITIVE (args.h:126).

Core tags exactly four: -torpassword (init.cpp:602), -rpcauth (:707),
-rpcpassword (:712) and -rpcuser (:716). logArgsPrefix (common/args.cpp:883)
prints `****` in place of the value for those and the value itself for
everything else, which is why -rpcbind and -rpcallowip -- named in
feature_config_args.py's unexpected_msgs -- must NOT be tagged."
  (let ((o (find-config-option name)))
    (and o (config-option-sensitive o))))

(defun core-only-option-p (name)
  "T when NAME is an option bitcoind accepts and we do not implement.

Case-SENSITIVE, like every other lookup here and like Core's own: outside
WIN32, ArgsManager never folds an option name (args.cpp:200-204 lower-cases
the command line only there), so GetArgFlags (:258-268) misses
`-LogSourceLocations` and Core reports `Invalid parameter` for it on the
command line and `Ignoring unknown configuration value` in a file. This
function used to downcase while FIND-CONFIG-OPTION did not, so the two
disagreed about the same name: a settings.json key spelled
`LogSourceLocations` was core-only and unknown at once, and the warning
KNOWN-CONFIG-OPTION-P drives was emitted for a key this predicate claimed to
recognise. The CLI and config-file parsers downcase their keys before either
predicate sees them (SPLIT-OPTION-TOKEN, CONF-SETTINGS-ROWS), which is this
tree's one deviation from that case-sensitivity and is deliberate; the
settings file is the source Core does not downcase either."
  (let ((o (find-config-option name)))
    (and o (eq (config-option-kind o) :core-only))))

(defun scalar-key-options ()
  "The options that feed a start-node keyword from their last occurrence, in
definition order."
  (remove-if-not #'config-option-key *config-options*))

(defun collected-key-options ()
  "The options whose every occurrence is listed under a start-node keyword."
  (remove-if-not #'config-option-collect *config-options*))

(defun global-options ()
  "The options APPLY-CONFIG-GLOBALS applies: every row with a :global
special or an :apply function, in definition order."
  (remove-if-not (lambda (o) (or (config-option-global o) (config-option-apply o)))
                 *config-options*))

;;; Reading a value the table's way, and applying the :GLOBAL rows.

(defun parse-option-value (option raw)
  "RAW, the string value of OPTION, parsed by the option's :TYPE. The error
texts are Core's: \"Invalid amount for -x=v\" for a fee that ParseMoney
rejects, \"Invalid value for -x=v (must be a positive integer)\" for an
:int below its :MIN."
  (let ((name (config-option-name option)))
    (ecase (config-option-type option)
      ((nil :string) raw)
      (:bool (conf-parse-bool raw))
      (:int (let ((n (conf-parse-int raw))
                  (min (config-option-min option)))
              (when (and min (< n min))
                (config-error "Invalid value for -~A=~A (must be a ~A integer)"
                       name raw (if (zerop min) "non-negative" "positive")))
              n))
      (:money (or (conf-parse-money raw)
                  (config-error "Invalid amount for -~A=~A" name raw)))
      (:hex (bl.crypto:hex-to-bytes raw))
      (:byte-units (conf-parse-byte-units raw))
      (:loglevel (conf-parse-loglevel raw))
      (:loglevel-global (conf-parse-loglevel-global raw)))))

(defun apply-option-globals (merged)
  "Apply every :GLOBAL / :APPLY row of the option table to the MERGED config
alist, in table order: a present scalar option sets its special (or is
handed to its function) parsed by PARSE-OPTION-VALUE; a repeatable option's
function always runs, with the list of every raw value."
  (dolist (option (global-options))
    (let ((name (config-option-name option)))
      (if (config-option-repeatable option)
          (funcall (config-option-apply option)
                   (loop for (k . v) in merged when (string= k name) collect v))
          (let ((cell (assoc name merged :test #'string=)))
            (when cell
              (let ((value (parse-option-value option (cdr cell))))
                (if (config-option-global option)
                    (setf (symbol-value (config-option-global option)) value)
                    (funcall (config-option-apply option) value)))))))))
