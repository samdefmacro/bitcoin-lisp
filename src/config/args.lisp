(in-package #:bitcoin-lisp.config)

;;;; The command line (Core ArgsManager::ParseParameters, common/args.cpp)
;;;
;;; -name, -name=value, -noname and the rules Core applies to them: which
;;; occurrences count, which names are known, which are accepted but not
;;; implemented.

(defun split-option-token (arg)
  "Split one -key / -key=value / --key=value token. Returns (VALUES raw-key
value), where VALUE is NIL when the token carried none and RAW-KEY is
lower-cased and still carries any `no` prefix. NIL raw-key for a bare - or --."
  (let* ((s (string-left-trim "-" arg))
         (eq-pos (position #\= s)))
    (if (zerop (length s))
        (values nil nil)
        (values (string-downcase (if eq-pos (subseq s 0 eq-pos) s))
                (and eq-pos (subseq s (1+ eq-pos)))))))

(defun interpret-arg (raw-key value)
  "Core's InterpretKey + InterpretValue for one option (common/args.cpp:86-126).
Returns (VALUES name string-value json-value).

NAME is RAW-KEY with any `no` prefix stripped. STRING-VALUE is what the option
readers here consume; JSON-VALUE is the JSON Core would have stored, which is
what its `Command-line arg:` / `Config file arg:` lines print — the two differ
exactly on a negation, where the readers want \"0\" and the log wants `false`.

One function for the command line AND the config file, because Core applies the
same two steps to both (config.cpp:63 calls InterpretKey). It used to be written
out three times — twice for the command line, once for the file — and the copies
had already drifted apart on whether the `no` prefix was stripped at all.

Stripping is UNCONDITIONAL, as Core's is. Gating it on the remainder being a
known option looks safer and is not: it makes what a line in bitcoin.conf MEANS
depend on the contents of a lookup table, so adding an option would silently
change the meaning of existing config files. No option in any of this tree's
tables begins with `no`, so the two rules agree today anyway — and where they
would not, Core's is the one whose behaviour is documented."
  (let ((negated (and (> (length raw-key) 2)
                      (string= "no" (subseq raw-key 0 2)))))
    (if negated
        (let ((name (subseq raw-key 2)))
          ;; Double negatives like -nofoo=0 are supported but discouraged
          ;; (args.cpp:114-118), and they mean TRUE.
          (if (and value (not (conf-parse-bool value)))
              (progn
                ;; DEFER-LOG, not LOG-WARN: config parsing runs before the log
                ;; file exists. See FLUSH-DEFERRED-LOG-LINES.
                (bl.log:defer-log :warn "Parsed potentially confusing double-negative -~A=~A"
                  name value)
                (values name "1" "true"))
              (values name "0" "false")))
        ;; A bare -flag is the empty string to Core, and truthy to InterpretBool.
        (values raw-key (or value "1")
                (render-json-value (or value ""))))))

(defun parse-cli-args (args)
  "Parse Bitcoin Core-style CLI ARGS (a list of strings) into an alist of
 (lower-case-key . value-string), in order. Accepts -key=value and
--key=value; a bare -key means key=1 and -nokey means key=0 (Core
InterpretKey/InterpretValue). A repeated non-repeatable key keeps only its
LAST occurrence (see CONFIG-OPTION-REPEATABLE-P), so an assoc lookup
matches Core's command-line GetArg. Non-flag tokens are ignored here;
check-cli-args rejects them up front."
  (let ((out nil))
    (dolist (arg args)
      (when (and (stringp arg) (plusp (length arg)) (char= (char arg 0) #\-))
        (multiple-value-bind (raw-key value) (split-option-token arg)
          (when raw-key                            ; NIL for a bare "-" / "--"
            ;; One interpreter for the command line AND the config file, so
            ;; Core's InterpretKey/InterpretValue rule has a single home.
            (multiple-value-bind (key string-value) (interpret-arg raw-key value)
              (push (cons key string-value) out))))))
    ;; OUT is reversed (last arg first): keep the FIRST cell seen per
    ;; non-repeatable key = the LAST command-line occurrence, then restore
    ;; command-line order.
    (let ((kept nil) (seen (make-hash-table :test 'equal)))
      (dolist (cell out (copy-list kept))
        (let ((key (car cell)))
          (if (config-option-repeatable-p key)
              (push cell kept)
              (unless (gethash key seen)
                (setf (gethash key seen) t)
                (push cell kept))))))))

(defun supplied-core-only-options (alist)
  "The core-only options actually present in ALIST, deduplicated and in order.
The caller warns about each, so accepting them never passes for implementing
them."
  (remove-duplicates
   (loop for (k . nil) in alist
         when (core-only-option-p k) collect (string-downcase k))
   :test #'string= :from-end t))

(defun known-config-option-p (name)
  "T if NAME (lower-case, no dashes) is a recognized config option: any
DEFINE-OPTION row, including the recognised-but-unimplemented Core options
(accepted so an ordinary bitcoind command line starts this node, warned
about at startup so nobody mistakes that for support). check-cli-args uses
this to reject unknown command-line options at startup, like Core
ArgsManager::ParseParameters (common/args.cpp:229-238)."
  (and (or (find-config-option name)
           ;; -nokey negation of a known key parses to key=0 before this
           ;; check, but tolerate the raw \"noKEY\" spelling too.
           (and (> (length name) 2) (string-equal (subseq name 0 2) "no")
                (known-config-option-p (subseq name 2))))
       t))

(define-condition cli-parse-error (config-error)
  ((detail :initarg :detail :reader cli-parse-error-detail))
  (:report (lambda (c stream)
             ;; Core's bitcoind prints the parse failure with this prefix and
             ;; nothing else (bitcoind.cpp: InitError(strprintf("Error parsing
             ;; command line arguments: %s", error))), and its functional tests
             ;; match on the prefix rather than on the detail —
             ;; feature_help.py asserts exactly b'Error parsing command line
             ;; arguments' on stderr for an unknown option.
             (format stream "Error parsing command line arguments: ~A"
                     (cli-parse-error-detail c))))
  (:documentation "A command line Core would refuse to parse."))

(defun check-cli-args (args)
  "Reject unknown command-line options and bare non-option tokens, like
Bitcoin Core (common/args.cpp:211 \"Invalid command\", :229-238 \"Invalid
parameter\" — unknown CLI options are a HARD error; unknown CONFIG-FILE keys
only warn, common/config.cpp:107-115 with ignore_invalid_keys=true from
common/init.cpp:38). Returns ARGS.

Signals CLI-PARSE-ERROR, whose report carries Core's prefix. The detail texts
are Core's own, verbatim, because they are what an operator searches for."
  (flet ((refuse (fmt &rest args)
           (error 'cli-parse-error :detail (apply #'format nil fmt args))))
    (dolist (arg args args)
      (unless (stringp arg)
        (refuse "Invalid command '~A'" arg))
      (if (and (plusp (length arg)) (char= (char arg 0) #\-))
          (let* ((s (string-left-trim "-" arg))
                 (eq-pos (position #\= s))
                 (name (string-downcase (if eq-pos (subseq s 0 eq-pos) s))))
            ;; -includeconf is a CONFIG-FILE directive only. Core refuses it on
            ;; the command line outright (common/args.cpp; the text is pinned
            ;; by argsman_tests.cpp:205-206), because honouring it there would
            ;; let a command line pull in a file whose own -includeconf pulls
            ;; in another, with no datadir to anchor the recursion.
            ;; -includeconf, through Core's own key/value interpretation.
            ;;
            ;; The refusal fires on a non-empty settings span (args.cpp:247-253)
            ;; and reports the first value as Core's SettingsValue::write()
            ;; renders it — a JSON string is quoted, a JSON bool is not. So the
            ;; three refusable spellings read:
            ;;
            ;;   -includeconf              -> -includeconf=""      (empty string)
            ;;   -includeconf=x.conf       -> -includeconf="x.conf"
            ;;   -noincludeconf=0          -> -includeconf=true    (double negative)
            ;;
            ;; while -noincludeconf and -noincludeconf=1 CLEAR the span and are
            ;; allowed: that is how an operator suppresses includes from the
            ;; command line, and refusing it would break the one CLI spelling
            ;; Core accepts. feature_includeconf.py exercises the double
            ;; negative and the valued form, and the bare form is pinned by
            ;; argsman_tests.cpp:205-206.
            (let* ((negated (and (> (length name) 2) (string= "no" (subseq name 0 2))))
                   (base (if negated (subseq name 2) name))
                   (value (and eq-pos (subseq s (1+ eq-pos)))))
              (when (string= base "includeconf")
                (cond
                  ((not negated)
                   (refuse "-includeconf cannot be used from commandline; -includeconf=\"~A\""
                           (or value "")))
                  ((and value (not (conf-parse-bool value)))
                   (refuse "-includeconf cannot be used from commandline; -includeconf=true")))))
            (unless (or (zerop (length name))          ; bare "-"/"--"
                        (known-config-option-p name))
              (refuse "Invalid parameter ~A" arg)))
          (refuse "Invalid command '~A'" arg)))))

;;; --- Core's LogArgs() ---

(defun cli-arg-log-cells (args)
  "The (name . json-text) pairs Core's `Command-line arg:` lines carry.

Re-walks the raw ARGS rather than reading PARSE-CLI-ARGS' output, because that
output is normalized to \"1\"/\"0\" strings and Core logs the JSON value it
actually stored: a negation is `false`, a bare -flag is `\"\"`, and -flag=x is
the string \"x\". INTERPRET-ARG returns both forms from one reading of the
token, so the log and the option readers cannot disagree about what it meant."
  (let ((out nil))
    (dolist (arg args (nreverse out))
      (when (and (stringp arg) (plusp (length arg)) (char= (char arg 0) #\-))
        (multiple-value-bind (raw-key value) (split-option-token arg)
          (when raw-key
            (multiple-value-bind (key string-value json) (interpret-arg raw-key value)
              (declare (ignore string-value))
              (push (cons key json) out))))))))
