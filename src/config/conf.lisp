(in-package #:bitcoin-lisp.config)

;;;; bitcoin.conf (Core ArgsManager::ReadConfigStream, common/config.cpp)
;;;
;;; The file's sections, includes and comment rules, and the network the
;;; file and the command line together select.

(define-condition config-parse-error (config-error)
  ((message :initarg :message :reader config-parse-error-message))
  (:report (lambda (c stream) (write-string (config-parse-error-message c) stream)))
  (:documentation
   "A bitcoin.conf line Core refuses to parse. Core returns false from
GetConfigOptions with an `error` string and the node does not start; a config
this malformed silently half-applying is how an operator ends up running
settings they did not write."))

(defun config-file-read-error (format-string &rest args)
  "Signal one of the failures Core's ArgsManager::ReadConfigFiles returns
 (common/config.cpp:130-215), carrying the prefix its only caller puts on it.

Core keeps the sentence and the prefix apart -- ReadConfigFiles returns the
sentence in `error', and common/init.cpp:39 reports it as `Error reading
configuration file: %s' -- but the two never travel apart, so the prefix belongs
to every one of these messages. It is the half that says the node could not get
past its CONFIG FILE rather than past something else, and Core's framework
compares the whole of stderr against it: feature_includeconf.py:70 and
feature_config_args.py:52,62,80,555,559 all name the prefix.

The steps AROUND the config read keep their own wording: the chain selectors'
`Invalid combination ...' (SelectParams) and the ignored-conf refusal
(common/init.cpp:65-95) are reported without it."
  (error 'config-parse-error
         :message (format nil "Error reading configuration file: ~?"
                          format-string args)))

(defun %conf-strip-comment (line)
  "Cut LINE at its first #, as Core does (config.cpp:41-44). Returns
 (values text used-hash-p).

Core strips a # ANYWHERE in the line, not only at the start. We stripped only
whole-line comments, so `datadir=/srv/btc  # mainnet` produced a datadir whose
literal name contained the comment — and, since a missing datadir was created
rather than refused, a silent resync from genesis into a junk directory."
  (let ((pos (position #\# line)))
    (if pos
        (values (subseq line 0 pos) t)
        (values line nil))))

(defun conf-settings-rows (text)
  "Parse bitcoin.conf TEXT into settings ROWS — (section name string-value
json), in file order. SECTION is \"\" for the default section, i.e. the area
before any [section] header.

Core prefixes EVERY line with the current header (`prefix = section + '.'`,
config.cpp:47-56) and then runs the result through InterpretKey
(config.cpp:99), which splits the key at its FIRST dot. So the section of a
line is not decided by the header alone: `main.rpcport=8332` written anywhere
in the file — with no header at all — is a [main] setting, the spelling
doc/bitcoin-conf.md:44-46 documents and argsman_tests.cpp:788 exercises. We used
to hand the whole `main.rpcport` to the option lookup, fail it, and drop the
line with an `Ignoring unknown configuration value` warning. A dotted key
written INSIDE a section keeps the header as its section and the whole rest of
the key as its name, which is then unknown — in Core too, for the same reason.

STRING-VALUE is what the option readers consume; JSON is the value Core stored,
which is what the `Config file arg:` lines print. They differ exactly where a
negation happened — `nolisten=1` is the string \"0\" to an option reader and
`false` in a log line — and the log wording is a contract Core's functional
tests read back.

Signals CONFIG-PARSE-ERROR on the three lines Core refuses:
a leading `-`, a non-empty line with no `=`, and `#` inside an rpcpassword;
and, once every line has parsed, on a `conf' key (IsConfSupported)."
  (let ((rows nil)
        (prefix "")
        (linenr 0))
    (with-input-from-string (in text)
      (loop for raw = (read-line in nil nil)
            while raw
            do (incf linenr)
               (multiple-value-bind (body used-hash) (%conf-strip-comment raw)
                 (let ((line (string-trim '(#\Space #\Tab #\Return) body)))
                   (cond
                     ((zerop (length line)))
                     ((and (char= (char line 0) #\[)
                           (char= (char line (1- (length line))) #\]))
                      (setf prefix
                            (concatenate 'string
                                         (string-downcase
                                          (string-trim '(#\Space)
                                                       (subseq line 1 (1- (length line)))))
                                         ".")))
                     ((char= (char line 0) #\-)
                      (config-file-read-error
                       "parse error on line ~D: ~A, options in configuration file ~
must be specified without leading -" linenr line))
                     (t
                      (let ((eq-pos (position #\= line)))
                        (unless eq-pos
                          (config-file-read-error
                           "parse error on line ~D: ~A~@[~A~]" linenr line
                           (when (and (>= (length line) 2)
                                      (string= "no" (subseq line 0 2)))
                             (format nil ", if you intended to specify a negated ~
option, use ~A=1 instead" line))))
                        ;; Core runs InterpretKey/InterpretValue over
                        ;; config-file keys exactly as over command-line ones
                        ;; (common/config.cpp:99 calls InterpretKey), so this is
                        ;; the same INTERPRET-ARG the command line uses. Without
                        ;; it, `nolisten=1` in bitcoin.conf set an option called
                        ;; "nolisten" that nothing reads, so the file could not
                        ;; negate anything at all.
                        (multiple-value-bind (key value json section)
                            (interpret-arg
                             (concatenate 'string prefix
                                          (string-downcase
                                           (string-trim '(#\Space #\Tab)
                                                        (subseq line 0 eq-pos))))
                             (string-trim '(#\Space #\Tab) (subseq line (1+ eq-pos))))
                          (when (and used-hash (search "rpcpassword" key))
                            (config-file-read-error
                             "parse error on line ~D, using # in rpcpassword can be ~
ambiguous and should be avoided" linenr))
                          (push (list section key value json) rows)))))))))
    ;; IsConfSupported (common/config.cpp:79-83), which ReadConfigStream runs
    ;; over every option once the whole file has parsed (:96-103): `conf'
    ;; cannot be set from a config file, in any section or negated -- it
    ;; would name the very file being read.
    (when (find "conf" rows :key #'second :test #'string=)
      (config-file-read-error "conf cannot be set in the configuration file; use ~
includeconf= if you want to include additional config files"))
    ;; The same function's other arm (:84-89): `reindex' is allowed but
    ;; warned about, since the node would reindex on every start. Deferred,
    ;; as debug.log is not open yet; identical lines from repeated parses of
    ;; the same text are emitted once.
    (when (find "reindex" rows :key #'second :test #'string=)
      (bl.log:defer-log :warn "reindex=1 is set in the configuration file, which will ~
significantly slow down startup. Consider removing or commenting out this option for ~
better performance, unless there is currently a condition which makes rebuilding the ~
indexes necessary"))
    (nreverse rows)))

(defparameter +recognized-conf-sections+
  '("regtest" "signet" "test" "testnet4" "main")
  "The section names Core's GetUnrecognizedSections accepts
(common/args.cpp:157-163): ChainTypeToString of each chain, compared exactly.")

(defun conf-unrecognized-sections (text filepath)
  "The sections TEXT names that Core does not recognize, as
 (name filepath line) lists in file order -- Core's m_config_sections, filled
by GetConfigOptions (common/config.cpp:48-66) and filtered by
GetUnrecognizedSections (common/args.cpp:154-169). A section appears in two
ways: a `[name]' header, and a key whose full name -- the current header's
prefix plus the key -- has a dot at or past the end of that prefix, which
makes the part before its LAST dot a section (`testnot.datadir=1' names
`testnot'). FILEPATH is what Core prints: the main file's path, or an
include as it was written. Lines Core refuses are CONF-SETTINGS-ROWS'
business; they name no section here."
  (let ((prefix "") (linenr 0) (found '()))
    (with-input-from-string (in text)
      (loop for raw = (read-line in nil nil)
            while raw
            do (incf linenr)
               (let ((line (string-trim '(#\Space #\Tab #\Return #\Newline)
                                        (%conf-strip-comment raw))))
                 (flet ((note (name) (push (list name filepath linenr) found)))
                   (cond
                     ((zerop (length line)))
                     ((and (char= (char line 0) #\[)
                           (char= (char line (1- (length line))) #\]))
                      (let ((section (subseq line 1 (1- (length line)))))
                        (note section)
                        (setf prefix (concatenate 'string section "."))))
                     ((position #\= line)
                      (let* ((name (concatenate
                                    'string prefix
                                    (string-trim '(#\Space #\Tab #\Return #\Newline)
                                                 (subseq line 0 (position #\= line)))))
                             (dot (position #\. name :from-end t)))
                        (when (and dot (<= (length prefix) dot))
                          (note (subseq name 0 dot))))))))))
    (remove-if (lambda (s) (member (first s) +recognized-conf-sections+
                                   :test #'string=))
               (nreverse found))))

(defun unrecognized-sections-warning (texts filepaths)
  "Core's InitWarning text for the unrecognized sections of TEXTS, read from
FILEPATHS in the same order (init.cpp:958-966): one `<file>:<line> Section
[<name>] is not recognized.' line each, newline-terminated; NIL when there
are none."
  (let ((sections (loop for text in texts
                        for path in filepaths
                        append (conf-unrecognized-sections text path))))
    (when sections
      (with-output-to-string (out)
        (loop for (name file line) in sections
              do (format out "~A:~D Section [~A] is not recognized.~%"
                         file line name))))))

(defun parse-bitcoin-conf-sections (text &optional network)
  "Parse bitcoin.conf TEXT into (values section-entries global-entries
section-json global-json). The first two are in-order alists of
 (lower-case-key . value-string); the last two are the same keys paired with
the JSON rendering Core would have stored, for LogArgs.

GLOBAL-ENTRIES are the default section's keys; SECTION-ENTRIES are the keys of
the section matching NETWORK (all sections when NETWORK is NIL). Which section
a line belongs to is CONF-SETTINGS-ROWS' answer, not the [header] alone. Core
keeps the same split — it stores section keys under `ro_config[section][name]`
(config.cpp:110) — because the two are consulted in a definite order, not
merged blindly. See PARSE-BITCOIN-CONF."
  (let ((want (and network (conf-section-name network)))
        (sections nil) (globals nil) (sections-json nil) (globals-json nil))
    (loop for (section name value json) in (conf-settings-rows text)
          do (cond ((string= section "")
                    (push (cons name value) globals)
                    (push (cons name json) globals-json))
                   ((or (null want) (string= section want))
                    (push (cons name value) sections)
                    (push (cons name json) sections-json))))
    (values (nreverse sections) (nreverse globals)
            (nreverse sections-json) (nreverse globals-json))))

(defun parse-bitcoin-conf (text &optional network)
  "Parse bitcoin.conf TEXT into a single in-order alist, ordered so that ASSOC
gives Core's precedence: the [network] section BEFORE the global area.

That order is the fix for a silent inversion. Core resolves a setting as
`forced > command line > rw settings > config network section > config default
section` (settings.cpp:36), so a `[main] rpcport=8888` beats a global
`rpcport=7777`. We returned keys in file order and let the first ASSOC win,
which made the GLOBAL value beat the section — the reverse of Core, on every
key an operator bothered to scope."
  (multiple-value-bind (sections globals) (parse-bitcoin-conf-sections text network)
    (append sections globals)))

(defun conf-global-entries (text)
  "The global-area entries only. Core reads the chain selectors with
`section=\"\"` (args.cpp:825-829, get_chain_type=true): the network cannot be
chosen from inside a network section, because the section cannot be scoped
until the network is known.

This is what lets a network selected INSIDE bitcoin.conf still scope its own
section. We used to resolve the network from the CLI alone and then parse the
file against it, so `testnet4=1` in the file left us scoping to the DEFAULT
network's section and silently dropping the whole [testnet4] block."
  (nth-value 1 (parse-bitcoin-conf-sections text nil)))

(defun resolve-network-from-config (alist &optional (default :mainnet))
  "Determine the network from a merged config ALIST. Honors -regtest/-signet/
-testnet4/-testnet flags and -chain=main|test|testnet4|signet|regtest. With
no selector at all the chain is MAINNET, as it is in Core (ArgsManager::
GetChainType, args.cpp:851 returns ChainType::MAIN); this node defaulted to
testnet3 until 2026-09-13, so every test in Core's functional suite that
writes a config with no selector (mining_mainnet.py, rpc_validateaddress.py)
started on the wrong chain and refused its own [main] options.

More than one selector is an ERROR, as it is in Core (args.cpp:839-841,
\"Invalid combination of -regtest, -signet, -testnet, -testnet4 and -chain. Can
use at most one.\"). We used to resolve a conflict by a silent priority order,
so `-chain=regtest` on the command line plus a stale `testnet=1` left in
bitcoin.conf started the node on PUBLIC TESTNET3 without saying anything."
  (flet ((flag (k) (let ((c (assoc k alist :test #'string=)))
                     (and c (conf-parse-bool (cdr c)))))
         (val (k) (let ((c (assoc k alist :test #'string=))) (and c (cdr c)))))
    (let ((selectors (count t (list (flag "regtest") (flag "signet")
                                    (flag "testnet4") (flag "testnet")
                                    (and (val "chain") t)))))
      (when (> selectors 1)
        (error 'config-parse-error
               :message (format nil "Invalid combination of -regtest, -signet, ~
                                     -testnet, -testnet4 and -chain. Can use at ~
                                     most one."))))
    (cond
      ((flag "regtest") :regtest)
      ((flag "signet") :signet)
      ((flag "testnet4") :testnet4)
      ((flag "testnet") :testnet3)
      ((val "chain")
       (let ((c (string-downcase (val "chain"))))
         (cond ((member c '("main" "mainnet") :test #'string=) :mainnet)
               ((member c '("test" "testnet" "testnet3") :test #'string=) :testnet3)
               ((string= c "testnet4") :testnet4)
               ((string= c "signet") :signet)
               ((string= c "regtest") :regtest)
               (t (config-error "Unknown -chain value: ~S" c)))))
      (t default))))

(defun unknown-config-file-keys (conf-alist)
  "The keys in CONF-ALIST that no option table recognizes. The caller logs a
warning per key (Core LogWarning \"Ignoring unknown configuration value\")
— unknown config-FILE keys never abort startup."
  (remove-duplicates
   (loop for (k . nil) in conf-alist
         unless (known-config-option-p k)
           collect k)
   :test #'string= :from-end t))

(defun config-arg-log-cells (text network)
  "The (section name json-text) triples Core's `Config file arg:` lines carry.

The JSON comes from the parser, not from re-rendering the string it produced:
a negated key is stored as `false`, and the string the option readers see for
it is \"0\", which would render as the string \"0\" instead."
  (multiple-value-bind (sections globals sections-json globals-json)
      (parse-bitcoin-conf-sections text network)
    (declare (ignore sections globals))
    (append
     (loop for (name . json) in sections-json
           collect (list (conf-section-name network) name json))
     (loop for (name . json) in globals-json
           collect (list "" name json)))))

(defun warn-includeconf-from-included-file (name &optional (stream *error-output*))
  "Core's warning for an -includeconf found INSIDE an included config file:
`warning: -includeconf cannot be used from included files; ignoring
-includeconf=<name>' (common/config.cpp:212).

Core writes it to STDERR, not to the log -- config files are read before
debug.log exists, so the log is not a place an operator can be told. The whole
of a node's stderr is also compared against the expected text at every stop by
Core's framework (test_node.py:502-509), which is how
feature_includeconf.py:59 asserts on this exact sentence; ours logged it
instead, leaving stderr empty and an operator who collects stderr with nothing
at all."
  (format stream
          "warning: -includeconf cannot be used from included files; ~
ignoring -includeconf=~A~%"
          name)
  (finish-output stream))
