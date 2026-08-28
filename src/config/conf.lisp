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

(defun parse-bitcoin-conf-sections (text &optional network)
  "Parse bitcoin.conf TEXT into (values section-entries global-entries
section-json global-json). The first two are in-order alists of
 (lower-case-key . value-string); the last two are the same keys paired with
the JSON rendering Core would have stored, for LogArgs.

GLOBAL-ENTRIES are the keys before any [section]; SECTION-ENTRIES are the keys
in the [section] matching NETWORK (all sections when NETWORK is NIL). Core keeps
the same split — it prefixes section keys and stores them under
`ro_config[section][name]` (config.cpp:48-65) — because the two are consulted in
a definite order, not merged blindly. See PARSE-BITCOIN-CONF.

Signals CONFIG-PARSE-ERROR on the three lines Core refuses:
a leading `-`, a non-empty line with no `=`, and `#` inside an rpcpassword."
  (let ((sections nil)
        (globals nil)
        ;; The same cells again, but carrying the JSON rendering Core stored
        ;; rather than the string the config layer wants. They differ exactly
        ;; where a negation happened — `nolisten=1` is the string "0" to an
        ;; option reader and `false` in a `Config file arg:` line — and the log
        ;; wording is a contract Core's functional tests read back.
        (sections-json nil)
        (globals-json nil)
        (in-section nil)
        (active t)
        (want (and network (conf-section-name network)))
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
                      (let ((sec (string-downcase
                                  (string-trim '(#\Space)
                                               (subseq line 1 (1- (length line)))))))
                        (setf in-section t
                              active (or (null want) (string= sec want)))))
                     ((char= (char line 0) #\-)
                      (error 'config-parse-error
                             :message (format nil "parse error on line ~D: ~A, options in ~
                                                   configuration file must be specified ~
                                                   without leading -" linenr line)))
                     (t
                      (let ((eq-pos (position #\= line)))
                        (unless eq-pos
                          (error 'config-parse-error
                                 :message
                                 (format nil "parse error on line ~D: ~A~@[~A~]" linenr line
                                         (when (and (>= (length line) 2)
                                                    (string= "no" (subseq line 0 2)))
                                           (format nil ", if you intended to specify a ~
                                                        negated option, use ~A=1 instead"
                                                   line)))))
                        ;; Core runs InterpretKey/InterpretValue over
                        ;; config-file keys exactly as over command-line ones
                        ;; (common/config.cpp:63 calls InterpretKey), so this is
                        ;; the same INTERPRET-ARG the command line uses. Without
                        ;; it, `nolisten=1` in bitcoin.conf set an option called
                        ;; "nolisten" that nothing reads, so the file could not
                        ;; negate anything at all.
                        (multiple-value-bind (key value json)
                            (interpret-arg
                             (string-downcase
                              (string-trim '(#\Space #\Tab) (subseq line 0 eq-pos)))
                             (string-trim '(#\Space #\Tab) (subseq line (1+ eq-pos))))
                          (when (and used-hash (search "rpcpassword" key))
                            (error 'config-parse-error
                                   :message
                                   (format nil "parse error on line ~D, using # in ~
                                                rpcpassword can be ambiguous and should ~
                                                be avoided" linenr)))
                          (when active
                            (if in-section
                                (progn (push (cons key value) sections)
                                       (push (cons key json) sections-json))
                                (progn (push (cons key value) globals)
                                       (push (cons key json) globals-json))))))))))))
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

(defun resolve-network-from-config (alist &optional (default :testnet3))
  "Determine the network from a merged config ALIST. Honors -regtest/-signet/
-testnet4/-testnet flags and -chain=main|test|testnet4|signet|regtest.

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
