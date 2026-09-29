(in-package #:bitcoin-lisp.tools)

;;;; `bitcoin' (Core src/bitcoin.cpp): the wrapper that turns
;;;; `bitcoin [OPTIONS] COMMAND [ARGS]' into one of the per-tool programs --
;;;; `bitcoin node' is bitcoind, `bitcoin rpc' is `bitcoin-cli -named', and so
;;;; on. Core EXECs the sibling executable (ExecCommand, bitcoin.cpp:198-243).
;;;; Here every tool Core would find is this same image under another name, so
;;;; for those the wrapper hands NODE-MAIN the argument vector the exec would
;;;; have started with and the dispatch on argv[0] carries on in-process: the
;;;; process's output, stderr and exit code are the ones the sibling's would
;;;; be. A program this image is NOT (bitcoin-node, bitcoin-qt, bench_bitcoin,
;;;; ...) goes through Core's own search and execvp, so a build without it
;;;; fails in Core's words.

(defparameter +in-image-programs+
  '("bitcoind" "bitcoin-cli" "bitcoin-tx" "bitcoin-util" "bitcoin-wallet")
  "The programs this executable is when started under their name (NODE-MAIN):
the wrapper runs these in-process instead of exec'ing a sibling.")

(defun bitcoin-wrapper-program-name-p (argv0)
  "T when the process was started as the `bitcoin' wrapper."
  (string= (program-base-name argv0) "bitcoin"))

;;; --- Texts (bitcoin.cpp:22-48) ------------------------------------------

(defparameter +bitcoin-help-usage+
  "Usage: ~A [OPTIONS] COMMAND...

Options:
  -m, --multiprocess     Run multiprocess binaries bitcoin-node, bitcoin-gui.
  -M, --monolithic       Run monolithic binaries bitcoind, bitcoin-qt. (Default behavior)
  -v, --version          Show version information
  -h, --help             Show full help message

Commands:
  gui [ARGS]     Start GUI, equivalent to running 'bitcoin-qt [ARGS]' or 'bitcoin-gui [ARGS]'.
  node [ARGS]    Start node, equivalent to running 'bitcoind [ARGS]' or 'bitcoin-node [ARGS]'.
  rpc [ARGS]     Call RPC method, equivalent to running 'bitcoin-cli -named [ARGS]'.
  wallet [ARGS]  Call wallet command, equivalent to running 'bitcoin-wallet [ARGS]'.
  tx [ARGS]      Manipulate hex-encoded transactions, equivalent to running 'bitcoin-tx [ARGS]'.
  help           Show full help message.
"
  "HELP_USAGE (bitcoin.cpp:22-38), a FORMAT control over the exe name.")

(defparameter +bitcoin-help-full+
  "
Additional less commonly used commands:
  bench [ARGS]      Run bench command, equivalent to running 'bench_bitcoin [ARGS]'.
  chainstate [ARGS] Run bitcoin kernel chainstate util, equivalent to running 'bitcoin-chainstate [ARGS]'.
  test [ARGS]       Run unit tests, equivalent to running 'test_bitcoin [ARGS]'.
  test-gui [ARGS]   Run GUI unit tests, equivalent to running 'test_bitcoin-qt [ARGS]'.
"
  "HELP_FULL (bitcoin.cpp:40-46).")

(defparameter +bitcoin-help-short+
  "
Run '~A help' to see additional commands (e.g. for testing and debugging).
"
  "HELP_SHORT (bitcoin.cpp:48-50), a FORMAT control over the exe name.")

;;; --- The command line (bitcoin.cpp:52-58, 138-161) -----------------------

(define-condition bitcoin-wrapper-error (error)
  ((message :initarg :message :reader bitcoin-wrapper-error-message))
  (:report (lambda (c s) (write-string (bitcoin-wrapper-error-message c) s)))
  (:documentation "A std::runtime_error main() of bitcoin.cpp catches and
reports as `Error: <what>' plus the --help hint."))

(defun %wrapper-error (fmt &rest args)
  (error 'bitcoin-wrapper-error :message (apply #'format nil fmt args)))

(defstruct (bitcoin-command-line (:conc-name bcl-))
  "Core's CommandLine: USE-MULTIPROCESS is :UNSET, T (-m) or NIL (-M)."
  (use-multiprocess :unset)
  (show-version nil)
  (show-help nil)
  (command nil)
  (args '()))

(defun parse-bitcoin-command-line (args)
  "Core ParseCommandLine (bitcoin.cpp:138-161) over ARGS, argv after the
program name. Everything after the first command is the command's own."
  (let ((cmd (make-bitcoin-command-line)) (rest '()))
    (dolist (arg args)
      (cond ((bcl-command cmd) (push arg rest))
            ((member arg '("-m" "--multiprocess") :test #'string=)
             (setf (bcl-use-multiprocess cmd) t))
            ((member arg '("-M" "--monolithic") :test #'string=)
             (setf (bcl-use-multiprocess cmd) nil))
            ((member arg '("-v" "--version") :test #'string=)
             (setf (bcl-show-version cmd) t))
            ((member arg '("-h" "--help" "help") :test #'string=)
             (setf (bcl-show-help cmd) t))
            ((and (plusp (length arg)) (char= (char arg 0) #\-))
             (%wrapper-error "Unknown option: ~A" arg))
            ((plusp (length arg)) (setf (bcl-command cmd) arg))))
    (setf (bcl-args cmd) (nreverse rest))
    cmd))

;;; --- UseMultiprocess (bitcoin.cpp:163-184) -------------------------------

(defparameter +ipc-options+ '("ipcbind" "ipcconnect" "ipcfd")
  "The options only a multiprocess binary processes (bitcoin.cpp:181-183).")

(defun %parse-any-args (args err)
  "ArgsManager::ParseParameters with SetDefaultFlags(ALLOW_ANY)
(common/args.cpp:177-256): every -name is accepted. Returns an alist
name -> T for the names given, in any spelling (negated included, since
IsArgSet counts a negation), plus the values of -datadir / -conf and the
chain selectors as (name . value). A failure is only a warning here, as it is
in Core, and what was parsed before it is kept."
  (let ((seen '()))
    (flet ((fail (fmt &rest fargs)
             (format err "Warning: failed to parse subcommand command line options: ~?~%"
                     fmt fargs)
             (return-from %parse-any-args seen)))
      (dolist (arg args)
        (when (or (string= arg "-") (zerop (length arg)) (char/= (char arg 0) #\-))
          (return))
        (let* ((eq-pos (position #\= arg))
               (key (subseq arg 0 eq-pos))
               (val (if eq-pos (subseq arg (1+ eq-pos)) t)))
          (setf key (subseq key (if (and (> (length key) 1) (char= (char key 1) #\-)) 2 1)))
          ;; InterpretKey: a section prefix is never valid on the command line.
          (when (find #\. key)
            (fail "Invalid parameter ~A" arg))
          (let ((negated (and (>= (length key) 2) (string= "no" key :end2 2))))
            (when negated (setf key (subseq key 2)))
            (when (and (string= key "includeconf") (not negated))
              (fail "-includeconf cannot be used from commandline; -includeconf=~S"
                    (if (stringp val) val "")))
            (push (cons key (cond ((not negated) val)
                                  ((and (stringp val) (not (bl.cfg:conf-parse-bool val))) t)
                                  (t "0")))
                  seen))))
      seen)))

(defun %subcommand-config-rows (cli err)
  "ReadConfigFiles' file half for UseMultiprocess: the rows of the config
file CLI's -datadir / -conf name, or NIL when there is none. A failure is a
warning, as in Core (bitcoin.cpp:176-178). Files an includeconf= names are
not followed: they could only add an -ipc* option, which picks a program
this build does not have either way."
  (flet ((arg (name) (let ((c (assoc name cli :test #'string=)))
                       (and c (stringp (cdr c)) (plusp (length (cdr c))) (cdr c)))))
    (let* ((datadir (uiop:ensure-directory-pathname
                     (or (arg "datadir") (bl.cfg:default-data-directory))))
           (conf-set (arg "conf"))
           (path (and (not (equal (cdr (assoc "conf" cli :test #'string=)) "0"))
                      (merge-pathnames (or conf-set "bitcoin.conf")
                                       (merge-pathnames datadir (uiop:getcwd))))))
      (handler-case
          (cond ((null path) nil)
                ((probe-file path)
                 (bl.cfg:conf-settings-rows (uiop:read-file-string path)))
                (conf-set
                 (%wrapper-error "Error reading configuration file: specified config file \"~A\" could not be opened."
                                 (namestring path))))
        (error (e)
          (format err "Warning: failed to parse subcommand config: ~A~%" e)
          nil)))))

(defun bitcoin-use-multiprocess-p (cmd &optional (err *error-output*))
  "Core UseMultiprocess (bitcoin.cpp:163-184): -m / -M decide; otherwise the
command's own arguments and config file are read with every option allowed,
and an -ipcbind / -ipcconnect / -ipcfd anywhere that applies to the selected
chain picks the multiprocess binary. Signals BITCOIN-WRAPPER-ERROR for a
chain selection Core's GetChainTypeString throws on."
  (unless (eq (bcl-use-multiprocess cmd) :unset)
    (return-from bitcoin-use-multiprocess-p (bcl-use-multiprocess cmd)))
  (let* ((cli (%parse-any-args (bcl-args cmd) err))
         (rows (%subcommand-config-rows cli err))
         (network
           (handler-case
               (bl.cfg:resolve-network-from-config
                (append (loop for (k . v) in cli
                              collect (cons k (if (stringp v) v "1")))
                        (loop for (section name value) in rows
                              when (string= section "") collect (cons name value))))
             (error (e) (%wrapper-error "~A" e))))
         (section (bl.chain:chain-params-core-name (bl.chain:find-chain-params network))))
    ;; IsArgSet: the command line, the chain's section, then the default
    ;; section -- none of the three is NETWORK_ONLY.
    (and (some (lambda (name)
                 (or (assoc name cli :test #'string=)
                     (find-if (lambda (row)
                                (and (member (first row) (list section "") :test #'string=)
                                     (string= (second row) name)))
                              rows)))
               +ipc-options+)
         t)))

;;; --- main() (bitcoin.cpp:62-136) -----------------------------------------

(defun bitcoin-target-argv (cmd &optional (err *error-output*))
  "The program and arguments main() would exec for CMD (bitcoin.cpp:86-119)."
  (let* ((command (bcl-command cmd))
         (head (cond ((string= command "gui")
                      (list (if (bitcoin-use-multiprocess-p cmd err) "bitcoin-gui" "bitcoin-qt")))
                     ((string= command "node")
                      (list (if (bitcoin-use-multiprocess-p cmd err) "bitcoin-node" "bitcoind")))
                     ;; `bitcoin rpc' is a new interface, so -named is on by
                     ;; default; -nonamed after it turns it off (:95-101).
                     ((string= command "rpc") (list "bitcoin-cli" "-named"))
                     ((string= command "wallet") (list "bitcoin-wallet"))
                     ((string= command "tx") (list "bitcoin-tx"))
                     ((string= command "bench") (list "bench_bitcoin"))
                     ((string= command "chainstate") (list "bitcoin-chainstate"))
                     ((string= command "test") (list "test_bitcoin"))
                     ((string= command "test-gui") (list "test_bitcoin-qt"))
                     ((string= command "util") (list "bitcoin-util"))
                     (t (%wrapper-error "Unrecognized command: '~A'" command)))))
    (append head (bcl-args cmd))))

(defun %report-wrapper-error (e argv0 err)
  "main()'s catch (bitcoin.cpp:130-133): the error and where to look, exit 1."
  (format err "Error: ~A~%Try '~A --help' for more information.~%" e argv0)
  1)

(defun run-bitcoin (argv0 args &key (out *standard-output*) (err *error-output*))
  "Core bitcoin.cpp main() up to the exec, for the wrapper started as ARGV0
with ARGS: (VALUES :EXIT code) when it has printed what it prints (version,
help, an error), or (VALUES :EXEC argv) with the program and arguments it
would exec. The usage texts name ARGV0's file name, the error hint ARGV0
itself, as Core's do."
  (handler-case
      (let ((cmd (parse-bitcoin-command-line args))
            (exe-name (file-namestring argv0)))
        (cond
          ((bcl-show-version cmd)
           (format out "~A version ~A~%~A" bl.cfg:+client-name+ (format-full-version)
                   (tool-license-info))
           (values :exit 0))
          ((bcl-show-help cmd)
           (format out +bitcoin-help-usage+ exe-name)
           (write-string +bitcoin-help-full+ out)
           (values :exit 0))
          ((null (bcl-command cmd))
           (format out +bitcoin-help-usage+ exe-name)
           (format out +bitcoin-help-short+ exe-name)
           (values :exit 1))
          (t (values :exec (bitcoin-target-argv cmd err)))))
    (error (e) (values :exit (%report-wrapper-error e argv0 err)))))

;;; --- ExecCommand (bitcoin.cpp:186-243) -----------------------------------

(defconstant +enoent+ 2 "ENOENT, the one errno a candidate may fail with.")

(defun %execvp (file argv)
  "util::ExecVp (util/exec.cpp:21-24): execvp(3) of FILE with ARGV. Returns
only when the exec failed, with errno."
  (finish-output *standard-output*)
  (finish-output *error-output*)
  (let ((vec (sb-alien:make-alien sb-alien:c-string (1+ (length argv)))))
    (loop for arg in argv for i from 0
          do (setf (sb-alien:deref vec i) arg)
          finally (setf (sb-alien:deref vec i) nil))
    (sb-alien:alien-funcall
     (sb-alien:extern-alien "execvp" (function sb-alien:int sb-alien:c-string
                                               (* sb-alien:c-string)))
     file vec)
    (sb-alien:get-errno)))

(defun %exe-path (argv0)
  "util::GetExePath (util/exec.cpp:41-70): ARGV0, or when it names no
directory the first regular file of that name on $PATH."
  (or (and (not (find #\/ argv0))
           (loop for dir in (uiop:split-string (or (uiop:getenv "PATH") "") :separator ":")
                 for candidate = (concatenate 'string dir "/" argv0)
                 when (uiop:file-exists-p candidate) return candidate))
      argv0))

(defun %wrapper-directory (argv0)
  "The directory of the wrapper executable, symlinks resolved as
weakly_canonical resolves them (bitcoin.cpp:216-220), as a string ending in
/, or NIL when it has none."
  (let* ((path (%exe-path argv0))
         (true (or (ignore-errors (probe-file path)) path))
         (name (namestring true))
         (slash (position #\/ name :from-end t)))
    (and slash (subseq name 0 (1+ slash)))))

(defun bitcoin-exec (argv wrapper-argv0)
  "Core ExecCommand (bitcoin.cpp:198-243) for ARGV, whose first element is a
program name: libexec/ beside a bin/ wrapper, then the wrapper's own
directory, then $PATH when the wrapper was itself found on it. A program this
image is (+IN-IMAGE-PROGRAMS+) is not exec'd: the argument vector the exec
would have started is RETURNED, for NODE-MAIN to carry on with. Any other
program is exec'd, so this returns only for the in-image ones; a failed exec
signals BITCOIN-WRAPPER-ERROR in Core's words."
  (let* ((name (first argv))
         (dir (%wrapper-directory wrapper-argv0))
         (fallback-os-search (not (find #\/ wrapper-argv0)))
         (candidates
           (append
            (when (and dir (equal (car (last (pathname-directory dir))) "bin"))
              (list (list (concatenate 'string (subseq dir 0 (- (length dir) 4))
                                       "libexec/" name)
                          t)))
            (when dir (list (list (concatenate 'string dir name) fallback-os-search)))
            (when fallback-os-search (list (list name nil))))))
    (when (member name +in-image-programs+ :test #'string=)
      (return-from bitcoin-exec
        (cons (if dir (concatenate 'string dir name) name) (rest argv))))
    (loop for (path allow-notfound) in candidates
          for errno = (%execvp path (cons path (rest argv)))
          unless (and allow-notfound (= errno +enoent+))
            do (%wrapper-error "execvp failed to execute '~A': ~A"
                               path (sb-int:strerror errno)))))

(defun bitcoin-wrapper-main (argv)
  "NODE-MAIN's first step when the executable was started as `bitcoin'
\(ARGV is the whole of argv): RUN-BITCOIN, then BITCOIN-EXEC. Returns the
argument vector the process carries on as when the target is this image;
otherwise prints, execs or fails, and exits."
  (let ((argv0 (first argv)))
    (multiple-value-bind (action value) (run-bitcoin argv0 (rest argv))
      (let ((code (if (eq action :exit)
                      value
                      (handler-case (return-from bitcoin-wrapper-main
                                      (bitcoin-exec value argv0))
                        (error (e) (%report-wrapper-error e argv0 *error-output*))))))
        (finish-output *standard-output*)
        (finish-output *error-output*)
        (sb-ext:exit :code code :abort t)))))
