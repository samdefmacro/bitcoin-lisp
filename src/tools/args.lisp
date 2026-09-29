(in-package #:bitcoin-lisp.tools)

;;;; A side tool's command line: Core's ArgsManager as the three tools use it
;;;; (common/args.cpp:177-256 ParseParameters, :77-100 InterpretKey, :57-62
;;;; InterpretBool, :101-137 InterpretValue, :717-720 HelpRequested), plus the
;;;; chain selection every tool registers through SetupChainParamsBaseOptions
;;;; (chainparamsbase.cpp:17-35).
;;;;
;;;; The node has its own, much larger, option registry (bl.cfg); the tools do
;;;; not share it because Core does not: each tool registers ONLY its own
;;;; handful of options, and every other -name is "Invalid parameter -name"
;;;; (tool_wallet.py:115 passes -foo, :306 -descriptors, :424 -legacy).

(defparameter +chain-options+
  '("chain" "regtest" "signet" "signetchallenge" "signetseednode" "testnet"
    "testnet4" "testactivationheight" "vbparams")
  "The options SetupChainParamsBaseOptions registers (chainparamsbase.cpp:17-35).
Every tool accepts them; only the chain selectors change anything here.")

(defparameter +core-whitespace+
  (list #\Space #\Tab #\Newline #\Return #\Page (code-char 11))
  "Core's TrimString default pattern \" \\f\\n\\r\\t\\v\" (util/string.h).")

(defparameter +help-options+ '("help" "h" "?")
  "SetupHelpOptions (common/args.cpp:722-726): -help and its hidden -h, -?.")

(defstruct (tool-args (:constructor %make-tool-args))
  "A parsed tool command line. OPTIONS is an alist name -> the LAST value
given (a string, T for a bare switch, NIL for a negated one) -- Core keeps
every value, but GetArg / GetBoolArg read the last one. COMMAND is Core's
m_command: the first non-dash argument and everything after it."
  (options '() :type list)
  (command '() :type list))

(defun %interpret-bool (value)
  "Core InterpretBool (common/args.cpp:57-62): the empty string is true,
otherwise LocaleIndependentAtoi != 0."
  (bl.cfg:conf-parse-bool value))

(defun parse-tool-args (argv &key options commands)
  "Core ArgsManager::ParseParameters over ARGV (the arguments AFTER the program
name). OPTIONS are the option names the tool registered (without the dash; the
help and chain options are added here). COMMANDS, when given, are the only
accepted commands (Core's AddCommand turns m_accept_any_command off, so the
first non-dash argument must be one of them).

Returns the TOOL-ARGS, or (values NIL message) with Core's error text, which
every caller prints as \"Error parsing command line arguments: <message>\"."
  (let ((known (append options +help-options+ +chain-options+))
        (settings '()))
    (loop for rest on argv
          for arg = (car rest)
          do (block one
               ;; bitcoin-tx's stdin marker ends option parsing (args.cpp:193).
               (when (string= arg "-") (loop-finish))
               (let* ((eq-pos (position #\= arg))
                      (key (if eq-pos (subseq arg 0 eq-pos) arg))
                      (val (and eq-pos (subseq arg (1+ eq-pos)))))
                 (when (or (zerop (length key)) (char/= (char key 0) #\-))
                   (when (and commands
                              (not (member key commands :test #'string=)))
                     (return-from parse-tool-args
                       (values nil (format nil "Invalid command '~A'" arg))))
                   ;; The command keeps its name only -- Core has already cut
                   ;; `=value' off the key -- and the arguments after it verbatim.
                   (return-from parse-tool-args
                     (%make-tool-args :options settings
                                      :command (cons key (copy-list (cdr rest))))))
                 ;; --foo is -foo; then the dash goes (args.cpp:224-228).
                 (when (and (> (length key) 1) (char= (char key 1) #\-))
                   (setf key (subseq key 1)))
                 (setf key (subseq key 1))
                 ;; InterpretKey: a section prefix is never valid on the
                 ;; command line, and a leading "no" negates.
                 (let ((negated nil))
                   (when (find #\. key)
                     (return-from parse-tool-args
                       (values nil (format nil "Invalid parameter ~A" arg))))
                   (when (and (>= (length key) 2) (string= "no" key :end2 2))
                     (setf key (subseq key 2) negated t))
                   (unless (member key known :test #'string=)
                     (return-from parse-tool-args
                       (values nil (format nil "Invalid parameter ~A" arg))))
                   ;; InterpretValue (args.cpp:101-137): -nofoo is false,
                   ;; -nofoo=0 a double negative that means true.
                   (let ((value (cond ((not negated) (or val t))
                                      ((and val (not (%interpret-bool val))) t)
                                      (t nil))))
                     (setf settings
                           (cons (cons key value)
                                 (remove key settings :key #'car :test #'string=))))
                   (return-from one)))))
    (%make-tool-args :options settings :command '())))

(defun tool-arg-set-p (args name)
  "Core IsArgSet: NAME was given at all, negated or not."
  (and (assoc name (tool-args-options args) :test #'string=) t))

(defun tool-arg (args name &optional default)
  "Core GetArg: NAME's last value as a string, DEFAULT when it was not given.
A bare switch reads as \"\" and a negated one as \"0\", as SettingToString
renders a bool."
  (let ((cell (assoc name (tool-args-options args) :test #'string=)))
    (cond ((null cell) default)
          ((eq (cdr cell) t) "")
          ((null (cdr cell)) "0")
          (t (cdr cell)))))

(defun tool-bool-arg (args name &optional default)
  "Core GetBoolArg: NAME's last value as a boolean, DEFAULT when not given."
  (let ((cell (assoc name (tool-args-options args) :test #'string=)))
    (cond ((null cell) default)
          ((stringp (cdr cell)) (%interpret-bool (cdr cell)))
          (t (cdr cell)))))

(defun tool-help-requested-p (args)
  "Core HelpRequested (common/args.cpp:717-720)."
  (some (lambda (name) (tool-arg-set-p args name)) +help-options+))

(defun tool-args-network (args)
  "Core GetChainType (common/args.cpp:822-857) as this node's network keyword.
Signals BL.CFG:CONFIG-PARSE-ERROR with Core's sentence for more than one
selector or an unknown -chain."
  (bl.cfg:resolve-network-from-config
   (loop for (name . value) in (tool-args-options args)
         when (member name '("chain" "regtest" "signet" "testnet" "testnet4")
                      :test #'string=)
           collect (cons name (cond ((eq value t) "1")
                                    ((null value) "0")
                                    (t value))))))

(defun program-base-name (argv0)
  "ARGV0's file name, with a trailing .exe (Core's EXEEXT) removed."
  (let ((name (file-namestring (or argv0 ""))))
    (if (and (> (length name) 4)
             (string-equal ".exe" name :start2 (- (length name) 4)))
        (subseq name 0 (- (length name) 4))
        name)))

(defun format-full-version ()
  "Core FormatFullVersion (clientversion.cpp:58-62): the build's version,
\"v\" and the dotted client version."
  (concatenate 'string "v" (bl.ser:client-version-string)))

(defun tool-version-banner (tool)
  "The first line every tool prints for -help and -version:
\"<CLIENT_NAME> <tool> utility version <FormatFullVersion>\"."
  (format nil "~A ~A utility version ~A~%"
          bl.cfg:+client-name+ tool (format-full-version)))

(defun format-paragraph (text &key (width 79) (indent 0))
  "Core FormatParagraph (util/strencodings.cpp:202-242): TEXT with every line
longer than WIDTH broken at its last space before the limit (or, failing one,
at the first space after it), continuation lines indented by INDENT."
  (with-output-to-string (out)
    (let ((ptr 0) (indented 0) (size (length text)))
      (loop while (< ptr size)
            do (let* ((lineend (or (position #\Newline text :start ptr) size))
                      (linelen (- lineend ptr))
                      (rem-width (- width indented)))
                 (if (<= linelen rem-width)
                     (progn (write-string text out :start ptr :end (min size (1+ lineend)))
                            (setf ptr (1+ lineend) indented 0))
                     (let ((finalspace
                             (position-if (lambda (c) (member c '(#\Space #\Newline))) text
                                          :end (min size (1+ (+ ptr rem-width))) :from-end t)))
                       (when (or (null finalspace) (< finalspace ptr))
                         (setf finalspace
                               (position-if (lambda (c) (member c '(#\Space #\Newline))) text
                                            :start ptr))
                         (unless finalspace
                           (write-string text out :start ptr)
                           (return)))
                       (write-string text out :start ptr :end finalspace)
                       (terpri out)
                       (cond ((char= (char text finalspace) #\Newline) (setf indented 0))
                             ((plusp indent)
                              (write-string (make-string indent :initial-element #\Space) out)
                              (setf indented indent)))
                       (setf ptr (1+ finalspace)))))))))

(defun tool-license-info ()
  "Core FormatParagraph(LicenseInfo()) (clientversion.cpp:86-103), in this
project's words: what every program prints after its -version line."
  (format-paragraph (%license-info)))

(defun %license-info ()
  "Core LicenseInfo (clientversion.cpp:86-103), in this project's words."
  (format nil "Copyright (C) 2026 samdefmacro~%~%~
Please contribute if you find bitcoin-lisp useful. Visit ~
<https://github.com/samdefmacro/bitcoin-lisp> for further information about ~
the software.~%~%This is experimental software.~%Distributed under the MIT ~
software license, see the accompanying file COPYING or ~
<https://opensource.org/license/MIT>~%"))
