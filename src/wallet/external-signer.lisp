(in-package #:bitcoin-lisp.wallet)

;;;; External signers (Core external_signer.cpp, common/run_command.cpp,
;;;; wallet/external_signer_scriptpubkeyman.cpp, rpc/external_signer.cpp).
;;;;
;;;; -signer=<cmd> names a program speaking HWI's command-line protocol. The
;;;; node never holds the keys: `<cmd> enumerate' lists the connected devices,
;;;; `getdescriptors' hands a new wallet its PUBLIC descriptors,
;;;; `displayaddress' shows an address on the device, and `signtx' (the PSBT
;;;; on stdin) signs. Each call is one process whose first stdout line is a
;;;; JSON document -- RunCommandParseJSON.
;;;;
;;;; Core compiles all of it behind ENABLE_EXTERNAL_SIGNER; this node has it
;;;; always, and scripts/conformance-config.sh says so to the functional
;;;; framework (rpc_signer.py, wallet_signer.py).

(defvar *signer-command* ""
  "-signer (Core init.cpp's `-signer=<cmd>'): the external signing tool, as a
command line split on spaces and tabs. Empty when none was given.")

(define-condition external-signer-error (error)
  ((message :initarg :message :reader external-signer-error-message))
  (:report (lambda (c s) (write-string (external-signer-error-message c) s)))
  (:documentation "A std::runtime_error from the external-signer code, with
Core's text. The RPC handlers turn it into RPC_MISC_ERROR (-1), which is what
Core's generic exception path answers."))

(defun %signer-fail (control &rest args)
  (error 'external-signer-error :message (apply #'format nil control args)))

(defstruct external-signer
  "Core ExternalSigner (external_signer.h): how to run the tool, the chain to
tell it, and which device it found."
  (command '() :type list)
  (chain "" :type string)
  (fingerprint "" :type string)
  (name "" :type string))

(defun %split-command (command)
  "subprocess::util::split(command, \" \\t\"): words, no quoting."
  (remove "" (uiop:split-string command :separator '(#\Space #\Tab)) :test #'string=))

(defun network-chain-type-string (network)
  "Core ChainTypeToString (chaintype.cpp): the name `--chain' carries."
  (bl.chain:chain-params-core-name (bl.chain:find-chain-params network)))

(defun %first-line (text)
  (subseq text 0 (or (position #\Newline text) (length text))))

(defun %parse-signer-json (text)
  "UniValue::read over TEXT: objects as alists, arrays as vectors (so an empty
array is not null), or NIL and a second value of NIL when it is not JSON."
  (handler-case
      (let ((yason:*parse-object-as* :alist)
            (yason:*parse-json-arrays-as-vectors* t)
            (yason:*parse-json-booleans-as-symbols* t))
        (with-input-from-string (in text)
          (let ((value (yason:parse in)))
            (if (peek-char t in nil nil) (values nil nil) (values value t)))))
    (error () (values nil nil))))

(defvar *signer-run-counter* (list 0)
  "Serial number for %RUN-WITH-FILES's temporary names. Together with the pid
it keeps two calls -- in this process or in another node sharing the
temporary directory -- off each other's files; a random suffix would not,
since every process started from the saved image starts from the same
random state.")

(defun %run-with-files (args stdin)
  "Run ARGS (program first, looked up on PATH) with STDIN as its standard
input; (values exit-code stdout stderr).

All three streams go through temporary FILES. Handing SB-EXT:RUN-PROGRAM a
Lisp string stream instead makes it copy through a pipe from a serve-event
handler, and :WAIT returns when the child EXITS, not when that handler has
drained the pipe -- so the output can be cut short and the handler outlive
the call. A file the child writes and we read afterwards has neither
problem."
  (let* ((base (format nil "bl-signer-~D-~D" (sb-posix:getpid)
                      (sb-ext:atomic-incf (car *signer-run-counter*))))
         (dir (uiop:temporary-directory))
         (in (merge-pathnames (format nil "~A.in" base) dir))
         (out (merge-pathnames (format nil "~A.out" base) dir))
         (err (merge-pathnames (format nil "~A.err" base) dir)))
    (unwind-protect
         (progn
           (with-open-file (s in :direction :output :if-exists :supersede
                                 :external-format :utf-8)
             (write-string stdin s))
           (let ((process (handler-case
                              (sb-ext:run-program (first args) (rest args)
                                                  :search t :wait t :input in
                                                  :output out :if-output-exists :supersede
                                                  :error err :if-error-exists :supersede)
                            ;; cpp-subprocess's OSError: the child could not exec.
                            (error (e)
                              (let* ((text (princ-to-string e))
                                     (colon (search ": " text :from-end t)))
                                (%signer-fail "execve failed: ~A"
                                              (if colon (subseq text (+ colon 2)) text)))))))
             (flet ((slurp (path)
                      (or (ignore-errors (uiop:read-file-string path :external-format :utf-8)) "")))
               (values (sb-ext:process-exit-code process) (slurp out) (slurp err)))))
      (dolist (path (list in out err))
        (ignore-errors (delete-file path))))))

(defun run-command-parse-json (args &optional (stdin ""))
  "Core RunCommandParseJSON (common/run_command.cpp:17-47): run ARGS with
STDIN on its standard input, and read the FIRST line of its stdout as JSON. A
non-zero exit is \"RunCommandParseJSON error: process(<cmd>) returned <n>:
<first stderr line>\"; output that is not JSON is \"Unable to parse JSON:
<line>\". The child inherits the node's working directory, which is where
Core's mock signer finds the files a test leaves for it (mocks/signer.py:14)."
  (when (null args) (return-from run-command-parse-json nil))
  (multiple-value-bind (code stdout stderr) (%run-with-files args stdin)
    (let ((result (%first-line stdout)))
      (unless (zerop code)
        ;; Core keeps only the first stderr line in the error; the log keeps
        ;; the rest, which for a Python signer is where the traceback is.
        (bl:log-warn "signer ~{~A~^ ~} exited ~D: ~A" args code
                     (subseq stderr 0 (min 4000 (length stderr))))
        (%signer-fail "RunCommandParseJSON error: process(~{~A~^ ~}) returned ~D: ~A~%"
                      args code (%first-line stderr)))
      (multiple-value-bind (json ok) (%parse-signer-json result)
        (unless ok (%signer-fail "Unable to parse JSON: ~A" result))
        json))))

(defun %json-field (object name)
  (and (listp object) (cdr (assoc name object :test #'string=))))

(defun enumerate-external-signers (command chain)
  "Core ExternalSigner::Enumerate (external_signer.cpp:28-65): `<command>
enumerate', one signer per entry, stopping at the first repeated fingerprint."
  (let ((result (run-command-parse-json
                 (append (%split-command command) (list "enumerate"))))
        (signers '()))
    (unless (vectorp result)
      (%signer-fail "'~A' received invalid response, expected array of signers" command))
    (loop for entry across result
          do (let ((error (%json-field entry "error")))
               (when error
                 (if (stringp error)
                     (%signer-fail "'~A' error: ~A" command error)
                     (%signer-fail "'~A' error" command))))
             (let ((fingerprint (%json-field entry "fingerprint"))
                   (model (%json-field entry "model")))
               (unless fingerprint
                 (%signer-fail "'~A' received invalid response, missing signer fingerprint" command))
               (unless (stringp fingerprint)
                 (%signer-fail "JSON value of type ~A is not of expected type string"
                               (bl.rpc:json-type-name fingerprint)))
               (when (find fingerprint signers :key #'external-signer-fingerprint
                                               :test #'string=)
                 (loop-finish))
               (push (make-external-signer :command (%split-command command)
                                           :chain chain
                                           :fingerprint fingerprint
                                           :name (if (stringp model) model ""))
                     signers)))
    (nreverse signers)))

(defun get-external-signer (network)
  "Core ExternalSignerScriptPubKeyMan::GetExternalSigner
(external_signer_scriptpubkeyman.cpp:48-57): the ONE connected signer, or
EXTERNAL-SIGNER-ERROR saying why not."
  (when (string= *signer-command* "")
    (%signer-fail "restart bitcoind with -signer=<cmd>"))
  (let ((signers (enumerate-external-signers *signer-command*
                                             (network-chain-type-string network))))
    (cond ((null signers) (%signer-fail "No external signers found"))
          ((rest signers)
           (%signer-fail "More than one external signer found. Please connect only one at a time."))
          (t (first signers)))))

(defun %signer-call (signer &rest command)
  "`<cmd> --fingerprint <fp> --chain <chain> COMMAND...' (NetworkArg)."
  (run-command-parse-json
   (append (external-signer-command signer)
           (list "--fingerprint" (external-signer-fingerprint signer)
                 "--chain" (external-signer-chain signer))
           command)))

(defun signer-get-descriptors (signer account)
  "Core ExternalSigner::GetDescriptors (external_signer.cpp:72-75)."
  (%signer-call signer "getdescriptors" "--account" (format nil "~D" account)))

(defun signer-display-address (signer descriptor)
  "Core ExternalSigner::DisplayAddress (external_signer.cpp:67-70)."
  (%signer-call signer "displayaddress" "--desc" descriptor))

;;; --- enumeratesigners (rpc/external_signer.cpp:20-65) ---

(bl.rpc:define-rpc "enumeratesigners" (node params)
  "Returns a list of external signers from -signer (Core enumeratesigners)."
  (declare (ignore params))
  (when (string= *signer-command* "")
    (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-misc-error+
                             :message "Error: restart bitcoind with -signer=<cmd>"))
  (let ((signers (handler-case
                     (enumerate-external-signers
                      *signer-command*
                      (network-chain-type-string (bl.rpc:rpc-get-network node)))
                   (external-signer-error (e)
                     (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-misc-error+
                                              :message (external-signer-error-message e))))))
    `(("signers" . ,(bl.rpc:json-array
                     (mapcar (lambda (s)
                               `(("fingerprint" . ,(external-signer-fingerprint s))
                                 ("name" . ,(external-signer-name s))))
                             signers))))))
