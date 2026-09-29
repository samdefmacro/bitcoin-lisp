(in-package #:bitcoin-lisp.tests)

(def-suite :tools-tests
  :description "Core's side tools: bitcoin-util, bitcoin-tx (Core's own
bitcoin-util-test.json corpus, replayed in-process) and bitcoin-wallet"
  :in :bitcoin-lisp-tests)

(in-suite :tools-tests)

;;; --- Core's bitcoin-util-test.json corpus ------------------------------------
;;;
;;; test/functional/data/util/bitcoin-util-test.json is what tool_utils.py
;;; replays against the real executables: for each vector the arguments, an
;;; optional stdin file, the expected stdout file (compared as TEXT -- its
;;; "Output formatting mismatch" arm -- as well as parsed), the exit code and
;;; a substring of stderr. This lane runs the same vectors through
;;; RUN-BITCOIN-TX / RUN-BITCOIN-UTIL in the image; tool_utils.py remains the
;;; end-to-end check of the executable itself.

(defparameter *tool-corpus-dir*
  (asdf:system-relative-pathname "bitcoin-lisp" "refs/bitcoin/test/functional/data/util/"))

(defun %tool-corpus ()
  "The corpus vectors as alists, in file order."
  (let ((yason:*parse-object-as* :alist))
    (with-open-file (in (merge-pathnames "bitcoin-util-test.json" *tool-corpus-dir*))
      (yason:parse in))))

(defun %vector-field (vector name)
  (cdr (assoc name vector :test #'string=)))

(defun %run-tool-vector (vector)
  "Run one corpus VECTOR. Returns (values stdout stderr exit-code)."
  (let* ((input (%vector-field vector "input"))
         (stdin (make-string-input-stream
                 (if input
                     (uiop:read-file-string (merge-pathnames input *tool-corpus-dir*))
                     "")))
         (out (make-string-output-stream))
         (err (make-string-output-stream))
         (args (%vector-field vector "args"))
         (rc (if (string= (%vector-field vector "exec") "./bitcoin-util")
                 (bl.tools:run-bitcoin-util args :out out :err err)
                 (bl.tools:run-bitcoin-tx args :stdin stdin :out out :err err))))
    (values (get-output-stream-string out) (get-output-stream-string err) rc)))

(defun %tool-vector-failure (vector)
  "NIL when VECTOR's run matches tool_utils.py's four checks, else why not."
  (multiple-value-bind (stdout stderr rc) (%run-tool-vector vector)
    (let ((expected-file (%vector-field vector "output_cmp"))
          (want-rc (or (%vector-field vector "return_code") 0))
          (want-error (%vector-field vector "error_txt")))
      (cond
        ((and expected-file
              (string/= stdout (uiop:read-file-string
                                (merge-pathnames expected-file *tool-corpus-dir*))))
         (format nil "stdout differs from ~A:~%~A" expected-file stdout))
        ((/= rc want-rc)
         (format nil "exit code ~D, want ~D; stderr ~S" rc want-rc stderr))
        ((and want-error (not (search want-error stderr)))
         (format nil "stderr ~S does not contain ~S" stderr want-error))
        ((and (not want-error) (plusp (length stderr)))
         (format nil "unexpected stderr ~S" stderr))))))

(test bitcoin-tx-and-util-match-cores-corpus
  "Every vector of Core's bitcoin-util-test.json gives Core's stdout (byte for
byte), exit code and error text (tool_utils.py:35-115)."
  (let ((corpus (%tool-corpus)))
    (is (= 107 (length corpus))
        "the corpus is 107 vectors, not ~D -- refs/bitcoin moved?" (length corpus))
    (let ((failures (loop for vector in corpus
                          for i from 0
                          for why = (%tool-vector-failure vector)
                          when why
                            collect (format nil "[~D] ~A: ~A" i
                                            (%vector-field vector "description") why))))
      (is (null failures) "~D corpus vector~:P fail:~%~{~A~%~}"
          (length failures) failures))))

;;; --- The pieces, each against Core's own spelling ---------------------------

(test univalue-write-breaks-an-empty-array-over-two-lines
  "UniValue::write(4) (univalue_write.cpp): members at four spaces a level,
and an EMPTY array still opens and closes on separate lines -- the shape of a
transaction with no inputs in every -json vector of the corpus."
  (is (string= (format nil "{~%    \"vin\": [~%    ],~%    \"n\": 1~%}")
               (bl.tools:univalue-write '(("vin" . #()) ("n" . 1)) 4)))
  (is (string= "[\"a\\u001fb\",true,null]"
               (bl.tools:univalue-write (list (format nil "a~Cb" (code-char 31)) t nil)))))

(test parse-script-asm-is-cores-parsescript
  "Core ParseScript (core_io.cpp:95-130): numbers are push_int64, 0x words
are raw bytes, opcodes are read with or without OP_."
  (is (equalp #(#x00 #x51 #x4f #x01 #x11 #x75 #x75 #xab #xcd)
              (bl.tools:parse-script-asm "0 1 -1 17 DROP OP_DROP 0xabcd")))
  (is (equalp #(#x05 #xff #xff #xff #xff #x00)
              (bl.tools:parse-script-asm "4294967295")))
  (signals error (bl.tools:parse-script-asm "4294967296"))
  (signals error (bl.tools:parse-script-asm "OP_NOTANOPCODE")))

(test bitcoin-util-grind-meets-the-headers-own-target
  "Core Grind (bitcoin-util.cpp:112-150): the nonce it writes makes the
header's hash meet the header's own nBits, and nothing else changes."
  (let* ((header (make-array 80 :element-type '(unsigned-byte 8) :initial-element 7))
         (out (make-string-output-stream)))
    ;; nBits 0x1f7fffff: a target of about 2^254, so a few tries suffice.
    (replace header #(#xff #xff #x7f #x1f) :start1 72)
    (is (= 0 (bl.tools:run-bitcoin-util (list "grind" (bl.crypto:bytes-to-hex header))
                                        :out out :err (make-broadcast-stream))))
    (let* ((ground (bl.crypto:hex-to-bytes
                    (string-trim '(#\Newline) (get-output-stream-string out))))
           (hash (bl.crypto:hash256 ground)))
      (is (equalp (subseq header 0 76) (subseq ground 0 76)))
      ;; The most significant byte of the hash is at index 31.
      (is (<= (aref hash 31) #x7f)))))

(test tools-are-chosen-by-program-name
  "The executable is a side tool exactly when argv[0]'s file name is one."
  (is (eq #'bl.tools:run-bitcoin-tx (bl.tools:tool-for-program-name "/x/build/bin/bitcoin-tx")))
  (is (eq #'bl.tools:run-bitcoin-util (bl.tools:tool-for-program-name "bitcoin-util.exe")))
  (is (null (bl.tools:tool-for-program-name "/x/build/bin/bitcoind"))))

;;; --- bitcoin-wallet (bitcoin-wallet.cpp, wallettool.cpp, dump.cpp) ---------

(defun %wallet-tool (datadir &rest args)
  "Run bitcoin-wallet over ARGS with -datadir=DATADIR -regtest, as
tool_wallet.py:32-35 does. Returns (values stdout stderr exit-code)."
  (let ((out (make-string-output-stream))
        (err (make-string-output-stream)))
    (let ((rc (bl.tools:run-bitcoin-wallet
               (list* (format nil "-datadir=~A" (namestring datadir)) "-regtest" args)
               :out out :err err)))
      (values (get-output-stream-string out) (get-output-stream-string err) rc))))

(defun %wallet-tool-error (datadir &rest args)
  "The stderr of a bitcoin-wallet run that must fail with exit 1 and no
stdout (tool_wallet.py:37-46), or a description of what happened instead."
  (multiple-value-bind (out err rc) (apply #'%wallet-tool datadir args)
    (if (and (= rc 1) (string= out ""))
        (string-trim '(#\Newline) err)
        (format nil "rc ~D stdout ~S stderr ~S" rc out err))))

(defun %rewrite-dump (from to edit)
  "Copy the dump FROM to TO with EDIT applied to each (key . value) line."
  (with-open-file (in from)
    (with-open-file (out to :direction :output :if-exists :supersede)
      (loop for line = (read-line in nil nil)
            while line
            do (let* ((comma (position #\, line))
                      (row (funcall edit (cons (subseq line 0 comma) (subseq line (1+ comma))))))
                 (when row (format out "~A,~A~%" (car row) (cdr row))))))))

(test bitcoin-wallet-refuses-bad-command-lines
  "The command-line refusals tool_wallet.py:111-120 asserts, in Core's words."
  (with-temp-directory (dir "bl-wallet-tool")
    (is (equal "Error parsing command line arguments: Invalid command 'foo'"
               (%wallet-tool-error dir "foo")))
    (is (equal "Error parsing command line arguments: Invalid command 'help'"
               (%wallet-tool-error dir "help")))
    (is (equal "Error: Additional arguments provided (create). Methods do not take arguments. Please refer to `-help`."
               (%wallet-tool-error dir "info" "create")))
    (is (equal "Error parsing command line arguments: Invalid parameter -foo"
               (%wallet-tool-error dir "-foo")))
    (is (equal "No method provided. Run `bitcoin-wallet -help` for valid methods."
               (%wallet-tool-error dir)))
    (is (equal "Wallet name must be provided when creating a new wallet."
               (%wallet-tool-error dir "create")))
    (is (equal "Error parsing command line arguments: Invalid parameter -descriptors"
               (%wallet-tool-error dir "-descriptors" "-wallet=x" "create")))
    (is (equal "Wallet name cannot be empty" (%wallet-tool-error dir "-wallet=" "create")))
    (is (search "Path does not exist."
                (%wallet-tool-error dir "-wallet=nonexistent.dat" "info")))))

(test bitcoin-wallet-create-info-dump-createfromdump
  "create tops up and reports; info reads the same wallet back; dump writes
Core's record format with its SHA256d checksum; createfromdump rebuilds a
wallet whose own dump is the same records; and each createfromdump refusal
is Core's sentence with no wallet left behind (tool_wallet.py:201-286)."
  (with-temp-directory (dir "bl-wallet-tool")
    (multiple-value-bind (out err rc) (%wallet-tool dir "-wallet=w" "create")
      (is (= 0 rc))
      (is (string= "" err))
      (is (search (format nil "Topping up keypool...~%Wallet info~%===========~%Name: w~%")
                  out))
      (is (search (format nil "Descriptors: yes~%Encrypted: no~%HD (hd seed available): yes~%Keypool Size: 8000~%Transactions: 0~%Address Book: 0~%")
                  out)))
    (multiple-value-bind (out err rc) (%wallet-tool dir "-wallet=w" "info")
      (is (= 0 rc))
      (is (string= "" err))
      (is (search "Keypool Size: 8000" out)))
    (let ((dump (merge-pathnames "w.dump" dir))
          (again (merge-pathnames "rt.dump" dir)))
      (is (equal "No dump file provided. To use dump, -dumpfile=<filename> must be provided."
                 (%wallet-tool-error dir "-wallet=w" "dump")))
      (multiple-value-bind (out err rc)
          (%wallet-tool dir "-wallet=w" (format nil "-dumpfile=~A" (namestring dump)) "dump")
        (is (= 0 rc))
        (is (string= "" err))
        (is (string= (format nil "The dumpfile may contain private keys. To ensure the safety of your Bitcoin, do not share the dumpfile.~%")
                     out)))
      (let ((lines (uiop:read-file-lines dump)))
        (is (equal "BITCOIN_CORE_WALLET_DUMP,1" (first lines)))
        (is (equal "format,leveldb" (second lines)))
        ;; The checksum is SHA256d over every line before it, newline included.
        (is (equal (format nil "checksum,~A"
                           (bl.crypto:bytes-to-hex
                            (bl.crypto:hash256
                             (bl.ser:utf8-string-to-bytes
                              (format nil "~{~A~%~}" (butlast lines))))))
                   (car (last lines)))))
      (is (search "already exists. If you are sure this is what you want"
                  (%wallet-tool-error dir "-wallet=w" (format nil "-dumpfile=~A" (namestring dump)) "dump")))
      ;; The round trip.
      (multiple-value-bind (out err rc)
          (%wallet-tool dir "-wallet=load" (format nil "-dumpfile=~A" (namestring dump)) "createfromdump")
        (is (= 0 rc))
        (is (string= "" err))
        (is (string= "" out)))
      (%wallet-tool dir "-wallet=load" (format nil "-dumpfile=~A" (namestring again)) "dump")
      (is (equal (uiop:read-file-lines dump) (uiop:read-file-lines again)))
      (is (search "Database already exists."
                  (%wallet-tool-error dir "-wallet=load" (format nil "-dumpfile=~A" (namestring dump))
                                      "createfromdump")))
      ;; Each damaged dump is refused and leaves no wallet behind.
      (flet ((damaged (edit want)
               (let ((bad (merge-pathnames "bad.dump" dir)))
                 (%rewrite-dump dump bad edit)
                 (is (search want (%wallet-tool-error dir "-wallet=badload"
                                                      (format nil "-dumpfile=~A" (namestring bad))
                                                      "createfromdump"))
                     "wanted ~S" want)
                 (is (null (uiop:directory-exists-p (merge-pathnames "regtest/wallets/badload/" dir)))))))
        (damaged (lambda (row) (if (string= (car row) "BITCOIN_CORE_WALLET_DUMP")
                                   (cons (car row) "2") row))
                 "Error: Dumpfile version is not supported. This version of bitcoin-wallet only supports version 1 dumpfiles. Got dumpfile with version 2")
        (damaged (lambda (row) (if (string= (car row) "BITCOIN_CORE_WALLET_DUMP")
                                   (cons "not_the_right_magic" "1") row))
                 "Error: Dumpfile identifier record is incorrect. Got \"not_the_right_magic\", expected \"BITCOIN_CORE_WALLET_DUMP\".")
        (damaged (lambda (row) (if (string= (car row) "checksum")
                                   (cons "checksum" (make-string 64 :initial-element #\1)) row))
                 "Error: Dumpfile checksum does not match. Computed ")
        (damaged (lambda (row) (unless (string= (car row) "checksum") row))
                 "Error: Missing checksum")
        (damaged (lambda (row) (if (string= (car row) "checksum")
                                   (cons "checksum" "2222222222") row))
                 "Error: Checksum is not the correct size")))))

;;; --- bitcoin, the wrapper (Core bitcoin.cpp) --------------------------------

(defun %run-bitcoin (&rest args)
  "RUN-BITCOIN as /w/build/bin/bitcoin over ARGS: (values action value stdout
stderr)."
  (let ((out (make-string-output-stream)) (err (make-string-output-stream)))
    (multiple-value-bind (action value)
        (bl.tools:run-bitcoin "/w/build/bin/bitcoin" args :out out :err err)
      (values action value (get-output-stream-string out) (get-output-stream-string err)))))

(test bitcoin-wrapper-maps-commands-to-programs
  "bitcoin.cpp:86-119: each command names the program Core execs, with the
command's arguments after it; `rpc' turns -named on; -M and -m pick the
monolithic or multiprocess binary; anything else is an error in Core's words."
  (flet ((target (&rest args)
           (multiple-value-bind (action value) (apply #'%run-bitcoin args)
             (and (eq action :exec) value))))
    (is (equal '("bitcoind" "-regtest" "-version") (target "node" "-regtest" "-version")))
    (is (equal '("bitcoind") (target "-M" "node")))
    (is (equal '("bitcoin-node") (target "-m" "node")))
    (is (equal '("bitcoind" "-ipcbind=unix") (target "-M" "node" "-ipcbind=unix")))
    ;; Without -m/-M an -ipc* option is what asks for the multiprocess binary.
    (is (equal '("bitcoin-node" "-ipcbind=unix") (target "node" "-ipcbind=unix")))
    (is (equal '("bitcoin-cli" "-named" "-nonamed" "getblockcount")
               (target "rpc" "-nonamed" "getblockcount")))
    (is (equal '("bitcoin-wallet" "info") (target "wallet" "info")))
    (is (equal '("bitcoin-tx" "-create") (target "tx" "-create")))
    (is (equal '("bitcoin-util" "grind") (target "util" "grind")))
    (is (equal '("bitcoin-chainstate") (target "chainstate")))
    (is (equal '("bitcoin-qt") (target "gui")))
    ;; Options after the command belong to the command.
    (is (equal '("bitcoind" "-v" "help") (target "node" "-v" "help"))))
  (multiple-value-bind (action code out err) (%run-bitcoin "frob")
    (is (equal '(:exit 1 "") (list action code out)))
    (is (equal (format nil "Error: Unrecognized command: 'frob'~%Try '/w/build/bin/bitcoin --help' for more information.~%")
               err)))
  (multiple-value-bind (action code out err) (%run-bitcoin "--frob" "node")
    (declare (ignore out))
    (is (equal '(:exit 1) (list action code)))
    (is (search "Error: Unknown option: --frob" err))))

(test bitcoin-wrapper-help-and-version
  "No command prints the usage and the short hint and fails; help, -h and
--help print the usage and the full list and succeed; -v prints the version
line and the license (bitcoin.cpp:66-85)."
  (multiple-value-bind (action code out err) (%run-bitcoin)
    (is (equal '(:exit 1 "") (list action code err)))
    (is (eql 0 (search "Usage: bitcoin [OPTIONS] COMMAND..." out)))
    (is (search "Run 'bitcoin help' to see additional commands" out))
    (is (null (search "Additional less commonly used commands" out))))
  (dolist (spelling '("help" "-h" "--help"))
    (multiple-value-bind (action code out) (%run-bitcoin spelling)
      (is (equal '(:exit 0) (list action code)))
      (is (search "Additional less commonly used commands:" out))
      (is (search "  chainstate [ARGS] Run bitcoin kernel chainstate util" out))))
  (multiple-value-bind (action code out) (%run-bitcoin "--version")
    (is (equal '(:exit 0) (list action code)))
    (is (eql 0 (search (format nil "bitcoin-lisp version ~A~%" (bl.tools:format-full-version))
                       out)))
    ;; FormatParagraph: no license line is wider than 79 columns.
    (is (every (lambda (line) (<= (length line) 79))
               (uiop:split-string out :separator '(#\Newline))))))

(test bitcoin-wrapper-reads-ipc-options-from-the-config
  "UseMultiprocess (bitcoin.cpp:163-184) reads the command's config file:
an -ipcbind in the default section or in the chosen chain's section picks
bitcoin-node, one in another chain's section does not."
  (with-temp-directory (dir "bl-bitcoin-wrapper")
    (flet ((node-program (conf &rest args)
             (with-open-file (s (merge-pathnames "bitcoin.conf" dir)
                                :direction :output :if-exists :supersede)
               (write-string conf s))
             (multiple-value-bind (action value)
                 (apply #'%run-bitcoin "node"
                        (format nil "-datadir=~A" (namestring dir)) args)
               (and (eq action :exec) (first value)))))
      (is (equal "bitcoind" (node-program (format nil "server=1~%"))))
      (is (equal "bitcoin-node" (node-program (format nil "ipcbind=unix~%"))))
      (is (equal "bitcoin-node" (node-program (format nil "[regtest]~%ipcbind=unix~%") "-regtest")))
      (is (equal "bitcoind" (node-program (format nil "[regtest]~%ipcbind=unix~%"))))
      (is (equal "bitcoind" (node-program (format nil "ipcbind=unix~%") "-noconf"))))))

(test bitcoin-wrapper-execs-what-this-image-is-not
  "ExecCommand (bitcoin.cpp:198-243): a program this image is comes back as
the argument vector to carry on with, named beside the wrapper; any other is
exec'd along Core's search path, and a missing one is Core's execvp error."
  (is (equal '("/nonexistent/bin/bitcoind" "-regtest")
             (bl.tools:bitcoin-exec '("bitcoind" "-regtest") "/nonexistent/bin/bitcoin")))
  (is (equal '("bitcoin-cli" "-named" "x")
             (bl.tools:bitcoin-exec '("bitcoin-cli" "-named" "x") "bitcoin-no-such-name")))
  (let ((e (handler-case (bl.tools:bitcoin-exec '("bitcoin-qt") "/nonexistent/bin/bitcoin")
             (bl.tools:bitcoin-wrapper-error (e) e))))
    (is (typep e 'bl.tools:bitcoin-wrapper-error))
    (is (equal "execvp failed to execute '/nonexistent/bin/bitcoin-qt': No such file or directory"
               (princ-to-string e)))))

(test bitcoind-refuses-ipcbind-and-accepts-the-help-spellings
  "A monolithic bitcoind never registers -ipcbind (init.cpp:721-723), so it
is an invalid parameter (tool_bitcoin.py:71); -h and -? are SetupHelpOptions'
hidden spellings of -help (common/args.cpp:722-726)."
  (let ((e (handler-case (bl:check-cli-args '("-ipcbind=unix" "-version"))
             (bl.cfg:cli-parse-error (e) e))))
    (is (equal "Error parsing command line arguments: Invalid parameter -ipcbind=unix"
               (and e (princ-to-string e)))))
  (finishes (bl:check-cli-args '("-h")))
  (finishes (bl:check-cli-args '("-?"))))

(test every-program-prints-the-one-license-text
  "Core has ONE LicenseInfo, and every program prints FormatParagraph of it
after its -version line (bitcoind.cpp:146-147, bitcoin-cli.cpp:152-155,
bitcoin-util.cpp:58, bitcoin-tx.cpp:113, bitcoin.cpp:69). bitcoin-cli printed
a copyright line of its own, unwrapped."
  (let ((license (bl.cfg:format-paragraph (bl.cfg:license-info))))
    (is (every (lambda (line) (<= (length line) 79))
               (uiop:split-string license :separator '(#\Newline))))
    (is (search license (nth-value 0 (bl.cli:run-cli '("-version")))))
    (is (search license (nth-value 2 (%run-bitcoin "--version"))))
    (let ((out (make-string-output-stream)))
      (bl.tools:run-bitcoin-util '("-version") :out out :err (make-broadcast-stream))
      (is (search license (get-output-stream-string out))))))

(test bitcoind-reads-its-config-before-help-and-version
  "bitcoind's ParseArgs runs InitConfig -- the -datadir check, the config file,
the chain selection -- before -help and -version are looked at
(bitcoind.cpp:111-127, :283-285): `bitcoind -datadir=<missing> -version' is
Core's datadir error, not a version banner. NODE-MAIN asks
%READ-INIT-CONFIG for exactly that before its -version branch."
  (with-temp-directory (dir "bl-init-config")
    (let ((missing (namestring (merge-pathnames "nope/" dir))))
      (is (search "does not exist"
                  (handler-case
                      (progn (bl::%read-init-config (list (format nil "-datadir=~A" missing)
                                                          "-version"))
                             "no error")
                    (error (e) (princ-to-string e)))))
      ;; Control: an existing datadir reads.
      (is (getf (bl::%read-init-config (list (format nil "-datadir=~A" (namestring dir))
                                             "-regtest" "-version"))
                :cli)))))
