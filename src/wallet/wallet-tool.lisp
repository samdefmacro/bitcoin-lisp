(in-package #:bitcoin-lisp.wallet)

;;;; bitcoin-wallet's wallet half (Core wallet/wallettool.cpp and
;;;; wallet/dump.cpp): info, create, dump and createfromdump on a wallet
;;;; directory, with no node running. The command line is bl.tools'
;;;; (src/tools/bitcoin-wallet.lisp); everything that opens the database is
;;;; here, next to the loader it shares with the node.
;;;;
;;;; DIVERGENCE, and the same one getwalletinfo carries: the database is this
;;;; project's LevelDB directory, not Core's wallet.dat SQLite file
;;;; (docs/wallet-plan.md §7.1), so `Format:' and the dump's `format' record
;;;; say leveldb. The records themselves are Core's -- the DBKeys schema,
;;;; byte for byte (wallet-store.lisp) -- so a dump's lines mean in either
;;;; implementation what they mean in the other, and createfromdump accepts a
;;;; sqlite dump as well as its own.

(defparameter +wallet-tool-dump-magic+ "BITCOIN_CORE_WALLET_DUMP"
  "Core DUMP_MAGIC (dump.cpp:18).")

(defparameter +wallet-tool-dump-version+ 1
  "Core DUMP_VERSION (dump.cpp:19).")

(defparameter +wallet-tool-dump-formats+ '("leveldb" "sqlite")
  "The `format' records createfromdump loads. Core takes sqlite only
(dump.cpp:139-146); the leveldb dump is this build's own, and a sqlite dump
carries the same record schema.")

(defun %active-spkms (wallet)
  "Core GetActiveScriptPubKeyMans: every active SPKM, external or internal,
once each."
  (remove-duplicates
   (append (alexandria:hash-table-values (wallet-external-spkms wallet))
           (alexandria:hash-table-values (wallet-internal-spkms wallet)))))

(defun wallet-key-pool-size (wallet)
  "Core CWallet::GetKeyPoolSize (wallet.cpp:2580-2589): the unused keys of
every active SPKM, range_end - next_index each."
  (loop for spkm in (%active-spkms wallet)
        sum (max 0 (- (desc-spkm-range-end spkm) (desc-spkm-next-index spkm)))))

(defun %wallet-hd-enabled-p (wallet)
  "Core CWallet::IsHDEnabled (wallet.cpp:1702-1711): there is an active SPKM
and every one of them is ranged."
  (let ((active (%active-spkms wallet)))
    (and active
         (every (lambda (spkm) (bl.rpc:out-desc-ranged-p (desc-spkm-desc spkm))) active))))

(defun wallet-tool-info-text (wallet)
  "Core WalletShowInfo (wallettool.cpp:82-95), as the text it prints."
  (format nil "Wallet info~%===========~%Name: ~A~%Format: leveldb~%~
Descriptors: ~:[no~;yes~]~%Encrypted: ~:[no~;yes~]~%HD (hd seed available): ~:[no~;yes~]~%~
Keypool Size: ~D~%Transactions: ~D~%Address Book: ~D~%"
          (wallet-name wallet)
          (wallet-flag-set-p wallet +wallet-flag-descriptors+)
          (wallet-has-encryption-keys-p wallet)
          (%wallet-hd-enabled-p wallet)
          (wallet-key-pool-size wallet)
          (hash-table-count (wallet-map-wallet wallet))
          (hash-table-count (wallet-address-book wallet))))

(defun %tool-database-error (condition)
  "MakeDatabase's error text for a database that exists but will not open. A
LevelDB held by a running node refuses its LOCK file, which is Core's
SQLiteDatabase exclusive-lock refusal (sqlite.cpp:260-266) -- said here in
this database's name."
  (let ((text (princ-to-string condition)))
    (if (search "lock" text :test #'char-equal)
        "LevelDB: Unable to obtain an exclusive lock on the database, is it being used by another instance of bitcoin-lisp?"
        text)))

(defun %tool-require-existing (manager path)
  "MakeDatabase with require_existing (walletdb.cpp:1329-1382): NIL when PATH
holds a wallet database of MANAGER's network, else Core's sentence."
  (unless (wallet-db-format-recognized-p path (wallet-manager-network manager))
    (format nil "Failed to load database path '~A'. ~A"
            (wallet-path-string path)
            (if (uiop:directory-exists-p path)
                "Data is not in recognized format."
                "Path does not exist."))))

(defun %tool-absolute (filename)
  "fs::absolute: FILENAME against the process's working directory."
  (merge-pathnames filename (uiop:getcwd)))

;;; --- info / create (wallettool.cpp:30-80, 97-140) ---

(defun %wallet-tool-info (manager name out err)
  (let ((missing (%tool-require-existing manager (wallet-path-for manager name))))
    (when missing
      (format err "~A~%" missing)
      (return-from %wallet-tool-info nil)))
  (multiple-value-bind (wallet warnings)
      (handler-case (load-wallet manager name :top-up nil)
        (bl.rpc:rpc-error (e)
          (format err "~A~%" (%tool-database-error (bl.rpc:rpc-error-message e)))
          (return-from %wallet-tool-info nil)))
    (dolist (warning warnings) (write-string warning err))
    (write-string (wallet-tool-info-text wallet) out)
    t))

(defun %wallet-tool-create (manager name out err)
  "Core's `create': a new descriptor wallet, its keypool topped up, and its
info. A wallet that already exists is reported on stderr and the command
still succeeds -- Core's `if (wallet_instance)' falls through to
`return true' (wallettool.cpp:115-122)."
  (when (zerop (length name))
    (format err "Wallet name cannot be empty~%")
    (return-from %wallet-tool-create nil))
  (let ((wallet (handler-case (create-wallet manager name)
                  (bl.rpc:rpc-error (e)
                    (format err "~A~%" (bl.rpc:rpc-error-message e))
                    (return-from %wallet-tool-create t)))))
    (format out "Topping up keypool...~%")
    (write-string (wallet-tool-info-text wallet) out)
    t))

;;; --- dump (dump.cpp:21-104) ---

(defun %dump-line (stream hasher control &rest args)
  "Write one dump line and feed exactly those bytes to the checksum."
  (let ((line (apply #'format nil control args)))
    (write-string line stream)
    (ironclad:update-digest hasher (bl.ser:utf8-string-to-bytes line))))

(defun %dump-checksum (hasher)
  "HashWriter::GetHash: SHA256d of everything fed, as HexStr prints it."
  (bl.crypto:bytes-to-hex (bl.crypto:sha256 (ironclad:produce-digest hasher))))

(defun %wallet-tool-dump (manager name dumpfile out err)
  (let* ((path (wallet-path-for manager name))
         (missing (%tool-require-existing manager path)))
    (when missing
      (format err "~A~%" missing)
      (return-from %wallet-tool-dump nil))
    (let ((db (handler-case (wallet-db-open path)
                (error (e)
                  (format err "~A~%" (%tool-database-error e))
                  (return-from %wallet-tool-dump nil)))))
      (unwind-protect
           (let ((target (and dumpfile (plusp (length dumpfile)) (%tool-absolute dumpfile))))
             (cond
               ((null target)
                (format err "No dump file provided. To use dump, -dumpfile=<filename> must be provided.~%")
                nil)
               ((probe-file target)
                (format err "File ~A already exists. If you are sure this is what you want, move it out of the way first.~%"
                        (namestring target))
                nil)
               (t
                (let ((hasher (ironclad:make-digest :sha256)))
                  (with-open-file (stream target :direction :output :if-exists :error
                                                 :external-format :utf-8)
                    (%dump-line stream hasher "~A,~D~%" +wallet-tool-dump-magic+ +wallet-tool-dump-version+)
                    (%dump-line stream hasher "format,leveldb~%")
                    (map-wallet-db-records
                     db (lambda (key value)
                          (%dump-line stream hasher "~A,~A~%"
                                      (bl.crypto:bytes-to-hex key)
                                      (bl.crypto:bytes-to-hex value))))
                    (format stream "checksum,~A~%" (%dump-checksum hasher))))
                (format out "The dumpfile may contain private keys. To ensure the safety of your Bitcoin, do not share the dumpfile.~%")
                t)))
        (bl.store:leveldb-close db)))))

;;; --- createfromdump (dump.cpp:114-290) ---

(defun %read-dump-field (stream delimiter)
  "std::getline(stream, s, DELIMITER): the text up to DELIMITER or the end."
  (let ((text (with-output-to-string (s)
                (loop for c = (read-char stream nil nil)
                      while (and c (char/= c delimiter))
                      do (write-char c s)))))
    text))

(defun %dump-header-error (stream hasher)
  "Read and check the magic/version and format records (dump.cpp:139-186),
hashing them as Core does. NIL when both are good, else the error text."
  (let* ((magic (%read-dump-field stream #\,))
         (version (%read-dump-field stream #\Newline)))
    (unless (string= magic +wallet-tool-dump-magic+)
      (return-from %dump-header-error
        (format nil "Error: Dumpfile identifier record is incorrect. Got \"~A\", expected \"~A\"."
                magic +wallet-tool-dump-magic+)))
    (let ((ver (and (plusp (length version)) (every #'digit-char-p version)
                    (parse-integer version))))
      (unless ver
        (return-from %dump-header-error
          (format nil "Error: Unable to parse version ~A as a uint32_t" version)))
      (unless (= ver +wallet-tool-dump-version+)
        (return-from %dump-header-error
          (format nil "Error: Dumpfile version is not supported. This version of bitcoin-wallet only supports version 1 dumpfiles. Got dumpfile with version ~A"
                  version))))
    (ironclad:update-digest hasher (bl.ser:utf8-string-to-bytes (format nil "~A,~A~%" magic version)))
    (let* ((format-key (%read-dump-field stream #\,))
           (format-value (%read-dump-field stream #\Newline)))
      (unless (string= format-key "format")
        (return-from %dump-header-error
          (format nil "Error: Dumpfile format record is incorrect. Got \"~A\", expected \"format\"."
                  format-key)))
      (unless (member format-value +wallet-tool-dump-formats+ :test #'string=)
        (return-from %dump-header-error
          (format nil "Error: Dumpfile specifies an unsupported database format (~A). Only sqlite database dumps are supported"
                  format-value)))
      (ironclad:update-digest hasher (bl.ser:utf8-string-to-bytes
                                      (format nil "~A,~A~%" format-key format-value)))
      nil)))

(defun %dump-records-error (stream hasher batch)
  "Read the key,value records into BATCH up to the checksum record and check
it (dump.cpp:208-259). NIL when everything verified, else the error text."
  (let ((checksum nil))
    (loop while (peek-char nil stream nil nil)
          do (let ((key (%read-dump-field stream #\,))
                   (value (%read-dump-field stream #\Newline)))
               (when (string= key "checksum")
                 (let ((parsed (and (%dump-hex-p value) (bl.crypto:hex-to-bytes value))))
                   (unless (= (length parsed) 32)
                     (return-from %dump-records-error "Error: Checksum is not the correct size"))
                   (setf checksum parsed)
                   (loop-finish)))
               (ironclad:update-digest hasher (bl.ser:utf8-string-to-bytes
                                               (format nil "~A,~A~%" key value)))
               (unless (or (zerop (length key)) (zerop (length value)))
                 (unless (%dump-hex-p key)
                   (return-from %dump-records-error (format nil "Error: Got key that was not hex: ~A" key)))
                 (unless (%dump-hex-p value)
                   (return-from %dump-records-error (format nil "Error: Got value that was not hex: ~A" value)))
                 (bl.store:leveldb-writebatch-put batch (bl.crypto:hex-to-bytes key)
                                                  (bl.crypto:hex-to-bytes value)))))
    (let ((computed (bl.crypto:sha256 (ironclad:produce-digest hasher))))
      (cond ((null checksum) "Error: Missing checksum")
            ((not (equalp checksum computed))
             (format nil "Error: Dumpfile checksum does not match. Computed ~A, expected ~A"
                     (bl.crypto:bytes-to-hex computed) (bl.crypto:bytes-to-hex checksum)))))))

(defun %dump-hex-p (text)
  "Core IsHex: non-empty, even length, hex digits only."
  (and (plusp (length text)) (evenp (length text))
       (every (lambda (c) (digit-char-p c 16)) text)))

(defun %wallet-tool-create-from-dump (manager name dumpfile out err)
  (declare (ignore out))
  (when (zerop (length name))
    (format err "Wallet name cannot be empty~%")
    (return-from %wallet-tool-create-from-dump nil))
  (flet ((fail (text) (format err "~A~%" text) (return-from %wallet-tool-create-from-dump nil)))
    (unless (and dumpfile (plusp (length dumpfile)))
      (fail "No dump file provided. To use createfromdump, -dumpfile=<filename> must be provided."))
    (let ((dump-path (%tool-absolute dumpfile))
          (path (wallet-path-for manager name))
          (hasher (ironclad:make-digest :sha256)))
      (unless (probe-file dump-path)
        (fail (format nil "Dump file ~A does not exist." (namestring dump-path))))
      (with-open-file (stream dump-path :external-format :utf-8)
        (let ((header-error (%dump-header-error stream hasher)))
          (when header-error (fail header-error)))
        (when (wallet-db-exists-p path)
          (fail (format nil "Failed to create database path '~A'. Database already exists."
                        (wallet-path-string path))))
        (let ((db (wallet-db-open path :create t
                                  :network (wallet-manager-network manager)))
              (ok nil))
          (unwind-protect
               (bl.store:with-leveldb-writebatch (batch)
                 (let ((records-error (%dump-records-error stream hasher batch)))
                   (when records-error
                     (format err "~A~%" records-error))
                   (unless records-error
                     (bl.store:leveldb-write db batch :sync t)
                     (setf ok t))))
            (bl.store:leveldb-close db)
            ;; On failure the new wallet directory goes (dump.cpp:280-288).
            (unless ok
              (uiop:delete-directory-tree (uiop:ensure-directory-pathname path)
                                          :validate t :if-does-not-exist :ignore)))
          ok)))))

;;; --- ExecuteWalletToolFunc (wallettool.cpp:97-172) ---

(defun wallet-tool-execute (command data-directory network
                            &key name name-p dumpfile dumpfile-p
                                 (out *standard-output*) (err *error-output*))
  "Core WalletTool::ExecuteWalletToolFunc: run COMMAND (\"info\", \"create\",
\"dump\" or \"createfromdump\") on wallet NAME under DATA-DIRECTORY (the
network's own directory, where wallets/ lives), writing what Core writes to OUT
and ERR. Returns T for success. NAME-P and DUMPFILE-P say whether -wallet and
-dumpfile were given at all, which is what Core's IsArgSet checks read."
  (when (and dumpfile-p (not (member command '("dump" "createfromdump") :test #'string=)))
    (format err "The -dumpfile option can only be used with the \"dump\" and \"createfromdump\" commands.~%")
    (return-from wallet-tool-execute nil))
  (when (and (member command '("create" "createfromdump") :test #'string=) (not name-p))
    (format err "Wallet name must be provided when creating a new wallet.~%")
    (return-from wallet-tool-execute nil))
  ;; The tool has no -keypool: its wallets get DEFAULT_KEYPOOL_SIZE, whatever
  ;; the process's node side was configured with.
  (let* ((*default-keypool-size* 1000)
         (manager (init-wallet-manager data-directory network))
         (name (or name "")))
    (unwind-protect
         (cond ((string= command "create") (%wallet-tool-create manager name out err))
               ((string= command "info") (%wallet-tool-info manager name out err))
               ((string= command "dump") (%wallet-tool-dump manager name dumpfile out err))
               ((string= command "createfromdump")
                (%wallet-tool-create-from-dump manager name dumpfile out err))
               (t (format err "Invalid command: ~A~%" command) nil))
      (ignore-errors (close-wallet-manager manager)))))
