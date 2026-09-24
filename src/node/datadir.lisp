(in-package #:bitcoin-lisp)

(defvar *pid-file-path* nil
  "The PID file this process created, or NIL. Set by WRITE-PID-FILE and cleared
by REMOVE-PID-FILE; Core's g_generated_pid serves the same purpose — a pid file
we did NOT create is never removed.")

(defun %abs-path-for-config-val (path datadir)
  "PATH resolved the way Core resolves a config-file path value
(AbsPathForConfigVal with net_specific=false, common/config.cpp:226-232): an
absolute path stands as given, a relative one is joined onto the BASE data
directory -- NOT the process's working directory.

Ours used the -conf value verbatim, so `-conf=bitcoin.conf` alongside
`-datadir=/srv/node` read nothing at all where Core reads
/srv/node/bitcoin.conf, and the node came up on defaults."
  (if (uiop:absolute-pathname-p path)
      (pathname path)
      (merge-pathnames path (uiop:ensure-directory-pathname datadir))))

(alexandria:define-constant +pid-filename+ "bitcoind.pid"
  :test #'equal
  :documentation "Core BITCOIN_PID_FILENAME (init.cpp:171), the default -pid
value.

Core's name, not a name of our own: the pid file is part of the datadir
layout every supervisor and packaging script already knows, and
feature_filelock.py:43 and feature_init.py:255 look for it by that name.
An operator who wants another one passes -pid.")

(defun pid-file-path (pid-arg data-directory &optional network)
  "Where -pid points: PID-ARG, prefixed by NETWORK's directory under
DATA-DIRECTORY when relative (Core GetPidFile -> AbsPathForConfigVal,
init.cpp:178-181). NIL when -pid was negated, which Core treats as \"write no
pid file\" (init.cpp:185).

The NETWORK directory, not the base one. GetPidFile takes AbsPathForConfigVal's
DEFAULT net_specific, which is true (common/args.h:42), so on regtest the pid
file is <datadir>/regtest/bitcoind.pid and only on mainnet is it the datadir
root -- the same rule -debuglogfile and -settings already follow here.
feature_init.py:256 looks for `-pid=<relative>` under `node.chain_path`; a pid
file one directory up is one a supervisor pointed at the chain directory never
finds. Passing no NETWORK keeps the base directory, which is what mainnet and
the pre-Core callers want."
  (let ((arg (cond ((null pid-arg) +pid-filename+)
                   ((not (stringp pid-arg)) pid-arg)
                   ((or (string= pid-arg "0") (string= pid-arg "")) nil)
                   (t pid-arg))))
    (when arg
      (let ((base (uiop:ensure-directory-pathname (or data-directory "./"))))
        (%abs-path-for-config-val
         arg (if network (network-data-path base network) base))))))

(defun write-pid-file (pid-arg data-directory &optional network)
  "Write our PID where -pid says (Core CreatePidFile, init.cpp:183-199).

Core makes a write failure a fatal InitError, and so do we: an operator who
asked for a pid file and silently did not get one has a supervisor that will
never find this process."
  (let ((path (pid-file-path pid-arg data-directory network)))
    (when path
      (handler-case
          (with-open-file (out path :direction :output
                                    :if-exists :supersede
                                    :if-does-not-exist :create)
            (format out "~D~%" (sb-posix:getpid)))
        (error (e)
          (init-error "Unable to create the PID file '~A': ~A" path e)))
      (setf *pid-file-path* path)
      path)))

(defun remove-pid-file ()
  "Remove the pid file we created (Core RemovePidFile, init.cpp:200-208). A
failure is a warning, never a reason to fail shutdown."
  (let ((path *pid-file-path*))
    (when path
      (setf *pid-file-path* nil)
      (handler-case (delete-file path)
        (error (e)
          (log-warn "Unable to remove PID file (~A): ~A" path e))))))

(defun %ensure-wallets-subdirectory (data-directory network)
  "Create wallets/ under a datadir that did not exist yet (Core
common/init.cpp:45-63).

Both the base path and the network path, and only when the path itself is
being created — an existing datadir keeps whatever layout it has, which is the
backwards-compatibility rule Core states in that comment. Wallet code then USES
the subdirectory only if it is already there, so this runs whether or not the
wallet is enabled.

Its caller must run it FIRST, before anything that can create the network
directory: opening the log file does ENSURE-DIRECTORIES-EXIST on
<datadir>/<network>/debug.log, and after that the `did this path exist?' test
below is answered by our own side effect and is always false.

Small, and it was blocking the whole functional-test corpus: the framework
builds a shared 199-block cache datadir once and copies it per test, and its
cleanup does `os.rmdir(cache/regtest/wallets)`. With no such directory that
raises, the cache build FAILS, and every run then falls back on whatever cache
was last built successfully — which here was one written in the pre-Core
per-block format, months old. Every non-clean-chain test in the suite was
running against it."
  (flet ((claim (dir)
           (let ((path (uiop:ensure-directory-pathname dir)))
             (unless (probe-file path)
               (ensure-directories-exist (merge-pathnames "wallets/" path))))))
    (let ((base (uiop:ensure-directory-pathname data-directory)))
      (claim base)
      (claim (network-data-path base network)))))

(defun %check-datadir-option (cli)
  "An explicitly named -datadir that does not exist is FATAL, as it is in Core
 (CheckDataDirOption, args.cpp:789-793; the error is \"specified data directory
... does not exist\").

We created it instead. On a node that is the wrong default in both directions
an operator hits it: a typo and an unmounted volume both present as an empty
directory, and an empty datadir means a full re-sync from genesis — started
silently, and on mainnet measured in days. Not naming -datadir at all is still
fine; that is the default path, and creating THAT is the intended behaviour."
  (let ((datadir (cdr (assoc "datadir" cli :test #'string=))))
    (when (and datadir (plusp (length datadir)))
      (let ((path (pathname (if (char= (char datadir (1- (length datadir))) #\/)
                                datadir
                                (concatenate 'string datadir "/")))))
        (unless (probe-file path)
          ;; ReadConfigFiles' last step (common/config.cpp:218-221), so it
          ;; carries the config-read prefix and Core's closing period.
          (bl.cfg:config-file-read-error
           "specified data directory \"~A\" does not exist." datadir))))))

(defun blocks-dir-path (blocks-directory data-directory network)
  "Where the blk/rev/xor files go -- Core ArgsManager::GetBlocksDirPath
(common/args.cpp:286-309): <-blocksdir>/<chain subdirectory>/blocks when
-blocksdir is set, and <datadir>/<chain subdirectory>/blocks otherwise.

A -blocksdir that is not an existing DIRECTORY makes Core return an empty path,
which init.cpp:967-970 turns into \"Specified blocks directory ... does not
exist.\" -- so this signals instead of creating it. That refusal is the whole
point of the option: an unmounted volume otherwise presents as a node quietly
writing hundreds of GB to the mount point's underlying disk."
  (if (and blocks-directory (plusp (length blocks-directory)))
      (let ((root (uiop:ensure-directory-pathname blocks-directory)))
        (unless (uiop:directory-exists-p root)
          (init-error "Specified blocks directory \"~A\" does not exist."
                      blocks-directory))
        (merge-pathnames "blocks/"
                         (network-data-path (truename root) network)))
      (merge-pathnames "blocks/" (uiop:ensure-directory-pathname data-directory))))

(alexandria:define-constant +bitcoin-conf-filename+ "bitcoin.conf"
  :test #'equal
  :documentation "Core BITCOIN_CONF_FILENAME (common/args.h).")

(defun %conf-negated-p (args)
  "T when -noconf was given (Core IsArgNegated for -conf, which makes
GetPathArg return an EMPTY path and suppresses the config file entirely).
Read from the command-line rows rather than the parsed alist, because
`-noconf` and `-conf=0` both reduce to the value 0 and only the first is
Core's JSON false."
  (let ((rows (remove-if-not (lambda (row) (string= (first row) "conf"))
                             (bl.cfg:cli-settings-rows args))))
    (and rows (bl.cfg:setting-row-negated-p (car (last rows))))))

(defun resolve-conf-path (args cli datadir)
  "Where the config file is, as Core's ReadConfigFiles resolves it
(common/config.cpp:122-142 + AbsPathForConfigVal). Returns
 (values path explicit-p): PATH is NIL under -noconf, the -conf value resolved
against DATADIR when one was given, and <datadir>/bitcoin.conf otherwise.
EXPLICIT-P says whether -conf named it, which is what makes an unreadable file
FATAL rather than a silent fall-through to no configuration at all."
  (let ((conf (cdr (assoc "conf" cli :test #'string=))))
    (cond
      ((%conf-negated-p args) (values nil t))
      ((and conf (plusp (length conf)))
       (values (%abs-path-for-config-val conf datadir) t))
      (t (values (%abs-path-for-config-val +bitcoin-conf-filename+ datadir) nil)))))

(defun check-config-file-readable (conf-path explicit-p)
  "Core ReadConfigFiles' two refusals (common/config.cpp:134-141), in Core's
order and words. A DIRECTORY at the path is `Config file \"...\" is a
directory.' whether -conf named it or it is the datadir's own bitcoin.conf;
only then, and only for a file -conf named EXPLICITLY, an unopenable one is
`specified config file \"...\" could not be opened.'.

We fell through to no config at all, so a typo in -conf started a node on
defaults -- and a default-configured node on mainnet is an unpruned sync with
no rpcauth -- and a directory passed PROBE-FILE (which answers its truename)
only to die in the read with `Is a directory', a stream error naming no
option. init/common.cpp:131's `(is directory, not file)' warning is the
same case seen from a later step: bitcoind never gets there, because
ReadConfigFiles has already refused."
  (when conf-path
    (when (uiop:directory-exists-p conf-path)
      (bl.cfg:config-file-read-error
       "Config file \"~A\" is a directory." (namestring conf-path)))
    (when (and explicit-p (not (probe-file conf-path)))
      (bl.cfg:config-file-read-error
       "specified config file \"~A\" could not be opened." (namestring conf-path))))
  conf-path)

(defun %same-file-p (a b)
  "Core fs::equivalent: the same file on disk, not merely the same spelling."
  (let ((ta (ignore-errors (truename a)))
        (tb (ignore-errors (truename b))))
    (and ta tb (equal (namestring ta) (namestring tb)))))

(defun %datadir-string (directory)
  "DIRECTORY as Core's fs::PathToString prints a data directory: no trailing
separator. A Lisp directory namestring ends in `/', and feature_config_args.py
:86 and :443 compare the quoted path exactly."
  (let ((text (namestring (uiop:ensure-directory-pathname directory))))
    (if (and (> (length text) 1) (char= #\/ (char text (1- (length text)))))
        (subseq text 0 (1- (length text)))
        text)))

(defun check-ignored-config-file (orig-datadir conf-path effective-datadir cli
                                  &key allow-ignored)
  "Refuse to start when the EFFECTIVE data directory holds a bitcoin.conf that
is not the file we read -- Core common/init.cpp:65-95.

Two shapes reach it, and Core's comment (:25-33) says why neither may be
silent: a `datadir=` line INSIDE the config file moves the data directory, and
the bitcoin.conf sitting in the directory it moved to is then ignored; and a
`-conf=` on the command line shadows the bitcoin.conf in the data directory.
Either way the operator's whole second file -- prune, rpcauth, bind, txindex --
is dropped with nothing in the log, and the node runs on defaults for all of it.

ORIG-DATADIR is the data directory as the command line and the defaults gave
it, before the config file was read; EFFECTIVE-DATADIR is what the merged
config settled on. CONF-PATH is the file that was actually read, NIL under
-noconf. ALLOW-IGNORED is -allowignoredconf, which downgrades the refusal to a
warning and is the only way past it."
  (let* ((base (uiop:ensure-directory-pathname effective-datadir))
         (base-config (merge-pathnames +bitcoin-conf-filename+ base)))
    (when (probe-file base-config)
      (cond
        ((null conf-path)
         (defer-log :info "Data directory \"~A\" contains a \"~A\" file which is ~
explicitly ignored using -noconf."
                    (%datadir-string base) +bitcoin-conf-filename+))
        ;; The ordinary case: the file we read IS the datadir's own.
        ((%same-file-p conf-path base-config))
        (t
         (let* ((cli-conf (cdr (assoc "conf" cli :test #'string=)))
                (source (if (and cli-conf (plusp (length cli-conf)))
                            (format nil "command line argument \"-conf=~A\"" cli-conf)
                            (format nil "data directory \"~A\""
                                    (%datadir-string orig-datadir))))
                (text (format nil
                              "Data directory \"~A\" contains a \"~A\" file which is ignored, ~
because a different configuration file \"~A\" from ~A is being used instead. ~
Possible ways to address this would be to:~%~
- Delete or rename the \"~A\" file in data directory \"~A\".~%~
- Change datadir= or conf= options to specify one configuration file, not two, ~
and use includeconf= to include any other configuration files."
                              (%datadir-string base) +bitcoin-conf-filename+
                              (namestring conf-path) source
                              +bitcoin-conf-filename+ (%datadir-string base))))
           (if allow-ignored
               (defer-log :warn "~A" text)
               (error 'bl.cfg:config-parse-error
                      :message
                      (format nil "~A~%- Set allowignoredconf=1 option to treat this ~
condition as a warning, not an error."
                              text)))))))))

(defun %read-config-includes (conf-text cli datadir)
  "Resolve -includeconf, returning the list of config texts to merge (the main
file first) and, as a second value, the name each INCLUDED text was given by
-- as written, which is how Core's section warning names the file
(ReadConfigStream(conf_file_stream, conf_file_name, ...), config.cpp:192).
Core ArgsManager::ReadConfigFiles, common/config.cpp:150-213.

Ours was unimplemented: a split configuration loaded with everything at
defaults after a single warning line, which on a node is indistinguishable from
a config file that was read and understood.

Core's rules, all of which apply here:
  - the include list is read from the network section AND the global area;
  - a relative path is relative to the base datadir (net_specific=false);
  - a missing or unreadable include is a FATAL error, not a warning — the
    alternative is silently running without the settings it holds;
  - -includeconf inside an INCLUDED file is ignored with a warning, so a config
    cannot recurse;
  - on the command line only the negated form is accepted, and -noincludeconf
    suppresses includes entirely."
  (when (null conf-text)
    (return-from %read-config-includes nil))
  (let ((cli-include (assoc "includeconf" cli :test #'string=)))
    (when (and cli-include (not (bl.cfg:conf-parse-bool (cdr cli-include))))
      ;; -noincludeconf
      (return-from %read-config-includes (list conf-text)))
    (when (and cli-include (bl.cfg:conf-parse-bool (cdr cli-include)))
      (error 'bl.cfg:config-parse-error
             :message "-includeconf cannot be used from the command line; put it ~
                       in the configuration file")))
  (let* ((network (bl.cfg:resolve-network-from-config
                   (append cli (bl.cfg:conf-global-entries conf-text))))
         (entries (bl.cfg:parse-bitcoin-conf conf-text network))
         (names (loop for (k . v) in entries
                      when (and (string= k "includeconf") (plusp (length v)))
                        collect v))
         (base (pathname (if (and (plusp (length datadir))
                                  (char= (char datadir (1- (length datadir))) #\/))
                             datadir
                             (concatenate 'string datadir "/"))))
         (texts (list conf-text))
         (read-names '()))
    (dolist (name names)
      (let ((path (merge-pathnames name base)))
        (when (uiop:directory-exists-p path)
          ;; Core tests the include for a DIRECTORY first, and says so
          ;; (common/config.cpp:185-188); ours fell through to the
          ;; could-not-open sentence, which names the wrong problem.
          (bl.cfg:config-file-read-error
           "Included config file \"~A\" is a directory." (namestring path)))
        (unless (probe-file path)
          (bl.cfg:config-file-read-error
           "Failed to include configuration file ~A" name))
        (let ((text (alexandria:read-file-into-string path)))
          ;; A recursive include is dropped with a warning, exactly as Core
          ;; does (it re-scans for includeconf after reading,
          ;; common/config.cpp:202-213) -- on STDERR, where Core puts it and
          ;; where alone it can be read before debug.log exists.
          (dolist (inner (bl.cfg:parse-bitcoin-conf text nil))
            (when (string= (car inner) "includeconf")
              (bl.cfg:warn-includeconf-from-included-file (cdr inner))))
          (log-info "Included configuration file ~A" name)
          (push text texts)
          (push name read-names))))
    (values (nreverse texts) (nreverse read-names))))

(defun %network-subdirectory (network)
  "The per-network subdirectory of the datadir, as Bitcoin Core defines it
 (CreateBaseChainParams, chainparamsbase.cpp:40-55). NIL means the datadir root.

  mainnet   -> the root        testnet3 -> testnet3/
  testnet4  -> testnet4/       signet   -> signet/       regtest -> regtest/

Ours used to be the INVERSE for exactly the two that matter: mainnet in
`mainnet/` and testnet3 at the root. Pointing our node at a Core datadir with
the default network therefore wrote testnet3 data into Core's MAINNET
directory, and pointing Core at ours found nothing and started a fresh sync."
  (bl.chain:chain-params-data-subdirectory (bl.chain:find-chain-params network)))

(defun network-data-path (base-path network)
  "Where NETWORK's data lives under BASE-PATH.

Core's layout, with one deliberate exception: a datadir that already holds data
in our OLD layout keeps using it. Silently adopting Core's layout on an existing
node would present an empty datadir to a node that has one — which on mainnet
means discarding a synced chain and starting IBD from genesis, the single most
expensive way to be wrong here. The legacy directory is logged every start so it
is visible rather than inherited by accident."
  (let* ((subdir (%network-subdirectory network))
         (core-path (if subdir (merge-pathnames subdir base-path) base-path))
         ;; The layout this tree used before: mainnet under mainnet/, testnet3
         ;; at the root. Every other network already agreed with Core.
         (legacy-subdir (and (eq network :mainnet) "mainnet/"))
         (legacy-path (if legacy-subdir
                          (merge-pathnames legacy-subdir base-path)
                          base-path)))
    (cond
      ((equal core-path legacy-path) core-path)
      ;; "Holds data" means a chainstate, not merely an existing directory —
      ;; ensure-directories-exist creates empty ones freely.
      ((and (not (probe-file (merge-pathnames "chainstate.dat" core-path)))
            (probe-file (merge-pathnames "chainstate.dat" legacy-path)))
       (log-warn "Using the legacy data layout ~A for ~A; Bitcoin Core's layout ~
                  for this network is ~A. Move the directory to adopt it."
                 legacy-path network core-path)
       legacy-path)
      (t core-path))))

(defun %settings-file-path (scope datadir network)
  "Where the read-write settings file lives, or NIL when -nosettings turned it
off (Core ArgsManager::GetSettingsPath).

Default is settings.json in the NETWORK directory, not the datadir root — on
regtest that is <datadir>/regtest/settings.json, which is the path the
functional tests compute as `node.chain_path / \"settings.json\"`. An explicit
-settings= is taken relative to the DATADIR, as Core does.

SCOPE is the command line followed by the config file's sections and globals,
in precedence order — -settings is an ordinary option and can be set in
bitcoin.conf like any other (feature_settings.py drives exactly that with a
`nosettings=1` appended to the [regtest] section). It cannot come from the
settings file itself, which is why SCOPE is assembled here rather than taken
from the merged config."
  (let ((value (cdr (assoc "settings" scope :test #'string=))))
    (cond
      ;; -nosettings arrives as "0" from PARSE-CLI-ARGS' negation handling.
      ((and value (string= value "0")) nil)
      ((and value (not (string= value "1")))
       (merge-pathnames value (pathname datadir)))
      (t (merge-pathnames "settings.json"
                          (network-data-path (pathname datadir) network))))))

(defun %read-settings-file (path)
  "The settings file at PATH as an alist, or NIL when there is none.

A malformed file ABORTS startup, exactly as Core does (common/init.cpp:99-108
turns a failed ReadSettingsFile into a fatal ConfigError). Starting anyway with
the file ignored would run the node on settings the operator cannot see in it."
  (unless (probe-file path)
    (return-from %read-settings-file nil))
  (multiple-value-bind (alist errors)
      (bl:parse-settings-json
       (handler-case (alexandria:read-file-into-string path)
         (error (e)
           (init-error "Settings file could not be read: ~A. Please check permissions." e)))
       (namestring path))
    (when errors
      (init-error "Settings file could not be read: ~{~A~^; ~}" errors))
    (let ((invalid (bl:validate-settings-values alist)))
      (when invalid (init-error "~A" invalid)))
    (dolist (name (bl:unknown-settings-keys alist))
      (defer-log :warn "Ignoring unknown rw_settings value ~A" name))
    alist))

(defun %write-settings-file (path alist)
  "Rewrite PATH with ALIST plus Core's warning comment.

Temp file, fsync, rename, fsync the directory — the same discipline
BITCOIN-LISP.WALLET::%WRITE-SETTINGS uses for the wallet half of this very file.
Core writes it through a temp and a rename too (args.cpp:429-460). Without the
fsyncs a crash can leave the renamed file empty or revert the rename, and this
is now rewritten on EVERY start, so it is the crash window an operator hits
most often. A truncated settings file refuses the next start outright.

The wallet layer is the other writer: it reads the whole object and replaces
only the \"wallet\" key, and this reader keeps every key it did not put there,
so the two compose rather than clobbering each other."
  (handler-case
      (let ((tmp (make-pathname :type "json.tmp" :defaults path)))
        (ensure-directories-exist path)
        (with-open-file (out tmp :direction :output :external-format :utf-8
                                 :if-exists :supersede :if-does-not-exist :create)
          (write-string (bl:render-settings-json alist) out))
        (bl.kv:fsync-file tmp)
        (rename-file tmp path)
        (bl.kv:fsync-parent-directory path))
    (error (e)
      (init-error "Settings file could not be written: ~A" e))))

(defvar *directory-lock-fds* '()
  "Open file descriptors holding the exclusive advisory locks on the .lock
files of the directories this process claimed. Held for the lifetime of the
process: closing one releases its lock and lets a second node open that
directory.")
(defconstant +flock-ex-nb+ 6
  "flock(2) LOCK_EX (2) | LOCK_NB (4) — take an exclusive lock, or fail
immediately rather than waiting for the holder to exit.")

(defun path-to-string (path)
  "PATH as Core's fs::PathToString prints a directory: no trailing separator.

Core names a directory in a message with fs::PathToString of an fs::path, and
an fs::path carries no trailing separator. A Lisp DIRECTORY pathname's
namestring does, so a sentence built with ~A read `.../regtest/' where Core
reads `.../regtest' — and feature_filelock.py:33 builds the sentence it expects
from the path itself and compares the whole line, so the one character was the
whole failure."
  (let ((text (namestring path)))
    (if (and (> (length text) 1)
             (char= (char text (1- (length text))) #\/))
        (subseq text 0 (1- (length text)))
        text)))

(defun lock-directory (directory)
  "Take Core's exclusive .lock on DIRECTORY (init.cpp:1158-1168 ->
util/fs_helpers.cpp:47). Signals an init error if another process holds it.

Two nodes sharing a data directory destroy it: each keeps its own in-memory
block index and UTXO cache and flushes over the other's files, so the loser is
not the second to start but whichever flushes last. The coins LevelDB takes its
own lock, but only over that subdirectory and only once startup gets that far —
by which point this node has already read, and may already have rewritten,
chainstate.dat and headerindex.dat.

Advisory-only, like Core's: it stops a second bitcoin-lisp, not an unrelated
process editing the files."
  (ensure-directories-exist directory)
  (let* ((path (merge-pathnames ".lock" directory))
         (fd (handler-case
                 (sb-posix:open (namestring path)
                                (logior sb-posix:o-creat sb-posix:o-rdwr)
                                #o644)
               (error (e)
                 (init-error "Cannot create the lock file at ~A: ~A" path e)))))
    (when (minusp (cffi:foreign-funcall "flock" :int fd :int +flock-ex-nb+ :int))
      (ignore-errors (sb-posix:close fd))
      ;; Core's wording exactly (init.cpp:1165): "Cannot obtain a lock on
      ;; directory %s. %s is probably already running." Not decoration —
      ;; feature_filelock.py matches on that sentence, and an operator whose
      ;; second node will not start searches for the string bitcoind prints.
      ;; Ours said "data directory" and joined the two halves with a semicolon.
      (let ((message (format nil "Cannot obtain a lock on directory ~A. ~A is probably already running."
                             (path-to-string directory)
                             "bitcoin-lisp")))
        (log-error "~A" message)
        (init-error "~A" message)))
    ;; Keep the descriptor open. UNWIND from here on must not close it.
    (push fd *directory-lock-fds*)))

(defun lock-data-directories (data-directory blocks-directory)
  "Claim BOTH directories Core claims (LockDirectories, init.cpp:1170-1174):
the network data directory and the blocks directory.

Core locks the blocks directory separately because -blocksdir can point it at
another volume, which two nodes can then share while their data directories
differ — and the blk/rev files are exactly what a second writer corrupts.
feature_filelock.py:37 starts a second node with only -blocksdir pointing at a
running node's directory and expects the same refusal."
  (lock-directory data-directory)
  (unless (equal (truename (ensure-directories-exist data-directory))
                 (truename (ensure-directories-exist blocks-directory)))
    (lock-directory blocks-directory)))

(defun unlock-data-directory ()
  "Release every directory lock this process holds. The .lock files themselves
stay behind, as Core leaves them — their presence means nothing, only the
advisory lock on them does."
  (dolist (fd *directory-lock-fds*)
    (ignore-errors (sb-posix:close fd)))
  (setf *directory-lock-fds* '()))

(defun %normalize-datadir (datadir)
  "DATADIR as a string that names a DIRECTORY, whatever spelling it arrived in.

Core accepts -datadir with or without a trailing separator. Here \"/tmp/x\"
parses as a FILE pathname whose NAME is \"x\", so merging \"regtest/chainstate/\"
onto it yields /tmp/regtest/chainstate/x — the node opens its databases
somewhere nobody asked for, and the first symptom is a LevelDB NotFound on a
path the operator never typed. Kept a STRING because the config layer treats it
as one."
  (when datadir
    (namestring (uiop:ensure-directory-pathname datadir))))

(defun asmap-file-path (asmap data-directory network)
  "Where -asmap's value points (Core init.cpp:1588-1594): an absolute path
as given, a relative one under the NETWORK data directory -- GetDataDirNet,
so `-asmap=ASN_map` on regtest is <datadir>/regtest/ASN_map, not
<datadir>/ASN_map, which is where a file the framework wrote there is NOT.
The boolean spellings (a bare -asmap, -asmap=1) ask for the embedded map
(init.cpp:1611-1626), which this node does not carry: :EMBEDDED, for the
caller to refuse as Core does without ENABLE_EMBEDDED_ASMAP."
  (cond
    ((or (string= asmap "") (string= asmap "1")) :embedded)
    ((uiop:absolute-pathname-p asmap) (pathname asmap))
    (t (merge-pathnames asmap
                        (network-data-path
                         (uiop:ensure-directory-pathname (or data-directory "./"))
                         network)))))
