(in-package #:bitcoin-lisp.kv)

;;;; Core's data-directory layout (doc/files.md)
;;;;
;;;; Core:
;;;;   blocks/{blkNNNNN.dat, revNNNNN.dat, xor.dat}, blocks/index/
;;;;   chainstate/
;;;;   indexes/txindex/, indexes/blockfilter/basic/db/,
;;;;   indexes/coinstatsindex/db/, indexes/txospenderindex/db/
;;;;   wallets/
;;;;
;;;; This tree grew a flatter one: undo/ and headerindex.dat at the network-dir
;;;; root, and the three indexes as siblings of blocks/ rather than under
;;;; indexes/. That is not merely cosmetic — Core's functional tests read and
;;;; delete these paths by name, so a node with a different layout cannot be
;;;; driven by them.
;;;;
;;;; EVERY resolver here PREFERS Core's path and FALLS BACK to the legacy one
;;;; only when the legacy path exists and Core's does not. A running node is
;;;; therefore untouched until its operator migrates, while a fresh datadir is
;;;; Core-shaped from the first byte — which is what the harness needs.
;;;;
;;;; The alternative, adopting Core's layout unconditionally, would present an
;;;; EMPTY datadir to a node that has one: on mainnet that means discarding a
;;;; synced chain and starting IBD from genesis. The same reasoning already
;;;; governs the network-subdirectory choice in node/datadir.lisp.
;;;;
;;;; Audited against Core d3056bc, path by path. Every NAME now agrees:
;;;; blocks/ with blkNNNNN.dat, revNNNNN.dat and xor.dat; blocks/index/
;;;; (init.cpp:1140); chainstate/ (validation.cpp:1873) with its snapshot
;;;; sibling chainstate_snapshot/ (utxo_snapshot.h:128) and the _INVALID
;;;; (validation.cpp:6229) and _todelete (:6309) names the snapshot paths use;
;;;; indexes/txindex/ (txindex.cpp:52); and the three nested databases below.
;;;;
;;;; Three differences that remain are FORMAT, not location, and are named
;;;; here so the next audit does not re-derive them:
;;;;
;;;;   - blocks/index/ is a LevelDB in Core (init.cpp:1140 hands it DBParams);
;;;;     ours is one flat headerindex.dat inside that directory.
;;;;   - indexes/blockfilter/basic/ holds Core's fltrNNNNN.dat flat files
;;;;     (blockfilterindex.cpp:89, FlatFileSeq "fltr"); we keep each filter in
;;;;     the LevelDB instead, so this tree writes no fltr file at all.
;;;;   - chainstate.dat (and chainstate_snapshot.dat) are ours alone: Core
;;;;     keeps the equivalent inside the coins database.
;;;;
;;;; Core's own doc/files.md lists the spender index as indexes/txospenderindex/
;;;; while txospenderindex.cpp:64 appends "db"; the code is what the node does.

(defun %dir-has-content-p (path)
  "T when PATH names a directory that actually holds something.

Existence alone is not enough: ENSURE-DIRECTORIES-EXIST creates empty
directories freely, and an empty one must not win the fallback against a
legacy directory that holds real data."
  (and path
       (probe-file path)
       (or (directory (merge-pathnames "*.*" path))
           (directory (merge-pathnames "*/" path)))))

(defun %resolve-datadir-path (core-path legacy-path)
  "CORE-PATH unless only LEGACY-PATH holds data. Returns (values path legacy-p)."
  (cond ((equal core-path legacy-path) (values core-path nil))
        ((%dir-has-content-p core-path) (values core-path nil))
        ((%dir-has-content-p legacy-path) (values legacy-path t))
        (t (values core-path nil))))

(defun datadir-block-index-path (data-dir)
  "Core's blocks/index/ for the block index. The legacy layout is a flat
headerindex.dat at the network-dir root; the FILE is resolved by
DATADIR-HEADER-INDEX-FILE, which is what callers use."
  (merge-pathnames "index/" (merge-pathnames "blocks/" data-dir)))

(defun datadir-header-index-file (data-dir)
  "The header/block index file. Core's location is blocks/index/; ours was
headerindex.dat at the root. Returns (values path legacy-p)."
  (let ((core (merge-pathnames "headerindex.dat"
                               (datadir-block-index-path data-dir)))
        (legacy (merge-pathnames "headerindex.dat" data-dir)))
    (cond ((probe-file core) (values core nil))
          ((probe-file legacy) (values legacy t))
          (t (values core nil)))))

(alexandria:define-constant +core-index-subdirectories+
  '((:txindex . "indexes/txindex/")
    ;; Three of the four keep their LevelDB in a `db' SUBDIRECTORY of the
    ;; index's own directory and the txindex does not. That is Core's shape
    ;; rather than a convention: index/txindex.cpp:52 hands BaseIndex::DB the
    ;; bare indexes/txindex, while index/blockfilterindex.cpp:88,
    ;; index/coinstatsindex.cpp:106 and index/txospenderindex.cpp:64 each
    ;; append "db". The filter index's parent is not spare room either: in
    ;; Core the fltr?????.dat flat files live in it, beside db/.
    (:blockfilter . "indexes/blockfilter/basic/db/")
    (:coinstats . "indexes/coinstatsindex/db/")
    (:txospenderindex . "indexes/txospenderindex/db/"))
  :test #'equalp :documentation "Core doc/files.md's index paths.")

;;;; The `db' subdirectory, and moving an existing index into it
;;;;
;;;; This tree opened the filter index at indexes/blockfilter/basic/ and the
;;;; coinstatsindex at indexes/coinstatsindex/, one level above where Core
;;;; opens them. Core's own feature_reindex.py:94-95 addresses the filter
;;;; index's database by name, so the difference is not cosmetic.
;;;;
;;;; Correcting the constant alone would present an EMPTY database to a node
;;;; that has a populated one and silently rebuild the index from genesis --
;;;; hours on mainnet, and exactly the failure the legacy fallback above exists
;;;; to prevent. So the LevelDB is MOVED into db/ the first time such a datadir
;;;; is opened, in two rename(2) calls with a staging name between them (a
;;;; directory cannot be renamed into its own child). A crash between the two
;;;; leaves the staging directory, and the next open finishes the move.

(defun %index-db-parent (data-dir which)
  "The directory Core's `db' subdirectory sits in for index WHICH, or NIL when
that index's LevelDB is not nested (the txindex)."
  (let ((sub (cdr (assoc which +core-index-subdirectories+))))
    (when (and sub (alexandria:ends-with-subseq "db/" sub))
      (merge-pathnames (subseq sub 0 (- (length sub) 3)) data-dir))))

(defun %leveldb-directory-p (path)
  "T when PATH holds a LevelDB. CURRENT is the file leveldb writes last when it
creates a database and reads first when it opens one, so its presence is what
DB::Open actually requires, and a directory holding only Core's fltr?????.dat
flat files (or nothing) correctly answers NIL."
  (and path (probe-file (merge-pathnames "CURRENT" path)) t))

(defun %index-db-staging-path (parent)
  "The sibling name the index directory is parked under between the two
renames. A sibling, because rename(2) cannot move a directory into itself."
  (pathname (concatenate 'string
                         (%path-without-trailing-slash parent) ".migrating/")))

(defun %drop-empty-directory (path)
  "Remove PATH when it exists and holds nothing, so a rename can land on the
name. ENSURE-DIRECTORIES-EXIST creates such directories freely."
  (when (and (probe-file path) (not (%dir-has-content-p path)))
    (ignore-errors (uiop:delete-empty-directory path))))

(defun migrate-index-db-subdirectory (data-dir which &key dry-run)
  "Move index WHICH's LevelDB into Core's `db' subdirectory when an earlier
version of this tree left it in the index directory itself. Returns
 (values from to) for the move made (or that WOULD be made under DRY-RUN), and
NIL when there is nothing to do.

Nothing to do is the overwhelmingly common case, reached in two PROBE-FILEs: a
fresh datadir, a datadir already migrated, an index still on the flat pre-Core
path, and the txindex, whose LevelDB Core does not nest.

A parent and a db/ that BOTH hold a LevelDB are left alone rather than merged:
two databases for one index is a state nothing here expects, and picking one of
them silently is how the wrong records get served."
  (let ((parent (%index-db-parent data-dir which)))
    (when parent
      (let ((db (merge-pathnames "db/" parent))
            (staging (%index-db-staging-path parent)))
        (cond ((%leveldb-directory-p staging)
               ;; A crash landed between the two renames. Finish the move.
               (unless dry-run
                 (%drop-empty-directory db)
                 (rename-path staging db))
               (values staging db))
              ((and (%leveldb-directory-p parent)
                    (not (%leveldb-directory-p db)))
               (unless dry-run
                 (%drop-empty-directory db)
                 (rename-path parent staging)
                 (rename-path staging db))
               (values parent db))
              (t nil))))))

(alexandria:define-constant +legacy-index-subdirectories+
  '((:txindex . "txindex/")
    (:blockfilter . "blockfilterindex/")
    (:coinstats . "coinstatsindex/")
    (:txospenderindex . "txospenderindex/"))
  :test #'equalp :documentation "The flat layout this tree used before.")

(defun datadir-index-path (data-dir which &key migrate)
  "Where index WHICH (:txindex, :blockfilter, :coinstats or
:txospenderindex) lives. Returns
 (values path legacy-p).

MIGRATE first moves a LevelDB left in the index directory itself into Core's
`db' subdirectory (MIGRATE-INDEX-DB-SUBDIRECTORY). It is off by default so
this stays a pure resolver: DATADIR-LAYOUT-REPORT calls it to say what a
datadir looks like, and a report must not move anything."
  (when migrate
    (migrate-index-db-subdirectory data-dir which))
  (let ((core (merge-pathnames (cdr (assoc which +core-index-subdirectories+))
                               data-dir))
        (legacy (merge-pathnames (cdr (assoc which +legacy-index-subdirectories+))
                                 data-dir)))
    (%resolve-datadir-path core legacy)))

(defun datadir-layout-report (data-dir)
  "Which paths are resolving to the LEGACY location, as a list of
 (label core-path legacy-path). Empty when the datadir is fully Core-shaped.

Reported at startup rather than silently tolerated: an operator whose node
cannot be driven by Core's functional tests should be told which directory is
the reason."
  (let ((out '()))
    (multiple-value-bind (path legacy-p) (datadir-header-index-file data-dir)
      (declare (ignore path))
      (when legacy-p
        (push (list "block index"
                    (merge-pathnames "headerindex.dat"
                                     (datadir-block-index-path data-dir))
                    (merge-pathnames "headerindex.dat" data-dir))
              out)))
    ;; undo/ is deliberately absent from this report. Its per-block files are a
    ;; different FORMAT from Core's revNNNNN.dat, not a different location, so
    ;; "which directory" is not a question with an answer here — migrateblocks
    ;; converts them, and until it has, undo/ is exactly where they belong.
    (dolist (which '(:txindex :blockfilter :coinstats))
      (multiple-value-bind (path legacy-p) (datadir-index-path data-dir which)
        (declare (ignore path))
        (when legacy-p
          (push (list (string-downcase (symbol-name which))
                      (merge-pathnames (cdr (assoc which +core-index-subdirectories+))
                                       data-dir)
                      (merge-pathnames (cdr (assoc which +legacy-index-subdirectories+))
                                       data-dir))
                out))))
    (nreverse out)))

(defun rename-path (from to)
  "Move FROM to TO, file or directory, and VERIFY it arrived.

rename(2) rather than CL's RENAME-FILE, which merges the target with the source
pathname — a surprise that has already produced one silently successful no-op
in this project (backupwallet reported success and wrote nothing). uiop's
rename-file-overwriting-target refuses a directory outright, and both callers
here move a directory (the datadir migration below, and the wallet database
rewrite that swaps a rebuilt directory into place).

The verification is not ceremony: a move that reports success and moved
nothing is exactly the failure this comment is about."
  (ensure-directories-exist (uiop:pathname-parent-directory-pathname
                             (uiop:ensure-directory-pathname to)))
  (sb-posix:rename (%path-without-trailing-slash from)
                   (%path-without-trailing-slash to))
  (unless (probe-file to)
    (storage-error "rename: ~A did not arrive at ~A" from to))
  (when (probe-file from)
    (storage-error "rename: ~A still exists after moving to ~A" from to))
  to)

(defun %path-without-trailing-slash (path)
  "PATH's namestring with a directory's trailing separator removed.

Two callers want exactly this. rename(2) tolerates the slash but some systems
are fussier than others, and SBCL renders every directory pathname with one.
And Core prints a database directory through fs::PathToString, which carries no
trailing separator, so a log line our own path produces has to drop it to read
the way Core's does (dbwrapper.cpp:232/237)."
  (let ((s (namestring path)))
    (if (and (> (length s) 1) (char= #\/ (char s (1- (length s)))))
        (subseq s 0 (1- (length s)))
        s)))

(defun migrate-datadir-layout (data-dir &key dry-run)
  "Move a legacy datadir to Core's layout. Returns the list of (label from to)
moves made (or that WOULD be made under DRY-RUN).

RENAME-FILE is not used for the directories: it merges the target with the
source pathname in ways that have already cost this project a silently
successful no-op (the backupwallet bug). Each move is an explicit
rename-and-verify, and a move whose target already exists is skipped rather
than merged — two block indexes in one datadir is a state no code here expects.

The node must not be running: nothing below coordinates with an open LevelDB
handle, and the caller is responsible for that."
  (let ((moves '()))
    (flet ((move (label from to)
             (when (and (probe-file from) (not (probe-file to)))
               (push (list label from to) moves)
               (unless dry-run
                 (rename-path from to)))))
      ;; blocks/index/headerindex.dat
      (let ((legacy (merge-pathnames "headerindex.dat" data-dir)))
        (when (probe-file legacy)
          (unless dry-run (ensure-directories-exist (datadir-block-index-path data-dir)))
          (move "block index" legacy
                (merge-pathnames "headerindex.dat"
                                 (datadir-block-index-path data-dir)))))
      ;; The indexes.
      (dolist (which '(:txindex :blockfilter :coinstats))
        (let ((legacy (merge-pathnames
                       (cdr (assoc which +legacy-index-subdirectories+)) data-dir))
              (core (merge-pathnames
                     (cdr (assoc which +core-index-subdirectories+)) data-dir)))
          (when (%dir-has-content-p legacy)
            (unless dry-run
              (ensure-directories-exist (uiop:pathname-parent-directory-pathname core)))
            (move (string-downcase (symbol-name which)) legacy core)))))
    ;; undo/ is deliberately NOT moved here: its per-block files are a
    ;; different FORMAT from Core's revNNNNN.dat, not merely a different place.
    ;; `migrateblocks` is what converts them, and it already exists.
    (nreverse moves)))
