(in-package #:bitcoin-lisp.kv)

;;;; Core's data-directory layout (doc/files.md)
;;;;
;;;; Core:
;;;;   blocks/{blkNNNNN.dat, revNNNNN.dat, xor.dat}, blocks/index/
;;;;   chainstate/
;;;;   indexes/txindex/, indexes/blockfilter/basic/{db/,fltrNNNNN.dat},
;;;;   indexes/coinstatsindex/db/, indexes/txospenderindex/db/
;;;;   wallets/
;;;;
;;;; This tree grew a flatter one: undo/ and headerindex.dat at the network-dir
;;;; root, and the four indexes as siblings of blocks/ rather than under
;;;; indexes/. That is not merely cosmetic -- Core's functional tests read and
;;;; delete these paths by name, and since Round 9 the RECORDS in each index
;;;; are Core's, so the directory name was the last thing standing between a
;;;; datadir of ours and Core opening it as its own.
;;;;
;;;; Every index is opened at Core's path and nowhere else. A datadir that
;;;; still has an index at the flat path gets it MOVED there at start-up, once,
;;;; by ADOPT-CORE-INDEX-DIRECTORIES: one rename(2) per index, after the datadir
;;;; lock and before any database opens. Opening Core's path without the move
;;;; would present an EMPTY index to a node that has one and rebuild it from
;;;; genesis (hours on mainnet); keeping a fallback to the flat path, as this
;;;; file did until 2026-09-30, left every such datadir on a layout Core does
;;;; not read.
;;;;
;;;; Audited against Core d3056bc, path by path. Every NAME agrees:
;;;; blocks/ with blkNNNNN.dat, revNNNNN.dat and xor.dat; blocks/index/
;;;; (init.cpp:1140); chainstate/ (validation.cpp:1873) with its snapshot
;;;; sibling chainstate_snapshot/ (utxo_snapshot.h:128) and the _INVALID
;;;; (validation.cpp:6229) and _todelete (:6309) names the snapshot paths use;
;;;; indexes/txindex/ (txindex.cpp:52); indexes/blockfilter/basic/ with db/
;;;; and the fltrNNNNN.dat files beside it (blockfilterindex.cpp:85-89);
;;;; indexes/coinstatsindex/db/ (coinstatsindex.cpp:103-106);
;;;; indexes/txospenderindex/db/ (txospenderindex.cpp:64).
;;;;
;;;; chainstate.dat (and chainstate_snapshot.dat) are ours alone: Core keeps
;;;; the equivalent inside the coins database. headerindex.dat, at the root or
;;;; in blocks/index/, is read only by the one-time migration into the block
;;;; tree database (block-tree-db.lisp), which renames it *.migrated.
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

(defun datadir-block-index-path (data-dir)
  "Core's blocks/index/: the block tree database, a LevelDB (Core BlockTreeDB).
Before 2026-09-24 it held this tree's own headerindex.dat instead, which
DATADIR-HEADER-INDEX-FILE still finds for the one-time migration."
  (merge-pathnames "index/" (merge-pathnames "blocks/" data-dir)))

(defun datadir-header-index-file (data-dir)
  "The FORMER block index file, headerindex.dat: in blocks/index/ after the
datadir-layout migration, at the network-dir root before it. Only the
migration into the block tree database reads it. Returns (values path
legacy-p)."
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
;;;; hours on mainnet, and exactly the failure the move below exists to
;;;; prevent. So the LevelDB is MOVED into db/ the first time such a datadir
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
  :test #'equalp
  :documentation "The flat layout this tree used before 2026-09-30, each index
a sibling of blocks/. Read only by ADOPT-CORE-INDEX-DIRECTORIES, which moves
what it finds there to Core's path.")

(defun datadir-index-path (data-dir which &key migrate)
  "Where index WHICH (:txindex, :blockfilter, :coinstats or :txospenderindex)
lives: Core's path, always (+CORE-INDEX-SUBDIRECTORIES+). A datadir that kept
an index at the flat pre-Core path had it moved here at start-up
 (ADOPT-CORE-INDEX-DIRECTORIES), before anything opens it.

MIGRATE first moves a LevelDB left in the index directory itself into Core's
`db' subdirectory (MIGRATE-INDEX-DB-SUBDIRECTORY). It is off by default so
this stays a pure resolver: the -reindex wipe calls it to name what to delete,
and naming a path must not move anything."
  (when migrate
    (migrate-index-db-subdirectory data-dir which))
  (merge-pathnames (cdr (assoc which +core-index-subdirectories+)) data-dir))

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

;;;; The move from the flat layout to Core's
;;;;
;;;; Both live nodes kept their indexes at the flat pre-Core paths (testnet4's
;;;; txindex alone is 1.4 GB), and Core opens them only at its own. A rename is
;;;; the whole migration: the records have been Core's since Round 9, so the
;;;; directory is moved as it is, in one rename(2) per index -- atomic on one
;;;; file system, seconds whatever the size -- and nothing is rebuilt.

(alexandria:define-constant +index-display-names+
  '((:txindex . "txindex")
    (:blockfilter . "basic block filter index")
    (:coinstats . "coinstatsindex")
    (:txospenderindex . "txospenderindex"))
  :test #'equalp
  :documentation "Each index's name as Core's GetName() gives it (txindex.cpp,
blockfilterindex.cpp:79, coinstatsindex.cpp:91, txospenderindex.cpp:64), the
name the move's log lines and its refusal use.")

(defun %tree-holds-a-file-p (dir)
  "T when some FILE exists anywhere under DIR. An index directory holding only
empty directories (ENSURE-DIRECTORIES-EXIST makes them freely) holds no index."
  (and dir
       (uiop:directory-exists-p dir)
       (block found
         (uiop:collect-sub*directories
          dir t t (lambda (d) (when (uiop:directory-files d) (return-from found t))))
         nil)))

(defun %durable-rename (from to)
  "RENAME-PATH, then fsync both parent directories: the rename is recorded in
the directory entries, and a move the operator was told about must survive a
crash (Core's RenameOver callers follow it with DirectoryCommit)."
  (rename-path from to)
  (fsync-parent-directory (%path-without-trailing-slash from))
  (fsync-parent-directory (%path-without-trailing-slash to)))

(defun %core-index-root (data-dir which)
  "The directory index WHICH owns at Core's path: indexes/txindex/ itself, or
the parent of the other three's db/ -- the filter index's fltr files live
there, so it is part of the index as much as db/ is."
  (or (%index-db-parent data-dir which)
      (merge-pathnames (cdr (assoc which +core-index-subdirectories+)) data-dir)))

(defun %lift-filter-files (data-dir)
  "Move any fltrNNNNN.dat file from indexes/blockfilter/basic/db/ up into
basic/, where Core's FlatFileSeq keeps them (blockfilterindex.cpp:85-89: the
sequence is rooted at basic/, the database at basic/db). Returns the files
moved as (from . to) pairs.

The flat blockfilterindex/ directory held the LevelDB AND the fltr files side
by side (BLOCKFILTERINDEX's %BFI-FLTR-DIRECTORY roots the sequence at the
database's own directory in that layout), so the rename into db/ carries the
filters one level too deep. Run on every start, not only after a rename: a
crash between the rename and the lift is finished by the next start.

A file already at the target name is a second copy of a filter file, and the
start is refused rather than one of them being picked."
  (let* ((basic (%index-db-parent data-dir :blockfilter))
         (db (merge-pathnames "db/" basic))
         (moved '()))
    (dolist (from (and (uiop:directory-exists-p db)
                       (directory (merge-pathnames "fltr?????.dat" db))))
      (let ((to (merge-pathnames (file-namestring from) basic)))
        (when (probe-file to)
          (init-error "Block filter file ~A exists both in ~A and in ~A. ~
Remove the copy that does not belong to the index and restart; nothing was moved."
                      (file-namestring from)
                      (%path-without-trailing-slash db)
                      (%path-without-trailing-slash basic)))
        (%durable-rename from to)
        (push (cons from to) moved)))
    (nreverse moved)))

(defun adopt-core-index-directories (data-dir)
  "Move every index DATA-DIR still keeps at the flat pre-Core path
 (+LEGACY-INDEX-SUBDIRECTORIES+) to Core's (+CORE-INDEX-SUBDIRECTORIES+), and
the filter index's fltr files up beside its db/ (%LIFT-FILTER-FILES). Returns
the moves made as (label from to) lists, the fltr files counted as one move of
the filter index; NIL on a datadir already in Core's shape, which is every
fresh one.

Idempotent: once moved, the flat path is gone and the next call finds nothing
to do. An EMPTY flat directory is removed rather than moved.

An index at BOTH paths -- a file under the flat directory and a file under
Core's -- refuses the start with an INIT-ERROR naming both: they are two
databases for one index, and choosing one silently is how a node serves
records it did not mean to. Nothing is moved in that case.

The node must hold the datadir lock and no index may be open: a rename under
an open LevelDB leaves it writing new tables at the old path. START-NODE calls
this right after LOCK-DATA-DIRECTORIES."
  (let ((moves '())
        (plan '()))
    ;; Every refusal before any move, so a refusal really leaves nothing moved.
    (dolist (which '(:txindex :blockfilter :coinstats :txospenderindex))
      (let ((label (cdr (assoc which +index-display-names+)))
            (legacy (merge-pathnames
                     (cdr (assoc which +legacy-index-subdirectories+)) data-dir))
            (root (%core-index-root data-dir which)))
        (when (%tree-holds-a-file-p legacy)
          (when (or (%tree-holds-a-file-p root)
                    (%tree-holds-a-file-p (%index-db-staging-path root)))
            (init-error "The ~A exists both at ~A, where this node kept it before, ~
and at ~A, where Bitcoin Core keeps it. Remove the one you do not want to keep ~
and restart; nothing was moved."
                        label
                        (%path-without-trailing-slash legacy)
                        (%path-without-trailing-slash root)))
          (push (list which label legacy root) plan))))
    (dolist (which '(:txindex :blockfilter :coinstats :txospenderindex))
      (let ((legacy (merge-pathnames
                     (cdr (assoc which +legacy-index-subdirectories+)) data-dir)))
        (when (and (uiop:directory-exists-p legacy)
                   (not (find which plan :key #'first)))
          (uiop:delete-directory-tree legacy :validate t))))
    (loop for (which label legacy root) in (nreverse plan)
          for core = (merge-pathnames
                      (cdr (assoc which +core-index-subdirectories+)) data-dir)
          do (when (uiop:directory-exists-p root)
               (uiop:delete-directory-tree root :validate t))
             (%durable-rename legacy core)
             (push (list label legacy core) moves))
    (let ((lifted (%lift-filter-files data-dir)))
      (when lifted
        (push (list "basic block filter index's filter files"
                    (uiop:pathname-directory-pathname (car (first lifted)))
                    (uiop:pathname-directory-pathname (cdr (first lifted))))
              moves)))
    (nreverse moves)))
