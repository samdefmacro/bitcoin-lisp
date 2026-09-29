(in-package #:bitcoin-lisp.tests)

;;;; The datadir's index layout and the move into Core's `db' subdirectory.
;;;;
;;;; Core opens three of its four indexes one level below the index directory:
;;;; indexes/blockfilter/basic/db (index/blockfilterindex.cpp:88),
;;;; indexes/coinstatsindex/db (index/coinstatsindex.cpp:106) and
;;;; indexes/txospenderindex/db (index/txospenderindex.cpp:64). The txindex is
;;;; the exception: index/txindex.cpp:52 hands BaseIndex::DB the bare
;;;; indexes/txindex.
;;;;
;;;; feature_reindex.py:94 addresses the filter index's database by that exact
;;;; name, so this is not cosmetic -- and a node that already has the database
;;;; one level up must be MOVED rather than told to rebuild from genesis.

(def-suite :datadir-layout-tests
  :description "Core's datadir index layout (doc/files.md) and its migrations"
  :in :bitcoin-lisp-tests)

(in-suite :datadir-layout-tests)

(defun %dd-temp-dir (tag)
  "A fresh empty directory for one datadir test."
  (let ((dir (merge-pathnames (format nil "bl-dd-~A-~D/" tag (get-internal-real-time))
                              (uiop:temporary-directory))))
    (ensure-directories-exist dir)
    dir))

(defun %dd-fake-leveldb (dir &optional (payload "manifest"))
  "Make DIR look like a LevelDB to the layout code: CURRENT is what leveldb
writes last and reads first, so it is what says `a database lives here'.
PAYLOAD is written beside it, so a move can be shown to carry the data and not
just the marker."
  (ensure-directories-exist dir)
  (with-open-file (out (merge-pathnames "CURRENT" dir)
                       :direction :output :if-exists :supersede)
    (write-line "MANIFEST-000001" out))
  (with-open-file (out (merge-pathnames "000003.log" dir)
                       :direction :output :if-exists :supersede)
    (write-line payload out))
  dir)

(defun %dd-file-text (path)
  "The first line of PATH, or NIL when it is not there."
  (when (probe-file path)
    (with-open-file (in path) (read-line in nil nil))))

(defmacro %with-datadir ((var tag) &body body)
  `(let ((,var (%dd-temp-dir ,tag)))
     (unwind-protect (progn ,@body)
       (ignore-errors (uiop:delete-directory-tree ,var :validate t
                                                       :if-does-not-exist :ignore)))))

;;; --- The layout itself ------------------------------------------------------

(test a-fresh-datadir-puts-each-index-where-core-opens-it
  "Core's paths, read off the constructor of each index. Three nest the
database in db/ and the txindex does not; ours must agree on both halves, or a
functional test that deletes or inspects a database by name is addressing a
directory this node never writes."
  (%with-datadir (dir "fresh")
    (is (search "indexes/blockfilter/basic/db/"
                (namestring (bl.store:datadir-index-path dir :blockfilter))))
    (is (search "indexes/coinstatsindex/db/"
                (namestring (bl.store:datadir-index-path dir :coinstats))))
    (is (search "indexes/txospenderindex/db/"
                (namestring (bl.store:datadir-index-path dir :txospenderindex))))
    ;; The exception, and it is an exception in Core too.
    (let ((tx (namestring (bl.store:datadir-index-path dir :txindex))))
      (is (search "indexes/txindex/" tx))
      (is-false (search "indexes/txindex/db/" tx)
                "the txindex must NOT be nested: Core opens the bare directory"))))

(test datadir-index-path-does-not-move-anything-by-default
  "The resolver is also what the -reindex wipe calls to name the directory it
deletes. Naming a path must not move anything, so the move is behind :MIGRATE."
  (%with-datadir (dir "pure")
    (let ((old (merge-pathnames "indexes/blockfilter/basic/" dir)))
      (%dd-fake-leveldb old)
      (bl.store:datadir-index-path dir :blockfilter)
      (is-true (probe-file (merge-pathnames "CURRENT" old))
               "resolving without :migrate moved the database")
      (is-false (probe-file (merge-pathnames "db/CURRENT" old))))))

;;; --- The move ---------------------------------------------------------------

(test a-filter-index-left-above-db-is-moved-into-it
  "Both live nodes have a populated filter index at indexes/blockfilter/basic/.
Correcting the constant alone would present them with an EMPTY database and
rebuild the index from genesis, so the database is moved instead -- and the
move has to carry the data, not merely create the directory."
  (%with-datadir (dir "move")
    (let ((old (merge-pathnames "indexes/blockfilter/basic/" dir)))
      (%dd-fake-leveldb old "the-real-records")
      (let ((path (bl.store:datadir-index-path dir :blockfilter :migrate t)))
        (is (search "indexes/blockfilter/basic/db/" (namestring path)))
        (is (equal "the-real-records"
                   (%dd-file-text (merge-pathnames "000003.log" path)))
            "the move created the directory but left the records behind")
        (is-true (probe-file (merge-pathnames "CURRENT" path)))
        ;; The old location must not still look like a database, or the next
        ;; start sees two of them and refuses to choose.
        (is-false (probe-file (merge-pathnames "CURRENT" old))
                  "the database is still readable at the pre-move path")
        ;; And nothing is left parked under the staging name.
        (is-false (probe-file (merge-pathnames "indexes/blockfilter/basic.migrating/"
                                               dir)))))))

(test the-coinstatsindex-moves-into-db-the-same-way
  "coinstatsindex.cpp:106 nests the database exactly as blockfilterindex.cpp:88
does, and this tree got both of them wrong in the same way."
  (%with-datadir (dir "csmove")
    (let ((old (merge-pathnames "indexes/coinstatsindex/" dir)))
      (%dd-fake-leveldb old "coinstats-records")
      (let ((path (bl.store:datadir-index-path dir :coinstats :migrate t)))
        (is (search "indexes/coinstatsindex/db/" (namestring path)))
        (is (equal "coinstats-records"
                   (%dd-file-text (merge-pathnames "000003.log" path))))
        (is-false (probe-file (merge-pathnames "CURRENT" old)))))))

(test an-already-migrated-datadir-is-left-alone
  "The control. A datadir already in Core's shape must come out byte for byte
as it went in -- a migration that re-ran would move a live database out from
under the handle that is about to open it."
  (%with-datadir (dir "already")
    (let* ((parent (merge-pathnames "indexes/blockfilter/basic/" dir))
           (db (merge-pathnames "db/" parent)))
      (%dd-fake-leveldb db "already-here")
      (is-false (bl.store:migrate-index-db-subdirectory dir :blockfilter)
                "an already-migrated datadir reported a move")
      (let ((path (bl.store:datadir-index-path dir :blockfilter :migrate t)))
        (is (equal (namestring db) (namestring path)))
        (is (equal "already-here"
                   (%dd-file-text (merge-pathnames "000003.log" db))))
        (is-false (probe-file (merge-pathnames "CURRENT" parent))
                  "the move ran and lifted the database back out of db/")))))

(test a-fresh-datadir-has-nothing-to-migrate
  "The other control: an empty datadir, and a txindex, whose database Core does
not nest at all. Neither may report a move."
  (%with-datadir (dir "nothing")
    (is-false (bl.store:migrate-index-db-subdirectory dir :blockfilter))
    (is-false (bl.store:migrate-index-db-subdirectory dir :coinstats))
    (%dd-fake-leveldb (merge-pathnames "indexes/txindex/" dir))
    (is-false (bl.store:migrate-index-db-subdirectory dir :txindex)
              "the txindex was nested; Core opens indexes/txindex itself")))

(test an-interrupted-index-move-is-finished-by-the-next-open
  "A directory cannot be renamed into its own child, so the move is two
rename(2) calls with a staging name between them. A crash in the gap leaves
the staging directory and no index directory at all; the next open must finish
the move rather than start a rebuild from genesis."
  (%with-datadir (dir "resume")
    (let ((staging (merge-pathnames "indexes/blockfilter/basic.migrating/" dir))
          (db (merge-pathnames "indexes/blockfilter/basic/db/" dir)))
      (%dd-fake-leveldb staging "interrupted-records")
      (let ((path (bl.store:datadir-index-path dir :blockfilter :migrate t)))
        (is (equal (namestring db) (namestring path)))
        (is (equal "interrupted-records"
                   (%dd-file-text (merge-pathnames "000003.log" db)))
            "the interrupted move was not finished")
        (is-false (probe-file (merge-pathnames "CURRENT" staging)))))))

(test two-databases-for-one-index-are-left-alone
  "Nothing here expects one index to have two databases, and picking one of
them silently is how a node serves records it rebuilt over records it had.
Core's path wins the resolution and neither directory is touched."
  (%with-datadir (dir "both")
    (let* ((parent (merge-pathnames "indexes/blockfilter/basic/" dir))
           (db (merge-pathnames "db/" parent)))
      (%dd-fake-leveldb parent "above")
      (%dd-fake-leveldb db "below")
      (is-false (bl.store:migrate-index-db-subdirectory dir :blockfilter)
                "two databases were merged")
      (is (equal "above" (%dd-file-text (merge-pathnames "000003.log" parent))))
      (is (equal "below" (%dd-file-text (merge-pathnames "000003.log" db))))
      (is (equal (namestring db)
                 (namestring (bl.store:datadir-index-path dir :blockfilter
                                                              :migrate t)))))))

;;; --- The flat pre-Core layout, moved to Core's at start-up ------------------
;;;
;;; Both live nodes kept their indexes as siblings of blocks/ (txindex/,
;;; blockfilterindex/, coinstatsindex/, txospenderindex/) and the resolver fell
;;; back to them. Core opens only its own paths (txindex.cpp:52,
;;; blockfilterindex.cpp:85-89, coinstatsindex.cpp:103-106,
;;; txospenderindex.cpp:64), so a datadir of ours was Core's in every record
;;; and still not in its directory names. Start-up now renames each one.

(defun %dd-flat-layout (dir)
  "A datadir in this tree's flat pre-Core layout, every index populated, the
filter index with two fltr files beside its LevelDB as Round 9 wrote them."
  (%dd-fake-leveldb (merge-pathnames "txindex/" dir) "tx-records")
  (%dd-fake-leveldb (merge-pathnames "blockfilterindex/" dir) "filter-records")
  (dolist (name '("fltr00000.dat" "fltr00001.dat"))
    (with-open-file (out (merge-pathnames (concatenate 'string "blockfilterindex/" name) dir)
                         :direction :output :if-exists :supersede)
      (write-line name out)))
  (%dd-fake-leveldb (merge-pathnames "coinstatsindex/" dir) "coinstats-records")
  (%dd-fake-leveldb (merge-pathnames "txospenderindex/" dir) "spender-records")
  dir)

(test the-resolver-names-core-s-path-even-beside-a-flat-index
  "The fallback is gone: a flat index is moved at start-up, so the resolver
names Core's directory whatever the datadir holds. Before 2026-09-30 it
answered the flat txindex/ here, and the node kept serving from a path Core
never opens."
  (%with-datadir (dir "noflat")
    (%dd-flat-layout dir)
    (is (search "indexes/txindex/"
                (namestring (bl.store:datadir-index-path dir :txindex)))
        "the resolver fell back to the flat txindex/")
    (is (search "indexes/blockfilter/basic/db/"
                (namestring (bl.store:datadir-index-path dir :blockfilter))))))

(test flat-indexes-are-moved-to-core-s-paths-with-their-records
  "Every index arrives at Core's path WITH its records, the filter index's
fltr files beside db/ where Core's FlatFileSeq is rooted and not inside it,
and nothing is left at the flat names. A second call is a no-op."
  (%with-datadir (dir "adopt")
    (%dd-flat-layout dir)
    (let ((moves (bl.store:adopt-core-index-directories dir)))
      (is (= 5 (length moves)) "moves: ~S" moves))
    (flet ((text (rel) (%dd-file-text (merge-pathnames rel dir))))
      (is (equal "tx-records" (text "indexes/txindex/000003.log")))
      (is (equal "filter-records" (text "indexes/blockfilter/basic/db/000003.log")))
      (is (equal "coinstats-records" (text "indexes/coinstatsindex/db/000003.log")))
      (is (equal "spender-records" (text "indexes/txospenderindex/db/000003.log")))
      (is (equal "fltr00001.dat" (text "indexes/blockfilter/basic/fltr00001.dat"))
          "a fltr file did not arrive beside db/")
      (is-false (text "indexes/blockfilter/basic/db/fltr00000.dat")
                "a fltr file was left inside db/, where Core's sequence never looks"))
    (dolist (flat '("txindex/" "blockfilterindex/" "coinstatsindex/" "txospenderindex/"))
      (is-false (probe-file (merge-pathnames flat dir))
                "~A is still there after the move" flat))
    (is-false (bl.store:adopt-core-index-directories dir)
              "a second start moved something again")))

(test empty-core-directories-do-not-block-the-move
  "ENSURE-DIRECTORIES-EXIST makes empty directories freely; an empty
indexes/txindex/ or basic/db/ is not a second index, and must not refuse the
start of a node whose flat index holds the records."
  (%with-datadir (dir "emptycore")
    (%dd-fake-leveldb (merge-pathnames "txindex/" dir) "tx-records")
    (%dd-fake-leveldb (merge-pathnames "blockfilterindex/" dir) "filter-records")
    (ensure-directories-exist (merge-pathnames "indexes/txindex/" dir))
    (ensure-directories-exist (merge-pathnames "indexes/blockfilter/basic/db/" dir))
    (bl.store:adopt-core-index-directories dir)
    (is (equal "tx-records"
               (%dd-file-text (merge-pathnames "indexes/txindex/000003.log" dir))))
    (is (equal "filter-records"
               (%dd-file-text (merge-pathnames "indexes/blockfilter/basic/db/000003.log"
                                               dir))))))

(test an-index-at-both-paths-refuses-the-start-and-moves-nothing
  "Two databases for one index: the start is refused with a sentence naming
both directories, and neither is touched. The control is the move above,
which the same flat directory makes when Core's path is empty."
  (%with-datadir (dir "bothpaths")
    (%dd-fake-leveldb (merge-pathnames "txindex/" dir) "flat")
    (%dd-fake-leveldb (merge-pathnames "indexes/txindex/" dir) "core")
    (let ((message (handler-case (progn (bl.store:adopt-core-index-directories dir) nil)
                     (bl.err:init-error (e) (princ-to-string e)))))
      (is-true message "an index at both paths did not refuse the start")
      (is-true (and message (search "exists both at" message)))
      (is-true (and message (search (namestring (merge-pathnames "txindex" dir)) message))))
    (is (equal "flat" (%dd-file-text (merge-pathnames "txindex/000003.log" dir))))
    (is (equal "core" (%dd-file-text (merge-pathnames "indexes/txindex/000003.log" dir))))))

(test fltr-files-left-inside-db-are-lifted-by-the-next-start
  "The rename into db/ and the lift of the fltr files are two steps; a crash
between them leaves the filters inside db/, and the next start finishes the
job rather than the filter index finding its sequence empty."
  (%with-datadir (dir "lift")
    (let ((db (merge-pathnames "indexes/blockfilter/basic/db/" dir)))
      (%dd-fake-leveldb db "filter-records")
      (with-open-file (out (merge-pathnames "fltr00000.dat" db)
                           :direction :output :if-exists :supersede)
        (write-line "filters" out))
      (is (= 1 (length (bl.store:adopt-core-index-directories dir))))
      (is (equal "filters"
                 (%dd-file-text (merge-pathnames "indexes/blockfilter/basic/fltr00000.dat"
                                                 dir))))
      (is (equal "filter-records" (%dd-file-text (merge-pathnames "000003.log" db)))))))

(test start-up-moves-the-indexes-after-the-lock-and-before-any-open
  "The rename is safe only while no LevelDB has the directory open: after
LOCK-DATA-DIRECTORIES (a second node on a running node's datadir is refused
first) and before the chain load, whose -reindex wipe names the indexes by
Core's path. The pre-Core layout warning this replaces is gone with it."
  (let* ((src (%node-source-text))
         (lock (search "(%init-lock-and-banner network" src))
         (move (search "(%init-index-directories)" src))
         (load (search "(%init-load-chain network" src)))
    (is-true lock) (is-true move) (is-true load)
    (is-true (and lock move load (< lock move load))
             "the index directories move outside the lock-to-load window")
    (is-false (search "pre-Core layout for:" src)
              "start-up still warns about a layout it now moves")))
