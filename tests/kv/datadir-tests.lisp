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
  "The resolver is also what DATADIR-LAYOUT-REPORT calls to say what a datadir
looks like. A report that migrated the thing it is reporting on would be a
side effect nobody asked for, so the move is behind :MIGRATE."
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
      (multiple-value-bind (path legacy-p)
          (bl.store:datadir-index-path dir :blockfilter :migrate t)
        (is-false legacy-p)
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

(test an-index-on-the-flat-pre-core-path-still-wins-the-fallback
  "The layout has two migrations stacked on it now. A node that never moved to
indexes/ at all keeps resolving to its flat directory: the db/ move must not
quietly create an empty Core-side database that beats it."
  (%with-datadir (dir "flat")
    (%dd-fake-leveldb (merge-pathnames "blockfilterindex/" dir) "flat-records")
    (multiple-value-bind (path legacy-p)
        (bl.store:datadir-index-path dir :blockfilter :migrate t)
      (is-true legacy-p "the flat legacy index lost its fallback")
      (is (equal "flat-records" (%dd-file-text (merge-pathnames "000003.log" path)))))))

(test migrate-datadir-layout-moves-a-flat-index-into-core-s-db-directory
  "-migratedatadir is the operator's explicit move, and its target is the same
constant. It has to land on the db/ directory, not on its parent."
  (%with-datadir (dir "explicit")
    (%dd-fake-leveldb (merge-pathnames "blockfilterindex/" dir) "flat-records")
    (bl.store:migrate-datadir-layout dir)
    (is (equal "flat-records"
               (%dd-file-text (merge-pathnames "indexes/blockfilter/basic/db/000003.log"
                                               dir))))
    (is-false (bl.store:datadir-layout-report dir)
              "the layout report still names a legacy directory after the move")))
