(in-package #:bitcoin-lisp.storage)

;;;; Core's data-directory layout (doc/files.md)
;;;;
;;;; Core:
;;;;   blocks/{blkNNNNN.dat, revNNNNN.dat, xor.dat}, blocks/index/
;;;;   chainstate/
;;;;   indexes/txindex/, indexes/blockfilter/basic/, indexes/coinstatsindex/
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
;;;; governs the network-subdirectory choice in node.lisp.

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

(defparameter +core-index-subdirectories+
  '((:txindex . "indexes/txindex/")
    (:blockfilter . "indexes/blockfilter/basic/")
    (:coinstats . "indexes/coinstatsindex/")
    ;; Core nests this one a level deeper than the others — the DB lives at
    ;; indexes/txospenderindex/db (index/txospenderindex.cpp:64).
    (:txospenderindex . "indexes/txospenderindex/db/"))
  "Core doc/files.md's index paths.")

(defparameter +legacy-index-subdirectories+
  '((:txindex . "txindex/")
    (:blockfilter . "blockfilterindex/")
    (:coinstats . "coinstatsindex/")
    (:txospenderindex . "txospenderindex/"))
  "The flat layout this tree used before.")

(defun datadir-index-path (data-dir which)
  "Where index WHICH (:txindex, :blockfilter, :coinstats or
:txospenderindex) lives. Returns
 (values path legacy-p)."
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

(defun %rename-path (from to)
  "Move FROM to TO, file or directory, and VERIFY it arrived.

rename(2) rather than CL's RENAME-FILE, which merges the target with the source
pathname — a surprise that has already produced one silently successful no-op
in this project (backupwallet reported success and wrote nothing). uiop's
rename-file-overwriting-target refuses a directory outright, and half of what
moves here is a directory.

The verification is not ceremony: a migration that reports success and moved
nothing is exactly the failure this comment is about."
  (ensure-directories-exist (uiop:pathname-parent-directory-pathname
                             (uiop:ensure-directory-pathname to)))
  (sb-posix:rename (%rename-namestring from) (%rename-namestring to))
  (unless (probe-file to)
    (error "datadir migration: ~A did not arrive at ~A" from to))
  (when (probe-file from)
    (error "datadir migration: ~A still exists after moving to ~A" from to))
  to)

(defun %rename-namestring (path)
  "PATH as a namestring rename(2) accepts: a directory's trailing slash is
harmless, but SBCL renders a directory pathname with one and some systems are
fussier than others, so it goes."
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
                 (%rename-path from to)))))
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
