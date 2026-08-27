(in-package #:bitcoin-lisp.storage)

;;;; base-index (Core index/base.h BaseIndex)
;;;
;;; Four indexes -- txindex, txospenderindex, blockfilterindex, coinstatsindex
;;; -- each keep a LevelDB, a best-block marker, a connect-time write, a
;;; disconnect-time erase and a startup catch-up, and until this file each
;;; re-implemented that skeleton, with a third and fourth copy of the
;;; catch-up living in node.lisp. BASE-INDEX is the shared state and the
;;; generic functions below are the protocol the node drives them through:
;;; one catch-up driver, one connect hook, one disconnect hook, whatever the
;;; number of indexes. Adding an index is its file plus its methods.
;;;
;;; What differs per index (key layouts, meta encodings, what a block
;;; contributes) stays in the index's own file, as its methods.

(defstruct (base-index (:constructor nil) (:copier nil) (:predicate nil))
  "What every index shares: where its LevelDB lives, the open handle (NIL
until INIT-* opens it, and for a disabled index), and whether it is on.
Never instantiated directly; the indexes :INCLUDE it."
  (base-path nil :type (or null pathname))
  (db nil)
  (enabled nil :type boolean))

(defgeneric index-name (index)
  (:documentation "The index's name as Core spells it: \"txindex\", ..."))

(defgeneric index-height (index chainstate)
  (:documentation "The highest height INDEX has indexed contiguously from
genesis, or -1. CHAINSTATE lets an index whose marker is a hash only (the
txindex, like Core's locator) resolve it against the active chain."))

(defgeneric index-best-block (index)
  (:documentation "(values block-hash height) of the highest indexed block,
or NIL when nothing has been indexed."))

(defgeneric index-set-best (index block-hash height)
  (:documentation "Record BLOCK-HASH/HEIGHT as the highest indexed block
(Core BaseIndex's locator)."))

(defgeneric index-clear-best (index)
  (:documentation "Forget the best-block marker, so the next catch-up
rebuilds from genesis."))

(defgeneric index-write-block (index chainstate block block-hash height spent-utxos)
  (:documentation "Fold BLOCK, connected at HEIGHT with SPENT-UTXOS as its
undo list, into the index (Core CustomAppend). Returns (values result status);
a STATUS of :noncontiguous means the index refused a block above a gap and
waits for the startup catch-up. May signal; the node's hook catches."))

(defgeneric index-rewind-block (index chainstate block block-hash height)
  (:documentation "Erase what INDEX-WRITE-BLOCK wrote for BLOCK, on
disconnect (Core CustomRemove). Default: nothing, for indexes keyed by height
whose records the next connect overwrites.")
  (:method ((index base-index) chainstate block block-hash height)
    (declare (ignore chainstate block block-hash height))
    nil))

(defgeneric index-prepare-sync (index chainstate block-store)
  (:documentation "Make the best marker trustworthy before a catch-up builds
on it: repair one left above the tip, rewind one off the active chain
(Core BaseIndex::Rewind / the CustomInit checks). Default: nothing.")
  (:method ((index base-index) chainstate block-store)
    (declare (ignore chainstate block-store))
    nil))

(defgeneric index-sync (index chainstate block-store &key undo-fn subsidy-fn progress)
  (:documentation "Backfill from just past the best marker to CHAINSTATE's tip
(Core BaseIndex::Sync). UNDO-FN maps a block hash to its undo data and
SUBSIDY-FN a height to its subsidy, for the indexes that need them; PROGRESS
is called with (height percent). Returns how many blocks (or entries) were
added."))
