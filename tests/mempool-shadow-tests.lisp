(in-package #:bitcoin-lisp.tests)

;;;; Cluster mempool P3: shadow-mode txgraph maintenance
;;;;
;;;; The mempool mirrors every mutation into its shadow txgraph
;;;; (src/mempool/mempool.lisp), and *txgraph-shadow-checks* - enabled
;;;; suite-wide in tests/package.lisp - asserts full graph/BFS equivalence
;;;; after every operation, so most coverage here is implicit: any
;;;; divergence on any path errors the test that triggered it. These tests
;;;; drive the specific sequences the plan calls out (add/remove/replace,
;;;; block-confirmation cluster splitting, block conflicts, a reorg re-add
;;;; cycle, mempool.dat reload, prioritisation, the cluster limits at
;;;; acceptance, and a seeded randomized op mix) and assert the resulting
;;;; graph state directly.

(def-suite :mempool-shadow-tests
  :description "Mempool/txgraph shadow-mode equivalence (cluster mempool P3)"
  :in :bitcoin-lisp-tests)

(in-suite :mempool-shadow-tests)

;;;; Helpers

(defun %shp-hash (tx) (bitcoin-lisp.serialization:transaction-hash tx))

(defun %shp-graph (mempool) (bitcoin-lisp.mempool:mempool-graph mempool))

(defun %shp-handle (mempool txid)
  (bitcoin-lisp.mempool:mempool-entry-graph-handle
   (bitcoin-lisp.mempool:mempool-get mempool txid)))

(defun %shp-outpoint-hash (n)
  "A 32-byte outpoint hash derived from integer N (supports N > 255)."
  (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref h 0) (ldb (byte 8 0) n)
          (aref h 1) (ldb (byte 8 8) n)
          (aref h 2) #xAB)                ; distinct from other test tx spaces
    h))

(defun %shp-spk ()
  (let ((s (make-array 25 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref s 0) #x76 (aref s 1) #xa9 (aref s 2) #x14
          (aref s 23) #x88 (aref s 24) #xac)
    s))

(defun %shp-tx (outpoints &key (value 40000000))
  "A tx spending OUTPOINTS, a list of (hash . index) conses."
  (bitcoin-lisp.serialization:make-transaction
   :version 1
   :inputs (map 'vector
                (lambda (op)
                  (bitcoin-lisp.serialization:make-tx-in
                   :previous-output (bitcoin-lisp.serialization:make-outpoint
                                     :hash (car op) :index (cdr op))
                   :script-sig (make-array 10 :element-type '(unsigned-byte 8)
                                              :initial-element 0)
                   :sequence #xFFFFFFFF))
                outpoints)
   :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                     :value value :script-pubkey (%shp-spk)))
   :lock-time 0))

(defun %shp-root-tx (n &key (value 50000000))
  "A root tx (confirmed-input spend) unique to integer N."
  (%shp-tx (list (cons (%shp-outpoint-hash n) 0)) :value value))

(defun %shp-add (mempool tx &key (fee 10000))
  (bitcoin-lisp.mempool:mempool-add
   mempool (%shp-hash tx)
   (bitcoin-lisp.mempool:make-entry-from-tx tx fee 0 :entry-time 1000000)))

(defun %shp-block (txs)
  "A block containing TXS, sufficient for mempool-remove-for-block."
  (bitcoin-lisp.serialization:make-bitcoin-block
   :header (bitcoin-lisp.serialization:make-block-header
            :version 1
            :prev-block (make-array 32 :element-type '(unsigned-byte 8)
                                       :initial-element 0)
            :merkle-root (make-array 32 :element-type '(unsigned-byte 8)
                                        :initial-element 0)
            :timestamp 1000000 :bits #x1d00ffff :nonce 0)
   :transactions txs))

(defun %shp-verify (mempool)
  "Run the full shadow verification directly; T if it did not error."
  (bitcoin-lisp.mempool::%mempool-graph-verify mempool)
  t)

(defun %shp-equiv-p (mempool txid)
  "Graph ancestor/descendant txid sets = BFS sets (plus self), checked
independently of the mempool's own shadow asserts."
  (let* ((graph (%shp-graph mempool))
         (handle (%shp-handle mempool txid)))
    (flet ((graph-txids (handles)
             (sort (mapcar #'bitcoin-lisp.mempool:tx-handle-data handles)
                   #'%shp-txid<))
           (bfs-txids (set)
             (let ((ids (list txid)))
               (maphash (lambda (k v) (declare (ignore v)) (push k ids)) set)
               (sort ids #'%shp-txid<))))
      (and (equalp (graph-txids (bitcoin-lisp.mempool:txgraph-get-ancestors
                                 graph handle))
                   (bfs-txids (bitcoin-lisp.mempool:mempool-ancestors
                               mempool txid)))
           (equalp (graph-txids (bitcoin-lisp.mempool:txgraph-get-descendants
                                 graph handle))
                   (bfs-txids (bitcoin-lisp.mempool:mempool-descendants
                               mempool txid)))))))

(defun %shp-txid< (a b)
  (loop for i from 0 below 32
        for d = (- (aref a i) (aref b i))
        unless (zerop d) return (minusp d)
        finally (return nil)))

;;;; Add / remove / replace

(test shadow-add-builds-clusters
  "Adds mirror into the graph: handles live, dependencies wired, clusters
formed."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (graph (%shp-graph mempool))
         (a (%shp-root-tx 1))
         (b (%shp-tx (list (cons (%shp-hash a) 0))))
         (c (%shp-tx (list (cons (%shp-hash b) 0))))
         (lone (%shp-root-tx 2)))
    (is (eq :ok (%shp-add mempool a)))
    (is (= 1 (bitcoin-lisp.mempool:txgraph-tx-count graph)))
    (is (bitcoin-lisp.mempool:txgraph-exists-p
         graph (%shp-handle mempool (%shp-hash a))))
    (is (equalp (%shp-hash a)
                (bitcoin-lisp.mempool:tx-handle-data
                 (%shp-handle mempool (%shp-hash a)))))
    (is (eq :ok (%shp-add mempool b)))
    (is (eq :ok (%shp-add mempool c)))
    (is (eq :ok (%shp-add mempool lone)))
    (is (= 4 (bitcoin-lisp.mempool:txgraph-tx-count graph)))
    ;; c's ancestors are the whole chain; the chain is one cluster, the
    ;; lone root another.
    (is (= 3 (length (bitcoin-lisp.mempool:txgraph-get-ancestors
                      graph (%shp-handle mempool (%shp-hash c))))))
    (is (= 3 (length (bitcoin-lisp.mempool:txgraph-get-cluster
                      graph (%shp-handle mempool (%shp-hash a))))))
    (is (= 2 (bitcoin-lisp.mempool:txgraph-count-distinct-clusters
              graph (list (%shp-handle mempool (%shp-hash a))
                          (%shp-handle mempool (%shp-hash lone))))))
    (is (%shp-equiv-p mempool (%shp-hash c)))))

(test shadow-remove-and-replace
  "Leaf removal, recursive removal, and an RBF-style replacement all keep
the graph in step."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (graph (%shp-graph mempool))
         (a (%shp-root-tx 3))
         (b (%shp-tx (list (cons (%shp-hash a) 0)) :value 30000000))
         (c (%shp-tx (list (cons (%shp-hash b) 0)))))
    (%shp-add mempool a)
    (%shp-add mempool b :fee 5000)
    (%shp-add mempool c)
    ;; Plain removal of the childless leaf.
    (let ((c-handle (%shp-handle mempool (%shp-hash c))))
      (bitcoin-lisp.mempool:mempool-remove mempool (%shp-hash c))
      (is (not (bitcoin-lisp.mempool:txgraph-exists-p graph c-handle)))
      (is (= 2 (bitcoin-lisp.mempool:txgraph-tx-count graph))))
    ;; RBF-style replacement of b by b2 (same outpoint, higher fee) through
    ;; the shared acceptance tail.
    (let ((b-handle (%shp-handle mempool (%shp-hash b)))
          (b2 (%shp-tx (list (cons (%shp-hash a) 0)) :value 20000000)))
      (multiple-value-bind (result entry)
          (bitcoin-lisp.mempool:accept-validated-tx
           mempool (%shp-hash b2) b2 15000 0 :replaced (list (%shp-hash b)))
        (is (eq :ok result))
        (is (not (bitcoin-lisp.mempool:txgraph-exists-p graph b-handle)))
        (is (= 2 (bitcoin-lisp.mempool:txgraph-tx-count graph)))
        ;; b2 is wired under a.
        (is (= 2 (length (bitcoin-lisp.mempool:txgraph-get-ancestors
                          graph (bitcoin-lisp.mempool:mempool-entry-graph-handle
                                 entry)))))))
    ;; Recursive removal from the root clears the graph.
    (is (= 2 (bitcoin-lisp.mempool:mempool-remove-recursive
              mempool (%shp-hash a))))
    (is (zerop (bitcoin-lisp.mempool:txgraph-tx-count graph)))))

;;;; Block confirmation

(test shadow-block-confirmation-splits-clusters
  "Confirming part of a cluster splits the remainder into components."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (graph (%shp-graph mempool))
         (a (%shp-root-tx 4))
         (b (%shp-tx (list (cons (%shp-hash a) 0))))
         (c (%shp-tx (list (cons (%shp-hash b) 0))))
         (d (%shp-tx (list (cons (%shp-hash a) 1)))))
    (dolist (tx (list a b c d)) (%shp-add mempool tx))
    (is (= 4 (length (bitcoin-lisp.mempool:txgraph-get-cluster
                      graph (%shp-handle mempool (%shp-hash a))))))
    ;; A block confirms a and b: c and d remain, now unrelated singletons.
    (bitcoin-lisp.mempool:mempool-remove-for-block mempool (%shp-block (list a b)))
    (is (= 2 (bitcoin-lisp.mempool:mempool-count mempool)))
    (is (= 2 (bitcoin-lisp.mempool:txgraph-tx-count graph)))
    (let ((c-handle (%shp-handle mempool (%shp-hash c)))
          (d-handle (%shp-handle mempool (%shp-hash d))))
      (is (= 1 (length (bitcoin-lisp.mempool:txgraph-get-ancestors graph c-handle))))
      (is (= 1 (length (bitcoin-lisp.mempool:txgraph-get-ancestors graph d-handle))))
      (is (= 2 (bitcoin-lisp.mempool:txgraph-count-distinct-clusters
                graph (list c-handle d-handle)))))
    (is (%shp-equiv-p mempool (%shp-hash c)))
    (is (%shp-equiv-p mempool (%shp-hash d)))))

(test shadow-block-conflict-removes-descendants
  "A block conflict evicts the conflicting tx AND its descendants (Core
removeForBlock -> removeConflicts -> removeRecursive): the descendants
spend outputs that no longer exist."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (graph (%shp-graph mempool))
         (w (%shp-root-tx 5))
         ;; y spends w's output plus a contested outpoint.
         (contested (cons (%shp-outpoint-hash 6) 0))
         (y (%shp-tx (list (cons (%shp-hash w) 0) contested)))
         (z (%shp-tx (list (cons (%shp-hash y) 0))))
         ;; The block tx double-spends the contested outpoint.
         (block-tx (%shp-tx (list contested) :value 1000)))
    (dolist (tx (list w y z)) (%shp-add mempool tx))
    (bitcoin-lisp.mempool:mempool-remove-for-block mempool (%shp-block (list block-tx)))
    (is (bitcoin-lisp.mempool:mempool-has mempool (%shp-hash w)))
    (is (not (bitcoin-lisp.mempool:mempool-has mempool (%shp-hash y))))
    (is (not (bitcoin-lisp.mempool:mempool-has mempool (%shp-hash z))))
    (is (= 1 (bitcoin-lisp.mempool:txgraph-tx-count graph)))
    (is (%shp-equiv-p mempool (%shp-hash w)))))

;;;; Reorg cycle

(test shadow-reorg-cycle-rebuilds-graph
  "Disconnect re-adds go through the normal acceptance tail, so the graph
is rebuilt with its dependencies re-wired."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (graph (%shp-graph mempool))
         (a (%shp-root-tx 7))
         (b (%shp-tx (list (cons (%shp-hash a) 0)))))
    (%shp-add mempool a)
    (%shp-add mempool b)
    ;; Connect: a block confirms both.
    (bitcoin-lisp.mempool:mempool-remove-for-block mempool (%shp-block (list a b)))
    (is (zerop (bitcoin-lisp.mempool:txgraph-tx-count graph)))
    ;; Disconnect: re-add in block order, as readd-disconnected-txs-to-mempool
    ;; does (src/validation/block.lisp) via accept-validated-tx.
    (is (eq :ok (bitcoin-lisp.mempool:accept-validated-tx
                 mempool (%shp-hash a) a 10000 0)))
    (is (eq :ok (bitcoin-lisp.mempool:accept-validated-tx
                 mempool (%shp-hash b) b 8000 0)))
    (is (= 2 (bitcoin-lisp.mempool:txgraph-tx-count graph)))
    (is (= 2 (length (bitcoin-lisp.mempool:txgraph-get-ancestors
                      graph (%shp-handle mempool (%shp-hash b))))))
    (is (%shp-equiv-p mempool (%shp-hash b)))))

;;;; mempool.dat reload

(test shadow-mempool-dat-roundtrip-rebuilds-graph
  "Reloading mempool.dat replays acceptance, rebuilding the graph with
dependencies and prioritisation deltas intact."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (parent (%shp-root-tx 8))
         (child (%shp-tx (list (cons (%shp-hash parent) 0))))
         (path (merge-pathnames
                (format nil "mempool-shadow-~D.dat" (get-universal-time))
                (uiop:temporary-directory))))
    (%shp-add mempool parent :fee 5000)
    (%shp-add mempool child :fee 7000)
    (bitcoin-lisp.mempool:mempool-prioritise mempool (%shp-hash child) 1234)
    (unwind-protect
         (progn
           (is (= 2 (bitcoin-lisp.mempool:save-mempool-file mempool path)))
           (multiple-value-bind (entries residual ok)
               (bitcoin-lisp.mempool:read-mempool-file path)
             (declare (ignore residual))
             (is-true ok)
             ;; Replay into a fresh mempool the way load-mempool-from-disk
             ;; does (src/node.lisp): delta first, then the acceptance tail.
             (let* ((mempool2 (bitcoin-lisp.mempool:make-mempool))
                    (graph2 (%shp-graph mempool2)))
               (loop for (tx entry-time delta) in entries
                     for txid = (%shp-hash tx)
                     do (unless (zerop delta)
                          (bitcoin-lisp.mempool:mempool-prioritise
                           mempool2 txid delta))
                        (is (eq :ok (bitcoin-lisp.mempool:accept-validated-tx
                                     mempool2 txid tx 5000 0
                                     :entry-time entry-time))))
               (is (= 2 (bitcoin-lisp.mempool:txgraph-tx-count graph2)))
               (is (= 2 (length (bitcoin-lisp.mempool:txgraph-get-ancestors
                                 graph2 (%shp-handle mempool2 (%shp-hash child))))))
               ;; The delta rode along: the graph sees the modified fee.
               (is (= 6234 (bitcoin-lisp.mempool:feefrac-fee
                            (bitcoin-lisp.mempool:txgraph-get-individual-feerate
                             graph2 (%shp-handle mempool2 (%shp-hash child))))))
               (is (%shp-equiv-p mempool2 (%shp-hash child))))))
      (ignore-errors (delete-file path)))))

;;;; Prioritisation

(test shadow-prioritise-updates-graph-fee
  "prioritisetransaction reaches the graph: at add time for pre-existing
deltas, via set-transaction-fee for in-mempool entries."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (graph (%shp-graph mempool))
         (a (%shp-root-tx 9))
         (b (%shp-root-tx 10)))
    (flet ((graph-fee (txid)
             (bitcoin-lisp.mempool:feefrac-fee
              (bitcoin-lisp.mempool:txgraph-get-individual-feerate
               graph (%shp-handle mempool txid)))))
      ;; Post-add prioritisation.
      (%shp-add mempool a :fee 10000)
      (bitcoin-lisp.mempool:mempool-prioritise mempool (%shp-hash a) 500)
      (is (= 10500 (graph-fee (%shp-hash a))))
      ;; Negative delta.
      (bitcoin-lisp.mempool:mempool-prioritise mempool (%shp-hash a) -700)
      (is (= 9800 (graph-fee (%shp-hash a))))
      ;; Pre-add prioritisation is applied by mempool-add.
      (bitcoin-lisp.mempool:mempool-prioritise mempool (%shp-hash b) 300)
      (%shp-add mempool b :fee 10000)
      (is (= 10300 (graph-fee (%shp-hash b)))))))

;;;; Cluster limits at acceptance (P6: what P3 merely tolerated is rejected)

(test shadow-cluster-limit-rejects-oversized-component
  "A connected component may not exceed 64 txs: growing a caterpillar (every
tx well within the old 25/25 limits) is fine until the bridge that would
fuse it into a 65-tx cluster, which is rejected with :too-large-cluster and
its staged graph addition rolled back - the graph never stays oversized,
mempool and graph agree throughout, and the pool remains fully usable."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (graph (%shp-graph mempool))
         (roots (loop for i from 1 to 33
                      collect (%shp-root-tx (+ 100 i)))))
    (dolist (r roots) (is (eq :ok (%shp-add mempool r))))
    ;; bridge-i spends (root-i, 1) and (root-i+1, 0). After k bridges the
    ;; component holds 2k+1 txs: bridges 1-31 pass (63 txs), bridge 32 would
    ;; make 65 and is rejected.
    (loop for (r1 r2) on roots
          for k from 1
          while r2
          for bridge = (%shp-tx (list (cons (%shp-hash r1) 1)
                                      (cons (%shp-hash r2) 0)))
          do (is (eq (if (<= k 31) :ok :too-large-cluster)
                     (%shp-add mempool bridge))))
    (is (= 64 (bitcoin-lisp.mempool:mempool-count mempool)))
    (is (= 64 (bitcoin-lisp.mempool:txgraph-tx-count graph)))
    (is-false (bitcoin-lisp.mempool:txgraph-oversized-p graph))
    ;; The pool stays fully usable after the rejection.
    (let ((extra (%shp-root-tx 200)))
      (is (eq :ok (%shp-add mempool extra)))
      (is (= 65 (bitcoin-lisp.mempool:txgraph-tx-count graph)))
      (bitcoin-lisp.mempool:mempool-remove mempool (%shp-hash extra)))
    (is (%shp-verify mempool))
    (is (%shp-equiv-p mempool (%shp-hash (first roots))))))

;;;; Randomized equivalence

(test shadow-randomized-ops-equivalence
  "A seeded random mix of adds, child adds, removals, prioritisations, and
block confirmations, with the per-mutation shadow asserts doing the heavy
checking; explicit spot checks at the end."
  (dolist (seed '(88172645463325252 3141592653589793))
    (let ((rng (%cl-make-rng seed))
          (mempool (bitcoin-lisp.mempool:make-mempool))
          (all-txs (make-hash-table :test 'equalp))   ; txid -> tx
          (next-vout (make-hash-table :test 'equalp)) ; txid -> next free vout
          (next-root 0))
      (flet ((live-txids ()
               (let ((ids '()))
                 (maphash (lambda (txid tx) (declare (ignore tx))
                            (when (bitcoin-lisp.mempool:mempool-has mempool txid)
                              (push txid ids)))
                          all-txs)
                 ;; Deterministic order for reproducible seeding.
                 (sort ids #'%shp-txid<)))
             (track (tx)
               (setf (gethash (%shp-hash tx) all-txs) tx))
             (fresh-outpoint (parent-txid)
               (cons parent-txid
                     (1- (incf (gethash parent-txid next-vout 0))))))
        (dotimes (step 140)
          (let* ((live (live-txids))
                 (n (length live))
                 ;; Force shrinkage when large; otherwise mostly grow.
                 (op (if (> n 45) (+ 5 (funcall rng 3)) (funcall rng 8))))
            (case op
              ((0 1 2)                     ; add a root
               (let ((tx (%shp-root-tx (+ 1000 (incf next-root)))))
                 (track tx)
                 (%shp-add mempool tx :fee (+ 1000 (funcall rng 20000)))))
              ((3 4)                       ; add a child of 1-2 live parents
               (when (plusp n)
                 (let* ((p1 (nth (funcall rng n) live))
                        (p2 (when (and (> n 1) (zerop (funcall rng 2)))
                              (nth (funcall rng n) live)))
                        (outpoints
                          (cons (fresh-outpoint p1)
                                (when (and p2 (not (equalp p1 p2)))
                                  (list (fresh-outpoint p2)))))
                        (tx (%shp-tx outpoints)))
                   (track tx)
                   ;; May be rejected (chain limits); the graph must stay
                   ;; consistent either way.
                   (%shp-add mempool tx :fee (+ 1000 (funcall rng 20000))))))
              (5                           ; recursive removal
               (when (plusp n)
                 (bitcoin-lisp.mempool:mempool-remove-recursive
                  mempool (nth (funcall rng n) live))))
              (6                           ; confirm a random ancestor-closed set
               (when (plusp n)
                 (let* ((target (nth (funcall rng n) live))
                        (txids (let ((ids (list target)))
                                 (maphash (lambda (k v) (declare (ignore v))
                                            (push k ids))
                                          (bitcoin-lisp.mempool:mempool-ancestors
                                           mempool target))
                                 ids)))
                   (bitcoin-lisp.mempool:mempool-remove-for-block
                    mempool
                    (%shp-block (mapcar (lambda (id) (gethash id all-txs))
                                        txids))))))
              (7                           ; prioritise
               (when (plusp n)
                 (bitcoin-lisp.mempool:mempool-prioritise
                  mempool (nth (funcall rng n) live)
                  (- (funcall rng 5000) 2500))))))
          (when (zerop (mod step 20))
            (is (= (bitcoin-lisp.mempool:txgraph-tx-count (%shp-graph mempool))
                   (bitcoin-lisp.mempool:mempool-count mempool)))))
        ;; Final explicit spot equivalence, independent of the hooks.
        (is (%shp-verify mempool))
        (let ((live (live-txids)))
          (is (= (length live)
                 (bitcoin-lisp.mempool:txgraph-tx-count (%shp-graph mempool))))
          (unless (bitcoin-lisp.mempool:txgraph-oversized-p (%shp-graph mempool))
            (dolist (txid live)
              (is (%shp-equiv-p mempool txid)))))))))
