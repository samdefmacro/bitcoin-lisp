(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/coinscache_sim.cpp at the pin: random coin operations
;;;; on a cache stack, mirrored on a plain simulation of every level, the two
;;;; compared after each read and in full at the end.
;;;;
;;;; Core's bottom is an in-memory CCoinsView with up to four
;;;; CCoinsViewCache/CoinsViewOverlay levels above it. Ours is the one stack
;;;; the node runs: a COINS-VIEW-CACHE over a COINS-VIEW-DB, so the bottom is a
;;;; scratch LevelDB and there is at most ONE cache level (MAX_CACHES = 1).
;;;; "Add a cache level" makes a new cache over the database when there is
;;;; none; "Remove a cache level" drops the cache unflushed; CreateResetGuard
;;;; (Reset: forget every entry, write nothing) is the same thing for us -- a
;;;; fresh cache object over the same database. HaveCoinInCache, PeekCoin and
;;;; SanityCheck read cache internals Core exposes and we do not; PeekCoin is
;;;; GetCoin here, and the rest of SanityCheck's accounting is asserted where
;;;; it is observable (a flushed cache is empty and holds no bytes, and the
;;;; memory estimate is never negative and is zero over an empty cache).

(def-suite :fuzz-coinscache-sim-tests :in :bitcoin-lisp-tests
  :description "Core fuzz coinscache_sim.cpp over our coins-view cache and database")

(in-suite :fuzz-coinscache-sim-tests)

(defconstant +sim-num-outpoints+ 256 "Core NUM_OUTPOINTS.")
(defconstant +sim-num-coins+ 256 "Core NUM_COINS.")

(defun %sim-le32 (i)
  (coerce (list (ldb (byte 8 0) i) (ldb (byte 8 8) i) (ldb (byte 8 16) i) (ldb (byte 8 24) i))
          '(simple-array (unsigned-byte 8) (*))))

(defun %sim-hash (prefix i)
  (bl.crypto:sha256 (concatenate '(simple-array (unsigned-byte 8) (*))
                                 (vector (char-code prefix)) (%sim-le32 i))))

(defun %sim-u64 (hash word)
  "uint256::GetUint64(WORD): the little-endian 64-bit word WORD of HASH."
  (loop for k from 0 below 8
        sum (ash (aref hash (+ (* 8 word) k)) (* 8 k))))

(defparameter +sim-outpoints+
  (coerce (loop for i below +sim-num-outpoints+
                collect (cons (%sim-hash #\o (ash (* i 1200) -12)) i))
          'simple-vector)
  "PrecomputedData::outpoints (coinscache_sim.cpp:36-43): three or four
outputs share each txid.")

(defparameter +sim-coins+
  (coerce
   (loop for i below +sim-num-coins+
         collect (let* ((h (%sim-hash #\s i))
                        (spk (flet ((cat (&rest parts)
                                      (apply #'concatenate '(simple-array (unsigned-byte 8) (*))
                                             parts)))
                               (ecase (mod i 5)
                                 (0 (cat #(#x76 #xa9 20) (subseq h 0 20) #(#x88 #xac)))
                                 ;; Core writes OP_EQUAL at [12] over the hash
                                 ;; bytes it has just copied (coinscache_sim.cpp:67),
                                 ;; so its "P2SH" has 22 at [22] -- kept as is.
                                 (1 (let ((s (cat #(#xa9 20) (subseq h 0 20) #(0))))
                                      (setf (aref s 12) #x87)
                                      s))
                                 (2 (cat #(0 20) (subseq h 0 20)))
                                 (3 (cat #(0 32) h))
                                 (4 (cat #(#x51 32) h)))))
                        (m (%sim-hash #\m i)))
                   (list :value (mod (%sim-u64 m 0) bl.val:+max-money+)
                         :script spk
                         :coinbase (zerop (logand (%sim-u64 m 1) 7)))))
   'simple-vector)
  "PrecomputedData::coins (coinscache_sim.cpp:45-99): P2PKH, P2SH, P2WPKH,
P2WSH and P2TR scripts of different lengths, a value below MAX_MONEY, a
coinbase flag set one time in eight.")

(defun %sim-key (outpoint-idx)
  (let ((op (aref +sim-outpoints+ outpoint-idx)))
    (bl.store:make-utxo-key (car op) (cdr op))))

(defun %sim-entry (coin-idx height)
  (let ((c (aref +sim-coins+ coin-idx)))
    (bl.store:make-utxo-entry :value (getf c :value) :script-pubkey (getf c :script)
                              :height height :coinbase (getf c :coinbase))))

(defun %sim-expected (coin-idx-and-height)
  "The (value script height coinbase) a simulated entry stands for, or NIL."
  (when coin-idx-and-height
    (%coin-fields (%sim-entry (car coin-idx-and-height) (cdr coin-idx-and-height)))))

(defstruct (coins-sim (:conc-name sim-))
  "The simulated levels: BOTTOM (the database) and CACHE (the cache level, or
NIL when there is none), each a vector of NIL (no entry), :SPENT or
(coin-idx . height) per outpoint -- Core's CacheLevel of EntryType."
  (bottom (make-array +sim-num-outpoints+ :initial-element nil) :type simple-vector)
  (cache nil :type (or null simple-vector)))

(defun %sim-lookup (sim idx &optional (level :top))
  "Core's lookup (coinscache_sim.cpp:196-210): the topmost entry at IDX from
LEVEL down; NIL for none or spent."
  (let ((e (and (eq level :top) (sim-cache sim) (aref (sim-cache sim) idx))))
    (cond ((consp e) e)
          ((eq e :spent) nil)
          (t (let ((b (aref (sim-bottom sim) idx)))
               (and (consp b) b))))))

(defun %sim-flush (sim)
  "Core's flush (coinscache_sim.cpp:213-224): every entry of the cache level
moves down; a spent one clears the bottom's."
  (let ((cache (sim-cache sim)))
    (dotimes (i +sim-num-outpoints+)
      (let ((e (aref cache i)))
        (when e
          (setf (aref (sim-bottom sim) i) (if (eq e :spent) nil e)
                (aref cache i) nil))))))

(defun %sim-assert-coin (what got sim idx)
  (let ((want (%sim-expected (%sim-lookup sim idx))))
    (fuzz-assert (equalp (fuzz-sabotage (%coin-fields got)) want)
                 "~A of outpoint ~D: ~S, the simulation says ~S" what idx (%coin-fields got) want)))

(defun %coinscache-sim (fdp db)
  (let ((sim (make-coins-sim))
        (cache nil)
        (height 1))
    (flet ((top () cache)
           (outpoint () (consume-integral-in-range fdp 0 (1- +sim-num-outpoints+)))
           (coin () (consume-integral-in-range fdp 0 (1- +sim-num-coins+)))
           (set-top (idx value) (setf (aref (sim-cache sim) idx) value)))
      (limited-while ((plusp (remaining-bytes fdp)) 10000)
        (incf height)
        (unless cache
          (setf cache (bl.store:make-coins-view-cache db)
                (sim-cache sim) (make-array +sim-num-outpoints+ :initial-element nil)))
        (call-one-of fdp
          ;; GetCoin (PeekCoin is the same read here: we have no non-fetching one)
          (let ((idx (outpoint)))
            (consume-bool fdp)
            (%sim-assert-coin "GetCoin" (bl.store:coins-view-cache-get (top) (%sim-key idx)) sim idx))
          ;; HaveCoin
          (let ((idx (outpoint)))
            (fuzz-assert (eq (fuzz-sabotage (and (%sim-lookup sim idx) t))
                             (and (bl.store:coins-view-cache-has-p (top) (%sim-key idx)) t))
                         "HaveCoin of outpoint ~D disagrees with the simulation" idx))
          ;; HaveCoinInCache: no counterpart
          (outpoint)
          ;; AccessCoin: GetCoin again
          (let ((idx (outpoint)))
            (%sim-assert-coin "AccessCoin" (bl.store:coins-view-cache-get (top) (%sim-key idx)) sim idx))
          ;; AddCoin, possible_overwrite only if necessary
          (let* ((idx (outpoint)) (c (coin)))
            (bl.store:coins-view-cache-add (top) (%sim-key idx) (%sim-entry c height)
                                           :allow-overwrite (and (%sim-lookup sim idx) t))
            (set-top idx (cons c height)))
          ;; AddCoin, always possible_overwrite
          (let* ((idx (outpoint)) (c (coin)))
            (bl.store:coins-view-cache-add (top) (%sim-key idx) (%sim-entry c height)
                                           :allow-overwrite t)
            (set-top idx (cons c height)))
          ;; SpendCoin (moveto = nullptr)
          (let ((idx (outpoint)))
            (bl.store:coins-view-cache-spend (top) (%sim-key idx))
            (set-top idx :spent))
          ;; SpendCoin with moveto: the coin handed back is the one spent
          (let* ((idx (outpoint))
                 (op (aref +sim-outpoints+ idx))
                 (was (%sim-lookup sim idx))
                 (moved (bl.store:coin-view-spend (top) (car op) (cdr op))))
            (set-top idx :spent)
            (fuzz-assert (equalp (fuzz-sabotage (%coin-fields moved)) (%sim-expected was))
                         "SpendCoin of outpoint ~D moved out ~S, the simulation says ~S"
                         idx (%coin-fields moved) (%sim-expected was)))
          ;; Uncache
          (bl.store:coins-view-cache-uncache (top) (%sim-key (outpoint)))
          ;; Add a cache level: we are at the maximum of one
          (consume-bool fdp)
          ;; Remove a cache level: dropped unflushed, and its level with it
          (setf cache nil (sim-cache sim) nil)
          ;; Flush
          (progn
            (%sim-flush sim)
            (consume-bool fdp)
            (bl.store:coins-view-cache-flush (top))
            (fuzz-assert (and (zerop (fuzz-sabotage (bl.store:utxo-count (top))))
                              (zerop (bl.store:view-mem-bytes (top))))
                         "a flushed cache holds ~D entries and ~D bytes"
                         (bl.store:utxo-count (top)) (bl.store:view-mem-bytes (top))))
          ;; Sync: in the simulation the same as a flush
          (progn
            (%sim-flush sim)
            (bl.store:coins-view-cache-sync (top)))
          ;; Reset: every entry forgotten, nothing written
          (setf cache (bl.store:make-coins-view-cache db)
                (sim-cache sim) (make-array +sim-num-outpoints+ :initial-element nil))
          ;; GetCacheSize, DynamicMemoryUsage: the estimate is never negative,
          ;; and an empty cache holds no bytes (cachedCoinsUsage is
          ;; maintained entry by entry, so drift shows here)
          (bl.store:utxo-count (top))
          (let ((mem (bl.store:view-mem-bytes (top))) (n (bl.store:utxo-count (top))))
            (fuzz-assert (and (>= mem 0) (or (plusp n) (zerop (fuzz-sabotage mem))))
                         "the memory estimate is ~D bytes over ~D entries" mem n))
          ;; Change height
          (setf height (consume-integral-in-range fdp 1 (1- height))))))
    ;; The full comparison (coinscache_sim.cpp:421-470): the cache level
    ;; against its simulation, then the database against the bottom one.
    (when cache
      (dotimes (idx +sim-num-outpoints+)
        (%sim-assert-coin "AccessCoin at the end" (bl.store:coins-view-cache-get cache (%sim-key idx)) sim idx)))
    (setf (sim-cache sim) nil)
    (dotimes (idx +sim-num-outpoints+)
      (%sim-assert-coin "the database" (bl.store:coins-view-db-get db (%sim-key idx)) sim idx))))

(define-fuzz-target coinscache-sim
    (buffer :core "coinscache_sim.cpp:175-471" :iterations 120 :max-len 3000)
  "Random coin operations on a coins-view cache over its database -- adds
with and without possible_overwrite, spends, uncaches, flushes, syncs, the
cache dropped unflushed -- agree at every read with a plain simulation of
both levels, and at the end every outpoint reads as simulated in the cache
and in the database."
  (with-temp-directory (dir "fuzz-coinscache-sim")
    (bl.store:with-coins-view-db (db (merge-pathnames "chainstate/" dir))
      (%coinscache-sim (make-fuzzed-data-provider buffer) db))))
