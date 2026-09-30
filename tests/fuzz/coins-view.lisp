(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/coins_view.cpp at the pin: TestCoinsView over a
;;;; CCoinsViewCache on a CCoinsViewDB (coins_view_db, :278-291), ours a
;;;; COINS-VIEW-CACHE on a COINS-VIEW-DB in a scratch LevelDB.
;;;;
;;;; Core runs the same body over three stacks. coins_view (a cache on the
;;;; empty CCoinsView) and coins_view_overlay (a CoinsViewOverlay on a guarded
;;;; cache) have no counterpart: our cache's base is always a LevelDB and
;;;; nothing layers a cache on a cache. Of the operations, EmplaceCoinInternalDANGER,
;;;; CreateResetGuard, SetBackend, Cursor and a BatchWrite of a hand-built
;;;; CCoinsMap are Core API with no counterpart here either; the rest map
;;;; one to one (AddCoin, Flush, Sync, SetBestBlock, SpendCoin, Uncache, the
;;;; reads, and the six consumers of the view in the tail: AddCoins,
;;;; AreInputsStandard, CheckTxInputs, GetP2SHSigOpCount,
;;;; GetTransactionSigOpCost, IsWitnessStandard).
;;;;
;;;; Beyond Core's assertions -- which only check that the view's readers
;;;; agree with each other -- the target keeps a plain hash table of what the
;;;; view must hold (coins_tests.cpp SimulationTest's `result' map) and checks
;;;; the cache against it after every step, and the DATABASE against it after
;;;; every Flush and Sync. That is where a misapplied FRESH or a lost DIRTY
;;;; shows: a coin FRESH over a base row is dropped at spend and comes back
;;;; from LevelDB after the flush; an entry whose DIRTY was cleared before its
;;;; write never reaches the database.
;;;;
;;;; A libFuzzer corpus makes Core's random outpoints collide and its loops
;;;; long; our uniform bytes would do neither, so outpoints are drawn from two
;;;; txids and two indexes (now and then a fresh random one), and the loop
;;;; goes on with probability 63/64 where Core's goes on with ConsumeBool.

(def-suite :fuzz-coins-view-tests :in :bitcoin-lisp-tests
  :description "Core fuzz coins_view.cpp (coins_view_db) over our coins-view cache")

(in-suite :fuzz-coins-view-tests)

(defparameter +fuzz-coins-txids+
  (coerce (loop for i from 1 to 2
                collect (bl.crypto:sha256 (make-array 1 :element-type '(unsigned-byte 8)
                                                        :initial-element i)))
          'simple-vector)
  "The txids the coins_view outpoints are drawn from.")

(defun %fuzz-continue-p (fdp)
  "LIMITED_WHILE's ConsumeBool for a buffer no corpus shaped: go on 63
times in 64 while the buffer lasts, so a sequence runs dozens of steps."
  (and (plusp (remaining-bytes fdp))
       (plusp (consume-integral-in-range fdp 0 63))))

(defun %fuzz-coins-outpoint (fdp)
  "An outpoint (TXID . VOUT): usually one of +FUZZ-COINS-TXIDS+, index 0-1."
  (cons (if (zerop (consume-integral-in-range fdp 0 15))
            (consume-uint256 fdp)
            (pick-value-in-array fdp +fuzz-coins-txids+))
        (consume-integral-in-range fdp 0 1)))

(defun %fuzz-coins-script (fdp)
  "A short scriptPubKey: empty, OP_RETURN (provably unspendable), P2WSH of
OP_TRUE, or up to 40 random bytes."
  (call-one-of fdp
    (make-array 0 :element-type '(unsigned-byte 8))
    (coerce (list #x6a (consume-integral fdp :u8)) '(simple-array (unsigned-byte 8) (*)))
    +p2wsh-op-true+
    (consume-random-length-byte-vector fdp 40)))

(defun %fuzz-coins-coin (fdp)
  "A Coin: any amount, a script that is sometimes provably unspendable, a
height below 2^31 and a coinbase flag."
  (bl.store:make-utxo-entry
   :value (consume-money fdp)
   :script-pubkey (%fuzz-coins-script fdp)
   :height (ash (consume-integral fdp :u32) -1)
   :coinbase (consume-bool fdp)))

(defun %fuzz-coins-transaction (fdp)
  "A transaction spending up to three outpoints of the pool (or the null
outpoint: a coinbase) into up to four outputs, witness-less or with one small
item per input -- ConsumeDeserializable<CMutableTransaction> for a buffer no
corpus shaped, cheap enough to leave bytes for the operations."
  (let* ((coinbase (zerop (consume-integral-in-range fdp 0 7)))
         (inputs (if coinbase
                     (list (bl.ser:make-tx-in
                            :previous-output (bl.ser:make-outpoint
                                              :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                   :initial-element 0)
                                              :index #xffffffff)
                            :script-sig (consume-random-length-byte-vector fdp 8)))
                     (loop repeat (consume-integral-in-range fdp 0 3)
                           collect (let ((op (%fuzz-coins-outpoint fdp)))
                                     (bl.ser:make-tx-in
                                      :previous-output (bl.ser:make-outpoint :hash (car op) :index (cdr op))
                                      :script-sig (consume-random-length-byte-vector fdp 8)
                                      :sequence (consume-sequence fdp))))))
         (witness (when (consume-bool fdp)
                    (loop repeat (length inputs)
                          collect (list (consume-random-length-byte-vector fdp 8))))))
    (bl.ser:make-transaction
     :version 2 :lock-time 0
     :inputs (coerce inputs 'simple-vector)
     :outputs (coerce (loop repeat (consume-integral-in-range fdp 0 4)
                            collect (bl.ser:make-tx-out :value (consume-integral-in-range
                                                                fdp -10 (+ bl.val:+max-money+ 10))
                                                        :script-pubkey (%fuzz-coins-script fdp)))
                      'simple-vector)
     :witness (when witness (coerce witness 'simple-vector)))))

(defun %coin-fields (entry)
  "ENTRY as a list Core's Coin operator== compares, or NIL for no coin."
  (when entry
    (list (bl.store:utxo-entry-value entry) (bl.store:utxo-entry-script-pubkey entry)
          (bl.store:utxo-entry-height entry) (bl.store:utxo-entry-coinbase entry))))

(defun %outpoint-key (op)
  (bl.store:make-utxo-key (car op) (cdr op)))

(defun %model-key (op)
  (cons (bl.crypto:bytes-to-hex (car op)) (cdr op)))

(defun %check-view-against-model (what reader model universe)
  "Every outpoint of UNIVERSE reads through READER as MODEL says it must."
  (dolist (op universe)
    (let ((want (gethash (%model-key op) model))
          (got (%coin-fields (funcall reader (%outpoint-key op)))))
      (fuzz-assert (equalp (fuzz-sabotage got) want)
                   "~A: ~A:~D reads ~S, the model holds ~S"
                   what (bl.crypto:bytes-to-hex (car op)) (cdr op) got want))))

(defun %core-add-coin (cache model op coin possible-overwrite)
  "CCoinsViewCache::AddCoin (coins.cpp:89-130), whose first act is to drop a
provably unspendable output -- a check our callers make before the add."
  (unless (bl.store:script-unspendable-p (bl.store:utxo-entry-script-pubkey coin))
    (bl.store:coins-view-cache-add cache (%outpoint-key op) coin
                                   :allow-overwrite possible-overwrite)
    (setf (gethash (%model-key op) model) (%coin-fields coin))))

(defun %fuzz-spent-script-fn (cache)
  "The (txid index) -> scriptPubKey reader the policy checks take; NIL for a
missing coin, as Core's AccessCoin answers an empty coin."
  (lambda (txid index)
    (let ((e (bl.store:coin-view-get cache txid index)))
      (and e (bl.store:utxo-entry-script-pubkey e)))))

(defun %contains-spent-input-p (tx cache)
  "Core ContainsSpentInput (test/fuzz/util.cpp)."
  (some (lambda (in)
          (let ((op (bl.ser:tx-in-previous-output in)))
            (null (bl.store:coin-view-get cache (bl.ser:outpoint-hash op) (bl.ser:outpoint-index op)))))
        (bl.ser:transaction-inputs tx)))

(defun %fuzz-coins-tail (fdp cache model tx universe)
  "The CallOneOf after the loop (coins_view.cpp:232-300): one consumer of the view."
  (call-one-of fdp
    ;; AddCoins (coins.cpp:142-151): every output, overwrite allowed where the
    ;; view already has the coin (check_for_overwrite) or for a coinbase.
    (let* ((txid (bl.ser:transaction-hash tx))
           (height (ash (consume-integral fdp :u32) -1))
           (coinbase (and (bl.val:is-coinbase-tx tx) t))
           (outputs (bl.ser:transaction-outputs tx))
           (check-for-overwrite
             (or coinbase
                 (loop for i below (length outputs)
                         thereis (gethash (%model-key (cons txid i)) model))
                 (consume-bool fdp))))
      (dotimes (i (length outputs))
        (let* ((op (cons txid i))
               (out (aref outputs i))
               (overwrite (if check-for-overwrite
                              (and (bl.store:coins-view-cache-has-p cache (%outpoint-key op)) t)
                              coinbase)))
          (push op (car universe))
          (%core-add-coin cache model op
                          (bl.store:make-utxo-entry :value (bl.ser:tx-out-value out)
                                                    :script-pubkey (bl.ser:tx-out-script-pubkey out)
                                                    :height height :coinbase coinbase)
                          overwrite))))
    (bl.val:are-inputs-standard-p tx (%fuzz-spent-script-fn cache))
    ;; Consensus::CheckTxInputs, only after CheckTransaction and with every
    ;; input present: a fee it accepts is in MoneyRange.
    (unless (or (%contains-spent-input-p tx cache)
                (not (bl.val:validate-transaction-structure tx)))
      (multiple-value-bind (ok error fee)
          (bl.val:validate-transaction-contextual
           tx cache (consume-integral-in-range fdp 0 (1- (ash 1 31))))
        (declare (ignore error))
        (when ok
          (fuzz-assert (bl.val:money-range-p (fuzz-sabotage (bl.interop:unwrap-satoshi fee)))
                       "CheckTxInputs accepted a fee out of MoneyRange"))))
    (unless (%contains-spent-input-p tx cache)
      (bl.val:count-transaction-sigops-cost tx (%fuzz-spent-script-fn cache)
                                            :count-p2sh t :count-witness nil))
    (let* ((flags (consume-integral fdp :u32))
           (p2sh (logbitp 0 flags))
           (witness (logbitp 11 flags)))
      (unless (or (%contains-spent-input-p tx cache)
                  (and (plusp (length (bl.ser:transaction-inputs tx))) witness (not p2sh)))
        (bl.val:count-transaction-sigops-cost tx (%fuzz-spent-script-fn cache)
                                              :count-p2sh p2sh :count-witness witness)))
    (bl.val:is-witness-standard-p tx (%fuzz-spent-script-fn cache))))

(defun %fuzz-coins-step (fdp cache db model state universe)
  "One CallOneOf of TestCoinsView's loop (coins_view.cpp:97-205). STATE is a
plist cell (:outpoint :coin :tx)."
  (flet ((check-db ()
           (%check-view-against-model "the database" (lambda (k) (bl.store:coins-view-db-get db k))
                                      model (car universe))))
    (call-one-of fdp
      ;; AddCoin: possible_overwrite unless no unspent coin exists here.
      (let ((op (getf (car state) :outpoint)))
        (when (consume-bool fdp)
          (%core-add-coin cache model op (getf (car state) :coin)
                          (or (and (gethash (%model-key op) model) t) (consume-bool fdp)))))
      (progn
        (consume-bool fdp)              ; reallocate_cache
        (bl.store:coins-view-cache-flush cache)
        (fuzz-assert (and (zerop (fuzz-sabotage (bl.store:utxo-count cache)))
                          (zerop (bl.store:view-mem-bytes cache)))
                     "a flushed cache still holds ~D entries, ~D bytes"
                     (bl.store:utxo-count cache) (bl.store:view-mem-bytes cache))
        (check-db))
      (progn
        (bl.store:coins-view-cache-sync cache)
        (check-db))
      (let ((best (consume-uint256 fdp)))
        (when (every #'zerop best) (setf (aref best 0) 1))
        (setf (bl.store:cvc-best-block cache) best))
      (let* ((op (getf (car state) :outpoint))
             (had (and (gethash (%model-key op) model) t)))
        (consume-bool fdp)              ; SpendCoin's moveout
        (fuzz-assert (eq (fuzz-sabotage had)
                         (and (bl.store:coins-view-cache-spend cache (%outpoint-key op)) t))
                     "SpendCoin of ~A:~D disagrees with the model (~A)"
                     (bl.crypto:bytes-to-hex (car op)) (cdr op) had)
        (remhash (%model-key op) model))
      (bl.store:coins-view-cache-uncache cache (%outpoint-key (getf (car state) :outpoint)))
      (let ((op (%fuzz-coins-outpoint fdp)))
        (push op (car universe))
        (setf (getf (car state) :outpoint) op))
      (setf (getf (car state) :coin) (%fuzz-coins-coin fdp))
      (setf (getf (car state) :tx)
            (%fuzz-coins-transaction fdp)))))

(defun %test-coins-view (fdp cache db)
  "TestCoinsView (coins_view.cpp:90-276), is_db = true."
  (let ((model (make-hash-table :test 'equalp))
        (universe (list '()))
        (state (list (list :outpoint (cons (aref +fuzz-coins-txids+ 0) 0)
                           :coin nil :tx (bl.ser:make-transaction)))))
    (setf (bl.store:cvc-best-block cache)
          (let ((one (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
            (setf (aref one 0) 1)
            one))
    (push (getf (car state) :outpoint) (car universe))
    (setf (getf (car state) :coin) (%fuzz-coins-coin fdp))
    (limited-while ((%fuzz-continue-p fdp) 10000)
      (%fuzz-coins-step fdp cache db model state universe)
      (%check-view-against-model "the cache" (lambda (k) (bl.store:coins-view-cache-get cache k))
                                 model (list (getf (car state) :outpoint))))
    (let ((tx (getf (car state) :tx)))
      ;; Core HaveInputs, and the size and memory estimates: they answer.
      (every (lambda (in)
               (let ((op (bl.ser:tx-in-previous-output in)))
                 (bl.store:coin-view-has-p cache (bl.ser:outpoint-hash op) (bl.ser:outpoint-index op))))
             (bl.ser:transaction-inputs tx))
      (fuzz-assert (>= (bl.store:view-mem-bytes cache) 0)
                   "the cache's memory estimate went negative: ~D" (bl.store:view-mem-bytes cache))
      (when (consume-bool fdp)
        (%fuzz-coins-tail fdp cache model tx universe)))
    ;; coins_view.cpp:302-327: the readers agree, and a coin the backend holds
    ;; is one the cache has, unless the cache has it spent.
    (dolist (op (car universe))
      (let* ((key (%outpoint-key op))
             (got (bl.store:coins-view-cache-get cache key))
             (have (and (bl.store:coins-view-cache-has-p cache key) t))
             (in-db (and (bl.store:coins-view-db-has-p db key) t)))
        (fuzz-assert (eq (fuzz-sabotage (and got t)) have)
                     "GetCoin and HaveCoin disagree on ~A:~D" (bl.crypto:bytes-to-hex (car op)) (cdr op))
        (fuzz-assert (eq in-db (and (bl.store:coins-view-db-get db key) t))
                     "the backend's GetCoin and HaveCoin disagree")
        (fuzz-assert (equalp (%coin-fields got) (gethash (%model-key op) model))
                     "~A:~D reads ~S, the model holds ~S" (bl.crypto:bytes-to-hex (car op)) (cdr op)
                     (%coin-fields got) (gethash (%model-key op) model))))
    ;; And what reaches the database at the end is exactly the model.
    (bl.store:coins-view-cache-flush cache)
    (%check-view-against-model "the database after the last flush"
                               (lambda (k) (bl.store:coins-view-db-get db k))
                               model (car universe))))

(define-fuzz-target coins-view-db
    (buffer :core "coins_view.cpp:278-291 (TestCoinsView :90-276)" :iterations 400 :max-len 3000)
  "A coins-view cache over a LevelDB, driven through random adds, spends,
flushes, syncs, uncaches and best-block moves, reads every outpoint exactly
as a plain map of the same operations says -- after every step, and in the
database itself after every flush and sync -- and its readers agree."
  (with-temp-directory (dir "fuzz-coins-view")
    (bl.store:with-coins-view-db (db (merge-pathnames "chainstate/" dir))
      (%test-coins-view (make-fuzzed-data-provider buffer)
                        (bl.store:make-coins-view-cache db) db))))
