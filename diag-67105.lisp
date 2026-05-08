;; One-shot diagnostic: load testnet4 state, find a failing tapscript spend
;; in block 67105, dump everything needed to verify BIP 341 sighash externally.

(asdf:load-system :bitcoin-lisp)
(setf bitcoin-lisp:*network* :testnet4)

(defpackage #:diag-67105 (:use :cl))
(in-package #:diag-67105)

(defvar *data-dir* #P"/data/bitcoin-lisp/data/testnet4/testnet4/")

(defun hex (bytes) (bitcoin-lisp.crypto:bytes-to-hex bytes))

(defun init ()
  (let* ((cs (bitcoin-lisp.storage:init-chain-state *data-dir*))
         (loaded-cs (bitcoin-lisp.storage:load-state cs)))
    (declare (ignore loaded-cs))
    (bitcoin-lisp.storage:load-header-index cs)
    (let ((utxo (bitcoin-lisp.storage:make-utxo-set)))
      (bitcoin-lisp.storage:load-utxo-set
       utxo (bitcoin-lisp.storage:utxo-set-file-path *data-dir*))
      (let ((bs (bitcoin-lisp.storage:init-block-store *data-dir*)))
        (values cs utxo bs)))))

(defun load-block-at-height (cs bs h)
  ;; Block 67105 is downloaded but NOT connected to the chain (validation
  ;; failed), so get-block-at-height (which walks back from chain tip) won't
  ;; find it. Scan the header index directly for entries with height=H.
  ;;
  ;; Stored .blk files are LEGACY format (witness data stripped — pre-existing
  ;; behaviour of write-bitcoin-block). For tapscript debugging we MUST load
  ;; the raw wire bytes from /data/bitcoin-lisp/forensic-blocks/<hash>.raw,
  ;; which are written by ibd.lisp's *forensic-store-from-height* hook.
  (declare (ignore bs))
  (let ((found-hash nil))
    (maphash (lambda (hash entry)
               (when (= (bitcoin-lisp.storage:block-index-entry-height entry) h)
                 (setf found-hash hash)))
             (bitcoin-lisp.storage::chain-state-block-index cs))
    (unless found-hash
      (error "no block-index-entry at height ~D" h))
    (format t "~%height ~D hash=~A~%" h (hex found-hash))
    (let* ((hash-hex (hex found-hash))
           (raw-path (merge-pathnames
                      (make-pathname :name hash-hex :type "raw")
                      "/data/bitcoin-lisp/forensic-blocks/")))
      (unless (probe-file raw-path)
        (error "forensic raw payload missing at ~A" raw-path))
      (let ((data (with-open-file (in raw-path :direction :input
                                                :element-type '(unsigned-byte 8))
                    (let ((buf (make-array (file-length in)
                                           :element-type '(unsigned-byte 8))))
                      (read-sequence buf in)
                      buf))))
        (bitcoin-lisp.serialization:parse-block-payload data)))))

(defun list-tapscript-spends (block)
  "List every tapscript spend in BLOCK (witness stack length >= 3)."
  (loop for tx in (bitcoin-lisp.serialization:bitcoin-block-transactions block)
        for tx-idx from 0
        for witness = (bitcoin-lisp.serialization:transaction-witness tx)
        when witness
          do (loop for stack in witness
                   for input-idx from 0
                   when (and stack (>= (length stack) 3))
                     do (let* ((control-block (car (last stack)))
                               (internal-pk (when (>= (length control-block) 33)
                                              (subseq control-block 1 33))))
                          (format t "  tx-idx=~D input-idx=~D witness-items=~D control-block(~D)=~A internal-pk=~A~%"
                                  tx-idx input-idx (length stack)
                                  (length control-block)
                                  (and control-block
                                       (hex (subseq control-block 0 (min 33 (length control-block)))))
                                  (and internal-pk (hex internal-pk)))))))

(defun find-failing-tx (block target-pubkey-hex)
  "Find a tx in BLOCK whose input has a witness with control-block matching
TARGET-PUBKEY-HEX (matching internal pubkey 6c1722c5...)."
  (let ((target (bitcoin-lisp.crypto:hex-to-bytes target-pubkey-hex)))
    (loop for tx in (bitcoin-lisp.serialization:bitcoin-block-transactions block)
          for tx-idx from 0
          for witness = (bitcoin-lisp.serialization:transaction-witness tx)
          when witness
            do (loop for stack in witness
                     for input-idx from 0
                     when (and stack (>= (length stack) 3))
                       do (let ((control-block (car (last stack))))
                            (when (and (>= (length control-block) 33)
                                       (let ((internal-pk (subseq control-block 1 33)))
                                         (equalp internal-pk target)))
                              (return-from find-failing-tx
                                (values tx tx-idx input-idx))))))))

(defun verify-input-tapscript (tx input-idx utxo-set block-tx-outputs)
  "Re-run the BIP 341 sighash for this tx-input and verify Schnorr.
BLOCK-TX-OUTPUTS is a hash table (cons txid index)→utxo-entry built
from earlier txs in the same block — fills the same-block dep gap that
validate-block-scripts has when prevout was created in this block.
Returns :pass / :fail / :skip-no-utxo and the (sighash, sig, pk1)."
  (let* ((inputs (bitcoin-lisp.serialization:transaction-inputs tx))
         (witness (bitcoin-lisp.serialization:transaction-witness tx))
         (witness-stack (nth input-idx witness))
         (sig (first witness-stack))
         (script (nth (- (length witness-stack) 2) witness-stack))
         (control-block (car (last witness-stack)))
         (leaf-version (logand (aref control-block 0) #xfe))
         (tapleaf-hash (bitcoin-lisp.crypto:tap-leaf-hash leaf-version script))
         (pk1 (subseq script 1 33))
         (spent-utxos (make-array (length inputs)))
         (any-missing nil))
    (loop for inp in inputs
          for i from 0
          do (let* ((po (bitcoin-lisp.serialization:tx-in-previous-output inp))
                    (h (bitcoin-lisp.serialization:outpoint-hash po))
                    (idx (bitcoin-lisp.serialization:outpoint-index po))
                    (utxo (or (bitcoin-lisp.storage:get-utxo utxo-set h idx)
                              (gethash (cons h idx) block-tx-outputs))))
               (unless utxo (setf any-missing t))
               (setf (aref spent-utxos i) utxo)))
    (when any-missing
      (return-from verify-input-tapscript
        (values :skip-no-utxo nil sig pk1 tapleaf-hash)))
    (let* ((bitcoin-lisp.coalton.interop:*current-tx* tx)
           (bitcoin-lisp.coalton.interop:*current-input-index* input-idx)
           (bitcoin-lisp.coalton.interop:*current-spent-utxos* spent-utxos)
           (bitcoin-lisp.coalton.interop:*precomputed-sighash*
             (bitcoin-lisp.coalton.interop:init-precomputed-sighash tx spent-utxos))
           (sighash (bitcoin-lisp.coalton.interop:compute-bip341-sighash
                     0 0 tapleaf-hash 0))
           (verify-fn (find-symbol "VERIFY-SCHNORR-SIGNATURE" "BITCOIN-LISP.CRYPTO"))
           (valid (funcall verify-fn sighash sig pk1)))
      (values (if valid :pass :fail) sighash sig pk1 tapleaf-hash))))

(defun build-block-tx-outputs (block)
  "Walk all txs in BLOCK and build a (txid . index) → utxo-entry hash
covering every output created in this block. Used to satisfy same-block
dependency lookups (mirrors what validate-block's pending-utxos does)."
  (let ((tbl (make-hash-table :test 'equalp)))
    (loop for tx in (bitcoin-lisp.serialization:bitcoin-block-transactions block)
          for txid = (bitcoin-lisp.serialization:transaction-hash tx)
          do (loop for out in (bitcoin-lisp.serialization:transaction-outputs tx)
                   for idx from 0
                   do (setf (gethash (cons txid idx) tbl)
                            (bitcoin-lisp.storage::make-utxo-entry
                             :value (bitcoin-lisp.serialization:tx-out-value out)
                             :script-pubkey (bitcoin-lisp.serialization:tx-out-script-pubkey out)
                             :height 67105
                             :coinbase nil))))
    tbl))

(defun dump-input (tx tx-idx input-idx utxo-set)
  (let* ((inputs (bitcoin-lisp.serialization:transaction-inputs tx))
         (outputs (bitcoin-lisp.serialization:transaction-outputs tx))
         (witness (bitcoin-lisp.serialization:transaction-witness tx))
         (input (nth input-idx inputs))
         (prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
         (prev-txid (bitcoin-lisp.serialization:outpoint-hash prevout))
         (prev-vout (bitcoin-lisp.serialization:outpoint-index prevout))
         (witness-stack (nth input-idx witness))
         (utxo (bitcoin-lisp.storage:get-utxo utxo-set prev-txid prev-vout))
         (txid (bitcoin-lisp.serialization:transaction-hash tx)))
    (format t "~%=== tx-idx=~D input-idx=~D ===~%" tx-idx input-idx)
    (format t "  txid (display, reversed)=~A~%"
            (hex (reverse txid)))
    (format t "  version=~D locktime=~D~%"
            (bitcoin-lisp.serialization:transaction-version tx)
            (bitcoin-lisp.serialization:transaction-lock-time tx))
    (format t "  num-inputs=~D num-outputs=~D~%"
            (length inputs) (length outputs))
    (format t "  prev-txid=~A:~D~%" (hex prev-txid) prev-vout)
    (format t "  prev-utxo: value=~D script=~A~%"
            (bitcoin-lisp.storage:utxo-entry-value utxo)
            (hex (bitcoin-lisp.storage:utxo-entry-script-pubkey utxo)))
    (format t "  sequence=~,'0X~%"
            (bitcoin-lisp.serialization:tx-in-sequence input))
    (format t "  witness items (~D):~%" (length witness-stack))
    (loop for w in witness-stack
          for i from 0
          do (format t "    [~D] (~D bytes) ~A~%" i (length w) (hex w)))
    ;; Dump all inputs for this tx (needed for sha_prevouts computation)
    (format t "  all inputs:~%")
    (loop for inp in inputs
          for i from 0
          do (let ((po (bitcoin-lisp.serialization:tx-in-previous-output inp)))
               (format t "    [~D] prev=~A:~D seq=~,'0X~%"
                       i
                       (hex (bitcoin-lisp.serialization:outpoint-hash po))
                       (bitcoin-lisp.serialization:outpoint-index po)
                       (bitcoin-lisp.serialization:tx-in-sequence inp))))
    (format t "  all outputs:~%")
    (loop for out in outputs
          for i from 0
          do (format t "    [~D] value=~D script=~A~%"
                     i
                     (bitcoin-lisp.serialization:tx-out-value out)
                     (hex (bitcoin-lisp.serialization:tx-out-script-pubkey out))))
    ;; Build spent-utxos vector and compute our sighash
    (let ((spent-utxos (make-array (length inputs))))
      (loop for inp in inputs
            for i from 0
            do (let* ((po (bitcoin-lisp.serialization:tx-in-previous-output inp))
                      (u (bitcoin-lisp.storage:get-utxo
                          utxo-set
                          (bitcoin-lisp.serialization:outpoint-hash po)
                          (bitcoin-lisp.serialization:outpoint-index po))))
                 (setf (aref spent-utxos i) u)))
      (let* ((bitcoin-lisp.coalton.interop:*current-tx* tx)
             (bitcoin-lisp.coalton.interop:*current-input-index* input-idx)
             (bitcoin-lisp.coalton.interop:*current-spent-utxos* spent-utxos)
             (bitcoin-lisp.coalton.interop:*precomputed-sighash*
               (bitcoin-lisp.coalton.interop:init-precomputed-sighash tx spent-utxos)))
        (format t "  precomputed:~%")
        (format t "    sha_prevouts=~A~%"
                (hex (bitcoin-lisp.coalton.interop::precomputed-sighash-data-sha-prevouts
                      bitcoin-lisp.coalton.interop:*precomputed-sighash*)))
        (format t "    sha_amounts=~A~%"
                (hex (bitcoin-lisp.coalton.interop::precomputed-sighash-data-sha-amounts
                      bitcoin-lisp.coalton.interop:*precomputed-sighash*)))
        (format t "    sha_scriptpubkeys=~A~%"
                (hex (bitcoin-lisp.coalton.interop::precomputed-sighash-data-sha-script-pubkeys
                      bitcoin-lisp.coalton.interop:*precomputed-sighash*)))
        (format t "    sha_sequences=~A~%"
                (hex (bitcoin-lisp.coalton.interop::precomputed-sighash-data-sha-sequences
                      bitcoin-lisp.coalton.interop:*precomputed-sighash*)))
        (format t "    sha_outputs=~A~%"
                (hex (bitcoin-lisp.coalton.interop::precomputed-sighash-data-sha-outputs
                      bitcoin-lisp.coalton.interop:*precomputed-sighash*)))
        ;; Compute tapleaf hash from witness script
        (let* ((control-block (car (last witness-stack)))
               (script (nth (- (length witness-stack) 2) witness-stack))
               (leaf-version (logand (aref control-block 0) #xfe))
               (tapleaf-hash (bitcoin-lisp.crypto:tap-leaf-hash leaf-version script)))
          (format t "  leaf-version=~,'0X~%" leaf-version)
          (format t "  tapleaf=~A~%" (hex tapleaf-hash))
          (let ((sighash (bitcoin-lisp.coalton.interop:compute-bip341-sighash
                          (bitcoin-lisp.storage:utxo-entry-value utxo)
                          0 ; SIGHASH_DEFAULT
                          tapleaf-hash 0)))
            (format t "  our-sighash=~A~%" (hex sighash))))))))

(multiple-value-bind (cs utxo bs) (init)
  (let ((blk (load-block-at-height cs bs 67105))
        (target-pk "6c1722c5baaa83da821c70ba37226591ebd50e34c8ef58739c705970daf7a171"))
    (let ((txs (bitcoin-lisp.serialization:bitcoin-block-transactions blk)))
      (format t "~%block has ~D txs~%" (length txs))
      (let ((witness-tx-count 0)
            (multi-stack-count 0)
            (longest-stack 0))
        (loop for tx in txs
              for tx-idx from 0
              for witness = (bitcoin-lisp.serialization:transaction-witness tx)
              when witness
                do (incf witness-tx-count)
                   (loop for stack in witness
                         when stack
                           do (when (> (length stack) longest-stack)
                                (setf longest-stack (length stack)))
                              (when (>= (length stack) 3)
                                (incf multi-stack-count))))
        (format t "witness txs: ~D / multi-item stacks: ~D / longest stack: ~D items~%"
                witness-tx-count multi-stack-count longest-stack)))
    ;; Identify tx-idx=30's prevouts: which come from same-block vs prior?
    (let* ((txs (bitcoin-lisp.serialization:bitcoin-block-transactions blk))
           (block-txids (mapcar #'bitcoin-lisp.serialization:transaction-hash txs))
           (block-txids-set (make-hash-table :test 'equalp)))
      (dolist (tid block-txids) (setf (gethash tid block-txids-set) t))
      (let ((tx30 (nth 30 txs)))
        (format t "~%--- tx-idx=30 prevout sources ---~%")
        (loop for inp in (bitcoin-lisp.serialization:transaction-inputs tx30)
              for i from 0
              do (let* ((po (bitcoin-lisp.serialization:tx-in-previous-output inp))
                        (h (bitcoin-lisp.serialization:outpoint-hash po))
                        (idx (bitcoin-lisp.serialization:outpoint-index po))
                        (in-block (gethash h block-txids-set))
                        (in-utxo (bitcoin-lisp.storage:get-utxo utxo h idx)))
                   (format t "  input ~D prev=~A:~D in-this-block=~A in-utxo-set=~A~%"
                           i (hex h) idx (if in-block "YES" "no") (if in-utxo "YES" "no"))))))
    ;; Run the LIVE validator path (validate-tx-scripts) on tx-idx=89.
    ;; Compare with my diagnostic which gives PASS — should also pass here
    ;; if the bug is in the IBD context (race, stale specials, etc.) or
    ;; FAIL here if the bug is in the validate-tx-scripts code itself.
    (let* ((txs (bitcoin-lisp.serialization:bitcoin-block-transactions blk))
           (tx89 (nth 89 txs))
           (script-flags (bitcoin-lisp.validation::compute-script-flags-for-height 67105)))
      (format t "~%--- LIVE PATH validate-tx-scripts(tx-idx=89) ---~%")
      (let ((result (bitcoin-lisp.validation::validate-tx-scripts
                     tx89 89 utxo script-flags 67105)))
        (format t "  result: ~A~%" result)))
    ;; Dump tx-idx=89 fully so we know its real input count.
    (let* ((txs (bitcoin-lisp.serialization:bitcoin-block-transactions blk))
           (tx89 (nth 89 txs))
           (inps (bitcoin-lisp.serialization:transaction-inputs tx89))
           (witness89 (bitcoin-lisp.serialization:transaction-witness tx89)))
      (format t "~%tx-idx=89 inputs=~D witness-stacks=~D~%"
              (length inps) (length witness89))
      (loop for w in witness89
            for i from 0
            do (format t "  input-idx=~D witness-items=~D~%" i (length w))))
    (format t "~%--- pass/fail for every 6c1722... tapscript spend ---~%")
    (let ((target (bitcoin-lisp.crypto:hex-to-bytes target-pk))
          (block-outs (build-block-tx-outputs blk))
          (passes '()) (fails '()) (skips 0))
      (loop for tx in (bitcoin-lisp.serialization:bitcoin-block-transactions blk)
            for tx-idx from 0
            for witness = (bitcoin-lisp.serialization:transaction-witness tx)
            when witness
              do (loop for stack in witness
                       for input-idx from 0
                       when (and stack (>= (length stack) 3))
                         do (let* ((cb (car (last stack))))
                              (when (and (>= (length cb) 33)
                                         (equalp (subseq cb 1 33) target))
                                (multiple-value-bind (status sighash sig pk1)
                                    (verify-input-tapscript tx input-idx utxo block-outs)
                                  (declare (ignore pk1))
                                  (case status
                                    (:skip-no-utxo (incf skips))
                                    (t
                                     (format t "  tx-idx=~D input-idx=~D ~A sighash=~A sig=~A~%"
                                             tx-idx input-idx status
                                             (subseq (hex sighash) 0 16)
                                             (subseq (hex sig) 0 16))
                                     (if (eq status :pass)
                                         (push (list tx tx-idx input-idx) passes)
                                         (push (list tx tx-idx input-idx) fails)))))))))
      (format t "~%~D passing, ~D failing, ~D skipped (no utxo)~%"
              (length passes) (length fails) skips)
      (when fails
        (format t "~%=== FAILING SAMPLE (first) ===~%")
        (destructuring-bind (tx tx-idx input-idx) (first (last fails))
          (dump-input tx tx-idx input-idx utxo)))
      (when passes
        (format t "~%=== PASSING SAMPLE (first) ===~%")
        (destructuring-bind (tx tx-idx input-idx) (first (last passes))
          (dump-input tx tx-idx input-idx utxo))))))

(sb-ext:exit :code 0)
