;;;; Testnet sync test - 1000 blocks with UTXO verification
;;;; Task 8.1: Manual testnet sync test
;;;;
;;;; Run with: sbcl --noinform --load tests/testnet-1000-blocks.lisp

(format t "Loading bitcoin-lisp system...~%")
(force-output)

(require :asdf)
(asdf:load-system :bitcoin-lisp)

(format t "System loaded.~%")
(force-output)

(defparameter *target-blocks* 1000)
(defparameter *test-dir* (merge-pathnames "btc-lisp-1000-test/" (user-homedir-pathname)))
(ensure-directories-exist *test-dir*)

;; Enable console output
(setf bitcoin-lisp:*log-stream* *standard-output*)
(setf bitcoin-lisp::*current-log-level* :info)

(format t "~%========================================~%")
(format t "Testnet Sync Test - Target: ~A blocks~%" *target-blocks*)
(format t "Data directory: ~A~%" *test-dir*)
(format t "========================================~%~%")
(force-output)

;; Start node
(bitcoin-lisp:start-node :data-directory *test-dir*
                          :network :testnet
                          :sync nil
                          :log-level :info)

(defparameter *start-height*
  (bitcoin-lisp.storage:current-height
   (bitcoin-lisp::node-chain-state bitcoin-lisp:*node*)))

(format t "Starting height: ~D~%" *start-height*)
(force-output)

;; Connect to peers
(format t "~%Connecting to peers...~%")
(force-output)
(bitcoin-lisp::connect-to-peers bitcoin-lisp:*node* 4 :timeout 30 :min-peers 1)

(defparameter *peer-count* (length (bitcoin-lisp::node-peers bitcoin-lisp:*node*)))
(format t "Connected to ~D peers~%" *peer-count*)
(force-output)

(when (zerop *peer-count*)
  (format t "~%ERROR: No peers connected. Exiting.~%")
  (bitcoin-lisp:stop-node)
  (sb-ext:exit :code 1))

;; Track UTXO checkpoints
(defparameter *utxo-checkpoints* (make-hash-table))
(defparameter *start-time* (get-universal-time))

(defun get-utxo-count ()
  (let ((utxo-set (bitcoin-lisp::node-utxo-set bitcoin-lisp:*node*)))
    (when utxo-set
      (hash-table-count (bitcoin-lisp.storage::utxo-set-entries utxo-set)))))

(defun verify-utxo-consistency ()
  "Verify UTXO set is consistent"
  (let* ((utxo-set (bitcoin-lisp::node-utxo-set bitcoin-lisp:*node*))
         (utxos (when utxo-set (bitcoin-lisp.storage::utxo-set-entries utxo-set)))
         (count (if utxos (hash-table-count utxos) 0))
         (valid-count 0)
         (invalid-count 0))
    (when utxos
      (maphash (lambda (key value)
                 (if (and (= (length key) 36)  ; txid (32) + vout (4)
                          (typep value 'bitcoin-lisp.storage::utxo-entry))
                     (incf valid-count)
                     (incf invalid-count)))
               utxos))
    (format t "~%UTXO Verification:~%")
    (format t "  Total entries: ~A~%" count)
    (format t "  Valid entries: ~A~%" valid-count)
    (format t "  Invalid entries: ~A~%" invalid-count)
    (force-output)
    (zerop invalid-count)))

;; Start background sync
(format t "~%Starting sync to ~D blocks...~%" *target-blocks*)
(force-output)

;; Run sync in a separate thread so we can monitor
(defparameter *sync-complete* nil)
(defparameter *sync-error* nil)

(sb-thread:make-thread
 (lambda ()
   (handler-case
       (progn
         (bitcoin-lisp::sync-blockchain bitcoin-lisp:*node* :max-blocks *target-blocks*)
         (setf *sync-complete* t))
     (error (e)
       (setf *sync-error* e)
       (setf *sync-complete* t))))
 :name "sync-thread")

;; Monitor progress
(loop
  (sleep 10)
  (let* ((height (bitcoin-lisp.storage:current-height
                  (bitcoin-lisp::node-chain-state bitcoin-lisp:*node*)))
         (elapsed (- (get-universal-time) *start-time*))
         (utxo-count (get-utxo-count)))

    ;; Save checkpoint every 250 blocks
    (when (and (> height 0)
               (zerop (mod height 250))
               (not (gethash height *utxo-checkpoints*)))
      (setf (gethash height *utxo-checkpoints*) utxo-count)
      (format t "~%*** Checkpoint at block ~A: ~A UTXOs ***~%" height utxo-count)
      (force-output))

    ;; Check if sync complete or error
    (when *sync-complete*
      (cond
        (*sync-error*
         (format t "~%~%========================================~%")
         (format t "SYNC ERROR: ~A~%" *sync-error*)
         (format t "========================================~%")
         (force-output)
         (bitcoin-lisp:stop-node)
         (sb-ext:exit :code 1))
        (t
         (let ((final-height (bitcoin-lisp.storage:current-height
                              (bitcoin-lisp::node-chain-state bitcoin-lisp:*node*))))
           (format t "~%~%========================================~%")
           (format t "SYNC COMPLETE: ~A blocks synced!~%" final-height)
           (format t "Time elapsed: ~A seconds~%" elapsed)
           (when (> elapsed 0)
             (format t "Average rate: ~,2F blocks/sec~%" (/ final-height elapsed)))
           (format t "========================================~%")
           (force-output)

           ;; Final verification
           (let ((consistent (verify-utxo-consistency)))
             (format t "~%Checkpoints recorded:~%")
             (maphash (lambda (h utxos)
                        (format t "  Block ~A: ~A UTXOs~%" h utxos))
                      *utxo-checkpoints*)

             (format t "~%========================================~%")
             (if consistent
                 (format t "TEST PASSED: UTXO set is consistent~%")
                 (format t "TEST FAILED: UTXO set has inconsistencies~%"))
             (format t "========================================~%")
             (force-output)

             ;; Stop node and exit
             (bitcoin-lisp:stop-node)
             (sb-ext:exit :code (if consistent 0 1)))))))))
