;;;; Testnet sync resume test
;;;; Task 8.2: Verify sync resume - stop mid-sync, restart, confirm resume
;;;;
;;;; Run with: sbcl --noinform --load tests/testnet-resume-test.lisp

(format t "Loading bitcoin-lisp system...~%")
(force-output)

(require :asdf)
(asdf:load-system :bitcoin-lisp)

(format t "System loaded.~%")
(force-output)

(defparameter *test-dir* (merge-pathnames "btc-lisp-resume-test/" (user-homedir-pathname)))

;; Clean start for this test
(when (probe-file *test-dir*)
  (format t "Cleaning previous test data...~%")
  (uiop:delete-directory-tree (pathname *test-dir*) :validate t))
(ensure-directories-exist *test-dir*)

;; Enable console output
(setf bitcoin-lisp:*log-stream* *standard-output*)
(setf bitcoin-lisp::*current-log-level* :info)

(format t "~%========================================~%")
(format t "Testnet Sync Resume Test~%")
(format t "Data directory: ~A~%" *test-dir*)
(format t "========================================~%~%")
(force-output)

;;; PHASE 1: Sync some blocks, then stop

(format t "=== PHASE 1: Initial sync to 500 blocks ===~%")
(force-output)

(bitcoin-lisp:start-node :data-directory *test-dir*
                          :network :testnet
                          :sync nil
                          :log-level :info)

(format t "Connecting to peers...~%")
(force-output)
(bitcoin-lisp::connect-to-peers bitcoin-lisp:*node* 4 :timeout 30 :min-peers 1)

(defparameter *peer-count* (length (bitcoin-lisp::node-peers bitcoin-lisp:*node*)))
(format t "Connected to ~D peers~%" *peer-count*)
(force-output)

(when (zerop *peer-count*)
  (format t "~%ERROR: No peers connected. Exiting.~%")
  (bitcoin-lisp:stop-node)
  (sb-ext:exit :code 1))

;; Start sync in background thread
(defparameter *sync-thread*
  (sb-thread:make-thread
   (lambda ()
     (handler-case
         (bitcoin-lisp::sync-blockchain bitcoin-lisp:*node* :max-blocks 500)
       (error (e)
         (format t "Sync error: ~A~%" e))))
   :name "sync-thread"))

;; Wait until we have at least 200 blocks
(format t "Waiting for 200+ blocks before stopping...~%")
(force-output)

(loop
  (sleep 5)
  (let ((height (bitcoin-lisp.storage:current-height
                 (bitcoin-lisp::node-chain-state bitcoin-lisp:*node*))))
    (format t "  Current height: ~D~%" height)
    (force-output)
    (when (>= height 200)
      (return))))

(defparameter *phase1-height*
  (bitcoin-lisp.storage:current-height
   (bitcoin-lisp::node-chain-state bitcoin-lisp:*node*)))

(format t "~%Phase 1 complete. Stopping at height ~D~%" *phase1-height*)
(force-output)

;; Stop the node (this should persist state)
(format t "Stopping node...~%")
(force-output)
(bitcoin-lisp:stop-node)

;; Wait for sync thread to finish
(sb-thread:join-thread *sync-thread* :default nil :timeout 5)

(format t "Node stopped.~%~%")
(force-output)

;; Check what files were persisted
(format t "Persisted files:~%")
(dolist (f (directory (merge-pathnames "*.*" *test-dir*)))
  (format t "  ~A~%" (enough-namestring f *test-dir*)))
(let ((blocks-dir (merge-pathnames "blocks/" *test-dir*)))
  (when (probe-file blocks-dir)
    (format t "  blocks/: ~D files~%" (length (directory (merge-pathnames "*" blocks-dir))))))
(force-output)

;;; PHASE 2: Restart and verify resume

(format t "~%=== PHASE 2: Restart and verify resume ===~%")
(format t "Waiting 3 seconds before restart...~%")
(force-output)
(sleep 3)

(format t "Starting node again...~%")
(force-output)

(bitcoin-lisp:start-node :data-directory *test-dir*
                          :network :testnet
                          :sync nil
                          :log-level :info)

(defparameter *phase2-start-height*
  (bitcoin-lisp.storage:current-height
   (bitcoin-lisp::node-chain-state bitcoin-lisp:*node*)))

(format t "~%Restart complete. Starting height: ~D~%" *phase2-start-height*)
(force-output)

;; Verify we resumed from persisted state
(cond
  ((zerop *phase2-start-height*)
   (format t "~%========================================~%")
   (format t "TEST FAILED: Node started from height 0~%")
   (format t "Expected to resume from ~D~%" *phase1-height*)
   (format t "========================================~%")
   (force-output)
   (bitcoin-lisp:stop-node)
   (sb-ext:exit :code 1))

  ((< *phase2-start-height* (- *phase1-height* 10))
   (format t "~%========================================~%")
   (format t "TEST FAILED: Resumed too far back~%")
   (format t "Phase 1 stopped at: ~D~%" *phase1-height*)
   (format t "Phase 2 started at: ~D~%" *phase2-start-height*)
   (format t "========================================~%")
   (force-output)
   (bitcoin-lisp:stop-node)
   (sb-ext:exit :code 1))

  (t
   (format t "~%Resume verification PASSED!~%")
   (format t "  Phase 1 stopped at: ~D~%" *phase1-height*)
   (format t "  Phase 2 started at: ~D~%" *phase2-start-height*)
   (force-output)))

;; Continue syncing to verify we can build on resumed state
(format t "~%Connecting to peers to continue sync...~%")
(force-output)
(bitcoin-lisp::connect-to-peers bitcoin-lisp:*node* 4 :timeout 30 :min-peers 1)

(setf *peer-count* (length (bitcoin-lisp::node-peers bitcoin-lisp:*node*)))
(format t "Connected to ~D peers~%" *peer-count*)
(force-output)

(when (> *peer-count* 0)
  (format t "~%Syncing 100 more blocks to verify chain continuity...~%")
  (force-output)

  ;; Sync in background
  (defparameter *sync-thread-2*
    (sb-thread:make-thread
     (lambda ()
       (handler-case
           (bitcoin-lisp::sync-blockchain bitcoin-lisp:*node*
                                           :max-blocks (+ *phase2-start-height* 100))
         (error (e)
           (format t "Sync error: ~A~%" e))))
     :name "sync-thread-2"))

  ;; Wait for 100 more blocks
  (loop
    (sleep 5)
    (let ((height (bitcoin-lisp.storage:current-height
                   (bitcoin-lisp::node-chain-state bitcoin-lisp:*node*))))
      (format t "  Current height: ~D~%" height)
      (force-output)
      (when (>= height (+ *phase2-start-height* 100))
        (return)))))

(defparameter *final-height*
  (bitcoin-lisp.storage:current-height
   (bitcoin-lisp::node-chain-state bitcoin-lisp:*node*)))

(format t "~%========================================~%")
(format t "TEST PASSED: Sync Resume Verified~%")
(format t "========================================~%")
(format t "  Phase 1 stopped at:  ~D blocks~%" *phase1-height*)
(format t "  Phase 2 resumed at:  ~D blocks~%" *phase2-start-height*)
(format t "  Final height:        ~D blocks~%" *final-height*)
(format t "  Blocks synced after resume: ~D~%" (- *final-height* *phase2-start-height*))
(format t "========================================~%")
(force-output)

(bitcoin-lisp:stop-node)
(sb-ext:exit :code 0)
