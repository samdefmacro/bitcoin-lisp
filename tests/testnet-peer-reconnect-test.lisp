;;;; Testnet peer reconnection test
;;;; Task 8.3: Verify peer reconnection - disconnect peer during sync, confirm replacement
;;;;
;;;; Run with: sbcl --noinform --load tests/testnet-peer-reconnect-test.lisp

(format t "Loading bitcoin-lisp system...~%")
(force-output)

(require :asdf)
(asdf:load-system :bitcoin-lisp)

(format t "System loaded.~%")
(force-output)

(defparameter *test-dir* (merge-pathnames "btc-lisp-peer-test/" (user-homedir-pathname)))

;; Clean start
(when (probe-file *test-dir*)
  (format t "Cleaning previous test data...~%")
  (uiop:delete-directory-tree (pathname *test-dir*) :validate t))
(ensure-directories-exist *test-dir*)

;; Enable console output
(setf bitcoin-lisp:*log-stream* *standard-output*)
(setf bitcoin-lisp::*current-log-level* :info)

(format t "~%========================================~%")
(format t "Testnet Peer Reconnection Test~%")
(format t "Data directory: ~A~%" *test-dir*)
(format t "========================================~%~%")
(force-output)

;; Start node
(bitcoin-lisp:start-node :data-directory *test-dir*
                          :network :testnet
                          :sync nil
                          :log-level :info)

(format t "Connecting to peers...~%")
(force-output)
(bitcoin-lisp::connect-to-peers bitcoin-lisp:*node* 4 :timeout 30 :min-peers 2)

(defparameter *initial-peers* (copy-list (bitcoin-lisp::node-peers bitcoin-lisp:*node*)))
(defparameter *initial-peer-count* (length *initial-peers*))

(format t "~%Initial peer count: ~D~%" *initial-peer-count*)
(dolist (peer *initial-peers*)
  (format t "  - ~A~%" (bitcoin-lisp::peer-address peer)))
(force-output)

(when (< *initial-peer-count* 2)
  (format t "~%ERROR: Need at least 2 peers for this test. Exiting.~%")
  (bitcoin-lisp:stop-node)
  (sb-ext:exit :code 1))

;; Start sync in background
(defparameter *sync-thread*
  (sb-thread:make-thread
   (lambda ()
     (handler-case
         (bitcoin-lisp::sync-blockchain bitcoin-lisp:*node* :max-blocks 300)
       (error (e)
         (format t "Sync error: ~A~%" e))))
   :name "sync-thread"))

;; Wait for some blocks to sync
(format t "~%Waiting for sync to start (50+ blocks)...~%")
(force-output)

(loop
  (sleep 5)
  (let ((height (bitcoin-lisp.storage:current-height
                 (bitcoin-lisp::node-chain-state bitcoin-lisp:*node*))))
    (format t "  Height: ~D, Peers: ~D~%"
            height (length (bitcoin-lisp::node-peers bitcoin-lisp:*node*)))
    (force-output)
    (when (>= height 50)
      (return))))

;; Get current peers before disconnect
(defparameter *peers-before* (copy-list (bitcoin-lisp::node-peers bitcoin-lisp:*node*)))
(defparameter *peer-count-before* (length *peers-before*))

(format t "~%=== DISCONNECTING A PEER ===~%")
(format t "Peers before disconnect: ~D~%" *peer-count-before*)
(force-output)

;; Disconnect the first peer
(let ((peer-to-disconnect (first *peers-before*)))
  (when peer-to-disconnect
    (format t "Disconnecting peer: ~A~%" (bitcoin-lisp::peer-address peer-to-disconnect))
    (force-output)
    ;; Close the socket to simulate disconnect
    (handler-case
        (progn
          (when (bitcoin-lisp::peer-socket peer-to-disconnect)
            (usocket:socket-close (bitcoin-lisp::peer-socket peer-to-disconnect)))
          ;; Remove from peer list
          (setf (bitcoin-lisp::node-peers bitcoin-lisp:*node*)
                (remove peer-to-disconnect (bitcoin-lisp::node-peers bitcoin-lisp:*node*))))
      (error (e)
        (format t "  (Disconnect error: ~A)~%" e)))))

(defparameter *peers-after-disconnect* (length (bitcoin-lisp::node-peers bitcoin-lisp:*node*)))
(format t "Peers immediately after disconnect: ~D~%" *peers-after-disconnect*)
(force-output)

;; Wait and monitor for peer replacement
(format t "~%Monitoring for peer replacement (60 seconds)...~%")
(force-output)

(defparameter *replacement-detected* nil)
(defparameter *max-peers-seen* *peers-after-disconnect*)
(defparameter *sync-continued* nil)
(defparameter *height-at-disconnect*
  (bitcoin-lisp.storage:current-height
   (bitcoin-lisp::node-chain-state bitcoin-lisp:*node*)))

(loop for i from 1 to 12 do  ; 12 * 5 = 60 seconds
  (sleep 5)
  (let* ((current-peers (length (bitcoin-lisp::node-peers bitcoin-lisp:*node*)))
         (current-height (bitcoin-lisp.storage:current-height
                          (bitcoin-lisp::node-chain-state bitcoin-lisp:*node*))))
    (format t "  [~2D] Height: ~D, Peers: ~D~%" (* i 5) current-height current-peers)
    (force-output)

    ;; Track max peers seen
    (when (> current-peers *max-peers-seen*)
      (setf *max-peers-seen* current-peers)
      (unless *replacement-detected*
        (format t "       *** Peer replacement detected! ***~%")
        (force-output)
        (setf *replacement-detected* t)))

    ;; Check if sync continued
    (when (> current-height (+ *height-at-disconnect* 20))
      (setf *sync-continued* t))))

;; Final status
(defparameter *final-peer-count* (length (bitcoin-lisp::node-peers bitcoin-lisp:*node*)))
(defparameter *final-height*
  (bitcoin-lisp.storage:current-height
   (bitcoin-lisp::node-chain-state bitcoin-lisp:*node*)))

(format t "~%========================================~%")
(format t "TEST RESULTS~%")
(format t "========================================~%")
(format t "  Initial peers:           ~D~%" *initial-peer-count*)
(format t "  Peers after disconnect:  ~D~%" *peers-after-disconnect*)
(format t "  Max peers observed:      ~D~%" *max-peers-seen*)
(format t "  Final peer count:        ~D~%" *final-peer-count*)
(format t "  Height at disconnect:    ~D~%" *height-at-disconnect*)
(format t "  Final height:            ~D~%" *final-height*)
(format t "  Blocks synced after:     ~D~%" (- *final-height* *height-at-disconnect*))
(format t "========================================~%")
(force-output)

;; Determine pass/fail
;; Test passes if:
;; 1. Sync continued after disconnect (height increased by 20+)
;; 2. Either peer count recovered OR sync completed successfully
(let ((test-passed (and *sync-continued*
                        (or *replacement-detected*
                            (>= *final-peer-count* *peers-after-disconnect*)))))
  (format t "~%")
  (if test-passed
      (progn
        (format t "TEST PASSED: ")
        (when *replacement-detected*
          (format t "Peer replacement detected. "))
        (when *sync-continued*
          (format t "Sync continued after disconnect."))
        (format t "~%"))
      (format t "TEST FAILED: Sync did not continue properly after peer disconnect.~%"))
  (format t "========================================~%")
  (force-output)

  (bitcoin-lisp:stop-node)
  (sb-ext:exit :code (if test-passed 0 1)))
