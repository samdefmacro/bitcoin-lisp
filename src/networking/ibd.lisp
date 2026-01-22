(in-package #:bitcoin-lisp.networking)

;;; Initial Block Download (IBD)
;;;
;;; Coordinates headers-first synchronization with the Bitcoin network.
;;; Implements download queue management, checkpoint validation, and
;;; sync state machine.

;;;; IBD State Machine

(deftype ibd-state ()
  "States for Initial Block Download."
  '(member :idle :syncing-headers :syncing-blocks :synced))

(defstruct ibd-context
  "Context for managing Initial Block Download."
  (state :idle :type keyword)
  (header-sync-peer nil)
  (target-height 0 :type (unsigned-byte 32))
  (headers-received 0 :type (unsigned-byte 32))
  (blocks-received 0 :type (unsigned-byte 32))
  ;; Download queue
  (pending-blocks (make-hash-table :test 'equalp) :type hash-table)  ; hash -> height
  (in-flight (make-hash-table :test 'equalp) :type hash-table)       ; hash -> (peer . timestamp)
  (block-queue '() :type list)  ; blocks received out-of-order, sorted by height
  ;; Configuration
  (max-in-flight 16 :type (unsigned-byte 8))
  (request-timeout 60 :type (unsigned-byte 16))  ; seconds
  ;; Progress tracking
  (start-time 0 :type integer)
  (last-progress-time 0 :type integer))

(defvar *ibd-context* nil
  "Current IBD context.")

(defun make-ibd ()
  "Create a new IBD context."
  (make-ibd-context :start-time (get-internal-real-time)))

(defun ibd-state ()
  "Get the current IBD state."
  (if *ibd-context*
      (ibd-context-state *ibd-context*)
      :idle))

(defun set-ibd-state (new-state)
  "Transition to a new IBD state."
  (when *ibd-context*
    (let ((old-state (ibd-context-state *ibd-context*)))
      (unless (eq old-state new-state)
        (setf (ibd-context-state *ibd-context*) new-state)
        ;; Only log if node is running (log-info requires *node*)
        (when bitcoin-lisp:*node*
          (bitcoin-lisp:log-info "IBD state: ~A -> ~A" old-state new-state))))))

;;;; Testnet Checkpoints

(defvar *testnet-checkpoints*
  '((546 . "000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70")
    (100000 . "00000000009e2958c15ff9290d571bf9459e93b19765c6801ddeccadbb160a1e")
    (200000 . "0000000000287bffd321963ef05feab753ber7dcf93e7f002f0fd1c21d2ee6")  ; Placeholder
    (500000 . "000000000001a7c0aaa2630fbb2c0e476aafffc60f82177375b2aaa22209f606")
    (1000000 . "0000000000478e259a3eda2fafbeeb0106626f946347955e99278fe6cc848414")
    (1500000 . "00000000000000a33e21d6d82fe7cef5b35dfe75af01baafa5df7c11e69cf099")
    (2000000 . "0000000000000795a6501e606e3fd3b3f51c6d9e47d3a1ba83c3fb1e84d50b7a"))
  "Testnet checkpoints as (height . hex-hash) pairs.")

(defun get-checkpoint-hash (height)
  "Get the checkpoint hash for HEIGHT, or NIL if no checkpoint exists."
  (let ((entry (assoc height *testnet-checkpoints*)))
    (when entry
      (bitcoin-lisp.crypto:hex-to-bytes (cdr entry)))))

(defun last-checkpoint-height ()
  "Get the height of the last checkpoint."
  (if *testnet-checkpoints*
      (caar (last *testnet-checkpoints*))
      0))

(defun validate-checkpoint (hash height)
  "Validate that HASH at HEIGHT matches any applicable checkpoint.
Returns T if valid or no checkpoint at that height, NIL if checkpoint mismatch."
  (let ((checkpoint-hash (get-checkpoint-hash height)))
    (or (null checkpoint-hash)
        (equalp hash checkpoint-hash))))

;;;; Header Chain Validation

(defun validate-header-pow (header)
  "Validate proof-of-work for a header.
Returns T if hash is below target, NIL otherwise."
  (let* ((hash (bitcoin-lisp.serialization:block-header-hash header))
         (bits (bitcoin-lisp.serialization:block-header-bits header))
         (target (bitcoin-lisp.storage:bits-to-target bits)))
    ;; Convert hash to integer (little-endian)
    (let ((hash-value 0))
      (loop for i from 31 downto 0
            do (setf hash-value (logior (ash hash-value 8) (aref hash i))))
      (<= hash-value target))))

(defun validate-header-chain (headers chain-state)
  "Validate a list of headers against the current chain state.
Returns (VALUES valid-headers error-message).
VALID-HEADERS is a list of headers that passed validation (may be fewer than input)."
  (let ((valid-headers '())
        (prev-hash nil)
        (prev-entry nil))
    (dolist (header headers)
      (block continue
        (let* ((hash (bitcoin-lisp.serialization:block-header-hash header))
               (header-prev-hash (bitcoin-lisp.serialization:block-header-prev-block header)))

          ;; Check if we already have this header
          (when (bitcoin-lisp.storage:get-block-index-entry chain-state hash)
            (setf prev-hash hash)
            (setf prev-entry (bitcoin-lisp.storage:get-block-index-entry chain-state hash))
            (return-from continue))

          ;; Check chain linkage
          (let ((parent (or prev-entry
                            (bitcoin-lisp.storage:get-block-index-entry
                             chain-state header-prev-hash))))
            (unless parent
              ;; No parent found, stop here
              (return-from validate-header-chain
                (values (nreverse valid-headers)
                        (format nil "Missing parent ~A"
                                (bitcoin-lisp.crypto:bytes-to-hex header-prev-hash)))))

            ;; Validate proof-of-work
            (unless (validate-header-pow header)
              (return-from validate-header-chain
                (values (nreverse valid-headers)
                        "Invalid proof-of-work")))

            ;; Calculate new height and validate checkpoint
            (let ((new-height (1+ (bitcoin-lisp.storage:block-index-entry-height parent))))
              (unless (validate-checkpoint hash new-height)
                (return-from validate-header-chain
                  (values (nreverse valid-headers)
                          (format nil "Checkpoint mismatch at height ~D" new-height))))

              ;; Header is valid
              (push header valid-headers)
              (setf prev-hash hash)
              (setf prev-entry nil))))))  ; Will look up in chain-state next iteration

    (values (nreverse valid-headers) nil)))

;;;; Enhanced Header Handling

(defun process-headers (headers chain-state)
  "Process validated headers and add to block index.
Returns the number of new headers added."
  (let ((added 0)
        (best-height (bitcoin-lisp.storage:current-height chain-state)))
    (dolist (header headers)
      (let* ((hash (bitcoin-lisp.serialization:block-header-hash header))
             (prev-hash (bitcoin-lisp.serialization:block-header-prev-block header)))
        ;; Skip if already have it
        (unless (bitcoin-lisp.storage:get-block-index-entry chain-state hash)
          (let ((prev-entry (bitcoin-lisp.storage:get-block-index-entry
                             chain-state prev-hash)))
            (when prev-entry
              (let* ((new-height (1+ (bitcoin-lisp.storage:block-index-entry-height
                                      prev-entry)))
                     (prev-work (bitcoin-lisp.storage:block-index-entry-chain-work
                                 prev-entry))
                     (bits (bitcoin-lisp.serialization:block-header-bits header))
                     (entry (bitcoin-lisp.storage:make-block-index-entry
                             :hash hash
                             :height new-height
                             :header header
                             :prev-entry prev-entry
                             :chain-work (bitcoin-lisp.storage:calculate-chain-work
                                          bits prev-work)
                             :status :header-valid)))
                (bitcoin-lisp.storage:add-block-index-entry chain-state entry)
                (incf added)
                ;; Update best height if this extends our chain
                (when (> new-height best-height)
                  (setf best-height new-height))))))))
    added))

;;;; Download Queue Management

(defun queue-blocks-for-download (chain-state start-height end-height)
  "Queue blocks for download from START-HEIGHT to END-HEIGHT.
Walks the header chain and adds block hashes to the pending queue."
  (unless *ibd-context*
    (return-from queue-blocks-for-download 0))

  (let ((queued 0)
        (pending (ibd-context-pending-blocks *ibd-context*)))
    ;; Find headers at each height and queue them
    ;; This is O(n) in the chain length, but we only do it once per batch
    (maphash (lambda (hash entry)
               (let ((height (bitcoin-lisp.storage:block-index-entry-height entry)))
                 (when (and (>= height start-height)
                            (<= height end-height)
                            (eq (bitcoin-lisp.storage:block-index-entry-status entry)
                                :header-valid)
                            (not (gethash hash pending)))
                   (setf (gethash hash pending) height)
                   (incf queued))))
             (bitcoin-lisp.storage::chain-state-block-index chain-state))
    queued))

(defun get-next-blocks-to-request (n)
  "Get up to N block hashes to request, sorted by height."
  (unless *ibd-context*
    (return-from get-next-blocks-to-request nil))

  (let ((pending (ibd-context-pending-blocks *ibd-context*))
        (in-flight (ibd-context-in-flight *ibd-context*))
        (available '()))
    ;; Collect blocks that are pending but not in-flight
    (maphash (lambda (hash height)
               (unless (gethash hash in-flight)
                 (push (cons hash height) available)))
             pending)
    ;; Sort by height and take first N
    (let ((sorted (sort available #'< :key #'cdr)))
      (mapcar #'car (subseq sorted 0 (min n (length sorted)))))))

(defun mark-block-in-flight (hash peer)
  "Mark a block as being requested from PEER."
  (when *ibd-context*
    (setf (gethash hash (ibd-context-in-flight *ibd-context*))
          (cons peer (get-internal-real-time)))))

(defun mark-block-received (hash)
  "Mark a block as received, removing it from pending and in-flight."
  (when *ibd-context*
    (remhash hash (ibd-context-pending-blocks *ibd-context*))
    (remhash hash (ibd-context-in-flight *ibd-context*))
    (incf (ibd-context-blocks-received *ibd-context*))))

(defun get-timed-out-requests ()
  "Get list of block hashes that have timed out."
  (unless *ibd-context*
    (return-from get-timed-out-requests nil))

  (let ((in-flight (ibd-context-in-flight *ibd-context*))
        (timeout-ticks (* (ibd-context-request-timeout *ibd-context*)
                          internal-time-units-per-second))
        (now (get-internal-real-time))
        (timed-out '()))
    (maphash (lambda (hash peer-time)
               (when (> (- now (cdr peer-time)) timeout-ticks)
                 (push hash timed-out)))
             in-flight)
    timed-out))

(defun retry-timed-out-requests ()
  "Remove timed out requests from in-flight so they can be retried."
  (let ((timed-out (get-timed-out-requests)))
    (dolist (hash timed-out)
      (remhash hash (ibd-context-in-flight *ibd-context*)))
    (length timed-out)))

;;;; Multi-Peer Request Distribution

(defun request-blocks-from-peers (peers chain-state)
  "Request blocks from multiple peers, distributing the load."
  (unless (and *ibd-context* peers)
    (return-from request-blocks-from-peers 0))

  ;; First, handle any timed out requests
  (let ((retried (retry-timed-out-requests)))
    (when (> retried 0)
      (bitcoin-lisp:log-warn "Retrying ~D timed out block requests" retried)))

  ;; Calculate how many more requests we can make
  (let* ((in-flight-count (hash-table-count (ibd-context-in-flight *ibd-context*)))
         (max-in-flight (ibd-context-max-in-flight *ibd-context*))
         (can-request (- max-in-flight in-flight-count)))

    (when (<= can-request 0)
      (return-from request-blocks-from-peers 0))

    ;; Get blocks to request
    (let ((to-request (get-next-blocks-to-request can-request))
          (ready-peers (remove-if-not (lambda (p) (eq (peer-state p) :ready)) peers)))

      (when (or (null to-request) (null ready-peers))
        (return-from request-blocks-from-peers 0))

      ;; Distribute requests across peers
      (let ((requests-made 0)
            (peer-index 0)
            (num-peers (length ready-peers)))
        (dolist (hash to-request)
          (let ((peer (nth (mod peer-index num-peers) ready-peers)))
            (mark-block-in-flight hash peer)
            (incf peer-index)
            (incf requests-made)))

        ;; Now send the actual requests, grouped by peer
        (let ((peer-requests (make-hash-table :test 'eq)))
          (maphash (lambda (hash peer-time)
                     (let ((peer (car peer-time)))
                       (push hash (gethash peer peer-requests))))
                   (ibd-context-in-flight *ibd-context*))

          ;; Send batch request to each peer
          (maphash (lambda (peer hashes)
                     (when hashes
                       (let ((inv-vectors (mapcar (lambda (h)
                                                    (bitcoin-lisp.serialization:make-inv-vector
                                                     :type bitcoin-lisp.serialization:+inv-type-block+
                                                     :hash h))
                                                  hashes)))
                         (send-message peer
                                       (bitcoin-lisp.serialization:make-getdata-message
                                        inv-vectors)))))
                   peer-requests))

        requests-made))))

;;;; Progress Reporting

(defun ibd-progress ()
  "Return a plist with current IBD progress."
  (unless *ibd-context*
    (return-from ibd-progress nil))

  (let* ((ctx *ibd-context*)
         (elapsed-secs (/ (- (get-internal-real-time) (ibd-context-start-time ctx))
                          internal-time-units-per-second))
         (blocks (ibd-context-blocks-received ctx))
         (target (ibd-context-target-height ctx))
         (pending (hash-table-count (ibd-context-pending-blocks ctx)))
         (in-flight (hash-table-count (ibd-context-in-flight ctx))))
    (list :state (ibd-context-state ctx)
          :headers-received (ibd-context-headers-received ctx)
          :blocks-received blocks
          :target-height target
          :pending-blocks pending
          :in-flight-blocks in-flight
          :elapsed-seconds (round elapsed-secs)
          :blocks-per-second (if (> elapsed-secs 0)
                                 (/ blocks elapsed-secs)
                                 0)
          :progress-percent (if (> target 0)
                                (* 100.0 (/ blocks target))
                                0))))

(defun report-ibd-progress ()
  "Log current IBD progress."
  (let ((progress (ibd-progress)))
    (when progress
      (bitcoin-lisp:log-info "IBD Progress: ~D/~D blocks (~,1F%), ~,1F blocks/sec, ~D pending, ~D in-flight"
                             (getf progress :blocks-received)
                             (getf progress :target-height)
                             (getf progress :progress-percent)
                             (getf progress :blocks-per-second)
                             (getf progress :pending-blocks)
                             (getf progress :in-flight-blocks)))))

;;;; Main IBD Loop

(defun start-ibd (peers chain-state utxo-set block-store target-height)
  "Start Initial Block Download.
Returns the number of blocks downloaded."
  (setf *ibd-context* (make-ibd))
  (setf (ibd-context-target-height *ibd-context*) target-height)

  (unwind-protect
       (run-ibd peers chain-state utxo-set block-store)
    (setf *ibd-context* nil)))

(defun run-ibd (peers chain-state utxo-set block-store)
  "Main IBD loop."
  (let ((ctx *ibd-context*)
        (start-height (bitcoin-lisp.storage:current-height chain-state)))

    ;; Phase 1: Download headers
    (set-ibd-state :syncing-headers)
    (let ((best-peer (first (sort (copy-list peers) #'>
                                  :key #'peer-start-height))))
      (when best-peer
        (setf (ibd-context-header-sync-peer ctx) best-peer)
        (sync-headers best-peer chain-state)))

    ;; Phase 2: Download and validate blocks
    (set-ibd-state :syncing-blocks)

    ;; Queue all blocks from current height to header tip
    (let ((header-tip (bitcoin-lisp.storage:current-height chain-state)))
      (queue-blocks-for-download chain-state (1+ start-height) header-tip))

    ;; Download blocks
    (let ((last-report-time (get-internal-real-time))
          (report-interval (* 10 internal-time-units-per-second)))  ; Every 10 seconds

      (loop while (> (hash-table-count (ibd-context-pending-blocks ctx)) 0)
            do (progn
                 ;; Request more blocks if needed
                 (request-blocks-from-peers peers chain-state)

                 ;; Receive and process messages from all peers
                 (dolist (peer peers)
                   (when (eq (peer-state peer) :ready)
                     (multiple-value-bind (command payload)
                         (receive-message peer :timeout 1)  ; Short timeout for polling
                       (when command
                         (cond
                           ((string= command "block")
                            (let* ((block (bitcoin-lisp.serialization:parse-block-payload payload))
                                   (header (bitcoin-lisp.serialization:bitcoin-block-header block))
                                   (hash (bitcoin-lisp.serialization:block-header-hash header)))
                              (mark-block-received hash)
                              (process-received-block block chain-state utxo-set block-store)))

                           ((string= command "headers")
                            (let ((headers (bitcoin-lisp.serialization:parse-headers-payload payload)))
                              (process-headers headers chain-state)
                              (incf (ibd-context-headers-received ctx) (length headers))))

                           (t (handle-message peer command payload
                                              chain-state utxo-set block-store)))))))

                 ;; Periodic progress report
                 (let ((now (get-internal-real-time)))
                   (when (> (- now last-report-time) report-interval)
                     (report-ibd-progress)
                     (setf last-report-time now))))))

    ;; Done
    (set-ibd-state :synced)
    (ibd-context-blocks-received ctx)))

(defun sync-headers (peer chain-state)
  "Download all headers from a peer."
  (let ((received-count 0)
        (done nil))
    (loop until done
          do (progn
               ;; Request headers
               (request-headers peer chain-state)

               ;; Wait for response
               (multiple-value-bind (command payload)
                   (receive-message peer :timeout 60)
                 (unless (and command (string= command "headers"))
                   (bitcoin-lisp:log-warn "Expected headers, got ~A" command)
                   (setf done t)
                   (return))

                 (let ((headers (bitcoin-lisp.serialization:parse-headers-payload payload)))
                   (when (null headers)
                     (setf done t)
                     (return))

                   ;; Validate and add headers
                   (multiple-value-bind (valid-headers error)
                       (validate-header-chain headers chain-state)
                     (when error
                       (bitcoin-lisp:log-warn "Header validation error: ~A" error))

                     (let ((added (process-headers valid-headers chain-state)))
                       (incf received-count added)

                       ;; If we got less than 2000, we're done
                       (when (< (length headers) 2000)
                         (setf done t))

                       (bitcoin-lisp:log-debug "Received ~D headers, ~D new, total ~D"
                                               (length headers) added received-count)))))))

    (bitcoin-lisp:log-info "Header sync complete: ~D headers received" received-count)
    received-count))

(defun process-received-block (block chain-state utxo-set block-store)
  "Process a received block - validate and connect to chain."
  (let* ((header (bitcoin-lisp.serialization:bitcoin-block-header block))
         (hash (bitcoin-lisp.serialization:block-header-hash header))
         (entry (bitcoin-lisp.storage:get-block-index-entry chain-state hash)))

    (unless entry
      (bitcoin-lisp:log-warn "Received unknown block ~A"
                             (bitcoin-lisp.crypto:bytes-to-hex hash))
      (return-from process-received-block nil))

    (let ((height (bitcoin-lisp.storage:block-index-entry-height entry))
          (current-height (bitcoin-lisp.storage:current-height chain-state)))

      ;; Check if this is the next block we need
      (if (= height (1+ current-height))
          ;; Validate and connect
          (let ((current-time (bitcoin-lisp.serialization:get-unix-time)))
            (multiple-value-bind (valid error)
                (bitcoin-lisp.validation:validate-block
                 block chain-state utxo-set height current-time)
              (if valid
                  (progn
                    (bitcoin-lisp.validation:connect-block
                     block chain-state block-store utxo-set)
                    t)
                  (progn
                    (bitcoin-lisp:log-error "Block ~D validation failed: ~A" height error)
                    nil))))

          ;; Out of order - queue for later
          (progn
            (bitcoin-lisp:log-debug "Block ~D received out of order (current: ~D)"
                                    height current-height)
            ;; Store in queue for later processing
            (when *ibd-context*
              (push (cons height block) (ibd-context-block-queue *ibd-context*)))
            nil)))))
