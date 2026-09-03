(in-package #:bitcoin-lisp)

;;; -stopatheight / disk-space / periodic peers.dat dump support

(defvar *stop-at-height-triggered* nil
  "Once-only latch for -stopatheight so the shutdown request is made once.")

(defvar *disk-space-abort-triggered* nil
  "Once-only latch for the low-disk-space abort at flush points.")

(defvar *last-peers-dump-time* 0
  "Universal-time of the last periodic peers.dat dump.")

(defconstant +peers-dump-interval-seconds+ (* 15 60)
  "Cadence of the periodic peers.dat dump (Core DUMP_PEERS_INTERVAL = 15
minutes, net.cpp:63, scheduled at net.cpp:3560).")

(bl.vi:define-validation-hook :updated-block-tip maybe-stop-at-height (chainstate hash height)
  "Request a node shutdown once HEIGHT reaches -stopatheight (Core
KernelNotifications::blockTip, node/kernel_notifications.cpp:61-66). An
:updated-block-tip hook; a background (targeted) chainstate's tips never
trigger it -- Core's blockTip is the active chainstate's. Only REQUESTS the
shutdown: the main thread runs stop-node (which joins the sync thread --
usually the caller here), and the clean exit code stops the supervisor from
respawning straight back into the same trigger."
  (declare (ignore hash))
  (when (and chainstate (bl.store:chain-state-target-blockhash chainstate))
    (return-from maybe-stop-at-height nil))
  ;; Under -debug=net, say WHICH guard declined when the height has been
  ;; reached. The stopatheight fix wired this into the activation-step loop and a benchmark
  ;; reindex then ran straight past -stopatheight=134000 to 134898. The seam is
  ;; connected — ACTIVATION-STEPS-REPORT-THE-NEW-TIP-TO-STOPATHEIGHT proves
  ;; activate-best-chain calls this with the height it reached — so the refusal
  ;; is one of the guards below, and nothing on the outside can tell which.
  (when (and (plusp *stop-at-height*)
             (>= height *stop-at-height*)
             (or *stop-at-height-triggered*
                 (null *node*)
                 (not (node-running *node*))))
    (log-debug "stopatheight ~D reached at height ~D but not acted on: ~A"
               *stop-at-height* height
               (cond (*stop-at-height-triggered* "already triggered")
                     ((null *node*) "no *node*")
                     (t "node not running"))))
  (when (and (plusp *stop-at-height*)
             (>= height *stop-at-height*)
             (not *stop-at-height-triggered*)
             *node*
             (node-running *node*))
    (setf *stop-at-height-triggered* t)
    (log-info "Reached stopatheight=~D — requesting shutdown" *stop-at-height*)
    (request-node-shutdown (format nil "-stopatheight=~D reached" *stop-at-height*)
                           :exit-code +node-exit-clean+)
    t))

(defun check-disk-space (directory &optional (additional-bytes 0))
  "Free-space gate at flush points (Core CheckDiskSpace, util/fs_helpers.cpp:
87-93: available >= 50 MiB + ADDITIONAL-BYTES). Reads df -Pk; any failure to
determine free space passes — the gate must never false-positive a healthy
node into shutdown."
  (handler-case
      (let* ((out (with-output-to-string (s)
                    (uiop:run-program (list "df" "-Pk" (namestring directory))
                                      :output s :error-output nil)))
             (lines (remove-if (lambda (l) (zerop (length l)))
                               (uiop:split-string out :separator '(#\Newline))))
             (fields (and (>= (length lines) 2)
                          (remove-if (lambda (f) (zerop (length f)))
                                     (uiop:split-string (second lines)
                                                        :separator '(#\Space #\Tab)))))
             (avail-kb (and fields
                            (>= (length fields) 4)
                            (parse-integer (fourth fields) :junk-allowed t))))
        (or (null avail-kb)
            (>= (* avail-kb 1024) (+ 52428800 additional-bytes))))
    (error () t)))

(defvar *last-block-disk-check-time* 0
  "Universal time of the last block-write disk-space sample.")

(defvar *last-block-disk-check-ok* t
  "The verdict that sample produced.")

(defconstant +block-disk-check-interval-seconds+ 30
  "How often the block-write path re-samples free disk space.")

(defun check-disk-space-for-blocks (directory)
  "T when DIRECTORY has room for more block data, sampled at most every
+BLOCK-DISK-CHECK-INTERVAL-SECONDS+.

Core calls CheckDiskSpace before EVERY block and undo write (FindBlockPos /
FindUndoPos, blockstorage.cpp:337), which it can afford because its check is a
statvfs call. Ours shells out to `df`, so a per-block check would fork a
process per block during IBD. Sampling keeps the property that matters — a node
does not keep writing blocks onto a disk that is nearly full — with a bounded
lag of one interval.

Removing the caveat means binding statvfs(3) through CFFI, which is worth doing
and is not done here."
  (let ((now (get-universal-time)))
    (when (>= (- now *last-block-disk-check-time*)
              +block-disk-check-interval-seconds+)
      (setf *last-block-disk-check-time* now
            *last-block-disk-check-ok* (check-disk-space directory)))
    *last-block-disk-check-ok*))

(defun gate-block-write-on-disk-space ()
  "Abort the node when the block directory has no room left, before a block
write rather than after (Core FindBlockPos -> CheckDiskSpace -> FatalError,
blockstorage.cpp:337). A no-op when there is no node or no data directory,
which is every test that connects blocks against a bare chainstate."
  (let ((dir (and *node* (node-data-directory *node*))))
    (when (and dir (not (check-disk-space-for-blocks dir)))
      (%abort-on-low-disk-space "Block write"))))

(defvar *flush-failure-abort-triggered* nil
  "Set once a flush failure has requested shutdown, so a failing flush called
again during teardown does not re-request it.")

(defun %abort-on-flush-failure (label condition)
  "Request shutdown after a flush failure (Core AbortNode from
FlushStateToDisk's catch, validation.cpp:2698). Exits non-clean: whatever made
the write fail — a full disk, a revoked mount, a corrupt database — will still
be there on respawn, so the supervisor should back off rather than spin."
  (unless *flush-failure-abort-triggered*
    (setf *flush-failure-abort-triggered* t)
    (request-node-shutdown (format nil "~A flush failed: ~A" label condition)
                           :exit-code +node-exit-error+)))

(defun %abort-on-low-disk-space (label)
  "Log + request shutdown once when free disk space is below the floor
(Core FlushStateToDisk's CheckDiskSpace failure -> FatalError \"Disk space
is too low!\", validation.cpp:2775/2808). Exits non-clean: respawning into a
full disk just reproduces the abort, so the supervisor backs off instead."
  (log-error "~A flush: Disk space is too low!" label)
  (unless *disk-space-abort-triggered*
    (setf *disk-space-abort-triggered* t)
    (request-node-shutdown "disk space is too low"
                           :exit-code +node-exit-error+)))

(defun maybe-dump-peer-addresses (node)
  "Dump the address book to peers.dat when the 15-minute cadence elapses
(Core scheduler DumpAddresses every DUMP_PEERS_INTERVAL, net.cpp:3560).
Called from the sync loop; also runs unconditionally at shutdown."
  (let ((now (get-universal-time)))
    (when (and (node-address-book node)
               (node-data-directory node)
               (>= (- now *last-peers-dump-time*) +peers-dump-interval-seconds+))
      (setf *last-peers-dump-time* now)
      (handler-case
          (progn
            (bl.net:save-address-book
             (node-address-book node)
             (bl.net:peers-dat-path (node-data-directory node)))
            (log-debug "Periodic peers.dat dump (~D entries)"
                       (bl.net:address-book-count
                        (node-address-book node))))
        (error (e)
          (log-warn "Periodic peers.dat dump failed: ~A" e)))
      t)))
