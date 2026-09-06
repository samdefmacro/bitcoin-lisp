(in-package #:bitcoin-lisp.tests)

(def-suite :notify-tests
  :description "-blocknotify / -shutdownnotify: the node's operator hooks (Core init.cpp:2009-2018)"
  :in :bitcoin-lisp-tests)

(in-suite :notify-tests)

(defmacro %recording-notify-commands ((records) &body body)
  "Run BODY with RUN-NOTIFY-COMMAND replaced by a recorder, so a hook's decision
is observable without forking a shell. RECORDS is bound to a list of
(COMMAND . VALUE), oldest first. The replacement is a plain function
redefinition, which is enough here because the caller is in another file and
another package: nothing inlines it."
  (let ((saved (gensym "SAVED")))
    `(let ((,records '())
           (,saved (symbol-function 'bl.log:run-notify-command)))
       (unwind-protect
            (progn
              (setf (fdefinition 'bl.log:run-notify-command)
                    (lambda (command &key value substitutions wait check)
                      (declare (ignore substitutions wait check))
                      (setf ,records (append ,records (list (cons command value))))
                      t))
              ,@body)
         (setf (fdefinition 'bl.log:run-notify-command) ,saved)))))

(defmacro %counting-notify-commands ((counter) &body body)
  "%RECORDING-NOTIFY-COMMANDS for the tests that only count: COUNTER reads as
the number of commands run so far."
  (let ((records (gensym "RECORDS")))
    `(%recording-notify-commands (,records)
       (symbol-macrolet ((,counter (length ,records)))
         ,@body))))

(test blocknotify-is-silent-until-the-node-is-past-init
  "GA11 c537a699. Core connects -blocknotify to NotifyBlockTip and the first
line of the handler is `if (sync_state != SynchronizationState::POST_INIT)
return;' (init.cpp:2012), so the command is suppressed for every tip update
during initial block download and reindex.

Ours had only the assumeutxo background-chainstate guard, and
notify-updated-block-tip fires after every connected block. An operator who
configures -blocknotify -- the standard Core setup for explorers, mining and
monitoring -- and then syncs from scratch, reindexes or restores a snapshot
forked one detached /bin/sh per connected block, as fast as blocks connect."
  (let ((cs (bl.store:make-chain-state))
        (hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3)))
    (%counting-notify-commands (calls)
      (let ((bl::*block-notify-command* "true"))
        ;; In IBD: not one run, however many tips go by.
        (let ((bl.net:*cached-is-ibd* t))
          (dotimes (i 50) (bl::notify-block-tip cs hash i)))
        (is (zerop calls)
            "-blocknotify ran ~D time~:P during initial block download" calls)
        ;; Positive control: past init it DOES run, once per tip update. Without
        ;; this the assertion above would also pass with the hook unwired.
        (let ((bl.net:*cached-is-ibd* nil))
          (bl::notify-block-tip cs hash 51)
          (bl::notify-block-tip cs hash 52))
        (is (= 2 calls)
            "positive control: -blocknotify must run once per tip update past init, ran ~D"
            calls)
        ;; The assumeutxo background chainstate stays excluded, gate or no gate:
        ;; Core's UpdatedBlockTip is the ACTIVE chainstate's.
        (let ((bl.net:*cached-is-ibd* nil)
              (background (bl.store:make-chain-state)))
          (setf (bl.store:chain-state-target-blockhash background) hash)
          (bl::notify-block-tip background hash 53)
          (is (= 2 calls)
              "a background (targeted) chainstate's tip must not fire -blocknotify"))))))

(test blocknotify-gate-is-cores-synchronization-state
  "TIP-NOTIFICATION-POST-INIT-P is Core's GetSynchronizationState reduced to
the distinction the gate makes (validation.cpp:3307-3312): POST_INIT exactly
when the node has left initial block download."
  (let ((cs (bl.store:make-chain-state)))
    (is-false (let ((bl.net:*cached-is-ibd* t)) (bl::tip-notification-post-init-p cs)))
    (is-true (let ((bl.net:*cached-is-ibd* nil)) (bl::tip-notification-post-init-p cs)))))

(test blocknotify-unset-runs-nothing
  "No -blocknotify configured, no command -- past init included."
  (let ((cs (bl.store:make-chain-state))
        (hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7)))
    (%counting-notify-commands (calls)
      (let ((bl::*block-notify-command* nil)
            (bl.net:*cached-is-ibd* nil))
        (bl::notify-block-tip cs hash 9))
      (is (zerop calls)))))

;;; --- -alertnotify and the warnings registry (finding c053f780) --------------

(defmacro %with-clean-warnings (&body body)
  "Run BODY over a fresh warnings map and give the image its own back. The map
is process-global, and a warning left behind would show up in every later
suite's getblockchaininfo."
  `(unwind-protect (progn (bl.log:reset-warnings) ,@body)
     (bl.log:reset-warnings)))

(test alertnotify-fires-once-per-transition
  "Core fires -alertnotify from KernelNotifications::warningSet, and only when
Warnings::Set reports that the state CHANGED (kernel_notifications.cpp:79-85,
warnings.cpp:28-33). That return value is the whole mechanism: without it the
pager fires again on every block for as long as the condition lasts. Ours had
no warnings registry at all and -alertnotify was accepted and dropped
(GA11 c053f780)."
  (%with-clean-warnings
    (%recording-notify-commands (runs)
      (let ((bl.log:*alert-notify-command* "/usr/bin/pager %s")
            (message "Warning: found an invalid chain"))
        (is-true (bl.log:set-kernel-warning :large-work-invalid-chain message))
        (is (= 1 (length runs)))
        ;; Core sanitizes the message to SAFE_CHARS_DEFAULT and wraps it in
        ;; single quotes before the %s substitution, in that order -- the safe
        ;; set holds no quote, so the quoting cannot be escaped from.
        (is (equal (cons "/usr/bin/pager %s" (format nil "'~A'" message))
                   (first runs)))
        ;; The same warning again is not a transition, so no second page.
        (is-false (bl.log:set-kernel-warning :large-work-invalid-chain message))
        (is (= 1 (length runs)))
        ;; Once it clears, the next occurrence pages again.
        (is-true (bl.log:unset-warning :large-work-invalid-chain))
        (is-false (bl.log:unset-warning :large-work-invalid-chain))
        (is-true (bl.log:set-kernel-warning :large-work-invalid-chain message))
        (is (= 2 (length runs)))
        ;; A node:: warning reaches the RPC array and never the pager, as in
        ;; Core, where those are set on the map directly (warnings.h:23-27).
        (is-true (bl.log:set-warning :clock-out-of-sync "clock out of sync"))
        (is (= 2 (length runs)))
        (is (= 2 (length (bl.log:warnings-for-rpc))))))))

(test alertnotify-unset-runs-nothing
  "The positive control for the test above: with no -alertnotify the same
transition runs no command, so a page can only come from the option."
  (%with-clean-warnings
    (%recording-notify-commands (runs)
      (let ((bl.log:*alert-notify-command* nil))
        (is-true (bl.log:set-kernel-warning :large-work-invalid-chain "boom"))
        (is (= 0 (length runs)))
        (is (= 1 (length (bl.log:warnings-for-rpc)))))
      (let ((bl.log:*alert-notify-command* ""))
        (is-true (bl.log:set-kernel-warning :unknown-new-rules-activated "bits"))
        (is (= 0 (length runs)))))))

(test warnings-map-follows-cores-shape
  "The map itself: Core's GetMessages is sorted by warning id, its constructor
seeds the pre-release entry when the build is not a release
(warnings.cpp:20-27), and a node with nothing to report answers an empty ARRAY
rather than null."
  (%with-clean-warnings
    ;; A release build starts empty -- and this is the positive control for
    ;; every non-empty assertion elsewhere.
    (is (equalp #() (bl.log:warnings-for-rpc)))
    ;; Core's map order: the kernel warnings first, then the node ones.
    (bl.log:set-warning :clock-out-of-sync "clock")
    (bl.log:set-warning :unknown-new-rules-activated "bits")
    (is (equal '("bits" "clock") (bl.log:warnings-for-rpc)))
    (bl.log:reset-warnings)
    ;; The pre-release entry, which a packager turns on by declaring the build.
    (let ((bl.log:*client-version-is-release* nil))
      (bl.log:reset-warnings)
      (is (= 1 (length (bl.log:warnings-for-rpc))))
      (is-true (search "pre-release test build" (first (bl.log:warnings-for-rpc)))))))

(test alertnotify-is-a-real-option
  "-alertnotify left the accept-and-drop list (GA11 c053f780)."
  (let ((saved bl.log:*alert-notify-command*))
    (unwind-protect
         (progn
           (apply-config-globals '(("alertnotify" . "/usr/bin/pager %s")))
           (is (equal "/usr/bin/pager %s" bl.log:*alert-notify-command*)))
      (setf bl.log:*alert-notify-command* saved)))
  (is-true (bl:known-config-option-p "alertnotify"))
  (is-false (bl.cfg:core-only-option-p "alertnotify")))
