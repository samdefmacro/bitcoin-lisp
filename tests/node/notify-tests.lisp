(in-package #:bitcoin-lisp.tests)

(def-suite :notify-tests
  :description "-blocknotify / -shutdownnotify: the node's operator hooks (Core init.cpp:2009-2018)"
  :in :bitcoin-lisp-tests)

(in-suite :notify-tests)

(defmacro %counting-notify-commands ((counter) &body body)
  "Run BODY with RUN-NOTIFY-COMMAND replaced by a counter bound to COUNTER, so
a hook's decision is observable without forking a shell. The replacement is a
plain function redefinition, which is enough here because the caller is in
another file and another package: nothing inlines it."
  (let ((saved (gensym "SAVED")))
    `(let ((,counter 0)
           (,saved (symbol-function 'bl.log:run-notify-command)))
       (unwind-protect
            (progn
              (setf (fdefinition 'bl.log:run-notify-command)
                    (lambda (command &key value substitutions wait)
                      (declare (ignore command value substitutions wait))
                      (incf ,counter)
                      t))
              ,@body)
         (setf (fdefinition 'bl.log:run-notify-command) ,saved)))))

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
