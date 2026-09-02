(in-package #:bitcoin-lisp)

;;;; -blocknotify / -startupnotify / -shutdownnotify (Core init.cpp:255-266,
;;;; 2009-2019)
;;;;
;;;; An operator hook: run a shell command when something happens. The runner
;;;; itself (RUN-NOTIFY-COMMAND) lives in src/logging.lisp, early enough that the
;;;; wallet can reach it for -walletnotify; what lives here is the set of hooks
;;;; the NODE fires.

(defvar *block-notify-command* nil
  "Shell command to run when the best block changes; %s is replaced by the
block hash (Core -blocknotify, init.cpp:498).")

(defvar *shutdown-notify-commands* '()
  "Shell commands to run at shutdown, in order (Core -shutdownnotify). Core
JOINS these — shutdown waits for them — because a detached command racing
process exit is a command that may not run at all (init.cpp:257-265).")

(bl.vi:define-validation-hook :updated-block-tip notify-block-tip (chainstate hash height)
  "Run -blocknotify for a new best block, if configured. Detached, so an
operator hook can never stall block connection (Core \"thread runs free\",
init.cpp:2017); the ACTIVE chain's tip only, like Core's UpdatedBlockTip."
  (declare (ignore height))
  (when (and *block-notify-command*
             (not (bl.store:chain-state-target-blockhash chainstate)))
    (run-notify-command *block-notify-command*
                        :value (bl.crypto:bytes-to-hex hash))))

(defun run-shutdown-notify ()
  "Run every -shutdownnotify command and WAIT for it (Core joins them,
init.cpp:263-265): a detached command racing process exit may not run at all."
  (dolist (command *shutdown-notify-commands*)
    (run-notify-command command :wait t)))
