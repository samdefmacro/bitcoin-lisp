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

(defun tip-notification-post-init-p (chainstate)
  "T when a tip update on CHAINSTATE is Core's SynchronizationState::POST_INIT
-- that is, the node is no longer in initial block download.

Core computes this next to the notification, GetSynchronizationState(
fInitialDownload, m_blockfiles_indexed) (validation.cpp:3307-3312), and gives
it to every blockTip subscriber; the value only ever distinguishes POST_INIT
from the two init states, and the -blocknotify callback is written as
`if (sync_state != SynchronizationState::POST_INIT) return;'
(init.cpp:2012). Core's third value, INIT_REINDEX, has no separate meaning for
that gate and no reachable moment here either: -reindex rebuilds the block
index inside INIT-NODE, before any block can connect and therefore before any
tip update is announced (src/node/init.lisp).

The predicate is computed HERE rather than passed down from the announcement
because the IBD latch lives in the net layer (BL.NET:INITIAL-BLOCK-DOWNLOAD-P,
Core's m_cached_is_ibd) and validation must not name it. That is also where
Core puts the test: in the -blocknotify callback, not in the signal."
  (not (bl.net:initial-block-download-p chainstate)))

(bl.vi:define-validation-hook :updated-block-tip notify-block-tip (chainstate hash height)
  "Run -blocknotify for a new best block, if configured. Detached, so an
operator hook can never stall block connection (Core \"thread runs free\",
init.cpp:2017); the ACTIVE chain's tip only, like Core's UpdatedBlockTip; and
only once the node is past init.

The initial-block-download gate is Core's first line in this callback
(init.cpp:2012) and it is not a nicety. -blocknotify is the standard Core
setup for block explorers, mining and monitoring, and RUN-NOTIFY-COMMAND
forks a detached /bin/sh per call: without the gate, an operator who
configures it and then syncs from scratch, reindexes or restores from a
snapshot forks one process per connected block, as fast as blocks connect --
hundreds of thousands of them on a mainnet sync. Every one of those is also a
spurious \"new best block\" for whatever the hook drives.

The other subscribers of this event decide for themselves: -stopatheight must
keep working during IBD (an offline reindex is exactly when it is used), and
so must the periodic flush. That is why the gate is in this subscriber and not
a filter on the announcement."
  (declare (ignore height))
  (when (and *block-notify-command*
             (not (bl.store:chain-state-target-blockhash chainstate))
             (tip-notification-post-init-p chainstate))
    (run-notify-command *block-notify-command*
                        :value (bl.crypto:bytes-to-hex hash))))

(defun run-shutdown-notify ()
  "Run every -shutdownnotify command and WAIT for it (Core joins them,
init.cpp:263-265): a detached command racing process exit may not run at all."
  (dolist (command *shutdown-notify-commands*)
    (run-notify-command command :wait t)))
