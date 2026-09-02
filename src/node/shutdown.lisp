(in-package #:bitcoin-lisp)

;;;; Shutdown coordination (Core's StartShutdown / WaitForShutdown split)
;;;;
;;;; Every internal stop path — the `stop` RPC, -stopatheight, the low-disk
;;;; abort, a snapshot that fails background validation — runs on a NON-main
;;;; thread, while the supervisor's watchdog runs on the main thread and exits
;;;; the process shortly after it sees the node stop running. Calling stop-node
;;;; from those threads is therefore a race with the process exit: stop-node
;;;; clears node-running FIRST and does the chainstate flush, mempool.dat,
;;;; peers.dat, banlist and wallet best-block markers AFTER, and sb-ext:exit
;;;; unwinds other threads without waiting for them. At an idle tip the whole
;;;; sequence takes about as long as one watchdog tick (a coin flip); mid-block,
;;;; or with a large dirty coins cache, the kill is certain.
;;;;
;;;; Core has exactly this split: StartShutdown() only sets a token
;;;; (shutdown/shutdown.cpp), the main thread's WaitForShutdown() returns, and
;;;; Shutdown() then runs the entire teardown on the MAIN thread
;;;; (bitcoind.cpp:180-193). We mirror it: internal paths call
;;;; request-node-shutdown, run-node-watchdog (the main thread) runs stop-node
;;;; itself and only exits once *shutdown-complete* is set — stop-node's final
;;;; act.

(defvar *node-starting* nil
  "T while start-node is still building the node. The SIGTERM handler is
installed at the START of start-node (Core AppInitBasicSetup), so a stop can
arrive while there is no node to tear down and no watchdog yet — in that window
the handler only registers the request; see install-shutdown-handler.")

(defvar *shutdown-request* nil
  "NIL, or the pending shutdown request as (REASON . EXIT-CODE). Written
exactly once per run by request-node-shutdown, via CAS rather than a lock so
it is safe to call from a signal handler (a lock could deadlock against the
thread the signal interrupted). One cell, so a reader never sees a reason
without its exit code.")

;;;; The shutdown token pipe (Core util::SignalInterrupt, util/signalinterrupt.cpp)
;;;;
;;;; Core's whole SIGTERM handler is `(*g_shutdown)()`, and that call is an
;;;; atomic exchange on a flag plus, only if it won, one write() of a single
;;;; byte to a pipe. The comment above it states the rule this file now follows:
;;;; "This must be reentrant and safe for calling in a signal handler, so using
;;;; a condition variable is not safe."
;;;;
;;;; Ours used to do considerably more from inside the handler — format to
;;;; *error-output*, log-info (taking the log mutex), and on the REPL path
;;;; bt:make-thread and the entire stop-node teardown. That is why *LOG-LOCK*
;;;; had to be recursive: a signal delivered to a thread already inside an emit
;;;; would otherwise deadlock on its own lock. With the handler reduced to
;;;; Core's two operations, none of that is reachable and the lock is a plain
;;;; one again, as Core's StdMutex is.
;;;;
;;;; write(2) on a pipe is async-signal-safe (POSIX.1 async-signal-safe list);
;;;; a mutex acquisition is not. The byte's only job is to WAKE a servicer —
;;;; the flag is what carries the request.

(defvar *shutdown-servicer-thread* nil
  "The thread blocked in %RUN-SHUTDOWN-SERVICER, or NIL. Its existence is what
lets REQUEST-NODE-SHUTDOWN stop spawning a thread per request.")

(defvar *shutdown-pipe-read* nil "Read end of the shutdown token pipe, or NIL.")
(defvar *shutdown-pipe-write* nil "Write end of the shutdown token pipe, or NIL.")

(defvar *shutdown-token-buffer*
  (make-array 1 :element-type '(unsigned-byte 8) :initial-element (char-code #\x))
  "Preallocated one-byte buffer for the token write. Allocated ONCE, at load
time: a signal handler must not cons, and Core's TokenWrite writes a stack
byte for the same reason.")

(defvar *signal-shutdown-request* (cons "SIGTERM/SIGINT" +node-exit-clean+)
  "Preallocated (REASON . EXIT-CODE) cell the signal handler CASes into
*SHUTDOWN-REQUEST*. Building the cons inside the handler would allocate, and an
allocation can land in the middle of the GC the signal interrupted.")

(defun %open-shutdown-pipe ()
  "Create the token pipe if it does not exist yet. Idempotent."
  #+sbcl
  (unless *shutdown-pipe-write*
    (multiple-value-bind (r w) (sb-posix:pipe)
      (setf *shutdown-pipe-read* r
            *shutdown-pipe-write* w)))
  *shutdown-pipe-write*)

(defun %write-shutdown-token ()
  "Write the single wake-up byte. Async-signal-safe: no allocation, no lock,
no stream. Core SignalInterrupt::operator()'s TokenWrite."
  #+sbcl
  (let ((fd *shutdown-pipe-write*))
    (when fd
      ;; The return value is intentionally ignored, for the reason Core gives
      ;; in HandleSIGTERM: there is no better way to handle a failure here.
      (ignore-errors
       (sb-sys:with-pinned-objects (*shutdown-token-buffer*)
         (sb-posix:write fd (sb-sys:vector-sap *shutdown-token-buffer*) 1)))))
  nil)

(defun %await-shutdown-token ()
  "Block until a token arrives. Core SignalInterrupt::wait() over
TokenPipeEnd::TokenRead: a read interrupted by a signal (EINTR) is retried,
any other failure -- the pipe end closed under us, a bad descriptor -- ends
the wait instead of spinning on it forever (the first version wrapped the
read in IGNORE-ERRORS, so a closed pipe was a busy loop)."
  #+sbcl
  (let ((fd *shutdown-pipe-read*)
        (buf (make-array 1 :element-type '(unsigned-byte 8))))
    (when fd
      (sb-sys:with-pinned-objects (buf)
        (loop
          (handler-case
              (when (eql 1 (sb-posix:read fd (sb-sys:vector-sap buf) 1))
                (return))
            (sb-posix:syscall-error (e)
              (unless (eql (sb-posix:syscall-errno e) sb-posix:eintr)
                (bl:log-warn "shutdown token read failed: ~A" e)
                (return))))))))
  t)

(defvar *shutdown-complete* nil
  "Set by stop-node as its FINAL act, after the chainstate flush, mempool.dat,
peers.dat, banlist and wallet markers are on disk. The watchdog waits for this
before exiting the process; a concurrent stop-node caller waits on it too.")

(defvar *stop-node-in-progress* nil
  "CAS latch: T while one thread is inside stop-node's teardown. stop-node is
otherwise not concurrent-safe — two overlapping runs would both drive
%flush-chainstate through the same fixed chainstate.dat.tmp path and
double-close the same LevelDB handles.")

(defvar *shutdown-watchdog-running* nil
  "T while run-node-watchdog polls on the main thread. Read from other threads,
so it is SETF on the global (a LET binding would be invisible to them).")

(defun request-node-shutdown (reason &key (exit-code +node-exit-clean+))
  "Ask the node to shut down; the MAIN thread does the actual work (Core
StartShutdown). REASON is logged; EXIT-CODE is what the supervisor will see
(+node-exit-clean+ / -error+ / -watchdog+). Returns T if this call registered
the request, NIL if a shutdown was already pending (first caller wins).

Without a main-thread watchdog — a REPL or embedded use of start-node — nobody
would ever run stop-node, so this falls back to the historical behaviour of
running it on a throwaway thread. That is safe there precisely because nothing
is about to exit the process out from under it."
  (let* ((reason (or reason "shutdown requested"))
         (registered (null (sb-ext:cas (symbol-value '*shutdown-request*)
                                       nil (cons reason exit-code)))))
    (when registered
      (log-info "Shutdown requested: ~A (exit code ~D)" reason exit-code)
      ;; Wake the servicer the same way the signal handler does. This is not a
      ;; signal context, so the logging above is fine — but the SERVICING still
      ;; goes through one path, so a `stop` RPC and a SIGTERM tear the node down
      ;; identically instead of by two different mechanisms.
      (cond
        ((and *shutdown-servicer-thread*
              (bt:thread-alive-p *shutdown-servicer-thread*))
         (%write-shutdown-token))
        ((not *shutdown-watchdog-running*)
         ;; No servicer (a test, or an embedded caller that never installed the
         ;; handler) and no watchdog: nobody else would ever run stop-node.
         (bt:make-thread (lambda () (ignore-errors (stop-node)))
                         :name "node-shutdown"))))
    registered))

(defun node-shutdown-requested-p ()
  "The reason a shutdown was requested, or NIL (Core ShutdownRequested)."
  (car *shutdown-request*))

(defun %node-interrupt-requested-p ()
  "The node-wide stop predicate installed into bl:*interrupt-check*
(config.lisp), which states the contract. Two flags mean stop and this is the
only file that sees both: *shutdown-request* is set FIRST (the SIGTERM handler
just registers it), *ibd-stop-requested* later by stop-node."
  (or (bl.net:ibd-stop-requested-p)
      (node-shutdown-requested-p)))

(setf *interrupt-check* '%node-interrupt-requested-p)

(defun wait-for-shutdown-complete (&key (timeout 900))
  "Block until stop-node's *shutdown-complete* latch is set, or TIMEOUT
seconds pass. Returns T iff the shutdown completed. The default outlasts
stop-node's own 600s sync-thread join."
  (let ((deadline (+ (get-internal-real-time)
                     (* timeout internal-time-units-per-second))))
    (loop until *shutdown-complete*
          while (< (get-internal-real-time) deadline)
          do (sleep 0.05))
    (and *shutdown-complete* t)))

(defun %pending-shutdown-exit-code ()
  "The exit code the supervisor should see, or NIL while the node should keep
running. A node that stopped running without a request was not asked to stop
(fatal snapshot, dead sync thread) — that is the respawn case."
  (cond ((cdr *shutdown-request*))
        ((or (null *node*) (not (node-running *node*))) +node-exit-watchdog+)
        (t nil)))

(defun run-node-watchdog (&key (poll-seconds 1) (exit t))
  "Main-thread shutdown watchdog, the last form the supervisor launcher
evaluates (scripts/run-node.sh). Blocks until a shutdown is requested or the
node stops running, runs stop-node ON THIS THREAD — so the whole
flush/mempool.dat/peers.dat/banlist/wallet sequence completes before anything
exits — and then exits with a code the supervisor discriminates on:

  0  deliberate, completed stop (`stop` RPC, SIGTERM, -stopatheight): stay down
  1  deterministic failure (config, disk): back off, do not spin
  7  the node died unasked, or crashed: respawn

With EXIT NIL it returns the code instead of exiting (tests)."
  ;; SETF, not LET: the internal stop paths run on other threads and read the
  ;; GLOBAL value to decide whether anyone will run stop-node for them.
  (setf *shutdown-watchdog-running* t)
  (unwind-protect
       (loop
         (let ((code (%pending-shutdown-exit-code)))
           (when code
             (log-info "Shutdown watchdog: ~A — stopping node (exit code ~D)"
                       (or (node-shutdown-requested-p) "node is no longer running")
                       code)
             (ignore-errors (stop-node))
             (unless *shutdown-complete*
               (log-warn "Shutdown did not complete cleanly; exiting anyway"))
             ;; Release the servicer before exiting. It is a real thread blocked
             ;; in read(2), and SB-EXT:EXIT joins threads — a servicer that
             ;; never woke would hold the process for the full 5s timeout on
             ;; every shutdown. It always has a token when a request came
             ;; through request-node-shutdown or the signal handler, but NOT on
             ;; the exit-7 path (the node stopped running unasked, so nobody
             ;; ever asked), which is exactly the path that must not hang.
             (%write-shutdown-token)
             (if exit
                 (sb-ext:exit :code code :timeout 5)
                 (return code))))
         (sleep poll-seconds))
    (setf *shutdown-watchdog-running* nil)))

(defun %handle-stop-signal ()
  "What SIGTERM/SIGINT does, and ALL it does: set the flag, wake the servicer.
Core HandleSIGTERM (init.cpp:425-431) is one call with the same two effects,
and its comment says the return value is deliberately ignored because a signal
handler has no better way to report a failure.

Nothing here allocates, takes a lock, touches a stream or starts a thread. It
used to do all four — see the commentary on the token pipe above for what that
cost. Whoever services the request does the work: the main-thread watchdog when
one is running (Core's WaitForShutdown), else the servicer thread."
  (unless (sb-ext:cas (symbol-value '*shutdown-request*)
                      nil *signal-shutdown-request*)
    ;; First writer wins; only the winner writes the token, exactly as Core
    ;; guards TokenWrite with m_flag.exchange(true).
    (%write-shutdown-token))
  t)

(defun %run-shutdown-servicer ()
  "Block on the token pipe and service whatever shutdown request wakes us.
Core's WaitForShutdown, moved off the signal path.

When a main-thread watchdog is running it owns the teardown, so this only has
to not interfere: the watchdog's poll sees the same flag. Otherwise — a REPL or
embedded start-node — nobody else would ever run stop-node, so this thread does
it, which is where the old signal handler ran it from."
  (%await-shutdown-token)
  (let ((reason (node-shutdown-requested-p)))
    (when reason
      ;; Logging is safe HERE: an ordinary thread, not a signal context.
      (log-info "Shutdown requested: ~A" reason))
    (unless *shutdown-watchdog-running*
      (ignore-errors (stop-node))
      ;; Per-block script-check worker threads (bt:make-thread :name
      ;; "script-check-N" in validate-block.lisp) are non-daemon and can outlive
      ;; stop-node if validation was in progress when the sync thread was
      ;; destroyed. Without a timeout, sb-ext:exit blocks forever waiting for them
      ;; (incident 2026-05-11: node logged "Node stopped" but SBCL hung 6+
      ;; minutes, eventually needed SIGKILL). Give 5 seconds, then force-exit.
      ;; Core's CCheckQueue (checkqueue.h:206-225) has an explicit stop flag +
      ;; condvar to join workers; ours are ephemeral per-block, not a pool.
      #+sbcl (sb-ext:exit :code (or (cdr *shutdown-request*) +node-exit-clean+)
                          :timeout 5))))

(defun %ensure-shutdown-servicer ()
  "Start the servicer once. Idempotent."
  (%open-shutdown-pipe)
  (unless (and *shutdown-servicer-thread*
               (bt:thread-alive-p *shutdown-servicer-thread*))
    (setf *shutdown-servicer-thread*
          (bt:make-thread #'%run-shutdown-servicer :name "shutdown-servicer")))
  *shutdown-servicer-thread*)

(defun install-shutdown-handler ()
  "Trap SIGTERM and SIGINT so kill <pid> / Ctrl-C calls stop-node and persists
   chain state and UTXO set before exit. Without this, SIGKILL is the only way
   to stop a long-running node and IBD must restart from genesis on next boot.

   Also installs a fail-fast debugger hook: any unhandled error (including
   heap-exhausted) logs a stack and exits non-zero rather than dropping into
   LDB on a tty no one is reading."
  #+sbcl
  (progn
    ;; The servicer (and its pipe) must exist BEFORE the handler can fire:
    ;; a token written to a pipe nobody opened is a lost wake-up.
    (%ensure-shutdown-servicer)
    (let ((handler (lambda (&rest _)
                     (declare (ignore _))
                     ;; No banner line here any more. `format` to a shared
                     ;; stream from a signal handler is exactly the class of
                     ;; call Core's handler exists to avoid, and the servicer
                     ;; logs the same fact one line later from a normal thread.
                     (%handle-stop-signal))))
      (sb-sys:enable-interrupt sb-unix:sigterm handler)
      (sb-sys:enable-interrupt sb-unix:sigint handler)))
  ;; SIGUSR1 toggles sb-sprof profiling. First USR1: start sampling. Second
  ;; USR1: stop, write graph + flat report to /data/bitcoin-lisp/logs/profile.txt.
  ;; Use to identify the hot path during live validation: kill -USR1 <pid> to
  ;; arm, wait through a heavy block, kill -USR1 <pid> again, then read report.
  #+sbcl
  (let ((profiling nil))
    (sb-sys:enable-interrupt
     sb-unix:sigusr1
     (lambda (&rest _)
       (declare (ignore _))
       (cond
         ((not profiling)
          (sb-sprof:reset)
          (sb-sprof:start-profiling :max-samples 200000
                                    :sample-interval 0.001
                                    :mode :cpu
                                    :threads :all)
          (setf profiling t)
          (log-info "[sprof] profiling started"))
         (t
          (sb-sprof:stop-profiling)
          (with-open-file (s "/data/bitcoin-lisp/logs/profile.txt"
                             :direction :output
                             :if-exists :supersede
                             :if-does-not-exist :create)
            (let ((*standard-output* s))
              (format s "=== sb-sprof flat report ===~%")
              (sb-sprof:report :type :flat :max 60)
              (format s "~%~%=== sb-sprof graph report ===~%")
              (sb-sprof:report :type :graph :max 50)))
          (setf profiling nil)
          (log-info "[sprof] profile written to /data/bitcoin-lisp/logs/profile.txt")))))
    (log-info "SIGUSR1 toggles sb-sprof profiling"))
  #+sbcl
  (setf sb-ext:*invoke-debugger-hook*
        (lambda (condition hook)
          (declare (ignore hook))
          (ignore-errors
            (log-error "Fatal: ~A" condition)
            (let ((bt (with-output-to-string (s)
                        (sb-debug:print-backtrace :stream s :count 30))))
              (log-error "Backtrace:~%~A" bt)))
          (sb-ext:exit :code 1))))

(defun %shutdown-flush-chainstates (node)
  "Shutdown flush: every chainstate through the same 3-phase in-transition
commit as the periodic flush, then close its coins DB (Core Shutdown
iterates m_chainstates calling ForceFlushStateToDisk — the marker-protected
FlushStateToDisk/BatchWrite path — then ResetCoinsViews, init.cpp:379-387).
The previous bare save-state + coins-flush pair re-opened the exact crash
window the marker exists to close: killed between the two steps,
chainstate.dat (clean, no marker) was ahead of the coins DB, and startup
loaded the inconsistency silently. Per-chainstate: with an assumeutxo
snapshot active there are two, each owning its own storage-suffix-named
state file and LevelDB. The shared header index is saved inside each flush's
Phase 1."
  (dolist (cs (node-chainstates node))
    (log-info "Flushing chain state~@[ (~A)~]..."
              (let ((suffix (bl.store:chain-state-storage-suffix cs)))
                (and (plusp (length suffix)) suffix)))
    (%flush-chainstate cs :label "Shutdown" :force-full-header-index t)
    (bl.store:close-chainstate-coins-view cs)))

(defun stop-node ()
  "Stop the running Bitcoin node: the full teardown, ending with the
*shutdown-complete* latch. Returns T when this call performed the teardown.

Concurrency: the FIRST caller owns the shutdown. A second, overlapping call
does not run the teardown again — two runs would drive %flush-chainstate
through the same fixed chainstate.dat.tmp path (storage/utxo.lisp) and
double-close the same LevelDB handles — it waits for the owner to finish and
returns NIL. Prefer request-node-shutdown from anything that is not the main
thread; see the shutdown-coordination section above."
  (unless *node*
    (return-from stop-node nil))
  ;; CAS rather than a lock: reachable from the SIGTERM handler, which runs in
  ;; whichever thread the signal interrupted.
  (unless (null (sb-ext:cas (symbol-value '*stop-node-in-progress*) nil t))
    (log-info "Shutdown already in progress on another thread; waiting for it")
    (wait-for-shutdown-complete)
    (return-from stop-node nil))
  (unwind-protect
       (%stop-node)
    ;; The latch is stop-node's FINAL act: the watchdog (and any concurrent
    ;; caller) waits on it, so it must be set strictly after the flush,
    ;; mempool.dat, peers.dat, banlist and wallet writes below — never before.
    (setf *stop-node-in-progress* nil
          *shutdown-complete* t)))

(defun %stop-node ()
  "stop-node's teardown proper; run by exactly one thread (see stop-node)."
  (log-info "Stopping node...")
  ;; Whatever start-node got to, it is not building any more. Clearing here (not
  ;; only on start-node's success path) keeps a failed start from leaving the
  ;; latch set, which would make a later REPL Ctrl-C register a request nobody
  ;; services.
  (setf *node-starting* nil)

  ;; Persist reconnection anchors while peers are still connected (before the
  ;; teardown below disconnects them).
  (save-anchors *node*)

  ;; -shutdownnotify runs FIRST and is WAITED for (Core ShutdownNotify,
  ;; init.cpp:255-266): a hook that fires after the process is gone, or races
  ;; it, is a hook that may not run at all.
  (run-shutdown-notify)

  ;; Stop RPC server first. Warmup is the SERVER's state, cleared by
  ;; stop-rpc-server — re-arming it here left it armed for anything else in the
  ;; image, which in the test suite meant every later request answered -28.
  (bl.rpc:stop-rpc-server)

  ;; Signal the node to stop. request-ibd-stop reaches the IBD inner
  ;; loops, which can otherwise run for hours after node-running flips
  ;; (the outer sync loop only checks between run-ibd passes).
  (setf (node-running *node*) nil)
  (bl.net:request-ibd-stop)

  ;; Stop the torcontrol client: closing the control connection is what tears
  ;; the ephemeral onion service down inside Tor (no DEL_ONION, like Core).
  (when (node-tor-controller *node*)
    (bl.net:stop-tor-control (node-tor-controller *node*))
    (setf (node-tor-controller *node*) nil))

  ;; Stop the inbound listeners: close the sockets (unblocks accept) and let
  ;; the accept threads observe node-running=nil and exit (accept timeout 1s).
  (when (node-listener-socket *node*)
    (bl.net:close-listener (node-listener-socket *node*))
    (setf (node-listener-socket *node*) nil))
  (when (node-onion-listener-socket *node*)
    (bl.net:close-listener (node-onion-listener-socket *node*))
    (setf (node-onion-listener-socket *node*) nil))
  ;; One shared deadline bounds the TOTAL wait for both accept threads.
  (let ((deadline (+ (get-internal-real-time) (* 5 internal-time-units-per-second))))
    (bl.net:join-thread-or-destroy
     (node-listener-thread *node*) :deadline deadline)
    (bl.net:join-thread-or-destroy
     (node-onion-listener-thread *node*) :deadline deadline))
  (setf (node-listener-thread *node*) nil
        (node-onion-listener-thread *node*) nil)
  ;; Disconnect any inbound peers not yet merged into the peer list. The listener
  ;; thread is already joined above, but take the lock for consistency.
  (let ((pending (bt:with-recursive-lock-held ((node-lock *node*))
                   (prog1 (node-pending-inbound-peers *node*)
                     (setf (node-pending-inbound-peers *node*) nil)))))
    (dolist (peer pending)
      (handler-case (bl.net:disconnect-peer peer) (error () nil))))

  ;; Wait for sync thread to finish (with timeout)
  (when (and (node-sync-thread *node*)
             (bt:thread-alive-p (node-sync-thread *node*)))
    (log-info "Waiting for sync thread to stop...")
    (let ((deadline (+ (get-internal-real-time)
                       ;; 10 minutes — long enough that a single heavy block's
                       ;; validation finishes and connect-block updates UTXO set
                       ;; + chain tip atomically, so destroy-thread fallback
                       ;; (which can corrupt mid-update state) is virtually
                       ;; never needed. A reorg no longer holds the thread to its
                       ;; end either — perform-reorg truncates on a block boundary
                       ;; (plan phase 3b). Deliberately NOT shortened: a tighter
                       ;; deadline would only make the destroy path more likely.
                       (* 600 internal-time-units-per-second))))
      (loop while (and (bt:thread-alive-p (node-sync-thread *node*))
                       (< (get-internal-real-time) deadline))
            do (sleep 0.1))
      (when (bt:thread-alive-p (node-sync-thread *node*))
        (log-warn "Sync thread did not stop gracefully, destroying...")
        (bt:destroy-thread (node-sync-thread *node*)))))
  (setf (node-sync-thread *node*) nil)

  ;; Disconnect all peers
  (log-info "Disconnecting peers...")
  (dolist (peer (node-peers *node*))
    (handler-case
        (bl.net:disconnect-peer peer)
      (error (c)
        (log-warn "Error disconnecting peer: ~A" c))))
  (bt:with-recursive-lock-held ((node-lock *node*))
    (setf (node-peers *node*) nil))

  ;; Flush every chainstate through the crash-safe 3-phase commit and close
  ;; its coins view (see %shutdown-flush-chainstates).
  (%shutdown-flush-chainstates *node*)

  ;; Save fee statistics
  (when (node-fee-estimator *node*)
    (log-info "Saving fee statistics...")
    (bl.mp:save-fee-stats (node-fee-estimator *node*)))

  ;; Save mempool (Core DumpMempool)
  (let ((path (bl.mp:mempool-dat-path (node-data-directory *node*))))
    (when (and path (node-mempool *node*))
      (log-info "Saving mempool (~D entries)..."
                (bl.mp:save-mempool-file (node-mempool *node*) path))))

  ;; Save peer address book
  (when (node-address-book *node*)
    (log-info "Saving peer address book...")
    (bl.net:save-address-book
     (node-address-book *node*)
     (bl.net:peers-dat-path (node-data-directory *node*))))

  ;; Final banlist dump (Core ~BanMan calls DumpBanlist, banman.cpp:26),
  ;; then detach the path so post-shutdown mutations stop writing.
  (bl.net:save-banlist)
  (setf bl.net:*banlist-path* nil)

  ;; Unload wallets (writes each wallet's best-block marker, closes its DB)
  (when (node-wallet-manager *node*)
    (log-info "Unloading wallets...")
    (bl.wallet:close-wallet-manager (node-wallet-manager *node*))
    (setf (node-wallet-manager *node*) nil))

  ;; Close transaction index
  (when (node-tx-index *node*)
    (log-info "Closing transaction index...")
    (bl.store:close-tx-index (node-tx-index *node*)))

  ;; Drop the prune locks before the DBs they read close. Each lock is a thunk
  ;; holding the index object, so leaving them registered keeps a stopped
  ;; node's indexes reachable AND leaves the thunks callable against closed
  ;; LevelDB handles — a live hazard in a test image that starts several nodes,
  ;; since the next PRUNE-LOCK-CEILING would consult the previous node's index.
  (bl.store:clear-prune-locks)

  ;; Close block filter index
  (when (node-blockfilterindex *node*)
    (log-info "Closing block filter index...")
    (bl.store:close-blockfilterindex (node-blockfilterindex *node*)))

  ;; Close coinstats index
  (when (node-coinstatsindex *node*)
    (log-info "Closing coinstats index...")
    (bl.store:close-coinstatsindex (node-coinstatsindex *node*)))

  ;; Close the spender index. Its LevelDB handle is no different from the
  ;; others' — leaving it open on shutdown leaks the handle and leaves the
  ;; database without a clean close.
  (when (node-txospenderindex *node*)
    (log-info "Closing spender index...")
    (bl.store:close-txospender-index (node-txospenderindex *node*)))

  ;; Cleanup secp256k1
  (bl.crypto:cleanup-secp256k1)

  ;; Stop the script-check workers (Core's CCheckQueue is stopped with the
  ;; validation interface). They hold no resources but would keep the process
  ;; alive, and a pool left running across a restart-in-one-image would be
  ;; sized for the previous -par.
  (ignore-errors (bl.val:stop-script-check-pool))

  ;; Close the ZMQ publishers before the directory lock: a subscriber should
  ;; see the node go away, not hold a socket to a process that has released
  ;; everything else.
  (zmq-stop-publishers)

  ;; Release the data-directory lock last: everything above may still touch
  ;; the directory, and a successor node must not open it until they are done.
  (unlock-data-directory)
  (remove-pid-file)

  (log-info "Node stopped")

  (setf *node* nil)
  t)
