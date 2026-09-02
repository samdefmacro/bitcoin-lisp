(in-package #:bitcoin-lisp.rpc)

;;;; Node RPCs (Core rpc/node.cpp: setmocktime, mockscheduler, logging, echo,
;;;; getmemoryinfo, getindexinfo; rpc/server.cpp: uptime, stop, help,
;;;; getrpcinfo) and getzmqnotifications (Core zmq/zmqrpc.cpp).

;;; --- Node / chain info RPCs ---

(define-rpc "uptime" (node params)
  "Seconds the node has been running (Bitcoin Core uptime)."
  (declare (ignore node params))
  (if bl:*node-start-time*
      ;; Real clock on BOTH sides. Core's uptime is SteadyClock::now() minus a
      ;; steady startup stamp (common/system.cpp:134), so setmocktime does not
      ;; move it; reading the mockable clock here would make uptime jump — or
      ;; clamp to 0 — the moment a test set the clock backwards.
      (max 0 (- (bl.ser:get-real-unix-time)
                bl:*node-start-time*))
      0))

(define-rpc "stop" (node params)
  "Request a graceful node shutdown (Bitcoin Core stop, rpc/node.cpp: the RPC
only calls StartShutdown()). It must not run stop-node on this thread: the
teardown stops the RPC server serving this very request, and — the reason the
request/perform split exists — a stop driven from any non-main thread races
the supervisor's watchdog, which exits the process while the chainstate flush,
mempool.dat, peers.dat and wallet markers are still being written. So register
the request and let the main thread do the work; the short sleep only lets
this response flush before the RPC server goes away."
  (declare (ignore node params))
  (bt:make-thread (lambda ()
                    (sleep 0.3)
                    (ignore-errors
                     (bl:request-node-shutdown "RPC stop")))
                  :name "rpc-stop")
  "Bitcoin-lisp server stopping")

;;; --- Test-harness control methods (Core rpc/node.cpp) ---

(defconstant +max-mock-time+ 9223372036
  "The largest timestamp setmocktime accepts: Core's max_time is
Ticks<seconds>(nanoseconds::max()), i.e. (2^63-1) nanoseconds expressed in
whole seconds (rpc/node.cpp:64).")

(define-rpc "setmocktime" (node params)
  "Set the clock GET-UNIX-TIME reports (Bitcoin Core setmocktime,
rpc/node.cpp:38-80). Regtest only, and 0 restores the system clock.

This is what lets the functional test framework drive time forward instead of
sleeping; almost every non-clean test depends on it."
  (declare (ignore node))
  (unless (eq bl:*network* :regtest)
    ;; Core raises a plain std::runtime_error here, which JSONRPCError maps to
    ;; RPC_MISC_ERROR with this exact text (rpc/node.cpp:52-54).
    (error 'rpc-error :code +rpc-misc-error+
                      :message "setmocktime is for regression testing (-regtest mode) only"))
  (let ((timestamp (first params)))
    (unless (integerp timestamp)
      (error 'rpc-error :code +rpc-type-error+
                        :message "JSON value of type string is not of expected type number"))
    (unless (<= 0 timestamp +max-mock-time+)
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message (format nil "Mocktime must be in the range [0, ~D], not ~D."
                                         +max-mock-time+ timestamp)))
    ;; Core's SetMockTime(0) means "stop mocking" — GetTime falls back to the
    ;; system clock when g_mock_time is zero — so 0 is NIL here, not epoch.
    (setf bl.ser:*mock-time*
          (if (zerop timestamp) nil timestamp))
    :null))

(define-rpc "getmemoryinfo" (node params)
  "Report process memory use (Bitcoin Core getmemoryinfo). Reports the SBCL heap
under the \"locked\" object Core uses."
  (declare (ignore node params))
  (let ((used #+sbcl (sb-kernel:dynamic-usage) #-sbcl 0)
        (total #+sbcl (sb-ext:dynamic-space-size) #-sbcl 0))
    `(("locked" . (("used" . ,used)
                   ("total" . ,total)
                   ("free" . ,(max 0 (- total used)))
                   ("locked" . 0)
                   ("chunks_used" . 0)
                   ("chunks_free" . 0))))))

(define-rpc "logging" (node params)
  "Get or set the active debug-logging categories (Bitcoin Core logging). PARAMS:
([include] [exclude]) — arrays of category names to enable / disable; \"all\"
(or \"1\") toggles every category. Returns an object mapping every category to
whether it is currently enabled. Errors on an unknown category."
  (declare (ignore node))
  (let ((include (positional-array (first params)))
        (exclude (positional-array (second params))))
    (when (and include (not (listp include)))
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "include must be an array"))
    (when (and exclude (not (listp exclude)))
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "exclude must be an array"))
    (dolist (cat include)
      (unless (and (stringp cat) (bl.log:enable-log-category cat))
        (error 'rpc-error :code +rpc-invalid-parameter+
                          :message (format nil "unknown logging category ~A" cat))))
    (dolist (cat exclude)
      (unless (and (stringp cat) (bl.log:disable-log-category cat))
        (error 'rpc-error :code +rpc-invalid-parameter+
                          :message (format nil "unknown logging category ~A" cat))))
    (mapcar (lambda (c) (cons c (json-bool (bl:log-category-enabled-p c))))
            bl.log:+log-categories+)))

(define-rpc "mockscheduler" (node params)
  "Advance the scheduler by DELTA_TIME seconds (Core mockscheduler,
rpc/node.cpp:86-99). Regtest only.

Our scheduled work is driven off GET-UNIX-TIME rather than a separate scheduler
thread, so advancing the mock clock IS advancing the scheduler — which is what
the tests using this actually depend on (mempool_unbroadcast.py forwards past
the unbroadcast re-announce interval and then asserts the re-announce happened)."
  (declare (ignore node))
  (unless (eq bl:*network* :regtest)
    (error 'rpc-error :code +rpc-misc-error+
                      :message "mockscheduler is for regression testing (-regtest mode) only"))
  (let ((delta (first params)))
    (unless (integerp delta)
      (error 'rpc-error :code +rpc-type-error+
                        :message "Expected type number for delta_time"))
    ;; Core's bounds, verbatim (rpc/node.cpp:97-99).
    (when (or (<= delta 0) (> delta 3600))
      (error 'rpc-error :code +rpc-misc-error+
                        :message "delta_time must be between 1 and 3600 seconds (1 hr)"))
    ;; NB the base is GET-UNIX-TIME, not *MOCK-TIME*: Core forwards from "now"
    ;; whether or not the clock is already mocked, and a test that calls
    ;; mockscheduler without a prior setmocktime relies on that.
    (setf bl.ser:*mock-time*
          (+ (bl.ser:get-unix-time) delta))
    :null))

(define-rpc "echo" (node params)
  "Return the arguments unchanged (Core echo, rpc/node.cpp:279). It exists for
the test framework to check argument marshalling end to end, which is exactly
what rpc_misc.py uses it for."
  (declare (ignore node))
  (or params '()))

(define-rpc "getrpcinfo" (node params)
  "Report RPC server state (Bitcoin Core getrpcinfo): the commands currently
executing, with each one's running time in MICROSECONDS, and the log file path.

active_commands was always empty, which is not merely incomplete: it is how a
client learns that a long-running call is still running. Core's own
feature_shutdown.py waits for TWO concurrent commands before attempting a
shutdown, so a node reporting none hangs that test forever."
  (declare (ignore node params))
  `(("active_commands"
     . ,(json-array
         (mapcar (lambda (c) `(("method" . ,(car c)) ("duration" . ,(cdr c))))
                 (active-rpc-commands))))
    ("logpath" . ,(or (and bl:*log-file-path*
                           (namestring bl:*log-file-path*))
                      ""))))

(define-rpc "echojson" (node params)
  "Return the arguments unchanged (Core echojson, rpc/misc.cpp). For testing
only; it exists so a test can check the JSON round-trip of every argument type
without depending on what any real method does with them."
  (declare (ignore node))
  (coerce params 'vector))

(defun %dump-all-command-conversions ()
  "Core CRPCTable::dumpArgMap / RPCHelpMan::GetArgMap (rpc/util.cpp:833-863):
one [method, position, argument-name, is-string-type] row per argument.

IS-STRING-TYPE is Core's `type == STR || type == STR_HEX`. FALSE means a
JSON-RPC client must parse the argument before sending it; TRUE means it goes
through as a string. Core's own rpc_help.py compares this table against
src/rpc/client.cpp and fails the node if they disagree, which is the whole
reason the method exists — it is undocumented and for testing only."
  (let ((rows '()))
    (dolist (entry *rpc-arg-conversions*)
      (let ((method (first entry)))
        ;; A method we no longer register must not appear: the table is
        ;; generated from Core's list, and Core dumps what it SERVES.
        (when (gethash method *rpc-methods*)
          (dolist (arg (rest entry))
            (destructuring-bind (position name . string-p) arg
              (push (vector method position name (json-bool string-p)) rows))))))
    (coerce (nreverse rows) 'vector)))

(define-rpc "help" (node params)
  "List available RPC methods, or echo the name of a known one (Bitcoin Core
help). A full per-method help text is out of scope.

The undocumented \"dump_all_command_conversions\" argument returns the
argument-conversion table instead (Core rpc/server.cpp:135-138); it is what
rpc_help.py uses to check this node against Core's client.cpp."
  (declare (ignore node))
  (let ((method (first params)))
    (cond
      ((equal method "dump_all_command_conversions")
       (%dump-all-command-conversions))
      ((and method (stringp method))
       (if (gethash method *rpc-methods*)
           method
           (format nil "help: unknown command: ~A" method)))
      (t
       (let ((names '()))
         (maphash (lambda (k v) (declare (ignore v)) (push k names)) *rpc-methods*)
         (format nil "~{~A~^~%~}" (sort names #'string<)))))))

(define-rpc "getindexinfo" (node params)
  "Report the status of optional indexes (Bitcoin Core getindexinfo): txindex,
the basic block filter index, coinstatsindex and txospenderindex -- each
reported only when
enabled. An optional index-name argument filters to a single index (empty object
if it is not an enabled index). Every index is maintained inline as blocks
connect, so a present index normally tracks the tip; \"synced\" reflects whether
its best indexed block has reached the current tip."
  (let* ((name (and (consp params) (first params)))
         (cs (rpc-get-chain-state node))
         (tip (bl.store:current-height cs))
         (entries '()))
    ;; One row per enabled index, named as Core names them (the BaseIndex
    ;; name argument, e.g. "txospenderindex" index/txospenderindex.cpp:64),
    ;; which is the string the optional filter argument matches on. The
    ;; txindex's height is resolved against the chain (its marker is a
    ;; hash), so under assumeutxo it reports the validated tip it is really
    ;; at rather than claiming the snapshot tip.
    (dolist (index (bl:node-indexes node))
      (let ((key (bl.store:index-name index))
            (height (bl.store:index-height index cs)))
        (when (or (null name) (string= name key))
          (push `(,key . (("synced" . ,(json-bool (>= height tip)))
                          ("best_block_height" . ,height)))
                entries))))
    ;; No matching active index -> empty JSON object.
    (if entries (nreverse entries) (make-hash-table :test 'equal))))

(define-rpc "getzmqnotifications" (node params)
  "Active ZMQ notification publishers (Bitcoin Core getzmqnotifications):
an array of {type, address, hwm}. Empty when ZMQ is not configured, which is
also the case on a node whose host has no libzmq -- the library is loaded only
when a -zmqpub* option asks for it."
  (declare (ignore node params))
  (json-array
   (mapcar (lambda (entry)
             (destructuring-bind (type address hwm) entry
               `(("type" . ,type)
                 ("address" . ,address)
                 ("hwm" . ,hwm))))
           (bl:zmq-notifications-info))))

