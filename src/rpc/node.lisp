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

(defconstant +heap-chunk-bytes+ #+sbcl sb-vm:gencgc-page-bytes #-sbcl 4096
  "The allocation granule this node's heap is carved into -- SBCL\'s GC page.
It stands in for the chunk of Core\'s locked pool: see GETMEMORYINFO.")

(define-rpc "getmemoryinfo" (node params)
  "Report process memory use (Bitcoin Core getmemoryinfo). Reports the SBCL heap
under the \"locked\" object Core uses.

DIVERGENCE, stated rather than faked: Core\'s object describes its LockedPool,
an mlock()ed arena it keeps keys in (support/lockedpool.h:57-64), and this node
has no such arena -- the same secrets live in the ordinary heap. So the numbers
describe the heap this node does have, in the units the field names mean:
`used\'/`free\'/`total\' are the dynamic space, and `chunks_used\'/
`chunks_free\' are that space counted in allocation granules (SBCL GC pages),
which is what a chunk IS for Core\'s arena. `locked\' stays 0 because nothing
here is mlock()ed, and claiming otherwise would be a security claim we cannot
make.

Reporting 0 chunks was worse than either: rpc_misc.py:61 asserts
`chunks_used > 0\', and a caller watching for allocator pressure saw a
constant.

MODE is Core\'s argument (rpc/node.cpp:733-760): \"stats\" (the default) is the
object below, \"mallocinfo\" is the glibc malloc_info XML -- which this runtime
has no equivalent of, so it takes Core\'s own #else arm, `mallocinfo mode not
available\' -- and any other value is `unknown mode <mode>\'. Ignoring the
argument answered the stats object to every one of them, including the typo
rpc_misc.py:73 sends."
  (declare (ignore node))
  (let ((mode (or (first params) "stats")))
    (unless (stringp mode)
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "JSON value of type null is not of expected type string"))
    (cond
      ((string= mode "stats"))
      ((string= mode "mallocinfo")
       (error 'rpc-error :code +rpc-invalid-parameter+
                         :message "mallocinfo mode not available"))
      (t
       (error 'rpc-error :code +rpc-invalid-parameter+
                         :message (format nil "unknown mode ~A" mode)))))
  (let* ((used #+sbcl (sb-kernel:dynamic-usage) #-sbcl 0)
         (total #+sbcl (sb-ext:dynamic-space-size) #-sbcl 0)
         (free (max 0 (- total used))))
    `(("locked" . (("used" . ,used)
                   ("total" . ,total)
                   ("free" . ,free)
                   ("locked" . 0)
                   ("chunks_used" . ,(ceiling used +heap-chunk-bytes+))
                   ("chunks_free" . ,(floor free +heap-chunk-bytes+)))))))

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
    ;; ALPHABETICAL, as Core answers: LogCategoriesList walks
    ;; LOG_CATEGORIES_BY_STR, a std::map keyed by the category NAME
    ;; (logging.cpp:172, :278-286), so its iteration order is sorted.
    ;; rpc_misc.py:87-88 asserts `list(node.logging()) ==
    ;; sorted(node.logging())'. Ours came out in declaration order, so a
    ;; client rendering the object as given showed an arbitrary one.
    (mapcar (lambda (c) (cons c (json-bool (bl:log-category-enabled-p c))))
            (sort (copy-list bl.log:+log-categories+) #'string<))))

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
    ;; Core's MockForward moves every scheduled task's deadline back by DELTA
    ;; and the scheduler THREAD then runs whatever has come due
    ;; (scheduler.cpp; rpc/node.cpp:86-99). Our periodic work has no thread of
    ;; its own -- it is cadence-gated inside the sync thread's idle tick -- so
    ;; running what is now due here is the same event, on the thread that has
    ;; just moved the clock. Without it the work happens only when the sync
    ;; thread next ticks, which is not within the one second
    ;; feature_fee_estimation.py:345/:371 waits after the call, and on a node
    ;; that has just restarted the first tick can be several seconds out.
    ;; The fee-estimate flush alone: it is the one scheduled task a test drives
    ;; through this RPC, and reaching further up into the node layer from here
    ;; would be a new upward reference the layering ratchet refuses.
    (let* ((node bl:*node*)
           (estimator (and node (bl:node-fee-estimator node))))
      (when estimator
        (ignore-errors (bl.mp:maybe-flush-fee-estimates estimator))))
    :null))

(defparameter *client-bug-report-url*
  "https://github.com/samdefmacro/bitcoin-lisp/issues"
  "Where a caller is asked to report an internal bug (Core CLIENT_BUGREPORT,
the last line StrFormatInternalBug prints).")

(defun str-format-internal-bug (assertion where)
  "Core StrFormatInternalBug (util/check.cpp:18-25): the report text a failed
CHECK_NONFATAL carries out of an RPC handler.

    Internal bug detected: <assertion>
    <file>:<line> (<function>)
    <client name> <version>
    Please report this issue here: <bug report URL>

WHERE stands in for Core's std::source_location, which SBCL has no equivalent
of, so the caller names its own file and function. The FIRST line is the
contract: Core's rpc_misc.py:45 asserts `Internal bug detected: ' followed by
the condition's own SOURCE TEXT is a substring of the error message, so
ASSERTION is quoted exactly as Core's `#condition' stringification renders it."
  (format nil "Internal bug detected: ~A~%~A~%bitcoin-lisp ~A~%Please report this issue here: ~A~%"
          assertion where (bl.ser:client-version-string) *client-bug-report-url*))

(defun %echo-arguments (params)
  "Core's echo/echojson body (rpc/node.cpp:299-306): the arguments, unchanged
-- except that arg9 = \"trigger_internal_bug\" trips a CHECK_NONFATAL (:301-303)
whose NonFatalCheckError the RPC server turns into an RPC_MISC_ERROR (-1)
carrying the report text (rpc/server.cpp:514-516).

That branch is not decoration: it is the only way a test can exercise the
internal-bug path end to end, and rpc_misc.py:32-45 requires the call either to
kill the node or to answer with that error. A node that echoed the string back
answered neither, and the test's `assert False' fired on the line after the
call. Both names share this body because Core builds them from one
RPCHelpMan (`static RPCHelpMan echo(const std::string& name)', :277).

The answer is Core's `return request.params;' -- a UniValue VARR, so a call
with NO arguments answers [] and not null. A bare Lisp list gets that right
for every case but the empty one, where NIL encodes as null:
rpc_named_arguments.py:28 is `assert_equal(node.echo(), [])'."
  (let ((arg9 (nth 9 params)))
    (when (and (stringp arg9) (string= arg9 "trigger_internal_bug"))
      (error 'rpc-error
             :code +rpc-misc-error+
             :message (str-format-internal-bug
                       "request.params[9].get_str() != \"trigger_internal_bug\""
                       "src/rpc/node.lisp (%ECHO-ARGUMENTS)"))))
  (coerce params 'vector))

(define-rpc "echo" (node params)
  "Return the arguments unchanged (Core echo, rpc/node.cpp:279). It exists for
the test framework to check argument marshalling end to end, which is exactly
what rpc_misc.py uses it for -- including arg9 = \"trigger_internal_bug\",
which Core answers with its internal-bug report (see %ECHO-ARGUMENTS)."
  (declare (ignore node))
  (%echo-arguments params))

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
  "Return the arguments unchanged (Core echojson, rpc/node.cpp:311). For testing
only; it exists so a test can check the JSON round-trip of every argument type
without depending on what any real method does with them. Core builds echo and
echojson from ONE RPCHelpMan (rpc/node.cpp:277-311), so the arg9 internal-bug
trigger is this method's too."
  (declare (ignore node))
  (%echo-arguments params))

(defun %logging-categories-help ()
  "The sentence Core's `help logging' carries: `valid logging categories are:
<names>', comma-separated and ALPHABETICAL (rpc/node.cpp builds it from
LogCategoriesString, logging.cpp:288-292 over the sorted LOG_CATEGORIES_BY_STR).
rpc_misc.py:90-93 builds the same string from the logging RPC's own keys and
asserts it appears in the help."
  (format nil "~%valid logging categories are: ~{~A~^, ~}"
          (sort (copy-list bl.log:+log-categories+) #'string<)))

(register-rpc-help-detail "logging" #'%logging-categories-help)

(define-rpc "echoipc" (node (arg))
  "Echo back ARG (Core echoipc, rpc/node.cpp:313-345). Hidden, and for
testing only.

Core spawns a bitcoin-node process and round-trips the string through it in a
multiprocess build; without one it takes interfaces::MakeEcho() and the call
is the identity. This node has no IPC, so it is always the identity -- which
is Core's own non-multiprocess behaviour, not a stub. It exists because
rpc_misc.py:96 calls it and rpc_help.py:110 fails a node whose
dump_all_command_conversions is missing a method client.cpp lists."
  (declare (ignore node))
  (unless (stringp arg)
    (error 'rpc-error :code +rpc-type-error+
                      :message "JSON value of type null is not of expected type string"))
  arg)

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

(defun %method-help-text (method)
  "The help document for one METHOD, the shape Core's RPCHelpMan::ToString
builds (rpc/util.cpp:773-793): the ONE-LINE summary -- the method name and
its declared arguments, a run of optional ones wrapped in `( )' -- then a
blank line, then the description.

    getblockchaininfo

    Returns an object containing various state info regarding blockchain
    processing.

The name-then-newline opening is the part clients rely on: Core's
rpc_named_arguments.py:21 asserts `node.help(command='getblockchaininfo')
.startswith('getblockchaininfo\\n')', and the web console reads the first
word of each line. Answering the bare method name, as this did, has no
newline at all.

DIVERGENCE, unchanged from before: no method here carries Core's Arguments,
Result or Examples sections, so the document stops after the description."
  (let ((description (rpc-method-description method)))
    (if description
        (format nil "~A~%~%~A~%" (rpc-usage-line method)
                (string-trim '(#\Space #\Tab #\Newline #\Return) description))
        (format nil "~A~%" (rpc-usage-line method)))))

(define-rpc "help" (node params)
  "List available RPC methods, or answer with one method's help document
(Bitcoin Core help / CRPCTable::help, rpc/server.cpp:295-330).

A bare call lists every method Core would list: the ones it files under the
category \"hidden\" -- generate*, invalidateblock, setmocktime, echo,
addconnection, getorphantxs -- are left out (:310-311, *RPC-HIDDEN-METHODS*),
because they are test and debugging entry points rather than part of the
node's interface. `help <name>' still answers for a hidden method, which is
how rpc_orphans.py:152-153 tells the two apart: getorphantxs must be absent
from the listing AND must not be an \"unknown command\".

DIVERGENCE: the listing is one bare method name per line rather than Core's
usage lines under `== Category ==' headings; this node carries no category
for its methods (rpc_help.py's test_categories is what wants them).

A method whose help text IS its behaviour registers it in *RPC-HELP-TEXTS*
(register-rpc-help) and is answered from there first -- today `generate'
alone, whose deprecation notice is what rpc_generate.py:129-132 asks for.

The undocumented \"dump_all_command_conversions\" argument returns the
argument-conversion table instead (Core rpc/server.cpp:135-138); it is what
rpc_help.py uses to check this node against Core's client.cpp."
  (declare (ignore node))
  (let ((method (first params)))
    (cond
      ((equal method "dump_all_command_conversions")
       (%dump-all-command-conversions))
      ((and method (stringp method))
       (cond ((gethash method *rpc-help-texts*))
             ((gethash method *rpc-methods*) (%method-help-text method))
             (t (format nil "help: unknown command: ~A" method))))
      (t
       (let ((names '()))
         (maphash (lambda (k v)
                    (declare (ignore v))
                    (unless (rpc-method-hidden-p k) (push k names)))
                  *rpc-methods*)
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

