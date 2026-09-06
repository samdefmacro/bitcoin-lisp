(in-package #:bitcoin-lisp.rpc)

;;; JSON-RPC 2.0 Server
;;;
;;; Implements Bitcoin Core-compatible RPC interface over HTTP.

(defvar *rpc-warmup-status* nil
  "What the node is doing while it starts, or NIL once it is ready.

Core's rpcWarmupStatus / fRPCInWarmup (rpc/server.cpp:35-36). Every RPC answers
RPC_IN_WARMUP (-28) with this string until SetRPCWarmupFinished, which is what
lets the server be REACHABLE before the node is usable — a client gets a
specific, retryable answer instead of a refused connection.

NIL by default, and START-RPC-SERVER enters warmup only when its caller asks
(:WARMUP T, which START-NODE passes). Core's equivalent is true at static init
because its only caller is AppInitMain; here the server is also started
directly from tests and the REPL, where \"ready\" is the honest answer and an
implicit warmup would be a trap.")

(defun set-rpc-warmup-status (status)
  "Report what startup is doing (Core SetRPCWarmupStatus, wired to InitMessage,
init.cpp:1559)."
  (setf *rpc-warmup-status* status))

(defun finish-rpc-warmup ()
  "Mark the node ready; every RPC answers normally from here (Core
SetRPCWarmupFinished, init.cpp:2293)."
  (setf *rpc-warmup-status* nil))

(defvar *active-rpc-commands* '()
  "In-flight RPC commands, each a cons of the method name and the
INTERNAL-REAL-TIME it started at. Core's g_rpc_server_info.active_commands,
maintained by an RAII guard around every command execution (rpc/server.cpp).

Reported by getrpcinfo, and that is not cosmetic: it is how a client knows a
long-running call is still running — feature_shutdown.py waits for two
concurrent commands before it will attempt a shutdown, so a node that always
reports none hangs that test forever.")

(defvar *active-rpc-commands-lock* (bt:make-lock "rpc-active")
  "Guards *ACTIVE-RPC-COMMANDS*: RPC handlers run one thread per connection.")

(defmacro with-active-rpc-command ((method) &body body)
  "Record METHOD as in-flight for the duration of BODY.

The entry is removed by IDENTITY, not by value: two concurrent calls to the
same method are two indistinguishable entries, and removing by value would drop
whichever came first and leave the other listed forever."
  (let ((entry (gensym "ENTRY")))
    `(let ((,entry (cons ,method (get-internal-real-time))))
       (bt:with-lock-held (*active-rpc-commands-lock*)
         (push ,entry *active-rpc-commands*))
       (unwind-protect (progn ,@body)
         (bt:with-lock-held (*active-rpc-commands-lock*)
           (setf *active-rpc-commands*
                 (delete ,entry *active-rpc-commands* :test #'eq :count 1)))))))

(defun active-rpc-commands ()
  "The in-flight commands as (method . duration-microseconds) pairs."
  (let ((now (get-internal-real-time))
        (per-second internal-time-units-per-second))
    (bt:with-lock-held (*active-rpc-commands-lock*)
      (loop for (method . started) in *active-rpc-commands*
            collect (cons method
                          (round (* (- now started) 1000000) per-second))))))

(defun dispatch-rpc-method (node method params)
  "Dispatch to the appropriate method handler.

Warmup is checked FIRST, before the method is even looked up — the position
Core checks it in (CRPCTable::execute, rpc/server.cpp:484-489) — and with no
exemptions, also as in Core. That ordering is deliberate: during warmup the
node cannot answer anything honestly, so \"still starting\" is a better reply
than \"no such method\" for a method that does exist."
  (let ((warmup *rpc-warmup-status*))
    (when warmup
      (error 'rpc-error :code +rpc-in-warmup+ :message warmup)))
  (let ((handler (gethash method *rpc-methods*)))
    (unless handler
      ;; Core's exact message (server.cpp:499) — no method-name suffix.
      (error 'rpc-error :code +rpc-method-not-found+
                        :message "Method not found"))
    ;; In-flight for as long as the handler runs, so getrpcinfo can report it.
    (with-active-rpc-command (method)
      (funcall handler node params))))

;;; --- Register All Methods ---

(defun register-all-methods ()
  "Install every DEFINE-RPC method into *RPC-METHODS*. Definitions register
themselves at load time; this reinstalls them all, for a table a test has
cleared or a server started after one."
  (loop for (name . symbol) in *rpc-registry*
        do (register-rpc-method name (symbol-function symbol))))

;;; --- JSON-RPC Request/Response Handling ---

(defun %normalize-json-value (value top-level)
  "Boolean normalization of a parsed request value (booleans arrive as
'yason:true / 'yason:false from the symbols parse mode): true -> T
everywhere; false -> the +json-false+ sentinel when TOP-LEVEL (a direct
positional parameter — handlers read those through positional-bool so
explicit false, null, and omitted are distinguishable, Core's isNull
semantics), NIL inside nested arrays/objects (the historical folding —
object readers distinguish absence via present-p). Hash tables are
normalized in place; lists are rebuilt."
  (cond ((eq value 'yason:true) t)
        ((eq value 'yason:false) (if top-level +json-false+ nil))
        ((hash-table-p value)
         (maphash (lambda (key v)
                    (setf (gethash key value) (%normalize-json-value v nil)))
                  value)
         value)
        ;; Arrays are parsed as VECTORS purely so that an EMPTY one is
        ;; distinguishable from null — `[]` and `null` are both NIL once an
        ;; array is a list, and Core's argument checking splits on exactly
        ;; that difference. They are turned straight back into lists here, so
        ;; every handler and every test keeps seeing the lists it always saw;
        ;; the ONE value that survives the round trip differently is a
        ;; top-level empty array, which becomes the +json-empty-array+
        ;; sentinel. Nested empty arrays fold to NIL, as explicit false does.
        ;; NOT (VECTORP value): a string is a vector too, and mapping one
        ;; would turn every JSON string into a list of characters.
        ((and (vectorp value) (not (stringp value)))
         (if (zerop (length value))
             (if top-level +json-empty-array+ nil)
             (map 'list (lambda (v) (%normalize-json-value v nil)) value)))
        ((and (consp value) (rpc-proper-list-p value))
         (mapcar (lambda (v) (%normalize-json-value v nil)) value))
        (t value)))

(defun %normalize-rpc-params (params)
  "Normalize a request's params: positional (array) params keep explicit
false as the +json-false+ sentinel and an explicit empty array as
+json-empty-array+, both at top level only; named-params objects are
normalized as nested values.

The positional case arrives as a VECTOR from the parser and as a LIST from
the tests and from the named-parameter transform, and both must get the
top-level treatment — reading only one of them is how a sentinel silently
stops being applied."
  (cond ((and (vectorp params) (not (stringp params)))
         (map 'list (lambda (v) (%normalize-json-value v t)) params))
        ((and (consp params) (rpc-proper-list-p params))
         (mapcar (lambda (v) (%normalize-json-value v t)) params))
        (t (%normalize-json-value params nil))))

(defun request-json-version (request)
  "The JSON-RPC version of one parsed request object REQUEST (a hash-table):
:V2 only for the exact marker jsonrpc:\"2.0\", else :V1 — an absent member,
\"1.0\" or \"1.1\" all mean legacy 1.x, which is Core's V1_LEGACY default
(JSONRPCRequest::parse, rpc/request.cpp:212-227)."
  (if (equal (gethash "jsonrpc" request) "2.0") :v2 :v1))

(defun %named-arg-slot (name-spec key)
  "T when KEY names the slot NAME-SPEC, which may list aliases separated by
#\\| (Core splits the pattern on '|', rpc/server.cpp:396)."
  (let ((start 0))
    (loop
      (let* ((bar (position #\| name-spec :start start))
             (alias (subseq name-spec start (or bar (length name-spec)))))
        (when (string= alias key) (return t))
        (unless bar (return nil))
        (setf start (1+ bar))))))

(defun %named-params-to-positional (method params)
  "PARAMS as a positional list, mapping a JSON object onto METHOD's argument
names (Core transformNamedArguments, rpc/server.cpp:368-470). A params ARRAY is
returned unchanged.

Core's \"args\" convenience is honoured: a client may pass positional arguments
under that key alongside named ones, and the named ones fill the slots after
them (doc/JSON-RPC-interface.md#parameter-passing). This is what the functional
framework's own client sends whenever a call mixes the two
(authproxy.py:122-125).

Unfilled slots before a filled one become NIL, which is how an omitted optional
argument already reaches every handler."
  (if (not (hash-table-p params))
      params
      (let ((names (cdr (assoc (string-downcase method) *rpc-named-arg-names*
                               :test #'string=)))
            (remaining (make-hash-table :test 'equal))
            (positional '()))
        (maphash (lambda (k v) (setf (gethash k remaining) v)) params)
        ;; The positional prefix, taken out before the named slots are filled.
        (multiple-value-bind (args args-present) (gethash "args" remaining)
          (remhash "args" remaining)
          (when args-present
            ;; This transform runs on RAW parse output, before normalization,
            ;; so an array here is still a vector; a list only shows up from
            ;; the tests. Both are arrays, and neither is a string.
            (unless (or (and (vectorp args) (not (stringp args)))
                        (rpc-proper-list-p args))
              (error 'rpc-error :code +rpc-invalid-parameter+
                                :message "Parameter args must be an array"))
            (setf positional (coerce args 'list))))
        ;; Named-only members of the method's options object, collected out
        ;; before the positional slots are matched. Core does this inline in
        ;; the same loop (rpc/server.cpp:408); pulling it out first is the same
        ;; thing, because a named-only name can never also be a positional one.
        (let ((options '())
              (option-names (cdr (assoc method *rpc-named-only-args*
                                        :test #'string=))))
          (dolist (opt option-names)
            (multiple-value-bind (v present) (gethash opt remaining)
              (when present
                (remhash opt remaining)
                (push (cons opt v) options))))
          (setf options (nreverse options))
          (when options
            ;; Core pushes the accumulated object at the OPTIONS slot, which is
            ;; the one positional argument of type OBJ_NAMED_PARAMS. Finding it
            ;; by name is enough: every method that has one calls it "options",
            ;; except send/sendall/walletcreatefundedpsbt, where Core's own
            ;; help calls it "options" too.
            (let ((slot (position-if (lambda (n) (%named-arg-slot n "options"))
                                     names)))
              (when (and slot (not (gethash "options" remaining)))
                (setf (gethash "options" remaining)
                      (let ((h (make-hash-table :test 'equal)))
                        (dolist (kv options h)
                          (setf (gethash (car kv) h) (cdr kv)))))))))
        (let ((slots '()))
          (loop for name-spec in names
                for index from 0
                do (let ((hit nil) (hit-key nil))
                     (maphash (lambda (k v)
                                (when (and (not hit-key) (%named-arg-slot name-spec k))
                                  (setf hit v hit-key k)))
                              remaining)
                     (cond
                       ((null hit-key) (push :absent slots))
                       (t
                        (remhash hit-key remaining)
                        ;; A slot the positional prefix already filled cannot
                        ;; also be named (Core raises on exactly this).
                        (when (< index (length positional))
                          (error 'rpc-error
                                 :code +rpc-invalid-parameter+
                                 :message
                                 (format nil "Parameter ~A specified twice both as ~
positional and named argument" hit-key)))
                        (push hit slots)))))
          ;; Anything left names no slot of this method.
          (let ((unknown nil))
            (maphash (lambda (k v) (declare (ignore v))
                       (when (or (null unknown) (string< k unknown))
                         (setf unknown k)))
                     remaining)
            (when unknown
              (error 'rpc-error :code +rpc-invalid-parameter+
                                :message (format nil "Unknown named parameter ~A" unknown))))
          (setf slots (nreverse slots))
          ;; Trailing absent slots are simply not passed; interior ones are NIL.
          (let* ((last-filled (position :absent slots :test-not #'eq :from-end t))
                 (kept (if last-filled (subseq slots 0 (1+ last-filled)) '()))
                 (named (mapcar (lambda (s) (if (eq s :absent) nil s)) kept)))
            (append positional (nthcdr (length positional) named)))))))

(defun %request-params (method params)
  "One request's PARAMS as the positional list every handler takes: METHOD's
named-argument transform first, then normalization.

Both halves belong to a REQUEST, not to the transport that carried it: Core
reaches transformNamedArguments through ExecuteCommand (rpc/server.cpp:502-512),
which a batch member and a singleton alike arrive at through
JSONRPCExec -> CRPCTable::execute (httprpc.cpp:151-201). The order is fixed --
the transform reads RAW parse output, so normalizing first would fold a named
`false` to NIL before the slot it fills is a top-level positional argument."
  (%normalize-rpc-params (%named-params-to-positional method params)))

(defun rpc-recoverable-storage-condition-p (condition)
  "Whether a STORAGE-CONDITION raised while serving a request can be answered.

SBCL raises four of these, and none of them is an ERROR -- probed on 2.6.5,
(subtypep 'storage-condition 'error) is NIL -- so an `(error (e) ...)' clause
never saw one and the worker thread died holding the connection instead of
replying. They do not all deserve the same treatment:

  CONTROL-STACK-EXHAUSTED, BINDING-STACK-EXHAUSTED and ALIEN-STACK-EXHAUSTED
  are recoverable. The stack is a bounded resource that unwinding gives back,
  and HANDLER-CASE has already unwound by the time a clause runs, so the reply
  is built with the whole stack available again.

  HEAP-EXHAUSTED-ERROR is not. Building and encoding a reply allocates, which
  is precisely what just failed, and the shortage is process-wide rather than
  something this request can give back. It is left to propagate."
  (typep condition '(or sb-kernel::control-stack-exhausted
                     sb-kernel::binding-stack-exhausted
                     sb-kernel::alien-stack-exhausted)))

(defun rpc-resignal-storage-condition (condition)
  "Re-raise CONDITION, which this boundary will not answer. HANDLER-CASE has
already unwound, so the original frames are gone; what survives is the
condition itself and the log line its handler wrote."
  (error condition))

(defun parse-json-rpc-request (body)
  "Parse JSON-RPC request body. Returns (values :single method params id
version id-present-p) or (values :batch requests). VERSION is :v2 when the
request carries jsonrpc:\"2.0\", else :v1 (absent/1.0/1.1 — Core JSONRPCRequest
::parse's V1_LEGACY); ID-PRESENT-P distinguishes a V2 notification (no id
member at all) from id:null. Signals rpc-error on malformed input.
Booleans are parsed as symbols and normalized via %normalize-rpc-params so
top-level positional false survives as the +json-false+ sentinel; arrays are
parsed as VECTORS for the same reason — it is the only way an empty array can
be told from null — and %normalize-json-value turns them back into the lists
handlers expect, leaving +json-empty-array+ where a top-level positional
argument was `[]`."
  (handler-case
      (let ((json (let ((yason:*parse-json-booleans-as-symbols* t)
                        (yason:*parse-json-arrays-as-vectors* t))
                    (yason:parse body))))
        (cond
          ;; Batch request (array). A vector now, since that is how arrays
          ;; arrive; the members are objects and stay hash-tables. An EMPTY
          ;; batch is still a batch — Core answers it with the invalid-request
          ;; error rather than treating it as a single call — so this must
          ;; test arrayness, not emptiness.
          ((and (vectorp json) (not (stringp json)))
           (values :batch (coerce json 'list)))
          ;; Single request (object)
          ((hash-table-p json)
           (let ((method (gethash "method" json))
                 (params (gethash "params" json))
                 (version (request-json-version json)))
             ;; Accept any/absent "jsonrpc" version: bitcoin-cli sends 1.0 (or
             ;; omits it) on older builds and 2.0 on newer; Core doesn't
             ;; validate it. Rejecting non-2.0 made stock bitcoin-cli unusable.
             (unless (stringp method)
               (error 'rpc-error :code +rpc-invalid-request+
                                 :message "Missing or invalid method"))
             (multiple-value-bind (id id-present) (gethash "id" json)
               (values :single method
                       (%request-params method (or params '()))
                       id version
                       (and id-present t)))))
          (t
           (error 'rpc-error :code +rpc-invalid-request+
                             :message "Invalid request format"))))
    ;; Our own -32600 invalid-request errors must pass through unchanged;
    ;; only a genuine JSON parse failure is -32700 (previously the outer
    ;; clause swallowed them into "Parse error").
    (rpc-error (e) (error e))
    (error (e)
      (declare (ignore e))
      (error 'rpc-error :code +rpc-parse-error+
                        :message "Parse error"))
    ;; Not a parse failure: a resource the request exhausted while being read.
    ;; -32603 says so, where -32700 would blame the caller's JSON.
    (storage-condition (e)
      (bl.log:node-log :error "RPC request exhausted a resource while parsing: ~A"
                       (type-of e))
      (unless (rpc-recoverable-storage-condition-p e)
        (rpc-resignal-storage-condition e))
      (error 'rpc-error :code +rpc-internal-error+
                        :message "Internal error"))))

(defun rpc-proper-list-p (x)
  "True if X is a proper (nil-terminated) list."
  (loop for tail = x then (cdr tail)
        while (consp tail)
        finally (return (null tail))))

(defun rpc-object-alist-p (x)
  "True if X is a non-empty proper list whose every element is a (string-key . value)
cons — i.e. an alist that should serialize as a JSON object. A list whose elements
are themselves lists/alists (e.g. an array of objects) is NOT an object-alist."
  (and (consp x)
       (rpc-proper-list-p x)
       (every (lambda (e) (and (consp e) (stringp (car e)))) x)))

(defun rpc-result->json (x)
  "Normalize an RPC handler result for yason: object-alists become hash-tables
(JSON objects), other proper lists become arrays (recursing into elements), and
atoms pass through unchanged. RPC methods build results as alists, but yason's
default list encoder treats every list as an array and chokes on the dotted
pairs — so without this every object-returning RPC errors out."
  (cond
    ((rpc-object-alist-p x)
     (let ((ht (make-hash-table :test 'equal)))
       (dolist (pair x ht)
         (setf (gethash (car pair) ht) (rpc-result->json (cdr pair))))))
    ((and (consp x) (rpc-proper-list-p x))
     (mapcar #'rpc-result->json x))
    (t x)))

(defun %make-rpc-reply (result error-obj id version id-present)
  "Assemble a JSON-RPC reply the way Core's JSONRPCReplyObj does
(rpc/request.cpp:51-68) — the one place that knows how a reply's shape depends
on the request's VERSION (:v1 or :v2):
- the \"jsonrpc\" key is emitted for :V2 ONLY (:55);
- a legacy 1.x reply carries BOTH \"result\" and \"error\", one of them null
  (:57-64). python-bitcoinrpc's AuthServiceProxy does
  `if response['error'] is not None:` and so raises KeyError: 'error' on every
  successful call against a reply that omits it. NIL encodes as JSON null;
- \"id\" is omitted entirely when the request carried no id member (:66,
  id = std::nullopt at request.cpp:207-211) — that is ID-PRESENT NIL.
ERROR-OBJ NIL means success. Anything other than :V2 is treated as legacy 1.x,
matching Core's V1_LEGACY default for a request with no \"jsonrpc\" member."
  (let ((response (make-hash-table :test 'equal))
        (v2 (eq version :v2)))
    (when v2
      (setf (gethash "jsonrpc" response) "2.0"))
    (cond ((null error-obj)
           (setf (gethash "result" response) result)
           (unless v2
             (setf (gethash "error" response) nil)))
          (t
           (unless v2
             (setf (gethash "result" response) nil))
           (setf (gethash "error" response) error-obj)))
    (when id-present
      (setf (gethash "id" response) id))
    response))

(defun make-rpc-response (result id version &key (id-present t))
  "Create a successful JSON-RPC response for a request of VERSION (:v1 or :v2);
see %MAKE-RPC-REPLY for the version-dependent shape."
  (%make-rpc-reply (rpc-result->json result) nil id version id-present))

(defun make-rpc-error-response (code message id version &key data (id-present t))
  "Create an error JSON-RPC response for a request of VERSION (:v1 or :v2);
see %MAKE-RPC-REPLY for the version-dependent shape."
  (let ((error-obj (make-hash-table :test 'equal)))
    (setf (gethash "code" error-obj) code)
    (setf (gethash "message" error-obj) message)
    (when data
      (setf (gethash "data" error-obj) (rpc-result->json data)))
    (%make-rpc-reply nil error-obj id version id-present)))

(defun rpc-error-response (condition id version &key (id-present t))
  "The reply an RPC-ERROR CONDITION becomes for a request of VERSION."
  (make-rpc-error-response (rpc-error-code condition)
                           (rpc-error-message condition)
                           id version
                           :data (rpc-error-data condition)
                           :id-present id-present))

(defun handle-single-request (node method params id version &key (id-present t))
  "Handle a single RPC request. VERSION and ID-PRESENT come from the parsed
request and shape the reply (see MAKE-RPC-RESPONSE)."
  (handler-case
      (let ((result (dispatch-rpc-method node method params)))
        (make-rpc-response result id version :id-present id-present))
    (rpc-error (e)
      (rpc-error-response e id version :id-present id-present))
    (error (e)
      (bl.log:node-log :error "RPC internal error: ~A" e)
      (make-rpc-error-response +rpc-internal-error+
                               (format nil "Internal error: ~A" e)
                               id version
                               :id-present id-present))
    (storage-condition (e)
      (bl.log:node-log :error "RPC method ~A exhausted a resource: ~A"
                       method (type-of e))
      (unless (rpc-recoverable-storage-condition-p e)
        (rpc-resignal-storage-condition e))
      (make-rpc-error-response +rpc-internal-error+
                               (format nil "Internal error: ~A" (type-of e))
                               id version
                               :id-present id-present))))

(defun handle-batch-request (node requests)
  "Handle a batch of RPC requests, returning the list of replies to send.
Core re-parses every batch member on its own (httprpc.cpp:194-206), so version
and id-presence are PER MEMBER; a 2.0 notification (no id member) is executed
but contributes no reply at all (:207-209).

A member takes the SAME per-request path as a singleton, %REQUEST-PARAMS
included: Core runs both through JSONRPCExec -> execute -> ExecuteCommand,
where transformNamedArguments lives (rpc/server.cpp:502-512). Skipping it here
left a member whose \"params\" was a JSON object handing the handler a raw
hash-table, which every handler read positionally and answered with -32603 and
a Lisp type error in the message. The transform can itself signal (an unknown
named parameter is -8), and Core catches a member's error into that member's
reply rather than failing the batch (httprpc.cpp:202-206), which is what the
handler-case around it does."
  (let ((responses '()))
    (dolist (req requests (nreverse responses))
      (if (hash-table-p req)
          (let ((method (gethash "method" req))
                (version (request-json-version req)))
            (multiple-value-bind (id id-present) (gethash "id" req)
              (let ((response
                      (handler-case
                          (if (stringp method)
                              (handle-single-request
                               node method
                               (%request-params method (or (gethash "params" req) '()))
                               id version :id-present id-present)
                              (make-rpc-error-response +rpc-invalid-request+
                                                       "Missing or invalid method"
                                                       id version
                                                       :id-present id-present))
                        (rpc-error (e)
                          (rpc-error-response e id version :id-present id-present)))))
                (unless (and (eq version :v2) (not id-present))
                  (push response responses)))))
          ;; A non-object member has no version of its own; Core's default is
          ;; V1_LEGACY with a null id.
          (push (make-rpc-error-response +rpc-invalid-request+
                                         "Invalid request format"
                                         nil :v1)
                responses)))))

;;; --- HTTP Server ---

(defvar *rpc-server* nil
  "The running RPC server instance.")

(defvar *rpc-node* nil
  "The node instance for RPC handlers.")

(defvar *rpc-request-uri* nil
  "The path of the HTTP request being served, bound by RPC-HANDLER for the
duration of the call (Core JSONRPCRequest::URI). The wallet reads its
/wallet/<name> endpoint from it; NIL outside a request.")

(defvar *rpc-credentials* '()
  "Every credential the RPC server authorizes against, each an RPC-CREDENTIAL:
Core's g_rpcauth (httprpc.cpp:36). The cookie-or-rpcuser pair and the -rpcauth
entries live in this ONE list, as they do in Core — the plaintext pair is
salted and hashed at install time (InitRPCAuthentication, httprpc.cpp:275-287)
and the password itself is then discarded rather than held in a global for the
node's lifetime.")

(alexandria:define-constant +rpc-cookie-user+ "__cookie__"
  :test #'equalp :documentation "Username in the .cookie file (Bitcoin Core convention).")

(defvar *rpc-cookie-path* nil
  "Path of the .cookie file this process generated, so shutdown can remove it
(Core's g_generated_cookie / DeleteAuthCookie, request.cpp:167-177). NIL when
the credential came from -rpcuser/-rpcpassword instead.")

(defun %write-cookie-file (namestring contents)
  "Create NAMESTRING owner-only and write CONTENTS into it. The file must not
exist and must not be a symlink, and it is 0600 from creation — never for one
instant a mode the process umask chose.

Core gets this from a process-wide umask 0077 (common/system.cpp:92-93), so its
cookie is 0600 at open(2) and fs::permissions is only ever called for an
explicit -rpccookieperms (request.cpp:99-146). We do not set a process umask, so
the mode has to come from open(2) itself: creating the file under the ambient
umask and chmod-ing afterwards leaves the secret world-readable while it is
being written (the live host runs umask 002 — its cookies were 0664), and POSIX
checks permissions only at open, so an fd opened in that window stays valid
across the chmod and the rename.

O_EXCL also means the secret is never written into a file we did not create:
:if-exists :supersede opens the EXISTING inode with O_TRUNC (verified on SBCL
2.6.5), so a planted .cookie.tmp — or a hard link to one — receives the secret,
and O_NOFOLLOW additionally refuses a planted symlink, which would otherwise be
written through and then renamed target-and-all over .cookie."
  (let* ((mode (%cookie-file-mode))
         (fd (sb-posix:open namestring
                            (logior sb-posix:o-wronly sb-posix:o-creat
                                    sb-posix:o-excl sb-posix:o-nofollow)
                            mode))
         (stream nil))
    (unwind-protect
         (progn
           ;; open(2) applies mode & ~umask, so the file is never MORE
           ;; permissive than MODE; fchmod on our own fd (no path, no race)
           ;; pins it to exactly MODE even under a umask that strips bits the
           ;; operator asked for with -rpccookieperms.
           (sb-posix:fchmod fd mode)
           (setf stream (sb-sys:make-fd-stream fd :output t :external-format :utf-8
                                                  :name "rpc-cookie"))
           (write-string contents stream)
           (finish-output stream))
      ;; CLOSE on an fd-stream closes the fd, so close exactly one of them.
      (if stream (close stream) (sb-posix:close fd)))))

(defvar *rpc-threads* nil
  "Maximum concurrent RPC handler threads, or NIL for hunchentoot's default
(Core -rpcthreads, DEFAULT_HTTP_THREADS = 16). Core services requests from a
fixed pool; hunchentoot is thread-per-connection, so this caps the pool rather
than sizing it — the observable behaviour, a bound on concurrent work, is the
same.")

(defvar *rpc-server-timeout* 30
  "Seconds an idle RPC connection is held before it is closed (Core
-rpcservertimeout / DEFAULT_HTTP_SERVER_TIMEOUT = 30, httpserver.h:28). NIL
means no timeout, which is what Core's -rpcservertimeout=0 asks for.

Core's default is 30; hunchentoot's is 20, so leaving hunchentoot's in place
was already off by a third. What actually mattered is that the option did not
reach the acceptor at all — see START-RPC-SERVER.")

(defvar *rpc-cookie-file* nil
  "Where the .cookie goes, or NIL for <datadir>/.cookie (Core -rpccookiefile,
init.cpp:710). A relative path is taken relative to the data directory, as Core
prefixes it with the net-specific datadir.")

(defvar *rpc-cookie-perms* :owner
  "Who may read the .cookie: :OWNER (0600), :GROUP (0640) or :ALL (0644).
Core's -rpccookieperms (init.cpp:711), whose default is owner via umask 0077.

Loosening this is a real decision, not a formatting one — the cookie IS the RPC
credential — so the mode is passed explicitly to the create rather than left to
the ambient umask. See %WRITE-COOKIE-FILE for why that distinction matters.")

(defun %cookie-file-mode ()
  "The octal mode *RPC-COOKIE-PERMS* names."
  (ecase *rpc-cookie-perms*
    (:owner #o600)
    (:group #o640)
    (:all   #o644)))

(defun parse-rpc-cookie-perms (value)
  "Parse a -rpccookieperms value, or NIL when it names no known audience."
  (when (stringp value)
    (cond ((string-equal value "owner") :owner)
          ((string-equal value "group") :group)
          ((string-equal value "all") :all))))

(defun rpc-cookie-path (data-directory)
  "Where the cookie goes for DATA-DIRECTORY, honouring -rpccookiefile."
  (cond ((null *rpc-cookie-file*) (merge-pathnames ".cookie" data-directory))
        ;; An absolute path is used as given; a relative one hangs off the data
        ;; directory, which is what Core means by "prefixed by a net-specific
        ;; datadir location".
        ((uiop:absolute-pathname-p *rpc-cookie-file*)
         (pathname *rpc-cookie-file*))
        (t (merge-pathnames *rpc-cookie-file* data-directory))))

(defun generate-rpc-cookie (data-directory)
  "Write <data-directory>/.cookie as \"__cookie__:<random>\" and return
(values path secret), or NIL on failure. The file is the RPC credential, so it
is created owner-only and is never reachable under any other name — Core
creates it under umask 0077 (request.cpp:99-146)."
  (handler-case
      (let* ((secret (ironclad:byte-array-to-hex-string (ironclad:random-data 32)))
             (path (rpc-cookie-path data-directory))
             (tmp (make-pathname :type "tmp" :defaults path)))
        (ensure-directories-exist path)
        ;; A .cookie.tmp left behind by a crash would make the exclusive create
        ;; below fail on every later start; unlink drops the name (and a
        ;; symlink itself, never its target). Losing the race to a file planted
        ;; between the unlink and the open just fails the open, which aborts
        ;; cookie generation instead of writing the secret somewhere chosen.
        (handler-case (sb-posix:unlink (namestring tmp)) (error () nil))
        (%write-cookie-file (namestring tmp)
                            (format nil "~A:~A" +rpc-cookie-user+ secret))
        ;; Rename the file we exclusively created — not (truename tmp), which
        ;; would resolve a symlink and move its target over .cookie.
        (sb-posix:rename (namestring tmp) (namestring path))
        (values path secret))
    (error (e)
      (bl.log:node-log :warn "Could not write RPC cookie: ~A" e)
      nil)))

(defun delete-rpc-cookie ()
  "Remove the .cookie file this process generated (Core DeleteAuthCookie,
request.cpp:167-177). A cookie we did not write is left alone."
  (when *rpc-cookie-path*
    (handler-case
        (when (probe-file *rpc-cookie-path*)
          (delete-file *rpc-cookie-path*))
      (error (e)
        (bl.log:node-log :warn "Could not remove RPC cookie ~A: ~A"
                                *rpc-cookie-path* e)))
    (setf *rpc-cookie-path* nil)))

(defun %timing-resistant-equal (a b)
  "STRING= over A and B in time that does not depend on how many characters
matched (Core TimingResistantEqual, util/strencodings.h:203-210) — a plain
comparison of an attacker-supplied credential leaks its correct prefix."
  (declare (type string a b))
  (let ((la (length a))
        (lb (length b)))
    (if (zerop lb)
        (zerop la)
        (let ((accumulator (logxor la lb)))
          (dotimes (i la)
            (setf accumulator
                  (logior accumulator
                          (logxor (char-code (char a i))
                                  (char-code (char b (mod i lb)))))))
          (zerop accumulator)))))

(defvar *rpc-dispatcher* nil
  "The RPC dispatcher function (for cleanup on stop).")

(defstruct (http-surface (:constructor %make-http-surface (name options start stop)))
  "An HTTP surface a layer above serves through this acceptor (REST, the web
UI). OPTIONS are the START-RPC-SERVER keywords it reads; START is called with
that option plist and returns the hunchentoot dispatcher to install, or NIL
to stay off; STOP (may be NIL) clears its state when the server stops."
  name options start stop)

(defvar *http-surfaces* '()
  "The surfaces registered so far, in registration order -- Core's
RegisterHTTPHandler table (httpserver.cpp). START-RPC-SERVER installs each
one's dispatcher in FRONT of the JSON-RPC \"/\" dispatcher, later
registrations in front of earlier ones.")

(defvar *surface-dispatchers* '()
  "The dispatchers the running server installed for its surfaces.")

(defun register-http-surface (name &key options start stop)
  "Register (or replace) the HTTP surface NAME; see HTTP-SURFACE. Called at
load time by the file that serves the surface, so START-RPC-SERVER never has
to name it."
  (setf *http-surfaces*
        (append (remove name *http-surfaces* :key #'http-surface-name)
                (list (%make-http-surface name options start stop)))))

(defun %check-surface-options (options)
  "Refuse a START-RPC-SERVER keyword neither the server nor any registered
surface reads -- the check &ALLOW-OTHER-KEYS gave away."
  (let ((known (append '(:port :bind :bind-supplied-p :user :password
                         :rpc-auth :allow-ip :rpc-whitelist
                         :rpc-whitelist-default :warmup)
                       (loop for surface in *http-surfaces*
                             append (http-surface-options surface)))))
    (loop for (key nil) on options by #'cddr
          unless (member key known)
            do (internal-error "start-rpc-server: unknown option ~S (known: ~{~S~^ ~})"
                               key known))))

(defun %stop-http-surfaces ()
  (setf *surface-dispatchers* '())
  (dolist (surface *http-surfaces*)
    (when (http-surface-stop surface)
      (funcall (http-surface-stop surface)))))

;;; --- RPC Rate Limiting ---

(defvar *rpc-rate-limit* '(100.0 . 200.0)
  "Rate limit for RPC requests: (rate-per-sec . burst).")

(defconstant +max-rpc-body-size+ #x02000000
  "Maximum RPC request body size in bytes: 32 MiB, matching Bitcoin Core's
evhttp_set_max_body_size(MAX_SIZE) (httpserver.cpp:410, serialize.h:32).
The previous 1 MiB cap rejected submitblock for a normal mainnet block.
Oversized bodies get HTTP 400, like libevent's enforcement.")

(defvar *rpc-rate-limiter* nil
  "Global RPC rate limiter (token bucket). Thread-safe via *rpc-rate-limiter-lock*.")

(defvar *rpc-rate-limiter-lock* (bt:make-lock "rpc-rate-limiter")
  "Lock for thread-safe access to *rpc-rate-limiter*.")

(defun init-rpc-rate-limiter ()
  "Initialize the global RPC rate limiter from configuration."
  (let ((config *rpc-rate-limit*))
    (setf *rpc-rate-limiter*
          (bl.rl:make-rate-limiter (car config) (cdr config)))))

(defun rpc-rate-limit-check ()
  "Check if the RPC request is within rate limits (thread-safe).
Returns T if allowed, NIL if rate limited."
  (when *rpc-rate-limiter*
    (bt:with-lock-held (*rpc-rate-limiter-lock*)
      (return-from rpc-rate-limit-check
        (bl.rl:token-bucket-allow-p *rpc-rate-limiter*))))
  t)

(defun rpc-origin-allowed-p (origin host)
  "T unless ORIGIN (the Origin request header, or NIL when absent) names a
different authority than HOST (the request's Host header). Browsers attach
Origin to cross-site POSTs but never let a page forge it, so an alien value
(including \"null\") is a hostile web page driving the user's browser at our
RPC port — rejected before auth (docs/gui-plan.md §2/§4). Non-browser
clients (bitcoin-cli, curl) send no Origin at all and always pass."
  (or (null origin)
      (let* ((origin (string-trim '(#\Space #\Tab) origin))
             (scheme-end (search "://" origin)))
        (and scheme-end host
             (string-equal (subseq origin (+ scheme-end 3))
                           (string-trim '(#\Space #\Tab) host))))))

(defun %credential-bytes (string)
  "The bytes a configured credential is made of. UTF-8, because that is how the
config file and the .cookie file were read; Core never decodes at all and
compares the file's bytes directly, so encoding here is how we recover the same
comparison."
  (flexi-streams:string-to-octets string :external-format :utf-8))

(defun %timing-resistant-equal-bytes (a b)
  "TIMING-RESISTANT-EQUAL over octet vectors (Core TimingResistantEqual,
util/strencodings.h:203-210). Byte-wise, because an HTTP Basic credential is
bytes: decoding it to characters first is what made a non-ASCII password
unusable."
  (declare (type (vector (unsigned-byte 8)) a b))
  (let ((la (length a))
        (lb (length b)))
    (if (zerop lb)
        (zerop la)
        (let ((accumulator (logxor la lb)))
          (dotimes (i la)
            (setf accumulator
                  (logior accumulator (logxor (aref a i) (aref b (mod i lb))))))
          (zerop accumulator)))))

(defstruct (rpc-credential
            (:constructor %make-rpc-credential (user salt hash user-bytes salt-bytes)))
  "One RPC credential: a username and the salted HMAC-SHA256 of its password,
never the password. Core's g_rpcauth element (httprpc.cpp:36).

USER-BYTES and SALT-BYTES are the UTF-8 encodings of USER and SALT, precomputed
because both are fixed at startup and every authentication attempt would
otherwise re-encode them once per credential."
  (user nil :type string)
  (salt nil :type string)
  (hash nil :type string)
  (user-bytes nil :type (vector (unsigned-byte 8)))
  (salt-bytes nil :type (vector (unsigned-byte 8))))

(defun make-rpc-credential (user salt hash)
  "An RPC-CREDENTIAL for USER whose password hashes to HASH under SALT."
  (%make-rpc-credential user salt hash
                        (%credential-bytes user) (%credential-bytes salt)))

(defun parse-rpcauth-entry (spec)
  "Parse one -rpcauth SPEC of the form USER:SALT$HMAC into an RPC-CREDENTIAL, or
NIL when malformed. Core splits SPEC on #\: demanding exactly two fields, then
splits the second on #\$ demanding exactly two more (InitRPCAuthentication,
httprpc.cpp:289-300) — so neither a username with a colon nor a salt with a
dollar sign is expressible, and both are rejected rather than truncated."
  (when (stringp spec)
    (let ((colon (position #\: spec)))
      (when (and colon (not (find #\: spec :start (1+ colon))))
        (let* ((rest (subseq spec (1+ colon)))
               (dollar (position #\$ rest)))
          (when (and dollar (not (find #\$ rest :start (1+ dollar))))
            (make-rpc-credential (subseq spec 0 colon)
                                 (subseq rest 0 dollar)
                                 (subseq rest (1+ dollar)))))))))

(defun %rpcauth-hmac-hex (salt-bytes password-bytes)
  "Lowercase hex of HMAC-SHA256 keyed by SALT-BYTES over PASSWORD-BYTES — the
digest an offered password is reduced to before comparison (CheckUserAuthorized,
httprpc.cpp:70-76). The salt keys the MAC as its own characters, not as the
bytes its hex spells."
  (bl.crypto:bytes-to-hex
   (bl.crypto:hmac-sha256 salt-bytes password-bytes)))

(defun %credential-authorizes-p (credential user-bytes password-bytes)
  "T when CREDENTIAL accepts USER-BYTES/PASSWORD-BYTES. Core compares the
username timing-resistantly and hashes the offered password with that entry's
salt only once the username matched (CheckUserAuthorized, httprpc.cpp:63-82)."
  (and (%timing-resistant-equal-bytes user-bytes
                                      (rpc-credential-user-bytes credential))
       (%timing-resistant-equal
        (%rpcauth-hmac-hex (rpc-credential-salt-bytes credential) password-bytes)
        (rpc-credential-hash credential))))

(defparameter *rpc-loopback-subnets*
  (list (bl.net:parse-subnet "127.0.0.0/8")
        (bl.net:parse-subnet "::1"))
  "The subnets the RPC ACL always contains. Core seeds rpc_allow_subnets with
127.0.0.0/8 and ::1 before reading any -rpcallowip and offers no way to remove
them (InitHTTPAllowList, httpserver.cpp:150-152), so they are the floor of the
ACL rather than something a configuration step has to remember to add.")

(defvar *rpc-allow-subnets* *rpc-loopback-subnets*
  "The RPC address ACL: Core's rpc_allow_subnets (httpserver.cpp:71). The
loopback floor is the initial value, so a request reaching the acceptor before
-rpcallowip is installed behaves like a node configured without it — not like
one that refuses even localhost.")

(defun rpc-client-allowed-p (address)
  "T when ADDRESS, the remote address of an HTTP request, is inside the RPC ACL
(Core ClientAllowed, httpserver.cpp:137-146)."
  (bl.net:address-in-subnets-p address *rpc-allow-subnets*))

(defun check-auth (auth-header)
  "The username AUTH-HEADER authenticates as, or NIL. AUTH-HEADER is the
request's Authorization header (NIL when it carried none); it authorizes when it
is an HTTP Basic credential matching any installed RPC credential — the
cookie-or-rpcuser pair and every -rpcauth entry alike, all of them salted
hashes in one list, as in Core's g_rpcauth (InitRPCAuthentication,
httprpc.cpp:275-300; CheckUserAuthorized, httprpc.cpp:63-82).

Every request needs a credential: Core answers 401 for an absent header and for
a non-matching one alike (HTTPReq_JSONRPC, httprpc.cpp:112-133). The username
is returned rather than just T because Core threads it out of RPCAuthorized
(httprpc.cpp:84) for -rpcwhitelist to key on."
  (and (stringp auth-header)
       *rpc-credentials*
       (> (length auth-header) 6)
       (string-equal (subseq auth-header 0 6) "Basic ")
       (handler-case
           ;; Compare BYTES, never decoded characters. Core assigns the base64
           ;; output straight into a std::string and compares it against the
           ;; configured credential as raw bytes (RPCAuthorized,
           ;; httprpc.cpp:84-102) — no encoding is involved on either side.
           ;;
           ;; We decoded the header with FLEXI-STREAMS:OCTETS-TO-STRING, whose
           ;; default external format is latin-1, while the configured password
           ;; came from a config file read as UTF-8. For any non-ASCII byte the
           ;; two disagree, so a non-ASCII -rpcpassword could never authenticate
           ;; — the credential was correct and the node said 401 forever.
           (let* ((decoded (cl-base64:base64-string-to-usb8-array
                            (string-trim '(#\Space #\Tab)
                                         (subseq auth-header 6))))
                  (colon-pos (position (char-code #\:) decoded)))
             (when colon-pos
               (let ((user (subseq decoded 0 colon-pos))
                     (password (subseq decoded (1+ colon-pos))))
                 (loop for credential in *rpc-credentials*
                       when (%credential-authorizes-p credential user password)
                         return (rpc-credential-user credential)))))
         (error () nil))))

;;; --- -rpcwhitelist: which methods each user may call ----------------------

(defvar *rpc-whitelist* (make-hash-table :test 'equal)
  "Which methods each -rpcwhitelist user may call: the authenticated user name
-> the list of method names (Core's g_rpc_whitelist, httprpc.cpp:37). A user
with NO entry here was named by no -rpcwhitelist, and *RPC-WHITELIST-DEFAULT*
decides what it may call.")

(defvar *rpc-whitelist-default* nil
  "What a user with no -rpcwhitelist entry may call: with NIL everything, with
T nothing at all (Core's g_rpc_whitelist_default, httprpc.cpp:38).

Core derives it from the whitelists themselves -- GetBoolArg
\"-rpcwhitelistdefault\" defaulting to \"any -rpcwhitelist was given\"
(httprpc.cpp:306) -- so the first whitelist an operator writes locks out every
OTHER user, __cookie__ (and with it bitcoin-cli and the web UI) included.
That is why Core's own rpc_whitelist.py has to whitelist __cookie__ explicitly
as soon as it turns the default on.")

(defun %split-rpc-whitelist-methods (string)
  "STRING split on a comma or a space, empty pieces kept.

Core splits a whitelist's method list with SplitString(s, \", \"), whose second
argument is a SET of separator characters (util/string.h:116-134): the \", \"
an operator naturally writes therefore yields an EMPTY piece between the two
names, and so does a trailing comma. Core keeps those in the std::set, where
they name no method and never match; dropping them here would be a difference
without a distinction, while trimming instead would accept a spelling Core
does not."
  (loop with start = 0
        for separator = (position-if (lambda (c) (member c '(#\, #\Space)))
                                     string :start start)
        collect (subseq string start separator)
        while separator
        do (setf start (1+ separator))))

(defun %parse-rpc-whitelist (specs)
  "The user -> allowed-methods table for the -rpcwhitelist SPECS
(InitRPCAuthentication, httprpc.cpp:307-325). A spec is
USERNAME[:<method>[,<method>...]], and three details are Core's:

- a spec with NO colon still CREATES the user's entry -- Core indexes
  g_rpc_whitelist with operator[] before it looks at the colon and then
  assigns nothing -- so a user mentioned that way has an EMPTY whitelist and
  may call nothing at all;
- a SECOND spec for the same user is INTERSECTED with what it already had, so
  repeating the option can only narrow a whitelist, never widen it;
- `user:' is a one-element list holding the empty method name, which matches
  no method: the user may call nothing."
  (let ((table (make-hash-table :test 'equal)))
    (dolist (spec specs table)
      (let* ((colon (position #\: spec))
             (user (subseq spec 0 (or colon (length spec))))
             (methods (when colon
                        (remove-duplicates
                         (%split-rpc-whitelist-methods (subseq spec (1+ colon)))
                         :test #'string=))))
        (multiple-value-bind (existing listed) (gethash user table)
          (setf (gethash user table)
                (cond ((null colon) (if listed existing '()))
                      (listed (intersection methods existing :test #'string=))
                      (t methods))))))))

(defun reset-rpc-whitelist ()
  "Forget the -rpcwhitelist configuration. It belongs to the server it was
given to, so a stop -- or a start that failed after installing it -- must drop
it rather than leave it restricting the next server, which was never told to."
  (setf *rpc-whitelist* (make-hash-table :test 'equal)
        *rpc-whitelist-default* nil))

(defun rpc-method-allowed-p (user method)
  "T when the authenticated USER may call METHOD (HTTPReq_JSONRPC,
httprpc.cpp:144-158). A user WITH a -rpcwhitelist may call exactly what it
lists; a user without one may call everything, unless -rpcwhitelistdefault is
in force, in which case it may call nothing."
  (multiple-value-bind (methods listed) (gethash user *rpc-whitelist*)
    (if listed
        (and (member method methods :test #'string=) t)
        (not *rpc-whitelist-default*))))

(defun %rpc-request-allowed-p (user request-type method-or-batch)
  "T when USER's -rpcwhitelist admits this whole request, else NIL after
logging the refusal Core logs (httprpc.cpp:145,155,186).

Core checks every member of a BATCH before it runs any of them
(httprpc.cpp:176-189), so one forbidden method refuses the batch as a unit
with HTTP 403 rather than answering that one member with an error -- a batch
is not a way to smuggle a method past the whitelist and read the rest of the
results anyway."
  (flet ((refuse (method)
           (if method
               (bl.log:node-log
                :warn "RPC User ~A not allowed to call method ~A" user method)
               (bl.log:node-log
                :warn "RPC User ~A not allowed to call any methods" user))
           nil))
    (let ((listed (nth-value 1 (gethash user *rpc-whitelist*))))
      (cond ((not listed) (or (not *rpc-whitelist-default*) (refuse nil)))
            ((eq request-type :single)
             (or (rpc-method-allowed-p user method-or-batch)
                 (refuse method-or-batch)))
            (t
             ;; A member that is not an object, or whose "method" is not a
             ;; string, is left to HANDLE-BATCH-REQUEST's -32600: Core reaches
             ;; for its method name here and throws instead, so neither tree
             ;; answers 403 for it.
             (dolist (req method-or-batch t)
               (let ((method (and (hash-table-p req) (gethash "method" req))))
                 (when (and (stringp method)
                            (not (rpc-method-allowed-p user method)))
                   (return (refuse method))))))))))

(defun rpc-json-error (http-status code message)
  "Return a JSON-RPC error response string with the given HTTP status.
These are pre-dispatch HTTP-level refusals (origin, rate limit, body size), so
no request version has been parsed: Core's JSONRPCRequest starts out
V1_LEGACY with a null id (request.h:55,63), which is the shape used here."
  (setf (hunchentoot:return-code*) http-status)
  (setf (hunchentoot:content-type*) "application/json")
  (with-output-to-string (s)
    (yason:encode (make-rpc-error-response code message nil :v1) s)))

(defun rpc-error-http-status (code)
  "HTTP status for a JSON-RPC 1.x error response (Core JSONErrorReply,
httprpc.cpp:41-59): -32600 -> 400, -32601 -> 404, everything else -> 500.
JSON-RPC 2.0 requests never use this — they always answer HTTP 200 with the
error in the body (httprpc.cpp:160-164)."
  (cond ((= code +rpc-invalid-request+) hunchentoot:+http-bad-request+)
        ((= code +rpc-method-not-found+) hunchentoot:+http-not-found+)
        (t hunchentoot:+http-internal-server-error+)))

(defun rpc-response-http-status (response version)
  "The HTTP status to send with a single JSON-RPC RESPONSE hash-table:
200 for success or any :V2 request; the Core 1.x mapping otherwise.
A :V1 success carries an \"error\" key whose value is null, so the test below
must stay a value test (NIL = success), not a key-presence test."
  (let ((err (gethash "error" response)))
    (if (or (null err) (eq version :v2))
        hunchentoot:+http-ok+
        (rpc-error-http-status (gethash "code" err)))))

(defun rpc-handler ()
  "Handle incoming RPC requests."
  (let ((request hunchentoot:*request*))
    ;; The address ACL is NOT here: it gates the whole acceptor
    ;; (acceptor-dispatch-request on rpc-acceptor), so it also covers /rest/ and
    ;; /ui/, exactly as Core's check in http_request_cb precedes the path-handler
    ;; lookup (httpserver.cpp:216-222 vs :235-250).

    ;; Reject cross-origin browser POSTs BEFORE auth (rpc-origin-allowed-p).
    (unless (rpc-origin-allowed-p (hunchentoot:header-in :origin request)
                                  (hunchentoot:header-in :host request))
      (return-from rpc-handler
        (rpc-json-error hunchentoot:+http-forbidden+ +rpc-misc-error+
                        "Origin does not match Host")))

    ;; Check authentication.
    ;;
    ;; The rate limiter lives inside the FAILURE branch, and that placement is
    ;; the point. Core has no RPC rate limit at all: the port is authenticated
    ;; and loopback-only by default, and a client that gets past both is a
    ;; trusted administrator. Ours ran AFTER auth and throttled that
    ;; administrator at 100 requests/second — which is fewer than one
    ;; `wait_until` poll loop, so Core's functional framework answered its own
    ;; polls with HTTP 429 and failed tests that had nothing to do with rates.
    ;;
    ;; What the limiter is actually for is the UNAUTHENTICATED side: bounding
    ;; the work a stranger can make us do, and slowing credential guessing.
    ;; That is preserved exactly, and it now composes with Core's 250ms
    ;; brute-force pause rather than duplicating it a layer later.
    (let* ((auth-header (hunchentoot:header-in :authorization request))
           ;; The USER, not just a yes: it is what -rpcwhitelist keys on, which
           ;; is why check-auth returns it (Core threads it out of
           ;; RPCAuthorized into jreq.authUser, httprpc.cpp:84,121).
           (user (check-auth auth-header)))
      (unless user
        (unless (rpc-rate-limit-check)
          (return-from rpc-handler
            (rpc-json-error 429 +rpc-misc-error+ "Rate limit exceeded")))
        ;; Core deters brute-forcing with a 250ms pause, but only once a
        ;; credential has actually been offered: a request with no
        ;; Authorization header is answered immediately (httprpc.cpp:112-133).
        (when auth-header
          (bl.log:node-log :warn "RPC incorrect password attempt from ~A"
                                  (hunchentoot:remote-addr request))
          (sleep 0.25))
        (setf (hunchentoot:return-code*) hunchentoot:+http-authorization-required+)
        (setf (hunchentoot:header-out :www-authenticate) "Basic realm=\"bitcoin-lisp\"")
        (return-from rpc-handler ""))
      (%rpc-handle-authorized request user))))

(defun %rpc-handle-authorized (request user)
  "Answer REQUEST, which USER has already authenticated for. Everything from
the body-size limit onwards; split out of RPC-HANDLER so the authenticated
user name reaches the -rpcwhitelist gate without the whole body having to
nest inside the auth check."
  ;; Check body size limit: 32 MiB (Core evhttp_set_max_body_size(MAX_SIZE),
  ;; httpserver.cpp:410). libevent answers an oversized body with 400.
  (let* ((content-length-str (hunchentoot:header-in :content-length request))
         (content-length (and content-length-str
                              (parse-integer content-length-str :junk-allowed t))))
    (when (and content-length
               (> content-length +max-rpc-body-size+))
      (return-from %rpc-handle-authorized
        (rpc-json-error hunchentoot:+http-bad-request+ +rpc-misc-error+
                        "Request body too large"))))

  ;; No Content-Type check. Core's HTTPReq_JSONRPC (httprpc.cpp:104-165) never
  ;; inspects the request's Content-Type at all — it writes one on the
  ;; RESPONSE and reads the body as JSON regardless. We required
  ;; application/json or text/plain and answered 415 otherwise, so a plain
  ;; `curl -d ...` (which defaults to application/x-www-form-urlencoded) and
  ;; any client that omits the header were refused here and worked against
  ;; Core. A body that is not JSON already fails at the parse below with a
  ;; -32700, which is the accurate answer; 415 blamed the header instead.

  ;; Process request. The request path is exposed to the handlers as
  ;; *RPC-REQUEST-URI* (Core JSONRPCRequest::URI): a /wallet/<name> endpoint
  ;; is how the wallet routes a call to one of its wallets (httprpc.cpp:340
  ;; registers the same handler under /wallet/); every other method
  ;; ignores it.
  (setf (hunchentoot:content-type*) "application/json")
  (let ((*rpc-request-uri* (hunchentoot:script-name*))
        (body (hunchentoot:raw-post-data :force-text t)))
    ;; Post-read body size check (in case Content-Length was absent or wrong)
    (when (and body (> (length body) +max-rpc-body-size+))
      (return-from %rpc-handle-authorized
        (rpc-json-error hunchentoot:+http-bad-request+ +rpc-misc-error+
                        "Request body too large")))
    (handler-case
        (multiple-value-bind (request-type method-or-batch params id version id-present)
            (parse-json-rpc-request body)
          ;; -rpcwhitelist, in Core's position: the body has parsed, nothing
          ;; has run yet (httprpc.cpp:144-189). Core's answer is a bare HTTP
          ;; 403 with no body — it names neither the method it refused nor
          ;; whether one exists.
          (unless (%rpc-request-allowed-p user request-type method-or-batch)
            (setf (hunchentoot:return-code*) hunchentoot:+http-forbidden+)
            (return-from %rpc-handle-authorized ""))
          (case request-type
            (:single
             (let ((response (handle-single-request *rpc-node* method-or-batch
                                                    params id version
                                                    :id-present id-present)))
               ;; A JSON-RPC 2.0 notification (no id member) answers 204
               ;; with no body after executing (Core httprpc.cpp:169);
               ;; otherwise the 1.x error->status mapping applies
               ;; (rpc-response-http-status; 2.0 is always 200).
               (cond
                 ((and (eq version :v2) (not id-present))
                  (setf (hunchentoot:return-code*) hunchentoot:+http-no-content+)
                  "")
                 (t
                  (setf (hunchentoot:return-code*)
                        (rpc-response-http-status response version))
                  (with-output-to-string (s)
                    (yason:encode response s))))))
            (:batch
             ;; Batches always answer HTTP 200 (Core httprpc.cpp:196-206),
             ;; except a non-empty all-notification batch, which answers 204
             ;; with no body (:220). An EMPTY batch keeps answering [] for
             ;; backwards compatibility (:211-219) — note NIL encodes as JSON
             ;; null, so the empty array must be spelled #().
             (let ((responses (handle-batch-request *rpc-node* method-or-batch)))
               (cond
                 ((and (null responses) method-or-batch)
                  (setf (hunchentoot:return-code*) hunchentoot:+http-no-content+)
                  "")
                 (t
                  (with-output-to-string (s)
                    (yason:encode (or responses #()) s))))))))
      (rpc-error (e)
        ;; Body-level failures (parse error -32700, invalid request -32600)
        ;; have no version context; Core treats them as 1.x — both for the
        ;; status mapping (parse error -> 500, invalid request -> 400) and
        ;; for the reply shape, since JSONErrorReply passes the still-default
        ;; V1_LEGACY/null-id JSONRPCRequest (httprpc.cpp:41-59).
        (setf (hunchentoot:return-code*)
              (rpc-error-http-status (rpc-error-code e)))
        (with-output-to-string (s)
          (yason:encode (make-rpc-error-response (rpc-error-code e)
                                                 (rpc-error-message e)
                                                 nil :v1)
                        s)))
      (error (e)
        (bl.log:node-log :error "RPC handler error: ~A" e)
        (setf (hunchentoot:return-code*) hunchentoot:+http-internal-server-error+)
        (with-output-to-string (s)
          (yason:encode (make-rpc-error-response +rpc-internal-error+
                                                 "Internal error"
                                                 nil :v1)
                        s)))
      (storage-condition (e)
        (bl.log:node-log :error "RPC handler exhausted a resource: ~A" (type-of e))
        (unless (rpc-recoverable-storage-condition-p e)
          (rpc-resignal-storage-condition e))
        (setf (hunchentoot:return-code*) hunchentoot:+http-internal-server-error+)
        (with-output-to-string (s)
          (yason:encode (make-rpc-error-response +rpc-internal-error+
                                                 "Internal error"
                                                 nil :v1)
                        s))))))

(defclass rpc-acceptor (hunchentoot:easy-acceptor)
  ()
  (:documentation
   "The RPC acceptor, whose only difference from EASY-ACCEPTOR is that it
enforces the -rpcallowip address ACL for EVERY request before any routing
happens.

The gate belongs here rather than in RPC-HANDLER because this one acceptor
serves three surfaces — the JSON-RPC \"/\" handler, the REST interface and the
web UI — and only the first goes through RPC-HANDLER. Core is arranged the same
way: ClientAllowed runs in http_request_cb (httpserver.cpp:216-222) ahead of the
pathHandlers lookup (:235-250), so /rest/ (rest.cpp:1160-1164) inherits the ACL
without doing anything itself. Putting the check in one handler would leave
/rest/ and /ui/ reachable from any address the moment -rpcbind is honoured."))

(defmethod hunchentoot:acceptor-dispatch-request ((acceptor rpc-acceptor) request)
  (if (rpc-client-allowed-p (hunchentoot:remote-addr request))
      (call-next-method)
      ;; Core answers a bare 403 and reveals nothing else — not the method it
      ;; would have refused, not whether a handler exists at this path.
      (rpc-json-error hunchentoot:+http-forbidden+ +rpc-misc-error+
                      "Client network is not allowed RPC access")))

(defun rpc-dispatch-handler ()
  "Dispatch handler for hunchentoot. Only handles POST requests."
  (if (eq (hunchentoot:request-method*) :post)
      (rpc-handler)
      (progn
        (setf (hunchentoot:return-code*) hunchentoot:+http-method-not-allowed+)
        "")))

(defun rpc-bind-loopback-p (address)
  "T when ADDRESS names a loopback interface. NIL and \"\" mean bind-any and
are not loopback."
  (and (stringp address)
       (let ((a (string-trim '(#\Space #\Tab #\[ #\]) address)))
         (or (string-equal a "localhost")
             (string= a "::1")
             (and (> (length a) 4) (string= (subseq a 0 4) "127."))))))

(defun %rpc-bind-address (bind allow-ip &optional bind-supplied-p)
  "The address the RPC acceptor may bind to. Core requires -rpcbind and
-rpcallowip to be given TOGETHER and ignores both otherwise, rather than
letting one flag expose the RPC port; it warns about whichever one was supplied
alone (HTTPBindAddresses, httpserver.cpp:316-327).

Core binds BOTH ::1 and 127.0.0.1 in the loopback default (httpserver.cpp:321-322)
where we bind one address; that is why the ACL's ::1 floor cannot match on a
default configuration here."
  (cond ((rpc-bind-loopback-p bind)
         ;; Core's warning here is about -rpcallowip given with no -rpcbind at
         ;; all; an explicit -rpcbind=127.0.0.1 alongside -rpcallowip takes its
         ;; else branch and warns about nothing. BIND-SUPPLIED-P is what keeps
         ;; the two apart, since BIND arrives already defaulted to 127.0.0.1.
         (when (and allow-ip (not bind-supplied-p))
           (bl.log:node-log
            :warn "Option -rpcallowip was specified without -rpcbind; this ~
doesn't usually make sense, as the RPC port stays on ~A" bind))
         bind)
        (allow-ip bind)
        (t
         (bl.log:node-log
          :warn "-rpcbind=~A ignored because -rpcallowip was not specified, ~
refusing to allow everyone to connect; the RPC port stays on 127.0.0.1"
          (or bind "<any>"))
         "127.0.0.1")))

(defun %parse-rpc-acl (allow-ip)
  "The RPC ACL for the -rpcallowip specs in ALLOW-IP, or NIL after logging when
one is unparseable. Core seeds the list with 127.0.0.0/8 and ::1 before
appending any -rpcallowip, and aborts startup on the first entry it cannot
parse (InitHTTPAllowList, httpserver.cpp:148-165) — so a successful result is
never empty, and NIL is unambiguously the failure.

Parsing is separated from installing so a later startup failure cannot leave a
half-configured ACL behind — the same reason the credential is installed only
after the socket is bound."
  (let ((subnets '()))
    (dolist (spec allow-ip)
      (let ((subnet (bl.net:parse-subnet spec)))
        (unless subnet
          (bl.log:node-log
           :error "RPC server not started: invalid -rpcallowip subnet ~S. Valid ~
values are a single IP (1.2.3.4), a network/netmask (1.2.3.4/255.255.255.0), a ~
network/CIDR (1.2.3.4/24), all ipv4 (0.0.0.0/0), or all ipv6 (::/0)"
           spec)
          (return-from %parse-rpc-acl nil))
        (push subnet subnets)))
    (append *rpc-loopback-subnets* (nreverse subnets))))

(defun %parse-rpcauth-credentials (rpc-auth)
  "The RPC-CREDENTIALs for the -rpcauth specs in RPC-AUTH, or :INVALID after
logging when one is malformed. Core logs a warning and returns false from
InitRPCAuthentication, which fails StartHTTPRPC (httprpc.cpp:300-301,334-335)
and aborts AppInitServers (init.cpp:756) — a bad -rpcauth stops the node on
both sides.

An empty RPC-AUTH is legitimately an empty list, hence the :INVALID sentinel
rather than NIL. The spec is never logged: it names a user and carries the
password's HMAC."
  (loop for spec in rpc-auth
        for credential = (parse-rpcauth-entry spec)
        unless credential
          do (bl.log:node-log
              :error "RPC server not started: invalid -rpcauth argument. ~
Expected USERNAME:SALT$HMAC as produced by share/rpcauth/rpcauth.py")
             (return :invalid)
        collect credential))

(defun hash-rpc-credential (user password)
  "An RPC-CREDENTIAL for USER/PASSWORD under a fresh random salt. Core hashes
every plaintext credential this way before storing it, with a random 16-byte
hex salt, and keeps the password nowhere else (InitRPCAuthentication,
httprpc.cpp:275-287)."
  (let ((salt (bl.crypto:bytes-to-hex (ironclad:random-data 16))))
    (make-rpc-credential
     user salt
     (%rpcauth-hmac-hex (%credential-bytes salt) (%credential-bytes password)))))

(defgeneric rpc-server-data-directory (node)
  (:documentation "The directory the .cookie credential is written to for NODE,
or NIL when NODE has none (then -rpcuser/-rpcpassword is the only way to
authorize a request). The node above this layer adds the method for its own
struct; the server never names it.")
  (:method (node) (declare (ignore node)) nil))

(defun %install-rpc-credential (node user password rpcauth-credentials)
  "Install every credential check-auth authorizes against and return T, or log
and return NIL when the node would have none at all. As in Core's
InitRPCAuthentication (httprpc.cpp:275-300): the -rpcuser/-rpcpassword pair —
or the .cookie pair when that is absent — is salted, hashed and pushed onto the
same list the -rpcauth entries go on.

Callers must have bound the listening socket first — this writes .cookie, and
.cookie is the live credential of whatever node owns the data directory."
  (flet ((install (pair cookie-path)
           (setf *rpc-credentials* (append pair rpcauth-credentials)
                 *rpc-cookie-path* cookie-path)
           t))
    (if (and user password)
        (install (list (hash-rpc-credential user password)) nil)
        (multiple-value-bind (path secret)
            (let ((data-directory (rpc-server-data-directory node)))
              (if data-directory (generate-rpc-cookie data-directory) (values nil nil)))
          (cond (path
                 (install (list (hash-rpc-credential +rpc-cookie-user+ secret)) path))
                (t
                 (bl.log:node-log
                  :error "RPC server not started: no -rpcuser/-rpcpassword and the ~
.cookie file could not be written, so no request could be authorized")
                 nil))))))

(defun start-rpc-server (node &rest options
                         &key port (bind "127.0.0.1") (bind-supplied-p nil)
                              user password rpc-auth allow-ip
                              rpc-whitelist (rpc-whitelist-default :unset)
                              warmup
                         &allow-other-keys)
  "Start the RPC server.
PORT defaults to 18332 for testnet, 8332 for mainnet.
Every request must carry a credential: the USER/PASSWORD pair when configured,
otherwise the .cookie file generated in the node's data directory. Without
either the server does not start, as Core aborts startup when
InitRPCAuthentication fails (httprpc.cpp:300-302). RPC-AUTH holds -rpcauth
specs, additional USERNAME:SALT$HMAC credentials accepted alongside that pair.
ALLOW-IP holds -rpcallowip specs; loopback is always allowed, and a
non-loopback BIND is honoured only when ALLOW-IP is non-empty.
RPC-WHITELIST holds -rpcwhitelist specs (USERNAME:<method>,...), which restrict
what each named user may call. RPC-WHITELIST-DEFAULT is what a user NOT named
by any of them may call: :UNSET is Core's own default, \"whether any
-rpcwhitelist was given at all\" (GetBoolArg, httprpc.cpp:306), so the first
whitelist locks out every other user until it is whitelisted too.
The remaining keywords belong to the registered HTTP surfaces
(REGISTER-HTTP-SURFACE): :REST-ENABLED to the /rest/ interface (rest.lisp),
:UI-ENABLED and :UI-DIRECTORY to the web UI (ui.lisp). Each surface reads
its own from OPTIONS; an option nobody reads is an error."
  (%check-surface-options options)
  (let ((port (or port (bl.chain:network-rpc-port bl.chain:*network*)))
        (acl nil)
        (rpcauth-credentials nil)
        (whitelist (%parse-rpc-whitelist rpc-whitelist))
        ;; Core: GetBoolArg("-rpcwhitelistdefault", !GetArgs("-rpcwhitelist")
        ;; .empty()) -- the option when it was given, otherwise "a whitelist
        ;; exists" (httprpc.cpp:306).
        (whitelist-default (if (eq rpc-whitelist-default :unset)
                               (and rpc-whitelist t)
                               (and rpc-whitelist-default t))))
    (when *rpc-server*
      (bl.log:node-log :warn "RPC server already running")
      (return-from start-rpc-server nil))
    (setf bind (%rpc-bind-address bind allow-ip bind-supplied-p))

    ;; WARMUP: answer -28 to everything until FINISH-RPC-WARMUP. Set before the
    ;; socket binds, so the very first request a client can make already gets
    ;; the honest answer.
    (when warmup
      (set-rpc-warmup-status (if (stringp warmup) warmup "Loading...")))

    ;; Parse the ACL and the -rpcauth credentials before anything is bound or
    ;; written, so a malformed option is a clean refusal to start (Core
    ;; validates -rpcallowip in InitHTTPServer and -rpcauth in
    ;; InitRPCAuthentication, both of which abort AppInitServers).
    (setf acl (%parse-rpc-acl allow-ip))
    (unless acl (return-from start-rpc-server nil))
    (setf rpcauth-credentials (%parse-rpcauth-credentials rpc-auth))
    (when (eq rpcauth-credentials :invalid)
      (return-from start-rpc-server nil))

    ;; Bind the listening socket BEFORE touching any credential, the order Core
    ;; uses: AppInitServers calls InitHTTPServer (which binds) and only then
    ;; StartHTTPRPC -> InitRPCAuthentication -> GenerateAuthCookie
    ;; (init.cpp:748-761), so a port conflict aborts before .cookie is written.
    ;;
    ;; Generating the cookie first is not a cosmetic difference: a second
    ;; process started on a running node's data directory would overwrite
    ;; .cookie with a secret matching nothing, then fail to bind and exit. The
    ;; healthy node keeps serving with the old secret it holds in memory, so
    ;; bitcoin-cli, the /ui/ SPA and every monitoring script that re-reads the
    ;; file get 401 from a node that is perfectly fine — and the surviving
    ;; process logs nothing, because nothing happened to it. (This has already
    ;; happened here: restart-node.sh's pkill marker did not match the live
    ;; supervisor and left two processes on one data directory.)
    ;;
    ;; Installing the credential after the bind is safe: until
    ;; *rpc-credentials* is set check-auth returns NIL for every header, and the
    ;; dispatchers are pushed last, so nothing can reach the handler at all in
    ;; that window.
    (let ((acceptor nil)
          (listening nil)
          (credential-installed nil)
          (pushed '()))
      (flet ((abort-start ()
               ;; Undo only what THIS attempt did. A failure before the
               ;; credential was installed must leave *rpc-credentials* and
               ;; *rpc-cookie-path* alone: in a second process they are empty,
               ;; and in this one they may belong to a server already running.
               (dolist (d pushed)
                 (setf hunchentoot:*dispatch-table*
                       (remove d hunchentoot:*dispatch-table*)))
               (when pushed
                 (setf *rpc-dispatcher* nil)
                 (%stop-http-surfaces))
               (when listening
                 (handler-case (hunchentoot:stop acceptor) (error () nil)))
               (when credential-installed
                 (delete-rpc-cookie)
                 (setf *rpc-credentials* '() *rpc-cookie-path* nil
                       *rpc-allow-subnets* *rpc-loopback-subnets*)
                 (reset-rpc-whitelist))
               nil))
        (handler-case
            (progn
              (setf acceptor
                    (apply #'make-instance 'rpc-acceptor
                           :port port
                           :address bind
                           ;; -rpcthreads caps concurrent handler threads. The
                           ;; initarg is passed only when configured, so
                           ;; hunchentoot's own default stands otherwise.
                           (append
                            (when *rpc-threads*
                              (list :taskmaster
                                    (make-instance
                                     'hunchentoot:one-thread-per-connection-taskmaster
                                     :max-thread-count *rpc-threads*)))
                            ;; -rpcservertimeout, as INITARGS. This used to
                            ;; SETF hunchentoot:*default-connection-timeout*
                            ;; after the acceptor existed, and the special is
                            ;; only ever read as the read-timeout/write-timeout
                            ;; SLOT INITFORM — so the assignment reached
                            ;; nothing and every RPC connection kept
                            ;; hunchentoot's 20-second idle timeout.
                            ;;
                            ;; Core's functional framework writes
                            ;; rpcservertimeout=99000 into every node's config
                            ;; precisely so a connection survives a long wait.
                            ;; With the option inert, connect_nodes' first
                            ;; poll of the second node came ~50s after that
                            ;; node's last RPC call and died on a broken pipe.
                            ;; A dropped idle connection is invisible until a
                            ;; client stops reconnecting.
                            (list :read-timeout *rpc-server-timeout*
                                  :write-timeout *rpc-server-timeout*)
                            ;; NOTHING to stderr. Hunchentoot defaults both
                            ;; logs there, so a node running normally dribbled
                            ;; an Apache-style access line per RPC call onto
                            ;; stderr — which Core's test framework reads back
                            ;; at EVERY node stop and requires to be empty
                            ;; (test_node.py:502-509), so it would have failed
                            ;; every test that stops a node. Core logs HTTP
                            ;; requests only under -debug=http.
                            (list :access-log-destination nil
                                  :message-log-destination nil))))
              (hunchentoot:start acceptor)
              (setf listening t)

              ;; Bound. Now install the one credential the handler authorizes
              ;; against (Core InitRPCAuthentication, httprpc.cpp:240-288).
              (unless (%install-rpc-credential node user password
                                               rpcauth-credentials)
                (return-from start-rpc-server (abort-start)))
              (setf credential-installed t
                    *rpc-allow-subnets* acl
                    *rpc-whitelist* whitelist
                    *rpc-whitelist-default* whitelist-default)

              ;; Register methods
              (register-all-methods)

              ;; Initialize RPC rate limiter
              (init-rpc-rate-limiter)

              ;; Set globals for handler
              (setf *rpc-node* node)

              ;; Dispatchers go in LAST: pushing them into the global
              ;; hunchentoot:*dispatch-table* is the step that makes requests
              ;; reachable, and a failed start must not leak them (it used to
              ;; leave *rpc-dispatcher* in the table when the bind threw).
              (let ((dispatcher (hunchentoot:create-prefix-dispatcher "/" 'rpc-dispatch-handler)))
                (setf *rpc-dispatcher* dispatcher)
                (push dispatcher pushed)
                (push dispatcher hunchentoot:*dispatch-table*))
              ;; The surfaces the layers above registered (the REST interface,
              ;; the web UI): each goes in FRONT of the "/" dispatcher so it
              ;; matches first, later registrations in front of earlier ones.
              (dolist (surface *http-surfaces*)
                (let ((dispatcher (funcall (http-surface-start surface) options)))
                  (when dispatcher
                    (push dispatcher *surface-dispatchers*)
                    (push dispatcher pushed)
                    (push dispatcher hunchentoot:*dispatch-table*))))

              (setf *rpc-server* acceptor)
              (bl.log:node-log :info "RPC server started on ~A:~A" bind port)
              acceptor)
          (usocket:address-in-use-error ()
            (bl.log:node-log :error "RPC port ~A already in use, continuing without RPC" port)
            (abort-start))
          (error (e)
            (bl.log:node-log :error "Failed to start RPC server: ~A" e)
            (abort-start)))))))

(defun stop-rpc-server ()
  "Stop the RPC server."
  (when *rpc-server*
    (handler-case
        (progn
          (hunchentoot:stop *rpc-server*)
          (bl.log:node-log :info "RPC server stopped"))
      (error (e)
        (bl.log:node-log :warn "Error stopping RPC server: ~A" e)))
    ;; Remove dispatcher from dispatch table to prevent accumulation
    (when *rpc-dispatcher*
      (setf hunchentoot:*dispatch-table*
            (remove *rpc-dispatcher* hunchentoot:*dispatch-table*)))
    (dolist (dispatcher *surface-dispatchers*)
      (setf hunchentoot:*dispatch-table*
            (remove dispatcher hunchentoot:*dispatch-table*)))
    (delete-rpc-cookie)
    (setf *rpc-server* nil)
    (setf *rpc-node* nil)
    (setf *rpc-credentials* '())
    ;; Warmup belongs to a RUNNING server; with none there is nothing to be
    ;; warming up, and leaving it armed would make every later request in this
    ;; image answer -28.
    (setf *rpc-warmup-status* nil)
    (setf *rpc-allow-subnets* *rpc-loopback-subnets*)
    (reset-rpc-whitelist)
    (setf *rpc-dispatcher* nil)
    (%stop-http-surfaces)
    (setf *rpc-rate-limiter* nil)))
