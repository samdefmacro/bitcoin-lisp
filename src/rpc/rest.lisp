(in-package #:bitcoin-lisp.rpc)

;;; Bitcoin Core REST interface (HTTP GET, read-only) — src/rest.cpp.
;;;
;;; Mounted on the same Hunchentoot acceptor as JSON-RPC, under /rest/.
;;; Every endpoint reuses an existing rpc-* method body, so REST and RPC
;;; can never diverge. Content type comes from the URI extension:
;;;   .json -> application/json   .hex -> text/plain   .bin -> octet-stream
;;;
;;; Supported (the node-level, no-wallet subset):
;;;   /rest/chaininfo.json
;;;   /rest/blockhashbyheight/<height>.<json|hex|bin>
;;;   /rest/block/<hash>.<json|hex|bin>
;;;   /rest/block/notxdetails/<hash>.json
;;;   /rest/tx/<txid>.<json|hex|bin>
;;;   /rest/headers/<hash>.<json|hex|bin>?count=<n>   (default 5, max 2000)
;;;   /rest/mempool/info.json
;;;   /rest/mempool/contents.json
;;;   /rest/getutxos[/checkmempool]/<txid>-<n>/...  .<json|hex|bin>
;;;
;;; NOT supported (out of scope here): /rest/blockfilter*,
;;; /rest/blockfilterheaders* (BIP157/158), /rest/spenttxouts (needs undo,
;;; pruned away), /rest/deploymentinfo.

(defconstant +rest-max-headers+ 2000
  "Cap on headers returned by /rest/headers, matching Core's MAX_REST_HEADERS.")

(defun %rest-respond (status content-type body)
  "Set HTTP STATUS + CONTENT-TYPE and return BODY (string or octet-vector)."
  (setf (hunchentoot:return-code*) status
        (hunchentoot:content-type*) content-type)
  body)

(defun %rest-error (status message)
  "Plain-text error, mirroring Core's RESTERR."
  (%rest-respond status "text/plain"
                 (format nil "~A~%" message)))

(defun %rest-json (alist-or-value)
  "Encode an RPC-shaped result as a JSON string (200 application/json)."
  (%rest-respond 200 "application/json"
                 (with-output-to-string (s)
                   (yason:encode (rpc-result->json alist-or-value) s))))

(defun %rest-split-ext (path)
  "Split PATH at its final dot into (values body extension), or
(values path nil) if there is no extension."
  (let ((dot (position #\. path :from-end t)))
    (if dot
        (values (subseq path 0 dot) (subseq path (1+ dot)))
        (values path nil))))

(defmacro %rest-by-ext (ext &key json hex/bin)
  "Branch on a REST extension: evaluate JSON for .json, HEX/BIN for
.hex or .bin, else a 400. Centralizes the negotiation repeated across
the hex-capable endpoints."
  (let ((e (gensym "EXT")))
    `(let ((,e ,ext))
       (cond ((string= ,e "json") ,json)
             ((or (string= ,e "hex") (string= ,e "bin")) ,hex/bin)
             (t (%rest-error 400 "Unsupported extension"))))))

(defun %rest-hex-or-bin (ext hex)
  "Render a hex payload for a .hex (string + newline) or .bin (bytes)
response. Caller has already validated EXT is one of those."
  (if (string= ext "bin")
      (%rest-respond 200 "application/octet-stream"
                     (bitcoin-lisp.crypto:hex-to-bytes hex))
      (%rest-respond 200 "text/plain" (format nil "~A~%" hex))))

;;; --- Endpoint handlers. Each takes the path remainder after the route
;;;     prefix, already split into (body . ext), plus the node. ---

(defun %rest-chaininfo (node body ext)
  (declare (ignore body))
  (if (string= ext "json")
      (%rest-json (rpc-getblockchaininfo node nil))
      (%rest-error 400 "chaininfo: only .json is supported")))

(defun %rest-blockhashbyheight (node body ext)
  (let ((height (parse-integer body :junk-allowed t)))
    (unless (and height (>= height 0))
      (return-from %rest-blockhashbyheight (%rest-error 400 "Invalid height")))
    (let ((hash-hex (handler-case (rpc-getblockhash node (list height))
                      (rpc-error () nil))))
      (unless hash-hex
        (return-from %rest-blockhashbyheight (%rest-error 404 "Block not found")))
      (%rest-by-ext ext
        :json (%rest-json `(("blockhash" . ,hash-hex)))
        :hex/bin (%rest-hex-or-bin ext hash-hex)))))

(defun %rest-block (node body ext &key notxdetails)
  (unless (valid-hex-hash-p body)
    (return-from %rest-block (%rest-error 400 "Invalid block hash")))
  (handler-case
      (%rest-by-ext ext
        :json (%rest-json (rpc-getblock node (list body (if notxdetails 1 2))))
        :hex/bin (%rest-hex-or-bin ext (rpc-getblock node (list body 0))))
    (rpc-error () (%rest-error 404 "Block not found"))))

(defun %rest-tx (node body ext)
  (unless (valid-hex-hash-p body)
    (return-from %rest-tx (%rest-error 400 "Invalid txid")))
  (handler-case
      (%rest-by-ext ext
        :json (%rest-json (rpc-getrawtransaction node (list body t)))
        :hex/bin (%rest-hex-or-bin ext (rpc-getrawtransaction node (list body nil))))
    (rpc-error () (%rest-error 404 "Transaction not found (mempool/txindex only on a pruned node)"))))

(defun %rest-headers (node body ext)
  "Up to COUNT headers starting at BODY (a block hash), walking forward on
the active chain — Core's /rest/headers/<hash>?count=<n>."
  (unless (valid-hex-hash-p body)
    (return-from %rest-headers (%rest-error 400 "Invalid block hash")))
  (let* ((count (let ((q (hunchentoot:get-parameter "count")))
                  (or (and q (parse-integer q :junk-allowed t)) 5)))
         (chain-state (rpc-get-chain-state node))
         (start (bitcoin-lisp.storage:get-block-index-entry
                 chain-state (parse-hex-hash body))))
    (when (or (< count 1) (> count +rest-max-headers+))
      (return-from %rest-headers (%rest-error 400 "Invalid count")))
    (unless start
      (return-from %rest-headers (%rest-error 404 "Block not found")))
    ;; Walk forward via active-chain successors by height.
    (let ((entries
            (loop with h = (bitcoin-lisp.storage:block-index-entry-height start)
                  for i from 0 below count
                  for e = start then (bitcoin-lisp.storage:get-block-at-height
                                      chain-state (+ h i))
                  while e collect e)))
      (%rest-by-ext ext
        :json (%rest-json (mapcar (lambda (e)
                                    (block-header-entry-to-json
                                     e (hash-to-hex (bitcoin-lisp.storage:block-index-entry-hash e))
                                     chain-state))
                                  entries))
        :hex/bin (let ((bb (bitcoin-lisp.serialization:make-byte-buf)))
                   (dolist (e entries)
                     (bitcoin-lisp.serialization:bb-write-bytes
                      bb (bitcoin-lisp.serialization:serialize-block-header
                          (bitcoin-lisp.storage:block-index-entry-header e))))
                   (%rest-hex-or-bin
                    ext (bitcoin-lisp.crypto:bytes-to-hex
                         (bitcoin-lisp.serialization:bb-finish bb))))))))

(defun %rest-mempool (node body ext)
  (unless (string= ext "json")
    (return-from %rest-mempool (%rest-error 400 "mempool: only .json is supported")))
  (cond
    ((string= body "info") (%rest-json (rpc-getmempoolinfo node nil)))
    ((string= body "contents") (%rest-json (rpc-getrawmempool node (list t))))
    (t (%rest-error 400 "Expected /rest/mempool/<info|contents>.json"))))

(defun %rest-getutxos (node body ext)
  "Core /rest/getutxos[/checkmempool]/<txid>-<n>/... — query unspent
outputs. BODY is the path after getutxos/, the outpoints slash-separated
as txid-vout. Returns each requested outpoint's coin (or absence)."
  (let* ((segments (remove "" (uiop:split-string body :separator "/") :test #'string=))
         (check-mempool (and segments (string= (first segments) "checkmempool")))
         (outpoint-strs (if check-mempool (rest segments) segments))
         (results '()))
    (declare (ignore check-mempool))   ; relay disabled here; confirmed set only
    (when (null outpoint-strs)
      (return-from %rest-getutxos (%rest-error 400 "No outpoints given")))
    (dolist (op outpoint-strs)
      (let* ((dash (position #\- op :from-end t))
             (txid (and dash (subseq op 0 dash)))
             (vout (and dash (parse-integer op :start (1+ dash) :junk-allowed t))))
        (unless (and txid vout (valid-hex-hash-p txid))
          (return-from %rest-getutxos (%rest-error 400 (format nil "Bad outpoint ~A" op))))
        ;; gettxout returns NIL (absent) or the coin alist.
        (let ((coin (handler-case (rpc-gettxout node (list txid vout))
                      (rpc-error () nil))))
          (push `(("txid" . ,txid) ("vout" . ,vout)
                  ("found" . ,(and coin t))
                  ,@(when coin `(("utxo" . ,coin))))
                results))))
    (let ((chain-state (rpc-get-chain-state node)))
      (if (string= ext "json")
          (%rest-json `(("chainHeight" . ,(bitcoin-lisp.storage:current-height chain-state))
                        ("utxos" . ,(nreverse results))))
          (%rest-error 400 "getutxos: only .json is supported")))))

;;; --- Router ---

(defun rest-handle (node uri)
  "Route a /rest/... URI (script-name, query already stripped by Hunchentoot)
to its handler. Returns the response body; sets status/content-type."
  (let ((rest (cond ((alexandria:starts-with-subseq "/rest/" uri) (subseq uri 6))
                    (t (return-from rest-handle (%rest-error 400 "Not a /rest/ path"))))))
    (flet ((after (prefix) (subseq rest (length prefix))))
      (cond
        ((alexandria:starts-with-subseq "chaininfo" rest)
         (multiple-value-bind (b e) (%rest-split-ext rest) (%rest-chaininfo node b e)))
        ((alexandria:starts-with-subseq "blockhashbyheight/" rest)
         (multiple-value-bind (b e) (%rest-split-ext (after "blockhashbyheight/"))
           (%rest-blockhashbyheight node b e)))
        ;; notxdetails must precede the bare "block/" prefix below.
        ((alexandria:starts-with-subseq "block/notxdetails/" rest)
         (multiple-value-bind (b e) (%rest-split-ext (after "block/notxdetails/"))
           (%rest-block node b e :notxdetails t)))
        ((alexandria:starts-with-subseq "block/" rest)
         (multiple-value-bind (b e) (%rest-split-ext (after "block/"))
           (%rest-block node b e)))
        ((alexandria:starts-with-subseq "tx/" rest)
         (multiple-value-bind (b e) (%rest-split-ext (after "tx/"))
           (%rest-tx node b e)))
        ((alexandria:starts-with-subseq "headers/" rest)
         (multiple-value-bind (b e) (%rest-split-ext (after "headers/"))
           (%rest-headers node b e)))
        ((alexandria:starts-with-subseq "mempool/" rest)
         (multiple-value-bind (b e) (%rest-split-ext (after "mempool/"))
           (%rest-mempool node b e)))
        ((alexandria:starts-with-subseq "getutxos/" rest)
         (multiple-value-bind (b e) (%rest-split-ext (after "getutxos/"))
           (%rest-getutxos node b e)))
        (t (%rest-error 404 "Unknown REST endpoint"))))))

(defun rest-dispatch-handler ()
  "Hunchentoot handler for /rest/* — GET only."
  (if (eq (hunchentoot:request-method*) :get)
      (handler-case (rest-handle *rpc-node* (hunchentoot:script-name*))
        (error (e)
          (bitcoin-lisp::node-log :error "REST handler error: ~A" e)
          (%rest-error 500 "Internal error")))
      (progn
        (setf (hunchentoot:return-code*) hunchentoot:+http-method-not-allowed+)
        "")))
