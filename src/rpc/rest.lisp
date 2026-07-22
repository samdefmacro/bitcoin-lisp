(in-package #:bitcoin-lisp.rpc)

;;; Bitcoin Core REST interface (HTTP GET, read-only) — src/rest.cpp.
;;;
;;; Mounted on the same Hunchentoot acceptor as JSON-RPC, under /rest/ —
;;; and, like Core, ONLY when -rest is given (DEFAULT_REST_ENABLE = false,
;;; init.cpp:153; see start-rpc-server's :rest-enabled).
;;; Every endpoint reuses an existing rpc-* method body, so REST and RPC
;;; can never diverge. Content type comes from the URI extension:
;;;   .json -> application/json   .hex -> text/plain   .bin -> octet-stream
;;; An unknown extension is Core's 404 "output format not found".
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
;;;     (BIP64: bitmap + coins; GET-URI input only, no POST body)
;;;
;;; NOT supported (out of scope here): /rest/blockfilter*,
;;; /rest/blockfilterheaders* (BIP157/158), /rest/spenttxouts (needs undo,
;;; pruned away), /rest/deploymentinfo, POST-body getutxos input.

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

(defun %rest-format-not-found (&optional (available ".bin, .hex, .json"))
  "Core's unknown-format response: HTTP 404 \"output format not found
(available: ...)\" (rest.cpp RESTERR(HTTP_NOT_FOUND, ...) default arms)."
  (%rest-error 404 (format nil "output format not found (available: ~A)" available)))

(defmacro %rest-by-ext (ext &key json hex/bin)
  "Branch on a REST extension: evaluate JSON for .json, HEX/BIN for
.hex or .bin, else Core's 404 format-not-found. Centralizes the negotiation
repeated across the hex-capable endpoints."
  (let ((e (gensym "EXT")))
    `(let ((,e ,ext))
       (cond ((string= ,e "json") ,json)
             ((or (string= ,e "hex") (string= ,e "bin")) ,hex/bin)
             (t (%rest-format-not-found))))))

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
      (%rest-format-not-found "json")))

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
    (return-from %rest-mempool (%rest-format-not-found "json")))
  (cond
    ((string= body "info") (%rest-json (rpc-getmempoolinfo node nil)))
    ((string= body "contents") (%rest-json (rpc-getrawmempool node (list t))))
    (t (%rest-error 400 "Expected /rest/mempool/<info|contents>.json"))))

(defconstant +max-getutxos-outpoints+ 15
  "Cap on outpoints per /rest/getutxos query (Core MAX_GETUTXOS_OUTPOINTS,
rest.cpp:43).")

(defun %parse-getutxos-outpoint (op)
  "Parse one <txid>-<n> URI segment into (values txid-bytes vout), or NIL.
Core splits on '-' into EXACTLY two parts, txid via Txid::FromHex, vout via
ToIntegral<uint32_t> (digits only — no sign, no junk; rest.cpp:927-941)."
  (let ((dash (position #\- op)))
    (when (and dash
               (= dash (position #\- op :from-end t)) ; exactly one '-'
               (= dash 64))
      (let ((txid-hex (subseq op 0 dash))
            (vout-str (subseq op (1+ dash))))
        (when (and (valid-hex-hash-p txid-hex)
                   (plusp (length vout-str))
                   (every #'digit-char-p vout-str)
                   (<= (length vout-str) 10))
          (let ((vout (parse-integer vout-str)))
            (when (<= vout #xFFFFFFFF)
              (values (parse-hex-hash txid-hex) vout))))))))

(defun %getutxos-coin (node mempool txid vout)
  "The queried coin for TXID:VOUT, or NIL: the confirmed UTXO set, minus
mempool spends and plus mempool-created outputs when MEMPOOL is non-NIL
(Core's CCoinsViewMemPool + mempool.isSpent path, rest.cpp:1003-1024).
Mempool coins carry +mempool-coin-height+."
  (cond
    ((and mempool (bitcoin-lisp.mempool:mempool-spending-tx mempool txid vout))
     nil)
    (t (or (bitcoin-lisp.storage:get-utxo (rpc-get-utxo-set node) txid vout)
           (and mempool (%mempool-view-coin mempool txid vout))))))

(defun %getutxos-spk-json (spk network)
  "The scriptPubKey object of a getutxos JSON coin (Core ScriptToUniv with
include_hex + include_address)."
  (let ((addr (%script->address spk network)))
    `(("asm" . ,(bitcoin-lisp.validation:disassemble-script spk))
      ("desc" . ,(scriptpubkey-desc spk network))
      ("hex" . ,(bitcoin-lisp.crypto:bytes-to-hex spk))
      ("type" . ,(%script-type spk))
      ,@(when addr `(("address" . ,addr))))))

(defun %getutxos-binary (height tip-hash hits coins)
  "The BIP64 binary response body (Core rest.cpp:1034-1043): u32 LE chain
height, 32-byte tip hash (internal order), CompactSize+bitmap (LSB-first
bit per outpoint), CompactSize(coin count) then per hit coin the CCoin wire
form (rest.cpp:56-68): u32 dummy version 0, u32 LE height, i64 LE value,
CompactSize+scriptPubKey."
  (let ((bb (bitcoin-lisp.serialization:make-byte-buf))
        (bitmap (make-array (ceiling (length hits) 8)
                            :element-type '(unsigned-byte 8) :initial-element 0)))
    (loop for hit in hits
          for i from 0
          when hit
            do (setf (aref bitmap (floor i 8))
                     (logior (aref bitmap (floor i 8)) (ash 1 (mod i 8)))))
    (bitcoin-lisp.serialization:bb-write-u32-le bb height)
    (bitcoin-lisp.serialization:bb-write-bytes bb tip-hash)
    (bitcoin-lisp.serialization:bb-write-varint bb (length bitmap))
    (bitcoin-lisp.serialization:bb-write-bytes bb bitmap)
    (bitcoin-lisp.serialization:bb-write-varint bb (length coins))
    (dolist (coin coins)
      (bitcoin-lisp.serialization:bb-write-u32-le bb 0) ; nTxVerDummy
      (bitcoin-lisp.serialization:bb-write-u32-le
       bb (bitcoin-lisp.storage:utxo-entry-height coin))
      (bitcoin-lisp.serialization:bb-write-i64-le
       bb (bitcoin-lisp.storage:utxo-entry-value coin))
      (let ((spk (bitcoin-lisp.storage:utxo-entry-script-pubkey coin)))
        (bitcoin-lisp.serialization:bb-write-varint bb (length spk))
        (bitcoin-lisp.serialization:bb-write-bytes bb spk)))
    (bitcoin-lisp.serialization:bb-finish bb)))

(defun %rest-getutxos (node body ext)
  "BIP64 /rest/getutxos[/checkmempool]/<txid>-<n>/... (Core rest.cpp:
896-1088): query up to 15 outpoints against the UTXO set, optionally
overlaid with the mempool. .json emits {chainHeight, chaintipHash, bitmap
(a string of 0/1 per outpoint), utxos:[{height, value, scriptPubKey}]};
.bin/.hex emit the BIP64 binary form. POST-body input is not supported —
outpoints come from the URI."
  (unless (member ext '("json" "bin" "hex") :test #'string=)
    (return-from %rest-getutxos (%rest-format-not-found)))
  (let* ((segments (remove "" (uiop:split-string body :separator "/") :test #'string=))
         (check-mempool (and segments (string= (first segments) "checkmempool")))
         (outpoint-strs (if check-mempool (rest segments) segments))
         (outpoints '()))
    (when (null outpoint-strs)
      (return-from %rest-getutxos (%rest-error 400 "Error: empty request")))
    (dolist (op outpoint-strs)
      (multiple-value-bind (txid vout) (%parse-getutxos-outpoint op)
        (unless txid
          (return-from %rest-getutxos (%rest-error 400 "Parse error")))
        (push (cons txid vout) outpoints)))
    (setf outpoints (nreverse outpoints))
    (when (> (length outpoints) +max-getutxos-outpoints+)
      (return-from %rest-getutxos
        (%rest-error 400 (format nil "Error: max outpoints exceeded (max: ~D, tried: ~D)"
                                 +max-getutxos-outpoints+ (length outpoints)))))
    ;; One consistent snapshot of tip + coins (+ mempool when checkmempool),
    ;; like Core's LOCK2(cs_main, mempool.cs) around process_utxos.
    (multiple-value-bind (height tip-hash hits coins)
        (with-node-lock (node)
          (let* ((chain-state (rpc-get-chain-state node))
                 (mempool (and check-mempool (rpc-get-mempool node)))
                 (hits '())
                 (coins '()))
            (dolist (op outpoints)
              (let ((coin (%getutxos-coin node mempool (car op) (cdr op))))
                (push (and coin t) hits)
                (when coin (push coin coins))))
            (values (bitcoin-lisp.storage:current-height chain-state)
                    ;; A tipless (fresh) chainstate reports the zero hash —
                    ;; Core always has genesis, so this only affects tests.
                    (or (bitcoin-lisp.storage:best-block-hash chain-state)
                        (make-array 32 :element-type '(unsigned-byte 8)
                                       :initial-element 0))
                    (nreverse hits)
                    (nreverse coins))))
      (cond
        ((string= ext "json")
         (let ((network (rpc-get-network node)))
           (%rest-json
            `(("chainHeight" . ,height)
              ("chaintipHash" . ,(hash-to-hex tip-hash))
              ("bitmap" . ,(map 'string (lambda (h) (if h #\1 #\0)) hits))
              ("utxos" . ,(mapcar
                           (lambda (coin)
                             `(("height" . ,(bitcoin-lisp.storage:utxo-entry-height coin))
                               ("value" . ,(/ (bitcoin-lisp.storage:utxo-entry-value coin)
                                              100000000.0d0))
                               ("scriptPubKey"
                                . ,(%getutxos-spk-json
                                    (bitcoin-lisp.storage:utxo-entry-script-pubkey coin)
                                    network))))
                           coins))))))
        (t
         (%rest-hex-or-bin
          ext (bitcoin-lisp.crypto:bytes-to-hex
               (%getutxos-binary height tip-hash hits coins))))))))

;;; --- Liveness probe (bitcoin-lisp extension, not a Core REST endpoint) ---

(defun %rest-health (node)
  "Unauthenticated liveness probe. HTTP 200 iff the node's sync thread is alive
AND the active chain tip advanced within the staleness threshold; else HTTP
503. Body: {\"status\", \"seconds_since_tip\", \"synced\"}. The underlying
node-tip-liveness read is lock-free and side-effect-free, so the probe stays
responsive (and correctly reports 503) even when the node is wedged."
  (multiple-value-bind (healthy seconds-since-tip synced)
      (bitcoin-lisp::node-tip-liveness node)
    (%rest-respond (if healthy 200 503)
                   "application/json"
                   (with-output-to-string (s)
                     (yason:encode
                      (rpc-result->json
                       `(("status" . ,(if healthy "ok" "unhealthy"))
                         ("seconds_since_tip" . ,seconds-since-tip)
                         ("synced" . ,(json-bool synced))))
                      s)))))

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
        ;; Unauthenticated liveness probe (bitcoin-lisp extension, not Core):
        ;; /rest/health or /rest/health.json.
        ((or (string= rest "health") (string= rest "health.json"))
         (%rest-health node))
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
