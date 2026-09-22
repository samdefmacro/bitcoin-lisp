(in-package #:bitcoin-lisp.rpc)

;;; Bitcoin Core REST interface (HTTP GET and POST, read-only) — src/rest.cpp.
;;;
;;; Mounted on the same Hunchentoot acceptor as JSON-RPC, under /rest/ —
;;; and, like Core, ONLY when -rest is given (DEFAULT_REST_ENABLE = false,
;;; init.cpp:153; see the :rest surface at the end of this file).
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
;;;   /rest/blockpart/<hash>.<hex|bin>?offset=<n>&size=<n>
;;;   /rest/tx/<txid>.<json|hex|bin>
;;;   /rest/headers/<hash>.<json|hex|bin>?count=<n>   (default 5, max 2000)
;;;   /rest/mempool/info.json
;;;   /rest/mempool/contents.json?verbose=<bool>&mempool_sequence=<bool>
;;;   /rest/getutxos[/checkmempool]/<txid>-<n>/...  .<json|hex|bin>
;;;     (BIP64: bitmap + coins; outpoints from the URI, or from a POSTed
;;;      binary/hex body for .bin and .hex)
;;;   /rest/deploymentinfo[/<hash>].json
;;;   /rest/blockfilter/<filtertype>/<hash>.<json|hex|bin>
;;;   /rest/blockfilterheaders/<filtertype>/<hash>.<json|hex|bin>?count=<n>
;;;   /rest/spenttxouts/<hash>.<json|hex|bin>
;;;

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

(defun %rest-bad-count-message (raw-count)
  "Core's message for an out-of-range `count' query parameter
(rest.cpp:207-209, :525-527): the accepted range and the value as it arrived,
not a bare `Invalid count'."
  (format nil "Header count is invalid or out of acceptable range (1-~D): ~A"
          +rest-max-headers+ raw-count))

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
                     (bl.crypto:hex-to-bytes hex))
      (%rest-respond 200 "text/plain" (format nil "~A~%" hex))))

;;; --- Endpoint handlers. Each takes the path remainder after the route
;;;     prefix, already split into (body . ext), plus the node. ---

(defun %rest-chaininfo (node body ext)
  (declare (ignore body))
  (if (string= ext "json")
      (%rest-json (rpc-getblockchaininfo node nil))
      (%rest-format-not-found "json")))

(defun %rest-parse-height (text)
  "TEXT as Core's ToIntegral<int32_t> reads it (util/strencodings.h:
std::from_chars over the whole string): an optional minus sign and decimal
digits, nothing else -- no `+', no whitespace, no trailing junk -- and inside
int32 range. NIL otherwise."
  (let* ((digits (if (and (plusp (length text)) (char= (char text 0) #\-))
                     (subseq text 1)
                     text)))
    (when (and (plusp (length digits)) (every #'digit-char-p digits))
      (let ((value (parse-integer text)))
        (when (<= (- (expt 2 31)) value (1- (expt 2 31)))
          value)))))

(defun %rest-blockhashbyheight (node body ext)
  "/rest/blockhashbyheight/<height> (Core rest_blockhash_by_height,
rest.cpp:1017-1058). The .bin answer is the hash as it is serialized -- the
uint256 streamed in internal byte order (`ss_blockhash << GetBlockHash()') --
while .hex and .json carry GetHex's display order, the byte reverse of it;
interface_rest.py:270-272 reverses the .bin bytes to compare them."
  (let ((height (%rest-parse-height body)))
    (unless (and height (>= height 0))
      (return-from %rest-blockhashbyheight
        (%rest-error 400 (format nil "Invalid height: ~A" body))))
    (let ((hash-hex (handler-case (rpc-getblockhash node (list height))
                      (rpc-error () nil))))
      (unless hash-hex
        (return-from %rest-blockhashbyheight
          (%rest-error 404 "Block height out of range")))
      (%rest-by-ext ext
        :json (%rest-json `(("blockhash" . ,hash-hex)))
        :hex/bin (if (string= ext "bin")
                     (%rest-respond 200 "application/octet-stream"
                                    (bl.crypto:reverse-bytes
                                     (bl.crypto:hex-to-bytes hash-hex)))
                     (%rest-hex-or-bin ext hash-hex))))))

(defun %rest-block (node body ext &key notxdetails)
  "/rest/block/<hash> and /rest/block/notxdetails/<hash>.

The JSON verbosities are Core's TxVerbosity, not getblock's defaults:
rest_block_extended passes SHOW_DETAILS_AND_PREVOUT (rest.cpp:470-473), which
getblock reaches only at verbosity 3 (rpc/blockchain.cpp:867-874) and which
gives every non-coinbase vin its `prevout` object, while
rest_block_notxdetails passes SHOW_TXID, i.e. verbosity 1. Serving verbosity 2
here answered without any prevout, so a block explorer had to fetch every
spent output itself."
  (unless (valid-hex-hash-p body)
    (return-from %rest-block (%rest-error 400 (format nil "Invalid hash: ~A" body))))
  (handler-case
      (%rest-by-ext ext
        :json (%rest-json (rpc-getblock node (list body (if notxdetails 1 3))))
        :hex/bin (%rest-hex-or-bin ext (rpc-getblock node (list body 0))))
    (rpc-error () (%rest-error 404 (format nil "~A not found" body)))))

(defun %rest-tx (node body ext)
  (unless (valid-hex-hash-p body)
    (return-from %rest-tx (%rest-error 400 (format nil "Invalid hash: ~A" body))))
  (handler-case
      (%rest-by-ext ext
        :json (%rest-json (rpc-getrawtransaction node (list body t)))
        :hex/bin (%rest-hex-or-bin ext (rpc-getrawtransaction node (list body nil))))
    (rpc-error () (%rest-error 404 (format nil "~A not found" body)))))

(defun %rest-headers (node body ext)
  "Up to COUNT headers starting at BODY (a block hash), walking forward on
the active chain — Core's /rest/headers/<hash>?count=<n> (rest.cpp:225-233).

The start block must itself be ON the active chain: Core's loop is
`while (pindex && active_chain.Contains(pindex)) { ...; pindex =
active_chain.Next(pindex); }`, so a fork header yields an EMPTY result and
the returned chain is contiguous by construction. We walk forward by
ABSOLUTE HEIGHT via get-block-at-height, which descends from the ACTIVE tip,
so without that gate a fork header at height H was spliced onto the ACTIVE
chain's H+1, H+2, ... and headers[1].previousblockhash did not match
headers[0].hash. Once the start is on the active chain every successor is
too, which is what makes the single check sufficient.

An UNKNOWN hash is 200 with an empty result, not a 404: Core's
LookupBlockIndex answers nullptr, the loop never runs, and the empty header
vector is written with HTTP_OK. There is no error path for it in rest_headers
at all -- the only 404s that endpoint has are for a MISSING BLOCK BODY, which
headers do not need. This used to be a deliberate divergence here (\"an
existing client may rely on it\"), which made a well-formed unknown hash and
a fork header answer differently for the same non-answer;
interface_rest.py:231 asks for the unknown hash and compares against []."
  (unless (valid-hex-hash-p body)
    (return-from %rest-headers (%rest-error 400 (format nil "Invalid hash: ~A" body))))
  (let* ((raw-count (or (hunchentoot:get-parameter "count") "5"))
         (count (parse-integer raw-count :junk-allowed t))
         (chain-state (rpc-get-chain-state node))
         (start (bl.store:get-block-index-entry
                 chain-state (parse-hex-hash body))))
    (when (or (null count) (< count 1) (> count +rest-max-headers+))
      (return-from %rest-headers (%rest-error 400 (%rest-bad-count-message raw-count))))
    ;; Walk forward via active-chain successors by height.
    (let ((entries
            (when (and start
                       (bl.store:entry-on-active-chain-p chain-state start))
              (loop with h = (bl.store:block-index-entry-height start)
                    for i from 0 below count
                    for e = start then (bl.store:get-block-at-height
                                        chain-state (+ h i))
                    while e collect e))))
      (%rest-by-ext ext
        :json (%rest-json (json-array
                           (mapcar (lambda (e)
                                     (block-header-entry-to-json
                                      e (hash-to-hex (bl.store:block-index-entry-hash e))
                                      chain-state (rpc-get-block-store node)))
                                   entries)))
        :hex/bin (let ((bb (bl.ser:make-byte-buf)))
                   (dolist (e entries)
                     (bl.ser:bb-write-bytes
                      bb (bl.ser:serialize-block-header
                          (bl.store:block-index-entry-header e))))
                   (%rest-hex-or-bin
                    ext (bl.crypto:bytes-to-hex
                         (bl.ser:bb-finish bb))))))))

(defun %rest-bool-parameter (name default)
  "One of Core's rest_mempool query flags (rest.cpp:804-820). The parameter
must be the literal string \"true\" or \"false\"; DEFAULT stands in when it
is absent. Returns (values flag message) -- MESSAGE is Core's 400 text and is
NIL when the parameter parsed, so a caller cannot mistake a refused parameter
for a false one."
  (let ((raw (or (hunchentoot:get-parameter name) default)))
    (cond ((string= raw "true") (values t nil))
          ((string= raw "false") (values nil nil))
          (t (values nil
                     (format nil "The \"~A\" query parameter must be either ~
\"true\" or \"false\"." name))))))

(defun %rest-mempool-contents (node)
  "/rest/mempool/contents.json?verbose=<bool>&mempool_sequence=<bool> --
Core's rest_mempool contents arm (rest.cpp:802-825).

Both flags reach GETRAWMEMPOOL, which is our MempoolToJSON: Core's REST and
RPC surfaces call that one function with the same two booleans, so the shapes
cannot diverge. verbose defaults to true and mempool_sequence to false, and
the pair is refused, because a verbose result is keyed by txid and has nowhere
to carry the sequence."
  (multiple-value-bind (verbose verbose-message)
      (%rest-bool-parameter "verbose" "true")
    (multiple-value-bind (sequence sequence-message)
        (%rest-bool-parameter "mempool_sequence" "false")
      (cond
        ;; Core validates verbose first, so its message wins when both are bad.
        ((or verbose-message sequence-message)
         (%rest-error 400 (or verbose-message sequence-message)))
        ((and verbose sequence)
         ;; FORMAT, not a bare literal: a tilde-newline continues a format
         ;; CONTROL string, and %REST-ERROR passes its message through ~A.
         (%rest-error 400 (format nil "Verbose results cannot contain mempool ~
sequence values. (hint: set \"verbose=false\")")))
        (t (%rest-json (rpc-getrawmempool node (list verbose sequence))))))))

(defun %rest-mempool (node body ext)
  (unless (string= ext "json")
    (return-from %rest-mempool (%rest-format-not-found "json")))
  (cond
    ((string= body "info") (%rest-json (rpc-getmempoolinfo node nil)))
    ((string= body "contents") (%rest-mempool-contents node))
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
    ((and mempool (bl.mp:mempool-spending-tx mempool txid vout))
     nil)
    (t (or (bl.store:get-utxo (rpc-get-utxo-set node) txid vout)
           (and mempool (%mempool-view-coin mempool txid vout))))))

(defun %getutxos-binary (height tip-hash hits coins)
  "The BIP64 binary response body (Core rest.cpp:1034-1043): u32 LE chain
height, 32-byte tip hash (internal order), CompactSize+bitmap (LSB-first
bit per outpoint), CompactSize(coin count) then per hit coin the CCoin wire
form (rest.cpp:56-68): u32 dummy version 0, u32 LE height, i64 LE value,
CompactSize+scriptPubKey."
  (let ((bb (bl.ser:make-byte-buf))
        (bitmap (make-array (ceiling (length hits) 8)
                            :element-type '(unsigned-byte 8) :initial-element 0)))
    (loop for hit in hits
          for i from 0
          when hit
            do (setf (aref bitmap (floor i 8))
                     (logior (aref bitmap (floor i 8)) (ash 1 (mod i 8)))))
    (bl.ser:bb-write-u32-le bb height)
    (bl.ser:bb-write-bytes bb tip-hash)
    (bl.ser:bb-write-varint bb (length bitmap))
    (bl.ser:bb-write-bytes bb bitmap)
    (bl.ser:bb-write-varint bb (length coins))
    (dolist (coin coins)
      (bl.ser:bb-write-u32-le bb 0) ; nTxVerDummy
      (bl.ser:bb-write-u32-le
       bb (bl.store:utxo-entry-height coin))
      (bl.ser:bb-write-i64-le
       bb (bl.store:utxo-entry-value coin))
      (let ((spk (bl.store:utxo-entry-script-pubkey coin)))
        (bl.ser:bb-write-varint bb (length spk))
        (bl.ser:bb-write-bytes bb spk)))
    (bl.ser:bb-finish bb)))

(defun %parse-getutxos-post-body (bytes)
  "The BIP64 request body: a one-byte checkmempool flag, then a CompactSize
count and that many 32-byte txid + u32-LE index outpoints (Core reads
`oss >> fCheckMemPool; oss >> vOutPoints', rest.cpp:967-968). Returns
(values T check-mempool outpoints), or NIL as the first value when the bytes
do not read -- Core's own ios_base::failure, which it answers as \"Parse
error\". A well-formed body asking for NOTHING is a success with no outpoints,
which is why the flag is a separate value.

The count is not capped here: Core deserializes the whole vector and applies
MAX_GETUTXOS_OUTPOINTS afterwards, and a count the body cannot hold fails on
the first read past its end."
  (handler-case
      (let* ((br (bl.ser:make-byte-reader-from bytes))
             (check-mempool (bl.ser:br-read-bool br))
             (outpoints '()))
        (dotimes (i (bl.ser:br-read-compact-size br))
          (declare (ignore i))
          (let ((txid (bl.ser:br-read-bytes br 32)))
            (push (cons txid (bl.ser:br-read-u32-le br)) outpoints)))
        (values t check-mempool (nreverse outpoints)))
    (error () nil)))

(defun %getutxos-request (body ext post-body)
  "What a /rest/getutxos call is asking for, as (VALUES CHECK-MEMPOOL OUTPOINTS
REFUSAL) -- a non-NIL REFUSAL being the response to send instead (Core
rest.cpp:905-1000, which reads the request in this order).

The outpoints come from the URI or, for .bin and .hex, from POST-BODY -- the
binary request form BIP64 specifies, which Core reads with the SAME handler
(:967-968) and which interface_rest.py:167 sends. Giving both is Core's
\"Combination of URI scheme inputs and raw post data is not allowed\"; .json
has no body form at all, so a bodyless .json is Core's empty request."
  (let* ((segments (remove "" (uiop:split-string body :separator "/") :test #'string=))
         (check-mempool (and segments (string= (first segments) "checkmempool")))
         (outpoint-strs (if check-mempool (rest segments) segments))
         ;; Core's `fInputParsed': outpoints came from the URI. A bare
         ;; /checkmempool with no outpoint is an empty request, below.
         (uri-input nil)
         (outpoints '()))
    (macrolet ((refuse (&rest args)
                 `(return-from %getutxos-request
                    (values nil nil (%rest-error ,@args)))))
      ;; Core rest.cpp:913-914: no body AND no URI parts at all.
      (when (and (null segments) (null post-body))
        (refuse 400 "Error: empty request"))
      (when segments
        (when (null outpoint-strs) (refuse 400 "Error: empty request"))
        (dolist (op outpoint-strs)
          (multiple-value-bind (txid vout) (%parse-getutxos-outpoint op)
            (unless txid (refuse 400 "Parse error"))
            (push (cons txid vout) outpoints)))
        (setf outpoints (nreverse outpoints)
              uri-input t))
      (if (string= ext "json")
          ;; Core's JSON arm accepts URI input only (:978-981).
          (unless uri-input (refuse 400 "Error: empty request"))
          ;; .hex delivers the same bytes in hex; an unreadable hex body becomes
          ;; the empty body, as Core's ParseHex does (:949-953).
          (let ((bytes (if (string= ext "hex")
                           (ignore-errors
                            (bl.crypto:hex-to-bytes
                             (string-trim '(#\Space #\Newline #\Return #\Tab)
                                          (map 'string #'code-char post-body))))
                           post-body)))
            (when (plusp (length bytes))
              (when uri-input
                (refuse 400 "Combination of URI scheme inputs and raw post data is not allowed"))
              (multiple-value-bind (ok body-check-mempool body-outpoints)
                  (%parse-getutxos-post-body bytes)
                (unless ok (refuse 400 "Parse error"))
                (setf check-mempool body-check-mempool
                      outpoints body-outpoints)))))
      (when (> (length outpoints) +max-getutxos-outpoints+)
        (refuse 400 (format nil "Error: max outpoints exceeded (max: ~D, tried: ~D)"
                            +max-getutxos-outpoints+ (length outpoints))))
      (values check-mempool outpoints nil))))

(defun %rest-getutxos (node body ext &optional post-body)
  "BIP64 /rest/getutxos[/checkmempool]/<txid>-<n>/... (Core rest.cpp:
896-1088): query up to 15 outpoints against the UTXO set, optionally
overlaid with the mempool. .json emits {chainHeight, chaintipHash, bitmap
(a string of 0/1 per outpoint), utxos:[{height, value, scriptPubKey}]};
.bin/.hex emit the BIP64 binary form. %GETUTXOS-REQUEST reads the request,
from the URI or the POSTed body."
  (unless (member ext '("json" "bin" "hex") :test #'string=)
    (return-from %rest-getutxos (%rest-format-not-found)))
  (multiple-value-bind (check-mempool outpoints refusal)
      (%getutxos-request body ext post-body)
    (when refusal (return-from %rest-getutxos refusal))
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
            (values (bl.store:current-height chain-state)
                    ;; A tipless (fresh) chainstate reports the zero hash —
                    ;; Core always has genesis, so this only affects tests.
                    (or (bl.store:best-block-hash chain-state)
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
              ;; An EMPTY list must encode as [], not null: NIL is JSON null,
              ;; and a query whose every outpoint is spent has no utxos at all
              ;; -- interface_rest.py:148 takes len() of this field.
              ("utxos" . ,(or (mapcar
                               (lambda (coin)
                                 `(("height" . ,(bl.store:utxo-entry-height coin))
                                   ("value" . ,(satoshi->btc (bl.store:utxo-entry-value coin)))
                                   ;; Core ScriptToUniv with include_hex and
                                   ;; include_address (rest.cpp:1072).
                                   ("scriptPubKey"
                                    . ,(script-to-json
                                        (bl.store:utxo-entry-script-pubkey coin)
                                        :network network))))
                               coins)
                              #()))))))
        (t
         (%rest-hex-or-bin
          ext (bl.crypto:bytes-to-hex
               (%getutxos-binary height tip-hash hits coins))))))))

;;; --- Liveness probe (bitcoin-lisp extension, not a Core REST endpoint) ---

(defun %rest-health (node)
  "Unauthenticated liveness probe. HTTP 200 iff the node's sync thread is alive
AND the active chain tip advanced within the staleness threshold; else HTTP
503. Body: {\"status\", \"seconds_since_tip\", \"synced\"}. The underlying
node-tip-liveness read is lock-free and side-effect-free, so the probe stays
responsive (and correctly reports 503) even when the node is wedged."
  (multiple-value-bind (healthy seconds-since-tip synced)
      (bl:node-tip-liveness node)
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

(defun %rest-blockpart (node body ext)
  "/rest/blockpart/<blockhash>.<ext>?offset=<n>&size=<n> — a byte RANGE of the
serialized block (rest_block_part, rest.cpp:480-497).

Offset and size are QUERY parameters, not path segments, and JSON is not a
supported format for this endpoint: the whole point is raw bytes.

Core seeks into the block file and reads SIZE bytes; we take the range from the
serialized block, which is the same bytes — a blk record's payload IS the
witness-complete serialization. The range check is Core's (size 0 is invalid,
and offset+size must not exceed the block; blockstorage.cpp:1116-1120), which
matters because both numbers come from untrusted REST input. Core needs a
SaturatingAdd there to stop the sum wrapping past the check; Lisp integers do
not wrap, so a plain + is already the safe version."
  ;; Offset and size are validated BEFORE the hash, which is Core's order:
  ;; rest_block_part parses the query parameters and only then delegates to
  ;; rest_block, which is where the hash is parsed (rest.cpp:480-497 vs :390).
  ;; A request missing both a valid hash and a valid offset therefore reports
  ;; the OFFSET, and a client fixing errors in the order it is told them
  ;; converges either way — but only one order matches Core's messages.
  (let ((offset (%rest-size-parameter "offset"))
        (size (%rest-size-parameter "size")))
    (cond
      ((null offset) (%rest-error 400 "Block part offset missing or invalid"))
      ((null size) (%rest-error 400 "Block part size missing or invalid"))
      ((not (valid-hex-hash-p body)) (%rest-error 400 (format nil "Invalid hash: ~A" body)))
      ((string= ext "json") (%rest-format-not-found ".bin, .hex"))
      ((not (or (string= ext "hex") (string= ext "bin")))
       (%rest-format-not-found ".bin, .hex"))
      (t
       (let* ((hash (parse-hex-hash body))
              (store (rpc-get-block-store node))
              (block (and store (bl.store:get-block store hash))))
         (cond
           ((null block) (%rest-error 404 (format nil "~A not found" body)))
           (t
            (let ((bytes (bl.ser:serialize-witness-block block)))
              (if (or (zerop size) (> (+ offset size) (length bytes)))
                  (%rest-error 400 (format nil "Bad block part offset/size ~D/~D for ~A"
                                           offset size body))
                  (%rest-hex-or-bin
                   ext (bl.crypto:bytes-to-hex
                        (subseq bytes offset (+ offset size)))))))))))))

(defun %rest-size-parameter (name)
  "A non-negative integer query parameter, or NIL when absent or malformed.
Core parses these with ToIntegral<size_t>, so a negative or non-numeric value
is not a zero — it is a 400."
  (let ((v (hunchentoot:get-parameter name)))
    (when (and v (plusp (length v)) (every #'digit-char-p v))
      (parse-integer v :junk-allowed t))))

(defun %rest-deploymentinfo (node body ext)
  "/rest/deploymentinfo[/<blockhash>] — JSON only, as in Core
(rest_deploymentinfo, rest.cpp). The hash is optional: without one Core reports
against the tip."
  (if (string= ext "json")
      (handler-case
          (%rest-json (rpc-getdeploymentinfo
                       node (if (plusp (length body)) (list body) nil)))
        (rpc-error (e) (%rest-error 404 (rpc-error-message e))))
      (%rest-format-not-found "json")))

(defun %rest-blockfilter (node body ext)
  "/rest/blockfilter/<filtertype>/<blockhash> — the BIP158 filter for a block
(rest_block_filter, rest.cpp). Core's URI carries the filter type FIRST."
  (let* ((slash (position #\/ body))
         (filtertype (and slash (subseq body 0 slash)))
         (hash (and slash (subseq body (1+ slash)))))
    (cond
      ((null slash)
       (%rest-error 400 "Invalid URI format. Expected /rest/blockfilter/<filtertype>/<blockhash>"))
      ((not (valid-hex-hash-p hash)) (%rest-error 400 (format nil "Invalid hash: ~A" hash)))
      (t
       (handler-case
           (let ((result (rpc-getblockfilter node (list hash filtertype))))
             (%rest-by-ext ext
               :json (%rest-json result)
               ;; The hex/bin forms carry the FILTER itself, not the wrapper
               ;; object — Core serializes the filter (rest.cpp).
               :hex/bin (%rest-hex-or-bin
                         ext (cdr (assoc "filter" result :test #'string=)))))
         (rpc-error (e) (%rest-error 404 (rpc-error-message e))))))))

(defun %rest-blockfilterheaders (node body ext)
  "/rest/blockfilterheaders/<filtertype>/<blockhash>?count=<n>, and Core's
deprecated /<filtertype>/<count>/<blockhash> form (rest_filter_header,
rest.cpp).

Walks forward on the active chain from BLOCKHASH exactly as %REST-HEADERS
does, and for the same reason: a start that is not itself on the active chain
would otherwise be spliced onto the active chain's successors and return a
sequence that never existed."
  (let* ((parts (uiop:split-string body :separator "/"))
         (filtertype (first parts))
         ;; Three parts is Core's deprecated <filtertype>/<count>/<blockhash>;
         ;; two is the current <filtertype>/<blockhash> with ?count=.
         (deprecated (= (length parts) 3))
         (hash (if deprecated (third parts) (second parts)))
         (raw-count (if deprecated
                        (second parts)
                        (or (hunchentoot:get-parameter "count") "5")))
         (count (and raw-count (parse-integer raw-count :junk-allowed t))))
    (cond
      ((not (member (length parts) '(2 3)))
       (%rest-error 400 "Invalid URI format. Expected /rest/blockfilterheaders/<filtertype>/<blockhash>.<ext>?count=<count>"))
      ((or (null count) (< count 1) (> count +rest-max-headers+))
       (%rest-error 400 (%rest-bad-count-message (or raw-count ""))))
      ((not (valid-hex-hash-p hash)) (%rest-error 400 (format nil "Invalid hash: ~A" hash)))
      (t
       (let* ((chain-state (rpc-get-chain-state node))
              (start (bl.store:get-block-index-entry
                      chain-state (parse-hex-hash hash))))
         (cond
           ((null start) (%rest-error 404 (format nil "~A not found" hash)))
           (t
            (handler-case
                (let* ((entries
                         (when (bl.store:entry-on-active-chain-p
                                chain-state start)
                           (loop with h = (bl.store:block-index-entry-height start)
                                 for i from 0 below count
                                 for e = start then (bl.store:get-block-at-height
                                                     chain-state (+ h i))
                                 while e collect e)))
                       (headers
                         (mapcar
                          (lambda (e)
                            (let ((result (rpc-getblockfilter
                                           node
                                           (list (bl.crypto:bytes-to-hex
                                                  (bl.store:block-index-entry-hash e))
                                                 filtertype))))
                              (cdr (assoc "header" result :test #'string=))))
                          entries)))
                  (%rest-by-ext ext
                    :json (%rest-json (json-array headers))
                    ;; Core concatenates the raw 32-byte headers.
                    :hex/bin (%rest-hex-or-bin
                              ext (apply #'concatenate 'string headers))))
              (rpc-error (e) (%rest-error 404 (rpc-error-message e)))))))))))

(defun %rest-spent-txouts-bytes (tx-undos)
  "TX-UNDOS as Core's SerializeBlockUndo (rest.cpp:277-289): CompactSize of the
transaction count PLUS ONE, then CompactSize(0) standing in for the coinbase,
which CBlockUndo does not carry; then, per transaction, the CompactSize input
count followed by each spent coin as a BARE CTxOut — int64 value and
CompactSize-prefixed scriptPubKey (CTxOut::SERIALIZE_METHODS,
primitives/transaction.h:152).

Deliberately NOT BL.STORE:SERIALIZE-BLOCK-UNDO. That is the rev-file codec —
Core VARINT(height*2+coinbase), the dummy byte, and TxOutCompression of the
amount and script — and Core does not use it here: this endpoint's format
carries no height, no coinbase flag and no compression, and its leading count
is one larger. Serving the disk codec makes every .bin/.hex response
undecodable by a client written against Core, with the coins reading as
plausible garbage rather than failing."
  (let ((bb (bl.ser:make-byte-buf)))
    (bl.ser:bb-write-varint bb (1+ (length tx-undos)))
    (bl.ser:bb-write-varint bb 0)
    (dolist (tx-undo tx-undos)
      (bl.ser:bb-write-varint bb (length tx-undo))
      (dolist (entry tx-undo)
        (bl.ser:bb-write-tx-out
         bb (bl.ser:make-tx-out
             :value (bl.store:utxo-entry-value entry)
             :script-pubkey (bl.store:utxo-entry-script-pubkey entry)))))
    (bl.ser:bb-finish bb)))

(defun %rest-spenttxouts (node body ext)
  "/rest/spenttxouts/<blockhash> — the block's CBlockUndo, i.e. the coins its
inputs spent (rest_spent_txouts, rest.cpp:311-379).

Both forms carry Core's REST-specific shape, which leads with a placeholder
for the coinbase: %REST-SPENT-TXOUTS-BYTES for .bin/.hex and %BLOCK-UNDO-JSON
for .json."
  (unless (valid-hex-hash-p body)
    (return-from %rest-spenttxouts (%rest-error 400 (format nil "Invalid hash: ~A" body))))
  (let* ((hash (parse-hex-hash body))
         (store (and hash (rpc-get-block-store node)))
         (block (and store (bl.store:get-block store hash))))
    (cond
      ((null block) (%rest-error 404 (format nil "~A not found" body)))
      (t
       (let ((undo (bl.val:get-undo-data hash)))
         (handler-case
             (let ((tx-undos (bl.store:block-undo-from-spent-utxos
                              block (or undo '()))))
               (%rest-by-ext ext
                 :json (%rest-json (%block-undo-json tx-undos node))
                 :hex/bin (%rest-hex-or-bin
                           ext (bl.crypto:bytes-to-hex
                                (%rest-spent-txouts-bytes tx-undos)))))
           (error ()
             ;; block-undo-from-spent-utxos refuses undo data that does not
             ;; account for exactly this block's inputs, which is what a pruned
             ;; or missing record looks like.
             (%rest-error 404 (format nil "~A undo not available" body)))))))))

(defun %block-undo-json (tx-undos node)
  "TX-UNDOS as Core's BlockUndoToJSON (rest.cpp:293-311): an EMPTY array
first — CBlockUndo has no entry for the coinbase, and Core pushes the
placeholder so that result[i] is block transaction i's coins — then one array
per non-coinbase transaction, each holding the coins that transaction's inputs
spent. Without the placeholder every array is attributed to the transaction
before it."
  (let ((network (rpc-get-network node)))
    (cons
     (json-array '())
     (mapcar
      (lambda (tx-undo)
        (json-array
         (mapcar
          (lambda (entry)
            (let ((spk (bl.store:utxo-entry-script-pubkey entry)))
              `(("value" . ,(satoshi->btc (bl.store:utxo-entry-value entry)))
                ;; Core's ScriptToUniv with include_hex and include_address
                ;; (rest.cpp:303).
                ("scriptPubKey" . ,(script-to-json spk :network network)))))
          tx-undo)))
      tx-undos))))

(defun rest-handle (node uri &optional post-body)
  "Route a /rest/... URI (script-name, query already stripped by Hunchentoot)
to its handler. Returns the response body; sets status/content-type. POST-BODY
is the raw request body, which only /rest/getutxos reads (BIP64's binary
request form).

Warmup is checked FIRST, for every endpoint, and answers Core's HTTP 503
\"Service temporarily unavailable: <status>\" (CheckWarmup, rest.cpp:170-176).
Core writes `if (!CheckWarmup(req)) return false;` at the head of each of its
eleven handlers; one gate on the single dispatch point is the same rule with
no handler left to forget it in, and it is the REST twin of the -28
DISPATCH-RPC-METHOD answers on the JSON-RPC path. The REST surface is
installed by the same START-RPC-SERVER call that enters warmup, long before
the mempool replay and the index catch-ups, so without this a client polling
/rest/chaininfo.json across a restart was served 200 with content computed
against a chainstate that was not consistent yet."
  (let ((warmup *rpc-warmup-status*))
    (when warmup
      (return-from rest-handle
        (%rest-error 503 (format nil "Service temporarily unavailable: ~A" warmup)))))
  (let ((rest (cond ((alexandria:starts-with-subseq "/rest/" uri) (subseq uri 6))
                    (t (return-from rest-handle (%rest-error 400 "Not a /rest/ path"))))))
    (flet ((after (prefix) (subseq rest (length prefix))))
      (cond
        ((alexandria:starts-with-subseq "chaininfo" rest)
         (multiple-value-bind (b e) (%rest-split-ext rest) (%rest-chaininfo node b e)))
        ((alexandria:starts-with-subseq "blockhashbyheight/" rest)
         (multiple-value-bind (b e) (%rest-split-ext (after "blockhashbyheight/"))
           (%rest-blockhashbyheight node b e)))
        ;; blockpart must precede "block/" — "block" is a prefix of it, so the
        ;; shorter route would swallow every blockpart request and read
        ;; "part/<hash>" as a block hash.
        ((alexandria:starts-with-subseq "blockpart/" rest)
         (multiple-value-bind (b e) (%rest-split-ext (after "blockpart/"))
           (%rest-blockpart node b e)))
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
           (%rest-getutxos node b e post-body)))
        ;; The bare form, whose outpoints are in the POST body: Core registers
        ;; ONE "/rest/getutxos" prefix and ParseDataFormat splits the extension
        ;; off whatever follows (rest.cpp:1153, :899). We routed only the
        ;; slashed spelling, so interface_rest.py:167's POST /rest/getutxos.bin
        ;; reached no handler at all.
        ((alexandria:starts-with-subseq "getutxos" rest)
         (multiple-value-bind (b e) (%rest-split-ext (after "getutxos"))
           (%rest-getutxos node b e post-body)))
        ;; deploymentinfo takes an OPTIONAL hash, so both the bare and the
        ;; slashed forms route here (Core registers both, rest.cpp:1154-1155).
        ((alexandria:starts-with-subseq "deploymentinfo/" rest)
         (multiple-value-bind (b e) (%rest-split-ext (after "deploymentinfo/"))
           (%rest-deploymentinfo node b e)))
        ((alexandria:starts-with-subseq "deploymentinfo" rest)
         (multiple-value-bind (b e) (%rest-split-ext rest)
           (declare (ignore b))
           (%rest-deploymentinfo node "" e)))
        ;; blockfilterheaders must precede blockfilter, which is a prefix of it.
        ((alexandria:starts-with-subseq "blockfilterheaders/" rest)
         (multiple-value-bind (b e) (%rest-split-ext (after "blockfilterheaders/"))
           (%rest-blockfilterheaders node b e)))
        ((alexandria:starts-with-subseq "blockfilter/" rest)
         (multiple-value-bind (b e) (%rest-split-ext (after "blockfilter/"))
           (%rest-blockfilter node b e)))
        ((alexandria:starts-with-subseq "spenttxouts/" rest)
         (multiple-value-bind (b e) (%rest-split-ext (after "spenttxouts/"))
           (%rest-spenttxouts node b e)))
        ;; Unauthenticated liveness probe (bitcoin-lisp extension, not Core):
        ;; /rest/health or /rest/health.json.
        ((or (string= rest "health") (string= rest "health.json"))
         (%rest-health node))
        (t (%rest-error 404 "Unknown REST endpoint"))))))

(defun rest-dispatch-handler ()
  "Hunchentoot handler for /rest/* — GET and POST.

Core's REST endpoints are reached by whatever method libevent hands them; its
HTTP server rejects only an UNKNOWN method (httpserver.cpp http_request_cb),
and /rest/getutxos exists to be POSTed to -- BIP64 puts the outpoints in the
request body. We answered 405 to every POST, so interface_rest.py:167 never
reached the handler."
  (if (member (hunchentoot:request-method*) '(:get :post))
      (handler-case (rest-handle *rpc-node* (hunchentoot:script-name*)
                                 (and (eq (hunchentoot:request-method*) :post)
                                      (hunchentoot:raw-post-data :force-binary t)))
        (error (e)
          (bl.log:node-log :error "REST handler error: ~A" e)
          (%rest-error 500 "Internal error")))
      (progn
        (setf (hunchentoot:return-code*) hunchentoot:+http-method-not-allowed+)
        "")))

;;; A /rest/ URI with a malformed percent-escape never reaches the router:
;;; Hunchentoot's request initializer decodes the path and the query while it
;;; builds the request, fails, and marks the reply 400, and process-request then
;;; answers with ACCEPTOR-STATUS-MESSAGE instead of dispatching. Core parses the
;;; same URI with evhttp_uri_parse when a handler reads a query parameter and
;;; answers RESTERR 400 with the parser's own sentence (httpserver.cpp:661-666,
;;; rest.cpp:198-200); interface_rest.py:291-294 sends `%' at the end of three
;;; URIs and compares the body with that sentence.

(defun %malformed-percent-escape-p (uri)
  "T when URI has a `%' not followed by two hex digits -- the RFC 3986
pct-encoded form evhttp_uri_parse refuses."
  (loop for i from 0 below (length uri)
        thereis (and (char= (char uri i) #\%)
                     (not (and (< (+ i 2) (length uri))
                               (digit-char-p (char uri (+ i 1)) 16)
                               (digit-char-p (char uri (+ i 2)) 16))))))

(defmethod hunchentoot:acceptor-status-message ((acceptor rpc-acceptor)
                                                (http-status-code (eql 400))
                                                &key)
  (let ((uri (and (boundp 'hunchentoot:*request*)
                  hunchentoot:*request*
                  (hunchentoot:request-uri hunchentoot:*request*))))
    (if (and uri
             (alexandria:starts-with-subseq "/rest/" uri)
             (%malformed-percent-escape-p uri))
        (progn
          (setf (hunchentoot:content-type*) "text/plain")
          (format nil "URI parsing failed, it likely contained RFC 3986 invalid characters~%"))
        (call-next-method))))

;;; The surface itself. Off unless -rest is given (Core StartREST gate,
;;; init.cpp:758; DEFAULT_REST_ENABLE = false, init.cpp:153 -- we once
;;; registered it unconditionally).
(register-http-surface
 :rest
 :options '(:rest-enabled)
 :start (lambda (options)
          (when (getf options :rest-enabled)
            (bl.log:node-log :info "REST interface enabled at /rest/")
            (hunchentoot:create-prefix-dispatcher "/rest/" 'rest-dispatch-handler))))
