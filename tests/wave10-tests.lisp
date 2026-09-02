(in-package #:bitcoin-lisp.tests)

;;; Wave 10: RPC/config polish tests
;;;
;;; - JSON boolean correctness (false vs null) across RPC results
;;; - RPC error-code parity with Bitcoin Core (protocol.h RPCErrorCode)
;;; - HTTP layer: 1.x error->status mapping, 2.0 always-200, notification
;;;   detection, 32 MiB body cap
;;; - BIP64 /rest/getutxos (json + binary forms, checkmempool, limits)
;;; - gettxout include_mempool
;;; - Config wires (-assumevalid/-minimumchainwork/-mempoolexpiry/... )
;;; - ArgsManager-parity argument handling (unknown args, precedence)
;;; - banlist.json persistence + periodic peers.dat dump cadence

(def-suite :wave10-tests
  :description "Wave 10 RPC/config polish"
  :in :bitcoin-lisp-tests)

(in-suite :wave10-tests)

(defun wave10-encode (result)
  "Encode an RPC result alist exactly like the server does."
  (with-output-to-string (s)
    (yason:encode (bl.rpc::rpc-result->json result) s)))

;;; ---------------------------------------------------------------------
;;; A. JSON booleans
;;; ---------------------------------------------------------------------

(test wave10-json-bool-helper
  "json-bool maps generalized booleans to T / the yason false literal, and
yason renders the literal as JSON false (not null)."
  (is (eq t (bl.rpc:json-bool 42)))
  (is (eq t (bl.rpc:json-bool '(:truthy))))
  (is (eq bl.rpc:+json-false+ (bl.rpc:json-bool nil)))
  (is (string= "false" (with-output-to-string (s)
                         (yason:encode bl.rpc:+json-false+ s))))
  ;; rpc-result->json passes the literal through inside objects and arrays.
  (is (string= "{\"a\":false}" (wave10-encode '(("a" . yason:false)))))
  (is (string= "[false,true,null]"
               (wave10-encode (list 'yason:false t nil)))))

(test wave10-boolean-fields-encode-false-not-null
  "Always-present Core booleans render as false on an empty node:
getblockchaininfo (initialblockdownload/pruned), getnetworkinfo
(networkactive is true here; localrelay honest), getmempoolinfo (loaded
true), gettxout coinbase, testmempoolaccept allowed — spot-checked through
the real yason pipeline."
  (let* ((node (make-test-node))
         (chain (wave10-encode (bl.rpc::rpc-getblockchaininfo node nil))))
    (is (search "\"initialblockdownload\":false" chain))
    (is (search "\"pruned\":false" chain))
    (is (not (search "\"pruned\":null" chain)))
    (let ((net (wave10-encode (bl.rpc::rpc-getnetworkinfo node nil))))
      ;; network-active defaults to T on a fresh node struct.
      (is (search "\"networkactive\":true" net))
      ;; localrelay is a real boolean either way — never null.
      (is (or (search "\"localrelay\":true" net)
              (search "\"localrelay\":false" net)))
      ;; subversion comes from the shared user-agent variable (slash-free
      ;; probe: yason may escape '/').
      (is (search "bl:0.1.0" net)))
    (let ((mem (wave10-encode (bl.rpc::rpc-getmempoolinfo node nil))))
      (is (search "\"loaded\":true" mem))
      (is (search "\"permitbaremultisig\":" mem)))))

(test wave10-getaddednodeinfo-connected-false
  "getaddednodeinfo reports connected:false (not null) for an added but
unconnected peer."
  (let ((node (make-test-node)))
    (bl.rpc::rpc-addnode node (list "192.0.2.10:48333" "add"))
    (let* ((r (bl.rpc::rpc-getaddednodeinfo node nil))
           (row (first r)))
      (is (eq 'yason:false (cdr (assoc "connected" row :test #'string=))))
      (is (search "\"connected\":false" (wave10-encode r))))))

(test wave10-scan-abort-bare-booleans
  "scantxoutset/scanblocks abort with no scan running return JSON false."
  (is (eq 'yason:false (bl.rpc::rpc-scantxoutset
                        (make-test-node) (list "abort"))))
  (is (eq 'yason:false (bl.rpc::rpc-scanblocks
                        (make-test-node) (list "abort")))))

(test wave10-setnetworkactive-bare-boolean
  "setnetworkactive returns the new state as a bare JSON boolean."
  (let ((node (make-test-node)))
    (is (eq 'yason:false (bl.rpc::rpc-setnetworkactive node (list nil))))
    (is (eq t (bl.rpc::rpc-setnetworkactive node (list t))))))

(test wave10-mempool-entry-unbroadcast-real
  "The mempool entry's unbroadcast field reflects the actual unbroadcast set
(was hardcoded null)."
  (let* ((node (make-test-node))
         (mempool (bl:node-mempool node))
         (tx (make-mempool-test-tx :input-id 71))
         (txid (bl.ser:transaction-hash tx)))
    (is (eq :ok (bl.mp:mempool-add
                 mempool txid (make-mempool-entry-for-tx tx))))
    (let ((fields (bl.rpc::rpc-getmempoolentry
                   node (list (bl.rpc:hash-to-hex txid)))))
      (is (eq 'yason:false (cdr (assoc "unbroadcast" fields :test #'string=)))))
    (bl.mp:mempool-add-unbroadcast mempool txid)
    (let ((fields (bl.rpc::rpc-getmempoolentry
                   node (list (bl.rpc:hash-to-hex txid)))))
      (is (eq t (cdr (assoc "unbroadcast" fields :test #'string=)))))))

;;; ---------------------------------------------------------------------
;;; B. Error-code parity
;;; ---------------------------------------------------------------------

(test wave10-not-found-errors-are-minus-5
  "Block/tx lookups that fail on well-formed input throw -5
RPC_INVALID_ADDRESS_OR_KEY, like Core (was -1)."
  (let ((node (make-test-node))
        (hash (make-string 64 :initial-element #\a)))
    (is (= -5 (rpc-error-code-of
               (lambda () (bl.rpc::rpc-getblock node (list hash))))))
    (is (= -5 (rpc-error-code-of
               (lambda () (bl.rpc::rpc-getblockheader node (list hash))))))
    (is (= -5 (rpc-error-code-of
               (lambda () (bl.rpc::rpc-getmempoolentry node (list hash))))))
    (is (= -5 (rpc-error-code-of
               (lambda () (bl.rpc::rpc-getmempoolancestors node (list hash))))))))

(test wave10-disconnectnode-minus-29
  "disconnectnode on an unknown peer throws -29 RPC_CLIENT_NODE_NOT_CONNECTED
with Core's message."
  (signals-rpc-error (:code -29 :exact-message "Node not found in connected nodes")
    (bl.rpc::rpc-disconnectnode (make-test-node) (list "203.0.113.9"))))

(test wave10-setban-error-codes
  "setban: invalid address -30; double-add -23; unban of a never-banned
address -30; absolute past timestamp -8 (Core net.cpp:766-812)."
  (let ((bl.net:*banlist-path* nil)
        (node (make-test-node)))
    (unwind-protect
         (progn
           ;; hostnames / garbage are not bannable addresses
           (is (= -30 (rpc-error-code-of
                       (lambda () (bl.rpc::rpc-setban
                                   node (list "not-an-ip" "add"))))))
           (is (null (bl.rpc::rpc-setban node (list "198.51.100.7" "add"))))
           (is (= -23 (rpc-error-code-of
                       (lambda () (bl.rpc::rpc-setban
                                   node (list "198.51.100.7" "add"))))))
           (is (= -8 (rpc-error-code-of
                      (lambda () (bl.rpc::rpc-setban
                                  node (list "192.0.2.44" "add" 12345 t))))))
           (is (null (bl.rpc::rpc-setban node (list "198.51.100.7" "remove"))))
           (is (= -30 (rpc-error-code-of
                       (lambda () (bl.rpc::rpc-setban
                                   node (list "198.51.100.7" "remove")))))))
      (bl.net:clear-ban-list))))

(test wave10-deserialization-errors-are-minus-22
  "submitblock/testmempoolaccept/submitpackage decode failures throw -22
RPC_DESERIALIZATION_ERROR (whole call — no per-tx allowed:false rows)."
  (let ((node (make-test-node)))
    (is (= -22 (rpc-error-code-of
                (lambda () (bl.rpc::rpc-submitblock node (list "zz"))))))
    (is (= -22 (rpc-error-code-of
                (lambda () (bl.rpc::rpc-submitblock node (list ""))))))
    (is (= -22 (rpc-error-code-of
                (lambda () (bl.rpc::rpc-testmempoolaccept
                            node (list (list "nothex!")))))))
    (is (= -22 (rpc-error-code-of
                (lambda () (bl.rpc::rpc-submitpackage
                            node (list (list "nothex!" "alsonot")))))))))

(test wave10-maxmempool-wire-and-blocksonly-interaction
  "-maxmempool is megabytes of pool memory (Core DEFAULT_MAX_MEMPOOL_SIZE_MB
300), and -blocksonly SOFT-sets it to 5 MB: a node that does not relay
transactions has no reason to hold 300 MB of them (init.cpp:826). Soft means an
explicit -maxmempool still wins."
  (let ((bl.mp:*max-mempool-bytes*
          bl.mp:+default-max-mempool-bytes+))
    ;; Explicit value, in megabytes.
    (bl::apply-config-globals '(("maxmempool" . "50")))
    (is (= (* 50 1000 1000) bl.mp:*max-mempool-bytes*))
    ;; The mempool built AFTER the wire uses the new cap.
    (is (= (* 50 1000 1000)
           (bl.mp:mempool-max-size
            (bl.mp:make-mempool))))
    ;; -blocksonly alone shrinks the default.
    (setf bl.mp:*max-mempool-bytes*
          bl.mp:+default-max-mempool-bytes+)
    (bl::apply-config-globals '(("blocksonly" . "1")))
    (is (= (* 5 1000 1000) bl.mp:*max-mempool-bytes*))
    ;; ...but an explicit -maxmempool beats it, which is what "soft" means.
    (setf bl.mp:*max-mempool-bytes*
          bl.mp:+default-max-mempool-bytes+)
    (bl::apply-config-globals '(("blocksonly" . "1")
                                          ("maxmempool" . "100")))
    (is (= (* 100 1000 1000) bl.mp:*max-mempool-bytes*))
    ;; -blocksonly=0 is not the interaction.
    (setf bl.mp:*max-mempool-bytes*
          bl.mp:+default-max-mempool-bytes+)
    (bl::apply-config-globals '(("blocksonly" . "0")))
    (is (= bl.mp:+default-max-mempool-bytes+
           bl.mp:*max-mempool-bytes*))
    (signals error (bl::apply-config-globals '(("maxmempool" . "junk"))))))

(test wave10-block-weight-options-wire-and-validate
  "-blockmaxweight/-blockreservedweight are template SELECTION budgets with
Core's three guards (init.cpp:1079-1093): neither may exceed the consensus
maximum, and the reserve may not fall below MINIMUM_BLOCK_RESERVED_WEIGHT."
  (let ((bl.mining:*block-max-weight*
          bl.val:+max-block-weight+)
        (bl.mining:*block-reserved-weight*
          bl.mining:+block-reserved-weight+))
    (bl::apply-config-globals '(("blockmaxweight" . "3000000")))
    (is (= 3000000 bl.mining:*block-max-weight*))
    (bl::apply-config-globals '(("blockreservedweight" . "4000")))
    (is (= 4000 bl.mining:*block-reserved-weight*))
    ;; A fresh template starts at the configured reserve.
    (is (= 4000 (bl.mining:block-template-total-weight
                 (bl.mining::make-block-template))))
    ;; Above consensus: refused, both options.
    (signals error
      (bl::apply-config-globals
       (list (cons "blockmaxweight"
                   (format nil "~D" (1+ bl.val:+max-block-weight+))))))
    (signals error
      (bl::apply-config-globals
       (list (cons "blockreservedweight"
                   (format nil "~D" (1+ bl.val:+max-block-weight+))))))
    ;; Below the safety floor: refused. Exactly at it: accepted.
    (signals error
      (bl::apply-config-globals
       (list (cons "blockreservedweight"
                   (format nil "~D" (1- bl.mining:+minimum-block-reserved-weight+))))))
    (bl::apply-config-globals
     (list (cons "blockreservedweight"
                 (format nil "~D" bl.mining:+minimum-block-reserved-weight+))))
    (is (= bl.mining:+minimum-block-reserved-weight+
           bl.mining:*block-reserved-weight*))))

(test wave10-testmempoolaccept-count-limits
  "testmempoolaccept enforces Core's 1..25 batch bound with -8.

The EMPTY-array case earns -8; a NULL rawtxs earns -3 instead, and the two
were the same value here until the decoder could tell them apart. Core's
RPCArg::MatchesType returns early for a null only when the argument is
OPTIONAL (rpc/util.cpp:903); rawtxs is required, so null falls through to the
type comparison and answers \"JSON value of type null is not of expected type
array\". This test asserted -8 for NIL, which was our merged representation
rather than either of Core's answers."
  (let ((node (make-test-node)))
    (is (= -8 (rpc-error-code-of
               (lambda () (bl.rpc::rpc-testmempoolaccept
                           node (list bl.rpc::+json-empty-array+))))))
    (is (= -3 (rpc-error-code-of
               (lambda () (bl.rpc::rpc-testmempoolaccept node (list '()))))))
    (is (= -8 (rpc-error-code-of
               (lambda () (bl.rpc::rpc-testmempoolaccept
                           node (list (make-list 26 :initial-element "00")))))))))

(test wave10-misc-error-code-parity
  "generatetoaddress bad address -5; prioritisetransaction bad txid -8;
signmessagewithprivkey bad WIF -5; getblockfilter malformed hash -8."
  (let ((node (make-test-node)))
    (is (= -5 (rpc-error-code-of
               (lambda () (bl.rpc::rpc-generatetoaddress
                           node (list 1 "notanaddress"))))))
    (is (= -8 (rpc-error-code-of
               (lambda () (bl.rpc::rpc-prioritisetransaction
                           node (list "nothex" 0 1000))))))
    (is (= -5 (rpc-error-code-of
               (lambda () (bl.rpc:rpc-signmessagewithprivkey
                           node (list "notawif" "msg"))))))
    (is (= -8 (rpc-error-code-of
               (lambda () (bl.rpc::rpc-getblockfilter
                           node (list "shorthex"))))))))

(test wave10-verifymessage-error-codes
  "verifymessage: undecodable address -5 'Invalid address'; a decodable
non-P2PKH (bech32) address -3 'Address does not refer to key'."
  (let ((node (make-test-node)))
    (signals-rpc-error (:code -5 :exact-message "Invalid address")
      (bl.rpc::rpc-verifymessage
       node (list "not-an-address" "AAAA" "m")))
    (signals-rpc-error (:code -3 :exact-message "Address does not refer to key")
      (bl.rpc::rpc-verifymessage
       node (list "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx" "AAAA" "m")))))

(test wave10-getblocktemplate-mainnet-gates
  "getblocktemplate on MAINNET with no peers throws -9 (Core's
!isTestChain() gate); test networks skip the gate entirely."
  (let ((node (bl:make-node :network :mainnet)))
    (signals-rpc-error (:code -9 :exact-message "Bitcoin is not connected!")
      (bl.rpc::rpc-getblocktemplate node nil))))

(test wave10-method-not-found
  "Unknown methods throw -32601 with Core's exact message."
  (bl.rpc::register-all-methods)
  (signals-rpc-error (:code -32601 :exact-message "Method not found")
    (bl.rpc:dispatch-rpc-method nil "nosuchmethod" '())))

;;; ---------------------------------------------------------------------
;;; HTTP layer
;;; ---------------------------------------------------------------------

(test wave10-http-status-mapping
  "JSON-RPC 1.x error responses map -32600->400, -32601->404, else 500;
2.0 responses are always 200 (Core httprpc.cpp JSONErrorReply)."
  (is (= 400 (bl.rpc::rpc-error-http-status -32600)))
  (is (= 404 (bl.rpc::rpc-error-http-status -32601)))
  (is (= 500 (bl.rpc::rpc-error-http-status -5)))
  (is (= 500 (bl.rpc::rpc-error-http-status -1)))
  (is (= 500 (bl.rpc::rpc-error-http-status -32700)))
  (let ((ok (bl.rpc::make-rpc-response 1 1 :v1))
        (nf (bl.rpc::make-rpc-error-response -32601 "Method not found" 1 :v1))
        (misc (bl.rpc::make-rpc-error-response -1 "x" 1 :v1)))
    (is (= 200 (bl.rpc::rpc-response-http-status ok :v1)))
    (is (= 200 (bl.rpc::rpc-response-http-status ok :v2)))
    (is (= 404 (bl.rpc::rpc-response-http-status nf :v1)))
    (is (= 200 (bl.rpc::rpc-response-http-status nf :v2)))
    (is (= 500 (bl.rpc::rpc-response-http-status misc :v1)))))

(test wave10-jsonrpc-version-and-notification-detection
  "parse-json-rpc-request reports :v2 only for jsonrpc:\"2.0\" and
distinguishes an absent id (notification -> 204) from id:null."
  (multiple-value-bind (type method params id version id-present)
      (bl.rpc::parse-json-rpc-request
       "{\"jsonrpc\":\"2.0\",\"method\":\"m\"}")
    (declare (ignore method params id))
    (is (eq type :single))
    (is (eq version :v2))
    (is (null id-present)))
  (multiple-value-bind (type method params id version id-present)
      (bl.rpc::parse-json-rpc-request
       "{\"jsonrpc\":\"2.0\",\"method\":\"m\",\"id\":null}")
    (declare (ignore method params id))
    (is (eq type :single))
    (is (eq version :v2))
    (is (eq t id-present)))
  (multiple-value-bind (type method params id version id-present)
      (bl.rpc::parse-json-rpc-request
       "{\"method\":\"m\",\"id\":7}")
    (declare (ignore method params))
    (is (eq type :single))
    (is (= 7 id))
    (is (eq version :v1))
    (is (eq t id-present))))

(test wave10-invalid-request-not-parse-error
  "A parseable body with a missing method is -32600 INVALID_REQUEST, not
-32700 PARSE_ERROR (previously swallowed by the outer handler)."
  (signals-rpc-error (:code -32600)
    (bl.rpc::parse-json-rpc-request "{\"id\":1}"))
  (signals-rpc-error (:code -32700)
    (bl.rpc::parse-json-rpc-request "not json")))

;;; ---------------------------------------------------------------------
;;; D. gettxout include_mempool
;;; ---------------------------------------------------------------------

(test wave10-gettxout-include-mempool-spend
  "A confirmed coin spent by a mempool tx is hidden by default and visible
with include_mempool=false (Core mempool.isSpent path)."
  (let* ((node (make-test-node))
         (utxo (bl:node-utxo-set node))
         (mempool (bl:node-mempool node))
         (funding (make-array 32 :element-type '(unsigned-byte 8) :initial-element 42))
         (spk (bl.crypto:hex-to-bytes
               "76a914000000000000000000000000000000000000000088ac")))
    (bl.store:add-utxo utxo funding 0 100000000 spk 0)
    (let ((hex (bl.rpc:hash-to-hex funding)))
      ;; Visible while nothing spends it.
      (is (consp (bl.rpc::rpc-gettxout node (list hex 0))))
      ;; A mempool tx spending funding:0 hides it under include_mempool.
      (let* ((spender (bl.ser:make-transaction
                       :version 1
                       :inputs (vector (bl.ser:make-tx-in
                                        :previous-output (bl.ser:make-outpoint
                                                          :hash funding :index 0)
                                        :script-sig (make-array 1 :element-type '(unsigned-byte 8)
                                                                  :initial-element 0)
                                        :sequence #xFFFFFFFF))
                       :outputs (vector (bl.ser:make-tx-out
                                         :value 99990000 :script-pubkey spk))
                       :lock-time 0))
             (spender-txid (bl.ser:transaction-hash spender)))
        (is (eq :ok (bl.mp:mempool-add
                     mempool spender-txid (make-mempool-entry-for-tx spender))))
        (is (null (bl.rpc::rpc-gettxout node (list hex 0))))
        (is (null (bl.rpc::rpc-gettxout node (list hex 0 t))))
        (is (consp (bl.rpc::rpc-gettxout
                    node (list hex 0 bl.rpc:+json-false+))))
        ;; null include_mempool = Core default true (spent view).
        (is (null (bl.rpc::rpc-gettxout node (list hex 0 nil))))
        ;; The SPENDER's own output is visible via the mempool view with 0
        ;; confirmations and coinbase:false.
        (let ((r (bl.rpc::rpc-gettxout
                  node (list (bl.rpc:hash-to-hex spender-txid) 0))))
          (is (consp r))
          (is (= 0 (cdr (assoc "confirmations" r :test #'string=))))
          (is (eq 'yason:false (cdr (assoc "coinbase" r :test #'string=))))
          ;; ... and invisible without the mempool (explicit false).
          (is (null (bl.rpc::rpc-gettxout
                     node (list (bl.rpc:hash-to-hex spender-txid) 0
                                bl.rpc:+json-false+)))))))))

;;; ---------------------------------------------------------------------
;;; E. BIP64 /rest/getutxos
;;; ---------------------------------------------------------------------

(defun wave10-getutxos-node ()
  "A test node with one spendable coin; returns (values node txid-hex spk)."
  (let* ((node (make-test-node))
         (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7))
         (spk (bl.crypto:hex-to-bytes
               "76a914111111111111111111111111111111111111111188ac")))
    (bl.store:add-utxo
     (bl:node-utxo-set node) txid 0 250000000 spk 0)
    (values node (bl.rpc:hash-to-hex txid) spk)))

(test wave10-getutxos-json-bitmap
  "BIP64 json: two outpoints (hit, miss) -> bitmap \"10\", one utxo with
height/value/scriptPubKey (Core interface_rest.py expectations)."
  (multiple-value-bind (node txid-hex spk) (wave10-getutxos-node)
    (let* ((hunchentoot:*reply* (make-instance 'hunchentoot:reply))
           (miss (make-string 64 :initial-element #\e))
           (body (bl.rpc::rest-handle
                  node (format nil "/rest/getutxos/~A-0/~A-1.json" txid-hex miss)))
           (parsed (yason:parse body)))
      (is (= 200 (hunchentoot:return-code*)))
      (is (string= "10" (gethash "bitmap" parsed)))
      (let ((utxos (gethash "utxos" parsed)))
        (is (= 1 (length utxos)))
        (let ((u (first utxos)))
          (is (= 0 (gethash "height" u)))
          (is (= 5/2 (rational (gethash "value" u))))
          (let ((spk-obj (gethash "scriptPubKey" u)))
            (is (string= (bl.crypto:bytes-to-hex spk)
                         (gethash "hex" spk-obj)))
            (is (string= "pubkeyhash" (gethash "type" spk-obj)))))))))

(test wave10-getutxos-binary-layout
  "BIP64 .bin: u32 LE height | 32-byte tip hash | CompactSize+bitmap |
CompactSize(n) | per coin u32 dummy 0, u32 LE height, i64 LE value,
CompactSize+spk (Core rest.cpp:56-68,1034-1043)."
  (multiple-value-bind (node txid-hex spk) (wave10-getutxos-node)
    (let* ((hunchentoot:*reply* (make-instance 'hunchentoot:reply))
           (bytes (bl.rpc::rest-handle
                   node (format nil "/rest/getutxos/~A-0.bin" txid-hex))))
      (is (= 200 (hunchentoot:return-code*)))
      (is (typep bytes '(vector (unsigned-byte 8))))
      (is (= (+ 4 32 2 1 (+ 4 4 8 1 (length spk))) (length bytes)))
      ;; height 0 LE
      (is (equalp #(0 0 0 0) (subseq bytes 0 4)))
      ;; bitmap: 1 byte, first outpoint hit -> LSB set
      (is (= 1 (aref bytes 36)))
      (is (= #x01 (aref bytes 37)))
      ;; one coin follows
      (is (= 1 (aref bytes 38)))
      ;; u32 version dummy 0
      (is (equalp #(0 0 0 0) (subseq bytes 39 43)))
      ;; coin height 0
      (is (equalp #(0 0 0 0) (subseq bytes 43 47)))
      ;; value 250000000 LE over 8 bytes
      (is (= 250000000
             (loop for i from 0 below 8
                   sum (ash (aref bytes (+ 47 i)) (* 8 i)))))
      ;; spk length + bytes
      (is (= (length spk) (aref bytes 55)))
      (is (equalp spk (subseq bytes 56))))))

(test wave10-getutxos-checkmempool
  "checkmempool: a coin spent by a mempool tx drops out of the checkmempool
view but stays in the plain view; a mempool-created coin appears only in the
checkmempool view at MEMPOOL_HEIGHT (Core rest.cpp CCoinsViewMemPool)."
  (multiple-value-bind (node txid-hex spk) (wave10-getutxos-node)
    (let* ((hunchentoot:*reply* (make-instance 'hunchentoot:reply))
           (mempool (bl:node-mempool node))
           (funding (bl.rpc:parse-hex-hash txid-hex))
           (spender (bl.ser:make-transaction
                     :version 1
                     :inputs (vector (bl.ser:make-tx-in
                                      :previous-output (bl.ser:make-outpoint
                                                        :hash funding :index 0)
                                      :script-sig (make-array 1 :element-type '(unsigned-byte 8)
                                                                :initial-element 0)
                                      :sequence #xFFFFFFFF))
                     :outputs (vector (bl.ser:make-tx-out
                                       :value 249990000 :script-pubkey spk))
                     :lock-time 0))
           (spender-hex (bl.rpc:hash-to-hex
                         (bl.ser:transaction-hash spender))))
      (is (eq :ok (bl.mp:mempool-add
                   mempool (bl.ser:transaction-hash spender)
                   (make-mempool-entry-for-tx spender))))
      ;; Plain view: funding coin still there.
      (let ((parsed (yason:parse (bl.rpc::rest-handle
                                  node (format nil "/rest/getutxos/~A-0.json" txid-hex)))))
        (is (string= "1" (gethash "bitmap" parsed))))
      ;; checkmempool: hidden.
      (let ((parsed (yason:parse (bl.rpc::rest-handle
                                  node (format nil "/rest/getutxos/checkmempool/~A-0.json"
                                               txid-hex)))))
        (is (string= "0" (gethash "bitmap" parsed))))
      ;; Mempool-created coin: only via checkmempool, at MEMPOOL_HEIGHT.
      (let ((parsed (yason:parse (bl.rpc::rest-handle
                                  node (format nil "/rest/getutxos/~A-0.json" spender-hex)))))
        (is (string= "0" (gethash "bitmap" parsed))))
      (let* ((parsed (yason:parse (bl.rpc::rest-handle
                                   node (format nil "/rest/getutxos/checkmempool/~A-0.json"
                                                spender-hex))))
             (utxos (gethash "utxos" parsed)))
        (is (string= "1" (gethash "bitmap" parsed)))
        (is (= 1 (length utxos)))
        (is (= 2147483647 (gethash "height" (first utxos))))))))

(test wave10-getutxos-limits-and-parse-errors
  "BIP64 error paths: >15 outpoints, malformed outpoints, empty request,
unknown output format (Core rest.cpp:919-947)."
  (let ((node (make-test-node))
        (hunchentoot:*reply* (make-instance 'hunchentoot:reply))
        (txid (make-string 64 :initial-element #\d)))
    (flet ((status () (hunchentoot:return-code*)))
      ;; 16 outpoints -> 400 max exceeded
      (let ((body (with-output-to-string (s)
                    (dotimes (i 16) (format s "/~A-~D" txid i)))))
        (let ((resp (bl.rpc::rest-handle
                     node (format nil "/rest/getutxos~A.json" body))))
          (is (= 400 (status)))
          (is (search "max outpoints exceeded" resp))))
      ;; malformed vout (sign / junk / missing)
      (bl.rpc::rest-handle node (format nil "/rest/getutxos/~A-+1.json" txid))
      (is (= 400 (status)))
      (bl.rpc::rest-handle node (format nil "/rest/getutxos/~A-1x.json" txid))
      (is (= 400 (status)))
      (bl.rpc::rest-handle node (format nil "/rest/getutxos/~A-.json" txid))
      (is (= 400 (status)))
      ;; short txid
      (bl.rpc::rest-handle node "/rest/getutxos/abcd-0.json")
      (is (= 400 (status)))
      ;; empty request
      (bl.rpc::rest-handle node "/rest/getutxos/.json")
      (is (= 400 (status)))
      ;; unknown format -> Core's 404 "output format not found"
      (let ((resp (bl.rpc::rest-handle
                   node (format nil "/rest/getutxos/~A-0.xml" txid))))
        (is (= 404 (status)))
        (is (search "output format not found" resp))))))

;;; ---------------------------------------------------------------------
;;; F. Config wires
;;; ---------------------------------------------------------------------

(test wave10-conf-parse-money
  "conf-parse-money follows Core ParseMoney: BTC decimal string -> satoshis;
malformed/negative/9-decimals/oversized -> NIL."
  (is (= 100000000 (bl:conf-parse-money "1")))
  (is (= 1000 (bl:conf-parse-money "0.00001")))
  (is (= 1 (bl:conf-parse-money "0.00000001")))
  (is (= 123456789 (bl:conf-parse-money "1.23456789")))
  (is (null (bl:conf-parse-money "x")))
  (is (null (bl:conf-parse-money "-1")))
  (is (null (bl:conf-parse-money "0.000000001")))  ; 9 decimals
  (is (null (bl:conf-parse-money "")))
  (is (null (bl:conf-parse-money "22000000.00000001")))) ; > MAX_MONEY

(test wave10-conf-parse-user-hex
  "conf-parse-user-hex follows uint256::FromUserHex: optional 0x, up to 64
hex digits, left-padded; junk/overlong -> NIL."
  (let ((z (bl:conf-parse-user-hex "0")))
    (is (= 32 (length z)))
    (is (every #'zerop z)))
  (let ((v (bl:conf-parse-user-hex "0xabcd")))
    (is (= #xab (aref v 30)))
    (is (= #xcd (aref v 31)))
    (is (every #'zerop (subseq v 0 30))))
  (is (null (bl:conf-parse-user-hex "zz")))
  (is (null (bl:conf-parse-user-hex (make-string 65 :initial-element #\a)))))

(test wave10-config-wires-globals
  "apply-config-globals wires -assumevalid/-minimumchainwork/-mempoolexpiry/
-minrelaytxfee/-blockmintxfee/-bantime/-dnsseed/-fixedseeds/-stopatheight/
-uacomment/-externalip onto their process globals."
  (let ((bl:*assumevalid-override* :unset)
        (bl:*minimum-chain-work-override* nil)
        (bl.mp:*mempool-expiry-hours* 336)
        (bl.mp:*min-relay-fee-rate* 100)
        (bl.mining:*block-min-tx-fee-rate* 1)
        (bl.net:*default-ban-time-seconds* 86400)
        (bl:*dns-seed-enabled* t)
        (bl:*fixed-seeds-enabled* t)
        (bl:*stop-at-height* 0)
        (bl.ser:*user-agent* "/bl:0.1.0/")
        (bl.net:*external-ips* '())
        ;; reachability tail scratch state
        (bl.net:*reachable-networks* '())
        (bl.net:*onlynet-networks* '())
        (bl.net:*cjdns-reachable* nil)
        (bl.net:*proxy* nil)
        (bl.net:*onion-proxy* nil)
        (bl.net:*onion-proxy-explicit* nil))
    ;; -assumevalid=<hash>: stored in WIRE order (display reversed)
    (bl::apply-config-globals '(("assumevalid" . "0xabcd")))
    (is (= #xcd (aref bl:*assumevalid-override* 0)))
    (is (= #xab (aref bl:*assumevalid-override* 1)))
    ;; -assumevalid=0 disables
    (bl::apply-config-globals '(("assumevalid" . "0")))
    (is (null bl:*assumevalid-override*))
    (signals error (bl::apply-config-globals '(("assumevalid" . "nothex"))))
    ;; -minimumchainwork
    (bl::apply-config-globals '(("minimumchainwork" . "0x1234")))
    (is (= #x1234 bl:*minimum-chain-work-override*))
    (signals error (bl::apply-config-globals '(("minimumchainwork" . "junk"))))
    ;; -mempoolexpiry / -minrelaytxfee / -blockmintxfee / -bantime
    (bl::apply-config-globals '(("mempoolexpiry" . "24")))
    (is (= 24 bl.mp:*mempool-expiry-hours*))
    (bl::apply-config-globals '(("minrelaytxfee" . "0.00002")))
    (is (= 2000 bl.mp:*min-relay-fee-rate*))
    ;; the mempool built AFTER the wire uses the new floor
    (is (= 2000 (bl.mp:mempool-min-fee-rate
                 (bl.mp:make-mempool))))
    (signals error (bl::apply-config-globals '(("minrelaytxfee" . "junk"))))
    (bl::apply-config-globals '(("blockmintxfee" . "0.00005")))
    (is (= 5000 bl.mining:*block-min-tx-fee-rate*))
    (bl::apply-config-globals '(("bantime" . "3600")))
    (is (= 3600 bl.net:*default-ban-time-seconds*))
    ;; -dnsseed=0 / -fixedseeds=0 / -stopatheight
    (bl::apply-config-globals '(("dnsseed" . "0") ("fixedseeds" . "0")
                                          ("stopatheight" . "12345")))
    (is (null bl:*dns-seed-enabled*))
    (is (null bl:*fixed-seeds-enabled*))
    (is (= 12345 bl:*stop-at-height*))
    ;; -uacomment (repeatable, BIP14)
    (bl::apply-config-globals '(("uacomment" . "alpha") ("uacomment" . "beta")))
    (is (string= "/bl:0.1.0(alpha; beta)/"
                 bl.ser:*user-agent*))
    (signals error (bl::apply-config-globals '(("uacomment" . "bad(char)"))))
    (signals error (bl::apply-config-globals
                    (list (cons "uacomment" (make-string 300 :initial-element #\a)))))
    ;; -externalip collected raw
    (bl::apply-config-globals '(("externalip" . "203.0.113.5")
                                          ("externalip" . "198.51.100.6")))
    (is (= 2 (length bl.net:*external-ips*)))))

(test wave10-format-subversion
  "FormatSubVersion parity (Core clientversion.cpp:67-72) + sanitizer; the
user agent is built from the one client version constant."
  (is (string= "/bl:0.1.0/" (bl.ser:format-user-agent '())))
  (is (string= "/bl:0.1.0(a; b)/"
               (bl.ser:format-user-agent '("a" "b"))))
  ;; Unstamped build: the build-rev composition is the plain user agent.
  (is (string= "/bl:0.1.0(a; b)/"
               (bl.ser:subversion-with-build-rev '("a" "b"))))
  (is-true (bl:ua-comment-safe-p "Safe comment .,;-_?@ 123"))
  (is-false (bl:ua-comment-safe-p "bad(char)")))

(test wave10-mempool-expiry-wire-effective
  "mempool-expire honors *mempool-expiry-hours* (Core -mempoolexpiry)."
  (let ((bl.mp:*mempool-expiry-hours* 1)
        (mempool (bl.mp:make-mempool))
        (tx (make-mempool-test-tx :input-id 81)))
    ;; entry-time 1000000 (helper default) is far older than 1h before now.
    (is (eq :ok (bl.mp:mempool-add
                 mempool (bl.ser:transaction-hash tx)
                 (make-mempool-entry-for-tx tx))))
    (is (= 1 (bl.mp:mempool-expire mempool)))
    (is (zerop (bl.mp:mempool-count mempool)))))

(test wave10-plist-wires
  "config-alist->start-node-plist: -port (validated), -networkactive,
-rest, repeatable -addnode."
  (let ((plist (bl::config-alist->start-node-plist
                '(("port" . "12345") ("networkactive" . "0") ("rest" . "1")
                  ("addnode" . "192.0.2.1:8333") ("addnode" . "198.51.100.2"))
                :testnet4)))
    (is (= 12345 (getf plist :port)))
    (is (null (getf plist :network-active)))
    (is (eq t (getf plist :rest)))
    (is (equal '("192.0.2.1:8333" "198.51.100.2") (getf plist :addnode))))
  (signals error (bl::config-alist->start-node-plist
                  '(("port" . "0")) :testnet4))
  (signals error (bl::config-alist->start-node-plist
                  '(("port" . "70000")) :testnet4)))

(test wave10-listen-port-override
  "listen-port honors *p2p-port-override* and falls back to the network
default; the dial default (network-port) is never affected."
  (let ((bl:*p2p-port-override* nil))
    (is (= 48333 (bl:listen-port :testnet4)))
    (setf bl:*p2p-port-override* 15555)
    (is (= 15555 (bl:listen-port :testnet4)))
    (is (= 48333 (bl:network-port :testnet4)))))

;;; ---------------------------------------------------------------------
;;; G. Argument handling
;;; ---------------------------------------------------------------------

(test wave10-unknown-cli-arg-errors
  "Unknown command-line options and positional tokens are startup errors
(Core ArgsManager::ParseParameters); known options and -no variants pass."
  (finishes (bl:check-cli-args '("-txindex" "-dbcache=100" "-nolisten"
                                           "-chain=main" "-" "--")))
  (signals error (bl:check-cli-args '("-bogusopt")))
  (signals error (bl:check-cli-args '("-bogusopt=1")))
  (signals error (bl:check-cli-args '("positional")))
  ;; new wave-10 options are recognized
  (finishes (bl:check-cli-args
             '("-assumevalid=0" "-minimumchainwork=0x00" "-mempoolexpiry=1"
               "-port=1234" "-dnsseed=0" "-nofixedseeds" "-externalip=1.2.3.4"
               "-addnode=x:1" "-bantime=60" "-uacomment=hi" "-blockmintxfee=0.0001"
               "-minrelaytxfee=0.0001" "-stopatheight=5" "-networkactive=0" "-rest"))))

(test wave10-unknown-config-file-keys-warn-only
  "Unknown config-FILE keys are reported for warning, never an error
(Core ReadConfigFiles with ignore_invalid_keys)."
  (is (equal '("frobnicate")
             (bl:unknown-config-file-keys
              '(("txindex" . "1") ("frobnicate" . "9") ("rest" . "0")))))
  (is (null (bl:unknown-config-file-keys '(("dbcache" . "100"))))))

(test wave10-repeated-arg-precedence
  "Repeated command-line args: LAST wins; repeatable options keep every
occurrence in order; config-file repeats: FIRST wins; CLI beats config."
  ;; CLI scalar: last occurrence wins
  (let ((a (bl.cfg:parse-cli-args '("-dbcache=100" "-dbcache=200"))))
    (is (string= "200" (cdr (assoc "dbcache" a :test #'string=))))
    (is (= 1 (count "dbcache" a :key #'car :test #'string=))))
  ;; repeatable: all kept, in order
  (let ((a (bl.cfg:parse-cli-args '("-onlynet=ipv4" "-onlynet=ipv6"))))
    (is (equal '("ipv4" "ipv6")
               (loop for (k . v) in a when (string= k "onlynet") collect v))))
  ;; config file scalar: first occurrence wins
  (let ((c (bl.cfg:parse-bitcoin-conf
            (format nil "dbcache=1~%dbcache=2~%"))))
    (is (string= "1" (cdr (assoc "dbcache" c :test #'string=)))))
  ;; CLI over config (merged = cli ++ conf)
  (let* ((cli (bl.cfg:parse-cli-args '("-dbcache=100" "-dbcache=200")))
         (conf (bl.cfg:parse-bitcoin-conf (format nil "dbcache=1~%")))
         (merged (append cli conf)))
    (is (string= "200" (cdr (assoc "dbcache" merged :test #'string=))))))

;;; ---------------------------------------------------------------------
;;; H. Persistence/ops
;;; ---------------------------------------------------------------------

(test wave10-banlist-roundtrip
  "banlist.json: bans persist across a simulated restart; expired entries
are swept at load (Core BanMan LoadBanlist/SweepBanned)."
  (let* ((dir (ensure-directories-exist
               (merge-pathnames (format nil "wave10-banlist-~D/" (get-universal-time))
                                (uiop:temporary-directory))))
         (path (merge-pathnames "banlist.json" dir))
         (bl.net:*banlist-path* path))
    (unwind-protect
         (progn
           (bl.net:ban-address "203.0.113.77" 3600)
           (bl.net:ban-address "198.51.100.88" 3600)
           (is (probe-file path))
           ;; Simulated restart: wipe memory, reload.
           (clrhash bl.net:*banned-peers*)
           (is (not (bl.net:peer-banned-p "203.0.113.77")))
           (is (= 2 (bl.net:load-banlist)))
           (is (bl.net:peer-banned-p "203.0.113.77"))
           (is (bl.net:peer-banned-p "198.51.100.88"))
           ;; unban dumps immediately: reload sees 1.
           (bl.net:unban-address "203.0.113.77")
           (clrhash bl.net:*banned-peers*)
           (is (= 1 (bl.net:load-banlist)))
           ;; Expired entries are swept at load.
           (with-open-file (out path :direction :output :if-exists :supersede)
             (write-string "{\"banned_nets\":[{\"version\":1,\"ban_created\":0,\"banned_until\":5,\"address\":\"192.0.2.66\"}]}" out))
           (clrhash bl.net:*banned-peers*)
           (is (= 0 (bl.net:load-banlist)))
           (is (not (bl.net:peer-banned-p "192.0.2.66"))))
      (clrhash bl.net:*banned-peers*)
      (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore))))

(test wave10-peers-dump-cadence
  "maybe-dump-peer-addresses writes peers.dat on the 15-minute cadence and
not before (Core DumpAddresses every DUMP_PEERS_INTERVAL)."
  (let* ((dir (ensure-directories-exist
               (merge-pathnames (format nil "wave10-peersdump-~D/" (get-universal-time))
                                (uiop:temporary-directory))))
         (node (bl:make-node :network :testnet4))
         (bl::*last-peers-dump-time* 0))
    (setf (bl:node-data-directory node) dir)
    (setf (bl:node-address-book node)
          (bl.net:make-address-book))
    (unwind-protect
         (progn
           ;; Stale timestamp -> dump fires and the file appears.
           (is (eq t (bl::maybe-dump-peer-addresses node)))
           (is (probe-file (bl.net:peers-dat-path dir)))
           ;; Fresh timestamp -> cadence gate holds.
           (is (null (bl::maybe-dump-peer-addresses node))))
      (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore))))

(test wave10-stop-at-height-guards
  "maybe-stop-at-height: disabled (0) or below-target heights never trigger;
no node running -> no trigger."
  (let ((bl:*stop-at-height* 0)
        (bl::*stop-at-height-triggered* nil)
        (bl:*node* nil))
    (is (null (bl:maybe-stop-at-height nil nil 100))))
  (let ((bl:*stop-at-height* 50)
        (bl::*stop-at-height-triggered* nil)
        (bl:*node* nil))
    (is (null (bl:maybe-stop-at-height nil nil 49)))
    (is (null (bl:maybe-stop-at-height nil nil 50))) ; no node -> no trigger
    (is (null bl::*stop-at-height-triggered*))))

(test wave10-check-disk-space
  "check-disk-space: plenty of space passes; an absurd additional-bytes
requirement fails; unreadable paths fail open."
  (is-true (bl::check-disk-space (uiop:temporary-directory)))
  (is-false (bl::check-disk-space (uiop:temporary-directory)
                                            (* 1024 1024 1024 1024 1024)))
  ;; Nonexistent directory: df fails -> fail-open T.
  (is-true (bl::check-disk-space "/nonexistent/wave10/path/")))
