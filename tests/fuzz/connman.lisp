(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/connman.cpp at the pin: random calls into the
;;;; connection manager -- AddNode, RemoveAddedNode, DisconnectNode by id,
;;;; address and subnet, SetNetworkActive, GetAddedNodeInfo, GetNodeCount,
;;;; GetAddresses, the node stats -- over a set of test nodes. We have no
;;;; CConnman object: its state is the node's peer list, added-node list and
;;;; network-active flag, and its interface is the P2P RPCs that read and write
;;;; them (addnode, getaddednodeinfo, disconnectnode, setnetworkactive,
;;;; getconnectioncount, getpeerinfo, getnetworkinfo, getnodeaddresses, ping,
;;;; getnettotals), so those are what the target drives, on the process_message
;;;; fixture node with socket-less peers.
;;;;
;;;; Core asserts that the calls return (and that the outbound limit reads back
;;;; as set). Beside that the target keeps a model of what the manager holds --
;;;; the added nodes, the connected peers, the network-active flag -- and checks
;;;; the RPCs against it: every refusal is an RPC error Core gives for the same
;;;; call, the counts agree with each other and with the model.

(def-suite :fuzz-connman-tests :in :bitcoin-lisp-tests
  :description "Core fuzz connman.cpp over our connection-manager RPCs")

(in-suite :fuzz-connman-tests)

(defparameter +connman-node-strings+
  '("10.0.0.1" "10.0.0.1:18444" "10.0.0.2:8333" "127.1:18444" "127.0.0.1:18444"
    "127.0.0.1" "node.example" "node.example:18444" "[::1]:18444" "::1" "")
  "Added-node strings with known equivalences: 10.0.0.1 is 10.0.0.1:18444 on
regtest, 127.1 is 127.0.0.1.")

(defun %connman-endpoint (spec)
  "The (ip-bytes . port) a numeric SPEC names on regtest, or NIL -- the
model's own reading of Core's ResolveService for AddNode's duplicate check."
  (let* ((colon (position #\: spec :from-end t))
         (bracketed (and (plusp (length spec)) (char= (char spec 0) #\[)))
         (host (cond (bracketed (subseq spec 1 (position #\] spec)))
                     ((and colon (= 1 (count #\: spec))) (subseq spec 0 colon))
                     (t spec)))
         (port (cond ((and bracketed (position #\] spec) (< (1+ (position #\] spec)) (length spec)))
                      (parse-integer spec :start (+ 2 (position #\] spec))))
                     ((and colon (= 1 (count #\: spec))) (parse-integer spec :start (1+ colon)))
                     (t 18444)))
         (ip (and (plusp (length host)) (bl.net:numeric-host-ip-bytes host))))
    (and ip (cons ip port))))

(defun %rpc-json (node method params)
  "(values parsed-json nil) or (values nil rpc-error-code)."
  (handler-case (values (yason:parse (rpc-result-json (bl.rpc:dispatch-rpc-method node method params))) nil)
    (bl.rpc:rpc-error (e) (values nil (bl.rpc:rpc-error-code e)))))

(define-fuzz-target connman
    (buffer :core "connman.cpp:38-235" :iterations 60 :max-len 400)
  "Any sequence of connection-manager calls answers or refuses as Core does,
and what it reports agrees with what was done: the added-node list is the
nodes added and not removed, a disconnected peer is gone from the counts,
the connection count, getpeerinfo and getnetworkinfo agree, and the network
flag reads back as set."
  (let ((fdp (make-fuzzed-data-provider buffer)))
    (with-fuzz-p2p-node (p2p)
      (let* ((node (fp-node p2p))
             (peers (loop for i from 1 to (consume-integral-in-range fdp 0 6)
                          collect (bl.net:make-peer
                                   :id i :state :ready :address (format nil "10.0.0.~D" i)
                                   :inbound (consume-bool fdp)
                                   :connection (make-test-connection :host (format nil "10.0.0.~D" i)
                                                                     :port 18444 :connected t))))
             (added '())
             (active t))
        (setf (bl:node-peers node) (copy-list peers)
              (bl:node-network-active node) t)
        (flet ((live () (count-if-not (lambda (p) (eq (bl.net:peer-state p) :disconnected)) peers)))
          (limited-while ((plusp (consume-integral-in-range fdp 0 15)) 1000)
            (call-one-of fdp
              ;; AddNode: refused as a duplicate exactly when Core's check says so.
              (let* ((spec (pick-value-in-array fdp +connman-node-strings+))
                     (dup (and (plusp (length spec))
                               (some (lambda (a) (or (string= a spec)
                                                     (let ((x (%connman-endpoint spec)))
                                                       (and x (equalp x (%connman-endpoint a))))))
                                     added))))
                (multiple-value-bind (r code) (%rpc-json node "addnode" (list spec "add" nil))
                  (declare (ignore r))
                  (cond ((zerop (length spec)) (fuzz-assert code "addnode of an empty name was taken"))
                        (dup (fuzz-assert (eql code -23) "~S duplicates ~S, answered ~S" spec added code))
                        (t (fuzz-assert (null (fuzz-sabotage code)) "addnode ~S refused with ~S" spec code)
                           (setf added (append added (list spec)))))))
              ;; RemoveAddedNode: exact string.
              (let ((spec (pick-value-in-array fdp +connman-node-strings+)))
                (multiple-value-bind (r code) (%rpc-json node "addnode" (list spec "remove" nil))
                  (declare (ignore r))
                  (cond ((zerop (length spec)) (fuzz-assert code))
                        ((member spec added :test #'string=)
                         (fuzz-assert (null code) "remove of added ~S refused with ~S" spec code)
                         (setf added (remove spec added :test #'string=)))
                        (t (fuzz-assert (eql code -24) "remove of ~S (not added) answered ~S" spec code)))))
              ;; GetAddedNodeInfo: the model's list, in order.
              (let ((info (%rpc-json node "getaddednodeinfo" nil)))
                (fuzz-assert (equal (mapcar (lambda (h) (gethash "addednode" h)) info) added)
                             "getaddednodeinfo lists ~S, added ~S"
                             (mapcar (lambda (h) (gethash "addednode" h)) info) added))
              ;; DisconnectNode by id, then by address: a connected peer is
              ;; found and dropped, an absent one is RPC_CLIENT_NODE_NOT_CONNECTED
              ;; (net.cpp:3809-3852, rpc/net.cpp:482). Both forms search the
              ;; same list, so a peer already dropped but not yet reaped from
              ;; it is found by either, as Core finds a node marked
              ;; fDisconnect that is still in m_nodes.
              (flet ((check-disconnect (peer params what)
                       (multiple-value-bind (r code) (%rpc-json node "disconnectnode" params)
                         (declare (ignore r))
                         (cond ((null peer)
                                (fuzz-assert (eql code -29) "disconnectnode of absent ~A answered ~S" what code))
                               (t
                                (fuzz-assert (null code) "disconnectnode ~A refused with ~S" what code)
                                (fuzz-assert (eq (bl.net:peer-state peer) :disconnected)
                                             "disconnectnode ~A left the peer ~S" what (bl.net:peer-state peer)))))))
                (let ((id (consume-integral-in-range fdp 0 8)))
                  (check-disconnect (find id (bl:node-peers node) :key #'bl.net:peer-id)
                                    (list "" id) id))
                (let ((i (consume-integral-in-range fdp 0 8)))
                  (check-disconnect (find (format nil "10.0.0.~D" i) (bl:node-peers node)
                                          :key #'bl.net:peer-address :test #'string=)
                                    (list (format nil "10.0.0.~D:18444" i))
                                    (format nil "10.0.0.~D:18444" i))))
              ;; SetNetworkActive: reads back; off drops every peer.
              (let ((state (consume-bool fdp)))
                (%rpc-json node "setnetworkactive" (list (if state t bl.rpc:+json-false+)))
                (setf active state)
                (unless state
                  (fuzz-assert (zerop (live)) "~D peers survive setnetworkactive false" (live))))
              ;; GetNodeCount, the node stats and getnetworkinfo agree.
              (let ((count (%rpc-json node "getconnectioncount" nil))
                    (info (%rpc-json node "getpeerinfo" nil))
                    (net (%rpc-json node "getnetworkinfo" nil)))
                (fuzz-assert (= (fuzz-sabotage count) (length info) (gethash "connections" net))
                             "connections: ~S by count, ~D in getpeerinfo, ~S in getnetworkinfo"
                             count (length info) (gethash "connections" net))
                (fuzz-assert (<= count (live)) "~D connections counted for ~D live peers" count (live))
                (fuzz-assert (eq (gethash "networkactive" net) active)
                             "networkactive reads ~S, set ~S" (gethash "networkactive" net) active))
              ;; GetAddresses.
              (let ((n (consume-integral-in-range fdp 0 10)))
                (multiple-value-bind (r code) (%rpc-json node "getnodeaddresses" (list n))
                  (fuzz-assert (or code (zerop n) (<= (length r) n)))))
              (%rpc-json node "ping" nil)
              (%rpc-json node "getnettotals" nil))))))))
